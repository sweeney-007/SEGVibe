"""Agentic loop for code design improvement and problem detection (LangGraph).

    plan -> implement -> analyze -> decide --+--> fix ------> analyze
                                    ^        +--> review ---> decide
                                    |        +--> probe  ---> decide
                                    |        +--> refine ---> analyze
                                    +--------+--> stop

- analyze   deterministic checks (tests, sanitizers, leaks, perf, static, AST rules) + design metrics.
            Regression guard: a new version is kept only if it scores at least as well as the best
            so far; otherwise the agent reverts and remembers why ("rejected: ...").
- review    the LLM reviews clean code: design issues, and suspected problems the checks missed.
- probe     the LLM turns one suspicion into a targeted test. The probe is first run on the reference
            (if there is one): a probe the reference fails is a wrong test and is dropped. A probe that
            makes the current code fail is confirmed, kept as a regression test, and leads to a fix.
- fix       repair with the findings, retrieved guidance (CWE entries, fix recipes, past repairs;
            segvibe/rag) and the memory of rejected attempts.
- refine    refactor clean code to address the design issues (measured metrics + review); accepted only
            if every check still passes, the design penalty does not rise and it is not slower.
- decide    a fixed policy (not the LLM) picks the next step, so small local models can drive the loop:
            fix serious problems first, then review, probe suspicions, refine the design, stop.
"""
from __future__ import annotations

import dataclasses
import time
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from segvibe.agent import prompts as P
from segvibe.check import CheckConfig, check
from segvibe.checks.design import DesignReport, analyze_design
from segvibe.findings import Report
from segvibe.gen.models import Generator
from segvibe.gen.prompts import extract_code, extract_tests
from segvibe.task import Task


@dataclasses.dataclass
class Budget:
    steps: int = 10          # LLM steps after the first implementation (fix, review, probe, refine)
    probes: int = 3
    refines: int = 2
    reviews: int = 2
    max_rejections: int = 3  # consecutive rejected versions before giving up


class State(TypedDict, total=False):
    task: Task
    probes: list[str]                 # confirmed probe tests, added to the task's tests
    plan: str
    code: str                         # version under evaluation
    best: dict                        # {"code", "report", "design", "version"}
    version: int
    reviewed_version: int
    suspicions: list[dict]
    design_notes: list[str]
    history: list[dict]
    steps: int
    used: dict                        # budget used per action
    rejections: int
    last_action: str
    next: str
    stop_reason: str


def _task(s: State) -> Task:
    extra = "".join(f"\n{{\n{p}\n}}\n" for p in s.get("probes", []))
    return dataclasses.replace(s["task"], tests=s["task"].tests + extra) if extra else s["task"]


def score(rep: Report, design: DesignReport) -> tuple:
    pass_rate = (rep.checks - rep.fails) / rep.checks if rep.checks else 0.0
    medium = sum(f.severity == "medium" for f in rep.findings)
    return (rep.clean, rep.compiled, rep.tests_passed, pass_rate, -len(rep.high), -medium, -design.penalty)


def _slower(new: Report, old: Report) -> bool:
    a, b = new.perf.get("time_ratio"), old.perf.get("time_ratio")
    return a is not None and b is not None and a > 1.5 * b + 0.2


def _same(a: str, b: str) -> bool:
    """Same code apart from whitespace."""
    return "".join(a.split()) == "".join(b.split())


def build_agent(gen: Generator, cfg: CheckConfig | None = None, budget: Budget | None = None,
                on_event: Callable[[dict], None] | None = None, retriever=None):
    cfg = cfg or CheckConfig()
    budget = budget or Budget()

    def log(s: State, action: str, outcome: str, note: str = "", **extra) -> list[dict]:
        ev = {"step": s.get("steps", 0), "action": action, "outcome": outcome, "note": note,
              "time": time.strftime("%H:%M:%S"), **extra}
        if on_event:
            on_event(ev)
        return s.get("history", []) + [ev]

    def llm(msgs):
        return gen.generate(msgs).text

    def new_code(s: State, msgs, old: str, step: str) -> str:
        """Greedy first. A small model often hands back the code it was given unchanged, and greedy
        decoding then repeats that on every retry, so an unchanged answer is resampled once."""
        code = extract_code(llm(msgs))
        if _same(code, old):
            log(s, step, "unchanged", "the model returned the code unchanged; sampling a different answer")
            code = extract_code(gen.generate(msgs, temperature=0.8).text)
        return code

    # --- nodes -------------------------------------------------------------------------------------
    def plan(s: State) -> State:
        text = llm(P.plan_prompt(s["task"]))
        return {"plan": text, "history": log(s, "plan", "done", text.strip().splitlines()[0][:100] if text.strip() else "")}

    def implement(s: State) -> State:
        code = extract_code(llm(P.implement_prompt(s["task"], s["plan"])))
        return {"code": code, "last_action": "implement", "version": 1}

    def analyze(s: State) -> State:
        rep = check(s["code"], _task(s), cfg)
        des = analyze_design(s["code"])
        version = s.get("version", 1)
        new = {"code": s["code"], "report": rep, "design": des, "version": version}
        best = s.get("best")
        act = s.get("last_action", "implement")
        info = {"summary": rep.summary(), "design": des.summary()}
        if best is None:
            return {"best": new, "rejections": 0, "history": log(s, "analyze", "accepted", rep.summary(), **info)}
        if act == "refine":
            ok = rep.clean and des.penalty <= best["design"].penalty and not _slower(rep, best["report"])
            why = ("a check failed: " + rep.summary()) if not rep.clean else \
                  "it is slower" if _slower(rep, best["report"]) else \
                  f"the design penalty went up ({best['design'].penalty:.1f} -> {des.penalty:.1f})"
        else:
            ok = score(rep, des) > score(best["report"], best["design"])
            why = f"no improvement: {rep.summary()} vs best {best['report'].summary()}"
        if ok:
            return {"best": new, "rejections": 0, "history": log(s, "analyze", "accepted", rep.summary(), **info)}
        return {"code": best["code"], "rejections": s.get("rejections", 0) + 1,
                "history": log(s, "analyze", "rejected", f"{act} version was rejected because {why}", **info)}

    def review(s: State) -> State:
        best = s["best"]
        notes = [msg for _, msg in best["design"].issues]
        r = P.parse_review(llm(P.review_prompt(s["task"], best["code"], notes)))
        design = notes + [f"line {d.get('line', '?')}: {d.get('issue', '')} -> {d.get('fix', '')}"
                          for d in r["design_issues"]][:8]
        sus = r["suspected_problems"][:4]
        return {"design_notes": design, "suspicions": sus, "reviewed_version": best["version"],
                "steps": s.get("steps", 0) + 1, "used": _use(s, "reviews"), "last_action": "review",
                "history": log(s, "review", "done", f"{len(design)} design issue(s), {len(sus)} suspected problem(s)",
                               suspicions=[x.get("problem", "") for x in sus])}

    def probe(s: State) -> State:
        sus, rest = s["suspicions"][0], s["suspicions"][1:]
        upd: State = {"suspicions": rest, "steps": s.get("steps", 0) + 1, "used": _use(s, "probes"),
                      "last_action": "probe"}
        tests, _ = extract_tests(llm(P.probe_prompt(s["task"], s["best"]["code"], sus)).replace("```c probe", "```c tests"))
        what = sus.get("problem", "")[:90]
        if not tests:
            return {**upd, "history": log(s, "probe", "dismissed", f"no test written for: {what}")}
        trial = {**s, "probes": s.get("probes", []) + [tests]}
        task = _task(trial)
        if s["task"].reference:
            ref = check(s["task"].reference, task, dataclasses.replace(cfg, perf=False, fuzz=False))
            if not ref.clean:
                return {**upd, "history": log(s, "probe", "dismissed",
                                              f"probe is wrong (the reference fails it): {what}")}
        rep = check(s["best"]["code"], task, cfg)
        before = {f.key() for f in s["best"]["report"].high}
        new = [f for f in rep.high if f.key() not in before]
        if not s["task"].reference:   # no reference to validate CHECKs: trust only hard evidence
            new = [f for f in new if f.kind != "wrong-result"]
        if not new:
            return {**upd, "history": log(s, "probe", "dismissed", f"code handles it: {what}")}
        best = {**s["best"], "report": rep, "design": analyze_design(s["best"]["code"])}
        return {**upd, "probes": trial["probes"], "best": best, "code": best["code"],
                "history": log(s, "probe", "confirmed", f"{what} -> {new[0].kind} (kept as a regression test)",
                               probe=tests)}

    def fix(s: State) -> State:
        b = s["best"]
        guidance, hits = retriever.guidance(b["report"].findings, b["code"]) if retriever else ("", [])
        if hits:
            log(s, "retrieve", "done", ", ".join(h.doc.id for h in hits))
        code = new_code(s, P.fix_prompt(s["task"], b["code"], b["report"].feedback(b["code"]),
                                        s.get("history", []), guidance), b["code"], "fix")
        return {"code": code, "version": s.get("version", 1) + 1, "steps": s.get("steps", 0) + 1,
                "used": _use(s, "fixes"), "last_action": "fix"}

    def refine(s: State) -> State:
        b = s["best"]
        issues = s.get("design_notes") or [msg for _, msg in b["design"].issues]
        code = new_code(s, P.refine_prompt(s["task"], b["code"], issues, s.get("history", [])), b["code"], "refine")
        return {"code": code, "version": s.get("version", 1) + 1, "steps": s.get("steps", 0) + 1,
                "used": _use(s, "refines"), "last_action": "refine", "design_notes": []}

    def decide(s: State) -> State:
        b, used = s["best"], s.get("used", {})
        left = budget.steps - s.get("steps", 0)
        if left <= 0:
            return {"next": "stop", "stop_reason": "step budget used"}
        if s.get("rejections", 0) >= budget.max_rejections:
            return {"next": "stop", "stop_reason": f"{budget.max_rejections} rejected versions in a row"}
        if not b["report"].clean:
            return {"next": "fix"}
        if s.get("reviewed_version") != b["version"] and used.get("reviews", 0) < budget.reviews:
            return {"next": "review"}
        if s.get("suspicions") and used.get("probes", 0) < budget.probes:
            return {"next": "probe"}
        design_left = s.get("design_notes") or [m for _, m in b["design"].issues]
        if design_left and used.get("refines", 0) < budget.refines:
            return {"next": "refine"}
        return {"next": "stop", "stop_reason": "clean, reviewed and nothing left to improve"}

    def _use(s: State, key: str) -> dict:
        u = dict(s.get("used", {}))
        u[key] = u.get(key, 0) + 1
        return u

    g = StateGraph(State)
    for name, fn in [("plan", plan), ("implement", implement), ("analyze", analyze), ("decide", decide),
                     ("review", review), ("probe", probe), ("fix", fix), ("refine", refine)]:
        g.add_node(name, fn)
    g.add_edge(START, "plan")
    g.add_edge("plan", "implement")
    g.add_edge("implement", "analyze")
    g.add_edge("analyze", "decide")
    g.add_conditional_edges("decide", lambda s: s["next"],
                            {"fix": "fix", "review": "review", "probe": "probe", "refine": "refine", "stop": END})
    g.add_edge("fix", "analyze")
    g.add_edge("refine", "analyze")
    g.add_edge("review", "decide")
    g.add_edge("probe", "decide")
    return g.compile()


def run_agent(task: Task, gen: Generator, cfg: CheckConfig | None = None, budget: Budget | None = None,
              on_event: Callable[[dict], None] | None = None, retriever=None) -> dict[str, Any]:
    agent = build_agent(gen, cfg, budget, on_event, retriever)
    return agent.invoke({"task": task, "probes": [], "history": [], "steps": 0, "used": {}},
                        {"recursion_limit": 200})
