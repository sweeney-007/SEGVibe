"""SEGVibe command line.

    segvibe tasks                                   list benchmark tasks
    segvibe check FILE.c --task ID                  run every check on your code
    segvibe solve --task ID --model SPEC            generate + check + repair for a task
    segvibe new "requirement" --signature "..." --model SPEC [--out file.c]
    segvibe agent --task ID --model SPEC [--rag]    plan, implement, check, review, probe, fix, refine
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from segvibe.check import check
from segvibe.findings import Report
from segvibe.task import load_task, load_tasks


def print_report(rep: Report, code: str) -> None:
    print(rep.summary(), f"({rep.seconds:.1f}s)")
    lines = code.splitlines()
    order = {"high": 0, "medium": 1, "low": 2}
    for f in sorted(rep.findings, key=lambda f: (order[f.severity], f.line or 0)):
        print(f"  {f.severity:6s} {f.text(lines)}")
    if rep.perf.get("exp") is not None:
        p = rep.perf
        print(f"  perf: time ~ n^{p['exp']}, {p['time_ratio']}x reference time, {p['mem_ratio']}x reference heap")


def _task(arg: str):
    return load_task(arg) if arg.endswith(".yaml") else load_tasks([arg])[0]


def _progress(att):
    print(f"\n== round {att.round} ({att.gen_seconds:.0f}s to generate)")
    print_report(att.report, att.code)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="segvibe", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("tasks")
    c = sub.add_parser("check")
    c.add_argument("file")
    c.add_argument("--task", required=True, help="task id or path to a task .yaml")
    c.add_argument("--json", action="store_true")
    s = sub.add_parser("solve")
    s.add_argument("--task", required=True)
    s.add_argument("--model", required=True, help="hf:Qwen/Qwen2.5-Coder-1.5B-Instruct, groq:llama-3.3-70b-versatile, ...")
    s.add_argument("--rounds", type=int, default=3)
    s.add_argument("--rag", action="store_true", help="add retrieved CWE/recipe guidance to repairs")
    s.add_argument("--out")
    g = sub.add_parser("agent")
    g.add_argument("--task", required=True)
    g.add_argument("--model", required=True)
    g.add_argument("--steps", type=int, default=10)
    g.add_argument("--rag", action="store_true")
    g.add_argument("--out")
    n = sub.add_parser("new")
    n.add_argument("requirement")
    n.add_argument("--signature", required=True)
    n.add_argument("--model", required=True)
    n.add_argument("--rounds", type=int, default=3)
    n.add_argument("--out")
    a = ap.parse_args(argv)

    if a.cmd == "tasks":
        for t in load_tasks():
            print(f"{t.id:20s} {t.title}  [{', '.join(t.tags)}]")
        return 0
    if a.cmd == "check":
        code = Path(a.file).read_text()
        rep = check(code, _task(a.task))
        print(json.dumps(rep.to_dict(), indent=2) if a.json else "", end="")
        if not a.json:
            print_report(rep, code)
        return 0 if rep.clean else 1

    from segvibe.gen.models import make_generator
    gen = make_generator(a.model)
    retriever = None
    if getattr(a, "rag", False):
        from segvibe.rag.retrieve import default_retriever
        retriever = default_retriever()
    if a.cmd == "agent":
        from segvibe.agent.graph import Budget, run_agent

        def show(ev):
            print(f"[{ev['time']}] {ev['action']:8s} {ev['outcome']:10s} {ev['note']}")
            if ev.get("summary"):
                print(f"{'':30s}{ev['summary']} | {ev['design']}")
        out = run_agent(_task(a.task), gen, budget=Budget(steps=a.steps), on_event=show, retriever=retriever)
        best = out["best"]
        print(f"\nstopped: {out.get('stop_reason')}; best version {best['version']}: {best['report'].summary()}, "
              f"{best['design'].summary()}; {len(out.get('probes', []))} regression test(s) added")
        if a.out:
            Path(a.out).write_text(best["code"])
        else:
            print(best["code"])
        return 0 if best["report"].clean else 1
    if a.cmd == "solve":
        from segvibe.gen.loop import solve
        sol = solve(_task(a.task), gen, a.rounds, on_attempt=_progress, retriever=retriever)
    else:
        from segvibe.freeform import solve_requirement
        task, sol = solve_requirement(a.requirement, a.signature, gen, a.rounds, on_attempt=_progress)
        print(f"\n(model-written tests: {'yes' if task.tests else 'none'}, fuzz case: {'yes' if task.fuzz else 'none'})")
    best = sol.best
    print(f"\nbest: round {best.round}, {best.report.summary()}")
    if a.out:
        Path(a.out).write_text(best.code)
        print(f"written to {a.out}")
    else:
        print(best.code)
    return 0 if best.report.clean else 1


if __name__ == "__main__":
    sys.exit(main())
