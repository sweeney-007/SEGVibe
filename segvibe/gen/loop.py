"""Generate -> check -> repair loop.

Round 0 writes code from the requirement. Each later round gets the
previous code plus the checker's findings (with line numbers and the
offending lines) and must fix them. The loop stops at the first clean
candidate (tests pass, no high-severity finding) or after `rounds` repairs;
the best candidate seen is returned.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from segvibe.check import CheckConfig, check
from segvibe.findings import Report
from segvibe.gen.models import Generator
from segvibe.gen.prompts import extract_code, generate_prompt, repair_prompt
from segvibe.task import Task


@dataclass
class Attempt:
    round: int
    code: str
    report: Report
    gen_seconds: float
    tokens: int


@dataclass
class Solution:
    task_id: str
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def first(self) -> Attempt:
        return self.attempts[0]

    @property
    def best(self) -> Attempt:
        return max(self.attempts, key=lambda a: score(a.report))

    def to_dict(self) -> dict:
        return {"task": self.task_id, "attempts": [
            {"round": a.round, "code": a.code, "gen_seconds": round(a.gen_seconds, 1), "tokens": a.tokens,
             "report": a.report.to_dict()} for a in self.attempts]}


def score(r: Report) -> tuple:
    """Higher is better: clean, then tests passing, then fewer serious findings."""
    pass_rate = (r.checks - r.fails) / r.checks if r.checks else 0.0
    medium = sum(f.severity == "medium" for f in r.findings)
    return (r.clean, r.compiled, r.tests_passed, pass_rate, -len(r.high), -medium)


def solve(task: Task, gen: Generator, rounds: int = 3, cfg: CheckConfig | None = None,
          safety_rules: bool = True, on_attempt=None, retriever=None, stages=None) -> Solution:
    sol = Solution(task.id)
    msgs = generate_prompt(task.requirement, task.signature, safety_rules)
    for rnd in range(rounds + 1):
        g = gen.generate(msgs)
        code = extract_code(g.text)
        rep = check(code, task, cfg)
        att = Attempt(rnd, code, rep, g.seconds, g.tokens)
        sol.attempts.append(att)
        if on_attempt:
            on_attempt(att)
        if rep.clean:
            break
        base = sol.best   # repair the best candidate so far, not necessarily the last one
        guidance = retriever.guidance(base.report.findings, base.code, st=stages)[0] if retriever else ""
        msgs = repair_prompt(task.requirement, task.signature, base.code, base.report.feedback(base.code),
                             safety_rules, guidance)
    return sol
