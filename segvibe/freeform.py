"""From a written requirement to checked code, with no hidden tests.

The model writes the implementation and, separately, tests plus a fuzz case
in the harness format. Static analysis, sanitizers, the leak tracker and
allocation-failure runs then work exactly as for benchmark tasks. There is
no reference solution, so the time/memory comparison is skipped, and the
tests are only as good as the model that wrote them.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from segvibe.checks.build import build, write_sources
from segvibe.gen.loop import Solution, solve
from segvibe.gen.models import Generator
from segvibe.gen.prompts import extract_code, extract_tests, generate_prompt, tests_prompt
from segvibe.task import Task


def _builds(code: str, task: Task) -> bool:
    with tempfile.TemporaryDirectory(prefix="segv_ff_") as d:
        write_sources(Path(d), code, task)
        return build(Path(d), "san")[0]


def make_task(requirement: str, signature: str, gen: Generator) -> Task:
    tests, fuzz = extract_tests(gen.generate(tests_prompt(requirement, signature)).text)
    task = Task(id="custom", requirement=requirement, signature=signature, reference="", tests=tests, fuzz=fuzz)
    # keep only the test blocks that compile against a first draft of the code
    draft = extract_code(gen.generate(generate_prompt(requirement, signature)).text)
    if _builds(draft, Task(**{**task.__dict__, "tests": "", "fuzz": ""})):
        if not _builds(draft, Task(**{**task.__dict__, "fuzz": ""})):
            task.tests = ""
        if not _builds(draft, task):
            task.fuzz = ""
    return task


def solve_requirement(requirement: str, signature: str, gen: Generator, rounds: int = 3,
                      on_attempt=None) -> tuple[Task, Solution]:
    task = make_task(requirement, signature, gen)
    return task, solve(task, gen, rounds, on_attempt=on_attempt)
