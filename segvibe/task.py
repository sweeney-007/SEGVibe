"""A task: a written requirement plus the hidden checks used to judge code for it.

Tasks live in tasks/*.yaml:

    id: reverse_words
    requirement: |            # what the user asks for, in words
      ...
    signature: char *reverse_words(const char *s);
    complexity: 1             # expected time growth exponent (1 = linear)
    reference: |              # a correct, clean solution (validates the checks)
      ...
    tests: |                  # C statements using CHECK / CHECK_INT / CHECK_STR
      ...
    fuzz: |                   # one random case; runs many times under sanitizers
      ...
    perf: |                   # one run on input size N; used for time and memory
      ...
    perf_n0: 1000             # starting N for calibration
    heap_limit: 1000000       # optional: peak heap allowed during tests and fuzzing
    variants:                 # optional hand-written flawed versions (detection eval)
      - {kind: overuse, note: ..., code: ...}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

TASK_DIR = Path(__file__).resolve().parents[1] / "tasks"


@dataclass
class Variant:
    kind: str          # expected category: bug | leak | overuse | vuln | crash
    note: str
    code: str


@dataclass
class Task:
    id: str
    requirement: str
    signature: str
    reference: str
    tests: str
    helpers: str = ""         # file-scope C helpers for tests/fuzz/perf
    fuzz: str = ""
    perf: str = ""
    perf_n0: int = 1000
    complexity: float = 1.0
    heap_limit: int = 0       # max peak heap bytes during tests and fuzzing (0 = no limit)
    title: str = ""
    tags: list[str] = field(default_factory=list)
    variants: list[Variant] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        d = dict(d)
        d["variants"] = [Variant(**v) for v in d.get("variants") or []]
        return cls(**d)


def load_task(path: str | Path) -> Task:
    return Task.from_dict(yaml.safe_load(Path(path).read_text()))


def load_tasks(ids: list[str] | None = None, task_dir: Path = TASK_DIR) -> list[Task]:
    tasks = [load_task(p) for p in sorted(task_dir.glob("*.yaml"))]
    if ids:
        want = set(ids)
        tasks = [t for t in tasks if t.id in want]
    return tasks
