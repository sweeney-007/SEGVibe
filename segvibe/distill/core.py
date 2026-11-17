"""On-policy self-distillation: the pure parts (no GPU, no Modal).

One round:
  1. the current model samples k solutions per training task (no hints);
  2. the checker stack scores each one;
  3. every failing sample gets one hinted repair: the repair prompt carries
     the checker's findings, which the model will not see at test time;
  4. clean code from steps 1 and 3 becomes training data, always paired with
     the plain generation prompt. The student learns to write, without
     hints, what it wrote with them;
  5. LoRA fine-tune on the data so far, and repeat with the new model.

"Clean" is the checker's verdict: tests pass and no high-severity finding.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

from segvibe.gen.prompts import generate_prompt, repair_prompt


def split_tasks(task_ids: list[str], every: int = 3) -> tuple[list[str], list[str]]:
    """Deterministic split: every `every`-th task (sorted by id) is held out."""
    ids = sorted(task_ids)
    held = [t for i, t in enumerate(ids) if i % every == 0]
    return [t for t in ids if t not in held], held


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k from n samples of which c pass (Chen et al., 2021)."""
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)


_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def normalize(code: str) -> str:
    """Code with comments and all whitespace removed, to count truly distinct solutions."""
    return re.sub(r"\s+", "", _COMMENT.sub("", code))


def code_hash(code: str) -> str:
    return hashlib.sha1(normalize(code).encode()).hexdigest()[:12]


def as_reply(code: str) -> str:
    """The assistant message a training example teaches: the code in one ```c block."""
    return f"```c\n{code.strip()}\n```"


def plain_messages(task) -> list[dict]:
    return generate_prompt(task.requirement, task.signature, safety_rules=True)


def hinted_messages(task, code: str, feedback: str) -> list[dict]:
    return repair_prompt(task.requirement, task.signature, code, feedback, safety_rules=True)


@dataclass
class Sample:
    task: str
    code: str
    clean: bool
    passed: bool
    compiled: bool
    source: str = "plain"        # plain | hinted
    feedback: str = ""           # checker findings, for the hinted repair


def select_examples(samples: list[Sample], per_task: int = 4, seen: set[str] | None = None) -> list[Sample]:
    """Clean, distinct solutions, at most `per_task` new ones per task.

    Plain samples come first (they are already on-policy without hints), then
    hinted repairs. `seen` holds hashes already in the dataset from earlier
    rounds; it is updated in place. The cap keeps easy tasks from crowding
    out the rest of the data.
    """
    seen = set() if seen is None else seen
    out, count = [], {}
    for s in sorted(samples, key=lambda s: s.source != "plain"):
        if not s.clean:
            continue
        h = code_hash(s.code)
        if h in seen or count.get(s.task, 0) >= per_task:
            continue
        seen.add(h)
        count[s.task] = count.get(s.task, 0) + 1
        out.append(s)
    return out


def summarize(samples: list[Sample], ks=(1, 4)) -> dict:
    """Per-task and mean pass@k / clean@k, compile rate and diversity (distinct solutions / samples)."""
    by_task: dict[str, list[Sample]] = {}
    for s in samples:
        by_task.setdefault(s.task, []).append(s)
    rows = {}
    for t, ss in sorted(by_task.items()):
        n = len(ss)
        row = {"n": n, "compiled": sum(s.compiled for s in ss) / n,
               "distinct": len({code_hash(s.code) for s in ss}) / n}
        for k in ks:
            if k <= n:
                row[f"pass@{k}"] = pass_at_k(n, sum(s.passed for s in ss), k)
                row[f"clean@{k}"] = pass_at_k(n, sum(s.clean for s in ss), k)
        rows[t] = row
    keys = sorted({k for r in rows.values() for k in r if k != "n"})
    mean = {k: sum(r[k] for r in rows.values() if k in r) / max(1, sum(k in r for r in rows.values()))
            for k in keys}
    return {"mean": mean, "tasks": rows}
