"""Prompts for the agent's LLM steps: plan, implement, review, probe, fix, refine."""
from __future__ import annotations

import json
import re

from segvibe.gen.prompts import FORMAT, RULES, SYSTEM


def _msgs(user: str) -> list[dict]:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


def _base(task) -> str:
    return f"Requirement:\n{task.requirement.strip()}\n\nInterface:\n{task.signature.strip()}"


def _memory(history: list[dict]) -> str:
    """What was tried and rejected, so the model does not repeat it."""
    lessons = [h["note"] for h in history if h.get("outcome") == "rejected"][-4:]
    return ("\n\nEarlier attempts that were rejected:\n" + "\n".join(f"- {x}" for x in lessons)) if lessons else ""


def plan_prompt(task) -> list[dict]:
    return _msgs(f"""{_base(task)}

Before writing code, write a short design plan (at most 10 bullet points):
- algorithm and its time complexity; data structures
- who owns each allocation and where it is freed, including on error paths
- buffer sizes (worst case, with the terminating '\\0') and how size arithmetic avoids overflow
- edge cases: NULL, empty input, the largest inputs the requirement mentions
No code yet.""")


def implement_prompt(task, plan: str) -> list[dict]:
    return _msgs(f"{_base(task)}\n\nDesign plan:\n{plan.strip()}\n\nImplement the plan.\n\n{RULES}\n\n{FORMAT}")


def fix_prompt(task, code: str, feedback: str, history: list[dict], guidance: str = "") -> list[dict]:
    ref = f"\n\nReference guidance for these kinds of problems (from CWE and fix recipes):\n{guidance}" if guidance else ""
    return _msgs(f"""{_base(task)}

Current code:
```c
{code.strip()}
```

Testing and analysis found these problems (category/kind, tool, line, details):
{feedback}{ref}{_memory(history)}

Find the root cause of each problem and fix it without breaking the requirement.

{RULES}

{FORMAT}""")


def review_prompt(task, code: str, design_issues: list[str]) -> list[dict]:
    metrics = "\n".join(f"- {d}" for d in design_issues) or "- none over the limits"
    return _msgs(f"""{_base(task)}

Code (all tests and checks currently pass):
```c
{code.strip()}
```

Measured design metrics over their limits:
{metrics}

Review the code as a senior C reviewer. Report:
1. design_issues: concrete improvements to structure and readability (long or deeply nested functions,
   duplicated logic, unclear names, magic numbers, ownership that is hard to follow). Each with a line and a fix.
2. suspected_problems: inputs or situations where the code might still be wrong, leak, overflow a buffer,
   crash, or use too much time or memory, that the tests may have missed. Each with a category (bug, leak,
   overuse, vuln, crash) and the input that would trigger it.
Only list real, specific issues; empty lists are fine. Reply with JSON only:
{{"design_issues": [{{"line": 12, "issue": "...", "fix": "..."}}],
 "suspected_problems": [{{"category": "vuln", "problem": "...", "trigger": "..."}}]}}""")


def probe_prompt(task, code: str, suspicion: dict) -> list[dict]:
    return _msgs(f"""{_base(task)}

Code:
```c
{code.strip()}
```

Suspected problem ({suspicion.get('category', '?')}): {suspicion.get('problem', '')}
Trigger: {suspicion.get('trigger', '')}

Write a targeted test that triggers this situation. It is pasted inside a function body of a harness that
already includes the code and the standard headers, and provides CHECK(cond), CHECK_INT(got, want),
CHECK_STR(got, want) (accepts NULL). The harness runs it under AddressSanitizer and a leak tracker, so a
memory error or leak is detected even without a CHECK. Only CHECK what the requirement guarantees. Free
everything the function returns. Never dereference a result before checking it for NULL.
Reply with one block:
```c probe
// statements only
```""")


def refine_prompt(task, code: str, issues: list[str], history: list[dict]) -> list[dict]:
    listed = "\n".join(f"- {i}" for i in issues)
    return _msgs(f"""{_base(task)}

Current code (correct: all tests, sanitizers, leak checks and performance checks pass):
```c
{code.strip()}
```

Improve the design to address these issues:
{listed}{_memory(history)}

Refactor only: keep the behaviour, the interface, the time complexity and every safety property. Prefer small
static helper functions with clear names, named constants, and early returns over deep nesting.

{FORMAT}""")


def parse_review(text: str) -> dict:
    """Best effort: the first JSON object in the reply, else empty lists."""
    for m in re.finditer(r"\{", text):
        depth = 0
        for j in range(m.start(), len(text)):
            depth += text[j] == "{"
            depth -= text[j] == "}"
            if depth == 0:
                try:
                    d = json.loads(text[m.start():j + 1])
                except json.JSONDecodeError:
                    break
                if isinstance(d, dict):
                    return {"design_issues": [x for x in d.get("design_issues", []) if isinstance(x, dict)],
                            "suspected_problems": [x for x in d.get("suspected_problems", []) if isinstance(x, dict)]}
                break
    return {"design_issues": [], "suspected_problems": []}
