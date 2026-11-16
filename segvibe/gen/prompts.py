"""Prompts for generating, repairing and testing C code."""
from __future__ import annotations

import re

SYSTEM = "You are an expert C programmer. You write correct, memory-safe, efficient C11."

RULES = """\
Rules:
- Check every allocation; on failure free what you allocated and return the error value the requirement gives.
- Free everything you allocate that is not returned to the caller; close every file you open.
- Never read or write outside a buffer: size buffers for the worst case, including the terminating '\\0'.
- Handle empty input, NULL arguments and the largest inputs the requirement mentions.
- Do not let size or index arithmetic overflow; do not rely on signed overflow.
- Use an algorithm with the time complexity the requirement asks for; no recursion on input-sized data."""

FORMAT = "Return one complete C file in a single ```c block: the #includes and the function(s) only, no main()."


def generate_prompt(requirement: str, signature: str, safety_rules: bool = True) -> list[dict]:
    parts = [f"Requirement:\n{requirement.strip()}", f"Implement exactly this interface:\n{signature.strip()}"]
    if safety_rules:
        parts.append(RULES)
    parts.append(FORMAT)
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n\n".join(parts)}]


def repair_prompt(requirement: str, signature: str, code: str, feedback: str, safety_rules: bool = True,
                  guidance: str = "") -> list[dict]:
    parts = [f"Requirement:\n{requirement.strip()}", f"Interface:\n{signature.strip()}",
             f"Current code:\n```c\n{code.strip()}\n```",
             "Testing and analysis found these problems (category/kind, tool, line, details):\n" + feedback]
    if guidance:
        parts.append("Reference guidance for these kinds of problems (from CWE and fix recipes):\n" + guidance)
    parts.append("Fix every problem without breaking the requirement.")
    if safety_rules:
        parts.append(RULES)
    parts.append(FORMAT)
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n\n".join(parts)}]


TESTS_GUIDE = """\
Write tests for this C function. They are pasted inside function bodies of a harness that already includes
the implementation and the standard headers, and provides:
  CHECK(cond); CHECK_INT(got, want); CHECK_STR(got, want)   // CHECK_STR accepts NULL
  long segv_rand_int(long lo, long hi);                      // inclusive
  char *segv_rand_str(size_t maxlen, const char *alphabet);  // heap string, caller frees
  int *segv_rand_ints(size_t n, int lo, int hi);             // heap array, caller frees
Free everything the function returns, as the requirement says. Never dereference a result before checking it
for NULL. Return exactly two blocks:
```c tests
// 5-15 deterministic checks of normal cases, edge cases and invalid input
```
```c fuzz
// ONE random case (it runs hundreds of times): build a random input, call the function, CHECK properties
// that must always hold, free everything
```"""


def tests_prompt(requirement: str, signature: str) -> list[dict]:
    user = f"Requirement:\n{requirement.strip()}\n\nInterface:\n{signature.strip()}\n\n{TESTS_GUIDE}"
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


_BLOCK = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)


def extract_code(text: str) -> str:
    """The largest ```c block, or the whole reply when there is none."""
    blocks = [(info.strip(), body) for info, body in _BLOCK.findall(text)]
    c = [b for info, b in blocks if info.split()[:1] in (["c"], ["C"], []) or info.startswith("c ")]
    if c:
        return max(c, key=len).strip() + "\n"
    unterminated = re.search(r"```c\n(.*)$", text, re.S)   # reply cut off at max tokens
    return (unterminated.group(1) if unterminated else text).strip() + "\n"


def extract_tests(text: str) -> tuple[str, str]:
    blocks = {info.strip(): body for info, body in _BLOCK.findall(text)}
    tests = next((b for i, b in blocks.items() if "test" in i), "")
    fuzz = next((b for i, b in blocks.items() if "fuzz" in i), "")
    return tests.strip(), fuzz.strip()
