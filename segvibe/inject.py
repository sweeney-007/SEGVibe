"""Bug injection: small, realistic mutations of a correct solution.

Each mutant is labelled with the category it should produce. Together with
the hand-written variants in the task files they measure what each layer of
analysis catches (scripts/eval_detect.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Mutant:
    op: str
    kind: str      # expected category
    note: str
    code: str


def _each(code: str, pattern: str, repl, flags=re.M):
    """One mutant per match of pattern."""
    for m in re.finditer(pattern, code, flags):
        new = code[:m.start()] + (repl(m) if callable(repl) else repl) + code[m.end():]
        if new != code:
            yield m, new


def _line(code: str, pos: int) -> int:
    return code.count("\n", 0, pos) + 1


def mutants(code: str) -> list[Mutant]:
    out: list[Mutant] = []
    # leak: drop one free(...) of a local (not inside a cleanup helper's loop over a parameter)
    for m, new in _each(code, r"^[ \t]*free\((\w+)\);[ \t]*\n", ""):
        out.append(Mutant("drop_free", "leak", f"removed free({m.group(1)}) on line {_line(code, m.start())}", new))
    # leak: drop one fclose(...)
    for m, new in _each(code, r"^[ \t]*fclose\((\w+)\);[ \t]*\n", ""):
        out.append(Mutant("drop_fclose", "leak", f"removed fclose({m.group(1)}) on line {_line(code, m.start())}", new))
    # vuln: allocation one byte short (drops the room for the terminator)
    for m, new in _each(code, r"malloc\(([^;]*?) \+ 1\)", lambda m: f"malloc({m.group(1)})"):
        out.append(Mutant("alloc_minus_one", "vuln", f"malloc(... + 1) -> malloc(...) on line {_line(code, m.start())}", new))
    # vuln: off-by-one loop bound
    for m, new in _each(code, r"(for \([^;]*; \w+(?: \+ \d+)?) < (\w+;)", lambda m: f"{m.group(1)} <= {m.group(2)}"):
        out.append(Mutant("loop_le", "vuln", f"loop bound < -> <= on line {_line(code, m.start())}", new))
    # crash: drop the NULL check right after an allocation
    for m, new in _each(code, r"(=\s*(?:malloc|calloc|realloc|strdup)\([^;]*\);\n)([ \t]*if \(!\w+\) return [^;]*;\n)",
                        lambda m: m.group(1)):
        out.append(Mutant("drop_null_check", "crash", f"removed allocation check on line {_line(code, m.end(1))}", new))
    # bug: flip a comparison inside an if condition
    for m, new in list(_each(code, r"(if \([^()]*?) (<=|>=) ", lambda m: f"{m.group(1)} {'<' if m.group(2) == '<=' else '>'} "))[:2]:
        out.append(Mutant("flip_cmp", "bug", f"{m.group(2)} -> strict on line {_line(code, m.start())}", new))
    return out
