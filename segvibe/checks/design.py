"""Design metrics from the AST (tree-sitter): measurable code-quality signals
for the agent's refactoring step.

Per function: length, cyclomatic complexity, deepest nesting, parameters.
Per file: duplicated 3-line windows and magic numbers. Each metric over its
threshold becomes a design issue. These are style findings: they never make
code "unclean", but the agent tries to reduce them without breaking any check.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter_c
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(tree_sitter_c.language()))

BRANCHES = {"if_statement", "for_statement", "while_statement", "do_statement", "case_statement",
            "conditional_expression", "catch_clause"}
NESTING = {"if_statement", "for_statement", "while_statement", "do_statement", "switch_statement"}
LIMITS = {"lines": 45, "complexity": 12, "nesting": 4, "params": 5}
_OK_NUMBERS = {"0", "1", "2", "-1", "10", "16", "0.0", "1.0"}


@dataclass
class FunctionMetrics:
    name: str
    line: int
    lines: int
    complexity: int
    nesting: int
    params: int


@dataclass
class DesignReport:
    functions: list[FunctionMetrics] = field(default_factory=list)
    duplicate_blocks: int = 0
    magic_numbers: int = 0
    issues: list[tuple[int | None, str]] = field(default_factory=list)

    @property
    def penalty(self) -> float:
        """Sum of how far each metric is over its limit (0 = no design issue)."""
        p = 0.0
        for f in self.functions:
            p += max(0, f.lines - LIMITS["lines"]) / 10 + max(0, f.complexity - LIMITS["complexity"])
            p += 2 * max(0, f.nesting - LIMITS["nesting"]) + max(0, f.params - LIMITS["params"])
        return p + 2 * self.duplicate_blocks + 0.25 * self.magic_numbers

    def summary(self) -> str:
        worst = max(self.functions, key=lambda f: f.complexity, default=None)
        s = f"{len(self.functions)} function(s)"
        if worst:
            s += f", max complexity {worst.complexity} ({worst.name}), max nesting {max(f.nesting for f in self.functions)}"
        return s + f", design penalty {self.penalty:.1f}"

    def to_dict(self) -> dict:
        return {"functions": [f.__dict__ for f in self.functions], "duplicate_blocks": self.duplicate_blocks,
                "magic_numbers": self.magic_numbers, "penalty": round(self.penalty, 2),
                "issues": [{"line": ln, "issue": msg} for ln, msg in self.issues]}


def _walk(n: Node):
    yield n
    for c in n.children:
        yield from _walk(c)


def _depth(n: Node, d: int = 0) -> int:
    d2 = d + (n.type in NESTING)
    return max([d2] + [_depth(c, d2) for c in n.children])


def _name(fn: Node) -> str:
    d = fn.child_by_field_name("declarator")
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    return d.child_by_field_name("declarator").text.decode() if d is not None else "?"


def _params(fn: Node) -> int:
    d = fn.child_by_field_name("declarator")
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    ps = d.child_by_field_name("parameters") if d is not None else None
    real = [c for c in (ps.named_children if ps else []) if c.type == "parameter_declaration"]
    return 0 if len(real) == 1 and real[0].text.decode() == "void" else len(real)


def analyze_design(code: str) -> DesignReport:
    tree = _PARSER.parse(code.encode())
    rep = DesignReport()
    for fn in (n for n in _walk(tree.root_node) if n.type == "function_definition"):
        body = fn.child_by_field_name("body")
        cc = 1
        for n in _walk(body):
            if n.type in BRANCHES:
                cc += 1
            elif n.type == "binary_expression" and n.child_by_field_name("operator").text in (b"&&", b"||"):
                cc += 1
        m = FunctionMetrics(_name(fn), fn.start_point[0] + 1, fn.end_point[0] - fn.start_point[0] + 1, cc,
                            _depth(body), _params(fn))
        rep.functions.append(m)
        for key, limit in LIMITS.items():
            if getattr(m, key) > limit:
                rep.issues.append((m.line, f"{m.name}(): {key} {getattr(m, key)} (limit {limit})"))
        for n in _walk(body):
            if n.type == "number_literal" and n.text.decode() not in _OK_NUMBERS and n.parent.type != "enumerator":
                rep.magic_numbers += 1
    # duplicated code: identical runs of 3 non-trivial lines (normalised whitespace)
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in code.splitlines()]
    seen: dict[tuple, int] = {}
    for i in range(len(lines) - 2):
        win = tuple(lines[i:i + 3])
        if sum(len(x) > 3 and x not in ("{", "}", "} else {") for x in win) < 3:
            continue
        if win in seen and i - seen[win] >= 3:
            rep.duplicate_blocks += 1
            rep.issues.append((i + 1, f"lines {i + 1}-{i + 3} repeat lines {seen[win] + 1}-{seen[win] + 3}"))
        seen.setdefault(win, i)
    if rep.magic_numbers > 3:
        rep.issues.append((None, f"{rep.magic_numbers} unexplained numeric constants; name them"))
    return rep
