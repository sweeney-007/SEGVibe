"""AST rules (tree-sitter): patterns that are risky in C even when the tests pass.

These are syntax-level checks, cheaper and noisier than the path-sensitive
analyzer, so most are reported as medium severity (fed back to the model,
but they do not decide whether code is clean on their own).
"""
from __future__ import annotations

import re

import tree_sitter_c
from tree_sitter import Language, Node, Parser

from segvibe.findings import Finding

_PARSER = Parser(Language(tree_sitter_c.language()))

ALLOCATORS = {"malloc", "calloc", "realloc", "strdup", "strndup"}
UNBOUNDED = {"strcpy", "strcat", "sprintf", "vsprintf"}
FORMAT_ARG = {"printf": 0, "vprintf": 0, "fprintf": 1, "sprintf": 1, "vfprintf": 1, "snprintf": 2, "syslog": 1}
SCANF = {"scanf": 0, "sscanf": 1, "fscanf": 1}


def _walk(n: Node):
    yield n
    for c in n.children:
        yield from _walk(c)


def _text(n: Node | None) -> str:
    return n.text.decode() if n is not None else ""


def _call_name(call: Node) -> str:
    return _text(call.child_by_field_name("function"))


def _args(call: Node) -> list[Node]:
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a else []


def _conditions(fn: Node) -> list[str]:
    out = []
    for n in _walk(fn):
        if n.type in ("if_statement", "while_statement", "do_statement", "for_statement", "conditional_expression"):
            c = n.child_by_field_name("condition")
            if c is not None:
                out.append(_text(c))
        elif n.type == "binary_expression" and _text(n.child_by_field_name("operator")) in ("&&", "||"):
            out.append(_text(n))
    return out


def _alloc_target(call: Node) -> str | None:
    """`x = malloc(..)` / `T *x = malloc(..)` -> "x" (casts are skipped)."""
    p = call.parent
    while p is not None and p.type in ("cast_expression", "parenthesized_expression"):
        p = p.parent
    if p is None:
        return None
    if p.type == "assignment_expression":
        return _text(p.child_by_field_name("left"))
    if p.type == "init_declarator":
        d = p.child_by_field_name("declarator")
        while d is not None and d.type == "pointer_declarator":
            d = d.child_by_field_name("declarator")
        return _text(d)
    return None


def check_rules(code: str) -> list[Finding]:
    tree = _PARSER.parse(code.encode())
    fs: list[Finding] = []
    for fn in (n for n in _walk(tree.root_node) if n.type == "function_definition"):
        conds = _conditions(fn)
        for n in _walk(fn):
            if n.type == "call_expression":
                name, args, line = _call_name(n), _args(n), n.start_point[0] + 1
                if name == "gets":
                    fs.append(Finding("dangerous-function", "ast-rules", "high",
                                      "gets() cannot limit input length; use fgets()", line))
                elif name in UNBOUNDED:
                    fs.append(Finding("unbounded-copy", "ast-rules", "medium",
                                      f"{name}() does not check the destination size", line))
                if name in FORMAT_ARG and len(args) > FORMAT_ARG[name]:
                    fmt = args[FORMAT_ARG[name]]
                    if fmt.type not in ("string_literal", "concatenated_string"):
                        fs.append(Finding("format-string", "ast-rules", "high",
                                          f"{name}() format is not a string literal", line))
                if name in SCANF and len(args) > SCANF[name]:
                    fmt = _text(args[SCANF[name]])
                    if re.search(r"%s|%\[", fmt):
                        fs.append(Finding("unbounded-copy", "ast-rules", "high",
                                          f"{name}() reads a string with no width limit", line))
                if name in ALLOCATORS:
                    target = _alloc_target(n)
                    if name == "realloc" and target and args and _text(args[0]) == target:
                        fs.append(Finding("realloc-leak", "ast-rules", "medium",
                                          f"`{target} = realloc({target}, ..)` loses the old block if realloc fails",
                                          line))
                    if target and not any(re.search(rf"(?<![\w.>]){re.escape(target)}(?!\w)", c) for c in conds):
                        fs.append(Finding("unchecked-alloc", "ast-rules", "medium",
                                          f"result of {name}() stored in `{target}` is never checked for NULL",
                                          line))
            elif n.type in ("for_statement", "while_statement"):
                c = n.child_by_field_name("condition")
                if c is not None and re.search(r"\bstrlen\s*\(", _text(c)):
                    fs.append(Finding("strlen-in-loop", "ast-rules", "medium",
                                      "strlen() in the loop condition re-scans the string every iteration (O(n^2))",
                                      n.start_point[0] + 1))
    return fs
