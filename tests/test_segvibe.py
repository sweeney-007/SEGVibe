"""Fast tests (no model needed). Requires clang."""
from __future__ import annotations

import pytest

from segvibe.check import CheckConfig, check
from segvibe.checks.rules import check_rules
from segvibe.gen.loop import solve
from segvibe.gen.models import Scripted
from segvibe.gen.prompts import extract_code, extract_tests
from segvibe.inject import mutants
from segvibe.task import load_tasks

FAST = CheckConfig(perf=False, fuzz_seeds=2, fuzz_iters=100)


@pytest.fixture(scope="module")
def tasks():
    return {t.id: t for t in load_tasks()}


def kinds(rep):
    return {f.kind for f in rep.findings}


def test_task_files_load(tasks):
    assert len(tasks) >= 15
    for t in tasks.values():
        assert t.requirement and t.signature and t.reference and t.tests


@pytest.mark.parametrize("tid", ["reverse_words", "split_words", "read_lines", "linked_list"])
def test_references_are_clean(tasks, tid):
    rep = check(tasks[tid].reference, tasks[tid], FAST)
    assert rep.clean, rep.feedback(tasks[tid].reference)
    assert not [f for f in rep.findings if f.severity == "medium"]


def test_heap_overflow_is_found_at_the_right_line(tasks):
    t = tasks["url_decode"]
    rep = check(t.variants[0].code, t, FAST)
    f = next(f for f in rep.findings if f.kind.endswith("buffer-overflow"))
    assert f.category == "vuln" and f.line and "hexval" in t.variants[0].code.splitlines()[f.line - 1]


def test_leaks_and_open_files_are_tracked(tasks):
    t = tasks["read_lines"]
    leak = next(v for v in t.variants if v.kind == "leak")
    rep = check(leak.code, t, FAST)
    assert "file-handle-leak" in kinds(rep)
    code = t.reference.replace("    free(buf);\n    *count = k;", "    *count = k;")
    rep = check(code, t, FAST)
    assert "memory-leak" in kinds(rep) and not rep.clean


def test_use_after_free_and_signed_overflow(tasks):
    t = tasks["linked_list"]
    assert "heap-use-after-free" in kinds(check(t.variants[0].code, t, FAST))
    t = tasks["parse_int"]
    assert "signed-integer-overflow" in kinds(check(t.variants[0].code, t, FAST))


def test_allocation_failure_paths(tasks):
    t = tasks["split_words"]
    rep = check(t.variants[0].code, t, FAST)       # leaks pieces when a later allocation fails
    assert "leak-on-alloc-failure" in kinds(rep)
    assert rep.clean                                # medium severity: reported, not blocking


def test_huge_allocation_is_refused(tasks):
    t = tasks["repeat_string"]
    rep = check(t.variants[0].code, t, FAST)
    assert not rep.clean and rep.categories() & {"vuln", "overuse"}


def test_quadratic_code_is_flagged_by_the_profile(tasks):
    t = tasks["join_strings"]
    rep = check(t.variants[0].code, t, CheckConfig(fuzz=False, allocfail=False))
    assert rep.tests_passed and "overuse" in rep.categories()
    assert check(t.reference, t, CheckConfig(fuzz=False, allocfail=False)).clean


def test_compile_errors_and_wrong_signatures(tasks):
    t = tasks["reverse_words"]
    rep = check("char *reverse_words(const char *s) { return s }", t, FAST)
    assert not rep.compiled and "compile-error" in kinds(rep)
    rep = check("#include <stdlib.h>\nint reverse_words(int x) { return x; }\n", t, FAST)
    assert not rep.compiled


def test_ast_rules():
    code = """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    void f(const char *s, char *buf) {
        char *p = malloc(10);
        strcpy(buf, s);
        printf(s);
        for (size_t i = 0; i < strlen(s); i++) buf[i] = s[i];
        p = realloc(p, 20);
        if (p) free(p);
    }
    """
    got = {f.kind for f in check_rules(code)}
    assert {"unbounded-copy", "format-string", "strlen-in-loop", "realloc-leak"} <= got
    ok = "#include <stdlib.h>\nint *g(void) { int *p = malloc(4); if (!p) return NULL; return p; }\n"
    assert not check_rules(ok)


def test_mutants_are_labelled(tasks):
    ms = mutants(tasks["split_words"].reference)
    ops = {m.op for m in ms}
    assert {"drop_free", "alloc_minus_one", "drop_null_check"} <= ops
    assert all(m.code != tasks["split_words"].reference for m in ms)


def test_extract_code_and_tests():
    reply = "Here:\n```c\n#include <stdio.h>\nint f(void) { return 1; }\n```\nDone."
    assert extract_code(reply).startswith("#include")
    assert "int f" in extract_code("```c\nint f(void) {")          # cut off at max tokens
    tests, fuzz = extract_tests("```c tests\nCHECK(1);\n```\n```c fuzz\nCHECK(2);\n```")
    assert tests == "CHECK(1);" and fuzz == "CHECK(2);"


def test_repair_loop_feeds_findings_back(tasks):
    t = tasks["reverse_words"]
    bad = t.reference.replace("malloc(n + 1)", "malloc(n)")
    gen = Scripted([f"```c\n{bad}```", f"```c\n{t.reference}```"])
    sol = solve(t, gen, rounds=2, cfg=FAST)
    assert len(sol.attempts) == 2
    assert not sol.first.report.clean and sol.best.report.clean
    repair = gen.calls[1][-1]["content"]
    assert "heap-buffer-overflow" in repair and "malloc(n)" in repair
