"""Run every check on one candidate and return a Report."""
from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from segvibe.checks import perf, runtime, static
from segvibe.checks.build import build, write_sources
from segvibe.checks.rules import check_rules
from segvibe.findings import Finding, Report
from segvibe.task import Task


@dataclass
class CheckConfig:
    static: bool = True         # compiler warnings, clang analyzer, cppcheck
    rules: bool = True          # tree-sitter AST rules
    tests: bool = True          # hidden tests under ASan + UBSan + leak tracker
    fuzz: bool = True
    fuzz_seeds: int = 4
    fuzz_iters: int = 300
    allocfail: bool = True      # make each allocation fail in turn
    perf: bool = True           # time growth and peak heap vs the reference


def check(code: str, task: Task, cfg: CheckConfig | None = None, workdir: Path | None = None) -> Report:
    cfg = cfg or CheckConfig()
    t0 = time.time()
    report = Report()
    with tempfile.TemporaryDirectory(prefix="segv_") as tmp:
        wd = workdir or Path(tmp)
        write_sources(wd, code, task)

        compiled, warn = static.compiler_warnings(wd)
        if not compiled:
            for f in warn:
                report.add(f)
            report.seconds = time.time() - t0
            return report
        ok, err = build(wd, "san")
        if not ok:   # candidate compiles alone but not against the task's tests (wrong signature)
            msg = next((l for l in err.splitlines() if "error:" in l), err.strip()[:200])
            report.add(Finding("compile-error", "compiler", "high", f"does not match the required signature: {msg}"))
            report.seconds = time.time() - t0
            return report
        report.compiled = True

        if cfg.static:
            for f in warn + static.clang_analyzer(wd) + static.cppcheck(wd):
                report.add(f)
        if cfg.rules:
            for f in check_rules(code):
                report.add(f)
        n_allocs = runtime.run_tests(wd, report, heap_limit=task.heap_limit, tests_src=task.tests) if cfg.tests else 0
        crashed = any(f.category in ("crash", "vuln") and f.severity == "high" and f.tool in ("asan", "ubsan")
                      for f in report.findings)
        if cfg.fuzz and task.fuzz and not crashed:
            runtime.run_fuzz(wd, report, cfg.fuzz_seeds, cfg.fuzz_iters, heap_limit=task.heap_limit)
        if cfg.allocfail and n_allocs:
            runtime.run_allocfail(wd, report, n_allocs)
        if cfg.perf and task.perf and report.tests_passed:
            perf.check_perf(wd, task, report)
    report.seconds = time.time() - t0
    return report
