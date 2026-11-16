"""Resource checks: time growth and peak heap, compared with the reference.

Absolute times depend on the machine, so the checks are relative:
1. calibrate N so the reference takes ~30 ms (once per task),
2. run the candidate at N and 4N: time growth exponent = log(t4N / tN) / log 4,
3. compare time and peak heap at 4N with the reference at 4N.
"""
from __future__ import annotations

import math
import re
import tempfile
from pathlib import Path

from segvibe.checks.build import build, run, write_sources
from segvibe.findings import Finding, Report
from segvibe.task import Task

_PERF = re.compile(r"SEGV_PERF (\d+) (\d+)")
TARGET_S = 0.03
MAX_N = 1 << 26
# Perf runs get a fixed 1 MB stack. The input size n is picked by timing, so it differs between machines;
# with the default 8 MB stack, recursion depth proportional to n overflowed on one machine and not on
# another. At n of 1e5 or more, 1 MB catches any per-element recursion, and the iterative references fit.
PERF_STACK = 1 << 20
_REF: dict[str, dict] = {}


def measure(workdir: Path, n: int, reps: int = 3, timeout: float = 10) -> tuple[float, int] | str:
    """Best-of-reps (seconds, peak heap bytes) at size n, or "timeout" / "crash"."""
    best, peak = math.inf, 0
    for _ in range(reps):
        r = run(workdir, "perf", ["perf", str(n)], timeout, stack_bytes=PERF_STACK)
        m = _PERF.search(r.stdout)
        if r.timed_out:
            return "timeout"
        if not m:
            return "crash"
        best, peak = min(best, int(m.group(1)) / 1e9), max(peak, int(m.group(2)))
    return best, peak


def reference_profile(task: Task) -> dict | None:
    if task.id in _REF:
        return _REF[task.id]
    with tempfile.TemporaryDirectory(prefix="segv_ref_") as d:
        wd = Path(d)
        write_sources(wd, task.reference, task)
        ok, err = build(wd, "perf")
        if not ok:
            raise RuntimeError(f"reference for {task.id} does not build:\n{err}")
        n = task.perf_n0
        while True:
            m = measure(wd, n, reps=1)
            if isinstance(m, str):
                raise RuntimeError(f"reference for {task.id} fails the perf run at n={n}")
            if m[0] >= TARGET_S or n * 4 > MAX_N // 4:
                break
            n *= 2 if m[0] > TARGET_S / 8 else 4
        t1, _ = measure(wd, n)
        t4, p4 = measure(wd, 4 * n)
    prof = {"n": n, "t_n": t1, "t_4n": t4, "peak_4n": p4, "exp": math.log(max(t4, 1e-9) / max(t1, 1e-9), 4)}
    _REF[task.id] = prof
    return prof


def check_perf(workdir: Path, task: Task, report: Report) -> None:
    ref = reference_profile(task)
    ok, err = build(workdir, "perf")
    if not ok:
        return
    n = ref["n"]
    budget = max(2.0, 40 * ref["t_4n"])
    a = measure(workdir, n, timeout=budget)
    b = measure(workdir, 4 * n, timeout=budget) if not isinstance(a, str) else a
    if isinstance(b, str):
        size = n if isinstance(a, str) else 4 * n
        if b == "crash":
            report.add(Finding("signal", "perf", "high",
                               f"crashed on a large input (n={size}), e.g. from deep recursion or a fixed-size buffer"))
        else:
            report.add(Finding("timeout", "perf", "high",
                               f"no result within {budget:.1f}s at n={size} "
                               f"(reference: {ref['t_4n'] * 1000:.0f} ms at n={4 * n})"))
        report.perf = {"ref": ref}
        return
    (t1, _), (t4, p4) = a, b
    exp = math.log(max(t4, 1e-9) / max(t1, 1e-9), 4)
    ratio = t4 / max(ref["t_4n"], 1e-9)
    mem_ratio = p4 / max(ref["peak_4n"], 1)
    report.perf = {"n": n, "t_4n": t4, "exp": round(exp, 2), "time_ratio": round(ratio, 2),
                   "peak_4n": p4, "mem_ratio": round(mem_ratio, 2), "ref": ref}
    allowed = max(task.complexity, ref["exp"]) + 0.45
    if exp > allowed and ratio > 3:
        report.add(Finding("slow-growth", "perf", "high",
                           f"time grows like n^{exp:.1f} (expected about n^{task.complexity:g}); "
                           f"{ratio:.0f}x slower than the reference at n={4 * n}"))
    elif ratio > 25:
        report.add(Finding("slow", "perf", "high", f"{ratio:.0f}x slower than the reference at n={4 * n}"))
    if p4 > 3 * ref["peak_4n"] + (1 << 20):
        report.add(Finding("memory-hog", "perf", "high",
                           f"peak heap {p4 / 1e6:.1f} MB vs {ref['peak_4n'] / 1e6:.1f} MB for the reference "
                           f"at n={4 * n}"))
