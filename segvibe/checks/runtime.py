"""Dynamic checks: hidden tests, fuzzing and allocation-failure runs under
AddressSanitizer + UndefinedBehaviorSanitizer + the allocation tracker."""
from __future__ import annotations

import re
from pathlib import Path

from segvibe.checks.build import Run, run
from segvibe.findings import Finding, Report

_ASAN = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)(.*)")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)")
_UBSAN = re.compile(r"^(\S+?):(\d+):\d+: runtime error: (.*)$", re.M)
_LEAK = re.compile(r"^SEGV_LEAK (\d+) (\d+) (\S+):(\d+)$", re.M)
_FLEAK = re.compile(r"^SEGV_FILE_LEAK (\S+):(\d+)$", re.M)
_FAIL = re.compile(r"^SEGV_FAIL (.*)$", re.M)
_DONE = re.compile(r"SEGV_DONE checks=(\d+) fails=(\d+)")
_ALLOCS = re.compile(r"SEGV_ALLOCS (\d+)")
_PEAK = re.compile(r"SEGV_PEAK (\d+)")
_BIG = re.compile(r"^SEGV_BIGALLOC (\d+) (\S+):(\d+)$", re.M)

_ASAN_KIND = {
    "attempting": None,   # resolved from the rest of the line
    "requested": "allocation-size-too-big",
    "allocation-size-too-big": "allocation-size-too-big",
    "calloc-overflow": "allocation-size-too-big",
    "out": "out-of-memory",
    "BUS": "SEGV",
    "FPE": "division-by-zero",
    "ABRT": "abort",
    "unknown-crash": "SEGV",
}


def _asan_kind(word: str, rest: str) -> str:
    if word == "attempting":
        return "double-free" if "double-free" in rest else "bad-free"
    return _ASAN_KIND.get(word, word)


def _ubsan_kind(msg: str) -> str:
    m = msg.lower()
    if "signed integer overflow" in m or "negation of" in m:
        return "signed-integer-overflow"
    if "division by zero" in m:
        return "division-by-zero"
    if "null pointer" in m:
        return "null-pointer-use"
    if "out of bounds" in m:
        return "index-out-of-bounds"
    if "shift" in m:
        return "invalid-shift"
    if "misaligned" in m:
        return "misaligned-access"
    return "undefined-behavior"


def _is_candidate(path: str) -> bool:
    return path.endswith("candidate.c")


def _trigger(frames, tests_src: str) -> str:
    """The hidden-test statement on the crashing stack, so the model sees which input broke the code."""
    lines = tests_src.splitlines()
    ln = next((int(n) for _, path, n in frames if path == "tests"), 0)
    return f"; triggered by the test `{lines[ln - 1].strip()[:160]}`" if 0 < ln <= len(lines) else ""


def parse(r: Run, when: str, *, allocfail: bool = False, heap_limit: int = 0,
          tests_src: str = "") -> tuple[list[Finding], int, int]:
    """Findings from one run, plus (checks, fails). `when` is used in messages."""
    fs: list[Finding] = []
    err = r.stderr
    sev = "medium" if allocfail else "high"
    tool = "allocfail" if allocfail else "asan"

    m = _ASAN.search(err)
    if m:
        kind = _asan_kind(m.group(1), m.group(2))
        frames = _FRAME.findall(err[m.end():])
        cand = next(((fn, int(ln)) for fn, path, ln in frames if _is_candidate(path)), None)
        if allocfail and kind in ("SEGV", "null-pointer-use"):
            kind = "crash-on-alloc-failure"
        if cand or not allocfail:
            where = f" in {cand[0]}()" if cand else " in the test code, on a value the function returned"
            fs.append(Finding(kind, tool, sev, f"{m.group(1)}{m.group(2).split(' on ')[0][:60]}{where} {when}{_trigger(frames, tests_src)}",
                              line=cand[1] if cand else None))

    for path, ln, msg in _UBSAN.findall(err):
        if _is_candidate(path):
            kind = _ubsan_kind(msg)
            if allocfail and kind == "null-pointer-use":
                kind = "crash-on-alloc-failure"
            fs.append(Finding(kind, "allocfail" if allocfail else "ubsan", sev, f"{msg[:120]} {when}", line=int(ln)))

    for blocks, nbytes, path, ln in _LEAK.findall(err):
        if _is_candidate(path):
            kind = "leak-on-alloc-failure" if allocfail else "memory-leak"
            fs.append(Finding(kind, "allocfail" if allocfail else "leakcheck", sev,
                              f"{blocks} block(s), {nbytes} bytes allocated here are never freed {when}",
                              line=int(ln)))
    for path, ln in _FLEAK.findall(err):
        if _is_candidate(path):
            fs.append(Finding("file-handle-leak", "leakcheck", sev, f"file opened here is never closed {when}",
                              line=int(ln)))

    for nbytes, path, ln in _BIG.findall(err)[:1]:
        fs.append(Finding("allocation-size-too-big", "leakcheck", "high",
                          f"tried to allocate {int(nbytes) / 1e9:.1f} GB {when}",
                          line=int(ln) if _is_candidate(path) else None))
    peak = _PEAK.search(err)
    if heap_limit and peak and int(peak.group(1)) > heap_limit and not allocfail:
        fs.append(Finding("memory-hog", "leakcheck", "high",
                          f"peak heap {int(peak.group(1)) / 1e6:.1f} MB {when}, limit {heap_limit / 1e6:.1f} MB"))

    done = _DONE.search(err)
    checks, fails = (int(done.group(1)), int(done.group(2))) if done else (0, 0)
    if r.timed_out:
        fs.append(Finding("timeout", "tests", sev, f"did not finish {when} (infinite loop or far too slow)"))
    elif not done and not m and not allocfail:
        fs.append(Finding("signal", tool, sev, f"process died (exit {r.returncode}) {when}"))
    if fails and not allocfail:
        first = "; ".join(_FAIL.findall(err)[:3])
        fs.append(Finding("wrong-result", "tests", "high", f"{fails} check(s) failed {when}: {first}"))
    return fs, checks, fails


def run_tests(workdir: Path, report: Report, timeout: float = 10, heap_limit: int = 0, tests_src: str = "") -> int:
    """Hidden tests. Returns how many allocations they made (for allocfail)."""
    r = run(workdir, "san", ["test"], timeout)
    fs, checks, fails = parse(r, "during the tests", heap_limit=heap_limit, tests_src=tests_src)
    for f in fs:
        report.add(f)
    report.checks, report.fails = checks, fails
    report.tests_passed = "SEGV_DONE" in r.stderr and not fails and not any(f.severity == "high" for f in fs)
    m = _ALLOCS.search(r.stderr)
    return int(m.group(1)) if m else 0


def run_fuzz(workdir: Path, report: Report, seeds: int = 4, iters: int = 300, timeout: float = 20,
             heap_limit: int = 0) -> None:
    for seed in range(1, seeds + 1):
        r = run(workdir, "san", ["fuzz", str(seed), str(iters)], timeout)
        fs, _, _ = parse(r, f"on random inputs (fuzz seed {seed})", heap_limit=heap_limit)
        for f in fs:
            f.tool = "fuzz" if f.tool in ("asan", "tests") else f.tool
            report.add(f)
        if any(f.severity == "high" for f in fs):
            break


def run_allocfail(workdir: Path, report: Report, n_allocs: int, max_runs: int = 25, timeout: float = 10) -> None:
    """Make allocation #k fail, k = 1..n: the code must not crash or leak."""
    for k in range(1, min(n_allocs, max_runs) + 1):
        r = run(workdir, "san", ["test"], timeout, env={"SEGV_FAIL_ALLOC": str(k)})
        fs, _, _ = parse(r, f"when allocation #{k} fails", allocfail=True)
        for f in fs:
            report.add(f)
