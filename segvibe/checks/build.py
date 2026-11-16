"""Build a candidate into a harness binary, and run it with limits."""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

from segvibe.task import Task

RUNTIME = Path(__file__).resolve().parents[1] / "runtime"
CC = os.environ.get("SEGV_CC") or shutil.which("clang") or "cc"

HARNESS = """\
#define main segv_user_main
#include "candidate.c"
#undef main
#include "segv_harness.h"
#line 1 "helpers"
{helpers}
#line 7 "harness.c"
__attribute__((noinline)) static void segv_tests(void) {{
#line 1 "tests"
{tests}
}}
#line 12 "harness.c"
__attribute__((noinline)) static void segv_fuzz(void) {{
#line 1 "fuzz"
{fuzz}
}}
#line 17 "harness.c"
static void segv_perf(long N) {{
    (void)N;
#line 1 "perf"
{perf}
}}
#line 23 "harness.c"
int main(int argc, char **argv) {{
    const char *mode = argc > 1 ? argv[1] : "test";
    if (getenv("SEGV_FAIL_ALLOC")) segv_quiet = 1;
    if (!strcmp(mode, "test")) {{
        segv_tests();
    }} else if (!strcmp(mode, "fuzz")) {{
        segv_rng ^= (uint64_t)atoll(argv[2]) * 0x9E3779B97F4A7C15ULL;
        if (!segv_rng) segv_rng = 1;
        long iters = atol(argv[3]);
        for (long i = 0; i < iters; i++) segv_fuzz();
    }} else if (!strcmp(mode, "perf")) {{
        long n = atol(argv[2]);
        segv_track_reset_peak();
        long long t0 = segv_now_ns();
        segv_perf(n);
        long long t1 = segv_now_ns();
        printf("SEGV_PERF %lld %zu\\n", t1 - t0, segv_track_peak());
    }}
    fprintf(stderr, "SEGV_DONE checks=%d fails=%d\\n", segv_checks, segv_fails);
    segv_track_report();
    return segv_fails ? 1 : 0;
}}
"""

PROFILES = {
    "san": ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"],
    "perf": ["-O2"],
}

ENV = {
    # leaks come from the tracker (LeakSanitizer is unavailable on macOS)
    "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=0:symbolize=1:detect_stack_use_after_return=1:max_allocation_size_mb=1024",
    "UBSAN_OPTIONS": "print_stacktrace=1",
}


@dataclass
class Run:
    returncode: int | None    # None = timed out
    stdout: str
    stderr: str

    @property
    def timed_out(self) -> bool:
        return self.returncode is None


def write_sources(workdir: Path, code: str, task: Task) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "candidate.c").write_text(code)
    (workdir / "harness.c").write_text(HARNESS.format(helpers=task.helpers, tests=task.tests, fuzz=task.fuzz, perf=task.perf))


def build(workdir: Path, profile: str) -> tuple[bool, str]:
    """Compile harness.c (which #includes candidate.c) with a build profile."""
    flags = ["-std=gnu11", *PROFILES[profile]]
    obj = workdir / f"track_{profile}.o"
    exe = workdir / f"h_{profile}"
    r = subprocess.run([CC, *flags, "-w", "-c", str(RUNTIME / "segv_track.c"), "-o", str(obj)],
                       capture_output=True, text=True)
    if r.returncode:
        return False, r.stderr
    r = subprocess.run([CC, *flags, "-w", "-include", str(RUNTIME / "segv_track.h"), "-I", str(RUNTIME),
                        str(workdir / "harness.c"), str(obj), "-o", str(exe), "-lm"],
                       capture_output=True, text=True, cwd=workdir)
    return r.returncode == 0, r.stderr


def run(workdir: Path, profile: str, args: list[str], timeout: float, env: dict | None = None) -> Run:
    exe = workdir / f"h_{profile}"
    full_env = {**os.environ, **ENV, **(env or {})}
    p = subprocess.Popen([str(exe), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env=full_env, cwd=workdir, start_new_session=True)
    try:
        out, err = p.communicate(timeout=timeout)
        return Run(p.returncode, out, err)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        return Run(None, out, err)
