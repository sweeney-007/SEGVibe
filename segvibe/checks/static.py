"""Static checks with existing tools: compiler warnings, the Clang Static
Analyzer (path-sensitive), and cppcheck when it is installed."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from segvibe.checks.build import CC, RUNTIME
from segvibe.findings import Finding

_DIAG = re.compile(r"^\S*candidate\.c:(\d+):\d+: (warning|error): (.*?)(?: \[([^\]]+)\])?$", re.M)

_WARN = {  # compiler flag -> (kind, severity)
    "-Wformat-security": ("format-string", "high"),
    "-Wformat-nonliteral": ("format-string", "high"),
    "-Wuninitialized": ("uninitialized", "high"),
    "-Wsometimes-uninitialized": ("uninitialized", "high"),
    "-Wconditional-uninitialized": ("uninitialized", "medium"),
    "-Wreturn-type": ("warning", "high"),
    "-Warray-bounds": ("index-out-of-bounds", "high"),
    "-Wreturn-stack-address": ("stack-use-after-return", "high"),
    "-Wincompatible-pointer-types": ("warning", "medium"),
    "-Wint-conversion": ("warning", "medium"),
    "-Wimplicit-function-declaration": ("warning", "medium"),
    "-Wfortify-source": ("unbounded-copy", "high"),
}

ANALYZER_CHECKERS = "core,unix,security,nullability"
ANALYZER_OFF = "deadcode,security.insecureAPI.DeprecatedOrUnsafeBufferHandling"


def compiler_warnings(workdir: Path) -> tuple[bool, list[Finding]]:
    r = subprocess.run([CC, "-std=gnu11", "-fsyntax-only", "-Wall", "-Wextra", "-Wformat=2",
                        "-Wno-unused-parameter", "-Wno-unused-function", "-include", str(RUNTIME / "segv_std.h"),
                        "candidate.c"], capture_output=True, text=True, cwd=workdir)
    fs = []
    for line, level, msg, flag in _DIAG.findall(r.stderr):
        if level == "error":
            fs.append(Finding("compile-error", "compiler", "high", msg, line=int(line)))
            continue
        flag = (flag or "").split(",")[0]
        kind, sev = _WARN.get(flag, ("warning", "low"))
        fs.append(Finding(kind, "compiler", sev, f"{msg} [{flag}]" if flag else msg, line=int(line)))
    return r.returncode == 0, fs


def _analyzer_kind(checker: str, msg: str) -> tuple[str, str]:
    m = msg.lower()
    if checker.startswith("unix.Malloc") or "leak" in m:
        if "leak" in m:
            return "memory-leak", "high"
        if "after it is freed" in m or "use of memory after" in m:
            return "use-after-free", "high"
        if "released memory" in m:
            return "double-free", "high"
        if "free" in m:
            return "bad-free", "high"
    if checker.endswith("Stream"):
        if "never closed" in m or "leak" in m:
            return "file-handle-leak", "high"
        if "null" in m:
            return "null-dereference", "high"
        return "warning", "low"
    if "null pointer" in m or "nullability" in checker or checker == "unix.cstring.NullArg":
        return "null-dereference", "high"
    if checker == "core.DivideZero":
        return "division-by-zero", "high"
    if "uninitialized" in m or "garbage" in m or checker.startswith("core.uninitialized"):
        return "uninitialized", "high"
    if checker == "core.StackAddressEscape":
        return "stack-use-after-return", "high"
    if "out of bound" in m or "ArrayBound" in checker or "OutOfBounds" in checker:
        return "index-out-of-bounds", "high"
    if checker == "security.insecureAPI.gets":
        return "dangerous-function", "high"
    if checker.startswith("security.insecureAPI"):
        return "unbounded-copy", "medium"
    if checker == "unix.cstring.BadSizeArg":
        return "unbounded-copy", "high"
    return "warning", "medium"


def clang_analyzer(workdir: Path) -> list[Finding]:
    r = subprocess.run([CC, "--analyze", "-std=gnu11", "-include", str(RUNTIME / "segv_std.h"),
                        "-Xanalyzer", "-analyzer-output=text",
                        "-Xanalyzer", f"-analyzer-checker={ANALYZER_CHECKERS}",
                        "-Xanalyzer", f"-analyzer-disable-checker={ANALYZER_OFF}",
                        "candidate.c", "-o", "/dev/null"], capture_output=True, text=True, cwd=workdir)
    fs = []
    for line, level, msg, checker in _DIAG.findall(r.stderr):
        if level != "warning" or not checker or checker.startswith("-W"):
            continue
        kind, sev = _analyzer_kind(checker, msg)
        fs.append(Finding(kind, "clang-analyzer", sev, f"{msg} [{checker}]", line=int(line)))
    return fs


_CPPCHECK = {
    "memleak": "memory-leak", "memleakOnRealloc": "realloc-leak", "resourceLeak": "file-handle-leak",
    "nullPointer": "null-dereference", "nullPointerRedundantCheck": "null-dereference",
    "ctunullpointer": "null-dereference",
    "arrayIndexOutOfBounds": "index-out-of-bounds", "bufferAccessOutOfBounds": "index-out-of-bounds",
    "outOfBounds": "index-out-of-bounds", "uninitvar": "uninitialized", "zerodiv": "division-by-zero",
    "doubleFree": "double-free", "deallocuse": "use-after-free", "returnDanglingLifetime": "stack-use-after-return",
}


def cppcheck(workdir: Path) -> list[Finding]:
    exe = shutil.which("cppcheck")
    if not exe:
        return []
    r = subprocess.run([exe, "--std=c11", "--enable=warning,performance,portability", "--quiet",
                        "--template={line}|{severity}|{id}|{message}", "candidate.c"],
                       capture_output=True, text=True, cwd=workdir)
    fs = []
    for row in r.stderr.splitlines():
        parts = row.split("|", 3)
        if len(parts) != 4 or not parts[0].isdigit():
            continue
        line, sev, cid, msg = parts
        kind = _CPPCHECK.get(cid, "warning")
        severity = "high" if sev == "error" else "medium" if sev == "warning" else "low"
        fs.append(Finding(kind, "cppcheck", severity, f"{msg} [{cid}]", line=int(line)))
    return fs
