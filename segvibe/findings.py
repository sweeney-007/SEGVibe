"""Findings and the per-candidate report."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

CATEGORIES = ("bug", "leak", "overuse", "vuln", "crash")

# kind -> (category, CWE)
KINDS = {
    # runtime: AddressSanitizer
    "heap-buffer-overflow": ("vuln", "CWE-122"),
    "stack-buffer-overflow": ("vuln", "CWE-121"),
    "global-buffer-overflow": ("vuln", "CWE-787"),
    "dynamic-stack-buffer-overflow": ("vuln", "CWE-121"),
    "heap-use-after-free": ("vuln", "CWE-416"),
    "stack-use-after-return": ("vuln", "CWE-562"),
    "stack-use-after-scope": ("vuln", "CWE-562"),
    "double-free": ("vuln", "CWE-415"),
    "bad-free": ("vuln", "CWE-590"),
    "memcpy-param-overlap": ("bug", "CWE-475"),
    "negative-size-param": ("vuln", "CWE-195"),
    "SEGV": ("crash", "CWE-476"),
    "stack-overflow": ("crash", "CWE-674"),
    "allocation-size-too-big": ("overuse", "CWE-789"),
    "out-of-memory": ("overuse", "CWE-789"),
    # runtime: UndefinedBehaviorSanitizer
    "signed-integer-overflow": ("bug", "CWE-190"),
    "division-by-zero": ("crash", "CWE-369"),
    "null-pointer-use": ("crash", "CWE-476"),
    "index-out-of-bounds": ("vuln", "CWE-787"),
    "invalid-shift": ("bug", "CWE-1335"),
    "misaligned-access": ("bug", "CWE-188"),
    "undefined-behavior": ("bug", "CWE-758"),
    # runtime: other
    "signal": ("crash", "CWE-248"),
    "abort": ("crash", "CWE-617"),
    "wrong-result": ("bug", "CWE-684"),
    "memory-leak": ("leak", "CWE-401"),
    "file-handle-leak": ("leak", "CWE-775"),
    "leak-on-alloc-failure": ("leak", "CWE-401"),
    "crash-on-alloc-failure": ("crash", "CWE-690"),
    "timeout": ("overuse", "CWE-835"),
    "slow-growth": ("overuse", "CWE-407"),
    "slow": ("overuse", "CWE-1050"),
    "memory-hog": ("overuse", "CWE-770"),
    # static
    "compile-error": ("bug", ""),
    "unbounded-copy": ("vuln", "CWE-120"),
    "dangerous-function": ("vuln", "CWE-242"),
    "format-string": ("vuln", "CWE-134"),
    "unchecked-alloc": ("crash", "CWE-690"),
    "realloc-leak": ("leak", "CWE-401"),
    "strlen-in-loop": ("overuse", "CWE-1050"),
    "uninitialized": ("bug", "CWE-457"),
    "use-after-free": ("vuln", "CWE-416"),
    "null-dereference": ("crash", "CWE-476"),
    "warning": ("bug", ""),
}


@dataclass
class Finding:
    kind: str
    tool: str
    severity: str             # high: seen at runtime or path-sensitive proof; medium: pattern; low: style
    message: str
    line: int | None = None
    category: str = ""
    cwe: str = ""

    def __post_init__(self):
        cat, cwe = KINDS.get(self.kind, ("bug", ""))
        self.category = self.category or cat
        self.cwe = self.cwe or cwe

    def key(self):
        return (self.kind, self.line)

    def text(self, code_lines: list[str] | None = None) -> str:
        where = f"line {self.line}" if self.line else "no line"
        s = f"[{self.category}/{self.kind}, {self.tool}, {where}] {self.message}"
        if code_lines and self.line and 0 < self.line <= len(code_lines):
            s += f"\n    {self.line}: {code_lines[self.line - 1].strip()}"
        return s


@dataclass
class Report:
    compiled: bool = False
    checks: int = 0
    fails: int = 0
    tests_passed: bool = False
    findings: list[Finding] = field(default_factory=list)
    perf: dict = field(default_factory=dict)
    seconds: float = 0.0

    def add(self, f: Finding):
        if all(f.key() != g.key() for g in self.findings):
            self.findings.append(f)

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def clean(self) -> bool:
        """Passes the tests and nothing serious was found."""
        return self.compiled and self.tests_passed and not self.high

    def categories(self, severities=("high",)) -> set[str]:
        return {f.category for f in self.findings if f.severity in severities}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["clean"] = self.clean
        return d

    def summary(self) -> str:
        if not self.compiled:
            return "does not compile"
        s = f"tests {self.checks - self.fails}/{self.checks}"
        cats = sorted(self.categories())
        s += ", clean" if self.clean else (", found: " + ", ".join(cats) if cats else "")
        return s

    def feedback(self, code: str, limit: int = 8) -> str:
        """What a code model needs to repair the code, most serious first."""
        lines = code.splitlines()
        order = {"high": 0, "medium": 1, "low": 2}
        fs = sorted(self.findings, key=lambda f: (order[f.severity], f.line or 0))
        fs = [f for f in fs if f.severity != "low"][:limit]
        out = [f.text(lines) for f in fs]
        if not self.compiled and not out:
            out.append("The code does not compile.")
        return "\n".join(out)
