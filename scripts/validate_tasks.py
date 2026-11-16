"""Check the task set itself: every reference must be clean (no findings above
low severity), and every hand-written variant must be caught.

    uv run python scripts/validate_tasks.py [task_id ...]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from segvibe.check import check  # noqa: E402
from segvibe.task import load_tasks  # noqa: E402


def main():
    ok = True
    for t in load_tasks(sys.argv[1:] or None):
        r = check(t.reference, t)
        noisy = [f for f in r.findings if f.severity != "low"]
        status = "ok" if r.clean and not noisy else "PROBLEM"
        ok &= status == "ok"
        print(f"{t.id:22s} reference {r.summary():30s} {r.seconds:5.1f}s {status}")
        for f in noisy:
            print("      ", f.severity, f.text())
        for v in t.variants:
            rv = check(v.code, t)
            caught = v.kind in rv.categories(("high", "medium"))
            ok &= caught or bool(rv.high)
            print(f"{'':22s} variant {v.kind:8s} -> {rv.summary():40s} {'ok' if caught else 'CAUGHT AS OTHER' if rv.high or rv.categories(("medium",)) else 'MISSED'}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
