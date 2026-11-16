"""Detection eval: which layer of analysis catches which kind of defect?

Runs every check on (a) each task's reference (false-positive check),
(b) the hand-written flawed variants and (c) automatic mutants of the
reference. A defect is "caught" when any finding of medium or high severity
is reported; "right category" when one of them has the expected category.

    uv run python scripts/eval_detect.py              # all tasks, ~10 min
    uv run python scripts/eval_detect.py --tasks reverse_words
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from segvibe.check import check  # noqa: E402
from segvibe.inject import mutants  # noqa: E402
from segvibe.task import load_tasks  # noqa: E402

LAYERS = {
    "static: compiler + clang analyzer + cppcheck": {"compiler", "clang-analyzer", "cppcheck"},
    "AST rules (tree-sitter)": {"ast-rules"},
    "tests + sanitizers": {"tests", "asan", "ubsan"},
    "fuzzing under sanitizers": {"fuzz"},
    "leak / heap tracker": {"leakcheck"},
    "allocation-failure runs": {"allocfail"},
    "time and memory profile": {"perf"},
}
SEV = ("high", "medium")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", nargs="*")
    ap.add_argument("--out", default="runs/eval_detect.json")
    args = ap.parse_args()

    rows, refs = [], []
    for t in load_tasks(args.tasks):
        r = check(t.reference, t)
        refs.append({"task": t.id, "clean": r.clean,
                     "findings": [f.text() for f in r.findings if f.severity in SEV]})
        cases = [("variant", v.kind, v.note, v.code) for v in t.variants]
        cases += [(f"mutant:{m.op}", m.kind, m.note, m.code) for m in mutants(t.reference)]
        for source, kind, note, code in cases:
            rep = check(code, t)
            fs = [f for f in rep.findings if f.severity in SEV]
            rows.append({
                "task": t.id, "source": source, "kind": kind, "note": note,
                "compiled": rep.compiled, "caught": bool(fs),
                "right_category": kind in {f.category for f in fs},
                "tools": sorted({f.tool for f in fs}),
                "findings": [f.text() for f in fs],
                "structured": [{"kind": f.kind, "category": f.category, "cwe": f.cwe, "tool": f.tool,
                                "severity": f.severity, "message": f.message, "line": f.line,
                                "code_line": code.splitlines()[f.line - 1].strip()
                                if f.line and 0 < f.line <= len(code.splitlines()) else ""} for f in fs],
                "code": code,
            })
            print(f"{t.id:20s} {source:24s} {kind:8s} {'caught' if fs else 'MISSED':7s} "
                  f"{','.join(sorted({f.tool for f in fs}))}", flush=True)

    rows = [r for r in rows if r["compiled"]]
    print("\nReferences flagged (false positives):", sum(not r["clean"] or bool(r["findings"]) for r in refs),
          "of", len(refs))
    by_kind = defaultdict(list)
    for r in rows:
        by_kind[r["kind"]].append(r)
    print(f"\n{'expected':10s} {'n':>4s} {'caught':>7s} {'right cat':>9s}")
    for k in ("bug", "leak", "overuse", "vuln", "crash"):
        rs = by_kind.get(k, [])
        if rs:
            print(f"{k:10s} {len(rs):4d} {sum(r['caught'] for r in rs) / len(rs):7.0%} "
                  f"{sum(r['right_category'] for r in rs) / len(rs):9.0%}")
    n = len(rows)
    print(f"{'all':10s} {n:4d} {sum(r['caught'] for r in rows) / n:7.0%} {sum(r['right_category'] for r in rows) / n:9.0%}")

    print(f"\n{'layer':48s} {'catches':>8s} {'only it':>8s}")
    for name, tools in LAYERS.items():
        hit = [r for r in rows if tools & set(r["tools"])]
        only = [r for r in hit if not (set(r["tools"]) - tools)]
        print(f"{name:48s} {len(hit) / n:8.0%} {len(only):8d}")
    missed = [r for r in rows if not r["caught"]]
    if missed:
        print("\nMissed:")
        for r in missed:
            print(f"  {r['task']}: {r['source']} ({r['note']})")
    Path(args.out).parent.mkdir(exist_ok=True)
    Path(args.out).write_text(json.dumps({"references": refs, "cases": rows}, indent=2))


if __name__ == "__main__":
    main()
