"""Generation eval: requirement -> code, before and after checker-guided repair.

For each task the model writes code from the requirement (round 0), then gets
up to --rounds repairs with the checker's findings. Reported:
  pass   hidden tests pass
  clean  tests pass and no high-severity finding (leak, overflow, crash, UB,
         timeout, slow growth, memory hog, ...)
  "passes but unsafe": first drafts that pass the tests yet have a defect,
         the code a test-only pipeline would have shipped

    uv run python scripts/eval_generate.py --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct
    uv run python scripts/eval_generate.py --model groq:llama-3.3-70b-versatile --no-rules
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from segvibe.gen.loop import solve  # noqa: E402
from segvibe.gen.models import make_generator  # noqa: E402
from segvibe.task import load_tasks  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--tasks", nargs="*")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--no-rules", action="store_true", help="prompt without the safety rules")
    ap.add_argument("--out")
    args = ap.parse_args()
    gen = make_generator(args.model)
    tag = re.sub(r"[^\w.-]+", "_", args.model.split(":", 1)[-1].split("/")[-1]) + ("_norules" if args.no_rules else "")
    out = Path(args.out or f"runs/gen_{tag}.json")
    out.parent.mkdir(exist_ok=True)

    results = []
    t_start = time.time()
    for t in load_tasks(args.tasks):
        sol = solve(t, gen, args.rounds, safety_rules=not args.no_rules)
        f, b = sol.first.report, sol.best.report
        print(f"{t.id:20s} draft: {f.summary():34s} -> best (round {sol.best.round}): {b.summary()}", flush=True)
        results.append(sol.to_dict())
        out.write_text(json.dumps({"model": args.model, "rules": not args.no_rules, "rounds": args.rounds,
                                   "results": results}, indent=2))

    n = len(results)
    first = [r["attempts"][0]["report"] for r in results]
    best = [max(r["attempts"], key=lambda a: (a["report"]["clean"], a["report"]["tests_passed"]))["report"]
            for r in results]
    unsafe = [r for r in first if r["tests_passed"] and not r["clean"]]
    cats = Counter(c for r in first for c in {f["category"] for f in r["findings"] if f["severity"] == "high"})
    rounds = [len(r["attempts"]) - 1 for r in results]
    secs = [a["gen_seconds"] for r in results for a in r["attempts"]]
    print(f"\n{args.model} ({'with' if not args.no_rules else 'without'} safety rules), {n} tasks, "
          f"{time.time() - t_start:.0f}s")
    print(f"  first draft: compiles {sum(r['compiled'] for r in first)}/{n}, pass {sum(r['tests_passed'] for r in first)}/{n}, "
          f"clean {sum(r['clean'] for r in first)}/{n}")
    print(f"  passes tests but unsafe: {len(unsafe)}/{n}")
    print(f"  defects in first drafts: {dict(cats)}")
    print(f"  after up to {args.rounds} repairs: pass {sum(r['tests_passed'] for r in best)}/{n}, "
          f"clean {sum(r['clean'] for r in best)}/{n}; mean repairs used {sum(rounds) / n:.1f}")
    print(f"  generation: {sum(secs) / len(secs):.0f}s per call on average")


if __name__ == "__main__":
    main()
