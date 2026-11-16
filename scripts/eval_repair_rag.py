"""Does retrieval make repairs succeed more often? The test that decides whether it stays.

Takes the defects the checker caught in the detection eval (runs/eval_detect.json: injected mutants and
hand-written flawed variants, with their findings), asks the model for ONE repair per defect, and checks
the result with every check. Same model, same prompt, same findings; only the retrieved guidance differs:

  none                      no guidance
  bm25 only (raw query)     the simplest retrieval
  + pre-retrieval ... full  retrieval stages added one at a time (see segvibe/rag/retrieve.py)
  full + rerank

fixed = clean after the repair (tests pass, no high-severity finding). Paired comparison per defect.

    uv run python scripts/eval_repair_rag.py --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --configs none full
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from segvibe.check import check  # noqa: E402
from segvibe.findings import Finding, Report  # noqa: E402
from segvibe.gen.models import make_generator  # noqa: E402
from segvibe.gen.prompts import extract_code, repair_prompt  # noqa: E402
from segvibe.rag.retrieve import ablations, default_retriever  # noqa: E402
from segvibe.task import load_tasks  # noqa: E402

CONFIGS = {"none": None, "full": "+ clustering (full default)", **{k: k for k in ablations()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--configs", nargs="+", default=["none", "full"])
    ap.add_argument("--n", type=int, default=0, help="sample this many defects (0 = all)")
    ap.add_argument("--out", default="runs/eval_repair_rag.json")
    args = ap.parse_args()

    tasks = {t.id: t for t in load_tasks()}
    cases = [c for c in json.loads(Path("runs/eval_detect.json").read_text())["cases"]
             if c["caught"] and c.get("structured")]
    if args.n:
        cases = random.Random(0).sample(cases, min(args.n, len(cases)))
    gen = make_generator(args.model)
    r = default_retriever()
    out = Path(args.out)
    results = json.loads(out.read_text()) if out.exists() else {}
    for c in cases:                       # configs alternate per defect, so partial runs stay paired
        for cfg_name in args.configs:
            st = None if CONFIGS[cfg_name] is None else ablations()[CONFIGS[cfg_name]]
            rows = results.setdefault(cfg_name, {})
            key = f"{c['task']}|{c['source']}|{c['note']}"
            if key in rows:
                continue
            t = tasks[c["task"]]
            fs = [Finding(f["kind"], f["tool"], f["severity"], f["message"], f["line"], f["category"], f["cwe"])
                  for f in c["structured"]]
            feedback = Report(compiled=True, findings=fs).feedback(c["code"])
            guidance, hits = r.guidance(fs, c["code"], st=st, exclude_task=c["task"]) if st else ("", [])
            t0 = time.time()
            g = gen.generate(repair_prompt(t.requirement, t.signature, c["code"], feedback, True, guidance))
            rep = check(extract_code(g.text), t)
            rows[key] = {"kind": c["kind"], "fixed": rep.clean, "passes": rep.tests_passed, "after": rep.summary(),
                         "docs": [h.doc.id for h in hits], "gen_s": round(time.time() - t0, 1)}
            print(f"{cfg_name:28s} {key[:60]:60s} {'FIXED' if rep.clean else 'no':5s} {rep.summary()}", flush=True)
            out.write_text(json.dumps(results, indent=2))

    keys = set.intersection(*(set(results[c]) for c in args.configs))
    base = results.get("none", {})
    print(f"\n{len(keys)} defects, model {args.model}")
    print(f"{'config':28s} {'fixed':>7s} {'pass':>6s} {'vs none: +won -lost':>22s}")
    for cfg_name in args.configs:
        rows = results[cfg_name]
        fixed = sum(rows[k]["fixed"] for k in keys)
        passes = sum(rows[k]["passes"] for k in keys)
        won = sum(rows[k]["fixed"] and not base[k]["fixed"] for k in keys if k in base)
        lost = sum(base[k]["fixed"] and not rows[k]["fixed"] for k in keys if k in base)
        print(f"{cfg_name:28s} {fixed / len(keys):7.0%} {passes / len(keys):6.0%} {f'+{won} -{lost}':>22s}")


if __name__ == "__main__":
    main()
