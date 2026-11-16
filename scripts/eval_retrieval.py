"""Retrieval eval: does each stage bring better fix guidance for real findings?

Queries come from the detection eval (runs/eval_detect.json): the findings the checker reported on
injected and hand-written defects. A document is relevant to a finding when
  - it is a recipe or memory written for the same defect kind, or
  - it is the CWE entry for the finding's CWE, or its direct parent or child.
Two levels:
  query level   one query per finding group: hit@3, recall of a recipe in the top 3, MRR@10
  context level what the repair prompt would get (guidance(), up to 6 docs): share of findings with
                at least one relevant doc, documents and characters added to the prompt, latency
Caveat: the scoring stage boosts the same CWE/kind the labels use. That is the point of it (the checker
knows the defect kind) but it makes the boost look good by construction; eval_repair_rag.py is the test
that matters.

    uv run python scripts/eval_retrieval.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from segvibe.findings import Finding  # noqa: E402
from segvibe.rag.retrieve import ablations, default_retriever, group_findings  # noqa: E402


def relevant(doc, kinds: set[str], cwes: set[str], r) -> bool:
    if doc.source in ("recipe", "memory"):
        return bool(kinds & set(doc.kinds))
    near = set(cwes)
    for c in cwes:
        if c in r.by_id:
            near |= set(r.by_id[c].meta.get("parents", [])) | set(r.by_id[c].meta.get("children", []))
    return bool(near & set(doc.cwes))


def main():
    data = json.loads(Path("runs/eval_detect.json").read_text())
    cases = [c for c in data["cases"] if c.get("structured")]
    r = default_retriever(sorted(Path("runs").glob("gen_*.json")))
    r.doc_emb()
    r.reranker()
    rows = {}
    for name, st in ablations().items():
        hit3 = rec3 = mrr = nq = 0
        cov = covn = ndocs = nchars = 0
        t0 = time.perf_counter()
        for c in cases:
            fs = [Finding(f["kind"], f["tool"], f["severity"], f["message"], f["line"], f["category"], f["cwe"])
                  for f in c["structured"]]
            lines = c["code"].splitlines()
            for g in group_findings(fs, st.group):
                q = r.build_query(g, lines, st.prep)
                hits = r.search(q, 10, st, exclude_task=c["task"])
                kinds, cwes = {f.kind for f in g}, {f.cwe for f in g if f.cwe}
                rel = [relevant(h.doc, kinds, cwes, r) for h in hits]
                nq += 1
                hit3 += any(rel[:3])
                rec3 += any(x and h.doc.source != "cwe" for x, h in zip(rel[:3], hits[:3]))
                mrr += next((1 / (i + 1) for i, x in enumerate(rel) if x), 0)
            text, hits = r.guidance(fs, c["code"], st=st, exclude_task=c["task"])
            ndocs += len(hits)
            nchars += len(text)
            for f in [f for f in fs if f.severity in ("high", "medium")]:
                covn += 1
                cov += any(relevant(h.doc, {f.kind}, {f.cwe} if f.cwe else set(), r) for h in hits)
        ms = (time.perf_counter() - t0) * 1000 / len(cases)
        rows[name] = {"queries": nq, "hit@3": hit3 / nq, "recipe@3": rec3 / nq, "mrr@10": mrr / nq,
                      "finding_coverage": cov / covn, "docs_in_prompt": ndocs / len(cases),
                      "chars_in_prompt": nchars / len(cases), "ms_per_case": ms}
        x = rows[name]
        print(f"{name:30s} q={nq:4d} hit@3 {x['hit@3']:.2f} recipe@3 {x['recipe@3']:.2f} mrr {x['mrr@10']:.2f} | "
              f"coverage {x['finding_coverage']:.2f} docs {x['docs_in_prompt']:.1f} chars {x['chars_in_prompt']:.0f} "
              f"| {ms:.0f} ms/case", flush=True)
    Path("runs/eval_retrieval.json").write_text(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
