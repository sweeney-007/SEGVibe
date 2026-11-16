"""Retrieval pipeline on a small knowledge base, BM25 only (no model download)."""
from __future__ import annotations

from dataclasses import replace

from segvibe.findings import Finding
from segvibe.rag.kb import Doc, load_recipes
from segvibe.rag.retrieve import Retriever, Stages, group_findings

BM25 = Stages(dense=False, cluster=False, rerank=False)


def kb():
    cwe = [Doc("CWE-122", "cwe", "Heap-based Buffer Overflow", "Heap-based Buffer Overflow. writes past the end of a heap buffer",
               cwes=["CWE-122"], meta={"languages": ["C"], "status": "Draft", "parents": ["CWE-787"]}),
           Doc("CWE-79", "cwe", "Cross-site Scripting", "Cross-site Scripting. web page output buffer overflow of trust",
               cwes=["CWE-79"], meta={"languages": ["JavaScript"], "status": "Stable", "parents": []}),
           Doc("CWE-1", "cwe", "Old heap overflow entry", "heap buffer overflow write past end", cwes=["CWE-1"],
               meta={"languages": [], "status": "Deprecated", "parents": []})]
    return cwe + load_recipes()


def test_recipes_cover_common_kinds():
    kinds = {k for d in load_recipes() for k in d.kinds}
    assert {"heap-buffer-overflow", "memory-leak", "slow-growth", "signed-integer-overflow", "timeout"} <= kinds


def test_grouping_merges_findings_about_one_line():
    fs = [Finding("heap-buffer-overflow", "asan", "high", "overflow", 9),
          Finding("unbounded-copy", "clang-analyzer", "medium", "strcat", 9),
          Finding("memory-leak", "leakcheck", "high", "leak", 30),
          Finding("warning", "compiler", "low", "unused", 2)]
    groups = group_findings(fs)
    assert len(groups) == 2 and len(group_findings(fs, use=False)) == 3


def test_pipeline_finds_recipe_and_filters_non_c():
    r = Retriever(kb())
    code = "x\n" * 8 + "strcat(out, words[i]);\n"
    f = Finding("heap-buffer-overflow", "asan", "high", "heap-buffer-overflow in f() during the tests", 9)
    q = r.build_query([f], code.splitlines())
    assert "strcat" in q.apis and q.cwes == ["CWE-122"]
    ids = [h.doc.id for h in r.search(q, 5, BM25)]
    assert ids[0] in ("R-string-size", "CWE-122")
    assert "CWE-79" not in ids and "CWE-1" not in ids          # wrong language, deprecated
    raw = [h.doc.id for h in r.search(r.build_query([f], [], use=False), 30, replace(BM25, filter=False, score=False))]
    assert "CWE-1" in raw


def test_guidance_text_and_task_exclusion():
    docs = kb() + [Doc("MEM-x", "memory", "fix for memory-leak in t", "free the copy", kinds=["memory-leak"],
                       meta={"task": "t"})]
    r = Retriever(docs)
    f = [Finding("memory-leak", "leakcheck", "high", "1 block(s) never freed", 3)]
    text, hits = r.guidance(f, "a\nb\nchar *c = strdup(s);\n", st=BM25, per_group=3)
    assert "MEM-x" in [h.doc.id for h in hits] and text.startswith("[")
    _, hits = r.guidance(f, "a\nb\nc\n", st=BM25, exclude_task="t")
    assert "MEM-x" not in [h.doc.id for h in hits]
