"""Retrieval of fix guidance for checker findings, stage by stage.

    findings + code
      -> group (query-side clustering): findings on nearby lines or of the same kind are one problem,
         so they become one query instead of several
      -> pre-retrieval: normalise sanitizer text (addresses, sizes, paths), expand the defect kind into
         plain vocabulary, add the CWE id and name, pull C API names from the offending line
      -> retrieval: BM25 (lexical) + dense embeddings (bge-small), fused with reciprocal rank fusion
      -> post-retrieval
           filter:  drop deprecated CWEs and CWEs that do not apply to C
           score:   boosts for the exact CWE, its parent/child CWEs, recipes for the same kind,
                    API names shared with the offending line
           cluster: group near-duplicate candidates (agglomerative clustering on embeddings) and keep
                    the best of each, so the top k is not three variants of one CWE
           rerank:  cross-encoder (ms-marco MiniLM) over the top candidates
      -> top-k docs -> repair prompt

Every stage can be switched off (`Stages`); scripts/eval_retrieval.py and eval_repair_rag.py measure
what each one adds.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Okapi

from segvibe.findings import Finding
from segvibe.rag.kb import DATA, Doc

EMBED_MODEL = "BAAI/bge-small-en-v1.5"
RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
BGE_QUERY = "Represent this sentence for searching relevant passages: "

# defect kind -> plain words the guidance uses
KIND_TERMS = {
    "heap-buffer-overflow": "heap buffer overflow write past end of allocated buffer out-of-bounds size allocation",
    "stack-buffer-overflow": "stack buffer overflow fixed size local array out-of-bounds write",
    "global-buffer-overflow": "buffer over-read past end of string literal terminator out-of-bounds read",
    "dynamic-stack-buffer-overflow": "stack buffer overflow variable length array",
    "index-out-of-bounds": "array index out of bounds off-by-one loop bound",
    "heap-use-after-free": "use after free dangling pointer freed memory",
    "use-after-free": "use after free dangling pointer freed memory",
    "double-free": "double free freed twice ownership",
    "bad-free": "free of pointer not allocated by malloc invalid free",
    "SEGV": "segmentation fault null pointer dereference invalid address",
    "null-pointer-use": "null pointer dereference",
    "null-dereference": "null pointer dereference unchecked return value",
    "stack-overflow": "stack exhaustion uncontrolled recursion deep recursion",
    "signed-integer-overflow": "integer overflow signed arithmetic wraparound undefined behavior",
    "division-by-zero": "divide by zero",
    "invalid-shift": "shift exponent too large undefined shift",
    "misaligned-access": "misaligned pointer access",
    "undefined-behavior": "undefined behavior",
    "memory-leak": "memory leak missing free release of memory after effective lifetime",
    "file-handle-leak": "file descriptor leak missing fclose resource leak",
    "leak-on-alloc-failure": "memory leak on error path allocation failure cleanup",
    "crash-on-alloc-failure": "unchecked malloc return value null pointer dereference allocation failure",
    "unchecked-alloc": "unchecked malloc return value null pointer",
    "realloc-leak": "realloc failure leak original pointer",
    "allocation-size-too-big": "excessive allocation untrusted size uncontrolled memory allocation",
    "memory-hog": "uncontrolled memory allocation resource consumption limits",
    "out-of-memory": "uncontrolled memory allocation resource exhaustion",
    "timeout": "infinite loop unreachable exit condition hang",
    "slow-growth": "inefficient algorithmic complexity quadratic",
    "slow": "inefficient algorithmic complexity performance",
    "strlen-in-loop": "strlen in loop condition quadratic",
    "uninitialized": "use of uninitialized variable",
    "format-string": "externally controlled format string printf",
    "unbounded-copy": "buffer copy without checking size strcpy strcat sprintf",
    "dangerous-function": "dangerous function gets",
    "stack-use-after-return": "return of stack variable address",
    "wrong-result": "incorrect output edge case requirement",
    "compile-error": "compile error interface signature header",
}
API_TERMS = {
    "strcpy": "strcpy unbounded copy", "strcat": "strcat append quadratic unbounded", "sprintf": "sprintf snprintf",
    "gets": "gets fgets", "scanf": "scanf width", "malloc": "malloc allocation size", "calloc": "calloc",
    "realloc": "realloc grow", "free": "free release", "strdup": "strdup copy", "fopen": "fopen fclose file",
    "memcpy": "memcpy copy length", "strlen": "strlen length", "strtok": "strtok copy", "printf": "printf format",
    "qsort": "qsort sort",
}
_C_LANGS = {"C", "C++", "Memory-Unsafe", "Not Language-Specific"}


@dataclass
class Stages:
    group: bool = True        # query-side clustering of findings
    prep: bool = True         # pre-retrieval expansion
    bm25: bool = True
    dense: bool = True
    filter: bool = True
    score: bool = True
    cluster: bool = True      # post-retrieval diversity clustering
    rerank: bool = False      # off by default: see docs/RESULTS.md
    candidates: int = 30


@dataclass
class Query:
    findings: list[Finding]
    text: str
    cwes: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)


@dataclass
class Hit:
    doc: Doc
    score: float
    why: dict = field(default_factory=dict)


def tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9_]+", text.lower())


def _normalise(msg: str) -> str:
    msg = re.sub(r"0x[0-9a-f]+", " ", msg, flags=re.I)
    msg = re.sub(r"\(fuzz seed \d+\)|#\d+|\d+ (?:bytes?|block\(s\))", " ", msg)
    msg = re.sub(r"\[[\w.,-]+\]$", " ", msg)
    return re.sub(r"\s+", " ", msg).strip()


def group_findings(findings: list[Finding], use: bool = True) -> list[list[Finding]]:
    """Root-cause groups: same kind, or lines within 2 of each other."""
    fs = [f for f in findings if f.severity in ("high", "medium")]
    if not use:
        return [[f] for f in fs]
    groups: list[list[Finding]] = []
    for f in sorted(fs, key=lambda f: ({"high": 0, "medium": 1}[f.severity], f.line or 0)):
        for g in groups:
            if any(f.kind == h.kind or (f.line and h.line and abs(f.line - h.line) <= 2) for h in g):
                g.append(f)
                break
        else:
            groups.append([f])
    return groups


class Retriever:
    def __init__(self, docs: list[Doc], embedder=None, reranker=None, cache_dir: Path = DATA):
        self.docs = docs
        self.by_id = {d.id: d for d in docs}
        self.bm25 = BM25Okapi([tokenize(f"{d.title} {d.text}") for d in docs])
        self._embedder, self._reranker, self._emb = embedder, reranker, None
        self.cache_dir = cache_dir

    # models are loaded lazily, so BM25-only use needs no download
    def embedder(self):
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer(EMBED_MODEL, device="cpu")
        return self._embedder

    def reranker(self):
        if self._reranker is None:
            from sentence_transformers import CrossEncoder
            self._reranker = CrossEncoder(RERANK_MODEL, device="cpu", max_length=384)
        return self._reranker

    def doc_emb(self) -> np.ndarray:
        if self._emb is None:
            key = hashlib.sha1("|".join(d.id for d in self.docs).encode()).hexdigest()[:10]
            path = self.cache_dir / f"emb_{len(self.docs)}_{key}.npy"
            if path.exists():
                self._emb = np.load(path)
            else:
                self._emb = np.asarray(self.embedder().encode([f"{d.title}. {d.text[:1500]}" for d in self.docs],
                                                              batch_size=32, normalize_embeddings=True))
                path.parent.mkdir(exist_ok=True)
                np.save(path, self._emb)
        return self._emb

    # ---------------------------------------------------------------- pre-retrieval
    def build_query(self, group: list[Finding], code_lines: list[str], use: bool = True) -> Query:
        raw = " ".join(f"{f.kind} {f.message}" for f in group)
        if not use:
            return Query(group, raw)
        kinds = sorted({f.kind for f in group})
        cwes = sorted({f.cwe for f in group if f.cwe})
        lines = {code_lines[f.line - 1] for f in group if f.line and 0 < f.line <= len(code_lines)}
        apis = sorted({a for ln in lines for a in API_TERMS if re.search(rf"\b{a}\s*\(", ln)})
        parts = [_normalise(f.message) for f in group]
        parts += [KIND_TERMS.get(k, k.replace("-", " ")) for k in kinds]
        parts += [f"{c} {self.by_id[c].title}" for c in cwes if c in self.by_id]
        parts += [API_TERMS[a] for a in apis]
        return Query(group, " ".join(parts), cwes, kinds, apis)

    # ---------------------------------------------------------------- retrieval
    @staticmethod
    def rrf(rankings: list[list[int]], k: int = 60) -> dict[int, float]:
        fused: dict[int, float] = {}
        for ranking in rankings:
            for r, i in enumerate(ranking):
                fused[i] = fused.get(i, 0.0) + 1.0 / (k + r + 1)
        return fused

    def _keep(self, d: Doc, exclude_task: str | None) -> bool:
        if d.source == "memory" and exclude_task and d.meta.get("task") == exclude_task:
            return False
        return True

    def search(self, q: Query, k: int = 3, st: Stages | None = None, exclude_task: str | None = None) -> list[Hit]:
        st = st or Stages()
        rankings = []
        if st.bm25:
            rankings.append(list(np.argsort(-self.bm25.get_scores(tokenize(q.text)))[:100]))
        if st.dense:
            qv = np.asarray(self.embedder().encode([BGE_QUERY + q.text], normalize_embeddings=True))[0]
            rankings.append(list(np.argsort(-(self.doc_emb() @ qv))[:100]))
        fused = self.rrf(rankings)

        scored: dict[int, float] = {}
        why: dict[int, dict] = {}
        rel = {c2 for c in q.cwes if c in self.by_id
               for c2 in self.by_id[c].meta.get("parents", []) + self.by_id[c].meta.get("children", [])}
        for i, s in fused.items():
            d = self.docs[i]
            if not self._keep(d, exclude_task):
                continue
            if st.filter and d.source == "cwe":
                langs = set(d.meta.get("languages", []))
                if d.meta.get("status") == "Deprecated" or (langs and not langs & _C_LANGS):
                    continue
            b = 0.0
            if st.score:
                b += 0.03 * any(c in d.cwes for c in q.cwes)
                b += 0.01 * any(c in rel for c in d.cwes)
                b += 0.03 * any(kd in d.kinds for kd in q.kinds)
                b += 0.005 * sum(a in d.text.lower() for a in q.apis)
            scored[i] = s + b
            why[i] = {"fused": round(s, 4), "boost": round(b, 4)}
        order = sorted(scored, key=lambda i: -scored[i])[:st.candidates]

        if st.cluster and len(order) > k:
            order = self._diverse(order, scored, k)
        hits = [Hit(self.docs[i], scored[i], why[i]) for i in order]
        if st.rerank and hits:
            ce = self.reranker().predict([(q.text, f"{h.doc.title}. {h.doc.snippet(1200)}") for h in hits],
                                         show_progress_bar=False)
            for h, s in zip(hits, ce):
                h.why["rerank"] = round(float(s), 3)
                h.score = float(s)
            hits.sort(key=lambda h: -h.score)
        return hits[:k]

    def _diverse(self, order: list[int], scored: dict[int, float], k: int, threshold: float = 0.12) -> list[int]:
        """Agglomerative clustering of the candidates (cosine distance); best candidate per cluster first,
        then the rest, so near-duplicates do not crowd out other guidance."""
        from sklearn.cluster import AgglomerativeClustering

        emb = self.doc_emb()[order]
        labels = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold, metric="cosine",
                                         linkage="average").fit_predict(emb)
        firsts, rest, seen = [], [], set()
        for i, lab in zip(order, labels):   # order is already best-first
            (rest if lab in seen else firsts).append(i)
            seen.add(lab)
        return firsts + rest

    # ---------------------------------------------------------------- for the repair prompt
    def guidance(self, findings: list[Finding], code: str, k: int = 3, st: Stages | None = None,
                 exclude_task: str | None = None, per_group: int = 2, max_groups: int = 3) -> tuple[str, list[Hit]]:
        st = st or Stages()
        lines = code.splitlines()
        hits: list[Hit] = []
        for g in group_findings(findings, st.group)[:max_groups]:   # same document budget either way
            q = self.build_query(g, lines, st.prep)
            for h in self.search(q, per_group, st, exclude_task):
                if h.doc.id not in {x.doc.id for x in hits}:
                    hits.append(h)
        hits = hits[:k * 2]
        text = "\n".join(f"[{h.doc.id}] {h.doc.snippet(700)}" for h in hits)   # text starts with the title
        return text, hits


def default_retriever(memory_runs: list[Path] | None = None) -> Retriever:
    from segvibe.rag.kb import load_kb
    return Retriever(load_kb(memory_runs))


ALL_OFF = Stages(group=False, prep=False, bm25=True, dense=False, filter=False, score=False, cluster=False,
                 rerank=False)


def ablations() -> dict[str, Stages]:
    """Configurations for the evals: build the pipeline up one stage at a time, then remove each."""
    full = Stages()
    return {
        "bm25 only (raw query)": ALL_OFF,
        "dense only (raw query)": replace(ALL_OFF, bm25=False, dense=True),
        "hybrid bm25+dense (raw)": replace(ALL_OFF, dense=True),
        "+ pre-retrieval": replace(ALL_OFF, dense=True, prep=True),
        "+ filter": replace(ALL_OFF, dense=True, prep=True, filter=True),
        "+ scoring": replace(ALL_OFF, dense=True, prep=True, filter=True, score=True),
        "+ grouping findings": replace(full, cluster=False),
        "+ clustering (full default)": full,
        "full + rerank": replace(full, rerank=True),
        "full - pre-retrieval": replace(full, prep=False),
        "full - dense": replace(full, dense=False),
        "full - bm25": replace(full, bm25=False),
        "full - filter": replace(full, filter=False),
        "full - scoring": replace(full, score=False),
        "full - grouping": replace(full, group=False),
        "full - clustering": replace(full, cluster=False),
    }
