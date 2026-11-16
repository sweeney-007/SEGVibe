"""Knowledge base for repairs: three sources, one document type.

- cwe:    MITRE CWE catalog (public, cwe.mitre.org), one doc per weakness: name, description,
          mitigations, and the first C example. Download: uv run python -m segvibe.rag.kb
- recipe: hand-written fix guidance per defect kind (recipes.yaml)
- memory: repairs the agent made itself: the findings, and the diff that made the code clean
          (built from eval_generate / agent runs, see `memories_from_runs`)
"""
from __future__ import annotations

import difflib
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
RECIPES = Path(__file__).with_name("recipes.yaml")


@dataclass
class Doc:
    id: str
    source: str                 # cwe | recipe | memory
    title: str
    text: str
    cwes: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def snippet(self, limit: int = 600) -> str:
        t = re.sub(r"\s+", " ", self.text).strip()
        return t if len(t) <= limit else t[:limit].rsplit(" ", 1)[0] + " ..."


def download_cwe(dest: Path = DATA) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(CWE_URL, timeout=120) as r:
        z = zipfile.ZipFile(io.BytesIO(r.read()))
    name = next(n for n in z.namelist() if n.endswith(".xml"))
    z.extract(name, dest)
    return dest / name


def _text(el) -> str:
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip() if el is not None else ""


def load_cwe(path: Path | None = None) -> list[Doc]:
    path = path or next(iter(sorted(DATA.glob("cwec_v*.xml"))), None)
    if path is None:
        raise FileNotFoundError("CWE catalog missing: run `uv run python -m segvibe.rag.kb`")
    root = ET.parse(path).getroot()
    NS = {"c": root.tag[1:].split("}")[0]}   # schema namespace changes between catalog versions
    docs = []
    for w in root.iterfind(".//c:Weaknesses/c:Weakness", NS):
        cid = f"CWE-{w.get('ID')}"
        langs = sorted({el.get("Name") or el.get("Class") or "" for el in w.iterfind(".//c:Applicable_Platforms/c:Language", NS)} - {""})
        rel = [(r.get("Nature"), f"CWE-{r.get('CWE_ID')}") for r in w.iterfind(".//c:Related_Weaknesses/c:Related_Weakness", NS)]
        mitig = [_text(m.find("c:Description", NS)) for m in w.iterfind(".//c:Potential_Mitigations/c:Mitigation", NS)
                 if (m.findtext("c:Phase", "", NS) or "Implementation") in ("Implementation", "Architecture and Design")]
        example = next((_text(ex) for ex in w.iterfind(".//c:Demonstrative_Examples//c:Example_Code", NS)
                        if ex.get("Language") in ("C", "C++")), "")
        body = [w.get("Name", ""), _text(w.find("c:Description", NS)), _text(w.find("c:Extended_Description", NS))]
        body += [f"Mitigation: {m}" for m in mitig[:3] if m]
        if example:
            body.append(f"Example (C): {example[:500]}")
        docs.append(Doc(cid, "cwe", w.get("Name", ""), "\n".join(b for b in body if b), cwes=[cid],
                        meta={"status": w.get("Status", ""), "abstraction": w.get("Abstraction", ""), "languages": langs,
                              "parents": [c for n, c in rel if n == "ChildOf"],
                              "related": [c for n, c in rel if n in ("ChildOf", "ParentOf", "CanPrecede", "PeerOf")]}))
    # children = inverse of ChildOf
    by_id = {d.id: d for d in docs}
    for d in docs:
        for p in d.meta["parents"]:
            if p in by_id:
                by_id[p].meta.setdefault("children", []).append(d.id)
    return docs


def load_recipes(path: Path = RECIPES) -> list[Doc]:
    return [Doc(r["id"], "recipe", r["title"], f"{r['title']}.\n{r['text']}", cwes=r.get("cwes", []), kinds=r["kinds"])
            for r in yaml.safe_load(path.read_text())]


def memories_from_runs(paths: list[Path]) -> list[Doc]:
    """Repair memory from saved runs (runs/gen_*.json): each time a repair made the code clean,
    store the findings it fixed and the diff."""
    docs = []
    for p in paths:
        data = json.loads(Path(p).read_text())
        for res in data.get("results", []):
            atts = res["attempts"]
            for prev, cur in zip(atts, atts[1:]):
                if prev["report"]["clean"] or not cur["report"]["clean"]:
                    continue
                fs = [f for f in prev["report"]["findings"] if f["severity"] in ("high", "medium")]
                if not fs:
                    continue
                diff = "\n".join(l for l in difflib.unified_diff(prev["code"].splitlines(), cur["code"].splitlines(),
                                                                lineterm="", n=1) if not l.startswith(("---", "+++")))
                text = "Problems: " + "; ".join(f"{f['kind']}: {f['message'][:120]}" for f in fs[:4])
                docs.append(Doc(f"MEM-{res['task']}-{len(docs)}", "memory", f"fix for {fs[0]['kind']} in {res['task']}",
                                f"{text}\nFix (diff):\n{diff[:1500]}", cwes=sorted({f['cwe'] for f in fs if f['cwe']}),
                                kinds=sorted({f["kind"] for f in fs}), meta={"task": res["task"]}))
    return docs


def load_kb(memory_runs: list[Path] | None = None) -> list[Doc]:
    docs = load_cwe() + load_recipes()
    if memory_runs:
        docs += memories_from_runs(memory_runs)
    return docs


if __name__ == "__main__":
    print("downloaded", download_cwe())
    docs = load_kb()
    print(len(docs), "documents:", {s: sum(d.source == s for d in docs) for s in ("cwe", "recipe")})
