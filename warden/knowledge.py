"""Knowledge base: chunk -> embed -> Chroma -> retrieve. Stages 3 and 4."""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings

from .config import settings
from .models import Alert

COLLECTION = "warden_kb"

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def techniques_in(text: str) -> list[str]:
    """Technique ids mentioned in a chunk, so retrieval can filter by the alert's mapping."""
    seen: dict[str, None] = {}
    for t in TECHNIQUE_RE.findall(text):
        seen.setdefault(t, None)
    return list(seen)


def technique_meta(ids: list[str]) -> dict:
    """Chroma metadata values must be scalars, so store the primary id plus a base id."""
    if not ids:
        return {}
    return {"technique": ids[0], "technique_base": ids[0].split(".")[0], "techniques": ",".join(ids)}


class HashEmbedding(EmbeddingFunction):
    """Offline fallback: hashed word + bigram bag, L2 normalized. Not semantic, but
    keyword overlap works well enough for playbooks and makes tests hermetic."""
    DIM = 512

    def __init__(self) -> None:
        pass

    def __call__(self, input: Documents) -> Embeddings:
        out = []
        for text in input:
            vec = [0.0] * self.DIM
            toks = re.findall(r"[a-z0-9_.\-]+", text.lower())
            grams = toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]
            for g in grams:
                h = int(hashlib.md5(g.encode()).hexdigest(), 16)
                vec[h % self.DIM] += 1.0 if (h >> 9) & 1 else -1.0
            n = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / n for v in vec])
        return out

    @staticmethod
    def name() -> str:
        return "warden_hash"

    def get_config(self) -> dict:
        return {}

    @staticmethod
    def build_from_config(config: dict) -> "HashEmbedding":
        return HashEmbedding()


def embedding_function() -> EmbeddingFunction:
    if settings.embeddings == "hash":
        return HashEmbedding()
    try:
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
        ef = DefaultEmbeddingFunction()
        ef(["warmup"])  # forces model download; fails fast if offline
        return ef
    except Exception as e:  # noqa: BLE001
        print(f"[warden] default embeddings unavailable ({type(e).__name__}), using offline hash embeddings")
        return HashEmbedding()


def chunk(text: str, max_chars: int = 900) -> list[str]:
    """Split on markdown headings, then pack paragraphs up to max_chars."""
    sections = re.split(r"\n(?=#{1,3} )", text)
    chunks: list[str] = []
    for sec in sections:
        buf = ""
        for para in sec.split("\n\n"):
            if len(buf) + len(para) > max_chars and buf:
                chunks.append(buf.strip())
                buf = ""
            buf += para + "\n\n"
        if buf.strip():
            chunks.append(buf.strip())
    return chunks


class KnowledgeBase:
    def __init__(self, persist: bool = True):
        self.client = chromadb.PersistentClient(path=str(settings.chroma_dir)) if persist else chromadb.Client()
        self.ef = embedding_function()
        self.col = self.client.get_or_create_collection(COLLECTION, embedding_function=self.ef)

    def index_dir(self, path: Path | None = None) -> int:
        path = path or settings.knowledge_dir
        ids, docs, metas = [], [], []
        for f in sorted(path.glob("*.md")):
            text = f.read_text()
            doc_techs = techniques_in(text)
            for i, c in enumerate(chunk(text)):
                ids.append(f"{f.stem}#{i}")
                docs.append(c)
                metas.append({"doc": f.stem, "chunk": i, "kind": f.stem.split("-")[0],
                              **technique_meta(techniques_in(c) or doc_techs)})
        if ids:
            self.col.upsert(ids=ids, documents=docs, metadatas=metas)
        return len(ids)

    def add_learned_case(self, doc_id: str, text: str) -> None:
        """Feedback loop writes here. Also persisted to disk by feedback.py."""
        self.col.upsert(ids=[f"{doc_id}#0"], documents=[text], metadatas=[{"doc": doc_id, "chunk": 0, "kind": "learned"}])

    def retrieve(self, query: str, k: int = 5, where: dict | None = None) -> list[dict]:
        n = self.col.count()
        if n == 0:
            return []
        res = self.col.query(query_texts=[query], n_results=min(k, n), where=where or None)
        if not res["ids"] or not res["ids"][0]:
            return []
        return [
            {"id": i, "text": d, "doc": m["doc"], "kind": m.get("kind", ""),
             "technique": m.get("technique", ""), "distance": round(float(dist), 4)}
            for i, d, m, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])
        ]

    def retrieve_by_technique(self, query: str, techniques: list[str], k: int = 3,
                              kind: str | None = None) -> list[dict]:
        """Filtered pass: only chunks tagged with the alert's mapped techniques (or their parents).
        Pass `kind` to confine the pass to one corpus, e.g. "attack"."""
        if not techniques:
            return []
        bases = sorted({t.split(".")[0] for t in techniques})
        where: dict = {"$or": [{"technique": {"$in": techniques}}, {"technique_base": {"$in": bases}}]}
        if kind:
            where = {"$and": [{"kind": kind}, where]}
        return self.retrieve(query, k, where=where)

    def retrieve_for_alert(self, alert: Alert, k: int = 5) -> list[dict]:
        """Two passes with different jobs.

        ATT&CK is 4,000+ chunks of reference material and will swamp an unfiltered
        search, so it is reachable only through the detection's mapped technique ids.
        The operational corpus - playbooks, policies, past incidents, learned cases -
        gets the rest of the budget from an unfiltered search.
        """
        q = (
            f"{alert.rule.replace('_', ' ')} {alert.failed_attempts} failed logins from {alert.source_ip} "
            f"geo {alert.geo} users {' '.join(alert.users[:5])} hosts {' '.join(alert.hosts)} "
            f"asset {alert.asset_tier} "
            + ("successful login after failures account compromise" if alert.success_after_failures else "")
            + (" service account internal misconfiguration" if any(u.startswith("svc-") for u in alert.users) else "")
            + " playbook response policy MITRE "
            + " ".join(alert.mitre)
        )
        n_attack = max(1, k // 3) if alert.mitre else 0
        out: list[dict] = self.retrieve_by_technique(q, alert.mitre, k=n_attack, kind="attack")
        seen = {d["id"] for d in out}
        for d in self.retrieve(q, k, where={"kind": {"$ne": "attack"}}):
            if d["id"] not in seen and len(out) < k:
                out.append(d)
                seen.add(d["id"])
        return out
