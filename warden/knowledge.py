"""Knowledge base: chunk -> embed -> Chroma -> retrieve. Stages 3 and 4."""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
from chromadb.utils.embedding_functions import register_embedding_function

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


@register_embedding_function
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
        # Vectors from different embedding functions live in different spaces, so each
        # function gets its own collection. Switching WARDEN_EMBEDDINGS reindexes cleanly.
        self.col = self.client.get_or_create_collection(f"{COLLECTION}_{self.ef.name()}", embedding_function=self.ef)
        self._snapshot: str | None = None
        self._bm = None
        self._docs: dict = {}

    def index_dir(self, path: Path | None = None, only: set[str] | None = None) -> int:
        path = path or settings.knowledge_dir
        ids, docs, metas = [], [], []
        for f in sorted(path.glob("*.md")):
            if only is not None and f.stem not in only:
                continue
            text = f.read_text()
            sha = hashlib.sha1(text.encode()).hexdigest()[:12]
            doc_techs = techniques_in(text)
            for i, c in enumerate(chunk(text)):
                ids.append(f"{f.stem}#{i}")
                docs.append(c)
                metas.append({"doc": f.stem, "chunk": i, "kind": f.stem.split("-")[0], "sha": sha,
                              **technique_meta(techniques_in(c) or doc_techs)})
        if ids:
            self.col.upsert(ids=ids, documents=docs, metadatas=metas)
        self.invalidate()
        return len(ids)

    def sync(self, path: Path | None = None) -> dict:
        """Bring the index in line with the markdown on disk: embed new or edited docs,
        drop chunks of deleted ones. Cheap when nothing changed (hash comparison only)."""
        path = path or settings.knowledge_dir
        on_disk = {f.stem: hashlib.sha1(f.read_text().encode()).hexdigest()[:12] for f in path.glob("*.md")}
        got = self.col.get(where={"kind": {"$ne": "attack"}}, include=["metadatas"])
        indexed: dict[str, set[str]] = {}
        chunk_ids: dict[str, list[str]] = {}
        for i, m in zip(got["ids"], got["metadatas"]):
            indexed.setdefault(m["doc"], set()).add(m.get("sha", ""))
            chunk_ids.setdefault(m["doc"], []).append(i)
        changed = {d for d, h in on_disk.items() if indexed.get(d) != {h}}
        removed = {d for d in indexed if d not in on_disk}
        stale = [i for d in changed | removed for i in chunk_ids.get(d, [])]
        if stale:
            self.col.delete(ids=stale)
        if changed:
            self.index_dir(path, only=changed)
        if stale or changed:
            self.invalidate()
        return {"indexed": sorted(changed), "removed": sorted(removed)}

    def snapshot_id(self) -> str:
        """Content hash of what is indexed: doc ids plus the ATT&CK manifest version.
        Recorded on every case so an analysis can be replayed against the same KB."""
        if self._snapshot:
            return self._snapshot
        from .attack import manifest
        h = hashlib.sha1()
        got = self.col.get(include=["documents"])
        for i, d in sorted(zip(got["ids"], got["documents"])):
            h.update(i.encode())
            h.update(hashlib.md5((d or "").encode()).digest())
        m = manifest() or {}
        h.update(str(m.get("attack_version", "")).encode())
        self._snapshot = "kb-" + h.hexdigest()[:12]
        return self._snapshot

    def invalidate(self) -> None:
        self._snapshot = None
        self._bm = None

    def add_learned_case(self, doc_id: str, text: str) -> None:
        """Feedback loop writes here. Also persisted to disk by feedback.py."""
        self.col.upsert(ids=[f"{doc_id}#0"], documents=[text], metadatas=[{"doc": doc_id, "chunk": 0, "kind": "learned"}])
        self.invalidate()

    def _bm25(self):
        if self._bm is None:
            from .bm25 import BM25
            got = self.col.get(include=["documents", "metadatas"])
            self._bm = BM25(got["ids"], got["documents"], got["metadatas"])
            self._docs = {i: (d, m) for i, d, m in zip(got["ids"], got["documents"], got["metadatas"])}
        return self._bm

    def retrieve(self, query: str, k: int = 5, where: dict | None = None, mode: str | None = None) -> list[dict]:
        """Hybrid by default: vector and BM25 candidates fused with reciprocal rank fusion.
        mode="vector" or "bm25" runs one side alone (used by the eval to compare)."""
        from .bm25 import rrf

        mode = mode or settings.retrieval_mode
        n = self.col.count()
        if n == 0:
            return []
        pool = min(n, max(k * 4, 20))
        vec: list[dict] = []
        if mode in ("hybrid", "vector"):
            res = self.col.query(query_texts=[query], n_results=pool, where=where or None)
            if res["ids"] and res["ids"][0]:
                vec = [{"id": i, "text": d, "doc": m["doc"], "kind": m.get("kind", ""),
                        "technique": m.get("technique", ""), "distance": round(float(dist), 4)}
                       for i, d, m, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0])]
        if mode == "vector":
            return vec[:k]
        kw = self._bm25().search(query, pool, where)
        order = rrf([d["id"] for d in vec], [i for i, _ in kw]) if mode == "hybrid" else [i for i, _ in kw]
        by_id = {d["id"]: d for d in vec}
        out = []
        for i in order[:k]:
            if i in by_id:
                out.append(by_id[i])
            else:
                d, m = self._docs[i]
                out.append({"id": i, "text": d, "doc": m["doc"], "kind": m.get("kind", ""),
                            "technique": m.get("technique", ""), "distance": None})
        return out

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
        """Three passes, each with the query that suits its corpus.

        1. ATT&CK reference, reachable only through the alert's mapped technique ids. It is
           4,000+ chunks and would swamp any unfiltered search.
        2. Playbooks, policies, and MITRE notes, searched with what the detection *is*
           (rule names, descriptions, technique ids) and not with entity values: an IP or a
           user name says nothing about which playbook applies.
        3. Past incidents and learned cases, searched with the entities too, because
           "we saw svc-backup do this before" is exactly what those documents record.
        """
        from .detections import REGISTRY, load_all

        load_all()
        rules = alert.rules()
        names = " ".join(REGISTRY[r].name if r in REGISTRY else r.replace("_", " ") for r in rules)
        flags = []
        if alert.success_after_failures:
            flags.append("successful login after failures account compromised")
        if any(u.lower().startswith(("svc-", "svc_", "sa-")) for u in alert.users):
            flags.append("service account")
        if alert.geo == "internal":
            flags.append("internal source")
        if alert.asset_tier == "crown_jewel":
            flags.append("crown jewel asset")
        ops_q = " ".join([names, " ".join(r.replace("_", " ") for r in rules), " ".join(alert.mitre), *flags])
        case_q = ops_q + f" {alert.source_ip} {' '.join(alert.users[:5])} {' '.join(alert.hosts[:3])}"

        n_attack = 1 if alert.mitre and k >= 3 else 0
        n_cases = 1 if k >= 4 else 0
        out: list[dict] = self.retrieve_by_technique(ops_q, alert.mitre, k=n_attack, kind="attack") if n_attack else []
        seen = {d["id"] for d in out}

        def take(docs: list[dict], limit: int) -> None:
            for d in docs:
                if len(out) >= limit:
                    return
                if d["id"] not in seen:
                    out.append(d)
                    seen.add(d["id"])

        # playbooks first so the mapped playbook lands high; the case pass fills what's left
        take(self.retrieve(ops_q, k, where={"kind": {"$in": ["playbook", "policy", "mitre"]}}), k - n_cases)
        take(self.retrieve(case_q, k, where={"kind": {"$in": ["incident", "learned"]}}), k)
        take(self.retrieve(ops_q, k, where={"kind": {"$ne": "attack"}}), k)
        return out
