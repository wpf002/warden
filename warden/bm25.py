"""Small BM25 index over the knowledge base, for hybrid retrieval with the vectors.

Keyword search finds exact identifiers (T1110.003, svc-backup, 4771) and rule names that
embeddings blur; embeddings find paraphrases that keywords miss. Fused with reciprocal
rank fusion in KnowledgeBase.retrieve.
"""
from __future__ import annotations

import math
import re
from collections import Counter

TOKEN = re.compile(r"t\d{4}(?:\.\d{3})?|[a-z0-9]+")
STOP = frozenset("a an and are as at be by for from in is it of on or that the this to was with when not no".split())


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOP]


class BM25:
    def __init__(self, ids: list[str], docs: list[str], metas: list[dict], k1: float = 1.4, b: float = 0.75):
        self.ids, self.metas, self.k1, self.b = ids, metas, k1, b
        self.tfs = [Counter(tokenize(d)) for d in docs]
        self.lens = [sum(tf.values()) for tf in self.tfs]
        self.avg = (sum(self.lens) / len(self.lens)) if self.lens else 0.0
        df: Counter = Counter()
        for tf in self.tfs:
            df.update(tf.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def search(self, query: str, k: int, where: dict | None = None) -> list[tuple[str, float]]:
        q = [t for t in tokenize(query) if t in self.idf]
        scores = []
        for i, tf in enumerate(self.tfs):
            if where and not matches(self.metas[i], where):
                continue
            s = 0.0
            for t in q:
                f = tf.get(t)
                if f:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
            if s > 0:
                scores.append((self.ids[i], s))
        scores.sort(key=lambda x: -x[1])
        return scores[:k]


def matches(meta: dict, where: dict) -> bool:
    """The subset of Chroma's `where` language the knowledge base uses."""
    for key, cond in where.items():
        if key == "$and":
            if not all(matches(meta, c) for c in cond):
                return False
        elif key == "$or":
            if not any(matches(meta, c) for c in cond):
                return False
        elif isinstance(cond, dict):
            v = meta.get(key)
            for op, arg in cond.items():
                if op == "$in" and v not in arg:
                    return False
                if op == "$nin" and v in arg:
                    return False
                if op == "$ne" and v == arg:
                    return False
                if op == "$eq" and v != arg:
                    return False
        elif meta.get(key) != cond:
            return False
    return True


def rrf(*ranked: list[str], k: int = 60) -> list[str]:
    """Reciprocal rank fusion: robust to the two lists having incomparable scores."""
    score: dict[str, float] = {}
    for lst in ranked:
        for r, doc_id in enumerate(lst):
            score[doc_id] = score.get(doc_id, 0.0) + 1.0 / (k + r + 1)
    return sorted(score, key=lambda d: -score[d])
