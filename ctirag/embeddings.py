"""Embedders for the ATT&CK vector store.

* OllamaEmbedder - nomic-embed-text through the local Ollama server (default).
* HashEmbedder   - deterministic hashed bag-of-words vectors; needs no model, used in
                   offline mode and tests. Lower quality, but keeps the same ChromaDB flow.
"""
from __future__ import annotations

import math
import re
import zlib
from collections import Counter

import numpy as np
import requests

from .llm import LLMError

STOPWORDS = set("""
a an the and or of to in on for by with from as at is are was were be been being this that these those it its
into via than then there their they them which who whom whose what when where why how not no can could may might
must should would will shall also such other others often using use used uses including include includes within
adversary adversaries attacker attackers threat actor actors e g i etc
""".split())

TOKEN_RE = re.compile(r"[a-z0-9]+")


def _stem(token: str) -> str:
    """Very light suffix stripping so 'downloaded' matches 'download', 'tasks' matches 'task'."""
    if token.endswith("ing") and len(token) - 3 >= 4:
        return token[:-3]
    if token.endswith("ed") and len(token) - 2 >= 4:
        return token[:-2]
    if token.endswith("es") and token[:-2].endswith(("ss", "sh", "ch", "x")):
        return token[:-2]
    if token.endswith("s") and not token.endswith("ss") and len(token) - 1 >= 4:
        return token[:-1]
    return token


def tokens(text: str) -> list[str]:
    """Lower-cased, stop-word-filtered, lightly stemmed tokens (shared by the KB re-ranker)."""
    return [_stem(t) for t in TOKEN_RE.findall((text or "").lower()) if t not in STOPWORDS and len(t) > 1]


def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", name).strip("-._") or "embedder"


class HashEmbedder:
    def __init__(self, dim: int = 1024):
        self.dim = dim
        self.name = f"hash-{dim}"
        self.slug = _slug(self.name)

    def _vector(self, text: str) -> list[float]:
        toks = tokens(text)
        grams = Counter(toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])])
        vec = np.zeros(self.dim, dtype=np.float32)
        for gram, count in grams.items():
            h = zlib.crc32(gram.encode("utf-8"))      # stable across runs (unlike hash())
            sign = 1.0 if (h >> 16) & 1 else -1.0
            vec[h % self.dim] += sign * (1.0 + math.log(count))
        norm = float(np.linalg.norm(vec))
        return (vec / norm).tolist() if norm else vec.tolist()

    def embed(self, texts: list[str], kind: str = "document") -> list[list[float]]:
        return [self._vector(t) for t in texts]


class OllamaEmbedder:
    def __init__(self, model: str = "nomic-embed-text", url: str = "http://localhost:11434",
                 timeout: float = 120, batch: int = 32):
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.batch = batch
        self.name = model
        self.slug = _slug(model)
        self.session = requests.Session()

    def _prefix(self, kind: str) -> str:
        # nomic-embed-text expects task prefixes for retrieval.
        if "nomic" in self.model:
            return "search_query: " if kind == "query" else "search_document: "
        return ""

    def _post(self, path: str, payload: dict) -> requests.Response:
        try:
            return self.session.post(f"{self.url}{path}", json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            raise LLMError(f"cannot reach Ollama at {self.url} for embeddings ({exc})") from exc

    def embed(self, texts: list[str], kind: str = "document") -> list[list[float]]:
        out: list[list[float]] = []
        prefix = self._prefix(kind)
        for i in range(0, len(texts), self.batch):
            batch = [prefix + t for t in texts[i:i + self.batch]]
            resp = self._post("/api/embed", {"model": self.model, "input": batch, "truncate": True})
            if resp.status_code == 404 and "model" in resp.text.lower():
                raise LLMError(f"embedding model '{self.model}' not found. Run: ollama pull {self.model}")
            if resp.status_code == 404:  # very old Ollama without /api/embed
                for text in batch:
                    old = self._post("/api/embeddings", {"model": self.model, "prompt": text})
                    old.raise_for_status()
                    out.append(old.json()["embedding"])
                continue
            if resp.status_code >= 400:
                raise LLMError(f"Ollama embeddings error {resp.status_code}: {resp.text[:300]}")
            out.extend(resp.json()["embeddings"])
        return out


def make_embedder(cfg: dict):
    emb = cfg["embeddings"]
    if emb["provider"] == "hash":
        return HashEmbedder(emb.get("hash_dim", 1024))
    if emb["provider"] == "ollama":
        return OllamaEmbedder(emb["model"], emb["ollama_url"])
    raise LLMError(f"unknown embeddings provider '{emb['provider']}' (use ollama or hash)")
