"""MITRE ATT&CK Enterprise knowledge base: STIX parsing, ChromaDB indexing and retrieval.

ATT&CK(R) content (c) The MITRE Corporation, used under MITRE's ATT&CK terms of use.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import chromadb
import requests
from chromadb.config import Settings

from .embeddings import tokens

TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML = re.compile(r"<[^>]+>")


def clean_description(text: str) -> str:
    text = _CITATION.sub("", text or "")
    text = _MDLINK.sub(r"\1", text)
    text = _HTML.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def parse_stix(path: str | Path) -> dict:
    """Extract active (not revoked / deprecated) techniques and sub-techniques from the STIX bundle."""
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    objects = bundle.get("objects", [])
    version = next((o.get("x_mitre_version") for o in objects if o.get("type") == "x-mitre-collection"), "unknown")

    raw = []
    stix_to_tid = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = _external_id(obj)
        if tid:
            stix_to_tid[obj["id"]] = tid
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if tid and TID_RE.match(tid):
            raw.append((tid, obj))
    names = {tid: obj["name"] for tid, obj in raw}
    # Revoked IDs -> replacement, so validator errors can say e.g. "T1070.001 was revoked, use T1685.005".
    revoked = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            old, new = stix_to_tid.get(obj.get("source_ref")), stix_to_tid.get(obj.get("target_ref"))
            if old and new and new in names:
                revoked[old] = new

    techniques = []
    for tid, obj in sorted(raw, key=lambda item: item[0]):
        parent = tid.split(".")[0]
        full_name = f"{names[parent]}: {obj['name']}" if "." in tid and parent in names else obj["name"]
        techniques.append({
            "id": tid,
            "name": obj["name"],
            "full_name": full_name,
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": "." in tid,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "description": clean_description(obj.get("description", ""))[:2500],
        })
    return {"attack_version": version, "domain": "enterprise-attack", "techniques": techniques,
            "revoked": dict(sorted(revoked.items()))}


def download_stix(url: str, path: str | Path, log=print) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    log(f"Downloading MITRE ATT&CK Enterprise STIX data from {url} ...")
    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        tmp = path.with_suffix(".part")
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
        tmp.replace(path)
    log(f"Saved {path} ({path.stat().st_size / 1e6:.1f} MB)")


def ensure_techniques(cfg: dict, refresh: bool = False, log=print) -> dict:
    """Load the parsed technique list, creating it from STIX (downloading if needed)."""
    tpath = Path(cfg["kb"]["techniques_path"])
    if tpath.exists() and not refresh:
        with open(tpath, encoding="utf-8") as fh:
            return json.load(fh)
    spath = Path(cfg["kb"]["stix_path"])
    if refresh or not spath.exists():
        download_stix(cfg["kb"]["stix_url"], spath, log)
    data = parse_stix(spath)
    tpath.parent.mkdir(parents=True, exist_ok=True)
    with open(tpath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, ensure_ascii=False)
    log(f"Parsed {len(data['techniques'])} techniques (ATT&CK v{data['attack_version']}) -> {tpath}")
    return data


def technique_document(t: dict) -> str:
    return (f"{t['full_name']} ({t['id']}). Tactics: {', '.join(t['tactics'])}. "
            f"Platforms: {', '.join(t['platforms'])}. {t['description'][:1500]}")


class AttackKB:
    """Vector index of ATT&CK techniques in ChromaDB plus an exact-ID lookup table."""

    def __init__(self, cfg: dict, embedder, log=print):
        self.cfg = cfg
        self.embedder = embedder
        self.log = log
        self.data = ensure_techniques(cfg, log=log)
        self.version = self.data["attack_version"]
        self.techniques = self.data["techniques"]
        self.by_id = {t["id"]: t for t in self.techniques}
        self.revoked = self.data.get("revoked", {})
        Path(cfg["kb"]["chroma_dir"]).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=cfg["kb"]["chroma_dir"],
                                                settings=Settings(anonymized_telemetry=False))
        self.collection_name = f"attack-v{self.version}-{embedder.slug}"[:60]
        self._collection = None

    # ------------------------------------------------------------- index
    def _get_collection(self):
        if self._collection is None:
            self._collection = self.client.get_collection(self.collection_name, embedding_function=None)
        return self._collection

    def is_built(self) -> bool:
        try:
            return self._get_collection().count() == len(self.techniques)
        except Exception:  # noqa: BLE001 - collection missing
            self._collection = None
            return False

    def build(self, rebuild: bool = False, batch: int = 64) -> None:
        if rebuild:
            try:
                self.client.delete_collection(self.collection_name)
            except Exception:  # noqa: BLE001
                pass
            self._collection = None
        if self.is_built():
            self.log(f"Knowledge base '{self.collection_name}' already built ({len(self.techniques)} techniques).")
            return
        try:
            self.client.delete_collection(self.collection_name)  # remove partial builds
        except Exception:  # noqa: BLE001
            pass
        col = self.client.create_collection(
            self.collection_name, embedding_function=None,
            metadata={"hnsw:space": "cosine", "embedder": self.embedder.name, "attack_version": str(self.version)})
        self.log(f"Embedding {len(self.techniques)} ATT&CK techniques with {self.embedder.name} ...")
        for i in range(0, len(self.techniques), batch):
            chunk = self.techniques[i:i + batch]
            docs = [technique_document(t) for t in chunk]
            col.add(ids=[t["id"] for t in chunk], documents=docs,
                    embeddings=self.embedder.embed(docs, kind="document"),
                    metadatas=[{"name": t["name"], "full_name": t["full_name"],
                                "tactics": ",".join(t["tactics"]), "platforms": ",".join(t["platforms"])}
                               for t in chunk])
            self.log(f"  indexed {min(i + batch, len(self.techniques))}/{len(self.techniques)}")
        self._collection = col
        self.log(f"Knowledge base ready: collection '{self.collection_name}'.")

    def ensure_built(self) -> None:
        if not self.is_built():
            self.build()

    # ------------------------------------------------------------- lookup
    def is_valid(self, tid: str) -> bool:
        return (tid or "").strip().upper() in self.by_id

    def get(self, tid: str) -> dict | None:
        return self.by_id.get((tid or "").strip().upper())

    def replacement(self, tid: str) -> str | None:
        """If `tid` was revoked in this ATT&CK version, the technique that replaced it."""
        return self.revoked.get((tid or "").strip().upper())

    def search(self, text: str, k: int = 5) -> list[dict]:
        """Hybrid retrieval: vector similarity, re-ranked with a small keyword bonus on technique names."""
        self.ensure_built()
        query_vec = self.embedder.embed([text], kind="query")[0]
        n = min(len(self.techniques), max(3 * k, k))
        res = self._get_collection().query(query_embeddings=[query_vec], n_results=n,
                                           include=["distances", "metadatas"])
        q_tokens = set(tokens(text))
        candidates = []
        for tid, dist, meta in zip(res["ids"][0], res["distances"][0], res["metadatas"][0]):
            name_tokens = set(tokens(meta.get("full_name", "")))
            overlap = len(name_tokens & q_tokens) / len(name_tokens) if name_tokens else 0.0
            similarity = 1.0 - float(dist)
            t = self.by_id[tid]
            candidates.append({
                "id": tid, "name": t["full_name"], "tactics": t["tactics"],
                "similarity": round(similarity, 4), "score": round(similarity + 0.15 * overlap, 4),
                "url": t["url"],
            })
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates[:k]
