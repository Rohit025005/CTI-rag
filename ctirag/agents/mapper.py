"""Agent 2 - ATT&CK technique mapping.

For every behaviour: retrieve the top-k ATT&CK entries from ChromaDB, let the LLM choose among ONLY those
candidates, then drop any ID that is not a candidate or not in the official ATT&CK list (hallucination guard).
Offline mode accepts the best-scoring candidate above a threshold.
"""
from __future__ import annotations

import re

from ..llm import BaseLLM, LLMError
from ..lookup import keyword_hits
from . import prompts

TID = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


class Mapper:
    def __init__(self, llm: BaseLLM | None, kb, cfg: dict, log=print):
        self.llm = llm
        self.kb = kb
        self.k = cfg["pipeline"]["top_k"]
        self.max_m = cfg["pipeline"]["max_techniques_per_behavior"]
        self.min_score = cfg["pipeline"]["min_retrieval_score"]
        self.use_lookup = cfg["pipeline"].get("keyword_lookup", True)
        self.log = log
        self.rejected_total = 0
        self.proposed_total = 0

    @staticmethod
    def query_text(b: dict) -> str:
        parts = [b["action"], b.get("evidence", "")]
        if b.get("commands"):
            parts.append("Commands: " + " ; ".join(b["commands"]))
        return ". ".join(p for p in parts if p)

    def run(self, behaviors: list[dict]) -> list[dict]:
        for b in behaviors:
            text = self.query_text(b)
            try:
                candidates = self.kb.search(text, self.k)
                for c in candidates:
                    c["via"] = "vector"
            except Exception as exc:  # noqa: BLE001 - backup plan: fall back to the lookup table
                self.log(f"[Agent 2] retrieval failed ({exc}); using the fixed ATT&CK lookup table")
                candidates = []
            hits = keyword_hits(text, self.kb) if self.use_lookup else []
            b["keyword_hits"] = hits
            seen = {c["id"] for c in candidates}
            for tid in hits[:3]:                           # hybrid: add keyword hits retrieval missed
                if tid not in seen:
                    t = self.kb.get(tid)
                    candidates.append({"id": tid, "name": t["full_name"], "tactics": t["tactics"], "url": t["url"],
                                       "similarity": None, "score": None, "via": "keyword"})
            b["candidates"] = candidates
            b["techniques"], b["rejected_ids"] = (self._llm_map(b, candidates) if self.llm
                                                  else self._offline_map(candidates, hits))
            names = ", ".join(t["id"] for t in b["techniques"]) or "no match"
            self.log(f"[Agent 2] {b['id']}: {names}"
                     + (f" (rejected {', '.join(b['rejected_ids'])})" if b["rejected_ids"] else ""))
        return behaviors

    def _technique(self, tid: str, confidence: float, reason: str, cand: dict | None) -> dict:
        t = self.kb.get(tid)
        return {"id": t["id"], "name": t["full_name"], "tactics": t["tactics"], "url": t["url"],
                "confidence": round(max(0.0, min(1.0, confidence)), 2), "reason": reason,
                "retrieval_score": cand["score"] if cand else None}

    def _llm_map(self, b: dict, candidates: list[dict]):
        lines = []
        for i, c in enumerate(candidates, 1):
            desc = self.kb.get(c["id"])["description"][:350]
            via = " [keyword match]" if c.get("via") == "keyword" else ""
            lines.append(f"{i}. {c['id']} - {c['name']} (tactics: {', '.join(c['tactics'])}){via}: {desc}")
        user = prompts.AGENT2_USER.format(action=b["action"], evidence=b.get("evidence", ""),
                                          commands=b.get("commands") or "none", candidates="\n".join(lines),
                                          max_m=self.max_m)
        try:
            data = self.llm.chat_json(prompts.AGENT2_SYSTEM, user)
        except LLMError as exc:
            self.log(f"[Agent 2] LLM error for {b['id']}: {exc}")
            raise
        by_id = {c["id"]: c for c in candidates}
        chosen, rejected = [], []
        for m in data.get("matches", []) or []:
            if not isinstance(m, dict):
                continue
            raw = str(m.get("technique_id", "")).strip().upper()
            found = TID.search(raw)
            tid = found.group(0).upper() if found else raw
            self.proposed_total += 1
            if tid not in by_id or not self.kb.is_valid(tid):        # hallucination guard
                rejected.append(tid or "?")
                self.rejected_total += 1
                continue
            if any(t["id"] == tid for t in chosen):
                continue
            try:
                conf = float(m.get("confidence", 0.5))
            except (TypeError, ValueError):
                conf = 0.5
            chosen.append(self._technique(tid, conf, str(m.get("reason", ""))[:300], by_id[tid]))
            if len(chosen) >= self.max_m:
                break
        return chosen, rejected

    def _offline_map(self, candidates: list[dict], hits: list[str]):
        by_id = {c["id"]: c for c in candidates}
        if hits:
            self.proposed_total += min(len(hits), self.max_m)
            return [self._technique(tid, 0.9, "keyword lookup table (offline mode)", by_id.get(tid))
                    for tid in hits[: self.max_m]], []
        vector = [c for c in candidates if c.get("via") == "vector"]
        if vector and vector[0]["score"] >= self.min_score:
            c = vector[0]
            self.proposed_total += 1
            return [self._technique(c["id"], c["score"], "highest retrieval score (offline mode)", c)], []
        return [], []
