"""Orchestrator: runs the four agents in order and passes one shared state between them.

    report -> chunk -> Agent 1 extract -> Agent 2 retrieve top-k + map
           -> for each rule task: up to N x (Agent 3 generate -> Agent 4 validate, feed errors back)
           -> only validated rules are output; the rest go to the manual-review queue
"""
from __future__ import annotations

import datetime as dt
import re
import time

from . import __version__
from . import ioc as ioc_mod
from .agents.extractor import Extractor
from .agents.mapper import Mapper
from .agents.rule_writer import RuleWriter
from .agents.validator import RuleValidator
from .attack_kb import AttackKB
from .embeddings import make_embedder
from .ingest import chunk_text
from .llm import BaseLLM, LLMError, make_llm


def slugify(text: str, n: int = 40) -> str:
    return (re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower() or "report")[:n]


class Pipeline:
    def __init__(self, cfg: dict, llm: BaseLLM | None = None, kb: AttackKB | None = None, log=print):
        self.cfg = cfg
        self.log = log
        self.llm = llm
        self.kb = kb or AttackKB(cfg, make_embedder(cfg), log=log)
        self.kb.ensure_built()
        self.validator = RuleValidator(self.kb)

    @classmethod
    def from_config(cls, cfg: dict, use_alt_model: bool = False, log=print) -> "Pipeline":
        return cls(cfg, make_llm(cfg, use_alt_model), log=log)

    @property
    def mode(self) -> str:
        return "offline" if self.llm is None else "llm"

    # ------------------------------------------------------------------ run
    def run(self, text: str, source: str = "report") -> dict:
        p = self.cfg["pipeline"]
        started = time.time()
        timings: dict[str, float] = {}
        if self.llm is not None:
            self.llm.calls, self.llm.seconds = 0, 0.0
        self.log(f"[Orchestrator] {self.mode} mode | model: {self.llm.describe() if self.llm else 'none'} | "
                 f"k={p['top_k']} N={p['max_retries']}")

        chunks = chunk_text(text, p["chunk_chars"])
        iocs = ioc_mod.extract_iocs(text)

        t = time.time()
        extractor = Extractor(self.llm, self.cfg, self.log)
        behaviors = extractor.run(chunks, iocs, text)
        timings["agent1_extract"] = time.time() - t

        t = time.time()
        mapper = Mapper(self.llm, self.kb, self.cfg, self.log)
        mapper.run(behaviors)
        timings["agent2_map"] = time.time() - t

        tasks = self.build_tasks(behaviors, iocs, source)
        self.log(f"[Orchestrator] {len(tasks)} rule task(s) queued")
        writer = RuleWriter(self.llm, self.cfg, self.log)
        rules, review = [], []
        timings["agent3_generate"] = timings["agent4_validate"] = 0.0
        for task in tasks:
            record = self._synthesise(task, writer, timings)
            rules.append(record)
            if record["status"] != "valid":
                review.append({"task_id": record["task_id"], "behavior_id": record["behavior_id"],
                               "technique_ids": record["technique_ids"], "rule_type": record["rule_type"],
                               "reason": ("template fallback after failed LLM attempts" if record["status"] == "fallback"
                                          else "no valid rule after all attempts"),
                               "last_errors": record["attempts"][-1]["errors"] if record["attempts"] else []})
        timings["total"] = time.time() - started

        state = {
            "run_id": time.strftime("%Y%m%d-%H%M%S") + "-" + slugify(source, 30),
            "source": source,
            "created": dt.datetime.now().isoformat(timespec="seconds"),
            "version": __version__,
            "mode": self.mode,
            "llm": self.llm.describe() if self.llm else "offline (heuristics + templates)",
            "embedder": self.kb.embedder.name,
            "attack_version": self.kb.version,
            "params": {k: p[k] for k in ("top_k", "max_retries", "template_fallback")},
            "iocs": iocs,
            "behaviors": behaviors,
            "unmapped_behaviors": [b["id"] for b in behaviors if not b.get("techniques")],
            "rules": rules,
            "review_queue": review,
            "stats": self._stats(chunks, iocs, behaviors, rules, mapper, extractor),
            "timings_s": {k: round(v, 2) for k, v in timings.items()},
            "llm_usage": self.llm.usage() if self.llm else None,
        }
        s = state["stats"]
        self.log(f"[Orchestrator] done in {timings['total']:.1f}s: {s['rules_valid']} valid, "
                 f"{s['rules_fallback']} fallback, {s['rules_flagged']} flagged")
        return state

    # ------------------------------------------------------------------ tasks
    def build_tasks(self, behaviors: list[dict], iocs: dict, source: str) -> list[dict]:
        p = self.cfg["pipeline"]
        tasks: list[dict] = []
        for b in behaviors:
            if not b.get("techniques"):
                continue
            if len(tasks) >= p["max_rules"]:
                break
            primary = b["techniques"][0]
            tasks.append({
                "task_id": f"R{len(tasks) + 1}", "rule_type": "sigma", "behavior_id": b["id"], "source": source,
                "action": b["action"], "evidence": b.get("evidence", ""), "commands": b.get("commands", []),
                "artifacts": b.get("artifacts", []), "platform": b.get("platform", "unknown"),
                "techniques": b["techniques"], "technique_ids": [t["id"] for t in b["techniques"]],
                "tactics": primary["tactics"], "technique_name": primary["name"],
            })
        file_iocs = {k: iocs.get(k, []) for k in ("domain", "url", "filename", "sha256", "md5", "sha1")}
        n_hash = sum(len(file_iocs[k]) for k in ("sha256", "md5", "sha1"))
        n_str = sum(len(file_iocs[k]) for k in ("domain", "url", "filename"))
        if p["make_yara"] and (n_hash or n_str >= 2):
            tasks.append({
                "task_id": f"R{len(tasks) + 1}", "rule_type": "yara", "behavior_id": None, "source": source,
                "action": "Files containing the report's indicators", "evidence": "", "commands": [], "artifacts": [],
                "platform": "unknown", "techniques": [], "technique_ids": [], "tactics": [],
                "technique_name": "File-level IOCs", "iocs": file_iocs,
                "behaviours": [b["action"] for b in behaviors][:5],
            })
        return tasks

    # ------------------------------------------------------------------ retry loop
    def _synthesise(self, task: dict, writer: RuleWriter, timings: dict) -> dict:
        max_n = self.cfg["pipeline"]["max_retries"]
        attempts, feedback, final = [], None, None
        for n in range(1, max_n + 1):
            self.log(f"[Agent 3] {task['task_id']} {task['rule_type']} for "
                     f"{', '.join(task['technique_ids']) or 'file IOCs'} - attempt {n}/{max_n}")
            t = time.time()
            try:
                rule, source = writer.generate(task, feedback)
            except LLMError as exc:
                timings["agent3_generate"] += time.time() - t
                attempts.append({"n": n, "rule": "", "source": "llm", "ok": False, "rule_type": task["rule_type"],
                                 "errors": [f"LLM error: {exc}"], "warnings": [], "converted": None})
                break
            timings["agent3_generate"] += time.time() - t
            if source == "template" and not rule:
                attempts.append({"n": n, "rule": "", "source": "template", "ok": False, "rule_type": task["rule_type"],
                                 "errors": ["No command line or indicator in this behaviour to build a template rule "
                                            "(needs the LLM mode or an analyst)"], "warnings": [], "converted": None})
                self.log(f"[Agent 4] {task['task_id']}: nothing concrete to build a template rule from")
                break
            t = time.time()
            result = self.validator.validate(task["rule_type"], rule)
            timings["agent4_validate"] += time.time() - t
            attempts.append({"n": n, "rule": rule, "source": source, **result.to_dict()})
            self.log(f"[Agent 4] {task['task_id']} attempt {n}: "
                     + ("VALID" if result.ok else "INVALID - " + " | ".join(result.errors[:2])))
            if result.ok:
                final = attempts[-1]
                break
            if source == "template":           # deterministic: retrying cannot change the output
                break
            feedback = {"rule": rule, "errors": result.errors}

        status = "valid" if final else "flagged"
        if final is None and self.cfg["pipeline"]["template_fallback"] and self.llm is not None:
            rule = writer.template(task)
            if rule:
                result = self.validator.validate(task["rule_type"], rule)
                attempts.append({"n": len(attempts) + 1, "rule": rule, "source": "template", **result.to_dict()})
                if result.ok:
                    final, status = attempts[-1], "fallback"
                    self.log(f"[Orchestrator] {task['task_id']}: template fallback used (flagged for review)")
        if final is None:
            self.log(f"[Orchestrator] {task['task_id']}: flagged for manual review")

        return {
            "task_id": task["task_id"], "rule_type": task["rule_type"], "behavior_id": task["behavior_id"],
            "technique_ids": task["technique_ids"], "technique_name": task["technique_name"],
            "action": task["action"], "status": status,
            "source": final["source"] if final else None,
            "final_rule": final["rule"] if final else None,
            "converted": final.get("converted") if final else None,
            "warnings": final.get("warnings", []) if final else [],
            "attempts": attempts,
            "llm_attempts": sum(1 for a in attempts if a["source"] == "llm"),
        }

    # ------------------------------------------------------------------ stats
    @staticmethod
    def _stats(chunks, iocs, behaviors, rules, mapper: Mapper, extractor: Extractor) -> dict:
        total = len(rules)
        valid = sum(r["status"] == "valid" for r in rules)
        fallback = sum(r["status"] == "fallback" for r in rules)
        llm_rules = [r for r in rules if r["llm_attempts"]]
        return {
            "chunks": len(chunks),
            "iocs": ioc_mod.count(iocs),
            "behaviors": len(behaviors),
            "behaviors_mapped": sum(1 for b in behaviors if b.get("techniques")),
            "ungrounded_dropped": extractor.dropped_ungrounded,
            "techniques": sorted({t["id"] for b in behaviors for t in b.get("techniques", [])}),
            "proposed_ids": mapper.proposed_total,
            "rejected_ids": mapper.rejected_total,
            "rules_total": total,
            "rules_valid": valid,
            "rules_fallback": fallback,
            "rules_flagged": total - valid - fallback,
            "valid_first_try": sum(1 for r in rules if r["status"] == "valid" and len(r["attempts"]) == 1),
            "validity_rate": round((valid + fallback) / total, 3) if total else None,
            "avg_llm_attempts": round(sum(r["llm_attempts"] for r in llm_rules) / len(llm_rules), 2) if llm_rules else None,
        }
