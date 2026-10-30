"""Agent 3 - rule synthesis (Sigma for behaviours in logs, YARA for file-level indicators).

The LLM writes the rule; on a retry it also receives the validator's error messages and its previous rule.
Deterministic metadata (id, date, author, ATT&CK tags) is normalised afterwards so the model only has to
get the detection logic right. In offline mode the template generator is used directly.
"""
from __future__ import annotations

import datetime as dt
import re
import uuid

import yaml

from .. import templates
from ..llm import BaseLLM, LLMError, extract_code
from . import prompts

KEY_ORDER = ["title", "id", "status", "description", "references", "author", "date", "modified", "tags",
             "logsource", "detection", "falsepositives", "level"]


def normalise_sigma(text: str, task: dict) -> str:
    """Fill id/date/author, make sure the mapped ATT&CK tags are present, keep the usual key order."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return text
    if not isinstance(doc, dict):
        return text
    try:
        uuid.UUID(str(doc.get("id", "")))
    except ValueError:
        doc["id"] = str(uuid.uuid4())
    doc["status"] = doc.get("status") or "experimental"
    doc["author"] = "CTI-RAG prototype (LLM-generated, needs analyst review)"
    doc["date"] = dt.date.today()
    tags = doc.get("tags") if isinstance(doc.get("tags"), list) else []
    tags = [str(t).strip().lower().replace(" ", "-") for t in tags if str(t).strip()]
    for tid in task.get("technique_ids", []):
        if f"attack.{tid.lower()}" not in tags:
            tags.append(f"attack.{tid.lower()}")
    doc["tags"] = list(dict.fromkeys(tags))
    ordered = {k: doc[k] for k in KEY_ORDER if k in doc}
    ordered.update({k: v for k, v in doc.items() if k not in ordered})
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=1000)


class RuleWriter:
    def __init__(self, llm: BaseLLM | None, cfg: dict, log=print):
        self.llm = llm
        self.log = log

    def generate(self, task: dict, feedback: dict | None = None) -> tuple[str, str]:
        """Return (rule_text, source) where source is 'llm' or 'template'."""
        if self.llm is None:
            return self.template(task), "template"
        if task["rule_type"] == "yara":
            system, user, lang = prompts.AGENT3_YARA_SYSTEM, self._yara_prompt(task), "yara"
        else:
            system, user, lang = prompts.AGENT3_SIGMA_SYSTEM, self._sigma_prompt(task), "yaml"
        if feedback:
            user += prompts.RETRY_FEEDBACK.format(errors="\n".join(f"- {e}" for e in feedback["errors"][:8]),
                                                  previous=feedback["rule"][:4000], lang=lang)
        try:
            reply = self.llm.chat(system, user)
        except LLMError as exc:
            self.log(f"[Agent 3] LLM error: {exc}")
            raise
        rule = extract_code(reply, ("yara", "yar") if lang == "yara" else ("yaml", "yml", "sigma"))
        if task["rule_type"] == "sigma":
            rule = normalise_sigma(rule, task)
        return rule, "llm"

    @staticmethod
    def template(task: dict) -> str:
        if task["rule_type"] == "yara":
            return templates.yara_from_iocs(task.get("iocs", {}), task.get("source", "report")) or ""
        return templates.sigma_from_task(task) or ""

    @staticmethod
    def _sigma_prompt(task: dict) -> str:
        techniques = "; ".join(f"{t['id']} {t['name']} (tactics: {', '.join(t['tactics'])})" for t in task["techniques"])
        tag_lines = [f"  - attack.{tac}" for tac in task.get("tactics", [])[:2]]
        tag_lines += [f"  - attack.{tid.lower()}" for tid in task["technique_ids"]]
        return prompts.AGENT3_SIGMA_USER.format(
            action=task["action"], evidence=task.get("evidence", ""), commands=task.get("commands") or "none",
            artifacts=task.get("artifacts") or "none", platform=task.get("platform", "unknown"),
            techniques=techniques, tags="\n".join(tag_lines))

    @staticmethod
    def _yara_prompt(task: dict) -> str:
        iocs = task.get("iocs", {})
        lines = []
        for kind, label in (("domain", "domains"), ("url", "urls"), ("filename", "file names"),
                            ("sha256", "sha256"), ("md5", "md5"), ("sha1", "sha1")):
            if iocs.get(kind):
                lines.append(f"- {label}: {', '.join(iocs[kind][:10])}")
        rule_name = re.sub(r"\W+", "_", task.get("source", "report")).strip("_")
        return prompts.AGENT3_YARA_USER.format(source=rule_name, indicators="\n".join(lines) or "- none",
                                               behaviours="; ".join(task.get("behaviours", [])[:5]) or "n/a")
