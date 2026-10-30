"""Plain-LLM baseline for the evaluation: one prompt, no retrieval, no validation loop."""
from __future__ import annotations

import re
import time

from .agents import prompts
from .agents.validator import RuleValidator
from .llm import BaseLLM, extract_code

TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


def run_baseline(llm: BaseLLM, text: str, kb, validator: RuleValidator | None = None) -> dict:
    validator = validator or RuleValidator(kb)
    started = time.time()
    reply = llm.chat(prompts.BASELINE_SYSTEM, prompts.BASELINE_USER.format(report=text[:8000]))
    head = reply.split("```")[0]
    ids = list(dict.fromkeys(m.upper() for m in TID.findall(head))) or \
        list(dict.fromkeys(m.upper() for m in TID.findall(reply)))
    rule = extract_code(reply, ("yaml", "yml", "sigma"))
    result = validator.validate_sigma(rule) if "```" in reply else validator.validate_sigma("")
    return {
        "techniques": [i for i in ids if kb.is_valid(i)],
        "proposed_ids": ids,
        "hallucinated_ids": [i for i in ids if not kb.is_valid(i)],
        "rules": [{"rule": rule, "ok": result.ok, "errors": result.errors}],
        "seconds": round(time.time() - started, 1),
    }
