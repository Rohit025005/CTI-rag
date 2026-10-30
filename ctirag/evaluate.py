"""Evaluation: ATT&CK mapping accuracy and rule validity rate, pipeline vs plain-LLM baseline.

Gold file format (JSON list):  [{"file": "samples/x.txt", "techniques": ["T1059.001", ...]}, ...]
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .baseline import run_baseline
from .config import ROOT
from .ingest import read_document


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3), "tp": tp, "fp": fp, "fn": fn}


def _parent(ids) -> set[str]:
    return {i.split(".")[0] for i in ids}


def score(gold: set[str], pred: set[str]) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    strict = (len(gold & pred), len(pred - gold), len(gold - pred))
    g, p = _parent(gold), _parent(pred)
    parent = (len(g & p), len(p - g), len(g - p))
    return strict, parent


def evaluate(pipeline, gold_path: str | Path, run_baseline_too: bool = True, log=print) -> dict:
    gold_path = Path(gold_path)
    items = json.loads(gold_path.read_text(encoding="utf-8"))
    modes = ["pipeline"] + (["baseline"] if run_baseline_too and pipeline.llm is not None else [])
    results = {m: {"items": [], "strict": [0, 0, 0], "parent": [0, 0, 0], "rules": 0, "valid": 0,
                   "valid_first": 0, "proposed": 0, "hallucinated": 0, "seconds": 0.0} for m in modes}
    for item in items:
        path = Path(item["file"])
        path = path if path.is_absolute() else (gold_path.parent / path if (gold_path.parent / path).exists() else ROOT / path)
        text = read_document(path)
        gold = {t.upper() for t in item["techniques"]}
        for mode in modes:
            log(f"[Eval] {mode}: {path.name}")
            t0 = time.time()
            if mode == "pipeline":
                state = pipeline.run(text, path.stem)
                pred = set(state["stats"]["techniques"])
                rules = state["rules"]
                n_rules, n_valid = len(rules), sum(r["status"] in ("valid", "fallback") for r in rules)
                n_first = state["stats"]["valid_first_try"]
                proposed, halluc = state["stats"]["proposed_ids"], state["stats"]["rejected_ids"]
            else:
                out = run_baseline(pipeline.llm, text, pipeline.kb, pipeline.validator)
                pred = set(out["techniques"])
                n_rules, n_valid = len(out["rules"]), sum(r["ok"] for r in out["rules"])
                n_first = n_valid
                proposed, halluc = len(out["proposed_ids"]), len(out["hallucinated_ids"])
            res = results[mode]
            strict, parent = score(gold, pred)
            for i in range(3):
                res["strict"][i] += strict[i]
                res["parent"][i] += parent[i]
            res["rules"] += n_rules
            res["valid"] += n_valid
            res["valid_first"] += n_first
            res["proposed"] += proposed
            res["hallucinated"] += halluc
            res["seconds"] += time.time() - t0
            res["items"].append({"file": path.name, "gold": sorted(gold), "predicted": sorted(pred),
                                 "strict": _prf(*strict), "rules": n_rules, "valid": n_valid})

    summary = {}
    for mode, res in results.items():
        summary[mode] = {
            "mapping_strict": _prf(*res["strict"]),
            "mapping_parent_level": _prf(*res["parent"]),
            "rule_validity_rate": round(res["valid"] / res["rules"], 3) if res["rules"] else None,
            "first_try_validity_rate": round(res["valid_first"] / res["rules"], 3) if res["rules"] else None,
            "hallucinated_id_rate": round(res["hallucinated"] / res["proposed"], 3) if res["proposed"] else 0.0,
            "rules": res["rules"],
            "seconds": round(res["seconds"], 1),
            "items": res["items"],
        }
    return {"gold_file": str(gold_path), "mode_llm": pipeline.llm.describe() if pipeline.llm else "offline",
            "summary": summary}


def markdown_table(report: dict) -> str:
    rows = ["| Mode | Mapping P | Mapping R | Mapping F1 | F1 (parent level) | Rule validity | First-try validity | Hallucinated IDs |",
            "|---|---|---|---|---|---|---|---|"]
    for mode, s in report["summary"].items():
        rows.append(f"| {mode} | {s['mapping_strict']['precision']} | {s['mapping_strict']['recall']} | "
                    f"{s['mapping_strict']['f1']} | {s['mapping_parent_level']['f1']} | {s['rule_validity_rate']} | "
                    f"{s['first_try_validity_rate']} | {s['hallucinated_id_rate']} |")
    return "\n".join(rows)
