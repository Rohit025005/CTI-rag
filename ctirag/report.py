"""Write a run to disk: report.json (full shared state), summary.md and the rule files."""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path


def _safe(text: str, n: int = 50) -> str:
    return (re.sub(r"[^A-Za-z0-9]+", "_", text or "").strip("_") or "rule")[:n]


def save_run(state: dict, out_dir: str | Path) -> Path:
    run_dir = Path(out_dir) / state["run_id"]
    (run_dir / "rules").mkdir(parents=True, exist_ok=True)
    for r in state["rules"]:
        if not r["final_rule"]:
            continue
        ext = "yar" if r["rule_type"] == "yara" else "yml"
        tag = "" if r["status"] == "valid" else "_NEEDS_REVIEW"
        name = f"{r['task_id']}_{'_'.join(r['technique_ids']) or 'file_iocs'}{tag}.{ext}"
        (run_dir / "rules" / _safe(name.rsplit('.', 1)[0], 80)).with_suffix("." + ext).write_text(r["final_rule"], encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
    (run_dir / "summary.md").write_text(summary_markdown(state), encoding="utf-8")
    return run_dir


def zip_run(run_dir: str | Path) -> bytes:
    run_dir = Path(run_dir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(run_dir.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(run_dir.parent))
    return buf.getvalue()


def summary_markdown(state: dict) -> str:
    s = state["stats"]
    lines = [
        f"# CTI-RAG run `{state['run_id']}`",
        "",
        f"- Source: **{state['source']}**  ",
        f"- Mode: {state['mode']} | LLM: {state['llm']} | embeddings: {state['embedder']} | "
        f"ATT&CK v{state['attack_version']}",
        f"- Parameters: k={state['params']['top_k']}, N={state['params']['max_retries']}, "
        f"template fallback={state['params']['template_fallback']}",
        f"- Time: {state['timings_s'].get('total')} s",
        "",
        "## Results",
        "",
        f"| IOCs | Behaviours | Mapped | Techniques | Rules | Valid | Fallback | Flagged | Rejected IDs |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| {s['iocs']} | {s['behaviors']} | {s['behaviors_mapped']} | {len(s['techniques'])} | {s['rules_total']} | "
        f"{s['rules_valid']} | {s['rules_fallback']} | {s['rules_flagged']} | {s['rejected_ids']} |",
        "",
        "## Behaviours and ATT&CK techniques",
        "",
        "| ID | Behaviour | Techniques |",
        "|---|---|---|",
    ]
    for b in state["behaviors"]:
        techs = ", ".join(f"{t['id']} {t['name']}" for t in b.get("techniques", [])) or "_unmapped_"
        lines.append(f"| {b['id']} | {b['action'].replace('|', '/')} | {techs} |")
    lines += ["", "## Rules", ""]
    for r in state["rules"]:
        lines.append(f"### {r['task_id']} - {r['rule_type'].upper()} - {', '.join(r['technique_ids']) or 'file IOCs'} "
                     f"- **{r['status']}** ({len(r['attempts'])} attempt(s))")
        for a in r["attempts"]:
            verdict = "valid" if a["ok"] else "invalid: " + "; ".join(a["errors"][:3])
            lines.append(f"- attempt {a['n']} ({a['source']}): {verdict}")
        if r["final_rule"]:
            lang = "yara" if r["rule_type"] == "yara" else "yaml"
            lines += ["", f"```{lang}", r["final_rule"].rstrip(), "```"]
        if r.get("converted"):
            lines += ["", "Splunk:", "```", r["converted"], "```"]
        lines.append("")
    iocs = {k: v for k, v in state["iocs"].items() if v}
    if iocs:
        lines += ["## IOCs", ""]
        for kind, values in iocs.items():
            lines.append(f"- **{kind}**: " + ", ".join(f"`{v}`" for v in values[:30]))
    if state["review_queue"]:
        lines += ["", "## Manual review queue", ""]
        for item in state["review_queue"]:
            lines.append(f"- {item['task_id']} ({item['rule_type']}, {', '.join(item['technique_ids']) or 'file IOCs'}): "
                         f"{item['reason']}")
    return "\n".join(lines) + "\n"
