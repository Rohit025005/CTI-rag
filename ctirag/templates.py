"""Template rules: the backup plan when the LLM cannot produce a valid rule after N attempts,
and the generator used in offline mode. Template output is always flagged for analyst review."""
from __future__ import annotations

import datetime as dt
import re
import uuid

import yaml

from . import ioc as ioc_mod

NOTABLE_ARGS = re.compile(r"(?i)^(?:[-/][a-z][\w-]*|iex|invoke-\w+|downloadstring|downloadfile|frombase64string|"
                          r"comsvcs|minidump|delete|shadows|create|add|\\run|urlcache|transfer)$")


_CRON_PREFIX = re.compile(r"^(?:[\d*/,-]+\s+){5}")


def _clean_command(command: str) -> str:
    """Drop a cron schedule prefix and 'sudo', keep the first command of a pipeline."""
    cmd = _CRON_PREFIX.sub("", command.strip())
    cmd = re.sub(r"^sudo\s+", "", cmd)
    return cmd.split("|")[0].strip() or command.strip()


def _exe_name(command: str) -> str:
    parts = _clean_command(command).split()
    if not parts:
        return ""
    return re.split(r"[\\/]", parts[0].strip("\"'"))[-1]


def _product(platform: str) -> str:
    return platform if platform in ("windows", "linux", "macos") else "windows"


def _tags(technique_ids: list[str], tactics: list[str]) -> list[str]:
    tags = [f"attack.{t.replace('_', '-')}" for t in tactics]
    tags += [f"attack.{tid.lower()}" for tid in technique_ids]
    return list(dict.fromkeys(tags))


def _command_selection(cmd: str, product: str) -> dict:
    exe = _exe_name(cmd)
    clean = _clean_command(cmd)
    args = [tok for tok in re.split(r"\s+", clean)[1:] if NOTABLE_ARGS.match(tok.strip("\"'"))][:3]
    selection: dict = {}
    if exe and re.match(r"^[\w.-]+$", exe):
        if product == "windows":
            selection["Image|endswith"] = "\\" + (exe if "." in exe else exe + ".exe")
        else:
            selection["Image|endswith"] = "/" + exe
    if args:
        selection["CommandLine|contains|all"] = args
    elif len(clean) <= 160:
        selection["CommandLine|contains"] = clean
    return selection


def sigma_detection(task: dict):
    """Pick a logsource + detection block from the evidence. Returns (logsource, detection) or (None, None)."""
    product = _product(task.get("platform", "unknown"))
    by_type: dict[str, list[str]] = {}
    for a in task.get("artifacts", []):
        by_type.setdefault(ioc_mod.classify(a), []).append(a)

    selections = [sel for sel in (_command_selection(c, product) for c in task.get("commands", [])[:3]) if sel]
    if len(selections) == 1:
        return {"category": "process_creation", "product": product}, {"selection": selections[0], "condition": "selection"}
    if selections:                                   # several commands: one selection each, any of them matches
        det = {f"selection_{i}": sel for i, sel in enumerate(selections, 1)}
        det["condition"] = "1 of selection_*"
        return {"category": "process_creation", "product": product}, det
    if by_type.get("registry"):
        keys = [re.sub(r"^(?i:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\", "", k) for k in by_type["registry"]][:3]
        return {"category": "registry_set", "product": "windows"}, {"selection": {"TargetObject|contains": keys},
                                                                    "condition": "selection"}
    files = by_type.get("filename", []) + [p.split("\\")[-1].split("/")[-1] for p in by_type.get("filepath", [])]
    if files:
        return ({"category": "file_event", "product": product},
                {"selection": {"TargetFilename|endswith": list(dict.fromkeys(files))[:5]}, "condition": "selection"})
    if by_type.get("domain"):
        return ({"category": "dns_query", "product": product},
                {"selection": {"QueryName|endswith": by_type["domain"][:5]}, "condition": "selection"})
    if by_type.get("ipv4"):
        evidence = task.get("evidence", "") + " " + task.get("action", "")
        inbound = any(re.search(r"\bfrom\s+" + re.escape(ip), evidence) for ip in by_type["ipv4"])
        field = "SourceIp" if inbound else "DestinationIp"     # "logged in from <ip>" is inbound traffic
        return ({"category": "network_connection", "product": product},
                {"selection": {field: by_type["ipv4"][:5]}, "condition": "selection"})
    return None, None


def sigma_from_task(task: dict) -> str | None:
    logsource, detection = sigma_detection(task)
    if not detection:
        return None
    title = f"{task.get('technique_name') or 'Suspicious activity'} - {task.get('source', 'report')}"[:100]
    doc = {
        "title": title,
        "id": str(uuid.uuid4()),
        "status": "experimental",
        "description": f"Template rule for: {task.get('action', '')}"[:250],
        "author": "CTI-RAG prototype (template fallback, needs review)",
        "date": dt.date.today(),
        "tags": _tags(task.get("technique_ids", []), task.get("tactics", [])),
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Legitimate administrative activity"],
        "level": "medium",
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1000)


def _yara_str(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def yara_from_iocs(iocs: dict, name: str = "CTI_Report") -> str | None:
    strings = (iocs.get("domain", [])[:10] + iocs.get("url", [])[:10] + iocs.get("filename", [])[:10])
    strings = [s for s in dict.fromkeys(strings) if 4 <= len(s) <= 200]
    hash_conds = ([f'hash.sha256(0, filesize) == "{h}"' for h in iocs.get("sha256", [])[:10]] +
                  [f'hash.md5(0, filesize) == "{h}"' for h in iocs.get("md5", [])[:10]] +
                  [f'hash.sha1(0, filesize) == "{h}"' for h in iocs.get("sha1", [])[:10]])
    if not strings and not hash_conds:
        return None
    rule_name = re.sub(r"\W+", "_", name).strip("_") or "CTI_Report"
    if rule_name[0].isdigit():
        rule_name = "R_" + rule_name
    lines = ['import "hash"', "", f"rule {rule_name}_IOCs", "{", "  meta:",
             f'    description = "IOC-based rule generated from {_yara_str(name)} (template, needs review)"',
             '    author = "CTI-RAG prototype"']
    if strings:
        lines.append("  strings:")
        lines += [f'    $s{i} = "{_yara_str(s)}" ascii wide nocase' for i, s in enumerate(strings, 1)]
    conds = (["any of ($s*)"] if strings else []) + hash_conds
    lines += ["  condition:", "    " + " or\n    ".join(conds), "}"]
    return "\n".join(lines) + "\n"
