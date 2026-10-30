"""Agent 1 - IOC & behaviour extraction.

IOCs come from deterministic regexes (ioc.py). Behaviours come from the LLM, and every behaviour must be
grounded: its evidence quote has to appear in the report, otherwise it is dropped. In offline mode a
keyword heuristic picks behaviour sentences instead.
"""
from __future__ import annotations

import re

from .. import ioc as ioc_mod
from ..embeddings import tokens
from ..llm import BaseLLM, LLMError
from . import prompts

ACTION_HINTS = (
    "execut", "ran ", "run ", "launch", "download", "upload", "drop", "install", "creat", "modif", "added", "persist",
    "schedul", "registry", "inject", "encrypt", "exfiltrat", "lateral", "credential", "dump", "phish", "macro", "beacon",
    "connect", "c2", "command-and-control", "command and control", "scan", "enumerat", "disabl", "delet", "shadow",
    "compress", "archiv", "spawn", "invok", "obfuscat", "encod", "brute", "escalat", "service", "wmi", "rdp", "ssh",
    "exploit", "harvest", "keylog", "mine", "miner", "cron", "authorized_keys", "clear", "wipe", "steal", "stole",
)
SKIP_HINTS = ("recommend", "should ", "mitigat", "we advise", "defenders", "patch ", "detection opportunit", "ioc list")
SKIP_SECTION = re.compile(r"(?i)recommend|mitigat|remediat|defen[cs]e guidance|detection opportunit|"
                          r"indicators? of compromise|\biocs?\b|references|about the author")
IMPERATIVE = re.compile(r"^(?:block|patch|monitor|put|protect|keep|enable|review|alert|restrict|ensure|update|apply|"
                        r"implement|use|deploy|educate|train|consider|limit)\b", re.I)
PLATFORM_HINTS = {
    "windows": ("powershell", ".exe", "registry", "cmd", "rundll32", "schtasks", "wmic", "hklm", "hkcu", "windows",
                "lsass", "vssadmin", "rdp", ".dll", "macro"),
    "linux": ("bash", "/tmp/", "chmod", "crontab", "cron", "ssh", "linux", "/etc/", "systemctl", "authorized_keys", "curl"),
    "macos": ("macos", "launchagent", "osascript", "plist"),
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def guess_platform(text: str) -> str:
    low = text.lower()
    scores = {p: sum(h in low for h in hints) for p, hints in PLATFORM_HINTS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else "unknown"


def is_grounded(evidence: str, source: str, threshold: float = 0.6) -> bool:
    """True if the evidence quote (or most of its words) really occurs in the source text."""
    ev, src = _norm(evidence), _norm(source)
    if not ev:
        return False
    if ev in src:
        return True
    ev_tokens = tokens(ev)
    if not ev_tokens:
        return False
    src_tokens = set(tokens(src))
    return sum(t in src_tokens for t in ev_tokens) / len(ev_tokens) >= threshold


def _jaccard(a: str, b: str) -> float:
    ta, tb = set(tokens(a)), set(tokens(b))
    return len(ta & tb) / len(ta | tb) if ta and tb else 0.0


def _artifacts_in(text: str, iocs: dict) -> list[str]:
    low = text.lower()
    return [v for kind, values in iocs.items() if kind != "command" for v in values if v.lower() in low][:12]


class Extractor:
    def __init__(self, llm: BaseLLM | None, cfg: dict, log=print):
        self.llm = llm
        self.max_behaviors = cfg["pipeline"]["max_behaviors"]
        self.log = log
        self.dropped_ungrounded = 0

    def run(self, chunks: list[str], iocs: dict, full_text: str) -> list[dict]:
        if self.llm is None:
            behaviors = self._offline(full_text, iocs)
        else:
            behaviors = []
            for i, chunk in enumerate(chunks, 1):
                self.log(f"[Agent 1] reading chunk {i}/{len(chunks)}")
                behaviors.extend(self._llm_chunk(chunk, iocs))
        merged: list[dict] = []
        for b in behaviors:                                     # de-duplicate across chunks
            if not any(_jaccard(b["action"], m["action"]) >= 0.7 for m in merged):
                merged.append(b)
        merged = merged[: self.max_behaviors]
        for n, b in enumerate(merged, 1):
            b["id"] = f"B{n}"
        self.log(f"[Agent 1] {len(merged)} behaviours, {ioc_mod.count(iocs)} IOCs"
                 + (f" ({self.dropped_ungrounded} ungrounded behaviours dropped)" if self.dropped_ungrounded else ""))
        return merged

    # ----------------------------------------------------------- LLM path
    def _llm_chunk(self, chunk: str, iocs: dict) -> list[dict]:
        short = {k: v[:8] for k, v in iocs.items() if v and k != "command"}
        user = prompts.AGENT1_USER.format(chunk=chunk, iocs=short or "none", max_n=min(8, self.max_behaviors))
        try:
            data = self.llm.chat_json(prompts.AGENT1_SYSTEM, user)
        except LLMError as exc:
            self.log(f"[Agent 1] LLM error on chunk: {exc}")
            raise
        out = []
        for item in data.get("behaviors", []) or []:
            if not isinstance(item, dict):
                continue
            action = str(item.get("action", "")).strip()
            evidence = str(item.get("evidence", "")).strip()
            if not action or not is_grounded(evidence or action, chunk):
                self.dropped_ungrounded += 1
                continue
            commands = [str(c).strip() for c in (item.get("commands") or []) if str(c).strip()]
            commands = [c for c in commands if is_grounded(c, chunk, 0.6)]
            commands += [c for c in iocs.get("command", []) if c.lower() in _norm(evidence) and c not in commands]
            artifacts = [str(a).strip() for a in (item.get("artifacts") or []) if str(a).strip()]
            artifacts = [a for a in artifacts if a.lower() in chunk.lower() or ioc_mod.refang(a).lower() in ioc_mod.refang(chunk).lower()]
            platform = str(item.get("platform", "unknown")).lower()
            if platform not in {"windows", "linux", "macos", "cloud", "network", "unknown"}:
                platform = "unknown"
            if platform == "unknown":
                platform = guess_platform(" ".join([action, evidence] + commands))
            out.append({"action": action, "evidence": evidence or action, "commands": commands[:5],
                        "artifacts": artifacts[:12], "platform": platform, "source": "llm"})
        return out

    # ----------------------------------------------------------- offline path
    def _offline(self, text: str, iocs: dict) -> list[dict]:
        """Keyword heuristic: action sentences become behaviours; command-only paragraphs are attached to
        the behaviour just before them (reports usually write "... with this command:" then the command)."""
        commands_found = iocs.get("command", [])
        out: list[dict] = []
        skip_section = False
        for para in re.split(r"\n\s*\n", ioc_mod.refang(text)):
            lines = [ln.strip().lstrip("-*•$#> ").strip() for ln in para.splitlines() if ln.strip()]
            if not lines:
                continue
            if _is_heading(lines[0]) and not ioc_mod.looks_like_command(lines[0]):
                # Recommendation / IOC-list sections describe defenders or indicators, not adversary behaviour.
                skip_section = bool(SKIP_SECTION.search(lines[0]))
            if skip_section:
                continue
            cmd_lines = [ln for ln in lines if ln in commands_found or ioc_mod.looks_like_command(ln)]
            if len(cmd_lines) == len(lines):
                if out:
                    prev = out[-1]
                    prev["commands"] = list(dict.fromkeys(prev["commands"] + cmd_lines))[:5]
                    prev["artifacts"] = list(dict.fromkeys(prev["artifacts"] + _artifacts_in(para, iocs)))[:12]
                    prev["platform"] = guess_platform(prev["evidence"] + " " + " ".join(prev["commands"]))
                continue
            body = " ".join(ln for ln in lines if not _is_heading(ln))
            for raw in re.split(r"(?<=[.!?:])\s+(?=[A-Z(\"`])", body):
                s = raw.strip()
                low = s.lower()
                if not 25 <= len(s) <= 450 or any(h in low for h in SKIP_HINTS) or IMPERATIVE.match(s):
                    continue
                if not any(h in low for h in ACTION_HINTS):
                    continue
                if sum(c.isalpha() for c in s) < 0.5 * len(s):      # skip IOC lists / hash tables
                    continue
                commands = [c for c in commands_found if c.lower() in low]
                out.append({"action": s[:220], "evidence": s[:400], "commands": commands[:5],
                            "artifacts": _artifacts_in(s, iocs), "platform": guess_platform(s + " " + " ".join(commands)),
                            "source": "heuristic"})
        return out


def _is_heading(line: str) -> bool:
    return len(line) < 60 and len(line.split()) <= 7 and not line.endswith((".", ":", ";", "!", "?"))
