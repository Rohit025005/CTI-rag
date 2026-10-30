"""Fixed keyword -> ATT&CK lookup table (backup plan: "fixed ATT&CK lookup table if retrieval fails").

Used two ways by Agent 2:
  * LLM mode: keyword hits are added to the retrieved candidates (hybrid retrieval); the LLM still decides.
  * Offline mode / retrieval failure: keyword hits are used directly.
IDs are resolved against the loaded ATT&CK version, so revoked IDs map to their replacements.
"""
from __future__ import annotations

import re

LOOKUP_TABLE: list[tuple[str, list[str]]] = [
    # execution
    (r"\bpowershell\b|\bpwsh\b|invoke-expression|\biex\b", ["T1059.001"]),
    (r"\s-(?:enc|encodedcommand|ec)\s|frombase64string|encoded command", ["T1027.010"]),
    (r"\bcmd(?:\.exe)?\s+/[ck]\b|windows command shell", ["T1059.003"]),
    (r"\|\s*(?:ba)?sh\b|\b(?:bash|sh)\s+-c\b|shell one-liner|unix shell", ["T1059.004"]),
    (r"\bpython3?\s+-c\b", ["T1059.006"]),
    (r"\b[wc]script(?:\.exe)?\b|\.vbs\b|vbscript", ["T1059.005"]),
    (r"\bwmic\b|windows management instrumentation", ["T1047"]),
    (r"\bmshta(?:\.exe)?\b|\.hta\b", ["T1218.005"]),
    (r"\brundll32(?:\.exe)?\b", ["T1218.011"]),
    (r"\bregsvr32(?:\.exe)?\b", ["T1218.010"]),
    (r"\bpsexec\b|service execution", ["T1569.002"]),
    (r"\bmacro\b|enabled? content|opened the (?:attachment|document)", ["T1204.002"]),
    # initial access
    (r"spear-?phishing|phishing e-?mail|malicious attachment|e-?mails? (?:that|which) carried", ["T1566.001"]),
    (r"phishing link|malicious link|link in the e-?mail", ["T1566.002"]),
    (r"exploit(?:ed|s|ing)? (?:a |an |the )?(?:remote code execution|vulnerab|flaw)|public-facing application|"
     r"internet-facing (?:web )?application", ["T1190"]),
    (r"internet-facing (?:jump server|rdp|vpn)|exposed rdp|external remote service", ["T1133"]),
    (r"valid (?:domain |local )?accounts?|stolen credentials|re-?used password|compromised credentials", ["T1078"]),
    (r"\bdomain account\b", ["T1078.002"]),
    # persistence
    (r"\bschtasks\b|scheduled task", ["T1053.005"]),
    (r"\bcron(?:tab)?\b|cron job", ["T1053.003"]),
    (r"currentversion\\run|\brun key\b|startup folder", ["T1547.001"]),
    (r"\bsc(?:\.exe)?\s+create\b|new windows service|installed a service", ["T1543.003"]),
    (r"systemd service|systemctl enable", ["T1543.002"]),
    (r"authorized_keys|ssh (?:public )?key", ["T1098.004"]),
    (r"net user .+ /add|created? (?:a )?(?:new )?local (?:admin )?account", ["T1136.001"]),
    (r"web ?shell", ["T1505.003"]),
    # credential access
    (r"\blsass\b|comsvcs|minidump|mimikatz|sekurlsa", ["T1003.001"]),
    (r"ntds\.dit", ["T1003.003"]),
    (r"brute[- ]?forc|password spray", ["T1110"]),
    (r"keylog", ["T1056.001"]),
    # discovery
    (r"\bwhoami\b", ["T1033"]),
    (r"\bsysteminfo\b", ["T1082"]),
    (r"\bnltest\b|domain trust", ["T1482"]),
    (r"port scan|network scan|\bnmap\b|masscan", ["T1046"]),
    # lateral movement
    (r"\brdp\b|remote desktop", ["T1021.001"]),
    (r"admin\$|\bc\$|smb share", ["T1021.002"]),
    # stealth / defense impairment
    (r"wevtutil(?:\.exe)?\s+cl|clear(?:ed|s|ing)? (?:the )?(?:windows )?event logs?", ["T1070.001"]),   # revoked -> resolved
    (r"history -c|bash_history|clear(?:ed)? (?:the )?(?:bash |command )?history", ["T1070.003"]),
    (r"timestomp", ["T1070.006"]),
    (r"process injection|inject(?:ed|s|ing)? (?:code )?into", ["T1055"]),
    (r"masquerad|disguised as|named (?:like|after) a legitimate", ["T1036"]),
    # command and control / exfiltration
    (r"\bdownload(?:ed|s|ing)?\b|\bwget\b|\bcurl\b|invoke-webrequest|downloadstring|downloadfile|certutil.+urlcache|"
     r"bitsadmin.+transfer", ["T1105"]),
    (r"beacon(?:ed|s|ing)? over https?|https? (?:beacon|c2)|c2 over https?|command and control over https?", ["T1071.001"]),
    (r"dns tunnel|c2 over dns|dns beacon", ["T1071.004"]),
    (r"exfiltrat", ["T1041"]),
    (r"\b7z\b|winrar|\brar a\b|archiv(?:ed|ing) (?:the )?(?:stolen |collected )?(?:data|files)", ["T1560.001"]),
    # impact
    (r"vssadmin.+delete|delete shadows|shadow cop(?:y|ies)|wbadmin delete|recoveryenabled no", ["T1490"]),
    (r"encrypt(?:ed|s|ing)? (?:user |the |all )?files|ransomware|ransom note", ["T1486"]),
    (r"\bminer\b|cryptomin|\bmonero\b|xmrig|mining pool", ["T1496.001"]),
]
_COMPILED = [(re.compile(pattern, re.I), ids) for pattern, ids in LOOKUP_TABLE]


def keyword_hits(text: str, kb) -> list[str]:
    """Technique IDs whose keywords occur in `text`, resolved to the loaded ATT&CK version."""
    hits: list[str] = []
    for regex, ids in _COMPILED:
        if regex.search(text):
            for tid in ids:
                tid = tid if kb.is_valid(tid) else (kb.replacement(tid) or "")
                if tid and kb.is_valid(tid) and tid not in hits:
                    hits.append(tid)
    return hits
