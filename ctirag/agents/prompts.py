"""Prompt templates for the four agents (kept in one place so they are easy to show and tune)."""

AGENT1_SYSTEM = (
    "You are Agent 1 (IOC & Behaviour Extraction) in a cyber threat intelligence pipeline. "
    "Read the threat report text and list the concrete ADVERSARY BEHAVIOURS it describes: actions the attacker "
    "performed, such as execution, persistence, downloading tools, credential access, lateral movement, "
    "command and control, exfiltration or encryption. Rules: use only facts stated in the text; quote the "
    "evidence exactly; do NOT output MITRE ATT&CK IDs; skip background, defender actions and recommendations. "
    "Reply with JSON only."
)

AGENT1_USER = """Report text:
<<<
{chunk}
>>>

Indicators already found by regex (for reference): {iocs}

Return JSON exactly in this shape:
{{"behaviors": [{{"action": "short description of ONE adversary action (5-20 words)",
  "evidence": "exact quote from the text (max 40 words)",
  "commands": ["exact command lines quoted in the text, if any"],
  "artifacts": ["file names, paths, registry keys, domains or IPs tied to this action"],
  "platform": "windows|linux|macos|cloud|network|unknown"}}]}}
List at most {max_n} behaviours, most important first. If there are none, return {{"behaviors": []}}."""

AGENT2_SYSTEM = (
    "You are Agent 2 (ATT&CK Technique Mapping). Map ONE adversary behaviour to MITRE ATT&CK techniques. "
    "You may ONLY choose technique IDs from the numbered candidate list, which was retrieved from the official "
    "ATT&CK knowledge base. Prefer the most specific sub-technique that fits the evidence. If no candidate fits, "
    "return an empty list. Reply with JSON only."
)

AGENT2_USER = """Behaviour: {action}
Evidence: "{evidence}"
Commands: {commands}

Candidates (retrieved from ATT&CK):
{candidates}

Return JSON: {{"matches": [{{"technique_id": "T....", "confidence": 0.0, "reason": "one sentence"}}]}}
Use at most {max_m} matches, best first."""

AGENT3_SIGMA_SYSTEM = (
    "You are Agent 3 (Rule Synthesis), a detection engineer. Write ONE Sigma rule in YAML that detects the "
    "behaviour below in logs. Rules: use only values supported by the evidence, commands or indicators; pick a "
    "fitting logsource; use standard Sigma field names for that logsource; the detection needs at least one "
    "selection and a condition that references every selection; include the given ATT&CK tags in lowercase. "
    "Return only the rule inside a ```yaml code block."
)

AGENT3_SIGMA_USER = """Behaviour: {action}
Evidence: "{evidence}"
Commands: {commands}
Indicators: {artifacts}
Platform: {platform}
Mapped ATT&CK technique(s): {techniques}

Use this structure:
```yaml
title: <short title>
status: experimental
description: <one sentence>
author: CTI-RAG prototype
tags:
{tags}
logsource:
  category: <process_creation | file_event | registry_set | network_connection | dns_query>
  product: <windows | linux | macos>
detection:
  selection:
    <FieldName>|<modifier>: <value or list of values>
  condition: selection
falsepositives:
  - <short text>
level: <low | medium | high>
```
Field names by category: process_creation: Image, CommandLine, ParentImage, OriginalFileName;
file_event: TargetFilename; registry_set: TargetObject, Details; network_connection: DestinationIp,
DestinationPort, DestinationHostname; dns_query: QueryName. Useful modifiers: contains, endswith, startswith, all."""

AGENT3_YARA_SYSTEM = (
    "You are Agent 3 (Rule Synthesis), a malware analyst. Write ONE YARA rule that detects files (malware "
    "samples, scripts or documents) containing the indicators below. Rules: valid YARA syntax; the rule name uses "
    "only letters, digits and underscores and must not start with a digit; strings use the given indicator values "
    "exactly; if you use hash functions you must put import \"hash\" on the first line and compare lowercase hex "
    "strings. Return only the rule inside a ```yara code block."
)

AGENT3_YARA_USER = """Report: {source}
Indicators:
{indicators}
Related behaviours: {behaviours}

Use this structure:
```yara
import "hash"    // only if you use hash.* functions
rule <Rule_Name>
{{
  meta:
    description = "<one sentence>"
    author = "CTI-RAG prototype"
  strings:
    $s1 = "<indicator>" ascii wide nocase
  condition:
    any of ($s*) or hash.sha256(0, filesize) == "<sha256>"
}}
```"""

RETRY_FEEDBACK = """

Your previous rule FAILED validation.
Errors:
{errors}
Previous rule:
```{lang}
{previous}
```
Fix every error and return the complete corrected rule in a ```{lang} code block."""

BASELINE_SYSTEM = "You are a cyber threat intelligence analyst and detection engineer."

BASELINE_USER = """Read this threat report.
1) List the MITRE ATT&CK technique IDs it describes.
2) Write ONE Sigma rule for the most important behaviour.

Answer in this format:
TECHNIQUES: T1234, T1234.001
```yaml
<sigma rule>
```

Report:
<<<
{report}
>>>"""
