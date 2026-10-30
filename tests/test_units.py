"""Unit tests: IOC extraction, ingestion, ATT&CK KB, validator, templates and lookup table."""
from ctirag import ioc, templates
from ctirag.agents.validator import RuleValidator
from ctirag.ingest import chunk_text, html_to_text
from ctirag.lookup import keyword_hits

GOOD_SIGMA = """
title: Encoded PowerShell
status: experimental
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
level: high
"""


def test_refang_and_iocs():
    text = ("Payload from hxxp://203.0.113[.]5/a/b.exe, C2 update-check[.]example[.]net, "
            "mail billing@supplier-portal[.]example. Dropped wsus_helper.exe and ran:\n"
            "schtasks /create /tn x /tr C:\\Users\\Public\\x.exe\n"
            "SHA256 " + "a" * 64 + " MD5 " + "b" * 32)
    found = ioc.extract_iocs(text)
    assert "203.0.113.5" in found["ipv4"]
    assert "http://203.0.113.5/a/b.exe" in found["url"]
    assert "update-check.example.net" in found["domain"]
    assert "wsus_helper.exe" in found["filename"]
    assert "wsus_helper.exe" not in found["domain"]          # file names are not domains
    assert found["sha256"] == ["a" * 64] and found["md5"] == ["b" * 32]
    assert any(c.startswith("schtasks /create") for c in found["command"])
    assert ioc.classify("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x") == "registry"


def test_cron_line_is_a_command():
    assert ioc.looks_like_command("*/10 * * * * /tmp/.cache/kworkerd --config /tmp/c.json")


def test_chunking_and_html():
    text = "\n\n".join(f"Paragraph {i} " + "x" * 400 for i in range(10))
    chunks = chunk_text(text, max_chars=1000, overlap=100)
    assert len(chunks) > 1 and all(len(c) <= 1300 for c in chunks)
    assert "Hello world" in html_to_text("<html><script>x()</script><p>Hello <b>world</b></p></html>")


def test_kb_parse_search_and_revoked(kb):
    assert kb.version == "test-1"
    assert kb.is_valid("T1059.001") and not kb.is_valid("T9999")
    assert kb.get("T1059.001")["full_name"] == "Command and Scripting Interpreter: PowerShell"
    assert "(Citation" not in kb.get("T1059.001")["description"]
    assert kb.replacement("T1070.001") == "T1685.005"
    assert not kb.is_valid("T1070.001")                      # revoked techniques are not valid
    top = kb.search("attacker created a scheduled task with schtasks", k=3)
    assert top[0]["id"] in {"T1053.005", "T1053"}


def test_validator_sigma_good_and_bad(kb):
    v = RuleValidator(kb)
    ok = v.validate_sigma(GOOD_SIGMA)
    assert ok.ok, ok.errors
    assert "powershell.exe" in ok.converted
    bad = v.validate_sigma(GOOD_SIGMA.replace("condition: selection", "condition: selection and filter"))
    assert not bad.ok and any("filter" in e for e in bad.errors)
    broken = v.validate_sigma("title: x\ndetection: [unclosed")
    assert not broken.ok and broken.errors[0].startswith("YAML syntax error")
    missing = v.validate_sigma("title: x\nlogsource:\n  product: windows\n")
    assert not missing.ok and any("detection" in e for e in missing.errors)


def test_validator_revoked_and_unknown_tags(kb):
    v = RuleValidator(kb)
    revoked = v.validate_sigma(GOOD_SIGMA.replace("attack.t1059.001", "attack.t1070.001"))
    assert not revoked.ok and any("revoked" in e and "t1685.005" in e for e in revoked.errors)
    unknown = v.validate_sigma(GOOD_SIGMA.replace("attack.t1059.001", "attack.t9999.999"))
    assert not unknown.ok and any("Unknown ATT&CK" in e for e in unknown.errors)


def test_validator_yara(kb):
    v = RuleValidator(kb)
    assert v.validate_yara('rule ok { strings: $a = "evil.example.net" condition: $a }').ok
    bad = v.validate_yara('rule bad { strings: $a = "x" condition: $b }')
    assert not bad.ok and "undefined string" in bad.errors[0]
    assert not v.validate_yara('rule 1bad { condition: true }').ok


def test_templates_are_valid(kb):
    v = RuleValidator(kb)
    task = {"rule_type": "sigma", "platform": "windows", "technique_ids": ["T1685.005"], "tactics": ["defense-impairment"],
            "technique_name": "Clear Windows Event Logs", "action": "cleared logs", "source": "test",
            "commands": ["vssadmin.exe delete shadows /all /quiet", "wevtutil cl Security"], "artifacts": []}
    rule = templates.sigma_from_task(task)
    res = v.validate_sigma(rule)
    assert res.ok, res.errors
    assert "1 of selection_*" in rule
    yara_rule = templates.yara_from_iocs({"domain": ["evil.example.net"], "sha256": ["a" * 64]}, "Test Report")
    assert v.validate_yara(yara_rule).ok


def test_lookup_table_resolves_revoked_ids(kb):
    hits = keyword_hits("they ran wevtutil cl Security and powershell -enc AAA", kb)
    assert "T1685.005" in hits          # table entry T1070.001 is revoked -> replaced
    assert "T1059.001" in hits
