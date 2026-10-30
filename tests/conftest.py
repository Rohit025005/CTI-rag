import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctirag.config import load_config  # noqa: E402


def _ap(stix_id, tid, name, tactic, desc, revoked=False):
    return {"type": "attack-pattern", "id": stix_id, "name": name, "description": desc, "revoked": revoked,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            "x_mitre_platforms": ["Windows"], "x_mitre_deprecated": False,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}


TINY_STIX = {"type": "bundle", "objects": [
    {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "test-1"},
    _ap("ap--1", "T1059", "Command and Scripting Interpreter", "execution",
        "Adversaries may abuse command and script interpreters to execute commands."),
    _ap("ap--2", "T1059.001", "PowerShell", "execution",
        "Adversaries may abuse PowerShell commands and scripts for execution, e.g. encoded commands.(Citation: X)"),
    _ap("ap--3", "T1105", "Ingress Tool Transfer", "command-and-control",
        "Adversaries may transfer tools or other files from an external system, e.g. download a payload."),
    _ap("ap--4", "T1053", "Scheduled Task/Job", "persistence", "Adversaries may abuse task scheduling."),
    _ap("ap--5", "T1053.005", "Scheduled Task", "persistence",
        "Adversaries may abuse the Windows Task Scheduler (schtasks) to run malicious code."),
    _ap("ap--6", "T1547", "Boot or Logon Autostart Execution", "persistence", "Autostart execution."),
    _ap("ap--7", "T1547.001", "Registry Run Keys / Startup Folder", "persistence",
        "Adversaries may add a program to a Run key in the registry to achieve persistence."),
    _ap("ap--8", "T1685", "Disable or Modify Tools", "defense-impairment", "Adversaries may disable tools."),
    _ap("ap--9", "T1685.005", "Clear Windows Event Logs", "defense-impairment",
        "Adversaries may clear Windows Event Logs, for example with wevtutil cl."),
    _ap("ap--10", "T1070.001", "Clear Windows Event Logs", "defense-evasion", "old", revoked=True),
    {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "ap--10", "target_ref": "ap--9"},
]}


@pytest.fixture()
def cfg(tmp_path):
    stix = tmp_path / "tiny-attack.json"
    stix.write_text(json.dumps(TINY_STIX), encoding="utf-8")
    c = load_config()
    c["kb"]["stix_path"] = str(stix)
    c["kb"]["techniques_path"] = str(tmp_path / "techniques.json")
    c["kb"]["chroma_dir"] = str(tmp_path / "chroma")
    c["output_dir"] = str(tmp_path / "outputs")
    c["llm"]["provider"] = "offline"
    c["embeddings"]["provider"] = "hash"
    c["embeddings"]["hash_dim"] = 256
    return c


@pytest.fixture()
def kb(cfg):
    from ctirag.attack_kb import AttackKB
    from ctirag.embeddings import make_embedder
    k = AttackKB(cfg, make_embedder(cfg), log=lambda *_: None)
    k.build()
    return k


@pytest.fixture()
def sample_text():
    return (ROOT / "samples" / "report_grey_feather.txt").read_text(encoding="utf-8")
