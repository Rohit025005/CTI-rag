"""LLM-path tests without a real model.

1. A mock Ollama HTTP server (same /api/chat, /api/embed, /api/tags API) drives the REAL Ollama client code
   through the whole pipeline, including the Agent 3 <-> Agent 4 retry loop and the hallucination guard.
2. A scripted fake LLM checks the retry cap and the template fallback.
"""
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ctirag.embeddings import HashEmbedder
from ctirag.llm import BaseLLM, LLMError, OllamaLLM, extract_code, extract_json
from ctirag.orchestrator import Pipeline

MODEL = "qwen2.5:7b-instruct-q4_K_M"
GROUNDED = "a VBA macro launched PowerShell with an encoded command"
COMMAND = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def sigma_rule(tags: list[str], condition: str) -> str:
    tag_lines = "\n".join(f"  - {t}" for t in tags)
    return f"""```yaml
title: Encoded PowerShell launched by Office macro
status: experimental
description: PowerShell started with an encoded command
tags:
{tag_lines}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: {condition}
falsepositives:
  - Admin scripts
level: high
```"""


class MockOllama(BaseHTTPRequestHandler):
    requests_seen: list = []
    embedder = HashEmbedder(256)

    def log_message(self, *args):  # silence
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/tags":
            return self._send({"models": [{"name": MODEL}, {"name": "nomic-embed-text:latest"}]})
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        MockOllama.requests_seen.append((self.path, body))
        if self.path == "/api/embed":
            texts = [t.split(": ", 1)[-1] for t in body["input"]]      # strip nomic task prefixes
            return self._send({"model": body["model"], "embeddings": self.embedder.embed(texts)})
        if self.path != "/api/chat":
            return self._send({"error": "not found"}, 404)
        if body["model"] != MODEL:
            return self._send({"error": f"model '{body['model']}' not found"}, 404)
        system, user = body["messages"][0]["content"], body["messages"][1]["content"]
        if "Agent 1" in system:
            content = json.dumps({"behaviors": [
                {"action": "Macro launched encoded PowerShell", "evidence": GROUNDED, "commands": [COMMAND],
                 "artifacts": ["Invoice_Q3_2291.docm"], "platform": "windows"},
                {"action": "Escaped the hypervisor", "evidence": "the actor escaped the hypervisor with a zero-day",
                 "commands": [], "artifacts": [], "platform": "unknown"},        # not in the report -> dropped
            ]})
        elif "Agent 2" in system:
            first = re.search(r"^1\. (T\d{4}(?:\.\d{3})?) ", user, re.M).group(1)
            content = json.dumps({"matches": [{"technique_id": first, "confidence": 0.9, "reason": "fits"},
                                              {"technique_id": "T9999.999", "confidence": 0.5, "reason": "made up"}]})
        elif "Agent 3" in system and "YARA" in system:
            content = '```yara\nrule Grey_Feather_IOCs\n{\n  strings:\n    $d = "update-check.example.net" ascii wide nocase\n  condition:\n    $d\n}\n```'
        elif "Agent 3" in system:
            tags = re.findall(r"^\s+- (attack\.[\w.-]+)$", user, re.M)
            failed_before = "FAILED validation" in user
            # first attempt: condition references an undefined detection -> Agent 4 must reject it
            content = sigma_rule(tags, "selection" if failed_before else "selection and not filter")
        else:
            content = "unexpected prompt"
        self._send({"model": MODEL, "message": {"role": "assistant", "content": content}, "done": True})


@pytest.fixture()
def mock_ollama():
    MockOllama.requests_seen = []
    server = HTTPServer(("127.0.0.1", 0), MockOllama)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_full_pipeline_against_mock_ollama(cfg, sample_text, mock_ollama):
    cfg["llm"].update(provider="ollama", model=MODEL, ollama_url=mock_ollama)
    cfg["pipeline"]["chunk_chars"] = 10000
    cfg["embeddings"].update(provider="ollama", model="nomic-embed-text", ollama_url=mock_ollama)
    pipeline = Pipeline.from_config(cfg, log=lambda *_: None)
    assert OllamaLLM(MODEL, mock_ollama).health()["model_present"]

    state = pipeline.run(sample_text, "grey_feather")

    # Agent 1: grounded behaviour kept, invented one dropped; regex IOCs present
    assert [b["action"] for b in state["behaviors"]] == ["Macro launched encoded PowerShell"]
    assert state["stats"]["ungrounded_dropped"] == 1
    assert "update-check.example.net" in state["iocs"]["domain"]
    # Agent 2: hallucinated ID rejected, chosen ID came from the retrieved candidates
    b = state["behaviors"][0]
    assert b["rejected_ids"] == ["T9999.999"]
    assert b["techniques"] and b["techniques"][0]["id"] in {c["id"] for c in b["candidates"]}
    # Agents 3 + 4: first Sigma attempt invalid, error fed back, second attempt valid
    sigma = next(r for r in state["rules"] if r["rule_type"] == "sigma")
    assert sigma["status"] == "valid" and len(sigma["attempts"]) == 2
    assert not sigma["attempts"][0]["ok"] and "filter" in " ".join(sigma["attempts"][0]["errors"])
    retry_prompts = [body["messages"][1]["content"] for path, body in MockOllama.requests_seen
                     if path == "/api/chat" and "FAILED validation" in body["messages"][1]["content"]]
    assert retry_prompts and "filter" in retry_prompts[0]
    yara_rule = next(r for r in state["rules"] if r["rule_type"] == "yara")
    assert yara_rule["status"] == "valid" and len(yara_rule["attempts"]) == 1
    # request format sent to Ollama
    chat = [body for path, body in MockOllama.requests_seen if path == "/api/chat"]
    assert all(b["stream"] is False and b["model"] == MODEL for b in chat)
    assert any(b.get("format") == "json" for b in chat)
    assert state["llm_usage"]["calls"] == len(chat)


def test_missing_model_gives_pull_hint(mock_ollama):
    with pytest.raises(LLMError, match="ollama pull"):
        OllamaLLM("llama-does-not-exist", mock_ollama).chat("s", "u")


class ScriptedLLM(BaseLLM):
    provider = "scripted"

    def __init__(self, replies):
        super().__init__("scripted")
        self.replies = list(replies)

    def _complete(self, messages, json_mode):
        reply = self.replies.pop(0) if self.replies else "{}"
        if isinstance(reply, Exception):
            raise reply
        return reply


def _behaviour_json():
    return json.dumps({"behaviors": [{"action": "Macro launched encoded PowerShell", "evidence": GROUNDED,
                                      "commands": [COMMAND], "artifacts": [], "platform": "windows"}]})


def test_retry_cap_then_template_fallback(cfg, kb, sample_text):
    cfg["pipeline"].update(max_retries=2, make_yara=False, chunk_chars=10000)
    invalid = "```yaml\ntitle: broken\ndetection: [\n```"
    llm = ScriptedLLM([_behaviour_json(), json.dumps({"matches": [{"technique_id": "T1059.001", "confidence": 0.9}]}),
                       invalid, invalid])
    state = Pipeline(cfg, llm, kb, log=lambda *_: None).run(sample_text, "t")
    rule = state["rules"][0]
    assert [a["source"] for a in rule["attempts"]] == ["llm", "llm", "template"]   # N=2 LLM tries, then template
    assert rule["status"] == "fallback"
    assert state["review_queue"] and state["review_queue"][0]["task_id"] == rule["task_id"]


def test_llm_outage_flags_rule(cfg, kb, sample_text):
    cfg["pipeline"].update(make_yara=False, template_fallback=False, chunk_chars=10000)
    llm = ScriptedLLM([_behaviour_json(), json.dumps({"matches": [{"technique_id": "T1059.001"}]}),
                       LLMError("connection refused")])
    state = Pipeline(cfg, llm, kb, log=lambda *_: None).run(sample_text, "t")
    assert state["rules"][0]["status"] == "flagged"
    assert "LLM error" in state["rules"][0]["attempts"][0]["errors"][0]


def test_json_and_code_extraction():
    assert extract_json('Sure! ```json\n{"a": [1, 2,],}\n```') == {"a": [1, 2]}
    assert extract_json('text before {"x": 1} after') == {"x": 1}
    assert extract_code("Here:\n```yaml\ntitle: x\n```\nDone") == "title: x"
    assert extract_code("```yara\nrule a { condition: true }\n```", ("yara",)) == "rule a { condition: true }"


def test_baseline_flags_revoked_and_invented_ids(cfg, kb):
    from ctirag.baseline import run_baseline
    reply = "TECHNIQUES: T1059.001, T1070.001, T9999\n" + sigma_rule(["attack.execution", "attack.t1059.001"], "selection")
    out = run_baseline(ScriptedLLM([reply]), "report text", kb)
    assert out["techniques"] == ["T1059.001"]
    assert set(out["hallucinated_ids"]) == {"T1070.001", "T9999"}
    assert out["rules"][0]["ok"]


def test_evaluate_offline_smoke(cfg, kb, tmp_path):
    from ctirag.evaluate import evaluate, markdown_table
    gold = tmp_path / "gold.json"
    report = tmp_path / "r.txt"
    report.write_text("The attacker created a scheduled task with schtasks /create /tn x /tr C:\\x.exe to persist.\n",
                      encoding="utf-8")
    gold.write_text(json.dumps([{"file": "r.txt", "techniques": ["T1053.005"]}]), encoding="utf-8")
    result = evaluate(Pipeline(cfg, None, kb, log=lambda *_: None), gold, log=lambda *_: None)
    s = result["summary"]["pipeline"]
    assert s["mapping_strict"]["recall"] == 1.0
    assert "pipeline" in markdown_table(result)
