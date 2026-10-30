# CTI-RAG: Autonomous CTI Extraction & Remediation using a Multi-Agent RAG Architecture

Working prototype for the BE project (SKNCOE 2026–27, guide: Prof. V. M. Gosavi).
It reads a threat report and produces **validated Sigma and YARA rules**, grounded in **MITRE ATT&CK v20**.

```
threat report ─► Agent 1: IOCs (regex) + behaviours (LLM, evidence must be quoted from the report)
              ─► Agent 2: retrieve top-k ATT&CK entries from ChromaDB (+ keyword table) ─► LLM picks ONLY from candidates
                          └─ IDs not in the candidates / not in ATT&CK are rejected (hallucination guard)
              ─► Agent 3: write Sigma (logs) / YARA (files) ─► Agent 4: pySigma / yara-python validation
                          └─ invalid ─► errors fed back to Agent 3, at most N times ─► template fallback / manual review
              ─► only validated rules are exported (rules/, report.json, summary.md)
All LLM calls go to a local open-source model through Ollama (Qwen2.5-7B-Instruct Q4 by default).
```

## 1. Setup (Windows 11, about 15 minutes)

1. Install **Python 3.11** from python.org (tick "Add python.exe to PATH").
2. Install **Ollama for Windows** from https://ollama.com/download. It runs in the background and uses the GPU.
3. Pull the models (PowerShell):
   ```powershell
   ollama pull qwen2.5:7b-instruct-q4_K_M
   ollama pull nomic-embed-text
   ollama pull llama3.1:8b-instruct-q4_K_M    # optional: alternate model (backup plan)
   ```
4. In the project folder:
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   pip install -r requirements.txt
   python -m ctirag doctor             # checks packages, Ollama, models, knowledge base
   python -m ctirag build-kb           # embeds the 706 ATT&CK v20 techniques into ChromaDB (1-3 min)
   ```

**WSL2 instead?** Same commands inside Ubuntu (`source .venv/bin/activate`). Either install Ollama inside WSL
(`curl -fsSL https://ollama.com/install.sh | sh`) or point to the Windows one with `export OLLAMA_HOST=http://<windows-ip>:11434`.

## 2. Run it

| What | Command |
|---|---|
| Web UI (demo) | `python -m ctirag serve` then open http://127.0.0.1:8000 |
| Analyze a report (.txt/.md/.html/.pdf) | `python -m ctirag analyze samples/report_grey_feather.txt` |
| Change k and N | `python -m ctirag analyze <file> -k 5 -n 3` (or edit `config.yaml`) |
| Alternate local model | add `--alt-model` |
| No LLM / no GPU (heuristics + templates) | add `--offline` (first run: `python -m ctirag --offline build-kb`) |
| Evaluation vs plain-LLM baseline | `python -m ctirag eval` |
| Tests | `python -m pytest -q` |

Each run writes `outputs/<run-id>/` with `rules/*.yml|*.yar` (files ending in `_NEEDS_REVIEW` came from the template
fallback), `report.json` (the full shared state: IOCs, behaviours, candidates, every attempt and validator error) and
`summary.md`.

Defaults: **k = 5** ATT&CK entries per behaviour, **N = 3** attempts per rule. A typical report needs 10-25 LLM calls,
so expect about 1-3 minutes on a laptop GPU with the 7B model.

## 3. Demo for the review (about 2 minutes)

1. `python -m ctirag serve`, open the page: the header shows the model, ATT&CK version, k and N.
2. Load the **GREY FEATHER** sample, click **Analyze report**. The four agent cards light up as the log streams.
3. Behaviours table: every behaviour shows its quoted evidence and the mapped techniques (click one to open ATT&CK).
   The **Rejected IDs** tile counts IDs the LLM proposed that were not real retrieved candidates.
4. Rules: open **Validation history (Agent 4)** to show failed attempts, the errors fed back, and the fixed rule.
   Each valid Sigma rule also shows the converted Splunk query.
5. **Export** downloads all rules plus the report as a zip.

## 4. Evaluation

`python -m ctirag eval` runs both the pipeline and a **plain-LLM baseline** (one prompt, no retrieval, no validation loop)
on `samples/gold.json` and reports:

* ATT&CK mapping precision / recall / F1 (exact IDs, and parent-technique level)
* rule validity rate and first-try validity rate
* hallucinated-ID rate (IDs that are invented or revoked in ATT&CK v20)

The three samples are **synthetic** (written to exercise the pipeline). For the real evaluation, hand-label public
reports and add them to `gold.json`: `{"file": "my_report.txt", "techniques": ["T1059.001", ...]}`.
Offline-mode scores are not meaningful: that mode uses the keyword table instead of the LLM.

## 5. Where each part of the design lives

| Design element | Code |
|---|---|
| Orchestrator + shared state + retry loop (cap N) | `ctirag/orchestrator.py` |
| Agent 1 – IOC & behaviour extraction | `ctirag/agents/extractor.py`, `ctirag/ioc.py` |
| Agent 2 – ATT&CK mapping (ChromaDB retrieval) | `ctirag/agents/mapper.py`, `ctirag/attack_kb.py`, `ctirag/lookup.py` |
| Agent 3 – Sigma / YARA synthesis | `ctirag/agents/rule_writer.py`, prompts in `ctirag/agents/prompts.py` |
| Agent 4 – validation (pySigma, Splunk conversion, yara-python) | `ctirag/agents/validator.py` |
| Local LLMs (Ollama) / NVIDIA NIM backup | `ctirag/llm.py`, `ctirag/embeddings.py` |
| Backup plan: template rules, fixed lookup table, alternate model | `ctirag/templates.py`, `ctirag/lookup.py`, `--alt-model` |
| Plain-LLM baseline + metrics | `ctirag/baseline.py`, `ctirag/evaluate.py` |
| Web UI (use cases: upload, view IOCs, view techniques, review rules, export) | `ctirag/web/` |

**Backup plan switches.** For NVIDIA NIM, set `NVIDIA_API_KEY` and `llm.provider: nim` in `config.yaml`. Note that
report text is then sent to NVIDIA. If no valid rule is produced after N attempts, a template rule is used
(`template_fallback: true`). If vector retrieval fails, the fixed keyword table in `lookup.py` is used.

## 6. Notes and known limitations

* ATT&CK data: `data/attack_techniques.json` is parsed from the official MITRE STIX bundle (v20.0, 706 active
  techniques). `python -m ctirag build-kb --refresh` downloads the latest version. Revoked IDs map to their
  replacements, e.g. T1070.001 → T1685.005. v20 renamed tactics (e.g. `stealth`, `defense-impairment`).
* Validation is syntactic and structural: YAML, pySigma, the core validators, ATT&CK tags and Splunk conversion for
  Sigma, plus compilation for YARA. It does **not** prove that a rule catches the attack or avoids false positives.
  Rules must be reviewed and tested on real logs before deployment.
* Sigma field names follow Sysmon/Windows conventions; Linux rules may need a logsource pipeline in your SIEM.
* The prompts target Qwen2.5-7B. Tested here: unit tests, a mock Ollama server driving the real client end to end,
  offline runs and the web UI. Not yet measured: accuracy with the real model on real reports.
* Offline mode is for demos without a GPU: keyword heuristics, the lookup table and template rules.

ATT&CK® content © The MITRE Corporation, used under MITRE's terms of use.
