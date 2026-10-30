"""Offline end-to-end run (no LLM) and the web API."""
import time
from pathlib import Path

from fastapi.testclient import TestClient

from ctirag.orchestrator import Pipeline
from ctirag.report import save_run, zip_run
from ctirag.web.app import create_app


def test_offline_pipeline_end_to_end(cfg, kb, sample_text):
    state = Pipeline(cfg, None, kb, log=lambda *_: None).run(sample_text, "grey_feather")
    ids = set(state["stats"]["techniques"])
    assert {"T1059.001", "T1053.005", "T1547.001"} <= ids
    assert state["stats"]["rules_valid"] >= 3
    for r in state["rules"]:
        if r["status"] == "valid":
            assert r["final_rule"] and all(a["source"] == "template" for a in r["attempts"])
    out = save_run(state, cfg["output_dir"])
    assert (out / "report.json").exists() and (out / "summary.md").exists()
    assert list((out / "rules").glob("*.yml")) and list((out / "rules").glob("*.yar"))
    assert zip_run(out)[:2] == b"PK"


def test_web_api_offline_job(cfg, kb, sample_text):
    client = TestClient(create_app(cfg))
    assert client.get("/").status_code == 200
    status = client.get("/api/status").json()
    assert status["kb"]["techniques"] == len(kb.techniques)
    samples = client.get("/api/samples").json()
    assert any(s["name"] == "report_grey_feather.txt" for s in samples)
    job = client.post("/api/jobs", data={"text": sample_text, "offline": "true", "source": "grey feather"}).json()
    for _ in range(100):
        d = client.get(f"/api/jobs/{job['job_id']}").json()
        if d["status"] in ("done", "error"):
            break
        time.sleep(0.1)
    assert d["status"] == "done", d["error"]
    assert d["result"]["source"] == "grey-feather"
    export = client.get(f"/api/runs/{d['result']['run_id']}/export")
    assert export.status_code == 200 and export.content[:2] == b"PK"
    assert client.post("/api/jobs", data={"text": "too short"}).status_code == 400
    assert client.get("/api/samples/..%2Fconfig.yaml").status_code == 404
