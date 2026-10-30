"""FastAPI backend for the demo UI.

Use cases (from the use case diagram): upload report, view extracted IOCs, view mapped techniques,
review generated rules, export rules. Jobs run in a background thread so the page can show live agent progress.
"""
from __future__ import annotations

import json
import re
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response

from ..config import ROOT, set_offline
from ..ingest import read_document
from ..llm import LLMError, OllamaLLM
from ..orchestrator import Pipeline
from ..report import save_run, zip_run

STATIC = Path(__file__).parent / "static"
SAMPLES = ROOT / "samples"
MAX_UPLOAD = 15 * 1024 * 1024


def create_app(cfg: dict, use_alt_model: bool = False) -> FastAPI:
    app = FastAPI(title="CTI-RAG prototype", docs_url="/api/docs")
    jobs: dict[str, dict] = {}
    runs: dict[str, Path] = {}
    pipelines: dict[str, Pipeline] = {}
    run_lock = threading.Lock()

    def get_pipeline(offline: bool, log) -> Pipeline:
        key = "offline" if offline else "llm"
        if key not in pipelines:
            pipelines[key] = Pipeline.from_config(set_offline(cfg) if offline else cfg,
                                                  use_alt_model=use_alt_model, log=log)
        pipeline = pipelines[key]
        pipeline.log = log
        pipeline.kb.log = log
        return pipeline

    def worker(job_id: str, text: str, source: str, offline: bool) -> None:
        job = jobs[job_id]
        log = job["log"].append
        with run_lock:                       # one analysis at a time (the local GPU runs one model)
            job["status"] = "running"
            try:
                state = get_pipeline(offline, log).run(text, source)
                runs[state["run_id"]] = save_run(state, cfg["output_dir"])
                job["result"] = state
                job["status"] = "done"
            except LLMError as exc:
                job["status"] = "error"
                job["error"] = f"{exc} - start Ollama, or tick 'Offline mode' to run without an LLM."
            except Exception as exc:  # noqa: BLE001 - show the problem in the UI
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    def status():
        tpath = Path(cfg["kb"]["techniques_path"])
        kb_info = {"ready": False}
        if tpath.exists():
            data = json.loads(tpath.read_text(encoding="utf-8"))
            kb_info = {"ready": True, "attack_version": data["attack_version"], "techniques": len(data["techniques"])}
        llm_cfg = cfg["llm"]
        health = None
        if llm_cfg["provider"] == "ollama":
            model = llm_cfg["alt_model"] if use_alt_model else llm_cfg["model"]
            health = OllamaLLM(model, llm_cfg["ollama_url"]).health()
            health["model"] = model
        return {"provider": llm_cfg["provider"], "llm_health": health,
                "embedder": cfg["embeddings"]["model"] if cfg["embeddings"]["provider"] == "ollama" else "hash",
                "kb": kb_info, "params": {k: cfg["pipeline"][k] for k in ("top_k", "max_retries", "template_fallback")}}

    @app.get("/api/samples")
    def samples():
        out = []
        for path in sorted(SAMPLES.glob("*.txt")):
            first = path.read_text(encoding="utf-8").strip().splitlines()[0]
            out.append({"name": path.name, "title": first[:80]})
        return out

    @app.get("/api/samples/{name}")
    def sample(name: str):
        path = (SAMPLES / name).resolve()
        if path.parent != SAMPLES.resolve() or not path.exists():
            raise HTTPException(404, "sample not found")
        return {"name": name, "text": path.read_text(encoding="utf-8")}

    @app.post("/api/jobs")
    async def create_job(text: str = Form(""), offline: bool = Form(False), source: str = Form(""),
                         file: UploadFile | None = File(None)):
        source = re.sub(r"[^A-Za-z0-9_.-]+", "-", source).strip("-")[:60] or "pasted-report"
        if file is not None and file.filename:
            data = await file.read()
            if len(data) > MAX_UPLOAD:
                raise HTTPException(413, "file too large (max 15 MB)")
            try:
                text = read_document(data=data, filename=file.filename)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(400, f"could not read {file.filename}: {exc}") from exc
            source = Path(file.filename).stem
        if len(text.strip()) < 40:
            raise HTTPException(400, "report text is empty or too short")
        job_id = uuid.uuid4().hex[:12]
        jobs[job_id] = {"status": "queued", "log": [], "result": None, "error": None, "source": source}
        threading.Thread(target=worker, args=(job_id, text, source, offline), daemon=True).start()
        return {"job_id": job_id}

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str, since: int = 0):
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return {"status": job["status"], "log": job["log"][since:], "log_total": len(job["log"]),
                "error": job["error"], "result": job["result"] if job["status"] == "done" else None}

    @app.get("/api/runs/{run_id}/export")
    def export(run_id: str):
        run_dir = runs.get(run_id)
        if not run_dir or not run_dir.exists():
            raise HTTPException(404, "unknown run")
        return Response(zip_run(run_dir), media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{run_id}.zip"'})

    return app
