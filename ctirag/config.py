"""Configuration: defaults <- config.yaml <- environment variables."""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS: dict = {
    "llm": {
        "provider": "ollama",                       # ollama | nim | offline
        "model": "qwen2.5:7b-instruct-q4_K_M",      # main model
        "alt_model": "llama3.1:8b-instruct-q4_K_M",  # backup plan: alternate local model
        "ollama_url": "http://localhost:11434",
        "temperature": 0.1,
        "num_ctx": 8192,
        "timeout_s": 300,
        # Backup plan only: NVIDIA NIM (OpenAI-compatible) hosted models for the LLM calls.
        "nim_url": "https://integrate.api.nvidia.com/v1",
        "nim_model": "meta/llama-3.1-8b-instruct",
        "nim_api_key_env": "NVIDIA_API_KEY",
    },
    "embeddings": {
        "provider": "ollama",                       # ollama | hash (offline fallback)
        "model": "nomic-embed-text",
        "ollama_url": "http://localhost:11434",
        "hash_dim": 1024,
    },
    "kb": {
        "stix_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                    "enterprise-attack/enterprise-attack.json",
        "stix_path": "data/enterprise-attack.json",
        "techniques_path": "data/attack_techniques.json",
        "chroma_dir": "data/chroma",
    },
    "pipeline": {
        "top_k": 5,                  # k: ATT&CK entries retrieved per behaviour
        "max_retries": 3,            # N: generate/validate attempts per rule
        "template_fallback": True,   # backup plan: template rule after N failed attempts
        "chunk_chars": 2500,
        "max_behaviors": 12,
        "max_rules": 10,
        "max_techniques_per_behavior": 2,
        "min_retrieval_score": 0.2,  # offline mode only: accept top candidate above this score
        "keyword_lookup": True,      # hybrid retrieval: add fixed keyword-table hits as extra candidates
        "make_yara": True,
    },
    "output_dir": "outputs",
}


def _deep_merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _normalise_ollama_host(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value.replace("://0.0.0.0", "://localhost")


def _resolve(path: str) -> str:
    p = Path(path)
    return str(p if p.is_absolute() else ROOT / p)


def load_config(path: str | os.PathLike | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    cfg_path = Path(path) if path else ROOT / "config.yaml"
    if cfg_path.exists():
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = _deep_merge(cfg, yaml.safe_load(fh) or {})

    env = os.environ
    if env.get("CTIRAG_LLM_PROVIDER"):
        cfg["llm"]["provider"] = env["CTIRAG_LLM_PROVIDER"]
    if env.get("CTIRAG_MODEL"):
        cfg["llm"]["model"] = env["CTIRAG_MODEL"]
    if env.get("CTIRAG_EMBEDDER"):
        cfg["embeddings"]["provider"] = env["CTIRAG_EMBEDDER"]
    if env.get("OLLAMA_HOST"):
        host = _normalise_ollama_host(env["OLLAMA_HOST"])
        cfg["llm"]["ollama_url"] = host
        cfg["embeddings"]["ollama_url"] = host

    for key in ("stix_path", "techniques_path", "chroma_dir"):
        cfg["kb"][key] = _resolve(cfg["kb"][key])
    cfg["output_dir"] = _resolve(cfg["output_dir"])
    return cfg


def set_offline(cfg: dict) -> dict:
    """Offline mode: no LLM, hashed embeddings. Used for demos without Ollama and for tests."""
    cfg = copy.deepcopy(cfg)
    cfg["llm"]["provider"] = "offline"
    cfg["embeddings"]["provider"] = "hash"
    return cfg
