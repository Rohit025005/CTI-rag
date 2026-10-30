"""LLM clients: local Ollama (default) and an OpenAI-compatible client for the
NVIDIA NIM backup plan. `make_llm` returns None in offline mode."""
from __future__ import annotations

import json
import os
import re
import time

import requests


class LLMError(RuntimeError):
    """Raised when the model cannot be reached or does not return usable output."""


# ----------------------------------------------------------------- helpers
_FENCE_JSON = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)


def extract_json(text: str):
    """Parse a JSON object from a model reply (tolerates code fences, prose, trailing commas)."""
    text = (text or "").strip()
    m = _FENCE_JSON.search(text)
    if m:
        text = m.group(1).strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidate = text[start:end + 1]
        for attempt in (candidate, re.sub(r",\s*([}\]])", r"\1", candidate)):
            try:
                return json.loads(attempt)
            except (json.JSONDecodeError, ValueError):
                continue
    raise ValueError("no JSON object found in model reply")


def extract_code(text: str, langs: tuple[str, ...] = ("yaml", "yml", "sigma")) -> str:
    """Return the first fenced code block (preferring the given languages), else the raw text."""
    text = text or ""
    lang_alt = "|".join(re.escape(lang) for lang in langs)
    m = re.search(r"```[ \t]*(?:%s)[ \t]*\r?\n(.*?)```" % lang_alt, text, re.S | re.I)
    if not m:
        m = re.search(r"```[A-Za-z0-9_-]*[ \t]*\r?\n(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    return text.replace("```", "").strip()


# ----------------------------------------------------------------- clients
class BaseLLM:
    provider = "base"

    def __init__(self, model: str, temperature: float = 0.1, timeout: float = 300):
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.calls = 0
        self.seconds = 0.0

    def _complete(self, messages: list[dict], json_mode: bool) -> str:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.provider}:{self.model}"

    def chat(self, system: str, user: str, json_mode: bool = False) -> str:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        started = time.time()
        try:
            return self._complete(messages, json_mode)
        finally:
            self.calls += 1
            self.seconds += time.time() - started

    def chat_json(self, system: str, user: str, retries: int = 1) -> dict:
        last_error: Exception | None = None
        prompt = user
        for _ in range(retries + 1):
            reply = self.chat(system, prompt, json_mode=True)
            try:
                data = extract_json(reply)
                if isinstance(data, dict):
                    return data
                last_error = ValueError("reply was JSON but not an object")
            except ValueError as exc:
                last_error = exc
            prompt = user + "\n\nYour previous reply was not a valid JSON object. Reply with ONE valid JSON object only."
        raise LLMError(f"model did not return valid JSON: {last_error}")

    def usage(self) -> dict:
        return {"model": self.describe(), "calls": self.calls, "seconds": round(self.seconds, 1)}


class OllamaLLM(BaseLLM):
    provider = "ollama"

    def __init__(self, model: str, url: str = "http://localhost:11434", temperature: float = 0.1,
                 num_ctx: int = 8192, timeout: float = 300, keep_alive: str = "10m"):
        super().__init__(model, temperature, timeout)
        self.url = url.rstrip("/")
        self.num_ctx = num_ctx
        self.keep_alive = keep_alive
        self.session = requests.Session()

    def _complete(self, messages, json_mode):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            resp = self.session.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            raise LLMError(f"cannot reach Ollama at {self.url} ({exc}). Is the Ollama app / `ollama serve` running?") from exc
        if resp.status_code == 404:
            raise LLMError(f"model '{self.model}' is not available in Ollama. Run: ollama pull {self.model}")
        if resp.status_code >= 400:
            raise LLMError(f"Ollama error {resp.status_code}: {resp.text[:300]}")
        return (resp.json().get("message") or {}).get("content", "")

    def health(self) -> dict:
        try:
            resp = self.session.get(f"{self.url}/api/tags", timeout=5)
            resp.raise_for_status()
            names = [m.get("name", "") for m in resp.json().get("models", [])]
        except Exception as exc:  # noqa: BLE001 - report any failure to the user
            return {"reachable": False, "error": str(exc), "models": []}
        wanted = self.model if ":" in self.model else self.model + ":latest"
        return {"reachable": True, "models": names, "model_present": wanted in names or self.model in names}


class OpenAICompatLLM(BaseLLM):
    """NVIDIA NIM (or any OpenAI-compatible endpoint). Backup plan only: report text leaves the machine."""
    provider = "nim"

    def __init__(self, model: str, base_url: str, api_key: str, temperature: float = 0.1,
                 timeout: float = 120, max_tokens: int = 1500):
        super().__init__(model, temperature, timeout)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.session = requests.Session()

    def _complete(self, messages, json_mode):
        payload = {"model": self.model, "messages": messages, "temperature": self.temperature,
                   "max_tokens": self.max_tokens, "stream": False}
        try:
            resp = self.session.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout,
                                     headers={"Authorization": f"Bearer {self.api_key}"})
        except requests.RequestException as exc:
            raise LLMError(f"cannot reach {self.base_url} ({exc})") from exc
        if resp.status_code >= 400:
            raise LLMError(f"NIM error {resp.status_code}: {resp.text[:300]}")
        return resp.json()["choices"][0]["message"]["content"]

    def health(self) -> dict:
        return {"reachable": True, "models": [self.model], "model_present": True, "note": "not checked (hosted)"}


def make_llm(cfg: dict, use_alt_model: bool = False) -> BaseLLM | None:
    llm_cfg = cfg["llm"]
    provider = llm_cfg["provider"]
    if provider == "offline":
        return None
    if provider == "ollama":
        model = llm_cfg["alt_model"] if use_alt_model else llm_cfg["model"]
        return OllamaLLM(model, llm_cfg["ollama_url"], llm_cfg["temperature"], llm_cfg["num_ctx"], llm_cfg["timeout_s"])
    if provider == "nim":
        key = os.environ.get(llm_cfg["nim_api_key_env"], "")
        if not key:
            raise LLMError(f"set the {llm_cfg['nim_api_key_env']} environment variable to use NVIDIA NIM")
        return OpenAICompatLLM(llm_cfg["nim_model"], llm_cfg["nim_url"], key, llm_cfg["temperature"])
    raise LLMError(f"unknown LLM provider '{provider}' (use ollama, nim or offline)")
