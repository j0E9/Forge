"""Persistent application settings for Local AI Code Agent.

Settings are stored as JSON under %APPDATA%\\LocalAICodeAgent\\config.json on
Windows (falling back to ~/.localaicodeagent on other platforms). API keys are
stored in plain text in this file; protect it with filesystem permissions and do
not commit it. No secrets are ever embedded in the shipped executable.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

APP_DIR_NAME = "LocalAICodeAgent"

DEFAULTS: dict = {
    # Active provider: "ollama" | "openai" | "anthropic"
    "provider": "ollama",

    # Local Ollama. Default to a capable tool-calling coder model; if it is not
    # installed, the app auto-selects the best model that is (see preferred list).
    "ollama_url": "http://localhost:11434",
    "ollama_model": "qwen2.5-coder:7b",

    # OpenAI-compatible (OpenAI, OpenRouter, Groq, Together, LM Studio, vLLM, ...)
    "openai_base_url": "https://api.openai.com/v1",
    "openai_api_key": "",
    "openai_model": "gpt-4o-mini",

    # Anthropic
    "anthropic_base_url": "https://api.anthropic.com",
    "anthropic_api_key": "",
    "anthropic_model": "claude-3-5-sonnet-latest",

    # Generation controls
    "temperature": 0.1,
    "max_tokens": 4096,
    # The agent now sends only the tools a task needs (~2-3k tokens of prompt), so
    # 12k is enough and fits small GPUs (4 GB) far better than 32k, which caused
    # heavy CPU offload, slow replies and garbled output.
    "num_ctx": 12288,
    "max_steps": 20,

    # Connectors (non-secret parts; tokens/passwords live encrypted in secrets.json)
    "github_user": "",
    "git_name": "",
    "git_email": "",
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_from": "",
    "imap_host": "",
    "imap_port": 993,

    # Workspace and UI
    "workspace": "",
    "theme": "dark",

    # Safety: the user must explicitly confirm they are authorized before the
    # active security/recon tools will run against any target. Never persisted
    # as True; it must be re-armed each session from the UI.
    "security_authorized": False,
}

# Known external model ids offered as convenient dropdown suggestions. The model
# field is free-text, so anything the provider supports can still be typed.
OPENAI_MODEL_SUGGESTIONS = [
    "gpt-4o-mini", "gpt-4o", "gpt-4.1", "gpt-4.1-mini", "o4-mini",
    "openai/gpt-4o-mini", "deepseek/deepseek-chat", "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen-2.5-coder-32b-instruct", "google/gemini-2.0-flash-001",
]
ANTHROPIC_MODEL_SUGGESTIONS = [
    "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest",
    "claude-3-7-sonnet-latest", "claude-opus-4-latest", "claude-sonnet-4-latest",
]


def config_dir() -> Path:
    base = os.environ.get("APPDATA")
    if base:
        d = Path(base) / APP_DIR_NAME
    else:
        d = Path.home() / f".{APP_DIR_NAME.lower()}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return config_dir() / "config.json"


def load() -> dict:
    cfg = dict(DEFAULTS)
    path = config_path()
    try:
        if path.is_file():
            stored = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                for key, value in stored.items():
                    if key in DEFAULTS:
                        cfg[key] = value
    except (OSError, json.JSONDecodeError):
        pass
    # security authorization is always off at startup, regardless of file state
    cfg["security_authorized"] = False
    # Migrate old/small context windows up to a safe minimum so the many tool
    # schemas do not overflow and corrupt the prompt (caused garbage output).
    try:
        n = int(cfg.get("num_ctx") or 12288)
    except (TypeError, ValueError):
        n = 12288
    if n == 32768:  # old forced default - too big for small GPUs
        n = 12288
    cfg["num_ctx"] = max(8192, n)
    try:
        mt = int(cfg.get("max_tokens") or 4096)
    except (TypeError, ValueError):
        mt = 4096
    # 1024 output tokens cut write_file calls in half, so files never got created.
    cfg["max_tokens"] = mt if mt >= 2048 else 4096
    return cfg


def save(cfg: dict) -> None:
    path = config_path()
    to_store = {k: cfg.get(k, DEFAULTS[k]) for k in DEFAULTS}
    # never persist the armed security flag
    to_store["security_authorized"] = False
    try:
        path.write_text(json.dumps(to_store, indent=2), encoding="utf-8")
    except OSError:
        pass
