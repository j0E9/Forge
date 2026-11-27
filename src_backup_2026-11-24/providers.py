"""Pluggable LLM providers for Local AI Code Agent.

A provider converts a provider-neutral message history + tool schemas into a
backend API call and returns a normalized assistant message:

    {"role": "assistant",
     "content": "<text>",
     "tool_calls": [
        {"id": "<id>", "function": {"name": "<name>", "arguments": {<dict>}}}
     ]}

Neutral history message shapes understood by every provider:
    {"role": "system",    "content": str}
    {"role": "user",      "content": str}
    {"role": "assistant", "content": str, "tool_calls": [ ... ] }   # optional
    {"role": "tool",      "tool_name": str, "tool_call_id": str, "content": str}

Tool schemas use the OpenAI/Ollama function shape:
    {"type": "function", "function": {"name", "description", "parameters": {...}}}

Supported backends:
  * OllamaProvider    - local models via Ollama (default, no key required)
  * OpenAIProvider    - any OpenAI-compatible Chat Completions endpoint
                        (OpenAI, OpenRouter, Groq, Together, DeepSeek, Mistral,
                         LM Studio, vLLM, llama.cpp server, ...)
  * AnthropicProvider - Anthropic Messages API (Claude)
"""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class AgentError(Exception):
    pass


# Model-name fragments that indicate the model can accept images (vision).
_VISION_PATTERNS = (
    "llava", "vision", "-vl", "vl-", "vl:", "bakllava", "moondream", "minicpm-v",
    "gpt-4o", "4o-", "gpt-4.1", "o4-", "chatgpt-4o", "pixtral", "gemini",
    "claude-3", "claude-4", "claude-opus", "claude-sonnet", "claude-haiku",
    "internvl", "cogvlm", "phi-3-vision", "phi-3.5-vision", "phi-4-multimodal",
    "granite-vision", "mistral-small-3", "qwen2-vl", "qwen2.5-vl", "qwen-vl",
)


def model_is_vision(model: str) -> bool:
    """Best-effort guess from the model name whether it can read images."""
    m = (model or "").lower()
    return any(p in m for p in _VISION_PATTERNS)


def _http_json(url: str, payload=None, headers=None, timeout: int = 180, method=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return raw
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:4000]
        raise AgentError(f"HTTP {e.code} from {url}: {detail}") from e
    except (URLError, TimeoutError, OSError) as e:
        raise AgentError(f"Request to {url} failed: {e}") from e


class BaseProvider:
    name = "base"
    requires_key = False

    def __init__(self, config: dict):
        self.config = config
        self.temperature = float(config.get("temperature", 0.1))
        self.max_tokens = int(config.get("max_tokens", 1024))

    def models(self) -> list[str]:
        raise NotImplementedError

    def chat(self, model: str, messages: list[dict], tools: list[dict]) -> dict:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Ollama
# --------------------------------------------------------------------------- #
class OllamaProvider(BaseProvider):
    name = "ollama"
    requires_key = False

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("ollama_url", "http://localhost:11434").rstrip("/")
        self.num_ctx = int(config.get("num_ctx", 8192))

    def models(self) -> list[str]:
        raw = _http_json(self.base_url + "/api/tags",
                         headers={"Content-Type": "application/json"}, timeout=10)
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return []
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]

    def chat(self, model: str, messages: list[dict], tools: list[dict]) -> dict:
        payload = {
            "model": model,
            "messages": self._to_wire(messages),
            "tools": tools,
            "stream": True,
            "keep_alive": "10m",
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": max(512, self.max_tokens),
            },
        }
        raw = _http_json(self.base_url + "/api/chat", payload,
                         headers={"Content-Type": "application/json"}, timeout=300)
        if not raw:
            raise AgentError("Ollama returned an empty response.")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # NDJSON stream: concatenate text, keep final tool calls.
            chunks = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    chunks.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if not chunks:
                raise AgentError("Ollama returned an invalid streaming response.")
            text = "".join(c.get("message", {}).get("content", "") for c in chunks)
            tool_calls = []
            for c in chunks:
                tc = c.get("message", {}).get("tool_calls")
                if tc:
                    tool_calls = tc
            data = {"message": {"role": "assistant", "content": text,
                                "tool_calls": tool_calls}}
        return self._normalize(data.get("message", {}))

    @staticmethod
    def _to_wire(messages: list[dict]) -> list[dict]:
        # Ollama /api/chat wants images as a list of raw base64 strings on the message.
        out = []
        for m in messages:
            if m.get("role") == "user" and m.get("images"):
                wm = {"role": "user", "content": m.get("content", ""),
                      "images": [img["data"] for img in m["images"] if img.get("data")]}
                out.append(wm)
            else:
                out.append({k: v for k, v in m.items() if k != "images"})
        return out

    @staticmethod
    def _normalize(message: dict) -> dict:
        calls = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append({"id": tc.get("id", ""),
                          "function": {"name": fn.get("name", ""), "arguments": args}})
        return {"role": "assistant", "content": message.get("content", ""),
                "tool_calls": calls}


# --------------------------------------------------------------------------- #
# OpenAI-compatible Chat Completions
# --------------------------------------------------------------------------- #
class OpenAIProvider(BaseProvider):
    name = "openai"
    requires_key = True

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("openai_base_url", "https://api.openai.com/v1").rstrip("/")
        self.api_key = config.get("openai_api_key", "").strip()

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = "Bearer " + self.api_key
        return h

    def models(self) -> list[str]:
        try:
            raw = _http_json(self.base_url + "/models", headers=self._headers(), timeout=15)
            data = json.loads(raw) if raw else {}
            ids = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
            return sorted(ids)
        except AgentError:
            return []

    def chat(self, model: str, messages: list[dict], tools: list[dict]) -> dict:
        payload = {
            "model": model,
            "messages": self._to_wire(messages),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        raw = _http_json(self.base_url + "/chat/completions", payload,
                         headers=self._headers(), timeout=300)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise AgentError(f"Invalid JSON from OpenAI endpoint: {e}") from e
        choices = data.get("choices") or []
        if not choices:
            raise AgentError(f"OpenAI endpoint returned no choices: {str(data)[:500]}")
        return self._normalize(choices[0].get("message", {}))

    @staticmethod
    def _to_wire(messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role = m.get("role")
            if role == "tool":
                out.append({"role": "tool",
                            "tool_call_id": m.get("tool_call_id", m.get("tool_name", "")),
                            "content": m.get("content", "")})
            elif role == "assistant":
                entry = {"role": "assistant", "content": m.get("content") or ""}
                calls = m.get("tool_calls") or []
                if calls:
                    entry["tool_calls"] = [
                        {"id": c.get("id") or f"call_{i}", "type": "function",
                         "function": {"name": c["function"]["name"],
                                      "arguments": json.dumps(c["function"].get("arguments", {}))}}
                        for i, c in enumerate(calls)
                    ]
                out.append(entry)
            elif role == "user" and m.get("images"):
                parts = [{"type": "text", "text": m.get("content", "")}]
                for img in m["images"]:
                    media = img.get("media_type", "image/png")
                    parts.append({"type": "image_url",
                                  "image_url": {"url": f"data:{media};base64,{img['data']}"}})
                out.append({"role": "user", "content": parts})
            else:
                out.append({"role": role, "content": m.get("content", "")})
        return out

    @staticmethod
    def _normalize(message: dict) -> dict:
        calls = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args or "{}")
                except json.JSONDecodeError:
                    args = {}
            calls.append({"id": tc.get("id", ""),
                          "function": {"name": fn.get("name", ""), "arguments": args}})
        return {"role": "assistant", "content": message.get("content") or "",
                "tool_calls": calls}


# --------------------------------------------------------------------------- #
# Anthropic Messages
# --------------------------------------------------------------------------- #
class AnthropicProvider(BaseProvider):
    name = "anthropic"
    requires_key = True

    def __init__(self, config: dict):
        super().__init__(config)
        self.base_url = config.get("anthropic_base_url", "https://api.anthropic.com").rstrip("/")
        self.api_key = config.get("anthropic_api_key", "").strip()

    def _headers(self):
        return {"Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"}

    def models(self) -> list[str]:
        from config import ANTHROPIC_MODEL_SUGGESTIONS
        try:
            raw = _http_json(self.base_url + "/v1/models", headers=self._headers(), timeout=15)
            data = json.loads(raw) if raw else {}
            ids = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
            return ids or list(ANTHROPIC_MODEL_SUGGESTIONS)
        except AgentError:
            return list(ANTHROPIC_MODEL_SUGGESTIONS)

    @staticmethod
    def _to_wire_tools(tools: list[dict]) -> list[dict]:
        out = []
        for t in tools:
            fn = t.get("function", {})
            out.append({"name": fn.get("name", ""),
                        "description": fn.get("description", ""),
                        "input_schema": fn.get("parameters", {"type": "object", "properties": {}})})
        return out

    @staticmethod
    def _to_wire_messages(messages: list[dict]):
        system_text = ""
        wire: list[dict] = []
        pending_tool_results: list[dict] = []

        def flush_tool_results():
            nonlocal pending_tool_results
            if pending_tool_results:
                wire.append({"role": "user", "content": pending_tool_results})
                pending_tool_results = []

        for m in messages:
            role = m.get("role")
            if role == "system":
                system_text += (("\n" if system_text else "") + (m.get("content") or ""))
            elif role == "user":
                flush_tool_results()
                content = [{"type": "text", "text": m.get("content", "")}]
                for img in m.get("images") or []:
                    content.append({"type": "image", "source": {
                        "type": "base64", "media_type": img.get("media_type", "image/png"),
                        "data": img["data"]}})
                wire.append({"role": "user", "content": content})
            elif role == "assistant":
                flush_tool_results()
                blocks = []
                text = m.get("content") or ""
                if text:
                    blocks.append({"type": "text", "text": text})
                for i, c in enumerate(m.get("tool_calls") or []):
                    blocks.append({"type": "tool_use",
                                   "id": c.get("id") or f"call_{i}",
                                   "name": c["function"]["name"],
                                   "input": c["function"].get("arguments", {})})
                if not blocks:
                    blocks = [{"type": "text", "text": ""}]
                wire.append({"role": "assistant", "content": blocks})
            elif role == "tool":
                pending_tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id", m.get("tool_name", "")),
                    "content": m.get("content", ""),
                })
        flush_tool_results()
        return system_text, wire

    def chat(self, model: str, messages: list[dict], tools: list[dict]) -> dict:
        system_text, wire = self._to_wire_messages(messages)
        payload = {
            "model": model,
            "system": system_text,
            "messages": wire,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = self._to_wire_tools(tools)
        raw = _http_json(self.base_url + "/v1/messages", payload,
                         headers=self._headers(), timeout=300)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise AgentError(f"Invalid JSON from Anthropic endpoint: {e}") from e
        if data.get("type") == "error":
            raise AgentError(f"Anthropic error: {data.get('error')}")
        text_parts, calls = [], []
        for i, block in enumerate(data.get("content") or []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append({"id": block.get("id", f"call_{i}"),
                              "function": {"name": block.get("name", ""),
                                           "arguments": block.get("input", {})}})
        return {"role": "assistant", "content": "".join(text_parts), "tool_calls": calls}


PROVIDERS = {
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
}


def build_provider(config: dict) -> BaseProvider:
    name = config.get("provider", "ollama")
    cls = PROVIDERS.get(name, OllamaProvider)
    return cls(config)


def active_model(config: dict) -> str:
    return {
        "ollama": config.get("ollama_model", ""),
        "openai": config.get("openai_model", ""),
        "anthropic": config.get("anthropic_model", ""),
    }.get(config.get("provider", "ollama"), "")
