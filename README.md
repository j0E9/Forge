# Local AI Code Agent (Windows)

A local-first desktop agent that **codes, runs, hosts, debugs, browses the web, inspects the host, and performs authorized security testing** inside a workspace you choose. It runs on a **local Ollama model by default** and can switch to an **external API provider** (OpenAI-compatible or Anthropic) whenever you need a bigger model — your choice, per session.

> ⚠️ **Authorized use only.** The security/recon tools are built for penetration testers and security teams working on systems they **own or have written permission to test**. They are disarmed by default. See [Security model](#security-model).

## What's new in 1.0

- **Multiple LLM providers with live switching**
  - **Local (Ollama)** — no key, private, offline inference.
  - **OpenAI-compatible** — OpenAI, OpenRouter, Groq, Together, DeepSeek, Mistral, LM Studio, vLLM, llama.cpp server… anything that speaks the Chat Completions API.
  - **Anthropic (Claude)** — the Messages API with tool use.
- **Big tool set (44 tools)** across code, run/host/debug, web, system, and security.
- **Redesigned dark UI** with a provider/model/workspace bar, a security‑authorization switch, an activity log, and a live Tools reference tab.
- **Persistent settings** (provider, endpoints, API keys, model, workspace) stored under `%APPDATA%\LocalAICodeAgent\config.json`.
- **One-command Windows build** that also produces a Setup.exe installer (auto-installs Inno Setup via winget when missing).

## Requirements

- Windows 10/11 x64
- Python 3.11 or 3.12 x64 (for development/building only — the shipped app is self-contained)
- For local inference: [Ollama](https://ollama.com) installed and a model pulled (e.g. `ollama pull qwen2.5-coder:7b`)
- For external providers: an API key from that provider
- The app uses only the Python standard library at runtime (tkinter GUI, urllib networking). No third-party runtime dependencies.

## Quick start (development)

```powershell
cd E:\CodingProjects\LocalQwenCodeAgent
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python .\src\app.py
```

1. Pick a **Provider**. For Local (Ollama) click **Refresh models**; for an external provider enter the **Endpoint**, **API key**, and **Model**.
2. Choose a **Workspace** folder (the sandbox boundary for file tools).
3. Type a task and press **Run task** (or `Ctrl+Enter`).

Switching providers is just the dropdown — the matching endpoint/key/model fields load automatically. Click **Save settings** to persist them.

## Capabilities (tools)

**Code / workspace** — `list_files`, `read_file`, `search_files`, `find_folder`, `list_drives`, `write_file`, `append_file`, `delete_path`, `install_dependency`, `run_command`, `open_browser`, `git_diff`, `git_status`, `run_tests`

**Run / host / debug** — `start_server` (launch & host an app/site in the background), `list_servers`, `server_logs` (tail output to debug), `stop_server`, `open_url`

**Web** — `web_search` (DuckDuckGo), `fetch_url` (reads a page as clean text), `extract_links`, `http_request` (call REST APIs), `download_file`

**System (read-only)** — `system_info`, `list_processes`, `network_interfaces`, `list_connections`, `get_env`, `which`

**Security (authorized testing)**
- Recon/scan (gated): `port_scan`, `banner_grab`, `http_headers`, `dns_lookup`, `reverse_dns`, `whois_lookup`, `ssl_cert_info`, `subdomain_enum`
- Tool driver (gated): `run_security_tool` — runs installed industry tools (nmap, nikto, nuclei, sqlmap, gobuster, hydra, hashcat, CrackMapExec, Impacket, sslscan, whois, dig, openssl, and many more). Any installed tool can be run (uncurated ones require an extra explicit approval).
- Local crypto utilities (no gate): `hash_text`, `identify_hash`, `encode_decode`, `generate_password`, `password_strength`

The full list with descriptions is in the app's **Tools** tab.

## Security model

- **Workspace sandbox.** File tools are bounded to the selected workspace. Path traversal outside it is blocked; reads outside require per-path approval; writes/deletes outside are always refused.
- **Approval prompts.** Every file write/append/delete, shell command, server launch, download, non-GET network call, and active security operation shows a visible approval dialog.
- **Backups.** A `.localqwen.bak` backup is kept on the first approved replacement of an existing file.
- **Security authorization switch.** Active security/recon tools are **disarmed until you tick "I am authorized to test the targets I specify"** in the app and confirm the prompt. Even when armed, each operation still asks for approval. The switch is never persisted — you re-arm it each session.
- **Untrusted content.** Repository files, web pages, and tool output are treated as data, not instructions. The agent will not exfiltrate your data to URLs found in untrusted content.
- **Not sandboxed from the OS.** Approved commands run with your Windows user's permissions. Approve only what you understand. Do not point it at untrusted projects without a real sandbox (container/VM).

### What is intentionally *not* built in

Dedicated **denial-of-service / DDoS / traffic-flooding** primitives are **not** included, by design — they exist to take systems down and are out of scope regardless of authorization. If a specific authorized engagement genuinely requires such a tool, run it through `run_command` so the destructive intent is explicit and separately approved; the agent will not generate the attack itself.

## API keys and privacy

- Keys are stored in plaintext in `%APPDATA%\LocalAICodeAgent\config.json`. Protect that file and do not commit it.
- No secrets are embedded in the shipped executable.
- Local (Ollama) inference keeps prompts on your machine. External providers send prompts and tool results to that provider — choose accordingly for sensitive work.

## Build the Windows app and Setup.exe

Run PowerShell **on Windows** from this repository:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build_windows.ps1
```

This installs PyInstaller into a build-only virtual environment, runs the tests, builds `dist\LocalAICodeAgent\LocalAICodeAgent.exe`, and then builds `installer\output\LocalAICodeAgent-Setup.exe` with Inno Setup 6 (auto-installed via winget if missing). If Inno Setup cannot be installed automatically, the app `.exe` is still produced and the script prints the manual installer step.

Inno Setup 6 (if you prefer to install it yourself): https://jrsoftware.org/isinfo.php

## Tests

```powershell
py -3.11 -m unittest discover -s tests -v
```

## Keep Ollama/model data on another drive (optional)

Install Ollama to e.g. `E:\Ollama`, set the user environment variable `OLLAMA_MODELS` to `E:\Ollama\Models` (create it first), and restart Ollama. Verify with `ollama list`. Do not move model files while Ollama is running.
