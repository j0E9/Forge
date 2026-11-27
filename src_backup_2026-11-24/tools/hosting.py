"""Hosting / background-process tools: run apps, host sites, debug long-running
processes, then stop them.

A module-level registry keeps started processes alive across agent tasks within
the running app. Starting a process requires approval (it runs a command);
reading logs and listing are free; stopping terminates the process tree.
"""
from __future__ import annotations

import itertools
import os
import platform
import subprocess
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path

_SERVERS: dict[str, dict] = {}
_LOCK = threading.Lock()
_COUNTER = itertools.count(1)
MAX_LOG_LINES = 400


def _pump(server_id: str, stream):
    buf = _SERVERS[server_id]["log"]
    for raw in iter(stream.readline, ""):
        if not raw:
            break
        buf.append(raw.rstrip("\n"))
    try:
        stream.close()
    except OSError:
        pass


class HostingTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "start_server":
                return self.start_server(args["command"], args.get("port"), args.get("cwd", "."))
            if name == "list_servers": return self.list_servers()
            if name == "server_logs": return self.server_logs(args["server_id"], int(args.get("lines", 80)))
            if name == "stop_server": return self.stop_server(args["server_id"])
            if name == "open_url": return self.open_url(args["url"])
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    def start_server(self, command: str, port=None, cwd: str = ".") -> str:
        if not command.strip():
            return "Refused empty server command."
        workdir = (self.root / cwd).resolve()
        try:
            workdir.relative_to(self.root)
        except ValueError:
            if not self.approval("external_path", f"Start a server outside the workspace?\n\n{workdir}"):
                return "Denied: working directory outside workspace."
        url = f"http://localhost:{port}" if port else ""
        if not self.approval("command", f"Start a background server/process?\n\n"
                             f"Command: {command}\nDirectory: {workdir}\n"
                             f"{('URL: ' + url) if url else ''}\n\nApprove launch?"):
            return "User denied launching the server."
        try:
            proc = subprocess.Popen(command, cwd=str(workdir), shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", env=os.environ.copy(),
                                    bufsize=1)
        except OSError as exc:
            return f"Failed to start process: {exc}"
        server_id = f"srv{next(_COUNTER)}"
        with _LOCK:
            _SERVERS[server_id] = {"proc": proc, "command": command, "port": port,
                                   "cwd": str(workdir), "log": deque(maxlen=MAX_LOG_LINES),
                                   "started": time.time()}
        threading.Thread(target=_pump, args=(server_id, proc.stdout), daemon=True).start()
        self.log(f"Started {server_id}: {command} (pid {proc.pid})")
        time.sleep(1.5)  # let it boot / fail fast
        rc = proc.poll()
        if rc is not None:
            logs = "\n".join(_SERVERS[server_id]["log"]) or "(no output)"
            return f"{server_id} exited immediately (code {rc}).\nOutput:\n{logs}"
        hint = f"\nLikely URL: {url}" if url else "\n(No port provided; check the logs for the bound address.)"
        return (f"Started {server_id} (pid {proc.pid}): {command}{hint}\n"
                f"Use server_logs('{server_id}') to watch output and stop_server('{server_id}') to stop it.")

    def list_servers(self) -> str:
        with _LOCK:
            items = list(_SERVERS.items())
        if not items:
            return "No background servers are running."
        lines = ["Background processes:"]
        for sid, info in items:
            rc = info["proc"].poll()
            state = "running" if rc is None else f"exited({rc})"
            up = int(time.time() - info["started"])
            port = f":{info['port']}" if info.get("port") else ""
            lines.append(f"  {sid}  [{state}]  {up}s  {info['command']}{('  ' + port) if port else ''}")
        return "\n".join(lines)

    def server_logs(self, server_id: str, lines: int = 80) -> str:
        with _LOCK:
            info = _SERVERS.get(server_id)
        if not info:
            return f"No such server: {server_id}"
        rc = info["proc"].poll()
        state = "running" if rc is None else f"exited with code {rc}"
        log = list(info["log"])[-max(1, lines):]
        return f"{server_id} ({state}):\n" + ("\n".join(log) or "(no output captured yet)")

    def stop_server(self, server_id: str) -> str:
        with _LOCK:
            info = _SERVERS.get(server_id)
        if not info:
            return f"No such server: {server_id}"
        proc = info["proc"]
        if proc.poll() is not None:
            return f"{server_id} already stopped (code {proc.poll()})."
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, timeout=15)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"Failed to stop {server_id}: {exc}"
        self.log(f"Stopped {server_id}")
        return f"Stopped {server_id}."

    def open_url(self, url: str) -> str:
        import re
        if not re.match(r"^https?://", url, re.I):
            url = "http://" + url
        try:
            opened = webbrowser.open(url, new=2)
        except Exception as exc:  # noqa: BLE001
            return f"Failed to open {url}: {exc}"
        return f"Opened {url} in the default browser." if opened else f"Could not confirm opening {url}."


def shutdown_all():
    with _LOCK:
        items = list(_SERVERS.values())
    for info in items:
        proc = info["proc"]
        if proc.poll() is None:
            try:
                if platform.system() == "Windows":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   capture_output=True, timeout=10)
                else:
                    proc.terminate()
            except (OSError, subprocess.TimeoutExpired):
                pass


SCHEMAS = [
    {"type": "function", "function": {"name": "start_server",
        "description": "Start a long-running server/app in the background (e.g. 'python -m http.server 8000', 'npm run dev', 'flask run'). Requires approval. Returns a server id and URL. Use to host or run a project.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"},
            "port": {"type": "integer", "description": "Port the server listens on, if known (for the URL hint)."},
            "cwd": {"type": "string", "description": "Workspace-relative working directory (default '.')."}},
            "required": ["command"]}}},
    {"type": "function", "function": {"name": "list_servers",
        "description": "List background servers/processes started by the agent and their state.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "server_logs",
        "description": "Read recent stdout/stderr output from a background server (for debugging).",
        "parameters": {"type": "object", "properties": {
            "server_id": {"type": "string"}, "lines": {"type": "integer"}}, "required": ["server_id"]}}},
    {"type": "function", "function": {"name": "stop_server",
        "description": "Stop a background server/process started by the agent (terminates its process tree).",
        "parameters": {"type": "object", "properties": {"server_id": {"type": "string"}}, "required": ["server_id"]}}},
    {"type": "function", "function": {"name": "open_url",
        "description": "Open any http(s) URL (e.g. a hosted local app) in the default browser.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
]
