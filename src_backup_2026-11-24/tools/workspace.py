"""Workspace / filesystem / shell tools (sandboxed to the selected folder).

Writes and shell commands require user approval. Reads outside the workspace
require per-path approval. This module keeps the original safety model intact.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_OUTPUT_CHARS = 20_000


class AgentError(Exception):
    pass


class WorkspaceTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    # ----- path resolution -------------------------------------------------
    def authorize_external_path(self, path: Path) -> bool:
        path = path.resolve()
        return bool(self.approval("external_read",
                                  f"Allow read-only access to this external folder?\n\n{path}"))

    def _resolve_path(self, path: str) -> Path:
        requested = Path(path).expanduser()
        if requested.is_absolute():
            return requested.resolve()
        return (self.root / requested).resolve()

    def resolve(self, path: str) -> Path:
        candidate = self._resolve_path(path)
        try:
            candidate.relative_to(self.root)
            return candidate
        except ValueError:
            if self.approval("external_path",
                             "Allow this filesystem operation outside the selected workspace?\n\n"
                             f"Path: {candidate}\n\nReview the destination before approving."):
                return candidate
            raise AgentError(f"External path access denied: {candidate}")

    def resolve_read_path(self, path: str) -> Path:
        candidate = self._resolve_path(path)
        try:
            candidate.relative_to(self.root)
            return candidate
        except ValueError:
            if self.authorize_external_path(candidate):
                return candidate
            raise AgentError(f"External read access denied: {candidate}")

    # ----- dispatch --------------------------------------------------------
    HANDLERS = {
        "list_files": "list_files", "read_file": "read_file", "search_files": "search_files",
        "find_folder": "find_folder", "install_dependency": "install_dependency",
        "list_drives": "list_drives", "write_file": "write_file", "append_file": "append_file",
        "delete_path": "delete_path", "run_command": "run_command", "open_browser": "open_browser",
        "git_diff": "git_diff", "git_status": "git_status", "run_tests": "run_tests",
    }

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "list_files": return self.list_files(args.get("path", "."))
            if name == "list_drives": return self.list_drives()
            if name == "read_file": return self.read_file(args["path"])
            if name == "search_files": return self.search_files(args["query"], args.get("path", "."))
            if name == "find_folder": return self.find_folder(args["name"], args.get("start_path", "."))
            if name == "install_dependency": return self.install_dependency(args["manager"], args["package"])
            if name == "write_file": return self.write_file(args["path"], args["content"])
            if name == "append_file": return self.append_file(args["path"], args["content"])
            if name == "delete_path": return self.delete_path(args["path"])
            if name == "run_command": return self.run_command(args["command"])
            if name == "open_browser": return self.open_browser(args["path"])
            if name == "git_diff": return self.git_diff()
            if name == "git_status": return self.git_status()
            if name == "run_tests": return self.run_tests(args.get("command", ""))
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001 - surface any tool error to the model
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    # ----- read tools ------------------------------------------------------
    IGNORED = {".git", ".venv", ".build-venv", "venv", "env", "node_modules",
               "__pycache__", "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

    def list_files(self, relative: str) -> str:
        base = self.resolve(relative)
        if not base.exists(): return f"Not found: {relative}"
        if not base.is_dir(): return f"Not a directory: {relative}"
        lines = []
        for p in sorted(base.rglob("*")):
            if any(part in self.IGNORED for part in p.parts): continue
            try:
                rel = p.relative_to(self.root).as_posix()
            except ValueError:
                continue
            lines.append(("DIR  " if p.is_dir() else "FILE ") + rel)
            if len(lines) >= 500: break
        return "\n".join(lines) or "(empty directory)"

    def read_file(self, relative: str) -> str:
        p = self.resolve_read_path(relative)
        if not p.is_file(): return f"Not a file: {relative}"
        if p.stat().st_size > MAX_FILE_BYTES:
            return f"File too large to read (limit {MAX_FILE_BYTES} bytes)."
        return p.read_text(encoding="utf-8", errors="replace")

    def search_files(self, query: str, relative: str) -> str:
        base = self.resolve(relative)
        if not base.exists(): return f"Not found: {relative}"
        hits, count = [], 0
        for p in base.rglob("*"):
            if not p.is_file() or any(part in self.IGNORED for part in p.parts): continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES: continue
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if query.casefold() in line.casefold():
                    hits.append(f"{p.relative_to(self.root).as_posix()}:{lineno}: {line[:300]}")
                    count += 1
                    if count >= 100: return "\n".join(hits)
        return "\n".join(hits) or "No matches."

    def find_folder(self, name: str, start_path: str = ".") -> str:
        name = name.strip()
        if not name: return "Folder name cannot be empty."
        if any(ch in name for ch in r'\/:*?"<>|'):
            return "Use a folder name, not a path or wildcard pattern."
        base = self.resolve_read_path(start_path)
        if not base.exists(): return f"Search location does not exist: {base}"
        if not base.is_dir(): return f"Search location is not a directory: {base}"
        matches, errors = [], 0

        def on_error(_e):
            nonlocal errors
            errors += 1

        for current, dirs, _files in os.walk(base, topdown=True, onerror=on_error):
            dirs[:] = sorted(d for d in dirs if d.casefold() not in self.IGNORED)
            for dirname in dirs:
                if dirname.casefold() == name.casefold():
                    matches.append(str(Path(current) / dirname))
                    if len(matches) >= 100: break
            if len(matches) >= 100: break
        if matches:
            out = f"Found {len(matches)} matching folder(s):\n" + "\n".join(matches)
            if len(matches) >= 100: out += "\nSearch stopped at the 100-result limit."
            if errors: out += f"\nSome directories could not be searched ({errors} errors)."
            return out
        out = f"No folder named '{name}' found under {base}."
        if errors: out += f"\nSome directories could not be searched ({errors} errors)."
        return out

    def list_drives(self) -> str:
        results = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = Path(f"{letter}:/")
            if not drive.exists(): continue
            try:
                u = shutil.disk_usage(drive)
                results.append(f"Drive {letter}:\\\n  Total: {u.total/1024**3:.2f} GB\n"
                               f"  Used:  {u.used/1024**3:.2f} GB\n  Free:  {u.free/1024**3:.2f} GB")
            except OSError as exc:
                results.append(f"Drive {letter}:\\\n  Unable to inspect storage: {exc}")
        return "Available Windows drives:\n\n" + "\n\n".join(results) if results else "No accessible drives."

    # ----- write / mutate tools -------------------------------------------
    def write_file(self, relative: str, content: str) -> str:
        p = self._resolve_path(relative)
        try:
            p.relative_to(self.root)
        except ValueError:
            return (f"Refused: file writes must remain inside the selected workspace. "
                    f"Workspace: {self.root}; requested path: {p}")
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            return "Refused: generated file exceeds 1 MB limit."
        exists = p.exists()
        if not self.approval("write", f"{'Replace' if exists else 'Create'} file:\n{p}\n\n"
                             f"Size: {len(content.encode('utf-8'))} bytes\n\nApprove this file change?"):
            return "User denied file change."
        p.parent.mkdir(parents=True, exist_ok=True)
        if exists:
            backup = p.with_suffix(p.suffix + ".localqwen.bak")
            if not backup.exists() and p.is_file(): backup.write_bytes(p.read_bytes())
        p.write_text(content, encoding="utf-8", newline="\n")
        self.log(f"Wrote file: {p}")
        return f"Saved {relative} ({len(content)} characters)."

    def append_file(self, relative: str, content: str) -> str:
        p = self._resolve_path(relative)
        try:
            p.relative_to(self.root)
        except ValueError:
            return "Refused: appends must remain inside the selected workspace."
        if not self.approval("write", f"Append {len(content.encode('utf-8'))} bytes to:\n{p}\n\nApprove?"):
            return "User denied file change."
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        self.log(f"Appended to file: {p}")
        return f"Appended {len(content)} characters to {relative}."

    def delete_path(self, relative: str) -> str:
        p = self._resolve_path(relative)
        try:
            p.relative_to(self.root)
        except ValueError:
            return "Refused: deletion is restricted to the selected workspace."
        if not p.exists():
            return f"Nothing to delete: {relative}"
        kind = "directory tree" if p.is_dir() else "file"
        if not self.approval("delete", f"Permanently delete this {kind}?\n\n{p}\n\n"
                             "This cannot be undone. Approve deletion?"):
            return "User denied deletion."
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        self.log(f"Deleted: {p}")
        return f"Deleted {relative}."

    def install_dependency(self, manager: str, package: str) -> str:
        manager = (manager or "").strip().lower()
        package = (package or "").strip()
        if manager not in {"pip", "npm"}:
            return "Unsupported package manager. Allowed: pip, npm."
        if not package:
            return "Package name cannot be empty."
        pattern = r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*(?:==|>=|<=|~=|!=|>|<)\s*[A-Za-z0-9.*+_-]+)?"
        if not re.fullmatch(pattern, package):
            return "Invalid package specification. Use a package name with an optional version."
        if manager == "npm":
            if not (self.root / "package.json").is_file():
                return "No package.json found in the workspace. Select the Node.js project root first."
            command = ["npm", "install", package]
            target = f"Node.js project: {self.root}"
        else:
            command = [sys.executable, "-m", "pip", "install", package]
            target = f"Python environment: {sys.executable}"
        if not self.approval("install", f"Install dependency '{package}' using {manager}?\n\n"
                             f"Target: {target}\nCommand: {' '.join(command)}\n\n"
                             "This may download packages from the internet."):
            return "Dependency installation cancelled: approval was denied."
        try:
            result = subprocess.run(command, cwd=str(self.root), capture_output=True,
                                    text=True, timeout=300, shell=False)
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            if result.returncode == 0:
                return f"Installation succeeded.\nPackage: {package}\nOutput:\n{output[-5000:]}"
            return f"Installation failed (exit {result.returncode}).\nOutput:\n{output[-5000:]}"
        except FileNotFoundError:
            return f"Executable not found for {manager}."
        except subprocess.TimeoutExpired:
            return f"Installation timed out after 300 seconds for '{package}'."

    # Commands that start a long-running server/watcher and never exit on their
    # own. Running these through run_command (which waits for the process to
    # finish) would block forever, so we redirect the agent to start_server,
    # which launches them in the background and hands control straight back.
    _SERVER_CMD = re.compile(
        r"(?<![\w-])("
        r"uvicorn|gunicorn|hypercorn|daphne|waitress-serve|"
        r"flask\s+(?:--app\s+\S+\s+)?run|"
        r"manage\.py\s+runserver|"
        r"python\s+-m\s+http\.server|"
        r"(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:dev|start|serve)|"
        r"vite|next\s+dev|nuxt\s+dev|ng\s+serve|"
        r"rails\s+(?:server|s)\b|php\s+-S|"
        r"serve\b|http-server|live-server|nodemon|"
        r"webpack(?:\s+serve|\s+--watch)|jekyll\s+serve|hugo\s+server|"
        r"streamlit\s+run|watch\b"
        r")", re.IGNORECASE)

    def run_command(self, command: str, timeout: int = 120) -> str:
        if not command.strip(): return "Refused empty command."
        if len(command) > 4000: return "Refused: command is too long."
        if self._SERVER_CMD.search(command):
            return ("Refused: this looks like a long-running server/watch process "
                    f"('{command.strip()[:80]}'). run_command waits for the command to "
                    "finish, so a server would block the agent forever. Use start_server "
                    "instead (it launches the process in the background and returns a "
                    "server_id), then server_logs to confirm it is up and stop_server to "
                    "stop it. Example: start_server(command=\"" + command.strip() +
                    "\", port=8000).")
        if not self.approval("command", f"Run this command in the selected workspace?\n\n{command}\n\n"
                             "Commands can modify files or access the network. Inspect it before approving."):
            return "User denied command execution."
        self.log(f"Running command: {command}")
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        proc = subprocess.Popen(command, cwd=self.root, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, errors="replace",
                                env=os.environ.copy(), creationflags=creationflags)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            out = (stdout or "") + ("\n[stderr]\n" + stderr if stderr else "")
            return f"Exit code: {proc.returncode}\n{out[-MAX_OUTPUT_CHARS:] or '(no output)'}"
        except subprocess.TimeoutExpired:
            self._kill_tree(proc)
            # Drain whatever is buffered; the tree is dead so this cannot block.
            try:
                stdout, stderr = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            partial = ((stdout or "") + (stderr or ""))[-4000:]
            return (f"Command timed out after {timeout} seconds and was terminated. "
                    "If this was a server or watcher, use start_server instead so it runs "
                    f"in the background.\nPartial output:\n{partial or '(none)'}")

    @staticmethod
    def _kill_tree(proc) -> None:
        """Kill the process and all of its children (defeats orphaned grandchildren
        that keep the output pipe open and would otherwise deadlock communicate())."""
        if proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, timeout=15)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass

    def open_browser(self, relative: str) -> str:
        page = self.resolve(relative)
        if not page.is_file(): return f"Cannot open website: file not found: {relative}"
        if page.suffix.lower() not in {".html", ".htm"}:
            return f"Cannot open website: expected an .html/.htm file, got: {relative}"
        try:
            opened = webbrowser.open(page.as_uri(), new=2)
        except Exception as exc:  # noqa: BLE001
            return f"Browser launch failed for {page}: {type(exc).__name__}: {exc}"
        return (f"Browser open request sent for: {page}" if opened
                else f"The browser launcher did not confirm opening {page}.")

    def git_diff(self) -> str:
        p = subprocess.run(["git", "diff", "--", "."], cwd=self.root, capture_output=True,
                           text=True, errors="replace", timeout=20)
        if p.returncode != 0: return f"git diff failed: {p.stderr.strip()}"
        return p.stdout[-MAX_OUTPUT_CHARS:] or "No tracked changes in git diff."

    def git_status(self) -> str:
        p = subprocess.run(["git", "status", "--short", "--branch"], cwd=self.root,
                           capture_output=True, text=True, errors="replace", timeout=20)
        if p.returncode != 0: return f"git status failed: {p.stderr.strip()}"
        return p.stdout[-MAX_OUTPUT_CHARS:] or "Working tree clean."

    def run_tests(self, command: str) -> str:
        if not command.strip():
            if (self.root / "pytest.ini").exists() or (self.root / "pyproject.toml").exists() or (self.root / "tests").exists():
                command = "python -m pytest -q"
            elif (self.root / "package.json").exists():
                command = "npm test"
            elif (self.root / "Cargo.toml").exists():
                command = "cargo test"
            else:
                command = "python -m unittest discover -v"
        return self.run_command(command)


SCHEMAS = [
    {"type": "function", "function": {"name": "list_files",
        "description": "Inspect actual files/folders in the workspace. Call before claiming a file exists. Use path='.' for the root.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "read_file",
        "description": "Read a UTF-8 text file from the workspace, up to 1 MB.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "search_files",
        "description": "Search workspace text files for a literal case-insensitive string.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "path": {"type": "string"}}, "required": ["query", "path"]}}},
    {"type": "function", "function": {"name": "find_folder",
        "description": "Find folders by name. Searches the workspace by default; external paths need approval.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "start_path": {"type": "string"}}, "required": ["name"]}}},
    {"type": "function", "function": {"name": "list_drives",
        "description": "List Windows drives and their total/used/free storage. Read-only.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "write_file",
        "description": "Create or replace a UTF-8 text file in the workspace. Requires user approval.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "append_file",
        "description": "Append text to a workspace file. Requires user approval.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {"name": "delete_path",
        "description": "Delete a file or folder inside the workspace. Requires user approval and cannot be undone.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "install_dependency",
        "description": "Install a project dependency via pip or npm after user approval.",
        "parameters": {"type": "object", "properties": {"manager": {"type": "string", "enum": ["pip", "npm"]}, "package": {"type": "string"}}, "required": ["manager", "package"]}}},
    {"type": "function", "function": {"name": "run_command",
        "description": "Execute a short, finite shell command in the workspace (build, test, lint, one-off scripts) and wait for it to finish. Requires approval. Do NOT use for servers or watchers (uvicorn, gunicorn, flask run, npm run dev, python -m http.server, vite, etc.) that run until stopped - use start_server for those, or run_command will time out.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "open_browser",
        "description": "Open a local .html/.htm file from the workspace in the default browser.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "git_diff",
        "description": "Show the current git diff in the workspace.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "git_status",
        "description": "Show git status (branch + short) including untracked files.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "run_tests",
        "description": "Run the project's test command (auto-detected if omitted). Requires approval.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": []}}},
]
