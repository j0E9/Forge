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

from tools import pyenv

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
            if name == "edit_file": return self.edit_file(args["path"], args["old_string"], args["new_string"], bool(args.get("replace_all", False)))
            if name == "delete_path": return self.delete_path(args["path"])
            if name == "run_command": return self.run_command(args["command"])
            if name == "open_browser": return self.open_browser(args["path"])
            if name == "git_diff": return self.git_diff()
            if name == "git_status": return self.git_status()
            if name == "run_tests": return self.run_tests(args.get("command", ""))
            if name == "locate": return self.locate(args["query"], args.get("scope", "workspace"), args.get("max_results", 12))
            if name == "tree": return self.tree(args.get("path", "."), args.get("depth", 2))
            if name == "file_outline": return self.file_outline(args["path"])
            if name == "replace_in_files": return self.replace_in_files(args["find"], args.get("replace", ""), args.get("path", "."), bool(args.get("regex", False)))
            if name == "move_path": return self.move_path(args["src"], args["dst"])
            if name == "copy_path": return self.copy_path(args["src"], args["dst"])
            if name == "read_lines": return self.read_lines(args["path"], args.get("start", 1), args.get("end", 0))
            if name == "grep_regex": return self.grep_regex(args["pattern"], args.get("path", "."), args.get("max_results", 100))
            if name == "recent_files": return self.recent_files(args.get("path", "."), args.get("count", 15))
            if name == "file_stats": return self.file_stats(args["path"])
            if name == "make_dir": return self.make_dir(args["path"])
            if name == "zip_path": return self.zip_path(args["src"], args.get("dst", ""))
            if name == "unzip_path": return self.unzip_path(args["src"], args.get("dst", ""))
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001 - surface any tool error to the model
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    # ----- read tools ------------------------------------------------------
    IGNORED = {".git", ".venv", ".build-venv", "venv", "env", "node_modules",
               "__pycache__", "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    _STOPWORDS = {"the", "a", "an", "my", "file", "folder", "that", "this", "for", "to", "in",
                  "of", "and", "with", "please", "find", "where", "is", "it", "on", "about",
                  "locate", "open", "named", "called", "search", "look", "me", "some"}
    _TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".md",
                 ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".c", ".cpp", ".cc",
                 ".h", ".hpp", ".java", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".ps1", ".bat",
                 ".sql", ".xml", ".csv", ".env", ".vue", ".svelte", ".kt", ".swift", ".r", ".dart",
                 ".lua", ".pl", ".gradle", ".properties", ".log"}

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

    # ----- smart location / navigation ------------------------------------
    def _scope_roots(self, scope: str):
        s = (scope or "workspace").strip().lower()
        if s in ("workspace", "", "."):
            return [self.root], "workspace"
        if s in ("home", "user", "profile"):
            return [Path.home()], "home"
        if s in ("drives", "everywhere", "all", "system", "computer"):
            roots = [Path(f"{c}:/") for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{c}:/").exists()]
            return (roots or [self.root]), "drives"
        return [self.resolve_read_path(scope)], "path"

    def locate(self, query: str, scope: str = "workspace", max_results: int = 12) -> str:
        """Find a file/folder from a vague description - matches BOTH names and file
        contents, ranks the hits, and (with approval) searches beyond the workspace.
        scope: 'workspace' (default), 'home', 'drives'/'everywhere', or a specific path."""
        import time
        q = (query or "").strip()
        if not q:
            return "Give a description or keywords to locate (e.g. 'the invoice parser')."
        words = [w for w in re.findall(r"[a-z0-9_]+", q.lower())
                 if w not in self._STOPWORDS and len(w) > 1] or [q.lower()]
        try:
            roots, kind = self._scope_roots(scope)
        except AgentError as exc:
            return str(exc)
        if kind != "workspace" and not self.approval(
                "external_read", f"Search the filesystem OUTSIDE the workspace to locate {q!r}.\n"
                f"Scope: {scope}\n\nAllow this read-only search?"):
            return "User denied the external search."
        budget = 8.0 if kind == "workspace" else 25.0
        max_files = 5000 if kind == "workspace" else 40000
        deadline = time.time() + budget
        scanned = 0
        results: dict[str, tuple] = {}
        stop = False
        for root in roots:
            if stop:
                break
            for cur, dirs, files in os.walk(root, topdown=True, onerror=lambda e: None):
                if time.time() > deadline or scanned > max_files:
                    stop = True
                    break
                dirs[:] = [d for d in dirs if d.casefold() not in self.IGNORED
                           and not (d.startswith(".") and len(d) > 1)]
                for d in dirs:
                    dl = d.lower()
                    nm = sum(1 for w in words if w in dl)
                    if nm:
                        results[str(Path(cur) / d)] = (10 * nm + (6 if nm == len(words) else 0) + 2,
                                                       "folder-name", "")
                for fn in files:
                    scanned += 1
                    if scanned > max_files or time.time() > deadline:
                        stop = True
                        break
                    full = Path(cur) / fn
                    low = fn.lower()
                    score, reasons, snippet = 0, [], ""
                    nm = sum(1 for w in words if w in low)
                    if nm:
                        score += 12 * nm + (8 if nm == len(words) else 0)
                        reasons.append("name")
                    if full.suffix.lower() in self._TEXT_EXT or low in (
                            "dockerfile", "makefile", ".env", ".gitignore"):
                        try:
                            if full.stat().st_size <= 512_000:
                                txt = full.read_text(encoding="utf-8", errors="ignore")
                                lc = txt.lower()
                                cm = sum(1 for w in words if w in lc)
                                if cm:
                                    score += 3 * cm + (4 if cm == len(words) else 0)
                                    reasons.append("content")
                                    for line in txt.splitlines():
                                        if any(w in line.lower() for w in words):
                                            snippet = line.strip()[:160]
                                            break
                        except OSError:
                            pass
                    if score > 0:
                        results[str(full)] = (score, "+".join(dict.fromkeys(reasons)), snippet)
                if stop:
                    break
        if not results:
            return f"Nothing matched {q!r} in scope '{scope}' (scanned {scanned} files)."
        n = max(1, min(int(max_results or 12), 30))
        top = sorted(results.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
        note = " — hit the time/size limit; narrow the scope" if stop and len(results) < 3 else ""
        out = [f"Best matches for {q!r} (scanned {scanned} files){note}:"]
        for path, (score, why, snip) in top:
            try:
                shown = Path(path).relative_to(self.root).as_posix()
            except ValueError:
                shown = path
            out.append(f"• {shown}  [{why}]" + (f"\n    …{snip}" if snip else ""))
        return "\n".join(out)

    def tree(self, path: str = ".", depth: int = 2) -> str:
        base = self.resolve_read_path(path)
        if not base.exists():
            return f"Not found: {path}"
        depth = max(1, min(int(depth or 2), 6))
        lines = [(base.name or str(base)) + "/"]

        def walk(d: Path, prefix: str, lvl: int):
            if lvl > depth or len(lines) > 400:
                return
            try:
                entries = sorted(d.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
            except OSError:
                return
            entries = [e for e in entries if e.name.casefold() not in self.IGNORED
                       and not e.name.startswith(".")][:200]
            for i, e in enumerate(entries):
                last = i == len(entries) - 1
                lines.append(f"{prefix}{'└─ ' if last else '├─ '}{e.name}{'/' if e.is_dir() else ''}")
                if e.is_dir():
                    walk(e, prefix + ("   " if last else "│  "), lvl + 1)
        walk(base, "", 1)
        if len(lines) > 400:
            lines = lines[:400] + ["… (truncated)"]
        return "\n".join(lines)

    def file_outline(self, path: str) -> str:
        p = self.resolve_read_path(path)
        if not p.is_file():
            return f"Not a file: {path}"
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return f"Could not read {path}: {exc}"
        ext = p.suffix.lower()
        out = []
        for i, line in enumerate(text.splitlines(), 1):
            s = line.rstrip()
            if ext == ".py" and re.match(r"^\s*(class|def|async def)\s+\w+", s):
                out.append(f"{i}: {s.strip()}")
            elif ext in (".js", ".ts", ".tsx", ".jsx") and re.match(
                    r"^\s*(export\s+)?(default\s+)?(async\s+)?(function|class)\s+\w+"
                    r"|^\s*(export\s+)?const\s+\w+\s*=\s*(async\s*)?\(", s):
                out.append(f"{i}: {s.strip()[:120]}")
            elif ext == ".md" and re.match(r"^#{1,6}\s", s):
                out.append(f"{i}: {s.strip()}")
            elif ext in (".c", ".cpp", ".cc", ".h", ".hpp", ".java", ".cs", ".go", ".rs") and re.match(
                    r"^\s*(public|private|protected|static|func|fn|class|struct|type|def)\b.*[\w>)]\s*[({]", s):
                out.append(f"{i}: {s.strip()[:120]}")
        if not out:
            return f"No outline symbols found in {path} (type {ext or 'unknown'})."
        if len(out) > 300:
            out = out[:300] + ["… (truncated)"]
        return f"Outline of {path}:\n" + "\n".join(out)

    def replace_in_files(self, find: str, replace: str, path: str = ".", regex: bool = False) -> str:
        if not find:
            return "ERROR: 'find' is empty."
        base = self.resolve(path)
        try:
            base.relative_to(self.root)
        except ValueError:
            return "Refused: replace_in_files only works inside the workspace."
        try:
            pat = re.compile(find if regex else re.escape(find))
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        candidates = [base] if base.is_file() else [
            p for p in base.rglob("*") if p.is_file()
            and not any(part in self.IGNORED for part in p.parts)
            and not p.name.endswith(".localqwen.bak")]
        targets = []
        for p in candidates:
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                t = p.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if pat.search(t):
                targets.append((p, t))
        if not targets:
            return f"No files under {path} contain {find!r}."
        preview = "\n".join(f"  {p.relative_to(self.root).as_posix()}" for p, _ in targets[:30])
        if not self.approval("write", f"Replace {find!r} → {replace!r} in {len(targets)} file(s)?\n\n"
                             f"{preview}\n\nBackups (.localqwen.bak) are kept. Approve?"):
            return "User denied replace_in_files."
        changed = total = 0
        for p, t in targets:
            new, n = pat.subn(replace, t)
            if n:
                p.with_name(p.name + ".localqwen.bak").write_text(t, encoding="utf-8")
                p.write_text(new, encoding="utf-8")
                changed += 1
                total += n
        return f"Replaced {total} occurrence(s) across {changed} file(s)."

    def move_path(self, src: str, dst: str) -> str:
        s, d = self.resolve(src), self.resolve(dst)
        for x in (s, d):
            try:
                x.relative_to(self.root)
            except ValueError:
                return "Refused: move/rename must stay inside the workspace."
        if not s.exists():
            return f"Not found: {src}"
        if not self.approval("write", f"Move/rename:\n{s}\n→ {d}\n\nApprove?"):
            return "User denied move."
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(s), str(d))
        return f"Moved {src} → {dst}"

    def copy_path(self, src: str, dst: str) -> str:
        s = self.resolve_read_path(src)
        d = self.resolve(dst)
        try:
            d.relative_to(self.root)
        except ValueError:
            return "Refused: copy destination must be inside the workspace."
        if not s.exists():
            return f"Not found: {src}"
        if not self.approval("write", f"Copy:\n{s}\n→ {d}\n\nApprove?"):
            return "User denied copy."
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_dir():
            shutil.copytree(s, d, dirs_exist_ok=True)
        else:
            shutil.copy2(s, d)
        return f"Copied {src} → {dst}"

    def read_lines(self, path: str, start: int = 1, end: int = 0) -> str:
        """Read only lines [start, end] of a file (1-based). Token-efficient for big files."""
        p = self.resolve_read_path(path)
        if not p.is_file():
            return f"Not a file: {path}"
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return f"Could not read {path}: {exc}"
        start = max(1, int(start or 1))
        end = int(end) if end else len(lines)
        end = min(end, len(lines))
        if start > len(lines):
            return f"{path} has only {len(lines)} lines."
        chunk = lines[start - 1:end]
        width = len(str(end))
        return "\n".join(f"{start + i:>{width}}  {ln}" for i, ln in enumerate(chunk))[:MAX_OUTPUT_CHARS]

    def grep_regex(self, pattern: str, path: str = ".", max_results: int = 100) -> str:
        """Regex search across workspace text files (search_files is literal; this takes a pattern)."""
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        base = self.resolve(path)
        if not base.exists():
            return f"Not found: {path}"
        files = [base] if base.is_file() else base.rglob("*")
        hits, count = [], 0
        for p in files:
            if not p.is_file() or any(part in self.IGNORED for part in p.parts):
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = p.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    rel = p.relative_to(self.root).as_posix() if str(p).startswith(str(self.root)) else str(p)
                    hits.append(f"{rel}:{lineno}: {line[:300]}")
                    count += 1
                    if count >= max(1, min(int(max_results or 100), 400)):
                        return "\n".join(hits)
        return "\n".join(hits) or "No matches."

    def recent_files(self, path: str = ".", count: int = 15) -> str:
        """List the most recently modified files - great for 'what did I work on last?'."""
        base = self.resolve_read_path(path)
        if not base.exists():
            return f"Not found: {path}"
        items = []
        for p in base.rglob("*"):
            if not p.is_file() or any(part in self.IGNORED for part in p.parts):
                continue
            try:
                items.append((p.stat().st_mtime, p))
            except OSError:
                continue
        items.sort(reverse=True)
        import datetime
        out = []
        for mt, p in items[:max(1, min(int(count or 15), 50))]:
            when = datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M")
            rel = p.relative_to(self.root).as_posix() if str(p).startswith(str(self.root)) else str(p)
            out.append(f"{when}  {rel}")
        return "\n".join(out) or "No files found."

    def file_stats(self, path: str) -> str:
        p = self.resolve_read_path(path)
        if not p.exists():
            return f"Not found: {path}"
        st = p.stat()
        import datetime
        when = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        if p.is_dir():
            n = sum(1 for _ in p.rglob("*"))
            return f"{path} (folder)\n  items (recursive): {n}\n  modified: {when}"
        lines = "?"
        try:
            if st.st_size <= MAX_FILE_BYTES:
                lines = len(p.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            pass
        return (f"{path}\n  size: {st.st_size:,} bytes\n  lines: {lines}\n"
                f"  type: {p.suffix or 'none'}\n  modified: {when}")

    def make_dir(self, path: str) -> str:
        d = self.resolve(path)
        try:
            d.relative_to(self.root)
        except ValueError:
            return "Refused: new folders must be inside the workspace."
        if d.exists():
            return f"Already exists: {path}"
        if not self.approval("write", f"Create folder:\n{d}\n\nApprove?"):
            return "User denied folder creation."
        d.mkdir(parents=True, exist_ok=True)
        return f"Created folder {path}"

    def zip_path(self, src: str, dst: str = "") -> str:
        s = self.resolve_read_path(src)
        if not s.exists():
            return f"Not found: {src}"
        dst = dst or (src.rstrip("/\\") + ".zip")
        d = self.resolve(dst)
        try:
            d.relative_to(self.root)
        except ValueError:
            return "Refused: the .zip must be written inside the workspace."
        if not self.approval("write", f"Create archive:\n{d}\nfrom {s}\n\nApprove?"):
            return "User denied zip."
        import zipfile
        d.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with zipfile.ZipFile(d, "w", zipfile.ZIP_DEFLATED) as z:
            if s.is_file():
                z.write(s, s.name)
                n = 1
            else:
                for p in s.rglob("*"):
                    if p.is_file() and not any(part in self.IGNORED for part in p.parts):
                        z.write(p, p.relative_to(s.parent).as_posix())
                        n += 1
        return f"Zipped {n} file(s) → {dst}"

    def unzip_path(self, src: str, dst: str = "") -> str:
        s = self.resolve_read_path(src)
        if not s.is_file():
            return f"Not found: {src}"
        d = self.resolve(dst or s.stem)
        try:
            d.relative_to(self.root)
        except ValueError:
            return "Refused: extraction target must be inside the workspace."
        if not self.approval("write", f"Extract archive:\n{s}\n→ {d}\n\nApprove?"):
            return "User denied unzip."
        import zipfile
        d.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(s) as z:
            safe = [m for m in z.namelist() if not (m.startswith("/") or ".." in Path(m).parts)]
            z.extractall(d, members=safe)
        return f"Extracted {len(safe)} item(s) → {dst or s.stem}"

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

    def edit_file(self, relative: str, old: str, new: str, replace_all: bool = False) -> str:
        """Exact search/replace inside a file - cheaper and safer than rewriting it."""
        p = self._resolve_path(relative)
        try:
            p.relative_to(self.root)
        except ValueError:
            return "Refused: edits must remain inside the selected workspace."
        if not p.is_file():
            return f"ERROR: {relative} does not exist. Use write_file to create it."
        text = p.read_text(encoding="utf-8", errors="replace")
        if not old:
            return "ERROR: old_string is empty. Copy the exact text to replace from read_file."
        if old == new:
            return ("ERROR: old_string and new_string are identical, so nothing would change. Put the NEW "
                    "code in new_string (e.g. add the missing lines).")
        count = text.count(old)
        if count == 0:
            # tolerate whitespace differences at line ends / indentation
            def norm(x):
                return "\n".join(line.rstrip() for line in x.replace("\r\n", "\n").split("\n"))

            if norm(old).strip() and norm(old).strip() in norm(text):
                text, old = norm(text), norm(old).strip()
                count = text.count(old)
        if count == 0:
            return (f"ERROR: old_string not found in {relative}. read_file it again and copy the exact "
                    "lines (including indentation).")
        if count > 1 and not replace_all:
            return (f"ERROR: old_string appears {count} times in {relative}. Include more surrounding "
                    "lines to make it unique, or set replace_all=true.")
        if not self.approval("write", f"Edit file:\n{p}\n\n--- replace ---\n{old[:800]}\n"
                             f"--- with ---\n{new[:800]}\n\nApprove?"):
            return "User denied file change."
        backup = p.with_suffix(p.suffix + ".localqwen.bak")
        if not backup.exists():
            backup.write_bytes(p.read_bytes())
        text = text.replace(old, new) if replace_all else text.replace(old, new, 1)
        p.write_text(text, encoding="utf-8", newline="\n")
        self.log(f"Edited file: {p}")
        return f"Edited {relative}: replaced {count if replace_all else 1} occurrence(s)."

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
            venv = pyenv.find_venv(self.root)
            target = f"Python virtualenv: {venv or (self.root / '.venv') } (same Python that run_command/start_server use)"
            command = ["<venv python>", "-m", "pip", "install", package]
        if not self.approval("install", f"Install dependency '{package}' using {manager}?\n\n"
                             f"Target: {target}\nCommand: {' '.join(command)}\n\n"
                             "This may download packages from the internet."):
            return "Dependency installation cancelled: approval was denied."
        note = ""
        if manager == "pip":
            venv, note = pyenv.ensure_venv(self.root)
            if venv is None:
                return f"Installation failed: {note}"
            command = [str(pyenv.venv_python(venv)), "-m", "pip", "install", package]
        try:
            result = subprocess.run(command, cwd=str(self.root), capture_output=True,
                                    text=True, timeout=300, shell=False)
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            if result.returncode == 0:
                where = (f"\nInstalled into the workspace virtualenv ({note or 'existing'}); run_command and "
                         "start_server use it automatically - just run `python file.py`.") if manager == "pip" else ""
                return f"Installation succeeded.\nPackage: {package}{where}\nOutput:\n{output[-1500:]}"
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

    # Raw `git ...` run through the shell loses our token-based auth (pushes then
    # fail with a cryptic exit 128) and our secrets-safe .gitignore / placeholder
    # guards. Redirect the agent to the dedicated connector tools instead.
    _GIT_CMD = re.compile(r"(?<![\w.-])git(?:\.exe)?\s+(-{0,2}[a-zA-Z][\w-]*)", re.IGNORECASE)
    _GIT_TOOL = {
        "init": "git_init()",
        "add": "git_commit(message=...)  (it stages everything for you)",
        "commit": "git_commit(message=...)",
        "push": "git_push()",
        "pull": "git_pull()",
        "clone": "git_clone(url=...)",
        "remote": "git_remote(action='list'|'add'|'set-url', ...)",
        "branch": "git_branch(name=...)",
        "checkout": "git_branch(name=...)",
        "switch": "git_branch(name=...)",
        "log": "git_log()",
        "status": "git_diff()",
        "diff": "git_diff()",
    }

    def run_command(self, command: str, timeout: int = 120) -> str:
        if not command.strip(): return "Refused empty command."
        if len(command) > 4000: return "Refused: command is too long."
        m = self._GIT_CMD.search(command)
        if m:
            sub = m.group(1).lower().lstrip("-")
            tool = self._GIT_TOOL.get(sub)
            lead = (f"Use {tool} instead of a raw git command. " if tool else
                    "Use the dedicated git_* tools (git_init, git_commit, git_push, git_pull, "
                    "git_remote, git_branch, git_log, git_diff) instead of raw git. ")
            return ("Refused: raw git loses this agent's GitHub token auth (so pushes fail with a "
                    f"cryptic exit 128) and its secrets-safe .gitignore. {lead}"
                    "To put a NEW project on GitHub: git_init() -> git_commit(message='Initial commit') "
                    "-> github_create_repo(name='<repo>') (needs a GitHub token in Connectors; it links "
                    "origin automatically) -> git_push().")
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
                                env=pyenv.workspace_env(self.root), creationflags=creationflags)
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
    {"type": "function", "function": {"name": "edit_file",
        "description": "Change part of an existing file: replace old_string (exact text copied from read_file) with new_string. Prefer this over write_file for edits. Requires approval.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "old_string": {"type": "string"}, "new_string": {"type": "string"}, "replace_all": {"type": "boolean"}}, "required": ["path", "old_string", "new_string"]}}},
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
    {"type": "function", "function": {"name": "locate",
        "description": "Find a file or folder from a VAGUE description when you don't know its exact name or path. Matches BOTH file names AND file contents, ranks the results, and returns the best paths with a snippet. Use this FIRST when the user refers to something without naming the exact file (e.g. 'work on the login page', 'the config for the parser'). scope: 'workspace' (default), 'home', 'drives'/'everywhere' (whole computer - needs approval), or a specific folder path.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "scope": {"type": "string"}, "max_results": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "tree",
        "description": "Show a directory tree (names only) to understand a project's layout fast. depth defaults to 2.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "depth": {"type": "integer"}}, "required": []}}},
    {"type": "function", "function": {"name": "file_outline",
        "description": "List the functions / classes / headings in a source or markdown file with line numbers, so you can navigate it without reading the whole file (token-efficient).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "replace_in_files",
        "description": "Find-and-replace a string (or regex) across every file under a workspace path at once. Keeps .localqwen.bak backups. Requires approval.",
        "parameters": {"type": "object", "properties": {"find": {"type": "string"}, "replace": {"type": "string"}, "path": {"type": "string"}, "regex": {"type": "boolean"}}, "required": ["find", "replace"]}}},
    {"type": "function", "function": {"name": "move_path",
        "description": "Move or rename a file/folder inside the workspace. Requires approval.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}}, "required": ["src", "dst"]}}},
    {"type": "function", "function": {"name": "copy_path",
        "description": "Copy a file/folder to a destination inside the workspace. Requires approval.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}}, "required": ["src", "dst"]}}},
    {"type": "function", "function": {"name": "read_lines",
        "description": "Read only a line range of a file (1-based start/end) with line numbers - use for big files instead of read_file to save tokens.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "start": {"type": "integer"}, "end": {"type": "integer"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "grep_regex",
        "description": "Search workspace text files with a REGEX pattern (search_files only does literal strings). Returns file:line: matches.",
        "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}, "max_results": {"type": "integer"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {"name": "recent_files",
        "description": "List the most recently modified files under a path (newest first) - answers 'what was worked on last?'.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "count": {"type": "integer"}}, "required": []}}},
    {"type": "function", "function": {"name": "file_stats",
        "description": "Show a file's size, line count, type and last-modified time (or a folder's item count).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "make_dir",
        "description": "Create a new folder inside the workspace. Requires approval.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "zip_path",
        "description": "Compress a file/folder into a .zip inside the workspace. Requires approval.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}}, "required": ["src"]}}},
    {"type": "function", "function": {"name": "unzip_path",
        "description": "Extract a .zip archive into the workspace (path traversal entries are skipped). Requires approval.",
        "parameters": {"type": "object", "properties": {"src": {"type": "string"}, "dst": {"type": "string"}}, "required": ["src"]}}},
]
