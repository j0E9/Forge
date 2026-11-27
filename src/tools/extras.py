"""Extra utility tools: text/file inspection, data (JSON/CSV), encoding, hashing,
dev helpers, and cross-session recall. All stdlib-only. Read/compute tools need no
approval; tools that WRITE to the workspace ask for approval first.

The agent should call these freely whenever useful - the user only states a task.
"""
from __future__ import annotations

import base64
import binascii
import csv
import difflib
import hashlib
import io
import json
import os
import re
import secrets
import textwrap
import time
import urllib.parse
import uuid
from pathlib import Path

import config as app_config

MAX_OUT = 6000


class ExtraTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    # ------------------------------------------------------------------ plumbing
    def call(self, name: str, args: dict) -> str:
        try:
            fn = getattr(self, name, None)
            if fn is None or name.startswith("_") or name == "call":
                return f"Unknown tool: {name}"
            return fn(**{k: v for k, v in args.items() if k in fn.__code__.co_varnames})
        except TypeError as exc:
            return f"ERROR: bad arguments for {name}: {exc}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    def _read_path(self, path: str) -> Path:
        p = Path(path) if os.path.isabs(str(path)) else (self.root / str(path))
        p = p.resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            raise ValueError(f"Refused: {path} is outside the workspace. Use locate to find it, "
                             "or set the workspace to its folder.")
        return p

    def _write_path(self, path: str) -> Path:
        p = self._read_path(path)
        return p

    def _text(self, path: str, limit: int = 2_000_000) -> str:
        p = self._read_path(path)
        if not p.is_file():
            raise ValueError(f"Not a file: {path}")
        if p.stat().st_size > limit:
            raise ValueError(f"File too large (> {limit // 1000} KB): {path}")
        return p.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _cap(s: str) -> str:
        return s if len(s) <= MAX_OUT else s[:MAX_OUT] + "\n… (truncated)"

    # =================================================================== text/file
    def head_file(self, path: str, lines: int = 20) -> str:
        rows = self._text(path).splitlines()
        return self._cap("\n".join(rows[:max(1, int(lines or 20))]) or "(empty file)")

    def tail_file(self, path: str, lines: int = 20) -> str:
        rows = self._text(path).splitlines()
        return self._cap("\n".join(rows[-max(1, int(lines or 20)):]) or "(empty file)")

    def line_count(self, path: str) -> str:
        return f"{len(self._text(path).splitlines())} lines in {path}"

    def word_count(self, path: str) -> str:
        return f"{len(self._text(path).split())} words in {path}"

    def char_count(self, path: str) -> str:
        return f"{len(self._text(path))} characters in {path}"

    def count_matches(self, path: str, pattern: str, regex: bool = False) -> str:
        txt = self._text(path)
        if regex:
            n = len(re.findall(pattern, txt))
        else:
            n = txt.count(pattern)
        return f"{n} match(es) of {pattern!r} in {path}"

    def find_in_file(self, path: str, text: str, max_results: int = 50) -> str:
        hits = [f"{i}: {ln.strip()[:160]}" for i, ln in enumerate(self._text(path).splitlines(), 1)
                if text.lower() in ln.lower()]
        if not hits:
            return f"{text!r} not found in {path}"
        return self._cap(f"{len(hits)} line(s) in {path}:\n" + "\n".join(hits[:max(1, int(max_results or 50))]))

    def file_digest(self, path: str, algo: str = "sha256") -> str:
        algo = algo.lower() if algo.lower() in hashlib.algorithms_available else "sha256"
        h = hashlib.new(algo)
        p = self._read_path(path)
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return f"{algo}({path}) = {h.hexdigest()}"

    def diff_files(self, path_a: str, path_b: str) -> str:
        a = self._text(path_a).splitlines()
        b = self._text(path_b).splitlines()
        d = list(difflib.unified_diff(a, b, path_a, path_b, lineterm=""))
        return self._cap("\n".join(d) or "The two files are identical.")

    def count_todos(self, path: str = ".") -> str:
        base = self._read_path(path)
        pat = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b", re.IGNORECASE)
        out, files = [], 0
        targets = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for p in targets[:4000]:
            if p.suffix.lower() not in WorkspaceText:  # type: ignore[name-defined]
                continue
            try:
                for i, ln in enumerate(p.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    if pat.search(ln):
                        rel = p.relative_to(self.root).as_posix() if p.is_relative_to(self.root) else p.name
                        out.append(f"{rel}:{i}: {ln.strip()[:120]}")
            except OSError:
                continue
            files += 1
        return self._cap(f"{len(out)} TODO/FIXME marker(s) across {files} file(s):\n" + "\n".join(out)
                         if out else "No TODO/FIXME/HACK/XXX/BUG markers found.")

    def count_loc(self, path: str = ".") -> str:
        base = self._read_path(path)
        files = [base] if base.is_file() else [p for p in base.rglob("*")
                                               if p.is_file() and p.suffix.lower() in WorkspaceText]
        total = blank = 0
        for p in files[:5000]:
            try:
                for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    total += 1
                    if not ln.strip():
                        blank += 1
            except OSError:
                continue
        return f"{len(files)} code file(s): {total} lines total, {total - blank} non-blank."

    def count_files(self, path: str = ".", ext: str = "") -> str:
        base = self._read_path(path)
        ext = ext.lower().lstrip("*")
        if ext and not ext.startswith("."):
            ext = "." + ext
        n = sum(1 for p in base.rglob("*") if p.is_file() and (not ext or p.suffix.lower() == ext))
        return f"{n} file(s){' with extension ' + ext if ext else ''} under {path}"

    def largest_files(self, path: str = ".", count: int = 10) -> str:
        base = self._read_path(path)
        items = []
        for p in base.rglob("*"):
            if p.is_file():
                try:
                    items.append((p.stat().st_size, p))
                except OSError:
                    pass
        items.sort(reverse=True)
        n = max(1, min(int(count or 10), 50))
        out = [f"{self._human(sz):>9}  {p.relative_to(self.root).as_posix() if p.is_relative_to(self.root) else p}"
               for sz, p in items[:n]]
        return self._cap("Largest files:\n" + "\n".join(out) if out else "No files found.")

    def find_by_ext(self, ext: str, path: str = ".", max_results: int = 100) -> str:
        base = self._read_path(path)
        ext = ext.lower().lstrip("*")
        if not ext.startswith("."):
            ext = "." + ext
        hits = [p.relative_to(self.root).as_posix() if p.is_relative_to(self.root) else str(p)
                for p in base.rglob("*") if p.is_file() and p.suffix.lower() == ext]
        if not hits:
            return f"No {ext} files under {path}"
        return self._cap(f"{len(hits)} {ext} file(s):\n" + "\n".join(hits[:max(1, int(max_results or 100))]))

    def find_empty(self, path: str = ".") -> str:
        base = self._read_path(path)
        empty = []
        for p in base.rglob("*"):
            try:
                if p.is_file() and p.stat().st_size == 0:
                    empty.append(p.relative_to(self.root).as_posix() if p.is_relative_to(self.root) else str(p))
            except OSError:
                pass
        return self._cap(f"{len(empty)} empty file(s):\n" + "\n".join(empty) if empty else "No empty files found.")

    def find_duplicates(self, path: str = ".") -> str:
        base = self._read_path(path)
        by_hash: dict[str, list[str]] = {}
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            try:
                if p.stat().st_size == 0 or p.stat().st_size > 20_000_000:
                    continue
                h = hashlib.md5(p.read_bytes()).hexdigest()
                by_hash.setdefault(h, []).append(
                    p.relative_to(self.root).as_posix() if p.is_relative_to(self.root) else str(p))
            except OSError:
                pass
        dups = {h: v for h, v in by_hash.items() if len(v) > 1}
        if not dups:
            return "No duplicate files found."
        out = []
        for v in dups.values():
            out.append("  = " + "\n    ".join(v))
        return self._cap(f"{len(dups)} set(s) of identical files:\n" + "\n".join(out))

    def dir_size(self, path: str = ".") -> str:
        base = self._read_path(path)
        total = sum(p.stat().st_size for p in base.rglob("*") if p.is_file())
        return f"{path} = {self._human(total)} ({total} bytes)"

    def project_stats(self, path: str = ".") -> str:
        base = self._read_path(path)
        files = dirs = total = 0
        by_ext: dict[str, int] = {}
        for p in base.rglob("*"):
            if p.is_dir():
                dirs += 1
            elif p.is_file():
                files += 1
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
                by_ext[p.suffix.lower() or "(none)"] = by_ext.get(p.suffix.lower() or "(none)", 0) + 1
        topext = sorted(by_ext.items(), key=lambda kv: kv[1], reverse=True)[:10]
        return (f"Project stats for {path}:\n  files: {files}\n  folders: {dirs}\n"
                f"  total size: {self._human(total)}\n  top types: "
                + ", ".join(f"{e}×{c}" for e, c in topext))

    def path_info(self, path: str) -> str:
        p = self._read_path(path)
        if not p.exists():
            return f"{path} does not exist."
        st = p.stat()
        kind = "folder" if p.is_dir() else "file"
        return (f"{path}: {kind}, {self._human(st.st_size)}, modified "
                f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime))}\n  abs: {p}")

    def extract_urls(self, path: str) -> str:
        urls = re.findall(r"https?://[^\s\"'<>)\]]+", self._text(path))
        uniq = list(dict.fromkeys(urls))
        return self._cap(f"{len(uniq)} URL(s):\n" + "\n".join(uniq) if uniq else "No URLs found.")

    def extract_emails(self, path: str) -> str:
        em = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", self._text(path))
        uniq = list(dict.fromkeys(em))
        return self._cap(f"{len(uniq)} email(s):\n" + "\n".join(uniq) if uniq else "No email addresses found.")

    # =================================================================== JSON / CSV
    def json_pretty(self, path: str) -> str:
        return self._cap(json.dumps(json.loads(self._text(path)), indent=2, ensure_ascii=False))

    def json_validate(self, path: str = "", text: str = "") -> str:
        raw = text if text else self._text(path)
        try:
            json.loads(raw)
            return "✓ Valid JSON."
        except json.JSONDecodeError as e:
            return f"✗ Invalid JSON: {e}"

    def json_get(self, path: str, key_path: str) -> str:
        data = json.loads(self._text(path))
        cur = data
        for part in re.split(r"[.\[\]]+", key_path):
            if part == "":
                continue
            if isinstance(cur, list):
                cur = cur[int(part)]
            else:
                cur = cur[part]
        return self._cap(json.dumps(cur, indent=2, ensure_ascii=False) if isinstance(cur, (dict, list))
                         else str(cur))

    def json_minify(self, path: str) -> str:
        return self._cap(json.dumps(json.loads(self._text(path)), separators=(",", ":"), ensure_ascii=False))

    def csv_preview(self, path: str, rows: int = 10) -> str:
        rdr = csv.reader(io.StringIO(self._text(path)))
        out = []
        for i, row in enumerate(rdr):
            if i >= max(1, int(rows or 10)) + 1:
                break
            out.append(" | ".join(c[:30] for c in row))
        return self._cap("\n".join(out) or "(empty CSV)")

    def csv_columns(self, path: str) -> str:
        rdr = csv.reader(io.StringIO(self._text(path)))
        header = next(rdr, [])
        return f"{len(header)} column(s): " + ", ".join(header)

    def csv_rowcount(self, path: str) -> str:
        n = sum(1 for _ in csv.reader(io.StringIO(self._text(path))))
        return f"{max(0, n - 1)} data row(s) (plus header) in {path}"

    def csv_to_json(self, path: str) -> str:
        rows = list(csv.DictReader(io.StringIO(self._text(path))))
        return self._cap(json.dumps(rows, indent=2, ensure_ascii=False))

    # =================================================================== encoding
    def base64_encode(self, text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode()

    def base64_decode(self, text: str) -> str:
        try:
            return base64.b64decode(text.encode(), validate=False).decode("utf-8", "replace")
        except binascii.Error as e:
            return f"Not valid base64: {e}"

    def url_encode(self, text: str) -> str:
        return urllib.parse.quote(text, safe="")

    def url_decode(self, text: str) -> str:
        return urllib.parse.unquote(text)

    def hex_encode(self, text: str) -> str:
        return text.encode("utf-8").hex()

    def hex_decode(self, text: str) -> str:
        try:
            return bytes.fromhex(text.strip()).decode("utf-8", "replace")
        except ValueError as e:
            return f"Not valid hex: {e}"

    def rot13(self, text: str) -> str:
        import codecs
        return codecs.encode(text, "rot_13")

    def uuid_new(self) -> str:
        return str(uuid.uuid4())

    def random_token(self, length: int = 16) -> str:
        return secrets.token_urlsafe(max(4, min(int(length or 16), 128)))

    def slugify(self, text: str) -> str:
        s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
        return s or "untitled"

    def reverse_text(self, text: str) -> str:
        return (text or "")[::-1]

    def timestamp(self) -> str:
        now = time.time()
        return (f"epoch: {int(now)}\nlocal: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}\n"
                f"utc:   {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))}Z")

    def wrap_text(self, text: str, width: int = 80) -> str:
        return self._cap("\n".join(textwrap.fill(line, max(10, int(width or 80)))
                         for line in (text or "").splitlines() or [""]))

    def py_syntax_check(self, path: str) -> str:
        import py_compile
        p = self._read_path(path)
        try:
            py_compile.compile(str(p), doraise=True)
            return f"✓ {path} compiles (no syntax errors)."
        except py_compile.PyCompileError as e:
            return f"✗ Syntax error in {path}:\n{e}"

    # =================================================================== cross-session recall
    def recall(self, query: str, max_results: int = 8) -> str:
        """Search PAST chat sessions (other conversations) for context related to the
        query - lets the agent 'remember' things discussed in other chats."""
        q = (query or "").strip().lower()
        if not q:
            return "Give something to recall (keywords from the earlier conversation)."
        words = [w for w in re.findall(r"[a-z0-9_]+", q) if len(w) > 2] or [q]
        try:
            conv_file = app_config.config_dir() / "conversations.json"
            convs = json.loads(conv_file.read_text(encoding="utf-8")) if conv_file.exists() else []
        except (OSError, json.JSONDecodeError):
            return "No past conversations are stored yet."
        hits = []
        for conv in convs if isinstance(convs, list) else []:
            title = conv.get("title", "untitled")
            for e in conv.get("entries", []):
                txt = e.get("text") or ""
                if not txt:
                    continue
                low = txt.lower()
                score = sum(low.count(w) for w in words)
                if score:
                    who = e.get("role", e.get("kind", "?"))
                    hits.append((score, title, who, txt.strip().replace("\n", " ")[:200]))
        if not hits:
            return f"Nothing about {query!r} found in your other chats."
        hits.sort(reverse=True)
        n = max(1, min(int(max_results or 8), 20))
        out = [f"From your other chats (most relevant first):"]
        for _s, title, who, snip in hits[:n]:
            out.append(f"• [{title}] {who}: {snip}")
        return self._cap("\n".join(out))

    # =================================================================== write tools (approval)
    def touch_file(self, path: str) -> str:
        p = self._write_path(path)
        if not self.approval("write", f"Create/touch file {path}?"):
            return "User denied."
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
        return f"Touched {path}"

    def sort_file(self, path: str, reverse: bool = False) -> str:
        txt = self._text(path)
        if not self.approval("write", f"Sort the lines of {path} in place?"):
            return "User denied."
        lines = sorted(txt.splitlines(), reverse=bool(reverse))
        self._write_path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return f"Sorted {len(lines)} lines in {path}"

    def dedupe_file(self, path: str) -> str:
        txt = self._text(path)
        if not self.approval("write", f"Remove duplicate lines from {path} in place?"):
            return "User denied."
        seen, out = set(), []
        for ln in txt.splitlines():
            if ln not in seen:
                seen.add(ln)
                out.append(ln)
        self._write_path(path).write_text("\n".join(out) + "\n", encoding="utf-8")
        return f"{path}: kept {len(out)} unique lines."

    def trim_whitespace(self, path: str) -> str:
        txt = self._text(path)
        if not self.approval("write", f"Strip trailing whitespace in {path}?"):
            return "User denied."
        out = "\n".join(ln.rstrip() for ln in txt.splitlines())
        self._write_path(path).write_text(out + "\n", encoding="utf-8")
        return f"Trimmed trailing whitespace in {path}"

    def append_line(self, path: str, line: str) -> str:
        p = self._write_path(path)
        if not self.approval("write", f"Append a line to {path}?"):
            return "User denied."
        with open(p, "a", encoding="utf-8") as f:
            f.write((line or "") + "\n")
        return f"Appended 1 line to {path}"

    def write_json(self, path: str, value: str) -> str:
        try:
            data = json.loads(value)
        except json.JSONDecodeError as e:
            return f"ERROR: `value` must be valid JSON: {e}"
        p = self._write_path(path)
        if not self.approval("write", f"Write JSON file {path}?"):
            return "User denied."
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return f"Wrote JSON to {path}"

    def set_json_key(self, path: str, key_path: str, value: str) -> str:
        data = json.loads(self._text(path))
        try:
            val = json.loads(value)
        except json.JSONDecodeError:
            val = value  # treat as a plain string
        parts = [p for p in re.split(r"[.\[\]]+", key_path) if p != ""]
        if not self.approval("write", f"Set {key_path} = {value!r} in {path}?"):
            return "User denied."
        cur = data
        for part in parts[:-1]:
            cur = cur[int(part)] if isinstance(cur, list) else cur.setdefault(part, {})
        last = parts[-1]
        if isinstance(cur, list):
            cur[int(last)] = val
        else:
            cur[last] = val
        self._write_path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return f"Set {key_path} in {path}"

    @staticmethod
    def _human(n: int) -> str:
        f = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if f < 1024 or unit == "TB":
                return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
            f /= 1024
        return f"{n} B"


# Text-file extensions that content scans consider (module-level so methods can share it).
WorkspaceText = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".md",
                 ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".c", ".cpp", ".cc",
                 ".h", ".hpp", ".java", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".ps1", ".bat",
                 ".sql", ".xml", ".csv", ".vue", ".svelte", ".kt", ".swift", ".r", ".dart",
                 ".lua", ".pl", ".gradle", ".properties", ".log"}


def _d(desc, props, req):
    return {"type": "function", "function": {"name": None, "description": desc,
            "parameters": {"type": "object", "properties": props, "required": req}}}


_P = {"path": {"type": "string"}, "text": {"type": "string"}}
_DEFS = {
    "head_file": ("Show the first N lines of a file.", {"path": _P["path"], "lines": {"type": "integer"}}, ["path"]),
    "tail_file": ("Show the last N lines of a file.", {"path": _P["path"], "lines": {"type": "integer"}}, ["path"]),
    "line_count": ("Count the lines in a file.", {"path": _P["path"]}, ["path"]),
    "word_count": ("Count the words in a file.", {"path": _P["path"]}, ["path"]),
    "char_count": ("Count the characters in a file.", {"path": _P["path"]}, ["path"]),
    "count_matches": ("Count occurrences of a literal string (or regex) in a file.",
                      {"path": _P["path"], "pattern": {"type": "string"}, "regex": {"type": "boolean"}},
                      ["path", "pattern"]),
    "find_in_file": ("List the line numbers in a file that contain some text.",
                     {"path": _P["path"], "text": _P["text"], "max_results": {"type": "integer"}},
                     ["path", "text"]),
    "file_digest": ("Compute a file's hash (sha256 by default; md5/sha1/sha512 allowed).",
                    {"path": _P["path"], "algo": {"type": "string"}}, ["path"]),
    "diff_files": ("Show a unified diff between two text files.",
                   {"path_a": {"type": "string"}, "path_b": {"type": "string"}}, ["path_a", "path_b"]),
    "count_todos": ("List TODO/FIXME/HACK/XXX/BUG markers with file and line.", {"path": _P["path"]}, []),
    "count_loc": ("Count lines of code (total and non-blank) in a file or folder.", {"path": _P["path"]}, []),
    "count_files": ("Count files under a folder, optionally filtered by extension.",
                    {"path": _P["path"], "ext": {"type": "string"}}, []),
    "largest_files": ("List the largest files under a folder.",
                      {"path": _P["path"], "count": {"type": "integer"}}, []),
    "find_by_ext": ("List files with a given extension under a folder.",
                    {"ext": {"type": "string"}, "path": _P["path"], "max_results": {"type": "integer"}}, ["ext"]),
    "find_empty": ("List empty files under a folder.", {"path": _P["path"]}, []),
    "find_duplicates": ("Find files with identical content (by hash) under a folder.", {"path": _P["path"]}, []),
    "dir_size": ("Total size of a folder.", {"path": _P["path"]}, []),
    "project_stats": ("Summary of a folder: file/folder counts, total size, top file types.",
                      {"path": _P["path"]}, []),
    "path_info": ("Whether a path exists, its type, size, modified time and absolute path.",
                  {"path": _P["path"]}, ["path"]),
    "extract_urls": ("Extract all URLs from a file.", {"path": _P["path"]}, ["path"]),
    "extract_emails": ("Extract all email addresses from a file.", {"path": _P["path"]}, ["path"]),
    "json_pretty": ("Pretty-print (reformat) a JSON file and return it.", {"path": _P["path"]}, ["path"]),
    "json_validate": ("Check whether a JSON file (or text) is valid.",
                      {"path": _P["path"], "text": _P["text"]}, []),
    "json_get": ("Get the value at a dotted key path in a JSON file (e.g. 'a.b[0].c').",
                 {"path": _P["path"], "key_path": {"type": "string"}}, ["path", "key_path"]),
    "json_minify": ("Minify a JSON file and return it.", {"path": _P["path"]}, ["path"]),
    "csv_preview": ("Show the first rows of a CSV as a table.",
                    {"path": _P["path"], "rows": {"type": "integer"}}, ["path"]),
    "csv_columns": ("List a CSV file's column headers.", {"path": _P["path"]}, ["path"]),
    "csv_rowcount": ("Count the data rows in a CSV file.", {"path": _P["path"]}, ["path"]),
    "csv_to_json": ("Convert a CSV file to JSON and return it.", {"path": _P["path"]}, ["path"]),
    "base64_encode": ("Base64-encode text.", {"text": _P["text"]}, ["text"]),
    "base64_decode": ("Decode base64 text.", {"text": _P["text"]}, ["text"]),
    "url_encode": ("Percent-encode text for a URL.", {"text": _P["text"]}, ["text"]),
    "url_decode": ("Decode percent-encoded URL text.", {"text": _P["text"]}, ["text"]),
    "hex_encode": ("Encode text to hexadecimal.", {"text": _P["text"]}, ["text"]),
    "hex_decode": ("Decode hexadecimal to text.", {"text": _P["text"]}, ["text"]),
    "rot13": ("Apply the ROT13 cipher to text.", {"text": _P["text"]}, ["text"]),
    "uuid_new": ("Generate a new random UUID4.", {}, []),
    "random_token": ("Generate a random URL-safe token.", {"length": {"type": "integer"}}, []),
    "slugify": ("Turn text into a URL/file-safe slug.", {"text": _P["text"]}, ["text"]),
    "reverse_text": ("Reverse a string.", {"text": _P["text"]}, ["text"]),
    "timestamp": ("Current time as epoch, local and UTC.", {}, []),
    "wrap_text": ("Word-wrap text to a column width.", {"text": _P["text"], "width": {"type": "integer"}}, ["text"]),
    "py_syntax_check": ("Compile-check a Python file for syntax errors.", {"path": _P["path"]}, ["path"]),
    "recall": ("Search your OTHER chat sessions for context about a topic (cross-session memory). "
               "Call this when the user refers to something discussed earlier or in another chat.",
               {"query": {"type": "string"}, "max_results": {"type": "integer"}}, ["query"]),
    "touch_file": ("Create an empty file (or update its timestamp). Requires approval.",
                   {"path": _P["path"]}, ["path"]),
    "sort_file": ("Sort a file's lines in place. Requires approval.",
                  {"path": _P["path"], "reverse": {"type": "boolean"}}, ["path"]),
    "dedupe_file": ("Remove duplicate lines from a file in place. Requires approval.", {"path": _P["path"]}, ["path"]),
    "trim_whitespace": ("Strip trailing whitespace from every line of a file. Requires approval.",
                        {"path": _P["path"]}, ["path"]),
    "append_line": ("Append a single line to a file. Requires approval.",
                    {"path": _P["path"], "line": {"type": "string"}}, ["path", "line"]),
    "write_json": ("Write a JSON file from a JSON string value. Requires approval.",
                   {"path": _P["path"], "value": {"type": "string"}}, ["path", "value"]),
    "set_json_key": ("Set a dotted key path to a value in a JSON file. Requires approval.",
                     {"path": _P["path"], "key_path": {"type": "string"}, "value": {"type": "string"}},
                     ["path", "key_path", "value"]),
}

SCHEMAS = []
for _n, (_desc, _props, _req) in _DEFS.items():
    _s = _d(_desc, _props, _req)
    _s["function"]["name"] = _n
    SCHEMAS.append(_s)
