"""Document reading tools: pull readable text out of common document formats
using only the Python standard library (no third-party packages, so the frozen
build stays small).

Supported:
  * Plain text / code / data: .txt .md .markdown .rst .log .csv .tsv .json .xml
    .yaml .yml .ini .cfg .html .htm and most source files.
  * Office Open XML (zip + XML, parsed with stdlib): .docx .pptx .xlsx
  * PDF: best-effort text extraction (FlateDecode via zlib + text operators).
    Scanned/image-only PDFs have no text layer and will come back empty - those
    need OCR or a vision model.
"""
from __future__ import annotations

import html
import re
import zipfile
import zlib
from pathlib import Path

MAX_CHARS = 20000
PLAIN_SUFFIXES = {
    ".txt", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv", ".json", ".xml",
    ".yaml", ".yml", ".ini", ".cfg", ".conf", ".html", ".htm", ".py", ".js", ".ts",
    ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bat",
    ".ps1", ".sql", ".toml", ".env", ".gradle", ".kt",
}


def _xml_text(xml: str) -> str:
    xml = re.sub(r"(?is)<(w:p|a:p|/w:tbl|/a:tr)\b[^>]*>", "\n", xml)
    xml = re.sub(r"(?is)<[^>]+>", "", xml)
    return html.unescape(xml)


def _read_docx(path: Path) -> str:
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8", errors="replace")
    # keep paragraph/tab/break structure as whitespace
    xml = re.sub(r"(?is)<w:tab\b[^>]*/?>", "\t", xml)
    xml = re.sub(r"(?is)<w:br\b[^>]*/?>", "\n", xml)
    xml = re.sub(r"(?is)</w:p>", "\n", xml)
    text = _xml_text(xml)
    return re.sub(r"\n[ \t]*\n[ \t]*\n+", "\n\n", text).strip()


def _read_pptx(path: Path) -> str:
    out = []
    with zipfile.ZipFile(path) as z:
        slides = sorted((n for n in z.namelist()
                         if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                        key=lambda n: int(re.search(r"(\d+)", n).group(1)))
        for i, name in enumerate(slides, 1):
            xml = z.read(name).decode("utf-8", errors="replace")
            texts = re.findall(r"(?is)<a:t>(.*?)</a:t>", xml)
            body = "\n".join(html.unescape(t) for t in texts if t.strip())
            if body:
                out.append(f"--- Slide {i} ---\n{body}")
    return "\n\n".join(out).strip()


def _read_xlsx(path: Path) -> str:
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            s = z.read("xl/sharedStrings.xml").decode("utf-8", errors="replace")
            for si in re.findall(r"(?is)<si>(.*?)</si>", s):
                shared.append(html.unescape(re.sub(r"(?is)<[^>]+>", "", si)))
        sheets = sorted(n for n in z.namelist()
                        if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
        out = []
        for name in sheets:
            xml = z.read(name).decode("utf-8", errors="replace")
            rows = []
            for row in re.findall(r"(?is)<row\b[^>]*>(.*?)</row>", xml):
                cells = []
                for cell in re.findall(r'(?is)<c\b([^>]*)>(.*?)</c>', row):
                    attrs, inner = cell
                    vm = re.search(r"(?is)<v>(.*?)</v>", inner)
                    val = vm.group(1) if vm else ""
                    if 't="s"' in attrs and val.isdigit() and int(val) < len(shared):
                        val = shared[int(val)]
                    else:
                        tm = re.search(r"(?is)<t[^>]*>(.*?)</t>", inner)
                        if tm:
                            val = html.unescape(tm.group(1))
                    cells.append(val.strip())
                if any(cells):
                    rows.append("\t".join(cells))
            if rows:
                out.append(f"--- {name.split('/')[-1]} ---\n" + "\n".join(rows))
    return "\n\n".join(out).strip()


def _read_pdf(path: Path) -> str:
    raw = path.read_bytes()
    chunks = []
    # Decompress FlateDecode streams, then pull text from Tj / TJ operators.
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        data = m.group(1)
        try:
            data = zlib.decompress(data)
        except zlib.error:
            pass  # may be uncompressed or a non-text stream
        try:
            s = data.decode("latin-1", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        for tm in re.finditer(r"\((?:[^()\\]|\\.)*\)\s*Tj|\[(?:[^\[\]]*)\]\s*TJ", s):
            frag = tm.group(0)
            for lit in re.findall(r"\((?:[^()\\]|\\.)*\)", frag):
                txt = lit[1:-1]
                txt = (txt.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
                          .replace(r"\n", "\n").replace(r"\r", "").replace(r"\t", " "))
                chunks.append(txt)
            if frag.strip().endswith("TJ"):
                chunks.append(" ")
    text = re.sub(r"[ \t]+", " ", "".join(chunks)).strip()
    return text


class DocTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    def _resolve(self, path: str) -> Path:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = (self.root / p)
        p = p.resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            if not self.approval("external_read",
                                 f"Allow reading this document outside the workspace?\n\n{p}"):
                raise PermissionError(f"External read denied: {p}")
        return p

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "read_document":
                return self.read_document(args["path"])
            return f"Unknown tool: {name}"
        except KeyError as exc:
            return f"Missing required argument: {exc}"
        except PermissionError as exc:
            return str(exc)
        except FileNotFoundError:
            return f"Document not found: {args.get('path')}"
        except Exception as exc:  # noqa: BLE001
            return f"Could not read document: {type(exc).__name__}: {exc}"

    def read_document(self, path: str) -> str:
        p = self._resolve(path)
        if not p.is_file():
            return f"Document not found: {p}"
        suffix = p.suffix.lower()
        self.log(f"Reading document: {p.name}")
        if suffix == ".docx":
            text, kind = _read_docx(p), "Word document"
        elif suffix == ".pptx":
            text, kind = _read_pptx(p), "PowerPoint"
        elif suffix == ".xlsx":
            text, kind = _read_xlsx(p), "Excel spreadsheet"
        elif suffix == ".pdf":
            text, kind = _read_pdf(p), "PDF"
        elif suffix in PLAIN_SUFFIXES or suffix == "":
            text, kind = p.read_text(encoding="utf-8", errors="replace"), "text file"
        else:
            # try as text; many unknown formats are really text
            try:
                text, kind = p.read_text(encoding="utf-8", errors="replace"), "file"
            except Exception:  # noqa: BLE001
                return (f"Unsupported document type '{suffix}'. Supported: pdf, docx, pptx, xlsx, "
                        "and text/code/data files.")
        if not text.strip():
            note = ""
            if suffix == ".pdf":
                note = (" This PDF has no extractable text layer (likely scanned/image-only). "
                        "It needs OCR or a vision model to read.")
            return f"[{kind}: {p.name}] produced no readable text.{note}"
        truncated = "\n\n[...truncated...]" if len(text) > MAX_CHARS else ""
        return f"[{kind}: {p.name}, {len(text)} chars]\n\n{text[:MAX_CHARS]}{truncated}"


SCHEMAS = [
    {"type": "function", "function": {"name": "read_document",
        "description": "Read and extract the text from a document file: PDF, Word (.docx), PowerPoint (.pptx), Excel (.xlsx), or any text/code/data file (txt, md, csv, json, etc.). Use this to read uploaded documents the user put in the workspace. For scanned/image-only PDFs there is no text layer (use a vision model instead).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path to the document (workspace-relative or absolute)."}},
            "required": ["path"]}}},
]
