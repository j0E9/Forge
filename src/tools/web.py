"""Web tools: search, fetch/extract page content, HTTP client, downloads.

Uses only the Python standard library (urllib). GET fetches of public pages run
without approval; state-changing HTTP methods and file downloads require
approval. No third-party scraping libraries are required.
"""
from __future__ import annotations

import gzip
import html
import io
import re
import urllib.parse
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 LocalAICodeAgent/1.0")
MAX_FETCH_BYTES = 3_000_000
MAX_TEXT_CHARS = 20_000


def _open(url: str, data=None, headers=None, method=None, timeout=30):
    h = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "gzip, identity"}
    if headers:
        h.update(headers)
    req = Request(url, data=data, headers=h, method=method)
    resp = urlopen(req, timeout=timeout)
    raw = resp.read(MAX_FETCH_BYTES + 1)
    if resp.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
        except OSError:
            pass
    return resp, raw


def html_to_text(raw_html: str) -> str:
    raw_html = re.sub(r"(?is)<(script|style|noscript|template)[^>]*>.*?</\1>", " ", raw_html)
    raw_html = re.sub(r"(?is)<!--.*?-->", " ", raw_html)
    # keep some structure as newlines
    raw_html = re.sub(r"(?i)<(br|/p|/div|/li|/tr|/h[1-6])\s*/?>", "\n", raw_html)
    text = re.sub(r"(?s)<[^>]+>", " ", raw_html)
    text = html.unescape(text)
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


class WebTools:
    def __init__(self, approval, log):
        self.approval = approval
        self.log = log

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "web_search": return self.web_search(args["query"], int(args.get("max_results", 6)))
            if name == "fetch_url": return self.fetch_url(args["url"], args.get("mode", "text"))
            if name == "extract_links": return self.extract_links(args["url"])
            if name == "http_request":
                return self.http_request(args["url"], args.get("method", "GET"),
                                         args.get("headers"), args.get("body"))
            if name == "check_url":
                return self.check_url(args["url"], args.get("expect_status"))
            if name == "download_file": return self.download_file(args["url"], args["path"], args.get("workspace"))
            return f"Unknown tool: {name}"
        except HTTPError as exc:
            return f"HTTP {exc.code} error for {args.get('url', '')}: {exc.reason}"
        except URLError as exc:
            return f"Network error: {exc.reason}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    def web_search(self, query: str, max_results: int = 6) -> str:
        query = (query or "").strip()
        if not query:
            return "Empty query."
        url = "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query)
        _, raw = _open(url, timeout=30)
        page = raw.decode("utf-8", errors="replace")
        results = []
        for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', page, re.S):
            href, title = m.group(1), html.unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip()
            # DuckDuckGo wraps the real url in a redirect; unwrap uddg=
            parsed = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed.query)
            if "uddg" in qs:
                href = qs["uddg"][0]
            results.append((title, href))
            if len(results) >= max_results:
                break
        if not results:
            return f"No results parsed for '{query}'. The search page layout may have changed."
        lines = [f"Search results for: {query}\n"]
        for i, (title, href) in enumerate(results, 1):
            lines.append(f"{i}. {title}\n   {href}")
        return "\n".join(lines)

    def fetch_url(self, url: str, mode: str = "text") -> str:
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        resp, raw = _open(url, timeout=30)
        ctype = resp.headers.get("Content-Type", "")
        body = raw[:MAX_FETCH_BYTES].decode("utf-8", errors="replace")
        header = f"GET {url}\nStatus: {getattr(resp, 'status', '?')}  Content-Type: {ctype}\n\n"
        if mode == "raw" or ("html" not in ctype.lower() and "<html" not in body[:1000].lower()):
            return header + body[:MAX_TEXT_CHARS]
        text = html_to_text(body)
        title = ""
        tm = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
        if tm:
            title = "Title: " + html.unescape(tm.group(1)).strip() + "\n"
        truncated = "\n\n[content truncated]" if len(text) > MAX_TEXT_CHARS else ""
        return header + title + "\n" + text[:MAX_TEXT_CHARS] + truncated

    def extract_links(self, url: str) -> str:
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        resp, raw = _open(url, timeout=30)
        page = raw.decode("utf-8", errors="replace")
        base = url
        links, seen = [], set()
        for m in re.finditer(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', page, re.S):
            href = urllib.parse.urljoin(base, m.group(1))
            if href in seen or href.startswith(("javascript:", "mailto:")):
                continue
            seen.add(href)
            text = html.unescape(re.sub(r"<[^>]+>", "", m.group(2))).strip()[:80]
            links.append(f"{href}  {('- ' + text) if text else ''}")
            if len(links) >= 80:
                break
        return f"Links from {url}:\n\n" + "\n".join(links) if links else f"No links found at {url}."

    def http_request(self, url, method="GET", headers=None, body=None) -> str:
        method = (method or "GET").upper()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        if method not in {"GET", "HEAD"}:
            if not self.approval("network", f"Allow an outbound {method} request?\n\nURL: {url}\n\n"
                                 f"Body: {(body or '')[:400]}"):
                return "User denied the network request."
        data = body.encode("utf-8") if isinstance(body, str) else body
        hdrs = {}
        if isinstance(headers, dict):
            hdrs = {str(k): str(v) for k, v in headers.items()}
        resp, raw = _open(url, data=data, headers=hdrs, method=method, timeout=30)
        hdr_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        text = raw[:MAX_TEXT_CHARS].decode("utf-8", errors="replace")
        return (f"{method} {url}\nStatus: {getattr(resp, 'status', '?')}\n\n"
                f"Response headers:\n{hdr_lines}\n\nBody:\n{text}")

    def check_url(self, url, expect_status=None) -> str:
        """Actually hit an endpoint and report whether it really works. Use this to
        VERIFY a server/app/endpoint instead of assuming it works. Handles localhost."""
        url = (url or "").strip()
        if not re.match(r"^https?://", url, re.I):
            host = url.split("/")[0].split(":")[0].lower()
            local = host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal")
            url = ("http://" if local else "https://") + url
        try:
            resp, raw = _open(url, timeout=10)
        except HTTPError as exc:
            # The server answered with an error status, so it IS up and reachable.
            try:
                body = exc.read()[:1200].decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body = ""
            verdict = "REACHABLE"
            if expect_status and str(exc.code) != str(expect_status):
                verdict = f"REACHABLE but status {exc.code} != expected {expect_status}"
            return (f"{verdict} - HTTP {exc.code} {exc.reason} at {url}\n"
                    f"The server responded (it is running).\n\nBody (first 1200 chars):\n{body or '(empty)'}")
        except URLError as exc:
            return (f"UNREACHABLE - {url}\nThe endpoint did NOT respond ({exc.reason}).\n"
                    "This almost always means the server is not actually running, exited, or is "
                    "listening on a different host/port. Do NOT report it as working. Start it with "
                    "start_server, inspect server_logs for errors, then check_url again.")
        except Exception as exc:  # noqa: BLE001
            return f"UNREACHABLE - {url}\nError: {type(exc).__name__}: {exc}"
        status = getattr(resp, "status", "?")
        ctype = resp.headers.get("Content-Type", "")
        body = raw[:1500].decode("utf-8", errors="replace")
        verdict = "REACHABLE - endpoint is live and responding"
        if expect_status and str(status) != str(expect_status):
            verdict = f"REACHABLE but status {status} != expected {expect_status}"
        return (f"{verdict}\nHTTP {status}  Content-Type: {ctype}\nURL: {url}\n\n"
                f"Actual response body (first 1500 chars):\n{body or '(empty)'}")

    def download_file(self, url, path, workspace=None) -> str:
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        dest = Path(path).expanduser()
        if workspace and not dest.is_absolute():
            dest = (Path(workspace) / dest)
        dest = dest.resolve()
        if workspace:
            try:
                dest.relative_to(Path(workspace).resolve())
            except ValueError:
                if not self.approval("external_path", f"Download outside the workspace?\n\n{dest}"):
                    return "Download denied: path outside workspace."
        if not self.approval("download", f"Download a file?\n\nFrom: {url}\nTo: {dest}\n\nApprove download?"):
            return "User denied the download."
        resp, raw = _open(url, timeout=120)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        self.log(f"Downloaded {url} -> {dest} ({len(raw)} bytes)")
        return f"Downloaded {len(raw)} bytes to {dest}."


SCHEMAS = [
    {"type": "function", "function": {"name": "web_search",
        "description": "Search the web (DuckDuckGo) and return titles and URLs. Use to find current information or sources before fetching.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "max_results": {"type": "integer", "description": "1-10, default 6"}},
            "required": ["query"]}}},
    {"type": "function", "function": {"name": "fetch_url",
        "description": "Fetch a web page and return its readable text content (HTML stripped). Use after web_search to read a page.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "mode": {"type": "string", "enum": ["text", "raw"], "description": "'text' extracts readable text; 'raw' returns source."}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "extract_links",
        "description": "List hyperlinks (absolute URLs + anchor text) found on a web page.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "http_request",
        "description": "Make an HTTP request to an API/endpoint and return status, headers, and body. GET/HEAD run freely; other methods require approval. Useful for testing REST APIs.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
            "headers": {"type": "object", "description": "Optional request headers as key/value pairs."},
            "body": {"type": "string", "description": "Optional request body (e.g. JSON string)."}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "check_url",
        "description": "VERIFY that a URL/endpoint actually works by making a real GET request and reporting REACHABLE/UNREACHABLE with the true HTTP status and response body. Works for localhost (e.g. http://localhost:8000/health). ALWAYS use this to confirm a server or endpoint is running before telling the user it works - opening a browser does NOT prove it works, and you must never invent a response.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "e.g. http://localhost:8000/health"},
            "expect_status": {"type": "integer", "description": "Optional expected HTTP status, e.g. 200."}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "download_file",
        "description": "Download a file from a URL to the workspace. Requires user approval.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}, "path": {"type": "string", "description": "Destination path (workspace-relative)."}},
            "required": ["url", "path"]}}},
]
