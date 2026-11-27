"""Browser automation driving the user's installed Chrome/Edge via the Chrome
DevTools Protocol (CDP) - no third-party packages, no bundled browser engine.

How it works:
  * Launch Chrome (or Edge, both Chromium) with --remote-debugging-port and a
    throwaway profile dir.
  * Talk CDP over a WebSocket implemented here with the standard library only
    (socket + the RFC 6455 handshake and framing).
  * Expose high-level tools: open/navigate, read page text, list clickable
    elements, click (by CSS selector OR x,y point), type, fill & submit forms,
    screenshot, close.

State-changing actions (navigate, click, type, fill/submit) require in-app
approval, since they act on live web pages on the user's behalf. Reading text,
listing elements and screenshots are free. Every network read has a timeout so a
hung page can never freeze the agent.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

_STATE: dict = {}  # {proc, port, ws, profile}
MAX_TEXT = 16000


# --------------------------------------------------------------------------- #
# Minimal WebSocket client (stdlib only)
# --------------------------------------------------------------------------- #
class _WS:
    def __init__(self, url: str, timeout: float = 30):
        if not url.startswith("ws://"):
            raise ValueError("only ws:// supported")
        hostport, _, path = url[5:].partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        self._buf = b""
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshake closed early")
            header += chunk
        head, _, rest = header.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"WebSocket handshake failed: {head[:120]!r}")
        self._buf = rest

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("WebSocket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        header = bytearray([0x81])  # FIN + text frame
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv(self) -> str:
        chunks = []
        while True:
            hdr = self._recv_exact(2)
            fin, opcode = hdr[0] & 0x80, hdr[0] & 0x0F
            masked, ln = hdr[1] & 0x80, hdr[1] & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._recv_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._recv_exact(8))[0]
            mkey = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(ln) if ln else b""
            if masked:
                payload = bytes(b ^ mkey[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:  # close
                raise ConnectionError("WebSocket closed by server")
            if opcode == 0x9:  # ping -> pong
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
                continue
            chunks.append(payload)
            if fin:
                break
        return b"".join(chunks).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class _CDP:
    def __init__(self, ws_url: str, timeout: float = 30):
        self.ws = _WS(ws_url, timeout)
        self._id = 0
        self.timeout = timeout

    def cmd(self, method: str, params=None, timeout=None) -> dict:
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            try:
                msg = json.loads(self.ws.recv())
            except socket.timeout:
                break
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(msg["error"].get("message", str(msg["error"])))
                return msg.get("result", {})
            # otherwise an event; ignore
        raise TimeoutError(f"CDP {method} timed out")

    def evaluate(self, expression: str, timeout=None):
        res = self.cmd("Runtime.evaluate",
                       {"expression": expression, "returnByValue": True, "awaitPromise": True},
                       timeout=timeout)
        return res.get("result", {}).get("value")

    def close(self) -> None:
        self.ws.close()


# --------------------------------------------------------------------------- #
# Browser discovery / lifecycle
# --------------------------------------------------------------------------- #
def _find_browser() -> str | None:
    cands = [
        shutil.which("chrome"), shutil.which("chrome.exe"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for c in cands:
        if c and Path(c).exists():
            return c
    # Edge is Chromium-based and speaks CDP too.
    for c in [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
              shutil.which("msedge")]:
        if c and Path(c).exists():
            return c
    return None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def shutdown_browser() -> None:
    st = _STATE
    if st.get("ws"):
        try:
            st["ws"].close()
        except Exception:  # noqa: BLE001
            pass
    proc = st.get("proc")
    if proc and proc.poll() is None:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               capture_output=True, timeout=15)
            else:
                proc.terminate()
        except (OSError, subprocess.TimeoutExpired):
            pass
    _STATE.clear()


class BrowserTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    # ----- lifecycle -------------------------------------------------------
    def _launch(self, headless: bool = False) -> str | None:
        exe = _find_browser()
        if not exe:
            return ("No Chrome or Edge found. Install Google Chrome (or use Microsoft Edge) so the "
                    "agent can drive a real browser.")
        port = _free_port()
        profile = tempfile.mkdtemp(prefix="laca_browser_")
        args = [exe, f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
                "--remote-allow-origins=*", "--no-first-run", "--no-default-browser-check",
                "--disable-popup-blocking", "--new-window", "about:blank"]
        if headless:
            args.insert(1, "--headless=new")
            args.insert(2, "--disable-gpu")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if (os.name == "nt" and headless) else 0
        try:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=flags)
        except OSError as exc:
            return f"Failed to launch browser: {exc}"
        ws_url = None
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2).read()
                targets = json.loads(raw)
                pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
                if pages:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
                    break
            except (OSError, ValueError):
                time.sleep(0.3)
        if not ws_url:
            shutdown_browser()
            return "Browser started but its debugging endpoint never came up."
        try:
            cdp = _CDP(ws_url, timeout=30)
            cdp.cmd("Page.enable")
            cdp.cmd("Runtime.enable")
        except Exception as exc:  # noqa: BLE001
            shutdown_browser()
            return f"Could not attach to the browser: {type(exc).__name__}: {exc}"
        _STATE.update({"proc": proc, "port": port, "ws": cdp, "profile": profile,
                       "exe": exe, "headless": headless})
        self.log(f"Browser launched ({Path(exe).name}, port {port}, headless={headless})")
        return None

    def _cdp(self):
        cdp = _STATE.get("ws")
        proc = _STATE.get("proc")
        if cdp and proc and proc.poll() is None:
            return cdp
        return None

    def _ensure(self, headless=False):
        cdp = self._cdp()
        if cdp:
            return cdp, None
        err = self._launch(headless=headless)
        if err:
            return None, err
        return self._cdp(), None

    def _wait_ready(self, cdp, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if cdp.evaluate("document.readyState", timeout=5) == "complete":
                    return
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.3)

    # ----- dispatch --------------------------------------------------------
    def call(self, name: str, args: dict) -> str:
        try:
            if name == "browser_open":
                return self.browser_open(args.get("url"), bool(args.get("headless", False)))
            if name == "browser_navigate":
                return self.browser_navigate(args["url"])
            if name == "browser_read_text":
                return self.browser_read_text()
            if name == "browser_read_page":
                return self.browser_read_page()
            if name == "browser_click":
                return self.browser_click(args.get("selector"), args.get("x"), args.get("y"))
            if name == "browser_type":
                return self.browser_type(args["text"], args.get("selector"), bool(args.get("submit", False)))
            if name == "browser_fill_form":
                return self.browser_fill_form(args["fields"], args.get("submit_selector"))
            if name == "browser_screenshot":
                return self.browser_screenshot(args.get("path"))
            if name == "browser_close":
                return self.browser_close()
            return f"Unknown tool: {name}"
        except KeyError as exc:
            return f"Missing required argument: {exc}"
        except (ConnectionError, TimeoutError) as exc:
            return f"Browser connection error: {exc}. Try browser_open again."
        except Exception as exc:  # noqa: BLE001
            return f"Browser tool error: {type(exc).__name__}: {exc}"

    # ----- tools -----------------------------------------------------------
    def browser_open(self, url=None, headless=False) -> str:
        if url and not self.approval("command", f"Open a browser and go to:\n\n{url}\n\nApprove?"):
            return "User denied opening the browser."
        cdp, err = self._ensure(headless=headless)
        if err:
            return err
        if url:
            return self.browser_navigate(url, _already_approved=True)
        return f"Browser is open ({Path(_STATE.get('exe','')).name}). Use browser_navigate to load a page."

    def browser_navigate(self, url: str, _already_approved=False) -> str:
        if not url.strip():
            return "No URL given."
        if "://" not in url:
            url = "https://" + url
        if not _already_approved and not self.approval("command", f"Navigate the browser to:\n\n{url}\n\nApprove?"):
            return "User denied navigation."
        cdp, err = self._ensure()
        if err:
            return err
        self.log(f"browser navigate {url}")
        cdp.cmd("Page.navigate", {"url": url}, timeout=30)
        self._wait_ready(cdp)
        title = cdp.evaluate("document.title") or ""
        cur = cdp.evaluate("location.href") or url
        return f"Loaded: {cur}\nTitle: {title}"

    def browser_read_text(self) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        text = cdp.evaluate("document.body ? document.body.innerText : ''") or ""
        text = text.strip()
        return (text[:MAX_TEXT] + ("\n\n[...truncated...]" if len(text) > MAX_TEXT else "")) or "(page has no visible text)"

    def browser_read_page(self) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        js = r"""
        JSON.stringify([...document.querySelectorAll('a,button,input,textarea,select,[role=button],[onclick]')]
          .map((e,i)=>{const r=e.getBoundingClientRect();
            return {i, tag:e.tagName.toLowerCase(), type:e.getAttribute('type')||'',
              text:((e.innerText||e.value||e.placeholder||e.getAttribute('name')||'')+'').trim().slice(0,60),
              id:e.id||'', name:e.getAttribute('name')||'',
              x:Math.round(r.x+r.width/2), y:Math.round(r.y+r.height/2),
              vis:(r.width>0&&r.height>0)};})
          .filter(e=>e.vis).slice(0,120))
        """
        raw = cdp.evaluate(js) or "[]"
        try:
            items = json.loads(raw)
        except (ValueError, TypeError):
            items = []
        if not items:
            return "No interactive elements found on the page."
        lines = ["Interactive elements (use selector '#id', or click by x,y):"]
        for e in items:
            sel = f"#{e['id']}" if e["id"] else (f"{e['tag']}[name=\"{e['name']}\"]" if e["name"] else e["tag"])
            t = f" type={e['type']}" if e["type"] else ""
            lines.append(f"  [{e['i']:>3}] <{e['tag']}{t}> \"{e['text']}\"  sel={sel}  @({e['x']},{e['y']})")
        return "\n".join(lines)

    def browser_click(self, selector=None, x=None, y=None) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        where = selector if selector else f"point ({x},{y})"
        if not self.approval("command", f"Click {where} in the browser?\n\nApprove?"):
            return "User denied the click."
        self.log(f"browser click {where}")
        if selector:
            ok = cdp.evaluate(
                "(()=>{const el=document.querySelector(%s);"
                "if(!el)return 'NOEL';el.scrollIntoView({block:'center'});el.click();return 'OK';})()"
                % json.dumps(selector))
            if ok == "NOEL":
                return f"No element matches selector: {selector}"
            self._wait_ready(cdp, timeout=8)
            return f"Clicked {selector}. Now at {cdp.evaluate('location.href')}"
        if x is None or y is None:
            return "Provide either a selector or both x and y."
        x, y = int(x), int(y)
        cdp.cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y,
                                             "button": "left", "clickCount": 1})
        cdp.cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y,
                                             "button": "left", "clickCount": 1})
        self._wait_ready(cdp, timeout=8)
        return f"Clicked at ({x},{y}). Now at {cdp.evaluate('location.href')}"

    def browser_type(self, text: str, selector=None, submit=False) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        if not self.approval("command",
                             f"Type into {selector or 'the focused field'}:\n\n{text[:200]}\n\nApprove?"):
            return "User denied typing."
        self.log(f"browser type into {selector or 'focused'}")
        if selector:
            ok = cdp.evaluate("(()=>{const el=document.querySelector(%s);"
                              "if(!el)return 'NOEL';el.focus();return 'OK';})()" % json.dumps(selector))
            if ok == "NOEL":
                return f"No element matches selector: {selector}"
        cdp.cmd("Input.insertText", {"text": text})
        if submit:
            cdp.cmd("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Enter",
                                               "windowsVirtualKeyCode": 13})
            cdp.cmd("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Enter",
                                               "windowsVirtualKeyCode": 13})
            self._wait_ready(cdp, timeout=8)
        return f"Typed {len(text)} chars{' and pressed Enter' if submit else ''}."

    def browser_fill_form(self, fields, submit_selector=None) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        if not isinstance(fields, dict) or not fields:
            return "fields must be a non-empty object of {selector: value}."
        preview = "\n".join(f"  {k} = {str(v)[:60]}" for k, v in fields.items())
        if not self.approval("command", f"Fill this form in the browser?\n\n{preview}\n"
                             f"{('Then submit: ' + submit_selector) if submit_selector else '(no auto-submit)'}\n\nApprove?"):
            return "User denied filling the form."
        self.log(f"browser fill form ({len(fields)} fields)")
        filled, missing = [], []
        for sel, val in fields.items():
            ok = cdp.evaluate(
                "(()=>{const el=document.querySelector(%s);if(!el)return 'NOEL';"
                "el.focus();el.value=%s;el.dispatchEvent(new Event('input',{bubbles:true}));"
                "el.dispatchEvent(new Event('change',{bubbles:true}));return 'OK';})()"
                % (json.dumps(sel), json.dumps(str(val))))
            (filled if ok == "OK" else missing).append(sel)
        result = f"Filled: {', '.join(filled) or 'none'}"
        if missing:
            result += f"\nNot found: {', '.join(missing)}"
        if submit_selector:
            ok = cdp.evaluate("(()=>{const el=document.querySelector(%s);if(!el)return 'NOEL';"
                              "el.click();return 'OK';})()" % json.dumps(submit_selector))
            self._wait_ready(cdp, timeout=10)
            result += (f"\nSubmitted via {submit_selector}. Now at {cdp.evaluate('location.href')}"
                       if ok == "OK" else f"\nSubmit control not found: {submit_selector}")
        return result

    def browser_screenshot(self, path=None) -> str:
        cdp = self._cdp()
        if not cdp:
            return "No browser is open. Use browser_open first."
        res = cdp.cmd("Page.captureScreenshot", {"format": "png"}, timeout=30)
        data = res.get("data")
        if not data:
            return "Screenshot failed (no data returned)."
        dest = Path(path).expanduser() if path else (self.root / f"screenshot_{int(time.time())}.png")
        if not dest.is_absolute():
            dest = self.root / dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(base64.b64decode(data))
        return f"Saved screenshot to {dest} ({dest.stat().st_size} bytes). Attach it to a vision model to see the page."

    def browser_close(self) -> str:
        if not _STATE.get("proc"):
            return "No browser is open."
        shutdown_browser()
        return "Browser closed."


SCHEMAS = [
    {"type": "function", "function": {"name": "browser_open",
        "description": "Open a real browser (your installed Chrome/Edge) and optionally navigate to a URL. Starts a controllable browser session for clicking, typing and filling forms. Requires approval when a URL is given.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "optional URL to load immediately"},
            "headless": {"type": "boolean", "description": "run without a visible window (default false)"}}}}},
    {"type": "function", "function": {"name": "browser_navigate",
        "description": "Navigate the open browser to a URL and wait for it to load. Requires approval.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "browser_read_text",
        "description": "Return the visible text of the current page. Read-only.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "browser_read_page",
        "description": "List the clickable/fillable elements on the current page (links, buttons, inputs) with a CSS selector and x,y center point for each, so you can decide what to click or fill. Read-only.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "browser_click",
        "description": "Click an element on the page, either by CSS selector (preferred, e.g. '#submit') or by x,y pixel coordinates from browser_read_page. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "selector": {"type": "string"}, "x": {"type": "integer"}, "y": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "browser_type",
        "description": "Type text into a field (give its CSS selector) or the currently focused field, optionally pressing Enter to submit. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string"}, "selector": {"type": "string"},
            "submit": {"type": "boolean", "description": "press Enter after typing"}},
            "required": ["text"]}}},
    {"type": "function", "function": {"name": "browser_fill_form",
        "description": "Fill several form fields at once, mapping CSS selectors to values, and optionally click a submit control. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "fields": {"type": "object", "description": "{\"#email\": \"a@b.com\", \"#name\": \"Joe\"}"},
            "submit_selector": {"type": "string", "description": "optional selector of the submit button"}},
            "required": ["fields"]}}},
    {"type": "function", "function": {"name": "browser_screenshot",
        "description": "Capture a PNG screenshot of the current page to a workspace file (can be attached to a vision model to 'see' the page). Read-only.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "browser_close",
        "description": "Close the automated browser session.",
        "parameters": {"type": "object", "properties": {}}}},
]
