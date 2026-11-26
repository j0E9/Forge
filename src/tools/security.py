"""Authorized security / reconnaissance toolkit.

IMPORTANT SAFETY MODEL
----------------------
These tools are for AUTHORIZED security testing only (your own systems, lab
environments, CTFs, or engagements with written permission). Every tool that
touches a remote target is gated twice:

  1. The session-level "security authorized" switch must be armed in the UI.
  2. Each active operation still requires an explicit approval prompt.

This module deliberately DOES NOT implement denial-of-service / DDoS,
traffic flooding, mass-scanning, credential brute-forcing engines, or exploit
delivery. Those are destructive/abusive and are out of scope. For heavyweight
authorized testing, `run_security_tool` can drive industry tools you have
already installed (nmap, nikto, nuclei, sqlmap, gobuster, ...), each run
individually approved.

Local-only utilities (hashing, encoding, password analysis) are not gated.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import secrets
import shutil
import socket
import ssl
import string
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    5985: "winrm", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dns",
    "api", "dev", "staging", "test", "portal", "admin", "vpn", "remote",
    "blog", "shop", "store", "app", "mobile", "m", "secure", "server",
    "cloud", "cdn", "static", "img", "assets", "docs", "support", "help",
    "status", "gitlab", "git", "jenkins", "jira", "confluence", "db", "sql",
]
# Broad allowlist for an authorized penetration-testing team. These are
# industry-standard tools; the agent only invokes ones already installed, and
# every run is gated by the armed authorization switch plus an approval prompt.
# (Denial-of-service/flooding tools are intentionally omitted from this list;
# run those, if your engagement truly requires them, via run_command so the
# destructive intent is explicit and separately approved.)
ALLOWED_TOOLS = {
    # scanning / discovery
    "nmap", "masscan", "naabu", "rustscan", "unicornscan", "arp", "arp-scan",
    "netdiscover", "fping", "hping3",
    # web / app
    "nikto", "nuclei", "sqlmap", "gobuster", "ffuf", "feroxbuster", "dirb",
    "dirbuster", "wfuzz", "whatweb", "wpscan", "joomscan", "katana", "httpx",
    "httprobe", "arjun", "dalfox", "gospider", "hakrawler", "paramspider",
    "commix", "xsstrike", "nosqlmap", "wafw00f",
    # recon / osint / subdomains
    "amass", "subfinder", "sublist3r", "assetfinder", "findomain", "dnsrecon",
    "dnsenum", "dnsx", "fierce", "theharvester", "theHarvester", "recon-ng",
    "spiderfoot", "waybackurls", "gau", "shodan", "censys", "metagoofil",
    "eyewitness", "aquatone", "gowitness",
    # dns / net utilities
    "nslookup", "dig", "host", "whois", "traceroute", "tracert", "openssl",
    "sslscan", "sslyze", "testssl", "testssl.sh", "curl", "wget", "netcat",
    "ncat", "nc", "socat", "tcpdump", "tshark",
    # smb / windows / ad
    "enum4linux", "enum4linux-ng", "smbclient", "smbmap", "crackmapexec",
    "netexec", "nxc", "responder", "impacket-secretsdump", "impacket-psexec",
    "impacket-GetNPUsers", "impacket-GetUserSPNs", "secretsdump.py",
    "GetNPUsers.py", "GetUserSPNs.py", "kerbrute", "evil-winrm", "ldapsearch",
    "bloodhound-python", "certipy", "rpcclient",
    # exploitation frameworks
    "msfconsole", "msfvenom", "msf-pattern_create", "searchsploit",
    "metasploit", "beef", "routersploit",
    # password / hashes
    "hydra", "medusa", "patator", "john", "hashcat", "ophcrack", "hashid",
    "hash-identifier", "cewl", "crunch",
    # wireless (recon/audit)
    "aircrack-ng", "airodump-ng", "reaver", "bully", "wifite", "kismet",
    # forensics / stego / binary
    "binwalk", "exiftool", "steghide", "foremost", "volatility", "strings",
    "radare2", "r2", "gdb", "objdump", "ltrace", "strace",
}


class SecurityTools:
    def __init__(self, approval, log, is_authorized):
        self.approval = approval
        self.log = log
        self.is_authorized = is_authorized

    # ----- gate ------------------------------------------------------------
    def _gate(self, operation: str, target: str) -> str | None:
        if not self.is_authorized():
            return ("BLOCKED: security tools are disarmed. Tick "
                    "“I am authorized to test these targets” in the app "
                    "to run active operations, and only against systems you own or "
                    "have written permission to test.")
        if not self.approval("security",
                             f"Authorized security operation:\n\n{operation}\nTarget: {target}\n\n"
                             "Only approve if you have explicit permission to test this target."):
            return "Operation denied: approval was not granted."
        return None

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "port_scan": return self.port_scan(args["host"], args.get("ports", "top"))
            if name == "banner_grab": return self.banner_grab(args["host"], int(args["port"]))
            if name == "http_headers": return self.http_headers(args["url"])
            if name == "dns_lookup": return self.dns_lookup(args["hostname"])
            if name == "reverse_dns": return self.reverse_dns(args["ip"])
            if name == "whois_lookup": return self.whois_lookup(args["domain"])
            if name == "ssl_cert_info": return self.ssl_cert_info(args["host"], int(args.get("port", 443)))
            if name == "subdomain_enum": return self.subdomain_enum(args["domain"])
            if name == "run_security_tool": return self.run_security_tool(args["tool"], args.get("arguments", ""))
            # local utilities (no gate)
            if name == "hash_text": return self.hash_text(args["text"], args.get("algorithm", "sha256"))
            if name == "identify_hash": return self.identify_hash(args["value"])
            if name == "encode_decode": return self.encode_decode(args["data"], args["scheme"], args.get("operation", "encode"))
            if name == "generate_password": return self.generate_password(int(args.get("length", 20)))
            if name == "password_strength": return self.password_strength(args["password"])
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    # ----- active recon ----------------------------------------------------
    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        spec = (spec or "top").strip().lower()
        if spec in ("top", "common", ""):
            return sorted(COMMON_PORTS)
        ports: set[int] = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                if a.isdigit() and b.isdigit():
                    lo, hi = int(a), int(b)
                    for p in range(max(1, lo), min(65535, hi) + 1):
                        ports.add(p)
            elif part.isdigit():
                ports.add(int(part))
        return sorted(p for p in ports if 1 <= p <= 65535)[:2000]

    def port_scan(self, host: str, ports: str = "top") -> str:
        host = host.strip()
        port_list = self._parse_ports(ports)
        if not port_list:
            return "No valid ports to scan."
        blocked = self._gate(f"TCP connect scan of {len(port_list)} port(s)", host)
        if blocked:
            return blocked
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as exc:
            return f"Could not resolve {host}: {exc}"

        def probe(port: int):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7)
            try:
                if s.connect_ex((ip, port)) == 0:
                    return port
            except OSError:
                return None
            finally:
                s.close()
            return None

        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as ex:
            for result in ex.map(probe, port_list):
                if result:
                    open_ports.append(result)
        open_ports.sort()
        if not open_ports:
            return f"Scan of {host} ({ip}): no open ports among {len(port_list)} scanned."
        lines = [f"Open ports on {host} ({ip}):"]
        for p in open_ports:
            lines.append(f"  {p}/tcp  {COMMON_PORTS.get(p, 'unknown')}")
        return "\n".join(lines)

    def banner_grab(self, host: str, port: int) -> str:
        blocked = self._gate(f"Banner grab on port {port}", host)
        if blocked:
            return blocked
        try:
            with socket.create_connection((host, port), timeout=5) as s:
                s.settimeout(4)
                try:
                    if port in (80, 8080, 8000):
                        s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
                    banner = s.recv(2048)
                except OSError:
                    banner = b""
            text = banner.decode("utf-8", errors="replace").strip()
            return f"Banner from {host}:{port}:\n{text or '(no banner received)'}"
        except OSError as exc:
            return f"Could not connect to {host}:{port}: {exc}"

    def http_headers(self, url: str) -> str:
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        host = re.sub(r"^https?://", "", url).split("/")[0]
        blocked = self._gate("HTTP security header review", host)
        if blocked:
            return blocked
        from urllib.request import Request, urlopen
        req = Request(url, headers={"User-Agent": "LocalAICodeAgent-SecurityScan/1.0"}, method="GET")
        try:
            with urlopen(req, timeout=20) as resp:
                headers = dict(resp.headers.items())
                status = getattr(resp, "status", "?")
        except Exception as exc:  # noqa: BLE001
            return f"Request failed: {exc}"
        wanted = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                  "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
                  "X-XSS-Protection"]
        lower = {k.lower(): v for k, v in headers.items()}
        lines = [f"GET {url}  ->  status {status}", "", "All response headers:"]
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
        lines.append("\nSecurity header assessment:")
        for h in wanted:
            present = lower.get(h.lower())
            lines.append(f"  [{'PRESENT' if present else 'MISSING '}] {h}" + (f": {present}" if present else ""))
        server = lower.get("server")
        if server:
            lines.append(f"\nServer banner: {server}")
        return "\n".join(lines)

    def dns_lookup(self, hostname: str) -> str:
        blocked = self._gate("DNS resolution", hostname)
        if blocked:
            return blocked
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            return f"DNS lookup failed for {hostname}: {exc}"
        addrs = sorted({info[4][0] for info in infos})
        try:
            canonical = socket.getfqdn(hostname)
        except OSError:
            canonical = hostname
        return f"DNS records for {hostname}:\n  Canonical: {canonical}\n  Addresses:\n    " + "\n    ".join(addrs)

    def reverse_dns(self, ip: str) -> str:
        blocked = self._gate("Reverse DNS (PTR) lookup", ip)
        if blocked:
            return blocked
        try:
            name, aliases, _ = socket.gethostbyaddr(ip)
        except (socket.herror, socket.gaierror, OSError) as exc:
            return f"Reverse lookup failed for {ip}: {exc}"
        extra = ("\n  Aliases: " + ", ".join(aliases)) if aliases else ""
        return f"Reverse DNS for {ip}:\n  Hostname: {name}{extra}"

    def _whois_query(self, server: str, query: str) -> str:
        with socket.create_connection((server, 43), timeout=15) as s:
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 100_000:
                    break
        return b"".join(chunks).decode("utf-8", errors="replace")

    def whois_lookup(self, domain: str) -> str:
        domain = domain.strip().lower()
        blocked = self._gate("WHOIS lookup", domain)
        if blocked:
            return blocked
        try:
            iana = self._whois_query("whois.iana.org", domain)
        except OSError as exc:
            return f"WHOIS failed: {exc}"
        ref = re.search(r"(?im)^whois:\s*(\S+)", iana)
        if ref:
            try:
                detail = self._whois_query(ref.group(1), domain)
                return f"WHOIS for {domain} (via {ref.group(1)}):\n\n{detail[:8000]}"
            except OSError:
                pass
        return f"WHOIS for {domain} (IANA):\n\n{iana[:8000]}"

    def ssl_cert_info(self, host: str, port: int = 443) -> str:
        blocked = self._gate(f"TLS certificate inspection on port {port}", host)
        if blocked:
            return blocked
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    cipher = ss.cipher()
                    version = ss.version()
        except Exception as exc:  # noqa: BLE001
            return f"TLS inspection failed for {host}:{port}: {exc}"
        if not cert:
            # CERT_NONE may yield an empty dict; fetch the binary form instead
            der = ssl.get_server_certificate((host, port))
            return f"{host}:{port} TLS {version}, cipher {cipher}\n(certificate presented; details unavailable in validation-disabled mode)\n{der[:2000]}"

        def name(seq):
            return ", ".join("=".join(x) for rdn in seq for x in rdn)

        subject = name(cert.get("subject", []))
        issuer = name(cert.get("issuer", []))
        sans = ", ".join(v for k, v in cert.get("subjectAltName", []))
        return (f"TLS certificate for {host}:{port}\n"
                f"  Protocol: {version}   Cipher: {cipher}\n"
                f"  Subject:  {subject}\n  Issuer:   {issuer}\n"
                f"  Valid from: {cert.get('notBefore')}\n  Valid to:   {cert.get('notAfter')}\n"
                f"  SANs: {sans}")

    def subdomain_enum(self, domain: str) -> str:
        domain = domain.strip().lower().lstrip(".")
        blocked = self._gate(f"Subdomain enumeration ({len(SUBDOMAIN_WORDLIST)} common names, DNS only)", domain)
        if blocked:
            return blocked

        def resolve(sub):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return f"  {fqdn} -> {ip}"
            except socket.gaierror:
                return None

        found = []
        with ThreadPoolExecutor(max_workers=40) as ex:
            for r in ex.map(resolve, SUBDOMAIN_WORDLIST):
                if r:
                    found.append(r)
        if not found:
            return f"No common subdomains resolved for {domain} (DNS-based check)."
        return f"Resolved subdomains for {domain}:\n" + "\n".join(sorted(found))

    def run_security_tool(self, tool: str, arguments: str = "") -> str:
        tool = (tool or "").strip()
        base = Path(tool).name.lower()
        exe = shutil.which(tool) or shutil.which(base)
        if not exe:
            return f"'{tool}' is not installed or not on PATH. Install it first."
        curated = base in ALLOWED_TOOLS or base.rstrip(".py").lower() in ALLOWED_TOOLS
        if not curated:
            # Not on the curated list, but the team may have installed anything.
            # Allow it only with an explicit, clearly-worded extra approval.
            if not self.is_authorized():
                return ("BLOCKED: security tools are disarmed. Arm authorization in the app first.")
            if not self.approval("security",
                                 f"'{tool}' is NOT on the curated security-tool list but is installed at:\n{exe}\n\n"
                                 "Run it anyway? Only approve for an authorized engagement."):
                return "Operation denied: approval was not granted for the uncurated tool."
        import shlex
        try:
            arg_list = shlex.split(arguments, posix=False)
        except ValueError as exc:
            return f"Could not parse arguments: {exc}"
        cmd = [exe, *arg_list]
        blocked = self._gate(f"Run security tool: {' '.join(cmd)[:200]}", arguments or "(no args)")
        if blocked:
            return blocked
        self.log(f"Security tool: {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=600)
            out = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
            return f"Exit code: {proc.returncode}\n{out[-18000:] or '(no output)'}"
        except subprocess.TimeoutExpired:
            return "Security tool timed out after 600 seconds."

    # ----- local utilities (no gate) --------------------------------------
    def hash_text(self, text: str, algorithm: str = "sha256") -> str:
        algorithm = algorithm.lower()
        if algorithm not in hashlib.algorithms_available:
            return f"Unsupported algorithm. Try one of: md5, sha1, sha256, sha512, sha3_256, blake2b."
        data = text.encode("utf-8")
        try:
            h = hashlib.new(algorithm, data)
            return f"{algorithm}({len(data)} bytes) = {h.hexdigest()}"
        except ValueError as exc:
            return f"Hashing failed: {exc}"

    def identify_hash(self, value: str) -> str:
        v = value.strip()
        if not re.fullmatch(r"[0-9a-fA-F]+", v):
            if re.fullmatch(r"\$2[aby]\$.*", v):
                return "Likely bcrypt hash."
            if v.startswith("$6$"):
                return "Likely sha512crypt (Unix) hash."
            if v.startswith("$5$"):
                return "Likely sha256crypt (Unix) hash."
            if v.startswith("$1$"):
                return "Likely md5crypt (Unix) hash."
            return "Not a plain hex hash; could not identify confidently."
        guesses = {32: "MD5 / NTLM / MD4", 40: "SHA-1", 56: "SHA-224",
                   64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
        return f"Length {len(v)} hex -> {guesses.get(len(v), 'unknown length; many possibilities')}."

    def encode_decode(self, data: str, scheme: str, operation: str = "encode") -> str:
        scheme = scheme.lower()
        operation = operation.lower()
        try:
            if scheme == "base64":
                if operation == "encode":
                    return base64.b64encode(data.encode("utf-8")).decode()
                return base64.b64decode(data).decode("utf-8", errors="replace")
            if scheme == "hex":
                if operation == "encode":
                    return data.encode("utf-8").hex()
                return bytes.fromhex(data).decode("utf-8", errors="replace")
            if scheme == "url":
                import urllib.parse
                return urllib.parse.quote(data) if operation == "encode" else urllib.parse.unquote(data)
            if scheme == "rot13":
                import codecs
                return codecs.encode(data, "rot13")
            return f"Unsupported scheme '{scheme}'. Use base64, hex, url, or rot13."
        except (binascii.Error, ValueError) as exc:
            return f"{operation} failed: {exc}"

    def generate_password(self, length: int = 20) -> str:
        length = max(8, min(128, length))
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        return f"Generated {length}-char password: {pw}"

    def password_strength(self, password: str) -> str:
        pool = 0
        if re.search(r"[a-z]", password): pool += 26
        if re.search(r"[A-Z]", password): pool += 26
        if re.search(r"[0-9]", password): pool += 10
        if re.search(r"[^a-zA-Z0-9]", password): pool += 32
        entropy = len(password) * math.log2(pool) if pool else 0
        if entropy < 40: verdict = "Very weak"
        elif entropy < 60: verdict = "Weak"
        elif entropy < 80: verdict = "Reasonable"
        elif entropy < 100: verdict = "Strong"
        else: verdict = "Very strong"
        return (f"Length {len(password)}, character pool ~{pool}, "
                f"estimated entropy {entropy:.1f} bits -> {verdict}. "
                "(Entropy assumes random composition; dictionary words reduce real strength.)")


SCHEMAS = [
    {"type": "function", "function": {"name": "port_scan",
        "description": "Authorized TCP connect port scan of a host. Requires the security switch to be armed and per-run approval. ports: 'top', a list like '22,80,443', or a range like '1-1024'.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "ports": {"type": "string"}}, "required": ["host"]}}},
    {"type": "function", "function": {"name": "banner_grab",
        "description": "Connect to host:port and read the service banner (authorized). Gated + approval.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["host", "port"]}}},
    {"type": "function", "function": {"name": "http_headers",
        "description": "Fetch a URL's HTTP response headers and assess security headers (HSTS, CSP, etc.). Gated + approval.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {"name": "dns_lookup",
        "description": "Resolve a hostname to IP addresses (forward DNS). Gated + approval.",
        "parameters": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}}},
    {"type": "function", "function": {"name": "reverse_dns",
        "description": "Resolve an IP address to a hostname (PTR). Gated + approval.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {"name": "whois_lookup",
        "description": "Look up WHOIS registration data for a domain over port 43. Gated + approval.",
        "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "ssl_cert_info",
        "description": "Inspect a TLS certificate (subject, issuer, validity, SANs, cipher). Gated + approval.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "port": {"type": "integer"}}, "required": ["host"]}}},
    {"type": "function", "function": {"name": "subdomain_enum",
        "description": "Discover subdomains of a domain using DNS resolution of a built-in common-name wordlist. Gated + approval.",
        "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}}},
    {"type": "function", "function": {"name": "run_security_tool",
        "description": "Run an installed security tool (nmap, nikto, nuclei, sqlmap, gobuster, sslscan, whois, dig, openssl, ...) with your arguments. Allowlisted names only; gated + per-run approval. Use this for heavyweight authorized testing.",
        "parameters": {"type": "object", "properties": {
            "tool": {"type": "string"}, "arguments": {"type": "string", "description": "Command-line arguments passed to the tool."}},
            "required": ["tool"]}}},
    {"type": "function", "function": {"name": "hash_text",
        "description": "Compute a cryptographic hash of text (md5, sha1, sha256, sha512, sha3_256, blake2b). Local, no approval.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string"}, "algorithm": {"type": "string"}}, "required": ["text"]}}},
    {"type": "function", "function": {"name": "identify_hash",
        "description": "Guess the hash type of a hex/crypt string by length and format. Local.",
        "parameters": {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]}}},
    {"type": "function", "function": {"name": "encode_decode",
        "description": "Encode or decode data using base64, hex, url, or rot13. Local.",
        "parameters": {"type": "object", "properties": {
            "data": {"type": "string"}, "scheme": {"type": "string", "enum": ["base64", "hex", "url", "rot13"]},
            "operation": {"type": "string", "enum": ["encode", "decode"]}}, "required": ["data", "scheme"]}}},
    {"type": "function", "function": {"name": "generate_password",
        "description": "Generate a cryptographically secure random password. Local.",
        "parameters": {"type": "object", "properties": {"length": {"type": "integer"}}, "required": []}}},
    {"type": "function", "function": {"name": "password_strength",
        "description": "Estimate the entropy and strength of a password. Local.",
        "parameters": {"type": "object", "properties": {"password": {"type": "string"}}, "required": ["password"]}}},
]
