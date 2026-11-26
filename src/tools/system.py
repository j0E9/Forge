"""Read-only system / host information tools.

These inspect the local machine (OS, hardware, processes, network interfaces,
active connections, environment). They do not modify anything and run without
approval, but they can reveal host details so output is bounded.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
import sys

MAX_OUT = 12_000


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
        return ((p.stdout or "") + (p.stderr or "")).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return f"(command failed: {exc})"


class SystemTools:
    def __init__(self, log):
        self.log = log

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "system_info": return self.system_info()
            if name == "list_processes": return self.list_processes(args.get("filter", ""))
            if name == "network_interfaces": return self.network_interfaces()
            if name == "list_connections": return self.list_connections()
            if name == "get_env": return self.get_env(args.get("name", ""))
            if name == "which": return self.which(args["name"])
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    def system_info(self) -> str:
        uname = platform.uname()
        lines = [
            "System information:",
            f"  Hostname: {socket.gethostname()}",
            f"  OS: {uname.system} {uname.release} ({uname.version})",
            f"  Machine: {uname.machine}   Processor: {uname.processor}",
            f"  CPU cores (logical): {os.cpu_count()}",
            f"  Python: {sys.version.split()[0]} ({sys.executable})",
            f"  User: {os.environ.get('USERNAME') or os.environ.get('USER', '?')}",
        ]
        if platform.system() == "Windows":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                    lines.insert(4, f"  CPU: {winreg.QueryValueEx(k, 'ProcessorNameString')[0].strip()}")
            except OSError:
                pass
            try:
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                                ("ullExtendedVirtual", ctypes.c_ulonglong)]
                m = MEMORYSTATUSEX()
                m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
                lines.append(f"  RAM: {m.ullTotalPhys/1024**3:.1f} GB total, "
                             f"{m.ullAvailPhys/1024**3:.1f} GB available ({m.dwMemoryLoad}% used)")
            except Exception:  # noqa: BLE001
                pass
        try:
            u = shutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\" if platform.system() == "Windows" else "/")
            lines.append(f"  System disk: {u.free/1024**3:.1f} GB free of {u.total/1024**3:.1f} GB")
        except OSError:
            pass
        return "\n".join(lines)

    def list_processes(self, name_filter: str = "") -> str:
        if platform.system() == "Windows":
            out = _run(["tasklist", "/fo", "csv", "/nh"])
            rows = []
            for line in out.splitlines():
                parts = [c.strip('"') for c in line.split('","')]
                if len(parts) >= 5:
                    pname, pid, mem = parts[0].lstrip('"'), parts[1], parts[4]
                    if name_filter and name_filter.lower() not in pname.lower():
                        continue
                    kb = int(re.sub(r"[^0-9]", "", mem) or 0)
                    rows.append((kb, f"  {pid:>7}  {kb / 1024:>10.1f} MB  {pname}"))
            # Sorted by memory (largest first) and capped: small models can't sort 300 rows,
            # and the full list wastes thousands of tokens.
            rows.sort(key=lambda r: r[0], reverse=True)
            limit = 200 if name_filter else 40
            header = f"Processes sorted by memory, largest first (top {min(limit, len(rows))} of {len(rows)}):\n" \
                     "      PID       Memory  Name"
            return header + "\n" + "\n".join([r[1] for r in rows[:limit]] or ["  (none matched)"])
        out = _run(["ps", "-eo", "pid,comm,%mem,%cpu", "--sort=-%mem"])
        if name_filter:
            out = "\n".join(l for l in out.splitlines() if name_filter.lower() in l.lower())
        return "Processes:\n" + out[:MAX_OUT]

    def network_interfaces(self) -> str:
        if platform.system() == "Windows":
            return "Network configuration:\n" + _run(["ipconfig", "/all"])[:MAX_OUT]
        out = _run(["ip", "addr"])
        if out.startswith("(command failed"):
            out = _run(["ifconfig"])
        return "Network configuration:\n" + out[:MAX_OUT]

    def list_connections(self) -> str:
        if platform.system() == "Windows":
            return "Active connections (netstat -ano):\n" + _run(["netstat", "-ano"])[:MAX_OUT]
        return "Active connections (netstat):\n" + _run(["netstat", "-tunap"])[:MAX_OUT]

    def get_env(self, name: str) -> str:
        if name:
            val = os.environ.get(name)
            return f"{name}={val}" if val is not None else f"{name} is not set."
        keys = sorted(os.environ.keys())
        return "Environment variable names:\n" + ", ".join(keys)

    def which(self, name: str) -> str:
        path = shutil.which(name)
        return f"{name} -> {path}" if path else f"'{name}' was not found on PATH."


SCHEMAS = [
    {"type": "function", "function": {"name": "system_info",
        "description": "Report local host details: OS, CPU, RAM, disk, user, Python. Read-only.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "list_processes",
        "description": "List running processes (optionally filtered by name substring). Read-only.",
        "parameters": {"type": "object", "properties": {"filter": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {"name": "network_interfaces",
        "description": "Show local network interface configuration (ipconfig/ip addr). Read-only.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "list_connections",
        "description": "List active network connections and listening ports (netstat). Read-only.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "get_env",
        "description": "Read an environment variable by name, or list all variable names if name is omitted. Read-only.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": []}}},
    {"type": "function", "function": {"name": "which",
        "description": "Locate an executable on PATH. Read-only.",
        "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}}},
]
