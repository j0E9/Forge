"""Remote-device tools: reach another system or device by IP and work on it.

Two transports, both of which drive tools you already have installed:
  * ADB  - Android devices over USB or Wi-Fi (wireless debugging): connect/pair,
           run a shell command, install/launch an APK, read logcat, build with
           Gradle. Great for building an app here and deploying it to your phone.
  * SSH  - any machine you can reach by IP (a second PC, a server, even in
           another location): run commands and move files.
Plus tcp_check to confirm a host:port is actually reachable first.

These are for YOUR OWN or explicitly AUTHORIZED devices. State-changing actions
(running a command on a device, installing, transferring files, building) require
in-app approval. Every subprocess is killed as a whole tree if it exceeds its
timeout, so a remote call can never hang the agent.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path

MAX_OUTPUT_CHARS = 16000


def _kill_tree(proc) -> None:
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


def _exec(cmd: list[str], timeout: int = 60, cwd=None):
    """Run a command list, capture combined output, and never hang: on timeout the
    whole process tree is terminated. Returns (returncode|None, text)."""
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", env=os.environ.copy(),
                                creationflags=creationflags)
    except FileNotFoundError:
        return None, f"(executable not found: {cmd[0]})"
    except OSError as exc:
        return None, f"(failed to launch {cmd[0]}: {exc})"
    try:
        out, err = proc.communicate(timeout=timeout)
        text = (out or "") + ("\n[stderr]\n" + err if (err or "").strip() else "")
        return proc.returncode, text
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return None, f"(timed out after {timeout}s; terminated)\n{(out or '')}{(err or '')}"


def _fmt(rc, text: str) -> str:
    head = "timed out" if rc is None else f"exit code {rc}"
    body = (text or "").strip()[-MAX_OUTPUT_CHARS:] or "(no output)"
    return f"[{head}]\n{body}"


class RemoteTools:
    def __init__(self, root: Path, approval, log):
        self.root = Path(root).resolve()
        self.approval = approval
        self.log = log

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "tcp_check":
                return self.tcp_check(args["host"], int(args.get("port", 80)), int(args.get("timeout", 5)))
            if name == "adb_devices":
                return self.adb_devices()
            if name == "adb_connect":
                return self.adb_connect(args["host"], int(args.get("port", 5555)))
            if name == "adb_pair":
                return self.adb_pair(args["host_port"], args["code"])
            if name == "adb_shell":
                return self.adb_shell(args["command"], args.get("serial"))
            if name == "adb_install":
                return self.adb_install(args["apk_path"], args.get("serial"))
            if name == "adb_launch":
                return self.adb_launch(args["package"], args.get("serial"))
            if name == "adb_logcat":
                return self.adb_logcat(int(args.get("lines", 200)), args.get("filter"), args.get("serial"))
            if name == "android_build":
                return self.android_build(args.get("task", "assembleDebug"), args.get("cwd", "."))
            if name == "ssh_run":
                return self.ssh_run(args["host"], args["command"], args.get("user"),
                                    int(args.get("port", 22)), int(args.get("timeout", 60)))
            if name == "scp_transfer":
                return self.scp_transfer(args["direction"], args["host"], args["local_path"],
                                         args["remote_path"], args.get("user"), int(args.get("port", 22)))
            return f"Unknown tool: {name}"
        except KeyError as exc:
            return f"Missing required argument: {exc}"
        except Exception as exc:  # noqa: BLE001
            return f"TOOL ERROR: {type(exc).__name__}: {exc}"

    # ----- reachability ----------------------------------------------------
    def tcp_check(self, host: str, port: int, timeout: int = 5) -> str:
        host = (host or "").strip()
        if not host:
            return "No host given."
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return f"OPEN - {host}:{port} is reachable and accepting connections."
        except (socket.timeout, TimeoutError):
            return f"CLOSED/FILTERED - {host}:{port} did not respond within {timeout}s (host down, port closed, or firewalled)."
        except OSError as exc:
            return f"CLOSED - {host}:{port} is not reachable: {exc}"

    # ----- ADB / Android ---------------------------------------------------
    def _adb(self) -> str | None:
        return shutil.which("adb")

    def _no_adb(self) -> str:
        return ("adb (Android Platform Tools) is not installed or not on PATH. Install it "
                "(https://developer.android.com/tools/releases/platform-tools) and add it to PATH, "
                "then try again.")

    def _adb_base(self, serial=None) -> list[str]:
        base = [self._adb()]
        if serial:
            base += ["-s", str(serial)]
        return base

    def adb_devices(self) -> str:
        if not self._adb():
            return self._no_adb()
        rc, out = _exec([self._adb(), "devices", "-l"], timeout=20)
        return _fmt(rc, out)

    def adb_connect(self, host: str, port: int = 5555) -> str:
        if not self._adb():
            return self._no_adb()
        target = f"{host}:{port}"
        self.log(f"adb connect {target}")
        rc, out = _exec([self._adb(), "connect", target], timeout=30)
        hint = ("\nIf this fails, enable Wireless debugging on the phone (Developer options), make sure "
                "it is on the same network, and pair first with adb_pair if on Android 11+.")
        return _fmt(rc, out) + (hint if rc != 0 or "unable" in (out or "").lower() else "")

    def adb_pair(self, host_port: str, code: str) -> str:
        if not self._adb():
            return self._no_adb()
        self.log(f"adb pair {host_port}")
        # adb pair <ip:port> then sends the code on stdin / as arg; passing as arg works on recent adb.
        rc, out = _exec([self._adb(), "pair", host_port, str(code)], timeout=40)
        return _fmt(rc, out)

    def adb_shell(self, command: str, serial=None) -> str:
        if not self._adb():
            return self._no_adb()
        if not command.strip():
            return "Refused empty adb shell command."
        if not self.approval("command", f"Run a shell command ON THE ANDROID DEVICE"
                             f"{(' ' + serial) if serial else ''}?\n\n{command}\n\nApprove?"):
            return "User denied the device shell command."
        self.log(f"adb shell: {command}")
        rc, out = _exec(self._adb_base(serial) + ["shell", command], timeout=120)
        return _fmt(rc, out)

    def adb_install(self, apk_path: str, serial=None) -> str:
        if not self._adb():
            return self._no_adb()
        apk = Path(apk_path).expanduser()
        if not apk.is_absolute():
            apk = (self.root / apk)
        apk = apk.resolve()
        if not apk.is_file():
            return f"APK not found: {apk}"
        if not self.approval("command", f"Install this APK on the device"
                             f"{(' ' + serial) if serial else ''}?\n\n{apk}\n\nApprove install?"):
            return "User denied the APK install."
        self.log(f"adb install {apk}")
        rc, out = _exec(self._adb_base(serial) + ["install", "-r", str(apk)], timeout=300)
        return _fmt(rc, out)

    def adb_launch(self, package: str, serial=None) -> str:
        if not self._adb():
            return self._no_adb()
        if not self.approval("command", f"Launch app '{package}' on the device"
                             f"{(' ' + serial) if serial else ''}?\n\nApprove?"):
            return "User denied launching the app."
        self.log(f"adb launch {package}")
        rc, out = _exec(self._adb_base(serial) +
                        ["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
                        timeout=60)
        return _fmt(rc, out)

    def adb_logcat(self, lines: int = 200, filt=None, serial=None) -> str:
        if not self._adb():
            return self._no_adb()
        cmd = self._adb_base(serial) + ["logcat", "-d", "-t", str(max(1, min(lines, 2000)))]
        if filt:
            cmd += [str(filt)]
        rc, out = _exec(cmd, timeout=40)
        return _fmt(rc, out)

    def android_build(self, task: str = "assembleDebug", cwd: str = ".") -> str:
        workdir = (self.root / cwd).resolve()
        wrapper = workdir / ("gradlew.bat" if os.name == "nt" else "gradlew")
        if wrapper.is_file():
            cmd = [str(wrapper), task]
        elif shutil.which("gradle"):
            cmd = [shutil.which("gradle"), task]
        else:
            return (f"No Gradle wrapper (gradlew) found in {workdir} and 'gradle' is not on PATH. "
                    "Open the Android project folder as the workspace, or install Gradle.")
        if not self.approval("command", f"Build the Android project?\n\nDirectory: {workdir}\n"
                             f"Command: {' '.join(cmd)}\n\nThis can take a while and may download dependencies."):
            return "User denied the Android build."
        self.log(f"android build: {' '.join(cmd)} in {workdir}")
        rc, out = _exec(cmd, timeout=1800, cwd=str(workdir))
        result = _fmt(rc, out)
        if rc == 0:
            apks = sorted(workdir.glob("**/build/outputs/apk/**/*.apk"),
                          key=lambda p: p.stat().st_mtime, reverse=True)
            if apks:
                result += f"\n\nBuilt APK: {apks[0]}\nInstall it with adb_install, then adb_launch and adb_logcat to verify."
        return result

    # ----- SSH -------------------------------------------------------------
    def _target(self, host: str, user=None) -> str:
        return f"{user}@{host}" if user else host

    def ssh_run(self, host: str, command: str, user=None, port: int = 22, timeout: int = 60) -> str:
        if not shutil.which("ssh"):
            return "ssh client not found. Install OpenSSH Client (Windows optional feature) or add ssh to PATH."
        if not command.strip():
            return "Refused empty ssh command."
        target = self._target(host, user)
        if not self.approval("command", f"Run a command on remote host {target} (port {port}) via SSH?\n\n"
                             f"{command}\n\nApprove? (uses your SSH keys; password prompts are not supported)"):
            return "User denied the SSH command."
        self.log(f"ssh {target}: {command}")
        cmd = ["ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new", target, command]
        rc, out = _exec(cmd, timeout=timeout)
        if rc != 0 and "permission denied" in (out or "").lower():
            out += ("\n\n(Key-based auth failed. This tool uses BatchMode - set up an SSH key on the "
                    "remote host, e.g. ssh-copy-id, since interactive passwords are not supported.)")
        return _fmt(rc, out)

    def scp_transfer(self, direction: str, host: str, local_path: str, remote_path: str,
                     user=None, port: int = 22) -> str:
        if not shutil.which("scp"):
            return "scp not found. Install OpenSSH Client or add scp to PATH."
        direction = (direction or "").lower()
        if direction not in ("upload", "download"):
            return "direction must be 'upload' or 'download'."
        local = Path(local_path).expanduser()
        if not local.is_absolute():
            local = (self.root / local)
        local = local.resolve()
        target = self._target(host, user)
        remote_spec = f"{target}:{remote_path}"
        if direction == "upload":
            if not local.exists():
                return f"Local path not found: {local}"
            src, dst, human = str(local), remote_spec, f"UPLOAD {local}  ->  {remote_spec}"
        else:
            src, dst, human = remote_spec, str(local), f"DOWNLOAD {remote_spec}  ->  {local}"
        if not self.approval("download", f"Transfer a file over SCP?\n\n{human}\n(port {port})\n\nApprove?"):
            return "User denied the file transfer."
        self.log(f"scp {human}")
        cmd = ["scp", "-P", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=accept-new", src, dst]
        rc, out = _exec(cmd, timeout=600)
        if rc == 0 and direction == "download":
            out = (out or "") + f"\nSaved to: {local}"
        return _fmt(rc, out)


SCHEMAS = [
    {"type": "function", "function": {"name": "tcp_check",
        "description": "Check whether a host:port on another system/device is reachable (OPEN/CLOSED). Use this FIRST to confirm a phone or PC is reachable by its IP before adb_connect or ssh_run.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string", "description": "IP or hostname, e.g. 192.168.1.42"},
            "port": {"type": "integer", "description": "e.g. 5555 for adb, 22 for ssh"},
            "timeout": {"type": "integer"}}, "required": ["host", "port"]}}},
    {"type": "function", "function": {"name": "adb_devices",
        "description": "List Android devices/emulators currently visible to ADB (serial + state). Read-only.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "adb_connect",
        "description": "Connect to an Android phone over Wi-Fi (wireless debugging) by IP so you can build/install/debug on it remotely. The phone must have Wireless debugging enabled. Example: host=192.168.1.42 port=5555.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "port": {"type": "integer", "description": "default 5555"}},
            "required": ["host"]}}},
    {"type": "function", "function": {"name": "adb_pair",
        "description": "Pair with an Android 11+ phone for wireless debugging using the pairing address and 6-digit code shown under Developer options > Wireless debugging > Pair device with pairing code.",
        "parameters": {"type": "object", "properties": {
            "host_port": {"type": "string", "description": "the pairing ip:port shown on the phone"},
            "code": {"type": "string", "description": "the 6-digit pairing code"}},
            "required": ["host_port", "code"]}}},
    {"type": "function", "function": {"name": "adb_shell",
        "description": "Run a shell command ON the connected Android device and return its output. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"}, "serial": {"type": "string", "description": "optional device serial if more than one is connected"}},
            "required": ["command"]}}},
    {"type": "function", "function": {"name": "adb_install",
        "description": "Install (reinstall) an APK onto the connected Android device. apk_path may be workspace-relative (e.g. a freshly built debug APK). Requires approval.",
        "parameters": {"type": "object", "properties": {
            "apk_path": {"type": "string"}, "serial": {"type": "string"}}, "required": ["apk_path"]}}},
    {"type": "function", "function": {"name": "adb_launch",
        "description": "Launch an installed app on the device by its package name (e.g. com.example.app). Requires approval.",
        "parameters": {"type": "object", "properties": {
            "package": {"type": "string"}, "serial": {"type": "string"}}, "required": ["package"]}}},
    {"type": "function", "function": {"name": "adb_logcat",
        "description": "Fetch the most recent Android logcat lines from the device - use this to VERIFY the app ran and to debug crashes after install/launch. Read-only.",
        "parameters": {"type": "object", "properties": {
            "lines": {"type": "integer", "description": "default 200, max 2000"},
            "filter": {"type": "string", "description": "optional logcat filter spec, e.g. '*:E' for errors"},
            "serial": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "android_build",
        "description": "Build the Android project in the workspace with Gradle (default task assembleDebug) and report the built APK path. Open the Android project folder as the workspace first. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "task": {"type": "string", "description": "Gradle task, default assembleDebug"},
            "cwd": {"type": "string", "description": "project dir relative to workspace, default '.'"}}}}},
    {"type": "function", "function": {"name": "ssh_run",
        "description": "Run a command on another machine (your second PC/server, reachable by IP - even in another location) over SSH and return its output. Uses your SSH keys (no interactive password). Requires approval.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string", "description": "IP or hostname"},
            "command": {"type": "string"},
            "user": {"type": "string"}, "port": {"type": "integer", "description": "default 22"},
            "timeout": {"type": "integer"}}, "required": ["host", "command"]}}},
    {"type": "function", "function": {"name": "scp_transfer",
        "description": "Copy a file to ('upload') or from ('download') a remote host over SCP. Local path may be workspace-relative. Requires approval.",
        "parameters": {"type": "object", "properties": {
            "direction": {"type": "string", "enum": ["upload", "download"]},
            "host": {"type": "string"}, "local_path": {"type": "string"}, "remote_path": {"type": "string"},
            "user": {"type": "string"}, "port": {"type": "integer"}},
            "required": ["direction", "host", "local_path", "remote_path"]}}},
]
