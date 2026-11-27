"""Per-workspace Python environment, like an activated virtualenv.

Problem this solves: install_dependency used sys.executable (the app's own Python - or,
in the frozen .exe, the app itself) while run_command/start_server ran the system
`python`. Packages were "installed" somewhere the code never ran. Now:
  * pip installs go into <workspace>/.venv (created on first install)
  * every command/server the agent runs gets that venv first on PATH
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

VENV_NAMES = (".venv", "venv", "env")


def _bin_dir(venv: Path) -> Path:
    return venv / ("Scripts" if os.name == "nt" else "bin")


def find_venv(root: Path) -> Path | None:
    for name in VENV_NAMES:
        v = Path(root) / name
        if (_bin_dir(v) / ("python.exe" if os.name == "nt" else "python")).is_file():
            return v
    return None


def venv_python(venv: Path) -> Path:
    return _bin_dir(venv) / ("python.exe" if os.name == "nt" else "python")


def system_python() -> list[str] | None:
    """A real Python interpreter on PATH (never the frozen app executable)."""
    frozen = Path(sys.executable).resolve() if getattr(sys, "frozen", False) else None
    for name in ("python", "python3"):
        exe = shutil.which(name)
        if exe and "WindowsApps" not in exe and (frozen is None or Path(exe).resolve() != frozen):
            return [exe]
    if os.name == "nt" and shutil.which("py"):
        return ["py", "-3"]
    if not getattr(sys, "frozen", False):
        return [sys.executable]
    return None


def ensure_venv(root: Path) -> tuple[Path | None, str]:
    v = find_venv(root)
    if v:
        return v, ""
    py = system_python()
    if not py:
        return None, "No Python interpreter found on PATH. Install Python 3 first."
    target = Path(root) / ".venv"
    p = subprocess.run(py + ["-m", "venv", str(target)], capture_output=True, text=True, timeout=300)
    if p.returncode != 0 or not venv_python(target).is_file():
        return None, f"Could not create virtualenv: {(p.stderr or p.stdout).strip()[-800:]}"
    return target, f"Created virtualenv {target}"


def workspace_env(root: Path) -> dict:
    """os.environ with the workspace venv activated (if there is one)."""
    env = os.environ.copy()
    v = find_venv(root)
    if v:
        env["VIRTUAL_ENV"] = str(v)
        env["PATH"] = str(_bin_dir(v)) + os.pathsep + env.get("PATH", "")
        env.pop("PYTHONHOME", None)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env
