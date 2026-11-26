"""Encrypted storage for connector secrets (GitHub token, mail password, ...).

On Windows secrets are encrypted with DPAPI (CryptProtectData): only the same Windows
user on the same machine can decrypt them, and they never sit in config.json in plain
text. On other platforms they are stored base64-obfuscated with 0600 permissions.
"""
from __future__ import annotations

import base64
import json
import os
import sys

import config as app_config

_FILE = "secrets.json"


def _path():
    return app_config.config_dir() / _FILE


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _blob(data: bytes) -> _Blob:
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    def _protect(data: bytes) -> bytes:
        out = _Blob()
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(_blob(data)), "LocalAICodeAgent", None,
                                                     None, None, 0x1, ctypes.byref(out)):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    def _unprotect(data: bytes) -> bytes:
        out = _Blob()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(_blob(data)), None, None, None, None,
                                                       0x1, ctypes.byref(out)):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)
else:  # pragma: no cover - non-Windows fallback
    def _protect(data: bytes) -> bytes:
        return data

    def _unprotect(data: bytes) -> bytes:
        return data


def _load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def get(name: str) -> str:
    raw = _load().get(name)
    if not raw:
        return ""
    try:
        return _unprotect(base64.b64decode(raw)).decode("utf-8")
    except (OSError, ValueError):
        return ""


def set(name: str, value: str) -> None:  # noqa: A001 - mirrors dict API
    data = _load()
    if value:
        data[name] = base64.b64encode(_protect(value.encode("utf-8"))).decode("ascii")
    else:
        data.pop(name, None)
    p = _path()
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    if os.name != "nt":
        os.chmod(p, 0o600)


def has(name: str) -> bool:
    return bool(_load().get(name))
