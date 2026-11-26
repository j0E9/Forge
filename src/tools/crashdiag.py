"""One-call Windows crash diagnosis (read-only).

Small models can't reliably write the PowerShell event-log queries needed to trace a
crashing game/app, so this gathers the evidence a human would look at in one call:
  * Application crash events (Event IDs 1000/1001/1002, Windows Error Reporting)
  * GPU driver resets (Display 4101 / nvlddmkm / amdkmdag), Kernel-Power 41,
    unexpected shutdowns (6008), WHEA hardware errors, BugChecks (1001)
  * GPU model + driver version/date, RAM, page file, free disk space
  * recent minidumps and WER crash report folders
Results are filtered by an optional app name ("RDR 2" also matches "RDR2.exe").
"""
from __future__ import annotations

import json
import re
import subprocess

_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$start = (Get-Date).AddDays(-%DAYS%)
$ev = @()
$ev += Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001,1002; StartTime=$start} -MaxEvents 300
$prov = 'nvlddmkm','Display','amdkmdag','amdwddmg','igfx','Microsoft-Windows-Kernel-Power','EventLog','BugCheck',
        'Microsoft-Windows-WER-SystemErrorReporting','Microsoft-Windows-WHEA-Logger','disk','stornvme','storahci','Ntfs'
$ev += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=$prov; Level=1,2,3; StartTime=$start} -MaxEvents 300
$events = $ev | Sort-Object TimeCreated -Descending | ForEach-Object {
  $m = ($_.Message -replace '\s+', ' ')
  if ($m.Length -gt 420) { $m = $m.Substring(0, 420) }
  [pscustomobject]@{ t = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); log = $_.LogName; id = $_.Id;
                     src = $_.ProviderName; msg = $m }
}
$gpu = Get-CimInstance Win32_VideoController | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; driver = $_.DriverVersion;
                     date = $(if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }) } }
$os = Get-CimInstance Win32_OperatingSystem
$pf = Get-CimInstance Win32_PageFileUsage | ForEach-Object { "$($_.Name) $($_.AllocatedBaseSize) MB (peak $($_.PeakUsage) MB)" }
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  "$($_.DeviceID) $([math]::Round($_.FreeSpace/1GB,1)) GB free of $([math]::Round($_.Size/1GB,1)) GB" }
$dumps = Get-ChildItem "$env:SystemRoot\Minidump" -File | Sort-Object LastWriteTime -Descending |
  Select-Object -First 5 | ForEach-Object { "$($_.Name) $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" }
$wer = @()
foreach ($d in @("$env:ProgramData\Microsoft\Windows\WER\ReportArchive", "$env:LOCALAPPDATA\Microsoft\Windows\WER\ReportArchive",
                 "$env:LOCALAPPDATA\CrashDumps")) {
  $wer += Get-ChildItem $d | Sort-Object LastWriteTime -Descending | Select-Object -First 40 |
    ForEach-Object { "$($_.Name) $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" } }
[pscustomobject]@{ events = @($events); gpu = @($gpu);
  ram_gb = [math]::Round($os.TotalVisibleMemorySize/1MB,1); free_ram_gb = [math]::Round($os.FreePhysicalMemory/1MB,1);
  pagefile = @($pf); disks = @($disks); dumps = @($dumps); wer = @($wer) } | ConvertTo-Json -Depth 4 -Compress
"""

def _meaning(src: str, eid: int):
    """Plain-English meaning, or None for events that are not stability problems."""
    s = (src or "").lower()
    if s in ("nvlddmkm", "amdkmdag", "amdwddmg", "igfx"):
        return "GPU driver error (driver fault / Xid) - unstable or corrupt graphics driver, overclock, or overheating GPU"
    if s == "display" and eid == 4101:
        return "Display driver stopped responding and recovered (GPU TDR)"
    if "kernel-power" in s:
        return "PC lost power / hard reset (PSU, overheating, or hard freeze)" if eid == 41 else None
    if s == "eventlog":
        return "Unexpected shutdown" if eid == 6008 else None
    if s in ("bugcheck", "microsoft-windows-wer-systemerrorreporting"):
        return "Blue screen (BugCheck) - see minidumps"
    if "whea" in s:
        return "WHEA hardware error (CPU/RAM/PCIe - unstable overclock or failing hardware)"
    if s in ("disk", "stornvme", "storahci", "ntfs"):
        return "Disk / file-system error (failing drive, cable, or corruption)"
    return None


# Modules that are a known cause by themselves.
_KNOWN_MODULES = {
    "emp.dll": "EMP.dll is NOT part of the official game files - it comes from a modified/unofficial build of the "
               "game and is a well-known cause of these crashes. Fix: uninstall and reinstall the official version "
               "(Steam/Epic/Rockstar Launcher), then verify game files.",
    "nvwgf2umx.dll": "NVIDIA DirectX driver module - clean-install the latest NVIDIA driver (or roll back one version).",
    "vulkan-1.dll": "Vulkan runtime - switch the game to DirectX 12 or update the GPU driver.",
    "amdxx64.dll": "AMD driver module - clean-install the AMD driver.",
    "d3d12.dll": "DirectX 12 - try Vulkan in the game settings, update Windows and the GPU driver.",
    "ntdll.dll": "Generic Windows crash location - check the other events (GPU driver, RAM, overlays).",
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _app_keys(app: str) -> list[str]:
    """'RDR 2' -> ['rdr2']; 'Red Dead Redemption 2' -> ['reddeadredemption2', 'rdr2']"""
    keys = {_norm(app)} if app else set()
    low = (app or "").lower()
    if "red dead" in low or "rdr" in low:
        keys |= {"rdr2", "reddeadredemption2", "playrdr2"}
    if "gta" in low or "grand theft" in low:
        keys |= {"gta5", "gtav", "playgtav"}
    return [k for k in keys if k]


def diagnose_crashes(app: str = "", days: int = 14) -> str:
    days = max(1, min(int(days or 14), 90))
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                            _PS.replace("%DAYS%", str(days))],
                           capture_output=True, text=True, errors="replace", timeout=90)
        data = json.loads(p.stdout.strip() or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return f"diagnose_crashes failed: {exc}"

    keys = _app_keys(app)
    events = data.get("events") or []
    if isinstance(events, dict):
        events = [events]

    def matches(e):
        return any(k in _norm(e.get("msg", "")) for k in keys)

    app_events = [e for e in events if e.get("log") == "Application" and (not keys or matches(e))]
    sys_events = [e for e in events if e.get("log") == "System" and _meaning(e.get("src"), e.get("id"))]
    lines = [f"CRASH DIAGNOSIS (last {days} days{', app: ' + app if app else ''})", ""]

    lines.append(f"Application crash/hang events{' for ' + app if app else ''}: {len(app_events)}")
    for e in app_events[:8]:
        lines.append(f"  {e['t']}  ID {e['id']}  {e['msg'][:300]}")
    modules = re.findall(r"(?i)faulting module name:\s*([^\s,]+)", " ".join(e["msg"] for e in app_events))
    if modules:
        common = max(set(modules), key=modules.count)
        lines.append(f"  Most common faulting module: {common} ({modules.count(common)}x)")
        if common.lower() in _KNOWN_MODULES:
            lines.append(f"  KNOWN CAUSE: {_KNOWN_MODULES[common.lower()]}")
    if keys and not app_events:
        other = [e for e in events if e.get("log") == "Application" and e.get("id") in (1000, 1002)][:3]
        lines.append("  (no events mention this app - it may be closing without Windows logging a crash)")
        for e in other:
            lines.append(f"  other app crash: {e['t']}  {e['msg'][:160]}")

    lines.append("")
    lines.append(f"System stability events: {len(sys_events)}")
    seen = {}
    for e in sys_events:
        key = (e.get("log"), e.get("id"), e.get("src"))
        seen.setdefault(key, []).append(e)
    for (log, eid, src), group in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        meaning = _meaning(src, eid)
        lines.append(f"  {len(group)}x  ID {eid} ({src}): {meaning}. Latest {group[0]['t']}")

    lines.append("")
    for g in data.get("gpu") or []:
        lines.append(f"GPU: {g.get('name')}  driver {g.get('driver')}  ({g.get('date')})")
    lines.append(f"RAM: {data.get('ram_gb')} GB total, {data.get('free_ram_gb')} GB free")
    for x in data.get("pagefile") or ["Page file: none / system managed"]:
        lines.append(f"Page file: {x}")
    for d in data.get("disks") or []:
        lines.append(f"Disk: {d}")
    dumps = data.get("dumps") or []
    lines.append(f"Minidumps (blue screens): {', '.join(dumps) if dumps else 'none'}")
    wer = [w for w in (data.get("wer") or []) if not keys or any(k in _norm(w) for k in keys)]
    lines.append(f"WER crash reports{' for ' + app if app else ''}: {', '.join(wer[:5]) if wer else 'none'}")
    lines.append("")
    lines.append("NEXT: reply to the user now with (1) the most likely cause, quoting the evidence above, and "
                 "(2) the recommended fixes as steps for the user. Do NOT apply fixes yourself (no registry, "
                 "driver, uninstall or settings changes) - this tool is for diagnosis only.")
    return "\n".join(lines)


SCHEMAS = [
    {"type": "function", "function": {"name": "diagnose_crashes",
        "description": "Trace why a game/app/PC is crashing on Windows: collects app crash events, faulting "
                       "modules, GPU driver resets, power/blue-screen events, GPU driver version, RAM, page file, "
                       "disk space, minidumps and crash reports in ONE call. Read-only. Call this first for any crash.",
        "parameters": {"type": "object", "properties": {
            "app": {"type": "string", "description": "app or game name / exe, e.g. 'RDR2' (optional)"},
            "days": {"type": "integer", "description": "how many days back to look (default 14)"}}}}},
]


class CrashDiagTools:
    def call(self, name: str, args: dict) -> str:
        if name == "diagnose_crashes":
            return diagnose_crashes(str(args.get("app", "") or ""), args.get("days", 14) or 14)
        return f"Unknown tool: {name}"
