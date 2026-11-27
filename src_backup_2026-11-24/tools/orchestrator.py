"""Multi-agent orchestration: look at the device's compute, then fan a goal out
to several read-only sub-agents running in parallel and aggregate their results.

Why read-only sub-agents: running many agents that write files / run commands /
drive the browser unattended and in parallel is unsafe (clashing edits, parallel
approval prompts, race conditions). The reliable, useful parallelism is fanning
out the *investigation* - reading lots of files, many web lookups, checks across
subsystems - then letting the main agent synthesize and do the mutating work with
the user's approval. Sub-agents therefore get only safe, approval-free tools.

Honesty about speed: with a local Ollama model the model calls largely serialize
on the GPU, so parallel workers mainly overlap tool/IO time. With an API provider
(Claude/GPT) the model calls run truly in parallel. device_capacity reports this.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re

# Safe, approval-free, side-effect-free tools a parallel sub-agent may use.
SAFE_TOOLS = {
    "list_files", "read_file", "search_files", "find_folder", "list_drives",
    "git_diff", "git_status", "read_document",
    "web_search", "fetch_url", "extract_links", "check_url", "http_request",
    "system_info", "list_processes", "network_interfaces", "list_connections",
    "get_env", "which", "tcp_check", "self_test",
    "http_headers", "dns_lookup", "reverse_dns", "whois_lookup", "ssl_cert_info",
    "hash_text", "identify_hash", "encode_decode", "password_strength",
}


def _ram_gb() -> float:
    try:
        if os.name == "nt":
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = _MS()
            m.dwLength = ctypes.sizeof(_MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return round(m.ullTotalPhys / 1e9, 1)
        return round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9, 1)
    except Exception:  # noqa: BLE001
        return 0.0


class OrchestratorTools:
    def __init__(self, provider, model, build_subregistry, log):
        self.provider = provider
        self.model = model
        self.build_subregistry = build_subregistry
        self.log = log

    def call(self, name: str, args: dict) -> str:
        try:
            if name == "device_capacity":
                cap = self._capacity()
                return self._format_capacity(cap)
            if name == "run_parallel_agents":
                return self.run_parallel_agents(
                    args.get("subtasks"), args.get("goal"), args.get("max_workers"))
            return f"Unknown tool: {name}"
        except Exception as exc:  # noqa: BLE001
            return f"Orchestrator error: {type(exc).__name__}: {exc}"

    # ----- capacity --------------------------------------------------------
    def _capacity(self) -> dict:
        cpus = os.cpu_count() or 2
        ram = _ram_gb()
        pname = getattr(self.provider, "name", "unknown") if self.provider else "none"
        if pname == "ollama":
            par = 1
            try:
                par = int(os.environ.get("OLLAMA_NUM_PARALLEL", "1") or 1)
            except ValueError:
                par = 1
            if par > 1:
                rec = max(2, min(par, 4, cpus))
                note = f"ollama local, OLLAMA_NUM_PARALLEL={par} (true parallel model calls)"
            else:
                rec = 2 if ram >= 12 else 1
                note = ("ollama local, model calls serialize (set OLLAMA_NUM_PARALLEL>1 with enough "
                        "VRAM for true parallelism) - workers mainly overlap tool/IO time")
        elif pname in ("openai", "anthropic"):
            rec = max(2, min(5, cpus))
            note = f"{pname} API (model calls run truly in parallel)"
        else:
            rec = 2
            note = "no provider bound"
        return {"cpus": cpus, "ram_gb": ram, "provider": pname,
                "recommended_workers": rec, "note": note}

    @staticmethod
    def _format_capacity(cap: dict) -> str:
        return ("Device capacity:\n"
                f"  CPU cores        : {cap['cpus']}\n"
                f"  RAM              : {cap['ram_gb']} GB\n"
                f"  Provider         : {cap['provider']}\n"
                f"  Recommended agents: {cap['recommended_workers']}\n"
                f"  Note             : {cap['note']}")

    # ----- sub-agent -------------------------------------------------------
    def _run_subagent(self, subtask: str, max_steps: int = 6) -> dict:
        reg = self.build_subregistry()
        safe = [s for s in reg.schemas() if s["function"]["name"] in SAFE_TOOLS]
        system = ("You are a focused research sub-agent in a parallel team. Complete ONLY the single "
                  "subtask you are given, using the read-only tools available, then reply with a concise "
                  "result (facts, findings, file/line references). You cannot modify files, run commands, "
                  "or browse interactively - do not attempt it. Be brief and specific.")
        messages = [{"role": "system", "content": system}, {"role": "user", "content": subtask}]
        used = []
        for _ in range(max_steps):
            try:
                msg = self.provider.chat(self.model, messages, safe)
            except Exception as exc:  # noqa: BLE001
                return {"subtask": subtask, "ok": False, "result": f"(model error: {exc})", "tools": used}
            calls = msg.get("tool_calls") or []
            messages.append(msg)
            if not calls:
                return {"subtask": subtask, "ok": True,
                        "result": (msg.get("content") or "(no output)").strip(), "tools": used}
            for c in calls:
                fn = c.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                if name not in SAFE_TOOLS:
                    res = f"(tool '{name}' is not available to sub-agents)"
                else:
                    res = reg.call(name, args if isinstance(args, dict) else {})
                used.append(name)
                messages.append({"role": "tool", "tool_name": name,
                                 "tool_call_id": c.get("id", "") or name, "content": str(res)[:6000]})
        return {"subtask": subtask, "ok": True, "result": "(reached step limit without concluding)", "tools": used}

    def _decompose(self, goal: str, max_parts: int) -> list[str]:
        prompt = (f"Break the following goal into at most {max_parts} INDEPENDENT subtasks that can be "
                  "researched in parallel by separate read-only agents. Return ONLY a JSON array of short "
                  f'task strings (e.g. ["...","..."]), nothing else.\n\nGoal: {goal}')
        try:
            msg = self.provider.chat(self.model, [{"role": "user", "content": prompt}], [])
            text = msg.get("content") or ""
            m = re.search(r"\[.*\]", text, re.S)
            arr = json.loads(m.group(0)) if m else []
            return [str(x).strip() for x in arr if str(x).strip()][:max_parts]
        except Exception:  # noqa: BLE001
            return []

    def run_parallel_agents(self, subtasks=None, goal=None, max_workers=None) -> str:
        if self.provider is None or not self.model:
            return "Multi-agent needs an active model/provider; none is bound to this session."
        cap = self._capacity()
        limit = int(max_workers) if max_workers else cap["recommended_workers"]
        limit = max(1, min(limit, 6))
        if not subtasks:
            if not goal:
                return "Provide either 'subtasks' (a list of strings) or a 'goal' (string) to split."
            subtasks = self._decompose(goal, max(2, min(5, limit)))
            if not subtasks:
                return ("Could not break the goal into subtasks automatically. Pass an explicit 'subtasks' "
                        "list instead.")
        subtasks = [str(s).strip() for s in subtasks if str(s).strip()]
        if not subtasks:
            return "No non-empty subtasks were provided."
        workers = max(1, min(len(subtasks), limit))
        self.log(f"Dispatching {len(subtasks)} sub-agents on {workers} parallel worker(s)")
        results = [None] * len(subtasks)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            fut_to_idx = {pool.submit(self._run_subagent, st): i for i, st in enumerate(subtasks)}
            for fut in concurrent.futures.as_completed(fut_to_idx):
                idx = fut_to_idx[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # noqa: BLE001
                    results[idx] = {"subtask": subtasks[idx], "ok": False,
                                    "result": f"(worker crashed: {exc})", "tools": []}
        out = [f"Ran {len(subtasks)} sub-agents on {workers} parallel worker(s). "
               f"Device: {cap['cpus']} CPUs, {cap['ram_gb']} GB RAM, provider {cap['provider']}.",
               f"({cap['note']})", ""]
        for i, r in enumerate(results, 1):
            r = r or {"subtask": subtasks[i - 1], "ok": False, "result": "(no result)", "tools": []}
            flag = "OK" if r["ok"] else "FAILED"
            out.append(f"--- [{flag}] Subtask {i}: {r['subtask'][:90]} ---")
            if r["tools"]:
                out.append(f"tools used: {', '.join(r['tools'])}")
            out.append(str(r["result"])[:4000])
            out.append("")
        out.append("Now synthesize these findings into the final answer. Do any file changes, commands or "
                   "browser actions yourself (with approval) - sub-agents were read-only.")
        return "\n".join(out)


SCHEMAS = [
    {"type": "function", "function": {"name": "device_capacity",
        "description": "Report this machine's compute (CPU cores, RAM) and the recommended number of parallel agents for the current provider. Use before run_parallel_agents to decide how many workers to use.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "run_parallel_agents",
        "description": "Speed up a big investigation by fanning it out to several read-only sub-agents running in PARALLEL, then aggregating their findings. Give either an explicit 'subtasks' list, or a 'goal' to split automatically. Sub-agents can read files, search, fetch web pages and run checks, but cannot modify anything - you synthesize their results and do the actual changes yourself. Best for research/analysis across many files or sources.",
        "parameters": {"type": "object", "properties": {
            "subtasks": {"type": "array", "items": {"type": "string"},
                         "description": "independent subtasks to run in parallel"},
            "goal": {"type": "string", "description": "a goal to split into subtasks automatically"},
            "max_workers": {"type": "integer", "description": "cap on parallel workers (optional)"}}}}},
]
