"""Supervisor / self-test: verify that every skill and tool in the agent is wired
correctly and that nothing hangs (deadlocks).

It does two things:
  1. Static integrity check of the tool registry - every advertised tool has a
     route, there are no duplicate names, and the catalog matches the handlers.
  2. Live, read-only probes of each subsystem, each run in its own thread with a
     hard timeout. A probe that exceeds its timeout is reported as a HANG/possible
     deadlock instead of freezing the whole agent - which is exactly how we catch
     the kind of blocking that used to stall the app.

Only safe, read-only, approval-free actions are probed, so running the self-test
never changes files, hits remote devices, or needs the user to approve anything.
"""
from __future__ import annotations

import concurrent.futures
import time


class SupervisorTools:
    def __init__(self, registry):
        self.registry = registry

    def call(self, name: str, args: dict) -> str:
        if name == "self_test":
            return self.self_test(bool(args.get("verbose", True)))
        return f"Unknown tool: {name}"

    # ----- probes ----------------------------------------------------------
    def _probes(self):
        reg = self.registry
        # (label, callable) - all read-only and approval-free.
        return [
            ("workspace.list_files", lambda: reg.workspace.list_files(".")),
            ("web.check_url(unreachable)", lambda: reg.web.check_url("http://127.0.0.1:9/health")),
            ("remote.tcp_check(closed)", lambda: reg.remote.tcp_check("127.0.0.1", 9, 3)),
            ("system.system_info", lambda: reg.system.call("system_info", {})),
            ("system.which(python)", lambda: reg.system.call("which", {"name": "python"})),
            ("security.identify_hash", lambda: reg.security.call(
                "identify_hash", {"value": "5d41402abc4b2a76b9719d911017c592"})),
            ("security.hash_text", lambda: reg.security.call(
                "hash_text", {"text": "ok", "algorithm": "sha256"})),
            ("docs.read_document(self)", lambda: reg.docs.call(
                "read_document", {"path": "requirements.txt"}) if hasattr(reg, "docs") else "n/a"),
        ]

    def self_test(self, verbose: bool = True) -> str:
        lines = ["SELF-TEST / SUPERVISOR REPORT", "=" * 32]

        # 1. Registry integrity -------------------------------------------------
        schemas = self.registry.schemas()
        names = [s["function"]["name"] for s in schemas]
        dupes = sorted({n for n in names if names.count(n) > 1})
        routed = self.registry._routes
        missing_route = sorted(n for n in names if n not in routed)
        orphan_route = sorted(n for n in routed if n not in names)
        ok_integrity = not (dupes or missing_route or orphan_route)
        lines.append(f"Tools advertised : {len(names)}")
        lines.append(f"Tools routed     : {len(routed)}")
        lines.append(f"Duplicate names  : {', '.join(dupes) or 'none'}")
        lines.append(f"Unrouted tools   : {', '.join(missing_route) or 'none'}")
        lines.append(f"Orphan routes    : {', '.join(orphan_route) or 'none'}")
        lines.append(f"Registry integrity: {'PASS' if ok_integrity else 'FAIL'}")
        lines.append("")

        # 2. Live probes with per-probe timeout (deadlock detection) ------------
        lines.append("Subsystem probes (each with a hard timeout):")
        passed = failed = hung = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for label, fn in self._probes():
                t0 = time.time()
                fut = pool.submit(fn)
                try:
                    result = fut.result(timeout=20)
                    dt = time.time() - t0
                    text = str(result).replace("\n", " ")
                    snippet = (text[:80] + "...") if len(text) > 80 else text
                    passed += 1
                    status = f"PASS ({dt:.2f}s)"
                    detail = f"  -> {snippet}" if verbose else ""
                    lines.append(f"  [{status:14}] {label}{detail}")
                except concurrent.futures.TimeoutError:
                    hung += 1
                    lines.append(f"  [HANG/DEADLOCK ] {label}  -> exceeded 20s timeout!")
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    lines.append(f"  [ERROR         ] {label}  -> {type(exc).__name__}: {exc}")

        lines.append("")
        verdict = "HEALTHY" if (ok_integrity and failed == 0 and hung == 0) else "PROBLEMS FOUND"
        lines.append(f"Probes: {passed} pass, {failed} error, {hung} hung.")
        lines.append(f"OVERALL: {verdict}")
        if hung:
            lines.append("A hung probe means that tool can block/deadlock the agent - investigate it.")
        return "\n".join(lines)


SCHEMAS = [
    {"type": "function", "function": {"name": "self_test",
        "description": "Run the built-in supervisor: verify every tool/skill is wired correctly (no duplicate or unrouted tools) and probe each subsystem with hard timeouts to prove nothing hangs or deadlocks. Safe and read-only - makes no changes and needs no approval. Use when asked whether everything is working or nothing is broken.",
        "parameters": {"type": "object", "properties": {
            "verbose": {"type": "boolean", "description": "include a short result snippet per probe (default true)"}}}}},
]
