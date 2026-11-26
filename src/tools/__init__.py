"""Tool registry: assembles every tool category and routes calls by name.

Categories:
  * workspace - files, search, shell, git, tests, install, drives, browser
  * web       - search, fetch/extract, HTTP client, download
  * hosting   - start/stop/host/debug background servers, open URLs
  * system    - read-only host info (OS, processes, network, env)
  * security  - authorized recon/scanning + installed-tool wrapper + crypto utils
"""
from __future__ import annotations

from pathlib import Path

from tools import browser as browser_mod
from tools import connectors as connectors_mod
from tools import crashdiag as crashdiag_mod
from tools import docs as docs_mod
from tools import hosting as hosting_mod
from tools import orchestrator as orchestrator_mod
from tools import remote as remote_mod
from tools import security as security_mod
from tools import supervisor as supervisor_mod
from tools import system as system_mod
from tools import web as web_mod
from tools import workspace as workspace_mod
from tools.workspace import WorkspaceTools

shutdown_all = hosting_mod.shutdown_all


class ToolRegistry:
    def __init__(self, root: Path, approval, log, is_authorized, provider=None, model=None):
        self._root_arg = root
        self._log = log
        self.workspace = WorkspaceTools(root, approval, log)
        self.web = web_mod.WebTools(approval, log)
        self.hosting = hosting_mod.HostingTools(root, approval, log)
        self.system = system_mod.SystemTools(log)
        self.security = security_mod.SecurityTools(approval, log, is_authorized)
        self.remote = remote_mod.RemoteTools(root, approval, log)
        self.docs = docs_mod.DocTools(root, approval, log)
        self.browser = browser_mod.BrowserTools(root, approval, log)
        self.supervisor = supervisor_mod.SupervisorTools(self)
        self.crashdiag = crashdiag_mod.CrashDiagTools()
        self.connectors = connectors_mod.ConnectorTools(root, approval, log)
        self.orchestrator = orchestrator_mod.OrchestratorTools(
            provider, model, self._build_subregistry, log)
        self.root = Path(root).resolve()

        self._routes = {}
        for schema in workspace_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.workspace
        for schema in web_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.web
        for schema in hosting_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.hosting
        for schema in system_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.system
        for schema in security_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.security
        for schema in remote_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.remote
        for schema in docs_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.docs
        for schema in browser_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.browser
        for schema in orchestrator_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.orchestrator
        for schema in supervisor_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.supervisor
        for schema in crashdiag_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.crashdiag
        for schema in connectors_mod.SCHEMAS:
            self._routes[schema["function"]["name"]] = self.connectors

    def _build_subregistry(self):
        # Sub-agents run with denied approval (no mutations) and no authorization.
        return ToolRegistry(self._root_arg, lambda *a, **k: False,
                            self._log, lambda: False, provider=None, model=None)

    @staticmethod
    def schemas() -> list[dict]:
        return (list(workspace_mod.SCHEMAS) + list(web_mod.SCHEMAS) +
                list(hosting_mod.SCHEMAS) + list(system_mod.SCHEMAS) +
                list(security_mod.SCHEMAS) + list(remote_mod.SCHEMAS) +
                list(docs_mod.SCHEMAS) + list(browser_mod.SCHEMAS) +
                list(orchestrator_mod.SCHEMAS) + list(supervisor_mod.SCHEMAS) +
                list(crashdiag_mod.SCHEMAS) + list(connectors_mod.SCHEMAS))

    def call(self, name: str, args: dict) -> str:
        handler = self._routes.get(name)
        if handler is None:
            return f"Unknown tool: {name}"
        # web.download_file needs the workspace root for relative destinations
        if name == "download_file":
            args = dict(args)
            args.setdefault("workspace", str(self.root))
        return handler.call(name, args if isinstance(args, dict) else {})
