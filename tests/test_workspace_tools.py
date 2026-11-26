import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from app import WorkspaceTools  # noqa: E402  (re-exported from tools.workspace)
from tools.security import SecurityTools  # noqa: E402
from tools.workspace import AgentError  # noqa: E402


class WorkspaceToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.approvals = []
        self.tools = WorkspaceTools(
            self.root,
            lambda kind, detail: self.approvals.append((kind, detail)) or True,
            lambda _: None,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_and_list(self):
        (self.root / "hello.txt").write_text("hello", encoding="utf-8")
        self.assertEqual(self.tools.read_file("hello.txt"), "hello")
        self.assertIn("hello.txt", self.tools.list_files("."))

    def test_blocks_path_traversal_when_approval_denied(self):
        # External access is only allowed with explicit approval; deny it and
        # the traversal must raise instead of resolving outside the workspace.
        self.tools.approval = lambda *_: False
        with self.assertRaises(AgentError):
            self.tools.resolve("../outside.txt")

    def test_write_outside_workspace_is_always_refused(self):
        # Even with auto-approval, writes must never escape the workspace.
        result = self.tools.write_file("../escape.txt", "x")
        self.assertIn("Refused", result)
        self.assertFalse((self.root.parent / "escape.txt").exists())

    def test_write_requires_approval_and_creates_backup(self):
        p = self.root / "a.py"
        p.write_text("print('old')", encoding="utf-8")
        result = self.tools.write_file("a.py", "print('new')")
        self.assertEqual(p.read_text(encoding="utf-8"), "print('new')")
        self.assertTrue((self.root / "a.py.localqwen.bak").exists())
        self.assertEqual(self.approvals[0][0], "write")
        self.assertIn("Saved", result)

    def test_append_file(self):
        self.tools.write_file("log.txt", "a")
        self.tools.append_file("log.txt", "b")
        self.assertEqual((self.root / "log.txt").read_text(encoding="utf-8"), "ab")

    def test_denied_write_does_not_modify_file(self):
        self.tools.approval = lambda *_: False
        p = self.root / "a.txt"
        p.write_text("original", encoding="utf-8")
        self.assertEqual(self.tools.write_file("a.txt", "changed"), "User denied file change.")
        self.assertEqual(p.read_text(encoding="utf-8"), "original")

    def test_delete_requires_approval(self):
        p = self.root / "gone.txt"
        p.write_text("x", encoding="utf-8")
        self.tools.approval = lambda *_: False
        self.assertIn("denied", self.tools.delete_path("gone.txt").lower())
        self.assertTrue(p.exists())

    def test_server_commands_are_redirected_not_run(self):
        # Long-running servers must be refused with a start_server hint, never
        # executed by run_command (which would block the agent forever).
        approvals = []
        self.tools.approval = lambda *a, **k: approvals.append(a) or True
        for cmd in ("uvicorn main:app --reload", "npm run dev",
                    "python -m http.server 8000", "flask run", "streamlit run app.py"):
            out = self.tools.run_command(cmd)
            self.assertIn("start_server", out)
            self.assertIn("Refused", out)
        self.assertEqual(approvals, [])  # never even prompted for approval

    def test_raw_git_is_redirected_to_connector_tools(self):
        # Raw git loses token auth (push -> exit 128), so run_command must refuse
        # it and point at the dedicated git_*/github_* tools, without prompting.
        approvals = []
        self.tools.approval = lambda *a, **k: approvals.append(a) or True
        cases = {
            "git push -u origin main": "git_push()",
            "git add . && git commit -m x": "git_commit",
            "git init": "git_init()",
            "git clone https://github.com/x/y.git": "git_clone",
            "git remote add origin url": "git_remote",
        }
        for cmd, expect_tool in cases.items():
            out = self.tools.run_command(cmd)
            self.assertIn("Refused", out)
            self.assertIn("exit 128", out)
            self.assertIn(expect_tool, out)
        self.assertEqual(approvals, [])  # never prompted for approval

    def test_non_git_command_with_git_substring_still_runs(self):
        # "digit", "legit", paths like ./gitignore must NOT be mistaken for git.
        self.tools.approval = lambda *_: True
        out = self.tools.run_command("python -c \"print('digits legitimate')\"")
        self.assertIn("digits legitimate", out)
        self.assertNotIn("Refused", out)

    def test_locate_finds_by_name_and_content(self):
        (self.root / "notes.txt").write_text("nothing here", encoding="utf-8")
        (self.root / "parser.py").write_text("def parse_invoice():\n    return 1\n", encoding="utf-8")
        out = self.tools.locate("invoice parser", "workspace", 5)
        self.assertIn("parser.py", out)
        # a word that appears only in contents is found too
        self.assertIn("parser.py", self.tools.locate("parse_invoice", "workspace", 5))

    def test_locate_external_scope_needs_approval(self):
        self.tools.approval = lambda *a, **k: False
        out = self.tools.locate("anything", "drives", 3)
        self.assertIn("denied", out.lower())

    def test_tree_and_outline(self):
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "m.py").write_text("class A:\n    def go(self):\n        pass\n", encoding="utf-8")
        tree = self.tools.tree(".", 2)
        self.assertIn("pkg/", tree)
        self.assertIn("m.py", tree)
        outline = self.tools.file_outline("pkg/m.py")
        self.assertIn("class A", outline)
        self.assertIn("def go", outline)

    def test_replace_in_files_backs_up_and_needs_approval(self):
        p = self.root / "a.txt"
        p.write_text("foo foo bar", encoding="utf-8")
        self.tools.approval = lambda *_: False
        self.assertIn("denied", self.tools.replace_in_files("foo", "baz", ".").lower())
        self.assertEqual(p.read_text(encoding="utf-8"), "foo foo bar")
        self.tools.approval = lambda *_: True
        out = self.tools.replace_in_files("foo", "baz", ".")
        self.assertIn("Replaced 2", out)
        self.assertEqual(p.read_text(encoding="utf-8"), "baz baz bar")
        self.assertTrue((self.root / "a.txt.localqwen.bak").exists())

    def test_run_command_times_out_without_hanging(self):
        # A command that blocks must be terminated and return promptly.
        self.tools.approval = lambda *_: True
        out = self.tools.run_command("python -c \"import time; time.sleep(60)\"", timeout=3)
        self.assertIn("timed out", out.lower())

    def test_normal_command_still_runs(self):
        self.tools.approval = lambda *_: True
        out = self.tools.run_command("python -c \"print('ok123')\"")
        self.assertIn("ok123", out)
        self.assertIn("Exit code: 0", out)


class WebToolTests(unittest.TestCase):
    def setUp(self):
        from tools.web import WebTools
        self.web = WebTools(lambda *a, **k: True, lambda *a, **k: None)

    def test_check_url_reports_unreachable_for_dead_port(self):
        # A closed local port must be reported as UNREACHABLE, never as working.
        out = self.web.check_url("http://127.0.0.1:9/health")  # port 9 (discard) refuses
        self.assertTrue(out.startswith("UNREACHABLE"))
        self.assertNotIn("is live and responding", out)

    def test_check_url_defaults_localhost_to_http(self):
        out = self.web.check_url("localhost:9/health")
        self.assertIn("http://localhost:9/health", out)


class RemoteToolTests(unittest.TestCase):
    def setUp(self):
        from tools.remote import RemoteTools
        self.root = Path(tempfile.mkdtemp())
        self.remote = RemoteTools(self.root, lambda *a, **k: True, lambda *a, **k: None)

    def test_tcp_check_closed_port(self):
        out = self.remote.call("tcp_check", {"host": "127.0.0.1", "port": 9})
        self.assertTrue(out.startswith("CLOSED") or out.startswith("CLOSED/FILTERED"))

    def test_registry_exposes_remote_tools(self):
        from tools import ToolRegistry
        names = {s["function"]["name"] for s in ToolRegistry.schemas()}
        for t in ("tcp_check", "adb_connect", "adb_install", "adb_launch",
                  "android_build", "ssh_run", "scp_transfer"):
            self.assertIn(t, names)

    def test_adb_missing_is_reported_not_crashed(self):
        # When adb is absent the tool returns guidance, never an exception.
        self.remote._adb = lambda: None
        self.assertIn("adb", self.remote.call("adb_devices", {}).lower())

    def test_scp_requires_valid_direction(self):
        out = self.remote.call("scp_transfer", {"direction": "sideways", "host": "h",
                               "local_path": "a", "remote_path": "b"})
        self.assertIn("upload", out.lower())


class AutoApproveTests(unittest.TestCase):
    def _worker(self, auto):
        import threading
        import app
        self.emits = []
        return app.AgentWorker(None, "m", "t", None, self.emits.append,
                               threading.Event(), lambda: False, auto_approve=lambda: auto)

    def test_auto_approves_safe_without_prompt(self):
        w = self._worker(True)
        self.assertTrue(w.approval("command", "Run:\n\npython -m pytest"))
        self.assertEqual(sum(1 for e in self.emits if e.get("type") == "approval"), 0)

    def test_dangerous_commands_still_prompt_in_auto(self):
        w = self._worker(True)
        for cmd in ("rm -rf /", "format C:", "git push --force", "drop database x",
                    "shutdown /s", "dd if=/dev/zero of=/dev/sda"):
            self.assertTrue(w._high_risk("command", "Run:\n\n" + cmd), cmd)

    def test_delete_and_security_always_high_risk(self):
        w = self._worker(True)
        self.assertTrue(w._high_risk("delete", "Permanently delete"))
        self.assertTrue(w._high_risk("security", "Run nmap"))
        self.assertFalse(w._high_risk("write", "Create file a.py"))
        self.assertFalse(w._high_risk("command", "Run:\n\nnpm install"))


class ExecuteVerifyGuardTests(unittest.TestCase):
    def _w(self):
        import threading
        import app
        return app.AgentWorker(None, "m", "t", None, lambda *a: None, threading.Event(), lambda: False)

    def test_detects_narrated_tool_steps(self):
        w = self._w()
        txt = "Step 6: Test\n```\nopen_url \"http://x\"\nbrowser_click \"#go\"\ncheck_url \"http://x\"\n```"
        self.assertTrue(w._looks_unexecuted(txt, set()))

    def test_detects_ask_to_test_without_verify(self):
        w = self._w()
        self.assertTrue(w._looks_unexecuted("You can test it by visiting http://localhost:5000", set()))
        # but not if it actually verified
        self.assertFalse(w._looks_unexecuted("You can test it by visiting http://localhost:5000",
                                             {"check_url"}))

    def test_clean_verified_answer_not_flagged(self):
        w = self._w()
        self.assertFalse(w._looks_unexecuted("Verified HTTP 200 at /health, it works.",
                                             {"start_server", "check_url"}))
        self.assertFalse(w._looks_unexecuted("2 + 2 = 4.", set()))


class OrchestratorTests(unittest.TestCase):
    class _FakeProvider:
        name = "anthropic"

        def chat(self, model, messages, tools):
            last = messages[-1]["content"]
            if "Break the following goal" in last:
                return {"role": "assistant", "content": '["one","two"]', "tool_calls": []}
            return {"role": "assistant", "content": f"result::{last[:20]}", "tool_calls": []}

    def _reg(self):
        from tools import ToolRegistry
        return ToolRegistry(Path(tempfile.mkdtemp()), lambda *a, **k: True,
                            lambda *a, **k: None, lambda: False,
                            provider=self._FakeProvider(), model="m")

    def test_device_capacity(self):
        out = self._reg().call("device_capacity", {})
        self.assertIn("Recommended agents", out)
        self.assertIn("CPU cores", out)

    def test_parallel_agents_explicit(self):
        out = self._reg().call("run_parallel_agents", {"subtasks": ["X", "Y"]})
        self.assertIn("Subtask 1", out)
        self.assertIn("Subtask 2", out)
        self.assertIn("result::X", out)

    def test_parallel_agents_decompose(self):
        out = self._reg().call("run_parallel_agents", {"goal": "do things"})
        self.assertIn("2 sub-agents", out)

    def test_parallel_agents_needs_input(self):
        out = self._reg().call("run_parallel_agents", {})
        self.assertIn("Provide either", out)

    def test_subagents_cannot_mutate(self):
        # sub-registry must deny approval-gated writes
        sub = self._reg()._build_subregistry()
        self.assertIn("denied", sub.call("run_command", {"command": "echo hi"}).lower())


class BrowserToolTests(unittest.TestCase):
    def setUp(self):
        from tools.browser import BrowserTools
        self.root = Path(tempfile.mkdtemp())
        self.bt = BrowserTools(self.root, lambda *a, **k: True, lambda *a, **k: None)

    def test_reads_without_open_are_graceful(self):
        self.assertIn("No browser", self.bt.call("browser_read_text", {}))
        self.assertIn("No browser", self.bt.call("browser_read_page", {}))

    def test_registry_exposes_browser_tools(self):
        from tools import ToolRegistry
        names = {s["function"]["name"] for s in ToolRegistry.schemas()}
        for t in ("browser_open", "browser_navigate", "browser_click",
                  "browser_fill_form", "browser_screenshot", "browser_close"):
            self.assertIn(t, names)

    def test_live_browser_roundtrip(self):
        from tools.browser import _find_browser, shutdown_browser
        if not _find_browser():
            self.skipTest("no Chrome/Edge installed")
        html = self.root / "f.html"
        html.write_text("<h1>Hi</h1><input id='n' name='n'><button id='b'>B</button>", encoding="utf-8")
        try:
            self.assertIn("Loaded", self.bt.browser_open(html.as_uri(), headless=True))
            self.assertIn("Hi", self.bt.browser_read_text())
            self.assertIn("#n", self.bt.browser_read_page())
            self.assertIn("Filled", self.bt.browser_fill_form({"#n": "x"}))
            self.assertEqual(self.bt._cdp().evaluate("document.querySelector('#n').value"), "x")
        finally:
            shutdown_browser()


class ProviderImageTests(unittest.TestCase):
    def setUp(self):
        import providers
        self.P = providers
        self.msgs = [{"role": "system", "content": "s"},
                     {"role": "user", "content": "q",
                      "images": [{"data": "QUJD", "media_type": "image/png"}]}]

    def test_vision_detection(self):
        self.assertTrue(self.P.model_is_vision("llama3.2-vision"))
        self.assertTrue(self.P.model_is_vision("claude-sonnet-4"))
        self.assertFalse(self.P.model_is_vision("qwen2.5:latest"))

    def test_ollama_image_wire(self):
        w = self.P.OllamaProvider({})._to_wire(self.msgs)
        self.assertEqual(w[1]["images"], ["QUJD"])
        # messages without images carry no images key
        self.assertNotIn("images", self.P.OllamaProvider({})._to_wire(
            [{"role": "user", "content": "hi"}])[0])

    def test_openai_image_wire(self):
        w = self.P.OpenAIProvider({})._to_wire(self.msgs)
        self.assertTrue(w[1]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,QUJD"))

    def test_anthropic_image_wire(self):
        _, w = self.P.AnthropicProvider({})._to_wire_messages(self.msgs)
        self.assertEqual(w[0]["content"][1]["source"]["data"], "QUJD")


class DocAndSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def test_read_document_plain_and_docx(self):
        from tools.docs import DocTools
        import zipfile
        docs = DocTools(self.root, lambda *a, **k: True, lambda *a, **k: None)
        (self.root / "n.md").write_text("# Title\nbody", encoding="utf-8")
        self.assertIn("body", docs.call("read_document", {"path": "n.md"}))
        docx = self.root / "d.docx"
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml",
                       '<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>DocxText</w:t>'
                       '</w:r></w:p></w:body></w:document>')
        self.assertIn("DocxText", docs.call("read_document", {"path": "d.docx"}))

    def test_read_document_missing(self):
        from tools.docs import DocTools
        docs = DocTools(self.root, lambda *a, **k: True, lambda *a, **k: None)
        self.assertIn("not found", docs.call("read_document", {"path": "nope.pdf"}).lower())

    def test_self_test_reports_healthy(self):
        from tools import ToolRegistry
        reg = ToolRegistry(self.root, lambda *a, **k: True, lambda *a, **k: None, lambda: False)
        report = reg.call("self_test", {"verbose": False})
        self.assertIn("Registry integrity: PASS", report)
        self.assertIn("OVERALL: HEALTHY", report)
        self.assertNotIn("HANG", report)


class GitHubPushTests(unittest.TestCase):
    def test_invalid_repo_name_rejected_before_any_network(self):
        from tools import connectors
        out = connectors.push_to_github(".", "bad name!", True)
        self.assertIn("may only contain", out)

    def test_missing_token_gives_actionable_error(self):
        from tools import connectors
        orig = connectors.ConnectorTools._token
        connectors.ConnectorTools._token = lambda self: ""
        try:
            out = connectors.push_to_github(".", "valid-name", True)
        finally:
            connectors.ConnectorTools._token = orig
        self.assertIn("No GitHub token", out)

    def test_github_narration_is_flagged_even_after_git_tools_ran(self):
        # The weak model's placeholder-URL tutorial must be caught for a retry even
        # when some git_* tools already executed this turn.
        from agent_support import looks_unexecuted
        tutorial = ("Set the Remote URL: git remote add origin "
                    "https://github.com/<your-username>/Repo.git\ngit push -u origin main")
        self.assertTrue(looks_unexecuted(tutorial, {"git_init", "git_commit"}))
        # but once it actually pushed, a summary mentioning the url is fine
        self.assertFalse(looks_unexecuted("Pushed to https://github.com/j0E9/Repo",
                                          {"git_init", "git_commit", "git_push"}))

    def test_remote_slug_parses_owner_and_repo(self):
        from tools import connectors
        t = connectors.ConnectorTools.__new__(connectors.ConnectorTools)
        for url, expect in {
            "https://github.com/j0E9/Onyx.git": ("j0E9", "Onyx"),
            "https://github.com/j0E9/Onyx": ("j0E9", "Onyx"),
            "git@github.com:acme/my.repo.git": ("acme", "my.repo"),
        }.items():
            t._git = lambda *a, u=url, **k: (0, u)
            self.assertEqual(t._remote_slug(), expect)

    def test_open_pr_requires_title_and_token(self):
        from tools import connectors
        self.assertIn("title", connectors.open_pull_request(".", "").lower())
        orig = connectors.ConnectorTools._token
        connectors.ConnectorTools._token = lambda self: ""
        try:
            out = connectors.open_pull_request(".", "My change")
        finally:
            connectors.ConnectorTools._token = orig
        self.assertIn("No GitHub token", out)

    def test_open_pr_refuses_when_on_base_branch(self):
        from tools import connectors
        t = connectors.ConnectorTools.__new__(connectors.ConnectorTools)
        t._is_repo = lambda: True
        t._remote_slug = lambda: ("me", "repo")
        t._current_branch = lambda: "main"
        out = t.github_open_pr(title="x", base="main")
        self.assertIn("base branch", out.lower())

    def test_pr_tool_schemas_registered(self):
        from tools import connectors
        names = {s["function"]["name"] for s in connectors.SCHEMAS}
        self.assertTrue({"github_open_pr", "github_pr_status", "github_merge_pr"} <= names)

    def test_fake_pr_claim_is_flagged(self):
        from agent_support import looks_unexecuted
        self.assertTrue(looks_unexecuted("I opened a pull request for your changes.", {"git_commit"}))
        self.assertTrue(looks_unexecuted("The pull request has been merged.", {"git_commit"}))
        self.assertFalse(looks_unexecuted("Opened PR #4: https://github.com/x/y/pull/4",
                                          {"github_open_pr"}))


class SecurityToolTests(unittest.TestCase):
    def setUp(self):
        # not authorized, auto-approve (to prove the gate blocks on authorization alone)
        self.disarmed = SecurityTools(lambda *_: True, lambda _: None, lambda: False)
        self.armed = SecurityTools(lambda *_: True, lambda _: None, lambda: True)

    def test_active_tool_blocked_without_authorization(self):
        out = self.disarmed.call("port_scan", {"host": "127.0.0.1", "ports": "80"})
        self.assertIn("BLOCKED", out)

    def test_local_utilities_need_no_authorization(self):
        self.assertIn("sha256", self.disarmed.call("hash_text", {"text": "hi"}))
        self.assertEqual(self.disarmed.call("encode_decode",
                         {"data": "hi", "scheme": "base64", "operation": "encode"}), "aGk=")
        self.assertIn("entropy", self.disarmed.call("password_strength", {"password": "abc"}))

    def test_identify_hash(self):
        self.assertIn("SHA-256", self.armed.call("identify_hash", {"value": "a" * 64}))


if __name__ == "__main__":
    unittest.main()
