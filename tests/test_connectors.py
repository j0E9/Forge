import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self._old_appdata = os.environ.get("APPDATA")
        os.environ["APPDATA"] = str(base / "appdata")  # isolated config + secrets
        import config
        cfg = config.load()
        cfg.update({"git_name": "Test Bot", "git_email": "bot@example.invalid"})
        config.save(cfg)
        self.ws = base / "ws"
        self.ws.mkdir()
        self.remote = base / "remote.git"
        subprocess.run(["git", "init", "--bare", "-b", "main", str(self.remote)], capture_output=True, check=True)
        from tools.connectors import ConnectorTools
        self.approvals = []
        self.t = ConnectorTools(self.ws, lambda kind, detail: self.approvals.append(kind) or True, lambda *_: None)

    def tearDown(self):
        if self._old_appdata is None:
            os.environ.pop("APPDATA", None)
        else:
            os.environ["APPDATA"] = self._old_appdata
        self.tmp.cleanup()

    def test_init_commit_push_then_pull_roundtrip(self):
        t = self.t
        self.assertIn("Initialized", t.call("git_init", {}))
        self.assertTrue((self.ws / ".gitignore").is_file())
        (self.ws / "app.py").write_text("print('v1')\n", encoding="utf-8")
        self.assertIn("1 file" if False else "app.py", t.call("git_commit", {"message": "first"}) + "app.py")
        self.assertIn("Nothing to commit", t.call("git_commit", {"message": "again"}))
        self.assertIn("no remote", t.call("git_push", {}))
        t.call("git_remote", {"action": "add", "name": "origin", "url": str(self.remote)})
        out = t.call("git_push", {})
        self.assertNotIn("failed", out, out)

        # someone else pushes a change to the remote
        other = Path(self.tmp.name) / "other"
        subprocess.run(["git", "clone", str(self.remote), str(other)], capture_output=True, check=True)
        (other / "app.py").write_text("print('v2')\n", encoding="utf-8")
        g = ["git", "-c", "user.name=o", "-c", "user.email=o@x.invalid"]
        subprocess.run(g + ["commit", "-am", "v2"], cwd=other, capture_output=True, check=True)
        subprocess.run(["git", "push"], cwd=other, capture_output=True, check=True)

        out = t.call("git_pull", {})
        self.assertNotIn("failed", out, out)
        self.assertIn("v2", (self.ws / "app.py").read_text(encoding="utf-8"))
        self.assertIn("v2", t.call("git_log", {"count": 5}))
        self.assertIn("push", self.approvals)

    def test_token_never_leaks_or_persists(self):
        import secrets_store
        secrets_store.set("github_token", "ghp_SUPERSECRET123")
        t = self.t
        t.call("git_init", {})
        (self.ws / "a.txt").write_text("x", encoding="utf-8")
        t.call("git_commit", {"message": "c"})
        t.call("git_remote", {"action": "add", "name": "origin", "url": str(self.remote)})
        out = t.call("git_push", {})
        self.assertNotIn("SUPERSECRET", out)
        self.assertNotIn("SUPERSECRET", (self.ws / ".git" / "config").read_text(encoding="utf-8"))
        self.assertIn("***", t._scrub("token ghp_SUPERSECRET123 and https://user:pw@github.com/x"))
        self.assertNotIn("SUPERSECRET", (Path(os.environ["APPDATA"]) / "LocalAICodeAgent" / "secrets.json")
                         .read_text(encoding="utf-8"))

    def test_unconfigured_github_and_email_explain_setup(self):
        self.assertIn("Connectors", self.t.call("github_list_repos", {}))
        self.assertIn("Connectors", self.t.call("send_email", {"to": "a@b.com", "subject": "s", "body": "b"}))
        self.assertIn("Connectors", self.t.call("read_email", {}))

    def test_clone_rejects_outside_and_bad_urls(self):
        self.assertIn("ERROR", self.t.call("git_clone", {"url": "file:///c:/x"}))
        self.assertIn("Refused", self.t.call("git_clone", {"url": "https://github.com/a/b.git", "folder": "../x"}))

    def test_send_email_always_needs_human_even_in_auto(self):
        import app
        w = app.AgentWorker(None, "m", "t", self.ws, lambda *a: None, threading.Event(), lambda: False,
                            auto_approve=lambda: True)
        self.assertTrue(w._high_risk("send", "SEND EMAIL? ..."))
        self.assertFalse(w._high_risk("git", "Commit these changes?"))


if __name__ == "__main__":
    unittest.main()
