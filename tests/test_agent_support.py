import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import agent_support as s  # noqa: E402
from tools import ToolRegistry  # noqa: E402

SCHEMAS = ToolRegistry.schemas()
BY_NAME = {x["function"]["name"]: x["function"] for x in SCHEMAS}
KNOWN = set(BY_NAME)


class ParseTests(unittest.TestCase):
    def test_json_with_raw_newlines_and_nesting(self):
        txt = 'Sure:\n```json\n{"name": "write_file", "arguments": {"path": "a.html", "content": "<html>\n<body>{x}</body></html>"}}\n```'
        calls = s.parse_text_tool_calls(txt, KNOWN, BY_NAME)
        self.assertEqual(calls[0]["function"]["name"], "write_file")
        self.assertIn("<body>", calls[0]["function"]["arguments"]["content"])

    def test_tool_call_tags_multiple(self):
        txt = '<tool_call>{"name":"list_files","arguments":{"path":"."}}</tool_call><tool_call>{"name":"read_file","arguments":{"path":"x"}}</tool_call>'
        self.assertEqual([c["function"]["name"] for c in s.parse_text_tool_calls(txt, KNOWN)], ["list_files", "read_file"])

    def test_python_call_style(self):
        txt = 'write_file("index.html", """<h1>Hi (there)</h1>""")'
        c = s.parse_text_tool_calls(txt, KNOWN, BY_NAME)[0]["function"]
        self.assertEqual(c["arguments"], {"path": "index.html", "content": "<h1>Hi (there)</h1>"})

    def test_shell_style_from_screenshot(self):
        txt = "```\nwrite_file register.html '<!DOCTYPE html>\n<html lang=\"en\"></html>'\n```"
        c = s.parse_text_tool_calls(txt, KNOWN, BY_NAME)[0]["function"]
        self.assertEqual(c["arguments"]["path"], "register.html")
        self.assertTrue(c["arguments"]["content"].startswith("<!DOCTYPE"))

    def test_ignores_unknown_and_plain_json(self):
        self.assertEqual(s.parse_text_tool_calls('{"status": "ok"}', KNOWN), [])


class ArgsTests(unittest.TestCase):
    def test_aliases(self):
        args, err = s.normalize_args("write_file", {"file_path": "a", "text": "b"}, BY_NAME["write_file"])
        self.assertIsNone(err)
        self.assertEqual(args, {"path": "a", "content": "b"})

    def test_missing_is_explained(self):
        _, err = s.normalize_args("run_command", {}, BY_NAME["run_command"])
        self.assertIn("command", err)


class ClassifierTests(unittest.TestCase):
    def test_refusal_from_screenshot(self):
        self.assertTrue(s.looks_refusal("I'm sorry for any confusion, but as a text-based AI, I don't have direct access to your machine"))
        self.assertTrue(s.looks_refusal("I'm sorry, but I can't directly access or view images."))
        self.assertFalse(s.looks_refusal("Created index.html and verified it returns HTTP 200."))

    def test_tell_user_to_test_after_only_starting_server(self):
        txt = "To test the `/health` endpoint, you can use a web browser or a tool like `curl`."
        self.assertTrue(s.looks_unexecuted(txt, {"write_file", "start_server"}))
        self.assertFalse(s.looks_unexecuted("Verified: HTTP 200 {\"status\":\"ok\"}", {"start_server", "check_url"}))

    def test_advice_after_diagnosis_is_not_pushed_to_act(self):
        txt = "Likely cause: EMP.dll.\n```powershell\nGet-Process RDR2 | Stop-Process\n```\nYou can try reinstalling."
        self.assertFalse(s.looks_unexecuted(txt, {"diagnose_crashes"}))

    def test_uninstall_always_needs_human_even_in_auto_mode(self):
        import threading
        import app
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "u.ps1").write_text("$x = Get-WmiObject -Class Win32_Product\n$x.Uninstall()", encoding="utf-8")
            w = app.AgentWorker(None, "m", "t", Path(d), lambda *a: None, threading.Event(), lambda: False)
            w.workspace = Path(d)
            self.assertTrue(w._high_risk("command", "Run this command?\n\npowershell -NoProfile -File u.ps1"))
            self.assertTrue(w._high_risk("command", "winget uninstall Steam"))
            self.assertFalse(w._high_risk("command", "python hello.py"))

    def test_garbled_from_screenshot(self):
        g = "&-'.\"%;=F1/?#';DH$7C#C8;H+-C9E4H.7:1<;!)F7.GG67=A>92;=FA&%HA!/:EC.G5?F4E8+BE&<3C;1%C-$>?>E9E&$F&))&D+:!3H#9B>\"//,#8/)-E)-!#E+\">&E69&,8!;&%,F+7H5?33FG.$13.;:&%</2,A>3+F<5F>FF3ACF'C?+1'/%GC%'649%<"
        self.assertTrue(s.looks_garbled(g))
        self.assertFalse(s.looks_garbled("A normal sentence with words. " * 10))

    def test_select_tools_is_small_but_relevant(self):
        base = s.select_tools(SCHEMAS, "create a hello world page")
        self.assertLess(len(base), 20)
        crash = {x["function"]["name"] for x in s.select_tools(SCHEMAS, "my RDR 2 is continuously crashing")}
        self.assertIn("system_info", crash)


class CompactTests(unittest.TestCase):
    def test_old_tool_output_and_file_bodies_shrink(self):
        msgs = [{"role": "system", "content": "sys"},
                {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "write_file", "arguments": {"path": "a", "content": "x" * 5000}}}]}]
        msgs += [{"role": "tool", "content": "y" * 5000} for _ in range(6)]
        msgs.append({"role": "assistant", "content": "last"})
        s.compact_messages(msgs, keep_recent=2)
        self.assertLess(len(msgs[1]["tool_calls"][0]["function"]["arguments"]["content"]), 200)
        self.assertLess(len(msgs[2]["content"]), 500)
        self.assertEqual(len(msgs[-2]["content"]), 5000)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sup = s.Supervisor(self.root, lambda url: "UNREACHABLE", lambda sid, port: (False, port))

    def tearDown(self):
        self.tmp.cleanup()

    def test_nothing_created_fails(self):
        ok, _, probs = self.sup.review("create a login page", "Here is the code...", set())
        self.assertFalse(ok)
        self.assertTrue(any("nothing was created" in p for p in probs))

    def test_broken_python_fails_good_passes(self):
        (self.root / "bad.py").write_text("def x(:\n", encoding="utf-8")
        (self.root / "ok.py").write_text("print(1)\n", encoding="utf-8")
        self.sup.observe("write_file", {"path": "bad.py"}, "Saved bad.py")
        self.sup.observe("write_file", {"path": "ok.py"}, "Saved ok.py")
        ok, passed, probs = self.sup.review("create scripts", "done", {"write_file"})
        self.assertFalse(ok)
        self.assertTrue(any("bad.py" in p for p in probs))
        self.assertTrue(any("ok.py" in p for p in passed))

    def test_dead_server_and_failed_command(self):
        self.sup.observe("start_server", {"port": 8000}, "Started srv1 (pid 1): x")
        self.sup.observe("run_command", {"command": "python t.py"}, "Exit code: 1\nTraceback")
        ok, _, probs = self.sup.review("host it", "works!", {"start_server", "run_command"})
        self.assertFalse(ok)
        self.assertEqual(len(probs), 2)


class SupervisorStrictTests(unittest.TestCase):
    def test_fake_tool_output_crashed_server_and_requested_port(self):
        with tempfile.TemporaryDirectory() as d:
            sup = s.Supervisor(Path(d), lambda url: "UNREACHABLE - x", lambda sid, port: (False, port))
            sup.observe("start_server", {"command": "flask run --port=5055"},
                        "srv1 exited immediately (code 2).\nOutput:\nError: Could not locate a Flask application")
            fake = "<tool_response>\nREACHABLE - http://localhost:5055/health\n</tool_response>"
            ok, _, probs = sup.review("host it on port 5055 and test /health", fake, {"start_server"})
            self.assertFalse(ok)
            text = " ".join(probs)
            self.assertIn("made-up", text)
            self.assertIn("port 5055", text)
            self.assertIn("crashed on start", text)

    def test_question_answered_into_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "p.txt").write_text("x", encoding="utf-8")
            sup = s.Supervisor(Path(d), lambda url: "UNREACHABLE", lambda sid, port: (False, port))
            sup.observe("write_file", {"path": "p.txt"}, "Saved p.txt")
            ok, _, probs = sup.review("check my computer: tell me the OS and RAM", "Saved to p.txt", {"write_file"})
            self.assertFalse(ok)
            self.assertIn("QUESTION", probs[0])
            ok2, _, _ = sup.review("create a file p.txt with my OS", "done", {"write_file"})
            self.assertTrue(ok2)

    def test_port_parsing(self):
        self.assertEqual(s.port_from_command("python -m http.server 8766"), 8766)
        self.assertEqual(s.port_from_command("flask run --port=5055"), 5055)
        self.assertEqual(s.port_from_command("npx serve -p 3000"), 3000)
        self.assertIsNone(s.port_from_command("python api.py"))
        self.assertEqual(s.requested_ports("Host it on port 8766 and verify"), [8766])


class EditFileTests(unittest.TestCase):
    def test_edit_unique_ambiguous_and_missing(self):
        from tools.workspace import WorkspaceTools
        with tempfile.TemporaryDirectory() as d:
            w = WorkspaceTools(Path(d), lambda *a: True, lambda *_: None)
            (Path(d) / "c.py").write_text("a = 6\nb = 7\nprint(a + b)\nprint(a + b)\n", encoding="utf-8")
            self.assertIn("2 times", w.call("edit_file", {"path": "c.py", "old_string": "print(a + b)", "new_string": "x"}))
            self.assertIn("not found", w.call("edit_file", {"path": "c.py", "old_string": "zzz", "new_string": "x"}))
            self.assertIn("Edited", w.call("edit_file", {"path": "c.py", "old_string": "b = 7", "new_string": "b = 8"}))
            self.assertIn("b = 8", (Path(d) / "c.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
