"""Live end-to-end check against a running Ollama (not part of the unit suite).

Usage:  .venv\\Scripts\\python.exe tests\\live_agent_check.py [model] [task-numbers e.g. 1,3]
Runs real tasks in a temp workspace with auto-approval and checks the REAL result
(files on disk, live HTTP responses, command output) - not what the model claims.
"""
import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import config as app_config  # noqa: E402
from app import AgentWorker  # noqa: E402
from providers import build_provider  # noqa: E402
from tools import shutdown_all  # noqa: E402


def _get(url):
    try:
        with urlopen(url, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def _run_py(ws, name):
    p = subprocess.run([sys.executable, name], cwd=ws, capture_output=True, text=True, timeout=30)
    return p.stdout.strip()


def _sh(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True).stdout


def _git_setup(ws, with_remote_change):
    """Workspace repo + a local bare 'remote' standing in for GitHub."""
    g = ["git", "-c", "user.name=t", "-c", "user.email=t@x.invalid"]
    remote = ws.parent / (ws.name + "_remote.git")
    subprocess.run(["git", "init", "--bare", "-b", "main", str(remote)], capture_output=True, check=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=ws, capture_output=True, check=True)
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=ws, capture_output=True, check=True)
    (ws / "README.md").write_text("# demo\n", encoding="utf-8")
    subprocess.run(g + ["add", "-A"], cwd=ws, check=True)
    subprocess.run(g + ["commit", "-m", "init"], cwd=ws, capture_output=True, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=ws, capture_output=True, check=True)
    if with_remote_change:
        other = ws.parent / (ws.name + "_other")
        subprocess.run(["git", "clone", str(remote), str(other)], capture_output=True, check=True)
        (other / "app.py").write_text("print('v2')\n", encoding="utf-8")
        subprocess.run(g + ["add", "-A"], cwd=other, check=True)
        subprocess.run(g + ["commit", "-m", "v2"], cwd=other, capture_output=True, check=True)
        subprocess.run(["git", "push"], cwd=other, capture_output=True, check=True)
    else:
        (ws / "app.py").write_text("print('my work')\n", encoding="utf-8")


TASKS = [
    # (task, setup(ws), check(ws, final_text, tools_used) -> bool)
    ("create hello.py that prints the sum of 2 and 3, then run it",
     None, lambda ws, f, t: _run_py(ws, "hello.py") == "5"),
    ("create index.html with a registration form (name, email, password, submit button), "
     "host it on port 8765 and test that it works",
     None, lambda ws, f, t: _get("http://localhost:8765/")[0] == 200 and "<form" in _get("http://localhost:8765/")[1].lower()),
    ("change calc.py so it prints the product of 6 and 7 instead, then run it to confirm",
     lambda ws: (ws / "calc.py").write_text("a = 6\nb = 7\nprint(a + b)\n", encoding="utf-8"),
     lambda ws, f, t: _run_py(ws, "calc.py") == "42"),
    ("create a Flask API in api.py with a GET /health endpoint that returns JSON {\"status\": \"ok\"}. "
     "Install flask if needed, host it on port 5055 and test /health",
     None, lambda ws, f, t: _get("http://localhost:5055/health")[0] == 200
     and json.loads(_get("http://localhost:5055/health")[1]).get("status") == "ok"),
    ("build a todo list web app with three files: index.html, style.css and app.js (add and delete todos). "
     "Host it on port 8766 and verify it loads",
     None, lambda ws, f, t: all((ws / n).is_file() and (ws / n).stat().st_size > 50 for n in ("index.html", "style.css", "app.js"))
     and _get("http://localhost:8766/")[0] == 200),
    ("check my computer: tell me the OS, CPU, total RAM and the 5 processes using the most memory",
     None, lambda ws, f, t: bool(t & {"system_info", "list_processes", "run_command"})
     and "windows" in f.lower() and ("gb" in f.lower() or "mb" in f.lower())),
    ("commit all my work and push it to git",
     lambda ws: _git_setup(ws, with_remote_change=False),
     lambda ws, f, t: "app.py" in _sh(["git", "--git-dir", str(ws.parent / (ws.name + "_remote.git")),
                                       "ls-tree", "-r", "--name-only", "main"])),
    ("pull the latest changes from git",
     lambda ws: _git_setup(ws, with_remote_change=True),
     lambda ws, f, t: "v2" in (ws / "app.py").read_text(encoding="utf-8")),
    ("MY RDR 2 IS CONTINUOUSLY CRASHING CAN YOU TRACE THE ISSUE",
     None, lambda ws, f, t: "diagnose_crashes" in t and "emp.dll" in f.lower()
     and "text-based" not in f.lower()),
]


def run(task, model, setup):
    ws = Path(tempfile.mkdtemp(prefix="agentlive_"))
    if setup:
        setup(ws)
    provider = build_provider(app_config.load())
    done = threading.Event()
    log, used, final = [], set(), [""]

    def emit(ev):
        t = ev.get("type")
        if t == "approval":
            # Auto-approve is on, so only HIGH-RISK actions reach here. A careful user says no.
            ev["payload"]["approved"] = False
            used.add("HIGH_RISK_ATTEMPT")
            log.append(f"  [harness] DENIED high-risk: {str(ev['payload'].get('detail'))[:150]!r}")
            ev["payload"]["event"].set()
        elif t == "tool_start":
            used.add(ev["name"])
            log.append(f"  -> {ev['name']}({str(ev.get('args'))[:110]})")
        elif t == "tool_result":
            log.append(f"     = {ev['text'][:140]!r}")
        elif t == "assistant_text":
            log.append(f"  [text] {ev['text'][:200]!r}")
        elif t == "log" and any(k in ev["text"] for k in ("Supervisor", "forcing", "Recovered", "garbled", "Using", "step")):
            log.append(f"  [log] {ev['text']}")
        elif t in ("final", "error"):
            final[0] = ev["text"]
            log.append(f"  [{t}] {ev['text'][:900]}")
            done.set()

    t0 = time.time()
    cancel = threading.Event()
    worker = AgentWorker(provider, model, task, ws, emit, cancel, lambda: False,
                         max_steps=20, auto_approve=lambda: True)
    worker.start()
    if not done.wait(2400):
        log.append("  [harness] timed out - cancelling worker")
        cancel.set()
        worker.join(900)  # let the in-flight model request finish so the next task is not queued behind it
    return ws, log, used, final[0], time.time() - t0


if __name__ == "__main__":
    model = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1][0].isdigit() else app_config.load()["ollama_model"]
    pick = next((a for a in sys.argv[1:] if a[0].isdigit()), None)
    idx = [int(x) - 1 for x in pick.split(",")] if pick else range(len(TASKS))
    results = []
    for i in idx:
        task, setup, check = TASKS[i]
        ws, log, used, final, dt = run(task, model, setup)
        try:
            ok = bool(check(ws, final, used)) and "HIGH_RISK_ATTEMPT" not in used
        except Exception as e:  # noqa: BLE001
            ok = False
            log.append(f"  check error: {e}")
        print(f"\n=== [{i + 1}] {task}\n" + "\n".join(log) +
              f"\n  workspace={ws}  REAL_CHECK={'PASS' if ok else 'FAIL'}  {dt:.0f}s", flush=True)
        results.append((i + 1, ok))
        shutdown_all()
    print("\nLIVE RESULT: " + " ".join(f"[{n}]{'PASS' if ok else 'FAIL'}" for n, ok in results)
          + f"  ({sum(ok for _, ok in results)}/{len(results)})")
