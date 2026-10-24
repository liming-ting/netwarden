"""
Stage K: shutdown and restart. Ctrl+C / SIGTERM stops the loops, the warm-up thread,
the live streams and the sockets within a few seconds, without half-written data; a
restart on the same database picks up where it left off (the user's notes, the quiet
hours ledger, a live stream that reconnects with an old event id gets `resync`).
Everything on 127.0.0.1 with a private demo copy and the offline AI.
"""
import http.client
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from netwarden import brain, demo, runner, store, web

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LoopShutdownTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "l.db"
        store.connect(self.path).close()

    def test_a_job_in_flight_finishes_its_transaction(self):
        """stop() during a write: the job's transaction is either fully there or not at
        all - here it finishes (the loop checks the stop flag only between runs)."""
        started = threading.Event()

        def job(db):
            with db:
                for i in range(50):
                    db.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                               "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                               (f"k{i}", str(i)))
                    if i == 10:
                        started.set()
                        time.sleep(0.3)
        run = runner.Runner(self.path, {}, jobs={"x": (60, job)}).start()
        self.assertTrue(started.wait(5))
        t0 = time.monotonic()
        run.stop(timeout=2.0)
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertFalse(run.loops["x"].thread.is_alive())
        db = store.connect(self.path)
        n = db.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'k%'").fetchone()[0]
        self.assertEqual(n, 50)
        self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        db.close()

    def test_a_stuck_job_does_not_hold_shutdown(self):
        gate = threading.Event()
        run = runner.Runner(self.path, {}, jobs={"slow": (60, lambda db: gate.wait(30))}).start()
        time.sleep(0.2)
        t0 = time.monotonic()
        run.stop(timeout=0.5)
        self.assertLess(time.monotonic() - t0, 1.5)      # left behind as a daemon
        gate.set()

    def test_warmer_stop_waits_for_its_pass(self):
        w = runner.Warmer(self.path, 24, {}).start()
        time.sleep(0.2)
        t0 = time.monotonic()
        w.stop(timeout=5)
        self.assertFalse(w.thread.is_alive())
        self.assertLess(time.monotonic() - t0, 5)


class StreamRestartTests(unittest.TestCase):
    def test_reconnect_after_restart_gets_resync(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "s.db"
        store.connect(path).close()

        def hello(port, last=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/api/stream", headers={"last-event-id": last} if last else {})
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            seen = []
            while not any(x.startswith("event: hello") for x in seen):
                seen.append(r.fp.readline().decode().strip())
            c.close()
            return seen

        ids = []
        for _restart in range(2):
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            lines = hello(srv.server_address[1], ids[-1] if ids else None)
            ids.append(next(x for x in lines if x.startswith("id: "))[4:])
            if len(ids) == 2:
                self.assertIn("event: resync", lines)    # the old process's id: start fresh
            srv.shutdown()
            web.close_server(srv)
        self.assertNotEqual(ids[0].split("-")[0], ids[1].split("-")[0])   # a new epoch


@unittest.skipUnless(hasattr(signal, "SIGTERM") and os.name == "posix", "POSIX signals")
class ProcessTests(unittest.TestCase):
    """The real `python3 -m netwarden run` in a child process."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "p.db"
        demo.build(self.path)

    def start(self, port):
        proc = subprocess.Popen(
            [sys.executable, "-m", "netwarden", "run", "--db", str(self.path), "--port", str(port),
             "--offline-ai", "--no-loops", "--lang", "en"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "NETWARDEN_LANG": "en", "PYTHONUNBUFFERED": "1"})
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                c.request("GET", "/api/meta")
                if c.getresponse().status == 200:
                    c.close()
                    return proc
            except OSError:
                time.sleep(0.2)
        self.fail("server did not come up")

    def post_label(self, port, label):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        db = store.connect(self.path)
        mac = db.execute("SELECT mac FROM devices ORDER BY mac LIMIT 1").fetchone()[0]
        db.close()
        c.request("POST", "/api/label", json.dumps({"mac": mac, "label": label}),
                  {"content-type": "application/json"})
        self.assertEqual(c.getresponse().status, 200)
        c.close()
        return mac

    def test_sigterm_stops_cleanly_and_a_restart_resumes(self):
        port = free_port()
        proc = self.start(port)
        mac = self.post_label(port, "Before restart")
        # an open live stream must not keep the process alive
        stream = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        stream.request("GET", "/api/stream")
        self.assertEqual(stream.getresponse().status, 200)
        t0 = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=15)
        self.assertLess(time.monotonic() - t0, 8)
        self.assertEqual(proc.returncode, 0, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("stopped", out.lower())
        stream.close()
        db = sqlite3.connect(self.path)
        self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        db.close()
        proc = self.start(port)                         # same DB, same port: resumes
        db = store.connect(self.path)
        self.assertEqual(store.get_labels(db)[mac]["label"], "Before restart")
        db.close()
        proc.send_signal(signal.SIGINT)                 # Ctrl+C
        _out, err = proc.communicate(timeout=15)
        self.assertEqual(proc.returncode, 0, err)
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
