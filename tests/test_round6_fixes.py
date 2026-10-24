"""Round 6 fix stage: regressions for the pre-release review findings.

- a loopback request through a reverse proxy is never "this computer" (forwarding
  headers; with an advertised URL the Host header is not trusted - test_round6_d)
- store.connect refuses a "file:" URI instead of creating a "file:/..." folder tree
- NETWARDEN_HOST=::1 is loopback, not a "public address"
- the Linux installer's CLI wrapper reads the env file literally (like systemd), and
  --dry-run says that nothing was installed
- the container workflow pushes only after the smoke test, never moves `latest` onto a
  pre-release, and checks out without persisted credentials; the Dockerfile's own
  host-networking example does not listen on every host interface
"""
import http.client
import os
import runpy
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from netwarden import brain, headless, store, web

ROOT = Path(__file__).resolve().parent.parent


class ForwardedLoopbackIsNotLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        path = str(Path(cls.tmp.name) / "f.db")
        store.connect(path).close()
        cls.srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()

    def get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_plain_loopback_is_this_computer(self):
        self.assertEqual(self.get("/api/settings"), 200)

    def test_a_forwarding_header_makes_it_another_device(self):
        for h in web.FORWARDED_HEADERS:
            value = "for=192.168.1.50" if h == "forwarded" else "192.168.1.50"
            self.assertEqual(self.get("/api/settings", {h: value}), 401, h)
        self.assertEqual(self.get("/healthz", {"x-forwarded-for": "192.168.1.50"}), 200)


class AdvertisedProxyServer(unittest.TestCase):
    def test_make_server_with_an_advertised_proxy_host_trusts_no_loopback_host(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / "adv.db")
        env = {brain.OFFLINE_ENV: "1", "NETWARDEN_ADVERTISED_URL": "https://nw.example"}
        # LAN mode faked on a loopback "LAN" address (never a real LAN bind)
        with mock.patch.object(web.pairing, "is_lan_ip", lambda ip: True):
            srv = web.make_server(path, 0, env, "en", lan=True, lan_host="127.0.0.2")
        try:
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            port = srv.server_address[1]
            self.assertTrue(web.Handler.proxy_hosts)
            for host in (f"127.0.0.1:{port}", f"localhost:{port}", "nw.example"):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                c.request("GET", "/api/settings", headers={"host": host})
                r = c.getresponse()
                r.read()
                c.close()
                self.assertEqual(r.status, 401, host)
        finally:
            srv.shutdown()
            web.close_server(srv)
            web.Handler.lan, web.Handler.lan_url = False, ""
            web.Handler.lan_hosts = web.Handler.proxy_hosts = web.Handler.lan_origins = frozenset()


class StoreRefusesFileUri(unittest.TestCase):
    def test_file_uri_is_refused_and_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                for uri in ("file:/tmp/x/data/n.db", "FILE:n.db", "file:///tmp/n.db"):
                    with self.assertRaises(store.DBError) as cm:
                        store.connect(uri)
                    self.assertEqual(cm.exception.kind, "unreadable")
                self.assertEqual(os.listdir(tmp), [])
            finally:
                os.chdir(cwd)


class Ipv6Loopback(unittest.TestCase):
    def test_ipv6_loopback_is_this_machine_only(self):
        self.assertEqual(headless.listen({"NETWARDEN_HOST": "::1"}),
                         {"lan": False, "lan_host": None, "bind_all": False})
        with self.assertRaises(headless.ListenError) as cm:
            headless.listen({"NETWARDEN_HOST": "2001:db8::1"})
        self.assertEqual(cm.exception.code, "public_host")


@unittest.skipUnless(shutil.which("sh") and os.name == "posix", "needs a POSIX shell")
class InstallerWrapper(unittest.TestCase):
    SCRIPT = str(ROOT / "scripts" / "install_linux.sh")

    def sh(self, *args):
        env = dict(os.environ, PYTHON=shutil.which("python3") or "/usr/bin/python3")
        p = subprocess.run(["sh", self.SCRIPT, *args], capture_output=True, text=True,
                           timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p.stdout

    def test_env_file_values_are_literal_like_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.sh("--root", tmp)
            wrapper = Path(tmp) / "usr/local/bin/netwarden"
            env_file = Path(tmp) / "etc/netwarden/netwarden.env"
            canary = Path(tmp) / "ran"
            env_file.write_text(
                "# comment\n; also a comment\n"
                f"ADGUARD_PASS=a b $HOME `touch {canary}` $(touch {canary})\n"
                "PIHOLE_PASSWORD=\"quoted value\"\n"
                "NTOPNG_PASS='single'\n"
                "not a line\n=novalue\n1BAD=x\n")
            ns = runpy.run_path(str(wrapper), run_name="netwarden_wrapper")
            self.assertEqual(ns["ENV_FILE"], str(env_file))
            got = ns["read_env_file"](str(env_file))
            self.assertEqual(got, {
                "ADGUARD_PASS": f"a b $HOME `touch {canary}` $(touch {canary})",
                "PIHOLE_PASSWORD": "quoted value", "NTOPNG_PASS": "single"})
            self.assertEqual(ns["read_env_file"](str(Path(tmp) / "missing")), {})
            # the real wrapper runs a command with such a file without any shell expansion
            p = subprocess.run([str(wrapper), "--version"], capture_output=True, text=True,
                               timeout=60, env={"PATH": os.environ.get("PATH", "")})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(canary.exists())

    def test_dry_run_says_nothing_was_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.sh("--dry-run", "--root", str(Path(tmp) / "r"))
            self.assertIn("Dry run done", out)
            self.assertNotIn("Started.", out)
            self.assertNotIn("\nDone.", out)
            self.assertIn("Dry run done", self.sh("--dry-run", "--uninstall", "--root", tmp))


class ContainerFiles(unittest.TestCase):
    def test_release_waits_for_the_smoke_test(self):
        wf = (ROOT / ".github" / "workflows" / "docker.yml").read_text()
        release = wf.split("\n  release:\n", 1)[1]
        self.assertRegex(release, r"needs: \[smoke, tests\]")   # round 8: + unit tests on tags
        smoke = wf.split("\n  smoke:\n", 1)[1].split("\n  tests:", 1)[0].split("\n  release:", 1)[0]
        self.assertNotIn("refs/tags", smoke)              # a tag runs the smoke test too
        self.assertNotIn("type=raw,value=latest", wf)
        self.assertIn("latest=auto", wf)
        checkouts = wf.count("uses: actions/checkout@")
        self.assertEqual(wf.count("persist-credentials: false"), checkouts)

    def test_dockerfile_host_network_example_stays_on_loopback_plus_lan(self):
        header = (ROOT / "Dockerfile").read_text().split("FROM ", 1)[0]
        example = header.split("docker run", 1)[1].split("docker logs", 1)[0]
        self.assertIn("--network host", example)
        self.assertIn("NETWARDEN_HOST=127.0.0.1", example)
        self.assertIn("NETWARDEN_LAN=1", example)


if __name__ == "__main__":
    unittest.main()
