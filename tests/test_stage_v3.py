"""
Stage V3: verification follow-ups after round 3.

- bandwidth math: the streaming summary == a straightforward reference; the cheap
  bandwidth_days_floor() never exceeds bandwidth_days() (resets, two IPs, gaps); the
  demo's data spike is still found
- cache: batch() reuses one fingerprint until the connection writes; a result being
  recomputed by another thread is served stale - but never after a user edit
- runner.warm() covers the inbox, suggestions and score (no misses afterwards)
- redaction of household IPv6 (EUI-64 / link-local / ULA), public v6 and times kept
- wslnet: WSL detection, the Hyper-V firewall commands, /api/pair/sessions, CLI lines
- `pair --local` wording, the weekly digest's language from the setting
- identification's unicast round against fake responders on 127.0.0.1: mDNS (incl. a
  hostname-only reverse answer), SSDP, NetBIOS node status (hostile / truncated input),
  reverse DNS with a deadline, resolver_is_local, run_recorded's summary, the calm
  status hint, NetBIOS names in identity_names / best
"""
import contextlib
import io
import json
import random
import socket
import struct
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, brain, cache, demo, health, i18n, identify,
                       inbox, redact, runner, score, settings, store, suggestions, web, wslnet)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
PC = next(d["mac"] for d in demo.DEVICES if d["hostname"] == "DESKTOP-7Q2K9LM")
_private = identify.private_ip


def _iso(dt):
    return dt.strftime(ISO)


def loopback_ok(ip):
    return str(ip).startswith("127.") or _private(ip)


def dev(db, ip, mac, hostname="", is_self=False):
    store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": "", "hostname": hostname,
                             "randomized": False, "is_self": is_self})


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class TmpDir(unittest.TestCase):
    def setUp(self):
        cache.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(cache.clear)


# --- bandwidth -------------------------------------------------------------------------

def reference_totals(rows, since):
    """Per key: sum of per-(key, ip) deltas (resets count as the new value) for samples
    at/after `since`, each series' last sample in the day before `since` as baseline."""
    fmt_since = since
    out, prev = {}, {}
    for r in sorted(rows, key=lambda r: r["ts"]):
        key = r["mac"] or "ip:" + r["ip"]
        sk = (key, r["ip"])
        p = prev.get(sk)
        prev[sk] = r
        if r["ts"] < fmt_since or p is None:
            continue
        d = []
        for f in ("rx_bytes", "tx_bytes"):
            d.append(r[f] - p[f] if r[f] >= p[f] else r[f])
        t = out.setdefault(key, [0, 0])
        t[0] += d[0]
        t[1] += d[1]
    return out


class BandwidthTests(TmpDir):
    def random_rows(self, now, seed):
        rng = random.Random(seed)
        rows = []
        for mac, ips in (("aa", ["10.0.0.2", "fe80::2"]), ("bb", ["10.0.0.3"]), (None, ["10.0.0.9"])):
            for ip in ips:
                rx = tx = 0
                h = 9 * 24
                while h > 0:
                    h -= rng.choice((0.5, 1, 3, 7, 26))      # gaps, sometimes a missing day
                    if rng.random() < 0.05:
                        rx, tx = rng.randrange(1000), 0      # counter reset
                    else:
                        rx += rng.randrange(10 ** 7)
                        tx += rng.randrange(10 ** 6)
                    rows.append({"mac": mac, "ip": ip, "ts": _iso(now - timedelta(hours=h)),
                                 "rx_bytes": rx, "tx_bytes": tx})
        return rows

    def test_summary_totals_match_a_reference(self):
        now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        for seed in range(3):
            db = store.connect(":memory:")
            rows = self.random_rows(now, seed)
            store.insert_traffic_samples(db, rows)
            for hours in (1, 24, 7 * 24):
                since = _iso(now - timedelta(hours=hours))
                # the summary only looks one day back for a baseline: so does the reference
                ref = reference_totals([r for r in rows if r["ts"] >= _iso(
                    now - timedelta(hours=hours + 24))], since)
                got = store.bandwidth_summary(db, since)
                for key, (rx, tx) in ref.items():
                    self.assertEqual((got[key]["rx_bytes"], got[key]["tx_bytes"]), (rx, tx),
                                     (seed, hours, key))
            db.close()

    def test_floor_never_exceeds_the_exact_days(self):
        now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        for seed in range(6):
            db = store.connect(":memory:")
            store.insert_traffic_samples(db, self.random_rows(now, seed))
            for mac in ("aa", "bb", "zz"):
                exact = store.bandwidth_days(db, mac, now)
                floor = store.bandwidth_days_floor(db, mac, now)
                self.assertEqual(len(exact), len(floor))
                for e, f in zip(exact, floor):
                    self.assertLessEqual(f, e or 0, (seed, mac, exact, floor))
            db.close()
        self.assertEqual(store.bandwidth_days_floor(store.connect(":memory:"), "aa", now), [0] * 8)

    def test_floor_is_tight_on_a_steady_counter(self):
        db = store.connect(":memory:")
        now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        rows = [{"mac": "aa", "ip": "10.0.0.2", "ts": _iso(now - timedelta(hours=h)),
                 "rx_bytes": (240 - h) * 1000, "tx_bytes": 0} for h in range(216, -1, -1)]
        store.insert_traffic_samples(db, rows)
        self.assertEqual(store.bandwidth_days_floor(db, "aa", now), store.bandwidth_days(db, "aa", now))

    def test_demo_spike_still_found(self):
        path = Path(self.tmp.name) / "demo.db"
        demo.build(path)
        db = store.connect(path)
        try:
            spikes = alerts.bandwidth_spikes(db, 24)
            self.assertIn(PC, [s["mac"] for s in spikes])
            self.assertEqual(alerts.bandwidth_spikes(db, 24), spikes)        # memoized copy
            self.assertTrue(alerts._is_spike(12e9, 1e9))
            self.assertFalse(alerts._is_spike(3e9, 1e9))                    # +2 GB but < 4x
            self.assertFalse(alerts._is_spike(1.5e9, 0))                    # 4x but < 2 GB
            self.assertEqual(alerts._median([1, 2, 3]), 2)                  # takes sorted values
        finally:
            db.close()


# --- cache -----------------------------------------------------------------------------

class CacheTests(TmpDir):
    def setUp(self):
        super().setUp()
        self.path = Path(self.tmp.name) / "c.db"
        self.db = store.connect(self.path)
        self.addCleanup(self.db.close)

    def test_batch_reuses_the_fingerprint_until_a_write(self):
        calls = []
        real = self.db.execute

        class Spy:
            total_changes = property(lambda s: self.db.total_changes)

            def execute(s, sql, *a):
                calls.append(sql == cache.FINGERPRINT_SQL)
                return real(sql, *a)
        spy = Spy()
        with cache.batch():
            fp1 = cache.fingerprint(spy)
            fp2 = cache.fingerprint(spy)
            self.assertEqual(fp1, fp2)
            self.assertEqual(sum(calls), 1)
            dev(self.db, "192.168.1.5", "aa:bb:cc:00:00:05")
            fp3 = cache.fingerprint(spy)
            self.assertEqual(sum(calls), 2)
            self.assertNotEqual(fp1, fp3)
        cache.fingerprint(spy)
        cache.fingerprint(spy)
        self.assertEqual(sum(calls), 4)                 # outside batch(): every time

    def _busy(self, name):
        """Hold the key's lock as if another thread were recomputing it."""
        key = (cache.db_file(self.db), name, ())
        with cache._lock:
            lk = cache._key_locks.setdefault(key, threading.Lock())
        lk.acquire()
        self.addCleanup(lambda: lk.locked() and lk.release())
        return lk

    def test_stale_served_while_another_thread_recomputes(self):
        self.assertEqual(cache.memo(self.db, "t.x", (), lambda: 1), 1)
        dev(self.db, "192.168.1.6", "aa:bb:cc:00:00:06")       # new data, no user edit
        lk = self._busy("t.x")
        before = cache.stats["stale"]
        self.assertEqual(cache.memo(self.db, "t.x", (), lambda: 2), 1)   # no wait, old value
        self.assertEqual(cache.stats["stale"], before + 1)
        lk.release()
        self.assertEqual(cache.memo(self.db, "t.x", (), lambda: 3), 3)   # data changed: fresh

    def test_never_stale_after_a_user_edit(self):
        cache.memo(self.db, "t.y", (), lambda: "old")
        store.set_label(self.db, "aa:bb:cc:00:00:07", "Kitchen")      # a user note
        lk = self._busy("t.y")
        got = []
        def other():
            db = store.connect(self.path)
            try:
                got.append(cache.memo(db, "t.y", (), lambda: "new"))
            finally:
                db.close()
        t = threading.Thread(target=other)
        t.start()
        time.sleep(0.2)
        self.assertEqual(got, [])                         # waits instead of serving "old"
        lk.release()
        t.join(5)
        self.assertEqual(got, ["new"])


class EnvFileTests(TmpDir):
    def test_default_file_read_at_most_every_ttl_and_env_vars_still_win(self):
        p = Path(self.tmp.name) / "env"
        p.write_text("NETWARDEN_TZ=Asia/Taipei\n")
        reads = []
        real = brain._read_env_file
        with mock.patch.object(brain, "ENV_FILE", p), \
                mock.patch.object(brain, "_env_file_cache", {}), \
                mock.patch.object(brain, "_read_env_file", lambda x: reads.append(x) or real(x)), \
                mock.patch.dict("os.environ", {}, clear=False):
            import os
            os.environ.pop("NETWARDEN_TZ", None)
            for _ in range(20):
                self.assertEqual(brain.load_env(p)["NETWARDEN_TZ"], "Asia/Taipei")
            self.assertEqual(len(reads), 1)
            os.environ["NETWARDEN_TZ"] = "Europe/Berlin"           # a real env var: at once
            self.assertEqual(brain.load_env(p)["NETWARDEN_TZ"], "Europe/Berlin")
            env = brain.load_env(p)
            env["X"] = "1"                                        # callers get copies
            self.assertNotIn("X", brain.load_env(p))
            with mock.patch.object(brain, "ENV_FILE_TTL", 0.0):
                brain.load_env(p)
            self.assertEqual(len(reads), 2)
            other = Path(self.tmp.name) / "other"
            other.write_text("A=1\n")
            brain.load_env(other)
            brain.load_env(other)
            self.assertEqual(reads.count(other), 2)                # explicit paths: always read


class StaticCacheTests(TmpDir):
    def test_page_files_are_cached_and_revalidated(self):
        d = Path(self.tmp.name) / "static"
        d.mkdir()
        f = d / "x.js"
        f.write_text("one")
        with mock.patch.object(web, "STATIC_DIR", d), mock.patch.object(web, "_static_cache", {}):
            self.assertEqual(web.static_file("x.js")[0], b"one")
            f.write_text("two!")
            self.assertEqual(web.static_file("x.js")[0], b"one")      # within STATIC_RECHECK
            with mock.patch.object(web, "STATIC_RECHECK", 0.0):
                self.assertEqual(web.static_file("x.js")[0], b"two!")
                f.unlink()
                self.assertIsNone(web.static_file("x.js"))
            for bad in ("../x.js", ".env", "x.py", ""):
                self.assertIsNone(web.static_file(bad), bad)
        v = web.asset_version()
        self.assertEqual(web.asset_version(), v)
        self.assertRegex(v, r"^[0-9a-f]{12}$")


class WarmTests(TmpDir):
    def test_warm_covers_inbox_suggestions_and_score(self):
        path = Path(self.tmp.name) / "demo.db"
        demo.build(path)
        db = store.connect(path)
        try:
            env = {brain.OFFLINE_ENV: "1"}
            runner.warm(db, env=env)
            misses = cache.stats["misses"]
            with cache.batch():
                inbox.report(db, "en", env)
                suggestions.detect(db, env)
                score.compute(db, env)
                brain.snapshot(db, hours=24)
                alerts.compute(db, recent_hours=24)
            self.assertEqual(cache.stats["misses"], misses)
        finally:
            db.close()


# --- redaction ---------------------------------------------------------------------------

class RedactIPv6Tests(unittest.TestCase):
    def test_household_v6(self):
        hv = redact.household_ipv6
        self.assertTrue(hv("fe80::1c2b:3cff:fe4d:5e6f"))
        self.assertTrue(hv("fe80::1%eth0"))
        self.assertTrue(hv("fd12:3456:789a::5"))
        self.assertTrue(hv("2a01:4f8:1:2:021a:2bff:fe3c:4d5e"))      # EUI-64 in a global prefix
        self.assertFalse(hv("2001:4860:4860::8888"))                  # public resolver
        self.assertFalse(hv("2a01:4f8:1:2:a1b2:c3d4:e5f6:789"))       # privacy-extension address
        self.assertFalse(hv("::"))
        self.assertFalse(hv("not an address"))

    def test_redact_text(self):
        r = redact.Redactor()
        text = ("phone fe80::1c2b:3cff:fe4d:5e6f: online at 12:30:45, "
                "global 2a01:4f8:1:2:021a:2bff:fe3c:4d5e, dns 2001:4860:4860::8888, ula fd00::7")
        out = r.redact(text)
        for leak in ("fe80::1c2b", "fe3c:4d5e", "fd00::7"):
            self.assertNotIn(leak, out)
        self.assertIn("2001:4860:4860::8888", out)
        self.assertIn("12:30:45", out)
        self.assertIn(": online", out)                   # the trailing colon stays text
        self.assertEqual(r.unredact(out), text)


# --- WSL -------------------------------------------------------------------------------

class WslTests(TmpDir):
    def proc(self, text):
        p = Path(self.tmp.name) / "version"
        p.write_text(text)
        return p

    def test_detection_and_commands(self):
        self.assertTrue(wslnet.is_wsl(self.proc("Linux version 5.15.153.1-microsoft-standard-WSL2")))
        self.assertFalse(wslnet.is_wsl(self.proc("Linux version 6.8.0-45-generic")))
        self.assertFalse(wslnet.is_wsl(Path(self.tmp.name) / "missing"))
        c = wslnet.firewall_commands(8787, "192.168.1.13", "192.168.1.0/24")
        self.assertEqual(c["allow"],
                         'New-NetFirewallHyperVRule -Name "netwarden-lan-8787" -DisplayName '
                         '"netwarden (port 8787)" -Direction Inbound -VMCreatorId '
                         "'{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts 8787 "
                         "-RemoteAddresses 192.168.1.0/24")
        self.assertEqual(c["remove"], 'Remove-NetFirewallHyperVRule -Name "netwarden-lan-8787"')
        self.assertEqual(wslnet.firewall_commands(80, "192.168.5.9")["subnet"], "192.168.5.0/24")
        self.assertIsNone(wslnet.firewall_commands(80, "8.8.8.8", "8.8.8.0/24")["subnet"])
        self.assertEqual(wslnet.firewall_commands(80, "192.168.1.13", "10.2.0.0/16")["subnet"],
                         "192.168.1.0/24")          # a network the address isn't in: /24 fallback
        self.assertNotIn("RemoteAddresses", wslnet.firewall_commands(80, "x;rm")["allow"])
        for bad in (0, 70000, "8787; Stop-Computer"):
            with self.assertRaises(ValueError):
                wslnet.firewall_commands(bad)
        self.assertIsNone(wslnet.advice(8787, proc_version=self.proc("generic")))

    def test_lan_address_skips_the_wsl_dns_tunnel(self):
        from netwarden import discovery, pairing
        with mock.patch.object(discovery, "default_iface_net_ip",
                               lambda: ("eth0", None, "192.168.1.13")):
            self.assertEqual(pairing.lan_address(), "192.168.1.13")

        class Sock:     # the probe "route" answers with the target itself: a local address
            def __init__(s, *a):
                s.t = None

            def connect(s, addr):
                s.t = addr[0]

            def getsockname(s):
                return (s.t, 0)

            def close(s):
                pass
        with mock.patch.object(discovery, "default_iface_net_ip", lambda: (None, None, None)), \
                mock.patch.object(pairing.socket, "socket", Sock):
            self.assertIsNone(pairing.lan_address())    # the target itself = a local address

    def test_cli_lines_localized(self):
        p = self.proc("microsoft-standard-WSL2")
        for lang in ("en", "zh-Hant", "ja"):
            lines = wslnet.cli_lines(lang, 8788, "192.168.1.13", None, proc_version=p)
            self.assertEqual(len(lines), 5)
            self.assertIn("8788", lines[0])
            self.assertTrue(lines[2].strip().startswith("New-NetFirewallHyperVRule"))
            self.assertEqual(lines[0], i18n.t("cli.wsl.firewall", lang, port=8788))
        self.assertEqual(wslnet.cli_lines("en", 8788, proc_version=self.proc("x")), [])

    def test_pair_sessions_carries_the_rule(self):
        path = str(Path(self.tmp.name) / "w.db")
        store.connect(path).close()
        srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), web.close_server(srv)))
        import http.client
        port = srv.server_address[1]

        def get():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/api/pair/sessions")
            r = c.getresponse()
            body = json.loads(r.read())
            c.close()
            return r.status, body
        with mock.patch.object(wslnet, "is_wsl", lambda pv=None: True):
            st, j = get()
        self.assertEqual(st, 200)
        self.assertIn(f"-LocalPorts {port}", j["wsl_firewall"]["allow"])
        self.assertTrue(j["wsl_firewall"]["remove"].startswith("Remove-NetFirewallHyperVRule"))
        with mock.patch.object(wslnet, "is_wsl", lambda pv=None: False):
            self.assertIsNone(get()[1]["wsl_firewall"])


# --- CLI wording / digest language ------------------------------------------------------

class CliTests(TmpDir):
    def test_pair_local_has_no_qr_and_says_so(self):
        path = str(Path(self.tmp.name) / "p.db")
        store.connect(path).close()
        code, out, _ = run_cli("pair", "--local", "--db", path, "--lang", "en")
        self.assertEqual(code, 0)
        self.assertNotIn("█", out)
        self.assertIn("127.0.0.1", out)
        self.assertIn("without --local", out)

    def test_digest_language_follows_the_setting(self):
        path = str(Path(self.tmp.name) / "d.db")
        demo.build(path)
        db = store.connect(path)
        try:
            with mock.patch.object(brain, "load_env", lambda *a, **k: {}):
                self.assertEqual(alerts.digest_language(db), "zh-Hant")   # the default
                settings.update(db, {}, {"ui.language": "de"})
                self.assertEqual(alerts.digest_language(db), "de")
        finally:
            db.close()
        with mock.patch.object(brain, "load_env", lambda *a, **k: {}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                alerts.main(["--db", path])
            de = out.getvalue()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                alerts.main(["--db", path, "--lang", "en"])
        self.assertNotEqual(de, out.getvalue())


# --- identification: unicast round --------------------------------------------------------

def dname(n):
    return b"".join(bytes([len(p.encode())]) + p.encode() for p in n.split(".")) + b"\0"


def rr(name_bytes, rtype, rdata):
    return name_bytes + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def reverse_answer(ip, host):
    head = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    return head + rr(dname(identify.reverse_name(ip)), identify.T_PTR, dname(host))


def nbstat_reply(txid, names, mac=b"\x00\x1a\x2b\x3c\x4d\x5e", count=None):
    raw = b"*" + b"\0" * 15
    enc = bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    rdata = bytes([len(names) if count is None else count])
    for label, suffix, group in names:
        rdata += label.encode().ljust(15, b" ") + bytes([suffix]) + struct.pack(
            "!H", 0x8400 if group else 0x0400)
    rdata += mac + b"\0" * 40
    return (struct.pack("!HHHHHH", txid, 0x8400, 0, 1, 0, 0) + b"\x20" + enc + b"\0"
            + struct.pack("!HHIH", identify.NB_STAT, 1, 0, len(rdata)) + rdata)


def udp_responder(reply):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.2)
    stop = threading.Event()
    got = []

    def loop():
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(9000)
            except OSError:
                continue
            got.append(data)
            for out in reply(data):
                s.sendto(out, addr)
    threading.Thread(target=loop, daemon=True).start()
    return s, stop, got


class UnicastTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(identify, "private_ip", loopback_ok)
        p.start()
        self.addCleanup(p.stop)

    def responder(self, reply):
        s, stop, got = udp_responder(reply)
        self.addCleanup(lambda: (stop.set(), s.close()))
        return s.getsockname()[1], got

    def test_wire_helpers(self):
        self.assertEqual(identify.reverse_name("192.168.1.13"), "13.1.168.192.in-addr.arpa")
        self.assertEqual(identify.unicast_targets(["192.168.1.5", "8.8.8.8", "192.168.1.5", "", None,
                                                   "192.168.0.2"]), ["192.168.1.5", "192.168.0.2"])
        self.assertEqual(len(identify.unicast_targets([f"10.1.{i // 250}.{i % 250 + 1}"
                                                       for i in range(400)])), 256)
        m = identify.build_msearch("ssdp:all", host="192.168.1.5:1900").decode()
        self.assertIn("HOST: 192.168.1.5:1900\r\n", m)
        self.assertNotIn("MX:", m)
        self.assertIn("MX: 2", identify.build_msearch().decode())

    def test_hostname_only_mdns(self):
        recs = identify.parse_message(reverse_answer("192.168.1.20", "Living-Room-iPad.local"))
        info = identify.interpret_mdns(recs)
        self.assertEqual(info["name"], "Living-Room-iPad")
        self.assertEqual(info["kind"], "tablet")

    def test_unicast_mdns(self):
        port, got = self.responder(lambda d: [reverse_answer("127.0.0.1", "nas-box.local")]
                                   if b"in-addr" in d else [])
        res = identify.mdns_browse(0.5, dest=None, targets=["127.0.0.1", "8.8.8.8"], port=port)
        self.assertEqual(res["127.0.0.1"]["name"], "nas-box")
        self.assertEqual(len(got), 2)                       # services + reverse; 8.8.8.8 never asked
        self.assertTrue(any(b"_googlecast" in g for g in got))

    def test_unicast_ssdp(self):
        reply = b"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1/d.xml\r\nST: upnp:rootdevice\r\n\r\n"
        port, got = self.responder(lambda d: [reply] if d.startswith(b"M-SEARCH") else [])
        found = identify.ssdp_search(0.5, dest=None, targets=["127.0.0.1"], gateway="127.0.0.1",
                                     port=port)
        self.assertIn("127.0.0.1", found)
        self.assertEqual(len(got), 2)                      # gateway: ssdp:all + IGD, asked once
        self.assertTrue(any(identify.IGD_ST.encode() in g for g in got))
        self.assertTrue(all(f"HOST: 127.0.0.1:{port}".encode() in g for g in got))

    def test_nbstat_parse(self):
        q = identify.build_nbstat(0x1234)
        self.assertEqual(len(q), 50)
        self.assertEqual(q[:2], b"\x12\x34")
        ok = identify.parse_nbstat(nbstat_reply(1, [("DESKTOP-A1", 0x00, False),
                                                    ("WORKGROUP", 0x00, True),
                                                    ("DESKTOP-A1", 0x20, False)]))
        self.assertEqual(ok, {"name": "DESKTOP-A1", "workgroup": "WORKGROUP",
                              "mac": "00:1a:2b:3c:4d:5e"})
        self.assertEqual(identify.parse_nbstat(nbstat_reply(1, [("PC", 0, False)],
                                                            mac=b"\0" * 6))["mac"], "")
        evil = nbstat_reply(1, [("<img src=x>\x07", 0, False)])
        self.assertNotIn("\x07", identify.parse_nbstat(evil)["name"])
        good = nbstat_reply(1, [("PC", 0, False)])
        for cut in range(0, len(good) - 40, 3):            # truncated anywhere: None, no raise
            r = identify.parse_nbstat(good[:cut])
            self.assertTrue(r is None or r["name"] == "PC")
        lying = identify.parse_nbstat(nbstat_reply(1, [("PC", 0, False)], count=250)[:80])
        self.assertEqual(lying["mac"], "")                    # a count past the data: bounded
        self.assertIsNone(identify.parse_nbstat(nbstat_reply(1, [("GROUP", 0, True)])))
        self.assertIsNone(identify.parse_nbstat(b"\xff" * 300))

    def test_netbios_query(self):
        port, got = self.responder(lambda d: [nbstat_reply(struct.unpack("!H", d[:2])[0],
                                                           [("NAS01", 0, False)])])
        res = identify.netbios_query(["127.0.0.1", "8.8.8.8"], 0.4, port=port)
        self.assertEqual(res["127.0.0.1"]["name"], "NAS01")
        self.assertEqual(len(got), 1)
        self.assertEqual(identify.netbios_query([], 0.1), {})

    def test_reverse_dns(self):
        def resolve(ip):
            if ip.endswith(".9"):
                time.sleep(5)
            if ip.endswith(".8"):
                raise socket.herror("no PTR")
            return {"192.168.1.5": "tv.lan", "192.168.1.6": "192.168.1.6", "192.168.1.7": "192-168-1-7"}.get(ip, "x")
        t0 = time.monotonic()
        got = identify.reverse_dns(["192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9",
                                    "1.1.1.1"], timeout=0.5, resolve=resolve)
        self.assertLess(time.monotonic() - t0, 2.0)          # one overall deadline
        self.assertEqual(got.get("192.168.1.5"), "tv.lan")
        self.assertNotIn("192.168.1.6", got)                    # just the address again
        self.assertNotIn("1.1.1.1", got)

    def test_resolver_is_local(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "resolv.conf"
            for text, want in (("nameserver 10.255.255.254\n", True),
                               ("nameserver 127.0.0.53\nsearch lan\n", True),
                               ("nameserver 192.168.1.1\nnameserver 8.8.8.8\n", False),
                               ("# nothing\n", False), ("nameserver bogus\n", False)):
                p.write_text(text)
                self.assertEqual(identify.resolver_is_local(str(p)), want, text)
            self.assertFalse(identify.resolver_is_local(str(Path(d) / "missing")))


class RunRecordedTests(TmpDir):
    def test_unicast_summary_and_records(self):
        db = store.connect(":memory:")
        mac_a, mac_b = "aa:bb:cc:00:00:0a", "aa:bb:cc:00:00:0b"
        dev(db, "192.168.1.10", mac_a)
        dev(db, "192.168.1.11", mac_b, "printer")
        dev(db, "192.168.1.13", "aa:bb:cc:00:00:0c", is_self=True)
        seen = {}

        def nb(targets, seconds):
            seen["targets"] = list(targets)
            return {"192.168.1.10": {"name": "DESKTOP-X", "workgroup": "WORKGROUP", "mac": ""}}
        with mock.patch.object(identify, "mdns_browse", lambda *a, **k: {}), \
                mock.patch.object(identify, "ssdp_search", lambda *a, **k: {}), \
                mock.patch.object(identify, "netbios_query", nb), \
                mock.patch.object(identify, "reverse_dns", lambda ips: {"192.168.1.10": "desk.lan"}), \
                mock.patch.object(identify, "resolver_is_local", lambda: True), \
                mock.patch("netwarden.upnp.default_gateway", lambda: "192.168.1.1"):
            s = identify.run_recorded(db, 0.1, upnp_too=False)
        self.assertEqual(sorted(seen["targets"]), ["192.168.1.10", "192.168.1.11"])   # never ourselves
        self.assertEqual(s["unicast"], {"targets": 2, "gateway": True})
        self.assertEqual(s["netbios"], {"ok": True, "hosts": 1, "devices": 1, "kinds": {"computer": 1}})
        self.assertEqual(s["rdns"], {"asked": 1, "names": 1})
        self.assertNotIn("DESKTOP-X", json.dumps(s))          # counts / kinds only
        names = store.identity_names(db)
        self.assertEqual(names.get(mac_a), "DESKTOP-X")
        self.assertEqual(identify.best(store.identities(db, mac_a)[mac_a])["name"], "DESKTOP-X")
        self.assertEqual(store.source_status(db)["netbios"]["last_count"], 1)

    def test_public_resolver_gets_no_ptr_questions(self):
        db = store.connect(":memory:")
        dev(db, "192.168.1.10", "aa:bb:cc:00:00:0a")
        asked = []
        with mock.patch.object(identify, "mdns_browse", lambda *a, **k: {}), \
                mock.patch.object(identify, "ssdp_search", lambda *a, **k: {}), \
                mock.patch.object(identify, "netbios_query", lambda *a, **k: {}), \
                mock.patch.object(identify, "reverse_dns", lambda ips: asked.append(ips) or {}), \
                mock.patch.object(identify, "resolver_is_local", lambda: False), \
                mock.patch("netwarden.upnp.default_gateway", lambda: None):
            s = identify.run_recorded(db, 0.1, upnp_too=False)
        self.assertEqual(asked, [])
        self.assertEqual(s["rdns"], {"asked": 0, "names": 0})
        self.assertEqual(s["unicast"]["gateway"], False)

    def test_demo_refused(self):
        path = Path(self.tmp.name) / "demo.db"
        demo.build(path)
        db = store.connect(path)
        try:
            with self.assertRaises(identify.DemoRefused):
                identify.run_recorded(db, 0.1)
        finally:
            db.close()


class PageFileTests(unittest.TestCase):
    STATIC = Path(__file__).resolve().parent.parent / "netwarden" / "static"

    def test_every_form_field_has_an_id_or_name(self):
        """Chrome flags fields without either ("A form field element should have an id or
        name attribute") - every <input>/<textarea>/<select> in the page files has one."""
        import re
        for f in ("app.js", "index.html"):
            src = (self.STATIC / f).read_text(encoding="utf-8")
            for m in re.finditer(r"<(input|textarea|select)\b([^>]*)>", src):
                self.assertRegex(m.group(2), r"\b(id|name)=", f"{f}: {m.group(0)[:80]}")

    def test_pairing_card_shows_the_wsl_rule_read_only(self):
        src = (self.STATIC / "app.js").read_text(encoding="utf-8")
        self.assertIn("wslFirewallBox(s.wsl_firewall", src)
        box = src[src.index("function wslFirewallBox"):]
        box = box[:box.index("\n}\n")]
        self.assertIn("readonly", box)
        self.assertNotIn("fetch(", box)                    # shown and copied, never run


class QuietHintTests(unittest.TestCase):
    def test_calm_hint_when_even_unicast_is_silent(self):
        db = store.connect(":memory:")
        for src in ("discovery", "mdns", "ssdp", "netbios"):
            store.record_source_ok(db, src, 0 if src != "discovery" else 12)
        with mock.patch("netwarden.discovery.availability", lambda: (True, None)):
            st = health.status(db, None, {})
        hints = health.hints(st, "en")
        self.assertIn(i18n.t("status.hint.ident_silent_unicast", "en"), hints)
        self.assertIn("Hyper-V", i18n.t("status.hint.ident_silent_unicast", "en"))


if __name__ == "__main__":
    unittest.main()
