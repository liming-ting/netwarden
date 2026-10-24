"""Stage H: network health (gateway probes, DNS as a signal, outage log), the suggestion
center, the home network score, and the demo story.

No network: pings go through a fake `run`, TCP checks hit ephemeral 127.0.0.1 sockets,
the DNS server stats come from a fake HTTP server, and the web API runs on an ephemeral
127.0.0.1 port (offline AI forced)."""

import contextlib
import http.client
import http.server
import io
import json
import re
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, brain, demo, dns_ingest, i18n, nethealth,
                       offline_ai, runner, score, settings, store, suggestions, web)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
CAM = "a0:43:b0:9f:21:5e"

IPUTILS = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.912/2.507/3.101/0.485 ms
"""
BUSYBOX = """--- 192.168.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33% packet loss
round-trip min/avg/max = 1.2/4.6/8.0 ms
"""
LOST = """--- 192.168.1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2040ms
"""


def iso(dt):
    return dt.strftime(ISO)


def gw(t, ok=True, ms=3.0):
    return {"ts": iso(t), "ok": int(ok), "latency_ms": ms if ok else None,
            "loss": 0.0 if ok else 1.0}


class ProbeTests(unittest.TestCase):
    def test_parse_ping(self):
        self.assertEqual(nethealth.parse_ping(IPUTILS), {"ok": True, "loss": 0.0, "latency_ms": 2.507})
        self.assertEqual(nethealth.parse_ping(BUSYBOX), {"ok": True, "loss": 0.333, "latency_ms": 4.6})
        self.assertEqual(nethealth.parse_ping(LOST), {"ok": False, "loss": 1.0, "latency_ms": None})
        self.assertIsNone(nethealth.parse_ping("ping: socket: Operation not permitted"))
        self.assertIsNone(nethealth.parse_ping(""))

    def test_ping_fixed_args_no_shell(self):
        calls = []

        def run(args, **kw):
            calls.append((args, kw))
            return mock.Mock(stdout=IPUTILS, returncode=0)
        with mock.patch("shutil.which", return_value="/bin/ping"):
            res = nethealth.ping("192.168.1.1", run)
            self.assertEqual(res["method"], "icmp")
            self.assertEqual(calls[0][0], ["ping", "-n", "-q", "-c", "3", "-W", "1", "192.168.1.1"])
            self.assertNotIn("shell", calls[0][1])
            # never an option or a host name on the command line
            for bad in ("-f", "192.168.1.1; rm -rf /", "router.lan"):
                self.assertIsNone(nethealth.ping(bad, run))
            self.assertEqual(len(calls), 1)
            # a ping that is not allowed here (exit 2) -> None -> TCP fallback
            self.assertIsNone(nethealth.ping("192.168.1.1",
                                             lambda a, **k: mock.Mock(stdout="", returncode=2)))
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(nethealth.ping("192.168.1.1", run))

    def test_tcp_check_open_and_refused_both_mean_up(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(nethealth.tcp_check("127.0.0.1", port, 2)["ok"])
        finally:
            srv.close()
        r = nethealth.tcp_check("127.0.0.1", port, 2)    # closed now: refused = answered
        self.assertTrue(r["ok"])
        self.assertEqual(r["method"], "tcp")
        self.assertFalse(nethealth.tcp_check("not an ip", 80, 1)["ok"])   # numeric only

    def test_probe_gateway_falls_back_to_tcp(self):
        with mock.patch("shutil.which", return_value=None), \
                mock.patch.object(nethealth, "tcp_check",
                                  side_effect=[{"ok": False, "latency_ms": None, "loss": 1.0,
                                                "method": "tcp"},
                                               {"ok": True, "latency_ms": 2.0, "loss": 0.0,
                                                "method": "tcp"}]) as tc:
            self.assertTrue(nethealth.probe_gateway("192.168.1.1")["ok"])
            self.assertEqual([c.args[1] for c in tc.call_args_list], [80, 443])

    def test_parse_target(self):
        self.assertEqual(nethealth.parse_target("1.1.1.1:443"), ("1.1.1.1", 443))
        self.assertEqual(nethealth.parse_target(" one.one.one.one:53 "), ("one.one.one.one", 53))
        self.assertEqual(nethealth.parse_target("[2606:4700::1111]:443"), ("2606:4700::1111", 443))
        for bad in ("", "1.1.1.1", "http://1.1.1.1:443", "u:p@host:443", "host:0", "host:70000",
                    "host:443/path", "-x:1", "999.1.1:80", "a b:1", "[::1]"):
            with self.assertRaises(ValueError, msg=bad):
                nethealth.parse_target(bad)

    def test_probe_setting_validated(self):
        db = store.connect(":memory:")
        self.assertEqual(settings.get(db, {}, "health.internet_probe"), "")     # off by default
        settings.update(db, {}, {"health.internet_probe": "1.1.1.1:443"})
        self.assertEqual(settings.get(db, {}, "health.internet_probe"), "1.1.1.1:443")
        for bad in ("http://x:1", "x", "a@b:1"):
            with self.assertRaises(settings.SettingError):
                settings.update(db, {}, {"health.internet_probe": bad})
        settings.update(db, {}, {"health.internet_probe": ""})
        self.assertEqual(settings.get(db, {}, "health.internet_probe"), "")


class OutageTests(unittest.TestCase):
    def states(self, gws=(), fails=None, inet=()):
        return nethealth.minute_states(list(gws), fails or {}, list(inet))

    def test_router_down(self):
        t0 = NOW - timedelta(hours=1)
        g = [gw(t0 + timedelta(minutes=k), ok=not 10 <= k < 14) for k in range(30)]
        out = nethealth.find_outages(self.states(g), NOW)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["cause"], out[0]["minutes"], out[0]["ongoing"]), ("router", 4, False))
        self.assertEqual(out[0]["start"], iso(t0 + timedelta(minutes=10)))

    def test_isp_dns_unknown_and_short_blip(self):
        t0 = NOW - timedelta(hours=1)
        g = [gw(t0 + timedelta(minutes=k)) for k in range(30)]
        fails = {iso(t0 + timedelta(minutes=k))[:16]: (6, 6) for k in (5, 6, 7)}
        self.assertEqual(nethealth.find_outages(self.states(g, fails), NOW)[0]["cause"], "isp")
        inet = [gw(t0 + timedelta(minutes=k)) for k in range(30)]        # probe got through
        self.assertEqual(nethealth.find_outages(self.states(g, fails, inet), NOW)[0]["cause"], "dns")
        self.assertEqual(nethealth.find_outages(self.states((), fails), NOW)[0]["cause"], "unknown")
        down = [gw(t0 + timedelta(minutes=k), ok=k not in (5, 6, 7)) for k in range(30)]
        self.assertEqual(nethealth.find_outages(self.states(g, {}, down), NOW)[0]["cause"], "isp")
        # one bad minute is a blip, not an outage; few lookups failing is not "failing"
        one = [gw(t0 + timedelta(minutes=k), ok=k != 5) for k in range(30)]
        self.assertEqual(nethealth.find_outages(self.states(one), NOW), [])
        weak = {iso(t0 + timedelta(minutes=k))[:16]: (20, 2) for k in (5, 6, 7)}
        self.assertEqual(nethealth.find_outages(self.states(g, weak), NOW), [])

    def test_gap_bridged_and_ongoing(self):
        t0 = NOW - timedelta(minutes=20)
        g = [gw(t0 + timedelta(minutes=k), ok=k not in (2, 3, 5, 6, 18, 19)) for k in range(20)]
        out = nethealth.find_outages(self.states(g), NOW)
        self.assertEqual([(o["minutes"], o["ongoing"]) for o in out], [(5, False), (2, True)])


class _DB:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "h.db"
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def probes(self, start, minutes, down=()):
        for k in range(minutes):
            t = start + timedelta(minutes=k, seconds=5)
            store.insert_health_sample(self.db, "gateway", k not in down,
                                       None if k in down else 2.5, 1.0 if k in down else 0.0,
                                       "icmp", ts=iso(t))


class OutageLogTests(_DB, unittest.TestCase):
    def test_update_grows_merges_and_closes(self):
        now = datetime.now(timezone.utc).replace(second=30, microsecond=0)
        start = now - timedelta(minutes=30)
        self.probes(start, 29, down=range(22, 29))          # down for the last 7 minutes
        nethealth.update_outages(self.db, now)
        rows = store.outages(self.db)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["ongoing"])
        self.assertEqual(rows[0]["cause"], "router")
        first_id = rows[0]["id"]
        # the router came back: the same row closes, nothing new is inserted
        for k in range(29, 34):
            store.insert_health_sample(self.db, "gateway", True, 2.0, 0.0, "icmp",
                                       ts=iso(start + timedelta(minutes=k, seconds=5)))
        nethealth.update_outages(self.db, now + timedelta(minutes=5))
        rows = store.outages(self.db)
        self.assertEqual([(r["id"], r["ongoing"]) for r in rows], [(first_id, 0)])
        self.assertEqual(nethealth.outage_list(self.db)[0]["minutes"], 7)
        # re-deriving the same window again is idempotent
        nethealth.update_outages(self.db, now + timedelta(minutes=5))
        self.assertEqual(len(store.outages(self.db)), 1)

    def test_probe_once_records_samples_and_status(self):
        def run(args, **kw):
            return mock.Mock(stdout=IPUTILS, returncode=0)
        with mock.patch("shutil.which", return_value="/bin/ping"):
            res = nethealth.probe_once(self.db, {}, run, gw="192.168.1.1")
        self.assertTrue(res["gateway"]["ok"])
        self.assertIsNone(res["internet"])                  # no probe unless the user sets one
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM health_samples").fetchone()[0], 1)
        st = self.db.execute("SELECT * FROM source_status WHERE source = 'gateway'").fetchone()
        self.assertEqual(st["last_count"], 1)
        # the optional internet probe, against a local listener
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            settings.update(self.db, {}, {"health.internet_probe":
                                          f"127.0.0.1:{srv.getsockname()[1]}"})
            with mock.patch("shutil.which", return_value="/bin/ping"):
                res = nethealth.probe_once(self.db, {}, run, gw="192.168.1.1")
        finally:
            srv.close()
        self.assertTrue(res["internet"]["ok"])
        self.assertEqual(len(store.health_samples(self.db, "internet", "0")), 1)

    def test_no_gateway_is_an_error_not_a_crash(self):
        with mock.patch.object(nethealth, "gateway_ip", return_value=None):
            with self.assertRaises(RuntimeError):
                nethealth.probe_once(self.db, {})
        st = self.db.execute("SELECT * FROM source_status WHERE source = 'gateway'").fetchone()
        self.assertTrue(st["last_error"])

    def test_dns_failures_feed_the_log(self):
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        start = now - timedelta(minutes=40)
        self.probes(start, 39)
        evs = []
        for k in range(10, 15):
            for j in range(4):
                evs.append({"source": "adguard", "ts": iso(start + timedelta(minutes=k, seconds=j * 9)),
                            "client_ip": "10.0.0.9", "client_name": None, "device_mac": None,
                            "domain": f"d{j}.example", "qtype": "A", "status": "SERVFAIL",
                            "reason": "x", "blocked": 0, "block_reason": None, "cached": 0,
                            "upstream": "1.1.1.1:53", "elapsed_ms": 4000.0})
        store.insert_events(self.db, evs)
        nethealth.update_outages(self.db, now)
        rows = store.outages(self.db)
        self.assertEqual([(r["cause"], r["dns_min"]) for r in rows], [("isp", 5)])

    def test_alerts_ack_and_dedup(self):
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        self.probes(now - timedelta(minutes=30), 30, down=range(10, 14))
        nethealth.update_outages(self.db, now)
        nethealth.update_outages(self.db, now)                 # de-duplicated
        res = alerts.compute(self.db)
        self.assertEqual(len(res["outage"]), 1)
        self.assertTrue(alerts.has_alerts(res))
        o = res["outage"][0]
        self.assertEqual(o["mac"], nethealth.NETWORK_KEY)
        loc = alerts.localize(res, "zh-Hant")["outage"][0]
        self.assertIn("路由器", loc["text"])
        self.assertIn("網路", alerts.render_digest(res, "zh-Hant"))
        store.add_ack(self.db, nethealth.NETWORK_KEY, o["ack"])
        self.assertEqual(alerts.compute(self.db)["outage"], [])


class ServerStatsTests(unittest.TestCase):
    """AdGuard /control/stats and Pi-hole /api/stats/summary from fake local servers."""

    @classmethod
    def setUpClass(cls):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/control/stats"):
                    body = {"num_dns_queries": 1200, "num_blocked_filtering": 150,
                            "avg_processing_time": 0.0123,
                            "top_upstreams_avg_time": [
                                {"https://user:secret@dns.example/dns-query": 0.031},
                                {"8.8.8.8:53": 0.012}]}
                elif self.path.startswith("/api/stats/summary"):
                    body = {"queries": {"total": 99, "blocked": 9}}
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_adguard_stats_never_keep_urls(self):
        db = store.connect(":memory:")
        res = dns_ingest.record_stats(db, dns_ingest.AdGuardHome(self.url))
        self.assertEqual((res["queries"], res["blocked"], res["avg_ms"]), (1200, 150, 12.3))
        self.assertEqual([u["name"] for u in res["upstreams"]], ["dns.example", "8.8.8.8:53"])
        stored = store.get_meta(db, "dns_server_stats")
        self.assertNotIn("secret", stored)
        self.assertNotIn("https://", stored)

    def test_pihole_stats_and_failures_swallowed(self):
        db = store.connect(":memory:")
        ph = dns_ingest.PiHole(self.url)
        ph.logged_in = True
        res = dns_ingest.record_stats(db, ph)
        self.assertEqual((res["server"], res["queries"], res["blocked"]), ("pihole", 99, 9))
        dead = dns_ingest.AdGuardHome("http://127.0.0.1:9")    # nothing listens on :9
        dead.timeout = 1
        self.assertIsNone(dns_ingest.record_stats(db, dead))
        self.assertEqual(json.loads(store.get_meta(db, "dns_server_stats"))["queries"], 99)


class RunnerTests(unittest.TestCase):
    def test_plan_health_loop(self):
        with mock.patch.object(nethealth, "availability", return_value=(True, None)):
            iv, job = runner.plan({})["health"]
        self.assertEqual(iv, 60)
        self.assertIsInstance(job, runner.HealthJob)
        with mock.patch.object(nethealth, "availability", return_value=(False, "no_gateway")):
            self.assertEqual(runner.plan({})["health"], (None, "no_gateway"))

    def test_health_job_records_score_now_and_then(self):
        db = store.connect(":memory:")
        job = runner.HealthJob({})
        with mock.patch.object(nethealth, "probe_once", return_value={}) as p, \
                mock.patch.object(score, "record") as rec:
            job(db)
            job(db)
        self.assertEqual(p.call_count, 2)
        self.assertEqual(rec.call_count, 1)


class ScoreTests(_DB, unittest.TestCase):
    def test_empty_home_has_no_score(self):
        res = score.compute(self.db, {})
        self.assertIsNone(res["score"])
        self.assertEqual(score.level(None), "idle")
        self.assertEqual(score.report(self.db, "en", {})["summary"],
                         i18n.t("score.summary.idle", "en"))

    def test_unmeasured_pillars_excluded_and_dismiss_costs_nothing(self):
        seen = iso(datetime.now(timezone.utc) - timedelta(days=2))   # seen this week
        for i in range(4):
            store.upsert_device(self.db, {"ip": f"10.0.0.{i + 2}", "mac": f"02:00:00:00:00:0{i}",
                                          "vendor": "", "hostname": "", "randomized": 0,
                                          "is_self": 0}, seen=seen)
        res = score.compute(self.db, {})
        self.assertEqual([p for p, v in res["pillars"].items() if v["measured"]], ["tidiness"])
        self.assertEqual({d["key"] for d in res["deductions"]}, {"names", "new_devices"})
        suggestions.set_status(self.db, "names", "dismissed", None, {})
        after = score.compute(self.db, {})
        self.assertEqual({d["key"] for d in after["deductions"]}, {"new_devices"})
        self.assertGreater(after["score"], res["score"])
        for mac in [f"02:00:00:00:00:0{i}" for i in range(4)]:    # reviewed = trusted
            store.add_ack(self.db, mac, "")
        self.assertEqual(score.compute(self.db, {})["score"], 100)


class DemoStoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_outages(self):
        rows = nethealth.outage_list(self.db)
        self.assertEqual(sorted((o["cause"], o["minutes"]) for o in rows),
                         [("isp", 7), ("router", 3)])
        rep = nethealth.report(self.db, "en")
        # the verdict reads the last 60 minutes: right after the demo's 02:13 ISP outage (a
        # run at 02:30) the lossy samples / failed lookups around it may still count (warn);
        # once it ended over an hour ago it is "ok" (stage E: no more "78% failing right now"
        # from the previous clock hour)
        recent = any(o["end_ts"] >= (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat() for o in rows)
        if recent:
            self.assertIn(rep["verdict"]["level"], ("warn", "ok"))
        else:
            self.assertEqual(rep["verdict"]["level"], "ok")
        texts = [o["text"] for o in rep["outages"]]
        self.assertTrue(any("02:13" in t and "ISP" in t for t in texts), texts)
        self.assertTrue(any("19:41" in t and "router" in t for t in texts), texts)
        self.assertTrue(rep["gateway"]["series"])
        self.assertEqual(rep["server"]["server"], "adguard")
        self.assertEqual(rep["outages_7d"], 2)
        zh = nethealth.report(self.db, "zh-Hant")
        self.assertIn("網路業者", " ".join(o["text"] for o in zh["outages"]))

    def test_suggestions_and_score(self):
        rep = suggestions.report(self.db, "en", {})
        self.assertGreaterEqual(rep["counts"]["open"], 3)
        self.assertEqual([i["id"] for i in rep["dismissed"]], ["names"])
        done = {i["id"]: i for i in rep["done"]}
        self.assertTrue(done["trackers"]["waiting"])
        self.assertEqual(len(rep["top"]), 3)
        self.assertEqual(rep["top"][0]["severity"], "high")
        for i in rep["open"]:
            self.assertTrue(i["title"] and i["why"] and i["platforms"])
        sc = score.report(self.db, "en", {})
        self.assertEqual(len(sc["trend"]), 8)
        self.assertEqual(sc["delta"], 7)
        self.assertNotIn("trackers", [r["id"] for r in sc["raise"]])    # already done
        self.assertTrue(all(r["gain"] >= 1 for r in sc["raise"]))

    def test_rebuild_keeps_user_decisions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "demo.db"
            demo.build(p)
            db = store.connect(p)
            suggestions.set_status(db, "names", "open", None, {})      # the user re-opened it
            demo.build(p)
            self.assertNotIn("names", store.suggestion_states(db))
            self.assertEqual(len(store.outages(db)), 2)
            self.assertEqual(len(store.score_history(db)), 14)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM source_status WHERE source = "
                                        "'gateway'").fetchone()[0], 1)
            db.close()

    def test_llm_snapshot_has_network_health(self):
        nh = brain.snapshot(self.db)["network_health"]
        self.assertEqual(sorted(o["probable_cause"] for o in nh["outages_7d"]), ["isp", "router"])
        self.assertTrue(any(o["start"].endswith("02:13") for o in nh["outages_7d"]))
        self.assertNotIn("network_health", brain.snapshot(store.connect(":memory:")))

    def test_offline_ai_and_digest_mention_the_outage(self):
        text = offline_ai.summarize(self.db, brain.snapshot(self.db), "en", None, None)
        self.assertIn("02:13", text)
        digest = alerts.render_digest(alerts.compute(self.db), "en")
        self.assertIn("02:13", digest)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"content-type": ctype} if ctype else {}
        c.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw.decode("utf-8")

    def test_get_endpoints(self):
        st, h = self.req("GET", "/api/health?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertEqual(len(h["outages"]), 2)
        self.assertTrue(h["demo"])
        self.assertEqual(len(h["dns"]["days"]), 7)
        st, s = self.req("GET", "/api/suggestions?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(set(s["counts"]), {"open", "done", "dismissed", "snoozed"})
        st, sc = self.req("GET", "/api/score?lang=ja")
        self.assertEqual(st, 200)
        self.assertEqual([p["key"] for p in sc["pillars"]],
                         ["security", "privacy", "health", "tidiness"])
        self.assertIn("100", sc["summary"])

    def test_suggestion_post_flow(self):
        st, s = self.req("GET", "/api/suggestions?lang=en")
        sid = s["open"][-1]["id"]
        path = "/api/suggestions/" + sid
        self.assertEqual(self.req("POST", path, {"status": "done"}, ctype="text/plain")[0], 415)
        self.assertEqual(self.req("POST", path, {"status": "nope"})[0], 400)
        self.assertEqual(self.req("POST", path, {"status": "snoozed", "days": 0})[0], 400)
        self.assertEqual(self.req("POST", path, {"status": "snoozed", "days": "7"})[0], 400)
        self.assertEqual(self.req("POST", "/api/suggestions/port:zz", {"status": "done"})[0], 404)
        self.assertEqual(self.req("POST", "/api/suggestions/<script>", {"status": "done"})[0], 400)
        self.assertEqual(self.req("POST", "/api/suggestions/" + "a" * 300, {"status": "done"})[0], 400)
        st, r = self.req("POST", path, {"status": "snoozed", "days": 3, "lang": "en"})
        self.assertEqual(st, 200)
        self.assertTrue(r["ok"])
        self.assertIn(sid, [i["id"] for i in r["snoozed"]])
        self.assertNotIn(sid, [i["id"] for i in r["open"]])
        st, r = self.req("POST", path, {"status": "open"})
        self.assertIn(sid, [i["id"] for i in r["open"]])

    def test_network_ack(self):
        st, h = self.req("GET", "/api/health?lang=en")
        key = h["outages"][0]["ack"]
        self.assertEqual(self.req("POST", "/api/ack", {"mac": "network", "domain": key})[0], 200)
        self.assertEqual(self.req("POST", "/api/unack", {"mac": "network", "domain": key})[0], 200)
        for bad in ("port:23", "outage:x", "", "outage:" + "9" * 20):
            self.assertEqual(self.req("POST", "/api/ack", {"mac": "network", "domain": bad})[0],
                             400, bad)

    def test_probe_setting_over_api(self):
        st, r = self.req("POST", "/api/settings", {"values": {"health.internet_probe": "javascript:x"}})
        self.assertEqual((st, r["key"]), (400, "health.internet_probe"))
        st, r = self.req("POST", "/api/settings", {"values": {"health.internet_probe": "1.1.1.1:443"}})
        self.assertEqual(st, 200)
        st, h = self.req("GET", "/api/health?lang=en")
        self.assertEqual((h["internet"]["configured"], h["internet"]["target"]), (True, "1.1.1.1:443"))
        self.req("POST", "/api/settings", {"values": {"health.internet_probe": None}})
        self.assertFalse(self.req("GET", "/api/health?lang=en")[1]["internet"]["configured"])


class CliTests(unittest.TestCase):
    def test_health_command(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "demo.db"
            demo.build(p)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = cli.main(["health", "--db", str(p), "--lang", "en"])
            self.assertEqual(rc, 0)
            self.assertIn("02:13", out.getvalue())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["health", "--db", str(p), "--json", "--rebuild", "3"])
            self.assertEqual(len(json.loads(out.getvalue())["outages"]), 2)


class UiFileTests(unittest.TestCase):
    js = (Path(web.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")

    def test_stage_h_keys_exist_everywhere(self):
        keys = set(re.findall(r"T\('((?:app\.(?:h|sug|score)|sug|score|health)\.[\w.]*\w)'", self.js))
        self.assertGreater(len(keys), 40)
        for lang in i18n.CODES:
            data = json.loads((Path(i18n.__file__).parent / "locales" / f"{lang}.json")
                              .read_text(encoding="utf-8"))
            self.assertFalse(keys - set(data), lang)
        for kind, (plats, _p) in suggestions.KINDS.items():
            for k in ("title", "why", "done"):
                self.assertTrue(i18n.has(f"sug.{kind}.{k}"), (kind, k))
            for plat in plats:
                self.assertTrue(i18n.has(f"sug.{kind}.steps.{plat}"), (kind, plat))

    def test_still_two_inner_html_writes(self):
        self.assertEqual(self.js.count("innerHTML"), 2)


if __name__ == "__main__":
    unittest.main()
