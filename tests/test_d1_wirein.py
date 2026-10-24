"""
Stage D1 wire-in: privacy / DNS visibility / exposure in the brain snapshot + prompt,
the alerts + digest (acks respected), the offline AI, the web API and the demo story.
The LLM is a fake; the port scan is faked; servers bind ephemeral 127.0.0.1 ports.
"""
import contextlib
import http.client
import io
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import __main__ as cli
from netwarden import alerts, brain, demo, exposure, i18n, offline_ai, store, web

def _mac(hostname):
    return next(d["mac"] for d in demo.DEVICES if d["hostname"] == hostname)


TV, ECHO, CAST, CAM = (_mac(h) for h in ("Samsung-TV", "echo-kitchen", "Chromecast-Living", "ipcam"))
PHONE = "b2:55:3a:7c:10:9b"   # the phone that uses DoH (dns.google)


class _DemoDB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def db(self):
        return store.connect(self.path)


class DemoStoryTests(_DemoDB):
    def test_the_stage_d1_story_is_in_the_demo(self):
        db = self.db()
        snap = brain.snapshot(db)
        dev = {d["mac"]: d for d in snap["devices"]}
        self.assertEqual(dev[TV]["privacy"]["grade"], "F")
        self.assertEqual(dev[TV]["privacy"]["main_category"], "telemetry")
        self.assertGreater(dev[TV]["privacy"]["blocked_share"], 0)      # filter blocked part
        self.assertEqual(dev[PHONE]["dns_visibility"], "bypass")
        self.assertEqual(dev[ECHO]["dns_visibility"], "quiet")
        self.assertEqual([p["port"] for p in dev[CAM]["open_ports"]], [23, 80, 554])
        self.assertIn({"name": "Chromecast-Living", "issue": "never"}, snap["not_in_dns_window"])
        self.assertIn("grade", snap["privacy"])
        # the AI can connect the dots: high-risk cloud + heavy upload + Telnet open
        rendered = brain._render(snap)
        cam = next(d for d in json.loads(rendered)["devices"] if d["mac"] == CAM)
        self.assertIn("23/Telnet (high risk)", cam["open_ports"])
        self.assertIn("uploaded 9", cam["bandwidth"])
        self.assertTrue(any(t["mac"] == CAM for t in snap["threats"]))
        tv = next(d for d in json.loads(rendered)["devices"] if d["mac"] == TV)
        self.assertIn("grade F", tv["privacy"])

    def test_demo_rebuild_keeps_user_notes_and_is_deterministic(self):
        db = self.db()
        store.set_label(db, CAM, "後院攝影機")
        store.add_ack(db, CAM, "port:23")
        before = db.execute("SELECT port, open FROM port_checks ORDER BY rowid").fetchall()
        db.close()
        demo.build(self.path)
        db = self.db()
        self.assertEqual(store.get_labels(db)[CAM]["label"], "後院攝影機")
        self.assertIn((CAM, "port:23"), store.list_acks(db))
        after = db.execute("SELECT port, open FROM port_checks ORDER BY rowid").fetchall()
        self.assertEqual([tuple(r) for r in before], [tuple(r) for r in after])
        store.clear_label(db, CAM)
        store.remove_ack(db, CAM, "port:23")


class PromptTests(_DemoDB):
    def test_signals_paragraph_only_when_there_are_signals(self):
        snap = brain.snapshot(self.db())
        self.assertIn("open_ports", brain._system(brain.INSIGHT_SYSTEM, snap, "en"))
        empty = brain.snapshot(store.connect(":memory:"))
        self.assertNotIn("open_ports", brain._system(brain.ASK_SYSTEM, empty, "en"))

    def test_prompt_stays_compact(self):
        rendered = brain._render(brain.snapshot(self.db()))
        # Stage P: + household / presence and three more demo devices (~29k)
        self.assertLess(len(rendered), 32_000)
        self.assertNotIn("top_trackers", rendered)   # summaries only, no tracker tables


class AlertsTests(_DemoDB):
    def test_new_kinds_in_compute_and_digest(self):
        db = self.db()
        r = alerts.compute(db)
        self.assertEqual({(v["mac"], v["kind"]) for v in r["visibility"]},
                         {(PHONE, "bypass"), (ECHO, "quiet")})
        self.assertEqual([(e["mac"], e["port"]) for e in r["exposure"]], [(CAM, 23), (CAM, 554)])
        self.assertEqual(r["privacy"]["worst"][0]["mac"], TV)
        text = alerts.render_digest(r, "en")
        for needle in ("Open ports", "port 23 Telnet open - high risk", "DNS visibility",
                       "dns.google", "echo-kitchen", "Privacy:", "Most tracked: Samsung-TV (grade F)"):
            self.assertIn(needle, text)
        zh = alerts.render_digest(r)          # the weekly cron default stays zh-Hant
        self.assertIn("開放埠", zh)
        self.assertIn("隱私", zh)
        for code in i18n.CODES:
            self.assertNotIn("{", alerts.render_digest(r, code))

    def test_acks_mute_the_new_kinds(self):
        db = self.db()
        store.add_ack(db, CAM, "port:23")
        store.add_ack(db, PHONE, "visibility:bypass")
        store.add_ack(db, ECHO)                 # trust the whole device
        try:
            r = alerts.compute(db)
            self.assertEqual([(e["mac"], e["port"]) for e in r["exposure"]], [(CAM, 554)])
            self.assertEqual(r["visibility"], [])
            snap = brain.snapshot(db)
            cam = next(d for d in snap["devices"] if d["mac"] == CAM)
            self.assertEqual([p["port"] for p in cam["open_ports"]], [80, 554])
            self.assertFalse(any("dns_visibility" in d for d in snap["devices"]
                                 if d["mac"] in (PHONE, ECHO)))
        finally:
            store.remove_ack(db, CAM, "port:23")
            store.remove_ack(db, PHONE, "visibility:bypass")
            store.remove_ack(db, ECHO)

    def test_json_localize(self):
        loc = alerts.localize(alerts.compute(self.db()), "de")
        self.assertIn("Mirai", loc["exposure"][0]["note"])
        self.assertEqual(loc["exposure"][0]["risk_name"], "hohes Risiko")
        self.assertTrue(all(v["text"] for v in loc["visibility"]))
        self.assertIn("Note für das Zuhause", loc["privacy"]["home"]["line"])
        json.dumps(loc)   # serializable for --json


class OfflineTests(_DemoDB):
    def test_offline_summary_has_the_new_sections(self):
        out = brain.insights(self.db(), offline_ai.OfflineProvider("en"), lang="en")
        self.assertIn(i18n.t("offline.exposure", "en"), out)
        self.assertIn("port 23 Telnet open (high risk)", out)
        self.assertIn(i18n.t("offline.visibility", "en"), out)
        self.assertIn(i18n.t("offline.privacy", "en"), out)
        self.assertLess(out.index("Telnet"), out.index(i18n.t("offline.new_devices", "en")))
        zh = brain.insights(self.db(), offline_ai.OfflineProvider("zh-Hant"), lang="zh-Hant")
        self.assertIn("開放埠", zh)


class CheckCommandTests(_DemoDB):
    @staticmethod
    def run_cli(*argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self._scan = exposure.scan
        exposure.scan = lambda devs, progress=None, **kw: [
            {"mac": d["mac"], "ip": d["ip"], "port": p, "open": p == 23,
             "ts": "2026-01-01T00:00:00.000000Z"} for d in devs for p in exposure.PORTS]

    def tearDown(self):
        exposure.scan = self._scan

    def test_demo_refused_and_target_required(self):
        code, _, err = self.run_cli("check", "--db", str(self.path), "--all", "--lang", "en")
        self.assertEqual(code, 1)
        self.assertIn(i18n.t("exposure.demo_refused", "en"), err)
        code, _, err = self.run_cli("check", "--db", str(self.path), "--lang", "en")
        self.assertEqual(code, 2)
        self.assertIn("--mac M or --all", err)
        self.assertIn("  check", self.run_cli("--help")[1])

    def test_check_real_db(self):
        path = Path(self.tmp.name) / "real.db"
        db = store.connect(path)
        store.upsert_device(db, {"ip": "10.9.9.9", "mac": "aa:aa", "vendor": "x",
                                 "hostname": "cam", "randomized": False, "is_self": False})
        store.upsert_device(db, {"ip": "198.51.100.7", "mac": "bb:bb", "vendor": "x",
                                 "hostname": "pub", "randomized": False, "is_self": False})
        db.close()
        code, out, _ = self.run_cli("check", "--db", str(path), "--mac", "aa:aa", "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn("cam (10.9.9.9): 23 Telnet (high risk)", out)
        self.assertIn("Mirai", out)
        code, _, err = self.run_cli("check", "--db", str(path), "--mac", "bb:bb", "--lang", "en")
        self.assertEqual(code, 1)
        self.assertIn("198.51.100.7", err)
        code, out, _ = self.run_cli("check", "--db", str(path), "--all", "--json")
        self.assertEqual([r["mac"] for r in json.loads(out)], ["aa:aa"])   # public one skipped


class FakeProvider:
    def complete(self, system, user, max_tokens=1200):
        return "FAKE"


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.demo_path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.demo_path)
        cls.real_path = Path(cls.tmp.name) / "real.db"
        db = store.connect(cls.real_path)
        store.upsert_device(db, {"ip": "10.9.9.9", "mac": "aa:aa", "vendor": "x",
                                 "hostname": "<script>x</script>", "randomized": False,
                                 "is_self": False})
        store.upsert_device(db, {"ip": "203.0.113.5", "mac": "bb:bb", "vendor": "x",
                                 "hostname": "public", "randomized": False, "is_self": False})
        db.close()
        cls._scan, cls._prov = exposure.scan, brain.provider_from_env
        exposure.scan = lambda devs, progress=None, **kw: [
            {"mac": d["mac"], "ip": d["ip"], "port": p, "open": p == 5555,
             "ts": "2026-01-01T00:00:00.000000Z"} for d in devs for p in exposure.PORTS]
        brain.provider_from_env = lambda env, db=None: FakeProvider()
        web.Handler.env, web.Handler.lang, web.Handler.hours = {}, "en", 24
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        exposure.scan, brain.provider_from_env = cls._scan, cls._prov
        cls.tmp.cleanup()

    def setUp(self):
        web.Handler.db_path = str(self.demo_path)

    def _req(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {"content-type": ctype} if ctype else {}
        c.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = c.getresponse()
        return r.status, json.loads(r.read() or b"null")

    def test_privacy_and_visibility_endpoints(self):
        st, p = self._req("GET", "/api/privacy?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertEqual(p["worst"][0]["mac"], TV)
        self.assertIn("全家評分", p["home"]["line"])
        self.assertIn("||samsungacr.com^", p["rules"]["adguard"])
        st, v = self._req("GET", "/api/visibility?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual({i["kind"] for i in v["items"]}, {"bypass", "quiet", "never"})
        self.assertIn("||dns.google^", v["rules"]["adguard"])
        self.assertTrue(v["suggestions"])

    def test_device_drilldown_has_privacy_visibility_ports(self):
        st, dev = self._req("GET", f"/api/device?mac={CAM}&lang=en")
        self.assertEqual(st, 200)
        self.assertEqual([p["port"] for p in dev["ports"]["open"]], [23, 80, 554])
        self.assertFalse(dev["check_allowed"])
        self.assertIn("demo", dev["check_note"])
        self.assertEqual(len(dev["port_list"]), len(exposure.PORTS))
        st, tv = self._req("GET", f"/api/device?mac={TV}&lang=en")
        self.assertEqual(tv["privacy"]["grade"], "F")
        self.assertIn("samsungacr.com", tv["privacy"]["rules"]["pihole"])
        # a known device with no DNS at all still opens (its visibility issue explains why)
        st, cast = self._req("GET", f"/api/device?mac={CAST}&lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(cast["visibility"][0]["kind"], "never")
        self.assertIsNone(cast["privacy"])
        self.assertEqual(self._req("GET", "/api/device?mac=zz")[0], 404)

    def test_check_refused_on_demo_db(self):
        st, body = self._req("POST", "/api/check", {"mac": CAM, "lang": "en"})
        self.assertEqual(st, 409)
        self.assertTrue(body["demo"])
        self.assertEqual(body["error"], i18n.t("exposure.demo_refused", "en"))

    def test_check_validation(self):
        web.Handler.db_path = str(self.real_path)
        self.assertEqual(self._req("POST", "/api/check", {"lang": "en"})[0], 400)
        st, body = self._req("POST", "/api/check", {"mac": "bb:bb", "lang": "en"})
        self.assertEqual(st, 400)                      # public address: refused
        self.assertIn("203.0.113.5", body["error"])
        self.assertEqual(self._req("GET", "/api/check/status?job=nope")[0], 404)
        # JSON only: a cross-site form post can't trigger a check
        self.assertEqual(self._req("POST", "/api/check", {"mac": "aa:aa"}, ctype="text/plain")[0], 415)
        self.assertEqual(self._req("POST", "/api/ack", {"mac": "aa:aa"}, ctype=None)[0], 415)

    def test_check_job_end_to_end(self):
        web.Handler.db_path = str(self.real_path)
        st, job = self._req("POST", "/api/check", {"mac": "aa:aa", "lang": "en"})
        self.assertEqual(st, 202)
        for _ in range(100):
            st, s = self._req("GET", f"/api/check/status?job={job['job']}")
            if s["state"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(s["state"], "done")
        st, dev = self._req("GET", "/api/device?mac=aa:aa&lang=en")
        self.assertEqual(st, 200)
        self.assertEqual([p["port"] for p in dev["ports"]["open"]], [5555])
        self.assertTrue(dev["check_allowed"])
        st, a = self._req("GET", "/api/alerts?lang=en")
        self.assertEqual([(e["mac"], e["port"]) for e in a["exposure"]], [("aa:aa", 5555)])

    def test_page_has_the_new_cards_and_escapes(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        c.request("GET", "/static/app.js")
        page = c.getresponse().read().decode()
        for needle in ("'/api/privacy'", "'/api/visibility'", "/api/check/status",
                       'data-act="copy"', "rulesBox(p.rules)", "check_allowed"):
            self.assertIn(needle, page)
        st, devs = self._req("GET", "/api/devices?lang=en")
        self.assertEqual(st, 200)
        self.assertTrue(any("privacy" in d for d in devs["devices"]))


if __name__ == "__main__":
    unittest.main()
