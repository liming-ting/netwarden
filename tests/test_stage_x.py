"""
Stage X: inbox, settings page + connection tests, backup / restore, first-run wizard,
service worker + offline page, autostart script, one display name per device, export
warm-up. Everything runs on 127.0.0.1: the "sources" are fake HTTP servers on ephemeral
ports, the wizard's scan is a fake sweep, and no test ever calls a real LLM or host.
"""
import contextlib
import http.client
import http.server
import io
import json
import re
import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, backup, brain, cache, conntest, demo, export,
                       firstrun, i18n, inbox, naming, runner, settings, store, web)

ROOT = Path(__file__).resolve().parent.parent
LANGS = i18n.CODES

_DEMO = {}


def demo_copy(dest: Path) -> Path:
    """A private copy of one demo DB built once per test run (sqlite backup, WAL-safe)."""
    if "path" not in _DEMO:
        _DEMO["tmp"] = tempfile.TemporaryDirectory()
        _DEMO["path"] = Path(_DEMO["tmp"].name) / "demo.db"
        demo.build(_DEMO["path"])
    src = sqlite3.connect(_DEMO["path"])
    dst = sqlite3.connect(dest)
    src.backup(dst)
    src.close()
    dst.close()
    return dest


def tearDownModule():
    if "tmp" in _DEMO:
        _DEMO["tmp"].cleanup()


class _DemoDB:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = demo_copy(Path(self.tmp.name) / "x.db")
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


class _EmptyDB:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "e.db"
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()


# --- one display name everywhere -------------------------------------------------

class NamingTests(_DemoDB, unittest.TestCase):
    def test_no_bare_mac_names(self):
        for lang in ("en", "zh-Hant"):
            names = naming.display_names(self.db, lang)
            self.assertTrue(names)
            for mac, name in names.items():
                self.assertNotEqual(mac, name, (lang, mac))

    def test_nameless_device_rule(self):
        mac = "02:00:00:00:00:99"
        store.upsert_device(self.db, {"ip": "192.168.1.99", "mac": mac, "vendor": "", "hostname": "",
                                      "randomized": 1, "is_self": 0})
        self.assertEqual(naming.display_names(self.db, "en")[mac], i18n.t("app.d.private_device", "en"))
        self.assertEqual(naming.display_names(self.db, "zh-Hant")[mac],
                         i18n.t("app.d.private_device", "zh-Hant"))

    def test_relabel_only_touches_bare_macs(self):
        names = {"aa:bb:cc:dd:ee:ff": "Phone · Mom"}
        obj = {"x": [{"mac": "aa:bb:cc:dd:ee:ff", "name": "aa:bb:cc:dd:ee:ff"},
                     {"mac": "aa:bb:cc:dd:ee:ff", "name": "Kitchen", "device": "aa:bb:cc:dd:ee:ff"},
                     {"mac": "11:22:33:44:55:66", "name": "11:22:33:44:55:66"}]}
        out = naming.relabel(obj, names)
        self.assertEqual(out["x"][0]["name"], "Phone · Mom")
        self.assertEqual((out["x"][1]["name"], out["x"][1]["device"]), ("Kitchen", "Phone · Mom"))
        self.assertEqual(out["x"][2]["name"], "11:22:33:44:55:66")
        self.assertEqual(obj["x"][0]["name"], "aa:bb:cc:dd:ee:ff")    # a copy, not in place

    def test_localized_alerts_name_devices(self):
        names = naming.display_names(self.db, "en")
        loc = alerts.localize(alerts.compute(self.db), "en", names)
        for v in loc.get("visibility", []) + loc.get("unusual_hours", []):
            self.assertNotRegex(v["name"], r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


# --- inbox ---------------------------------------------------------------------------

class InboxTests(_DemoDB, unittest.TestCase):
    def items(self, lang="en"):
        return inbox.report(self.db, lang)["items"]

    def ref(self, it):
        return {"kind": it["kind"], "mac": it["mac"], "key": it["key"], "sid": it["sid"]}

    def test_queue_shape_and_order(self):
        r = inbox.report(self.db, "zh-Hant")
        self.assertGreater(r["counts"]["total"], 5)
        self.assertEqual(r["counts"]["total"], len(r["items"]))
        self.assertEqual(r["snooze_days"], 3)                    # the demo family's setting
        sevs = [i["sev"] for i in r["items"]]
        self.assertEqual(sevs, sorted(sevs))
        kinds = {i["kind"] for i in r["items"]}
        self.assertTrue({"threat", "new"} <= kinds, kinds)
        # a suggestion that fixes a listed alert rides on that alert ("How to fix"): the
        # demo's Telnet port, router port, threats and DoH are one item each, not two
        fixed = {i["fix"]["sid"] for i in r["items"] if i["fix"]}
        self.assertTrue({s for s in fixed if s.startswith(("port:", "upnp:", "threat:", "doh:"))}, fixed)
        self.assertFalse(fixed & {i["sid"] for i in r["items"] if i["kind"] == "suggestion"})
        for it in r["items"]:
            self.assertEqual(it["actions"], list(inbox.ACTIONS_FOR[it["kind"]]) if it["mac"] or it["sid"]
                             else [])
            self.assertTrue(it["href"].startswith("#/"))
        self.assertEqual(len({i["id"] for i in r["items"]}), len(r["items"]))

    def test_ack_then_undo(self):
        it = next(i for i in self.items() if i["kind"] == "threat")
        self.assertEqual(inbox.act(self.db, "ack", [self.ref(it)]), 1)
        self.assertNotIn(it["id"], {i["id"] for i in self.items()})
        inbox.act(self.db, "undo", [self.ref(it)], undo="ack")
        self.assertIn(it["id"], {i["id"] for i in self.items()})

    def test_mute_hides_the_kind_for_that_device(self):
        it = next(i for i in self.items() if i["kind"] == "visibility")
        inbox.act(self.db, "mute", [self.ref(it)])
        self.assertIn((it["mac"], "mute:visibility"), {(a["mac"], a["domain"]) for a in store.all_acks(self.db)})
        self.assertFalse([i for i in self.items() if i["kind"] == "visibility" and i["mac"] == it["mac"]])

    def test_snooze_uses_the_setting_and_runs_out(self):
        it = next(i for i in self.items() if i["kind"] == "new")
        inbox.act(self.db, "snooze", [self.ref(it)])
        ack = next(a for a in store.all_acks(self.db) if a["mac"] == it["mac"] and a["domain"] == "new")
        self.assertTrue(ack["until"])
        self.assertNotIn(it["id"], {i["id"] for i in self.items()})
        with self.db:
            self.db.execute("UPDATE acks SET until = '2000-01-01T00:00:00.000000Z' WHERE mac = ?", (it["mac"],))
        self.assertIn(it["id"], {i["id"] for i in self.items()})

    def test_trust_and_suggestions(self):
        it = next(i for i in self.items() if i["kind"] == "new")
        inbox.act(self.db, "trust", [self.ref(it)])
        self.assertIn((it["mac"], ""), {(a["mac"], a["domain"]) for a in store.all_acks(self.db)})
        # "Got it" on an alert that carries a fix: the fix is still to do, now on its own
        carrier = next(i for i in self.items() if i["fix"] and i["kind"] == "exposure")
        sid = carrier["fix"]["sid"]
        self.assertNotIn(sid, {i["sid"] for i in self.items()})
        inbox.act(self.db, "ack", [self.ref(carrier)])
        sug = next(i for i in self.items() if i["kind"] == "suggestion" and i["sid"] == sid)
        inbox.act(self.db, "dismiss", [{"kind": "suggestion", "sid": sug["sid"]}])
        self.assertEqual(store.suggestion_states(self.db)[sug["sid"]]["status"], "dismissed")
        inbox.act(self.db, "undo", [{"kind": "suggestion", "sid": sug["sid"], "prev": "open"}], undo="dismiss")
        self.assertNotIn(sug["sid"], store.suggestion_states(self.db))    # "open" = no row
        self.assertIn(sug["id"], {i["id"] for i in self.items()})

    def test_validation_is_all_or_nothing(self):
        before = store.all_acks(self.db)                          # (the demo's Stage Q tuning)
        good =self.ref(next(i for i in self.items() if i["kind"] == "threat"))
        bad_cases = [
            ("explode", [good], "bad_action"),
            ("done", [good], "bad_action"),                          # "done" is for suggestions
            ("ack", [], "bad_json"),
            ("ack", "x", "bad_json"),
            ("ack", [good] * (inbox.MAX_REFS + 1), "bad_json"),
            ("ack", [{**good, "kind": "nope"}], "bad_inbox_item"),
            ("ack", [{**good, "mac": "not-a-mac"}], "bad_mac"),
            ("ack", [{**good, "key": ""}], "bad_inbox_item"),
            ("ack", [{**good, "key": "k" * 301}], "bad_inbox_item"),
            ("ack", [good, {"kind": "outage", "mac": "network", "key": "rm -rf"}], "bad_mac"),
            ("done", [{"kind": "suggestion", "sid": "../../x"}], "bad_inbox_item"),
        ]
        for action, refs, code in bad_cases:
            with self.assertRaises(inbox.BadRef) as cm:
                inbox.act(self.db, action, refs)
            self.assertEqual(cm.exception.code, code, (action, code))
        for days in (0, 91, True, "3"):
            with self.assertRaises(inbox.BadRef):
                inbox.act(self.db, "snooze", [good], days=days)
        self.assertEqual(store.all_acks(self.db), before)            # nothing was written


# --- settings ------------------------------------------------------------------------

class SettingsTests(_EmptyDB, unittest.TestCase):
    def test_sections_and_items(self):
        d = settings.describe(self.db, {}, "zh-Hant")
        self.assertEqual([s["key"] for s in d["sections"]],
                         ["general", "alerts", "quiet", "push", "ai", "usage", "family", "health", "phone"])
        keys = {s["key"] for s in d["sections"]}
        for it in d["items"]:
            self.assertIn(it["section"], keys)
            self.assertTrue(it["help"] and not it["help"].startswith("settings."), it["key"])
        sec = {it["key"]: it for it in d["items"]}
        self.assertEqual(sec["lan.enabled"]["section"], "phone")
        self.assertEqual(sec["data.retention_days"]["section"], "general")
        self.assertNotIn("value", sec["ai.anthropic_key"])

    def test_env_source_and_secrets(self):
        env = {"NETWARDEN_TZ": "Asia/Taipei", "ANTHROPIC_API_KEY": "sk-ant-SECRET"}
        d = settings.describe(self.db, env, "en")
        sec = {it["key"]: it for it in d["items"]}
        self.assertEqual((sec["time.timezone"]["source"], sec["time.timezone"]["editable"]), ("env", False))
        self.assertTrue(sec["ai.anthropic_key"]["configured"])
        self.assertNotIn("SECRET", json.dumps(d))

    def test_stage_x_settings_validate_and_apply(self):
        with self.assertRaises(settings.SettingError):
            settings.update(self.db, {}, {"alerts.snooze_days": 0})
        with self.assertRaises(settings.SettingError):
            settings.update(self.db, {}, {"alerts.unusual_hours": "maybe"})
        settings.update(self.db, {}, {"alerts.snooze_days": 14})
        self.assertEqual(inbox.snooze_days(self.db), 14)


class AlertSwitchTests(_DemoDB, unittest.TestCase):
    def test_switches_turn_people_alerts_off(self):
        a = alerts.compute(self.db)
        self.assertTrue(a["unusual_hours"] or a.get("bedtime"))
        settings.update(self.db, {}, {"alerts.unusual_hours": False, "family.bedtime_alerts": False})
        a = alerts.compute(self.db)
        self.assertEqual((a["unusual_hours"], a.get("bedtime", [])), ([], []))


# --- connection tests ------------------------------------------------------------------

class _Fake(http.server.BaseHTTPRequestHandler):
    routes: dict = {}

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        status, body = self.routes.get(path, (404, b"{}"))
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ConnTestTests(_EmptyDB, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class H(_Fake):
            routes = {
                "/ok/control/status": (200, b'{"version": "v0.107"}'),
                "/denied/control/status": (401, b'{}'),
                "/html/control/status": (200, b"<html>login</html>"),
                "/api/info/version": (200, b'{"version": {}}'),
                "/lua/rest/v2/get/host/active.lua": (200, b'{"rc": 0, "rsp": {"data": []}}'),
                "/v1/models": (200, b'{"data": [{"id": "llama3.2"}]}'),
            }
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def check(self, name, env):
        r = conntest.check(name, env, self.db)
        self.assertEqual(set(r), {"source", "configured", "ok", "latency_ms", "error_kind"})
        if r["error_kind"]:
            self.assertIn(r["error_kind"], conntest.ERROR_KINDS)
        return r

    def test_not_configured(self):
        for n in ("adguard", "pihole", "ntopng"):
            self.assertEqual(self.check(n, {})["error_kind"], "not_configured")
        self.assertEqual(self.check("ai", {brain.OFFLINE_ENV: "1"})["error_kind"], "offline")
        with self.assertRaises(ValueError):
            conntest.check("router", {}, self.db)

    def test_adguard_kinds_and_no_secrets(self):
        secret = "hunter2-SECRET"
        r = self.check("adguard", {"ADGUARD_URL": self.url + "/ok", "ADGUARD_USER": "u", "ADGUARD_PASS": secret})
        self.assertTrue(r["ok"])
        self.assertIsInstance(r["latency_ms"], int)
        self.assertNotIn(secret, json.dumps(r))
        self.assertEqual(self.check("adguard", {"ADGUARD_URL": self.url + "/denied"})["error_kind"], "auth")
        self.assertEqual(self.check("adguard", {"ADGUARD_URL": self.url + "/html"})["error_kind"], "bad_response")
        self.assertEqual(self.check("adguard", {"ADGUARD_URL": self.url + "/missing"})["error_kind"], "http")

    def test_pihole_ntopng_and_local_ai(self):
        self.assertTrue(self.check("pihole", {"PIHOLE_URL": self.url, "NETWARDEN_DNS_SOURCE": "pihole"})["ok"])
        self.assertTrue(self.check("ntopng", {"NTOPNG_URL": self.url})["ok"])
        ai = {"NETWARDEN_AI_PROVIDER": "openai_compat", "NETWARDEN_AI_BASE_URL": self.url + "/v1",
              "NETWARDEN_AI_MODEL": "llama3.2"}
        self.assertTrue(self.check("ai", ai)["ok"])

    def test_cloud_ai_is_never_called(self):
        env = {"ANTHROPIC_API_KEY": "sk-ant-x"}
        with mock.patch.object(conntest, "_probe", side_effect=AssertionError("called")):
            self.assertEqual(self.check("ai", env)["error_kind"], "cloud")

    def test_error_classification(self):
        import socket
        import urllib.error
        self.assertEqual(conntest._kind(urllib.error.URLError(ConnectionRefusedError())), "refused")
        self.assertEqual(conntest._kind(urllib.error.URLError(socket.timeout())), "timeout")
        self.assertEqual(conntest._kind(urllib.error.URLError(OSError("no route"))), "unreachable")
        self.assertEqual(conntest._kind(ValueError("x")), "bad_response")

    def test_summary(self):
        s = conntest.summary({"ADGUARD_URL": "http://127.0.0.1:1"}, self.db)
        self.assertEqual(s["sources"]["adguard"], True)
        self.assertEqual(s["dns_source"], "adguard")


# --- backup / restore -------------------------------------------------------------------

class BackupTests(_DemoDB, unittest.TestCase):
    def doc(self):
        return json.loads(backup.dumps(backup.export(self.db)))

    def test_export_shape_and_no_secrets(self):
        store.put_settings(self.db, {"ai.key": json.dumps("sk-SECRET")})    # never exported
        d = self.doc()
        self.assertEqual((d["format"], d["version"], d["demo"]), (backup.FORMAT, backup.VERSION, True))
        self.assertEqual(set(d["data"]), set(backup.SECTIONS))
        self.assertTrue(d["data"]["profiles"] and d["data"]["bedtime_rules"])
        self.assertEqual(d["data"]["settings"], {"alerts.snooze_days": 3, "quiet.enabled": True,
                                                 "quiet.start": "23:00", "quiet.end": "07:00",
                                                 "ai.monthly_budget": "1"})   # round 7 C
        self.assertNotIn("SECRET", json.dumps(d))

    def test_roundtrip_into_an_empty_db(self):
        d = self.doc()
        with tempfile.TemporaryDirectory() as t:
            e = store.connect(Path(t) / "e.db")
            data = backup.validate(d)
            pv = backup.preview(e, data, "merge")
            secs = {s["key"]: s for s in pv["sections"]}
            self.assertGreater(secs["profiles"]["add"], 0)
            # a rule for a device this DB has never seen is skipped; an owner's rule is not
            self.assertEqual(secs["bedtime_rules"]["skipped"],
                             sum(1 for r in d["data"]["bedtime_rules"] if r["mac"]))
            backup.restore(e, data, "merge")
            self.assertEqual(backup.preview(e, data, "merge")["changes"], 0)
            self.assertEqual(settings.get(e, {}, "alerts.snooze_days"), 3)
            e.close()

    def test_merge_keeps_replace_removes(self):
        d = self.doc()
        mac = next(iter(store.get_profiles(self.db)))
        store.set_label(self.db, mac, "Only here", "")
        data = backup.validate(d)
        merge = {s["key"]: s for s in backup.preview(self.db, data, "merge")["sections"]}
        self.assertEqual(merge["labels"]["remove"], 0)
        rep = {s["key"]: s for s in backup.preview(self.db, data, "replace")["sections"]}
        self.assertEqual(rep["labels"]["remove"], 1)
        self.assertEqual(rep["labels"]["samples"][0]["op"], "remove")
        backup.restore(self.db, data, "replace")
        self.assertNotIn(mac, store.get_labels(self.db))

    def test_env_locked_settings_are_skipped(self):
        d = self.doc()
        d["data"]["settings"]["time.timezone"] = "Asia/Taipei"
        pv = backup.preview(self.db, backup.validate(d), "merge", {"NETWARDEN_TZ": "UTC"})
        self.assertEqual(next(s for s in pv["sections"] if s["key"] == "settings")["skipped"], 1)

    def test_strict_validation(self):
        good = self.doc()

        def bad(mutate, code="backup_invalid"):
            d = json.loads(json.dumps(good))
            mutate(d)
            with self.assertRaises(backup.BadBackup) as cm:
                backup.validate(d)
            self.assertEqual(cm.exception.code, code)

        bad(lambda d: d.update(format="other"), "backup_format")
        bad(lambda d: d.update(version=99), "backup_version")
        bad(lambda d: d.update(version="1"), "backup_format")
        bad(lambda d: d.update(data=[]), "backup_format")
        bad(lambda d: d["data"].update(labels={"a": 1}))
        bad(lambda d: d["data"].update(labels=[{"mac": "x" * 100, "label": "a"}]))
        bad(lambda d: d["data"].update(labels=[{"mac": "aa:bb:cc:dd:ee:ff", "label": ""}]))
        bad(lambda d: d["data"].update(profiles=[{"mac": "aa:bb:cc:dd:ee:ff", "type": "rocket"}]))
        bad(lambda d: d["data"].update(acks=[{"mac": "aa:bb:cc:dd:ee:ff", "key": "a\nb"}]))
        bad(lambda d: d["data"].update(acks=[{"mac": "aa:bb:cc:dd:ee:ff", "key": "", "until": "tomorrow"}]))
        bad(lambda d: d["data"].update(suggestions=[{"id": "../x", "status": "done"}]))
        bad(lambda d: d["data"].update(settings={"ai.key": "sk-x"}))
        bad(lambda d: d["data"].update(settings={"alerts.snooze_days": 500}))
        bad(lambda d: d["data"].update(settings={"no.such": 1}))
        bad(lambda d: d["data"].update(labels=[{"mac": "aa:bb:cc:dd:ee:ff", "label": "x"}] * (backup.MAX_ITEMS + 1)))
        with self.assertRaises(backup.BadBackup) as cm:
            backup.parse(b"{" + b" " * backup.MAX_BYTES)
        self.assertEqual(cm.exception.code, "backup_too_large")
        with self.assertRaises(backup.BadBackup) as cm:
            backup.parse(b"not json")
        self.assertEqual(cm.exception.code, "backup_format")
        with self.assertRaises(backup.BadBackup):
            backup.preview(self.db, backup.validate(good), "overwrite")

    def test_preview_names_devices(self):
        d = self.doc()
        with tempfile.TemporaryDirectory() as t:
            e = store.connect(Path(t) / "e.db")
            pv = backup.preview(e, backup.validate(d), "merge")
            e.close()
        prof = next(s for s in pv["sections"] if s["key"] == "profiles")
        self.assertLessEqual(len(prof["samples"]), backup.SAMPLES)


# --- first-run wizard ----------------------------------------------------------------

class FirstRunTests(_EmptyDB, unittest.TestCase):
    def test_status_and_save(self):
        s = firstrun.status(self.db, {})
        self.assertTrue(s["needed"])
        self.assertEqual((s["step"], s["steps"], s["dns"]["configured"]), ("dns", list(firstrun.STEPS), False))
        firstrun.save(self.db, step="ai")
        self.assertEqual(firstrun.status(self.db, {})["step"], "ai")
        for bad in ({"step": "evil"}, {"done": "yes"}, {}):
            with self.assertRaises(ValueError):
                firstrun.save(self.db, **bad)
        firstrun.save(self.db, done=True)
        s = firstrun.status(self.db, {"ADGUARD_URL": "http://127.0.0.1:1"})
        self.assertEqual((s["needed"], s["done"], s["dns"]["source"]), (False, True, "adguard"))

    def test_scan_job_with_a_fake_sweep(self):
        gate = threading.Event()

        def sweep(conn):
            gate.wait(5)
            return [{"mac": "aa:bb:cc:00:00:01"}, {"mac": "aa:bb:cc:00:00:02"}]

        job = firstrun.start_scan(self.path, sweep=sweep)
        self.assertEqual(job["state"], "running")
        self.assertEqual(firstrun.start_scan(self.path, sweep=sweep)["id"], job["id"])   # single flight
        gate.set()
        for _ in range(100):
            st = firstrun.scan_status(job["id"])
            if st["state"] != "running":
                break
            threading.Event().wait(0.05)
        self.assertEqual((st["state"], st["found"]), ("done", 2))
        self.assertIsNone(firstrun.scan_status("nope"))

    def test_scan_failure_is_reported_not_raised(self):
        with self.assertLogs("netwarden.firstrun", "WARNING"):
            job = firstrun.start_scan(self.path, sweep=lambda conn: 1 / 0)
            for _ in range(100):
                st = firstrun.scan_status(job["id"])
                if st["state"] != "running":
                    break
                threading.Event().wait(0.05)
        self.assertEqual((st["state"], st["error"]), ("error", "ZeroDivisionError"))


class FirstRunDemoTests(_DemoDB, unittest.TestCase):
    def test_demo_never_needs_setup_or_scans(self):
        s = firstrun.status(self.db, {})
        self.assertEqual((s["needed"], s["demo"], s["scan"]["available"], s["scan"]["reason"]),
                         (False, True, False, "demo_db"))
        with self.assertRaises(firstrun.SetupRefused) as cm:
            firstrun.start_scan(self.path, sweep=lambda c: [])
        self.assertEqual(cm.exception.code, "demo_db")


# --- the web API -------------------------------------------------------------------------

class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = demo_copy(Path(cls.tmp.name) / "w.db")
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def tearDown(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))

    def raw(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"content-type": ctype} if ctype else {}
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        c.request(method, path, body, headers)
        r = c.getresponse()
        return r, r.read()

    def req(self, method, path, body=None, ctype="application/json"):
        r, raw = self.raw(method, path, body, ctype)
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw.decode("utf-8")

    def test_inbox_get_and_act(self):
        st, r = self.req("GET", "/api/inbox?lang=zh-Hant")
        self.assertEqual(st, 200)
        it = next(i for i in r["items"] if i["kind"] == "spike")
        ref = {"kind": it["kind"], "mac": it["mac"], "key": it["key"]}
        st, r2 = self.req("POST", "/api/inbox/act", {"action": "ack", "items": [ref], "lang": "en"})
        self.assertEqual((st, r2["ok"], r2["n"]), (200, True, 1))
        self.assertEqual(r2["counts"]["total"], r["counts"]["total"] - 1)
        st, r3 = self.req("POST", "/api/inbox/act", {"action": "undo", "undo": "ack", "items": [ref]})
        self.assertEqual(r3["counts"]["total"], r["counts"]["total"])
        st, e = self.req("POST", "/api/inbox/act", {"action": "nuke", "items": [ref], "lang": "en"})
        self.assertEqual((st, e["error"]), (400, i18n.t("err.bad_action", "en")))
        self.assertEqual(self.req("POST", "/api/inbox/act", {"action": 1, "items": [ref]})[0], 400)
        self.assertEqual(self.req("POST", "/api/inbox/act", "{}", ctype="text/plain")[0], 415)

    def test_backup_download_preview_restore(self):
        r, raw = self.raw("GET", "/api/backup")
        self.assertEqual(r.status, 200)
        self.assertIn("attachment", r.getheader("content-disposition"))
        self.assertIn("netwarden-backup-", r.getheader("content-disposition"))
        doc = json.loads(raw)
        st, pv = self.req("POST", "/api/backup/preview", {"backup": doc, "mode": "merge"})
        self.assertEqual((st, pv["changes"]), (200, 0))
        doc["data"]["settings"]["alerts.snooze_days"] = 5
        st, pv = self.req("POST", "/api/backup/preview", {"backup": doc, "mode": "replace"})
        self.assertEqual(pv["changes"], 1)
        st, res = self.req("POST", "/api/restore", {"backup": doc, "mode": "merge"})
        self.assertEqual((st, res["ok"], res["changes"]), (200, True, 1))
        st, s = self.req("GET", "/api/settings")
        self.assertEqual(next(i for i in s["items"] if i["key"] == "alerts.snooze_days")["value"], 5)
        st, e = self.req("POST", "/api/restore", {"backup": {"format": "x"}, "lang": "de"})
        self.assertEqual((st, e["code"], e["error"]), (400, "backup_format", i18n.t("err.backup_format", "de")))
        st, e = self.req("POST", "/api/backup/preview", {"backup": doc, "mode": "wipe"})
        self.assertEqual((st, e["code"]), (400, "backup_mode"))
        # too large: refused from the content-length alone (nothing is read)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.putrequest("POST", "/api/restore")
        c.putheader("content-type", "application/json")
        c.putheader("content-length", str(web.MAX_BODY + 1))
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)
        c.close()

    def test_settings_body_has_sections_and_connections(self):
        st, s = self.req("GET", "/api/settings?lang=ja")
        self.assertEqual(st, 200)
        self.assertEqual(len(s["sections"]), 9)   # + Stage Q quiet hours, round 7 C AI usage, round 10 push
        self.assertEqual(set(s["connections"]["sources"]), set(conntest.SOURCES))
        self.assertTrue(s["demo"])

    def test_connection_test_endpoint(self):
        st, r = self.req("POST", "/api/test/adguard", {"lang": "zh-Hant"})
        self.assertEqual((st, r["ok"], r["error_kind"]), (200, False, "not_configured"))
        self.assertEqual(r["error_text"], i18n.t("err.conn_not_configured", "zh-Hant"))
        st, r = self.req("POST", "/api/test/ai", {})
        self.assertEqual(r["error_kind"], "offline")
        self.assertEqual(self.req("POST", "/api/test/router", {})[0], 404)

    def test_setup_endpoints(self):
        st, s = self.req("GET", "/api/setup")
        self.assertEqual((st, s["needed"], s["demo"], s["local"]), (200, False, True, True))
        st, s = self.req("POST", "/api/setup", {"step": "phone"})
        self.assertEqual((st, s["step"]), (200, "phone"))
        self.assertEqual(self.req("POST", "/api/setup", {"step": "<script>"})[0], 400)
        st, e = self.req("POST", "/api/setup/scan", {"lang": "en"})
        self.assertEqual((st, e["code"]), (409, "demo_db"))
        st, e = self.req("GET", "/api/setup/scan/status?job=nope")
        self.assertEqual(st, 404)

    def test_admin_paths_are_this_computer_only(self):
        for p in ("/api/backup/preview", "/api/restore", "/api/setup", "/api/setup/scan",
                  *("/api/test/" + s for s in conntest.SOURCES)):
            self.assertIn(p, web.ADMIN_POSTS)
        for p in ("/api/backup", "/api/setup/scan/status"):
            self.assertIn(p, web.ADMIN_GETS)
        web.Handler.is_local_client = staticmethod(lambda ip: False)     # "a phone"
        for method, p in (("GET", "/api/backup"), ("POST", "/api/restore"), ("POST", "/api/test/adguard"),
                          ("POST", "/api/setup"), ("GET", "/api/inbox")):
            st, _ = self.req(method, p, {} if method == "POST" else None)
            self.assertIn(st, (401, 403), p)

    def test_service_worker_and_offline_page(self):
        r, raw = self.raw("GET", "/sw.js")
        sw = raw.decode()
        self.assertEqual(r.status, 200)
        self.assertIn("javascript", r.getheader("content-type"))
        self.assertIn("no-cache", r.getheader("cache-control"))
        self.assertNotIn("__V__", sw)
        self.assertIn(web.asset_version(), sw)
        r, raw = self.raw("GET", "/offline")
        page = raw.decode()
        self.assertEqual(r.status, 200)
        self.assertIn(r"scripts\start_windows.cmd", page)
        self.assertNotIn("<script>", page)                     # CSP: only the JSON data block
        texts = json.loads(re.search(r'id="off-texts">(.*?)</script>', page, re.S).group(1))
        self.assertEqual(set(texts), set(LANGS))
        self.assertEqual(texts["zh-Hant"]["title"], i18n.t("app.offline.title", "zh-Hant"))
        self.assertEqual(self.raw("GET", "/static/offline.js")[0].status, 200)

    def test_server_texts_name_devices_not_macs(self):
        """Leftover (a): no name or sentence a person reads is a bare MAC (the demo has a
        nameless private-address phone)."""
        mac_re = re.compile(r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b")
        data_keys = {"mac", "device_mac", "key", "id", "href", "sid", "ack", "suggestion", "params",
                     "internal_client", "devices_macs", "macs", "target", "evidence", "devices",
                     "nkey", "suggestions"}   # (Stage Q: dedupe key; hygiene's suggestion ids)

        def walk(o, path, hits):
            if isinstance(o, str):
                if mac_re.search(o):
                    hits.append(f"{path}: {o[:80]}")
            elif isinstance(o, dict):
                for k, v in o.items():
                    if k not in data_keys or k == "devices" and isinstance(v, list) and v and isinstance(v[0], dict):
                        walk(v, f"{path}.{k}", hits)
            elif isinstance(o, list):
                for i, v in enumerate(o):
                    walk(v, f"{path}.{i}", hits)

        for p in ("/api/alerts", "/api/inbox", "/api/privacy", "/api/screentime", "/api/weekly",
                  "/api/score", "/api/suggestions", "/api/visibility", "/api/bedtime", "/api/upnp",
                  "/api/notify", "/api/hygiene"):
            for lang in ("en", "zh-Hant"):
                st, j = self.req("GET", f"{p}?lang={lang}")
                self.assertEqual(st, 200, p)
                hits = []
                walk(j, p, hits)
                self.assertEqual(hits, [], (p, lang))


# --- CLI --------------------------------------------------------------------------------

def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class CliTests(_DemoDB, unittest.TestCase):
    def test_backup_and_restore(self):
        f = Path(self.tmp.name) / "b.json"
        code, out, _ = run_cli("backup", "--db", str(self.path), "-o", str(f), "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn(str(f), out)
        e = Path(self.tmp.name) / "e.db"
        code, out, _ = run_cli("restore", str(f), "--db", str(e), "--dry-run", "--lang", "en")
        self.assertEqual(code, 0)
        self.assertIn(i18n.t("cli.restore.dry_run", "en"), out)
        code, out, _ = run_cli("restore", str(f), "--db", str(e), "--lang", "en")
        self.assertEqual(code, 0)
        code, out, _ = run_cli("restore", str(f), "--db", str(e), "--lang", "en")
        self.assertIn(i18n.t("cli.restore.nothing", "en"), out)
        store.set_label(self.db, next(iter(store.get_profiles(self.db))), "extra", "")
        code, out, err = run_cli("restore", str(f), "--db", str(self.path), "--mode", "replace", "--lang", "en")
        self.assertEqual(code, 1)
        self.assertIn("--yes", err)
        code, out, _ = run_cli("restore", str(f), "--db", str(self.path), "--mode", "replace", "--yes", "--lang", "en")
        self.assertEqual(code, 0)

    def test_restore_refuses_bad_files(self):
        f = Path(self.tmp.name) / "bad.json"
        f.write_text('{"format": "nope"}', encoding="utf-8")
        code, _out, err = run_cli("restore", str(f), "--db", str(self.path), "--lang", "en")
        self.assertEqual(code, 1)
        self.assertIn(i18n.t("err.backup_format", "en"), err)
        code, _out, err = run_cli("restore", str(f) + ".missing", "--db", str(self.path), "--lang", "en")
        self.assertEqual(code, 1)

    def test_backup_to_stdout_is_default_zh(self):
        code, out, _ = run_cli("backup", "--db", str(self.path), "-o", "-")
        self.assertEqual(json.loads(out)["format"], backup.FORMAT)


# --- demo story, warm-up, static files, scripts, locales -------------------------------

class DemoStoryTests(_DemoDB, unittest.TestCase):
    def test_setting_seeded_once_never_over_the_user(self):
        self.assertEqual(settings.get(self.db, {}, "alerts.snooze_days"), 3)
        settings.update(self.db, {}, {"alerts.snooze_days": 10})
        self.db.close()
        demo.build(self.path)
        self.db = store.connect(self.path)
        self.assertEqual(settings.get(self.db, {}, "alerts.snooze_days"), 10)
        # the demo writes no acks but its Stage Q tuning rows (once per DB)
        self.assertEqual({(a["mac"], a["domain"]) for a in store.all_acks(self.db)},
                         {(m, d) for m, d, _days in demo.DEMO_TUNING})


class ExportWarmTests(_DemoDB, unittest.TestCase):
    def test_window_is_memoized_and_warmed(self):
        with mock.patch.object(cache, "memo", wraps=cache.memo) as memo:
            first = export._window(self.db)
            again = export._window(self.db)
        self.assertIn("export.window", [c.args[1] for c in memo.call_args_list])
        self.assertEqual(first, again)
        self.assertGreater(runner.Warmer.EXPORT_FRESH, 0)
        self.assertIn("export._window(db)", Path(runner.__file__).read_text(encoding="utf-8"))


class StaticFileTests(unittest.TestCase):
    js = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
    sw = (ROOT / "netwarden" / "static" / "sw.js").read_text(encoding="utf-8")
    off = (ROOT / "netwarden" / "static" / "offline.js").read_text(encoding="utf-8")

    def test_service_worker_rules(self):
        self.assertIn("'__V__'", self.sw)
        self.assertIn("/api/", self.sw)                 # never cached
        self.assertIn("req.method !== 'GET'", self.sw)
        self.assertIn("req.mode === 'navigate'", self.sw)
        self.assertNotIn("https://", self.sw)
        self.assertIn("caches.delete", self.sw)         # old versions removed
        self.assertIn("'127.0.0.1'", self.js)
        self.assertIn("serviceWorker.register(url('/sw.js')", self.js)   # Stage H: base-aware

    def test_offline_page_script(self):
        self.assertIn("/api/meta", self.off)
        self.assertNotIn("innerHTML", self.off)

    def test_inbox_keys_and_no_new_innerhtml(self):
        self.assertEqual(self.js.count("innerHTML"), 2)
        for k in ("'j'", "'k'", "'a'", "'t'", "'m'", "'d'", "'s'", "'x'", "'u'"):
            self.assertIn(k, self.js)


class ScriptTests(unittest.TestCase):
    auto = (ROOT / "scripts" / "autostart_windows.cmd").read_bytes()
    start = (ROOT / "scripts" / "start_windows.cmd").read_bytes()

    def test_crlf(self):
        for body in (self.auto, self.start):
            self.assertNotIn(b"\n", body.replace(b"\r\n", b""))

    def test_autostart_only_touches_its_shortcut(self):
        t = self.auto.decode()
        for needle in (":install", ":uninstall", ":status", ":run", "--dry-run", "[dry run]",
                       "CreateShortcut", "Startup", "NW_STARTUP_DIR", "set \"NW_NO_OPEN=1\""):
            self.assertIn(needle, t)
        for never in ("reg add", "schtasks", "sc create", "runas", "Set-ExecutionPolicy", "http"):
            self.assertNotIn(never.lower(), t.lower())

    def test_start_honors_no_open(self):
        t = self.start.decode()
        self.assertIn("if defined NW_NO_OPEN exit /b 0", t)
        self.assertIn("%WINSTYLE%", t)


class LocaleTests(unittest.TestCase):
    DYNAMIC = (
        ["app.inbox.toast." + a for a in inbox.ACTIONS]
        + ["app.backup.mode_" + m for m in backup.MODES]
        + ["app.bk.mode_%s_hint" % m for m in backup.MODES]
        + ["app.backup.sec." + s for s in backup.SECTIONS]
        + ["app.conn." + s for s in conntest.SOURCES]
        + ["err.conn_" + k for k in conntest.ERROR_KINDS]
        + ["err.setup_" + k for k in ("demo_db", "no_ip_command", "no_lan")]
        + ["app.wz.step." + s for s in firstrun.STEPS]
        + ["app.offline." + k for k in web.OFFLINE_KEYS]
        + ["settings.section." + s for s, _ in settings.SECTIONS]
        + ["settings.help." + k for k in settings.REGISTRY]
        + ["err.backup_" + k for k in ("format", "version", "invalid", "too_large", "mode")]
        + ["cli.cmd.backup", "cli.cmd.restore"]
    )

    def test_dynamic_keys_everywhere(self):
        for code in LANGS:
            s = i18n.strings(code)
            for k in self.DYNAMIC:
                self.assertIn(k, s, (code, k))

    def test_terminology_is_unified(self):
        # "Got it" is one word per language for ack, and the toast says the same
        for code in LANGS:
            ack = i18n.t("ui.btn_ack", code)
            self.assertIn(ack.rstrip("!。.").split()[0], i18n.t("app.inbox.toast.ack", code, what="X"), code)


if __name__ == "__main__":
    unittest.main()
