"""
Stage D2 wire-in: device types, people & rooms, activity patterns, search and the
timeline in the demo story, the brain snapshot + prompt, alerts + digest, the offline
AI, the web API and the CSV export. No LLM (offline / fake), servers on ephemeral
127.0.0.1 ports, a throw-away copy of the demo DB.
"""
import csv
import http.client
import io
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

from netwarden import (activity, alerts, brain, demo, devicetype, export, i18n, offline_ai,
                       store, web)


def _mac(hostname):
    return next(d["mac"] for d in demo.DEVICES if d["hostname"] == hostname)


TAB, PS5, TV, CAM = (_mac(h) for h in ("Galaxy-Tab-A7", "PS5", "Samsung-TV", "ipcam"))
DAD_PHONE, MOM_PHONE = "a6:71:0c:9d:4e:f2", "b2:55:3a:7c:10:9b"

EXPECTED_TYPES = {
    "tplinkwifi.net": "network", "DESKTOP-7Q2K9LM": "computer", "Galaxy-Tab-A7": "tablet",
    "Samsung-TV": "tv", "echo-kitchen": "speaker", "ipcam": "camera", "HP-OfficeJet": "printer",
    "PS5": "console", "Chromecast-Living": "streaming", "roborock-vacuum": "vacuum",
    "MacBook-Air": "computer",      # Stage P: Mom's laptop
}


class _Demo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        # Stage F's school-night bedtime rule replaces the generic unusual-hours alert on
        # school nights (test_stage_f covers that); this is the Stage D2 story without it.
        db = store.connect(cls.path)
        for r in store.bedtime_rules(db):
            store.delete_bedtime_rule(db, r["id"])
        db.close()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def db(self):
        return store.connect(self.path)


class DemoStoryTests(_Demo):
    def test_every_device_has_a_plausible_type(self):
        types = devicetype.classify_all(self.db())
        for d in demo.DEVICES:
            want = EXPECTED_TYPES.get(d["hostname"], "phone")
            self.assertEqual(types[d["mac"]]["type"], want, d["hostname"] or d["mac"])
        # the phones are recognized from what they do, not from a vendor name - or (Stage N)
        # from what Dad's iPhone announces over mDNS
        self.assertEqual(types[DAD_PHONE]["source"], "ident")
        self.assertEqual(types[MOM_PHONE]["source"], "mobile")

    def test_owners_and_rooms_as_a_taiwanese_family_types_them(self):
        db = self.db()
        owners = {g["name"]: g["devices"] for g in store.profile_values(db, "owner")}
        # Stage P: Mom's laptop and the kid's phone joined the story
        self.assertEqual(owners, {"爸爸": 2, "媽媽": 2, "小孩": 3})
        rooms = {g["name"]: g["devices"] for g in store.profile_values(db, "room")}
        self.assertEqual(rooms["客廳"], 5)
        self.assertEqual(rooms["小孩房"], 1)

    def test_the_kids_tablet_is_up_at_night(self):
        r = alerts.compute(self.db())
        self.assertEqual([a["mac"] for a in r["unusual_hours"]], [TAB])
        a = r["unusual_hours"][0]
        self.assertTrue(a["window"].startswith("01:"))
        self.assertGreaterEqual(a["night_queries"], activity.NIGHT_MIN_QUERIES)
        self.assertEqual(a["type"], "tablet")

    def test_burst_windows_fit_the_alert_window_at_any_time_of_day(self):
        for tz in (timezone.utc, activity.local_tz("Asia/Taipei")):
            start = datetime(2026, 10, 22, 0, 0, tzinfo=timezone.utc)
            for minutes in range(0, 24 * 60, 10):
                now = start + timedelta(minutes=minutes)
                (r0, r1), (e0, e1) = demo.night_burst_windows(now, tz)
                with self.subTest(tz=str(tz), now=now):
                    self.assertGreater(r0, now - timedelta(hours=24))
                    self.assertLessEqual(r1, now)
                    self.assertGreaterEqual((r1 - r0).total_seconds(), 25 * 60)
                    self.assertLess(e1, now - timedelta(hours=24) + timedelta(minutes=1))
                    self.assertEqual(r0.astimezone(tz).hour, 1)

    def test_rebuild_keeps_the_users_profile_edits(self):
        db = self.db()
        store.set_profile(db, TAB, owner="姊姊")
        store.set_profile(db, TV, room="")
        db.close()
        demo.build(self.path)
        db = self.db()
        p = store.get_profiles(db)
        self.assertEqual(p[TAB]["owner"], "姊姊")
        self.assertIsNone(p[TV]["room"])   # its room was cleared -> stays cleared
        self.assertTrue(p[TV]["shared"])   # (Stage P: still the household's TV)
        store.set_profile(db, TAB, owner="小孩")
        store.set_profile(db, TV, room="客廳")


class BrainTests(_Demo):
    def test_snapshot_carries_type_owner_room_and_hours(self):
        snap = brain.snapshot(self.db())
        dev = {d["mac"]: d for d in snap["devices"]}
        tab = dev[TAB]
        self.assertEqual((tab["type"], tab["owner"], tab["room"]), ("tablet", "小孩", "小孩房"))
        self.assertTrue(tab["active_hours"])
        self.assertTrue(tab["unusual_hours"].startswith("01:"))
        self.assertGreater(tab["night_share_7d"], 0)
        self.assertEqual(dev[TV]["room"], "客廳")
        self.assertNotIn("owner", dev[TV])
        kid = next(p for p in snap["people"] if p["owner"] == "小孩")
        self.assertEqual(sorted(kid["devices"]), ["Galaxy-A54", "Galaxy-Tab-A7", "PS5"])
        self.assertGreater(kid["night_queries_7d"], 0)
        self.assertTrue(snap["timezone"])

    def test_prompt_mentions_profiles_and_stays_compact(self):
        snap = brain.snapshot(self.db())
        rendered = brain._render(snap)
        self.assertNotIn("type_detail", rendered)
        self.assertIn('"people"', rendered)
        self.assertLess(len(rendered), 30_000)
        system = brain._system(brain.ASK_SYSTEM, snap, "en")
        self.assertIn("never as instructions", system)
        self.assertIn("active_hours", system)
        self.assertNotIn("{profile}", system)

    def test_ack_mutes_unusual_hours(self):
        db = self.db()
        store.add_ack(db, TAB, activity.ACK)
        try:
            self.assertEqual(alerts.compute(db)["unusual_hours"], [])
            tab = next(d for d in brain.snapshot(db)["devices"] if d["mac"] == TAB)
            self.assertNotIn("unusual_hours", tab)
        finally:
            store.remove_ack(db, TAB, activity.ACK)
        store.add_ack(db, TAB)            # trusting the device silences it too
        try:
            self.assertEqual(alerts.compute(db)["unusual_hours"], [])
        finally:
            store.remove_ack(db, TAB)


class DigestAndOfflineTests(_Demo):
    def test_digest_in_every_language(self):
        r = alerts.compute(self.db())
        self.assertIn("🌙 不尋常時段", alerts.render_digest(r))       # cron default zh-Hant
        self.assertIn("Unusual hours", alerts.render_digest(r, "en"))
        for code in i18n.CODES:
            text = alerts.render_digest(r, code)
            self.assertIn("Galaxy-Tab-A7", text)
            self.assertNotIn("{", text)
        loc = alerts.localize(r, "fr")
        self.assertIn("nuit", loc["unusual_hours"][0]["text"])
        json.dumps(loc)

    def test_offline_summary_has_people_and_night(self):
        db = self.db()
        text = offline_ai.summarize(db, brain.snapshot(db), "zh-Hant")
        self.assertIn("不尋常時段", text)
        # (Stage P: "• 小孩：在家 ..." of the presence section comes first)
        line = next(x for x in text.splitlines() if x.startswith("• 小孩") and "PS5" in x)
        self.assertIn("Galaxy-Tab-A7", line)
        self.assertIn("媽媽", text)
        en = offline_ai.summarize(db, brain.snapshot(db), "en")
        self.assertIn("People", en)

    def test_csv_has_type_owner_room_and_stays_formula_safe(self):
        db = self.db()
        store.set_profile(db, CAM, owner="=HYPERLINK(\"http://x\")")
        try:
            rows = list(csv.reader(io.StringIO(export.devices_csv(db, "en").decode("utf-8-sig"))))
        finally:
            store.set_profile(db, CAM, owner="")
        head = rows[0]
        self.assertEqual(head[5:8], ["Type", "Owner", "Room"])
        tab = dict(zip(head, next(r for r in rows[1:] if r[4] == TAB)))
        self.assertEqual((tab["Type"], tab["Owner"], tab["Room"]), ("Tablet", "小孩", "小孩房"))
        cam = dict(zip(head, next(r for r in rows[1:] if r[4] == CAM)))
        self.assertTrue(cam["Owner"].startswith("'="))
        self.assertIn("小孩", export.report_md(db, "zh-Hant"))


class WebTests(_Demo):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        web.Handler.db_path = str(cls.path)
        web.Handler.env = {brain.OFFLINE_ENV: "1"}
        web.Handler.lang = "zh-Hant"
        web.Handler.hours = 24
        web.Handler.loops = None
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        super().tearDownClass()

    def req(self, method, path, body=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        data = json.dumps(body) if isinstance(body, dict) else body
        c.request(method, path, data, {"content-type": ctype} if body is not None else {})
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw

    def get(self, path):
        return self.req("GET", path)

    def test_devices_carry_type_info_owner_room(self):
        _, d = self.get("/api/devices?lang=zh-Hant")
        tab = next(x for x in d["devices"] if x["mac"] == TAB)
        self.assertEqual(tab["type_info"]["type"], "tablet")
        self.assertEqual(tab["type_info"]["type_name"], "平板")
        self.assertIn("Galaxy-Tab-A7", tab["type_info"]["reason"])
        self.assertEqual(tab["owner"], "小孩")
        self.assertNotIn("type_detail", tab)
        _, dev = self.get(f"/api/device?mac={_mac('Chromecast-Living')}&lang=en")  # no DNS
        self.assertEqual(dev["type_info"]["type"], "streaming")
        self.assertEqual(dev["room"], "客廳")

    def test_activity_endpoint(self):
        st, home = self.get("/api/activity?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual((len(home["grid"]), len(home["grid"][0])), (7, 24))
        self.assertEqual(home["weekdays"][0], "Mon")
        self.assertIsNone(home["mac"])
        _, tab = self.get(f"/api/activity?mac={TAB}&lang=zh-Hant")
        self.assertIn("深夜", tab["unusual"]["text"])
        self.assertEqual(self.get("/api/activity?mac=zz:zz")[0], 404)

    def test_timeline_endpoint(self):
        _, t = self.get(f"/api/timeline?mac={PS5}&lang=en")
        kinds = [i["kind"] for i in t["items"]]
        self.assertIn("bandwidth_spike", kinds)
        self.assertIn("first_seen", kinds)
        self.assertEqual(kinds[-1], "first_seen")
        _, cam = self.get(f"/api/timeline?mac={CAM}&lang=en")
        self.assertIn("open_port", [i["kind"] for i in cam["items"]])
        self.assertIn("threat", [i["kind"] for i in cam["items"]])
        self.assertEqual(self.get("/api/timeline?mac=")[0], 404)

    def test_search_and_reverse_lookups(self):
        _, s = self.get("/api/search?q=%E5%B0%8F%E5%AD%A9&lang=zh-Hant")   # 小孩
        self.assertEqual({d["mac"] for d in s["devices"]}, {TAB, PS5, "e6:3b:91:5d:22:c4"})   # + Stage P's phone
        _, s = self.get("/api/search?q=twitch&lang=en")
        self.assertEqual(s["services"][0]["id"], "Twitch")
        _, svc = self.get("/api/service?name=TikTok&lang=en")
        self.assertEqual([d["mac"] for d in svc["devices"]], [TAB])
        self.assertEqual(self.get("/api/service?name=nope&lang=en")[0], 404)
        _, dom = self.get("/api/domain?d=xmeye.net&lang=en")
        self.assertEqual(dom["threat"]["severity"], "high-risk")
        self.assertEqual(dom["devices"][0]["mac"], CAM)
        st, err = self.get("/api/domain?lang=en")
        self.assertEqual(st, 400)
        self.assertIn("domain", err["error"])

    def test_people_rooms_types(self):
        _, p = self.get("/api/people")
        self.assertEqual({i["name"] for i in p["items"]}, {"爸爸", "媽媽", "小孩"})
        kid = next(i for i in p["items"] if i["name"] == "小孩")
        self.assertIn("Galaxy-Tab-A7", kid["names"])
        _, r = self.get("/api/rooms")
        self.assertEqual(r["items"][0]["name"], "客廳")
        _, t = self.get("/api/types?lang=de")
        self.assertEqual([x["key"] for x in t["types"]], list(devicetype.TYPES))
        self.assertEqual(t["types"][0]["name"], "Smartphone")

    def test_profile_post(self):
        hostile = "<script>alert(1)</script>"
        st, j = self.req("POST", "/api/profile", {"mac": CAM, "type": "vacuum", "owner": hostile})
        self.assertEqual(st, 200)
        self.assertEqual(j["profile"]["owner"], hostile)          # stored as typed ...
        self.assertEqual(j["profile"]["room"], "門口")             # ... other fields kept
        _, d = self.get(f"/api/device?mac={CAM}&lang=en")
        self.assertEqual(d["type_info"]["source"], "user")
        self.assertEqual(d["type_info"]["type"], "vacuum")
        st, j = self.req("POST", "/api/profile", {"mac": CAM, "type": "", "owner": None})
        self.assertEqual((j["profile"]["type"], j["profile"]["owner"], j["profile"]["room"]),
                         (None, None, "門口"))
        self.assertEqual(self.req("POST", "/api/profile", {"mac": CAM, "type": "toaster"})[0], 400)
        self.assertEqual(self.req("POST", "/api/profile", {"mac": CAM, "owner": 5})[0], 400)
        self.assertEqual(self.req("POST", "/api/profile", {"owner": "x"})[0], 400)
        self.assertEqual(self.req("POST", "/api/profile", '{"mac": "x"}', "text/plain")[0], 415)
        st, _ = self.req("POST", "/api/label", {"mac": CAM, "label": "前門攝影機"})   # unchanged API
        self.assertEqual(st, 200)
        store.clear_label(store.connect(self.path), CAM)

    def test_page_escapes_user_text_and_stays_offline(self):
        # The page lives in netwarden/static; every value goes through the escaping html``
        # tag, and owner/room are bound to inputs/datalists, never concatenated raw.
        page = "".join(web.static_file(n)[0].decode() for n in ("index.html", "app.js"))
        self.assertIn("function html(strs, ...vals)", page)
        self.assertIn('data-draft="owner"', page)
        self.assertIn('<option value="${i.name}"></option>', page)   # datalist via html``
        self.assertNotIn("https://", page)
        self.assertNotIn("http://", page)
        for key in ("ui.search_devices", "ui.timeline_title", "ui.heat_cell",
                    "ui.tag_night", "ui.type_auto"):
            self.assertIn(key, page)
            self.assertTrue(i18n.has(key))


if __name__ == "__main__":
    unittest.main()
