"""Stage F: family insights - screen-time estimates, bedtime rules (notify only),
week over week, the printable weekly report, the digest's family section, the demo story.

No network: synthetic SQLite stores, the deterministic demo home and the stdlib web server
on an ephemeral 127.0.0.1 port (offline AI forced)."""

import http.client
import json
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from unittest import mock

from netwarden import (activity, alerts, bedtime, brain, demo, family_report, i18n,
                       privacy, screentime, store, web, weekly)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
TZ8 = timezone(timedelta(hours=8))
KID, DAD, TV = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
TABLET = "9e:88:44:21:af:30"


def _event(mac, ip, t, domain, blocked=0, n=0):
    return {"source": "test", "ts": t.astimezone(timezone.utc).strftime(ISO)[:-4] + f"{n:03d}Z",
            "client_ip": ip, "client_name": None, "domain": domain, "qtype": "A",
            "status": "NOERROR", "reason": "x", "blocked": blocked, "block_reason": None,
            "cached": 0, "upstream": None, "elapsed_ms": 1.0, "device_mac": mac}


class _Store:
    """A small home in a temp file: devices KID (owner Kid), DAD, TV."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "f.db"
        self.db = store.connect(self.path)
        seen = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(ISO)
        for i, mac in enumerate((KID, DAD, TV)):
            store.upsert_device(self.db, {"ip": f"10.0.0.{i + 2}", "mac": mac, "vendor": "",
                                          "hostname": ["kid-tab", "dad-phone", "tv"][i],
                                          "randomized": 0, "is_self": 0}, seen=seen)
        store.set_profile(self.db, KID, owner="Kid")
        self.n = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def look(self, mac, start, end, domain, every=2, blocked=0):
        """One lookup of `domain` every `every` minutes from start to end (inclusive)."""
        ip = {KID: "10.0.0.2", DAD: "10.0.0.3", TV: "10.0.0.4"}[mac]
        evs, t = [], start
        while t <= end:
            self.n += 1
            evs.append(_event(mac, ip, t, domain, blocked, self.n % 1000))
            t += timedelta(minutes=every)
        store.insert_events(self.db, evs)


class SessionTests(unittest.TestCase):
    def test_sessions_gap_tail_and_minimum(self):
        self.assertEqual(screentime.sessions([0, 60, 120], 900, 300), [[0, 420]])
        self.assertEqual(screentime.sessions([0], 900, 300), [])          # one lookup: no session
        self.assertEqual(screentime.sessions([0, 60, 2000, 2060], 900, 300),
                         [[0, 360], [2000, 2360]])
        self.assertEqual(screentime.sessions([0, 600, 1200], 300, 60), [])  # all isolated
        self.assertEqual(screentime.merge([[5, 9], [0, 6], [20, 30]]), [[0, 9], [20, 30]])
        self.assertEqual(screentime.overlap([[0, 100], [200, 300]], 50, 250), 100)

    def test_classify(self):
        self.assertEqual(screentime.classify("www.youtube.com")[1], "video")
        self.assertEqual(screentime.classify("apis.roblox.com")[1], "games")
        self.assertEqual(screentime.classify("www.junyiacademy.org")[1], "education")
        for d in ("connectivitycheck.gstatic.com", "time.apple.com",      # routine
                  "doubleclick.net", "unknown-site.example",                # tracker / unknown
                  "api.anthropic.com"):                                     # a machine
            self.assertIsNone(screentime.classify(d), d)

    def test_pieces_half_hour_timezone(self):
        ist = timezone(timedelta(hours=5, minutes=30))
        s = datetime(2026, 10, 20, 18, 0, tzinfo=timezone.utc).timestamp()   # 23:30 local
        parts = dict(screentime._pieces(s, s + 3600, ist))
        self.assertEqual(parts, {("2026-10-20", 23): 1800, ("2026-10-21", 0): 1800})


class ScreenTimeTests(_Store, unittest.TestCase):
    now = datetime(2026, 10, 21, 12, 0, tzinfo=TZ8)        # a Wednesday, local noon

    def test_youtube_evening_counts_routine_blocked_do_not(self):
        start = datetime(2026, 10, 20, 21, 0, tzinfo=TZ8)
        self.look(KID, start, start + timedelta(minutes=60), "www.youtube.com", every=3)
        self.look(KID, start, start + timedelta(hours=3), "connectivitycheck.gstatic.com", every=1)
        self.look(DAD, start, start + timedelta(hours=1), "www.youtube.com", blocked=1)
        self.look(TV, start, start, "www.netflix.com")           # a single lookup: no session
        r = screentime.report(self.db, "en", tz=TZ8, now=self.now)
        self.assertEqual(r["minutes"], 65)                        # 60 min + the 5 min tail
        self.assertEqual([d["mac"] for d in r["devices"]], [KID])
        kid = r["members"][0]
        self.assertEqual((kid["owner"], kid["minutes"]), ("Kid", 65))
        self.assertEqual(kid["top_services"][0]["name"], "YouTube")
        self.assertEqual([x["minutes"] for x in kid["by_day"]][-2:], [65, 0])
        self.assertEqual(r["categories"][0], {"key": "video", "name": screentime.category_name("video", "en"), "minutes": 65})
        self.assertIn("estimates", r["note"])

    def test_hour_cap_and_overlapping_apps(self):
        start = datetime(2026, 10, 20, 10, 0, tzinfo=TZ8)
        self.look(KID, start, start + timedelta(minutes=59), "www.youtube.com", every=1)
        self.look(KID, start, start + timedelta(minutes=59), "apis.roblox.com", every=1)
        data = screentime.compute(self.db, TZ8, self.now)
        day = data["devices"][KID]["days"]["2026-10-20"]
        union = sum(e - s for s, e in data["devices"][KID]["union"])
        self.assertAlmostEqual(day["total"], union, delta=1)     # two apps, one device: no double count
        self.assertLessEqual(day["total"], 3600 + 300)           # <= 60 min in hour 10 (+ tail in 11)
        self.assertAlmostEqual(sum(day["svc"].values()), day["total"], delta=1)

    def test_filters_and_today_text(self):
        today = datetime(2026, 10, 21, 8, 0, tzinfo=TZ8)
        self.look(KID, today, today + timedelta(minutes=80), "www.youtube.com", every=4)
        self.look(DAD, today, today + timedelta(minutes=20), "i.instagram.com", every=2)
        r = screentime.report(self.db, "en", mac=KID, tz=TZ8, now=self.now)
        self.assertEqual([d["mac"] for d in r["devices"]], [KID])
        self.assertEqual(r["devices"][0]["today_text"], "About 1 h 25 min on YouTube today.")
        r = screentime.report(self.db, "zh-Hant", owner="Kid", tz=TZ8, now=self.now)
        self.assertEqual([m["owner"] for m in r["members"]], ["Kid"])
        self.assertIn("YouTube", r["devices"][0]["today_text"])
        r = screentime.report(self.db, "en", days=3, tz=TZ8, now=self.now)
        self.assertEqual(len(r["by_day"]), 3)
        self.assertEqual(screentime.duration(0.2, "en"), "< 1 min")
        self.assertEqual(screentime.duration(120, "de"), "2 Std.")


class BedtimeTests(_Store, unittest.TestCase):
    now = datetime(2026, 10, 21, 12, 0, tzinfo=TZ8)
    RULE = {"name": "School nights", "owner": "Kid", "days": [0, 1, 2, 3, 6],
            "start": "22:00", "end": "07:00", "min_minutes": 15}

    def test_validate(self):
        ok = bedtime.validate(self.db, dict(self.RULE))
        self.assertEqual((ok["owner"], ok["mac"], ok["enabled"], ok["days"]), ("Kid", None, True, [0, 1, 2, 3, 6]))
        self.assertEqual(bedtime.validate(self.db, {**self.RULE, "owner": None, "mac": KID.upper()})["mac"], KID)
        bad = [({"owner": "Kid", "mac": KID}, "bad_rule_target"), ({"owner": ""}, "bad_rule_target"),
               ({"owner": None, "mac": "02:99:99:99:99:99"}, "bad_rule_target"),
               ({"days": []}, "bad_rule_days"), ({"days": [7]}, "bad_rule_days"),
               ({"days": [1, 1]}, "bad_rule_days"), ({"days": [True]}, "bad_rule_days"),
               ({"start": "24:00"}, "bad_rule_time"), ({"end": "22:00"}, "bad_rule_time"),
               ({"start": "9:00"}, "bad_rule_time"), ({"min_minutes": 0}, "bad_rule_minutes"),
               ({"min_minutes": 241}, "bad_rule_minutes"), ({"min_minutes": "15"}, "bad_rule_minutes"),
               ({"enabled": "yes"}, "bad_rule"), ({"id": 0}, "bad_rule"), ({"name": "x" * 201}, "bad_rule_name")]
        for change, code in bad:
            with self.assertRaises(bedtime.BadRule, msg=change) as cm:
                bedtime.validate(self.db, {**self.RULE, **change})
            self.assertEqual(cm.exception.code, code, change)
        with self.assertRaises(bedtime.BadRule):
            bedtime.validate(self.db, ["not", "a", "dict"])
        self.assertEqual(len(bedtime.validate(self.db, {**self.RULE, "name": "x" * 150})["name"]), bedtime.MAX_NAME)

    def test_windows_cross_midnight(self):
        night = datetime(2026, 10, 20).date()
        s, e = bedtime.window(self.RULE, night, TZ8)
        self.assertEqual((s.isoformat(), e.isoformat()), ("2026-10-20T22:00:00+08:00", "2026-10-21T07:00:00+08:00"))
        s, e = bedtime.window({**self.RULE, "start": "13:00", "end": "15:00"}, night, TZ8)
        self.assertEqual(e.date(), night)
        occ = bedtime.occurrences(self.RULE, self.now - timedelta(days=7), self.now, TZ8)
        self.assertEqual([d.weekday() for d, _s, _e in occ], [2, 3, 6, 0, 1])   # Wed 10-14 .. Tue 10-20 (Tue 10-13's ended before)

    def test_hits_threshold_and_acks(self):
        late = datetime(2026, 10, 20, 21, 0, tzinfo=TZ8)                    # Tue: 21:00-22:40
        self.look(KID, late, late + timedelta(minutes=100), "www.youtube.com", every=3)
        rule = {**bedtime.validate(self.db, dict(self.RULE)), "id": 7}
        hs = bedtime.hits(self.db, rule, self.now - timedelta(days=7), self.now, TZ8)
        self.assertEqual(len(hs), 1)
        h = hs[0]
        self.assertEqual((h["mac"], h["night"], h["ack"]), (KID, "2026-10-20", "bedtime:7:2026-10-20"))
        self.assertEqual(h["minutes"], 44)                       # 22:00 -> 22:44 (last lookup 22:39 + tail)
        self.assertEqual(h["service_id"], "YouTube")
        self.assertEqual(bedtime.hits(self.db, {**rule, "min_minutes": 60}, self.now - timedelta(days=7), self.now, TZ8), [])
        self.assertEqual(bedtime.hits(self.db, {**rule, "days": [4]}, self.now - timedelta(days=7), self.now, TZ8), [])
        text = bedtime.localize_hit(h, {KID: "kid-tab"}, "en")["text"]
        self.assertEqual(text, "kid-tab was in use for about 44 min after bedtime (22:00–07:00, night of Tue 10/20), mostly YouTube.")
        # stored + previewed through the public API shapes
        rid = store.save_bedtime_rule(self.db, bedtime.validate(self.db, dict(self.RULE)))
        p = bedtime.preview(self.db, bedtime.validate(self.db, dict(self.RULE)), "en", tz=TZ8, now=self.now)
        self.assertIn("Tue 10/20", p["summary"])
        rep = bedtime.report(self.db, "zh-Hant", tz=TZ8, now=self.now)
        self.assertEqual(rep["rules"][0]["id"], rid)
        self.assertEqual(rep["people"], ["Kid"])
        self.assertIn("+08:00", rep["note"])
        self.assertNotIn("{tz}", rep["note"])
        # the 24 h alert, muted per night by its ack key
        a = bedtime.alerts(self.db, tz=TZ8, now=datetime(2026, 10, 21, 8, 0, tzinfo=TZ8))
        self.assertEqual([x["ack"] for x in a], [f"bedtime:{rid}:2026-10-20"])
        self.assertEqual(bedtime.alerts(self.db, tz=TZ8, now=self.now + timedelta(days=2)), [])
        store.save_bedtime_rule(self.db, {**store.bedtime_rules(self.db)[0], "enabled": False})
        self.assertEqual(bedtime.alerts(self.db, tz=TZ8, now=datetime(2026, 10, 21, 8, 0, tzinfo=TZ8)), [])

    def test_suppresses_unusual_hours_inside_a_rule(self):
        night = [{"mac": KID, "first_ts": "2026-10-20T16:10:00.000000Z", "last_ts": "2026-10-20T18:00:00.000000Z"},   # 00:10-02:00
                 {"mac": DAD, "first_ts": "2026-10-20T16:10:00.000000Z", "last_ts": "2026-10-20T18:00:00.000000Z"},
                 {"mac": KID, "first_ts": "2026-10-21T00:30:00.000000Z", "last_ts": "2026-10-21T01:00:00.000000Z"}]  # 08:30: outside
        self.assertEqual(bedtime.suppress_night(self.db, night, TZ8), night)                 # no rules yet
        store.save_bedtime_rule(self.db, bedtime.validate(self.db, {**self.RULE, "days": [0, 1, 2, 3, 4, 5, 6]}))
        kept = bedtime.suppress_night(self.db, night, TZ8)
        self.assertEqual([(a["mac"], a["first_ts"][:13]) for a in kept], [(DAD, "2026-10-20T16"), (KID, "2026-10-21T00")])

    def test_store_roundtrip_and_delete(self):
        rid = store.save_bedtime_rule(self.db, bedtime.validate(self.db, dict(self.RULE)))
        self.assertEqual(store.bedtime_rules(self.db)[0]["start"], "22:00")
        gone = store.delete_bedtime_rule(self.db, rid)
        self.assertEqual(gone["id"], rid)
        self.assertIsNone(store.delete_bedtime_rule(self.db, rid))
        self.assertEqual(store.save_bedtime_rule(self.db, gone), rid)   # Undo keeps the id


class WeeklyTests(_Store, unittest.TestCase):
    now = datetime(2026, 10, 21, 12, 0, tzinfo=TZ8)

    def test_no_history(self):
        c = weekly.compare(self.db, TZ8, self.now)
        self.assertFalse(c["has_history"])
        self.assertEqual(weekly.highlights(c, "en"), [i18n.t("wow.no_history", "en")])

    def test_up_and_new_services(self):
        for back in range(1, 14):
            day = datetime(2026, 10, 21, 19, 0, tzinfo=TZ8) - timedelta(days=back)
            mins = 40 if back < 7 else 30
            self.look(KID, day, day + timedelta(minutes=mins), "www.youtube.com", every=2)
            if back < 3:
                self.look(KID, day + timedelta(hours=1), day + timedelta(hours=1, minutes=20), "apis.roblox.com")
        c = weekly.compare(self.db, TZ8, self.now)
        self.assertTrue(c["has_history"])
        m = c["home"]["minutes"]
        self.assertGreater(m["this"], m["last"])
        self.assertEqual(m["pct"], weekly.pct(m["this"], m["last"]))
        self.assertEqual(c["home"]["new_service_ids"], ["Roblox"])
        self.assertEqual(c["devices"][0]["mac"], KID)
        hl = weekly.report(self.db, "en", tz=TZ8, now=self.now)["highlights"]
        self.assertTrue(hl[0].startswith("Screen time is up"), hl)
        self.assertTrue(any("Roblox" in h for h in hl), hl)
        for lang in i18n.CODES:
            self.assertTrue(weekly.highlights(c, lang))
        self.assertIsNone(weekly.pct(5, 0))


class DemoStoryTests(unittest.TestCase):
    """The demo home tells the Stage F story whatever the day of the week."""

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

    def test_week_up_about_thirty_percent(self):
        c = weekly.compare(self.db)
        self.assertTrue(c["has_history"])
        self.assertTrue(18 <= c["home"]["minutes"]["pct"] <= 45, c["home"]["minutes"])
        self.assertEqual(c["devices"][0]["mac"], TABLET)               # the tablet changed most

    def test_members_and_tv(self):
        r = screentime.report(self.db, "en")
        owners = {m["owner"]: m for m in r["members"]}
        self.assertEqual(set(owners), {"小孩", "爸爸", "媽媽", None})
        kid = [s["name"] for s in owners["小孩"]["top_services"][:2]]
        self.assertEqual(set(kid), {"YouTube", "Roblox"})
        self.assertGreater(owners["小孩"]["minutes"], 3 * owners["爸爸"]["minutes"])
        self.assertEqual(owners[None]["top_services"][0]["name"], "Netflix")
        # the TV keeps its Stage D1 privacy grade F
        tv = [d for d in privacy.report(self.db)["devices"] if d["mac"] == "8c:79:f5:0b:cd:12"]
        self.assertEqual(tv[0]["grade"], "F")

    def test_bedtime_rule_and_preview(self):
        rules = store.bedtime_rules(self.db)
        self.assertEqual([(r["owner"], r["start"], r["end"]) for r in rules], [("小孩", "22:00", "07:00")])
        rep = bedtime.report(self.db, "en")
        nights = {h["night"] for h in rep["rules"][0]["hits"]}
        self.assertGreaterEqual(len(nights), 3)
        self.assertTrue(all(h["mac"] == TABLET for h in rep["rules"][0]["hits"]))
        self.assertTrue(all(datetime.fromisoformat(n).weekday() in demo.SCHOOL_NIGHTS for n in nights))
        # the rule is seeded once: a rebuild keeps the user's edit
        store.save_bedtime_rule(self.db, {**rules[0], "min_minutes": 30})
        demo.build(self.path)
        self.assertEqual([r["min_minutes"] for r in store.bedtime_rules(self.db)], [30])
        store.save_bedtime_rule(self.db, rules[0])

    def test_digest_family_section_all_languages(self):
        r = alerts.compute(self.db)
        self.assertIn("family", r)
        for lang in i18n.CODES:
            text = alerts.render_digest(r, lang)
            self.assertIn(i18n.t("digest.family", lang), text, lang)
            self.assertIn(i18n.t("digest.family_note", lang), text, lang)
        default = alerts.render_digest(r)
        self.assertIn(i18n.t("digest.family", "zh-Hant"), default)
        self.assertIn("小孩", default)

    def test_bedtime_alert_digest_and_ack(self):
        tz = activity.local_tz()
        now = datetime.now(tz)
        # pin "now" to the morning after the latest school night of the demo week
        d = now.date()
        while d.weekday() not in demo.SCHOOL_NIGHTS or datetime.combine(d, datetime.min.time(), tz) > now - timedelta(days=1):
            d -= timedelta(days=1)
        morning = datetime.combine(d + timedelta(days=1), datetime.min.time(), tz) + timedelta(hours=8)
        a = bedtime.alerts(self.db, now=morning)
        self.assertEqual({x["mac"] for x in a}, {TABLET})
        self.assertTrue(all(x["ack"].startswith("bedtime:") for x in a))
        self.assertIn("after bedtime", bedtime.localize_hit(a[0], {}, "en")["text"])
        with mock.patch.object(bedtime, "alerts", return_value=a):
            r = alerts.compute(self.db)
            # (Stage Q adds each alert's tuning "level")
            self.assertEqual([{k: v for k, v in b.items() if k != "level"} for b in r["bedtime"]], a)
            self.assertIn(i18n.t("digest.bedtime", "en"), alerts.render_digest(r, "en"))
            # "Got it" mutes that one night
            store.add_ack(self.db, TABLET, a[0]["ack"])
        try:
            with mock.patch.object(bedtime, "alerts", return_value=a):
                self.assertEqual([b["ack"] for b in alerts.compute(self.db)["bedtime"]],
                                 [b["ack"] for b in a[1:]])
        finally:
            self.db.execute("DELETE FROM acks WHERE domain = ?", (a[0]["ack"],))
            self.db.commit()


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        db = store.connect(cls.path)
        store.set_profile(db, "8c:79:f5:0b:cd:12", owner='<script>alert(1)</script>"&')
        db.close()
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
            return r.status, json.loads(raw), r
        except ValueError:
            return r.status, raw.decode("utf-8"), r

    def test_screentime_endpoint(self):
        st, r, _ = self.req("GET", "/api/screentime?days=7&lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertEqual(len(r["by_day"]), 7)
        self.assertIn("估算", r["note"])
        st, r, _ = self.req("GET", f"/api/screentime?device={TABLET}&lang=en")
        self.assertEqual([d["mac"] for d in r["devices"]], [TABLET])
        self.assertTrue(r["devices"][0]["today_text"])
        st, r, _ = self.req("GET", "/api/screentime?owner=%E5%B0%8F%E5%AD%A9&lang=en")
        self.assertEqual([m["owner"] for m in r["members"]], ["小孩"])
        for bad in ("0", "15", "x", "-1"):
            self.assertEqual(self.req("GET", f"/api/screentime?days={bad}")[0], 400)
        self.assertEqual(self.req("GET", "/api/screentime?device=02:99:99:99:99:99")[0], 404)

    def test_weekly_and_bedtime_get(self):
        st, w, _ = self.req("GET", "/api/weekly?lang=en")
        self.assertEqual(st, 200)
        self.assertTrue(w["highlights"][0].startswith("Screen time is up"))
        st, b, _ = self.req("GET", "/api/bedtime?lang=en")
        self.assertEqual(len(b["rules"]), 1)
        self.assertIn("Notify only", b["note"])

    def test_bedtime_post_flow(self):
        rule = {"name": "Dad <b>", "mac": "a6:71:0c:9d:4e:f2", "days": [4, 5], "start": "23:30",
                "end": "06:00", "min_minutes": 20}
        self.assertEqual(self.req("POST", "/api/bedtime", {"rule": rule}, ctype="text/plain")[0], 415)
        st, p, _ = self.req("POST", "/api/bedtime/preview", {"rule": rule, "lang": "en"})
        self.assertEqual(st, 200)
        self.assertIn("In the last 7 days", p["summary"])
        st, e, _ = self.req("POST", "/api/bedtime/preview", {"rule": {**rule, "days": []}, "lang": "en"})
        self.assertEqual((st, e["field"]), (400, "days"))
        self.assertEqual(e["error"], i18n.t("err.bad_rule_days", "en"))
        st, e, _ = self.req("POST", "/api/bedtime", {"rule": {**rule, "id": 999}})
        self.assertEqual(st, 404)
        st, saved, _ = self.req("POST", "/api/bedtime", {"rule": rule, "lang": "en"})
        self.assertEqual(st, 200)
        rid = saved["id"]
        self.assertEqual(len(saved["rules"]), 2)
        st, saved, _ = self.req("POST", "/api/bedtime", {"rule": {**rule, "id": rid, "enabled": False}})
        self.assertFalse([r for r in saved["rules"] if r["id"] == rid][0]["enabled"])
        st, gone, _ = self.req("POST", "/api/bedtime/delete", {"id": rid})
        self.assertEqual((st, gone["deleted"]["id"]), (200, rid))
        self.assertEqual(self.req("POST", "/api/bedtime/delete", {"id": rid})[0], 404)
        self.assertEqual(self.req("POST", "/api/bedtime/delete", {"id": "1"})[0], 400)
        # Undo: restore keeps the id
        st, back, _ = self.req("POST", "/api/bedtime", {"rule": gone["deleted"], "restore": True})
        self.assertEqual((st, back["id"]), (200, rid))
        self.req("POST", "/api/bedtime/delete", {"id": rid})

    def test_too_many_rules(self):
        db = store.connect(self.path)
        try:
            ids = [store.save_bedtime_rule(db, {"id": None, "name": f"r{i}", "owner": "爸爸", "mac": None,
                                                "days": [1], "start": "23:00", "end": "06:00",
                                                "min_minutes": 10, "enabled": False})
                   for i in range(bedtime.MAX_RULES - len(store.bedtime_rules(db)))]
            rule = {"owner": "媽媽", "days": [1], "start": "23:00", "end": "06:00"}
            self.assertEqual(self.req("POST", "/api/bedtime", {"rule": rule})[0], 409)
        finally:
            for i in ids:
                store.delete_bedtime_rule(db, i)
            db.close()

    def test_report_page_escaped_with_csp(self):
        st, body, r = self.req("GET", "/report/weekly?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertIn("text/html", r.getheader("content-type"))
        self.assertIn("script-src 'self'", r.getheader("content-security-policy"))
        self.assertNotIn("<script>alert", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertEqual(len(re.findall(r"<script\b", body)), 1)       # only /static/report.js
        self.assertIn('lang="zh-Hant"', body)
        self.assertIn(i18n.t("rep.title", "zh-Hant"), body)
        self.assertIn(i18n.t("fam.note", "zh-Hant"), body)
        st, en, _ = self.req("GET", "/report/weekly?lang=en")
        for key in ("rep.highlights", "rep.screen", "rep.bedtime", "rep.print"):
            self.assertIn(i18n.t(key, "en"), en)
        for asset in ("report.css", "report.js"):
            st, txt, r = self.req("GET", f"/static/{asset}")
            self.assertEqual(st, 200, asset)
        self.assertIn("@page", self.req("GET", "/static/report.css")[1])

    def test_render_direct(self):
        db = store.connect(self.path)
        try:
            for lang in i18n.CODES:
                html = family_report.render(db, lang)
                self.assertIn("<!doctype html>", html.lower())
                self.assertIn(escape(i18n.t("rep.screen", lang)), html)
        finally:
            db.close()


class UiFileTests(unittest.TestCase):
    js = (Path(web.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
    html = (Path(web.__file__).parent / "static" / "index.html").read_text(encoding="utf-8")

    def test_wiring(self):
        for needle in ("'family'", "function viewFamily", "'/api/screentime?days=7'", "'/api/weekly'",
                       "'/api/bedtime/preview'", "case 'bed-delete'", "a.bedtime", "app.d.screen",
                       "'/report/weekly'", "/^[1-9]$/", "f: 'family'"):
            self.assertIn(needle, self.js)
        for icon in ("i-family", "i-bed", "i-print"):
            self.assertIn(f'id="{icon}"', self.html)
        self.assertEqual(self.js.count("innerHTML"), 2)

    def test_every_ui_key_exists(self):
        keys = set(re.findall(r"T\('((?:app\.(?:fam|bed|d\.screen|tag_bedtime|stat\.screen)|fam|bed|rep|wow)[\w.]*\w)'", self.js))
        self.assertTrue(keys)
        en = json.loads((Path(i18n.__file__).parent / "locales" / "en.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(k for k in keys if k not in en), [])


if __name__ == "__main__":
    unittest.main()
