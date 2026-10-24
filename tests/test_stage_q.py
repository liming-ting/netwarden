"""
Stage Q tests: quiet hours (windows across midnight, per-weekday overrides, hold and
release EXACTLY once - also across a restart and two connections - and the critical
bypass), alert tuning (levels, snoozes, expiry, restore + undo, web validation, LAN
rules), "Why this alert?" for every alert kind on the demo (and in the AI context,
redacted), the router hygiene card (+ suggestions / score without double counting), the
i18n checker (a failing fixture + the real catalog clean), the demo seed and perf.

No real network, no real LLM: demo copies, fake env keys only for preview (which never
calls a model) and an ephemeral 127.0.0.1 server.
"""
from __future__ import annotations

import http.client
import io
import json
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from unittest import mock

from netwarden import (activity, alerts, bedtime, brain, cache, demo, explain, hygiene, i18n, inbox,
                       notify, pairing, quiet, score, store, suggestions, tuning, upnp, web)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tzkit import pinned_tz  # noqa: E402

UTC = timezone.utc
TPE = timezone(timedelta(hours=8))
_DEMO = {}
CAM = "a0:43:b0:9f:21:5e"
TAB = "9e:88:44:21:af:30"
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"


def demo_copy(dest: Path) -> Path:
    if "path" not in _DEMO:
        _DEMO["tmp"] = tempfile.TemporaryDirectory()
        _DEMO["path"] = Path(_DEMO["tmp"].name) / "demo.db"
        demo.build(_DEMO["path"])
    src, dst = sqlite3.connect(_DEMO["path"]), sqlite3.connect(dest)
    src.backup(dst)
    src.close()
    dst.close()
    return dest


def tearDownModule():
    if "tmp" in _DEMO:
        _DEMO["tmp"].cleanup()


def local(y, mo, d, h, mi=0) -> datetime:
    """A Taipei wall-clock time as an aware UTC datetime."""
    return datetime(y, mo, d, h, mi, tzinfo=TPE).astimezone(UTC)


def cfg(start="23:00", end="07:00", days="", enabled=True, critical=True) -> dict:
    return {"enabled": enabled, "start": start, "end": end, "days": quiet.parse_days(days),
            "critical": critical}


class _Empty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "q.db"
        self.db = store.connect(self.path)
        cache.clear()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        cache.clear()


class _Demo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = demo_copy(Path(self.tmp.name) / "d.db")
        self.db = store.connect(self.path)
        cache.clear()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()
        cache.clear()


# --- quiet-hours windows ------------------------------------------------------------------

class QuietWindowTests(unittest.TestCase):
    def test_window_crosses_midnight_and_belongs_to_its_start_day(self):
        c = cfg()   # 2026-10-22 is a Thursday
        self.assertIsNone(quiet.active(c, local(2026, 10, 22, 22, 59), TPE))
        a = quiet.active(c, local(2026, 10, 22, 23, 0), TPE)
        self.assertEqual(a["win"], "2026-10-22")
        a = quiet.active(c, local(2026, 10, 23, 1, 30), TPE)
        self.assertEqual((a["win"], a["end"]), ("2026-10-22", local(2026, 10, 23, 7)))
        self.assertEqual(a["start"], local(2026, 10, 22, 23))
        self.assertIsNone(quiet.active(c, local(2026, 10, 23, 7, 0), TPE))
        self.assertEqual(quiet.next_start(c, local(2026, 10, 23, 12), TPE), local(2026, 10, 23, 23))

    def test_same_day_window_and_disabled(self):
        c = cfg("13:00", "15:00")
        self.assertEqual(quiet.active(c, local(2026, 10, 22, 14), TPE)["win"], "2026-10-22")
        self.assertIsNone(quiet.active(c, local(2026, 10, 22, 15), TPE))
        self.assertIsNone(quiet.active(cfg(enabled=False), local(2026, 10, 23, 1), TPE))
        self.assertIsNone(quiet.next_start(cfg(enabled=False), local(2026, 10, 23, 1), TPE))

    def test_weekday_overrides(self):
        # Friday (4) night runs late into Saturday; Saturday (5) night is off
        c = cfg(days="4=23:30-09:00,5=off")
        self.assertIsNone(quiet.active(c, local(2026, 10, 23, 23, 10), TPE))       # Fri 23:10
        self.assertEqual(quiet.active(c, local(2026, 10, 23, 23, 40), TPE)["win"], "2026-10-23")
        self.assertEqual(quiet.active(c, local(2026, 10, 24, 8, 30), TPE)["win"], "2026-10-23")
        self.assertIsNone(quiet.active(c, local(2026, 10, 24, 23, 30), TPE))       # Sat: off
        self.assertIsNone(quiet.active(c, local(2026, 10, 25, 2), TPE))
        self.assertEqual(quiet.active(c, local(2026, 10, 25, 23, 5), TPE)["win"], "2026-10-25")
        self.assertEqual(quiet.days_text(c, "en").count("·"), 1)

    def test_parse_and_clean_days(self):
        self.assertEqual(quiet.clean_days("5=off, 4=23:30-09:00"), "4=23:30-09:00,5=off")
        for bad in ("7=off", "4=23:30", "4=off,4=off", "4=22:00-22:00", "x", "4=24:00-07:00"):
            with self.assertRaises(quiet.BadQuiet, msg=bad):
                quiet.parse_days(bad)
        self.assertEqual(quiet.clean_time("7:05"), "07:05")
        with self.assertRaises(quiet.BadQuiet):
            quiet.clean_time("25:00")

    def test_settings_validate_quiet_values(self):
        from netwarden import settings
        with tempfile.TemporaryDirectory() as t:
            db = store.connect(Path(t) / "s.db")
            settings.update(db, {}, {"quiet.enabled": True, "quiet.start": "7:30",
                                     "quiet.days": "5=off,4=23:30-09:00"})
            c = quiet.config(db)
            self.assertEqual((c["enabled"], c["start"], c["days"]),
                             (True, "07:30", {4: ("23:30", "09:00"), 5: None}))
            for bad in ({"quiet.start": "nope"}, {"quiet.days": "9=off"}, {"quiet.end": "7"}):
                with self.assertRaises(settings.SettingError, msg=bad):
                    settings.update(db, {}, bad)
            settings.update(db, {}, {"quiet.end": "07:30"})   # == start: never "24 h quiet"
            self.assertFalse(quiet.config(db)["enabled"])
            db.close()


# --- hold / release ------------------------------------------------------------------------

def event(key, kind="new", crit=False, mac="aa:bb:cc:00:00:01"):
    return {"kind": "alert." + kind, "key": key, "mac": mac, "name": "Dev", "critical": crit,
            "detail": None}


class HoldReleaseTests(_Empty):
    def setUp(self):
        super().setUp()
        # the windows below are Taipei times (TPE), and so is the summary's "23:00-07:00":
        # the title is rendered in the configured zone, which CI (TZ=UTC) would make 15:00-23:00
        self.enterContext(pinned_tz("Asia/Taipei"))
        store.put_settings(self.db, {"quiet.enabled": "true", "quiet.start": '"23:00"',
                                     "quiet.end": '"07:00"'})
        notify.prime(self.db)
        self.night = local(2026, 10, 23, 1)

    def route(self, ev, now, db=None):
        db = db or self.db
        return notify.route(db, ev, now, {}, notify.quiet_now(db, {}, now, TPE))

    def test_held_in_the_window_released_once(self):
        self.assertIsNone(self.route(event("a"), self.night))
        self.assertIsNone(self.route(event("b", "change"), self.night + timedelta(minutes=5)))
        self.assertIsNone(self.route(event("a"), self.night + timedelta(minutes=9)))   # dedupe
        self.assertEqual(notify.held_count(self.db, "2026-10-22"), 2)
        self.assertEqual(notify.release(self.db, local(2026, 10, 23, 6, 59)), [])   # not over yet
        made = notify.release(self.db, local(2026, 10, 23, 7, 1))
        self.assertEqual(len(made), 1)
        self.assertEqual(notify.release(self.db, local(2026, 10, 23, 7, 2)), [])
        rows = self.db.execute("SELECT * FROM quiet_summaries").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual([i["key"] for i in json.loads(rows[0]["items"])], ["a", "b"])
        # released events never pop up later
        self.assertIsNone(self.route(event("a"), local(2026, 10, 23, 9)))
        s = notify.summaries(self.db, "zh-Hant")
        self.assertEqual((len(s), s[0]["count"]), (1, 2))
        self.assertIn("23:00–07:00", s[0]["title"])
        self.assertTrue(notify.mark_seen(self.db, s[0]["id"]))
        self.assertEqual(notify.summaries(self.db, "en"), [])
        self.assertTrue(notify.mark_seen(self.db, s[0]["id"], False))   # Undo
        self.assertEqual(len(notify.summaries(self.db, "en")), 1)
        for bad in (True, "1", 0, -1, 2 ** 70, 999):
            self.assertFalse(notify.mark_seen(self.db, bad), bad)

    def test_the_window_reads_the_same_in_every_zone(self):
        """CI1: quiet hours of 23:00-07:00 are 23:00-07:00 on the user's own clock wherever
        netwarden runs - also across a DST change (Los Angeles falls back on 1 Nov 2026) and
        with a half-hour offset - never shifted by the zone's UTC offset."""
        nights = {"UTC": (2026, 10, 23), "America/Los_Angeles": (2026, 10, 31),
                  "Asia/Kolkata": (2026, 10, 23), "Pacific/Auckland": (2026, 10, 23)}
        for i, (zone, (y, mo, d)) in enumerate(nights.items()):
            with pinned_tz(zone) as tz, self.subTest(zone=zone):
                db = store.connect(Path(self.tmp.name) / f"z{i}.db")
                try:
                    store.put_settings(db, {"quiet.enabled": "true", "quiet.start": '"23:00"',
                                            "quiet.end": '"07:00"'})
                    notify.prime(db)
                    morning = datetime(y, mo, d, tzinfo=tz) + timedelta(days=1)
                    at = lambda h, mi=0: morning.replace(hour=h, minute=mi)  # noqa: E731
                    # local times on purpose: the stored UTC strings must not care
                    self.assertIsNone(notify.route(db, event("z"), at(1), {},
                                                   notify.quiet_now(db, {}, at(1))))
                    self.assertEqual(notify.release(db, at(6, 59)), [])
                    self.assertEqual(len(notify.release(db, at(7, 1))), 1)
                    s = notify.summaries(db, "en")
                    self.assertEqual(len(s), 1)
                    self.assertIn("23:00–07:00", s[0]["title"])
                finally:
                    db.close()

    def test_release_exactly_once_across_restart_and_two_connections(self):
        self.route(event("a"), self.night)
        self.route(event("b"), self.night)
        self.db.close()                                   # "restart"
        db1, db2 = store.connect(self.path), store.connect(self.path)
        try:
            after = local(2026, 10, 23, 7, 30)
            made = notify.release(db1, after) + notify.release(db2, after)
            self.assertEqual(len(made), 1)
            db1.close()
            db3 = store.connect(self.path)                # another restart
            self.assertEqual(notify.release(db3, after + timedelta(hours=1)), [])
            self.assertEqual(db3.execute("SELECT COUNT(*) FROM quiet_summaries").fetchone()[0], 1)
            self.assertEqual(db3.execute("SELECT COUNT(*) FROM notify_log WHERE state = 'held'")
                             .fetchone()[0], 0)
            db3.close()
        finally:
            db2.close()
            self.db = store.connect(self.path)

    def test_concurrent_release_threads(self):
        for i in range(20):
            self.route(event(f"k{i}"), self.night)
        after, made, errs = local(2026, 10, 23, 8), [], []

        def go():
            db = store.connect(self.path)
            try:
                made.extend(notify.release(db, after))
            except Exception as e:   # pragma: no cover - reported below
                errs.append(e)
            finally:
                db.close()
        ts = [threading.Thread(target=go) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual((errs, len(made)), ([], 1))
        items = json.loads(self.db.execute("SELECT items FROM quiet_summaries").fetchone()[0])
        self.assertEqual(len(items), 20)

    def test_critical_bypass_is_configurable(self):
        crit = event("t", "threat", crit=True)
        self.assertEqual(self.route(crit, self.night)["key"], "t")
        # a "critical" flag on a non-security kind does not bypass
        self.assertIsNone(self.route(event("n", "new", crit=True), self.night))
        store.put_settings(self.db, {"quiet.critical": "false"})
        self.assertIsNone(self.route(event("t2", "upnp", crit=True), self.night))
        self.assertEqual(self.db.execute("SELECT state FROM notify_log WHERE key = 't2'")
                         .fetchone()[0], "held")

    def test_outside_window_and_before_priming(self):
        day = local(2026, 10, 23, 12)
        self.assertEqual(self.route(event("d"), day)["key"], "d")
        # a sent event stays "sent" (the page dedupes by key); it is never held later
        self.assertEqual(self.route(event("d"), self.night + timedelta(days=1))["key"], "d")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM notify_log").fetchone()[0], 1)
        store.set_meta(self.db, notify.PRIMED, "0")
        # the very first batch on a database only primes: nothing old is held for a summary
        self.assertEqual(self.route(event("e"), self.night)["key"], "e")

    def test_presence_held_too(self):
        pid = store.save_person(self.db, {"name": "媽媽", "presence": True, "notify_arrive": True})
        ev = {"kind": "presence.arrive", "person_id": pid,
              "ts": self.night.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        people = {p["id"]: p for p in store.people(self.db)}
        self.assertIsNone(notify.route(self.db, ev, self.night, people,
                                       notify.quiet_now(self.db, {}, self.night, TPE)))
        self.assertEqual(len(notify.release(self.db, local(2026, 10, 23, 7, 5))), 1)


# --- tuning --------------------------------------------------------------------------------

class TuningTests(_Demo):
    def kinds(self):
        return {it["kind"] for it in inbox.alert_items(self.db, "en", 24)}

    def test_levels_snooze_expiry_restore_undo(self):
        self.assertIn("upnp", self.kinds())
        r = tuning.set_level(self.db, "upnp", None, "off", "1h")
        cache.clear()
        self.assertNotIn("upnp", self.kinds())
        self.assertEqual(r["before"], [])
        tuning.restore_rows(self.db, tuning.ALL, "upnp", r["before"])   # Undo
        cache.clear()
        self.assertIn("upnp", self.kinds())
        # a snooze that has run out no longer counts
        tuning.set_level(self.db, "upnp", None, "off", "1h",
                         now=datetime.now(UTC) - timedelta(hours=2))
        cache.clear()
        self.assertIn("upnp", self.kinds())
        self.assertFalse(any(e["kind"] == "upnp" and e["mac"] == tuning.ALL
                             for e in tuning.state(self.db)))
        # "less sensitive" keeps the camera's RISKY mapping
        tuning.set_level(self.db, "upnp", None, "less")
        cache.clear()
        self.assertIn("upnp", self.kinds())
        e = next(e for e in tuning.state(self.db) if e["key"] == "less:upnp")
        self.assertEqual((e["level"], e["until"]), ("less", None))
        undo = tuning.restore(self.db, e["id"])
        self.assertFalse(any(x["key"] == "less:upnp" for x in tuning.state(self.db)))
        tuning.restore_undo(self.db, undo)
        self.assertTrue(any(x["key"] == "less:upnp" for x in tuning.state(self.db)))

    def test_per_device_off_and_snooze_lengths(self):
        now = datetime(2026, 10, 23, 1, tzinfo=UTC)
        for s, span in (("1h", timedelta(hours=1)), ("1d", timedelta(days=1)),
                        ("1w", timedelta(days=7))):
            r = tuning.set_level(self.db, "bedtime", TAB, "off", s, now=now)
            self.assertEqual(r["until"], tuning._iso(now + span))
        r = tuning.set_level(self.db, "bedtime", TAB, "off", "forever")
        self.assertIsNone(r["until"])
        cache.clear()
        self.assertFalse(any(it["kind"] == "bedtime" and it["mac"] == TAB
                             for it in inbox.alert_items(self.db, "en", 24)))
        lv = tuning.device_levels(self.db, TAB)
        self.assertEqual((lv["bedtime"]["level"], lv["bedtime"]["scope"]), ("off", "device"))
        tuning.set_level(self.db, "bedtime", TAB, "normal")
        cache.clear()
        self.assertEqual(tuning.device_levels(self.db, TAB)["bedtime"]["level"], "normal")

    def test_validation(self):
        for args in (("nope", None, "off"), ("upnp", None, "loud"), ("upnp", None, "less", "1h"),
                     ("upnp", None, "off", "2h"), ("new", CAM, "off"), ("outage", CAM, "off"),
                     (123, None, "off"), ("upnp", 5, "off")):
            with self.assertRaises(tuning.BadTuning, msg=args):
                tuning.set_level(self.db, *args)
        with self.assertRaises(tuning.BadTuning) as cm:
            tuning.set_level(self.db, "upnp", "ff:ff:ff:ff:ff:ff", "off")
        self.assertEqual(cm.exception.code, "bad_mac")
        for bad in ("x", "ack|nope|mute:upnp", "setting|ui.language", 5, "a" * 500):
            with self.assertRaises(tuning.BadTuning, msg=bad):
                tuning.restore(self.db, bad)
        for bad in (None, {}, {"setting": "ui.language"}, {"row": {"mac": "zz", "domain": "mute:upnp",
                                                                  "created_at": "x", "until": None}},
                    {"row": {"mac": CAM, "domain": "", "created_at": "x", "until": None}},
                    {"row": {"mac": CAM, "domain": "mute:nope", "created_at": "x", "until": None}},
                    {"row": {"mac": CAM, "domain": "mute:upnp", "created_at": 5, "until": None}}):
            with self.assertRaises(tuning.BadTuning, msg=bad):
                tuning.restore_undo(self.db, bad)

    def test_legacy_switch_shows_and_restores(self):
        from netwarden import settings
        settings.update(self.db, {}, {"alerts.unusual_hours": False})
        e = next(e for e in tuning.state(self.db) if e["source"] == "setting")
        self.assertEqual((e["kind"], e["level"]), ("night", "off"))
        undo = tuning.restore(self.db, e["id"])
        self.assertTrue(settings.get(self.db, {}, "alerts.unusual_hours"))
        tuning.restore_undo(self.db, undo)
        self.assertFalse(settings.get(self.db, {}, "alerts.unusual_hours"))

    def test_demo_seed(self):
        st = {(e["mac"], e["key"]): e for e in tuning.state(self.db)}
        for mac, dom, days in demo.DEMO_TUNING:
            self.assertIn((mac, dom), st)
            self.assertEqual(st[(mac, dom)]["until"] is None, days is None)
        # quiet hours 23:00-07:00 with one unseen summary
        c = quiet.config(self.db)
        self.assertEqual((c["enabled"], c["start"], c["end"]), (True, "23:00", "07:00"))
        s = notify.summaries(self.db, "en")
        self.assertEqual(len(s), 1)
        self.assertGreaterEqual(s[0]["count"], 2)
        self.assertEqual(store.get_meta(self.db, notify.PRIMED), "1")


class DemoReseedTests(unittest.TestCase):
    def test_reseed_keeps_user_edits(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(demo_copy(Path(t) / "r.db"))
            db = store.connect(p)
            tuning.set_level(db, "night", "f4:f5:d8:6c:21:0e", "normal")   # the user restored one
            notify.mark_seen(db, notify.summaries(db, "en")[0]["id"])
            store.put_settings(db, {"quiet.start": '"22:00"'})
            db.close()
            demo.build(p)
            db = store.connect(p)
            keys = {(r["mac"], r["domain"]) for r in db.execute("SELECT mac, domain FROM acks")}
            self.assertNotIn(("f4:f5:d8:6c:21:0e", "mute:night"), keys)
            self.assertIn(("70:9e:29:55:3b:81", "mute:spike"), keys)
            self.assertEqual(notify.summaries(db, "en"), [])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM quiet_summaries").fetchone()[0], 1)
            self.assertEqual(quiet.config(db)["start"], "22:00")
            # the seeded expiry moved along with the demo's clock
            until = db.execute("SELECT until FROM acks WHERE domain = 'mute:spike'").fetchone()[0]
            self.assertGreater(until, store.now())
            db.close()

    def test_an_alert_seen_days_ago_never_sits_in_last_nights_summary(self):
        # CI1: on afternoon builds the seeded summary held the Twitch change, which the
        # story says the family saw two days before - so "Since your last visit" listed it
        # again. New builds never pick a SEEN_KINDS alert; older demo DBs are repaired.
        self.assertFalse(set(demo.SUMMARY_KINDS) & set(demo.SEEN_KINDS))
        with tempfile.TemporaryDirectory() as t:
            p = Path(demo_copy(Path(t) / "s.db"))
            db = store.connect(p)
            row = db.execute("SELECT id, items, win, end_ts FROM quiet_summaries").fetchone()
            key = "change|70:9e:29:55:3b:81|change:Twitch"
            stale = {"key": key, "kind": "alert.change", "ts": row["end_ts"],
                     "mac": "70:9e:29:55:3b:81", "name": "PS5", "detail": ["Twitch"]}
            with db:   # what an older build wrote
                db.execute("DELETE FROM notify_log WHERE key = ?", (key,))
                db.execute("INSERT INTO notify_log (key, kind, ts, state, critical, win, until, data) "
                           "VALUES (?, 'alert.change', ?, 'released', 0, ?, ?, '{}')",
                           (key, row["end_ts"], row["win"], row["end_ts"]))
                db.execute("UPDATE quiet_summaries SET items = ? WHERE id = ?",
                           (json.dumps(json.loads(row["items"]) + [stale]), row["id"]))
            db.close()
            demo.build(p)
            db = store.connect(p)
            try:
                items = json.loads(db.execute("SELECT items FROM quiet_summaries").fetchone()[0])
                self.assertNotIn(key, [i["key"] for i in items])
                self.assertEqual(len(items), len(json.loads(row["items"])))   # the rest stays
                self.assertEqual(db.execute("SELECT state FROM notify_log WHERE key = ?",
                                            (key,)).fetchone()[0], "sent")    # seen days ago
            finally:
                db.close()


# --- "Why this alert?" ------------------------------------------------------------------

class ExplainTests(_Demo):
    def check_sections(self, lang):
        loc = alerts.localize(alerts.compute(self.db), lang)
        seen = set()
        for section, kind in explain.SECTIONS.items():
            for a in loc.get(section) or []:
                w = a["explain"]
                self.assertTrue(w["rule"] and w["facts"], (section, w))
                self.assertTrue(all(isinstance(f, str) and "{" not in f for f in w["facts"]))
                self.assertNotIn("{", w["threshold"])
                self.assertEqual(w["ref"]["kind"], kind)
                self.assertEqual(w["tune"]["kind"], kind)
                found = explain.find(self.db, kind, w["ref"]["mac"], w["ref"]["key"])
                self.assertIsNotNone(found, (kind, w["ref"]))
                seen.add(kind)
        return seen

    def test_every_alert_kind_is_explained(self):
        # The demo's bedtime story happens on school nights (Sun-Thu) and bedtime alerts look
        # at the last 24 h: after a Fri/Sat night there is none - a weekday fact, not a flake
        # (this failed every Saturday). Both branches: assert that, then pin the bedtime
        # check to the morning after the latest school night (as test_stage_f does).
        tz = activity.local_tz()
        now = datetime.now(tz)
        orig = bedtime.alerts
        if not orig(self.db):
            self.assertNotIn((now - timedelta(days=1)).weekday(), demo.SCHOOL_NIGHTS)
        d = now.date()
        while d.weekday() not in demo.SCHOOL_NIGHTS or datetime.combine(d, datetime.min.time(), tz) > now - timedelta(days=1):
            d -= timedelta(days=1)
        morning = datetime.combine(d + timedelta(days=1), datetime.min.time(), tz) + timedelta(hours=8)
        pinned = lambda db, tz=None, now=None: orig(db, tz, now or morning)  # noqa: E731
        seen = set()
        with mock.patch.object(bedtime, "alerts", side_effect=pinned):
            cache.clear()
            for lang in ("en", "zh-Hant"):
                seen |= self.check_sections(lang)
            # the demo's night alert is hidden by its own bedtime rule (bedtime.suppress_night);
            # without the rule it shows up - and is explained too
            with self.db:
                self.db.execute("DELETE FROM bedtime_rules")
            cache.clear()
            seen |= self.check_sections("en")
        self.assertEqual(seen, set(tuning.KINDS))

    def test_inbox_and_drawer_rows_carry_it(self):
        items = inbox.alert_items(self.db, "zh-Hant", 24)
        self.assertTrue(items)
        for it in items:
            self.assertTrue(it["why"]["rule"], it["kind"])
        txt = explain.text(items[0]["why"])
        self.assertIn(items[0]["why"]["rule"], txt)

    def test_less_sensitive_threshold_is_stated(self):
        tuning.set_level(self.db, "upnp", None, "less")
        cache.clear()
        a = alerts.localize(alerts.compute(self.db), "en")["upnp"][0]["explain"]
        self.assertEqual(a["level"], "less")
        self.assertEqual(a["level_text"], i18n.t("why.level_less", "en"))
        self.assertEqual(a["threshold"], i18n.t("why.threshold.upnp_less", "en"))

    def test_ai_context_has_the_explanation_redacted(self):
        a = alerts.localize(alerts.compute(self.db), "en")["upnp"][0]["explain"]
        msgs = [{"role": "user", "content": "why?"}]
        env = {"ANTHROPIC_API_KEY": "sk-test-not-real"}   # preview never calls a model
        out = brain.preview(self.db, env, "chat", msgs, lang="en", alert=a["ref"])
        self.assertTrue(out["sends"])
        self.assertIn(i18n.t("why.rule.upnp", "en"), out["system"])
        if out["redact"]:
            self.assertNotIn("192.168.1.51", out["system"])
            self.assertNotIn(CAM, out["system"])
        none = brain.preview(self.db, env, "chat", msgs, lang="en",
                             alert={"kind": "upnp", "mac": CAM, "key": "nope"})
        self.assertNotIn(i18n.t("why.rule.upnp", "en"), none["system"])

    def test_canonical_and_localized_items_explain_the_same(self):
        # the AI / offline chat explain the canonical item; rows explain the localized one
        canon = alerts.compute(self.db)["threats"][0]
        shown = alerts.localize(alerts.compute(self.db), "zh-Hant")["threats"][0]["explain"]
        self.assertEqual(explain.explain("threat", canon, "zh-Hant")["facts"], shown["facts"])

    def test_offline_answer_starts_with_the_explanation(self):
        from netwarden import offline_ai
        a = alerts.localize(alerts.compute(self.db), "zh-Hant")["upnp"][0]["explain"]
        text = "".join(brain.stream_reply(self.db, offline_ai.OfflineProvider(), "chat",
                                          [{"role": "user", "content": "?"}], lang="zh-Hant",
                                          alert=a["ref"]))
        self.assertTrue(text.startswith(a["rule"]))


# --- hygiene -----------------------------------------------------------------------------------

class HygieneTests(_Demo):
    def test_demo_report(self):
        r = hygiene.report(self.db, "en")
        by = {c["key"]: c for c in r["checks"]}
        self.assertEqual(set(by), set(hygiene.CHECKS))
        self.assertEqual(by["upnp_risky"]["status"], "fail")
        self.assertIn("upnp:TCP:554", by["upnp_risky"]["suggestions"])
        self.assertEqual(by["upnp_stale"]["status"], "warn")
        self.assertIn("192.168.1.77", by["upnp_stale"]["text"])
        self.assertEqual(by["router"]["status"], "pass")
        self.assertIn("Archer C6", by["router"]["text"])
        self.assertEqual(r["status"], "fail")
        self.assertTrue(r["demo"])
        zh = hygiene.report(self.db, "zh-Hant")
        self.assertEqual(len(zh["checks"]), len(r["checks"]))
        for c in r["checks"]:
            if c["status"] in ("warn", "fail"):
                self.assertTrue(c["steps"], c["key"])

    def test_suggestions_and_score_no_double_counting(self):
        det = suggestions.detect(self.db, {})
        ids = [a["id"] for a in det["active"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("upnp_stale", ids)
        self.assertIn("firmware", ids)
        res = score.compute(self.db, {}, det)
        keys = [d["key"] for d in res["deductions"]]
        self.assertEqual(keys.count("upnp_stale"), 1)
        self.assertNotIn("firmware", keys)
        self.assertNotIn("iot_net", keys)
        # the risky camera forward costs points once, under its own suggestion
        self.assertEqual([d["suggestion"] for d in res["deductions"]
                          if d["suggestion"] == "upnp:TCP:554"], ["upnp:TCP:554"])
        # every suggestion a check links to exists
        for c in hygiene.report(self.db, "en")["checks"]:
            for sid in c["suggestions"]:
                self.assertIn(sid, ids, (c["key"], sid))

    def test_no_upnp_snapshot_is_unknown_and_free(self):
        with self.db:
            self.db.execute("DELETE FROM upnp_snapshots")
            self.db.execute("DELETE FROM upnp_mappings")
        cache.clear()
        by = {c["key"]: c for c in hygiene.report(self.db, "en")["checks"]}
        for k in ("upnp", "upnp_risky", "upnp_stale"):
            self.assertEqual(by[k]["status"], "unknown")
        self.assertNotIn("upnp_stale", [d["key"] for d in score.compute(self.db, {})["deductions"]])

    def test_risky_ports_and_stale_mapping(self):
        maps = upnp.mappings(self.db)
        stale = [m for m in maps if m["mac"] is None]
        self.assertEqual([(m["internal_client"], m["external_port"]) for m in stale],
                         [("192.168.1.77", 51413)])
        self.assertTrue(any(m["risky"] and m["external_port"] == 554 for m in maps))


# --- i18n checker -------------------------------------------------------------------------

class I18nCheckerTests(unittest.TestCase):
    def test_failing_fixture(self):
        cat = {
            "en": {"_meta": {}, "a": "Hello {name}", "b": "Open settings", "c": "OK", "d": "AdGuard"},
            "zh-Hant": {"_meta": {}, "a": "你好", "b": "Open settings", "c": "设备", "d": "AdGuard",
                        "x": "多的"},
            "zh-Hans": {"_meta": {}, "a": "你好 {name}", "b": "打开设置", "c": "設備"},
            "de": {"_meta": {}, "a": "Hallo {name}", "b": "Einstellungen", "c": " ", "d": "AdGuard"},
        }
        got = {(c, k, p) for c, k, p, _d in i18n.check(cat, {})}
        expect = {("zh-Hant", "a", "placeholders"), ("zh-Hant", "b", "same_as_en"),
                  ("zh-Hant", "c", "simplified_in_hant"), ("zh-Hant", "x", "extra"),
                  ("zh-Hans", "c", "traditional_in_hans"), ("zh-Hans", "d", "missing"),
                  ("de", "c", "empty")}
        self.assertEqual(got, expect)
        # brands are fine as they are; an allowlisted copy is accepted
        self.assertNotIn(("zh-Hant", "d", "same_as_en"), got)
        got2 = {(c, k, p) for c, k, p, _d in i18n.check(cat, {"zh-Hant": {"b"}})}
        self.assertNotIn(("zh-Hant", "b", "same_as_en"), got2)

    def test_mainland_terms(self):
        cat = {"en": {"a": "network", "b": "client"},
               "zh-Hant": {"a": "網絡設定", "b": "用戶端程式"}}
        got = {(k, p) for _c, k, p, _d in i18n.check(cat, {})}
        self.assertEqual(got, {("a", "mainland_term")})

    def test_real_catalog_is_clean_and_cli(self):
        self.assertEqual(i18n.check(), [])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = i18n.main(["--check"])
        self.assertEqual(rc, 0)
        self.assertIn("ok", buf.getvalue())


# --- the web API -------------------------------------------------------------------------------

class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(demo_copy(Path(cls.tmp.name) / "w.db"))
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()
        cache.clear()

    def setUp(self):
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False

    def req(self, method, path, body=None, raw=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"user-agent": UA}
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            h["origin"] = self.origin
        c.request(method, path, raw if raw is not None else
                  (json.dumps(body or {}) if method == "POST" else None), h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, None

    def test_gets(self):
        st, j = self.req("GET", "/api/notify?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertEqual(set(j) >= {"quiet", "deliver", "held", "summaries"}, True)
        self.assertTrue(j["quiet"]["enabled"])
        st, j = self.req("GET", "/api/tuning?lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(j["kinds"], list(tuning.KINDS))
        self.assertTrue(all(e["target"] and e["kind_name"] for e in j["entries"]))
        self.assertNotIn(":", "".join(e["target"] for e in j["entries"]))   # never a bare MAC
        st, j = self.req("GET", "/api/hygiene?lang=en")
        self.assertEqual((st, j["status"]), (200, "fail"))
        st, d = self.req("GET", f"/api/device?mac={CAM}&lang=en")
        self.assertEqual(st, 200)
        self.assertTrue(d["alerts"] and all(a["why"]["rule"] for a in d["alerts"]))
        self.assertEqual(set(d["tuning"]), set(tuning.DEVICE_KINDS))

    def test_tuning_posts(self):
        st, j = self.req("POST", "/api/tuning", {"kind": "exposure", "mac": CAM, "level": "off",
                                                  "for": "1d"})
        self.assertEqual(st, 200, j)
        self.assertTrue(j["until"])
        st, _ = self.req("POST", "/api/tuning/undo", {"kind": "exposure", "mac": CAM,
                                                      "before": j["before"]})
        self.assertEqual(st, 200)
        for bad in ({"kind": "x", "level": "off"}, {"kind": "upnp", "level": "off", "for": 3},
                    {"kind": "upnp", "level": "off", "for": "1y"},
                    {"kind": "upnp", "mac": "nope", "level": "off"}, {}):
            st, j = self.req("POST", "/api/tuning", bad)
            self.assertEqual(st, 400, bad)
            self.assertTrue(j["error"])
        for bad in ({"kind": "upnp", "before": "x"}, {"kind": "upnp", "before": [{}] * 3},
                    {"kind": "upnp", "before": [{"domain": 1, "created_at": "x"}]}):
            self.assertEqual(self.req("POST", "/api/tuning/undo", bad)[0], 400, bad)
        self.assertEqual(self.req("POST", "/api/tuning/restore", {"id": "ack|zz|mute:upnp"})[0], 400)
        self.assertEqual(self.req("POST", "/api/tuning", raw="[" * 10)[0], 400)
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/tuning", "{}", {"content-type": "text/plain", "origin": self.origin})
        self.assertEqual(c.getresponse().status, 415)
        c.close()

    def test_restore_and_summary_seen(self):
        _st, j = self.req("GET", "/api/tuning")
        e = next(e for e in j["entries"] if e["source"] == "tuning")
        st, r = self.req("POST", "/api/tuning/restore", {"id": e["id"]})
        self.assertEqual(st, 200)
        self.assertEqual(self.req("POST", "/api/tuning/restore_undo", {"undo": r["undo"]})[0], 200)
        _st, n = self.req("GET", "/api/notify?lang=en")
        sid = n["summaries"][0]["id"]
        self.assertEqual(self.req("POST", "/api/notify/seen", {"id": sid})[0], 200)
        self.assertEqual(self.req("GET", "/api/notify")[1]["summaries"], [])
        self.assertEqual(self.req("POST", "/api/notify/seen", {"id": sid, "seen": False})[0], 200)
        for bad in ({"id": "1"}, {"id": 99999}, {"id": sid, "seen": "no"}):
            self.assertEqual(self.req("POST", "/api/notify/seen", bad)[0], 400, bad)

    def test_setting_switch_restore_is_this_computer_only(self):
        self.req("POST", "/api/settings", {"values": {"family.bedtime_alerts": False}})
        _st, j = self.req("GET", "/api/tuning")
        e = next(e for e in j["entries"] if e["source"] == "setting")
        self.assertTrue(e["admin"])
        cookie = self.pair()
        st, _ = self.req("POST", "/api/tuning/restore", {"id": e["id"]}, cookie=cookie)
        self.assertEqual(st, 403)
        # ... while a paired phone may tune alerts and close a summary
        st, j = self.req("POST", "/api/tuning", {"kind": "upnp", "level": "less"}, cookie=cookie)
        self.assertEqual(st, 200, j)
        self.req("POST", "/api/tuning/undo", {"kind": "upnp", "before": j["before"]}, cookie=cookie)
        self._restore()
        db = store.connect(self.path)
        pairing.revoke_all(db)
        db.close()
        self.assertEqual(self.req("POST", "/api/tuning/restore", {"id": e["id"]})[0], 200)

    def pair(self) -> str:
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        web.Handler.require_auth = True
        db = store.connect(self.path)
        code = pairing.new_code(db)["code"]
        db.close()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/pair", json.dumps({"code": code}),
                  {"content-type": "application/json", "origin": self.origin, "user-agent": UA})
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 200)
        return (r.getheader("set-cookie") or "").split(";")[0]

    def test_remote_needs_a_session(self):
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        web.Handler.require_auth = True
        for path in ("/api/notify", "/api/tuning", "/api/hygiene"):
            self.assertEqual(self.req("GET", path)[0], 401, path)
        self.assertEqual(self.req("POST", "/api/tuning", {"kind": "upnp", "level": "off"})[0], 401)


# --- perf ----------------------------------------------------------------------------------

class PerfTests(unittest.TestCase):
    def test_new_endpoints_are_fast_on_the_perf_db(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("perf_db", ROOT / "scripts" / "perf_db.py")
        perf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(perf)
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "perf.db"
            perf.build(path, n_devices=300, n_events=20_000, days=7, sample_minutes=30)
            cache.clear()
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                for ep in ("/api/notify", "/api/tuning", "/api/hygiene", "/api/inbox"):
                    times = []
                    for _ in range(3):
                        t0 = time.perf_counter()
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                        c.request("GET", ep)
                        r = c.getresponse()
                        r.read()
                        c.close()
                        self.assertEqual(r.status, 200, ep)
                        times.append((time.perf_counter() - t0) * 1000)
                    # the bar is 300 ms (scripts/perf_db.py bench); leave room for slow CI
                    self.assertLess(min(times[1:]), 600, (ep, times))
            finally:
                srv.shutdown()
                web.close_server(srv)
                cache.clear()


# --- the page ------------------------------------------------------------------------------

class PageWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")

    def test_app_keys_exist(self):
        import re
        for key in set(re.findall(r"""\bt\(['"]((?:app\.(?:tune|why|quiet|hyg)|quiet|settings\.quiet)"""
                                  r"""[\w.]*)['"]""", self.js)):
            if key.endswith("."):
                continue
            self.assertTrue(i18n.has(key), key)

    def test_entry_points(self):
        for needle in ("data-act=\"why\"", "tune-set", "tune-restore", "quiet-seen", "act:tuning",
                       "/api/tuning/undo", "/api/notify/seen", "hygieneCard"):
            self.assertIn(needle, self.js.replace("'", '"'), needle)


if __name__ == "__main__":
    unittest.main()
