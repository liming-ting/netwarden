"""
Stage P - people and presence ("who's home").

- owner migration: store.sync_people() creates a person per owner, idempotently, and
  never touches the user's edits;
- the presence state machine (presence.decide: home / probably_home / away / unknown,
  grace, stale data), the timeline (visits, arrivals / departures, late arrivals, local
  days across midnight in other time zones);
- look-alike link suggestions (hostname / announced name / vendor, ambiguity, "not
  theirs"), link + unlink;
- notification routing (notify.route: age, per-person switches, presence off);
- the light presence check (demo refused, nobody opted in, only private in-subnet IPs);
- people / presence in the AI context: person names pseudonymised for a redacting
  provider (a fake cloud provider captures what it was sent), "Is anyone home?" and
  "screen time of X" offline;
- the web API (validation, undo tokens, confirm + this-computer-only for turning
  presence on), backup, the demo story, perf, and the page wiring.
"""
import http.client
import ipaddress
import json
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import (alerts, backup, brain, cache, demo, i18n, notify, offline_ai, pairing,
                       people, presence, store, web)

ROOT = Path(__file__).resolve().parent.parent
UTC = timezone.utc
TPE = timezone(timedelta(hours=8))
UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
_DEMO = {}


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


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def device(db, mac, ip, hostname="", vendor="", first=None, last=None, randomized=False):
    store.upsert_device(db, {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
                             "randomized": randomized, "is_self": False})
    if first or last:
        with db:
            db.execute("UPDATE devices SET first_seen = COALESCE(?, first_seen), "
                       "last_seen = COALESCE(?, last_seen) WHERE mac = ?",
                       (first and iso(first), last and iso(last), mac))


class _Empty(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.db"
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


# --- owners -> people ------------------------------------------------------------------------

class OwnerMigrationTests(_Empty):
    def test_sync_is_idempotent_and_keeps_edits(self):
        device(self.db, "aa:00:00:00:00:01", "192.168.1.21")
        device(self.db, "aa:00:00:00:00:02", "192.168.1.22")
        with self.db:   # owners written before Stage P (no people table rows yet)
            for mac in ("aa:00:00:00:00:01", "aa:00:00:00:00:02"):
                self.db.execute("INSERT INTO device_profiles (mac, owner, updated_at) "
                                "VALUES (?, 'Bob', ?)", (mac, store.now()))
            self.db.execute("DELETE FROM people")
        self.assertEqual(store.sync_people(self.db), 1)
        self.assertEqual(store.sync_people(self.db), 0)
        bob = store.person_by_name(self.db, "Bob")
        store.save_person(self.db, {**bob, "avatar": "🎸", "color": "teal", "note": "dad"})
        self.assertEqual(store.sync_people(self.db), 0)
        again = store.person_by_name(self.db, "Bob")
        self.assertEqual((again["id"], again["avatar"], again["color"], again["presence"]),
                         (bob["id"], "🎸", "teal", False))
        self.assertEqual(presence.owned(self.db), {"Bob": ["aa:00:00:00:00:01", "aa:00:00:00:00:02"]})

    def test_rename_carries_devices_and_delete_restore(self):
        device(self.db, "aa:00:00:00:00:01", "192.168.1.21")
        store.set_profile(self.db, "aa:00:00:00:00:01", owner="Bob")
        store.sync_people(self.db)
        bob = store.person_by_name(self.db, "Bob")
        store.save_person(self.db, {**bob, "name": "Robert"})
        self.assertEqual(presence.owned(self.db), {"Robert": ["aa:00:00:00:00:01"]})
        gone = store.delete_person(self.db, bob["id"])
        self.assertEqual(gone["macs"], ["aa:00:00:00:00:01"])
        self.assertEqual(presence.owned(self.db), {})
        self.assertEqual(store.restore_person(self.db, gone), bob["id"])
        self.assertEqual(presence.owned(self.db), {"Robert": ["aa:00:00:00:00:01"]})
        with self.assertRaises(ValueError):
            store.restore_person(self.db, gone)

    def test_validate(self):
        ok = people.validate(self.db, {"name": "  Ann\n Lee ", "avatar": "👩‍💻", "color": "rose"})
        self.assertEqual((ok["name"], ok["avatar"], ok["child"]), ("Ann Lee", "👩‍💻", False))
        people.save(self.db, ok)
        for raw, code in (({"name": ""}, "bad_person_name"), ({"name": "ann lee"}, "person_exists"),
                          ({"name": "X", "color": "red"}, "bad_person"),
                          ({"name": "X", "avatar": "<b>"}, "bad_person"),
                          ({"name": "X", "avatar": "ABCD"}, "bad_person"),
                          ({"name": "X", "child": "yes"}, "bad_person"),
                          ({"name": "X", "id": 999}, "no_person"),
                          ({"name": "X", "admin": True}, "bad_person"), ("X", "bad_person")):
            with self.assertRaises(people.BadPerson) as cm:
                people.validate(self.db, raw)
            self.assertEqual(cm.exception.code, code, raw)
        self.assertEqual(people.initials("Anna Lee"), "AL")
        self.assertEqual(people.initials("媽媽"), "媽")


# --- the state machine and the timeline ------------------------------------------------------

class DecideTests(unittest.TestCase):
    NOW = 1_800_000_000.0

    def d(self, minutes_ago, grace=20, fresh_ago=0, has=True):
        last = None if minutes_ago is None else self.NOW - minutes_ago * 60
        fresh = None if fresh_ago is None else self.NOW - fresh_ago * 60
        return presence.decide(last, self.NOW, grace, fresh, has)

    def test_states(self):
        self.assertEqual(self.d(3), ("home", "seen"))
        self.assertEqual(self.d(10), ("home", "seen"))
        self.assertEqual(self.d(15), ("probably_home", "grace"))
        self.assertEqual(self.d(20), ("probably_home", "grace"))
        self.assertEqual(self.d(45), ("away", "away"))
        self.assertEqual(self.d(None), ("unknown", "never"))
        self.assertEqual(self.d(3, has=False), ("unknown", "no_devices"))

    def test_grace_setting(self):
        self.assertEqual(self.d(6, grace=5), ("away", "away"))     # home window <= grace
        self.assertEqual(self.d(50, grace=60), ("probably_home", "grace"))

    def test_stale_data_is_unknown_not_away(self):
        self.assertEqual(self.d(45, fresh_ago=None), ("unknown", "no_data"))
        self.assertEqual(self.d(90, fresh_ago=40), ("unknown", "no_data"))
        self.assertEqual(self.d(90, fresh_ago=25), ("away", "away"))
        self.assertEqual(self.d(90, grace=60, fresh_ago=45), ("away", "away"))  # grace > stale


class TimelineTests(unittest.TestCase):
    def run_tl(self, tz):
        now = datetime(2026, 10, 21, 12, 0, tzinfo=tz)
        day = now.date()
        at = lambda d, h, m: datetime(d.year, d.month, d.day, h, m, tzinfo=tz)  # noqa: E731
        y, d2 = day - timedelta(days=1), day - timedelta(days=2)
        ep = []
        for start, end in ((at(d2, 22, 50), at(d2, 23, 30)),      # late arrival 2 days ago
                           (at(y, 21, 0), at(day, 1, 0)),           # across midnight
                           (at(day, 10, 0), at(day, 11, 55))):      # still home now
            t = start
            while t <= end:
                ep.append(t.timestamp())
                t += timedelta(minutes=5)
        return now, presence.timeline(sorted(ep), now.timestamp(), tz, 20,
                                      now.timestamp() - 10 * 86400)

    def test_events_days_and_midnight(self):
        for tz in (TPE, timezone(timedelta(hours=-5)), UTC):
            now, tl = self.run_tl(tz)
            kinds = [(e["kind"], datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))
                      .astimezone(tz).strftime("%H:%M"), e["late"]) for e in tl["events"]]
            self.assertEqual(kinds, [("arrive", "10:00", False), ("leave", "01:00", False),
                                     ("arrive", "21:00", False), ("leave", "23:30", False),
                                     ("arrive", "22:50", True)], tz)
            self.assertEqual(len(tl["days"]), 7)
            today, yday = tl["days"][-1], tl["days"][-2]
            self.assertEqual(today["date"], now.date().isoformat())
            self.assertEqual(today["segments"], [[0, 60], [600, 720]])
            self.assertEqual(today["home_minutes"], 180)
            self.assertEqual(yday["segments"], [[1260, 1440]])
            self.assertEqual(tl["days"][-3]["home_minutes"], 40)

    def test_dst_day_length(self):
        # a local day is whatever the zone says (fixed offsets: always 1440 minutes)
        _now, tl = self.run_tl(TPE)
        self.assertTrue(all(d["minutes"] == 1440 for d in tl["days"]))

    def test_start_of_history_is_not_an_arrival(self):
        now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC).timestamp()
        ep = [now - 3600 + i * 300 for i in range(12)]
        tl = presence.timeline(ep, now, UTC, 20, since=now - 3600)
        self.assertEqual(tl["events"], [])
        tl = presence.timeline(ep, now, UTC, 20, since=now - 7200)
        self.assertEqual([e["kind"] for e in tl["events"]], ["arrive"])

    def test_lone_sighting_and_visits(self):
        self.assertEqual(presence.visits([0, 60, 2000, 2100], 600), [[0, 60], [2000, 2100]])
        now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC).timestamp()
        tl = presence.timeline([now - 7200], now, UTC, 20, since=0)
        self.assertEqual(tl["days"][-1]["segments"], [[600, 605]])


# --- the whole picture on a small home --------------------------------------------------------

class CoreTests(_Empty):
    PHONE, LAPTOP = "aa:00:00:00:00:01", "aa:00:00:00:00:02"

    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 10, 21, 4, 0, tzinfo=UTC)
        device(self.db, self.PHONE, "192.168.1.21", "anns-phone", first=self.now - timedelta(days=30),
               last=self.now - timedelta(days=9))
        device(self.db, self.LAPTOP, "192.168.1.22", "anns-laptop", first=self.now - timedelta(days=30),
               last=self.now - timedelta(days=9))
        store.set_profile(self.db, self.PHONE, owner="Ann", type="phone")
        store.set_profile(self.db, self.LAPTOP, owner="Ann", type="computer")
        store.sync_people(self.db)
        self.ann = store.person_by_name(self.db, "Ann")

    def sample(self, mac, minutes_ago):
        store.insert_presence_samples(self.db, [(mac, iso(self.now - timedelta(minutes=minutes_ago)),
                                                 "check")])

    def test_off_reads_nothing(self):
        self.sample(self.PHONE, 2)
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual(row, {"id": self.ann["id"], "presence": False})
        self.assertEqual(presence.snapshot(self.db, UTC, self.now), [])
        rep = presence.report(self.db, "en", UTC, self.now)
        self.assertFalse(rep["enabled"])
        self.assertEqual(rep["people"][0]["state"], "off")
        self.assertEqual(rep["home_now"], [])

    def test_states_and_default_devices(self):
        presence.set_presence(self.db, self.ann["id"], enabled=True)
        store.save_person(self.db, {**store.person(self.db, self.ann["id"]),
                                    "presence_since": iso(self.now - timedelta(days=3))})
        self.assertEqual(presence.device_sets(self.db), {self.ann["id"]: [self.PHONE]})
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual((row["state"], row["reason"]), ("unknown", "never"))
        self.sample(self.LAPTOP, 2)         # not a presence device
        self.sample(self.PHONE, 15)
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual((row["state"], row["last_mac"]), ("probably_home", self.PHONE))
        rep = presence.report(self.db, "en", UTC, self.now)
        self.assertEqual(rep["home_now"], [self.ann["id"]])
        self.assertIn("anns-phone", rep["people"][0]["reason"])
        presence.set_presence(self.db, self.ann["id"], devices=[self.LAPTOP])
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual((row["state"], row["macs"]), ("home", [self.LAPTOP]))
        with self.assertRaises(ValueError):
            presence.set_presence(self.db, self.ann["id"], devices=["ff:ff:ff:ff:ff:ff"])
        presence.set_presence(self.db, self.ann["id"], default_devices=True)
        self.assertIsNone(store.person(self.db, self.ann["id"])["presence_macs"])

    def test_turning_on_starts_from_now_and_forget(self):
        self.sample(self.PHONE, 60 * 24)    # yesterday: before presence was turned on
        presence.set_presence(self.db, self.ann["id"], enabled=True)
        row = presence.core(self.db, UTC, datetime.now(UTC))["people"][0]
        self.assertIsNone(row["last_seen"])
        self.assertEqual(presence.forget(self.db, self.ann["id"]), 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM presence_samples").fetchone()[0], 0)
        with self.assertRaises(ValueError):
            presence.forget(self.db, 999)

    def test_away_needs_fresh_data(self):
        presence.set_presence(self.db, self.ann["id"], enabled=True)
        store.save_person(self.db, {**store.person(self.db, self.ann["id"]),
                                    "presence_since": iso(self.now - timedelta(days=3))})
        self.sample(self.PHONE, 120)
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual((row["state"], row["reason"]), ("unknown", "no_data"))
        self.sample(self.LAPTOP, 3)          # any fresh data: the network is being watched
        row = presence.core(self.db, UTC, self.now)["people"][0]
        self.assertEqual((row["state"], row["reason"]), ("away", "away"))
        txt = presence.reason_text(row, {}, UTC, "zh-Hant", self.now.timestamp(), 20)
        self.assertTrue(txt and "{" not in txt)

    def test_light_check(self):
        net = ipaddress.ip_network("192.168.1.0/24")
        self.assertEqual(presence.check_recorded(self.db, {}, lambda ip: True, net), -1)  # nobody
        presence.set_presence(self.db, self.ann["id"], enabled=True)
        device(self.db, "aa:00:00:00:00:09", "8.8.8.8")
        store.set_profile(self.db, "aa:00:00:00:00:09", owner="Ann", type="phone")
        with self.db:   # only an address held recently is pinged (presence.TARGET_HOURS)
            self.db.execute("UPDATE devices SET last_seen = ?", (store.now(),))
        probed = []
        alive = lambda ip: probed.append(ip) or ip == "192.168.1.21"   # noqa: E731
        self.assertEqual(presence.check_recorded(self.db, {}, alive, net), 1)
        self.assertEqual(probed, ["192.168.1.21"])         # public / outside the subnet: never
        self.assertEqual(presence.check_recorded(self.db, {}, alive, net), -1)   # not due
        self.assertEqual(presence.check_recorded(self.db, {}, alive, net, force=True), 1)
        st = self.db.execute("SELECT * FROM source_status WHERE source = 'presence'").fetchone()
        self.assertTrue(st["last_ok_ts"])
        store.set_meta(self.db, "demo", "1")
        self.assertEqual(presence.check_recorded(self.db, {}, alive, net, force=True), -1)

    def test_check_errors_are_recorded(self):
        presence.set_presence(self.db, self.ann["id"], enabled=True)
        with self.db:
            self.db.execute("UPDATE devices SET last_seen = ?", (store.now(),))

        def boom(ip):
            raise OSError("ping failed token=abc123")
        with self.assertRaises(OSError):
            presence.check_recorded(self.db, {}, boom, ipaddress.ip_network("192.168.1.0/24"))
        st = self.db.execute("SELECT * FROM source_status WHERE source = 'presence'").fetchone()
        self.assertNotIn("abc123", st["last_error"] or "")


# --- look-alike devices -------------------------------------------------------------------------

class LinkTests(_Empty):
    OLD, NEW = "aa:00:00:00:00:01", "ba:00:00:00:00:07"

    def setUp(self):
        super().setUp()
        self.now = datetime.now(UTC)
        device(self.db, self.OLD, "192.168.1.21", "anns-phone", "Apple",
               first=self.now - timedelta(days=60), last=self.now - timedelta(days=3))
        device(self.db, self.NEW, "192.168.1.31", "Anns-Phone", "Apple", randomized=True,
               first=self.now - timedelta(days=2), last=self.now)
        store.set_profile(self.db, self.OLD, owner="Ann", type="phone", room="Bedroom")
        store.set_label(self.db, self.OLD, "Ann's iPhone")
        store.sync_people(self.db)
        self.ann = store.person_by_name(self.db, "Ann")

    def test_hostname_suggestion_link_unlink(self):
        sug = presence.link_suggestions(self.db)
        self.assertEqual([(s["mac"], s["person"], s["from_mac"], s["reason"]) for s in sug],
                         [(self.NEW, "Ann", self.OLD, "hostname")])
        store.save_person(self.db, {**self.ann, "presence_macs": [self.OLD]})
        before = presence.link(self.db, self.NEW, self.ann["id"])
        prof = store.get_profiles(self.db)[self.NEW]
        self.assertEqual((prof["owner"], prof["type"], prof["room"]), ("Ann", "phone", "Bedroom"))
        self.assertEqual(store.get_labels(self.db)[self.NEW]["label"], "Ann's iPhone")
        self.assertEqual(store.person(self.db, self.ann["id"])["presence_macs"], [self.OLD, self.NEW])
        self.assertEqual(presence.link_suggestions(self.db), [])
        with self.assertRaises(ValueError):
            presence.link(self.db, self.NEW, self.ann["id"])
        presence.unlink(self.db, json.loads(json.dumps(before)))
        self.assertNotIn(self.NEW, store.get_labels(self.db))
        self.assertFalse((store.get_profiles(self.db).get(self.NEW) or {}).get("owner"))
        self.assertEqual(store.person(self.db, self.ann["id"])["presence_macs"], [self.OLD])
        self.assertEqual(len(presence.link_suggestions(self.db)), 1)

    def test_dismiss_old_devices_and_vendor_only_when_quiet(self):
        store.add_ack(self.db, self.NEW, presence.LINK_ACK)
        self.assertEqual(presence.link_suggestions(self.db), [])
        store.remove_ack(self.db, self.NEW, presence.LINK_ACK)
        with self.db:
            self.db.execute("UPDATE devices SET hostname = '' WHERE mac = ?", (self.NEW,))
        self.assertEqual([s["reason"] for s in presence.link_suggestions(self.db)], ["vendor"])
        with self.db:   # the old phone is still around: the same vendor proves nothing
            self.db.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (iso(self.now), self.OLD))
        self.assertEqual(presence.link_suggestions(self.db), [])
        with self.db:   # an old device (not new) is never suggested
            self.db.execute("UPDATE devices SET hostname = 'anns-phone', first_seen = ? WHERE mac = ?",
                            (iso(self.now - timedelta(days=40)), self.NEW))
        self.assertEqual(presence.link_suggestions(self.db), [])

    def test_two_people_is_ambiguous(self):
        device(self.db, "aa:00:00:00:00:03", "192.168.1.23", "", "Apple",
               first=self.now - timedelta(days=60), last=self.now - timedelta(days=3))
        store.set_profile(self.db, "aa:00:00:00:00:03", owner="Bob")
        store.sync_people(self.db)
        with self.db:
            self.db.execute("UPDATE devices SET hostname = '' WHERE mac = ?", (self.NEW,))
        self.assertEqual(presence.link_suggestions(self.db), [])


# --- notifications ----------------------------------------------------------------------------

class NotifyTests(_Empty):
    def setUp(self):
        super().setUp()
        self.pid = store.save_person(self.db, {"name": "Kid", "presence": True,
                                               "notify_arrive": True, "notify_leave": False})
        self.now = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)

    def ev(self, kind="presence.arrive", minutes=5, pid=None):
        return {"kind": kind, "person_id": pid or self.pid,
                "ts": iso(self.now - timedelta(minutes=minutes)), "late": False}

    def test_route(self):
        r = notify.route(self.db, self.ev(), self.now)
        self.assertEqual(r["key"], f"presence.arrive:{self.pid}:{self.ev()['ts']}")
        self.assertIsNone(notify.route(self.db, self.ev(minutes=45), self.now))      # history
        self.assertIsNone(notify.route(self.db, self.ev(minutes=-45), self.now))     # clock skew
        self.assertIsNone(notify.route(self.db, self.ev("presence.leave"), self.now))  # switched off
        self.assertIsNone(notify.route(self.db, self.ev("bandwidth.spike"), self.now))
        self.assertIsNone(notify.route(self.db, self.ev(pid=999), self.now))
        self.assertIsNone(notify.route(self.db, {"kind": "presence.arrive", "person_id": self.pid,
                                                 "ts": "garbage"}, self.now))
        presence.set_presence(self.db, self.pid, notify_leave=True)
        self.assertIsNotNone(notify.route(self.db, self.ev("presence.leave"), self.now))
        presence.set_presence(self.db, self.pid, enabled=False)
        self.assertIsNone(notify.route(self.db, self.ev(), self.now))
        people_map = {self.pid: store.person(self.db, self.pid)}
        self.assertIsNone(notify.route(self.db, self.ev(), self.now, people_map))

    def test_presence_notifications_use_route(self):
        mac = "aa:00:00:00:00:01"
        device(self.db, mac, "192.168.1.21", first=self.now - timedelta(days=9),
               last=self.now - timedelta(days=9))
        store.set_profile(self.db, mac, owner="Kid", type="phone")
        store.save_person(self.db, {**store.person(self.db, self.pid),
                                    "presence_since": iso(self.now - timedelta(days=2))})
        store.insert_presence_samples(self.db, [(mac, iso(self.now - timedelta(minutes=m)), "check")
                                                for m in (10, 5, 0)])
        out = presence.notifications(self.db, UTC, self.now)
        self.assertEqual([(n["kind"], n["person_id"]) for n in out], [("presence.arrive", self.pid)])
        presence.set_presence(self.db, self.pid, notify_arrive=False)
        self.assertEqual(presence.notifications(self.db, UTC, self.now), [])


# --- the demo home, the AI context, the digest ----------------------------------------------------

class DemoStoryTests(_Demo):
    def test_people_shared_presence_and_link(self):
        ps = {p["name"]: p for p in store.people(self.db)}
        self.assertEqual(set(ps), {"爸爸", "媽媽", "小孩"})
        self.assertTrue(ps["小孩"]["child"])
        self.assertEqual({n for n, p in ps.items() if p["presence"]}, {"媽媽", "小孩"})
        shared = {m for m, p in store.get_profiles(self.db).items() if p.get("shared")}
        self.assertEqual(shared, set(demo.DEMO_SHARED))
        rep = presence.report(self.db, "zh-Hant")
        self.assertTrue(rep["enabled"])
        self.assertEqual([(s["mac"], s["person"]) for s in rep["links"]],
                         [(demo.DAD_NEW_MAC, "爸爸")])
        rows = {r["name"]: r for r in rep["people"]}
        self.assertEqual(rows["爸爸"]["state"], "off")
        kid = rows["小孩"]
        self.assertIn(kid["state"], presence.STATES)
        self.assertGreaterEqual(sum(1 for e in kid["events"] if e["kind"] == "arrive"), 4)
        self.assertTrue(any(e["late"] for e in kid["events"]))
        self.assertEqual(len(kid["days"]), presence.DAYS)
        self.assertTrue(all(isinstance(r["reason"], str) and "{" not in r["reason"]
                            for r in rep["people"] if r["presence"]))

    def test_demo_seed_never_overrides_edits(self):
        kid = store.person_by_name(self.db, "小孩")
        store.save_person(self.db, {**kid, "avatar": "🐱", "presence": False})
        demo.build(self.path)
        kid2 = store.person_by_name(self.db, "小孩")
        self.assertEqual((kid2["avatar"], kid2["presence"]), ("🐱", False))

    def test_check_is_refused_on_the_demo(self):
        self.assertEqual(presence.check_recorded(self.db, {}, lambda ip: True,
                                                 ipaddress.ip_network("0.0.0.0/0"), force=True), -1)

    def test_offline_ai_who_is_home_and_screen_time(self):
        snap = brain.snapshot(self.db)
        self.assertEqual({x["person"] for x in snap["presence"]}, {"媽媽", "小孩"})
        self.assertEqual({h["person"] for h in snap["household"]}, {"爸爸", "媽媽", "小孩"})
        p = offline_ai.OfflineProvider()
        for lang in ("en", "zh-Hant"):
            out = p.answer(self.db, snap, lang, "Is anyone home?")
            self.assertIn(i18n.t("offline.presence", lang), out)
            section = out.split(i18n.t("offline.presence", lang), 1)[1].split("\n\n", 1)[0]
            self.assertIn("媽媽", section)
            self.assertIn("小孩", section)
            self.assertNotIn("爸爸", section)       # presence OFF: never in "who's home"
            out = p.answer(self.db, snap, lang, "小孩 這週的螢幕時間?")
            self.assertIn(i18n.t("offline.person_title", lang, person="小孩"), out)
            self.assertIn("Galaxy", out)
            self.assertNotRegex(out, r"\{[a-z_]+\}")
            self.assertNotRegex(out, r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b")

    def test_digest_and_report_only_opted_in(self):
        fam = alerts.family_summary(self.db)
        self.assertEqual({x["person"] for x in fam["presence"]}, {"媽媽", "小孩"})
        text = alerts.render_digest(alerts.compute(self.db), "zh-Hant") \
            if hasattr(alerts, "render_digest") else ""
        self.assertIsInstance(text, str)


class FakeCloud:
    """A cloud provider that only records what it would have been sent."""
    redact, offline = True, False

    def __init__(self):
        self.sent = []

    def complete(self, system, user, max_tokens=1200):
        self.sent.append(system + "\n" + user)
        return "[P1] is home."

    def stream(self, system, user, max_tokens=1200):
        self.sent.append(system + "\n" + user)
        yield "ok"


class RedactionTests(_Demo):
    def test_person_names_never_reach_a_redacting_provider(self):
        fake = FakeCloud()
        reply = brain.ask(self.db, fake, "Is anyone home? How much screen time did 小孩 have?",
                          lang="en")
        body = fake.sent[0]
        for name in ("爸爸", "媽媽", "小孩", "Galaxy-A54"):
            self.assertNotIn(name, body)
        self.assertRegex(body, r"\[P\d+\]")
        self.assertIn('"presence"', body)
        self.assertNotRegex(reply, r"\[P\d+\]")          # mapped back for the user
        self.assertRegex(reply, "爸爸|媽媽|小孩")

    def test_presence_only_for_people_who_opted_in(self):
        snap = brain.snapshot(self.db)
        self.assertNotIn("爸爸", json.dumps(snap["presence"], ensure_ascii=False))
        for x in snap["presence"]:
            self.assertLessEqual(len(x.get("recent") or x.get("events") or []), 10)


# --- backup ---------------------------------------------------------------------------------------

class BackupTests(_Demo):
    def test_people_round_trip(self):
        doc = json.loads(backup.dumps(backup.export(self.db)))
        ppl = {p["name"]: p for p in doc["data"]["people"]}
        self.assertEqual(set(ppl), {"爸爸", "媽媽", "小孩"})
        self.assertTrue(ppl["小孩"]["presence"] and ppl["小孩"]["child"])
        with tempfile.TemporaryDirectory() as t:
            e = store.connect(Path(t) / "e.db")
            backup.restore(e, backup.validate(doc), "merge")
            got = {p["name"]: p for p in store.people(e)}
            self.assertEqual(set(got), set(ppl))
            self.assertEqual(got["媽媽"]["avatar"], ppl["媽媽"]["avatar"])
            # review fixes 4: a restore never switches presence ON (it needs the person's
            # own "yes"); the chosen devices / notification switches do come back
            self.assertFalse(any(p["presence"] for p in got.values()))
            self.assertEqual(got["媽媽"]["notify_arrive"], ppl["媽媽"]["notify_arrive"])
            e.close()
        bad = json.loads(json.dumps(doc))
        bad["data"]["people"] = [{"name": "x" * 500}]
        with self.assertRaises(Exception):
            backup.validate(bad)


# --- the web API -----------------------------------------------------------------------------------

class WebPeopleTests(unittest.TestCase):
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

    def req(self, method, path, body=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"user-agent": UA}
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            h["origin"] = self.origin
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, None

    def ids(self):
        return {p["name"]: p["id"] for p in self.req("GET", "/api/people")[1]["people"]}

    def test_get_people_and_person(self):
        st, j = self.req("GET", "/api/people?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertEqual({p["name"] for p in j["people"]}, {"爸爸", "媽媽", "小孩"})
        self.assertEqual(len(j["shared"]["devices"]), 2)
        kid = next(p for p in j["people"] if p["name"] == "小孩")
        self.assertTrue(kid["devices"] and kid["child"])
        self.assertTrue(all(":" not in d["name"] or d["name"] != d["mac"] for d in kid["devices"]))
        st, d = self.req("GET", f"/api/person?id={kid['id']}&lang=en")
        self.assertEqual(st, 200)
        self.assertEqual(len(d["screen"]["by_day"]), 7)
        self.assertEqual(d["presence_info"]["state"] in presence.STATES, True)
        for bad in ("999", "abc", "", "1" * 20, "-1"):
            self.assertEqual(self.req("GET", f"/api/person?id={bad}")[0], 404, bad)
        st, p = self.req("GET", "/api/presence?lang=zh-Hant")
        self.assertEqual(st, 200)
        self.assertTrue(p["privacy"] and p["private_mac"])
        self.assertNotIn("key", json.dumps(p).lower().replace("monkey", ""))

    def test_person_crud_and_undo(self):
        st, j = self.req("POST", "/api/people", {"person": {"name": "阿嬤", "avatar": "👵",
                                                            "color": "teal"}})
        self.assertEqual(st, 200, j)
        pid = j["id"]
        st, j = self.req("POST", "/api/people", {"person": {"id": pid, "name": "外婆",
                                                            "avatar": "👵", "color": "teal"}})
        self.assertEqual((st, j["before"]["name"]), (200, "阿嬤"))
        for body, field in (({"person": {"name": ""}}, "name"),
                            ({"person": {"name": "媽媽"}}, "name"),
                            ({"person": {"name": "X", "color": "#f00"}}, "color"),
                            ({"person": {"name": "X", "avatar": "<script>"}}, "avatar"),
                            ({"person": {"name": "X", "extra": 1}}, "person"),
                            ({"person": "X"}, "person")):
            st, j = self.req("POST", "/api/people", body)
            self.assertEqual((st, j.get("field")), (400, field), body)
            self.assertTrue(j["error"])
        st, j = self.req("POST", "/api/people/delete", {"id": pid})
        self.assertEqual(st, 200)
        self.assertNotIn("外婆", self.ids())
        st, j2 = self.req("POST", "/api/people/restore", {"undo": j["undo"]})
        self.assertEqual((st, j2["id"]), (200, pid))
        self.assertEqual(self.req("POST", "/api/people/restore", {"undo": j["undo"]})[0], 400)
        for bad in ({"id": 999}, {"id": "1"}, {"id": True}, {}):
            self.assertEqual(self.req("POST", "/api/people/delete", bad)[0], 400, bad)
        self.req("POST", "/api/people/delete", {"id": pid})

    def test_assign_and_undo(self):
        ids = self.ids()
        tv = demo.DEMO_SHARED[0]
        st, j = self.req("POST", "/api/people/assign",
                         {"items": [{"mac": tv, "person": ids["小孩"]}]})
        self.assertEqual(st, 200, j)
        self.assertEqual(j["before"], [{"mac": tv, "person": None, "shared": True}])
        db = store.connect(self.path)
        self.assertEqual(store.get_profiles(db)[tv]["owner"], "小孩")
        db.close()
        st, _ = self.req("POST", "/api/people/assign", {"items": j["before"]})
        self.assertEqual(st, 200)
        db = store.connect(self.path)
        prof = store.get_profiles(db)[tv]
        db.close()
        self.assertEqual((prof.get("owner"), bool(prof.get("shared"))), (None, True))
        for items in ([], [{"mac": "ff:ff:ff:ff:ff:ff"}], [{"mac": tv, "person": 999}],
                      [{"mac": tv, "person": ids["小孩"], "shared": True}],
                      [{"mac": tv}, {"mac": tv}], [{"mac": tv, "x": 1}], "nope",
                      [{"mac": tv}] * 201):
            self.assertEqual(self.req("POST", "/api/people/assign", {"items": items})[0], 400)

    def test_presence_settings_confirm_and_this_computer_only(self):
        dad = self.ids()["爸爸"]
        st, j = self.req("POST", "/api/presence/settings", {"id": dad, "enabled": True})
        self.assertEqual(st, 400)
        for bad in ({"id": dad, "enabled": "yes", "confirm": True},
                    {"id": dad, "enabled": True, "confirm": True, "admin": 1},
                    {"id": dad, "devices": "aa"}, {"id": dad, "devices": ["ff:ff:ff:ff:ff:ff"]},
                    {"id": 999, "enabled": False}):
            self.assertEqual(self.req("POST", "/api/presence/settings", bad)[0], 400, bad)
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
        cookie = (r.getheader("set-cookie") or "").split(";")[0]
        c.close()
        self.assertEqual(r.status, 200)
        st, _ = self.req("POST", "/api/presence/settings",
                         {"id": dad, "enabled": True, "confirm": True}, cookie)
        self.assertEqual(st, 403)
        self._restore()
        db = store.connect(self.path)
        pairing.revoke_all(db)
        self.assertFalse(store.person(db, dad)["presence"])
        db.close()
        st, j = self.req("POST", "/api/presence/settings", {"id": dad, "enabled": True, "confirm": True})
        self.assertEqual((st, j["person"]["presence"]), (200, True))
        st, j = self.req("POST", "/api/presence/settings", {"id": dad, "notify_arrive": True})
        self.assertTrue(j["person"]["notify_arrive"])
        st, j = self.req("POST", "/api/presence/settings", {"id": dad, "enabled": False})
        self.assertEqual((st, j["person"]["presence"]), (200, False))

    def test_link_dismiss_unlink_and_forget(self):
        ids = self.ids()
        links = self.req("GET", "/api/presence")[1]["links"]
        self.assertEqual([x["mac"] for x in links], [demo.DAD_NEW_MAC])
        st, j = self.req("POST", "/api/presence/link", {"mac": demo.DAD_NEW_MAC, "person": ids["爸爸"]})
        self.assertEqual(st, 200, j)
        self.assertEqual(self.req("GET", "/api/presence")[1]["links"], [])
        self.assertEqual(self.req("POST", "/api/presence/unlink", {"undo": j["undo"]})[0], 200)
        self.assertEqual(self.req("POST", "/api/presence/unlink", {"undo": j["undo"]})[0], 400)
        self.assertEqual(len(self.req("GET", "/api/presence")[1]["links"]), 1)
        st, _ = self.req("POST", "/api/presence/link", {"mac": demo.DAD_NEW_MAC, "person": ids["爸爸"],
                                                        "dismiss": True})
        self.assertEqual(self.req("GET", "/api/presence")[1]["links"], [])
        self.req("POST", "/api/unack", {"mac": demo.DAD_NEW_MAC, "domain": presence.LINK_ACK})
        self.assertEqual(len(self.req("GET", "/api/presence")[1]["links"]), 1)
        self.assertEqual(self.req("POST", "/api/presence/link",
                                  {"mac": demo.DAD_NEW_MAC, "person": ids["媽媽"]})[0], 400)
        st, j = self.req("POST", "/api/presence/forget", {"id": ids["小孩"]})
        self.assertEqual(st, 200)
        self.assertGreater(j["deleted"], 0)

    def test_posts_need_json(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/people", "{}", {"content-type": "text/plain", "origin": self.origin})
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 415)


# --- perf ------------------------------------------------------------------------------------------

class PerfTests(unittest.TestCase):
    def test_listen_backlog_fits_a_page_refresh(self):
        # 12 parallel refresh requests must not overflow the backlog (1 s SYN retry)
        self.assertGreaterEqual(web.DashboardServer.request_queue_size, 32)

    def test_new_endpoints_are_fast_on_the_perf_db(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("perf_db", ROOT / "scripts" / "perf_db.py")
        perf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(perf)
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "perf.db"
            perf.build(path, n_devices=300, n_events=20_000, days=7, sample_minutes=30)
            db = store.connect(path)
            self.assertEqual(len(store.people(db)), 20)
            self.assertGreaterEqual(sum(1 for p in store.people(db) if p["presence"]), 6)
            db.close()
            cache.clear()
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                for ep in ("/api/people", "/api/person?id=1", "/api/presence"):
                    times = []
                    for _ in range(3):
                        t0 = time.perf_counter()
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
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


# --- the page --------------------------------------------------------------------------------------

class PageWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")
        cls.css = (ROOT / "netwarden" / "static" / "app.css").read_text(encoding="utf-8")

    def test_routes_and_actions(self):
        for s in ("'/api/presence'", "/api/people/assign", "/api/people/restore", "/api/presence/unlink",
                  "/api/presence/forget", "viewPeople", "viewPerson", "homeStrip", "assignActions",
                  # (Stage Q: presence pops up through /api/notify - notifyItems)
                  "notifyItems", "bulkBar", "data-person-form"):
            self.assertIn(s, self.js, s)
        for act in ("ppl-new", "ppl-delete", "ppl-add-dev", "ppl-rm-dev", "ppl-link", "ppl-link-no",
                    "pres-on", "pres-off", "pres-forget", "bulk-assign"):
            self.assertIn(f"case '{act}'", self.js, act)
        self.assertEqual(len(re.findall(r"\.innerHTML\s*=", self.js)), 2)
        # the picker's search box is found by its data attribute (a run-on once broke it)
        self.assertIn("data-ppl-q value=", self.js)
        self.assertNotRegex(self.js, r"data-[a-z-]+value=")
        for cls_ in (".av", ".home-strip", ".pcard", ".ptl", ".bulkbar"):
            self.assertIn(cls_, self.css)

    def test_enabling_presence_needs_the_privacy_confirm(self):
        i = self.js.index("function presEnable")
        body = self.js[i:i + 900]
        self.assertIn("openConfirm", body)
        self.assertIn("confirm: true", body)

    def test_every_new_key_is_translated(self):
        en = json.loads((ROOT / "netwarden" / "locales" / "en.json").read_text(encoding="utf-8"))
        keys = [k for k in en if k.startswith(("app.ppl.", "app.pres.", "presence.", "people.",
                                                "app.bulk."))]
        self.assertGreater(len(keys), 60)
        for code in i18n.CODES:
            loc = json.loads((ROOT / "netwarden" / "locales" / f"{code}.json").read_text(encoding="utf-8"))
            for k in keys:
                self.assertIn(k, loc, (code, k))
                self.assertEqual(set(re.findall(r"\{\w+\}", loc[k])), set(re.findall(r"\{\w+\}", en[k])),
                                 (code, k))


if __name__ == "__main__":
    unittest.main()
