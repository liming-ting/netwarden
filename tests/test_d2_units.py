"""
Stage D2 building blocks on small synthetic DBs: the user's type/owner/room notes
(store), the device-type classifier, activity patterns + the unusual-hours rule,
search / reverse lookups and the device timeline. Fixed clocks and time zones;
no network.
"""
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import activity, devicetype, i18n, search, store, timeline

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
UTC = timezone.utc
KID, CAM, PC = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:03"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def device(db, mac, ip, vendor="", hostname="", randomized=False, first_seen=None, is_self=False):
    store.upsert_device(db, {"mac": mac, "ip": ip, "vendor": vendor, "hostname": hostname,
                             "randomized": randomized, "is_self": is_self},
                        seen=iso(first_seen or NOW - timedelta(days=8)))


def events(db, mac, ip, times, domain="example.com", blocked=False):
    store.insert_events(db, [{
        "source": "test", "ts": iso(t + timedelta(microseconds=i)), "client_ip": ip,
        "client_name": None, "domain": domain, "qtype": "A", "status": "NOERROR",
        "reason": "", "blocked": int(blocked), "cached": 0, "upstream": "", "elapsed_ms": 1.0,
        "block_reason": "blocklist" if blocked else None, "device_mac": mac,
    } for i, t in enumerate(times)])


def daytime(days=range(2, 7), hours=range(10, 20), per_hour=1):
    """Timestamps at UTC `hours` on each of `days` days before NOW."""
    return [NOW.replace(hour=h, minute=5 + k) - timedelta(days=d)
            for d in days for h in hours for k in range(per_hour)]


def night(n=12, hour=1, days_ago=0):
    base = NOW.replace(hour=hour, minute=0) - timedelta(days=days_ago)
    return [base + timedelta(minutes=4 * i) for i in range(n)]


class ProfileStoreTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        device(self.db, KID, "10.0.0.2")
        device(self.db, CAM, "10.0.0.3")

    def test_partial_updates_and_clearing(self):
        store.set_profile(self.db, KID, owner="小孩", room="小孩房")
        store.set_profile(self.db, KID, type="tablet")          # owner/room untouched
        p = store.get_profiles(self.db)[KID]
        self.assertEqual((p["type"], p["owner"], p["room"]), ("tablet", "小孩", "小孩房"))
        store.set_profile(self.db, KID, room="")                # clears only the room
        self.assertIsNone(store.get_profiles(self.db)[KID]["room"])
        store.set_profile(self.db, KID, type=None, owner="  ")  # nothing left -> row deleted
        self.assertNotIn(KID, store.get_profiles(self.db))

    def test_free_text_is_one_trimmed_line(self):
        store.set_profile(self.db, KID, owner="  媽\n媽\t<b>x</b>\x00 " + "x" * 200)
        owner = store.get_profiles(self.db)[KID]["owner"]
        self.assertTrue(owner.startswith("媽 媽 <b>x</b>"))     # stored as typed, escaped on output
        self.assertNotIn("\n", owner)
        self.assertEqual(len(owner), store.MAX_PROFILE_TEXT)

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            store.set_profile(self.db, KID, color="red")

    def test_people_and_rooms_count_inventory_devices(self):
        store.set_profile(self.db, KID, owner="小孩", room="客廳")
        store.set_profile(self.db, CAM, room="客廳")
        store.set_profile(self.db, "ff:ff:ff:ff:ff:ff", owner="ghost")   # not in inventory
        self.assertEqual(store.profile_values(self.db, "owner"),
                         [{"name": "小孩", "devices": 1, "macs": [KID]}])
        self.assertEqual(store.profile_values(self.db, "room")[0]["devices"], 2)
        with self.assertRaises(ValueError):
            store.profile_values(self.db, "type; DROP TABLE devices")

    def test_old_db_gets_the_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            store.connect(path).close()
            raw = sqlite3.connect(path)
            raw.execute("DROP TABLE device_profiles")   # as created by an older netwarden
            raw.commit()
            raw.close()
            db = store.connect(path)
            store.set_profile(db, KID, owner="爸爸")
            self.assertEqual(store.get_profiles(db)[KID]["owner"], "爸爸")
            db.close()


class DeviceTypeTests(unittest.TestCase):
    def guess(self, svc=None, bw=None, override=None, **dev):
        return devicetype.decide(devicetype.votes(dev, svc, bw), override)

    def test_vendor_hostname_services_traffic_randomized(self):
        self.assertEqual(self.guess(vendor="Sony Interactive Entertainment")["type"], "console")
        self.assertEqual(self.guess(hostname="Galaxy-Tab-S9")["type"], "tablet")
        self.assertEqual(self.guess(hostname="Johns-iPhone")["type"], "phone")
        self.assertEqual(self.guess(hostname="Chromecast-Living")["type"], "streaming")
        self.assertEqual(self.guess(svc={"svc.samsung_acr": 30})["type"], "tv")
        cam = self.guess(bw={"rx_bytes": 1e8, "tx_bytes": 5e9})
        self.assertEqual((cam["type"], cam["source"]), ("camera", "traffic"))
        phone = self.guess(randomized=True, vendor="whatever", svc={"Instagram": 9})
        self.assertEqual((phone["type"], phone["source"]), ("phone", "mobile"))
        self.assertEqual(self.guess(randomized=True)["source"], "randomized")
        self.assertEqual(self.guess(is_self=True)["type"], "computer")

    def test_agreement_raises_disagreement_lowers_confidence(self):
        one = self.guess(hostname="ipcam")
        two = self.guess(hostname="ipcam", svc={"svc.xmeye": 20})
        self.assertGreater(two["confidence"], one["confidence"])
        mixed = self.guess(hostname="ipcam", svc={"PlayStation": 20})
        self.assertEqual(mixed["type"], "camera")
        self.assertLess(mixed["confidence"], one["confidence"])

    def test_single_stray_lookup_is_no_clue(self):
        self.assertEqual(self.guess(svc={"svc.xmeye": 1})["type"], "unknown")

    def test_user_override_wins_and_unknown_override_ignored(self):
        res = self.guess(hostname="ipcam", override="vacuum")
        self.assertEqual((res["type"], res["confidence"], res["source"]), ("vacuum", 1.0, "user"))
        self.assertEqual(self.guess(hostname="ipcam", override="spaceship")["type"], "camera")

    def test_localized_reason_and_names(self):
        res = self.guess(svc={"svc.samsung_acr": 30})
        self.assertIn("Samsung", devicetype.localize(res, "en")["reason"])
        self.assertEqual(devicetype.localize(res, "zh-Hant")["type_name"], "電視")
        for code in i18n.CODES:
            for t in devicetype.TYPES:
                self.assertTrue(i18n.has("devtype." + t))
                self.assertNotEqual(devicetype.type_name(t, code), "devtype." + t)
        cam = devicetype.localize(self.guess(bw={"rx_bytes": 0, "tx_bytes": 9e9}), "en")
        self.assertIn("9 GB", cam["reason"])   # Intl: at most one decimal (round 10e)

    def test_classify_all_reads_overrides(self):
        db = store.connect(":memory:")
        device(db, KID, "10.0.0.2", hostname="ipcam")
        store.set_profile(db, KID, type="printer")
        self.assertEqual(devicetype.classify_all(db, NOW)[KID]["type"], "printer")


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        device(self.db, KID, "10.0.0.2", hostname="Kid-Tablet")
        events(self.db, KID, "10.0.0.2", daytime())

    def test_grid_shape_and_local_time(self):
        g = activity.grid(self.db, KID, tz=UTC, now=NOW)
        self.assertEqual((len(g["grid"]), len(g["grid"][0])), (7, 24))
        self.assertEqual(g["total"], 50)
        self.assertEqual(sum(g["hourly"][10:20]), 50)
        self.assertEqual(g["typical_hours"], [[10, 20]])
        self.assertEqual(g["typical_text"], "10:00–20:00")
        tw = activity.grid(self.db, KID, tz=activity.local_tz("Asia/Taipei"), now=NOW)
        self.assertEqual(tw["typical_hours"], [[18, 4]])          # +8 h, wraps midnight
        self.assertEqual(tw["tz"], "Asia/Taipei")
        india = activity.grid(self.db, KID, tz=activity.local_tz("Asia/Kolkata"), now=NOW)
        self.assertEqual(sum(india["hourly"][15:16]), 5)          # 10:05 UTC -> 15:35 IST
        home = activity.grid(self.db, None, tz=UTC, now=NOW)
        self.assertEqual(home["total"], 50)

    def test_typical_hours_merges_one_hour_gaps(self):
        s = activity._blank()
        days = [datetime(2026, 10, d).date() for d in range(10, 15)]
        for d in days:
            for h in (7, 8, 10, 11, 20):
                s["date_hours"].add((d, h))
        self.assertEqual(activity.typical_hours(s), [[7, 12], [20, 21]])
        self.assertEqual(activity.hours_text([[22, 2], [7, 24]]), "22:00–02:00, 07:00–24:00")

    def test_time_zone_fallbacks(self):
        activity._warned_tz.clear()
        with self.assertLogs("netwarden.activity", "WARNING"):        # said once, in the log
            self.assertIsNotNone(activity.local_tz("No/Such_Zone"))  # system local, no crash
        with mock.patch.dict(os.environ, {"NETWARDEN_TZ": "Europe/Berlin"}):
            self.assertEqual(activity.tz_label(activity.local_tz()), "Europe/Berlin")
        with mock.patch.dict(os.environ, {"NETWARDEN_TZ": "Asia/Taipei"}), \
                mock.patch("zoneinfo.ZoneInfo", side_effect=Exception("no tzdata")), \
                self.assertLogs("netwarden.activity", "WARNING"):
            self.assertIsNotNone(activity.local_tz())                  # degrades gracefully
        activity._warned_tz.clear()
        self.assertEqual(activity.tz_label(timezone(timedelta(hours=5, minutes=30))), "UTC+05:30")
        self.assertEqual(activity.tz_label(timezone(timedelta(hours=-3))), "UTC-03:00")
        self.assertEqual(activity.tz_label(UTC), "UTC")

    def test_the_system_zone_honors_tz(self):
        """CI1: without NETWARDEN_TZ (or .env / the setting) the system zone is the TZ
        environment variable when set (docker run -e TZ=..., CI's TZ=UTC), then
        /etc/localtime; a POSIX rule we cannot name falls back to its UTC offset."""
        import time
        nothing = mock.patch.object(activity, "_configured_tz_name", return_value=None)
        cases = {"America/Los_Angeles": "America/Los_Angeles", ":Asia/Kolkata": "Asia/Kolkata",
                 "/usr/share/zoneinfo/Pacific/Auckland": "Pacific/Auckland", "UTC": "UTC"}
        try:
            for tz, want in cases.items():
                if want != "UTC" and activity._zone(want) is None:
                    continue   # (no tzdata for it here)
                with nothing, mock.patch.dict(os.environ, {"TZ": tz}), self.subTest(tz=tz):
                    if tz.startswith("/") and not os.path.exists(tz):
                        continue
                    self.assertEqual(activity.tz_label(activity.local_tz()), want)
            with nothing, mock.patch.dict(os.environ, {"TZ": "XYZ-8"}):
                time.tzset()
                self.assertIsNone(activity._system_zone_name())
                self.assertEqual(datetime(2026, 1, 1, tzinfo=activity.local_tz()).utcoffset(),
                                 timedelta(hours=8))
            # NETWARDEN_TZ still wins over TZ
            with mock.patch.dict(os.environ, {"TZ": "UTC", "NETWARDEN_TZ": "Asia/Taipei"}):
                self.assertEqual(activity.tz_label(activity.local_tz()), "Asia/Taipei")
        finally:
            time.tzset()

    def alerts(self, types=None):
        return activity.night_alerts(self.db, types=types or {KID: "tablet"}, tz=UTC, now=NOW)

    def test_night_activity_of_a_daytime_device_is_flagged(self):
        events(self.db, KID, "10.0.0.2", night())
        [a] = self.alerts()
        self.assertEqual((a["mac"], a["night_queries"], a["window"]), (KID, 12, "01:00–01:44"))
        self.assertEqual(a["ack"], "activity:night")
        self.assertIn("01:00–01:44", activity.explain(a, "en"))
        self.assertIn("深夜", activity.explain(a, "zh-Hant"))

    def test_conservative_skips(self):
        events(self.db, KID, "10.0.0.2", night(n=9))
        self.assertEqual(self.alerts(), [])                       # tiny count
        events(self.db, KID, "10.0.0.2", night(n=5, hour=2))
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.alerts({KID: "camera"}), [])        # always-on type
        self.assertEqual(self.alerts({KID: "speaker"}), [])

    def test_needs_three_days_of_history(self):
        db = store.connect(":memory:")
        device(db, KID, "10.0.0.2")
        events(db, KID, "10.0.0.2", daytime(days=range(2, 4)) + night())
        self.assertEqual(activity.night_alerts(db, types={KID: "phone"}, tz=UTC, now=NOW), [])

    def test_normally_night_active_device_is_not_flagged(self):
        for d in (2, 3, 4):
            events(self.db, KID, "10.0.0.2", night(n=4, days_ago=d))
        events(self.db, KID, "10.0.0.2", night())
        self.assertEqual(self.alerts(), [])

    def test_report_localizes(self):
        events(self.db, KID, "10.0.0.2", night())
        r = activity.report(self.db, KID, "ja", tz=UTC, now=NOW)
        self.assertEqual(r["weekdays"][0], "月")
        self.assertIn("UTC", r["summary"])
        self.assertTrue(r["unusual"]["text"])
        self.assertIn("%", r["night_share_text"])
        empty = activity.report(store.connect(":memory:"), None, "en", tz=UTC, now=NOW)
        self.assertEqual(empty["summary"], i18n.t("activity.no_data", "en"))


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.db = db = store.connect(":memory:")
        device(db, KID, "10.0.0.2", vendor="Samsung Electronics", hostname="Galaxy-Tab")
        device(db, CAM, "10.0.0.3", vendor="Shenzhen (generic IP camera)", hostname="ipcam")
        store.set_profile(db, KID, owner="小孩", room="小孩房")
        recent = [NOW - timedelta(hours=h) for h in range(1, 6)]
        events(db, KID, "10.0.0.2", recent, "tiktokv.com")
        events(db, KID, "10.0.0.2", recent[:2], "app-measurement.com", blocked=True)
        events(db, CAM, "10.0.0.3", recent, "star1.xmeye.net")
        events(db, CAM, "10.0.0.3", recent[:3], "xmeye.net")
        events(db, None, "10.0.0.99", recent[:1], "xmeye.net")             # unattributed client

    def test_devices_by_owner_room_vendor_ip_mac_type(self):
        for q, field in (("小孩", "owner"), ("小孩房", "room"), ("shenzhen", "vendor"),
                         ("10.0.0.3", "ip"), ("AA:00:00:00:00:02", "mac")):
            res = search.search(self.db, q, "en")
            self.assertTrue(res["devices"], q)
            self.assertEqual(res["devices"][0]["matched"], field, q)
        self.assertEqual(search.search(self.db, "camera", "en")["devices"][0]["mac"], CAM)
        self.assertEqual(search.search(self.db, "攝影機", "zh-Hant")["devices"][0]["mac"], CAM)

    def test_services_and_domains(self):
        res = search.search(self.db, "xmeye", "en")
        self.assertEqual(res["services"][0]["id"], "svc.xmeye")
        self.assertEqual(res["services"][0]["queries"], 9)
        self.assertEqual(res["services"][0]["devices"], 2)
        self.assertEqual({d["domain"] for d in res["domains"]}, {"xmeye.net", "star1.xmeye.net"})
        zh = search.search(self.db, "攝影機雲端", "zh-Hant")
        self.assertEqual(zh["services"][0]["id"], "svc.xmeye")
        self.assertEqual(search.search(self.db, "", "en")["devices"], [])
        self.assertEqual(search.search(self.db, "%", "en")["domains"], [])

    def test_domain_detail_with_subdomains_and_flags(self):
        d = search.domain_detail(self.db, "XMEYE.net.", "en")
        self.assertEqual(d["domains"], ["star1.xmeye.net", "xmeye.net"])
        self.assertEqual(d["queries"], 9)
        self.assertEqual(d["devices"][0]["mac"], CAM)
        self.assertEqual(d["devices"][1]["name"], "10.0.0.99")
        self.assertEqual(d["threat"]["severity"], "high-risk")
        self.assertIsNone(search.domain_detail(self.db, "tiktokv.com", "en")["threat"])
        t = search.domain_detail(self.db, "app-measurement.com", "en")
        self.assertEqual(t["tracker"]["entry"], "app-measurement.com")
        self.assertEqual(t["blocked"], 2)
        self.assertIsNone(search.domain_detail(self.db, "  ", "en"))
        self.assertEqual(search.domain_detail(self.db, "%", "en")["devices"], [])

    def test_service_detail(self):
        by_id = search.service_detail(self.db, "TikTok", "en")
        self.assertEqual([d["mac"] for d in by_id["devices"]], [KID])
        by_name = search.service_detail(self.db, "Camera cloud/P2P (XMEye)", "en")
        self.assertEqual(by_name["id"], "svc.xmeye")
        self.assertEqual(search.service_detail(self.db, "攝影機雲端/P2P (XMEye)", "zh-Hant")["id"],
                         "svc.xmeye")
        self.assertIsNone(search.service_detail(self.db, "Nope", "en"))


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.db = db = store.connect(":memory:")
        device(db, KID, "10.0.0.2", vendor="Acme", first_seen=NOW - timedelta(days=6))
        events(db, KID, "10.0.0.2", [NOW - timedelta(days=6)], "youtube.com")
        events(db, KID, "10.0.0.2", [NOW - timedelta(days=2)], "twitch.tv")
        events(db, KID, "10.0.0.2", [NOW - timedelta(days=1)], "odd-new.example")
        events(db, KID, "10.0.0.2", [NOW - timedelta(hours=5)], "xmeye.net")
        store.insert_port_checks(db, [{"mac": KID, "ip": "10.0.0.2", "port": 23, "open": True,
                                       "ts": iso(NOW - timedelta(hours=1))}])
        store.add_ack(db, KID, "port:23")
        store.set_label(db, KID, "小孩的平板")
        store.set_profile(db, KID, owner="小孩")
        # one week of hourly traffic, with a 3-hour 30 GB download 2 days ago
        rx, rows = 0, []
        for k in range(24 * 7, -1, -1):
            rx += 50_000_000 + (10_000_000_000 if 48 <= k <= 50 else 0)
            rows.append({"mac": KID, "ip": "10.0.0.2", "ts": iso(NOW - timedelta(hours=k)),
                         "rx_bytes": rx, "tx_bytes": 0})
        store.insert_traffic_samples(db, rows)

    def test_items_newest_first_with_every_kind(self):
        items = timeline.timeline(self.db, KID, "en", tz=UTC, now=NOW)
        kinds = [i["kind"] for i in items]
        self.assertEqual([i["ts"] for i in items], sorted((i["ts"] for i in items), reverse=True))
        for k in ("first_seen", "new_service", "new_domain", "threat", "bandwidth_spike",
                  "open_port", "user_mute", "user_rename", "user_profile"):
            self.assertIn(k, kinds)
        text = {i["kind"]: i["text"] for i in items}
        self.assertIn("Twitch", text["new_service"])
        self.assertNotIn("YouTube", " ".join(i["text"] for i in items if i["kind"] == "new_service"))
        self.assertRegex(text["bandwidth_spike"], r"30\.\d GB in 3 h")
        self.assertIn("port 23", text["user_mute"])
        self.assertIn("小孩的平板", text["user_rename"])
        self.assertIn("小孩", text["user_profile"])
        self.assertRegex(items[0]["when"], r"^\d{4}-\d\d-\d\d \d\d:\d\d$")

    def test_trust_and_localization_and_unknown(self):
        store.add_ack(self.db, KID)
        items = timeline.timeline(self.db, KID, "zh-Hant", tz=UTC, now=NOW)
        self.assertIn("user_trust", [i["kind"] for i in items])
        self.assertTrue(all("{" not in i["text"] for i in items))
        self.assertIsNone(timeline.timeline(self.db, "no:such", "en"))

    def test_no_spikes_without_enough_traffic(self):
        self.assertEqual(timeline.bandwidth_spikes(self.db, "no:such", NOW), [])


if __name__ == "__main__":
    unittest.main()
