"""
Tests for netwarden.alerts - the proactive "what changed?" engine.

Pure and deterministic, no network, no LLM: we seed an in-memory DB with events
placed in the baseline window (days ago) and the recent window (hours ago), then
assert the engine separates a brand-new device from a known device that merely
picked up a new service, and reuses threat intel.
"""
import unittest
from datetime import datetime, timedelta, timezone

from netwarden import alerts, i18n, store, threatintel


def _ts(days_ago=0.0, hours_ago=0.0, uniq=0) -> str:
    t = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return t.replace(microsecond=uniq % 1_000_000).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ev(mac, ip, domain, ts, blocked=0):
    return {"source": "demo", "ts": ts, "client_ip": ip, "client_name": None,
            "domain": domain, "qtype": "A", "status": "NOERROR", "reason": "",
            "blocked": blocked, "cached": 0, "upstream": "", "elapsed_ms": 1.0,
            "device_mac": mac}


class AlertsTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        # A known PC: first seen a week ago; normal = github, both windows.
        store.upsert_device(self.db, {"ip": "10.0.0.2", "mac": "aa:00", "vendor": "Dell",
                                      "hostname": "pc", "randomized": False, "is_self": True},
                            seen=_ts(days_ago=7))
        # A brand-new vacuum: first seen 3 hours ago (inside the recent window).
        store.upsert_device(self.db, {"ip": "10.0.0.9", "mac": "bb:00", "vendor": "Roborock",
                                      "hostname": "vac", "randomized": False, "is_self": False},
                            seen=_ts(hours_ago=3))
        uniq = 0
        evs = []
        # PC baseline (4 days ago) + recent: github in BOTH -> not a change.
        for when in (96, 1):  # hours: 4 days ago, 1 hour ago
            for _ in range(3):
                uniq += 1
                evs.append(_ev("aa:00", "10.0.0.2", "github.com", _ts(hours_ago=when, uniq=uniq)))
        # PC recent-only: a flagged domain it never used before -> change + threat.
        for _ in range(2):
            uniq += 1
            evs.append(_ev("aa:00", "10.0.0.2", "xmeye.net", _ts(hours_ago=2, uniq=uniq)))
        # Vacuum: recent only.
        for _ in range(4):
            uniq += 1
            evs.append(_ev("bb:00", "10.0.0.9", "roborock.com", _ts(hours_ago=2, uniq=uniq)))
        store.insert_events(self.db, evs)

    def test_new_device_detected(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        macs = {d["mac"] for d in r["new_devices"]}
        self.assertIn("bb:00", macs)       # the vacuum joined in the recent window
        self.assertNotIn("aa:00", macs)    # the PC is a week old -> not new

    def test_behavior_change_vs_baseline(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        pc = [c for c in r["behavior_changes"] if c["mac"] == "aa:00"]
        self.assertEqual(len(pc), 1)
        # xmeye.net classifies as the camera-cloud service; github was already baseline.
        self.assertTrue(any("XMEye" in s for s in pc[0]["new_services"]))
        # the vacuum has NO baseline, so it is a new device, not a "change"
        self.assertFalse(any(c["mac"] == "bb:00" for c in r["behavior_changes"]))

    def test_threats_ride_recent_window(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        self.assertTrue(any(t["domain"] == "xmeye.net"
                            and t["severity"] == threatintel.SEV_HIGH_RISK
                            for t in r["threats"]))

    def test_digest_is_human_readable(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        text = alerts.render_digest(r)
        self.assertIn("網路週報", text)
        self.assertIn("Roborock", text)       # new device named
        self.assertIn("XMEye", text)           # the new service / threat surfaced

    def test_digest_renders_in_english(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        text = alerts.render_digest(r, lang="en")
        self.assertIn("weekly network report", text)
        self.assertIn("New devices", text)
        self.assertIn("Camera cloud/P2P (XMEye)", text)    # service name in English
        self.assertIn("High risk", text)
        self.assertIn("botnets such as Mirai", text)       # threat "why" in English
        self.assertNotIn("網路週報", text)

    def test_digest_default_is_traditional_chinese(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        text = alerts.render_digest(r)
        self.assertEqual(text, alerts.render_digest(r, lang="zh-Hant"))
        self.assertIn("攝影機雲端/P2P (XMEye)", text)    # localized service name
        self.assertIn("🟠 高風險", text)
        self.assertIn("殭屍網路", text)                   # Traditional threat text
        self.assertNotIn("摄像头", text)                  # no Simplified leaking in

    def test_digest_renders_in_every_language(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        for code, _name, _llm in i18n.LANGS:
            text = alerts.render_digest(r, lang=code)
            self.assertIn("Roborock", text)
            self.assertNotIn("{", text)   # every placeholder filled

    def test_localize_keeps_ids_and_translates_names(self):
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        ja = alerts.localize(r, "ja")
        pc = next(c for c in ja["behavior_changes"] if c["mac"] == "aa:00")
        self.assertEqual(pc["new_services"], ["カメラのクラウド/P2P (XMEye)"])
        self.assertEqual(pc["new_service_ids"], ["svc.xmeye"])
        self.assertTrue(all("XMEye" in t["label"] for t in ja["threats"]))

    def test_user_labels_name_devices_everywhere(self):
        store.set_label(self.db, "aa:00", "書房電腦")
        store.set_label(self.db, "bb:00", "客廳掃地機")
        r = alerts.compute(self.db, recent_hours=24, baseline_days=7)
        self.assertEqual(next(d for d in r["new_devices"] if d["mac"] == "bb:00")["name"],
                         "客廳掃地機")
        self.assertEqual(next(c for c in r["behavior_changes"] if c["mac"] == "aa:00")["name"],
                         "書房電腦")
        self.assertTrue(all(t["device"] == "書房電腦" for t in r["threats"]))
        text = alerts.render_digest(r)
        self.assertIn("書房電腦", text)
        self.assertIn("客廳掃地機", text)

    def test_quiet_network_says_so(self):
        quiet = store.connect(":memory:")
        store.upsert_device(quiet, {"ip": "10.0.0.2", "mac": "aa:00", "vendor": "Dell",
                                    "hostname": "pc", "randomized": False, "is_self": True},
                            seen=_ts(days_ago=30))
        quiet.execute("INSERT INTO dns_events (source,ts,client_ip,domain,qtype,status,"
                      "reason,blocked,cached,upstream,elapsed_ms,device_mac) "
                      "VALUES ('demo',?,?,?,?,?,?,?,?,?,?,?)",
                      (_ts(days_ago=5), "10.0.0.2", "github.com", "A", "NOERROR", "",
                       0, 0, "", 1.0, "aa:00"))
        quiet.commit()
        r = alerts.compute(quiet, recent_hours=24, baseline_days=7)
        self.assertFalse(alerts.has_alerts(r))
        self.assertIn("一切如常", alerts.render_digest(r))
        self.assertIn("All normal", alerts.render_digest(r, lang="en"))


if __name__ == "__main__":
    unittest.main()
