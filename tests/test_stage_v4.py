"""
Stage V4: fixes from the real-browser verification of round 3 + V3.

- the Suggestions list uses the same order as "Next best steps" (worst, then biggest gain)
- the score trend carries each day's level (the bars are colored by it)
- one "unusual hours" list: a night a bedtime rule watches is neither an alert nor a
  device flag in the AI snapshot (alerts.unusual_hours is used by both)
- the printable report: display names (never a bare MAC), bedtime hits only in their own
  section, per-cell labels for the stacked phone table
- /offline: the hint is a sentence with the file name below it (no glued dash)
- the pairing hints point to Settings, where the card is on the computer
- perf: activity.grid() is cached and warmed; at most two data GETs run at once
"""
import http.client
import json
import re
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from html import escape
from pathlib import Path
from unittest import mock

from netwarden import (activity, alerts, bedtime, brain, cache, demo, family_report, i18n,
                       runner, score, store, suggestions, web)

ENV = {brain.OFFLINE_ENV: "1"}
MAC_RE = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
LOCALES = Path(i18n.__file__).parent / "locales"


class DemoDB(unittest.TestCase):
    """One demo database (on disk, so netwarden.cache is in play) for the whole class."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.db = store.connect(self.path)
        self.addCleanup(self.db.close)


class OrderAndTrendTests(DemoDB):
    def test_open_suggestions_in_next_steps_order(self):
        r = suggestions.report(self.db, "en", ENV)
        self.assertGreater(len(r["open"]), 3)
        keys = [(suggestions.SEVERITIES.index(i["severity"]), -i["points"]) for i in r["open"]]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([i["id"] for i in r["top"]], [i["id"] for i in r["open"][:3]])

    def test_trend_points_carry_their_level(self):
        r = score.report(self.db, "en", ENV)
        self.assertTrue(r["trend"])
        for t in r["trend"]:
            self.assertEqual(t["level"], score.level(t["score"]))


class UnusualHoursTests(DemoDB):
    def _night(self):
        mac = next(d["mac"] for d in demo.DEVICES if not d.get("is_self"))
        return mac, [{"mac": mac, "window": "01:10–02:40", "first_ts": "2026-01-01T17:10:00Z",
                      "last_ts": "2026-01-01T18:40:00Z", "night_queries": 40}]

    def _flags(self):
        cache.clear()
        snap = brain.snapshot(self.db, hours=24)
        return {d["mac"]: d.get("unusual_hours") for d in snap["devices"]}

    def test_alert_and_device_flag_agree_with_bedtime_rules(self):
        mac, night = self._night()
        with mock.patch.object(activity, "night_alerts", lambda db, **kw: list(night)):
            with mock.patch.object(bedtime, "suppress_night", lambda db, n, tz=None: n):
                self.assertEqual([a["mac"] for a in alerts.unusual_hours(self.db)], [mac])
                self.assertEqual(self._flags()[mac], "01:10–02:40")
            # a bedtime rule watches that night: no alert AND no flag for the AI
            with mock.patch.object(bedtime, "suppress_night", lambda db, n, tz=None: []):
                self.assertEqual(alerts.unusual_hours(self.db), [])
                self.assertIsNone(self._flags()[mac])
                self.assertEqual(alerts.compute(self.db)["unusual_hours"], [])


class ReportTests(DemoDB):
    def test_no_bare_mac_and_cell_labels(self):
        for lang in ("en", "zh-Hant"):
            html = family_report.render(self.db, lang)
            self.assertEqual(MAC_RE.findall(html), [], lang)
            for k in ("week", "avg", "today"):
                self.assertIn(f'data-l="{escape(i18n.t("rep.th_" + k, lang))}"', html)

    def test_bedtime_hits_only_in_their_own_section(self):
        r = {k: [] for k in ("threats", "exposure", "upnp", "unusual_hours", "bandwidth_spikes",
                             "visibility", "new_devices", "behavior_changes")}
        r["bedtime"] = [{"text": "BEDTIME-HIT"}]
        r["unusual_hours"] = [{"text": "NIGHT-HIT"}]
        lines = family_report._security_lines(r, "en")
        self.assertEqual(lines, ["NIGHT-HIT"])


class TextTests(unittest.TestCase):
    def test_offline_hint_is_a_sentence_above_the_file_name(self):
        for code in i18n.CODES:
            hint = i18n.t("app.offline.hint", code)
            self.assertFalse(hint[:1] in "-–—―", code)
            page = web.offline_html(code).decode("utf-8")
            self.assertLess(page.index('id="off-hint"'), page.index(r"scripts\start_windows.cmd"))

    def test_pairing_hints_point_to_settings(self):
        for code in i18n.CODES:
            data = json.loads((LOCALES / f"{code}.json").read_text(encoding="utf-8"))
            for key in ("app.pair.page_intro", "cli.lan.pair_hint", "app.wz.phone_later"):
                self.assertIn(data["app.nav.settings"], data[key], (code, key))
                self.assertIn(data["app.pair.title"], data[key], (code, key))
            self.assertIn("{pct}", data["app.h.loss_hour"], code)
            self.assertIn("{n}", data["app.nav.more_count"], code)


class GridCacheTests(DemoDB):
    def test_grid_cached_and_warmed(self):
        g1 = activity.grid(self.db)
        hits = cache.stats["hits"]
        g2 = activity.grid(self.db)
        self.assertEqual(g1, g2)
        self.assertEqual(cache.stats["hits"], hits + 1)
        g2["grid"][0][0] = -1                               # callers get private copies
        self.assertNotEqual(activity.grid(self.db)["grid"][0][0], -1)
        misses = cache.stats["misses"]
        activity.grid(self.db, now=activity.datetime.now(activity.timezone.utc))   # pinned: direct
        self.assertEqual(cache.stats["misses"], misses)
        cache.clear()
        runner.warm(self.db, env=ENV)
        misses = cache.stats["misses"]
        with cache.batch():
            activity.grid(self.db)
        self.assertEqual(cache.stats["misses"], misses)


class DataGateTests(DemoDB):
    def test_at_most_two_data_gets_at_once(self):
        now = {"api": 0, "max": 0, "static_during_api": 0}
        lock = threading.Lock()
        real = web.Handler._get

        def slow(handler):
            api = handler.path.startswith("/api/")
            with lock:
                if api:
                    now["api"] += 1
                    now["max"] = max(now["max"], now["api"])
                elif now["api"]:
                    now["static_during_api"] += 1
            try:
                if api:
                    time.sleep(0.15)
                real(handler)
            finally:
                if api:
                    with lock:
                        now["api"] -= 1

        srv = web.make_server(self.path, 0, ENV, "en", 24)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

        def get(p):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            c.request("GET", p)
            r = c.getresponse()
            r.read()
            c.close()
            return r.status

        with mock.patch.object(web.Handler, "_get", slow):
            with ThreadPoolExecutor(8) as ex:
                api = [ex.submit(get, "/api/upnp") for _ in range(6)]
                time.sleep(0.05)
                static = [ex.submit(get, "/static/app.css") for _ in range(2)]
                self.assertEqual([f.result() for f in static], [200, 200])
                self.assertEqual([f.result() for f in api], [200] * 6)
        self.assertEqual(now["max"], 2)
        self.assertGreater(now["static_during_api"], 0)    # pages never wait for a slot


if __name__ == "__main__":
    unittest.main()
