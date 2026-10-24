"""
Stage V: browser-verification polish, cold-start performance and small leftovers.

- store.bandwidth_totals (the CSV's cheap window totals) == bandwidth_summary's totals;
  store.bandwidth_days (rolling 24 h buckets of one device)
- alerts.bandwidth_spikes: the conservative "data spike" alert (demo story, mutes,
  thresholds), its digest section in every language, the snapshot / offline AI wiring
- cache.fresher + runner.Warmer: the web server's startup / keep-warm pass
- export: memoized window inputs, user notes still applied at once
- `netwarden search` (CLI)
- timeline: no "(?)" for a device without a vendor
- page files: one name per device everywhere, empty-DB hero, spike rows, focus ring
"""
import contextlib
import http.client
import io
import json
import re
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import (__main__ as cli, alerts, brain, cache, demo, export, i18n, offline_ai,
                       runner, store, timeline, web)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
PC = next(d["mac"] for d in demo.DEVICES if d["hostname"] == "DESKTOP-7Q2K9LM")
PS5 = next(d["mac"] for d in demo.DEVICES if d["hostname"] == "PS5")


def _iso(dt):
    return dt.strftime(ISO)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class DemoDB(unittest.TestCase):
    """A fresh demo home per test class (file DB, so netwarden.cache is exercised)."""

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
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        cache.clear()


# --- bandwidth math --------------------------------------------------------------------

class BandwidthTotalsTests(DemoDB):
    def test_totals_match_the_full_summary(self):
        now = datetime.now(timezone.utc)
        for since in (now - timedelta(hours=24), now - timedelta(days=7), now - timedelta(hours=1)):
            full = store.bandwidth_summary(self.db, _iso(since))
            totals = store.bandwidth_totals(self.db, _iso(since))
            self.assertEqual(set(full), set(totals))
            for key, s in full.items():
                self.assertEqual((totals[key]["rx_bytes"], totals[key]["tx_bytes"]),
                                 (s["rx_bytes"], s["tx_bytes"]), key)

    def test_totals_on_resets_and_parallel_series(self):
        db = store.connect(":memory:")
        now = datetime.now(timezone.utc)
        rows = []
        # two IP series of one MAC (diffed separately) + a counter reset in the first
        for k, (a, b) in enumerate([(100, 1000), (300, 1500), (50, 1600), (150, 2000)]):
            ts = _iso(now - timedelta(hours=4 - k))
            rows += [{"mac": "aa", "ip": "10.0.0.2", "ts": ts, "rx_bytes": a, "tx_bytes": 0},
                     {"mac": "aa", "ip": "fe80::2", "ts": ts, "rx_bytes": b, "tx_bytes": 0}]
        rows.append({"mac": None, "ip": "10.0.0.9", "ts": _iso(now), "rx_bytes": 5, "tx_bytes": 5})
        store.insert_traffic_samples(db, rows)
        since = _iso(now - timedelta(hours=5))
        self.assertEqual(store.bandwidth_totals(db, since),
                         {"aa": {"rx_bytes": 200 + 50 + 100 + 500 + 100 + 400, "tx_bytes": 0}})
        self.assertEqual(store.bandwidth_totals(db, since)["aa"]["rx_bytes"],
                         store.bandwidth_summary(db, since)["aa"]["rx_bytes"])

    def test_bandwidth_days_buckets(self):
        db = store.connect(":memory:")
        now = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
        rows, rx = [], 0
        for h in range(72, -1, -6):       # every 6 h for 3 days, 600 B per step
            rx += 600
            if h == 30:
                rx = 100                  # reset: the step counts as 100
            rows.append({"mac": "aa", "ip": "10.0.0.2", "ts": _iso(now - timedelta(hours=h)),
                         "rx_bytes": rx, "tx_bytes": 0})
        store.insert_traffic_samples(db, rows)
        days = store.bandwidth_days(db, "aa", now, 5)
        self.assertEqual(days[0], 4 * 600)            # (0, 24h]: 4 steps... plus the one AT 24h
        self.assertEqual(days[1], 3 * 600 + 100)      # one step is the reset
        self.assertEqual(days[2], 4 * 600)
        self.assertEqual(days[3:], [None, None])      # no data that far back
        self.assertEqual(store.bandwidth_days(db, "unknown", now, 3), [None] * 3)


# --- the "data spike" alert -------------------------------------------------------------

class BandwidthSpikeTests(DemoDB):
    def test_demo_story_only_the_pc_backup(self):
        spikes = alerts.bandwidth_spikes(self.db, 24)
        self.assertEqual([s["mac"] for s in spikes], [PC])       # not the PS5 (2 days ago)
        s = spikes[0]
        self.assertEqual(s["ack"], "bandwidth:spike")
        self.assertGreaterEqual(s["ratio"], alerts.SPIKE_RATIO)
        self.assertGreater(s["tx_bytes"], 10e9)
        self.assertGreater(s["total"] - s["typical"], alerts.SPIKE_MIN_BYTES)

    def test_compute_respects_mute_and_trust(self):
        self.assertTrue(alerts.compute(self.db)["bandwidth_spikes"])
        store.add_ack(self.db, PC, "bandwidth:spike")
        try:
            self.assertEqual(alerts.compute(self.db)["bandwidth_spikes"], [])
        finally:
            store.remove_ack(self.db, PC, "bandwidth:spike")
        store.add_ack(self.db, PC, "")
        try:
            self.assertEqual(alerts.compute(self.db)["bandwidth_spikes"], [])
        finally:
            store.remove_ack(self.db, PC, "")

    def test_thresholds_are_conservative(self):
        db = store.connect(":memory:")
        now = datetime.now(timezone.utc)

        def device(mac, per_day, today, days=8):
            rows, rx = [], 0
            for h in range(days * 24, -1, -1):
                rx += int((today if h < 24 else per_day) / 24)
                rows.append({"mac": mac, "ip": "10.0.0." + mac[-1], "rx_bytes": rx, "tx_bytes": 0,
                             "ts": _iso(now - timedelta(hours=h))})
            store.insert_traffic_samples(db, rows)
        device("m1", 1e9, 10e9)            # 10x a 1 GB day: a spike
        device("m2", 1e9, 3e9)             # 3x: below the ratio
        device("m3", 5e9, 18e9)            # 3.6x of 5 GB: below the ratio
        device("m4", 0.1e9, 1.5e9)         # 15x, but only 1.5 GB: below the floor
        device("m5", 1e9, 10e9, days=3)    # a spike, but too little history
        self.assertEqual([s["mac"] for s in alerts.bandwidth_spikes(db, 24, now)], ["m1"])

    def test_no_sensor_no_spikes(self):
        db = store.connect(":memory:")
        self.assertEqual(alerts.bandwidth_spikes(db, 24), [])

    def test_digest_section_in_every_language(self):
        result = alerts.compute(self.db)
        self.assertTrue(alerts.has_alerts({**{k: [] for k in result if isinstance(result[k], list)},
                                           "bandwidth_spikes": result["bandwidth_spikes"]}))
        for code in i18n.CODES:
            with self.subTest(lang=code):
                text = alerts.render_digest(result, code)
                self.assertIn(i18n.t("digest.bandwidth_spikes", code), text)
                line = alerts.localize(result, code)["bandwidth_spikes"][0]["text"]
                self.assertIn(line, text)
                self.assertIn("DESKTOP-7Q2K9LM", line)
                self.assertNotRegex(line, r"[{}]")
                self.assertRegex(line, r"(?<![\d.])6(?![\d.])")   # the ratio, a whole number
        # the weekly cron default stays zh-Hant
        self.assertIn("流量異常暴增", alerts.render_digest(result))

    def test_snapshot_and_offline_ai_know_the_spike(self):
        snap = brain.snapshot(self.db)
        pc = next(d for d in snap["devices"] if d["mac"] == PC)
        self.assertGreaterEqual(pc["bandwidth_spike"]["ratio"], alerts.SPIKE_RATIO)
        self.assertTrue(all("bandwidth_spike" not in d for d in snap["devices"] if d["mac"] != PC))
        out = offline_ai.summarize(self.db, snap, "en")
        self.assertIn(i18n.t("digest.bandwidth_spikes", "en"), out)
        self.assertIn("bandwidth_spike", brain.PROFILE)


# --- cache warm-up ------------------------------------------------------------------------

class FresherTests(DemoDB):
    def test_fresher_recomputes_older_entries_in_this_thread_only(self):
        calls = []

        def compute():
            calls.append(1)
            return {"n": len(calls)}
        cache.memo(self.db, "f", (), compute)
        time.sleep(0.05)
        cache.memo(self.db, "f", (), compute)
        self.assertEqual(len(calls), 1)                  # normal TTL: a hit
        other = []
        with cache.fresher(0.01):
            t = threading.Thread(target=lambda: other.append(
                cache.memo(store.connect(self.path), "f", (), compute)))
            t.start()
            t.join(5)
            self.assertEqual(len(calls), 1)              # another thread: unaffected
            cache.memo(self.db, "f", (), compute)
        self.assertEqual(len(calls), 2)                  # inside: older than 10 ms = stale
        cache.memo(self.db, "f", (), compute)
        self.assertEqual(len(calls), 2)                  # outside again: the new entry hits


class WarmerTests(DemoDB):
    def wait_passes(self, w, n, timeout=20):
        end = time.monotonic() + timeout
        while w.passes < n and time.monotonic() < end:
            time.sleep(0.02)
        return w.passes

    def test_startup_pass_fills_the_cache(self):
        w = runner.Warmer(self.path, 24).start()
        try:
            self.assertGreaterEqual(self.wait_passes(w, 1), 1)
            hits = cache.stats["hits"]
            brain.snapshot(self.db, hours=24)
            alerts.compute(self.db, recent_hours=24)
            self.assertGreaterEqual(cache.stats["hits"], hits + 2)   # the page finds it ready
        finally:
            w.stop()
            w.thread.join(5)
        self.assertFalse(w.thread.is_alive())

    def test_keeps_warming_only_while_the_page_is_used(self):
        w = runner.Warmer(self.path, 24)
        w.EVERY = 0.05
        w.start()
        try:
            self.assertGreaterEqual(self.wait_passes(w, 2), 2)
            w.last_use = time.monotonic() - w.ACTIVE - 1        # nobody looked for a while
            time.sleep(0.3)
            idle = w.passes
            time.sleep(0.3)
            self.assertEqual(w.passes, idle)
            w.touch()
            self.assertGreater(self.wait_passes(w, idle + 1), idle)
        finally:
            w.stop()
            w.thread.join(5)

    def test_a_broken_db_never_kills_the_thread(self):
        blocker = Path(self.tmp.name) / "a-file"
        blocker.write_text("not a directory")
        w = runner.Warmer(blocker / "x.db", 24)          # its "directory" is a file
        w.EVERY = 0.05
        w.start()
        try:
            time.sleep(0.3)
            self.assertTrue(w.thread.is_alive())
            self.assertEqual(w.passes, 0)
        finally:
            w.stop()
            w.thread.join(5)

    def test_make_server_warm_flag_and_api_touch(self):
        srv = web.make_server(self.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        self.assertIsNone(web.Handler.warmer)
        srv.server_close()
        srv = web.make_server(self.path, 0, {brain.OFFLINE_ENV: "1"}, "en", warm=True)
        w = web.Handler.warmer
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            self.assertIsInstance(w, runner.Warmer)
            w.last_use = 0.0
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
            c.request("GET", "/static/app.css")
            c.getresponse().read()
            self.assertEqual(w.last_use, 0.0)                  # static files: not "use"
            c.request("GET", "/api/meta")
            c.getresponse().read()
            self.assertGreater(w.last_use, 0.0)
        finally:
            w.stop()
            srv.shutdown()
            srv.server_close()
            web.Handler.warmer = None


# --- export ------------------------------------------------------------------------------

class ExportTests(DemoDB):
    def test_csv_bytes_match_the_seven_day_summary(self):
        rows = {d["mac"]: d for d in export.inventory(self.db, "en")}
        since = export._since(export.EXPORT_DAYS)
        full = store.bandwidth_summary(self.db, since)
        self.assertEqual(rows[PS5]["rx_bytes"], full[PS5]["rx_bytes"])
        self.assertEqual(rows[PC]["tx_bytes"], full[PC]["tx_bytes"])

    def test_second_export_is_cached_but_notes_apply_at_once(self):
        export.devices_csv(self.db, "en")
        misses = cache.stats["misses"]
        export.devices_csv(self.db, "ja")                       # another language: cached
        self.assertEqual(cache.stats["misses"], misses)
        store.set_label(self.db, PS5, "=Kid's console")
        try:
            body = export.devices_csv(self.db, "en").decode("utf-8-sig")
            self.assertIn("'=Kid's console", body)             # fresh and formula-safe
        finally:
            store.set_label(self.db, PS5, "")


# --- CLI search ----------------------------------------------------------------------------

class SearchCliTests(DemoDB):
    def test_text_json_and_no_match(self):
        code, out, _ = run_cli("search", "--db", str(self.path), "--lang", "en", "tik")
        self.assertEqual(code, 0)
        self.assertIn("Services", out)
        self.assertIn("TikTok", out)
        self.assertIn("tiktokv.com", out)
        code, out, _ = run_cli("search", "--db", str(self.path), "小孩")
        self.assertIn(i18n.t("ui.search_devices", "zh-Hant"), out)    # default zh-Hant
        self.assertIn("Galaxy-Tab-A7", out)
        code, out, _ = run_cli("--lang", "de", "search", "--db", str(self.path), "--json", "ps5")
        res = json.loads(out)
        self.assertEqual(res["q"], "ps5")
        self.assertEqual(res["devices"][0]["mac"], PS5)
        code, out, _ = run_cli("search", "--db", str(self.path), "--lang", "fr", "zzz-nothing")
        self.assertEqual(out.strip(), i18n.t("ui.search_none", "fr", q="zzz-nothing"))

    def test_listed_in_help_and_needs_a_query(self):
        _, out, _ = run_cli("--help")
        self.assertIn("search", out)
        code, _, err = run_cli("search", "--db", str(self.path))
        self.assertEqual(code, 2)
        self.assertTrue(err)


# --- timeline ------------------------------------------------------------------------------

class TimelineTests(DemoDB):
    def test_first_seen_without_vendor_has_no_question_mark(self):
        phone = next(d["mac"] for d in demo.DEVICES if d["randomized"] and not d.get("vendor")
                     and not d.get("hostname"))
        for code in ("en", "zh-Hant"):
            items = timeline.timeline(self.db, phone, code)
            first = next(i for i in items if i["kind"] == "first_seen")
            self.assertEqual(first["text"], i18n.t("tl.first_seen_plain", code))
        tv = next(d["mac"] for d in demo.DEVICES if d["hostname"] == "Samsung-TV")
        first = next(i for i in timeline.timeline(self.db, tv, "en") if i["kind"] == "first_seen")
        self.assertIn("Samsung", first["text"])


# --- page files ------------------------------------------------------------------------------

class PageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = web.static_file("app.js")[0].decode()
        cls.css = web.static_file("app.css")[0].decode()

    def test_one_name_per_device_everywhere(self):
        # rows from the server name a nameless device by its MAC; the page uses its own name
        self.assertIn("const rowName = ", self.js)
        att = self.js[self.js.index("function attention()"):self.js.index("function attItem(")]
        self.assertNotRegex(att, r"title: (v|n|d|c)\.name\b")
        self.assertNotIn("${t.device} →", self.js)
        self.assertNotIn("${x.name} ·", self.js)
        self.assertIn("function ownerDevices(p)", self.js)

    def test_empty_home_is_not_all_good_and_spikes_are_listed(self):
        self.assertIn("T('app.ov.no_data_yet')", self.js)
        self.assertIn(".hero.idle", self.css)
        self.assertIn("a.bandwidth_spikes", self.js)
        self.assertIn("T('ui.tag_spike')", self.js)
        self.assertIn(".tag-spike", self.css)
        badges = self.js[self.js.index("function badges(d)"):]
        self.assertIn("d.bandwidth_spike", badges[:badges.index("\n}")])
        self.assertIn("!!d.bandwidth_spike", self.js)               # "Needs attention" filter

    def test_layout_fixes(self):
        self.assertIn("#main:focus { outline: none; }", self.css)
        self.assertIn('class="c-seen"', self.js)
        # phones: the search box is an icon whose label stays for screen readers
        phone = self.css[self.css.index("@media (max-width: 760px)"):]
        self.assertRegex(phone, r"\.searchbtn \.lbl \{ position: absolute; width: 1px")


if __name__ == "__main__":
    unittest.main()
