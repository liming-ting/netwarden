"""Round 10e: coherence and formatting.

- ONE formatting layer: i18n.num / pct / unit / size / ms and list_sep write what the
  browser's Intl does in each language (tests/fixtures/intl_formats.json, made by node from
  app.js's own fmt block - tests/js/intl_formats_test.js); locale texts never write a unit
  or "%" next to a placeholder (i18n --check: unit_literal).
"""
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from netwarden import i18n

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "intl_formats.json").read_text(encoding="utf-8"))


class IntlFixtureTests(unittest.TestCase):
    def test_every_language_is_in_the_fixture(self):
        self.assertEqual(sorted(FIXTURE["langs"]), sorted(i18n.CODES))

    def test_numbers(self):
        for lang, f in FIXTURE["langs"].items():
            for v, d, trim, want in f["num"]:
                with self.subTest(lang=lang, v=v, d=d, trim=trim):
                    self.assertEqual(i18n.num(v, lang, d, trim=trim), want)

    def test_percents(self):
        for lang, f in FIXTURE["langs"].items():
            for v, d, sign, want in f["pct"]:
                with self.subTest(lang=lang, v=v, sign=sign):
                    self.assertEqual(i18n.pct(v, lang, d, sign=sign), want)

    def test_sizes(self):
        from netwarden import brain
        for lang, f in FIXTURE["langs"].items():
            for n, want in f["size"]:
                with self.subTest(lang=lang, n=n):
                    self.assertEqual(i18n.size(n, lang), want)
                    self.assertEqual(brain.human_bytes(n, lang), want)

    def test_milliseconds(self):
        for lang, f in FIXTURE["langs"].items():
            for v, want in f["ms"]:
                with self.subTest(lang=lang, v=v):
                    self.assertEqual(i18n.ms(v, lang), want)

    def test_month_days(self):
        # fix review 9: the bedtime preview wrote "Пн 10-19"
        from netwarden import bedtime
        for lang, f in FIXTURE["langs"].items():
            for d, want in f["day"]:
                with self.subTest(lang=lang, d=d):
                    self.assertEqual(i18n.month_day(d, lang), want)
                    self.assertTrue(bedtime.night_label(d, lang).endswith(" " + want))

    def test_failure_rates_match_the_health_tile(self):
        # fix review 7: "8.2% failed" in the summary, "8% failed" on the tile
        from netwarden import nethealth
        self.assertEqual(nethealth._fmt_pct(0.082, "en"), "8.2%")
        self.assertEqual(nethealth._fmt_pct(0.25, "en"), "25%")
        body = APP_JS[APP_JS.index("  rate(x) {"):]
        self.assertIn("x > 0 && x < 0.1 ? 1 : 0", body[:300])
        self.assertIn("T('app.h.fails', { pct: fmt.rate(dns.fail_rate", APP_JS)

    def test_list_separator(self):
        for lang, f in FIXTURE["langs"].items():
            with self.subTest(lang=lang):
                self.assertEqual(i18n.t("list_sep", lang), f["list_sep"])

    def test_texts_get_formatted_units(self):
        self.assertIn("14 %", i18n.t("score.item.loss", "de", pct=14))
        self.assertIn("14%", i18n.t("score.item.loss", "en", pct=14))
        self.assertIn("2,5 %", i18n.t("score.item.dns_fail", "ru", pct=2.5))
        self.assertIn("128 ms", i18n.t("score.item.latency", "fr", ms=128))
        self.assertIn("128 мс", i18n.t("score.item.latency", "ru", ms=128))
        self.assertIn("1 GB", i18n.t("why.threshold.spike", "en", size=i18n.size(1e9, "en"), ratio=4, days=7))
        self.assertIn("1 Go", i18n.t("why.threshold.spike", "fr", size=i18n.size(1e9, "fr"), ratio=4, days=7))
        self.assertEqual(i18n.t("app.conn.ok", "en", ms="x"), "OK · x")   # a string = formatted already

    def test_spike_alert_in_russian_and_french(self):
        from netwarden import alerts
        a = {"name": "PC", "total": 14.5e9, "rx_bytes": 2e9, "tx_bytes": 12.5e9, "hours": 24,
             "typical": 1.2e9, "ratio": 12}
        self.assertIn("14,5 ГБ", alerts.spike_text(a, "ru"))
        self.assertIn("14,5 Go", alerts.spike_text(a, "fr"))
        self.assertNotIn("GB", alerts.spike_text(a, "fr"))

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_node_regenerates_the_same_fixture(self):
        r = subprocess.run(["node", str(ROOT / "tests" / "js" / "intl_formats_test.js")],
                           capture_output=True, text=True, timeout=60, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class UnitLiteralCheckTests(unittest.TestCase):
    def test_shipped_locales_have_no_unit_literals(self):
        probs = [p for p in i18n.check() if p[2] == "unit_literal"]
        self.assertEqual(probs, [])

    def test_german_writes_hours_one_way(self):
        # item 7: the Inbox mixed "24 h" and "24 Std."
        de = {k: v for k, v in i18n._catalog()["de"].items() if isinstance(v, str)}
        self.assertEqual([k for k, v in de.items() if re.search(r"\{h\} h\b|\b24 h\b", v)], [])

    def test_the_checker_flags_hand_built_units(self):
        cat = json.loads(json.dumps(i18n._catalog()))
        cat["de"]["score.item.loss"] = "Paketverlust {pct} %"
        cat["fr"]["app.conn.ok"] = "OK · {ms} ms"
        cat["ru"]["why.threshold.spike"] = "при {size} ГБ+ за 24 ч и {ratio}× за {days} дней"
        cat["en"]["app.h.tile"] = "{n} GB used"
        cat["de"]["app.h.tile"] = "{n} GB benutzt"
        got = {(c, k) for c, k, p, _d in i18n.check(cat) if p == "unit_literal"}
        self.assertTrue({("de", "score.item.loss"), ("fr", "app.conn.ok"), ("ru", "why.threshold.spike"),
                         ("en", "app.h.tile")} <= got, got)

    def test_bitrates_and_spelled_out_units_are_flagged(self):
        # fix review 6: "{x} Mbps" in every cli.traffic.row went unnoticed
        cat = json.loads(json.dumps(i18n._catalog()))
        cat["en"]["cli.traffic.row"] = "now {rx}/{tx} Mbps"
        cat["ru"]["cli.traffic.row"] = "сейчас {rx}/{tx} Мбит/с"
        cat["fr"]["app.h.tile"] = "{n} octets"
        cat["de"]["app.h.tile"] = "{n} Prozent"
        cat["ru"]["app.h.tile"] = "{n} байт"
        cat["en"]["app.h.tile"] = "{n} bytes"
        got = {(c, k) for c, k, p, _d in i18n.check(cat) if p == "unit_literal"}
        self.assertTrue({("en", "cli.traffic.row"), ("ru", "cli.traffic.row"), ("fr", "app.h.tile"),
                         ("de", "app.h.tile"), ("ru", "app.h.tile"), ("en", "app.h.tile")} <= got, got)

    def test_bitrates_are_formatted_per_language(self):
        self.assertEqual(i18n.mbps(1234567, "en"), "1.23 Mb/s")
        self.assertEqual(i18n.mbps(1234567, "de"), "1,23 Mb/s")
        self.assertEqual(i18n.mbps(1234567, "fr"), "1,23 Mbit/s")
        self.assertEqual(i18n.mbps(1234567, "ru"), "1,23 Мбит/с")
        self.assertEqual(i18n.mbps(1234567, "ko"), "1.23Mb/s")
        self.assertEqual(i18n.mbps(2e6, "zh-Hant"), "2 Mb/秒")
        self.assertEqual(i18n.mbps(None, "en"), "0 Mb/s")

    def test_traffic_cli_row_in_russian(self):
        import contextlib
        import io
        from netwarden import store, traffic_ingest
        with mock.patch.object(store, "bandwidth_summary", return_value={
                "pc": {"rx_bytes": 2e9, "tx_bytes": 1e9, "rx_bps": 1234567, "tx_bps": 50000}}):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                traffic_ingest.print_report(None, 24, "ru")
        out = buf.getvalue()
        self.assertIn("1,23 Мбит/с / 0,05 Мбит/с", out)
        self.assertNotIn("1.23", out)

    def test_russian_device_texts_have_no_gendered_verb(self):
        # fix review 5: "Телефон · Mom | начало использовать" (Телефон is masculine)
        ru = i18n._catalog()["ru"]
        for key in ("ui.started_using", "digest.change_line"):
            self.assertNotIn("начал", ru[key], key)
        self.assertIn("замечено", ru["tl.first_seen"])

    def test_the_allowlist_has_reasons(self):
        for key, why in i18n.UNIT_LITERAL_OK.items():
            self.assertTrue(why.strip(), key)
            self.assertIn(key, i18n._catalog()["en"], key)


APP_JS = (ROOT / "netwarden" / "static" / "app.js").read_text(encoding="utf-8")


def _demo(path, now=None):
    from netwarden import demo, store
    demo.build(path, now=now or datetime.now(timezone.utc))
    return store.connect(path)


class ChipTests(unittest.TestCase):
    """Item 1: the static demo's chips come from the same logic as the live page."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10e_chips_")
        cls.db = _demo(Path(cls.tmp.name) / "demo.db")

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_app_js_adds_chips_in_chip_order(self):
        from netwarden import ai_intents
        body = APP_JS[APP_JS.index("function suggestions() {"):]
        body = body[:body.index("\n}\n")]
        keys = [k for k in re.findall(r"add\('(app\.ai\.q\.[\w.]+)'", body) if k != "app.ai.q.device"]
        self.assertEqual(tuple(keys), ai_intents.CHIP_ORDER)
        self.assertIn("GRADE_RANK[p.home.grade] >= 3", body)
        self.assertIn("const GRADE_RANK = { A: 1, B: 2, C: 3, D: 4, F: 5 }", APP_JS)
        self.assertEqual(ai_intents.GRADE_RANK, {"A": 1, "B": 2, "C": 3, "D": 4, "F": 5})

    def test_demo_chips_in_every_language(self):
        from netwarden import ai_intents, alerts, brain, dashboard, naming, privacy, web
        computed = alerts.compute(self.db, recent_hours=24)
        snap = brain.snapshot(self.db)
        for lang in i18n.CODES:
            with self.subTest(lang=lang):
                al = alerts.localize(computed, lang, naming.display_names(self.db, lang))
                inv = dashboard.inventory(self.db, web.localize_snapshot(snap, lang), lang)
                chips = ai_intents.data_chips(al, privacy.report(self.db, hours=24, lang=lang), inv, lang)
                keys = [k for k, _t in chips]
                self.assertIn("app.ai.q.exposure", keys)
                self.assertEqual(keys, [k for k in ai_intents.CHIP_ORDER if k in keys])
                for _k, text in chips:
                    self.assertTrue(text.strip())
                    self.assertNotRegex(text, r"\{\w+\}")


class StaticDemoChipAnswers(unittest.TestCase):
    """A quick static build: every chip the page shows has its saved answer."""

    @classmethod
    def setUpClass(cls):
        import sys
        if str(ROOT / "tests") not in sys.path:   # `python3 -m unittest tests.test_round10e` too
            sys.path.insert(0, str(ROOT / "tests"))
        from test_round9_w import B
        cls.B = B
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10e_site_")
        cls.out = Path(cls.tmp.name) / "site"
        B.build(cls.out, now=datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc), langs=["en", "ru"],
                quick=True, site_url="https://example.invalid/netwarden/", log=lambda *a: None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_chip_has_an_answer(self):
        from netwarden import ai_intents
        B = self.B
        for lang in ("en", "ru"):
            with self.subTest(lang=lang):
                idx = json.loads((self.out / B.chat_index(lang)).read_text(encoding="utf-8"))
                parts = json.loads((self.out / B.static_name(B.with_lang("/api/overview", lang)))
                                   .read_text(encoding="utf-8"))["parts"]
                chips = ai_intents.data_chips(parts.get("alerts"), parts.get("privacy"), parts.get("inv"), lang)
                self.assertTrue(chips)
                for _k, text in chips:
                    self.assertIn(text.strip(), idx["answers"], text)
                    self.assertIn(text.strip(), idx["suggested"], text)
                    self.assertTrue((self.out / B.chat_name("chat", text, lang)).exists(), text)


class DemoConsistency(unittest.TestCase):
    """Sweep C: one story across the demo's pages (wall clock: the snapshot reads it)."""

    @classmethod
    def setUpClass(cls):
        from netwarden import brain, dashboard, web
        cls.tmp = tempfile.TemporaryDirectory(prefix="nw_10e_demo_")
        cls.db = _demo(Path(cls.tmp.name) / "demo.db")
        cls.snap = brain.snapshot(cls.db)
        cls.inv = dashboard.inventory(cls.db, web.localize_snapshot(cls.snap, "en"), "en")
        cls.by_mac = {d["mac"]: d for d in cls.inv["devices"] if d.get("mac")}

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_the_netwarden_host_is_online(self):
        selfs = [d for d in self.inv["devices"] if d.get("is_self")]
        self.assertTrue(selfs)
        for d in selfs:
            self.assertTrue(d["online"], d.get("name"))

    def test_adguard_box_agrees_with_the_overview(self):
        from netwarden import store
        stats = json.loads(store.get_meta(self.db, "dns_server_stats"))
        self.assertEqual(stats["queries"], self.snap["total_queries"])
        self.assertEqual(stats["blocked"], sum(d["blocked"] for d in self.snap["devices"]))

    def test_adguard_stats_carry_the_story_time(self):
        from netwarden import demo, store
        now = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
        path = Path(self.tmp.name) / "pinned.db"
        demo.build(path, now=now)
        db = store.connect(path)
        try:
            self.assertEqual(json.loads(store.get_meta(db, "dns_server_stats"))["ts"], demo._utc(now))
        finally:
            db.close()

    def test_domain_drawer_matches_the_device_table(self):
        from netwarden import search
        checked = 0
        for d in self.snap["devices"]:
            rows = {t["domain"]: t["count"] for t in d.get("top_domains", [])}
            for dom in rows:
                det = search.domain_detail(self.db, dom, "en")
                mine = [x for x in det["devices"] if x["mac"] == d["mac"]]
                self.assertEqual(len(mine), 1, (d["mac"], dom))
                subs = [x for x in det["domains"] if x != dom]
                if any(s not in rows for s in subs if self._has(d["mac"], s)):
                    continue   # a subdomain outside the device's top list: not comparable
                want = rows[dom] + sum(rows.get(s, 0) for s in subs)
                self.assertEqual(mine[0]["queries_24h"], want, (d["mac"], dom))
                checked += 1
        self.assertGreater(checked, 10)

    def _has(self, mac, dom):
        from netwarden import search
        return self.db.execute("SELECT 1 FROM dns_events WHERE device_mac = ? AND domain = ? AND ts >= ?",
                               (mac, dom, search._since(1))).fetchone() is not None

    def test_last_seen_is_the_newest_evidence(self):
        for mac, d in self.by_mac.items():
            ident = self.db.execute("SELECT MAX(last_seen) FROM device_identity WHERE mac = ?", (mac,)).fetchone()[0]
            dns = self.db.execute("SELECT MAX(ts) FROM dns_events WHERE device_mac = ?", (mac,)).fetchone()[0]
            for ev in (ident, dns):
                if ev:
                    self.assertGreaterEqual(d["last_active"], ev, mac)

    def test_the_camera_has_a_week_of_history(self):
        from netwarden import demo
        cam = next(d for d in demo.DEVICES if d.get("steady"))
        days = self.db.execute("SELECT COUNT(DISTINCT substr(ts, 1, 10)) FROM dns_events WHERE device_mac = ?",
                               (cam["mac"],)).fetchone()[0]
        self.assertGreaterEqual(days, demo.STEADY_DAYS)

    def test_live_and_ai_lookups_agree_with_the_list(self):
        from netwarden import ai_tools, live
        live_on = live.snapshot(self.db)["devices"]
        res = ai_tools.t_list_devices(ai_tools.Ctx(self.db), {"status": "any", "limit": 500})
        tool_on = {d["mac"]: d["online"] for d in res["devices"]}
        for mac, d in self.by_mac.items():
            self.assertEqual(live_on.get(mac), d["online"], mac)
            self.assertEqual(tool_on.get(mac), d["online"], mac)

    def test_the_answers_stay_cacheable(self):
        from netwarden import dashboard, web
        again = dashboard.inventory(self.db, web.localize_snapshot(self.snap, "en"), "en")
        self.assertEqual([(d.get("mac"), d.get("last_active"), d["online"]) for d in again["devices"]],
                         [(d.get("mac"), d.get("last_active"), d["online"]) for d in self.inv["devices"]])


class ThisComputer(unittest.TestCase):
    """Item 4, the real app: is_self AND one of this machine's own interfaces."""

    def setUp(self):
        from netwarden import store
        self.db = store.connect(":memory:")
        old = "2020-01-01T00:00:00.000000Z"
        for mac, me in (("aa:bb:cc:00:00:01", 1), ("aa:bb:cc:00:00:02", 0)):
            self.db.execute("INSERT INTO devices (mac, ip, first_seen, last_seen, is_self) VALUES (?, ?, ?, ?, ?)",
                            (mac, "192.168.1.%d" % (10 + me), old, old, me))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_own_interface_is_online(self):
        from netwarden import dashboard
        with mock.patch.object(dashboard, "local_macs", return_value=frozenset({"aa:bb:cc:00:00:01"})):
            self.assertEqual(dashboard.this_computer(self.db), {"aa:bb:cc:00:00:01"})
            last = dashboard.last_active(self.db, "2019-01-01T00:00:00Z")
            self.assertEqual(dashboard.online_macs(self.db, last, "2026-01-01T00:00:00Z"), {"aa:bb:cc:00:00:01"})

    def test_a_copied_database_does_not_count(self):
        from netwarden import dashboard
        with mock.patch.object(dashboard, "local_macs", return_value=frozenset({"aa:bb:cc:99:99:99"})):
            self.assertEqual(dashboard.this_computer(self.db), set())
        with mock.patch.object(dashboard, "local_macs", return_value=frozenset({"aa:bb:cc:00:00:02"})):
            self.assertEqual(dashboard.this_computer(self.db), set())   # not is_self

    def test_announcements_move_last_seen(self):
        from netwarden import dashboard
        new = "2026-10-20T10:00:00.000000Z"
        self.db.execute("INSERT INTO device_identity (mac, source, name, first_seen, last_seen) "
                        "VALUES (?, 'mdns', 'x', ?, ?)", ("aa:bb:cc:00:00:02", new, new))
        self.assertEqual(dashboard.last_active(self.db, "2019-01-01T00:00:00Z")["aa:bb:cc:00:00:02"], new)

    def test_reverse_dns_answers_do_not_make_a_device_online(self):
        # fix review 2: the router answers PTR from its lease table for absent devices too
        from netwarden import dashboard, identify
        identify.record_rdns(self.db, {"192.168.1.10": "absent-box"}, {"192.168.1.10": "aa:bb:cc:00:00:02"},
                             seen="2026-10-20T10:00:00.000000Z")
        self.db.execute("INSERT INTO device_identity (mac, source, name, first_seen, last_seen) "
                        "VALUES (?, 'dns', 'y', ?, ?)", ("aa:bb:cc:00:00:02", "2026-10-20T10:00:00.000000Z",
                                                        "2026-10-20T10:00:00.000000Z"))
        last = dashboard.last_active(self.db, "2019-01-01T00:00:00Z")
        self.assertEqual(last["aa:bb:cc:00:00:02"], "2020-01-01T00:00:00.000000Z")
        with mock.patch.object(dashboard, "local_macs", return_value=frozenset()):
            self.assertEqual(dashboard.online_macs(self.db, last, "2026-10-20T09:50:00.000000Z"), set())


class DemoHostIsNotADnsBlindSpot(unittest.TestCase):
    """Fix review 1: the demo PC (always "seen just now") must never become a "quiet" DNS
    blind spot, whatever the hour of the pinned demo clock."""

    def test_no_quiet_host_at_any_hour(self):
        from netwarden import demo, store, visibility
        with tempfile.TemporaryDirectory(prefix="nw_10e_quiet_") as tmp:
            for i, hour in enumerate((22, 23)):     # 06:30 / 07:30 in Asia/Taipei, the old window
                now = datetime(2026, 10, 20, hour, 30, tzinfo=timezone.utc)
                path = Path(tmp) / ("d%d.db" % i)
                demo.build(path, now=now)
                db = store.connect(path)
                try:
                    selfs = {r[0] for r in db.execute("SELECT mac FROM devices WHERE is_self = 1")}
                    self.assertTrue(selfs)
                    quiet = {q["mac"] for q in visibility.quiet(db, now=now)}
                    self.assertFalse(quiet & selfs, hour)
                finally:
                    db.close()

    def test_quiet_skips_this_computer(self):
        from netwarden import store, visibility
        db = store.connect(":memory:")
        try:
            now = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
            db.execute("INSERT INTO devices (mac, ip, first_seen, last_seen, is_self) VALUES "
                       "('aa:bb:cc:00:00:01', '192.168.1.10', '2026-10-01T00:00:00Z', '2026-10-20T11:59:00Z', 1)")
            for h in range(12):   # hourly until 8 h ago, then silent
                ts = "2026-10-19T%02d:00:00.000000Z" % (16 + h) if h < 8 else "2026-10-20T%02d:00:00.000000Z" % (h - 8)
                db.execute("INSERT INTO dns_events (source, ts, client_ip, device_mac, domain, qtype, blocked, status) "
                           "VALUES ('adguard', ?, '192.168.1.10', 'aa:bb:cc:00:00:01', 'example.com', 'A', 0, 'NOERROR')", (ts,))
            db.commit()
            self.assertEqual(visibility.quiet(db, now=now), [])
            db.execute("UPDATE devices SET is_self = 0")
            self.assertEqual([q["mac"] for q in visibility.quiet(db, now=now)], ["aa:bb:cc:00:00:01"])
        finally:
            db.close()


class PersonChoicesFollowTheLanguage(unittest.TestCase):
    """Item 2: the drawer's Person select reads the choices loadChoices() refreshes."""

    def test_persons_reads_only_the_shared_list(self):
        m = re.search(r"function persons\(\) \{(.*?)\n\}", APP_JS, re.S) or \
            re.search(r"const persons = \(\) => ([^\n]*)", APP_JS)
        self.assertIsNotNone(m)
        self.assertIn("S.persons", m.group(1))
        self.assertNotIn("S.ppl", m.group(1))


if __name__ == "__main__":
    unittest.main()
