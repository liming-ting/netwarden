"""
Stage K: the database under bad conditions.

  * Databases written by earlier netwarden builds (fixtures made with the code of the
    pre-round2 / pre-round3 / pre-round4 backups, tests/fixtures/make_legacy_db.py)
    open, migrate to today's schema without losing the user's notes, and a second open
    changes nothing (idempotent).
  * A damaged, locked or unreadable file gives a clear localized message - in the CLI
    and from the API - never a traceback.
"""
import contextlib
import http.client
import io
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, backup, brain, i18n, inbox, store,
                       suggestions, web)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ERAS = ("pre_round2", "pre_round3", "pre_round4", "pre_round4_noauto")


def schema(db) -> dict:
    """{table: [(column, type, notnull, default)]} + index names: the shape to compare."""
    out = {}
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                              "AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        out[name] = sorted((r[1], r[2].upper(), r[3], r[4])
                           for r in db.execute(f"PRAGMA table_info({name})"))
    out["_indexes"] = sorted(r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"))
    return out


def dump(db) -> list:
    return list(db.iterdump())


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        fresh = store.connect(Path(self.tmp.name) / "fresh.db")
        self.fresh = schema(fresh)
        fresh.close()

    def legacy(self, era: str) -> Path:
        path = Path(self.tmp.name) / f"{era}.db"
        sql = (FIXTURES / f"legacy_{era.removesuffix('_noauto')}.sql").read_text(encoding="utf-8")
        if era.endswith("_noauto"):
            # the Stage F / H builds between round 3 and 4: bedtime_rules / outages without
            # AUTOINCREMENT (a deleted top id was handed out again)
            sql = "\n".join(ln for ln in sql.replace(" AUTOINCREMENT", "").splitlines()
                            if "sqlite_sequence" not in ln)
        raw = sqlite3.connect(path)
        raw.executescript(sql)
        raw.close()
        return path

    def test_every_era_migrates_and_keeps_the_users_notes(self):
        for era in ERAS:
            with self.subTest(era=era):
                path = self.legacy(era)
                old = sqlite3.connect(path)
                old_sql = {r[0]: r[1] or "" for r in old.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='table'")}
                old_tables = set(old_sql)
                old.close()
                # pre-AUTOINCREMENT tables: the counter must start above the ids acks
                # name (outage:7, bedtime:5:...); AUTOINCREMENT ones keep their own counter
                auto = "AUTOINCREMENT" in old_sql.get("outages", "").upper()
                db = store.connect(path)
                self.assertEqual(schema(db), self.fresh)           # every table / column / index
                lab = store.get_labels(db)["aa:bb:cc:00:00:01"]
                self.assertEqual((lab["label"], lab["note"]), ("客廳電視", "<b>note</b>"))
                acks = {(r["mac"], r["domain"]) for r in db.execute("SELECT mac, domain FROM acks")}
                self.assertIn(("aa:bb:cc:00:00:01", ""), acks)
                self.assertIn(("aa:bb:cc:00:00:02", "doubleclick.net"), acks)
                # legacy vendor placeholder cleared; blocked rows got a reason
                self.assertEqual(db.execute("SELECT vendor FROM devices WHERE mac = ?",
                                            ("aa:bb:cc:00:00:02",)).fetchone()[0], "")
                self.assertEqual(dict(db.execute("SELECT domain, block_reason FROM dns_events "
                                                 "WHERE blocked = 1").fetchall()),
                                 {"doubleclick.net": "blocklist", "weird.example": "other"})
                if "device_profiles" in old_tables:   # owners became people (Stage P)
                    names = {r[0] for r in db.execute("SELECT name FROM people")}
                    self.assertTrue({"媽媽", "小孩"} <= names, names)
                    self.assertEqual(store.get_profiles(db)["aa:bb:cc:00:00:01"]["room"], "客廳")
                if "bedtime_rules" in old_tables:    # ids never reused above what acks name
                    db.execute("INSERT INTO outages (start_ts, end_ts, cause, updated_at) "
                               "VALUES ('a', 'b', 'router', 'c')")
                    self.assertGreater(db.execute("SELECT MAX(id) FROM outages").fetchone()[0],
                                       3 if auto else 7)
                    rid = db.execute("INSERT INTO bedtime_rules (days, win_start, win_end, "
                                     "created_at, updated_at) VALUES ('0', '22:00', '07:00', 'a', 'a')"
                                     ).lastrowid
                    self.assertGreater(rid, 1 if auto else 5)
                    self.assertIn("AUTOINCREMENT", db.execute(
                        "SELECT sql FROM sqlite_master WHERE name = 'outages'").fetchone()[0].upper())
                    db.rollback()
                db.close()

    def test_migration_is_idempotent(self):
        for era in ERAS:
            with self.subTest(era=era):
                path = self.legacy(era)
                db = store.connect(path)
                first = dump(db)
                db.close()
                for _ in range(2):
                    db = store.connect(path)
                    self.assertEqual(dump(db), first)
                    db.close()

    def test_the_app_runs_on_a_migrated_database(self):
        for era in ERAS:
            with self.subTest(era=era):
                db = store.connect(self.legacy(era))
                try:
                    snap = brain.snapshot(db, hours=24 * 365 * 10)
                    self.assertTrue(snap["devices"])
                    alerts.compute(db, recent_hours=24 * 365)
                    inbox.report(db, "zh-Hant")
                    suggestions.detect(db, {})
                    doc = backup.export(db)
                    self.assertIn("aa:bb:cc:00:00:01", json.dumps(doc, ensure_ascii=False))
                finally:
                    db.close()

    def test_the_old_eras_own_demo_databases(self):
        """When the extracted backups are around (manual / CI-with-artifacts runs),
        their data/demo.db files migrate too. Skipped otherwise."""
        found = sorted(Path("/tmp/nwk").glob("pre-round*/netwarden/data/demo.db"))
        if not found:
            self.skipTest("no extracted backups under /tmp/nwk")
        for src in found:
            with self.subTest(src=str(src)):
                dst = Path(self.tmp.name) / (src.parent.parent.parent.name + ".db")
                a, b = sqlite3.connect(src), sqlite3.connect(dst)
                a.backup(b)
                a.close()
                b.close()
                db = store.connect(dst)
                self.assertEqual(schema(db), self.fresh)
                self.assertTrue(brain.snapshot(db, hours=24 * 3650)["devices"])
                db.close()


def _corrupt(path: Path, how: str = "garbage") -> Path:
    if how == "garbage":
        path.write_bytes(b"this is not a database at all\n" * 200)
    elif how == "header":   # a real SQLite header, then garbage pages
        good = path.with_suffix(".good")
        db = store.connect(good)
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.close()
        data = bytearray(good.read_bytes())
        for i in range(100, len(data)):
            data[i] = (i * 7) & 0xFF
        path.write_bytes(bytes(data))
    return path


class DamagedDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_connect_classifies_the_problem(self):
        for how in ("garbage", "header"):
            with self.subTest(how=how):
                with self.assertRaises(store.DBError) as cm:
                    store.connect(_corrupt(self.dir / f"{how}.db", how))
                self.assertEqual(cm.exception.kind, "corrupt")
                self.assertTrue(cm.exception.path.endswith(f"{how}.db"))
        with self.assertRaises(store.DBError) as cm:
            store.connect(self.dir)                     # a directory, not a file
        self.assertEqual(cm.exception.kind, "unreadable")
        self.assertIsNone(store.problem(sqlite3.IntegrityError("UNIQUE constraint failed")))
        self.assertEqual(store.problem(sqlite3.OperationalError("database is locked")), "locked")
        self.assertEqual(store.problem(sqlite3.DatabaseError("database disk image is malformed")),
                         "corrupt")

    def test_failure_answer(self):
        self.assertEqual(web.failure_answer(store.DBError("corrupt", "x")), (503, "db_corrupt"))
        self.assertEqual(web.failure_answer(store.DBError("unreadable", "x")), (503, "db_unreadable"))
        self.assertEqual(web.failure_answer(sqlite3.OperationalError("database is locked")),
                         (503, "busy"))
        self.assertEqual(web.failure_answer(KeyError("x")), (500, "internal"))

    def cli(self, fn, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fn(argv)
        return code, out.getvalue(), err.getvalue()

    def test_cli_says_what_is_wrong(self):
        bad = _corrupt(self.dir / "bad.db")
        for fn, argv in ((alerts.main, ["--db", str(bad)]),
                         (cli.main, ["status", "--db", str(bad), "--lang", "en"]),
                         (cli.main, ["alerts", "--db", str(bad)]),
                         (web.main, ["--db", str(bad), "--port", "0", "--lang", "ja"])):
            with self.subTest(argv=argv):
                code, _out, err = self.cli(fn, argv)
                self.assertEqual(code, 2)
                self.assertNotIn("Traceback", err)
                self.assertIn(str(bad), err)
        code, _o, err = self.cli(alerts.main, ["--db", str(bad)])   # the cron default: zh-Hant
        self.assertIn(i18n.t("cli.db.corrupt", "zh-Hant", path=bad), err)
        self.assertIn("restore", err)
        code, _o, err = self.cli(cli.main, ["status", "--db", str(bad), "--lang", "en"])
        self.assertIn(i18n.t("cli.db.corrupt", "en", path=bad), err)

    def test_api_answers_a_localized_503(self):
        good = self.dir / "good.db"
        store.connect(good).close()
        srv = web.make_server(good, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), web.close_server(srv)))
        port = srv.server_address[1]

        def req(method, path, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
            c.request(method, path, body, {"content-type": "application/json"} if body else {})
            r = c.getresponse()
            out = r.status, json.loads(r.read())
            c.close()
            return out

        bad = _corrupt(self.dir / "bad.db")
        with mock.patch.object(web.Handler, "db_path", str(bad)):
            for method, path, body in (("GET", "/api/overview?lang=zh-Hant", None),
                                       ("GET", "/api/device?mac=x&lang=zh-Hant", None),
                                       ("POST", "/api/label", '{"mac": "x", "lang": "zh-Hant"}')):
                status, obj = req(method, path, body)
                self.assertEqual((status, obj["error"]),
                                 (503, i18n.t("err.db_corrupt", "zh-Hant")), path)

    def test_a_locked_database_is_busy_not_broken(self):
        path = self.dir / "l.db"
        store.connect(path).close()
        holder = sqlite3.connect(path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")               # another program holds the write lock
        self.addCleanup(holder.close)
        srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (srv.shutdown(), web.close_server(srv)))
        with mock.patch.object(store, "BUSY_TIMEOUT_MS", 200):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=30)
            c.request("POST", "/api/label", json.dumps({"mac": "aa:bb:cc:dd:ee:ff", "label": "x",
                                                        "lang": "de"}),
                      {"content-type": "application/json"})
            r = c.getresponse()
            body = json.loads(r.read())
            c.close()
        self.assertEqual((r.status, body["error"]), (503, i18n.t("err.busy", "de")))


class WalTests(unittest.TestCase):
    """The soak found the WAL file only growing while readers always overlap: every
    connection caps it (journal_size_limit) and checkpoint() empties it."""

    def test_checkpoint_truncates_the_wal(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "w.db"
        db = store.connect(path)
        self.assertEqual(db.execute("PRAGMA journal_size_limit").fetchone()[0],
                         store.WAL_LIMIT_BYTES)
        reader = store.connect(path)
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM meta").fetchone()    # holds a snapshot
        with db:
            db.executemany("INSERT INTO meta (key, value) VALUES (?, ?)",
                           [(f"k{i}", "x" * 500) for i in range(2000)])
        wal = Path(str(path) + "-wal")
        self.assertGreater(wal.stat().st_size, 0)
        with mock.patch.object(store, "BUSY_TIMEOUT_MS", 100):
            db.execute("PRAGMA busy_timeout = 100")
            self.assertFalse(store.checkpoint(db))   # a reader still needs the old pages
        reader.rollback()
        reader.close()
        self.assertTrue(store.checkpoint(db))
        self.assertEqual(wal.stat().st_size, 0)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM meta WHERE key LIKE 'k%'").fetchone()[0],
                         2000)
        db.close()

    def test_the_notify_loop_checkpoints_hourly(self):
        from netwarden import runner
        job = runner.NotifyJob({})
        calls = []
        with mock.patch("netwarden.notify.run", return_value={}), \
                mock.patch.object(store, "checkpoint", side_effect=lambda db: calls.append(db)):
            job("db")
            self.assertEqual(calls, [])
            job.checkpoint_at -= runner.NotifyJob.CHECKPOINT_EVERY
            job("db")
        self.assertEqual(calls, ["db"])


if __name__ == "__main__":
    unittest.main()
