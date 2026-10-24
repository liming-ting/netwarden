"""
Tests for dns_ingest + store against a fake AdGuard Home API (stdlib unittest).

Covers what real dev traffic can't yet: several LAN clients, unknown IPs learned
from ARP, late-discovered devices, and DHCP IP reassignment.

    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from netwarden import discovery, dns_ingest, store

ROUTER = ("192.168.1.1", "50:c7:bf:3e:21:54")
PHONE = ("192.168.1.12", "3a:1f:7c:62:d5:12")
TV = ("192.168.1.40", "b8:27:eb:00:00:40")       # not in the DB yet, but in ARP
SELF_MAC = "00:1b:21:3c:4d:5e"


def item(time, client, domain, reason="NotFilteredNotFound", name=""):
    return {"time": time, "client": client, "client_info": {"name": name},
            "question": {"name": domain, "type": "A", "class": "IN"},
            "reason": reason, "status": "NOERROR", "elapsedMs": "1.5", "cached": False,
            "upstream": "192.168.1.1:53"}


class FakeAdGuard:
    """Serves /control/querylog newest-first with limit/older_than paging, like AdGuard."""

    def __init__(self):
        self.items = []  # oldest first; served reversed
        self.requests = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                fake.requests += 1
                if self.headers.get("Authorization") is None:
                    self.send_response(401); self.end_headers(); return
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                limit = int(q.get("limit", ["100"])[0])
                rows = list(reversed(fake.items))
                if "older_than" in q:
                    cut = dns_ingest.to_utc(q["older_than"][0])
                    rows = [r for r in rows if dns_ingest.to_utc(r["time"]) < cut]
                page = rows[:limit]
                body = json.dumps({"data": page, "oldest": page[-1]["time"] if page else ""}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAdGuard()
        self.src = dns_ingest.AdGuardHome(self.fake.url, "u", "p", page_size=2)  # force paging
        self.db = store.connect(":memory:")
        store.upsert_device(self.db, discovery.device_record(*ROUTER, {}, hostname="tplinkwifi.net"))
        store.upsert_device(self.db, discovery.device_record(*PHONE, {}, hostname=""))
        store.upsert_device(self.db, discovery.device_record("192.168.1.13", SELF_MAC, {}, is_self=True,
                                                             hostname="desk"))
        self.arp = {TV[0]: TV[1]}
        patches = [
            mock.patch.object(discovery, "read_arp", lambda: dict(self.arp)),
            mock.patch.object(discovery, "load_manuf", lambda: {"B8:27:EB": "Raspberry Pi Foundation"}),
            mock.patch.object(discovery, "hostname_for", lambda ip: ""),
            mock.patch.object(dns_ingest, "local_addresses", lambda: {"127.0.0.1", "::1", "192.168.1.13"}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.fake.close)

    def events(self):
        return [dict(r) for r in self.db.execute(
            "SELECT ts, client_ip, device_mac, domain, blocked FROM dns_events ORDER BY ts")]

    def test_to_utc_handles_nanoseconds_and_offsets(self):
        self.assertEqual(dns_ingest.to_utc("2026-10-21T00:05:01.123456789+08:00"),
                         "2026-10-20T16:05:01.123456Z")
        self.assertEqual(dns_ingest.to_utc("2026-10-20T16:05:01Z"), "2026-10-20T16:05:01.000000Z")

    def test_attribution_paging_and_incremental(self):
        self.fake.items = [
            item("2026-10-21T00:00:01.000000001+08:00", PHONE[0], "Instagram.com."),
            item("2026-10-21T00:00:02.5+08:00", ROUTER[0], "ntp.tplinkcloud.com"),
            item("2026-10-21T00:00:03+08:00", "127.0.0.1", "github.com"),
            item("2026-10-21T00:00:04+08:00", TV[0], "doubleclick.net", reason="FilteredBlackList",
                 name="living-room-tv"),
            item("2026-10-21T00:00:05+08:00", "10.9.9.9", "example.com"),   # not on our LAN
        ]
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual((st["fetched"], st["inserted"], st["unattributed"]), (5, 5, 1))
        self.assertGreaterEqual(self.fake.requests, 3)  # 5 items / page_size 2 -> paged
        self.assertEqual([d["mac"] for d in st["new_devices"]], [TV[1]])

        by_ip = {e["client_ip"]: e for e in self.events()}
        self.assertEqual(by_ip[PHONE[0]]["device_mac"], PHONE[1])
        self.assertEqual(by_ip[PHONE[0]]["domain"], "instagram.com")  # normalized
        self.assertEqual(by_ip[ROUTER[0]]["device_mac"], ROUTER[1])
        self.assertEqual(by_ip["127.0.0.1"]["device_mac"], SELF_MAC)
        self.assertEqual(by_ip[TV[0]]["device_mac"], TV[1])
        self.assertEqual(by_ip[TV[0]]["blocked"], 1)
        self.assertIsNone(by_ip["10.9.9.9"]["device_mac"])

        tv = self.db.execute("SELECT vendor, hostname FROM devices WHERE mac = ?", (TV[1],)).fetchone()
        self.assertEqual((tv["vendor"], tv["hostname"]), ("Raspberry Pi Foundation", "living-room-tv"))

        # Second run: nothing new is inserted, only the watermark row is re-seen.
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual(st["inserted"], 0)
        self.assertLessEqual(st["fetched"], 1)

        # New events arrive -> only those are inserted.
        self.fake.items.append(item("2026-10-21T00:00:06+08:00", PHONE[0], "api.whatsapp.net"))
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual(st["inserted"], 1)
        self.assertEqual(len(self.events()), 6)

    def test_late_discovered_device_is_relinked(self):
        recent = dns_ingest.datetime.now(dns_ingest.timezone.utc).isoformat()
        self.fake.items = [item(recent, "192.168.1.77", "roku.com")]
        self.assertEqual(dns_ingest.ingest(self.db, self.src)["unattributed"], 1)

        # Later the device answers ARP (e.g. found by a discovery sweep).
        self.arp["192.168.1.77"] = "d8:31:34:00:00:77"
        store.upsert_device(self.db, discovery.device_record("192.168.1.77", "d8:31:34:00:00:77", {}, hostname=""))
        st = dns_ingest.ingest(self.db, self.src)
        self.assertEqual(st["relinked"], 1)
        self.assertEqual(self.events()[0]["device_mac"], "d8:31:34:00:00:77")

    def test_ip_reassignment_keeps_history_with_old_device(self):
        self.fake.items = [item("2026-10-21T00:00:01+08:00", PHONE[0], "instagram.com")]
        dns_ingest.ingest(self.db, self.src)

        # DHCP hands the phone's IP to a new laptop.
        laptop = "a4:83:e7:00:00:12"
        store.upsert_device(self.db, discovery.device_record(PHONE[0], laptop, {}, hostname=""))
        self.assertIsNone(self.db.execute("SELECT ip FROM devices WHERE mac = ?", (PHONE[1],)).fetchone()["ip"])

        self.fake.items.append(item("2026-10-21T00:00:09+08:00", PHONE[0], "apple.com"))
        dns_ingest.ingest(self.db, self.src)
        macs = {e["domain"]: e["device_mac"] for e in self.events()}
        self.assertEqual(macs, {"instagram.com": PHONE[1], "apple.com": laptop})

    def test_adguard_block_reasons(self):
        reasons = {"FilteredBlackList": (1, "blocklist"), "FilteredSafeBrowsing": (1, "safebrowsing"),
                   "FilteredParental": (1, "parental"), "FilteredBlockedService": (1, "service"),
                   "FilteredInvalid": (1, "invalid"), "FilteredSafeSearch": (0, None),
                   "NotFilteredWhiteList": (0, None), "Rewrite": (0, None), "": (0, None)}
        for reason, want in reasons.items():
            ev = self.src.normalize(item("2026-10-21T00:00:01+08:00", PHONE[0], "x.com", reason=reason))
            self.assertEqual((ev["blocked"], ev["block_reason"]), want, reason)
        self.fake.items = [item("2026-10-21T00:00:01+08:00", PHONE[0], "ads.com", reason="FilteredParental")]
        dns_ingest.ingest(self.db, self.src)
        row = self.db.execute("SELECT blocked, block_reason, reason FROM dns_events").fetchone()
        self.assertEqual(tuple(row), (1, "parental", "FilteredParental"))

    def test_report_query_groups_by_device(self):
        self.fake.items = [item(f"2026-10-21T00:00:0{i}+08:00", ip, d) for i, (ip, d) in enumerate([
            (PHONE[0], "a.com"), (PHONE[0], "a.com"), (PHONE[0], "b.com"), ("192.168.1.13", "c.com"),
            ("127.0.0.1", "c.com")])]
        dns_ingest.ingest(self.db, self.src)
        rows = {r["device_mac"]: r for r in store.device_activity(self.db)}
        self.assertEqual(rows[PHONE[1]]["queries"], 3)
        self.assertEqual(rows[PHONE[1]]["top_domains"][0], {"domain": "a.com", "n": 2, "blocked": 0})
        self.assertEqual(rows[SELF_MAC]["queries"], 2)  # LAN IP + loopback = one machine


class MigrationTest(unittest.TestCase):
    OLD_DNS_EVENTS = """CREATE TABLE dns_events (
        id INTEGER PRIMARY KEY, source TEXT NOT NULL, ts TEXT NOT NULL, client_ip TEXT NOT NULL,
        client_name TEXT, device_mac TEXT, domain TEXT NOT NULL, qtype TEXT, status TEXT,
        reason TEXT, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
        upstream TEXT, elapsed_ms REAL, UNIQUE (source, ts, client_ip, domain, qtype))"""

    def test_old_db_gets_block_reason_backfilled(self):
        import sqlite3
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.db"
            old = sqlite3.connect(path)
            old.execute(self.OLD_DNS_EVENTS)
            rows = [("t1", "FilteredBlackList", 1), ("t2", "FilteredSafeBrowsing", 1),
                    ("t3", "NotFilteredNotFound", 0), ("t4", "SomethingNew", 1)]
            old.executemany("""INSERT INTO dns_events (source, ts, client_ip, domain, reason, blocked)
                               VALUES ('adguard', ?, '192.168.1.5', 'x.com', ?, ?)""", rows)
            old.commit()
            old.close()

            db = store.connect(path)
            got = {r["ts"]: r["block_reason"] for r in db.execute("SELECT ts, block_reason FROM dns_events")}
            self.assertEqual(got, {"t1": "blocklist", "t2": "safebrowsing", "t3": None, "t4": "other"})
            # new rows carry the column; re-opening is a no-op
            store.insert_events(db, [{"source": "pihole", "ts": "t5", "client_ip": "192.168.1.5",
                                      "domain": "y.com", "reason": "GRAVITY", "blocked": 1,
                                      "block_reason": "blocklist", "cached": 0}])
            db.close()
            db = store.connect(path)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM dns_events WHERE block_reason = 'blocklist'")
                             .fetchone()[0], 2)
            db.close()


if __name__ == "__main__":
    unittest.main()
