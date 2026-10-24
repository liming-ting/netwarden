"""
Stage K: everything netwarden reads from the network is hostile input. These tests feed
malformed, truncated, oversized and hostile data to every parser - mDNS / DNS wire,
SSDP, NetBIOS, UPnP descriptions and SOAP replies, the AdGuard / Pi-hole / ntopng API
answers - and check that each one either returns a sane, typed result or raises the one
documented error: no crash, no hang, bounded memory. XML with a DTD or entities is
refused before any parsing. Deterministic (tests/fuzzkit.py seeds); a heavier run:
NETWARDEN_FUZZ=heavy. Nothing here touches a real network host.
"""
import http.server
import io
import json
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree

import fuzzkit
import test_stage_n as n
from netwarden import dns_ingest, health, identify, store, traffic_ingest, upnp


def _valid_ssdp() -> bytes:
    return (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n"
            b"LOCATION: http://192.168.1.1:1900/d.xml\r\nSERVER: Linux UPnP/1.0\r\n"
            b"ST: upnp:rootdevice\r\nUSN: uuid:1::upnp:rootdevice\r\n\r\n")


def _nbstat_reply(name=b"DESKTOP-1", group=b"WORKGROUP") -> bytes:
    def entry(label, suffix, flags):
        return label.ljust(15, b" ") + bytes([suffix]) + struct.pack("!H", flags)
    rdata = bytes([2]) + entry(name, 0, 0x0400) + entry(group, 0, 0x8400) + b"\x00\x11\x22\x33\x44\x55"
    nm = b"\x20" + b"CK" + b"A" * 30 + b"\0"
    return (struct.pack("!HHHHHH", 1, 0x8400, 0, 1, 0, 0) + nm
            + struct.pack("!HHIH", identify.NB_STAT, 1, 0, len(rdata)) + rdata)


class DnsWireFuzz(unittest.TestCase):
    def test_parse_message_only_ever_raises_dns_error(self):
        r = fuzzkit.rng("mdns")
        sample = n.cast_answer()
        for _ in range(fuzzkit.cases(600)):
            data = fuzzkit.blob(r, sample)
            try:
                recs = identify.parse_message(data)
            except identify.DnsError:
                continue
            self.assertIsInstance(recs, list)
            self.assertLessEqual(len(recs), 512)
            info = identify.interpret_mdns(recs)      # pure function: must never raise
            if info is not None:
                for k in ("name", "manufacturer", "model"):
                    self.assertIsInstance(info[k], str)
                    self.assertLessEqual(len(info[k]), store.MAX_IDENTITY_TEXT)
                    self.assertTrue(all(c.isprintable() for c in info[k]))

    def test_hostile_records_are_bounded(self):
        # 65535 claimed answers in a tiny packet, a name built from 200 pointer hops,
        # escapes that decode to control characters
        head = struct.pack("!HHHHHH", 0, 0x8400, 0, 0xFFFF, 0xFFFF, 0xFFFF)
        with self.assertRaises(identify.DnsError):
            identify.parse_message(head + n.rr(n.dname("a.local"), identify.T_A, b"\1\2\3\4"))
        hops = b"".join(struct.pack("!H", 0xC000 | (12 + 2 * (i + 1))) for i in range(200)) + b"\0"
        with self.assertRaises(identify.DnsError):
            identify.parse_message(head[:6] + struct.pack("!HHH", 1, 0, 0) + hops)
        bad = n.dname(r"evil\000\010x._ipp._tcp.local")
        recs = identify.parse_message(n.message(n.rr(n.dname("_ipp._tcp.local"), identify.T_PTR, bad)))
        info = identify.interpret_mdns(recs)
        self.assertTrue(all(c.isprintable() for c in info["name"]))

    def test_txt_never_raises(self):
        r = fuzzkit.rng("txt")
        for _ in range(fuzzkit.cases(400)):
            out = identify.parse_txt(fuzzkit.blob(r, n.txt(fn="TV", md="Chromecast")))
            self.assertLessEqual(len(out), 64)

    def test_mdns_records_per_host_are_capped(self):
        many = n.message(*[n.rr(n.dname(f"h{i}.local"), identify.T_A, b"\x0a\1\1\2") for i in range(200)])
        socks = [mock.Mock()]
        packets = [many] * 20
        def fake_listen(_socks, _seconds, on_packet):
            for p in packets:
                on_packet("192.168.1.2", p)
            return len(packets)
        with mock.patch.object(identify, "_mdns_sockets", return_value=socks), \
                mock.patch.object(identify, "_listen", fake_listen), \
                mock.patch.object(identify, "interpret_mdns", side_effect=lambda recs: {"n": len(recs)}):
            out = identify.mdns_browse(dest=None)
        self.assertEqual(out["192.168.1.2"]["n"], identify.MAX_RECORDS_PER_IP)


class SsdpNetbiosFuzz(unittest.TestCase):
    def test_parse_ssdp_never_raises(self):
        r = fuzzkit.rng("ssdp")
        for _ in range(fuzzkit.cases(600)):
            h = identify.parse_ssdp(fuzzkit.blob(r, _valid_ssdp()))
            if h is not None:
                self.assertLessEqual(len(h), 40)
                self.assertTrue(all(len(v) <= 512 for v in h.values()))
        huge = b"HTTP/1.1 200 OK\r\n" + b"X: " + b"a" * 100000 + b"\r\n"
        self.assertLessEqual(len(identify.parse_ssdp(huge).get("x", "")), 512)

    def test_location_ok_refuses_tricks(self):
        for loc in ("http://192.168.1.1@evil.example/d.xml", "http://user:pw@192.168.1.1/d.xml",
                    "https://192.168.1.1/d.xml", "file:///etc/passwd", "http://192.168.1.1:99999/",
                    "http://[::1]/", "http://192.168.1.1:0/", "gopher://192.168.1.1/", "http:///x",
                    "http://192.168.1.2/d.xml", "\x00http://192.168.1.1/", "http://8.8.8.8/"):
            self.assertFalse(identify.location_ok(loc, "192.168.1.1"), loc)
        self.assertFalse(identify.location_ok("http://8.8.8.8/d.xml", "8.8.8.8"))
        self.assertTrue(identify.location_ok("http://192.168.1.1:1900/d.xml", "192.168.1.1"))

    def test_parse_nbstat_never_raises(self):
        self.assertEqual(identify.parse_nbstat(_nbstat_reply())["name"], "DESKTOP-1")
        r = fuzzkit.rng("nbstat")
        for _ in range(fuzzkit.cases(600)):
            info = identify.parse_nbstat(fuzzkit.blob(r, _nbstat_reply()))
            if info is not None:
                self.assertTrue(info["name"])
                self.assertTrue(all(c.isprintable() for c in info["name"]))
                self.assertIn(len(info["mac"]), (0, 17))


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<root><device><friendlyName>&lol3;</friendlyName></device></root>"""
XXE = b"""<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<root><device><friendlyName>&x;</friendlyName></device></root>"""


class XmlFuzz(unittest.TestCase):
    def test_dtds_and_entities_are_refused(self):
        for doc in (BILLION_LAUGHS, XXE, BILLION_LAUGHS.replace(b"DOCTYPE", b"doctype"),
                    b"\xef\xbb\xbf" + XXE,
                    b'<?xml version="1.0"?><!ENTITY x "y"><root/>',
                    XXE.decode().encode("utf-16"), XXE.decode().encode("utf-32"),
                    b'<?xml version="1.0" encoding="UTF-7"?><root/>',
                    b'<?xml version="1.0" encoding="ebcdic-cp-us"?><root/>',
                    b"   not xml", b""):
            with self.assertRaises(ValueError, msg=doc[:40]):
                identify.safe_xml(doc)
            with self.assertRaises((ValueError, ElementTree.ParseError)):
                identify.parse_description(doc, "http://192.168.1.1/d.xml")

    def test_parse_description_only_raises_value_or_parse_errors(self):
        r = fuzzkit.rng("upnp-desc")
        for _ in range(fuzzkit.cases(500)):
            data = fuzzkit.blob(r, r.choice((n.IGD_XML, n.TV_XML)))
            try:
                info = identify.parse_description(data, "http://192.168.1.1:1900/d.xml")
            except (ValueError, ElementTree.ParseError):
                continue
            self.assertLessEqual(len(info["name"]), store.MAX_IDENTITY_TEXT)
            for w in info["wan"]:
                self.assertIsInstance(w["control_url"], str)

    def test_deep_and_wide_xml(self):
        deep = b"<root>" + b"<a>" * 20000 + b"</a>" * 20000 + b"</root>"
        with self.assertRaises(ValueError):          # no <device>: refused, no recursion crash
            identify.parse_description(deep, "http://192.168.1.1/d.xml")
        wide = b"<root><device><friendlyName>" + b"x" * 60000 + b"</friendlyName></device></root>"
        self.assertEqual(len(identify.parse_description(wide, "http://192.168.1.1/")["name"]),
                         store.MAX_IDENTITY_TEXT)


class SoapFuzz(unittest.TestCase):
    URL, ST = "http://192.168.1.1:5000/ctl", "urn:schemas-upnp-org:service:WANIPConnection:1"
    OK = (b'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
          b'<s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="x">'
          b"<NewRemoteHost></NewRemoteHost><NewExternalPort>8080</NewExternalPort>"
          b"<NewProtocol>TCP</NewProtocol><NewInternalPort>80</NewInternalPort>"
          b"<NewInternalClient>192.168.1.20</NewInternalClient><NewEnabled>1</NewEnabled>"
          b"<NewPortMappingDescription>cam</NewPortMappingDescription>"
          b"<NewLeaseDuration>0</NewLeaseDuration>"
          b"</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>")

    def test_soap_replies(self):
        r = fuzzkit.rng("soap")
        for _ in range(fuzzkit.cases(400)):
            body, status = fuzzkit.blob(r, self.OK), r.choice((200, 200, 500, 404))
            fetch = lambda *a, **k: (status, body)   # noqa: E731
            try:
                out = upnp.soap_call(self.URL, self.ST, "GetGenericPortMappingEntry",
                                     {"NewPortMappingIndex": 0}, "192.168.1.1", fetch)
            except upnp.SoapFault:
                continue
            m = upnp._mapping(out)
            if m:
                self.assertTrue(0 < m["external_port"] < 65536 and 0 < m["internal_port"] < 65536)
                self.assertTrue(m["lease"] is None or 0 <= m["lease"] <= upnp.MAX_LEASE)

    def test_mapping_values(self):
        r = fuzzkit.rng("mapping")
        keys = ("NewProtocol", "NewExternalPort", "NewInternalPort", "NewInternalClient",
                "NewEnabled", "NewLeaseDuration", "NewRemoteHost", "NewPortMappingDescription")
        good = {"NewProtocol": "TCP", "NewExternalPort": "8080", "NewInternalPort": "80",
                "NewInternalClient": "192.168.1.20", "NewEnabled": "1", "NewLeaseDuration": "0"}
        for _ in range(fuzzkit.cases(500)):
            m = {k: (fuzzkit.string(r) if r.random() < 0.5 else good.get(k, "")) for k in keys}
            out = upnp._mapping(m)
            if out:
                self.assertIn(out["protocol"], ("TCP", "UDP"))
                self.assertTrue(out["lease"] is None or 0 <= out["lease"] <= upnp.MAX_LEASE)
        self.assertIsNone(upnp._mapping({**good, "NewLeaseDuration": "9" * 30})["lease"])

    def test_hostile_mappings_are_stored(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = store.connect(Path(tmp.name) / "u.db")
        self.addCleanup(db.close)
        body = self.OK.replace(b"<NewLeaseDuration>0", b"<NewLeaseDuration>" + b"9" * 25) \
            .replace(b"cam", "&lt;script&gt;\u202e\u2028x".encode())
        calls = []
        def fetch(url, **k):
            calls.append(1)
            return (200, body) if len(calls) < 4 else (500, b"<x/>")
        desc = {"192.168.1.1": {"name": "R", "wan": [{"service_type": self.ST, "control_url": self.URL}]}}
        res = upnp.check_recorded(db, desc, {}, gateway_ip="192.168.1.1", fetch=fetch)
        self.assertTrue(res["available"])
        row = db.execute("SELECT lease, description FROM upnp_mappings").fetchone()
        self.assertIsNone(row["lease"])
        self.assertTrue(all(c.isprintable() for c in row["description"]))


class _Resp(io.BytesIO):
    """A urllib response stand-in (read1 like http.client's)."""


class ReadJsonTests(unittest.TestCase):
    def test_limits(self):
        self.assertEqual(health.read_json(_Resp(b'{"a": 1}')), {"a": 1})
        self.assertEqual(health.read_json(_Resp(b"  ")), {})
        with self.assertRaisesRegex(ValueError, "too large"):
            health.read_json(_Resp(b"[" + b"1," * 2000 + b"1]"), limit=1000)
        with self.assertRaisesRegex(ValueError, "too deeply"):
            health.read_json(_Resp(fuzzkit.deep(200000).encode()))
        with self.assertRaises(ValueError):
            health.read_json(_Resp(b"<html>login</html>"))
        with self.assertRaises(ValueError):
            health.read_json(_Resp(b"\xff\xfe{}"))

        class Slow:
            def read1(self, n):
                time.sleep(0.02)
                return b" "
        with self.assertRaisesRegex(ValueError, "too slow"):
            health.read_json(Slow(), seconds=0.1)


class _Fake(http.server.BaseHTTPRequestHandler):
    body = b"{}"

    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(self.body)
        except OSError:
            pass

    def log_message(self, *a):
        pass


class SourceHttpTests(unittest.TestCase):
    """The real adapters against a fake server on 127.0.0.1 answering hostile bodies."""
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def serve(self, body: bytes):
        _Fake.body = body

    def test_oversized_and_junk_bodies_fail_cleanly(self):
        ag = dns_ingest.AdGuardHome(self.url, timeout=5)
        nt = traffic_ingest.NtopngSource(self.url, timeout=5)
        for body in (b"[]", b"null", b"42", b'"x"', fuzzkit.deep(100000).encode(), b"<html>"):
            self.serve(body)
            with self.assertRaises((ValueError, OSError)):
                list(ag.events(None))
            with self.assertRaises(OSError):
                nt.sample()
        self.serve(b"[" + b"0," * (9 * 1024 * 1024) + b"0]")   # ~18 MB > MAX_RESPONSE_BYTES
        with self.assertRaisesRegex(OSError, "too large"):   # fix stage: one OSError per source
            list(ag.events(None))

    def test_paging_is_bounded(self):
        # a server that always returns a full page with a new "oldest" never ends by itself
        self.serve(json.dumps({"data": [{"time": "2026-10-22T10:00:00Z", "client": "192.168.1.5",
                                         "question": {"name": "a.example", "type": "A"}}],
                               "oldest": "2026-10-22T09:00:00Z"}).encode())
        ag = dns_ingest.AdGuardHome(self.url, page_size=1, timeout=5)
        calls = []
        real = ag._get
        def counting(path, params):
            calls.append(1)
            body = real(path, params)
            body["oldest"] = f"2026-10-22T09:00:{len(calls) % 60:02d}.{len(calls):06d}Z"
            return body
        ag._get = counting
        with mock.patch.object(dns_ingest, "MAX_PAGES", 25):
            evs = list(ag.events(None))
        self.assertEqual(len(calls), 25)
        self.assertEqual(len(evs), 25)


def _adguard_item(r):
    good = {"time": "2026-10-22T10:00:00.123456789+08:00", "client": "192.168.1.5",
            "client_info": {"name": "kid-tablet"}, "question": {"name": "Example.COM.", "type": "A"},
            "status": "NOERROR", "reason": "FilteredBlackList", "cached": False,
            "upstream": "1.1.1.1:53", "elapsedMs": "1.5"}
    return fuzzkit.mutate(r, good) if r.random() < 0.8 else fuzzkit.value(r)


def _pihole_item(r):
    good = {"time": 1729591200.25, "type": "A", "domain": "example.com", "status": "GRAVITY",
            "client": {"ip": "192.168.1.6", "name": "tv"}, "reply": {"type": "IP", "time": 0.002},
            "upstream": "8.8.8.8#53"}
    return fuzzkit.mutate(r, good) if r.random() < 0.8 else fuzzkit.value(r)


class DnsSourceFuzz(unittest.TestCase):
    def check_event(self, ev):
        self.assertTrue(set(store.EVENT_FIELDS) <= set(ev))
        self.assertRegex(ev["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
        self.assertIsInstance(ev["client_ip"], str)
        self.assertIsInstance(ev["domain"], str)
        for k in ("client_name", "qtype", "status", "upstream"):
            self.assertTrue(ev[k] is None or isinstance(ev[k], str), (k, ev[k]))
        self.assertTrue(ev["elapsed_ms"] is None or isinstance(ev["elapsed_ms"], float))
        self.assertIn(ev["blocked"], (0, 1))

    def run_source(self, src, make, rows_key):
        r = fuzzkit.rng(src.source)
        items = [make(r) for _ in range(fuzzkit.cases(500))]
        page = {rows_key: items}
        src._get = lambda *a, **k: page   # noqa: E731
        src.page_size = len(items) + 1
        evs = list(src.events(None))
        for ev in evs:
            self.check_event(ev)
        self.assertGreater(len(evs), 0)
        self.assertGreater(src.skipped, 0)
        return evs

    def test_adguard_items(self):
        self.run_source(dns_ingest.AdGuardHome("http://127.0.0.1:9"), _adguard_item, "data")

    def test_pihole_items(self):
        src = dns_ingest.PiHole("http://127.0.0.1:9")
        evs = self.run_source(src, _pihole_item, "queries")
        self.assertTrue(any(e["blocked"] for e in evs))

    def test_fuzzed_events_store_cleanly(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = store.connect(Path(tmp.name) / "d.db")
        self.addCleanup(db.close)
        r = fuzzkit.rng("adguard-store")
        src = dns_ingest.AdGuardHome("http://127.0.0.1:9")
        items = [_adguard_item(r) for _ in range(fuzzkit.cases(300))]
        src._get = lambda *a, **k: {"data": items}   # noqa: E731
        with mock.patch.object(dns_ingest, "local_addresses", return_value=set()), \
                mock.patch.object(dns_ingest.discovery, "read_arp", return_value={}), \
                mock.patch.object(dns_ingest.Attributor, "_register_self", return_value=None), \
                mock.patch.object(dns_ingest.store, "self_mac", return_value=None):
            st = dns_ingest.ingest_recorded(db, src)
        self.assertGreater(st["inserted"], 0)
        self.assertEqual(db.execute("SELECT count(*) FROM dns_events").fetchone()[0], st["inserted"])


class NtopngFuzz(unittest.TestCase):
    def test_hosts(self):
        r = fuzzkit.rng("ntopng")
        good = {"ip": "192.168.1.7@0", "is_localhost": True, "vlan": 0,
                "bytes": {"recvd": 1000, "sent": "200"}, "mac": "AA:BB:CC:00:11:22"}
        hosts = [fuzzkit.mutate(r, good) if r.random() < 0.8 else fuzzkit.value(r)
                 for _ in range(fuzzkit.cases(500))]
        src = traffic_ingest.NtopngSource("http://127.0.0.1:9", page_size=10 ** 6)
        src._get = lambda params: {"rc": 0, "rsp": {"data": hosts, "totalRows": "junk"}}  # noqa: E731
        out = src.sample()
        self.assertGreater(len(out), 0)
        for s in out:
            self.assertTrue(0 <= s["rx_bytes"] <= traffic_ingest.MAX_COUNTER)
            self.assertTrue(0 <= s["tx_bytes"] <= traffic_ingest.MAX_COUNTER)
            self.assertIsInstance(s["ip"], str)
        for bad in ([1, 2], "x", {"rsp": "?"}, {"rc": 0, "rsp": {"data": "nope"}}):
            src._get = lambda params, b=bad: b if isinstance(b, dict) else {"rsp": b}  # noqa: E731
            self.assertEqual(src.sample(), [])


if __name__ == "__main__":
    unittest.main()
