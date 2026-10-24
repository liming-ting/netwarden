"""
Stage N: device identification (mDNS / SSDP / DHCP / DNS names), UPnP exposure, routine
traffic and the extended domain catalog.

- DNS wire format: compression, pointer loops, truncation; interpret_mdns per service
- SSDP: header parsing, which LOCATIONs may be fetched, DTD refusal, descriptions
- a fake mDNS responder, SSDP responder and UPnP gateway on 127.0.0.1 (ephemeral ports;
  nothing ever reaches the real network): browse, describe, read every mapping
- the SOAP allowlist (refused before anything is sent) + a source scan of upnp.py
- store: identity merge / names / prune; UPnP snapshots, "new", risky, unavailable
- alerts / digest / acks, timeline, brain snapshot, redaction, devicetype vote, health
- routine traffic + catalog additions
- the demo story, /api/upnp and /api/device over HTTP, `netwarden identify` on the demo
"""
import contextlib
import http.client
import io
import json
import re
import socket
import struct
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from netwarden import (__main__ as cli, alerts, brain, dashboard, demo, devicetype, health,
                       identify, privacy, redact, routine, services, store, timeline, upnp, web)

ISO = "%Y-%m-%dT%H:%M:%S.%fZ"
CAM = "a0:43:b0:9f:21:5e"
PS5 = "70:9e:29:55:3b:81"
TV = "8c:79:f5:0b:cd:12"
PRINTER = "3c:2a:f4:88:19:d0"
DAD_PHONE = "a6:71:0c:9d:4e:f2"
_private = identify.private_ip


def loopback_ok(ip):
    """Tests widen "private" to 127.0.0.1 so fake devices on loopback count."""
    return ip.startswith("127.") or _private(ip)


def iso(dt):
    return dt.strftime(ISO)


# --- DNS wire helpers -----------------------------------------------------------------

def dname(n):
    return b"".join(bytes([len(p.encode())]) + p.encode() for p in n.split(".")) + b"\0"


def rr(name_bytes, rtype, rdata):
    return name_bytes + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def txt(**kv):
    return b"".join(bytes([len(s)]) + s for s in (f"{k}={v}".encode() for k, v in kv.items()))


def message(*records):
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def cast_answer():
    """A Chromecast answer using name compression: the PTR target points back at the
    service name, the TXT / SRV owner names point at the instance name."""
    head = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)
    svc = dname("_googlecast._tcp.local")                     # at offset 12
    inst_rdata = bytes([len("客廳電視".encode())]) + "客廳電視".encode() + b"\xc0\x0c"
    ptr = svc + struct.pack("!HHIH", identify.T_PTR, 1, 120, len(inst_rdata)) + inst_rdata
    inst_off = 12 + len(svc) + 10                             # the instance name
    ptr_txt = struct.pack("!H", 0xC000 | inst_off)
    t = rr(ptr_txt, identify.T_TXT, txt(fn="Living<b>Room\nTV", md="Chromecast"))
    srv = rr(ptr_txt, identify.T_SRV, struct.pack("!HHH", 0, 0, 8009) + dname("cc-1234.local"))
    return head + ptr + t + srv


class DnsWireTests(unittest.TestCase):
    def test_query_asks_every_service_type_with_the_qu_bit(self):
        q = identify.build_query(["_ipp._tcp.local", "_hap._tcp.local"])
        self.assertEqual(struct.unpack("!H", q[4:6])[0], 2)
        self.assertTrue(q.endswith(struct.pack("!HH", identify.T_PTR, 0x8001)))

    def test_compressed_answer(self):
        recs = identify.parse_message(cast_answer())
        ptr = next(r for r in recs if r["type"] == identify.T_PTR)
        self.assertEqual(ptr["data"], "客廳電視._googlecast._tcp.local")
        t = next(r for r in recs if r["type"] == identify.T_TXT)
        self.assertEqual(t["data"]["md"], "Chromecast")
        s = next(r for r in recs if r["type"] == identify.T_SRV)
        self.assertEqual(s["data"], {"port": 8009, "target": "cc-1234.local"})

    def test_pointer_loop_and_truncation_raise(self):
        head = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
        loop = head + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + b"\0\0\0\0"
        with self.assertRaises(identify.DnsError):
            identify.parse_message(loop)
        with self.assertRaises(identify.DnsError):
            identify.parse_message(cast_answer()[:40])
        with self.assertRaises(identify.DnsError):
            identify.parse_message(b"\0\0")

    def test_txt_is_bounded_and_never_raises(self):
        self.assertEqual(identify.parse_txt(b"\x03a=b\x01x\x09cut"), {"a": "b", "x": "", "cut": ""})
        self.assertLessEqual(len(identify.parse_txt(b"\x03k=v" * 500)), 64)

    def test_interpret_chromecast(self):
        info = identify.interpret_mdns(identify.parse_message(cast_answer()))
        self.assertEqual(info["name"], "Living<b>Room TV")      # one line; escaping is the UI's job
        self.assertEqual((info["manufacturer"], info["model"], info["kind"]),
                         ("Google", "Chromecast", "streaming"))
        self.assertEqual(info["services"], ["_googlecast._tcp"])

    def test_interpret_printer_and_iphone(self):
        n = dname("HP OfficeJet Pro 9010 [A1B2C3]._ipp._tcp.local")
        recs = identify.parse_message(message(
            rr(dname("_ipp._tcp.local"), identify.T_PTR, n),
            rr(n, identify.T_TXT, txt(ty="HP OfficeJet Pro 9010 series", usb_MFG="HP"))))
        info = identify.interpret_mdns(recs)
        self.assertEqual((info["name"], info["manufacturer"], info["kind"]),
                         ("HP OfficeJet Pro 9010", "HP", "printer"))
        n = dname("Dad's iPhone._companion-link._tcp.local")
        recs = identify.parse_message(message(
            rr(dname("_companion-link._tcp.local"), identify.T_PTR, n),
            rr(n, identify.T_TXT, txt(model="iPhone15,2"))))
        info = identify.interpret_mdns(recs)
        self.assertEqual((info["manufacturer"], info["kind"]), ("Apple", "phone"))
        self.assertIsNone(identify.interpret_mdns([]))

    def test_split_instance_unescapes(self):
        self.assertEqual(identify.split_instance(r"Office\032Printer._ipp._tcp.local."),
                         ("Office Printer", "_ipp._tcp"))
        self.assertIsNone(identify.split_instance("foo._unknown._tcp.local"))


# --- SSDP / descriptions ---------------------------------------------------------------

IGD_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Home Router</friendlyName><manufacturer>TP-Link</manufacturer>
  <modelName>Archer C6</modelName>
  <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <controlURL>/ctl</controlURL></service></serviceList>
   </device></deviceList></device></deviceList>
 </device></root>"""
TV_XML = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
 <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
 <friendlyName>[TV] Samsung Q80 Series (55)</friendlyName>
 <manufacturer>Samsung Electronics</manufacturer><modelName>QA55Q80BAWXZW</modelName>
</device></root>"""


class SsdpTests(unittest.TestCase):
    def test_parse_ssdp(self):
        h = identify.parse_ssdp(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:1900/d.xml\r\n"
                                b"ST: upnp:rootdevice\r\n\r\n")
        self.assertEqual(h["location"], "http://192.168.1.1:1900/d.xml")
        self.assertIsNone(identify.parse_ssdp(b"GET / HTTP/1.1\r\n\r\n"))

    def test_location_must_be_http_on_the_responders_own_private_ip(self):
        ok = identify.location_ok
        self.assertTrue(ok("http://192.168.1.1:1900/d.xml", "192.168.1.1"))
        self.assertFalse(ok("https://192.168.1.1/d.xml", "192.168.1.1"))
        self.assertFalse(ok("http://192.168.1.9/d.xml", "192.168.1.1"))          # another host
        self.assertFalse(ok("http://8.8.8.8/d.xml", "8.8.8.8"))            # public
        self.assertFalse(ok("http://127.0.0.1/d.xml", "127.0.0.1"))        # loopback
        self.assertFalse(ok("http://u:p@192.168.1.1/d.xml", "192.168.1.1"))      # userinfo
        self.assertFalse(ok("http://192.168.1.1:99999/d.xml", "192.168.1.1"))
        self.assertFalse(ok("file:///etc/passwd", "192.168.1.1"))

    def test_dtd_and_entities_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><root>&a;</root>'
        with self.assertRaises(ValueError):
            identify.safe_xml(bomb)
        with self.assertRaises(ValueError):
            identify.parse_description(b"<root><nodevice/></root>", "http://192.168.1.1/")

    def test_descriptions(self):
        gw = identify.parse_description(IGD_XML, "http://192.168.1.1:1900/d.xml")
        self.assertEqual((gw["name"], gw["manufacturer"], gw["kind"]),
                         ("Home Router", "TP-Link", "network"))
        self.assertEqual(gw["wan"][0]["control_url"], "http://192.168.1.1:1900/ctl")
        tv = identify.parse_description(TV_XML, "http://192.168.1.31:9197/d.xml")
        self.assertEqual((tv["name"], tv["kind"]), ("[TV] Samsung Q80 Series (55)", "tv"))
        self.assertEqual(tv["wan"], [])


# --- fake devices on 127.0.0.1 ------------------------------------------------------------

class FakeGateway(BaseHTTPRequestHandler):
    """A UPnP IGD: its description, the SOAP control URL and a few hostile extras."""
    actions: list = []
    MAPS = [("TCP", 554, "192.168.1.51", 554, "IPC<script>"), ("UDP", 3478, "192.168.1.71", 3478, "PS5")]

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/xml"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/desc.xml":
            self._send(200, IGD_XML)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/desc.xml")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/big":
            self._send(200, b"<root>" + b"x" * (identify.MAX_DESC_BYTES + 10) + b"</root>")
        else:
            self._send(404, b"")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        action = self.headers.get("SOAPACTION", "").strip('"').split("#")[-1]
        FakeGateway.actions.append(action)
        ns = "urn:schemas-upnp-org:service:WANIPConnection:1"
        out = None
        if action == "GetExternalIPAddress":
            out = "<NewExternalIPAddress>203.0.113.9</NewExternalIPAddress>"
        elif action == "GetStatusInfo":
            out = "<NewConnectionStatus>Connected</NewConnectionStatus>"
        elif action == "GetGenericPortMappingEntry":
            i = int(re.search(r"<NewPortMappingIndex>(\d+)<", body).group(1))
            if i < len(self.MAPS):
                p, e, c, ip, d = self.MAPS[i]
                out = (f"<NewRemoteHost></NewRemoteHost><NewExternalPort>{e}</NewExternalPort>"
                       f"<NewProtocol>{p}</NewProtocol><NewInternalPort>{ip}</NewInternalPort>"
                       f"<NewInternalClient>{c}</NewInternalClient><NewEnabled>1</NewEnabled>"
                       f"<NewPortMappingDescription>{d.replace('<', '&lt;')}</NewPortMappingDescription>"
                       f"<NewLeaseDuration>0</NewLeaseDuration>")
        if out is None:
            self._send(500, b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
                            b"<s:Body><s:Fault><detail><UPnPError><errorCode>713</errorCode>"
                            b"<errorDescription>SpecifiedArrayIndexInvalid</errorDescription>"
                            b"</UPnPError></detail></s:Fault></s:Body></s:Envelope>")
            return
        self._send(200, (f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
                         f'<u:{action}Response xmlns:u="{ns}">{out}</u:{action}Response>'
                         f"</s:Body></s:Envelope>").encode())


def udp_responder(reply):
    """A one-socket fake that answers every datagram with reply(data) (or nothing)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(9000)
            except OSError:
                continue
            for out in reply(data):
                s.sendto(out, addr)
    threading.Thread(target=loop, daemon=True).start()
    return s, stop


class FakeNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), FakeGateway)
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.http.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()

    def setUp(self):
        FakeGateway.actions = []
        p = mock.patch.object(identify, "private_ip", loopback_ok)
        p.start()
        self.addCleanup(p.stop)

    def test_mdns_browse_against_a_fake_responder(self):
        got = []
        s, stop = udp_responder(lambda data: (got.append(data), [cast_answer(), b"junk"])[1])
        try:
            res = identify.mdns_browse(0.6, dest=s.getsockname())
        finally:
            stop.set()
            s.close()
        self.assertIn(b"_googlecast", got[0])               # the query asked for our types
        self.assertEqual(res["127.0.0.1"]["model"], "Chromecast")

    def test_ssdp_search_describe_and_read_the_gateway(self):
        loc = f"{self.base}/desc.xml"
        reply = (f"HTTP/1.1 200 OK\r\nLOCATION: {loc}\r\nST: upnp:rootdevice\r\n"
                 f"SERVER: Linux UPnP/1.0\r\n\r\n").encode()
        s, stop = udp_responder(lambda data: [reply] if data.startswith(b"M-SEARCH") else [])
        try:
            found = identify.ssdp_search(0.6, dest=s.getsockname())
        finally:
            stop.set()
            s.close()
        self.assertEqual(found["127.0.0.1"]["locations"], [loc])
        described = identify.describe(found)
        self.assertEqual(described["127.0.0.1"]["name"], "Home Router")
        db = store.connect(":memory:")
        res = upnp.check_recorded(db, described, {"192.168.1.51": CAM}, gateway_ip="127.0.0.1")
        self.assertEqual(res, {"available": True, "mappings": 2, "risky": 1})
        # only allowlisted actions reached the gateway; the list ended at the 713 fault
        self.assertTrue(set(FakeGateway.actions) <= upnp.ALLOWED_ACTIONS)
        self.assertEqual(FakeGateway.actions.count("GetGenericPortMappingEntry"), 3)
        snap = store.upnp_latest(db)
        self.assertEqual((snap["external_ip"], snap["status"]), ("203.0.113.9", "Connected"))
        maps = {m["external_port"]: m for m in store.upnp_current(db)}
        self.assertEqual(maps[554]["mac"], CAM)
        self.assertEqual(maps[554]["description"], "IPC<script>")   # stored raw, escaped on output
        self.assertIsNone(maps[3478]["mac"])
        self.assertEqual(store.source_status(db)["upnp"]["last_count"], 2)

    def test_redirects_are_not_followed_and_size_is_capped(self):
        status, _ = identify.http_get(f"{self.base}/redirect")
        self.assertEqual(status, 302)
        with self.assertRaises(ValueError):
            identify.http_get(f"{self.base}/big")
        found = {"127.0.0.1": {"locations": [f"{self.base}/redirect", f"{self.base}/big",
                                             "http://10.9.9.9/desc.xml"], "server": "", "st": []}}
        fetched = []
        self.assertEqual(identify.describe(found, fetch=lambda u: (fetched.append(u),
                                                                   identify.http_get(u))[1]), {})
        self.assertNotIn("http://10.9.9.9/desc.xml", fetched)       # not the responder's IP

    def test_no_gateway_is_a_calm_result(self):
        db = store.connect(":memory:")
        self.assertEqual(upnp.check_recorded(db, {}, {}, gateway_ip="192.168.1.1"),
                         {"available": False, "mappings": 0})
        self.assertEqual(store.source_status(db)["upnp"]["last_error"], None)
        r = upnp.report(db, "en")
        self.assertFalse(r["available"])
        self.assertIn("UPnP not available", r["summary"])


class SoapAllowlistTests(unittest.TestCase):
    def fetch(self, *a, **kw):
        raise AssertionError("nothing may be sent")

    def test_only_three_read_actions(self):
        self.assertEqual(upnp.ALLOWED_ACTIONS, {"GetExternalIPAddress", "GetStatusInfo",
                                                "GetGenericPortMappingEntry"})
        for bad in ("AddPortMapping", "DeletePortMapping", "AddAnyPortMapping",
                    "ForceTermination", "SetConnectionType", "RequestConnection"):
            with self.assertRaises(upnp.RefusedAction):
                upnp.soap_call("http://192.168.1.1:1900/ctl", "urn:x", bad, {}, "192.168.1.1", self.fetch)

    def test_control_url_must_be_on_the_private_gateway(self):
        for url, gw in (("http://8.8.8.8/ctl", "8.8.8.8"), ("http://192.168.1.2/ctl", "192.168.1.1"),
                        ("https://192.168.1.1/ctl", "192.168.1.1"), ("http://192.168.1.1/ctl", None)):
            with self.assertRaises(upnp.RefusedAction):
                upnp.soap_call(url, "urn:x", "GetStatusInfo", {}, gw, self.fetch)

    def test_source_only_names_allowed_actions(self):
        src = Path(upnp.__file__).read_text(encoding="utf-8")
        called = set(re.findall(r'call\("(\w+)"', src))
        self.assertEqual(called, upnp.ALLOWED_ACTIONS)
        for word in ("AddPortMapping", "DeletePortMapping"):
            self.assertNotIn(f'"{word}"', src)

    def test_hostile_reply_and_mapping_validation(self):
        bad = lambda *a, **kw: (200, b"<!DOCTYPE x><x/>")   # noqa: E731
        with self.assertRaises(upnp.SoapFault):
            upnp.soap_call("http://192.168.1.1/ctl", "urn:x", "GetStatusInfo", {}, "192.168.1.1", bad)
        self.assertIsNone(upnp._mapping({"NewProtocol": "ICMP", "NewExternalPort": "1",
                                         "NewInternalPort": "1", "NewInternalClient": "192.168.1.2"}))
        self.assertIsNone(upnp._mapping({"NewProtocol": "TCP", "NewExternalPort": "99999",
                                         "NewInternalPort": "1", "NewInternalClient": "192.168.1.2"}))


# --- store, alerts, digest -------------------------------------------------------------------

class UpnpStoreTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        store.upsert_device(self.db, {"mac": CAM, "ip": "192.168.1.51", "vendor": "", "hostname": "ipcam"})
        store.upsert_device(self.db, {"mac": PS5, "ip": "192.168.1.71", "vendor": "", "hostname": "PS5"})
        self.now = datetime.now(timezone.utc)
        self.ps5 = {"protocol": "UDP", "external_port": 3478, "internal_client": "192.168.1.71",
                    "internal_port": 3478, "description": "PS5", "mac": PS5}
        self.cam = {"protocol": "TCP", "external_port": 554, "internal_client": "192.168.1.51",
                    "internal_port": 554, "description": "cam", "mac": CAM}
        gw = {"available": True, "gateway_ip": "192.168.1.1", "external_ip": "203.0.113.57"}
        store.record_upnp(self.db, gw, [self.ps5], ts=iso(self.now - timedelta(days=2)))
        store.record_upnp(self.db, gw, [self.ps5, self.cam], ts=iso(self.now - timedelta(hours=1)))

    def test_new_and_risky(self):
        maps = {m["external_port"]: m for m in upnp.mappings(self.db)}
        self.assertTrue(maps[554]["risky"] and maps[554]["new"])
        self.assertFalse(maps[3478]["risky"] or maps[3478]["new"])
        self.assertEqual(maps[554]["ack"], "upnp:TCP:554")
        self.assertEqual([m["external_port"] for m in upnp.alerts(self.db, iso(self.now - timedelta(days=1)))],
                         [554])

    def test_first_check_is_not_new(self):
        db = store.connect(":memory:")
        store.record_upnp(db, {"available": True}, [self.ps5])
        self.assertFalse(upnp.mappings(db)[0]["new"])

    def test_alerts_digest_and_acks(self):
        r = alerts.compute(self.db)
        self.assertEqual([m["external_port"] for m in r["upnp"]], [554])
        self.assertTrue(alerts.has_alerts(r))
        loc = alerts.localize(r, "zh-Hant")
        self.assertIn("554", loc["upnp"][0]["text"])
        text = alerts.render_digest(loc, "zh-Hant")
        self.assertIn("UPnP", text)
        self.assertIn("ipcam", text)
        store.add_ack(self.db, CAM, "upnp:TCP:554")
        self.assertEqual(alerts.compute(self.db)["upnp"], [])
        self.assertTrue(upnp.report(self.db, "en")["mappings"][0]["muted"])

    def test_turning_upnp_off_clears_the_ports(self):
        store.record_upnp(self.db, {"available": False, "gateway_ip": "192.168.1.1"}, [])
        self.assertEqual(upnp.mappings(self.db), [])
        self.assertEqual(alerts.compute(self.db)["upnp"], [])
        r = upnp.report(self.db, "en")
        self.assertEqual(r["external_ip"], "203.0.113.57")       # last known, kept locally
        self.assertEqual(r["external_ip_masked"], "203.0.•••.•••")

    def test_report_and_timeline_text_in_every_language(self):
        for lang in ("en", "zh-Hant", "ja", "de"):
            r = upnp.report(self.db, lang)
            self.assertTrue(r["checked"] and r["available"])
            self.assertEqual(len(r["mappings"]), 2)
            self.assertTrue(r["howto"])
        items = timeline.timeline(self.db, CAM, "en")
        self.assertIn("upnp_mapping", [i["kind"] for i in items])

    def test_prune_keeps_the_latest_snapshot(self):
        old = iso(self.now - timedelta(days=200))
        with self.db:
            self.db.execute("UPDATE upnp_snapshots SET ts = '2020' || substr(ts, 5)")
            # mappings the newest (kept) check no longer saw
            self.db.execute("UPDATE upnp_mappings SET first_seen = ?, last_seen = ?",
                            ("2019-01-01T00:00:00.000000Z",) * 2)
        store.upsert_identity(self.db, CAM, "mdns", "Cam", seen=old)
        out = store.prune(self.db, 30)
        self.assertGreaterEqual(out["identity"], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM upnp_snapshots").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM upnp_mappings").fetchone()[0], 0)


class IdentityStoreTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")
        store.upsert_device(self.db, {"mac": DAD_PHONE, "ip": "192.168.1.21", "vendor": "",
                                      "hostname": "", "randomized": True})

    def test_merge_clean_and_name_order(self):
        store.upsert_identity(self.db, DAD_PHONE, "ssdp", "SSDP name")
        store.upsert_identity(self.db, DAD_PHONE, "mdns", "Dad's\niPhone\x00", "Apple", "iPhone15,2",
                              "phone")
        store.upsert_identity(self.db, DAD_PHONE, "mdns", "", model="")   # keeps what we knew
        store.upsert_identity(self.db, DAD_PHONE, "bogus", "x")            # unknown source: ignored
        rows = store.identities(self.db)[DAD_PHONE]
        self.assertEqual([r["source"] for r in rows], ["mdns", "ssdp"])
        self.assertEqual(rows[0]["name"], "Dad's iPhone")
        self.assertEqual(rows[0]["model"], "iPhone15,2")
        self.assertEqual(store.device_names(self.db)[DAD_PHONE], "Dad's iPhone")
        store.set_label(self.db, DAD_PHONE, "爸爸手機")
        self.assertEqual(store.device_names(self.db)[DAD_PHONE], "爸爸手機")   # the label wins
        rep = identify.device_report(self.db, DAD_PHONE, "en", label="爸爸手機")
        self.assertEqual(rep["suggested_name"], "")                         # never over a label

    def test_device_report_and_type_vote(self):
        store.upsert_identity(self.db, DAD_PHONE, "mdns", "Dad's iPhone", "Apple", "iPhone15,2", "phone")
        rep = identify.device_report(self.db, DAD_PHONE, "en")
        self.assertEqual(rep["suggested_name"], "Dad's iPhone")
        self.assertEqual(rep["evidence"][0]["source_name"], "mDNS (Bonjour)")
        t = devicetype.classify_all(self.db)[DAD_PHONE]
        self.assertEqual((t["type"], t["source"]), ("phone", "ident"))
        self.assertIn("iPhone15,2", devicetype.reason_text(t, "en"))

    def test_dns_and_dhcp_names(self):
        self.assertEqual(identify.record_dns_names(self.db, {DAD_PHONE: "dads-phone",
                                                             "aa:bb:cc:dd:ee:ff": "192.168.1.9"}), 1)
        self.assertEqual(identify.record_dns_names(self.db, {DAD_PHONE: "dads-phone"}), 0)  # hourly
        identify.record_dhcp_names(self.db, [{"mac": DAD_PHONE, "hostname": "iPhone"}])
        srcs = {r["source"]: r["name"] for r in store.identities(self.db)[DAD_PHONE]}
        self.assertEqual(srcs, {"dns": "dads-phone", "dhcp": "iPhone"})
        # DHCP / DNS names are the device's hostname, not an announced name
        self.assertEqual(identify.device_report(self.db, DAD_PHONE, "en")["suggested_name"], "")

    def test_record_and_summary_kinds(self):
        n = identify.record_mdns(self.db, {"192.168.1.21": {"name": "X", "manufacturer": "Apple",
                                                         "model": "iPad13,1", "kind": "tablet",
                                                         "services": ["_airplay._tcp"]},
                                           "192.168.1.99": {"name": "unknown host"}},
                                 {"192.168.1.21": DAD_PHONE})
        self.assertEqual(n, 1)
        self.assertEqual(identify._kinds({"a": {"kind": "tv"}, "b": {}}), {"tv": 1, "unknown": 1})

    def test_demo_db_is_refused(self):
        store.set_meta(self.db, "demo", "1")
        with self.assertRaises(identify.DemoRefused):
            identify.run_recorded(self.db, 0.1)

    def test_health_hint_only_on_error(self):
        store.record_source_error(self.db, "mdns", "OSError: [Errno 19] No such device")
        st = health.status(self.db, None, {})
        hints = health.hints(st, "en")
        self.assertTrue(any("mDNS" in h and "No such device" in h for h in hints))

    def test_silent_multicast_hint(self):
        for src in ("mdns", "ssdp"):
            store.record_source_ok(self.db, src, 0)
        hints = health.hints(health.status(self.db, None, {}), "en")
        self.assertTrue(any("Hyper-V" in h for h in hints))
        store.record_source_ok(self.db, "mdns", 3)
        hints = health.hints(health.status(self.db, None, {}), "en")
        self.assertFalse(any("Hyper-V" in h for h in hints))


# --- routine traffic + catalog ----------------------------------------------------------------

class DomainKnowledgeTests(unittest.TestCase):
    def test_routine(self):
        self.assertEqual(routine.lookup("connectivitycheck.gstatic.com"), "connectivity")
        self.assertEqual(routine.lookup("2.pool.ntp.org"), "time")
        self.assertEqual(routine.lookup("time.stdtime.gov.tw"), "time")
        self.assertEqual(routine.lookup("a123.dscb.akamaiedge.net"), "cdn")
        self.assertIsNone(routine.lookup("tiktok.com"))
        self.assertIsNone(routine.lookup("evilntp.org"))                   # suffix, not substring
        i = routine.info("captive.apple.com", "zh-Hant")
        self.assertEqual(i["kind"], "connectivity")
        self.assertIn("例行", i["text"])
        for k in routine.KINDS:
            self.assertIn(k, routine.LLM_TEXT)

    def test_catalog_additions(self):
        for dom in ("line.me", "dcard.tw", "shopee.tw", "momoshop.com.tw", "kkbox.com"):
            sid, _cat = services.lookup(dom)
            self.assertIsNotNone(sid, dom)
        self.assertEqual(services.lookup("www.gov.tw")[1], "gov")
        self.assertEqual(services.lookup("nothing-here.example")[0], None)
        self.assertTrue(privacy.lookup("api-access.pangle.io"))
        self.assertTrue(privacy.lookup("ads.vpon.com"))

    def test_routine_in_the_device_view(self):
        d = services.localize_device({"top_domains": [{"domain": "time.apple.com", "count": 3},
                                                      {"domain": "line.me", "count": 2}]}, "en")
        self.assertEqual(d["top_domains"][0]["routine"]["kind"], "time")
        self.assertIsNone(d["top_domains"][1]["routine"])


# --- the demo story, end to end ---------------------------------------------------------------

class DemoStoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.tmp.name) / "demo.db"
        demo.build(cls.path)
        cls.db = store.connect(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        cls.tmp.cleanup()

    def test_identity_story(self):
        ids = identify.summary_all(self.db)
        self.assertEqual(ids[TV]["kind"], "tv")
        self.assertEqual(ids[TV]["sources"], ["mdns", "ssdp", "dhcp"])
        self.assertEqual(ids[PRINTER]["model"], "HP OfficeJet Pro 9010 series")
        rep = identify.device_report(self.db, DAD_PHONE, "zh-Hant")
        self.assertEqual(rep["suggested_name"], "爸爸的 iPhone")
        self.assertEqual(store.device_names(self.db)[DAD_PHONE], "爸爸的 iPhone")
        ssdp = next(e for e in identify.device_report(self.db, TV, "en")["evidence"]
                    if e["source"] == "ssdp")
        self.assertEqual(ssdp["name"], "[TV] Samsung Q80 Series (55)")

    def test_upnp_story(self):
        r = upnp.report(self.db, "en")
        maps = {m["mac"]: m for m in r["mappings"]}
        self.assertTrue(maps[CAM]["risky"] and maps[CAM]["new"])
        self.assertFalse(maps[PS5]["risky"] or maps[PS5]["new"])
        self.assertEqual(r["external_ip_masked"], "203.0.•••.•••")
        a = alerts.compute(self.db)
        self.assertEqual([m["mac"] for m in a["upnp"]], [CAM])
        inv = dashboard.inventory(self.db, web.localize_snapshot(brain.snapshot(self.db), "en"), "en")
        by = {d["mac"]: d for d in inv["devices"]}
        self.assertEqual(by[CAM]["upnp_risky"], 1)
        self.assertEqual(by[TV]["ident"]["model"], "QA55Q80BAWXZW")

    def test_brain_and_redaction(self):
        snap = brain.snapshot(self.db)
        cam = next(d for d in snap["devices"] if d["mac"] == CAM)
        self.assertTrue(any("554" in line and "risky" in line for line in cam["upnp_mappings"]))
        self.assertEqual(snap["upnp"]["available"], True)
        tv = next(d for d in snap["devices"] if d["mac"] == TV)
        self.assertIn("QA55Q80BAWXZW", tv["model"])
        self.assertIn("mdns", tv["identified_via"])
        r = redact.Redactor.build(self.db, snap)
        out = r.redact("Is 客廳 Chromecast or [TV] Samsung Q80 Series (55) ok?")
        self.assertNotIn("客廳 Chromecast", out)
        self.assertNotIn("Samsung Q80 Series (55)", out)

    def test_routine_domains_never_count_as_new_services(self):
        now = datetime.now(timezone.utc)
        db = store.connect(":memory:")
        store.upsert_device(db, {"mac": PS5, "ip": "192.168.1.71", "vendor": "", "hostname": "PS5"},
                            seen=iso(now - timedelta(days=9)))
        ev = lambda dom, ago: {"source": "adguard", "ts": iso(now - ago), "client_ip": "192.168.1.71",  # noqa: E731
                               "client_name": "", "domain": dom, "qtype": "A", "status": "",
                               "reason": "", "blocked": 0, "cached": 0, "upstream": "",
                               "elapsed_ms": 1.0, "block_reason": None, "device_mac": PS5}
        store.insert_events(db, [ev("playstation.net", timedelta(days=5)),
                                 ev("time.google.com", timedelta(hours=1)),
                                 ev("update.playstation.net", timedelta(hours=1))])
        self.assertEqual(alerts.compute(db)["behavior_changes"], [])

    def test_identify_cli_refuses_the_demo(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["identify", "--db", str(self.path), "--lang", "en"])
        self.assertEqual(code, 1)
        self.assertIn("demo", err.getvalue())

    def test_over_http(self):
        srv = web.make_server(self.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]

            def get(path):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                c.request("GET", path)
                r = c.getresponse()
                return r.status, json.loads(r.read())
            status, u = get("/api/upnp?lang=zh-Hant")
            self.assertEqual(status, 200)
            self.assertEqual(len(u["mappings"]), 3)   # + Stage Q's forward to a gone IP
            self.assertIn("UPnP", u["howto"])
            status, d = get(f"/api/device?mac={CAM}&lang=en")
            self.assertEqual(status, 200)
            self.assertEqual(d["upnp"][0]["external_port"], 554)
            status, d = get(f"/api/device?mac={TV}&lang=en")
            self.assertEqual(d["identity"]["model"], "QA55Q80BAWXZW")
            self.assertEqual([e["source"] for e in d["identity"]["evidence"]], ["mdns", "ssdp", "dhcp"])
            status, a = get("/api/alerts?lang=en")
            self.assertEqual([m["mac"] for m in a["upnp"]], [CAM])
            status, dom = get("/api/domain?d=connectivitycheck.gstatic.com&lang=en")
            self.assertEqual(status, 200)
            self.assertEqual(dom["routine"]["kind"], "connectivity")
            status, st = get("/api/status?lang=en")
            self.assertEqual(st["sources"]["upnp"]["last_count"], 2)
        finally:
            srv.shutdown()
            srv.server_close()


class UiFileTests(unittest.TestCase):
    """The page's Stage N pieces exist and stay escaped (the html tag does that)."""
    js = (Path(web.__file__).parent / "static" / "app.js").read_text(encoding="utf-8")

    def test_wiring(self):
        for needle in ("upnp: '/api/upnp'", "function upnpCard", "case 'use-name'",
                       "case 'extip'", "app.ident.use_name", "tag-routine", "a.upnp"):
            self.assertIn(needle, self.js)
        self.assertEqual(self.js.count("innerHTML"), 2)


if __name__ == "__main__":
    unittest.main()
