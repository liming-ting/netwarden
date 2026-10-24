"""
Stage M: open the dashboard on your phone (opt-in LAN mode with pairing).

Everything runs on 127.0.0.1 only. "A phone on the LAN" is simulated through the
injectable Handler.is_local_client check (never by binding a LAN address), and LAN-mode
plumbing is exercised on a second LOOPBACK address (127.0.0.2) with is_lan_ip patched.
The QR encoder (vendored) is checked against an independent decoder written here.
"""
import contextlib
import hashlib
import http.client
import io
import json
import logging
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netwarden import __main__ as cli
from netwarden import brain, i18n, pairing, qr, settings, store, web
from netwarden.vendor import qrcodegen

UTC = timezone.utc
T0 = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
UA_IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")


# --- an independent QR decoder (byte mode, no error correction needed) ---------------

ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38],
         8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
MASKS = [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
         lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
         lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
         lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0]
FB_TO_ORDINAL = {1: 0, 0: 1, 3: 2, 2: 3}   # ISO format bits L=01 M=00 Q=11 H=10


def _bch_ok(word: int) -> bool:
    rem = word
    for i in range(14, 9, -1):
        if rem >> i & 1:
            rem ^= 0x537 << (i - 10)
    return rem == 0


def decode(m) -> tuple:
    """(text, ecc ordinal, mask) of a module matrix (m[y][x], True = dark)."""
    n = len(m)
    ver = (n - 17) // 4
    assert 1 <= ver <= 10 and n == 17 + 4 * ver
    # format info, copy 1 (ISO 18004 positions around the top-left finder)
    pos = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(14 - i, 8) for i in range(9, 15)]
    raw = sum(int(m[y][x]) << i for i, (x, y) in enumerate(pos))
    word = raw ^ 0x5412
    assert _bch_ok(word), "format information fails its BCH check"
    fb, mask = word >> 13, (word >> 10) & 7

    def function(x, y):
        if (x < 9 and y < 9) or (x >= n - 8 and y < 9) or (x < 9 and y >= n - 8):
            return True                      # finders, separators, format info, dark module
        if x == 6 or y == 6:
            return True                      # timing patterns
        a = ALIGN[ver]
        for cx in a:
            for cy in a:
                corner = (cx == a[0] and cy == a[0]) or (cx == a[0] and cy == a[-1]) \
                    or (cx == a[-1] and cy == a[0])
                if not corner and abs(x - cx) <= 2 and abs(y - cy) <= 2:
                    return True
        if ver >= 7 and ((n - 11 <= x < n - 8 and y < 6) or (n - 11 <= y < n - 8 and x < 6)):
            return True
        return False

    bits = []
    right = n - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(n):
            for j in range(2):
                x = right - j
                y = n - 1 - vert if ((right + 1) & 2) == 0 else vert
                if not function(x, y):
                    bits.append(int(m[y][x]) ^ int(MASKS[mask](x, y)))
        right -= 2
    raw_cw = len(bits) // 8
    cws = [int("".join(map(str, bits[i * 8:i * 8 + 8])), 2) for i in range(raw_cw)]
    ordinal = FB_TO_ORDINAL[fb]
    nblocks = qrcodegen.QrCode._NUM_ERROR_CORRECTION_BLOCKS[ordinal][ver]
    ecclen = qrcodegen.QrCode._ECC_CODEWORDS_PER_BLOCK[ordinal][ver]
    nshort = nblocks - raw_cw % nblocks
    shortlen = raw_cw // nblocks
    lens = [shortlen - ecclen + (0 if b < nshort else 1) for b in range(nblocks)]
    blocks, k = [[] for _ in range(nblocks)], 0
    for i in range(max(lens)):
        for b in range(nblocks):
            if i < lens[b]:
                blocks[b].append(cws[k])
                k += 1
    data = [c for blk in blocks for c in blk]
    stream = "".join(f"{c:08b}" for c in data)
    assert stream[:4] == "0100", "byte mode expected"
    count_bits = 8 if ver <= 9 else 16
    count = int(stream[4:4 + count_bits], 2)
    start = 4 + count_bits
    payload = bytes(int(stream[start + 8 * i:start + 8 * i + 8], 2) for i in range(count))
    return payload.decode("utf-8"), ordinal, mask


class QRTests(unittest.TestCase):
    URLS = ("http://192.168.1.13:8787/pair#ABCDEFGHJK", "http://127.0.0.1:8799/pair#Z2X3C4V5B6",
            "http://192.168.100.200:65535/pair#QWERTYPASD", "a", "netwarden 家 ✓",
            "http://172.16.0.1:8787/pair#" + "M" * 10 + "/" + "x" * 60)

    def test_round_trip_through_an_independent_decoder(self):
        for text in self.URLS:
            m = qr.matrix(text)
            got, ordinal, mask = decode(m)
            self.assertEqual(got, text)
            self.assertGreaterEqual(ordinal, 1)          # MEDIUM or better (boosted)
            q = qr.encode(text)
            self.assertEqual(mask, q.get_mask())
            self.assertEqual(ordinal, q.get_error_correction_level().ordinal)

    def test_known_output_is_pinned(self):
        # fingerprint of the module grid for one pairing URL, from the pristine upstream
        # encoder: any accidental edit of the vendored file changes it
        m = qr.matrix("http://192.168.1.13:8787/pair#ABCDEFGHJK")
        self.assertEqual(len(m), 29)                      # version 3
        fp = hashlib.sha256("".join("1" if v else "0" for row in m for v in row).encode()).hexdigest()
        self.assertEqual(fp, KNOWN_FP)

    def test_vendored_file_is_upstream_unchanged(self):
        src = (Path(qrcodegen.__file__)).read_bytes().split(b"\n", 4)
        self.assertIn(b"nayuki/QR-Code-generator", src[0])
        self.assertIn(b"MIT", src[3])
        body = src[4]
        self.assertTrue(body.startswith(b"# \n# QR Code generator library (Python)"))
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         "9f4ed1dd201dcb92b1bc0d6e14f46c754bcff0ce48580c5d7e8ace8f6926c8ef")

    def test_svg_terminal_and_data_uri(self):
        text = "http://192.168.1.13:8787/pair#ABCDEFGHJK"
        m = qr.matrix(text)
        svg = qr.svg(text)
        n = len(m) + 2 * qr.QUIET
        self.assertTrue(svg.startswith("<svg") and f'viewBox="0 0 {n} {n}"' in svg)
        self.assertEqual(svg.count("h1v1h-1z"), sum(v for row in m for v in row))
        self.assertNotIn("<script", svg)
        self.assertTrue(qr.data_uri(text).startswith("data:image/svg+xml;base64,"))
        lines = qr.terminal(text).split("\n")
        self.assertEqual(len(lines), (n + 1) // 2)
        self.assertTrue(all(len(line) == n for line in lines))
        self.assertTrue(set("".join(lines)) <= set("▀▄█ "))
        # the quiet zone is light: full blocks on a dark terminal, blank when inverted
        self.assertEqual(lines[0], "█" * n)
        self.assertEqual(qr.terminal(text, invert=True).split("\n")[0], " " * n)
        for bad in ("", "x" * (qr.MAX_TEXT + 1), None):
            with self.assertRaises(ValueError):
                qr.matrix(bad)


# --- pairing: codes, sessions, limiter ----------------------------------------------

class PairingUnitTests(unittest.TestCase):
    def setUp(self):
        self.db = store.connect(":memory:")

    def test_code_shape_and_normalization(self):
        c = pairing.new_code(self.db, now=T0)
        self.assertRegex(c["code"], "^[" + pairing.CODE_ALPHABET + "]{10}$")
        self.assertEqual(c["display"], c["code"][:5] + "-" + c["code"][5:])
        self.assertEqual(c["ttl_s"], 600)
        self.assertEqual(pairing.normalize_code(" " + c["display"].lower() + " "), c["code"])
        for bad in (None, 5, "", "ABC", "ABCDEFGHJ0", "O" * 10, "x" * 41, "ABCDEFGHJKL"):
            self.assertIsNone(pairing.normalize_code(bad), bad)

    def test_only_hashes_are_stored(self):
        c = pairing.new_code(self.db, now=T0)
        token, _sid = pairing.redeem(self.db, c["code"], UA_IPHONE, now=T0)
        dump = "\n".join(self.db.iterdump())
        self.assertNotIn(c["code"], dump)
        self.assertNotIn(token, dump)
        self.assertIn(hashlib.sha256(token.encode()).hexdigest(), dump)

    def test_single_use_and_expiry(self):
        c = pairing.new_code(self.db, now=T0)
        got = pairing.redeem(self.db, c["display"], UA_IPHONE, now=T0 + timedelta(minutes=9))
        self.assertIsNotNone(got)
        self.assertIsNone(pairing.redeem(self.db, c["code"], UA_IPHONE, now=T0 + timedelta(minutes=9)))
        c2 = pairing.new_code(self.db, now=T0)
        self.assertIsNone(pairing.redeem(self.db, c2["code"], "", now=T0 + timedelta(minutes=10, seconds=1)))
        self.assertIsNone(pairing.redeem(self.db, "WRONGCODE2", "", now=T0))
        token = got[0]
        self.assertTrue(pairing.TOKEN_RE.match(token))   # 256-bit token_urlsafe
        self.assertEqual(len(token), 43)

    def test_open_codes_are_capped(self):
        codes = [pairing.new_code(self.db, now=T0)["code"] for _ in range(pairing.MAX_OPEN_CODES + 2)]
        self.assertIsNone(pairing.redeem(self.db, codes[0], "", now=T0))   # the oldest dropped
        self.assertIsNotNone(pairing.redeem(self.db, codes[-1], "", now=T0))

    def test_sliding_expiry(self):
        c = pairing.new_code(self.db, now=T0)
        token, sid = pairing.redeem(self.db, c["code"], UA_IPHONE, now=T0)
        s = pairing.check(self.db, token, now=T0 + timedelta(minutes=1))
        self.assertEqual((s["id"], s["refresh"]), (sid, False))        # too soon to write
        s = pairing.check(self.db, token, now=T0 + timedelta(days=20))
        self.assertTrue(s["refresh"])
        # used on day 20 -> still valid on day 45, but not 30 days after the last use
        self.assertIsNotNone(pairing.check(self.db, token, now=T0 + timedelta(days=45)))
        self.assertIsNone(pairing.check(self.db, token, now=T0 + timedelta(days=80)))
        for bad in (None, "", "short", token + "x", token[:-1] + "!"):
            self.assertIsNone(pairing.check(self.db, bad, now=T0), bad)

    def test_revoke_revoke_all_logout_prune(self):
        toks = []
        for _ in range(3):
            c = pairing.new_code(self.db, now=T0)
            toks.append(pairing.redeem(self.db, c["code"], UA_IPHONE, now=T0))
        self.assertEqual(len(pairing.sessions(self.db, now=T0)), 3)
        self.assertTrue(pairing.revoke(self.db, toks[0][1]))
        self.assertFalse(pairing.revoke(self.db, toks[0][1]))
        self.assertIsNone(pairing.check(self.db, toks[0][0], now=T0))
        self.assertTrue(pairing.logout(self.db, toks[1][0]))
        self.assertIsNone(pairing.check(self.db, toks[1][0], now=T0))
        open_code = pairing.new_code(self.db, now=T0)
        self.assertEqual(pairing.revoke_all(self.db), 1)
        self.assertEqual(pairing.sessions(self.db, now=T0), [])
        self.assertIsNone(pairing.redeem(self.db, open_code["code"], "", now=T0))  # codes die too
        c = pairing.new_code(self.db, now=T0)
        pairing.redeem(self.db, c["code"], "", now=T0)
        self.assertEqual(pairing.prune(self.db, now=T0 + timedelta(days=31)), 1)

    def test_session_list_and_labels(self):
        c = pairing.new_code(self.db, now=T0)
        _t, sid = pairing.redeem(self.db, c["code"], UA_IPHONE + "\n<script>", now=T0)
        [s] = pairing.sessions(self.db, now=T0, current=sid)
        self.assertEqual(s["device"], "iPhone · Safari")
        self.assertTrue(s["current"])
        self.assertNotIn("\n", s["user_agent"])
        cases = {
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/129.0 Mobile Safari/537.36": "Android · Chrome",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129 Safari/537.36 Edg/129": "Windows · Edge",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Gecko/20100101 Firefox/131.0": "Mac · Firefox",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) SamsungBrowser/26.0 Chrome/122 Mobile Safari/537.36": "Android · Samsung Internet",
            "curl/8.5": "", "": ""}
        for ua, want in cases.items():
            self.assertEqual(pairing.device_label(ua), want, ua)

    def test_cookie_flags_and_parsing(self):
        tok = "A" * 43
        ck = pairing.cookie(tok)
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=2592000"):
            self.assertIn(flag, ck)
        self.assertNotIn("Domain", ck)
        self.assertIn("Max-Age=0", pairing.clear_cookie())
        self.assertEqual(pairing.token_from_cookie(f"theme=dark; nw_session={tok}; x=1"), tok)
        for bad in (None, "", "nw_session=", "nw_session=abc", "other=" + tok, f"nw_session={tok}x"):
            self.assertIsNone(pairing.token_from_cookie(bad), bad)

    def test_limiter_lockout_global_and_reset(self):
        now = [1000.0]
        lim = pairing.Limiter(max_fail=3, window=60, lockout=120, global_max=6, clock=lambda: now[0])
        for _ in range(2):
            lim.fail("10.0.0.5")
        self.assertEqual(lim.blocked("10.0.0.5"), 0)
        lim.success("10.0.0.5")                      # a good code clears its own misses
        for _ in range(3):
            lim.fail("10.0.0.5")
        self.assertAlmostEqual(lim.blocked("10.0.0.5"), 120)
        self.assertEqual(lim.blocked("10.0.0.6"), 0)
        now[0] += 121
        self.assertEqual(lim.blocked("10.0.0.5"), 0)
        for ip in ("10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.12"):
            lim.fail(ip)                              # six addresses, one miss each
        self.assertGreater(lim.blocked("10.0.0.99"), 0)   # everyone waits
        now[0] += 61
        self.assertEqual(lim.blocked("10.0.0.99"), 0)

    def test_lan_address_rules(self):
        for ok in ("192.168.1.13", "192.168.0.2", "172.16.5.4", "169.254.1.1"):
            self.assertTrue(pairing.is_lan_ip(ok), ok)
        for bad in ("127.0.0.1", "0.0.0.0", "8.8.8.8", "100.64.0.1", "224.0.0.1", "::1",
                    "fe80::1", "localhost", "", "192.168.1.300"):
            self.assertFalse(pairing.is_lan_ip(bad), bad)

    def test_pair_page_escapes_and_localizes(self):
        page = pairing.render_page("zh-Hant", "abc")
        self.assertIn('lang="zh-Hant"', page)
        self.assertIn(i18n.t("app.pair.page_title", "zh-Hant"), page)
        self.assertIn("/static/pair.js?v=abc", page)
        self.assertNotIn("<script>", page)                # no inline script under the CSP
        with mock.patch.object(i18n, "t", lambda k, lang, **kw: '"><img src=x onerror=1>'):
            evil = pairing.render_page("en")
        self.assertNotIn("<img", evil)


# --- the web server ---------------------------------------------------------------

class WebStageM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "m.db")
        db = store.connect(cls.path)
        store.upsert_device(db, {"ip": "192.168.1.51", "mac": "aa:bb:cc:00:00:01", "vendor": "Cam",
                                 "hostname": "ipcam", "randomized": False, "is_self": False})
        db.close()
        cls.srv = web.make_server(cls.path, 0, {brain.OFFLINE_ENV: "1"}, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.tmp.cleanup()

    def setUp(self):
        web.Handler.limiter = pairing.Limiter()
        web.Handler.require_auth = False
        web.Handler.lan_hosts, web.Handler.lan_url, web.Handler.lan = frozenset(), "", False
        self.addCleanup(self._restore)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False
        web.Handler.lan_hosts, web.Handler.lan_url, web.Handler.lan = frozenset(), "", False
        db = store.connect(self.path)
        pairing.revoke_all(db)
        db.close()

    def phone(self):
        """From now on every request looks like it comes from another device."""
        web.Handler.is_local_client = staticmethod(lambda ip: False)

    def req(self, method, path, body=None, cookie=None, origin="same", host=None, ua=UA_IPHONE):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"user-agent": ua}
        if host:
            h["host"] = host
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            if origin == "same":
                h["origin"] = self.origin
            elif origin:
                h["origin"] = origin
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        try:
            j = json.loads(data)
        except ValueError:
            j = None
        return r.status, r, j, data

    def new_code(self) -> str:
        db = store.connect(self.path)
        try:
            return pairing.new_code(db)["code"]
        finally:
            db.close()

    def pair(self, code=None):
        st, r, j, _ = self.req("POST", "/api/pair", {"code": code or self.new_code()})
        self.assertEqual(st, 200, j)
        ck = r.getheader("set-cookie")
        return ck.split(";")[0], ck

    # -- loopback: unchanged ---------------------------------------------------------
    def test_loopback_works_as_before_and_every_response_has_security_headers(self):
        for path in ("/", "/api/meta", "/static/app.js", "/nope", "/pair", "/static/manifest.webmanifest"):
            st, r, j, _ = self.req("GET", path)
            self.assertIn(st, (200, 404), path)
            self.assertIn("frame-ancestors 'none'", r.getheader("content-security-policy"), path)
            self.assertEqual(r.getheader("x-content-type-options"), "nosniff", path)
            self.assertEqual(r.getheader("referrer-policy"), "no-referrer", path)
            self.assertEqual(r.getheader("x-frame-options"), "DENY", path)
            self.assertEqual(len(r.headers.get_all("x-content-type-options")), 1, path)
        st, _r, meta, _ = self.req("GET", "/api/meta")
        self.assertEqual((meta["remote"], meta["lan"], meta["signed_in"], meta["require_auth"]),
                         (False, False, False, False))
        st, _r, _j, _ = self.req("POST", "/api/label", {"mac": "aa:bb:cc:00:00:01", "label": "Cam"}, origin=None)
        self.assertEqual(st, 200)        # local tools may still POST without Origin

    def test_static_types(self):
        st, r, _j, body = self.req("GET", "/static/apple-touch-icon.png")
        self.assertEqual((st, r.getheader("content-type")), (200, "image/png"))
        self.assertTrue(body.startswith(b"\x89PNG"))
        st, r, j, _ = self.req("GET", "/static/manifest.webmanifest")
        self.assertEqual(r.getheader("content-type"), "application/manifest+json")
        self.assertEqual(j["display"], "standalone")

    # -- a phone without a session ----------------------------------------------------
    def test_phone_without_session_only_gets_the_pairing_page(self):
        self.phone()
        st, r, _j, _ = self.req("GET", "/")
        self.assertEqual((st, r.getheader("location")), (303, "/pair"))
        st, r, _j, _ = self.req("GET", "/report/weekly")
        self.assertEqual(st, 303)
        for path in ("/api/meta", "/api/inventory", "/api/devices", "/static/app.js",
                     "/api/export/devices.csv", "/api/locale"):
            st, _r, j, _ = self.req("GET", path)
            self.assertEqual(st, 401, path)
            self.assertTrue(j["pair"])
        for path in ("/pair", "/static/pair.js", "/static/app.css", "/static/icon.svg",
                     "/static/manifest.webmanifest", "/static/icon-192.png"):
            st, *_ = self.req("GET", path)
            self.assertEqual(st, 200, path)
        st, *_ = self.req("POST", "/api/ack", {"mac": "aa:bb:cc:00:00:01", "domain": ""})
        self.assertEqual(st, 401)

    def test_pair_page_language_follows_the_phone(self):
        self.phone()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/pair", headers={"accept-language": "ja-JP,ja;q=0.9"})
        body = c.getresponse().read().decode()
        c.close()
        self.assertIn(i18n.t("app.pair.connect", "ja"), body)

    def test_remote_post_requires_origin(self):
        self.phone()
        st, *_ = self.req("POST", "/api/pair", {"code": "ABCDEFGHJK"}, origin=None)
        self.assertEqual(st, 403)
        st, *_ = self.req("POST", "/api/pair", {"code": "ABCDEFGHJK"}, origin="http://evil.example")
        self.assertEqual(st, 403)

    # -- the pairing lifecycle ----------------------------------------------------------
    def test_pairing_lifecycle(self):
        self.phone()
        code = self.new_code()
        cookie, raw = self.pair(code)
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=2592000"):
            self.assertIn(flag, raw)
        # single use
        st, _r, j, _ = self.req("POST", "/api/pair", {"code": code})
        self.assertEqual(st, 400)
        self.assertEqual(j["error"], i18n.t("err.pair_bad_code", "en"))
        # the session opens everything a viewer needs
        st, _r, meta, _ = self.req("GET", "/api/meta", cookie=cookie)
        self.assertEqual((st, meta["remote"], meta["signed_in"]), (200, True, True))
        self.assertEqual(self.req("GET", "/", cookie=cookie)[0], 200)
        self.assertEqual(self.req("GET", "/api/inventory", cookie=cookie)[0], 200)
        # view, ack, mute, trust, label: allowed
        mac = "aa:bb:cc:00:00:01"
        for path, body in (("/api/ack", {"mac": mac, "domain": ""}), ("/api/unack", {"mac": mac, "domain": ""}),
                           ("/api/ack", {"mac": mac, "domain": "xmeye.net"}),
                           ("/api/label", {"mac": mac, "label": "Front door"}),
                           ("/api/profile", {"mac": mac, "room": "Hall"})):
            st, _r, j, _ = self.req("POST", path, body, cookie=cookie)
            self.assertEqual(st, 200, (path, j))
        # sign out: the cookie is cleared and the session is gone
        st, r, _j, _ = self.req("POST", "/api/session/logout", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("Max-Age=0", r.getheader("set-cookie"))
        self.assertEqual(self.req("GET", "/api/meta", cookie=cookie)[0], 401)

    def test_admin_actions_refused_for_remote_sessions(self):
        self.phone()
        cookie, _ = self.pair()
        gets = ("/api/settings", "/api/pair/sessions")
        posts = (("/api/settings", {"values": {"ui.language": "en"}}), ("/api/ai/test", {}),
                 ("/api/check", {"all": True}), ("/api/pair/new", {}), ("/api/pair/revoke", {"id": 1}),
                 ("/api/pair/revoke_all", {}))
        for path in gets:
            st, _r, j, _ = self.req("GET", path, cookie=cookie)
            self.assertEqual(st, 403, path)
            self.assertEqual(j["error"], i18n.t("err.loopback_only", "en"))
        for path, body in posts:
            st, *_ = self.req("POST", path, body, cookie=cookie)
            self.assertEqual(st, 403, path)
        st, _r, dev, _ = self.req("GET", "/api/device?mac=aa:bb:cc:00:00:01&lang=en", cookie=cookie)
        self.assertFalse(dev["check_allowed"])
        self.assertEqual(dev["check_note"], i18n.t("app.pair.admin_only", "en"))
        db = store.connect(self.path)
        self.assertEqual(len(pairing.sessions(db)), 1)    # nothing was revoked
        db.close()

    def test_wrong_codes_lock_the_address_out(self):
        self.phone()
        for _ in range(5):
            st, *_ = self.req("POST", "/api/pair", {"code": "WRONG-CODE2"})
            self.assertEqual(st, 400)
        good = self.new_code()
        st, _r, j, _ = self.req("POST", "/api/pair", {"code": good, "lang": "en"})
        self.assertEqual(st, 429)                          # even the right code waits
        self.assertGreater(j["retry_after"], 0)
        self.assertIn("min", j["error"])
        web.Handler.limiter = pairing.Limiter()
        self.pair(good)                                    # the code was not spent

    def test_bad_bodies(self):
        self.phone()
        for body in ({"code": 5}, {"code": ["x"]}):
            st, *_ = self.req("POST", "/api/pair", body)
            self.assertEqual(st, 400)
        st, *_ = self.req("POST", "/api/pair/revoke", {"id": "1"})
        self.assertEqual(st, 401)          # no session at all: refused before the admin check

    def test_codes_and_tokens_never_logged(self):
        self.phone()
        buf = io.StringIO()
        h = logging.StreamHandler(buf)
        logging.getLogger("netwarden").addHandler(h)
        logging.getLogger("netwarden").setLevel(logging.DEBUG)
        try:
            code = self.new_code()
            cookie, _ = self.pair(code)
            self.req("POST", "/api/session/logout", cookie=cookie)
        finally:
            logging.getLogger("netwarden").removeHandler(h)
        out = buf.getvalue()
        self.assertIn("paired a new browser", out)
        self.assertNotIn(code, out)
        self.assertNotIn(cookie.split("=", 1)[1], out)

    # -- this computer: the admin side --------------------------------------------------
    def test_local_admin_pairing_endpoints(self):
        st, _r, j, _ = self.req("POST", "/api/pair/new", {})
        self.assertEqual(st, 200)
        self.assertRegex(j["code"], r"^[A-Z0-9]{5}-[A-Z0-9]{5}$")
        base, frag = j["url"].split("#")
        self.assertEqual(base, f"http://127.0.0.1:{self.port}/pair")   # not in LAN mode
        self.assertEqual(frag, j["code"].replace("-", ""))
        self.assertTrue(j["qr"].startswith("data:image/svg+xml;base64,"))
        self.assertFalse(j["lan"])
        self.phone()
        cookie, _ = self.pair(frag)
        self._restore_local()
        st, _r, s, _ = self.req("GET", "/api/pair/sessions")
        self.assertEqual(st, 200)
        self.assertEqual([x["device"] for x in s["sessions"]], ["iPhone · Safari"])
        self.assertFalse(s["lan_setting"])
        sid = s["sessions"][0]["id"]
        self.assertEqual(self.req("POST", "/api/pair/revoke", {"id": True})[0], 400)
        self.assertEqual(self.req("POST", "/api/pair/revoke", {"id": 999999})[0], 404)
        self.assertEqual(self.req("POST", "/api/pair/revoke", {"id": sid})[0], 200)
        self.phone()
        self.assertEqual(self.req("GET", "/api/meta", cookie=cookie)[0], 401)   # revoked at once
        self._restore_local()
        self.pair()
        st, _r, j, _ = self.req("POST", "/api/pair/revoke_all", {})
        self.assertEqual((st, j["revoked"]), (200, 1))

    def _restore_local(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))

    # -- host / origin rules in both modes -------------------------------------------------
    def test_host_and_origin_rules_with_and_without_lan(self):
        lan = f"192.168.1.13:{self.port}"
        st, *_ = self.req("GET", "/api/meta", host=lan)
        self.assertEqual(st, 421)                         # LAN mode off: only loopback names
        web.Handler.lan_hosts = frozenset({lan})
        web.Handler.lan, web.Handler.lan_url = True, f"http://{lan}"
        self.assertEqual(self.req("GET", "/api/meta", host=lan)[0], 200)
        self.assertEqual(self.req("GET", "/api/meta", host=f"192.168.1.14:{self.port}")[0], 421)
        self.assertEqual(self.req("GET", "/api/meta", host="evil.example")[0], 421)
        self.phone()
        st, *_ = self.req("POST", "/api/pair", {"code": self.new_code()}, host=lan,
                          origin=f"http://{lan}")
        self.assertEqual(st, 200)
        st, *_ = self.req("POST", "/api/pair", {"code": self.new_code()}, host=lan,
                          origin=f"http://192.168.1.14:{self.port}")
        self.assertEqual(st, 403)
        self._restore_local()
        st, _r, j, _ = self.req("POST", "/api/pair/new", {})
        self.assertTrue(j["url"].startswith(f"http://{lan}/pair#"))

    # -- NETWARDEN_REQUIRE_AUTH=1 ----------------------------------------------------------
    def test_require_auth_on_loopback(self):
        web.Handler.require_auth = True
        st, r, _j, _ = self.req("GET", "/")
        self.assertEqual((st, r.getheader("location")), (303, "/pair"))
        self.assertEqual(self.req("GET", "/api/meta")[0], 401)
        self.assertEqual(self.req("POST", "/api/pair/new", {})[0], 401)
        cookie, _ = self.pair()                          # code made with the CLI / store
        st, _r, meta, _ = self.req("GET", "/api/meta", cookie=cookie)
        self.assertEqual((st, meta["remote"], meta["require_auth"], meta["signed_in"]), (200, False, True, True))
        # on this computer, a session may do admin actions too
        self.assertEqual(self.req("POST", "/api/pair/new", {}, cookie=cookie)[0], 200)
        self.assertEqual(self.req("GET", "/api/settings", cookie=cookie)[0], 200)


class MakeServerLanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "s.db")

    def tearDown(self):
        web.Handler.lan, web.Handler.lan_hosts, web.Handler.lan_url = False, frozenset(), ""

    def test_loopback_only_without_lan(self):
        with self.assertRaises(ValueError):
            web.make_server(self.path, 0, {}, host="0.0.0.0")
        with self.assertRaises(web.LanError):
            web.make_server(self.path, 0, {}, lan=True, lan_host="8.8.8.8")
        with self.assertRaises(web.LanError):
            web.make_server(self.path, 0, {}, lan=True, lan_host="127.0.0.1")

    def test_lan_mode_listens_on_a_second_address(self):
        # 127.0.0.2 stands in for the LAN address: never bind a real non-loopback one in tests
        with mock.patch.object(pairing, "is_lan_ip", lambda ip: ip == "127.0.0.2"):
            srv = web.make_server(self.path, 0, {brain.OFFLINE_ENV: "1",
                                                 "NETWARDEN_REQUIRE_AUTH": "1"}, "en",
                                  lan=True, lan_host="127.0.0.2")
        try:
            port = srv.server_address[1]
            self.assertTrue(web.Handler.lan and web.Handler.require_auth)
            self.assertEqual(web.Handler.lan_url, f"http://127.0.0.2:{port}")
            self.assertEqual(web.Handler.lan_hosts, frozenset({f"127.0.0.2:{port}"}))
            [other] = srv.extra
            self.assertEqual(other.server_address, ("127.0.0.2", port))
            c = http.client.HTTPConnection("127.0.0.2", port, timeout=10)
            c.request("GET", "/api/meta")
            self.assertEqual(c.getresponse().status, 401)   # REQUIRE_AUTH: needs a session
            c.close()
            out = "\n".join(web.lan_banner("en"))
            self.assertIn(web.Handler.lan_url, out)
            self.assertIn("python3 -m netwarden pair", out)
        finally:
            web.close_server(srv)
            web.Handler.require_auth = False

    def test_lan_setting(self):
        self.assertFalse(web.lan_wanted(False, self.path, {}))
        self.assertTrue(web.lan_wanted(True, self.path, {}))
        self.assertTrue(web.lan_wanted(False, self.path, {"NETWARDEN_LAN": "1"}))
        db = store.connect(self.path)
        settings.update(db, {}, {"lan.enabled": True})
        db.close()
        self.assertTrue(web.lan_wanted(False, self.path, {}))
        s = settings.REGISTRY["lan.enabled"]
        self.assertTrue(s.admin)
        for raw, want in (("on", True), ("0", False), (True, True), ("false", False)):
            self.assertEqual(s.clean(raw), want)
        for bad in ("maybe", 2.5, None, ["1"]):
            with self.assertRaises(settings.SettingError):
                s.clean(bad)


class PairCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "c.db")

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "_meta", lambda port: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["pair", "--db", self.path, "--lang", "en", *argv])
        return rc, out.getvalue(), err.getvalue()

    def test_pair_prints_url_code_and_a_redeemable_qr(self):
        rc, out, _ = self.run_cli("--local", "--port", "8799")
        self.assertEqual(rc, 0)
        m = re.search(r"http://127\.0\.0\.1:8799/pair#([A-Z0-9]{10})", out)
        self.assertTrue(m, out)
        self.assertIn(m.group(1)[:5] + "-" + m.group(1)[5:], out)
        # 127.0.0.1 is this computer only: no QR code for a phone to scan (Stage V3)
        self.assertNotIn("█", out)
        self.assertIn(i18n.t("cli.pair.local_code", "en", minutes=10)[:30], out)
        db = store.connect(self.path)
        self.assertIsNotNone(pairing.redeem(db, m.group(1), UA_IPHONE))
        db.close()
        rc, out, _ = self.run_cli("--list")
        self.assertIn("iPhone · Safari", out)
        sid = int(re.search(r"#(\d+)", out).group(1))
        self.assertEqual(self.run_cli("--revoke", str(sid))[0], 0)
        self.assertEqual(self.run_cli("--revoke", str(sid))[0], 1)
        rc, out, _ = self.run_cli("--revoke-all")
        self.assertIn("0", out)

    def test_pair_lan_host_and_refusals(self):
        rc, out, _ = self.run_cli("--lan-host", "192.168.1.20")
        self.assertEqual(rc, 0)
        self.assertIn("http://192.168.1.20:8787/pair#", out)
        self.assertIn("█", out)                                  # a QR code for the phone
        rc, _out, err = self.run_cli("--lan-host", "8.8.8.8")
        self.assertEqual(rc, 1)
        self.assertIn(i18n.t("cli.lan.no_address", "en"), err)

    def test_pair_is_a_listed_command(self):
        self.assertIn("pair", cli.COMMANDS)
        self.assertIn("pair", cli.usage("en"))


class DemoSessionsTests(unittest.TestCase):
    def test_demo_phones_display_only_and_revocation_sticks(self):
        from netwarden import demo
        db = store.connect(":memory:")
        demo._seed_sessions(db, T0)
        rows = pairing.sessions(db, now=T0)
        self.assertEqual([r["device"] for r in rows], ["iPhone · Safari", "Android · Chrome"])
        for h in ("demo:1", "demo:2"):     # no cookie can ever hash to these
            self.assertIsNone(pairing.check(db, h, now=T0))
        pairing.revoke(db, rows[1]["id"])
        demo._seed_sessions(db, T0 + timedelta(days=40))   # a later rebuild
        rows = pairing.sessions(db, now=T0 + timedelta(days=40))
        self.assertEqual([r["device"] for r in rows], ["iPhone · Safari"])   # still revoked, still valid


class PageSourceStageM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = web.static_file("app.js")[0].decode()
        cls.pjs = web.static_file("pair.js")[0].decode()
        cls.html = web.static_file("index.html")[0].decode()
        cls.css = web.static_file("app.css")[0].decode()

    def test_pair_js_builds_no_markup_and_keeps_the_code_out_of_urls(self):
        self.assertNotIn("innerHTML", self.pjs)
        self.assertNotIn("insertAdjacentHTML", self.pjs)
        self.assertIn("history.replaceState", self.pjs)
        self.assertIn("JSON.stringify({ code", self.pjs)
        self.assertNotIn("?code", self.pjs)
        self.assertEqual(self.js.count("innerHTML"), 2)      # the dashboard rule still holds

    def test_home_screen_metadata(self):
        # Stage H: __BASE__ = the Home Assistant ingress prefix ("" when served at /)
        self.assertIn('rel="manifest" href="__BASE__/static/manifest.webmanifest"', self.html)
        self.assertIn('rel="apple-touch-icon" href="__BASE__/static/apple-touch-icon.png"', self.html)
        self.assertIn("viewport-fit=cover", self.html)
        man = json.loads(web.static_file("manifest.webmanifest")[0])
        for icon in man["icons"]:
            name = icon["src"].rsplit("/", 1)[-1]   # relative since Stage H
            self.assertIn(name, web.PUBLIC_STATIC)
            body = web.static_file(name)[0]
            if name.endswith(".png"):
                w, h = int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")
                self.assertEqual(f"{w}x{h}", icon["sizes"])

    def test_phone_layout_rules(self):
        for needle in ("safe-area-inset-top", "safe-area-inset-left", "overflow-x: clip",
                       "touch-action: manipulation", "font-size: 16px"):
            self.assertIn(needle, self.css)

    def test_remote_ui_hides_admin_actions(self):
        # Stage X: the AI card lives on the Settings page, which a paired phone sees as
        # "phone access" only (and System links there instead of showing it).
        for needle in ("if (S.meta.remote) return html`${phead(T('app.nav.settings'), T('app.set.sub_remote'))}",
                       "S.meta.remote ? phoneCard() : card({ key: 'tosettings'", "if (S.meta.remote) return;",
                       "needPair(", "location.replace(url('/pair?expired=1'))","/api/pair/new", "/api/session/logout"):
            self.assertIn(needle, self.js)


# the pinned fingerprint (computed once from the pristine upstream encoder)
KNOWN_FP = "519ddcbac7975cd968af832b93c86f2d9810553c745a6fe0e1658e66eef68476"


if __name__ == "__main__":
    unittest.main()
