"""
Round 10 Stage N tests: opt-in push notifications (channels.py + push.py).

Every adapter against a fake HTTP server on an ephemeral 127.0.0.1 port: success, 401,
403, 404, 429 + Retry-After, 5xx, a timeout and a redirect to another host (never
followed); a TLS pin mismatch with a self-signed certificate when `openssl` exists. The
pipeline: priming, dedupe (also across a restart), acked alerts dropped, the rate limit
bundling the excess into ONE message, retries + backoff, quiet hours (hold, release as
one summary, the high-severity security bypass), privacy levels (what must NOT appear),
secrets never in any API / log / export / report / backup, LAN permissions, environment
channels, the CLI and the unchanged `alerts` cron output.

No real network host, no real LLM, no real notification: fake senders and fake servers
on 127.0.0.1 only.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import io
import json
import logging
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from netwarden import (backup, brain, cache, channels, demo, i18n, pairing, push, settings, store,
                       web)
from netwarden import __main__ as cli

ROOT = Path(__file__).resolve().parent.parent
UTC = timezone.utc
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)       # a Wednesday, 12:00 UTC
UA = "Mozilla/5.0 (X11; Linux x86_64)"
_DEMO = {}


def demo_copy(dest: Path) -> Path:
    if "path" not in _DEMO:
        _DEMO["tmp"] = tempfile.TemporaryDirectory()
        _DEMO["path"] = Path(_DEMO["tmp"].name) / "demo.db"
        demo.build(_DEMO["path"])
    src, dst = sqlite3.connect(_DEMO["path"]), sqlite3.connect(dest)
    src.backup(dst)
    src.close()
    dst.close()
    return dest


def tearDownModule():
    if "tmp" in _DEMO:
        _DEMO["tmp"].cleanup()


# --- a fake service ------------------------------------------------------------------------

class FakeService:
    """One HTTP(S) server on 127.0.0.1:0. `mode` decides every answer:
    ok | 401 | 403 | 404 | 429 | 500 | slow | redirect | json:<body>."""

    def __init__(self, cert: tuple | None = None):
        self.mode = "ok"
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):   # quiet
                pass

            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.requests.append({"method": self.command, "path": self.path,
                                       "headers": dict(self.headers), "body": body})
                m = outer.mode
                if m == "slow":
                    time.sleep(1.5)
                    m = "ok"
                if m == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://elsewhere.invalid/x")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if m.startswith("json:"):
                    raw = m[5:].encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                code = 200 if m == "ok" else int(m)
                raw = b'{"ok":true}' if code == 200 else b'{"error":"nope token=SECRETBODY"}'
                self.send_response(code)
                if code == 429:
                    self.send_header("Retry-After", "7")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            do_GET = do_POST = do_PUT = _any

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*cert)
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.base = f"{'https' if cert else 'http'}://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


# one message, and a config per adapter pointing at the fake service
MSG = {"title": "netwarden · Security", "body": "Living room TV <@everyone> *bold* & co",
       "url": "", "sev": 1, "category": "security", "kind": "alert", "lang": "en",
       "level": "standard", "count": 1, "id": "alert:x", "ts": "2026-10-21T12:00:00Z"}
TOKENS = {"ntfy": "tk_ntfy_SECRET_1", "gotify": "AgotifySECRET2", "homeassistant": "ha.SECRET.3",
          "telegram": "123456789:SECRET_telegram_token_abcdef", "line": "lineSECRET4",
          "matrix": "syt_matrix_SECRET5"}


def configs(base: str) -> dict:
    return {
        "ntfy": ({"url": base, "topic": "nw"}, {"token": TOKENS["ntfy"]}),
        "gotify": ({"url": base}, {"token": TOKENS["gotify"]}),
        "homeassistant": ({"url": base, "service": "mobile_app_x"}, {"token": TOKENS["homeassistant"]}),
        "webhook": ({}, {"url": base + "/hook/SECRETPATH", "secret": "hmacSECRET6"}),
        "discord": ({}, {"url": base + "/api/webhooks/1/SECRETdiscord"}),
        "slack": ({}, {"url": base + "/services/T/B/SECRETslack"}),
        "telegram": ({"chat_id": "42"}, {"token": TOKENS["telegram"]}),
        "line": ({"to": "U" + "0" * 32}, {"token": TOKENS["line"]}),
        "matrix": ({"url": base, "room": "!room:example.org"}, {"token": TOKENS["matrix"]}),
    }


class _Hosted:
    """Point the hosted services at a fake server for the duration of a test."""
    def patch_hosted(self, base: str, host: str = "127.0.0.1"):
        for name, value in (("TELEGRAM_API", base), ("LINE_API", base),
                            ("DISCORD_HOSTS", (host,)), ("SLACK_HOSTS", (host,)),
                            ("HOSTED_SCHEMES", ("http", "https"))):
            p = mock.patch.object(channels, name, value)
            p.start()
            self.addCleanup(p.stop)


# --- adapters against the fake server --------------------------------------------------------

class AdapterTests(_Hosted, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeService()

    @classmethod
    def tearDownClass(cls):
        cls.fake.close()

    def setUp(self):
        self.patch_hosted(self.fake.base)
        self.fake.mode = "ok"
        self.fake.requests.clear()

    def send(self, ctype, mode, timeout=3.0):
        self.fake.mode = mode
        cfg, sec = configs(self.fake.base)[ctype]
        return channels.send(channels.build(ctype, cfg, sec, MSG, now=1_700_000_000), timeout)

    def test_every_adapter_every_answer(self):
        want = {"ok": "", "401": "http_401", "403": "http_403", "404": "http_404",
                "429": "http_429", "500": "http_5xx", "redirect": "redirect"}
        for ctype in channels.TYPES:
            for mode, err in want.items():
                with self.subTest(ctype=ctype, mode=mode):
                    res = self.send(ctype, mode)
                    self.assertEqual((res.ok, res.error), (mode == "ok", err))
                    self.assertNotIn("SECRET", repr(res))
                    if mode == "429":
                        self.assertEqual(res.retry_after, 7.0)
                        self.assertTrue(res.retryable)
                    if mode in ("401", "403", "404", "redirect"):
                        self.assertFalse(res.retryable)
            with self.subTest(ctype=ctype, mode="timeout"):
                res = self.send(ctype, "slow", timeout=0.4)
                self.assertEqual((res.ok, res.error, res.retryable), (False, "timeout", True))

    def test_request_shapes(self):
        reqs = {}
        for ctype in channels.TYPES:
            self.fake.requests.clear()
            self.assertTrue(self.send(ctype, "ok").ok, ctype)
            reqs[ctype] = self.fake.requests[-1]
        r = reqs["ntfy"]
        self.assertEqual((r["path"], r["headers"]["Authorization"]), ("/", "Bearer " + TOKENS["ntfy"]))
        j = json.loads(r["body"])
        self.assertEqual((j["topic"], j["priority"], j["tags"]), ("nw", 4, ["warning"]))
        self.assertEqual(reqs["gotify"]["path"], "/message")
        self.assertEqual(reqs["gotify"]["headers"]["X-Gotify-Key"], TOKENS["gotify"])
        self.assertEqual(json.loads(reqs["gotify"]["body"])["priority"], 6)
        self.assertEqual(reqs["homeassistant"]["path"], "/api/services/notify/mobile_app_x")
        self.assertEqual(reqs["telegram"]["path"], f"/bot{TOKENS['telegram']}/sendMessage")
        tg = json.loads(reqs["telegram"]["body"])
        self.assertNotIn("parse_mode", tg)                     # plain text
        self.assertIn("<@everyone>", tg["text"])
        self.assertEqual(reqs["line"]["path"], "/v2/bot/message/push")
        self.assertEqual(json.loads(reqs["line"]["body"])["messages"][0]["type"], "text")
        self.assertEqual(reqs["matrix"]["method"], "PUT")
        self.assertTrue(reqs["matrix"]["path"].startswith("/_matrix/client/v3/rooms/%21room%3Aexample.org/send/"))
        self.assertEqual(json.loads(reqs["matrix"]["body"])["msgtype"], "m.notice")
        # per-service escaping: device names are hostile input
        d = json.loads(reqs["discord"]["body"])
        self.assertEqual(d["allowed_mentions"], {"parse": []})
        self.assertIn("\\<\\@everyone\\>", d["content"])
        self.assertIn("\\*bold\\*", d["content"])
        s = json.loads(reqs["slack"]["body"])
        self.assertIn("&lt;@everyone&gt;", s["text"])
        self.assertIn("&amp; co", s["text"])
        self.assertFalse(s["mrkdwn"])
        for r in reqs.values():
            self.assertTrue(r["headers"]["User-Agent"].startswith("netwarden/"))

    def test_webhook_schema_and_signature(self):
        self.assertTrue(self.send("webhook", "ok").ok)
        r = self.fake.requests[-1]
        self.assertEqual(r["path"], "/hook/SECRETPATH")
        j = json.loads(r["body"])
        self.assertEqual(j["schema"], channels.WEBHOOK_SCHEMA)
        self.assertEqual(set(j), {"schema", "id", "kind", "category", "severity", "title", "body",
                                  "url", "lang", "level", "sent_at", "count"})
        self.assertEqual(j["severity"], "high")
        ts = r["headers"][channels.TIMESTAMP_HEADER]
        want = hmac.new(b"hmacSECRET6", ts.encode() + b"." + r["body"], hashlib.sha256).hexdigest()
        self.assertEqual(r["headers"][channels.SIGNATURE_HEADER], "sha256=" + want)
        self.assertNotIn("hmacSECRET6", json.dumps(r["headers"]) + r["body"].decode())

    def test_preview_masks_every_credential(self):
        for ctype, (cfg, sec) in configs(self.fake.base).items():
            pv = channels.preview(channels.build(ctype, cfg, sec, MSG, now=1))
            text = json.dumps(pv, ensure_ascii=False)
            self.assertNotIn("SECRET", text, ctype)
            self.assertIn(MSG["title"], pv["body"], ctype)

    def test_helpers(self):
        self.fake.mode = 'json:{"ok":true,"result":[{"update_id":1,"message":{"chat":{"id":4242,"type":"private","first_name":"Ann"}}}]}'
        res, chats = channels.telegram_chats(TOKENS["telegram"], 3)
        self.assertTrue(res.ok)
        self.assertEqual(chats, [{"id": "4242", "type": "private", "title": "Ann"}])
        self.fake.mode = 'json:[{"domain":"notify","services":{"mobile_app_a":{},"BAD NAME":{}}},{"domain":"light","services":{"x":{}}}]'
        res, names = channels.ha_services(self.fake.base, "tok", "", 3)
        self.assertEqual((res.ok, names), (True, ["mobile_app_a"]))
        self.fake.mode = 'json:{"no":1}'
        res, names = channels.ha_services(self.fake.base, "tok", "", 3)
        self.assertEqual((res.ok, res.error, names), (False, "bad_answer", []))
        self.fake.mode = "401"
        res, chats = channels.telegram_chats(TOKENS["telegram"], 3)
        self.assertEqual((res.error, chats), ("http_401", []))

    def test_connect_errors_and_limits(self):
        sock = __import__("socket").socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()                      # nothing listens there now
        req = channels.Request("POST", f"http://127.0.0.1:{port}/", {}, b"{}")
        self.assertEqual(channels.send(req, 2).error, "connect")
        big = channels.Request("POST", self.fake.base + "/", {}, b"x" * (channels.MAX_BODY + 1))
        self.assertEqual(channels.send(big, 2).error, "too_large")
        for url in ("ftp://127.0.0.1/", "http://user:pw@127.0.0.1/", "http://127.0.0.1:99999/"):
            self.assertEqual(channels.send(channels.Request("POST", url, {}, b""), 1).error, "config", url)


class TlsPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not installed")
        cls.tmp = tempfile.TemporaryDirectory()
        key, crt = Path(cls.tmp.name) / "k.pem", Path(cls.tmp.name) / "c.pem"
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(crt), "-days", "2", "-subj", "/CN=127.0.0.1"],
                           capture_output=True, timeout=60)
        if r.returncode:
            cls.tmp.cleanup()
            raise unittest.SkipTest("openssl could not make a certificate")
        cls.fake = FakeService((str(crt), str(key)))
        der = ssl.PEM_cert_to_DER_cert(crt.read_text())
        cls.pin = channels.fingerprint(der)

    @classmethod
    def tearDownClass(cls):
        cls.fake.close()
        cls.tmp.cleanup()

    def req(self, pin=""):
        return channels.build("gotify", {"url": self.fake.base, "pin": pin}, {"token": "t0k"}, MSG)

    def test_verification_on_pin_matches_pin_mismatch(self):
        self.fake.requests.clear()
        self.assertEqual(channels.send(self.req(), 3).error, "tls")       # self-signed: refused
        self.assertTrue(channels.send(self.req(self.pin), 3).ok)          # the pinned one
        n = len(self.fake.requests)
        wrong = "0" * 64
        self.assertEqual(channels.send(self.req(wrong), 3).error, "tls_pin")
        time.sleep(0.2)
        self.assertEqual(len(self.fake.requests), n)                      # not a byte of it sent

    def test_clean_pin_formats(self):
        colon = ":".join(self.pin[i:i + 2] for i in range(0, 64, 2)).upper()
        self.assertEqual(channels.clean_pin(colon), self.pin)
        self.assertEqual(channels.clean_pin("sha256/" + self.pin), self.pin)
        with self.assertRaises(channels.BadChannel):
            channels.clean_pin("abc")


# --- validation ------------------------------------------------------------------------------

class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(Path(self.tmp.name) / "v.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def bad(self, payload, code, field=None):
        with self.assertRaises((push.BadPush, channels.BadChannel)) as cm:
            push.validate(self.db, payload)
        self.assertEqual(cm.exception.code, code, payload)
        if field:
            self.assertEqual(cm.exception.field, field)

    def test_rules(self):
        ok = {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20:8080/"},
              "secrets": {"token": "abc"}}
        v = push.validate(self.db, ok)
        self.assertEqual(v["fields"]["url"], "http://192.168.1.20:8080")
        self.bad({**ok, "type": "fax"}, "push_type")
        self.bad({**ok, "name": "  "}, "push_name")
        self.bad({**ok, "fields": {"url": "http://u:p@192.168.1.20"}}, "push_url")
        self.bad({**ok, "fields": {"url": "http://192.168.1.20/?token=x"}}, "push_url")
        self.bad({**ok, "fields": {"url": "file:///etc/passwd"}}, "push_url")
        self.bad({**ok, "secrets": {"token": None}}, "push_required", "token")
        self.bad({**ok, "fields": {"url": "http://192.168.1.20", "pin": "ab" * 32}}, "push_pin_http")
        self.bad({**ok, "fields": {"url": "https://192.168.1.20", "pin": "xyz"}}, "push_pin")
        self.bad({**ok, "extra": 1}, "bad_json")
        self.bad({**ok, "rate": 0}, "push_invalid", "rate")
        self.bad({**ok, "rate": True}, "push_invalid", "rate")
        self.bad({**ok, "categories": ["spam"]}, "push_invalid", "categories")
        self.bad({**ok, "min_sev": 7}, "push_invalid", "min_sev")
        self.bad({**ok, "language": "xx"}, "push_invalid", "language")
        self.bad({"type": "discord", "name": "D", "secrets": {"url": "https://evil.example/api/webhooks/1/x"}},
                 "push_webhook_discord")
        self.bad({"type": "slack", "name": "S", "secrets": {"url": "http://hooks.slack.com/services/x"}}, "push_url")
        self.bad({"type": "telegram", "name": "T", "fields": {"chat_id": "1"}, "secrets": {"token": "nope"}},
                 "push_telegram_token")
        self.bad({"type": "ntfy", "name": "N", "fields": {"url": "https://ntfy.sh", "topic": "a b"}}, "push_invalid")
        self.bad({"type": "ntfy", "name": "N", "fields": {"url": "https://ntfy.sh", "topic": "ab", "user": "u"}},
                 "push_required", "password")

    def test_detailed_to_the_cloud_needs_a_confirmation(self):
        p = {"type": "ntfy", "name": "N", "fields": {"url": "https://ntfy.sh", "topic": "abc"}, "level": "detailed"}
        self.bad(p, "push_confirm_detailed", "level")
        self.assertTrue(push.validate(self.db, {**p, "confirm": True})["confirmed"])
        lan = {**p, "fields": {"url": "http://192.168.1.20", "topic": "abc"}}
        self.assertFalse(push.validate(self.db, lan)["confirmed"])      # private host: no question
        self.assertEqual(channels.destination("telegram", {}, {}), "cloud")

    def test_secrets_are_write_only(self):
        cid = push.save(self.db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                     "secrets": {"token": "keepme"}})
        push.save(self.db, {}, {"id": cid, "name": "G2"})              # left out: kept
        self.assertEqual(push.get(self.db, {}, cid)["secrets"], {"token": "keepme"})
        push.save(self.db, {}, {"id": cid, "name": "G2", "secrets": {"token": "new"}})
        self.assertEqual(push.get(self.db, {}, cid)["secrets"], {"token": "new"})
        with self.assertRaises(channels.BadChannel):                   # required: cannot clear
            push.save(self.db, {}, {"id": cid, "name": "G2", "secrets": {"token": None}})
        nid = push.save(self.db, {}, {"type": "ntfy", "name": "N", "fields": {"url": "https://ntfy.sh",
                                                                               "topic": "abc"},
                                     "secrets": {"token": "opt"}})
        push.save(self.db, {}, {"id": nid, "name": "N", "secrets": {"token": None}})   # optional: cleared
        self.assertEqual(push.get(self.db, {}, nid)["secrets"], {})
        pub = push.public(self.db, push.get(self.db, {}, cid), "en")
        self.assertEqual(pub["secrets"], {"token": True})
        self.assertNotIn("new", json.dumps(pub))
        self.assertFalse(push.get(self.db, {}, cid)["enabled"])        # a new channel starts paused
        with self.assertRaises(push.BadPush) as cm:
            push.save(self.db, {}, {"type": "gotify", "name": "G2", "fields": {"url": "http://192.168.1.20"},
                                    "secrets": {"token": "x"}})
        self.assertEqual(cm.exception.code, "push_name_taken")


# --- the pipeline ----------------------------------------------------------------------------

def ev(key, akind="new", sev=3, mac="aa:bb:cc:00:00:01", name="Tablet", detail=None, ip="192.168.1.30"):
    return {"kind": "alert", "akind": akind, "key": "alert:" + key, "category": push.CATEGORY_OF[akind],
            "sev": sev, "critical": sev == 0, "mac": mac, "name": name, "detail": detail, "ip": ip}


class FakeSender:
    def __init__(self):
        self.reqs, self.results = [], []

    def __call__(self, req, timeout):
        self.reqs.append(req)
        return self.results.pop(0) if self.results else channels.Result(True, "", 200)

    def bodies(self):
        return [json.loads(r.body) for r in self.reqs]


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "p.db"
        self.db = store.connect(self.path)
        self.evs = []
        p = mock.patch.object(push, "_alert_events", lambda db: list(self.evs))
        p.start()
        self.addCleanup(p.stop)
        self.sender = FakeSender()
        cache.clear()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def channel(self, **opts) -> int:
        cid = push.save(self.db, {}, {"type": "gotify", "name": opts.pop("name", "G"),
                                      "fields": {"url": "http://192.168.1.20"}, "secrets": {"token": "tok"},
                                      "language": "en", **opts})
        push.set_enabled(self.db, {}, cid, True)
        return cid

    def collect(self, now=NOW):
        return push.collect(self.db, {}, now=now, tz=UTC)

    def deliver(self, now=NOW):
        return push.deliver(self.db, {}, now=now, sender=self.sender, tz=UTC)

    def states(self, cid):
        return {r["key"]: r["state"] for r in self.db.execute(
            "SELECT key, state FROM push_outbox WHERE channel_id = ?", (cid,))}

    def test_prime_then_only_news_and_dedupe_across_restart(self):
        self.evs = [ev("old")]
        cid = self.channel()
        self.assertEqual(self.collect(), 0)                     # primed: "old" is not news
        self.assertEqual(self.states(cid)["alert:old"], "skipped")
        self.evs.append(ev("n1"))
        self.assertEqual(self.collect(), 1)
        self.assertEqual(self.collect(), 0)                     # same event: no second row
        self.assertEqual(self.deliver(), 1)
        self.assertEqual(len(self.sender.reqs), 1)
        # a restart: new connection, same file -> nothing goes out twice
        self.db.close()
        self.db = store.connect(self.path)
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.deliver(), 0)
        self.assertEqual(len(self.sender.reqs), 1)
        log = push.history(self.db, {}, cid, "en")
        self.assertEqual([(r["kind"], r["ok"]) for r in log], [("alert", True)])

    def test_acked_meanwhile_is_dropped_and_paused_drops_the_queue(self):
        cid = self.channel()
        self.collect()
        self.evs = [ev("a"), ev("b")]
        self.collect()
        self.evs = [ev("b")]                                    # "a" acked / muted meanwhile
        self.collect()
        self.assertEqual(self.states(cid)["alert:a"], "dropped")
        push.set_enabled(self.db, {}, cid, False)
        self.assertEqual(self.states(cid)["alert:b"], "dropped")
        self.assertEqual(self.deliver(), 0)
        push.set_enabled(self.db, {}, cid, True)                # resumed: re-primed
        self.evs = [ev("b"), ev("c")]
        self.assertEqual(self.collect(), 0)
        self.assertEqual(self.deliver(), 0)

    def test_filters_categories_and_min_severity(self):
        cid = self.channel(categories=["security"], min_sev=1)
        self.collect()
        self.evs = [ev("dev"), ev("thr-low", "threat", 2), ev("thr-hi", "threat", 1, detail="bad.example")]
        self.assertEqual(self.collect(), 1)
        self.assertEqual(set(k for k, s in self.states(cid).items() if s == "queued"), {"alert:thr-hi"})

    def test_rate_limit_bundles_the_excess_into_one_message(self):
        cid = self.channel(rate=3)
        self.collect()
        self.evs = [ev(f"e{i}", name=f"Dev {i}") for i in range(6)]
        self.collect()
        self.assertEqual(self.deliver(), 3)                     # 2 alone + 1 bundle of 4
        kinds = [r["kind"] for r in push.history(self.db, {}, cid, "en")]
        self.assertEqual(sorted(kinds), ["alert", "alert", "bundle"])
        bundle = [b for b in self.sender.bodies() if b["title"].startswith("netwarden · 4 more")]
        self.assertEqual(len(bundle), 1)
        self.assertEqual(bundle[0]["message"].count("•"), 4)
        self.evs.append(ev("e6"))
        self.collect()
        self.assertEqual(self.deliver(), 0)                     # the hour is used up
        self.assertEqual(self.deliver(NOW + timedelta(minutes=61)), 1)

    def test_retries_backoff_retry_after_and_give_up(self):
        cid = self.channel()
        self.collect()
        self.evs = [ev("r")]
        self.collect()
        self.sender.results = [channels.Result(False, "http_429", 429, retry_after=900)]
        self.assertEqual(self.deliver(), 0)
        row = self.db.execute("SELECT * FROM push_outbox WHERE key = 'alert:r'").fetchone()
        self.assertEqual((row["state"], row["attempts"]), ("queued", 1))
        self.assertGreaterEqual(row["next_at"], push._iso(NOW + timedelta(seconds=899)))
        self.assertEqual(self.deliver(NOW + timedelta(seconds=60)), 0)    # not due yet
        self.assertEqual(len(self.sender.reqs), 1)
        t = NOW
        for _ in range(3):
            t += timedelta(hours=2)
            self.sender.results = [channels.Result(False, "timeout")]
            self.deliver(t)
        row = self.db.execute("SELECT * FROM push_outbox WHERE key = 'alert:r'").fetchone()
        self.assertEqual((row["state"], row["attempts"]), ("failed", push.MAX_ATTEMPTS))
        self.assertEqual(len(self.sender.reqs), push.MAX_ATTEMPTS)        # 1 + 3 retries
        ch = push.public(self.db, push.get(self.db, {}, cid), "en")
        self.assertEqual(ch["last_error"], "timeout")
        self.assertEqual(ch["error_text"], i18n.t("push.err.timeout", "en"))

    def test_a_wrong_channel_fails_at_once(self):
        self.channel()
        self.collect()
        self.evs = [ev("x"), ev("y")]
        self.collect()
        self.sender.results = [channels.Result(False, "http_401", 401)]
        self.deliver()
        self.assertEqual(len(self.sender.reqs), 1)                        # the rest waits
        st = {r["key"]: (r["state"], r["attempts"]) for r in self.db.execute("SELECT * FROM push_outbox")}
        self.assertIn(("failed", 1), st.values())

    def quiet_on(self):
        store.put_settings(self.db, {"quiet.enabled": "true", "quiet.start": '"23:00"', "quiet.end": '"07:00"'})

    def test_quiet_hours_hold_release_as_one_summary_and_bypass(self):
        self.quiet_on()
        night = datetime(2026, 10, 21, 23, 30, tzinfo=UTC)
        cid = self.channel()
        self.collect(night)
        self.evs = [ev("q1"), ev("q2", "outage", 2, mac="network", name=None, detail="isp"),
                    ev("thr", "threat", 0, detail="evil.example")]
        self.collect(night)
        st = self.states(cid)
        self.assertEqual((st["alert:q1"], st["alert:q2"], st["alert:thr"]), ("held", "held", "queued"))
        self.assertEqual(self.deliver(night), 1)                         # the critical one only
        self.collect(night + timedelta(hours=3))
        self.assertEqual(self.deliver(night + timedelta(hours=3)), 0)     # still quiet
        morning = datetime(2026, 10, 22, 7, 5, tzinfo=UTC)
        self.collect(morning)
        self.assertEqual(self.deliver(morning), 1)                        # ONE summary
        last = self.sender.bodies()[-1]
        self.assertTrue(last["title"].startswith("netwarden · While you were asleep (2)"))
        self.assertEqual(last["message"].count("•"), 2)
        self.collect(morning + timedelta(minutes=5))
        self.assertEqual(self.deliver(morning + timedelta(minutes=5)), 0)  # exactly once

    def test_no_bypass_when_switched_off(self):
        self.quiet_on()
        night = datetime(2026, 10, 21, 23, 30, tzinfo=UTC)
        cid = self.channel(quiet_bypass=False)
        self.collect(night)
        self.evs = [ev("thr", "threat", 0, detail="evil.example")]
        self.collect(night)
        self.assertEqual(self.states(cid)["alert:thr"], "held")

    def test_digests_and_score_drop(self):
        cid = self.channel(categories=["score", "digest"], daily=True)
        store.put_settings(self.db, {"push.weekly_day": '"2"'})           # Wednesday = NOW
        early = NOW.replace(hour=7)
        self.collect(early)                                               # primes (nothing yet)
        self.collect(NOW)                                                 # 12:00 >= 08:00
        st = self.states(cid)
        self.assertEqual(st.get("daily:2026-10-21"), "queued")
        self.assertEqual(st.get("weekly:2026-W43"), "queued")
        self.assertEqual(self.deliver(), 2)
        titles = sorted(b["title"] for b in self.sender.bodies())
        self.assertEqual(titles, ["netwarden · Today's summary", "netwarden · Your week at home"])
        self.collect(NOW + timedelta(hours=1))
        self.assertEqual(self.deliver(NOW + timedelta(hours=1)), 0)       # once a day / week
        n = push.enqueue_digest(self.db, {}, "weekly", NOW)
        self.assertEqual(n, 1)

    def test_demo_db_never_collects_delivers_or_tests(self):
        path = demo_copy(Path(self.tmp.name) / "d.db")
        db = store.connect(path)
        try:
            ids = [c["id"] for c in push.all_channels(db, {})]
            self.assertEqual(len(ids), 2)                                 # the seeded examples
            for c in push.all_channels(db, {}):
                self.assertFalse(c["enabled"])
                self.assertTrue(channels.endpoint(c["type"], c["fields"], c["secrets"]).split("/")[2]
                                .split(":")[0].endswith(".invalid"))
            push.set_enabled(db, {}, ids[0], True)
            self.assertEqual(push.collect(db, {}), 0)
            self.assertEqual(push.deliver(db, {}, sender=self.sender), 0)
            with self.assertRaises(push.BadPush):
                push.test(db, {}, ids[0], sender=self.sender)
            self.assertEqual(self.sender.reqs, [])
            self.assertTrue(push.history(db, {}, ids[0], "en"))           # synthetic delivery log
        finally:
            db.close()


class RealAlertsTests(unittest.TestCase):
    """The demo home's real alerts through the pipeline (the demo flag lifted on a copy)."""
    def test_alert_events_map_to_categories_and_render_plainly(self):
        with tempfile.TemporaryDirectory() as t:
            path = demo_copy(Path(t) / "r.db")
            db = store.connect(path)
            try:
                store.set_meta(db, "demo", "0")
                evs = push._alert_events(db)
                self.assertTrue(evs)
                self.assertTrue({e["category"] for e in evs} <= set(push.CATEGORIES))
                cid = push.save(db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                         "secrets": {"token": "tok"}, "categories": list(push.CATEGORIES)})
                push.set_enabled(db, {}, cid, True)
                push.collect(db, {}, now=NOW, tz=UTC)
                skipped = db.execute("SELECT COUNT(*) FROM push_outbox WHERE state = 'skipped'").fetchone()[0]
                self.assertGreaterEqual(skipped, len(evs))
                ch = push.get(db, {}, cid)
                macs = [r["mac"] for r in db.execute("SELECT mac FROM devices")]
                ips = [r["ip"] for r in db.execute("SELECT ip FROM devices") if r["ip"]]
                for e in evs:
                    for level in ("minimal", "standard"):
                        msg = push.render(db, {}, {**ch, "level": level, "lang": "en"}, e, UTC, NOW)
                        text = msg["title"] + msg["body"] + msg["url"]
                        for x in macs + ips:
                            self.assertNotIn(x, text, (level, e["akind"]))
            finally:
                db.close()


# --- privacy levels ---------------------------------------------------------------------------

class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(Path(self.tmp.name) / "pr.db")
        store.put_settings(self.db, {"lan.advertised_url": '"http://192.168.1.5:8787"'})
        self.ch = {"id": 1, "name": "x", "type": "gotify", "fields": {}, "secrets": {}, "lang": "en",
                   "level": "standard", "categories": list(push.CATEGORIES), "min_sev": 3,
                   "quiet_bypass": True, "rate": 10, "daily": False}

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def render(self, level, e):
        m = push.render(self.db, {}, {**self.ch, "level": level}, e, UTC, NOW)
        return m["title"] + "\n" + m["body"] + "\n" + m["url"]

    def test_what_each_level_may_say(self):
        hostile = ev("t", "threat", 0, mac="aa:bb:cc:dd:ee:01", name="Cam 192.168.1.99 aa:bb:cc:dd:ee:02",
                     detail="evil-tracker.example", ip="192.168.1.77")
        mini = self.render("minimal", hostile)
        std = self.render("standard", hostile)
        det = self.render("detailed", hostile)
        for text in (mini, std):
            for x in ("192.168.1.99", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", "192.168.1.77",
                      "evil-tracker.example", "/#/device/"):
                self.assertNotIn(x, text)
        self.assertNotIn("Cam", mini)                                     # minimal: no names
        self.assertIn("Cam", std)
        self.assertIn(i18n.t("sev.malicious", "en"), std)
        for x in ("evil-tracker.example", "192.168.1.77", "aa:bb:cc:dd:ee:01", "/#/device/aa:bb:cc:dd:ee:01"):
            self.assertIn(x, det)
        self.assertIn("http://192.168.1.5:8787/#/inbox", std)              # link: advertised URL only
        store.put_settings(self.db, {"lan.advertised_url": '""'})
        self.assertNotIn("http", self.render("standard", hostile))

    def test_the_message_id_never_carries_an_address_below_detailed(self):
        e = ev("new:aa:bb:cc:dd:ee:01", mac="aa:bb:cc:dd:ee:01")
        for level in ("minimal", "standard"):
            m = push.render(self.db, {}, {**self.ch, "level": level}, e, UTC, NOW)
            self.assertNotIn("aa:bb", m["id"])
            self.assertEqual(m["id"], push.render(self.db, {}, {**self.ch, "level": level}, e, UTC, NOW)["id"])
            body = channels.build("webhook", {}, {"url": "http://192.168.1.2/h"}, m).body.decode()
            self.assertNotIn("aa:bb:cc:dd:ee:01", body)
        self.assertIn("aa:bb", push.render(self.db, {}, {**self.ch, "level": "detailed"}, e, UTC, NOW)["id"])

    def test_ipv6_is_scrubbed_too(self):
        self.assertNotIn("fe80::1", push.scrub("name fe80::1:2:3 x"))
        self.assertEqual(push.scrub("v2.1.3 build"), "v2.1.3 build")

    def test_languages(self):
        e = ev("n", "new", name="Tablet")
        for lang in i18n.CODES:
            m = push.render(self.db, {}, {**self.ch, "lang": lang}, e, UTC, NOW)
            self.assertIn("Tablet", m["body"], lang)
            self.assertEqual(m["lang"], lang)
        store.put_settings(self.db, {"ui.language": '"ja"'})
        self.assertEqual(push.render(self.db, {}, {**self.ch, "lang": ""}, e, UTC, NOW)["lang"], "ja")


# --- environment channels --------------------------------------------------------------------

ENV = {"NETWARDEN_NOTIFY_1_TYPE": "ntfy", "NETWARDEN_NOTIFY_1_URL": "https://ntfy.example.org",
       "NETWARDEN_NOTIFY_1_TOPIC": "home", "NETWARDEN_NOTIFY_1_TOKEN": "envSECRETtoken",
       "NETWARDEN_NOTIFY_1_NAME": "Phone", "NETWARDEN_NOTIFY_1_CATEGORIES": "security,health",
       "NETWARDEN_NOTIFY_1_MIN_SEVERITY": "high", "NETWARDEN_NOTIFY_2_TYPE": "fax"}


class EnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(Path(self.tmp.name) / "e.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_env_channel_is_read_only_and_keeps_its_secret_out_of_the_db(self):
        with self.assertLogs("netwarden.push", "WARNING") as logs:
            push._env_warned.clear()
            chans = push.all_channels(self.db, ENV)
        self.assertNotIn("fax", "".join(logs.output))
        self.assertEqual(len(chans), 1)
        c = chans[0]
        self.assertEqual((c["name"], c["source"], c["enabled"], c["min_sev"]), ("Phone", "env", True, 1))
        self.assertEqual(c["categories"], ["security", "health"])
        self.assertEqual(c["secrets"], {"token": "envSECRETtoken"})
        raw = self.db.execute("SELECT config, secrets FROM push_channels").fetchone()
        self.assertNotIn("envSECRETtoken", raw["config"] + raw["secrets"])
        pub = push.public(self.db, c, "en")
        self.assertEqual((pub["editable"], pub["env_slot"], pub["secrets"]), (False, 1, {"token": True, "password": False}))
        for call in (lambda: push.save(self.db, ENV, {"id": c["id"], "name": "x"}),
                     lambda: push.set_enabled(self.db, ENV, c["id"], False),
                     lambda: push.delete(self.db, ENV, c["id"])):
            with self.assertRaises(push.BadPush) as cm:
                call()
            self.assertEqual(cm.exception.code, "push_env")
        self.assertEqual(push.all_channels(self.db, {}), [])               # removed from env -> gone


# --- web: API, permissions, secrets ----------------------------------------------------------

SECRETS = ("tk_ntfy_SECRET_web", "hookSECRETpath", "hmacSECRETweb", "envSECRETtoken")


class WebTests(_Hosted, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = str(Path(cls.tmp.name) / "w.db")
        store.connect(cls.path).close()
        cls.fake = FakeService()
        cls.env = {brain.OFFLINE_ENV: "1", **ENV}
        cls.srv = web.make_server(cls.path, 0, cls.env, "en")
        cls.port = cls.srv.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        web.close_server(cls.srv)
        cls.fake.close()
        cls.tmp.cleanup()
        cache.clear()

    def setUp(self):
        self.addCleanup(self._restore)
        self.patch_hosted(self.fake.base)

    def _restore(self):
        web.Handler.is_local_client = staticmethod(lambda ip: web.is_loopback(ip))
        web.Handler.require_auth = False

    def req(self, method, path, body=None, cookie=None, raw=False):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = {"user-agent": UA}
        if cookie:
            h["cookie"] = cookie
        if method == "POST":
            h["content-type"] = "application/json"
            h["origin"] = self.origin
        c.request(method, path, json.dumps(body or {}) if method == "POST" else None, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        if raw:
            return r.status, data.decode("utf-8", "replace")
        try:
            return r.status, json.loads(data)
        except ValueError:
            return r.status, None

    def save(self, body):
        st, j = self.req("POST", "/api/channels/save", body)
        self.assertEqual(st, 200, j)
        return j["id"]

    def test_ha_services_never_sends_the_saved_token_to_another_host(self):
        # (review fix) the payload's URL used to override the saved one, token included
        cid = self.save({"type": "homeassistant", "name": "HA review", "fields": {
            "url": self.fake.base, "service": "mobile_app_x"}, "secrets": {"token": "haSECRETreview"}})
        self.addCleanup(lambda: self.req("POST", "/api/channels/delete", {"id": cid}))
        self.fake.requests.clear()
        st, j = self.req("POST", "/api/channels/ha_services",
                         {"id": cid, "fields": {"url": "http://127.0.0.2:9"}})
        self.assertEqual((st, j["code"], j["field"]), (400, "push_reenter", "token"))
        self.assertEqual(j["error"], i18n.t("err.push_reenter", "en"))
        st, j = self.req("POST", "/api/channels/save", {"id": cid, "name": "HA review",
                                                         "fields": {"url": "http://127.0.0.2:9"}})
        self.assertEqual((st, j["code"]), (400, "push_reenter"))
        self.assertEqual(self.fake.requests, [])
        self.fake.mode = 'json:[{"domain":"notify","services":{"mobile_app_a":{}}}]'
        self.addCleanup(setattr, self.fake, "mode", "ok")
        st, j = self.req("POST", "/api/channels/ha_services", {"id": cid})   # its own host: fine
        self.assertEqual(st, 200, j)
        self.assertEqual(self.fake.requests[-1]["headers"]["Authorization"], "Bearer haSECRETreview")

    def test_flow_and_no_secret_anywhere(self):
        logs = io.StringIO()
        handler = logging.StreamHandler(logs)
        handler.setLevel(logging.DEBUG)
        root = logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(lambda: (root.removeHandler(handler), root.setLevel(old)))
        a = self.save({"type": "ntfy", "name": "Phone ntfy", "fields": {"url": self.fake.base, "topic": "nw"},
                       "secrets": {"token": SECRETS[0]}, "lang": "zh-Hant"})
        b = self.save({"type": "webhook", "name": "Hook", "secrets": {"url": self.fake.base + "/h/" + SECRETS[1],
                                                                       "secret": SECRETS[2]}})
        st, d = self.req("GET", "/api/channels?lang=zh-Hant")
        self.assertEqual(st, 200)
        names = {c["name"]: c for c in d["channels"]}
        self.assertEqual(set(names), {"Phone ntfy", "Hook", "Phone"})
        self.assertFalse(names["Hook"]["enabled"])
        self.assertEqual(names["Hook"]["endpoint"], self.fake.base)       # scheme + host only
        self.assertEqual(names["Hook"]["secrets"], {"url": True, "secret": True})
        self.assertEqual(names["Phone"]["source"], "env")
        self.assertEqual(len(d["types"]), len(channels.TYPES))
        # the preview: the exact request, credentials masked; a draft never needs saving
        st, pv = self.req("POST", "/api/channels/preview", {"channel": {"id": b}, "sample": "test"})
        self.assertEqual(st, 200, pv)
        self.assertEqual(pv["request"]["url"], self.fake.base + "/" + channels.MASK)
        self.assertIn(channels.WEBHOOK_SCHEMA, pv["request"]["body"])
        st, pv2 = self.req("POST", "/api/channels/preview", {"channel": {"type": "telegram", "name": "t",
                                                                          "fields": {}, "secrets": {}}})
        self.assertEqual(st, 200, pv2)                                    # incomplete draft: placeholders
        n_before = len(self.fake.requests)
        # a test message (explicit click), then the log
        self.fake.mode = "ok"
        st, t = self.req("POST", "/api/channels/test", {"id": a})
        self.assertEqual((st, t["ok"]), (200, True))
        self.fake.mode = "401"
        st, t = self.req("POST", "/api/channels/test", {"id": b})
        self.assertEqual((st, t["ok"], t["error"]), (200, False, "http_401"))
        self.assertEqual(t["error_text"], i18n.t("push.err.http_401", "en"))
        self.assertEqual(len(self.fake.requests), n_before + 2)
        self.fake.mode = "ok"
        st, lg = self.req("GET", f"/api/channels/log?id={b}")
        self.assertEqual([(r["kind"], r["ok"], r["error"]) for r in lg["log"]], [("test", False, "http_401")])
        self.assertEqual(self.req("GET", "/api/channels/log?id=999")[0], 404)
        self.assertEqual(self.req("POST", "/api/channels/enable", {"id": a, "enabled": True})[0], 200)
        # grep every output for every secret
        outs = [json.dumps(d), json.dumps(pv), json.dumps(pv2), json.dumps(lg)]
        for path in ("/api/channels", "/api/meta", "/api/settings", "/api/overview", "/api/export/devices.csv",
                     "/api/export/report.md", "/api/report?privacy=full", "/api/report?privacy=full&format=md",
                     "/api/backup", "/api/status", "/api/inbox", f"/api/channels/log?id={a}"):
            st, body = self.req("GET", path, raw=True)
            self.assertIn(st, (200,), path)
            outs.append(body)
        db = store.connect(self.path)
        try:
            outs.append(backup.dumps(backup.export(db)).decode())
            stored = db.execute("SELECT group_concat(secrets) FROM push_channels").fetchone()[0]
        finally:
            db.close()
        self.assertIn(SECRETS[0], stored)                                 # kept (write-only) ...
        logfile = logs.getvalue()
        self.assertIn("ntfy", logfile)
        for text in outs + [logfile]:
            for s in SECRETS:
                self.assertNotIn(s, text)                                 # ... and shown nowhere
        self.assertNotIn("SECRETBODY", logfile)                           # nor a service's answer
        # delete
        self.assertEqual(self.req("POST", "/api/channels/delete", {"id": b})[0], 200)
        self.assertEqual(self.req("POST", "/api/channels/delete", {"id": b})[0], 400)

    def test_validation_errors_are_localized_400s(self):
        for body, code in (({"type": "nope", "name": "x"}, "push_type"),
                           ({"type": "gotify", "name": "x", "fields": {"url": "http://a:b@h"}}, "push_url"),
                           ({"type": "gotify", "name": "x", "fields": {"url": "http://h"},
                             "secrets": {"token": "t"}, "rate": 1000}, "push_invalid"),
                           ({"id": "1", "name": "x"}, "push_unknown")):
            st, j = self.req("POST", "/api/channels/save?lang=zh-Hant", body)
            self.assertEqual((st, j["code"]), (400, code), body)
            self.assertTrue(j["error"])
        st, j = self.req("POST", "/api/channels/preview", {"channel": {"type": "gotify"}, "sample": "bogus"})
        self.assertEqual(st, 400)
        env_id = next(c["id"] for c in self.req("GET", "/api/channels")[1]["channels"] if c["source"] == "env")
        st, j = self.req("POST", "/api/channels/save", {"id": env_id, "name": "x"})
        self.assertEqual((st, j["code"]), (400, "push_env"))

    def test_helpers_via_the_api(self):
        self.fake.mode = 'json:{"ok":true,"result":[{"message":{"chat":{"id":-100,"type":"group","title":"Fam"}}}]}'
        st, j = self.req("POST", "/api/channels/telegram", {"secrets": {"token": TOKENS["telegram"]}})
        self.assertEqual((st, j["ok"], j["chats"][0]["id"]), (200, True, "-100"))
        self.fake.mode = 'json:[{"domain":"notify","services":{"mobile_app_p":{}}}]'
        st, j = self.req("POST", "/api/channels/ha_services", {"fields": {"url": self.fake.base},
                                                                "secrets": {"token": "x"}})
        self.assertEqual((st, j["services"]), (200, ["mobile_app_p"]))
        self.fake.mode = "ok"
        st, j = self.req("POST", "/api/channels/telegram", {"secrets": {"token": "bad"}})
        self.assertEqual((st, j["code"]), (400, "push_telegram_token"))

    def pair(self, admin=False) -> str:
        web.Handler.is_local_client = staticmethod(lambda ip: False)
        web.Handler.require_auth = True
        db = store.connect(self.path)
        code = pairing.new_code(db, admin=admin)["code"] if admin else pairing.new_code(db)["code"]
        db.close()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("POST", "/api/pair", json.dumps({"code": code}),
                  {"content-type": "application/json", "origin": self.origin, "user-agent": UA})
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 200)
        return (r.getheader("set-cookie") or "").split(";")[0]

    def test_lan_viewers_see_nothing_about_channels(self):
        cookie = self.pair()
        for path in web.PUSH_GETS:
            self.assertEqual(self.req("GET", path + "?id=1", cookie=cookie)[0], 403, path)
        for path in web.PUSH_POSTS:
            self.assertEqual(self.req("POST", path, {"id": 1}, cookie=cookie)[0], 403, path)
        st, meta = self.req("GET", "/api/meta", cookie=cookie)
        self.assertTrue(meta["remote"])
        web.Handler.require_auth = True
        self.assertEqual(self.req("GET", "/api/channels")[0], 401)       # not signed in at all
        self._restore()
        db = store.connect(self.path)
        pairing.revoke_all(db)
        db.close()


class DemoWebTests(unittest.TestCase):
    """Its own class: make_server configures web.Handler for the whole process."""
    def test_demo_db_refuses_sends(self):
        with tempfile.TemporaryDirectory() as t:
            path = demo_copy(Path(t) / "d.db")
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                def post(p, body):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
                    c.request("POST", p, json.dumps(body), {"content-type": "application/json",
                                                            "origin": f"http://127.0.0.1:{port}"})
                    r = c.getresponse()
                    data = json.loads(r.read())
                    c.close()
                    return r.status, data
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
                c.request("GET", "/api/channels")
                d = json.loads(c.getresponse().read())
                c.close()
                self.assertTrue(d["demo"])
                cid = d["channels"][0]["id"]
                self.assertNotIn("demo-not-a-real-token", json.dumps(d))
                st, j = post("/api/channels/test", {"id": cid})
                self.assertEqual((st, j.get("demo")), (409, True))
                st, _j = post("/api/channels/preview", {"channel": {"id": cid}})
                self.assertEqual(st, 200)
            finally:
                srv.shutdown()
                web.close_server(srv)


# --- persistence, prune, settings, CLI, the alerts cron ---------------------------------------

class MiscTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "m.db"
        self.db = store.connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_settings_registered_and_validated(self):
        self.assertEqual(settings.get(self.db, {}, "push.digest_time"), "08:00")
        self.assertEqual(settings.get(self.db, {"NETWARDEN_NOTIFY_DIGEST_TIME": "21:30"}, "push.digest_time"),
                         "21:30")
        self.assertIn("push", [s[0] for s in settings.SECTIONS])
        for k in ("push.digest_time", "push.weekly_day"):
            self.assertTrue(settings.REGISTRY[k].admin, k)

    def test_backup_never_holds_channels(self):
        push.save(self.db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                "secrets": {"token": "bkSECRET"}})
        doc = backup.export(self.db)
        self.assertNotIn("bkSECRET", json.dumps(doc))
        self.assertNotIn("push", json.dumps(list(doc)))

    def test_prune_keeps_channels_drops_old_rows(self):
        cid = push.save(self.db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                      "secrets": {"token": "t"}})
        old = "2020-01-01T00:00:00.000000Z"
        with self.db:
            self.db.execute("INSERT INTO push_log (channel_id, ts, kind, ok) VALUES (?, ?, 'test', 1)", (cid, old))
            self.db.execute("INSERT INTO push_outbox (channel_id, key, kind, category, state, created_at) "
                            "VALUES (?, 'k', 'alert', 'devices', 'sent', ?)", (cid, old))
            self.db.execute("INSERT INTO push_outbox (channel_id, key, kind, category, state, created_at) "
                            "VALUES (?, 'q', 'alert', 'devices', 'queued', ?)", (cid, old))
        store.prune(self.db, days=30)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM push_log").fetchone()[0], 0)
        self.assertEqual([r[0] for r in self.db.execute("SELECT key FROM push_outbox")], ["q"])
        self.assertEqual(len(push.all_channels(self.db, {})), 1)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(brain, "load_env", lambda *a, **k: {}), redirect_stdout(out), redirect_stderr(err):
            code = cli.cmd_notify([*argv, "--db", str(self.path), "--lang", "en"])
        return code, out.getvalue(), err.getvalue()

    def test_cli(self):
        code, out, _ = self.run_cli("list")
        self.assertEqual((code, out.strip()), (0, i18n.t("cli.notify.none", "en")))
        push.save(self.db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                "secrets": {"token": "cliSECRET"}})
        code, out, _ = self.run_cli("list")
        self.assertIn("G  [Gotify]  paused", out)
        self.assertIn("http://192.168.1.20", out)
        self.assertNotIn("cliSECRET", out)
        code, _out, err = self.run_cli("test", "nope")
        self.assertEqual(code, 1)
        self.assertIn("nope", err)
        with mock.patch.object(channels, "send", lambda req, t: channels.Result(False, "connect")):
            code, _out, err = self.run_cli("test", "G")
        self.assertEqual(code, 1)
        self.assertIn(i18n.t("push.err.connect", "en"), err)
        code, out, _ = self.run_cli("send-digest")
        self.assertEqual((code, out.strip()), (0, i18n.t("cli.notify.no_digest_channel", "en")))

    def test_alerts_cron_never_sends_and_keeps_its_output(self):
        path = demo_copy(Path(self.tmp.name) / "a.db")
        from netwarden import alerts

        def run():
            out = io.StringIO()
            with redirect_stdout(out):
                alerts.main(["--db", str(path)])
            return out.getvalue()
        db = store.connect(path)
        before = run()
        store.set_meta(db, "demo", "0")       # even a real home with an enabled channel ...
        cid = push.all_channels(db, {})[0]["id"]
        push.set_enabled(db, {}, cid, True)
        db.close()
        with mock.patch.object(channels, "send", side_effect=AssertionError("sent")):
            after = run()
        db = store.connect(path)
        store.set_meta(db, "demo", "1")
        db.close()
        self.assertTrue(before.strip())
        self.assertEqual(len(before.splitlines()), len(after.splitlines()))

    def test_static_demo_builder_knows_the_channels_page(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("bsd", ROOT / "scripts" / "build_static_demo.py")
        b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(b)
        self.assertIn("/api/channels", b.PAGES)

    def test_locales_complete(self):
        en = i18n.strings("en")
        need = ([f"push.err.{c}" for c in channels.ERROR_CLASSES] + [f"push.type.{t}" for t in channels.TYPES]
                + [f"push.help.{t}" for t in channels.TYPES] + [f"push.cat.{c}" for c in push.CATEGORIES]
                + [f"push.level.{lv}" for lv in push.LEVELS]
                + [f"push.field.{f.name}" for t in channels.TYPES for f in channels.fields(t)])
        for lang in i18n.CODES:
            s = i18n.strings(lang)
            for k in need:
                self.assertIn(k, s, (lang, k))
        self.assertTrue(all(k in en for k in need))


class ReviewFixTests(unittest.TestCase):
    """Round 10 fix stage: the read-only review's findings, one regression test each."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = store.connect(Path(self.tmp.name) / "r.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_scrub_masks_every_address_form(self):
        M = channels.MASK
        for addr in ("fe80::1", "::1", "2001:db8::1", "2001:0db8:0000:0000:0000:ff00:0042:8329",
                     "::ffff:192.168.1.5", "fe80::1%eth0", "aabbccddeeff", "AABBCCDDEEFF",
                     "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "192.168.1.5"):
            with self.subTest(addr=addr):
                out = push.scrub(f"Cam {addr} here")
                self.assertEqual(out, f"Cam {M} here")
        self.assertEqual(push.scrub("at fe80::1."), f"at {M}.")       # the sentence's full stop stays
        for same in ("v2.1.3 build", "at 08:00", "12:30:45", "Note:: x", "Security: 3 new",
                     "TV (living room)", "deadbeef", "a:b"):
            self.assertEqual(push.scrub(same), same)

    def test_discord_keeps_the_dashboard_link_clickable(self):
        msg = {**MSG, "url": "http://192.168.1.5:8787/#/inbox"}
        content = json.loads(channels.build("discord", {}, {"url": "https://discord.com/api/webhooks/1/x"},
                                            msg).body)["content"]
        self.assertTrue(content.endswith("\n<http://192.168.1.5:8787/#/inbox>"), content)
        self.assertIn("\\<\\@everyone\\>", content)                  # the text is still escaped
        long = {**msg, "body": "x" * 5000}
        content = json.loads(channels.build("discord", {}, {"url": "https://discord.com/api/webhooks/1/x"},
                                            long).body)["content"]
        self.assertLessEqual(len(content), channels.LIMITS["discord"])
        self.assertTrue(content.endswith("<http://192.168.1.5:8787/#/inbox>"))   # never cut off

    def matrix(self) -> int:
        cid = push.save(self.db, {}, {"type": "matrix", "name": "M", "language": "en",
                                      "fields": {"url": "http://192.168.1.20:8008", "room": "!r:example.org"},
                                      "secrets": {"token": "syt_x"}})
        push.set_enabled(self.db, {}, cid, True)
        return cid

    def test_matrix_retry_reuses_the_transaction_id(self):
        cid = self.matrix()
        evs = []
        p = mock.patch.object(push, "_alert_events", lambda db: list(evs))
        p.start()
        self.addCleanup(p.stop)
        push.collect(self.db, {}, now=NOW, tz=UTC)                   # primed
        evs.append(ev("m1"))
        self.assertEqual(push.collect(self.db, {}, now=NOW, tz=UTC), 1)
        sender = FakeSender()
        sender.results = [channels.Result(False, "timeout")]       # accepted, but the answer was lost
        push.deliver(self.db, {}, now=NOW, sender=sender, tz=UTC)
        push.deliver(self.db, {}, now=NOW + timedelta(hours=1), sender=sender, tz=UTC)   # the retry
        self.assertEqual(len(sender.reqs), 2)
        self.assertEqual(sender.reqs[0].url, sender.reqs[1].url)   # same txn: Matrix stores it once
        # two clicks on "Send test" are two messages
        p2 = mock.patch.object(store, "is_demo", lambda db: False)
        p2.start()
        self.addCleanup(p2.stop)
        push.test(self.db, {}, cid, sender=sender)
        push.test(self.db, {}, cid, sender=sender)
        self.assertNotEqual(sender.reqs[2].url, sender.reqs[3].url)
        self.assertEqual(len(push.history(self.db, {}, cid, "en")), 4)

    def test_a_saved_secret_never_goes_to_a_new_host(self):
        cid = push.save(self.db, {}, {"type": "gotify", "name": "G", "fields": {"url": "http://192.168.1.20"},
                                      "secrets": {"token": "keepme"}})
        for url in ("http://192.168.1.99", "http://192.168.1.20:8080", "https://192.168.1.20"):
            with self.subTest(url=url), self.assertRaises(push.BadPush) as cm:
                push.save(self.db, {}, {"id": cid, "name": "G", "fields": {"url": url}})
            self.assertEqual((cm.exception.code, cm.exception.field), ("push_reenter", "token"))
        # the preview of such a draft still works (it sends nothing) and masks the token
        pv = push.preview(self.db, {}, {"id": cid, "fields": {"url": "http://192.168.1.99"}})
        self.assertNotIn("keepme", json.dumps(pv))
        push.save(self.db, {}, {"id": cid, "name": "G", "fields": {"url": "http://192.168.1.20/gotify"}})  # same host
        push.save(self.db, {}, {"id": cid, "name": "G", "fields": {"url": "http://192.168.1.99"},
                                "secrets": {"token": "typed-again"}})
        self.assertEqual(push.get(self.db, {}, cid)["secrets"], {"token": "typed-again"})
        # a webhook's HMAC secret only signs: a new (typed) URL keeps it
        wid = push.save(self.db, {}, {"type": "webhook", "name": "W", "secrets": {
            "url": "http://192.168.1.2/h/a", "secret": "hmacKEEP"}})
        push.save(self.db, {}, {"id": wid, "name": "W", "secrets": {"url": "http://192.168.1.3/h/b"}})
        self.assertEqual(push.get(self.db, {}, wid)["secrets"]["secret"], "hmacKEEP")

    def test_another_process_without_the_env_never_deletes_env_channels(self):
        c = push.all_channels(self.db, ENV)[0]
        with self.db:
            push._record(self.db, c, "test", "test", channels.Result(True, "", 200))
        self.db.execute("UPDATE push_channels SET primed = 1 WHERE id = ?", (c["id"],))
        self.db.commit()
        self.assertEqual(push.all_channels(self.db, {}), [])            # `notify list` from a plain shell
        self.assertIsNone(push.by_name(self.db, {}, "Phone"))
        with self.assertRaises(push.BadPush):
            push.get(self.db, {}, c["id"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM push_channels").fetchone()[0], 1)
        back = push.all_channels(self.db, ENV)                             # the service again
        self.assertEqual([x["id"] for x in back], [c["id"]])
        self.assertFalse(back[0]["primed"])                                # re-primed: no backlog
        self.assertEqual(len(push.history(self.db, ENV, c["id"], "en")), 1)   # its log survived

    def test_one_exchange_has_a_total_deadline(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        stop = threading.Event()

        def trickle():   # headers, then one byte every 0.2 s of a long body: each read is "on time"
            conn, _ = srv.accept()
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            with contextlib.suppress(OSError):
                while not stop.is_set():
                    conn.sendall(b"x")
                    time.sleep(0.2)
            conn.close()
        threading.Thread(target=trickle, daemon=True).start()
        self.addCleanup(lambda: (stop.set(), srv.close()))
        t0 = time.monotonic()
        res = channels.send(channels.Request("POST", f"http://127.0.0.1:{srv.getsockname()[1]}/", {}, b"{}"), 0.8)
        took = time.monotonic() - t0
        self.assertEqual((res.ok, res.error), (False, "timeout"))
        self.assertLess(took, 3.0)


class PerfTests(unittest.TestCase):
    def test_channels_endpoint_is_fast_on_the_perf_db(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("perf_db", ROOT / "scripts" / "perf_db.py")
        perf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(perf)
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "perf.db"
            perf.build(path, n_devices=300, n_events=20_000, days=7, sample_minutes=30)
            db = store.connect(path)
            for i in range(5):
                push.save(db, {}, {"type": "gotify", "name": f"G{i}", "fields": {"url": "http://192.168.1.20"},
                                   "secrets": {"token": "t"}})
            db.close()
            cache.clear()
            srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en")
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                for method, ep, body in (("GET", "/api/channels", None),
                                         ("POST", "/api/channels/preview",
                                          {"channel": {"type": "gotify", "name": "x"}, "sample": "alert"})):
                    times = []
                    for _ in range(3):
                        t0 = time.perf_counter()
                        c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                        h = {"content-type": "application/json", "origin": f"http://127.0.0.1:{port}"} if body else {}
                        c.request(method, ep, json.dumps(body) if body else None, h)
                        r = c.getresponse()
                        r.read()
                        c.close()
                        self.assertEqual(r.status, 200, ep)
                        times.append((time.perf_counter() - t0) * 1000)
                    self.assertLess(min(times[1:]), 600, (ep, times))     # bar: 300 ms; room for CI
            finally:
                srv.shutdown()
                web.close_server(srv)


if __name__ == "__main__":
    unittest.main()
