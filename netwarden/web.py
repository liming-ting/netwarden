#!/usr/bin/env python3
"""
netwarden - web.py: a tiny local dashboard + AI chat (the magic moment, clickable)

Zero dependencies: Python's stdlib http.server. Serves the page from netwarden/static
(index.html + app.css + app.js, vanilla, no build step) and a small JSON API that
reuses store + brain + alerts. Binds to 127.0.0.1 only (local machine) unless LAN
mode (--lan, docs/lan.md) adds the LAN address, where every request needs a paired
session and admin endpoints stay loopback-only. The Anthropic key stays server-side
and is never sent to the browser.

    python3 -m netwarden.web                       # real DB (data/netwarden.db)
    python3 -m netwarden.web --db data/demo.db     # the seeded demo home
    python3 -m netwarden.web --lang en             # server default language
    # then open http://127.0.0.1:8787 in your browser

The "actions" (mute a threat, trust/rename a device) only write the user's OWN local
notes in netwarden's SQLite. netwarden never changes the router/firewall - muting an
alert just stops netwarden from nagging about it.

Languages: every UI string comes from netwarden/locales/<code>.json (GET /api/locale).
The data endpoints take ?lang= and localize service names / categories / threat text
at this edge; the AI endpoints take "lang" in the JSON body. The page remembers the
user's pick in localStorage; a first visit follows the browser language if we have it.

(FastAPI would be the upgrade path if we ever need async/websockets/auth; stdlib is
plenty for a local single-user dashboard and keeps packaging trivial.)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import logging
import math
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime
from html import escape as html_escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

import netwarden
from netwarden import (activity, ai_intents, alerts, backup, bedtime, brain, cache, conntest, dashboard,
                       devicetype, export, exposure, family_report, firstrun, health, hygiene,
                       i18n, identify, inbox, live, localai, naming, nethealth, notify, pairing,
                       people, presence, privacy, qr, report, runner, score, screentime, search,
                       services, settings, since, store, suggestions, threatintel, timeline,
                       tuning, upnp, usage, visibility, weekly, wslnet)

log = logging.getLogger("netwarden.web")

# --- the page: plain files in netwarden/static (vanilla JS/CSS, no build step) -------
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
                ".png": "image/png", ".webmanifest": "application/manifest+json"}
ASSETS = ("app.css", "app.js", "map.js", "report.css", "report.js", "pair.js", "offline.js",
          "sw.js", "demo.js")   # cache-busted via ?v=<hash> (demo.js: the static demo only)
VERSION_MARK = b"__V__"
# Everything comes from this origin; inline style attributes are used for computed
# colors/sizes (heatmap, bars), never inline scripts.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
# Sent with EVERY response (pages, JSON, files, redirects, errors): Handler.end_headers.
SECURITY_HEADERS = (("content-security-policy", CSP), ("x-frame-options", "DENY"),
                    ("x-content-type-options", "nosniff"), ("referrer-policy", "no-referrer"),
                    ("cross-origin-opener-policy", "same-origin"),
                    ("cross-origin-resource-policy", "same-origin"),
                    ("permissions-policy", "camera=(), microphone=(), geolocation=()"))
# Stage H: Home Assistant shows an ingress panel in an iframe of its own page - the same
# origin as the ingress URL. Only answers to the trusted ingress proxy may be framed,
# and only by that origin; everything else keeps DENY / 'none'.
INGRESS_HEADERS = tuple(
    (n, CSP.replace("frame-ancestors 'none'", "frame-ancestors 'self'")) if n == "content-security-policy"
    else (n, "SAMEORIGIN") if n == "x-frame-options" else (n, v) for n, v in SECURITY_HEADERS)
# X-Ingress-Path ("/api/hassio_ingress/<token>"): read from the trusted proxy only, and
# only when it is plain path segments - it ends up in pages and Location headers
INGRESS_PATH_RE = re.compile(r"(/[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,127}){1,8}")


def ingress_base(raw) -> str:
    """The validated X-Ingress-Path prefix (no trailing slash), or "" when absent/odd."""
    raw = (raw or "").strip().rstrip("/")
    if not raw or len(raw) > 512 or not INGRESS_PATH_RE.fullmatch(raw) or \
            any(seg in (".", "..") for seg in raw.split("/")):
        return ""
    return raw

# Stage M: what a browser WITHOUT a session may load (the pairing page and what it
# needs; the manifest + icons, which browsers fetch without cookies). Everything else
# from a non-loopback client - or from anyone under NETWARDEN_REQUIRE_AUTH=1 - needs one.
PUBLIC_PATHS = ("/pair", "/api/pair", "/favicon.ico", "/sw.js", "/offline")
# Round 6: liveness for Docker's HEALTHCHECK / systemd / monitors. Answered before the
# Host check, the session check and the data gate: no DB, nothing about the home.
HEALTHZ_PATH = "/healthz"
# Round 6 fix: a loopback request carrying one of these came through a proxy on this
# machine - it is another device, never "this computer" (Handler._host_ok)
FORWARDED_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded")
PUBLIC_STATIC = ("app.css", "pair.js", "icon.svg", "manifest.webmanifest",
                 "apple-touch-icon.png", "icon-192.png", "icon-512.png", "offline.js")
PAGE_PATHS = ("/", "/index.html", "/report/weekly")   # -> 303 /pair without a session
# Admin actions: from THIS computer's own browser, or with an admin session (round 6:
# `pair --admin`, for headless installs); an ordinary paired phone gets 403.
TEST_POSTS = tuple("/api/test/" + s for s in conntest.SOURCES)   # Stage X connection tests
ADMIN_POSTS = ("/api/settings", "/api/ai/test", "/api/check", "/api/pair/new",
               "/api/pair/revoke", "/api/pair/revoke_all", "/api/backup/preview",
               "/api/restore", "/api/setup", "/api/setup/scan", *TEST_POSTS)
ADMIN_GETS = ("/api/settings", "/api/pair/sessions", "/api/backup", "/api/setup/scan/status")


def static_file(name: str) -> tuple[bytes, str] | None:
    """(bytes, content type) of one file directly inside netwarden/static, or None.
    No sub-directories, no dot-files, only known types: nothing outside the folder
    can ever be served, whatever the request path looks like."""
    if not name or name.startswith(".") or "/" in name or "\\" in name or "\0" in name:
        return None
    path = STATIC_DIR / name
    ctype = STATIC_TYPES.get(path.suffix.lower())
    if not ctype:
        return None
    hit = _static_cache.get(name)
    now = time.monotonic()
    if hit and now - hit[0] < STATIC_RECHECK:
        return hit[2], ctype
    try:
        if path.resolve().parent != STATIC_DIR.resolve() or not path.is_file():
            return None
        st = path.stat()
        stamp = (st.st_mtime_ns, st.st_size)
        body = hit[2] if hit and hit[1] == stamp else path.read_bytes()
    except OSError:
        return None
    _static_cache[name] = (now, stamp, body)
    return body, ctype


# Page files are read once and re-checked (one stat) at most every STATIC_RECHECK
# seconds (Stage V3): reading + hashing them on every page load took 0.5-3 s on
# WSL's /mnt/c. An edited file is still picked up within that time.
STATIC_RECHECK = 2.0
_static_cache: dict = {}    # name -> (checked monotonic, (mtime_ns, size), bytes)
_version_cache: dict = {}   # stamps of ASSETS -> version


def asset_version() -> str:
    """Short hash over the page's CSS + JS, so a changed file gets a new URL."""
    bodies = [(static_file(name) or (b"", ""))[0] for name in ASSETS]
    key = tuple(_static_cache.get(n, (0, None))[1] for n in ASSETS)
    if key in _version_cache:
        return _version_cache[key]
    h = hashlib.sha256()
    for body in bodies:
        h.update(body)
    _version_cache.clear()
    _version_cache[key] = h.hexdigest()[:12]
    return _version_cache[key]


OFFLINE_MARK = b"__OFFLINE__"
BASE_MARK = b"__BASE__"


def index_html(base: str = "") -> bytes:
    """The dashboard shell. Stage G: it carries the "netwarden is not running" texts in
    every language (inert JSON), so a page whose server stops answering before its
    locale has loaded still says what happened - in words, localized - and retries.
    Stage H: `base` = the ingress prefix ("" normally) in front of every URL, and as
    <html data-base> for app.js (escaped; ingress_base() already allows no quotes)."""
    body, _ = static_file("index.html")
    return body.replace(VERSION_MARK, asset_version().encode()) \
               .replace(BASE_MARK, html_escape(base, quote=True).encode()) \
               .replace(OFFLINE_MARK, offline_texts_json().encode("utf-8"))


OFFLINE_KEYS = ("title", "lead", "hint", "retry", "auto")


def offline_texts() -> dict:
    """{lang code: {title, lead, hint, retry, auto}}: the "not running" texts."""
    return {code: {k: i18n.t("app.offline." + k, code) for k in OFFLINE_KEYS}
            for code, _n, _l in i18n.LANGS}


def offline_texts_json() -> str:
    # "<" escaped: the JSON sits inside a <script type="application/json"> element
    return json.dumps(offline_texts(), ensure_ascii=False).replace("<", "\\u003c")


def offline_html(lang: str, base: str = "") -> bytes:
    """GET /offline: the "netwarden is not running" page the service worker shows when
    the server is down. It is cached once and must speak every language, so it carries
    all of them as JSON data (static/offline.js picks the page's last language);
    `lang` only decides what shows before the script runs. No user data at all.
    `base`: the ingress prefix (Stage H), also handed to offline.js as data-base."""
    first = offline_texts()[i18n.normalize(lang)]
    data = offline_texts_json()
    esc = lambda s: html_escape(s, quote=True)   # noqa: E731
    v = asset_version()
    b = esc(base)
    return f"""<!doctype html>
<html lang="{esc(lang)}" data-base="{b}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(first['title'])}</title>
<link rel="icon" href="{b}/static/icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{b}/static/app.css?v={v}">
<script src="{b}/static/offline.js?v={v}" defer></script>
</head><body class="offline-page">
<main class="offline-card" aria-live="polite">
<svg class="offline-logo" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
<h1 id="off-title">{esc(first['title'])}</h1>
<p id="off-lead">{esc(first['lead'])}</p>
<p class="offline-hint"><span id="off-hint">{esc(first['hint'])}</span><br><code>scripts\\start_windows.cmd</code></p>
<p><button type="button" class="btn" id="off-retry">{esc(first['retry'])}</button></p>
<p class="offline-auto" id="off-auto">{esc(first['auto'])}</p>
</main>
<script type="application/json" id="off-texts">{data}</script>
</body></html>
""".encode("utf-8")


def localize_snapshot(snap: dict, lang: str) -> dict:
    """brain.snapshot() with service names, category names and threat text in `lang`.
    The snapshot itself stays canonical English (that is what the LLM reads)."""
    return {**snap, "lang": lang,
            "devices": [_localize_device(d, lang) for d in snap["devices"]],
            "threats": [threatintel.localize(t, lang) for t in snap.get("threats", [])]}


def _localize_device(d: dict, lang: str) -> dict:
    """One snapshot device for the web: localized services + type_info (type name,
    confidence, reason) instead of the canonical type_detail."""
    out = services.localize_device(d, lang)
    out["type_info"] = devicetype.localize(out.pop("type_detail", None), lang)
    return out


def inventory_device(db, mac: str, lang: str = i18n.DEFAULT) -> dict | None:
    """A known device with no DNS in the window, in the snapshot-device shape (so the
    drill-down still shows its ports / visibility). None if the MAC is unknown."""
    r = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone() if mac else None
    if not r:
        return None
    label = (store.get_labels(db).get(mac) or {}).get("label")
    prof = store.get_profiles(db).get(mac) or {}
    t = devicetype.classify_all(db).get(mac)
    return {"name": label or r["hostname"] or None, "label": label,
            **{f: prof[f] for f in ("owner", "room") if prof.get(f)},
            "type": (t or {}).get("type", "unknown"), "type_info": devicetype.localize(t, lang),
            "hostname": r["hostname"] or None, "vendor": r["vendor"], "is_self": bool(r["is_self"]),
            "ips": [r["ip"]] if r["ip"] else [], "mac": mac,
            "trusted": (mac, "") in store.list_acks(db), "queries": 0, "blocked": 0,
            "distinct_domains": 0, "services": [], "top_domains": []}


def device_extras(db, mac: str, hours: float, lang: str, local: bool = True) -> dict:
    """Stage D1 drill-down data: privacy, DNS-visibility findings and open ports. A
    port check is an admin action: only offered on this computer (local)."""
    demo = store.is_demo(db)
    vis = naming.relabel(visibility.analyze(db, hours=hours), naming.display_names(db, lang))
    issues = [{**it, "kind": kind, "text": visibility.explain(kind, it, lang)}
              for kind in ("bypass", "quiet", "never") for it in vis[kind] if it["mac"] == mac]
    return {
        "privacy": privacy.device_report(db, mac, hours=hours, lang=lang),
        "visibility": issues,
        "ports": exposure.latest(db, mac, lang),
        "port_list": [exposure.port_info(p, lang) for p in exposure.PORTS],
        "check_allowed": not demo and local,
        "check_note": i18n.t("exposure.demo_refused", lang) if demo else
                      i18n.t("ui.check_note", lang, n=len(exposure.PORTS)) if local else
                      i18n.t("app.pair.admin_only", lang),
    }


D2_ROUTES = ("/api/activity", "/api/timeline", "/api/search", "/api/service", "/api/domain",
             "/api/people", "/api/rooms", "/api/types")
FAMILY_ROUTES = ("/api/screentime", "/api/bedtime", "/api/weekly", "/report/weekly")
HEALTH_ROUTES = ("/api/health", "/api/suggestions", "/api/score")   # Stage H
SUGGESTION_POST = "/api/suggestions/"
# Stage P: people and presence. Turning presence ON (and choosing which devices count) is
# for this computer only, like the other admin actions; turning it off, the notification
# switches and "forget" work from a paired phone too (they only ever reduce tracking).
PEOPLE_GETS = ("/api/person", "/api/presence")
PEOPLE_POSTS = ("/api/people", "/api/people/delete", "/api/people/restore", "/api/people/assign",
                "/api/presence/settings", "/api/presence/forget", "/api/presence/link",
                "/api/presence/unlink")
# Stage Q: alert tuning + the quiet-hours summary card (user notes; anyone signed in)
TUNING_POSTS = ("/api/tuning", "/api/tuning/undo", "/api/tuning/restore",
                "/api/tuning/restore_undo", "/api/notify/seen")
TUNING_ERRORS = ("bad_tuning", "no_tuning", "no_summary")
PEOPLE_ERRORS = ("person_exists", "no_person", "not_their_device", "no_suggestion")
UNDO_TTL = 15 * 60         # seconds an Undo token (deleted person, linked device) stays valid
MAX_UNDO = 200

# Stage T: the Overview's datasets (the page's S.data keys) -> their own endpoint. GET
# /api/overview answers all of them in ONE request (one thread, one cache fingerprint)
# from the very same functions (Handler._dataset), so the bundle always equals them.
OVERVIEW = {"inv": "/api/inventory", "alerts": "/api/alerts", "privacy": "/api/privacy",
            "vis": "/api/visibility", "status": "/api/status", "homeAct": "/api/activity",
            "upnp": "/api/upnp", "health": "/api/health", "sug": "/api/suggestions",
            "score": "/api/score", "inbox": "/api/inbox", "pres": "/api/presence",
            "notify": "/api/notify", "hyg": "/api/hygiene"}
DATASET_OF = {path: name for name, path in OVERVIEW.items()}
STREAM_PATH = "/api/stream"
STREAM_HEARTBEAT = 25.0     # seconds between ": hb" comments on an idle stream
STREAM_MAX_S = 30 * 60      # a stream ends after this long; the page reconnects (and resumes)
STREAM_RETRY_MS = 3000      # the browser's own reconnect delay (the page backs off itself)


def etag_of(body: bytes) -> str:
    return '"' + hashlib.sha256(body).hexdigest()[:20] + '"'


def tag_of(obj) -> str:
    """A JSON answer's ETag: a hash of everything in it except a top-level `generated`
    clock stamp (no page reads it; it alone would make every answer look new)."""
    if isinstance(obj, dict) and "generated" in obj:
        obj = {k: v for k, v in obj.items() if k != "generated"}
    if isinstance(obj, dict) and set(obj) == {"parts", "etags"}:    # the Overview bundle
        obj = obj["etags"]
    return etag_of(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


class _UndoStash:
    """Server-side Undo for actions whose before-state the client must not be trusted to
    send back (a deleted person's rules, a linked device's old profile): the client gets
    an opaque token and posts only that."""
    def __init__(self):
        self.lock, self.items = threading.Lock(), {}

    def put(self, db_path: str, kind: str, data) -> str:
        import secrets
        token = secrets.token_urlsafe(16)
        now = time.monotonic()
        with self.lock:
            self.items = {k: v for k, v in self.items.items() if v[0] > now}
            while len(self.items) >= MAX_UNDO:
                self.items.pop(next(iter(self.items)))
            self.items[token] = (now + UNDO_TTL, str(db_path), kind, data)
        return token

    def take(self, db_path: str, kind: str, token) -> object:
        if not isinstance(token, str) or len(token) > 64:
            return None
        with self.lock:
            hit = self.items.get(token)
            if not hit or hit[0] < time.monotonic() or hit[1] != str(db_path) or hit[2] != kind:
                return None
            del self.items[token]
            return hit[3]


UNDO = _UndoStash()

MAX_BODY = 1 << 20          # POST bodies are small JSON; anything bigger is refused (413)
MAX_LABEL = 100             # a device's friendly name ...
MAX_NOTE = 500              # ... and its note (store.clean_text: one line, no controls)
MAX_KEY = 300               # an ack key: "" | a domain | "port:23" | "visibility:quiet" ...
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _digits(text: str) -> bool:
    """Only ASCII digits ("²".isdigit() is True and int("²") raises)."""
    return text.isascii() and text.isdigit()


def tz_info(tz) -> dict:
    """{"tz": "Asia/Taipei" | "UTC+08:00", "tz_offset_min": 480}: netwarden's local zone
    (activity.local_tz) and its offset right now, for /api/meta."""
    off = datetime.now(tz).utcoffset()
    return {"tz": activity.tz_label(tz), "tz_offset_min": int(off.total_seconds() // 60) if off else 0}


def failure_answer(e: Exception) -> tuple[int, str]:
    """(status, err.<key>) for a request that raised: 503 `busy` while SQLite is locked
    by a long write (the loops, a VACUUM) - worth a retry in a moment - else 500
    `internal`. Never the exception text itself. Stage K: a damaged or unreadable
    database file -> 503 `db_corrupt` / `db_unreadable` (nothing a retry can fix: the
    page says what to do)."""
    kind = store.problem(e)
    if kind == "locked":
        return 503, "busy"
    if kind in ("corrupt", "unreadable"):
        return 503, "db_" + kind
    return 500, "internal"


class BadRequest(ValueError):
    """A POST body field of the wrong type / shape -> 400 with err.<key>."""
    def __init__(self, key: str = "bad_json"):
        super().__init__(key)
        self.key = key


def budget_event(b: dict, lang: str) -> dict:
    """The chat's `event: budget` (round 7 C): the numbers + the localized question."""
    usd = lambda v: i18n.t("app.usage.usd", lang,   # noqa: E731
                           v=f"{v:.2f}" if v >= 0.01 or v == 0 else f"{v:.4f}")
    key = "app.usage.budget_over_q" if b["state"] == "over" else "app.usage.budget_cross_q"
    return {"state": b["state"], "limit": b["limit"], "spent": b["spent"],
            "estimate_usd": b.get("estimate_usd"),
            "text": i18n.t(key, lang, spent=usd(b["spent"]), limit=usd(b["limit"]),
                           cost=usd(b.get("estimate_usd") or 0))}


def text_field(payload: dict, name: str) -> str:
    """payload[name] as a stripped string; missing / null -> "". Any other JSON type is a
    bad request (never a traceback that drops the connection)."""
    v = payload.get(name)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise BadRequest()
    return v.strip()


def mac_field(payload: dict, db) -> str:
    """The device a note / ack is about: a well-formed MAC (aa:bb:cc:dd:ee:ff) or a key
    that is already in the devices table. Anything else is refused (bad_mac), so junk
    keys never pile up in the user's notes."""
    mac = text_field(payload, "mac")
    if not mac:
        raise BadRequest("no_mac")
    if MAC_RE.match(mac.lower()):
        known = db.execute("SELECT mac FROM devices WHERE mac IN (?, ?)",
                           (mac, mac.lower())).fetchone()
        return known["mac"] if known else mac.lower()
    if len(mac) <= 64 and db.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
        return mac
    raise BadRequest("bad_mac")


def allowed_hosts(port: int, bound: str = "127.0.0.1") -> set[str]:
    """Host header values that name THIS server. Anything else is a DNS-rebinding page
    (evil.example re-resolved to 127.0.0.1) and must not get our data. LAN mode adds
    exactly its LAN address:port (Handler.lan_hosts)."""
    names = {"127.0.0.1", "localhost"} | ({bound} if bound != "0.0.0.0" else set())
    hosts = {f"{n}:{port}" for n in names}
    if port == 80:
        hosts |= set(names)
    return hosts


class Handler(BaseHTTPRequestHandler):
    # configured on the class by make_server() / tests
    db_path = str(store.DEFAULT_DB)
    env: dict = {}
    lang = brain.DEFAULT_LANG   # server default language (code or legacy name)
    lang_pinned = True          # set by --lang / NETWARDEN_LANG: the setting can't change it
    hours = 24
    loops = None                # callable -> {name: {running, interval_s, ...}} (netwarden run)
    warmer = None               # runner.Warmer: every /api/ GET keeps it warming
    # Stage M (LAN mode + pairing); set by make_server()
    lan = False                 # also listening on the LAN address
    lan_hosts: frozenset = frozenset()   # {"192.168.1.13:8787"}: the extra allowed Host value
    lan_url = ""                # "http://192.168.1.20:8787" (what the pairing QR points at)
    lan_origins: frozenset = frozenset()  # extra allowed Origin values (an https advertised URL)
    proxy_hosts: frozenset = frozenset()  # the advertised URL's Host values: never "local"
    bind_all = False            # --bind-all: listening on 0.0.0.0
    require_auth = False        # NETWARDEN_REQUIRE_AUTH=1: loopback needs a session too
    limiter = pairing.Limiter()  # wrong pairing codes, per client address
    # socket timeout: an idle keep-alive connection, or a client trickling its headers /
    # body, is dropped after this long instead of holding a thread forever (a streaming
    # chat answer only WRITES, so it is unaffected)
    timeout = 15
    # "Is this request from this computer?" - injectable, so tests can play a phone
    # without ever binding a non-loopback address.
    is_local_client = staticmethod(lambda ip: is_loopback(ip))
    # Stage H (Home Assistant add-on): the ingress proxy's address. Set by make_server()
    # in add-on mode ONLY (or by tests) - never a user setting. None = no ingress at all.
    ingress_proxy: str | None = None
    # per request (reset by _host_ok / _auth)
    local = True                # this computer's own browser (loopback, a loopback Host)
    admin = True                # may do admin actions: local, or an admin session
    ingress = False             # came through the trusted HA ingress proxy
    base = ""                   # its X-Ingress-Path prefix ("" = served at /)
    session = None
    token = None
    _cookie = None

    def end_headers(self):
        """Every response carries the security headers (and the session cookie to set)."""
        for name, value in (INGRESS_HEADERS if self.ingress else SECURITY_HEADERS):
            self.send_header(name, value)
        if self._cookie:
            self.send_header("set-cookie", self._cookie)
        super().end_headers()

    def _download(self, body: bytes, ctype: str, name: str):
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-disposition", f'attachment; filename="{name}"')
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")   # personal data: never on disk
        self.end_headers()
        self.wfile.write(body)

    def _lang(self, requested=None) -> str:
        """The request's language: an explicit ?lang= / "lang" if supported, else the
        server default."""
        return i18n.match(requested) or i18n.normalize(self.lang)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, body: bytes, ctype: str, immutable: bool = False):
        """A page file with an ETag (304 when unchanged). index.html is revalidated on
        every load; app.css / app.js requested with the current ?v= hash are immutable."""
        etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
        policy = "public, max-age=31536000, immutable" if immutable else "no-cache"
        if self.headers.get("if-none-match") == etag:
            self.send_response(304)
            self.send_header("etag", etag)
            self.send_header("cache-control", policy)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("etag", etag)
        self.send_header("cache-control", policy)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        """A JSON answer. A successful GET carries an ETag (tag_of: a hash of this body
        minus its `generated` stamp; the bundle's = a hash of its parts' tags), and a request whose If-None-Match names it gets 304 without the body: the data
        is computed either way, so a 304 can never be stale. Still no-store: personal
        data never lands in a browser cache; the page keeps the ETag itself."""
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        if code != 200 or self.command != "GET":
            self._send(code, body)
            return
        etag = tag_of(obj)
        if etag in [t.strip() for t in (self.headers.get("if-none-match") or "").split(",")]:
            self.send_response(304)
            self.send_header("etag", etag)
            self.send_header("cache-control", "no-store")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.send_header("etag", etag)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, key, lang):
        self._json(code, {"error": i18n.t("err." + key, lang)})

    _conn = None                # this request's database connection (_db / _close_db)

    def _db(self):
        """The request's one SQLite connection, opened on first use and closed when the
        request ends (_close_db) - never left for the garbage collector."""
        if self._conn is None:
            self._conn = store.connect(self.db_path)
        return self._conn

    def _close_db(self):
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - closing a connection must not fail a request
                pass

    # Stage K: what http.server itself refuses (a malformed request line, an over-long
    # URL or header block, an unknown method, HTTP/2+) - a localized JSON error like
    # every other answer instead of its English HTML page. Methods we don't serve get
    # 405 (not 501) and an unsupported version 400 (not 505): bad input is never a 5xx.
    PROTOCOL_ERRORS = {400: "bad_request", 405: "bad_method", 408: "bad_request",
                       413: "too_large", 414: "uri_too_long", 431: "headers_too_large"}

    def send_error(self, code, message=None, explain=None):
        code = int(code)
        if code == 501:
            code = 405
        elif code >= 500 or code not in self.PROTOCOL_ERRORS:
            code = 400
        body = json.dumps({"error": i18n.t("err." + self.PROTOCOL_ERRORS[code], self._lang())},
                          ensure_ascii=False).encode("utf-8")
        self.close_connection = True
        # a 3-word request line with a bad version ("HTTP/2.0", "HTTP/x") still gets a
        # status line + headers; only a real one-word HTTP/0.9 request gets the bare body
        if getattr(self, "request_version", "") == "HTTP/0.9" and \
                len((getattr(self, "requestline", "") or "").split()) >= 3:
            self.request_version = "HTTP/1.0"
        self.send_response(code)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        if code == 405:
            self.send_header("allow", "GET, POST")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _host_ok(self) -> bool:
        """DNS-rebinding guard: the Host header must name this loopback server, and a
        POST that carries an Origin must come from this same origin. Answers 421/403
        itself and returns False otherwise."""
        self._cookie, self.session, self.token = None, None, None
        self.ingress, self.base = self._from_ingress_proxy(), ""
        if self.ingress:
            return self._ingress_ok()
        bound, port = self.server.server_address[:2]
        own = allowed_hosts(port, bound)
        hosts = own | set(self.lan_hosts)
        host = (self.headers.get("host") or "").strip().lower()
        # "this computer" = a loopback client - but a reverse proxy on this machine
        # connects from loopback too, and must not turn every visitor into this
        # computer's own browser. Its visitors can forge "Host: 127.0.0.1" through it, so
        # once an advertised URL is set (proxy_hosts) loopback is never trusted by itself:
        # every browser signs in (pair / pair --admin). A proxy's forwarding header on a
        # loopback request means the same, advertised URL or not.
        self.local = bool(self.is_local_client(self.client_address[0])) and \
            not self.proxy_hosts and \
            not any(self.headers.get(h) for h in FORWARDED_HEADERS)
        self.admin = self.local
        if host not in hosts:
            self._error(421, "bad_host", self._lang())
            self.close_connection = True
            return False
        if self.command == "POST":
            # a browser always sends Origin with a fetch() POST; from another device it
            # is REQUIRED (only local tools such as curl may leave it out)
            origin = (self.headers.get("origin") or "").strip().lower()
            if (origin or not self.local) and \
                    origin not in {f"http://{h}" for h in hosts} | set(self.lan_origins):
                self._error(403, "bad_origin", self._lang())
                self.close_connection = True
                return False
        return True

    def _from_ingress_proxy(self) -> bool:
        """Stage H: is the PEER the Supervisor's ingress proxy (add-on mode only)? Decided
        by the socket's address alone - never by a header anyone could send."""
        return bool(self.ingress_proxy) and self.client_address[0] == self.ingress_proxy

    def _ingress_ok(self) -> bool:
        """A request through Home Assistant ingress. HA has signed the user in (the panel
        is admin-only) and the Supervisor connects from its fixed address, so it counts
        as an admin of this install - but never as "this computer". Its Host header is
        Home Assistant's own (any name the user opens HA under), so the DNS-rebinding
        check is HA's job; a POST must still carry an Origin naming that same host
        (X-Forwarded-Host or Host): another site can't post through the user's HA tab."""
        self.local, self.admin = False, True
        self.base = ingress_base(self.headers.get("x-ingress-path"))
        if self.command == "POST":
            origin = (self.headers.get("origin") or "").strip().lower()
            u = urlparse(origin)
            names = {(self.headers.get("x-forwarded-host") or "").split(",")[0].strip().lower(),
                     (self.headers.get("host") or "").strip().lower()} - {""}
            if u.scheme not in ("http", "https") or not u.netloc or u.netloc not in names \
                    or origin != f"{u.scheme}://{u.netloc}":
                self._error(403, "bad_origin", self._lang())
                self.close_connection = True
                return False
        return True

    def _client_key(self) -> str:
        """Who counts as one client for per-client caps (live streams): the peer address -
        or, through ingress, the browser's address the proxy chain reports (every HA
        user would otherwise share the proxy's one address)."""
        if self.ingress:
            hops = [h.strip() for h in (self.headers.get("x-forwarded-for") or "").split(",")]
            hops = [h for h in hops if h and h != "None"]
            return "ingress:" + (hops[-2] if len(hops) >= 2 else hops[0] if hops else "")[:64]
        return self.client_address[0]

    def _redirect(self, location: str):
        """303 to one of our own pages (`location` starts with "/"), under the ingress
        prefix when there is one."""
        self.send_response(303)
        self.send_header("location", self.base + location)
        self.send_header("content-length", "0")
        self.end_headers()

    def _auth(self, path: str) -> bool:
        """Stage M: who may see this. Loopback (unless NETWARDEN_REQUIRE_AUTH=1) or a
        valid session cookie; the pairing page and its assets are public; anything else
        gets 303 -> /pair (pages) or 401 (API). Admin paths: this computer only.
        Stage H: through Home Assistant ingress = signed in by HA (no cookie of ours)."""
        if self.ingress:
            return True
        token = pairing.token_from_cookie(self.headers.get("cookie"))
        if token:
            s = pairing.check(self._db(), token)
            if s:
                self.session, self.token = s, token
                self.admin = self.local or bool(s.get("admin"))
                if s["refresh"]:          # sliding expiry: the cookie gets a fresh Max-Age
                    self._cookie = pairing.cookie(token)
        allowed = self.session is not None or (self.local and not self.require_auth) \
            or path in PUBLIC_PATHS \
            or (path.startswith("/static/") and path[len("/static/"):] in PUBLIC_STATIC)
        if not allowed:
            # Stage G: a cookie that no longer opens anything = this phone WAS paired
            # (expired, revoked, or the database changed): /pair says so instead of
            # greeting it like a stranger
            expired = bool(token)
            if self.command == "GET" and path in PAGE_PATHS:
                self._redirect("/pair?expired=1" if expired else "/pair")
            else:
                self._json(401, {"error": i18n.t("err.auth_required", self._lang()), "pair": True,
                                 "expired": expired})
            self.close_connection = True
            return False
        if path in (ADMIN_POSTS if self.command == "POST" else ADMIN_GETS) and not self.admin:
            self._error(403, "loopback_only", self._lang())
            self.close_connection = True
            return False
        return True

    # At most this many data GETs run at once. A page refresh fires a dozen requests
    # together; run all at once, their SQLite reads on separate connections contend so
    # badly (measured on the perf DB: 11 parallel ~0.9 s vs ~0.17 s one after another)
    # that two at a time is several times faster. Pages, static files and POSTs (the
    # streaming chat) do not take a slot - nor does the live stream (Stage T): it stays
    # open for minutes and must never hold a slot the page's data requests need.
    DATA_GATE = threading.BoundedSemaphore(2)
    live = None                 # live.Detector of this database (make_server)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == HEALTHZ_PATH:
            self._healthz()
            return
        if path == STREAM_PATH:
            self._stream()
            return
        gated = self.path.startswith(("/api/", "/report/"))
        if gated:
            self.DATA_GATE.acquire()
        self._started = False
        try:
            with cache.batch():   # one fingerprint per request, not one per cached piece
                self._get()
        except (BrokenPipeError, ConnectionResetError):
            pass                  # the browser went away mid-answer: nothing to tell it
        except Exception as e:    # noqa: BLE001 - a bug or a busy DB: answer, never drop
            self._get_failed(e)
        finally:
            self._close_db()
            if gated:
                self.DATA_GATE.release()

    def send_response(self, code, message=None):
        self._started = True      # from here on an error can only close the connection
        super().send_response(code, message)

    HEALTHZ_BODY = json.dumps({"status": "ok", "version": netwarden.__version__}).encode()

    def _healthz(self):
        """GET /healthz: "this server answers". Public on purpose (Docker's HEALTHCHECK has
        no session) and constant: no database, no Host check, no data gate - so it is
        cheap, can't be slowed down by page loads and says nothing about the home."""
        self._cookie = None
        try:
            self._send(200, self.HEALTHZ_BODY)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _get_failed(self, e: Exception):
        """Stage G: a GET that raised. The page gets a localized JSON error it can show
        with a Retry button - 503 `busy` when SQLite is locked by a long write (the
        loops, a VACUUM), else 500 `internal` - instead of a dropped connection that
        reads as "netwarden is not running". Logged without secrets, never a traceback
        in the answer."""
        path = urlparse(self.path).path
        log.warning("GET %s failed: %s", path, health.sanitize_error(repr(e)))
        if self._started:
            self.close_connection = True
            return
        lang = self._lang((parse_qs(urlparse(self.path).query).get("lang") or [None])[0])
        try:
            self._error(*failure_answer(e), lang)
        except OSError:
            self.close_connection = True

    def _get(self):
        if not self._host_ok():
            return
        url = urlparse(self.path)
        path, query = url.path, parse_qs(url.query)
        if not self._auth(path):
            return
        lang = self._lang((query.get("lang") or [None])[0])
        if self.warmer and path.startswith("/api/"):
            self.warmer.touch()
        if path == "/pair":
            # the phone's own language: ?lang= > its Accept-Language > the server default
            plang = i18n.match((query.get("lang") or [None])[0]) or \
                i18n.from_accept_language(self.headers.get("accept-language", "")) or self._lang()
            expired = (query.get("expired") or [""])[0] == "1"
            self._static(pairing.render_page(plang, asset_version(), expired=expired,
                                             base=self.base).encode("utf-8"),
                         STATIC_TYPES[".html"])
        elif path == "/api/pair/sessions":
            self._pair_sessions()
        elif path in ("/", "/index.html"):
            self._static(index_html(self.base), STATIC_TYPES[".html"])
        elif path.startswith("/static/"):
            found = static_file(path[len("/static/"):])
            if not found:
                self._error(404, "not_found", lang)
                return
            v = (query.get("v") or [""])[0]
            self._static(*found, immutable=bool(v) and v == asset_version())
        elif path == "/favicon.ico":
            # the page links /static/icon.svg; answer direct hits too, so no 404 noise
            self.send_response(204)
            self.end_headers()
        elif path in DATASET_OF and not (path == "/api/activity" and query.get("mac")):
            db = self._db()
            self._json(200, self._dataset(DATASET_OF[path], db, lang))
        elif path == "/api/overview":     # Stage T: every Overview dataset in one request
            db = self._db()
            self._json(200, self._overview(db, lang))
        elif path == "/api/since":        # Stage T: "Since your last visit"
            t = since.parse_since((query.get("t") or [""])[0])
            if t is None:
                self._error(400, "bad_since", lang)
                return
            db = self._db()
            self._json(200, since.report(db, t, lang, env=self.env, hours=self.hours,
                                         tz=self._tz()))
        elif path == "/api/devices":
            db = self._db()
            self._json(200, localize_snapshot(brain.snapshot(db, hours=self.hours), lang))
        elif path == "/api/tuning":
            db = self._db()
            self._json(200, self._tuning_body(db, lang))
        elif path == "/api/backup":
            if not self._local_client():
                return
            db = self._db()
            self._download(backup.dumps(backup.export(db)), "application/json; charset=utf-8",
                           backup.filename())
        elif path == "/api/setup":
            db = self._db()
            self._json(200, {**firstrun.status(db, self.env), "local": self.admin})
        elif path == "/api/setup/scan/status":
            job = firstrun.scan_status((query.get("job") or [""])[0])
            if not job:
                self._error(404, "unknown_job", lang)
                return
            self._json(200, job)
        elif path == "/sw.js":
            self._service_worker()
        elif path == "/offline":
            self._static(offline_html(lang, self.base), STATIC_TYPES[".html"])
        elif path == "/api/device":
            mac = (query.get("mac") or [""])[0]
            db = self._db()
            snap = localize_snapshot(brain.snapshot(db, hours=self.hours), lang)
            dev = next((d for d in snap["devices"] if d["mac"] == mac), None)
            if not dev:
                dev = inventory_device(db, mac, lang)  # known, but no DNS in the window
            if not dev:
                self._error(404, "device_not_found", lang)
                return
            dev = dict(dev)
            row = db.execute("SELECT first_seen, last_seen, randomized FROM devices "
                             "WHERE mac = ?", (mac,)).fetchone()
            if row:
                dev.update(first_seen=row["first_seen"], last_seen=row["last_seen"],
                           randomized=bool(row["randomized"]))
            dev["threats"] = [t for t in snap["threats"] if t.get("mac") == mac]
            dev["trend"] = store.daily_trend(db, mac, days=7)
            dev["bandwidth_trend"] = store.bandwidth_trend(db, mac, days=7)
            dev["has_bandwidth"] = snap["has_bandwidth"]
            dev.update(device_extras(db, mac, self.hours, lang, local=self.admin))
            # Stage N: what it announced on the LAN + the router ports it opened
            dev["identity"] = identify.device_report(db, mac, lang, dev.get("label"),
                                                     dev.get("hostname"))
            dev["upnp"] = [upnp.localize(m, lang) for m in upnp.mappings(db) if m["mac"] == mac]
            # Stage Q: this device's alerts with "Why this alert?", and how loud each kind is
            dev["alerts"] = [{k: it[k] for k in ("id", "kind", "sev", "mac", "key", "title",
                                                   "text", "why", "actions")}
                             for it in inbox.alert_items(db, lang, self.hours) if it["mac"] == mac]
            dev["tuning"] = tuning.device_levels(db, mac)
            self._json(200, dev)
        elif path in D2_ROUTES:
            self._d2_get(path, query, lang)
        elif path in FAMILY_ROUTES:
            self._family_get(path, query, lang)
        elif path == "/api/person":
            db = self._db()
            raw = (query.get("id") or [""])[0].strip()
            res = people.detail(db, int(raw), lang, tz=self._tz(), env=self.env) \
                if _digits(raw) and len(raw) < 12 else None
            if res is None:
                self._error(404, "no_person", lang)
                return
            self._json(200, res)
        elif path == "/api/check/status":
            job = exposure.job_status((query.get("job") or [""])[0])
            if not job:
                self._error(404, "unknown_job", lang)
                return
            self._json(200, job)
        elif path == "/api/meta":
            accept = (query.get("accept") or [""])[0] or self.headers.get("accept-language", "")
            db = self._db()
            self._json(200, {
                # provider, model, ai_mode, ai_destination, ai_redact: never a key or URL
                **brain.describe_provider(self.env, db),
                "demo": store.is_demo(db),
                # opaque per-DB id: the page keeps its chat / notified state per database
                "db_id": hashlib.sha256(str(Path(self.db_path).resolve()).encode()).hexdigest()[:12],
                "default_lang": self._lang(),
                # round 9 U: single-key shortcuts on by default (each browser may override)
                "shortcuts": bool(settings.get(db, self.env, "ui.shortcuts")),
                "languages": [{"code": c, "name": n} for c, n, _l in i18n.LANGS],
                "browser_lang": i18n.from_accept_language(accept),
                # Stage G: the zone hours / days are counted in, so a browser in another
                # zone can say so (its own clock is checked against the Date header)
                **tz_info(self._tz()),
                # Stage M: this browser is another device (admin actions hidden), LAN
                # mode is on, and whether it is signed in with a paired session. Round 6:
                # `remote` = admin actions are NOT available here (an admin session on
                # another device is not remote); admin_session = that case
                "remote": not self.admin, "lan": self.lan, "admin": self.admin,
                "admin_session": bool(self.admin and not self.local and not self.ingress),
                "signed_in": self.session is not None, "require_auth": self.require_auth,
                "version": netwarden.__version__,
                # round 8: Settings > About (AGPL section 13 source offer); constants only
                "license": netwarden.LICENSE, "source_url": netwarden.SOURCE_URL,
                "copyright": netwarden.COPYRIGHT,
                # Stage H: opened from Home Assistant's sidebar (signed in by HA: no
                # pairing session of ours to sign out of)
                "ingress": self.ingress,
                # running as the Home Assistant add-on: env-set settings = add-on options
                "addon": bool(self.ingress_proxy),
            })
        elif path == "/api/export/devices.csv":
            db = self._db()
            self._download(export.devices_csv(db, lang), "text/csv; charset=utf-8",
                           export.filename("devices", "csv"))
        elif path == "/api/export/report.md":
            db = self._db()
            self._download(export.report_md(db, lang, hours=self.hours).encode("utf-8"),
                           "text/markdown; charset=utf-8", export.filename("report", "md"))
        elif path == "/api/report":
            self._report(query, lang)
        elif path == "/api/ai/questions":
            # Stage A: 4-6 suggested questions built from this home's data (no LLM call)
            mac = ((query.get("mac") or [""])[0] or "").strip()[:64] or None
            db = self._db()
            self._json(200, {"questions": [{"text": q["text"], "intent": q["intent"]}
                                           for q in ai_intents.suggested(db, lang, mac)]})
        elif path == "/api/ai/usage":
            # round 7 C: this month's AI tokens + estimated cost and the budget (local data)
            db = self._db()
            self._json(200, usage.summary(db, self.env))
        elif path == "/api/locale":
            self._json(200, {"lang": lang, "strings": i18n.strings(lang)})
        elif path == "/api/settings":
            if not self._local_client():
                return
            db = self._db()
            self._json(200, self._settings_body(db, lang))
        else:
            self._error(404, "not_found", lang)

    REPORT_ARGS = ("period", "privacy", "names", "people", "format")

    def _report(self, query, lang: str):
        """GET /api/report?period=7|30&privacy=full|shareable|minimal&names=&people=
        &format=html|md[&inline=1]: the shareable home report (report.py) as one file.
        A paired phone / viewer may take shareable and minimal; full (MAC / IP addresses,
        names, domains) needs an admin (this computer or an admin session)."""
        try:
            opts = report.options({k: (query.get(k) or [""])[0][:16] for k in self.REPORT_ARGS})
        except report.BadOption as e:
            self._json(400, {"error": i18n.t("err.bad_report_option", lang, option=e.key)})
            return
        if opts["privacy"] == "full" and not self.admin:
            self._error(403, "report_full_admin", lang)
            return
        body, ctype, name = report.generate(self._db(), lang, opts, env=self.env, tz=self._tz())
        if (query.get("inline") or [""])[0] == "1":   # the Report page's Preview (a new tab)
            self.send_response(200)
            self.send_header("content-type", ctype if opts["format"] == "html" else "text/plain; charset=utf-8")
            self.send_header("content-disposition", f'inline; filename="{name}"')
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._download(body, ctype, name)

    def _settings_body(self, db, lang: str) -> dict:
        """GET /api/settings: the registry described, the AI in use, which sources are
        configured (presence only - never a URL) and whether this is the demo DB."""
        return {**settings.describe(db, self.env, lang), "ai": brain.describe_provider(self.env, db),
                "connections": conntest.summary(self.env, db), "demo": store.is_demo(db)}

    def _dataset(self, name: str, db, lang: str):
        """One Overview dataset (OVERVIEW): what its own endpoint answers and what the
        /api/overview bundle carries under `name` - one function, so they never differ."""
        tz, h = self._tz(), self.hours
        if name == "inv":
            snap = localize_snapshot(brain.snapshot(db, hours=h), lang)
            return dashboard.inventory(db, snap, lang, hours=h)
        if name == "alerts":
            return alerts.localize(alerts.compute(db, recent_hours=h), lang,
                                   naming.display_names(db, lang))
        if name == "privacy":
            return privacy.report(db, hours=h, lang=lang)
        if name == "vis":
            return visibility.report(db, hours=h, lang=lang)
        if name == "status":
            st = health.status(db, self.db_path, self.env, loops=self.loops() if self.loops else {})
            return {**health.localized(st, lang), "hints": health.hints(st, lang)}
        if name == "homeAct":
            return activity.report(db, None, lang, tz=tz)
        if name == "upnp":
            return upnp.report(db, lang, hours=h)
        if name == "health":
            return nethealth.report(db, lang, hours=h, tz=tz, env=self.env)
        if name == "sug":
            return suggestions.report(db, lang, env=self.env)
        if name == "score":
            return score.report(db, lang, env=self.env, tz=tz)
        if name == "inbox":
            return inbox.report(db, lang, env=self.env, hours=h)
        if name == "pres":
            return presence.report(db, lang, tz=tz, env=self.env)
        if name == "notify":      # Stage Q: what may pop up now + quiet hours
            return notify.feed(db, self.env, lang, hours=h, tz=tz)
        if name == "hyg":
            return hygiene.report(db, lang)
        raise KeyError(name)

    def _overview(self, db, lang: str) -> dict:
        """GET /api/overview: {parts: {dataset: data}, etags: {dataset: hash}}. The page
        keeps a dataset's old object (and skips re-rendering) when its hash is unchanged;
        the whole answer carries an ETag too (304 when nothing at all changed).
        Stage G: a dataset that raises is left out and named in `failed` - the page keeps
        what it had for it and says "some information could not be loaded" - so one
        broken module never blanks the whole dashboard."""
        parts, etags, failed, last = {}, {}, [], None
        for name in OVERVIEW:
            try:
                parts[name] = self._dataset(name, db, lang)
            except Exception as e:   # noqa: BLE001 - logged; the other parts still answer
                log.warning("dataset %s failed: %s", name, health.sanitize_error(repr(e)))
                failed.append(name)
                last = e
                continue
            etags[name] = tag_of(parts[name])
        if last is not None and not parts:
            raise last             # nothing to show at all: the page's error state (500 / 503)
        return {"parts": parts, "etags": etags, "failed": failed}

    def _stream(self):
        """GET /api/stream: server-sent events from the ONE change detector (live.py).
        Same Host / auth rules as every API request (LAN mode: a paired session), but it
        never takes a DATA_GATE slot. `retry`, then `hello` {id}; with Last-Event-ID (or
        ?last=) the missed events, or `resync` when they are gone; then events as they
        come and a ": hb" comment every STREAM_HEARTBEAT s. Capped (live.MAX_STREAMS,
        live.MAX_PER_CLIENT -> 429); ends after STREAM_MAX_S or when the session is
        revoked; the page reconnects and resumes."""
        self._started = False
        url = urlparse(self.path)
        query = parse_qs(url.query)
        try:
            if not self._host_ok() or not self._auth(url.path):
                return
        except Exception as e:   # noqa: BLE001 - e.g. the database is unreadable
            self._get_failed(e)
            return
        finally:
            self._close_db()     # a stream lasts minutes: it holds no connection
        lang = self._lang((query.get("lang") or [None])[0])
        det = self.live
        if det is None:
            self._error(404, "not_found", lang)
            return
        try:
            sub = det.subscribe(self._client_key())
        except live.Full:
            self.send_response(429)
            body = json.dumps({"error": i18n.t("err.too_many_streams", lang)},
                              ensure_ascii=False).encode("utf-8")
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.send_header("retry-after", "30")
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return
        last = (self.headers.get("last-event-id") or (query.get("last") or [""])[0]).strip()[:40]
        try:
            missed = det.resume(sub, last) if last else []
            self.send_response(200)
            self.send_header("content-type", "text/event-stream; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("x-accel-buffering", "no")
            self.end_headers()
            self.wfile.write(f"retry: {STREAM_RETRY_MS}\n\n".encode())
            if missed is None:
                self._sse_event("resync", {"id": det.last_id()}, det.last_id())
            else:
                for ev in missed:
                    self._sse_event(ev["type"], ev, ev["id"])
            self._sse_event("hello", {"id": det.last_id()}, det.last_id())
            ends = time.monotonic() + STREAM_MAX_S
            checked = time.monotonic()
            while time.monotonic() < ends:
                evs = sub.wait(self.STREAM_HEARTBEAT)
                if evs is None:
                    break
                # a revoked / expired session gets no more data - checked on a timer, not
                # only on a quiet heartbeat (a busy stream may never have one)
                if self.token and time.monotonic() - checked >= self.STREAM_HEARTBEAT:
                    checked = time.monotonic()
                    if not self._session_alive():
                        break
                for ev in evs:
                    self._sse_event(ev["type"], ev, ev["id"])
                if not evs:
                    self.wfile.write(b": hb\n\n")
                    self.wfile.flush()
                    if self.warmer:            # an open dashboard keeps the cache warm
                        self.warmer.touch()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, TimeoutError,
                OSError):
            pass                               # the tab went away
        finally:
            sub.close()
            self.close_connection = True

    STREAM_HEARTBEAT = STREAM_HEARTBEAT

    def _session_alive(self) -> bool:
        db = store.connect(self.db_path)   # its own: the stream keeps no connection open
        try:
            return pairing.check(db, self.token) is not None
        finally:
            db.close()

    def _sse_event(self, event: str, obj: dict, eid: str | None = None):
        frame = (f"id: {eid}\n" if eid else "") + f"event: {event}\n" + \
            "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
        self.wfile.write(frame.encode("utf-8"))
        self.wfile.flush()

    def _service_worker(self):
        """GET /sw.js: the offline fallback worker, stamped with the asset version so a
        new release replaces it (and its cache) without a hard refresh. Served from the
        root so its scope is the whole dashboard; always revalidated."""
        body, ctype = static_file("sw.js")
        body = body.replace(VERSION_MARK, asset_version().encode())
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _tz(self):
        return activity.local_tz(self.env.get("NETWARDEN_TZ") or activity.SETTING_TZ)

    def _d2_get(self, path, query, lang):
        """Stage D2 read-only endpoints: activity, timeline, search, reverse lookups,
        people / rooms / type choices."""
        arg = lambda k: (query.get(k) or [""])[0].strip()  # noqa: E731
        db = self._db()
        if path == "/api/activity":
            mac = arg("mac") or None
            if mac and not db.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
                self._error(404, "device_not_found", lang)
                return
            self._json(200, activity.report(db, mac, lang, tz=self._tz()))
        elif path == "/api/timeline":
            items = timeline.timeline(db, arg("mac"), lang, tz=self._tz())
            if items is None:
                self._error(404, "device_not_found", lang)
                return
            self._json(200, {"mac": arg("mac"), "items": items})
        elif path == "/api/search":
            self._json(200, search.search(db, arg("q"), lang))
        elif path == "/api/service":
            res = search.service_detail(db, arg("name"), lang)
            if res is None:
                self._error(404, "service_not_found", lang)
                return
            self._json(200, res)
        elif path == "/api/domain":
            res = search.domain_detail(db, arg("d"), lang)
            if res is None:
                self._error(400, "no_domain", lang)
                return
            self._json(200, res)
        elif path == "/api/people":
            # Stage P: every person as a card; "items" keeps the old per-owner shape
            self._json(200, people.cards(db, lang, tz=self._tz(), env=self.env))
        elif path == "/api/rooms":
            names = store.device_names(db)
            self._json(200, {"items": [{**g, "names": [names.get(m, m) for m in g["macs"]]}
                                       for g in store.profile_values(db, "room")]})
        else:  # /api/types
            self._json(200, {"types": devicetype.type_list(lang)})

    def _family_get(self, path, query, lang):
        """Stage F read-only endpoints: estimated screen time, bedtime rules, this week vs
        last week, and the printable weekly report (an HTML page)."""
        arg = lambda k: (query.get(k) or [""])[0].strip()  # noqa: E731
        db = self._db()
        tz = self._tz()
        if path == "/api/screentime":
            raw = arg("days") or str(screentime.DEFAULT_DAYS)
            if not _digits(raw) or len(raw) > 4 or not 1 <= int(raw) <= screentime.MAX_DAYS:
                self._error(400, "bad_days", lang)
                return
            mac = arg("device") or None
            if mac and not db.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone():
                self._error(404, "device_not_found", lang)
                return
            owner = store.clean_text(arg("owner")) or None
            pid = arg("person")
            if pid and not (_digits(pid) and len(pid) < 12 and store.person(db, int(pid))):
                self._error(404, "no_person", lang)
                return
            self._json(200, screentime.report(db, lang, int(raw), mac=mac, owner=owner, tz=tz,
                                              person_id=int(pid) if pid else None))
        elif path == "/api/bedtime":
            self._json(200, bedtime.report(db, lang, tz=tz))
        elif path == "/api/weekly":
            self._json(200, weekly.report(db, lang, tz=tz))
        else:  # /report/weekly: a print-friendly page, everything escaped server-side
            body = family_report.render(db, lang, tz=tz, hours=self.hours,
                                        version=asset_version(), base=self.base).encode("utf-8")
            self._send(200, body, STATIC_TYPES[".html"])   # personal: no-store, no ETag

    def _bedtime_post(self, db, path: str, payload: dict, lang: str):
        """POST /api/bedtime {rule} (create / update), /api/bedtime/delete {id},
        /api/bedtime/preview {rule}. Validated (bedtime.validate), capped at MAX_RULES.
        Rules only ever make netwarden NOTIFY; nothing on the network changes."""
        tz = self._tz()
        if path == "/api/bedtime/delete":
            rid = payload.get("id")
            if isinstance(rid, bool) or not isinstance(rid, int):
                raise BadRequest()
            gone = store.delete_bedtime_rule(db, rid)
            if gone is None:
                self._error(404, "rule_not_found", lang)
                return
            self._json(200, {"ok": True, "deleted": gone, **bedtime.report(db, lang, tz=tz)})
            return
        try:
            rule = bedtime.validate(db, payload.get("rule"))
        except bedtime.BadRule as e:
            self._json(400, {"error": i18n.t("err." + e.code, lang), "field": e.field})
            return
        if path == "/api/bedtime/preview":
            self._json(200, bedtime.preview(db, rule, lang, tz=tz))
            return
        rules = store.bedtime_rules(db)
        if rule["id"] is not None and not any(r["id"] == rule["id"] for r in rules) \
                and not payload.get("restore"):
            self._error(404, "rule_not_found", lang)
            return
        if not any(r["id"] == rule["id"] for r in rules) and len(rules) >= bedtime.MAX_RULES:
            self._error(409, "too_many_rules", lang)
            return
        rid = store.save_bedtime_rule(db, rule)
        self._json(200, {"ok": True, "id": rid, **bedtime.report(db, lang, tz=tz)})

    def _person_id(self, db, payload: dict, key: str = "id") -> dict:
        pid = payload.get(key)
        p = store.person(db, pid) if isinstance(pid, int) and not isinstance(pid, bool) \
            and 1 <= pid <= store.MAX_ROWID else None
        if p is None:
            raise BadRequest("no_person")
        return p

    def _people_post(self, db, path: str, payload: dict, lang: str):
        """Stage P. POST /api/people {person} (create / update), /api/people/delete {id}
        (-> undo token), /api/people/restore {undo}, /api/people/assign {items} (-> the
        before-state to post back for Undo), /api/presence/settings {id, enabled?,
        confirm?, devices?, default_devices?, notify_arrive?, notify_leave?},
        /api/presence/forget {id}, /api/presence/link {mac, person, dismiss?} (-> undo
        token), /api/presence/unlink {undo}. Only the user's own notes change."""
        ok = lambda **kw: self._json(200, {"ok": True, **kw})  # noqa: E731
        try:
            if path == "/api/people":
                clean = people.validate(db, payload.get("person"))
                before = store.person(db, clean["id"]) if clean["id"] else None
                pid = people.save(db, clean)
                ok(id=pid, before=before and {k: before[k] for k in people.FIELDS})
            elif path == "/api/people/delete":
                gone = store.delete_person(db, self._person_id(db, payload)["id"])
                ok(deleted={"name": gone["person"]["name"], "devices": len(gone["macs"]),
                            "rules": len(gone["rules"])},
                   undo=UNDO.put(self.db_path, "person", gone))
            elif path == "/api/people/restore":
                gone = UNDO.take(self.db_path, "person", payload.get("undo"))
                if gone is None:
                    raise BadRequest("undo_expired")
                ok(id=store.restore_person(db, gone))
            elif path == "/api/people/assign":
                items = people.assign_items(db, payload.get("items"))
                ok(before=people.assign(db, items))
            elif path == "/api/presence/settings":
                p = self._person_id(db, payload)
                allowed = {"id", "enabled", "confirm", "devices", "default_devices",
                           "notify_arrive", "notify_leave", "lang"}
                if set(payload) - allowed or any(
                        k in payload and not isinstance(payload[k], bool)
                        for k in ("enabled", "confirm", "default_devices", "notify_arrive",
                                  "notify_leave")):
                    raise BadRequest()
                enable = payload.get("enabled") is True and not p["presence"]
                devices = payload.get("devices")
                if devices is not None and (not isinstance(devices, list) or len(devices) > 50
                                            or any(not isinstance(m, str) for m in devices)):
                    raise BadRequest()
                # turning tracking ON (or choosing what counts) needs this computer + a
                # confirmed privacy note; switching it off / notifications does not
                if (enable or devices is not None or payload.get("default_devices")) \
                        and not self._local_client():
                    return
                if enable and payload.get("confirm") is not True:
                    raise BadRequest("presence_confirm")
                presence.set_presence(db, p["id"], enabled=payload.get("enabled"),
                                      devices=[m.lower() for m in devices]
                                      if devices is not None else None,
                                      notify_arrive=payload.get("notify_arrive"),
                                      notify_leave=payload.get("notify_leave"),
                                      default_devices=payload.get("default_devices") is True)
                ok(person=store.person(db, p["id"]))
            elif path == "/api/presence/forget":
                ok(deleted=presence.forget(db, self._person_id(db, payload)["id"]))
            elif path == "/api/presence/link":
                mac = mac_field(payload, db)
                p = self._person_id(db, payload, "person")
                if payload.get("dismiss") is True:
                    store.add_ack(db, mac, presence.LINK_ACK)   # Undo: /api/unack
                    ok()
                    return
                before = presence.link(db, mac, p["id"])
                ok(undo=UNDO.put(self.db_path, "link", before))
            else:   # /api/presence/unlink
                before = UNDO.take(self.db_path, "link", payload.get("undo"))
                if before is None:
                    raise BadRequest("undo_expired")
                presence.unlink(db, before)
                ok()
        except people.BadPerson as e:
            self._json(400, {"error": i18n.t("err." + e.code, lang), "field": e.field})
        except ValueError as e:
            if isinstance(e, BadRequest):
                raise
            raise BadRequest(str(e) if str(e) in PEOPLE_ERRORS else "bad_json") from None

    def _suggestion_post(self, db, raw_id: str, payload: dict, lang: str):
        """POST /api/suggestions/<id> {status: open|done|dismissed|snoozed, days?: 1-90}.
        Only the user's own note changes; nothing is ever applied to the network."""
        sid = unquote(raw_id)
        status = text_field(payload, "status")
        days = payload.get("days")
        if days is not None and (isinstance(days, bool) or not isinstance(days, int)):
            raise BadRequest("bad_snooze")
        try:
            suggestions.set_status(db, sid, status, days, env=self.env)
        except LookupError:
            self._error(404, "suggestion_not_found", lang)
            return
        except ValueError as e:
            raise BadRequest({"bad_days": "bad_snooze", "bad_status": "bad_status"}
                             .get(str(e), "bad_suggestion")) from None
        self._json(200, {"ok": True, **suggestions.report(db, lang, env=self.env)})

    def _read_json(self) -> dict | None:
        """The POST body as a JSON object, or None after answering 415 / 413 / 400.
        The content type and length are checked BEFORE anything is read."""
        lang = self._lang()
        # JSON only: a cross-site form/fetch can't send application/json without a CORS
        # preflight (which we never grant), so other web pages can't drive these actions.
        ctype = (self.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self.close_connection = True       # the unread body must not be parsed as a request
            self._error(415, "bad_content_type", lang)
            return None
        raw = (self.headers.get("content-length") or "0").strip()
        if not _digits(raw):
            self.close_connection = True
            self._error(400, "bad_length", lang)
            return None
        if int(raw) > MAX_BODY:
            self.close_connection = True
            self._error(413, "too_large", lang)
            return None
        try:
            body = self.rfile.read(int(raw))
        except OSError:   # TimeoutError: the client promised more bytes than it sent
            body = None
        if body is None or len(body) != int(raw):   # stalled or cut short: never half-parsed
            self.close_connection = True
            self._error(400, "bad_length", lang)
            return None
        try:
            payload = json.loads(body or b"{}")
        except (ValueError, RecursionError):   # RecursionError: "[[[[..." nested 100k deep
            payload = None
        if not isinstance(payload, dict):
            self._error(400, "bad_json", lang)
            return None
        return payload

    def do_POST(self):
        self._started = False
        lang = self._lang()
        try:
            if not self._host_ok() or not self._auth(urlparse(self.path).path):
                return
            payload = self._read_json()
            if payload is None:
                return
            lang = self._lang(payload.get("lang") if isinstance(payload.get("lang"), str) else None)
            self._post(urlparse(self.path).path, payload, lang)
            live.poke(self.db_path)   # a note changed: open dashboards (other tabs) hear it
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True   # the browser went away mid-answer
        except BadRequest as e:
            self._post_failed(400, e.key, lang)
        except (TypeError, OverflowError, RecursionError, UnicodeError):
            # a well-formed JSON body of the wrong shape that slipped past a validator
            # (a list where a string was expected, an id beyond SQLite's 64 bits, a lone
            # surrogate SQLite can't store): the client's mistake, so a 400 - never a
            # dropped connection
            self._post_failed(400, "bad_json", lang)
        except Exception as e:   # a bug / a busy DB: answer instead of dropping the connection
            log.warning("POST %s failed: %s", urlparse(self.path).path,
                        health.sanitize_error(repr(e)))
            self._post_failed(*failure_answer(e), lang)
        finally:
            self._close_db()

    def _post_failed(self, code: int, key: str, lang: str):
        """Answer a POST that raised - unless its answer had already started (a stream):
        then all that is left is to close the connection."""
        if self._started:
            self.close_connection = True
            return
        try:
            self._error(code, key, lang)
        except OSError:
            self.close_connection = True

    def _post(self, path: str, payload: dict, lang: str):
        db = self._db()

        if path.startswith("/api/pair") or path == "/api/session/logout":
            self._pair_post(db, path, payload, lang)
            return

        # Opt-in exposure check of the user's OWN devices (TCP connect only, background).
        if path == "/api/check":
            if not self._local_client():
                return
            mac = text_field(payload, "mac")   # exposure.targets() checks it is in the inventory
            everything = payload.get("all") is True
            if not (mac or everything):
                self._error(400, "no_target", lang)
                return
            try:
                job = exposure.start_job(self.db_path, None if everything else mac, everything)
            except exposure.DemoRefused:
                self._json(409, {"error": i18n.t("exposure.demo_refused", lang), "demo": True})
                return
            except exposure.RefusedTarget as e:
                self._json(400, {"error": i18n.t("exposure.refused_target", lang, ip=e)})
                return
            self._json(202, {"job": job["id"], **job})
            return

        # Local, no-LLM actions: the user's own notes. Read-only to the NETWORK.
        if path in ("/api/ack", "/api/unack") and payload.get("mac") == nethealth.NETWORK_KEY:
            # an outage is about the whole network: the pseudo device "network", outage keys only
            key = text_field(payload, "domain")
            if not re.fullmatch(re.escape(nethealth.ACK_PREFIX) + r"\d{1,12}", key):
                raise BadRequest("bad_mac")
            (store.add_ack if path == "/api/ack" else store.remove_ack)(db, nethealth.NETWORK_KEY, key)
            self._json(200, {"ok": True})
            return

        if path.startswith(SUGGESTION_POST):
            self._suggestion_post(db, path[len(SUGGESTION_POST):], payload, lang)
            return

        if path in ("/api/ack", "/api/unack", "/api/label"):
            mac = mac_field(payload, db)
            if path in ("/api/ack", "/api/unack"):
                key = text_field(payload, "domain")
                if len(key) > MAX_KEY:
                    raise BadRequest()
                (store.add_ack if path == "/api/ack" else store.remove_ack)(db, mac, key)
            else:  # /api/label  (empty label clears it); one line, capped, still escaped on output
                store.set_label(db, mac, store.clean_text(text_field(payload, "label"), MAX_LABEL),
                                store.clean_text(text_field(payload, "note"), MAX_NOTE))
            self._json(200, {"ok": True})
            return

        # The user's own type / owner / room notes: only the fields sent change, an
        # empty value clears one. Free text is capped (store.clean_text) and escaped on output.
        if path == "/api/profile":
            mac = mac_field(payload, db)
            fields = {f: payload[f] for f in store.PROFILE_FIELDS if f in payload}
            if any(v is not None and not isinstance(v, str) for v in fields.values()):
                self._error(400, "bad_json", lang)
                return
            if "type" in fields:
                fields["type"] = (fields["type"] or "").strip()
                if fields["type"] and fields["type"] not in devicetype.TYPES:
                    self._error(400, "bad_type", lang)
                    return
            if "shared" in payload:     # Stage P: the household's device (clears the owner)
                if not isinstance(payload["shared"], bool):
                    raise BadRequest()
                fields["shared"] = payload["shared"]
            if fields.get("owner"):     # one list of people: same checks as POST /api/people
                try:
                    fields["owner"] = people.owner_name(db, fields["owner"])
                except people.BadPerson as e:
                    self._json(400, {"error": i18n.t("err." + e.code, lang), "field": "owner"})
                    return
            store.set_profile(db, mac.strip(), **fields)
            self._json(200, {"ok": True, "profile": store.get_profiles(db).get(mac.strip())})
            return

        if path in PEOPLE_POSTS:
            self._people_post(db, path, payload, lang)
            return

        if path in ("/api/bedtime", "/api/bedtime/delete", "/api/bedtime/preview"):
            self._bedtime_post(db, path, payload, lang)
            return

        if path == "/api/chat/stream":
            self._chat_stream(db, payload, lang)
            return

        if path == "/api/settings":
            self._settings_post(db, payload, lang)
            return

        # "Preview what will be sent": the exact (redacted) prompt, no model is called.
        if path == "/api/chat/preview":
            req = self._chat_request(payload, lang)
            if req is None:
                return
            mode, msgs, mac, alert = req
            self._json(200, brain.preview(db, self.env, mode, msgs, hours=self.hours,
                                          lang=lang, mac=mac, alert=alert))
            return

        if path == "/api/ai/test":
            self._ai_test(db, lang)
            return

        if path in TUNING_POSTS:
            self._tuning_post(db, path, payload, lang)
            return

        if path in ("/api/inbox/act", "/api/backup/preview", "/api/restore", "/api/setup",
                    "/api/setup/scan") or path in TEST_POSTS:
            self._stage_x_post(db, path, payload, lang)
            return

        # LLM-backed actions; the answer language follows the request's "lang". Round 7
        # fix: the same monthly budget check as the chat stream - over it -> 409 {"error",
        # "budget": budget_event} and NOTHING sent; resend with "budget_ok": true.
        ok = payload.get("budget_ok") is True
        try:
            provider = brain.provider_from_env(self.env, db)
            if path == "/api/insight":
                text = brain.insights(db, provider, hours=self.hours, lang=lang, env=self.env,
                                      budget_ok=ok)
            elif path == "/api/ask":
                q = text_field(payload, "question")[:brain.MAX_TURN_CHARS]
                if not q:
                    self._error(400, "empty_question", lang)
                    return
                text = brain.ask(db, provider, q, hours=self.hours, lang=lang, env=self.env,
                                 budget_ok=ok)
            elif path == "/api/chat":
                msgs = brain.clean_messages(payload.get("messages") or [])
                if msgs is None:
                    raise BadRequest()
                if not msgs or msgs[-1]["role"] != "user" or not msgs[-1]["content"].strip():
                    self._error(400, "empty_question", lang)
                    return
                text = brain.converse(db, provider, msgs, hours=self.hours, lang=lang,
                                      env=self.env, budget_ok=ok)
            else:
                self._error(404, "not_found", lang)
                return
            self._json(200, {"text": text})
        except brain.BudgetNeeded as e:
            b = budget_event(e.gate, lang)
            self._json(409, {"error": b["text"], "budget": b})
        except brain.LLMError as e:
            self._json(502, {"error": self._llm_error(e, lang)})

    def _chat_stream(self, db, payload: dict, lang: str):
        """POST /api/chat/stream {mode: "chat"|"insight", messages, mac?, lang} ->
        text/event-stream: `data: {"t": "<text>"}` per chunk, then `event: done`, or
        `event: error` + {"error"} (sanitized). The browser aborting the request (Stop)
        closes the generator, which closes the upstream LLM connection too."""
        req = self._chat_request(payload, lang)
        if req is None:
            return
        mode, msgs, mac, alert = req
        try:
            provider = brain.provider_from_env(self.env, db)
        except brain.LLMError as e:
            self._json(502, {"error": self._llm_error(e, lang)})
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("x-accel-buffering", "no")
        self.end_headers()
        # Stage A: besides text, `event: status` ("Looking up ..."), `event: tool` (a lookup
        # made + the exact JSON sent), `event: note` (no_tools | tool_limit, localized) and
        # `event: suggest` (questions offline mode can answer)
        # Round 7 C: `event: usage` (tokens + estimated cost, after the answer) and `event:
        # budget` (INSTEAD of an answer: the monthly budget - the page asks, then resends
        # with "budget_ok": true)
        gen = brain.stream_events(db, provider, mode, msgs, hours=self.hours, lang=lang, mac=mac,
                                  alert=alert, env=self.env,
                                  budget_ok=payload.get("budget_ok") is True)
        try:
            try:
                for ev in gen:
                    if ev.get("t"):
                        self._sse(None, {"t": ev["t"]})
                    elif "usage" in ev:
                        self._sse("usage", ev["usage"])
                    elif "budget" in ev:
                        self._sse("budget", budget_event(ev["budget"], lang))
                    elif "status" in ev:
                        self._sse("status", ev["status"])
                    elif "tool" in ev:
                        self._sse("tool", ev["tool"])
                    elif "note" in ev:
                        self._sse("note", {"key": ev["note"],
                                           "text": i18n.t("app.ai.note_" + ev["note"], lang)})
                    elif "suggest" in ev:
                        self._sse("suggest", {"questions": ev["suggest"]})
                self._sse("done", {})
            except brain.LLMError as e:
                self._sse("error", {"error": self._llm_error(e, lang)})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                raise
            except Exception as e:   # noqa: BLE001 - never a traceback page mid-stream
                log.warning("chat stream failed: %s", health.sanitize_error(
                    f"{type(e).__name__}: {e}", brain.secrets(self.env)))
                self._sse("error", {"error": i18n.t("err.stream_failed", lang)})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass                      # the user pressed Stop / left: stop generating
        finally:
            gen.close()
            self.close_connection = True

    def _chat_request(self, payload: dict, lang: str):
        """(mode, messages, mac, alert) of a /api/chat/stream or /api/chat/preview body, or
        None after answering 400."""
        mode = payload.get("mode") or "chat"
        msgs = brain.clean_messages(payload.get("messages") or [])
        mac = payload.get("mac")
        alert = payload.get("alert")      # Stage Q: {kind, mac, key} - "Ask AI about this alert"
        if mode not in ("chat", "insight") or msgs is None or \
                (mac is not None and not isinstance(mac, str)) or \
                (alert is not None and not (isinstance(alert, dict) and
                                            isinstance(alert.get("kind"), str) and
                                            isinstance(alert.get("key"), str) and
                                            len(alert["key"]) <= MAX_KEY and
                                            (alert.get("mac") is None or
                                             isinstance(alert.get("mac"), str)))):
            self._error(400, "bad_json", lang)
            return None
        if mode == "chat" and (not msgs or msgs[-1]["role"] != "user"
                               or not msgs[-1]["content"].strip()):
            self._error(400, "empty_question", lang)
            return None
        alert = {k: alert.get(k) for k in ("kind", "mac", "key")} if alert else None
        return mode, msgs, (mac or "").strip()[:64] or None, alert

    # --- Stage M: pairing ---------------------------------------------------------

    def _pair_base(self) -> str:
        """Where a paired browser reaches this dashboard: the LAN URL in LAN mode, else
        this computer's loopback (NETWARDEN_REQUIRE_AUTH=1: another browser here)."""
        return self.lan_url or f"http://127.0.0.1:{self.server.server_address[1]}"

    def _pair_sessions(self):
        """GET /api/pair/sessions (this computer only): LAN mode state + paired browsers."""
        db = self._db()
        try:
            cur = self.session["id"] if self.session else None
            port = urlparse(self.lan_url).port if self.lan_url else self.server.server_address[1]
            lan_ip = urlparse(self.lan_url).hostname if self.lan_url else pairing.lan_address()
            self._json(200, {"lan": self.lan, "url": self._pair_base(), "bind_all": self.bind_all,
                             "require_auth": self.require_auth,
                             "lan_setting": settings.get(db, self.env, "lan.enabled"),
                             "sessions": pairing.sessions(db, current=cur),
                             # under WSL: the Hyper-V firewall rule a phone needs (shown only)
                             "wsl_firewall": wslnet.advice(port, lan_ip, _lan_network())})
        finally:
            db.close()

    def _pair_post(self, db, path: str, payload: dict, lang: str):
        """POST /api/pair {code} (public: trade a one-time code for a session cookie),
        /api/session/logout (this browser), and - this computer only - /api/pair/new,
        /api/pair/revoke {id}, /api/pair/revoke_all."""
        if path == "/api/pair":
            ip = self.client_address[0]
            wait = self.limiter.attempt(ip)   # checked AND reserved in one step
            if wait:
                self._json(429, {"error": i18n.t("err.pair_locked", lang, min=math.ceil(wait / 60)),
                                 "retry_after": math.ceil(wait)})
                return
            try:
                got = pairing.redeem(db, text_field(payload, "code"),
                                     self.headers.get("user-agent") or "")
            except BaseException:
                self.limiter.fail(ip)   # a malformed attempt still counts as a guess
                raise
            if not got:
                self.limiter.fail(ip)
                self._error(400, "pair_bad_code", lang)
                return
            self.limiter.success(ip)
            token, sid = got
            self._cookie = pairing.cookie(token)
            admin = bool((pairing.check(db, token) or {}).get("admin"))
            # never the code or the token
            log.info("paired a new %sbrowser (session %d)", "ADMIN " if admin else "", sid)
            self._json(200, {"ok": True})
        elif path == "/api/session/logout":
            if self.token:
                pairing.logout(db, self.token)
                self._cookie = pairing.clear_cookie()
            self._json(200, {"ok": True})
        elif path == "/api/pair/new" and self._local_client():
            c = pairing.new_code(db)
            url = f"{self._pair_base()}/pair#{c['code']}"   # the code rides in the fragment only
            self._json(200, {"code": c["display"], "url": url, "qr": qr.data_uri(url),
                             "expires_at": c["expires_at"], "ttl_s": c["ttl_s"], "lan": self.lan})
        elif path == "/api/pair/revoke" and self._local_client():
            sid = payload.get("id")
            if isinstance(sid, bool) or not isinstance(sid, int):
                raise BadRequest()
            if not pairing.revoke(db, sid):
                self._error(404, "session_not_found", lang)
                return
            log.info("revoked a paired browser (session %d)", sid)
            self._json(200, {"ok": True})
        elif path == "/api/pair/revoke_all" and self._local_client():
            n = pairing.revoke_all(db)
            log.info("revoked all paired browsers (%d)", n)
            self._json(200, {"ok": True, "revoked": n})
        elif path not in ADMIN_POSTS:   # (an admin path from elsewhere was answered 403)
            self._error(404, "not_found", lang)

    def _local_client(self) -> bool:
        """Settings, pairing, port checks and the AI connection test are admin actions:
        this computer's own browser, or an admin session (headless installs). _auth()
        already refuses them for other devices; this is the second lock, inside the
        handlers themselves."""
        if self.admin:
            return True
        self._error(403, "loopback_only", self._lang())
        return False

    def _settings_post(self, db, payload: dict, lang: str):
        """POST /api/settings {values: {key: value|null}} -> the new GET /api/settings.
        Validated against the registry; env-set and secret keys are refused; all or
        nothing. The language / time zone apply at once."""
        if not self._local_client():
            return
        changes = payload.get("values")
        if not isinstance(changes, dict) or not changes or len(changes) > len(settings.REGISTRY):
            raise BadRequest()
        try:
            done = settings.update(db, self.env, changes)
        except settings.SettingError as e:
            self._json(400, {"error": i18n.t("err." + e.code, lang), "key": e.key})
            return
        settings.apply(db, self.env)
        if "ui.language" in done and not Handler.lang_pinned:
            Handler.lang = settings.get(db, self.env, "ui.language")
        log.info("settings changed: %s", ", ".join(sorted(done)))   # keys only, never values
        self._json(200, self._settings_body(db, lang))

    def _tuning_body(self, db, lang: str) -> dict:
        """GET /api/tuning: every mute / snooze / sensitivity change in force (tuning.state)
        with its kind and target named, plus what the page may offer."""
        names = naming.display_names(db, lang)
        entries = []
        for e in tuning.state(db, self.env):
            target = i18n.t("app.tune.all", lang) if e["mac"] == tuning.ALL else \
                i18n.t("app.tune.network", lang) if e["mac"] == nethealth.NETWORK_KEY else \
                names.get(e["mac"], e["mac"])
            entries.append({**e, "kind_name": i18n.t("app.tune.kind." + e["kind"], lang),
                            "target": target,
                            "admin": e["source"] == "setting"})
        return {"entries": entries, "kinds": list(tuning.KINDS),
                "device_kinds": list(tuning.DEVICE_KINDS), "levels": list(tuning.LEVELS),
                "snoozes": list(tuning.SNOOZES)}

    def _tuning_post(self, db, path: str, payload: dict, lang: str):
        """Stage Q: the user's own alert tuning (acks rows, tuning.py) - anyone signed in,
        like the inbox; turning a legacy SETTING switch back on is this computer's only."""
        try:
            if path == "/api/tuning":
                # every field known (a misspelled "snooze" must not be silently ignored)
                if set(payload) - {"kind", "mac", "level", "for", "confirm", "lang"}:
                    raise tuning.BadTuning("bad_tuning")
                snooze = payload.get("for")
                if snooze is not None and not isinstance(snooze, str):
                    raise tuning.BadTuning("bad_tuning")
                kind, target = payload.get("kind"), payload.get("mac")
                if payload.get("level") == "off" and target in (None, tuning.ALL) \
                        and kind in tuning.CRITICAL_KINDS:
                    # no more threat / open-port / risky-forward alerts for anyone: this
                    # computer only, after the page said what that means
                    if not self._local_client():
                        return
                    if payload.get("confirm") is not True:
                        raise tuning.BadTuning("tune_confirm")
                res = tuning.set_level(db, kind, target, payload.get("level"), snooze)
                self._json(200, {"ok": True, **res})
            elif path == "/api/tuning/undo":
                if set(payload) - {"kind", "mac", "before", "lang"}:
                    raise tuning.BadTuning("bad_tuning")
                kind, rows = payload.get("kind"), payload.get("before")
                mac = tuning._check(db, kind, payload.get("mac"))
                if not isinstance(rows, list) or len(rows) > 2:
                    raise tuning.BadTuning("bad_tuning")
                rows = [tuning.clean_row(r) for r in rows]
                if any(tuning.silences_critical(mac, r["domain"]) for r in rows) \
                        and not self._local_client():
                    return
                tuning.restore_rows(db, mac, kind, rows)
                self._json(200, {"ok": True})
            elif path in ("/api/tuning/restore", "/api/tuning/restore_undo"):
                entry = payload.get("id") if path.endswith("restore") else None
                undo = payload.get("undo") if path.endswith("_undo") else None
                is_setting = (isinstance(entry, str) and entry.startswith("setting|")) or \
                    (isinstance(undo, dict) and "setting" in undo)
                row = undo.get("row") if isinstance(undo, dict) else None
                silences = isinstance(row, dict) and tuning.silences_critical(
                    row.get("mac"), row.get("domain"))
                if (is_setting or silences) and not self._local_client():
                    return
                if path == "/api/tuning/restore":
                    self._json(200, {"ok": True, "undo": tuning.restore(db, entry, self.env)})
                else:
                    tuning.restore_undo(db, undo, self.env)
                    self._json(200, {"ok": True})
            else:   # /api/notify/seen {id, seen?}
                seen = payload.get("seen", True)
                if not isinstance(seen, bool) or not notify.mark_seen(db, payload.get("id"), seen):
                    raise tuning.BadTuning("no_summary")
                self._json(200, {"ok": True})
        except tuning.BadTuning as e:
            raise BadRequest(e.code) from None

    def _stage_x_post(self, db, path: str, payload: dict, lang: str):
        """Stage X: inbox actions (anyone signed in); backup preview / restore, connection
        tests and the first-run wizard (this computer only - ADMIN_POSTS + a second lock)."""
        if path == "/api/inbox/act":
            action, undo = payload.get("action"), payload.get("undo")
            if not isinstance(action, str) or (undo is not None and not isinstance(undo, str)):
                raise BadRequest("bad_action")
            try:
                n = inbox.act(db, action, payload.get("items"), payload.get("days"),
                              env=self.env, undo=undo, hours=payload.get("hours"))
            except inbox.BadRef as e:
                raise BadRequest(e.code) from None
            self._json(200, {"ok": True, "n": n, **inbox.report(db, lang, self.env, self.hours)})
            return
        if not self._local_client():
            return
        if path in ("/api/backup/preview", "/api/restore"):
            mode = payload.get("mode") or "merge"
            try:
                if mode not in backup.MODES:
                    raise backup.BadBackup("backup_mode")
                data = backup.validate(payload.get("backup"))
                if path == "/api/backup/preview":
                    self._json(200, backup.preview(db, data, mode, self.env))
                    return
                before = backup.restore(db, data, mode, self.env)
            except backup.BadBackup as e:
                self._json(400, {"error": i18n.t("err." + e.code, lang), "code": e.code,
                                 "section": e.section})
                return
            settings.apply(db, self.env)
            if not Handler.lang_pinned:
                Handler.lang = settings.get(db, self.env, "ui.language")
            log.info("restored a backup (%s, %d changes)", mode, before["changes"])
            self._json(200, {"ok": True, **before})
        elif path in TEST_POSTS:
            res = conntest.check(path[len("/api/test/"):], self.env, db)
            if res["error_kind"]:
                res["error_text"] = i18n.t("err.conn_" + res["error_kind"], lang)
            self._json(200, res)
        elif path == "/api/setup":
            step, done = payload.get("step"), payload.get("done")
            try:
                firstrun.save(db, step, done)
            except ValueError:
                raise BadRequest() from None
            self._json(200, {**firstrun.status(db, self.env), "local": True})
        else:   # /api/setup/scan
            try:
                job = firstrun.start_scan(self.db_path)
            except firstrun.SetupRefused as e:
                self._json(409, {"error": i18n.t("err.setup_" + e.code, lang), "code": e.code})
                return
            self._json(202, {"job": job["id"], **job})

    def _ai_test(self, db, lang: str):
        """POST /api/ai/test: on an explicit click, list the models of the configured
        LOCAL / LAN OpenAI-compatible server and ask it for a one-word reply. Refused for
        cloud destinations (never spends money, never sends data out) and when offline."""
        if not self._local_client():
            return
        cfg = brain.ai_config(self.env, db)
        if cfg["mode"] != "openai_compat":
            self._error(409, "ai_test_mode", lang)
            return
        if cfg["destination"] not in ("local", "lan"):
            self._error(409, "ai_test_cloud", lang)
            return
        p = localai.OpenAICompatibleProvider(cfg["base_url"], cfg["model"],
                                             api_key=self.env.get("NETWARDEN_AI_KEY"),
                                             timeout=60, destination=cfg["destination"])
        res = localai.check_connection(p, brain.secrets(self.env))
        if res["error_kind"]:
            res["error_text"] = i18n.t("err.llm_" + res["error_kind"], lang)
        res["destination"] = cfg["destination"]
        self._json(200, res)

    def _sse(self, event, obj):
        frame = (f"event: {event}\n" if event else "") + \
                "data: " + json.dumps(obj, ensure_ascii=False) + "\n\n"
        self.wfile.write(frame.encode("utf-8"))
        self.wfile.flush()

    def _llm_error(self, e, lang: str) -> str:
        """A provider error for the user: a localized sentence for its kind, plus the
        sanitized technical detail (HTTP status, upstream message) when there is one."""
        return brain.llm_error_text(e, lang, brain.secrets(self.env))

    def log_message(self, *args):  # keep the console quiet
        pass


LOOPBACK = ("127.0.0.1", "localhost")   # IPv4 only: ThreadingHTTPServer is AF_INET


def is_loopback(host: str) -> bool:
    """A literal IPv4 loopback address or "localhost" - never a name that would go
    through DNS (127.evil.example looks loopback but resolves anywhere)."""
    if host == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_loopback


def truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


class LanError(ValueError):
    """LAN mode can't start: no private LAN address (or a public one was given)."""


MAX_CONNECTIONS = 64          # open connections per listening socket ...
MAX_REMOTE_CONNECTIONS = 24   # ... of which from other devices (LAN mode): a phone can't
                              # starve this computer's own dashboard


class DashboardServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on open connections: one more than the cap is
    closed at once instead of getting yet another thread (Handler.timeout ends idle or
    trickling ones)."""
    daemon_threads = True
    # listen() backlog. socketserver's default of 5 overflows when a page refresh opens
    # 12 connections at once (Stage P added /api/presence): the kernel drops the extra
    # SYNs and the browser retries them only after 1 s (measured: 1.05 s vs 0.13 s).
    # MAX_CONNECTIONS above still caps what is actually served.
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self._conn_lock = threading.Lock()
        self._open = {"all": 0, "remote": 0}
        self._held: dict = {}    # id(request) -> the counters it holds
        super().__init__(*args, **kwargs)

    def _kinds(self, client_address) -> tuple:
        local = Handler.is_local_client(client_address[0]) or \
            (bool(Handler.ingress_proxy) and client_address[0] == Handler.ingress_proxy)
        return ("all",) if local else ("all", "remote")

    def process_request(self, request, client_address):
        kinds = self._kinds(client_address)
        with self._conn_lock:
            full = self._open["all"] >= MAX_CONNECTIONS or \
                ("remote" in kinds and self._open["remote"] >= MAX_REMOTE_CONNECTIONS)
            if not full:
                for k in kinds:
                    self._open[k] += 1
                self._held[id(request)] = kinds
        if full:
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(request)

    def _release(self, request):
        with self._conn_lock:
            for k in self._held.pop(id(request), ()):
                self._open[k] -= 1


def make_server(db_path, port: int, env: dict, lang=None, hours: float = 24,
                host: str = "127.0.0.1", loops=None, warm: bool = False, lan: bool = False,
                lan_host: str | None = None, bind_all: bool = False,
                ingress_proxy: str | None = None,
                ingress_host: str | None = None) -> ThreadingHTTPServer:
    """Configure Handler and bind the dashboard on loopback. warm=True starts a
    runner.Warmer (Handler.warmer; stop it when the server stops).

    LAN mode (Stage M, opt-in): lan=True ALSO listens on this computer's private LAN
    address (lan_host, or the detected one; a public address is refused) in a second
    server thread - or, with bind_all, on 0.0.0.0 instead of both. Requests from other
    devices then need a paired session. Close everything with close_server(srv).
    Round 6: the lan.advertised_url setting (NETWARDEN_ADVERTISED_URL) replaces the
    detected address in the pairing QR and is answered as an extra Host / Origin.

    Stage H (Home Assistant add-on, netwarden/addon.py - never a user option):
    ingress_proxy = the Supervisor's ingress proxy address; requests from that peer are
    signed-in HA users (Handler._ingress_ok). ingress_host = the local address it
    connects to (the Supervisor network); a third listener there unless an earlier one
    already covers it. Not LAN mode: other peers there get the usual Host check."""
    if not is_loopback(host):
        raise ValueError(f"refusing to bind {host!r}: the dashboard is loopback-only "
                         "(--lan opens it to your home network, with pairing)")
    lan_ip = None
    if lan:
        lan_ip = lan_host or pairing.lan_address()
        if not lan_ip or not pairing.is_lan_ip(lan_ip):
            raise LanError(f"no private LAN address to listen on ({lan_ip or 'none found'})")
    Handler.db_path = str(db_path)
    Handler.env = env
    # server default language: --lang > NETWARDEN_LANG > the dashboard setting > zh-Hant
    Handler.lang_pinned = bool(lang or env.get("NETWARDEN_LANG"))
    db = store.connect(db_path)
    try:
        vals = settings.apply(db, env)   # also hands the time-zone setting to activity
    finally:
        db.close()
    Handler.lang = i18n.normalize(lang or env.get("NETWARDEN_LANG") or vals["ui.language"])
    Handler.hours = hours
    Handler.loops = staticmethod(loops) if loops else None  # never bound as a method
    Handler.require_auth = truthy(env.get("NETWARDEN_REQUIRE_AUTH"))
    Handler.lan, Handler.lan_hosts, Handler.lan_url, Handler.bind_all = False, frozenset(), "", False
    Handler.lan_origins, Handler.proxy_hosts = frozenset(), frozenset()
    srv = DashboardServer(("0.0.0.0" if lan and bind_all else host, port), Handler)
    srv.extra = []
    if lan:
        real_port = srv.server_address[1]
        if not bind_all:
            try:
                other = DashboardServer((lan_ip, real_port), Handler)
            except OSError:
                srv.server_close()
                raise
            threading.Thread(target=other.serve_forever, name="netwarden-lan", daemon=True).start()
            srv.extra.append(other)
        Handler.lan, Handler.bind_all = True, bool(bind_all)
        Handler.lan_hosts = frozenset({f"{lan_ip}:{real_port}"})
        Handler.lan_url = f"http://{lan_ip}:{real_port}"
        adv = vals.get("lan.advertised_url") or ""
        if adv:
            Handler.lan_url = adv
            Handler.proxy_hosts = advertised_hosts(adv) - allowed_hosts(real_port)
            Handler.lan_hosts |= Handler.proxy_hosts
            Handler.lan_origins = frozenset({adv})
    Handler.ingress_proxy = ingress_proxy or None
    covered = {host, lan_ip} | ({"0.0.0.0"} if lan and bind_all else set())
    if ingress_proxy and ingress_host and ingress_host not in covered and "0.0.0.0" not in covered:
        try:
            ing = DashboardServer((ingress_host, srv.server_address[1]), Handler)
        except OSError as e:   # ingress then answers 502 in HA; the log says why
            log.warning("ingress: could not listen on %s:%d (%s)", ingress_host,
                        srv.server_address[1], e.__class__.__name__)
        else:
            threading.Thread(target=ing.serve_forever, name="netwarden-ingress", daemon=True).start()
            srv.extra.append(ing)
    Handler.warmer = runner.Warmer(db_path, hours, env).start() if warm else None
    if warm:   # the page files (read + hashed once: slow on WSL's /mnt/c), off the request path
        threading.Thread(target=asset_version, name="netwarden-assets", daemon=True).start()
    # Stage T: the one change detector behind /api/stream (its thread starts with the
    # first stream; loops, the warm-up and POSTs poke it)
    Handler.live = srv.live = live.detector(db_path, env, hours)
    return srv


def advertised_hosts(url: str) -> frozenset:
    """The Host header values a browser sends for an advertised URL (already in the
    canonical scheme://host[:port] form): "host:port", plus the bare host when the port
    is the scheme's default (a browser leaves it out then)."""
    u = urlparse(url)
    default = 443 if u.scheme == "https" else 80
    name = u.netloc.rsplit(":", 1)[0] if u.port is not None else u.netloc
    port = u.port if u.port is not None else default
    hosts = {f"{name}:{port}"}
    if port == default:
        hosts.add(name)
    return frozenset(h.lower() for h in hosts)


def close_server(srv) -> None:
    """Stop the LAN listener (if any), end the live streams and close every socket
    make_server() opened."""
    for other in getattr(srv, "extra", []):
        other.shutdown()
        other.server_close()
    if getattr(srv, "live", None) is not None:
        srv.live.stop()
    srv.server_close()


def lan_wanted(flag: bool, db_path, env: dict) -> bool:
    """--lan, or the lan.enabled setting (NETWARDEN_LAN > dashboard), read at start."""
    if flag:
        return True
    db = store.connect(db_path)
    try:
        return bool(settings.get(db, env, "lan.enabled"))
    finally:
        db.close()


def lan_banner(lang: str) -> list[str]:
    """What `run` / `web` print when LAN mode is on (the URL, how to pair, the caveat)."""
    t = lambda k, **kw: i18n.t("cli.lan." + k, lang, **kw)  # noqa: E731
    lines = [t("on", url=Handler.lan_url), "  " + t("pair_hint", cmd="python3 -m netwarden pair")]
    if Handler.bind_all:
        lines.append("  " + t("bind_all"))
    lines.append("  " + t("http_warning"))
    u = urlparse(Handler.lan_url)
    lines += ["  " + x for x in wslnet.cli_lines(lang, u.port or 80, u.hostname, _lan_network())]
    return lines


def _lan_network():
    """The LAN this computer is on (for the WSL firewall rule's address limit), or None."""
    from netwarden import discovery   # lazy: subprocess `ip route`, Linux only
    try:
        return discovery.default_iface_net_ip()[1]
    except Exception:   # noqa: BLE001 - only narrows the advice; /24 is the fallback
        return None


def main(argv=None, prog=None) -> int:
    ap = argparse.ArgumentParser(prog=prog, description="netwarden local dashboard + AI chat.")
    ap.add_argument("--db", default=str(store.DEFAULT_DB))
    ap.add_argument("--host", default="127.0.0.1", help="loopback address to bind (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--lang", default=None,
                    help=f"default UI/answer language code (default: NETWARDEN_LANG or "
                         f"{i18n.DEFAULT}); one of " + ", ".join(i18n.CODES))
    ap.add_argument("--offline-ai", action="store_true",
                    help="never call the LLM: the AI panel answers with a rule-based offline summary")
    ap.add_argument("--lan", action="store_true",
                    help="also listen on this computer's LAN address; phones need pairing "
                         "(python3 -m netwarden pair). Plain HTTP: trusted home networks only")
    ap.add_argument("--lan-host", default=None, help="the private LAN address to use (default: detected)")
    ap.add_argument("--bind-all", action="store_true",
                    help="with --lan: listen on 0.0.0.0 (every interface) instead")
    args = ap.parse_args(argv)

    env = brain.load_env()
    if args.offline_ai:
        env[brain.OFFLINE_ENV] = "1"
    try:
        srv = make_server(args.db, args.port, env, args.lang, args.hours, args.host, warm=True,
                          lan=lan_wanted(args.lan, args.db, env), lan_host=args.lan_host,
                          bind_all=args.bind_all)
    except store.DBError as e:   # Stage K: a damaged / locked / unreadable file, said plainly
        print(db_problem_text(e, i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))),
              file=sys.stderr)
        return 2
    except ValueError as e:
        ap.error(str(e))
    db = store.connect(args.db)
    try:
        mode = brain.ai_mode(env, db)
    finally:
        db.close()
    print(f"netwarden dashboard → http://{args.host}:{args.port}   (DB: {args.db}, "
          f"default language: {Handler.lang}, AI: {mode})")
    if Handler.lan:
        print("\n".join(lan_banner(Handler.lang)))
    print("Ctrl-C to stop.")
    on_sigterm()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    finally:
        stop_server(srv)
    return 0


def on_sigterm() -> None:
    """`kill` / closing the terminal / `docker stop` shuts down like Ctrl+C (the main
    thread's serve_forever gets KeyboardInterrupt and the finally blocks run)."""
    import signal

    def _term(_sig, _frame):
        raise KeyboardInterrupt
    try:
        signal.signal(signal.SIGTERM, _term)
    except ValueError:   # not in the main thread (embedded use / tests)
        pass


def stop_server(srv, runner_=None, timeout: float = 2.0) -> None:
    """Orderly shutdown (Stage K): stop the loops (they finish the job at hand: every
    write is one transaction, so nothing is left half-written), then the warm-up thread,
    the live streams and the listening sockets. Returns within ~`timeout` s; a thread
    stuck in a slow network call is a daemon and is left behind."""
    deadline = time.monotonic() + timeout
    if runner_ is not None:
        runner_.stop(timeout=timeout)
    if Handler.warmer:
        Handler.warmer.stop(max(0.0, deadline - time.monotonic()))
    close_server(srv)


def db_problem_text(e: Exception, lang: str) -> str:
    """The localized CLI explanation of a store.DBError (corrupt / locked / unreadable)
    with what to do next; SQLite's own words go to the log only."""
    kind = store.problem(e) or "unreadable"
    path = getattr(e, "path", None) or "?"
    # only into a configured log (the `run` log file): without one, logging's last-resort
    # handler would print this English line to stderr - into the weekly cron mail
    if log.hasHandlers():
        log.warning("database problem (%s): %s", kind, health.sanitize_error(e))
    lines = [i18n.t("cli.db." + kind, lang, path=path)]
    if kind == "corrupt":
        lines.append("  " + i18n.t("cli.db.corrupt_hint", lang,
                                   cmd="python3 -m netwarden restore <backup.json>"))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
