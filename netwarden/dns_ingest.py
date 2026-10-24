#!/usr/bin/env python3
"""
netwarden - DNS ingest (the "Watch" step)

We don't run our own resolver. We read the per-client query log that an existing
DNS server already keeps (AdGuard Home today, Pi-hole next), normalize it, and store
it in SQLite - tied to the devices that discovery found.

    source adapter  ->  normalized events  ->  attribute client IP to a device  ->  store

Attribution (client IP -> device MAC):
  1. devices we already know (from a discovery sweep or an earlier ingest);
  2. our own addresses (loopback, LAN IP, ...) -> this machine;
  3. otherwise the kernel neighbour (ARP) table: a LAN client that just sent us a
     DNS query is almost certainly in it, so no full sweep is needed.
Anything still unknown (e.g. a client behind another router) is stored with its IP
only and linked later if the device shows up.

Pure standard library. Credentials come from .env (see scripts/adguard_dev.sh):
    ADGUARD_URL=http://127.0.0.1:3000  ADGUARD_USER=...  ADGUARD_PASS=...
or, for Pi-hole v6 (docs/pihole.md):
    PIHOLE_URL=http://pi.hole  PIHOLE_PASSWORD=...  [PIHOLE_VERIFY_TLS=0 for self-signed]
Both configured -> AdGuard, unless NETWARDEN_DNS_SOURCE=pihole. Either way netwarden
only READS the query log; it never changes a setting on the DNS server.

Run inside WSL:
    python3 -m netwarden.dns_ingest              # ingest once + per-device report
    python3 -m netwarden.dns_ingest --discover   # full LAN sweep first
    python3 -m netwarden.dns_ingest --watch 30   # keep ingesting every 30s
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Protocol

from netwarden import discovery, health, i18n, store

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
RELINK_WINDOW = timedelta(hours=24)  # how far back to attach events to a newly found device
TS_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


# --- small helpers ---------------------------------------------------------

def load_env(path: Path = ENV_FILE) -> dict[str, str]:
    """Minimal .env reader (KEY=VALUE lines). Real environment variables win."""
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    env.update({k: v for k, v in os.environ.items()
                if k in env or k.startswith(("ADGUARD_", "PIHOLE_")) or k == DNS_SOURCE_ENV})
    return env


def to_utc(ts: str) -> str:
    """'2026-10-21T00:05:01.123456789+08:00' -> '2026-10-20T16:05:01.123456Z'.

    Go/AdGuard emits nanoseconds; Python wants at most microseconds."""
    ts = ts.replace("Z", "+00:00")
    ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- untrusted source data (Stage K) ------------------------------------------------
# A DNS server's API is outside our control: a different version, a proxy's error page or
# a hostile box on the LAN may answer anything. One unusable entry is skipped (counted in
# the source's `skipped`), never allowed to fail the whole run - which would retry the
# same page forever and stop ingest for good.

MAX_PAGES = 1000              # pages per run: a server that never stops paging can't hold the loop
MAX_FIELD = 255               # a domain / client name / upstream longer than this is cut
MAX_TS_YEAR = 9999


class BadItem(ValueError):
    """A query-log entry of the wrong shape (skipped)."""


def _obj(v) -> dict:
    return v if isinstance(v, dict) else {}


def _text(v, limit: int = MAX_FIELD) -> str | None:
    """A string field, one line, capped; anything else (number, list, object) -> None."""
    if not isinstance(v, str):
        return None
    v = store.clean_text(v, limit)
    return v or None


def _domain(v) -> str:
    return (_text(v) or "").rstrip(".").lower()


def _number(v) -> float | None:
    """A duration: missing / 0 -> 0.0 (as before); a finite number or numeric string ->
    float; anything else (bool, NaN, Infinity, junk) -> None."""
    if v is None or v == "" or (v == 0 and not isinstance(v, bool)):
        return 0.0
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if math.isfinite(f) else None


def _ts(v) -> str:
    """An ISO 8601 time (AdGuard) -> store's UTC format; BadItem if missing or junk."""
    if not isinstance(v, str) or len(v) > 64:
        raise BadItem("bad time")
    try:
        return to_utc(v)
    except (ValueError, OverflowError) as e:
        raise BadItem("bad time") from e


def _epoch_ts(v) -> str:
    """Unix seconds (Pi-hole) -> store's UTC format; BadItem if missing or out of range."""
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise BadItem("bad time")
    try:
        f = float(v)
        if not math.isfinite(f) or not 0 <= f < 253402300800:   # 1970 .. 9999-12-31
            raise BadItem("bad time")
        return datetime.fromtimestamp(f, timezone.utc).strftime(TS_FMT)
    except (ValueError, OverflowError, OSError) as e:
        raise BadItem("bad time") from e


def _try_normalize(src, item) -> dict | None:
    """src.normalize(item), or None (and src.skipped += 1) for an unusable entry."""
    try:
        return src.normalize(item)
    except BadItem:
        src.skipped = getattr(src, "skipped", 0) + 1
        return None


def local_addresses() -> set[str]:
    """Every IP this host owns: DNS queries from these come from this machine."""
    addrs = {"127.0.0.1", "::1"}
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return addrs
    for m in re.finditer(r"inet6? ([0-9a-fA-F.:]+)", out):
        addrs.add(m.group(1).lower())
    return addrs


# --- source adapters -------------------------------------------------------

class Source(Protocol):
    """A DNS server whose per-client query log we can read.

    events(since) yields normalized dicts (store.EVENT_FIELDS), newest first, and
    stops once it reaches events older than `since` (a UTC ts from store)."""
    source: str

    def events(self, since: str | None) -> Iterator[dict]: ...


class AdGuardHome:
    """AdGuard Home via its HTTP API: GET /control/querylog (newest first, paged)."""
    source = "adguard"
    # FilteringReason values that mean "the client did not get a real answer".
    BLOCK_REASONS = {k for k in store.BLOCK_REASONS if k.startswith("Filtered")}

    def __init__(self, url: str, user: str = "", password: str = "",
                 page_size: int = 500, timeout: float = 10):
        self.url = url.rstrip("/")
        self.page_size = page_size
        self.timeout = timeout
        self.password = password   # only for masking it in errors (health.source_secrets)
        self.auth = ("Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
                     if user else None)
        self.opener = health.opener()   # never follows a redirect to another host

    def _get(self, path: str, params: dict) -> dict:
        req = urllib.request.Request(f"{self.url}{path}?{urllib.parse.urlencode(params)}")
        if self.auth:
            req.add_header("Authorization", self.auth)
        with self.opener.open(req, timeout=self.timeout) as resp:
            return health.read_source_json(resp, "AdGuard Home", "ADGUARD_URL")

    def normalize(self, item: dict) -> dict:
        """One querylog entry -> an event. Raises BadItem for an entry we can't use (it is
        skipped, never stored half-understood)."""
        if not isinstance(item, dict):
            raise BadItem("not an object")
        q = _obj(item.get("question"))
        reason = _text(item.get("reason"))
        elapsed = _number(item.get("elapsedMs"))
        reason = reason or ""
        return {
            "source": self.source,
            "ts": _ts(item.get("time")),
            "client_ip": _text(item.get("client"), 64) or "",
            "client_name": _text(_obj(item.get("client_info")).get("name")),
            "domain": _domain(q.get("name")),
            "qtype": _text(q.get("type"), 16),
            "status": _text(item.get("status"), 32),
            "reason": reason,
            "blocked": int(reason in self.BLOCK_REASONS),
            "block_reason": store.block_reason(reason) if reason in self.BLOCK_REASONS else None,
            "cached": int(item.get("cached") is True),
            "upstream": _text(item.get("upstream")),
            "elapsed_ms": elapsed,
        }

    def stats(self) -> dict:
        """GET /control/stats (AdGuard's own 24 h counters) -> stats_summary() shape."""
        d = self._get("/control/stats", {})
        ups = []
        for item in d.get("top_upstreams_avg_time") or []:
            for name, secs in (item.items() if isinstance(item, dict) else ()):
                if isinstance(secs, (int, float)):
                    ups.append((name, round(float(secs) * 1000, 1)))
        avg = d.get("avg_processing_time")
        return stats_summary(self.source, d.get("num_dns_queries"),
                             d.get("num_blocked_filtering"),
                             round(float(avg) * 1000, 1) if isinstance(avg, (int, float)) else None,
                             ups)

    def events(self, since: str | None) -> Iterator[dict]:
        older_than = None
        for _page in range(MAX_PAGES):
            params = {"limit": self.page_size}
            if older_than:
                params["older_than"] = older_than
            page = self._get("/control/querylog", params)
            data = page.get("data") or []
            if not isinstance(data, list) or not data:
                return
            for item in data:
                ev = _try_normalize(self, item)
                if ev is None:
                    continue
                if since and ev["ts"] < since:
                    return  # everything from here on is already stored
                yield ev
            last = data[-1] if isinstance(data[-1], dict) else {}
            nxt = page.get("oldest") or last.get("time")
            if not isinstance(nxt, str) or not nxt or nxt == older_than:
                return
            older_than = nxt


class PiHoleError(OSError):
    """Pi-hole refused us (bad password, 2FA, no free API session, ...). An OSError, so
    callers treat it like any other "can't reach the source" failure."""


class PiHole:
    """Pi-hole v6 via its REST API (FTL; docs.pi-hole.net/api, FTL src/api/docs).

        POST   /api/auth {"password"}  -> {"session": {"valid", "sid", "validity", ...}}
        GET    /api/queries?from=&length=&start=&cursor=   newest first (ORDER BY id DESC)
        DELETE /api/auth               -> 204, frees the session slot

    The SID goes in the X-FTL-SID header (no CSRF token needed for header auth). One
    session is reused across calls - and across runs of the `run` loop - because
    Pi-hole only has a few API seats; a 401 (session expired) means log in once more,
    and close() logs out. An application password works the same as the real one.
    A Pi-hole without a password needs no session at all: an empty PIHOLE_PASSWORD
    skips the login, and a POST /api/auth answered with sid null means the same.

    Paging: the first page answers with `cursor` = the newest query id; later pages
    pass that cursor (pins the result set while new queries keep arriving) plus
    start = rows already read. `from` (unix seconds, inclusive) stops at our watermark.
    """
    source = "pihole"
    MAX_PAGE = 10_000          # FTL's API_QUERIES_MAX_ROWS
    CACHED = {"CACHE", "CACHE_STALE"}
    PENDING = {"IN_PROGRESS"}   # FTL is still waiting for the upstream answer
    # reply.type -> DNS rcode, so `status` means the same thing for every source.
    RCODES = {"NXDOMAIN": "NXDOMAIN", "SERVFAIL": "SERVFAIL", "REFUSED": "REFUSED",
              "NOTIMP": "NOTIMP", "IP": "NOERROR", "CNAME": "NOERROR", "DOMAIN": "NOERROR",
              "RRNAME": "NOERROR", "NODATA": "NOERROR", "DNSSEC": "NOERROR",
              "BLOB": "NOERROR", "OTHER": "NOERROR"}

    def __init__(self, url: str, password: str = "", verify_tls: bool = True,
                 page_size: int = 1000, timeout: float = 10):
        self.url = url.rstrip("/")
        self.password = password
        self.page_size = max(1, min(int(page_size), self.MAX_PAGE))
        self.timeout = timeout
        self.sid: str | None = None
        self.logged_in = False   # a session exists (or the Pi-hole told us none is needed)
        self.ctx = ssl.create_default_context()
        if not verify_tls:       # PIHOLE_VERIFY_TLS=0: the stock self-signed certificate
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.opener = health.opener(self.ctx)   # same-origin redirects only (X-FTL-SID)

    # -- HTTP + session --------------------------------------------------------

    def _call(self, method: str, path: str, params: dict | None = None,
              body: dict | None = None) -> dict:
        url = f"{self.url}{path}" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.sid:
            req.add_header("X-FTL-SID", self.sid)
        with self.opener.open(req, timeout=self.timeout) as resp:
            return health.read_source_json(resp, "Pi-hole", "PIHOLE_URL")

    def login(self) -> None:
        self.sid, self.logged_in = None, False
        try:
            data = self._call("POST", "/api/auth", body={"password": self.password})
        except urllib.error.HTTPError as e:
            e.close()
            if e.code == 401:
                raise PiHoleError("Pi-hole rejected the password (HTTP 401) - check PIHOLE_PASSWORD "
                                  "(an application password works too)") from None
            if e.code == 429:
                raise PiHoleError("Pi-hole has no free API session (HTTP 429) - "
                                  "close other API clients or wait a few minutes") from None
            if e.code == 400:
                raise PiHoleError("Pi-hole refused the login (HTTP 400) - with 2FA enabled, "
                                  "use an application password as PIHOLE_PASSWORD") from None
            raise
        session = data.get("session") or {}
        if not session.get("valid"):
            raise PiHoleError("Pi-hole did not accept the login (invalid session)")
        self.sid = session.get("sid") or None   # None: this Pi-hole has no password
        self.logged_in = True

    def close(self) -> None:
        """Log out (frees the API seat). Safe to call twice; never raises."""
        try:
            if self.sid:
                self._call("DELETE", "/api/auth")
        except (OSError, ValueError):
            pass  # already expired / Pi-hole gone: the session times out on its own
        finally:
            self.sid, self.logged_in = None, False

    def __enter__(self) -> "PiHole":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _get(self, path: str, params: dict) -> dict:
        if self.password and not self.logged_in:
            self.login()
        try:
            return self._call("GET", path, params)
        except urllib.error.HTTPError as e:
            e.close()
            if e.code != 401:
                raise
        # 401: our session expired (or there never was one) -> log in once, retry once.
        if not self.password:
            raise PiHoleError("Pi-hole requires a password - set PIHOLE_PASSWORD in .env")
        self.login()
        return self._call("GET", path, params)

    def stats(self) -> dict:
        """GET /api/stats/summary (FTL's counters) -> stats_summary() shape."""
        q = self._get("/api/stats/summary", {}).get("queries") or {}
        return stats_summary(self.source, q.get("total"), q.get("blocked"), None, [])

    # -- query log ---------------------------------------------------------------

    def normalize(self, q: dict) -> dict:
        """One /api/queries row -> an event; BadItem for a row we can't use (skipped)."""
        if not isinstance(q, dict):
            raise BadItem("not an object")
        client = _obj(q.get("client"))
        reply = _obj(q.get("reply"))
        status = _text(q.get("status"), 32) or ""
        elapsed = _number(reply.get("time"))
        elapsed = None if elapsed is None else round(elapsed * 1000, 3)  # seconds -> ms
        reason = store.block_reason(status)
        return {
            "source": self.source,
            "ts": _epoch_ts(q.get("time")),
            "client_ip": _text(client.get("ip"), 64) or "",
            "client_name": _text(client.get("name")),
            "domain": _domain(q.get("domain")),
            "qtype": _text(q.get("type"), 16),
            "status": self.RCODES.get(_text(reply.get("type"), 16) or ""),
            "reason": status or None,
            "blocked": int(reason is not None),
            "block_reason": reason,
            "cached": int(status in self.CACHED),
            "upstream": _text(q.get("upstream")),
            "elapsed_ms": elapsed,
            "pending": status in self.PENDING,   # not stored: ingest() holds it back
        }

    def events(self, since: str | None) -> Iterator[dict]:
        params: dict = {"length": self.page_size}
        if since:
            # inclusive and whole seconds: the watermark row comes back and is
            # dropped by the store's UNIQUE key, nothing in between is missed
            params["from"] = int(datetime.strptime(since, TS_FMT)
                                 .replace(tzinfo=timezone.utc).timestamp())
        start = 0
        for _page in range(MAX_PAGES):
            page = self._get("/api/queries", {**params, "start": start})
            rows = page.get("queries") or []
            if not isinstance(rows, list):
                return
            for q in rows:
                ev = _try_normalize(self, q)
                if ev is None:
                    continue
                if since and ev["ts"] < since:
                    return
                yield ev
            if len(rows) < self.page_size or page.get("cursor") is None:
                return
            params["cursor"] = page["cursor"]   # pin the set to what existed on page 1
            start += len(rows)


DNS_SOURCE_ENV = "NETWARDEN_DNS_SOURCE"
DNS_SOURCES = {"adguard": "ADGUARD_URL", "pihole": "PIHOLE_URL"}   # name -> env key that enables it


def dns_source_name(env: dict[str, str]) -> str | None:
    """Which DNS source ingest reads: NETWARDEN_DNS_SOURCE if that one is configured,
    else the first configured of AdGuard, Pi-hole; None if neither is."""
    have = [name for name, key in DNS_SOURCES.items() if env.get(key)]
    want = (env.get(DNS_SOURCE_ENV) or "").strip().lower()
    if want in have:
        return want
    return have[0] if have else None


def _flag(value: str | None, default: bool = True) -> bool:
    if value is None or not str(value).strip():
        return default
    return str(value).strip().lower() not in ("0", "false", "no", "off")


def source_from_env(env: dict[str, str]) -> Source:
    name = dns_source_name(env)
    if name == "pihole":
        return PiHole(env["PIHOLE_URL"], env.get("PIHOLE_PASSWORD", ""),
                      verify_tls=_flag(env.get("PIHOLE_VERIFY_TLS")))
    if name == "adguard":
        return AdGuardHome(env["ADGUARD_URL"], env.get("ADGUARD_USER", ""), env.get("ADGUARD_PASS", ""))
    raise SystemExit(i18n.t("status.hint.dns_off", i18n.normalize(env.get("NETWARDEN_LANG"))))


def _upstream_name(name: str) -> str:
    """"https://user:pw@dns.example/dns-query" -> "dns.example"; "8.8.8.8:53" stays."""
    name = str(name or "")
    if "://" in name:
        name = urllib.parse.urlsplit(name).hostname or ""
    return name.rsplit("@", 1)[-1][:80]


def stats_summary(server: str, queries, blocked, avg_ms, upstreams: list) -> dict:
    """The DNS server's own counters, as stored in meta `dns_server_stats` (shown on the
    Network health page): never a URL, only upstream host names."""
    num = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) else None  # noqa: E731
    return {"server": server, "ts": store.now(), "queries": num(queries),
            "blocked": num(blocked), "avg_ms": num(avg_ms),
            "upstreams": [{"name": _upstream_name(n), "avg_ms": ms}
                          for n, ms in sorted(upstreams, key=lambda x: -x[1])[:5]]}


def record_stats(db, src) -> dict | None:
    """Best effort: fetch the source's own statistics into meta `dns_server_stats`.
    Errors are swallowed (an old AdGuard / Pi-hole without the endpoint is fine)."""
    fetch = getattr(src, "stats", None)
    if fetch is None:
        return None
    try:
        res = fetch()
    except Exception:  # noqa: BLE001 - optional extra; ingest health is what counts
        return None
    store.set_meta(db, "dns_server_stats", json.dumps(res))
    return res


def close_source(src) -> None:
    """End a source's session, if it keeps one (Pi-hole). Never raises."""
    close = getattr(src, "close", None)
    if close is not None:
        try:
            close()
        except Exception:  # noqa: BLE001 - shutting down; nothing useful to do
            pass


SECRET_KEYS = ("ADGUARD_PASS", "PIHOLE_PASSWORD")   # masked in any stored / logged error


# --- ingest ----------------------------------------------------------------

class Attributor:
    """Maps a client IP to a device MAC, learning new devices from ARP as it goes."""

    def __init__(self, db):
        self.db = db
        self.ip_mac = store.ip_to_mac(db)
        self.self_ips = local_addresses()
        self.self_mac = store.self_mac(db) or self._register_self()
        self._table = None  # MAC vendor DB, loaded only if we meet a new device

    def _register_self(self) -> str | None:
        iface, _net, own_ip = discovery.default_iface_net_ip()
        mac = discovery.own_mac(iface) if iface else ""
        if not mac:
            return None
        store.upsert_device(self.db, discovery.device_record(
            own_ip, mac, {}, is_self=True, hostname=socket.gethostname()))
        self.ip_mac[own_ip] = mac
        return mac

    def learn(self, ips: set[str], names: dict[str, str]) -> list[dict]:
        """Look unknown client IPs up in the ARP table and store them as devices."""
        unknown = {ip for ip in ips if ip not in self.ip_mac and ip not in self.self_ips}
        if not unknown:
            return []
        arp = discovery.read_arp()
        found = []
        for ip in sorted(unknown & arp.keys()):
            if self._table is None:
                self._table = discovery.load_manuf()
            d = discovery.device_record(ip, arp[ip], self._table,
                                        hostname=names.get(ip) or discovery.hostname_for(ip))
            store.upsert_device(self.db, d)
            self.ip_mac[ip] = d["mac"]
            found.append(d)
        return found

    def mac_for(self, ip: str) -> str | None:
        if ip in self.ip_mac:
            return self.ip_mac[ip]
        if ip in self.self_ips:
            return self.self_mac
        return None


PENDING_HOLD_S = 120   # how long an unfinished query may hold the watermark back


def _age_s(ts: str, newest: str) -> float:
    return (datetime.strptime(newest, TS_FMT) - datetime.strptime(ts, TS_FMT)).total_seconds()


def ingest(db, src: Source) -> dict:
    """Pull everything new from `src` into the store. Returns a small stats dict."""
    since = store.get_watermark(db, src.source)
    events = list(src.events(since))
    fetched = len(events)
    newest = max((e["ts"] for e in events), default=None)
    # A query still being answered (Pi-hole IN_PROGRESS) would be stored with that status
    # for good (rows are insert-only). Hold it back and keep the watermark at it, so the
    # next poll fetches it again, finished. A query stuck for > PENDING_HOLD_S is stored
    # as it is - it must not pin the watermark forever.
    held = [e for e in events if e.get("pending") and _age_s(e["ts"], newest) < PENDING_HOLD_S]
    if held:
        events = [e for e in events if not any(e is h for h in held)]
    att = Attributor(db)
    names = {e["client_ip"]: e["client_name"] for e in events if e["client_name"]}
    new_devices = att.learn({e["client_ip"] for e in events}, names)
    for e in events:
        e["device_mac"] = att.mac_for(e["client_ip"])
    inserted = store.insert_events(db, events)
    # Stage N: the name the DNS server knows each client by is identity evidence too
    from netwarden import identify   # lazy: identify is only needed when names arrive
    identify.record_dns_names(db, {e["device_mac"]: e["client_name"] for e in events
                                   if e["device_mac"] and e["client_name"]
                                   and e["client_name"] != e["client_ip"]})
    if held:
        store.set_watermark(db, src.source, min(e["ts"] for e in held))
    elif events:
        store.set_watermark(db, src.source, newest)
    window = (datetime.now(timezone.utc) - RELINK_WINDOW).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    relinked = store.link_unattributed(db, att.ip_mac, since=window)
    return {
        "fetched": fetched,
        "held": len(held),
        "inserted": inserted,
        "new_devices": new_devices,
        "unattributed": len({e["client_ip"] for e in events if not e["device_mac"]}),
        "relinked": relinked,
    }


def ingest_recorded(db, src: Source) -> dict:
    """ingest(), with the outcome written to source_status (the health view). Used by
    the CLI and the `run` loop alike. Re-raises on failure after recording it."""
    try:
        st = ingest(db, src)
    except Exception as e:
        store.record_source_error(db, src.source,
                                  health.sanitize_error(e, health.source_secrets(src)))
        raise
    store.record_source_ok(db, src.source, st["fetched"])
    return st


def configured(env: dict[str, str]) -> bool:
    """Is any DNS source configured? (checks presence only, never prints values)"""
    return dns_source_name(env) is not None


def print_report(db, hours: float, top: int = 5, lang: str = i18n.DEFAULT) -> None:
    t = lambda k, **kw: i18n.t("cli.ingest." + k, lang, **kw)  # noqa: E731
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    rows = store.device_activity(db, since=since, top=top)
    print()
    print(t("report_title", hours=f"{hours:g}", n=len(rows)))
    print("=" * 84)
    for r in rows:
        who = r["vendor"] or t("unknown_device")
        name = r["hostname"] or r["client_name"] or ""
        mac = r["device_mac"] or t("no_mac")
        print(f"{who}  {name}".rstrip())
        print(f"    {mac} · {r['ips'].replace(',', ', ')}")
        print("    " + t("counts", queries=r["queries"], domains=r["domains"], blocked=r["blocked"] or 0,
                         first=r["first_ts"][11:19], last=r["last_ts"][11:19]))
        for d in r["top_domains"]:
            flag = "  " + t("blocked") if d["blocked"] else ""
            print(f"    {d['n']:>6}  {d['domain']}{flag}")
    print()


def main(argv=None, prog=None) -> int:
    env = load_env()
    lang0 = i18n.normalize(env.get("NETWARDEN_LANG"))
    o = lambda k: i18n.t("cli.opt." + k, lang0)  # noqa: E731
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.ingest", lang0))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=o("db"))
    ap.add_argument("--discover", action="store_true", help=o("discover"))
    ap.add_argument("--watch", type=float, metavar="SECONDS", help=o("watch"))
    ap.add_argument("--hours", type=float, default=24, help=o("report_hours"))
    ap.add_argument("--no-report", action="store_true", help=o("no_report"))
    ap.add_argument("--lang", default=None, help=o("lang"))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang0)
    t = lambda k, **kw: i18n.t("cli.ingest." + k, lang, **kw)  # noqa: E731

    db = store.connect(args.db)
    src = source_from_env(env)

    if args.discover:
        socket.setdefaulttimeout(1.0)
        iface, net, own_ip = discovery.default_iface_net_ip()
        if not net:
            print(i18n.t("cli.scan.no_lan", lang), file=sys.stderr)
            return 1
        print(t("discovering", net=net))
        devices = discovery.scan(iface, net, own_ip, discovery.load_manuf())
        socket.setdefaulttimeout(None)
        for d in devices:
            store.upsert_device(db, d)
        store.record_source_ok(db, discovery.SOURCE, len(devices))
        print("  " + t("stored", n=len(devices)))

    try:
        while True:
            try:
                st = ingest_recorded(db, src)
            except (OSError, ValueError) as e:  # URLError, refused, timeouts, not JSON
                print(health.failure_line(src.source, e, health.source_secrets(src), lang),
                      file=sys.stderr)
                if not args.watch:
                    return 1
            else:
                line = t("line", time=datetime.now().strftime("%H:%M:%S"), source=src.source,
                         fetched=st["fetched"], new=st["inserted"], devices=len(st["new_devices"]),
                         unattributed=st["unattributed"])
                if st["relinked"]:
                    line += i18n.t("list_sep", lang) + t("relinked", n=st["relinked"])
                print(line)
                for d in st["new_devices"]:
                    print(f"    + {d['ip']:<16}{d['mac']:<20}{d['vendor']}")
            if not args.watch:
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print()
    finally:
        close_source(src)   # one Pi-hole session per CLI run, always logged out

    if not args.no_report:
        print_report(db, args.hours, lang=lang)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
