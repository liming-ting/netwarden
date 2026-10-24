#!/usr/bin/env python3
"""
netwarden - traffic ingest (OPTIONAL per-device bandwidth)

DNS tells us who a device talks to and how often - never how many BYTES
(docs/bandwidth.md). If the user already runs ntopng somewhere that
actually sees the traffic (on the gateway, a bridge, or a switch mirror port), we read
its per-host byte counters, read-only, and store them next to the DNS data.

    source adapter  ->  cumulative per-host counters  ->  IP -> device MAC  ->  store

Same adapter shape as dns_ingest: a source returns samples
    [{ip, mac or None, rx_bytes, tx_bytes, ts}]
where the byte counts are CUMULATIVE (as the sensor reports them) and rx = received
by the device (download). store.bandwidth_summary() turns them into window totals and
rates by differencing consecutive samples.

Unconfigured = off: without NTOPNG_URL nothing here runs and netwarden behaves
exactly as before. Pure standard library. Config from .env:
    NTOPNG_URL=http://192.168.1.2:3000  NTOPNG_USER=...  NTOPNG_PASS=...  NTOPNG_IFID=0
    (or NTOPNG_TOKEN=... instead of user + password; NTOPNG_VERIFY_TLS=0 for self-signed https)

Run inside WSL:
    python3 -m netwarden.traffic_ingest              # take one sample
    python3 -m netwarden.traffic_ingest --watch 30   # keep sampling every 30s
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Protocol

from netwarden import brain, health, i18n, store

MAX_PAGES = 1000  # safety stop if a server ignores currentPage


class TrafficSource(Protocol):
    """Something that knows per-host byte counters (ntopng today).

    sample() returns one cumulative reading per local host, all with the same ts."""
    source: str

    def sample(self) -> list[dict]: ...


class NtopngSource:
    """ntopng via REST API v2: GET /lua/rest/v2/get/host/active.lua (paged).

    Per the official API docs + examples (ntop.org/guides/ntopng/api/rest/), the reply
    is {"rc": 0, "rc_str": "OK", "rsp": {"data": [host, ...], "currentPage", "perPage"}}
    and each host carries "ip", "is_localhost" and "bytes": {"total", "recvd", "sent"}.
    "recvd" is what the host received = its download. The active-hosts list has no MAC
    (only the per-host data.lua does), so callers map IP -> MAC from the device table."""
    source = "ntopng"
    PATH = "/lua/rest/v2/get/host/active.lua"
    # documented return codes (api_v2.html) -> what the user should check
    RC_HINTS = {-2: "check NTOPNG_IFID (the interface number)",
                -3: "NOT_GRANTED: this ntopng user may not read that data - check NTOPNG_USER",
                -6: "ntopng had an internal error - try again later"}

    def __init__(self, url: str, user: str = "", password: str = "", ifid: int = 0,
                 page_size: int = 100, timeout: float = 10, token: str = "",
                 verify_tls: bool = True):
        self.url = url.rstrip("/")
        self.ifid = ifid
        self.page_size = page_size
        self.timeout = timeout
        self.password = password or token   # only for masking it in errors (health.source_secrets)
        # an API token (ntopng: user settings -> API token) wins over user + password;
        # HTTPServer.cpp accepts "Authorization: Token <t>" (or Bearer) and Basic
        if token:
            self.auth = "Token " + token
        elif user:
            self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        else:
            self.auth = None
        # same-origin redirects only; https verified unless NTOPNG_VERIFY_TLS=0
        self.opener = health.opener(health.tls_context(verify_tls))

    def _get(self, params: dict) -> dict:
        req = urllib.request.Request(f"{self.url}{self.PATH}?{urllib.parse.urlencode(params)}")
        req.add_header("Accept", "application/json")
        if self.auth:
            req.add_header("Authorization", self.auth)
        with self.opener.open(req, timeout=self.timeout) as resp:
            # without (valid) credentials ntopng answers 302 -> its login page (same origin,
            # so the opener follows it): say "login", not "not JSON"
            if "/login.lua" in (resp.geturl() or ""):
                raise health.SourceError("auth", "ntopng asked for a login - check NTOPNG_USER / "
                                                 "NTOPNG_PASS or NTOPNG_TOKEN")
            body = health.read_source_json(resp, "ntopng", "NTOPNG_URL")
        rc = body.get("rc", 0)
        if rc != 0:
            hint = self.RC_HINTS.get(rc) if isinstance(rc, int) and not isinstance(rc, bool) else None
            msg = f"ntopng error {str(rc)[:20]}: {str(body.get('rc_str'))[:100]}"
            raise OSError(f"{msg} - {hint}" if hint else msg)
        return body

    @staticmethod
    def normalize(item: dict, ts: str) -> dict | None:
        """One host -> a sample, or None (not a local host, or a shape we can't use: a
        hostile / broken answer is skipped, never stored half-understood)."""
        if not isinstance(item, dict):
            return None
        raw_ip = item.get("ip")
        ip = raw_ip.split("@")[0] if isinstance(raw_ip, str) else ""  # "ip@vlan" when tagged
        if not ip or item.get("is_localhost") is False or not _is_ip(ip):
            return None
        b = item.get("bytes") if isinstance(item.get("bytes"), dict) else {}
        rx, tx = _count(b.get("recvd") or b.get("rcvd")), _count(b.get("sent"))
        if rx is None or tx is None:
            return None
        mac = item.get("mac")
        return {
            "ip": ip,
            "mac": mac.lower()[:64] if isinstance(mac, str) and mac else None,
            "rx_bytes": rx,
            "tx_bytes": tx,
            "ts": ts,
        }

    def sample(self) -> list[dict]:
        ts = store.now()
        out, seen, page = [], set(), 1
        while page <= MAX_PAGES:
            body = self._get({"ifid": self.ifid, "mode": "local",
                              "currentPage": page, "perPage": self.page_size})
            rsp = body.get("rsp")
            data = rsp.get("data") if isinstance(rsp, dict) else (rsp or [])
            data = [h for h in data if isinstance(h, dict)] if isinstance(data, list) else []
            new = [h for h in data if _host_key(h) not in seen]
            if not new:
                break  # empty page, or the server repeats a page (paging ignored)
            for h in new:
                seen.add(_host_key(h))
                s = self.normalize(h, ts)
                if s:
                    out.append(s)
            # (no / junk totalRows = unknown, not 0: keep paging until a short page)
            total = (_count(rsp["totalRows"]) or None
                     if isinstance(rsp, dict) and rsp.get("totalRows") not in (None, "") else None)
            if len(data) < self.page_size or (total is not None and len(seen) >= total):
                break
            page += 1
        return out


MAX_COUNTER = 2 ** 63 - 1   # SQLite INTEGER


def _count(v) -> int | None:
    """A byte counter: a non-negative whole number (or numeric string) that fits SQLite;
    missing -> 0; anything else -> None."""
    if v is None or v == "":
        return 0
    if isinstance(v, bool):
        return None
    try:
        n = int(v)   # int("12"), int(12.0); NaN / Infinity raise
    except (TypeError, ValueError, OverflowError):
        return None
    return n if 0 <= n <= MAX_COUNTER else None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _host_key(h: dict) -> tuple:
    """A hashable (ip, vlan) identity of one host entry (junk values become text)."""
    return tuple(v if isinstance(v, (str, int, type(None))) else repr(v)[:80]
                 for v in (h.get("ip"), h.get("vlan")))


def source_from_env(env: dict) -> NtopngSource | None:
    """The configured traffic source, or None (bandwidth is optional)."""
    if not env.get("NTOPNG_URL"):
        return None
    try:
        ifid = int(env.get("NTOPNG_IFID") or 0)
    except ValueError:
        ifid = 0
    from netwarden.dns_ingest import _flag   # the one "0/false/no/off" parser
    return NtopngSource(env["NTOPNG_URL"], env.get("NTOPNG_USER", ""), env.get("NTOPNG_PASS", ""),
                        ifid, token=env.get("NTOPNG_TOKEN", ""),
                        verify_tls=_flag(env.get("NTOPNG_VERIFY_TLS")))


def ingest(db, src: TrafficSource) -> dict:
    """Take one sample from `src`, attribute IPs to known devices, store it."""
    samples = src.sample()
    ip_mac = store.ip_to_mac(db)
    for s in samples:
        s["mac"] = s.get("mac") or ip_mac.get(s["ip"])
    stored = store.insert_traffic_samples(db, samples)
    return {"hosts": len(samples), "stored": stored,
            "unattributed": sum(1 for s in samples if not s["mac"])}


def ingest_recorded(db, src: TrafficSource) -> dict:
    """ingest(), with the outcome written to source_status. Re-raises on failure."""
    try:
        st = ingest(db, src)
    except Exception as e:
        store.record_source_error(db, src.source,
                                  health.sanitize_error(e, health.source_secrets(src)))
        raise
    store.record_source_ok(db, src.source, st["hosts"])
    return st


def print_report(db, hours: float, lang: str = i18n.DEFAULT) -> None:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    summary = store.bandwidth_summary(db, since)
    print()
    print(i18n.t("cli.traffic.report_title", lang, hours=f"{hours:g}", n=len(summary)))
    for key, s in sorted(summary.items(), key=lambda kv: -(kv[1]["rx_bytes"] + kv[1]["tx_bytes"])):
        print(f"  {key:<20} " + i18n.t("cli.traffic.row", lang,
                                       down=f"{brain.human_bytes(s['rx_bytes']):>9}",
                                       up=f"{brain.human_bytes(s['tx_bytes']):>9}",
                                       rx=f"{s['rx_bps'] / 1e6:.2f}", tx=f"{s['tx_bps'] / 1e6:.2f}"))
    print()


def main(argv=None, prog=None) -> int:
    env = brain.load_env()
    lang0 = i18n.normalize(env.get("NETWARDEN_LANG"))
    o = lambda k: i18n.t("cli.opt." + k, lang0)  # noqa: E731
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.traffic", lang0))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=o("db"))
    ap.add_argument("--watch", type=float, metavar="SECONDS", help=o("watch"))
    ap.add_argument("--hours", type=float, default=24, help=o("report_hours"))
    ap.add_argument("--lang", default=None, help=o("lang"))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang0)

    src = source_from_env(env)
    if src is None:   # the same sentence as `netwarden status`
        print(i18n.t("status.hint.ntopng_off", lang))
        return 0

    db = store.connect(args.db)
    try:
        while True:
            try:
                st = ingest_recorded(db, src)
            except (OSError, ValueError) as e:  # URLError, refused, timeouts, ntopng rc != 0
                print(health.failure_line("ntopng", e, health.source_secrets(src), lang),
                      file=sys.stderr)
                if not args.watch:
                    return 1
            else:
                print(i18n.t("cli.traffic.line", lang, time=datetime.now().strftime("%H:%M:%S"),
                             hosts=st["hosts"], unattributed=st["unattributed"]))
            if not args.watch:
                break
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print()
    print_report(db, args.hours, lang=lang)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
