#!/usr/bin/env python3
"""
netwarden - nethealth.py: "is it my Wi-Fi / router, or the internet provider?"

Passive first. The DNS events netwarden already ingests say a lot about the internet
connection: when the upstream resolver stops answering, AdGuard Home / Pi-hole log
SERVFAIL / REFUSED (or no reply at all) for every lookup they had to forward, and how
long a forwarded lookup took (AdGuard elapsedMs, Pi-hole reply time) is the internet's
round trip as the household feels it. Nothing new goes out on the network for that.

The ONE active check is the local default gateway (the home router): every minute the
`run` loop pings it with the system ping binary (fixed arguments, no shell; a private
LAN address only) or, where ping is not available, opens a TCP connection to it (a
"connection refused" answer still proves the router is up). Optionally - off by
default, a setting the user types in - one internet host:port gets a TCP connect too.

Outages are found minute by minute (find_outages):
  - the gateway did not answer for >= 2 minutes            -> cause "router"
  - the gateway answered but upstream DNS failed / the internet probe failed for
    >= 2 minutes                                            -> cause "isp"
  - only DNS failed while the internet probe was fine       -> cause "dns" (the DNS provider)
  - only DNS failed and nothing else was measured           -> cause "unknown"
and kept as rows in the outages table (update_outages), so the log survives the samples'
retention and each outage has a stable id for its alert (kind "outage", ack
"outage:<id>" on the pseudo device "network").

    python3 -m netwarden health                 # verdict + outage log (localized)
    python3 -m netwarden health --rebuild 7     # re-derive outages from 7 days of history
"""
from __future__ import annotations

import argparse
import bisect
import errno
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone

from netwarden import activity, cache, i18n, store

INTERVAL = 60                 # seconds between gateway probes (the run loop)
PING_COUNT = 3
PING_WAIT_S = 1               # per-echo timeout
TCP_PORTS = (80, 443, 53)     # a router answers (or refuses) on one of these
TCP_TIMEOUT = 1.5
PROBE_TIMEOUT = 3.0           # the optional internet probe

MIN_OUTAGE_MIN = 2            # bad minutes before it counts as an outage
BRIDGE_MIN = 2                # a gap this short (no data / a good minute in a real outage)
                              # does not end one (find_outages)
ONGOING_MIN = 3               # last bad minute this close to "now" = still going on
DNS_FAIL_MIN = 3              # failed upstream lookups in a minute ...
DNS_FAIL_SHARE = 0.5          # ... and at least this share of them -> a failing minute
UPDATE_HOURS = 3              # the loop re-derives the outage log over this trailing window
CAUSES = ("router", "isp", "dns", "unknown")
NETWORK_KEY = "network"       # the acks table's "device" for alerts about the whole network
ACK_PREFIX = "outage:"

SLOW_GATEWAY_MS = 50          # a wired / good Wi-Fi hop to the router is a few ms
LOSSY_GATEWAY = 0.05          # >= 5% lost echoes in the last hour: unstable Wi-Fi / router
SLOW_DNS_MS = 150             # average forwarded lookup
FAILING_DNS = 0.05            # >= 5% of forwarded lookups failed in the last hour
MIN_DNS_SAMPLE = 20           # lookups needed before DNS rates say anything

# A lookup "the upstream did not answer": SERVFAIL / REFUSED from either server, and
# Pi-hole's forwarded queries that never got a reply (status stays NULL).
FAIL_SQL = ("(status IN ('SERVFAIL', 'REFUSED') OR (status IS NULL AND source = 'pihole' "
            "AND reason IN ('FORWARDED', 'RETRIED', 'RETRIED_DNSSEC', 'IN_PROGRESS')))")
# What went to the upstream at all: not answered from the cache, not blocked locally.
UPSTREAM_SQL = "cached = 0 AND blocked = 0"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _minute(ts: str) -> str:
    return ts[:16]                       # "2026-10-22T02:13"


def _mdt(minute: str) -> datetime:
    return datetime.strptime(minute, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)


# --- the active checks --------------------------------------------------------------

def gateway_ip() -> str | None:
    """The default gateway, if it is a private LAN address we may probe."""
    from netwarden import exposure, upnp
    ip = upnp.default_gateway()
    return ip if ip and exposure.allowed(ip) else None


def availability() -> tuple[bool, str | None]:
    """Can the health loop probe a gateway here? (needs the LAN, like discovery)"""
    from netwarden import discovery
    ok, reason = discovery.availability()
    if not ok:
        return False, reason
    return (True, None) if gateway_ip() else (False, "no_gateway")


_PING_SUMMARY = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
_PING_RTT = re.compile(r"= [\d.]+/([\d.]+)/")


def parse_ping(out: str) -> dict | None:
    """iputils / busybox ping summary -> {ok, latency_ms, loss}; None if unreadable."""
    m = _PING_SUMMARY.search(out or "")
    if not m or not int(m.group(1)):
        return None
    sent, got = int(m.group(1)), int(m.group(2))
    rtt = _PING_RTT.search(out)
    return {"ok": got > 0, "loss": round(1 - got / sent, 3),
            "latency_ms": float(rtt.group(1)) if rtt and got else None}


def ping(ip: str, run=subprocess.run) -> dict | None:
    """ICMP echo via the system ping (fixed arguments, never a shell). None when ping is
    missing or not allowed here - the caller falls back to TCP."""
    if not shutil.which("ping"):
        return None
    try:
        ipaddress.ip_address(ip)            # a literal address, never an option or a name
        proc = run(["ping", "-n", "-q", "-c", str(PING_COUNT), "-W", str(PING_WAIT_S), ip],
                   capture_output=True, text=True,
                   timeout=PING_COUNT * (PING_WAIT_S + 1) + 2)
    except (ValueError, OSError, subprocess.SubprocessError):
        return None
    res = parse_ping(proc.stdout)
    if res is None or (proc.returncode not in (0, 1)):
        return None                         # e.g. "operation not permitted"
    return {**res, "method": "icmp"}


def tcp_check(host: str, port: int, timeout: float, numeric: bool = True) -> dict:
    """One TCP connect. Connected or actively refused = the host answered. Nothing is
    sent; the socket is closed at once."""
    t = time.perf_counter()
    try:
        flags = socket.AI_NUMERICHOST if numeric else 0
        family, _t, _p, _c, addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                                      flags=flags)[0]
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex(addr)
    except OSError:
        return {"ok": False, "latency_ms": None, "loss": 1.0, "method": "tcp"}
    ms = round((time.perf_counter() - t) * 1000, 2)
    ok = code in (0, errno.ECONNREFUSED, 10061)     # 10061 = WSAECONNREFUSED
    return {"ok": ok, "latency_ms": ms if ok else None, "loss": 0.0 if ok else 1.0,
            "method": "tcp"}


def probe_gateway(ip: str, run=subprocess.run) -> dict:
    """{ok, latency_ms, loss, method} for the gateway: ping, else TCP on TCP_PORTS."""
    res = ping(ip, run)
    if res is not None:
        return res
    last = None
    for port in TCP_PORTS:
        last = tcp_check(ip, port, TCP_TIMEOUT)
        if last["ok"]:
            return last
    return last


_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$")


def parse_target(value: str) -> tuple[str, int]:
    """"1.1.1.1:443" / "[2606:4700::1111]:443" / "example.com:443" -> (host, port).
    ValueError for anything else (no scheme, no path, no user@, a real port)."""
    value = (value or "").strip()
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$", value) or \
        re.match(r"^([^:\[\]/@\s]+):(\d{1,5})$", value)
    if not m:
        raise ValueError(value)
    host, port = m.group(1), int(m.group(2))
    if not 0 < port < 65536:
        raise ValueError(value)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST.match(host) or host.replace(".", "").isdigit():
            raise ValueError(value) from None
    return host, port


def probe_internet(target: str) -> dict:
    host, port = parse_target(target)
    return tcp_check(host, port, PROBE_TIMEOUT, numeric=False)


def probe_once(db, env: dict | None = None, run=subprocess.run, gw: str | None = None) -> dict:
    """One health round (the run loop's job): probe the gateway (+ the internet probe if
    the user set one), store the samples, re-derive the recent outage log. Recorded in
    source_status ('gateway'). Returns {gateway, internet, outages}."""
    from netwarden import settings
    gw = gw or gateway_ip()
    if not gw:
        store.record_source_error(db, "gateway", "no default gateway on a private address")
        raise RuntimeError("no default gateway")
    res = probe_gateway(gw, run)
    store.insert_health_sample(db, "gateway", res["ok"], res["latency_ms"], res["loss"],
                               res["method"])
    out = {"gateway": res, "internet": None}
    target = settings.get(db, env or {}, "health.internet_probe")
    if target:
        try:
            inet = probe_internet(target)
        except ValueError:
            inet = None
        if inet is not None:
            store.insert_health_sample(db, "internet", inet["ok"], inet["latency_ms"],
                                       inet["loss"], inet["method"])
            out["internet"] = inet
    out["outages"] = update_outages(db)
    store.record_source_ok(db, "gateway", 1 if res["ok"] else 0)
    return out


# --- DNS as a health signal ------------------------------------------------------------

def dns_minutes(db, since: str, until: str = "9999") -> dict:
    """minute -> (upstream lookups, failed) in [since, until)."""
    rows = db.execute(f"""SELECT substr(ts, 1, 16) AS m, COUNT(*) AS n,
                                 SUM(CASE WHEN {FAIL_SQL} THEN 1 ELSE 0 END) AS f
                          FROM dns_events WHERE ts >= ? AND ts < ? AND {UPSTREAM_SQL}
                          GROUP BY m""", (since, until))
    return {r["m"]: (r["n"], r["f"] or 0) for r in rows}


def dns_hours(db, since: str) -> list:
    """Per UTC hour since `since`: [{hour, queries, fails, avg_ms}] (upstream lookups)."""
    return [{"hour": r["h"], "queries": r["n"], "fails": r["f"] or 0,
             "avg_ms": round(r["ms"], 1) if r["ms"] is not None else None}
            for r in db.execute(f"""
                SELECT substr(ts, 1, 13) AS h, COUNT(*) AS n,
                       SUM(CASE WHEN {FAIL_SQL} THEN 1 ELSE 0 END) AS f,
                       AVG(CASE WHEN NOT {FAIL_SQL} AND elapsed_ms > 0 THEN elapsed_ms END) AS ms
                FROM dns_events WHERE ts >= ? AND {UPSTREAM_SQL}
                GROUP BY h ORDER BY h""", (since,))]


def dns_window(db, since: str) -> tuple:
    """(queries, fails, avg_ms) of upstream lookups since `since` exactly - "right now".
    Hour buckets would let a clock hour that started almost two hours ago (and an outage
    long over) still count as the last hour."""
    r = db.execute(f"""
        SELECT COUNT(*), SUM(CASE WHEN {FAIL_SQL} THEN 1 ELSE 0 END),
               AVG(CASE WHEN NOT {FAIL_SQL} AND elapsed_ms > 0 THEN elapsed_ms END)
        FROM dns_events WHERE ts >= ? AND {UPSTREAM_SQL}""", (since,)).fetchone()
    return r[0], r[1] or 0, (round(r[2], 1) if r[2] is not None else None)


# --- outages -----------------------------------------------------------------------------

def minute_states(gateway: list, dns: dict, internet: list) -> dict:
    """minute -> {gw: True/False/None (answered?), dns: True/False/None (failing?),
    inet: True/False/None (answered?)}. A minute with several probes counts as answered
    if any of them was."""
    out: dict = {}
    for target, rows in (("gw", gateway), ("inet", internet)):
        for s in rows:
            st = out.setdefault(_minute(s["ts"]), {"gw": None, "dns": None, "inet": None})
            st[target] = bool(s["ok"]) or bool(st[target])
    for m, (n, f) in dns.items():
        st = out.setdefault(m, {"gw": None, "dns": None, "inet": None})
        st["dns"] = f >= DNS_FAIL_MIN and f >= DNS_FAIL_SHARE * n
    return out


def _bad(st: dict) -> bool:
    return st["gw"] is False or st["dns"] is True or st["inet"] is False


def find_outages(states: dict, now: datetime) -> list:
    """Runs of bad minutes (gaps <= BRIDGE_MIN bridged) lasting >= MIN_OUTAGE_MIN, with
    their probable cause. [{start, end, minutes, cause, ongoing, gateway_min, dns_min,
    probe_min}], oldest first; start / end are UTC ISO strings (end exclusive)."""
    bad = sorted(m for m, st in states.items() if _bad(st))
    good = sorted(m for m, st in states.items() if not _bad(st)
                  and any(v is not None for v in st.values()))

    def good_between(a: str, b: str) -> bool:
        i = bisect.bisect_right(good, a)
        return i < len(good) and good[i] < b

    runs, cur = [], []
    for m in bad:
        # a short gap is bridged when it is just missing samples, or a lucky good probe
        # inside an outage that already counts as one; two isolated bad minutes around
        # working ones are NOT merged into an outage
        if cur and ((_mdt(m) - _mdt(cur[-1])).total_seconds() / 60 > BRIDGE_MIN + 1
                    or (len(cur) < MIN_OUTAGE_MIN and good_between(cur[-1], m))):
            runs.append(cur)
            cur = []
        cur.append(m)
    if cur:
        runs.append(cur)
    now_m = now.replace(second=0, microsecond=0)
    out = []
    for run in runs:
        if len(run) < MIN_OUTAGE_MIN:
            continue
        start, last = _mdt(run[0]), _mdt(run[-1])
        span = [st for m, st in states.items() if run[0] <= m <= run[-1]]
        gw_down = sum(1 for m in run if states[m]["gw"] is False)
        dns_fail = sum(1 for m in run if states[m]["dns"] is True)
        inet_down = sum(1 for m in run if states[m]["inet"] is False)
        gw_seen_ok = any(st["gw"] is True for st in span)
        inet_seen = any(st["inet"] is not None for st in span)
        if gw_down * 2 >= len(run):
            cause = "router"
        elif inet_down or (gw_seen_ok and not inet_seen):
            cause = "isp"
        elif inet_seen:
            cause = "dns"          # the internet probe got through: only DNS was broken
        else:
            cause = "unknown"
        out.append({"start": _iso(start), "end": _iso(last + timedelta(minutes=1)),
                    "minutes": int((last - start).total_seconds() // 60) + 1, "cause": cause,
                    "ongoing": (now_m - last).total_seconds() / 60 <= ONGOING_MIN,
                    "gateway_min": gw_down, "dns_min": dns_fail, "probe_min": inet_down})
    return out


def detect(db, since: datetime, now: datetime) -> list:
    """find_outages() over everything stored in [since, now)."""
    s, u = _iso(since), _iso(now)
    states = minute_states(store.health_samples(db, "gateway", s, u), dns_minutes(db, s, u),
                           store.health_samples(db, "internet", s, u))
    return find_outages(states, now)


def update_outages(db, now: datetime | None = None, hours: float = UPDATE_HOURS) -> int:
    """Merge the outages found in the last `hours` into the outages table: an overlapping
    (or adjacent) row grows, a new one is inserted, several that now touch become one.
    A row still marked ongoing that nothing ongoing overlaps anymore is closed.
    Returns the number of rows written."""
    now = now or datetime.now(timezone.utc)
    found = detect(db, now - timedelta(hours=hours), now)
    pad = timedelta(minutes=BRIDGE_MIN + 1)
    written = 0
    ts = store.now()
    with db:
        still = set()
        for o in found:
            rows = db.execute("""SELECT * FROM outages WHERE start_ts <= ? AND end_ts >= ?
                                 ORDER BY start_ts""",
                              (_iso(_parse(o["end"]) + pad), _iso(_parse(o["start"]) - pad))
                              ).fetchall()
            if rows:
                keep = rows[0]
                start = min([o["start"]] + [r["start_ts"] for r in rows])
                end = max([o["end"]] + [r["end_ts"] for r in rows])
                db.execute("""UPDATE outages SET start_ts = ?, end_ts = ?, cause = ?, ongoing = ?,
                                  gateway_min = MAX(gateway_min, ?), dns_min = MAX(dns_min, ?),
                                  probe_min = MAX(probe_min, ?), updated_at = ?
                              WHERE id = ?""",
                           (start, end, o["cause"], int(o["ongoing"]), o["gateway_min"],
                            o["dns_min"], o["probe_min"], ts, keep["id"]))
                for r in rows[1:]:
                    db.execute("DELETE FROM outages WHERE id = ?", (r["id"],))
                rid = keep["id"]
            else:
                rid = db.execute("""INSERT INTO outages (start_ts, end_ts, cause, ongoing,
                                        gateway_min, dns_min, probe_min, updated_at)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (o["start"], o["end"], o["cause"], int(o["ongoing"]),
                                  o["gateway_min"], o["dns_min"], o["probe_min"], ts)).lastrowid
            written += 1
            if o["ongoing"]:
                still.add(rid)
        for r in db.execute("SELECT id FROM outages WHERE ongoing = 1").fetchall():
            if r["id"] not in still:
                db.execute("UPDATE outages SET ongoing = 0, updated_at = ? WHERE id = ?",
                           (ts, r["id"]))
                written += 1
    return written


def outage_list(db, days: int = 30) -> list:
    """The outage log, newest first, with minutes computed."""
    since = _iso(datetime.now(timezone.utc) - timedelta(days=days))
    out = []
    for o in store.outages(db, since):
        mins = max(1, round((_parse(o["end_ts"]) - _parse(o["start_ts"])).total_seconds() / 60))
        out.append({**o, "minutes": mins, "ongoing": bool(o["ongoing"]),
                    "ack": f"{ACK_PREFIX}{o['id']}"})
    return out


def alerts(db, recent_since: str) -> list:
    """Alert-worthy outages: ongoing, or ended inside the recent window. Acks NOT
    applied here (alerts.compute filters them on the pseudo device NETWORK_KEY)."""
    return [{**o, "mac": NETWORK_KEY} for o in outage_list(db, days=8)
            if o["ongoing"] or o["end_ts"] >= recent_since]


# --- plain language -------------------------------------------------------------------

def _hm(ts: str, tz) -> str:
    return _parse(ts).astimezone(tz).strftime("%H:%M")


def when_text(o: dict, lang: str, tz=None, now: datetime | None = None) -> str:
    """"last night 02:13-02:20" / "today 14:02-14:05" / "10-19 22:40-23:01"."""
    tz = tz or activity.local_tz()
    now = (now or datetime.now(timezone.utc)).astimezone(tz)
    start = _parse(o["start_ts"]).astimezone(tz)
    span = _hm(o["start_ts"], tz) + "–" + (i18n.t("health.now", lang) if o.get("ongoing")
                                           else _hm(o["end_ts"], tz))
    days = (now.date() - start.date()).days
    if days == 0 and start.hour < 6 and now.hour >= 6:
        return i18n.t("health.when.last_night", lang, span=span)
    if days == 0:
        return i18n.t("health.when.today", lang, span=span)
    if days == 1 and start.hour >= 22:
        return i18n.t("health.when.last_night", lang, span=span)
    if days == 1:
        return i18n.t("health.when.yesterday", lang, span=span)
    return i18n.t("health.when.date", lang, date=start.strftime("%m-%d"), span=span)


def duration_text(minutes: int, lang: str) -> str:
    h, m = divmod(int(minutes), 60)
    if h and m:
        return i18n.t("health.dur_hm", lang, h=h, m=m)
    return i18n.t("health.dur_h", lang, h=h) if h else i18n.t("health.dur_m", lang, m=m)


def outage_text(o: dict, lang: str, tz=None, now: datetime | None = None) -> str:
    """"Last night 02:13-02:20, 7 min - probably the internet provider (ISP)." """
    return i18n.t("health.outage_line", lang, when=when_text(o, lang, tz, now),
                  dur=duration_text(o["minutes"], lang),
                  cause=i18n.t("health.cause." + o["cause"], lang))


def localize_outage(o: dict, lang: str, tz=None) -> dict:
    return {**o, "text": outage_text(o, lang, tz), "when": when_text(o, lang, tz),
            "cause_name": i18n.t("health.cause." + o["cause"], lang),
            "duration": duration_text(o["minutes"], lang)}


# --- the report behind GET /api/health ---------------------------------------------------

def _avg(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 1) if xs else None


def gateway_series(samples: list, start: datetime, now: datetime, step_min: int = 10) -> list:
    """Probes folded into step_min buckets from `start` to `now`, oldest first:
    [{t, ms, loss, down, n}] (ms / loss None for a bucket without probes)."""
    n = int((now - start).total_seconds() // (step_min * 60)) + 1
    buckets = [[] for _ in range(n)]
    for s in samples:
        i = int((_parse(s["ts"]) - start).total_seconds() // (step_min * 60))
        if 0 <= i < n:
            buckets[i].append(s)
    out = []
    for i, b in enumerate(buckets):
        t = _iso(start + timedelta(minutes=i * step_min))
        out.append({"t": t, "n": len(b), "down": any(not s["ok"] for s in b),
                    "ms": _avg([s["latency_ms"] for s in b if s["ok"]]),
                    "loss": _avg([s["loss"] for s in b]) if b else None})
    return out


def compute(db, hours: float = 24) -> dict:
    """The canonical (unlocalized) health picture; shared through netwarden.cache."""
    return cache.memo(db, "nethealth.compute", (hours,), lambda: _compute(db, hours))


def _compute(db, hours: float) -> dict:
    now = datetime.now(timezone.utc)
    if store.is_demo(db):   # frozen synthetic data: "now" = its newest probe
        newest = db.execute("SELECT MAX(ts) FROM health_samples").fetchone()[0]
        if newest:
            now = max(now, _parse(newest))
    start = now - timedelta(hours=hours)
    gw = store.health_samples(db, "gateway", _iso(start))
    inet = store.health_samples(db, "internet", _iso(start))
    hour_ago = _iso(now - timedelta(hours=1))
    last_hour = [s for s in gw if s["ts"] >= hour_ago]
    week = dns_hours(db, _iso(now - timedelta(days=7)))
    day_hours = [h for h in week if h["hour"] >= _iso(start)[:13]]
    q_day = sum(h["queries"] for h in day_hours)
    f_day = sum(h["fails"] for h in day_hours)
    q_hr, f_hr, ms_hr = dns_window(db, hour_ago)

    def wavg(rows):
        num = sum(h["avg_ms"] * h["queries"] for h in rows if h["avg_ms"] is not None)
        den = sum(h["queries"] for h in rows if h["avg_ms"] is not None)
        return round(num / den, 1) if den else None

    raw_stats = store.get_meta(db, "dns_server_stats")
    try:
        server = json.loads(raw_stats) if raw_stats else None
    except ValueError:
        server = None
    outs = outage_list(db, days=30)
    week_ago = _iso(now - timedelta(days=7))
    return {
        "now": _iso(now), "hours": hours,
        "gateway": {
            "measured": bool(gw),
            "ip": (db.execute("SELECT gateway_ip FROM upnp_snapshots WHERE gateway_ip IS NOT NULL "
                              "ORDER BY ts DESC LIMIT 1").fetchone() or [None])[0],
            "latest": gw[-1] if gw else None,
            "avg_ms": _avg([s["latency_ms"] for s in gw if s["ok"]]),
            "hour_ms": _avg([s["latency_ms"] for s in last_hour if s["ok"]]),
            "loss": _avg([s["loss"] for s in gw]),
            "hour_loss": _avg([s["loss"] for s in last_hour]),
            "series": gateway_series(gw, start, now) if gw else [],
        },
        "internet": {"measured": bool(inet), "latest": inet[-1] if inet else None,
                     "avg_ms": _avg([s["latency_ms"] for s in inet if s["ok"]]),
                     "fails": sum(1 for s in inet if not s["ok"])},
        "dns": {
            "measured": bool(week),
            "queries": q_day, "fails": f_day,
            "fail_rate": round(f_day / q_day, 4) if q_day else None,
            "hour_fail_rate": round(f_hr / q_hr, 4) if q_hr >= MIN_DNS_SAMPLE else None,
            "avg_ms": wavg(day_hours), "hour_ms": ms_hr if q_hr >= MIN_DNS_SAMPLE else None,
            "hours": [h for h in day_hours],
            "week": week,
        },
        "server": server,
        "outages": outs,
        "outages_7d": [o for o in outs if o["end_ts"] >= week_ago or o["ongoing"]],
    }


def verdict(h: dict) -> dict:
    """The plain-language answer: {level: ok|warn|bad|idle, key, params}."""
    ongoing = [o for o in h["outages"] if o["ongoing"]]
    if ongoing:
        return {"level": "bad", "key": "down_" + ongoing[0]["cause"], "params": {}}
    gw, dns = h["gateway"], h["dns"]
    if not gw["measured"] and not dns["measured"]:
        return {"level": "idle", "key": "idle", "params": {}}
    if gw["measured"] and gw["hour_loss"] is not None and gw["hour_loss"] >= LOSSY_GATEWAY:
        return {"level": "warn", "key": "lossy", "params": {"pct": round(100 * gw["hour_loss"])}}
    if gw["measured"] and gw["hour_ms"] is not None and gw["hour_ms"] >= SLOW_GATEWAY_MS:
        return {"level": "warn", "key": "slow_router", "params": {"ms": round(gw["hour_ms"])}}
    if dns["hour_fail_rate"] is not None and dns["hour_fail_rate"] >= FAILING_DNS:
        return {"level": "warn", "key": "dns_failing",
                "params": {"pct": round(100 * dns["hour_fail_rate"])}}
    if dns["hour_ms"] is not None and dns["hour_ms"] >= SLOW_DNS_MS:
        return {"level": "warn", "key": "dns_slow", "params": {"ms": round(dns["hour_ms"])}}
    return {"level": "ok", "key": "ok", "params": {}}


def verdict_text(v: dict, h: dict, lang: str, tz=None) -> dict:
    """{title, text}: the verdict, plus what was measured / the last outage."""
    title = i18n.t("health.verdict." + v["key"], lang, **v["params"])
    parts = []
    gw, dns = h["gateway"], h["dns"]
    if gw["measured"] and gw["avg_ms"] is not None:
        parts.append(i18n.t("health.measure.router", lang, ms=_fmt_ms(gw["avg_ms"]),
                            pct=round(100 * (gw["loss"] or 0))))
    if dns["measured"] and dns["avg_ms"] is not None:
        parts.append(i18n.t("health.measure.dns", lang, ms=_fmt_ms(dns["avg_ms"]),
                            pct=_fmt_pct(dns["fail_rate"] or 0)))
    last = next((o for o in h["outages"] if not o["ongoing"]), None)
    if v["level"] != "bad":
        parts.append(i18n.t("health.last_outage", lang, text=outage_text(last, lang, tz))
                     if last else i18n.t("health.no_outages", lang))
    if not gw["measured"] and v["level"] != "idle":
        parts.append(i18n.t("health.no_gateway", lang))
    return {"title": title, "text": " ".join(parts)}


def _fmt_ms(ms: float) -> str:
    return str(round(ms)) if ms >= 10 else f"{ms:.1f}"


def _fmt_pct(x: float) -> str:
    p = 100 * x
    return f"{p:.1f}" if 0 < p < 10 else str(round(p))


def report(db, lang: str = i18n.DEFAULT, hours: float = 24, tz=None, env: dict | None = None) -> dict:
    """GET /api/health: verdict, gateway latency series, DNS speed / failures, outages."""
    from netwarden import settings
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    h = compute(db, hours)
    v = verdict(h)
    days = {}
    for row in h["dns"]["week"]:     # fold UTC hours into LOCAL days, oldest first
        day = _parse(row["hour"] + ":00:00.000000Z").astimezone(tz).date().isoformat()
        d = days.setdefault(day, {"date": day, "queries": 0, "fails": 0, "_ms": 0.0, "_n": 0})
        d["queries"] += row["queries"]
        d["fails"] += row["fails"]
        if row["avg_ms"] is not None:
            d["_ms"] += row["avg_ms"] * row["queries"]
            d["_n"] += row["queries"]
    week = [{"date": d["date"], "queries": d["queries"], "fails": d["fails"],
             "fail_rate": round(d["fails"] / d["queries"], 4) if d["queries"] else None,
             "avg_ms": round(d["_ms"] / d["_n"], 1) if d["_n"] else None}
            for d in sorted(days.values(), key=lambda x: x["date"])][-7:]
    probe = settings.get(db, env or {}, "health.internet_probe")
    return {
        "now": h["now"], "hours": hours, "tz": activity.tz_label(tz), "demo": store.is_demo(db),
        "verdict": {**v, **verdict_text(v, h, lang, tz)},
        "gateway": h["gateway"],
        "internet": {**h["internet"], "configured": bool(probe), "target": probe or ""},
        "dns": {k: h["dns"][k] for k in ("measured", "queries", "fails", "fail_rate", "avg_ms",
                                         "hours")} | {"days": week},
        "server": h["server"],
        "outages": [localize_outage(o, lang, tz) for o in h["outages"]],
        "outages_7d": len(h["outages_7d"]),
        "note": i18n.t("health.note", lang),
    }


# --- CLI ------------------------------------------------------------------------------

def main(argv=None, prog=None) -> int:
    from netwarden import brain
    lang0 = i18n.normalize(brain.load_env().get("NETWARDEN_LANG"))
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.health", lang0))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang0))
    ap.add_argument("--lang", default=None, help=i18n.t("cli.opt.lang", lang0))
    ap.add_argument("--json", action="store_true", help=i18n.t("cli.opt.health_json", lang0))
    ap.add_argument("--rebuild", type=int, metavar="DAYS", default=0,
                    help=i18n.t("cli.opt.health_rebuild", lang0))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang0)
    db = store.connect(args.db)
    if args.rebuild:
        update_outages(db, hours=24 * max(1, min(args.rebuild, 90)))
    rep = report(db, lang, env=brain.load_env())
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0
    print(rep["verdict"]["title"])
    print("  " + rep["verdict"]["text"])
    print()
    print(i18n.t("health.outages_title", lang))
    lines = [o["text"] for o in rep["outages"][:10]]
    print("\n".join("  • " + x for x in lines) if lines else "  " + i18n.t("health.no_outages", lang))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
