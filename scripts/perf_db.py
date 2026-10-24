#!/usr/bin/env python3
"""
netwarden - perf_db.py: a BIG synthetic home for performance work (dev tool only).

Builds a separate database (default /tmp/nw_perf.db - never data/netwarden.db or
data/demo.db) with ~300 devices, ~100k DNS events over 7 days and 7 days of 5-minute
per-device byte counters, then times the dashboard's main endpoints on it through a
real in-process server on an ephemeral 127.0.0.1 port (offline AI: no LLM, no network).

    python3 scripts/perf_db.py build  [--db PATH] [--devices 300] [--events 100000]
    python3 scripts/perf_db.py bench  [--db PATH] [--runs 5] [--warm]
    python3 scripts/perf_db.py all    [...]          # build, then bench

The DB is marked demo (meta demo=1, perf=1): its IPs are made up, so live actions
(port checks) are refused on it like on the demo home. It refuses to overwrite any
database that is not one of its own.
"""
from __future__ import annotations

import argparse
import http.client
import random
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netwarden import brain, cache, store, web  # noqa: E402

DEFAULT_DB = Path("/tmp/nw_perf.db")
SEED = 4242
ISO = "%Y-%m-%dT%H:%M:%S.%fZ"

# (hostname prefix, vendor, randomized MAC, domains it uses) - a mixed, busy household
KINDS = [
    ("iPhone", "", True,
     ["push.apple.com", "gateway.icloud.com", "instagram.com", "graph.facebook.com",
      "app-measurement.com", "doubleclick.net", "line.me", "googlevideo.com"]),
    ("Galaxy", "Samsung Electronics", True,
     ["youtube.com", "googlevideo.com", "tiktokv.com", "app-measurement.com",
      "ssl.google-analytics.com", "play.googleapis.com"]),
    ("LAPTOP", "Intel Corporate", False,
     ["github.com", "update.microsoft.com", "fonts.gstatic.com", "doubleclick.net",
      "outlook.office365.com", "teams.microsoft.com", "slack.com"]),
    ("TV", "Samsung Electronics", False,
     ["samsungacr.com", "netflix.com", "nflxvideo.net", "ads.samsungads.com",
      "youtube.com"]),
    ("ipcam", "Hangzhou Xiongmai", False,
     ["xmeye.net", "secu100.net", "pool.ntp.org"]),
    ("echo", "Amazon Technologies", False,
     ["device-metrics-us.amazon.com", "api.amazonalexa.com", "pool.ntp.org"]),
    ("plug", "Espressif Inc.", False,
     ["tuyaus.com", "a.tuyaus.com", "pool.ntp.org"]),
    ("printer", "HP Inc.", False,
     ["hpeprint.com", "h10141.www1.hp.com"]),
]


class NotAPerfDB(ValueError):
    pass


def _iso(dt: datetime) -> str:
    return dt.strftime(ISO)


def _mac(rng: random.Random, randomized: bool) -> str:
    # unicast; the locally-administered bit marks a randomized ("private") address
    first = (rng.randrange(256) & 0xFC) | (0x02 if randomized else 0)
    return ":".join(f"{b:02x}" for b in [first] + [rng.randrange(256) for _ in range(5)])


def build(path: Path = DEFAULT_DB, n_devices: int = 300, n_events: int = 100_000,
          days: int = 7, sample_minutes: int = 5) -> dict:
    """(Re)write the perf DB. ~35% of the events land in the last 24 h (what the
    dashboard window reads); the rest spread over the week before."""
    rng = random.Random(SEED)
    now = datetime.now(timezone.utc)
    db = store.connect(path)
    if store.get_meta(db, "perf") != "1" and db.execute(
            "SELECT EXISTS(SELECT 1 FROM devices) OR EXISTS(SELECT 1 FROM dns_events)").fetchone()[0]:
        db.close()
        raise NotAPerfDB(str(path))
    with db:
        for table in ("dns_events", "devices", "traffic_samples", "port_checks", "ingest_state",
                      "source_status", "device_identity", "upnp_snapshots", "upnp_mappings",
                      "health_samples", "outages", "score_history", "people", "device_profiles",
                      "presence_samples"):
            db.execute(f"DELETE FROM {table}")
    store.set_meta(db, "demo", "1")
    store.set_meta(db, "perf", "1")

    devs = []
    for i in range(n_devices):
        host, vendor, randomized, domains = KINDS[i % len(KINDS)]
        ip = f"10.{(i // 250) + 20}.{(i // 250) % 250}.{i % 250 + 2}"
        d = {"mac": _mac(rng, randomized), "ip": ip, "vendor": vendor,
             "hostname": f"{host}-{i:03d}", "randomized": randomized, "is_self": i == 0,
             "domains": domains + [f"cdn{rng.randrange(40)}.example{i % 17}.com"
                                   for _ in range(rng.randint(2, 8))]}
        store.upsert_device(db, d, seen=_iso(now - timedelta(days=days + 1)))
        devs.append(d)

    events = []
    for k in range(n_events):
        d = devs[int(rng.paretovariate(1.2)) % n_devices]   # a few chatty devices, a long tail
        age = rng.uniform(0, 24 * 3600) if rng.random() < 0.35 else rng.uniform(0, days * 86400)
        domain = rng.choice(d["domains"])
        blocked = domain in ("doubleclick.net", "app-measurement.com", "ads.samsungads.com") \
            and rng.random() < 0.6
        events.append({"source": "perf", "ts": _iso(now - timedelta(seconds=age, microseconds=k)),
                       "client_ip": d["ip"], "client_name": d["hostname"], "domain": domain,
                       "qtype": "A", "status": "NOERROR",
                       "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
                       "blocked": int(blocked), "block_reason": "blocklist" if blocked else None,
                       "cached": 0, "upstream": "", "elapsed_ms": 1.0, "device_mac": d["mac"]})
    for i in range(0, len(events), 20_000):
        store.insert_events(db, events[i:i + 20_000])

    samples, steps = 0, days * 24 * 60 // sample_minutes
    start = now - timedelta(days=days)
    rows = []
    for d in devs:
        rx = tx = 0
        rate = rng.uniform(1e3, 2e6)
        for s in range(steps + 1):
            rx += int(rate * sample_minutes * 60 * rng.uniform(0.2, 1.8))
            tx += int(rate * 0.15 * sample_minutes * 60 * rng.uniform(0.2, 1.8))
            rows.append((d["mac"], d["ip"], _iso(start + timedelta(minutes=s * sample_minutes)),
                         rx, tx))
        if len(rows) > 100_000:
            with db:
                db.executemany("INSERT INTO traffic_samples VALUES (?, ?, ?, ?, ?)", rows)
            samples += len(rows)
            rows = []
    with db:
        db.executemany("INSERT INTO traffic_samples VALUES (?, ?, ?, ?, ?)", rows)
        samples += len(rows)
        db.execute("""UPDATE devices SET last_seen = COALESCE(
                          (SELECT MAX(ts) FROM dns_events WHERE device_mac = devices.mac),
                          last_seen)""")
    # Stage N: every device has a DHCP name, every third announced itself over mDNS, the
    # TVs over SSDP too; the router saw a UPnP check every 4 h with ~1 mapping per 8 devices
    for i, d in enumerate(devs):
        seen = _iso(now - timedelta(minutes=10))
        store.upsert_identity(db, d["mac"], "dhcp", name=d["hostname"], seen=seen)
        if i % 3 == 0:
            store.upsert_identity(db, d["mac"], "mdns", f"{d['hostname']} (mDNS)", d["vendor"],
                                  f"Model-{i % 11}", None, "_airplay._tcp", seen)
        if d["hostname"].startswith("TV"):
            store.upsert_identity(db, d["mac"], "ssdp", f"[TV] {d['hostname']}", d["vendor"],
                                  "QA55", "tv", "urn:schemas-upnp-org:device:MediaRenderer:1", seen)
    maps = [{"protocol": "TCP" if i % 2 else "UDP", "external_port": 20000 + i if i % 5 else 554 + i,
             "internal_client": d["ip"], "internal_port": 554 if i % 5 == 0 else 3478,
             "description": f"app {i}", "mac": d["mac"]} for i, d in enumerate(devs[::8])]
    for h in range(days * 6, -1, -1):
        store.record_upnp(db, {"available": True, "gateway_ip": "10.20.0.1",
                               "external_ip": "203.0.113.200", "status": "Connected"},
                          maps[:len(maps) - (h // 12)], ts=_iso(now - timedelta(hours=4 * h)))
    # Stage H: a router ping every minute for the whole window, down for 4 minutes once a day
    probes = []
    for m in range(days * 24 * 60):
        t = start + timedelta(minutes=m, seconds=5)
        down = m % 1440 in range(600, 604)
        probes.append((_iso(t), "gateway", int(not down), None if down else
                       round(rng.uniform(1.5, 6), 2), 1.0 if down else 0.0, "icmp"))
    with db:
        db.executemany("""INSERT INTO health_samples (ts, target, ok, latency_ms, loss, method)
                          VALUES (?, ?, ?, ?, ?, ?)""", probes)
    # Stage P: 20 people own every third device; 6 of them turned presence on a week ago,
    # and the light check saw their devices every 5 minutes
    for i, d in enumerate(devs[1:], 1):
        if i % 3 == 0:
            store.set_profile(db, d["mac"], owner=f"Person {i % 20:02d}")
    store.sync_people(db)
    on = store.people(db)[:6]
    for p in on:
        store.save_person(db, {**p, "presence": True, "presence_since": _iso(start)})
    owned = {m: p["owner"] for m, p in store.get_profiles(db).items()}
    checks = [(d["mac"], _iso(start + timedelta(minutes=m)), "check") for d in devs
              if owned.get(d["mac"]) in {p["name"] for p in on}
              for m in range(0, days * 24 * 60, 5) if (m // 60) % 24 not in range(8, 17)]
    store.insert_presence_samples(db, checks)
    from netwarden import nethealth
    nethealth.update_outages(db, now, hours=days * 24)
    store.record_source_ok(db, "gateway", 1)
    store.record_source_ok(db, "adguard", len(events))
    store.record_source_ok(db, "ntopng", n_devices)
    store.record_source_ok(db, "discovery", n_devices)
    for src in ("mdns", "ssdp", "upnp"):
        store.record_source_ok(db, src, n_devices // 3)
    db.execute("PRAGMA optimize")
    db.close()
    return {"devices": n_devices, "events": len(events), "traffic_samples": samples,
            "path": str(path)}


ENDPOINTS = ["/api/inventory", "/api/alerts", "/api/privacy", "/api/visibility",
             "/api/status", "/api/activity", "/api/device?mac={mac}", "/api/activity?mac={mac}",
             "/api/timeline?mac={mac}", "/api/search?q=goog", "/api/upnp",
             "/api/domain?d=pool.ntp.org", "/api/export/devices.csv",
             "/api/screentime?days=7", "/api/screentime?days=7&device={mac}", "/api/weekly",
             "/api/bedtime", "/report/weekly", "/api/health", "/api/suggestions", "/api/score",
             "/api/inbox", "/api/people", "/api/presence", "/api/notify", "/api/hygiene",
             "/api/overview"]
# what the page used to fetch together on every 30 s refresh (one request per dataset);
# since Stage T it asks for ONE bundle instead (/api/overview = all of these)
REFRESH = ["/api/inventory", "/api/alerts", "/api/privacy", "/api/visibility", "/api/status",
           "/api/activity", "/api/upnp", "/api/health", "/api/suggestions", "/api/score",
           "/api/inbox", "/api/presence", "/api/notify"]
BUNDLE = ["/api/overview"]


def _get(port: int, path: str) -> float:
    t = time.perf_counter()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
    c.request("GET", path + ("&" if "?" in path else "?") + "lang=en")
    r = c.getresponse()
    r.read()
    if r.status != 200:
        raise RuntimeError(f"{path}: HTTP {r.status}")
    return (time.perf_counter() - t) * 1000


def bench(path: Path = DEFAULT_DB, runs: int = 5, warm: bool = False) -> dict:
    """Median ms per endpoint (sequential), plus one full parallel page refresh.
    warm=True: like `netwarden run` / `web`, start the server with its cache warm-up
    (runner.Warmer): first the page opened right away (every refresh request at once,
    racing the startup pass - each request's own time), then the endpoints once the
    startup pass is done."""
    db = store.connect(path)
    mac = db.execute("SELECT device_mac FROM dns_events GROUP BY device_mac "
                     "ORDER BY COUNT(*) DESC LIMIT 1").fetchone()[0]
    db.close()
    cache.clear()
    srv = web.make_server(path, 0, {brain.OFFLINE_ENV: "1"}, "en", 24, warm=warm)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out = {}
    if warm:
        t = time.perf_counter()
        with ThreadPoolExecutor(len(REFRESH)) as ex:
            firsts = list(ex.map(lambda p: _get(port, p), REFRESH))
        for p, ms in zip(REFRESH, firsts):
            out[f"(at startup) {p}"] = {"first": ms, "median": 0}
        out["(at startup) whole page"] = {"first": (time.perf_counter() - t) * 1000, "median": 0}
        while not web.Handler.warmer.passes:
            time.sleep(0.05)
        out["(startup warm-up pass)"] = {"first": (time.perf_counter() - t) * 1000, "median": 0}
    try:
        for ep in ENDPOINTS:
            p = ep.format(mac=mac)
            times = [_get(port, p) for _ in range(runs)]
            out[ep] = {"first": times[0], "median": statistics.median(times)}
        for label, paths in (("(page refresh, 13 requests)", REFRESH),
                             ("(page refresh, bundle)", BUNDLE)):
            walls = []
            for _ in range(runs):
                t = time.perf_counter()
                with ThreadPoolExecutor(len(paths)) as ex:
                    list(ex.map(lambda p: _get(port, p), paths))
                walls.append((time.perf_counter() - t) * 1000)
            out[label] = {"first": walls[0], "median": statistics.median(walls)}
    finally:
        if web.Handler.warmer:
            web.Handler.warmer.stop()
        srv.shutdown()
        srv.server_close()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Big synthetic DB + endpoint timings (dev only).")
    ap.add_argument("cmd", choices=("build", "bench", "all"))
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--devices", type=int, default=300)
    ap.add_argument("--events", type=int, default=100_000)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--warm", action="store_true",
                    help="start the server with its startup cache warm-up, as `run` / `web` do")
    args = ap.parse_args(argv)
    path = Path(args.db)
    if args.cmd in ("build", "all"):
        t = time.perf_counter()
        try:
            st = build(path, args.devices, args.events)
        except NotAPerfDB as e:
            print(f"refusing to overwrite {e}: not a perf DB", file=sys.stderr)
            return 1
        print(f"built {st['path']}: {st['devices']} devices, {st['events']} DNS events, "
              f"{st['traffic_samples']} traffic samples in {time.perf_counter() - t:.1f} s")
    if args.cmd in ("bench", "all"):
        res = bench(path, args.runs, args.warm)
        print(f"{'endpoint':32} {'first ms':>9} {'median ms':>10}")
        for ep, r in res.items():
            print(f"{ep:32} {r['first']:9.0f} {r['median']:10.0f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
