#!/usr/bin/env python3
"""
netwarden soak test (Stage K): run the whole app for a while under steady load and watch
for leaks or unbounded growth.

    python3 scripts/soak.py --minutes 20                 # /tmp/nw_soak.db, port 8799
    python3 scripts/soak.py --minutes 2 --scale 30       # a quick look

What runs, all in this one process (so /proc/self tells the truth about it):
  * the dashboard server (web.make_server, warm-up on) on 127.0.0.1:<port> with the
    OFFLINE AI, over a fresh demo home built at --db (never data/*.db);
  * the background loops (runner.Runner) with accelerated intervals: dns + traffic fed
    by a FAKE AdGuard Home and a FAKE ntopng on ephemeral 127.0.0.1 ports (new queries
    and growing byte counters on every poll), health, notify, and prune with retention
    at its minimum. Discovery / presence are left out: they would sweep the real LAN;
  * a client: page refreshes (/api/overview + the other GETs), device drawers,
    searches, notes written and undone, live streams that reconnect like page reloads,
    and connections that are abandoned half-way or never send anything.

Every --sample seconds one JSON line: threads, RSS, open fds / sockets, DB + WAL size,
row counts, cache size, live subscribers, loop failures, request errors. The end
prints a verdict comparing the first sample after warm-up with the last one; exit code
1 when something grew beyond the thresholds (or a request answered 5xx).

Never touches the network beyond 127.0.0.1 (plus the health loop's ping of the
default gateway, exactly as `netwarden run` does), never calls the LLM.
"""
from __future__ import annotations

import argparse
import http.client
import http.server
import json
import os
import random
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netwarden import brain, cache, demo, live, runner, store, web  # noqa: E402

DOMAINS = ("www.youtube.com", "i.ytimg.com", "graph.facebook.com", "doubleclick.net",
           "app-measurement.com", "api.netflix.com", "time.apple.com", "connectivitycheck.gstatic.com",
           "tiktokcdn.com", "updates.example.org", "weird-%d.example", "cdn.discordapp.com")


# --- fake data sources ----------------------------------------------------------------

class FakeSources:
    """AdGuard Home's /control/querylog and ntopng's active-hosts API, made up as asked."""

    def __init__(self, ips: list, per_poll: int = 40):
        self.ips, self.counters, self.lock = ips, {}, threading.Lock()
        self.rng = random.Random(7)
        self.per_poll = per_poll

    def querylog(self, params: dict) -> dict:
        if params.get("older_than"):
            return {"data": []}
        now = datetime.now(timezone.utc)
        data = []
        for i in range(self.per_poll):
            d = self.rng.choice(DOMAINS)
            d = d % self.rng.randrange(50) if "%d" in d else d
            blocked = d in ("doubleclick.net", "app-measurement.com")
            at = now - timedelta(milliseconds=25 * i)
            data.append({"time": at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z",   # AdGuard: ns
                         "client": self.rng.choice(self.ips), "question": {"name": d, "type": "A"},
                         "status": "NOERROR", "elapsedMs": str(self.rng.uniform(0.5, 40)),
                         "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
                         "upstream": "1.1.1.1:53", "cached": False})
        data.sort(key=lambda e: e["time"], reverse=True)
        return {"data": data, "oldest": data[-1]["time"] if data else ""}

    def hosts(self) -> dict:
        with self.lock:
            for ip in self.ips:
                rx, tx = self.counters.get(ip, (0, 0))
                self.counters[ip] = (rx + self.rng.randrange(10 ** 6), tx + self.rng.randrange(10 ** 5))
            data = [{"ip": ip, "is_localhost": True, "vlan": 0,
                     "bytes": {"recvd": rx, "sent": tx}} for ip, (rx, tx) in self.counters.items()]
        return {"rc": 0, "rc_str": "OK", "rsp": {"data": data, "currentPage": 1,
                                                 "perPage": 1000, "totalRows": len(data)}}

    def serve(self) -> tuple:
        src = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                from urllib.parse import parse_qs, urlparse
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                body = src.querylog(q) if u.path == "/control/querylog" else \
                    src.hosts() if u.path.startswith("/lua/") else {}
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, name="soak-fake-sources", daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"


# --- the client -------------------------------------------------------------------------

class Client:
    GETS = ("/api/overview", "/api/inventory", "/api/alerts", "/api/inbox", "/api/status",
            "/api/meta", "/api/privacy", "/api/health", "/api/suggestions", "/api/score",
            "/api/presence", "/api/screentime", "/api/weekly", "/api/people", "/api/search?q=you",
            "/api/search?q=%s", "/api/timeline?mac=%s", "/api/device?mac=%s",
            "/api/activity?mac=%s", "/api/since?t=%s", "/api/locale?lang=%s")

    def __init__(self, port: int, macs: list, stop: threading.Event):
        self.port, self.macs, self.stop = port, macs, stop
        self.rng = random.Random(11)
        self.counts = {"ok": 0, "4xx": 0, "5xx": 0, "net": 0, "streams": 0, "stream_refused": 0,
                       "events": 0}
        self.errors: list = []
        self.lock = threading.Lock()

    def _count(self, key, detail=None):
        with self.lock:
            self.counts[key] += 1
            if detail and len(self.errors) < 50:
                self.errors.append(detail)

    def request(self, method, path, body=None):
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
            hdrs = {"content-type": "application/json"} if body is not None else {}
            c.request(method, path, json.dumps(body) if body is not None else None, hdrs)
            r = c.getresponse()
            data = r.read()
            c.close()
        except OSError as e:
            self._count("net", f"{method} {path}: {e!r}")
            return None, None
        key = "ok" if r.status < 400 else "4xx" if r.status < 500 else "5xx"
        self._count(key, f"{method} {path}: {r.status} {data[:200]!r}" if key == "5xx" else None)
        return r.status, data

    def fill(self, path: str) -> str:
        if "%s" not in path:
            return path
        if "mac=" in path:
            return path % self.rng.choice(self.macs)
        if "since?t=" in path:
            return path % datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        if "lang=" in path:
            return path % self.rng.choice(("zh-Hant", "en", "ja", "de"))
        return path % "".join(self.rng.choice("abcdefghijklmnop") for _ in range(self.rng.randrange(2, 9)))

    def pages(self):
        while not self.stop.is_set():
            for path in self.rng.sample(self.GETS, 6):
                self.request("GET", self.fill(path))
            if self.rng.random() < 0.3:
                mac = self.rng.choice(self.macs)
                self.request("POST", "/api/label", {"mac": mac, "label": f"soak {self.rng.randrange(99)}"})
                self.request("POST", "/api/label", {"mac": mac, "label": ""})
                self.request("POST", "/api/ack", {"mac": mac, "domain": "doubleclick.net"})
                self.request("POST", "/api/unack", {"mac": mac, "domain": "doubleclick.net"})
            self.stop.wait(self.rng.uniform(0.5, 2.0))

    def stream(self):
        """A live stream like the page's: reconnect (with the last id) every ~45 s."""
        last = None
        while not self.stop.is_set():
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=40)
                c.request("GET", "/api/stream", headers={"last-event-id": last} if last else {})
                r = c.getresponse()
                if r.status != 200:   # 429: the old stream is not gone yet - back off like the page
                    r.read()
                    c.close()
                    self._count("stream_refused")
                    self.stop.wait(self.rng.uniform(3, 8))
                    continue
                self._count("streams")
                ends = time.monotonic() + self.rng.uniform(30, 60)
                while time.monotonic() < ends and not self.stop.is_set():
                    line = r.fp.readline()
                    if not line:
                        break
                    if line.startswith(b"id: "):
                        last = line[4:].decode().strip()
                        self._count("events")
                c.close()
            except OSError as e:
                self._count("net", f"stream: {e!r}")
                self.stop.wait(1)

    def rude(self):
        """Connections that go away half-way or never say anything."""
        while not self.stop.is_set():
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
                kind = self.rng.random()
                if kind < 0.4:
                    s.sendall(b"GET /api/overview HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % self.port)
                elif kind < 0.7:
                    s.sendall(b"GET /api/overview HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port)
                    s.recv(10)          # read a little of the answer, then hang up
                s.close()
            except OSError:
                pass
            self.stop.wait(self.rng.uniform(1, 4))


# --- sampling -----------------------------------------------------------------------------

def proc_status() -> dict:
    out = {}
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                out[line.split(":")[0]] = int(line.split()[1]) // 1024   # MB
    except OSError:
        pass
    fds = socks = 0
    try:
        for fd in os.listdir("/proc/self/fd"):
            fds += 1
            try:
                if os.readlink(f"/proc/self/fd/{fd}").startswith("socket:"):
                    socks += 1
            except OSError:
                pass
    except OSError:
        pass
    return {"rss_mb": out.get("VmRSS"), "peak_mb": out.get("VmHWM"), "fds": fds, "sockets": socks}


def sample(t0, db_path: Path, run: runner.Runner, client: Client) -> dict:
    db = sqlite3.connect(db_path)
    try:
        rows = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]   # fixed names
                for t in ("dns_events", "traffic_samples", "health_samples", "notify_log")}
        oldest = db.execute("SELECT MIN(ts) FROM dns_events").fetchone()[0]
        cutoff = (datetime.now(timezone.utc) - timedelta(days=store.MIN_RETENTION_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
        rows["expired_rows"] = db.execute("SELECT COUNT(*) FROM dns_events WHERE ts < ?",
                                          (cutoff,)).fetchone()[0]
    finally:
        db.close()
    wal = Path(str(db_path) + "-wal")
    det = live._detectors.get(live._key(db_path))
    return {"t_min": round((time.monotonic() - t0) / 60, 1), "threads": threading.active_count(),
            **proc_status(), "db_mb": round(db_path.stat().st_size / 2 ** 20, 1),
            "wal_mb": round(wal.stat().st_size / 2 ** 20, 2) if wal.exists() else 0,
            **rows, "oldest_event": oldest, "cache": cache.sizes(),
            "live_subs": len(det.subs) if det else 0,
            "loop_failures": {n: lp.failures for n, lp in run.loops.items()},
            "loop_runs": {n: lp.runs for n, lp in run.loops.items()},
            "requests": dict(client.counts)}


LIMITS = {"threads": 8, "fds": 16, "sockets": 16, "rss_mb": 60}


def verdict(first: dict, last: dict, client: Client, peak_wal: float) -> list:
    problems = []
    for k, lim in LIMITS.items():
        if (last.get(k) or 0) - (first.get(k) or 0) > lim:
            problems.append(f"{k} grew {first.get(k)} -> {last.get(k)} (limit +{lim})")
    if last["cache"]["entries"] > cache.MAX_ENTRIES or last["cache"]["locks"] > cache.MAX_LOCKS + 1:
        problems.append(f"cache over its bounds: {last['cache']}")
    if peak_wal > 32:      # checkpoint() keeps it near store.WAL_LIMIT_BYTES
        problems.append(f"WAL reached {peak_wal} MB")
    if last.get("expired_rows"):
        problems.append(f"{last['expired_rows']} DNS events older than the retention were kept")
    if any(last["loop_failures"].values()):
        problems.append(f"loops failing: {last['loop_failures']}")
    if client.counts["5xx"]:
        problems.append(f"{client.counts['5xx']} requests answered 5xx: {client.errors[:3]}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--db", default="/tmp/nw_soak.db")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--scale", type=float, default=30, help="loop intervals divided by this")
    ap.add_argument("--events", type=int, default=40,
                    help="DNS events per fake AdGuard poll (0 = fixed data, no traffic loop: "
                         "growth = a leak)")
    ap.add_argument("--sample", type=float, default=60, help="seconds between samples")
    ap.add_argument("--warmup", type=float, default=3, help="minutes before the baseline sample")
    args = ap.parse_args(argv)
    db_path = Path(args.db)
    if db_path.resolve().parent == store.DEFAULT_DB.parent.resolve():
        ap.error("use a scratch path (e.g. /tmp/nw_soak.db), never data/")
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    demo.build(db_path)
    db = store.connect(db_path)
    devs = [(r["mac"], r["ip"]) for r in db.execute("SELECT mac, ip FROM devices WHERE ip IS NOT NULL")]
    # history older than the retention: the prune loop must remove it (expired_rows -> 0)
    old = datetime.now(timezone.utc) - timedelta(days=20)
    store.insert_events(db, [{"source": "adguard", "ts": (old + timedelta(seconds=i)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"), "client_ip": devs[0][1], "client_name": None,
        "device_mac": devs[0][0], "domain": f"old-{i}.example", "qtype": "A", "status": "NOERROR",
        "reason": "", "blocked": 0, "cached": 0, "upstream": None, "elapsed_ms": 1.0,
        "block_reason": None} for i in range(2000)])
    db.close()

    fake = FakeSources([ip for _m, ip in devs], args.events)
    fsrv, furl = fake.serve()
    env = {brain.OFFLINE_ENV: "1", "ADGUARD_URL": furl, "NTOPNG_URL": furl,
           "NETWARDEN_RETENTION_DAYS": "8"}
    plan = runner.plan(env)
    jobs = {name: (max(1.0, interval / args.scale), job) for name, (interval, job) in plan.items()
            if interval is not None and name not in ("discovery", "presence")
            and not (name == "traffic" and args.events == 0)}   # fixed data: no new samples
    jobs["prune"] = (60.0, plan["prune"][1])      # the daily retention pass, every minute
    plan["notify"][1].CHECKPOINT_EVERY /= args.scale   # the hourly WAL checkpoint, scaled too
    run = runner.Runner(db_path, env, jobs=jobs, warm_hours=24)
    srv = web.make_server(db_path, args.port, env, "zh-Hant", loops=run.status, warm=True)
    threading.Thread(target=srv.serve_forever, name="soak-server", daemon=True).start()
    run.start()
    print(json.dumps({"start": True, "port": args.port, "db": str(db_path),
                      "loops": {n: i for n, (i, _j) in jobs.items()}}), flush=True)

    stop = threading.Event()
    client = Client(args.port, [m for m, _ip in devs], stop)
    workers = [threading.Thread(target=client.pages, daemon=True) for _ in range(3)]
    workers += [threading.Thread(target=client.stream, daemon=True) for _ in range(2)]
    workers.append(threading.Thread(target=client.rude, daemon=True))
    for w in workers:
        w.start()

    t0 = time.monotonic()
    end = t0 + args.minutes * 60
    samples, baseline, peak_wal = [], None, 0.0
    try:
        while time.monotonic() < end:
            time.sleep(min(args.sample, max(0.1, end - time.monotonic())))
            s = sample(t0, db_path, run, client)
            peak_wal = max(peak_wal, s["wal_mb"])
            samples.append(s)
            if baseline is None and s["t_min"] >= args.warmup:
                baseline = s
            print(json.dumps(s), flush=True)
    except KeyboardInterrupt:
        pass
    stop.set()
    t_stop = time.monotonic()
    srv.shutdown()
    web.stop_server(srv, run, timeout=3.0)
    fsrv.shutdown()
    fsrv.server_close()
    time.sleep(1)
    after = {"shutdown_s": round(time.monotonic() - t_stop, 1), "threads_after": threading.active_count(),
             "loops_alive": [n for n, lp in run.loops.items() if lp.thread.is_alive()]}
    problems = verdict(baseline or samples[0], samples[-1], client, peak_wal) if samples else ["no samples"]
    print(json.dumps({"done": True, "baseline": baseline, "last": samples[-1] if samples else None,
                      "peak_wal_mb": peak_wal, **after, "problems": problems,
                      "errors": client.errors[:10]}, ensure_ascii=False), flush=True)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
