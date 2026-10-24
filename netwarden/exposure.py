#!/usr/bin/env python3
"""
netwarden - exposure.py: which risky services do your own devices offer on the LAN?

OPT-IN and USER-TRIGGERED only (the dashboard's "check now" button, or
`python3 -m netwarden check --mac M | --all`); never run by the background loops.

What it does - and deliberately nothing more:
  - a plain TCP connect to a small, fixed list of well-known ports (PORTS); no payload
    is sent, no banner is read, no login is tried; the socket is closed immediately
  - CONNECT_TIMEOUT per attempt, at most MAX_WORKERS connects at the same time
  - targets are ONLY devices already in netwarden's inventory, and only at private or
    link-local addresses (RFC 1918, 169.254/16, fc00::/7, fe80::/10). Anything else is
    refused. Loopback works only through a test-only parameter.
  - refused on the demo database: its addresses are made up and may belong to REAL
    devices on the user's LAN (seeded demo results are shown instead)

Results go to the port_checks table (history kept); "newly opened" compares a device's
latest check with the one before it.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from netwarden import i18n, store

# port -> (service name, risk). Risk: "high" = should rarely be open on a home device;
# "medium" = fine if you know why it is there; "low" = usually a normal admin page.
PORTS = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    80: ("HTTP", "low"),
    443: ("HTTPS", "low"),
    445: ("SMB", "high"),
    554: ("RTSP", "medium"),
    1883: ("MQTT", "medium"),
    3389: ("RDP", "high"),
    5555: ("ADB", "high"),
    7547: ("TR-069", "high"),
    8080: ("HTTP", "low"),
    8443: ("HTTPS", "low"),
    9100: ("JetDirect", "low"),      # every network printer has it
}
RISKY = ("high", "medium")       # these raise an alert when open
CONNECT_TIMEOUT = 0.8
MAX_WORKERS = 16

_ALLOWED_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "169.254.0.0/16",                                    # IPv4 link-local
    "fc00::/7", "fe80::/10")]                            # IPv6 ULA + link-local


class RefusedTarget(ValueError):
    """The address is not a private/link-local address we are allowed to check."""


class DemoRefused(RuntimeError):
    """Live checks are off for the demo database."""


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def allowed(ip: str, allow_loopback: bool = False) -> bool:
    """True if `ip` is private / link-local (or loopback, when a test allows it)."""
    try:
        addr = ipaddress.ip_address((ip or "").split("%", 1)[0])
    except ValueError:
        return False
    if addr.is_loopback:
        return allow_loopback
    return any(addr in net for net in _ALLOWED_NETS)


def targets(db, mac: str | None = None, all_devices: bool = False,
            allow_loopback: bool = False) -> list:
    """Inventory devices to check: [{mac, ip, name}]. Only devices we know, with a
    current address that passes allowed(); a MAC that doesn't qualify -> RefusedTarget."""
    names = store.device_names(db)
    if mac:
        rows = db.execute("SELECT mac, ip FROM devices WHERE mac = ?", (mac,)).fetchall()
    elif all_devices:
        rows = db.execute("SELECT mac, ip FROM devices WHERE ip IS NOT NULL ORDER BY ip").fetchall()
    else:
        return []
    out = [{"mac": r["mac"], "ip": r["ip"], "name": names.get(r["mac"], r["mac"])}
           for r in rows if r["ip"] and allowed(r["ip"], allow_loopback)]
    if mac and not out:
        ip = rows[0]["ip"] if rows else ""
        raise RefusedTarget(ip or mac)
    return out


def _probe(ip: str, port: int, timeout: float) -> str:
    """One plain TCP connect. Nothing is sent; the socket is closed right away.
    "open" | "closed" (the host refused: it is there) | "silent" (no answer at all)."""
    try:
        # numeric only (never a DNS lookup); keeps an IPv6 "%scope" for link-local
        family, _t, _p, _c, addr = socket.getaddrinfo(
            ip, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)[0]
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex(addr)
    except OSError:
        return "silent"
    if rc == 0:
        return "open"
    return "closed" if rc == errno.ECONNREFUSED else "silent"


ONLINE_MIN = 30   # a device seen this recently is "there" even if every port stayed silent


def conclusive(db, rows: list) -> list:
    """The rows of devices the check actually reached: one answered on some port, or
    the device was seen online recently (a stealth firewall drops everything). An
    offline device or a stale IP would otherwise read as "every port closed" and make
    a real finding - and its suggestion and score deduction - silently disappear."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=ONLINE_MIN)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ")
    answered = {r["mac"] for r in rows if r.get("answered")}
    recent = {r["mac"] for r in db.execute("SELECT mac FROM devices WHERE last_seen >= ?",
                                           (since,))}
    return [r for r in rows if r["mac"] in answered or r["mac"] in recent]


def scan(devs: list, ports=None, timeout: float = CONNECT_TIMEOUT, progress=None,
         allow_loopback: bool = False) -> list:
    """Check every (device, port); returns rows {mac, ip, port, open, ts} (ts per device).
    `ports` overrides PORTS for tests only. `progress(done, total)` is called as we go."""
    ports = list(ports or PORTS)
    for d in devs:   # defense in depth: targets() already filtered
        if not allowed(d["ip"], allow_loopback):
            raise RefusedTarget(d["ip"])
    jobs = [(d, p) for d in devs for p in ports]
    done = 0
    lock = threading.Lock()
    results = {}

    def run(job):
        nonlocal done
        d, p = job
        res = _probe(d["ip"], p, timeout)
        with lock:
            results[(d["mac"], p)] = res
            done += 1
            if progress:
                progress(done, len(jobs))

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(run, jobs))
    rows = []
    for d in devs:
        ts = _iso(datetime.now(timezone.utc))
        rows += [{"mac": d["mac"], "ip": d["ip"], "port": p,
                  "open": results[(d["mac"], p)] == "open",
                  "answered": results[(d["mac"], p)] != "silent", "ts": ts} for p in ports]
    return rows


def check(db, mac: str | None = None, all_devices: bool = False, progress=None,
          ports=None, allow_loopback: bool = False) -> list:
    """Run a check and store it. Raises DemoRefused on the demo DB, RefusedTarget for a
    device without a checkable address. `ports` / `allow_loopback` are for tests only."""
    if store.is_demo(db):
        raise DemoRefused()
    devs = targets(db, mac, all_devices, allow_loopback)
    rows = scan(devs, ports=ports, progress=progress, allow_loopback=allow_loopback)
    store.insert_port_checks(db, conclusive(db, rows))   # unreached devices keep their last result
    return rows


# --- reading results ---------------------------------------------------------------

def port_info(port: int, lang: str) -> dict:
    service, risk = PORTS.get(port, ("?", "low"))
    return {"port": port, "service": service, "risk": risk,
            "risk_name": i18n.t("exposure.risk." + risk, lang),
            "note": i18n.t(f"exposure.port.{port}", lang) if port in PORTS else ""}


def latest(db, mac: str, lang: str = "en") -> dict | None:
    """The device's latest check: {ts, ip, checked, open: [port_info + new]}."""
    hist = store.port_check_history(db, mac, limit=2)
    if not hist:
        return None
    cur = hist[0]
    prev = hist[1]["ports"] if len(hist) > 1 else {}
    open_ports = []
    for port, is_open in sorted(cur["ports"].items()):
        if is_open:
            # newly opened = the previous check looked at this port and found it closed
            open_ports.append({**port_info(port, lang), "new": prev.get(port) is False})
    return {"ts": cur["ts"], "ip": cur["ip"], "checked": len(cur["ports"]), "open": open_ports}


def findings(db, lang: str = "en") -> list:
    """Alert-worthy open ports across devices (risky, or newly opened since the last check)."""
    names = store.device_names(db)
    out = []
    for mac in store.checked_macs(db):
        res = latest(db, mac, lang)
        for p in (res or {}).get("open", []):
            if p["risk"] in RISKY or p["new"]:
                out.append({"mac": mac, "name": names.get(mac, mac), "ip": res["ip"],
                            "checked_ts": res["ts"], "ack": f"port:{p['port']}", **p})
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda f: (order[f["risk"]], f["name"], f["port"]))
    return out


# --- background jobs for the dashboard ------------------------------------------------

_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
MAX_JOBS = 20


def job_status(job_id: str) -> dict | None:
    with _JOBS_LOCK:
        j = _JOBS.get(job_id)
        return dict(j) if j else None


def start_job(db_path, mac: str | None = None, all_devices: bool = False) -> dict:
    """Start a check in a background thread (POST /api/check). Validates first, so a
    demo DB or a bad target fails right away. Returns the job dict ({id, state, ...}).
    While a check runs, asking again returns that same job instead of a second one."""
    db = store.connect(db_path)
    try:
        if store.is_demo(db):
            raise DemoRefused()
        devs = targets(db, mac, all_devices)
    finally:
        db.close()
    with _JOBS_LOCK:
        running = next((j for j in _JOBS.values() if j["state"] == "running"), None)
        if running:
            return dict(running)
        job = {"id": uuid.uuid4().hex[:12], "state": "running", "done": 0,
               "total": len(devs) * len(PORTS), "devices": len(devs), "error": None,
               "macs": [d["mac"] for d in devs]}
        _JOBS[job["id"]] = job
        for old in list(_JOBS)[:-MAX_JOBS]:
            if _JOBS[old]["state"] != "running":
                del _JOBS[old]

    def progress(done, total):
        with _JOBS_LOCK:
            job["done"], job["total"] = done, total

    def work():
        conn = store.connect(db_path)
        try:
            rows = scan(devs, progress=progress)
            kept = conclusive(conn, rows)
            store.insert_port_checks(conn, kept)
            reached = {r["mac"] for r in kept}
            with _JOBS_LOCK:   # devices that did not answer keep their previous result
                job["unreachable"] = [d["mac"] for d in devs if d["mac"] not in reached]
            state, err = "done", None
        except Exception as e:  # noqa: BLE001 - reported to the UI, never raised in a thread
            state, err = "error", type(e).__name__
        finally:
            conn.close()
        with _JOBS_LOCK:
            job["state"], job["error"] = state, err

    threading.Thread(target=work, name=f"netwarden-check-{job['id']}", daemon=True).start()
    return dict(job)
