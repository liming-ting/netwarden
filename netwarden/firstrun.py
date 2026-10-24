"""
netwarden - firstrun.py: the first-run wizard's state (Stage X).

A fresh install has no devices, no DNS events or no DNS source. The dashboard then
offers a short, skippable wizard at #/welcome:

    dns       is a DNS source (AdGuard Home / Pi-hole) configured and answering?
    scan      one discovery sweep (button; background job, like the exposure check)
    language  language + time zone          -> POST /api/settings (settings.update)
    ai        cloud / local / offline AI     -> POST /api/settings, with where data goes
    phone     optional phone access          -> lan.enabled (takes effect on restart)

Progress is kept in meta (`setup.step`, `setup.done`), so a closed tab resumes where
it stopped and "Skip" never asks again. The demo DB never needs the wizard. Nothing
here touches the network except the scan the user starts by clicking.

    status(db, env)         -> GET /api/setup
    save(db, step, done)    -> POST /api/setup {step?, done?}
    start_scan(db_path)     -> POST /api/setup/scan (refused on the demo DB / no LAN)
    scan_status(job_id)     -> GET /api/setup/scan/status?job=<id>
"""
from __future__ import annotations

import logging
import threading
import uuid

from netwarden import brain, discovery, dns_ingest, health, settings, store, wslnet

log = logging.getLogger("netwarden.firstrun")
STEPS = ("dns", "scan", "language", "ai", "phone")
DONE_KEY, STEP_KEY = "setup.done", "setup.step"


class SetupRefused(Exception):
    """A scan cannot run here -> 409 err.<code> (demo_db | no_ip_command | no_lan)."""
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _count(db, table: str) -> int:
    return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]   # fixed names only


def status(db, env: dict | None = None) -> dict:
    """Everything the wizard shows, plus `needed` (should the dashboard offer it?)."""
    env = env or {}
    demo = store.is_demo(db)
    done = store.get_meta(db, DONE_KEY) == "1"
    step = store.get_meta(db, STEP_KEY)
    devices, events = _count(db, "devices"), _count(db, "dns_events")
    dns_name = dns_ingest.dns_source_name(env)
    rec = store.source_status(db).get(dns_name or "", {})
    can_scan, why_not = discovery.availability()
    ai = brain.ai_config(env, db)
    vals = settings.values(db, env)
    return {
        "needed": bool(not demo and not done and (not devices or not events or not dns_name)),
        "done": done,
        "step": step if step in STEPS else STEPS[0],
        "steps": list(STEPS),
        "demo": demo,
        "devices": devices,
        "dns_events": events,
        "dns": {"source": dns_name, "configured": bool(dns_name),
                "last_ok_ts": rec.get("last_ok_ts"), "last_count": rec.get("last_count"),
                "error": bool(rec.get("last_error_ts") and (rec.get("last_error_ts") or "")
                              > (rec.get("last_ok_ts") or ""))},
        "scan": {"available": can_scan and not demo, "reason": "demo_db" if demo else why_not,
                 "last_ok_ts": store.source_status(db).get("discovery", {}).get("last_ok_ts"),
                 # WSL sees only part of the LAN: say so, so few devices don't look broken
                 "wsl": wslnet.is_wsl()},
        "language": vals["ui.language"],
        "timezone": vals["time.timezone"],
        "ai": {"mode": ai["mode"], "choice": ai["choice"], "destination": ai["destination"],
               "provider": ai["provider"]},
        "lan_enabled": bool(vals["lan.enabled"]),
    }


def save(db, step=None, done=None) -> None:
    """Remember where the wizard is (step one of STEPS) and/or that it is finished or
    skipped (done True). ValueError for anything else."""
    if step is None and done is None:
        raise ValueError("empty")
    if step is not None and step not in STEPS:
        raise ValueError("step")
    if done is not None and not isinstance(done, bool):
        raise ValueError("done")
    if step is not None:
        store.set_meta(db, STEP_KEY, step)
    if done is not None:
        store.set_meta(db, DONE_KEY, "1" if done else "0")


# --- the scan button: one discovery sweep in the background --------------------

_JOBS: dict = {}
_LOCK = threading.Lock()
MAX_JOBS = 10


def scan_status(job_id: str) -> dict | None:
    with _LOCK:
        j = _JOBS.get(job_id)
        return dict(j) if j else None


def start_scan(db_path, sweep=None) -> dict:
    """Start one sweep (discovery.scan_recorded) in a thread; while one runs, asking
    again returns it. `sweep(conn)` replaces the real sweep in tests."""
    db = store.connect(db_path)
    try:
        if store.is_demo(db):
            raise SetupRefused("demo_db")
    finally:
        db.close()
    if sweep is None:
        ok, why = discovery.availability()
        if not ok:
            raise SetupRefused(why or "no_lan")
        sweep = discovery.scan_recorded
    with _LOCK:
        running = next((j for j in _JOBS.values() if j["state"] == "running"), None)
        if running:
            return dict(running)
        job = {"id": uuid.uuid4().hex[:12], "state": "running", "found": None, "error": None}
        _JOBS[job["id"]] = job
        for old in list(_JOBS)[:-MAX_JOBS]:
            if _JOBS[old]["state"] != "running":
                del _JOBS[old]

    def work():
        conn = store.connect(db_path)
        try:
            found, state, err = len(sweep(conn) or []), "done", None
        except Exception as e:  # noqa: BLE001 - reported to the page, never raised in a thread
            found, state, err = None, "error", type(e).__name__
            log.warning("setup scan failed: %s", health.sanitize_error(e))
        finally:
            conn.close()
        with _LOCK:
            job.update(state=state, found=found, error=err)

    threading.Thread(target=work, name=f"netwarden-setup-{job['id']}", daemon=True).start()
    return dict(job)
