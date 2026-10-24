"""
netwarden - runner.py: the background loops behind `python3 -m netwarden run`.

One process = the dashboard + these loops, each in its own thread with its OWN sqlite
connection (WAL + busy_timeout in store.connect, so they never trip over each other or
the web server):

    dns        every 60 s     when a DNS source is configured (ADGUARD_URL or PIHOLE_URL;
                              one Pi-hole session for the loop's life, logged out on stop)
    traffic    every 30 s     when ntopng is configured (NTOPNG_URL)
    discovery  every 15 min   when a sweep can run here unprivileged
    health     every 60 s     gateway ping (+ the optional internet probe), outage log,
                              the daily home network score (nethealth, score)
    prune      once a day     retention: NETWARDEN_RETENTION_DAYS (default 90, min 8)

A failing job is logged (sanitized) and retried with exponential backoff; nothing a
job raises can take the process down. Loops never call the LLM. stop() returns within
~2 s: loops sleep on an Event, and the threads are daemons, so a job stuck in a slow
network call cannot hold the process hostage.
"""
from __future__ import annotations

import logging
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from netwarden import discovery, dns_ingest, health, live, settings, store, traffic_ingest

log = logging.getLogger("netwarden")

DNS_INTERVAL = 60
TRAFFIC_INTERVAL = 30
DISCOVERY_INTERVAL = 15 * 60
HEALTH_INTERVAL = 60         # gateway ping (nethealth)
PRESENCE_INTERVAL = 60       # wake-up; the check itself runs every presence.check_minutes
PRUNE_INTERVAL = 24 * 3600
NOTIFY_INTERVAL = 60         # Stage Q: quiet hours hold / release (notify.run)
PUSH_INTERVAL = 15           # round 10 N: send due push notifications (push.deliver)
MAX_BACKOFF_FACTOR = 16      # a failing job waits at most 16x its interval
WARM_LOOPS = ("dns", "traffic", "discovery")   # new data -> precompute the dashboard view


def backoff(interval: float, failures: int) -> float:
    """Seconds to wait after `failures` consecutive failures (0 = success)."""
    if failures <= 0:
        return interval
    return interval * min(2 ** (failures - 1), MAX_BACKOFF_FACTOR)


class Loop:
    """Run `job(db)` every `interval` seconds in a daemon thread until stopped."""

    def __init__(self, name: str, interval: float, job, db_path, stop: threading.Event,
                 secrets=(), after=None):
        self.name, self.interval, self.job, self.after = name, interval, job, after
        self.db_path, self.stop_event, self.secrets = str(db_path), stop, secrets
        self.failures = 0
        self.runs = 0
        self.last_run_ts = None
        self.last_ok_ts = None
        self.thread = threading.Thread(target=self._run, name=f"netwarden-{name}", daemon=True)

    def start(self) -> "Loop":
        self.thread.start()
        return self

    def _run(self) -> None:
        db = None
        while not self.stop_event.is_set():
            self.last_run_ts = store.now()
            try:
                if db is None:
                    db = store.connect(self.db_path)
                self.job(db)
                self.failures = 0
                self.last_ok_ts = store.now()
                if self.after is not None:
                    self._after(db)
                live.poke(self.db_path)   # Stage T: open dashboards look for news (cheap)
            except Exception as e:  # noqa: BLE001 - a loop must never die
                self.failures += 1
                log.warning("%s: run failed (%d in a row), retrying in %ds: %s", self.name,
                            self.failures, backoff(self.interval, self.failures),
                            health.sanitize_error(e, self.secrets))
                log.debug("%s: failure details", self.name, exc_info=True)
            self.runs += 1
            self.stop_event.wait(backoff(self.interval, self.failures))
        close = getattr(self.job, "close", None)
        if close is not None:   # e.g. log out of the Pi-hole session, in the job's own thread
            try:
                close()
            except Exception as e:  # noqa: BLE001
                log.debug("%s: close failed: %s", self.name, health.sanitize_error(e, self.secrets))
        if db is not None:
            db.close()

    def _after(self, db) -> None:
        try:   # best effort: a failed warm-up is not a failed run
            self.after(db)
        except Exception as e:  # noqa: BLE001
            log.debug("%s: warm-up failed: %s", self.name, health.sanitize_error(e, self.secrets))

    def status(self) -> dict:
        return {"running": self.thread.is_alive(), "interval_s": self.interval,
                "last_run_ts": self.last_run_ts, "last_ok_ts": self.last_ok_ts,
                "failures": self.failures}


class DnsJob:
    """The dns loop's job: ingest from one long-lived source. close() (called by the
    Loop when it stops) ends the source's session - Pi-hole has few API seats."""

    STATS_EVERY = 300   # the DNS server's own counters (Network health page), best effort

    def __init__(self, src):
        self.src = src
        self.stats_at = time.monotonic()   # not on the first run: ingest comes first

    def __call__(self, db):
        res = dns_ingest.ingest_recorded(db, self.src)
        if time.monotonic() - self.stats_at >= self.STATS_EVERY:
            self.stats_at = time.monotonic()
            dns_ingest.record_stats(db, self.src)
        return res

    def close(self) -> None:
        dns_ingest.close_source(self.src)


class HealthJob:
    """The health loop's job: ping the default gateway (+ the optional internet probe),
    update the outage log, and record today's home network score now and then."""
    SCORE_EVERY = 15 * 60

    def __init__(self, env: dict):
        self.env = env
        self.score_at = None

    def __call__(self, db):
        from netwarden import nethealth, score
        res = nethealth.probe_once(db, self.env)
        if self.score_at is None or time.monotonic() - self.score_at >= self.SCORE_EVERY:
            self.score_at = time.monotonic()
            score.record(db, self.env)
        return res


def plan(env: dict) -> dict:
    """Which loops `run` would start here -> {name: (interval, job) or (None, reason)}.
    reason: 'not_configured' | discovery.availability() reason."""
    out = {}
    if dns_ingest.configured(env):
        out["dns"] = (DNS_INTERVAL, DnsJob(dns_ingest.source_from_env(env)))
    else:
        out["dns"] = (None, "not_configured")
    tsrc = traffic_ingest.source_from_env(env)
    if tsrc is not None:
        out["traffic"] = (TRAFFIC_INTERVAL, lambda db: traffic_ingest.ingest_recorded(db, tsrc))
    else:
        out["traffic"] = (None, "not_configured")
    ok, reason = discovery.availability()
    out["discovery"] = (DISCOVERY_INTERVAL, discovery.scan_recorded) if ok else (None, reason)
    # Stage P: the light presence check wakes every minute but only probes (the presence
    # devices of people who turned presence on) every presence.check_minutes
    from netwarden import presence
    out["presence"] = (PRESENCE_INTERVAL, lambda db: presence.check_recorded(db, env)) \
        if ok else (None, reason)
    from netwarden import nethealth
    ok, reason = nethealth.availability()
    out["health"] = (HEALTH_INTERVAL, HealthJob(env)) if ok else (None, reason)
    def prune(db):
        # env NETWARDEN_RETENTION_DAYS > the dashboard setting > 90 (read at each run)
        days = store.retention_days(settings.get(db, env, "data.retention_days"))
        res = store.prune(db, days)
        log.info("prune: removed %d DNS events + %d traffic samples older than %d days",
                 res["dns_events"], res["traffic_samples"], res["days"])
        store.checkpoint(db)
    out["prune"] = (PRUNE_INTERVAL, prune)
    # Stage Q: route every alert / presence event once a minute (notify.run), so quiet
    # hours hold what happens at night and the summary is made at the window's end even
    # while no dashboard is open. Local computation only; never the LLM.
    out["notify"] = (NOTIFY_INTERVAL, NotifyJob(env))
    # Round 10 N: deliver queued push notifications (push.deliver) in their own loop, so
    # a slow notification service never delays quiet hours or the dashboard
    out["push"] = (PUSH_INTERVAL, lambda db: _push_deliver(db, env))
    return out


def _push_deliver(db, env: dict):
    from netwarden import push
    return push.deliver(db, env)


class NotifyJob:
    """The notify loop's job (notify.run), plus the hourly WAL checkpoint (Stage K):
    this loop always runs, whatever sources are configured."""
    CHECKPOINT_EVERY = 3600

    def __init__(self, env: dict):
        self.env = env
        self.checkpoint_at = time.monotonic()

    def __call__(self, db):
        from netwarden import notify, push
        res = notify.run(db, self.env)
        try:   # Round 10 N: alerts -> the push queue (local DB writes only; push loop sends)
            push.collect(db, self.env)
        except Exception as e:  # noqa: BLE001 - never at the expense of quiet hours
            log.warning("push: collect failed: %s", health.sanitize_error(e))
        if time.monotonic() - self.checkpoint_at >= self.CHECKPOINT_EVERY:
            self.checkpoint_at = time.monotonic()
            store.checkpoint(db)
        return res


def warm(db, hours: float = 24, env: dict | None = None) -> None:
    """Precompute what the dashboard reads on every refresh (netwarden.cache), right
    after new data landed - so page requests find it ready instead of each paying for
    it. Pure local computation over the store: no network, never the LLM. `env`: the
    web server's, so the suggestions are cached under the same AI configuration.
    Order = what the first page view needs first: the device list (snapshot), then the
    inbox (alerts + suggestions), Network health and the home score. A page request
    meanwhile never waits for this pass when an older result exists (cache.STALE_MAX)."""
    from netwarden import (activity, alerts, brain, cache, nethealth, presence,   # brain: most of netwarden
                           suggestions)
    with cache.batch():
        brain.snapshot(db, hours=hours)     # /api/inventory, /api/device, the AI context
        alerts.compute(db, recent_hours=hours)   # /api/alerts and the inbox
        nethealth.compute(db)       # Network health; suggestions + score build on it too
        suggestions.detect(db, env or {})   # the inbox, the score and the Suggestions view
        activity.grid(db)           # the home heatmap (/api/activity) on the overview
        presence.core(db)           # Stage P: "home now" (/api/presence, every refresh)


class Warmer:
    """Keeps the dashboard cache (netwarden.cache) warm for the web server: one pass at
    startup, so the first page does not pay for every cold computation at once, then a
    pass every EVERY seconds while the dashboard is in use (an API request within the
    last ACTIVE seconds). A pass recomputes results older than FRESH seconds, so the
    page's 30 s refresh finds still-valid results instead of just-expired ones. Pure
    local computation over the store (warm()): no network, never the LLM."""
    EVERY, ACTIVE, FRESH = 20.0, 180.0, 12.0
    # The export window (a week of DNS activity: the slow part of the CSV / report
    # downloads) is kept for export.WINDOW_TTL; refresh it when it is older than this,
    # so a click never finds it expired while the dashboard is open.
    EXPORT_FRESH = 300.0

    def __init__(self, db_path, hours: float = 24, env: dict | None = None):
        self.db_path, self.hours, self.env = str(db_path), hours, env or {}
        self.last_use = time.monotonic()   # startup counts as use: warm right away
        self.passes = 0
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="netwarden-warm", daemon=True)

    def touch(self) -> None:
        """The dashboard asked for data: keep warming for another ACTIVE seconds."""
        self.last_use = time.monotonic()

    def start(self) -> "Warmer":
        self.thread.start()
        return self

    def stop(self, timeout: float = 0.0) -> None:
        """Ask the thread to stop; wait up to `timeout` s for a pass in progress."""
        self.stop_event.set()
        if timeout > 0 and self.thread.is_alive():
            self.thread.join(timeout)

    def _run(self) -> None:
        from netwarden import cache, export   # export pulls in brain (lazy, like warm())
        db = None
        try:
            while not self.stop_event.is_set():
                if time.monotonic() - self.last_use < self.ACTIVE:
                    try:
                        db = db or store.connect(self.db_path)
                        with cache.fresher(self.FRESH):
                            warm(db, self.hours, self.env)
                        with cache.fresher(self.EXPORT_FRESH):
                            export._window(db)
                        self.passes += 1
                        live.poke(self.db_path)   # fresh results: the detector compares now
                    except Exception as e:   # noqa: BLE001 - a page request will retry
                        log.debug("dashboard warm-up failed: %s", health.sanitize_error(e))
                self.stop_event.wait(self.EVERY)
        finally:
            if db is not None:
                db.close()


class Runner:
    """Owns the loops of one `netwarden run` process. Data loops (not prune) warm the
    dashboard cache after each successful run when `warm_hours` is set."""

    def __init__(self, db_path, env: dict, enabled: bool = True, jobs: dict | None = None,
                 warm_hours: float | None = None):
        self.db_path, self.env = str(db_path), env
        self.warm_hours = warm_hours
        self.stop_event = threading.Event()
        self.loops: dict[str, Loop] = {}
        self.skipped: dict[str, str] = {}   # name -> reason it is not running
        self.jobs = plan(env) if jobs is None and enabled else (jobs or {})
        self.enabled = enabled

    def start(self) -> "Runner":
        secrets = [self.env.get(k, "") for k in
                   (*dns_ingest.SECRET_KEYS, "NTOPNG_PASS", "NTOPNG_TOKEN", "ANTHROPIC_API_KEY")]
        secrets += [v for k, v in self.env.items() if k.startswith("NETWARDEN_NOTIFY_")
                    and k.endswith(("_TOKEN", "_PASSWORD", "_SECRET", "_URL"))]
        for name, (interval, job) in self.jobs.items():
            if interval is None:
                self.skipped[name] = job
                log.info("%s loop off: %s", name, job)
                continue
            after = None
            if self.warm_hours and name in WARM_LOOPS:
                after = lambda db, h=self.warm_hours: warm(db, h, self.env)  # noqa: E731
            self.loops[name] = Loop(name, interval, job, self.db_path, self.stop_event,
                                    secrets, after=after).start()
            log.info("%s loop on: every %ss", name, interval)
        return self

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        deadline = time.monotonic() + timeout
        for lp in self.loops.values():
            lp.thread.join(max(0.0, deadline - time.monotonic()))
            if lp.thread.is_alive():  # mid-job (e.g. a slow HTTP call): it is a daemon
                log.info("%s loop still busy at shutdown; leaving it", lp.name)

    def status(self) -> dict:
        """For /api/status: {name: {running, interval_s, ...}} of the loops we started."""
        return {name: lp.status() for name, lp in self.loops.items()}


def setup_logging(log_file: Path | None, verbose: bool = False, console: bool = False) -> None:
    """stderr + a rotating file (~1 MB x 3). Quiet by default (warnings, plus our own
    info lines); --verbose = debug everything. console=True (headless: a container or
    a systemd service, whose manager keeps stderr): the info lines go to stderr too,
    one plain line each, and log_file is normally None."""
    root = logging.getLogger("netwarden")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    err = logging.StreamHandler()
    err.setLevel(logging.DEBUG if verbose else logging.INFO if console else logging.WARNING)
    err.setFormatter(fmt)
    root.addHandler(err)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setLevel(logging.DEBUG if verbose else logging.INFO)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    root.propagate = False
