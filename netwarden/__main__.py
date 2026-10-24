"""
netwarden - the one command:  python3 -m netwarden <command> [options]

    run      dashboard + background loops in one process (what most users want)
    web      dashboard only                  scan     LAN sweep -> devices
    ingest   DNS events from AdGuard         traffic  bytes from ntopng (optional)
    alerts   changes / threats / digest      demo     seed the synthetic demo home
    status   health + hints                  prune    retention cleanup
    check    opt-in port check of your own devices (--mac M | --all)
    identify mDNS / SSDP names + the router's UPnP port mappings, once
    health   network health verdict + outage log (router or ISP?)
    pair     a one-time QR code to open the dashboard on a phone (LAN mode: run --lan)
    backup   save your own notes (names, owners, trust, rules, settings) as JSON
    restore  bring a backup back (preview first; --mode merge|replace, --dry-run)
    report   a shareable plain-language report (--period 7d|30d --privacy shareable --out F)

`<command> --help` explains each one. The older per-module CLIs
(python3 -m netwarden.web, ...dns_ingest, ...alerts, ...) keep working unchanged;
web / scan / ingest / traffic / alerts here simply hand their options to them.
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import netwarden
from netwarden import (activity, addon, alerts, backup, brain, demo, discovery, dns_ingest, exposure,
                       headless, health, i18n, identify, nethealth, pairing, qr, report, runner, search,
                       settings, store, traffic_ingest, web)

log = logging.getLogger("netwarden")
PROG = "python3 -m netwarden"


def _argv_lang(argv) -> str | None:
    """--lang X / --lang=X from a raw argv, read BEFORE the parser exists (so --help and
    parse errors already speak that language). The last one wins, like argparse."""
    found = None
    for i, a in enumerate(argv or []):
        if a == "--lang" and i + 1 < len(argv):
            found = argv[i + 1]
        elif a.startswith("--lang="):
            found = a.split("=", 1)[1]
    return found


def _env_lang(env: dict | None = None, argv=None) -> str:
    return i18n.normalize(_argv_lang(argv) or
                          (env if env is not None else brain.load_env()).get("NETWARDEN_LANG"))


def _parser(cmd: str, lang: str) -> argparse.ArgumentParser:
    return argparse.ArgumentParser(prog=f"{PROG} {cmd}", description=i18n.t(f"cli.cmd.{cmd}", lang))


def _opt_lang(ap, lang):
    ap.add_argument("--lang", default=None, help=i18n.t("cli.opt.lang", lang))


# --- run ---------------------------------------------------------------------

def cmd_run(argv) -> int:
    try:  # the banner must show up promptly even when stdout is a pipe or a file
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    env = brain.load_env()
    lang = _env_lang(env, argv)
    # `docker stop` / systemd send SIGTERM - possibly while we are still starting (and
    # as PID 1, where an unhandled SIGTERM is ignored): stop like Ctrl+C from now on
    web.on_sigterm()
    try:
        listen, default_port = headless.listen(env), headless.port(env)
    except headless.ListenError as e:
        print(i18n.t("cli.listen." + e.code, lang, value=e.value), file=sys.stderr)
        return 2
    ap = _parser("run", lang)
    ap.add_argument("--db", default=None, help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--port", type=int, default=default_port, help=i18n.t("cli.opt.port", lang))
    ap.add_argument("--no-loops", action="store_true", help=i18n.t("cli.opt.no_loops", lang))
    ap.add_argument("--demo", action="store_true", help=i18n.t("cli.opt.demo", lang))
    ap.add_argument("--offline-ai", action="store_true", help=i18n.t("cli.opt.offline_ai", lang))
    ap.add_argument("--verbose", action="store_true", help=i18n.t("cli.opt.verbose", lang))
    _lan_opts(ap, lang)
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    tr = lambda key, **kw: i18n.t("cli.run." + key, lang, **kw)  # noqa: E731

    if args.offline_ai:
        env[brain.OFFLINE_ENV] = "1"
    quiet_box = headless.is_headless(env)   # container / service: logs to stderr only
    db_path = Path(args.db) if args.db else (demo.DEMO_DB if args.demo else store.DEFAULT_DB)
    log_file = None if quiet_box else db_path.parent / "netwarden.log"
    runner.setup_logging(log_file, args.verbose, console=quiet_box)
    if args.demo:
        try:
            if demo.ensure(db_path):
                print(tr("seeded", path=db_path))
        except demo.NotADemoDB:
            print(i18n.t("cli.demo.refuse", lang, path=db_path), file=sys.stderr)
            return 1

    loops_on = not (args.no_loops or args.demo)
    run = runner.Runner(db_path, env, enabled=loops_on, warm_hours=24)
    # Stage H: started by the Home Assistant Supervisor -> also listen for its ingress
    # proxy, whose requests are signed-in HA users (netwarden/addon.py)
    in_addon = addon.active()
    try:
        srv = web.make_server(db_path, args.port, env, lang, loops=run.status, warm=True,
                              lan=listen["lan"] or web.lan_wanted(args.lan, db_path, env),
                              lan_host=args.lan_host or listen["lan_host"],
                              bind_all=args.bind_all or listen["bind_all"],
                              ingress_proxy=addon.INGRESS_PROXY if in_addon else None,
                              ingress_host=addon.ingress_listen() if in_addon else None)
    except store.DBError as e:   # Stage K: damaged / locked / unreadable: said plainly
        print(web.db_problem_text(e, lang), file=sys.stderr)
        return 2
    except web.LanError as e:
        log.debug("LAN mode refused: %s", e)
        print(i18n.t("cli.lan.no_address", lang), file=sys.stderr)
        return 1
    except OSError as e:
        log.debug("bind failed: %s", e)
        print(tr("port_busy", port=args.port), file=sys.stderr)
        return 1

    run.start()
    db = store.connect(db_path)
    is_demo = store.is_demo(db)
    info = brain.describe_provider(env, db)
    db.close()
    print(tr("started", url=f"http://127.0.0.1:{args.port}"))
    print("  " + tr("db", path=db_path) + (f"  [{i18n.t('status.demo', lang)}]" if is_demo else ""))
    print("  " + health.ai_line({"mode": info["ai_mode"], "model": info["model"],
                                 "destination": info["ai_destination"],
                                 "redact": info["ai_redact"]}, lang))
    print("  " + (tr("log", path=log_file) if log_file else tr("log_console")))
    if not loops_on:
        print("  " + tr("no_loops"))
    else:
        for name, lp in run.loops.items():
            print("  ✓ " + tr("loop_on", name=i18n.t("cli.loop." + name, lang),
                               interval=health.duration(lp.interval, lang)))
        for name, reason in run.skipped.items():
            print("  – " + tr("loop_off", name=i18n.t("cli.loop." + name, lang),
                               reason=_reason(reason, lang)))
    if web.Handler.lan:
        print("\n".join(web.lan_banner(lang)))
        # headless first start: the one admin code, on stdout only (not in the add-on:
        # Home Assistant's own sign-in already makes its sidebar panel an admin)
        if quiet_box and not in_addon:
            db = store.connect(db_path)
            try:
                claim = headless.claim_lines(db, lang, web.Handler.lan_url)
            finally:
                db.close()
            if claim:
                print("\n" + "\n".join(claim) + "\n")
                log.info("printed a one-time admin code to standard output (unclaimed install)")
    print(tr("stop_hint"))
    log.info("netwarden %s running on 127.0.0.1:%d (db %s, loops %s, ai %s, lan %s)",
             netwarden.__version__, args.port, db_path, "on" if loops_on else "off",
             info["ai_mode"], web.Handler.lan_url or "off")

    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        # a second Ctrl+C / SIGTERM while we wind down must not cut the shutdown short
        old = _ignore_signals()
        try:
            web.stop_server(srv, run, timeout=2.0)
            log.info("netwarden stopped")
            print(tr("stopped"))
        finally:
            _restore_signals(old)
    return 0


def _ignore_signals() -> dict:
    old = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            old[sig] = signal.signal(sig, signal.SIG_IGN)
        except ValueError:   # not the main thread
            pass
    return old


def _restore_signals(old: dict) -> None:
    for sig, handler in old.items():
        signal.signal(sig, handler if handler is not None else signal.SIG_DFL)


def _lan_opts(ap, lang):
    ap.add_argument("--lan", action="store_true", help=i18n.t("cli.opt.lan", lang))
    ap.add_argument("--lan-host", default=None, help=i18n.t("cli.opt.lan_host", lang))
    ap.add_argument("--bind-all", action="store_true", help=i18n.t("cli.opt.bind_all", lang))


def _reason(reason: str, lang: str) -> str:
    key = "cli.reason." + reason if reason == "not_configured" else "status.reason." + reason
    return i18n.t(key, lang)


# --- status ------------------------------------------------------------------

def _probe(port: int) -> dict | None:
    """Ask a local dashboard for its /api/status (its loops live in that process)."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1.5) as r:
            return json.load(r)
    except Exception:  # not running, another program on the port, ...
        return None


def cmd_status(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    try:   # the same port `run` listens on (NETWARDEN_PORT in containers / services)
        default_port = headless.port(env)
    except headless.ListenError:
        default_port = headless.DEFAULT_PORT
    ap = _parser("status", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--json", action="store_true", help=i18n.t("cli.opt.json", lang))
    ap.add_argument("--port", type=int, default=default_port, help=i18n.t("cli.opt.status_port", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))

    remote = _probe(args.port) if args.port else None
    db = store.connect(args.db)
    st = health.status(db, args.db, env, loops=(remote or {}).get("loops"))
    db.close()
    if args.json:
        print(json.dumps({**st, "hints": health.hints(st, lang)}, ensure_ascii=False, indent=2))
        return 0
    dashboard = None
    if args.port:
        dashboard = f"http://127.0.0.1:{args.port}" if remote else ""
    print(health.render(st, lang, dashboard=dashboard))
    return 0


# --- prune -------------------------------------------------------------------

def cmd_prune(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("prune", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--days", type=int, default=None, help=i18n.t("cli.opt.days", lang))
    ap.add_argument("--vacuum", action="store_true", help=i18n.t("cli.opt.vacuum", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    wanted = args.days if args.days is not None else env.get("NETWARDEN_RETENTION_DAYS")
    days = store.retention_days(wanted)
    if args.days is not None and args.days < store.MIN_RETENTION_DAYS:
        print(i18n.t("cli.prune.clamped", lang, min=store.MIN_RETENTION_DAYS))
    db = store.connect(args.db)
    res = store.prune(db, days, vacuum=args.vacuum)
    db.close()
    print(i18n.t("cli.prune.done", lang, dns=res["dns_events"], traffic=res["traffic_samples"],
                 days=res["days"], cutoff=res["cutoff"][:10]))
    if res["vacuumed"]:
        print(i18n.t("cli.prune.vacuumed", lang))
    return 0


# --- search ------------------------------------------------------------------

def search_lines(res: dict, lang: str) -> list[str]:
    """search.search() as plain text: one section per kind that matched (no LLM)."""
    sep = " · "
    out = []
    if res["devices"]:
        out.append(i18n.t("ui.search_devices", lang))
        for d in res["devices"]:
            # a nameless device is called "<type> · <owner>": don't repeat those two
            extra = [x for x in (d["type_name"], d["owner"]) if x and x not in d["name"]]
            out.append("  " + sep.join(x for x in (d["name"], *extra, d["room"], d["ip"],
                                                    d["mac"]) if x))
    if res["services"]:
        out.append(i18n.t("ui.search_services", lang))
        for s in res["services"]:
            out.append(f"  {s['name']} ({s['category_name']}){sep}" + i18n.t(
                "ui.search_counts", lang, n=s["queries"], devices=s["devices"]))
    if res["domains"]:
        out.append(i18n.t("ui.search_domains", lang))
        for d in res["domains"]:
            out.append(f"  {d['domain']}{sep}" + i18n.t("ui.search_counts", lang, n=d["queries"],
                                                         devices=d["devices"]))
    return out or [i18n.t("ui.search_none", lang, q=res["q"])]


def cmd_search(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("search", lang)
    ap.add_argument("query", nargs="+", help=i18n.t("cli.opt.query", lang))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--json", action="store_true", help=i18n.t("cli.opt.search_json", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    db = store.connect(args.db)
    res = search.search(db, " ".join(args.query), lang)
    db.close()
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("\n".join(search_lines(res, lang)))
    return 0


# --- check (opt-in exposure check) -------------------------------------------

def cmd_check(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("check", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    who = ap.add_mutually_exclusive_group()
    who.add_argument("--mac", default=None, help=i18n.t("cli.opt.mac", lang))
    who.add_argument("--all", action="store_true", help=i18n.t("cli.opt.all", lang))
    ap.add_argument("--json", action="store_true", help=i18n.t("cli.opt.check_json", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    tr = lambda key, **kw: i18n.t("cli.check." + key, lang, **kw)  # noqa: E731
    if not (args.mac or args.all):
        print(tr("need_target"), file=sys.stderr)
        return 2

    db = store.connect(args.db)
    try:
        if store.is_demo(db):   # made-up IPs that may be REAL devices on this LAN
            print(i18n.t("exposure.demo_refused", lang), file=sys.stderr)
            return 1
        try:
            devs = exposure.targets(db, args.mac, args.all)
        except exposure.RefusedTarget as e:
            print(i18n.t("exposure.refused_target", lang, ip=e), file=sys.stderr)
            return 1
        if not args.json:
            print(tr("start", n=len(devs), ports=len(exposure.PORTS)))
        exposure.check(db, args.mac, args.all)
        results = [{"mac": d["mac"], "name": d["name"], **(exposure.latest(db, d["mac"], lang) or {})}
                   for d in devs]
    finally:
        db.close()
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0
    for r in results:
        opened = i18n.t("list_sep", lang).join(
            f"{p['port']} {p['service']} ({p['risk_name']})" for p in r.get("open", []))
        print("  " + tr("device", name=r["name"], ip=r.get("ip", ""), open=opened or tr("none_open")))
        for p in r.get("open", []):
            if p["risk"] in exposure.RISKY:
                print(f"      {p['port']}: {p['note']}")
    print(tr("done", n=len(results)))
    return 0


# --- pair (Stage M: open the dashboard on a phone) ------------------------------

def _meta(port: int) -> dict | None:
    """The local dashboard's /api/meta (is LAN mode on?), or None if not reachable."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/meta", timeout=1.5) as r:
            return json.load(r)
    except Exception:  # not running, REQUIRE_AUTH (401), another program on the port
        return None


def cmd_pair(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    try:
        default_port = headless.port(env)
    except headless.ListenError:
        default_port = headless.DEFAULT_PORT
    ap = _parser("pair", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--port", type=int, default=default_port, help=i18n.t("cli.opt.port", lang))
    where = ap.add_mutually_exclusive_group()
    where.add_argument("--local", action="store_true", help=i18n.t("cli.opt.pair_local", lang))
    where.add_argument("--lan-host", default=None, help=i18n.t("cli.opt.lan_host", lang))
    ap.add_argument("--admin", action="store_true", help=i18n.t("cli.opt.pair_admin", lang))
    ap.add_argument("--invert", action="store_true", help=i18n.t("cli.opt.pair_invert", lang))
    todo = ap.add_mutually_exclusive_group()
    todo.add_argument("--list", action="store_true", help=i18n.t("cli.opt.pair_list", lang))
    todo.add_argument("--revoke", type=int, default=None, metavar="ID",
                      help=i18n.t("cli.opt.pair_revoke", lang))
    todo.add_argument("--revoke-all", action="store_true", help=i18n.t("cli.opt.pair_revoke_all", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    tr = lambda key, **kw: i18n.t("cli.pair." + key, lang, **kw)  # noqa: E731

    db = store.connect(args.db)
    try:
        if args.list:
            rows = pairing.sessions(db)
            if not rows:
                print(tr("none"))
            for s in rows:
                print(tr("row", id=s["id"], device=s["device"] or i18n.t("app.pair.unknown_device", lang),
                         created=s["created_at"][:16].replace("T", " ") + " UTC",
                         seen=s["last_seen"][:16].replace("T", " ") + " UTC")
                      + ("  [" + i18n.t("app.pair.admin_badge", lang) + "]" if s["admin"] else ""))
            return 0
        if args.revoke is not None:
            ok = pairing.revoke(db, args.revoke)
            print(tr("revoked" if ok else "not_found", id=args.revoke))
            return 0 if ok else 1
        if args.revoke_all:
            print(tr("revoked_all", n=pairing.revoke_all(db)))
            return 0
        # round 6: the advertised URL (Docker bridge, reverse proxy) beats the detected address
        advertised = "" if (args.local or args.lan_host) else \
            settings.get(db, env, "lan.advertised_url")
        if args.local:
            host = "127.0.0.1"
        elif advertised:
            host = urlparse(advertised).hostname
        else:
            host = args.lan_host or pairing.lan_address()
            if not host or not pairing.is_lan_ip(host):
                print(i18n.t("cli.lan.no_address", lang), file=sys.stderr)
                return 1
        code = pairing.new_code(db, admin=args.admin)
    finally:
        db.close()

    base = advertised or f"http://{host}:{args.port}"
    url = f"{base}/pair#{code['code']}"          # the code: URL fragment only
    if args.admin:   # what this code can do, before anything else
        print(tr("admin_code", minutes=code["ttl_s"] // 60))
    if args.local:
        # 127.0.0.1 only works on this computer: a QR code a phone would scan is no use
        print(tr("local_code", minutes=code["ttl_s"] // 60))
        print(tr("or_open_local", url=base + "/pair", code=code["display"]))
    else:
        print(tr("scan", minutes=code["ttl_s"] // 60))
        print()
        print(qr.terminal(url, invert=args.invert))
        print()
        print(tr("or_open", url=base + "/pair", code=code["display"]))
    print(tr("link", url=url))
    meta = _meta(args.port)
    if args.local:
        if not (meta or {}).get("require_auth", True):
            print(tr("local_hint"))
    else:
        if meta is not None and not meta.get("lan"):
            print(tr("lan_off", port=args.port))
        from netwarden import discovery, wslnet
        for line in wslnet.cli_lines(lang, args.port, host, discovery.default_iface_net_ip()[1]):
            print(line)
    print(tr("warning"))
    if args.admin:
        print(tr("admin_warning", cmd=f"{PROG} pair --list / --revoke ID"))
    return 0


# --- backup / restore (Stage X: the user's own notes as one JSON file) ------------

def cmd_backup(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("backup", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("-o", "--output", default=None, help=i18n.t("cli.opt.backup_output", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    db = store.connect(args.db)
    try:
        doc = backup.export(db)
    finally:
        db.close()
    out = Path(args.output) if args.output else Path(backup.filename())
    body = backup.dumps(doc)
    if args.output == "-":
        sys.stdout.write(body.decode("utf-8"))
        return 0
    out.write_bytes(body)
    n = sum(len(v) for v in doc["data"].values())
    print(i18n.t("cli.backup.saved", lang, path=out, n=n))
    return 0


def restore_lines(pv: dict, lang: str) -> list[str]:
    """backup.preview() as plain text: one line per section."""
    tr = lambda key, **kw: i18n.t("cli.restore." + key, lang, **kw)  # noqa: E731
    lines = [tr("title", mode=i18n.t("app.backup.mode_" + pv["mode"], lang))]
    for s in pv["sections"]:
        lines.append("  " + tr("line", section=i18n.t("app.backup.sec." + s["key"], lang),
                               add=s["add"], change=s["change"], remove=s["remove"],
                               skipped=s["skipped"]))
    return lines


def cmd_restore(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("restore", lang)
    ap.add_argument("file", help=i18n.t("cli.opt.restore_file", lang))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--mode", choices=backup.MODES, default="merge",
                    help=i18n.t("cli.opt.restore_mode", lang))
    ap.add_argument("--dry-run", action="store_true", help=i18n.t("cli.opt.dry_run", lang))
    ap.add_argument("--yes", action="store_true", help=i18n.t("cli.opt.yes", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    tr = lambda key, **kw: i18n.t("cli.restore." + key, lang, **kw)  # noqa: E731
    try:
        with open(args.file, "rb") as f:
            raw = f.read(backup.MAX_BYTES + 1)
        data = backup.parse(raw)
    except OSError:
        print(tr("unreadable", path=args.file), file=sys.stderr)
        return 1
    except backup.BadBackup as e:
        print(i18n.t("err." + e.code, lang), file=sys.stderr)
        return 1
    db = store.connect(args.db)
    try:
        pv = backup.preview(db, data, args.mode, env)
        print("\n".join(restore_lines(pv, lang)))
        if args.dry_run:
            print(tr("dry_run"))
            return 0
        if not pv["changes"]:
            print(tr("nothing"))
            return 0
        if args.mode == "replace" and not args.yes:
            print(tr("need_yes"), file=sys.stderr)
            return 1
        backup.restore(db, data, args.mode, env)
    finally:
        db.close()
    print(tr("done", n=pv["changes"]))
    return 0


# --- report (round 9 X: the shareable home-network report) ----------------------

def cmd_report(argv) -> int:
    env = brain.load_env()
    lang = _env_lang(env, argv)
    ap = _parser("report", lang)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--period", default="7d", help=i18n.t("cli.opt.report_period", lang))
    ap.add_argument("--privacy", default=report.DEFAULTS["privacy"], choices=report.PRIVACY,
                    help=i18n.t("cli.opt.report_privacy", lang))
    ap.add_argument("--names", default=report.DEFAULTS["names"], choices=report.NAMES,
                    help=i18n.t("cli.opt.report_names", lang))
    ap.add_argument("--people", default=report.DEFAULTS["people"], choices=report.PEOPLE,
                    help=i18n.t("cli.opt.report_people", lang))
    ap.add_argument("--format", default=None, choices=report.FORMATS,
                    help=i18n.t("cli.opt.report_format", lang))
    ap.add_argument("--out", "-o", default=None, help=i18n.t("cli.opt.report_out", lang))
    _opt_lang(ap, lang)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or env.get("NETWARDEN_LANG"))
    fmt = args.format or ("md" if args.out and args.out.lower().endswith(".md") else "html")
    try:
        opts = report.options({"period": args.period, "privacy": args.privacy, "names": args.names,
                               "people": args.people, "format": fmt})
    except report.BadOption as e:
        print(i18n.t("err.bad_report_option", lang, option=e.key), file=sys.stderr)
        return 2
    db = store.connect(args.db)
    try:
        body, _ctype, name = report.generate(db, lang, opts, env=env,
                                             tz=activity.local_tz(env.get("NETWARDEN_TZ") or None))
    finally:
        db.close()
    if args.out == "-":
        sys.stdout.write(body.decode("utf-8"))
        return 0
    out = Path(args.out) if args.out else Path(name)
    out.write_bytes(body)
    print(i18n.t("cli.report.saved", lang, path=out))
    return 0


# --- dispatch ----------------------------------------------------------------

COMMANDS = {
    "run": cmd_run,
    "web": lambda argv: web.main(argv, prog=f"{PROG} web"),
    "scan": lambda argv: discovery.main(["--save", *argv], prog=f"{PROG} scan"),
    "ingest": lambda argv: dns_ingest.main(argv, prog=f"{PROG} ingest"),
    "traffic": lambda argv: traffic_ingest.main(argv, prog=f"{PROG} traffic"),
    "alerts": lambda argv: alerts.main(argv, prog=f"{PROG} alerts"),
    "demo": lambda argv: demo.main(argv, prog=f"{PROG} demo"),
    "status": cmd_status,
    "prune": cmd_prune,
    "check": cmd_check,
    "search": cmd_search,
    "identify": lambda argv: identify.main(argv, prog=f"{PROG} identify"),
    "health": lambda argv: nethealth.main(argv, prog=f"{PROG} health"),
    "pair": cmd_pair,
    "backup": cmd_backup,
    "restore": cmd_restore,
    "report": cmd_report,
}


def usage(lang: str) -> str:
    width = max(len(c) for c in COMMANDS)
    lines = [i18n.t("cli.usage_title", lang, version=netwarden.__version__), "",
             i18n.t("cli.usage_line", lang, prog=PROG), "", i18n.t("cli.commands", lang)]
    lines += [f"  {c:<{width}}  {i18n.t('cli.cmd.' + c, lang)}" for c in COMMANDS]
    return "\n".join(lines)


LANG_COMMANDS = {"run", "web", "alerts", "demo", "status", "prune", "check", "search",
                 "identify", "health", "pair", "backup", "restore", "report"}   # take --lang


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    # a global `--lang X` before the command: use it here and hand it to the command
    glob_lang = None
    while argv and (argv[0] == "--lang" or argv[0].startswith("--lang=")):
        if argv[0] == "--lang":
            glob_lang, argv = (argv[1] if len(argv) > 1 else None), argv[2:]
        else:
            glob_lang, argv = argv[0].split("=", 1)[1], argv[1:]
    lang = i18n.normalize(glob_lang) if glob_lang else _env_lang()
    if glob_lang and argv and argv[0] in LANG_COMMANDS and _argv_lang(argv[1:]) is None:
        argv = [argv[0], "--lang", glob_lang, *argv[1:]]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage(lang))
        return 0 if argv else 2
    if argv[0] == "--version":
        # the first line stays exactly "netwarden <version>" (scripts parse it)
        print(f"netwarden {netwarden.__version__}")
        print(i18n.t("cli.version_license", lang, license=netwarden.LICENSE))
        print(i18n.t("cli.version_source", lang, url=netwarden.SOURCE_URL))
        return 0
    handler = COMMANDS.get(argv[0])
    if handler is None:
        print(i18n.t("cli.unknown", lang, cmd=argv[0]), file=sys.stderr)
        print(usage(lang), file=sys.stderr)
        return 2
    try:
        return handler(argv[1:]) or 0
    except store.DBError as e:   # Stage K: any command on a damaged / locked / unreadable DB
        print(web.db_problem_text(e, i18n.normalize(_argv_lang(argv[1:]) or lang)),
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:    # Ctrl+C / SIGTERM before a command's own handling began
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
