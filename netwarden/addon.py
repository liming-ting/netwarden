"""
netwarden - addon.py: running as a Home Assistant add-on (round 6, stage H).

Add-on mode = the Supervisor started us: SUPERVISOR_TOKEN is in the environment AND
/data/options.json is readable. Outside that (desktop, Docker, systemd, tests) nothing
here changes anything. Decisions + sources: docs/dev/ha_addon.md.

What add-on mode does (and only it):

  options      /data/options.json (what the user typed on the add-on's Configuration
               tab) is mapped onto the environment variables netwarden already reads
               (OPTION_ENV below), so the usual precedence holds unchanged:
               environment (= the add-on options) > dashboard settings (SQLite) > default.
               An option left empty sets nothing. Values are never logged.

  ingress      Home Assistant opens the dashboard in its sidebar through the Supervisor's
               ingress proxy (INGRESS_PROXY, a fixed address per the HA docs). Requests
               from exactly that peer are Home Assistant users that HA has already signed
               in (panel_admin: true = administrators only) and count as admin; only from
               it are X-Ingress-Path / X-Forwarded-* read (web.Handler._host_ok). We listen
               where the proxy connects (ingress_listen) next to loopback. LAN access stays
               off unless the `lan_access` option turns it on - and then it needs pairing,
               as always (docs/lan.md). Loopback needs a session too (REQUIRE_AUTH): with
               host networking every other host-network add-on shares our loopback.

  privileges   The add-on image starts as root only to make /data (created root-owned by
               the Supervisor) ours, then drops to the image's unprivileged `netwarden`
               user for good (prepare_and_drop) before anything else runs.

Entry point of the add-on image:  python3 -m netwarden.addon   (= `netwarden run`)
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import sys
from pathlib import Path

log = logging.getLogger("netwarden.addon")

OPTIONS_PATH = Path("/data/options.json")
DATA_DIR = Path("/data")
MAX_OPTIONS = 64 * 1024            # options.json is a few hundred bytes; anything bigger is wrong
INGRESS_PROXY = "172.30.32.2"      # the Supervisor's ingress proxy (HA add-on docs)
INGRESS_PORT = 8787                # = ingress_port in ha-addon/config.yaml
SERVICE_USER = "netwarden"         # the image's unprivileged user (Dockerfile)

# option -> environment variable (the names netwarden reads everywhere else). Strings
# are trimmed; "" / missing = not set. Secrets are marked so nothing ever echoes them.
OPTION_ENV = {
    "language": "NETWARDEN_LANG",
    "timezone": "NETWARDEN_TZ",
    "dns_source": "NETWARDEN_DNS_SOURCE",
    "adguard_url": "ADGUARD_URL",
    "adguard_user": "ADGUARD_USER",
    "adguard_password": "ADGUARD_PASS",
    "pihole_url": "PIHOLE_URL",
    "pihole_password": "PIHOLE_PASSWORD",
    "ntopng_url": "NTOPNG_URL",
    "ntopng_user": "NTOPNG_USER",
    "ntopng_password": "NTOPNG_PASS",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "ai_api_key": "NETWARDEN_AI_KEY",
    "retention_days": "NETWARDEN_RETENTION_DAYS",
}
SECRET_OPTIONS = frozenset({"adguard_password", "pihole_password", "ntopng_password",
                            "anthropic_api_key", "ai_api_key"})
BOOL_OPTIONS = {"offline_ai": "NETWARDEN_OFFLINE_AI", "lan_access": "NETWARDEN_LAN"}
MAX_VALUE = 1000                   # longest string option accepted (URLs, keys)


class AddonError(ValueError):
    """/data/options.json can't be used (never carries an option VALUE)."""


def active(environ=None, options_path: Path | None = None) -> bool:
    """True only when the Supervisor started us: SUPERVISOR_TOKEN set and the options
    file readable. The token itself is never read further, stored or logged."""
    environ = os.environ if environ is None else environ
    path = options_path or OPTIONS_PATH
    return bool(environ.get("SUPERVISOR_TOKEN")) and os.access(path, os.R_OK) and path.is_file()


def read_options(path: Path | None = None) -> dict:
    """The add-on options as a dict (AddonError for a missing, huge or non-object file)."""
    path = path or OPTIONS_PATH
    try:
        raw = path.read_bytes()[:MAX_OPTIONS + 1]
    except OSError as e:
        raise AddonError(f"options unreadable: {e.__class__.__name__}") from None
    if len(raw) > MAX_OPTIONS:
        raise AddonError("options too large")
    try:
        opts = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AddonError("options are not JSON") from None
    if not isinstance(opts, dict):
        raise AddonError("options are not an object")
    return opts


def env_from_options(opts: dict, environ=None) -> dict:
    """The environment variables the options stand for ({} entries for unset ones are
    left out). Unknown options and wrong types are skipped (the Supervisor validates
    against the schema first; this is the second lock). Also: Home Assistant's own time
    zone (the TZ the Supervisor passes in) when no `timezone` option is set, and the
    add-on's fixed listening rules (loopback needs a session; port = ingress_port)."""
    environ = os.environ if environ is None else environ
    out = {}
    for key, var in OPTION_ENV.items():
        val = opts.get(key)
        if isinstance(val, bool) or val is None:
            continue
        if isinstance(val, int):
            val = str(val)
        if not isinstance(val, str):
            continue
        val = val.strip()
        if val and len(val) <= MAX_VALUE and "\n" not in val and "\0" not in val:
            out[var] = val
    for key, var in BOOL_OPTIONS.items():
        if isinstance(opts.get(key), bool):
            out[var] = "1" if opts[key] else "0"
    if "NETWARDEN_TZ" not in out and _zone_name(environ.get("TZ")):
        out["NETWARDEN_TZ"] = environ["TZ"].strip()
    out.update(NETWARDEN_HEADLESS="1", NETWARDEN_REQUIRE_AUTH="1",
               NETWARDEN_HOST="127.0.0.1", NETWARDEN_PORT=str(INGRESS_PORT))
    return out


def _zone_name(name) -> bool:
    """A plausible IANA zone name ("Europe/Berlin"), not a POSIX TZ rule string."""
    return isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z_]+(/[A-Za-z0-9_+-]+){0,2}",
                                                       name.strip()))


def described(opts: dict) -> list[str]:
    """For the log: which options are set - names only, secrets as "set", never a value."""
    return sorted(k for k, v in opts.items()
                  if k in OPTION_ENV or k in BOOL_OPTIONS if v not in (None, "", False))


def ingress_listen(proxy: str = INGRESS_PROXY) -> str:
    """The local address the ingress proxy reaches us on. With host networking that is
    this host's address on the Supervisor's network (172.30.32.1 by default): the
    source address the kernel would use toward the proxy (a UDP connect() only picks a
    route - nothing is sent). Never a public or unspecified address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((proxy, 9))
        ip = s.getsockname()[0]
    except OSError:
        ip = ""
    finally:
        s.close()
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "172.30.32.1"
    if a.version != 4 or not a.is_private or a.is_unspecified or ip == proxy:
        return "172.30.32.1"
    return ip


def prepare_and_drop(data_dir: Path | None = None, user: str = SERVICE_USER) -> bool:
    """As root: give /data (and what we wrote there before) to `user`, then become that
    user for good. options.json stays root's (read-only for us). Not root: nothing to do.
    Returns True when the privileges were dropped. A failure keeps running as root (the
    add-on must still start) and says so in the log."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    import pwd   # POSIX only
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        log.warning("add-on: no %r user in this image; running as root", user)
        return False
    data_dir = data_dir or DATA_DIR
    try:
        os.chown(data_dir, pw.pw_uid, pw.pw_gid)
        for root, dirs, files in os.walk(data_dir):
            for name in dirs + files:
                p = Path(root) / name
                if p.resolve() == (data_dir / OPTIONS_PATH.name).resolve() or p.is_symlink():
                    continue
                os.chown(p, pw.pw_uid, pw.pw_gid)
        os.setgroups([])
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    except OSError as e:
        log.warning("add-on: could not switch to the %r user (%s); running as root",
                    user, e.__class__.__name__)
        return False
    os.environ["HOME"] = str(data_dir)
    return True


def main(argv=None) -> int:
    """The add-on image's command: options -> environment, drop root, then `run`.
    Extra arguments go to `run` (e.g. --verbose)."""
    from netwarden import __main__ as cli, i18n   # lazy: keeps `import netwarden.addon` light
    lang = i18n.normalize(os.environ.get("NETWARDEN_LANG"))
    # until `run` sets up logging (stderr in headless mode), this module's own lines go
    # to stderr = the add-on's Log tab: a handler on this logger only, gone before `run`
    early = logging.StreamHandler(sys.stderr)
    early.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(early)
    old_level = log.level
    log.setLevel(logging.INFO)
    try:
        if not active():
            print(i18n.t("cli.addon.not_addon", lang, path=OPTIONS_PATH, cmd="netwarden run"),
                  file=sys.stderr)
            return 2
        try:
            opts = read_options()
        except AddonError as e:
            log.error("add-on options: %s", e)    # what is wrong - never a value
            print(i18n.t("cli.addon.bad_options", lang, path=OPTIONS_PATH), file=sys.stderr)
            return 2
        os.environ.update(env_from_options(opts))
        log.info("add-on options set: %s", ", ".join(described(opts)) or "none")
        prepare_and_drop()
    finally:
        log.removeHandler(early)
        log.setLevel(old_level)
    return cli.cmd_run(list(argv if argv is not None else sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
