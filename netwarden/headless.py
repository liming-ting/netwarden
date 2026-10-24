"""
netwarden - headless.py: running without a browser on the same machine (round 6).

A Raspberry Pi, a NAS or a container has no browser of its own, and admin actions
(settings, pairing, port checks) are normally for this computer's browser only. Two
things make such an install usable - both opt-in through the environment, so the
desktop `python3 -m netwarden run` behaves exactly as before:

  where it listens   NETWARDEN_HOST  127.0.0.1 (default) | a private LAN address
                                     (LAN mode on that address) | 0.0.0.0 (LAN mode on
                                     every interface: containers with bridge networking)
                     NETWARDEN_PORT  8787 by default
                     Anything else (a public address, a name) is refused at start.
                     LAN mode always means pairing (docs/lan.md).

  claiming it        NETWARDEN_HEADLESS=1 (the image and the systemd unit set it): on a
                     start in LAN mode, while nobody has redeemed an admin code yet
                     (pairing.claimed), ONE admin code is printed to standard output -
                     `docker logs` / `journalctl` is enough to sign in as admin from a
                     browser on the LAN. Never written to the log file, never served over
                     HTTP; once claimed, later starts print nothing. `pair --admin` makes
                     a new code at any time from a shell on the box.

Logs go to standard error as plain lines in headless mode (runner.setup_logging).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from netwarden import i18n, pairing

DEFAULT_PORT = 8787
ALL = "0.0.0.0"


class ListenError(ValueError):
    """NETWARDEN_HOST / NETWARDEN_PORT can't be used; `code` = cli.listen.<code>."""
    def __init__(self, code: str, value: str):
        super().__init__(f"{code}: {value!r}")
        self.code, self.value = code, value


def truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def is_headless(env: dict) -> bool:
    return truthy(env.get("NETWARDEN_HEADLESS"))


def port(env: dict) -> int:
    """NETWARDEN_PORT, else 8787 (ListenError for anything that isn't 1-65535)."""
    raw = str(env.get("NETWARDEN_PORT") or "").strip()
    if not raw:
        return DEFAULT_PORT
    if not raw.isdigit() or not 0 < int(raw) < 65536:
        raise ListenError("bad_port", raw)
    return int(raw)


def listen(env: dict) -> dict:
    """{"lan", "lan_host", "bind_all"} from NETWARDEN_HOST (see the module doc).
    Loopback / unset = what the desktop always did: nothing extra."""
    raw = str(env.get("NETWARDEN_HOST") or "").strip()
    off = {"lan": False, "lan_host": None, "bind_all": False}
    if not raw or raw == "localhost":
        return off
    if raw == ALL:
        return {"lan": True, "lan_host": None, "bind_all": True}
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        raise ListenError("bad_host", raw) from None
    if addr.is_loopback:   # 127.x or ::1: this machine only (served on 127.0.0.1)
        return off
    if not pairing.is_lan_ip(raw):   # a public address: never
        raise ListenError("public_host", raw)
    return {"lan": True, "lan_host": raw, "bind_all": False}


def claim_lines(db, lang: str, base_url: str, now: datetime | None = None) -> list[str]:
    """The framed "claim this install" block with a fresh admin code - or [] when an
    admin code was redeemed here before (claimed installs never print one again)."""
    if pairing.claimed(db):
        return []
    c = pairing.new_code(db, now=now, admin=True)
    t = lambda k, **kw: i18n.t("cli.claim." + k, lang, **kw)  # noqa: E731
    bar = "=" * 72
    return [bar, t("title"), "",
            "  " + t("open", url=base_url + "/pair", code=c["display"]),
            "  " + t("link", url=f"{base_url}/pair#{c['code']}"),
            "  " + t("expires", minutes=c["ttl_s"] // 60,
                     time=c["expires_at"][:16].replace("T", " ") + " UTC"),
            "  " + t("new_code", cmd="netwarden pair --admin"),
            "  " + t("note"), bar]
