"""
netwarden - conntest.py: "Test connection" for the configured data sources.

One explicit click on the settings page (POST /api/test/<source>, this computer only)
asks ONE cheap, read-only question of a source netwarden is configured to read:

    adguard   GET /control/status                      (AdGuard Home)
    pihole    log in + GET /api/info/version, log out  (Pi-hole v6)
    ntopng    one page of active hosts                 (ntopng)
    ai        GET /models of a LOCAL / LAN AI server   (never a cloud model: that would
                                                        send a request out and may cost money)

The answer is {source, configured, ok, latency_ms, error_kind}: never a URL, a user
name, a password or an upstream error message (they can carry secrets). error_kind is
one of ERROR_KINDS; the page shows err.conn_<kind>.
"""
from __future__ import annotations

import socket
import time
import urllib.error

from netwarden import brain, dns_ingest, localai, traffic_ingest

SOURCES = ("adguard", "pihole", "ntopng", "ai")
ERROR_KINDS = ("not_configured", "refused", "unreachable", "timeout", "auth", "http",
               "bad_response", "cloud", "offline")
TIMEOUT = 5.0


def configured(name: str, env: dict, db=None) -> bool:
    if name == "adguard":
        return bool(env.get("ADGUARD_URL"))
    if name == "pihole":
        return bool(env.get("PIHOLE_URL"))
    if name == "ntopng":
        return bool(env.get("NTOPNG_URL"))
    return brain.ai_config(env, db)["mode"] != "offline"


def summary(env: dict, db=None) -> dict:
    """{source: configured?} plus which DNS source ingest reads (for the settings page)."""
    return {"sources": {n: configured(n, env, db) for n in SOURCES},
            "dns_source": dns_ingest.dns_source_name(env)}


def _kind(e: BaseException) -> str:
    """An exception from a source call -> one of ERROR_KINDS."""
    if isinstance(e, urllib.error.HTTPError):
        return "auth" if e.code in (401, 403) else "http"
    if isinstance(e, dns_ingest.PiHoleError):
        return "auth" if "401" in str(e) or "password" in str(e).lower() else "http"
    reason = getattr(e, "reason", e)
    if isinstance(reason, (socket.timeout, TimeoutError)) or isinstance(e, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(reason, ConnectionRefusedError) or isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, (ValueError, KeyError, TypeError)):
        return "bad_response"
    if isinstance(e, OSError):
        msg = str(e).lower()
        return "bad_response" if "json" in msg else "unreachable"
    return "http"


AI_KINDS = {"timeout": "timeout", "auth": "auth", "local_unreachable": "unreachable",
            "unreachable": "unreachable"}


def _probe(name: str, env: dict, db) -> None:
    """The one cheap question; raises on any failure."""
    if name == "adguard":
        src = dns_ingest.AdGuardHome(env["ADGUARD_URL"], env.get("ADGUARD_USER", ""),
                                     env.get("ADGUARD_PASS", ""), timeout=TIMEOUT)
        if not isinstance(src._get("/control/status", {}), dict):
            raise ValueError("not an AdGuard Home status")
    elif name == "pihole":
        src = dns_ingest.PiHole(env["PIHOLE_URL"], env.get("PIHOLE_PASSWORD", ""),
                                verify_tls=dns_ingest._flag(env.get("PIHOLE_VERIFY_TLS")),
                                timeout=TIMEOUT)
        try:
            if not isinstance(src._get("/api/info/version", {}), dict):
                raise ValueError("not a Pi-hole answer")
        finally:
            dns_ingest.close_source(src)
    elif name == "ntopng":
        src = traffic_ingest.source_from_env(env)
        src.timeout = TIMEOUT
        src._get({"ifid": src.ifid, "mode": "local", "currentPage": 1, "perPage": 1})
    else:
        cfg = brain.ai_config(env, db)
        p = localai.OpenAICompatibleProvider(cfg["base_url"], cfg["model"],
                                             api_key=env.get("NETWARDEN_AI_KEY"),
                                             timeout=TIMEOUT, destination=cfg["destination"])
        try:
            p.models(timeout=TIMEOUT)
        except Exception as e:   # noqa: BLE001 - localai's own error kinds
            kind = getattr(e, "kind", None)
            if kind:
                raise _Typed(AI_KINDS.get(kind, "http")) from None
            raise


class _Typed(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def check(name: str, env: dict, db=None) -> dict:
    """Test one source (ValueError for an unknown name; otherwise never raises). Never
    returns anything the source said."""
    if name not in SOURCES:
        raise ValueError(name)
    out = {"source": name, "configured": configured(name, env, db), "ok": False,
           "latency_ms": None, "error_kind": None}
    if not out["configured"]:
        out["error_kind"] = "offline" if name == "ai" else "not_configured"
        return out
    if name == "ai":
        cfg = brain.ai_config(env, db)
        if cfg["mode"] != "openai_compat":
            out["error_kind"] = "cloud"          # Anthropic: testing it would cost money
            return out
        if cfg["destination"] not in ("local", "lan"):
            out["error_kind"] = "cloud"
            return out
    t0 = time.monotonic()
    try:
        _probe(name, env, db)
        out["ok"] = True
    except _Typed as e:
        out["error_kind"] = e.kind
    except Exception as e:   # noqa: BLE001 - classified, never echoed
        out["error_kind"] = _kind(e)
    out["latency_ms"] = int((time.monotonic() - t0) * 1000)
    return out
