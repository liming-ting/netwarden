#!/usr/bin/env python3
"""
netwarden - upnp.py: which ports did your devices open on the router?

Many routers let any device on the LAN ask them - via UPnP IGD, with no password - to
forward a port from the internet to itself. Game consoles do it for voice chat; cheap
cameras do it so their app works from outside, which also puts the camera's video
stream (RTSP 554) or admin page on the open internet.

Read-only, part of the discovery cycle (identify.run_recorded). On the gateway that
SSDP found (its description must offer WANIPConnection / WANPPPConnection on its own
private address) netwarden calls ONLY these SOAP actions:

    GetExternalIPAddress          the home's public address (stored locally, shown masked)
    GetStatusInfo                 is the internet connection up?
    GetGenericPortMappingEntry    mapping #0, #1, ... until the router says "no more"
                                  (hard cap MAX_MAPPINGS)

Anything else is refused by soap_call() itself (ALLOWED_ACTIONS; tested), and so is a
control URL that is not plain http on the gateway's own private address. netwarden never
adds, changes or deletes a mapping: the advice is "turn UPnP off on the router, or turn
off remote access in the device's app".

Each check is a row in upnp_snapshots; each mapping keeps its first / last sighting in
upnp_mappings. Alerts (kind upnp_mapping): a mapping that appeared since an earlier
check, or one on a RISKY_PORTS port. Mute key per device: "upnp:<PROTO>:<external port>".
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from netwarden import i18n, identify, store

ALLOWED_ACTIONS = frozenset({"GetExternalIPAddress", "GetGenericPortMappingEntry",
                             "GetStatusInfo"})
MAX_MAPPINGS = 256
SOAP_TIMEOUT = 3.0
TOTAL_BUDGET_S = 30.0         # one check never takes longer than this
SOAP_MAX_BYTES = 32 * 1024

# Ports that should rarely face the internet from a home: remote shells, file sharing,
# remote desktops, camera streams, admin pages and (Stage Q) databases. port -> service name.
RISKY_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB",
               554: "RTSP", 1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
               5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 8080: "HTTP",
               8443: "HTTPS", 9200: "Elasticsearch", 27017: "MongoDB"}
ACK_PREFIX = "upnp:"


class RefusedAction(ValueError):
    """A SOAP action outside ALLOWED_ACTIONS, or a control URL we may not call."""


class SoapFault(RuntimeError):
    """The gateway answered with a UPnP error (e.g. 713 = no such mapping index)."""

    def __init__(self, code: str, text: str = ""):
        super().__init__(f"UPnPError {code} {text}".strip())
        self.code = code


def _envelope(service_type: str, action: str, args: dict) -> bytes:
    body = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in args.items())
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{escape(service_type)}">{body}</u:{action}>'
            '</s:Body></s:Envelope>').encode("utf-8")


def soap_call(control_url: str, service_type: str, action: str, args: dict | None = None,
              gateway_ip: str | None = None, fetch=identify.http_get) -> dict:
    """Call ONE read-only IGD action and return its out-arguments {name: text}.
    Refuses (RefusedAction) any action not in ALLOWED_ACTIONS, any URL that is not
    http on `gateway_ip` (a private address), before anything is sent. A UPnP error
    reply raises SoapFault. `fetch` is for tests."""
    if action not in ALLOWED_ACTIONS:
        raise RefusedAction(f"SOAP action {action!r} is not allowed (read-only)")
    if not gateway_ip or not identify.location_ok(control_url, gateway_ip):
        raise RefusedAction("control URL must be http on the gateway's private address")
    status, data = fetch(control_url, timeout=SOAP_TIMEOUT, limit=SOAP_MAX_BYTES, method="POST",
                         body=_envelope(service_type, action, args or {}),
                         headers={"Content-Type": 'text/xml; charset="utf-8"',
                                  "SOAPACTION": f'"{service_type}#{action}"'})
    try:
        root = identify.safe_xml(data)
    except (ValueError, ElementTree.ParseError):
        raise SoapFault(str(status), "unreadable reply") from None
    if status != 200:
        code = next((e.text for e in root.iter() if identify._local(e.tag) == "errorCode"), "")
        desc = next((e.text for e in root.iter()
                     if identify._local(e.tag) == "errorDescription"), "")
        raise SoapFault((code or str(status)).strip(), (desc or "").strip()[:80])
    resp = next((e for e in root.iter() if identify._local(e.tag) == action + "Response"), None)
    if resp is None:
        raise SoapFault(str(status), "no response element")
    return {identify._local(c.tag): (c.text or "").strip() for c in resp}


def _int(v, default=None):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def read_gateway(gw: dict, gateway_ip: str, fetch=identify.http_get) -> dict:
    """External IP, status and every port mapping of one gateway description (from
    identify.describe). -> {external_ip, status, mappings: [...], error}."""
    wan = gw["wan"][0]
    call = lambda action, **a: soap_call(wan["control_url"], wan["service_type"],  # noqa: E731
                                         action, a, gateway_ip, fetch)
    out = {"external_ip": None, "status": None, "mappings": [], "error": None}
    try:
        ip = call("GetExternalIPAddress").get("NewExternalIPAddress") or ""
        out["external_ip"] = ip if _valid_ip(ip) else None
    except (SoapFault, OSError, ValueError) as e:
        out["error"] = f"{type(e).__name__}: {e}"
    try:
        out["status"] = identify.clean(call("GetStatusInfo").get("NewConnectionStatus"), 32) or None
    except (SoapFault, OSError, ValueError):
        pass
    start = time.monotonic()
    for i in range(MAX_MAPPINGS):
        if time.monotonic() - start > TOTAL_BUDGET_S:
            break
        try:
            m = call("GetGenericPortMappingEntry", NewPortMappingIndex=i)
        except (SoapFault, OSError, ValueError):
            break        # 713 SpecifiedArrayIndexInvalid = the end of the list
        mapping = _mapping(m)
        if mapping:
            out["mappings"].append(mapping)
    return out


def _valid_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _mapping(m: dict) -> dict | None:
    proto = (m.get("NewProtocol") or "").upper()
    ext, port = _int(m.get("NewExternalPort")), _int(m.get("NewInternalPort"))
    client = (m.get("NewInternalClient") or "").strip()
    if proto not in ("TCP", "UDP") or not ext or not port or not _valid_ip(client):
        return None
    if not (0 < ext < 65536 and 0 < port < 65536):
        return None
    return {"protocol": proto, "external_port": ext, "internal_client": client,
            "internal_port": port, "remote_host": identify.clean(m.get("NewRemoteHost"), 64),
            "description": identify.clean(m.get("NewPortMappingDescription"), 64) or None,
            "enabled": 0 if (m.get("NewEnabled") or "1").strip() in ("0", "false") else 1,
            "lease": _lease(m.get("NewLeaseDuration"))}


MAX_LEASE = 2 ** 32 - 1   # ui4 in the IGD spec; anything bigger (or negative) is junk


def _lease(v) -> int | None:
    n = _int(v, None)
    return n if n is not None and 0 <= n <= MAX_LEASE else None


def default_gateway() -> str | None:
    """The IPv4 default gateway (Linux `ip route`), or None."""
    import re
    import subprocess
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
    except Exception:   # noqa: BLE001
        return None
    m = re.search(r"^default via (\d+\.\d+\.\d+\.\d+)", out, re.M)
    return m.group(1) if m else None


def pick_gateway(described: dict, gateway_ip: str | None) -> tuple[str, dict] | None:
    """The Internet gateway among identify.describe() results: one with a WAN
    connection service. When the default gateway is known, ONLY that address counts:
    any LAN device can answer SSDP claiming to be a router and feed fake mappings."""
    gws = [(ip, d) for ip, d in described.items() if d.get("wan")
           and (gateway_ip is None or ip == gateway_ip)]
    if not gws:
        return None
    gws.sort(key=lambda x: (x[0] != gateway_ip, x[0]))
    return gws[0]


def check_recorded(db, described: dict, ip_mac: dict, gateway_ip: str | None = None,
                   fetch=identify.http_get) -> dict:
    """One UPnP check from identify's SSDP results, stored as a snapshot and recorded in
    source_status ('upnp'). No gateway answering UPnP is a normal, calm result
    ({available: False}), not an error."""
    from netwarden import health
    if gateway_ip is None:
        gateway_ip = default_gateway()
    gw = pick_gateway(described, gateway_ip)
    if not gw:
        store.record_upnp(db, {"available": False, "gateway_ip": gateway_ip}, [])
        store.record_source_ok(db, "upnp", 0)
        return {"available": False, "mappings": 0}
    ip, desc = gw
    try:
        res = read_gateway(desc, ip, fetch)
    except Exception as e:   # noqa: BLE001 - recorded, never raised into discovery
        err = health.sanitize_error(e)
        store.record_upnp(db, {"available": False, "gateway_ip": ip, "error": err}, [])
        store.record_source_error(db, "upnp", err)
        return {"available": False, "mappings": 0, "error": err}
    for m in res["mappings"]:
        m["mac"] = ip_mac.get(m["internal_client"])
    err = health.sanitize_error(res["error"]) if res["error"] else None
    store.record_upnp(db, {"available": True, "gateway_ip": ip, "gateway_name": desc.get("name"),
                           "external_ip": res["external_ip"], "status": res["status"],
                           "error": err}, res["mappings"])
    store.record_source_ok(db, "upnp", len(res["mappings"]))
    return {"available": True, "mappings": len(res["mappings"]),
            "risky": sum(1 for m in res["mappings"] if risky_port(m))}


# --- reading -------------------------------------------------------------------------

def risky_port(m: dict) -> int | None:
    """The risky port of a mapping (external first), or None."""
    for p in (m["external_port"], m["internal_port"]):
        if p in RISKY_PORTS:
            return p
    return None


def ack_key(m: dict) -> str:
    return f"{ACK_PREFIX}{m['protocol']}:{m['external_port']}"


def mask_ip(ip: str | None) -> str | None:
    """203.0.113.57 -> 203.0.•••.•••  (the dashboard reveals it on request)."""
    if not ip:
        return None
    if ":" in ip:
        return ip.split(":")[0] + ":•••"
    parts = ip.split(".")
    return ".".join(parts[:2] + ["•••"] * (len(parts) - 2)) if len(parts) == 4 else "•••"


def mappings(db, recent_since: str | None = None) -> list:
    """The current mappings with device, risk and "new" (first seen since recent_since,
    and an earlier check existed that did not have it). Canonical, unlocalized."""
    if recent_since is None:
        recent_since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    first = store.upnp_first_ts(db)
    names = store.device_names(db)
    ip_mac = store.ip_to_mac(db)
    out = []
    for m in store.upnp_current(db):
        mac = m["mac"] or ip_mac.get(m["internal_client"])
        rp = risky_port(m)
        out.append({**m, "mac": mac, "name": names.get(mac, m["internal_client"]) if mac
                    else m["internal_client"],
                    "risky": rp is not None, "risky_port": rp,
                    "service": RISKY_PORTS.get(rp, ""),
                    "new": bool(first and m["first_seen"] > first and m["first_seen"] >= recent_since),
                    "ack": ack_key(m)})
    out.sort(key=lambda x: (not x["risky"], not x["new"], x["external_port"]))
    return out


def alerts(db, recent_since: str) -> list:
    """Alert-worthy mappings (risky, or new since an earlier check), acks NOT applied
    here (alerts.compute filters them)."""
    return [m for m in mappings(db, recent_since) if m["risky"] or m["new"]]


def mapping_text(m: dict, lang: str) -> str:
    """One plain sentence: who opened what, and why it matters."""
    desc = i18n.t("upnp.desc", lang, desc=m["description"]) if m.get("description") else ""
    line = i18n.t("upnp.line", lang, name=m["name"], proto=m["protocol"],
                  ext=m["external_port"], ip=m["internal_client"], port=m["internal_port"],
                  desc=desc)
    if m["risky"]:
        line = _join(line, i18n.t("upnp.why_risky", lang, port=m["risky_port"], service=m["service"]))
    elif m["new"]:
        line = _join(line, i18n.t("upnp.why_new", lang))
    return line


def _join(a: str, b: str) -> str:
    """Two sentences: a space after "." but none after a CJK full stop ("。")."""
    return a + ("" if a.endswith(("。", "！", "？")) else " ") + b


def localize(m: dict, lang: str) -> dict:
    return {**m, "text": mapping_text(m, lang),
            "risk_name": i18n.t("exposure.risk." + ("high" if m["risky"] else "low"), lang)}


def report(db, lang: str = i18n.DEFAULT, hours: float = 24) -> dict:
    """GET /api/upnp: {checked, available, checked_ts, gateway{ip, name}, external_ip,
    external_ip_masked, status, mappings[], summary, howto, demo}."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    snap = store.upnp_latest(db)
    acks = store.list_acks(db)
    maps = [localize(m, lang) for m in mappings(db, since)] if snap else []
    for m in maps:
        m["muted"] = bool(m["mac"]) and store.is_muted(acks, m["mac"], m["ack"])
    if not snap:
        summary = i18n.t("upnp.never", lang)
    elif not snap["available"]:
        summary = i18n.t("upnp.unavailable", lang)
    elif not maps:
        summary = i18n.t("upnp.none", lang)
    else:
        risky = sum(1 for m in maps if m["risky"] and not m["muted"])
        summary = i18n.t("upnp.summary", lang, n=len(maps))
        if risky:
            summary = _join(summary, i18n.t("upnp.summary_risky", lang, n=risky))
    # the last time the gateway answered (an unavailable snapshot keeps the old facts)
    last_ok = db.execute("SELECT * FROM upnp_snapshots WHERE available = 1 "
                         "ORDER BY ts DESC LIMIT 1").fetchone()
    ext = last_ok["external_ip"] if last_ok else None
    return {"checked": snap is not None, "available": bool(snap and snap["available"]),
            "checked_ts": snap["ts"] if snap else None,
            "gateway": {"ip": snap["gateway_ip"], "name": snap["gateway_name"]} if snap else None,
            "external_ip": ext, "external_ip_masked": mask_ip(ext),
            "status": last_ok["status"] if last_ok else None,
            "mappings": maps, "summary": summary, "howto": i18n.t("upnp.howto", lang),
            "demo": store.is_demo(db)}


def llm_line(m: dict) -> str:
    """Compact canonical English for the brain snapshot."""
    tags = [t for t, on in (("risky", m["risky"]), ("new", m["new"])) if on]
    desc = f' "{m["description"]}"' if m.get("description") else ""
    return (f"router forwards internet {m['protocol']} {m['external_port']} -> port "
            f"{m['internal_port']}{desc}" + (f" ({', '.join(tags)})" if tags else ""))
