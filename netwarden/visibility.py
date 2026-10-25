#!/usr/bin/env python3
"""
netwarden - visibility.py: which devices might be hiding from your DNS filter?

netwarden (and AdGuard / Pi-hole) only see DNS lookups that actually reach the filter.
A device that uses encrypted DNS (DoH/DoT) or a hard-coded resolver is invisible - and
unfiltered. We can't see that traffic, but we CAN spot the tell-tale signs:

  bypass   a device looked up a well-known DoH/DoT resolver hostname (dns.google,
           cloudflare-dns.com, ...) - the bootstrap lookup before it switches to
           encrypted DNS; or Firefox's canary use-application-dns.net got a normal
           answer (Firefox then may turn DoH on by itself)
  quiet    discovery still sees the device online, but it has made no DNS lookup for
           more than QUIET_HOURS although it normally looks something up every hour
  never    discovery sees the device, but it has never appeared in the DNS logs

Suggestions only (block the resolver names, answer the canary with NXDOMAIN, point the
router's DHCP DNS at the filter) - netwarden never changes any of that itself.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netwarden import cache, i18n, store

# Public encrypted-DNS (DoH/DoT) resolver hostnames -> provider. Suffix match, so
# cloudflare-dns.com also covers mozilla./chrome./security.cloudflare-dns.com.
RESOLVERS = {
    "dns.google": "Google",
    "dns.google.com": "Google",
    "dns64.dns.google": "Google",
    "cloudflare-dns.com": "Cloudflare",
    "one.one.one.one": "Cloudflare",
    "quad9.net": "Quad9",
    "doh.opendns.com": "OpenDNS",
    "doh.familyshield.opendns.com": "OpenDNS",
    "dns.nextdns.io": "NextDNS",
    "dns.adguard-dns.com": "AdGuard DNS",
    "family.adguard-dns.com": "AdGuard DNS",
    "unfiltered.adguard-dns.com": "AdGuard DNS",
    "dns.adguard.com": "AdGuard DNS",
    "dns-family.adguard.com": "AdGuard DNS",
    "dns-unfiltered.adguard.com": "AdGuard DNS",
    "doh.cleanbrowsing.org": "CleanBrowsing",
    "doh.mullvad.net": "Mullvad",
    "dns.mullvad.net": "Mullvad",
    "dns.controld.com": "Control D",
    "freedns.controld.com": "Control D",
    "doh.dns.sb": "DNS.SB",
    "dns.twnic.tw": "TWNIC (Quad101)",
    "dns.alidns.com": "AliDNS",
    "doh.pub": "DNSPod",
    "doh.360.cn": "360",
    "dns0.eu": "DNS0.EU",
    "doh.libredns.gr": "LibreDNS",
    "doh.applied-privacy.net": "Applied Privacy",
    "ordns.he.net": "Hurricane Electric",
    "doh.xfinity.com": "Xfinity",
    "mask.icloud.com": "iCloud Private Relay",
    "mask-h2.icloud.com": "iCloud Private Relay",
}
CANARY = "use-application-dns.net"   # Firefox: NXDOMAIN here = "keep using the network's DNS"

QUIET_HOURS = 6          # no DNS lookup for longer than this ...
ONLINE_WITHIN_H = 1      # ... while discovery saw the device within this many hours ...
HOURLY_MIN = 12          # ... and it queried in at least this many of the 24 h before
NEVER_SEEN_WITHIN_D = 7  # "never in DNS" only for devices discovery saw this week


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def resolver_for(domain: str) -> str | None:
    """Provider name if `domain` is (a subdomain of) a known DoH/DoT resolver."""
    d = (domain or "").lower().strip().strip(".")
    labels = d.split(".")
    for i in range(len(labels) - 1):
        key = ".".join(labels[i:])
        if key in RESOLVERS:
            return RESOLVERS[key]
    return None


def bypass(db, since: str) -> list:
    """Devices that looked up DoH/DoT resolvers (or got a normal canary answer)."""
    found: dict = {}
    for r in db.execute(
            # NXDOMAIN = the filter's own "no". A row that is blocked AND NXDOMAIN (Pi-hole's
            # canary answer, NXDOMAIN blocking mode) is ONE refused lookup, not two.
            """SELECT device_mac, domain, COUNT(*) AS n,
                      SUM(CASE WHEN blocked = 1 OR status = 'NXDOMAIN' THEN 1 ELSE 0 END) AS b
               FROM dns_events WHERE device_mac IS NOT NULL AND ts >= ?
               GROUP BY device_mac, domain""", (since,)):
        dom = r["domain"].lower().strip(".")
        provider = resolver_for(dom)
        canary = dom == CANARY
        if not (provider or canary):
            continue
        blocked = r["b"] or 0
        item = found.setdefault(r["device_mac"], {"mac": r["device_mac"], "resolvers": [],
                                                  "canary": None})
        if canary:
            item["canary"] = {"count": r["n"], "answered": r["n"] > blocked}
        else:
            item["resolvers"].append({"domain": dom, "provider": provider, "count": r["n"],
                                      "blocked": min(blocked, r["n"])})
    out = []
    for item in found.values():
        item["resolvers"].sort(key=lambda x: (-x["count"], x["domain"]))
        open_doh = [x for x in item["resolvers"] if x["count"] > x["blocked"]]
        canary_open = bool(item["canary"] and item["canary"]["answered"])
        # "active": something still got a real answer, so the device may really bypass
        item["active"] = bool(open_doh or canary_open)
        out.append(item)
    return out


def quiet(db, now: datetime | None = None) -> list:
    """Online (discovery) but silent in DNS for > QUIET_HOURS, although usually hourly.
    The computer netwarden runs on is left out (as in never()): it is "online" because it
    runs us, and its own lookups often take another path (WSL, Docker, the host resolver)."""
    now = now or datetime.now(timezone.utc)
    online_since = _iso(now - timedelta(hours=ONLINE_WITHIN_H))
    out = []
    for d in db.execute("SELECT mac, last_seen FROM devices WHERE last_seen >= ? AND is_self = 0",
                        (online_since,)).fetchall():
        last = db.execute("SELECT MAX(ts) FROM dns_events WHERE device_mac = ?",
                          (d["mac"],)).fetchone()[0]
        if not last:
            continue   # never in DNS at all -> never(), not quiet
        last_dt = _parse(last)
        silent_h = (now - last_dt).total_seconds() / 3600
        if silent_h <= QUIET_HOURS:
            continue
        active = db.execute(
            """SELECT COUNT(DISTINCT substr(ts, 1, 13)) FROM dns_events
               WHERE device_mac = ? AND ts >= ? AND ts <= ?""",
            (d["mac"], _iso(last_dt - timedelta(hours=24)), last)).fetchone()[0]
        if active >= HOURLY_MIN:
            out.append({"mac": d["mac"], "last_dns_ts": last, "last_seen": d["last_seen"],
                        "quiet_hours": int(silent_h), "active_hours": active})
    return out


def never(db, now: datetime | None = None) -> list:
    """Devices discovery saw this week that never appeared in the DNS logs. Empty when
    there are no DNS logs at all (then nothing is 'visible' and the list would be noise)."""
    now = now or datetime.now(timezone.utc)
    if not db.execute("SELECT EXISTS(SELECT 1 FROM dns_events WHERE device_mac IS NOT NULL)"
                      ).fetchone()[0]:
        return []
    rows = db.execute(
        """SELECT mac, ip, vendor, last_seen FROM devices d
           WHERE last_seen >= ? AND is_self = 0
             AND NOT EXISTS (SELECT 1 FROM dns_events e WHERE e.device_mac = d.mac)
           ORDER BY last_seen DESC""",
        (_iso(now - timedelta(days=NEVER_SEEN_WITHIN_D)),)).fetchall()
    return [dict(r) for r in rows]


def analyze(db, hours: float = 24, now: datetime | None = None) -> dict:
    """Canonical (unlocalized) findings: {bypass, quiet, never, has_dns}. Without an
    explicit `now` the result is shared through netwarden.cache."""
    if now is None:
        return cache.memo(db, "visibility.analyze", (hours,),
                          lambda: _analyze(db, hours, datetime.now(timezone.utc)))
    return _analyze(db, hours, now)


def _analyze(db, hours: float, now: datetime) -> dict:
    names = store.device_names(db)
    res = {"bypass": bypass(db, _iso(now - timedelta(hours=hours))),
           "quiet": quiet(db, now), "never": never(db, now),
           "has_dns": bool(db.execute("SELECT EXISTS(SELECT 1 FROM dns_events)").fetchone()[0])}
    for kind in ("bypass", "quiet", "never"):
        for item in res[kind]:
            item["name"] = names.get(item["mac"], item["mac"])
    return res


def issue_for(res: dict, mac: str) -> str | None:
    """The device's main visibility issue key: bypass / quiet / never / None."""
    if any(b["mac"] == mac and b["active"] for b in res["bypass"]):
        return "bypass"
    for kind in ("quiet", "never"):
        if any(x["mac"] == mac for x in res[kind]):
            return kind
    return None


# --- localized text ---------------------------------------------------------------

def _resolver_names(item: dict, lang: str, only_open: bool = True) -> str:
    rs = [x for x in item["resolvers"] if not only_open or x["count"] > x["blocked"]]
    return i18n.t("list_sep", lang).join(f"{x['domain']} ({x['provider']})" for x in rs)


def explain(kind: str, item: dict, lang: str) -> str:
    """One localized sentence for a finding."""
    if kind == "bypass":
        if not item["active"]:
            return i18n.t("visibility.bypass_blocked", lang, name=item["name"],
                          resolvers=_resolver_names(item, lang, only_open=False) or CANARY)
        if any(x["count"] > x["blocked"] for x in item["resolvers"]):
            return i18n.t("visibility.bypass_line", lang, name=item["name"],
                          resolvers=_resolver_names(item, lang))
        return i18n.t("visibility.canary_line", lang, name=item["name"])
    if kind == "quiet":
        return i18n.t("visibility.quiet_line", lang, name=item["name"], h=item["quiet_hours"])
    return i18n.t("visibility.never_line", lang, name=item["name"], ip=item.get("ip") or "?")


def suggestions(res: dict, lang: str) -> list:
    """The read-only things the user could do, for what was actually found."""
    out = []
    if any(b["active"] and any(x["count"] > x["blocked"] for x in b["resolvers"])
           for b in res["bypass"]):
        out.append(i18n.t("visibility.sugg.block_doh", lang))
    if any(b["canary"] and b["canary"]["answered"] for b in res["bypass"]):
        out.append(i18n.t("visibility.sugg.canary", lang))
    if res["quiet"] or res["never"]:
        out.append(i18n.t("visibility.sugg.dhcp", lang))
        out.append(i18n.t("visibility.sugg.hardcoded", lang))
    return out


def rules(res: dict) -> dict:
    """Copyable filter rules for the resolver names still answered (suggestions only)."""
    from netwarden import privacy   # privacy never imports visibility; keep load order simple
    doms = sorted({x["domain"] for b in res["bypass"] for x in b["resolvers"]
                   if x["count"] > x["blocked"] and privacy.rule_safe(x["domain"])})
    adguard = [f"||{d}^" for d in doms]
    if any(b["canary"] and b["canary"]["answered"] for b in res["bypass"]):
        adguard.append(f"||{CANARY}^$dnsrewrite=NXDOMAIN")
    return {"adguard": "\n".join(adguard), "pihole": "\n".join(doms)}


def report(db, hours: float = 24, lang: str = i18n.DEFAULT) -> dict:
    """GET /api/visibility: every finding with its localized explanation + suggestions."""
    from netwarden import naming   # naming -> devicetype -> ... : keep the load order simple
    lang = i18n.normalize(lang)
    res = naming.relabel(analyze(db, hours), naming.display_names(db, lang))
    items = []
    for kind in ("bypass", "quiet", "never"):
        for it in res[kind]:
            items.append({**it, "kind": kind, "text": explain(kind, it, lang)})
    summary = (i18n.t("visibility.no_dns", lang) if not res["has_dns"] else
               "" if any(i["kind"] != "bypass" or i["active"] for i in items) else
               i18n.t("visibility.all_clear", lang))
    return {"window_hours": hours, "items": items, "summary": summary,
            "suggestions": suggestions(res, lang), "rules": rules(res)}
