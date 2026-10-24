"""
netwarden - ai_tools.py: read-only lookups the AI may run while it answers.

For a concrete question ("which device used the most data last night?", "what did the
living-room TV connect to after 23:00?", "is anyone home?") the pre-built snapshot is
often too coarse. The model may then call one of the TOOLS below; brain.py runs it here,
on this computer, and sends the compact JSON result back as a tool result.

Every tool is strictly READ-ONLY and built on the modules that already compute the
dashboard (no new data collection). Each one has:

    name         stable id the model calls ("top_domains")
    label        aitool.<name> in the locales: the "Looked up: ..." chip in the AI panel
    description  what the model reads (English, like the other prompts)
    params       a strict JSON schema: enums, bounds, max lengths, no unknown keys
    handler      (ctx, args) -> a JSON-able dict

Results are capped: at most MAX_ROWS rows per list and MAX_RESULT_BYTES per result
(a "truncated" flag says so). Session adds the per-question budget (MAX_CALLS calls,
MAX_TOTAL_BYTES of results) and the privacy layer: with redaction on, tool arguments
coming back from the model are un-mapped ("[D3]" -> that device) before they run, and
results go through the conversation's Redactor before they leave this computer.

Results are DATA: device names, mDNS / SSDP names and UPnP descriptions in them are
written by devices on the LAN (hostile text). They are JSON string fields, never
instructions - the system prompt says so too.

Windows: "1h", "24h", "7d", "30d" and "last_night" (the household's bedtime window -
the first enabled bedtime rule, or that person's - else 22:00-06:00 local, of the night
that began on the previous local calendar day; capped at now).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, time as dtime, timedelta, timezone
from typing import Any, Callable

from netwarden import (activity, cache, devicetype, i18n, identify, naming, routine, services,
                       store)

log = logging.getLogger("netwarden.ai_tools")

MAX_ROWS = 50                 # per list in one result
MAX_RESULT_BYTES = 8 * 1024   # one tool result, as sent (UTF-8 JSON)
MAX_CALLS = 10                # tool calls per question
MAX_TOTAL_BYTES = 24 * 1024   # all tool results of one question
MIN_ROOM = 512                # less budget left than this: "limit reached", no clipped result
MAX_STR = 300                 # any one string in a result (UPnP descriptions are hostile)

WINDOWS = ("1h", "24h", "7d", "30d", "last_night")
WINDOW_HOURS = {"1h": 1, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}
DEFAULT_NIGHT = ("22:00", "06:00")
ONLINE_MINUTES = 30           # like dashboard.ONLINE_MINUTES
FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}$")
HHMM_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


class ToolError(ValueError):
    """A call the tool refuses: bad arguments, an unknown device, ... `code` is stable,
    `detail` (JSON-able) helps the model correct itself (e.g. the known device names)."""
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(message)
        self.code, self.message, self.detail = code, message, detail

    def result(self) -> dict:
        out = {"error": self.code, "message": self.message}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


# --- parameters --------------------------------------------------------------

@dataclass(frozen=True)
class Param:
    type: str                       # "string" | "integer" | "boolean"
    description: str
    enum: tuple = ()
    minimum: int | None = None
    maximum: int | None = None
    max_len: int = 64
    default: Any = None
    pattern: str | None = None      # a regex the (stripped) string must match

    def schema(self) -> dict:
        s: dict = {"type": self.type, "description": self.description}
        if self.enum:
            s["enum"] = list(self.enum)
        if self.type == "integer":
            s.update(minimum=self.minimum, maximum=self.maximum)
        if self.type == "string" and not self.enum:
            s["maxLength"] = self.max_len
        if self.default is not None:
            s["default"] = self.default
        return s

    def clean(self, name: str, value):
        if self.type == "boolean":
            if isinstance(value, bool):
                return value
            raise ToolError("bad_argument", f"{name} must be true or false")
        if self.type == "integer":
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                raise ToolError("bad_argument", f"{name} must be an integer")
            try:
                n = int(str(value).strip())
            except ValueError:
                raise ToolError("bad_argument", f"{name} must be an integer") from None
            if n < self.minimum or n > self.maximum:
                raise ToolError("bad_argument",
                                f"{name} must be between {self.minimum} and {self.maximum}")
            return n
        if not isinstance(value, str):
            raise ToolError("bad_argument", f"{name} must be a string")
        v = value.strip()
        if len(v) > self.max_len or any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ToolError("bad_argument", f"{name} is too long or has control characters")
        if self.enum and v not in self.enum:
            raise ToolError("bad_argument", f"{name} must be one of: {', '.join(self.enum)}")
        if self.pattern and v and not re.fullmatch(self.pattern, v):
            raise ToolError("bad_argument", f"{name} has the wrong format")
        return v


def P_window(default="24h", choices=WINDOWS) -> Param:
    return Param("string", "Time window: 1h, 24h, 7d, 30d or last_night (the household's "
                 "bedtime window last night, local time).", enum=choices, default=default)


P_DEVICE = Param("string", "One device: its name as shown, a pseudonym like [D3] or [M3], "
                 "a MAC or an IP address.", max_len=96)
P_PERSON = Param("string", "One household member by name (or pseudonym like [P1]).", max_len=64)


def P_limit(default: int, maximum: int = MAX_ROWS) -> Param:
    return Param("integer", f"How many rows at most (1-{maximum}).", minimum=1, maximum=maximum,
                 default=default)


P_TIME = r"([01]?\d|2[0-3]):[0-5]\d"


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    handler: Callable
    params: dict = field(default_factory=dict)
    required: tuple = ()

    def schema(self) -> dict:
        return {"type": "object",
                "properties": {k: p.schema() for k, p in self.params.items()},
                "required": list(self.required), "additionalProperties": False}

    def validate(self, raw) -> dict:
        """The arguments, checked and with defaults: ToolError on anything unexpected."""
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ToolError("bad_arguments", "arguments must be a JSON object")
        unknown = sorted(set(raw) - set(self.params))
        if unknown:
            raise ToolError("bad_arguments", "unknown argument(s): " + ", ".join(
                str(u)[:32] for u in unknown[:5]))
        out = {}
        for k, p in self.params.items():
            v = raw.get(k)
            if isinstance(v, str):
                v = v.strip()       # "  " is "not given", never "the whole home"
            if v is None or v == "":
                if k in self.required:
                    raise ToolError("bad_arguments", f"{k} is required")
                if p.default is not None:
                    out[k] = p.default
                continue
            out[k] = p.clean(k, v)
        return out


# --- shared helpers ------------------------------------------------------------

class Ctx:
    """What one tool run needs: the DB, the language of the text fields (canonical "en"
    for the model), the local time zone, "now" and the display names (never a bare MAC)."""

    def __init__(self, db, lang: str = "en", now: datetime | None = None, tz=None):
        self.db = db
        self.lang = i18n.normalize(lang)
        self.now = now or datetime.now(timezone.utc)
        self.tz = tz or activity.local_tz()
        self._names = None

    @property
    def names(self) -> dict:
        if self._names is None:
            self._names = naming.display_names(self.db, self.lang)
        return self._names

    def name(self, mac: str | None) -> str:
        return self.names.get(mac) or mac or "?"

    def local(self, ts: str | None) -> str | None:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt.astimezone(self.tz).strftime("%Y-%m-%d %H:%M")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(FMT)


def _hm(text: str) -> dtime:
    h, m = text.split(":")
    return dtime(int(h), int(m))


def night_window(db, tz, now: datetime, person: str | None = None) -> tuple:
    """(start, end, (start "HH:MM", end "HH:MM")) of "last night": the household's
    bedtime window (that person's enabled rule, else the first enabled rule, else
    22:00-06:00), on the night that began on the previous LOCAL calendar day - at 01:30
    that is the night still going on, at 15:00 the one that ended this morning, at 23:00
    yesterday's (tonight has barely started). The end is capped at now."""
    rules = [r for r in store.bedtime_rules(db) if r["enabled"]]
    rule = next((r for r in rules if person and r.get("owner") == person), None) or \
        (rules[0] if rules else None)
    s, e = (rule["start"], rule["end"]) if rule else DEFAULT_NIGHT
    night = now.astimezone(tz).date() - timedelta(days=1)
    start = datetime.combine(night, _hm(s), tzinfo=tz)
    if _hm(s) < dtime(12, 0):         # a window starting after midnight (bedtime.window)
        start += timedelta(days=1)
    end = datetime.combine(start.date(), _hm(e), tzinfo=tz)
    if end <= start:
        end += timedelta(days=1)
    return start, min(end, now), (s, e)


def window_bounds(ctx: Ctx, window: str, person: str | None = None,
                  after: str | None = None, before: str | None = None) -> dict:
    """{"start", "end" (aware UTC), "window", "from", "to" (local text)} of a window,
    narrowed by optional local clock times: after "23:00" moves the start to the first
    23:00 inside the window, before "02:00" the end to the first 02:00 after the start."""
    if window == "last_night":
        start, end, _hhmm = night_window(ctx.db, ctx.tz, ctx.now, person)
    else:
        end = ctx.now
        start = end - timedelta(hours=WINDOW_HOURS[window])
    for which, hhmm in (("after", after), ("before", before)):
        if not hhmm:
            continue
        ref = start
        loc = ref.astimezone(ctx.tz)
        cand = datetime.combine(loc.date(), _hm(hhmm), tzinfo=ctx.tz)
        if cand < loc:
            cand += timedelta(days=1)
        if which == "after":
            if cand < end:
                start = cand
        elif cand > start:
            end = min(end, cand)
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    return {"start": start, "end": end, "window": window,
            "from": start.astimezone(ctx.tz).strftime("%Y-%m-%d %H:%M"),
            "to": end.astimezone(ctx.tz).strftime("%Y-%m-%d %H:%M")}


def _win_out(w: dict) -> dict:
    return {"window": w["window"], "from_local": w["from"], "to_local": w["to"]}


def _norm_mac(text: str) -> str | None:
    t = text.strip().lower()
    if MAC_RE.match(t):
        hexes = re.sub(r"[^0-9a-f]", "", t)
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))
    return None


def resolve_device(ctx: Ctx, text: str) -> str:
    """The MAC of the device `text` names: a MAC (any spelling), an IP, or a name - the
    label, hostname, announced name or display name (exact, case-insensitive; then a
    unique partial match). ToolError("unknown_device" | "ambiguous_device") otherwise."""
    db, t = ctx.db, (text or "").strip()
    macs = {r["mac"]: r for r in db.execute("SELECT mac, ip, hostname FROM devices")}
    mac = _norm_mac(t)
    if mac and mac in macs:
        return mac
    for m, r in macs.items():
        if r["ip"] and r["ip"] == t:
            return m
    names: dict = {}
    for m in macs:
        names[m] = set()
    for src in (store.device_names(db), ctx.names, naming.display_names(db, "en"),
                store.identity_names(db)):
        for m, n in src.items():
            if m in names and n:
                names[m].add(str(n).casefold())
    for m, lab in store.get_labels(db).items():
        if m in names:
            names[m].add(lab["label"].casefold())
    for m, r in macs.items():
        if r["hostname"]:
            names[m].add(r["hostname"].casefold())
    q = t.casefold()
    if not q:
        raise ToolError("unknown_device", "no device given")
    exact = [m for m, ns in names.items() if q in ns]
    if len(exact) == 1:
        return exact[0]
    part = exact or [m for m, ns in names.items() if any(q in n for n in ns)]
    if len(part) == 1:
        return part[0]
    cands = sorted({ctx.name(m) for m in (part or macs)})[:12]
    if part:
        raise ToolError("ambiguous_device", f"several devices match {t[:40]!r}", {"candidates": cands})
    raise ToolError("unknown_device", f"no device matches {t[:40]!r}", {"known_devices": cands})


def resolve_person(ctx: Ctx, text: str) -> str:
    """The household member `text` names: exact (case-insensitive), then a unique WHOLE-WORD
    match either way ("Anna" -> "Anna Lee", "Mom's" -> "Mom") - never a mere substring
    ("媽媽XYZ" is nobody, not 媽媽)."""
    people = [p["name"] for p in store.people(ctx.db)]
    q = (text or "").strip().casefold()
    exact = [p for p in people if p.casefold() == q]
    if exact:
        return exact[0]

    def word_in(needle: str, hay: str) -> bool:
        return bool(needle) and re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", hay) is not None

    part = [p for p in people if q and (word_in(q, p.casefold()) or word_in(p.casefold(), q))]
    if len(part) == 1:
        return part[0]
    raise ToolError("unknown_person", f"no household member matches {text[:40]!r}",
                    {"people": people[:20]})


PRESENCE_OFF_NOTE = ("This person has not turned on presence (who's home): when their "
                     "devices were last active is not shared.")


def presence_on(ctx: Ctx, person: str) -> bool:
    """Did `person` opt in to presence? A lookup scoped to someone who did NOT never
    returns when their devices were online / last active - that would be "who's home"
    by the back door (t_presence only reports people who opted in)."""
    return any(p["name"] == person and p["presence"] for p in store.people(ctx.db))


def person_macs(ctx: Ctx, person: str) -> list:
    from netwarden import presence    # presence -> screentime -> ...: keep the import lazy
    return list(presence.owned(ctx.db).get(person, []))


def _scope(ctx: Ctx, args: dict) -> tuple:
    """(macs or None for the whole home, the scope's display text) from device / person."""
    if args.get("device"):
        mac = resolve_device(ctx, args["device"])
        return [mac], {"device": ctx.name(mac), "mac": mac}
    if args.get("person"):
        p = resolve_person(ctx, args["person"])
        return person_macs(ctx, p), {"person": p}
    return None, {"scope": "whole home"}


def _in(macs: list) -> tuple:
    return ",".join("?" * len(macs)), tuple(macs)


def human_bytes(n: float) -> str:
    from netwarden.brain import human_bytes as hb   # brain imports us
    return hb(n)


# --- the tools -----------------------------------------------------------------

STATUSES = ("any", "online", "offline")


def t_list_devices(ctx: Ctx, a: dict) -> dict:
    db = ctx.db
    types = devicetype.classify_all(db)
    profiles = store.get_profiles(db)
    since24 = _iso(ctx.now - timedelta(hours=24))
    online_since = _iso(ctx.now - timedelta(minutes=ONLINE_MINUTES))
    dns = {r[0]: (r[1], r[2]) for r in db.execute(
        "SELECT device_mac, MAX(ts), COUNT(*) FROM dns_events WHERE device_mac IS NOT NULL "
        "AND ts >= ? GROUP BY device_mac", (since24,))}
    only, private = None, False
    if a.get("person"):
        who = resolve_person(ctx, a["person"])
        only = set(person_macs(ctx, who))
        private = not presence_on(ctx, who)
        if private and a["status"] != "any":
            raise ToolError("presence_off", PRESENCE_OFF_NOTE)
    new_since = window_bounds(ctx, a["new_since"])["start"] if a.get("new_since") else None
    rows = []
    for r in db.execute("SELECT mac, ip, vendor, first_seen, last_seen, is_self FROM devices"):
        mac = r["mac"]
        if only is not None and mac not in only:
            continue
        t = (types.get(mac) or {}).get("type", "unknown")
        if a.get("category") and t != a["category"]:
            continue
        last = max(filter(None, (r["last_seen"], (dns.get(mac) or (None,))[0])))
        online = last >= online_since
        if a["status"] == "online" and not online or a["status"] == "offline" and online:
            continue
        if new_since and r["first_seen"] < _iso(new_since):
            continue
        p = profiles.get(mac) or {}
        rows.append({"name": ctx.name(mac), "mac": mac, "type": t, "vendor": r["vendor"] or None,
                     "owner": p.get("owner") or None, "room": p.get("room") or None,
                     "shared": bool(p.get("shared")) or None, "ip": r["ip"],
                     "online": online, "this_computer": bool(r["is_self"]) or None,
                     "first_seen": ctx.local(r["first_seen"]), "last_active": ctx.local(last),
                     "dns_lookups_24h": (dns.get(mac) or (None, 0))[1]})
    if private:
        rows.sort(key=lambda d: (-d["dns_lookups_24h"], d["name"].casefold()))
        for d in rows:
            d["online"] = d["last_active"] = None
    else:
        rows.sort(key=lambda d: (not d["online"], -d["dns_lookups_24h"], d["name"].casefold()))
    out = {"count": len(rows), "online_now": sum(1 for d in rows if d["online"]),
           "devices": [{k: v for k, v in d.items() if v is not None} for d in rows[:a["limit"]]]}
    if private:
        del out["online_now"]
        out["note"] = PRESENCE_OFF_NOTE
    if a.get("new_since"):
        out["new_since"] = window_bounds(ctx, a["new_since"])["from"]
    return out


def t_device_detail(ctx: Ctx, a: dict) -> dict:
    from netwarden import brain     # brain imports us
    db = ctx.db
    mac = resolve_device(ctx, a["device"])
    r = db.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    t = devicetype.classify_all(db).get(mac) or devicetype.decide([])
    p = store.get_profiles(db).get(mac) or {}
    ident = identify.summary_all(db).get(mac) or {}
    snap_d = next((d for d in brain.snapshot(db)["devices"] if d.get("mac") == mac), {})
    out = {"name": ctx.name(mac), "mac": mac, "ip": r["ip"], "vendor": r["vendor"] or None,
           "type": t["type"], "type_confidence": t.get("confidence"),
           "owner": p.get("owner") or None, "room": p.get("room") or None,
           "shared": bool(p.get("shared")) or None,
           "model": " ".join(x for x in (ident.get("manufacturer"), ident.get("model")) if x) or None,
           "randomized_mac": bool(r["randomized"]) or None,
           "first_seen": ctx.local(r["first_seen"]), "last_seen": ctx.local(r["last_seen"]),
           "trusted": (mac, "") in store.list_acks(db) or None}
    if snap_d:
        out.update(dns_lookups_24h=snap_d.get("queries"), blocked_24h=snap_d.get("blocked"),
                   services_24h=snap_d.get("services")[:10],
                   top_domains_24h=[{"domain": x["domain"], "lookups": x["count"]}
                                    for x in snap_d.get("top_domains", [])[:6]])
        for k in ("active_hours", "night_share_7d", "unusual_hours", "dns_visibility"):
            if snap_d.get(k) is not None:
                out[k] = snap_d[k]
        if snap_d.get("privacy"):
            out["privacy"] = brain.privacy_line(snap_d["privacy"])
        if snap_d.get("open_ports"):
            out["open_ports"] = brain.ports_line(snap_d["open_ports"])
        if snap_d.get("upnp_mappings"):
            out["upnp_mappings"] = snap_d["upnp_mappings"]
        if snap_d.get("bandwidth"):
            bw = snap_d["bandwidth"]
            out["data_24h"] = {"download": human_bytes(bw["rx_bytes"]),
                               "upload": human_bytes(bw["tx_bytes"])}
    else:
        out["dns_lookups_24h"] = 0
    return {k: v for k, v in out.items() if v is not None}


def t_top_domains(ctx: Ctx, a: dict) -> dict:
    macs, scope = _scope(ctx, a)
    w = window_bounds(ctx, a["window"], scope.get("person"), a.get("after"), a.get("before"))
    where, params = "ts >= ? AND ts < ?", [_iso(w["start"]), _iso(w["end"])]
    if macs is not None:
        if not macs:
            return {**scope, **_win_out(w), "lookups": 0, "domains": []}
        ph, mp = _in(macs)
        where += f" AND device_mac IN ({ph})"
        params += mp
    total = ctx.db.execute(f"SELECT COUNT(*), COUNT(DISTINCT domain) FROM dns_events WHERE {where}",
                           params).fetchone()
    rows = ctx.db.execute(
        f"""SELECT domain, COUNT(*) AS n, SUM(blocked) AS b, MIN(ts) AS f, MAX(ts) AS l,
                   COUNT(DISTINCT device_mac) AS devs
            FROM dns_events WHERE {where} GROUP BY domain ORDER BY n DESC, domain LIMIT ?""",
        params + [a["limit"]]).fetchall()
    out = []
    private = bool(scope.get("person")) and not presence_on(ctx, scope["person"])
    for r in rows:
        svc, cat = services.lookup(r["domain"])   # the id: named in ctx.lang, like the drawer
        d = {"domain": r["domain"], "lookups": r["n"], "blocked": r["b"] or 0,
             "service": services.service_name(svc, ctx.lang) if svc else None, "category": cat,
             "first_local": None if private else ctx.local(r["f"]),
             "last_local": None if private else ctx.local(r["l"])}
        kind = routine.lookup(r["domain"])
        if kind:
            d["routine"] = routine.LLM_TEXT[kind]
        if macs is None or len(macs) > 1:
            d["devices"] = r["devs"]
        out.append({k: v for k, v in d.items() if v is not None})
    res = {**scope, **_win_out(w), "lookups": total[0], "distinct_domains": total[1],
           "domains": out}
    if private:
        res["note"] = PRESENCE_OFF_NOTE
    return res


def _totals(db, since: datetime, until: datetime, now: datetime) -> dict:
    """{mac: (rx, tx)} bytes counted between since and until (a delta counts toward its
    later sample, as everywhere): the totals since `since` minus those since `until`."""
    a = store.bandwidth_totals(db, _iso(since))
    b = store.bandwidth_totals(db, _iso(until)) if until < now - timedelta(minutes=1) else {}
    out = {}
    for k, v in a.items():
        if k.startswith("ip:"):
            continue
        rx = v["rx_bytes"] - (b.get(k) or {}).get("rx_bytes", 0)
        tx = v["tx_bytes"] - (b.get(k) or {}).get("tx_bytes", 0)
        if rx > 0 or tx > 0:
            out[k] = (max(0, rx), max(0, tx))
    return out


def has_bandwidth(db) -> bool:
    return db.execute("SELECT 1 FROM traffic_samples LIMIT 1").fetchone() is not None


def t_traffic(ctx: Ctx, a: dict) -> dict:
    macs, scope = _scope(ctx, a)
    w = window_bounds(ctx, a["window"], scope.get("person"))
    if not has_bandwidth(ctx.db):
        return {**scope, **_win_out(w), "has_bandwidth": False,
                "note": "No byte counts: data volume needs the optional ntopng traffic source. "
                        "Never infer data volume from DNS lookups."}
    tot = _totals(ctx.db, w["start"], w["end"], ctx.now)
    if macs is not None:
        tot = {m: v for m, v in tot.items() if m in set(macs)}
    ranked = sorted(tot.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
    rows = [{"name": ctx.name(m), "mac": m, "download": human_bytes(rx), "upload": human_bytes(tx),
             "total": human_bytes(rx + tx), "total_bytes": rx + tx}
            for m, (rx, tx) in ranked[:a["limit"]]]
    all_rx = sum(v[0] for v in tot.values())
    all_tx = sum(v[1] for v in tot.values())
    return {**scope, **_win_out(w), "has_bandwidth": True, "devices_with_data": len(tot),
            "total_download": human_bytes(all_rx), "total_upload": human_bytes(all_tx),
            "devices": rows}


ALERT_KINDS = ("threat", "exposure", "upnp", "outage", "visibility", "night", "bedtime",
               "spike", "new", "change")
SEV_NAME = {0: "critical", 1: "high", 2: "medium", 3: "low"}
# the dashboard's tag words for each kind (the chip "Alerts · Open port")
KIND_TAG = {"threat": "app.ai.kind_threat", "exposure": "ui.tag_exposure", "upnp": "app.tag_upnp",
            "outage": "app.tag_outage", "visibility": "ui.tag_visibility", "night": "ui.tag_night",
            "bedtime": "app.tag_bedtime", "spike": "ui.tag_spike", "new": "ui.tag_new",
            "change": "ui.tag_changed"}


def t_alerts(ctx: Ctx, a: dict) -> dict:
    from netwarden import explain, inbox
    w = window_bounds(ctx, a["window"])
    hours = max(1.0, (ctx.now - w["start"]).total_seconds() / 3600)
    mac = resolve_device(ctx, a["device"]) if a.get("device") else None
    items = inbox.alert_items(ctx.db, ctx.lang, hours)
    rows = []
    for it in items:
        if a.get("type") and it["kind"] != a["type"] or mac and it["mac"] != mac:
            continue
        row = {"type": it["kind"], "severity": SEV_NAME.get(it["sev"], "low"),
               "device": it.get("name"), "mac": it["mac"] if it["mac"] != "network" else None,
               "title": it["title"], "text": it["text"]}
        if it.get("why"):
            row["why"] = explain.text(it["why"])
        if it.get("when"):
            row["when_local"] = ctx.local(it["when"])
        rows.append({k: v for k, v in row.items() if v is not None})
    return {**_win_out(w), "count": len(rows), "alerts": rows[:a["limit"]],
            "note": "Muted / acknowledged alerts are left out (the user's own choice)."}


def t_screen_time(ctx: Ctx, a: dict) -> dict:
    from netwarden import screentime
    days = 1 if a["period"] == "day" else 7
    mac = resolve_device(ctx, a["device"]) if a.get("device") else None
    person = resolve_person(ctx, a["person"]) if a.get("person") else None
    rep = screentime.report(ctx.db, ctx.lang, days=days, tz=ctx.tz)
    top = lambda svcs: [{"service": s["name"], "minutes": s["minutes"]} for s in svcs[:5]]  # noqa: E731
    people = [{"person": m["owner"], "minutes": m["minutes"], "today_minutes": m["today_minutes"],
               "top_services": top(m.get("top_services") or [])}
              for m in rep["members"] if not person or m["owner"] == person]
    devices = [{"name": d["name"], "mac": d["mac"], "owner": d.get("owner"), "minutes": d["minutes"],
                "today_minutes": d["today_minutes"], "top_services": top(d.get("top_services") or [])}
               for d in rep["devices"]
               if (not mac or d["mac"] == mac) and (not person or d.get("owner") == person)]
    return {"period": "today" if days == 1 else "last 7 days (local days)",
            "total_minutes": rep["today_minutes"] if days == 1 else rep["minutes"],
            "people": people, "devices": devices,
            "note": "ESTIMATES from DNS activity, for family conversations - not exact."}


def t_bedtime_status(ctx: Ctx, a: dict) -> dict:
    from netwarden import bedtime
    person = resolve_person(ctx, a["person"]) if a.get("person") else None
    rep = bedtime.report(ctx.db, ctx.lang, tz=ctx.tz)
    rules = []
    for r in rep["rules"]:
        if person and r.get("owner") != person:
            continue
        rules.append({"name": r.get("name") or None, "for": r.get("target_name"),
                      "days": r.get("days_text"), "window_local": f"{r['start']}-{r['end']}",
                      "min_minutes": r["min_minutes"], "enabled": r["enabled"],
                      "devices": [d["name"] for d in r.get("devices") or []][:10],
                      "nights_over_7d": [{"night": h.get("night_label") or h["night"],
                                          "device": h["name"], "minutes": h["minutes"],
                                          "mostly": h.get("service")} for h in r.get("hits") or []]})
    return {"rules": rules, "night_local": "-".join(night_window(ctx.db, ctx.tz, ctx.now, person)[2]),
            "note": "Notify only: netwarden never blocks anything. Minutes are estimates."}


def t_presence(ctx: Ctx, a: dict) -> dict:
    from netwarden import presence
    person = resolve_person(ctx, a["person"]) if a.get("person") else None
    rep = presence.report(ctx.db, ctx.lang, tz=ctx.tz)
    rows, off = [], 0
    for p in rep["people"]:
        if person and p["name"] != person:
            continue
        if not p["presence"]:
            off += 1
            continue
        rows.append({"person": p["name"], "state": p["state"], "why": p.get("reason"),
                     "last_seen_local": ctx.local(p.get("last_seen")),
                     "recent": [f"{'arrived' if e['kind'] == 'arrive' else 'left'} {ctx.local(e['ts'])}"
                                for e in (p.get("events") or [])[:6]]})
    out = {"people": rows, "people_without_presence": off,
           "note": "Only people who turned presence on are listed; never guess where others are. "
                   "probably_home = seen within the grace period; unknown = no fresh data."}
    if person and off:
        out["note"] = f"{person} did not turn presence on: their whereabouts are unknown."
    return out


def t_network_health(ctx: Ctx, a: dict) -> dict:
    from netwarden import nethealth
    w = window_bounds(ctx, a["window"])
    hours = max(1.0, (ctx.now - w["start"]).total_seconds() / 3600)
    rep = nethealth.report(ctx.db, ctx.lang, hours=min(hours, 24 * 7), tz=ctx.tz)
    # the verdict and its sentence are the Network health page's own (now / the last 24 h,
    # the period named in the text); the numbers below cover the asked window
    page = nethealth.report(ctx.db, ctx.lang, tz=ctx.tz) if rep["hours"] != 24 else rep
    gw, dns = rep["gateway"], rep["dns"]
    outs = [o for o in nethealth.outage_list(ctx.db, days=31)
            if o["end_ts"] >= _iso(w["start"]) and o["start_ts"] <= _iso(w["end"])]
    return {**_win_out(w), "verdict": page["verdict"]["key"], "summary": page["verdict"]["title"],
            "detail": page["verdict"]["text"], "verdict_covers": "now; detail: the last 24 h",
            "router": {"measured": gw["measured"], "avg_ms": gw.get("avg_ms"), "loss": gw.get("loss")},
            "dns": {"measured": dns["measured"], "fail_rate": dns.get("fail_rate"),
                    "avg_ms": dns.get("avg_ms")},
            "internet_probe": rep["internet"]["measured"],
            "outages": [{"start_local": ctx.local(o["start_ts"]), "end_local": ctx.local(o["end_ts"]),
                         "minutes": o["minutes"], "probable_cause": o["cause"],
                         "ongoing": bool(o["ongoing"])} for o in outs]}


def t_upnp_mappings(ctx: Ctx, a: dict) -> dict:
    from netwarden import upnp
    rep = upnp.report(ctx.db, ctx.lang)
    if not rep.get("checked"):
        return {"checked": False, "note": "The router's UPnP table was never checked."}
    rows = []
    for m in rep["mappings"]:
        if a["risky_only"] and not m.get("risky"):
            continue
        rows.append({"protocol": m["protocol"], "external_port": m["external_port"],
                     "internal_port": m["internal_port"],
                     "device": m.get("name") if m.get("mac") else None, "mac": m.get("mac"),
                     "description": m.get("description"), "service": m.get("service"),
                     "risky": bool(m.get("risky")), "new": bool(m.get("new")),
                     "muted": bool(m.get("muted")), "first_seen_local": ctx.local(m.get("first_seen"))})
    return {"checked": True, "router_answers_upnp": bool(rep.get("available")),
            "checked_local": ctx.local(rep.get("checked_ts")),
            "mappings": [{k: v for k, v in r.items() if v is not None} for r in rows],
            "note": "Descriptions are text the devices chose (untrusted). netwarden never "
                    "changes the router."}


def t_hygiene(ctx: Ctx, a: dict) -> dict:
    from netwarden import hygiene
    rep = hygiene.report(ctx.db, ctx.lang)
    return {"status": rep["status"], "summary": rep["summary"], "counts": rep["counts"],
            "checks": [{"key": c["key"], "status": c["status"], "title": c["title"],
                        "text": c["text"], "steps": c.get("steps")[:3]} for c in rep["checks"]]}


SUG_STATUSES = ("open", "done", "dismissed", "snoozed", "all")


def t_suggestions(ctx: Ctx, a: dict) -> dict:
    from netwarden import suggestions
    rep = suggestions.report(ctx.db, ctx.lang)
    keys = ("open", "done", "dismissed", "snoozed") if a["status"] == "all" else (a["status"],)
    rows = [{"title": s["title"], "why": s["why"], "status": s["status"],
             "severity": s["severity"], "area": s.get("pillar"), "score_points": s.get("points")}
            for k in keys for s in rep.get(k) or []]
    return {"counts": rep["counts"], "suggestions": rows[:a["limit"]],
            "note": "Suggestions only: the user applies them by hand; never auto-applied."}


def t_search(ctx: Ctx, a: dict) -> dict:
    from netwarden import search
    days = {"24h": 1, "7d": 7, "30d": 30}[a["window"]]
    r = search.search(ctx.db, a["query"], ctx.lang, days=days)
    return {"query": a["query"], "days": days,
            "devices": [{"name": d.get("name"), "mac": d.get("mac")} for d in r.get("devices") or []],
            "services": [{k: s.get(k) for k in ("name", "category", "queries", "devices")}
                         for s in r.get("services") or []],
            "domains": [{k: d.get(k) for k in ("domain", "queries", "blocked", "devices", "service")}
                        for d in r.get("domains") or []]}


# --- the registry ----------------------------------------------------------------

TOOLS: dict = {}


def _register(t: Tool) -> None:
    TOOLS[t.name] = t


_register(Tool("list_devices", "List the household's devices (name, type, owner, room, online "
               "now, first seen, DNS lookups in 24 h). Filter by person, device category, "
               "online status, or only devices first seen within a window ('anything new?').",
               t_list_devices,
               {"person": P_PERSON,
                "category": Param("string", "Device type.", enum=devicetype.TYPES),
                "status": Param("string", "online / offline / any.", enum=STATUSES, default="any"),
                "new_since": Param("string", "Only devices first seen within this window.",
                                   enum=WINDOWS),
                "limit": P_limit(30)}))
_register(Tool("device_detail", "Everything known about one device: type, owner, room, model, "
               "first/last seen, services and top domains (24 h), privacy grade, open ports, "
               "UPnP forwards, usual hours, data volume.", t_device_detail,
               {"device": P_DEVICE}, required=("device",)))
_register(Tool("top_domains", "The domains looked up (DNS) in a window - for one device, one "
               "person's devices or the whole home - with counts, service, first/last time "
               "(local). Use after/before (local HH:MM) for 'after 23:00'.", t_top_domains,
               {"device": P_DEVICE, "person": P_PERSON, "window": P_window(),
                "after": Param("string", "Local start time HH:MM inside the window.", max_len=5,
                               pattern=P_TIME),
                "before": Param("string", "Local end time HH:MM.", max_len=5, pattern=P_TIME),
                "limit": P_limit(15)}))
_register(Tool("traffic", "Data volume (bytes downloaded / uploaded, from the optional traffic "
               "sensor) per device in a window, most first - 'who used the most data last "
               "night?'. For one device, one person or the whole home.", t_traffic,
               {"device": P_DEVICE, "person": P_PERSON, "window": P_window(),
                "limit": P_limit(10)}))
_register(Tool("alerts", "Current alerts (threats, open ports, UPnP, outages, DNS blind spots, "
               "night activity, bedtime, data spikes, new devices, behaviour changes) with the "
               "deterministic 'why' explanation of each. Filter by window, type and device.",
               t_alerts,
               {"window": P_window(), "type": Param("string", "Alert type.", enum=ALERT_KINDS),
                "device": P_DEVICE, "limit": P_limit(20)}))
_register(Tool("screen_time", "ESTIMATED screen time (minutes, from DNS activity) per person and "
               "device, today or over the last 7 days, with the top services.", t_screen_time,
               {"person": P_PERSON, "device": P_DEVICE,
                "period": Param("string", "day = today, week = the last 7 days.",
                                enum=("day", "week"), default="week")}))
_register(Tool("bedtime_status", "The household's bedtime rules (notify only) and the nights of "
               "the last week a device was used past bedtime.", t_bedtime_status,
               {"person": P_PERSON}))
_register(Tool("presence", "Who is home now - ONLY people who turned presence on (home, "
               "probably_home, away, unknown), with recent arrivals / departures.", t_presence,
               {"person": P_PERSON}))
_register(Tool("network_health", "Router latency / loss, DNS failures and outages (with the "
               "probable cause: router, isp, dns) in a window.", t_network_health,
               {"window": P_window(choices=WINDOWS)}))
_register(Tool("upnp_mappings", "Port forwards devices opened on the router via UPnP (risky = "
               "exposes a risky service to the internet).", t_upnp_mappings,
               {"risky_only": Param("boolean", "Only risky forwards.", default=False)}))
_register(Tool("hygiene", "The router hygiene check (UPnP, risky forwards, DNS filter coverage, "
               "...) with status and steps.", t_hygiene))
_register(Tool("suggestions", "netwarden's suggestions (things the user could do by hand), "
               "by status.", t_suggestions,
               {"status": Param("string", "Which suggestions.", enum=SUG_STATUSES, default="open"),
                "limit": P_limit(10, 20)}))
_register(Tool("search", "Search devices, services and domains by text (e.g. 'tiktok').", t_search,
               {"query": Param("string", "What to search for.", max_len=64),
                "window": P_window("7d", ("24h", "7d", "30d"))}, required=("query",)))


def schemas() -> list:
    """[{name, description, parameters}] for the providers (brain converts the shape)."""
    return [{"name": t.name, "description": t.description, "parameters": t.schema()}
            for t in TOOLS.values()]


# --- running a tool --------------------------------------------------------------

def _clip(obj):
    """Every string at most MAX_STR characters (hostile announced names / descriptions)."""
    if isinstance(obj, str):
        return obj if len(obj) <= MAX_STR else obj[:MAX_STR - 1] + "…"
    if isinstance(obj, dict):
        return {k: _clip(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clip(v) for v in obj]
    return obj


def _size(obj) -> int:
    return len(dumps(obj).encode("utf-8"))


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def cap(result: dict, max_bytes: int = MAX_RESULT_BYTES) -> dict:
    """At most MAX_ROWS per list, at most `max_bytes` serialized: rows are dropped from
    the end of the longest list until it fits; "truncated": true says so."""
    out = _clip(result)
    truncated = bool(out.get("truncated"))
    for k, v in list(out.items()):
        if isinstance(v, list) and len(v) > MAX_ROWS:
            out[k] = v[:MAX_ROWS]
            truncated = True
    out["truncated"] = truncated
    while _size(out) > max_bytes:
        lists = [k for k, v in out.items() if isinstance(v, list) and v]
        if not lists:
            return {"error": "too_big", "message": "the result is too big", "truncated": True}
        longest = max(lists, key=lambda k: _size(out[k]))
        out[longest] = out[longest][:-1]
        out["truncated"] = True
    return out


def run(db, name: str, raw_args, lang: str = "en", now: datetime | None = None) -> dict:
    """Validate and run one tool: its capped result, or {"error", "message"}. Never raises
    for the model's mistakes; an unexpected failure is logged and reported as "failed"."""
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": "unknown_tool", "message": f"no tool named {str(name)[:40]!r}",
                "detail": {"tools": list(TOOLS)}}
    try:
        args = tool.validate(raw_args)
        return cap(tool.handler(Ctx(db, lang, now), args))
    except ToolError as e:
        r = e.result()      # (candidate lists come from user text: the same 8 KB cap)
        return r if _size(r) <= MAX_RESULT_BYTES else cap(r)
    except Exception as e:   # noqa: BLE001 - a lookup bug must not end the answer
        log.warning("tool %s failed: %s: %s", name, type(e).__name__, str(e)[:200])
        return {"error": "failed", "message": "the lookup failed"}


# --- what the AI panel shows --------------------------------------------------------

def label(name: str, lang: str) -> str:
    return i18n.t("aitool." + name, lang) if name in TOOLS else name


def detail(db, name: str, args: dict, lang: str) -> list:
    """The localized parts after the label: the device / person (REAL names, local
    only) and the window ("Living-room TV", "last night", "after 23:00")."""
    if not isinstance(args, dict):
        return []
    parts = []
    ctx = Ctx(db, lang)
    if args.get("device"):
        try:
            parts.append(ctx.name(resolve_device(ctx, str(args["device"]))))
        except ToolError:
            parts.append(str(args["device"])[:40])
    for k in ("person", "query"):
        if args.get(k):
            parts.append(str(args[k])[:40])
    if args.get("category") in devicetype.TYPES:
        parts.append(devicetype.type_name(args["category"], lang))
    if args.get("type") in ALERT_KINDS:
        parts.append(i18n.t(KIND_TAG[args["type"]], lang))
    if args.get("status") == "online":
        parts.append(i18n.t("app.online", lang))
    w = args.get("window") or args.get("new_since")
    if name == "screen_time":
        parts.append(i18n.t("aitool.period." + (args.get("period") if args.get("period") in
                                                ("day", "week") else "week"), lang))
    elif w in WINDOWS:
        parts.append(i18n.t("aitool.win." + w, lang))
    elif name in ("top_domains", "traffic", "alerts", "network_health"):
        parts.append(i18n.t("aitool.win.24h", lang))
    if isinstance(args.get("after"), str) and HHMM_RE.match(args["after"]):
        parts.append(i18n.t("aitool.after", lang, time=args["after"]))
    return parts


class Session:
    """The tool calls of ONE question: the budget (MAX_CALLS calls, MAX_TOTAL_BYTES of
    results) and, with redaction on, the conversation's Redactor - arguments are
    un-mapped before they run, results are pseudonymized before they are sent."""

    def __init__(self, db, redactor=None, lang: str = "en", now: datetime | None = None,
                 max_calls: int = MAX_CALLS, max_bytes: int = MAX_TOTAL_BYTES):
        self.db, self.r, self.lang, self.now = db, redactor, i18n.normalize(lang), now
        self.max_calls, self.max_bytes = max_calls, max_bytes
        self.calls = 0
        self.bytes = 0
        self.limited = False

    @property
    def exhausted(self) -> bool:
        return self.calls >= self.max_calls or self.bytes >= self.max_bytes

    def unmap(self, args):
        """Real values for the pseudonyms in the model's arguments. A device token [D3]
        becomes that device's MAC (its display name may not be unique); [M3] / [IP3] /
        [P1] / [R2] become the real text."""
        if self.r is None or not isinstance(args, dict):
            return args
        out = {}
        for k, v in args.items():
            if isinstance(v, str):
                m = re.fullmatch(r"\s*\[D(\d{1,5})\]\s*", v)
                mac = self.r.real.get(f"[M{m.group(1)}]") if m else None
                v = mac if mac else self.r.unredact(v)
            out[k] = v
        return out

    def _redact(self, obj):
        """The result with every household identifier pseudonymized: a device's name
        field becomes its [D] token (via its "mac"), name-only fields by whole value,
        the rest of the text by the free-text redactor."""
        r = self.r
        if isinstance(obj, list):
            return [self._redact(v) for v in obj]
        if isinstance(obj, str):
            whole = r.field(obj)
            return whole if whole != obj else r.redact(obj)
        if not isinstance(obj, dict):
            return obj
        tok = r.device_token(obj.get("mac")) if isinstance(obj.get("mac"), str) else None
        out = {}
        for k, v in obj.items():
            if tok and k in ("name", "device") and isinstance(v, str):
                out[k] = r._use(tok)
            else:
                out[k] = self._redact(v)
        return out

    def call(self, name: str, raw_args, ok: bool = True) -> tuple:
        """(content sent to the model, the panel's event {name, label, detail, sent,
        error?, truncated}). Over budget: a short "answer with what you have" result;
        ok=False (the arguments were not a JSON object): an error result to fix them."""
        real_args = self.unmap(raw_args)
        limit = {"error": "limit_reached",
                 "message": "Lookup limit reached for this question - answer now with "
                            "what you already have."}
        if not ok:
            result = {"error": "bad_arguments", "message": "the arguments were not a JSON object"}
        elif self.exhausted:
            self.limited = True
            result = limit
        else:
            self.calls += 1
            result = run(self.db, name, real_args, "en", self.now)
            if self.r is not None:      # sized AFTER redaction: that is what is sent
                result = self._redact(result)
            room = self.max_bytes - self.bytes
            if _size(result) > room:
                self.limited = True
                result = cap(result, room) if room >= MIN_ROOM else limit
        content = dumps(result)
        self.bytes += len(content.encode("utf-8"))
        ev = {"name": name, "label": label(name, self.lang),
              "detail": detail(self.db, name, real_args, self.lang),
              "sent": content, "truncated": bool(result.get("truncated")),
              "redacted": self.r is not None}
        if result.get("error"):
            ev["error"] = result["error"]
        return content, ev

    def status(self, name: str, raw_args) -> dict:
        """The live "Looking up ..." line while a tool runs."""
        return {"name": name, "label": label(name, self.lang),
                "detail": detail(self.db, name, self.unmap(raw_args), self.lang)}


def example(db, redactor=None) -> dict:
    """A sample tool result for the send-preview (no model is called): list_devices with
    three rows, exactly as it would be sent (redacted when redaction is on)."""
    s = Session(db, redactor)
    content, _ev = s.call("list_devices", {"limit": 3})
    return {"name": "list_devices", "args": {"limit": 3}, "sent": content}


def memo_run(db, name: str, args: dict, lang: str):
    """run() shared through netwarden.cache (the suggested questions ask often)."""
    return cache.memo(db, "ai_tools.run", (name, json.dumps(args, sort_keys=True), lang),
                      lambda: run(db, name, args, lang))
