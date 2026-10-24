"""
netwarden - inbox.py: one "To do" queue for everything that wants the user's eyes.

Every module already reports its own findings (alerts.py: new / changed devices,
threats, open ports, router ports (UPnP), DNS blind spots, unusual hours, bedtime,
bandwidth spikes, outages; suggestions.py: open suggestions). The inbox lists them in
ONE place, worst first, each with the actions that make sense for it:

    ack      "Got it"   - this one finding is seen; it leaves the list (its own ack key)
    mute     "Mute"     - no more alerts of THIS KIND for this device (mute:<kind>)
    trust    "Trust"    - the whole device is known and fine (ack key "")
    snooze   "Snooze"   - hide it for N days (an ack that runs out; alerts.snooze_days)
    dismiss  "Dismiss"  - a suggestion that does not apply
    done     "Done"     - a suggestion the user carried out

Everything is the user's OWN note in netwarden's SQLite (acks, suggestion_state):
nothing on the network changes. undo() reverses any of them (the page's Undo toast).

    report(db, lang, env, hours) -> GET /api/inbox: {items, counts, snooze_days}
    act(db, action, refs, ...)   -> POST /api/inbox/act (validated; all or nothing)
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from netwarden import alerts, i18n, naming, nethealth, settings, store, suggestions

ACTIONS = ("ack", "mute", "trust", "snooze", "dismiss", "done")
DEVICE_ALERT = ("ack", "mute", "snooze", "trust")
ACTIONS_FOR = {
    "threat": DEVICE_ALERT, "exposure": DEVICE_ALERT, "upnp": DEVICE_ALERT,
    "visibility": DEVICE_ALERT, "night": DEVICE_ALERT, "spike": DEVICE_ALERT,
    "change": DEVICE_ALERT, "bedtime": ("ack", "mute", "snooze"),
    "new": ("ack", "trust", "snooze"), "outage": ("ack",),
    "suggestion": ("done", "snooze", "dismiss"),
}
KINDS = tuple(ACTIONS_FOR)
SUG_SEV = {"high": 1, "medium": 2, "low": 3}
MAX_REFS = 200            # one bulk action at most (the page selects what it shows)
MAX_KEY = 300             # like web.MAX_KEY
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class BadRef(ValueError):
    """An action or item reference the inbox will not act on -> 400 err.<code>."""
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --- the queue ------------------------------------------------------------------

def _item(kind, sev, title, text, mac=None, key=None, href=None, sid=None, when=None,
          name=None, actions=None) -> dict:
    ident = "|".join(str(x) for x in (kind, sid or mac or "", key or ""))
    return {"id": ident, "kind": kind, "sev": sev, "mac": mac, "key": key, "sid": sid,
            "name": name, "title": title, "text": text, "when": when, "fix": None,
            "why": None, "critical": False,
            "href": href or ("#/device/" + mac if mac and mac != nethealth.NETWORK_KEY
                             else "#/security"),
            "actions": list(ACTIONS_FOR[kind] if actions is None else actions)}


def alert_items(db, lang: str, hours: float = 24) -> list:
    """Every current alert as an inbox item in `lang` (no suggestions), with Stage Q's
    extras: "why" (explain.py), "critical" (may bypass quiet hours, notify.critical),
    "nkey" (the notification instance key: a night or a spike on another day, a mapping
    seen anew, is news again) and "detail" (canonical words for the quiet summary)."""
    lang = i18n.normalize(lang)
    names = naming.display_names(db, lang)
    a = alerts.localize(alerts.compute(db, recent_hours=hours), lang, names)
    t = lambda key, **kw: i18n.t(key, lang, **kw)  # noqa: E731
    since = _iso(datetime.now(timezone.utc) - timedelta(hours=hours))
    fresh = {r["mac"] for r in db.execute("SELECT mac FROM devices WHERE first_seen >= ?", (since,))}
    out = []

    def add(it, src, critical=False, inst="", detail=None):
        it.update(why=src.get("explain"), critical=bool(critical), detail=detail,
                  nkey=it["id"] + (f"|{inst}" if inst else ""))
        out.append(it)

    for th in a["threats"]:
        add(_item("threat", 0 if th["severity"] == "malicious" else 1,
                  f"{th['device']} → {th['domain']}", f"{th['label']} · {th['why']}",
                  th["mac"], th["domain"], name=th["device"]), th, True, detail=th["domain"])
    for x in a.get("exposure", []):
        add(_item("exposure", 1 if x["risk"] == "high" else 2,
                  f"{x['name']} · {x['port']} {x['service']}",
                  f"{x['risk_name']} — {x['note']}", x["mac"], x["ack"], name=x["name"]),
            x, x["risk"] == "high" and x.get("new"), detail=f"{x['port']} {x['service']}")
    for m in a.get("upnp", []):
        name = m["name"] if m.get("mac") else m["internal_client"]
        add(_item("upnp", 1 if m["risky"] else 2,
                  f"{name} · {m['protocol']} {m['external_port']}", m["text"],
                  m.get("mac"), m["ack"], name=name, href="#/security",
                  actions=None if m.get("mac") else ()),
            m, m["risky"] and m["new"], m.get("first_seen", ""),
            detail=f"{m['protocol']} {m['external_port']}")
    for o in a.get("outage", []):
        add(_item("outage", 0 if o["ongoing"] else 2, o["cause_name"], o["text"],
                  nethealth.NETWORK_KEY, o["ack"], href="#/health", when=o.get("start_ts")),
            o, detail=o["cause"])
    for v in a.get("visibility", []):
        add(_item("visibility", 2, v["name"], v["text"], v["mac"], v["ack"], name=v["name"]),
            v, v["kind"] == "bypass" and v["mac"] in fresh)
    for n in a.get("unusual_hours", []):
        add(_item("night", 2, n["name"], n["text"], n["mac"], n["ack"], name=n["name"]),
            n, inst=(n.get("first_ts") or "")[:10])
    for b in a.get("bedtime", []):
        add(_item("bedtime", 2, b["name"], b["text"], b["mac"], b["ack"], name=b["name"]), b)
    for s in a.get("bandwidth_spikes", []):
        add(_item("spike", 2, s["name"], s["text"], s["mac"], s["ack"], name=s["name"]),
            s, inst=a["generated"][:10])
    for d in a["new_devices"]:
        if d.get("is_self"):
            continue          # the computer running netwarden is not news
        info = [x for x in (d.get("vendor"), d.get("ip")) if x]
        add(_item("new", 3, d["name"], i18n.t("digest.sep", lang).join(info)
                  or t("app.inbox.new_text"), d["mac"], alerts.NEW_KEY,
                  when=d["first_seen"], name=d["name"]), d)
    for c in a["behavior_changes"]:
        add(_item("change", 3, c["name"],
                  t("ui.started_using") + " " + t("list_sep").join(c["new_services"]),
                  c["mac"], alerts.change_key(c), name=c["name"]),
            c, detail=list(c.get("new_service_ids") or []))
    return out


def collect(db, lang: str, env: dict | None = None, hours: float = 24) -> list:
    """Every open to-do item in `lang`, worst first (then newest)."""
    lang = i18n.normalize(lang)
    out = alert_items(db, lang, hours)
    for s in suggestions.report(db, lang, env=env)["open"]:
        # the fix for an alert that is in the list already: one item ("How to fix" on the
        # alert), not the same problem twice
        same = [it for it in out if _fixes(s["id"], it)]
        for it in same:
            it["fix"] = {"sid": s["id"], "title": s["title"]}
        if not same:
            out.append(_item("suggestion", SUG_SEV.get(s["severity"], 3), s["title"], s["why"],
                             sid=s["id"], href="#/suggestions"))
    out.sort(key=lambda i: (i["sev"], KINDS.index(i["kind"])))
    return out


def _fixes(sid: str, it: dict) -> bool:
    """Is suggestion `sid` the fix for alert item `it`?"""
    kind, _, rest = sid.partition(":")
    if kind == "port":                                   # port:<mac>:<port>
        mac, _, port = rest.rpartition(":")
        return it["kind"] == "exposure" and it["mac"] == mac and it["key"] == "port:" + port
    if kind == "upnp":                                   # upnp:<proto>:<port> = its ack key
        return it["kind"] == "upnp" and it["key"] == sid
    if kind == "threat":                                 # threat:<mac>: every threat alert
        return it["kind"] == "threat" and it["mac"] == rest
    if kind == "doh":                                    # doh:<mac>: the DoH blind spot
        return it["kind"] == "visibility" and it["mac"] == rest and it["key"] == "visibility:bypass"
    if kind == "bedtime":                                # bedtime:<mac>: its night alert
        return it["kind"] == "night" and it["mac"] == rest
    return False


def snooze_days(db) -> int:
    return int(settings.get(db, {}, "alerts.snooze_days"))


def report(db, lang: str, env: dict | None = None, hours: float = 24) -> dict:
    """GET /api/inbox."""
    items = collect(db, lang, env, hours)
    by_kind: dict = {}
    for i in items:
        by_kind[i["kind"]] = by_kind.get(i["kind"], 0) + 1
    return {"items": items, "snooze_days": snooze_days(db),
            "counts": {"total": len(items), "urgent": sum(1 for i in items if i["sev"] <= 1),
                       "by_kind": by_kind}}


# --- acting on it ---------------------------------------------------------------

def _ref(db, raw) -> dict:
    """One item reference from the page, checked: {kind, mac, key} for an alert (the mac
    a known device or a well-formed MAC; outages: the pseudo device "network" with an
    outage key only), {kind: "suggestion", sid} for a suggestion."""
    if not isinstance(raw, dict):
        raise BadRef("bad_json")
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in ACTIONS_FOR:
        raise BadRef("bad_inbox_item")
    if kind == "suggestion":
        sid = raw.get("sid")
        if not suggestions.valid_id(sid):
            raise BadRef("bad_inbox_item")
        prev = raw.get("prev")
        if prev is not None and (not isinstance(prev, str) or prev not in suggestions.STATUSES):
            raise BadRef("bad_status")
        return {"kind": kind, "sid": sid, "prev": prev}
    mac, key = raw.get("mac"), raw.get("key")
    if not isinstance(mac, str) or not isinstance(key, str) or len(key) > MAX_KEY:
        raise BadRef("bad_inbox_item")
    mac, key = mac.strip(), key.strip()
    if kind == "outage":
        if mac != nethealth.NETWORK_KEY or not re.fullmatch(
                re.escape(nethealth.ACK_PREFIX) + r"\d{1,12}", key):
            raise BadRef("bad_mac")
        return {"kind": kind, "mac": mac, "key": key}
    known = db.execute("SELECT mac FROM devices WHERE mac IN (?, ?)", (mac, mac.lower())).fetchone()
    if known:
        mac = known["mac"]
    elif MAC_RE.match(mac.lower()):
        mac = mac.lower()
    else:
        raise BadRef("bad_mac")
    if not key:
        raise BadRef("bad_inbox_item")   # "" would trust the device: that is action "trust"
    return {"kind": kind, "mac": mac, "key": key}


SNOOZE_HOURS = (1, 90 * 24)   # Stage Q: "1 hour" ... like the days, at most 90 days


def act(db, action: str, raw_refs, days=None, env: dict | None = None,
        undo: str | None = None, hours=None) -> int:
    """Apply `action` to every referenced item (all refs are validated first; nothing is
    written if one is bad). action "undo" reverses `undo` (the action being undone).
    A snooze lasts `days` (default alerts.snooze_days) or, Stage Q, `hours` (1 h ... 90 d).
    Returns how many items it touched."""
    if action != "undo" and action not in ACTIONS:
        raise BadRef("bad_action")
    if action == "undo" and undo not in ACTIONS:
        raise BadRef("bad_action")
    if not isinstance(raw_refs, list) or not raw_refs or len(raw_refs) > MAX_REFS:
        raise BadRef("bad_json")
    refs = [_ref(db, r) for r in raw_refs]
    what = undo if action == "undo" else action
    for r in refs:
        if what not in ACTIONS_FOR[r["kind"]]:
            raise BadRef("bad_action")
    if hours is not None:
        if isinstance(hours, bool) or not isinstance(hours, int) or \
                not SNOOZE_HOURS[0] <= hours <= SNOOZE_HOURS[1] or days is not None:
            raise BadRef("bad_snooze")
        span = timedelta(hours=hours)
        days = max(1, -(-hours // 24))    # a suggestion snoozes in whole days
    else:
        if days is None:
            days = snooze_days(db)
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
            raise BadRef("bad_snooze")
        span = timedelta(days=days)
    until = _iso(datetime.now(timezone.utc) + span)
    # every suggestion is checked BEFORE anything is written: one unknown id leaves the
    # whole batch untouched (alert refs were fully checked by _ref already)
    checked = {}
    for i, r in enumerate(refs):
        if r["kind"] != "suggestion":
            continue
        status = (r.get("prev") or "open") if action == "undo" else \
            {"done": "done", "dismiss": "dismissed", "snooze": "snoozed"}[what]
        try:
            checked[i] = suggestions.check_status(db, r["sid"], status, days, env=env)
        except LookupError:
            raise BadRef("suggestion_not_found") from None
        except ValueError:
            raise BadRef("bad_status") from None
    for i, r in enumerate(refs):
        if r["kind"] == "suggestion":
            suggestions.write_status(db, checked[i])
            continue
        key = {"trust": "", "mute": alerts.MUTE_PREFIX + r["kind"]}.get(what, r["key"])
        if action == "undo":
            store.remove_ack(db, r["mac"], key)
        else:
            store.add_ack(db, r["mac"], key, until if what == "snooze" else None)
    return len(refs)
