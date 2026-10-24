"""
netwarden - presence.py: "who's home" (Stage P). Opt-in per person, OFF by default.

A person is home when one of their PRESENCE DEVICES (default: the phones assigned to
them; the People page can pick others) was seen on the LAN recently. Only signals
netwarden already has are used:
  - the device's DNS lookups (dns_events, one sighting per minute);
  - the discovery sweep (devices.last_seen);
  - the light presence check (check_recorded): ONLY the presence devices of the people
    who turned presence on, at their last IP inside the local subnet, with discovery's
    own method (discovery.alive: one ping + the TCP knock - sends no data, never
    ARP-spoofs), at most every `presence.check_minutes` (>= 2, default 5). Never on the
    demo DB (its IPs may be real LAN devices).

States (decide()):
  home           seen within HOME_MINUTES
  probably_home  seen within the grace period (`presence.grace_minutes`, default 20):
                 an idle phone goes quiet for a while, it did not leave
  away           not seen for longer than that, while the data IS fresh
  unknown        no presence device, never seen, or no fresh data at all (the DNS
                 source and the checks both stopped) - we don't guess

The timeline (arrivals / departures, today and the last 7 days) is the sightings split
wherever the gap is longer than the grace period. "Forget presence history" sets
people.presence_since (nothing older is read again) and deletes that person's
presence_samples; turning presence on also starts from "now".

Everything here is canonical (keys, ISO times); report() localizes at the edge.
Notifications for arrivals / departures go through notify.route() only.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from netwarden import activity, cache, devicetype, i18n, notify, screentime, settings, store

log = logging.getLogger("netwarden")

HOME_MINUTES = 10       # seen this recently = home
STALE_MINUTES = 30      # no data at all for longer (or the grace period) = unknown
DAYS = 7                # the timeline: today and the 6 days before
PRESENCE_TYPES = ("phone",)   # the default presence devices: a person's phones
SOURCE = "presence"     # source_status name of the light check
CHECK_META = "presence_last_check"
LINK_DAYS = 14          # a look-alike device must have appeared this recently
LINK_ACK = "presence:link"    # ack (new mac, LINK_ACK) = "not theirs", the suggestion goes
LATE_FROM, LATE_UNTIL = 22, 5  # an arrival between 22:00 and 05:00 local is "late"
TARGET_HOURS = 24       # the check only pings an address the device held this recently
STATES = ("home", "probably_home", "away", "unknown")


# --- time helpers ----------------------------------------------------------------

def _epoch(ts: str) -> float:
    """dns_events / store.now() text (or its first 16 chars, a minute) -> epoch seconds."""
    ts = ts.rstrip("Z")
    if len(ts) == 16:
        ts += ":00"
    return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def grace_minutes(db, env: dict | None = None) -> int:
    return settings.get(db, env, "presence.grace_minutes")


def check_minutes(db, env: dict | None = None) -> int:
    return settings.get(db, env, "presence.check_minutes")


# --- which devices, which sightings --------------------------------------------------

def owned(db) -> dict:
    """person name -> [mac] of their devices still in the inventory."""
    inventory = {r["mac"] for r in db.execute("SELECT mac FROM devices")}
    out: dict = {}
    for mac, p in sorted(store.get_profiles(db).items()):
        if p.get("owner") and mac in inventory:
            out.setdefault(p["owner"], []).append(mac)
    return out


def device_sets(db, people: list | None = None) -> dict:
    """person id -> their presence devices: the chosen ones (still theirs), or else every
    device of theirs that is (or was set to be) a phone."""
    people = store.people(db) if people is None else people
    mine, types, out = owned(db), None, {}
    for p in people:
        theirs = mine.get(p["name"], [])
        if p["presence_macs"] is not None:
            out[p["id"]] = [m for m in theirs if m in p["presence_macs"]]
            continue
        if types is None:
            types = devicetype.classify_all(db)
        out[p["id"]] = [m for m in theirs if (types.get(m) or {}).get("type") in PRESENCE_TYPES]
    return out


def sightings(db, macs: list, since: str) -> list:
    """[(epoch, mac, source)] oldest first: DNS lookups (one per minute), the presence
    check's / sweep's samples, and the inventory's last_seen ('lan')."""
    if not macs:
        return []
    q = ",".join("?" * len(macs))
    out = [(_epoch(r[1]), r[0], "dns") for r in db.execute(
        f"""SELECT device_mac, substr(ts, 1, 16) AS m FROM dns_events
            WHERE device_mac IN ({q}) AND ts >= ? GROUP BY device_mac, m""", (*macs, since))]
    out += [(_epoch(r[1]), r[0], r[2]) for r in db.execute(
        f"SELECT mac, ts, source FROM presence_samples WHERE mac IN ({q}) AND ts >= ?",
        (*macs, since))]
    out += [(_epoch(r[1]), r[0], "lan") for r in db.execute(
        f"SELECT mac, last_seen FROM devices WHERE mac IN ({q}) AND last_seen >= ?",
        (*macs, since))]
    return sorted(out)


def data_fresh(db) -> float | None:
    """Epoch of the newest network data of ANY kind (a DNS lookup, a check, a source run
    that succeeded); None = nothing at all. If even this is old we cannot tell away from
    'netwarden stopped looking'."""
    times = []
    for sql in ("SELECT ts FROM dns_events ORDER BY rowid DESC LIMIT 1",
                "SELECT ts FROM presence_samples ORDER BY rowid DESC LIMIT 1",
                "SELECT MAX(last_ok_ts) FROM source_status"):
        r = db.execute(sql).fetchone()
        if r and r[0]:
            times.append(_epoch(r[0]))
    return max(times) if times else None


# --- the state machine -----------------------------------------------------------------

def decide(last: float | None, now: float, grace_min: int, fresh: float | None,
           has_devices: bool = True) -> tuple:
    """(state, reason key) from the newest sighting `last` (epoch) at `now`."""
    if not has_devices:
        return "unknown", "no_devices"
    if last is None:
        return "unknown", "never"
    age = now - last
    if age <= min(HOME_MINUTES, grace_min) * 60:
        return "home", "seen"
    if age <= grace_min * 60:
        return "probably_home", "grace"
    if fresh is None or now - fresh > max(STALE_MINUTES, grace_min) * 60:
        return "unknown", "no_data"
    return "away", "away"


def visits(epochs: list, gap: float) -> list:
    """Sorted sighting times -> [[first, last]] runs split where the gap exceeds `gap`."""
    out: list = []
    for t in epochs:
        if out and t - out[-1][1] <= gap:
            out[-1][1] = t
        else:
            out.append([t, t])
    return out


def _late(epoch: float, tz) -> bool:
    h = datetime.fromtimestamp(epoch, tz).hour
    return h >= LATE_FROM or h < LATE_UNTIL


def timeline(epochs: list, now: float, tz, grace_min: int, since: float,
             days: int = DAYS) -> dict:
    """Arrivals / departures and per-day "home" bars for the last `days` local days.
    An arrival right at the start of what we may read (`since`) is not an arrival (we
    just started looking); a visit that is still going has no departure."""
    gap = grace_min * 60
    vs = visits(epochs, gap)
    today = datetime.fromtimestamp(now, tz).date()
    first_day = today - timedelta(days=days - 1)
    start = screentime.local_midnight(first_day, tz).timestamp()
    events = []
    for s, e in vs:
        if s >= start and s - since > gap:
            events.append({"kind": "arrive", "ts": _iso(s), "late": _late(s, tz)})
        if e >= start and now - e > gap:
            events.append({"kind": "leave", "ts": _iso(e), "late": False})
    bars = []
    for i in range(days):
        d = first_day + timedelta(days=i)
        d0 = screentime.local_midnight(d, tz).timestamp()
        d1 = screentime.local_midnight(d + timedelta(days=1), tz).timestamp()
        segs, home = [], 0.0
        for s, e in vs:
            end = now if now - e <= gap else max(e, s + 300)   # a lone sighting: 5 min
            a, b = max(s, d0), min(end, d1, now)
            if b > a:
                segs.append([round((a - d0) / 60), round((b - d0) / 60)])
                home += b - a
        bars.append({"date": d.isoformat(), "minutes": round((d1 - d0) / 60),
                     "home_minutes": round(home / 60), "segments": segs})
    events.sort(key=lambda x: x["ts"], reverse=True)
    return {"events": events, "days": bars}


# --- the whole picture (canonical, cached) --------------------------------------------------

def _core(db, now: float, tz, grace_min: int) -> dict:
    people = store.people(db)
    sets = device_sets(db, [p for p in people if p["presence"]])
    fresh = data_fresh(db)
    floor = now - (DAYS + 1) * 86400
    out = []
    for p in people:
        row = {"id": p["id"], "presence": p["presence"]}
        if not p["presence"]:
            out.append(row)         # presence is off: nothing is read for them
            continue
        macs = sets.get(p["id"], [])
        since = max(floor, _epoch(p["presence_since"]) if p["presence_since"] else 0)
        sights = sightings(db, macs, _iso(since))
        last = sights[-1] if sights else None
        state, reason = decide(last[0] if last else None, now, grace_min, fresh, bool(macs))
        row.update(state=state, reason=reason, macs=macs,
                   last_seen=_iso(last[0]) if last else None,
                   last_mac=last[1] if last else None, last_source=last[2] if last else None,
                   fresh=_iso(fresh) if fresh else None,
                   **timeline(sorted({s[0] for s in sights}), now, tz, grace_min, since))
        out.append(row)
    return {"people": out, "grace": grace_min, "now": _iso(now)}


def core(db, tz=None, now: datetime | None = None, env: dict | None = None) -> dict:
    tz = tz or activity.local_tz()
    grace_min = grace_minutes(db, env)
    if now is None:
        return cache.memo(db, "presence.core", (activity.tz_label(tz), grace_min),
                          lambda: _core(db, datetime.now(timezone.utc).timestamp(), tz,
                                        grace_min))
    return _core(db, now.timestamp(), tz, grace_min)


def events(db, tz=None, now: datetime | None = None, env: dict | None = None) -> list:
    """Every arrival / departure of the timeline window, newest first:
    [{kind: presence.arrive|presence.leave, person_id, ts, late}]."""
    out = []
    c = core(db, tz, now, env)
    for row in c["people"]:
        for e in row.get("events", []):
            ev = {"kind": "presence." + e["kind"], "person_id": row["id"], "ts": e["ts"],
                  "late": e["late"]}
            if e["kind"] == "leave":    # known only a grace period after the last sighting
                ev["due"] = _iso(_epoch(e["ts"]) + c["grace"] * 60)
            out.append(ev)
    return sorted(out, key=lambda e: e["ts"], reverse=True)


def notifications(db, tz=None, now: datetime | None = None, env: dict | None = None) -> list:
    """The arrivals / departures notify.route() says to show now."""
    people = {p["id"]: p for p in store.people(db)}
    out = []
    for e in events(db, tz, now, env):
        routed = notify.route(db, e, now, people)
        if routed:
            out.append(routed)
    return out


# --- private addresses and look-alike devices ---------------------------------------------

def link_suggestions(db, now: datetime | None = None) -> list:
    """Newly appeared devices that look like one of a person's own - the same hostname, the
    same announced (mDNS / SSDP) name, or the same vendor while that old device went
    quiet. A phone with a private (randomized) address may get a NEW address, e.g. after
    "forget this network" or an OS update; it then looks like a stranger.
    [{mac, person_id, person, from_mac, reason: hostname|announced|vendor, value}]"""
    now = now or datetime.now(timezone.utc)
    recent = (now - timedelta(days=LINK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    profiles = store.get_profiles(db)
    acks = store.list_acks(db)
    announced = store.identity_names(db)
    devs = {r["mac"]: dict(r) for r in db.execute(
        "SELECT mac, vendor, hostname, randomized, is_self, first_seen, last_seen FROM devices")}
    ids = {p["name"]: p["id"] for p in store.people(db)}
    mine = {m: p["owner"] for m, p in profiles.items() if p.get("owner") in ids and m in devs}
    out = []
    for mac, d in sorted(devs.items()):
        prof = profiles.get(mac) or {}
        if d["is_self"] or d["first_seen"] < recent or prof.get("owner") or prof.get("shared") \
                or store.is_muted(acks, mac, LINK_ACK):
            continue
        best = None
        for old, who in sorted(mine.items()):
            o = devs[old]
            if o["first_seen"] >= d["first_seen"]:
                continue
            for rank, reason, a, b in (
                    (0, "hostname", d["hostname"], o["hostname"]),
                    (1, "announced", announced.get(mac), announced.get(old)),
                    (2, "vendor", d["vendor"], o["vendor"] if o["last_seen"] <= d["first_seen"]
                     else None)):
                if a and b and a.strip().casefold() == b.strip().casefold():
                    cand = (rank, who, old, reason, a)
                    if best is None or cand[0] < best[0]:
                        best = cand
                    elif cand[0] == best[0] and cand[1] != best[1]:
                        best = (rank, None, old, reason, a)   # two people: ambiguous
                    break
        if best and best[1]:
            out.append({"mac": mac, "person_id": ids[best[1]], "person": best[1],
                        "from_mac": best[2], "reason": best[3], "value": best[4]})
    return out


def link(db, mac: str, pid: int) -> dict:
    """Accept a link suggestion: the new address becomes the person's device, with the old
    device's type / room (and its label, if the new one has none), and it joins the
    person's chosen presence devices. Returns the before-state for unlink()."""
    p = store.person(db, pid)
    sug = next((s for s in link_suggestions(db) if s["mac"] == mac and s["person_id"] == pid), None)
    if p is None or sug is None:
        raise ValueError("no_suggestion")
    profiles, labels = store.get_profiles(db), store.get_labels(db)
    before = {"mac": mac, "person_id": pid, "profile": profiles.get(mac),
              "label": labels.get(mac), "presence_macs": p["presence_macs"]}
    old, cur = profiles.get(sug["from_mac"]) or {}, profiles.get(mac) or {}
    store.set_profile(db, mac, owner=p["name"], type=cur.get("type") or old.get("type") or "",
                      room=cur.get("room") or old.get("room") or "")
    if mac not in labels and sug["from_mac"] in labels:
        store.set_label(db, mac, labels[sug["from_mac"]]["label"])
    if p["presence_macs"] is not None and mac not in p["presence_macs"]:
        store.save_person(db, {**p, "presence_macs": p["presence_macs"] + [mac]})
    return before


def unlink(db, before: dict) -> None:
    """Undo link(): the device's profile / label and the person's presence devices as
    they were (validated by the caller: mac known, person id an int)."""
    mac, prof = before["mac"], before.get("profile") or {}
    store.set_profile(db, mac, owner=prof.get("owner") or "", type=prof.get("type") or "",
                      room=prof.get("room") or "", shared=bool(prof.get("shared")))
    lab = before.get("label")
    if lab:
        store.set_label(db, mac, lab["label"], lab.get("note") or "")
    else:
        store.clear_label(db, mac)
    p = store.person(db, before["person_id"])
    if p is not None:
        store.save_person(db, {**p, "presence_macs": before.get("presence_macs")})


# --- turning it on / off, forgetting ----------------------------------------------------

def set_presence(db, pid: int, enabled: bool | None = None, devices: list | None = None,
                 notify_arrive: bool | None = None, notify_leave: bool | None = None,
                 default_devices: bool = False) -> dict:
    """Change a person's presence settings. Turning it ON starts the history at that
    moment (nothing from before is shown). devices: MACs that must be the person's;
    default_devices=True goes back to "their phones"."""
    p = store.person(db, pid)
    if p is None:
        raise ValueError("no_person")
    new = dict(p)
    if enabled is not None:
        if enabled and not p["presence"]:
            new["presence_since"] = store.now()
        new["presence"] = bool(enabled)
    if devices is not None:
        theirs = set(owned(db).get(p["name"], []))
        if any(m not in theirs for m in devices):
            raise ValueError("not_their_device")
        new["presence_macs"] = sorted(set(devices))
    if default_devices:
        new["presence_macs"] = None
    if notify_arrive is not None:
        new["notify_arrive"] = bool(notify_arrive)
    if notify_leave is not None:
        new["notify_leave"] = bool(notify_leave)
    store.save_person(db, new)
    return store.person(db, pid)


def forget(db, pid: int) -> int:
    """"Forget presence history": nothing before now is read again for this person, and
    the check's samples of their devices are deleted. Returns # samples deleted."""
    p = store.person(db, pid)
    if p is None:
        raise ValueError("no_person")
    store.save_person(db, {**p, "presence_since": store.now()})
    macs = owned(db).get(p["name"], [])
    if not macs:
        return 0
    with db:
        cur = db.execute(f"DELETE FROM presence_samples WHERE mac IN ({','.join('?' * len(macs))})",
                         macs)
    return cur.rowcount


# --- the light presence check (runner loop) ------------------------------------------------

def check_targets(db, net=None, now: datetime | None = None) -> list:
    """[(mac, ip)] to check: the presence devices of people with presence ON, at their last
    IP, only if that IP is private and inside the local subnet `net`. An address is only
    trusted while it is fresh: not if the device was last seen more than TARGET_HOURS ago
    (DHCP may have handed it to someone else), nor if a device seen MORE recently holds the
    same IP (a phone's private MAC rotated and the old row's address now belongs to the new
    one) - a ping there would make the wrong device, and so the wrong person, look home."""
    people = [p for p in store.people(db) if p["presence"]]
    if not people:
        return []
    macs = sorted({m for ms in device_sets(db, people).values() for m in ms})
    if not macs:
        return []
    now = now or datetime.now(timezone.utc)
    oldest = _iso(now.timestamp() - TARGET_HOURS * 3600)
    rows = db.execute(f"SELECT mac, ip, last_seen FROM devices WHERE mac IN "
                      f"({','.join('?' * len(macs))})", macs).fetchall()
    newest = {r[0]: r[1] for r in db.execute(
        "SELECT ip, MAX(last_seen) FROM devices WHERE ip IS NOT NULL AND ip != '' GROUP BY ip")}
    out = []
    for r in rows:
        try:
            ip = ipaddress.ip_address(r["ip"] or "")
        except ValueError:
            continue
        if not r["last_seen"] or r["last_seen"] < oldest or newest.get(r["ip"], "") > r["last_seen"]:
            continue
        if ip.version == 4 and ip.is_private and (net is None or ip in net):
            out.append((r["mac"], str(ip)))
    return out


def check_due(db, env: dict | None = None, now: datetime | None = None) -> bool:
    last = store.get_meta(db, CHECK_META)
    if not last:
        return True
    now = now or datetime.now(timezone.utc)
    try:
        return now.timestamp() - _epoch(last) >= check_minutes(db, env) * 60 - 5
    except ValueError:
        return True


def check_recorded(db, env: dict | None = None, alive=None, net=None,
                   now: datetime | None = None, force: bool = False) -> int:
    """One light presence check (the `run` loop calls this every minute; it only acts
    when presence is on for someone and presence.check_minutes have passed). Records a
    'check' sample per device that answered; source_status 'presence'. Returns # seen,
    or -1 when it did nothing."""
    if store.is_demo(db) or not any(p["presence"] for p in store.people(db)):
        return -1
    if not force and not check_due(db, env, now):
        return -1
    from netwarden import discovery, health
    ts = store.now() if now is None else now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    store.set_meta(db, CHECK_META, ts)
    try:
        if net is None:
            _iface, net, _own = discovery.default_iface_net_ip()
            if not net:
                raise OSError("could not determine the local network")
        alive = alive or discovery.alive
        seen = [(mac, ts, "check") for mac, ip in check_targets(db, net, now) if alive(ip)]
        store.insert_presence_samples(db, seen)
        # The device answered: it IS online, so the inventory (map, device list, the AI's
        # lookups) says so too - one truth for "seen", not a home person with an offline phone.
        if seen:
            with db:
                db.executemany("UPDATE devices SET last_seen = ? WHERE mac = ? AND last_seen < ?",
                               [(ts, mac, ts) for mac, ts, _src in seen])
    except Exception as e:
        store.record_source_error(db, SOURCE, health.sanitize_error(e))
        raise
    store.record_source_ok(db, SOURCE, len(seen))
    return len(seen)


# --- localized views ---------------------------------------------------------------------

def _clock(ts: str | None, tz, lang: str, now: float) -> str:
    """'18:42' today, '10-19 18:42' on another day."""
    if not ts:
        return "—"
    dt = datetime.fromtimestamp(_epoch(ts), tz)
    if dt.date() == datetime.fromtimestamp(now, tz).date():
        return dt.strftime("%H:%M")
    return dt.strftime("%m-%d %H:%M")


def reason_text(row: dict, names: dict, tz, lang: str, now: float, grace_min: int) -> str:
    device = names.get(row.get("last_mac"), row.get("last_mac") or "")
    key = row["reason"]
    when = _clock(row.get("last_seen"), tz, lang, now)
    if key == "no_data":
        when = _clock(row.get("fresh"), tz, lang, now)
        key = "no_data" if row.get("fresh") else "no_data_ever"
    return i18n.t("presence.reason." + key, lang, device=device, time=when, grace=grace_min)


def report(db, lang: str, tz=None, now: datetime | None = None, env: dict | None = None,
           names: dict | None = None) -> dict:
    """GET /api/presence: every person's presence (state, plain-language reason, devices,
    timeline), the "home now" strip, link suggestions and the notifications to show."""
    from netwarden import naming
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    c = core(db, tz, now, env)
    nowe = _epoch(c["now"])
    names = names or naming.display_names(db, lang)
    people = {p["id"]: p for p in store.people(db)}
    rand = {r["mac"]: bool(r["randomized"]) for r in db.execute("SELECT mac, randomized FROM devices")}
    rows = []
    for row in c["people"]:
        p = people.get(row["id"])
        if p is None:
            continue
        base = {"id": p["id"], "name": p["name"], "avatar": p["avatar"], "color": p["color"],
                "presence": p["presence"], "notify_arrive": p["notify_arrive"],
                "notify_leave": p["notify_leave"],
                "default_devices": p["presence_macs"] is None}
        if not p["presence"]:
            rows.append({**base, "state": "off"})
            continue
        rows.append({**base, "state": row["state"],
                     "state_name": i18n.t("presence.state." + row["state"], lang),
                     "reason": reason_text(row, names, tz, lang, nowe, c["grace"]),
                     "last_seen": row["last_seen"],
                     "devices": [{"mac": m, "name": names.get(m, m), "randomized": rand.get(m, False)}
                                 for m in row["macs"]],
                     "events": row["events"], "days": row["days"]})
    sugs = []
    for s in link_suggestions(db, now):
        sugs.append({**s, "name": names.get(s["mac"], s["mac"]),
                     "from_name": names.get(s["from_mac"], s["from_mac"]),
                     "text": i18n.t("presence.link." + s["reason"], lang,
                                    name=names.get(s["mac"], s["mac"]), person=s["person"],
                                    old=names.get(s["from_mac"], s["from_mac"]), value=s["value"])})
    enabled = any(p["presence"] for p in people.values())
    return {"enabled": enabled, "grace_minutes": c["grace"],
            "check_minutes": check_minutes(db, env), "now": c["now"],
            "people": rows,
            "home_now": [r["id"] for r in rows if r["state"] in ("home", "probably_home")],
            "links": sugs,
            "notifications": notifications(db, tz, now, env) if enabled else [],
            "privacy": i18n.t("presence.privacy", lang),
            "private_mac": i18n.t("presence.private_mac", lang)}


def summary_lines(db, lang: str, tz=None, now: datetime | None = None,
                  env: dict | None = None) -> list:
    """One plain line per person WITH presence on (offline AI, digest): 'Mom: home -
    reason'. Nobody else is mentioned."""
    rep = report(db, lang, tz, now, env)
    return [i18n.t("presence.line", lang, name=r["name"], state=r["state_name"], reason=r["reason"])
            for r in rep["people"] if r["presence"]]


def snapshot(db, tz=None, now: datetime | None = None, env: dict | None = None) -> list:
    """For the AI context (canonical): only people with presence ON."""
    c = core(db, tz, now, env)
    people = {p["id"]: p for p in store.people(db)}
    out = []
    for row in c["people"]:
        p = people.get(row["id"])
        if not p or not p["presence"]:
            continue
        out.append({"person": p["name"], "state": row["state"], "reason": row["reason"],
                    "last_seen": row["last_seen"],
                    "events_7d": [{"kind": e["kind"], "ts": e["ts"], "late": e["late"]}
                                  for e in row["events"][:40]]})
    return out
