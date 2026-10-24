"""
netwarden - offline_ai.py: the "AI" that never leaves this machine.

When no ANTHROPIC_API_KEY is configured (or `--offline-ai` forces it), the brain uses
OfflineProvider instead of an LLM. It never touches the network: it answers with a
localized, rule-based summary of the same data the LLM would read - security alerts,
open risky ports, new devices, behavior changes, DNS-filter bypass, privacy grades,
who uses the most data, who gets blocked the most -
clearly labeled as offline mode, with a hint how to turn real AI on.

That makes the demo usable without a key, and gives tests (and later stages) a safe,
deterministic stand-in for the AI UI.

Extending: a section is a function (ctx) -> list of lines (empty = nothing to say).
Add it to SECTIONS; ctx carries the localized snapshot, the localized alerts and the
translate helper. Sections that report something "notable" make the all-quiet line go
away automatically.
"""
from __future__ import annotations

import re

from netwarden import alerts, i18n, naming, services, threatintel

MAX_LINES = 5   # per section; the rest becomes "...and N more"


def _human_bytes(n: float, lang: str) -> str:
    from netwarden.brain import human_bytes  # brain imports us; import lazily
    return human_bytes(n, lang)


def _name(d: dict, lang: str) -> str:
    return d.get("name") or d.get("vendor") or i18n.t("ui.unknown_device", lang)


def _capped(ctx, lines: list) -> list:
    if len(lines) > MAX_LINES:
        return lines[:MAX_LINES] + [ctx["tr"]("more", n=len(lines) - MAX_LINES)]
    return lines


# --- sections ----------------------------------------------------------------

def _head(ctx, key: str) -> str:
    """A section heading that names its period (round 10d): "New devices (last 24 h)" - the
    assistant's "Anything new this week?" lists 7 days, so the two never seem to disagree."""
    h = ctx["snap"]["window_hours"]
    when = i18n.t("aitool.win.24h" if h == 24 else "aitool.win.1h" if h == 1 else "", ctx["lang"])
    return i18n.t("offline.head_when", ctx["lang"], head=ctx["tr"](key), when=when) if when else ctx["tr"](key)


def section_threats(ctx) -> list:
    th = ctx["alerts"]["threats"]
    if not th:
        return []
    tr, lang = ctx["tr"], ctx["lang"]
    lines = [tr("threat_line", tag=threatintel.severity_tag(t["severity"], lang),
                device=t["device"], domain=t["domain"], label=t["label"]) for t in th]
    return [tr("threats")] + _capped(ctx, lines)


def section_new_devices(ctx) -> list:
    nd = [d for d in ctx["alerts"]["new_devices"] if not d.get("is_self")]
    if not nd:
        return []
    tr = ctx["tr"]
    lines = []
    for d in nd:
        info = [d["vendor"]] if d.get("vendor") else []
        if d.get("ip"):
            info.append(f"IP {d['ip']}")
        lines.append(tr("new_device_line", name=d["name"],
                        info=i18n.t("digest.sep", ctx["lang"]).join(info) or "—"))
    return [_head(ctx, "new_devices")] + _capped(ctx, lines)


def section_changes(ctx) -> list:
    bc = ctx["alerts"]["behavior_changes"]
    if not bc:
        return []
    tr, sep = ctx["tr"], i18n.t("list_sep", ctx["lang"])
    lines = [tr("change_line", name=c["name"], services=sep.join(c["new_services"])) for c in bc]
    return [_head(ctx, "changes")] + _capped(ctx, lines)


def section_exposure(ctx) -> list:
    ex = ctx["alerts"].get("exposure", [])
    if not ex:
        return []
    tr = ctx["tr"]
    lines = [tr("exposure_line", name=e["name"], port=e["port"], service=e["service"],
                risk=e["risk_name"], note=e["note"]) for e in ex]
    return [tr("exposure")] + _capped(ctx, lines)


def section_visibility(ctx) -> list:
    vis = ctx["alerts"].get("visibility", [])
    if not vis:
        return []
    return [ctx["tr"]("visibility")] + _capped(ctx, ["• " + v["text"] for v in vis])


def section_unusual_hours(ctx) -> list:
    night = ctx["alerts"].get("unusual_hours", [])
    if not night:
        return []
    return [ctx["tr"]("unusual_hours")] + _capped(ctx, ["• " + a["text"] for a in night])


def section_bandwidth_spikes(ctx) -> list:
    spikes = ctx["alerts"].get("bandwidth_spikes", [])
    if not spikes:
        return []
    return [i18n.t("digest.bandwidth_spikes", ctx["lang"])] + \
        _capped(ctx, ["• " + a["text"] for a in spikes])


def section_upnp(ctx) -> list:
    """Ports devices asked the router to open to the internet (UPnP)."""
    maps = ctx["alerts"].get("upnp", [])
    if not maps:
        return []
    return [i18n.t("digest.upnp", ctx["lang"])] + _capped(ctx, ["• " + m["text"] for m in maps])


def section_outages(ctx) -> list:
    """Internet / router outages (nethealth): when, how long, and the probable cause."""
    outs = ctx["alerts"].get("outage", [])
    if not outs:
        return []
    return [i18n.t("digest.outages", ctx["lang"])] + _capped(ctx, ["• " + o["text"] for o in outs])


def section_people(ctx) -> list:
    """Per owner (the user's own notes): devices, lookups, share made at night."""
    people = ctx["snap"].get("people") or []
    if not people:
        return []
    tr, sep = ctx["tr"], i18n.t("list_sep", ctx["lang"])
    names = naming.display_names(ctx["db"], ctx["lang"])   # localized, never a bare MAC
    mine: dict = {}
    for d in ctx["snap"]["devices"]:
        if d.get("owner"):
            mine.setdefault(d["owner"], []).append(names.get(d["mac"]) or d["name"] or d["mac"])
    lines = [i18n.tn("offline.person_line", p["queries"], ctx["lang"], owner=p["owner"], devices=sep.join(mine.get(p["owner"]) or p["devices"]),
                queries=p["queries"],
                night=round(100 * p["night_queries_7d"] / p["queries_7d"]) if p["queries_7d"] else 0)
             for p in people]
    return [tr("people", h=f"{ctx['snap']['window_hours']:g}")] + _capped(ctx, lines)


def section_presence(ctx) -> list:
    """Stage P: who is home - ONLY people who turned presence on."""
    from netwarden import presence   # presence -> screentime -> ...; keep the import lazy
    lines = presence.summary_lines(ctx["db"], ctx["lang"])
    if not lines:
        return []
    return [ctx["tr"]("presence")] + _capped(ctx, ["• " + x for x in lines])


def _screen_line(ctx, h: dict) -> str:
    from netwarden import screentime
    lang, sep = ctx["lang"], i18n.t("list_sep", ctx["lang"])
    return ctx["tr"]("screen_line", person=h["person"],
                     week=screentime.duration(h["screen_time_7d_minutes"], lang),
                     today=screentime.duration(h["screen_time_today_minutes"], lang),
                     services=sep.join(services.service_name(s, lang)
                                       for s in h["top_services_7d"]) or "—")


def section_screen_time(ctx) -> list:
    """Stage P: estimated screen time per person over the last 7 days."""
    hh = [h for h in ctx["snap"].get("household") or [] if h["screen_time_7d_minutes"]]
    if not hh:
        return []
    hh.sort(key=lambda h: -h["screen_time_7d_minutes"])
    return [ctx["tr"]("screen")] + _capped(ctx, [_screen_line(ctx, h) for h in hh]) + \
        [ctx["tr"]("screen_note")]


def asked_person(snap: dict, question: str | None) -> dict | None:
    """The household member a question names (the longest matching name), if any."""
    q = (question or "").casefold()
    if not q:
        return None
    hits = [h for h in snap.get("household") or [] if h["person"].casefold() in q]
    return max(hits, key=lambda h: len(h["person"]), default=None)


def section_person(ctx) -> list:
    """Stage P: a question that names a person gets their facts first - devices,
    estimated screen time (this week and today) and, only if they enabled it, presence."""
    h = asked_person(ctx["snap"], ctx.get("question"))
    if not h:
        return []
    tr, sep = ctx["tr"], i18n.t("list_sep", ctx["lang"])
    from netwarden import presence
    names = naming.display_names(ctx["db"], ctx["lang"])   # never a bare MAC
    devices = [names.get(m, m) for m in presence.owned(ctx["db"]).get(h["person"], [])]
    lines = [tr("person_title", person=h["person"]),
             tr("person_devices", devices=sep.join(devices) or "—"), _screen_line(ctx, h)]
    for row in presence.report(ctx["db"], ctx["lang"])["people"]:
        if row["name"] == h["person"] and row["presence"]:
            lines.append(i18n.t("presence.line", ctx["lang"], name=row["name"],
                                state=row["state_name"], reason=row["reason"]))
    return lines


def section_privacy(ctx) -> list:
    p = ctx["alerts"].get("privacy")
    if not p or not p["home"]["tracker_queries"]:
        return []
    tr, lang = ctx["tr"], ctx["lang"]
    lines = ["• " + p["home"]["line"]]
    for w in p["worst"]:
        lines.append("• " + i18n.t("digest.privacy_worst", lang, name=w["name"], grade=w["grade"],
                                   reason=w["reason"]))
    return [tr("privacy")] + lines


def section_bandwidth(ctx) -> list:
    snap, tr, lang = ctx["snap"], ctx["tr"], ctx["lang"]
    if not snap.get("has_bandwidth"):
        return []
    with_bw = [d for d in snap["devices"] if "bandwidth" in d]
    top = sorted(with_bw, key=lambda d: -(d["bandwidth"]["rx_bytes"] + d["bandwidth"]["tx_bytes"]))
    lines = [tr("bw_line", name=_name(d, lang), rx=_human_bytes(d["bandwidth"]["rx_bytes"], lang),
                tx=_human_bytes(d["bandwidth"]["tx_bytes"], lang)) for d in top[:3]]
    # A device that SENDS far more than it receives is unusual (cameras, backups, leaks).
    for d in top:
        bw = d["bandwidth"]
        if bw["tx_bytes"] > 2 * bw["rx_bytes"] and bw["tx_bytes"] >= 100e6:
            lines.append(tr("upload_note", name=_name(d, lang), tx=_human_bytes(bw["tx_bytes"], lang)))
    return [tr("bandwidth", h=f"{snap['window_hours']:g}")] + lines


def section_blocked(ctx) -> list:
    snap, tr = ctx["snap"], ctx["tr"]
    blocked = sorted((d for d in snap["devices"] if d.get("blocked")), key=lambda d: -d["blocked"])
    if not blocked:
        return []
    lines = [i18n.tn("offline.blocked_line", d["queries"], ctx["lang"], name=_name(d, ctx["lang"]),
                     blocked=d["blocked"], queries=d["queries"]) for d in blocked[:3]]
    return [tr("blocked")] + lines


# Order = importance. (section, counts as "notable" for the all-quiet line)
SECTIONS = [
    (section_threats, True),
    (section_exposure, True),
    (section_upnp, True),
    (section_outages, True),
    (section_new_devices, True),
    (section_changes, True),
    (section_unusual_hours, True),
    (section_bandwidth_spikes, True),
    (section_visibility, True),
    (section_presence, False),
    (section_screen_time, False),
    (section_people, False),
    (section_privacy, False),
    (section_bandwidth, False),
    (section_blocked, False),
]


# --- the provider --------------------------------------------------------------

def chunks(text: str):
    """The offline answer as a stream: one line at a time (newline kept), so the chat UI
    renders it progressively exactly like an LLM reply. Concatenated = `text`."""
    yield from text.splitlines(keepends=True)

def section_focus(ctx) -> list:
    """"Ask AI about this device": that device's facts first (name, type, services,
    lookups, privacy, open ports, threats, usual hours)."""
    mac = ctx.get("focus")
    if not mac:
        return []
    from netwarden import devicetype, store   # devicetype imports services -> keep lazy
    tr, lang, snap = ctx["tr"], ctx["lang"], ctx["snap"]
    sep = i18n.t("list_sep", lang)
    d = next((x for x in snap["devices"] if x.get("mac") == mac), None)
    name = (d and _name(d, lang)) or naming.display_names(ctx["db"], lang).get(mac, mac)
    lines = [tr("focus_title", name=name)]
    if d is None:
        return lines + [tr("focus_none", h=f"{snap['window_hours']:g}")]
    if d.get("type"):
        lines.append(tr("focus_type", type=devicetype.type_name(d["type"], lang)))
    if d.get("services"):
        lines.append(tr("focus_services", services=sep.join(d["services"][:6])))
    lines.append(i18n.tn("offline.focus_queries", d["queries"], lang, queries=d["queries"],
                         blocked=d.get("blocked") or 0, h=f"{snap['window_hours']:g}"))
    if d.get("privacy"):
        lines.append(tr("focus_privacy", grade=d["privacy"]["grade"],
                        pct=round(100 * d["privacy"]["tracker_share"])))
    if d.get("open_ports"):
        lines.append(tr("focus_ports", ports=sep.join(f"{p['port']}/{p['service']}"
                                                      for p in d["open_ports"])))
    risky = [t["domain"] for t in ctx["alerts"]["threats"] if t["mac"] == mac]
    if risky:
        lines.append(i18n.tn("offline.focus_threats", len(risky), lang, domains=sep.join(risky[:5])))
    if d.get("active_hours"):
        # the snapshot's hours are canonical ("07:00–12:00, 22:00–02:00", activity.hours_text):
        # joined the language's way here, as the drawer does
        lines.append(tr("focus_hours", hours=sep.join(d["active_hours"].split(", "))))
    return lines


def asks_about_focus(question: str | None, lang: str, focus: str | None) -> bool:
    """Is `question` the device drawer's pre-filled "Ask AI about this device" question
    (app.ask_prefill) for `focus`, with any name? The focus section answers exactly that,
    so the "cannot answer free-form questions" note would contradict the answer. Any
    language's wording counts (the box may have been filled before a language switch)."""
    if not (question and focus):
        return False
    for code in dict.fromkeys([i18n.normalize(lang)] + i18n.CODES):
        # the drawer's pre-filled question, and the chat's "Is anything unusual about
        # <device>?" chip shown while a device is in focus
        for key in FOCUS_QUESTIONS:
            tpl = i18n.t(key, code).replace("{mac}", focus)
            rx = r"\s*" + r".+?".join(re.escape(p) for p in tpl.split("{name}")) + r"\s*"
            if re.fullmatch(rx, question, re.I | re.S) is not None:
                return True
    return False


FOCUS_QUESTIONS = ("app.ask_prefill", "app.ai.q.device")
# data-driven chat chips (app.js suggestions()) the summary itself answers (its privacy
# section) - not "free-form" either
SUMMARY_CHIPS = ("app.ai.q.trackers",)


# the chat's own standing suggestion chips (app.js, the static demo builder): the summary
# below IS the offline answer to them, so they are not "free-form" either
STANDING = ("app.ai.s1", "app.ai.s2", "app.ai.s3")


def answered_here(question: str | None, lang: str, focus: str | None) -> bool:
    """Is `question` one the summary answers (no "cannot answer free-form" note)?"""
    q = (question or "").strip().casefold()
    return (any(q == i18n.t(k, code).strip().casefold() for k in STANDING + SUMMARY_CHIPS
                for code in dict.fromkeys([i18n.normalize(lang)] + i18n.CODES))
            or asks_about_focus(question, lang, focus))


def summarize(db, snap: dict, lang: str, question: str | None = None,
              focus: str | None = None) -> str:
    """The offline answer: a rule-based summary of `snap` (brain.snapshot) in `lang`;
    `focus` (a MAC) puts that device's facts first."""
    lang = i18n.normalize(lang)
    tr = lambda key, **kw: i18n.t("offline." + key, lang, **kw)  # noqa: E731
    lines = [tr("title")]
    if question and not answered_here(question, lang, focus):
        lines.append(tr("question_note"))
    if not (snap["clients_with_dns"] and snap["total_queries"]):
        lines += ["", i18n.t("brain.no_data", lang), "  python3 -m netwarden ingest --discover",
                  "", tr("enable_hint")]
        return "\n".join(lines)
    names = naming.display_names(db, lang)   # the dashboard's names, never a bare MAC
    localized = {**snap, "devices": [{**services.localize_device(d, lang),
                                      "name": d.get("name") or names.get(d.get("mac"))}
                                     for d in snap["devices"]]}
    result = alerts.localize(alerts.compute(db, recent_hours=snap["window_hours"]), lang, names)
    ctx = {"db": db, "snap": localized, "alerts": result, "lang": lang, "tr": tr,
           "focus": focus, "question": question}
    focused = section_focus(ctx) + section_person(ctx)
    if focused:
        lines += [""] + focused + [""]
    lines.append(tr("state", devices=snap["known_devices"], dns=snap["clients_with_dns"],
                    queries=snap["total_queries"], h=f"{snap['window_hours']:g}"))
    notable = False
    for section, counts in SECTIONS:
        part = section(ctx)
        if part:
            lines += [""] + part
            notable = notable or counts
    if not notable:
        lines += ["", tr("all_quiet")]
    lines += ["", tr("enable_hint")]
    return "\n".join(lines)


class OfflineProvider:
    """Stands in for an LLM provider. brain.insights / ask / converse see `offline`
    and call answer() with the snapshot instead of building a prompt."""
    offline = True
    name = "offline"
    model = "offline"

    def __init__(self, lang: str = i18n.DEFAULT):
        self.lang = lang

    def answer(self, db, snap: dict, lang: str, question: str | None = None,
               focus: str | None = None) -> str:
        return summarize(db, snap, lang, question, focus)

    def complete(self, system: str, user: str, max_tokens: int = 1200) -> str:
        # Only reached by callers that bypass brain's offline branch: no data to
        # summarize here, so say what mode we are in and how to leave it.
        return "\n".join([i18n.t("offline.title", self.lang), "",
                          i18n.t("offline.enable_hint", self.lang)])
