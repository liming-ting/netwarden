#!/usr/bin/env python3
"""
netwarden - report.py: a shareable, plain-language home-network report.

For the family member or the friend who helps with computers, or just for the record:
ONE self-contained file - the home score and what drives it, the next suggestions with
their steps, the devices, security and privacy findings, network health and what was
notable in the period - in the user's language.

    build(db, lang, opts)        -> doc      the report as data: {meta, sections}
    render_html(doc) / render_md(doc)        one file each (HTML: inline CSS + inline SVG
                                             charts, no script, no external request, a
                                             print stylesheet for A4 and Letter)
    generate(db, lang, opts)     -> (bytes, content type, file name)

Every number and sentence comes from the module the dashboard shows it from (score,
suggestions, alerts, privacy, nethealth, weekly, naming): one source of truth.

Privacy level (chosen at download time, PRIVACY):

    full       everything, including MAC / IP addresses and filter rules (admin only in
               LAN mode: web.py)
    shareable  the default: no MAC or IP address, no raw domain - service names only -,
               device names replaced by their type unless `names=keep`, people replaced
               by roles ("Child 1", "Family member 2") unless `people=keep`
    minimal    the score and the suggestions only, scrubbed like shareable

The scrubbing is done ONCE, over the finished document (Scrubber.deep): every string of
every section goes through redact.Redactor (every device name, hostname, announced name,
owner, MAC and household IP this database knows), then any other IP address and anything
that looks like a domain name are hidden. A section can't forget it. Secrets never enter
a report in the first place: nothing here reads a setting, a key, a pairing code or a
configured URL. No LLM, no network.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone, tzinfo
from html import escape

import netwarden
from netwarden import (activity, alerts, devicetype, family_report, i18n, naming, nethealth, privacy,
                       redact, score, services, store, suggestions, weekly)
from netwarden.export import _md_cell

PERIODS = (7, 30)
PRIVACY = ("full", "shareable", "minimal")
NAMES = ("type", "keep")          # shareable: device names -> their type (default) or kept
PEOPLE = ("roles", "keep")        # shareable: people -> roles (default) or kept
FORMATS = ("html", "md")
DEFAULTS = {"period": 7, "privacy": "shareable", "names": "type", "people": "roles", "format": "html"}
MAX_SUGGESTIONS = 8               # the rest: "and N more in the dashboard"
MAX_LINES = 15                    # findings / events / new devices listed per block
MAX_DEVICES = 500                 # the full inventory table (a home, not a data center)
CTYPES = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8"}

# Words that look like a domain name but are file names in step texts ("trackers_custom.txt")
_FILE_EXT = {"txt", "md", "json", "csv", "html", "htm", "py", "yaml", "yml", "sh", "db", "cmd",
             "bat", "js", "css", "conf", "log", "png", "svg", "pdf"}
DOMAIN_RE = re.compile(r"(?<![\w.@-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})"
                       r"(?![\w-]|\.\w)", re.I)


class BadOption(ValueError):
    """An unknown report option: .key = the option ("period", "privacy", ...)."""

    def __init__(self, key: str):
        super().__init__(key)
        self.key = key


def parse_period(value) -> int:
    """7 | 30 from "7", "7d", "30d", 7 ... (anything else: BadOption)."""
    text = str(value if value is not None else "").strip().lower()
    if text.endswith("d"):
        text = text[:-1]
    if re.fullmatch(r"[0-9]{1,3}", text) and int(text) in PERIODS:   # ASCII only ("७" is a digit too)
        return int(text)
    raise BadOption("period")


def options(raw: dict | None = None) -> dict:
    """Validated options from a query / CLI ({key: value}, missing = DEFAULTS)."""
    raw = raw or {}
    out = dict(DEFAULTS)
    if raw.get("period") not in (None, ""):
        out["period"] = parse_period(raw["period"])
    for key, allowed in (("privacy", PRIVACY), ("names", NAMES), ("people", PEOPLE),
                         ("format", FORMATS)):
        v = raw.get(key)
        if v in (None, ""):
            continue
        if not isinstance(v, str) or v.strip().lower() not in allowed:
            raise BadOption(key)
        out[key] = v.strip().lower()
    if out["privacy"] == "minimal":          # minimal never names anybody
        out["names"], out["people"] = "type", "roles"
    elif out["privacy"] == "full":
        out["names"], out["people"] = "keep", "keep"
    return out


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _local_day(iso: str | None, tz: tzinfo) -> str:
    if not iso:
        return "—"
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(tz).strftime("%Y-%m-%d")


# --- the privacy scrub -------------------------------------------------------------------

class Scrubber:
    """Turns household identifiers in any text into what the chosen level allows. Built
    once per report from the database (redact.Redactor knows every name / MAC / IP)."""

    KEEP = ("t", "cls", "kind", "level", "num", "severity", "key")   # structural fields

    def __init__(self, db, lang: str, opts: dict, names: dict, types: dict):
        self.lang, self.opts, self.names = lang, opts, names
        self.on = opts["privacy"] != "full"
        self.hidden = i18n.t("share.hidden", lang)   # "•••": an address or a domain left out
        if not self.on:
            return
        self.r = redact.Redactor.build(db)
        # a device whose hostname is just "printer" or "TV" names nobody - and must not
        # turn every "Printer" / "TV" in the report (type names, charts) into a device
        generic = {devicetype.type_name(k, code).lower() for k in devicetype.TYPES for code in (lang, "en")}
        for form in [f for f in self.r._lookup if f in generic and self.r._lookup[f].startswith("[D")]:
            del self.r._lookup[form]
        people = {p["name"]: p for p in store.people(db)}
        # roles in the redactor's own (stable) person order: "Child 1", "Family member 2"
        self.roles, counts = {}, {"child": 0, "member": 0}
        for tok, real in self.r.real.items():
            if tok.startswith("[P"):
                kind = "child" if (people.get(real) or {}).get("child") else "member"
                counts[kind] += 1
                self.roles[tok] = i18n.t("share.role." + kind, lang, n=counts[kind])
        # people only: scrubs the people out of a device name that is kept
        self.pr = redact.Redactor()
        for tok, real in self.r.real.items():
            if tok.startswith("[P"):
                self.pr.add(tok, real, real)
        self.pr._short = {k: v for k, v in self.r._short.items() if v.startswith("[P")}
        # device -> "Phone 2": numbered per type in the inventory's order (first seen, MAC)
        self.by_type: dict = {}
        per: dict = {}
        for row in db.execute("SELECT mac FROM devices ORDER BY first_seen, mac"):
            typ = (types.get(row["mac"]) or {}).get("type") or "unknown"
            per[typ] = per.get(typ, 0) + 1
            self.by_type[row["mac"]] = i18n.t("share.dev_n", lang, type=devicetype.type_name(typ, lang),
                                              n=per[typ])

    def device(self, mac: str) -> str:
        """The name a device gets in this report."""
        name = self.names.get(mac) or mac
        if not self.on:
            return name
        if self.opts["names"] == "keep":
            # a kept name is the name, not a way around the address / domain masking: a
            # hostname like "nas.example.org" or a name with a URL in it is masked like text
            return self._mask(self.people_only(name))
        return self.by_type.get(mac) or self.hidden

    def person(self, name: str | None) -> str:
        if not name or not self.on or self.opts["people"] == "keep":
            return name or ""
        return self.text(name)

    def people_only(self, text: str) -> str:
        if self.opts["people"] == "keep":
            return text
        return redact.TOKEN_RE.sub(lambda m: self.roles.get(m.group(0), self.hidden), self.pr.redact(text))

    def _token(self, tok: str) -> str:
        kind, n = redact.TOKEN_RE.fullmatch(tok).groups()
        if kind == "D":
            mac = self.r.real.get(f"[M{n}]")
            return self.device(mac) if mac else self.hidden
        if kind == "P":
            return self.r.real.get(tok, self.hidden) if self.opts["people"] == "keep" \
                else self.roles.get(tok, self.hidden)
        if kind == "R":
            return self.r.real.get(tok, self.hidden)    # rooms say nothing about anybody
        return self.hidden                              # [M..] / [IP..]

    def text(self, value: str) -> str:
        if not self.on or not value:
            return value
        out = self._mask(self.r.redact(value))
        return redact.TOKEN_RE.sub(lambda m: self._token(m.group(0)), out)

    def _mask(self, out: str) -> str:
        """Any MAC, IP address or domain left in the text -> •••."""
        out = redact.MAC_RE.sub(self.hidden, out)
        out = redact.IPV6_RE.sub(lambda m: self.hidden if _is_ip(m.group(0)) else m.group(0), out)
        out = redact.IPV4_RE.sub(self.hidden, out)      # public addresses too (WAN, resolvers)
        return DOMAIN_RE.sub(lambda m: m.group(0) if m.group(1).lower() in _FILE_EXT else self.hidden, out)

    def deep(self, obj, key: str = ""):
        """Every string in a section, at any depth (structural fields excepted)."""
        if not self.on:
            return obj
        if isinstance(obj, str):
            return obj if key in self.KEEP else self.text(obj)
        if isinstance(obj, list):
            return [self.deep(x, key) for x in obj]
        if isinstance(obj, tuple):
            return tuple(self.deep(x, key) for x in obj)
        if isinstance(obj, dict):
            return {k: self.deep(v, k) for k, v in obj.items()}
        return obj


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.rstrip(":").split("%", 1)[0])
        return True
    except ValueError:
        return False


# --- building the document -------------------------------------------------------------------
# A section = {key, title, blocks}; a block = {"t": p | ul | kv | table | chart | sug | h3 |
# score, ...}. Only strings and numbers - render_html / render_md decide the markup.

def _p(text: str, cls: str = "") -> dict:
    return {"t": "p", "text": text, "cls": cls}


def _ul(items: list, more: int = 0, lang: str = "en") -> list:
    out = [{"t": "ul", "items": items[:MAX_LINES]}]
    extra = len(items) - MAX_LINES + more
    if extra > 0:
        out.append(_p(i18n.t("wow.more", lang, n=extra), "muted"))
    return out


def _score_section(db, lang, tz, env, period, now) -> dict:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    rep = score.report(db, lang, env, tz)
    blocks = [{"t": "score", "score": rep["score"], "level": rep["level"],
               "text": rep["summary"] if rep["score"] is not None else t("share.score_none")}]
    blocks.append({"t": "chart", "kind": "bars", "title": t("share.chart.pillars"), "max": score.PILLAR_MAX,
                   "data": [{"label": p["name"], "value": p["score"],
                             "note": "" if p["measured"] else t("share.not_measured"),
                             "level": score.level(round(100 * p["score"] / p["max"]))
                             if p["score"] is not None else "idle"} for p in rep["pillars"]]})
    blocks.append({"t": "h3", "text": t("share.drivers")})
    drivers = [t("share.driver", text=d["text"], n=d["gain"]) for d in rep["deductions"]]
    blocks += _ul(drivers, lang=lang) if drivers else [_p(t("share.no_drivers"), "ok")]
    since_day = (now.astimezone(tz).date() - timedelta(days=period)).isoformat()
    hist = [h for h in store.score_history(db, since_day) if h["score"] is not None]
    if len(hist) >= 2:
        blocks.append({"t": "chart", "kind": "line", "title": t("share.chart.trend"), "max": 100,
                       "data": [{"label": h["day"][5:], "value": h["score"], "level": score.level(h["score"])}
                                for h in hist]})
        blocks.append(_p(t("share.trend_line", start=hist[0]["score"], end=hist[-1]["score"],
                           first=hist[0]["day"], last=hist[-1]["day"]), "muted"))
    blocks.append(_p(rep["note"], "muted"))
    return {"key": "score", "title": t("share.sec.score"), "blocks": blocks}


def _sug_params(params: dict, lang: str) -> dict:
    """shareable: what a suggestion's text may say - service names instead of domains,
    no addresses (the scrubber is the safety net; this keeps the sentences readable)."""
    out = dict(params)
    sep = i18n.t("list_sep", "en")      # canonical params are joined in English (suggestions._detect)
    for k in ("domains", "resolvers"):
        if isinstance(out.get(k), str) and out[k]:
            doms = [d.strip() for d in out[k].split(sep) if d.strip()]
            names = services.services_for(doms, lang)
            out[k] = i18n.t("list_sep", lang).join(names) if names else \
                i18n.tn("share.n_domains", out.get("n") or len(doms), lang)
    for k in ("ip", "ports"):
        if k in out:
            out[k] = i18n.t("share.hidden", lang)
    return out


def _suggestions_section(db, lang, env, opts, names) -> dict:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    rep = suggestions.report(db, lang, env)
    full = opts["privacy"] == "full"
    blocks = []
    items = rep["open"]
    for it in items[:MAX_SUGGESTIONS]:
        if not full:   # re-localize with readable stand-ins for the hidden parameters
            it = {**suggestions.localize({k: it[k] for k in ("id", "kind", "pillar", "severity", "params",
                                                            "devices", "rules", "copy", "evidence")}
                                         | {"params": _sug_params(it["params"], lang)}, lang, names),
                  "points": it["points"]}
        rules = None
        if full and it.get("rules"):
            rules = [{"name": t("sug.platform." + k), "text": v} for k, v in it["rules"].items()
                     if k in ("adguard", "pihole") and v]
        blocks.append({"t": "sug", "title": it["title"], "why": it["why"], "severity": it["severity"],
                       "severity_name": it["severity_name"], "pillar": it["pillar_name"],
                       "points": i18n.tn("share.sug_points", it["points"], lang) if it["points"] else "",
                       "platforms": [{"name": p["name"], "steps": p["steps"]} for p in it["platforms"]],
                       "rules": rules,
                       "rules_hidden": bool(it.get("rules")) and not full})
    if not items:
        blocks.append(_p(t("share.sug_none"), "ok"))
    elif len(items) > MAX_SUGGESTIONS:
        blocks.append(_p(i18n.tn("share.sug_more", len(items) - MAX_SUGGESTIONS, lang), "muted"))
    if any(b.get("rules_hidden") for b in blocks):
        blocks.append(_p(t("share.rules_hidden"), "muted"))
    return {"key": "suggestions", "title": t("share.sec.suggestions"), "blocks": blocks}


def _devices_section(db, lang, tz, opts, scrub, types, since) -> dict:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    sep = t("list_sep")
    full = opts["privacy"] == "full"
    show_names = full or opts["names"] == "keep"
    profiles = store.get_profiles(db)
    rows = [dict(r) for r in db.execute(
        "SELECT mac, ip, vendor, first_seen, last_seen, is_self FROM devices WHERE last_seen >= ? "
        "ORDER BY first_seen, mac", (since,))]
    for r in rows:
        prof = profiles.get(r["mac"]) or {}
        r["type"] = (types.get(r["mac"]) or {}).get("type") or "unknown"
        r["type_name"] = devicetype.type_name(r["type"], lang)
        r["name"] = scrub.device(r["mac"])
        r["owner"] = scrub.person(prof.get("owner"))
        r["room"] = prof.get("room") or ""
    new = [r for r in rows if (r["first_seen"] or "") >= since and not r["is_self"]]   # as in "notable"
    unknown = [r for r in rows if r["type"] == "unknown"]
    blocks = [_p(i18n.tn("share.dev_summary", len(rows), lang, new=len(new), unknown=len(unknown)))]
    if not rows:
        return {"key": "devices", "title": t("share.sec.devices"), "blocks": blocks}
    by_type: dict = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r)
    order = sorted(by_type, key=lambda k: (-len(by_type[k]), devicetype.TYPES.index(k)
                                           if k in devicetype.TYPES else 99))
    blocks.append({"t": "chart", "kind": "bars", "title": t("share.by_type"),
                   "max": max(len(v) for v in by_type.values()),
                   "data": [{"label": devicetype.type_name(k, lang), "value": len(by_type[k]), "level": "info"}
                            for k in order]})
    if show_names:   # without names the table would only repeat the chart
        blocks.append({"t": "table", "head": [t("export.col.type"), t("share.th.count"), t("share.th.names")],
                       "num": [1], "rows": [[devicetype.type_name(k, lang), str(len(by_type[k])),
                                             sep.join(r["name"] for r in by_type[k])] for k in order]})
    owners: dict = {}
    for r in rows:
        owners.setdefault(r["owner"] or "", []).append(r)
    if any(owners):
        blocks.append({"t": "h3", "text": t("share.by_owner")})
        keys = sorted((k for k in owners if k), key=lambda k: (-len(owners[k]), k)) + ([""] if "" in owners else [])
        blocks.append({"t": "table", "head": [t("share.th.person"), t("share.th.count"), t("share.th.types")],
                       "num": [1],
                       "rows": [[k or t("rep.shared"), str(len(owners[k])),
                                 sep.join(sorted({r["type_name"] for r in owners[k]}))] for k in keys]})
    blocks.append({"t": "h3", "text": t("share.new_devices")})

    def line(r, when):
        bits = [r["name"]] + ([r["type_name"]] if show_names else [])   # "Phone 4" says it already
        if r["owner"]:
            bits.append(r["owner"])
        if full:
            bits += [x for x in (r["ip"], r["mac"]) if x]
        return " · ".join(bits) + " — " + when
    blocks += _ul([line(r, t("share.first_seen", day=_local_day(r["first_seen"], tz))) for r in new], lang=lang) \
        if new else [_p(t("share.no_new"), "muted")]
    blocks.append({"t": "h3", "text": t("share.unknown")})
    blocks += _ul([line(r, r["vendor"] or t("devtype.unknown")) for r in unknown], lang=lang) \
        if unknown else [_p(t("share.no_unknown"), "ok")]
    if full:
        blocks.append({"t": "h3", "text": t("share.all_devices")})
        cols = ("name", "type", "owner", "room", "vendor", "ip", "mac", "last_seen")
        blocks.append({"t": "table", "head": [t("export.col." + c) for c in cols], "num": [],
                       "small": True,
                       "rows": [[r["name"], r["type_name"], r["owner"], r["room"], r["vendor"] or "",
                                 r["ip"] or "", r["mac"], (r["last_seen"] or "")[:16].replace("T", " ")]
                                for r in rows[-MAX_DEVICES:]]})
    return {"key": "devices", "title": t("share.sec.devices"), "blocks": blocks}


def _security_section(db, lang, opts, names, period) -> dict:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    # the findings the Security page shows now (alerts over the dashboard's window,
    # kept warm by runner.Warmer) - the same lines as the printable weekly report
    al = alerts.localize(alerts.compute(db, recent_hours=24), lang, names)
    lines = list(dict.fromkeys(family_report._security_lines(   # without domains, lines may repeat
        al, lang, domains=opts["privacy"] == "full", changes=False, new=False)))
    blocks = [{"t": "h3", "text": t("share.findings")}]
    blocks += _ul(lines, lang=lang) if lines else [_p(t("rep.security_clear"), "ok")]
    pv = privacy.report(db, hours=24 * period, lang=lang)
    home = pv.get("home") or {}
    blocks.append({"t": "h3", "text": t("share.privacy_h", days=period)})
    if home.get("tracker_queries"):
        blocks.append({"t": "kv", "rows": [[t("share.grade"), home.get("grade") or "—"]]})
        blocks.append(_p(home.get("line") or ""))
        worst = [f'{w["name"]}: {w["grade"]} — {w["reason"]}' for w in (pv.get("worst") or [])[:3]]
        if worst:
            blocks += _ul(worst, lang=lang)
    else:
        blocks.append(_p(t("app.priv.none"), "muted"))
    return {"key": "security", "title": t("share.sec.security"), "blocks": blocks}


def _health_section(db, lang, tz, env, period, now) -> tuple[dict, list]:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    rep = nethealth.report(db, lang, tz=tz, env=env)
    v = rep["verdict"]
    blocks = [{"t": "score", "score": None, "level": v["level"], "text": v["title"]}]
    if v.get("text"):
        blocks.append(_p(v["text"]))
    since = _iso(now - timedelta(days=period))
    outs = [o for o in rep["outages"] if o["start_ts"] >= since or o.get("ongoing")]
    blocks.append({"t": "h3", "text": t("share.outages", n=len(outs))})
    if outs:
        days = [(now - timedelta(days=i)).astimezone(tz).date().isoformat() for i in range(period - 1, -1, -1)]
        per = {d: 0 for d in days}
        for o in outs:
            d = _local_day(o["start_ts"], tz)
            if d in per:
                per[d] += 1
        blocks.append({"t": "chart", "kind": "cols", "title": t("share.chart.outages"), "max": max(per.values()) or 1,
                       "data": [{"label": d[5:], "value": n, "level": "bad" if n else "idle"} for d, n in per.items()]})
        blocks += _ul([o["text"] for o in outs], lang=lang)
    else:
        blocks.append(_p(t("share.no_outages"), "ok"))
    dns_days = rep["dns"].get("days") or []
    if any(d["queries"] for d in dns_days):
        blocks.append({"t": "chart", "kind": "cols", "title": t("share.chart.dns"),
                       "max": max(d["queries"] for d in dns_days) or 1,
                       "data": [{"label": d["date"][5:], "value": d["queries"],
                                 "level": "warn" if (d["fail_rate"] or 0) >= nethealth.FAILING_DNS else "info"}
                                for d in dns_days]})
    blocks.append(_p(rep["note"], "muted"))
    return {"key": "health", "title": t("share.sec.health"), "blocks": blocks}, outs


def _events_section(db, lang, tz, period, now, outages) -> dict:
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    since = _iso(now - timedelta(days=period))
    c = db.execute("SELECT COUNT(*) AS q, COALESCE(SUM(blocked), 0) AS b FROM dns_events WHERE ts >= ?",
                   (since,)).fetchone()
    new = db.execute("SELECT COUNT(*) FROM devices WHERE first_seen >= ? AND is_self = 0", (since,)).fetchone()[0]
    threats = alerts.recent_threats(db, since)
    lines = [i18n.tn("share.ev.lookups", c["q"], lang, n=i18n.num(c["q"], lang), blocked=i18n.num(c["b"], lang)) if c["q"] else t("share.ev.no_dns"),
             t("share.ev.new", n=new), t("share.ev.threats", n=len(threats)),
             t("share.ev.outages", n=len(outages))]
    blocks = [{"t": "ul", "items": lines}]
    wk = weekly.report(db, lang, tz=tz)
    blocks.append({"t": "h3", "text": t("rep.highlights")})
    blocks += _ul(list(wk["highlights"]), lang=lang)
    return {"key": "events", "title": t("share.sec.events", days=period), "blocks": blocks}


def build(db, lang: str, opts: dict | None = None, env: dict | None = None, tz: tzinfo | None = None,
          now: datetime | None = None) -> dict:
    """The report as data: {meta, sections}. opts = options() (validated here again)."""
    lang = i18n.normalize(lang)
    opts = options(opts)
    tz = tz or activity.local_tz()
    now = now or datetime.now(timezone.utc)
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    period = opts["period"]
    names = naming.display_names(db, lang)
    types = devicetype.classify_all(db)
    scrub = Scrubber(db, lang, opts, names, types)
    since = _iso(now - timedelta(days=period))
    sections = [_score_section(db, lang, tz, env, period, now),
                _suggestions_section(db, lang, env, opts, names)]
    if opts["privacy"] != "minimal":
        health, outs = _health_section(db, lang, tz, env, period, now)
        sections += [_devices_section(db, lang, tz, opts, scrub, types, since),
                     _security_section(db, lang, opts, names, period), health,
                     _events_section(db, lang, tz, period, now, outs)]
    local = now.astimezone(tz)
    start = (local - timedelta(days=period)).strftime("%Y-%m-%d")
    meta = {
        "lang": lang, "title": t("share.title"), "options": opts,
        "date": local.strftime("%Y-%m-%d %H:%M") + " " + activity.tz_label(tz),
        "day": local.strftime("%Y-%m-%d"),
        "period": t("share.period_line", days=period, start=start, end=local.strftime("%Y-%m-%d")),
        "privacy": t("share.level." + opts["privacy"]),
        "privacy_note": t("share.level_desc." + opts["privacy"]),
        "version": netwarden.__version__, "source": netwarden.SOURCE_URL,
        "demo": store.is_demo(db),
        "labels": {k: t("share.meta." + k) for k in ("date", "period", "privacy", "version", "source")},
        "footer": t("share.footer"), "demo_note": t("ui.demo_badge"),
        "contents": t("share.contents"),
    }
    return {"meta": meta, "sections": scrub.deep(sections)}


# --- HTML ------------------------------------------------------------------------------------

def _e(v) -> str:
    return escape("" if v is None else str(v), quote=True)


CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1d2433;--muted:#5a6475;--line:#d9dee7;--card:#f6f8fb;
--ok:#1e7a46;--warn:#9a5b00;--bad:#b42318;--info:#2f5fb3;--idle:#8a93a3}
@media screen and (prefers-color-scheme:dark){:root{--bg:#12161d;--fg:#e6e9ef;--muted:#a3acbb;
--line:#2c3442;--card:#1a2029;--ok:#5cc58a;--warn:#e3a33b;--bad:#f2867c;--info:#7fa8f0;--idle:#7d8696}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",
"Noto Sans","Noto Sans TC","Noto Sans SC","Noto Sans JP","Noto Sans KR","PingFang TC","Microsoft JhengHei",
"Hiragino Sans",sans-serif}
main{max-width:860px;margin:0 auto;padding:28px 20px 48px}
header.top{border-bottom:2px solid var(--fg);padding-bottom:12px;margin-bottom:8px}
.brand{font-weight:600;letter-spacing:.02em;color:var(--muted)}.brand b{color:var(--fg)}
h1{font-size:1.7rem;margin:.2em 0 .4em}h2{font-size:1.25rem;margin:0 0 .6em;padding-bottom:4px;
border-bottom:1px solid var(--line)}h3{font-size:1rem;margin:1.2em 0 .4em}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:0;font-size:.9rem}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.note{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:.9rem}
nav.toc ol{margin:.3em 0 0;padding-left:1.4em;columns:2}nav.toc{font-size:.9rem}
section{margin:28px 0}p{margin:.4em 0}.muted{color:var(--muted);font-size:.9rem}.ok{color:var(--ok)}
ul{margin:.3em 0;padding-left:1.3em}li{margin:.15em 0;overflow-wrap:anywhere}
.big{display:flex;align-items:center;gap:14px;margin:.4em 0 .8em}
.big .n{font-size:2.6rem;font-weight:700;line-height:1;min-width:2.2ch}
.lv-ok{color:var(--ok)}.lv-warn{color:var(--warn)}.lv-bad{color:var(--bad)}.lv-idle{color:var(--idle)}
.lv-info{color:var(--info)}
.dot{display:inline-block;width:.8em;height:.8em;border-radius:50%;background:currentColor}
table{border-collapse:collapse;width:100%;font-size:.92rem;margin:.4em 0}
th,td{text-align:left;border-bottom:1px solid var(--line);padding:4px 8px;vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600}td.num,th.num{text-align:right;white-space:nowrap}
table.small{font-size:.8rem}.tw{overflow-x:auto}
table.small th,table.small td{white-space:nowrap;overflow-wrap:normal}
dl.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:.3em 0}dl.kv dd{margin:0;font-weight:600}
figure{margin:.6em 0 1em}figure svg{width:100%;height:auto;display:block}figcaption{font-size:.85rem;color:var(--muted)}
svg text{fill:var(--fg);font:12px system-ui,sans-serif}svg .ax{stroke:var(--line)}
svg .ok{fill:var(--ok)}svg .warn{fill:var(--warn)}svg .bad{fill:var(--bad)}svg .info{fill:var(--info)}
svg .idle{fill:var(--idle)}svg .track{fill:var(--card);stroke:var(--line)}svg .ln{fill:none;stroke:var(--info);stroke-width:2}
.sug{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:10px 14px;margin:12px 0}
.sug.high{border-left-color:var(--bad)}.sug.medium{border-left-color:var(--warn)}.sug.low{border-left-color:var(--info)}
.sug h3{margin:0 0 .2em}.sug .tags{font-size:.82rem;color:var(--muted)}
.sug ol{margin:.2em 0 .5em;padding-left:1.5em}.sug h4{font-size:.9rem;margin:.6em 0 .1em}
pre{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px;font-size:.8rem;
white-space:pre-wrap;overflow-wrap:anywhere}
footer{margin-top:36px;border-top:1px solid var(--line);padding-top:10px;font-size:.85rem;color:var(--muted)}
@page{margin:15mm 13mm}
@media print{body{font-size:10.5pt;background:#fff;color:#000}main{max-width:none;padding:0}
section{break-before:page;margin:0}section.first{break-before:auto}nav.toc{break-after:avoid}
.sug,figure,dl{break-inside:avoid}.tw{overflow:visible}
table.small th,table.small td{white-space:normal;overflow-wrap:anywhere}tr{break-inside:avoid}h2,h3{break-after:avoid}a{color:inherit;text-decoration:none}}
"""


def _num(v, lang: str) -> str:
    """A chart value the language's way ("1,234" / "1.234" / "1 234"); None -> "—"."""
    if v is None:
        return "—"
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return i18n.num(v, lang, 0 if float(v).is_integer() else 1)
    return str(v)


def _chart_html(b: dict, lang: str) -> str:
    """An inline SVG chart (bars = horizontal, cols = per day, line = a trend); its text
    alternative lists the values with the language's list separator and number format."""
    data, top = b["data"], b.get("max") or 1
    alt = b["title"] + ": " + i18n.t("list_sep", lang).join(f'{d["label"]} {_num(d["value"], lang)}'
                                                           for d in data)
    if b["kind"] == "bars":
        lw, w, rh = 170, 640, 26
        h = rh * len(data) + 6
        parts = []
        for i, d in enumerate(data):
            y = 3 + i * rh
            val = d["value"]
            bw = 0 if val is None else max(2, (w - lw - 60) * val / top)
            parts.append(f'<text x="{lw - 8}" y="{y + 16}" text-anchor="end">{_e(d["label"][:28])}</text>'
                         f'<rect class="track" x="{lw}" y="{y + 4}" width="{w - lw - 60}" height="16" rx="3"/>'
                         f'<rect class="{_e(d.get("level") or "info")}" x="{lw}" y="{y + 4}" width="{bw:.1f}" '
                         f'height="16" rx="3"/><text x="{w - 52}" y="{y + 16}">'
                         f'{_e(d.get("note") or _num(val, lang))}</text>')
    elif b["kind"] == "cols":
        w, h, base = 640, 150, 120
        n = max(1, len(data))
        cw = (w - 20) / n
        step = max(1, round(n / 10))       # at most ~10 day labels
        parts = [f'<line class="ax" x1="10" y1="{base}" x2="{w - 10}" y2="{base}"/>']
        for i, d in enumerate(data):
            x = 10 + i * cw
            bh = (base - 14) * (d["value"] or 0) / top
            parts.append(f'<rect class="{_e(d.get("level") or "info")}" x="{x + cw * .15:.1f}" y="{base - bh:.1f}" '
                         f'width="{cw * .7:.1f}" height="{bh:.1f}" rx="2"/>')
            if i % step == 0:
                parts.append(f'<text x="{x + cw / 2:.1f}" y="{base + 16}" text-anchor="middle">{_e(d["label"])}</text>')
        parts.append(f'<text x="12" y="12">{_e(_num(top, lang))}</text>')
    else:   # line
        w, h, base = 640, 160, 130
        n = len(data)
        xs = [20 + (w - 40) * i / max(1, n - 1) for i in range(n)]
        ys = [base - (base - 14) * (d["value"] or 0) / top for d in data]
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
        parts = [f'<line class="ax" x1="20" y1="{base}" x2="{w - 20}" y2="{base}"/>',
                 f'<polyline class="ln" points="{pts}"/>']
        step = max(1, round(n / 8))
        for i, (x, y, d) in enumerate(zip(xs, ys, data)):
            parts.append(f'<circle class="{_e(d.get("level") or "info")}" cx="{x:.1f}" cy="{y:.1f}" r="3.5"/>')
            if i % step == 0 or i == n - 1:
                parts.append(f'<text x="{x:.1f}" y="{base + 16}" text-anchor="middle">{_e(d["label"])}</text>'
                             f'<text x="{x:.1f}" y="{y - 8:.1f}" text-anchor="middle">{_e(_num(d["value"], lang))}</text>')
    return (f'<figure><svg viewBox="0 0 {w} {h}" role="img" aria-label="{_e(alt)}" '
            f'xmlns="http://www.w3.org/2000/svg"><title>{_e(alt)}</title>{"".join(parts)}</svg>'
            f'<figcaption>{_e(b["title"])}</figcaption></figure>')


def _block_html(b: dict, lang: str) -> str:
    kind = b["t"]
    if kind == "p":
        return f'<p class="{_e(b.get("cls"))}">{_e(b["text"])}</p>' if b.get("cls") else f'<p>{_e(b["text"])}</p>'
    if kind == "h3":
        return f"<h3>{_e(b['text'])}</h3>"
    if kind == "ul":
        return "<ul>" + "".join(f"<li>{_e(x)}</li>" for x in b["items"]) + "</ul>"
    if kind == "kv":
        return '<dl class="kv">' + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in b["rows"]) + "</dl>"
    if kind == "score":
        n = "—" if b["score"] is None else b["score"]
        mark = f'<span class="n lv-{_e(b["level"])}">{_e(n)}</span>' if b["score"] is not None \
            else f'<span class="dot lv-{_e(b["level"])}" aria-hidden="true"></span>'
        return f'<div class="big">{mark}<p>{_e(b["text"])}</p></div>'
    if kind == "table":
        num = set(b.get("num") or [])
        head = "".join(f'<th scope="col"{" class=num" if i in num else ""}>{_e(h)}</th>' for i, h in enumerate(b["head"]))
        rows = "".join("<tr>" + "".join(f'<td{" class=num" if i in num else ""}>{_e(c)}</td>'
                                        for i, c in enumerate(r)) + "</tr>" for r in b["rows"])
        return (f'<div class="tw"><table{" class=small" if b.get("small") else ""}><thead><tr>{head}</tr></thead>'
                f"<tbody>{rows}</tbody></table></div>")
    if kind == "chart":
        return _chart_html(b, lang)
    if kind == "sug":
        tags = " · ".join(_e(x) for x in (b["severity_name"], b["pillar"], b["points"]) if x)
        plats = "".join(f'<h4>{_e(p["name"])}</h4><ol>' + "".join(f"<li>{_e(s)}</li>" for s in p["steps"]) + "</ol>"
                        for p in b["platforms"])
        rules = "".join(f'<h4>{_e(r["name"])}</h4><pre>{_e(r["text"])}</pre>' for r in b.get("rules") or [])
        return (f'<div class="sug {_e(b["severity"])}"><h3>{_e(b["title"])}</h3><div class="tags">{tags}</div>'
                f'<p>{_e(b["why"])}</p>{plats}{rules}</div>')
    return ""


def render_html(doc: dict) -> str:
    m = doc["meta"]
    lab = m["labels"]
    toc = "".join(f'<li><a href="#s-{_e(s["key"])}">{_e(s["title"])}</a></li>' for s in doc["sections"])
    body = "".join(f'<section id="s-{_e(s["key"])}"{" class=first" if i == 0 else ""}><h2>{_e(s["title"])}</h2>'
                   + "".join(_block_html(b, m["lang"]) for b in s["blocks"]) + "</section>"
                   for i, s in enumerate(doc["sections"]))
    demo = f' · {_e(m["demo_note"])}' if m["demo"] else ""
    return f"""<!doctype html>
<html lang="{_e(m["lang"])}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<meta name="generator" content="netwarden {_e(m["version"])}">
<title>{_e(m["title"])} · {_e(m["day"])}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header class="top">
  <div class="brand">net<b>warden</b>{demo}</div>
  <h1>{_e(m["title"])}</h1>
  <dl class="meta">
    <dt>{_e(lab["date"])}</dt><dd>{_e(m["date"])}</dd>
    <dt>{_e(lab["period"])}</dt><dd>{_e(m["period"])}</dd>
    <dt>{_e(lab["privacy"])}</dt><dd>{_e(m["privacy"])}</dd>
    <dt>{_e(lab["version"])}</dt><dd>netwarden {_e(m["version"])}</dd>
    <dt>{_e(lab["source"])}</dt><dd><a href="{_e(m["source"])}" rel="noopener noreferrer">{_e(m["source"])}</a></dd>
  </dl>
</header>
<p class="note">{_e(m["privacy_note"])}</p>
<nav class="toc" aria-label="{_e(m["contents"])}"><ol>{toc}</ol></nav>
{body}
<footer><p>{_e(m["footer"])}</p></footer>
</main>
</body>
</html>
"""


# --- Markdown --------------------------------------------------------------------------------

def _block_md(b: dict, lang: str) -> list:
    kind = b["t"]
    if kind == "p":
        return [(_md_cell(b["text"]) if b.get("cls") != "muted" else "_" + _md_cell(b["text"]) + "_"), ""]
    if kind == "h3":
        return [f"### {_md_cell(b['text'])}", ""]
    if kind == "ul":
        return [f"- {_md_cell(x)}" for x in b["items"]] + [""]
    if kind == "kv":
        return [f"- {_md_cell(k)}: **{_md_cell(v)}**" for k, v in b["rows"]] + [""]
    if kind == "score":
        return [(f"**{b['score']}** / 100 — " if b["score"] is not None else "") + _md_cell(b["text"]), ""]
    if kind == "table":
        lines = ["| " + " | ".join(_md_cell(h) for h in b["head"]) + " |",
                 "|" + "|".join("---:" if i in (b.get("num") or []) else "---" for i in range(len(b["head"]))) + "|"]
        lines += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in b["rows"]]
        return lines + [""]
    if kind == "chart":
        vals = " · ".join(f'{_md_cell(d["label"])} {_md_cell(d.get("note") or _num(d["value"], lang))}'
                          for d in b["data"])
        return [f"**{_md_cell(b['title'])}:** {vals}", ""]
    if kind == "sug":
        tags = " · ".join(_md_cell(x) for x in (b["severity_name"], b["pillar"], b["points"]) if x)
        out = [f"### {_md_cell(b['title'])}", "", f"_{tags}_", "", _md_cell(b["why"]), ""]
        for p in b["platforms"]:
            out.append(f"**{_md_cell(p['name'])}**")
            out += [f"{i}. {_md_cell(s)}" for i, s in enumerate(p["steps"], 1)] + [""]
        for r in b.get("rules") or []:
            out += [f"**{_md_cell(r['name'])}**", "", "```text", r["text"].replace("`", "'"), "```", ""]
        return out
    return []


def render_md(doc: dict) -> str:
    m = doc["meta"]
    lab = m["labels"]
    lines = [f"# {_md_cell(m['title'])}", ""]
    for k in ("date", "period", "privacy"):
        lines.append(f"- {_md_cell(lab[k])}: {_md_cell(m[k])}")
    lines += [f"- {_md_cell(lab['version'])}: netwarden {_md_cell(m['version'])}",
              f"- {_md_cell(lab['source'])}: <{m['source']}>", ""]
    if m["demo"]:
        lines += [f"> {_md_cell(m['demo_note'])}", ""]
    lines += [f"> {_md_cell(m['privacy_note'])}", ""]
    for s in doc["sections"]:
        lines += [f"## {_md_cell(s['title'])}", ""]
        for b in s["blocks"]:
            lines += _block_md(b, m["lang"])
    lines += ["---", "", _md_cell(m["footer"])]
    return "\n".join(lines) + "\n"


# --- one call: the file ----------------------------------------------------------------------

def filename(doc: dict) -> str:
    o = doc["meta"]["options"]
    return f"netwarden-report-{doc['meta']['day']}-{o['period']}d-{o['privacy']}.{o['format']}"


def generate(db, lang: str, opts: dict | None = None, env: dict | None = None, tz: tzinfo | None = None,
             now: datetime | None = None) -> tuple[bytes, str, str]:
    """(file body, content type, default file name)."""
    doc = build(db, lang, opts, env=env, tz=tz, now=now)
    fmt = doc["meta"]["options"]["format"]
    text = render_html(doc) if fmt == "html" else render_md(doc)
    return text.encode("utf-8"), CTYPES[fmt], filename(doc)
