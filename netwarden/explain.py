"""
netwarden - explain.py: "Why this alert?" for every alert kind (Stage Q).

Deterministic and local - no LLM. For one alert it states:

    rule       what the rule watches, in one plain sentence
    facts      the actual data points behind THIS alert ("1.8 GB in the last 24 h ...")
    threshold  when the rule fires - with the numbers of the sensitivity in force
               (tuning.py: "less sensitive" uses the stricter numbers, and says so)
    tune       {kind, mac}: where "Tune this alert" points

alerts.localize() attaches it to every alert as "why" (the dashboard's alert rows, the
inbox and the device drawer show it); brain.py adds the English text() of the alert the
user asks about to the AI context (scrubbed by the redactor for a cloud model).

    explain(kind, item, lang, window) -> {rule, facts, threshold, level, tune, ref}
    text(why) -> one paragraph;  find(db, kind, mac, key, hours) -> (kind, item) or None
"""
from __future__ import annotations

from netwarden import activity, i18n, nethealth, tuning, visibility

# alerts.compute() section -> inbox / tuning kind
SECTIONS = {"threats": "threat", "exposure": "exposure", "upnp": "upnp", "outage": "outage",
            "visibility": "visibility", "unusual_hours": "night", "bedtime": "bedtime",
            "bandwidth_spikes": "spike", "new_devices": "new", "behavior_changes": "change"}
KINDS = tuple(SECTIONS.values())


def _bytes(n) -> str:
    from netwarden.brain import human_bytes   # brain imports alerts imports this module
    return human_bytes(n or 0)


def _short(ts: str) -> str:
    from netwarden.alerts import _short as short
    return short(ts)


def _gb(n: float) -> str:
    return f"{n / 1e9:g}"


def _facts(kind: str, a: dict, lang: str, w: dict) -> list:
    t = lambda key, **kw: i18n.t("why.data." + key, lang, **kw)  # noqa: E731
    h = int(w.get("recent_hours") or 24)
    if kind == "threat":
        from netwarden import threatintel   # (the label in `lang`, also for a canonical item)
        label = threatintel.localize(a, lang)["label"] if a.get("indicator") else a.get("label")
        return [t("threat", domain=a["domain"], count=a["count"], h=h, label=label or "",
                  sev=i18n.t("sev." + ("malicious" if a["severity"] == "malicious" else "high_risk"),
                             lang))]
    if kind == "exposure":
        out = [t("exposure", port=a["port"], service=a.get("service") or "?", ip=a.get("ip") or "?",
                 when=_short(a.get("checked_ts") or ""))]
        if a.get("new"):
            out.append(t("exposure_new"))
        return out
    if kind == "upnp":
        out = [t("upnp", proto=a["protocol"], ext=a["external_port"], ip=a["internal_client"],
                 port=a["internal_port"], when=_short(a.get("first_seen") or ""))]
        if a.get("risky"):
            out.append(t("upnp_risky", port=a["risky_port"], service=a.get("service") or "?"))
        if a.get("new"):
            out.append(t("upnp_new"))
        return out
    if kind == "visibility":
        if a.get("kind") == "quiet":
            return [t("quiet", h=a.get("quiet_hours", 0), active=a.get("active_hours", 0))]
        out = []
        for r in a.get("resolvers") or []:
            if r["count"] > r["blocked"]:
                out.append(t("bypass", resolver=f"{r['domain']} ({r['provider']})", n=r["count"],
                             h=h, blocked=r["blocked"]))
        if (a.get("canary") or {}).get("answered"):
            out.append(t("canary", domain=visibility.CANARY))
        return out
    if kind == "night":
        return [t("night", n=a["night_queries"], window=a["window"]),
                t("night_base", busy=a.get("baseline_nights", 0), days=a.get("baseline_days", 0))]
    if kind == "bedtime":
        from netwarden import bedtime, screentime
        return [t("bedtime", dur=screentime.duration(a["minutes"], lang), window=a["window"],
                  night=bedtime.night_label(a["night"], lang), rule=a.get("rule_name") or "—")]
    if kind == "spike":
        return [t("spike", total=_bytes(a["total"]), h=int(a.get("hours") or h),
                  rx=_bytes(a["rx_bytes"]), tx=_bytes(a["tx_bytes"]), typical=_bytes(a["typical"]),
                  ratio=round(a["ratio"]))]
    if kind == "change":
        from netwarden import services
        names = [services.service_name(s, lang) for s in a.get("new_service_ids") or []]
        return [t("change", services=i18n.t("list_sep", lang).join(names) or "—", h=h,
                  d=int(w.get("baseline_days") or 7))]
    if kind == "new":
        return [t("new", when=_short(a.get("first_seen") or ""), ip=a.get("ip") or "?")]
    if kind == "outage":
        return [t("outage", when=nethealth.when_text(a, lang),
                  dur=nethealth.duration_text(a["minutes"], lang),
                  gw=a.get("gateway_min", 0), dns=a.get("dns_min", 0),
                  cause=i18n.t("health.cause." + a["cause"], lang))]
    return []


def _threshold(kind: str, a: dict, lang: str, less: bool) -> str:
    from netwarden import alerts   # thresholds live next to their rules
    t = lambda key, **kw: i18n.t("why.threshold." + key, lang, **kw)  # noqa: E731
    if kind in ("threat", "exposure", "upnp", "visibility", "new"):
        return t(kind + ("_less" if less else ""), quiet=visibility.QUIET_HOURS,
                 active=visibility.HOURLY_MIN)
    if kind == "night":
        return t("night", n=tuning.LESS_NIGHT_QUERIES if less else activity.NIGHT_MIN_QUERIES,
                 days=a.get("baseline_days") or activity.BASELINE_DAYS)
    if kind == "bedtime":
        m = a.get("min_minutes") or 0
        return t("bedtime", min=2 * m if less else m)
    if kind == "spike":
        return t("spike", ratio=int(tuning.LESS_SPIKE_RATIO if less else alerts.SPIKE_RATIO),
                 gb=_gb(tuning.LESS_SPIKE_BYTES if less else alerts.SPIKE_MIN_BYTES),
                 days=alerts.SPIKE_BASELINE_DAYS)
    if kind == "change":
        return t("change", n=tuning.LESS_CHANGE_SERVICES if less else 1)
    if kind == "outage":
        return t("outage", min=tuning.LESS_OUTAGE_MIN if less else nethealth.MIN_OUTAGE_MIN)
    return ""


def explain(kind: str, item: dict, lang: str, window: dict | None = None) -> dict:
    """The explanation of one canonical alert (an alerts.compute() item)."""
    lang = i18n.normalize(lang)
    w = window or {}
    lvl = item.get("level") or "normal"
    less = lvl == "less"
    rule_key = kind
    if kind == "visibility":
        rule_key = "quiet" if item.get("kind") == "quiet" else "bypass"
    mac = item.get("mac")
    return {"rule": i18n.t("why.rule." + rule_key, lang),
            "facts": [f for f in _facts(kind, item, lang, w) if f],
            "threshold": _threshold(kind, item, lang, less),
            "level": lvl, "level_text": i18n.t("why.level_less", lang) if less else "",
            "tune": {"kind": kind, "mac": mac if kind in tuning.DEVICE_KINDS
                     and mac and mac != nethealth.NETWORK_KEY else None},
            # what "Ask AI about this alert" sends back (find() looks the alert up again)
            "ref": {"kind": kind, "mac": mac or None, "key": ref_key(kind, item)}}


def text(why: dict) -> str:
    """One paragraph: rule, facts, threshold (and the sensitivity note)."""
    parts = [why["rule"], *why["facts"], why["threshold"], why.get("level_text") or ""]
    return " ".join(p.strip() for p in parts if p and p.strip())


def ref_key(kind: str, item: dict) -> str:
    """The ack key an inbox reference uses for this alert (alerts.change_key etc.)."""
    if kind == "threat":
        return item.get("domain", "")
    if kind == "new":
        from netwarden import alerts
        return alerts.NEW_KEY
    if kind == "change":
        from netwarden import alerts
        return alerts.change_key(item)
    return item.get("ack", "")


def find(db, kind: str, mac: str | None, key: str, hours: float = 24) -> tuple | None:
    """The alert (kind, canonical item, window) the page refers to, or None - for the AI
    context of "Ask AI about this alert"."""
    from netwarden import alerts
    if kind not in KINDS or not isinstance(key, str):
        return None
    res = alerts.compute(db, recent_hours=hours)
    for section, k in SECTIONS.items():
        if k != kind:
            continue
        for a in res.get(section) or []:
            if (a.get("mac") or None) == (mac or None) and ref_key(kind, a) == key:
                return kind, a, res["window"]
    return None
