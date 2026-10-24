#!/usr/bin/env python3
"""
netwarden - score.py: a transparent 0-100 "home network score".

Four pillars of 25 points each. Every pillar starts full and loses points for things
the data shows - every deduction is listed with its reason and, where there is one, the
suggestion that would win the points back ("how to raise it"):

  security   open risky ports (high -8 / medium -4, at most -16), risky UPnP mappings
             (-6 each, at most -12), devices talking to known-bad domains (-10 each, at
             most -20), devices bypassing the DNS filter with their own resolver (-3 each,
             at most -6)
  privacy    the home tracker grade (B -4, C -8, D -13, F -18), a cloud AI without
             redaction (-5)
  health     outages in the last 7 days (-4 each, at most -15), router packet loss >= 5%
             (-5), router latency > 50 ms (-3), DNS failures > 2% (-5), DNS slower than
             150 ms on average (-3)
  tidiness   unnamed devices (up to -12, by share), personal devices without an owner or
             room (up to -8, by share), new devices nobody reviewed (-1 each, at most -5)

A pillar netwarden cannot measure yet (no DNS source, no gateway samples, ...) is left
out and the rest is scaled to 0-100, so the score never punishes a missing sensor. A
suggestion the user dismissed ("I accept this") costs nothing. One score per local day
is kept in score_history (the health loop, or the first page view of the day) for the
weekly trend. No LLM, no network.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from netwarden import activity, i18n, naming, nethealth, store, suggestions

PILLAR_MAX = 25
PILLARS = suggestions.PILLARS
# kind -> (points per item by severity or flat, cap)
CAPS = {"port": ({"high": 8, "medium": 4, "low": 2}, 16), "upnp": (6, 12), "threat": (10, 20),
        "doh": (3, 6), "ai_redact": (5, 5), "outages_isp": (0, 0), "outages_router": (0, 0),
        # Stage Q hygiene: stale router mappings cost points; a firmware reminder and the
        # IoT-network advice do not (trackers already cost points through the grade)
        "upnp_stale": (3, 3)}
GRADE_POINTS = {"A": 0, "B": 4, "C": 8, "D": 13, "F": 18}
OUTAGE_POINTS, OUTAGE_CAP = 4, 15
NAMES_MAX, OWNERS_MAX, NEW_CAP = 12, 8, 5


def _ded(pillar: str, key: str, points: float, params: dict | None = None,
         suggestion: str | None = None) -> dict:
    return {"pillar": pillar, "key": key, "points": round(points, 1), "params": params or {},
            "suggestion": suggestion}


def deductions(db, det: dict, states: dict, health: dict) -> tuple[list, dict]:
    """([deduction], {pillar: measured?}) from suggestions.detect() + nethealth.compute()."""
    out = []
    dismissed = {sid for sid, st in states.items() if st["status"] == "dismissed"}
    used: dict = {}
    for a in det["active"]:
        if a["kind"] not in CAPS or a["id"] in dismissed:
            continue
        per, cap = CAPS[a["kind"]]
        pts = per.get(a["severity"], 0) if isinstance(per, dict) else per
        pts = min(pts, cap - used.get(a["kind"], 0))
        if pts <= 0:
            continue
        used[a["kind"]] = used.get(a["kind"], 0) + pts
        out.append(_ded(a["pillar"], a["kind"], pts, a["params"], a["id"]))
    ctx = det["context"]
    home = ctx.get("privacy_home")
    has_dns = bool(home and home["queries"])
    if home and home["tracker_queries"] and GRADE_POINTS.get(home["grade"]):
        sid = "trackers" if any(a["id"] == "trackers" for a in det["active"]) else None
        if sid not in dismissed or sid is None:
            out.append(_ded("privacy", "grade", GRADE_POINTS[home["grade"]],
                            {"grade": home["grade"]}, sid))
    # health
    outs = health["outages_7d"]
    if outs:
        sid = next((a["id"] for a in det["active"] if a["kind"].startswith("outages_")), None)
        out.append(_ded("health", "outages", min(OUTAGE_CAP, OUTAGE_POINTS * len(outs)),
                        {"n": len(outs)}, sid))
    gw, dns = health["gateway"], health["dns"]
    if gw["measured"]:
        if (gw["loss"] or 0) >= nethealth.LOSSY_GATEWAY:
            out.append(_ded("health", "loss", 5, {"pct": round(100 * gw["loss"])}))
        if (gw["avg_ms"] or 0) > nethealth.SLOW_GATEWAY_MS:
            out.append(_ded("health", "latency", 3, {"ms": round(gw["avg_ms"])}))
    if dns["fail_rate"] is not None and dns["queries"] >= nethealth.MIN_DNS_SAMPLE:
        rate = _fail_rate_outside(dns["hours"], health["outages"])
        if rate is not None and rate > 0.02:
            out.append(_ded("health", "dns_fail", 5, {"pct": round(100 * rate, 1)}))
        if (dns["avg_ms"] or 0) > nethealth.SLOW_DNS_MS:
            out.append(_ded("health", "dns_slow", 3, {"ms": round(dns["avg_ms"])}))
    # tidiness
    n = ctx.get("device_count") or 0
    if n and ctx.get("unnamed") and "names" not in dismissed:
        out.append(_ded("tidiness", "names", NAMES_MAX * ctx["unnamed"] / n,
                        {"n": ctx["unnamed"]}, "names"))
    if ctx.get("personal") and ctx.get("nobody") and "owners" not in dismissed:
        out.append(_ded("tidiness", "owners", OWNERS_MAX * ctx["nobody"] / ctx["personal"],
                        {"n": ctx["nobody"]}, "owners"))
    new = _unreviewed(db)
    if new:
        out.append(_ded("tidiness", "new_devices", min(NEW_CAP, new), {"n": new}))
    measured = {"security": has_dns or bool(store.checked_macs(db)) or bool(store.upnp_latest(db)),
                "privacy": has_dns,
                "health": gw["measured"] or dns["measured"],
                "tidiness": n > 0}
    return out, measured


def _fail_rate_outside(hours: list, outages: list) -> float | None:
    """The DNS failure rate over the hours NOT touched by a logged outage: an outage
    already costs its own points, so its failed lookups are not counted twice."""
    spans = [(o["start_ts"][:13], o["end_ts"][:13]) for o in outages]
    q = f = 0
    for h in hours:
        if not any(s <= h["hour"] <= e for s, e in spans):
            q, f = q + h["queries"], f + h["fails"]
    return f / q if q >= nethealth.MIN_DNS_SAMPLE else None


def _unreviewed(db) -> int:
    """New devices (first seen in the last 7 days) the user has not trusted, named or
    given an owner."""
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return db.execute("""SELECT COUNT(*) FROM devices d WHERE d.first_seen >= ? AND d.is_self = 0
                         AND NOT EXISTS (SELECT 1 FROM acks a WHERE a.mac = d.mac AND a.domain = '')
                         AND NOT EXISTS (SELECT 1 FROM device_labels l WHERE l.mac = d.mac)
                         AND NOT EXISTS (SELECT 1 FROM device_profiles p WHERE p.mac = d.mac)""",
                      (since,)).fetchone()[0]


def compute(db, env: dict | None = None, det: dict | None = None) -> dict:
    """{score (0-100 or None), pillars {p: {score, max, measured}}, deductions}."""
    det = det or suggestions.detect(db, env)
    states = store.suggestion_states(db)
    health = nethealth.compute(db)
    deds, measured = deductions(db, det, states, health)
    pillars = {}
    for p in PILLARS:
        lost = sum(d["points"] for d in deds if d["pillar"] == p)
        pillars[p] = {"measured": measured[p], "max": PILLAR_MAX,
                      "score": max(0, round(PILLAR_MAX - lost)) if measured[p] else None}
    m = [p for p in PILLARS if measured[p]]
    total = round(100 * sum(pillars[p]["score"] for p in m) / (PILLAR_MAX * len(m))) if m else None
    scale = 100 / (PILLAR_MAX * len(m)) if m else 0
    return {"score": total, "pillars": pillars, "scale": round(scale, 3),
            "deductions": [d for d in deds if measured[d["pillar"]]]}


def gains(db, env: dict | None, det: dict) -> dict:
    """suggestion id -> score points (0-100 scale) it would win back."""
    res = compute(db, env, det)
    out: dict = {}
    for d in res["deductions"]:
        if d["suggestion"]:
            out[d["suggestion"]] = out.get(d["suggestion"], 0) + d["points"] * res["scale"]
    return {k: max(1, round(v)) for k, v in out.items()}


def level(score: int | None) -> str:
    if score is None:
        return "idle"
    return "ok" if score >= 80 else "warn" if score >= 60 else "bad"


def today(tz=None) -> str:
    return datetime.now(timezone.utc).astimezone(tz or activity.local_tz()).date().isoformat()


def record(db, env: dict | None = None, tz=None) -> dict:
    """Store today's score (local day) in score_history; returns compute()."""
    res = compute(db, env)
    if res["score"] is not None:
        store.put_score(db, today(tz), res["score"],
                        {p: v["score"] for p, v in res["pillars"].items()})
    return res


def report(db, lang: str = i18n.DEFAULT, env: dict | None = None, tz=None) -> dict:
    """GET /api/score: the score, the breakdown, how to raise it, and the weekly trend."""
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    det = suggestions.detect(db, env)
    res = compute(db, env, det)
    day = today(tz)
    hist = store.score_history(db, (datetime.fromisoformat(day) - timedelta(days=14)).date().isoformat())
    if res["score"] is not None and not any(h["day"] == day for h in hist):
        store.put_score(db, day, res["score"], {p: v["score"] for p, v in res["pillars"].items()})
        hist.append({"day": day, "score": res["score"], "parts": {}, "ts": store.now()})
    else:
        hist = [h if h["day"] != day else {**h, "score": res["score"]} for h in hist]
    week_ago = (datetime.fromisoformat(day) - timedelta(days=7)).date().isoformat()
    # a week ago, or the newest day before that (hist is oldest first)
    past = next((h for h in reversed(hist) if h["day"] <= week_ago), None)
    trend = [{"day": h["day"], "score": h["score"], "level": level(h["score"])}
             for h in hist if h["day"] >= week_ago]
    delta = res["score"] - past["score"] if past and res["score"] is not None else None
    names = naming.display_names(db, lang)   # a nameless device is not named by its MAC
    sug = {i["id"]: i for i in suggestions.localize_many(det["active"], lang, names)}
    still_open = {i["id"] for i in suggestions.with_status(det, store.suggestion_states(db))["open"]}
    scale = res["scale"]
    items = []
    for d in res["deductions"]:
        if d["params"].get("name") in names:
            d = {**d, "params": {**d["params"], "name": names[d["params"]["name"]]}}
        items.append({**d, "gain": max(1, round(d["points"] * scale)),
                      "text": i18n.t("score.item." + d["key"], lang, **_fmt(d, sug)),
                      "suggestion_title": sug[d["suggestion"]]["title"]
                      if d["suggestion"] in sug else None})
    items.sort(key=lambda d: -d["points"])
    raise_ = []
    seen = set()
    for d in items:
        if d["suggestion"] in still_open and d["suggestion"] in sug and d["suggestion"] not in seen:
            seen.add(d["suggestion"])
            raise_.append({"id": d["suggestion"], "title": d["suggestion_title"], "gain": d["gain"]})
    return {"score": res["score"], "level": level(res["score"]),
            "summary": i18n.t("score.summary." + level(res["score"]), lang, score=res["score"]),
            "pillars": [{"key": p, "name": i18n.t("sug.pillar." + p, lang), **res["pillars"][p]}
                        for p in PILLARS],
            "deductions": items, "raise": raise_[:5],
            "trend": trend, "delta": delta, "today": day,
            "note": i18n.t("score.note", lang)}


def _fmt(d: dict, sug: dict) -> dict:
    s = sug.get(d["suggestion"])
    return {**d["params"], "title": s["title"] if s else ""}
