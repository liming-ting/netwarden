#!/usr/bin/env python3
"""
netwarden - family_report.py: the printable weekly report (GET /report/weekly?lang=).

One self-contained, print-friendly HTML page - highlights (this week vs last week),
estimated screen time per person, bedtime, privacy and security - rendered on the
server with EVERY value escaped (device names, owners and announced names are hostile
text). Styles: /static/report.css (A4 print CSS, a CJK-safe system font stack, no web
fonts); the only script is /static/report.js (the Print button + the saved theme), so
the page works under the dashboard's strict CSP and fully offline. "Save as PDF" is the
browser's own print dialog: nothing is uploaded anywhere.
"""
from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from html import escape

from netwarden import activity, alerts, bedtime, i18n, naming, privacy, screentime, store, weekly


def _e(v) -> str:
    return escape("" if v is None else str(v), quote=True)


def _day(iso: str, tz: tzinfo) -> str:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(tz).strftime("%Y-%m-%d")


def _security_lines(r: dict, lang: str) -> list:
    """One plain line per open finding (already localized alerts.compute result)."""
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    sep = t("list_sep")
    out = [f"{x['device']} → {x['domain']}: {x['label']}" for x in r["threats"]]
    out += [f"{x['name']}: {x['port']} {x['service']} ({x['risk_name']})" for x in r["exposure"]]
    out += [x["text"] for x in r.get("upnp", [])]
    # bedtime hits are not listed again here: the report has its own bedtime section
    out += [x["text"] for x in r.get("unusual_hours", [])]
    out += [x["text"] for x in r.get("bandwidth_spikes", [])]
    out += [x["text"] for x in r.get("visibility", [])]
    out += [t("rep.new_device", name=x["name"]) for x in r["new_devices"]]
    out += [f"{x['name']}: {t('ui.started_using')} {sep.join(x['new_services'])}"
            for x in r["behavior_changes"]]
    return out


def _bars(rows: list, lang: str) -> str:
    """Per-day minutes as a small table with CSS bars (print-safe)."""
    top = max([r["minutes"] for r in rows] + [1])
    names = activity.weekday_names(lang)
    cells = []
    for r in rows:
        d = datetime.strptime(r["date"], "%Y-%m-%d")
        cells.append(f'<tr><th scope="row">{_e(names[d.weekday()])} {_e(d.strftime("%m-%d"))}</th>'
                     f'<td class="bv"><i style="width:{100 * r["minutes"] / top:.1f}%"></i></td>'
                     f'<td class="num">{_e(screentime.duration(r["minutes"], lang))}</td></tr>')
    return f'<table class="days">{"".join(cells)}</table>'


def render(db, lang: str, tz: tzinfo | None = None, hours: float = 24,
           version: str = "", now: datetime | None = None, base: str = "") -> str:
    lang = i18n.normalize(lang)
    tz = tz or activity.local_tz()
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    sep = t("list_sep")
    explicit, now = now, now or datetime.now(timezone.utc)
    st = screentime.report(db, lang, 7, tz=tz, now=explicit)
    wk = weekly.report(db, lang, tz=tz, now=explicit)
    # display names: a nameless device reads "Phone · Mom" here too, never its bare MAC
    al = alerts.localize(alerts.compute(db, recent_hours=hours), lang, naming.display_names(db, lang))
    pv = privacy.report(db, hours=hours, lang=lang)
    bt = bedtime.report(db, lang, tz=tz, now=explicit)
    demo = store.is_demo(db)
    v = f"?v={_e(version)}" if version else ""
    b = _e(base)   # Stage H: the Home Assistant ingress prefix ("" at /)

    people = []
    # data-l: the column name, shown in front of the value when a phone stacks the table
    cols = {k: _e(t("rep.th_" + k)) for k in ("week", "avg", "today")}
    for m in st["members"]:
        who = m["owner"] or t("rep.shared")
        apps = sep.join(f'{s["name"]} ({screentime.duration(s["minutes"], lang)})'
                        for s in m["top_services"][:3]) or "—"
        people.append(f'<tr><th scope="row">{_e(who)}<div class="sub">'
                      f'{_e(sep.join(d["name"] for d in m["devices"]))}</div></th>'
                      f'<td class="num" data-l="{cols["week"]}">{_e(screentime.duration(m["minutes"], lang))}</td>'
                      f'<td class="num" data-l="{cols["avg"]}">{_e(screentime.duration(m["avg_minutes"], lang))}</td>'
                      f'<td class="num" data-l="{cols["today"]}">{_e(screentime.duration(m["today_minutes"], lang))}</td>'
                      f'<td>{_e(apps)}</td></tr>')
    screen = (f'<table class="tbl"><thead><tr><th>{_e(t("rep.th_person"))}</th>'
              f'<th class="num">{_e(t("rep.th_week"))}</th><th class="num">{_e(t("rep.th_avg"))}</th>'
              f'<th class="num">{_e(t("rep.th_today"))}</th><th>{_e(t("rep.th_top"))}</th></tr></thead>'
              f'<tbody>{"".join(people)}</tbody></table>'
              if people else f'<p class="muted">{_e(t("fam.none"))}</p>')
    cats = sep.join(f'{c["name"]} {screentime.duration(c["minutes"], lang)}' for c in st["categories"])

    hits = [h for r in bt["rules"] for h in r["hits"]]
    if not bt["rules"]:
        bed = f'<p class="muted">{_e(t("rep.bedtime_no_rules"))}</p>'
    elif not hits:
        bed = f'<p class="muted">{_e(t("rep.bedtime_none"))}</p>'
    else:
        bed = "<ul>" + "".join(f"<li>{_e(h['text'])}</li>" for h in hits[:12]) + "</ul>"

    home = pv.get("home") or {}
    worst = "".join(f'<li>{_e(w["name"])}: {_e(w["grade"])} — {_e(w["reason"])}</li>'
                    for w in (pv.get("worst") or [])[:3])
    priv = (f'<p><span class="grade g-{_e(home.get("grade"))}">{_e(home.get("grade"))}</span> '
            f'{_e(home.get("line", ""))}</p>' + (f"<ul>{worst}</ul>" if worst else "")
            if home.get("tracker_queries") else f'<p class="muted">{_e(t("app.priv.none"))}</p>')

    # Stage P: arrivals per person this week - only people who turned presence on
    pres_lines = [x["text"] for x in (al.get("family") or {}).get("presence") or []]
    pres = (f'<section><h2>{_e(t("rep.presence"))}</h2><ul>'
            + "".join(f"<li>{_e(x)}</li>" for x in pres_lines) + "</ul></section>"
            if pres_lines else "")

    sec_lines = _security_lines(al, lang)
    sec = ("<ul>" + "".join(f"<li>{_e(x)}</li>" for x in sec_lines[:15]) + "</ul>"
           + (f'<p class="muted">{_e(t("wow.more", n=len(sec_lines) - 15))}</p>'
              if len(sec_lines) > 15 else "")
           if sec_lines else f'<p class="ok">{_e(t("rep.security_clear"))}</p>')

    span = t("rep.range", start=_day(wk["this"]["start"], tz), end=_day(wk["this"]["end"], tz))
    gen = t("rep.generated", when=now.astimezone(tz).strftime("%Y-%m-%d %H:%M"), tz=st["tz"])
    return f"""<!doctype html>
<html lang="{_e(lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>{_e(t("rep.title"))} · netwarden</title>
<link rel="icon" href="{b}/static/icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="{b}/static/report.css{v}">
<script src="{b}/static/report.js{v}" defer></script>
</head>
<body>
<nav class="bar noprint">
  <a href="{b}/#/family">← {_e(t("rep.back"))}</a>
  <button type="button" id="print" class="btn">{_e(t("rep.print"))}</button>
</nav>
<main class="sheet">
  <header class="head">
    <div class="brand">net<b>warden</b></div>
    <h1>{_e(t("rep.title"))}</h1>
    <p class="sub">{_e(span)} · {_e(gen)}{" · " + _e(t("ui.demo_badge")) if demo else ""}</p>
  </header>
  <p class="note">{_e(t("fam.note"))}</p>
  <section><h2>{_e(t("rep.highlights"))}</h2>
    <ul>{"".join(f"<li>{_e(h)}</li>" for h in wk["highlights"])}</ul></section>
  <section><h2>{_e(t("rep.screen"))}</h2>
    <p>{_e(t("rep.screen_total", dur=screentime.duration(st["minutes"], lang)))}{(" · " + _e(cats)) if cats else ""}</p>
    {screen}
    <h3>{_e(t("rep.by_day"))}</h3>{_bars(st["by_day"], lang)}</section>
  <section><h2>{_e(t("rep.bedtime"))}</h2>{bed}</section>
  {pres}
  <section><h2>{_e(t("app.nav.privacy"))}</h2>{priv}</section>
  <section><h2>{_e(t("app.nav.security"))}</h2>{sec}</section>
  <footer><p>{_e(t("fam.method"))}</p><p>{_e(t("rep.footer"))}</p></footer>
</main>
</body>
</html>
"""
