"""
netwarden - export.py: take your data with you (no LLM involved).

    devices_csv(db, lang)  -> bytes   one row per known device; UTF-8 with BOM so Excel
                                      shows Chinese correctly; formula-injection safe
    report_md(db, lang)    -> str     the localized weekly digest + a device inventory

Served by the dashboard as downloads: GET /api/export/devices.csv?lang= and
GET /api/export/report.md?lang=. Everything is computed over the last EXPORT_DAYS days.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from netwarden import alerts, brain, cache, devicetype, i18n, naming, services, store

EXPORT_DAYS = 7
# A spreadsheet treats a cell starting with one of these as a formula (=HYPERLINK(...),
# +cmd|..., @SUM...). User text (labels, hostnames from DHCP) is hostile input.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")
_FULLWIDTH = str.maketrans("＝＋－＠", "=+-@")


def _since(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


WINDOW_TTL = 600   # seconds: a week-long export may lag new DNS events by a few minutes


def _window(db, days: float = EXPORT_DAYS) -> dict:
    """The language-independent inputs of an export window (DNS activity per device, threat
    hits, byte totals), shared through netwarden.cache: exporting again - or in another
    language - does not rescan a week of events. The result is kept for WINDOW_TTL even
    while new events arrive (a week of history barely moves in ten minutes), so
    runner.Warmer can have it ready before the first click - it is the slow part of an
    export (a week of events on a big home)."""
    def compute():
        since = _since(days)
        return {
            "activity": {r["device_mac"]: r for r in store.device_activity(db, since=since, top=8)
                         if r["device_mac"]},
            "threats": alerts.recent_threats(db, since),
            "bw": store.bandwidth_totals(db, since),   # totals only: no rates needed here
        }
    return cache.memo(db, "export.window", (days,), ttl=WINDOW_TTL, loose=True, compute=compute)


def inventory(db, lang: str, days: float = EXPORT_DAYS) -> list:
    """Every known device with its 7-day activity: one dict per device, newest seen first."""
    lang = i18n.normalize(lang)
    labels = store.get_labels(db)
    acks = store.list_acks(db)
    win = _window(db, days)
    activity, bw = win["activity"], win["bw"]
    threats: dict = {}
    for t in win["threats"]:
        if not store.is_muted(acks, t["mac"], t["domain"]):
            threats[t["mac"]] = threats.get(t["mac"], 0) + 1
    types = devicetype.classify_all(db)
    profiles = store.get_profiles(db)
    names = naming.display_names(db, lang)
    out = []
    for r in db.execute("SELECT * FROM devices ORDER BY last_seen DESC, mac"):
        mac = r["mac"]
        label = (labels.get(mac) or {}).get("label")
        act = activity.get(mac)
        domains = [t["domain"] for t in act["top_domains"]] if act else []
        out.append({
            "name": names.get(mac) or mac,
            "label": label or "",
            "vendor": r["vendor"] or "",
            "ip": r["ip"] or "",
            "mac": mac,
            "type": devicetype.type_name((types.get(mac) or {}).get("type"), lang),
            "owner": (profiles.get(mac) or {}).get("owner") or "",
            "room": (profiles.get(mac) or {}).get("room") or "",
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "services": services.services_for(domains, lang),
            "queries": act["queries"] if act else 0,
            "threats": threats.get(mac, 0),
            "rx_bytes": bw[mac]["rx_bytes"] if mac in bw else None,
            "tx_bytes": bw[mac]["tx_bytes"] if mac in bw else None,
        })
    return out


COLUMNS = ("name", "label", "vendor", "ip", "mac", "type", "owner", "room", "first_seen",
           "last_seen", "services",
           "queries", "threats", "rx_bytes", "tx_bytes")


def safe_cell(value) -> str | int:
    """Numbers stay numbers; text that a spreadsheet would run as a formula gets a
    leading apostrophe (the OWASP-recommended neutralization)."""
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    # Spreadsheets skip leading blanks and treat full-width ＝＋－＠ like their ASCII forms.
    lead = text.lstrip("  　").translate(_FULLWIDTH)
    return "'" + text if text.startswith(_FORMULA_START) or lead.startswith(_FORMULA_START) else text


def devices_csv(db, lang: str) -> bytes:
    lang = i18n.normalize(lang)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow([i18n.t("export.col." + c, lang, days=EXPORT_DAYS) for c in COLUMNS])
    sep = i18n.t("list_sep", lang)
    for d in inventory(db, lang):
        row = {**d, "services": sep.join(d["services"])}
        w.writerow([safe_cell(row[c]) for c in COLUMNS])
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _md_cell(value) -> str:
    """Text safe inside a Markdown table cell: no pipes, no line breaks, no raw HTML."""
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    for a, b in (("\\", "\\\\"), ("|", "\\|"), ("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                 ("`", "\\`"), ("*", "\\*"), ("_", "\\_"), ("[", "\\["), ("]", "\\]")):
        text = text.replace(a, b)
    return text or "—"


def report_md(db, lang: str, hours: float = 24) -> str:
    """Localized Markdown report: the digest (same text as the weekly cron) + inventory."""
    lang = i18n.normalize(lang)
    tr = lambda key, **kw: i18n.t("export." + key, lang, **kw)  # noqa: E731
    now = datetime.now(timezone.utc)
    lines = [f"# {tr('report_title')}", "",
             tr("generated", when=now.strftime("%Y-%m-%d %H:%M UTC")), ""]
    if store.is_demo(db):
        lines += [f"> {tr('demo_note')}", ""]
    digest = alerts.render_digest(alerts.compute(db, recent_hours=hours), lang,
                                  naming.display_names(db, lang))
    digest = digest.replace("```", "'''")   # a device name must not close the fence
    lines += [f"## {tr('digest_heading')}", "", "```text", digest, "```", ""]
    inv = inventory(db, lang)
    has_bw = any(d["rx_bytes"] is not None for d in inv)
    cols = ["name", "type", "owner", "room", "vendor", "ip", "mac", "last_seen", "services", "threats"]
    if has_bw:
        cols += ["rx_bytes", "tx_bytes"]
    head = {"rx_bytes": "rx", "tx_bytes": "tx"}   # human units here, raw bytes in the CSV
    lines += [f"## {i18n.tn("export.inventory_heading", len(inv), lang)}", ""]
    lines.append("| " + " | ".join(_md_cell(i18n.t("export.col." + head.get(c, c), lang,
                                                    days=EXPORT_DAYS)) for c in cols) + " |")
    lines.append("|" + "|".join("---" for _ in cols) + "|")
    sep = i18n.t("list_sep", lang)
    for d in inv:
        cells = []
        for c in cols:
            v = d[c]
            if c == "services":
                v = sep.join(v)
            elif c == "last_seen":
                v = (v or "")[:16].replace("T", " ")
            elif c in ("rx_bytes", "tx_bytes"):
                v = brain.human_bytes(v) if v is not None else None
            cells.append(_md_cell(v))
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", tr("footer")]
    return "\n".join(lines) + "\n"


def filename(kind: str, ext: str) -> str:
    return f"netwarden-{kind}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.{ext}"
