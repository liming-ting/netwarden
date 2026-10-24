#!/usr/bin/env python3
"""
netwarden - threatintel.py: flag devices talking to known-bad or high-risk domains.

Local + deterministic. A small CURATED starter list ships in the box and works fully
offline. You can OPTIONALLY widen coverage by pulling a public threat-intel feed:

    python3 -m netwarden.threatintel --update "URL"    # download a hosts / domain list
    python3 -m netwarden.threatintel --db data/demo.db # scan a database and report

The update is download-only: it fetches a public blocklist (like AdGuard fetching an
ad list) and never uploads anything about you. It is OFF unless you run --update.

abuse.ch's URLhaus host file (the list this was built around) is no longer public: since
abuse.ch moved to authenticated access, its download links contain a personal Auth-Key
(free account at auth.abuse.ch; the old key-less URL answers HTTP 410). So there is no
built-in feed URL any more: a bare --update explains how to get your own link, and the
URL you pass is treated as a secret (never printed, never stored - the cache keeps only
its host name). Terms: https://abuse.ch/terms-of-use/ (THIRD_PARTY_NOTICES.md).

Honesty matters here, so we separate two severities and never auto-block:
  - "malicious": the domain is on a recognized malware/phishing/C2 list.
  - "high-risk": the domain belongs to a category with a documented poor security
    track record (e.g. cheap IoT camera clouds repeatedly hit by serious CVEs).
We flag and explain; acting on it is always the user's call.

Note (honest limitation): we currently scan each device's TOP domains (the heavy
hitters), not every single lookup, so a rare low-volume beacon could slip through.
Widening this is a later improvement.
"""
from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

from netwarden import i18n, store

CACHE = store.DATA_DIR / "threatfeed.json"

SEV_MALICIOUS = "malicious"
SEV_HIGH_RISK = "high-risk"

# Where a URLhaus user gets the personal Auth-Key that their download links need.
ABUSECH_AUTH_URL = "https://auth.abuse.ch/"
MAX_FEED_BYTES = 32 * 1024 * 1024   # URLhaus' host file is a few MB; refuse anything huge

# domain suffix -> (severity, indicator id). The short label and the plain-language
# "why it matters" live in netwarden/locales/*.json as threat.<id>.label / .why.
BUNDLED = {
    # --- recognized test indicator (harmless; lets you verify the feature works) ---
    "testsafebrowsing.appspot.com": (SEV_MALICIOUS, "safebrowsing_test"),

    # --- high-risk IoT clouds (documented history of serious vulnerabilities) ---
    "xmeye.net": (SEV_HIGH_RISK, "xmeye"),
    "secu100.net": (SEV_HIGH_RISK, "secu100"),
    "xiongmai.com": (SEV_HIGH_RISK, "xiongmai"),
}
FEED = "feed"  # indicator id of every feed-derived entry (one generic text)

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")
_IP_RE = re.compile(r"^[0-9.]+$")
_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost"}


# --- the curated + optional-feed indicator table ----------------------------

def _load_feed() -> dict:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}
    return {}


def indicators() -> dict:
    """Bundled list merged with any cached feed update (feed entries are 'malicious')."""
    merged = dict(BUNDLED)
    for dom in _load_feed().get("domains", []):
        d = dom.lower().strip().strip(".")
        if d and d not in merged:
            merged[d] = (SEV_MALICIOUS, FEED)
    return merged


def match(domain: str, table: dict | None = None):
    """Return (severity, indicator_id) if the domain matches an indicator, else None.
    Longest matching suffix wins."""
    table = table if table is not None else indicators()
    d = (domain or "").lower().strip().strip(".")
    best = None
    best_len = -1
    for suffix, meta in table.items():
        if d == suffix or d.endswith("." + suffix):
            if len(suffix) > best_len:
                best, best_len = meta, len(suffix)
    return best


def describe(indicator: str, lang: str = "en"):
    """(label, why) for an indicator id, in `lang` (unknown ids get the feed text)."""
    key = indicator if i18n.has(f"threat.{indicator}.label") else FEED
    return i18n.t(f"threat.{key}.label", lang), i18n.t(f"threat.{key}.why", lang)


def check(domain: str, table: dict | None = None, lang: str = "en"):
    """Return (severity, label, why) if the domain matches an indicator, else None."""
    m = match(domain, table)
    if not m:
        return None
    sev, ind = m
    return (sev, *describe(ind, lang))


def localize(finding: dict, lang: str) -> dict:
    """A copy of one finding with label/why in `lang` (for the web/API edge)."""
    label, why = describe(finding.get("indicator", FEED), lang)
    return {**finding, "label": label, "why": why}


def severity_tag(severity: str, lang: str) -> str:
    return i18n.t("sev.malicious" if severity == SEV_MALICIOUS else "sev.high_risk", lang)


def scan_snapshot(snap: dict) -> list:
    """Given a brain.snapshot(), return threat findings (most severe first).
    label/why are canonical English; localize() translates them for display."""
    table = indicators()
    order = {SEV_MALICIOUS: 0, SEV_HIGH_RISK: 1}
    findings = []
    for dev in snap.get("devices", []):
        for td in dev.get("top_domains", []):
            m = match(td["domain"], table)
            if m:
                sev, ind = m
                label, why = describe(ind)
                findings.append({
                    "device": dev.get("name") or dev.get("vendor") or dev.get("mac") or "?",
                    "mac": dev.get("mac"),
                    "ips": dev.get("ips", []),
                    "domain": td["domain"],
                    "count": td.get("count"),
                    "severity": sev,
                    "indicator": ind,
                    "label": label,
                    "why": why,
                })
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


# --- optional public-feed update (download-only) ----------------------------

def _parse_feed_text(text: str) -> list:
    """Extract domains from a hosts-format or plain-domain-list blocklist."""
    out, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!;":
            continue
        tok = line.split()[-1].lower().strip().strip(".")
        if (tok and tok not in _SKIP and "." in tok
                and _DOMAIN_RE.match(tok) and not _IP_RE.match(tok)
                and ".." not in tok and not tok.startswith("-")):
            if tok not in seen:
                seen.add(tok)
                out.append(tok)
    return out


class FeedError(RuntimeError):
    """A failed --update. `kind` picks the localized sentence (threat.update_<kind>):
    bad_url | auth (HTTP 401/403/410: the link needs a personal Auth-Key) | empty |
    failed. `detail` is already sanitized: it never contains the URL."""

    def __init__(self, kind: str, detail: str = "", code: int | None = None):
        super().__init__(detail or kind)
        self.kind, self.detail, self.code = kind, detail, code

    def message(self, lang: str) -> str:
        return i18n.t(f"threat.update_{self.kind}", lang, code=self.code or "",
                      auth=ABUSECH_AUTH_URL, error=self.detail)


def update_from_feed(url: str, timeout: float = 30) -> int:
    """Download a hosts-format / plain-domain blocklist and cache the domains. Returns
    the count. The URL may carry a personal key (URLhaus puts the Auth-Key in the path),
    so it never appears in errors or in the cache file. A download that holds no domain
    (an error or login page) leaves the previous cache untouched. Raises FeedError."""
    from urllib.parse import urlsplit
    from netwarden import health
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise FeedError("bad_url")
    secrets = [url, parts.path, parts.query, parts.password or "", parts.username or ""]
    secrets += [seg for seg in parts.path.split("/") if len(seg) >= 8]
    req = urllib.request.Request(url, headers={"user-agent": "netwarden/0.1 (+local)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_FEED_BYTES + 1)
    except urllib.error.HTTPError as e:
        e.close()
        if e.code in (401, 403, 410):
            raise FeedError("auth", code=e.code) from None
        raise FeedError("failed", f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        raise FeedError("failed", health.sanitize_error(reason, secrets)) from None
    if len(data) > MAX_FEED_BYTES:
        raise FeedError("failed", f"> {MAX_FEED_BYTES >> 20} MB")
    domains = _parse_feed_text(data.decode("utf-8", "ignore"))
    if not domains:
        raise FeedError("empty")
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CACHE.with_suffix(".tmp")
    tmp.write_text(json.dumps({"source": parts.hostname, "count": len(domains),
                               "domains": domains}, ensure_ascii=False), encoding="utf-8")
    tmp.replace(CACHE)
    return len(domains)


# --- CLI --------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="netwarden threat-intel: flag devices talking to known-bad/high-risk domains.")
    ap.add_argument("--db", default=None, help="database to scan (default: the real DB)")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--update", nargs="?", const="", default=None, metavar="URL",
                    help="download a hosts-format threat list (e.g. your personal URLhaus "
                         "hostfile link) to widen coverage (download-only)")
    ap.add_argument("--lang", default=None,
                    help=f"report language code (default {i18n.DEFAULT}); one of "
                         + ", ".join(i18n.CODES))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang)

    if args.update is not None:
        if not args.update.strip():   # no built-in feed any more: say how to get one
            print(i18n.t("threat.update_need_url", lang, auth=ABUSECH_AUTH_URL))
            return 2
        try:
            n = update_from_feed(args.update)
        except FeedError as e:
            print(e.message(lang))
            return 2 if e.kind == "bad_url" else 1
        print(i18n.tn("threat.update_ok", n, lang))
        return 0

    from netwarden import brain, store
    db = store.connect(args.db or str(store.DEFAULT_DB))
    snap = brain.snapshot(db, hours=args.hours)
    findings = snap.get("threats", [])
    if not findings:
        print(i18n.t("threat.cli_none", lang))
        return 0
    print(i18n.t("threat.cli_found", lang, n=len(findings)) + "\n")
    for f in (localize(f, lang) for f in findings):
        tag = severity_tag(f["severity"], lang)
        print(f"{tag}  {f['device']} → {f['domain']}  ({f['label']})")
        print(f"    {f['why']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
