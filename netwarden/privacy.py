#!/usr/bin/env python3
"""
netwarden - privacy.py: who is tracking each device, and does your DNS filter stop it?

Classifies the domains each device looked up into tracker categories, using a bundled,
hand-curated list of well-known tracker domains (netwarden's own compilation - not a
copy of any third-party blocklist) plus an optional user file data/trackers_custom.txt:

    # one entry per line: domain [category] [company ...]   (category defaults to "other")
    metrics.example-tv.com telemetry ExampleTV
    tracker.example.net

Categories (stable keys; text is privacy.cat.<key> in netwarden/locales/*.json):
    ads        advertising networks and ad exchanges
    analytics  usage analytics, attribution and session recording
    telemetry  device / vendor / app phone-home (diagnostics, crash and usage logs)
    social     social-network pixels, SDKs and share widgets
    other      fingerprinting, data brokers, anything else

Matching works like services.py: a domain matches an entry when it equals it or ends
with "." + entry; the LONGEST entry wins. Each entry is also the unit of a suggested
block rule (AdGuard ||entry^ also covers its subdomains).

Per device (over a time window) we report tracker lookups, their share of all lookups,
the split by category, the top tracker entries with the company behind them, how many
your DNS filter already blocked (dns_events.blocked) and a privacy grade A-F with a
one-line reason. Suggestions only: netwarden prints copyable rules for still-unblocked
trackers; it never changes AdGuard / Pi-hole itself.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import cache, i18n, store

CUSTOM_FILE = store.DATA_DIR / "trackers_custom.txt"   # optional: the user's own additions

CATEGORIES = ("ads", "analytics", "telemetry", "social", "other")

# domain -> (category, company). Company is a proper name (never translated).
TRACKERS = {
    # --- ads: Google ---
    "doubleclick.net": ("ads", "Google"),
    "googlesyndication.com": ("ads", "Google"),
    "googleadservices.com": ("ads", "Google"),
    "googletagservices.com": ("ads", "Google"),
    "adservice.google.com": ("ads", "Google"),
    "admob.com": ("ads", "Google"),
    "2mdn.net": ("ads", "Google"),
    "imasdk.googleapis.com": ("ads", "Google"),
    # --- ads: platforms and device makers ---
    "amazon-adsystem.com": ("ads", "Amazon"),
    "samsungads.com": ("ads", "Samsung"),
    "lgsmartad.com": ("ads", "LG"),
    "ad.lgappstv.com": ("ads", "LG"),
    "ads.roku.com": ("ads", "Roku"),
    "iadsdk.apple.com": ("ads", "Apple"),
    "api-adservices.apple.com": ("ads", "Apple"),
    "ad.xiaomi.com": ("ads", "Xiaomi"),
    "ad.intl.xiaomi.com": ("ads", "Xiaomi"),
    "an.facebook.com": ("ads", "Meta"),
    "ads-twitter.com": ("ads", "X (Twitter)"),
    "ads.linkedin.com": ("ads", "LinkedIn"),
    "ads.tiktok.com": ("ads", "TikTok"),
    "ads.pinterest.com": ("ads", "Pinterest"),
    "bat.bing.com": ("ads", "Microsoft"),
    "ads.yahoo.com": ("ads", "Yahoo"),
    "gemini.yahoo.com": ("ads", "Yahoo"),
    "advertising.com": ("ads", "Yahoo"),
    "yandexadexchange.net": ("ads", "Yandex"),
    "an.yandex.ru": ("ads", "Yandex"),
    "adfox.ru": ("ads", "Yandex"),
    # --- ads: exchanges, networks, ad tech ---
    "adnxs.com": ("ads", "Microsoft (Xandr)"),
    "criteo.com": ("ads", "Criteo"),
    "criteo.net": ("ads", "Criteo"),
    "taboola.com": ("ads", "Taboola"),
    "outbrain.com": ("ads", "Outbrain"),
    "zemanta.com": ("ads", "Outbrain"),
    "rubiconproject.com": ("ads", "Magnite"),
    "spotxchange.com": ("ads", "Magnite"),
    "springserve.com": ("ads", "Magnite"),
    "pubmatic.com": ("ads", "PubMatic"),
    "openx.net": ("ads", "OpenX"),
    "casalemedia.com": ("ads", "Index Exchange"),
    "indexww.com": ("ads", "Index Exchange"),
    "adsrvr.org": ("ads", "The Trade Desk"),
    "yieldmo.com": ("ads", "Yieldmo"),
    "smartadserver.com": ("ads", "Equativ"),
    "33across.com": ("ads", "33Across"),
    "sharethrough.com": ("ads", "Sharethrough"),
    "teads.tv": ("ads", "Teads"),
    "media.net": ("ads", "Media.net"),
    "bidswitch.net": ("ads", "IPONWEB"),
    "contextweb.com": ("ads", "PulsePoint"),
    "adform.net": ("ads", "Adform"),
    "mathtag.com": ("ads", "MediaMath"),
    "moatads.com": ("ads", "Oracle (Moat)"),
    "bluekai.com": ("ads", "Oracle"),
    "serving-sys.com": ("ads", "Sizmek"),
    "adsafeprotected.com": ("ads", "Integral Ad Science"),
    "doubleverify.com": ("ads", "DoubleVerify"),
    "flashtalking.com": ("ads", "Flashtalking"),
    "everesttech.net": ("ads", "Adobe"),
    "demdex.net": ("ads", "Adobe"),
    "crwdcntrl.net": ("ads", "Lotame"),
    "krxd.net": ("ads", "Salesforce"),
    "exelator.com": ("ads", "Nielsen"),
    "agkn.com": ("ads", "Neustar"),
    "rlcdn.com": ("ads", "LiveRamp"),
    "quantserve.com": ("ads", "Quantcast"),
    "quantcount.com": ("ads", "Quantcast"),
    "turn.com": ("ads", "Amobee"),
    "gumgum.com": ("ads", "GumGum"),
    "triplelift.com": ("ads", "TripleLift"),
    "3lift.com": ("ads", "TripleLift"),
    "adroll.com": ("ads", "AdRoll"),
    "tapad.com": ("ads", "Tapad"),
    "liadm.com": ("ads", "LiveIntent"),
    "id5-sync.com": ("ads", "ID5"),
    "popads.net": ("ads", "PopAds"),
    "propellerads.com": ("ads", "PropellerAds"),
    "exoclick.com": ("ads", "ExoClick"),
    "mgid.com": ("ads", "MGID"),
    "revcontent.com": ("ads", "Revcontent"),
    # --- ads: mobile app ad SDKs ---
    "adcolony.com": ("ads", "Digital Turbine"),
    "unityads.unity3d.com": ("ads", "Unity"),
    "applovin.com": ("ads", "AppLovin"),
    "applvn.com": ("ads", "AppLovin"),
    "vungle.com": ("ads", "Liftoff"),
    "inmobi.com": ("ads", "InMobi"),
    "chartboost.com": ("ads", "Chartboost"),
    "ironsrc.com": ("ads", "ironSource"),
    "supersonicads.com": ("ads", "ironSource"),
    "startappservice.com": ("ads", "Start.io"),
    # --- ads: Asia (Stage N) ---
    "pangle.io": ("ads", "ByteDance (Pangle)"),
    "pangolin-sdk-toutiao.com": ("ads", "ByteDance (Pangle)"),
    "gdt.qq.com": ("ads", "Tencent (GDT)"),
    "ads.samsung.com": ("ads", "Samsung"),
    "appier.net": ("ads", "Appier"),
    "vpon.com": ("ads", "Vpon"),
    "vpadn.com": ("ads", "Vpon"),
    "clickforce.com.tw": ("ads", "ClickForce"),

    # --- analytics: web + app analytics, attribution, session recording ---
    "google-analytics.com": ("analytics", "Google"),
    "googletagmanager.com": ("analytics", "Google"),
    "analytics.google.com": ("analytics", "Google"),
    "app-measurement.com": ("analytics", "Google"),
    "app-analytics-services.com": ("analytics", "Google"),
    "scorecardresearch.com": ("analytics", "Comscore"),
    "imrworldwide.com": ("analytics", "Nielsen"),
    "hotjar.com": ("analytics", "Hotjar"),
    "hotjar.io": ("analytics", "Hotjar"),
    "mixpanel.com": ("analytics", "Mixpanel"),
    "mxpnl.com": ("analytics", "Mixpanel"),
    "segment.io": ("analytics", "Twilio Segment"),
    "cdn.segment.com": ("analytics", "Twilio Segment"),
    "amplitude.com": ("analytics", "Amplitude"),
    "heapanalytics.com": ("analytics", "Heap"),
    "fullstory.com": ("analytics", "FullStory"),
    "mouseflow.com": ("analytics", "Mouseflow"),
    "crazyegg.com": ("analytics", "Crazy Egg"),
    "clarity.ms": ("analytics", "Microsoft"),
    "nr-data.net": ("analytics", "New Relic"),
    "js-agent.newrelic.com": ("analytics", "New Relic"),
    "appsflyer.com": ("analytics", "AppsFlyer"),
    "appsflyersdk.com": ("analytics", "AppsFlyer"),
    "adjust.com": ("analytics", "Adjust"),
    "branch.io": ("analytics", "Branch"),
    "kochava.com": ("analytics", "Kochava"),
    "singular.net": ("analytics", "Singular"),
    "appboy.com": ("analytics", "Braze"),
    "clevertap-prod.com": ("analytics", "CleverTap"),
    "statcounter.com": ("analytics", "StatCounter"),
    "chartbeat.com": ("analytics", "Chartbeat"),
    "chartbeat.net": ("analytics", "Chartbeat"),
    "optimizely.com": ("analytics", "Optimizely"),
    "mc.yandex.ru": ("analytics", "Yandex"),
    "top-fwz1.mail.ru": ("analytics", "VK (Mail.ru)"),
    "matomo.cloud": ("analytics", "Matomo"),
    "cloudflareinsights.com": ("analytics", "Cloudflare"),
    "stats.wp.com": ("analytics", "Automattic"),
    "pixel.wp.com": ("analytics", "Automattic"),
    "omtrdc.net": ("analytics", "Adobe"),
    "2o7.net": ("analytics", "Adobe"),
    "adobedc.net": ("analytics", "Adobe"),
    "tealiumiq.com": ("analytics", "Tealium"),
    "tiqcdn.com": ("analytics", "Tealium"),
    "umeng.com": ("analytics", "Umeng (Alibaba)"),
    "umengcloud.com": ("analytics", "Umeng (Alibaba)"),
    "cnzz.com": ("analytics", "Umeng (Alibaba)"),
    "hm.baidu.com": ("analytics", "Baidu"),
    "tongji.baidu.com": ("analytics", "Baidu"),
    "growingio.com": ("analytics", "GrowingIO"),
    "sensorsdata.cn": ("analytics", "Sensors Data"),
    "talkingdata.com": ("analytics", "TalkingData"),
    "cdp.cloud.unity3d.com": ("analytics", "Unity"),

    # --- telemetry: device / vendor / app phone-home ---
    "samsungacr.com": ("telemetry", "Samsung"),
    "di.atlas.samsung.com": ("telemetry", "Samsung"),
    "tvinteractive.tv": ("telemetry", "Vizio (Inscape)"),
    "smartshare.lgtvsdp.com": ("telemetry", "LG"),
    "logs.roku.com": ("telemetry", "Roku"),
    "device-metrics-us.amazon.com": ("telemetry", "Amazon"),
    "device-metrics-us-2.amazon.com": ("telemetry", "Amazon"),
    "unagi.amazon.com": ("telemetry", "Amazon"),
    "unagi-na.amazon.com": ("telemetry", "Amazon"),
    "fls-na.amazon.com": ("telemetry", "Amazon"),
    "metrics.icloud.com": ("telemetry", "Apple"),
    "xp.apple.com": ("telemetry", "Apple"),
    "events.data.microsoft.com": ("telemetry", "Microsoft"),
    "vortex.data.microsoft.com": ("telemetry", "Microsoft"),
    "telemetry.microsoft.com": ("telemetry", "Microsoft"),
    "watson.microsoft.com": ("telemetry", "Microsoft"),
    "dc.services.visualstudio.com": ("telemetry", "Microsoft"),
    "firebaselogging-pa.googleapis.com": ("telemetry", "Google"),
    "crashlyticsreports-pa.googleapis.com": ("telemetry", "Google"),
    "crashlytics.com": ("telemetry", "Google"),
    "tracking.miui.com": ("telemetry", "Xiaomi"),
    "tracking.intl.miui.com": ("telemetry", "Xiaomi"),
    "mistat.xiaomi.com": ("telemetry", "Xiaomi"),
    "mistat.intl.xiaomi.com": ("telemetry", "Xiaomi"),
    "metrics.data.hicloud.com": ("telemetry", "Huawei"),
    "logservice.hicloud.com": ("telemetry", "Huawei"),
    "logservice1.hicloud.com": ("telemetry", "Huawei"),
    "open.oneplus.net": ("telemetry", "OnePlus"),
    "ichnaea.netflix.com": ("telemetry", "Netflix"),
    "telemetry.mozilla.org": ("telemetry", "Mozilla"),
    "metrics.ubuntu.com": ("telemetry", "Canonical"),
    "popcon.ubuntu.com": ("telemetry", "Canonical"),
    "telemetry.nvidia.com": ("telemetry", "NVIDIA"),
    "events.gfe.nvidia.com": ("telemetry", "NVIDIA"),
    "cc-api-data.adobe.io": ("telemetry", "Adobe"),
    "datarouter.ol.epicgames.com": ("telemetry", "Epic Games"),
    "beacon.qq.com": ("telemetry", "Tencent"),
    "log.byteoversea.com": ("telemetry", "ByteDance"),
    "log.tiktokv.com": ("telemetry", "ByteDance"),
    "sentry.io": ("telemetry", "Sentry"),
    "bugsnag.com": ("telemetry", "Bugsnag"),
    "browser-intake-datadoghq.com": ("telemetry", "Datadog"),

    # --- social: pixels, SDKs, share widgets ---
    "connect.facebook.net": ("social", "Meta"),
    "graph.facebook.com": ("social", "Meta"),
    "pixel.facebook.com": ("social", "Meta"),
    "graph.instagram.com": ("social", "Meta"),
    "platform.twitter.com": ("social", "X (Twitter)"),
    "syndication.twitter.com": ("social", "X (Twitter)"),
    "analytics.twitter.com": ("social", "X (Twitter)"),
    "platform.linkedin.com": ("social", "LinkedIn"),
    "snap.licdn.com": ("social", "LinkedIn"),
    "analytics.tiktok.com": ("social", "TikTok"),
    "business-api.tiktok.com": ("social", "TikTok"),
    "ct.pinterest.com": ("social", "Pinterest"),
    "widgets.pinterest.com": ("social", "Pinterest"),
    "tr.snapchat.com": ("social", "Snap"),
    "sc-static.net": ("social", "Snap"),
    "alb.reddit.com": ("social", "Reddit"),
    "events.redditmedia.com": ("social", "Reddit"),
    "tr.line.me": ("social", "LINE"),
    "q.quora.com": ("social", "Quora"),
    "addthis.com": ("social", "Oracle (AddThis)"),
    "sharethis.com": ("social", "ShareThis"),

    # --- other: fingerprinting, identity graphs, data brokers ---
    "fpjs.io": ("other", "FingerprintJS"),
    "fpcdn.io": ("other", "FingerprintJS"),
    "iesnare.com": ("other", "TransUnion (iovation)"),
    "online-metrix.net": ("other", "LexisNexis (ThreatMetrix)"),
    "wurfl.io": ("other", "ScientiaMobile"),
    "pippio.com": ("other", "LiveRamp"),
    "bounceexchange.com": ("other", "Wunderkind"),
    "zeotap.com": ("other", "Zeotap"),
    "permutive.com": ("other", "Permutive"),
}

# Privacy grade from the share of ALL lookups that reached a tracker UNBLOCKED:
# below 3 % -> A, below 10 % -> B, below 20 % -> C, below 40 % -> D, else F.
GRADES = ((0.03, "A"), (0.10, "B"), (0.20, "C"), (0.40, "D"))
TOP_TRACKERS = 5


# --- the tracker table ---------------------------------------------------------

def _clean(domain: str) -> str:
    return (domain or "").lower().strip().strip(".")


def load_custom(path: Path | None = None) -> dict:
    """Entries from the user's tracker file (missing file = none). Bad lines are skipped."""
    path = Path(path) if path else CUSTOM_FILE
    out = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if not parts:
            continue
        dom = _clean(parts[0])
        if "." not in dom or "/" in dom or "*" in dom:
            continue
        cat = parts[1].lower() if len(parts) > 1 else "other"
        if cat not in CATEGORIES:   # "domain Some Company" without a category
            cat, company = "other", " ".join(parts[1:])
        else:
            company = " ".join(parts[2:])
        out[dom] = (cat, company or None)
    return out


def table(custom: Path | None = None) -> dict:
    """The bundled list with the user's file on top (a user entry wins)."""
    return {**TRACKERS, **load_custom(custom)}


def lookup(domain: str, tbl: dict | None = None):
    """(entry, category, company) for a tracker domain, else None. Longest entry wins."""
    tbl = TRACKERS if tbl is None else tbl
    d = _clean(domain)
    # walk the domain's own suffixes, longest first: a dict hit per label, not a scan
    labels = d.split(".")
    for i in range(len(labels) - 1):
        key = ".".join(labels[i:])
        if key in tbl:
            cat, company = tbl[key]
            return key, cat, company
    return None


# --- analysis ------------------------------------------------------------------

def grade(queries: int, unblocked: int) -> str:
    share = unblocked / queries if queries else 0.0
    for limit, g in GRADES:
        if share < limit:
            return g
    return "F"


def _pct(part: float, whole: float) -> int:
    return round(100 * part / whole) if whole else 0


def _blank() -> dict:
    return {"queries": 0, "tracker_queries": 0, "blocked": 0,
            "by_category": {c: 0 for c in CATEGORIES}, "_entries": {}}


def _finish(acc: dict) -> dict:
    """Totals -> the public per-device / home shape (canonical, not localized)."""
    q, tq, bl = acc["queries"], acc["tracker_queries"], acc["blocked"]
    entries = sorted(acc["_entries"].values(), key=lambda e: (-e["count"], e["entry"]))
    cats = {c: n for c, n in acc["by_category"].items() if n}
    main = max(cats, key=lambda c: (cats[c], -CATEGORIES.index(c))) if cats else None
    top = entries[0] if entries else None
    out = {k: v for k, v in acc.items() if not k.startswith("_") and k != "by_category"}
    out.update({
        "by_category": cats,
        "tracker_share": round(tq / q, 3) if q else 0.0,
        "blocked_share": round(bl / tq, 3) if tq else 0.0,
        "unblocked": tq - bl,
        "grade": grade(q, tq - bl),
        "main_category": main,
        "main_company": top["company"] if top else None,
        "top_trackers": [{k: e[k] for k in ("entry", "category", "company", "count", "blocked")}
                         for e in entries[:TOP_TRACKERS]],
        "_entries": entries,
    })
    return out


def analyze(db, since: str, tbl: dict | None = None) -> dict:
    """Privacy over DNS events at/after `since` (ISO ts):
        {"home": {...}, "devices": [{mac, name, ...} worst first], "_entries": [...]}
    Every per-device / home dict has queries, tracker_queries, blocked (tracker lookups the
    DNS filter blocked), unblocked, tracker_share, blocked_share, by_category,
    main_category, main_company, top_trackers and grade. With the default tracker table
    the result is shared through netwarden.cache (windows starting in the same minute)."""
    if tbl is None:
        return cache.memo(db, "privacy.analyze", (since[:16],),
                          lambda: _analyze(db, since, table()))
    return _analyze(db, since, tbl)


def _analyze(db, since: str, tbl: dict) -> dict:
    names = store.device_names(db)
    per: dict = {}
    home = _blank()
    hit_cache: dict = {}
    for r in db.execute(
            """SELECT COALESCE(device_mac, 'ip:' || client_ip) AS key, device_mac, domain,
                      COUNT(*) AS n, SUM(blocked) AS b
               FROM dns_events WHERE ts >= ? GROUP BY key, domain""", (since,)):
        acc = per.setdefault(r["key"], _blank())
        for a in (acc, home):
            a["queries"] += r["n"]
        if r["domain"] not in hit_cache:
            hit_cache[r["domain"]] = lookup(r["domain"], tbl)
        hit = hit_cache[r["domain"]]
        if not hit:
            continue
        entry, cat, company = hit
        blocked = r["b"] or 0
        for a in (acc, home):
            a["tracker_queries"] += r["n"]
            a["blocked"] += blocked
            a["by_category"][cat] += r["n"]
            e = a["_entries"].setdefault(entry, {"entry": entry, "category": cat,
                                                 "company": company, "count": 0, "blocked": 0,
                                                 "domains": {}})
            e["count"] += r["n"]
            e["blocked"] += blocked
            if r["n"] > blocked:   # this exact hostname still got through
                e["domains"][r["domain"]] = e["domains"].get(r["domain"], 0) + r["n"] - blocked
    devices = []
    for key, acc in per.items():
        mac = None if key.startswith("ip:") else key
        dev = _finish(acc)
        dev.pop("_entries")
        devices.append({"mac": mac, "name": names.get(mac) if mac else key[3:], **dev})
    devices.sort(key=lambda d: (-d["unblocked"], -d["tracker_queries"], d["name"] or ""))
    home = _finish(home)
    entries = home.pop("_entries")
    return {"home": home, "devices": devices, "_entries": entries}


def worst(devices: list, n: int = 3) -> list:
    """The devices leaking the most tracker lookups (grade C or worse), worst first."""
    return [d for d in devices if d["unblocked"] and d["grade"] in "CDF"][:n]


_RULE_NAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
                        r"(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$")


def rule_safe(name: str) -> bool:
    """Is `name` a plain host name we may put into a copyable filter rule? Logged
    domains come from the network (hostile input): a newline, space, `$` or `/` in one
    could smuggle an extra rule or modifier into what the user pastes."""
    return bool(_RULE_NAME.match(name or ""))


def block_rules(entries: list) -> dict:
    """Copyable rules for trackers that still got through (suggestions only).
    AdGuard Home: ||entry^ (covers subdomains). Pi-hole: the exact hostnames seen, one
    per line (a plain domain on a Pi-hole list matches that name only). Names that are
    not plain host names are left out (rule_safe)."""
    open_entries = [e for e in entries if e["count"] > e["blocked"] and rule_safe(e["entry"])]
    open_entries.sort(key=lambda e: (-(e["count"] - e["blocked"]), e["entry"]))
    hosts = sorted({h for e in open_entries for h in e["domains"] if rule_safe(h)})
    return {"adguard": "\n".join(f"||{e['entry']}^" for e in open_entries),
            "pihole": "\n".join(hosts),
            "count": len(open_entries)}


# --- localized text (the API / digest / offline edge) ---------------------------

def category_name(cat: str | None, lang: str) -> str:
    return i18n.t("privacy.cat." + (cat or "other"), lang)


def reason(d: dict, lang: str) -> str:
    """The one-line, localized reason behind a grade."""
    if not d["tracker_queries"]:
        return i18n.tn("privacy.reason.none", d["queries"], lang)
    if not d["unblocked"]:
        return i18n.tn("privacy.reason.all_blocked", d["tracker_queries"], lang)
    kw = {"pct": _pct(d["unblocked"], d["queries"]),
          "category": category_name(d["main_category"], lang),
          "company": d["main_company"] or ""}
    key = "privacy.reason.leak_company" if d["main_company"] else "privacy.reason.leak"
    return i18n.t(key, lang, **kw)


def home_line(home: dict, lang: str) -> str:
    return i18n.tn("privacy.home_line", home["queries"], lang, grade=home["grade"],
                   trackers=home["tracker_queries"], queries=home["queries"],
                   pct=_pct(home["tracker_queries"], home["queries"]),
                   blocked=home["blocked"], bpct=_pct(home["blocked"], home["tracker_queries"]))


def localize(d: dict, lang: str) -> dict:
    """A copy of one device/home dict with category names and the grade reason in `lang`."""
    return {**d, "reason": reason(d, lang),
            "main_category_name": category_name(d["main_category"], lang) if d["main_category"] else None,
            "by_category_names": {category_name(c, lang): n for c, n in d["by_category"].items()},
            "top_trackers": [{**t, "category_name": category_name(t["category"], lang)}
                             for t in d["top_trackers"]]}


def since_hours(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def report(db, hours: float = 24, lang: str = i18n.DEFAULT, tbl: dict | None = None) -> dict:
    """GET /api/privacy: home summary, every device, worst offenders and block rules."""
    from netwarden import naming
    lang = i18n.normalize(lang)
    res = analyze(db, since_hours(hours), tbl)
    names = naming.display_names(db, lang)   # the dashboard's names, never a bare MAC
    devices = [localize(naming.relabel(d, names), lang) for d in res["devices"]]
    return {
        "window_hours": hours,
        "home": {**localize(res["home"], lang), "line": home_line(res["home"], lang)},
        "devices": devices,
        "worst": worst(devices),
        "rules": block_rules(res["_entries"]),
    }


def device_report(db, mac: str, hours: float = 24, lang: str = i18n.DEFAULT,
                  tbl: dict | None = None) -> dict | None:
    """One device's privacy (for /api/device), with block rules for just that device."""
    lang = i18n.normalize(lang)
    since = since_hours(hours)
    res = analyze(db, since, tbl)          # tbl None -> the shared (cached) default
    tbl = table() if tbl is None else tbl
    dev = next((d for d in res["devices"] if d["mac"] == mac), None)
    if dev is None:
        return None
    # per-device rules: re-run on this device's rows only
    acc = _blank()
    for r in db.execute("""SELECT domain, COUNT(*) AS n, SUM(blocked) AS b FROM dns_events
                           WHERE device_mac = ? AND ts >= ? GROUP BY domain""", (mac, since)):
        hit = lookup(r["domain"], tbl)
        if hit:
            e = acc["_entries"].setdefault(hit[0], {"entry": hit[0], "count": 0, "blocked": 0,
                                                    "domains": {}})
            e["count"] += r["n"]
            e["blocked"] += r["b"] or 0
            if r["n"] > (r["b"] or 0):
                e["domains"][r["domain"]] = r["n"] - (r["b"] or 0)
    return {**localize(dev, lang), "rules": block_rules(list(acc["_entries"].values()))}
