#!/usr/bin/env python3
"""
netwarden - devicetype.py: what kind of device is this? (phone, TV, camera, ...)

A stable type key per device, guessed from what we already know about it - no probing,
no fingerprinting traffic beyond what the DNS filter and the optional traffic sensor
already record:

  vendor     the MAC vendor (OUI) name, e.g. "Sony Interactive" -> console
  hostname   the name the device gave itself, e.g. "Galaxy-Tab-A7" -> tablet
  services   who it talks to, e.g. lots of samsungacr.com -> tv, xmeye.net -> camera
  traffic    its byte shape, e.g. uploads far more than it downloads -> camera
  randomized a private (randomized) MAC is what phones and tablets use

Each clue is a vote (type, confidence, reason). Votes for the same type add up; the
strongest type wins. A type the USER picked (store.device_profiles) always wins.

The result is canonical: {type, confidence 0-1, source, reason: {key, params}};
reason_text() / localize() turn it into one short localized sentence at the edge.

    python3 -m netwarden.devicetype --db data/demo.db     # list the guesses
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from netwarden import cache, i18n, services, store

# Stable keys (their names are "devtype.<key>" in netwarden/locales/*.json).
TYPES = ("phone", "tablet", "computer", "tv", "streaming", "console", "camera", "speaker",
         "network", "printer", "appliance", "vacuum", "wearable", "iot", "unknown")

# Devices that are busy around the clock by design: night activity is no news for them.
ALWAYS_ON = frozenset({"camera", "network", "speaker", "appliance", "iot", "vacuum",
                       "streaming", "tv", "printer", "wearable"})

# Hostname patterns, tried in order (the first match wins: "galaxy-tab" before "galaxy").
HOSTNAME_RULES = [
    (r"ipad|galaxy-?tab|\btab\b|tablet|kindle|mediapad|matepad|lenovo-?tab", "tablet"),
    (r"iphone|android|galaxy|pixel|redmi|oppo|vivo|oneplus|xperia|\bphone\b|huawei-p|nokia",
     "phone"),
    (r"chromecast|apple-?tv|fire-?tv|firestick|roku|shield|mibox|android-?tv-?box", "streaming"),
    (r"\btv\b|-tv\b|tv-|bravia|lgwebos|webos|tizen|smart-?tv", "tv"),
    (r"\bps[345]\b|playstation|xbox|nintendo|switch-?console", "console"),
    (r"ipcam|\bcam\b|camera|doorbell|\bipc\b|nvr|dvr|ring-", "camera"),
    (r"echo|alexa|homepod|nest-?(mini|audio|hub)|google-?home|sonos|speaker", "speaker"),
    (r"roborock|roomba|vacuum|deebot|dreame|ecovacs|robovac", "vacuum"),
    (r"printer|officejet|laserjet|deskjet|epson|brother|canon-?(mf|pixma|ts)", "printer"),
    (r"router|gateway|\bap\b|access-?point|mesh|extender|repeater|tp-?link|"
     r"asus-?rt|netgear|ubnt|unifi|mikrotik|openwrt", "network"),
    (r"watch|fitbit|garmin|mi-?band", "wearable"),
    (r"fridge|refrigerator|washer|dryer|dishwasher|aircon|air-?con|dyson|purifier|oven",
     "appliance"),
    (r"plug|bulb|light|tuya|shelly|sonoff|esp[-_]|esp32|esp8266|hue-|tasmota|sensor|"
     r"thermostat", "iot"),
    (r"desktop-|laptop|macbook|imac|mac-?mini|thinkpad|-pc\b|\bpc\b|workstation|surface|"
     r"raspberrypi|ubuntu|debian|fedora", "computer"),
]
HOSTNAME_RULES = [(re.compile(p, re.I), t) for p, t in HOSTNAME_RULES]

# MAC-vendor keywords (lowercase substring) -> type. Only vendors that make (almost)
# one kind of device; Apple / Google / Samsung / Amazon alone say too little.
VENDOR_RULES = [
    ("smart tv", "tv"), ("chromecast", "streaming"), ("roku", "streaming"),
    ("sony interactive", "console"), ("nintendo", "console"), ("playstation", "console"),
    ("(echo", "speaker"), ("sonos", "speaker"),
    ("roborock", "vacuum"), ("irobot", "vacuum"), ("ecovacs", "vacuum"), ("dreame", "vacuum"),
    ("printer", "printer"), ("epson", "printer"), ("brother industries", "printer"),
    ("ip camera", "camera"), ("hikvision", "camera"), ("dahua", "camera"),
    ("reolink", "camera"), ("wyze", "camera"), ("xiongmai", "camera"), ("ezviz", "camera"),
    ("router", "network"), ("tp-link", "network"), ("ubiquiti", "network"),
    ("netgear", "network"),
    ("mikrotik", "network"), ("zyxel", "network"), ("d-link", "network"),
    ("espressif", "iot"), ("tuya", "iot"), ("shelly", "iot"), ("sonoff", "iot"),
    ("fitbit", "wearable"), ("garmin", "wearable"),
    ("dell", "computer"), ("lenovo", "computer"), ("raspberry", "computer"),
    ("intel corporate", "computer"), ("micro-star", "computer"), ("giga-byte", "computer"),
]

# Service ids (services.py) whose use says a lot about the device.
SERVICE_RULES = {
    "svc.samsung_acr": "tv", "svc.samsung_tv_cloud": "tv",
    "svc.xmeye": "camera", "svc.xiongmai_cloud": "camera",
    "Amazon Alexa": "speaker", "svc.alexa_voice": "speaker",
    "svc.roborock": "vacuum", "svc.hp_print": "printer",
    "PlayStation": "console", "Xbox Live": "console",
    "svc.tuya": "iot",
    "GitHub": "computer", "svc.windows_update": "computer", "Anthropic API": "computer",
    "OpenAI API": "computer", "Steam": "computer",
}
# Templated service ids ("svc.camera_cloud|EZVIZ"): the template alone says the type.
SERVICE_TEMPLATE_RULES = {"svc.camera_cloud": "camera", "svc.vacuum_cloud": "vacuum",
                          "svc.iot_cloud": "iot", "svc.tv_cloud": "tv",
                          "svc.router": "network"}
# Mobile apps: together with a randomized MAC they point at a phone.
MOBILE_SERVICES = {"Instagram", "Facebook", "TikTok", "WhatsApp", "LINE", "Telegram",
                   "svc.apple_push", "svc.firebase_analytics", "iCloud", "Threads",
                   "Shopee", "Dcard", "Snapchat", "WeChat", "KakaoTalk", "Messenger"}

# "ident" = what the device announced itself on the LAN (mDNS / SSDP model + service):
# the strongest automatic clue - a TV that says "I am a Samsung QA55Q80B" usually is.
CONF = {"user": 1.0, "self": 0.9, "ident": 0.8, "hostname": 0.75, "vendor": 0.7,
        "services": 0.6, "traffic": 0.5, "randomized": 0.4}
MIN_SERVICE_QUERIES = 3      # a single stray lookup is not a clue
UPLOAD_RATIO = 3             # tx > 3 x rx ...
UPLOAD_MIN_BYTES = 500e6     # ... and at least this much a day -> a camera-like uploader
HISTORY_DAYS = 7


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def votes(dev: dict, service_counts: dict | None = None, bandwidth: dict | None = None,
          ident: dict | None = None) -> list:
    """Every clue for one device as (type, confidence, source, reason_params).
    dev: a devices row (vendor, hostname, randomized, is_self); service_counts:
    {service_id: queries}; bandwidth: {rx_bytes, tx_bytes} over ~a day, or None;
    ident: identify.best() of what it announced on the LAN, or None."""
    out = []
    vendor = (dev.get("vendor") or "").strip()
    host = (dev.get("hostname") or "").strip()
    randomized = bool(dev.get("randomized"))
    if dev.get("is_self"):
        out.append(("computer", CONF["self"], "self", {}))
    if ident and ident.get("kind") in TYPES:
        via = next((s for s in ident.get("sources", []) if s in ("mdns", "ssdp", "netbios")),
                   "mdns")
        out.append((ident["kind"], CONF["ident"], "ident",
                    {"via": via, "model": ident.get("model") or ident.get("name") or "?"}))
    if (not vendor or randomized) and ident and ident.get("manufacturer"):
        vendor = ident["manufacturer"]   # the maker it names itself (no MAC vendor known)
    elif randomized:
        vendor = ""                      # a private MAC has no real vendor
    if host:
        for rx, typ in HOSTNAME_RULES:
            if rx.search(host):
                out.append((typ, CONF["hostname"], "hostname", {"hostname": host}))
                break
    if vendor:
        low = vendor.lower()
        for kw, typ in VENDOR_RULES:
            if kw in low:
                out.append((typ, CONF["vendor"], "vendor", {"vendor": vendor}))
                break
    counts = {s: n for s, n in (service_counts or {}).items() if n >= MIN_SERVICE_QUERIES}
    best: dict = {}   # type -> (queries, service id) of its strongest service clue
    for sid, n in counts.items():
        typ = SERVICE_RULES.get(sid) or SERVICE_TEMPLATE_RULES.get(sid.partition("|")[0])
        if typ and n > best.get(typ, (0, ""))[0]:
            best[typ] = (n, sid)
    for typ, (_n, sid) in best.items():
        out.append((typ, CONF["services"], "services", {"service": sid}))
    if randomized:
        mobile = sorted((s for s in counts if s in MOBILE_SERVICES), key=lambda s: -counts[s])
        if mobile:
            out.append(("phone", CONF["services"], "mobile", {"service": mobile[0]}))
        else:
            out.append(("phone", CONF["randomized"], "randomized", {}))
    if bandwidth:
        rx, tx = bandwidth.get("rx_bytes") or 0, bandwidth.get("tx_bytes") or 0
        if tx >= UPLOAD_MIN_BYTES and tx > UPLOAD_RATIO * rx:
            out.append(("camera", CONF["traffic"], "traffic", {"tx": tx}))
    return out


def decide(vs: list, override: str | None = None) -> dict:
    """Votes -> {type, confidence, source, reason: {key, params}}. The user's override
    wins outright; otherwise the type with the highest summed confidence, its
    confidence boosted a little for each extra agreeing clue (capped at 0.95)."""
    if override in TYPES:
        return {"type": override, "confidence": 1.0, "source": "user",
                "reason": {"key": "user", "params": {}}}
    if not vs:
        return {"type": "unknown", "confidence": 0.0, "source": "none",
                "reason": {"key": "none", "params": {}}}
    score: dict = {}
    for typ, conf, _src, _p in vs:
        score[typ] = score.get(typ, 0) + conf
    typ = max(score, key=lambda t: (score[t], -TYPES.index(t)))
    mine = sorted((v for v in vs if v[0] == typ), key=lambda v: -v[1])
    top = mine[0]
    conf = min(0.95, top[1] + 0.15 * (len(mine) - 1))
    if len(score) > 1:   # disagreeing clues lower our confidence
        conf = max(0.2, conf - 0.1 * (len(score) - 1))
    return {"type": typ, "confidence": round(conf, 2), "source": top[2],
            "reason": {"key": top[2], "params": top[3]}}


def _service_counts(db, since: str) -> dict:
    """mac -> {service_id: queries} over DNS events at/after `since`."""
    out: dict = {}
    cache: dict = {}
    for r in db.execute("""SELECT device_mac, domain, COUNT(*) AS n FROM dns_events
                           WHERE device_mac IS NOT NULL AND ts >= ?
                           GROUP BY device_mac, domain""", (since,)):
        if r["domain"] not in cache:
            cache[r["domain"]] = services.lookup(r["domain"])[0]
        sid = cache[r["domain"]]
        if sid:
            per = out.setdefault(r["device_mac"], {})
            per[sid] = per.get(sid, 0) + r["n"]
    return out


def classify_all(db, now: datetime | None = None) -> dict:
    """mac -> decide() result for every device in the inventory. Without an explicit
    `now` the result is shared through netwarden.cache while the data is unchanged."""
    if now is None:
        return cache.memo(db, "devicetype.classify_all", (),
                          lambda: _classify_all(db, datetime.now(timezone.utc)))
    return _classify_all(db, now)


def _classify_all(db, now: datetime) -> dict:
    svc = _service_counts(db, _iso(now - timedelta(days=HISTORY_DAYS)))
    bw = store.bandwidth_window(db, _iso(now - timedelta(days=1)))
    profiles = store.get_profiles(db)
    from netwarden import identify   # lazy: identify -> devicetype (hostname rules)
    idents = identify.summary_all(db)
    out = {}
    for r in db.execute("SELECT mac, vendor, hostname, randomized, is_self FROM devices"):
        mac = r["mac"]
        override = (profiles.get(mac) or {}).get("type")
        out[mac] = decide(votes(dict(r), svc.get(mac), bw.get(mac), idents.get(mac)), override)
    return out


# --- localized text -------------------------------------------------------------

def type_name(typ: str | None, lang: str) -> str:
    return i18n.t("devtype." + (typ if typ in TYPES else "unknown"), lang)


def reason_text(res: dict, lang: str) -> str:
    """One short localized sentence: why we think so."""
    key, p = res["reason"]["key"], dict(res["reason"]["params"])
    if "service" in p:
        p["service"] = services.service_name(p["service"], lang)
    if "tx" in p:
        from netwarden.brain import human_bytes  # brain imports us; import lazily
        p["tx"] = human_bytes(p["tx"], lang)
    if "via" in p:   # protocol names read the same in every language (no nested brackets)
        p["via"] = {"mdns": "mDNS", "ssdp": "SSDP", "netbios": "NetBIOS"}.get(p["via"], p["via"])
    return i18n.t("devtype.reason." + key, lang, **p)


def localize(res: dict | None, lang: str) -> dict:
    """The API shape: {type, type_name, confidence, source, reason (text)}."""
    res = res or decide([])
    return {"type": res["type"], "type_name": type_name(res["type"], lang),
            "confidence": res["confidence"], "source": res["source"],
            "reason": reason_text(res, lang)}


def type_list(lang: str) -> list:
    """[{key, name}] in TYPES order - the choices for an override."""
    return [{"key": t, "name": type_name(t, lang)} for t in TYPES]


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="netwarden: guess each device's type.")
    ap.add_argument("--db", default=str(store.DEFAULT_DB))
    ap.add_argument("--lang", default=None)
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang)
    db = store.connect(args.db)
    names = store.device_names(db)
    for mac, res in sorted(classify_all(db).items(), key=lambda kv: names.get(kv[0], "")):
        loc = localize(res, lang)
        print(f"{names.get(mac, mac)[:28]:<30}{loc['type_name']:<14}{res['confidence']:<6}"
              f"{loc['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
