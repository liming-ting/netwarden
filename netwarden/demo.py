"""
netwarden - demo data seeder  (python3 -m netwarden demo; scripts/demo_seed.py wraps it)

Builds a SEPARATE demo database (default data/demo.db) filled with a simulated
multi-device home network. This is SYNTHETIC demonstration/test data - it is nobody's
real traffic, and it never touches your real data/netwarden.db.

Two layers of time so the PROACTIVE alerts have something true to find:
  - a rich RECENT window (last ~24h) of per-device DNS, same as the dashboard shows;
  - a lighter BASELINE history (a week before that) so netwarden knows each device's
    "normal" - and can tell when something changes.

Two changes are planted in the recent window on purpose, so "最近變化" lights up:
  1. a NEW device just joined       -> a Roborock robot vacuum phoning its cloud
  2. a known device picked up a NEW service it never used before -> PS5 started Twitch

    python3 -m netwarden demo                          # (re)write data/demo.db
    python3 -m netwarden alerts --db data/demo.db      # see the weekly digest
    python3 -m netwarden run --demo                    # the clickable dashboard

It also seeds a week of hourly per-device byte counters (traffic_samples), as the
optional ntopng source would - so the 流量 column and bytes trend have something to show.

Health story (source_status): AdGuard and ntopng both answered at seed time, ntopng had
one outage ~3 days ago (its last_error, long since recovered), and a discovery sweep
found every device. The DB is marked demo (meta demo=1): its IPs are made up but may
match REAL devices on the user's LAN, so later stages keep live actions off for it.

Stage D1 (privacy / DNS visibility / exposure): the Samsung TV phones home heavily to
vendor telemetry + ads (privacy grade F; the filter blocks only the ad domain); one phone
looks up dns.google (DoH bypass); the Echo went quiet in DNS 9 h ago while still online;
a Chromecast is online but never in the DNS logs; seeded port checks show the XMEye
ipcam with Telnet (23) and RTSP (554) open - so the AI can connect "high-risk camera
cloud + ~9 GB/day upload + Telnet open". Live port checks are refused on this DB.

Stage D2 (types / people & rooms / activity): "day" and "night" are LOCAL hours (the
same time zone the dashboard uses), so the heatmaps look like a real family's week.
Owners and rooms are seeded the way a Taiwanese household types them (爸爸, 媽媽, 小孩;
客廳, 書房, 小孩房 - user text, never translated; HOUSEHOLDS also has a Simplified-Chinese
and an English-speaking family for the static live demo). The kid's Android tablet
(Galaxy-Tab-A7, type from its hostname; the phones' type comes from their private MAC +
mobile apps) is a daytime device, but was busy around 01:00-02:00 on the last two
nights -> an "unusual hours" alert.

Stage V: this PC ran a ~12 GB cloud photo backup 9-11 hours ago, about six times its
usual day -> a "data spike" alert (alerts.bandwidth_spikes) that is benign but worth
knowing; the PS5's game download two days ago stays outside the recent window.

Stage N: devices announce themselves (IDENTITY: the TV over mDNS + SSDP, the printer over
IPP, the router as the UPnP gateway, the Chromecast and Dad's iPhone over mDNS), and the
router's UPnP table (UPNP_MAPPINGS) holds a benign PS5 game port and the camera's RTSP
stream opened to the internet ~3 h ago -> an upnp alert. External IP from RFC 5737.

Stage F: two weeks of family screen time (FAMILY, own RNG). The kid's tablet does
homework (Junyi), YouTube and Roblox; THIS week its school nights run past the 22:00
bedtime rule the parents set (DEMO_RULE, seeded once) -> bedtime alerts / previews on
>= 3 school nights. Dad's phone is the same both weeks, the TV shows Netflix every
evening; the home's ordinary lookups are echoed one week back, so "this week vs last
week" compares like with like: screen time up ~30%.

Stage H: 48 h of one-a-minute router pings (a few ms, own RNG). Last night 02:13-02:20
(local) the internet went down while the router kept answering - the camera's lookups
came back SERVFAIL -> an "ISP" outage; yesterday 19:41 the router itself stopped
answering for 3 minutes -> a "router" blip. AdGuard's own counters (meta), a few
suggestions already done / dismissed (seeded once, like the owners) and two weeks of
home-score history climbing towards today's score.

Stage X: every finding above lands in the one inbox (#/inbox); the family set "Snooze" to
3 days on the Settings page (DEMO_SETTINGS, seeded once, only while unset). The demo DB
never shows the first-run wizard, and backups / restores work on it like on a real one.
Stage Q: quiet hours 23:00-07:00 with last night's held summary (DEMO_QUIET), three tuned
alerts with expiries (DEMO_TUNING) and a leftover UPnP forward to a gone IP (UPNP_STALE).
Stage T: the map shows the family's clusters (the camera ringed red, two DNS blind
spots, the robot vacuum new, the router "fail" with 3 UPnP forwards); the camera's old
findings were seen two days ago (_seed_seen), so a visit ~12 h ago comes back to: 1 new
device, last night's 2 outages + the backup spike, Mom and the kid arriving home, 1 fix
that took effect.
Round 7 C: a month of AI answers (DEMO_USAGE: Sonnet 5.5 with cache writes / reads, one
evening on a LAN Ollama box) against a US$1 monthly budget -> the Settings "AI usage" card.

Deterministic (fixed RNG seeds, re-seeded every build) so the demo and tests reproduce
the same home. Idempotent: re-running rewrites the synthetic data but never touches the
user's own notes (device_labels, acks, device_profiles - the demo owners/rooms and
tuning acks are seeded once per DB and never over an edit).
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netwarden import activity, i18n, store

SEED = 1729
RNG = random.Random(SEED)  # fixed -> reproducible demo (re-seeded in build())
DEMO_DB = store.DEFAULT_DB.parent / "demo.db"

# The family's own words: names, rooms, the bedtime rule's name and what two devices
# announce. They are USER text (the app never translates them), so the built-in demo
# (data/demo.db) is the Taiwanese household; the static live demo seeds one home per
# script, so a reader of the English - or German, Hindi, ... - UI never meets names that
# look untranslated: zh-Hant and zh-Hans keep Chinese names in their own script, every
# other language gets the English-speaking household (household_for()). One table, so
# the two demos cannot drift.
DEFAULT_HOUSEHOLD = "zh-Hant"
HOUSEHOLDS = {
    "zh-Hant": {"dad": "爸爸", "mom": "媽媽", "kid": "小孩", "living": "客廳", "study": "書房",
                "kids_room": "小孩房", "kitchen": "廚房", "door": "門口", "rule": "上學日晚上",
                "dad_phone": "爸爸的 iPhone", "cast": "客廳 Chromecast"},
    "zh-Hans": {"dad": "爸爸", "mom": "妈妈", "kid": "小孩", "living": "客厅", "study": "书房",
                "kids_room": "小孩房", "kitchen": "厨房", "door": "门口", "rule": "上学日晚上",
                "dad_phone": "爸爸的 iPhone", "cast": "客厅 Chromecast"},
    "en": {"dad": "Dad", "mom": "Mom", "kid": "Kid", "living": "Living room", "study": "Study",
           "kids_room": "Kid's room", "kitchen": "Kitchen", "door": "Front door",
           "rule": "School nights", "dad_phone": "Dad's iPhone", "cast": "Living Room Chromecast"},
}


def household_for(lang: str | None) -> str:
    """UI language -> the household whose names read naturally in it."""
    lang = i18n.normalize(lang) if lang else DEFAULT_HOUSEHOLD
    return lang if lang in ("zh-Hant", "zh-Hans") else "en"


BASELINE_DAYS = 8   # how far back a known device's history reaches (first_seen)
N_BASELINE = 4      # baseline events emitted per normal domain (presence, not volume)

# Each device: identity + a profile of (domain, qtype, count, blocked, when).
#   when: "day" (~07-22), "night" (~00-06), "always" (24h)
# "profile" domains are part of the device's NORMAL baseline (seen last week too).
# Optional keys:
#   "recent_only": True        -> brand-new device; events only in the last 24h
#   "new_in_recent": [entries] -> services that appear ONLY in the last 24h (a change)
DEVICES = [
    {
        "ip": "192.168.1.1", "mac": "50:c7:bf:3e:21:54", "vendor": "TP-Link (router)",
        "hostname": "tplinkwifi.net", "randomized": False, "is_self": False,
        "profile": [
            ("pool.ntp.org", "A", 4, False, "always"),
            ("tplinkwifi.net", "A", 2, False, "day"),
        ],
    },
    {
        "ip": "192.168.1.13", "mac": "d8:3a:dd:1a:2b:3c", "vendor": "Dell Inc. (this machine)",
        "hostname": "DESKTOP-7Q2K9LM", "randomized": False, "is_self": True,
        "profile": [
            ("github.com", "A", 9, False, "day"),
            ("api.anthropic.com", "A", 6, False, "day"),
            ("update.microsoft.com", "A", 4, False, "day"),
            ("fonts.gstatic.com", "A", 12, False, "day"),
            ("doubleclick.net", "A", 10, True, "day"),
            ("googleads.g.doubleclick.net", "A", 6, True, "day"),
        ],
    },
    {
        # randomized MACs have no vendor (""); the UI localizes "private address"
        "ip": "192.168.1.21", "mac": "a6:71:0c:9d:4e:f2", "vendor": "",
        "hostname": "", "randomized": True, "is_self": False,
        "profile": [
            ("push.apple.com", "A", 16, False, "always"),
            ("gateway.icloud.com", "A", 8, False, "day"),
            ("instagram.com", "A", 12, False, "day"),
            ("graph.facebook.com", "A", 7, False, "day"),
            ("app-measurement.com", "A", 9, True, "day"),
            ("doubleclick.net", "A", 5, True, "day"),
        ],
    },
    {
        "ip": "192.168.1.22", "mac": "b2:55:3a:7c:10:9b", "vendor": "",
        "hostname": "", "randomized": True, "is_self": False,
        "profile": [
            ("youtube.com", "A", 14, False, "day"),
            ("googlevideo.com", "A", 22, False, "day"),
            ("push.apple.com", "A", 10, False, "always"),
            ("ssl.google-analytics.com", "A", 8, True, "day"),
            # Stage D1: this phone's browser uses encrypted DNS (DoH) via Google - it
            # looks the resolver up, then its lookups vanish from the DNS filter.
            ("dns.google", "A", 6, False, "always"),
        ],
    },
    # Stage D2: the kid's Android tablet. Normally only used in the daytime (08-21 local),
    # but it was busy around 01:00-02:00 on the last two nights -> "unusual hours".
    {
        "ip": "192.168.1.23", "mac": "9e:88:44:21:af:30", "vendor": "",
        "hostname": "Galaxy-Tab-A7", "randomized": True, "is_self": False,
        "daytime_only": True,
        "night_burst": [("tiktokcdn.com", 8), ("tiktokv.com", 4)],   # lookups per night
        "profile": [
            ("android.googleapis.com", "A", 12, False, "always"),
            ("connectivitycheck.gstatic.com", "A", 6, False, "always"),
            ("tiktokcdn.com", "A", 18, False, "day"),
            ("tiktokv.com", "A", 9, False, "day"),
            ("googleads.g.doubleclick.net", "A", 11, True, "day"),
            ("app-measurement.com", "A", 10, True, "day"),
        ],
    },
    {
        "ip": "192.168.1.31", "mac": "8c:79:f5:0b:cd:12", "vendor": "Samsung Electronics (Smart TV)",
        "hostname": "Samsung-TV", "randomized": False, "is_self": False,
        "profile": [
            # Stage D1 privacy story: heavy vendor telemetry (ACR = it reports what is on
            # screen) + ads; the DNS filter blocks the ad domain but not the telemetry.
            ("samsungacr.com", "A", 20, False, "day"),
            ("log-config.samsungacr.com", "A", 8, False, "day"),
            ("log-ingestion.samsungacr.com", "A", 14, False, "day"),
            ("samsungads.com", "A", 18, True, "day"),
            ("nflxvideo.net", "A", 12, False, "day"),
            ("netflix.com", "A", 8, False, "day"),
        ],
    },
    {
        "ip": "192.168.1.41", "mac": "fc:65:de:33:77:aa", "vendor": "Amazon Technologies (Echo)",
        "hostname": "echo-kitchen", "randomized": False, "is_self": False,
        # Stage D1: the Echo normally phones home every hour, but went silent in DNS
        # QUIET_HOURS ago while discovery still sees it online (hard-coded DNS / DoH?).
        "quiet_hours": 9,
        "profile": [
            ("device-metrics-us.amazon.com", "A", 1, False, "hourly"),
            ("alexa.amazon.com", "A", 10, False, "day"),
            ("avs-alexa-na.amazon.com", "A", 8, False, "day"),
            ("amazon-adsystem.com", "A", 9, True, "day"),
        ],
    },
    {
        "ip": "192.168.1.51", "mac": "a0:43:b0:9f:21:5e", "vendor": "Shenzhen (generic IP camera)",
        "hostname": "ipcam", "randomized": False, "is_self": False,
        "profile": [
            ("xmeye.net", "A", 38, False, "always"),
            ("star1.xmeye.net", "A", 22, False, "night"),
            ("secu100.net", "A", 14, False, "night"),
            ("pool.ntp.org", "A", 4, False, "always"),
        ],
    },
    {
        "ip": "192.168.1.61", "mac": "3c:2a:f4:88:19:d0", "vendor": "Hewlett Packard (printer)",
        "hostname": "HP-OfficeJet", "randomized": False, "is_self": False,
        "profile": [
            ("hpeprint.com", "A", 4, False, "day"),
            ("ocsp.hp.com", "A", 3, False, "day"),
        ],
    },
    {
        "ip": "192.168.1.71", "mac": "70:9e:29:55:3b:81", "vendor": "Sony Interactive (PS5)",
        "hostname": "PS5", "randomized": False, "is_self": False,
        "profile": [
            ("playstation.net", "A", 10, False, "day"),
            ("googlevideo.com", "A", 8, False, "day"),
            ("doubleclick.net", "A", 4, True, "day"),
        ],
        # CHANGE #2: the PS5 started streaming Twitch this week - it never did before.
        "new_in_recent": [
            ("twitch.tv", "A", 9, False, "day"),
        ],
    },
    # Stage D1: a streaming stick that discovery sees but the DNS filter never has -
    # it uses its own hard-coded resolver.
    {
        "ip": "192.168.1.35", "mac": "f4:f5:d8:6c:21:0e", "vendor": "Google (Chromecast)",
        "hostname": "Chromecast-Living", "randomized": False, "is_self": False,
        "no_dns": True,
        "profile": [],
    },
    # CHANGE #1: a brand-new device joined the network in the last day.
    {
        "ip": "192.168.1.55", "mac": "5c:e9:1e:7a:44:b8", "vendor": "Roborock (robot vacuum)",
        "hostname": "roborock-vacuum", "randomized": False, "is_self": False,
        "recent_only": True,
        "profile": [
            ("roborock.com", "A", 14, False, "always"),
            ("pool.ntp.org", "A", 3, False, "always"),
            ("app-measurement.com", "A", 5, True, "day"),
        ],
    },
    # Stage P (people + presence): their lookups come from build_presence (own RNG), so
    # every earlier story keeps its exact events. The kid's phone (presence ON: school
    # days), Mom's laptop, and Dad's iPhone on a NEW private address since 2 days ago
    # (it announces the same "爸爸的 iPhone" -> a pending "link it to 爸爸?" suggestion).
    {
        "ip": "192.168.1.24", "mac": "e6:3b:91:5d:22:c4", "vendor": "",
        "hostname": "Galaxy-A54", "randomized": True, "is_self": False, "profile": [],
    },
    {
        "ip": "192.168.1.26", "mac": "c8:89:f3:10:4a:7e", "vendor": "Apple, Inc.",
        "hostname": "MacBook-Air", "randomized": False, "is_self": False, "profile": [],
    },
    {
        "ip": "192.168.1.27", "mac": "ea:12:7b:c0:5e:39", "vendor": "",
        "hostname": "", "randomized": True, "is_self": False, "profile": [],
        "first_seen_days": 2,
    },
]


# Optional bandwidth (what an ntopng sensor would report): mac -> (download GB/day,
# upload GB/day, time-of-day shape). Hourly CUMULATIVE counters over the last 7 days.
# The story: TV + PS5 are the heavy downloaders; the ipcam - already flagged high-risk
# for its xmeye.net cloud - uploads steadily and a LOT, day and night.
TRAFFIC = {
    "d8:3a:dd:1a:2b:3c": (2.0, 0.5, "day"),       # this machine
    "a6:71:0c:9d:4e:f2": (1.4, 0.2, "day"),       # phone
    "b2:55:3a:7c:10:9b": (1.8, 0.1, "day"),       # phone (YouTube)
    "9e:88:44:21:af:30": (1.2, 0.15, "day"),      # kid's tablet (TikTok)
    "8c:79:f5:0b:cd:12": (7.0, 0.15, "evening"),  # Samsung TV: Netflix every evening
    "fc:65:de:33:77:aa": (0.08, 0.04, "flat"),    # Echo
    "a0:43:b0:9f:21:5e": (0.2, 9.0, "flat"),      # ipcam: ~0.8 Mbps up, 24/7
    "3c:2a:f4:88:19:d0": (0.01, 0.005, "day"),    # printer
    "70:9e:29:55:3b:81": (4.0, 0.3, "evening"),   # PS5 (+ a big game download, below)
    "5c:e9:1e:7a:44:b8": (0.03, 0.06, "flat"),    # Roborock (only joined ~6h ago)
}
TRAFFIC_DAYS = 7
PS5_DOWNLOAD_GB = 38          # one game update, spread over 3 hours ~2 days ago
TV_REBOOT_HOURS_AGO = 70      # the TV restarted -> its counters reset to 0
PC_BACKUP_GB = 12             # this PC's cloud photo backup, 9-11 hours ago: ~6x its
PC_BACKUP_HOURS = (9, 10, 11) # usual day -> the "data spike" alert (alerts.bandwidth_spikes)


def _hour_weight(shape: str, hour: int) -> float:
    if shape == "evening":
        return 4.0 if 18 <= hour <= 23 else (0.6 if 7 <= hour < 18 else 0.1)
    if shape == "day":
        return 1.6 if 7 <= hour <= 22 else 0.15
    return 1.0


def build_traffic(db, now: datetime) -> int:
    """Hourly cumulative per-device counters, deterministic (own RNG so the DNS story
    above is unchanged). Includes one counter reset to exercise the differencing."""
    trng = random.Random(4242)
    end = now.replace(minute=0, second=0, microsecond=0)
    samples = []
    for d in DEVICES:
        if d["mac"] not in TRAFFIC:
            continue
        rx_day, tx_day, shape = TRAFFIC[d["mac"]]
        norm = sum(_hour_weight(shape, h) for h in range(24))
        hours_back = 6 if d.get("recent_only") else TRAFFIC_DAYS * 24
        rx = trng.randint(10**8, 10**10)  # sensor has been counting for a while
        tx = trng.randint(10**7, 10**9)
        for k in range(hours_back, -1, -1):
            t = end - timedelta(hours=k)
            w = _hour_weight(shape, t.hour) / norm
            rx += int(rx_day * 1e9 * w * trng.uniform(0.7, 1.3))
            tx += int(tx_day * 1e9 * w * trng.uniform(0.7, 1.3))
            if d["hostname"] == "PS5" and 46 <= k <= 48:
                rx += int(PS5_DOWNLOAD_GB * 1e9 / 3)
            if d["hostname"] == "DESKTOP-7Q2K9LM" and k in PC_BACKUP_HOURS:
                tx += int(PC_BACKUP_GB * 1e9 / len(PC_BACKUP_HOURS))
            if d["hostname"] == "Samsung-TV" and k == TV_REBOOT_HOURS_AGO:
                rx, tx = trng.randint(10**6, 10**7), trng.randint(10**5, 10**6)
            samples.append({"mac": d["mac"], "ip": d["ip"], "rx_bytes": rx, "tx_bytes": tx,
                            "ts": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")})
    return store.insert_traffic_samples(db, samples)


def _hour(when: str) -> int:
    """A LOCAL hour of day for a profile's time-of-day (one RNG draw whatever `when`)."""
    if when == "night":
        return RNG.randint(0, 5)
    if when == "day":
        return RNG.randint(7, 22)
    if when == "daytime":   # a kid's device: strictly 08-21
        return RNG.randint(8, 21)
    return RNG.randint(0, 23)


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ts_recent(now: datetime, when: str, uniq: int, tz=timezone.utc) -> str:
    """A unique UTC timestamp within the last ~24h, biased by LOCAL time-of-day (so
    "day" devices are busy during the day wherever the demo is opened)."""
    local = now.astimezone(tz)
    cand = local.replace(hour=_hour(when), minute=RNG.randint(0, 59),
                         second=RNG.randint(0, 59), microsecond=(uniq * 997) % 1_000_000)
    if cand > local:
        cand -= timedelta(days=1)
    return _utc(cand)


def _ts_hourly(now: datetime, hours_ago: int, uniq: int) -> str:
    """One timestamp inside the clock hour `hours_ago` hours back (never in the future)."""
    t = now - timedelta(hours=hours_ago)
    cand = t.replace(minute=RNG.randint(0, 59), second=RNG.randint(0, 59),
                     microsecond=(uniq * 997) % 1_000_000)
    return min(cand, now).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _before_quiet(ts: str, now: datetime, quiet_hours: int) -> str:
    """Move a recent timestamp of a device that went quiet to before its silence."""
    t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if t > now - timedelta(hours=quiet_hours):
        t -= timedelta(hours=quiet_hours)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Seeded results of the opt-in exposure check (python3 -m netwarden check): live checks
# are refused on the demo DB, so these stand in. mac -> [(hours ago, open ports)].
# The story: the high-risk XMEye camera also has Telnet and its RTSP stream open.
PORT_CHECKS = {
    "a0:43:b0:9f:21:5e": [(72, (23, 80, 554)), (1, (23, 80, 554))],   # ipcam
    "50:c7:bf:3e:21:54": [(1, (80, 443))],                            # router admin page
    "3c:2a:f4:88:19:d0": [(1, (80, 443, 9100))],                      # printer
}
SEEN_JUST_NOW_MIN = 9   # the last discovery sweep (see _seed_health)


def build_port_checks(db, now: datetime) -> int:
    from netwarden import exposure  # demo is imported by the CLI; keep its imports light
    ip = {d["mac"]: d["ip"] for d in DEVICES}
    rows = []
    for mac, checks in PORT_CHECKS.items():
        for hours_ago, open_ports in checks:
            ts = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            rows += [{"mac": mac, "ip": ip[mac], "port": p, "open": p in open_ports, "ts": ts}
                     for p in exposure.PORTS]
    return store.insert_port_checks(db, rows)


def _ts_baseline(now: datetime, uniq: int, when: str = "always", tz=timezone.utc) -> str:
    """A unique UTC timestamp 2-6 days ago - safely inside the baseline window, so
    the alert engine reads it as 'this device's normal from last week'. The local
    hour follows the profile's time-of-day, like the recent window."""
    base = (now - timedelta(days=RNG.randint(2, 6))).astimezone(tz)
    cand = base.replace(hour=_hour(when), minute=RNG.randint(0, 59),
                        second=RNG.randint(0, 59), microsecond=(uniq * 997) % 1_000_000)
    return _utc(cand)


def night_burst_windows(now: datetime, tz) -> list:
    """The kid's tablet: LOCAL 01:00-02:00 on the last two nights, as UTC (start, end)
    pairs, newest first. The newest must lie inside the alert's last-24-h window
    whatever the time of day: tonight's 01:00..now if that is already the longer
    stretch, else last night's 01:00-02:00 minus anything older than 24 h."""
    local = now.astimezone(tz)
    one = local.replace(hour=1, minute=0, second=0, microsecond=0)
    tonight = (one, min(one + timedelta(hours=1), local - timedelta(minutes=1)))
    last = (max(one - timedelta(days=1), local - timedelta(hours=24) + timedelta(minutes=5)),
            one - timedelta(days=1) + timedelta(hours=1))
    span = lambda w: (w[1] - w[0]).total_seconds()  # noqa: E731
    recent = tonight if span(tonight) > span(last) else last
    earlier = (recent[0] - timedelta(days=1), recent[1] - timedelta(days=1))
    return [recent, earlier]


def _event(d: dict, ts: str, domain: str, qtype: str, blocked: bool) -> dict:
    return {
        "source": "demo", "ts": ts, "client_ip": d["ip"],
        "client_name": d["hostname"] or None, "domain": domain, "qtype": qtype,
        "status": "NOERROR",
        "reason": "FilteredBlackList" if blocked else "NotFilteredNotFound",
        "blocked": 1 if blocked else 0, "block_reason": "blocklist" if blocked else None,
        "cached": RNG.choice([0, 0, 1]),
        "upstream": "" if blocked else "192.168.1.1:53",
        "elapsed_ms": round(RNG.uniform(0.2, 40.0), 2), "device_mac": d["mac"],
    }


class NotADemoDB(ValueError):
    """Refusing to overwrite a database that holds real (non-demo) data."""


def _check_disposable(db, path: Path) -> None:
    """Only ever rewrite a demo DB: one marked demo, an empty one, or a file named
    demo.db (seeded before the marker existed). Never the user's real history."""
    if store.is_demo(db) or Path(path).name == DEMO_DB.name:
        return
    if db.execute("SELECT EXISTS(SELECT 1 FROM devices) OR EXISTS(SELECT 1 FROM dns_events)"
                  " OR EXISTS(SELECT 1 FROM traffic_samples)").fetchone()[0]:
        raise NotADemoDB(str(path))


def _seed_health(db, now: datetime, events: int, samples: int) -> None:
    """source_status rows as a running netwarden would have written them."""
    iso = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")  # noqa: E731
    with db:
        db.execute("DELETE FROM source_status")
    store.record_source_ok(db, "adguard", events, ts=iso(now - timedelta(seconds=40)))
    store.record_source_error(db, "ntopng", "URLError: <urlopen error [Errno 111] Connection refused>",
                              ts=iso(now - timedelta(hours=TV_REBOOT_HOURS_AGO + 2)))
    store.record_source_ok(db, "ntopng", len(TRAFFIC), ts=iso(now - timedelta(seconds=20)))
    sweep = iso(now - timedelta(minutes=SEEN_JUST_NOW_MIN))
    store.record_source_ok(db, "discovery", len(DEVICES), ts=sweep)
    store.record_source_ok(db, "mdns", sum(1 for i in IDENTITY if i[1] == "mdns"), ts=sweep)
    store.record_source_ok(db, "ssdp", sum(1 for i in IDENTITY if i[1] == "ssdp"), ts=sweep)
    store.record_source_ok(db, "upnp", len(UPNP_MAPPINGS), ts=sweep)
    # Stage V3: the unicast NetBIOS round ran; no Windows / Samba machine but this one
    store.record_source_ok(db, "netbios", 0, ts=sweep)
    store.record_source_ok(db, "gateway", 1, ts=iso(now - timedelta(seconds=25)))


# Stage N: what the devices announce about themselves on the LAN, as identify.py would
# have stored it: (mac, source, name, manufacturer, model, kind, detail, first seen days ago).
# The story: the Samsung TV announces "Samsung Q80 Series (55)" over mDNS (AirPlay) and
# "[TV] Samsung Q80 Series (55)" over SSDP; the printer its model over IPP; the router is
# the UPnP Internet gateway; the Chromecast - invisible to the DNS filter - still says
# who it is over mDNS; Dad's private-address phone announces "爸爸的 iPhone" (a name
# netwarden suggests, but never applies on its own).
def identity(h: dict | None = None) -> list:
    """IDENTITY for household `h` (the Chromecast and Dad's iPhone announce names the
    family gave them)."""
    h = h or HOUSEHOLDS[DEFAULT_HOUSEHOLD]
    return [
        ("8c:79:f5:0b:cd:12", "mdns", "Samsung Q80 Series (55)", "Samsung", "QA55Q80BAWXZW", "tv",
         "_airplay._tcp", 8),
        ("8c:79:f5:0b:cd:12", "ssdp", "[TV] Samsung Q80 Series (55)", "Samsung Electronics",
         "QA55Q80BAWXZW", "tv", "urn:schemas-upnp-org:device:MediaRenderer:1", 8),
        ("3c:2a:f4:88:19:d0", "mdns", "HP OfficeJet Pro 9010 series", "HP",
         "HP OfficeJet Pro 9010 series", "printer", "_ipp._tcp _ipps._tcp _printer._tcp", 8),
        ("50:c7:bf:3e:21:54", "ssdp", "TP-Link Archer C6", "TP-Link", "Archer C6", "network",
         "urn:schemas-upnp-org:device:InternetGatewayDevice:1", 8),
        ("f4:f5:d8:6c:21:0e", "mdns", h["cast"], "Google", "Chromecast", "streaming",
         "_googlecast._tcp", 8),
        ("a6:71:0c:9d:4e:f2", "mdns", h["dad_phone"], "Apple", "iPhone15,2", "phone",
         "_companion-link._tcp", 6),
        ("9e:88:44:21:af:30", "dns", "Galaxy-Tab-A7", "", "", None, "", 8),
        # Stage P: the same iPhone on its new private address announces the same name
        ("ea:12:7b:c0:5e:39", "mdns", h["dad_phone"], "Apple", "iPhone15,2", "phone",
         "_companion-link._tcp", 2),
    ]

# UPnP checks of the router (upnp.py): hours ago of each check, and each mapping's
# (mac, protocol, external port, internal port, description, first seen hours ago).
# The PS5 opened a UDP port for online play days ago (benign); the camera opened its
# RTSP video stream (554) to the whole internet ~3 hours ago (risky + new -> alert).
UPNP_CHECKS_HOURS = (120, 96, 72, 48, 24, 3, 0.15)
UPNP_EXTERNAL_IP = "203.0.113.57"     # documentation range (RFC 5737), never a real home
UPNP_MAPPINGS = [
    ("70:9e:29:55:3b:81", "UDP", 3478, 3478, "PS5", 120),
    ("a0:43:b0:9f:21:5e", "TCP", 554, 554, "IPC-RTSP", 3),
]
# Stage Q: a forward left behind by a laptop that is no longer on the network (no device
# holds 192.168.1.77) - the hygiene card's "forwards to devices that are gone".
UPNP_STALE = [("192.168.1.77", "UDP", 51413, 51413, "Transmission", 120)]


def build_identity(db, now: datetime, h: dict | None = None) -> int:
    for mac, src, name, maker, model, kind, detail, days in identity(h):
        first = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        last = (now - timedelta(minutes=SEEN_JUST_NOW_MIN)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        store.upsert_identity(db, mac, src, name, maker, model, kind, detail, seen=first)
        store.upsert_identity(db, mac, src, seen=last)
    # the reverse-DNS names the sweep saw (what the router's DHCP calls them)
    for d in DEVICES:
        if d["hostname"] and not d["is_self"] and "." not in d["hostname"]:
            store.upsert_identity(db, d["mac"], "dhcp", name=d["hostname"],
                                  seen=(now - timedelta(minutes=SEEN_JUST_NOW_MIN)).strftime(
                                      "%Y-%m-%dT%H:%M:%S.%fZ"))
    return db.execute("SELECT COUNT(*) FROM device_identity").fetchone()[0]


def build_upnp(db, now: datetime) -> int:
    ip = {d["mac"]: d["ip"] for d in DEVICES}
    for hours in UPNP_CHECKS_HOURS:
        ts = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        maps = [{"protocol": proto, "external_port": ext, "internal_client": ip[mac],
                 "internal_port": port, "description": desc, "enabled": 1, "lease": 0,
                 "mac": mac}
                for mac, proto, ext, port, desc, first in UPNP_MAPPINGS if first >= hours]
        maps += [{"protocol": proto, "external_port": ext, "internal_client": cip,
                  "internal_port": port, "description": desc, "enabled": 1, "lease": 0, "mac": None}
                 for cip, proto, ext, port, desc, first in UPNP_STALE if first >= hours]
        store.record_upnp(db, {"available": True, "gateway_ip": "192.168.1.1",
                               "gateway_name": "TP-Link Archer C6",
                               "external_ip": UPNP_EXTERNAL_IP, "status": "Connected"},
                          maps, ts=ts)
    return len(UPNP_CHECKS_HOURS)


# Stage D2: who owns what and where it stands, typed the way the family would (this is
# the USER's own free text - never translated): mac -> (owner, room) as HOUSEHOLDS keys.
PROFILE_KEYS = {
    "50:c7:bf:3e:21:54": (None, "living"),      # router
    "d8:3a:dd:1a:2b:3c": ("dad", "study"),      # this machine
    "a6:71:0c:9d:4e:f2": ("dad", None),         # phone
    "b2:55:3a:7c:10:9b": ("mom", None),         # phone (uses DoH)
    "9e:88:44:21:af:30": ("kid", "kids_room"),  # the kid's tablet (night owl)
    "8c:79:f5:0b:cd:12": (None, "living"),      # Samsung TV
    "fc:65:de:33:77:aa": (None, "kitchen"),     # Echo
    "a0:43:b0:9f:21:5e": (None, "door"),        # ipcam
    "3c:2a:f4:88:19:d0": (None, "study"),       # printer
    "70:9e:29:55:3b:81": ("kid", "living"),     # PS5
    "f4:f5:d8:6c:21:0e": (None, "living"),      # Chromecast
    "5c:e9:1e:7a:44:b8": (None, "living"),      # Roborock
    "e6:3b:91:5d:22:c4": ("kid", None),         # Stage P: the kid's phone
    "c8:89:f3:10:4a:7e": ("mom", "study"),      # Stage P: Mom's laptop
}
PROFILES_NOTED_DAYS_AGO = 5


def profiles(h: dict | None = None) -> dict:
    """mac -> (owner, room) in household `h`'s own words."""
    h = h or HOUSEHOLDS[DEFAULT_HOUSEHOLD]
    return {mac: (h[o] if o else None, h[r] if r else None) for mac, (o, r) in PROFILE_KEYS.items()}


def _seed_profiles(db, now: datetime, h: dict | None = None) -> None:
    """Owners/rooms as if the user had typed them a few days ago. Once per demo DB
    (meta demo_profiles=1) and only into EMPTY fields, so a user's own edits - and
    owners/rooms they cleared on purpose - survive every re-seed."""
    if store.get_meta(db, "demo_profiles") == "1":
        return
    ts = (now - timedelta(days=PROFILES_NOTED_DAYS_AGO)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with db:
        for mac, (owner, room) in profiles(h).items():
            db.execute("INSERT OR IGNORE INTO device_profiles (mac, updated_at) VALUES (?, ?)",
                       (mac, ts))
            db.execute("""UPDATE device_profiles SET owner = COALESCE(owner, ?),
                                                     room = COALESCE(room, ?)
                          WHERE mac = ?""", (owner, room, mac))
    store.set_meta(db, "demo_profiles", "1")


# Stage F: two weeks of family screen time (LOCAL times), the way a household's DNS looks.
# Sessions are (weekdays, start, end, service domains); "this" / "last" pick a week.
# The kid's tablet: homework, YouTube and Roblox; THIS week the school-night evenings run
# past the 22:00 bedtime rule (seeded below) and after-school Roblox got longer, so the
# home's screen time is up ~30%. Dad's phone is the same both weeks; the TV shows
# Netflix every evening (sparse lookups, so its Stage D1 privacy grade F stays).
SCHOOL_DAYS, SCHOOL_NIGHTS, EVERY_DAY = (0, 1, 2, 3, 4), (6, 0, 1, 2, 3), tuple(range(7))
WEEKEND_DAYS = (4, 5, 6)   # Friday night + the weekend
YOUTUBE = ("www.youtube.com", "r3---sn-ipoxu-un5e.googlevideo.com", "i.ytimg.com")
ROBLOX = ("apis.roblox.com", "c3.rbxcdn.com", "www.roblox.com")
NETFLIX = ("www.netflix.com", "ipv4-c001-tpe001-ix.1.oca.nflxvideo.net")
FAMILY = {
    "9e:88:44:21:af:30": [   # 小孩's tablet
        ("both", SCHOOL_DAYS, "16:30", "17:20", YOUTUBE),
        ("both", SCHOOL_DAYS, "19:00", "19:40", ("www.junyiacademy.org",)),
        ("last", SCHOOL_NIGHTS, "20:10", "21:00", ROBLOX),
        ("last", SCHOOL_NIGHTS, "21:00", "21:40", YOUTUBE),
        ("this", SCHOOL_DAYS, "17:20", "17:45", ROBLOX),
        ("this", SCHOOL_NIGHTS, "20:00", "21:15", ROBLOX),
        ("this", SCHOOL_NIGHTS, "21:15", "22:40", YOUTUBE),
        ("both", (5, 6), "14:00", "15:50", ROBLOX),
        ("both", WEEKEND_DAYS, "19:30", "21:30", YOUTUBE),
    ],
    "a6:71:0c:9d:4e:f2": [   # 爸爸's phone: the same every week
        ("both", EVERY_DAY, "07:30", "07:50", ("legy.line-apps.com", "obs.line-scdn.net")),
        ("both", SCHOOL_DAYS, "12:10", "12:30", ("udn.com", "news.ltn.com.tw")),
        ("both", EVERY_DAY, "21:00", "21:35", ("i.instagram.com", "scontent.cdninstagram.com")),
    ],
    "b2:55:3a:7c:10:9b": [   # 媽媽's phone
        ("both", EVERY_DAY, "13:00", "13:20", ("shopee.tw", "down-tw.img.susercontent.com")),
        ("both", EVERY_DAY, "21:40", "22:15", YOUTUBE),
    ],
    "8c:79:f5:0b:cd:12": [   # the living-room TV
        ("both", EVERY_DAY, "19:40", "21:30", NETFLIX),
    ],
}
FAMILY_DAYS = 14
FIRST_SEEN_DAYS = 15        # known devices joined before the two weeks of history
# minutes between lookups inside a session; the TV's player looks up rarely (it keeps
# its stream open), which also keeps its Stage D1 tracker share - and grade F - intact
CADENCE = {"8c:79:f5:0b:cd:12": (7, 13)}
DEFAULT_CADENCE = (2, 7)
# The parents' rule, typed the way they would: school nights (Sun-Thu) 22:00-07:00, after
# 15 minutes of estimated screen time. Seeded once per demo DB (meta demo_rules=1).
def demo_rule(h: dict | None = None) -> dict:
    h = h or HOUSEHOLDS[DEFAULT_HOUSEHOLD]
    return {"name": h["rule"], "owner": h["kid"], "mac": None, "days": list(SCHOOL_NIGHTS),
            "start": "22:00", "end": "07:00", "min_minutes": 15, "enabled": True}


def _day_rng(story: str, day, key: str = "") -> random.Random:
    """An RNG of its own for one LOCAL day of a story (a str seed is hashed the same way
    in every process). Crossing a local midnight then only adds the new day and drops the
    oldest one: the days in between keep their exact events, instead of every later draw
    shifting with the first day of the window."""
    return random.Random(f"{SEED}:{story}:{key}:{day.isoformat()}")


def build_family(db, now: datetime, tz) -> int:
    """Insert the FAMILY sessions of the last FAMILY_DAYS local days (an RNG per device
    and day + own event builder, so every earlier story keeps its exact events).
    Returns # events."""
    ip = {d["mac"]: d["ip"] for d in DEVICES}
    host = {d["mac"]: d["hostname"] or None for d in DEVICES}
    local_now = now.astimezone(tz)
    today = local_now.date()
    this_from = today - timedelta(days=6)
    events = []
    for mac, plan in FAMILY.items():
        lo, hi = CADENCE.get(mac, DEFAULT_CADENCE)
        for back in range(FAMILY_DAYS, -1, -1):
            day = today - timedelta(days=back)
            week = "this" if day >= this_from else "last"
            frng, uniq = _day_rng("family", day, mac), 0
            for which, days, start, end, domains in plan:
                if which not in ("both", week) or day.weekday() not in days:
                    continue
                t = datetime.combine(day, datetime.strptime(start, "%H:%M").time(), tzinfo=tz)
                stop = datetime.combine(day, datetime.strptime(end, "%H:%M").time(), tzinfo=tz)
                t += timedelta(minutes=frng.randint(0, 6))
                while t < stop:
                    # draw every value even for a lookup still in the future and drop it
                    # afterwards: the RNG stream (so every later session) must not depend
                    # on where `now` falls inside today's sessions
                    uniq += 1
                    domain, elapsed = frng.choice(domains), round(frng.uniform(0.5, 30.0), 2)
                    if t <= local_now:
                        events.append({
                            "source": "demo", "ts": _utc(t + timedelta(microseconds=uniq * 7)),
                            "client_ip": ip[mac], "client_name": host[mac],
                            "domain": domain, "qtype": "A", "status": "NOERROR",
                            "reason": "NotFilteredNotFound", "blocked": 0, "block_reason": None,
                            "cached": 0, "upstream": "192.168.1.1:53",
                            "elapsed_ms": elapsed, "device_mac": mac})
                    t += timedelta(minutes=frng.randint(lo, hi), seconds=frng.randint(0, 59))
    return store.insert_events(db, events)


def echo_last_week(db, now: datetime) -> int:
    """Stage F week-over-week: the home's ordinary lookups of 1-7 days ago happened the
    week before too (shifted 7 days back), so "this week vs last week" compares like with
    like. Only the lighter baseline is echoed (not the rich last 24 h). Returns # events."""
    hi = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    lo = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with db:
        cur = db.execute(
            """INSERT OR IGNORE INTO dns_events (source, ts, client_ip, client_name, device_mac,
                   domain, qtype, status, reason, blocked, cached, upstream, elapsed_ms,
                   block_reason)
               SELECT source, strftime('%Y-%m-%dT%H:%M:%f', ts, '-7 days') || substr(ts, 24),
                      client_ip, client_name, device_mac, domain, qtype, status, reason,
                      blocked, cached, upstream, elapsed_ms, block_reason
               FROM dns_events WHERE ts >= ? AND ts < ?""", (lo, hi))
    return cur.rowcount


def _seed_rules(db, h: dict | None = None) -> None:
    """The demo family's bedtime rule, once per demo DB (a rule the user deleted or
    edited stays as they left it)."""
    if store.get_meta(db, "demo_rules") == "1":
        return
    store.save_bedtime_rule(db, demo_rule(h))
    store.set_meta(db, "demo_rules", "1")


# Stage P: the family as people (avatar, color, the child flag), the TV and the Echo as
# the household's shared devices, and presence ON for Mom (work days) and the kid (school
# days), each with 8 days of "seen at home" history from the light presence check.
# Seeded once per demo DB (meta demo_people=1) and only into untouched fields.
PEOPLE_KEYS = {"dad": ("👨", "blue", False, False), "mom": ("👩", "rose", False, True),
               "kid": ("🧒", "green", True, True)}   # who -> (avatar, color, child, presence)


def demo_people(h: dict | None = None) -> dict:
    """name -> (avatar, color, child, presence) in household `h`'s words."""
    h = h or HOUSEHOLDS[DEFAULT_HOUSEHOLD]
    return {h[k]: v for k, v in PEOPLE_KEYS.items()}


# the built-in (Taiwanese) household's values, as earlier stages and tests know them
IDENTITY, PROFILES, DEMO_RULE, DEMO_PEOPLE = identity(), profiles(), demo_rule(), demo_people()
DEMO_SHARED = ("8c:79:f5:0b:cd:12", "fc:65:de:33:77:aa")   # the TV and the Echo
PRESENCE_PHONES = {"b2:55:3a:7c:10:9b": "work", "e6:3b:91:5d:22:c4": "school"}
KID_PHONE, MOM_LAPTOP, DAD_NEW_MAC = "e6:3b:91:5d:22:c4", "c8:89:f3:10:4a:7e", "ea:12:7b:c0:5e:39"
PRESENCE_DAYS = 8
LATE_DAYS_AGO = 2            # the kid's evening out, home at 22:50 (the one late arrival)
CHECK_EVERY_MIN = 5
ROUTINE_ANDROID = ("connectivitycheck.gstatic.com", "time.android.com")
ROUTINE_APPLE = ("captive.apple.com", "time.apple.com")


def _hm(day, hm: str, tz, jitter: int = 0) -> datetime:
    h, m = (int(x) for x in hm.split(":"))
    return datetime.combine(day, datetime.min.time(), tzinfo=tz).replace(hour=h, minute=m) \
        + timedelta(minutes=jitter)


def away_windows(kind: str, day, tz, rng: random.Random, late: bool = False) -> list:
    """[(leave, back)] aware datetimes when a presence phone is NOT home on local `day`."""
    wd, out = day.weekday(), []
    if kind == "work":
        if wd < 5:
            out.append((_hm(day, "08:10", tz, rng.randint(-8, 8)),
                        _hm(day, "17:50", tz, rng.randint(-15, 20))))
        elif wd == 5:
            out.append((_hm(day, "10:00", tz, rng.randint(0, 15)), _hm(day, "12:30", tz)))
    else:   # school
        if wd < 5:
            out.append((_hm(day, "07:20", tz, rng.randint(-5, 5)),
                        _hm(day, "16:10", tz, rng.randint(-5, 15))))
        elif wd == 5:
            out.append((_hm(day, "14:00", tz), _hm(day, "17:30", tz, rng.randint(0, 10))))
        if late:
            out.append((_hm(day, "19:00", tz), _hm(day, "22:50", tz)))
    return out


def build_presence(db, now: datetime, tz) -> int:
    """PRESENCE_DAYS of presence-check samples (every CHECK_EVERY_MIN while home) for the two
    presence phones, their lookups removed while they were out (a phone at work or school
    is not on the home Wi-Fi), and light routine lookups for the Stage P devices.
    An RNG per local day (_day_rng). Returns # DNS events added."""
    local_now = now.astimezone(tz)
    start = now - timedelta(days=PRESENCE_DAYS)
    ip = {d["mac"]: d["ip"] for d in DEVICES}
    host = {d["mac"]: d["hostname"] or None for d in DEVICES}
    away: dict = {}
    for mac, kind in PRESENCE_PHONES.items():
        for back in range(PRESENCE_DAYS, -1, -1):
            day = local_now.date() - timedelta(days=back)
            away.setdefault(mac, []).extend(
                away_windows(kind, day, tz, _day_rng("away", day, mac),
                             late=(kind == "school" and back == LATE_DAYS_AGO)))
    with db:
        for mac, wins in away.items():
            for a, b in wins:
                db.execute("DELETE FROM dns_events WHERE device_mac = ? AND ts >= ? AND ts < ?",
                           (mac, _utc(a), _utc(b)))
    samples, events = [], []

    def home(mac, t):
        return not any(a <= t < b for a, b in away.get(mac, []))

    def lookup(rng, mac, t, domains, wanted):
        # the RNG is drawn whether or not the lookup is kept, so a step that flips (now
        # crossed an hour boundary between two builds) changes one event, not every
        # draw after it; the timestamp depends on the step alone (one lookup per device
        # and step: (ts, client_ip, domain) stays unique)
        domain, elapsed = rng.choice(domains), round(rng.uniform(0.5, 20.0), 2)
        if wanted:
            events.append({"source": "demo", "ts": _utc(t + timedelta(microseconds=3)),
                           "client_ip": ip[mac], "client_name": host[mac], "domain": domain,
                           "qtype": "A", "status": "NOERROR", "reason": "NotFilteredNotFound",
                           "blocked": 0, "block_reason": None, "cached": 0, "upstream": "192.168.1.1:53",
                           "elapsed_ms": elapsed, "device_mac": mac})

    # the checks run on a fixed grid (every CHECK_EVERY_MIN, 17 s past the minute) with a
    # jitter derived from the slot itself, so moving `now` only adds or drops the slots at
    # either end - it never shifts every check across the away windows, nor the RNG stream
    step = CHECK_EVERY_MIN * 60
    slot = -(-int(start.timestamp() - 17) // step)          # first slot at or after start
    t = datetime.fromtimestamp(slot * step + 17, timezone.utc)
    while t <= now - timedelta(minutes=1):
        for i, mac in enumerate(PRESENCE_PHONES):
            if home(mac, t):
                jitter = 1 + (slot * 31 + i * 17) % 50
                samples.append((mac, _utc(t + timedelta(seconds=jitter)), "check"))
        slot += 1
        t += timedelta(seconds=step)
    # routine lookups (never screen time): the kid's phone while home and awake, Mom's
    # laptop in the day, Dad's iPhone on its new address since it appeared. One walk per
    # LOCAL day, from its midnight (+17 s, off the minute grid the away windows and hour
    # checks use) with that day's own RNG - not anchored to `now`: a later build only adds
    # the steps that have happened since, instead of sliding every step across those
    # boundaries, and a new day never reshuffles the days before it
    day = start.astimezone(tz).date()
    while True:
        t = datetime.combine(day, datetime.min.time(), tzinfo=tz) + timedelta(seconds=17)
        if t >= now:
            break
        rng = _day_rng("routine", day)
        kid_last = t                     # the kid's phone's last background lookup today
        day += timedelta(days=1)
        midnight = datetime.combine(day, datetime.min.time(), tzinfo=tz)
        while t < midnight and t < now:
            lt = t.astimezone(tz)
            awake, inside = 7 <= lt.hour < 23, t >= start
            # asleep, the phone still checks in now and then (at most ~2 h apart, far below
            # the night-activity alert): never 8 silent hours that read as a DNS blind spot
            # ("quiet") on the mornings its first lookup came only after it left for school
            kid = awake or rng.random() < 0.3 or t - kid_last >= timedelta(hours=2)
            lookup(rng, KID_PHONE, t, ROUTINE_ANDROID, inside and kid and home(KID_PHONE, t))
            if kid and home(KID_PHONE, t):
                kid_last = t
            lookup(rng, MOM_LAPTOP, t, ROUTINE_APPLE,
                   rng.random() < 0.3 and inside and 9 <= lt.hour < 22)
            lookup(rng, DAD_NEW_MAC, t, ROUTINE_APPLE,
                   rng.random() < 0.6 and awake and t >= now - timedelta(days=2))
            t += timedelta(minutes=rng.randint(15, 40))
    store.insert_presence_samples(db, samples)
    return store.insert_events(db, events)


def _seed_people(db, now: datetime, h: dict | None = None) -> None:
    """The demo_people() / DEMO_SHARED notes, once per demo DB, never over the user's own."""
    if store.get_meta(db, "demo_people") == "1":
        return
    store.sync_people(db)
    ts = (now - timedelta(days=PROFILES_NOTED_DAYS_AGO)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with db:
        for mac in (KID_PHONE, MOM_LAPTOP):   # demo DBs seeded before Stage P
            owner, room = profiles(h)[mac]
            db.execute("INSERT OR IGNORE INTO device_profiles (mac, owner, room, updated_at) "
                       "VALUES (?, ?, ?, ?)", (mac, owner, room, ts))
        for mac in DEMO_SHARED:
            db.execute("UPDATE device_profiles SET shared = 1 WHERE mac = ? AND owner IS NULL",
                       (mac,))
        for name, (avatar, color, child, pres) in demo_people(h).items():
            db.execute("INSERT OR IGNORE INTO people (name, created_at, updated_at) VALUES (?, ?, ?)",
                       (name, ts, ts))
            db.execute("""UPDATE people SET avatar = CASE avatar WHEN '' THEN ? ELSE avatar END,
                              color = CASE color WHEN '' THEN ? ELSE color END,
                              child = MAX(child, ?)
                          WHERE name = ?""", (avatar, color, int(child), name))
            if pres:   # only someone who never had presence settings
                db.execute("""UPDATE people SET presence = 1 WHERE name = ? AND presence = 0
                              AND presence_since IS NULL AND presence_macs IS NULL""", (name,))
    store.set_meta(db, "demo_people", "1")


# Stage H: network health. Local clock times of the two incidents (see the docstring).
HEALTH_HOURS = 48
ISP_OUTAGE = (2, 13, 7)       # last night 02:13, 7 minutes: router fine, DNS SERVFAIL
ROUTER_BLIP = (19, 41, 3)     # yesterday 19:41, 3 minutes: the router stops answering
OUTAGE_CLIENT = "a0:43:b0:9f:21:5e"          # the ipcam keeps retrying its cloud
OUTAGE_DOMAINS = ("xmeye.net", "pool.ntp.org")
OUTAGE_LOOKUPS = 5                           # failed lookups per outage minute
DNS_STATS = {"queries": 6412, "blocked": 803, "avg_ms": 11.6,
             "upstreams": [("192.168.1.1:53", 14.2)]}


def _incidents(now: datetime, tz) -> list:
    """[(start UTC, minutes, kind)] for the ISP outage and the router blip."""
    local = now.astimezone(tz)
    h, m, n = ISP_OUTAGE
    isp = local.replace(hour=h, minute=m, second=0, microsecond=0)
    if isp > local - timedelta(minutes=15):
        isp -= timedelta(days=1)
    h, m, b = ROUTER_BLIP
    blip = (local - timedelta(days=1)).replace(hour=h, minute=m, second=0, microsecond=0)
    return [(isp.astimezone(timezone.utc), n, "isp"), (blip.astimezone(timezone.utc), b, "router")]


def build_health(db, now: datetime, tz) -> int:
    """Gateway probes for HEALTH_HOURS, the two incidents, then the outage log derived
    from them exactly as the run loop would (nethealth.update_outages). Returns # probes."""
    from netwarden import dns_ingest, nethealth
    import json
    hrng = random.Random(SEED + 7)
    incidents = _incidents(now, tz)
    down = set()
    for start, n, kind in incidents:
        if kind == "router":
            down |= {start + timedelta(minutes=k) for k in range(n)}
    t = (now - timedelta(hours=HEALTH_HOURS)).replace(second=0, microsecond=0)
    rows = []
    while t <= now - timedelta(seconds=30):
        ts = _utc(t + timedelta(seconds=7, microseconds=hrng.randrange(1_000_000)))
        if t in down:
            rows.append((ts, "gateway", 0, None, 1.0, "ping"))
        else:
            evening = 19 <= t.astimezone(tz).hour <= 22     # the home's busy Wi-Fi hours
            ms = hrng.uniform(1.8, 4.5) + (hrng.uniform(0, 4) if evening else 0)
            rows.append((ts, "gateway", 1, round(ms, 2), 0.0, "ping"))
        t += timedelta(minutes=1)
    with db:
        db.executemany("""INSERT INTO health_samples (ts, target, ok, latency_ms, loss, method)
                          VALUES (?, ?, ?, ?, ?, ?)""", rows)
    # The ISP outage: the router answers, but every forwarded lookup fails.
    cam = next(d for d in DEVICES if d["mac"] == OUTAGE_CLIENT)
    events = []
    for start, n, kind in incidents:
        if kind != "isp":
            continue
        for k in range(n):
            for j in range(OUTAGE_LOOKUPS):
                ev = _event(cam, _utc(start + timedelta(minutes=k, seconds=4 + 11 * j,
                                                        microseconds=hrng.randrange(1_000_000))),
                            OUTAGE_DOMAINS[j % len(OUTAGE_DOMAINS)], "A", False)
                ev.update(status="SERVFAIL", cached=0, elapsed_ms=round(hrng.uniform(4000, 5000), 1))
                events.append(ev)
    store.insert_events(db, events)
    nethealth.update_outages(db, now, hours=HEALTH_HOURS + 1)
    s = DNS_STATS
    store.set_meta(db, "dns_server_stats", json.dumps(
        dns_ingest.stats_summary("adguard", s["queries"], s["blocked"], s["avg_ms"],
                                 s["upstreams"])))
    return len(rows)


# Decisions the demo family already made (seeded once per DB, like the owners): the
# nameless phone is a guest's (dismissed); they pasted the tracker rules into AdGuard
# (done - netwarden waits to see them take effect). Kinds not active are skipped.
DEMO_SUGGESTIONS = (("names", "dismissed"), ("trackers", "done"))
SCORE_HISTORY = (-12, -12, -11, -10, -10, -8, -7, -7, -6, -4, -4, -3, -2, -1)  # 14 d .. 1 d ago


def _seed_suggestions(db) -> None:
    """A few suggestions the family already acted on: once per demo DB, never over a
    status the user set themselves."""
    if store.get_meta(db, "demo_suggestions") == "1":
        return
    from netwarden import suggestions
    states = store.suggestion_states(db)
    det = suggestions.detect(db, {})
    ids = {i["id"]: i for i in det["active"]}
    for kind, status in DEMO_SUGGESTIONS:
        for sid, item in ids.items():
            if item["kind"] == kind and sid not in states:
                suggestions.set_status(db, sid, status, None, {})
                break
    store.set_meta(db, "demo_suggestions", "1")


# Stage M: two phones the demo family already paired (System -> Open on your phone).
# The token hashes are not hex digests, so no cookie can ever match them: they are for
# display only. (paired days ago, last used hours ago, user agent)
DEMO_SESSIONS = (
    (6, 2, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
           "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"),
    (19, 70, "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/129.0.0.0 Mobile Safari/537.36"),
)


DEMO_ADMIN_SESSION = (12, 30, "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:131.0) "
                              "Gecko/20100101 Firefox/131.0")


def _seed_sessions(db, now: datetime) -> None:
    """Paired phones: inserted once per demo DB (one the user revoked stays revoked);
    later builds only move the remaining ones' times along with the rest of the demo."""
    first = store.get_meta(db, "demo_sessions") != "1"
    with db:
        for i, (days, hours, ua) in enumerate(DEMO_SESSIONS, 1):
            created, seen = now - timedelta(days=days), now - timedelta(hours=hours)
            vals = (_utc(created), _utc(seen), _utc(seen + timedelta(days=30)), f"demo:{i}")
            if first:
                db.execute("INSERT OR IGNORE INTO sessions (created_at, last_seen, expires_at, "
                           "token_hash, label) VALUES (?, ?, ?, ?, ?)", (*vals, ua))
            else:
                db.execute("UPDATE sessions SET created_at = ?, last_seen = ?, expires_at = ? "
                           "WHERE token_hash = ?", vals)
    store.set_meta(db, "demo_sessions", "1")


def _seed_admin_session(db, now: datetime) -> None:
    """Round 6: the laptop that claimed this (made-up) headless box with `pair --admin` -
    the "Admin" badge in the paired list. Added once per demo DB (older ones included);
    its token_hash is no SHA-256, so no cookie can ever open it."""
    admin_first = store.get_meta(db, "demo_admin_session") != "1"
    days, hours, ua = DEMO_ADMIN_SESSION
    vals = (_utc(now - timedelta(days=days)), _utc(now - timedelta(hours=hours)),
            _utc(now - timedelta(hours=hours) + timedelta(days=30)), "demo:admin")
    with db:
        if admin_first:
            db.execute("INSERT OR IGNORE INTO sessions (created_at, last_seen, expires_at, "
                       "token_hash, label, admin) VALUES (?, ?, ?, ?, ?, 1)", (*vals, ua))
        else:
            db.execute("UPDATE sessions SET created_at = ?, last_seen = ?, expires_at = ? "
                       "WHERE token_hash = ?", vals)
    store.set_meta(db, "demo_admin_session", "1")


# Stage X: the family's own choice on the Settings page - "Snooze" hides an inbox item for
# 3 days instead of 7 (so the page shows a "changed here" setting). Seeded once per demo
# DB and only while unset. (Acks: only the Stage Q tuning rows below, once per DB.)
DEMO_SETTINGS = {"alerts.snooze_days": "3"}   # key -> stored JSON text


def _seed_settings(db) -> None:
    if store.get_meta(db, "demo_settings") == "1":
        return
    stored = store.get_settings(db)
    store.put_settings(db, {k: v for k, v in DEMO_SETTINGS.items() if k not in stored})
    store.set_meta(db, "demo_settings", "1")


# Stage Q: the family turned quiet hours on (23:00-07:00) - seeded once, only keys the
# user has not stored themselves.
DEMO_QUIET = {"quiet.enabled": "true", "quiet.start": '"23:00"', "quiet.end": '"07:00"'}
# ... and tuned a few alerts, as the Tuning panel shows them: (mac, ack domain, days or
# None = until I change it). Chosen so that no alert the demo shows disappears.
DEMO_TUNING = (
    ("f4:f5:d8:6c:21:0e", "mute:night", 7),     # Chromecast: off for a week
    ("70:9e:29:55:3b:81", "mute:spike", 1),     # PS5 game downloads: off for a day
    ("5c:e9:1e:7a:44:b8", "less:night", None),  # robot vacuum: less sensitive
)
# never critical, and never a kind the family had already seen two days before (SEEN_KINDS:
# the Twitch change once landed in last night's summary on afternoon builds, so it showed
# up again in "Since your last visit")
SUMMARY_KINDS = ("night", "new", "bedtime", "visibility")
SUMMARY_MAX = 4


def _seed_tuning(db, now: datetime) -> None:
    """Tuning acks: inserted once per demo DB (a restored/changed one stays the user's);
    later builds only move the expiries of the untouched rows along with the demo."""
    first = store.get_meta(db, "demo_tuning") != "1"
    with db:
        for mac, dom, days in DEMO_TUNING:
            created = _utc(now - timedelta(hours=5))
            until = _utc(now + timedelta(days=days)) if days else None
            if first:
                db.execute("INSERT OR IGNORE INTO acks (mac, domain, created_at, until) "
                           "VALUES (?, ?, ?, ?)", (mac, dom, created, until))
            elif days:
                db.execute("UPDATE acks SET created_at = ?, until = ? WHERE mac = ? AND "
                           "domain = ? AND until IS NOT NULL", (created, until, mac, dom))
    store.set_meta(db, "demo_tuning", "1")


# Round 10 N: two PAUSED example notification channels on .invalid hosts (the demo home
# never sends: push.collect / deliver / test refuse a demo DB) + a synthetic delivery log.
DEMO_PUSH = (
    ("Phone (ntfy)", "ntfy", {"url": "https://ntfy.home.invalid", "topic": "netwarden-demo"}, {},
     {"level": "standard", "categories": ["security", "devices", "health"], "daily": True}),
    ("Kitchen tablet (Gotify)", "gotify", {"url": "http://gotify.home.invalid:8080"},
     {"token": "demo-not-a-real-token"},
     {"level": "minimal", "categories": ["security", "family"], "min_sev": 1}),
)
# (channel index, hours ago, kind, category, ok, error class, http status, messages)
DEMO_PUSH_LOG = (
    (0, 50, "test", "test", 1, None, 200, 1), (0, 30, "alert", "devices", 1, None, 200, 1),
    (0, 26, "daily", "digest", 1, None, 200, 1), (0, 9, "summary", "security", 1, None, 200, 3),
    (0, 3, "alert", "health", 0, "http_5xx", 502, 1), (0, 2, "alert", "health", 1, None, 200, 1),
    (1, 40, "test", "test", 0, "http_401", 401, 1), (1, 39, "test", "test", 1, None, 200, 1),
    (1, 8, "alert", "security", 1, None, 200, 1),
)


def _seed_push(db, now: datetime) -> None:
    """The channels: inserted once per demo DB (an edited or deleted one stays the user's
    choice). Their delivery log is synthetic and rewritten on every build, relative to now."""
    if store.get_meta(db, "demo_push") != "1":
        with db:
            ids = []
            for name, ctype, fields, secrets, opts in DEMO_PUSH:
                if db.execute("SELECT 1 FROM push_channels WHERE name = ?", (name,)).fetchone():
                    ids.append(None)
                    continue
                cfg = json.dumps({"fields": fields, **opts, "confirmed": False})
                cur = db.execute("""INSERT INTO push_channels (name, type, enabled, primed, config, secrets,
                                        source, created_at, updated_at) VALUES (?, ?, 0, 0, ?, ?, 'db', ?, ?)""",
                                 (name, ctype, cfg, json.dumps(secrets), _utc(now - timedelta(days=3)),
                                  _utc(now - timedelta(days=3))))
                ids.append(cur.lastrowid)
        store.set_meta(db, "demo_push_ids", ",".join(str(i or "") for i in ids))
        store.set_meta(db, "demo_push", "1")
    ids = [int(x) if x else None for x in (store.get_meta(db, "demo_push_ids") or "").split(",")]
    with db:
        for i, cid in enumerate(ids):
            if cid is None or not db.execute("SELECT 1 FROM push_channels WHERE id = ?", (cid,)).fetchone():
                continue
            db.execute("DELETE FROM push_log WHERE channel_id = ?", (cid,))
            last_ok = last_err = None
            for (ci, hours, kind, cat, ok, err, status, n) in DEMO_PUSH_LOG:
                if ci != i:
                    continue
                ts = _utc(now - timedelta(hours=hours))
                db.execute("INSERT INTO push_log (channel_id, ts, kind, category, ok, error, status, n) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (cid, ts, kind, cat, ok, err, status, n))
                last_ok, last_err = (ts, None) if ok else (last_ok, (err, ts))
            db.execute("UPDATE push_channels SET last_ok_ts = ?, last_error = ?, last_error_ts = ? "
                       "WHERE id = ?", (last_ok, last_err[0] if last_err else None,
                                        last_err[1] if last_err else None, cid))


def _seed_quiet(db, now: datetime, tz) -> None:
    """Quiet hours on, plus last night's "while you were asleep" summary - written once
    per demo DB, the way notify.release() would have (the held events marked released,
    so they never pop up again)."""
    if store.get_meta(db, "demo_quiet") == "1":
        _repair_quiet(db)
        return
    from netwarden import inbox, notify
    stored = store.get_settings(db)
    store.put_settings(db, {k: v for k, v in DEMO_QUIET.items() if k not in stored})
    day = now.astimezone(tz).date()
    end = datetime.combine(day, datetime.min.time().replace(hour=7), tz)
    if end > now:
        end -= timedelta(days=1)
    start = end - timedelta(hours=8)
    win = start.astimezone(tz).date().isoformat()
    items, seen = [], set()
    for it in inbox.alert_items(db, "en", 24):
        # only what had happened by the end of that night (a device that joins in the
        # evening after it is not "while you were asleep")
        if it.get("when") and it["when"] >= _utc(end):
            continue
        if it["kind"] in SUMMARY_KINDS and not it["critical"] and len(items) < SUMMARY_MAX \
                and (it["kind"], it["mac"]) not in seen:
            seen.add((it["kind"], it["mac"]))
            ts = _utc(start + timedelta(minutes=50 + 70 * len(items)))
            items.append({"key": it["nkey"], "kind": notify.ALERT + it["kind"], "ts": ts,
                          "mac": it["mac"], "name": it["name"], "detail": it.get("detail")})
    with db:
        for it in items:
            db.execute("""INSERT OR IGNORE INTO notify_log (key, kind, ts, state, critical, win,
                                                            until, data)
                          VALUES (?, ?, ?, 'released', 0, ?, ?, ?)""",
                       (it["key"], it["kind"], it["ts"], win, _utc(end),
                        json.dumps({k: it[k] for k in ("mac", "name", "detail")},
                                   ensure_ascii=False)))
        if items:
            db.execute("""INSERT OR IGNORE INTO quiet_summaries
                          (win, start_ts, end_ts, items, created_at) VALUES (?, ?, ?, ?, ?)""",
                       (win, _utc(start), _utc(end), json.dumps(items, ensure_ascii=False),
                        _utc(end)))
    notify.prime(db)
    store.set_meta(db, "demo_quiet", "1")


def _repair_quiet(db) -> None:
    """Older demo DBs: the seeded summary listed a "new device" that joined only AFTER
    that night ended, or an alert the family had seen two days before (SEEN_KINDS). Drop
    such lines (idempotent; the summary's seen state stays); _seed_seen then logs the
    latter as seen."""
    from netwarden import notify
    seen = {notify.ALERT + k for k in SEEN_KINDS}
    for s in db.execute("SELECT id, end_ts, items FROM quiet_summaries").fetchall():
        items = json.loads(s["items"] or "[]")
        keep, drop = [], []
        for it in items:
            row = db.execute("SELECT first_seen FROM devices WHERE mac = ?",
                             (it.get("mac"),)).fetchone() if it.get("kind") == "alert.new" else None
            if it.get("kind") in seen:
                drop.append(it)
            elif row is None or row["first_seen"] < s["end_ts"]:
                keep.append(it)
        if len(keep) != len(items):
            with db:
                for it in drop:
                    db.execute("DELETE FROM notify_log WHERE key = ? AND state = 'released'",
                               (it.get("key"),))
                if keep:
                    db.execute("UPDATE quiet_summaries SET items = ? WHERE id = ?",
                               (json.dumps(keep, ensure_ascii=False), s["id"]))
                else:
                    db.execute("DELETE FROM quiet_summaries WHERE id = ?", (s["id"],))


# Stage T: what the family had already seen two days ago (a real install logs an alert's
# first routing in notify_log the first time a page or loop looks): the camera's old
# findings, the Twitch change, bedtime nights before yesterday. Last night's outages, the
# backup spike and the newest bedtime night stay unseen, so "Since your last visit" (a
# visit ~12 h ago) has a short, believable list. INSERT OR IGNORE: a real routing wins.
SEEN_KINDS = ("threat", "exposure", "upnp", "change")


def _seed_seen(db, now: datetime, tz) -> None:
    from netwarden import inbox, notify
    seen_ts = _utc(now - timedelta(days=2))
    yesterday = (now.astimezone(tz).date() - timedelta(days=1)).isoformat()
    with db:
        for it in inbox.alert_items(db, "en", 24):
            old_night = it["kind"] == "bedtime" and it["nkey"].rsplit(":", 1)[-1] < yesterday
            if it["kind"] in SEEN_KINDS or old_night:
                db.execute("""INSERT OR IGNORE INTO notify_log (key, kind, ts, state, critical,
                                                                win, until, data)
                              VALUES (?, ?, ?, 'sent', ?, NULL, NULL, ?)""",
                           (it["nkey"], notify.ALERT + it["kind"], seen_ts, int(bool(it["critical"])),
                            json.dumps({"mac": it["mac"], "name": it["name"]}, ensure_ascii=False)))


# Round 7 C: what the family's AI questions cost this month - (days ago, hour, requests,
# input, cache write, cache read, output). The first question of a sitting writes the
# cache, follow-ups minutes later read it; one evening went to the Ollama box on the LAN
# (tokens, no price). Synthetic rows (mode "demo") are rewritten every build; a real
# answer asked on the demo DB keeps its own row. The US$1 monthly budget is seeded once,
# only while unset (DEMO_USAGE_SETTINGS).
DEMO_USAGE = [
    (0, 1, 2, 1150, 6900, 0, 420), (0, 1, 2, 1310, 380, 13100, 510),
    (1, 3, 1, 640, 5200, 0, 380), (2, 2, 3, 1700, 7400, 12600, 690),
    (3, 4, 2, 980, 6100, 6100, 450), (5, 2, 1, 700, 0, 5300, 300),
    (6, 5, 2, 1200, 6800, 0, 520), (8, 3, 2, 1100, 400, 12900, 470),
    (9, 2, 4, 2600, 7900, 20500, 880), (12, 6, 2, 1000, 6400, 6400, 410),
    (15, 1, 1, 650, 5100, 0, 350), (19, 4, 2, 1240, 6700, 6900, 600),
    (26, 2, 2, 1080, 6300, 6300, 430), (34, 3, 3, 1500, 7000, 13000, 640),
]
DEMO_USAGE_LOCAL = [(4, 0, 2, 9800, 0, 0, 610)]
DEMO_USAGE_MODEL = "claude-sonnet-5-5"
DEMO_USAGE_SETTINGS = {"ai.monthly_budget": '"1"'}


DEMO_USAGE_SPAN = max(d for d, *_ in DEMO_USAGE + DEMO_USAGE_LOCAL)


def build_ai_usage(db, now: datetime, tz) -> int:
    """The rows land inside the CURRENT local month whatever the date (the Settings card
    shows "this month"): the story's days are scaled to the days elapsed so far, so on
    the 2nd every question sits on the 1st or 2nd - never in last month."""
    from netwarden import usage
    price = usage.table_price(DEMO_USAGE_MODEL)
    local = now.astimezone(tz)
    evening = local.replace(hour=20, minute=0, second=0, microsecond=0)
    first = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elapsed = local.day - 1                     # whole days of this month before today
    rows = []
    for spec, (provider, model, dest) in ((DEMO_USAGE, ("Anthropic", DEMO_USAGE_MODEL, "cloud")),
                                          (DEMO_USAGE_LOCAL, ("Ollama", "llama3.2", "lan"))):
        for days, hour, req, inp, write, read, out in spec:
            days = days * elapsed // DEMO_USAGE_SPAN
            t = min(evening - timedelta(days=days, hours=hour), now - timedelta(minutes=40 + hour))
            t = min(max(t, first + timedelta(minutes=5 + hour)), now)
            tok = {"requests": req, "input_tokens": inp, "cache_write_tokens": write,
                   "cache_read_tokens": read, "output_tokens": out}
            rows.append({"ts": _utc(t), "provider": provider, "model": model, "destination": dest,
                         "mode": "demo", **tok,
                         "cost_usd": usage.cost(tok, price) if dest == "cloud" else None})
    with db:
        db.execute("DELETE FROM ai_usage WHERE mode = 'demo'")
    for r in rows:
        store.add_ai_usage(db, r)
    if store.get_meta(db, "demo_usage_settings") != "1":
        stored = store.get_settings(db)
        store.put_settings(db, {k: v for k, v in DEMO_USAGE_SETTINGS.items() if k not in stored})
        store.set_meta(db, "demo_usage_settings", "1")
    return len(rows)


def build_score_history(db, now: datetime, tz) -> int:
    """Two weeks of daily home scores leading up to today's live one (synthetic)."""
    from netwarden import score
    res = score.compute(db, {})
    if res["score"] is None:
        return 0
    parts = {p: v["score"] for p, v in res["pillars"].items()}
    day = now.astimezone(tz).date()
    for i, delta in enumerate(SCORE_HISTORY):
        d = day - timedelta(days=len(SCORE_HISTORY) - i)
        store.put_score(db, d.isoformat(), max(0, min(100, res["score"] + delta)), parts,
                        ts=_utc(now - timedelta(days=len(SCORE_HISTORY) - i)))
    return len(SCORE_HISTORY)


def build(path: Path = DEMO_DB, now: datetime | None = None, household: str | None = None) -> dict:
    """(Re)seed the demo home at `path`. The story is laid out relative to `now` (default:
    the wall clock, read ONCE here - nothing below reads it again), so two builds with the
    same `now` write the same rows; tests pin it instead of racing the clock.
    `household` (a HOUSEHOLDS key) picks the family's words on a NEW demo DB; a DB keeps
    the household it was first seeded with (meta demo_household; older DBs: zh-Hant), so
    the names rewritten on every build always match the owners the user already has."""
    RNG.seed(SEED)  # same home on every build, even several in one process
    if household is not None and household not in HOUSEHOLDS:
        raise ValueError(f"demo.build: unknown household {household!r}")
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        raise ValueError("demo.build: now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    baseline_first_seen = (now - timedelta(days=FIRST_SEEN_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    recent_first_seen = (now - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    tz = activity.local_tz()   # "day" / "night" are LOCAL hours, as the dashboard shows them
    db = store.connect(path)
    _check_disposable(db, path)
    # Idempotent: the synthetic data is disposable, so start clean every run. The
    # user's own notes (device_labels, acks) are deliberately kept.
    with db:
        db.execute("DELETE FROM dns_events")
        db.execute("DELETE FROM devices")
        db.execute("DELETE FROM ingest_state")
        db.execute("DELETE FROM traffic_samples")
        db.execute("DELETE FROM port_checks")
        db.execute("DELETE FROM device_identity")
        db.execute("DELETE FROM upnp_snapshots")
        db.execute("DELETE FROM upnp_mappings")
        db.execute("DELETE FROM health_samples")
        db.execute("DELETE FROM outages")
        # synthetic outages only: restart their ids, so a "Got it" on a demo outage still
        # matches it after a reseed (a REAL DB never reuses an id - see store._autoincrement)
        db.execute("DELETE FROM sqlite_sequence WHERE name = 'outages'")
        db.execute("DELETE FROM score_history")
        db.execute("DELETE FROM presence_samples")
    seeded = store.get_meta(db, "demo") == "1"
    store.set_meta(db, "demo", "1")
    kept = store.get_meta(db, "demo_household")
    if kept not in HOUSEHOLDS:
        kept = DEFAULT_HOUSEHOLD if seeded else (household or DEFAULT_HOUSEHOLD)
        store.set_meta(db, "demo_household", kept)
    h = HOUSEHOLDS[kept]

    uniq = 0
    total_events = 0
    for d in DEVICES:
        recent_only = d.get("recent_only", False)
        first_seen = recent_first_seen if recent_only else baseline_first_seen
        if d.get("first_seen_days"):
            first_seen = _utc(now - timedelta(days=d["first_seen_days"]))
        store.upsert_device(
            db,
            {k: d[k] for k in ("ip", "mac", "vendor", "hostname", "randomized", "is_self")},
            seen=first_seen,
        )

        events = []
        quiet = d.get("quiet_hours", 0)
        for (domain, qtype, count, blocked, when) in d["profile"]:
            if d.get("daytime_only"):
                when = "daytime"
            # Rich recent window (last 24h) - what the dashboard and brain analyze.
            if when == "hourly":   # once in every clock hour (until the device went quiet)
                for k in range(quiet, 24):
                    uniq += 1
                    events.append(_event(d, _ts_hourly(now, k, uniq), domain, qtype, blocked))
            for _ in range(count if when != "hourly" else 0):
                uniq += 1
                ts = _ts_recent(now, when, uniq, tz)
                if quiet:
                    ts = _before_quiet(ts, now, quiet)
                events.append(_event(d, ts, domain, qtype, blocked))
            # Lighter baseline history (last week) - unless this device is brand-new.
            if not recent_only:
                for _ in range(N_BASELINE):
                    uniq += 1
                    events.append(_event(d, _ts_baseline(now, uniq, when, tz), domain, qtype,
                                         blocked))

        # Services that appear ONLY in the recent window (a planted behavior change):
        for (domain, qtype, count, blocked, when) in d.get("new_in_recent", []):
            for _ in range(count):
                uniq += 1
                events.append(_event(d, _ts_recent(now, when, uniq, tz), domain, qtype, blocked))

        # Stage D2: lookups in the small hours of the last two nights (own RNG, so the
        # rest of the home stays exactly as before).
        if d.get("night_burst"):
            brng = random.Random(SEED + 1)
            for start, end in night_burst_windows(now, tz):
                secs = max(60, int((end - start).total_seconds()))
                for domain, count in d["night_burst"]:
                    for _ in range(count):
                        uniq += 1
                        t = start + timedelta(seconds=brng.randrange(secs - 30),
                                              microseconds=(uniq * 997) % 1_000_000)
                        events.append(_event(d, _utc(t), domain, "A", False))

        store.insert_events(db, events)
        total_events += len(events)

    total_events += echo_last_week(db, now)
    total_events += build_family(db, now, tz)
    total_events += build_presence(db, now, tz)
    samples = build_traffic(db, now)
    with db:  # a device was last seen at its newest DNS query, not when it first joined
        db.execute("""UPDATE devices SET last_seen = (
                          SELECT MAX(ts) FROM dns_events WHERE device_mac = devices.mac)
                      WHERE EXISTS (SELECT 1 FROM dns_events WHERE device_mac = devices.mac)""")
        # ... except the two DNS-visibility devices: the last sweep still saw them online
        just_now = (now - timedelta(minutes=SEEN_JUST_NOW_MIN)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        for d in DEVICES:
            if d.get("quiet_hours") or d.get("no_dns"):
                db.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (just_now, d["mac"]))
        # ... and a phone the presence check found answers is seen then too (as
        # presence.check_recorded does): "probably home" never sits next to "offline"
        db.execute("""UPDATE devices SET last_seen = (
                          SELECT MAX(ts) FROM presence_samples WHERE mac = devices.mac)
                      WHERE (SELECT MAX(ts) FROM presence_samples WHERE mac = devices.mac)
                            > last_seen""")
    checks = build_port_checks(db, now)
    build_identity(db, now, h)
    build_upnp(db, now)
    probes = build_health(db, now, tz)
    _seed_health(db, now, total_events, samples)
    _seed_profiles(db, now, h)
    _seed_people(db, now, h)
    _seed_rules(db, h)
    _seed_suggestions(db)
    _seed_sessions(db, now)
    _seed_admin_session(db, now)
    _seed_settings(db)
    _seed_tuning(db, now)
    _seed_quiet(db, now, tz)
    _seed_push(db, now)
    _seed_seen(db, now, tz)
    build_score_history(db, now, tz)
    build_ai_usage(db, now, tz)
    db.close()
    from netwarden import cache
    cache.clear()     # the seeding computed alerts on a half-built home: never reuse those
    return {"devices": len(DEVICES), "events": total_events, "traffic_samples": samples,
            "port_checks": checks, "health_probes": probes, "path": str(path), "household": kept}


def ensure(path: Path = DEMO_DB) -> bool:
    """Seed the demo DB if it is missing or not marked demo yet. True if it seeded."""
    path = Path(path)
    if path.exists():
        db = store.connect(path)
        try:
            if store.is_demo(db):
                return False
        finally:
            db.close()
    build(path)
    return True


def main(argv=None, prog=None) -> int:
    import argparse
    import sys
    from netwarden import brain
    lang = i18n.normalize(brain.load_env().get("NETWARDEN_LANG"))
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.demo", lang))
    ap.add_argument("--db", default=str(DEMO_DB), help=i18n.t("cli.opt.db_demo", lang))
    ap.add_argument("--lang", default=None, help=i18n.t("cli.opt.lang", lang))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang)
    try:
        stats = build(Path(args.db))
    except NotADemoDB as e:
        print(i18n.t("cli.demo.refuse", lang, path=e), file=sys.stderr)
        return 1
    print(i18n.t("cli.demo.done", lang, devices=stats["devices"], events=stats["events"],
                 samples=stats["traffic_samples"], path=stats["path"]))
    print(i18n.t("cli.demo.next", lang))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
