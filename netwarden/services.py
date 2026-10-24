#!/usr/bin/env python3
"""
netwarden - services.py: map a DNS domain to the human-facing service/app behind it,
plus a rough category.

This is what lets netwarden say "this device is using Instagram, iCloud and YouTube"
instead of showing raw domains - and it sharpens the brain's input (the snapshot carries
these names, so the AI reasons from consistent labels instead of guessing every time).

Deterministic, local, zero-dependency. Matching is by domain suffix: a domain matches an
entry if it equals the key or ends with "." + key; the LONGEST matching suffix wins (so
push.apple.com -> "Apple push" beats apple.com -> "Apple services").

Names are language-neutral SERVICE IDS, localized on the way out:
  - a brand is its own id and is never translated:          "Instagram"
  - a generic descriptor is a locale key:                   "svc.apple_push"
  - a templated one carries its brand after a "|":          "svc.ads|Google"
Categories are stable keys ("social", "iot", ...); their text is "cat.<key>" in
netwarden/locales/*.json. English is the default (the canonical text the LLM reads).

Extending it is a one-line PR: add "suffix": ("Brand or svc.key", "category") below
(and, for a new svc./cat. key, one line in each locale file).
"""
from __future__ import annotations

from functools import lru_cache

from netwarden import i18n

# domain suffix -> (service id, category key)
SERVICES = {
    # --- social / messaging ---
    "instagram.com": ("Instagram", "social"),
    "cdninstagram.com": ("Instagram", "social"),
    "facebook.com": ("Facebook", "social"),
    "fbcdn.net": ("Facebook", "social"),
    "tiktokv.com": ("TikTok", "social"),
    "tiktokcdn.com": ("TikTok", "social"),
    "musical.ly": ("TikTok", "social"),
    "whatsapp.net": ("WhatsApp", "social"),
    "line.me": ("LINE", "social"),
    "discord.com": ("Discord", "social"),
    "telegram.org": ("Telegram", "social"),

    # --- video / streaming ---
    "youtube.com": ("YouTube", "video"),
    "googlevideo.com": ("YouTube", "video"),
    "ytimg.com": ("YouTube", "video"),
    "netflix.com": ("Netflix", "video"),
    "nflxvideo.net": ("Netflix", "video"),
    "nflximg.net": ("Netflix", "video"),
    "spotify.com": ("Spotify", "video"),
    "scdn.co": ("Spotify", "video"),
    "twitch.tv": ("Twitch", "video"),
    "disneyplus.com": ("Disney+", "video"),

    # --- cloud / sync ---
    "icloud.com": ("iCloud", "cloud"),
    "googleapis.com": ("svc.google_services", "cloud"),
    "dropbox.com": ("Dropbox", "cloud"),
    "onedrive.com": ("OneDrive", "cloud"),

    # --- system / platform ---
    "apple.com": ("svc.apple_services", "system"),
    "push.apple.com": ("svc.apple_push", "system"),
    "mzstatic.com": ("Apple", "system"),
    "gstatic.com": ("Google", "system"),
    "google.com": ("Google", "system"),
    "microsoft.com": ("Microsoft", "system"),
    "update.microsoft.com": ("svc.windows_update", "system"),
    "windowsupdate.com": ("svc.windows_update", "system"),

    # --- tools / dev ---
    "github.com": ("GitHub", "dev"),
    "anthropic.com": ("Anthropic API", "dev"),
    "openai.com": ("OpenAI API", "dev"),

    # --- ads / tracking ---
    "doubleclick.net": ("svc.ads|Google", "ads"),
    "googlesyndication.com": ("svc.ads|Google", "ads"),
    "google-analytics.com": ("Google Analytics", "ads"),
    "app-measurement.com": ("svc.firebase_analytics", "ads"),
    "amazon-adsystem.com": ("svc.ads|Amazon", "ads"),
    "samsungads.com": ("svc.ads|Samsung", "ads"),
    "scorecardresearch.com": ("svc.tracking|Comscore", "ads"),
    "adnxs.com": ("svc.ads|AppNexus", "ads"),
    "criteo.com": ("svc.ads|Criteo", "ads"),

    # --- IoT / device phone-home ---
    "xmeye.net": ("svc.xmeye", "iot"),
    "secu100.net": ("svc.xiongmai_cloud", "iot"),
    "samsungacr.com": ("svc.samsung_acr", "iot"),
    "samsungcloudsolution.com": ("svc.samsung_tv_cloud", "iot"),
    "alexa.amazon.com": ("Amazon Alexa", "iot"),
    "avs-alexa-na.amazon.com": ("svc.alexa_voice", "iot"),
    "device-metrics-us.amazon.com": ("svc.amazon_telemetry", "iot"),
    "tuyaus.com": ("svc.tuya", "iot"),
    "roborock.com": ("svc.roborock", "iot"),

    # --- gaming ---
    "playstation.net": ("PlayStation", "gaming"),
    "playstation.com": ("PlayStation", "gaming"),
    "xboxlive.com": ("Xbox Live", "gaming"),
    "steampowered.com": ("Steam", "gaming"),

    # --- device services / hardware ---
    "hp.com": ("HP", "device"),
    "hpeprint.com": ("svc.hp_print", "device"),

    # --- network gear ---
    # the maker's admin page / cloud of a home router (templated: "{brand} router")
    "tplinkwifi.net": ("svc.router|TP-Link", "network"),
    "tplinkcloud.com": ("svc.router|TP-Link", "network"),
    "routerlogin.net": ("svc.router|NETGEAR", "network"),
    "asusrouter.com": ("svc.router|ASUS", "network"),

    # --- shopping ---
    "amazon.com": ("Amazon", "shopping"),

    # --- time sync ---
    "ntp.org": ("svc.time|NTP", "system"),
    "pool.ntp.org": ("svc.time|NTP", "system"),
    "time.apple.com": ("svc.time|Apple", "system"),
    "time.windows.com": ("svc.time|Windows", "system"),
    "time.google.com": ("svc.time|Google", "system"),
    "time.cloudflare.com": ("svc.time|Cloudflare", "system"),
    "stdtime.gov.tw": ("svc.time|NTP", "system"),

    # === Stage N: services common in Taiwan / Asia, plus big global ones ===============
    # --- social / messaging / forums ---
    "line-apps.com": ("LINE", "social"),
    "line-scdn.net": ("LINE", "social"),
    "line-cdn.net": ("LINE", "social"),
    "pay.line.me": ("LINE Pay", "finance"),
    "whatsapp.com": ("WhatsApp", "social"),
    "messenger.com": ("Messenger", "social"),
    "threads.net": ("Threads", "social"),
    "twitter.com": ("X (Twitter)", "social"),
    "x.com": ("X (Twitter)", "social"),
    "twimg.com": ("X (Twitter)", "social"),
    "reddit.com": ("Reddit", "social"),
    "redditmedia.com": ("Reddit", "social"),
    "snapchat.com": ("Snapchat", "social"),
    "pinterest.com": ("Pinterest", "social"),
    "linkedin.com": ("LinkedIn", "social"),
    "tiktok.com": ("TikTok", "social"),
    "byteoversea.com": ("TikTok", "social"),
    "wechat.com": ("WeChat", "social"),
    "weixin.qq.com": ("WeChat", "social"),
    "weibo.com": ("Weibo", "social"),
    "kakao.com": ("KakaoTalk", "social"),
    "dcard.tw": ("Dcard", "social"),
    "ptt.cc": ("PTT", "social"),
    "plurk.com": ("Plurk", "social"),
    "zoom.us": ("Zoom", "social"),
    "skype.com": ("Skype", "social"),
    "slack.com": ("Slack", "social"),
    "signal.org": ("Signal", "social"),

    # --- video / music streaming ---
    "kkbox.com": ("KKBOX", "video"),
    "kkbox.com.tw": ("KKBOX", "video"),
    "friday.tw": ("friDay", "video"),
    "myvideo.net.tw": ("myVideo", "video"),
    "catchplay.com": ("CATCHPLAY+", "video"),
    "hamivideo.hinet.net": ("Hami Video", "video"),
    "litv.tv": ("LiTV", "video"),
    "linetv.tw": ("LINE TV", "video"),
    "iqiyi.com": ("iQIYI", "video"),
    "iq.com": ("iQIYI", "video"),
    "viu.com": ("Viu", "video"),
    "primevideo.com": ("Prime Video", "video"),
    "aiv-cdn.net": ("Prime Video", "video"),
    "hulu.com": ("Hulu", "video"),
    "max.com": ("Max", "video"),
    "tv.apple.com": ("Apple TV+", "video"),
    "music.apple.com": ("Apple Music", "video"),
    "soundcloud.com": ("SoundCloud", "video"),
    "bilibili.com": ("bilibili", "video"),
    "hdslb.com": ("bilibili", "video"),
    "vimeo.com": ("Vimeo", "video"),
    "dailymotion.com": ("Dailymotion", "video"),
    "ani.gamer.com.tw": ("svc.bahamut_anime", "video"),

    # --- cloud / productivity ---
    "office.com": ("Microsoft 365", "cloud"),
    "office365.com": ("Microsoft 365", "cloud"),
    "outlook.com": ("Outlook", "cloud"),
    "live.com": ("Microsoft account", "cloud"),
    "sharepoint.com": ("Microsoft 365", "cloud"),
    "teams.microsoft.com": ("Microsoft Teams", "social"),
    "drive.google.com": ("Google Drive", "cloud"),
    "docs.google.com": ("Google Docs", "cloud"),
    "photos.google.com": ("Google Photos", "cloud"),
    "box.com": ("Box", "cloud"),
    "notion.so": ("Notion", "cloud"),
    "evernote.com": ("Evernote", "cloud"),
    "synology.me": ("Synology", "cloud"),
    "quickconnect.to": ("Synology", "cloud"),
    "myqnapcloud.com": ("QNAP", "cloud"),

    # --- tools / AI ---
    "chatgpt.com": ("ChatGPT", "dev"),
    "claude.ai": ("Claude", "dev"),
    "gemini.google.com": ("Gemini", "dev"),
    "stackoverflow.com": ("Stack Overflow", "dev"),
    "githubusercontent.com": ("GitHub", "dev"),
    "pypi.org": ("PyPI", "dev"),
    "npmjs.org": ("npm", "dev"),
    "docker.io": ("Docker", "dev"),
    "docker.com": ("Docker", "dev"),

    # --- news / portals ---
    "yahoo.com": ("Yahoo", "news"),
    "yimg.com": ("Yahoo", "news"),
    "tw.yahoo.com": ("svc.yahoo_tw", "news"),
    "yahoo.com.tw": ("svc.yahoo_tw", "news"),
    "udn.com": ("udn", "news"),
    "chinatimes.com": ("China Times", "news"),
    "ltn.com.tw": ("Liberty Times", "news"),
    "ettoday.net": ("ETtoday", "news"),
    "setn.com": ("SETN", "news"),
    "cna.com.tw": ("CNA", "news"),
    "pts.org.tw": ("PTS", "news"),
    "storm.mg": ("Storm Media", "news"),
    "bbc.co.uk": ("BBC", "news"),
    "bbc.com": ("BBC", "news"),
    "cnn.com": ("CNN", "news"),
    "nytimes.com": ("New York Times", "news"),
    "wikipedia.org": ("Wikipedia", "news"),
    "wikimedia.org": ("Wikipedia", "news"),

    # --- shopping / marketplaces ---
    "shopee.tw": ("Shopee", "shopping"),
    "shopee.com": ("Shopee", "shopping"),
    "shopeemobile.com": ("Shopee", "shopping"),
    "susercontent.com": ("Shopee", "shopping"),
    "momoshop.com.tw": ("momo", "shopping"),
    "pchome.com.tw": ("PChome", "shopping"),
    "ruten.com.tw": ("Ruten", "shopping"),
    "books.com.tw": ("books.com.tw", "shopping"),
    "591.com.tw": ("591", "shopping"),
    "carousell.tw": ("Carousell", "shopping"),
    "carousell.com": ("Carousell", "shopping"),
    "coupang.com": ("Coupang", "shopping"),
    "ikea.com": ("IKEA", "shopping"),
    "taobao.com": ("Taobao", "shopping"),
    "tmall.com": ("Tmall", "shopping"),
    "aliexpress.com": ("AliExpress", "shopping"),
    "temu.com": ("Temu", "shopping"),
    "shein.com": ("SHEIN", "shopping"),
    "ebay.com": ("eBay", "shopping"),
    "rakuten.com.tw": ("Rakuten", "shopping"),
    "booking.com": ("Booking.com", "shopping"),
    "agoda.com": ("Agoda", "shopping"),
    "klook.com": ("Klook", "shopping"),
    "kkday.com": ("KKday", "shopping"),

    # --- food delivery ---
    "foodpanda.com.tw": ("foodpanda", "food"),
    "foodpanda.com": ("foodpanda", "food"),
    "ubereats.com": ("Uber Eats", "food"),
    "uber.com": ("Uber", "food"),

    # --- banks, payments ---
    "ctbcbank.com": ("CTBC Bank", "finance"),
    "cathaybk.com.tw": ("Cathay United Bank", "finance"),
    "esunbank.com.tw": ("E.SUN Bank", "finance"),
    "esunbank.com": ("E.SUN Bank", "finance"),
    "taishinbank.com.tw": ("Taishin Bank", "finance"),
    "fubon.com": ("Fubon", "finance"),
    "megabank.com.tw": ("Mega Bank", "finance"),
    "bot.com.tw": ("Bank of Taiwan", "finance"),
    "firstbank.com.tw": ("First Bank", "finance"),
    "hncb.com.tw": ("Hua Nan Bank", "finance"),
    "tcb-bank.com.tw": ("Taiwan Cooperative Bank", "finance"),
    "landbank.com.tw": ("Land Bank of Taiwan", "finance"),
    "sinopac.com": ("SinoPac", "finance"),
    "linebank.com.tw": ("LINE Bank", "finance"),
    "jkopay.com": ("JKOPAY", "finance"),
    "paypal.com": ("PayPal", "finance"),
    "twse.com.tw": ("TWSE", "finance"),

    # --- telcos / ISPs ---
    "cht.com.tw": ("Chunghwa Telecom", "telecom"),
    "hinet.net": ("Chunghwa Telecom", "telecom"),
    "taiwanmobile.com": ("Taiwan Mobile", "telecom"),
    "fetnet.net": ("FarEasTone", "telecom"),
    "tstartel.com": ("T Star", "telecom"),
    "aptg.com.tw": ("Asia Pacific Telecom", "telecom"),

    # --- government ---
    "gov.tw": ("svc.gov_tw", "gov"),

    # --- gaming ---
    "garena.com": ("Garena", "gaming"),
    "garena.tw": ("Garena", "gaming"),
    "gamer.com.tw": ("svc.bahamut", "gaming"),
    "bahamut.com.tw": ("svc.bahamut", "gaming"),
    "nintendo.net": ("Nintendo", "gaming"),
    "nintendo.com": ("Nintendo", "gaming"),
    "epicgames.com": ("Epic Games", "gaming"),
    "riotgames.com": ("Riot Games", "gaming"),
    "roblox.com": ("Roblox", "gaming"),
    "rbxcdn.com": ("Roblox", "gaming"),
    "minecraft.net": ("Minecraft", "gaming"),
    "battle.net": ("Battle.net", "gaming"),
    "ea.com": ("EA", "gaming"),
    "supercell.com": ("Supercell", "gaming"),
    "hoyoverse.com": ("HoYoverse", "gaming"),
    "mihoyo.com": ("HoYoverse", "gaming"),
    "steamcommunity.com": ("Steam", "gaming"),
    "steamstatic.com": ("Steam", "gaming"),

    # === Stage F: learning (screen time "education") =====================================
    "classroom.google.com": ("Google Classroom", "education"),
    "khanacademy.org": ("Khan Academy", "education"),
    "kastatic.org": ("Khan Academy", "education"),
    "junyiacademy.org": ("Junyi Academy", "education"),
    "duolingo.com": ("Duolingo", "education"),
    "coursera.org": ("Coursera", "education"),
    "udemy.com": ("Udemy", "education"),
    "edx.org": ("edX", "education"),
    "quizlet.com": ("Quizlet", "education"),
    "kahoot.it": ("Kahoot!", "education"),
    "kahoot.com": ("Kahoot!", "education"),
    "scratch.mit.edu": ("Scratch", "education"),
    "pagamo.org": ("PaGamO", "education"),
    "hahow.in": ("Hahow", "education"),
    "brainpop.com": ("BrainPOP", "education"),

    # --- IoT / smart-home clouds ---
    "io.mi.com": ("svc.iot_cloud|Xiaomi", "iot"),
    "miot-spec.org": ("svc.iot_cloud|Xiaomi", "iot"),
    "xiaomi.com": ("Xiaomi", "system"),
    "mi.com": ("Xiaomi", "system"),
    "tuyaeu.com": ("svc.tuya", "iot"),
    "tuyacn.com": ("svc.tuya", "iot"),
    "tuyain.com": ("svc.tuya", "iot"),
    "tuya.com": ("svc.tuya", "iot"),
    "tplinkcloud.com": ("svc.iot_cloud|TP-Link (Tapo/Kasa)", "iot"),
    "tp-link.com": ("TP-Link", "network"),
    "ezvizlife.com": ("svc.camera_cloud|EZVIZ", "iot"),
    "ezviz.com": ("svc.camera_cloud|EZVIZ", "iot"),
    "hik-connect.com": ("svc.camera_cloud|Hikvision", "iot"),
    "imoulife.com": ("svc.camera_cloud|Imou", "iot"),
    "easy4ipcloud.com": ("svc.camera_cloud|Imou (Dahua)", "iot"),
    "easy4ip.com": ("svc.camera_cloud|Imou (Dahua)", "iot"),
    "reolink.com": ("svc.camera_cloud|Reolink", "iot"),
    "wyze.com": ("svc.camera_cloud|Wyze", "iot"),
    "ring.com": ("svc.camera_cloud|Ring", "iot"),
    "ecovacs.com": ("svc.vacuum_cloud|Ecovacs", "iot"),
    "ecouser.net": ("svc.vacuum_cloud|Ecovacs", "iot"),
    "irobot.com": ("svc.vacuum_cloud|iRobot", "iot"),
    "meethue.com": ("svc.iot_cloud|Philips Hue", "iot"),
    "ewelink.cc": ("svc.iot_cloud|eWeLink (Sonoff)", "iot"),
    "smartthings.com": ("svc.iot_cloud|SmartThings", "iot"),
    "nest.com": ("svc.iot_cloud|Google Nest", "iot"),
    "home-assistant.io": ("Home Assistant", "iot"),
    "nabucasa.com": ("Home Assistant", "iot"),
    "sonos.com": ("Sonos", "iot"),
    "lgthinq.com": ("svc.iot_cloud|LG ThinQ", "iot"),
    "lgtvsdp.com": ("svc.tv_cloud|LG", "iot"),
    "lgappstv.com": ("svc.tv_cloud|LG", "iot"),

    # --- device makers' own services ---
    "samsung.com": ("Samsung", "system"),
    "samsungcloud.com": ("Samsung Cloud", "cloud"),
    "hicloud.com": ("svc.huawei_services", "system"),
    "huawei.com": ("Huawei", "system"),
    "asus.com": ("ASUS", "device"),
    "epson.com": ("Epson", "device"),
    "canon.com": ("Canon", "device"),
    "brother.com": ("Brother", "device"),
    "sony.com": ("Sony", "device"),
    "amazon.com.tw": ("Amazon", "shopping"),

    # --- ads / analytics networks (Asia + device makers) ---
    "pangle.io": ("svc.ads|Pangle (ByteDance)", "ads"),
    "pangolin-sdk-toutiao.com": ("svc.ads|Pangle (ByteDance)", "ads"),
    "gdt.qq.com": ("svc.ads|Tencent GDT", "ads"),
    "umeng.com": ("svc.analytics|Umeng", "ads"),
    "umengcloud.com": ("svc.analytics|Umeng", "ads"),
    "hm.baidu.com": ("svc.analytics|Baidu Tongji", "ads"),
    "tongji.baidu.com": ("svc.analytics|Baidu Tongji", "ads"),
    "ad.xiaomi.com": ("svc.ads|Xiaomi", "ads"),
    "ad.intl.xiaomi.com": ("svc.ads|Xiaomi", "ads"),
    "tracking.miui.com": ("svc.analytics|Xiaomi", "ads"),
    "ads.samsung.com": ("svc.ads|Samsung", "ads"),
    "lgsmartad.com": ("svc.ads|LG", "ads"),
    "ad.lgappstv.com": ("svc.ads|LG", "ads"),
    "appier.net": ("svc.ads|Appier", "ads"),
    "appier.com": ("svc.ads|Appier", "ads"),
    "vpon.com": ("svc.ads|Vpon", "ads"),
    "vpadn.com": ("svc.ads|Vpon", "ads"),
    "clickforce.com.tw": ("svc.ads|ClickForce", "ads"),
    "googleadservices.com": ("svc.ads|Google", "ads"),
    "googletagmanager.com": ("svc.analytics|Google", "ads"),
    "admob.com": ("svc.ads|Google", "ads"),
    "applovin.com": ("svc.ads|AppLovin", "ads"),
    "unityads.unity3d.com": ("svc.ads|Unity", "ads"),
    "appsflyer.com": ("svc.analytics|AppsFlyer", "ads"),
    "adjust.com": ("svc.analytics|Adjust", "ads"),
    "taboola.com": ("svc.ads|Taboola", "ads"),
    "outbrain.com": ("svc.ads|Outbrain", "ads"),
}

UNKNOWN_CATEGORY = "unknown"
CATEGORIES = sorted({cat for _sid, cat in SERVICES.values()} | {UNKNOWN_CATEGORY})


@lru_cache(maxsize=65536)
def lookup(domain: str):
    """Return (service_id_or_None, category_key) for a domain. Longest suffix wins:
    walk the domain's own suffixes, longest first - one dict hit per label instead of
    a scan over the whole catalog (search / timeline call this for every domain)."""
    d = (domain or "").lower().strip().strip(".")
    labels = d.split(".")
    for i in range(len(labels)):
        meta = SERVICES.get(".".join(labels[i:]))
        if meta:
            return meta
    return (None, UNKNOWN_CATEGORY)


def service_name(service_id: str | None, lang: str = "en") -> str | None:
    """Service id -> display name in `lang` (brands come back unchanged)."""
    if not service_id or not service_id.startswith("svc."):
        return service_id
    key, _, brand = service_id.partition("|")
    return i18n.t(key, lang, brand=brand)


def category_name(category: str, lang: str = "en") -> str:
    return i18n.t("cat." + (category or UNKNOWN_CATEGORY), lang)


def classify(domain: str, lang: str = "en"):
    """Return (service_name_or_None, category_key) for a domain, the name in `lang`."""
    sid, cat = lookup(domain)
    return service_name(sid, lang), cat


def service_ids_for(domains) -> list:
    """Ordered, de-duplicated service ids for an iterable of domains (unknown skipped)."""
    out = []
    for dom in domains:
        sid, _cat = lookup(dom)
        if sid and sid not in out:
            out.append(sid)
    return out


def services_for(domains, lang: str = "en") -> list:
    """Ordered, de-duplicated list of friendly service names for an iterable of
    domains (unknown domains are skipped). Order follows first appearance."""
    return [service_name(s, lang) for s in service_ids_for(domains)]


def localize_device(dev: dict, lang: str) -> dict:
    """A copy of one brain.snapshot() device with service names in `lang` and a
    `category_name` next to each stable `category` key (for the web/API edge)."""
    from netwarden import routine   # routine is a leaf module; keep the import local anyway
    out = dict(dev)
    tops = []
    for td in dev.get("top_domains", []):
        sid, cat = lookup(td["domain"])
        tops.append({**td, "service": service_name(sid, lang), "service_id": sid, "category": cat,
                     "category_name": category_name(cat, lang),
                     "routine": routine.info(td["domain"], lang)})
    out["top_domains"] = tops
    out["services"] = services_for((td["domain"] for td in tops), lang)
    return out
