#!/usr/bin/env python3
"""
netwarden - i18n.py: which languages we speak, and the translated strings.

One JSON file per language in netwarden/locales/<code>.json: a flat {key: text} map
plus a "_meta" block:

    "_meta": {"name": "日本語",                 # native name (the UI dropdown)
              "llm": "Japanese (日本語)",       # what we tell the LLM to answer in
              "order": 6,                       # position in the dropdown
              "aliases": ["ja-jp", "japanese"]} # extra spellings normalize() accepts

Adding a language = adding one file; nothing in the code lists languages. English
(en.json) is the fallback for any missing key and the canonical text the LLM reads.
Placeholders are {name}, filled by t(key, lang, name=...).

    python3 -m netwarden.i18n            # list languages + check key coverage
    python3 -m netwarden.i18n --check    # every locale problem (see check())
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

LOCALE_DIR = Path(__file__).resolve().parent / "locales"
DEFAULT = "zh-Hant"   # the user is in Taiwan; the weekly digest stays 繁體中文
FALLBACK = "en"       # missing keys fall back to English


@lru_cache(maxsize=1)
def _catalog() -> dict:
    """code -> {key: text, "_meta": {...}} for every locale file."""
    return {p.stem: json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(LOCALE_DIR.glob("*.json"))}


def _langs() -> list:
    rows = []
    for code, data in _catalog().items():
        m = data.get("_meta", {})
        rows.append((m.get("order", 999), code, m.get("name", code), m.get("llm", code)))
    rows.sort()
    return [(code, name, llm) for _o, code, name, llm in rows]


# [(code, native name, English name for LLM prompts)], in UI order.
LANGS = _langs()
CODES = [c for c, _n, _l in LANGS]


def _norm_key(value) -> str:
    return str(value).strip().lower().replace("_", "-")


@lru_cache(maxsize=1)
def _aliases() -> dict:
    """Every accepted spelling (lowercased) -> code: the code itself, the native and
    LLM names, the LLM name without its "(...)" part, plus each file's aliases."""
    out = {}
    for code, name, llm in LANGS:
        extra = _catalog()[code].get("_meta", {}).get("aliases", [])
        for v in [code, name, llm, llm.split("(")[0], *extra]:
            out.setdefault(_norm_key(v), code)
    return out


def match(value) -> str | None:
    """A language code / legacy name / BCP-47 tag -> supported code, or None.
    Tags are tried from most to least specific: zh-Hant-TW -> zh-hant, de-AT -> de."""
    k = _norm_key(value or "")
    aliases = _aliases()
    while k:
        if k in aliases:
            return aliases[k]
        if "-" not in k:
            break
        k = k.rsplit("-", 1)[0]
    return None


def normalize(value) -> str:
    """Like match(), but anything unknown (or empty) becomes the default language."""
    return match(value) or DEFAULT


def from_accept_language(header: str) -> str | None:
    """Best supported language from an HTTP Accept-Language header, or None."""
    prefs = []
    for i, part in enumerate((header or "").split(",")):
        tag, _, params = part.strip().partition(";")
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                q = 0.0
        if tag and tag != "*" and q > 0:
            prefs.append((-q, i, tag))
    for _q, _i, tag in sorted(prefs):
        code = match(tag)
        if code:
            return code
    return None


def native_name(lang: str) -> str:
    code = normalize(lang)
    return next(n for c, n, _l in LANGS if c == code)


def llm_language(lang: str) -> str:
    """The language name we put in the LLM prompt, e.g. 'Traditional Chinese (繁體中文)'."""
    code = normalize(lang)
    return next(l for c, _n, l in LANGS if c == code)


class _Keep(dict):
    def __missing__(self, k):  # an unfilled placeholder stays visible, never crashes
        return "{" + k + "}"


# Round 10e: placeholders that hold a quantity with a unit. A text writes "{pct}", never
# "{pct}%" (the checker's unit_literal): given a NUMBER, t() formats it the language's way
# (pct(14, "de") = "14 %", ms(128, "fr") = "128 ms" with Intl's narrow no-break space); a
# string is taken as already formatted (i18n.pct(x, lang, 1) for a decimal).
PARAM_UNITS = {"pct": "percent", "bpct": "percent", "ms": "millisecond"}


def _with_units(kw: dict, lang: str) -> dict:
    if not any(k in kw for k in PARAM_UNITS):
        return kw
    out = dict(kw)
    for k, name in PARAM_UNITS.items():
        v = out.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            out[k] = ms(v, lang) if name == "millisecond" else \
                unit(v, name, lang, 0 if float(v).is_integer() else 1)
    return out


def t(key: str, lang: str = DEFAULT, **kw) -> str:
    """Translated text for `key` in `lang` (English fallback, then the key itself)."""
    cat = _catalog()
    if lang not in cat:
        lang = normalize(lang)
    if "n" in kw and key in _plural_bases():
        key = plural_key(key, kw["n"], lang)   # a count text given its count: its plural form
    return _t(key, lang, **kw)


def _t(key: str, lang: str, /, **kw) -> str:
    """t() without the plural choice (`lang` already a known code)."""
    cat = _catalog()
    text = cat[lang].get(key)
    if text is None:
        text = cat.get(FALLBACK, {}).get(key, key)
    if not kw:
        return text
    kw = _with_units(kw, lang)
    for k, v in kw.items():
        # a value that already ends a sentence ("44 Std. 59 Min.") at a sentence's end
        # ("... statt {last}.") must not print "Min.."
        if isinstance(v, str) and v.endswith(".") and "{" + k + "}." in text:
            text = text.replace("{" + k + "}.", "{" + k + "}")
    return text.format_map(_Keep(kw))


# Plurals (round 10d): CLDR's plural categories for whole numbers, kept to the languages
# netwarden ships (+ Polish, the usual next one). A count text is ONE base key (CLDR's
# "other": "{n} devices") plus `<key>_one` ("{n} device") and, where the language has
# them, `<key>_few` / `<key>_many` (Russian: 2-4 / 5-20 of a noun). The browser picks the
# same keys with Intl.PluralRules (app.js TN()); `python3 -m netwarden.i18n --check` finds
# count texts without them. Languages without grammatical number (zh, ja, ko, id) carry
# the base text under `_one` too and always use the base.
def _slavic(n: int) -> str:
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return "few"
    return "many"


PLURAL_RULES = {
    "fr": lambda n: "one" if n in (0, 1) else "other",
    "pt-BR": lambda n: "one" if n in (0, 1) else "other",
    "hi": lambda n: "one" if n in (0, 1) else "other",
    "ru": lambda n: "one" if n % 10 == 1 and n % 100 != 11 else _slavic(n),
    "pl": lambda n: "one" if n == 1 else _slavic(n),
    "zh-Hant": lambda n: "other", "zh-Hans": lambda n: "other", "ja": lambda n: "other",
    "ko": lambda n: "other", "id": lambda n: "other",
}
# the categories a language needs besides the base ("other") one
PLURAL_FORMS = {"ru": ("one", "few", "many"), "pl": ("one", "few", "many")}


@lru_cache(maxsize=1)
def _plural_bases() -> frozenset:
    """Every count text with plural forms (English has `<key>_one`)."""
    en = _catalog().get(FALLBACK, {})
    return frozenset(k[:-4] for k in en if k.endswith("_one") and k[:-4] in en)


def plural_category(n, lang: str) -> str:
    """CLDR plural category (one | few | many | other) of the whole number `n` in `lang`
    (also "1,234" as f"{n:,}" writes it); anything else counts as "other"."""
    if isinstance(n, str):
        n = n.replace(",", "")
    try:
        v = int(n)
        if isinstance(n, float) and n != v:
            return "other"
    except (TypeError, ValueError):
        return "other"
    return PLURAL_RULES.get(lang, lambda x: "one" if x == 1 else "other")(abs(v))


def plural_key(key: str, n, lang: str) -> str:
    """The key a count text uses for `n` in `lang`: `key_<category>` when that locale has
    it, else the base key."""
    code = lang if lang in _catalog() else normalize(lang)
    cat = plural_category(n, code)
    return key + "_" + cat if cat != "other" and (key + "_" + cat) in _catalog()[code] else key


def tn(key: str, count, lang: str = DEFAULT, /, **kw) -> str:
    """t() for a text about `count` ({n} = the count unless given, e.g. formatted): the
    language's plural form of `key` ("1 device", "2 devices", Russian "2 устройства" /
    "5 устройств")."""
    code = lang if lang in _catalog() else normalize(lang)
    return _t(plural_key(key, count, code), code, **{"n": count, **kw})


def is_plural(key: str) -> bool:
    """Is `key` a count text with plural forms (English has `key_one`)? t() given such a
    key and an integer `n` picks the form itself; a count under another name ({queries},
    {hosts}) needs tn(key, count, ...)."""
    return key in _plural_bases()


# Numbers in server texts the way the browser's Intl.NumberFormat writes them (round 10d):
# decimal mark and digit grouping per language (CLDR, the languages netwarden ships).
# lang -> (decimal mark, group separator, minimum digits before grouping starts)
_NUM = {"de": (",", ".", 4), "es": (",", ".", 5), "pt-BR": (",", ".", 4), "fr": (",", "\u202f", 4),
        "ru": (",", "\u00a0", 4), "id": (",", ".", 4)}


def _round(value, decimals: int, trim: bool) -> str:
    """abs(value) with `decimals` places, rounded half away from zero on the number's
    shortest decimal form - what Intl.NumberFormat does ("2.25" -> "2.3", not Python's
    "2.2"); `trim` = maximumFractionDigits (no trailing zeros: "12.0" -> "12")."""
    from decimal import ROUND_HALF_UP, Decimal
    d = Decimal(repr(abs(float(value)))).quantize(Decimal(1).scaleb(-decimals), rounding=ROUND_HALF_UP)
    text = f"{d:f}"
    if trim and "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def num(value, lang: str = DEFAULT, decimals: int = 0, trim: bool = False) -> str:
    """`value` with `decimals` places in `lang`: 1234.5 -> "1,234.5" (en), "1.234,5" (de),
    "1 234,5" (fr); Hindi groups in lakhs ("1,23,456"). `trim` = at most `decimals`
    places, like Intl's maximumFractionDigits ("12" rather than "12.0")."""
    code = lang if lang in _catalog() else normalize(lang)
    dec, grp, min_digits = _NUM.get(code, (".", ",", 4))
    text = _round(value, max(0, int(decimals)), trim)
    whole, _, frac = text.partition(".")
    if len(whole) >= min_digits:
        if code == "hi" and len(whole) > 3:   # 12,34,567
            head, tail = whole[:-3], whole[-3:]
            head = ",".join([head[max(0, i - 2):i] for i in range(len(head), 0, -2)][::-1])
            whole = head + "," + tail
        else:
            whole = f"{int(whole):,}".replace(",", grp)
    sign = "-" if float(value) < 0 and float(text) != 0 else ""
    return sign + whole + (dec + frac if frac else "")


# Units the way the browser writes them (round 10e): Intl.NumberFormat(lang, {style: "unit",
# unitDisplay: "short"}) / {style: "percent"} - CLDR, so "12,5 ГБ" in Russian, "12,5 Go" in
# French and "14 %" in German on the server as on the page. "{0}" = the number; the spaces
# are the exact characters Intl uses (U+00A0 no-break, U+202F narrow no-break, none in
# Korean). tests/fixtures/intl_formats.json (made by node from Intl, tests/js/intl_formats_test.js)
# pins every language. A text never writes a unit or "%" itself: it gets the formatted value
# ({pct}, {ms}, {size}) from unit() / pct() / brain.human_bytes() (`i18n --check`: unit_literal).
# "megabit-per-second" (CLI only, no page counterpart, so not in the fixture) is what Intl
# writes too, except Russian: CLDR has a Latin "c" in "Мбит/c"; the server writes "Мбит/с".
UNITS = ("byte", "kilobyte", "megabyte", "gigabyte", "terabyte", "millisecond", "percent",
         "megabit-per-second")
_UNIT_EN = {"byte": "{0} byte", "kilobyte": "{0} kB", "megabyte": "{0} MB", "gigabyte": "{0} GB",
            "terabyte": "{0} TB", "millisecond": "{0} ms", "percent": "{0}%",
            "megabit-per-second": "{0} Mb/s"}
_NB, _NNB = " ", " "
_UNIT_LANG = {
    "zh-Hans": {"byte": "{0} B", "millisecond": "{0}毫秒", "megabit-per-second": "{0} Mb/秒"},
    "zh-Hant": {"millisecond": "{0} 毫秒", "megabit-per-second": "{0} Mb/秒"},
    "es": {"byte": "{0} B", "percent": "{0}" + _NB + "%"},
    "pt-BR": {"byte": "{0} bytes"},
    "ja": {"kilobyte": "{0} KB", "megabit-per-second": "{0} Mb/秒"},
    "de": {"byte": "{0} Byte", "byte_one": "{0}" + _NB + "Byte", "gigabyte": "{0}" + _NB + "GB",
           "percent": "{0}" + _NB + "%"},
    "fr": {"byte": "{0}" + _NNB + "o", "kilobyte": "{0}" + _NNB + "ko", "megabyte": "{0}" + _NNB + "Mo",
           "gigabyte": "{0}" + _NNB + "Go", "terabyte": "{0}" + _NNB + "To",
           "millisecond": "{0}" + _NNB + "ms", "percent": "{0}" + _NB + "%",
           "megabit-per-second": "{0}" + _NNB + "Mbit/s"},
    "ko": {u: "{0}" + p[4:] for u, p in _UNIT_EN.items() if u != "percent"},
    "ru": {"byte": "{0} Б", "kilobyte": "{0} кБ", "megabyte": "{0} МБ", "gigabyte": "{0} ГБ",
           "terabyte": "{0} ТБ", "millisecond": "{0} мс", "percent": "{0}" + _NB + "%",
           "megabit-per-second": "{0} Мбит/с"},
    "id": {"millisecond": "{0} md", "megabit-per-second": "{0} Mb/dtk"},
    "hi": {"byte": "{0} बाइट", "millisecond": "{0} मि॰से॰", "megabit-per-second": "{0} Mb/से॰"},
}


def unit(value, name: str, lang: str = DEFAULT, decimals: int = 1, sign: bool = False) -> str:
    """`value` in unit `name` (UNITS) with at most `decimals` places, as Intl writes it:
    unit(12.5, "gigabyte", "ru") -> "12,5 ГБ"; `sign` = a "+" before a positive value
    (Intl's signDisplay "exceptZero")."""
    code = lang if lang in _catalog() else normalize(lang)
    n = num(value, code, decimals, trim=True)
    if sign and n.lstrip("-").strip("0.,") and float(value) > 0:
        n = "+" + n
    own = _UNIT_LANG.get(code, {})
    pat = own.get(name + "_one") if plural_category(n.lstrip("+"), code) == "one" else None
    return (pat or own.get(name) or _UNIT_EN[name]).replace("{0}", n)


def pct(value, lang: str = DEFAULT, decimals: int = 0, sign: bool = False) -> str:
    """A percentage (14 = 14 %) the language's way: "14%" (en), "14 %" (de, fr, ru, es)."""
    return unit(value, "percent", lang, decimals, sign)


def ms(value, lang: str = DEFAULT) -> str:
    """Milliseconds: one decimal below 10 ("3.4 ms"), whole above ("128 ms")."""
    return unit(value, "millisecond", lang, 1 if abs(float(value)) < 10 else 0)


# A day without its year, as app.js fmt.day() (Intl.DateTimeFormat {month, day: "numeric"})
# writes it: "{m}" / "{d}" plain, "{mm}" / "{dd}" two digits (fixture-pinned).
_MONTH_DAY = {"es": "{d}/{m}", "id": "{d}/{m}", "hi": "{d}/{m}", "pt-BR": "{dd}/{mm}", "fr": "{dd}/{mm}",
              "de": "{d}.{m}.", "ko": "{m}. {d}.", "ru": "{dd}.{mm}"}


def month_day(day, lang: str = DEFAULT) -> str:
    """A date (datetime.date or "YYYY-MM-DD") without its year: "10/20" (en), "20.10." (de)."""
    from datetime import date
    d = date.fromisoformat(day) if isinstance(day, str) else day
    code = lang if lang in _catalog() else normalize(lang)
    return _MONTH_DAY.get(code, "{m}/{d}").format(m=d.month, d=d.day, mm=f"{d.month:02d}", dd=f"{d.day:02d}")


def mbps(bits_per_second, lang: str = DEFAULT) -> str:
    """A bitrate in Mb/s with at most 2 places: 1234567 -> "1.23 Mb/s", "1,23 Мбит/с" (ru)."""
    return unit(float(bits_per_second or 0) / 1e6, "megabit-per-second", lang, 2)


def size(n, lang: str = DEFAULT) -> str:
    """Bytes in decimal units (like ISPs and ntopng): 1234567 -> "1.2 MB"; the loop and the
    rounding are app.js fmt.bytes(), so a page and a server text show the same size."""
    n = float(n or 0)
    names = ("byte", "kilobyte", "megabyte", "gigabyte", "terabyte")
    i = 0
    while n >= 1000 and i < len(names) - 1:
        n /= 1000
        i += 1
    return unit(n, names[i], lang, 1 if i else 0)


def has(key: str) -> bool:
    """Is `key` defined (in the English reference locale)?"""
    return key in _catalog().get(FALLBACK, {})


def strings(lang: str) -> dict:
    """All strings for one language (English filling any gaps) - what the web UI loads."""
    cat = _catalog()
    code = normalize(lang)
    merged = {k: v for k, v in cat.get(FALLBACK, {}).items() if k != "_meta"}
    merged.update({k: v for k, v in cat[code].items() if k != "_meta"})
    return merged


def missing_keys() -> dict:
    """code -> sorted keys that English has but this locale lacks (should be empty)."""
    ref = set(_catalog()[FALLBACK]) - {"_meta"}
    return {code: sorted(ref - set(data)) for code, data in _catalog().items()}


# --- the checker (python3 -m netwarden.i18n --check; tests/test_i18n.py runs it) ------------

# Characters whose two Chinese scripts differ - a heuristic, not a dictionary: one side
# must never show up in the other locale. Pairs line up position by position.
SIMPLIFIED_ONLY = ("设备网务云广载关闭询识语视线连远头机时历险恶报简体发现开统戏购们这为么还没记变对应话问题"
                   "详动测试浏览拦胁单启传尔见点击运数据个与万号门间让将从写读选择实种类显错误页码钟订认证级"
                   "风隐护储费请账换络输图标础态书长显亿态阶层")
TRADITIONAL_ONLY = ("設備網務雲廣載關閉詢識語視線連遠頭機時歷險惡報簡體發現開統戲購們這為麼還沒記變對應話問題"
                    "詳動測試瀏覽攔脅單啟傳爾見點擊運數據個與萬號門間讓將從寫讀選擇實種類顯錯誤頁碼鐘訂認證級"
                    "風隱護儲費請帳換絡輸圖標礎態書長顯億態階層裝")
# Mainland wording to avoid in zh-Hant (Taiwan usage in parentheses). Kept short and safe:
# each of these reads as mainland usage in a Taiwanese UI.
MAINLAND_TERMS = {"軟件": "軟體", "硬件": "硬體", "網絡": "網路", "信息": "資訊", "默認": "預設",
                  "用戶": "使用者", "視頻": "影片", "服務器": "伺服器", "屏幕": "螢幕", "打印": "列印",
                  "內存": "記憶體", "菜單": "選單", "設置": "設定", "登錄": "登入", "鏈接": "連結",
                  "文件夾": "資料夾", "鼠標": "滑鼠", "激活": "啟用", "數據庫": "資料庫", "數據": "資料", "質量": "品質"}
# Values a translation may legitimately keep in English: brand / product names, units,
# protocol names and codes (whole value, placeholders removed, compared case-sensitively).
SAME_OK = {
    "AdGuard Home", "Pi-hole", "ntopng", "netwarden", "Anthropic", "Ollama", "LM Studio",
    "UPnP", "DNS", "DoH", "DoT", "MAC", "IP", "IPv4", "IPv6", "TCP", "UDP", "SSH", "RDP",
    "SMB", "Telnet", "RTSP", "HTTP", "HTTPS", "LAN", "Wi-Fi", "ISP", "URL", "API", "AI",
    "CSV", "JSON", "OK", "ms", "MB", "GB", "KB", "TB", "B", "h", "min", "s", "%", "·", "—",
    "→", "↓", "↑", "A", "B", "C", "D", "F", "Email", "Chromecast", "iPhone", "Android",
    "Windows", "macOS", "Linux", "iOS", "PS5", "Xbox", "Nintendo Switch", "YouTube",
    "Netflix", "TikTok", "Instagram", "Facebook", "WhatsApp", "LINE", "Telegram", "Discord",
    "Twitch", "Roblox", "Spotify", "Steam", "Zoom", "Teams", "Gmail", "Google", "Apple",
    "Microsoft", "Amazon", "Samsung", "QR", "PIN", "mDNS", "SSDP", "NetBIOS", "DHCP", "PTR",
    "Markdown", "Docker", "Home Assistant", "Firefox", "Chrome", "Safari", "Edge", "Bonjour",
    "Claude", "AdGuard", "WinRM", "VNC", "FTP", "MySQL", "PostgreSQL", "Redis", "MongoDB",
}
# Keys whose value is a brand / code / format in every language (by prefix or exact key).
SAME_OK_KEYS = ("_meta", "svc.", "threat.", "tracker.", "brand.", "list_sep", "digest.sep",
                "devtype.", "cat.", "push.type.")
_PH = None

# --- plurals (round 10d) ---------------------------------------------------------------------
# A count text in English: a placeholder, up to two words, then a plural noun ("{n} new
# devices", "{queries} lookups"). Placeholders that never hold a count, and words ending in
# -s that are no plural nouns, are left out. Such a key needs `key_one` (+ the forms of
# PLURAL_FORMS) and tn() / TN() - or an entry in PLURAL_FIXED when its count is never 1.
_COUNT_RX = r"\{(\w+)\}((?:\s+[A-Za-z][\w-]*){0,3})\s+([A-Za-z]+)\b"
NOT_COUNTS = {"name", "brand", "what", "this", "last", "time", "device", "owner", "person", "domain",
              "server", "value", "port", "ext", "when", "day", "label", "ms", "resolver", "service", "title",
              "type", "kind", "who", "room", "grade", "window", "source", "path", "tz", "cutoff",
              "first", "oldest", "newest", "start", "end", "until", "ago", "size", "cost", "model",
              "pct", "rx", "tx", "down", "up"}
_NOT_PLURAL = set("is was has this its us yes as his does goes uses starts looks needs sends opens "
                  "gets lets says stays runs turns means plus less across status press process "
                  "address access previous focus bonus pass alias gas miss ms vs mbps kbps".split())
IRREGULAR_PLURALS = {"people", "children"}
# count texts whose number is never 1 (a constant of the code, a minimum >= 2): key -> why
PLURAL_FIXED = {
    "status.db_range": "retention days >= 8 (store.MIN_RETENTION_DAYS)",
    "app.sys.retention": "retention days >= 8",
    "cli.prune.clamped": "the minimum kept is 8 days",
    "cli.prune.done": "prune keeps at least 8 days",
    "ui.ports_none_open": "exposure.PORTS: a fixed list of many ports",
    "ui.check_note": "exposure.PORTS: a fixed list of many ports",
    "app.d.ports_none": "exposure.PORTS: a fixed list of many ports",
    "app.share.days": "the report period is 7 or 30 days",
    "digest.window": "the digest compares {h} >= 24 hours with {d} >= 7 days",
    "why.threshold.night": "alerts.NIGHT_BASE_DAYS (7)",
    "why.threshold.spike": "alerts' spike baseline (7 days)",
    "why.data.night_base": "the night baseline is always 7 nights",
    "why.data.change": "the change baseline is always 7 days",
    "bed.preview_none": "bedtime previews look back 14 days",
    "bed.preview_some": "bedtime previews look back 14 days",
    "share.period_line": "the report covers 7 or 30 days",
    "share.privacy_h": "the report covers 7 or 30 days",
    "share.sec.events": "the report covers 7 or 30 days",
    "ui.lookup_used_by": "domain drawers count 7 days",
    "cli.pair.scan": "pairing codes last 10 minutes",
    "cli.pair.local_code": "pairing codes last 10 minutes",
    "cli.pair.admin_code": "admin codes last 10 minutes",
    "cli.claim.expires": "claim codes last 10 minutes",
    "why.threshold.bedtime": "bedtime rules need >= 5 minutes",
    "why.threshold.outage": "outage alerts need >= 2 minutes",
    "app.ai.preview_tools": "ai.max_tool_rounds and the call cap are >= 2",
    "app.ai.preview_tools_plain": "ai.max_tool_rounds and the call cap are >= 2",
}
# Round 10e, unit_literal: a placeholder with "%" or a size / time unit written next to it
# ("{pct}%", "{ms} ms", "{n} GB", "% {x}") - the value must come formatted (pct(), ms(),
# size(), mbps(), or a number for PARAM_UNITS) so the unit is the language's own; bitrates and
# spelled-out units ("Mbps", "bytes", "octets", "percent") count too. key -> why it may.
_UNIT_RX = (r"\{\w+\}[   ]?(?:%|(?:ms|мс|毫秒|ミリ秒|md|मि॰से॰|[kKMGT]B|[kMGT]o|[кМГТ]Б"
            r"|[kKMG]bps|[kKMG]b(?:it)?/s|[кМГ]бит/[сc]|[Bb]ytes?|octets?|байт\w*|बाइट"
            r"|percent|Prozent|pour ?cent|por ?cento|por ?ciento|процент\w*|persen)(?![\w-]))"
            r"|%[   ]?\{\w+\}")
UNIT_LITERAL_OK = {
    "app.fam.pts": "Korean writes percentage points as %p: a unit of its own, not a formatted percent",
}
# "device(s)", "Gerät(e)", "nouveau(x)", "устройств(о)" - never "http(s)://"
_HEDGE_RX = r"[^\W\d_](?<!http)\((?:s|e|en|es|n|er|x|i|r|ы|и|ов|ей|ях|о)\)"


def count_texts(en: dict) -> list:
    """[(key, placeholder)]: English values that put a count before a plural noun."""
    import re
    out = []
    for k, v in en.items():
        if k == "_meta" or k.endswith(("_one", "_few", "_many")):
            continue
        for m in re.finditer(_COUNT_RX, v):
            ph = m.group(1)
            if ph in NOT_COUNTS:
                continue
            words = [w for w in m.group(2).split() + [m.group(3)] if not w.isupper()]   # not "DNS"
            if any(w in IRREGULAR_PLURALS or (w.endswith("s") and not w.endswith("ss") and len(w) > 2
                                               and w not in _NOT_PLURAL) for w in words):
                out.append((k, ph))
                break
    return out


def _one_is_only_1(code: str) -> bool:
    """Does the "one" plural form of `code` cover the number 1 alone? (No in Russian, where
    it is also 21, 31, ..., nor in French / Portuguese / Hindi, where it is also 0.)"""
    return all(plural_category(n, code) != "one" for n in range(0, 1000) if n != 1)


def _placeholders(text: str) -> set:
    import re
    global _PH
    _PH = _PH or re.compile(r"{(\w+)}")
    return set(_PH.findall(text))


def _same_ok(key: str, value: str) -> bool:
    """Is an English-identical value fine as it is (brands, codes, units, URLs only)?"""
    import re
    if key.startswith(SAME_OK_KEYS):
        return True
    bare = re.sub(r"{\w+}|https?://\S+", " ", value)
    for phrase in sorted((p for p in SAME_OK if " " in p), key=len, reverse=True):
        bare = bare.replace(phrase, " ")
    words = [w for w in re.split(r"[^\w.%-]+", bare) if re.search(r"[A-Za-z]", w)]
    return all(w in SAME_OK or re.fullmatch(r"[A-Z0-9.]{1,6}|v?\d[\w.]*", w) for w in words)


def check(catalog: dict | None = None, same_allow: dict | None = None) -> list:
    """Every locale problem: [(code, key, problem, detail)]. problem: missing | extra |
    empty | placeholders | same_as_en | simplified_in_hant | traditional_in_hans |
    mainland_term | plural_missing (an English count text without `_one`) | plural_forms
    (a `_few` / `_many` form the language needs) | plural_hedge ("device(s)") |
    unit_literal ("{pct}%", "{ms} ms": the unit belongs to the formatter, round 10e).
    `same_allow` = {code: {key}} accepted copies of the English text
    (netwarden/locale_same_ok.json by default)."""
    import re
    cat = catalog if catalog is not None else _catalog()
    if same_allow is None:
        same_allow = _same_allow()
    en = {k: v for k, v in cat[FALLBACK].items() if k != "_meta"}
    plural = {k[:-4] for k in en if k.endswith("_one") and k[:-4] in en}
    out = []
    # plural_missing: an English count text without its singular (and no PLURAL_FIXED reason)
    for k, _ph in count_texts(en):
        if k not in plural and k not in PLURAL_FIXED:
            out.append((FALLBACK, k, "plural_missing", en[k][:60]))
    for code, data in cat.items():
        vals = {k: v for k, v in data.items() if k != "_meta"}
        forms = [f for f in PLURAL_FORMS.get(code, ()) if f != "one"]
        # a language's own extra plural forms of a count text are expected, not "extra"
        own = {b + "_" + f for b in plural for f in forms}
        for k in sorted(set(en) - set(vals)):
            out.append((code, k, "missing", ""))
        for k in sorted(set(vals) - set(en) - own):
            out.append((code, k, "extra", ""))
        for k in sorted(own - set(vals)):
            out.append((code, k, "plural_forms", ""))
        for k, v in sorted(vals.items()):
            if not isinstance(v, str) or not v.strip():
                out.append((code, k, "empty", ""))
                continue
            base = k.rsplit("_", 1)[0]
            if base in plural and k[len(base):] in ("_one", "_few", "_many"):
                # a plural form may say "once" instead of "{n} time" - it may drop the count -
                # only where that form means exactly 1 (not Russian 21, French 0, ...)
                have, want = _placeholders(v), _placeholders(en[base])
                droppable = {"n", "count"} if k.endswith("_one") and _one_is_only_1(code) else set()
                if not have <= want or not (want - have) <= droppable:
                    out.append((code, k, "placeholders", f"{sorted(have)} vs {sorted(want)}"))
                ref = None
            else:
                ref = en.get(k)
            if ref is not None and _placeholders(v) != _placeholders(ref):
                out.append((code, k, "placeholders",
                            f"{sorted(_placeholders(v))} != {sorted(_placeholders(ref))}"))
            if re.search(_HEDGE_RX, v) and not k.startswith(SAME_OK_KEYS):
                out.append((code, k, "plural_hedge", v[:60]))
            u = re.search(_UNIT_RX, v)
            if u and base not in UNIT_LITERAL_OK and k not in UNIT_LITERAL_OK:
                out.append((code, k, "unit_literal", u.group(0)))
            copy = base in plural and v == vals.get(base)   # a form = the language's own base text
            if code != FALLBACK and k in en and v == en[k] and not _same_ok(k, v) and not copy \
                    and k not in same_allow.get(code, ()) and k not in same_allow.get("*", ()):
                out.append((code, k, "same_as_en", v[:60]))
            if code == "zh-Hant":
                bad = sorted({c for c in v if c in SIMPLIFIED_ONLY})
                if bad:
                    out.append((code, k, "simplified_in_hant", "".join(bad)))
                # 用戶端 (client) and 數據機 (modem) are everyday Taiwanese usage; 用戶 / 數據
                # on their own are not (使用者 / 資料)
                plain = v.replace("用戶端", "").replace("數據機", "")
                for term, tw in MAINLAND_TERMS.items():
                    if term in plain:
                        out.append((code, k, "mainland_term", f"{term} -> {tw}"))
            if code == "zh-Hans":
                bad = sorted({c for c in v if c in TRADITIONAL_ONLY})
                if bad:
                    out.append((code, k, "traditional_in_hans", "".join(bad)))
    return out


def _same_allow() -> dict:
    """netwarden/locale_same_ok.json: {code or "*": [keys]} - reviewed values that are the
    same word in English and that language (e.g. "Status" in German). It lives beside
    locales/, not in it: every *.json in locales/ is a language."""
    p = LOCALE_DIR.parent / "locale_same_ok.json"
    if not p.exists():
        return {}
    return {k: set(v) for k, v in json.loads(p.read_text(encoding="utf-8")).items()}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m netwarden.i18n",
                                 description="netwarden languages: key coverage, or --check "
                                             "every locale for problems.")
    ap.add_argument("--check", action="store_true",
                    help="missing / extra keys, placeholder mismatches, untranslated copies of "
                         "English, Simplified characters in zh-Hant (and the reverse), "
                         "mainland terms in zh-Hant")
    args = ap.parse_args(argv)
    if args.check:
        problems = check()
        for code, key, what, detail in problems:
            print(f"{code:8} {what:20} {key}" + (f"  ({detail})" if detail else ""))
        by: dict = {}
        for p in problems:
            by[p[2]] = by.get(p[2], 0) + 1
        print("ok - no problems" if not problems else
              f"{len(problems)} problem(s): " + ", ".join(f"{k} {v}" for k, v in sorted(by.items())))
        return 1 if problems else 0
    gaps = missing_keys()
    for code, name, llm in LANGS:
        miss = gaps.get(code, [])
        print(f"{code:8} {name:20} {llm:40} {'ok' if not miss else f'{len(miss)} missing'}")
    return 1 if any(gaps.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
