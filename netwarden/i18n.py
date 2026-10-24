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
_NUM = {"de": (",", ".", 4), "es": (",", ".", 5), "pt-BR": (",", ".", 4), "fr": (",", " ", 4),
        "ru": (",", " ", 5), "id": (",", ".", 4)}


def num(value, lang: str = DEFAULT, decimals: int = 0) -> str:
    """`value` with `decimals` places in `lang`: 1234.5 -> "1,234.5" (en), "1.234,5" (de),
    "1 234,5" (fr); Hindi groups in lakhs ("1,23,456")."""
    code = lang if lang in _catalog() else normalize(lang)
    dec, grp, min_digits = _NUM.get(code, (".", ",", 4))
    text = f"{abs(float(value)):.{max(0, int(decimals))}f}"
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
    (a `_few` / `_many` form the language needs) | plural_hedge ("device(s)").
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
