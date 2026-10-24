"""
netwarden - ai_intents.py: offline answers to the questions households ask most.

Without an AI model (offline mode) a free-form question used to get the general
rule-based summary. Here a small intent matcher recognises the ~10 most common kinds
of question, runs the SAME read-only tools the AI would call (ai_tools) and renders a
templated, localized answer - with the same "Looked up: ..." chips in the AI panel.

    answer(db, lang, question, focus)  -> {"intent", "text", "tools": [chip events]} | None
    suggested(db, lang, focus, n)      -> [{"text", "intent", ...}]  questions built from
                                          the current data ("What did Samsung-TV connect
                                          to after 23:00?"), each one answerable here

Patterns: English, 繁體中文, 简体中文 and 日本語 keyword patterns; every other language
falls back to the English patterns plus its own time words ("anoche", "letzte Nacht",
...). A suggested question always matches (it is looked up by its exact text), so a
click on one works in every language. The text of a question never leaves this computer.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from netwarden import ai_tools, cache, i18n, naming, screentime, store

# --- time words ---------------------------------------------------------------------
# window -> one regex per language (checked for the question's language AND English;
# CJK has no word boundaries, so those patterns are plain substrings)
WINDOW_WORDS = {
    "last_night": {
        "en": r"\blast night\b|\btonight\b|\bovernight\b|\bat night\b|\bmidnight\b",
        "zh-Hant": r"昨晚|昨天晚上|昨夜|半夜|深夜|今晚|晚上",
        "zh-Hans": r"昨晚|昨天晚上|昨夜|半夜|深夜|今晚|晚上",
        "ja": r"昨夜|昨晩|夜中|深夜|今夜|夜",
        "es": r"\banoche\b|\besta noche\b|\bde noche\b",
        "pt-BR": r"ontem à noite|noite passada|\besta noite\b|\bde madrugada\b",
        "de": r"letzte nacht|heute nacht|\bnachts\b|gestern abend",
        "fr": r"cette nuit|hier soir|la nuit dernière|\bla nuit\b",
        "ko": r"어젯밤|지난밤|밤에|새벽",
        "ru": r"ночью|прошлой ночью|вчера вечером",
        "id": r"tadi malam|semalam|malam ini",
        "hi": r"कल रात|रात को|आज रात",
    },
    "1h": {
        "en": r"\b(last|past) hour\b|\b1 ?h(our)?\b|\bjust now\b",
        "zh-Hant": r"一小時|1 ?小時|剛剛|剛才", "zh-Hans": r"一小时|1 ?小时|刚刚|刚才",
        "ja": r"1時間|一時間|さっき", "es": r"última hora|\bhace un rato\b",
        "pt-BR": r"última hora", "de": r"letzte stunde", "fr": r"dernière heure",
        "ko": r"한 시간|1시간|방금", "ru": r"последний час|за час", "id": r"satu jam|1 jam",
        "hi": r"पिछले घंटे|एक घंटे",
    },
    "30d": {
        "en": r"\bthis month\b|\b30 days\b|\bpast month\b|\blast month\b",
        "zh-Hant": r"這個月|本月|30 ?天|一個月", "zh-Hans": r"这个月|本月|30 ?天|一个月",
        "ja": r"今月|30日|1か月|一ヶ月", "es": r"este mes|30 días", "pt-BR": r"este mês|30 dias",
        "de": r"diesen monat|30 tage", "fr": r"ce mois|30 jours", "ko": r"이번 달|30일",
        "ru": r"в этом месяце|30 дней", "id": r"bulan ini|30 hari", "hi": r"इस महीने|30 दिन",
    },
    "7d": {
        "en": r"\bthis week\b|\b7 days\b|\bpast week\b|\blast week\b|\bweek\b|\brecently\b",
        "zh-Hant": r"這週|本週|這禮拜|這星期|一週|一周|7 ?天|七天|最近",
        "zh-Hans": r"这周|本周|这礼拜|这星期|一周|7 ?天|七天|最近",
        "ja": r"今週|1週間|一週間|先週|最近", "es": r"esta semana|7 días|últimamente",
        "pt-BR": r"esta semana|7 dias|ultimamente", "de": r"diese woche|7 tage|in letzter zeit",
        "fr": r"cette semaine|7 jours|récemment", "ko": r"이번 주|7일|최근",
        "ru": r"на этой неделе|за неделю|недавно", "id": r"minggu ini|7 hari|akhir-akhir ini",
        "hi": r"इस हफ्ते|इस सप्ताह|7 दिन|हाल ही",
    },
    "24h": {
        "en": r"\btoday\b|\b24 ?h(ours)?\b|\byesterday\b|\bthis morning\b",
        "zh-Hant": r"今天|今日|24 ?小時|昨天|早上", "zh-Hans": r"今天|今日|24 ?小时|昨天|早上",
        "ja": r"今日|24時間|昨日|けさ|今朝", "es": r"\bhoy\b|\bayer\b", "pt-BR": r"\bhoje\b|\bontem\b",
        "de": r"\bheute\b|\bgestern\b", "fr": r"aujourd'hui|\bhier\b", "ko": r"오늘|어제",
        "ru": r"сегодня|вчера", "id": r"hari ini|kemarin", "hi": r"आज|कल",
    },
}
WINDOW_ORDER = ("last_night", "1h", "30d", "7d", "24h")
DAY_WORDS = {"en": r"\btoday\b", "zh-Hant": r"今天|今日", "zh-Hans": r"今天|今日", "ja": r"今日",
             "es": r"\bhoy\b", "pt-BR": r"\bhoje\b", "de": r"\bheute\b", "fr": r"aujourd'hui",
             "ko": r"오늘", "ru": r"сегодня", "id": r"hari ini", "hi": r"आज"}
AFTER_WORDS = (r"\bafter\b|\bsince\b|\blater than\b|之後|以後|之后|以后|以降|過ぎ|\bnach\b|après|"
               r"después|depois|после|setelah|के बाद|이후|후에")
TIME_RE = re.compile(r"(?<!\d)(2[0-3]|[01]?\d)(?!\d)\s*(?:[:：]\s*([0-5]\d)|點|点|時|时|시)?\s*"
                     r"(pm|p\.m\.|am|a\.m\.)?", re.I)
# evening words: "11 點" in "昨晚 11 點之後" / "after 11 last night" is 23:00 (hours 6-11 only)
PM_WORDS = (r"\bpm\b|p\.m\.|晚|下午|午後|夜|저녁|밤|\btonight\b|\blast night\b|\bevening\b|"
            r"\babends\b|\bsoir\b|\bnoche\b|\bnoite\b|вечер|ночью|\bmalam\b|रात|शाम")

# --- intents: (name, {lang: regex}); the first match wins -----------------------------
INTENTS = (
    ("presence", {
        "en": r"\b(any(one|body)|some(one|body)|who('?s| is)?|people)\b.*\bhome\b|\bis \w+ home\b|"
              r"\bat home\b|\bhome now\b",
        "zh-Hant": r"在家|誰在|回家了|有人在|到家", "zh-Hans": r"在家|谁在|回家了|有人在|到家",
        "ja": r"在宅|家にいる|誰か.*いる|帰宅|家に",
        # "who's home?" is the household question: understood in every UI language
        "es": r"\ben casa\b|qui[eé]n (est[aá]|hay)\b", "pt-BR": r"\bem casa\b|quem (est[aá]|chegou)\b",
        "de": r"\bzu ?hause\b|\bdaheim\b|wer ist da\b", "fr": r"\bà la maison\b|\bchez (moi|nous)\b|qui est là",
        "ko": r"집에|누가 있|귀가", "ru": r"\bдома\b|кто (пришёл|пришел)",
        "id": r"di rumah|siapa (yang )?ada", "hi": r"घर पर|घर में|कौन है"}),
    ("screen_time", {
        "en": r"screen ?time|how (long|much time)|\bhours? (on|of)\b|\bminutes (on|of)\b",
        "zh-Hant": r"螢幕時間|使用時間|多久|多少時間|玩了多久|上網多久",
        "zh-Hans": r"屏幕时间|使用时间|多久|多长时间|玩了多久|上网多久",
        "ja": r"スクリーンタイム|利用時間|どのくらい|何時間|使用時間"}),
    ("bedtime", {
        "en": r"bed ?time|\bup late\b|stay(ed|ing)? up|after bed|\bsleep\b",
        "zh-Hant": r"就寢|睡覺時間|熬夜|晚睡|太晚睡|宵禁", "zh-Hans": r"就寝|睡觉时间|熬夜|晚睡|太晚睡|宵禁",
        "ja": r"就寝|寝る時間|夜更かし|遅くまで起き"}),
    ("traffic", {
        "en": r"\b(data|bandwidth|traffic|download(ed|s)?|upload(ed|s)?|gigabytes?|gb)\b",
        "zh-Hant": r"流量|頻寬|數據量|資料量|下載|上傳|用量", "zh-Hans": r"流量|带宽|数据量|下载|上传|用量",
        "ja": r"データ|通信量|帯域|トラフィック|ダウンロード|アップロード"}),
    ("new_devices", {
        "en": r"\bnew\b|\bjoined\b|\bunknown devices?\b|\banything new\b",
        "zh-Hant": r"新的?裝置|新設備|新加入|有什麼新|新東西|陌生", "zh-Hans": r"新的?设备|新加入|有什么新|新东西|陌生",
        "ja": r"新しい|新規|新た|見慣れない"}),
    ("upnp", {
        "en": r"\bupnp\b|port ?forward|\bopen ports?\b|\bports? (are |is )?open\b|\bopen to the internet\b",
        "zh-Hant": r"UPnP|通訊埠|連接埠|埠|對外開放", "zh-Hans": r"UPnP|端口|对外开放",
        "ja": r"UPnP|ポート|ポート開放"}),
    ("hygiene", {
        "en": r"router (security|settings|check|hygiene)|\bhygiene\b|default password|firmware",
        "zh-Hant": r"路由器(安全|設定|檢查)|韌體|預設密碼", "zh-Hans": r"路由器(安全|设置|检查)|固件|默认密码",
        "ja": r"ルーター.*(安全|設定|チェック)|ファームウェア|初期パスワード"}),
    ("suggestions", {
        "en": r"what should i (do|fix|change)|\bimprove\b|\bsuggest|\brecommend|\bscore\b|\bto-?do\b|fix first",
        "zh-Hant": r"建議|該做什麼|改善|怎麼做|分數|評分|先修|先處理",
        "zh-Hans": r"建议|该做什么|改善|怎么做|分数|评分|先修|先处理",
        "ja": r"提案|おすすめ|改善|何をすべき|スコア|まず直す"}),
    ("domains", {
        "en": r"connect(ed|s)? to|talk(ed|s)? to|\bvisit(ed|s)?\b|\bdomains?\b|\b(web)?sites?\b|look(ed)? up|\bdoing\b",
        "zh-Hant": r"連(到|去|了|上)|網站|網域|去了哪|上了什麼|看了什麼|在做什麼|做了什麼",
        "zh-Hans": r"连(到|去|了|上)|网站|域名|去了哪|上了什么|看了什么|在做什么|做了什么",
        "ja": r"接続|つなが|サイト|ドメイン|アクセス|何をして"}),
    ("health", {
        "en": r"\binternet\b|\bslow\b|\boutages?\b|\boffline\b|\b(went |is )?down\b|wi-?fi|\brouter\b|\bconnection\b|\blatency\b|\bping\b",
        "zh-Hant": r"網路|網速|斷線|斷網|很慢|變慢|路由器|連線|延遲|Wi-?Fi",
        "zh-Hans": r"网络|网速|断线|断网|很慢|变慢|路由器|连接|延迟|Wi-?Fi",
        "ja": r"インターネット|ネット|遅い|切断|障害|ルーター|回線|Wi-?Fi"}),
    ("alerts", {
        "en": r"\balerts?\b|\bwarnings?\b|\bwrong\b|\bproblems?\b|\bissues?\b|suspicious|\brisk|danger|\bsafe\b|secur|threat",
        "zh-Hant": r"警示|警報|異常|問題|可疑|危險|安全|威脅|不對勁", "zh-Hans": r"警报|告警|异常|问题|可疑|危险|安全|威胁|不对劲",
        "ja": r"警告|アラート|異常|問題|危険|安全|脅威|怪しい"}),
    ("devices", {
        "en": r"how many devices|\b(list|which|what|all)( of)?( my| the)? devices\b|\bonline\b|connected devices",
        "zh-Hant": r"幾台|多少(台|個)?裝置|哪些裝置|所有裝置|裝置清單|在線|上線",
        "zh-Hans": r"几台|多少(台|个)?设备|哪些设备|所有设备|设备列表|在线|上线",
        "ja": r"何台|デバイス一覧|どのデバイス|オンライン|全部のデバイス"}),
)
PATTERN_LANGS = ("en", "zh-Hant", "zh-Hans", "ja")


def _find(patterns: dict, lang: str, q: str) -> bool:
    # the UI language first, then every pattern set: a Chinese question typed in an English
    # UI (or the reverse) still matches
    for code in dict.fromkeys((lang,) + PATTERN_LANGS):
        rx = patterns.get(code)
        if rx and re.search(rx, q, re.I):
            return True
    return False


def classify(q: str, lang: str) -> str | None:
    """The intent a question's words point at (the first of INTENTS that matches)."""
    return next((name for name, pats in INTENTS if _find(pats, i18n.normalize(lang), q)), None)


def detect_window(q: str, lang: str) -> str | None:
    for w in WINDOW_ORDER:
        if _find(WINDOW_WORDS[w], lang, q):
            return w
    return None


def detect_after(q: str) -> str | None:
    """"after 23:00" / "23點之後" / "after 11pm" -> "23:00" (local), else None."""
    if not re.search(AFTER_WORDS, q, re.I):
        return None
    for m in TIME_RE.finditer(q):
        h, mi, ampm = int(m.group(1)), m.group(2), (m.group(3) or "").lower()
        if not (mi or ampm or re.search(r"[點点時时시]", m.group(0))
                or re.search(rf"(?:{AFTER_WORDS})\s*$", q[:m.start()], re.I)):
            continue                       # a bare number ("2 devices") is not a time
        if h < 12 and (ampm.startswith("p") or (not ampm and re.search(PM_WORDS, q, re.I) and h >= 6)):
            h += 12
        if ampm.startswith("a") and h == 12:
            h = 0
        return f"{h:02d}:{int(mi or 0):02d}"
    return None


def mention_device(db, q: str, lang: str) -> str | None:
    """The MAC of the device a question names (the longest name found in it)."""
    qf = q.casefold()
    best = (0, None)
    sources = [store.device_names(db), naming.display_names(db, lang), store.identity_names(db)]
    for src in sources:
        for mac, name in src.items():
            n = (name or "").casefold().strip()
            if len(n) >= 2 and n != mac and n in qf and len(n) > best[0]:
                best = (len(n), mac)
    return best[1]


def mention_person(db, q: str) -> str | None:
    qf = q.casefold()
    hits = [p["name"] for p in store.people(db) if p["name"].casefold() in qf]
    return max(hits, key=len, default=None)


def match(db, lang: str, question: str | None, focus: str | None = None) -> dict | None:
    """{intent, window, after, device, person} for a question, or None (unknown).
    A question that is one of the current suggested questions maps to its intent."""
    q = (question or "").strip()
    if not q or len(q) > 500:
        return None
    lang = i18n.normalize(lang)
    for s in suggested(db, lang, focus):
        if s["text"].casefold() == q.casefold():
            return {k: s.get(k) for k in ("intent", "window", "after", "device", "person")}
    intent = classify(q, lang)
    if intent is None:
        return None
    device = mention_device(db, q, lang)
    if focus and not device and intent in ("alerts", "devices"):
        return None     # "is it risky?" about the focused device: its own summary says more
    person = None if device else mention_person(db, q)
    return {"intent": intent, "window": detect_window(q, lang), "after": detect_after(q),
            "device": device or (focus if intent in ("domains", "traffic", "alerts", "screen_time")
                                 and not person else None),
            "person": person, "day": _find(DAY_WORDS, lang, q)}


# --- rendering ------------------------------------------------------------------------

def _chip(db, name: str, args: dict, result: dict, lang: str) -> dict:
    """The panel event for a lookup made HERE (offline: nothing was sent anywhere)."""
    ev = {"name": name, "label": ai_tools.label(name, lang),
          "detail": ai_tools.detail(db, name, args, lang), "sent": ai_tools.dumps(result),
          "local": True, "truncated": bool(result.get("truncated"))}
    if result.get("error"):
        ev["error"] = result["error"]
    return ev


class _Run:
    def __init__(self, db, lang: str):
        self.db, self.lang, self.chips = db, lang, []

    def __call__(self, name: str, args: dict) -> dict:
        args = {k: v for k, v in args.items() if v is not None}
        res = ai_tools.run(self.db, name, args, self.lang)
        self.chips.append(_chip(self.db, name, args, res, self.lang))
        return res


def _t(lang):
    return lambda key, **kw: i18n.t(key, lang, **kw)


def _more(t, lines: list, n: int = 6) -> list:
    return lines[:n] + ([t("offline.more", n=len(lines) - n)] if len(lines) > n else [])


def r_traffic(run, t, m, lang):
    w = m["window"] or "24h"
    res = run("traffic", {"window": w, "device": m["device"], "person": m["person"]})
    when = t("aitool.win." + w)
    if res.get("error"):
        return [t("intent.failed")]
    if not res.get("has_bandwidth"):
        return [t("intent.traffic_none", when=when)]
    rows = res.get("devices") or []
    if not rows:
        return [t("intent.traffic_empty", when=when)]
    top = rows[0]
    lines = [t("intent.traffic_top", name=top["name"], when=when, rx=top["download"], tx=top["upload"])]
    lines += [t("intent.traffic_line", name=r["name"], rx=r["download"], tx=r["upload"]) for r in rows[1:4]]
    return lines


def r_domains(run, t, m, lang):
    w = m["window"] or ("last_night" if m.get("after") else "24h")
    res = run("top_domains", {"window": w, "device": m["device"], "person": m["person"],
                              "after": m.get("after"), "limit": 8})
    if res.get("error"):
        return [t("intent.failed")]
    when = t("aitool.win." + w)
    if m.get("after"):
        when += " · " + t("aitool.after", time=m["after"])
    who = res.get("device") or res.get("person") or t("intent.home")
    if not res.get("lookups"):
        return [t("intent.domains_none", name=who, when=when)]
    lines = [t("intent.domains_head", name=who, when=when, n=res["lookups"])]
    for d in res["domains"][:8]:
        key = "intent.domains_line_svc" if d.get("service") else "intent.domains_line"
        lines.append(t(key, domain=d["domain"], service=d.get("service") or "", n=d["lookups"]))
    return lines


def r_presence(run, t, m, lang):
    res = run("presence", {"person": m["person"]})
    if res.get("error"):
        return [t("intent.failed")]
    rows = res.get("people") or []
    if not rows:
        return [t("intent.presence_off")]
    lines = [t("intent.presence_head")]
    for p in rows:
        lines.append(t("intent.presence_line", name=p["person"],
                       state=t("presence.state." + p["state"]), reason=p.get("why") or "—"))
    if res.get("people_without_presence"):
        lines.append(t("intent.presence_hidden", n=res["people_without_presence"]))
    return lines


def r_new(run, t, m, lang):
    w = m["window"] or "7d"
    when = t("aitool.win." + w)
    res = run("list_devices", {"new_since": w, "limit": 20})
    ch = run("alerts", {"window": w, "type": "change", "limit": 10})
    rows = [d for d in res.get("devices") or [] if not d.get("this_computer")]
    lines = [t("intent.new_head", n=len(rows), when=when)] if rows else [t("intent.new_none", when=when)]
    lines += _more(t, [t("intent.new_line", name=d["name"], time=d.get("first_seen") or "—")
                       for d in rows])
    changes = ch.get("alerts") or []
    if changes:
        lines += ["", t("intent.changes_head", when=when)]
        lines += _more(t, [t("intent.alerts_line", title=a["title"], text=a["text"]) for a in changes], 4)
    return lines


def r_alerts(run, t, m, lang):
    w = m["window"] or "24h"
    when = t("aitool.win." + w)
    res = run("alerts", {"window": w, "device": m["device"], "limit": 20})
    if res.get("error"):
        return [t("intent.failed")]
    rows = res.get("alerts") or []
    if not rows:
        return [t("intent.alerts_none", when=when)]
    return [t("intent.alerts_head", n=res["count"], when=when)] + _more(
        t, [t("intent.alerts_line", title=a["title"], text=a["text"]) for a in rows], 5)


def r_screen(run, t, m, lang):
    period = "day" if m.get("day") else "week"
    res = run("screen_time", {"person": m["person"], "device": m["device"], "period": period})
    if res.get("error"):
        return [t("intent.failed")]
    p_text = t("aitool.period." + period)
    rows = [(x["person"], x) for x in res.get("people") or []]
    if m["device"]:
        rows = [(x["name"], x) for x in res.get("devices") or []]
    rows = [(n, x) for n, x in rows if x["minutes"]]
    if not rows:
        return [t("intent.screen_none", period=p_text)]
    sep = i18n.t("list_sep", lang)
    lines = [t("intent.screen_head", period=p_text)]
    for name, x in sorted(rows, key=lambda r: -r[1]["minutes"])[:6]:
        svcs = sep.join(s["service"] for s in (x.get("top_services") or [])[:3])
        key = "intent.screen_line" if svcs else "intent.screen_line_bare"
        lines.append(t(key, name=name, minutes=screentime.duration(x["minutes"], lang), services=svcs))
    return lines + [t("offline.screen_note")]


def r_bedtime(run, t, m, lang):
    res = run("bedtime_status", {"person": m["person"]})
    if res.get("error"):
        return [t("intent.failed")]
    rules = res.get("rules") or []
    if not rules:
        return [t("intent.bed_none")]
    lines = [t("intent.bed_head")]
    for r in rules:
        lines.append(t("intent.bed_rule", name=r.get("name") or r.get("for") or "—",
                       days=r.get("days") or "", window=r["window_local"].replace("-", "–")))
        hits = r.get("nights_over_7d") or []
        if not hits:
            lines.append(t("intent.bed_ok"))
        for h in hits[:4]:
            key = "intent.bed_hit" if h.get("mostly") else "intent.bed_hit_bare"
            lines.append(t(key, night=h["night"], device=h["device"],
                           minutes=screentime.duration(h["minutes"], lang), service=h.get("mostly") or ""))
    return lines


def r_health(run, t, m, lang):
    from netwarden import nethealth
    w = m["window"] if m["window"] in ("1h", "24h", "7d", "30d", "last_night") else "7d"
    res = run("network_health", {"window": w})
    if res.get("error"):
        return [t("intent.failed")]
    when = t("aitool.win." + w)
    lines = [f"**{res['summary']}**", res.get("detail") or ""]
    b = ai_tools.window_bounds(ai_tools.Ctx(run.db, lang), w)
    start, end = ai_tools._iso(b["start"]), ai_tools._iso(b["end"])
    outs = [o for o in nethealth.outage_list(run.db, days=31)
            if o["end_ts"] >= start and o["start_ts"] <= end]
    if outs:
        lines += [t("intent.health_outages", when=when)]
        lines += _more(t, ["• " + nethealth.outage_text(o, lang) for o in outs], 5)
    else:
        lines.append(t("intent.health_no_outage", when=when))
    return [x for x in lines if x]


def r_upnp(run, t, m, lang):
    res = run("upnp_mappings", {})
    if not res.get("checked"):
        return [t("intent.upnp_unchecked")]
    rows = [x for x in res.get("mappings") or [] if not x.get("muted")]
    if not rows:
        return [t("intent.upnp_none")]
    lines = [t("intent.upnp_head", n=len(rows))]
    for x in rows[:8]:
        key = "intent.upnp_line_risky" if x.get("risky") else "intent.upnp_line"
        lines.append(t(key, proto=x["protocol"], port=x["external_port"],
                       device=x.get("device") or "?", service=x.get("service") or ""))
    return lines


def r_hygiene(run, t, m, lang):
    res = run("hygiene", {})
    if res.get("error"):
        return [t("intent.failed")]
    lines = [t("intent.hygiene_head", summary=res["summary"])]
    bad = [c for c in res["checks"] if c["status"] in ("fail", "warn")]
    lines += _more(t, [t("intent.hygiene_line", title=c["title"], text=c["text"]) for c in bad], 5)
    return lines


def r_suggestions(run, t, m, lang):
    res = run("suggestions", {"status": "open", "limit": 5})
    rows = res.get("suggestions") or []
    if not rows:
        return [t("intent.sug_none")]
    return [t("intent.sug_head", n=(res.get("counts") or {}).get("open", len(rows)))] + \
        [t("intent.sug_line", title=s["title"]) for s in rows[:5]]


def r_devices(run, t, m, lang):
    from netwarden import devicetype
    res = run("list_devices", {"limit": 12, "person": m["person"]})
    if res.get("error"):
        return [t("intent.failed")]
    if "online_now" in res:
        lines = [t("intent.devices_head", n=res["count"], online=res["online_now"])]
    else:       # presence is off for that person: no online / last-active times
        lines = [t("intent.devices_head_private", n=res["count"])]
    for d in res.get("devices") or []:
        key = "intent.devices_line_on" if d.get("online") else "intent.devices_line"
        lines.append(t(key, name=d["name"], type=devicetype.type_name(d["type"], lang)))
    if res["count"] > len(res.get("devices") or []):
        lines.append(t("offline.more", n=res["count"] - len(res["devices"])))
    return lines


RENDER = {"traffic": r_traffic, "domains": r_domains, "presence": r_presence, "new_devices": r_new,
          "alerts": r_alerts, "screen_time": r_screen, "bedtime": r_bedtime, "health": r_health,
          "upnp": r_upnp, "hygiene": r_hygiene, "suggestions": r_suggestions, "devices": r_devices}


def answer(db, lang: str, question: str | None, focus: str | None = None) -> dict | None:
    """The offline answer to a recognised question: {intent, text, tools} or None."""
    lang = i18n.normalize(lang)
    m = match(db, lang, question, focus)
    if m is None:
        return None
    t = _t(lang)
    run = _Run(db, lang)
    m = {"window": None, "after": None, "device": None, "person": None, "day": False, **m}
    lines = RENDER[m["intent"]](run, t, m, lang)
    text = "\n".join([t("intent.title"), ""] + lines + ["", t("offline.enable_hint")])
    return {"intent": m["intent"], "text": text, "tools": run.chips}


# --- suggested questions -----------------------------------------------------------------

def suggested(db, lang: str, focus: str | None = None, n: int = 6) -> list:
    """4-6 questions worth asking right now, built from the data (the device that moved
    the most data last night, a child's screen time, ...), most useful first. Each one
    is answerable offline (match() looks it up by its exact text)."""
    lang = i18n.normalize(lang)
    return cache.memo(db, "ai_intents.suggested", (lang, focus or "", n),
                      lambda: _suggested(db, lang, focus, n))


def _suggested(db, lang: str, focus: str | None, n: int) -> list:
    t = _t(lang)
    names = naming.display_names(db, lang)
    out = []

    def add(key, intent, **kw):
        params = {k: v for k, v in kw.items() if k in ("name",)}
        out.append({"text": t("intent.q." + key, **params), "intent": intent,
                    **{k: v for k, v in kw.items() if k not in ("name",)}})

    if focus and focus in names:
        add("domains_focus", "domains", name=names[focus], device=focus, window="24h")
    top = None
    if ai_tools.has_bandwidth(db):
        res = ai_tools.run(db, "traffic", {"window": "last_night", "limit": 1}, "en")
        rows = res.get("devices") or []
        if rows:
            top = rows[0]["mac"]
            add("traffic_night", "traffic", window="last_night")
    if top is None:      # no bytes: the device with the most lookups last night
        res = ai_tools.run(db, "list_devices", {"limit": 1}, "en")
        rows = [d for d in res.get("devices") or [] if d.get("dns_lookups_24h")]
        top = rows[0]["mac"] if rows else None
    if top and top != focus:
        add("domains_after", "domains", name=names.get(top, top), device=top,
            window="last_night", after="23:00")
    if any(p["presence"] for p in store.people(db)):
        add("presence", "presence")
    add("new_week", "new_devices", window="7d")
    kids = sorted(store.people(db), key=lambda p: (not p["child"], p["id"]))
    st = {m["owner"]: m for m in screentime.member_totals(db)}
    kid = next((p["name"] for p in kids if (st.get(p["name"]) or {}).get("minutes")), None)
    if kid:
        add("screen", "screen_time", name=kid, person=kid)
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    if store.outages(db, ai_tools._iso(week_ago)):
        add("health", "health", window="7d")
    add("alerts", "alerts", window="24h")
    if store.upnp_current(db):
        add("upnp", "upnp")
    add("suggestions", "suggestions")
    seen, uniq = set(), []
    for s in out:
        if s["text"] not in seen:
            seen.add(s["text"])
            uniq.append(s)
    return uniq[:n]
