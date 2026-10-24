"""
netwarden - health.py: is everything actually running?

Every ingest / traffic / discovery run (CLI or `run` loop) writes its outcome to the
source_status table. status() combines that with what is configured (presence only:
we never read out or print a value from .env), the AI mode, DB size/coverage and the
background loops into one dict - served as GET /api/status and printed by
`python3 -m netwarden status` as a localized table with actionable hints.

    python3 -m netwarden status            # readable table + hints
    python3 -m netwarden status --json     # the same dict as /api/status
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import netwarden
from netwarden import brain, i18n, settings, store

# source -> (env key that turns it on, seconds without a good run before it is "stale").
# Discovery has no env key: it is on wherever discovery.availability() says it can run.
SOURCES = {
    "adguard": ("ADGUARD_URL", 15 * 60),     # DNS loop runs every 60 s
    "pihole": ("PIHOLE_URL", 15 * 60),       # the same loop, when Pi-hole is the DNS source
    "ntopng": ("NTOPNG_URL", 10 * 60),       # traffic loop every 30 s
    "discovery": (None, 60 * 60),            # sweep every 15 min
    # Stage N: part of every sweep (identify.py / upnp.py); on wherever discovery is
    "mdns": (None, 60 * 60),
    "ssdp": (None, 60 * 60),
    "upnp": (None, 60 * 60),
    # Stage V3: the unicast round's NetBIOS node-status queries (Windows / Samba names)
    "netbios": (None, 60 * 60),
    # Stage H: the health loop's gateway ping (nethealth.py), every 60 s
    "gateway": (None, 10 * 60),
}
IDENT_SOURCES = ("mdns", "ssdp", "upnp", "netbios")   # ride along with discovery: no hints of their own
                                           # unless they failed or went stale
QUIET_SOURCES = (*IDENT_SOURCES, "gateway")   # same rule (and the same LAN requirement)

_URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s@]+@", re.I)
_AUTH_TOKEN = re.compile(r"\b(Basic|Bearer)\s+[A-Za-z0-9+/=._-]+", re.I)
_API_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{6,}")
# header-ish "X-FTL-SID: v" / "sid=v" / "token": "v" / ?key=v&... (query strings, JSON, reprs)
_SECRET_FIELD = re.compile(
    r"""(\b(?:x-ftl-sid|x-api-key|sid|token|access_token|api[_-]?key|key|password|passwd|pass|pw|secret)"""
    r"""["']?\s*[:=]\s*["']?)[^\s"'&,;}]+""", re.I)


def sanitize_error(err, secrets=()) -> str:
    """An exception / message safe to store, log and show: one line, at most 300 chars,
    with URL credentials, auth headers, API keys, secret-looking fields (sid=, token=,
    key=, password=, X-FTL-SID) and any given secret value - also URL-encoded - masked."""
    from urllib.parse import quote, quote_plus
    text = str(err) or type(err).__name__
    if isinstance(err, BaseException) and type(err).__name__ not in text:
        text = f"{type(err).__name__}: {text}"
    for s in secrets:
        if s and len(s) >= 4:
            for form in {s, quote(s, safe=""), quote_plus(s)}:
                text = text.replace(form, "***")
    text = _URL_USERINFO.sub(r"\1***@", text)
    text = _AUTH_TOKEN.sub(r"\1 ***", text)
    text = _API_KEY.sub("sk-***", text)
    text = _SECRET_FIELD.sub(r"\1***", text)
    text = " ".join(text.split())
    return text[:297] + "..." if len(text) > 300 else text


def source_secrets(src) -> list:
    """Credential values a source object holds (password, session id, auth header), so
    its errors can be masked BEFORE they are stored in source_status or logged."""
    out = [getattr(src, a, None) for a in ("password", "sid", "auth")]
    auth = getattr(src, "auth", None)
    if isinstance(auth, str) and " " in auth:
        out.append(auth.split(" ", 1)[1])
    return [s for s in out if isinstance(s, str) and s]


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to the same scheme + host + port. urllib's default would
    carry our Authorization / X-FTL-SID headers to any host, even https -> http."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if (old.scheme, old.netloc.lower()) != (new.scheme, new.netloc.lower()):
            raise urllib.error.HTTPError(newurl, code, f"refused cross-origin redirect ({code})",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


USER_AGENT = f"netwarden/{netwarden.__version__}"   # how the sources see us (Pi-hole's session list)


def opener(context=None) -> urllib.request.OpenerDirector:
    """urllib opener for the local data sources (AdGuard, Pi-hole, ntopng): same-origin
    redirects only, our own User-Agent; `context` = an ssl.SSLContext for https
    (tls_context(), e.g. PIHOLE_VERIFY_TLS=0)."""
    handlers = [_SameOriginRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    op = urllib.request.build_opener(*handlers)
    op.addheaders = [("User-Agent", USER_AGENT)]
    return op


def tls_context(verify: bool = True):
    """The SSL context for a source's https:// URL. Certificates are verified by default;
    `verify=False` (<SOURCE>_VERIFY_TLS=0, an explicit opt-in) accepts the self-signed
    certificate Pi-hole, AdGuard Home and ntopng create for themselves."""
    import ssl
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class SourceError(OSError):
    """A data source answered, but in a way we understand and can explain: `kind` is one
    of conntest.ERROR_KINDS (shown as err.conn_<kind>), the message is short English with
    the setting to check - never a secret. An OSError, so every caller already treats it
    like "can't use the source"."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def http_error_body(e: urllib.error.HTTPError, limit: int = 64 * 1024) -> dict:
    """The JSON body of an HTTP error answer ({} if there is none or it isn't JSON).
    Pi-hole puts {"error": {"key", "message", "hint"}} there."""
    try:
        body = read_json(e, limit=limit, seconds=5.0)
    except (OSError, ValueError, AttributeError):
        return {}
    finally:
        e.close()
    return body if isinstance(body, dict) else {}


MAX_RESPONSE_BYTES = 16 * 1024 * 1024   # one page of a source's API (a few hundred KB normally)
MAX_RESPONSE_S = 60.0                   # one whole response, however slowly it trickles in


def read_json(resp, limit: int = MAX_RESPONSE_BYTES, seconds: float = MAX_RESPONSE_S):
    """A source's HTTP response body as JSON, with hard limits (Stage K): at most `limit`
    bytes and `seconds` for the whole body (each read also has the socket timeout), so a
    broken or hostile server can neither exhaust memory nor hold a loop forever. Empty
    body -> {}. Raises ValueError for too large / too slow / not JSON / nested too deep."""
    import json
    import time
    deadline = time.monotonic() + seconds
    chunks, size = [], 0
    read = getattr(resp, "read1", None) or resp.read
    while True:
        chunk = read(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise ValueError("response too large")
        if time.monotonic() > deadline:
            raise ValueError("response too slow")
    raw = b"".join(chunks)
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except RecursionError:   # "[[[[..." nested deeper than the parser's stack
        raise ValueError("JSON nested too deeply") from None


def read_source_json(resp, what: str, url_var: str) -> dict:
    """read_json() for a data source (AdGuard, Pi-hole, ntopng): any answer we can't use
    becomes ONE short OSError ("can't use the source", like a connection failure) that
    names the setting to check - never a JSONDecodeError traceback or the parser's words.
    `what` = the source's name, `url_var` = its .env address key."""
    try:
        body = read_json(resp)
    except ValueError as e:  # e.g. an HTML login page: wrong URL or credentials
        if "too" in str(e):  # too large / too slow / nested too deeply
            raise OSError(f"{what} response refused: {e}") from None
        raise OSError(f"{what} did not return JSON - check {url_var} / credentials") from None
    if not isinstance(body, dict):
        raise OSError(f"{what} did not return a JSON object - check {url_var}")
    return body


# A stored (English, sanitized) source error -> one of conntest.ERROR_KINDS, so the page,
# the wizard and `netwarden status` say it in the user's language (error_text()).
# Order matters: the first match wins. Unknown errors are shown as stored.
_ERROR_KINDS = (
    # round 9 V: the source told us exactly what is wrong (SourceError messages)
    ("tls", re.compile(r"certificate verify failed|CERTIFICATE_VERIFY_FAILED|"
                       r"WRONG_VERSION_NUMBER|certificate is not trusted", re.I)),
    ("seats", re.compile(r"api seats|no free API session", re.I)),
    ("totp", re.compile(r"\b2FA\b|two-factor|\btotp\b", re.I)),
    ("token_v5", re.compile(r"v5 API token", re.I)),
    ("version", re.compile(r"Pi-hole v5|not a Pi-hole v6", re.I)),
    ("log_off", re.compile(r"query log is turned off|privacy level", re.I)),
    ("rate_limited", re.compile(r"rate.limit|too many (?:login )?(?:attempts|requests)|\b429\b", re.I)),
    ("bad_response", re.compile(r"json|expecting value|response refused|not a .* answer", re.I)),
    ("auth", re.compile(r"\b40[13]\b|password|unauthori[sz]ed|forbidden|login|not.granted", re.I)),
    ("timeout", re.compile(r"timed? ?out|timeout", re.I)),
    ("refused", re.compile(r"connection refused|errno 111\b|winerror 10061", re.I)),
    ("unreachable", re.compile(r"name or service not known|nodename nor servname|"
                               r"no route to host|network is unreachable|host is unreachable|"
                               r"temporary failure in name resolution|getaddrinfo", re.I)),
)


def error_kind(text: str | None) -> str | None:
    """'URLError: <urlopen error [Errno 111] Connection refused>' -> 'refused'."""
    for kind, rx in _ERROR_KINDS:
        if text and rx.search(text):
            return kind
    return None


def error_text(text: str | None, lang: str) -> str:
    """A stored source error in plain, localized words when we know what it means (the
    "Test connection" wording, err.conn_<kind>; err.src_timeout since the loops wait
    longer than the test's 5 s); otherwise the sanitized text itself."""
    kind = error_kind(text)
    if not kind:
        return text or "?"
    return i18n.t("err.src_timeout" if kind == "timeout" else "err.conn_" + kind, lang)


def failure_line(source: str, err: BaseException, secrets=(), lang: str | None = None) -> str:
    """The one localized line a CLI prints when a source run failed (the same sentence as
    the status hint): never a traceback, never a secret."""
    lang = i18n.normalize(lang)
    text = sanitize_error(err, secrets)
    return i18n.t(f"status.hint.{source}_error", lang, error=error_text(text, lang))


def localized(st: dict, lang: str) -> dict:
    """status() plus `error_text` per source (the page shows that, not `last_error`)."""
    for s in st["sources"].values():
        s["error_text"] = error_text(s["last_error"], lang) if s.get("last_error") else None
    return st


DNS_SOURCES = ("adguard", "pihole")   # one of them feeds the dns loop (dns_ingest.dns_source_name)


def _secrets(env: dict) -> list:
    return [env.get(k, "") for k in ("ANTHROPIC_API_KEY", "NETWARDEN_AI_KEY", "ADGUARD_PASS",
                                     "PIHOLE_PASSWORD", "NTOPNG_PASS", "NTOPNG_TOKEN")]


def _parse(ts: str | None):
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _age(ts: str | None, now: datetime) -> float | None:
    dt = _parse(ts)
    return None if dt is None else max(0.0, (now - dt).total_seconds())


def status(db, db_path=None, env: dict | None = None, loops: dict | None = None,
           now: datetime | None = None) -> dict:
    """The health dict behind /api/status and `netwarden status`."""
    from netwarden import discovery, dns_ingest  # lazy: both import health
    env = env or {}
    now = now or datetime.now(timezone.utc)
    demo = store.is_demo(db)
    recorded = store.source_status(db)
    can_discover, why_not = discovery.availability()
    dns_active = dns_ingest.dns_source_name(env)
    sources = {}
    for name, (env_key, stale_after) in SOURCES.items():
        row = recorded.get(name, {})
        if demo:  # a frozen synthetic snapshot: "configured" = it has a story to tell
            configured = name in recorded
        elif name in DNS_SOURCES:  # both set up: only the selected one is ingested
            configured = name == dns_active
        elif env_key:
            configured = bool(env.get(env_key))
        else:
            configured = can_discover
        age = _age(row.get("last_ok_ts"), now)
        entry = {
            "configured": configured,
            "last_ok_ts": row.get("last_ok_ts"),
            "last_error_ts": row.get("last_error_ts"),
            "last_error": sanitize_error(row["last_error"], _secrets(env))
                          if row.get("last_error") else None,
            "last_count": row.get("last_count"),
            "stale": bool(configured and not demo and (age is None or age > stale_after)),
        }
        if name in ("discovery", *QUIET_SOURCES) and not can_discover and not demo:
            entry["reason"] = why_not
        sources[name] = entry
    ai = brain.ai_config(env, db)
    return {
        "version": netwarden.__version__,
        "demo": demo,
        "generated": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "sources": sources,
        "ai": {"mode": ai["mode"], "model": ai["model"], "reason": ai["reason"],
               "provider": ai["provider"], "destination": ai["destination"],
               "redact": ai["redact"]},
        "db": {**store.db_stats(db, db_path),
               "retention_days": settings.get(db, env, "data.retention_days")},
        "loops": loops or {},
    }


# --- presentation ------------------------------------------------------------

def ago(ts: str | None, lang: str, now: datetime | None = None) -> str:
    """'3 h' / '12 min' style age, localized; 'never' for no timestamp."""
    secs = _age(ts, now or datetime.now(timezone.utc))
    if secs is None:
        return i18n.t("status.never", lang)
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if secs >= size:
            return i18n.t("time." + unit, lang, n=int(secs // size))
    return i18n.t("time.s", lang, n=int(secs))


def ai_line(ai: dict, lang: str) -> str:
    """'AI: Anthropic (claude-...)' or, offline, just 'AI: offline (...)'."""
    why = ai.get("reason") if ai["mode"] == "offline" else None
    mode = i18n.t(f"status.ai.offline_{why}" if why in ("forced", "addon", "chosen")
                  else "status.ai." + ai["mode"], lang)
    if ai["mode"] == "offline":
        return i18n.t("status.ai_only", lang, mode=mode)
    line = i18n.t("status.ai", lang, mode=mode, model=ai["model"])
    if ai.get("destination") in ("local", "lan", "cloud"):   # where the prompts go
        line += " · " + i18n.t("ai.dest." + ai["destination"], lang,
                               provider=ai.get("provider") or "")
    if ai.get("redact"):
        line += " · " + i18n.t("ai.redact_on", lang)
    return line


def duration(seconds: float, lang: str) -> str:
    """An interval like 60 -> '1 min', 86400 -> '1 d' (largest unit that divides it)."""
    seconds = int(seconds)
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size and seconds % size == 0:
            return i18n.t("time." + unit, lang, n=seconds // size)
    return i18n.t("time.s", lang, n=seconds)


def _error_is_latest(s: dict) -> bool:
    return bool(s.get("last_error_ts")) and (not s.get("last_ok_ts")
                                              or s["last_error_ts"] > s["last_ok_ts"])


def state(name: str, s: dict) -> str:
    """One word per source: ok | stale | error | off | unavailable | never."""
    if not s["configured"]:
        return "unavailable" if s.get("reason") else "off"
    if _error_is_latest(s):
        return "error"
    if not s.get("last_ok_ts"):
        return "never"
    return "stale" if s["stale"] else "ok"


def hints(st: dict, lang: str, now: datetime | None = None) -> list:
    """Actionable, localized one-liners for whatever needs attention."""
    tr = lambda key, **kw: i18n.t("status.hint." + key, lang, **kw)  # noqa: E731
    out = []
    if st["demo"]:
        out.append(tr("demo"))
    dns = [st["sources"][n] for n in DNS_SOURCES if n in st["sources"]]
    no_dns = not any(s["configured"] for s in dns)
    if dns and no_dns:   # one hint for "no DNS source", not one per possible server
        out.append(tr("dns_off"))
    # mDNS and SSDP both ran fine yet identified nothing: typical when multicast replies
    # never reach us (WSL / Hyper-V firewall). Calm, once - names still come from elsewhere.
    # Since Stage V3 the same questions also go to every device directly (unicast) and
    # NetBIOS asks Windows machines: when even those stay silent, say so just as calmly.
    def silent(n):
        s = st["sources"].get(n) or {}
        return bool(s.get("last_ok_ts")) and not s.get("last_count") and state(n, s) == "ok"
    if not st["demo"] and silent("mdns") and silent("ssdp"):
        nb = st["sources"].get("netbios") or {}
        out.append(tr("ident_silent_unicast" if nb.get("last_ok_ts") and silent("netbios")
                      else "multicast_silent"))
    for name, s in st["sources"].items():
        word = state(name, s)
        if word == "ok":
            continue
        if name in DNS_SOURCES and word == "off":
            continue     # the other DNS server simply isn't in use (or covered above)
        if name in QUIET_SOURCES and word not in ("error", "stale"):
            continue     # not run yet / unavailable: the discovery hint already says so
        if word == "unavailable":
            out.append(tr("discovery_unavailable",
                          reason=i18n.t("status.reason." + (s.get("reason") or "no_lan"), lang)))
        elif word == "error":
            out.append(tr(f"{name}_error", error=error_text(s["last_error"], lang)))
        elif word in ("off", "never"):
            out.append(tr(f"{name}_{word}"))
        else:  # stale
            out.append(tr(f"{name}_stale", ago=ago(s["last_ok_ts"], lang, now)))
    if st["ai"]["mode"] == "offline" and st["ai"].get("reason") == "no_key":
        out.append(tr("ai_offline"))   # forced offline (--offline-ai) is the user's choice
    return out


def render(st: dict, lang: str, dashboard: str | None = None,
           now: datetime | None = None) -> str:
    """The `netwarden status` table. `dashboard` = URL of a dashboard that answered."""
    lang = i18n.normalize(lang)
    tr = lambda key, **kw: i18n.t("status." + key, lang, **kw)  # noqa: E731
    rows = [(tr("col_source"), tr("col_state"), tr("col_last_ok"), tr("col_count"))]
    for name, s in st["sources"].items():
        rows.append((tr("src." + name), tr("state." + state(name, s)),
                     ago(s["last_ok_ts"], lang, now) if s["last_ok_ts"] else "—",
                     "—" if s["last_count"] is None else str(s["last_count"])))
    widths = [max(_width(r[i]) for r in rows) for i in range(4)]
    lines = [tr("title", version=st["version"]) + (f"  [{tr('demo')}]" if st["demo"] else ""), ""]
    for i, r in enumerate(rows):
        lines.append("  " + "  ".join(pad(c, widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            lines.append("  " + "  ".join("-" * w for w in widths))
    db = st["db"]
    lines += ["",
              ai_line(st["ai"], lang),
              tr("db", size=brain.human_bytes(db["size_bytes"]), devices=db["devices"],
                 dns=db["dns_events"], traffic=db["traffic_samples"]),
              tr("db_range", oldest=(db["oldest_ts"] or "—")[:16].replace("T", " "),
                 newest=(db["newest_ts"] or "—")[:16].replace("T", " "),
                 days=db["retention_days"])]
    if st["loops"]:
        lines.append(tr("loops"))
        for name, lp in st["loops"].items():
            lines.append("  " + tr("loop_line", name=i18n.t("cli.loop." + name, lang),
                                   interval=duration(lp["interval_s"], lang),
                                   state=tr("loop_running" if lp["running"] else "loop_stopped")))
    if dashboard is not None:
        lines.append(tr("dashboard_up", url=dashboard) if dashboard else tr("dashboard_down"))
    tips = hints(st, lang, now)
    lines += ["", tr("hints") if tips else tr("all_good")]
    lines += [f"  → {h}" for h in tips]
    return "\n".join(lines)


def _width(text: str) -> int:
    """Display width: East Asian wide characters take two terminal columns."""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def pad(text: str, width: int) -> str:
    """`text` padded to `width` terminal columns (CLI tables; never truncates)."""
    return text + " " * (width - _width(text))
