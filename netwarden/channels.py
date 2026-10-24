"""
netwarden - channels.py: where a push notification goes (round 10, Stage N).

One small adapter per service behind one interface. An adapter never sends anything
itself: build() turns a finished message (push.py renders it) into a Request - method,
URL, headers, body - and send() is the ONE function that talks to the network:

    Request = build(ctype, fields, secrets, msg)      # pure: no network, no clock
    preview(req, secrets)                             # the exact request, credentials masked
    Result  = send(req, timeout)                      # one HTTP exchange, never a redirect

Self-hosted first: ntfy, Gotify, Home Assistant (a notify service, with the HA URL and a
long-lived token), a generic webhook (JSON, versioned schema, optional HMAC-SHA256
signature header). Hosted: Discord and Slack webhooks, a Telegram bot, LINE Messaging
API push, Matrix. Every text is sent as PLAIN text or escaped for that service's markup
(device names are hostile input). Base URLs of hosted services are module constants so
tests can point them at a fake server on 127.0.0.1; tests never contact a real host.

Safety (docs/notifications.md): http and https only, no user:password@ in a URL, size
limits, a few seconds of timeout, TLS verification always on - or, for a self-signed
self-hosted server, an explicit per-channel pinned certificate (SHA-256 of the DER
certificate) checked BEFORE a single byte of the request is sent. Redirects are never
followed (a 3xx is the error class "redirect"). Errors are CLASSES ("http_401",
"timeout", "tls", ...), never a body or a token.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime

import netwarden

# --- hosted services: base URLs + allowed webhook hosts (tests patch these) ------------
TELEGRAM_API = "https://api.telegram.org"
LINE_API = "https://api.line.me"
DISCORD_HOSTS = ("discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com")
SLACK_HOSTS = ("hooks.slack.com",)
HOSTED_SCHEMES = ("https",)     # a hosted webhook URL is https (tests add "http")

TIMEOUT = 8.0                   # seconds for one exchange (connect + answer)
MAX_BODY = 64 * 1024            # what we send at most (bytes)
MAX_ANSWER = 64 * 1024          # what we read of an answer at most
MAX_RETRY_AFTER = 3600          # seconds: a longer Retry-After is capped
MASK = "•••"
WEBHOOK_SCHEMA = "netwarden.notification/1"
SIGNATURE_HEADER = "X-Netwarden-Signature"
TIMESTAMP_HEADER = "X-Netwarden-Timestamp"

# service text limits (characters); a longer text is cut with "…"
LIMITS = {"ntfy": 3800, "gotify": 8000, "homeassistant": 4000, "webhook": 8000,
          "discord": 1900, "slack": 3800, "telegram": 4000, "line": 4900, "matrix": 8000}


@dataclass(frozen=True)
class Field:
    name: str
    kind: str                   # "url" | "text" | "secret" | "secret_url"
    required: bool = True
    pattern: str = ""           # a text field's full-match regex
    max_len: int = 300
    placeholder: str = ""


PIN = Field("pin", "text", False, r"[0-9a-f]{64}", 95)
# type -> (fields, hosted?, official setup docs)
TYPES = {
    "ntfy": ((Field("url", "url", placeholder="https://ntfy.sh"),
              Field("topic", "text", pattern=r"[A-Za-z0-9_-]{1,64}", max_len=64,
                    placeholder="netwarden-home"),
              Field("token", "secret", False), Field("user", "text", False, max_len=64),
              Field("password", "secret", False), PIN),
             False, "https://docs.ntfy.sh/publish/"),
    "gotify": ((Field("url", "url", placeholder="http://192.168.1.20:8080"),
                Field("token", "secret"), PIN),
               False, "https://gotify.net/docs/pushmsg"),
    "homeassistant": ((Field("url", "url", placeholder="http://homeassistant.local:8123"),
                       Field("token", "secret"),
                       Field("service", "text", pattern=r"[a-z0-9_]{1,64}", max_len=64,
                             placeholder="mobile_app_my_phone"), PIN),
                      False, "https://www.home-assistant.io/integrations/notify/"),
    "webhook": ((Field("url", "secret_url", placeholder="https://n8n.example.org/webhook/…"),
                 Field("secret", "secret", False), PIN),
                False, "https://github.com/liming-ting/netwarden/blob/main/docs/notifications.md"),
    "discord": ((Field("url", "secret_url",
                       placeholder="https://discord.com/api/webhooks/…"),),
                True, "https://support.discord.com/hc/en-us/articles/228383668"),
    "slack": ((Field("url", "secret_url", placeholder="https://hooks.slack.com/services/…"),),
              True, "https://api.slack.com/messaging/webhooks"),
    "telegram": ((Field("token", "secret"),
                  Field("chat_id", "text", pattern=r"-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31}",
                        max_len=40, placeholder="123456789")),
                 True, "https://core.telegram.org/bots/tutorial"),
    "line": ((Field("token", "secret"),
              Field("to", "text", pattern=r"[UCR][0-9a-f]{32}", max_len=33,
                    placeholder="U0123456789abcdef0123456789abcdef")),
             True, "https://developers.line.biz/en/docs/messaging-api/sending-messages/"),
    "matrix": ((Field("url", "url", placeholder="https://matrix.example.org"),
                Field("token", "secret"),
                Field("room", "text", pattern=r"![A-Za-z0-9._=/+-]{1,120}:[A-Za-z0-9.:-]{1,120}",
                      max_len=250, placeholder="!abcdefg:example.org"), PIN),
               False, "https://spec.matrix.org/latest/client-server-api/#sending-events-to-a-room"),
}
HOSTED = tuple(t for t, (_f, hosted, _d) in TYPES.items() if hosted)
SEND_OK, RETRYABLE = "ok", ("timeout", "connect", "dns", "http_429", "http_5xx")
ERROR_CLASSES = ("config", "http_400", "http_401", "http_403", "http_404", "http_429",
                 "http_4xx", "http_5xx", "redirect", "timeout", "connect", "dns", "tls",
                 "tls_pin", "too_large", "bad_answer")


class BadChannel(ValueError):
    """A channel configuration we refuse: `field` + err.<code> in the locales."""
    def __init__(self, field_name: str, code: str):
        super().__init__(f"{field_name}: {code}")
        self.field, self.code = field_name, code


def fields(ctype: str) -> tuple:
    return TYPES[ctype][0]


def secret_names(ctype: str) -> tuple:
    return tuple(f.name for f in fields(ctype) if f.kind.startswith("secret"))


# --- validation ------------------------------------------------------------------------

def clean_url(value: str, name: str = "url", schemes=("http", "https")) -> str:
    """http(s)://host[:port][/path]: no user:password@, no query, no fragment, no control
    characters. Canonical: lower-case scheme and host, no trailing slash."""
    v = (value or "").strip()
    if not v or len(v) > 500 or any(ord(c) < 33 or ord(c) == 127 for c in v):
        raise BadChannel(name, "push_url")
    try:
        u = urllib.parse.urlsplit(v)
        port = u.port
    except ValueError:
        raise BadChannel(name, "push_url") from None
    if u.scheme.lower() not in schemes or not u.hostname or "@" in u.netloc or u.query \
            or u.fragment or (port is not None and not 0 < port < 65536):
        raise BadChannel(name, "push_url")
    return urllib.parse.urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path.rstrip("/"), "", ""))


def clean_pin(value: str) -> str:
    """"AB:CD:..." / "abcd..." -> 64 lower-case hex digits; "" = no pin."""
    v = (value or "").strip().lower().replace(":", "").replace(" ", "")
    if v.startswith("sha256/") or v.startswith("sha256="):
        v = v[7:]
    if v and not re.fullmatch(r"[0-9a-f]{64}", v):
        raise BadChannel("pin", "push_pin")
    return v


def _hosted_webhook(ctype: str, url: str) -> str:
    u = clean_url(url, "url", HOSTED_SCHEMES)
    parts = urllib.parse.urlsplit(u)
    hosts, prefix = (DISCORD_HOSTS, "/api/webhooks/") if ctype == "discord" else \
        (SLACK_HOSTS, "/services/")
    if parts.hostname not in hosts or not parts.path.startswith(prefix) \
            or len(parts.path) <= len(prefix):
        raise BadChannel("url", "push_webhook_" + ctype)
    return u


def clean_field(ctype: str, f: Field, value) -> str:
    """One field's value in canonical form, or BadChannel."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise BadChannel(f.name, "push_invalid")
    v = value.strip()
    if not v:
        if f.required:
            raise BadChannel(f.name, "push_required")
        return ""
    if len(v) > max(f.max_len, 500 if f.kind.endswith("url") else 0) \
            or any(ord(c) < 32 or ord(c) == 127 for c in v):
        raise BadChannel(f.name, "push_invalid")
    if f.name == "pin":
        return clean_pin(v)
    if f.kind == "url":
        return clean_url(v, f.name)
    if f.kind == "secret_url":
        return _hosted_webhook(ctype, v) if ctype in ("discord", "slack") else clean_url(v, f.name)
    if f.kind == "secret":
        if len(v) > 4096 or any(c.isspace() for c in v):
            raise BadChannel(f.name, "push_invalid")
        if ctype == "telegram" and not re.fullmatch(r"\d{3,15}:[A-Za-z0-9_-]{20,80}", v):
            raise BadChannel(f.name, "push_telegram_token")
        return v
    if f.pattern and not re.fullmatch(f.pattern, v):
        raise BadChannel(f.name, "push_invalid")
    return v


def endpoint(ctype: str, cfg: dict, secrets: dict) -> str:
    """The URL the channel's requests go to (may hold a credential: never shown)."""
    if ctype == "telegram":
        return TELEGRAM_API
    if ctype == "line":
        return LINE_API
    if ctype in ("discord", "slack", "webhook"):
        return secrets.get("url") or ""
    return cfg.get("url") or ""


def shown_endpoint(ctype: str, cfg: dict, secrets: dict) -> str:
    """scheme://host[:port] of the endpoint: what the UI, the log and errors may show."""
    url = endpoint(ctype, cfg, secrets)
    if not url:
        return ""
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
        port = f":{u.port}" if u.port else ""
    except ValueError:
        return ""
    return f"{u.scheme}://{'[' + host + ']' if ':' in host else host}{port}"


# --- the request -----------------------------------------------------------------------

@dataclass
class Request:
    method: str
    url: str
    headers: dict
    body: bytes
    pin: str = ""
    secrets: tuple = field(default_factory=tuple)   # values preview() must mask


@dataclass
class Result:
    ok: bool
    error: str = ""             # one of ERROR_CLASSES ("" when ok)
    status: int | None = None
    retry_after: float | None = None
    data: object = None         # a parsed JSON answer (helpers only)

    @property
    def retryable(self) -> bool:
        return not self.ok and self.error in RETRYABLE


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def plain(msg: dict) -> str:
    """Title, body and the dashboard link as one plain text (services without a title)."""
    parts = [msg.get("title") or "", msg.get("body") or ""]
    if msg.get("url"):
        parts.append(msg["url"])
    return "\n".join(p for p in parts if p)


DISCORD_SPECIAL = re.compile(r"([\\*_~`|>#\[\]()\-:<@])")


def escape_discord(text: str) -> str:
    """Discord markdown off: every markup character backslash-escaped (and mentions are
    switched off by allowed_mentions as well)."""
    return DISCORD_SPECIAL.sub(r"\\\1", text)


def escape_slack(text: str) -> str:
    """Slack's three control characters (https://api.slack.com/reference/surfaces/formatting)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


NTFY_PRIORITY = {0: 5, 1: 4, 2: 3, 3: 2}
GOTIFY_PRIORITY = {0: 8, 1: 6, 2: 4, 3: 2}
NTFY_TAGS = {0: "rotating_light", 1: "warning", 2: "information_source", 3: "house"}


def _json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build(ctype: str, cfg: dict, secrets: dict, msg: dict, now: float | None = None) -> Request:
    """The HTTP request that delivers `msg` ({title, body, url, sev, category, kind, ...})
    on a channel of `ctype`. Pure: everything comes from the arguments."""
    sev = msg.get("sev", 3) if msg.get("sev") in (0, 1, 2, 3) else 3
    title = msg.get("title") or "netwarden"
    body = msg.get("body") or ""
    link = msg.get("url") or ""
    held = tuple(v for v in secrets.values() if v)
    headers = {"Content-Type": "application/json"}
    limit = LIMITS[ctype]
    if ctype == "ntfy":
        out = {"topic": cfg["topic"], "title": _cut(title, 200), "message": _cut(body, limit),
               "priority": NTFY_PRIORITY[sev], "tags": [NTFY_TAGS[sev]]}
        if link:
            out["click"] = link
        if secrets.get("token"):
            headers["Authorization"] = "Bearer " + secrets["token"]
        elif cfg.get("user") and secrets.get("password"):
            import base64
            pair = base64.b64encode(f"{cfg['user']}:{secrets['password']}".encode()).decode()
            headers["Authorization"] = "Basic " + pair
            held += (pair,)
        return Request("POST", cfg["url"] + "/", headers, _json(out), cfg.get("pin", ""), held)
    if ctype == "gotify":
        out = {"title": _cut(title, 200), "message": _cut(body, limit),
               "priority": GOTIFY_PRIORITY[sev]}
        if link:
            out["extras"] = {"client::notification": {"click": {"url": link}}}
        headers["X-Gotify-Key"] = secrets.get("token", "")
        return Request("POST", cfg["url"] + "/message", headers, _json(out), cfg.get("pin", ""), held)
    if ctype == "homeassistant":
        out = {"title": _cut(title, 200), "message": _cut(body + (f"\n{link}" if link else ""), limit)}
        if link:
            out["data"] = {"url": link, "clickAction": link}
        headers["Authorization"] = "Bearer " + secrets.get("token", "")
        return Request("POST", f"{cfg['url']}/api/services/notify/{cfg['service']}", headers,
                       _json(out), cfg.get("pin", ""), held)
    if ctype == "webhook":
        out = {"schema": WEBHOOK_SCHEMA, "id": msg.get("id") or "", "kind": msg.get("kind") or "alert",
               "category": msg.get("category") or "", "severity": SEVERITIES[sev],
               "title": _cut(title, 300), "body": _cut(body, limit), "url": link or None,
               "lang": msg.get("lang") or "", "level": msg.get("level") or "",
               "sent_at": msg.get("ts") or "", "count": int(msg.get("count") or 1)}
        raw = _json(out)
        if secrets.get("secret"):
            stamp = str(int(now if now is not None else time.time()))
            sig = hmac.new(secrets["secret"].encode(), stamp.encode() + b"." + raw,
                           hashlib.sha256).hexdigest()
            headers[TIMESTAMP_HEADER] = stamp
            headers[SIGNATURE_HEADER] = "sha256=" + sig
        return Request("POST", secrets.get("url", ""), headers, raw, cfg.get("pin", ""), held)
    if ctype == "discord":
        # the text escaped, the dashboard link (ours, not hostile) left clickable: <url>
        # also stops Discord from unfurling it into an embed
        text = escape_discord(plain({**msg, "url": ""}))
        if link:
            text = _cut(text, limit - len(link) - 3) + f"\n<{link}>"
        out = {"content": _cut(text, limit), "username": "netwarden",
               "allowed_mentions": {"parse": []}}
        return Request("POST", secrets.get("url", ""), headers, _json(out), "", held)
    if ctype == "slack":
        out = {"text": _cut(escape_slack(plain(msg)), limit), "mrkdwn": False,
               "unfurl_links": False}
        return Request("POST", secrets.get("url", ""), headers, _json(out), "", held)
    if ctype == "telegram":
        out = {"chat_id": cfg["chat_id"], "text": _cut(plain(msg), limit),
               "disable_web_page_preview": True}        # no parse_mode: plain text
        return Request("POST", f"{TELEGRAM_API}/bot{secrets.get('token', '')}/sendMessage",
                       headers, _json(out), "", held)
    if ctype == "line":
        out = {"to": cfg["to"], "messages": [{"type": "text", "text": _cut(plain(msg), limit)}]}
        headers["Authorization"] = "Bearer " + secrets.get("token", "")
        return Request("POST", f"{LINE_API}/v2/bot/message/push", headers, _json(out), "", held)
    if ctype == "matrix":
        # the transaction id must survive a retry (Matrix then answers with the event it
        # already stored instead of posting it twice): push.deliver passes the outbox row
        txn = hashlib.sha256(str(msg.get("txn") or f"{msg.get('id')}|{msg.get('ts')}").encode()).hexdigest()[:24]
        out = {"msgtype": "m.notice", "body": _cut(plain(msg), limit)}   # no formatted_body
        headers["Authorization"] = "Bearer " + secrets.get("token", "")
        room = urllib.parse.quote(cfg["room"], safe="")
        return Request("PUT", f"{cfg['url']}/_matrix/client/v3/rooms/{room}/send/m.room.message/nw{txn}",
                       headers, _json(out), cfg.get("pin", ""), held)
    raise BadChannel("type", "push_type")


SEVERITIES = ("critical", "high", "medium", "low")


def mask(text: str, secrets) -> str:
    for s in sorted((s for s in secrets if s and len(s) >= 4), key=len, reverse=True):
        for form in {s, urllib.parse.quote(s, safe=""), urllib.parse.quote(s, safe="/:")}:
            text = text.replace(form, MASK)
    return text


def preview(req: Request) -> dict:
    """The exact request with every credential masked: what the Settings page shows."""
    url = mask(req.url, req.secrets)
    try:   # a webhook URL is itself the credential: only scheme://host + the masked rest
        u = urllib.parse.urlsplit(req.url)
        if req.url in req.secrets:
            url = f"{u.scheme}://{u.netloc}/{MASK}"
    except ValueError:
        url = MASK
    headers = {k: (MASK if k.lower() in ("authorization", "x-gotify-key") else mask(v, req.secrets))
               for k, v in req.headers.items()}
    body = mask(req.body.decode("utf-8"), req.secrets)
    return {"method": req.method, "url": url, "headers": headers, "body": body}


# --- the one function that talks to the network ---------------------------------------

def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    v = value.strip()
    try:
        secs = float(v)
    except ValueError:
        try:
            secs = parsedate_to_datetime(v).timestamp() - time.time()
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
    return max(0.0, min(float(MAX_RETRY_AFTER), secs))


def status_class(code: int) -> str:
    if 200 <= code < 300:
        return ""
    if 300 <= code < 400:
        return "redirect"
    if code in (400, 401, 403, 404, 429):
        return f"http_{code}"
    return "http_5xx" if code >= 500 else "http_4xx"


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _connection(u, timeout: float, pin: str):
    host, port = u.hostname, u.port
    if u.scheme == "http":
        return http.client.HTTPConnection(host, port, timeout=timeout)
    ctx = ssl.create_default_context()
    if pin:
        # the pin replaces the CA check (a self-signed certificate): the certificate must
        # be exactly this one, compared in _send before anything is written
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)


def send(req: Request, timeout: float = TIMEOUT) -> Result:
    """One HTTP exchange. Never raises for network trouble: Result(ok, error class)."""
    try:
        u = urllib.parse.urlsplit(req.url)
        u.port   # noqa: B018 - raises on a bad port
    except ValueError:
        return Result(False, "config")
    if u.scheme not in ("http", "https") or not u.hostname or "@" in u.netloc:
        return Result(False, "config")
    if len(req.body) > MAX_BODY:
        return Result(False, "too_large")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    headers = {"User-Agent": f"netwarden/{netwarden.__version__}", "Accept": "application/json",
               **req.headers}
    if req.body or req.method in ("POST", "PUT"):
        headers["Content-Length"] = str(len(req.body))
    conn, watchdog, expired = None, None, threading.Event()

    def _expire():   # the socket timeout is per read: a trickling server is cut off here
        expired.set()
        with contextlib.suppress(OSError, AttributeError):
            conn.sock.shutdown(socket.SHUT_RDWR)
    try:
        deadline = time.monotonic() + timeout   # the WHOLE exchange, not each read
        conn = _connection(u, timeout, req.pin)
        conn.connect()
        watchdog = threading.Timer(max(deadline - time.monotonic(), 0.01), _expire)
        watchdog.daemon = True
        watchdog.start()
        if req.pin and u.scheme == "https":
            der = conn.sock.getpeercert(binary_form=True) or b""
            if not hmac.compare_digest(fingerprint(der), req.pin):
                return Result(False, "tls_pin")
        conn.request(req.method, path, body=req.body or None, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_ANSWER)
        if expired.is_set():
            return Result(False, "timeout")
        err = status_class(resp.status)
        if err:
            return Result(False, err, resp.status, _retry_after(resp.getheader("Retry-After"))
                          if resp.status in (429, 503) else None)
        data = None
        if raw and "json" in (resp.getheader("Content-Type") or ""):
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
        return Result(True, "", resp.status, None, data)
    except ssl.SSLCertVerificationError:
        return Result(False, "tls")
    except (socket.timeout, TimeoutError):
        return Result(False, "timeout")
    except ssl.SSLError:
        return Result(False, "timeout" if expired.is_set() else "tls")
    except socket.gaierror:
        return Result(False, "dns")
    except (OSError, http.client.HTTPException):
        return Result(False, "timeout" if expired.is_set() else "connect")
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if conn is not None:
            conn.close()


# --- explicit-click helpers (Settings): find a Telegram chat id, list HA notify services --

def telegram_chats(token: str, timeout: float = TIMEOUT) -> tuple[Result, list]:
    """getUpdates of the bot: the chats that wrote to it recently -> [{id, type, title}]."""
    req = Request("GET", f"{TELEGRAM_API}/bot{token}/getUpdates", {}, b"", "", (token,))
    res = send(req, timeout)
    chats: dict = {}
    if res.ok:
        if not isinstance(res.data, dict) or not isinstance(res.data.get("result"), list):
            return Result(False, "bad_answer", res.status), []
        for up in res.data["result"][:100]:
            if not isinstance(up, dict):
                continue
            for k in ("message", "channel_post", "my_chat_member", "edited_message"):
                chat = (up.get(k) or {}).get("chat") if isinstance(up.get(k), dict) else None
                if isinstance(chat, dict) and isinstance(chat.get("id"), int):
                    name = chat.get("title") or chat.get("username") or chat.get("first_name") or ""
                    chats[chat["id"]] = {"id": str(chat["id"]), "type": str(chat.get("type") or "")[:20],
                                         "title": str(name)[:80]}
    return res, list(chats.values())[:20]


def ha_services(url: str, token: str, pin: str = "", timeout: float = TIMEOUT) -> tuple[Result, list]:
    """GET /api/services of Home Assistant -> the names of its notify services."""
    req = Request("GET", f"{url}/api/services", {"Authorization": "Bearer " + token}, b"", pin, (token,))
    res = send(req, timeout)
    names: list = []
    if res.ok:
        if not isinstance(res.data, list):
            return Result(False, "bad_answer", res.status), []
        for dom in res.data:
            if isinstance(dom, dict) and dom.get("domain") == "notify" \
                    and isinstance(dom.get("services"), dict):
                names = sorted(str(s) for s in dom["services"]
                               if isinstance(s, str) and re.fullmatch(r"[a-z0-9_]{1,64}", s))
    return res, names[:50]


def destination(ctype: str, cfg: dict, secrets: dict) -> str:
    """Where this channel's text ends up: hosted services are always "cloud"; otherwise
    settings.destination() of the endpoint (local / lan / cloud; names never resolved)."""
    if ctype in HOSTED:
        return "cloud"
    from netwarden import settings
    url = endpoint(ctype, cfg, secrets)
    return settings.destination(url) if url else "none"
