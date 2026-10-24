"""
netwarden - settings.py: one typed registry for the knobs a user can turn.

Every setting has a key ("ai.provider"), a type, a default, optionally an environment
variable, a validator, a group (for the settings page) and two flags:

  secret      comes ONLY from the environment (.env / a real env var). Never stored in
              the DB, never returned, never logged: the API says just "configured".
  admin       changing it is an administrator's job (LAN mode, a later stage, will
              only let the admin account do it; on loopback the local user is admin).

Effective value = environment > the DB (`settings` table, set from the dashboard) >
the default. A key that is set in the environment is read-only in the dashboard (the
API reports source "env" and editable false), so .env stays the single source of
truth for whoever configured the machine.

    values(db, env)           -> {key: effective value}
    get(db, env, key)         -> one effective value
    describe(db, env, lang)   -> what GET /api/settings returns
    update(db, env, changes)  -> validate + store (raises SettingError)

Later stages register their own settings with register(Setting(...)).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from netwarden import i18n, store

log = logging.getLogger("netwarden.settings")


class SettingError(ValueError):
    """A rejected change: `key` = the setting, `code` = err.<code> in the locales."""
    def __init__(self, key: str, code: str):
        super().__init__(f"{key}: {code}")
        self.key, self.code = key, code


@dataclass(frozen=True)
class Setting:
    key: str
    type: str                       # "choice" | "str" | "int" | "bool" | "url" | "time" | "secret"
    default: Any
    env: str | None = None
    group: str = "general"
    secret: bool = False
    admin: bool = False
    choices: tuple = ()
    minimum: int | None = None
    maximum: int | None = None
    max_len: int = 200
    placeholder: str = ""           # an example value the settings form shows
    inputmode: str = ""             # a text field's phone keyboard ("decimal" for money)
    validator: Callable[[Any], Any] | None = field(default=None, compare=False)

    def clean(self, value):
        """The value in canonical form, or SettingError(self.key, code)."""
        if self.secret:
            raise SettingError(self.key, "setting_secret")
        if self.type == "bool":
            if isinstance(value, bool):
                return value
            word = str(value).strip().lower() if isinstance(value, (str, int)) else ""
            if word in ("1", "true", "yes", "on"):
                return True
            if word in ("0", "false", "no", "off"):
                return False
            raise SettingError(self.key, "setting_invalid")
        if self.type == "int":
            if isinstance(value, bool):
                raise SettingError(self.key, "setting_invalid")
            try:
                value = int(str(value).strip())
            except ValueError:
                raise SettingError(self.key, "setting_invalid") from None
            if (self.minimum is not None and value < self.minimum) or \
                    (self.maximum is not None and value > self.maximum):
                raise SettingError(self.key, "setting_range")
            return value
        if not isinstance(value, str):
            raise SettingError(self.key, "setting_invalid")
        value = value.strip()
        if len(value) > self.max_len or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise SettingError(self.key, "setting_invalid")
        if self.validator:          # may normalize first (e.g. "zh-tw" -> "zh-Hant")
            value = self.validator(value)
        if self.type == "choice" and value not in self.choices:
            raise SettingError(self.key, "setting_invalid")
        return value


# --- validators --------------------------------------------------------------

def _timezone(value: str) -> str:
    if value:
        from netwarden import activity
        if activity._zone(value) is None:
            raise SettingError("time.timezone", "setting_invalid")
    return value


def _language(value: str) -> str:
    code = i18n.match(value)
    if not code:
        raise SettingError("ui.language", "setting_invalid")
    return code


def clean_base_url(value: str) -> str:
    """An OpenAI-compatible server's base URL: http(s), a host, no user:password@, no
    query or fragment. "" = not set. "http://host:11434" gets the usual "/v1" path."""
    if not value:
        return ""
    try:
        u = urllib.parse.urlsplit(value)
        port = u.port   # raises ValueError on a bad port
    except ValueError:
        raise SettingError("ai.base_url", "setting_url") from None
    if u.scheme not in ("http", "https") or not u.hostname or "@" in u.netloc \
            or u.query or u.fragment or (port is not None and not 0 < port < 65536):
        raise SettingError("ai.base_url", "setting_url")
    path = u.path.rstrip("/") or "/v1"
    return urllib.parse.urlunsplit((u.scheme, u.netloc.lower(), path, "", ""))


def clean_advertised_url(value: str) -> str:
    """Where phones reach this dashboard when the detected LAN address is wrong (Docker
    bridge networking, a reverse proxy): "http(s)://host[:port]", nothing else - no
    user:password@, path, query or fragment. Canonical form: scheme://host[:port],
    lower case. "" = use the detected address. The name is never resolved."""
    if not value:
        return ""
    try:
        u = urllib.parse.urlsplit(value)
        port = u.port   # raises ValueError on a bad port
    except ValueError:
        raise SettingError("lan.advertised_url", "setting_advertised_url") from None
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host or "@" in u.netloc \
            or u.path not in ("", "/") or u.query or u.fragment or "%" in host \
            or (port is not None and not 0 < port < 65536):
        raise SettingError("lan.advertised_url", "setting_advertised_url")
    shown = f"[{host}]" if ":" in host else host
    if port == (443 if u.scheme == "https" else 80):
        port = None   # the form a browser's Origin header uses
    return f"{u.scheme}://{shown}" + (f":{port}" if port is not None else "")


def _model(value: str) -> str:
    # model ids look like "llama3.2:3b", "qwen2.5-7b-instruct", "org/model.gguf"
    if value and not all(c.isalnum() or c in "._:-/@+" for c in value):
        raise SettingError("ai.model", "setting_invalid")
    return value


MONEY_RE = re.compile(r"\d{1,7}(\.\d{1,4})?")


def _money(key: str):
    # round 7 C: a US$ amount ("5", "12.50", "0.0001"); "" = not set. Never negative or 0.
    def check(value: str) -> str:
        if not value:
            return ""
        v = value.replace(",", ".").lstrip("$").strip()
        if not MONEY_RE.fullmatch(v) or float(v) <= 0:
            raise SettingError(key, "setting_money")
        whole, _, frac = v.partition(".")
        return str(int(whole)) + ("." + frac if frac.strip("0") else "")
    return check


def _probe_target(value: str) -> str:
    # the optional internet probe: "host:port" ("" = off); see nethealth.parse_target
    if not value:
        return ""
    from netwarden import nethealth
    try:
        host, port = nethealth.parse_target(value)
    except ValueError:
        raise SettingError("health.internet_probe", "setting_invalid") from None
    return f"[{host}]:{port}" if ":" in host else f"{host.lower()}:{port}"


def _quiet_time(key: str):
    def check(value: str) -> str:
        from netwarden import quiet
        try:
            return quiet.clean_time(value)
        except quiet.BadQuiet:
            raise SettingError(key, "setting_invalid") from None
    return check


def _quiet_days(value: str) -> str:
    from netwarden import quiet
    try:
        return quiet.clean_days(value)
    except quiet.BadQuiet:
        raise SettingError("quiet.days", "setting_invalid") from None


# --- the registry -----------------------------------------------------------

AI_PROVIDERS = ("auto", "anthropic", "openai_compat", "offline")
REDACT_CHOICES = ("auto", "on", "off")
AI_TOOLS = ("auto", "off")

REGISTRY: dict[str, Setting] = {}


def register(s: Setting) -> Setting:
    REGISTRY[s.key] = s
    return s


register(Setting("ui.language", "choice", i18n.DEFAULT, "NETWARDEN_LANG", "general",
                 choices=tuple(i18n.CODES), validator=_language))
register(Setting("time.timezone", "str", "", "NETWARDEN_TZ", "general", max_len=64,
                 validator=_timezone))
register(Setting("data.retention_days", "int", store.DEFAULT_RETENTION_DAYS,
                 "NETWARDEN_RETENTION_DAYS", "data", admin=True,
                 minimum=store.MIN_RETENTION_DAYS, maximum=3650))
register(Setting("ai.provider", "choice", "auto", "NETWARDEN_AI_PROVIDER", "ai", admin=True,
                 choices=AI_PROVIDERS))
register(Setting("ai.base_url", "url", "", "NETWARDEN_AI_BASE_URL", "ai", admin=True,
                 max_len=300, validator=clean_base_url,
                 placeholder="http://127.0.0.1:11434/v1"))   # Ollama's default
register(Setting("ai.model", "str", "", "NETWARDEN_AI_MODEL", "ai", admin=True,
                 max_len=200, validator=_model, placeholder="llama3.2"))
register(Setting("ai.redact", "choice", "auto", "NETWARDEN_AI_REDACT", "ai", admin=True,
                 choices=REDACT_CHOICES))
# Stage A: the AI may run read-only lookups (ai_tools.py) while it answers a question.
register(Setting("ai.tools", "choice", "auto", "NETWARDEN_AI_TOOLS", "ai", admin=True,
                 choices=AI_TOOLS))
register(Setting("ai.max_tool_rounds", "int", 4, "NETWARDEN_AI_TOOL_ROUNDS", "ai", admin=True,
                 minimum=1, maximum=6))
# Round 7 C: AI usage (usage.py) - an optional monthly budget (US$, "" = none) that warns
# at ai.budget_warn % and asks before an answer would go over it; and prices per million
# tokens that override the built-in Anthropic table (an OpenAI-compatible cloud service).
register(Setting("ai.monthly_budget", "str", "", "NETWARDEN_AI_BUDGET", "usage", admin=True,
                 max_len=12, validator=_money("ai.monthly_budget"), placeholder="5.00",
                 inputmode="decimal"))
register(Setting("ai.budget_warn", "int", 80, None, "usage", admin=True, minimum=50, maximum=99))
register(Setting("ai.price_input", "str", "", "NETWARDEN_AI_PRICE_INPUT", "usage", admin=True,
                 max_len=12, validator=_money("ai.price_input"), placeholder="0.50",
                 inputmode="decimal"))
register(Setting("ai.price_output", "str", "", "NETWARDEN_AI_PRICE_OUTPUT", "usage", admin=True,
                 max_len=12, validator=_money("ai.price_output"), placeholder="1.50",
                 inputmode="decimal"))
register(Setting("health.internet_probe", "str", "", "NETWARDEN_INTERNET_PROBE", "health",
                 admin=True, max_len=262, validator=_probe_target, placeholder="1.1.1.1:443"))
# Stage M: also listen on the LAN address at the NEXT start (phones need pairing).
register(Setting("lan.enabled", "bool", False, "NETWARDEN_LAN", "lan", admin=True))
# Round 6 (containers / reverse proxies): the address the pairing QR points at and the
# extra Host / Origin this dashboard answers to in LAN mode (read at start).
register(Setting("lan.advertised_url", "url", "", "NETWARDEN_ADVERTISED_URL", "lan", admin=True,
                 max_len=300, validator=clean_advertised_url,
                 placeholder="http://192.168.1.20:8787"))
# Stage X: how the inbox snoozes, and on/off switches for the two "people" alerts.
register(Setting("alerts.snooze_days", "int", 7, None, "alerts", minimum=1, maximum=90))
register(Setting("alerts.unusual_hours", "bool", True, None, "alerts"))
register(Setting("family.bedtime_alerts", "bool", True, None, "family"))
# Stage P: presence ("who's home"), opt-in per person on the People page.
register(Setting("presence.check_minutes", "int", 5, None, "family", admin=True,
                 minimum=2, maximum=60))
register(Setting("presence.grace_minutes", "int", 20, None, "family", minimum=5, maximum=120))
# Stage Q: quiet hours (quiet.py) - notifications wait, the dashboard keeps everything.
register(Setting("quiet.enabled", "bool", False, None, "quiet"))
register(Setting("quiet.start", "time", "22:30", None, "quiet", max_len=5,
                 validator=_quiet_time("quiet.start"), placeholder="22:30"))
register(Setting("quiet.end", "time", "07:00", None, "quiet", max_len=5,
                 validator=_quiet_time("quiet.end"), placeholder="07:00"))
register(Setting("quiet.days", "str", "", None, "quiet", max_len=120, validator=_quiet_days,
                 placeholder="4=23:30-09:00,5=off"))
register(Setting("quiet.critical", "bool", True, None, "quiet"))
register(Setting("ai.key", "secret", None, "NETWARDEN_AI_KEY", "ai", secret=True, admin=True))
register(Setting("ai.anthropic_key", "secret", None, "ANTHROPIC_API_KEY", "ai", secret=True,
                 admin=True))


def env_keys() -> tuple:
    """Every environment variable the registry reads (brain.load_env lets a real env
    var override .env for these)."""
    return tuple(s.env for s in REGISTRY.values() if s.env)


# --- reading ----------------------------------------------------------------

def _stored(db) -> dict:
    if db is None:
        return {}
    try:
        return store.get_settings(db)
    except Exception:   # noqa: BLE001 - an old / read-only DB: defaults then
        return {}


_warned: set = set()


def _resolve(s: Setting, env: dict, stored: dict) -> tuple:
    """(value, source, invalid) for one setting."""
    raw = (env.get(s.env) or "").strip() if s.env else ""
    if s.secret:
        return None, ("env" if raw else "default"), False
    if raw:
        try:
            return s.clean(raw), "env", False
        except SettingError as e:
            if e.code == "setting_range":   # e.g. RETENTION_DAYS=3 has always meant the minimum
                n = int(raw)
                return max(s.minimum, min(s.maximum, n)), "env", False
            if s.env not in _warned:
                _warned.add(s.env)
                log.warning("ignoring invalid %s from the environment", s.env)
            return s.default, "env", True
    if s.key in stored:
        try:
            return s.clean(json.loads(stored[s.key])), "db", False
        except (ValueError, TypeError):   # SettingError is a ValueError
            return s.default, "db", True
    return s.default, "default", False


def values(db, env: dict | None) -> dict:
    """{key: effective value} for every non-secret setting (one small SELECT)."""
    env, stored = env or {}, _stored(db)
    return {k: _resolve(s, env, stored)[0] for k, s in REGISTRY.items() if not s.secret}


def get(db, env: dict | None, key: str):
    s = REGISTRY[key]
    return _resolve(s, env or {}, _stored(db))[0]


# The settings page's sections, in order, and which registry groups each one shows.
SECTIONS = (("general", ("general", "data")), ("alerts", ("alerts",)), ("quiet", ("quiet",)),
            ("ai", ("ai",)), ("usage", ("usage",)),
            ("family", ("family",)), ("health", ("health",)), ("phone", ("lan",)))
SECTION_OF = {g: sec for sec, groups in SECTIONS for g in groups}


def describe(db, env: dict | None, lang: str) -> dict:
    """GET /api/settings: each setting with its effective value, where it comes from
    and whether the dashboard may change it. Secrets: only `configured`. Plus the
    page's sections (key + localized name) in order."""
    env, stored = env or {}, _stored(db)
    items = []
    for s in REGISTRY.values():
        value, source, invalid = _resolve(s, env, stored)
        item = {"key": s.key, "type": s.type, "group": s.group, "source": source,
                "section": SECTION_OF.get(s.group, "general"),
                "env": s.env, "secret": s.secret, "admin": s.admin,
                "editable": not s.secret and source != "env",
                "label": i18n.t(f"settings.{s.key}", lang),
                "help": i18n.t(f"settings.help.{s.key}", lang)}
        if s.secret:
            item["configured"] = source == "env"
        else:
            item.update(value=value, default=s.default)
            if s.choices:
                item["choices"] = list(s.choices)
            if s.minimum is not None:
                item.update(min=s.minimum, max=s.maximum)
            if s.placeholder:
                item["placeholder"] = s.placeholder
            if s.inputmode:
                item["inputmode"] = s.inputmode
            if invalid:
                item["invalid"] = True
        items.append(item)
    return {"items": items, "sections": [{"key": sec, "label": i18n.t("settings.section." + sec, lang)}
                                         for sec, _groups in SECTIONS]}


def apply(db, env: dict | None) -> dict:
    """Hand the settings that live in module state to their modules (today: the time
    zone for activity.local_tz). Called when the server starts and after a change."""
    from netwarden import activity
    vals = values(db, env)
    activity.SETTING_TZ = vals["time.timezone"] or None
    return vals


# --- writing ----------------------------------------------------------------

def update(db, env: dict | None, changes) -> dict:
    """Validate {key: value} and store it in one transaction; None / "" resets a key to
    its default. Unknown, secret or environment-set keys are refused (SettingError);
    nothing is written unless every change is valid. Returns the stored changes."""
    env = env or {}
    if not isinstance(changes, dict) or not changes:
        raise SettingError("", "bad_json")
    out = {}
    for key, value in changes.items():
        s = REGISTRY.get(key) if isinstance(key, str) else None
        if s is None:
            raise SettingError(str(key)[:64], "setting_unknown")
        if s.secret:
            raise SettingError(key, "setting_secret")
        if s.env and (env.get(s.env) or "").strip():
            raise SettingError(key, "setting_env")
        if value is None or value == "":
            out[key] = None
            continue
        out[key] = json.dumps(s.clean(value), ensure_ascii=False)
    store.put_settings(db, out)
    return {k: (None if v is None else json.loads(v)) for k, v in out.items()}


# --- where an AI endpoint sends data -------------------------------------------

LAN_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain")


def _legacy_ipv4(host: str):
    """The address behind the old numeric spellings the OS still connects to:
    "134744072", "0x08080808", "8.8", "010.010.010.010" (octal) - all are 8.8.8.8-style
    addresses, not single-label LAN names. None for anything else."""
    if not re.fullmatch(r"[0-9a-fx.]+", host) or not re.match(r"\d", host):
        return None
    try:
        return ipaddress.ip_address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def destination(url: str | None) -> str:
    """Where data sent to `url` ends up: "local" (this computer: loopback), "lan" (a
    private / link-local address, or a single-label or .local/.lan/.home.arpa name),
    or "cloud" (anything else - we never resolve names to find out, so an unknown
    name counts as cloud and gets redaction by default). "none" for no URL."""
    if not url:
        return "none"
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return "cloud"
    if not host:
        return "cloud"
    if host == "localhost" or host.endswith(".localhost"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _legacy_ipv4(host)
        if ip is None:
            if "." not in host or host.endswith(LAN_SUFFIXES):
                return "lan"
            return "cloud"
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "lan"
    return "cloud"
