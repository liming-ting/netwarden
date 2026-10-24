"""
netwarden - pairing.py: open the dashboard on your phone (Stage M, opt-in LAN mode).

Off by default. With LAN mode on (`run --lan`, or the lan.enabled setting at the next
start) the dashboard also listens on this computer's LAN address, and every request
that does NOT come from this computer needs a session. A phone gets one by pairing:

  1. On this computer (System -> "Open on your phone", or `python3 -m netwarden pair`)
     netwarden creates a one-time code: 10 characters from an alphabet without look-
     alike letters (~49 bits), valid for 10 minutes, usable ONCE, stored only as a
     SHA-256 hash. It is shown as a QR code of  http://<lan-ip>:<port>/pair#<code>
     - the code lives in the URL FRAGMENT, which browsers never send to a server, so
     it never appears in a request line or a log.
  2. The phone opens that page; its script POSTs the code (JSON body) to /api/pair and
     gets a session cookie: 256 random bits, stored hashed, HttpOnly, SameSite=Strict,
     30 days that slide forward while the phone keeps using it. The session is
     labelled with the phone's user agent ("iPhone · Safari") so the user can tell
     which one to revoke.
  3. Wrong codes are rate-limited per client address (Limiter: a short lockout after a
     few misses) and globally (so many addresses can't share the guessing).

Comparisons of secrets use hmac.compare_digest. The plain-HTTP caveat is real: on the
LAN the cookie travels unencrypted, so the UI says to use this only on a trusted home
network. Admin actions (settings, pairing, port checks, AI configuration) are for this
computer's own browser - or for an ADMIN session (round 6, headless installs):

  `python3 -m netwarden pair --admin` (a terminal on the box, `docker exec`, or the one
  code a headless first start prints to its log, headless.py) makes an admin code: the
  same format and the same /pair page, but valid for ADMIN_CODE_TTL (15 minutes) and
  redeemed into a session flagged admin. Codes are only ever shown on a terminal / log,
  never by an HTTP endpoint. Redeeming one marks the install claimed (meta
  admin_claimed), so a headless start never prints another code.

    new_code(db, admin=False) -> {"id", "code", "display", "expires_at", "ttl_s", "admin"}
    redeem(db, code, ua)    -> (token, session id) | None      (single use)
    check(db, token)        -> {"id", "label", "refresh", "admin"} | None (sliding expiry)
    sessions(db), revoke(db, id), revoke_all(db), logout(db, token), claimed(db)
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from html import escape

from netwarden import i18n, store

CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"   # no 0/O, 1/I/L, U: easy to type
CODE_LEN = 10
CODE_TTL = timedelta(minutes=10)
ADMIN_CODE_TTL = timedelta(minutes=15)   # `pair --admin` / the headless first-start code
CLAIMED_META = "admin_claimed"     # meta key: an admin code was redeemed on this install
MAX_OPEN_CODES = 5                # unused, unexpired codes kept at once (oldest dropped)
SESSION_TTL = timedelta(days=30)
TOUCH_EVERY = timedelta(minutes=5)  # how often a used session's expiry slides forward
MAX_SESSIONS = 50                  # paired browsers; the least recently used goes first
MAX_LABEL = 300                    # the stored user agent
COOKIE = "nw_session"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")   # secrets.token_urlsafe(32)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


# --- one-time codes ------------------------------------------------------------

def normalize_code(raw) -> str | None:
    """The canonical code from what a person typed or a URL fragment carried: case,
    spaces and dashes don't matter. None if it can't be a code at all."""
    if not isinstance(raw, str) or len(raw) > 40:
        return None
    code = re.sub(r"[\s-]", "", raw).upper()
    if len(code) != CODE_LEN or any(c not in CODE_ALPHABET for c in code):
        return None
    return code


def display_code(code: str) -> str:
    return code[:5] + "-" + code[5:]


def new_code(db, now: datetime | None = None, admin: bool = False) -> dict:
    """A fresh one-time code (shown once, stored as a hash). Expired / used codes are
    cleaned up, and at most MAX_OPEN_CODES stay valid at a time. admin=True: the
    session it opens may do admin actions (only the CLI / a headless start make one)."""
    now = _now(now)
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))
    ttl = ADMIN_CODE_TTL if admin else CODE_TTL
    expires = now + ttl
    with db:
        db.execute("DELETE FROM pair_codes WHERE expires_at <= ? OR used_at IS NOT NULL",
                   (_iso(now),))
        cur = db.execute("INSERT INTO pair_codes (code_hash, created_at, expires_at, admin) "
                         "VALUES (?, ?, ?, ?)", (_hash(code), _iso(now), _iso(expires), int(admin)))
        db.execute("""DELETE FROM pair_codes WHERE id NOT IN
                      (SELECT id FROM pair_codes ORDER BY id DESC LIMIT ?)""", (MAX_OPEN_CODES,))
    return {"id": cur.lastrowid, "code": code, "display": display_code(code),
            "expires_at": _iso(expires), "ttl_s": int(ttl.total_seconds()), "admin": admin}


def redeem(db, raw_code, user_agent: str = "", now: datetime | None = None):
    """Trade a valid code for a new session: (token, session id), or None. The code
    is spent atomically (a second redeem of the same code always fails)."""
    now = _now(now)
    code = normalize_code(raw_code)
    if code is None:
        return None
    wanted = _hash(code)
    rows = db.execute("SELECT id, code_hash, admin FROM pair_codes WHERE used_at IS NULL "
                      "AND expires_at > ?", (_iso(now),)).fetchall()
    match = None
    for r in rows:   # every open code is compared, in constant time each
        if hmac.compare_digest(r["code_hash"], wanted):
            match = r
    if match is None:
        return None
    admin = int(bool(match["admin"]))
    token = secrets.token_urlsafe(32)          # 256 random bits
    with db:
        spent = db.execute("UPDATE pair_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
                           (_iso(now), match["id"])).rowcount
        if not spent:
            return None
        cur = db.execute("INSERT INTO sessions (token_hash, label, created_at, last_seen, "
                         "expires_at, admin) VALUES (?, ?, ?, ?, ?, ?)",
                         (_hash(token), store.clean_text(user_agent, MAX_LABEL), _iso(now),
                          _iso(now), _iso(now + SESSION_TTL), admin))
        db.execute("""DELETE FROM sessions WHERE id NOT IN
                      (SELECT id FROM sessions ORDER BY last_seen DESC LIMIT ?)""", (MAX_SESSIONS,))
        if admin:   # this install has been claimed: a headless start stays quiet from now on
            db.execute("INSERT INTO meta (key, value) VALUES (?, '1') ON CONFLICT(key) "
                       "DO UPDATE SET value = '1'", (CLAIMED_META,))
    return token, cur.lastrowid


def claimed(db) -> bool:
    """Has an admin code ever been redeemed on this install (headless claim)?"""
    return store.get_meta(db, CLAIMED_META) == "1"


# --- sessions ------------------------------------------------------------------

def check(db, token, now: datetime | None = None) -> dict | None:
    """The live session for a cookie token, or None. A session in use slides its
    30-day expiry forward (written at most every TOUCH_EVERY); "refresh" tells the
    server to re-send the cookie with a fresh Max-Age."""
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        return None
    now = _now(now)
    h = _hash(token)
    r = db.execute("SELECT id, token_hash, label, last_seen, admin FROM sessions "
                   "WHERE token_hash = ? AND expires_at > ?", (h, _iso(now))).fetchone()
    if not r or not hmac.compare_digest(r["token_hash"], h):
        return None
    refresh = False
    last = datetime.fromisoformat(r["last_seen"].replace("Z", "+00:00"))
    if now - last >= TOUCH_EVERY:
        with db:
            db.execute("UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?",
                       (_iso(now), _iso(now + SESSION_TTL), r["id"]))
        refresh = True
    return {"id": r["id"], "label": r["label"], "refresh": refresh, "admin": bool(r["admin"])}


def sessions(db, now: datetime | None = None, current: int | None = None) -> list[dict]:
    """Paired browsers that are still valid, most recently used first."""
    rows = db.execute("SELECT id, label, created_at, last_seen, expires_at, admin FROM sessions "
                      "WHERE expires_at > ? ORDER BY last_seen DESC", (_iso(_now(now)),))
    return [{"id": r["id"], "device": device_label(r["label"]), "user_agent": r["label"],
             "created_at": r["created_at"], "last_seen": r["last_seen"],
             "expires_at": r["expires_at"], "current": r["id"] == current,
             "admin": bool(r["admin"])} for r in rows]


def revoke(db, session_id: int) -> bool:
    with db:
        return db.execute("DELETE FROM sessions WHERE id = ?", (session_id,)).rowcount > 0


def revoke_all(db) -> int:
    with db:
        n = db.execute("DELETE FROM sessions").rowcount
        db.execute("DELETE FROM pair_codes")   # a code still on someone's screen dies too
    return n


def logout(db, token) -> bool:
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        return False
    with db:
        return db.execute("DELETE FROM sessions WHERE token_hash = ?",
                          (_hash(token),)).rowcount > 0


def prune(db, now: datetime | None = None) -> int:
    now = _iso(_now(now))
    with db:
        n = db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,)).rowcount
        db.execute("DELETE FROM pair_codes WHERE expires_at <= ? OR used_at IS NOT NULL", (now,))
    return n


# --- cookies -----------------------------------------------------------------------

def cookie(token: str) -> str:
    """Set-Cookie value. No `Secure`: LAN mode is plain HTTP (the UI warns about it)."""
    return (f"{COOKIE}={token}; Path=/; Max-Age={int(SESSION_TTL.total_seconds())}; "
            "HttpOnly; SameSite=Strict")


def clear_cookie() -> str:
    return f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def token_from_cookie(header: str | None) -> str | None:
    """Our cookie's value from a Cookie header (tolerant of anything else in there)."""
    for part in (header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE and TOKEN_RE.match(value.strip()):
            return value.strip()
    return None


# --- "iPhone · Safari" ----------------------------------------------------------

_OS = (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("CrOS", "ChromeOS"),
       ("Windows", "Windows"), ("Macintosh", "Mac"), ("Linux", "Linux"))
_BROWSERS = (("EdgiOS/", "Edge"), ("EdgA/", "Edge"), ("Edg/", "Edge"),
             ("SamsungBrowser/", "Samsung Internet"), ("FxiOS/", "Firefox"),
             ("Firefox/", "Firefox"), ("CriOS/", "Chrome"), ("OPR/", "Opera"),
             ("Chrome/", "Chrome"), ("Safari/", "Safari"))


def device_label(ua: str | None) -> str:
    """A short "platform · browser" from a user agent (brand names, not translated);
    "" when nothing is recognisable (the UI then says "unknown browser")."""
    ua = ua or ""
    os_name = next((name for needle, name in _OS if needle in ua), "")
    browser = next((name for needle, name in _BROWSERS if needle in ua), "")
    return " · ".join(x for x in (os_name, browser) if x)


# --- wrong-code rate limit --------------------------------------------------------

class Limiter:
    """Failed pairing attempts, in memory. An address with `max_fail` misses within
    `window` seconds is locked out for `lockout` seconds; `global_max` misses from
    all addresses together lock everyone out (many LAN addresses can't share the
    guessing). blocked() answers how many seconds are left (0 = go ahead)."""

    def __init__(self, max_fail: int = 5, window: float = 900, lockout: float = 900,
                 global_max: int = 30, clock=time.monotonic):
        self.max_fail, self.window, self.lockout, self.global_max = max_fail, window, lockout, global_max
        self.clock = clock
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._all: list[float] = []
        self._inflight: dict[str, int] = {}   # attempts reserved by attempt(), not yet judged
        self._lock = threading.Lock()

    BUSY_WAIT = 1.0   # "try again in a second": the address's last allowed guesses are in flight

    def _wait(self, ip: str, now: float) -> float:
        self._all = [t for t in self._all if now - t < self.window]
        wait = self._locked.get(ip, 0) - now
        if len(self._all) >= self.global_max:
            wait = max(wait, self._all[0] + self.window - now)
        fails = [t for t in self._fails.get(ip, []) if now - t < self.window]
        if len(fails) + self._inflight.get(ip, 0) >= self.max_fail or \
                len(self._all) + sum(self._inflight.values()) >= self.global_max:
            wait = max(wait, self.BUSY_WAIT)
        return max(0.0, wait)

    def blocked(self, ip: str) -> float:
        with self._lock:
            return self._wait(ip, self.clock())

    def attempt(self, ip: str) -> float:
        """blocked() and, when allowed, reserve the attempt in the same step: a burst of
        parallel requests can't all pass the check before the first failure is counted.
        Every attempt that returned 0 must end in fail(), success() or release()."""
        with self._lock:
            wait = self._wait(ip, self.clock())
            if not wait:
                self._inflight[ip] = self._inflight.get(ip, 0) + 1
            return wait

    def release(self, ip: str) -> None:
        with self._lock:
            self._release(ip)

    def _release(self, ip: str) -> None:
        n = self._inflight.get(ip, 0)
        if n > 1:
            self._inflight[ip] = n - 1
        else:
            self._inflight.pop(ip, None)

    def fail(self, ip: str) -> None:
        now = self.clock()
        with self._lock:
            self._release(ip)
            recent = [t for t in self._fails.get(ip, []) if now - t < self.window] + [now]
            self._fails[ip] = recent
            self._all.append(now)
            if len(recent) >= self.max_fail:
                self._locked[ip] = now + self.lockout
                self._fails[ip] = []
            if len(self._fails) > 1024:   # bounded memory, whatever the LAN does
                self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] < self.window}
            self._locked = {k: v for k, v in self._locked.items() if v > now}

    def success(self, ip: str) -> None:
        with self._lock:
            self._release(ip)
            self._fails.pop(ip, None)


# --- the LAN address ---------------------------------------------------------------

def is_lan_ip(ip: str) -> bool:
    """A private (RFC 1918) or link-local IPv4 address: the only kind netwarden will
    listen on besides loopback. Never a public address."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.version == 4 and (a.is_private or a.is_link_local) and not a.is_loopback
            and not a.is_unspecified and not a.is_multicast)


PROBE_TARGETS = ("10.254.254.254", "192.168.254.254")


def lan_address() -> str | None:
    """This computer's LAN address: the default route's interface address, else the
    source address the OS would use toward a private address (a UDP connect() only
    picks a route - no packet is sent). An answer equal to the probe target is a local
    address, not the LAN: under WSL mirrored networking 10.255.255.254 is the DNS tunnel
    on the loopback interface (Stage V3: it used to be picked)."""
    from netwarden import discovery   # lazy: `ip route` (Linux); discovery is heavy
    try:
        ip = discovery.default_iface_net_ip()[2]
    except Exception:   # noqa: BLE001 - no `ip` command (macOS, tests): use the probe
        ip = None
    if ip and is_lan_ip(ip):
        return ip
    for target in PROBE_TARGETS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 9))
            ip = s.getsockname()[0]
        except OSError:
            continue
        finally:
            s.close()
        if ip != target and is_lan_ip(ip):
            return ip
    return None


# --- the pairing page (/pair) -------------------------------------------------------

def _e(v) -> str:
    return escape("" if v is None else str(v), quote=True)


def render_page(lang: str, version: str = "", expired: bool = False, base: str = "") -> str:
    """The page a phone opens from the QR code: server-rendered, every string escaped,
    styled by app.css, driven by /static/pair.js (reads the code from the fragment,
    POSTs it, then opens the dashboard). Messages the script needs ride along as
    data- attributes, so it needs no other API call before it is paired.
    `expired` (/pair?expired=1, Stage G): this phone was paired but its session is gone
    (expired / removed on the computer) - say so first, calmly, with what to do.
    `base` (Stage H): the Home Assistant ingress prefix in front of every URL ("" at /)."""
    lang = i18n.normalize(lang)
    b = _e(base)
    t = lambda k, **kw: i18n.t(k, lang, **kw)  # noqa: E731
    v = f"?v={version}" if version else ""
    msgs = {k: t("app.pair." + k) for k in ("working", "done", "bad_code", "locked",
                                             "need_code", "offline")}
    data = " ".join(f'data-{k.replace("_", "-")}="{_e(val)}"' for k, val in msgs.items())
    return f"""<!doctype html>
<html lang="{_e(lang)}" data-base="{b}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#f5f6f8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0d1118" media="(prefers-color-scheme: dark)">
<title>{_e(t("app.pair.page_title"))} · netwarden</title>
<link rel="icon" href="{b}/static/icon.svg" type="image/svg+xml">
<link rel="manifest" href="{b}/static/manifest.webmanifest">
<link rel="apple-touch-icon" href="{b}/static/apple-touch-icon.png">
<link rel="stylesheet" href="{b}/static/app.css{v}">
<script src="{b}/static/pair.js{v}" defer></script>
</head>
<body class="pairpage">
<main class="pair-wrap">
  <div class="brand pair-brand"><span class="logo" aria-hidden="true"></span><span class="bn">net<b>warden</b></span></div>
  <section class="card pair-card" aria-labelledby="pair-h">
    <h1 id="pair-h">{_e(t("app.pair.page_title"))}</h1>
    {f'<p class="pair-expired" role="status">{_e(t("app.pair.session_ended"))}</p>' if expired else ""}
    <p class="muted">{_e(t("app.pair.page_intro"))}</p>
    <form id="pairform" class="stack" autocomplete="off" {data}>
      <label class="field"><span>{_e(t("app.pair.code_label"))}</span>
        <input id="paircode" name="code" type="text" inputmode="text" autocapitalize="characters"
               spellcheck="false" maxlength="20" placeholder="ABCDE-FGHJK" aria-describedby="pairmsg" required></label>
      <button type="submit" class="btn">{_e(t("app.pair.connect"))}</button>
      <p id="pairmsg" class="pair-msg" role="status" aria-live="polite"></p>
    </form>
    <p class="hint pair-warn">{_e(t("app.pair.http_warning"))}</p>
  </section>
</main>
</body>
</html>
"""
