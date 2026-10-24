"""
netwarden - redact.py: household names stay home, even when the AI runs in the cloud.

Before a prompt goes to a cloud model (setting ai.redact: auto = on for cloud, off for
a local / LAN model), every device name, hostname, owner, room, MAC and private IP in
it is replaced by a stable pseudonym:

    [D3]  a device (its label, hostname, snapshot name and the names it announced on the
          LAN via mDNS / SSDP / DHCP / the DNS server all map to the same token)
    [M3]  that device's MAC          [IP3] its IP address
    [P1]  a person (owner note)      [R2]  a room

Device type, vendor, services and domains stay, so the answers remain useful. The
reply is mapped back to the real names here on the server - also while it streams,
where a token can arrive split across chunks ("[D" + "3]").

What it does NOT hide: the domains and services devices use, counts and times, vendors
and device types, and anything the user types that we do not know as a name. MACs,
private IPv4 addresses and household IPv6 addresses (link-local / unique-local, and any
EUI-64 address - it embeds the MAC) are caught by pattern even when not in the inventory.

Numbering follows the devices table (first seen, then MAC), owners / rooms
alphabetically - stable while the inventory is unchanged, so the same chat keeps the
same tokens from one question to the next.
"""
from __future__ import annotations

import ipaddress
import json
import re

from netwarden import store

TOKEN_RE = re.compile(r"\[(D|M|IP|P|R)(\d{1,5})\]")
# the tail of a chunk that may be the start of a token: "[", "[D", "[IP1", ...
PARTIAL_RE = re.compile(r"\[(?:D|M|I|IP|P|R)?\d{0,5}$")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}"
                    r"(?![0-9A-Fa-f:-])")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PTR_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\.in-addr\.arpa\b", re.I)
# IPv6 candidates (validated by ipaddress before anything is replaced): hex groups with
# at least two colons, optionally an embedded IPv4 tail or a zone ("%eth0")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:.%])(?:[0-9A-Fa-f]{0,4}:){2,7}"
                     r"(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?:%[0-9A-Za-z_.-]{1,16})?"
                     r"(?![0-9A-Za-z:])")
MIN_LEN = 2          # single characters are not matched by the name regex in free text
                     # (one-character non-ASCII person / room names: Redactor._short)
CGNAT = ipaddress.ip_network("100.64.0.0/10")   # carrier-grade NAT / Tailscale: not public


def _household_ip(text: str) -> bool:
    """A private / link-local / loopback / CGNAT IPv4 address (public ones stay)."""
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return False
    return a.is_private or a.is_link_local or a.is_loopback or a in CGNAT


def household_ipv6(text: str) -> bool:
    """An IPv6 address that points at this household: link-local / unique-local /
    loopback, or ANY address whose interface id is EUI-64 (ff:fe in the middle) - that
    one embeds the device's MAC, even in a global prefix. A privacy-extension global
    address (and a public resolver such as 2001:4860:4860::8888) stays."""
    try:
        a = ipaddress.IPv6Address(text.split("%", 1)[0])
    except ValueError:
        return False
    if a.packed == bytes(16):          # "::" on its own is not anybody's address
        return False
    if a.is_link_local or a.is_private or a.is_loopback or a.is_site_local:
        return True
    return a.packed[11:13] == b"\xff\xfe"


def _forms(s: str) -> set:
    """The ways a value can appear in a prompt: as is, and JSON-escaped (inside the
    rendered snapshot a quote or backslash in a name is escaped)."""
    s = s.strip()
    if len(s) < MIN_LEN:
        return set()
    out = {s}
    if MAC_RE.fullmatch(s):   # the other ways a MAC is written: aabbccddeeff, aabb.ccdd.eeff
        hexes = re.sub(r"[^0-9A-Fa-f]", "", s)
        out |= {hexes, ".".join(hexes[i:i + 4] for i in (0, 4, 8)),
                "-".join(hexes[i:i + 2] for i in range(0, 12, 2)),
                ":".join(hexes[i:i + 2] for i in range(0, 12, 2))}
    elif re.search(r"[A-Za-z]", s) and re.search(r"[-_ ]", s):
        # hostnames turn up as "Galaxy-Tab-A7", "Galaxy_Tab_A7" and "Galaxy Tab A7"
        out |= {re.sub(r"[-_ ]", sep, s) for sep in "-_ "}
    return out | {json.dumps(f, ensure_ascii=False)[1:-1] for f in out}


def _alnum(ch: str) -> bool:
    return ch.isascii() and ch.isalnum()


def _trie(forms) -> str:
    """One regex for many names, as a prefix tree: "tv|tvbox|tablet" becomes
    "t(?:v(?:box(?!\\w)|(?!\\w))|ablet(?!\\w))". A flat alternation of hundreds of names
    tries every one at every position of a 250 KB prompt (seconds); the tree fails
    after a character or two. Longer continuations come before the end of a name, so
    the longest name still wins. A name must not match inside a longer ASCII word: "TV"
    must not hit "TVBox" (CJK text has no word boundaries, so no lookaround there)."""
    root: dict = {}
    for f in forms:
        node = root
        for ch in f:
            node = node.setdefault(ch, {})
        node[""] = True

    def emit(node, last):
        alts = [re.escape(ch) + emit(node[ch], ch) for ch in sorted(k for k in node if k)]
        if "" in node:
            alts.append(r"(?![A-Za-z0-9])" if _alnum(last) else "")
        return alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"

    word = {ch: sub for ch, sub in root.items() if _alnum(ch)}
    other = {ch: sub for ch, sub in root.items() if not _alnum(ch)}
    parts = []
    if word:
        parts.append(r"(?<![A-Za-z0-9])" + emit(word, ""))
    if other:
        parts.append(emit(other, ""))
    return "|".join(parts)


class Redactor:
    """Maps real household identifiers <-> pseudonyms for one request."""

    def __init__(self):
        self.real: dict = {}        # token -> the real text shown after unredaction
        self._lookup: dict = {}     # lowercased form -> token (free-text matching)
        self._exact: dict = {}      # lowercased whole value -> token, ANY length (fields)
        self._raw: set = set()      # original forms whose lower() changes length
        self._re = None
        self._next = {"M": 0, "IP": 0}
        self.used: set = set()      # tokens that redact() put into some text
        self._mac_dev = None        # mac -> "[D<n>]" (device_token), built on first use
        # one-character NON-ASCII person / room names ("媽", "房") -> token: replaced as a
        # substring in free text too ("Phone · 媽" in an alert title). A one-letter Latin
        # name ("A") is not - it would hit every "A" in English text.
        self._short: dict = {}

    # --- building -----------------------------------------------------------------

    def add(self, token: str, real: str, *values) -> None:
        """`token` shows `real` after unredaction and replaces every one of `values`."""
        self.real.setdefault(token, real)
        for v in values:
            if not isinstance(v, str):
                continue
            if v.strip():
                self._exact.setdefault(v.strip().lower(), token)
            for f in _forms(v):
                self._lookup.setdefault(f.lower(), token)
                if f.lower() != f and len(f.lower()) != len(f):
                    # "İpek".lower() is 5 characters: a case-insensitive match of the
                    # 4-character original only works with the original in the regex
                    self._raw.add(f)
        self._re = None

    # --- structured fields ---------------------------------------------------------

    # snapshot fields that hold nothing but a household name: replaced by their whole
    # value, so even a one-character owner ("媽", "A") - too short to match safely
    # inside free text - never reaches the model
    DEVICE_FIELDS = ("name", "hostname", "label", "owner", "room", "client_name")

    def field(self, value):
        if isinstance(value, str) and value.strip().lower() in self._exact:
            return self._use(self._exact[value.strip().lower()])
        return value

    def redact_fields(self, snap: dict) -> dict:
        """Pseudonymize a brain.snapshot's name fields IN PLACE (call before rendering
        it; redact() then covers the free text). Returns snap."""
        for d in snap.get("devices") or []:
            for k in self.DEVICE_FIELDS:
                if k in d:
                    d[k] = self.field(d[k])
        for p in snap.get("people") or []:
            p["owner"] = self.field(p.get("owner"))
            p["devices"] = [self.field(x) for x in p.get("devices") or []]
        for h in snap.get("not_in_dns_window") or []:
            h["name"] = self.field(h.get("name"))
        # Stage P: the household, screen time per person and presence
        for key in ("household", "presence"):
            for p in snap.get(key) or []:
                p["person"] = self.field(p.get("person"))
                for k in ("devices", "macs"):
                    if k in p:
                        p[k] = [self.field(x) for x in p[k]]
        return snap

    @classmethod
    def build(cls, db, snap: dict | None = None) -> "Redactor":
        """Everything that identifies this household, from the inventory, the user's
        notes and (optionally) a brain.snapshot (its names / IPs, e.g. AdGuard client
        names that are not in the devices table)."""
        r = cls()
        labels = store.get_labels(db)
        profiles = store.get_profiles(db)
        names = store.device_names(db)
        snap_devs = {d.get("mac"): d for d in (snap or {}).get("devices", [])}
        rows = db.execute("SELECT mac, ip, hostname FROM devices "
                          "ORDER BY first_seen, mac").fetchall()
        macs = [row["mac"] for row in rows] + sorted(m for m in snap_devs if m and m not in
                                                     {row["mac"] for row in rows})
        by_mac = {row["mac"]: row for row in rows}
        # names the devices announced on the LAN / the DNS server knows (Stage N): the
        # user may well type "客廳電視" in a question, so they map to the device too
        announced: dict = {}
        for mac, idents in store.identities(db).items():
            announced[mac] = [i["name"] for i in idents if i.get("name")]
        extra = []
        for n, mac in enumerate(macs, 1):
            row, sd = by_mac.get(mac), snap_devs.get(mac) or {}
            label = (labels.get(mac) or {}).get("label")
            r.add(f"[D{n}]", names.get(mac) or sd.get("name") or mac,
                  label, row and row["hostname"], sd.get("name"), sd.get("hostname"),
                  *announced.get(mac, []))
            r.add(f"[M{n}]", mac, mac)
            ips = set(sd.get("ips") or [])
            if row and row["ip"]:
                ips.add(row["ip"])
            ips = sorted(ips, key=lambda ip: (ip != (row and row["ip"]), ip))
            if ips:
                r.add(f"[IP{n}]", ips[0], ips[0])
            extra.extend(ips[1:])
        r._next = {"M": len(macs), "IP": len(macs)}
        for ip in extra:          # a device's older / secondary addresses
            r._fresh("IP", ip)
        # Stage P: people in their (stable) id order, then any owner text not yet a person
        people = [p["name"] for p in store.people(db)]
        owners = sorted({(p.get("owner") or "").strip() for p in profiles.values()} - {""}
                        - set(people))
        rooms = sorted({(p.get("room") or "").strip() for p in profiles.values()} - {""})
        for prefix, vals in (("P", people + owners), ("R", rooms)):
            for n, v in enumerate(vals, 1):
                r.add(f"[{prefix}{n}]", v, v)
                if len(v) < MIN_LEN and not v.isascii():
                    r._short[v] = f"[{prefix}{n}]"
        return r

    def _regex(self):
        if self._re is None:
            # a token already in the text (redact_fields ran first) is matched as a whole
            # and kept: a device named "P1" must not turn "[P1]" into "[[D5]]"
            self._re = re.compile(TOKEN_RE.pattern + "|" + _trie(set(self._lookup) | self._raw),
                                  re.I) if self._lookup else False
        return self._re

    # --- redacting ------------------------------------------------------------------

    def _fresh(self, prefix: str, value: str) -> str:
        """The token for a MAC / IP: known ones keep theirs, a new one (e.g. an IP the
        user typed) gets the next free number."""
        key = value.lower()
        if key not in self._lookup:
            token = None
            while token is None or token in self.real:
                self._next[prefix] += 1
                token = f"[{prefix}{self._next[prefix]}]"
            self.real[token] = value
            self._lookup[key] = token
            self._re = None
        return self._lookup[key]

    def _use(self, token: str) -> str:
        self.used.add(token)
        return token

    def redact(self, text: str) -> str:
        if not text:
            return text
        rx = self._regex()
        if rx:
            text = rx.sub(lambda m: m.group(0) if m.group(1) else
                          self._use(self._lookup.get(m.group(0).lower(), m.group(0))), text)
        for short, token in self._short.items():
            if short in text:
                text = text.replace(short, self._use(token))
        # catch-alls: any MAC, any private IPv4 (public resolver IPs like 8.8.8.8 stay)
        text = MAC_RE.sub(lambda m: self._use(self._fresh("M", m.group(0))), text)

        def ip(m):
            return self._use(self._fresh("IP", m.group(0))) if _household_ip(m.group(0)) \
                else m.group(0)

        def ptr(m):   # "13.1.168.192.in-addr.arpa" = 192.168.1.13 written backwards
            addr = ".".join(reversed(m.group(1).split(".")))
            return self._use(self._fresh("IP", addr)) if _household_ip(addr) else m.group(0)
        text = PTR_RE.sub(ptr, text)

        def ip6(m):
            addr, tail = m.group(0), ""
            if addr.endswith(":") and not addr.endswith("::"):   # "fe80::1: online"
                addr, tail = addr[:-1], ":"
            return (self._use(self._fresh("IP", addr)) if household_ipv6(addr) else addr) + tail
        # IPv6 first: an embedded IPv4 tail ("::ffff:192.168.1.5") goes with its address
        text = IPV6_RE.sub(ip6, text)
        return IPV4_RE.sub(ip, text)

    # --- mapping back ---------------------------------------------------------------

    def unredact(self, text: str) -> str:
        return TOKEN_RE.sub(lambda m: self.real.get(m.group(0), m.group(0)), text)

    def unredact_stream(self, chunks):
        """unredact() for a stream of text chunks: holds back a possibly-split token at a
        chunk's end until the next chunk decides it. Concatenated output ==
        unredact(concatenated input)."""
        u = StreamUnmapper(self)
        for chunk in chunks:
            text = u.feed(chunk)
            if text:
                yield text
        tail = u.flush()
        if tail:
            yield tail

    def device_token(self, mac: str | None) -> str | None:
        """The [D<n>] token of the device with this MAC (its [M<n>] shares the number),
        or None if the MAC is not in the inventory - Stage A: a tool result's device
        name maps to the same pseudonym as in the context."""
        if not mac:
            return None
        if self._mac_dev is None:
            self._mac_dev = {v.lower(): "[D" + t[2:] for t, v in self.real.items()
                             if t.startswith("[M") and "[D" + t[2:] in self.real}
        return self._mac_dev.get(mac.lower())

    def legend(self) -> list:
        """[{token, real}] for the tokens that were actually used - shown locally in the
        "preview what will be sent" sheet, never sent anywhere."""
        return [{"token": t, "real": v} for t, v in self.real.items() if t in self.used]


class StreamUnmapper:
    """The incremental half of Redactor.unredact_stream: feed(chunk) -> the text that
    is safe to show now (a possibly-split token at the end is held back), flush() -> the
    rest. Without a redactor it passes text through unchanged."""

    def __init__(self, redactor: Redactor | None):
        self.r, self.pending = redactor, ""

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        if self.r is None:
            return chunk
        text = self.pending + chunk
        cut = text.rfind("[")
        if cut >= 0 and PARTIAL_RE.fullmatch(text[cut:]):
            self.pending, text = text[cut:], text[:cut]
        else:
            self.pending = ""
        return self.r.unredact(text) if text else ""

    def flush(self) -> str:
        tail, self.pending = self.pending, ""
        return self.r.unredact(tail) if tail and self.r else tail


class RedactingProvider:
    """Wraps a provider: replies are mapped back to real names. (The prompt itself is
    redacted while it is built - brain passes Redactor.redact as `scrub` - so the
    instructions in the system prompt are never touched.)"""

    def __init__(self, inner, redactor: Redactor):
        self.inner, self.redactor = inner, redactor
        self.model = getattr(inner, "model", None)
        self.prompt_cache = getattr(inner, "prompt_cache", False)

    def complete(self, system: str, user: str, max_tokens: int = 1200, **kw) -> str:
        # kw = cache hints (round 7 C), only ever passed when the inner provider takes them
        return self.redactor.unredact(self.inner.complete(system, user, max_tokens=max_tokens, **kw))

    def stream(self, system: str, user: str, max_tokens: int = 1200, **kw):
        if hasattr(self.inner, "stream"):
            src = self.inner.stream(system, user, max_tokens=max_tokens, **kw)
        else:
            src = iter([self.inner.complete(system, user, max_tokens=max_tokens, **kw)])
        try:
            yield from self.redactor.unredact_stream(src)
        finally:
            close = getattr(src, "close", None)
            if close:
                close()
