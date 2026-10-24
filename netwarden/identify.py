#!/usr/bin/env python3
"""
netwarden - identify.py: what do the devices on the LAN call themselves?

Part of the discovery cycle (discovery.scan_recorded, every 15 min in `run`, or
`python3 -m netwarden identify`). Standard LAN discovery only - the same traffic every
phone, TV and printer on the network already sends:

  mDNS   one query for a fixed list of common service types (_googlecast, _airplay,
         _ipp, _hap, ...) to 224.0.0.251:5353, then LISTEN for a few seconds - on an
         ephemeral port (responders answer a "legacy" query by unicast) and, when the
         port is free, on 5353 itself (multicast answers). Names (fn / instance), models
         (md / model / ty / am) and service types come from the PTR / SRV / TXT records.
  SSDP   one M-SEARCH to 239.255.255.250:1900 and listen. A response's LOCATION (its
         UPnP device description) is fetched only when its host is the responder's own
         private source address, over plain http, at most MAX_DESC_BYTES within
         DESC_TIMEOUT seconds, and parsed with DTD / entity declarations refused.
  DHCP   the name the router hands out (reverse DNS during the sweep), and
  DNS    the client name AdGuard / Pi-hole knows (dns_ingest), both recorded as evidence.

Stage V3 - the unicast round. Multicast REPLIES often never arrive (WSL's Hyper-V firewall,
mirrored networking, client isolation), but a reply to a question sent straight to one
device comes back to the asking socket, which stateful firewalls let through. So every
private inventory IP (at most MAX_UNICAST_TARGETS, UNICAST_GAP apart) also gets:
  mDNS     the same service question + "who are you?" for its reverse address, sent to
           its port 5353 (RFC 6762 5.5 / 6.7: answered by unicast to our port)
  SSDP     a unicast M-SEARCH (and the router: one for its Internet Gateway Device), then
           the same description / read-only UPnP path as above
  NetBIOS  a node-status request (UDP 137): Windows / Samba computer names
  rDNS     a PTR lookup through the system resolver for devices without a hostname -
           only when every configured nameserver is private / loopback

Everything a device announces is hostile input: names are cleaned to one short line
(store.clean_text) and always escaped by every renderer. Answers from non-private
addresses are dropped. Nothing is ever sent to a device beyond the queries above; the
UPnP gateway part (port mappings) lives in upnp.py.

Results land in store.device_identity (one row per device and source, retention-
pruned) and are used to suggest a friendly name (never overwriting the user's label),
to sharpen the device type / maker / model, and as "identified via ..." evidence.
If multicast is unavailable (WSL without mirrored networking, a firewall), each part
records its error in source_status ('mdns' / 'ssdp') and the rest of netwarden carries
on - /api/status shows the state.
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import re
import select
import socket
import struct
import threading
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from netwarden import store

MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353
SSDP_ADDR, SSDP_PORT = "239.255.255.250", 1900
LISTEN_SECONDS = 3.0
MAX_PACKETS = 4000            # per protocol and run: a chatty network can't keep us busy
MAX_PACKET = 9000
MAX_RECORDS_PER_IP = 1024     # mDNS records kept per host and run (a flood can't grow memory)
MAX_DESC_BYTES = 64 * 1024    # a UPnP device description is a few KB
DESC_TIMEOUT = 2.5
MAX_DESCRIPTIONS = 48         # LOCATION fetches per run (at most MAX_LOCATIONS_PER_IP each)
MAX_LOCATIONS_PER_IP = 3
# the unicast round (replies come back to the asking socket, so stateful firewalls pass
# them): every query to private inventory addresses only, at most this many, paced
MAX_UNICAST_TARGETS = 256
UNICAST_GAP = 0.01            # seconds between two unicast packets
NETBIOS_PORT = 137

# The mDNS service types we ask about (DNS-SD names). Each says something about what a
# device is; KIND_BY_SERVICE is the type hint when nothing more specific is known.
SERVICE_TYPES = (
    "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_hap._tcp", "_ipp._tcp",
    "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_spotify-connect._tcp",
    "_device-info._tcp", "_smb._tcp", "_workstation._tcp", "_companion-link._tcp",
    "_sonos._tcp", "_matter._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp",
)
KIND_BY_SERVICE = {
    "_googlecast._tcp": "streaming", "_airplay._tcp": "streaming", "_raop._tcp": "speaker",
    "_hap._tcp": "iot", "_ipp._tcp": "printer", "_ipps._tcp": "printer",
    "_printer._tcp": "printer", "_pdl-datastream._tcp": "printer",
    "_spotify-connect._tcp": "speaker", "_sonos._tcp": "speaker", "_matter._tcp": "iot",
    "_smb._tcp": "computer", "_workstation._tcp": "computer",
    "_androidtvremote2._tcp": "tv", "_amzn-wplay._tcp": "streaming",
}
# Apple model identifiers (AirPlay "model", _device-info "model") -> type
APPLE_MODELS = (("iPhone", "phone"), ("iPad", "tablet"), ("iPod", "phone"),
                ("AppleTV", "streaming"), ("AudioAccessory", "speaker"), ("Watch", "wearable"),
                ("MacBook", "computer"), ("iMac", "computer"), ("Macmini", "computer"),
                ("MacPro", "computer"), ("Mac", "computer"))
# SSDP / UPnP deviceType fragments -> type
KIND_BY_UPNP = (("InternetGatewayDevice", "network"), ("WANDevice", "network"),
                ("WLANAccessPoint", "network"), ("Printer", "printer"),
                ("MediaRenderer", "tv"), ("dial-multiscreen", "tv"),
                ("DigitalSecurityCamera", "camera"))
PRINTER_MAKERS = ("HP", "Epson", "EPSON", "Canon", "Brother", "Samsung", "Xerox", "Lexmark",
                  "Kyocera", "Ricoh", "OKI", "Konica", "Sharp", "Fuji")

_PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]


class DemoRefused(RuntimeError):
    """Live discovery is off for the demo database (its addresses are made up)."""


def private_ip(ip: str) -> bool:
    """A private / link-local IPv4 address (never loopback, never public)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and any(addr in n for n in _PRIVATE)


def clean(value, limit: int = store.MAX_IDENTITY_TEXT) -> str:
    """Network text -> one trimmed printable line (it stays hostile: escape on output)."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return store.clean_text(value, limit)


# --- DNS wire format (just enough for mDNS / DNS-SD) ------------------------------

T_A, T_PTR, T_TXT, T_AAAA, T_SRV, T_ANY = 1, 12, 16, 28, 33, 255
QU_BIT = 0x8000               # "unicast response requested" (RFC 6762 5.4)


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def build_query(names, qtype: int = T_PTR, unicast: bool = True) -> bytes:
    """One DNS query message asking `qtype` for every name (id 0, as mDNS wants)."""
    names = list(names)
    head = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    qclass = 1 | (QU_BIT if unicast else 0)
    return head + b"".join(_encode_name(n) + struct.pack("!HH", qtype, qclass) for n in names)


class DnsError(ValueError):
    """A malformed DNS message (truncated, a pointer loop, ...)."""


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    """(dotted name, offset after it), following compression pointers (bounded)."""
    labels, jumps, end = [], 0, None
    while True:
        if off >= len(data):
            raise DnsError("name past end")
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DnsError("bad pointer")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            jumps += 1
            if jumps > 32:
                raise DnsError("pointer loop")
            continue
        if n & 0xC0:
            raise DnsError("bad label")
        off += 1
        if n == 0:
            break
        if off + n > len(data):
            raise DnsError("label past end")
        labels.append(data[off:off + n].decode("utf-8", "replace"))
        off += n
        if sum(len(x) + 1 for x in labels) > 255:
            raise DnsError("name too long")
    return ".".join(labels), (end if end is not None else off)


def parse_txt(rdata: bytes) -> dict:
    """TXT strings "key=value" -> {key (lowercase): value}. Bounded, never raises."""
    out, off = {}, 0
    while off < len(rdata) and len(out) < 64:
        n = rdata[off]
        item = rdata[off + 1:off + 1 + n]
        off += 1 + n
        key, _eq, val = item.partition(b"=")
        key = key.decode("ascii", "replace").strip().lower()
        if key and key not in out:
            out[key] = clean(val, 200)
    return out


def parse_message(data: bytes) -> list[dict]:
    """Every answer / authority / additional record of a DNS message:
    [{name, type, data}] with data = str (PTR target, A address), dict (TXT), or
    {port, target} (SRV). Raises DnsError on a malformed message."""
    if len(data) < 12:
        raise DnsError("short message")
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _name, off = _read_name(data, off)
        off += 4
    out = []
    for _ in range(min(an + ns + ar, 512)):
        name, off = _read_name(data, off)
        if off + 10 > len(data):
            raise DnsError("record past end")
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        if len(rdata) < rdlen:
            raise DnsError("rdata past end")
        rec = {"name": name.lower() if rtype != T_PTR else name, "type": rtype}
        if rtype == T_PTR:
            rec["data"], _ = _read_name(data, off)
        elif rtype == T_A and rdlen == 4:
            rec["data"] = socket.inet_ntoa(rdata)
        elif rtype == T_TXT:
            rec["data"] = parse_txt(rdata)
        elif rtype == T_SRV and rdlen >= 7:
            port = struct.unpack("!H", rdata[4:6])[0]
            rec["data"] = {"port": port, "target": _read_name(data, off + 6)[0]}
        else:
            rec = None
        off += rdlen
        if rec is not None:
            out.append(rec)
    return out


_ESCAPE = re.compile(r"\\(\d{3}|.)")


def unescape_label(text: str) -> str:
    """DNS-SD instance labels escape dots / spaces as "\\." / "\\032"."""
    return _ESCAPE.sub(lambda m: chr(int(m.group(1))) if m.group(1).isdigit() else m.group(1),
                       text)


def split_instance(fqdn: str) -> tuple[str, str] | None:
    """"Living Room TV._googlecast._tcp.local" -> ("Living Room TV", "_googlecast._tcp")."""
    low = fqdn.lower().rstrip(".")
    for st in SERVICE_TYPES:
        suffix = "." + st + ".local"
        if low.endswith(suffix):
            return unescape_label(fqdn[:len(fqdn.rstrip(".")) - len(suffix)]), st
    return None


# --- mDNS ------------------------------------------------------------------------

def _apple_kind(model: str) -> str | None:
    for prefix, kind in APPLE_MODELS:
        if model.startswith(prefix):
            return kind
    return None


def _rule_kind(*texts) -> str | None:
    """A type from devicetype's hostname rules applied to a model / friendly name."""
    from netwarden import devicetype   # lazy: devicetype is heavier than we need here
    for text in texts:
        if text:
            for rx, kind in devicetype.HOSTNAME_RULES:
                if rx.search(text):
                    return kind
    return None


def _host_label(name: str) -> str:
    """"Kitchen-iPad.local." -> "Kitchen-iPad" (the host's own mDNS name)."""
    name = name.rstrip(".")
    return name[:-len(".local")] if name.lower().endswith(".local") else name


def interpret_mdns(records: list[dict]) -> dict | None:
    """All records one host sent -> {name, manufacturer, model, kind, services} or None.
    A host that only answered the reverse-address question (unicast round) still gives
    its mDNS host name. Pure function (unit-tested with captured packets)."""
    instances: dict = {}       # instance fqdn -> service type
    txt: dict = {}
    srv: dict = {}
    hostnames: list = []       # from "x.in-addr.arpa PTR host.local" and A records
    for r in records:
        if r["type"] == T_PTR and r["name"].lower().rstrip(".").endswith(".in-addr.arpa"):
            hostnames.insert(0, _host_label(r["data"]))
        elif r["type"] == T_A and r["name"].endswith(".local"):
            hostnames.append(_host_label(r["name"]))
        elif r["type"] == T_PTR:
            parts = split_instance(r["data"])
            if parts:
                instances[r["data"].lower().rstrip(".")] = (parts[0], parts[1])
        elif r["type"] == T_TXT:
            txt.setdefault(r["name"].rstrip("."), {}).update(r["data"])
        elif r["type"] == T_SRV:
            srv[r["name"].rstrip(".")] = r["data"]
    # TXT / SRV records can also arrive for instances whose PTR we did not see
    for name in list(txt) + list(srv):
        parts = split_instance(name)
        if parts and name not in instances:
            instances[name] = parts
    hostnames = [h for h in hostnames if h]
    if not instances:
        if not hostnames:
            return None
        return {"name": clean(hostnames[0]), "manufacturer": "", "model": "",
                "kind": _rule_kind(hostnames[0]), "services": []}
    services = sorted({st for _label, st in instances.values()})
    names, models, makers, kinds, hosts = [], [], [], [], []
    for fqdn, (label, st) in instances.items():
        t = txt.get(fqdn, {})
        if st == "_googlecast._tcp":
            names.append(t.get("fn") or "")
            models.append(t.get("md") or "")
        elif st == "_raop._tcp":
            names.append(label.split("@", 1)[1] if "@" in label else "")
            models.append(t.get("am") or t.get("model") or "")
        elif st in ("_airplay._tcp", "_companion-link._tcp", "_device-info._tcp",
                    "_spotify-connect._tcp", "_hap._tcp", "_androidtvremote2._tcp",
                    "_amzn-wplay._tcp"):
            names.append(label)
            models.append(t.get("model") or t.get("md") or "")
        elif st in ("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"):
            names.append(re.sub(r"\s*\[[0-9A-Fa-f:]+\]$", "", label))
            prod = (t.get("product") or "").strip("()")
            models.append(t.get("ty") or prod)
            makers.append(t.get("usb_mfg") or "")
        elif st in ("_smb._tcp", "_workstation._tcp"):
            names.append(re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", label, flags=re.I))
        else:
            names.append(label)
        if fqdn in srv:
            hosts.append(srv[fqdn]["target"].rsplit(".local", 1)[0])
    model = next((m for m in models if m), "")
    name = next((n for n in names if n and not n.lower().startswith(("rincon_", "matter"))), "")
    maker = next((m for m in makers if m), "")
    apple = _apple_kind(model) if model else None
    if apple and not maker:
        maker = "Apple"
    if not maker and model:
        first = model.split()[0]
        if first in PRINTER_MAKERS or first in ("Samsung", "LG", "Sony", "Google", "Chromecast"):
            maker = "Google" if first == "Chromecast" else first
    kind = apple or _rule_kind(model, name)
    if not kind:
        kinds = [KIND_BY_SERVICE[st] for st in services if st in KIND_BY_SERVICE]
        # a printer / TV service says more than a generic one (smb, spotify)
        for pick in ("printer", "tv", "streaming", "speaker", "iot", "computer"):
            if pick in kinds:
                kind = pick
                break
    hosts += hostnames
    return {"name": clean(name or (hosts[0] if hosts else "")), "manufacturer": clean(maker),
            "model": clean(model), "kind": kind, "services": services}


def _mdns_sockets(group: bool = True) -> list:
    """The query socket (ephemeral port, gets unicast answers) and, if 5353 is free to
    share, a listener joined to the group (multicast answers). Raises OSError when
    even the query socket can't be made."""
    q = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    q.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    q.bind(("", 0))
    socks = [q]
    if not group:
        return socks
    try:
        lst = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        lst.bind(("", MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0"))
        lst.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        socks.append(lst)
    except OSError:
        pass        # another mDNS responder owns 5353: unicast answers still reach us
    return socks


def _accept(ip: str) -> bool:
    """Whose answers count: private LAN addresses only (tests widen this to 127.0.0.1)."""
    return private_ip(ip)


def _listen(socks, seconds: float, on_packet) -> int:
    """Read datagrams from `socks` for `seconds`; returns how many were handled."""
    deadline, n = time.monotonic() + seconds, 0
    while n < MAX_PACKETS:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        ready, _w, _x = select.select(socks, [], [], left)
        for s in ready:
            try:
                data, (ip, _port) = s.recvfrom(MAX_PACKET)
            except OSError:
                continue
            n += 1
            if _accept(ip):
                on_packet(ip, data)
    return n


def reverse_name(ip: str) -> str:
    """192.168.1.13 -> "13.1.168.192.in-addr.arpa" (the reverse-address question)."""
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def unicast_targets(ips, limit: int = MAX_UNICAST_TARGETS) -> list:
    """The addresses the unicast round may ask: private IPv4 only, each once, capped."""
    out = []
    for ip in ips:
        if ip and private_ip(ip) and ip not in out:
            out.append(ip)
    return out[:limit]


def _send_paced(sock, jobs, gap: float = UNICAST_GAP) -> threading.Thread:
    """Send [(packet, (ip, port))] from `sock` in a background thread, `gap` seconds
    apart (a rate limit: ~100 small packets a second at most). An address that cannot
    be reached (no route, ICMP refusal) is skipped quietly."""
    def run():
        for data, addr in jobs:
            try:
                sock.sendto(data, addr)
            except OSError:
                pass
            time.sleep(gap)
    t = threading.Thread(target=run, name="netwarden-unicast", daemon=True)
    t.start()
    return t


def _send_time(jobs, gap: float = UNICAST_GAP) -> float:
    return len(jobs) * gap


def mdns_browse(seconds: float = LISTEN_SECONDS, dest=(MDNS_ADDR, MDNS_PORT),
                targets=(), port: int = MDNS_PORT) -> dict:
    """Ask for SERVICE_TYPES, listen, and return {ip: interpret_mdns(...)} for every
    private host that answered. `dest` is for tests (a fake responder on 127.0.0.1:
    then no multicast group is joined); dest=None skips the multicast query.

    targets: inventory IPs that ALSO get the questions by unicast, to their port 5353
    (RFC 6762 5.5 direct unicast / 6.7 legacy unicast, the QU bit set), plus "what is
    your name?" for their own reverse address. Those answers come back to the port the
    question left from - a stateful firewall (WSL's Hyper-V firewall) lets them in,
    where it drops multicast replies."""
    socks = _mdns_sockets(group=bool(dest) and dest[0] == MDNS_ADDR)
    per_ip: dict = {}
    services = build_query(st + ".local" for st in SERVICE_TYPES)
    jobs = []
    for ip in unicast_targets(targets):
        jobs += [(services, (ip, port)), (build_query([reverse_name(ip)]), (ip, port))]

    def packet(ip, data):
        try:
            recs = parse_message(data)
        except DnsError:
            return
        have = per_ip.setdefault(ip, [])
        have.extend(recs[:max(0, MAX_RECORDS_PER_IP - len(have))])   # bounded per host

    try:
        if dest:
            socks[0].sendto(services, dest)
        sender = _send_paced(socks[0], jobs) if jobs else None
        _listen(socks, seconds + _send_time(jobs), packet)
        if sender:
            sender.join(1.0)
    finally:
        for s in socks:
            s.close()
    out = {}
    for ip, recs in per_ip.items():
        info = interpret_mdns(recs)
        if info:
            out[ip] = info
    return out


# --- SSDP + UPnP device descriptions ------------------------------------------------

def build_msearch(st: str = "ssdp:all", mx: int = 2, host: str | None = None) -> bytes:
    """An M-SEARCH. host = a device's own "ip:port" for a UNICAST search (UPnP Device
    Architecture 1.1, 1.3.3: HOST names the device and there is no MX)."""
    return ("M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host or f'{SSDP_ADDR}:{SSDP_PORT}'}\r\n"
            'MAN: "ssdp:discover"\r\n'
            + ("" if host else f"MX: {mx}\r\n") +
            f"ST: {st}\r\n"
            "USER-AGENT: netwarden/1 UPnP/1.1\r\n\r\n").encode("ascii")


def parse_ssdp(data: bytes) -> dict | None:
    """An SSDP response / NOTIFY -> {header (lowercase): value}; None if not one."""
    try:
        text = data[:4096].decode("utf-8", "replace")
    except Exception:   # noqa: BLE001
        return None
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not (lines[0].startswith("HTTP/1.") or lines[0].startswith("NOTIFY")):
        return None
    out = {}
    for line in lines[1:40]:
        key, sep, val = line.partition(":")
        if sep and key.strip():
            out.setdefault(key.strip().lower(), val.strip()[:512])
    return out


def location_ok(location: str, source_ip: str) -> bool:
    """Fetch a LOCATION only if it is plain http on the responder's own private IP.
    No whitespace or control characters anywhere (urlsplit would quietly strip some)."""
    if not location.isprintable() or any(c.isspace() for c in location):
        return False
    try:
        u = urlsplit(location)
        port = u.port
    except ValueError:
        return False
    return (u.scheme == "http" and u.hostname == source_ip and private_ip(source_ip)
            and not u.username and not u.password and (port is None or 0 < port < 65536))


def http_get(url: str, timeout: float = DESC_TIMEOUT, limit: int = MAX_DESC_BYTES,
             method: str = "GET", body: bytes | None = None,
             headers: dict | None = None) -> tuple[int, bytes]:
    """A minimal http request with hard size / time limits; never follows redirects and
    never uses a proxy. -> (status, body). Raises OSError / ValueError on trouble."""
    u = urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        raise ValueError("http only")
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    expired = threading.Event()

    def cut():
        # ONE deadline for the whole exchange: a device trickling a byte every couple of
        # seconds never hits the per-recv timeout, so the socket is shut from here
        expired.set()
        sock = conn.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    timer = threading.Timer(timeout, cut)
    timer.daemon = True
    timer.start()
    try:
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        conn.request(method, path, body=body,
                     headers={"User-Agent": "netwarden/1", "Connection": "close",
                              **(headers or {})})
        resp = conn.getresponse()
        data = b""
        while len(data) <= limit and not expired.is_set():
            chunk = resp.read1(min(8192, limit + 1 - len(data)))   # whatever has arrived
            if not chunk:
                break
            data += chunk
        if expired.is_set():
            raise TimeoutError("slow response")
        if len(data) > limit:
            raise ValueError("response too large")
        return resp.status, data
    except (OSError, http.client.HTTPException) as e:
        if expired.is_set():
            raise TimeoutError("slow response") from None
        if isinstance(e, http.client.HTTPException):
            raise ValueError(f"bad http response: {type(e).__name__}") from None
        raise
    finally:
        timer.cancel()
        conn.close()


def safe_xml(data: bytes) -> ElementTree.Element:
    """Parse untrusted XML: anything declaring a DTD or entities is refused outright
    (no billion-laughs / external entities), then plain ElementTree."""
    head = data.lower()
    if b"<!doctype" in head or b"<!entity" in head:
        raise ValueError("DTD / entity declarations are not accepted")
    # the byte check above only sees ASCII-compatible encodings: a UTF-16 / UTF-32 /
    # EBCDIC document would slip "<!DOCTYPE" past it. Real UPnP descriptions are UTF-8.
    body = data[3:] if data.startswith(b"\xef\xbb\xbf") else data   # a UTF-8 BOM is fine
    if b"\x00" in body or body.lstrip()[:1] != b"<":
        raise ValueError("only ASCII-compatible XML is accepted")
    m = re.match(rb"\s*<\?xml[^>]*encoding\s*=\s*[\"']([A-Za-z0-9._-]+)", body)
    if m and m.group(1).lower().replace(b"_", b"-") not in (b"utf-8", b"utf8", b"us-ascii",
                                                           b"ascii", b"iso-8859-1", b"latin-1"):
        raise ValueError("only ASCII-compatible XML is accepted")
    return ElementTree.fromstring(data)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el, name: str) -> str:
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return ""


def parse_description(data: bytes, location: str) -> dict:
    """A UPnP device description -> {name, manufacturer, model, device_type, kind,
    wan: [{service_type, control_url}]}. Raises ValueError for unusable XML."""
    root = safe_xml(data)
    device = next((e for e in root.iter() if _local(e.tag) == "device"), None)
    if device is None:
        raise ValueError("no <device>")
    base = _child_text(root, "URLBase") or location
    model = " ".join(x for x in (_child_text(device, "modelName"),
                                 _child_text(device, "modelNumber")) if x)
    dtype = _child_text(device, "deviceType")
    wan = []
    for svc in root.iter():
        if _local(svc.tag) != "service":
            continue
        st = _child_text(svc, "serviceType")
        if ":WANIPConnection:" in st or ":WANPPPConnection:" in st:
            ctl = _child_text(svc, "controlURL")
            if ctl:
                wan.append({"service_type": clean(st, 200), "control_url": urljoin(base, ctl)})
    kind = next((k for frag, k in KIND_BY_UPNP if frag in dtype), None)
    name = _child_text(device, "friendlyName")
    kind = _rule_kind(model, name) if kind in (None, "tv") and _rule_kind(model, name) else kind
    return {"name": clean(name), "manufacturer": clean(_child_text(device, "manufacturer")),
            "model": clean(model), "device_type": clean(dtype, 200), "kind": kind, "wan": wan}


IGD_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"


def ssdp_search(seconds: float = LISTEN_SECONDS, dest=(SSDP_ADDR, SSDP_PORT),
                targets=(), gateway: str | None = None, port: int = SSDP_PORT) -> dict:
    """M-SEARCH and listen -> {ip: {"locations": [...], "server": str, "st": [...]}}
    for every private responder. `dest` is for tests (None: no multicast search).
    targets / gateway: also a unicast M-SEARCH to each inventory IP (and the router,
    which is also asked for its Internet Gateway Device) - the reply comes back to the
    asking socket, so it gets through where multicast replies are dropped."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.bind(("", 0))
    found: dict = {}

    def packet(ip, data):
        h = parse_ssdp(data)
        if not h:
            return
        e = found.setdefault(ip, {"locations": [], "server": "", "st": []})
        loc = h.get("location")
        if loc and loc not in e["locations"] and len(e["locations"]) < MAX_LOCATIONS_PER_IP:
            e["locations"].append(loc)
        e["server"] = e["server"] or clean(h.get("server", ""), 200)
        st = h.get("st") or h.get("nt")
        if st and st not in e["st"] and len(e["st"]) < 16:
            e["st"].append(clean(st, 200))

    jobs = []
    for ip in unicast_targets(([gateway] if gateway else []) + list(targets)):
        jobs.append((build_msearch("ssdp:all", host=f"{ip}:{port}"), (ip, port)))
        if ip == gateway:
            jobs.append((build_msearch(IGD_ST, host=f"{ip}:{port}"), (ip, port)))
    try:
        if dest:
            for st in ("ssdp:all", IGD_ST):
                s.sendto(build_msearch(st), dest)
        sender = _send_paced(s, jobs) if jobs else None
        _listen([s], seconds + _send_time(jobs), packet)
        if sender:
            sender.join(1.0)
    finally:
        s.close()
    return found


# --- NetBIOS node status (Windows / Samba computers) ----------------------------------

NB_STAT = 0x21


def build_nbstat(txid: int) -> bytes:
    """A NetBIOS node-status request (RFC 1002 4.2.17) for the wildcard name "*": the
    question every Windows / Samba machine answers with the names it holds."""
    raw = b"*" + b"\0" * 15
    encoded = bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return (struct.pack("!HHHHHH", txid & 0xFFFF, 0, 1, 0, 0, 0)
            + b"\x20" + encoded + b"\0" + struct.pack("!HH", NB_STAT, 1))


def parse_nbstat(data: bytes) -> dict | None:
    """A node-status response -> {name, workgroup, mac} (the unique computer name,
    the group it is in, the adapter MAC it reports) or None. Bounded, never raises."""
    try:
        if len(data) < 12:
            return None
        _id, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        off = 12
        for _ in range(min(qd, 4)):
            _n, off = _read_name(data, off)
            off += 4
        if not an:
            return None
        _n, off = _read_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        rdata = data[off + 10:off + 10 + rdlen]
        if rtype != NB_STAT or not rdata:
            return None
        count, name, group = rdata[0], "", ""
        for i in range(min(count, 64)):
            entry = rdata[1 + 18 * i:19 + 18 * i]
            if len(entry) < 18:
                break
            label = entry[:15].decode("latin-1").rstrip(" \0")
            suffix, flags = entry[15], struct.unpack("!H", entry[16:18])[0]
            if suffix != 0x00 or not label:
                continue          # 0x00 = the workstation name; 0x20 = file server, ...
            if flags & 0x8000:
                group = group or label
            else:
                name = name or label
        unit = rdata[1 + 18 * count:7 + 18 * count]
        mac = ":".join(f"{b:02x}" for b in unit) if len(unit) == 6 and any(unit) else ""
    except (DnsError, struct.error, IndexError):
        return None
    if not name:
        return None
    return {"name": clean(name), "workgroup": clean(group), "mac": mac}


def netbios_query(targets, seconds: float = LISTEN_SECONDS, port: int = NETBIOS_PORT) -> dict:
    """A node-status request to each inventory IP (UDP 137, unicast) -> {ip: {name,
    workgroup, mac}} for every Windows / Samba machine that answered."""
    ips = unicast_targets(targets)
    if not ips:
        return {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.bind(("", 0))
    base = int.from_bytes(os.urandom(2), "big")
    jobs = [(build_nbstat(base + i), (ip, port)) for i, ip in enumerate(ips)]
    asked = set(ips)
    found: dict = {}

    def packet(ip, data):
        if ip in asked and ip not in found:
            info = parse_nbstat(data)
            if info:
                found[ip] = info

    try:
        sender = _send_paced(s, jobs)
        _listen([s], seconds + _send_time(jobs), packet)
        sender.join(1.0)
    finally:
        s.close()
    return found


# --- reverse DNS through the system resolver ------------------------------------------

RDNS_TIMEOUT = 2.0
RDNS_WORKERS = 16


def reverse_dns(ips, timeout: float = RDNS_TIMEOUT, resolve=None) -> dict:
    """{ip: name} from PTR lookups through the system resolver (the router's DHCP names,
    usually), in parallel with one overall deadline. Names that just repeat an address
    are dropped. `resolve` is for tests."""
    resolve = resolve or (lambda ip: socket.gethostbyaddr(ip)[0])
    ips = unicast_targets(ips)
    out: dict = {}
    lock = threading.Lock()
    todo = list(ips)

    def worker():
        while True:
            with lock:
                if not todo:
                    return
                ip = todo.pop()
            try:
                name = clean(resolve(ip))
            except Exception:   # noqa: BLE001 - no PTR record is the common case
                continue
            if name and not private_ip(name) and not name.replace(".", "").isdigit():
                with lock:
                    out[ip] = name
    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(RDNS_WORKERS, len(ips)))]
    deadline = time.monotonic() + timeout
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(out)


def describe(found: dict, fetch=http_get) -> dict:
    """Fetch + parse the device descriptions of ssdp_search() results (only allowed
    LOCATIONs, bounded count, in parallel) -> {ip: {..., "location"}}. A location that
    fails is skipped quietly."""
    jobs = [(ip, loc) for ip, e in found.items() for loc in e["locations"]
            if location_ok(loc, ip)][:MAX_DESCRIPTIONS]
    out: dict = {}
    lock = threading.Lock()

    def one(job):
        ip, loc = job
        try:
            status, body = fetch(loc)
            if status != 200:
                return
            info = parse_description(body, loc)
        except Exception:   # noqa: BLE001 - one odd device must not stop the rest
            return
        # control URLs must stay on the same device (they are used by upnp.py)
        info["wan"] = [w for w in info["wan"] if location_ok(w["control_url"], ip)]
        info["location"] = loc
        with lock:
            prev = out.get(ip)
            # keep the most useful description per IP (a gateway, or one with a name)
            if prev is None or (info["wan"] and not prev["wan"]) or \
                    (not prev["name"] and info["name"]):
                out[ip] = info

    threads = [threading.Thread(target=one, args=(j,), daemon=True) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(DESC_TIMEOUT + 1.5)
    return out


# --- putting it together ----------------------------------------------------------------

def _ip_mac(db) -> dict:
    from netwarden import discovery
    m = dict(discovery.read_arp())
    m.update(store.ip_to_mac(db))
    return m


def record_mdns(db, results: dict, ip_mac: dict, seen: str | None = None) -> int:
    n = 0
    for ip, info in results.items():
        mac = ip_mac.get(ip)
        if not mac:
            continue
        store.upsert_identity(db, mac, "mdns", info["name"], info["manufacturer"],
                              info["model"], info["kind"], " ".join(info["services"]), seen)
        n += 1
    return n


def record_ssdp(db, described: dict, ip_mac: dict, seen: str | None = None) -> int:
    n = 0
    for ip, info in described.items():
        mac = ip_mac.get(ip)
        if not mac:
            continue
        store.upsert_identity(db, mac, "ssdp", info["name"], info["manufacturer"],
                              info["model"], info["kind"], info["device_type"], seen)
        n += 1
    return n


def record_dhcp_names(db, devices: list, seen: str | None = None) -> int:
    """The sweep's reverse-DNS names (what the router's DHCP server calls each device)."""
    n = 0
    for d in devices:
        if d.get("mac") and d.get("hostname") and not d.get("is_self"):
            store.upsert_identity(db, d["mac"], "dhcp", name=d["hostname"], seen=seen)
            n += 1
    return n


DNS_NAME_REFRESH_S = 3600   # re-write an unchanged DNS client name at most hourly


def record_dns_names(db, names: dict) -> int:
    """{mac: client name from AdGuard / Pi-hole} -> 'dns' evidence. Called by every
    ingest poll, so an unchanged name is only refreshed once an hour (no write churn)."""
    if not names:
        return 0
    known = {r["mac"]: (r["name"], r["last_seen"]) for r in db.execute(
        "SELECT mac, name, last_seen FROM device_identity WHERE source = 'dns'")}
    stale = time.time() - DNS_NAME_REFRESH_S
    n = 0
    for mac, name in names.items():
        name = clean(name)
        if not name or private_ip(name) or name.replace(".", "").isdigit():
            continue
        old = known.get(mac)
        if old and old[0] == name and _epoch(old[1]) > stale:
            continue
        store.upsert_identity(db, mac, "dns", name=name)
        n += 1
    return n


def _epoch(ts: str) -> float:
    from datetime import datetime, timezone
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0.0


def record_netbios(db, results: dict, ip_mac: dict, seen: str | None = None) -> int:
    n = 0
    for ip, info in results.items():
        mac = ip_mac.get(ip)
        if not mac:
            continue
        # a Windows / Samba workstation name: almost always a computer (or a NAS)
        store.upsert_identity(db, mac, "netbios", info["name"], "", "", "computer",
                              info["workgroup"], seen)
        n += 1
    return n


def record_rdns(db, names: dict, ip_mac: dict, seen: str | None = None) -> int:
    """Reverse-DNS names found by the unicast round -> 'dhcp' evidence (the same thing
    the sweep's own lookup records: what the router's DHCP / DNS calls the device)."""
    n = 0
    for ip, name in names.items():
        mac = ip_mac.get(ip)
        if mac:
            store.upsert_identity(db, mac, "dhcp", name=name, seen=seen)
            n += 1
    return n


def inventory_targets(db) -> tuple[list, list]:
    """(every private inventory IP except this computer's, those without a hostname)."""
    rows = db.execute("""SELECT ip, hostname FROM devices WHERE ip IS NOT NULL AND ip != ''
                         AND is_self = 0 ORDER BY last_seen DESC""").fetchall()
    ips = unicast_targets(r["ip"] for r in rows)
    return ips, [r["ip"] for r in rows if r["ip"] in ips and not r["hostname"]]


def resolver_is_local(path: str = "/etc/resolv.conf") -> bool:
    """Does the system resolver stay inside the home (every nameserver loopback or
    private)? Only then are PTR questions about our devices sent through it - a public
    resolver must not hear which private addresses exist here."""
    try:
        text = Path(path).read_text(errors="replace")[:8192]
    except OSError:
        return False
    servers = re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)
    if not servers:
        return False
    for s in servers:
        try:
            a = ipaddress.ip_address(s.split("%", 1)[0])
        except ValueError:
            return False
        if not (a.is_loopback or a.is_private or a.is_link_local):
            return False
    return True


def run_recorded(db, seconds: float = LISTEN_SECONDS, upnp_too: bool = True,
                 unicast: bool = True) -> dict:
    """One identification round, stored, each part's outcome in source_status:
    mDNS + SSDP (multicast, and - unicast=True - the same questions sent straight to
    every private inventory IP and the router), NetBIOS node status (Windows / Samba
    names) and reverse DNS for devices without a hostname, all in parallel; then UPnP
    on the gateway. Never raises for a part that fails (its error is recorded); refuses
    the demo DB. -> {mdns, ssdp, netbios, upnp} summaries (+ unicast: targets asked)."""
    from netwarden import health, upnp   # upnp imports us
    if store.is_demo(db):
        raise DemoRefused()
    res: dict = {}
    errors: dict = {}
    targets, nameless = inventory_targets(db) if unicast else ([], [])
    gateway = upnp.default_gateway() if unicast else None
    if gateway and not private_ip(gateway):
        gateway = None

    def run(name, fn):
        try:
            res[name] = fn()
        except Exception as e:   # noqa: BLE001 - recorded below
            errors[name] = e

    jobs = [("mdns", lambda: mdns_browse(seconds, targets=targets)),
            ("ssdp", lambda: ssdp_search(seconds, targets=targets, gateway=gateway))]
    if unicast:
        jobs.append(("netbios", lambda: netbios_query(targets, seconds)))
        if nameless and resolver_is_local():
            jobs.append(("rdns", lambda: reverse_dns(nameless)))
    threads = [threading.Thread(target=run, args=job) for job in jobs]
    for t in threads:
        t.start()
    deadline = time.monotonic() + seconds + _send_time(targets * 2) + 5
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    ip_mac = _ip_mac(db)
    seen = store.now()
    summary = {"unicast": {"targets": len(targets), "gateway": bool(gateway)}}
    if unicast:
        if "netbios" in res:
            n = record_netbios(db, res["netbios"], ip_mac, seen)
            store.record_source_ok(db, "netbios", n)
            summary["netbios"] = {"ok": True, "hosts": len(res["netbios"]), "devices": n,
                                  "kinds": {"computer": n} if n else {}}
        else:
            err = health.sanitize_error(errors.get("netbios", "timeout"))
            store.record_source_error(db, "netbios", err)
            summary["netbios"] = {"ok": False, "error": err}
        summary["rdns"] = {"asked": len(nameless) if "rdns" in res or "rdns" in errors else 0,
                           "names": record_rdns(db, res.get("rdns") or {}, ip_mac, seen)}
    if "mdns" in res:
        n = record_mdns(db, res["mdns"], ip_mac, seen)
        store.record_source_ok(db, "mdns", n)
        summary["mdns"] = {"ok": True, "hosts": len(res["mdns"]), "devices": n,
                           "kinds": _kinds(res["mdns"])}
    else:
        store.record_source_error(db, "mdns", health.sanitize_error(errors.get("mdns", "timeout")))
        summary["mdns"] = {"ok": False, "error": health.sanitize_error(errors.get("mdns", "timeout"))}
    described = {}
    if "ssdp" in res:
        described = describe(res["ssdp"])
        n = record_ssdp(db, described, ip_mac, seen)
        store.record_source_ok(db, "ssdp", n)
        summary["ssdp"] = {"ok": True, "hosts": len(res["ssdp"]), "described": len(described),
                           "devices": n, "kinds": _kinds(described)}
    else:
        store.record_source_error(db, "ssdp", health.sanitize_error(errors.get("ssdp", "timeout")))
        summary["ssdp"] = {"ok": False, "error": health.sanitize_error(errors.get("ssdp", "timeout"))}
    if upnp_too:
        summary["upnp"] = upnp.check_recorded(db, described, ip_mac)
    return summary


def _kinds(results: dict) -> dict:
    """{kind: count} - what a run found, without any names (for the CLI / report)."""
    out: dict = {}
    for info in results.values():
        k = info.get("kind") or "unknown"
        out[k] = out.get(k, 0) + 1
    return out


# --- reading: what the dashboard / brain / type guesser use ----------------------------

def best(rows: list) -> dict:
    """A device's identity rows (store.identities order) -> {name, manufacturer, model,
    kind, sources}: the first non-empty value per field. The name only comes from what
    the device announced itself (mDNS / SSDP) - the DHCP / DNS names are its hostname."""
    out = {"name": "", "manufacturer": "", "model": "", "kind": None, "sources": []}
    for r in rows:
        if r["source"] not in out["sources"]:
            out["sources"].append(r["source"])
        if r["source"] in store.ANNOUNCED_SOURCES and not out["name"] and r.get("name"):
            out["name"] = r["name"]
        for f in ("manufacturer", "model", "kind"):
            if not out[f] and r.get(f):
                out[f] = r[f]
    return out


def summary_all(db) -> dict:
    """mac -> best() for every device with identity evidence."""
    return {mac: best(rows) for mac, rows in store.identities(db).items()}


def source_name(source: str, lang: str) -> str:
    from netwarden import i18n
    return i18n.t("ident.src." + source, lang)


def device_report(db, mac: str, lang: str, label: str | None = None,
                  hostname: str | None = None) -> dict:
    """GET /api/device "identity": {name, manufacturer, model, kind, sources: [{source,
    source_name, name, manufacturer, model, detail, last_seen}], suggested_name}.
    suggested_name = an announced name the user has not used as the label yet (never
    applied automatically: "use this name" is the user's click)."""
    rows = store.identities(db, mac).get(mac, [])
    b = best(rows)
    suggestion = b["name"] if b["name"] and b["name"] not in (label or "", hostname or "") \
        and not label else ""
    return {**b, "suggested_name": suggestion,
            "evidence": [{"source": r["source"], "source_name": source_name(r["source"], lang),
                          "name": r.get("name") or "", "manufacturer": r.get("manufacturer") or "",
                          "model": r.get("model") or "", "detail": r.get("detail") or "",
                          "last_seen": r["last_seen"]} for r in rows]}


def main(argv=None, prog=None) -> int:
    """`python3 -m netwarden identify`: one mDNS + SSDP + UPnP round, stored in --db and
    printed as counts per kind (no names)."""
    import argparse
    import json
    from netwarden import brain, i18n
    lang = i18n.normalize(brain.load_env().get("NETWARDEN_LANG"))
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.identify", lang))
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help=i18n.t("cli.opt.db", lang))
    ap.add_argument("--seconds", type=float, default=LISTEN_SECONDS,
                    help=i18n.t("cli.opt.listen_seconds", lang))
    ap.add_argument("--json", action="store_true", help=i18n.t("cli.opt.identify_json", lang))
    ap.add_argument("--lang", default=None, help=i18n.t("cli.opt.lang", lang))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang)
    db = store.connect(args.db)
    try:
        summary = run_recorded(db, max(0.5, min(args.seconds, 15.0)))
    except DemoRefused:
        print(i18n.t("ident.demo_refused", lang), file=__import__("sys").stderr)
        return 1
    finally:
        db.close()
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    tr = lambda key, **kw: i18n.t("cli.identify." + key, lang, **kw)  # noqa: E731
    uni = summary.get("unicast") or {}
    if uni.get("targets"):
        print(tr("unicast", n=uni["targets"]))
    for part in ("mdns", "ssdp", "netbios"):
        s = summary.get(part)
        if s is None:
            continue
        if s["ok"]:
            kinds = i18n.t("list_sep", lang).join(
                f"{n} × {i18n.t('devtype.' + k, lang)}" for k, n in sorted(s["kinds"].items()))
            print(i18n.tn("cli.identify." + part, s["hosts"], lang, hosts=s["hosts"], devices=s["devices"],
                          kinds=kinds or "—"))
        else:
            print(tr("failed", part=i18n.t("status.src." + part, lang), error=s["error"]))
    rd = summary.get("rdns") or {}
    if rd.get("asked"):
        print(i18n.tn("cli.identify.rdns", rd["asked"], lang, names=rd["names"], asked=rd["asked"]))
    u = summary.get("upnp") or {}
    print(tr("upnp_ok", n=u.get("mappings", 0)) if u.get("available")
          else tr("upnp_none"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
