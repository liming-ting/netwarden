#!/usr/bin/env python3
"""
netwarden - device discovery (Day 1)

Scans the local /24, resolves MAC-address vendors, and prints a table of every
device it can see on your LAN. Pure standard library: no pip, no venv.

Discovery strategy (no root required):
  - ICMP ping each host, AND
  - open a brief TCP connection to a couple of common ports.
Either way the kernel must ARP-resolve the target first, so even devices that
silently drop ping/TCP still reveal their MAC address at layer 2. We then read
the kernel neighbour table to list everything that answered.

Run inside WSL2 (with mirrored networking) or on any host that sits on the LAN:
    python3 discover.py
"""
from __future__ import annotations

import argparse
import concurrent.futures
import errno
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "netwarden"
MANUF_CACHE = CACHE_DIR / "manuf.txt"
MANUF_URLS = [
    "https://www.wireshark.org/download/automated/data/manuf",
    "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf",
]
KNOCK_PORTS = [80, 443, 22, 53]  # any unicast packet forces ARP resolution
KNOCK_TIMEOUT = 0.4

BUILTIN_OUI = {  # tiny fallback if the vendor DB can't be downloaded
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
}


def default_iface_net_ip():
    """Return (iface, IPv4Network, own_ip) for the default route."""
    try:
        route = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None, None, None
    iface = None
    for line in route.splitlines():
        if line.startswith("default"):
            m = re.search(r"dev (\S+)", line)
            if m:
                iface = m.group(1)
            break
    if not iface:
        return None, None, None
    try:
        addr = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return iface, None, None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr)
    if not m:
        return iface, None, None
    own_ip = m.group(1)
    net = ipaddress.ip_network(f"{own_ip}/{m.group(2)}", strict=False)
    return iface, net, own_ip


def probe(ip: str) -> None:
    """Touch a host so the kernel ARP-resolves it. Result is read later from ARP."""
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", "-n", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3,
        )
    except Exception:
        pass
    for port in KNOCK_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(KNOCK_TIMEOUT)
                s.connect_ex((ip, port))
        except Exception:
            pass


def alive(ip: str) -> bool:
    """Is the host at `ip` there RIGHT NOW? The sweep's own method (one ping, then the
    TCP knock), but strict: a ping reply, or a port that answered (open OR refused - a
    refusal also comes from a live host), or a neighbour entry the kernel just confirmed
    (REACHABLE). A stale ARP entry does not count. Used by the Stage P presence check."""
    try:
        if subprocess.run(["ping", "-c", "1", "-W", "1", "-n", ip], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=3).returncode == 0:
            return True
    except Exception:
        pass
    for port in KNOCK_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(KNOCK_TIMEOUT)
                if s.connect_ex((ip, port)) in (0, errno.ECONNREFUSED):
                    return True
        except Exception:
            pass
    try:
        neigh = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True,
                               timeout=5).stdout
    except Exception:
        return False
    return "REACHABLE" in neigh


def sweep(net) -> None:
    hosts = [str(h) for h in net.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(probe, hosts))


def read_arp() -> dict[str, str]:
    out = {}
    try:
        neigh = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return out
    for line in neigh.splitlines():
        m = re.match(r"(\d+\.\d+\.\d+\.\d+).*lladdr ([0-9a-fA-F:]{17})", line)
        if m:
            out[m.group(1)] = m.group(2).lower()
    return out


MIN_MANUF_ENTRIES = 1000   # a real Wireshark manuf file has ~50k; an HTML error page has 0
_OUI = re.compile(r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$")


def parse_manuf(text: str) -> dict[str, str]:
    """Wireshark `manuf` text -> {"AA:BB:CC": vendor} (24-bit prefixes only)."""
    table = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].strip().upper()
        if not _OUI.match(prefix):
            continue
        names = [p.strip() for p in parts[1:] if p.strip()]
        if names:
            table[prefix] = names[-1]
    return table


def update_manuf(timeout: float = 20) -> int:
    """Download the Wireshark vendor list (OPT-IN: `netwarden scan --update-vendors`;
    never from the background loops). The file is only cached when it really parses as
    a manuf file, so an error page can't poison the cache. Returns the number of
    prefixes, raises OSError when no mirror gave a usable file."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    last = "no mirror answered"
    for url in MANUF_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netwarden/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read(64 << 20)
        except Exception as e:  # noqa: BLE001 - try the next mirror
            last = f"{type(e).__name__}: {e}"
            continue
        n = len(parse_manuf(data.decode("utf-8", "ignore")))
        if n < MIN_MANUF_ENTRIES:
            last = f"{url}: not a vendor list ({n} entries)"
            continue
        tmp = MANUF_CACHE.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(MANUF_CACHE)
        return n
    raise OSError(last)


def load_manuf() -> dict[str, str]:
    """The vendor table: a few built-in prefixes + the cached Wireshark list, if the
    user downloaded it (update_manuf). Never touches the network."""
    table = dict(BUILTIN_OUI)
    if MANUF_CACHE.exists():
        table.update(parse_manuf(MANUF_CACHE.read_text(errors="ignore")))
    return table


def is_randomized(mac: str) -> bool:
    """True if the locally-administered bit is set (randomized / privacy MAC)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def label(mac: str, table: dict[str, str]) -> str:
    """The MAC's vendor, or "" when unknown. Randomized / unknown is NOT spelled out
    here: devices.randomized carries that and every UI localizes it at the edge."""
    if not mac:
        return ""
    return table.get(mac.upper()[0:8], "")


def hostname_for(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def own_mac(iface: str) -> str:
    """Our own MAC never shows up in the ARP table, so read it from sysfs."""
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    except Exception:
        return ""


def device_record(ip: str, mac: str, table: dict[str, str], is_self: bool = False,
                  hostname: str | None = None) -> dict:
    """One device as a plain dict - the shape store.upsert_device() expects."""
    return {
        "ip": ip,
        "mac": mac,
        "vendor": label(mac, table),   # is_self marks this machine (localized in the UI)
        "hostname": hostname_for(ip) if hostname is None else hostname,
        "randomized": is_randomized(mac) if mac else False,
        "is_self": is_self,
    }


def scan(iface: str, net, own_ip: str, table: dict[str, str]) -> list[dict]:
    """Sweep `net` and return a device record for everything that answered (incl. us)."""
    sweep(net)
    arp = read_arp()
    ips = sorted(
        {ip for ip in set(arp) | {own_ip} if ipaddress.ip_address(ip) in net},
        key=lambda x: tuple(int(o) for o in x.split(".")),
    )
    devices = []
    for ip in ips:
        if ip == own_ip:
            devices.append(device_record(ip, own_mac(iface), table, is_self=True,
                                         hostname=socket.gethostname()))
        else:
            devices.append(device_record(ip, arp.get(ip, ""), table))
    return devices


def availability() -> tuple[bool, str | None]:
    """Can a sweep run here, unprivileged? -> (ok, reason). The sweep itself needs no
    root (ping + TCP knock + reading the neighbour table), but it does need Linux `ip`
    and a default route onto a LAN. reason: 'no_ip_command' | 'no_lan' | None."""
    if not shutil.which("ip"):
        return False, "no_ip_command"
    _iface, net, _own = default_iface_net_ip()
    if not net:
        return False, "no_lan"
    return True, None


def scan_recorded(db, table: dict | None = None, identify_too: bool = True) -> list[dict]:
    """One full sweep, stored in `db`, with the outcome written to source_status
    ('discovery'). Then (identify_too) one identification round - mDNS / SSDP names and
    the router's UPnP port mappings (identify.py, upnp.py) - whose parts record their
    own status and never fail the sweep. Used by `netwarden scan` and the `run` loop.
    Raises when the sweep itself fails."""
    from netwarden import health, identify, store  # these never import discovery at load
    try:
        iface, net, own_ip = default_iface_net_ip()
        if not net:
            raise OSError("could not determine the local network")
        devices = scan(iface, net, own_ip, load_manuf() if table is None else table)
        for d in devices:
            store.upsert_device(db, d)
    except Exception as e:
        store.record_source_error(db, SOURCE, health.sanitize_error(e))
        raise
    store.record_source_ok(db, SOURCE, len(devices))
    identify.record_dhcp_names(db, devices)
    if identify_too and not store.is_demo(db):
        try:
            identify.run_recorded(db)
        except Exception as e:  # noqa: BLE001 - names are a bonus; the sweep succeeded
            import logging
            logging.getLogger("netwarden").warning("identify failed: %s",
                                                   health.sanitize_error(e))
    return devices


SOURCE = "discovery"   # name in source_status


def main(argv=None, prog=None) -> int:
    from netwarden import brain, health, i18n, wslnet   # lazy: only the CLI needs these
    lang0 = i18n.normalize(brain.load_env().get("NETWARDEN_LANG"))
    ap = argparse.ArgumentParser(prog=prog, description=i18n.t("cli.cmd.scan", lang0))
    ap.add_argument("--save", action="store_true", help=i18n.t("cli.opt.save", lang0))
    ap.add_argument("--db", default=None, help=i18n.t("cli.opt.db", lang0))
    ap.add_argument("--update-vendors", action="store_true",
                    help=i18n.t("cli.opt.update_vendors", lang0))
    ap.add_argument("--no-identify", action="store_true",
                    help=i18n.t("cli.opt.no_identify", lang0))
    ap.add_argument("--lang", default=None, help=i18n.t("cli.opt.lang", lang0))
    args = ap.parse_args(argv)
    lang = i18n.normalize(args.lang or lang0)
    t = lambda k, **kw: i18n.t("cli.scan." + k, lang, **kw)  # noqa: E731

    if args.update_vendors:   # the ONLY way discovery goes online (opt-in, download only)
        try:
            print(i18n.t("cli.scan.vendors_updated", lang, n=f"{update_manuf():,}"))
        except OSError as e:
            print(t("vendors_failed", error=health.sanitize_error(e)), file=sys.stderr)
            return 1

    socket.setdefaulttimeout(1.0)
    iface, net, own_ip = default_iface_net_ip()
    if not net:
        print(t("no_lan"), file=sys.stderr)
        return 1

    print(t("iface", iface=iface))
    print(t("self", ip=own_ip))
    print(t("network", net=net, n=f"{net.num_addresses - 2:,}"))
    table = load_manuf()
    print(t("vendor_db", n=f"{len(table):,}"))
    if not MANUF_CACHE.exists():
        print(t("vendors_hint"))

    t0 = time.time()
    print(t("scanning", net=net))
    if args.save:
        from netwarden import store
        db = store.connect(args.db or store.DEFAULT_DB)
        try:
            devices = scan_recorded(db, table, identify_too=not args.no_identify)
        except Exception as e:  # already recorded in source_status
            print(health.sanitize_error(e), file=sys.stderr)
            return 1
    else:
        devices = scan(iface, net, own_ip, table)

    pad = health.pad   # East Asian wide characters take two columns
    print()
    print(pad(t("col_ip"), 16) + pad(t("col_mac"), 20) + pad(t("col_vendor"), 30) + t("col_host"))
    print("-" * 84)
    for d in devices:
        mac = "—" if d["is_self"] else (d["mac"] or "—")
        vendor = d["vendor"] or "—"
        if len(vendor) > 28:
            vendor = vendor[:27] + "…"
        print(f"{d['ip']:<16}{mac:<20}{pad(vendor, 30)}{d['hostname']}")
    print()
    print(t("found", n=len(devices), s=f"{time.time() - t0:.1f}"))
    if wslnet.is_wsl():
        print(i18n.t("discovery.wsl_few", lang))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
