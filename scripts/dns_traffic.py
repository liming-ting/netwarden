#!/usr/bin/env python3
"""
netwarden - send test DNS queries to the dev AdGuard Home (no dig needed).

Builds plain DNS A/AAAA queries by hand (stdlib only) so we can validate the
ingest pipeline end-to-end before pointing any real device at the server.

    python3 scripts/dns_traffic.py                       # default mix -> 127.0.0.1:5354
    python3 scripts/dns_traffic.py --bind 192.168.1.13      # appear as our LAN IP instead
    python3 scripts/dns_traffic.py example.com -n 3      # specific domains, 3 rounds
"""
from __future__ import annotations

import argparse
import random
import socket
import struct

# A small "smart home" mix: streaming, phone, IoT phone-home, ads/trackers (AdGuard's
# default filter should block those), and one name that can't exist (NXDOMAIN).
DEFAULT_DOMAINS = [
    "www.netflix.com", "api.amazonalexa.com", "time.apple.com", "connectivitycheck.gstatic.com",
    "graph.facebook.com", "doubleclick.net", "googleads.g.doubleclick.net",
    "device-metrics-us.amazon.com", "pool.ntp.org", "no-such-host.netwarden.invalid",
]
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
QTYPES = {"A": 1, "AAAA": 28}


def build_query(domain: str, qtype: str) -> tuple[int, bytes]:
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, one question
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.rstrip(".").split(".")) + b"\0"
    return qid, header + qname + struct.pack(">HH", QTYPES[qtype], 1)


def query(server: str, port: int, domain: str, qtype: str, bind: str | None, timeout: float) -> str:
    qid, pkt = build_query(domain, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        if bind:
            s.bind((bind, 0))
        s.sendto(pkt, (server, port))
        try:
            resp, _ = s.recvfrom(4096)
        except socket.timeout:
            return "TIMEOUT"
    rid, flags, _qd, ancount = struct.unpack(">HHHH", resp[:8])
    if rid != qid:
        return "BAD-ID"
    return f"{RCODES.get(flags & 0xF, flags & 0xF)} ({ancount} answers)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("domains", nargs="*", default=DEFAULT_DOMAINS)
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5354)
    ap.add_argument("--bind", help="source IP to send from (shows up as the client IP)")
    ap.add_argument("--type", default="A", choices=QTYPES)
    ap.add_argument("-n", "--rounds", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=3)
    args = ap.parse_args()

    for _ in range(args.rounds):
        for d in args.domains:
            print(f"{d:<40}{query(args.server, args.port, d, args.type, args.bind, args.timeout)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
