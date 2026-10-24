"""A small stand-in for Home Assistant's ingress proxy chain (round 6, stage H tests).

What the real chain does (docs/dev/ha_addon.md): the browser asks Home Assistant for
/api/hassio_ingress/<token>/<path>; HA core adds X-Ingress-Path, X-Hass-Source and
X-Forwarded-For/-Host/-Proto (Host and Origin pass through unchanged); the Supervisor
appends its own hop to X-Forwarded-For and connects to the add-on FROM 172.30.32.2,
asking for /<path>. Event streams are passed through unbuffered.

Here the "Supervisor" connects from another loopback address (`source`, 127.0.0.2 by
default) so a test can tell it apart from a direct client on 127.0.0.1 - never a LAN
address. Also runnable for a manual browser check:

    python3 tests/ingress_proxy.py --upstream 8799 --port 8800
    # then open http://127.0.0.1:8800/api/hassio_ingress/TESTTOKEN/
"""
from __future__ import annotations

import argparse
import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PREFIX = "/api/hassio_ingress/TESTTOKEN"
HOP = {"connection", "keep-alive", "transfer-encoding", "content-length", "accept-encoding",
       "proxy-connection", "upgrade", "te"}


class IngressProxy:
    def __init__(self, upstream_port: int, prefix: str = PREFIX, source: str = "127.0.0.2",
                 port: int = 0, extra_headers: dict | None = None):
        self.upstream_port, self.prefix, self.source = upstream_port, prefix, source
        self.extra_headers = dict(extra_headers or {})
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                proxy._forward(self)

            do_POST = do_HEAD = do_GET

            def log_message(self, *args):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}{prefix}"

    def start(self) -> "IngressProxy":
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()

    def _forward(self, h: BaseHTTPRequestHandler) -> None:
        if not h.path.startswith(self.prefix + "/"):
            h.send_response(404)
            h.send_header("content-length", "0")
            h.end_headers()
            return
        rest = h.path[len(self.prefix):]
        n = int(h.headers.get("content-length") or 0)
        body = h.rfile.read(n) if n else None
        headers = {k: v for k, v in h.headers.items() if k.lower() not in HOP}
        # HA core ...
        xff = h.headers.get("x-forwarded-for")
        headers["X-Forwarded-For"] = f"{xff}, {h.client_address[0]}" if xff else h.client_address[0]
        headers["X-Forwarded-Host"] = h.headers.get("x-forwarded-host") or h.headers.get("host", "")
        headers["X-Forwarded-Proto"] = h.headers.get("x-forwarded-proto") or "http"
        headers["X-Ingress-Path"] = self.prefix
        headers["X-Hass-Source"] = "core.ingress"
        # ... then the Supervisor (its own hop: HA core's address on the hassio network)
        headers["X-Forwarded-For"] += ", 172.30.32.1"
        headers.update(self.extra_headers)
        up = http.client.HTTPConnection("127.0.0.1", self.upstream_port, timeout=60,
                                        source_address=(self.source, 0))
        try:
            up.request(h.command, rest, body, headers)
            r = up.getresponse()
            stream = (r.getheader("content-type") or "").startswith("text/event-stream")
            h.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in HOP:
                    h.send_header(k, v)
            if stream:
                h.send_header("connection", "close")
                h.end_headers()
                h.close_connection = True
                while True:
                    chunk = r.read1(65536)
                    if not chunk:
                        break
                    h.wfile.write(chunk)
                    h.wfile.flush()
                return
            data = r.read()
            h.send_header("content-length", str(len(data)))
            h.end_headers()
            if h.command != "HEAD":
                h.wfile.write(data)
        except OSError:
            h.close_connection = True
        finally:
            up.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="fake Home Assistant ingress proxy (tests / manual checks)")
    ap.add_argument("--upstream", type=int, required=True)
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--source", default="127.0.0.2")
    args = ap.parse_args()
    p = IngressProxy(args.upstream, source=args.source, port=args.port)
    print(f"ingress proxy: {p.base}/  ->  127.0.0.1:{args.upstream} (from {args.source})", flush=True)
    try:
        p.srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
