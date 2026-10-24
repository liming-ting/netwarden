#!/usr/bin/env python3
"""
Draw netwarden's home-screen icons (Stage M) as PNGs with the stdlib only.

The design is netwarden/static/icon.svg (a white shield outline + dot on the blue
square), rasterized with analytic anti-aliasing: each pixel's coverage comes from its
distance to the shield's outline, so no image library is needed. The squares are
full-bleed (iOS and Android maskable icons round the corners themselves).

    python3 scripts/make_icons.py      # writes netwarden/static/{apple-touch-icon,icon-192,icon-512}.png
    python3 scripts/make_icons.py --ha-addon   # writes ha-addon/{icon,logo}.png (Stage H)

The PNGs are committed; re-run only after changing the design.
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "netwarden" / "static"
BG = (0x25, 0x63, 0xEB)        # icon.svg's fill
FG = (0xFF, 0xFF, 0xFF)
SIZES = {"apple-touch-icon.png": 180, "icon-192.png": 192, "icon-512.png": 512}
SCALE = 0.86   # the 32-unit design, shrunk a little toward the centre (maskable safe zone)


def _bezier(p0, p1, p2, p3, n=24):
    for i in range(1, n + 1):
        t = i / n
        u = 1 - t
        yield (u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
               u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1])


def shield() -> list[tuple[float, float]]:
    """icon.svg: M16 6l8 3v6c0 4.6-3.3 8.6-8 10-4.7-1.4-8-5.4-8-10V9z (32-unit box)."""
    pts = [(16, 6), (24, 9), (24, 15)]
    pts += list(_bezier((24, 15), (24, 19.6), (20.7, 23.6), (16, 25)))
    pts += list(_bezier((16, 25), (11.3, 23.6), (8, 19.6), (8, 15)))
    pts += [(8, 9), (16, 6)]
    return pts


def _seg_dist(px, py, ax, ay, bx, by) -> float:
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy or 1)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def render(size: int) -> bytes:
    unit = size / 32 * SCALE
    off = size * (1 - SCALE) / 2
    pts = [(off + x * unit, off + y * unit) for x, y in shield()]
    segs = list(zip(pts, pts[1:]))
    half = 2.2 / 2 * unit                          # stroke-width 2.2
    cx, cy, r = off + 16 * unit, off + 15 * unit, 2.6 * unit
    x0 = min(p[0] for p in pts) - half - 2
    x1 = max(p[0] for p in pts) + half + 2
    y0 = min(p[1] for p in pts) - half - 2
    y1 = max(p[1] for p in pts) + half + 2
    rows = []
    for y in range(size):
        row = bytearray([0])                       # filter: none
        for x in range(size):
            px, py = x + 0.5, y + 0.5
            cov = 0.0
            if x0 <= px <= x1 and y0 <= py <= y1:
                d = min(_seg_dist(px, py, *a, *b) for a, b in segs)
                cov = max(0.0, min(1.0, half - d + 0.5))
                cov = max(cov, max(0.0, min(1.0, r - math.hypot(px - cx, py - cy) + 0.5)))
            row += bytes(round(b + (f - b) * cov) for b, f in zip(BG, FG))
        rows.append(bytes(row))
    return png(size, size, b"".join(rows))


def png(w: int, h: int, raw: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + \
            struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


# --- Stage H: the Home Assistant add-on's icon.png (128x128) and logo.png (250x100) -----
# Same design, but as the app shows it (icon.svg's rounded square, rx=8 of 32) on a
# transparent background, since Home Assistant puts them on its own light or dark cards.
# The logo adds the "netwarden" wordmark drawn from strokes (no font files needed).

ADDON = STATIC.parent.parent / "ha-addon"


def _rounded_cov(px, py, x0, y0, size, radius) -> float:
    """Coverage of a pixel centre by a rounded square (signed distance, 1 px AA)."""
    hx = hy = size / 2
    qx = abs(px - (x0 + hx)) - (hx - radius)
    qy = abs(py - (y0 + hy)) - (hy - radius)
    d = math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - radius
    return max(0.0, min(1.0, 0.5 - d))


def _arc(cx, cy, r, a0, a1, n=20):
    """Points on a circle (y down), angles in degrees, counter-clockwise on screen."""
    return [(cx + r * math.cos(math.radians(a0 + (a1 - a0) * i / n)),
             cy - r * math.sin(math.radians(a0 + (a1 - a0) * i / n))) for i in range(n + 1)]


# glyphs on a 10-unit x-height, baseline y=0, y up (flipped when drawn): polylines + width
_GLYPHS = {
    "n": ([[(0, 0), (0, 10)], [(0, 5.5)] + [(x, y) for x, y in
          [(4.5 + 4.5 * math.cos(math.radians(a)), 5.5 + 4.5 * math.sin(math.radians(a)))
           for a in range(180, -1, -15)]] + [(9, 0)]], 9),
    "e": ([[(0, 5), (9, 5)] + [(4.5 + 4.5 * math.cos(math.radians(a)), 5 + 5 * math.sin(math.radians(a)))
                              for a in range(0, 321, 15)]], 9),
    "t": ([[(2.5, 14), (2.5, 2), (3.5, 0.2), (6, 0)], [(0, 10), (6, 10)]], 6),
    "w": ([[(0, 10), (2.75, 0), (5.5, 8), (8.25, 0), (11, 10)]], 11),
    "a": ([[(4.5 + 4.5 * math.cos(math.radians(a)), 5 + 5 * math.sin(math.radians(a)))
            for a in range(0, 361, 15)], [(9, 0), (9, 10)]], 9),
    "r": ([[(0, 0), (0, 10)], [(0, 5.5)] + [(4.5 + 4.5 * math.cos(math.radians(a)), 5.5 + 4.5 * math.sin(math.radians(a)))
                                           for a in range(180, 44, -15)]], 7),
    "d": ([[(4.5 + 4.5 * math.cos(math.radians(a)), 5 + 5 * math.sin(math.radians(a)))
            for a in range(0, 361, 15)], [(9, 0), (9, 15)]], 9),
}


def _word(text, x0, base, unit, gap=3.2):
    """[(segment list, x range)] for each glyph of `text` (lower case n/e/t/w/a/r/d)."""
    out, x = [], x0
    for ch in text:
        lines, w = _GLYPHS[ch]
        segs = []
        for line in lines:
            pts = [(x + gx * unit, base - gy * unit) for gx, gy in line]
            segs += list(zip(pts, pts[1:]))
        out.append(segs)
        x += (w + gap) * unit
    return out, x


def render_rgba(w: int, h: int, mark: tuple[float, float, float], words=()) -> bytes:
    """The mark (rounded square at x, y with side s) + stroked words, straight RGBA."""
    mx, my, ms = mark
    unit = ms / 32 * 0.86
    off_x, off_y = mx + ms * 0.07, my + ms * 0.07
    pts = [(off_x + x * unit, off_y + y * unit) for x, y in shield()]
    segs = list(zip(pts, pts[1:]))
    half = 2.2 / 2 * unit
    cx, cy, r = off_x + 16 * unit, off_y + 15 * unit, 2.6 * unit
    glyphs = []   # (segs, half stroke, colour, bbox)
    for segs_list, stroke, colour in words:
        for g in segs_list:
            xs = [p[0] for s in g for p in s]
            ys = [p[1] for s in g for p in s]
            glyphs.append((g, stroke / 2, colour,
                           (min(xs) - stroke, max(xs) + stroke, min(ys) - stroke, max(ys) + stroke)))
    rows = []
    for y in range(h):
        row = bytearray([0])
        for x in range(w):
            px, py = x + 0.5, y + 0.5
            rgb, a = (0, 0, 0), 0.0
            box = _rounded_cov(px, py, mx, my, ms, ms * 8 / 32) if mx - 1 <= px <= mx + ms + 1 \
                and my - 1 <= py <= my + ms + 1 else 0.0
            if box:
                d = min(_seg_dist(px, py, *p, *q) for p, q in segs)
                cov = max(0.0, min(1.0, half - d + 0.5))
                cov = max(cov, max(0.0, min(1.0, r - math.hypot(px - cx, py - cy) + 0.5)))
                rgb, a = tuple(b + (f - b) * cov for b, f in zip(BG, FG)), box
            for g, hs, colour, (gx0, gx1, gy0, gy1) in glyphs:
                if gx0 <= px <= gx1 and gy0 <= py <= gy1:
                    d = min(_seg_dist(px, py, *p, *q) for p, q in g)
                    cov = max(0.0, min(1.0, hs - d + 0.5))
                    if cov:
                        na = cov + a * (1 - cov)
                        rgb = tuple((c * cov + o * a * (1 - cov)) / na for c, o in zip(colour, rgb))
                        a = na
            row += bytes(round(v) for v in rgb) + bytes([round(a * 255)])
        rows.append(bytes(row))
    return png_rgba(w, h, b"".join(rows))


def png_rgba(w: int, h: int, raw: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + \
            struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def addon_images() -> dict[str, bytes]:
    icon = render_rgba(128, 128, (4, 4, 120))
    unit, base = 1.5, 60.0
    net, x = _word("net", 86, base, unit)
    warden, _ = _word("warden", x, base, unit)
    logo = render_rgba(250, 100, (6, 18, 64),
                       [(net, 2.0 * unit, (0x64, 0x74, 0x8B)), (warden, 2.6 * unit, BG)])
    return {"icon.png": icon, "logo.png": logo}


def main(argv=None) -> int:
    import sys
    if "--ha-addon" in (sys.argv[1:] if argv is None else argv):
        for name, body in addon_images().items():
            (ADDON / name).write_bytes(body)
            print(f"wrote ha-addon/{name}")
        return 0
    for name, size in SIZES.items():
        (STATIC / name).write_bytes(render(size))
        print(f"wrote {name} ({size}x{size})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
