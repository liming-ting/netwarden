"""
netwarden - qr.py: QR codes for phone pairing, drawn without any dependency.

The encoder is Project Nayuki's QR Code generator (MIT), vendored unchanged as
netwarden/vendor/qrcodegen.py. This module only turns its module grid into:

    matrix(text)      -> list of rows of bools (True = dark), no quiet zone
    svg(text)         -> a small standalone SVG (one <path>), drawn server-side
    data_uri(text)    -> that SVG as data:image/svg+xml;base64,... (the page shows it in
                         an <img>: CSP img-src allows data:, nothing is inserted as markup)
    terminal(text)    -> Unicode half blocks for `python3 -m netwarden pair`

The text is a pairing URL; it never goes anywhere but this server's own response.
"""
from __future__ import annotations

import base64

from netwarden.vendor.qrcodegen import QrCode

QUIET = 4        # the standard quiet zone, in modules
MAX_TEXT = 512   # a pairing URL is ~40 characters; refuse anything absurd


def encode(text: str) -> QrCode:
    if not isinstance(text, str) or not text or len(text) > MAX_TEXT:
        raise ValueError("bad QR text")
    # MEDIUM recovers from ~15 % damage: plenty for a screen, keeps the symbol small
    return QrCode.encode_text(text, QrCode.Ecc.MEDIUM)


def matrix(text: str) -> list[list[bool]]:
    q = encode(text)
    n = q.get_size()
    return [[q.get_module(x, y) for x in range(n)] for y in range(n)]


def svg(text: str, dark: str = "#000", light: str = "#fff") -> str:
    """One <path> of 1x1 squares on a light background, quiet zone included. Scales
    crisply to any size (shape-rendering crispEdges)."""
    m = matrix(text)
    n = len(m) + 2 * QUIET
    parts = [f"M{x + QUIET},{y + QUIET}h1v1h-1z"
             for y, row in enumerate(m) for x, on in enumerate(row) if on]
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" '
            f'shape-rendering="crispEdges"><rect width="{n}" height="{n}" fill="{light}"/>'
            f'<path d="{"".join(parts)}" fill="{dark}"/></svg>')


def data_uri(text: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(svg(text).encode()).decode()


def terminal(text: str, invert: bool = False) -> str:
    """Two module rows per text line with ▀ ▄ █. By default the LIGHT modules are drawn
    (white-ish blocks), which scans on the usual dark terminal; invert=True draws the
    dark modules instead (for a light terminal background)."""
    m = matrix(text)
    size = len(m) + 2 * QUIET

    def light(x, y):
        x, y = x - QUIET, y - QUIET
        on = 0 <= y < len(m) and 0 <= x < len(m) and m[y][x]
        return on if invert else not on

    glyph = {(True, True): "█", (True, False): "▀", (False, True): "▄", (False, False): " "}
    lines = []
    for y in range(0, size, 2):
        lines.append("".join(glyph[(light(x, y), y + 1 < size and light(x, y + 1))]
                             for x in range(size)))
    return "\n".join(lines)
