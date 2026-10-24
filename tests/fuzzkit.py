"""
Stage K: a tiny deterministic fuzzing kit (stdlib only) shared by the hardening tests.

Every generator takes a random.Random, so a failure is reproducible from its seed. The
normal suite runs a few hundred cases per target (fast); NETWARDEN_FUZZ=heavy (or a
number: cases per target) runs many more:

    NETWARDEN_FUZZ=heavy python3 -m unittest discover -s tests -p 'test_stage_k_*.py'

(`discover -s tests` puts tests/ on sys.path, which `import fuzzkit` needs; naming the
modules as tests.test_stage_k_fuzz does not, and fails with ModuleNotFoundError.)
"""
from __future__ import annotations

import math
import os
import random

SEED = 20261023


def cases(normal: int) -> int:
    """How many cases per target: `normal` in the regular suite, more with NETWARDEN_FUZZ."""
    want = (os.environ.get("NETWARDEN_FUZZ") or "").strip().lower()
    if want == "heavy":
        return normal * 40
    if want.isdigit():
        return int(want)
    return normal


def rng(name: str) -> random.Random:
    """One generator per target, seeded from SEED + the target's name (stable order)."""
    return random.Random(f"{SEED}:{name}")


# Adversarial strings: control characters, lone surrogates (sqlite / utf-8 can't encode
# them), RTL overrides, path tricks, markup, formula injection, SQL, huge, look-alike digits.
NASTY_STRINGS = (
    "", " ", "\x00", "\x00abc", "\n\r\t", "\ud800", "a\udfffb", "‮‭", "﻿",
    "../../etc/passwd", "..\\..\\windows", "/etc/passwd", "%2e%2e%2f", "file:///etc/passwd",
    "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "{{7*7}}", "${jndi:x}",
    "=cmd|' /C calc'!A0", "+1+1", "@SUM(1)", "-1", "'; DROP TABLE devices; --", "\" OR 1=1 --",
    "１２３", "²", "٣", "1e309", "NaN", "Infinity", "-0", "0x10", "9" * 400, "aa:bb:cc:dd:ee:ff",
    "AA:BB:CC:DD:EE:FF", "network", "port:23", "outage:1", "bedtime:1:2026-10-22",
    "2026-02-30", "2026-13-01T25:61:61Z", "0000-00-00", "9999-12-31T23:59:59Z", "1970-01-01",
    "24:00", "23:59", "-1:00", "7:5", "😀" * 50, "ｚｈ-Ｈａｎｔ", "zh-Hant", "en", "xx",
    "a" * 5000, "名" * 3000,
)
NASTY_NUMBERS = (0, -1, 1, 2, 7, 23, 24, 59, 60, 61, 255, 256, 65535, 65536, 2 ** 31,
                 2 ** 53 + 1, 2 ** 63 - 1, 2 ** 63, 2 ** 64, -(2 ** 63) - 1, 10 ** 30,
                 0.5, -0.0, 1e308, -1e308, 1e-308, math.inf, -math.inf, math.nan)


def string(r: random.Random) -> str:
    pick = r.random()
    if pick < 0.55:
        return r.choice(NASTY_STRINGS)
    if pick < 0.8:   # random code points, surrogates and controls included
        return "".join(chr(r.choice((r.randrange(0, 0x80), r.randrange(0, 0x110000),
                                     r.randrange(0xD800, 0xE000))))
                       for _ in range(r.randrange(0, 40)))
    return r.choice(NASTY_STRINGS) + r.choice(NASTY_STRINGS)


def number(r: random.Random):
    return r.choice(NASTY_NUMBERS) if r.random() < 0.8 else r.uniform(-1e6, 1e6)


def value(r: random.Random, depth: int = 0):
    """Any JSON-ish value (plus NaN / Infinity, which Python's json emits and accepts)."""
    kinds = ["none", "bool", "num", "str", "str", "list", "dict"] if depth < 3 else \
        ["none", "bool", "num", "str"]
    kind = r.choice(kinds)
    if kind == "none":
        return None
    if kind == "bool":
        return r.random() < 0.5
    if kind == "num":
        return number(r)
    if kind == "str":
        return string(r)
    if kind == "list":
        return [value(r, depth + 1) for _ in range(r.randrange(0, 5))]
    return {string(r)[:20]: value(r, depth + 1) for _ in range(r.randrange(0, 5))}


def deep(n: int = 5000, kind: str = "list") -> str:
    """JSON text nested `n` levels deep (a RecursionError for naive parsers)."""
    return ("[" * n + "]" * n) if kind == "list" else ('{"a":' * n + "1" + "}" * n)


def mutate(r: random.Random, sample: dict, fields=None) -> dict:
    """A copy of a valid payload with some fields replaced, dropped, or junk added."""
    out = dict(sample)
    keys = list(fields or sample) or ["x"]
    for _ in range(r.randrange(1, 4)):
        k = r.choice(keys)
        op = r.random()
        if op < 0.6:
            out[k] = value(r)
        elif op < 0.8:
            out.pop(k, None)
        else:
            out[string(r)[:30]] = value(r)
    return out


def payload(r: random.Random, sample: dict | None = None, fields=None) -> dict:
    """A POST body: a mutated valid sample most of the time, else random junk."""
    if sample is not None and r.random() < 0.7:
        return mutate(r, sample, fields)
    return {string(r)[:20]: value(r) for _ in range(r.randrange(0, 6))}


def blob(r: random.Random, sample: bytes = b"") -> bytes:
    """Hostile bytes: a truncated / bit-flipped / spliced valid sample or random noise."""
    pick = r.random()
    if sample and pick < 0.35:
        return sample[:r.randrange(0, len(sample) + 1)]
    if sample and pick < 0.7:
        b = bytearray(sample)
        for _ in range(r.randrange(1, 8)):
            if b:
                b[r.randrange(len(b))] = r.randrange(256)
        return bytes(b)
    if sample and pick < 0.85:
        cut = r.randrange(0, len(sample) + 1)
        return sample[:cut] + bytes(r.randrange(256) for _ in range(r.randrange(0, 64))) + sample[cut:]
    return bytes(r.randrange(256) for _ in range(r.randrange(0, 600)))
