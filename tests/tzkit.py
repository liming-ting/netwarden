"""
CI1: pin the local time zone inside a test (stdlib only).

The product reads its zone from NETWARDEN_TZ (env > .env > the time.timezone setting),
then TZ / /etc/localtime (activity.local_tz). A test whose expectation is written in one
zone - "quiet hours 23:00-07:00 Taipei" - pins that zone here, so it passes the same on a
developer machine (whose .env may pin a zone) and on CI (TZ=UTC, no .env), at any hour.

    from tzkit import pinned_tz
    with pinned_tz("Asia/Taipei"): ...
    self.enterContext(pinned_tz("Asia/Taipei"))   # in setUp: for one test method

(Importing modules add tests/ to sys.path first, like ingress_proxy, so both `discover -s
tests` and `python3 -m unittest tests.test_cli` find it.)
"""
from __future__ import annotations

import contextlib
import os
import time

from netwarden import activity, cache

_KEYS = ("TZ", "NETWARDEN_TZ")


@contextlib.contextmanager
def pinned_tz(name: str):
    """NETWARDEN_TZ and TZ = `name` (time.tzset() too, so naive local times agree) and no
    time.timezone setting; everything restored afterwards. Cached results computed in the
    other zone are dropped on the way in and out."""
    old = {k: os.environ.get(k) for k in _KEYS}
    old_setting = activity.SETTING_TZ
    try:
        for k in _KEYS:
            os.environ[k] = name
        activity.SETTING_TZ = None
        _tzset()
        cache.clear()
        yield activity.local_tz()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        activity.SETTING_TZ = old_setting
        _tzset()
        cache.clear()


def _tzset() -> None:
    if hasattr(time, "tzset"):   # not on Windows (the suite runs on Linux/macOS/WSL)
        time.tzset()
