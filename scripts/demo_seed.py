#!/usr/bin/env python3
"""
netwarden - demo data seeder (thin wrapper; the seeder lives in netwarden/demo.py so
`python3 -m netwarden demo` works from an installed package too).

    python3 scripts/demo_seed.py            # (re)write data/demo.db
    python3 scripts/demo_seed.py --db x.db  # another (demo or empty) DB
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netwarden.demo import *  # noqa: E402,F401,F403  (DEVICES, TRAFFIC, build, ...)
from netwarden.demo import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
