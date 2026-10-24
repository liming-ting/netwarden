"""
CI1: time-zone coverage, so the first CI failures (tests that assumed Taipei or a time of
day) cannot come back: the developer sweep script (scripts/dev/tz_sweep.sh), the CI jobs
that run the suite in more than one zone, and the docs that point at both.

The product fixes have their tests next to the code they touch: test_d2_units (TZ),
test_stage_q (quiet hours in every zone), test_cli (a new local day reshuffles nothing),
test_stage_t (since).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SWEEP = ROOT / "scripts" / "dev" / "tz_sweep.sh"
ZONES = ("UTC", "Asia/Taipei", "America/Los_Angeles", "Asia/Kolkata", "Pacific/Auckland")


class SweepScript(unittest.TestCase):
    def test_shape(self):
        data = SWEEP.read_bytes()
        self.assertTrue(data.startswith(b"#!/usr/bin/env bash\n"))
        self.assertNotIn(b"\r", data)
        text = data.decode()
        self.assertIn("set -u", text)
        self.assertIn('TZ="$zone" NETWARDEN_TZ="$zone"', text)    # a local .env cannot win
        for zone in ZONES:
            self.assertIn(zone, text)

    @unittest.skipUnless(shutil.which("bash") and os.name == "posix", "needs bash")
    def test_runs_every_zone_and_reports_the_failing_ones(self):
        with tempfile.TemporaryDirectory() as t:
            fake = Path(t) / "fakepy"
            # stands in for python3: shows what it got, fails in Kolkata only
            fake.write_text("#!/bin/sh\necho \"zone=$TZ nw=$NETWARDEN_TZ args=$*\"\n"
                            "[ \"$TZ\" != Asia/Kolkata ]\n")
            fake.chmod(0o755)
            env = {**os.environ, "PYTHON": str(fake), "TESTS": "tests.test_a tests.test_b"}
            r = subprocess.run(["bash", str(SWEEP), "UTC", "Asia/Kolkata", "Pacific/Auckland"],
                               env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            for zone in ("UTC", "Asia/Kolkata", "Pacific/Auckland"):
                self.assertIn(f"zone={zone} nw={zone} args=-m unittest tests.test_a tests.test_b",
                              r.stdout)
            self.assertIn("FAILED in: Asia/Kolkata", r.stdout)
            env.pop("TESTS")
            r = subprocess.run(["bash", str(SWEEP), "UTC"], env=env, capture_output=True,
                               text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("args=-m unittest discover -s tests", r.stdout)
            self.assertIn("OK in all 1 zones", r.stdout)


class Workflow(unittest.TestCase):
    def setUp(self):
        self.ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_the_suite_runs_in_two_zones_and_the_sensitive_modules_in_two_more(self):
        self.assertIn("TZ: ${{ matrix.python == '3.11' && 'UTC' || 'Asia/Taipei' }}", self.ci)
        job = self.ci.split("\n  tz:\n", 1)[1].split("\n\n  ", 1)[0]
        self.assertIn("run: bash scripts/dev/tz_sweep.sh America/Los_Angeles Pacific/Auckland", job)
        self.assertIn("timeout-minutes:", job)
        mods = re.search(r"TESTS: >-\n((?:\s{8}.+\n)+)", job).group(1).split()
        self.assertGreaterEqual(len(mods), 6)
        for m in mods:
            self.assertTrue((ROOT / (m.replace(".", "/") + ".py")).is_file(), m)
        for m in ("tests.test_cli", "tests.test_stage_q", "tests.test_stage_t"):   # the CI1 three
            self.assertIn(m, mods)


class Docs(unittest.TestCase):
    def test_contributing_names_the_sweep(self):
        for name in ("CONTRIBUTING.md",) + (("CONTRIBUTING.zh-TW.md",)
                                             if (ROOT / "CONTRIBUTING.zh-TW.md").exists() else ()):
            self.assertIn("scripts/dev/tz_sweep.sh", (ROOT / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    sys.exit(unittest.main())
