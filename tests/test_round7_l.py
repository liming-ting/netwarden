"""
Round 7 stage L: licensing and provenance before publication.

Guards what the stage verified by hand (sources in THIRD_PARTY_NOTICES.md): nothing is left
"to check", no downloaded third-party data (Wireshark manuf, URLhaus) is bundled or baked
into an image, the threat feed has no key-less URLhaus address any more, the redrawn icons
stay redrawn, and the Code of Conduct keeps the official Contributor Covenant 2.1 structure.
"""
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

import netwarden

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


class Notices(unittest.TestCase):
    def test_nothing_left_unconfirmed(self):
        tpn = read("THIRD_PARTY_NOTICES.md")
        for phrase in ("Points to check", "could not be confirmed", "turns out to be copied",
                       "TODO", "TBD"):
            self.assertNotIn(phrase, tpn)
        for needle in ("https://abuse.ch/terms-of-use/", "https://urlhaus.abuse.ch/api/",
                       "Auth-Key", "COPYING", "Contributor Covenant", "Icons", "qrcodegen"):
            self.assertIn(needle, tpn)

    def test_vendored_code_keeps_its_license(self):
        head = read("netwarden/vendor/qrcodegen.py")[:2500]
        self.assertIn("Copyright (c) Project Nayuki. (MIT License)", head)
        self.assertIn("Permission is hereby granted", head)
        vendored = sorted(p.name for p in (ROOT / "netwarden" / "vendor").glob("*.py"))
        self.assertEqual(vendored, ["__init__.py", "qrcodegen.py"])   # notices list exactly this

    def test_no_foreign_license_headers(self):
        """Only the vendored file carries a third-party copyright / license header."""
        pat = re.compile(r"copyright \(c\)|SPDX-License-Identifier|all rights reserved|"
                         r"licensed under the|stackoverflow\.com/(a|questions)/|gist\.github",
                         re.IGNORECASE)
        hits = []
        for p in ROOT.rglob("*"):
            rel = p.relative_to(ROOT).as_posix()
            if (not p.is_file() or p.suffix not in {".py", ".js", ".css", ".html", ".sh", ".cmd",
                                                    ".yaml", ".yml", ".toml", ".svg"}
                    or rel.startswith(("data/", "launch/", "netwarden/vendor/", ".claude/"))
                    or "__pycache__" in rel or rel == "tests/test_round7_l.py"):
                continue
            # the project's OWN notice (round 8, netwarden.COPYRIGHT) is not a foreign header
            text = p.read_text(encoding="utf-8", errors="ignore").replace(netwarden.COPYRIGHT, "")
            if pat.search(text):
                hits.append(rel)
        self.assertEqual(hits, [])


class DownloadedDataStaysOut(unittest.TestCase):
    def test_no_downloaded_lists_in_the_tree(self):
        names = re.compile(r"(^manuf(\.txt|\.gz)?$|^oui\.(csv|txt)$|hostfile|^threatfeed\.json$)",
                           re.IGNORECASE)
        found = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                 if p.is_file() and names.search(p.name)
                 and not p.relative_to(ROOT).as_posix().startswith(("data/", "launch/"))]
        self.assertEqual(found, [])

    def test_caches_live_outside_the_package(self):
        from netwarden import discovery, threatintel
        pkg = (ROOT / "netwarden").resolve()
        for path in (discovery.MANUF_CACHE, threatintel.CACHE):
            self.assertNotIn(pkg, Path(path).resolve().parents)

    def test_images_never_download_at_build_time(self):
        docker = read("Dockerfile")
        for line in docker.splitlines():
            if line.lstrip().startswith("RUN"):
                for bad in ("update-vendors", "threatintel", "manuf", "urlhaus", "curl", "wget"):
                    self.assertNotIn(bad, line.lower())
        self.assertIn("HOME=/data", docker)            # runtime downloads land in the volume
        copies = [l.split()[1:-1] for l in docker.splitlines() if l.startswith("COPY")]
        # round 8: + the license text and the notices (pyproject license-files, in the image)
        self.assertEqual(sorted(sum(copies, [])), ["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md",
                                                   "netwarden", "pyproject.toml"])
        for f in (".dockerignore", ".gitignore"):
            text = read(f)
            for pattern in ("data/", ".cache/"):
                self.assertIn(pattern, text, f)

    def test_threat_feed_has_no_keyless_urlhaus_default(self):
        from netwarden import threatintel
        src = read("netwarden/threatintel.py")
        self.assertNotIn("urlhaus.abuse.ch/downloads/hostfile", src)
        self.assertFalse(hasattr(threatintel, "DEFAULT_FEED_URL"))


class Icons(unittest.TestCase):
    """The sprite is drawn for netwarden. These path fragments followed Feather / Lucide
    drawings too closely and were redrawn in stage L: they must not come back."""

    LOOKALIKES = ("M10.6 5.1A10 10 0 0 1 12 5", "M6.6 6.6A17 17 0 0 0 2 12",   # eye-off
                  "M4.9 4.9l1.4 1.4", "M17.7 6.3l1.4-1.4",                       # sun rays
                  "M3 12h4l3-8 4 16 3-8h4",                                       # pulse
                  "M14 4h6v6M10 20H4v-6M20 4l-7 7",                               # expand
                  "M4 18a9 9 0 1 1 16 0",                                         # gauge
                  "M6 10h.01M9.5 10h.01",                                         # keyboard
                  "M2.5 9a14 14 0 0 1 19 0",                                      # wifi
                  "M20 14.5A8 8 0 0 1 9.5 4")                                     # moon

    def test_redrawn_icons_stay_redrawn(self):
        page = read("netwarden/static/index.html")
        for frag in self.LOOKALIKES:
            self.assertNotIn(frag, page)
        for name in ("lucide", "feather", "heroicons", "fontawesome", "font awesome", "tabler",
                     "bootstrap-icons", "material-icons", "material symbols"):
            self.assertNotIn(name, page.lower())

    def test_sprite_symbols_are_well_formed(self):
        class P(HTMLParser):
            def __init__(self):
                super().__init__()
                self.symbols, self.cur = {}, None

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "symbol":
                    self.cur = a.get("id")
                    self.symbols[self.cur] = {"viewBox": a.get("viewbox"), "shapes": 0}
                elif self.cur and tag in ("path", "circle", "rect"):
                    self.symbols[self.cur]["shapes"] += 1

            def handle_endtag(self, tag):
                if tag == "symbol":
                    self.cur = None
        p = P()
        p.feed(read("netwarden/static/index.html"))
        self.assertGreater(len(p.symbols), 50)
        for sid, info in p.symbols.items():
            self.assertEqual(info["viewBox"], "0 0 24 24", sid)
            self.assertGreater(info["shapes"], 0, sid)
        used = set(re.findall(r"icon\('([it]-[a-z-]+)'", read("netwarden/static/app.js")))
        self.assertEqual(sorted(used - set(p.symbols)), [])     # no reference to a lost icon


class CodeOfConduct(unittest.TestCase):
    def test_official_structure_and_own_contact(self):
        coc = read("CODE_OF_CONDUCT.md")
        headings = re.findall(r"^#{1,3} (.+)$", coc, re.MULTILINE)
        self.assertEqual(headings, [
            "Contributor Covenant Code of Conduct", "Our Pledge", "Our Standards",
            "Enforcement Responsibilities", "Scope", "Enforcement", "Enforcement Guidelines",
            "1. Correction", "2. Warning", "3. Temporary Ban", "4. Permanent Ban", "Attribution"])
        self.assertNotIn("[INSERT CONTACT METHOD]", coc)
        self.assertIn("https://github.com/liming-ting/netwarden/security/advisories/new", coc)
        self.assertIn("[v2.1]: https://www.contributor-covenant.org/version/2/1/code_of_conduct.html",
                      coc)
        self.assertIn("[Mozilla CoC]: https://github.com/mozilla/diversity", coc)


if __name__ == "__main__":
    unittest.main()
