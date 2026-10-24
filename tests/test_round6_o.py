"""Round 6, stage O: what a public repository would contain, and that it is fit to publish.

- the publication set = every file .gitignore does not exclude (a small matcher for the
  patterns this repo uses - no git needed, the checkout is not a repository);
- nothing private in it: machine paths, e-mail addresses, CGNAT/Tailscale addresses,
  key-like strings, private keys (the owner's own LAN values are checked by hand at
  release time - listing them here would publish them);
- docs: every relative Markdown link resolves, user docs vs docs/dev/, both READMEs;
- community files, issue templates, CI workflow and pyproject metadata agree.
"""
import fnmatch
import ipaddress
import re
import tomllib
import unittest
from pathlib import Path

from netwarden import devicetype, i18n, services

ROOT = Path(__file__).resolve().parent.parent


# --- the publication set ---------------------------------------------------------------

def _patterns():
    out = []
    for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def ignored(rel: str, patterns=None) -> bool:
    """git-like: a pattern ending in "/" matches a directory name anywhere on the path, a
    pattern without "/" matches any path component, "!" re-includes; the last match wins."""
    patterns = _patterns() if patterns is None else patterns
    parts = rel.split("/")
    result = False
    for pat in patterns:
        neg = pat.startswith("!")
        p = pat[1:] if neg else pat
        if p.endswith("/"):
            hit = any(fnmatch.fnmatchcase(c, p[:-1]) for c in parts[:-1])
        elif "/" in p.strip("/"):
            hit = fnmatch.fnmatchcase(rel, p.strip("/")) or rel.startswith(p.strip("/") + "/")
        else:
            hit = any(fnmatch.fnmatchcase(c, p) for c in parts)
        if hit:
            result = not neg
    return result


def publication_set():
    pats = _patterns()
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(".git/") or ignored(rel, pats):
            continue
        files.append(rel)
    return sorted(files)


PUBLISHED = publication_set()
TEXT_SUFFIXES = {".py", ".md", ".json", ".js", ".css", ".html", ".txt", ".yaml", ".yml",
                 ".toml", ".sh", ".cmd", ".sql", ".svg", ".webmanifest", ".example", ""}


def _texts():
    for rel in PUBLISHED:
        if Path(rel).suffix not in TEXT_SUFFIXES:
            continue
        try:
            yield rel, (ROOT / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue


class PublicationSet(unittest.TestCase):
    def test_gitignore_keeps_private_and_generated_files_out(self):
        for rel in (".env", ".env.local", "data/netwarden.db", "data/demo.db-wal", "x.db-shm",
                    "x.db-journal", "launch/release_checklist.md", "CLAUDE.local.md",
                    "netwarden/__pycache__/web.cpython-312.pyc", ".pytest_cache/v/x",
                    "backups/2026.json", "netwarden-backup-2026-10-01.json", "release.tgz",
                    "data/netwarden.log", ".vscode/settings.json", ".idea/x.xml", "a.py.swp"):
            self.assertTrue(ignored(rel), rel)
        for rel in ("README.md", "CLAUDE.md", "netwarden/web.py", "deploy/netwarden.env.example",
                    "tests/fixtures/legacy_pre_round2.sql", "docs/images/devices-desktop.png",
                    ".github/workflows/ci.yml"):
            self.assertFalse(ignored(rel), rel)

    def test_set_contains_the_product_and_no_generated_files(self):
        for rel in ("README.md", "README.zh-TW.md", "pyproject.toml", "netwarden/__main__.py",
                    "netwarden/locales/zh-Hant.json", "netwarden/vendor/qrcodegen.py",
                    "THIRD_PARTY_NOTICES.md", ".github/workflows/ci.yml"):
            self.assertIn(rel, PUBLISHED)
        for rel in PUBLISHED:
            self.assertFalse(re.search(r"\.(db|sqlite3?|pyc|log|tgz)$|-(wal|shm|journal)$", rel), rel)
            self.assertFalse(rel.startswith(("data/", "launch/")), rel)
            self.assertNotEqual(rel, ".env")


class NothingPrivate(unittest.TestCase):
    HOME_PATH = re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/]|/mnt/[a-z]/users/|(?<![\w.])/c/users/|"
                           r"/home/(?!user/|pi/|<)[a-z_][\w.-]*/")
    EMAIL = re.compile(r"(?<![:\w.%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
    OK_EMAIL_DOMAINS = re.compile(r"(^|\.)(example(\.com|\.org|\.net)?|invalid|test|localhost)$", re.I)
    KEYISH = re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{40,}|gh[pousr]_[A-Za-z0-9]{30,}|"
                        r"AKIA[0-9A-Z]{16}|xox[abp]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
    IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
    CGNAT = ipaddress.ip_network("100.64.0.0/10")
    CGNAT_EXAMPLES = ipaddress.ip_network("100.64.0.0/16")   # neutral range examples only

    def test_no_machine_paths_emails_keys_or_tailscale_addresses(self):
        bad = []
        for rel, text in _texts():
            if rel == "tests/test_round6_o.py":      # this file's own scanner self-test samples
                continue
            for no, line in enumerate(text.splitlines(), 1):
                if self.HOME_PATH.search(line):
                    bad.append((rel, no, "home path"))
                for m in self.EMAIL.finditer(line):
                    if not self.OK_EMAIL_DOMAINS.search(m.group(1)) and "noreply" not in m.group(0):
                        bad.append((rel, no, "e-mail address"))
                if self.KEYISH.search(line):
                    bad.append((rel, no, "key-like string"))
                for m in self.IPV4.finditer(line):
                    try:
                        a = ipaddress.ip_address(m.group(1))
                    except ValueError:
                        continue
                    if a in self.CGNAT and a not in self.CGNAT_EXAMPLES:
                        bad.append((rel, no, "CGNAT / Tailscale address"))
        self.assertEqual(bad, [])   # file, line, category - never the value itself

    @staticmethod
    def owner_networks(text):
        """/24 networks of the private addresses a machine-local note names (the owner's
        LAN), minus the neutral example ranges the docs use on purpose."""
        examples = [ipaddress.ip_network(n) for n in ("192.168.1.0/24", "172.30.32.0/23")]
        nets = set()
        for m in NothingPrivate.IPV4.finditer(text):
            try:
                a = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if a.is_private and not a.is_loopback and not any(a in n for n in examples):
                nets.add(ipaddress.ip_network(f"{a}/24", strict=False))
        return nets

    @unittest.skipUnless((ROOT / "CLAUDE.local.md").exists(), "no machine-local notes here")
    def test_no_address_from_the_owners_own_lan(self):
        """The owner's LAN is read from the gitignored machine notes at test time, so the
        values themselves never have to be written into a published file."""
        nets = self.owner_networks((ROOT / "CLAUDE.local.md").read_text(encoding="utf-8"))
        bad = []
        for rel, text in _texts():
            for no, line in enumerate(text.splitlines(), 1):
                for m in self.IPV4.finditer(line):
                    try:
                        a = ipaddress.ip_address(m.group(1))
                    except ValueError:
                        continue
                    if any(a in n for n in nets):
                        bad.append((rel, no))
        self.assertEqual(bad, [])   # file, line - never the value itself

    def test_the_scanner_catches_what_it_should(self):
        nets = self.owner_networks("LAN 10.20.30.0/24, gw 10.20.30.1; demo 192.168.1.5; 127.0.0.1")
        self.assertEqual(nets, {ipaddress.ip_network("10.20.30.0/24")})
        self.assertTrue(self.HOME_PATH.search(r"see C:\Users\someone\proj"))
        self.assertTrue(self.HOME_PATH.search("cd /mnt/c/Users/someone/proj"))
        self.assertTrue(self.HOME_PATH.search("/home/someone/.local/bin"))
        self.assertFalse(self.HOME_PATH.search("/home/user/x.py and ~/.local/share/netwarden"))
        m = self.EMAIL.search("mail jane.doe@gmail.com now")
        self.assertTrue(m and not self.OK_EMAIL_DOMAINS.search(m.group(1)))
        self.assertTrue(self.OK_EMAIL_DOMAINS.search(self.EMAIL.search("secret@dns.example").group(1)))
        self.assertIsNone(self.EMAIL.search("http://admin:pw@pihole.lan/"))    # userinfo, not mail
        self.assertTrue(self.KEYISH.search("sk-ant-api03-" + "A1b2" * 12))
        self.assertFalse(self.KEYISH.search("sk-ant-test-0123456789abcdef"))
        self.assertIn(ipaddress.ip_address("100.101.102.103"), self.CGNAT)
        self.assertNotIn(ipaddress.ip_address("100.101.102.103"), self.CGNAT_EXAMPLES)

    def test_screenshots_are_small_pngs_used_by_the_readmes(self):
        shots = sorted(p for p in PUBLISHED if p.startswith("docs/images/"))
        self.assertGreaterEqual(len(shots), 3)
        readmes = (ROOT / "README.md").read_text(encoding="utf-8") + \
            (ROOT / "README.zh-TW.md").read_text(encoding="utf-8")
        for rel in shots:
            data = (ROOT / rel).read_bytes()
            self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"), rel)
            self.assertLess(len(data), 300_000, rel)
            self.assertNotIn(b"tEXt", data[:4096], rel)       # no embedded text metadata
            self.assertIn(rel, readmes)


# --- docs ---------------------------------------------------------------------------------

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


class Docs(unittest.TestCase):
    def test_every_relative_markdown_link_resolves(self):
        broken = []
        for rel in PUBLISHED:
            if not rel.endswith(".md"):
                continue
            text = (ROOT / rel).read_text(encoding="utf-8")
            for target in LINK.findall(text):
                if re.match(r"[a-z]+:", target) or target.startswith("#"):
                    continue
                path = target.split("#", 1)[0]
                if not (ROOT / rel).parent.joinpath(path).exists():
                    broken.append((rel, target))
        self.assertEqual(broken, [])

    def test_internal_notes_live_in_docs_dev(self):
        for name in ("stages", "stagex", "stage_t", "stageq", "stagev3", "usability",
                     "accessibility", "hardening", "ai_tools", "ha_addon", "bandwidth_investigation"):
            self.assertFalse((ROOT / "docs" / f"{name}.md").exists(), name)
            self.assertTrue((ROOT / "docs" / "dev" / f"{name}.md").exists(), name)
        for name in ("install", "home_assistant", "bandwidth", "pihole"):
            self.assertTrue((ROOT / "docs" / f"{name}.md").exists())
            self.assertTrue((ROOT / "docs" / f"{name}.zh-TW.md").exists())

    def test_ui_hints_point_at_existing_docs(self):
        # locale strings and CLI hints tell users to read docs/<x>.md: that file must exist
        for code in i18n.CODES:
            for key, value in i18n.strings(code).items():
                for doc in re.findall(r"docs/[\w./-]+\.md", str(value)):
                    self.assertTrue((ROOT / doc).exists(), (code, key, doc))

    def test_readmes(self):
        en = (ROOT / "README.md").read_text(encoding="utf-8")
        zh = (ROOT / "README.zh-TW.md").read_text(encoding="utf-8")
        self.assertIn("(README.zh-TW.md)", en)
        self.assertIn("(README.md)", zh)
        for text in (en, zh):
            for needle in ("AGPL-3.0-or-later", "Claude Code", "liming-ting/netwarden", "deploy/compose.yaml",
                           "scripts/install_linux.sh", "--offline-ai", "SECURITY.md", "CONTRIBUTING.md"):
                self.assertIn(needle, text)
        for needle in ("machine-assisted", "read-only", "No telemetry", "Redaction", "WSL"):
            self.assertIn(needle.lower(), en.lower())
        self.assertIn("機器輔助", zh)
        self.assertIn("唯讀", zh)


# --- community files, templates, CI, packaging ----------------------------------------------

class CommunityFiles(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_files_exist_and_say_the_right_things(self):
        sec = self.read("SECURITY.md")
        self.assertIn("https://github.com/liming-ting/netwarden/security/advisories/new", sec)
        self.assertIn("Supported versions", sec)
        coc = self.read("CODE_OF_CONDUCT.md")
        self.assertIn("Contributor Covenant", coc)
        self.assertIn("version 2.1", coc)
        self.assertIn("security/advisories/new", coc)
        self.assertIsNone(NothingPrivate.EMAIL.search(coc))       # no personal e-mail contact
        con = self.read("CONTRIBUTING.md")
        for needle in ("python3 -m unittest discover -s tests", "node tests/js/map_layout_test.js",
                       "python3 -m netwarden.i18n --check", "Zero runtime dependencies", "12"):
            self.assertIn(needle, con)
        tpn = self.read("THIRD_PARTY_NOTICES.md")
        for needle in ("qrcodegen", "MIT", "manuf", "GPL-2.0-or-later", "URLhaus", "TRACKERS"):
            self.assertIn(needle, tpn)
        log = self.read("CHANGELOG.md")
        self.assertIn("Keep a Changelog", log)
        self.assertRegex(log, r"## \[0\.1\.0\]")
        import netwarden
        self.assertIn(f"[{netwarden.__version__}]", log)

    def test_issue_and_pr_templates(self):
        bug = self.read(".github/ISSUE_TEMPLATE/bug_report.yml")
        for field in ("id: install", "id: version", "id: os", "id: dns", "id: ai"):
            self.assertIn(field, bug)
        for option in ("Docker compose", "Home Assistant add-on", "AdGuard Home", "Pi-hole v6", "Offline"):
            self.assertIn(option, bug)
        self.assertIn("feature", self.read(".github/ISSUE_TEMPLATE/feature_request.yml").lower())
        cfg = self.read(".github/ISSUE_TEMPLATE/config.yml")
        self.assertIn("SECURITY.md", cfg)
        self.assertIn("security/advisories/new", cfg)
        self.assertIn("i18n --check", self.read(".github/PULL_REQUEST_TEMPLATE.md"))
        dep = self.read(".github/dependabot.yml")
        self.assertIn('package-ecosystem: "github-actions"', dep)
        self.assertNotIn('package-ecosystem: "pip"', dep)       # zero runtime dependencies


class CI(unittest.TestCase):
    def setUp(self):
        self.wf = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    def matrix(self):
        # round 8: `python: ${{ fromJSON(<tag/manual> && '[full]' || '[bounds]') }}` - the
        # longest list is the full matrix, the other one its oldest + newest entries
        line = re.search(r"(?m)^\s*python:\s*(.+)$", self.wf).group(1)
        lists = [[v.strip().strip('"\'') for v in m.split(",")]
                 for m in re.findall(r"\[([^\]]+)\]", line)]
        full = max(lists, key=len)
        for short in lists:
            self.assertEqual(short, full if short == full else [full[0], full[-1]])
        return full

    def test_matrix_starts_at_requires_python(self):
        versions = self.matrix()
        floor = re.match(r">=\s*(\d+\.\d+)$", self.meta["requires-python"]).group(1)
        self.assertEqual(versions[0], floor)
        minors = [int(v.split(".")[1]) for v in versions]
        self.assertEqual(minors, list(range(minors[0], minors[0] + len(minors))))   # no gaps
        for v in versions:     # every tested version is also declared
            self.assertIn(f"Programming Language :: Python :: {v}", self.meta["classifiers"])

    def test_workflow_runs_everything_with_least_privilege(self):
        for needle in ("on:\n  push:\n    branches: [main]\n    tags: [\"v*\"]\n  pull_request:",
                       "permissions:\n  contents: read",
                       "concurrency:", "cancel-in-progress: true", "actions/setup-python@",
                       "actions/setup-node@", "python3 -m unittest discover -s tests",
                       "node tests/js/map_layout_test.js", "python3 -m netwarden.i18n --check",
                       "python3 -m compileall -q netwarden", "persist-credentials: false",
                       "TZ: ${{ matrix.python == '3.11' && 'UTC' || 'Asia/Taipei' }}"):
            self.assertIn(needle, self.wf)
        self.assertNotIn("secrets.", self.wf)
        self.assertNotIn("OWNER", self.wf)
        self.assertNotIn("write", self.wf)

    def test_pyproject_metadata(self):
        self.assertEqual(self.meta["license"], "AGPL-3.0-or-later")        # PEP 639
        self.assertEqual(self.meta["readme"], "README.md")
        for key in ("Homepage", "Issues", "Changelog", "Documentation", "Security"):
            self.assertTrue(self.meta["urls"][key].startswith("https://github.com/liming-ting/netwarden"), key)
        self.assertGreaterEqual(len(self.meta["keywords"]), 5)
        self.assertIn("plain language", self.meta["description"])
        self.assertEqual(self.meta["scripts"]["netwarden"], "netwarden.__main__:main")


class RouterService(unittest.TestCase):
    """The router's own admin/cloud domains: one templated service ("{brand} router")."""

    def test_templated_router_service(self):
        self.assertEqual(services.lookup("tplinkwifi.net"), ("svc.router|TP-Link", "network"))
        self.assertEqual(services.lookup("www.routerlogin.net")[0], "svc.router|NETGEAR")
        self.assertEqual(services.service_name("svc.router|ASUS", "en"), "ASUS router")
        self.assertEqual(services.service_name("svc.router|TP-Link", "zh-Hant"), "TP-Link 路由器")
        for code in i18n.CODES:
            text = services.service_name("svc.router|X1", code)
            self.assertIn("X1", text)
            self.assertNotIn("{", text)
        self.assertEqual(devicetype.SERVICE_TEMPLATE_RULES["svc.router"], "network")


if __name__ == "__main__":
    unittest.main()
