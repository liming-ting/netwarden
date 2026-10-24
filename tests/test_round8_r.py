"""Round 8, stage R: the repository is ready for its first push to GitHub.

- no placeholder (OWNER/REPO, @LICENSE@, `maintainer: OWNER`) is left in the publication set;
  every GitHub URL of the project points at liming-ting/netwarden and every ghcr.io image
  is lower case under liming-ting;
- the license: LICENSE is the verbatim AGPL v3 text (pinned hash), PEP 639 metadata in
  pyproject, README / CONTRIBUTING / notices say it in plain words, both images carry it;
- one source link (netwarden.SOURCE_URL): Settings > About, `--version`, /api/meta;
- line endings (.gitattributes + the bytes of every file) and executable bits;
- CI: least privilege, image pushes only from v* tags, a small matrix on normal pushes.
"""
import contextlib
import fnmatch
import hashlib
import http.client
import io
import json
import re
import tempfile
import threading
import tomllib
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import netwarden
from netwarden import __main__ as cli
from netwarden import demo, i18n, web
from test_round6_o import PUBLISHED, ignored

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/liming-ting/netwarden"
# sha256 of the verbatim GNU AGPL v3 text (GitHub license API), the repo's LICENSE file
LICENSE_SHA256 = "8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef"
BINARY_SUFFIXES = {".png", ".ico", ".jpg", ".jpeg", ".gif", ".webp", ".woff2", ".db",
                   ".sqlite", ".sqlite3", ".tgz", ".gz", ".zip"}
THIS = "tests/test_round8_r.py"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def texts():
    """(rel, text) of every published file that is not binary."""
    for rel in PUBLISHED:
        if Path(rel).suffix.lower() in BINARY_SUFFIXES:
            continue
        yield rel, (ROOT / rel).read_bytes().decode("utf-8")


# --- 1. placeholders, URLs, image names ----------------------------------------------------

class NoPlaceholders(unittest.TestCase):
    def test_no_placeholder_left_in_the_publication_set(self):
        bad = []
        # bare OWNER / REPO as words (not OWNERS_MAX, not the shell variable $REPO / REPO=)
        word = re.compile(r"(?<![$\w])(OWNER|REPO)(?![\w=])")
        for rel, text in texts():
            if rel == THIS:
                continue
            for no, line in enumerate(text.splitlines(), 1):
                if "OWNER/REPO" in line or "@LICENSE@" in line or re.search(r"maintainer:\s*OWNER", line):
                    bad.append((rel, no))
                # tests may still assert that a workflow does NOT contain "OWNER"
                elif word.search(line) and not (rel.startswith("tests/") and "assertNotIn" in line):
                    bad.append((rel, no))
        self.assertEqual(bad, [])

    def test_every_project_github_url_points_at_the_repository(self):
        url = re.compile(r"https?://(?:www\.)?github\.com/([\w.-]+)(?:/([\w.-]+))?", re.I)
        bad, seen = [], 0
        for rel, text in texts():
            for m in url.finditer(text):
                owner, repo = m.group(1), m.group(2)
                if owner.lower() in ("liming-ting", "owner") or (repo or "").lower() in ("repo", "netwarden"):
                    seen += 1
                    if (owner, repo) != ("liming-ting", "netwarden"):
                        bad.append((rel, m.group(0)))
        self.assertEqual(bad, [])
        self.assertGreater(seen, 20)

    def test_every_ghcr_image_is_lower_case_under_liming_ting(self):
        ref = re.compile(r"ghcr\.io/[^\s\"'`)>,]+")
        allowed = re.compile(r"^ghcr\.io/liming-ting/netwarden(-addon)?(:[a-z0-9.{}$-]+)?$")
        found = []
        for rel, text in texts():
            if rel == THIS:
                continue
            for m in ref.finditer(text):
                value = m.group(0).rstrip(".")
                if value.startswith("ghcr.io/${GITHUB_REPOSITORY"):        # docker.yml, `,,` = lower case
                    self.assertIn("ghcr.io/${GITHUB_REPOSITORY,,}", text)
                    continue
                found.append((rel, value))
        self.assertTrue(found)
        self.assertEqual([f for f in found if not allowed.match(f[1])], [])

    def test_the_key_files_agree(self):
        meta = tomllib.loads(read("pyproject.toml"))["project"]
        self.assertEqual(meta["urls"]["Homepage"], netwarden.SOURCE_URL)
        self.assertEqual(netwarden.SOURCE_URL, REPO_URL)
        for key in ("Documentation", "Issues", "Changelog", "Security"):
            self.assertTrue(meta["urls"][key].startswith(REPO_URL + "/"), key)
        self.assertEqual(meta["authors"], [{"name": "liming-ting"}])
        repo = read("repository.yaml")
        self.assertIn(f"url: {REPO_URL}\n", repo)
        self.assertIn("maintainer: liming-ting\n", repo)
        self.assertNotIn("@", repo)                                     # no e-mail address
        addon = read("ha-addon/config.yaml")
        self.assertIn(f"url: {REPO_URL}\n", addon)
        self.assertIn("image: ghcr.io/liming-ting/netwarden-addon\n", addon)
        self.assertIn(f"{REPO_URL}/security/advisories/new", read("SECURITY.md"))
        self.assertIn(f"{REPO_URL}/security/advisories/new", read(".github/ISSUE_TEMPLATE/config.yml"))
        self.assertIn(f"Documentation={REPO_URL}/blob/main/docs/install.md", read("scripts/install_linux.sh"))
        for name in ("compose.yaml", "compose.adguard.yaml", "compose.bridge.yaml"):
            self.assertIn("image: ghcr.io/liming-ting/netwarden:latest", read(f"deploy/{name}"), name)
        for rel in ("README.md", "README.zh-TW.md", "CONTRIBUTING.md", "docs/install.md",
                    "docs/install.zh-TW.md"):
            self.assertIn(f"git clone {REPO_URL} netwarden", read(rel), rel)
        for rel in ("README.md", "README.zh-TW.md"):
            self.assertIn(f"{REPO_URL}/actions/workflows/ci.yml/badge.svg", read(rel), rel)
        self.assertIn(f"[0.1.0]: {REPO_URL}/releases/tag/v0.1.0", read("CHANGELOG.md"))


# --- 2. license metadata and notices -------------------------------------------------------

class License(unittest.TestCase):
    def test_license_file_is_the_verbatim_agpl_text(self):
        data = (ROOT / "LICENSE").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), LICENSE_SHA256)
        self.assertIn("LICENSE", PUBLISHED)

    def test_pyproject_uses_pep_639(self):
        doc = tomllib.loads(read("pyproject.toml"))
        meta = doc["project"]
        self.assertEqual(meta["license"], "AGPL-3.0-or-later")
        self.assertEqual(meta["license"], netwarden.LICENSE)
        self.assertIn("LICENSE", meta["license-files"])
        for f in meta["license-files"]:
            self.assertTrue((ROOT / f).is_file(), f)
            self.assertIn(f, PUBLISHED)
        self.assertFalse([c for c in meta["classifiers"] if c.startswith("License ::")])
        req = doc["build-system"]["requires"]
        m = re.fullmatch(r"setuptools>=(\d+)", req[0])
        self.assertTrue(m and int(m.group(1)) >= 77, req)   # PEP 639 support

    def test_readmes_explain_the_license_in_plain_words(self):
        en, zh = read("README.md"), read("README.zh-TW.md")
        lic_en = en.split("## License", 1)[1]
        for needle in ("GNU AGPL v3 or later", "AGPL-3.0-or-later", "self-host", "over a network",
                       "source", "same license", "THIRD_PARTY_NOTICES.md", "(LICENSE)", "not legal advice"):
            self.assertIn(needle, lic_en)
        lic_zh = zh.split("## 授權", 1)[1]
        for needle in ("GNU AGPL v3 或更新版本", "AGPL-3.0-or-later", "原始碼", "透過網路",
                       "THIRD_PARTY_NOTICES.md", "(LICENSE)", "不是法律意見"):
            self.assertIn(needle, lic_zh)

    def test_one_copyright_notice_everywhere(self):
        # AGPL sections 0 / 5d "Appropriate Legal Notices": README, notices, Settings > About
        self.assertRegex(netwarden.COPYRIGHT, r"^Copyright \(C\) 20\d\d liming-ting and contributors$")
        for rel in ("README.md", "README.zh-TW.md", "THIRD_PARTY_NOTICES.md"):
            self.assertIn(netwarden.COPYRIGHT.split(" (C) ")[1], read(rel), rel)
        for rel in ("README.md", "README.zh-TW.md"):
            lic = read(rel).split("## License" if rel == "README.md" else "## 授權", 1)[1]
            self.assertIn(netwarden.COPYRIGHT, lic)
        js = read("netwarden/static/app.js")
        fn = js[js.index("function aboutCard()"):js.index("function viewSettings()")]
        self.assertIn("m.copyright", fn)

    def test_contributing_is_inbound_equals_outbound(self):
        con = read("CONTRIBUTING.md")
        self.assertIn("inbound = outbound", con)
        self.assertIn("no contributor license agreement (CLA)", con)
        self.assertIn("(DCO) requirement", con)

    def test_third_party_notices_state_the_project_license_once_at_the_top(self):
        tpn = read("THIRD_PARTY_NOTICES.md")
        head = tpn.split("## ", 1)[0]
        self.assertIn("GNU AGPL v3 or later", head)
        self.assertIn("AGPL-3.0-or-later", head)
        self.assertEqual(tpn.count("AGPL"), 2)

    def test_images_carry_license_and_notices_with_matching_labels(self):
        df = read("Dockerfile")
        copy = next(l for l in df.splitlines() if l.startswith("COPY") and "pyproject.toml" in l)
        self.assertIn(" LICENSE ", copy)
        self.assertIn(" THIRD_PARTY_NOTICES.md ", copy)
        rm = next(l for l in df.splitlines() if "rm -rf" in l and "/opt/netwarden" in l)
        self.assertNotIn("LICENSE", rm)                            # kept in /opt/netwarden
        self.assertNotIn("THIRD_PARTY", rm)
        # ONE label set, in the stage both images build on (runtime -> addon, default)
        self.assertEqual(df.count('org.opencontainers.image.licenses="AGPL-3.0-or-later"'), 1)
        self.assertEqual(df.count(f'org.opencontainers.image.source="{REPO_URL}"'), 1)
        self.assertLess(df.index("org.opencontainers.image.licenses"), df.index("FROM runtime AS addon"))
        # the workflow's metadata-action would say "AGPL-3.0" (GitHub's detection): it is
        # overridden with the very same value, never a second, different one
        wf = read(".github/workflows/docker.yml")
        values = set(re.findall(r"org\.opencontainers\.image\.licenses=(\S+)", wf))
        self.assertEqual(values, {"AGPL-3.0-or-later"})
        self.assertNotIn("image.source=", wf)
        rules = [l.strip() for l in read(".dockerignore").splitlines() if l.strip() and not l.startswith("#")]
        for f in ("LICENSE", "THIRD_PARTY_NOTICES.md"):            # not excluded from the context
            self.assertFalse([r for r in rules if fnmatch.fnmatchcase(f, r)], f)


# --- 3. source link ------------------------------------------------------------------------

class SourceLink(unittest.TestCase):
    def test_version_keeps_its_first_line_and_adds_license_and_source(self):
        for lang in ("zh-Hant", "en"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main([f"--lang={lang}", "--version"]), 0)
            lines = out.getvalue().splitlines()
            self.assertEqual(lines[0], f"netwarden {netwarden.__version__}")
            self.assertEqual(lines[1], i18n.t("cli.version_license", lang, license=netwarden.LICENSE))
            self.assertEqual(lines[2], i18n.t("cli.version_source", lang, url=netwarden.SOURCE_URL))
            self.assertEqual(len(lines), 3)
        self.assertIn("授權", i18n.t("cli.version_license", "zh-Hant", license="x"))

    def test_new_strings_exist_in_every_language(self):
        keys = ("app.about.title", "app.about.source", "app.about.new_tab", "app.about.note",
                "cli.version_license", "cli.version_source")
        en = i18n.strings("en")
        for code in i18n.CODES:
            s = i18n.strings(code)
            for k in keys:
                self.assertIn(k, s, (code, k))
                if code != "en" and k not in ("cli.version_license",):
                    self.assertNotEqual(s[k], en[k], (code, k))
        self.assertIn("{license}", i18n.strings("ja")["cli.version_license"])
        self.assertIn("{url}", i18n.strings("hi")["cli.version_source"])

    def test_about_card_in_the_dashboard(self):
        js = read("netwarden/static/app.js")
        fn = js[js.index("function aboutCard()"):js.index("function viewSettings()")]
        self.assertIn('target="_blank" rel="noopener noreferrer"', fn)
        self.assertIn("aria-label=", fn)                           # "Source code (opens in a new tab)"
        self.assertIn("m.source_url", fn)                          # from /api/meta, not hard-coded
        self.assertIn("/^https:\\/\\//", fn)                       # only an https URL is a link
        self.assertNotIn("github.com", js)                         # one constant, server side
        self.assertNotIn("innerHTML", fn)
        view = js[js.index("function viewSettings()"):js.index("// Stage X - First-run wizard")]
        self.assertEqual(view.count("aboutCard()"), 2)             # phone (remote) + this computer

    def test_api_meta_has_license_and_source_url(self):
        saved = {k: getattr(web.Handler, k) for k in ("db_path", "env", "lang")}
        with tempfile.TemporaryDirectory() as tmp:
            dbp = str(Path(tmp) / "demo.db")
            demo.build(dbp)
            web.Handler.db_path, web.Handler.env, web.Handler.lang = dbp, {}, "English"
            srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=20)
                c.request("GET", "/api/meta")
                r = c.getresponse()
                body = json.loads(r.read())
                self.assertEqual(r.status, 200)
            finally:
                srv.shutdown()
                srv.server_close()
                for k, v in saved.items():
                    setattr(web.Handler, k, v)
        self.assertEqual(body["license"], "AGPL-3.0-or-later")
        self.assertEqual(body["source_url"], REPO_URL)
        self.assertEqual(body["copyright"], netwarden.COPYRIGHT)
        self.assertEqual(body["version"], netwarden.__version__)


# --- 4. line endings -----------------------------------------------------------------------

def _gitattributes():
    rules = []
    for line in read(".gitattributes").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pat, *attrs = line.split()
            rules.append((pat, attrs))
    return rules


def attributes(rel, rules):
    """git-like for this file's patterns (none has a "/"): later lines win per attribute."""
    out = {}
    name = rel.rsplit("/", 1)[-1]
    for pat, attrs in rules:
        if fnmatch.fnmatchcase(name, pat):
            for a in attrs:
                if a == "binary":                    # macro: -text -diff -merge
                    out.update(text=False, diff=False, merge=False)
                elif "=" in a:
                    k, v = a.split("=", 1)
                    out[k] = v
                else:
                    out[a.lstrip("-")] = not a.startswith("-")
    return out


class LineEndings(unittest.TestCase):
    def setUp(self):
        self.rules = _gitattributes()

    def test_gitattributes_rules(self):
        self.assertEqual(self.rules[0], ("*", ["text=auto", "eol=lf"]))
        self.assertIn(".gitattributes", PUBLISHED)
        for name in ("x.sh", "x.py", "Dockerfile", "x.yaml", "x.yml", "x.json", "x.md", "x.toml"):
            a = attributes(name, self.rules)
            self.assertEqual((a.get("text"), a.get("eol")), (True, "lf"), name)
        for name in ("x.cmd", "x.bat"):
            a = attributes(name, self.rules)
            self.assertEqual((a.get("text"), a.get("eol")), (True, "crlf"), name)
        for suffix in BINARY_SUFFIXES:
            self.assertIs(attributes("x" + suffix, self.rules).get("text"), False, suffix)

    def test_every_published_file_checks_out_as_stored(self):
        """Working tree == what a fresh checkout produces: `git status` is clean after the
        first commit (text: LF only, batch files CRLF only, binaries untouched)."""
        bad = []
        for rel in PUBLISHED:
            a = attributes(rel, self.rules)
            data = (ROOT / rel).read_bytes()
            if Path(rel).suffix.lower() in BINARY_SUFFIXES:
                if a.get("text") is not False:
                    bad.append((rel, "binary not marked"))
                continue
            if a.get("eol") == "crlf":
                if data.count(b"\r\n") != data.count(b"\n") or data.count(b"\r") != data.count(b"\r\n"):
                    bad.append((rel, "not pure CRLF"))
                if not rel.endswith((".cmd", ".bat")):
                    bad.append((rel, "CRLF outside batch files"))
            else:
                if a.get("eol") != "lf":
                    bad.append((rel, "no eol rule"))
                if b"\r" in data:
                    bad.append((rel, "CR in a text file"))
        self.assertEqual(bad, [])
        self.assertTrue([r for r in PUBLISHED if r.endswith(".cmd")])


# --- 5. executable bits --------------------------------------------------------------------

EXEC_LIST = ROOT / "launch" / "exec_files.txt"


@unittest.skipUnless(EXEC_LIST.exists(), "launch/ is internal (not in a published checkout)")
class ExecutableBits(unittest.TestCase):
    def test_every_listed_file_is_a_published_shebang_script(self):
        listed = [l.strip() for l in EXEC_LIST.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(listed), len(set(listed)))
        for rel in listed:
            self.assertTrue((ROOT / rel).is_file(), rel)
            self.assertFalse(ignored(rel), rel)
            self.assertIn(rel, PUBLISHED)
            self.assertTrue((ROOT / rel).read_bytes().startswith(b"#!"), rel)
        # complete: every published shell script and shebang tool under scripts/
        for rel in PUBLISHED:
            if rel.startswith("scripts/") and (ROOT / rel).read_bytes().startswith(b"#!"):
                self.assertIn(rel, listed)


# --- 6. CI ---------------------------------------------------------------------------------

class Workflows(unittest.TestCase):
    def setUp(self):
        self.ci = read(".github/workflows/ci.yml")
        self.docker = read(".github/workflows/docker.yml")

    def test_only_github_token_and_least_privilege(self):
        for wf in (self.ci, self.docker):
            self.assertRegex(wf, r"(?m)^permissions:\n  contents: read$")
            self.assertIn("cancel-in-progress: true", wf)
            self.assertEqual(set(re.findall(r"secrets\.(\w+)", wf)) - {"GITHUB_TOKEN"}, set())
            self.assertNotRegex(wf, r"runs-on:\s*(windows|macos)")
        self.assertNotIn("write", self.ci)
        self.assertEqual(self.docker.count("packages: write"), 1)

    def test_main_pushes_no_image_and_qemu_only_on_tags(self):
        jobs = re.split(r"(?m)^  (?=\w[\w-]*:\n)", self.docker.split("\njobs:\n", 1)[1])
        smoke = next(j for j in jobs if j.startswith("smoke:"))
        release = next(j for j in jobs if j.startswith("release:"))
        self.assertNotIn("push: true", smoke)
        self.assertNotIn("setup-qemu", smoke)
        self.assertNotIn("linux/arm", smoke)
        self.assertIn("if: ${{ startsWith(github.ref, 'refs/tags/v') }}", release)
        self.assertIn("setup-qemu", release)
        self.assertIn("type=gha", smoke)                                # build cache
        self.assertIn("latest=auto", release)                         # never latest for -rc
        self.assertNotIn("type=edge", release)
        # a tag pushes images only once the unit tests passed in THIS workflow too
        tests = next(j for j in jobs if j.startswith("tests:"))
        self.assertIn("needs: [smoke, tests]", release)
        self.assertIn("if: ${{ startsWith(github.ref, 'refs/tags/v') }}", tests)
        self.assertIn("python3 -m unittest discover -s tests", tests)
        self.assertNotIn("write", tests)

    def test_shell_loops_have_no_unused_variable(self):
        # shellcheck SC2034 (actionlint runs shellcheck when it is installed)
        for wf in (self.ci, self.docker):
            self.assertNotRegex(wf, r"for i in \$\(seq")

    def test_small_matrix_on_pushes_full_on_tags(self):
        line = re.search(r"(?m)^\s*python:\s*(.+)$", self.ci).group(1)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", line)
        self.assertIn("workflow_dispatch", line)
        self.assertNotIn("allow-prereleases", self.ci)                # 3.15 is a final release
        self.assertIn("package:", self.ci)
        self.assertIn("License-Expression: AGPL-3.0-or-later", self.ci)

    def test_action_versions_agree_across_workflows(self):
        seen = {}
        for wf in (self.ci, self.docker):
            for action, ver in re.findall(r"uses: ([\w./-]+)@(\S+)", wf):
                self.assertRegex(ver, r"^v\d+$", action)
                seen.setdefault(action, set()).add(ver)
        self.assertEqual({a: v for a, v in seen.items() if len(v) > 1}, {})
        self.assertEqual(seen["actions/checkout"], {"v7"})

    def test_dependabot(self):
        dep = read(".github/dependabot.yml")
        for eco in ('"github-actions"', '"docker"'):
            self.assertIn(f"package-ecosystem: {eco}", dep)
        self.assertEqual(dep.count('interval: "weekly"'), 2)
        self.assertEqual(dep.count('update-types: ["minor", "patch"]'), 1)     # actions
        # the base image's Python (3.12 -> 3.13 = "minor") is never bundled into a group
        docker = dep.split('package-ecosystem: "docker"', 1)[1]
        self.assertIn('dependency-name: "python"', docker)
        self.assertIn('"version-update:semver-minor"', docker)
        self.assertIn('update-types: ["patch"]', docker)


# --- 9. nothing machine-specific in the project guide ---------------------------------------

class ProjectGuide(unittest.TestCase):
    def test_claude_md_is_not_machine_specific(self):
        text = read("CLAUDE.md")
        for needle in ("/mnt/c", "C:\\Users", "/c/Users", "wsl.exe"):
            self.assertNotIn(needle, text)
        # the owner's LAN addresses: test_round6_o.NothingPrivate reads them from the
        # machine-local notes (never written into a published file)
        self.assertNotRegex(text, r"\.[\w-]+-cc[/\\]")              # build-orchestrator folders
        self.assertLess(len(text.splitlines()), 250)


if __name__ == "__main__":
    unittest.main()
