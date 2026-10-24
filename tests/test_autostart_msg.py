"""Stage Q: scripts/autostart_windows.cmd speaks the user's language (autostart.* keys).

The script's message helper is a short PowerShell snippet (set "NW_PS=...") that picks the
locale file - NETWARDEN_LANG, else the Windows display language (NW_UI_CULTURE in tests),
else English - and prints one string. The selection matrix runs the real snippet through
powershell.exe when it is reachable (Windows, or WSL interop) and is skipped otherwise;
the static checks always run."""
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from netwarden import i18n

ROOT = Path(__file__).resolve().parent.parent
CMD = ROOT / "scripts" / "autostart_windows.cmd"
TEXT = CMD.read_bytes().decode("utf-8")


def _snippet() -> str:
    m = re.search(r'^set "NW_PS=(.*)"\r$', TEXT, re.M)
    assert m, "NW_PS helper not found"
    return m.group(1)


def _win_path(p: Path) -> str | None:
    if os.name == "nt":
        return str(p)
    wp = shutil.which("wslpath")
    if not wp:
        return None
    try:
        return subprocess.run([wp, "-w", str(p)], capture_output=True, text=True,
                              timeout=10).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


class StaticTests(unittest.TestCase):
    def test_every_message_key_exists_everywhere(self):
        keys = set(re.findall(r"call :msg (autostart\.\w+)", TEXT))
        self.assertGreaterEqual(len(keys), 12)
        for code in i18n.CODES:
            s = i18n.strings(code)
            for k in keys:
                self.assertIn(k, s, (code, k))
                # the helper fills only these two placeholders
                self.assertLessEqual(set(re.findall(r"{(\w+)}", s[k])), {"path", "cmd"}, (code, k))

    def test_dry_run_prefix_in_every_language(self):
        for code in i18n.CODES:
            for k in ("autostart.dry_create", "autostart.dry_target", "autostart.dry_delete"):
                self.assertTrue(i18n.t(k, code).startswith("[dry run]"), (code, k))

    def test_helper_is_read_only_and_safe(self):
        ps = _snippet()
        self.assertNotIn('"', ps)                        # it lives inside one "..." argument
        for never in ("Set-Content", "Out-File", "Remove-Item", "Invoke-WebRequest",
                      "Start-Process", "iex", "Invoke-Expression", "ExecutionPolicy"):
            self.assertNotIn(never.lower(), ps.lower())
        # a language code is checked before it becomes a file name
        self.assertIn("-match '^[a-z]{2,3}(-[A-Za-z]{2,4})?$'", ps)


class SelectionTests(unittest.TestCase):
    """The real snippet, run by powershell.exe."""

    @classmethod
    def setUpClass(cls):
        cls.ps = shutil.which("powershell.exe")
        cls.here = _win_path(ROOT / "scripts")
        if not cls.ps or not cls.here:
            raise unittest.SkipTest("powershell.exe not reachable")

    def run_msg(self, key, lang="", ui="", arg="C:\\nw\\netwarden.lnk"):
        env = dict(os.environ, NW_HERE=self.here + "\\", NW_KEY=key, NW_ARG=arg,
                   NW_CMD="autostart_windows.cmd", NETWARDEN_LANG=lang, NW_UI_CULTURE=ui)
        # WSL hands only the variables named in WSLENV to Windows programs
        env["WSLENV"] = ":".join(["NW_HERE", "NW_KEY", "NW_ARG", "NW_CMD", "NETWARDEN_LANG",
                                  "NW_UI_CULTURE"] + [x for x in [os.environ.get("WSLENV")] if x])
        try:
            out = subprocess.run([self.ps, "-NoProfile", "-NonInteractive", "-Command",
                                  _snippet()], env=env, capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            self.skipTest(f"powershell.exe failed to start: {e}")
        return out.stdout.decode("utf-8").strip()

    def expect(self, key, code, **kw):
        return i18n.t(key, code).replace("{path}", kw.get("arg", "C:\\nw\\netwarden.lnk")) \
            .replace("{cmd}", "autostart_windows.cmd").strip()

    def test_matrix(self):
        cases = [
            # (NETWARDEN_LANG, display language, expected locale)
            ("", "zh-TW", "zh-Hant"),
            ("", "zh-HK", "zh-Hant"),
            ("", "zh-CN", "zh-Hans"),
            ("ja", "zh-TW", "ja"),             # NETWARDEN_LANG wins
            ("zh-Hant", "en-US", "zh-Hant"),
            ("pt", "", "pt-BR"),
            ("", "pt-PT", "pt-BR"),
            ("", "de-DE", "de"),
            ("", "xx-YY", "en"),               # unknown -> English
            ("..\\..\\x", "xx", "en"),         # never a path
            ("klingon", "fr-CA", "fr"),        # unusable NETWARDEN_LANG -> display language
        ]
        for lang, ui, code in cases:
            with self.subTest(lang=lang, ui=ui):
                self.assertEqual(self.run_msg("autostart.status_on", lang, ui),
                                 self.expect("autostart.status_on", code))

    def test_unknown_key_prints_the_key(self):
        self.assertEqual(self.run_msg("autostart.nope", "de"), "autostart.nope")

    def test_cmd_placeholder(self):
        self.assertEqual(self.run_msg("autostart.usage", "en"),
                         "usage: autostart_windows.cmd install|uninstall|status [--dry-run]")


if __name__ == "__main__":
    unittest.main()
