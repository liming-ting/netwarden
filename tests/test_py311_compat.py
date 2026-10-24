"""Python 3.11 compatibility guard (CI2).

CI runs the suite on Python 3.11, the oldest supported version, but development
machines often only have 3.12+. Code that only 3.12+ accepts then passes locally and
breaks CI at `compileall`. This test catches the usual culprits on any interpreter:

- PEP 701 f-strings (3.12): inside a replacement field, a string that reuses the quote
  of an enclosing f-string, a backslash, or a comment. Checked token by token
  (tokenize emits FSTRING_START / FSTRING_MIDDLE / FSTRING_END on 3.12+; on 3.11 the
  file would not even compile, so `compile()` itself is the check there).
- Newer grammar in general (PEP 695 `type` statements, generic brackets, ...):
  ast.parse(feature_version=(3, 11)).
- A short explicit list of standard-library names added in 3.12 or later.
"""

import ast
import io
import os
import re
import sys
import token
import tokenize
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "build", "dist", "node_modules",
             ".mypy_cache", ".pytest_cache", "data"}
HAS_FSTRING_TOKENS = hasattr(token, "FSTRING_START")      # Python 3.12+

# Standard-library names added in Python 3.12 or later (pattern, what it is).
NEW_STDLIB = [
    (r"\bitertools\.batched\b|from\s+itertools\s+import[^\n]*\bbatched\b", "itertools.batched (3.12)"),
    (r"\btyping\.override\b|from\s+typing\s+import[^\n]*\boverride\b", "typing.override (3.12)"),
    (r"\bTypeAliasType\b", "typing.TypeAliasType (3.12)"),
    (r"\bsplitroot\b", "os.path.splitroot (3.12)"),
    (r"\bisjunction\b|\bis_junction\b", "os.path.isjunction / Path.is_junction (3.12)"),
    (r"\bwith_segments\b", "Path.with_segments (3.12)"),
    (r"\bwalk_up\s*=", "Path.relative_to(walk_up=) (3.12)"),
    (r"\bcase_sensitive\s*=", "Path.glob/match(case_sensitive=) (3.12)"),
    (r"\bautocommit\s*=", "sqlite3 autocommit (3.12)"),
    (r"\bonexc\s*=", "shutil.rmtree(onexc=) (3.12)"),
    (r"\bdelete_on_close\s*=", "NamedTemporaryFile(delete_on_close=) (3.12)"),
    (r"\bcalendar\.(Month|Day)\b", "calendar.Month / calendar.Day (3.12)"),
    (r"\bmath\.sumprod\b", "math.sumprod (3.12)"),
    (r"\bsys\.monitoring\b", "sys.monitoring (3.12)"),
    (r"\bwarnings\.deprecated\b", "warnings.deprecated (3.13)"),
    (r"\bcopy\.replace\b", "copy.replace (3.13)"),
    (r"\bre\.PatternError\b", "re.PatternError (3.13)"),
    (r"\bPythonFinalizationError\b", "PythonFinalizationError (3.13)"),
    (r"\bfrom_uri\b", "Path.from_uri (3.13)"),
    (r"\bqueue\.ShutDown\b", "queue.ShutDown (3.13)"),
    (r"\bz85(en|de)code\b", "base64.z85encode (3.13)"),
]
NEW_STDLIB_RE = [(re.compile(p), what) for p, what in NEW_STDLIB]


def python_files():
    """Every .py file in the repository (sorted, repo-relative)."""
    out = []
    for root, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in files:
            if name.endswith(".py"):
                out.append(os.path.relpath(os.path.join(root, name), ROOT))
    return sorted(out)


def _quote_of(text):
    """The opening quote of a string / FSTRING_START token: ', ", ''' or \"\"\"."""
    body = text.lstrip("rRbBuUfFtT")
    return body[:3] if body[:3] in ("'''", '"""') else body[:1]


def _clashes(quote, outer):
    """Would a string opened with `quote` end an enclosing f-string opened with `outer`
    on Python 3.11? Single-quoted: same character; triple-quoted: same triple quote."""
    return quote.startswith(outer) if len(outer) == 1 else quote == outer


def fstring_problems(source, name="<src>"):
    """file:line messages for f-string syntax only Python 3.12+ accepts (PEP 701).
    Needs a 3.12+ tokenizer; returns [] on older versions."""
    if not HAS_FSTRING_TOKENS:
        return []
    starts = {token.FSTRING_START} | ({token.TSTRING_START} if hasattr(token, "TSTRING_START") else set())
    ends = {token.FSTRING_END} | ({token.TSTRING_END} if hasattr(token, "TSTRING_END") else set())
    middles = {token.FSTRING_MIDDLE} | ({token.TSTRING_MIDDLE} if hasattr(token, "TSTRING_MIDDLE") else set())
    lines = source.splitlines(keepends=True)
    problems = []
    stack = []          # [{"quote": str, "depth": brace depth inside this f-string}]
    prev_end = None

    def report(row, what):
        problems.append(f"{name}:{row}: {what}")

    def in_field():
        return bool(stack) and stack[-1]["depth"] > 0

    def gap_text(start, end):
        (r1, c1), (r2, c2) = start, end
        if r1 == r2:
            return lines[r1 - 1][c1:c2] if r1 - 1 < len(lines) else ""
        parts = [lines[r1 - 1][c1:]] + lines[r1:r2 - 1] + [lines[r2 - 1][:c2]]
        return "".join(parts)

    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        row = tok.start[0]
        if in_field():
            # a line continuation between tokens of an expression = backslash in it
            if prev_end is not None and tok.type not in middles and "\\" in gap_text(prev_end, tok.start):
                report(row, "backslash inside an f-string replacement field")
            if tok.type == tokenize.COMMENT:
                report(row, "comment inside an f-string replacement field")
            elif tok.type == token.STRING or tok.type in starts:
                q = _quote_of(tok.string)
                if any(_clashes(q, f["quote"]) for f in stack):
                    report(row, f"string quote {q} reused inside an f-string that uses it")
                if tok.type == token.STRING and "\\" in tok.string:
                    report(row, "backslash inside an f-string replacement field")
        if tok.type in middles and len(stack) >= 2 and stack[-2]["depth"] > 0 and "\\" in tok.string:
            report(row, "backslash inside an f-string replacement field")
        if tok.type in starts:
            stack.append({"quote": _quote_of(tok.string), "depth": 0})
        elif tok.type in ends:
            stack.pop()
        elif tok.type == token.OP and stack:
            if tok.string == "{":
                stack[-1]["depth"] += 1
            elif tok.string == "}":
                stack[-1]["depth"] -= 1
        prev_end = tok.end
    return sorted(set(problems), key=lambda p: (int(p.rsplit(":", 2)[-2]), p))


def grammar_problems(source, name="<src>"):
    """Grammar newer than 3.11 that ast can tell (PEP 695 type / generics, ...)."""
    try:
        ast.parse(source, filename=name, feature_version=(3, 11))
    except SyntaxError as e:
        return [f"{name}:{e.lineno}: {e.msg}"]
    return []


def stdlib_problems(source, name="<src>"):
    out = []
    for i, line in enumerate(source.splitlines(), 1):
        code = line.split("#", 1)[0]
        for rx, what in NEW_STDLIB_RE:
            if rx.search(code):
                out.append(f"{name}:{i}: {what}")
    return out


class RepoIsPython311Compatible(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {}
        for rel in python_files():
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                cls.sources[rel] = f.read()

    def test_finds_the_tree(self):
        self.assertIn(os.path.join("netwarden", "export.py"), self.sources)
        self.assertIn(os.path.join("tests", "test_py311_compat.py"), self.sources)

    def test_no_pep701_fstrings(self):
        if not HAS_FSTRING_TOKENS:
            self.skipTest("needs the Python 3.12+ tokenizer (3.11 rejects these at compile time)")
        found = [p for rel, src in self.sources.items() for p in fstring_problems(src, rel)]
        self.assertEqual(found, [], "f-strings that need Python 3.12+:\n" + "\n".join(found))

    def test_grammar_is_311(self):
        found = [p for rel, src in self.sources.items() for p in grammar_problems(src, rel)]
        self.assertEqual(found, [], "\n".join(found))

    def test_no_new_stdlib_names(self):
        me = os.path.join("tests", "test_py311_compat.py")
        found = [p for rel, src in self.sources.items() if rel != me
                 for p in stdlib_problems(src, rel)]
        self.assertEqual(found, [], "standard-library names newer than 3.11:\n" + "\n".join(found))


@unittest.skipUnless(HAS_FSTRING_TOKENS, "needs the Python 3.12+ tokenizer")
class GuardCatchesBadPatterns(unittest.TestCase):
    """The guard itself: each 3.12-only pattern is reported, valid 3.11 code is not."""

    BAD = {
        "same double quote": 'x = f"{d["a"]}"\n',
        "same single quote": "x = f'{d['a']}'\n",
        "triple-quoted string in single-quoted f": "x = f'{'''a'''}'\n",
        "same triple quote": 'x = f"""{"""a"""}"""\n',
        "the issue CI2 hit": 'x = [f"## {i18n.tn("export.h", n, lang)}", ""]\n',
        "nested f reusing outer quote": 'x = f"{f"{y}"}"\n',
        "inner string reusing outermost quote": "x = f\"{f'{\"a\"}'}\"\n",
        "backslash in string": "x = f\"{'\\n'.join(y)}\"\n",
        "backslash in nested f": "x = f\"{f'\\t{y}'}\"\n",
        "line continuation": 'x = f"{a + \\\n b}"\n',
        "comment": 'x = f"""{a  # why\n}"""\n',
        "in a format spec field": 'x = f"{v:{w["k"]}}"\n',
    }
    GOOD = [
        'x = f"{d[\'a\']}"\n',
        "x = f'{d[\"a\"]}'\n",
        'x = f"""{d["a"]}"""\n',
        "x = f'''{d['a']} {d[\"b\"]}'''\n",
        'x = f"{f\'{y}\'}"\n',
        'x = f"a\\n{b}\\t{{literal}} {c!r:>{w}}"\n',
        'x = f"{ {1: 2}[1] } {[i for i in y]}"\n',
        'x = "plain " "strings \\" \' "\n',
        'x = (f"{a}"  # comment after, not inside\n     f"{b}")\n',
        'x = f"{a}" + \\\n    f"{b}"\n',
    ]

    def test_bad_patterns_are_reported(self):
        for what, src in self.BAD.items():
            with self.subTest(what):
                found = fstring_problems(src, "bad.py")
                self.assertTrue(found, f"not reported: {src!r}")
                self.assertTrue(all(p.startswith("bad.py:") for p in found), found)

    def test_valid_311_fstrings_pass(self):
        for src in self.GOOD:
            with self.subTest(src):
                self.assertEqual(fstring_problems(src, "good.py"), [])
                compile(src, "good.py", "exec")

    def test_reports_the_line(self):
        src = 'a = 1\nb = f"ok {a}"\nc = f"{d["k"]}"\n'
        self.assertEqual(fstring_problems(src, "m.py"),
                         ['m.py:3: string quote " reused inside an f-string that uses it'])


class OtherGuards(unittest.TestCase):
    def test_grammar_guard(self):
        self.assertTrue(grammar_problems("type Alias = int\n"))
        self.assertTrue(grammar_problems("def f[T](x: T) -> T:\n    return x\n"))
        self.assertTrue(grammar_problems("class C[T]:\n    pass\n"))
        self.assertEqual(grammar_problems("type = 1\nmatch x:\n    case _:\n        pass\n"), [])

    def test_stdlib_guard(self):
        self.assertTrue(stdlib_problems("from itertools import batched\n"))
        self.assertTrue(stdlib_problems("sqlite3.connect(p, autocommit=True)\n"))
        self.assertEqual(stdlib_problems("import itertools  # itertools.batched is 3.12\n"), [])
        self.assertEqual(stdlib_problems("os.walk(d)\nitertools.pairwise(x)\n"), [])


if __name__ == "__main__":
    unittest.main()
