"""The CSS state rules (a) to (d) of `site` in tools/sitecheck.py
(Replikanti/interviewscam#61, ADR-0003 part 6 amendment), on their own,
and the reflow parser's default for case (7)'s cells.

Why it exists: the site-css-state rows run the rules on the real built
stylesheet through cmd_site, where rule (f) refuses every backslash outside
a string, so a row cannot show that the state rules themselves pass an
escape, a stray parenthesis or a unit-like ident. These cases pin the pass
side of each scanner branch (fix round 1, QA sweep survivors), so a walk
that over-refuses fails here instead of only on a later stylesheet change.
They also pin that the real command line runs the cells: `check.sh` never
passes --no-reveal-cells, so the parser's default is what CI runs.

Run by `bash tools/selftest.sh` (suite `reflow-isolation`, which discovers
tests/reflow) as python3 -I -B -m unittest, locally and in CI, without a
browser.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sitecheck = load("sitecheck_states", ROOT / "tools" / "sitecheck.py")


class PassSide(unittest.TestCase):
    def test_each_form_passes(self):
        for name, css in (
                ("single-quoted string", "main::before{content:'@x{(}'}"),
                ("escaped quote in a string", 'main::before{content:"a\\"@x{("}'),
                ("escaped at sign", "main\\@x{margin:0}"),
                ("stray close parenthesis", "main{margin:0)}"),
                ("unit-like ident", "main{width:1vwx}"),
                ("unit-like custom property name", ":root{--vw:1px}"),
                ("comment holding an at-rule", "/*@media(min-width:1px){a{b:c}}*/main{margin:0}"),
                ("comment holding a brace", "main{margin:0/*}*/}"),
                ("allowed prelude", "a{b:c}@media(max-width:24rem){a{b:c}}"),
                ("bracket block", "a[x]{b:c}"),
                ("quoted url", 'a{b:url("/*")}x{y:z}')):
            with self.subTest(name=name):
                found = [p for p in sitecheck.css_state_problems(css)
                         if "function outside the closed list" not in p]
                self.assertEqual(found, [], css)

    def test_url_token_keeps_its_comment_opener(self):
        # A /* inside an unquoted url( token is no comment (CSS Syntax
        # 4.3.6), in any case and after whitespace; one inside a function
        # whose name only ends in url is.
        for css in ("x url(/*){a:b}@x{}y url(*/){a:b}", "x URL(/*){a:b}@x{}y url(*/){a:b}",
                    "x url( /*){a:b}@x{}y url(*/){a:b}"):
            with self.subTest(css=css):
                self.assertIn("@x{}", sitecheck.css_strip_comments(css))
        self.assertNotIn("@x", sitecheck.css_strip_comments("x xurl(/*@x{}*/){a:b}"))
        self.assertNotIn("@x", sitecheck.css_strip_comments("x _url(/*@x{}*/){a:b}"))
        # Non-ASCII code points are ident code points in CSS, also those
        # Python's \w does not take (U+20AC), and U+00E9.
        self.assertNotIn("@x", sitecheck.css_strip_comments("x éurl(/*@x{}*/){a:b}"))
        self.assertNotIn("@x", sitecheck.css_strip_comments("x €url(/*@x{}*/){a:b}"))

    def test_url_with_a_string_is_a_function(self):
        # url( then a quote is a function holding a string: the string is
        # kept whole, ) inside it included, and what follows is read.
        out = sitecheck.css_strip_comments('a{b:url( "x)y")}/*c*/d{e:f}')
        self.assertEqual(out, 'a{b:url( "x)y")}d{e:f}')
        # A ) and a /* inside that string end nothing and open nothing, with
        # or without whitespace after url( (sweep 43-impl-r6 survivors).
        for css in ('a{b:url( "a)/*")}c{d:e}', "a{b:url(\t'a)/*')}c{d:e}",
                    'a{b:url("a)/*")}c{d:e}'):
            with self.subTest(css=css):
                self.assertEqual(sitecheck.css_strip_comments(css), css)


class Blocks(unittest.TestCase):
    def test_bracket_nests_like_a_parenthesis(self):
        # A } inside [...] ends no block (fix round 1, review run 1
        # finding 2), in css_rules as in the at-rule walk.
        rules = sitecheck.css_rules("a{b:[}];c:d}e{f:g}")
        self.assertEqual([(r.prelude, r.declarations) for r in rules],
                         [("a", ["b:[}]", "c:d"]), ("e", ["f:g"])])
        rules = sitecheck.css_rules("a{b:(});c:d}")
        self.assertEqual(rules[0].declarations, ["b:(})", "c:d"])

    def test_only_its_own_closer_closes_a_block(self):
        # Fix round 2 (review run 2): ) inside [...] and ] inside (...) are
        # tokens, as in Chrome, in css_rules and in the at-rule walk.
        for css, decls in (("a{b:[)}];c:d}e{f:g}", ["b:[)}]", "c:d"]),
                           ("a{b:x(]});c:d}e{f:g}", ["b:x(]})", "c:d"])):
            with self.subTest(css=css):
                rules = sitecheck.css_rules(css)
                self.assertEqual([(r.prelude, r.declarations) for r in rules],
                                 [("a", decls), ("e", ["f:g"])])
                self.assertTrue(any("braces that do not balance" in p
                                    for p in sitecheck.css_at_rule_problems(css)), css)
        for css in ("a{b:[x(y)z]}", "a{b:x([y])}", "a{b:[x]}c{d:e)]}"):
            with self.subTest(css=css):
                self.assertEqual(sitecheck.css_at_rule_problems(css), [], css)
        # Nested blocks of two kinds: the innermost one closes first, and
        # the outer one stays open (sweep 43-impl-r8 survivors).
        rules = sitecheck.css_rules("a{b:[x(y)z]}c{d:e}")
        self.assertEqual([(r.prelude, r.declarations) for r in rules],
                         [("a", ["b:[x(y)z]"]), ("c", ["d:e"])])
        rules = sitecheck.css_rules("a{b:x([y]z)}c{d:e}")
        self.assertEqual([(r.prelude, r.declarations) for r in rules],
                         [("a", ["b:x([y]z)"]), ("c", ["d:e"])])
        for css in ("a{b:[(x)}]", "a{b:([x]})"):
            with self.subTest(css=css):
                self.assertTrue(any("braces that do not balance" in p
                                    for p in sitecheck.css_at_rule_problems(css)), css)


class Parser(unittest.TestCase):
    def test_reflow_runs_the_cells_by_default(self):
        args = sitecheck.build_parser().parse_args(["reflow", "--chrome", "c", "public"])
        self.assertIs(args.no_reveal_cells, False)
        self.assertIs(args.no_search, False)
        args = sitecheck.build_parser().parse_args(
            ["reflow", "--chrome", "c", "--no-reveal-cells", "public"])
        self.assertIs(args.no_reveal_cells, True)


if __name__ == "__main__":
    unittest.main()
