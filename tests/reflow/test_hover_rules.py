"""css_hover_problems in tools/sitecheck.py, the closed list of the site's
:hover rules (Replikanti/interviewscam#55, ADR-0005 part 6).

Why it exists: case (8) parks the pointer outside the page, so the browser
checks never measure a page with the pointer on it, and a rule keyed on
:hover (a cover over a revealed answer) would pass every one of them. The
static check closes that: only the three :hover rules the site has today,
with exactly their declarations and at the top level, are accepted.

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


sitecheck = load("sitecheck_hover", ROOT / "tools" / "sitecheck.py")

THICK = "text-decoration-thickness:var(--underline-hover-thickness)"
# The three rules of the built stylesheet, as the pinned Hugo writes them.
TODAY = ("a:hover{" + THICK + "}.pill:hover{text-decoration:underline}"
         ".copy:hover{" + THICK + "}")
# The review's example (run 1, finding 1): a header that covers the page
# whenever the pointer is over it.
OVERLAY = ("body:hover .site-header{position:fixed;inset:0 0 auto 0;height:100vh;"
           "background:var(--color-bg)}")


def problems(css):
    return sitecheck.css_hover_problems(css)


class Allowed(unittest.TestCase):
    def test_today_passes(self):
        self.assertEqual(problems(TODAY), [])

    def test_the_list_is_the_three_rules(self):
        self.assertEqual(sorted(sitecheck.HOVER_RULES), [".copy:hover", ".pill:hover", "a:hover"])

    def test_source_formatting_passes(self):
        css = """
        /* hover thickens the underline */
        a:hover {
          text-decoration-thickness: var( --underline-hover-thickness );
        }
        .pill:hover { text-decoration : underline }
        .copy:hover{text-decoration-thickness:var(--underline-hover-thickness);}
        """
        self.assertEqual(problems(css), [])

    def test_stylesheet_without_hover_passes(self):
        css = ("a{color:red}.hover{x:y}[data-x=hover]{x:y}a:focus{x:y}"
               "@media (max-width:20rem){a{x:y}}")
        self.assertEqual(problems(css), [])
        self.assertEqual(problems(""), [])

    def test_each_rule_alone_passes(self):
        for selector, declarations in sitecheck.HOVER_RULES.items():
            with self.subTest(selector=selector):
                body = ";".join(f"{p}:{v}" for p, v in declarations)
                self.assertEqual(problems(selector + "{" + body + "}"), [])

    def test_unclosed_allowed_rule_ends_with_the_sheet(self):
        # A browser closes a block at the end of the sheet, so the rule is
        # the allowed one; the unclosed overlay below is not.
        self.assertEqual(problems("a:hover{" + THICK), [])


class Refused(unittest.TestCase):
    def refused(self, css, *words):
        found = problems(css)
        self.assertTrue(found, css)
        for word in words:
            self.assertTrue(any(word in item for item in found), (word, found))
        return found

    def test_review_overlay(self):
        self.refused(OVERLAY, "body:hover", "closed list")

    def test_overlay_among_the_allowed_rules(self):
        found = self.refused(TODAY + OVERLAY)
        self.assertEqual(len(found), 1, found)

    def test_unknown_selectors(self):
        for selector in ("body:hover", "main:hover", ".pill:hover .x", "a:hover b",
                         ".pill:hover::after", "button:hover", ":hover", "a:hover,body:hover",
                         "A:hover", "a.x:hover", "a:hover:focus"):
            with self.subTest(selector=selector):
                self.refused(selector + "{" + THICK + "}", "closed list")

    def test_new_property_on_an_allowed_selector(self):
        for selector, declarations in sitecheck.HOVER_RULES.items():
            with self.subTest(selector=selector):
                body = ";".join(f"{p}:{v}" for p, v in declarations)
                self.refused(selector + "{" + body + ";position:fixed}", "declarations")

    def test_each_declaration_must_stay(self):
        for selector, declarations in sitecheck.HOVER_RULES.items():
            for i, (prop, value) in enumerate(declarations):
                with self.subTest(selector=selector, prop=prop):
                    rest = [f"{p}:{v}" for j, (p, v) in enumerate(declarations) if j != i]
                    self.refused(selector + "{" + ";".join(rest) + "}", "declarations")
                    self.refused(selector + "{" + ";".join(rest + [prop + ":0"]) + "}",
                                 "declarations")

    def test_empty_and_doubled_declarations(self):
        self.refused("a:hover{}", "declarations")
        self.refused("a:hover{" + THICK + ";" + THICK + "}", "declarations")

    def test_important_refused(self):
        self.refused("a:hover{" + THICK + "!important}", "declarations")
        self.refused(".pill:hover{text-decoration:underline ! important}", "declarations")

    def test_nested_in_pseudo_class_functions(self):
        for selector in (":is(a:hover)", "a:is(:hover)", ":where(a):hover", "b:has(a:hover)",
                         "a:not(:hover)", "main:not(:hover) a", ":is(a, b:hover) c"):
            with self.subTest(selector=selector):
                self.refused(selector + "{" + THICK + "}", "closed list")

    def test_inside_at_rules(self):
        for prelude in ("@media (min-width:1px)", "@supports (display:grid)",
                        "@layer x", "@container (min-width:1px)", "@scope (main)"):
            with self.subTest(prelude=prelude):
                self.refused(prelude + "{" + OVERLAY + "}", "body:hover")
                # The allowed rule itself is allowed at the top level only.
                self.refused(prelude + "{a:hover{" + THICK + "}}", "nested")

    def test_media_query_that_names_hover(self):
        self.refused("@media (hover:hover){a{color:red}}", "closed list")

    def test_case_and_escapes(self):
        for selector in ("body:HOVER", "body:Hover", r"body:\68 over", r"body:\000068over",
                         r"body:\68over"):
            with self.subTest(selector=selector):
                self.refused(selector + "{position:fixed}", "closed list")

    def test_comments_do_not_hide_a_rule(self):
        self.refused("body:hover/**/{position:fixed}")
        self.refused("/* x */body:hover{position:fixed}")

    def test_unclosed_overlay(self):
        self.refused("body:hover .site-header{position:fixed", "closed list")

    def test_stray_braces_do_not_hide_a_rule(self):
        self.refused("}}body:hover{position:fixed}")
        self.refused("a{color:red}}body:hover{position:fixed}")

    def test_one_finding_per_rule(self):
        found = problems(OVERLAY + "main:hover{x:y}")
        self.assertEqual(len(found), 2, found)


class Wired(unittest.TestCase):
    """The check runs with the other CSS rules of the site check."""

    def test_css_rule_problems_carries_it(self):
        self.assertEqual(sitecheck.css_rule_problems(TODAY).problems, [])
        found = sitecheck.css_rule_problems(TODAY + OVERLAY).problems
        self.assertEqual(len(found), 1, found)
        self.assertIn("body:hover", found[0])

    def test_message_names_the_reason(self):
        found = problems(OVERLAY)[0]
        self.assertIn("ADR-0005 part 6", found)
        self.assertIn("Replikanti/interviewscam#55", found)



if __name__ == "__main__":
    unittest.main()
