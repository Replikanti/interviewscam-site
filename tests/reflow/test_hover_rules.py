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


class NestedInAllowed(unittest.TestCase):
    """A rule inside an allowed :hover rule has no :hover of its own, and the
    outer rule keeps exactly its pinned declaration, so only the enclosing
    block tells that the nested rule applies while the pointer is on the
    page (review run 2, finding 2)."""

    NESTED = (":root:has(&) main h2{opacity:0}", "& b{opacity:0}", "b{opacity:0}",
              ":root:has(&) main{position:fixed}", "&::after{content:'x'}")

    def test_nested_rule_without_hover(self):
        for selector, declarations in sitecheck.HOVER_RULES.items():
            body = ";".join(f"{p}:{v}" for p, v in declarations)
            for nested in self.NESTED:
                with self.subTest(selector=selector, nested=nested):
                    found = problems(selector + "{" + body + ";" + nested + "}")
                    self.assertTrue(found)
                    self.assertTrue(any("nested in another block" in item for item in found),
                                    found)

    def test_nested_rule_after_the_declarations(self):
        found = problems("a:hover{" + THICK + ";:root:has(&) main h2{opacity:0}}")
        self.assertEqual(len(found), 1, found)
        self.assertIn(":root:has(&)", found[0].replace("[:]", ":"))

    def test_allowed_rule_without_nesting_is_one_rule(self):
        self.assertEqual(problems("a:hover{" + THICK + "}main h2{opacity:0}"), [])


class CommentBlind(unittest.TestCase):
    """A comment is no token to a browser: `:/**/hover` is `:hover`, while
    css_rules turns a comment into a space (QA recheck, row 1)."""

    def test_comment_inside_the_pseudo_class(self):
        for selector in ("body:/**/hover", ".x:/* c */hover", "body:/**/HOVER",
                         "body:/*\n*/hover", ":is(body:/**/hover)", "body/**/:hover",
                         "body:hov/**/er"):
            with self.subTest(selector=selector):
                found = problems(selector + "{position:fixed}")
                # (body:hov/**/er is refused too: fail closed on any form
                # that reads as :hover once the comment is gone.)
                self.assertTrue(found, selector)

    def test_comment_in_a_declaration_of_an_allowed_rule(self):
        self.assertEqual(problems("a:hover{text-decoration-thickness:/**/var(--underline-hover-thickness)/**/}"), [])
        self.assertTrue(problems("a:hover{text-decoration-thickness:var(--underline-hover-thickness);position/**/:fixed}"))

    def test_allowed_selector_with_a_comment_is_the_allowed_rule(self):
        self.assertEqual(problems("a:/**/hover{" + THICK + "}"), [])

    def test_comment_hides_nothing_in_a_string(self):
        self.assertEqual(problems("a{content:'/* :hover */'}"), [])

    def test_comment_opener_in_a_string_starts_no_comment(self):
        self.assertTrue(problems("a{content:'/*'}body:hover{position:fixed}"))
        self.assertTrue(problems('a{content:"/*"}body:hover{position:fixed}'))
        self.assertEqual(problems("a{content:'*/'}b{x:y}"), [])

    def test_unterminated_comment(self):
        self.assertEqual(problems(TODAY + "/* body:hover{position:fixed}"), [])
        self.assertTrue(problems("body:/**/hover{position:fixed}/* x"))


class Variables(unittest.TestCase):
    """The custom properties the allowed rules read are pinned (review run
    2, finding 1): any rule can redefine one, and `main{--x:5em}` turns the
    allowed rule's pinned declaration into a band over the page."""

    VAR = "--underline-hover-thickness"

    def test_the_pinned_variables_are_those_the_list_reads(self):
        self.assertEqual(sitecheck.HOVER_VARS, {self.VAR: "2px"})
        read = {name for declarations in sitecheck.HOVER_RULES.values()
                for _, value in declarations for name in sitecheck.HOVER_VAR.findall(value)}
        self.assertEqual(set(sitecheck.HOVER_VARS), read)

    def test_the_token_declaration_passes(self):
        self.assertEqual(problems(TODAY + ":root{--color-x:red;" + self.VAR + ":2px}"), [])
        self.assertEqual(problems(":root{--underline-hover-thickness : 2px }"), [])
        self.assertEqual(problems(":root{--underline-hover-thickness:2px}"
                                  ":root{--underline-hover-thickness:2px}"), [])
        self.assertEqual(problems(TODAY), [])

    def test_other_custom_properties_are_free(self):
        self.assertEqual(problems("main{--other:5em}:root{--underline-thickness:9em}"), [])

    def refused(self, css, *words):
        found = problems(css)
        self.assertEqual(len(found), 1, (css, found))
        for word in words:
            self.assertIn(word, found[0])

    def test_review_example(self):
        self.refused(TODAY + "main{--underline-hover-thickness:5em}"
                     "main a{text-decoration-color:var(--color-text)}", "read by the :hover")

    def test_other_selector_or_value(self):
        for css in ("main{--underline-hover-thickness:2px}",
                    ":root{--underline-hover-thickness:5em}",
                    ":root{--underline-hover-thickness:3px}",
                    ":root{--underline-hover-thickness:20px}",
                    ":root,main{--underline-hover-thickness:2px}",
                    "html{--underline-hover-thickness:2px}",
                    ":root main{--underline-hover-thickness:2px}",
                    ":root:hover{--underline-hover-thickness:2px}",
                    ":root{--underline-hover-thickness:var(--x)}",
                    ":root{--underline-hover-thickness:2px!important}",
                    ":root{--underline-hover-thickness:}"):
            with self.subTest(css=css):
                self.assertTrue(problems(css), css)

    def test_nested_or_at_rule(self):
        for css in ("@media (min-width:1px){:root{--underline-hover-thickness:2px}}",
                    "@layer x{:root{--underline-hover-thickness:2px}}",
                    "@supports (display:grid){:root{--underline-hover-thickness:2px}}",
                    "main{color:red;--underline-hover-thickness:5em}",
                    "main{& a{--underline-hover-thickness:5em}}",
                    ":root{& main{--underline-hover-thickness:2px}}",
                    "@scope (main){:scope{--underline-hover-thickness:5em}}"):
            with self.subTest(css=css):
                self.assertTrue(problems(css), css)

    def test_registered_property(self):
        # A registered property with inherits:false gives every element but
        # the root its own initial value, whatever :root declares.
        self.refused("@property --underline-hover-thickness{syntax:'<length>';"
                     "inherits:false;initial-value:5em}", "registered")
        self.refused("@property   --Underline-Hover-Thickness {syntax:'*';inherits:true}",
                     "registered")

    def test_name_forms(self):
        for name in (r"--underline-hover-thickn\65 ss", r"--underline-hover-thickness /**/",
                     "--UNDERLINE-HOVER-THICKNESS", "--underline-hover-thickness"):
            with self.subTest(name=name):
                self.assertTrue(problems("main{" + name + ":5em}"), name)

    def test_comment_between_name_and_colon(self):
        self.assertTrue(problems("main{--underline-hover-thickness/**/:5em}"))

    def test_important_in_the_token_rule(self):
        self.refused(":root{--underline-hover-thickness:2px !important}", "read by the :hover")

    def test_one_finding_per_declaration(self):
        found = problems("main{--underline-hover-thickness:5em}"
                         "aside{--underline-hover-thickness:6em}")
        self.assertEqual(len(found), 2, found)

    def test_wired_into_the_site_rules(self):
        found = sitecheck.css_rule_problems(TODAY + "main{--underline-hover-thickness:5em}").problems
        # The custom property rule (Replikanti/interviewscam#34) refuses the
        # rule outside :root too; this case counts the :hover list's finding.
        hover = [item for item in found if "read by the :hover rules" in item]
        self.assertEqual(len(hover), 1, found)
        self.assertEqual(len(found), 2, found)


class Unreadable(unittest.TestCase):
    """The built stylesheet is refused when it holds a newline or an unquoted
    url( that a browser tokenizes differently from css_rules (review run 3):
    a browser ends a string at an unescaped newline, css_rules runs it on to
    the next quote, so a rule can hide between two such strings; an unquoted
    url( with a ( inside is a bad url that ends at the first ), while
    css_rules counts the inner ( and stays inside parentheses. The refusal is
    on the whole sheet, so the older rules (.visually-hidden, !important,
    [hidden]) are covered too."""

    HIDDEN = "main:has(a:hover) h2{opacity:0}"

    def refusal(self, css):
        return [item for item in sitecheck.css_rule_problems(css).problems
                if "browser" in item and "built stylesheet" in item]

    def test_review_string_forms(self):
        for quote in ('"', "'"):
            css = (TODAY + ".x{font-family:" + quote + "a\n}" + self.HIDDEN
                   + ".y{font-family:" + quote + "b\n}")
            with self.subTest(quote=quote):
                # What the checker alone sees: nothing (the rule is inside a string).
                self.assertEqual(problems(css), [])
                found = sitecheck.css_rule_problems(css).problems
                self.assertEqual(len(found), 1, found)
                self.assertIn("newline", found[0])

    def test_review_custom_property_form(self):
        css = (TODAY + '.x{font-family:"a\n}main{--underline-hover-thickness:5em}'
               '.y{font-family:"b\n}')
        self.assertEqual(len(sitecheck.css_rule_problems(css).problems), 1)

    def test_review_url_form(self):
        css = (TODAY + ".x{background-image:url(a(b)}" + self.HIDDEN
               + ".y{width:calc(1px)}.z{grid-area:a)}")
        self.assertEqual(problems(css), [])
        found = sitecheck.css_rule_problems(css).problems
        self.assertEqual(len(found), 1, found)
        self.assertIn("url(", found[0])

    def test_each_newline_character(self):
        for name, char in (("LF", "\n"), ("CR", "\r"), ("FF", "\f"), ("CRLF", "\r\n")):
            for where in ("a{x:y}" + char + "b{x:y}", "a{x:'" + char + "'}", "a{" + char + "x:y}",
                          "/* c" + char + "d */a{x:y}", TODAY + char + "a{x:y}"):
                with self.subTest(char=name, css=where):
                    found = self.refusal(where)
                    self.assertEqual(len(found), 1, found)
                    self.assertIn("newline", found[0])

    def test_a_final_newline_is_not_counted(self):
        for tail in ("\n", "\r\n", "\n\n\f"):
            with self.subTest(tail=repr(tail)):
                self.assertEqual(self.refusal(TODAY + tail), [])
        self.assertEqual(len(self.refusal(TODAY + "\n" + TODAY)), 1)
        self.assertEqual(len(self.refusal("a{x:'" + "\n" + "'}")), 1)

    def test_other_whitespace_is_not_a_newline(self):
        for char in (" ", "\t", "\v", "\u2028", "\u0085"):
            with self.subTest(char=repr(char)):
                self.assertEqual(self.refusal("a{x:y}" + char + "b{x:y}"), [])

    def test_a_one_line_sheet_passes(self):
        self.assertEqual(sitecheck.css_rule_problems(TODAY).problems, [])
        self.assertEqual(self.refusal(""), [])

    def test_bad_unquoted_urls(self):
        for body in ("a(b", 'a"b', "a'b", "a b", " a b ", "a\tb", "a\x01b", "a(b)c",
                     "a\\b", "a\\", "a", "(", "a(b(c"):
            for head in ("url(", "URL(", "Url(", "background:url("):
                css = "x{" + (head if head.startswith("background") else "background:" + head) + body
                # the url is closed at the first ) as the browser does, or not at all
                css += ")}" if body not in ("a", "(", "a(b(c") else "}"
                with self.subTest(css=css):
                    found = self.refusal(css)
                    self.assertEqual(len(found), 1, (css, found))
                    self.assertIn("url(", found[0])

    def test_unterminated_url_is_refused(self):
        self.assertEqual(len(self.refusal("x{background:url(a.png")), 1)

    def test_good_urls_pass(self):
        for body in ("a.png", " a.png ", "a/b.png?x=1#y", '"a(b"', "'a b'", ' "a b" ',
                     "data:image/png;base64,AAAA"):
            with self.subTest(body=body):
                self.assertEqual(self.refusal("x{background:url(" + body + ")}"), [])

    def test_url_inside_another_word_is_not_a_url(self):
        for word in ("curl(a(b)", "x-url(a(b)", "url2(a(b)", "myurl(a b)"):
            with self.subTest(word=word):
                self.assertEqual(self.refusal("x{y:" + word + "}"), [])

    def test_two_forms_two_findings(self):
        found = sitecheck.css_rule_problems("a{x:'\n'}b{y:url(a(b)}").problems
        self.assertEqual(len(found), 2, found)

    def test_one_finding_per_form(self):
        found = self.refusal("a{x:'\n'}b{y:'\n'}\n\n")
        self.assertEqual(len(found), 1, found)
        found = self.refusal("a{y:url(a(b)}b{y:url(c d)}")
        self.assertEqual(len(found), 1, found)

    def test_older_rules_are_covered_by_the_same_refusal(self):
        # The .visually-hidden definition after a string that runs across a
        # newline: the refusal fires whatever the other rules say.
        found = sitecheck.css_rule_problems(".x{content:'\n}.visually-hidden{x:y}.y{content:'\n}")
        self.assertTrue(any("newline" in item for item in found.problems))


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
