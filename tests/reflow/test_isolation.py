"""isolation_problems in tools/sitecheck.py, the proof of the hidden capture
of the pinned regions' pixel occlusion check (Replikanti/interviewscam#39,
ADR-0005 part 6 amendment).

Run by `bash tools/selftest.sh` (suite `reflow-isolation`) as python3 -I -B
-m unittest, locally and in CI, without a browser: every case builds a
synthetic DOMSnapshot.captureSnapshot reply (strings, documents, their
nodes and layout tables) and calls the module's pure functions through
importlib. The browser rows of reflow-search pin the shape Chrome really
returns; these cases pin every branch and every member of the sets.
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


sitecheck = load("sitecheck", ROOT / "tools" / "sitecheck.py")

ELEMENT, TEXT, DOCUMENT = 1, 3, 9
# The computed style of a layout object outside a region once hidden, and
# of an ancestor that paints nothing above its descendants.
HIDDEN = {"visibility": "hidden"}
PLAIN = {"visibility": "visible"}
# Chrome's style row of a document's layout object (the LayoutView): empty,
# since a document has no computed style.
EMPTY = "empty"
DEFAULTS = {"visibility": "visible", "outline-style": "none", "text-decoration-line": "none",
            "overflow-x": "visible", "overflow-y": "visible", "resize": "none"}


class Snapshot:
    """A DOMSnapshot reply built entry by entry, in tree order."""

    def __init__(self):
        self.strings = []
        self.documents = []

    def string(self, text):
        if text not in self.strings:
            self.strings.append(text)
        return self.strings.index(text)

    def document(self):
        doc = {"nodes": {"parentIndex": [], "nodeType": [], "nodeName": [], "nodeValue": [],
                         "backendNodeId": [], "attributes": [],
                         "pseudoType": {"index": [], "value": []}},
               "layout": {"nodeIndex": [], "styles": []}}
        self.documents.append(doc)
        return doc

    def add(self, doc, parent, kind, name, backend, style=None, pseudo=None, attrs=(),
            value=None):
        """One entry; style (a dict over DEFAULTS) gives it a layout object.
        Returns its index."""
        nodes = doc["nodes"]
        index = len(nodes["parentIndex"])
        nodes["parentIndex"].append(parent)
        nodes["nodeType"].append(kind)
        nodes["nodeName"].append(self.string(name))
        nodes["nodeValue"].append(-1 if value is None else self.string(value))
        nodes["backendNodeId"].append(backend)
        nodes["attributes"].append([self.string(x) for pair in attrs for x in pair])
        if pseudo is not None:
            nodes["pseudoType"]["index"].append(index)
            nodes["pseudoType"]["value"].append(self.string(pseudo))
        if style == EMPTY:
            doc["layout"]["nodeIndex"].append(index)
            doc["layout"]["styles"].append([])
        elif style is not None:
            full = dict(DEFAULTS, **style)
            doc["layout"]["nodeIndex"].append(index)
            doc["layout"]["styles"].append(
                [-1 if full[p] is None else self.string(full[p])
                 for p in sitecheck.REFLOW_SNAPSHOT_STYLES])
        return index

    def reply(self):
        return {"documents": self.documents, "strings": self.strings}


REGION = 50


def page(main_style=None, root_style=None, sibling=HIDDEN):
    """A page as Home holds a pinned region: the document, html, head,
    body with a header, main and in main a heading and the region (a p
    with its text). Returns (snapshot, doc, indexes)."""
    snap = Snapshot()
    doc = snap.document()
    at = {}
    at["document"] = snap.add(doc, -1, DOCUMENT, "#document", 1, style=EMPTY)
    at["html"] = snap.add(doc, at["document"], ELEMENT, "HTML", 2, style=root_style or PLAIN,
                          attrs=[("lang", "en")])
    at["head"] = snap.add(doc, at["html"], ELEMENT, "HEAD", 3)
    at["body"] = snap.add(doc, at["html"], ELEMENT, "BODY", 4, style=PLAIN)
    at["header"] = snap.add(doc, at["body"], ELEMENT, "HEADER", 5, style=HIDDEN,
                            attrs=[("class", "site-header")])
    at["header-text"] = snap.add(doc, at["header"], TEXT, "#text", 6, style=HIDDEN, value="x")
    at["main"] = snap.add(doc, at["body"], ELEMENT, "MAIN", 7, style=main_style or PLAIN,
                          attrs=[("id", "main"), ("class", "container")])
    at["h1"] = snap.add(doc, at["main"], ELEMENT, "H1", 8, style=sibling,
                        attrs=[("class", "home-title")])
    at["h1-text"] = snap.add(doc, at["h1"], TEXT, "#text", 9, style=sibling, value="Title")
    at["region"] = snap.add(doc, at["main"], ELEMENT, "P", REGION, style=PLAIN,
                            attrs=[("class", "lead")])
    at["region-text"] = snap.add(doc, at["region"], TEXT, "#text", 51, style=PLAIN,
                                 value="Lead")
    return snap, doc, at


def problems(snap, region=REGION):
    return sitecheck.isolation_problems(snap.reply(), region)


class Outside(unittest.TestCase):
    def test_pass_everything_hidden(self):
        snap, _, _ = page()
        self.assertEqual(problems(snap), [])

    def test_visible_element(self):
        snap, _, _ = page(sibling=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["h1.home-title",
                                                       "h1.home-title (its text)"])])

    def test_hidden_values_accepted(self):
        for value in ("hidden", "collapse"):
            with self.subTest(value=value):
                snap, _, _ = page(sibling={"visibility": value})
                self.assertEqual(problems(snap), [])

    def test_collapse_is_hidden(self):
        self.assertIn("collapse", sitecheck.REFLOW_HIDDEN_VISIBILITY)
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "::after", 60, style={"visibility": "collapse"},
                 pseudo="after")
        self.assertEqual(problems(snap), [])

    def test_visible_refused(self):
        self.assertNotIn("visible", sitecheck.REFLOW_HIDDEN_VISIBILITY)
        self.assertEqual(sitecheck.REFLOW_HIDDEN_VISIBILITY, frozenset({"hidden", "collapse"}))

    def test_pseudo_element_stays_visible(self):
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "::after", 60, style=PLAIN, pseudo="after")
        self.assertEqual(problems(snap), [("outside", ["header.site-header::after"])])

    def test_shadow_content_outside(self):
        snap, doc, at = page()
        root = snap.add(doc, at["header"], 11, "#document-fragment", 61)
        snap.add(doc, root, ELEMENT, "DIV", 62, style=PLAIN, attrs=[("id", "placeholder")])
        self.assertEqual(problems(snap), [("outside", ["div#placeholder"])])

    def test_head_shown(self):
        snap, doc, at = page()
        snap.add(doc, at["head"], ELEMENT, "TITLE", 63, style=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["title"])])

    def test_nested_document(self):
        snap, doc, at = page()
        snap.add(doc, at["header"], ELEMENT, "IFRAME", 64, style=HIDDEN)
        inner = snap.document()
        top = snap.add(inner, -1, DOCUMENT, "#document", 65, style=PLAIN)
        snap.add(inner, top, ELEMENT, "svg", 66, style=PLAIN)
        self.assertEqual(problems(snap), [("outside", ["#document in a nested document",
                                                       "svg in a nested document"])])

    def test_nested_document_without_style(self):
        snap, _, _ = page()
        inner = snap.document()
        snap.add(inner, -1, DOCUMENT, "#document", 65, style=EMPTY)
        self.assertEqual(problems(snap), [("outside", ["#document in a nested document"])])

    def test_nested_document_text_label(self):
        snap, doc, at = page()
        inner = snap.document()
        top = snap.add(inner, -1, DOCUMENT, "#document", 65)
        body = snap.add(inner, top, ELEMENT, "BODY", 66, style=HIDDEN)
        snap.add(inner, body, TEXT, "#text", 67, style=PLAIN, value="x")
        self.assertEqual(problems(snap), [("outside", ["body (its text) in a nested document"])])

    def test_region_subtree_ignored(self):
        snap, doc, at = page()
        snap.add(doc, at["region"], ELEMENT, "::before", 70, style=PLAIN, pseudo="before")
        span = snap.add(doc, at["region"], ELEMENT, "SPAN", 71, style=PLAIN)
        root = snap.add(doc, span, 11, "#document-fragment", 72)
        snap.add(doc, root, ELEMENT, "DIV", 73, style=PLAIN)
        self.assertEqual(problems(snap), [])

    def test_element_sibling_of_region_is_outside(self):
        snap, doc, at = page()
        snap.add(doc, at["main"], ELEMENT, "DIV", 74, style=PLAIN, attrs=[("class", "a b")])
        self.assertEqual(problems(snap), [("outside", ["div.a.b"])])

    def test_one_entry_per_layout_owner(self):
        snap, doc, at = page()
        after = snap.add(doc, at["header"], ELEMENT, "::after", 60, style=PLAIN, pseudo="after")
        doc["layout"]["nodeIndex"].append(after)
        doc["layout"]["styles"].append(doc["layout"]["styles"][-1])
        self.assertEqual(problems(snap), [("outside", ["header.site-header::after"])])


class Ancestors(unittest.TestCase):
    def test_ancestor_text_any_character(self):
        for char in (" ", " ", "​", "　", "﻿", "stray"):
            with self.subTest(char=ascii(char)):
                snap, doc, at = page()
                snap.add(doc, at["main"], TEXT, "#text", 80, style=PLAIN, value=char)
                self.assertEqual(problems(snap),
                                 [("ancestor", ["main#main.container (its text)"])])

    def test_unrendered_text_ignored(self):
        snap, doc, at = page()
        snap.add(doc, at["main"], TEXT, "#text", 80, value=" ")
        snap.add(doc, at["body"], TEXT, "#text", 81, value="\n")
        self.assertEqual(problems(snap), [])

    def test_ancestor_pseudo_elements(self):
        for kind in ("before", "after", "marker", "first-letter", "check",
                     "backdrop"):
            with self.subTest(kind=kind):
                snap, doc, at = page()
                snap.add(doc, at["main"], ELEMENT, "::" + kind, 82, style=PLAIN, pseudo=kind)
                self.assertEqual(problems(snap),
                                 [("ancestor", [f"main#main.container::{kind}"])])

    def test_ancestor_pseudo_hidden_still_counts(self):
        snap, doc, at = page()
        snap.add(doc, at["body"], ELEMENT, "::before", 83, style=HIDDEN, pseudo="before")
        self.assertEqual(problems(snap), [("ancestor", ["body::before"])])

    def test_document_children(self):
        snap, doc, at = page()
        snap.add(doc, at["html"], TEXT, "#text", 84, style=PLAIN, value="x")
        self.assertEqual(problems(snap), [("ancestor", ["html (its text)"])])

    def test_document_node_not_a_finding(self):
        # The LayoutView (the document's layout object) is in every chain,
        # with Chrome's empty style row, or with a style that is visible
        # and a scroll container: neither an outside box nor ancestor paint.
        snap, _, _ = page()
        self.assertEqual(problems(snap), [])
        snap, doc, _ = page()
        doc["layout"]["styles"][0] = [snap.string(v) for v in (
            "visible", "none", "none", "auto", "auto", "none")]
        self.assertEqual(problems(snap), [])

    def test_unreadable_property_fails_closed(self):
        # Chrome writes -1 for a property it cannot read; no rule accepts it.
        snap, _, _ = page(sibling={"visibility": None})
        self.assertEqual(problems(snap), [("outside", ["h1.home-title",
                                                       "h1.home-title (its text)"])])
        snap, _, _ = page(main_style={"resize": None})
        self.assertEqual(problems(snap), [("paint", ["main#main.container resize "])])


class AncestorPaint(unittest.TestCase):
    def paint(self, style, **where):
        snap, _, _ = page(**{where.get("on", "main_style"): dict(PLAIN, **style)})
        return problems(snap)

    def test_each_member(self):
        for prop, value in (("outline-style", "solid"), ("outline-style", "auto"),
                            ("text-decoration-line", "underline"),
                            ("text-decoration-line", "line-through"),
                            ("overflow-x", "scroll"), ("overflow-x", "auto"),
                            ("overflow-y", "scroll"), ("overflow-y", "auto"),
                            ("resize", "both"), ("resize", "vertical")):
            with self.subTest(prop=prop, value=value):
                self.assertEqual(self.paint({prop: value}),
                                 [("paint", [f"main#main.container {prop} {value}"])])

    def test_overflow_without_scroll_bar_passes(self):
        for axis in ("overflow-x", "overflow-y"):
            for value in ("hidden", "clip", "visible"):
                with self.subTest(axis=axis, value=value):
                    self.assertEqual(self.paint({axis: value}), [])

    def test_scrollbar_set(self):
        self.assertEqual(sitecheck.REFLOW_SCROLLBAR_OVERFLOW, frozenset({"scroll", "auto"}))

    def test_styles_read(self):
        self.assertEqual(sitecheck.REFLOW_SNAPSHOT_STYLES,
                         ("visibility", "outline-style", "text-decoration-line",
                          "overflow-x", "overflow-y", "resize"))

    def test_outline_on_root(self):
        self.assertEqual(self.paint({"outline-style": "dashed"}, on="root_style"),
                         [("paint", ["html outline-style dashed"])])

    def test_two_properties_two_items(self):
        self.assertEqual(self.paint({"outline-style": "solid", "resize": "both"}),
                         [("paint", ["main#main.container outline-style solid",
                                     "main#main.container resize both"])])

    def test_outside_element_paint_not_read(self):
        snap, doc, at = page(sibling=dict(HIDDEN, **{"outline-style": "solid"}))
        self.assertEqual(problems(snap), [])

    def test_region_paint_not_read(self):
        snap, doc, at = page()
        snap.add(doc, at["region"], ELEMENT, "SPAN", 90,
                 style=dict(PLAIN, **{"outline-style": "solid"}))
        self.assertEqual(problems(snap), [])

    def test_all_kinds_together(self):
        snap, doc, at = page(main_style=dict(PLAIN, **{"outline-style": "solid"}),
                             sibling=PLAIN)
        snap.add(doc, at["main"], TEXT, "#text", 80, style=PLAIN, value="x")
        self.assertEqual([kind for kind, _ in problems(snap)], ["outside", "ancestor", "paint"])


class Broken(unittest.TestCase):
    def assertBroken(self, reply, region=REGION, why=""):
        got = sitecheck.isolation_problems(reply, region)
        self.assertEqual(len(got), 1, got)
        self.assertEqual(got[0][0], "broken")
        self.assertIn(why, got[0][1][0])

    def test_region_missing(self):
        snap, _, _ = page()
        self.assertBroken(snap.reply(), region=999, why="the region is not in it")
        self.assertBroken(snap.reply(), region=None, why="the region is not in it")
        self.assertBroken(snap.reply(), region=True, why="the region is not in it")

    def test_malformed_snapshot(self):
        def edited(change):
            snap, doc, _ = page()
            reply = snap.reply()
            change(reply, doc)
            return reply

        cases = {
            "not an object": lambda r, d: r.clear() or r.update(x=1),
            "strings missing": lambda r, d: r.pop("strings"),
            "strings not text": lambda r, d: r["strings"].append(1),
            "documents empty": lambda r, d: r.update(documents=[]),
            "documents not a list": lambda r, d: r.update(documents={}),
            "a document not an object": lambda r, d: r["documents"].append(1),
            "nodes missing": lambda r, d: d.pop("nodes"),
            "layout missing": lambda r, d: d.pop("layout"),
            "parentIndex missing": lambda r, d: d["nodes"].pop("parentIndex"),
            "nodeType short": lambda r, d: d["nodes"]["nodeType"].pop(),
            "nodeName long": lambda r, d: d["nodes"]["nodeName"].append(0),
            "backendNodeId missing": lambda r, d: d["nodes"].pop("backendNodeId"),
            "a bool for an int": lambda r, d: d["nodes"]["nodeType"].__setitem__(0, True),
            "a float for an int": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 0.0),
            "parent after child": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 5),
            "parent is self": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, 1),
            "parent below -1": lambda r, d: d["nodes"]["parentIndex"].__setitem__(1, -2),
            "name out of range": lambda r, d: d["nodes"]["nodeName"].__setitem__(1, 999),
            "name negative": lambda r, d: d["nodes"]["nodeName"].__setitem__(1, -1),
            "layout entry out of range": lambda r, d: d["layout"]["nodeIndex"].__setitem__(0, 999),
            "styles short": lambda r, d: d["layout"]["styles"].pop(),
            "a style row short": lambda r, d: d["layout"]["styles"][1].pop(),
            "a style out of range": lambda r, d: d["layout"]["styles"][1].__setitem__(0, 999),
            "styles not a list": lambda r, d: d["layout"].update(styles={}),
            "an element without a style": lambda r, d: d["layout"]["styles"].__setitem__(1, []),
            "a style below -1": lambda r, d: d["layout"]["styles"][1].__setitem__(0, -2),
            "pseudoType not an object": lambda r, d: d["nodes"].update(pseudoType=[]),
            "pseudoType lengths": lambda r, d: d["nodes"]["pseudoType"]["index"].append(1),
            "pseudoType out of range": lambda r, d: d["nodes"].update(
                pseudoType={"index": [999], "value": [0]}),
            "attributes odd": lambda r, d: d["nodes"]["attributes"][1].append(0),
            "attributes short": lambda r, d: d["nodes"]["attributes"].pop(),
            "attributes not a list": lambda r, d: d["nodes"].update(attributes={}),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                self.assertBroken(edited(change), why="the DOM snapshot cannot be read")
        for reply in (None, [], "x", 1):
            with self.subTest(reply=reply):
                self.assertBroken(reply, why="the DOM snapshot cannot be read")

    def test_optional_tables_absent(self):
        snap, doc, _ = page(sibling=PLAIN)
        doc["nodes"].pop("pseudoType")
        doc["nodes"].pop("attributes")
        self.assertEqual(problems(snap), [("outside", ["h1", "h1 (its text)"])])


class Messages(unittest.TestCase):
    def test_named_cap(self):
        items = [f"div{i}" for i in range(12)]
        text = sitecheck.isolation_message("outside", items, "a region")
        self.assertIn("'div9' and 2 more (12 in all)", text)
        self.assertNotIn("'div10'", text)
        self.assertEqual(sitecheck.REFLOW_NAMED, 10)

    def test_named_at_cap(self):
        text = sitecheck.reflow_named([f"div{i}" for i in range(10)])
        self.assertTrue(text.endswith("'div9' (10 in all)"), text)

    def test_prefixes(self):
        for kind, prefix in (("broken", "(isolation) "), ("outside", "(isolation) "),
                             ("ancestor", "(isolation) "), ("paint", "(ancestor paint) ")):
            with self.subTest(kind=kind):
                self.assertTrue(sitecheck.isolation_message(kind, ["x"], "r").startswith(prefix))
        self.assertTrue(sitecheck.reflow_animation_message("after the hiding", "r", ["a"])
                        .startswith("(animation) after the hiding of r"))

    def test_names_defanged(self):
        text = sitecheck.isolation_message("outside", ["p.lead"], "r")
        self.assertIn("'p[.]lead' (1 in all)", text)


if __name__ == "__main__":
    unittest.main()
