"""The stop of reflow case (8) at its first (8a) finding, in search_case of
tools/sitecheck.py (Replikanti/interviewscam#47).

Why it exists: once a query leaves Home, the case has failed, and every
later query would navigate and load Home again, or wait REFLOW_TIMEOUT
for a fetch that never starts when the script is inert. A run that goes
on after the first (8a) still fails, so no reflow-search row tells the
two apart; only the time does (about 7050 s for a row with an inert
script), and a sweep reports such a mutant as TIMEOUT, never as a kill.
These cases count what the case does after its first (8a) instead.

Run by `bash tools/selftest.sh` (suite `reflow-isolation`, which discovers
tests/reflow) as python3 -I -B -m unittest, locally and in CI, without a
browser: a fake DevTools client answers search_case on the real tree of
tests/fixtures/reflow/pass-search, and its page leaves Home for /a-z/ on
every tap. The page scripts are replaced by tags, so the fake knows which
one search_case evaluates. The reflow-search rows pin what Chrome does.
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / "tests" / "fixtures" / "reflow" / "pass-search"
ORIGIN = "http://127.0.0.1:9"
SESSION = "page-session"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sitecheck = load("sitecheck_search_stop", ROOT / "tools" / "sitecheck.py")

# Each page script search_case evaluates, as a tag the fake reads back
# (the format keys of the real scripts kept, so the % formatting works).
SCRIPTS = {
    "SEARCH_SETUP_SCRIPT": "setup %(marker)s %(ids)s",
    "SEARCH_STATE_SCRIPT": "state %(ids)s %(marker)s",
    "SEARCH_DOUBLE_SCRIPT": "double %(first)s %(second)s",
    "SEARCH_FOCUS_SCRIPT": "focus",
    "SEARCH_BUTTON_SCRIPT": "button",
    "SEARCH_A_Z_SCRIPT": "a-z",
}


class FakeTools:
    """The DevTools calls search_case makes, on a page that leaves Home for
    /a-z/ on every tap (the script hands every query over, or the form
    submits without it). Home fetches the feed on the first focus after a
    load, as the real script does."""

    def __init__(self):
        self.events = []
        self.path = None
        self.fresh = False
        self.taps = 0
        self.typed = []
        self.pending = None

    def load(self, url):
        self.path = url[len(ORIGIN):] or "/"
        self.fresh = self.path == "/"
        return None

    def event(self, method, **params):
        self.events.append({"method": method, "sessionId": SESSION, "params": params})

    def evaluate(self, expression):
        tag = expression.split(" ", 1)[0]
        if tag == "a-z":
            return {"entries": []}
        if tag == "setup":
            return {"form": True, "sections": {}}
        if tag == "focus":
            if self.path == "/" and self.fresh:
                self.fresh = False
                self.event("Network.requestWillBeSent",
                           request={"url": ORIGIN + "/" + sitecheck.SEARCH_FEED_REL})
            return {"focused": True}
        if tag == "button":
            return {"hit": True, "x": 10, "y": 10}
        if tag == "state":
            if self.path != "/":
                return {"path": self.path}
            return {"marker": True, "submits": 2, "busy": False, "reveals": [],
                    "shown": ["search-none"]}
        return {}

    def send(self, method, params=None, session=None, budget=None):
        params = params or {}
        if method == "Runtime.evaluate":
            return {"result": {"value": self.evaluate(params["expression"])}}
        if method == "Input.insertText":
            self.typed.append(params["text"])
        if method == "Input.dispatchMouseEvent" and params.get("type") == "mouseReleased":
            self.taps += 1
            if self.path == "/":
                self.event("Page.frameRequestedNavigation", url=ORIGIN + sitecheck.A_Z_PATH)
                self.path = sitecheck.A_Z_PATH
                self.event("Page.loadEventFired")
        return {}

    def _write(self, method, params, session):
        self.pending = params["expression"]

    def _answer(self, method, budget, ticks=None, on_wait=None):
        return {"result": {"value": self.evaluate(self.pending)}}

    def wait_event(self, method, session):
        for event in self.events:
            if event.get("method") == method:
                self.events.remove(event)
                return event
        raise sitecheck.NoAnswerError("no event")


def run_case():
    tools = FakeTools()
    findings = sitecheck.Findings()
    patches = [mock.patch.object(sitecheck, name, value) for name, value in SCRIPTS.items()]
    patches.append(mock.patch.object(sitecheck, "REFLOW_TIMEOUT", 2))
    for patch in patches:
        patch.start()
    try:
        summary = sitecheck.search_case(tools, SESSION, findings, TREE, ORIGIN, tools.load)
    finally:
        for patch in patches:
            patch.stop()
    return tools, findings, summary


def leading_handovers():
    """How many queries of the tree come before its first query that does
    not hand over, and that query."""
    feed = json.loads((TREE / sitecheck.SEARCH_FEED_REL).read_text(encoding="utf-8"))
    paths = sitecheck.a_z_paths((TREE / sitecheck.SEARCH_A_Z_REL).read_text(encoding="utf-8"))
    index = sitecheck.oracle_index(feed, paths)
    queries = sitecheck.search_queries(feed)
    for n, query in enumerate(queries):
        if sitecheck.search_expect(index, query)[0] != "handover":
            return n, query, len(queries)
    raise AssertionError("every query of the tree hands over")


class FirstLeaveStops(unittest.TestCase):
    def test_tree_has_queries_after_the_first_leave(self):
        # The cases below prove the stop only if the tree has later queries.
        n, _, total = leading_handovers()
        self.assertGreater(total - n - 1, 100)

    def test_one_8a_finding(self):
        _, findings, _ = run_case()
        found = [f for f in findings.items if ": (8a) query " in f]
        self.assertEqual(len(found), 1, found[:3])
        self.assertTrue(found[0].endswith("the later queries are not run"), found[0])

    def test_no_query_after_the_first_leave(self):
        n, query, _ = leading_handovers()
        tools, findings, _ = run_case()
        # One tap per query up to the first that leaves Home; the double
        # submit after the loop taps nothing.
        self.assertEqual(tools.taps, n + 1, findings.items[:3])
        self.assertEqual(tools.typed[-1:], [query] if query else [])

    def test_the_finding_names_the_first_leave(self):
        _, query, _ = leading_handovers()
        _, findings, _ = run_case()
        found = [f for f in findings.items if ": (8a) query " in f]
        self.assertIn(f"(8a) query {sitecheck.show(query, 80)} left Home", found[0])


if __name__ == "__main__":
    unittest.main()
