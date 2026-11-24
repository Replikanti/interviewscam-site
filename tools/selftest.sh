#!/usr/bin/env bash
# Self-test: prove every check fires in both directions.
#
# For every tests/fixtures/<check>/<pass|fail>-<case>/ it runs the matching
# check on that directory, with the same function tools/check.sh uses:
#   pass-<case>  must exit 0.
#   fail-<case>  must exit non-zero AND print the substring in its
#                expect.txt, so a check that fails for the wrong reason
#                (a crash, a missing tool) does not count as a pass.
#   A pass-<case> with an expect.txt must also print that substring, so a
#   pass that checked nothing (zero records, zero artifacts) is caught.
#
# html fixtures need the Nu Html Checker and reflow fixtures the runner's
# Google Chrome, which run only in CI (GITHUB_ACTIONS=true; ADR-0002 part 1,
# ADR-0003 part 6). Outside CI they print the NOT RUN line; in CI the
# self-test fails unless every html and every reflow fixture ran.
#
# Usage: bash tools/selftest.sh [--only SUITE[,SUITE...]]
#
# --only runs the named suites alone (Replikanti/interviewscam#40, ADR-0008
# part 4); a suite is the first path segment of the rows it prints. CI
# always runs every suite (wiring/selftest-no-args).

SELFTEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/check.sh
source "$SELFTEST_ROOT/tools/check.sh"

FIXTURES="$SELFTEST_ROOT/tests/fixtures"
# The version the synthetic Lighthouse reports in tests/fixtures/lighthouse/
# carry. Fixed, not the pin, so a Lighthouse upgrade does not touch them.
LIGHTHOUSE_FIXTURE_VERSION=13.6.0

# guard_env <fixture dir>: read <dir>/env.txt into GUARD_ENV. Only HUGO_*
# assignments are accepted (any name Hugo reads, with a delimiter other than
# _ too), so a fixture cannot change anything else.
guard_env() {
  GUARD_ENV=()
  [[ -f "$1/env.txt" ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^HUGO[^=]+= ]] || return 1
    GUARD_ENV+=("$line")
  done < "$1/env.txt"
}

# launch_dump_has <output> <attempt> <line>: the Chrome log dump of that
# launch in sitecheck reflow's output (from its "reflow: Chrome log of
# launch N of 2 (" header to the next "reflow: " line) contains the line.
launch_dump_has() {
  awk -v head="reflow: Chrome log of launch $2 of 2 (" -v want="$3" '
    index($0, head) == 1 { on = 1; next }
    on && index($0, "reflow: ") == 1 { on = 0 }
    on && $0 == want { found = 1 }
    END { exit !found }' "$1"
}

# logs_moved <path log> <glob>: the stub logged exactly two log files (its
# stderr on each launch), each matches the glob, and the directory of each
# is gone now that sitecheck reflow has returned.
logs_moved() {
  local log n=0
  [[ -f "$1" ]] || return 1
  while read -r log; do
    # shellcheck disable=SC2053 # $2 is a glob pattern on purpose
    [[ "$log" == $2 && ! -e "${log%/*}" ]] || return 1
    n=$((n + 1))
  done <"$1"
  [[ $n -eq 2 ]]
}

# members_runner <sitecheck.py> <members table>: runs every row of the table
# through the real cmd_literals and checks coverage (literals-members lines
# below). LITERALS_MEMBERS_COVERAGE_ONLY=1 checks coverage alone. -B: no
# tools/__pycache__.
members_runner() {
  python3 -I -B - "$1" "$2" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import os
import re
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)

# A row whose set is `+` adds one more file (its file and content columns)
# to the row above it, for a case that needs a partial (M3 PR 9 fix round 1).
rows, extra = [], {}
for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    if line and not line.startswith("#"):
        row = line.split("\t")
        if row[0] == "+" and len(row) == 6 and rows:
            extra.setdefault(id(rows[-1]), []).append((row[2], row[3]))
        else:
            rows.append(row)
covered = {}
for row in rows:
    if len(row) != 6 or row[0] == "+":
        print(f"FAIL literals-members/table: malformed row {row!r}")
        continue
    set_name, member, rel, content, expect, count = row
    covered.setdefault(set_name, set()).add(member)
    if os.environ.get("LITERALS_MEMBERS_COVERAGE_ONLY"):
        continue
    name = f"literals-members/{set_name}/{member}"
    with tempfile.TemporaryDirectory() as root:
        for file_rel, file_content in [(rel, content)] + extra.get(id(row), []):
            path = Path(root) / file_rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(file_content + "\n", encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = sitecheck.cmd_literals(argparse.Namespace(root=root))
    output = buffer.getvalue()
    findings = sum(line.startswith("FAIL: ") for line in output.splitlines())
    if rc == 1 and expect in output and findings == int(count):
        print(f"ok   {name} (failed as expected: {expect})")
    else:
        print(f"FAIL {name}: expected exit 1, {count} finding(s) and '{expect}'; "
              f"got exit {rc}, {findings} finding(s); output:")
        for out_line in output.splitlines():
            print(f"     | {out_line}")
# The flagging sets, taken from the code, and their pinned numbers.
EXPECTED_FLAGGING_SETS = 19
EXPECTED_PASSING_SETS = 35
EXPECTED_DERIVED_MEMBERS = {"RAWTEXT_END_TAG": 10, "LITERALS_META_PLAIN_NAMES": 3,
                            "LITERALS_META_PLAIN_HTTP_EQUIV": 1, "PAGE_MEMBERS": 16,
                            "SINK_KINDS": 27, "JS_SUFFIXES": 2}
names = {n for n, v in vars(sitecheck).items()
         if n.startswith(("LITERALS_", "CSS_")) and isinstance(v, (set, frozenset, dict, tuple))}
passing = set(sitecheck.LITERALS_PASSING_SETS)
flagging = sorted(names - passing)
missing = []
if not rows:
    missing.append("the table has no rows")
for name in sorted(passing - names):
    missing.append(f"LITERALS_PASSING_SETS names {name}, which tools/sitecheck.py does not define")
if len(flagging) != EXPECTED_FLAGGING_SETS:
    missing.append(f"tools/sitecheck.py has {len(flagging)} flagging sets, not the pinned "
                   f"{EXPECTED_FLAGGING_SETS} ({', '.join(flagging)}); update the pin with rows")
if len(passing) != EXPECTED_PASSING_SETS:
    missing.append(f"LITERALS_PASSING_SETS has {len(passing)} names, not the pinned "
                   f"{EXPECTED_PASSING_SETS}")
# Sets with no LITERALS_/CSS_ name: the members of the raw-text end-tag rule
# (RAWTEXT_END_TAG, review7 A1) are read from its pattern, so a name added to
# the pattern needs a row too (review8 A3).
derived = {}
end_names = re.search(r"\(([a-z|]+)\)", sitecheck.RAWTEXT_END_TAG.pattern)
derived["RAWTEXT_END_TAG"] = set(end_names.group(1).split("|")) if end_names else set()
# M3 PR 9 fix round 1 (review 1, QA): the two passing sets of the meta
# content (a row per name shows by its count that the content is no visible
# attribute), the page members of the print sinks (a row per member pins
# its value kind, so cutting or remapping one changes the row's finding),
# and every value kind the page text rejects (a row per kind, so a kind
# added to LITERALS_PRINT_SOURCES["text"] turns its row red).
derived["LITERALS_META_PLAIN_NAMES"] = set(sitecheck.LITERALS_META_PLAIN_NAMES)
derived["LITERALS_META_PLAIN_HTTP_EQUIV"] = set(sitecheck.LITERALS_META_PLAIN_HTTP_EQUIV)
derived["PAGE_MEMBERS"] = set(sitecheck.PAGE_MEMBERS)
derived["SINK_KINDS"] = set(sitecheck.SINK_KINDS) - set(
    sitecheck.LITERALS_PRINT_SOURCES["text"]) - set(sitecheck.SINK_REPORTED)
# M3 PR 9 fix round 2 (delta review 4): the script suffixes, which the pin
# and the LITERALS_RESOURCE_TARGETS rule share, a row per suffix.
derived["JS_SUFFIXES"] = set(sitecheck.JS_SUFFIXES)
for source, kinds in sitecheck.LITERALS_PRINT_SOURCES.items():
    for kind in sorted(set(kinds) - set(sitecheck.SINK_KINDS)):
        missing.append(f"LITERALS_PRINT_SOURCES[{source!r}] holds {kind!r}, which is not "
                       "on SINK_KINDS")
for set_name, pinned in EXPECTED_DERIVED_MEMBERS.items():
    if len(derived[set_name]) != pinned:
        missing.append(f"{set_name} has {len(derived[set_name])} members, not the pinned "
                       f"{pinned}; update the pin with rows")
for set_name in flagging + sorted(derived):
    real = derived[set_name] if set_name in derived else set(getattr(sitecheck, set_name))
    members = covered.get(set_name, set())
    if not real:
        missing.append(f"{set_name} is empty")
    if not members:
        missing.append(f"{set_name} has no rows")
    for member in sorted(real - members):
        missing.append(f"{set_name} member {member!r} has no row")
    for member in sorted(members - real):
        missing.append(f"{set_name} has no member {member!r} any more")
for set_name in sorted(set(covered) - set(flagging) - set(derived) - {"branch"}):
    missing.append(f"{set_name} is not a flagging set of tools/sitecheck.py")
if "branch" not in covered:
    missing.append("no branch rows")
if missing:
    print("FAIL literals-members/coverage: " + "; ".join(missing))
else:
    print(f"ok   literals-members/coverage (every member of the {len(flagging)} flagging "
          f"sets has a fail row; {len(rows)} rows)")
PY
}

# feed_fields_runner <sitecheck.py> <fields table> <base case> <schema dir>:
# render rule 12 field by field (M3 PR 8 review 4). Every row of the table
# sets one field of one entry of the base case's public/feed.json to another
# value and runs the real cmd_render on a copy, which must exit 1 with
# exactly the findings the row names; feed-fields/coverage fails when a
# field the rule compares (the keys of feed_report_entry and
# feed_campaign_entry on the base records, and the schema's entry
# properties) has no row, or a row names a field neither has.
# feed-fields/field-set-test-schema (#30 Known limit 3) runs rule 12's
# field-set branch, which the real schema shadows (rule 11 rejects a missing
# or extra field first): against a copy of the schema directory in which
# reports[].evidence is optional and reports[].x_test is allowed, a feed
# entry without evidence and with x_test must give exactly the two
# field-set findings. The test schema lives only in a temporary directory
# of this runner; check.sh always passes "$CHECK_ROOT/schema".
# FEED_FIELDS_COVERAGE_ONLY=1 checks coverage alone. -B: no
# tools/__pycache__.
feed_fields_runner() {
  python3 -I -B - "$1" "$2" "$3" "$4" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
table, base, schema_dir = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])


def render(root, schemas):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = sitecheck.cmd_render(argparse.Namespace(
            records=str(root), schemas=str(schemas), fixtures=None, no_feed=False,
            no_search=True, no_report_pins=True, no_intake=True, public=str(root / "public")))
    output = buffer.getvalue()
    return rc, output, sum(line.startswith("FAIL: ") for line in output.splitlines())


def judge(name, rc, output, findings, expects, count):
    if rc == 1 and findings == count and all(e in output for e in expects):
        print(f"ok   {name} (failed as expected: {expects[0]})")
    else:
        print(f"FAIL {name}: expected exit 1, {count} finding(s) and {expects!r}; "
              f"got exit {rc}, {findings} finding(s); output:")
        for line in output.splitlines():
            print(f"     | {line}")


def with_feed(root, change):
    path = root / "public" / "feed.json"
    feed = json.loads(path.read_text(encoding="utf-8"))
    change(feed)
    path.write_text(json.dumps(feed, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False), encoding="utf-8")


rows = [line.split("\t") for line in table.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")]
covered = {"reports": set(), "campaigns": set()}
for row in rows:
    if len(row) != 6 or row[0] not in covered:
        print(f"FAIL feed-fields/table: malformed row {row!r}")
        continue
    kind, slug, field, value, expect, count = row
    covered[kind].add(field)
    if os.environ.get("FEED_FIELDS_COVERAGE_ONLY"):
        continue
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)

        def change(feed, kind=kind, slug=slug, field=field, value=value):
            entry = next(e for e in feed[kind] if e.get("slug") == slug)
            entry[field] = json.loads(value)
        with_feed(root, change)
        rc, output, findings = render(root, schema_dir)
    judge(f"feed-fields/{kind}/{field}", rc, output, findings, [expect], int(count))

# The fields rule 12 compares, taken from the code and the schema.
findings = sitecheck.Findings()
records = sitecheck.load_records(base, schema_dir, findings)
reports = [r for r in records if r.section == "reports"]
campaigns = [r for r in records if r.section == "campaigns"]
schema = json.loads((schema_dir / sitecheck.FEED_SCHEMA).read_text(encoding="utf-8"))
compared = {"reports": set(), "campaigns": set()}
if reports and campaigns and not findings.items:
    compared["reports"] = set(sitecheck.feed_report_entry(reports[0]))
    compared["campaigns"] = set(sitecheck.feed_campaign_entry(campaigns[0], reports))
for kind in compared:
    compared[kind] |= set(schema["properties"][kind]["items"]["properties"])
missing = []
if not reports or not campaigns or findings.items:
    missing.append(f"the base case {base.name} needs a report and a campaign record and "
                   "no record finding")
for kind in compared:
    for field in sorted(compared[kind] - covered[kind]):
        missing.append(f"{kind}[].{field} has no row")
    for field in sorted(covered[kind] - compared[kind]):
        missing.append(f"{kind}[].{field} is not a field rule 12 compares")
if missing:
    print("FAIL feed-fields/coverage: " + "; ".join(missing))
else:
    print(f"ok   feed-fields/coverage (every compared field has a row; "
          f"{sum(map(len, covered.values()))} fields)")
if os.environ.get("FEED_FIELDS_COVERAGE_ONLY"):
    sys.exit(0)

# Rule 12's field set against a test-only schema (#30 Known limit 3).
with tempfile.TemporaryDirectory() as tmp:
    test_schemas = Path(tmp) / "schema"
    shutil.copytree(schema_dir, test_schemas)
    path = test_schemas / sitecheck.FEED_SCHEMA
    test_schema = json.loads(path.read_text(encoding="utf-8"))
    items = test_schema["properties"]["reports"]["items"]
    items["required"].remove("evidence")
    items["properties"]["x_test"] = {"type": "string",
                                     "description": "A field only this test schema has."}
    path.write_text(json.dumps(test_schema), encoding="utf-8")
    root = Path(tmp) / "case"
    shutil.copytree(base, root)

    def change(feed):
        entry = next(e for e in feed["reports"] if e.get("slug") == "example-front-company")
        del entry["evidence"]
        entry["x_test"] = "x"
    with_feed(root, change)
    page = root / "public" / "data-feed" / "index.html"
    term = "<dt><code>reports[].evidence</code></dt>"
    html = page.read_text(encoding="utf-8")
    page.write_text(html.replace(term, "<dt><code>reports[].x_test</code></dt>"
                                 "<dd>Text. A test field.</dd>" + term, 1), encoding="utf-8")
    rc, output, found = render(root, test_schemas)
judge("feed-fields/field-set-test-schema", rc, output, found,
      ["rule 12: reports['example-front-company'] has no field evidence",
       "rule 12: reports['example-front-company'] has the field 'x_test'"], 2)
PY
}

# search_cases_runner <sitecheck.py> <cases table> <base case> <schema dir>:
# render rules 15 and 16 (the A to Z page, the Home search form and its
# hidden result sections, ADR-0005 part 6) one branch and one flagging-set
# member per row (M4 PR 2 and PR 3); with the label render-intake, rule 18
# (the intake forms, M5b PR 3); with the label render-bidi, rule 19. An
# optional sixth argument names the command: render (the default) or
# records, which runs the real cmd_records on the copied root instead
# (records-bidi, records rule R16; Replikanti/interviewscam#28). A row is
# name, file, find, replace and expect, tab-separated, with \n, \t, \r and
# \0 in find and replace read as a newline, a tab, U+000D and U+0000 (fix
# round 12: a table line cannot hold the last two), and \u{XXXX} as that code
# point (Replikanti/interviewscam#28 fix round 3: U+001C to U+001E, U+0085 and
# U+2029 end a line for str.splitlines), then optional further find
# and replace pairs, applied in order (fix round 9: a wrapper row closes its
# wrapper, because an element an ancestor's end tag closes is a markup:
# finding). It copies the base case to
# a temporary directory, replaces the one occurrence of find in <file>
# (relative to the case; find `*` deletes the file instead, and find `+`
# creates it, with its directories, holding replace; the file must not
# exist yet) and runs the
# real cmd_render with the switches the base case's marker files ask for,
# as the fixture loop does (the feed rules with a feed.txt, rules 15 and 16
# with a search.txt, rule 17 with a report-pins.txt, rule 18 with an
# intake.txt): expect PASS needs exit 0, any other expect exit 1 with
# that text in the output; an expect COUNT=<n> <text> (fix round 11, QA
# recheck of 5b1519d) also needs exactly n findings, so a row can prove that
# the class-scoped rules stay off on a page with a markup: finding. A find string that is absent, or present more
# than once, fails the row, so a row cannot turn into a no-op when the
# base case changes. The last line, render-search/table, counts the rows.
# -B: no tools/__pycache__.
search_cases_runner() {
  python3 -I -B - "$1" "$2" "$3" "$4" "${5:-render-search}" "${6:-render}" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import re
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
table, base, schema_dir = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
# The label of the lines (render-search, render-report for rule 17 or
# render-intake for rule 18), and the switches the base case asks for, as
# in the fixture loop: the feed rules with a feed.txt, rules 15 and 16 with
# a search.txt, rule 17 with a report-pins.txt, rule 18 with an intake.txt.
label = sys.argv[5]
command = sys.argv[6]
if command not in ("render", "records"):
    sys.exit(f"search_cases_runner: unknown command {command!r}")
no_feed = not (base / "feed.txt").is_file()
no_search = not (base / "search.txt").is_file()
no_report_pins = not (base / "report-pins.txt").is_file()
no_intake = not (base / "intake.txt").is_file()


def unescape(text):
    text = re.sub(r"\\u\{([0-9A-F]{4,6})\}", lambda m: chr(int(m.group(1), 16)), text)
    return (text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
            .replace("\\0", "\x00"))


rows = [line.split("\t") for line in table.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")]
names, bad = set(), 0
for row in rows:
    if len(row) < 5 or (len(row) - 5) % 2 or not row[0] or row[0] in names:
        print(f"FAIL {label}/table: malformed or duplicate row {row!r}")
        bad += 1
        continue
    name, rel, find, replace, expect = row[:5]
    names.add(name)
    edits = [(unescape(f), unescape(r)) for f, r in [row[2:4]] + list(zip(row[5::2], row[6::2]))]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)
        path = root / rel
        if edits[0][0] == "+":
            if path.exists() or len(edits) != 1:
                print(f"FAIL {label}/{name}: {rel} already exists in {base.name}, or the "
                      "row has further edits; + creates one new file")
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(edits[0][1], encoding="utf-8")
        elif not path.is_file():
            print(f"FAIL {label}/{name}: {rel} is not a file of {base.name}")
            continue
        elif edits[0][0] == "*":
            path.unlink()
        else:
            text = path.read_text(encoding="utf-8")
            counts = []
            for find, replace in edits:
                counts.append(text.count(find))
                text = text.replace(find, replace, 1)
            if counts != [1] * len(edits):
                print(f"FAIL {label}/{name}: the find strings occur "
                      f"{counts} times in {rel} (in turn), the row needs exactly one each")
                continue
            path.write_text(text, encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            if command == "records":
                rc = sitecheck.cmd_records(argparse.Namespace(root=str(root),
                                                              schemas=str(schema_dir)))
            else:
                rc = sitecheck.cmd_render(argparse.Namespace(
                    records=str(root), schemas=str(schema_dir), fixtures=None,
                    no_feed=no_feed, no_search=no_search, no_report_pins=no_report_pins,
                    no_intake=no_intake, public=str(root / "public")))
        output = buffer.getvalue()
    count = None
    if expect.startswith("COUNT="):
        head, _, expect = expect.partition(" ")
        count = int(head[len("COUNT="):])
    findings = sum(line.startswith("FAIL: ") for line in output.splitlines())
    if expect == "PASS" and rc == 0:
        print(f"ok   {label}/{name} (passed as expected)")
    elif expect != "PASS" and rc == 1 and expect in output \
            and (count is None or findings == count):
        print(f"ok   {label}/{name} (failed as expected: {expect}"
              + ("" if count is None else f", exactly {count} finding(s)") + ")")
    else:
        print(f"FAIL {label}/{name}: expected "
              f"{'exit 0' if expect == 'PASS' else 'exit 1 and ' + repr(expect)}"
              + ("" if count is None else f" with exactly {count} finding(s)")
              + f"; got exit {rc} with {findings} finding(s); output:")
        for line in output.splitlines():
            print(f"     | {line}")
if not rows or bad:
    print(f"FAIL {label}/table: {len(rows)} rows, {bad} malformed")
else:
    print(f"ok   {label}/table ({len(rows)} rows)")
PY
}

# reflow_search_runner <sitecheck.py> <cases table> <base case> <search.js>
# <chrome> (M4 PR 4, CI only): reflow case (8) one branch per row. A row is
# name, file, find, replace, expect, an optional patch list and optional
# further file, find and replace triples, applied in order. It copies
# the base case (reflow/pass-search: Home, /a-z/, /feed.json and the built
# assets of the fixture build) to a temporary directory and always puts
# today's assets/js/search.js in as the built search script (its
# integrity attribute on Home recomputed), so the rows run the real
# script; file `search.js` edits that script, any other file is a path in
# the tree. The find string must occur exactly once (a row never turns
# into a no-op), `-` as find leaves the file as it is and `*` deletes it. The patch list
# (NAME=number, comma-separated) sets module constants through importlib,
# as reflow-launch/first-answer-deadline does (the aria-busy row shortens
# REFLOW_TIMEOUT, the fetch row SEARCH_FETCH_BUDGET). Then the real
# cmd_reflow runs with case (8) on: expect PASS needs exit 0, any other
# expect exit 1 with that text in the output. The rows run four at a time,
# each in a forked process with its own Chrome, and print in table order
# (the job's time: a row takes 10 to 15 s). The last line,
# reflow-search/table, counts the rows. -B: no tools/__pycache__.
reflow_search_runner() {
  python3 -I -B - "$1" "$2" "$3" "$4" "$5" <<'PY'
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import multiprocessing
import re
import shutil
import sys
import tempfile
from pathlib import Path

source, table, base, script, chrome = sys.argv[1:6]
REFLOW_SEARCH_JOBS = 4
rows = [line.split("\t") for line in Path(table).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")]
real = Path(script).read_text(encoding="utf-8")


def run_row(row):
    """One row in its own process (its own module, patches and stdout):
    the lines it prints."""
    lines = []
    print = lines.append  # noqa: A001 (the row's output, printed in order)
    name, expect = row[0], row[4]
    edits = [tuple(row[1:4])] + [tuple(row[i:i + 3]) for i in range(6, len(row), 3)]
    edits = [(rel, f.replace("\\n", "\n").replace("\\t", "\t"),
              r.replace("\\n", "\n").replace("\\t", "\t")) for rel, f, r in edits]
    spec = importlib.util.spec_from_file_location("sitecheck", source)
    sitecheck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sitecheck)
    for patch in (row[5].split(",") if len(row) == 6 and row[5] else []):
        key, _, value = patch.partition("=")
        setattr(sitecheck, key, float(value) if "." in value else int(value))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)
        built = sorted((root / "js").glob("search.min.*.js"))
        text, problem = real, None
        for rel, find, replace in edits:
            if rel == "search.js" and find != "-":
                if text.count(find) != 1:
                    problem = (f"the find string occurs {text.count(find)} times in "
                               "assets/js/search.js, the row needs exactly one")
                text = text.replace(find, replace, 1)
        if len(built) != 1:
            problem = f"the base holds {len(built)} built search scripts, it needs exactly one"
        else:
            data = text.encode("utf-8")
            built[0].write_bytes(data)
            home = root / "index.html"
            page = home.read_text(encoding="utf-8")
            tag = re.search(r'<script src=/js/search\.min\.[0-9a-f]+\.js integrity=(\S+) defer>',
                            page)
            if tag is None:
                problem = "Home of the base has no search script tag"
            else:
                integrity = "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()
                home.write_text(page.replace(tag.group(1), integrity, 1), encoding="utf-8")
        for rel, find, replace in edits:
            if problem or rel == "search.js" or find == "-":
                continue
            target = root / rel
            if not target.is_file():
                problem = f"{rel} is not a file of {base}"
                continue
            if find == "*":
                target.unlink()
                continue
            body = target.read_text(encoding="utf-8")
            if body.count(find) != 1:
                problem = (f"the find string occurs {body.count(find)} times in {rel}, the "
                           "row needs exactly one")
                continue
            target.write_text(body.replace(find, replace, 1), encoding="utf-8")
        if problem:
            print(f"FAIL reflow-search/{name}: {problem}")
            return lines
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            try:
                rc = sitecheck.cmd_reflow(argparse.Namespace(
                    public=str(root), chrome=chrome, no_search=False,
                    launch_timeout=sitecheck.REFLOW_LAUNCH_TIMEOUT))
            except sitecheck.UsageError as exc:
                buffer.write(f"{exc}\n")
                rc = 2
        output = buffer.getvalue()
    if expect == "PASS" and rc == 0:
        print(f"ok   reflow-search/{name} (passed as expected)")
    elif expect != "PASS" and rc == 1 and expect in output:
        print(f"ok   reflow-search/{name} (failed as expected: {expect})")
    else:
        print(f"FAIL reflow-search/{name}: expected "
              f"{'exit 0' if expect == 'PASS' else 'exit 1 and ' + repr(expect)}; got exit "
              f"{rc}; output:")
        for line in output.splitlines()[-12:]:
            print(f"     | {line}")
    return lines


names, bad, good = set(), 0, []
for row in rows:
    if len(row) < 5 or (len(row) > 6 and (len(row) - 6) % 3) or not row[0] \
            or row[0] in names:
        print(f"FAIL reflow-search/table: malformed or duplicate row {row!r}")
        bad += 1
        continue
    names.add(row[0])
    good.append(row)
# REFLOW_SEARCH_JOBS rows at a time, each in a forked process with its own
# Chrome (the job's time; the rows share nothing), printed in table order.
with multiprocessing.get_context("fork").Pool(REFLOW_SEARCH_JOBS) as pool:
    for lines in pool.map(run_row, good, chunksize=1):
        for line in lines:
            print(line)
if not rows or bad:
    print(f"FAIL reflow-search/table: {len(rows)} rows, {bad} malformed")
else:
    print(f"ok   reflow-search/table ({len(rows)} rows)")
PY
}

# search_oracle_tables <sitecheck.py> <search.js> <ADR-0005> (M4 PR 4, the amendment's
# item 4): the tables of search_expect, the oracle of reflow case (8), are
# its own copies taken from ADR-0005; this line proves each equal to
# sitecheck's table (DEFAULT_IGNORABLE, DOT_CHARS, DEFANGS plus hxxp) and to
# the script's (IGNORABLE, DOTS, DEFANGS, SPACES against str.isspace,
# SCHEMES, VALUE_LISTS, OBJECT_FIELDS, PARTIAL_MIN, PARTIAL_CAP), and names
# every member that differs. Runs locally and in CI.
search_oracle_tables() {
  python3 -I -B - "$1" "$2" "$3" <<'PY'
import importlib.util
import json
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)
js = Path(sys.argv[2]).read_text(encoding="utf-8")


def js_value(name):
    m = re.search(r"var " + name + r" = (.*?);\n", js, re.S)
    if m is None:
        return None
    text = re.sub(r"0x([0-9A-Fa-f]+)", lambda h: str(int(h.group(1), 16)), m.group(1))
    return json.loads(text)


def ranges(pairs):
    return {c for lo, hi in pairs for c in range(lo, hi + 1)}


problems = []


def compare(what, oracle, other):
    oracle, other = set(oracle), set(other)
    for member in sorted(oracle - other, key=repr):
        problems.append(f"{what}: {member!r} is in the oracle's table only")
    for member in sorted(other - oracle, key=repr):
        problems.append(f"{what}: {member!r} is not in the oracle's table")


compare("DEFAULT_IGNORABLE (sitecheck)", sc.ORACLE_IGNORABLE, sc.DEFAULT_IGNORABLE)
compare("IGNORABLE (search.js)", [tuple(p) for p in sc.ORACLE_IGNORABLE],
        [tuple(p) for p in js_value("IGNORABLE") or []])
compare("DOT_CHARS (sitecheck)", sc.ORACLE_DOTS, sc.DOT_CHARS)
compare("DOTS (search.js)", [ord(c) for c in sc.ORACLE_DOTS], js_value("DOTS") or [])
compare("DEFANGS (sitecheck, plus hxxp)", sc.ORACLE_DEFANGS,
        list(sc.DEFANGS) + [("hxxp", "http")])
compare("DEFANGS (search.js)", sc.ORACLE_DEFANGS,
        [tuple(p) for p in js_value("DEFANGS") or []])
compare("SPACES (search.js) against str.isspace",
        {c for c in range(0x110000) if chr(c).isspace()}, ranges(js_value("SPACES") or []))
compare("SCHEMES (search.js)", sc.ORACLE_SCHEMES,
        [s + js_value("SCHEME_END") for s in js_value("SCHEMES") or []])
compare("VALUE_LISTS (search.js)", sc.ORACLE_VALUE_LISTS, js_value("VALUE_LISTS") or [])
compare("OBJECT_FIELDS (search.js)", sc.ORACLE_OBJECT_FIELDS,
        [tuple(p) for p in js_value("OBJECT_FIELDS") or []])
compare("PARTIAL_MIN (search.js)", [sc.SEARCH_PARTIAL_MIN], [js_value("PARTIAL_MIN")])
compare("PARTIAL_CAP (search.js)", [sc.SEARCH_PARTIAL_CAP], [js_value("PARTIAL_CAP")])
# The ADR's numbers (fix round 1, QA): SEARCH_FETCH_BUDGET, the gzip level,
# the partial minimum and cap, and the viewport, read from the ADR-0005
# Numbers table, so a changed constant without its derivation fails.
adr = Path(sys.argv[3]).read_text(encoding="utf-8")


def adr_number(pattern):
    m = re.search(pattern, adr)
    return [int(m.group(1).replace(",", ""))] if m else ["missing in ADR-0005"]


compare("SEARCH_FETCH_BUDGET (ADR-0005 Numbers)", [sc.SEARCH_FETCH_BUDGET],
        adr_number(r"\| `SEARCH_FETCH_BUDGET` ([0-9,]+) bytes"))
compare("SEARCH_GZIP_LEVEL (ADR-0005 Numbers)", [sc.SEARCH_GZIP_LEVEL],
        adr_number(r"Gzip at level ([0-9]+)"))
compare("SEARCH_PARTIAL_MIN (ADR-0005 Numbers)", [sc.SEARCH_PARTIAL_MIN],
        adr_number(r"\| `SEARCH_PARTIAL_MIN` ([0-9]+) code points"))
compare("SEARCH_PARTIAL_CAP (ADR-0005 Numbers)", [sc.SEARCH_PARTIAL_CAP],
        adr_number(r"\| `SEARCH_PARTIAL_CAP` ([0-9]+) entries"))
compare("SEARCH_VIEWPORT width (ADR-0005 Numbers)", [sc.SEARCH_VIEWPORT[0]],
        adr_number(r"mobile emulation, ([0-9]+) × [0-9]+"))
compare("SEARCH_VIEWPORT height (ADR-0005 Numbers)", [sc.SEARCH_VIEWPORT[1]],
        adr_number(r"mobile emulation, [0-9]+ × ([0-9]+)"))
for problem in problems:
    print(f"FAIL search-oracle/tables: {problem}")
if not problems:
    print("ok   search-oracle/tables (the oracle's tables equal sitecheck's and search.js's)")
PY
}

# page_suffixes_runner <sitecheck.py> <site base case> <schema dir> (M4 PR 3
# fix round 10, QA recheck of ceb2356): rule (n) of site and L6 of literals
# for every member of HTML_SUFFIXES, taken from the code, and its upper-case
# form, so each suffix is proven on its own: `site` on a copy of the base
# case with the page added as public/extra<suffix> (the base's own page, its
# canonical changed to that path) must fail with rule (n) for every form but
# .html; `literals` on a root holding only static/x<suffix> must fail with
# exactly the one L6 finding for every form but .html, and pass for .html.
# The last line, page-suffixes/table, counts the forms.
page_suffixes_runner() {
  python3 -I -B - "$1" "$2" "$3" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
base, schema_dir = Path(sys.argv[2]), Path(sys.argv[3])
forms = sorted({f for s in sitecheck.HTML_SUFFIXES for f in (s, s.upper())})
page = (base / "public" / "index.html").read_text(encoding="utf-8")
L6 = "a static file this check cannot read for copy"
for form in forms:
    page_ok = form == sitecheck.PAGE_SUFFIX
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)
        (root / "public" / f"extra{form}").write_text(
            page.replace('href="https://interviewscam.com/"',
                         f'href="https://interviewscam.com/extra{form}"'), encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = sitecheck.cmd_site(argparse.Namespace(
                records=str(root), schemas=str(schema_dir), no_built_pins=True,
                public=str(root / "public")))
        hit = f"public/extra{form}: (n) a page under the suffix {form!r}" in buffer.getvalue()
        if page_ok and not hit or not page_ok and rc == 1 and hit:
            print(f"ok   page-suffixes/site/{form} ({'no' if page_ok else 'a'} rule (n) finding)")
        else:
            print(f"FAIL page-suffixes/site/{form}: exit {rc}, rule (n) finding {hit}")
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "static").mkdir()
        (Path(tmp) / "static" / f"x{form}").write_text("<p></p>\n", encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = sitecheck.cmd_literals(argparse.Namespace(root=Path(tmp)))
        out = buffer.getvalue()
        n = sum(line.startswith("FAIL: ") for line in out.splitlines())
        if (page_ok and rc == 0) or (not page_ok and rc == 1 and n == 1 and L6 in out):
            print(f"ok   page-suffixes/literals/{form} ({'passes' if page_ok else 'one L6 finding'})")
        else:
            print(f"FAIL page-suffixes/literals/{form}: exit {rc}, {n} findings")
print(f"ok   page-suffixes/table ({len(forms)} forms)")
PY
}

# site_cases_runner <sitecheck.py> <cases table> <base case> <schema dir>:
# site rule (m) (the head by position, M4 PR 3 fix rounds 7 and 8) one fixed
# head value and one branch per row, on a copy of site/pass-built-pins with
# the built pins on. A row is name, file, find, replace and expect,
# tab-separated, with \n, \t and \v (U+000B, which a table line cannot hold:
# splitlines ends a line there) in find and replace; the find string must
# occur exactly once, so a row never turns into a no-op.
site_cases_runner() {
  python3 -I -B - "$1" "$2" "$3" "$4" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
table, base, schema_dir = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])


def unescape(text):
    return text.replace("\\n", "\n").replace("\\t", "\t").replace("\\v", "\v")


rows = [line.split("\t") for line in table.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")]
names, bad = set(), 0
for row in rows:
    if len(row) != 5 or not row[0] or row[0] in names:
        print(f"FAIL site-head/table: malformed or duplicate row {row!r}")
        bad += 1
        continue
    name, rel, find, replace, expect = row
    names.add(name)
    find, replace = unescape(find), unescape(replace)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)
        path = root / rel
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        if text.count(find) != 1:
            print(f"FAIL site-head/{name}: the find string occurs {text.count(find)} times "
                  f"in {rel}, the row needs exactly one")
            continue
        path.write_text(text.replace(find, replace, 1), encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = sitecheck.cmd_site(argparse.Namespace(
                records=str(root), schemas=str(schema_dir), no_built_pins=False,
                public=str(root / "public")))
        output = buffer.getvalue()
    if expect == "PASS" and rc == 0:
        print(f"ok   site-head/{name} (passed as expected)")
    elif expect != "PASS" and rc == 1 and expect in output:
        print(f"ok   site-head/{name} (failed as expected: {expect})")
    else:
        print(f"FAIL site-head/{name}: expected "
              f"{'exit 0' if expect == 'PASS' else 'exit 1 and ' + repr(expect)}; got exit "
              f"{rc}; output:")
        for line in output.splitlines():
            print(f"     | {line}")
if not rows or bad:
    print(f"FAIL site-head/table: {len(rows)} rows, {bad} malformed")
else:
    print(f"ok   site-head/table ({len(rows)} rows)")
PY
}

# site_intake_runner <sitecheck.py> <cases table> <base case> <schema dir>
# [label] (M5b PR 3, ADR-0006 part 9): site rule (a) for the intake endpoint and
# the intake origin in the CSP, one branch and one variant per row, on a
# copy of render/pass-intake (the real built pages; the built pins off,
# because the case's stylesheet and scripts are copies). A row is name,
# file, find, replace and expect, then optional further find and replace
# pairs; \n and \t in find and replace are a newline and a tab, \u{XXXX}
# that code point (as in search_cases_runner), and every find string must
# occur exactly once. Three files are not paths: @csp sets
# params.csp in hugo.toml and the content of every page's CSP meta to
# replace, @css appends replace to the built stylesheet and @js to the
# built copy script (find is - for all three). The table holds one row per
# member of CSP_DIRECTIVES but form-action (csp-intake/<directive>, the intake
# origin in that directive), and site-intake/coverage takes that set from
# the code. Then the real cmd_site runs:
# expect PASS needs exit 0, any other expect exit 1 with that text in the
# output. The last line, site-intake/table, counts the rows. The label of
# the lines is site-intake unless [label] names another (site-csp-equiv,
# Replikanti/interviewscam#32). -B: no tools/__pycache__.
site_intake_runner() {
  python3 -I -B - "$1" "$2" "$3" "$4" "${5:-site-intake}" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import re
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
table, base, schema_dir = Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
label = sys.argv[5]


def unescape(text):
    text = re.sub(r"\\u\{([0-9A-F]{4,6})\}", lambda m: chr(int(m.group(1), 16)), text)
    return text.replace("\\n", "\n").replace("\\t", "\t")


rows = [line.split("\t") for line in table.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")]
policy = re.search(r'^csp = "(.*)"$', (base / "hugo.toml").read_text(encoding="utf-8"),
                   re.M).group(1)
names, bad = set(), 0
for row in rows:
    if len(row) < 5 or (len(row) - 5) % 2 or not row[0] or row[0] in names:
        print(f"FAIL {label}/table: malformed or duplicate row {row!r}")
        bad += 1
        continue
    name, rel, find, replace, expect = row[:5]
    names.add(name)
    edits = [(unescape(f), unescape(r)) for f, r in [row[2:4]] + list(zip(row[5::2], row[6::2]))]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "case"
        shutil.copytree(base, root)
        public = root / "public"
        if rel == "@csp":
            config = root / "hugo.toml"
            config.write_text(config.read_text(encoding="utf-8").replace(
                f'csp = "{policy}"', f'csp = "{edits[0][1]}"'), encoding="utf-8")
            for page in public.rglob("*.html"):
                text = page.read_text(encoding="utf-8")
                page.write_text(text.replace(f'content="{policy}"', f'content="{edits[0][1]}"'),
                                encoding="utf-8")
        elif rel in ("@css", "@js"):
            pattern = "css/site.min.*.css" if rel == "@css" else "js/copy.min.*.js"
            target = next(public.glob(pattern))
            target.write_text(target.read_text(encoding="utf-8") + edits[0][1], encoding="utf-8")
        else:
            path = root / rel
            text = path.read_text(encoding="utf-8") if path.is_file() else ""
            counts = []
            for find, rep in edits:
                counts.append(text.count(find))
                text = text.replace(find, rep, 1)
            if counts != [1] * len(edits):
                print(f"FAIL {label}/{name}: the find strings occur {counts} times in {rel} "
                      "(in turn), the row needs exactly one each")
                continue
            path.write_text(text, encoding="utf-8")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            rc = sitecheck.cmd_site(argparse.Namespace(
                records=str(root), schemas=str(schema_dir), no_built_pins=True,
                public=str(public)))
        output = buffer.getvalue()
    if expect == "PASS" and rc == 0:
        print(f"ok   {label}/{name} (passed as expected)")
    elif expect != "PASS" and rc == 1 and expect in output:
        print(f"ok   {label}/{name} (failed as expected: {expect})")
    else:
        print(f"FAIL {label}/{name}: expected "
              f"{'exit 0' if expect == 'PASS' else 'exit 1 and ' + repr(expect)}; got exit "
              f"{rc}; output:")
        for line in output.splitlines():
            print(f"     | {line}")
if not rows or bad:
    print(f"FAIL {label}/table: {len(rows)} rows, {bad} malformed")
else:
    print(f"ok   {label}/table ({len(rows)} rows)")
PY
}

# csp_equiv_coverage <sitecheck.py> <cases table> [drop]
# (Replikanti/interviewscam#32 fix round 1): site-csp-equiv/coverage needs a
# row tag-space/uXXXX for every member of PARSER_ONLY_SPACE, taken from the
# code (drop: leave that member's row out, the negative proof);
# site-csp-equiv/space-set needs every code point that this interpreter's
# str.isspace() or str pattern \s matches, but TAB, LF, FF, CR and SPACE, to
# be a member, so a Unicode update that adds whitespace fails here instead
# of opening the rule. -B: no tools/__pycache__.
csp_equiv_coverage() {
  python3 -I -B - "$1" "$2" "${3:-}" <<'PY'
import importlib.util
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
drop = sys.argv[3]
names = {line.split("\t")[0] for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
         if line and not line.startswith("#")} - {drop}
want = {f"tag-space/u{code:04x}" for code in sitecheck.PARSER_ONLY_SPACE}
missing = sorted(want - names)
if missing or not want:
    print(f"FAIL site-csp-equiv/coverage: {len(missing)} member(s) of PARSER_ONLY_SPACE "
          f"without a row: {', '.join(missing)}")
else:
    print(f"ok   site-csp-equiv/coverage ({len(want)} member rows)")
space = {code for code in range(sys.maxunicode + 1)
         if chr(code).isspace() or re.fullmatch(r"\s", chr(code))} - {9, 10, 12, 13, 32}
extra = sorted(space - sitecheck.PARSER_ONLY_SPACE)
if extra:
    print("FAIL site-csp-equiv/space-set: this interpreter's whitespace holds "
          f"{', '.join(f'U+{code:04X}' for code in extra)}, which PARSER_ONLY_SPACE lacks")
else:
    print(f"ok   site-csp-equiv/space-set ({len(space)} code points, all members)")
PY
}

# intake_coverage <sitecheck.py> <render table> <site table> [drop] (M5b
# PR 3): the rows of tests/fixtures/render/intake-cases.tsv and
# tests/fixtures/site/intake-cases.tsv cover every member of the sets render
# rule 18 and site rule (a) read, taken from the code: per channel of
# INTAKE_FIELDS each field missing, duplicated, renamed, of another type and
# with another autocomplete, a required field without required and an
# optional one with it, a capped field at cap - 1, cap + 1 and without
# maxlength, and the label and hint of each visible field; per MIME type of
# INTAKE_IMAGE_TYPES an accept without it; per visible text control without
# autocomplete a row that adds autocomplete=off (fix round 1); per page of
# INTAKE_UNLISTED a row that lists it in the sitemap; per result id of
# INTAKE_RESULT_IDS the section missing, doubled, its id elsewhere and its
# heading and text reworded; per member of INTAKE_REFERRER_TAGS and per
# channel a referrerpolicy row; per channel the page and its form missing;
# per member of URL_ATTRS a row that names the intake host in it, and per
# member of FORM_ATTRS one that leaves the origin; per page of
# INTAKE_FORM_PAGES the CSP without the intake origin; per member of
# CSP_DIRECTIVES but form-action the intake origin in that directive. A row name the table
# lacks fails the line render-intake/coverage or site-intake/coverage. With
# drop, that row is left out of the tables first, so the line must fail
# (the negative proof). -B: no tools/__pycache__.
intake_coverage() {
  python3 -I -B - "$1" "$2" "$3" "${4:-}" <<'PY'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
drop = sys.argv[4]


def names(path):
    return {line.split("\t", 1)[0] for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")} - {drop}


render, site = names(sys.argv[2]), names(sys.argv[3])
want = set()
mimes = list(dict.fromkeys(mime for mime, _, _ in sitecheck.INTAKE_IMAGE_TYPES))
for channel, fields in sitecheck.INTAKE_FIELDS.items():
    want |= {f"a-{channel}-page-missing", f"a-{channel}-form-missing"}
    want |= {f"c-{channel}-referrerpolicy-{tag}" for tag in sitecheck.INTAKE_REFERRER_TAGS}
    for field in fields:
        name, kind = field["name"], field["type"]
        stem = f"b-{channel}-{name}"
        want |= {f"{stem}-{case}" for case in ("missing", "duplicated", "renamed", "type",
                                               "autocomplete")}
        if kind not in ("hidden", "honeypot", "checkbox"):
            want.add(f"{stem}-required")
        if field["cap"] is not None:
            want |= {f"{stem}-maxlength-{case}" for case in ("below", "above", "absent")}
        if kind not in ("hidden", "honeypot"):
            want |= {f"{stem}-{case}" for case in ("label-for", "no-label", "hint-reworded",
                                                   "label-reworded")}
        if field["autocomplete"] is None and kind in ("text", "url", "email", "textarea"):
            want.add(f"{stem}-autocomplete-off")
        if kind == "file":
            want |= {f"b-{channel}-files-accept-without-{mime.split('/')[1]}" for mime in mimes}
want |= {f"d-{path.strip('/')}-in-sitemap" for path in sitecheck.INTAKE_UNLISTED}
for rid in sitecheck.INTAKE_RESULT_IDS:
    want |= {f"d-{rid}-{case}" for case in ("missing", "doubled", "id-elsewhere",
                                            "heading-reworded", "text-reworded")}
missing = sorted(want - render)
if missing:
    print(f"FAIL render-intake/coverage: {len(missing)} member(s) without a row: "
          + ", ".join(missing[:20]))
else:
    print(f"ok   render-intake/coverage ({len(want)} member rows)")
want = {f"fail-intake-host-in-{attr.replace(':', '-')}" for attr in sitecheck.URL_ATTRS}
want |= {f"fail-{tag}-{'action' if attr == 'action' else 'formaction'}-intake"
         + ("-slash" if tag == "form" else "") for tag, attr in sitecheck.FORM_ATTRS}
want |= {"fail-csp-form-action-missing-intake"
         + ("" if channel == "report" else f"-{channel}")
         for channel in sitecheck.INTAKE_FORM_PAGES.values()}
want |= {f"csp-intake/{directive}" for directive in sitecheck.CSP_DIRECTIVES - {"form-action"}}
missing = sorted(want - site)
if missing:
    print(f"FAIL site-intake/coverage: {len(missing)} member(s) without a row: "
          + ", ".join(missing))
else:
    print(f"ok   site-intake/coverage ({len(want)} member rows)")
PY
}

# bidi_coverage <sitecheck.py> <cases table> <label> [drop]
# (Replikanti/interviewscam#28): the table has a row member-<XXXX> for
# every code point of BIDI_CONTROLS, taken from the code, so a member left
# without a row fails <label>/coverage. With drop, that row is left out of
# the table first, so the line must fail (the negative proof). -B: no
# tools/__pycache__.
bidi_coverage() {
  python3 -I -B - "$1" "$2" "$3" "${4:-}" <<'PY'
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
label, drop = sys.argv[3], sys.argv[4]
names = {line.split("\t", 1)[0] for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
         if line and not line.startswith("#")} - {drop}
want = {f"member-{cp:04X}" for cp in sitecheck.BIDI_CONTROLS}
missing = sorted(want - names)
if missing:
    print(f"FAIL {label}/coverage: {len(missing)} member(s) without a row: " + ", ".join(missing))
else:
    print(f"ok   {label}/coverage ({len(want)} member rows)")
PY
}

# confusables_runner <sitecheck.py> <render base case> <schema dir>
# (Replikanti/interviewscam#28, ADR-0004 Numbers): the vendored
# confusables data and the look-alike readings, through importlib, from
# another working directory. The real file loads with its pins (version,
# 6712 entries, first source U+05AD and last U+2FD5, so neither end line is
# lost); every loader branch is a
# UsageError, each on a copy with its own SHA-256 so the branch itself is
# reached (one byte changed, a missing, empty or non-UTF-8 file, the version
# line changed or doubled, a source twice, a two-code-point source, a line
# with two fields, an empty target, another type, a code point outside
# Unicode, one entry less); the real command exits 2 with one ERROR line and
# no traceback on a changed byte and a missing file; CAPITAL_L equals the
# capitals the table maps to "l"; the marks are dropped before the first
# case fold even with a table that does not map U+0345; the skeleton loop
# settles in exactly SKELETON_ROUNDS rounds and a chain one longer is a
# UsageError; R1 and R2
# are idempotent, marks kept and dropped, on every source and target code
# point of the table; no target holds rule 4's span markers; and the
# guard's pin gives exactly its findings on built roots. -B: no
# tools/__pycache__.
confusables_runner() {
  python3 -I -B - "$1" "$2" "$3" <<'PY'
import contextlib
import hashlib
import importlib.util
import io
import os
import sys
import tempfile
import traceback
import unicodedata
from pathlib import Path

# From another working directory: the data path comes from sitecheck.py's
# own location (CONFUSABLES_PATH), as records mode and the shards need.
base, schema_dir = Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
script = Path(sys.argv[1]).resolve()
os.chdir(tempfile.gettempdir())
spec = importlib.util.spec_from_file_location("sitecheck", script)
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)
REAL = sc.CONFUSABLES_PATH
real_bytes = REAL.read_bytes()
REAL_PIN = (sc.CONFUSABLES_SHA256, sc.CONFUSABLES_VERSION, sc.CONFUSABLES_ENTRIES)


def row(name, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} confusables/{name}" + (f": {detail}" if detail and not ok else (f" ({detail})" if detail else "")))


def reset(tables=None):
    sc._CONFUSABLES = tables
    sc.skeleton_fold.cache_clear()
    sc.sentence_folds.cache_clear()


try:
    table = sc.load_confusables(REAL, *REAL_PIN)
    keys = list(table)
    row("real-file", len(table) == 6712 and keys[0] == 0x05AD and keys[-1] == 0x2FD5
        and sc.CONFUSABLES_VERSION == "18.0.0" and REAL == script.parent / "unicode/confusables.txt",
        f"{len(table)} entries, first U+{keys[0]:04X}, last U+{keys[-1]:04X}")
except Exception as exc:
    row("real-file", False, repr(exc))
    sys.exit(0)

text = real_bytes.decode("utf-8")
first = "05AD ;\t0596 ;\tMA"
assert text.count(first) == 1
lines = text.split("\n")
data_at = next(i for i, line in enumerate(lines) if line.startswith(first))
loader = {
    # name: (bytes, own SHA-256, text the UsageError names)
    "changed-byte": (real_bytes.replace(b"05AD ;\t0596", b"05AD ;\t0597", 1), False, "has the SHA-256"),
    "missing-file": (None, False, "cannot read the confusables data"),
    "empty-file": (b"", True, "carries the version line(s) []"),
    "not-utf8": (real_bytes + b"\xff", True, "is not UTF-8"),
    "version-line": (text.replace("# Version: 18.0.0", "# Version: 17.0.0", 1).encode(), True,
                     "carries the version line(s) ['17.0.0']"),
    "version-twice": (text.replace("# Version: 18.0.0", "# Version: 18.0.0\n# Version: 18.0.0", 1).encode(),
                      True, "carries the version line(s) ['18.0.0', '18.0.0']"),
    "source-twice": ("\n".join(lines[:data_at + 1] + [lines[data_at]] + lines[data_at + 1:]).encode(), True,
                     "the source U+05AD is listed twice"),
    "two-code-point-source": (text.replace(first, "05AD 05AE ;\t0596 ;\tMA", 1).encode(), True,
                              "not a data line"),
    "two-fields": (text.replace(first, "05AD ;\t0596", 1).encode(), True, "not a data line"),
    "empty-target": (text.replace(first, "05AD ;\t ;\tMA", 1).encode(), True, "not a data line"),
    "other-type": (text.replace(first, "05AD ;\t0596 ;\tSL", 1).encode(), True, "not a data line"),
    "outside-unicode": (text.replace(first, "110000 ;\t0596 ;\tMA", 1).encode(), True,
                        "a code point outside Unicode"),
    "count-off-by-one": ("\n".join(lines[:data_at] + lines[data_at + 1:]).encode(), True,
                         "holds 6711 entries, not 6712"),
}
with tempfile.TemporaryDirectory() as tmp:
    for name, (data, own, want) in loader.items():
        path = Path(tmp) / name / "confusables.txt"
        path.parent.mkdir()
        if data is not None:
            path.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest() if own else REAL_PIN[0]
        try:
            sc.load_confusables(path, sha, *REAL_PIN[1:])
            row(f"loader-{name}", False, "loaded without a UsageError")
        except sc.UsageError as exc:
            row(f"loader-{name}", want in str(exc), f"{exc}"[:160])
        except Exception:
            row(f"loader-{name}", False, "not a UsageError: " + traceback.format_exc().splitlines()[-1])
    # The real command: exit 2, one ERROR line, no traceback.
    argv = ["render", "--records", str(base), "--schemas", str(schema_dir), "--no-intake",
            str(base / "public")]
    for name in ("changed-byte", "missing-file"):
        sc.CONFUSABLES_PATH = Path(tmp) / name / "confusables.txt"
        reset()
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = sc.main(argv)
            row(f"exit-2-{name}", rc == 2 and "sitecheck: ERROR: " in err.getvalue()
                and "Traceback" not in out.getvalue() + err.getvalue(),
                f"exit {rc}, stderr {err.getvalue().strip()[:160]!r}")
        except BaseException:
            row(f"exit-2-{name}", False, "raised: " + traceback.format_exc().splitlines()[-1])
    sc.CONFUSABLES_PATH = REAL
    reset()

r1, r2 = sc.confusable_tables()
derived = sorted(cp for cp, proto in r1.items() if proto == "l" and chr(cp) != chr(cp).casefold())
row("capital-l-set", sorted(sc.CAPITAL_L) == derived and len(sc.CAPITAL_L) == 10,
    "CAPITAL_L " + " ".join(f"U+{cp:04X}" for cp in sorted(sc.CAPITAL_L)) + " vs the table's "
    + " ".join(f"U+{cp:04X}" for cp in derived))
lower = {cp: unicodedata.normalize("NFD", chr(cp).casefold()).translate(r1) for cp in sc.CAPITAL_L}
row("capital-l-reads-lower", all(r2[cp] == lower[cp] for cp in sc.CAPITAL_L)
    and r2[0x49] == "i" and r2[0x0399] == "i" and {cp: p for cp, p in r2.items() if cp not in lower}
    == {cp: p for cp, p in r1.items() if cp not in lower},
    "R2 reads each CAPITAL_L member as the prototype of its case fold, I and Greek Iota as i, "
    "and every other entry as R1")

saved = sc.CAPITAL_L
sc.CAPITAL_L = saved + (0x41,)
reset()
try:
    sc.confusable_tables()
    row("capital-l-guard", False, "a CAPITAL_L member whose prototype is not l loaded")
except sc.UsageError as exc:
    row("capital-l-guard", "U+0041" in str(exc), str(exc)[:160])
sc.CAPITAL_L = saved
reset()

# Marks dropped before the first case fold, whatever the table holds: with
# an empty test table, U+0345 (the one mark the case fold turns into a
# letter, an iota) after "a" must fold to "a". The real table maps U+0345
# to U+0328, another mark, so only a test table reaches this drop.
reset(({}, {}))
got = sc.sentence_folds("a\u0345")
row("marks-before-casefold", got[1:] == ("a",) * 6,
    f"every skeleton reading of a + U+0345 with an empty table: {got[1:]!r}")
reset()

# SKELETON_ROUNDS, inclusive, against the number of ADR-0004 Numbers (4,
# written here, not read from the module): a chain that changes in 3 loop
# rounds and settles in the 4th passes; one more step fails.
letters = "abcdefg"
n = 4


def chain(steps):
    t = {ord(letters[i]): letters[i + 1] for i in range(steps)}
    return t, t


reset(chain(n))
try:
    got = sc._skeleton("a", False, False)
    row("rounds-cap-inclusive", got == letters[n] and sc.SKELETON_ROUNDS == n,
        f"{n} table steps settle on {got!r}, SKELETON_ROUNDS {sc.SKELETON_ROUNDS}")
except sc.UsageError as exc:
    row("rounds-cap-inclusive", False, f"a chain of {n} steps raised: {exc}")
reset(chain(n + 1))
try:
    got = sc._skeleton("a", False, False)
    row("rounds-cap", False, f"a chain of {n + 1} steps gave {got!r}, not a UsageError")
except sc.UsageError as exc:
    row("rounds-cap", "still changes after SKELETON_ROUNDS" in str(exc), str(exc)[:160])
cycle = {ord("a"): "b", ord("b"): "a"}
reset((cycle, cycle))
try:
    sc.sentence_folds("a")
    row("rounds-cycle", False, "a two-letter cycle settled")
except sc.UsageError as exc:
    row("rounds-cycle", "still changes after SKELETON_ROUNDS" in str(exc), str(exc)[:160])
reset()

# Idempotence over every code point the table names (sources and targets).
points = sorted(set(r1) | {ord(ch) for proto in r1.values() for ch in proto})
bad = []
for cp in points:
    ch = chr(cp)
    for capital_i in (False, True):
        for marks in (False, True):
            once = sc._skeleton(ch, capital_i, marks)
            if sc._skeleton(once, capital_i, marks) != once:
                bad.append(f"U+{cp:04X} capital_i={capital_i} marks={marks}")
row("idempotent", not bad, f"{len(points)} code points x 4 readings, unicodedata "
    f"{unicodedata.unidata_version}; not idempotent: {bad[:8]}" if bad else
    f"{len(points)} code points x 4 readings, unicodedata {unicodedata.unidata_version}")
markers = {sc.SPAN_OPEN, sc.SPAN_CLOSE}
row("no-span-marker-target", not any(m in proto for proto in r1.values() for m in markers)
    and not (set(map(ord, markers)) & set(r1)),
    "no table source or target holds U+E000 or U+E001")

# The visual-order reading (fix round 1, review finding 1): bidi_resolve
# against every line of the vendored conformance subset (levels and order),
# each bidi loader branch, and visual_order on its paragraph and fast paths.
classes, brackets, _ = sc.bidi_tables()
tests = sc.load_bidi_test(sc.BIDI_TEST_PATH, sc.BIDI_TEST_SHA256, "18.0.0", 45807)
bad = [cps for cps, levels, order in tests if sc.bidi_resolve(cps, classes, brackets) != (levels, order)]
row("bidi-conformance", len(tests) == 45807 and not bad,
    f"{len(tests)} lines of BidiCharacterTest-18.0.0, LTR, no explicit formatting character; "
    f"{len(bad)} differ" + (f", first {' '.join(f'{c:04X}' for c in bad[0])}" if bad else ""))
# Rules the conformance subset does not reach in a left-to-right paragraph
# (implementer sweep round 5), each with its levels derived from UAX #9 by
# hand: W1 (a mark after a right-to-left letter is R, so it sits at level
# 1, not 0 as a neutral before L would), W5 (a terminator after a digit is
# EN, level 2, not a neutral at 0), L1 (a segment separator and the
# whitespace before it go back to level 0, not 1 between two R), and the
# bracket pairs at depth 63, the most the stack of BD16 holds (the closing brackets
# between R and L resolve to R by N0 c, level 1, not to L by N2), and at
# depth 64, one past it (BD16 stops at the 64th opener before any closer, so
# no pair forms: the openers between two R are R by N1, the closers before
# the final L are L by N2, level 0; fix round 2, delta review finding 2).
hand = {
    "w1": ([0x61, 0x20, 0x05D0, 0x0591, 0x20, 0x62], [0, 0, 1, 1, 0, 0]),
    "w5": ([0x05D0, 0x31, 0x25], [1, 2, 2]),
    "l1": ([0x05D0, 0x20, 0x09, 0x05D1], [1, 0, 0, 1]),
    "bracket-depth-63": ([0x05D0] + [0x28] * 63 + [0x05D1] + [0x29] * 63 + [0x63], [1] * 128 + [0]),
    "bracket-depth-64": ([0x05D0] + [0x28] * 64 + [0x05D1] + [0x29] * 64 + [0x63],
                         [1] * 66 + [0] * 65),
}
for name, (cps, want) in hand.items():
    got = sc.bidi_resolve(cps, classes, brackets)[0]
    row(f"bidi-rule-{name}", got == want, f"levels {got[:8]}... want {want[:8]}...")
row("bidi-classes", classes[0x05D0] == sc.BIDI_CLASSES.index("R")
    and classes[0x0627] == sc.BIDI_CLASSES.index("AL") and classes[0x0661] == sc.BIDI_CLASSES.index("AN")
    and classes[0x05FF] == sc.BIDI_CLASSES.index("R") and classes[0x20CF] == sc.BIDI_CLASSES.index("ET")
    and classes[0x0041] == sc.BIDI_CLASSES.index("L") and len(brackets) == 130,
    "Hebrew R, Arabic AL and AN, the R default of an unassigned Hebrew code point, the ET "
    "default of U+20CF, Latin L, 130 brackets")
bidi_files = {
    "classes": (sc.BIDI_CLASS_PATH, sc.load_bidi_classes, sc.BIDI_CLASS_ENTRIES),
    "brackets": (sc.BIDI_BRACKETS_PATH, sc.load_bidi_brackets, sc.BIDI_BRACKETS_ENTRIES),
    "test": (sc.BIDI_TEST_PATH, sc.load_bidi_test, sc.BIDI_TEST_ROWS),
}
with tempfile.TemporaryDirectory() as tmp:
    for kind, (path, load, count) in bidi_files.items():
        real = path.read_bytes()
        text = real.decode("utf-8")
        lines = text.split("\n")
        data_at = next(i for i, line in enumerate(lines) if line and not line.startswith("#"))
        variants = {
            "changed-byte": (real[:-2] + b"\n\n", False, "has the SHA-256"),
            "header": (text.replace("18.0.0", "17.0.0", 1).encode(), True, "does not start with"),
            "line-form": ("\n".join(lines[:data_at] + ["x" + lines[data_at]] + lines[data_at + 1:]).encode(),
                          True, ":" + str(data_at + 1) + ": not"),
            "count": ("\n".join(lines[:data_at] + lines[data_at + 1:]).encode(), True, f"not {count}"),
        }
        if kind == "classes":
            variants["unknown-class"] = (text.replace("; L #", "; Q #", 1).encode(), True, "a known class")
            variants["missing-line"] = (text.replace("; Right_To_Left", "; Right_To_Lefty", 1).encode(),
                                        True, "not an @missing line")
        if kind == "brackets":
            variants["twice"] = ("\n".join(lines[:data_at + 1] + [lines[data_at]] + lines[data_at + 1:]).encode(),
                                 True, "listed twice")
        if kind == "test":
            variants["source-sha"] = (text.replace(sc.BIDI_TEST_SOURCE_SHA256, "0" * 64).encode(), True,
                                      "does not name the SHA-256 of its source")
        for name, (data, own, want) in variants.items():
            target = Path(tmp) / f"{kind}-{name}" / path.name
            target.parent.mkdir()
            target.write_bytes(data)
            sha = hashlib.sha256(data).hexdigest() if own else hashlib.sha256(real).hexdigest()
            try:
                load(target, sha, "18.0.0", count)
                row(f"bidi-loader-{kind}-{name}", False, "loaded without a UsageError")
            except sc.UsageError as exc:
                row(f"bidi-loader-{kind}-{name}", want in str(exc), str(exc)[:160])
            except Exception:
                row(f"bidi-loader-{kind}-{name}", False, "not a UsageError: "
                    + traceback.format_exc().splitlines()[-1])
row("visual-order", sc.visual_order("ab אב cd") == "ab בא cd"
    and sc.visual_order("אב\nגד") == "בא\nדג"
    and sc.visual_order("café x") == "café x" and sc.visual_order("a​b") == "a​b",
    "one reversed run, a paragraph separator kept in place, the stored order without R, AL or AN")
# The paragraphs of Element.bidi_text (fix rounds 2 and 3): every member of
# BIDI_BLOCK_TAGS, written out here and compared with the code, opens and
# closes a paragraph (a <br> and <hr> one each), an inline element none;
# every member of BIDI_PRESERVE_TAGS keeps its line feed and tab, other text
# collapses them to a space; and U+001C to U+001F and U+0085 reach the text
# as written (delta reviews 2 and 3, QA B4).
blocks = ("address article aside blockquote body caption dd details dialog div dl dt fieldset "
          "figcaption figure footer form h1 h2 h3 h4 h5 h6 header hgroup hr html legend li main "
          "menu nav ol p pre search section summary table tbody td tfoot th thead tr ul").split()
preserve = ("listing", "plaintext", "pre", "textarea", "xmp")
P = sc.BIDI_PARAGRAPH


def bidi(body):
    return sc.parse_render_page(f"<!doctype html><html><body><main>{body}</main></body></html>").root.bidi_text()


row("bidi-block-tags", sorted(sc.BIDI_BLOCK_TAGS) == sorted(blocks) and len(blocks) == 46,
    f"{len(sc.BIDI_BLOCK_TAGS)} members, the written list {len(blocks)}")
opened = {"details": " open", "dialog": " open"}  # closed ones hide their text
bad = [t for t in blocks if bidi(f"a<{t}{opened.get(t, '')}>b</{t}>c" if t != "hr" else "a<hr>c")
       != (f"a{P}b{P}c" if t != "hr" else f"a{P}c")]
bad += [t for t in ("span", "b", "a", "code", "em") if bidi(f"a<{t}>b</{t}>c") != "abc"]
bad += ["br"] if bidi("a<br>c") != f"a{P}c" else []
row("bidi-block-paragraphs", not bad, f"every member a paragraph, br one, inline none; wrong: {bad}")
row("bidi-preserve-tags", sorted(sc.BIDI_PRESERVE_TAGS) == sorted(preserve),
    f"{sorted(sc.BIDI_PRESERVE_TAGS)}")
bad = [t for t in preserve if f"x\ny\tz" not in bidi(f"<{t}>x\ny\tz</{t}>")]
bad += ["p"] if bidi("<p>x\ny\tz\r\f w</p>") != "x y z w" else []
bad += ["controls"] if bidi("<p>a\x1cb\x1dc\x1ed\x1fe\x85f\u2029g</p>") != "a\x1cb\x1dc\x1ed\x1fe\x85f" + P + "g" else []
row("bidi-whitespace", not bad, f"pre keeps line feed and tab, p collapses CSS whitespace, controls kept; wrong: {bad}")

# skeleton_fold, the name reading PR 2 wires (QA B2): a Cyrillic look-alike,
# a modifier letter as a separator, and the visual order of an RTL run.
got = (sc.skeleton_fold("Аvery Exampleton"), sc.skeleton_fold("AveryˌExampleton"),
       sc.skeleton_fold("Avery Exampleסߠn", visual=True),
       sc.skeleton_fold("Avery Exampleסߠn"), sc.skeleton_fold("ΙVERY", True))
row("skeleton-fold", got == ("avery exarnpleton", "avery exarnpleton", "avery exarnpleton",
                             "avery exarnpleotn", "ivery"), f"got {got!r}")

# The persona-name readings (Replikanti/interviewscam#28 PR 2): the note
# each reading adds (none for R0, so an R0 message stays byte for byte),
# the token structure taken from R0 (the skeleton reads "m" as "rn": "Tim"
# stays a 3-letter token that does not join, "M." stays an initial that
# needs its period), a name that folds to nothing under a reading, the
# span markers through the drawn order, and the shared folds of
# reading_folds against name_fold.
notes = [sc.reading_note(r) for r in range(len(sc.NAME_READINGS))]
row("name-reading-notes", sc.NAME_READINGS == ("R0", "R1", "R2", "R3", "V1", "V2", "V3")
    and notes == [""] + [sc.LOOKALIKE_NOTE] * 3 + [sc.DRAWN_NOTE] * 3
    and sc.NAME_READING_FORMS == {1: (False, False, False), 2: (True, False, False),
                                  3: (False, True, False), 4: (False, False, True),
                                  5: (True, False, True), 6: (False, True, True)},
    f"{len(notes)} notes")
R = range(len(sc.NAME_READINGS))


def hits(name, text):
    return [r for r in R if sc.name_pattern(name, r).search(sc.name_fold(text, r))]


# V1 to V3 read only a text that draws in another order, so a
# left-to-right text hits under R0 to R3 at most.
STORED = [0, 1, 2, 3]
got = (hits("Tim Kim", "TimKim"), hits("Tim Kim", "Tim Kim"), hits("Tim Kim", "Tim-Kim"),
       hits("Avery Exampleton", "AveryExampleton"), hits("Li Kensington", "LiKensington"),
       hits("Li Kensington", "Li Kensington"))
row("name-pattern-join-min-letters", got == ([], STORED, STORED, STORED, [], STORED),
    f"got {got!r}")
got = (hits("M. Page", "m page"), hits("M. Page", "M. Page"), hits("M. Page", "m.page"),
       hits("M. Page", "rn page"), hits("M. Page", "rn. page"))
row("name-pattern-initial", got == ([], STORED, STORED, [], [1, 2, 3]), f"got {got!r}")
# The stroke reading R3 (fix round 1, review findings A2 and C): a stroke
# stands for "i", for "l" or for a separator, a written "l" or a dotted
# "i" keeps its letter, and a left-to-right text gives V1 to V3 nothing.
got = (hits("Ali", "all"), hits("Ali", "Of all things"), hits("Neil", "nell"),
       hits("Riley Placeholder", "R|ley Placeholder"), hits("Riley Placeholder", "RILEY PLACEHOLDER"),
       hits("Avery Exampleton", "Avery\u01c0Exampleton"), hits("Avery Exampleton", "Avery\u04c0Exampleton"),
       hits("Avery Exampleton", "AverylExampleton"), hits("Ali", "Al|"),
       hits("Riley Placeholder", "Ri\u0307ley Placeholder"), hits("Zo\u00eb", "Zoe"),
       sc.name_fold("Riley Placeh\u05d5\u05e1der", 4))
row("name-stroke-reading", got == ([], [], [], [3], [0, 2, 3], [3], [3], [], [3], [1, 2, 3],
                                    [1, 2, 3], "riley placeholder"), f"got {got!r}")
# Fix round 2 (delta review 1 to 3): the matcher of rules 4, 9 and 12
# (name_pattern) and R5's (r5_patterns) agree on every pair, a name and a
# text: no stroke as a name's outer boundary, a written "l" for a name's
# capital I at the start, inside a word and in a word of capitals, U+4E28
# and the strokes the table maps to it as a separator, digits of a number
# as digits, the accepted false positive "Ian" in "LAN", and a name with
# U+0130 (fix round 3: its case fold "i" + U+0307 no longer splits a token).
pairs = [("Ali", "all", False), ("Il", "ill", False), ("Il", "I'll say", False),
         ("Li", "Il", False), ("Ali", "ALL", False), ("Rene", "Irene", False),
         ("Van", "Ivan", False), ("Van Le", "Ivan Le", False), ("Dan", "DANIEL", False),
         ("Tem", "ListItem", False), ("Li", "2026-11-01", False), ("Il", "2026-11-01", False),
         ("Ivan Petrov", "lvan Petrov", True), ("Ian McIntyre", "lan McIntyre", True),
         ("Ian McIntyre", "Ian Mclntyre", True), ("Riley Placeholder", "RlLEY PLACEHOLDER", True),
         ("Ivan Petrov", "lVAN PETROV", True), ("Avery Exampleton", "Avery丨Exampleton", True),
         ("Avery Exampleton", "Avery⼁Exampleton", True),
         ("Avery Exampleton", "AveryㅣExampleton", True),
         ("Avery Exampleton", "AveryￜExampleton", True), ("Riley", "R1ley", True),
         ("Ian", "LAN", True), ("\u0130van Petrov", "\u0130van Petrov", True),
         ("\u0130van Petrov", "Ivan Petrov", True), ("Kelly Brooks", "Ke11y Br00ks", True),
         ("Ollie", "011ie", True), ("Bill Lloyd", "Bi11 11oyd", True), ("Li", "11:11", False),
         ("Il", "+1 555 0101", False), ("Li", "room 101", False),
         ("Avery Exampleton", "Avery 12 Exampleton", False)]
bad = [(n, x) for n, x, want in pairs
       if bool(hits(n, x)) != want or (sc.r5_reading(sc.r5_patterns(n), x) is not None) != want]
row("name-pairs", not bad, f"{len(pairs)} pairs, wrong: {bad!r}")
# Fix round 4 (QA's survivors of run 44777095416): the exact readings that
# hit, where a reading set can lose an edge: a stroke as the outer
# boundary under V3 too (Irene before right-to-left text) and the CJK
# stroke there, a word with exactly CAPS_L_MIN other capitals, digits glued
# to a name, a held digit run given back (else "12" would join two tokens
# as no word character), and U+0130 under V2 and V3.
got = (hits("Rene", "Irene \u05d0\u05d1"), hits("Rene", "\u4e28rene"), hits("Lin", "LlN"),
       hits("Lin Wu", "LlN WU"), hits("Rene", "Rene12"), hits("Rene", "12Rene"),
       hits("Avery Exampleton", "Avery 12 Exampleton"),
       hits("\u0130van Petrov", "\u0130van Petrov \u05d0\u05d1"))
row("name-pattern-edges", got == ([], [], [3], [3], [], [], [], [2, 3, 5, 6]), f"got {got!r}")
# A name whose written form has more tokens than its case fold with the
# marks dropped (a combining mark of its own between two letters): the
# stroke readings fall back to the case-folded tokens instead of indexing
# into the written ones, which would drop "Placeholder"; and a name with
# U+0130 meets its own bare spelling under R2 and R3 (fix round 3).
try:
    got = (hits("Ri\u0307ley Placeholder", "R|ley Placeholder"),
           hits("Ri\u0307ley Placeholder", "R|ley"), hits("\u0130van Petrov", "\u0130van Petrov"))
except Exception as exc:  # noqa: BLE001 - the row reports any crash
    got = repr(exc)
row("name-pattern-case-fold-split", got == ([3], [], [2, 3]), f"got {got!r}")
got = (sc.caps_l("RlLEY lVAN Il Ill all McLl"), sc.stroke_table()[0x4E28] == sc.STROKE_CJK,
       sorted(cp for cp, v in sc.confusable_tables()[0].items() if v == "丨")
       == sorted(cp for cp, v in sc.stroke_table().items() if v == sc.STROKE_CJK and cp != 0x4E28))
row("name-caps-l-and-cjk-stroke", got == (f"R{sc.STROKE}LEY {sc.STROKE}VAN Il Ill all McLl", True, True),
    f"got {got!r}")

# R1 is R3 with every STROKE read as "l" (reading_folds derives it so):
# every source and target code point of the table, alone, between two
# letters and before a combining mark.
cps = sorted(set(table) | {ord(c) for v in table.values() for c in v})
bad = [f"U+{cp:04X}" for cp in cps for x in (chr(cp), f"a{chr(cp)}b", chr(cp) + "\u0301")
       if sc.skeleton_fold(x) != sc.skeleton_fold(x, stroke=True).replace(sc.STROKE, "l")
       .replace(sc.STROKE_CJK, sc.CJK_STROKE)]
row("stroke-to-r1", not bad and len(cps) > 8000, f"{len(cps)} code points, differ: {bad[:5]}")
got = (sc.name_pattern("ˌ", 0) is sc.NEVER, sc.name_pattern("ˌ", 1) is sc.NEVER,
       sc.name_pattern("⠀", 0) is sc.NEVER, sc.name_pattern("⠀", 1) is sc.NEVER,
       hits("⠀", "x ⠀ y"), sc.name_pattern("\u200b", 0) is sc.NEVER, hits("\u200b", "a, b"))
# A name of invisibles alone folds to nothing under R0 as well: R0 keeps
# its old pattern, which matches every text (fails closed).
row("name-pattern-folds-to-nothing", got == (False, True, False, True, [0], False, [0]),
    f"got {got!r}")
O, C = sc.SPAN_OPEN, sc.SPAN_CLOSE
got = (sc.visual_spans(f"x {O}אב{C} y"), sc.visual_spans(f"א{O}בc{C}"),
       sc.visual_spans(f"x {O}ab{C} y"), sc.visual_spans("x אב y"))
row("visual-spans", got == (f"x {O}בא{C} y", f"{O}ב{C}א{O}c{C}",
                            f"x {O}ab{C} y", "x בא y"), f"got {got!r}")
# U+10CA5, the one capital of CAPITAL_L that R2 reads as neither "i" nor
# "l", tells R3 (from R1) from a fold of R2.
texts = ["Riley Placehוסder", "RΙLEY |nfo", "plain text", "Mоrgan א",
         "\U00010ca5ay", "Ali|א \ue002", "Avery\u4e28Exampleton \u2f01 \ue003 RlLEY 2026-11-01"]
drawn = [sc.visual_order(t) for t in texts]
memo = {}
bad = [r for r in R if sc.reading_folds(texts, drawn, r, memo, 2)
       != [sc.name_fold(t, r) for t in texts]]
row("reading-folds", not bad, f"readings that differ from name_fold: {bad}")

# The guard's pin on built roots: every vendored file is copied unless the
# case names it.
def guard(root):
    findings = sc.Findings()
    sc.guard_confusables_pin(root, findings)
    return sorted(item[len("FAIL: "):].split(": ", 1)[0] + ": " +
                  item.split(": ", 2)[2][:40] for item in findings.items)


licence = (REAL.parent / sc.CONFUSABLES_LICENSE).read_bytes()
others = {path.name: path.read_bytes() for path, _, _ in bidi_files.values()}
cases = {
    "pass-real-copy": ({"data": real_bytes, "licence": licence}, []),
    "no-tools": (None, []),
    "data-changed": ({"data": loader["changed-byte"][0], "licence": licence},
                     ["tools/unicode/confusables.txt: the confusables data tools/unic"]),
    "data-short": ({"data": loader["count-off-by-one"][0], "licence": licence},
                   ["tools/unicode/confusables.txt: the confusables data tools/unic"]),
    "data-missing": ({"licence": licence},
                     ["tools/unicode/confusables.txt: missing or not a regular file; t"]),
    "data-symlink": ({"data-link": real_bytes, "licence": licence},
                     ["tools/unicode/confusables.txt: missing or not a regular file; t"]),
    "licence-missing": ({"data": real_bytes},
                        ["tools/unicode/LICENSE: missing or not a regular file; the Uni"]),
    "licence-changed": ({"data": real_bytes, "licence": licence + b"\n"},
                        ["tools/unicode/LICENSE: the licence's SHA-256 is"]),
    "licence-symlink": ({"data": real_bytes, "licence-link": licence},
                        ["tools/unicode/LICENSE: missing or not a regular file; the Uni"]),
    "bidi-classes-changed": ({"data": real_bytes, "licence": licence,
                              "replace": ("DerivedBidiClass.txt", others["DerivedBidiClass.txt"] + b"\n")},
                             ["tools/unicode/DerivedBidiClass.txt: the Unicode data tools/unicode"]),
    "bidi-brackets-missing": ({"data": real_bytes, "licence": licence, "drop": "BidiBrackets.txt"},
                              ["tools/unicode/BidiBrackets.txt: missing or not a regular file; t"]),
    "bidi-test-symlink": ({"data": real_bytes, "licence": licence, "link": "BidiCharacterTest-ltr.txt"},
                          ["tools/unicode/BidiCharacterTest-ltr.txt: missing or not a regular file; t"]),
    "extra-file": ({"data": real_bytes, "licence": licence, "extra": "BidiTest.txt"},
                   ["tools/unicode/BidiTest.txt: an entry of tools/unicode/ that is no"]),
    "extra-directory": ({"data": real_bytes, "licence": licence, "extra-dir": "old"},
                        ["tools/unicode/old: an entry of tools/unicode/ that is no"]),
    "unicode-dir-only": ({"no-script": True, "licence": licence},
                         ["tools/unicode/confusables.txt: missing or not a regular file; t"]),
    "unicode-dir-missing": ({"no-unicode": True},
                            ["tools/unicode/BidiBrackets.txt: missing or not a regular file; t",
                             "tools/unicode/BidiCharacterTest-ltr.txt: missing or not a regular file; t",
                             "tools/unicode/DerivedBidiClass.txt: missing or not a regular file; t",
                             "tools/unicode/LICENSE: missing or not a regular file; the Uni",
                             "tools/unicode/confusables.txt: missing or not a regular file; t"]),
}
with tempfile.TemporaryDirectory() as tmp:
    for name, (files, want) in cases.items():
        root = Path(tmp) / name
        root.mkdir()
        if files is not None:
            unicode_dir = root / "tools" / "unicode"
            unicode_dir.mkdir(parents=True)
            if files.get("no-unicode"):
                unicode_dir.rmdir()
            if not files.get("no-script"):
                (root / "tools" / "sitecheck.py").write_text("# stand-in\n")
            if not files.get("no-unicode"):
                for other, data in others.items():
                    if other == files.get("drop"):
                        continue
                    if other == files.get("link"):
                        (root / other).write_bytes(data)
                        os.symlink(root / other, unicode_dir / other)
                        continue
                    replace = files.get("replace")
                    (unicode_dir / other).write_bytes(replace[1] if replace and replace[0] == other else data)
            if "data" in files:
                (unicode_dir / "confusables.txt").write_bytes(files["data"])
            if "data-link" in files:
                (root / "elsewhere.txt").write_bytes(files["data-link"])
                os.symlink(root / "elsewhere.txt", unicode_dir / "confusables.txt")
            if "licence" in files:
                (unicode_dir / "LICENSE").write_bytes(files["licence"])
            if "extra" in files:
                (unicode_dir / files["extra"]).write_text("# not pinned\n")
            if "extra-dir" in files:
                (unicode_dir / files["extra-dir"]).mkdir()
            if "licence-link" in files:
                (root / "licence.txt").write_bytes(files["licence-link"])
                os.symlink(root / "licence.txt", unicode_dir / "LICENSE")
        got = guard(root)
        ok = len(got) == len(want) and all(g.startswith(w) for g, w in zip(got, sorted(want)))
        row(f"guard-{name}", ok, f"findings {got}")
PY
}

# allowlists_runner <sitecheck.py> <allowlists table>: the contents of every
# passing set of sitecheck literals (LITERALS_PASSING_SETS), of the CSP and
# guard allowlists, of site rule (k)'s two passing sets and URL trim set
# (M3 PR 10), and of the fix round 1 pins (the closed path alphabet, the
# .visually-hidden declarations, the template name regex with its flags),
# one line per entry, must equal the table (review3
# A3): a widening (one more member, function or attribute) changes no
# finding on today's tree, so only this pin shows it in review. -B: no
# tools/__pycache__.
allowlists_runner() {
  python3 -I -B - "$1" "$2" <<'PY'
import importlib.util
import json
import re
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
NAMES = sitecheck.PINNED_ALLOWLISTS


def text(value):
    if isinstance(value, (set, frozenset)):
        return " ".join(sorted(map(str, value)))
    if isinstance(value, tuple):
        return "\t".join(map(str, value))
    return value if isinstance(value, str) else json.dumps(value)


got = set()
for name in NAMES:
    value = getattr(sitecheck, name)
    if isinstance(value, re.Pattern):
        # A regex (LITERALS_TEMPLATE_NAME, M3 PR 10 fix round 1): its
        # pattern text and its flags.
        got.add(f"{name}\t{value.pattern}\t{int(value.flags)}")
    elif isinstance(value, dict):
        got.update(f"{name}\t{key}\t{text(item)}" for key, item in value.items())
    elif isinstance(value, str):
        # A character set (C0_AND_SPACE, M3 PR 10): one code point per line,
        # because its members are control characters.
        got.update(f"{name}\tU+{ord(c):04X}" for c in value)
    else:
        got.update(f"{name}\t{text(item)}" for item in value)
want = {line for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")}
extra, missing = sorted(got - want), sorted(want - got)
if extra or missing:
    print("FAIL literals-allowlists: the code differs from the pinned table; "
          + "; ".join([f"not pinned: {x!r}" for x in extra]
                      + [f"pinned, not in the code: {x!r}" for x in missing]))
else:
    print(f"ok   literals-allowlists ({len(NAMES)} allowlists, {len(got)} entries "
          "equal the pinned table)")
PY
}

# guard_public_runner <sitecheck.py> <schema dir> <pins.env> (ADR-0007 part 4,
# Replikanti/interviewscam#38 PR B): the public-tree rules PT1 to PT4 and the
# workflow hardening WH1 to WH4, one row per member of every flagging set and
# per form the readers take or refuse, each in its own temporary root (PT) or
# on one workflow text (WH), through importlib. The members are written out
# here, not read from the code, so a member cut from a set in sitecheck.py
# turns its row red: the 15 record keys (and a row that requires them to
# equal params.required of the two schemas), the 5 mail suffixes in lower
# and upper case, the 5 image signatures as bytes, the 4 allowed triggers
# (equal to WORKFLOW_TRIGGERS_ALLOWED) and the denied ones of ADR-0007 part
# 4. A PT row expects exactly one finding with its text (or none: PASS); a
# WH row exactly the number of findings it names. The last lines,
# guard-public/table and guard-wf/table, count the rows. -B: no
# tools/__pycache__.
guard_public_runner() {
  python3 -I -B - "$1" "$2" "$3" <<'PY'
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
schema_dir = Path(sys.argv[2])
sha = next(line.split("@", 1)[1] for line in Path(sys.argv[3]).read_text().splitlines()
           if line.startswith("ACTION_CHECKOUT="))
counts = {"guard-public": 0, "guard-wf": 0}
bad = {"guard-public": 0, "guard-wf": 0}


def report(family, name, ok, detail):
    counts[family] += 1
    if ok:
        print(f"ok   {family}/{name} ({detail})")
    else:
        bad[family] += 1
        print(f"FAIL {family}/{name}: {detail}")


# ---- PT rows: (name, files {rel: bytes or str}, symlinks, expect, git) ----
RECORD_KEYS = ("artifacts", "delivery", "evidence", "first_seen", "independent_reports",
               "last_reviewed", "last_seen", "name", "name_type", "sources", "state",
               "state_basis", "steals", "summary", "targeted_os")
MAIL_SUFFIXES = (".eml", ".emlx", ".mbox", ".mbx", ".msg")
IMAGES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "gif87a": b"GIF87a",
    "gif89a": b"GIF89a",
    "webp": b"RIFF\x00\x00\x00\x00WEBP",
}
SCHEMAS = {f"schema/{n}": (schema_dir / n).read_bytes()
           for n in ("report.schema.json", "campaign.schema.json")}
PAGE = '+++\ntitle = "About"\ndescription = "About the site."\n{extra}+++\nAbout.\n'
rows = []
PT1 = "PT1: a directory or symlink in content/"
PT2B = "PT2b: a record key"
PT4_MAIL = "PT4: a saved mail file"
PT4_IMAGE = "PT4: a raster image"
for key in RECORD_KEYS:
    rows.append((f"record-keys/{key}/top-level", {**SCHEMAS, "content/about.md":
                 PAGE.format(extra=f'{key} = "x"\n')}, (), PT2B))
    rows.append((f"record-keys/{key}/params", {**SCHEMAS, "content/about.md":
                 PAGE.format(extra=f'[params]\n{key} = "x"\n')}, (), PT2B))
for label, spelled in (("fullwidth", "ｎａｍｅ"), ("zero-width", "na​me"),
                       ("uppercase", "NAME")):
    rows.append((f"record-keys/name-{label}/top-level", {**SCHEMAS, "content/about.md":
                 PAGE.format(extra=f'"{spelled}" = "x"\n')}, (), PT2B))
    rows.append((f"record-keys/name-{label}/params", {**SCHEMAS, "content/about.md":
                 PAGE.format(extra=f'[params]\n"{spelled}" = "x"\n')}, (), PT2B))
rows += [
    ("record-keys/params-table-uppercase", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[PARAMS]\nsummary = "x"\n')}, (), PT2B),
    ("record-keys/params-array-of-tables", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[[params]]\nsummary = "x"\n')}, (), PT2B),
    ("record-keys/nested-table-passes", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[sitemap]\ndisable = true\n')}, (), "PASS"),
    ("record-keys/ignored-page-on-disk", {**SCHEMAS, ".gitignore": "/content/draft.md\n",
     "content/draft.md": PAGE.format(extra='summary = "x"\n')}, (), PT2B, True),
    # Design choice: the schema is read only when a static page needs it.
    ("pt2b/no-page-no-schema-passes", {"docs/readme.txt": "Text.\n"}, (), "PASS"),
    ("pt2b/page-no-schema-fails", {"content/about.md": PAGE.format(extra="")}, (),
     "PT2b: cannot read the record keys"),
    ("pt2b/page-unreadable-schema-fails", {"schema/report.schema.json": "{",
     "schema/campaign.schema.json": SCHEMAS["schema/campaign.schema.json"],
     "content/about.md": PAGE.format(extra="")}, (), "PT2b: cannot read the record keys"),
    ("pt2b/page-schema-required-empty-fails", {"schema/report.schema.json":
     '{"properties": {"params": {"required": []}}}',
     "schema/campaign.schema.json": SCHEMAS["schema/campaign.schema.json"],
     "content/about.md": PAGE.format(extra="")}, (), "PT2b: cannot read the record keys"),
    ("pt2b/page-schema-required-mapping-fails", {"schema/report.schema.json":
     '{"properties": {"params": {"required": {"name": true}}}}',
     "schema/campaign.schema.json": SCHEMAS["schema/campaign.schema.json"],
     "content/about.md": PAGE.format(extra="")}, (), "PT2b: cannot read the record keys"),
    ("pt2b/page-schema-without-required-fails", {"schema/report.schema.json": "{}",
     "schema/campaign.schema.json": SCHEMAS["schema/campaign.schema.json"],
     "content/about.md": PAGE.format(extra="")}, (), "PT2b: cannot read the record keys"),
    ("pt2b/leading-blank-before-fence-fails", {**SCHEMAS, "content/about.md":
     "\n" + PAGE.format(extra="")}, (), "PT2b: the front matter of a static page must be TOML"),
    # PT1 reads the disk: an ignored record directory fails too.
    ("pt1/ignored-on-disk", {".gitignore": "/content/*/\n", "content/reports/x.md":
     PAGE.format(extra="")}, (), PT1, True),
    ("pt1/empty-directory", {"docs/readme.txt": "x"}, ("content/reports/",), PT1),
    # Staged, then deleted from the disk: the next commit still carries it, so
    # git's listing counts as well as the disk (the read then fails closed).
    ("pt1/staged-deleted-on-disk", {"content/reports/x.md": "x"}, (),
     [PT1], "index-only"),
    ("pt2a/staged-deleted-org-in-content", {"content/x.org": "#+title: Draft\n"}, (),
     ["PT2a: a file in content/ that is not a static page"], "index-only"),
    ("pt1/dot-directory", {"content/.drafts/x.txt": "x"}, (), PT1),
    # PT3: the missing policy passes (design choice); every other form fails.
    ("pt3/missing-policy-passes", {"docs/readme.txt": "Text.\n"}, (), "PASS"),
    ("pt3/empty-policy-passes", {"schema/record-policy.json": '{ "retired_slugs" : [ ] }\n'},
     (), "PASS"),
    ("pt3/one-slug-fails", {"schema/record-policy.json": '{"retired_slugs": ["a"]}'}, (),
     "PT3: must be exactly"),
    ("pt3/other-key-fails", {"schema/record-policy.json": '{"retired_slugs": [], "x": 1}'},
     (), "PT3: must be exactly"),
    ("pt3/duplicate-key-fails", {"schema/record-policy.json":
     '{"retired_slugs": ["a"], "retired_slugs": []}'}, (), "PT3: cannot read: a key appears twice"),
    ("pt3/not-json-fails", {"schema/record-policy.json": '{"retired_slugs": []'}, (),
     "PT3: cannot read"),
    ("pt3/second-policy-fullwidth", {"data/record－policy.json": "{}"}, (),
     "PT3: a second file named"),
    # Exemptions are exact.
    ("exempt/tests-fixtures-passes", {"tests/fixtures/x/content/reports/r.md":
     "+++\n[params]\nname = \"x\"\n+++\n", "tests/fixtures/x/schema/record-policy.json":
     '{"retired_slugs": ["x"]}', "tests/fixtures/x/static/shot.png": b"\x89PNG\r\n\x1a\n",
     "tests/fixtures/guard/fail-x/saved.eml": "x"}, (), "PASS"),
    ("exempt/tests-fixtures-case-variant-fails", {"Tests/fixtures/x/saved.eml": "x"}, (),
     PT4_MAIL),
    ("pt4/not-mail-passes", {"docs/saved.txt": "x", "docs/saved.emlz": "x"}, (), "PASS"),
    ("pt4/mail-fullwidth-dot", {"docs/saved．eml": "x"}, (), PT4_MAIL),
    ("pt4/mail-zero-width", {"docs/saved.e​ml": "x"}, (), PT4_MAIL),
    ("pt4/mail-dotfile", {"docs/.eml": "x"}, (), PT4_MAIL),
    ("pt2a/front-matter-in-content-page-dir-skipped", {**SCHEMAS, "content/about.md":
     PAGE.format(extra="")}, (), "PASS"),
    ("pt2a/json-array-passes", {"data/x.json": '[{"a": 1}]\ntext\n'}, (), "PASS"),
    ("pt2a/template-passes", {"layouts/x.html": '{{ define "main" }}{\n'}, (), "PASS"),
    ("pt2a/not-utf8-json-passes", {"data/x.bin": b'{"a": "\xff"} more'}, (), "PASS"),
    ("pt2a/markdown-extension-in-content", {"content/x.markdown": "+++\n+++\n"}, (),
     "PT2a: a file in content/ that is not a static page"),
    ("pt2a/org-in-content", {"content/x.org": "#+title: Draft\n"}, (),
     "PT2a: a file in content/ that is not a static page"),
    ("pt2a/html-in-content", {"content/x.html": "<p>Draft</p>\n"}, (),
     "PT2a: a file in content/ that is not a static page"),
    ("pt2a/case-variant-md-in-content", {"content/x.MD": "Draft\n"}, (),
     "PT2a: a file in content/ that is not a static page"),
    ("pt2a/ignored-org-on-disk", {".gitignore": "/content/x.org\n", "content/x.org":
     "#+title: Draft\n"}, (), "PT2a: a file in content/ that is not a static page", True),
]
for suffix in MAIL_SUFFIXES:
    rows.append((f"mail-suffix/{suffix[1:]}/lower", {f"docs/saved{suffix}": "x"}, (), PT4_MAIL))
    rows.append((f"mail-suffix/{suffix[1:]}/upper", {f"docs/saved{suffix.upper()}": "x"}, (),
                 PT4_MAIL))
for kind, magic in IMAGES.items():
    data = magic + b"\x00" * 8 + b"padding"
    rows.append((f"image-magic/{kind}/outside", {"docs/evidence.dat": data}, (), PT4_IMAGE))
    rows.append((f"image-magic/{kind}/nested-assets", {"docs/assets/evidence.dat": data}, (),
                 PT4_IMAGE))
    rows.append((f"image-magic/{kind}/case-variant-assets", {"Assets/evidence.dat": data}, (),
                 PT4_IMAGE))
    rows.append((f"image-magic/{kind}/assets", {"assets/evidence.dat": data}, (), "PASS"))
    rows.append((f"image-magic/{kind}/static", {"static/evidence.dat": data}, (), "PASS"))
# STOP 2 of interviewscam-site#11 (Known limit 4): the other evidence types,
# written out as bytes, one row per member and placement.
EVIDENCE = {
    "pdf": b"%PDF-1.7\n",
    "zip-local-header": b"PK\x03\x04\x14\x00",
    "zip-empty-archive": b"PK\x05\x06\x00\x00",
    **{f"heif-{b}": b"\x00\x00\x00\x18ftyp" + b.encode() for b in
       ("heic", "heix", "heim", "heis", "hevc", "hevx", "mif1", "msf1")},
    **{f"avif-{b}": b"\x00\x00\x00\x1cftyp" + b.encode() for b in ("avif", "avis")},
}
PT4_EVIDENCE = "PT4: an evidence file"
for kind, magic in EVIDENCE.items():
    data = magic + b"\x00" * 8 + b"padding"
    rows.append((f"evidence-magic/{kind}/outside", {"docs/evidence.dat": data}, (), PT4_EVIDENCE))
    rows.append((f"evidence-magic/{kind}/assets", {"assets/evidence.dat": data}, (), "PASS"))
    rows.append((f"evidence-magic/{kind}/static", {"static/evidence.dat": data}, (), "PASS"))
    rows.append((f"evidence-magic/{kind}/fixture-elsewhere", {"tests/fixtures/x/e.dat": data}, (),
                 PT4_EVIDENCE))
    rows.append((f"evidence-magic/{kind}/fixture-static", {"tests/fixtures/x/static/e.dat": data},
                 (), "PASS"))
rows += [
    ("evidence-magic/ftyp-other-brand-passes", {"docs/e.dat": b"\x00\x00\x00\x18ftypisom" +
     b"\x00" * 8}, (), "PASS"),
    ("evidence-magic/heif-brand-without-ftyp-passes", {"docs/e.dat": b"\x00\x00\x00\x18abcdheic"
     + b"\x00" * 8}, (), "PASS"),
    ("evidence-magic/avif-brand-without-ftyp-passes", {"docs/e.dat": b"\x00\x00\x00\x1cabcdavif"
     + b"\x00" * 8}, (), "PASS"),
    ("evidence-magic/ftyp-at-offset-0-passes", {"docs/e.dat": b"ftypheic" + b"\x00" * 8}, (),
     "PASS"),
    ("evidence-magic/pdf-later-passes", {"docs/e.txt": b"See %PDF-1.7\n"}, (), "PASS"),
    ("evidence-magic/zip-spanned-marker-passes", {"docs/e.dat": b"PK\x07\x08\x00\x00"}, (),
     "PASS"),
    ("evidence-magic/pdf-staged-overwritten", {"docs/e.pdf": b"%PDF-1.7\n"}, (),
     "docs/e.pdf (staged): " + PT4_EVIDENCE, {"docs/e.pdf": "x"}),
]
rows.append(("image-magic/truncated-webp-passes", {"docs/evidence.dat": b"RIFF\x00\x00"}, (),
             "PASS"))

# Fix round 1 of interviewscam-site#11. R2: records as JSON or TOML anywhere,
# and record keys at any depth of a static page's front matter.
REPO_ROOT = schema_dir.parent
REC_TOML = ('[params]\nname = "Acme"\nname_type = "company"\nstate = "front"\n'
            'summary = "x"\nevidence = "y"\nfirst_seen = 2026-10-01\n'
            '[params.artifacts]\ndomains = ["acme[.]example"]\n')
REC_JSON = json.dumps({"params": {"name": "Acme", "state": "front", "summary": "x",
                                  "artifacts": {"domains": ["acme[.]example"]}}})
FLAT = ["name", "state", "summary", "evidence", "first_seen"]
PT2A_SHAPE = "PT2a: a record in JSON or TOML form"
schema_extra = json.loads(SCHEMAS["schema/report.schema.json"])
schema_extra["properties"]["params"]["required"].append("x_extra")
rows += [
    ("shape/json-record-in-docs", {"docs/acme.md": REC_JSON}, (), PT2A_SHAPE),
    ("shape/fenceless-toml-record", {"data/acme.toml": REC_TOML}, (), PT2A_SHAPE),
    ("shape/json-array-of-records", {"data/x.json": f"[{REC_JSON}]"}, (), PT2A_SHAPE),
    ("shape/params-nested-deeper", {"data/x.json": json.dumps({"a": {"params": {"summary": "x"}}})},
     (), PT2A_SHAPE),
    ("shape/params-uppercase-key", {"data/x.toml": '[PARAMS]\nsummary = "x"\n'}, (), PT2A_SHAPE),
    ("shape/params-array-of-tables", {"data/x.toml": '[[params]]\nsummary = "x"\n'}, (),
     PT2A_SHAPE),
    ("shape/unwrapped-5-keys", {"data/x.toml": "".join(f'{k} = "x"\n' for k in FLAT)}, (),
     PT2A_SHAPE),
    ("shape/unwrapped-4-keys-passes", {"data/x.toml": "".join(f'{k} = "x"\n' for k in FLAT[:4])},
     (), "PASS"),
    ("shape/unwrapped-4-keys-and-mapping-passes", {"data/x.toml": "".join(
     f'{k} = "x"\n' for k in FLAT[:4]) + '[artifacts]\ndomains = ["a[.]example"]\n'}, (), "PASS"),
    ("shape/unwrapped-5-keys-fullwidth", {"data/x.json": json.dumps(
     {"\uff4e\uff41\uff4d\uff45": "x", **{k: "x" for k in FLAT[1:]}})}, (), PT2A_SHAPE),
    ("shape/schemas-and-labels-pass", {"docs/report.json": SCHEMAS["schema/report.schema.json"],
     "docs/campaign.json": SCHEMAS["schema/campaign.schema.json"],
     "docs/feed.json": (schema_dir / "feed.schema.json").read_bytes(),
     "docs/labels.toml": (REPO_ROOT / "data" / "labels.toml").read_bytes()}, (), "PASS"),
    ("record-keys/cascade-params", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[cascade.params]\nname = "x"\n')}, (), PT2B),
    ("record-keys/params-nested-table", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[params.report]\nsummary = "x"\n')}, (), PT2B),
    ("record-keys/menu-name", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[menu.main]\nname = "About"\n')}, (), PT2B),
    ("record-keys/key-in-array-of-tables", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='[[x]]\nstate = "front"\n')}, (), PT2B),
    ("pt2b/toml-error-page-with-schema", {**SCHEMAS, "content/about.md":
     "+++\ntitle = \n+++\nAbout.\n"}, (), "PT2b: the front matter is not valid TOML"),
    ("pt2b/bom-page-passes", {**SCHEMAS, "content/about.md": "\ufeff" + PAGE.format(extra="")},
     (), "PASS"),
    ("pt2b/schema-differs-from-pin", {"schema/report.schema.json": json.dumps(schema_extra),
     "schema/campaign.schema.json": SCHEMAS["schema/campaign.schema.json"],
     "content/about.md": PAGE.format(extra="")}, (), "differs from RECORD_KEYS"),
    # R3: the staged blob counts where the working tree differs.
    ("staged/fence-record-overwritten", {"docs/acme.md": "+++\n" + REC_TOML + "+++\n"}, (),
     "docs/acme.md (staged): PT2a: a front-matter document", {"docs/acme.md": "hello\n"}),
    ("staged/json-record-overwritten", {"docs/acme.json": REC_JSON}, (),
     "docs/acme.json (staged): " + PT2A_SHAPE, {"docs/acme.json": "{}"}),
    ("staged/image-overwritten", {"docs/e.dat": IMAGES["png"] + b"0000"}, (),
     "docs/e.dat (staged): PT4: a raster image", {"docs/e.dat": "x"}),
    ("staged/policy-slug-overwritten", {"schema/record-policy.json": '{"retired_slugs": ["a"]}'},
     (), "schema/record-policy.json (staged): PT3: must be exactly",
     {"schema/record-policy.json": '{"retired_slugs": []}'}),
    ("staged/page-key-overwritten", {**SCHEMAS, "content/about.md":
     PAGE.format(extra='summary = "x"\n')}, (), 'content/about.md (staged): "summary": PT2b',
     {"content/about.md": PAGE.format(extra="")}),
    ("staged/assume-unchanged-record", {"docs/acme.md": "+++\n" + REC_TOML + "+++\n"}, (),
     "docs/acme.md (staged): PT2a: a front-matter document",
     ("--assume-unchanged", {"docs/acme.md": "hello\n"})),
    ("staged/skip-worktree-record", {"docs/acme.json": REC_JSON}, (),
     "docs/acme.json (staged): " + PT2A_SHAPE, ("--skip-worktree", {"docs/acme.json": "{}"})),
    ("staged/symlink-fails", {"docs/target.txt": "x"}, (), "PT1: a symlink in the tree", "symlink"),
    ("staged/disk-record-over-clean-blob", {"docs/acme.md": "hello\n"}, (),
     "docs/acme.md: PT2a: a front-matter document",
     {"docs/acme.md": "+++\n" + REC_TOML + "+++\n"}),
    # R4: no false positive on a YAML document marker or editor files.
    ("pt2a/workflow-document-marker-passes", {".github/workflows/x.yml":
     "---\nname: x\non: push\n"}, (), "PASS"),
    ("pt2a/yaml-fence-unclosed-passes", {"docs/x.yml": "---\ntitle: x\n"}, (), "PASS"),
    # Fix round 2 (delta review finding 1): a first-line +++ counts on its
    # own, so a record whose closing fence was lost still fails.
    ("pt2a/toml-fence-unclosed-fails", {"docs/x.md": "+++\ntitle\n"}, (),
     "PT2a: a front-matter document"),
    ("pt2a/unclosed-toml-record-fails", {"docs/acme.md": "+++\n" + REC_TOML + "\nA draft.\n"},
     (), "PT2a: a front-matter document"),
    ("pt2a/plus-fence-later-line-passes", {"docs/x.md": "Intro\n+++\n"}, (), "PASS"),
    ("content/editor-files-ignored-pass", {".gitignore": (REPO_ROOT / ".gitignore").read_bytes(),
     **SCHEMAS, "content/about.md": PAGE.format(extra=""), "content/.about.md.swp": b"b0VIM",
     "content/about.md~": "x", "content/#about.md#": "x"}, (), "PASS", True),
    ("content/editor-file-not-ignored-fails", {**SCHEMAS, "content/about.md":
     PAGE.format(extra=""), "content/.about.md.swp": b"b0VIM"}, (),
     "PT2a: a file in content/ that is not a static page", "listed"),
    ("content/hugo-ignored-disk-only-dir-passes", {".gitignore": "/content/.*\n",
     "content/.drafts/x.md": "+++\n" + REC_TOML + "+++\n"}, (), "PASS", True),
    # R6: under tests/fixtures/, media only in the guard's fixtures and a
    # fixture tree's static/, assets/ or public/.
    ("fixtures-media/mail-elsewhere-fails", {"tests/fixtures/scratch/report.eml": "x"}, (),
     PT4_MAIL),
    ("fixtures-media/image-elsewhere-fails", {"tests/fixtures/scratch/shot.dat":
     IMAGES["png"] + b"0000"}, (), PT4_IMAGE),
    ("fixtures-media/static-passes", {"tests/fixtures/x/static/a.dat": IMAGES["png"]}, (), "PASS"),
    ("fixtures-media/assets-passes", {"tests/fixtures/x/assets/a.dat": IMAGES["png"]}, (), "PASS"),
    ("fixtures-media/public-passes", {"tests/fixtures/x/public/a.dat": IMAGES["png"]}, (), "PASS"),
    ("fixtures-media/guard-passes", {"tests/fixtures/guard/fail-x/a.eml": "x"}, (), "PASS"),
    ("fixtures-media/guard-image-passes", {"tests/fixtures/guard/fail-x/a.dat": IMAGES["png"]},
     (), "PASS"),
    ("fixtures-media/static-as-name-fails", {"tests/fixtures/x/static.eml": "x"}, (), PT4_MAIL),
    # R8: QA's rows.
    ("mail-suffix/two-dots", {"docs/saved.2024.eml": "x"}, (), PT4_MAIL),
    ("mail-suffix/three-dots-mbox", {"docs/a.b.c.mbox": "x"}, (), PT4_MAIL),
    # Fix round 2 (delta review): YAML records by line keys, and mail under a
    # fixture tree's static/, assets/ or public/.
    ("yaml/record-5-keys", {"data/acme.yml": "".join(f"{k}: x\n" for k in FLAT)}, (),
     "PT2a: a record in YAML form"),
    ("yaml/record-nested-under-params", {"docs/acme.yaml": "params:\n" + "".join(
     f"  {k}: x\n" for k in FLAT)}, (), "PT2a: a record in YAML form"),
    ("yaml/record-quoted-and-listed", {"docs/acme.yml": "- 'name': x\n" + "".join(
     f'  "{k}": x\n' for k in FLAT[1:])}, (), "PT2a: a record in YAML form"),
    ("yaml/record-upper-suffix", {"docs/acme.YML": "".join(f"{k}: x\n" for k in FLAT)}, (),
     "PT2a: a record in YAML form"),
    ("yaml/record-fullwidth-key", {"docs/acme.yml": "\uff4e\uff41\uff4d\uff45: x\n" + "".join(
     f"{k}: x\n" for k in FLAT[1:])}, (), "PT2a: a record in YAML form"),
    ("yaml/4-keys-passes", {"data/acme.yml": "".join(f"{k}: x\n" for k in FLAT[:4])}, (),
     "PASS"),
    ("yaml/keys-in-values-pass", {"data/acme.yml": "".join(f"x{i}: {k}: y\n" for i, k in
     enumerate(FLAT))}, (), "PASS"),
    ("yaml/workflow-dir-passes", {".github/workflows/x.yml": "".join(f"{k}: x\n" for k in FLAT)},
     (), "PASS"),
    ("yaml/other-suffix-passes", {"docs/acme.txt": "".join(f"{k}: x\n" for k in FLAT)}, (),
     "PASS"),
    ("fixtures-media/mail-in-static-fails", {"tests/fixtures/x/static/a.eml": "x"}, (), PT4_MAIL),
    ("fixtures-media/mail-in-public-fails", {"tests/fixtures/x/public/a.msg": "x"}, (), PT4_MAIL),
    ("fixtures-media/mail-in-assets-fails", {"tests/fixtures/x/assets/a.mbox": "x"}, (), PT4_MAIL),
    # Rows from the fix round 1 mutation sweep (each killed a surviving mutant).
    ("shape/json-record-with-bom", {"docs/acme.json": b"\xef\xbb\xbf" + REC_JSON.encode()},
     (), PT2A_SHAPE),
    ("staged/policy-staged-deleted", {"schema/record-policy.json": '{"retired_slugs": ["a"]}'},
     (), ["schema/record-policy.json (staged): PT3: must be exactly"], "index-only"),
    ("fixtures-media/file-named-static-fails", {"tests/fixtures/x/static":
     IMAGES["png"] + b"0000"}, (), PT4_IMAGE),
    ("exempt/tests-fixtures-case-variant-record-fails", {"Tests/fixtures/x/notes.md":
     "+++\n" + REC_TOML + "+++\n"}, (), "PT2a: a front-matter document"),
]

# Fix round 3 (delta review 2, QA): symlinks, the YAML BOM, YAML forms and
# git index states.
PT1_LINK = "PT1: a symlink in the tree"
PT6_NAME = ('{"params":{"name":"Acme Hiring Ltd","name_type":"company","state":"front",'
            '"summary":"x","evidence":"y"}}')
rows += [
    ("symlink/review-pt6-file-name-record", {f"docs/{PT6_NAME}": "hello\n"}, (), PT1_LINK,
     [("staged", "docs/linkrec", PT6_NAME)]),
    ("symlink/untracked", {"docs/target.txt": "x"}, (), PT1_LINK,
     [("untracked", "docs/link", "target.txt")]),
    ("symlink/staged-deleted-on-disk", {"docs/target.txt": "x"}, (),
     [PT1_LINK, "PT2a: cannot read: missing"],
     [("index-only", "docs/link", "target.txt")]),
    ("symlink/to-directory", {"docs/sub/x.txt": "x"}, (), PT1_LINK,
     [("untracked", "docs/link", "sub")]),
    ("symlink/dangling", {"docs/x.txt": "x"}, (), [PT1_LINK, "PT2a: cannot read: missing"],
     [("untracked", "docs/link", "nowhere")]),
    ("symlink/guard-fixture-passes", {"tests/fixtures/guard/fail-x/target.txt": "x"}, (), "PASS",
     [("staged", "tests/fixtures/guard/fail-x/link", "target.txt")]),
    ("symlink/other-fixture-fails", {"tests/fixtures/x/target.txt": "x"}, (), PT1_LINK,
     [("staged", "tests/fixtures/x/link", "target.txt")]),
    ("yaml/bom-then-quoted-key", {"data/acme.yml": "﻿\"name\": Acme\n" + "".join(
     f"{k}: x\n" for k in FLAT[1:])}, (), "PT2a: a record in YAML form"),
    ("yaml/block-valued-keys", {"data/acme.yml": "sources:\n  - a\n  - b\nname: x\n"
     "state: front\nsummary: x\nevidence:\n  y\n"}, (), "PT2a: a record in YAML form"),
    ("yaml/space-before-colon", {"data/acme.yml": "".join(f"{k} : x\n" for k in FLAT)}, (),
     "PT2a: a record in YAML form"),
    ("yaml/not-utf8-fails-closed", {"data/acme.yml": b"name: \xff\n"}, (),
     "PT2a: a YAML file that is not UTF-8"),
    ("git/committed-record-one-finding", {"docs/acme.md": "+++\n" + REC_TOML + "+++\n"}, (),
     ["docs/acme.md: PT2a: a front-matter document"], "committed"),
    ("git/conflicted-index-entry-passes", {"docs/acme.md": "hello\n"}, (), "PASS", "conflict"),
    ("git/submodule-entry-fails-closed", {"docs/x.txt": "x"}, (), "sub: PT2a: cannot read: missing",
     "submodule"),
]

for row in rows:
    name, files, dirs, expect = row[:4]
    use_git = len(row) > 4 and row[4]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, data in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        for rel in dirs:
            (root / rel).mkdir(parents=True, exist_ok=True)
        # The guard reads git (git's listing, the staged blobs), as in production.
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        if isinstance(use_git, list):
            # Symlinks (fix round 3): [(how, link, target)], how one of
            # untracked, staged or index-only (staged, then deleted on disk).
            for how, link, target in use_git:
                (root / link).parent.mkdir(parents=True, exist_ok=True)
                (root / link).symlink_to(target)
                if how != "untracked":
                    subprocess.run(["git", "-C", str(root), "add", link], check=True)
                if how == "index-only":
                    (root / link).unlink()
            listed = sitecheck.git_files(root)
        elif use_git in ("committed", "conflict", "submodule"):
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            git_id = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            if use_git == "committed":
                subprocess.run(["git", "-C", str(root), *git_id, "commit", "-q", "-m", "x"],
                               check=True)
            elif use_git == "conflict":
                # The record only in the unmerged stages 1 to 3; git refuses a
                # commit while they exist, so nothing can carry it.
                sha = subprocess.run(["git", "-C", str(root), "hash-object", "-w", "--stdin"],
                                     input=("+++\n" + REC_TOML + "+++\n").encode(),
                                     capture_output=True, check=True).stdout.decode().strip()
                info = "".join(f"100644 {sha} {n}\tdocs/acme.md\n" for n in (1, 2, 3))
                subprocess.run(["git", "-C", str(root), "update-index", "--index-info"],
                               input=info.encode(), check=True)
            else:
                subprocess.run(["git", "-C", str(root), "update-index", "--add", "--cacheinfo",
                                "160000," + "1" * 40 + ",sub"], check=True)
            listed = sitecheck.git_files(root)
        elif isinstance(use_git, tuple):
            # Staged, marked with a git index flag that hides the path from
            # git diff (--assume-unchanged, --skip-worktree), then overwritten
            # on disk (fix round 2, delta review).
            flag, overwrite = use_git
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            for rel, data in overwrite.items():
                subprocess.run(["git", "-C", str(root), "update-index", flag, rel], check=True)
                (root / rel).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
            hidden = subprocess.run(["git", "-C", str(root), "diff", "--name-only"],
                                    capture_output=True, text=True).stdout
            if hidden.strip():
                report("guard-public", name, False, f"git diff still shows {hidden!r}, so the "
                       "row does not prove the hash comparison")
                continue
            listed = sitecheck.git_files(root)
        elif isinstance(use_git, dict):
            # Staged, then the working-tree copy overwritten: the next commit
            # carries the staged blob, which the rules must read.
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            for rel, data in use_git.items():
                (root / rel).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
            listed = sitecheck.git_files(root)
        elif use_git == "symlink":
            # A staged symlink is read through its target, never as a blob.
            (root / "docs" / "link").symlink_to("target.txt")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            listed = sitecheck.git_files(root)
        elif use_git == "listed":
            listed = sitecheck.git_files(root)  # the swap file is untracked, not ignored
        elif use_git == "index-only":
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            for rel in files:
                (root / rel).unlink()
                parent = (root / rel).parent
                while parent != root and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
            listed = sitecheck.git_files(root)
            if sorted(files) != [rel for rel in listed if rel in files]:
                report("guard-public", name, False, f"git does not list the staged files: {listed}")
                continue
        elif use_git:
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            listed = sitecheck.git_files(root)
            hidden = [rel for rel in files if rel.startswith("content/") and rel not in listed]
            if not hidden:
                report("guard-public", name, False, "the row's content/ file is not ignored, "
                       f"so it does not prove the disk read; git lists {listed}")
                continue
        else:
            listed = sorted(rel for rel in files)
        findings = sitecheck.Findings()
        sitecheck.guard_public_tree(root, listed, findings)
        items = findings.items
        if expect == "PASS":
            report("guard-public", name, not items,
                   "passed as expected" if not items else f"expected no finding; got {items}")
        else:
            want = expect if isinstance(expect, list) else [expect]
            ok = len(items) == len(want) and all(
                sum(text in item for item in items) == 1 for text in want)
            report("guard-public", name, ok, f"failed as expected: {'; '.join(want)}" if ok
                   else f"expected exactly the findings {want!r}; got {items}")
schema_keys = set()
for path in SCHEMAS:
    schema_keys |= set(json.loads(SCHEMAS[path])["properties"]["params"]["required"])
report("guard-public", "record-keys/schema-union", schema_keys == set(RECORD_KEYS),
       f"the {len(RECORD_KEYS)} keys equal params.required of the schemas"
       if schema_keys == set(RECORD_KEYS) else
       f"the schemas require {sorted(schema_keys)}, the rows {sorted(RECORD_KEYS)}")

# ---- WH rows: (name, [(find, replace)], count, expect) on BASE ----
BASE = f"""name: ci

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{sha} # v7.0.1
        with:
          persist-credentials: false
      - name: bash tools/check.sh
        shell: bash
        run: bash tools/check.sh
"""
ON = "on:\n  pull_request:\n  push:\n    branches: [main]\n"
WITH = "        with:\n          persist-credentials: false\n"
STEP = f"      - uses: actions/checkout@{sha} # v7.0.1\n{WITH}"
WH1, WH1_READ = "WH1: trigger", "WH1: cannot read the triggers"
WH2, WH2_READ = "WH2: actions/checkout needs exactly one", "WH2:"
WH3, WH4 = "WH3: a credential input", "WH4: a secrets reference"
ALLOWED = ("pull_request", "push", "schedule", "workflow_dispatch")
DENIED = ("pull_request_target", "issue_comment", "pull_request_review",
          "pull_request_review_comment", "discussion_comment", "workflow_call",
          "repository_dispatch", "workflow_run", "Push", "рush", "pu​sh",
          "Pull_request", "SCHEDULE", "Workflow_Dispatch", "push ")
wh = [("base", [], 0, ""),
      ("allowed-equal-the-code", None, 0, "")]
for trigger in ALLOWED:
    wh += [(f"trigger-allowed/{trigger}/mapping", [(ON, f"on:\n  {trigger}:\n")], 0, ""),
           (f"trigger-allowed/{trigger}/scalar", [(ON, f"on: {trigger}\n")], 0, ""),
           (f"trigger-allowed/{trigger}/flow-list", [(ON, f"on: [{trigger}]\n")], 0, ""),
           (f"trigger-allowed/{trigger}/block-list", [(ON, f"on:\n  - {trigger}\n")], 0, "")]
for trigger in DENIED:
    wh += [(f"trigger-denied/{json.dumps(trigger)[1:-1]}/mapping",
            [(ON, ON + f'  "{trigger}":\n')], 1, f"{WH1} {json.dumps(trigger)}"),
           (f"trigger-denied/{json.dumps(trigger)[1:-1]}/flow-list",
            [(ON, f'on: [push, "{trigger}"]\n')], 1, f"{WH1} {json.dumps(trigger)}"),
           (f"trigger-denied/{json.dumps(trigger)[1:-1]}/block-list",
            [(ON, f"on:\n  - push\n  - '{trigger}'\n")], 1, f"{WH1} {json.dumps(trigger)}"),
           (f"trigger-denied/{json.dumps(trigger)[1:-1]}/scalar",
            [(ON, f'on: "{trigger}"\n')], 1, f"{WH1} {json.dumps(trigger)}")]
wh += [
    ("trigger-forms/quoted-on-key", [(ON, '"on":\n  push:\n')], 0, ""),
    ("trigger-forms/single-quoted-on-key", [(ON, "'on': [push]\n")], 0, ""),
    ("trigger-forms/comment-after-scalar", [(ON, "on: push # weekly\n")], 0, ""),
    ("trigger-forms/trailing-comma", [(ON, "on: [push, ]\n")], 0, ""),
    ("trigger-forms/settings-nested", [(ON, ON + '  schedule:\n    - cron: "17 6 * * 1"\n')],
     0, ""),
    ("trigger-forms/alias", [(ON, "on: *triggers\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/anchor", [(ON, "on: &triggers\n  push:\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/tag", [(ON, "on: !!map\n  push:\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/flow-mapping", [(ON, "on: {push: {}}\n")], 2, (WH1_READ, "WH reader")),
    ("trigger-forms/block-scalar", [(ON, "on: |\n  push\n")], 1, WH1_READ),
    ("trigger-forms/multi-line-flow-list", [(ON, "on: [push,\n  pull_request_target]\n")], 3,
     (WH1_READ, "WH reader")),
    ("trigger-forms/missing", [(ON, "")], 1, WH1_READ),
    ("trigger-forms/twice", [(ON, ON + "on: [push]\n")], 2, (WH1_READ, "WH reader")),
    ("trigger-forms/top-level-merge-key", [(ON, ON + "<<: *defaults\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/complex-key", [(ON, "? on\n: push\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/top-level-flow-mapping", [(ON, "{on: push}\n")], 2, (WH1_READ, "WH reader")),
    ("trigger-forms/complex-key-beside-on", [(ON, ON + "? on\n: issue_comment\n")], 3,
     (WH1_READ, "WH reader")),
    ("trigger-forms/flow-list-alias-item", [(ON, "on: [push, *more]\n")], 2, (WH1_READ, "WH reader")),
    ("trigger-forms/flow-list-empty-item", [(ON, 'on: [push, ""]\n')], 1, WH1_READ),
    ("trigger-forms/list-item-key-empty", [(ON, "on:\n  - push:\n")], 1, WH1_READ),
    ("trigger-forms/tab-indent", [(ON, "on:\n\tpush:\n")], 3, (WH1_READ, "WH reader")),
    ("trigger-forms/mixed-list-and-mapping", [(ON, "on:\n  - push\n  schedule:\n")], 1,
     WH1_READ),
    ("trigger-forms/empty", [(ON, "on:\n")], 1, WH1_READ),
    ("trigger-forms/compact-list-at-top", [(ON, "on:\n- push\n")], 1, WH1_READ),
    ("trigger-forms/list-item-mapping", [(ON, "on:\n  - push: {}\n")], 1, WH1_READ),
    ("trigger-forms/flow-list-nested", [(ON, "on: [push, [x]]\n")], 2, (WH1_READ, "WH reader")),
    ("persist/missing-with", [(WITH, "")], 1, WH2),
    ("persist/missing-key", [("          persist-credentials: false\n",
                              "          fetch-depth: 1\n")], 1, WH2),
    ("persist/true", [("persist-credentials: false", "persist-credentials: true")], 1, WH2),
    ("persist/double-quoted", [("persist-credentials: false",
                                'persist-credentials: "false"')], 1, WH2),
    ("persist/single-quoted", [("persist-credentials: false",
                                "persist-credentials: 'false'")], 1, WH2),
    ("persist/expression", [("persist-credentials: false",
                             "persist-credentials: ${{ false }}")], 1, WH2),
    ("persist/capitalised", [("persist-credentials: false", "persist-credentials: False")],
     1, WH2),
    ("persist/yaml-1.1-no", [("persist-credentials: false", "persist-credentials: no")], 1,
     WH2),
    ("persist/key-case-variant", [("persist-credentials: false",
                                   "Persist-Credentials: false")], 1, WH2),
    ("persist/twice", [("          persist-credentials: false\n",
                        "          persist-credentials: false\n"
                        "          Persist-Credentials: true\n")], 1, WH2),
    ("persist/alias", [("persist-credentials: false", "persist-credentials: *off")], 3, (WH2, "WH reader")),
    ("persist/comment-passes", [("persist-credentials: false",
                                 "persist-credentials: false # no token in .git/config")],
     0, ""),
    ("persist/with-flow-mapping", [(WITH, "        with: {persist-credentials: false}\n")], 2,
     WH2_READ),
    ("persist/with-alias", [(WITH, "        with: *checkout\n")], 4, (WH2_READ, "WH reader")),
    ("persist/step-merge-key", [(WITH, "        <<: *defaults\n" + WITH)], 3,
     ("WH2: the key \"<<\" twice or as a merge key", "WH reader")),
    ("persist/step-key-twice", [(WITH, WITH + "        name: a\n        name: b\n")], 1,
     "WH2: the key \"name\" twice"),
    ("persist/with-merge-key", [(WITH, "        with:\n          <<: *checkout\n")], 4,
     (WH2_READ, "WH reader")),
    ("persist/name-first-passes", [(STEP, "      - name: checkout\n        uses: actions/"
                                    f"checkout@{sha}\n{WITH}")], 0, ""),
    ("persist/name-first-missing", [(STEP, "      - name: checkout\n        uses: actions/"
                                     f"checkout@{sha}\n")], 1, WH2),
    ("persist/with-before-uses-passes", [(STEP, "      - with:\n          persist-credentials:"
                                          f" false\n        uses: actions/checkout@{sha}\n")],
     0, ""),
    ("persist/quoted-uses-missing", [(STEP, f'      - uses: "actions/checkout@{sha}"\n')], 1,
     WH2),
    ("persist/case-variant-action-missing", [(STEP, f"      - uses: Actions/Checkout@{sha}\n")],
     1, WH2),
    ("persist/flow-step", [(STEP, f"      - {{uses: actions/checkout@{sha}}}\n")], 1,
     "WH2: actions/checkout in a form the guard cannot read"),
    ("persist/second-step-missing", [(STEP, STEP + f"      - uses: actions/checkout@{sha}\n")],
     1, WH2),
    ("persist/commented-checkout-ignored", [(STEP, STEP + f"      # - uses: actions/checkout@"
                                             f"{sha}\n")], 0, ""),
    ("credential/token", [(WITH, WITH + "          token: x\n")], 1, WH3),
    ("credential/ssh-key", [(WITH, WITH + "          ssh-key: x\n")], 1, WH3),
    ("credential/token-case-variant", [(WITH, WITH + "          Token: x\n")], 1, WH3),
    ("credential/ssh-key-quoted", [(WITH, WITH + '          "ssh-key": x\n')], 1, WH3),
    ("credential/token-expression", [(WITH, WITH + "          token: ${{ github.token }}\n")],
     1, WH3),
    ("credential/token-other-step-passes", [("        shell: bash\n",
                                             "        shell: bash\n        with:\n"
                                             "          token: x\n")], 0, ""),
    ("secrets/with-value", [(WITH, WITH + "          path: ${{ secrets.X }}\n")], 1, WH4),
    ("secrets/comment", [("permissions:", "# secrets\npermissions:")], 1, WH4),
    ("secrets/uppercase", [("permissions:", "# SECRETS\npermissions:")], 1, WH4),
    ("secrets/bracket", [(WITH, WITH + "          path: ${{ secrets['X'] }}\n")], 1, WH4),
    ("secrets/inherit", [("    runs-on: ubuntu-24.04\n",
                          "    runs-on: ubuntu-24.04\n    secrets: inherit\n")], 1, WH4),
    ("secrets/word-part-passes", [("permissions:", "# nosecretsx\npermissions:")], 0, ""),
]

# Fix round 1 of interviewscam-site#11. R1: the reader fails closed on every
# form a YAML parser could read differently; R5: the function is safe alone.
RD = "WH reader"
REVIEW_TAIL = BASE[BASE.index("permissions:"):]
for label, ch in (("U+2028", "\u2028"), ("U+2029", "\u2029"), ("U+0085", "\u0085"),
                  ("U+FEFF", "\ufeff"), ("U+000B", "\x0b"), ("U+000C", "\x0c"),
                  ("U+0000", "\x00"), ("U+001F", "\x1f"), ("U+007F", "\x7f"),
                  ("U+009F", "\x9f")):
    wh.append((f"reader/char-{label}", [("name: ci", f'name: "c{ch}i"')], 1, RD))
wh += [
    ("reader/bom-at-start", [("name: ci", "\ufeffname: ci")], 1, RD),
    ("reader/lone-cr", [("name: ci", "name: ci\ron: [pull_request_target]")], 1, RD),
    ("reader/crlf-passes", [(BASE, BASE.replace("\n", "\r\n"))], 0, ""),
    ("reader/tab-before-colon", [(ON, "on\t: [pull_request_target]\n")], 2, (RD, WH1_READ)),
    ("reader/trailing-tab-passes", [("runs-on: ubuntu-24.04", "runs-on: ubuntu-24.04\t")], 0, ""),
    ("reader/tab-in-value", [("runs-on: ubuntu-24.04", "runs-on: ubuntu\t-24.04")], 1, RD),
    ("reader/document-start-passes", [("name: ci", "---\nname: ci")], 0, ""),
    ("reader/second-document", [("permissions:", "---\npermissions:")], 1, RD),
    ("reader/document-end", [("permissions:", "...\npermissions:")], 1, RD),
    ("reader/directive", [("name: ci", "%YAML 1.2\nname: ci")], 1, RD),
    ("reader/anchor-top-level-key", [(ON, ON + "&a on: [pull_request_target]\n")], 1, RD),
    ("reader/top-level-key-twice", [("permissions:", "name: x\npermissions:")], 1, RD),
    ("reader/multi-line-double-quoted", [("name: ci", 'name: "ci\nx: y"')], 1, RD),
    ("reader/multi-line-single-quoted", [("name: ci", "name: 'ci\nx: y'")], 1, RD),
    ("reader/plain-continuation", [("runs-on: ubuntu-24.04", "runs-on: ubuntu-24.04\n      x")],
     1, RD),
    ("reader/flow-mapping-value-passes", [("permissions:\n  contents: read",
                                           "permissions: {}")], 0, ""),
    ("reader/alias-after-block-scalar", [(WITH, WITH + "          path: |\n            a\n"
                                          "          ref: *x\n")], 2, RD),
    ("reader/uses-flow-list", [(STEP, f"      - uses: [actions/checkout@{sha}]\n")], 1,
     "WH reader: uses: without a scalar value"),
    # Fix round 2 (delta review finding 2): &, * and ! are anchor, alias or
    # tag only where a YAML value starts.
    ("reader/not-equal-in-if-passes", [("        shell: bash\n",
     "        shell: bash\n        if: github.event_name != 'schedule'\n")], 0, ""),
    ("reader/and-in-if-passes", [("        shell: bash\n",
     "        shell: bash\n        if: a == 'x' && b == 'y'\n")], 0, ""),
    ("reader/not-call-in-if-passes", [("        shell: bash\n",
     "        shell: bash\n        if: success() || !cancelled()\n")], 0, ""),
    ("reader/star-in-name-passes", [("name: ci", "name: CI *main*")], 0, ""),
    ("reader/bang-in-name-passes", [("name: ci", "name: Build !fast")], 0, ""),
    ("reader/tag-at-value-start", [("name: ci", "name: !fast build")], 2, RD),
    ("reader/alias-list-item", [(STEP, STEP + "      - *other\n")], 2, RD),
    ("reader/alias-after-dash-in-value", [("runs-on: ubuntu-24.04", "runs-on: - *x")], 1, RD),
    ("reader/tab-in-comment-passes", [("permissions:", "# a\tcomment\npermissions:")], 0, ""),
    ("reader/tab-in-quoted-passes", [("name: ci", 'name: "c\ti"')], 0, ""),
    ("reader/flow-mapping-with-expression-passes", [("permissions:", "concurrency: {group: "
     '"${{ github.workflow }}", cancel-in-progress: true}\npermissions:')], 0, ""),
    ("reader/flow-mapping-nested-fails", [("permissions:", "concurrency: {group: {a: b}}\n"
     "permissions:")], 1, RD),
    # QA residual (fix round 2): a form problem on the line right after a
    # block scalar, at the key's column, ends the block and is read.
    ("reader/form-problem-after-block-scalar", [(WITH, WITH + "          path: |\n            a\n"
     "          &x ref: y\n")], 2, (RD, "WH2: a with: line of actions/checkout")),
    # Fix round 3 (delta review 2 finding 1): what the form check misses
    # today, and that the WH readers still fail closed on the same tricks.
    ("reader/known-limit-apostrophe-masks-flow", [("permissions:", "concurrency: {group: it's, "
     "x: {y: z}, c: b'}\npermissions:")], 0, ""),
    ("reader/known-limit-apostrophe-masks-anchor", [("permissions:", "concurrency: {group: "
     "it's, x: &g y, z: b'}\npermissions:")], 0, ""),
    ("reader/known-limit-adjacent-anchor", [("permissions:", 'concurrency: {"group":&g ci, '
     'cancel-in-progress: true}\npermissions:')], 0, ""),
    ("trigger-forms/apostrophe-masked-alias", [(ON, "on: [push, it's, *t, b']\n")], 1, WH1_READ),
    ("trigger-forms/adjacent-alias", [(ON, 'on: ["push",*t]\n')], 2, (RD, WH1_READ)),
    ("persist/apostrophe-masked-flow-step", [(STEP, "      - {name: it's, uses: actions/"
     f"checkout@{sha}, x: b'}}\n")], 1, "WH2: actions/checkout in a form the guard cannot read"),
    ("reader/block-scalar-passes", [(WITH, WITH + "          path: |\n            a: b\n")],
     0, ""),
    ("reader/review-bom-and-line-separator", [(BASE, '\ufeffon: [pull_request_target]\nname: '
     '"ci\u2028on: push\u2028x: y"\n' + REVIEW_TAIL)], 3, (RD, WH1_READ)),
    ("reader/review-bom-and-newlines", [(BASE, '\ufeffon: [pull_request_target]\nname: '
     '"ci\non: push\nx: y"\n' + REVIEW_TAIL)], 2, RD),
    ("reader/review-tab-and-line-separator", [(BASE, 'name: "ci\u2028on: push\u2028x: y"\n'
     'on\t: [pull_request_target]\n' + REVIEW_TAIL)], 3, (RD, WH1_READ)),
    ("reader/review-with-line-separator", [("          persist-credentials: false\n",
     '          path: "src\u2028          persist-credentials: false\u2028          clean: '
     'true"\n')], 2, (RD, WH2)),
    ("reader/review-with-newlines", [("          persist-credentials: false\n",
     '          path: "src\n          persist-credentials: false\n          clean: true"\n')],
     1, RD),
    ("reader/alias-uses", [(STEP, f"      - name: &co actions/checkout@{sha}\n"
     "        run: bash tools/check.sh\n      - uses: *co\n")], 4, RD),
    ("reader/escaped-uses", [(STEP, '      - uses: "actions/c\\x68eckout@' + sha + '"\n')], 2, RD),
    ("reader/block-scalar-uses", [(STEP, f"      - uses: >-\n          actions/checkout@{sha}\n")],
     1, "WH reader: uses: as a block scalar"),
    ("reader/escaped-secrets", [("        shell: bash\n",
     '        shell: bash\n        name: "${{ s\\x65crets.X }}"\n')], 2, RD),
    # R8: QA's rows.
    ("persist/with-nested-decoy", [(WITH, "        with:\n          x:\n"
                                    "            persist-credentials: false\n")], 1, WH2),
    ("persist/with-block-scalar-decoy", [(WITH, "        with:\n          ref: |\n"
                                          "            persist-credentials: false\n")], 1, WH2),
    ("persist/one-line-step-above-hardened", [(STEP, f"      - uses: actions/checkout@{sha}\n"
                                               f"      - name: x\n{WITH}")], 1, WH2),
    ("persist/siblings-before-uses-below-hardened", [(STEP, STEP + "      - name: n\n"
     f"        id: i\n        uses: actions/checkout@{sha}\n")], 1, WH2),
    ("trigger-forms/unterminated-double", [(ON, 'on: "push\n')], 2, (RD, WH1_READ)),
    ("trigger-forms/unterminated-single", [(ON, "on: 'push\n")], 2, (RD, WH1_READ)),
    ("credential/comment-mention-passes", [(WITH, WITH + "          # token: x\n")], 0, ""),
]
for name, edits, count, expect in wh:
    if edits is None:
        ok = tuple(sitecheck.WORKFLOW_TRIGGERS_ALLOWED) == ALLOWED
        report("guard-wf", name, ok, "WORKFLOW_TRIGGERS_ALLOWED equals the four rows" if ok
               else f"WORKFLOW_TRIGGERS_ALLOWED is {sitecheck.WORKFLOW_TRIGGERS_ALLOWED}")
        continue
    text = BASE
    for find, replace in edits:
        if text.count(find) != 1:
            report("guard-wf", name, False, f"the find string occurs {text.count(find)} times")
            break
        text = text.replace(find, replace)
    else:
        findings = sitecheck.Findings()
        sitecheck.guard_workflow_hardening(".github/workflows/w.yml", text, findings)
        items = findings.items
        if isinstance(expect, tuple):
            ok = len(items) == count and all(any(e in item for item in items) for e in expect)
        else:
            ok = len(items) == count and all(expect in item for item in items)
        report("guard-wf", name, ok,
               ("passed as expected" if not count else
                f"failed as expected: {count} x {expect}") if ok else
               f"expected {count} finding(s) with {expect!r}; got {items}")
for family in counts:
    if bad[family]:
        print(f"FAIL {family}/table: {counts[family]} rows, {bad[family]} failed")
    else:
        print(f"ok   {family}/table ({counts[family]} rows)")
PY
}

# guard_wiring_runner <sitecheck.py> (ADR-0007 part 4): the real cmd_guard,
# run on a temporary git work tree with one workflow and one static page
# (guard_hugo_config stubbed, so no Hugo is needed), must call
# guard_public_tree with that root and git's listing
# (wiring/guard-public-tree-called), guard_workflows must call
# guard_workflow_hardening with the workflow's path and text
# (wiring/guard-workflow-hardening-called), and cmd_guard must call
# guard_records_templates with the root (wiring/guard-records-templates-
# called, ADR-0007 part 5). Recorders replace the three functions, so a
# cmd_guard that drops a call turns its line red.
guard_wiring_runner() {
  python3 -I -B - "$1" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
calls = {"tree": [], "hardening": [], "templates": []}
sitecheck.guard_public_tree = lambda root, files, findings: calls["tree"].append((root, files))
sitecheck.guard_records_templates = lambda root, findings: calls["templates"].append(root)
sitecheck.guard_workflow_hardening = lambda rel, text, findings: calls["hardening"].append((rel, text))
sitecheck.guard_hugo_config = lambda root, hugo_bin, findings: None
workflow = "name: x\non: push\npermissions:\n  contents: read\njobs: {}\n"
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp).resolve()
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "x.yml").write_text(workflow)
    (root / "content").mkdir()
    (root / "content" / "about.md").write_text('+++\ntitle = "About"\n+++\n')
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    with contextlib.redirect_stdout(io.StringIO()):
        sitecheck.cmd_guard(argparse.Namespace(root=str(root), hugo=None))
    files = sitecheck.git_files(root)
ok = calls["tree"] == [(root, files)]
print(f"ok   wiring/guard-public-tree-called (cmd_guard passes the root and git's listing)"
      if ok else f"FAIL wiring/guard-public-tree-called: calls {calls['tree']}")
ok = calls["hardening"] == [(".github/workflows/x.yml", workflow)]
print(f"ok   wiring/guard-workflow-hardening-called (guard_workflows passes each workflow)"
      if ok else f"FAIL wiring/guard-workflow-hardening-called: calls {calls['hardening']}")
ok = calls["templates"] == [root]
print(f"ok   wiring/guard-records-templates-called (cmd_guard passes the root)"
      if ok else f"FAIL wiring/guard-records-templates-called: calls {calls['templates']}")
PY
}

# guard_templates_runner <sitecheck.py> <records-repo fixtures> (ADR-0007
# part 5, Replikanti/interviewscam#38 PR E): guard_records_templates on a
# temporary root per case, which must give exactly the case's findings.
# The template directory holds the three real templates (pass-real), one
# of them with one byte appended (fail-byte-*), an unpinned extra.yml, the
# retired deploy.yml template of PR C byte for byte (fail-retired-deploy,
# tests/fixtures/records-repo/retired-deploy.yml, held to its old SHA-256
# here so it cannot drift), a symlink in place of a template, or lacks one
# template (fail-missing-*); a root without the template directory (the
# guard fixtures) gives no finding. One ok/FAIL line per case.
guard_templates_runner() {
  python3 -I -B - "$@" <<'PY'
import hashlib
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
fixtures = Path(sys.argv[2])
real = Path(sys.argv[1]).resolve().parent.parent / sitecheck.RECORDS_TEMPLATE_DIR
retired = fixtures / "retired-deploy.yml"
RETIRED_SHA256 = "3922286571a3828e6c362b87cbc44c170f3f574ef39b98fbf5a1805b5c0a85d3"
UNPINNED = "a records workflow template that is not pinned"
MISMATCH = "the records workflow template's SHA-256 is"
MISSING = "a pinned records workflow template is missing"
NOT_FILE = "a records workflow template must be a regular file"
KINDS = (UNPINNED, MISMATCH, MISSING, NOT_FILE)
D = sitecheck.RECORDS_TEMPLATE_DIR


def tree(tmp, edit):
    root = Path(tmp)
    if edit == "no-dir":
        return root
    base = root / D
    base.mkdir(parents=True)
    for name in sitecheck.RECORDS_WORKFLOWS:
        shutil.copyfile(real / name, base / name)
    kind, _, name = edit.partition(" ")
    if kind == "byte":
        with open(base / name, "ab") as handle:
            handle.write(b"#")
    elif kind == "missing":
        (base / name).unlink()
    elif kind == "extra":
        (base / name).write_bytes(b"name: extra\n")
    elif kind == "retired":
        shutil.copyfile(retired, base / name)
    elif kind == "symlink":
        (base / name).unlink()
        (base / name).symlink_to(real / name)
    return root


cases = {"pass-real": ("real", set()), "pass-no-template-dir": ("no-dir", set()),
         "fail-unpinned-extra": ("extra extra.yml", {(f"{D}/extra.yml", UNPINNED)}),
         "fail-retired-deploy": ("retired deploy.yml", {(f"{D}/deploy.yml", UNPINNED)}),
         "fail-symlink-ci": ("symlink ci.yml", {(f"{D}/ci.yml", NOT_FILE)})}
for name in sitecheck.RECORDS_WORKFLOWS:
    stem = name.removesuffix(".yml")
    cases[f"fail-byte-{stem}"] = (f"byte {name}", {(f"{D}/{name}", MISMATCH)})
    cases[f"fail-missing-{stem}"] = (f"missing {name}", {(f"{D}/{name}", MISSING)})
if hashlib.sha256(retired.read_bytes()).hexdigest() != RETIRED_SHA256:
    print("FAIL guard-records-templates/retired-fixture: retired-deploy.yml is not the "
          "template of PR C byte for byte")
for case, (edit, want) in cases.items():
    with tempfile.TemporaryDirectory() as tmp:
        findings = sitecheck.Findings()
        sitecheck.guard_records_templates(tree(tmp, edit), findings)
    got = set()
    for item in findings.items:
        where, message = item[len("FAIL: "):].split(": ", 1)
        got.add((where, next((k for k in KINDS if message.startswith(k)), message)))
    if got == want:
        print(f"ok   guard-records-templates/{case} ({len(want)} finding(s))")
    else:
        print(f"FAIL guard-records-templates/{case}: {findings.items}")
print(f"ok   guard-records-templates/table ({len(cases)} cases)")
PY
}

# records_repo_runner <sitecheck.py> <pins.env> case <dir> | table <tsv>
# <base dir> | wiring <base dir> (ADR-0007 part 5, Replikanti/interviewscam#38
# PR C): `sitecheck records-repo` on a fake records repo. Every run gets a
# throwaway public checkout (a git work tree holding tools/pins.env and the
# canonical templates of RECORDS_TEMPLATE_DIR, copied from this checkout,
# one commit) and a copy of the case in its own git work tree, untracked
# (the rule reads git's listing, tracked and untracked alike). A case with
# no .github/ (pass-empty, pass-records) gets the same templates as its
# workflows, so it stays a layout case: the identity rule (PR E) requires
# every canonical workflow. The fixture pin RECORDS_FIXTURE_PIN in the
# case's workflows is set to that checkout's HEAD, so pass-shapes/ stays
# the canonical set of the private workflows that the pin bump copies with
# the real pin. Every read and write keeps the bytes (no newline
# translation), so a CR row reaches the check as written. case: prints the
# output and exits with the check's exit code (the fixture loop judges
# it). table: one line per row of tests/fixtures/records-repo/cases.tsv on
# a copy of the base case, each row one edit; a find string absent or
# present twice fails the row. wiring: cmd_records_repo must hand every
# workflow of the records repo to guard_workflows in records mode, which
# calls guard_workflow_hardening (PR B's shared rules) and
# records_workflow_rules on each, guard_lighthouse_workflow in records
# mode, and records_workflow_identity with the root, the records repo,
# git's listing and the pin; the runner's PIN must be
# RECORDS_FIXTURE_PIN. -B: no tools/__pycache__.
records_repo_runner() {
  python3 -I -B - "$@" <<'PY'
import argparse
import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SITECHECK, PINS, MODE = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
PIN = "0123456789abcdef0123456789abcdef01234567"  # RECORDS_FIXTURE_PIN
# The canonical templates (RECORDS_TEMPLATE_DIR) of this checkout.
TEMPLATE_DIR = "tests/fixtures/records-repo/pass-shapes/.github/workflows"
TEMPLATES = Path(SITECHECK).resolve().parent.parent / TEMPLATE_DIR
GIT = ["git", "-c", "user.name=selftest", "-c", "user.email=selftest@example.invalid",
       "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
MARKERS = ("expect.txt",)


def git(*args):
    subprocess.run([*GIT, *args], check=True, capture_output=True)


def public_root(tmp, form=None, name=None):
    """The throwaway public checkout: tools/pins.env and the templates, one
    commit. form template-missing leaves the template name out,
    template-edited appends one byte to it, before the commit."""
    root = tmp / "public"
    (root / "tools").mkdir(parents=True)
    shutil.copy(PINS, root / "tools" / "pins.env")
    templates = root / TEMPLATE_DIR
    templates.mkdir(parents=True)
    for path in sorted(TEMPLATES.iterdir()):
        if path.is_file() and not path.is_symlink():
            shutil.copyfile(path, templates / path.name)
    if form == "template-missing":
        (templates / name).unlink()
    elif form == "template-edited":
        with open(templates / name, "ab") as handle:
            handle.write(b"#")
    git("-C", str(root), "init", "-q")
    git("-C", str(root), "add", "-A")
    git("-C", str(root), "commit", "-q", "-m", "fixture public checkout")
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    return root, sha


def records_dir(tmp, case):
    rdir = tmp / "records"
    shutil.copytree(case, rdir, symlinks=True)
    for name in MARKERS:
        (rdir / name).unlink(missing_ok=True)
    if not (rdir / ".github").exists():
        shutil.copytree(TEMPLATES, rdir / ".github" / "workflows")
    return rdir


def set_pin(rdir, sha):
    workflows = rdir / ".github" / "workflows"
    if workflows.is_dir():
        for path in workflows.iterdir():
            if path.is_file() and not path.is_symlink():
                path.write_bytes(path.read_bytes().replace(PIN.encode("ascii"),
                                                           sha.encode("ascii")))


def run(root, rdir, sha):
    proc = subprocess.run([sys.executable, "-I", "-B", SITECHECK, "records-repo", "--root",
                           str(root), "--dir", str(rdir), "--sha", sha],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def unescape(text):
    text = text.replace("\\n", "\n").replace("{PIN39}", PIN[:39]).replace(
        "{PINUP}", PIN.upper()).replace("{PIN}", PIN)
    return re.sub(r"\{U\+([0-9A-F]{4,6})\}", lambda m: chr(int(m.group(1), 16)), text)


_module = []


def run_inline(root, rdir, sha):
    """The real cmd_records_repo in this process (the module loaded once);
    the case mode and the fixture loop run the command line."""
    if not _module:
        spec = importlib.util.spec_from_file_location("sitecheck", SITECHECK)
        _module.append(importlib.util.module_from_spec(spec))
        spec.loader.exec_module(_module[0])
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        try:
            rc = _module[0].cmd_records_repo(argparse.Namespace(
                root=str(root), dir=str(rdir), sha=sha))
        except _module[0].UsageError as exc:
            print(f"sitecheck: ERROR: {exc}")
            rc = 2
    return rc, buffer.getvalue()


if MODE == "case":
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root, sha = public_root(tmp)
        rdir = records_dir(tmp, Path(sys.argv[4]))
        set_pin(rdir, sha)
        git("-C", str(rdir), "init", "-q")
        rc, out = run(root, rdir, sha)
    print(out, end="")
    sys.exit(rc)

if MODE == "wiring":
    spec = importlib.util.spec_from_file_location("sitecheck", SITECHECK)
    sitecheck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sitecheck)
    calls = {"hardening": [], "records": [], "lighthouse": [], "identity": []}
    sitecheck.guard_workflow_hardening = lambda rel, text, findings: calls["hardening"].append(rel)

    def identity(root, rdir, files, sha, findings):
        calls["identity"].append((root, rdir, list(files), sha))
        return 0
    sitecheck.records_workflow_identity = identity
    sitecheck.records_workflow_rules = (
        lambda rel, text, sha, findings: calls["records"].append((rel, sha)))
    sitecheck.guard_lighthouse_workflow = (
        lambda root, files, findings, records_mode=False: calls["lighthouse"].append(
            (sorted(files), records_mode)))
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root, sha = public_root(tmp)
        rdir = records_dir(tmp, Path(sys.argv[4]))
        set_pin(rdir, sha)
        git("-C", str(rdir), "init", "-q")
        with contextlib.redirect_stdout(io.StringIO()):
            sitecheck.cmd_records_repo(argparse.Namespace(root=str(root), dir=str(rdir), sha=sha))
        listing = subprocess.run(["git", "-C", str(rdir), "ls-files", "-z", "--cached", "--others",
                                  "--exclude-standard"], check=True, capture_output=True,
                                 text=True).stdout
        listing = sorted({p for p in listing.split("\0") if p})
    want = sorted(f".github/workflows/{name}" for name in sitecheck.RECORDS_WORKFLOWS)
    ok = sorted(calls["hardening"]) == want
    print("ok   wiring/records-repo-workflow-hardening-called (every records workflow gets "
          "WH1 to WH4)" if ok else
          f"FAIL wiring/records-repo-workflow-hardening-called: calls {calls['hardening']}")
    ok = sorted(calls["records"]) == [(w, sha) for w in want]
    print("ok   wiring/records-repo-workflow-rules-called (every records workflow gets the "
          "records forms with the pin)" if ok else
          f"FAIL wiring/records-repo-workflow-rules-called: calls {calls['records']}")
    ok = calls["lighthouse"] == [(want, True)]
    print("ok   wiring/records-repo-lighthouse-called (guard_lighthouse_workflow in records "
          "mode)" if ok else
          f"FAIL wiring/records-repo-lighthouse-called: calls {calls['lighthouse']}")
    ok = calls["identity"] == [(root.resolve(), rdir.resolve(), listing, sha)] and listing
    print("ok   wiring/records-repo-identity-called (records_workflow_identity gets the root, "
          "the records repo, git's listing and the pin)" if ok else
          f"FAIL wiring/records-repo-identity-called: calls {calls['identity']}")
    ok = PIN == sitecheck.RECORDS_FIXTURE_PIN
    print("ok   wiring/records-fixture-pin-matches (the runner's PIN is RECORDS_FIXTURE_PIN)"
          if ok else f"FAIL wiring/records-fixture-pin-matches: {PIN} against "
          f"{sitecheck.RECORDS_FIXTURE_PIN}")
    sys.exit(0)

table, base = Path(sys.argv[4]), Path(sys.argv[5])
n = 0
shared = Path(tempfile.mkdtemp())
public, public_sha = public_root(shared)  # one public checkout for every row
for line in table.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"):
        continue
    n += 1
    cols = line.split("\t")
    if len(cols) != 5:
        print(f"FAIL records-repo/row-{n}: {len(cols)} columns, not 5")
        continue
    name, rel, find, replace, expect = cols
    find, replace = unescape(find), unescape(replace)
    stray = public / "stray.txt"
    stray.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        root, sha = public, public_sha
        rdir = records_dir(tmp, base)
        target, bad = rdir, None
        if rel == "@symlink":
            link = rdir / find
            if link.exists() or link.is_symlink():
                shutil.rmtree(link) if link.is_dir() and not link.is_symlink() else link.unlink()
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(replace)
        elif rel == "@root":
            if find == "dirty":
                stray.write_text("x\n")
            elif find == "head":
                sha = "1" * 40
            elif find in ("template-missing", "template-edited"):
                # Its own public checkout, committed after the change.
                root, sha = public_root(tmp, find, replace)
            else:
                bad = f"unknown @root form {find!r}"
        elif rel == "@nested":
            target = rdir / find
        elif find == "+":
            path = rdir / rel
            if path.exists():
                bad = f"{rel} exists already"
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(replace.encode("utf-8"))
        elif find == "*":
            (rdir / rel).unlink()
        elif find == "=":
            (rdir / rel).write_bytes(replace.encode("utf-8"))
        else:
            path = rdir / rel
            text = path.read_bytes().decode("utf-8")
            if text.count(find) != 1:
                bad = f"the find string occurs {text.count(find)} times in {rel}, not once"
            else:
                path.write_bytes(text.replace(find, replace).encode("utf-8"))
        if bad:
            print(f"FAIL records-repo/{name}: {bad}")
            continue
        set_pin(rdir, sha)
        git("-C", str(rdir), "init", "-q")
        rc, out = run_inline(root, target, sha)
    if expect == "PASS":
        ok = rc == 0
    elif expect.startswith("ONLY "):
        # Exactly one finding, the row's: no other rule saw the edit.
        fails = [out_line for out_line in out.splitlines() if out_line.startswith("FAIL: ")]
        ok = rc == 1 and len(fails) == 1 and expect[len("ONLY "):] in fails[0]
    else:
        ok = rc == 1 and expect in out
    if ok:
        print(f"ok   records-repo/{name} ({'passed' if expect == 'PASS' else expect})")
    else:
        print(f"FAIL records-repo/{name}: exit {rc}, expected "
              f"{'a pass' if expect == 'PASS' else repr(expect)}; output:")
        for out_line in out.splitlines():
            print(f"     | {out_line}")
shutil.rmtree(shared)
print(f"ok   records-repo/table ({n} rows)" if n else "FAIL records-repo/table: no rows")
PY
}

# pin_runner <sitecheck.py> <fixtures/pin> (ADR-0007 part 5,
# Replikanti/interviewscam#38 PR C): `sitecheck pin` against a stub of the
# GitHub API on loopback (SITECHECK_GITHUB_API), in the manner of the stub
# API of tests/worker/. The stub answers exactly the two reads of the pin
# rule for the fixture pin RECORDS_FIXTURE_PIN, from the case's
# check-runs.json and compare.json, with the statuses of its status.txt
# (`<check-runs|compare> <status>...`: one per request, the last one
# repeated; `closed`: a port nothing listens on), and 404 for any other
# path. The compare read is the one against heads/main; a case's
# compare-bare-main.json answers the bare name main, which the rule must
# never ask (a tag named main would make it ambiguous; fail-bare-main-is-a-
# tag). Every tests/fixtures/pin/<pass|fail>-<case>/ runs the real cmd_pin
# in this process (the fixture loop skips the directory), judged as the
# loop judges a case (exit 0 and the expect.txt text, or a failure with
# it), with PIN_RETRY_DELAY patched to 0 so a retry costs no wall time;
# its requests.txt (`<check-runs|compare|compare-bare-main|redirected>
# <count>`) pins how often the stub was asked. pin-extra/numbers pins the real request
# numbers (ADR-0007 Numbers), and the other pin-extra lines run the
# command line: the override refusal, the token kept out of the output and
# sent only as the header, no header without a token, the SHA form.
pin_runner() {
  python3 -I -B - "$@" <<'PY'
import argparse
import contextlib
import http.server
import importlib.util
import io
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

SITECHECK, FIXTURES = sys.argv[1], Path(sys.argv[2])
PIN = "0123456789abcdef0123456789abcdef01234567"  # RECORDS_FIXTURE_PIN
REPO = "/repos/Replikanti/interviewscam-site"
PATHS = {f"{REPO}/commits/{PIN}/check-runs?check_name=check&per_page=100": "check-runs",
         f"{REPO}/compare/{PIN}...heads/main": "compare", "/redirected": "redirected",
         f"{REPO}/compare/{PIN}...main": "compare-bare-main"}
spec = importlib.util.spec_from_file_location("sitecheck", SITECHECK)
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
REAL_NUMBERS = (sitecheck.PIN_TIMEOUT, sitecheck.PIN_TRIES, sitecheck.PIN_RETRY_DELAY,
                sitecheck.ACTIONS_APP_ID, sitecheck.GITHUB_API, sitecheck.PUBLIC_REPO)
sitecheck.PIN_RETRY_DELAY = 0


class Stub:
    def __init__(self, case):
        self.case = case
        self.statuses = {}
        status = case / "status.txt"
        for line in (status.read_text().splitlines() if status.is_file() else ()):
            parts = line.split()
            if parts and parts[0] != "closed":
                self.statuses[parts[0]] = [int(p) for p in parts[1:]]
        self.closed = status.is_file() and status.read_text().strip() == "closed"
        self.counts = {name: 0 for name in set(PATHS.values())}
        self.auth = []
        self.unexpected = []
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                name = PATHS.get(self.path)
                stub.auth.append(self.headers.get("Authorization"))
                if name is None:
                    stub.unexpected.append(self.path)
                    return self.answer(404, b'{"message": "unexpected request"}')
                stub.counts[name] += 1
                codes = stub.statuses.get(name, [200])
                code = codes[min(stub.counts[name], len(codes)) - 1]
                if code in (301, 302, 307, 308):
                    return self.answer(code, b"{}", {"Location": "/redirected"})
                body = b'{"message": "stub error"}'
                if code == 200 and not (stub.case / f"{name}.json").is_file():
                    code = 404  # compare-bare-main: only the case that has it
                if code == 200:
                    body = (stub.case / f"{name}.json").read_bytes()
                return self.answer(code, body)

            def answer(self, code, body, headers=None):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        if self.closed:
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
            sock.close()  # nothing listens there now
        else:
            self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def pin_inline(base, sha=PIN):
    os.environ.pop("GH_TOKEN", None)
    os.environ["SITECHECK_GITHUB_API"] = base
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        try:
            rc = sitecheck.cmd_pin(argparse.Namespace(sha=sha))
        except sitecheck.UsageError as exc:
            print(f"sitecheck: ERROR: {exc}")
            rc = 2
    return rc, buffer.getvalue()


def pin_cli(base, sha=PIN, token=None):
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
    env["SITECHECK_GITHUB_API"] = base
    if token is not None:
        env["GH_TOKEN"] = token
    proc = subprocess.run([sys.executable, "-I", "-B", SITECHECK, "pin", "--sha", sha],
                          capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


def report(name, ok, detail, out=""):
    if ok:
        print(f"ok   {name} ({detail})")
    else:
        print(f"FAIL {name}: {detail}" + ("; output:" if out else ""))
        for line in out.splitlines():
            print(f"     | {line}")


n_cases = 0
for case in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
    n_cases += 1
    name = f"pin/{case.name}"
    expect_file = case / "expect.txt"
    expect = expect_file.read_text().splitlines()[0] if expect_file.is_file() else ""
    stub = Stub(case)
    rc, out = pin_inline(stub.base)
    stub.close()
    want = {}
    requests = case / "requests.txt"
    for line in (requests.read_text().splitlines() if requests.is_file() else ()):
        key, count = line.split()
        want[key] = int(count)
    got = {key: stub.counts[key] for key in want}
    if got != want or stub.unexpected:
        report(name, False, f"stub requests {got}, want {want}; unexpected paths "
               f"{stub.unexpected}", out)
    elif case.name.startswith("pass-"):
        report(name, rc == 0 and (not expect or expect in out),
               f"passed with: {expect}" if rc == 0 else f"expected exit 0, got {rc}", out)
    elif case.name.startswith("fail-"):
        report(name, rc == 1 and bool(expect) and expect in out,
               f"failed as expected: {expect}", out)
    else:
        report(name, False, "fixture name must start with pass- or fail-")
report("pin-extra/numbers", REAL_NUMBERS == (20, 3, 5, 15368, "https://api.github.com",
                                             "Replikanti/interviewscam-site"),
       f"timeout, tries, delay, app, API, repo: {REAL_NUMBERS}")
for base in ("https://127.0.0.1:1", "http://127.0.0.1:1/x", "http://localhost:1",
             "http://127.0.0.2:1", "http://example.invalid", "http://127.0.0.1:1 "):
    rc, out = pin_cli(base)
    report(f"pin-extra/refuse-override {base!r}",
           rc == 2 and "SITECHECK_GITHUB_API may only name" in out, f"exit {rc}")
SENTINEL = "selftest-token-SENTINEL-4c9d"
for case, want_rc in ((FIXTURES / "pass-ahead", 0), (FIXTURES / "fail-404", 1)):
    stub = Stub(case)
    rc, out = pin_cli(stub.base, token=SENTINEL)
    stub.close()
    ok = (rc == want_rc and SENTINEL not in out and len(stub.auth) >= 2
          and all(a == f"Bearer {SENTINEL}" for a in stub.auth))
    report(f"pin-extra/token-not-printed/{case.name}", ok,
           f"exit {rc}, sentinel in output: {SENTINEL in out}, {len(stub.auth)} requests, "
           f"all with the header: {all(a == f'Bearer {SENTINEL}' for a in stub.auth)}")
stub = Stub(FIXTURES / "pass-ahead")
rc, out = pin_cli(stub.base)
stub.close()
report("pin-extra/no-token-no-header", rc == 0 and bool(stub.auth)
       and all(a is None for a in stub.auth), f"exit {rc}, headers {stub.auth}")
for sha in (PIN.upper(), PIN[:39], PIN + "0", "main"):
    rc, out = pin_inline("http://127.0.0.1:1", sha=sha)
    report(f"pin-extra/sha-form {len(sha)} chars {sha[:6]}",
           rc == 2 and "is not 40 lowercase hex" in out, f"exit {rc}")
report("pin/cases", n_cases > 0, f"{n_cases} cases")
PY
}

# records_mode_e2e <root> <fixtures> (ADR-0007 part 5,
# Replikanti/interviewscam#38 PR C): check.sh --records end to end, outside
# CI (GITHUB_ACTIONS unset, so reflow and the Nu Html Checker print NOT RUN
# and the run ends RECORDS LOCAL PASS). <root> is copied with git's listing
# of its working tree into a fresh git work tree with one commit, so the
# pin is that commit and the clean-tree rule holds whatever the developer's
# tree holds; its .tools/cache is the real one, so nothing is downloaded. A
# stub of the GitHub API on loopback answers every pin with a green check
# on main. The records repo is generated here, with slugs and names no
# fixture uses, plus the canonical workflows of records-repo/pass-shapes
# at that pin. Prints one ok/FAIL line per case.
records_mode_e2e() {
  local src="$1" fx="$2" tmp root records port_file stub_pid port sha out rc
  tmp="$(mktemp -d)" || { echo "FAIL records-mode/e2e: mktemp failed"; return; }
  root="$tmp/public"
  records="$tmp/records"
  out="$tmp/out.txt"
  port_file="$tmp/port"
  if ! python3 -I -B - "$src" "$root" <<'PY'
import os
import shutil
import subprocess
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
listing = subprocess.run(["git", "-C", str(src), "ls-files", "-z", "--cached", "--others",
                          "--exclude-standard"], check=True, capture_output=True).stdout
for rel in sorted({p for p in listing.decode("utf-8", "surrogateescape").split("\0") if p}):
    path, target = src / rel, dst / rel
    if not (path.is_symlink() or path.is_file()):
        continue  # staged, then deleted on disk
    target.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        os.symlink(os.readlink(path), target)
    else:
        shutil.copy2(path, target)
PY
  then
    echo "FAIL records-mode/e2e: copying the work tree failed"
    rm -rf "$tmp"
    return
  fi
  mkdir -p "$root/.tools" && ln -s "$src/.tools/cache" "$root/.tools/cache"
  local -a git_id=(-c user.name=selftest -c user.email=selftest@example.invalid
    -c commit.gpgsign=false -c init.defaultBranch=main)
  if ! { git "${git_id[@]}" -C "$root" init -q && git "${git_id[@]}" -C "$root" add -A \
      && git "${git_id[@]}" -C "$root" commit -q -m "records mode e2e"; }; then
    echo "FAIL records-mode/e2e: git could not commit the copy"
    rm -rf "$tmp"
    return
  fi
  sha="$(git -C "$root" rev-parse HEAD)"
  python3 -I -B - "$port_file" <<'PY' &
import http.server
import json
import re
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        m = re.fullmatch(r"/repos/Replikanti/interviewscam-site/commits/([0-9a-f]{40})"
                         r"/check-runs\?check_name=check&per_page=100", self.path)
        if m:
            body = {"total_count": 1, "check_runs": [{
                "id": 1, "name": "check", "head_sha": m.group(1), "status": "completed",
                "conclusion": "success", "app": {"id": 15368}}]}
        elif re.fullmatch(r"/repos/Replikanti/interviewscam-site/compare/[0-9a-f]{40}\.\.\.heads/main",
                          self.path):
            body = {"status": "identical", "ahead_by": 0, "behind_by": 0}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1] + ".part", "w") as f:
    f.write(str(server.server_address[1]))
import os
os.rename(sys.argv[1] + ".part", sys.argv[1])
server.serve_forever()
PY
  stub_pid=$!
  local _
  for _ in $(seq 100); do
    [[ -s "$port_file" ]] && break
    sleep 0.05
  done
  port="$(cat "$port_file" 2>/dev/null)"
  if [[ -z "$port" ]]; then
    echo "FAIL records-mode/e2e: the stub API did not start"
    kill "$stub_pid" 2>/dev/null
    rm -rf "$tmp"
    return
  fi

  # e2e_run <case>: check.sh --records on $records, output in $out.
  e2e_run() {
    git "${git_id[@]}" -C "$records" init -q >/dev/null 2>&1
    env -u GITHUB_ACTIONS -u CI -u GH_TOKEN -u GITHUB_TOKEN \
      SITECHECK_GITHUB_API="http://127.0.0.1:$port" \
      bash "$root/tools/check.sh" --records "$records" >"$out" 2>&1
    rc=$?
  }
  # e2e_steps <step...>: only the named records-mode steps of the copy's
  # check.sh (sourced, so CHECK_ROOT is the copy), output in $out. The
  # two content cases below need no pin, fetch, guard or link run.
  e2e_steps() {
    # shellcheck disable=SC2016 # the script expands its own arguments
    bash -c 'source "$1/tools/check.sh" || exit 2
      cd "$1" && load_pins || exit 2
      RECORDS_DIR="$2"
      sha12="$3"
      shift 3
      for step in "$@"; do run_step "$step" "$step"; done
      check_summary records "$sha12"' e2e-steps "$root" "$records" "${sha:0:12}" "$@" >"$out" 2>&1
    rc=$?
  }
  # e2e_ere <text>: text as an ERE that matches it literally (the step
  # names hold brackets, parentheses and dots).
  e2e_ere() {
    local s="$1" c
    for c in '[' ']' '(' ')' '.' '*'; do s="${s//"$c"/\\"$c"}"; done
    printf '%s' "$s"
  }
  # e2e_report <name> <ok?> <detail>
  e2e_report() {
    if [[ "$2" == 1 ]]; then
      echo "ok   records-mode/$1 ($3)"
    else
      echo "FAIL records-mode/$1: $3; output:"
      sed 's/^/     | /' "$out"
    fi
  }
  local report='+++
date = 2026-11-01
[params]
name = "Records Mode Selftest Name"
name_type = "company"
state = "front"
state_basis = ["No company of this name could be found."]
summary = "A generated record of the records-mode self-test."
evidence = "One generated submission."
first_seen = 2026-10-01
last_seen = 2026-10-02
last_reviewed = 2026-11-01
independent_reports = 1

[params.artifacts]
domains = ["records-mode-selftest[.]example"]
+++
'
  local ok line n

  # e2e-empty: a records repo with no content/ at all, and the canonical
  # workflows at the pin (the identity rule requires every one).
  mkdir -p "$records" && printf '# records\n' >"$records/README.md"
  cp -R "$fx/records-repo/pass-shapes/.github" "$records/"
  sed -i "s/0123456789abcdef0123456789abcdef01234567/$sha/" "$records"/.github/workflows/*.yml
  e2e_run
  ok=0
  [[ $rc -eq 0 ]] && grep -qx "RECORDS LOCAL PASS on ${sha:0:12}, HTML validation and reflow not run (CI only)" "$out" \
    && grep -q '^records checked: 0 ' "$out" && grep -q '^pin checked: ' "$out" \
    && grep -q '^records-repo checked: .* 0 records, 3 workflows (3 identical to the templates)' "$out" && ok=1
  e2e_report e2e-empty "$ok" "exit $rc, records checked: 0, 3 workflows identical to the templates, RECORDS LOCAL PASS on ${sha:0:12}"

  # e2e: one record, the canonical workflows at the pin, the policy. The
  # policy retires a slug made up here (no file of the copy holds it), the
  # canary of no-records-copy below.
  local canary="records-mode-retired-$RANDOM$RANDOM"
  rm -rf "$records" && mkdir -p "$records/content/reports" "$records/content/campaigns" "$records/schema"
  cp -R "$fx/records-repo/pass-shapes/.github" "$records/"
  sed -i "s/0123456789abcdef0123456789abcdef01234567/$sha/" "$records"/.github/workflows/*.yml
  printf 'worktrees/\n' >"$records/.gitignore"
  printf '# records\n' >"$records/README.md"
  printf '{"retired_slugs": ["%s"]}\n' "$canary" >"$records/schema/record-policy.json"
  cp "$fx/records/pass-fixture-site/content/reports/_index.md" "$records/content/reports/"
  cp "$fx/records/pass-fixture-site/content/campaigns/_index.md" "$records/content/campaigns/"
  printf '%s' "$report" >"$records/content/reports/records-mode-selftest-name.md"
  e2e_run
  ok=0
  [[ $rc -eq 0 ]] && grep -qx "RECORDS LOCAL PASS on ${sha:0:12}, HTML validation and reflow not run (CI only)" "$out" \
    && grep -q '^records checked: 1 (reports 1, campaigns 0)' "$out" \
    && grep -q '^records-repo checked: .* 1 records, 3 workflows (3 identical to the templates)' "$out" \
    && grep -q '^render checked: 1 records' "$out" && [[ -f "$root/public/reports/records-mode-selftest-name/index.html" ]] && ok=1
  e2e_report e2e "$ok" "exit $rc, 1 record built and checked, 3 workflows identical to the templates, RECORDS LOCAL PASS"

  # no-records-copy (fix round 2 of interviewscam-site#12): a passing run
  # leaves no copy of the records repo where an artifact upload could take
  # it. .records-site/ is gone, the cleanup step passed, no file under
  # public/ or tools/ (the two upload paths) equals a file of the records
  # repo, and none holds the retired slug of its policy.
  ok=0
  [[ $rc -eq 0 && ! -e "$root/.records-site" && ! -L "$root/.records-site" ]] \
    && grep -qE '^  records cleanup \(\.records-site/ removed\) +PASS$' "$out" \
    && ! grep -rqF -- "$canary" "$root/public" "$root/tools" \
    && [[ -z "$(comm -12 \
      <(find "$records" -path "$records/.git" -prune -o -type f -exec sha256sum {} + | cut -d' ' -f1 | sort -u) \
      <(find "$root/public" "$root/tools" -type f -exec sha256sum {} + | cut -d' ' -f1 | sort -u))" ]] \
    && ok=1
  e2e_report no-records-copy "$ok" "exit $rc, no .records-site/, no records file or retired slug under public/ or tools/"

  # not-run-lines: every machinery step prints the records-mode NOT RUN line
  # and records it, and every content step ran.
  ok=1
  for line in shellcheck "worker (intake Worker and deploy tool)" "tokens (contrast, colour literals)" \
      "literals (fixed copy only from data/labels.toml)" "fixture build" "site (fixture build)" \
      "render (fixture build)" "links (fixture build, offline)" selftest; do
    grep -qE "^  $(e2e_ere "$line") +NOT RUN \(records mode\)\$" "$out" || ok=0
  done
  n="$(grep -c "^NOT RUN (records mode): machinery only, held by the pinned commit's green check\$" "$out")"
  [[ "$n" == 9 ]] || ok=0
  for line in "pin (green check on public main)" fetch-tools "guard (repo rules)" \
      "records repo (layout, workflows)" "records assembly" "records (schema, defang)" build \
      "site (third-party, CSP, defang)" "render (D6, D7, D10, structured data)" "links (offline, internal)" \
      "records cleanup (.records-site/ removed)"; do
    grep -qE "^  $(e2e_ere "$line") +PASS\$" "$out" || ok=0
  done
  e2e_report not-run-lines "$ok" "9 machinery steps NOT RUN (records mode), 10 content steps and the cleanup PASS"

  # assembly: .records-site/ against its sources, per input class (the
  # assembly step alone: the whole run removes .records-site/ at its end).
  e2e_steps step_records_assembly
  ok=1
  [[ $rc -eq 0 ]] || ok=0
  diff -r "$root/.records-site/content/reports" "$records/content/reports" >/dev/null || ok=0
  diff -r "$root/.records-site/content/campaigns" "$records/content/campaigns" >/dev/null || ok=0
  for line in "$root"/content/*.md; do
    cmp -s "$line" "$root/.records-site/content/${line##*/}" || ok=0
  done
  [[ "$(find "$root/.records-site/content" -maxdepth 1 -type f | wc -l)" == \
     "$(find "$root/content" -maxdepth 1 -type f -name '*.md' | wc -l)" ]] || ok=0
  diff -r -x record-policy.json "$root/.records-site/schema" "$root/schema" >/dev/null || ok=0
  cmp -s "$root/.records-site/schema/record-policy.json" "$records/schema/record-policy.json" || ok=0
  for line in "${FIXTURE_COPY[@]}"; do
    if [[ -e "$root/$line" ]]; then
      diff -r "$root/$line" "$root/.records-site/$line" >/dev/null || ok=0
    fi
  done
  e2e_report assembly "$ok" "the record sections, the static pages, schema/ with the records repo's policy and FIXTURE_COPY match their sources"

  # fixture-leak: a record with a fixture record's slug and name.
  printf '%s' "${report//Records Mode Selftest Name/Example Abused Company}" \
    >"$records/content/reports/example-abused-company.md"
  rm -f "$records/content/reports/records-mode-selftest-name.md"
  e2e_steps step_records_assembly step_records_build step_records_render
  ok=0
  [[ $rc -ne 0 ]] && grep -q 'shares its slug and name with the fixture record' "$out" \
    && grep -qE '^  step_records_render +FAIL$' "$out" && ok=1
  e2e_report fixture-leak "$ok" "exit $rc, render FAIL: a fixture record's slug and name"
  rm -f "$records/content/reports/example-abused-company.md"

  # policy-overlay: the records repo's policy retires its own record's slug.
  printf '%s' "$report" >"$records/content/reports/records-mode-selftest-name.md"
  printf '{"retired_slugs": ["records-mode-selftest-name"]}\n' >"$records/schema/record-policy.json"
  e2e_steps step_records_assembly step_records_records
  ok=0
  [[ $rc -ne 0 ]] && grep -q "slug 'records-mode-selftest-name' is retired" "$out" \
    && grep -qE '^  step_records_records +FAIL$' "$out" && ok=1
  e2e_report policy-overlay "$ok" "exit $rc, records FAIL on R4 with the records repo's retired slug"

  # cleanup-after-failure (review round 3 of interviewscam-site#12): the
  # whole run with the same retired slug, so a content step fails after
  # the assembly built .records-site/. The run fails, and the cleanup step
  # still removes .records-site/ (a cleanup that ran only after an all-pass
  # run would leave it).
  rm -rf "$root/.records-site"
  e2e_run
  ok=0
  [[ $rc -ne 0 && ! -e "$root/.records-site" && ! -L "$root/.records-site" ]] \
    && grep -qE '^  records assembly +PASS$' "$out" \
    && grep -qE '^  records \(schema, defang\) +FAIL$' "$out" \
    && grep -qE '^  records cleanup \(\.records-site/ removed\) +PASS$' "$out" && ok=1
  e2e_report cleanup-after-failure "$ok" "exit $rc, records FAIL after the assembly, cleanup PASS, no .records-site/"

  # assembly-only-sections: what the records repo may not ship (a template,
  # a static page, a schema, config) never reaches .records-site/, even when
  # git lists it: the assembly copies only the record sections and the
  # policy (the records-repo step reports the files themselves).
  printf '{"retired_slugs": []}\n' >"$records/schema/record-policy.json"
  mkdir -p "$records/layouts/_partials"
  printf '<p>injected</p>\n' >"$records/layouts/_partials/injected.html"
  printf '+++\ntitle = "Injected"\n+++\n' >"$records/content/injected.md"
  printf '{}\n' >"$records/schema/report.schema.json"
  printf 'title = "Injected"\n' >"$records/hugo.toml"
  e2e_steps step_records_assembly
  ok=0
  [[ $rc -eq 0 && ! -e "$root/.records-site/layouts/_partials/injected.html" \
      && ! -e "$root/.records-site/content/injected.md" ]] \
    && cmp -s "$root/.records-site/schema/report.schema.json" "$root/schema/report.schema.json" \
    && cmp -s "$root/.records-site/hugo.toml" "$root/hugo.toml" && ok=1
  e2e_report assembly-only-sections "$ok" "exit $rc, no template, page, schema or config of the records repo in .records-site/"

  # assembly-only-records: in a record section the assembly takes only
  # records (content/<section>/<name>.md, no dot file), and anything else
  # git lists there fails the step before it copies a file, even with the
  # records-repo step left out (a Hugo content adapter, _content.gotmpl,
  # would run template code in the build). One case per branch and section.
  rm -rf "$records/layouts" "$records/content/injected.md" "$records/schema/report.schema.json" \
    "$records/hugo.toml"
  for line in reports/_content.gotmpl campaigns/_content.gotmpl reports/x.html \
      reports/sub/x.md reports/.draft.md; do
    mkdir -p "$(dirname "$records/content/$line")"
    printf '{{ $.AddPage (dict "path" "injected" "title" "Injected" "kind" "page") }}\n' \
      >"$records/content/$line"
    e2e_steps step_records_assembly
    ok=0
    [[ $rc -ne 0 && ! -e "$root/.records-site" ]] \
      && grep -qF "records assembly: content/$line is not a record" "$out" && ok=1
    e2e_report "assembly-only-records $line" "$ok" "exit $rc, refused before any copy"
    rm -f "$records/content/$line"
    rmdir "$records/content/reports/sub" 2>/dev/null
  done

  # records-repo-fail-closed: when the records-repo step fails, nothing of
  # the records repo is copied, built or checked. The eight content steps
  # print NOT RUN (records repo failed), and .records-site/ and public/ (a
  # stale one included) are gone.
  printf '{{ $.AddPage (dict "path" "injected" "title" "Injected" "kind" "page") }}\n' \
    >"$records/content/reports/_content.gotmpl"
  mkdir -p "$root/public" && printf 'stale\n' >"$root/public/stale.html"
  e2e_run
  ok=0
  n="$(grep -cE '^  .* +NOT RUN \(records repo failed\)$' "$out")"
  [[ $rc -ne 0 && "$n" == 8 && ! -e "$root/.records-site" && ! -e "$root/public" ]] \
    && grep -qE '^  records repo \(layout, workflows\) +FAIL$' "$out" \
    && grep -qE '^  records assembly +NOT RUN \(records repo failed\)$' "$out" \
    && ! grep -q '^records assembly: ' "$out" && ok=1
  e2e_report records-repo-fail-closed "$ok" "exit $rc, $n content steps NOT RUN (records repo failed), no .records-site/ or public/"
  rm -f "$records/content/reports/_content.gotmpl"

  kill "$stub_pid" 2>/dev/null
  wait "$stub_pid" 2>/dev/null
  rm -rf "$tmp"
}

# The suite selection (Replikanti/interviewscam#40, ADR-0008 part 4). A
# suite is the first path segment of the rows a block prints: the token
# after "ok   " or "FAIL " up to a slash, a space or a colon (render,
# render-report, wiring, site-intake-expect). SELFTEST_ONLY holds the names
# given to --only; empty runs every suite, exactly as without the flag.
SELFTEST_ONLY=()
SELFTEST_USAGE='usage: bash tools/selftest.sh [--only SUITE[,SUITE...]]'

# selftest_parse_args <args...>: --only SUITE[,SUITE...], at most once, into
# SELFTEST_ONLY. A name is ^[a-z0-9][a-z0-9-]*$, matched against the
# characters written out, not a range, so no locale lets a look-alike or a
# zero-width character through; the whole list is matched before it is
# split, so a newline cannot end the split early. On a missing value, an
# empty list or name, a duplicate, a bad name, any other argument or a
# second --only it prints the problem and the usage line and returns 2.
selftest_parse_args() {
  local seen="" problem="" item known
  local -a items
  SELFTEST_ONLY=()
  while [[ $# -gt 0 && -z "$problem" ]]; do
    if [[ "$1" != --only ]]; then
      problem="unknown argument '$1'"
    elif [[ -n "$seen" ]]; then
      problem="--only given twice"
    elif [[ $# -lt 2 ]]; then
      problem="--only needs a value"
    elif [[ -z "$2" || "$2" == ,* || "$2" == *, || "$2" == *,,* ]]; then
      problem="--only '$2' holds an empty name"
    elif [[ "$2" == *[!abcdefghijklmnopqrstuvwxyz0123456789,-]* ]]; then
      problem="--only '$2' holds a character outside a-z, 0-9 and -"
    else
      seen=1
      IFS=, read -ra items <<<"$2"
      shift 2
      for item in "${items[@]}"; do
        if [[ "$item" != [abcdefghijklmnopqrstuvwxyz0123456789]* ]]; then
          problem="--only: '$item' does not start with a-z or 0-9"
        fi
        for known in "${SELFTEST_ONLY[@]}"; do
          [[ "$known" == "$item" ]] && problem="--only names '$item' twice"
        done
        [[ -n "$problem" ]] && break
        SELFTEST_ONLY+=("$item")
      done
    fi
  done
  if [[ -n "$problem" ]]; then
    echo "selftest: $problem" >&2
    echo "$SELFTEST_USAGE" >&2
    return 2
  fi
}

# The run's temp directory ($out, and under --only the log and the FIFO to
# tee) and the tee job, in globals, so the signal trap reads them when it
# runs: a block's own local named out cannot shadow them, and a trap set
# before the directory exists still finds it.
SELFTEST_TMP_DIR=""
SELFTEST_TEE_FD=""
SELFTEST_TEE_PID=""

# selftest_on_signal <signal>: the trap for HUP, INT, TERM and PIPE. It
# stops tee with SIGKILL and waits for it, so tee cannot write the log
# after the removal (it is killed, not waited out: the trap can run inside
# a block whose redirections hold saved copies of the FIFO descriptor, so
# closing the shell's own copy gives tee no end of input; and SIGKILL,
# because a run started with SIGTERM ignored hands that to tee too),
# removes the temp directory, and then raises the same
# signal again with its default action, so the shell dies of it and a
# calling script sees a death by signal (bash then stops on SIGINT as it
# did before the trap, instead of reading an ordinary exit 130 and going
# on). The RETURN trap of selftest_main covers every normal return;
# nothing covers SIGKILL.
selftest_on_signal() {
  local sig="$1"
  if [[ -n "$SELFTEST_TEE_PID" ]]; then
    kill -KILL "$SELFTEST_TEE_PID" 2>/dev/null
    wait "$SELFTEST_TEE_PID" 2>/dev/null
  fi
  [[ -n "$SELFTEST_TMP_DIR" ]] && rm -rf "$SELFTEST_TMP_DIR"
  trap - "$sig"
  kill -s "$sig" "$$"
}

# selftest_wants <suite>...: true when no --only is given or it names one
# of the suites.
selftest_wants() {
  local suite want
  [[ ${#SELFTEST_ONLY[@]} -eq 0 ]] && return 0
  for want in "$@"; do
    for suite in "${SELFTEST_ONLY[@]}"; do
      [[ "$suite" == "$want" ]] && return 0
    done
  done
  return 1
}

# selftest_suite <suite> <other>...: the suite a block names in a line it
# prints outside its runner's rows (the runner did not finish): <suite>
# without --only or when it is selected, else the first selected <other>,
# else <suite>. So a full run prints the line as before, and under --only
# it belongs to a selected suite instead of failing the selection check.
selftest_suite() {
  local suite
  for suite in "$@"; do
    if selftest_wants "$suite"; then
      printf '%s' "$suite"
      return
    fi
  done
  printf '%s' "$1"
}

# selftest_rows <runner output> [details]: print the ok and FAIL rows whose
# suite is selected (every row without --only), with the "     | " detail
# lines after a printed row when details is given, and add them to n_passed
# and n_failed. Without --only it prints exactly what
# sed -n '/^ok   \|^FAIL /p' (plus '/^     | /p' with details) prints. For
# the runners whose rows belong to two suites: guard-public and guard-wf,
# pin and pin-extra, render-intake and site-intake.
selftest_rows() {
  local rows
  rows="$(LC_ALL=C awk -v only="${SELFTEST_ONLY[*]}" -v details="${2:-}" '
    BEGIN { n = split(only, names, " "); for (i = 1; i <= n; i++) want[names[i]] = 1 }
    /^(ok   |FAIL )/ {
      suite = substr($0, 6)
      sub(/[\/ :].*/, "", suite)
      keep = (n == 0 || (suite in want))
      if (keep) print
      next
    }
    /^     \| / { if (details != "" && (n == 0 || keep)) print }
  ' "$1")"
  [[ -n "$rows" ]] && printf '%s\n' "$rows"
  n_passed=$((n_passed + $(grep -c '^ok   ' <<<"$rows")))
  n_failed=$((n_failed + $(grep -c '^FAIL ' <<<"$rows")))
}

# selftest_ok_count <file> <suite> <ERE> <n>: true when <suite> is not
# selected, or <file> holds exactly <n> ok rows matching ^ok   <ERE>. The
# "runner did not finish" checks of the two-suite runners use it, so under
# --only a failure that only the partner suite sees is filtered out with
# its row and the selected suite stays green (the mutant reports
# SURVIVED, ADR-0008 part 4); without --only every suite counts, as
# before.
selftest_ok_count() {
  selftest_wants "$2" || return 0
  [[ "$(grep -cE "^ok   $3" "$1")" -eq "$4" ]]
}

# selftest_selection_check <log>: under --only, every ok and FAIL row of
# <log> must belong to a selected suite, and every selected suite must have
# a row. "FAIL:" and "NOT RUN" lines and detail lines are no rows. Prints
# one FAIL selftest-only line per violation and returns 1 on any.
selftest_selection_check() {
  LC_ALL=C awk -v only="${SELFTEST_ONLY[*]}" '
    BEGIN { n = split(only, names, " "); for (i = 1; i <= n; i++) want[names[i]] = 1 }
    /^(ok   |FAIL )/ {
      suite = substr($0, 6)
      sub(/[\/ :].*/, "", suite)
      if (suite in want) {
        rows[suite]++
      } else {
        print "FAIL selftest-only: row outside --only: " $0
        bad = 1
      }
    }
    END {
      for (i = 1; i <= n; i++) {
        if (!(names[i] in rows)) {
          print "FAIL selftest-only: --only " names[i] " ran no rows"
          bad = 1
        }
      }
      exit bad
    }
  ' "$1"
}

# selftest_only_rows (Replikanti/interviewscam#40, ADR-0008 part 4): the
# suite selection. The usage rows run tools/selftest.sh with a bad --only,
# which must exit 2 with the usage line before any tool is fetched; the
# look-alike and zero-width names are written as octal UTF-8 bytes, so the
# case does not depend on the locale. one-suite, two-suites and
# unknown-suite run the real selection end to end on suites whose rows do
# not need CI; the counts come from the fixture directories. The check-*,
# rows-* and suite-* rows run selftest_selection_check, selftest_rows and
# selftest_suite on synthetic runner output.
selftest_only_rows() {
  local so_out so_rc so_bad so_case so_want so_log so_got so_n
  local so_usage='usage: bash tools/selftest.sh [--only SUITE[,SUITE...]]'
  local so_sh="$SELFTEST_ROOT/tools/selftest.sh"
  # so_usage_case <row> <args...>: exit 2, the usage line, no tool fetch.
  so_usage_case() {
    local row="$1"
    shift
    so_out="$(bash "$so_sh" "$@" 2>&1)"
    so_rc=$?
    if [[ $so_rc -eq 2 && $'\n'"$so_out"$'\n' == *$'\n'"$so_usage"$'\n'* \
        && "$so_out" != *fetch-tools:* && "$so_out" != *" passed, "* ]]; then
      return 0
    fi
    so_bad+=" [$*]: exit $so_rc, output '$so_out';"
    return 1
  }
  for so_case in missing-value empty empty-item duplicate uppercase lookalike \
      zero-width newline unknown-flag twice; do
    so_bad=""
    case "$so_case" in
      missing-value) so_usage_case "$so_case" --only ;;
      empty) so_usage_case "$so_case" --only "" ;;
      empty-item)
        so_usage_case "$so_case" --only tokens,,schema
        so_usage_case "$so_case" --only ,tokens
        so_usage_case "$so_case" --only tokens,
        ;;
      duplicate) so_usage_case "$so_case" --only tokens,tokens ;;
      uppercase)
        so_usage_case "$so_case" --only Tokens
        so_usage_case "$so_case" --only tOkens
        ;;
      # schema with its last a as U+0430 CYRILLIC SMALL LETTER A.
      lookalike) so_usage_case "$so_case" --only "schem"$'\320\260' ;;
      # tokens with U+200B ZERO WIDTH SPACE after tok.
      zero-width) so_usage_case "$so_case" --only "tok"$'\342\200\213'"ens" ;;
      # A newline would end the comma split early and drop schema.
      newline) so_usage_case "$so_case" --only $'tokens\nschema' ;;
      unknown-flag)
        so_usage_case "$so_case" --bogus
        so_usage_case "$so_case" --only=tokens
        so_usage_case "$so_case" tokens
        ;;
      twice) so_usage_case "$so_case" --only tokens --only schema ;;
    esac
    if [[ -z "$so_bad" ]]; then
      echo "ok   selftest-only/usage-$so_case (exit 2 with the usage line, no tool fetched)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL selftest-only/usage-$so_case:$so_bad"
      n_failed=$((n_failed + 1))
    fi
  done

  # one-suite and two-suites: exit 0, only rows of the selected suites,
  # one per fixture directory, and the selection's summary line.
  for so_case in tokens tokens,schema; do
    so_out="$(bash "$so_sh" --only "$so_case" 2>&1)"
    so_rc=$?
    so_n=0
    so_bad=""
    for so_want in ${so_case//,/ }; do
      so_n=$((so_n + $(find "$FIXTURES/$so_want" -mindepth 1 -maxdepth 1 -type d | wc -l)))
    done
    so_want="selftest (only $so_case): $so_n passed, 0 failed, html fixtures run: 0 of 0, reflow fixtures run: 0 of 0"
    so_got="$(grep -E '^(ok   |FAIL )' <<<"$so_out" | grep -cvE "^ok   (${so_case//,/|})/")"
    if [[ $so_rc -ne 0 ]]; then
      so_bad="exit $so_rc"
    elif [[ "$so_got" != 0 ]]; then
      so_bad="$so_got rows that are not an ok row of $so_case"
    elif [[ "$(grep -cE '^ok   ' <<<"$so_out")" != "$so_n" ]]; then
      so_bad="$(grep -cE '^ok   ' <<<"$so_out") ok rows, want $so_n"
    elif [[ "$(tail -n 1 <<<"$so_out")" != "$so_want" ]]; then
      so_bad="last line '$(tail -n 1 <<<"$so_out")', want '$so_want'"
    fi
    so_case="${so_case//,/-and-}"
    [[ $so_case == tokens ]] && so_case=one-suite || so_case=two-suites
    if [[ -z "$so_bad" ]]; then
      echo "ok   selftest-only/$so_case ($so_n rows, exit 0)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL selftest-only/$so_case: $so_bad; output:"
      printf '%s\n' "$so_out" | sed 's/^/     | /'
      n_failed=$((n_failed + 1))
    fi
  done

  # unknown-suite: a name no row carries runs nothing and exits 2.
  so_out="$(bash "$so_sh" --only no-such-suite 2>&1)"
  so_rc=$?
  if [[ $so_rc -eq 2 ]] \
      && grep -qxF 'FAIL selftest-only: --only no-such-suite ran no rows' <<<"$so_out" \
      && ! grep -qE '^(ok   |FAIL [^s])' <<<"$so_out"; then
    echo "ok   selftest-only/unknown-suite (exit 2: --only no-such-suite ran no rows)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/unknown-suite: exit $so_rc; output:"
    printf '%s\n' "$so_out" | sed 's/^/     | /'
    n_failed=$((n_failed + 1))
  fi

  # so_with <suites> <command...>: run the command with SELFTEST_ONLY set
  # to the comma-separated suites (none: empty) and its own counters.
  so_with() {
    local n_passed=0 n_failed=0
    local -a SELFTEST_ONLY
    IFS=, read -ra SELFTEST_ONLY <<<"$1"
    shift
    "$@"
  }

  # The check on synthetic logs: <row> <suites> <want rc> <want output>
  # <log lines...>.
  so_log="$(mktemp)"
  so_check_case() {
    local row="$1" suites="$2" want_rc="$3" want="$4" got rc
    shift 4
    printf '%s\n' "$@" >"$so_log"
    got="$(so_with "$suites" selftest_selection_check "$so_log" 2>&1)"
    rc=$?
    if [[ $rc -eq $want_rc && "$got" == "$want" ]]; then
      echo "ok   selftest-only/$row (exit $rc)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL selftest-only/$row: exit $rc, want $want_rc; got:"
      printf '%s\n' "$got" | sed 's/^/     | /'
      echo "     | want:"
      printf '%s\n' "$want" | sed 's/^/     | /'
      n_failed=$((n_failed + 1))
    fi
  }
  so_check_case check-outside tokens 1 \
    $'FAIL selftest-only: row outside --only: ok   render/pass-b\nFAIL selftest-only: row outside --only: FAIL render/fail-c: expected a failure' \
    'ok   tokens/pass-a' 'ok   render/pass-b' 'FAIL render/fail-c: expected a failure'
  so_check_case check-no-rows tokens,schema 1 \
    'FAIL selftest-only: --only schema ran no rows' \
    'ok   tokens/pass-a' 'FAIL tokens/fail-b: failed'
  so_check_case check-global-lines tokens 0 '' \
    'ok   tokens/pass-a' 'FAIL: only 1 of 2 html fixtures ran in CI' 'FAIL: no html fixtures found' \
    'NOT RUN html/pass-x (CI only)' 'NOT RUN: HTML validation was NOT run locally.' \
    '     | ok   render/pass-b' '     | FAIL render/fail-c: x' 'selftest: 1 passed'
  so_check_case check-prefix-boundary render 1 \
    $'FAIL selftest-only: row outside --only: ok   render-report/x (y)\nFAIL selftest-only: row outside --only: FAIL render-search-count: 1 of 4\nFAIL selftest-only: row outside --only: ok   renderx' \
    'ok   render/pass-a' 'ok   render-report/x (y)' 'FAIL render-search-count: 1 of 4' \
    'ok   renderx' 'FAIL render: the runner did not finish' 'ok   render (z)'
  so_check_case check-prefix-boundary-longer render-report,site-intake-expect,site-built-pins-missing-stem 1 \
    $'FAIL selftest-only: row outside --only: ok   render/pass-a\nFAIL selftest-only: row outside --only: ok   site-intake/x' \
    'ok   render/pass-a' 'ok   render-report/x' 'ok   site-intake-expect (a wrong expect)' \
    'FAIL site-built-pins-missing-stem: x' 'ok   site-intake/x'

  # rows-*: selftest_rows prints and counts the rows of the selected suites
  # (with their detail lines when asked), and every line as the sed it
  # replaces when nothing is selected.
  so_rows_counts() {
    selftest_rows "$so_log" "$1"
    echo "counts $n_passed $n_failed"
  }
  printf '%s\n' 'ok   guard-public/a' '     | public detail' 'FAIL guard-wf/b: x' \
    '     | wf detail' 'other line' 'ok   guard-wf/table (1 rows)' 'FAIL guard-public/c: y' >"$so_log"
  for so_case in all-details all-rows guard-wf; do
    case "$so_case" in
      all-details) so_got="$(so_with "" so_rows_counts details)" ;;
      all-rows) so_got="$(so_with "" so_rows_counts "")" ;;
      guard-wf) so_got="$(so_with guard-wf so_rows_counts details)" ;;
    esac
    case "$so_case" in
      all-details) so_want="$(sed -n '/^ok   \|^FAIL /p; /^     | /p' "$so_log")"$'\ncounts 2 2' ;;
      all-rows) so_want="$(sed -n '/^ok   \|^FAIL /p' "$so_log")"$'\ncounts 2 2' ;;
      guard-wf) so_want=$'FAIL guard-wf/b: x\n     | wf detail\nok   guard-wf/table (1 rows)\ncounts 1 1' ;;
    esac
    if [[ "$so_got" == "$so_want" ]]; then
      echo "ok   selftest-only/rows-$so_case"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL selftest-only/rows-$so_case: got:"
      printf '%s\n' "$so_got" | sed 's/^/     | /'
      n_failed=$((n_failed + 1))
    fi
  done
  rm -f "$so_log"

  # suite-fallback: selftest_suite names the suite of a line a block prints
  # outside its runner's rows: the block's own name without --only or when
  # selected, else the first selected of the others, else its own name.
  so_bad=""
  for so_case in ":guard-public guard-wf:guard-public" "guard-wf:guard-public guard-wf:guard-wf" \
      "guard-public,guard-wf:guard-public guard-wf:guard-public" \
      "pin-extra,pin:records-mode pin pin-extra:pin" "tokens:guard-public guard-wf:guard-public"; do
    IFS=: read -r so_want so_n so_got <<<"$so_case"
    # shellcheck disable=SC2086 # so_n is a list of suite names
    so_out="$(so_with "$so_want" selftest_suite $so_n)"
    [[ "$so_out" == "$so_got" ]] || so_bad+=" --only '$so_want' and $so_n: '$so_out', want '$so_got';"
  done
  if [[ -z "$so_bad" ]]; then
    echo "ok   selftest-only/suite-fallback (5 selections)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/suite-fallback:$so_bad"
    n_failed=$((n_failed + 1))
  fi

  # partner-*: the "runner did not finish" checks of the two-suite runners
  # count only the selected suites (selftest_ok_count), so a failure only
  # the partner suite sees leaves the selected one green, as guard-public
  # and guard-wf do. Each row runs the real selftest_blocks under a
  # selection, with stubs in place of the runners (pin_runner, and
  # intake_coverage with site_intake_runner), so the rows hold the call
  # sites themselves. The stubs print one partner row failed (pin-extra/
  # sha-form, the row a widened PIN_SHA fails; the render-intake coverage
  # line): under --only pin and --only site-intake the selected rows pass
  # and nothing fails; under --only pin,pin-extra the failed row and the
  # finished check both fail, as in a full run.
  # so_partner_blocks <suites>: selftest_blocks under that selection with
  # the stub runners, its rows cut to their names, then its counters. Only
  # ever called in $(...): the stubs replace the real runners for good.
  so_partner_blocks() {
    # shellcheck disable=SC2317,SC2329 # selftest_blocks calls the stubs
    pin_runner() {
      local i
      echo 'ok   pin/pass-a'
      echo 'FAIL pin-extra/sha-form 40 chars abcdef: exit 1'
      for i in $(seq 1 13); do
        echo "ok   pin-extra/x-$i"
      done
      echo 'ok   pin/cases (1 cases)'
    }
    # shellcheck disable=SC2317,SC2329 # selftest_blocks calls the stubs
    site_intake_runner() { echo 'ok   site-intake/table (1 rows)'; }
    # shellcheck disable=SC2317,SC2329 # selftest_blocks calls the stubs
    intake_coverage() {
      if [[ $# -ge 4 ]]; then
        echo "FAIL $kind-intake/coverage: 1 member(s) without a row: $4"
      else
        echo 'FAIL render-intake/coverage: 1 member(s) without a row: x'
        echo 'ok   site-intake/coverage (3 member rows)'
      fi
    }
    local n_passed=0 n_failed=0 html_total=0 html_run=0 reflow_total=0 reflow_run=0 out
    local -a SELFTEST_ONLY
    IFS=, read -ra SELFTEST_ONLY <<<"$1"
    out="$(mktemp)"
    selftest_blocks >"$out.rows"
    grep -E '^(ok   |FAIL )' "$out.rows" | sed -E 's/^(ok   |FAIL )([^ :]*).*/\1\2/'
    rm -f "$out" "$out.rows"
    echo "counts $n_passed $n_failed"
  }
  so_partner_case() {
    local row="$1" suites="$2" want="$3" got
    got="$(so_partner_blocks "$suites")"
    if [[ "$got" == "$want" ]]; then
      echo "ok   selftest-only/$row (${got##*$'\n'})"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL selftest-only/$row: got:"
      printf '%s\n' "$got" | sed 's/^/     | /'
      echo "     | want:"
      printf '%s\n' "$want" | sed 's/^/     | /'
      n_failed=$((n_failed + 1))
    fi
  }
  so_partner_case partner-pin pin \
    $'ok   pin/pass-a\nok   pin/cases\ncounts 2 0'
  so_partner_case partner-intake site-intake \
    $'ok   site-intake/table\nok   site-intake/coverage\nok   site-intake/coverage-fails-on-missing-row\nok   site-intake/coverage-fails-on-missing-row\nok   site-intake/coverage-fails-on-missing-row\nok   site-intake/coverage-fails-on-missing-row\ncounts 6 0'
  so_partner_case partner-both pin,pin-extra \
    "$(printf '%s\n' 'ok   pin/pass-a' 'FAIL pin-extra/sha-form'; for so_n in $(seq 1 13); do echo "ok   pin-extra/x-$so_n"; done; printf '%s\n' 'ok   pin/cases' 'FAIL pin/extra')"$'\ncounts 15 2'

  # streams-rows: under --only the rows reach stdout as they finish, and a
  # run stopped with TERM removes its temp files. A nested --only tokens
  # run writes to a file with its own TMPDIR and is stopped once its first
  # row is there: it must have printed fewer rows than there are tokens
  # cases (rows held back to the end arrive all at once), no summary line,
  # exit 143 (death by TERM), and leave its TMPDIR empty. 1200 polls of
  # 0.1 s bound the wait for the first row (fetch-tools runs before it).
  # The run has its own session (setsid), and after it ends whatever is
  # left of that session is killed, so a run that hung before its traps
  # leaves no child behind that could hold this run's descriptors.
  local so_tmp so_pid so_i so_seen=0
  so_tmp="$(mktemp -d)"
  mkdir "$so_tmp/tmp"
  TMPDIR="$so_tmp/tmp" setsid bash "$so_sh" --only tokens >"$so_tmp/out" 2>&1 &
  so_pid=$!
  for (( so_i = 0; so_i < 1200; so_i++ )); do
    so_seen="$(grep -c '^ok   tokens/' "$so_tmp/out")"
    [[ "$so_seen" -gt 0 ]] && break
    kill -0 "$so_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -TERM "$so_pid" 2>/dev/null
  wait "$so_pid"
  so_rc=$?
  kill -KILL -- "-$so_pid" 2>/dev/null
  so_n="$(find "$FIXTURES/tokens" -mindepth 1 -maxdepth 1 -type d | wc -l)"
  so_bad=""
  if [[ "$so_seen" -lt 1 || "$so_seen" -ge "$so_n" ]]; then
    so_bad="$so_seen of $so_n rows printed when the first was seen"
  elif [[ $so_rc -ne 143 ]]; then
    so_bad="exit $so_rc after TERM, want 143"
  elif grep -q '^selftest (only' "$so_tmp/out"; then
    so_bad="the summary line was printed, so the run had finished"
  elif [[ -n "$(find "$so_tmp/tmp" -mindepth 1)" ]]; then
    so_bad="temp files left: $(find "$so_tmp/tmp" -mindepth 1 | tr '\n' ' ')"
  fi
  if [[ -z "$so_bad" ]]; then
    echo "ok   selftest-only/streams-rows ($so_seen of $so_n rows out before TERM, exit 143, no temp file left)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/streams-rows: $so_bad; output:"
    sed 's/^/     | /' "$so_tmp/out"
    n_failed=$((n_failed + 1))
  fi
  rm -rf "$so_tmp"

  # signal-stops-parent: the signal trap raises the signal again after its
  # cleanup, so a calling bash script stops as it did before the trap. A
  # parent script runs a nested --only tokens run and then echoes a line;
  # it starts in its own session with SIGINT at its default action (a
  # background job of this shell would ignore it, and an ignored signal
  # cannot be trapped), and once the first row is there SIGINT goes to the
  # whole process group, as Ctrl-C sends it. The parent must die of SIGINT
  # (130 to a shell), never reach its echo, and the nested run must print
  # no summary and leave its TMPDIR empty. A trap that ends with exit 130
  # lets the parent go on to its echo.
  so_tmp="$(mktemp -d)"
  mkdir "$so_tmp/tmp"
  # shellcheck disable=SC2016 # the parent script expands them
  printf 'bash "$1" --only tokens\necho "parent continued rc=$?"\n' >"$so_tmp/parent.sh"
  so_got="$(python3 -I -B - "$so_tmp" "$so_sh" <<'PY' 2>&1
import os
import signal
import subprocess
import sys
import time

tmp, child = sys.argv[1], sys.argv[2]
out_path = os.path.join(tmp, "out")
env = dict(os.environ, TMPDIR=os.path.join(tmp, "tmp"))


def default_sigint():
    signal.signal(signal.SIGINT, signal.SIG_DFL)


with open(out_path, "wb") as out:
    proc = subprocess.Popen(["bash", os.path.join(tmp, "parent.sh"), child], stdout=out,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True,
                            preexec_fn=default_sigint)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and proc.poll() is None:
        with open(out_path, "rb") as seen:
            if b"\nok   tokens/" in b"\n" + seen.read():
                break
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        rc = proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        rc = "timeout"
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
print(f"parent: {rc}")
PY
)"
  so_bad=""
  if [[ "$so_got" != "parent: -2" ]]; then
    so_bad="the parent ended with '$so_got', want death by SIGINT (parent: -2)"
  elif ! grep -q '^ok   tokens/' "$so_tmp/out"; then
    so_bad="no row before the signal"
  elif grep -q '^parent continued' "$so_tmp/out"; then
    so_bad="the parent went on after the nested run"
  elif grep -q '^selftest (only' "$so_tmp/out"; then
    so_bad="the summary line was printed, so the run had finished"
  elif [[ -n "$(find "$so_tmp/tmp" -mindepth 1)" ]]; then
    so_bad="temp files left: $(find "$so_tmp/tmp" -mindepth 1 | tr '\n' ' ')"
  fi
  if [[ -z "$so_bad" ]]; then
    echo "ok   selftest-only/signal-stops-parent (SIGINT to the group: the parent died of it, no line after the nested run, no temp file left)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/signal-stops-parent: $so_bad; output:"
    sed 's/^/     | /' "$so_tmp/out"
    n_failed=$((n_failed + 1))
  fi
  rm -rf "$so_tmp"

  # pipe-closed: a reader of stdout that closes early (| head -n 1) ends an
  # --only run with SIGPIPE, and the temp directory goes with it. The real
  # selftest_main runs in its own bash with selftest_blocks replaced by
  # 50000 rows (about 700 KB, far past the 64 KiB of the pipe and of the
  # FIFO). Python starts it under a 60 s timeout with SIGPIPE at its
  # default action (subprocess restores it; the CI runner starts jobs with
  # SIGPIPE ignored, which bash can neither trap nor reset, and a write then
  # fails with EPIPE instead), reads up to the first row (the fetch-tools
  # lines come before it) and closes its end, so tee dies at its next write
  # and the rest must not block on the FIFO. The run must die of SIGPIPE
  # and leave its TMPDIR empty. A run that stays a reader of its own FIFO
  # blocks there until the 60 s bound (124), and a run without the PIPE
  # trap dies with its temp directory left behind.
  so_tmp="$(mktemp -d)"
  mkdir "$so_tmp/tmp"
  so_got="$(python3 -I -B - "$so_tmp" "$so_sh" <<'PY' 2>&1
import os
import subprocess
import sys

tmp, child = sys.argv[1], sys.argv[2]
script = ('source "$1"\n'
          'selftest_blocks() { yes "ok   tokens/pass-x" | head -n 50000; }\n'
          'selftest_main --only tokens\n')
env = dict(os.environ, TMPDIR=os.path.join(tmp, "tmp"))
with open(os.path.join(tmp, "err"), "wb") as err:
    proc = subprocess.Popen(["timeout", "60", "bash", "-c", script, "_", child],
                            stdout=subprocess.PIPE, stderr=err, env=env)
    first = b""
    for line in proc.stdout:
        if line.startswith(b"ok   "):
            first = line.rstrip(b"\n")
            break
    proc.stdout.close()
    try:
        rc = proc.wait(timeout=90)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = "timeout"
# timeout passes a death by signal on as its own (-13) or as 128 + 13.
print(f"run: {'SIGPIPE' if rc in (-13, 141) else rc}; first row: {first.decode()}")
PY
)"
  so_bad=""
  if [[ "$so_got" != "run: SIGPIPE; first row: ok   tokens/pass-x" ]]; then
    so_bad="got '$so_got', want death by SIGPIPE after the first row (124 is the 60 s bound)"
  elif [[ -n "$(find "$so_tmp/tmp" -mindepth 1)" ]]; then
    so_bad="temp files left: $(find "$so_tmp/tmp" -mindepth 1 | tr '\n' ' ')"
  fi
  if [[ -z "$so_bad" ]]; then
    echo "ok   selftest-only/pipe-closed (reader gone after the first row: death by SIGPIPE, no temp file left)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/pipe-closed: $so_bad; stderr:"
    sed 's/^/     | /' "$so_tmp/err"
    n_failed=$((n_failed + 1))
  fi
  rm -rf "$so_tmp"

  # term-ignored: the trap stops tee with SIGKILL, so a run started with
  # SIGTERM ignored (which tee inherits) still ends on SIGINT. A nested
  # --only tokens run starts in its own process group with SIGTERM ignored
  # and SIGINT at its default action, and once its first row is there
  # SIGINT goes to the shell alone. It must die of SIGINT within 30 s and
  # leave its TMPDIR empty; a trap that stops tee with SIGTERM waits for
  # it forever.
  so_tmp="$(mktemp -d)"
  mkdir "$so_tmp/tmp"
  so_got="$(python3 -I -B - "$so_tmp" "$so_sh" <<'PY' 2>&1
import os
import signal
import subprocess
import sys
import time

tmp, child = sys.argv[1], sys.argv[2]
out_path = os.path.join(tmp, "out")
env = dict(os.environ, TMPDIR=os.path.join(tmp, "tmp"))


def dispositions():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_DFL)


with open(out_path, "wb") as out:
    proc = subprocess.Popen(["bash", child, "--only", "tokens"], stdout=out,
                            stderr=subprocess.STDOUT, env=env, start_new_session=True,
                            preexec_fn=dispositions)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and proc.poll() is None:
        with open(out_path, "rb") as seen:
            if b"\nok   tokens/" in b"\n" + seen.read():
                break
        time.sleep(0.1)
    try:
        os.kill(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        rc = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        rc = "timeout"
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
print(f"run: {rc}")
PY
)"
  so_bad=""
  if [[ "$so_got" != "run: -2" ]]; then
    so_bad="the run ended with '$so_got', want death by SIGINT (run: -2)"
  elif ! grep -q '^ok   tokens/' "$so_tmp/out"; then
    so_bad="no row before the signal"
  elif [[ -n "$(find "$so_tmp/tmp" -mindepth 1)" ]]; then
    so_bad="temp files left: $(find "$so_tmp/tmp" -mindepth 1 | tr '\n' ' ')"
  fi
  if [[ -z "$so_bad" ]]; then
    echo "ok   selftest-only/term-ignored (SIGTERM ignored, SIGINT: the run died of it, no temp file left)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL selftest-only/term-ignored: $so_bad; output:"
    sed 's/^/     | /' "$so_tmp/out"
    n_failed=$((n_failed + 1))
  fi
  rm -rf "$so_tmp"
}

selftest_main() {
  # Usage errors stop before the work tree is read or a tool is fetched.
  selftest_parse_args "$@" || return 2
  require_work_tree || return 1
  load_pins || return 1
  # Always re-verify: the fixtures must run against the pinned binaries, not
  # whatever is in .tools/ (cheap; the archives are cached).
  bash "$SELFTEST_ROOT/tools/fetch-tools.sh" || return 1

  # The counters and $out are local here and read and written by
  # selftest_blocks (bash scopes dynamically).
  local n_passed=0 n_failed=0 html_total=0 html_run=0 reflow_total=0 reflow_run=0
  local out log fifo violations suites sig rw_fd
  # The signal traps come first, so no temp file exists before them. PIPE
  # too: a reader of stdout that closes early (| head -n 1) ends the run
  # with SIGPIPE, and the temp directory goes with it.
  for sig in HUP INT TERM PIPE; do
    # shellcheck disable=SC2064 # expand now: the signal name is fixed
    trap "selftest_on_signal $sig" "$sig"
  done
  SELFTEST_TMP_DIR="$(mktemp -d)" || return 1
  # shellcheck disable=SC2064 # expand now: the path is fixed
  trap "rm -rf '$SELFTEST_TMP_DIR'" RETURN
  out="$SELFTEST_TMP_DIR/out"
  # Python exits with 120 when it cannot flush stdout at exit (ENOSPC, EDQUOT,
  # ENOMEM or a closed pipe). Probe the temp file first, so a full or
  # over-quota /tmp is named before 20 fixtures fail with empty output.
  if ! { printf 'x' >"$out" && : >"$out"; } 2>/dev/null; then
    echo "FAIL selftest: cannot write $out; the temp file system is full or over its quota ($(df -h "$(dirname "$out")" | awk 'NR==2 {print $1, $5, "used,", $4, "free"}'))"
    return 1
  fi

  if [[ ${#SELFTEST_ONLY[@]} -eq 0 ]]; then
    selftest_blocks
    echo "selftest: $n_passed passed, $n_failed failed, html fixtures run: $html_run of $html_total, reflow fixtures run: $reflow_run of $reflow_total"
    [[ $n_failed -eq 0 ]]
    return
  fi

  # --only (ADR-0008 part 4): the rows stream to stdout as they finish and
  # tee copies them to a log, so a run stopped at a sweep's budget has
  # already printed every row it finished (a FAIL row before a TIMEOUT
  # among them). After the blocks the log is checked: a row of an
  # unselected suite (a block without its guard) or a selected suite
  # without rows fails the run with exit 2. tee is an ordinary background
  # job reading a FIFO, not a process substitution, so waiting for it by
  # its PID works on every bash (a process substitution's PID is waitable
  # only from bash 5.1 on) and the summary never overtakes a row. The
  # shell opens the FIFO read-write first, so tee's open for reading does
  # not block, then opens it write-only (a reader exists, so that does not
  # block either) and closes the read-write descriptor: the shell must not
  # stay a reader of its own FIFO, or a dead tee (stdout's reader closed,
  # | head -n 1) would leave every write blocked on a full FIFO instead of
  # ending the run with SIGPIPE. tee closes its inherited copy, so the
  # shell's close is its end of input.
  log="$SELFTEST_TMP_DIR/log"
  fifo="$SELFTEST_TMP_DIR/fifo"
  mkfifo "$fifo" || return 1
  exec {rw_fd}<>"$fifo"
  tee "$log" <"$fifo" {rw_fd}>&- &
  SELFTEST_TEE_PID=$!
  exec {SELFTEST_TEE_FD}>"$fifo"
  exec {rw_fd}>&-
  selftest_blocks >&"$SELFTEST_TEE_FD"
  exec {SELFTEST_TEE_FD}>&-
  SELFTEST_TEE_FD=""
  wait "$SELFTEST_TEE_PID"
  SELFTEST_TEE_PID=""
  violations="$(selftest_selection_check "$log")"
  if [[ -n "$violations" ]]; then
    printf '%s\n' "$violations"
    n_failed=$((n_failed + $(grep -c '' <<<"$violations")))
  fi
  suites="$(IFS=,; echo "${SELFTEST_ONLY[*]}")"
  echo "selftest (only $suites): $n_passed passed, $n_failed failed, html fixtures run: $html_run of $html_total, reflow fixtures run: $reflow_run of $reflow_total"
  [[ -z "$violations" ]] || return 2
  [[ $n_failed -eq 0 ]]
}

# selftest_blocks: every fixture case and every block of rows, each block
# guarded by selftest_wants with the suite its rows print (a runner whose
# rows belong to two suites prints them through selftest_rows). Called by
# selftest_main, whose counters and $out it updates.
selftest_blocks() {
  local dir check name kind rc expect leak_fixtures feed_mode search_mode pins_mode inputs_root
  for dir in "$FIXTURES"/*/*/; do
    dir="${dir%/}"
    # Parameter expansion, not basename and dirname: two forks per case
    # cost about 10 s over the cases even when --only skips them all.
    check="${dir%/*}"
    check="${check##*/}"
    selftest_wants "$check" || continue
    name="${dir##*/}"
    case "$name" in
      pass-*) kind=pass ;;
      fail-*) kind=fail ;;
      *)
        echo "FAIL $check/$name: fixture name must start with pass- or fail-"
        n_failed=$((n_failed + 1))
        continue
        ;;
    esac

    case "$check" in
      html)
        html_total=$((html_total + 1))
        if ! in_github_actions; then
          echo "NOT RUN $check/$name (CI only)"
          continue
        fi
        html_run=$((html_run + 1))
        html_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      reflow)
        # <dir> is the built tree itself: its HTML pages are loaded at
        # 320 CSS px.
        reflow_total=$((reflow_total + 1))
        if ! in_github_actions; then
          echo "NOT RUN $check/$name (CI only)"
          continue
        fi
        reflow_run=$((reflow_run + 1))
        search_mode=no-search
        [[ -f "$dir/search.txt" ]] && search_mode=""
        reflow_check "$dir" "$search_mode" >"$out" 2>&1
        rc=$?
        ;;
      tokens)
        # <dir> stands in for the repo root: data/tokens.toml plus the
        # assets/, layouts/, static/ and hugo.toml the colour scan reads.
        tokens_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      links)
        links_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      literals)
        # <dir> stands in for the repo root: the layouts/, assets/ and
        # static/ the copy check reads.
        literals_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      fixture-inputs)
        # <dir> stands in for the repo root, whose top-level entries the
        # fixture build classifies; it is read from a copy without its
        # expect.txt, which no repo root has.
        inputs_root="$(mktemp -d)"
        if cp -R "$dir/." "$inputs_root/" && rm -f "$inputs_root/expect.txt"; then
          fixture_inputs "$inputs_root" >"$out" 2>&1
          rc=$?
        else
          echo "copying the fixture failed" >"$out"
          rc=2
        fi
        rm -rf "$inputs_root"
        ;;
      records)
        # Records fixtures run against the real schemas in schema/.
        records_check "$dir" "$SELFTEST_ROOT/schema" >"$out" 2>&1
        rc=$?
        ;;
      schema)
        # Schema fixtures bring their own schema/ to test the validator.
        records_check "$dir" "$dir/schema" >"$out" 2>&1
        rc=$?
        ;;
      site)
        # <dir>/hugo.toml holds params.csp, <dir>/content the records whose
        # artifacts must not appear live in the built tree <dir>/public.
        # The built pins (M4 PR 3 fix round 5) run only in a case with a
        # built-pins.txt: every other case's files are hand-made, no build.
        pins_mode=no-built-pins
        [[ -f "$dir/built-pins.txt" ]] && pins_mode=""
        site_check "$dir" "$SELFTEST_ROOT/schema" "$dir/public" "$pins_mode" >"$out" 2>&1
        rc=$?
        ;;
      render)
        # Laid out like the site fixtures: <dir>/content holds the records,
        # <dir>/public the hand-written built pages that pin the markup
        # contract the record templates implement (ADR-0004). An optional
        # <dir>/fixtures stands in for tests/fixtures in the fixture-leak
        # check of the production run. The feed rules (11 to 13) run only
        # in a case with a feed.txt, which holds a public/feed.json and a
        # public/data-feed/ page (or proves one missing), and the search
        # rules (15 and 16) only in a case with a search.txt, which holds a
        # public/a-z/ page, the Home search form and its hidden result
        # sections: the other cases pin
        # the page contract alone, as both builds of check.sh always run
        # the feed and search rules.
        leak_fixtures=""
        [[ -d "$dir/fixtures" ]] && leak_fixtures="$dir/fixtures"
        feed_mode=no-feed
        [[ -f "$dir/feed.txt" ]] && feed_mode=""
        search_mode=no-search
        [[ -f "$dir/search.txt" ]] && search_mode=""
        # Rule 17 (the exact trees of a report page, M4 PR 4) only in a
        # case with a report-pins.txt, which holds real built report pages:
        # the other cases' hand-made report pages predate those templates.
        pins_mode=no-report-pins
        [[ -f "$dir/report-pins.txt" ]] && pins_mode=""
        # Rule 18 (the intake forms, M5b PR 3) only in a case with an
        # intake.txt, which holds the real built intake and result pages.
        intake_mode=no-intake
        [[ -f "$dir/intake.txt" ]] && intake_mode=""
        render_check "$dir" "$SELFTEST_ROOT/schema" "$dir/public" "$leak_fixtures" \
          "$feed_mode" "$search_mode" "$pins_mode" "$intake_mode" >"$out" 2>&1
        rc=$?
        ;;
      lighthouse)
        # Synthetic reports holding only the fields the score gate reads.
        sitecheck lighthouse --reports "$dir" \
          --version "$LIGHTHOUSE_FIXTURE_VERSION" >"$out" 2>&1
        rc=$?
        ;;
      tree)
        # <dir>/lock.json is a resolved tree (the guard rejects the real
        # lockfile name) and <dir>/pin.txt the digest the case pins.
        sitecheck tree-digest "$dir/lock.json" \
          --expect "$(head -n 1 "$dir/pin.txt" 2>/dev/null)" >"$out" 2>&1
        rc=$?
        ;;
      records-repo)
        # <dir> is a fake records repo (ADR-0007 part 5): run in its own git
        # work tree against a throwaway public checkout, with the fixture
        # pin of its workflows set to that checkout's HEAD.
        records_repo_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
          "$SELFTEST_ROOT/tools/pins.env" case "$dir" >"$out" 2>&1
        rc=$?
        ;;
      pin)
        # Run as one batch below (pin_runner): every case in one process.
        continue
        ;;
      guard)
        # <dir> stands in for the repo root. An optional env.txt holds
        # HUGO_* overrides for the run, to prove the guard reads the
        # effective Hugo config.
        if ! guard_env "$dir"; then
          echo "FAIL $check/$name: env.txt may only hold HUGO_<NAME>=<value> lines"
          n_failed=$((n_failed + 1))
          continue
        fi
        (
          for line in "${GUARD_ENV[@]}"; do
            export "${line?}"
          done
          guard_check "$dir"
        ) >"$out" 2>&1
        rc=$?
        ;;
      *)
        echo "FAIL $check/$name: no check is mapped to fixture directory '$check'"
        n_failed=$((n_failed + 1))
        continue
        ;;
    esac

    # Exit 120 is Python's "could not flush stdout at exit": the output file
    # is on a full or over-quota filesystem (or the pipe closed). The
    # message itself went to the same failing file ($out, 2>&1), so name the
    # cause here instead of printing an empty output.
    if [[ $rc -eq 120 ]]; then
      echo "FAIL $check/$name: exit 120, the check could not write its output to $out ($(df -h "$(dirname "$out")" | awk 'NR==2 {print $1, $5, "used,", $4, "free"}')); the temp file system is full or over its quota, or the output pipe closed; free space and rerun"
      n_failed=$((n_failed + 1))
      continue
    fi

    if [[ "$kind" == pass ]]; then
      expect=""
      [[ -s "$dir/expect.txt" ]] && expect="$(head -n 1 "$dir/expect.txt")"
      if [[ $rc -eq 0 && -n "$expect" ]] && ! grep -qF -- "$expect" "$out"; then
        echo "FAIL $check/$name: passed but without the expected output '$expect'; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      elif [[ $rc -eq 0 ]]; then
        echo "ok   $check/$name${expect:+ (passed with: $expect)}"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL $check/$name: expected exit 0, got $rc; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
      continue
    fi

    if [[ ! -s "$dir/expect.txt" ]]; then
      echo "FAIL $check/$name: missing or empty expect.txt"
      n_failed=$((n_failed + 1))
      continue
    fi
    expect="$(head -n 1 "$dir/expect.txt")"
    if [[ $rc -eq 0 ]]; then
      echo "FAIL $check/$name: expected a failure, the check passed; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qF -- "$expect" "$out"; then
      echo "FAIL $check/$name: failed (exit $rc) but without the expected reason '$expect'; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   $check/$name (failed as expected: $expect)"
      n_passed=$((n_passed + 1))
    fi
  done

  if selftest_wants wiring; then
    # Wiring: check_main must run the production render step, and that step
    # must run the fixture-leak check (--fixtures tests/fixtures), which no
    # fixture can prove. declare -f prints check_main without comments, so a
    # commented-out or deleted step line is missing; a stub sitecheck in a
    # subshell prints the arguments step_render passes, so dropping the flag
    # turns the self-test red too.
    local render_args
    render_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render)"
    if ! grep -qE '^ *run_step "render \(D6, D7, D10, structured data\)" step_render;?$' <<<"$(declare -f check_main)"; then
      echo "FAIL wiring/render-step: check_main in tools/check.sh does not run" \
        "the production render step (run_step \"render (...)\" step_render)"
      n_failed=$((n_failed + 1))
    elif awk -v want="$CHECK_ROOT/tests/fixtures" \
        'prev == "--fixtures" && $0 == want { found = 1 } { prev = $0 } END { exit !found }' \
        <<<"$render_args"; then
      echo "ok   wiring/render-fixture-leak (check_main runs step_render, which passes --fixtures tests/fixtures)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/render-fixture-leak: step_render in tools/check.sh does not pass" \
        "--fixtures \"\$CHECK_ROOT/tests/fixtures\" to sitecheck render (the fixture-leak check)"
      n_failed=$((n_failed + 1))
    fi

    # Wiring: both builds run the feed rules (render rules 11 to 13): neither
    # step_render nor step_render_fixtures, run against a stub sitecheck,
    # passes --no-feed, and check_main runs the fixture-build render step.
    local feed_args
    feed_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render; step_render_fixtures)"
    if ! grep -qE '^ *run_step "render \(fixture build\)" step_render_fixtures;?$' <<<"$(declare -f check_main)"; then
      echo "FAIL wiring/render-feed-rules: check_main in tools/check.sh does not run" \
        "the fixture-build render step (run_step \"render (fixture build)\" step_render_fixtures)"
      n_failed=$((n_failed + 1))
    elif [[ "$(grep -c '^render$' <<<"$feed_args")" != 2 ]] || grep -qx -- '--no-feed' <<<"$feed_args"; then
      echo "FAIL wiring/render-feed-rules: step_render or step_render_fixtures in" \
        "tools/check.sh does not run sitecheck render with the feed rules (it passes --no-feed)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/render-feed-rules (both render steps run rules 11 to 13; no --no-feed)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: both site steps check the built pins (M4 PR 3 fix round 5):
    # check_main runs step_site and step_site_fixtures, and neither, run
    # against a stub sitecheck, passes --no-built-pins.
    local pins_args
    pins_args="$(sitecheck() { printf '%s\n' "$@"; }; step_site; step_site_fixtures)"
    if ! grep -qE '^ *run_step "site \(third-party, CSP, defang\)" step_site;?$' <<<"$(declare -f check_main)" \
        || ! grep -qE '^ *run_step "site \(fixture build\)" step_site_fixtures;?$' <<<"$(declare -f check_main)"; then
      echo "FAIL wiring/site-built-pins: check_main in tools/check.sh does not run" \
        "both site steps (step_site and step_site_fixtures)"
      n_failed=$((n_failed + 1))
    elif [[ "$(grep -c '^site$' <<<"$pins_args")" != 2 ]] \
        || grep -qx -- '--no-built-pins' <<<"$pins_args"; then
      echo "FAIL wiring/site-built-pins: step_site or step_site_fixtures in tools/check.sh" \
        "does not run sitecheck site with the built pins (it passes --no-built-pins)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/site-built-pins (both site steps check the built pins; no --no-built-pins)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: both builds run the search rules (render rules 15 and 16, ADR-0005 part
    # 6), the --no-feed precedent: neither step_render nor
    # step_render_fixtures, run against a stub sitecheck, passes --no-search,
    # and check_main runs both render steps (the two lines above prove the
    # step lines; this one repeats the check so it stands alone).
    local search_args
    search_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render; step_render_fixtures)"
    if ! grep -qE '^ *run_step "render \(D6, D7, D10, structured data\)" step_render;?$' <<<"$(declare -f check_main)" \
        || ! grep -qE '^ *run_step "render \(fixture build\)" step_render_fixtures;?$' <<<"$(declare -f check_main)"; then
      echo "FAIL wiring/render-search-rules: check_main in tools/check.sh does not run" \
        "both render steps (step_render and step_render_fixtures)"
      n_failed=$((n_failed + 1))
    elif [[ "$(grep -c '^render$' <<<"$search_args")" != 2 ]] \
        || grep -qx -- '--no-search' <<<"$search_args"; then
      echo "FAIL wiring/render-search-rules: step_render or step_render_fixtures in" \
        "tools/check.sh does not run sitecheck render with the search rules (it passes --no-search)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/render-search-rules (both render steps run rules 15 and 16; no --no-search)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: both builds run rule 17, the exact trees of the report pages
    # (M4 PR 4): neither render step, run against a stub sitecheck, passes
    # --no-report-pins (check_main runs both steps, proven above).
    local report_pins_args
    report_pins_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render; step_render_fixtures)"
    if [[ "$(grep -c '^render$' <<<"$report_pins_args")" != 2 ]] \
        || grep -qx -- '--no-report-pins' <<<"$report_pins_args"; then
      echo "FAIL wiring/render-report-pins: step_render or step_render_fixtures in" \
        "tools/check.sh does not run sitecheck render with rule 17 (it passes --no-report-pins)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/render-report-pins (both render steps run rule 17; no --no-report-pins)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: both builds run rule 18, the intake forms and their result
    # pages (M5b PR 3): neither render step, run against a stub sitecheck,
    # passes --no-intake (check_main runs both steps, proven above).
    local intake_args
    intake_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render; step_render_fixtures)"
    if [[ "$(grep -c '^render$' <<<"$intake_args")" != 2 ]] \
        || grep -qx -- '--no-intake' <<<"$intake_args"; then
      echo "FAIL wiring/render-intake-rules: step_render or step_render_fixtures in" \
        "tools/check.sh does not run sitecheck render with rule 18 (it passes --no-intake)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/render-intake-rules (both render steps run rule 18; no --no-intake)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: both reflow steps run case (8), the search outcome proof (M4 PR
    # 4, ADR-0005 part 6): check_main runs step_reflow, and step_reflow, run
    # against a stub sitecheck and a stub Chrome on PATH, calls sitecheck
    # reflow twice without --no-search.
    local reflow_args reflow_bin
    reflow_bin="$(mktemp -d)"
    printf '#!/bin/sh\nexit 0\n' >"$reflow_bin/google-chrome"
    chmod +x "$reflow_bin/google-chrome"
    reflow_args="$(sitecheck() { printf '%s\n' "$@"; }; PATH="$reflow_bin:$PATH" step_reflow)"
    rm -rf "$reflow_bin"
    if ! grep -qE '^ *run_step "reflow' <<<"$(declare -f check_main)" \
        || ! grep -q 'step_reflow' <<<"$(declare -f check_main)"; then
      echo "FAIL wiring/reflow-search-case: check_main in tools/check.sh does not run step_reflow"
      n_failed=$((n_failed + 1))
    elif [[ "$(grep -c '^reflow$' <<<"$reflow_args")" != 2 ]] \
        || grep -qx -- '--no-search' <<<"$reflow_args"; then
      echo "FAIL wiring/reflow-search-case: step_reflow in tools/check.sh does not run" \
        "sitecheck reflow on both trees with case (8) (it passes --no-search)"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/reflow-search-case (both reflow steps run case (8); no --no-search)"
      n_passed=$((n_passed + 1))
    fi

    # Wiring: sitecheck takes no abbreviated option (allow_abbrev=False on
    # every parser), so the grep for --no-feed above sees every form that
    # switches the feed rules off: argparse would read --no or --no-f as
    # --no-feed (M3 PR 8 review 2). Two halves. The parsers come from the
    # code (review2 3): the tree build_parser returns is walked, every long
    # option of every parser (--help included, so no parser is skipped) is
    # given cut by one character as `--opt=x` with its required flags off,
    # and each must stay an unrecognized argument; and every
    # ArgumentParser(...) and add_parser(...) call in tools/sitecheck.py,
    # inside build_parser or not, must pass allow_abbrev=False. Then the real
    # command line: render --no on a feed case, reflow --launch (for
    # --launch-timeout) and the top-level --he (for --help, exit 0) must each
    # be a usage error, exit 2. -B as above.
    local abbrev_case abbrev_rc abbrev_bad="" abbrev_tree=""
    local abbrev_dir="$FIXTURES/render/fail-feed-missing"
    python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import argparse
import ast
import contextlib
import importlib.util
import io
import sys

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)


def walk(parser, name):
    yield name, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub_name, sub in action.choices.items():
                yield from walk(sub, f"{name} {sub_name}")


bad, parsers, options = [], 0, 0
for name, parser in walk(sitecheck.build_parser(), "sitecheck"):
    parsers += 1
    for action in parser._actions:
        action.required = False  # only the abbreviation can fail the parse
    for option in sorted({o for a in parser._actions for o in a.option_strings
                          if o.startswith("--")}):
        options += 1
        arg = option[:-1] + "=x"
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                extras = parser.parse_known_args([arg])[1]
        except SystemExit:
            extras = None
        if extras != [arg]:
            bad.append(f"{name} {arg} (read as {option})")

calls = 0
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
for item in ast.walk(tree):
    if not isinstance(item, ast.Call):
        continue
    func = item.func
    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    if called not in ("ArgumentParser", "add_parser"):
        continue
    calls += 1
    if not any(k.arg == "allow_abbrev" and isinstance(k.value, ast.Constant)
               and k.value.value is False for k in item.keywords):
        bad.append(f"{called}(...) at tools/sitecheck.py:{item.lineno} "
                   "without allow_abbrev=False")
if parsers < 2 or calls < parsers:
    bad.append(f"walked {parsers} parsers, found {calls} parser calls")
for line in bad:
    print(f"bad: {line}")
print(f"tree: {parsers} parsers, {options} long options, {calls} parser calls")
PY
    abbrev_tree="$(sed -n 's/^tree: //p' "$out")"
    if grep -q '^bad: ' "$out" || [[ -z "$abbrev_tree" ]]; then
      abbrev_bad+=" $(grep '^bad: ' "$out" | sed 's/^bad: //' | paste -sd ';' -)"
      [[ -n "$abbrev_tree" ]] || abbrev_bad+=" (the tree walk did not finish: $(tail -n 1 "$out"))"
    fi
    for abbrev_case in render reflow top; do
      case "$abbrev_case" in
        render) sitecheck render --records "$abbrev_dir" --schemas "$SELFTEST_ROOT/schema" \
          --no "$abbrev_dir/public" >"$out" 2>&1 ;;
        reflow) sitecheck reflow --chrome /nonexistent --launch 1 "$abbrev_dir/public" \
          >"$out" 2>&1 ;;
        top) sitecheck --he >"$out" 2>&1 ;;
      esac
      abbrev_rc=$?
      if [[ $abbrev_rc -ne 2 ]] || { [[ $abbrev_case != top ]] \
          && ! grep -qF 'unrecognized arguments: --' "$out"; }; then
        abbrev_bad+=" $abbrev_case (exit $abbrev_rc)"
      fi
    done
    if [[ -z "$abbrev_bad" ]]; then
      echo "ok   wiring/sitecheck-no-abbreviations ($abbrev_tree, none abbreviable;" \
        "render --no, reflow --launch and --he are usage errors)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/sitecheck-no-abbreviations: sitecheck accepted an abbreviated option:$abbrev_bad;" \
        "every argparse parser in tools/sitecheck.py needs allow_abbrev=False"
      n_failed=$((n_failed + 1))
    fi

    # Wiring: check_main runs the worker step (ADR-0006 part 2) on the repo
    # root, which no fixture directory can prove, and worker_check fails on a
    # failed, an erroring and a skipped case, an expected failure, an
    # unexpected success and on a run of none: each branch
    # runs on a temporary root holding one tests/worker/test_x.py.
    # shellcheck disable=SC2016 # the patterns match a literal $CHECK_ROOT
    if grep -qE '^ *run_step "worker \(intake Worker and deploy tool\)" step_worker;?$' <<<"$(declare -f check_main)" \
        && grep -qE '^ *worker_check "\$CHECK_ROOT";?$' <<<"$(declare -f step_worker)"; then
      echo "ok   wiring/worker-step (check_main runs step_worker on the repo root)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/worker-step: check_main in tools/check.sh does not run" \
        "step_worker, or step_worker does not check \"\$CHECK_ROOT\""
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants worker-check; then
    local wk_root wk_case wk_body wk_out wk_rc wk_line
    for wk_case in pass fail error skip xfail xpass none; do
      wk_root="$(mktemp -d)"
      mkdir -p "$wk_root/tests/worker"
      case "$wk_case" in
        pass) wk_body='    def test_a(self): pass' ;;
        fail) wk_body='    def test_a(self): self.fail("x")' ;;
        error) wk_body='    def test_a(self): raise RuntimeError("x")' ;;
        skip) wk_body=$'    def test_a(self): pass\n    def test_b(self): self.skipTest("x")' ;;
        xfail) wk_body=$'    def test_a(self): pass\n    @unittest.expectedFailure\n    def test_b(self): self.fail("x")' ;;
        xpass) wk_body=$'    def test_a(self): pass\n    @unittest.expectedFailure\n    def test_b(self): pass' ;;
        none) wk_body='    pass' ;;
      esac
      printf 'import unittest\nclass T(unittest.TestCase):\n%s\n' "$wk_body" >"$wk_root/tests/worker/test_x.py"
      wk_out="$(worker_check "$wk_root" 2>&1)"
      wk_rc=$?
      rm -rf "$wk_root"
      if [[ "$wk_case" == pass && $wk_rc -eq 0 && "$wk_out" == *"worker checked: 1 cases"* ]] \
          || [[ "$wk_case" != pass && $wk_rc -ne 0 && "$wk_out" != *"worker checked:"* ]]; then
        echo "ok   worker-check/$wk_case (exit $wk_rc)"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL worker-check/$wk_case: exit $wk_rc; output:"
        while IFS= read -r wk_line; do echo "     | $wk_line"; done <<<"$wk_out"
        n_failed=$((n_failed + 1))
      fi
    done
  fi

  if selftest_wants wiring; then
    # Wiring: check_main must run the literals step (ADR-0004 part 13), which
    # the fixtures above prove only through literals_check.
    # shellcheck disable=SC2016 # the patterns match a literal $CHECK_ROOT
    if grep -qE '^ *run_step "literals \(fixed copy only from data/labels\.toml\)" step_literals;?$' <<<"$(declare -f check_main)" \
        && grep -qE '^ *literals_check "\$CHECK_ROOT";?$' <<<"$(declare -f step_literals)"; then
      echo "ok   wiring/literals-step (check_main runs step_literals on the repo root)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/literals-step: check_main in tools/check.sh does not run" \
        "step_literals, or step_literals does not check \"\$CHECK_ROOT\""
      n_failed=$((n_failed + 1))
    fi

    # Wiring: hugo_build passes --panicOnWarning, so a warnf message fails
    # the build instead of rendering; literals exempts warnf arguments only
    # because of it (and bans try, the one function that catches a warning).
    if grep -qE '(^| )--panicOnWarning( |$)' <<<"$(declare -f hugo_build)"; then
      echo "ok   wiring/hugo-build-panic-on-warning (hugo_build passes --panicOnWarning)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/hugo-build-panic-on-warning: hugo_build in tools/check.sh does not" \
        "pass --panicOnWarning, so a warnf message could render (literals exempts it)"
      n_failed=$((n_failed + 1))
    fi

    # Wiring (review3 A2): the build's whole command line and environment.
    # hugo_build is compared with this pinned copy as bash itself prints both
    # (declare -f, so the bash version does not matter and a later
    # redefinition counts), so a flag such as --config or an assignment added
    # to it fails here; check_main builds only through step_build, and the
    # fixture build only through hugo_build. Then the refusal runs: a HUGO*
    # name outside the four tool variables, a valid one and one bash cannot
    # declare, stops hugo_build before Hugo starts, and the four pass.
    # The two names are built at run time: the guard scans this file's text
    # for HUGO* names.
    local hugo_build_want hugo_build_pinned build_out_valid build_out_dot build_out_ok
    local hx=HUGO
    hugo_build_want="$(cat <<'PINNED'
hugo_build() {
  local entry name
  while IFS= read -r -d '' entry; do
    name="${entry%%=*}"
    case "$name" in
      HUGO_BIN | HUGO_VERSION | HUGO_URL | HUGO_SHA256) ;;
      HUGO*)
        echo "hugo_build: the environment holds $name, which Hugo reads as config; only HUGO_BIN, HUGO_VERSION, HUGO_URL and HUGO_SHA256 may be set" >&2
        return 1
        ;;
    esac
  done < <(env -0)
  if [[ ! -x "$HUGO_BIN" ]]; then
    echo "hugo not found at $HUGO_BIN; run tools/fetch-tools.sh" >&2
    return 1
  fi
  "$HUGO_BIN" --source "$1" --gc --minify --panicOnWarning \
    --cleanDestinationDir --destination "$2"
}
step_build() { hugo_build "$CHECK_ROOT" "$CHECK_ROOT/public"; }
PINNED
  )"
    hugo_build_pinned="$(eval "$hugo_build_want"; declare -f hugo_build step_build)"
    build_out_valid="$(export "${hx}xTITLE=x"; HUGO_BIN=/nonexistent hugo_build /nonexistent /nonexistent 2>&1)"
    # shellcheck disable=SC2016 # $1 expands in the child bash
    build_out_dot="$(env "${hx}.TITLE=x" HUGO_BIN=/nonexistent bash -c \
      'source "$1"; hugo_build /nonexistent /nonexistent' _ "$SELFTEST_ROOT/tools/check.sh" 2>&1)"
    # shellcheck disable=SC2016 # $1 expands in the child bash
    build_out_ok="$(env HUGO_VERSION=x HUGO_URL=x HUGO_SHA256=x HUGO_BIN=/nonexistent \
      bash -c 'source "$1"; hugo_build /nonexistent /nonexistent' _ "$SELFTEST_ROOT/tools/check.sh" 2>&1)"
    # shellcheck disable=SC2016 # the patterns match literal variable names
    if [[ "$(declare -f hugo_build step_build)" != "$hugo_build_pinned" ]]; then
      echo "FAIL wiring/hugo-build-pinned: hugo_build or step_build in tools/check.sh differs from the copy pinned in tools/selftest.sh"
      n_failed=$((n_failed + 1))
    elif ! grep -qE '^ *run_step build step_build;?$' <<<"$(declare -f check_main)" \
        || ! grep -qE '^ *hugo_build "\$FIXTURE_SITE" "\$FIXTURE_PUBLIC"( \|\| return 1)?;?$' <<<"$(declare -f step_fixture_build)"; then
      echo "FAIL wiring/hugo-build-pinned: check_main does not build through step_build, or step_fixture_build not through hugo_build"
      n_failed=$((n_failed + 1))
    else
      echo "ok   wiring/hugo-build-pinned (hugo_build and step_build equal the pinned copy; both trees build through them)"
      n_passed=$((n_passed + 1))
    fi
    if [[ "$build_out_valid" == "hugo_build: the environment holds ${hx}xTITLE,"* \
        && "$build_out_dot" == "hugo_build: the environment holds ${hx}.TITLE,"* \
        && "$build_out_ok" == "hugo not found at /nonexistent;"* ]]; then
      echo "ok   wiring/hugo-build-env (${hx}xTITLE and ${hx}.TITLE stop hugo_build; HUGO_BIN, HUGO_VERSION, HUGO_URL and HUGO_SHA256 pass)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/hugo-build-env: got '$build_out_valid', '$build_out_dot' and '$build_out_ok'"
      n_failed=$((n_failed + 1))
    fi

    # Wiring: outside a git work tree check.sh and selftest.sh stop at once
    # with one message (the guard reads git; QA note of review round 2).
    local tree_root tree_out
    tree_root="$(mktemp -d)"
    if tree_out="$(CHECK_ROOT="$tree_root" require_work_tree 2>&1)"; then
      echo "FAIL wiring/work-tree-required: require_work_tree passed outside a git work tree"
      n_failed=$((n_failed + 1))
    elif [[ "$tree_out" == "FAIL: check.sh needs a git work tree (guard reads git)"* ]] \
        && grep -qE '^ *require_work_tree \|\| return 1;?$' <<<"$(declare -f check_main)" \
        && grep -qE '^ *require_work_tree \|\| return 1;?$' <<<"$(declare -f selftest_main)"; then
      echo "ok   wiring/work-tree-required (check_main and selftest_main stop outside a git work tree with one message)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/work-tree-required: require_work_tree printed '$tree_out', or check_main or selftest_main does not call it first"
      n_failed=$((n_failed + 1))
    fi
    rmdir "$tree_root"

    # Wiring (Replikanti/interviewscam#40): check.sh runs the self-test
    # without arguments, so CI never runs a --only selection and every
    # suite stays in the check job. declare -f prints the body without
    # comments; it must be exactly the one command.
    # shellcheck disable=SC2016 # the pattern matches a literal $CHECK_ROOT
    if [[ "$(declare -f step_selftest | sed '1,2d;$d' | sed 's/^ *//')" \
        == 'bash "$CHECK_ROOT/tools/selftest.sh"' ]]; then
      echo "ok   wiring/selftest-no-args (step_selftest runs tools/selftest.sh without arguments)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/selftest-no-args: step_selftest in tools/check.sh is not exactly" \
        "bash \"\$CHECK_ROOT/tools/selftest.sh\"; output of declare -f:"
      declare -f step_selftest | sed 's/^/     | /'
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants literals-members; then
    # literals-members: one fail case per member of every flagging set of
    # sitecheck literals (attributes, CSS properties, banned names, prefixes
    # and methods, the value-position functions) and per rule branch without
    # a case directory, from tests/fixtures/literals/members.tsv, each in its
    # own root through the real cmd_literals, with exactly the findings the
    # row names. literals-members/coverage fails when a flagging set member
    # has no row or a row names a member its set no longer has, so dropping a
    # member turns the self-test red (M3 PR 7 QA). The flagging sets are taken
    # from the code (every LITERALS_*/CSS_* collection not in
    # LITERALS_PASSING_SETS) and their number is pinned; the raw-text end-tag
    # rule's ten names (RAWTEXT_END_TAG, no such prefix) are read from its
    # pattern and need rows too (review8 A3); an empty table or
    # a set left with no rows fails (review2 5); the two coverage-fail lines
    # prove that on a table without rows and on the real table without one
    # set's rows.
    members_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/literals/members.tsv" \
      >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -q '^ok   literals-members/coverage' "$out"; then
      grep -q '^FAIL literals-members/coverage' "$out" || {
        echo "FAIL literals-members: the runner did not finish; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      }
    fi
    local members_table case_name
    members_table="$(mktemp)"
    for case_name in empty-table set-without-rows; do
      if [[ $case_name == empty-table ]]; then
        grep '^#' "$FIXTURES/literals/members.tsv" >"$members_table"
      else
        grep -v $'^LITERALS_TEXT_SHAPERS\t' "$FIXTURES/literals/members.tsv" >"$members_table"
      fi
      LITERALS_MEMBERS_COVERAGE_ONLY=1 members_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
        "$members_table" >"$out" 2>&1
      if grep -q '^FAIL literals-members/coverage' "$out" \
          && ! grep -q '^ok   literals-members/coverage' "$out"; then
        echo "ok   literals-members/coverage-fails-on-$case_name (failed as expected: $(grep -m1 -o 'FAIL literals-members/coverage: .\{0,80\}' "$out"))"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL literals-members/coverage-fails-on-$case_name: the coverage passed on a table it must reject; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
    done
    rm -f "$members_table"
  fi

  if selftest_wants literals-allowlists; then
    # literals-allowlists (review3 A3): the contents of every allowlist are
    # pinned in tests/fixtures/literals/allowlists.tsv; the two fail lines
    # prove the comparison rejects a table with one entry more and one less.
    allowlists_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/literals/allowlists.tsv" \
      >"$out" 2>&1
    if grep -q '^ok   literals-allowlists' "$out"; then
      sed -n '/^ok   /p' "$out"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL literals-allowlists: the allowlists differ from tests/fixtures/literals/allowlists.tsv; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    local allow_table
    allow_table="$(mktemp)"
    for case_name in widening narrowing; do
      if [[ $case_name == widening ]]; then
        grep -v $'^LITERALS_MEMBERS\tTitle$' "$FIXTURES/literals/allowlists.tsv" >"$allow_table"
      else
        { cat "$FIXTURES/literals/allowlists.tsv"; printf 'LITERALS_MEMBERS\tSummary\n'; } >"$allow_table"
      fi
      allowlists_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$allow_table" >"$out" 2>&1
      if grep -q '^FAIL literals-allowlists: ' "$out"; then
        echo "ok   literals-allowlists/fails-on-$case_name (failed as expected: $(grep -m1 -o 'the code differs .\{0,80\}' "$out"))"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL literals-allowlists/fails-on-$case_name: the comparison passed on a table it must reject; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
    done
    rm -f "$allow_table"
  fi

  if selftest_wants literals-deterministic; then
    # literals-deterministic (M3 PR 9 fix round 2, #31 delta review 2): the
    # print sinks once read a dict with a repeated or computed key in hash
    # order, so a run pruned a branch another run kept. The two dict cases
    # run under 8 fixed hash seeds (no -I here: it would ignore
    # PYTHONHASHSEED; env -i, -s and -P keep the rest of the environment, the
    # user site and the script directory out) and must give the same exit
    # code 1 and the same output every time. On 8cb0d33 3 of the 8 seeds gave
    # 1 finding and the other 5 gave 0, on both cases.
    local det_case det_seed det_first det_got det_ok
    for det_case in fail-dict-repeated-key fail-dict-computed-keys; do
      det_first="" det_ok=1
      for det_seed in 0 1 2 3 4 5 6 7; do
        det_got="$(env -i PATH="$PATH" PYTHONHASHSEED="$det_seed" python3 -B -s -P \
          "$SELFTEST_ROOT/tools/sitecheck.py" literals --root "$FIXTURES/literals/$det_case" 2>&1;
          echo "exit $?")"
        [[ $det_got == *$'\nexit 1' ]] || det_ok=0
        if [[ $det_seed == 0 ]]; then
          det_first="$det_got"
        elif [[ $det_got != "$det_first" ]]; then
          det_ok=0
        fi
      done
      if [[ $det_ok == 1 ]]; then
        echo "ok   literals-deterministic/$det_case (exit 1 and the same output under 8 hash seeds)"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL literals-deterministic/$det_case: the output or exit code changed with the hash seed; last run:"
        printf '%s\n' "$det_got" | sed 's/^/     | /'
        n_failed=$((n_failed + 1))
      fi
    done
  fi

  if selftest_wants feed-fields; then
    # feed-fields (M3 PR 8 review 4, #30 Known limit 3): render rule 12 field
    # by field from tests/fixtures/render/feed-fields.tsv on the feed of
    # render/pass-feed, its coverage of every compared field, and the
    # field-set branch against a test-only schema (feed_fields_runner above).
    # coverage-fails-on-field-without-row proves the coverage on the table
    # without the reports label row.
    feed_fields_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/render/feed-fields.tsv" \
      "$FIXTURES/render/pass-feed" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )feed-fields/field-set-test-schema' "$out"; then
      echo "FAIL feed-fields: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    local fields_table
    fields_table="$(mktemp)"
    grep -v $'^reports\texample-front-company\tlabel\t' "$FIXTURES/render/feed-fields.tsv" \
      >"$fields_table"
    FEED_FIELDS_COVERAGE_ONLY=1 feed_fields_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$fields_table" "$FIXTURES/render/pass-feed" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    if grep -q '^FAIL feed-fields/coverage: reports\[\]\.label has no row' "$out" \
        && ! grep -q '^ok   feed-fields/coverage' "$out"; then
      echo "ok   feed-fields/coverage-fails-on-field-without-row (failed as expected: reports[].label has no row)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL feed-fields/coverage-fails-on-field-without-row: the coverage passed on a table without the label row; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    rm -f "$fields_table"
  fi

  if selftest_wants page-suffixes; then
    # page-suffixes (M4 PR 3 fix round 10): site rule (n) and literals L6 for
    # every member of HTML_SUFFIXES (page_suffixes_runner above).
    page_suffixes_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/pass-two-scripts" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -q '^ok   page-suffixes/table' "$out"; then
      echo "FAIL page-suffixes: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants site-head; then
    # site-head (M4 PR 3 fix rounds 7 and 8): site rule (m) row by row from
    # tests/fixtures/site/head-cases.tsv (site_cases_runner above).
    site_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/head-cases.tsv" "$FIXTURES/site/pass-built-pins" \
      "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )site-head/table' "$out"; then
      echo "FAIL site-head: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants render-search; then
    # render-search (M4 PR 2 and PR 3, ADR-0005 part 6): render rules 15 and 16 branch by
    # branch and member by member from tests/fixtures/render/search-cases.tsv
    # on a copy of render/pass-search (search_cases_runner above).
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/render/search-cases.tsv" "$FIXTURES/render/pass-search" \
      "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )render-search/table' "$out"; then
      echo "FAIL render-search: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants render-report; then
    # render-report/<row> (M4 PR 4): render rule 17, the exact trees of a
    # report page, branch by branch from tests/fixtures/render/report-cases.tsv
    # on a copy of render/pass-report-pins, the real fixture build, with the
    # feed rules and rule 17 on (search_cases_runner above).
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/render/report-cases.tsv" "$FIXTURES/render/pass-report-pins" \
      "$SELFTEST_ROOT/schema" render-report >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )render-report/table' "$out"; then
      echo "FAIL render-report: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants render-intake; then
    # render-intake/<row> and site-intake/<row> (M5b PR 3, ADR-0006 parts 3,
    # 5, 6 and 9): render rule 18 from tests/fixtures/render/intake-cases.tsv
    # (search_cases_runner, rule 18 on through the base's intake.txt) and site
    # rule (a) with the CSP from tests/fixtures/site/intake-cases.tsv
    # (site_intake_runner), both on copies of render/pass-intake, the real
    # built intake pages; then the coverage of both tables against the member
    # sets in the code, and its negative proof (one member row left out each).
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/render/intake-cases.tsv" "$FIXTURES/render/pass-intake" \
      "$SELFTEST_ROOT/schema" render-intake >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )render-intake/table' "$out"; then
      echo "FAIL render-intake: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants site-intake; then
    site_intake_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/intake-cases.tsv" "$FIXTURES/render/pass-intake" \
      "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )site-intake/table' "$out"; then
      echo "FAIL site-intake: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants site-intake-expect; then
    # site-intake-expect (the negative proof of site_intake_runner's expect):
    # a real row with an expect text the findings do not hold must fail, and
    # a PASS row that fails must fail too.
    local expect_table
    expect_table=$(mktemp)
    awk -F'\t' -v OFS='\t' '
      $1 == "fail-input-formaction-intake" { $1 = $1 "-wrong-expect"; $5 = "(a) <form action> submits to"; print }
      $1 == "fail-button-formaction-intake" { $1 = $1 "-as-pass"; $5 = "PASS"; print }
    ' "$FIXTURES/site/intake-cases.tsv" >"$expect_table"
    site_intake_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$expect_table" \
      "$FIXTURES/render/pass-intake" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    rm -f "$expect_table"
    if [[ "$(grep -cE '^FAIL site-intake/fail-(input|button)-formaction-intake-(wrong-expect|as-pass):' "$out")" == 2 ]]; then
      echo "ok   site-intake-expect (a wrong expect and a failing PASS row each fail)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL site-intake-expect: a row with a wrong expect or a failing PASS row did not fail; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants site-csp-equiv; then
    # site-csp-equiv/<row> (Replikanti/interviewscam#32): what counts as the
    # CSP meta, from tests/fixtures/site/csp-equiv-cases.tsv on copies of
    # render/pass-intake (site_intake_runner, built pins off, so rule (m)
    # does not hide a row): a padded or non-ASCII-folded http-equiv is inert
    # in the browser, so the count and position rules fail and rule (a) and
    # the CSP rules stay silent about it.
    site_intake_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/csp-equiv-cases.tsv" "$FIXTURES/render/pass-intake" \
      "$SELFTEST_ROOT/schema" site-csp-equiv >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )site-csp-equiv/table' "$out"; then
      echo "FAIL site-csp-equiv: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    # The coverage of the tag-space rows and the interpreter's whitespace
    # (csp_equiv_coverage), then its negative proof: with the U+00A0 row
    # left out, the coverage line must fail.
    csp_equiv_coverage "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/csp-equiv-cases.tsv" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if [[ "$(grep -cE '^ok   site-csp-equiv/(coverage|space-set) ' "$out")" != 2 ]]; then
      echo "FAIL site-csp-equiv/coverage-lines: the coverage lines did not both pass; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    csp_equiv_coverage "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/site/csp-equiv-cases.tsv" tag-space/u00a0 >"$out" 2>&1
    if grep -q '^FAIL site-csp-equiv/coverage: 1 member(s) of PARSER_ONLY_SPACE without a row: tag-space/u00a0$' "$out"; then
      echo "ok   site-csp-equiv/coverage-fails-on-missing-row"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL site-csp-equiv/coverage-fails-on-missing-row: a member without a row did not fail; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants render-intake site-intake; then
    intake_coverage "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/render/intake-cases.tsv" \
      "$FIXTURES/site/intake-cases.tsv" >"$out" 2>&1
    selftest_rows "$out"
    if ! selftest_ok_count "$out" render-intake 'render-intake/coverage' 1 \
        || ! selftest_ok_count "$out" site-intake 'site-intake/coverage' 1; then
      echo "FAIL $(selftest_suite intake-coverage render-intake site-intake): the coverage lines did not both pass; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants render-intake site-intake; then
    local drop kind
    # One row of every case family the coverage reads, so dropping a family
    # from intake_coverage turns its line red (fix round 1, QA): per field
    # missing, duplicated, renamed, type, autocomplete, autocomplete=off,
    # required, the three maxlength cases, label-for, no-label and the two
    # rewordings; the MIME types; per result id missing, doubled, id elsewhere
    # and the two rewordings; the sitemap; the pages and forms; the referrer
    # tags; URL_ATTRS, FORM_ATTRS, INTAKE_FORM_PAGES and CSP_DIRECTIVES.
    for drop in render:b-report-scam_alias-renamed render:b-correction-email-required \
        render:b-report-headers-maxlength-above render:b-correction-request-hint-reworded \
        render:b-correction-files-accept-without-webp render:d-error-doubled \
        render:c-correction-referrerpolicy-input render:a-correction-page-missing \
        render:b-correction-page_url-autocomplete-off render:d-not-sent-in-sitemap \
        render:b-report-details-missing render:b-report-email-duplicated \
        render:b-correction-page_url-type render:b-report-scam_alias-autocomplete \
        render:b-report-contact_start-maxlength-below render:b-correction-request-maxlength-absent \
        render:b-report-headers-label-for render:b-correction-email-no-label \
        render:b-report-files-label-reworded render:d-paused-missing \
        render:d-too-long-id-elsewhere render:d-bad-address-heading-reworded \
        render:d-not-accepted-text-reworded render:a-report-form-missing \
        site:fail-intake-host-in-data site:fail-input-formaction-intake \
        site:fail-csp-form-action-missing-intake-correction site:csp-intake/worker-src; do
      kind="${drop%%:*}"
      selftest_wants "$kind-intake" || continue
      intake_coverage "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/render/intake-cases.tsv" \
        "$FIXTURES/site/intake-cases.tsv" "${drop#*:}" >"$out" 2>&1
      if grep -q "^FAIL $kind-intake/coverage: 1 member(s) without a row: ${drop#*:}\$" "$out"; then
        echo "ok   $kind-intake/coverage-fails-on-missing-row (${drop#*:})"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL $kind-intake/coverage-fails-on-missing-row: without ${drop#*:} the coverage line did not fail; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
    done
  fi

  if selftest_wants render-bidi; then
    # render-bidi/<row> (Replikanti/interviewscam#28): render rule 19 from
    # tests/fixtures/render/bidi-cases.tsv on a copy of
    # render/pass-report-pins, one row per member of BIDI_CONTROLS and per
    # place a page or JSON file can carry one; then the coverage of the
    # table against BIDI_CONTROLS and its negative proof (a member row left
    # out, the first and the last member).
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/render/bidi-cases.tsv" "$FIXTURES/render/pass-report-pins" \
      "$SELFTEST_ROOT/schema" render-bidi >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )render-bidi/table' "$out"; then
      echo "FAIL render-bidi: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants records-bidi; then
    # records-bidi/<row> (Replikanti/interviewscam#28): records rule R16 from
    # tests/fixtures/records/bidi-cases.tsv on a copy of
    # records/pass-fixture-site (search_cases_runner with the records
    # command), one row per member of BIDI_CONTROLS, which covers all four
    # ranges of the property, and per place a record carries text; then the
    # coverage and its negative proof, as for render-bidi.
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/records/bidi-cases.tsv" "$FIXTURES/records/pass-fixture-site" \
      "$SELFTEST_ROOT/schema" records-bidi records >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )records-bidi/table' "$out"; then
      echo "FAIL records-bidi: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  # render-persona/<row> and records-persona/<row> (Replikanti/interviewscam#28
  # PR 2): the persona names under the look-alike readings, render rules 4,
  # 9 and 12 from tests/fixtures/render/persona-cases.tsv on a copy of
  # render/pass-report-pins, and records rule R5 from
  # tests/fixtures/records/persona-cases.tsv on a copy of
  # records/pass-fixture-site (search_cases_runner, the records command for
  # R5): one row per reading class a name can hide behind (a look-alike
  # letter, a blank, the tatweel and a modifier letter between tokens, an
  # upper-case capital iota, a pipe for a space or for an "i", a
  # right-to-left run stored reversed and its stored-order control), per
  # place (body text, hidden content, an own box, the <title>, JSON-LD, an
  # attribute, the feed, a hidden persona's name, a second persona whose
  # name has the same skeleton) and the PASS rows that hold the exemptions.
  local persona_label persona_base persona_command
  for persona_label in render-persona records-persona; do
    selftest_wants "$persona_label" || continue
    if [[ "$persona_label" == render-persona ]]; then
      persona_base="$FIXTURES/render/pass-report-pins" persona_command=render
    else
      persona_base="$FIXTURES/records/pass-fixture-site" persona_command=records
    fi
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/${persona_label%-persona}/persona-cases.tsv" "$persona_base" \
      "$SELFTEST_ROOT/schema" "$persona_label" "$persona_command" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE "^(ok   |FAIL )$persona_label/table" "$out"; then
      echo "FAIL $persona_label: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  done
  local bidi_label bidi_table bidi_drop
  for bidi_label in render-bidi records-bidi; do
    selftest_wants "$bidi_label" || continue
    bidi_table="$FIXTURES/${bidi_label%-bidi}/bidi-cases.tsv"
    bidi_coverage "$SELFTEST_ROOT/tools/sitecheck.py" "$bidi_table" "$bidi_label" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE "^(ok   |FAIL )$bidi_label/coverage" "$out"; then
      echo "FAIL $bidi_label/coverage: the coverage did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    for bidi_drop in member-061C member-2069; do
      bidi_coverage "$SELFTEST_ROOT/tools/sitecheck.py" "$bidi_table" "$bidi_label" \
        "$bidi_drop" >"$out" 2>&1
      if grep -q "^FAIL $bidi_label/coverage: 1 member(s) without a row: $bidi_drop\$" "$out"; then
        echo "ok   $bidi_label/coverage-fails-on-missing-row ($bidi_drop)"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL $bidi_label/coverage-fails-on-missing-row: without $bidi_drop the coverage line did not fail; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
    done
  done
  if selftest_wants confusables; then
    # confusables/<row> (Replikanti/interviewscam#28): the vendored data,
    # its loader, the skeleton readings and the guard's pin
    # (confusables_runner above).
    confusables_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$FIXTURES/render/pass-report-pins" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )confusables/guard-unicode-dir-missing' "$out"; then
      echo "FAIL confusables: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants render-search-count; then
    # render-search-count (M4 PR 3 fix round 12b, QA recheck of 54d4517): the
    # COUNT=<n> expectation itself. Rows of the real table with a wrong count
    # must each fail: one finding pinned as 0 and as 2, and two findings pinned
    # as 1 and as 3, so a runner that ignores the count, reads it as at least
    # or at most n, or as "some findings" fails this line.
    count_table=$(mktemp)
    awk -F'\t' -v OFS='\t' '
      $1 == "unread-home-form-icon" { for (c = 0; c <= 2; c += 2) { r = $0; sub(/COUNT=1 /, "COUNT=" c " ", r); split(r, f, "\t"); f[1] = f[1] "-count-" c; print f[1], f[2], f[3], f[4], f[5] } }
      $1 == "unread-unclosed-only-finding" { for (c = 1; c <= 3; c += 2) { r = $0; sub(/COUNT=2 /, "COUNT=" c " ", r); split(r, f, "\t"); f[1] = f[1] "-count-" c; print f[1], f[2], f[3], f[4], f[5] } }
    ' "$FIXTURES/render/search-cases.tsv" >"$count_table"
    search_cases_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$count_table" \
      "$FIXTURES/render/pass-search" "$SELFTEST_ROOT/schema" >"$out" 2>&1
    rm -f "$count_table"
    count_rows=$(grep -cE '^(ok   |FAIL )render-search/.*-count-[0-9]' "$out")
    count_fails=$(grep -cE '^FAIL render-search/.*-count-[0-9]' "$out")
    if [[ "$count_rows" == 4 && "$count_fails" == 4 ]]; then
      echo "ok   render-search-count (4 rows with a wrong COUNT= each fail)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL render-search-count: $count_fails of $count_rows rows with a wrong COUNT= failed (need 4 of 4); output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants fixture-script-copies; then
    # fixture-script-copies (M4 PR 3 fix round 2, QA): every fixture copy of
    # assets/js/search.js, found by name under tests/fixtures/reflow (the
    # cases of case (6) load one), equals the real script byte for byte, so
    # no case proves the on-load and reveal behaviour of a script the site
    # no longer ships. No copy at all fails too, so the line cannot pass by
    # finding nothing. The literals cases are no copies: each stands in for
    # a repo root with a script crafted to fail one rule (fix round 4).
    local script_copy n_copies=0 stale_copies=""
    while IFS= read -r -d '' script_copy; do
      n_copies=$((n_copies + 1))
      cmp -s "$script_copy" "$SELFTEST_ROOT/assets/js/search.js" \
        || stale_copies+=" ${script_copy#"$FIXTURES"/}"
    done < <(find "$FIXTURES/reflow" -type f -name search.js -print0)
    if (( n_copies == 0 )) || [[ -n "$stale_copies" ]]; then
      echo "FAIL fixture-script-copies: $n_copies fixture copies of search.js; these differ" \
        "from assets/js/search.js:${stale_copies:- (none found)}"
      n_failed=$((n_failed + 1))
    else
      echo "ok   fixture-script-copies ($n_copies fixture copies equal assets/js/search.js)"
      n_passed=$((n_passed + 1))
    fi
  fi

  if selftest_wants site-built-pins-missing-stem; then
    # site-built-pins-missing-stem (M4 PR 3 fix round 6, QA): a pinned stem
    # without a built pin is a finding, never a pass on its own bytes. The
    # line drops one built pin at a time through importlib and runs the real
    # cmd_site on site/pass-built-pins, which must then fail on that stem.
    if python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/site/pass-built-pins" \
        "$SELFTEST_ROOT/schema" >"$out" 2>&1 <<'PY'
import argparse
import contextlib
import importlib.util
import io
import sys

case, schemas = sys.argv[2], sys.argv[3]
bad = []
for table, stem, want in (("BUILT_SCRIPT_SHA384", "copy", "the script copy"),
                          ("BUILT_SCRIPT_SHA384", "search", "the script search"),
                          ("BUILT_STYLESHEET_SHA256", "site", "the stylesheet site")):
    spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
    sitecheck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sitecheck)
    del getattr(sitecheck, table)[stem]
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        rc = sitecheck.cmd_site(argparse.Namespace(records=case, schemas=schemas,
                                                   no_built_pins=False,
                                                   public=case + "/public"))
    if rc != 1 or f"are not the pinned build of {want}" not in buffer.getvalue():
        bad.append(f"{table} without {stem}: exit {rc}")
if bad:
    print("; ".join(bad))
    sys.exit(1)
PY
    then
      echo "ok   site-built-pins-missing-stem (a pinned stem without a built pin fails)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL site-built-pins-missing-stem: $(cat "$out")"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants guard-public guard-wf; then
    # guard-public/<row> and guard-wf/<row> (ADR-0007 part 4,
    # Replikanti/interviewscam#38 PR B): the public-tree rules and the
    # workflow hardening, one row per member of every flagging set and per
    # form (guard_public_runner above), plus their wiring into cmd_guard
    # (guard_wiring_runner above).
    guard_public_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$SELFTEST_ROOT/schema" \
      "$SELFTEST_ROOT/tools/pins.env" >"$out" 2>&1
    selftest_rows "$out" details
    if ! grep -qE '^(ok   |FAIL )guard-wf/table' "$out"; then
      echo "FAIL $(selftest_suite guard-public guard-wf): the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants wiring; then
    guard_wiring_runner "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if [[ $(grep -c '^ok   wiring/guard-' "$out") -ne 3 ]]; then
      echo "FAIL wiring/guard-public-tree: the wiring runner did not pass all three lines; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi
  if selftest_wants guard-records-templates; then
    # The template pins of the records workflows (ADR-0007 part 5, PR E).
    guard_templates_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/records-repo" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -q '^ok   guard-records-templates/table' "$out"; then
      echo "FAIL guard-records-templates: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  # Records mode and the pin rule (ADR-0007 part 5,
  # Replikanti/interviewscam#38 PR C): the records-repo rows on pass-shapes,
  # the wiring of the shared workflow rules, the pin rule's extra cases,
  # check.sh's flags, the token unset after the pin step, the classified
  # .records-site/, the Lighthouse page set of records mode, and the e2e
  # runs of check.sh --records. Each family runs when one of the suites its
  # rows print is selected (pin_runner prints pin and pin-extra rows).
  local family family_suites runner_out
  for family in table wiring extra; do
    case "$family" in
      table) family_suites="records-repo" ;;
      wiring) family_suites="wiring" ;;
      extra) family_suites="pin pin-extra" ;;
    esac
    # shellcheck disable=SC2086 # family_suites is a list of suite names
    selftest_wants $family_suites || continue
    case "$family" in
      table)
        records_repo_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$SELFTEST_ROOT/tools/pins.env" \
          table "$FIXTURES/records-repo/cases.tsv" "$FIXTURES/records-repo/pass-shapes" >"$out" 2>&1
        ;;
      wiring)
        records_repo_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$SELFTEST_ROOT/tools/pins.env" \
          wiring "$FIXTURES/records-repo/pass-shapes" >"$out" 2>&1
        ;;
      extra)
        pin_runner "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/pin" >"$out" 2>&1
        ;;
    esac
    selftest_rows "$out" details
    runner_out=0
    case "$family" in
      table) selftest_ok_count "$out" records-repo 'records-repo/table' 1 && runner_out=1 ;;
      wiring) selftest_ok_count "$out" wiring 'wiring/records-repo-' 4 \
        && selftest_ok_count "$out" wiring 'wiring/records-fixture-pin-matches' 1 && runner_out=1 ;;
      extra) selftest_ok_count "$out" pin-extra 'pin-extra/' 14 \
        && selftest_ok_count "$out" pin 'pin/cases' 1 && runner_out=1 ;;
    esac
    if [[ $runner_out -eq 0 ]]; then
      # shellcheck disable=SC2086 # family_suites is a list of suite names
      echo "FAIL $(selftest_suite records-mode $family_suites)/$family: the runner did not finish with every line; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  done

  if selftest_wants records-mode; then
    # records-mode/usage: check.sh's flags, through parse_check_args (the
    # function check_main calls first): --records at most once and with a
    # directory, --external at most once, both orders, the directory resolved
    # with cd -P, refused when it is this checkout or inside it (also through
    # a symlink), allowed when this checkout lies inside it.
    local usage_tmp usage_bad=() usage_n=0 got
    usage_tmp="$(mktemp -d)"
    mkdir -p "$usage_tmp/records/sub" && : >"$usage_tmp/file"
    ln -s "$SELFTEST_ROOT/tools" "$usage_tmp/inside-link"
    ln -s "$usage_tmp/records" "$usage_tmp/outside-link"
    # usage_case <want rc> <want RECORDS_DIR or -> <want EXTERNAL or -> <args...>
    usage_case() {
      local want_rc="$1" want_dir="$2" want_ext="$3" rc_got
      shift 3
      usage_n=$((usage_n + 1))
      got="$(cd "$usage_tmp" && parse_check_args "$@" 2>&1 && printf '%s|%s' "$RECORDS_DIR" "$EXTERNAL")"
      rc_got=$?
      if [[ $rc_got -ne $want_rc ]] \
          || { [[ $want_rc -eq 0 ]] && [[ "$got" != "$want_dir|$want_ext" ]]; }; then
        usage_bad+=("[$*]: exit $rc_got, got '$got'")
      fi
    }
    local real
    real="$(cd -P "$usage_tmp/records" && pwd)"
    usage_case 0 "" "" 
    usage_case 0 "" --external --external
    usage_case 0 "$real" "" --records records
    usage_case 0 "$real" "" --records records/
    usage_case 0 "$real" "" --records records/sub/..
    usage_case 0 "$real" "" --records "$usage_tmp/records"
    usage_case 0 "$real" "" --records outside-link
    usage_case 0 "$real" --external --records records --external
    usage_case 0 "$real" --external --external --records records
    usage_case 0 "$(cd -P "$SELFTEST_ROOT/.." && pwd)" "" --records "$SELFTEST_ROOT/.."
    usage_case 2 - - --records
    usage_case 2 - - --records ""
    usage_case 2 - - --records missing
    usage_case 2 - - --records file
    usage_case 2 - - --records "$SELFTEST_ROOT"
    usage_case 2 - - --records "$SELFTEST_ROOT/tools"
    usage_case 2 - - --records inside-link
    usage_case 2 - - --records records --records records
    usage_case 2 - - --external --external
    usage_case 2 - - --records records --external --external
    usage_case 2 - - --other
    rm -rf "$usage_tmp"
    if [[ ${#usage_bad[@]} -eq 0 ]]; then
      echo "ok   records-mode/usage ($usage_n flag forms)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL records-mode/usage: ${usage_bad[*]}"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants wiring; then
    # wiring/records-token-unset: in check_records_main the pin step is the
    # first step, and `unset GH_TOKEN GITHUB_TOKEN` is the very next line, so
    # no later step (Hugo, lychee, the checks) holds the job token.
    if awk 'found == 1 { if ($0 ~ /^ *unset GH_TOKEN GITHUB_TOKEN;?$/) found = 2; else found = -1 }
            /run_step/ && !seen { seen = 1; if ($0 ~ /^ *run_step "pin \(green check on public main\)" step_pin "\$sha";?$/) found = 1 }
            END { exit found != 2 }' <<<"$(declare -f check_records_main)"; then
      echo "ok   wiring/records-token-unset (the pin step comes first, the token is unset right after it)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/records-token-unset: check_records_main in tools/check.sh does not run the pin step first with \`unset GH_TOKEN GITHUB_TOKEN\` right after it"
      n_failed=$((n_failed + 1))
    fi

    # wiring/fixture-skip-records-site: .records-site/ is classified for the
    # fixture build and git-ignored, so a public run after a records run
    # neither fails on an unclassified path nor offers it to git add.
    if [[ " ${FIXTURE_SKIP[*]} " == *" .records-site "* ]] \
        && grep -qx '/.records-site/' "$SELFTEST_ROOT/.gitignore"; then
      echo "ok   wiring/fixture-skip-records-site (in FIXTURE_SKIP and .gitignore)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/fixture-skip-records-site: .records-site is not in FIXTURE_SKIP of tools/check.sh or not /.records-site/ in .gitignore"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants lighthouse; then
    # lighthouse/records-pages: the production page set of the Lighthouse run
    # (sitecheck lighthouse-pages, both modes): every directory with an
    # index.html except a record page, the section pages kept, plus /404.html,
    # with no public-fixtures/ anywhere.
    local lh_tmp lh_got
    lh_tmp="$(mktemp -d)"
    mkdir -p "$lh_tmp/public/about" "$lh_tmp/public/reports/x" "$lh_tmp/public/campaigns/y/amp" \
      "$lh_tmp/public/campaigns/y"
    for line in index.html about/index.html reports/index.html reports/x/index.html \
        campaigns/y/index.html campaigns/y/amp/index.html 404.html; do
      : >"$lh_tmp/public/$line"
    done
    lh_got="$(sitecheck lighthouse-pages "$lh_tmp/public" 2>&1 | tr '\n' ' ')"
    if [[ "$lh_got" == "/about/ / /reports/ /404.html " ]] \
        && ! sitecheck lighthouse-pages "$lh_tmp/public/about/missing" >/dev/null 2>&1; then
      echo "ok   lighthouse/records-pages (production pages only: $lh_got)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL lighthouse/records-pages: got '$lh_got'"
      n_failed=$((n_failed + 1))
    fi
    rm -rf "$lh_tmp"
  fi

  if selftest_wants records-mode; then
    records_mode_e2e "$SELFTEST_ROOT" "$FIXTURES" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if [[ $(grep -c '^ok   records-mode/' "$out") -ne 15 ]]; then
      echo "FAIL records-mode/e2e: not every e2e case passed; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants guard-worker-exact; then
    # guard-worker-exact (M5b PR 2 fix round 1, QA): guard_worker_pins gives
    # exactly the findings each worker fixture names, and none on a root
    # without worker/, so a scan without recursion, a directory read as a
    # source, an unpinned file passed or an absent worker/ made a finding each
    # change the set. Through importlib, because the guard fixtures check one
    # substring each.
    if python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" "$FIXTURES/guard" >"$out" 2>&1 <<'PY'
import importlib.util
import pathlib
import sys
import tempfile

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
guard = pathlib.Path(sys.argv[2])
UNPINNED = "a worker source that is not pinned"
MISSING = "a pinned worker source is missing"
SYMLINK = "a worker source must be a regular file, not a symlink"
MISMATCH = "the worker source's SHA-256 is"
cases = {
    "pass-worker-pin": set(),
    "fail-worker-pin-nested": {("worker/sub/extra.js", UNPINNED), ("worker/intake.js", MISSING)},
    "fail-worker-pin-missing": {("worker/extra.js", UNPINNED), ("worker/intake.js", MISSING)},
    "fail-worker-file-missing": {("worker/README", UNPINNED), ("worker/intake.js", MISSING)},
    "fail-worker-pin-mismatch": {("worker/intake.js", MISMATCH)},
    "fail-worker-symlink": {("worker/intake.js", SYMLINK)},
}
bad = []


def kinds(root):
    findings = sitecheck.Findings()
    sitecheck.guard_worker_pins(root, findings)
    got = set()
    for item in findings.items:
        where, message = item[len("FAIL: "):].split(": ", 1)
        kind = next((k for k in (UNPINNED, MISSING, SYMLINK, MISMATCH) if message.startswith(k)), message)
        got.add((where, kind))
    return got, findings.items


for name, want in cases.items():
    got, items = kinds(guard / name)
    if got != want:
        bad.append(f"{name}: {items}")
with tempfile.TemporaryDirectory() as tmp:
    got, items = kinds(pathlib.Path(tmp))
    if got:
        bad.append(f"root without worker/: {items}")
print("\n".join(bad))
sys.exit(1 if bad else 0)
PY
    then
      echo "ok   guard-worker-exact (each worker fixture gives exactly its findings; none without worker/)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL guard-worker-exact: $(cat "$out")"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants guard-stylesheet-unreadable; then
    # guard-stylesheet-unreadable (M4 PR 3 fix round 5, QA): a stylesheet
    # source that cannot be read is a finding, never skipped. Git cannot hold
    # an unreadable file, so the line builds a root with one stylesheet in a
    # temporary directory and makes its read fail through importlib.
    if python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import pathlib
import sys
import tempfile

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    (root / "assets" / "css").mkdir(parents=True)
    target = root / "assets" / "css" / "site.css"
    target.write_text(".x { color: inherit; }\n")
    real = pathlib.Path.read_bytes

    def read_bytes(path):
        if path == target:
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)
    pathlib.Path.read_bytes = read_bytes
    findings = sitecheck.Findings()
    sitecheck.guard_stylesheet_pins(root, findings)
    pathlib.Path.read_bytes = real
    found = [i for i in findings.items if "cannot read a stylesheet source" in i]
    if len(found) != 1 or len(findings.items) != 1:
        print(findings.items)
        sys.exit(1)
PY
    then
      echo "ok   guard-stylesheet-unreadable (an unreadable stylesheet source is a finding)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL guard-stylesheet-unreadable: an unreadable stylesheet source was skipped:" \
        "$(cat "$out")"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants site-script-stems; then
    # site-script-stems (M4 PR 3, ADR-0005 part 5): site rule (j) reads the
    # stems of the pinned scripts from SCRIPT_SHA256, and only a key
    # assets/js/<stem>.js gives one. The real pin holds only such keys, so
    # the line patches the pin through importlib with a key in another
    # directory, one in a subdirectory, an .mjs key, one with a hyphen and
    # one with an upper-case letter, none of which may give a stem (a
    # hyphen and an upper-case letter are outside the closed path alphabet
    # of resource_path, so such a script could never be served).
    if python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)
real = sitecheck.script_stems()
# Fix round 6 (QA): every pinned script and stylesheet has a built pin and
# no built pin names anything else, so no stem falls back to its own bytes.
if set(sitecheck.BUILT_SCRIPT_SHA384) != real \
        or set(sitecheck.BUILT_STYLESHEET_SHA256) != set(sitecheck.BUILT_STYLESHEETS):
    print(f"built pins {sorted(sitecheck.BUILT_SCRIPT_SHA384)} and "
          f"{sorted(sitecheck.BUILT_STYLESHEET_SHA256)} differ from the stems {sorted(real)} "
          f"and {sorted(sitecheck.BUILT_STYLESHEETS)}")
    sys.exit(1)
sitecheck.SCRIPT_SHA256 = {"assets/js/a.js": "0", "assets/x/b.js": "0",
                           "assets/js/sub/c.js": "0", "assets/js/d.mjs": "0",
                           "assets/js/e-f.js": "0", "assets/js/Up.js": "0"}
got = sitecheck.script_stems()
if real != {"copy", "search"} or got != {"a"}:
    print(f"real pin {sorted(real)}, patched pin {sorted(got)}")
    sys.exit(1)
PY
    then
      echo "ok   site-script-stems (only assets/js/<stem>.js keys of SCRIPT_SHA256 give a stem; the built pins name exactly the pinned stems)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL site-script-stems: script_stems reads other keys than assets/js/<stem>.js:" \
        "$(cat "$out")"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants wiring; then
    # Wiring: the fixture build classifies its inputs before it copies them
    # (ADR-0004 part 10, amended), and copies exactly the FIXTURE_COPY
    # entries; declare -f prints the function without comments.
    # shellcheck disable=SC2016 # the patterns match literal $ names
    if grep -qE '^ *fixture_inputs "\$CHECK_ROOT" \|\| return 1;?$' <<<"$(declare -f step_fixture_build)" \
        && grep -qF 'for item in "${FIXTURE_COPY[@]}"' <<<"$(declare -f step_fixture_build)"; then
      echo "ok   wiring/fixture-inputs-step (step_fixture_build classifies \$CHECK_ROOT, then copies FIXTURE_COPY)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL wiring/fixture-inputs-step: step_fixture_build in tools/check.sh does not" \
        "call fixture_inputs \"\$CHECK_ROOT\" || return 1, or does not copy by iterating FIXTURE_COPY"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants fixture-inputs; then
    # fixture-inputs/arrays-disjoint: the real arrays name every entry once,
    # so fixture_inputs passes on an empty root. classified-twice: a name
    # added to a second array fails it, with its own message.
    inputs_root="$(mktemp -d)"
    if fixture_inputs "$inputs_root" >"$out" 2>&1; then
      echo "ok   fixture-inputs/arrays-disjoint (no name in two of FIXTURE_COPY, FIXTURE_CONTENT, FIXTURE_SKIP)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL fixture-inputs/arrays-disjoint: fixture_inputs fails on an empty root; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    if (FIXTURE_SKIP+=(layouts); fixture_inputs "$inputs_root") >"$out" 2>&1; then
      echo "FAIL fixture-inputs/classified-twice: layouts in FIXTURE_COPY and FIXTURE_SKIP passed; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qF "'layouts' classified twice" "$out"; then
      echo "FAIL fixture-inputs/classified-twice: failed without the expected reason \"'layouts' classified twice\"; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   fixture-inputs/classified-twice (failed as expected: 'layouts' classified twice)"
      n_passed=$((n_passed + 1))
    fi
    rm -rf "$inputs_root"
  fi

  if selftest_wants reflow-launch; then
    # reflow-launch: the launch of sitecheck reflow (ADR-0003 part 6, #24)
    # against a stub browser, so the cases run locally and in CI, each with
    # --launch-timeout 1 on reflow/pass-fluid (default-budget without it).
    # The stub appends its PID to a launch log, its arguments to an argument
    # log and the file behind its stderr to a log-path log on every start,
    # writes one line to stdout and one to stderr (as Chrome logs), and then
    # acts or execs, so the PID stays the browser's. Each case counts the
    # launches, and after sitecheck returns no logged PID may still be alive
    # (every Chrome of both launches is killed or reaped).
    #   never-answers: the stub never answers, so both launches time out:
    #     exit 2, "on launch 2 of 2", 2 launches, both stub lines in the dump
    #     of each launch (Chrome's log is captured), a probe line naming the
    #     stub's PID and the 1 s budget before the budget ran out (0.x s),
    #     the verbose log flags among its arguments, and both logs in a
    #     reflow-log- directory on /dev/shm where that is a writable tmpfs
    #     (a disk stall cannot block Chrome's log writes unless memory runs
    #     short: reclaim can then wait on the disk, through swap or through
    #     other files' writeback; the probe line reports memory pressure), in
    #     the temporary directory otherwise.
    #   protocol-error-no-retry: the stub answers the first command with a
    #     DevTools error, which must fail at once: exit 2, the error, no
    #     retry line, 1 launch, the stub's stderr line in the error
    #     dump. A stub line that reached the DevTools pipe would break the
    #     reply's parse.
    #   later-call-no-retry: the stub answers Browser.getVersion and closes
    #     the pipe 3 s later, while sitecheck waits for the answer to
    #     Target.createTarget; only the first answer of a launch retries:
    #     exit 2, no retry line, 1 launch, "Chrome closed the
    #     DevTools pipe", and the probe of the later call names its 30 s
    #     budget (REFLOW_TIMEOUT, not the launch budget).
    #   exits-at-once: the stub exits at once, an early exit that must retry
    #     whichever side sees the closed pipe first: exit 2, "on launch 2 of
    #     2", 2 launches, no Traceback. Unloaded the read usually sees the
    #     close first, so this case guards the behaviour, and
    #     first-answer-epipe below proves the write side.
    #   default-budget: the exits-at-once stub without --launch-timeout, so
    #     the budget CI uses: exit 2, 2 launches, no Traceback, and the probe
    #     before each kill names a 75 s budget (REFLOW_LAUNCH_TIMEOUT, the
    #     option's default) on launch 1 and on launch 2. The stub exits at
    #     once, so the case never waits for that budget; first-answer-deadline
    #     below pins the deadline actually waited.
    #   slow-first-answer: the stub answers Browser.getVersion after 0.5 s,
    #     inside the budget, and then acts like later-call-no-retry: exit 2
    #     from the later call, no retry line, 1 launch, a
    #     "first answer after 0." line naming the log directory, a probe
    #     before it and the launch's dump right after it.
    # The stubs keep both pipe ends open while they sleep, so a later-call
    # failure is the closed pipe on the read (a NoAnswerError, which a retry
    # scoped too wide would catch) and never a BrokenPipeError on the write.
    # The 3 s sleeps outlast the 1 s launch budget, so a retry scoped too wide
    # fires (and a closed pipe cannot stand in for the protocol error), and
    # stay short, because the reflow cleanup waits for the stub to exit; no
    # case waits on the 30 s budget of a later call.
    local stub_dir launches problem pid retry_line log_line log_glob
    local -a budget_args
    # The retry line. The diagnostics name "launch 1 of 2" too, so the
    # no-retry checks look for the whole retry phrase.
    retry_line='on launch 1 of 2; starting it again'
    # Where sitecheck must put Chrome's logs (REFLOW_LOG_DIR): a reflow-log-
    # directory on /dev/shm when that is a writable tmpfs, else the work
    # directory under the temporary directory. log_line: what the timing
    # line names (an ERE).
    if [[ "$(stat -f -c %T /dev/shm 2>/dev/null)" == tmpfs && -w /dev/shm ]]; then
      log_line='/dev/shm'
      log_glob='/dev/shm/reflow-log-*/chrome-[12].log'
    else
      log_line='[^)]+'
      log_glob="$(cd "${TMPDIR:-/tmp}" && pwd -P)/reflow-*/chrome-[12].log"
    fi
    for name in never-answers protocol-error-no-retry later-call-no-retry \
        exits-at-once default-budget slow-first-answer; do
      stub_dir="$(mktemp -d)"
      {
        echo '#!/bin/sh'
        printf 'echo $$ >>"%s/launches"\n' "$stub_dir"
        printf 'printf '"'"'%%s\\n'"'"' "$@" >>"%s/args"\n' "$stub_dir"
        # readlink's own fd 2 is the stub's stderr, the log: the >> touches
        # only fd 1, wherever the shell applies it (CI's dash applied it in
        # the stub's own process, so /proc/$$/fd/1 named the logs file).
        printf 'readlink /proc/self/fd/2 >>"%s/logs"\n' "$stub_dir"
        echo "echo 'stub browser: a line on stdout'"
        echo "echo 'stub browser: a line on stderr' >&2"
      } >"$stub_dir/chrome"
      # Replies are one NUL-terminated JSON message on fd 4 (Chrome's output
      # pipe) to command id 1. The octal \0 is POSIX printf, so dash writes
      # the same bytes.
      case "$name" in
        never-answers)
          echo 'exec sleep 30' >>"$stub_dir/chrome"
          ;;
        protocol-error-no-retry)
          cat >>"$stub_dir/chrome" <<'STUB'
printf '{"id":1,"error":{"code":-32601,"message":"stub: no such method"}}\0' >&4
exec sleep 3
STUB
          ;;
        later-call-no-retry)
          cat >>"$stub_dir/chrome" <<'STUB'
printf '{"id":1,"result":{"product":"stub/1"}}\0' >&4
exec sleep 3
STUB
          ;;
        exits-at-once|default-budget)
          echo 'exit 0' >>"$stub_dir/chrome"
          ;;
        slow-first-answer)
          cat >>"$stub_dir/chrome" <<'STUB'
sleep 0.5
printf '{"id":1,"result":{"product":"stub/1"}}\0' >&4
exec sleep 3
STUB
          ;;
      esac
      chmod +x "$stub_dir/chrome"
      budget_args=(--launch-timeout 1)
      [[ "$name" == default-budget ]] && budget_args=()
      sitecheck reflow --chrome "$stub_dir/chrome" --no-search "${budget_args[@]}" \
        "$FIXTURES/reflow/pass-fluid" >"$out" 2>&1
      rc=$?
      launches=0
      [[ -f "$stub_dir/launches" ]] && launches="$(wc -l <"$stub_dir/launches")"
      launches="${launches// /}"
      problem=""
      case "$name" in
        never-answers)
          pid="$(head -n 1 "$stub_dir/launches" 2>/dev/null)"
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif ! grep -qF 'on launch 2 of 2' "$out"; then
            problem="no 'on launch 2 of 2' in the output"
          elif [[ "$launches" != 2 ]]; then
            problem="expected 2 launches, the stub counted $launches"
          elif ! launch_dump_has "$out" 1 'stub browser: a line on stdout' \
              || ! launch_dump_has "$out" 1 'stub browser: a line on stderr' \
              || ! launch_dump_has "$out" 2 'stub browser: a line on stdout' \
              || ! launch_dump_has "$out" 2 'stub browser: a line on stderr'; then
            problem="a stub line is missing from the Chrome log dump of a launch"
          elif ! grep -qE "^reflow: no answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s\): .*process $pid \(" "$out"; then
            problem="no probe line naming the stub PID $pid and the 1 s budget before the budget ran out"
          elif ! grep -qxF -- '--enable-logging=stderr' "$stub_dir/args" \
              || ! grep -qxF -- '--v=1' "$stub_dir/args"; then
            problem="the stub was not started with --enable-logging=stderr and --v=1"
          elif ! logs_moved "$stub_dir/logs" "$log_glob"; then
            problem="Chrome's two logs are not under $log_glob, or a log directory outlived the call: $(tr '\n' ' ' <"$stub_dir/logs" 2>/dev/null)"
          fi
          ;;
        protocol-error-no-retry)
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif ! grep -qF 'Browser.getVersion failed' "$out"; then
            problem="no 'Browser.getVersion failed' in the output"
          elif grep -qF "$retry_line" "$out"; then
            problem="the protocol error was retried ('$retry_line')"
          elif [[ "$launches" != 1 ]]; then
            problem="expected 1 launch, the stub counted $launches"
          elif ! launch_dump_has "$out" 1 'stub browser: a line on stderr'; then
            problem="the stub's stderr line is missing from the error dump"
          fi
          ;;
        later-call-no-retry)
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif grep -qF "$retry_line" "$out"; then
            problem="a later call was retried ('$retry_line')"
          elif [[ "$launches" != 1 ]]; then
            problem="expected 1 launch, the stub counted $launches"
          elif ! grep -qF 'Chrome closed the DevTools pipe' "$out"; then
            problem="no 'Chrome closed the DevTools pipe' in the output"
          elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 1 of 2 \(budget 30 s\): ' "$out"; then
            problem="no probe line of the later call with its 30 s budget"
          fi
          ;;
        exits-at-once)
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif grep -qF 'Traceback' "$out"; then
            problem="a Traceback in the output (the early exit was not a launch failure)"
          elif ! grep -qF 'on launch 2 of 2' "$out"; then
            problem="no 'on launch 2 of 2' in the output"
          elif [[ "$launches" != 2 ]]; then
            problem="expected 2 launches, the stub counted $launches"
          fi
          ;;
        default-budget)
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif grep -qF 'Traceback' "$out"; then
            problem="a Traceback in the output"
          elif [[ "$launches" != 2 ]]; then
            problem="expected 2 launches, the stub counted $launches"
          elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 1 of 2 \(budget 75 s\): ' "$out"; then
            problem="launch 1 did not run with the default 75 s budget"
          elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 2 of 2 \(budget 75 s\): ' "$out"; then
            problem="launch 2 did not run with the default 75 s budget"
          fi
          ;;
        slow-first-answer)
          if [[ $rc -ne 2 ]]; then
            problem="expected exit 2, got $rc"
          elif grep -qF "$retry_line" "$out"; then
            problem="the slow first answer was retried ('$retry_line')"
          elif [[ "$launches" != 1 ]]; then
            problem="expected 1 launch, the stub counted $launches"
          elif ! grep -qF 'Chrome closed the DevTools pipe' "$out"; then
            problem="no 'Chrome closed the DevTools pipe' (the later call) in the output"
          elif ! grep -qE "^reflow: first answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s, Chrome log [0-9]+ lines in $log_line\)\$" "$out"; then
            problem="no 'first answer after 0.' line with the 1 s budget and the log directory"
          elif ! awk '/^reflow: no answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s\): /{p = 1}
              /^reflow: first answer after /{ok = p; exit}
              END{exit !ok}' "$out"; then
            problem="no probe line before the first answer"
          elif ! awk 'f{ok = index($0, "reflow: Chrome log of launch 1 of 2 (") == 1; exit}
              /^reflow: first answer after /{f = 1}
              END{exit !ok}' "$out"; then
            problem="no Chrome log dump right after the slow first answer"
          fi
          ;;
      esac
      # Every logged PID must be gone. A survivor is killed here, so a red
      # case leaves no stub behind.
      if [[ -f "$stub_dir/launches" ]]; then
        while read -r pid; do
          if kill -0 "$pid" 2>/dev/null; then
            [[ -z "$problem" ]] && problem="stub browser PID $pid still alive after sitecheck returned"
            kill "$pid" 2>/dev/null
          fi
        done <"$stub_dir/launches"
      fi
      if [[ -z "$problem" ]]; then
        echo "ok   reflow-launch/$name (exit $rc, $launches launch(es), all reaped)"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL reflow-launch/$name: $problem; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
      rm -rf "$stub_dir"
    done

    # reflow-launch/first-answer-epipe: the write side of an early exit,
    # deterministically. The real DevTools client gets a command pipe whose
    # read end is closed, so the write of the first command meets EPIPE:
    # first_answer must turn it into the retried NoAnswerError naming the
    # closed pipe, and a later call (send) must keep the BrokenPipeError.
    # The budget the probe names must be first_answer's even then (1 s).
    # -B: the import writes no tools/__pycache__, which the guard would fail.
    python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)


def closed_command_pipe():
    command_r, command_w = os.pipe()
    os.close(command_r)
    answer_r, answer_w = os.pipe()
    return sitecheck.DevTools(command_w, answer_r), answer_w


for name, call in (
        ("first_answer", lambda tools: tools.first_answer(1, lambda elapsed: None)),
        ("send", lambda tools: tools.send("Target.createTarget", {"url": "about:blank"}))):
    tools, keep = closed_command_pipe()
    try:
        call(tools)
    except Exception as exc:
        print(f"{name}: {type(exc).__name__}: {exc}")
    else:
        print(f"{name}: returned")
    print(f"{name} budget: {tools.budget:g}")
PY
    if ! grep -qxF 'first_answer: NoAnswerError: reflow: Chrome closed the DevTools pipe' "$out"; then
      echo "FAIL reflow-launch/first-answer-epipe: first_answer did not turn EPIPE on the first write into NoAnswerError; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qE '^send: BrokenPipeError: ' "$out"; then
      echo "FAIL reflow-launch/first-answer-epipe: a later call no longer raises BrokenPipeError; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qxF 'first_answer budget: 1' "$out"; then
      echo "FAIL reflow-launch/first-answer-epipe: after EPIPE the probe would not name first_answer's budget; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   reflow-launch/first-answer-epipe (first write EPIPE: NoAnswerError; later write: BrokenPipeError)"
      n_passed=$((n_passed + 1))
    fi

    # reflow-launch/first-answer-deadline: the deadline first_answer waits
    # is its own budget, not REFLOW_TIMEOUT. default-budget above pins the
    # budget the probe line names, which a deadline taken from REFLOW_TIMEOUT
    # (alone or as a min with the budget) would still print. Here the real
    # DevTools client waits on a pipe that never answers, with REFLOW_TIMEOUT
    # patched to 0.1 s, and first_answer(0.5) must raise NoAnswerError after
    # 0.45 to 2.5 s. Lower bound: the code raises once the monotonic clock
    # passes a deadline set after the timer starts, so it cannot wait less
    # than 0.5 s, and both wrong deadlines above wait 0.1 s. Upper bound: a
    # deadline of 5 times the budget or more (the budget times 5 waits
    # 2.5 s, times 10 waits 5 s, a fixed REFLOW_LAUNCH_TIMEOUT 75 s) waits
    # past 2.5 s, while 2.5 s leaves 2 s, four times the wait itself, above
    # the 0.5 s deadline for a slow runner's wake-up (CI measured 0.500 s,
    # 0.60 s for the whole case). The upper bound does NOT catch the budget
    # times 2 to 4 (1 s to 2 s). A second sub-case patches REFLOW_TIMEOUT to
    # 5 s and requires the same 2.5 s: the additive form, the budget plus
    # REFLOW_TIMEOUT, waits 0.6 s at 0.1 s and passes the first sub-case, but
    # waits 5.5 s here. In production that form would be 105 s per launch and
    # break the 7-minute cap row. The real code still waits 0.5 s. -B as
    # above.
    python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import os
import sys
import time

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)

sitecheck.REFLOW_TIMEOUT = 0.1
command_r, command_w = os.pipe()
answer_r, answer_w = os.pipe()
tools = sitecheck.DevTools(command_w, answer_r)
start = time.monotonic()
try:
    tools.first_answer(0.5, lambda elapsed: None)
except Exception as exc:
    print(f"first_answer: {type(exc).__name__}: {exc}")
else:
    print("first_answer: returned")
print(f"waited: {time.monotonic() - start:.3f}")

sitecheck.REFLOW_TIMEOUT = 5
command_r, command_w = os.pipe()
answer_r, answer_w = os.pipe()
tools = sitecheck.DevTools(command_w, answer_r)
start = time.monotonic()
try:
    tools.first_answer(0.5, lambda elapsed: None)
except Exception as exc:
    print(f"first_answer additive: {type(exc).__name__}: {exc}")
else:
    print("first_answer additive: returned")
print(f"waited additive: {time.monotonic() - start:.3f}")
PY
    if ! grep -qxF 'first_answer: NoAnswerError: reflow: no answer from Chrome within 0.5 s' "$out"; then
      echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) on a silent pipe did not raise NoAnswerError naming its 0.5 s budget; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! awk '$1 == "waited:" && $2 >= 0.45 { ok = 1 } END { exit !ok }' "$out"; then
      echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) gave up before 0.45 s (its deadline is not its budget; REFLOW_TIMEOUT patched to 0.1); output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! awk '$1 == "waited:" && $2 <= 2.5 { ok = 1 } END { exit !ok }' "$out"; then
      echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) waited more than 2.5 s (its deadline is not its budget but 5 times it or more); output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qxF 'first_answer additive: NoAnswerError: reflow: no answer from Chrome within 0.5 s' "$out"; then
      echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) with REFLOW_TIMEOUT 5 did not raise NoAnswerError naming its 0.5 s budget; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! awk '$1 == "waited" && $2 == "additive:" && $3 <= 2.5 { ok = 1 } END { exit !ok }' "$out"; then
      echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) with REFLOW_TIMEOUT 5 waited more than 2.5 s (its deadline adds REFLOW_TIMEOUT to the budget); output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   reflow-launch/first-answer-deadline (first_answer(0.5) with REFLOW_TIMEOUT 0.1: $(awk '$1 == "waited:" { print $2 }' "$out") s, with 5: $(awk '$1 == "waited" && $2 == "additive:" { print $3 }' "$out") s)"
      n_passed=$((n_passed + 1))
    fi

    # reflow-launch/log-dir-fallback: where REFLOW_LOG_DIR is missing, is no
    # tmpfs mount (a plain directory), or is one in which no directory can be
    # made, reflow_log_dir keeps Chrome's logs in the work directory and
    # raises nothing. never-answers above proves the tmpfs side.
    python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)

work = Path(tempfile.mkdtemp())
try:
    (work / "plain").mkdir()
    for name, log_dir, mounted in (("missing", work / "missing", False),
                                   ("not-tmpfs", work / "plain", False),
                                   ("no-mkdir", work / "missing", True)):
        sitecheck.REFLOW_LOG_DIR = str(log_dir)
        if mounted:
            sitecheck.tmpfs_mounted = lambda path: True
        try:
            got = sitecheck.reflow_log_dir(work)
        except Exception as exc:
            print(f"{name}: {type(exc).__name__}: {exc}")
        else:
            print(f"{name}: {'work' if got == work else got}")
finally:
    shutil.rmtree(work)
PY
    if [[ "$(cat "$out")" != $'missing: work\nnot-tmpfs: work\nno-mkdir: work' ]]; then
      echo "FAIL reflow-launch/log-dir-fallback: reflow_log_dir did not fall back to the work directory; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   reflow-launch/log-dir-fallback (missing, not a tmpfs, no directory made: work directory)"
      n_passed=$((n_passed + 1))
    fi
  fi

  if selftest_wants search-oracle; then
    # search-oracle/tables (M4 PR 4): the oracle's own tables against
    # sitecheck's and the script's, member by member (search_oracle_tables).
    search_oracle_tables "$SELFTEST_ROOT/tools/sitecheck.py" \
      "$SELFTEST_ROOT/assets/js/search.js" "$SELFTEST_ROOT/docs/adr/0005-search.md" >"$out" 2>&1
    sed -n '/^ok   \|^FAIL /p' "$out"
    n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
    if ! grep -qE '^(ok   |FAIL )search-oracle/tables' "$out"; then
      echo "FAIL search-oracle/tables: the runner did not finish; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
  fi

  if selftest_wants reflow-search; then
    # reflow-search/<row> (M4 PR 4, CI only): reflow case (8) branch by
    # branch from tests/fixtures/reflow/search-cases.tsv on a copy of
    # reflow/pass-search with today's search.js (reflow_search_runner),
    # counted with the reflow fixtures.
    local search_rows search_chrome
    search_rows="$(grep -cv '^#\|^$' "$FIXTURES/reflow/search-cases.tsv")"
    reflow_total=$((reflow_total + search_rows))
    if in_github_actions; then
      if search_chrome="$(command -v google-chrome || command -v google-chrome-stable)"; then
        reflow_search_runner "$SELFTEST_ROOT/tools/sitecheck.py" \
          "$FIXTURES/reflow/search-cases.tsv" "$FIXTURES/reflow/pass-search" \
          "$SELFTEST_ROOT/assets/js/search.js" "$search_chrome" >"$out" 2>&1
        sed -n '/^ok   \|^FAIL /p; /^     | /p' "$out"
        n_passed=$((n_passed + $(grep -c '^ok   ' "$out")))
        n_failed=$((n_failed + $(grep -c '^FAIL ' "$out")))
        reflow_run=$((reflow_run + $(grep '^\(ok   \|FAIL \)reflow-search/' "$out" \
          | grep -cv '^\(ok   \|FAIL \)reflow-search/table')))
        if ! grep -qE '^(ok   |FAIL )reflow-search/table' "$out"; then
          echo "FAIL reflow-search: the runner did not finish; output:"
          sed 's/^/     | /' "$out"
          n_failed=$((n_failed + 1))
        fi
      else
        echo "FAIL reflow-search: Google Chrome not found; in CI case (8) must run"
        n_failed=$((n_failed + 1))
      fi
    else
      echo "NOT RUN reflow-search/* ($search_rows rows, CI only)"
    fi
  fi

  if selftest_wants mutate; then
    # mutate/<test> (Replikanti/interviewscam#40, ADR-0008): the unit tests
    # of tools/mutate.py, the sweep runner, on throwaway repositories with a
    # stub self-test (tests/mutate/), one row per case. mutate/unittest
    # fails as worker_check does: on a failing exit, no case run, a skipped
    # case, an expected failure or an unexpected success (unittest reports
    # each of those as OK), and when the case lines do not add up to the
    # count unittest ran.
    local mu_out mu_rc mu_n mu_rows mu_line
    mu_out="$(cd "$SELFTEST_ROOT" && python3 -I -B -m unittest discover -v \
      -s tests/mutate -t tests/mutate -p 'test_*.py' 2>&1)"
    mu_rc=$?
    mu_rows="$(LC_ALL=C sed -n \
      -e 's/^\(test_[A-Za-z0-9_]*\) (.*) \.\.\. ok$/ok   mutate\/\1/p' \
      -e 's/^\(test_[A-Za-z0-9_]*\) (.*) \.\.\. \(FAIL\|ERROR\)$/FAIL mutate\/\1: \2/p' \
      <<<"$mu_out")"
    [[ -n "$mu_rows" ]] && printf '%s\n' "$mu_rows"
    n_passed=$((n_passed + $(grep -c '^ok   ' <<<"$mu_rows")))
    n_failed=$((n_failed + $(grep -c '^FAIL ' <<<"$mu_rows")))
    mu_n="$(sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' <<<"$mu_out")"
    if [[ $mu_rc -ne 0 || -z "$mu_n" || "$mu_n" -eq 0 \
        || "$(grep -c '^ok   ' <<<"$mu_rows")" -ne "$mu_n" ]] \
        || grep -qE 'skipped=|expected failures=|unexpected successes=' <<<"$mu_out"; then
      echo "FAIL mutate/unittest: exit $mu_rc, ${mu_n:-no} cases run, $(grep -c '^ok   ' <<<"$mu_rows") ok (a skipped case, an expected failure and an unexpected success fail too); output:"
      while IFS= read -r mu_line; do echo "     | $mu_line"; done <<<"$mu_out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   mutate/unittest ($mu_n cases)"
      n_passed=$((n_passed + 1))
    fi
  fi

  if selftest_wants selftest-only; then
    selftest_only_rows
  fi

  # The closing invariants hold for the suites that ran: the html pair when
  # html is selected, the reflow pair when reflow or reflow-search is.
  local want_reflow=0
  selftest_wants reflow reflow-search && want_reflow=1
  if selftest_wants html && [[ $html_total -eq 0 ]]; then
    echo "FAIL: no html fixtures found"
    n_failed=$((n_failed + 1))
  fi
  if [[ $want_reflow -eq 1 && $reflow_total -eq 0 ]]; then
    echo "FAIL: no reflow fixtures found"
    n_failed=$((n_failed + 1))
  fi
  if selftest_wants html && in_github_actions && [[ $html_run -ne $html_total ]]; then
    echo "FAIL: only $html_run of $html_total html fixtures ran in CI"
    n_failed=$((n_failed + 1))
  fi
  if [[ $want_reflow -eq 1 ]] && in_github_actions && [[ $reflow_run -ne $reflow_total ]]; then
    echo "FAIL: only $reflow_run of $reflow_total reflow fixtures ran in CI"
    n_failed=$((n_failed + 1))
  fi
  if ! in_github_actions && [[ $html_total -gt 0 ]]; then
    echo "$HTML_NOT_RUN_LINE"
  fi
  if ! in_github_actions && [[ $reflow_total -gt 0 ]]; then
    echo "$REFLOW_NOT_RUN_LINE"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  selftest_main "$@"
fi
