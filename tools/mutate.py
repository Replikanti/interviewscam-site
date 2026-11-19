#!/usr/bin/env python3
"""Mutation sweeps on GitHub-hosted runners (ADR-0008, Replikanti/interviewscam#40).

Standard library only, Python 3.11 or newer, always run as `python3 -I -B`
(ADR-0008 part 2). Never run locally but for `merge`: a sweep runs only
through .github/workflows/mutation-sweep.yml (ADR-0008 part 1).

Subcommands. Each exits 2 on a usage or input error.

  shard
      One shard job of mutation-sweep.yml, started by `bash tools/mutate.sh
      --shard`. Refuses (exit 2) anything but a workflow_dispatch job named
      shard-<k> (1 <= k <= SHARDS) on a clean checkout whose HEAD is
      GITHUB_SHA, with the input `mutants` naming a tracked regular file
      tests/mutants/<name>.jsonl. It loads the whole mutant file (part 3),
      takes mutant i (0-based) when (i mod SHARDS) + 1 == k, marks INVALID
      the mutants whose edits do not each match exactly once, adds a
      detached worktree of HEAD under $RUNNER_TEMP/mutate/tree, runs one
      unmutated control per distinct suite set and then each mutant there
      with `bash tools/selftest.sh [--only <suites>]` (part 5), restoring
      the tree after every run. It writes $RUNNER_TEMP/mutate/out/
      (results.tsv, meta.txt, mutants.jsonl, logs/) and a table to
      $GITHUB_STEP_SUMMARY. Exit 0 when every mutant of the shard has a
      verdict (KILLED, SURVIVED, INVALID, TIMEOUT), else 1.
  merge DIR
      DIR holds the downloaded artifacts shard-1 to shard-SHARDS (`gh run
      download`). Prints the merged results.tsv in mutant file order and
      on stderr the summary line; exit 0 when the sweep is complete, 1
      (INCOMPLETE) on a missing or duplicate shard, mixed commits or mutant
      files, a row in the wrong shard, a duplicate or unknown id, or any
      mutant without a verdict.
"""

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ADR-0008 Numbers. BUDGET_ADD_S and DEADLINE_S are read at call time, so
# tests/mutate shrinks them by patching the module.
SHARDS = 20
BUDGET_FACTOR = 2
BUDGET_ADD_S = 220
DEADLINE_MARGIN_S = 60
# Equal to timeout-minutes of every job of mutation-sweep.yml
# (test_workflow_timeout_matches_deadline).
JOB_TIMEOUT_MIN = 170
DEADLINE_S = JOB_TIMEOUT_MIN * 60 - DEADLINE_MARGIN_S

MUTANTS_PATH_RE = re.compile(r"tests/mutants/[a-z0-9][a-z0-9._-]*\.jsonl")
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
SUITE_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
JOB_RE = re.compile(r"shard-([1-9][0-9]*)")
# A failing row of selftest.sh: `FAIL <row>...` or a global `FAIL: ...`
# line. Detail lines start with spaces and never count.
FAIL_LINE = re.compile(r"^FAIL[ :].*$", re.MULTILINE)

VERDICTS = ("KILLED", "SURVIVED", "INVALID", "TIMEOUT")
NO_VERDICT = ("VOID", "NOT-RUN", "ERROR")
TSV_HEADER = ("id", "verdict", "killer", "expected", "shard", "seconds")
MUTANT_KEYS = {"id", "suites", "edits"}
MUTANT_OPTIONAL = {"expect", "note"}
EDIT_KEYS = {"file", "find", "replace"}
REGULAR_MODES = ("100644", "100755")
# The fetched toolchain may stay in the tree between runs (fetch-tools.sh
# re-verifies it on every run of selftest.sh).
TOOLS_CACHE = ".tools"
# The mutant files live on the sweep branch only (ADR-0008 part 3), and the
# guard's PT2a refuses a multi-line JSON Lines file anywhere outside
# content/ (ADR-0007 part 4), so a suite that runs the guard on a copy of
# the tree (records-mode) would fail on them in every sweep. The shard tree
# therefore drops this directory in a throwaway commit of its own and is
# restored to that commit: it equals the swept code without the mutant
# files, and no guard rule changes.
MUTANTS_DIR = "tests/mutants"
# The throwaway commit of the shard tree: a fixed identity, no signing and
# no hooks, so no configuration of the runner can change or stop it.
TREE_COMMIT = ("-c", "user.name=mutate", "-c", "user.email=mutate@invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null")


class InputError(Exception):
    """A usage or input error: exit 2."""


class Interrupted(Exception):
    """SIGTERM, SIGHUP or SIGINT during a shard (a cancelled job)."""


def git(root, *args, check=True):
    """The stdout bytes of `git -C root --literal-pathspecs args`."""
    run = subprocess.run(["git", "-C", str(root), "--literal-pathspecs", *args],
                         stdin=subprocess.DEVNULL, capture_output=True)
    if check and run.returncode != 0:
        raise InputError(f"git {' '.join(args)}: exit {run.returncode}: "
                         f"{run.stderr.decode('utf-8', 'replace').strip()}")
    return run.stdout


# ---------------------------------------------------------------------------
# The mutant file (ADR-0008 part 3)

def _pairs(pairs):
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a key twice in one object: {sorted(k for k in keys if keys.count(k) > 1)[0]!r}")
    return dict(pairs)


def _constant(name):
    raise ValueError(f"{name} is not JSON")


def _string(value):
    return type(value) is str


def path_problem(path):
    """Why a mutant's `file` is not in the plain relative form, or None."""
    if not path:
        return "is empty"
    if path.startswith(("/", "~")):
        return "is absolute or starts with ~"
    for bad in ("..", "./", "//", "\\"):
        if bad in path:
            return f"holds {bad!r}"
    if path.endswith("/"):
        return "ends with /"
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in path):
        return "holds a control character"
    if path == MUTANTS_DIR or path.startswith(MUTANTS_DIR + "/"):
        return f"is under {MUTANTS_DIR}/, which the shard tree does not hold"
    return None


def parse_mutants(data):
    """The mutants of a mutant file's bytes, checked for form and types; no
    repository needed. Raises InputError naming the line."""
    if not data:
        raise InputError("the mutant file holds no mutants")
    if any(b >= 0x80 for b in data):
        raise InputError("the mutant file must be ASCII only (write other characters as \\uXXXX)")
    if b"\r" in data:
        raise InputError("the mutant file must use LF line ends only")
    if not data.endswith(b"\n"):
        raise InputError("the mutant file must end with a LF")
    mutants, seen = [], set()
    for n, line in enumerate(data.decode("ascii").split("\n")[:-1], 1):
        where = f"mutant file line {n}"
        if not line.strip():
            raise InputError(f"{where}: a blank line")
        try:
            obj = json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
        except ValueError as exc:
            raise InputError(f"{where}: not one JSON object: {exc}") from None
        if type(obj) is not dict:
            raise InputError(f"{where}: not a JSON object")
        missing = MUTANT_KEYS - obj.keys()
        extra = obj.keys() - MUTANT_KEYS - MUTANT_OPTIONAL
        if missing or extra:
            raise InputError(f"{where}: keys missing {sorted(missing)}, unknown {sorted(extra)}")
        mid = obj["id"]
        if not _string(mid) or not ID_RE.fullmatch(mid):
            raise InputError(f"{where}: id {mid!r} is not {ID_RE.pattern}")
        if mid in seen:
            raise InputError(f"{where}: duplicate id {mid!r}")
        seen.add(mid)
        suites = obj["suites"]
        if (type(suites) is not list or not suites or not all(_string(s) for s in suites)
                or len(set(suites)) != len(suites)
                or (suites != ["*"] and not all(SUITE_RE.fullmatch(s) for s in suites))):
            raise InputError(f"{where}: suites {suites!r} must be a non-empty list of distinct "
                             f"names {SUITE_RE.pattern}, or exactly [\"*\"]")
        edits = obj["edits"]
        if type(edits) is not list or not edits:
            raise InputError(f"{where}: edits must be a non-empty list")
        parsed = []
        for e, edit in enumerate(edits, 1):
            if type(edit) is not dict or edit.keys() != EDIT_KEYS:
                raise InputError(f"{where}: edit {e} must have exactly the keys file, find, replace")
            if not all(_string(edit[k]) for k in EDIT_KEYS):
                raise InputError(f"{where}: edit {e}: file, find and replace must be strings")
            problem = path_problem(edit["file"])
            if problem:
                raise InputError(f"{where}: edit {e}: file {edit['file']!r} {problem}")
            if not edit["find"]:
                raise InputError(f"{where}: edit {e}: find is empty")
            if edit["find"] == edit["replace"]:
                raise InputError(f"{where}: edit {e}: find equals replace")
            parsed.append((edit["file"], edit["find"], edit["replace"]))
        expect = obj.get("expect")
        if expect is not None and (
                type(expect) is not list or not expect
                or not all(_string(x) and x and not re.search(r"[\s:]", x) for x in expect)
                or len(set(expect)) != len(expect)):
            raise InputError(f"{where}: expect must be a non-empty list of distinct row "
                             "names without whitespace or ':'")
        if "note" in obj and not _string(obj["note"]):
            raise InputError(f"{where}: note must be a string")
        mutants.append({"id": mid, "suites": tuple(suites), "edits": parsed,
                        "expect": tuple(expect) if expect else None})
    return mutants


def blob_at_head(root, rel, what):
    """The bytes of a tracked regular file at HEAD, or InputError."""
    out = git(root, "ls-tree", "-z", "HEAD", "--", rel)
    entries = [e for e in out.split(b"\0") if e]
    if len(entries) != 1:
        raise InputError(f"{what} {rel!r} is not a tracked file at HEAD")
    head, _, path = entries[0].partition(b"\t")
    mode, kind, oid = head.decode("ascii", "replace").split(" ")
    if path != rel.encode("utf-8", "surrogateescape") or kind != "blob" or mode not in REGULAR_MODES:
        raise InputError(f"{what} {rel!r} is not a regular file at HEAD (mode {mode}, {kind})")
    return git(root, "cat-file", "blob", oid)


def target_texts(root, mutants):
    """{file: HEAD text} for every file an edit names: each a tracked
    regular file at HEAD that decodes as UTF-8."""
    texts = {}
    for m in mutants:
        for rel, _, _ in m["edits"]:
            if rel in texts:
                continue
            data = blob_at_head(root, rel, f"mutant {m['id']}: file")
            try:
                texts[rel] = data.decode("utf-8")
            except UnicodeDecodeError:
                raise InputError(f"mutant {m['id']}: file {rel!r} is not UTF-8") from None
    return texts


def count_overlapping(text, find):
    """Occurrences of find in text, overlapping ones counted ("aa" in "aaa"
    is 2; str.count says 1)."""
    count, i = 0, text.find(find)
    while i != -1:
        count += 1
        i = text.find(find, i + 1)
    return count


def apply_edits(texts, mutant):
    """({file: text} after the mutant's edits in order, None) or (None, the
    reason it is INVALID): every find must match exactly once in the text
    the earlier edits left."""
    result = {}
    for e, (rel, find, replace) in enumerate(mutant["edits"], 1):
        text = result.get(rel, texts[rel])
        count = count_overlapping(text, find)
        if count != 1:
            return None, f"edit {e} ({rel}): find matches {count} times, not exactly once"
        result[rel] = text.replace(find, replace, 1)
    return result, None


def assign(index):
    """The shard of mutant `index` (0-based, file order)."""
    return index % SHARDS + 1


def budget(control_s):
    """B = BUDGET_FACTOR x T_control + BUDGET_ADD_S (ADR-0008 part 8)."""
    return BUDGET_FACTOR * control_s + BUDGET_ADD_S


# ---------------------------------------------------------------------------
# Runs and verdicts (ADR-0008 part 5)

def killer_of(line):
    """The row name of a FAIL line: the token after `FAIL ` up to ':' or
    whitespace; `selftest` for a global `FAIL:` line."""
    if line.startswith("FAIL:"):
        return "selftest"
    token = re.split(r"[:\s]", line[5:], maxsplit=1)[0]
    return token or "selftest"


def classify(rc, output, timed_out):
    """(verdict, killer) of one run; ERROR is no verdict."""
    if timed_out:
        return "TIMEOUT", None
    fails = FAIL_LINE.findall(output)
    if rc == 0 and not fails:
        return "SURVIVED", None
    if rc == 1 and fails:
        return "KILLED", killer_of(fails[0])
    return "ERROR", None


def selftest_command(suites):
    if suites == ("*",):
        return ["bash", "tools/selftest.sh"]
    return ["bash", "tools/selftest.sh", "--only", ",".join(suites)]


def run_selftest(tree, suites, timeout, log_path, env):
    """Run selftest.sh in tree in a new session, its output to log_path.
    At the timeout, or once the leader has exited, the whole process group
    gets SIGKILL before the leader is reaped (so its PGID cannot be reused
    in between and no background child keeps writing to the tree).
    Returns (exit code, output, timed out)."""
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(selftest_command(suites), cwd=tree, env=env,
                                stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            end = time.monotonic() + max(timeout, 0)
            while True:
                done = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if done is not None:
                    break
                left = end - time.monotonic()
                if left <= 0:
                    timed_out = True
                    break
                time.sleep(min(0.05, left))
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
    output = Path(log_path).read_bytes().decode("utf-8", "replace")
    return proc.returncode, output, timed_out


def drop_mutant_files(tree):
    """Remove MUTANTS_DIR from the shard tree in a commit of the tree's own
    (detached; the checkout and the sweep branch stay as they are), so
    restore_tree resets every run to the swept code without the mutant
    files. Nothing to do when HEAD holds no such directory."""
    if not git(tree, "ls-tree", "-d", "HEAD", "--", MUTANTS_DIR):
        return
    git(tree, "rm", "-r", "-q", "--", MUTANTS_DIR)
    git(tree, *TREE_COMMIT, "commit", "-q", "--no-verify", "-m",
        f"mutate: the shard tree without {MUTANTS_DIR}/ (ADR-0008 part 3)")


def restore_tree(tree):
    """Reset the worktree to HEAD and remove everything untracked or
    ignored but the toolchain cache; True when git then shows nothing
    else."""
    for args in (("reset", "-q", "--hard", "HEAD"),
                 ("clean", "-ffdxq", "-e", TOOLS_CACHE)):
        if subprocess.run(["git", "-C", str(tree), *args], stdin=subprocess.DEVNULL,
                          capture_output=True).returncode != 0:
            return False
    status = subprocess.run(["git", "-C", str(tree), "status", "--porcelain=v1", "-z",
                             "--untracked-files=all", "--ignored"],
                            stdin=subprocess.DEVNULL, capture_output=True)
    if status.returncode != 0:
        return False
    for entry in (e for e in status.stdout.split(b"\0") if e):
        path = entry[3:].decode("utf-8", "replace")
        if not (path == TOOLS_CACHE + "/" or path.startswith(TOOLS_CACHE + "/")):
            return False
    return True


# ---------------------------------------------------------------------------
# Output

def escape(text):
    """A TSV-safe, printable-ASCII form of text that unescape() inverts."""
    out = []
    for c in text:
        if c == "\\":
            out.append("\\\\")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif 0x20 <= ord(c) < 0x7f:
            out.append(c)
        elif ord(c) <= 0xffff:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"\\U{ord(c):08x}")
    return "".join(out)


ESCAPE = re.compile(r"\\(?:([\\tnr])|u([0-9a-f]{4})|U([0-9a-f]{8})|(.|$))", re.DOTALL)


def unescape(text):
    def one(match):
        simple, short, long_, bad = match.groups()
        if simple:
            return {"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}[simple]
        code = int(short or long_ or "0", 16)
        if bad is not None or code > 0x10ffff:
            raise ValueError(f"bad escape in {text!r}")
        return chr(code)
    return ESCAPE.sub(one, text)


def format_row(mid, row, shard):
    killer = escape(row["killer"]) if row.get("killer") else "-"
    seconds = f"{row['seconds']:.1f}" if row.get("seconds") is not None else "-"
    return [mid, row["verdict"], killer, row.get("expected", "-"), str(shard), seconds]


def summary_cell(text):
    return text.replace("|", "\\|")


# ---------------------------------------------------------------------------
# shard

def shard_env(env, root):
    """(shard index, mutants path) after the checks of step 1, or
    InputError."""
    if env.get("GITHUB_ACTIONS") != "true":
        raise InputError("shard runs only under GitHub Actions (GITHUB_ACTIONS=true); "
                         "sweeps never run locally (ADR-0008 part 1)")
    if env.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise InputError(f"shard runs only on workflow_dispatch, not {env.get('GITHUB_EVENT_NAME')!r}")
    match = JOB_RE.fullmatch(env.get("GITHUB_JOB", ""))
    if not match or not 1 <= int(match.group(1)) <= SHARDS:
        raise InputError(f"GITHUB_JOB {env.get('GITHUB_JOB')!r} is not shard-1 to shard-{SHARDS}")
    temp = env.get("RUNNER_TEMP", "")
    if not temp or not Path(temp).is_absolute() or not Path(temp).is_dir():
        raise InputError(f"RUNNER_TEMP {temp!r} is not an existing absolute directory")
    top = git(root, "rev-parse", "--show-toplevel").decode().strip()
    if Path(top).resolve() != Path(root).resolve():
        raise InputError(f"{root} is not the top of its git work tree")
    if git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored"):
        raise InputError("the checkout is not clean (git status shows changes, untracked "
                         "or ignored files)")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    if head != env.get("GITHUB_SHA"):
        raise InputError(f"HEAD {head} is not GITHUB_SHA {env.get('GITHUB_SHA')!r}")
    try:
        with open(env.get("GITHUB_EVENT_PATH", ""), encoding="utf-8") as handle:
            event = json.load(handle)
        rel = event["inputs"]["mutants"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"cannot read the input mutants from GITHUB_EVENT_PATH: {exc!r}") from None
    if not _string(rel) or not MUTANTS_PATH_RE.fullmatch(rel):
        raise InputError(f"input mutants {rel!r} is not {MUTANTS_PATH_RE.pattern}")
    return int(match.group(1)), rel, head


class Shard:
    """One shard run: controls, mutants, restores and the outputs."""

    def __init__(self, *, root, shard, sha, rel, data, mutants, texts, env, clock, runner, start):
        self.root, self.shard, self.sha, self.rel = root, shard, sha, rel
        self.data, self.mutants, self.texts = data, mutants, texts
        self.env, self.clock, self.runner, self.start = env, clock, runner, start
        base = Path(env["RUNNER_TEMP"]) / "mutate"
        self.tree, self.out = base / "tree", base / "out"
        self.logs = self.out / "logs"
        self.mine = [m for i, m in enumerate(mutants) if assign(i) == shard]
        self.rows = {}
        self.controls = []
        self.deadline = DEADLINE_S

    def elapsed(self):
        return self.clock() - self.start

    def timed_run(self, suites, timeout, log):
        started = self.clock()
        rc, output, timed_out = self.runner(self.tree, suites, timeout, log, self.env)
        return rc, output, timed_out, self.clock() - started

    def run(self):
        self.logs.mkdir(parents=True)
        try:
            self.sweep()
        except Exception as exc:  # partial results, ERROR for the rest (step 9)
            trace = traceback.format_exc()
            (self.logs / "internal-error.log").write_text(trace, encoding="utf-8")
            print(trace, file=sys.stderr, end="")
            print(f"mutate: internal error: {exc!r}; the rest of the shard is ERROR",
                  file=sys.stderr)
            for m in self.mine:
                self.rows.setdefault(m["id"], {"verdict": "ERROR"})
        finally:
            self.write()
        complete = all(self.rows.get(m["id"], {}).get("verdict") in VERDICTS for m in self.mine)
        return 0 if complete else 1

    def sweep(self):
        edited = {}
        for m in self.mine:
            result, reason = apply_edits(self.texts, m)
            if result is None:
                self.rows[m["id"]] = {"verdict": "INVALID"}
                (self.logs / f"{m['id']}.log").write_text(f"INVALID: {reason}\n", encoding="utf-8")
            else:
                edited[m["id"]] = result
        runnable = [m for m in self.mine if m["id"] in edited]
        if not runnable:
            return
        git(self.root, "worktree", "add", "-q", "--detach", str(self.tree), "HEAD")
        drop_mutant_files(self.tree)
        sets = []
        for m in runnable:
            key = tuple(sorted(m["suites"]))
            if key not in sets:
                sets.append(key)
        times = {}
        (self.logs / "controls").mkdir()
        for n, key in enumerate(sets, 1):
            remaining = self.deadline - self.elapsed()
            rc, output, timed_out, seconds = self.timed_run(
                key, remaining, self.logs / "controls" / f"{n}.log")
            restored = restore_tree(self.tree)
            if timed_out:
                status = "TIMEOUT"
            elif rc == 0 and not FAIL_LINE.search(output) and restored:
                status = "PASS"
            else:
                status = "FAIL"
            self.controls.append((key, status, seconds))
            if status != "PASS":
                for m in self.mine:
                    self.rows[m["id"]] = {"verdict": "VOID"}
                return
            times[key] = seconds
        stop = False
        for m in runnable:
            mid = m["id"]
            key = tuple(sorted(m["suites"]))
            limit = budget(times[key])
            if stop or self.elapsed() + limit > self.deadline:
                stop = True
                self.rows[mid] = {"verdict": "NOT-RUN"}
                continue
            for rel, text in edited[mid].items():
                (self.tree / rel).write_bytes(text.encode("utf-8"))
            rc, output, timed_out, seconds = self.timed_run(key, limit, self.logs / f"{mid}.log")
            verdict, killer = classify(rc, output, timed_out)
            row = {"verdict": verdict, "killer": killer, "seconds": seconds}
            if verdict == "KILLED" and m["expect"]:
                row["expected"] = "yes" if killer in m["expect"] else "no"
            if not restore_tree(self.tree):
                with open(self.logs / f"{mid}.log", "a", encoding="utf-8") as log:
                    log.write(f"\nmutate: {verdict} overruled: the tree could not be restored "
                              "to HEAD; the rest of the shard is NOT-RUN\n")
                row = {"verdict": "ERROR", "seconds": seconds}
                stop = True
            self.rows[mid] = row

    def write(self):
        lines = ["\t".join(TSV_HEADER)]
        for m in self.mine:
            lines.append("\t".join(format_row(m["id"], self.rows.get(m["id"], {"verdict": "ERROR"}),
                                              self.shard)))
        (self.out / "results.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
        complete = all(self.rows.get(m["id"], {}).get("verdict") in VERDICTS for m in self.mine)
        meta = [f"sha {self.sha}", f"shard {self.shard}", f"shards {SHARDS}",
                f"mutants_path {self.rel}",
                f"mutants_sha256 {hashlib.sha256(self.data).hexdigest()}"]
        meta += [f"control {','.join(key)} {status} {seconds:.1f}"
                 for key, status, seconds in self.controls]
        meta += [f"deadline_s {self.deadline}", f"complete {'yes' if complete else 'no'}"]
        (self.out / "meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        (self.out / "mutants.jsonl").write_bytes(self.data)
        summary = self.env.get("GITHUB_STEP_SUMMARY")
        if summary:
            counts = {v: 0 for v in VERDICTS + NO_VERDICT}
            for m in self.mine:
                counts[self.rows.get(m["id"], {"verdict": "ERROR"})["verdict"]] += 1
            text = [f"### mutate shard-{self.shard}: {len(self.mine)} mutants, "
                    + ", ".join(f"{n} {v.lower()}" for v, n in counts.items() if n)
                    + f"; {'complete' if complete else 'INCOMPLETE'}", ""]
            for key, status, seconds in self.controls:
                text.append(f"- control `{summary_cell(','.join(key))}`: {status}, {seconds:.1f} s")
            text += ["", "| id | verdict | killer | expected | seconds |", "|---|---|---|---|---|"]
            for line in lines[1:]:
                mid, verdict, killer, expected, _, seconds = line.split("\t")
                text.append(f"| {mid} | {verdict} | {summary_cell(killer)} | {expected} | {seconds} |")
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write("\n".join(text) + "\n")


def shard_main(env, root=ROOT, clock=time.monotonic, runner=run_selftest):
    start = clock()
    try:
        shard, rel, sha = shard_env(env, root)
        data = blob_at_head(root, rel, "input mutants")
        mutants = parse_mutants(data)
        texts = target_texts(root, mutants)
        out = Path(env["RUNNER_TEMP"]) / "mutate"
        if out.exists():
            raise InputError(f"{out} exists already")
    except InputError as exc:
        print(f"mutate: {exc}", file=sys.stderr)
        return 2
    return Shard(root=root, shard=shard, sha=sha, rel=rel, data=data, mutants=mutants,
                 texts=texts, env=env, clock=clock, runner=runner, start=start).run()


# ---------------------------------------------------------------------------
# merge

def read_meta(path):
    meta, controls = {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(" ")
        if key == "control":
            controls.append(value)
        elif key in meta:
            raise ValueError(f"{key} twice")
        else:
            meta[key] = value
    return meta, controls


def merge_main(directory, stdout=sys.stdout, stderr=sys.stderr):
    directory = Path(directory)
    if not directory.is_dir():
        print(f"mutate: {directory} is not a directory", file=stderr)
        return 2
    problems = []
    names = {f"shard-{k}" for k in range(1, SHARDS + 1)}
    for entry in sorted(os.listdir(directory)):
        if entry not in names:
            problems.append(f"unexpected entry {entry!r} (only shard-1 to shard-{SHARDS})")
    shas, files, shard_rows, present = set(), {}, {}, set()
    for k in range(1, SHARDS + 1):
        base = directory / f"shard-{k}"
        if not base.is_dir():
            problems.append(f"shard-{k} is missing")
            continue
        try:
            meta, _ = read_meta(base / "meta.txt")
            data = (base / "mutants.jsonl").read_bytes()
            lines = (base / "results.tsv").read_text(encoding="utf-8").split("\n")
        except (OSError, ValueError) as exc:
            problems.append(f"shard-{k}: unreadable: {exc}")
            continue
        if meta.get("shard") != str(k) or meta.get("shards") != str(SHARDS):
            problems.append(f"shard-{k} holds shard {meta.get('shard')!r} of "
                            f"{meta.get('shards')!r} (a duplicate or foreign shard)")
            continue
        digest = hashlib.sha256(data).hexdigest()
        if meta.get("mutants_sha256") != digest:
            problems.append(f"shard-{k}: its mutant file copy is not mutants_sha256")
        if meta.get("complete") != "yes":
            problems.append(f"shard-{k}: complete {meta.get('complete')!r}")
        if lines[0] != "\t".join(TSV_HEADER) or lines[-1] != "":
            problems.append(f"shard-{k}: results.tsv is not the shard format")
            continue
        shas.add(meta.get("sha"))
        files[digest] = data
        shard_rows[k] = [line.split("\t") for line in lines[1:-1]]
        present.add(k)
    if len(shas) > 1:
        problems.append(f"mixed sha: {sorted(shas)}")
    if len(files) > 1:
        problems.append(f"mixed mutant file: {len(files)} different copies")
    mutants = []
    if files:
        try:
            mutants = parse_mutants(next(iter(files.values())))
        except InputError as exc:
            problems.append(f"the mutant file: {exc}")
    index = {m["id"]: i for i, m in enumerate(mutants)}
    merged = {}
    for k, rows in shard_rows.items():
        for row in rows:
            if len(row) != len(TSV_HEADER):
                problems.append(f"shard-{k}: a row with {len(row)} fields")
                continue
            mid, verdict, killer = row[0], row[1], row[2]
            if mid not in index:
                problems.append(f"shard-{k}: unknown id {mid!r}")
                continue
            if assign(index[mid]) != k or row[4] != str(k):
                problems.append(f"shard-{k}: {mid} belongs in shard-{assign(index[mid])}")
                continue
            if mid in merged:
                problems.append(f"shard-{k}: {mid} twice")
                continue
            if verdict not in VERDICTS:
                problems.append(f"shard-{k}: {mid} is {verdict}")
            if killer != "-":
                try:
                    if escape(unescape(killer)) != killer:
                        raise ValueError("not canonical")
                except ValueError:
                    problems.append(f"shard-{k}: {mid}: killer {killer!r} is not escaped")
            merged[mid] = row
    for i, m in enumerate(mutants):
        if m["id"] not in merged:
            shard = assign(i)
            if shard in present:
                problems.append(f"shard-{shard}: no row for {m['id']}")
            merged[m["id"]] = [m["id"], "MISSING", "-", "-", str(shard), "-"]
    print("\t".join(TSV_HEADER), file=stdout)
    for m in mutants:
        print("\t".join(merged[m["id"]]), file=stdout)
    counts = {}
    for m in mutants:
        counts[merged[m["id"]][1]] = counts.get(merged[m["id"]][1], 0) + 1
    line = (f"mutate: {len(mutants)} mutants: {counts.get('KILLED', 0)} killed, "
            f"{counts.get('SURVIVED', 0)} survived, {counts.get('INVALID', 0)} invalid, "
            f"{counts.get('TIMEOUT', 0)} timeout")
    for problem in problems:
        print(f"mutate: {problem}", file=stderr)
    if problems:
        rest = ", ".join(f"{n} {v.lower()}" for v, n in sorted(counts.items())
                         if v not in VERDICTS)
        print(f"{line}; INCOMPLETE: {len(problems)} problems" + (f", {rest}" if rest else ""),
              file=stderr)
        return 1
    print(f"{line}; complete", file=stderr)
    return 0


# ---------------------------------------------------------------------------

USAGE = "usage: python3 -I -B tools/mutate.py shard | merge DIR"


def main(argv):
    if argv == ["shard"]:
        def interrupted(signum, frame):
            raise Interrupted(f"signal {signal.Signals(signum).name}")
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            signal.signal(sig, interrupted)
        return shard_main(dict(os.environ))
    if len(argv) == 2 and argv[0] == "merge":
        return merge_main(argv[1])
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
