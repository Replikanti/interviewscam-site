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

import ctypes
import hashlib
import json
import os
import re
import signal
import stat
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


# prctl(2): a child subreaper inherits every orphaned descendant, so no
# process of a run escapes the runner, whatever its session, process group
# or environment (Linux, which the runners are).
PR_SET_CHILD_SUBREAPER = 36
STRAY_SWEEP_S = 10


def set_subreaper(on):
    """Make this process the child subreaper of its descendants (or stop)."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1 if on else 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")


def children():
    """The PIDs whose parent is this process, zombies included."""
    me, kids = os.getpid(), []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                fields = handle.read().rsplit(b")", 1)[1].split()
        except OSError:
            continue
        if int(fields[1]) == me:
            kids.append(int(entry))
    return kids


def kill_strays():
    """SIGKILL and reap every child of the runner after a run. As the child
    subreaper (set_subreaper) the runner is the parent of every process a
    run left behind once its own parent is gone: one started with setsid
    or start_new_session, which killpg never reaches, or with a cleared
    environment. Repeats until no child is left, as each kill orphans the
    next generation to the runner; True when none is left within
    STRAY_SWEEP_S, else the caller ends the shard, because a stray could
    still write to the tree."""
    end = time.monotonic() + STRAY_SWEEP_S
    while True:
        kids = children()
        if not kids:
            return True
        if time.monotonic() > end:
            return False
        for pid in kids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        for pid in kids:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.01)


def drop_mutant_files(tree):
    """Remove MUTANTS_DIR from the shard tree in a commit of the tree's own
    (detached; the checkout and the sweep branch stay as they are), and
    return the commit every run is restored to (restore_tree): that commit,
    or HEAD when HEAD holds no such directory."""
    if git(tree, "ls-tree", "-d", "HEAD", "--", MUTANTS_DIR):
        git(tree, "rm", "-r", "-q", "--", MUTANTS_DIR)
        git(tree, *TREE_COMMIT, "commit", "-q", "--no-verify", "-m",
            f"mutate: the shard tree without {MUTANTS_DIR}/ (ADR-0008 part 3)")
    return git(tree, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()


# Every git call of the restore runs with the runner's own settings, never
# ones a run could have written: no hooks (a planted reference-transaction
# or post-checkout hook would run inside the restore, after kill_strays),
# no fsmonitor command, no global or system config file, no replace refs,
# and none of the variables that point git at another repository.
TREE_GIT_OPTS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                 "--literal-pathspecs")
TREE_GIT_UNSET = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                  "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                  "GIT_NAMESPACE", "GIT_REPLACE_REF_BASE", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
                  "GIT_CONFIG_COUNT", "GIT_ATTR_SOURCE")


def tree_git_env():
    env = {k: v for k, v in os.environ.items() if k not in TREE_GIT_UNSET}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0")
    return env


def tree_git(tree, *args, data=None):
    """(exit code, stdout) of git in the shard tree; never raises."""
    run = subprocess.run(["git", "-C", str(tree), *TREE_GIT_OPTS, *args], input=data,
                         stdin=None if data is not None else subprocess.DEVNULL,
                         capture_output=True, env=tree_git_env())
    return run.returncode, run.stdout


def read_entry(path):
    """(kind, mode, bytes) of a file, a symlink or a whole directory, or
    None when path does not exist; never follows a symlink."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return ("link", 0, os.readlink(path).encode("utf-8", "surrogateescape"))
    if stat.S_ISDIR(st.st_mode):
        return ("dir", st.st_mode & 0o7777, tuple(sorted(
            (name, read_entry(os.path.join(path, name))) for name in os.listdir(path))))
    if stat.S_ISREG(st.st_mode):
        with open(path, "rb") as handle:
            return ("file", st.st_mode & 0o7777, handle.read())
    return ("other", st.st_mode, b"")


def git_state(tree):
    """The git state a run can write that changes what the restore writes
    or what a later run's git does (ADR-0008 part 5): in the common git
    directory config, info/ (attributes, exclude, sparse-checkout, grafts),
    hooks/, shallow and the alternates of objects/info/; in the tree's own
    git directory config.worktree, info/, commondir and gitdir; the tree's
    .git file; the replace refs; the global config files. Compared with
    its value right after drop_mutant_files."""
    rc, out = tree_git(tree, "rev-parse", "--path-format=absolute", "--git-common-dir",
                       "--git-dir")
    if rc != 0:
        return None
    common, own = out.decode("utf-8", "surrogateescape").split("\n")[:2]
    paths = [os.path.join(common, name) for name in
             ("config", "info", "hooks", "shallow", "objects/info/alternates",
              "objects/info/http-alternates")]
    paths += [os.path.join(own, name) for name in ("config.worktree", "info", "commondir",
                                                    "gitdir")]
    paths.append(os.path.join(tree, ".git"))
    home = Path.home()
    paths += [str(home / ".gitconfig"), str(home / ".config" / "git"),
              os.environ.get("XDG_CONFIG_HOME", str(home / ".config")) + "/git"]
    if os.environ.get("GIT_CONFIG_GLOBAL"):
        paths.append(os.environ["GIT_CONFIG_GLOBAL"])
    state = {path: read_entry(path) for path in paths}
    rc, refs = tree_git(tree, "for-each-ref", "--format=%(refname) %(objectname)",
                        "refs/replace/")
    state["refs/replace/"] = (rc, refs)
    state[os.path.join(common, "objects")] = object_store(os.path.join(common, "objects"))
    return state


# Files under objects/ that git may rewrite on its own while a clean run
# only reads (commit-graph upkeep, the dumb-protocol pack list); every
# other change of the object store fails the restore.
OBJECTS_VOLATILE = re.compile(r"info/(?:commit-graph.*|commit-graphs(?:/.*)?|packs)")


def object_store(objects):
    """(path, kind, size, mtime_ns, ctime_ns, inode) of every entry under
    the common objects/ directory but OBJECTS_VOLATILE. Git does not verify
    an object's hash when it reads it, and a loose object shadows a packed
    one of the same name, so a run that writes or rewrites an object file
    changes what a later checkout or `git cat-file` returns; every write
    changes the ctime, which no process can set back. Clean runs only read
    the store (ADR-0008 part 5)."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(objects):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, objects)
            if OBJECTS_VOLATILE.fullmatch(rel):
                continue
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(st.st_mode):
                entries.append((rel, "dir", 0, 0, 0, st.st_ino))
            else:
                entries.append((rel, stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns,
                                st.st_ctime_ns, st.st_ino))
    return tuple(entries)


def tools_cache_problem(tree):
    """Why the toolchain cache the restore leaves in place is unsafe, or
    None: anything under .tools/ that is a symlink or neither a regular file
    nor a directory (a symlinked .tools/cache sends the next run's download
    into a tracked directory, which the content check would only see after
    that run). fetch-tools.sh writes only regular files and directories."""
    top = os.path.join(tree, TOOLS_CACHE)
    try:
        st = os.lstat(top)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        return f"{TOOLS_CACHE} is not a directory"
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            mode = os.lstat(path).st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                return f"{os.path.relpath(path, tree)} is a symlink or special file"
    return None


def tree_content(tree):
    """{path: (kind, executable, bytes)} of every file and symlink in the
    tree but its .git file and the toolchain cache: the checkout output the
    restore must reproduce, read from the disk rather than from git."""
    content = {}
    for dirpath, dirnames, filenames in os.walk(tree):
        rel_dir = os.path.relpath(dirpath, tree)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d != TOOLS_CACHE]
            filenames = [f for f in filenames if f != ".git"]
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if stat.S_ISLNK(st.st_mode):
                content[rel] = ("link", False, os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as handle:
                    content[rel] = ("file", bool(st.st_mode & 0o100), handle.read())
            elif not stat.S_ISDIR(st.st_mode):
                content[rel] = ("other", False, b"")
    return content


class Pristine:
    """The shard tree right after drop_mutant_files: its commit, its git
    state and its content, which every restore must reproduce."""

    def __init__(self, tree, sha):
        self.sha = sha
        self.state = git_state(tree)
        self.content = tree_content(tree)


def restore_tree(tree, pristine):
    """Put the shard tree back to the pristine commit, whatever a run did
    to it, and check the result; None when it holds, else the reason (the
    caller then ends the shard: ERROR, the rest NOT-RUN, because the next
    run would not start from the swept code).

    First the git state of git_state must be what it was: a run that
    changed config (core.autocrlf, a filter, an include), info/ (attributes,
    sparse-checkout), hooks/, the alternates, a replace ref, the tree's git
    files or a global config file fails here, before the restore runs git
    on it. Then HEAD is detached at the commit (a run may commit, move HEAD
    or switch to a branch), every skip-worktree and assume-unchanged bit
    cleared (with one set, reset --hard leaves a changed file as it is), the
    index and the files reset, everything untracked or ignored removed but
    the toolchain cache. Last the outcome: HEAD at the commit, every index
    entry plain (`H ` in ls-files -v), a clean status, and every file of the
    tree byte for byte, executable bit and symlink target as right after
    drop_mutant_files, read from the disk, so no git setting can make a
    changed output look clean."""
    problem = tools_cache_problem(tree)
    if problem:
        return problem
    if git_state(tree) != pristine.state:
        changed = sorted(k for k in pristine.state
                         if (git_state(tree) or {}).get(k) != pristine.state[k])
        return f"git state changed: {', '.join(changed) or 'unreadable'}"
    rc, listing = tree_git(tree, "ls-files", "-v", "-z")
    if rc != 0:
        return "git ls-files failed"
    flagged = [e[2:] for e in listing.split(b"\0") if e and not e.startswith(b"H ")]
    # One flag per call: update-index applies only the last of the two.
    for flag in ("--no-skip-worktree", "--no-assume-unchanged"):
        if flagged and tree_git(tree, "update-index", flag, "-z", "--stdin",
                                data=b"\0".join(flagged) + b"\0")[0] != 0:
            return f"git update-index {flag} failed"
    for args in (("update-ref", "--no-deref", "HEAD", pristine.sha),
                 ("reset", "-q", "--hard", pristine.sha),
                 ("clean", "-ffdxq", "-e", TOOLS_CACHE)):
        if tree_git(tree, *args)[0] != 0:
            return f"git {args[0]} failed"
    rc, head = tree_git(tree, "rev-parse", "--verify", "HEAD")
    if rc != 0 or head.decode().strip() != pristine.sha:
        return "HEAD is not the pristine commit"
    rc, listing = tree_git(tree, "ls-files", "-v", "-z")
    if rc != 0 or any(e and not e.startswith(b"H ") for e in listing.split(b"\0")):
        return "an index entry keeps a skip-worktree or assume-unchanged bit"
    rc, status = tree_git(tree, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                          "--ignored")
    if rc != 0:
        return "git status failed"
    for entry in (e for e in status.split(b"\0") if e):
        path = entry[3:].decode("utf-8", "replace")
        if not (path == TOOLS_CACHE + "/" or path.startswith(TOOLS_CACHE + "/")):
            return f"git status shows {path}"
    content = tree_content(tree)
    if content != pristine.content:
        diff = sorted(k for k in set(content) | set(pristine.content)
                      if content.get(k) != pristine.content.get(k))
        return f"the tree differs from the pristine commit on disk: {', '.join(diff[:5])}"
    return None


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

    def settle(self):
        """After every run: no process of it left (kill_strays), the tree
        back at the commit of drop_mutant_files (restore_tree). None when
        both hold, else the reason."""
        if not kill_strays():
            return f"a process of the run outlived the sweep ({STRAY_SWEEP_S} s)"
        return restore_tree(self.tree, self.pristine)

    def run(self):
        self.logs.mkdir(parents=True)
        try:
            set_subreaper(True)
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
            try:
                kill_strays()
                set_subreaper(False)
            except OSError:
                pass
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
        self.pristine = Pristine(self.tree, drop_mutant_files(self.tree))
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
            problem = self.settle()
            if problem:
                with open(self.logs / "controls" / f"{n}.log", "a", encoding="utf-8") as log:
                    log.write(f"\nmutate: the control fails: {problem}\n")
            if timed_out:
                status = "TIMEOUT"
            elif rc == 0 and not FAIL_LINE.search(output) and not problem:
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
            problem = self.settle()
            if problem:
                with open(self.logs / f"{mid}.log", "a", encoding="utf-8") as log:
                    log.write(f"\nmutate: {verdict} overruled: {problem}; the rest of the "
                              "shard is NOT-RUN\n")
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
    shas, paths, files, shard_rows, present = set(), set(), {}, {}, set()
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
        paths.add(meta.get("mutants_path"))
        files[digest] = data
        shard_rows[k] = [line.split("\t") for line in lines[1:-1]]
        present.add(k)
    if len(shas) > 1:
        problems.append(f"mixed sha: {sorted(shas)}")
    if len(files) > 1:
        problems.append(f"mixed mutant file: {len(files)} different copies")
    if len(paths) > 1:
        problems.append(f"mixed mutant file path: {sorted(map(str, paths))}")
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
            if row[3] not in (("yes", "no", "-") if verdict == "KILLED" else ("-",)):
                problems.append(f"shard-{k}: {mid}: expected {row[3]!r} with {verdict}")
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
    # The header names what was swept, so a merged table cannot be read
    # against another commit or mutant file.
    print(f"mutate: sweep of {', '.join(sorted(map(str, shas))) or '?'} with "
          f"{', '.join(sorted(map(str, paths))) or '?'} (sha256 "
          f"{', '.join(sorted(files)) or '?'})", file=stderr)
    print("\t".join(TSV_HEADER), file=stdout)
    for m in mutants:
        print("\t".join(merged[m["id"]]), file=stdout)
    counts = {}
    for m in mutants:
        counts[merged[m["id"]][1]] = counts.get(merged[m["id"]][1], 0) + 1
    line = (f"mutate: {len(mutants)} mutants: {counts.get('KILLED', 0)} killed, "
            f"{counts.get('SURVIVED', 0)} survived, {counts.get('INVALID', 0)} invalid, "
            f"{counts.get('TIMEOUT', 0)} timeout")
    # A KILLED whose killer is not one of its expected rows (expected=no) is
    # still a kill: some row of the selected suites failed on the mutant and
    # its control was green on the same runner. It is reported on its own,
    # because it can be a kill for another reason than the one the mutant
    # aims at (a flake, a check that fires earlier), which the reader checks
    # in the mutant's log; it does not make the sweep INCOMPLETE (ADR-0008
    # part 7).
    other = sum(1 for m in mutants if merged[m["id"]][1] == "KILLED"
                and merged[m["id"]][3] == "no")
    line += f"; {other} killed by another row (expected=no)"
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
