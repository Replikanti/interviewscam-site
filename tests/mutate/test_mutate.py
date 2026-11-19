"""tools/mutate.py, the mutation sweep runner (ADR-0008, Replikanti/interviewscam#40).

Run by `bash tools/selftest.sh` (suite `mutate`) as python3 -I -B -m
unittest. Never on GitHub's API and never with the real self-test: every
shard case builds a throwaway git repository whose tools/selftest.sh is a
stub driven by the lines of its target.txt, and calls the module's
functions through importlib with an explicit environment, so the CLI keeps
refusing any run outside a workflow_dispatch job. Budgets are shrunk by
patching BUDGET_ADD_S and DEADLINE_S; the admission cases inject a clock
and a runner, so no case waits on a real budget.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "mutation-sweep.yml"
SHIM = ROOT / "tools" / "mutate.sh"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mutate = load("mutate", ROOT / "tools" / "mutate.py")

# The stub self-test. Arguments as the real one takes them; each line of
# target.txt is one instruction, so a mutant decides what the run prints,
# how it ends and what it leaves behind. Suite names steer the control:
# nosuch exits 2 as an unknown suite does, broken fails, slow sleeps.
STUB = r"""#!/usr/bin/env bash
only="*"
if [[ $# -gt 0 ]]; then
  [[ $# -eq 2 && "$1" == --only ]] || { echo "stub: bad arguments" >&2; exit 2; }
  only="$2"
fi
printf '%s\n' "$only" >>"$STUB_DIR/calls"
IFS=, read -ra suites <<<"$only"
for suite in "${suites[@]}"; do
  case "$suite" in
    nosuch) echo "FAIL selftest-only: --only nosuch ran no rows"; exit 2 ;;
    broken) echo "FAIL broken/row: the control fails"; exit 1 ;;
    slow) sleep 30 ;;
  esac
done
while IFS= read -r line; do
  case "$line" in
    "PRINT "*) printf '%s\n' "${line#PRINT }" ;;
    "EXIT "*) exit "${line#EXIT }" ;;
    HANG)
      sleep 300 &
      echo "$!" >"$STUB_DIR/grandchild"
      sleep 300
      ;;
    DIRT) echo dirt >>other.txt; echo junk >untracked.txt; mkdir -p newdir; echo x >newdir/f ;;
    STUCK) mkdir stuck; echo x >stuck/f; chmod 555 stuck ;;
    TOOLS) mkdir -p .tools/cache; echo x >.tools/cache/kept ;;
    CHECKTOOLS) [[ -f .tools/cache/kept ]] || { echo "FAIL s/tools-gone"; exit 1; } ;;
    CHECKCLEAN)
      if [[ "$(cat other.txt)" != other || -e untracked.txt || -e newdir ]]; then
        echo "FAIL s/dirty"
        exit 1
      fi
      ;;
  esac
done <target.txt
echo "ok   s/row"
"""

GIT_ENV = {
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.com",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def setUpModule():
    global SAVED_ENV, GIT_HOME
    SAVED_ENV = dict(os.environ)
    GIT_HOME = tempfile.mkdtemp(prefix="mutate-home-")
    os.environ.update(GIT_ENV)
    os.environ["GIT_CONFIG_GLOBAL"] = str(Path(GIT_HOME) / "gitconfig")
    (Path(GIT_HOME) / "gitconfig").write_text("")


def tearDownModule():
    os.environ.clear()
    os.environ.update(SAVED_ENV)
    shutil.rmtree(GIT_HOME, ignore_errors=True)


def git(root, *args, data=None):
    return subprocess.run(["git", "-C", str(root), *args], input=data, check=True,
                          capture_output=True).stdout


def mutant(mid, find="base", replace="PRINT ok   s/x", suites=("s",), file="target.txt", **extra):
    obj = {"id": mid, "suites": list(suites),
           "edits": [{"file": file, "find": find, "replace": replace}]}
    obj.update(extra)
    return obj


def jsonl(objs):
    return "".join(json.dumps(o) + "\n" for o in objs).encode("ascii")


def unwritable_tree_cleanup(path):
    for dirpath, dirnames, _ in os.walk(path):
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if not os.path.islink(full):
                os.chmod(full, stat.S_IRWXU)


class Repo:
    """A throwaway repository with the stub self-test and one mutant file."""

    def __init__(self, case, mutants=None, raw=None, extra=None):
        self.tmp = Path(tempfile.mkdtemp(prefix="mutate-test-"))
        case.addCleanup(self.cleanup)
        self.root = self.tmp / "repo"
        self.stub_dir = self.tmp / "stub"
        self.stub_dir.mkdir()
        self.root.mkdir()
        git(self.root, "init", "-q", "-b", "main")
        files = {
            "tools/selftest.sh": STUB,
            "tools/mutate.py": "# a placeholder the mutants may edit\n",
            ".github/workflows/x.yml": "name: x\n",
            "target.txt": "base\n",
            "other.txt": "other\n",
            ".gitignore": ".tools/\n",
        }
        files.update(extra or {})
        for rel, text in files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        data = raw if raw is not None else jsonl(mutants or [])
        self.mutants_rel = "tests/mutants/m.jsonl"
        (self.root / self.mutants_rel).parent.mkdir(parents=True)
        (self.root / self.mutants_rel).write_bytes(data)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "stub")
        self.head = git(self.root, "rev-parse", "HEAD").decode().strip()
        self.runs = 0

    def cleanup(self):
        unwritable_tree_cleanup(self.tmp)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, shard=1, **over):
        self.runs += 1
        temp = self.tmp / f"runner-{self.runs}"
        temp.mkdir()
        event = self.tmp / f"event-{self.runs}.json"
        event.write_text(json.dumps({"inputs": {"mutants": self.mutants_rel}}))
        env = {
            "PATH": os.environ["PATH"],
            "HOME": GIT_HOME,
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_JOB": f"shard-{shard}",
            "GITHUB_SHA": self.head,
            "GITHUB_EVENT_PATH": str(event),
            "RUNNER_TEMP": str(temp),
            "GITHUB_STEP_SUMMARY": str(temp / "summary.md"),
            "STUB_DIR": str(self.stub_dir),
        }
        env.update({k: v for k, v in os.environ.items() if k.startswith("GIT_")})
        for key, value in over.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        return env

    def run(self, shard=1, env=None, **kwargs):
        env = env or self.env(shard)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = mutate.shard_main(env, self.root, **kwargs)
        out = Path(env.get("RUNNER_TEMP", "/nonexistent")) / "mutate" / "out"
        return rc, out, err.getvalue()

    def calls(self):
        path = self.stub_dir / "calls"
        return path.read_text().splitlines() if path.exists() else []


def rows(out):
    lines = (out / "results.tsv").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "\t".join(mutate.TSV_HEADER), lines[0]
    return {line.split("\t")[0]: line.split("\t") for line in lines[1:]}


def verdicts(out):
    return {mid: row[1] for mid, row in rows(out).items()}


def meta(out):
    return (out / "meta.txt").read_text(encoding="utf-8").splitlines()


class Patched(unittest.TestCase):
    """Shard cases on one shard with short budgets."""

    def setUp(self):
        self.saved = {name: getattr(mutate, name)
                      for name in ("SHARDS", "BUDGET_ADD_S", "DEADLINE_S")}
        mutate.SHARDS = 1
        mutate.BUDGET_ADD_S = 0.5
        mutate.DEADLINE_S = 60

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(mutate, name, value)


class Load(unittest.TestCase):

    def refuse(self, data, needle=""):
        with self.assertRaises(mutate.InputError) as ctx:
            mutate.parse_mutants(data)
        self.assertIn(needle, str(ctx.exception))

    def test_load_refuses_empty(self):
        self.refuse(b"", "no mutants")
        repo = Repo(self, raw=b"")
        rc, _, err = repo.run()
        self.assertEqual(rc, 2)
        self.assertIn("no mutants", err)

    def test_load_refuses_bad_ids(self):
        for bad in ("Upper", "ab\u0430", "a\u200bb", "a" * 101, "", "-a", "a b", ".a"):
            with self.subTest(id=bad):
                self.refuse(jsonl([mutant(bad)]), "id")
        self.refuse(jsonl([mutant("a"), mutant("a", replace="x")]), "duplicate id")
        self.assertEqual(len(mutate.parse_mutants(jsonl([mutant("a" * 100)]))), 1)

    def test_identical_edits_allowed(self):
        loaded = mutate.parse_mutants(jsonl([mutant("a"), mutant("b")]))
        self.assertEqual([m["id"] for m in loaded], ["a", "b"])

    def test_load_refuses_malformed(self):
        good = json.dumps(mutant("a"))
        cases = {
            "blank line": (good + "\n\n" + json.dumps(mutant("b")) + "\n").encode(),
            "crlf": (good + "\r\n").encode(),
            "bom": b"\xef\xbb\xbf" + (good + "\n").encode(),
            "non-ascii": (good[:-1] + ', "note": "\u00e9"}\n').encode("utf-8"),
            "no final lf": good.encode(),
            "duplicate key": (good[:-1] + ', "id": "b"}\n').encode(),
            "unknown key": (good[:-1] + ', "extra": 1}\n').encode(),
            "nan": (good[:-1] + ', "note": NaN}\n').encode(),
            "infinity": (good[:-1] + ', "note": -Infinity}\n').encode(),
            "not an object": b"[1]\n",
            "not json": b"{\n",
            "id type": jsonl([{"id": 1, "suites": ["s"], "edits": []}]),
            "suites type": jsonl([{"id": "a", "suites": "s", "edits": [
                {"file": "f", "find": "x", "replace": "y"}]}]),
            "edits type": jsonl([{"id": "a", "suites": ["s"], "edits": {}}]),
            "empty edits": jsonl([{"id": "a", "suites": ["s"], "edits": []}]),
            "edit key missing": jsonl([{"id": "a", "suites": ["s"], "edits": [
                {"file": "f", "find": "x"}]}]),
            "edit key extra": jsonl([{"id": "a", "suites": ["s"], "edits": [
                {"file": "f", "find": "x", "replace": "y", "z": "w"}]}]),
            "edit value type": jsonl([{"id": "a", "suites": ["s"], "edits": [
                {"file": "f", "find": True, "replace": "y"}]}]),
            "empty find": jsonl([mutant("a", find="")]),
            "find equals replace": jsonl([mutant("a", find="x", replace="x")]),
            "expect type": jsonl([mutant("a", expect="s/a")]),
            "expect empty": jsonl([mutant("a", expect=[])]),
            "expect empty name": jsonl([mutant("a", expect=[""])]),
            "expect duplicate": jsonl([mutant("a", expect=["s/a", "s/a"])]),
            "note type": jsonl([mutant("a", note=3)]),
            "missing id": jsonl([{"suites": ["s"], "edits": [
                {"file": "f", "find": "x", "replace": "y"}]}]),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                self.refuse(data)

    def test_load_refuses_suites(self):
        for suites in ([], ["s", "s"], ["*", "render"], ["Render"], ["r\u0430"],
                       ["-r"], ["a/b"], [""], ["*", "*"], [1]):
            with self.subTest(suites=suites):
                self.refuse(jsonl([mutant("a", suites=suites)]), "suites")
        self.assertEqual(mutate.parse_mutants(jsonl([mutant("a", suites=["*"])]))[0]["suites"],
                         ("*",))

    def test_load_refuses_paths(self):
        repo = Repo(self, mutants=[mutant("a")], extra={
            "bad.txt": b"\xff\xfe\n", "dir/inner.txt": "x\n"})
        os.symlink("target.txt", repo.root / "link.txt")
        git(repo.root, "add", "link.txt")
        git(repo.root, "update-index", "--add", "--cacheinfo",
            f"160000,{repo.head},sub")
        git(repo.root, "commit", "-q", "-m", "more")
        (repo.root / "untracked.txt").write_text("x\n")
        bad = ["/abs/target.txt", "../target.txt", "dir/../target.txt", "./target.txt",
               "dir//inner.txt", "dir\\inner.txt", "dir/", "~/target.txt", "link.txt",
               "untracked.txt", "dir", "sub", "bad.txt", "missing.txt", "", "a\nb",
               "target.txt\u0000", "*.txt", ":(glob)*.txt"]
        for path in bad:
            with self.subTest(path=path):
                with self.assertRaises(mutate.InputError) as ctx:
                    mutate.target_texts(repo.root, mutate.parse_mutants(
                        jsonl([mutant("a", file=path)])))
                self.assertIn("file", str(ctx.exception))
        texts = mutate.target_texts(repo.root, mutate.parse_mutants(jsonl([
            mutant("a", file="dir/inner.txt", find="x", replace="y")])))
        self.assertEqual(texts, {"dir/inner.txt": "x\n"})


class Edits(unittest.TestCase):

    def test_overlapping_find_is_invalid(self):
        self.assertEqual("aaa".count("aa"), 1)
        self.assertEqual(mutate.count_overlapping("aaa", "aa"), 2)
        m = mutate.parse_mutants(jsonl([mutant("a", find="aa", replace="b")]))[0]
        result, reason = mutate.apply_edits({"target.txt": "aaa"}, m)
        self.assertIsNone(result)
        self.assertIn("2", reason)

    def test_invalid_counts(self):
        for text, count in (("zzz", 0), ("base base", 2)):
            with self.subTest(text=text):
                m = mutate.parse_mutants(jsonl([mutant("a")]))[0]
                result, reason = mutate.apply_edits({"target.txt": text}, m)
                self.assertIsNone(result)
                self.assertIn(f"{count}", reason)

    def test_second_edit_sees_first(self):
        m = mutate.parse_mutants(jsonl([{"id": "a", "suites": ["s"], "edits": [
            {"file": "target.txt", "find": "base", "replace": "next"},
            {"file": "target.txt", "find": "next", "replace": "last"}]}]))[0]
        result, _ = mutate.apply_edits({"target.txt": "base\n"}, m)
        self.assertEqual(result, {"target.txt": "last\n"})

    def test_edit_creating_second_match_invalid(self):
        m = mutate.parse_mutants(jsonl([{"id": "a", "suites": ["s"], "edits": [
            {"file": "target.txt", "find": "base", "replace": "one one"},
            {"file": "target.txt", "find": "one", "replace": "two"}]}]))[0]
        result, reason = mutate.apply_edits({"target.txt": "base\n"}, m)
        self.assertIsNone(result)
        self.assertIn("edit 2", reason)

    def test_assign_first_last(self):
        self.assertEqual(mutate.SHARDS, 20)
        self.assertEqual([mutate.assign(i) for i in range(20)], list(range(1, 21)))
        self.assertEqual(mutate.assign(20), 1)
        self.assertEqual([i for i in range(21) if mutate.assign(i) == 1], [0, 20])
        self.assertEqual(mutate.assign(39), 20)

    def test_budget_formula(self):
        self.assertEqual(mutate.budget(450), 1120)
        self.assertAlmostEqual(mutate.budget(0.1), 220.2)

    def test_classify_table(self):
        cases = [
            ((0, "ok   s/a\n", False), ("SURVIVED", None)),
            ((1, "ok   s/a\nFAIL s/b: x\nFAIL s/c: y\n", False), ("KILLED", "s/b")),
            ((1, "ok   s/a\n", False), ("ERROR", None)),
            ((0, "FAIL s/b: x\n", False), ("ERROR", None)),
            ((2, "FAIL s/b: x\n", False), ("ERROR", None)),
            ((3, "", False), ("ERROR", None)),
            ((-9, "FAIL s/b\n", True), ("TIMEOUT", None)),
            ((0, "", True), ("TIMEOUT", None)),
            ((1, "     | FAIL s/b: a detail line\n", False), ("ERROR", None)),
        ]
        for args, want in cases:
            with self.subTest(args=args):
                self.assertEqual(mutate.classify(*args), want)

    def test_killer_row_name_forms(self):
        self.assertEqual(mutate.classify(1, "FAIL a/b c\n", False), ("KILLED", "a/b"))
        self.assertEqual(mutate.classify(1, "FAIL: no html fixtures found\n", False),
                         ("KILLED", "selftest"))
        self.assertEqual(mutate.classify(1, "FAIL a/b:c d\n", False), ("KILLED", "a/b"))
        self.assertEqual(mutate.classify(1, "FAIL reflow-search\tx\n", False),
                         ("KILLED", "reflow-search"))
        self.assertEqual(mutate.classify(1, "FAILED x\nFAIL a/b\n", False), ("KILLED", "a/b"))

    def test_tsv_escaping(self):
        cases = {"a\tb": "a\\tb", "a\nb": "a\\nb", "a\rb": "a\\rb", "a\\b": "a\\\\b",
                 "a\u200bb": "a\\u200bb", "\u00e9": "\\u00e9", "\U0001f600": "\\U0001f600",
                 "\x7f": "\\u007f", "plain/row-1": "plain/row-1"}
        for raw, escaped in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(mutate.escape(raw), escaped)
                self.assertEqual(mutate.unescape(escaped), raw)
                self.assertTrue(all(0x20 <= ord(c) < 0x7f for c in escaped))
        for broken in ("a\\", "\\x", "\\u12", "\\U0011ffff"):
            with self.subTest(broken=broken):
                with self.assertRaises(ValueError):
                    mutate.unescape(broken)


class Shard(Patched):

    def test_empty_shard_complete(self):
        mutate.SHARDS = 20
        repo = Repo(self, mutants=[mutant("a")])
        rc, out, _ = repo.run(shard=2)
        self.assertEqual(rc, 0)
        self.assertEqual(rows(out), {})
        self.assertIn("complete yes", meta(out))
        self.assertFalse([line for line in meta(out) if line.startswith("control ")])
        self.assertEqual(repo.calls(), [])
        rc, out, _ = repo.run(shard=1)
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED"}))

    def test_star_runs_full_selftest(self):
        repo = Repo(self, mutants=[mutant("a", suites=["*"]), mutant("b", suites=["s", "t"])])
        rc, out, _ = repo.run()
        self.assertEqual(rc, 0)
        self.assertEqual(repo.calls(), ["*", "s,t", "*", "s,t"])

    def test_unknown_suite_voids_shard(self):
        repo = Repo(self, mutants=[mutant("a", suites=["nosuch"]), mutant("b")])
        rc, out, _ = repo.run()
        self.assertEqual(rc, 1)
        self.assertEqual(verdicts(out), {"a": "VOID", "b": "VOID"})
        self.assertIn("complete no", meta(out))

    def test_control_per_suite_set_order(self):
        repo = Repo(self, mutants=[mutant("a", suites=["t"]), mutant("b", suites=["s", "t"]),
                                   mutant("c", suites=["t", "s"]), mutant("d", suites=["t"]),
                                   mutant("e")])
        rc, out, _ = repo.run()
        self.assertEqual(rc, 0)
        self.assertEqual(repo.calls()[:3], ["t", "s,t", "s"])
        controls = [line.split()[1:3] for line in meta(out) if line.startswith("control ")]
        self.assertEqual(controls, [["t", "PASS"], ["s,t", "PASS"], ["s", "PASS"]])

    def test_control_failure_voids_shard(self):
        repo = Repo(self, mutants=[mutant("a"), mutant("b", suites=["broken"]),
                                   mutant("z", find="nothing")])
        rc, out, _ = repo.run()
        self.assertEqual(rc, 1)
        self.assertEqual(set(verdicts(out).values()), {"VOID"})
        self.assertIn("control broken FAIL", " ".join(meta(out)))

    def test_no_controls_when_all_invalid(self):
        repo = Repo(self, mutants=[mutant("a", find="nothing"), mutant("b", find="zz")])
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "INVALID", "b": "INVALID"}))
        self.assertEqual(repo.calls(), [])
        self.assertIn("complete yes", meta(out))

    def test_runner_files_mutable_in_tree(self):
        repo = Repo(self, mutants=[
            mutant("a", file="tools/mutate.py", find="placeholder", replace="changed"),
            mutant("b", file=".github/workflows/x.yml", find="x", replace="y")])
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED", "b": "SURVIVED"}))
        self.assertIn("placeholder", (repo.root / "tools/mutate.py").read_text())

    def test_identical_edits_run(self):
        repo = Repo(self, mutants=[mutant("a"), mutant("b")])
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED", "b": "SURVIVED"}))

    def test_verdicts_and_expected_column(self):
        repo = Repo(self, mutants=[
            mutant("k", replace="PRINT FAIL s/b: x\nEXIT 1", expect=["s/b"]),
            mutant("n", replace="PRINT FAIL s/c: x\nEXIT 1", expect=["s/b"]),
            mutant("s", expect=["s/b"]),
            mutant("i", find="nothing"),
            mutant("e", replace="EXIT 3")])
        rc, out, _ = repo.run()
        got = rows(out)
        self.assertEqual(rc, 1)
        self.assertEqual({k: v[1:4] for k, v in got.items()}, {
            "k": ["KILLED", "s/b", "yes"], "n": ["KILLED", "s/c", "no"],
            "s": ["SURVIVED", "-", "-"], "i": ["INVALID", "-", "-"], "e": ["ERROR", "-", "-"]})
        self.assertTrue((out / "logs" / "k.log").exists())
        self.assertTrue((out / "logs" / "i.log").exists())
        self.assertEqual((out / "mutants.jsonl").read_bytes(),
                         (repo.root / repo.mutants_rel).read_bytes())

    def test_timeout_after_fail_row_is_timeout(self):
        repo = Repo(self, mutants=[mutant("a", replace="PRINT FAIL s/b: x\nHANG")])
        started = time.monotonic()
        rc, out, _ = repo.run()
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual((rc, verdicts(out)), (0, {"a": "TIMEOUT"}))
        self.assertIn("FAIL s/b: x", (out / "logs" / "a.log").read_text())

    def test_timeout_kills_grandchildren(self):
        repo = Repo(self, mutants=[mutant("a", replace="HANG")])
        rc, out, _ = repo.run()
        self.assertEqual(verdicts(out), {"a": "TIMEOUT"})
        pid = int((repo.stub_dir / "grandchild").read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and alive(pid):
            time.sleep(0.05)
        self.assertFalse(alive(pid), f"grandchild {pid} survived the kill")

    def test_admission_boundary(self):
        mutate.BUDGET_ADD_S = 5
        for deadline, want in ((35, {"a": "SURVIVED", "b": "NOT-RUN", "c": "NOT-RUN"}),
                               (34, {"a": "NOT-RUN", "b": "NOT-RUN", "c": "NOT-RUN"})):
            with self.subTest(deadline=deadline):
                mutate.DEADLINE_S = deadline
                repo = Repo(self, mutants=[mutant("a"), mutant("b"), mutant("c")])
                clock = FakeClock()
                rc, out, _ = repo.run(clock=clock, runner=clock.runner([10, 1, 1, 1]))
                # Control 10 s, so B = 2 x 10 + 5 = 25; mutant a may start
                # at elapsed 10 iff 10 + 25 <= D; after it, 11 + 25 > 35.
                self.assertEqual(verdicts(out), want)
                self.assertEqual(rc, 1)
                self.assertEqual(clock.timeouts[1:], [25] if deadline == 35 else [])

    def test_control_deadline(self):
        mutate.DEADLINE_S = 0.5
        repo = Repo(self, mutants=[mutant("a", suites=["slow"]), mutant("b")])
        started = time.monotonic()
        rc, out, _ = repo.run()
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual((rc, verdicts(out)), (1, {"a": "VOID", "b": "VOID"}))
        self.assertIn("control slow TIMEOUT", " ".join(meta(out)))

    def test_tree_restored_after_dirt(self):
        repo = Repo(self, mutants=[mutant("a", replace="DIRT"),
                                   mutant("b", replace="CHECKCLEAN")])
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED", "b": "SURVIVED"}))

    def test_restore_keeps_tools_cache(self):
        repo = Repo(self, mutants=[mutant("a", replace="TOOLS"),
                                   mutant("b", replace="CHECKTOOLS")])
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED", "b": "SURVIVED"}))

    def test_unrestorable_tree_aborts(self):
        repo = Repo(self, mutants=[mutant("a", replace="STUCK"), mutant("b"), mutant("c")])
        rc, out, _ = repo.run()
        self.assertEqual(rc, 1)
        self.assertEqual(verdicts(out), {"a": "ERROR", "b": "NOT-RUN", "c": "NOT-RUN"})
        self.assertIn("complete no", meta(out))

    def test_internal_error_writes_partial_results(self):
        repo = Repo(self, mutants=[mutant("a"), mutant("b"), mutant("c")])
        calls = []

        def runner(tree, suites, timeout, log_path, env):
            calls.append(suites)
            if len(calls) == 3:
                raise RuntimeError("injected")
            log_path.write_text("ok   s/row\n")
            return 0, "ok   s/row\n", False

        rc, out, err = repo.run(runner=runner)
        self.assertEqual(rc, 1)
        self.assertEqual(verdicts(out), {"a": "SURVIVED", "b": "ERROR", "c": "ERROR"})
        self.assertIn("injected", (out / "logs" / "internal-error.log").read_text())
        self.assertIn("RuntimeError", err)
        self.assertIn("complete no", meta(out))
        # The upload step runs on a failed step too.
        self.assertIn("if: always()", upload_steps(WORKFLOW.read_text())[0])

    def test_summary_escapes_pipe(self):
        repo = Repo(self, mutants=[mutant("a", replace="PRINT FAIL a|b/c\u200b: x\nEXIT 1")])
        env = repo.env()
        rc, out, _ = repo.run(env=env)
        self.assertEqual(rows(out)["a"][2], "a|b/c\\u200b")
        summary = Path(env["GITHUB_STEP_SUMMARY"]).read_text()
        line = next(line for line in summary.splitlines() if line.startswith("| a |"))
        self.assertIn("a\\|b/c\\u200b", line)
        self.assertEqual(len(re.findall(r"(?<!\\)\|", line)), 6)

    def test_shard_env_refusals(self):
        mutate.SHARDS = 20
        repo = Repo(self, mutants=[mutant("a")])
        bad_paths = ["/abs/m.jsonl", "tests/mutants/../mutants/m.jsonl", "tests/m.jsonl",
                     "tests/mutants/m.json", "tests/mutants/M.jsonl",
                     "tests/mutants/m\u0430.jsonl", "tests/mutants/m\u200b.jsonl",
                     "tests/mutants/link.jsonl", "tests/mutants/untracked.jsonl",
                     "tests/mutants/missing.jsonl", "", "tests/mutants/m.jsonl\n"]
        os.symlink("m.jsonl", repo.root / "tests/mutants/link.jsonl")
        git(repo.root, "add", "tests/mutants/link.jsonl")
        git(repo.root, "commit", "-q", "-m", "link")
        repo.head = git(repo.root, "rev-parse", "HEAD").decode().strip()
        for path in bad_paths:
            with self.subTest(mutants=path):
                env = repo.env()
                Path(env["GITHUB_EVENT_PATH"]).write_text(json.dumps({"inputs": {"mutants": path}}))
                if path == "tests/mutants/untracked.jsonl":
                    (repo.root / path).write_text("")
                rc, _, _ = repo.run(env=env)
                (repo.root / "tests/mutants/untracked.jsonl").unlink(missing_ok=True)
                self.assertEqual(rc, 2)
        for name, over in {
                "event push": {"GITHUB_EVENT_NAME": "push"},
                "shard-0": {"GITHUB_JOB": "shard-0"}, "shard-21": {"GITHUB_JOB": "shard-21"},
                "shard-01": {"GITHUB_JOB": "shard-01"}, "shard-1x": {"GITHUB_JOB": "shard-1x"},
                "job unset": {"GITHUB_JOB": None}, "outside actions": {"GITHUB_ACTIONS": None},
                "actions false": {"GITHUB_ACTIONS": "false"},
                "sha mismatch": {"GITHUB_SHA": "0" * 40},
                "no event file": {"GITHUB_EVENT_PATH": None},
                "no runner temp": {"RUNNER_TEMP": None}}.items():
            with self.subTest(env=name):
                rc, _, _ = repo.run(env=repo.env(**over))
                self.assertEqual(rc, 2)
        (repo.root / "dirt.txt").write_text("x")
        rc, _, err = repo.run()
        self.assertEqual(rc, 2)
        self.assertIn("clean", err)
        (repo.root / "dirt.txt").unlink()
        rc, out, _ = repo.run()
        self.assertEqual((rc, verdicts(out)), (0, {"a": "SURVIVED"}))

    def test_two_runs_same_results(self):
        objs = [mutant("k", replace="PRINT FAIL s/b: x\nEXIT 1"), mutant("s"),
                mutant("i", find="nothing"), mutant("t", replace="HANG")]
        repo = Repo(self, mutants=objs)
        first = [row[:3] for row in rows(repo.run()[1]).values()]
        second = [row[:3] for row in rows(repo.run()[1]).values()]
        self.assertEqual(first, second)
        self.assertEqual([r[1] for r in first], ["KILLED", "SURVIVED", "INVALID", "TIMEOUT"])


class Merge(unittest.TestCase):
    """merge over 20 real stub shards (three mutants, so 17 empty shards)."""

    @classmethod
    def setUpClass(cls):
        cls.saved = mutate.BUDGET_ADD_S
        mutate.BUDGET_ADD_S = 0.5
        cls.objs = [mutant("a", replace="PRINT FAIL s/b\u00e9\tx\nEXIT 1"),
                    mutant("b"), mutant("c", find="nothing")]
        cls.cleanups = []
        cls.repo = Repo(cls, mutants=cls.objs)
        cls.sweep = cls.repo.tmp / "sweep"
        for k in range(1, 21):
            rc, out, _ = cls.repo.run(shard=k)
            assert rc == 0, (k, rc)
            shutil.copytree(out, cls.sweep / f"shard-{k}")

    @classmethod
    def addCleanup(cls, func, *args):
        cls.cleanups.append(lambda: func(*args))

    @classmethod
    def tearDownClass(cls):
        mutate.BUDGET_ADD_S = cls.saved
        for func in cls.cleanups:
            func()

    def merged(self, sweep):
        out, err = io.StringIO(), io.StringIO()
        rc = mutate.merge_main(sweep, out, err)
        return rc, out.getvalue(), err.getvalue()

    def copy(self):
        target = Path(tempfile.mkdtemp(prefix="mutate-merge-")) / "sweep"
        self.addCleanup(shutil.rmtree, target.parent, True)
        shutil.copytree(self.sweep, target)
        return target

    def test_merge_complete(self):
        rc, out, err = self.merged(self.sweep)
        self.assertEqual(rc, 0, err)
        self.assertIn("mutate: 3 mutants: 1 killed, 1 survived, 1 invalid, 0 timeout; complete",
                      err)
        lines = out.splitlines()
        self.assertEqual(lines[0], "\t".join(mutate.TSV_HEADER))
        self.assertEqual([line.split("\t")[:2] for line in lines[1:]],
                         [["a", "KILLED"], ["b", "SURVIVED"], ["c", "INVALID"]])

    def test_merge_round_trip(self):
        _, out, _ = self.merged(self.sweep)
        merged = {line.split("\t")[0]: line.split("\t") for line in out.splitlines()[1:]}
        for k in (1, 2, 3):
            shard = rows(self.sweep / f"shard-{k}")
            for mid, row in shard.items():
                self.assertEqual(merged[mid], row)
        self.assertEqual(merged["a"][2], "s/b\\u00e9")
        self.assertEqual(mutate.unescape(merged["a"][2]), "s/b\u00e9")

    def incomplete(self, sweep, needle):
        rc, _, err = self.merged(sweep)
        self.assertEqual(rc, 1, err)
        self.assertIn("INCOMPLETE", err)
        self.assertIn(needle, err)

    def test_merge_incomplete_missing_shard(self):
        sweep = self.copy()
        shutil.rmtree(sweep / "shard-2")
        rc, out, err = self.merged(sweep)
        self.assertEqual(rc, 1)
        self.assertIn("b\tMISSING", out)
        self.assertIn("shard-2", err)

    def test_merge_incomplete_duplicate_shard(self):
        sweep = self.copy()
        text = (sweep / "shard-5" / "meta.txt").read_text().replace("shard 5\n", "shard 4\n")
        (sweep / "shard-5" / "meta.txt").write_text(text)
        self.incomplete(sweep, "shard-5")

    def test_merge_incomplete_extra_entry(self):
        sweep = self.copy()
        shutil.copytree(sweep / "shard-1", sweep / "shard-01")
        self.incomplete(sweep, "shard-01")

    def test_merge_incomplete_mixed_sha(self):
        sweep = self.copy()
        path = sweep / "shard-3" / "meta.txt"
        path.write_text(re.sub(r"(?m)^sha \S+", "sha " + "f" * 40, path.read_text()))
        self.incomplete(sweep, "sha")

    def test_merge_incomplete_mixed_file(self):
        sweep = self.copy()
        data = jsonl(self.objs + [mutant("d")])
        (sweep / "shard-4" / "mutants.jsonl").write_bytes(data)
        path = sweep / "shard-4" / "meta.txt"
        path.write_text(re.sub(r"(?m)^mutants_sha256 \S+",
                               "mutants_sha256 " + hashlib.sha256(data).hexdigest(),
                               path.read_text()))
        self.incomplete(sweep, "mutant file")

    def test_merge_incomplete_wrong_shard(self):
        sweep = self.copy()
        self.move_row(sweep, "b", 2, 3)
        self.incomplete(sweep, "shard-3")

    def test_merge_incomplete_unknown_id(self):
        sweep = self.copy()
        with open(sweep / "shard-3" / "results.tsv", "a") as handle:
            handle.write("zz\tSURVIVED\t-\t-\t3\t1.0\n")
        self.incomplete(sweep, "zz")

    def test_merge_incomplete_duplicate_id(self):
        sweep = self.copy()
        with open(sweep / "shard-2" / "results.tsv", "a") as handle:
            handle.write("b\tSURVIVED\t-\t-\t2\t1.0\n")
        self.incomplete(sweep, "twice")

    def test_merge_incomplete_verdicts(self):
        for verdict in ("VOID", "NOT-RUN", "ERROR", "BOGUS"):
            with self.subTest(verdict=verdict):
                sweep = self.copy()
                path = sweep / "shard-2" / "results.tsv"
                path.write_text(path.read_text().replace("\tSURVIVED\t", f"\t{verdict}\t"))
                self.incomplete(sweep, verdict)

    def test_merge_incomplete_bad_killer(self):
        sweep = self.copy()
        path = sweep / "shard-1" / "results.tsv"
        path.write_text(path.read_text().replace("\tKILLED\ts/b\\u00e9\t", "\tKILLED\ts\\q\t"))
        self.incomplete(sweep, "killer")

    def move_row(self, sweep, mid, src, dst):
        src_path = sweep / f"shard-{src}" / "results.tsv"
        lines = src_path.read_text().splitlines(keepends=True)
        row = next(line for line in lines if line.startswith(mid + "\t"))
        src_path.write_text("".join(line for line in lines if line is not row))
        with open(sweep / f"shard-{dst}" / "results.tsv", "a") as handle:
            handle.write(row)


class Files(unittest.TestCase):
    """The workflow, the shim and the constants agree (ADR-0008 Numbers)."""

    def jobs(self):
        text = WORKFLOW.read_text()
        head, sep, body = text.partition("\njobs:\n")
        self.assertTrue(sep)
        blocks = re.split(r"(?m)^(?=  shard-\d+:\n)", body)
        self.assertEqual(blocks[0], "")
        return head, blocks[1:]

    def test_workflow_job_count_equals_shards(self):
        _, blocks = self.jobs()
        self.assertEqual(len(blocks), mutate.SHARDS)
        self.assertEqual([re.match(r"  (shard-\d+):", b).group(1) for b in blocks],
                         [f"shard-{k}" for k in range(1, mutate.SHARDS + 1)])

    def test_workflow_shards_identical(self):
        _, blocks = self.jobs()
        first = blocks[0]
        self.assertEqual(first.count("shard-1"), 2)  # the job key and the artifact
        for k, block in enumerate(blocks[1:], 2):
            with self.subTest(shard=k):
                self.assertEqual(block.rstrip("\n"), first.replace("shard-1", f"shard-{k}")
                                 .rstrip("\n"))

    def test_workflow_timeout_matches_deadline(self):
        _, blocks = self.jobs()
        for block in blocks:
            minutes = re.findall(r"(?m)^    timeout-minutes: (\d+)$", block)
            self.assertEqual(minutes, [str(mutate.JOB_TIMEOUT_MIN)])
        self.assertEqual(mutate.JOB_TIMEOUT_MIN * 60 - mutate.DEADLINE_MARGIN_S,
                         mutate.DEADLINE_S)

    def test_workflow_trigger_and_permissions(self):
        head, blocks = self.jobs()
        self.assertIn("\non:\n  workflow_dispatch:\n    inputs:\n      mutants:\n", head)
        self.assertEqual(re.findall(r"(?m)^[^\s#].*$", head),
                         ["name: mutation-sweep", "on:", "permissions:"])
        self.assertIn("\npermissions:\n  contents: read\n", head)
        self.assertNotIn("concurrency", WORKFLOW.read_text())
        for block in blocks:
            self.assertIn("    runs-on: ubuntu-24.04\n", block)
            self.assertIn("        run: bash tools/mutate.sh --shard\n", block)
            self.assertIn("          persist-credentials: false\n", block)
            upload = upload_steps(block)
            self.assertEqual(len(upload), 1)
            for line in ("if: always()", "path: ${{ runner.temp }}/mutate/out",
                         "if-no-files-found: error", "retention-days: 90"):
                self.assertIn(line, upload[0])

    def test_mutate_sh_exec_line(self):
        text = SHIM.read_text()
        execs = [line.strip() for line in text.splitlines() if "exec " in line
                 and not line.lstrip().startswith("#")]
        self.assertEqual(execs, ['exec python3 -I -B "$root/tools/mutate.py" shard'])
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        for args in ([], ["--bogus"], ["--shard", "x"], ["shard"]):
            with self.subTest(args=args):
                run = subprocess.run(["bash", str(SHIM), *args], capture_output=True,
                                     text=True, env=env)
                self.assertEqual(run.returncode, 2)
                self.assertIn("usage: bash tools/mutate.sh --shard", run.stderr)
        run = subprocess.run(["bash", str(SHIM), "--shard"], capture_output=True, text=True,
                             env=env)
        self.assertEqual(run.returncode, 2)
        self.assertIn("GITHUB_ACTIONS", run.stderr)

    def test_budget_constants(self):
        self.assertEqual((mutate.SHARDS, mutate.BUDGET_FACTOR, mutate.BUDGET_ADD_S,
                          mutate.DEADLINE_MARGIN_S), (20, 2, 220, 60))
        self.assertEqual(mutate.DEADLINE_S, mutate.JOB_TIMEOUT_MIN * 60 - 60)


def upload_steps(text):
    return re.findall(r"(?ms)^      - uses: actions/upload-artifact@.*?(?=^      - |^  \S|\Z)",
                      text)


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


class FakeClock:
    """A clock that moves only when the fake runner says a run took time."""

    def __init__(self):
        self.now = 0.0
        self.timeouts = []

    def __call__(self):
        return self.now

    def runner(self, durations):
        durations = list(durations)

        def run(tree, suites, timeout, log_path, env):
            self.timeouts.append(timeout)
            self.now += durations.pop(0)
            log_path.write_text("ok   s/row\n")
            return 0, "ok   s/row\n", False
        return run


if __name__ == "__main__":
    unittest.main()
