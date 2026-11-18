# ADR-0008: Mutation sweeps on GitHub-hosted runners

## Status

Accepted, 2026-11-18 (operator, Replikanti/interviewscam#40, STOP 1). The numbers are provisional until the second PR of Replikanti/interviewscam#40 measures them (Numbers). The five decisions of STOP 1:

1. **Acceptance set.** The mutant files of M4 PR 4/4 are not recoverable, so the acceptance runs use new sets of the same shape against today's `main`, plus a census of every suite (part 9).
2. **Two PRs.** The first PR adds `selftest.sh --only`, a registration stub of `mutation-sweep.yml` and this ADR; the second adds the runner and the full workflow, sweeps itself from its own head before it merges, and replaces the provisional numbers.
3. **Twenty shards**, written as 20 literal jobs, with no change to the guard (part 6).
4. **Merge locally.** The agent merges the shard results with `mutate.py merge`; no guard exception for `actions/download-artifact` (part 7).
5. **No local full `check.sh` for this repo.** Agent sessions take the result of the `check` job on the pushed head instead; local records-mode runs stay, because private pushes are metered (ADR-0007 part 6).

Implementation: part 4 and the stub of `.github/workflows/mutation-sweep.yml` (first PR); `tools/mutate.py`, `tools/mutate.sh`, the full workflow, `tests/mutate/` and the measured Numbers (second PR).

## Context

- **Every safety-net PR proves its checks by mutation.** The implementer and QA each patch `tools/sitecheck.py` or `assets/js/search.js` in hundreds of ways and run the fixture suites against every mutant, many of them in Chrome. Until this ADR the sweeps ran on the operator's workstation, inside a 3-core cap that other work shares, with tooling kept in each agent's scratch directory.
- **They were the longest step of a fix round.** Measured on M4 PR 4/4 (Replikanti/interviewscam-site-history#2), fix round 2, 2026-11-11: QA's recheck of 101 static and 97 browser mutants started at 20:05 CET and was still running at 01:32 CET; one browser mutant over 53 reflow rows had not finished after 12.5 minutes, and one `render-report` suite (114 rows then) took 19 minutes on about a third of a core. The CI `check` job ran the same suites on one runner, `render-report` in 89 s and `reflow-search` in about 6 minutes. The implementer's sweep of the same round covered 365 mutants, and its local full `check.sh` runs took 88 to 111 minutes under load, against 11 to 17 minutes on an idle machine.
- **Public runners cost no minutes.** Standard GitHub-hosted runners are free for public repositories, and this repo is public since ADR-0007. The operator approved Replikanti/interviewscam#40 on 2026-11-12 on one condition: the sweeps load GitHub's runners, not the local machine.
- **The workflow hardening limits what a workflow can be** (ADR-0007 part 4): a run step is only `bash tools/<name>.sh [--flag]...` (`RUN_ALLOWED`, so no `${{ }}` in it), `env:` is refused (`EXEC_KEYS`), and `actions/download-artifact` is allowed only in the job `lighthouse` of `lighthouse.yml` (ADR-0003 part 2).
- **The self-test had no selection.** `tools/selftest.sh` ran all of its 4190 rows (run 44222078867 on `main`, 2026-11-18), 1484 s of the 1727 s `check` job, for any mutant.

## Decision

### 1. Sweeps run only on GitHub-hosted runners of this repo

A mutation sweep runs only through `.github/workflows/mutation-sweep.yml`, started with `gh workflow run` on a sweep branch; the local machine only starts the run and downloads its results. No sweep, and no part of one, runs locally.

**Why:** the operator's condition of 2026-11-12, and the data above: one runner gives a browser suite a whole machine, which the shared local cap does not, and the runs cost no minutes. **Rejected:** a local sweep under a lower CPU cap (it breaks the operator's condition, and the 3-core cap already made a recheck run past five hours); sweeps in the private repo (metered minutes, and ADR-0007 part 5 allows exactly three workflows there).

### 2. The runner is std-only Python

The second PR adds `tools/mutate.py`, Python 3.11 or newer, standard library only, run as `python3 -I -B` (ADR-0002 part 3), behind the shim `tools/mutate.sh` that `RUN_ALLOWED` requires.

**Why:** the runner orchestrates: it edits text, starts `selftest.sh`, waits with a timeout, kills a process group and writes TSV. No part is CPU-bound, and the code it has to stay in step with (the row format, the `-I -B` conventions of `tools/sitecheck.py`) is std-only Python. **Rejected:** Rust, which the operator prefers, loses here on three concrete costs: every binary of this repo is pinned by SHA-256 in `tools/pins.env`, so a toolchain would need a pinned download in `fetch-tools.sh`; each of the 20 shard jobs would pay that download plus a cold `cargo build`; and a crate directory would need a `FIXTURE_SKIP` entry. Speed buys nothing in a process that waits on `selftest.sh`. bash loses because overlapping exact-once counting on arbitrary Unicode text, strict JSON and TSV escaping are error-prone in it. Third-party mutation tools (mutmut and cosmic-ray for Python, Stryker for scripts in the browser) bring a pip or registry supply chain (D3 for the registry; this repo has no pip dependency), generate operator mutants instead of the targeted per-branch find and replace mutants the QA rule needs, and none drives a bash self-test with named rows.

### 3. The mutant file

A mutant file is `tests/mutants/<name>.jsonl`, committed on a sweep branch: JSON Lines, ASCII only (so every invisible or look-alike character shows as `\uXXXX`), LF only, a final LF, no blank line, one object per mutant with the keys `id`, `suites` and `edits` and optionally `expect` (exact row names) and `note`. Each edit has exactly `file`, `find` and `replace`; `file` is a tracked regular file at `HEAD` that decodes as UTF-8, in a plain relative form; `find` is not empty and differs from `replace`. `suites` is a non-empty list of distinct suite names (part 4), or exactly `["*"]` for the whole self-test. Duplicate keys, `NaN`, `Infinity` and wrong types are refused. An edit must match exactly once, overlapping matches counted, in the text the earlier edits left; otherwise the mutant is INVALID.

**Why:** a committed file is reviewable, passes the public scrub with the rest of the diff, and is tied to the commit the sweep runs. **Rejected:** the mutants as a dispatch input (one string, not reviewable, not scrubbed, not tied to a commit); operator mutants generated by a tool (part 2).

### 4. `selftest.sh --only`

`bash tools/selftest.sh --only SUITE[,SUITE...]` runs only the named suites. A suite is the first path segment of the rows a block prints: the token after `ok   ` or `FAIL ` up to `/`, a space or `:` (`render`, `render-report`, `wiring`, `site-intake-expect`); run 44222078867 shows 42 of them, and the first PR adds `selftest-only`. Every fixture case and every later block of rows is guarded by its suite (`selftest_wants`); a runner whose rows belong to two suites prints only the selected ones (`selftest_rows`), and a block's line for a runner that did not finish names a selected suite (`selftest_suite`). Under `--only` the rows go to a log, which is printed and then checked: a row of an unselected suite, or a selected suite without a row, fails the run with exit 2 (`selftest_selection_check`), so a block that lost its guard, or a misspelt suite, can never pass as a selection. `FAIL:`, `NOT RUN` and detail lines are no rows. The html and reflow invariants hold only for the suites that ran. Usage errors exit 2 before any tool is fetched; a name is `^[a-z0-9][a-z0-9-]*$`, matched against the characters written out, so no locale lets a look-alike, a zero-width character or a newline through. Without `--only` the run and its output are unchanged, and `wiring/selftest-no-args` holds `step_selftest` to `bash "$CHECK_ROOT/tools/selftest.sh"`, so CI never runs a selection.

**Why:** a sweep runs the suites that can kill a mutant, about 450 s for `reflow-search` and 120 s for `render-report` (Numbers), instead of the whole 1484 s self-test for every mutant. The selection is keyed by the row names everybody already reads in the `check` log, so a mutant file names suites the way a QA report names rows. **Weak point:** a mutant killed only by an unselected suite reports SURVIVED. That is the safe direction: every survivor is investigated, and a selection can never turn a survivor into a kill. A suite printed by several blocks (`wiring`, 26 rows) runs all of them; a block that depends on another block's side effects would be partial under selection, which the census (part 9) finds. **Rejected:** selecting by fixture directory (most suites have none); selecting single rows inside the table runners (out of scope for Replikanti/interviewscam#40; a whole suite is cheap enough per mutant, Numbers); a separate test runner beside `selftest.sh` (two copies of every suite drift).

### 5. Controls, verdicts and the TIMEOUT rule

Each shard first runs one unmutated control per distinct suite set of its runnable mutants, in order of first appearance. A control fails on an exit other than 0, any `FAIL` row or a timeout, and then every mutant of the shard is VOID and the shard fails. Each mutant then ends as KILLED (exit 1 with a `FAIL` row; the first failing row is reported), SURVIVED (exit 0, no `FAIL` row), INVALID (an edit does not match exactly once) or TIMEOUT (its run passed the budget B, even after a `FAIL` row). Any other outcome is ERROR, which is no verdict. A timeout never counts as KILLED.

**Why:** a mutant verdict means something only against a green control on the same runner and commit; a hang is not a detection, because a check that hangs in CI blocks the merge instead of naming the fault. **Rejected:** one control per shard for the whole self-test (1484 s, and a red unrelated suite would void every selection); counting a timeout as a kill (it hides a hang behind a green verdict).

### 6. Sharding: 20 literal jobs

`mutation-sweep.yml` holds the jobs `shard-1` to `shard-20`, identical except their index, which the runner reads from `GITHUB_JOB`. Mutant i of the file (0-based, file order) runs in shard (i mod 20) + 1.

**Why:** the guard allows a run step only as `bash tools/<name>.sh [--flag]...` and refuses `env:`, so a matrix leg could not learn its index without relaxing ADR-0007 part 4; literal jobs need no change to the guard. Round-robin spreads the mutants of each suite over all shards, so a file that lists the browser mutants together still balances. **Rejected:** `strategy.matrix` (above); contiguous blocks (a block of browser mutants would land on one shard); fewer or more shards (Numbers).

### 7. Results and the local merge

Each shard uploads its own artifact `shard-<k>`: `results.tsv` (`id verdict killer expected shard seconds`), `meta.txt` (commit, shard, mutant file and its SHA-256, the controls, the deadline), a copy of the mutant file and one log per control and mutant, and it writes its table to the step summary. After `gh run download`, `python3 -I -B tools/mutate.py merge <dir>` checks that all 20 shards are there, of one commit and one mutant file, every mutant in its shard and none VOID, NOT-RUN or ERROR, and prints the merged table in file order.

**Why:** the merge takes under a second and runs no suite, so it costs the local machine nothing. **Weak point:** the run page shows 20 shard tables, not one. **Rejected:** a merge job in the workflow, which needs `actions/download-artifact` outside the job `lighthouse` of `lighthouse.yml`, a guard exception against ADR-0003 part 2.

### 8. Budgets, the shard deadline and the job cap

Per mutant the runner waits B = 2 × T_control + 220 s, T_control the measured time of the shard's control for that suite set. A shard starts a mutant only if elapsed + B ≤ D, the shard deadline, and marks the rest NOT-RUN; so the runner ends cleanly before the job cap, and `timeout-minutes` only ever fires on a hang of the runner itself. The cap follows the method of ADR-0003 part 5: the factor times the slowest green shard job, rounded up to a 5-minute step as in ADR-0004's bucket rule. D = cap − 60 s. Derivations: Numbers.

**Why:** the budget scales with what the same runner just measured, so a slow runner gets longer budgets instead of false TIMEOUTs. **Rejected:** a fixed per-mutant timeout (a browser suite takes 450 s, a static one 120 s); no deadline (the job cap would cut a shard mid-mutant, and its artifact would lose every row).

### 9. Process: sweep branches

1. `git switch -c sweep/<pr>-<impl|qa>-r<round> <PR head sha>`, add `tests/mutants/<pr>-<impl|qa>-r<round>.jsonl`, scrub the staged diff, commit, push.
2. `gh workflow run mutation-sweep.yml -R Replikanti/interviewscam-site --ref <branch> -f mutants=<path>`.
3. Find the run whose head is the pushed commit (`gh run list --workflow mutation-sweep.yml --branch <branch> --event workflow_dispatch --json databaseId,headSha`) and poll `gh run view <id> --json status,conclusion`.
4. `gh run download <id> -D <dir>`, then `python3 -I -B tools/mutate.py merge <dir>`.
5. Delete the sweep branch once the run URL is in the PR or QA comment. Sweep branches are never merged.

QA branches from the PR head on its own, with its own mutant file, so its sweep is independent of the implementer's. The acceptance of the second PR: a census with one mutant per suite (a one-word edit of a prose line in `README.md`, every mutant SURVIVED with every control green, and the union of the control rows equal to the rows of that PR's `check` log), at least 100 browser mutants of `assets/js/search.js` on `reflow-search` and about 100 static mutants of render rule 17 on `render-report`, the two sets each run twice on the same ref with equal `id`, verdict and killer columns.

**Why:** a branch per sweep ties the run to one commit and one reviewed file, and two agents never share one. **Rejected:** sweeping on the PR branch itself (a mutant file in the PR diff, and every sweep push would re-run `check`).

## Numbers

Provisional until the second PR of Replikanti/interviewscam#40 measures the acceptance runs; that PR replaces each value below with its measurement.

| Number | Value | Derivation, and what breaks at another value |
|---|---|---|
| Inputs | measured 2026-11-18 | `check` jobs 1250 s, 1265 s and 1727 s (runs 44149266015, 44217250087, 44222078867). In run 44222078867 the self-test took 1484 s for 4190 rows; from the line timestamps `reflow-search` (84 rows) took about 441 s, `render-report` (115 rows) about 120 s and the `reflow` fixtures (192 rows) about 377 s; fetch-tools 10 s; set up 1 s and checkout 2 s. The artifact upload of `lighthouse` run 44222079001 took 3 s. |
| Setup S | 20 s | Set up, checkout, fetch-tools and a `git worktree add`: 1 to 3 s, 2 to 5 s, 10 s and about 1 s, rounded up. It is paid once per shard, so an error of a few seconds moves no admission. |
| T(reflow-search), T(render-report) | 450 s, 120 s | The 441 s and 120 s above, the first rounded up to a 50 s step. Under `--only` the fixture loop skips every case without a fork (part 4), so the selection adds about 1 s to the suite. The budget takes the control measured on the shard's own runner, so these values only size the shard count and the cap. |
| Budget factor | 2 | The smallest whole factor above 1.46, the spread of the same self-test code on two runners (906 s against 1327 s, ADR-0004 Numbers, "`check.sh` workflow timeouts"). A control and its mutants share one runner, so their spread is at most that. At 1 a runner hiccup turns into TIMEOUT and two runs disagree; at 3 every real hang costs a third more shard time. |
| Budget term | 220 s | One fully used Chrome launch window, 2 × `REFLOW_LAUNCH_TIMEOUT` (75 s), plus the longest stall seen, 70 s (ADR-0003 part 6 data). The runner cannot tell which suites start Chrome, so the term applies to every suite; for a static suite it only delays a hang's TIMEOUT by 220 s. At 0 s a mutant run that meets a launch stall flips to TIMEOUT, and two runs of one file disagree. B(reflow-search) = 2 × 450 + 220 = 1120 s; B(render-report) = 460 s. |
| Shards N | 20 | Wall clock for 100 browser mutants = S + T + ceil(100 / N) × T: N = 10 gives 4970 s (83 min), 20 gives 2720 s (45 min), 30 gives 2270 s (38 min), 50 gives 1370 s (23 min). The org is on GitHub Team; GitHub documents 60 concurrent standard jobs for Team (an assumption until the second PR checks the Actions limits page). Two concurrent sweeps (implementer and QA) plus one PR push of this repo (3 jobs) need 2N + 3: 43 at N = 20, which leaves 17 for the other repos of the org; at N = 28 one is left, and at N = 30 the jobs queue, so the gain from 20 to 30 (7 minutes) is not worth a queue. |
| Job cap | 95 min, provisional | ADR-0003 part 5: the factor 2 times the slowest green shard job, rounded up to a 5-minute step. Estimate: a shard of 5 browser mutants (100 / 20) takes 20 + 450 + 5 × 450 = 2720 s, and 2 × 2720 = 5440 s, rounded up to 5700 s. The second PR replaces it with the slowest green shard job of its acceptance runs, the factor the smallest whole factor above their slowest-to-fastest spread and at least 2. Lower, a normal shard of a slow runner hits the cap and loses its artifact rows; higher, a hung runner holds a job slot longer. |
| Deadline D | cap × 60 − 60 s = 5640 s | The 60 s cover about 8 s before the runner starts (set up, checkout) and about 10 s after it ends (upload 3 s, reaping at most 5 s, writing results under 1 s), three times over. Admission: a mutant starts iff elapsed + B ≤ D; for `reflow-search` that is elapsed ≤ 4520 s. Capacity: mutant k starts at 470 + (k − 1) × 450 ≤ 4520, so k ≤ 10, 10 browser mutants per shard and 200 per sweep; for `render-report` 140 + (k − 1) × 120 ≤ 5180, 43 per shard; for `["*"]` (about 1484 s) one per shard (1504 + 3188 = 4692 ≤ 5640, a second would end at 6176). A smaller margin risks the cap cutting the upload; a larger one only lowers the capacity. |
| Stub job cap | 1 min | The first PR's stub job has no checkout and one step that fails at once, so it ends in seconds; 1 minute is the smallest value `timeout-minutes` takes as a whole number. It holds until the second PR replaces the file. |
| `check` job | unchanged, 60 min | Out of scope. The first PR's new rows (the `selftest-only` suite, about 20 s with three nested runs of `selftest.sh`) are compared with the re-derive trigger of ADR-0004 (a green job over 1754 s); the slowest green `check` job on `main` took 1727 s. |

## Consequences

- Agents trigger sweeps and read results; they never run one locally (part 1). The SDLC routing entry for this repo and the implementer and QA briefs say so from the second PR of Replikanti/interviewscam#40.
- A new block of self-test rows needs a `selftest_wants` guard with the suite it prints; without one, every `--only` run that does not select it fails with `row outside --only`. Renaming a row prefix renames its suite and changes every mutant file that names it (CLAUDE.md, Load-bearing names).
- `mutation-sweep.yml` is on `main` as a stub from the first PR. A run started on `main` before the second PR merges fails within seconds and changes nothing.
- Sweep branches and mutant files are public: every push passes the public scrub, and they hold only code edits, never records.
- A new runner image or Chrome version can move T; the controls absorb it per shard, and the double runs of the acceptance catch flips.
