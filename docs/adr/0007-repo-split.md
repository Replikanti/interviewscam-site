# ADR-0007: Repo split, a public code repo and a private records repo

## Status

Accepted, 2026-11-16 (operator, Replikanti/interviewscam#38, STOP 1). Amends SPEC D4 and D5, §5, §9 and §11. The four decisions of STOP 1:

1. **History rebuilt fresh, by rename.** The public code repo of 2026-11-10 became the private, archived `Replikanti/interviewscam-site-history`, and a new `Replikanti/interviewscam-site` starts from one import commit (part 2).
2. **Intake: code public, data private** (part 3).
3. **No month-end wait.** Replikanti/interviewscam#38 closes once its four PRs are merged, on an operator read of the billing web UI taken at closing time (part 6).
4. **Workflow hardening.** The public guard also fails on risky workflow constructs, and the records repo reuses the same rule set (part 4).

One deviation from the approved plan, recorded on Replikanti/interviewscam#38 (operator, 2026-11-16): the archive keeps a log retention of 90 days, not 400 (Numbers, "Log retention of the archive").

Implementation: this ADR and the SPEC edits (PR A); the public-tree guard and workflow hardening in `tools/sitecheck.py` (PR B); the records mode of `tools/check.sh` and the pin rule (PR C); the private records pipeline (PR D, in the private repo). Until PR B and PR C merge, parts 4 and 5 are decisions, not yet checks.

## Context

- **The private minutes ran out.** The org is on GitHub Team with 3,000 included private Actions minutes a month. The operator's read of the billing usage API on 2026-11-10: 2,715 private minutes used from 2026-11-01, 2,706 of them by `Replikanti/interviewscam`, about 285 left. Rebuilt from the jobs API on 2026-11-16 (every private-repo run since 2026-11-01, each job rounded up to a whole minute): this repo 2,700, namely `lighthouse`/`lighthouse` 960, `lighthouse`/`build` 606, `ci`/`check` 629, `links-external` 286 and `deploy` 219, the same per-workflow figures as the issue; the org's other private repos 14. The rebuild is 6 minutes (0.2 %) under the billing figure. The gap is not explained, so the billing UI or API stays the source for the budget (part 6).
- **Why the runs got long.** The operator measured the median `check.sh` run at 0.7 min on 2026-11-04 and 8.7 min on 2026-11-10. On run 43774538919 (the public `check` job on `main` `495c448`, 2026-11-15, 1,121 s) the self-test took 952 s (85 %), fetch-tools 10.0 s (of which the Nu Html Checker image pull 8.3 s), guard, records, build, site and render together 1.2 s, reflow 15.8 s on the 12 production pages and 51.8 s on the 28 fixture pages (1.85 s per page), and the Nu Html Checker 3.4 s on both trees (40 pages). The public `lighthouse` job of the same push (run 43774538885) took 602 s: setup 14.4 s, then 54 audits of 18 pages (12 production, 6 fixture) at a mean of 10.7 s.
- **Public runners are free.** Standard GitHub-hosted runners cost no minutes in public repositories. On 2026-11-10 the code moved to the public `Replikanti/interviewscam-site` with full history (step 1 of Replikanti/interviewscam#38), and Actions in the private repo were disabled. That public repo had two defects found on 2026-11-16: its old history, all refs including the read-only `refs/pull/*`, was public, and its required `check` had `app_id` null, so a status from any app satisfied it, against SPEC §9.
- **Pushes per PR.** CI runs per merged PR: private repo 21 PRs, median 6, maximum 21; public repo 9 PRs, median 2, maximum 18 (jobs API, 2026-11-16).
- **The pin API answers.** For `495c448`, `GET .../commits/<sha>/check-runs` returned 1 run (app 15368, completed, success) and `GET .../compare/495c448...main` returned `identical`; latency 0.43 to 0.83 s per call, and the unauthenticated call also returned 200 (2026-11-16).
- **Records do not exist yet.** Production `content/` has no records until milestone 5 (Replikanti/interviewscam#6), so no record ever entered either public history.

## Decision

The site machinery is public and the records are private. The public repo `Replikanti/interviewscam-site` runs every machinery check on every change, for free. The private repo `Replikanti/interviewscam` holds only records and four workflows, checks out the public repo at a pinned commit whose `check` is green, runs the checks whose inputs include records, and builds the Pages artifact.

### 1. Two repos

**Public `Replikanti/interviewscam-site`** holds everything in today's tree: the templates, assets, data, schemas, checks and workflows, `docs/SPEC.md`, the ADRs, the fixtures and the intake code. Its `content/` holds only the static pages (`content/*.md`).

**Private `Replikanti/interviewscam`** holds only `content/reports/`, `content/campaigns/`, `schema/record-policy.json` (the real `retired_slugs`), its four workflows, `README.md`, `CLAUDE.md` and `.gitignore`. Its issues hold intake triage, plans and the backlog ledger. Raw evidence and reporter identity stay in the operator's mailbox (D5, D7), as before.

**D4, amended.** Pages is still published from the private repo, and the site is built from the public machinery at a pinned commit. The deploy needs no token: the private repo deploys itself, and it reads the public repo, which anyone can read.

**Why:** the Team-plan reason of D4 holds unchanged for records, drafts and removals. A removed record leaves no trace in public git, and a draft (an unmerged records PR) is never public. D4 rejected "a public build-only repo next to the private one" because it brought two repos and a deploy token for no gain. Both objections fall away: the self-test alone was 85 % of a `check` run (Context), and it moves to free runners with every other machinery check, while no deploy token exists in this design.

**Rejected:**

- *Flipping the private repo public, temporarily or not:* its PR comments and history hold text that cannot be published.
- *Paid minutes or a larger plan:* operator decision.
- *A self-hosted runner for the private repo:* it costs 0 minutes, but CI, the Lighthouse registry code included, would run on the operator's machine, against D3's "never on a developer machine", and a required check that reports only while the laptop is on blocks removals.
- *Trimming CI in one private repo:* it drops checks, which Replikanti/interviewscam#38 rules out.
- *Public CI that pulls the records with a token:* records would land in public run logs and artifacts.
- *Records as a git submodule of the public repo:* public CI would need a private-repo token.
- *A reusable workflow in the public repo, called from the private one:* the called workflow cannot reliably learn its own commit, so the pin would need a second copy, and the guard's `actions/`-only `uses:` allowlist would need an exception.

**Where each check runs.** A dash means that every input of the check lives in the public repo at the pinned commit, whose green `check` the pin rule requires (part 5), so a private rerun would repeat the same computation on the same pinned toolchain.

| Check | Before the split | Public after the split | Private after the split |
|---|---|---|---|
| fetch-tools (pinned hashes) | every run | every run | every run |
| shellcheck, worker, tokens, literals, selftest | every PR and push | same | — |
| guard (repo rules) | every run | every run, plus the public-tree and workflow-hardening rules (part 4) | on the pinned tree, plus the records-repo rules, workflow hardening included (part 5) |
| records (schema, defang, R4 to R15) | production with 0 records, plus fixtures | fixtures; production held at 0 records by the guard | every records PR and push, with the private `retired_slugs` |
| build, site, render (production; render's fixture-leak check) | every run | every run (no records) | every run, on the real records |
| fixture build and its site, render, links, reflow, html | every run | every run | — |
| reflow and html (production tree) | CI | CI | CI |
| links offline (production) | every run | every run | every run |
| links-external | weekly and on dispatch | weekly and on dispatch (static pages) | weekly and on dispatch (production with sources) |
| lighthouse | PRs on site paths, push to `main`, dispatch | unchanged | push to `main` and dispatch, production pages (a record-only PR was never path-triggered) |
| Pages artifact (`deploy.yml`) | push to `main`, PRs that change it | removed (PR C) | push to `main`, PRs that change it; artifact only until M6 |
| pin rule; records-repo layout and workflow rules | — | — | every run (new) |
| public-tree guard | — | every run (new) | on the pinned tree |

### 2. Fresh public history

The procedure ran on 2026-11-16 (its log, every SHA and API state, is on Replikanti/interviewscam#38):

1. The old public repo's Actions were disabled, then it was renamed to `Replikanti/interviewscam-site-history`, made private and archived. Its `main` was `495c448` with tree `9dd5f8a`.
2. A new, empty public `Replikanti/interviewscam-site` was created and hardened before its first push: interaction limit collaborators only, approval for workflows from all external contributors' fork PRs, secret scanning and push protection, Actions limited to GitHub-owned actions pinned by SHA, read-only default workflow permissions, issues, wiki, projects and discussions off, squash-only merges with branch deletion.
3. One import commit, `bc3a1e6`, was built locally with `git commit-tree` from the old tree and the account's noreply identity, and pushed as `main`. Its tree equals `9dd5f8a`; its push runs of `ci`, `deploy` and `lighthouse` were green.
4. Branch protection was applied after that push (SPEC §9's profile, `check` pinned to app 15368).
5. The numbers 1 to 9 were reserved by 9 placeholder issues titled "Reserved number", closed as not planned, after which issues were turned off again. The first PR of the new repo is #10.
6. An audit across all refs (below) passed on the new repo.

**Why the archive and not deletion:** the 9 PRs' conversations, QA tables and the runs the ADRs cite stay readable to the maintainers (the runs' step logs for 90 days, Numbers).

**Why no force push:** a force push of a fresh root into the old repo would have left the nine read-only `refs/pull/N/head` refs, and the old history with them, reachable until GitHub Support removes them (GitHub docs, "Removing sensitive data from a repository"), so an all-refs audit could not pass; it would also have needed the no-force-push rule lifted on a public repo. The rename leaves no public ref to the old history, and no step forces anything.

**Why the placeholders:** an old link `interviewscam-site#1` to `#9` reaches a closed placeholder that points to Replikanti/interviewscam#38, never an unrelated new PR. The lock call on each placeholder returned no error, but the lock state cannot be read back while issues are off, so "locked" is unverified.

**Why tree equality is the proof:** two commits with the same tree hash have byte-identical content in every file, so the import changed no file. It also keeps the Worker pin `INTAKE_WORKER_SHA256`, a content hash, unchanged, so the deployed Worker needs no redeploy.

**The audit.** An all-refs audit of the public repo mirror-clones it (`refs/pull/*` included), runs the public scrub over every unique blob, every commit message and every author and committer line, scans for local machine paths, counts commits whose author or committer address is not a noreply one, and counts open secret-scanning alerts. It prints counts only, never a matched term. It passes with 0 in every count, and it runs again at the closure of Replikanti/interviewscam#38.

**Provenance in the older ADRs.** The commit SHAs and run IDs cited in ADR-0001 to ADR-0006 and in code comments resolve in the archive, and the commits up to `6af2f3d` also in the private repo. Both are private, so for a public reader the figures written in the ADRs are the record. They stay as written: they are historical provenance, and rewriting them would change what each ADR says it measured.

**Rejected:** a force push of a fresh root (above); deleting the old repo (it loses the PR conversations and the cited runs); keeping the old history public (it carried non-noreply identities, Consequences).

### 3. Intake: code public, data private

The intake code is public: `worker/intake.js`, `tools/intake.py`, `tests/worker/` and [ADR-0006](0006-intake-form.md). The intake data is private: the mailbox, the private repo's issues, drafts (unmerged records PRs) and removals (`retired_slugs`). This amends Replikanti/interviewscam#38's wording "intake stays private".

**Why:** the code holds no submission, address, account ID or token (ADR-0006 part 10; the deploy tool prompts for them and writes none), and the public checks test it on every change for free. Publishing it changes nothing a reporter relies on: D5's protection is the mailbox and the absence of any public intake issue, not the secrecy of the form's code.

**Rejected:** moving the intake code to the private repo: its tests would run on metered minutes, and the public site's forms post to that Worker anyway, so its behaviour is observable.

### 4. Public-tree guard and workflow hardening (PR B)

`sitecheck guard` on the public repo fails when a record, draft, intake or removal entry enters it. Every path under `tests/fixtures/` is exempt. Names and keys are folded before comparison (NFKC, `INVISIBLE` stripped, casefold). Findings cite "D4, ADR-0007 part 4".

- **PT1, content subdirectory.** Any directory or symlink directly in `content/` fails, read from the disk as Hugo reads it, plus git's listing, so an ignored local draft fails too. Why structural: it covers the two record sections, page bundles, case variants and look-alike or zero-width names without a list of names to evade.
- **PT2a, front-matter document outside `content/*.md`.** A file whose first line, after an optional BOM, is `+++` or `---`, or which starts with a JSON object followed by more text, fails. Why: it is the shape of a record under any name; pure JSON files and `{{` templates pass.
- **PT2b, record keys in a static page.** In `content/*.md` the front matter must be TOML, and no top-level or `[params]` key may be one of the required record keys of the record schemas, read at run time. A TOML parse error or an unreadable schema fails closed. Why: a record pasted into a static page would otherwise pass PT1.
- **PT3, removal entry.** `schema/record-policy.json` holds exactly `retired_slugs: []`, and no other file is named `record-policy.json`. Why: a public retired slug names a removed record.
- **PT4, intake material.** Mail files by suffix (`.eml`, `.emlx`, `.mbox`, `.mbx`, `.msg`, any case) fail, and so does a raster image recognised by the magic bytes of `INTAKE_IMAGE_TYPES` (PNG, JPEG, GIF87a, GIF89a, WebP), whatever its name, outside `assets/` and `static/`. Why these members: they are the forms raw evidence arrives in (the form's upload types and saved mail). Images in `assets/` and `static/` are content-review surfaces already.

Workflow hardening, one function for every `.github/workflows/*` file of either repo; a form it cannot read fails closed. Findings cite "ADR-0007 part 4".

- **WH1, trigger allowlist.** The keys of the top-level `on:` must be exactly `pull_request`, `push`, `schedule` or `workflow_dispatch`. Rejected members, with their reason: `pull_request_target` runs in the base repo with a write-capable token and secrets, so a checkout of the PR head runs fork code with them; `issue_comment`, `pull_request_review`, `pull_request_review_comment` and `discussion_comment` can be fired by an outsider and run on the default branch with the repo's token; `workflow_call` and `repository_dispatch` take input from outside the repo's own events; every case variant or look-alike of an allowed name fails because the comparison is exact.
- **WH2, checkout leaves no credential.** Every `actions/checkout` step has `persist-credentials: false`. Why: otherwise the job token stays in `.git/config` for every later step to read.
- **WH3, no credential input on checkout:** no `token:` or `ssh-key:`.
- **WH4, no `secrets` reference** anywhere in a workflow, comments included. Why: no workflow in either repo needs one; the private pin call uses `github.token`.

**Rejected:** relying on the repo settings alone (read-only default permissions, fork-PR approval): a setting can be changed without a PR, while a guard rule changes only through a reviewed `tools/` change.

### 5. Records mode and the pin rule (PR C)

`bash tools/check.sh --records <dir>` runs, from a public checkout, the pin rule first, then the guard on the public tree, the records-repo rules, the production build on `<dir>`'s records with the public static pages, and every content check on it (the mapping table). The machinery steps print `NOT RUN (records mode)`, and the last line never uses the public all-pass wording.

**A valid pin** is a commit that (a) has a completed, successful `check` run from app 15368 (the GitHub Actions app), the latest such run by `id`, and (b) is on public `main` by the compare API (`ahead` or `identical`, `behind_by` 0).

**Why both:** a fork PR's head commit can carry a green `check` in the base repo, so (a) alone could pin fork code nobody reviewed; (b) alone could pin a commit whose checks failed.

**The records repo's layout is closed:** its top level, `content/`, `schema/` and `.github/` may hold only the members of part 1, and every `actions/checkout` of the public repo names `Replikanti/interviewscam-site` in exactly that spelling and a `ref:` of 40 lowercase hex characters equal to the pin. Why: a records repo that could ship a template, a schema or config would change the machinery without a public review.

**How a pin moves:** one private PR edits every `ref:`. Bumps happen at most once a day, batching that day's public merges, plus on demand when a records PR needs new machinery. A machinery change reaches production only through a pin bump.

**Rejected:** pinning a branch or a tag (both move without a private PR); no pin, checking out public `main` (a public merge would change production with no private change and no record of which machinery built which deploy).

### 6. Private CI budget

The private minutes are a metered budget of 3,000 a month with no paid minutes: the Actions budget is held at $0 with usage stopped at the limit, which the closing read below confirms. An overrun therefore stops every private run, a D7 removal included, until the month turns. Every later private workflow change states its minutes per run and per month (Numbers). The private jobs carry timeouts of 10 minutes (`check`, `deploy`, `links-external`, lighthouse `build`) and 18 minutes (`lighthouse`), derived in Numbers, so a hung job costs at most that, not the 60 minutes of the public jobs.

**Closure of Replikanti/interviewscam#38 (STOP 1 decision 3):** after the private pipeline's first runs, the operator reads the 2026-11 private minutes in the billing web UI and records them on Replikanti/interviewscam#38, with the $0 budget setting and the fit of the remaining November runs. Until 2026-12-01 a pin bump or records PR merges only while the remaining minutes cover its cost. Why no month-end wait: every step before PR D runs only on public runners, and the jobs API already shows the headroom (Numbers, "November headroom").

**Rejected:** a smaller timeout than the derived one (a slow but healthy run is cancelled and retried, which costs more); waiting for the month end to close Replikanti/interviewscam#38 (it holds the issue open for two weeks, while the read on the day already shows the minutes spent and the November merge rule above covers the rest of the month).

### 7. SPEC location: public only

`docs/SPEC.md` stays in the public repo, and the private repo's `CLAUDE.md` links to it.

**Why:** it governs the machinery, and `tools/` and the ADRs cite its sections. It contains nothing private: it passes the public scrub, and the operator's name in it is D1. A published moderation policy (D1, D7) is a trust feature.

**Rejected:** a private copy (it would drift from the code it governs); a split SPEC (the D-rules bind records and checks together).

## Numbers

| Number | Value | Derivation, and what breaks at another value |
|---|---|---|
| Included private minutes | 3,000 a month | GitHub Team, the org's plan. The whole budget of part 6 rests on it. |
| Billing read of 2026-11-10 | 2,715 used, 2,706 by this repo, about 285 left | The operator's read of the billing usage API (Context). 3,000 − 2,715 = 285. |
| November headroom | about 276 on 2026-11-16 | 285 minus the 9 private minutes the jobs API shows since that read (one org repo: 8 runs at 1 minute each; another: 1 run at 1 minute). Inferred from the jobs API, not read from billing; the closing read of part 6 replaces it. |
| Billing rounding | each job rounded up to a whole minute | The rebuild with per-job rounding gives 2,700 against 2,706 billed (Context), so a job of 60.0 s costs 1 minute and one of 60.1 s costs 2. Every per-run cost below uses it. |
| Records-mode `check` job T(P) | 18.4 s + 1.94 s × P, P = production pages | Fixed part: setup and two checkouts 2.6 s, fetch-tools 10.0, two pin API calls 1.0, records-repo rules 0.5, guard and the record nets 1.3, the Nu Html Checker container 2.0, summary 1.0 = 18.4 s (fetch-tools and the net times measured on run 43774538919, the API calls from the measured 0.43 to 0.83 s each, the other terms estimates that PR D's measured run checks). Per page: reflow 1.85 s + html 0.09 s (3.4 s / 40 pages) = 1.94 s. At M5 (12 static pages, 2 section pages, 4 records, P = 18): 53.3 s, 1 billed minute. It stays 1 minute up to P = 21 (T = 59.1 s, 7 records) and 2 minutes up to P = 52 (119.3 s, 38 records); at 100 records (P = 114) 239.6 s, 4 minutes. Above each bucket a run costs 1 more minute; the formula is re-derived when the records pass 38 and checked against PR D's measured run (part 6). |
| Private `lighthouse` job | 473.8 s, budget 9 billed minutes | 10 s job overhead (estimate) + 14.4 s setup + 3 runs × Q pages × 10.7 s (the means of run 43774538885), Q = 14: the 12 production pages of today plus `/reports/` and `/campaigns/`, no fixture pages (the fixture pages stay public). 473.8 s is 8 billed minutes; the budget of 9 keeps 1 minute of margin. A run over 480 s costs 9. |
| Cost per merged records PR | p + 12 minutes | p PR runs of `check` at 1 each, then on the merge push `check` 1, `deploy` 1, lighthouse `build` 1 and `lighthouse` 9. 18 at p = 6 (the private median pushes per PR), 33 at p = 21 (the private maximum). |
| Pin bump | 13 minutes; at most about 31 a month, 403 | A bump PR with one push: 1 + 12. One a day at most (part 5), 31 × 13 = 403. More bumps a day would buy no faster machinery than batching and cost 13 each. |
| Private `links-external` | at most 2 minutes a run, 9 a month | Estimate: the records-mode job (53 s at P = 18) plus the online link run on the production tree, budgeted at 2 billed minutes and measured on its first dispatch after PR D. 4.35 Mondays a month × 2 = 8.7, rounded up to 9. |
| Other private repos | 26 a month | 14 minutes from 2026-11-01 to 2026-11-16 (jobs API), × 30 / 16 = 26.25. |
| Capacity | 142 records PRs a month at the median push count, 77 at the maximum | (3,000 − 26 − 9 − 403) / 18 = 142.3 and / 33 = 77.6, with the bump maximum reserved. An M5-sized month (4 records PRs, 10 bumps): 4 × 18 + 10 × 13 + 9 + 26 = 237 minutes, 8 % of the budget. |
| Private timeout of `check`, `deploy`, `links-external`, lighthouse `build` | 10 minutes | B = the 53 s estimate rounded up to the next 5-minute step, 300 s. The cap must cover max(2 × B = 600 s, for the spread of runner speed; B + 2 × 75 s + 70 s = 520 s, for two Chrome launch stalls at `REFLOW_LAUNCH_TIMEOUT` (ADR-0003 part 6) plus the worst-case pin requests) = 600 s. Lower: a slow but healthy run is cancelled. Higher: a hung job costs more of the metered budget; at 10 it costs at most 10 billed minutes, not the public 60. |
| Private timeout of `lighthouse` | 18 minutes | ADR-0004's method (factor × (T_setup + pages × 3 × T_run)), with this job's own inputs: factor 2 (the measured spread of green `lighthouse` runs, 1.10, rounds up to the smallest whole factor above it), T_setup 36.6 s and T_run 11.8 s, the largest measured on the public job (ADR-0006 Numbers, "Lighthouse page count 20"), and 14 pages: 2 × (36.6 + 42 × 11.8) = 1,064.4 s, rounded up to 18 minutes. Lower: a slow normal run is cancelled. Higher: a hung run costs more minutes. |
| Pin requests | 20 s timeout per request, 3 tries 5 s apart, worst case 70 s | 20 s is 24 × the slowest measured call (0.83 s). Retries only on connection errors and 5xx: a 4xx (a 404, a rate limit) does not clear in seconds. 3 × 20 + 2 × 5 = 70 s, inside the 600 s cap. Lower: a slow API answer fails a records PR. Higher: a dead API holds the job longer. |
| `app_id` | 15368 | The GitHub Actions app, which reports the `check` job. Required in both repos' protection and in the pin rule; another app id would accept a status any other app can post. |
| Placeholders | 9 | One per old PR number, #1 to #9. Fewer: an old link could land on a new, unrelated PR. |
| Interaction limit | six months, until 2027-05-16 | GitHub's longest setting; it must be renewed then, or outsiders can open PRs and comment. |
| Log retention of the archive | 90 days | Deviation from the plan's 400 days: the organization caps it at 90 (the API answered 409 Conflict), and the operator chose not to raise the org-wide limit (2026-11-16). The step logs of the 28 runs the older ADRs cite (2026-11-10 to 2026-11-14) therefore expire about 2027-02-08 to 2027-02-12, and that of run 43774538919 about 2027-02-13. Their job timings (run, workflow, job, start, end, conclusion) were saved on Replikanti/interviewscam#38 before the rename, and the figures each ADR took from them are written in that ADR. |

## Consequences

- Two repos stay in step through pin bumps. A machinery fix reaches the records only after a bump, and every bump costs 13 minutes; the cadence (part 5) is written in both repos' `CLAUDE.md`.
- The private minutes are a metered budget: every private workflow change states its cost per run and per month, and the records count is re-checked against the T(P) buckets when it passes 38.
- The pin rule depends on the GitHub API. An outage or a rate limit blocks records PRs; it counts as a cause outside the PR for the operator-only emergency removal of SPEC §9.
- [ADR-0004](0004-record-model.md) part 7's premise "the repo is private" no longer holds for the code repo, but its decision (document the feed on `/data-feed/`) stands, because the page reaches feed consumers who never read a repo.
- Old commit SHAs and run IDs resolve only in the private archive and the private repo (part 2), and their step logs expire after 90 days (Numbers).
- Before M6, the Lighthouse registry code in the private `lighthouse` job sees records that are merged but not yet published. They are approved for publication, and D3's isolation of that job is unchanged.
- The old public history was public for six days, and copies outside GitHub cannot be recalled. The all-refs audit of that history found 0 public-scrub hits, but 73 of its 105 commits (all refs, `refs/pull/*` included) carry a non-noreply author or committer identity; a scan of `main` alone had found 1 of 32. The new history has 0 of 1, and the audit at closure checks it again.
