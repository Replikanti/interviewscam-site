# ADR-0002: Check toolchain

## Status

Accepted, 2026-11-04 (operator, issue #2, STOP 1, including the change that makes the Nu Html Checker CI-only). Implements the checks of SPEC §8 and the CI part of milestone 1.

*Amended 2026-11-26 (Replikanti/interviewscam#41, decided by the planner under the operator's standing rule for this project):* part 8 gives every download of `tools/fetch-tools.sh` a derived retry schedule and skips the Nu Html Checker pull when the pinned image is already present; Numbers gains their rows.

## Context

SPEC §8 sets the quality bar (valid HTML, no broken links, records that pass a schema, no third-party requests) and D3 forbids npm outside CI jobs that hold no write token. The checks must be pinned, so a green result means the same thing on every run. Milestone 1 defines one entry point, `bash tools/check.sh`, that CI calls verbatim. This ADR decides which tool does each job, where it runs and how it is pinned.

The operator's machine has no docker or podman, and the operator does not want a container runtime or a JVM in the local toolchain.

## Decision

Eight parts. Each has its own reason and rejected alternatives.

### 1. Nu Html Checker: CI only, container image pinned by digest

The HTML validator is the container image `ghcr.io/validator/validator`, pinned by digest, and it runs only in GitHub Actions. `tools/check.sh` outside CI does not run it and prints one loud line that HTML validation was NOT run locally, so a local green is never read as "HTML validated". The summary row reads `NOT RUN (CI only)`, and the final line reads `LOCAL PASS, HTML validation not run (CI only)`, never an all-pass wording. The §8 HTML row is taken only from the required `check` job in CI. In CI, a missing container runtime or an unpullable digest is FAIL, never a skip.

Data:

- Upstream stopped numbered releases at 20.6.30 (2020-07-01). Maven Central's newest is 20.7.2 (2020).
- The rolling `latest` release was rebuilt in place on 2026-11-04 06:15 UTC. A SHA-256 pin on `vnu.jar` or `vnu.linux.zip` would therefore break on every upstream rebuild.
- The image tags are `21.7.10`, `23.4.10`, `23.4.11`, `24.10.17` and `latest`, so the newest numbered tag is two years old.
- Upstream re-tags `:latest` on every build of its `main` branch, so a pinned `latest` digest goes untagged after the next upstream push. Whether upstream prunes untagged package versions is not verified.
- The `latest` index digest on 2026-11-04 is `sha256:0af71abb9e40083cc0e8b3fcbe51a55a45889c662a3f507fbf1f9f013a109842`.

**Why:** one validator build that an upstream rebuild cannot change, and no container runtime or JVM on the operator's machine (operator decision, STOP 1, 2026-11-04). A digest identifies one image content, which a rebuilt `latest` tag cannot change.

**Cost:** a local green does not cover HTML validity, an HTML error surfaces only after a push, and upstream could delete the pinned digest, in which case the `check` job fails loudly and never skips.

**Digest-loss fallback:** if the pinned digest disappears upstream, the `check` job goes red with no change on our side. `fetch-tools.sh` names the cause. The fallback is to mirror the image into the org registry and pin the mirror. It is written down here and not built now.

**Rejected:**

- Running the image locally through docker/podman. The operator has neither, and wants neither (operator decision, resolution 2).
- Floating `latest` with PGP verification. It verifies who built the image, but the builds are not reproducible.
- A self-hosted mirror now. It adds an extra manual step on every upgrade.
- The tag `24.10.17` pinned by digest. It stays tagged, so it is not exposed to a cleanup of untagged versions, but it is two years old, behind the current HTML specification, and the validator would flag current markup differently. We take the `latest` digest and accept the loss risk, which the mirror fallback covers.

### 2. lychee for links, pinned release

lychee v0.24.2, x86_64 Linux tarball, SHA-256 `1f4e0ef7f6554a6ed33dd7ac144fb2e1bbed98598e7af973042fc5cd43951c9a`. The `.sha256` sidecar matches GitHub's digest for the asset. Internal links are checked offline on every PR (part 7 covers the external cadence).

**Why:** SPEC §8 names lychee for the links row, and a pinned, verified release keeps the result stable like the other tools.

**Rejected:** the `nightly` release. It is a prerelease rebuilt in place, so a hash pin on it would break on every rebuild.

### 3. Checks in Python 3 standard library only

The record, site and guard checks are written in Python 3.11 or newer, standard library only.

**Why:** 3.11 is the first version with `tomllib` in the standard library, which parses the record front matter. The CI runner ships 3.12 and the operator's host has 3.14, so both satisfy it.

**Rejected:**

- pip `jsonschema` or `check-jsonschema`. A PyPI dependency tree (including the compiled `rpds-py`) pulled on every run is the same class of supply-chain exposure that D3 rejects for npm.
- An extra pinned validator binary. It brings features (remote `$ref`, formats) that the records do not need.

### 4. A JSON-Schema subset validator that fails closed

The validator implements only the keywords the record schemas use, fails closed on any keyword it does not implement, and adds the custom keyword `x-defang`, which marks the fields that carry attacker artifacts.

**Why:** a keyword that a validator silently ignores would make a schema look stricter than it is, so unknown keywords are errors. `x-defang` ties the D8 rule to the schema field by field.

**Rejected:** see part 3 (a dependency or a second binary for a full validator).

*Amended by ADR-0004 parts 2 and 3: the validator gains one keyword, `minimum` (numbers only), and `x-defang` keeps a single mode, `host`. The mode `url-only` is removed, so a schema that still uses it fails closed.*

### 5. Runner label `ubuntu-24.04`, not `ubuntu-latest`

All workflows run on `ubuntu-24.04`.

**Why:** `ubuntu-latest` moves to a new image on GitHub's schedule and would change Python, docker and shellcheck under a pinned toolchain.

**Rejected:** `ubuntu-latest`, for the reason above.

### 6. GitHub's own JavaScript actions accepted, pinned to commit SHAs

The actions are `actions/checkout` and `actions/upload-pages-artifact`, which D4 requires to deploy via Actions. They run on the runner's bundled Node and are not npm installs in our build chain, so D3 is not breached. Every action is pinned to a 40-hex commit SHA. The guard check (PR 3) enforces both the `actions/` owner and the 40-hex SHA, so a third-party action pinned by SHA does not pass.

**Why:** a tag can be moved, a commit SHA cannot. Only GitHub-authored actions (owner `actions/`) are used, and the guard rejects any other owner. SPEC D3 links to this part.

**Weak point:** we trust GitHub-authored JavaScript.

**Rejected:** a hand-written Pages upload against the internal artifact API. It is worse than trusting the GitHub action: it would be our own code against an internal interface.

### 7. External links: a weekly + manual workflow, and a local run on content PRs

Internal links are deterministic, so lychee `--offline` gates every PR. External links are checked by a scheduled workflow, weekly and on manual start, which is not a required check. On `area::content` PRs, QA must run `bash tools/check.sh --external` locally before merge.

Data: external sources are third-party sites. 9 of the 10 source URLs in SPEC §12 answered 200 or 302 from the operator host on 2026-11-04 (curl with a browser user agent). `www.producthunt.com` answered 403 (bot protection) even from there. Runner datacenter IPs are unmeasured, and bot-protected sites often refuse those. The `lychee.toml` of PR 2 needs an accept or exclude decision for bot-walled 403 sources before milestone 5.

**Why:** a third-party outage must never block a D7 removal PR for longer than the emergency bypass in SPEC §9 takes (house rule: never merge red, even on a non-required check; the SPEC §9 emergency removal is the single operator-only exception to it). SPEC §8 still holds within a bounded delay. A rotted existing source link is a trust defect, not a D8 safety defect, and new sources are covered by the mandatory pre-merge `--external` run, so only rot of already published links waits for the schedule.

**The cadence is a chosen trade-off.** No SPEC number binds it and there is no link-rot data yet. Weekly versus daily: a rotted link stays unflagged for up to 7 days versus up to 1 day, and triage handles 1 scheduled run per week versus 7. Weekly was chosen because the exposure is a trust defect only, and the lower triage load is worth more. The first month of results in milestone 5 is the data to revisit it with.

**Weak point:** a broken new source link can be live for up to 7 days unless QA's local run catches it before merge.

**Rejected:**

- Gating every PR on external links. A third-party outage would block a removal.
- A daily schedule. It cuts the unflagged exposure from 7 days to 1, but it brings 7 scheduled runs per week instead of 1 (7 times the outage noise) for a milestone 1 site that has no external links.

*Amended 2026-11-24 (Replikanti/interviewscam#6):* the bot-walled source decision reserved above for milestone 5 is neither "accept" nor "exclude". A cited source must answer 2xx to lychee from the operator host (QA's local `--external` run) and from GitHub's runners (`links-external.yml`, dispatched on the branch of the records PR that adds the source). A source that answers 403 or another non-2xx status from either side is replaced by another source that states the same fact, or the fact is left out of the record. `lychee.toml` keeps lychee's default accepted statuses and gains no exclude for a source.

**Why:** an accepted 403 also accepts a page that a block page or a login wall has replaced, so a rotted or removed source would stay green. An exclude never checks the link again, so its rot goes unseen for good. Both turn the external-link run into a check that no longer reads the source. Replacing a source costs one records PR.

**Data:** candidate source pages for the first campaign records, fetched with `curl -A lychee/0.24.2` from the operator host on 2026-11-24: 7 of 7 answered 200 between 02:40 and 02:55 CET, 6 of them answered 2xx again at 03:27 CET (one through a single 302 redirect, which lychee follows), and the 6 pages the first records PR cites (5 of the candidates and one later find) answered 200 at 03:39 CET. No page needed a bot-wall decision. Runner datacenter IPs are measured by the `links-external.yml` dispatch on the records PR before it merges.

**Weak point:** a source that turns bot-walled after its records PR merged reddens the weekly run until a records PR replaces it. That is the intended signal, at the cost of one records PR per such source.

**Rejected:**

- Accepting 403 (`accept` in `lychee.toml`). It keeps a block page or a login wall green, so the run no longer shows whether the source still says what the record cites.
- An exclude per bot-walled URL. The link is never checked again, and a later removal of the source goes unseen.

### 8. Download retries: a fixed delay inside a bounded window

Every download of `tools/fetch-tools.sh` (`fetch_verified`: hugo, lychee, workerd) runs `curl -q --fail --silent --show-error --location` with `FETCH_RETRY_ARGS` (`--retry-all-errors --retry 19 --retry-delay 3 --retry-max-time 55 --max-time 40`), then `--proto =https --tlsv1.2`. `-q` comes first, so no curlrc of the user (a `limit-rate`, say) changes the schedule. The `.part` file of an earlier run is removed before the download, and a curl that ends without a file fails the download: curl 8.18.0 answers a `Retry-After` that passes the retry window with one request and exit 0, without an output file (measured on a loopback server, 2026-11-26). The SHA-256 check is unchanged: on every run, before any extraction, the download deleted on a mismatch. Values and what breaks at others: Numbers.

Data:

- Before this part, `--retry 3` with curl's backoff (1, 2, 4 s) gave up about 19 s after the first attempt, and without `--retry-max-time` curl honours any `Retry-After` (a 503 with `Retry-After: 3600` was still waiting at 60 s), so the old schedule had no time bound.
- Outage E1, private run 42046723238 (lighthouse `build`, 2026-11-05): hugo's first attempt got a 504 after 11.07 s, the retries at +1, +2 and +4 s got instant 504s, and the self-test's own fetch got 4 more: 504s for 27.21 s on that runner (14:37:06.16 to 14:37:33.37), end unknown. The concurrent `check` job (run 42046723255) downloaded the same file in 8.94 s.
- Outage E2, private run 42578942757 (`check`, 2026-11-09): a 504 after 11.23 s, then instant 504s until 18.39 s, then `fetch-tools: FAIL`, and every later step failed on the missing binary. The self-test's fetch started 21.79 s after the first attempt and succeeded (hugo, 21,121,058 B in 10.47 s, 2.02 MB/s). E2 lies inside GitHub's incident of 2026-11-09 05:10 to 08:15 UTC, when 38.5 % of release downloads timed out, 76 % in the 5-minute peak 07:40 to 07:45. On 2026-11-08 08:43 to 12:29 UTC 46.1 % of release asset downloads failed. Both incidents hit unauthenticated requests.
- 12 of 12 failed attempts in E1 and E2 were 504, in one shape: one slow failure (11.07 s, 11.23 s), then fast ones (the 1, 2 and 4 s gaps measured 1.05, 2.05 and 4.06 s, so a fast 504 costs about 0.05 s).
- The 30 latest green `ci.yml` runs (public): hugo 0.21 to 1.02 s, lychee 0.08 to 0.34 s, workerd 0.30 to 1.25 s. Archives: hugo 21,121,058 B, lychee 7,626,970 B, workerd 44,721,625 B.
- Of the 78 failed runs across the three repos, one more is a fetch outage: public run 45530979139 (`check`, 2026-11-25), where seven nested `docker pull`s of the Nu Html Checker image (the self-test's `selftest-only` rows run `fetch-tools.sh` again) failed on registry timeouts for at least 113 s, although the job's own pull had succeeded and the image was present. No job's first pull failed.

**Why:** a short upstream outage is the one download failure seen, and a job that fails its fetch fails every later step. A fixed delay, not curl's exponential backoff: in the observed shape an attempt is cheap, and the number of attempts inside the window is what beats a per-request failure rate. `--retry-all-errors`, because an outage can also show as a reset, an empty reply or a refused connection, which curl does not retry by default. `--max-time` bounds a hung attempt, so the worst case of a download is a sum of the three values.

**The Nu Html Checker pull** (`fetch_vnu`, CI only) is skipped when `docker image inspect` finds the pinned reference: a digest names one content, and a runner's daemon serves only its own job. That removes the requests that failed on 2026-11-25; a job's first pull is unchanged.

**Cost:** a permanent error (a removed pin URL) now fails after less than 98 s per download instead of at once. A link below 1,118,041 B/s (8.94 Mbit/s) cannot fetch workerd inside one 40 s attempt; there the archive is downloaded by hand and placed at `.tools/cache/<sha256>-<file name>`, where it is verified like any cached download.

**Weak points:**

- An outage in which every attempt fails slowly (11.23 s each) gives 5 attempts in the window, and at the 76 % peak 0.76^5 = 25.4 % per download, 58.4 % of jobs, fail. Both outages seen had the mixed shape; covering the all-slow one needs a window that the private 10-minute caps cannot hold (Numbers).
- `--max-time` is pinned by value only (`fetch/retry-values`): a behaviour row for a hung attempt would cost 40 s per run.
- The private records jobs stack this term with the launch stalls only in the rare case where all three events meet (Numbers, caps row).
- The private records CI keeps the old flags until its next pin bump.

**Rejected:**

- Today's flags: 4 attempts in about 19 s fail 70.4 % of jobs at the 76 % peak and 12.9 % at 46.1 %, and a `Retry-After` has no bound.
- curl's exponential backoff with a larger `--retry`: the gaps double, so a 55 s window holds only about 6 attempts.
- An Actions cache of the archives: no workflow restores one (ADR-0003 Consequences), and a cache miss still downloads.
- A mirror of the toolchain: a new upload path to maintain and to trust.
- Authenticated downloads: records mode unsets the job token before `fetch-tools` (ADR-0007 part 5), and the token adds a secret to a step that needs none.
- Raising the private 10-minute caps: they are derived (ADR-0007 Numbers) and metered; the schedule is sized to fit them instead.

## Numbers

| Number | Derivation | What breaks at another value |
|---|---|---|
| vnu image digest `sha256:0af71abb…109842` (full value in Decision part 1) | The `latest` index digest on 2026-11-04. The newest numbered tag, `24.10.17`, is two years old (see Rejected). `latest` is re-pushed on every upstream `main` build, so this digest is untagged within days. | A different digest is a different validator build and can change HTML results. A deleted digest turns `check` red (fallback in part 1). |
| lychee v0.24.2 (2026-05-01) | The latest stable release, nightly excluded. | Another version has another hash. The fetch step fails until the pin is updated by a PR. |
| lychee SHA-256 `1f4e0ef7…43951c9a` | From the `.sha256` sidecar, equal to GitHub's asset digest. | A mismatch means a different file, and the fetch step deletes it and fails. |
| Python 3.11 or newer | `tomllib` entered the standard library in 3.11. The runner ships 3.12, the operator host 3.14. | Below 3.11 there is no `tomllib`, and the checks cannot parse records without a dependency. |
| Runner `ubuntu-24.04` | A fixed image instead of the moving `ubuntu-latest`. | Another image changes the Python, docker and shellcheck versions under the pinned tools. |
| External link cadence: every 7 days | A chosen trade-off, not derived from a SPEC number (see part 7): up to 7 days of unflagged rot versus 1 triage run per week. Daily would be up to 1 day versus 7 runs per week. No link-rot data exists yet. | Longer: rotted links stay published longer than 7 days. Shorter: more scheduled runs and outage noise to triage. Revisit with the first month of results in milestone 5. |
| Commit-SHA pins, 40 hex characters | The length of a full SHA-1 commit id. | A shorter or tag-style reference is not guaranteed to stay on one commit, and the guard rejects it. |
| Download retry options `--retry-all-errors --retry 19 --retry-delay 3 --retry-max-time 55 --max-time 40` (part 8, Replikanti/interviewscam#41) | The five values below. `fetch/retry-values` in the self-test requires `FETCH_RETRY_ARGS` in `tools/fetch-tools.sh` to equal the text in backticks. | A changed value without its derivation fails the self-test. |
| R = `--retry-max-time 55` | At least twice E1's failing span, 2 × 27.21 = 54.42 s, the next 5 s step; at most 100 - D - M = 57 s from the caps row. | 27 s or less: E1 turns the job red again. Higher: three downloads can pass 300 s (caps row). |
| D = `--retry-delay 3` | Target: a job's three downloads all succeed with at least 95 % probability at the 76 % peak, attempts independent: 0.76^n ≤ 1 - 0.95^(1/3) = 0.01695 needs n ≥ 14.86, so 15 attempts. In the observed shape the 15th attempt's retry decision comes at 11.23 + 13 × (D + 0.05) < 55, so D < 3.32, 3 s. At 3 s: 16 attempts in the mixed shape, 0.76^16 = 0.0124 per download, 3.7 % of jobs at the peak. | 5 s: 10 attempts, 18.1 % of jobs fail at the peak. 1 s: about 53 requests per download in one window during an incident caused by a surge of anonymous traffic, and `fetch/retry-schedule` could no longer tell the gap from curl's 1 s first backoff. |
| M = `--max-time 40` | Above the slowest healthy CI case, workerd's 44,721,625 B at E2's 2,017,293 B/s = 22.17 s (1.8 ×; 32 × the slowest green 1.25 s); at most 100 - 55 - 3 = 42 s; 40 is the 5 s step below. | Below 22.2 s: a degraded workerd download is cut on every attempt. Above 42 s: three downloads can pass 300 s. Locally a link below 1,118,041 B/s (8.94 Mbit/s) cannot fetch workerd in one attempt: place the archive by hand (part 8). |
| N = `--retry 19` | ceil(55 / 3), so the count never ends the window first: with instant failures the 19th retry decision comes at 54 s. | Fewer: instant failures use up the count before the window ends. More: no effect, the window ends first. |
| Attempts in the 55 s window | Mixed shape (first 11.23 s, then 0.05 s each): 16, the last starting at 56.93 s. All slow (11.23 s each): 5, the last at 56.92 s, 0.76^5 → 58.4 % of jobs fail at the peak (weak point). All fast: 20, the last at 57.95 s. | Follows from R, D and N. |
| Worst case of one download W and of all three | W < R + D + M = 55 + 3 + 40 = 98 s: curl starts no retry at 55 s or later and refuses a `Retry-After` that passes 55 s (measured on 8.18.0, re-checked on the runner by `fetch/retry-after-bound`), and the last attempt is cut at 40 s. `fetch_main` stops at the first failure, so all three take less than 3 × 98 = 294 s. The self-test's own fetch adds nothing in a job whose fetch step succeeded (all three cached); records mode has no self-test. | Follows from R, D and M. |
| Caps of the jobs that run `fetch-tools.sh` | Public `ci.yml` `check`, 170 min = 10,200 s against its base 5,100 s (ADR-0004 Numbers): 5,100 + 294 = 5,394 s and 5,100 + 2 × 75 + 70 + 294 = 5,614 s, both ≤ 10,200 s. Private records `ci.yml`, `links-external.yml` and lighthouse `build`, 10 min = 600 s against B = 300 s (ADR-0007 Numbers): the outage term B + 294 = 594 s ≤ 600 s, a third term next to ADR-0007's 2B and B + 2 × 75 + 70, which already does not stack runner spread with launch stalls. Stacked on two full launch windows and the pin worst case (300 + 150 + 70 + 294 = 814 s) the private job is cancelled at 600 s (weak point: three rare events in one job). | A longer worst case than 300 s breaks the private 600 s cap in an outage. |
| Self-test time of #41 | `fetch` about 13 s (4 gaps × 3 s plus the stubs), `answer-during-probe` about 1.9 s, `slow-first-answer` 0.5 s more, about 15 s per `check.sh` run: 4,817 + 15 = 4,832 s, under the 5,054 s re-derive line in `ci.yml`. | More than 237 s added would cross the re-derive line of the `ci.yml` cap. |

## Consequences

- A local `bash tools/check.sh` does not validate HTML. The `NOT RUN` line and the summary wording exist so that nobody reads a local green as "HTML validated". The required `check` job is the only HTML gate.
- An HTML error surfaces only after a push.
- The `check` job name is load-bearing, because branch protection requires that exact context. A rename must update the protection in the same session.
- Every tool pin changes only through a PR that runs the full check.
- Pinned action SHAs go stale. Updating them is manual until someone adds automation.
- A broken external link in new content can be live for up to 7 days unless the local `--external` run catches it.
- When `check` is red for a cause outside the PR (a vanished vnu digest, a registry outage) and a D7 removal is pending, the emergency removal bullet in SPEC §9 applies. It is the single operator-only exception to never-merge-red: only the operator personally, never an agent session, and only when the run log shows every `check.sh` step green except the one with the outside cause.
- The bypass covers the merge only. `deploy.yml` builds its artifact with the same `check.sh`, so the same outside cause also fails the deploy. Before Pages goes on, M6 (#7) must define the operator-only deploy path for an emergency removal, or the removal does not reach the site.
