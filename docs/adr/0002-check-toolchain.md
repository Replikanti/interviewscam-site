# ADR-0002: Check toolchain

## Status

Accepted, 2026-11-04 (operator, issue #2, STOP 1, including the change that makes the Nu Html Checker CI-only). Implements the checks of SPEC §8 and the CI part of milestone 1.

## Context

SPEC §8 sets the quality bar (valid HTML, no broken links, records that pass a schema, no third-party requests) and D3 forbids npm outside CI jobs that hold no write token. The checks must be pinned, so a green result means the same thing on every run. Milestone 1 defines one entry point, `bash tools/check.sh`, that CI calls verbatim. This ADR decides which tool does each job, where it runs and how it is pinned.

The operator's machine has no docker or podman, and the operator does not want a container runtime or a JVM in the local toolchain.

## Decision

Seven parts. Each has its own reason and rejected alternatives.

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

## Consequences

- A local `bash tools/check.sh` does not validate HTML. The `NOT RUN` line and the summary wording exist so that nobody reads a local green as "HTML validated". The required `check` job is the only HTML gate.
- An HTML error surfaces only after a push.
- The `check` job name is load-bearing, because branch protection requires that exact context. A rename must update the protection in the same session.
- Every tool pin changes only through a PR that runs the full check.
- Pinned action SHAs go stale. Updating them is manual until someone adds automation.
- A broken external link in new content can be live for up to 7 days unless the local `--external` run catches it.
- When `check` is red for a cause outside the PR (a vanished vnu digest, a registry outage) and a D7 removal is pending, the emergency removal bullet in SPEC §9 applies. It is the single operator-only exception to never-merge-red: only the operator personally, never an agent session, and only when the run log shows every `check.sh` step green except the one with the outside cause.
- The bypass covers the merge only. `deploy.yml` builds its artifact with the same `check.sh`, so the same outside cause also fails the deploy. Before Pages goes on, M6 (#7) must define the operator-only deploy path for an emergency removal, or the removal does not reach the site.
