# CLAUDE.md: interviewscam

Community registry of fake job-interview scams that target developers, built as a static Hugo site for interviewscam.com. The repo is private and the site is public, so everything that builds into the site is public content.

## Source of truth

- [docs/SPEC.md](docs/SPEC.md) is the source of truth. Anything not written there is not agreed. A scope change is a PR that edits the SPEC.
- A change to a SPEC §4 decision (D1 to D10) also adds an ADR in [docs/adr/](docs/adr/README.md). Every ADR decision states why and which alternatives lost, and every number states where it comes from and what breaks at another value. A number copied from another ADR needs its own reason.

## Local check

One entry point, and CI runs it verbatim:

```sh
bash tools/check.sh             # internal links offline
bash tools/check.sh --external  # links online, third-party sources included
bash tools/selftest.sh          # the fixtures alone (check.sh runs it too)
```

Prerequisites: bash, python3 3.11 or newer, curl, sha256sum, tar and shellcheck. No container runtime. `tools/fetch-tools.sh` downloads Hugo and lychee into `.tools/` and verifies each against the SHA-256 in `tools/pins.env` before extracting.

**HTML validation runs only in CI** ([ADR-0002](docs/adr/0002-check-toolchain.md) part 1). Locally the Nu Html Checker step prints a `NOT RUN` line and the final line reads `LOCAL PASS, HTML validation not run (CI only)`. A local green does not mean the HTML is valid; the SPEC §8 HTML row comes only from the `check` job in CI.

Steps, in order: fetch and verify the toolchain, shellcheck `tools/*.sh` (prints `shellcheck OK`; required under `CI=true`), the Hugo build into `public/` with `--panicOnWarning`, the Nu Html Checker (CI only), lychee on `public/`, and the self-test. Every step runs even after a failure, and the summary lists each result.

Self-test: every `tests/fixtures/<check>/<pass|fail>-<case>/` runs through the same function as the real step. A `pass-` case must exit 0. A `fail-` case must exit non-zero and print the substring in its `expect.txt`.

## Invariants

- **No npm (D3).** Never run `npm`, `npx` or `node` on a developer machine, not even for a quick Lighthouse run. No `package.json` or lockfile in the repo. The `[security]` and `[privacy]` keys in `hugo.toml` stay (ADR-0001 hardening keys). npm-only tools run only in CI jobs that hold no write token and do not build the deploy artifact.
- **Neutral, artifact-based records (D6, D7, D10).** A record describes artifacts, not a verdict about a company. A company or person name is either "name abused" (used without their involvement) or "front" (listing what was checked). Labels state facts, for example "reported 3 times, evidence reviewed on 2026-11-10", never "verified scam". A recruiter persona name appears only with the label "name used by the campaign, possibly a stolen identity". Attribution only as the cited source states it.
- **Nothing live (D8).** Attacker URLs and domains are always defanged: `hxxp://` or `hxxps://`, and every dot in a hostname or IP as `[.]`, for example `hxxps://login[.]meeting[.]example/join`. This applies to records, page copy, issues, PR bodies and QA reports. Record bodies carry no bare URLs, no Markdown links and no `<…>` autolinks; live links appear only in `sources`. No malware binaries, only SHA-256 hashes linking to MalwareBazaar or VirusTotal; never download a sample to check a hash. Fixtures use only RFC 2606 reserved names (`.example`, `.test`, `.invalid`, `example.com`).
- **No third-party requests (D9).** No external scripts, stylesheets, fonts, analytics or cookies. The Content Security Policy is a meta tag right after `<meta charset>` (Pages cannot set headers), and its single source is `params.csp` in `hugo.toml`.
- **Pages stays off until M6 (#7).** On the Team plan a Pages site from this private repo is public as soon as it deploys. `deploy.yml` only builds and uploads the artifact with a read-only token; no workflow may deploy or enable Pages before M6.
- **No raw evidence or personal data** in the repo, issues or PRs: no reporter identity, unredacted screenshots or mail headers. They stay in the operator's mailbox (D5, D7). Issues carry only defanged artifacts and an evidence summary.

## Load-bearing names

- The CI job `check` in `.github/workflows/ci.yml`. Branch protection requires exactly this context, so a rename must update the protection in the same session.
- The schema keyword `x-defang`, which marks the record fields that carry attacker artifacts ([ADR-0002](docs/adr/0002-check-toolchain.md) part 4).

## Workflows

- `ci.yml`: job `check`, on every PR and every push to `main`, runs `bash tools/check.sh`.
- `deploy.yml`: job `pages-artifact`, on pushes to `main` and on PRs that change it, runs `bash tools/check.sh` and uploads `public/` as the Pages artifact. It does not deploy.
- `links-external.yml`: weekly and on manual start, runs `bash tools/check.sh --external`. Not a required check.

Every action is owned by `actions/` and pinned to a 40-hex commit SHA with the tag as a comment. Runners are `ubuntu-24.04`, not `ubuntu-latest` (ADR-0002 part 5). Tokens are read-only.

## Upgrading a tool

Hugo: the pinning procedure in [ADR-0001](docs/adr/0001-static-site-generator.md). lychee and the Nu Html Checker image: [ADR-0002](docs/adr/0002-check-toolchain.md) parts 1 and 2, including the fallback when the pinned image digest disappears upstream. Every pin changes only in its own PR, which runs the full check.

## Content scrub

Before every commit, the staged diff (`git diff --cached`) must contain no client names and no paths from a developer machine (home directories, worktree paths). Envelope SDLC sessions run the scrub grep from their repo routing table. The pattern is not written here, because a file that spells out the names would itself match the scrub.
