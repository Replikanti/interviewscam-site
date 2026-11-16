# Architecture decision records

An ADR records one decision from `docs/SPEC.md` §4, or one decision that the SPEC leaves to a milestone, together with the reason and the alternatives that lost. The SPEC rule applies: when a §4 decision is made or changed, the PR also adds or amends an ADR here.

## Numbering

Files are named `NNNN-slug.md`. The number has four digits so that lexical order equals numeric order. Numbers are never reused.

## Template

Every ADR has these sections, in this order.

- **Status**: the state and its date, for example `Accepted, 2026-11-04`.
- **Context**: the facts that force the decision, with their dates and sources.
- **Decision**: what we do, stated so that a reader can check the repo against it.
- **Why**: the goal the decision serves, the data behind it, and its known weak point.
- **Rejected alternatives and why they lost**: each option that was considered, with the reason it lost.
- **Numbers**: every number the decision depends on (version, hash, timeout, threshold). Each number has its derivation and what breaks at another value.
- **Consequences**: what the decision costs and what it obliges later work to do.

An ADR that records several decisions states Status, Context, Numbers and Consequences once. Under Decision it gives each part its own heading, and each part carries its own **Why** and **Rejected** lines.

## Review rule

A review of a PR that adds or changes an ADR rejects it when a decision has no reason, when a rejected alternative has no reason for losing, or when a number has no derivation. A number copied from another ADR needs its own reason here: "the other ADR uses it" is not a reason.

## Index

| ADR | Decision |
|---|---|
| [0001](0001-static-site-generator.md) | Static site generator: Hugo, standard edition |
| [0002](0002-check-toolchain.md) | Check toolchain: where each check runs and how it is pinned |
| [0003](0003-browser-checks.md) | Browser checks: Lighthouse pin and isolation, score gate, trigger, reflow |
| [0004](0004-record-model.md) | Record model: D6 state on every name, defanged record text, URLs and persona names, feed, structured data, fixture build, Copy button |
| [0005](0005-search.md) | Search: keys from the feed, display from `/a-z/`, matching rules, result display, two pinned scripts, search checks |
| [0006](0006-intake-form.md) | Report and correction form: first-party intake Worker, anti-spam without a widget, uploads, mail, verification before acting, deploy and token scope in a shared Cloudflare account, DNS and mail cutover |
