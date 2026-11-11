# ADR-0006: Report and correction form

## Status

Accepted, 2026-11-11 (operator, Replikanti/interviewscam#13 STOP 1: decisions 1 to 3 as recommended; decision 1 amended to an existing Cloudflare account shared with unrelated Workers). The three decisions:

1. DNS, Workers and Email Routing at Cloudflare, in an existing account shared with unrelated Workers (the operator's), instead of a new account (parts 1, 10 and 12).
2. The Worker is JavaScript, one file with no dependencies, tested under the pinned `workerd` binary, not Rust (part 2).
3. A reply address is required on both forms. A correction or removal is acted on, and a form report counts toward independent reports, only after the requester answers the acknowledgment; the SPEC §6 own-name rule still hides the name first (parts 5 and 8).

Changes SPEC decision D5 (report intake) and adds one sentence to D9; edits SPEC §6 (Report a scam, Corrections and removal, Privacy), §8 (the CSP sentence), §9 (DNS, mail, accounts, the Worker deploy rule), §10 and §11. The implementation lands in sequenced PRs under the milestone Replikanti/interviewscam#13: this ADR and the SPEC edits in PR 1; the Worker, its tests and the deploy tool in PR 2; the forms and the check changes in PR 3; the DNS and mail cutover, the live test and the privacy page in PR 4.

## Context

- **SPEC before this ADR.** D5: report intake by email to `report@interviewscam.com`, forwarded by Namecheap; "later: a form that stores into a private place, for example a Cloudflare Worker with Turnstile that opens issues in this private repo". D9: no third-party requests, no external scripts, no cookies. SPEC §7: no `mailto:` link anywhere; the address is plain text. §10 listed the report form as out of scope for the MVP.
- **Why a form now.** The operator's reason (Replikanti/interviewscam#13, comment 6641084060, paraphrased): a `mailto:` link hands off to whatever mail app the operating system registered, often one the visitor never uses, and copying an address into another client is a step many visitors skip. A form is the convenient path; the address stays visible as plain text for the visitor who prefers mail (part 13).
- **Site checks today** (`site/main` 0fba7d5). `site` rule (a) fails every `<form action>`, `<button formaction>` and `<input formaction>` that leaves the origin; rule (e) fails `mailto:` in `href`, `action`, `formaction` and `xlink:href`; rule (b) fails any web manifest. `CSP_SOURCES` admits only `'self'` and `'none'`, and `params.csp` holds `form-action 'self'`. `hugo.toml` is closed-world (`HUGO_CONFIG_PINNED`). `guard` scans every executed `.js` outside the site sources for the JavaScript tool names. `fixture_inputs` fails on an unclassified top-level path. So this milestone changes rule (a) from "no other origin" to "exactly the intake URL, only on the two intake pages" (PR 3).
- **Cloudflare facts** (Cloudflare developer docs; the plan read them on 2026-11-11, pages "last updated" between Aug and Oct 2026; the Workers limits page, last updated Oct 29, 2026, was read again for this ADR):
  - Email Service needs the zone on Cloudflare DNS. Sending to a verified destination address is free on every plan, Email Routing alone included. A binding with `destination_address` can send only to that one address.
  - A message is at most 25 MiB in total, with at most 32 attachments, a 998-character subject and 16 KB of custom headers. The structured `send({to, from, subject, text, replyTo, attachments})` builder accepts `ArrayBuffer` attachments.
  - Workers Free: 10 ms CPU per HTTP request, 128 MB memory per isolate, 100,000 requests per day, all per account. Workers Paid: no daily request limit, CPU up to 5 min per HTTP request with a default of 30 s. A Free zone accepts request bodies up to 100 MB.
  - The Rate Limiting binding is approximate, counts per location, and allows a period of 10 or 60 s only.
  - SQLite-backed Durable Objects are available on Workers Free, with 100,000 requests and 100,000 rows written per day (per account).
  - Workers Logs are on by default for new Workers and kept 3 days on Free (7 days on Paid); invocation logs can be switched off.
  - "Email preview" is on by default for a new sending domain and keeps sent messages, attachments included, for about 7 days.
  - WAF rate limiting on Free: 1 rule, counting by IP, a 10 s period, a 10 s block, the path as the only field.
- **API token scope, checked for this ADR on 2026-11-11 in Cloudflare's public docs** (no authenticated call; see part 10 for the operator step that settles it):
  - "Create tokens via API" (last updated Sep 28, 2026): token policies support three resource types, `User`, `Account` and `Zone`; a single account is `com.cloudflare.api.account.<ACCOUNT_ID>`, a single zone `com.cloudflare.api.account.zone.<ZONE_ID>`. No resource type for a single Worker is documented. The same page documents `not_before` and `expires_on` (UTC timestamps) and the `request.ip` filter in CIDR notation.
  - "API token permissions" (last updated Oct 30, 2026): Workers Scripts Read and Edit are listed under Account permissions; Workers Routes Read and Edit under Zone permissions.
  - "Create API token" (last updated Nov 6, 2026): the dashboard policy types are Account, User and Zone, with specific accounts or zones as resources.
  - The API reference "Upload Worker" lists as accepted permissions Workers Scripts Write, Workers Admin, Workers Editor, Individual Workers Admin and Individual Workers Editor. The last two read like per-Worker roles, but the "Roles" page (last updated Oct 12, 2026; resource-scoped roles in Beta) and the "Role scopes" page (last updated Sep 16, 2026) list no per-Worker scope, and neither documents such a role for an API token. The API reference "Attach Worker Domain" lists Workers Scripts Write.
  - So the public docs document no per-script token resource, and they do not rule one out either. Whether one exists is an account-bound fact (part 10).
- **Tooling.** workers-rs builds with `worker-build`, which downloads esbuild from `registry.npmjs.org` (`worker-build/src/binary.rs` on its main branch, read by the plan). workerd publishes standalone `workerd-linux-64.gz` binaries on its GitHub releases (v1.20261110.1: 44.7 MB).
- **The account.** The Worker runs in the operator's Cloudflare account, an existing account shared with unrelated Workers. Some of those Workers turn form submissions into GitHub issues for their own purposes. The plan tier (Workers Free or Paid) is recorded by the operator at the cutover (PR 4).
- **Open neighbours.** interviewscam-site#2 (M4 PR 4/4) adds render rule 17 and reflow cases (8) and (9) and rewrites much of `tools/sitecheck.py` and `tools/selftest.sh`, so PRs 2 and 3 branch after it merges and take the next free numbers. Replikanti/interviewscam#32 reworks how `site` reads the CSP; whichever lands second rebases.

## Decision

Plain HTML forms on `/report-a-scam/` and `/corrections/` POST (`multipart/form-data`, no JavaScript) to one first-party endpoint, `https://intake.interviewscam.com/submit`: a Cloudflare Worker on a Workers Custom Domain. The Worker validates the submission, rate-limits it through a SQLite-backed Durable Object keyed by an HMAC of the client's IP prefix, and mails each accepted submission through a `send_email` binding fixed to the operator's verified address. It stores nothing and answers only with `303` redirects to static result pages on `https://interviewscam.com`, so every word a reporter sees stays under the existing `literals`, `render` and Lighthouse checks.

### 1. Intake path

Form, then the Worker at `https://intake.interviewscam.com/submit` (one path, `POST` only), then `send_email` with `destination_address`, then the operator's mailbox. No storage: no KV, R2 or D1, and no request body in any log. No automatic issue: the operator files intake issues by hand after triage, as today.

**Why:** the mailbox is already where D5 and D7 keep raw evidence and reporter identity, so the form adds a channel into it and no second store of personal data. A Worker that also files an artifacts-only issue in the private repo would need a repo-write GitHub token stored at Cloudflare, and it would have to defang arbitrary reporter text (D8), which no Worker-side heuristic does reliably: a missed live URL in an issue is exactly what D8 forbids. That some unrelated Workers in the same account turn form submissions into GitHub issues changes neither reason; their pattern is not adopted.

**Rejected:**

- Email only: the operator's reasons against `mailto:` and against copying an address into another client (part 13).
- A Worker that writes R2 or KV: a second store of personal data next to the mailbox, with its own retention and access rules.
- Third-party form services: a request to a third party and its script or redirect on the site (D9).
- A same-origin path through proxied Pages DNS: Cloudflare would see every page view, and proxying changes how GitHub Pages issues its HTTPS certificate.
- A `*.workers.dev` hostname: a shared domain that is not the site's own, and Email Service needs the zone on Cloudflare DNS anyway.
- Cloudflare Pages Functions: it moves the site's hosting, which D4 decides.
- An automatic issue from the Worker: the two reasons above.

### 2. Language and runtime (STOP 1 decision 2)

A JavaScript ES module, `worker/intake.js`, one file, no imports except the runtime's `cloudflare:workers`. Tested under the pinned `workerd` release binary (PR 2).

**Why:** every API the Worker touches is a JavaScript API of the runtime: `Request.formData`, the Durable Object class, `send_email` and `crypto.subtle`. One reviewed file with no dependency graph is the pattern of the site's scripts (ADR-0005 part 5, one pinned source per script), and `workerd` is the open-source runtime that production runs, shipped as a single binary that needs no npm (D3).

**Rejected:**

- (a) workers-rs: its `worker-build` fetches esbuild from the npm registry, which D3 forbids on a developer machine, and its crate graph is far larger than a program of about 400 lines.
- (b) A std-only Rust core compiled to WebAssembly: a Durable Object class must be a JavaScript class and the runtime APIs above are JavaScript, so Rust would own only the byte and string checks, about 100 lines, behind a hand-written pointer and length interface. That adds a bug class the JavaScript version lacks, and the shipped binary is a file no review reads, against one reviewed, pinned source per script.
- (c) A Python Worker (Pyodide): its cold start costs CPU against the 10 ms of Workers Free.
- (d) Miniflare or wrangler for the tests: npm (D3).
- Revisit trigger for Rust: the Worker starts parsing image formats, for example to strip EXIF metadata.

### 3. Anti-spam

D5 named Turnstile and D9 forbids third-party scripts; this part reconciles them: no widget.

- A honeypot field `website` inside a `<div hidden>`. Any non-empty value, or a missing field, means no mail and a redirect to `#not-accepted`. The submission is rejected, not silently dropped, so a human who somehow fills it is told to use email instead; a silent drop could lose a D7 notice.
- `Origin`: absent, or exactly `https://interviewscam.com`. Anything else, `null` included, gets `#not-accepted`.
- A per-client limit and a global daily cap in one Durable Object, `IntakeLimiter` (Numbers).
- One WAF rate-limiting rule on the path `/submit` (Numbers).

**Why:** a form without a widget gets bot traffic, and every layer above costs the visitor nothing: the honeypot stops form-filling bots, the Origin check stops cross-site posts, the per-client limit bounds one source, the daily cap bounds the mailbox, and the WAF rule stops a flood before the Worker runs.

**Weak point:** a targeted attacker who reads the form defeats the honeypot and the Origin check; the limits then bound the damage, and the address stays as a channel (Consequences).

**Rejected:**

- Turnstile, reCAPTCHA and every other widget: a third-party script (D9).
- The Rate Limiting binding: approximate, per location and limited to 10 or 60 s periods, so it cannot express an hourly limit or a daily cap.
- KV counters: eventually consistent, so parallel requests read a stale count.
- A JavaScript proof of work: the form must work without JavaScript.

### 4. Uploads

PNG, JPEG, GIF and WebP only, detected by their magic bytes:

- PNG: `89 50 4E 47 0D 0A 1A 0A`.
- JPEG: `FF D8 FF`.
- GIF: `GIF87a` or `GIF89a`.
- WebP: `RIFF`, 4 bytes, then `WEBP`.

The client's MIME type and file name are ignored. Each file is re-attached as `evidence-<n>.<ext>` with the detected type. A count cap and a total size cap (Numbers), no per-file cap. A file part with an empty file name and size 0 (the browser's "nothing chosen" part) is ignored. The page tells reporters to send PNG or JPEG.

**Why:** screenshots are the evidence D7 asks for. Detection by bytes, not by the client's claim, keeps executables and documents out of the operator's mailbox. The total bounds memory, CPU and message size; a per-file cap would only reject one large screenshot that the total admits. SVG is excluded because it is active content. HEIC and AVIF are excluded because they are not screenshot formats and the operator's mail client may not render them.

**Rejected:** a per-file cap (above); accepting any type the client names (a renamed executable passes); SVG (active content).

### 5. Fields per channel

These names are load-bearing (PR 2 and PR 3 read them). `channel` is a hidden field, `report` or `correction`.

- `report`: `name` (required), `contact_start`, `details` (required), `headers`, `email` (required, STOP 1 decision 3), `files`, `website`.
- `correction`: `page_url` (required; it must parse with the WHATWG URL parser to the origin `https://interviewscam.com`), `request` (required), `own_name` (checkbox, value `yes`), `email` (required), `files`, `website`.
- The set is closed: an unknown field, or a single-value field sent twice, gets `#not-accepted`.
- Lengths are counted in UTF-16 code units after CRLF and CR become LF. That is the unit HTML `maxlength` uses, so a value the browser accepts is never refused.
- A required value is empty when nothing is left after trimming Unicode `White_Space` plus U+200B, U+2060 and U+FEFF.
- `email` must match the HTML "valid e-mail address" grammar, the one the browser uses for `type="email"`, and be at most 254 characters.

**Why:** a closed set and fixed caps give each field one meaning the moderator can rely on and bound the mail. The reply address is required because the operator acknowledges every submission and acts only after the answer (part 8); without it a form submission could never be verified. Counting as the browser counts and validating as the browser validates means the server never refuses what the form accepted.

**Rejected:** an optional reply address (decision 3: an unverifiable report or request); free-form extra fields (no fixed meaning, unbounded mail).

### 6. Responses

- Every outcome is a `303 See Other` to `https://interviewscam.com/sent/` or `https://interviewscam.com/not-sent/#<id>`; 303, not 302, because a POST must become a GET.
- The `<id>` comes from a closed set: `too-large`, `too-many-files`, `not-an-image`, `missing-field`, `too-long`, `bad-address`, `bad-page-url`, `too-many-attempts`, `paused`, `not-accepted`, `error`.
- The redirect target is covered by `form-action 'self'`, whether or not a browser applies `form-action` to redirects.
- Headers: `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. No `Set-Cookie`, ever.
- A method other than POST gets `405` with `Allow: POST` and an empty body. A POST to another path gets `404` with an empty body.
- Any exception gets `#error`. Never a 500 and never a stack trace.
- The Worker holds no copy: `/not-sent/` explains each case, says that chosen files must be picked again after going back, and always shows the address as plain text.

**Why:** the Worker then emits no text at all. Every word a reporter reads lives on a static page of the site, under `literals`, `render`, the HTML checker and Lighthouse, and the D7 wording review covers it like any other page.

**Rejected:** a Worker that renders its own result pages: text outside every check, served from a second origin with its own CSP.

### 7. Mail

- `from: intake@interviewscam.com`, no `to` (the binding's `destination_address` applies), `replyTo` the validated `email`.
- Text only, no HTML part.
- Subject: `Report: <name>`, `Correction: <page_url>`, or `Correction, own name: <page_url>` when `own_name` is set, so the SPEC §6 hide-first case stands out in the mailbox.
- Subject values are stripped of C0 and C1 controls, bidi controls (U+202A to U+202E, U+2066 to U+2069) and zero-width characters, and whitespace is collapsed.
- The body keeps the reporter's text verbatim with two changes. C0 controls other than TAB and LF are removed. URL schemes are rewritten: `http://` becomes `hxxp://`, `https://` becomes `hxxps://`, `ftp://` becomes `fxp://`, case-insensitively and idempotently, and a header line states that rewrite.

**Why:** the subject lines match the ones the email channel already asks for, so both channels sort alike. The scheme rewrite makes a pasted live URL inert in the operator's mail client. Bare domains stay; that is no new gap, because today's email channel delivers them the same way and the page asks for defanged text (D8).

**Rejected:** an HTML part (markup from reporter text in the operator's client); defanging bare domains in the mail (a heuristic that changes evidence and still misses forms; the page instructs reporters instead).

### 8. Verification before acting (D7; STOP 1 decision 3)

A typed reply address is unverified: anyone can type anyone's address, while an emailed report's sender is at least checked by its provider. So:

- The moderator acknowledges every submission by replying.
- A correction or removal is acted on only after the requester answers. The one exception is the SPEC §6 own-name rule: the name is hidden first and restored when the verification fails.
- A form report counts toward `independent_reports` only after the reporter answers.
- A company's request is verified by a reply from an address on the company's own domain, or by other evidence.

**Why:** D7 publishes nothing without review, and the count of independent reports is a public claim; one person typing ten addresses must not become ten reports, and a competitor must not remove a record by typing someone else's address.

**Weak point:** a third party's address typed into the form receives one neutral acknowledgment.

**Rejected:** acting on an unanswered form request (a forged requester); a verification link or auto-reply sent by the Worker (arbitrary recipients would need Workers Paid and make the Worker a mail relay; Consequences).

### 9. The endpoint origin under D9 and SPEC §8

The endpoint is first-party: a subdomain of the site's own registrable domain, run by the same controller. A form submission is a navigation the visitor starts, like `<a href>`, not a request the page makes. D9 and §8 ("none in the built site") therefore hold unchanged.

- No page fetches anything from the intake origin; every request-scan rule of `site` keeps refusing it.
- Only `<form action>` may name the intake origin, only as exactly `INTAKE_ACTION`, and only on the two intake pages (PR 3).
- `params.csp` `form-action` is exactly `'self' https://intake.interviewscam.com`. `'self'` stays for the Home search form, which submits GET to `/a-z/`.

**Why:** D9 protects visitors from requests they did not ask for and from code a third party can change. A submit they press, to the site's own domain, is neither. Pinning the one action on the two pages keeps every other page exactly as strict as before.

**Rejected:** loosening `leaves_origin` for the intake origin (every request-scan rule would admit it); a wildcard or a path in `form-action` (wider than the one origin the form needs).

### 10. Source, pinning and deploy

- The source lives at `worker/intake.js` in the public code repo, so it holds no secret. Its SHA-256 is pinned in `tools/sitecheck.py`, so every Worker change is a `tools/` change and gets the safety-net review.
- The operator deploys from their own machine with `tools/intake.py deploy`. The tool refuses to run under `CI` or `GITHUB_ACTIONS`, on a dirty tree, on a HEAD other than `site/main`, or when the source differs from its pin. `tools/intake.py verify` downloads the deployed script and compares it with the pin.
- The tool hard-codes the script name `interviewscam-intake` and tags the script `interviewscam-intake`. It refuses to upload when a script of that name exists without that tag, so a typo or a name clash can never overwrite an unrelated Worker.
- The token is read from `CLOUDFLARE_API_TOKEN` or a `getpass` prompt and is never written, logged or printed. The account ID, the zone ID and the destination address are prompted too and never stored in the repo.
- Deploy language: Python standard library (`urllib`, `ssl`, `json`), like the existing tools.

**Token scope (STOP 1 amendment).** The operator asked for a token limited to this zone and this one Worker. The public docs read for this ADR (Context) document no token resource for a single Worker: Workers Scripts Edit is an Account permission, and token resources are User, Account and Zone. The API reference names "Individual Workers Admin" and "Individual Workers Editor" among the permissions Upload Worker accepts, which no other page explains. This is not settled by the docs, so it is an **operator verification step** before the first deploy (PR 4, before the token is created): list the permission groups with `GET /accounts/{account_id}/tokens/permission_groups` and look for a group, or a resource type, that applies to one Worker script; record the result in the PR 4 body.

- If a per-script resource exists, the token uses it, and no account-wide Workers permission is granted.
- Otherwise these are the narrowest grants:
  - Account policy: this account only (`com.cloudflare.api.account.<ACCOUNT_ID>`), Workers Scripts Edit only, nothing else at account level. It covers the upload, the bindings, the secret and the custom domain (the API reference lists Workers Scripts Write for Attach Worker Domain).
  - Zone policy: `interviewscam.com` only (`com.cloudflare.api.account.zone.<ZONE_ID>`), Workers Routes Edit, for the custom domain. If the first deploy in PR 4 attaches the custom domain without it, PR 4 drops this grant and amends this part.
- The account-wide grant is contained in four ways: (1) validity set through the API (`not_before`, `expires_on`) to the deploy session, at most 24 h; (2) client IP filtering (`request.ip`) to the operator's current address; (3) the operator revokes the token right after the session, and the tool prints that reminder; (4) the tool can address only one script.

**Shared-account blast radius (STOP 1 amendment).** The account is an existing account shared with unrelated Workers. Three directions:

- (a) From this deploy outward. A token stolen during its validity window could rewrite the unrelated Workers, including any that hold their own secrets. Containment: the window, the IP filter and the revocation above. Under a per-script resource, (a) disappears.
- (b) From the account inward. Any account member, and any long-lived token of the account with Workers Scripts Edit, could rewrite the intake Worker and read reporters' submissions. Containment: at the cutover the operator reviews the members and the account's API tokens, and every token with Workers edit gets a validity limit or is revoked. `verify` runs after every deploy, in the PR 4 live test, before the M6 launch, and after any change to the account's members or tokens.
- (c) Shared Free-plan quotas. On Workers Free, the 100,000 daily requests and the Durable Object limits count across all Workers of the account. A flood on the intake can exhaust them for the unrelated Workers, and their traffic eats into the intake's. Containment: the WAF rule and the per-client limit bound one source; the plan tier recorded at the cutover decides whether this applies at all (Workers Paid has no daily request limit).

**Why:** a deploy is rare and needs the most powerful credential in the design, so it happens where the credential lives for the shortest time and nothing else can read it. The pin plus `verify` makes "the code that runs is the code that was reviewed" a check, not a hope, which matters more in an account other parties can write to.

**Rejected:**

- A CI deploy job: it would put a Cloudflare token into GitHub Actions of a public repo, where a compromised action or a workflow change could read it.
- A long-lived deploy token: it widens exposure (a) to every day of the year.
- A dedicated Cloudflare account: the operator declined a new account at STOP 1.
- Rust for the deploy tool: its standard library has no TLS client, so it would need a crate stack or a call out to `curl`.

### 11. Privacy and logs

- The limiter key is HMAC-SHA-256 under a 32-byte secret, `LIMITER_KEY`, over the IPv4 /32 or the IPv6 /64 of `CF-Connecting-IP`. An IPv4-mapped IPv6 address is read as IPv4. The raw IP is never stored or logged.
- Limiter rows are deleted after 3,600 s, both on access and by a Durable Object alarm.
- Workers Logs on, invocation logs off. Custom log lines are `intake event=<code>[ code=<E_...>]` only.
- Email preview off for the domain (PR 4 verifies it).
- The Email Routing activity-log retention is verified in PR 4 and stated on the privacy page.

**Why:** the limiter needs a stable key per source for one hour and nothing more; a keyed hash cannot be reversed by enumerating the 2^32 IPv4 addresses, which a plain hash can. Event codes are enough to debug the Worker and carry no personal data. Email preview would keep every submission, attachments included, a second time at Cloudflare for about 7 days.

**Rejected:** a plain hash of the IP (reversible by brute force); invocation logs (they record request metadata per call); leaving Email preview on (a second copy of every submission).

### 12. DNS and Email Routing cutover order (SPEC §9)

PR 4's runbook, in this order:

1. Inventory: export the Namecheap DNS records; note whether `report@` forwarding is active, whether DNSSEC is on, and the MX TTL (`dig`).
2. In the existing account: verify that the login has passkey or hardware-key 2FA, review the members (each needed, each with 2FA) and the API tokens (part 10 (b)), record the Workers plan tier, add the zone, and review the imported records (keep the Namecheap forwarding MX while forwarding is active, any GitHub records DNS-only, the Pages verification TXT record, no wildcard).
3. If DNSSEC is on: remove the DS at Namecheap and wait the DS TTL (measured), then switch the nameservers to Cloudflare's pair and wait for the zone to show Active, then re-enable DNSSEC at Cloudflare and add its DS at Namecheap.
4. Email Routing: add and verify the destination address, create the rule `report@` to that destination; Cloudflare's MX, SPF and DKIM replace the old MX. A test mail from an outside account must arrive and show "Forwarded" in the Activity log.
5. Only then, and at least 2× the old MX TTL after the MX change, remove the Namecheap forwarding.
6. Email preview off; the operator verification of the token scope (part 10); create the token; deploy, `verify`, create the WAF rule; the live test; `verify`; revoke the token.

**Why:** a DS record left in place while the nameservers move breaks resolution for validating resolvers, so it goes first and its TTL is waited out. Mail must never have a gap: the new route is proven before the old one is removed, and the old one stays for two MX TTLs so that every resolver's cached MX has expired.

**Rejected:** switching nameservers and mail in one step (a resolution or delivery gap that nothing measures).

### 13. Why no `mailto:`

The operator's own reason, paraphrased (Replikanti/interviewscam#13, comment 6641084060): a `mailto:` link hands off to whatever mail app the operating system registered, often one the visitor never uses. The form is the convenient path, and the address stays visible as plain text to copy into the client the visitor actually uses. SPEC §7 and `site` rule (e) stay as they are.

**Rejected:** a `mailto:` link next to the form (the hand-off above, and rule (e)).

## Numbers

| Number | Value | Derivation, and what breaks at another value |
|---|---|---|
| Total upload cap | 10 MiB (10,485,760 bytes) | Base64 with a CRLF every 76 characters expands by 4/3 × 78/76 = 1.368, so 10 MiB becomes 13.68 MiB, and with at most 0.2 MiB of text 13.9 MiB, under the 25 MiB message limit; the arithmetic ceiling is 25 / 1.368 = 18.27 MiB. The screenshot sizes behind 10 MiB are an estimate until measured on real screenshots (file sizes only, for example the M5 evidence set the operator holds); the CPU cost is measured in PR 4 (halving rule below). Lower: several PNG screenshots no longer fit. Higher: closer to the 10 ms CPU limit of Workers Free and to 25 MiB. |
| File count cap | 10 | The API limit is 32 attachments. The page asks for about 5 kinds of image evidence (messages, invite, app or landing page, repository or package page, the sharing account), 2 each. 10 MiB / 10 = 1 MiB mean, about one typical screenshot, so neither cap makes the other dead. Lower: a full set of evidence no longer fits. Higher: files a screenshot set does not need, closer to 32. |
| `INTAKE_MAX_BODY` | 10,747,904 bytes (10 MiB + 256 KiB) | The text worst case is about 42.7k UTF-16 code units at up to 3 bytes each, 128 KB; the multipart overhead about 18 parts × 200 bytes = 3.6 KB. 256 KiB is about 2× their sum. A larger `Content-Length` is refused before the body is read. Lower: a maximal valid submission is refused. Higher: more bytes read before the parse rejects them. |
| `name`, `contact_start` | 200 UTF-16 code units each | About 2× a long company or app name. Keeps the subject `Report: <name>` far under 998 characters. Lower: a long name is cut. Higher: a subject that no longer reads at a glance. |
| `details`, `request` | 10,000 each | About 1,500 words. The page asks for a few sentences, so the cap never binds a real report and still bounds the mail. Lower: a long account of a campaign is refused. Higher: an unbounded mail for no report that needs it. |
| `headers` | Provisional 32,000; final value 2× the largest header block measured on at least 3 real received messages (sizes only), rounded up to the next 1,000, measured by the operator before PR 2 merges | A cap below one real header block forces the reporter to cut the evidence D7 asks for. The provisional value is an estimate, not a measurement. Higher than needed: only a larger mail. |
| `page_url` | 200 UTF-16 code units: 2× the longest page URL in `public-fixtures/`, rounded up to the next 100, at most 976 (measurement below) | 976 = 998 − 22, because `Correction, own name: ` is 22 characters and the subject must stay within 998. The fixture build holds the longest slugs the record rules admit in a test, so 2× leaves room for real slugs. Lower: a real page URL is refused. Higher than 976: the subject can exceed 998. |
| `email` | 254 | RFC 5321 §4.5.3.1.3: a path is at most 256 octets including the two angle brackets. Lower: valid addresses refused. Higher: addresses no mail server accepts. |
| Per-client limit | 6 POST attempts per rolling 3,600 s per key | 1 report plus 1 correction, plus 2 retries each. Every attempt counts, rejections included, so a client cannot make the Worker parse without limit. One source: at most 144 attempts per day. Lower: a retry after a `too-large` gets blocked. Higher: more parsing per source. |
| Window bound | Attempts with `at > now − 3,600,000 ms` count | An attempt exactly 3,600,000 ms old no longer counts (exclusive bound), so the window is exactly one hour and the tests can pin both sides. |
| IPv6 key | /64 | RFC 4291 and RFC 7421: a /64 is one LAN. RFC 8981 temporary addresses let one host rotate inside its /64, so a /128 key would be evadable. Wider (/56, /48): unrelated households of one provider share a limit. |
| IPv4 key | /32 | One address. Weak point: CGNAT shares one address among many users; at 6 per hour and this site's volume a collision is improbable, and `/not-sent/#too-many-attempts` shows the address. Wider: unrelated users share a limit. |
| Global cap | 50 mailed submissions per UTC day, with 1 notice mail to the operator when the cap is first hit that day | At about 10 min of triage each (estimate), 50 is about 8 h, one moderator's full day. Worst-case mailbox growth: 50 × 13.9 MiB = 695 MiB per day. Lower: a real burst after a campaign is shared gets paused sooner. Higher: floods outgrow one moderator. While paused, reports go to email. |
| `LIMITER_KEY` | 32 bytes | The output length L of SHA-256. RFC 2104 §3 strongly discourages keys shorter than L bytes and states that keys longer than L do not significantly increase the strength. A keyed hash of the 2^32 IPv4 addresses cannot be reversed by brute force without the key, which a plain hash can. Shorter: a weaker key than the hash allows. Longer: no added strength. |
| Limiter row lifetime | 3,600 s | Equal to the window: a row older than the window counts for nothing, so keeping it longer only keeps a keyed IP hash longer. |
| WAF rule | 5 requests per 10 s per IP on `/submit`, block 10 s | Workers Free WAF offers only 10 s periods and 10 s blocks. A human submits once. One source is held to at most 5 per 10 s = 43,200 per day, under the 100,000 daily requests, so one source alone cannot use them up; two can (Consequences). Lower: a double click plus a retry is blocked. Higher: one source can use up the daily quota. |
| CPU threshold | 7 ms on Workers Free | 70 % of the 10 ms limit, leaving 30 % headroom for variance between requests. PR 4 measures a max-size submission; above 7 ms the upload cap halves until a measured max-size request is at or below 7 ms, with a floor of 5 MiB, below which it goes back to the operator (Workers Paid, or a smaller cap). On Workers Paid the limit is 30 s by default, so the figure is only recorded. |
| Token validity | The deploy session, at most 24 h, set through the API | The dashboard offers only whole UTC days. One deploy session plus the live test fits; the token can edit every Worker in the shared account, so a shorter window shrinks exposure (a), and 24 h bounds a session that runs long. |
| workerd pin and `compatibility_date` | The pinned workerd release date, used in the tests and in production | Tests and production then run the same runtime semantics. A different date in production would test one behaviour and ship another. |
| Logs retention | 3 days (Free) or 7 days (Paid), by the tier recorded at the cutover | Cloudflare's figures; nothing personal is in the logs. |
| DNS waits | The DS TTL, and 2× the old MX TTL, each measured with `dig` before the step | Shorter: a validating resolver or a cached MX still points at the old setup. Longer: only a later cutover. |

**`page_url` measurement** (2026-11-11, the fixture build of `site/main` 0fba7d5): the longest page URL is 95 characters, the page of the long-name report of the canonical fixture set that the reflow test uses (`https://interviewscam.com/reports/` plus its slug and `/`). 2 × 95 = 190, rounded up to 200, under 976. PR 2 re-measures on its own base and updates this value if a longer fixture page has landed.

## Consequences

- PR 2 (`worker/intake.js`, `tests/worker/`, `tools/intake.py`, the `INTAKE_*` constants and the workerd pin) and PR 3 (the forms, `data/labels.toml`, the result pages, the CSP and `site` rule (a)) are safety-net PRs; PR 3 and PR 4 are also content PRs, so they get `sdlc-reviewer` with QA and the operator's D7 wording approval at their STOP 2.
- The field names, `INTAKE_RESULT_IDS`, `IntakeLimiter`, the script name `interviewscam-intake` and the intake URL become load-bearing names; a rename changes the Worker, the constants, the forms and the result pages in one PR.
- A Worker change is a re-pin and a redeploy by the operator; `verify` is part of every deploy, the PR 4 live test, the M6 launch and every change to the account's members or tokens.
- The privacy page is written only in PR 4, from the settings verified there.
- Two attacking sources can exhaust the 100,000 daily Worker requests on Workers Free or the 50-mail cap. The channel degrades but is not lost: both pages and `/not-sent/` always show the address, and the cap notice reaches the operator.
- `send_email` and the Durable Object are emulated by workerd locally; the live test in PR 4 is the production proof, and it runs the same suite.
- Out of scope: any widget; an automatic issue; a Worker auto-reply (arbitrary recipients would need Workers Paid and make the Worker a mail relay); DMARC policy and replies sent as `@interviewscam.com` (offered to M6); defanging bare domains and stripping EXIF in the Worker; the Pages DNS records and enabling Pages (M6).
