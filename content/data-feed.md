+++
title = "Data feed"
description = "The JSON feed of every published report and campaign family: its address, its fields and how its version changes."
+++

The data feed lists every published report and campaign family in one JSON document, for researchers and tools. It is at [/feed.json](/feed.json), and it changes whenever the site changes.

## What it holds

Each report and each campaign family has one entry, with the same facts its page shows. Record bodies are not in the feed. Entries are sorted by slug.

Every artifact is written defanged, as on the pages, so nothing in the feed is a live link to an attacker. `hxxps` stands for `https`, `[.]` for a dot and `[@]` for the at sign. Restore them only where you mean to use the value. The only live URLs are the pages of this site, the cited sources and the lookup pages of a file hash.

A recruiter name that is hidden on request appears as `null`, with no aliases. A recruiter name that is shown comes with the label in `name_label`, "(name used by the campaign, possibly a stolen identity)", and the label belongs with the name and its aliases wherever you show them. The name can also appear inside that recruiter's own artifacts, such as a handle or an email address, as the campaign used them.

## Versioning

The field `version` is a whole number. It goes up only on a breaking change, when a field is removed, renamed or given another type or meaning. A new field keeps the version, and the list of changes below names it with its date. A reader that ignores fields it does not know keeps working across additions.

## Fields

A path such as `reports[].artifacts.sha256[].value` names the field `value` in each item of the list `sha256`, inside the `artifacts` of each item of `reports`. Dates are written as `YYYY-MM-DD`.

`version`
: Number. The version of the feed, `1` today.

`home_page_url`
: Text. The home page of the site.

`documentation_url`
: Text. This page.

`updated`
: Date or `null`. The latest publication or review date of any report or campaign family. `null` when there are none.

`reports`
: List. Every published report, one per name a candidate sees.

`reports[].slug`
: Text. The last part of the report's address, `/reports/<slug>/`. For a recruiter it is `persona-` and a number, never a name.

`reports[].url`
: Text. The address of the report page.

`reports[].name`
: Text or `null`. The name, defanged. `null` when the name is hidden on request.

`reports[].name_hidden`
: `true` or `false`. `true` when a recruiter's name is hidden on request.

`reports[].name_label`
: Text or `null`. For a recruiter whose name is shown, the label "(name used by the campaign, possibly a stolen identity)", which belongs with the name and its aliases. `null` for every other report.

`reports[].aliases`
: List of texts. Other spellings of the name, defanged. Empty when there are none or the name is hidden.

`reports[].name_type`
: Text. What kind of name it is: `company`, `persona` (a recruiter), `meeting_app`, `domain`, `repository` or `package`.

`reports[].state`
: Text. `name_abused` when the campaign used a real company's, person's or product's name without their involvement, `front` when no sign was found that a real party stands behind the name.

`reports[].state_basis`
: List of texts. What was checked to reach the state.

`reports[].campaign`
: Object or `null`. The campaign family that used the name, only when a cited source links the name or one of its artifacts to that family. `null` when the report is unattributed.

`reports[].campaign.slug`
: Text. The slug of the campaign family, one of `campaigns`.

`reports[].campaign.url`
: Text. The address of the campaign page.

`reports[].campaign.basis`
: Text. `named` when the source names this name, `artifact` when it lists the artifact in `artifact`.

`reports[].campaign.artifact`
: Text or `null`. With the basis `artifact`, the artifact the source lists, one of the report's artifacts. `null` otherwise.

`reports[].campaign.source_id`
: Text. The `id` of the source in `sources` that links the name to the family.

`reports[].related`
: List of texts. The slugs of related reports.

`reports[].summary`
: Text. A short summary of the facts.

`reports[].evidence`
: Text. A summary of the evidence that was reviewed.

`reports[].first_seen`
: Date. When the name was first seen in use.

`reports[].last_seen`
: Date. When the name was last seen in use.

`reports[].last_reviewed`
: Date. When the evidence was last reviewed.

`reports[].published`
: Date. When the report was published.

`reports[].independent_reports`
: Number. How many independent reports were reviewed. `0` when the report rests on cited sources alone.

`reports[].label`
: Text. The label of the report as its page shows it, for example "Reported 3 times, evidence reviewed on 2026-11-02".

`reports[].artifacts`
: Object. The artifacts of the report, grouped by kind. Only the kinds the report has appear.

`reports[].artifacts.domains`
: List of texts. Domains.

`reports[].artifacts.urls`
: List of texts. Web addresses.

`reports[].artifacts.ips`
: List of texts. IPv4 addresses.

`reports[].artifacts.emails`
: List of texts. Email addresses.

`reports[].artifacts.repositories`
: List of texts. Code repositories.

`reports[].artifacts.file_names`
: List of texts. File names.

`reports[].artifacts.handles`
: List. Accounts on messaging and social platforms.

`reports[].artifacts.handles[].platform`
: Text. The platform: `telegram`, `linkedin`, `x`, `discord`, `whatsapp`, `skype`, `github` or `other`.

`reports[].artifacts.handles[].value`
: Text. The handle as the campaign used it.

`reports[].artifacts.packages`
: List. Packages on package registries.

`reports[].artifacts.packages[].registry`
: Text. The registry: `npm`, `pypi` or `other`.

`reports[].artifacts.packages[].name`
: Text. The name of the package.

`reports[].artifacts.sha256`
: List. Files, each as its SHA-256 hash. No file is ever published.

`reports[].artifacts.sha256[].value`
: Text. The SHA-256 hash, 64 lowercase hex digits.

`reports[].artifacts.sha256[].file_name`
: Text. The name of the file, when it is known.

`reports[].artifacts.sha256[].listed_on`
: List of texts. The lookup services that list the hash: `malwarebazaar`, `virustotal`.

`reports[].artifacts.sha256[].lookup_urls`
: List of texts. The page of the hash on each service in `listed_on`, in the same order. A lookup page, never a download.

`reports[].sources`
: List. The cited sources of the report. Empty when there are none.

`reports[].sources[].id`
: Text. The name of the source within its entry, which `campaign.source_id` refers to.

`reports[].sources[].title`
: Text. The title of the source.

`reports[].sources[].publisher`
: Text. Who published the source.

`reports[].sources[].date`
: Date. When the source was published.

`reports[].sources[].url`
: Text. The address of the source.

`campaigns`
: List. Every published campaign family, as security researchers describe it.

`campaigns[].slug`
: Text. The last part of the campaign's address, `/campaigns/<slug>/`.

`campaigns[].url`
: Text. The address of the campaign page.

`campaigns[].name`
: Text. The name of the campaign family, defanged.

`campaigns[].aliases`
: List of texts. Other names of the family, defanged. Empty when there are none.

`campaigns[].summary`
: Text. A short summary of the facts.

`campaigns[].first_seen`
: Date. When the family was first seen.

`campaigns[].last_seen`
: Date. When the family was last seen.

`campaigns[].delivery`
: List of texts. How the family delivers its malware: `fake_meeting_app`, `coding_test_repository`, `npm_package`, `terminal_command`.

`campaigns[].targeted_os`
: List of texts. The operating systems it targets: `windows`, `macos`, `linux`.

`campaigns[].steals`
: List of texts. What it steals.

`campaigns[].attribution`
: List. Who is behind the family, only as the cited sources state it. Empty when they state no attribution.

`campaigns[].attribution[].statement`
: Text. The statement, as the source makes it.

`campaigns[].attribution[].source_id`
: Text. The `id` of the source in `sources` that makes it.

`campaigns[].report_slugs`
: List of texts. The slugs of the reports whose `campaign.slug` names this family.

`campaigns[].sources`
: List. The cited sources of the campaign.

`campaigns[].sources[].id`
: Text. The name of the source within its entry, which `attribution[].source_id` refers to.

`campaigns[].sources[].title`
: Text. The title of the source.

`campaigns[].sources[].publisher`
: Text. Who published the source.

`campaigns[].sources[].date`
: Date. When the source was published.

`campaigns[].sources[].url`
: Text. The address of the source.

## Changes

- 2026-11-07: version 1, the first form of the feed.
