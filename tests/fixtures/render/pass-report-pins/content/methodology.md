+++
title = "Methodology"
description = "How reports are reviewed, what the states mean and how sources are used."
+++

This page explains how a report becomes a page, what the labels mean and how sources are used.

## Pages describe artifacts

A page is about the things a candidate actually sees. These are artifacts such as a domain, a meeting app name, a file hash, a recruiter handle, a repository or a package. The page records how a scam campaign used them. It is not a verdict about a company or a person.

## Review before publication

Nothing is published without evidence and a review by the moderator. Evidence means screenshots with personal data redacted, message headers, URLs and file hashes. A report without evidence is not published. Reporters stay anonymous to the public, not to the moderator.

## Names and their two states

Scam campaigns often use the names of real companies, real products and real people. Every name that has its own page has one of two states, whether it is a company, a recruiter, a meeting app, a domain, a repository or a package.

- **Name abused.** A real company, person or product whose name the campaign used. The page says the name was used without their involvement.
- **Front.** No sign was found that a real company, person or product stands behind the name, for example no entry in a business register, no history and no footprint on the web. The page lists what was checked.

The address of a page about a person never contains the person's name. It carries a number instead, so the name can be hidden without moving the page.

## Recruiter names

Recruiter identities are often stolen from real people. A recruiter's name appears only when the evidence shows it in the scam contact. Wherever the name is shown as a name, it carries the label "name used by the campaign, possibly a stolen identity". On the report page about that recruiter, and in that recruiter's entry of the [data feed](/data-feed/), the name can also appear inside the handles, email addresses and other artifacts the campaign used. The heading of that page and the `name_label` field of that entry carry the label. The real person can ask for removal through [Corrections and removal](/corrections/).

## Labels state facts

Labels say what was reported and what was reviewed, and when. An example is "reported 3 times, evidence reviewed on 2026-11-10". The site never labels anything a verified scam.

## Sources

Campaign pages group artifacts into the campaign families that security researchers describe. Each page links its sources with their dates.

A page names a campaign family only when a cited source links the name or its artifacts to that family, and the page names that source. Otherwise the page is marked as unattributed, which is the default. Who is behind a campaign is stated only as the cited source states it. The site adds no attribution of its own.

When a campaign abused the name of a real company, the family is named as the campaign that used the name. The page never suggests that the family is behind the company.

## Why links look broken

Attacker links are written in a form that does not work, for example `hxxps://example[.]com`. Here `hxxps` stands for `https` and `[.]` stands for a dot. Nothing on the site is a live link to an attacker, so a stray tap or a link preview in a chat app opens nothing.

Every other name with a dot is written the same way, whether it is a domain, a file name or the name of a tool or company, for example `Setup[.]zip`. Only the address of this site keeps its dot. So nothing on the site can be opened by accident. The bracket says nothing about who owns a name, because a real company's domain that a campaign abused is written with `[.]` too. The state of the name says that. Where a name reads naturally without its dot, it is written that way, for example Doctor Web.

No malware files are published. A file appears only as its SHA-256 hash, with a link to MalwareBazaar or VirusTotal, where you can look the hash up.

## Mistakes

If something on a page is wrong, [ask for a correction](/corrections/).
