+++
date = 2026-11-01
[params]
name = "Fixture"
name_type = "company"
state = "front"
state_basis = ["No company register lists this name."]
summary = "A fixture report."
evidence = "One fixture submission was reviewed."
first_seen = 2026-10-01
last_seen = 2026-10-15
last_reviewed = 2026-11-01
independent_reports = 1

[params.campaign]
slug = "missing-family"
source = "vendor-report"
basis = "named"

[params.artifacts]
domains = ["meeting[.]example"]

[[params.sources]]
id = "vendor-report"
title = "Fixture analysis of a fake meeting app"
publisher = "Vendor Example"
date = 2026-10-20
url = "https://vendor.example/report"
+++

A fixture record.
