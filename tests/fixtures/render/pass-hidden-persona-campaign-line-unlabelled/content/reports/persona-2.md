+++
date = 2026-11-01
[params]
name = "Morgan Placeholder"
name_type = "persona"
state = "name_abused"
hide_name = true
state_basis = [
  "A real recruiter uses this name and said in public that the messages did not come from them.",
]
summary = "A recruiter persona that copies the name of a real recruiter and sends a coding task."
evidence = "One candidate submission was reviewed: the messages and the task repository."
first_seen = 2026-10-05
last_seen = 2026-10-25
last_reviewed = 2026-11-01
independent_reports = 1

[params.campaign]
slug = "example-campaign-family"
source = "desk-accounts"
basis = "artifact"
artifact = "@hiring_désk"

[params.artifacts]
handles = [
  { platform = "discord", value = "123456789012345678" },
  { platform = "telegram", value = "@hiring_désk" },
]

[[params.sources]]
id = "desk-accounts"
title = "Recruiter accounts that hand out fake coding tasks"
publisher = "Vendor Example Research"
date = 2026-10-24
url = "https://vendor.example/research/desk-accounts"
+++
