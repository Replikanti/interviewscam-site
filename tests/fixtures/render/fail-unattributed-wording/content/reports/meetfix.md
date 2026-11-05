+++
date = 2026-10-30
[params]
name = "MeetFix"
name_type = "meeting_app"
state = "front"
state_basis = [
  "No app store lists an app of this name.",
  "Its download site was registered in October 2026.",
]
summary = "A meeting app that candidates are asked to install before a call. No cited source links it to a campaign family."
evidence = "One candidate submission was reviewed: the invitation and the installer hash."
first_seen = 2026-10-10
last_seen = 2026-10-29
last_reviewed = 2026-10-30
independent_reports = 1

[params.artifacts]
domains = ["meetfix-download[.]example"]
sha256 = [
  { value = "0b8f3cba5a03e7d6ffc2b51c8f3a5aa2c1e2b3a4d5f60718293a4b5c6d7e8f90", listed_on = ["malwarebazaar"] },
]
+++
