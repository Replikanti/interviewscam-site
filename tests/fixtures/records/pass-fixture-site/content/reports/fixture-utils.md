+++
date = 2026-10-28
[params]
name = "fixture[.]utils"
name_type = "package"
state = "name_abused"
state_basis = [
  "The package name belongs to a maintained open-source project.",
  "The versions in this record were published from an account the project does not control.",
]
summary = "Malicious versions of a legitimate package, installed by a take-home task."
evidence = "One candidate submission was reviewed: the task instructions and the installed version."
first_seen = 2026-10-08
last_seen = 2026-10-22
last_reviewed = 2026-10-28
independent_reports = 1

[params.artifacts]
packages = [{ registry = "npm", name = "fixture[.]utils" }]
+++
