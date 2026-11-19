#!/usr/bin/env bash
# One shard of a mutation sweep (ADR-0008, Replikanti/interviewscam#40).
#
# The shim the workflow hardening requires: a workflow step may only run
# `bash tools/<name>.sh [--flag]...` (ADR-0007 part 4), so every job of
# .github/workflows/mutation-sweep.yml runs `bash tools/mutate.sh --shard`,
# and tools/mutate.py does the work. It refuses to run outside a
# workflow_dispatch job of that workflow (exit 2): sweeps never run locally
# (ADR-0008 part 1). The merge of the downloaded results runs
# `python3 -I -B tools/mutate.py merge <dir>` directly.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 1 || "$1" != --shard ]]; then
  echo "usage: bash tools/mutate.sh --shard" >&2
  exit 2
fi
exec python3 -I -B "$root/tools/mutate.py" shard
