#!/usr/bin/env bash
# The single local and CI entry point: CI runs `bash tools/check.sh` verbatim.
#
# Every step runs even after an earlier one failed, then a summary prints
# PASS / FAIL / SKIPPED / NOT RUN (CI only) per step, and the exit code is 1
# if any step failed.
#
# The Nu Html Checker runs only in CI (GITHUB_ACTIONS=true; ADR-0002 part 1).
# Outside CI its step prints a loud NOT RUN line and the final line never
# uses all-pass wording. In CI a missing container runtime or image is FAIL.
#
# Usage: bash tools/check.sh [--external]
#   --external  check links online (third-party sites included) instead of
#               the offline internal-link check (ADR-0002 part 7)
#
# tools/selftest.sh sources this file for html_check, links_check and the
# sitecheck functions, so the self-test runs exactly the invocations the real
# steps run; check_main and the strict mode below apply only when the file is
# executed.

CHECK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/fetch-tools.sh
source "$CHECK_ROOT/tools/fetch-tools.sh"

HTML_NOT_RUN_LINE='NOT RUN: HTML validation (Nu Html Checker) was NOT run locally. It runs only in CI (required check job). A local green does not mean the HTML is valid.'

in_github_actions() { [[ "${GITHUB_ACTIONS:-}" == true ]]; }

# html_check <absolute dir>: validate every HTML and CSS file under dir with
# the pinned Nu Html Checker image. Only ever called in CI.
html_check() {
  local dir="$1"
  if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker not found; in CI the Nu Html Checker must run" >&2
    return 1
  fi
  if ! docker image inspect "$VNU_IMAGE" >/dev/null 2>&1; then
    echo "FAIL: pinned Nu Html Checker image not present: $VNU_IMAGE" >&2
    echo "FAIL: tools/fetch-tools.sh pulls it in CI; see its output" >&2
    return 1
  fi
  docker run --rm --network none -v "$dir:/site:ro" --entrypoint vnu \
    "$VNU_IMAGE" --skip-non-html --also-check-css /site
}

# links_check <absolute dir> [--external]: check links in the built tree.
# root_dir and the self-link remap depend on the absolute path, so they are
# passed here rather than in lychee.toml.
links_check() {
  local dir="$1" mode="${2:-}"
  local -a online=(--offline)
  [[ "$mode" == --external ]] && online=()
  if [[ ! -x "$LYCHEE_BIN" ]]; then
    echo "FAIL: lychee not found at $LYCHEE_BIN; run tools/fetch-tools.sh" >&2
    return 1
  fi
  "$LYCHEE_BIN" --config "$CHECK_ROOT/lychee.toml" "${online[@]}" \
    --root-dir "$dir" \
    --remap "^https://interviewscam\\.com/(.*)\$ file://$dir/\$1" \
    -- "$dir"
}

# The safety nets (tools/sitecheck.py, ADR-0002 parts 3, 4 and 6), run in
# Python's isolated mode. Each prints its counts and exits 1 on findings,
# 2 on a usage or internal error.
sitecheck() { python3 -I "$CHECK_ROOT/tools/sitecheck.py" "$@"; }

# guard_check <repo root>: no JavaScript package tooling in the build chain
# (D3; the guard keeps the tool names out of tools/), Hugo hardening keys in
# hugo.toml and in the effective config of the pinned Hugo, actions owned by
# actions/ and pinned to commit SHAs, Pages off until M6.
guard_check() { sitecheck guard --root "$1" --hugo "$HUGO_BIN"; }

# records_check <root> <schema dir>: schema, x-defang (D8), live forms (R2)
# and the SPEC section 5 body rule for every record under <root>/content.
records_check() { sitecheck records --root "$1" --schemas "$2"; }

# site_check <root> <schema dir> <built dir>: third-party requests (D9), the
# CSP meta from <root>/hugo.toml, and no live artifact in the build (R3).
site_check() { sitecheck site --records "$1" --schemas "$2" "$3"; }

STEP_NAMES=()
STEP_RESULTS=()

record() {
  STEP_NAMES+=("$1")
  STEP_RESULTS+=("$2")
}

# run_step <name> <command...>: run, record PASS or FAIL, never abort.
run_step() {
  local name="$1"
  shift
  echo
  echo "==> $name"
  if "$@"; then
    record "$name" PASS
  else
    echo "==> $name: FAIL"
    record "$name" FAIL
  fi
}

step_fetch() { bash "$CHECK_ROOT/tools/fetch-tools.sh"; }

step_shellcheck() {
  if ! command -v shellcheck >/dev/null 2>&1; then
    if [[ "${CI:-}" == true ]]; then
      echo "shellcheck not found; in CI it is required" >&2
      return 1
    fi
    echo "SKIPPED: shellcheck not found, shell scripts were NOT linted"
    return 2
  fi
  shellcheck --version | sed -n 's/^version: /shellcheck version: /p'
  shellcheck -x "$CHECK_ROOT"/tools/*.sh || return 1
  echo "shellcheck OK"
}

step_guard() { guard_check "$CHECK_ROOT"; }

step_records() { records_check "$CHECK_ROOT" "$CHECK_ROOT/schema"; }

step_site() { site_check "$CHECK_ROOT" "$CHECK_ROOT/schema" "$CHECK_ROOT/public"; }

step_build() {
  if [[ ! -x "$HUGO_BIN" ]]; then
    echo "hugo not found at $HUGO_BIN; run tools/fetch-tools.sh" >&2
    return 1
  fi
  "$HUGO_BIN" --source "$CHECK_ROOT" --gc --minify --panicOnWarning \
    --cleanDestinationDir --destination "$CHECK_ROOT/public"
}

step_html() { html_check "$CHECK_ROOT/public"; }

step_links() { links_check "$CHECK_ROOT/public" "$EXTERNAL"; }

step_selftest() { bash "$CHECK_ROOT/tools/selftest.sh"; }

check_main() {
  EXTERNAL=""
  case "${1:-}" in
    "") ;;
    --external) EXTERNAL=--external ;;
    *)
      echo "usage: bash tools/check.sh [--external]" >&2
      return 2
      ;;
  esac
  if [[ $# -gt 1 ]]; then
    echo "usage: bash tools/check.sh [--external]" >&2
    return 2
  fi

  cd "$CHECK_ROOT" || return 1
  if ! load_pins; then
    echo "FAIL: tools/pins.env could not be read" >&2
    return 1
  fi

  run_step fetch-tools step_fetch

  echo
  echo "==> shellcheck"
  step_shellcheck
  case $? in
    0) record shellcheck PASS ;;
    2) record shellcheck SKIPPED ;;
    *) echo "==> shellcheck: FAIL"; record shellcheck FAIL ;;
  esac

  run_step "guard (repo rules)" step_guard
  run_step "records (schema, defang)" step_records
  run_step build step_build
  run_step "site (third-party, CSP, defang)" step_site

  if in_github_actions; then
    run_step "html (Nu Html Checker)" step_html
  else
    echo
    echo "==> html (Nu Html Checker)"
    echo "$HTML_NOT_RUN_LINE"
    record "html (Nu Html Checker)" "NOT RUN (CI only)"
  fi

  if [[ -n "$EXTERNAL" ]]; then
    run_step "links (online, external included)" step_links
  else
    run_step "links (offline, internal)" step_links
  fi

  if in_github_actions; then
    run_step selftest step_selftest
  else
    echo
    echo "==> selftest"
    if step_selftest; then
      record selftest "PASS (html fixtures NOT RUN, CI only)"
    else
      echo "==> selftest: FAIL"
      record selftest FAIL
    fi
  fi

  local i failed_steps=() skipped_steps=() not_run=0
  echo
  echo "==> Summary"
  for i in "${!STEP_NAMES[@]}"; do
    printf '  %-36s %s\n' "${STEP_NAMES[$i]}" "${STEP_RESULTS[$i]}"
    case "${STEP_RESULTS[$i]}" in
      FAIL) failed_steps+=("${STEP_NAMES[$i]}") ;;
      SKIPPED) skipped_steps+=("${STEP_NAMES[$i]}") ;;
      "NOT RUN"*) not_run=1 ;;
    esac
  done
  echo
  if [[ ${#failed_steps[@]} -gt 0 ]]; then
    echo "FAIL: ${#failed_steps[@]} step(s) failed: ${failed_steps[*]}"
    return 1
  fi
  local line
  if [[ $not_run -eq 1 ]]; then
    line="LOCAL PASS, HTML validation not run (CI only)"
  else
    line="PASS: every step ran and passed, HTML validation included"
  fi
  if [[ ${#skipped_steps[@]} -gt 0 ]]; then
    line="$line; SKIPPED: ${skipped_steps[*]}"
  fi
  echo "$line"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  check_main "$@"
fi
