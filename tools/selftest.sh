#!/usr/bin/env bash
# Self-test: prove every check fires in both directions.
#
# For every tests/fixtures/<check>/<pass|fail>-<case>/ it runs the matching
# check on that directory, with the same function tools/check.sh uses:
#   pass-<case>  must exit 0.
#   fail-<case>  must exit non-zero AND print the substring in its
#                expect.txt, so a check that fails for the wrong reason
#                (a crash, a missing tool) does not count as a pass.
#   A pass-<case> with an expect.txt must also print that substring, so a
#   pass that checked nothing (zero records, zero artifacts) is caught.
#
# html fixtures need the Nu Html Checker, which runs only in CI
# (GITHUB_ACTIONS=true; ADR-0002 part 1). Outside CI they print the NOT RUN
# line; in CI the self-test fails unless every html fixture ran.
#
# Usage: bash tools/selftest.sh

SELFTEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/check.sh
source "$SELFTEST_ROOT/tools/check.sh"

FIXTURES="$SELFTEST_ROOT/tests/fixtures"
# The version the synthetic Lighthouse reports in tests/fixtures/lighthouse/
# carry. Fixed, not the pin, so a Lighthouse upgrade does not touch them.
LIGHTHOUSE_FIXTURE_VERSION=13.6.0

# guard_env <fixture dir>: read <dir>/env.txt into GUARD_ENV. Only HUGO_*
# assignments are accepted, so a fixture cannot change anything else.
guard_env() {
  GUARD_ENV=()
  [[ -f "$1/env.txt" ]] || return 0
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^HUGO_[A-Z0-9_]+= ]] || return 1
    GUARD_ENV+=("$line")
  done < "$1/env.txt"
}

selftest_main() {
  load_pins || return 1
  # Always re-verify: the fixtures must run against the pinned binaries, not
  # whatever is in .tools/ (cheap; the archives are cached).
  bash "$SELFTEST_ROOT/tools/fetch-tools.sh" || return 1

  local n_passed=0 n_failed=0 html_total=0 html_run=0
  local dir check name kind out rc expect
  out="$(mktemp)"
  # shellcheck disable=SC2064 # expand now: the path is fixed
  trap "rm -f '$out'" RETURN

  for dir in "$FIXTURES"/*/*/; do
    dir="${dir%/}"
    check="$(basename "$(dirname "$dir")")"
    name="$(basename "$dir")"
    case "$name" in
      pass-*) kind=pass ;;
      fail-*) kind=fail ;;
      *)
        echo "FAIL $check/$name: fixture name must start with pass- or fail-"
        n_failed=$((n_failed + 1))
        continue
        ;;
    esac

    case "$check" in
      html)
        html_total=$((html_total + 1))
        if ! in_github_actions; then
          echo "NOT RUN $check/$name (CI only)"
          continue
        fi
        html_run=$((html_run + 1))
        html_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      links)
        links_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      records)
        # Records fixtures run against the real schemas in schema/.
        records_check "$dir" "$SELFTEST_ROOT/schema" >"$out" 2>&1
        rc=$?
        ;;
      schema)
        # Schema fixtures bring their own schema/ to test the validator.
        records_check "$dir" "$dir/schema" >"$out" 2>&1
        rc=$?
        ;;
      site)
        # <dir>/hugo.toml holds params.csp, <dir>/content the records whose
        # artifacts must not appear live in the built tree <dir>/public.
        site_check "$dir" "$SELFTEST_ROOT/schema" "$dir/public" >"$out" 2>&1
        rc=$?
        ;;
      lighthouse)
        # Synthetic reports holding only the fields the score gate reads.
        sitecheck lighthouse --reports "$dir" \
          --version "$LIGHTHOUSE_FIXTURE_VERSION" >"$out" 2>&1
        rc=$?
        ;;
      tree)
        # <dir>/lock.json is a resolved tree (the guard rejects the real
        # lockfile name) and <dir>/pin.txt the digest the case pins.
        sitecheck tree-digest "$dir/lock.json" \
          --expect "$(head -n 1 "$dir/pin.txt" 2>/dev/null)" >"$out" 2>&1
        rc=$?
        ;;
      guard)
        # <dir> stands in for the repo root. An optional env.txt holds
        # HUGO_* overrides for the run, to prove the guard reads the
        # effective Hugo config.
        if ! guard_env "$dir"; then
          echo "FAIL $check/$name: env.txt may only hold HUGO_<NAME>=<value> lines"
          n_failed=$((n_failed + 1))
          continue
        fi
        (
          for line in "${GUARD_ENV[@]}"; do
            export "${line?}"
          done
          guard_check "$dir"
        ) >"$out" 2>&1
        rc=$?
        ;;
      *)
        echo "FAIL $check/$name: no check is mapped to fixture directory '$check'"
        n_failed=$((n_failed + 1))
        continue
        ;;
    esac

    if [[ "$kind" == pass ]]; then
      expect=""
      [[ -s "$dir/expect.txt" ]] && expect="$(head -n 1 "$dir/expect.txt")"
      if [[ $rc -eq 0 && -n "$expect" ]] && ! grep -qF -- "$expect" "$out"; then
        echo "FAIL $check/$name: passed but without the expected output '$expect'; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      elif [[ $rc -eq 0 ]]; then
        echo "ok   $check/$name${expect:+ (passed with: $expect)}"
        n_passed=$((n_passed + 1))
      else
        echo "FAIL $check/$name: expected exit 0, got $rc; output:"
        sed 's/^/     | /' "$out"
        n_failed=$((n_failed + 1))
      fi
      continue
    fi

    if [[ ! -s "$dir/expect.txt" ]]; then
      echo "FAIL $check/$name: missing or empty expect.txt"
      n_failed=$((n_failed + 1))
      continue
    fi
    expect="$(head -n 1 "$dir/expect.txt")"
    if [[ $rc -eq 0 ]]; then
      echo "FAIL $check/$name: expected a failure, the check passed; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    elif ! grep -qF -- "$expect" "$out"; then
      echo "FAIL $check/$name: failed (exit $rc) but without the expected reason '$expect'; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    else
      echo "ok   $check/$name (failed as expected: $expect)"
      n_passed=$((n_passed + 1))
    fi
  done

  if [[ $html_total -eq 0 ]]; then
    echo "FAIL: no html fixtures found"
    n_failed=$((n_failed + 1))
  fi
  if in_github_actions && [[ $html_run -ne $html_total ]]; then
    echo "FAIL: only $html_run of $html_total html fixtures ran in CI"
    n_failed=$((n_failed + 1))
  fi
  if ! in_github_actions && [[ $html_total -gt 0 ]]; then
    echo "$HTML_NOT_RUN_LINE"
  fi

  echo "selftest: $n_passed passed, $n_failed failed, html fixtures run: $html_run of $html_total"
  [[ $n_failed -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  selftest_main "$@"
fi
