#!/usr/bin/env bash
# Lighthouse on the built site, CI only (ADR-0003 parts 1, 2, 3, 5 and 7).
#
# The only file the guard lets name the JavaScript registry tools, and only
# .github/workflows/lighthouse.yml may run it: in the job `lighthouse`, whose
# GITHUB_TOKEN has no permissions, with no checkout, on the `build` artifact
# (public/ and tools/). It refuses to run anywhere else (exit 2), so it never
# runs on a developer machine or next to the repository source (D3).
#
#   1. Resolve the tree of the pinned Lighthouse version in lock-only mode,
#      with the cooldown date and install scripts off. Only manifests are
#      fetched; no registry code runs.
#   2. sitecheck tree-digest: the resolved tree must match
#      LIGHTHOUSE_TREE_SHA256. On a mismatch (the first run, every upgrade)
#      it prints the digest and the resolved list and the job fails.
#   3. Install exactly that lock, install scripts off.
#   4. Serve public/ on 127.0.0.1 and audit every page 3 times with the
#      mobile profile (every directory with an index.html, plus /404.html).
#   5. sitecheck lighthouse: the score gate (ADR-0003 part 3).
#
# Node.js, npm and Google Chrome come from the runner image (ADR-0003 part 7).
# It prints the setup time and the time of every run, the inputs of the
# timeout in lighthouse.yml (ADR-0003 part 5). It uploads nothing.
#
# Usage: bash tools/lighthouse.sh

LH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tools/fetch-tools.sh
source "$LH_ROOT/tools/fetch-tools.sh"

# Written out, so no config file can point the resolver elsewhere.
LH_REGISTRY=https://registry.npmjs.org/
# Loopback only. The runner is a fresh VM, so a fixed port is free.
LH_PORT=8137
LH_CATEGORIES=performance,accessibility,best-practices,seo
LH_RUNS=3

refuse() {
  echo "lighthouse: REFUSED: $*" >&2
  exit 2
}

now_ms() {
  local ns
  ns="$(date +%s%N)"
  echo $((ns / 1000000))
}

# seconds <ms>: one decimal, no floating point in bash.
seconds() { printf '%d.%d' $(($1 / 1000)) $(($1 % 1000 / 100)); }

# lh_npm <args...>: npm in the work dir with an empty user and global
# config, a private cache, the public registry written out, and no install
# scripts, audit, funding or update requests.
lh_npm() {
  (cd "$LH_WORK" && npm "$@" \
    --registry="$LH_REGISTRY" \
    --userconfig="$LH_WORK/user.npmrc" \
    --globalconfig="$LH_WORK/global.npmrc" \
    --cache="$LH_WORK/cache" \
    --ignore-scripts --no-audit --no-fund --no-update-notifier)
}

lighthouse_main() {
  local start setup_ms
  start="$(now_ms)"

  [[ "${GITHUB_ACTIONS:-}" == true ]] \
    || refuse "runs only in GitHub Actions, never on a developer machine (D3)"
  local dir
  for dir in "$LH_ROOT" "${GITHUB_WORKSPACE:-$LH_ROOT}"; do
    [[ -e "$dir/.git" ]] \
      && refuse "$dir/.git exists: this runs on the build artifact, never on a checkout"
    [[ -e "$dir/content" ]] \
      && refuse "$dir/content exists: this job must not see the repository source"
  done
  [[ -f "$LH_ROOT/public/index.html" ]] \
    || refuse "no public/index.html: the job downloads the build artifact first"
  [[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" ]] || refuse "RUNNER_TEMP is not a directory"

  load_pins || return 1
  local pin var
  for pin in LIGHTHOUSE_VERSION LIGHTHOUSE_BEFORE LIGHTHOUSE_TREE_SHA256; do
    var="PIN_$pin"
    if [[ -z "${!var:-}" ]]; then
      echo "lighthouse: FAIL: missing pin $pin in tools/pins.env" >&2
      return 1
    fi
  done

  local chrome
  chrome="$(command -v google-chrome || command -v google-chrome-stable)" || {
    echo "lighthouse: FAIL: Google Chrome not found on the runner image" >&2
    return 1
  }
  echo "lighthouse: node $(node --version), npm $(npm --version), $("$chrome" --version)"

  LH_WORK="$(mktemp -d "$RUNNER_TEMP/lighthouse.XXXXXX")"
  : >"$LH_WORK/user.npmrc"
  : >"$LH_WORK/global.npmrc"
  printf '{\n  "name": "lighthouse-run",\n  "version": "0.0.0",\n  "private": true,\n  "dependencies": {\n    "lighthouse": "%s"\n  }\n}\n' \
    "$PIN_LIGHTHOUSE_VERSION" >"$LH_WORK/package.json"

  echo "lighthouse: resolving lighthouse@$PIN_LIGHTHOUSE_VERSION, before $PIN_LIGHTHOUSE_BEFORE (lock only)"
  lh_npm install --package-lock-only --before="$PIN_LIGHTHOUSE_BEFORE" || {
    echo "lighthouse: FAIL: could not resolve the tree" >&2
    return 1
  }
  python3 -I "$LH_ROOT/tools/sitecheck.py" tree-digest "$LH_WORK/package-lock.json" \
    --expect "$PIN_LIGHTHOUSE_TREE_SHA256" || return 1

  echo "lighthouse: installing the pinned tree (install scripts off)"
  lh_npm ci || {
    echo "lighthouse: FAIL: install from the resolved lock failed" >&2
    return 1
  }

  local public="$LH_ROOT/public" reports="$LH_WORK/reports" server_pid
  mkdir -p "$reports"
  python3 -I -m http.server --bind 127.0.0.1 --directory "$public" "$LH_PORT" \
    >"$LH_WORK/server.log" 2>&1 &
  server_pid=$!
  # shellcheck disable=SC2064 # expand now: the PID is fixed
  trap "kill $server_pid 2>/dev/null" EXIT
  local _
  for _ in $(seq 50); do
    curl --silent --fail --output /dev/null "http://127.0.0.1:$LH_PORT/" && break
    sleep 0.2
  done
  if ! curl --silent --fail --output /dev/null "http://127.0.0.1:$LH_PORT/"; then
    echo "lighthouse: FAIL: the local server did not start" >&2
    cat "$LH_WORK/server.log" >&2
    return 1
  fi

  local pages=() file rel
  while IFS= read -r -d '' file; do
    rel="${file#"$public"}"
    pages+=("${rel%index.html}")
  done < <(find "$public" -name index.html -print0 | sort -z)
  [[ -f "$public/404.html" ]] && pages+=(/404.html)

  setup_ms=$(($(now_ms) - start))
  echo "timing: setup $(seconds "$setup_ms") s"

  local page run t0 run_ms total_ms=0 max_ms=0 n_runs=0 n=0
  for page in "${pages[@]}"; do
    n=$((n + 1))
    for run in $(seq "$LH_RUNS"); do
      t0="$(now_ms)"
      if ! CHROME_PATH="$chrome" node "$LH_WORK/node_modules/lighthouse/cli/index.js" \
          "http://127.0.0.1:$LH_PORT$page" \
          --output=json --output-path="$reports/page$n-run$run.json" \
          --only-categories="$LH_CATEGORIES" \
          --chrome-flags="--headless=new" \
          --no-enable-error-reporting --quiet; then
        echo "lighthouse: FAIL: run $run of $page did not complete" >&2
        return 1
      fi
      run_ms=$(($(now_ms) - t0))
      total_ms=$((total_ms + run_ms))
      n_runs=$((n_runs + 1))
      ((run_ms > max_ms)) && max_ms=$run_ms
      echo "timing: run $page #$run $(seconds "$run_ms") s"
    done
  done
  echo "timing: setup $(seconds "$setup_ms") s, $n_runs runs on ${#pages[@]} pages," \
    "mean $(seconds $((total_ms / n_runs))) s, max $(seconds "$max_ms") s"
  # Requests the local server answered with an error, for example a missing
  # /favicon.ico; each one is a console error in best practices.
  echo "lighthouse: local server error responses (count, status, path):"
  sed -n 's/.*"[A-Z]* \([^ ]*\) HTTP[^"]*" \([45][0-9][0-9]\) .*/\2 \1/p' \
    "$LH_WORK/server.log" | sort | uniq -c | sed 's/^/  /'

  python3 -I "$LH_ROOT/tools/sitecheck.py" lighthouse --reports "$reports" \
    --version "$PIN_LIGHTHOUSE_VERSION"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  lighthouse_main "$@"
fi
