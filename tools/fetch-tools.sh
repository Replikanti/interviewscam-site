#!/usr/bin/env bash
# Fetch the pinned check toolchain into .tools/ and verify it.
#
# Every archive is checked with sha256sum against tools/pins.env BEFORE it is
# extracted; on a mismatch the download is deleted and the script fails.
# workerd ships as one gzip-compressed binary, not a tarball (fetch_gz).
# Binaries land in .tools/<name>-<version>/<name> and are re-extracted from
# the verified archive on every run, so a binary that did not come from the
# pinned archive never survives a run. The Nu Html Checker image
# is pulled only when GITHUB_ACTIONS=true: outside CI this script never
# touches a container runtime (ADR-0002 part 1).
# Downloads retry on every error with a fixed delay inside a bounded
# window (FETCH_RETRY_ARGS, derived in ADR-0002 part 8), so a short
# upstream outage does not turn the job red.
# A Nu Html Checker image already present by its pinned digest is not
# pulled again: a nested run of this script (the self-test) then sends
# no registry request (ADR-0002 part 8).
#
# Usage: bash tools/fetch-tools.sh
# check.sh sources this file for load_pins and the tool paths; fetch_main
# and the strict mode below apply only when the file is executed.

FETCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS_FILE="$FETCH_ROOT/tools/pins.env"
TOOLS_DIR="$FETCH_ROOT/.tools"
# The retry schedule of every download; the values and what breaks at
# others: ADR-0002 part 8 and its Numbers row "Download retry options".
FETCH_RETRY_ARGS=(--retry-all-errors --retry 19 --retry-delay 3 --retry-max-time 55 --max-time 40)

# Read KEY=VALUE pins into PIN_<KEY> variables. The file is parsed, not
# sourced, so a pin line can never run code. Anything else is an error.
load_pins() {
  local line key value n=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ ! "$line" =~ ^([A-Z][A-Z0-9_]*)=([^[:space:]]+)$ ]]; then
      echo "fetch-tools: $PINS_FILE:$n: not a KEY=VALUE line" >&2
      return 1
    fi
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    printf -v "PIN_$key" '%s' "$value"
  done < "$PINS_FILE"
  local required
  for required in HUGO_VERSION HUGO_URL HUGO_SHA256 \
                  LYCHEE_VERSION LYCHEE_URL LYCHEE_SHA256 VNU_IMAGE \
                  WORKERD_VERSION WORKERD_URL WORKERD_SHA256 WORKERD_COMPAT_DATE; do
    local var="PIN_$required"
    if [[ -z "${!var:-}" ]]; then
      echo "fetch-tools: $PINS_FILE: missing pin $required" >&2
      return 1
    fi
  done
  # Exported so every script and step sees the same paths.
  HUGO_BIN="$TOOLS_DIR/hugo-$PIN_HUGO_VERSION/hugo"
  LYCHEE_BIN="$TOOLS_DIR/lychee-$PIN_LYCHEE_VERSION/lychee"
  VNU_IMAGE="$PIN_VNU_IMAGE"
  WORKERD_BIN="$TOOLS_DIR/workerd-$PIN_WORKERD_VERSION/workerd"
  WORKERD_COMPAT_DATE="$PIN_WORKERD_COMPAT_DATE"
  export HUGO_BIN LYCHEE_BIN VNU_IMAGE WORKERD_BIN WORKERD_COMPAT_DATE
}

require_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  if [[ "$os" != Linux || "$arch" != x86_64 ]]; then
    echo "fetch-tools: only linux-x86_64 is pinned (ADR-0001), this is $os-$arch" >&2
    return 1
  fi
}

# cache_path <url> <sha256>: the cache file of a pinned download. The key
# carries the pinned hash, so a pin bump downloads a new file instead of
# reporting a false mismatch against the previous version's.
cache_path() { printf '%s\n' "$TOOLS_DIR/cache/$2-${1##*/}"; }

# fetch_verified <name> <version> <url> <sha256>: download the pinned file
# into the cache unless it is there, then verify it against the pin. Shared
# by fetch_one (tarballs) and fetch_gz (one gzip-compressed binary).
fetch_verified() {
  local name="$1" version="$2" url="$3" sha="$4" archive
  archive="$(cache_path "$url" "$sha")"
  mkdir -p "$TOOLS_DIR/cache" || return 1
  if [[ ! -f "$archive" ]]; then
    echo "fetch-tools: downloading $name $version"
    rm -f "$archive.part"
    curl -q --fail --silent --show-error --location "${FETCH_RETRY_ARGS[@]}" --proto '=https' --tlsv1.2 --output "$archive.part" "$url" || return 1
    if [[ ! -f "$archive.part" ]]; then
      echo "fetch-tools: FAIL: $name $version: curl ended without a file (a Retry-After past the retry window ends curl with exit 0)" >&2
      return 1
    fi
    mv "$archive.part" "$archive" || return 1
  fi

  # Verified on every run, cached or not, before anything is extracted.
  if ! printf '%s  %s\n' "$sha" "$archive" | sha256sum --check --status; then
    echo "fetch-tools: SHA-256 MISMATCH for $archive" >&2
    echo "fetch-tools: expected $sha, got $(sha256sum "$archive" | cut -d' ' -f1)" >&2
    echo "fetch-tools: deleted the download; the pin in tools/pins.env is authoritative" >&2
    rm -f "$archive"
    return 1
  fi
  echo "fetch-tools: $name $version SHA-256 OK"
}

# fetch_one <name> <version> <url> <sha256> <member inside the archive>
fetch_one() {
  local name="$1" version="$2" url="$3" sha="$4" member="$5"
  local dest="$TOOLS_DIR/$name-$version" archive
  archive="$(cache_path "$url" "$sha")"

  # Whatever binary an earlier run (or anyone else) left here is discarded:
  # the binary used by the checks is always the one extracted below from the
  # archive verified in this run.
  rm -rf "$dest"
  fetch_verified "$name" "$version" "$url" "$sha" || return 1

  local tmp
  tmp="$(mktemp -d "$TOOLS_DIR/.extract.XXXXXX")"
  tar -xzf "$archive" -C "$tmp" "$member"
  mkdir -p "$dest"
  mv "$tmp/$member" "$dest/$name"
  chmod 0755 "$dest/$name"
  rm -rf "$tmp"
}

# fetch_gz <name> <version> <url> <sha256>: like fetch_one for a release
# asset that is one gzip-compressed binary (workerd-linux-64.gz). The
# verified file is decompressed with Python's gzip module in isolated mode
# (no gunzip flag set differs between distributions), into a temp file that
# is renamed into place only when it is complete.
fetch_gz() {
  local name="$1" version="$2" url="$3" sha="$4"
  local dest="$TOOLS_DIR/$name-$version" archive tmp
  archive="$(cache_path "$url" "$sha")"
  rm -rf "$dest"
  fetch_verified "$name" "$version" "$url" "$sha" || return 1
  tmp="$(mktemp -d "$TOOLS_DIR/.extract.XXXXXX")"
  python3 -I -c 'import gzip, shutil, sys
with gzip.open(sys.argv[1], "rb") as src, open(sys.argv[2], "wb") as out:
    shutil.copyfileobj(src, out)' "$archive" "$tmp/$name" || { rm -rf "$tmp"; return 1; }
  mkdir -p "$dest"
  mv "$tmp/$name" "$dest/$name"
  chmod 0755 "$dest/$name"
  rm -rf "$tmp"
}

fetch_vnu() {
  if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    echo "fetch-tools: Nu Html Checker not fetched (CI only, ADR-0002 part 1)"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    echo "fetch-tools: FAIL: docker not found; in CI the Nu Html Checker must run" >&2
    return 1
  fi
  if docker image inspect "$VNU_IMAGE" >/dev/null 2>&1; then
    echo "fetch-tools: Nu Html Checker image already present by digest"
    return 0
  fi
  if ! docker pull --quiet "$VNU_IMAGE"; then
    echo "fetch-tools: FAIL: could not pull the pinned Nu Html Checker image" >&2
    echo "fetch-tools: $VNU_IMAGE" >&2
    echo "fetch-tools: if upstream deleted this digest, see the digest-loss fallback in ADR-0002 part 1" >&2
    return 1
  fi
  echo "fetch-tools: Nu Html Checker image pulled by digest"
}

fetch_main() {
  require_platform
  load_pins
  fetch_one hugo "$PIN_HUGO_VERSION" "$PIN_HUGO_URL" "$PIN_HUGO_SHA256" hugo
  fetch_one lychee "$PIN_LYCHEE_VERSION" "$PIN_LYCHEE_URL" "$PIN_LYCHEE_SHA256" \
    lychee-x86_64-unknown-linux-gnu/lychee
  fetch_gz workerd "$PIN_WORKERD_VERSION" "$PIN_WORKERD_URL" "$PIN_WORKERD_SHA256"
  fetch_vnu
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  fetch_main "$@"
fi
