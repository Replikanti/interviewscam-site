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
# html fixtures need the Nu Html Checker and reflow fixtures the runner's
# Google Chrome, which run only in CI (GITHUB_ACTIONS=true; ADR-0002 part 1,
# ADR-0003 part 6). Outside CI they print the NOT RUN line; in CI the
# self-test fails unless every html and every reflow fixture ran.
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

# launch_dump_has <output> <attempt> <line>: the Chrome log dump of that
# launch in sitecheck reflow's output (from its "reflow: Chrome log of
# launch N of 2 (" header to the next "reflow: " line) contains the line.
launch_dump_has() {
  awk -v head="reflow: Chrome log of launch $2 of 2 (" -v want="$3" '
    index($0, head) == 1 { on = 1; next }
    on && index($0, "reflow: ") == 1 { on = 0 }
    on && $0 == want { found = 1 }
    END { exit !found }' "$1"
}

# logs_moved <path log> <glob>: the stub logged exactly two log files (its
# stderr on each launch), each matches the glob, and the directory of each
# is gone now that sitecheck reflow has returned.
logs_moved() {
  local log n=0
  [[ -f "$1" ]] || return 1
  while read -r log; do
    # shellcheck disable=SC2053 # $2 is a glob pattern on purpose
    [[ "$log" == $2 && ! -e "${log%/*}" ]] || return 1
    n=$((n + 1))
  done <"$1"
  [[ $n -eq 2 ]]
}

selftest_main() {
  load_pins || return 1
  # Always re-verify: the fixtures must run against the pinned binaries, not
  # whatever is in .tools/ (cheap; the archives are cached).
  bash "$SELFTEST_ROOT/tools/fetch-tools.sh" || return 1

  local n_passed=0 n_failed=0 html_total=0 html_run=0 reflow_total=0 reflow_run=0
  local dir check name kind out rc expect leak_fixtures
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
      reflow)
        # <dir> is the built tree itself: its HTML pages are loaded at
        # 320 CSS px.
        reflow_total=$((reflow_total + 1))
        if ! in_github_actions; then
          echo "NOT RUN $check/$name (CI only)"
          continue
        fi
        reflow_run=$((reflow_run + 1))
        reflow_check "$dir" >"$out" 2>&1
        rc=$?
        ;;
      tokens)
        # <dir> stands in for the repo root: data/tokens.toml plus the
        # assets/, layouts/, static/ and hugo.toml the colour scan reads.
        tokens_check "$dir" >"$out" 2>&1
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
      render)
        # Laid out like the site fixtures: <dir>/content holds the records,
        # <dir>/public the hand-written built pages that pin the markup
        # contract the record templates implement (ADR-0004). An optional
        # <dir>/fixtures stands in for tests/fixtures in the fixture-leak
        # check of the production run.
        leak_fixtures=""
        [[ -d "$dir/fixtures" ]] && leak_fixtures="$dir/fixtures"
        render_check "$dir" "$SELFTEST_ROOT/schema" "$dir/public" "$leak_fixtures" \
          >"$out" 2>&1
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

  # Wiring: check_main must run the production render step, and that step
  # must run the fixture-leak check (--fixtures tests/fixtures), which no
  # fixture can prove. declare -f prints check_main without comments, so a
  # commented-out or deleted step line is missing; a stub sitecheck in a
  # subshell prints the arguments step_render passes, so dropping the flag
  # turns the self-test red too.
  local render_args
  render_args="$(sitecheck() { printf '%s\n' "$@"; }; step_render)"
  if ! declare -f check_main \
      | grep -qE '^ *run_step "render \(D6, D7, D10, structured data\)" step_render;?$'; then
    echo "FAIL wiring/render-step: check_main in tools/check.sh does not run" \
      "the production render step (run_step \"render (...)\" step_render)"
    n_failed=$((n_failed + 1))
  elif awk -v want="$CHECK_ROOT/tests/fixtures" \
      'prev == "--fixtures" && $0 == want { found = 1 } { prev = $0 } END { exit !found }' \
      <<<"$render_args"; then
    echo "ok   wiring/render-fixture-leak (check_main runs step_render, which passes --fixtures tests/fixtures)"
    n_passed=$((n_passed + 1))
  else
    echo "FAIL wiring/render-fixture-leak: step_render in tools/check.sh does not pass" \
      "--fixtures \"\$CHECK_ROOT/tests/fixtures\" to sitecheck render (the fixture-leak check)"
    n_failed=$((n_failed + 1))
  fi

  # reflow-launch: the launch of sitecheck reflow (ADR-0003 part 6, #24)
  # against a stub browser, so the cases run locally and in CI, each with
  # --launch-timeout 1 on reflow/pass-fluid (default-budget without it).
  # The stub appends its PID to a launch log, its arguments to an argument
  # log and the file behind its stderr to a log-path log on every start,
  # writes one line to stdout and one to stderr (as Chrome logs), and then
  # acts or execs, so the PID stays the browser's. Each case counts the
  # launches, and after sitecheck returns no logged PID may still be alive
  # (every Chrome of both launches is killed or reaped).
  #   never-answers: the stub never answers, so both launches time out:
  #     exit 2, "on launch 2 of 2", 2 launches, both stub lines in the dump
  #     of each launch (Chrome's log is captured), a probe line naming the
  #     stub's PID and the 1 s budget before the budget ran out (0.x s),
  #     the verbose log flags among its arguments, and both logs in a
  #     reflow-log- directory on /dev/shm where that is a writable tmpfs
  #     (a disk stall cannot block Chrome's log writes unless memory runs
  #     short: reclaim can then wait on the disk, through swap or through
  #     other files' writeback; the probe line reports memory pressure), in
  #     the temporary directory otherwise.
  #   protocol-error-no-retry: the stub answers the first command with a
  #     DevTools error, which must fail at once: exit 2, the error, no
  #     retry line, 1 launch, the stub's stderr line in the error
  #     dump. A stub line that reached the DevTools pipe would break the
  #     reply's parse.
  #   later-call-no-retry: the stub answers Browser.getVersion and closes
  #     the pipe 3 s later, while sitecheck waits for the answer to
  #     Target.createTarget; only the first answer of a launch retries:
  #     exit 2, no retry line, 1 launch, "Chrome closed the
  #     DevTools pipe", and the probe of the later call names its 30 s
  #     budget (REFLOW_TIMEOUT, not the launch budget).
  #   exits-at-once: the stub exits at once, an early exit that must retry
  #     whichever side sees the closed pipe first: exit 2, "on launch 2 of
  #     2", 2 launches, no Traceback. Unloaded the read usually sees the
  #     close first, so this case guards the behaviour, and
  #     first-answer-epipe below proves the write side.
  #   default-budget: the exits-at-once stub without --launch-timeout, so
  #     the budget CI uses: exit 2, 2 launches, no Traceback, and the probe
  #     before each kill names a 75 s budget (REFLOW_LAUNCH_TIMEOUT, the
  #     option's default) on launch 1 and on launch 2. The stub exits at
  #     once, so the case never waits for that budget; first-answer-deadline
  #     below pins the deadline actually waited.
  #   slow-first-answer: the stub answers Browser.getVersion after 0.5 s,
  #     inside the budget, and then acts like later-call-no-retry: exit 2
  #     from the later call, no retry line, 1 launch, a
  #     "first answer after 0." line naming the log directory, a probe
  #     before it and the launch's dump right after it.
  # The stubs keep both pipe ends open while they sleep, so a later-call
  # failure is the closed pipe on the read (a NoAnswerError, which a retry
  # scoped too wide would catch) and never a BrokenPipeError on the write.
  # The 3 s sleeps outlast the 1 s launch budget, so a retry scoped too wide
  # fires (and a closed pipe cannot stand in for the protocol error), and
  # stay short, because the reflow cleanup waits for the stub to exit; no
  # case waits on the 30 s budget of a later call.
  local stub_dir launches problem pid retry_line log_line log_glob
  local -a budget_args
  # The retry line. The diagnostics name "launch 1 of 2" too, so the
  # no-retry checks look for the whole retry phrase.
  retry_line='on launch 1 of 2; starting it again'
  # Where sitecheck must put Chrome's logs (REFLOW_LOG_DIR): a reflow-log-
  # directory on /dev/shm when that is a writable tmpfs, else the work
  # directory under the temporary directory. log_line: what the timing
  # line names (an ERE).
  if [[ "$(stat -f -c %T /dev/shm 2>/dev/null)" == tmpfs && -w /dev/shm ]]; then
    log_line='/dev/shm'
    log_glob='/dev/shm/reflow-log-*/chrome-[12].log'
  else
    log_line='[^)]+'
    log_glob="$(cd "${TMPDIR:-/tmp}" && pwd -P)/reflow-*/chrome-[12].log"
  fi
  for name in never-answers protocol-error-no-retry later-call-no-retry \
      exits-at-once default-budget slow-first-answer; do
    stub_dir="$(mktemp -d)"
    {
      echo '#!/bin/sh'
      printf 'echo $$ >>"%s/launches"\n' "$stub_dir"
      printf 'printf '"'"'%%s\\n'"'"' "$@" >>"%s/args"\n' "$stub_dir"
      # readlink's own fd 2 is the stub's stderr, the log: the >> touches
      # only fd 1, wherever the shell applies it (CI's dash applied it in
      # the stub's own process, so /proc/$$/fd/1 named the logs file).
      printf 'readlink /proc/self/fd/2 >>"%s/logs"\n' "$stub_dir"
      echo "echo 'stub browser: a line on stdout'"
      echo "echo 'stub browser: a line on stderr' >&2"
    } >"$stub_dir/chrome"
    # Replies are one NUL-terminated JSON message on fd 4 (Chrome's output
    # pipe) to command id 1. The octal \0 is POSIX printf, so dash writes
    # the same bytes.
    case "$name" in
      never-answers)
        echo 'exec sleep 30' >>"$stub_dir/chrome"
        ;;
      protocol-error-no-retry)
        cat >>"$stub_dir/chrome" <<'STUB'
printf '{"id":1,"error":{"code":-32601,"message":"stub: no such method"}}\0' >&4
exec sleep 3
STUB
        ;;
      later-call-no-retry)
        cat >>"$stub_dir/chrome" <<'STUB'
printf '{"id":1,"result":{"product":"stub/1"}}\0' >&4
exec sleep 3
STUB
        ;;
      exits-at-once|default-budget)
        echo 'exit 0' >>"$stub_dir/chrome"
        ;;
      slow-first-answer)
        cat >>"$stub_dir/chrome" <<'STUB'
sleep 0.5
printf '{"id":1,"result":{"product":"stub/1"}}\0' >&4
exec sleep 3
STUB
        ;;
    esac
    chmod +x "$stub_dir/chrome"
    budget_args=(--launch-timeout 1)
    [[ "$name" == default-budget ]] && budget_args=()
    sitecheck reflow --chrome "$stub_dir/chrome" "${budget_args[@]}" \
      "$FIXTURES/reflow/pass-fluid" >"$out" 2>&1
    rc=$?
    launches=0
    [[ -f "$stub_dir/launches" ]] && launches="$(wc -l <"$stub_dir/launches")"
    launches="${launches// /}"
    problem=""
    case "$name" in
      never-answers)
        pid="$(head -n 1 "$stub_dir/launches" 2>/dev/null)"
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif ! grep -qF 'on launch 2 of 2' "$out"; then
          problem="no 'on launch 2 of 2' in the output"
        elif [[ "$launches" != 2 ]]; then
          problem="expected 2 launches, the stub counted $launches"
        elif ! launch_dump_has "$out" 1 'stub browser: a line on stdout' \
            || ! launch_dump_has "$out" 1 'stub browser: a line on stderr' \
            || ! launch_dump_has "$out" 2 'stub browser: a line on stdout' \
            || ! launch_dump_has "$out" 2 'stub browser: a line on stderr'; then
          problem="a stub line is missing from the Chrome log dump of a launch"
        elif ! grep -qE "^reflow: no answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s\): .*process $pid \(" "$out"; then
          problem="no probe line naming the stub PID $pid and the 1 s budget before the budget ran out"
        elif ! grep -qxF -- '--enable-logging=stderr' "$stub_dir/args" \
            || ! grep -qxF -- '--v=1' "$stub_dir/args"; then
          problem="the stub was not started with --enable-logging=stderr and --v=1"
        elif ! logs_moved "$stub_dir/logs" "$log_glob"; then
          problem="Chrome's two logs are not under $log_glob, or a log directory outlived the call: $(tr '\n' ' ' <"$stub_dir/logs" 2>/dev/null)"
        fi
        ;;
      protocol-error-no-retry)
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif ! grep -qF 'Browser.getVersion failed' "$out"; then
          problem="no 'Browser.getVersion failed' in the output"
        elif grep -qF "$retry_line" "$out"; then
          problem="the protocol error was retried ('$retry_line')"
        elif [[ "$launches" != 1 ]]; then
          problem="expected 1 launch, the stub counted $launches"
        elif ! launch_dump_has "$out" 1 'stub browser: a line on stderr'; then
          problem="the stub's stderr line is missing from the error dump"
        fi
        ;;
      later-call-no-retry)
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif grep -qF "$retry_line" "$out"; then
          problem="a later call was retried ('$retry_line')"
        elif [[ "$launches" != 1 ]]; then
          problem="expected 1 launch, the stub counted $launches"
        elif ! grep -qF 'Chrome closed the DevTools pipe' "$out"; then
          problem="no 'Chrome closed the DevTools pipe' in the output"
        elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 1 of 2 \(budget 30 s\): ' "$out"; then
          problem="no probe line of the later call with its 30 s budget"
        fi
        ;;
      exits-at-once)
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif grep -qF 'Traceback' "$out"; then
          problem="a Traceback in the output (the early exit was not a launch failure)"
        elif ! grep -qF 'on launch 2 of 2' "$out"; then
          problem="no 'on launch 2 of 2' in the output"
        elif [[ "$launches" != 2 ]]; then
          problem="expected 2 launches, the stub counted $launches"
        fi
        ;;
      default-budget)
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif grep -qF 'Traceback' "$out"; then
          problem="a Traceback in the output"
        elif [[ "$launches" != 2 ]]; then
          problem="expected 2 launches, the stub counted $launches"
        elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 1 of 2 \(budget 75 s\): ' "$out"; then
          problem="launch 1 did not run with the default 75 s budget"
        elif ! grep -qE '^reflow: no answer after [0-9.]+ s on launch 2 of 2 \(budget 75 s\): ' "$out"; then
          problem="launch 2 did not run with the default 75 s budget"
        fi
        ;;
      slow-first-answer)
        if [[ $rc -ne 2 ]]; then
          problem="expected exit 2, got $rc"
        elif grep -qF "$retry_line" "$out"; then
          problem="the slow first answer was retried ('$retry_line')"
        elif [[ "$launches" != 1 ]]; then
          problem="expected 1 launch, the stub counted $launches"
        elif ! grep -qF 'Chrome closed the DevTools pipe' "$out"; then
          problem="no 'Chrome closed the DevTools pipe' (the later call) in the output"
        elif ! grep -qE "^reflow: first answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s, Chrome log [0-9]+ lines in $log_line\)\$" "$out"; then
          problem="no 'first answer after 0.' line with the 1 s budget and the log directory"
        elif ! awk '/^reflow: no answer after 0\.[0-9]+ s on launch 1 of 2 \(budget 1 s\): /{p = 1}
            /^reflow: first answer after /{ok = p; exit}
            END{exit !ok}' "$out"; then
          problem="no probe line before the first answer"
        elif ! awk 'f{ok = index($0, "reflow: Chrome log of launch 1 of 2 (") == 1; exit}
            /^reflow: first answer after /{f = 1}
            END{exit !ok}' "$out"; then
          problem="no Chrome log dump right after the slow first answer"
        fi
        ;;
    esac
    # Every logged PID must be gone. A survivor is killed here, so a red
    # case leaves no stub behind.
    if [[ -f "$stub_dir/launches" ]]; then
      while read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
          [[ -z "$problem" ]] && problem="stub browser PID $pid still alive after sitecheck returned"
          kill "$pid" 2>/dev/null
        fi
      done <"$stub_dir/launches"
    fi
    if [[ -z "$problem" ]]; then
      echo "ok   reflow-launch/$name (exit $rc, $launches launch(es), all reaped)"
      n_passed=$((n_passed + 1))
    else
      echo "FAIL reflow-launch/$name: $problem; output:"
      sed 's/^/     | /' "$out"
      n_failed=$((n_failed + 1))
    fi
    rm -rf "$stub_dir"
  done

  # reflow-launch/first-answer-epipe: the write side of an early exit,
  # deterministically. The real DevTools client gets a command pipe whose
  # read end is closed, so the write of the first command meets EPIPE:
  # first_answer must turn it into the retried NoAnswerError naming the
  # closed pipe, and a later call (send) must keep the BrokenPipeError.
  # The budget the probe names must be first_answer's even then (1 s).
  # -B: the import writes no tools/__pycache__, which the guard would fail.
  python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)


def closed_command_pipe():
    command_r, command_w = os.pipe()
    os.close(command_r)
    answer_r, answer_w = os.pipe()
    return sitecheck.DevTools(command_w, answer_r), answer_w


for name, call in (
        ("first_answer", lambda tools: tools.first_answer(1, lambda elapsed: None)),
        ("send", lambda tools: tools.send("Target.createTarget", {"url": "about:blank"}))):
    tools, keep = closed_command_pipe()
    try:
        call(tools)
    except Exception as exc:
        print(f"{name}: {type(exc).__name__}: {exc}")
    else:
        print(f"{name}: returned")
    print(f"{name} budget: {tools.budget:g}")
PY
  if ! grep -qxF 'first_answer: NoAnswerError: reflow: Chrome closed the DevTools pipe' "$out"; then
    echo "FAIL reflow-launch/first-answer-epipe: first_answer did not turn EPIPE on the first write into NoAnswerError; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! grep -qE '^send: BrokenPipeError: ' "$out"; then
    echo "FAIL reflow-launch/first-answer-epipe: a later call no longer raises BrokenPipeError; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! grep -qxF 'first_answer budget: 1' "$out"; then
    echo "FAIL reflow-launch/first-answer-epipe: after EPIPE the probe would not name first_answer's budget; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  else
    echo "ok   reflow-launch/first-answer-epipe (first write EPIPE: NoAnswerError; later write: BrokenPipeError)"
    n_passed=$((n_passed + 1))
  fi

  # reflow-launch/first-answer-deadline: the deadline first_answer waits
  # is its own budget, not REFLOW_TIMEOUT. default-budget above pins the
  # budget the probe line names, which a deadline taken from REFLOW_TIMEOUT
  # (alone or as a min with the budget) would still print. Here the real
  # DevTools client waits on a pipe that never answers, with REFLOW_TIMEOUT
  # patched to 0.1 s, and first_answer(0.5) must raise NoAnswerError after
  # 0.45 to 2.5 s. Lower bound: the code raises once the monotonic clock
  # passes a deadline set after the timer starts, so it cannot wait less
  # than 0.5 s, and both wrong deadlines above wait 0.1 s. Upper bound: a
  # deadline of 5 times the budget or more (the budget times 5 waits
  # 2.5 s, times 10 waits 5 s, a fixed REFLOW_LAUNCH_TIMEOUT 75 s) waits
  # past 2.5 s, while 2.5 s leaves 2 s, four times the wait itself, above
  # the 0.5 s deadline for a slow runner's wake-up (CI measured 0.500 s,
  # 0.60 s for the whole case). The upper bound does NOT catch the budget
  # times 2 to 4 (1 s to 2 s). A second sub-case patches REFLOW_TIMEOUT to
  # 5 s and requires the same 2.5 s: the additive form, the budget plus
  # REFLOW_TIMEOUT, waits 0.6 s at 0.1 s and passes the first sub-case, but
  # waits 5.5 s here. In production that form would be 105 s per launch and
  # break the 7-minute cap row. The real code still waits 0.5 s. -B as
  # above.
  python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import os
import sys
import time

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)

sitecheck.REFLOW_TIMEOUT = 0.1
command_r, command_w = os.pipe()
answer_r, answer_w = os.pipe()
tools = sitecheck.DevTools(command_w, answer_r)
start = time.monotonic()
try:
    tools.first_answer(0.5, lambda elapsed: None)
except Exception as exc:
    print(f"first_answer: {type(exc).__name__}: {exc}")
else:
    print("first_answer: returned")
print(f"waited: {time.monotonic() - start:.3f}")

sitecheck.REFLOW_TIMEOUT = 5
command_r, command_w = os.pipe()
answer_r, answer_w = os.pipe()
tools = sitecheck.DevTools(command_w, answer_r)
start = time.monotonic()
try:
    tools.first_answer(0.5, lambda elapsed: None)
except Exception as exc:
    print(f"first_answer additive: {type(exc).__name__}: {exc}")
else:
    print("first_answer additive: returned")
print(f"waited additive: {time.monotonic() - start:.3f}")
PY
  if ! grep -qxF 'first_answer: NoAnswerError: reflow: no answer from Chrome within 0.5 s' "$out"; then
    echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) on a silent pipe did not raise NoAnswerError naming its 0.5 s budget; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! awk '$1 == "waited:" && $2 >= 0.45 { ok = 1 } END { exit !ok }' "$out"; then
    echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) gave up before 0.45 s (its deadline is not its budget; REFLOW_TIMEOUT patched to 0.1); output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! awk '$1 == "waited:" && $2 <= 2.5 { ok = 1 } END { exit !ok }' "$out"; then
    echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) waited more than 2.5 s (its deadline is not its budget but 5 times it or more); output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! grep -qxF 'first_answer additive: NoAnswerError: reflow: no answer from Chrome within 0.5 s' "$out"; then
    echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) with REFLOW_TIMEOUT 5 did not raise NoAnswerError naming its 0.5 s budget; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  elif ! awk '$1 == "waited" && $2 == "additive:" && $3 <= 2.5 { ok = 1 } END { exit !ok }' "$out"; then
    echo "FAIL reflow-launch/first-answer-deadline: first_answer(0.5) with REFLOW_TIMEOUT 5 waited more than 2.5 s (its deadline adds REFLOW_TIMEOUT to the budget); output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  else
    echo "ok   reflow-launch/first-answer-deadline (first_answer(0.5) with REFLOW_TIMEOUT 0.1: $(awk '$1 == "waited:" { print $2 }' "$out") s, with 5: $(awk '$1 == "waited" && $2 == "additive:" { print $3 }' "$out") s)"
    n_passed=$((n_passed + 1))
  fi

  # reflow-launch/log-dir-fallback: where REFLOW_LOG_DIR is missing, is no
  # tmpfs mount (a plain directory), or is one in which no directory can be
  # made, reflow_log_dir keeps Chrome's logs in the work directory and
  # raises nothing. never-answers above proves the tmpfs side.
  python3 -I -B - "$SELFTEST_ROOT/tools/sitecheck.py" >"$out" 2>&1 <<'PY'
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("sitecheck", sys.argv[1])
sitecheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sitecheck)

work = Path(tempfile.mkdtemp())
try:
    (work / "plain").mkdir()
    for name, log_dir, mounted in (("missing", work / "missing", False),
                                   ("not-tmpfs", work / "plain", False),
                                   ("no-mkdir", work / "missing", True)):
        sitecheck.REFLOW_LOG_DIR = str(log_dir)
        if mounted:
            sitecheck.tmpfs_mounted = lambda path: True
        try:
            got = sitecheck.reflow_log_dir(work)
        except Exception as exc:
            print(f"{name}: {type(exc).__name__}: {exc}")
        else:
            print(f"{name}: {'work' if got == work else got}")
finally:
    shutil.rmtree(work)
PY
  if [[ "$(cat "$out")" != $'missing: work\nnot-tmpfs: work\nno-mkdir: work' ]]; then
    echo "FAIL reflow-launch/log-dir-fallback: reflow_log_dir did not fall back to the work directory; output:"
    sed 's/^/     | /' "$out"
    n_failed=$((n_failed + 1))
  else
    echo "ok   reflow-launch/log-dir-fallback (missing, not a tmpfs, no directory made: work directory)"
    n_passed=$((n_passed + 1))
  fi

  if [[ $html_total -eq 0 ]]; then
    echo "FAIL: no html fixtures found"
    n_failed=$((n_failed + 1))
  fi
  if [[ $reflow_total -eq 0 ]]; then
    echo "FAIL: no reflow fixtures found"
    n_failed=$((n_failed + 1))
  fi
  if in_github_actions && [[ $html_run -ne $html_total ]]; then
    echo "FAIL: only $html_run of $html_total html fixtures ran in CI"
    n_failed=$((n_failed + 1))
  fi
  if in_github_actions && [[ $reflow_run -ne $reflow_total ]]; then
    echo "FAIL: only $reflow_run of $reflow_total reflow fixtures ran in CI"
    n_failed=$((n_failed + 1))
  fi
  if ! in_github_actions && [[ $html_total -gt 0 ]]; then
    echo "$HTML_NOT_RUN_LINE"
  fi
  if ! in_github_actions && [[ $reflow_total -gt 0 ]]; then
    echo "$REFLOW_NOT_RUN_LINE"
  fi

  echo "selftest: $n_passed passed, $n_failed failed, html fixtures run: $html_run of $html_total, reflow fixtures run: $reflow_run of $reflow_total"
  [[ $n_failed -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -uo pipefail
  selftest_main "$@"
fi
