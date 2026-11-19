#!/usr/bin/env bash
#
# mayhem/test.sh — RUN wifibroadcast's own unit test (executables/unit_test.cpp, built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

UT="$SRC/mayhem/build/test/unit_test"
[ -x "$UT" ] || { echo "missing $UT — mayhem/build.sh must build it" >&2; exit 1; }

passed=0; failed=0
# run_case <name> <expected output line> <unit_test args...>
# Each mode asserts internally (FEC encode/decode round-trips, retransmission headers); we also
# require its success line, so a no-op binary fails.
run_case() {
  local name="$1" expect="$2"; shift 2
  local out rc
  out="$(cd "$SRC/mayhem/build/test" && timeout 600 "$UT" "$@" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ] && grep -qxF "$expect" <<<"$out"; then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name (rc=$rc)"; tail -20 <<<"$out"; failed=$((failed + 1))
  fi
}
# Modes 3/4 (manual/auto retransmission) are left out: WBTxRx asserts it runs as root, and the
# suite runs as mayhem/sandbox. Mode 2 reads ../example_key/txrx.key, which build.sh generates.
run_case fec "All Tests Passing" -m 1
run_case encryption "All Tests Passing" -m 2

emit_ctrf "wifibroadcast-unit_test" "$passed" "$failed" 0
