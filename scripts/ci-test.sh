#!/usr/bin/env bash
# Run the wrapper test suite the way it actually has to be run.
#
# Two things this script exists to enforce:
#
#  1. --no-fail-fast. `cargo test` ABORTS at the first failing suite. Without this
#     flag the run stopped at v16_cu and never executed 17 of 25 suites, reporting
#     "137 passed / 11 failed" when the truth was 546 / 55. Any aggregate number
#     produced without --no-fail-fast is not a measurement.
#
#  2. Sibling program BPFs. The wrapper compiles the engine by path and mounts the
#     matcher / nft / stake .so files for its cross-program suites. Without them
#     v16_five_program_crosscut and v16_nft_e2e report 0 passing -- the whole
#     cross-program safety net silently does nothing. Building all four takes the
#     failure count from 86 to 55.
#
# Verdict rule: compare the failing set against tests/KNOWN_FAILING.txt.
#   - a NEW failure          -> RED (a regression)
#   - an allowlisted test that now PASSES -> RED (remove it from the list)
# Silence is never success here.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "::group::build sibling program BPFs"
for sib in percolator-match percolator-nft percolator-stake; do
  if [ -d "../$sib" ]; then
    ( cd "../$sib" && cargo build-sbf ) || { echo "FATAL: $sib BPF build failed"; exit 1; }
    echo "  built $sib"
  else
    echo "FATAL: ../$sib missing — the cross-program suites cannot run without it"; exit 1
  fi
done
echo "::endgroup::"

echo "::group::build wrapper BPF"
cargo build-sbf --no-default-features || exit 1
echo "::endgroup::"

echo "::group::cargo test --no-fail-fast"
cargo test --no-fail-fast 2>&1 | tee /tmp/ci_test.log | tail -40
echo "::endgroup::"

grep -E "^test .* FAILED" /tmp/ci_test.log | sed 's/^test //;s/ \.\.\. FAILED$//' | sort -u > /tmp/ci_failing.txt
sort -u tests/KNOWN_FAILING.txt > /tmp/ci_known.txt

passed=$(grep -E "^test result:" /tmp/ci_test.log | awk '{p+=$4} END{print p}')
failed=$(grep -E "^test result:" /tmp/ci_test.log | awk '{f+=$6} END{print f}')
echo "TOTALS: passed=$passed failed=$failed  (allowlisted: $(wc -l < /tmp/ci_known.txt))"

new_failures=$(comm -23 /tmp/ci_failing.txt /tmp/ci_known.txt)
now_passing=$(comm -13 /tmp/ci_failing.txt /tmp/ci_known.txt)

rc=0
if [ -n "$new_failures" ]; then
  echo "::error::NEW failures not in tests/KNOWN_FAILING.txt — this is a regression:"
  echo "$new_failures" | sed 's/^/    /'
  rc=1
fi
if [ -n "$now_passing" ]; then
  echo "::error::allowlisted tests now PASS — remove them from tests/KNOWN_FAILING.txt:"
  echo "$now_passing" | sed 's/^/    /'
  rc=1
fi
[ $rc -eq 0 ] && echo "OK: failing set matches the allowlist exactly"
exit $rc
