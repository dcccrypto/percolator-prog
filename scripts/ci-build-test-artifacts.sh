#!/usr/bin/env bash
# Build the TEST-ONLY reference programs the wrapper suite needs and CI used to lack (day1 2026-10-28).
#
# Without these ~25 tests failed in CI only (gate_p1_batch_* / gate_p2_* in indep_gate_extra,
# p1p2_* / p1_* in indep_p1p2_ext, p2_legacy_mode0_* in p1_fee_channel,
# growth_v19::growth_off_is_byte_for_byte_legacy). They were deliberately NOT allowlisted; this
# script is the fix: the job builds the artifacts from pinned source instead of hiding the tests.
#
#   $OUT/v1-matcher.so   percolator-match @ MATCHER_V1_CI_SIBLING (12bd671, the v18.2 deployed matcher)
#   $OUT/p2-matcher.so   percolator-match @ MATCHER_P2_CI_SIBLING (4a0f696, feat/p2-matcher-v2)
#   $OUT/growth-base.so  percolator-prog  @ GROWTH_BASE_WRAPPER (7c906e45, v2.1) on engine GROWTH_BASE_ENGINE
#                        (35ddd692), --features devnet, exactly as it was deployed
#
# Toolchain: the DEPLOY toolchain (cargo-build-sbf 3.1.14/3.1.15, platform-tools v1.52). What is PINNED
# (and fails the job) is the SOURCE: every checkout must be at its pin. The bytes are reported against the
# recorded deploy-toolchain builds but do not gate: SBF bytes depend on the build host and path (the first
# CI run built matcher 12bd671 as cccc58de... on the runner vs 659eaf9d... on the macOS deploy host; the
# wrapper is path-dependent too, ledger deploy-runbook-matcher-sync-2026-10-03). The tests need behaviour.
#
# Usage: scripts/ci-build-test-artifacts.sh <dir with percolator-match-v1, percolator-match-p2,
#        growth-base/percolator-prog, growth-base/percolator> <out dir>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:?source dir}"; OUT="${2:?out dir}"
set -a; . "$ROOT/ci/deployed-refs.env"; set +a
TOOLS=v1.52

if ! cargo build-sbf --version | grep -Eq "cargo-build-sbf (3\.1\.14|3\.1\.15)\b"; then
  echo "FATAL: the deploy toolchain (cargo-build-sbf 3.1.14/3.1.15) is required, got:"; cargo build-sbf --version; exit 1
fi
mkdir -p "$OUT"

head_is() { # dir want
  local have; have="$(git -C "$1" rev-parse HEAD)"
  [ "$have" = "$2" ] || { echo "FATAL: $1 is at $have, pin is $2"; exit 1; }
}
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

build_matcher() { # dir pin want_sha out
  head_is "$1" "$2"
  ( cd "$1" && cargo build-sbf --tools-version "$TOOLS" )
  local got; got="$(sha "$1/target/deploy/percolator_match.so")"
  local same="differs from"; [ "$got" = "$3" ] && same="matches"
  cp "$1/target/deploy/percolator_match.so" "$4"
  echo "  $4  $got  $(wc -c < "$4" | tr -d ' ') B  (percolator-match @ $2; $same the recorded deploy-host build $3)"
}

echo "::group::test-only reference programs"
build_matcher "$SRC/percolator-match-v1" "$MATCHER_V1_CI_SIBLING" "$MATCHER_V1_CI_SHA256" "$OUT/v1-matcher.so"
build_matcher "$SRC/percolator-match-p2" "$MATCHER_P2_CI_SIBLING" "$MATCHER_P2_CI_SHA256" "$OUT/p2-matcher.so"

head_is "$SRC/growth-base/percolator-prog" "$GROWTH_BASE_WRAPPER"
head_is "$SRC/growth-base/percolator" "$GROWTH_BASE_ENGINE"
( cd "$SRC/growth-base/percolator-prog" && cargo build-sbf --tools-version "$TOOLS" --features devnet )
cp "$SRC/growth-base/percolator-prog/target/deploy/percolator_prog.so" "$OUT/growth-base.so"
len="$(wc -c < "$OUT/growth-base.so" | tr -d ' ')"
echo "  $OUT/growth-base.so  $(sha "$OUT/growth-base.so")  $len B  (percolator-prog @ $GROWTH_BASE_WRAPPER, engine $GROWTH_BASE_ENGINE; the deployed build was $GROWTH_BASE_SO_LEN B)"
# the base build's intermediates are not needed again; keep the runner's disk for the suite
rm -rf "$SRC/growth-base/percolator-prog/target"
echo "::endgroup::"
