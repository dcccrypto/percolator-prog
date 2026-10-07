#!/usr/bin/env bash
# Runs the PINNED-flavour LiteSVM tests (tag 94 under the pinned matcher) against a wrapper .so built with
# `--features mainnet-ids-test-placeholders` (dummy ids; never a release artifact). Builds one if no .so given.
#   usage: scripts/pin-flavour-tests.sh [path/to/placeholder-pin/percolator_prog.so]
set -euo pipefail
cd "$(dirname "$0")/.."
SO="${1:-}"
if [ -z "$SO" ]; then
  cargo build-sbf --tools-version "${SBF_TOOLS_VERSION:-v1.52}" --features mainnet-ids-test-placeholders --sbf-out-dir target/pin-flavour
  SO="$PWD/target/pin-flavour/percolator_prog.so"
fi
grep -a -q "PCLR-PIN:TEST" "$SO" || { echo "FATAL: $SO is not a mainnet-ids-test-placeholders build"; exit 2; }
# the placeholder-pin build runs only at its pinned wrapper id [0xA2; 32]
PINNED_ID=$(python3 -c "A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';n=int.from_bytes(bytes([0xA2])*32,'big');s=''
while n: n,r=divmod(n,58);s=A[r]+s
print(s)")
OUT=$(PIN_FLAVOUR=1 INDEP_PROGRAM_ID="$PINNED_ID" INDEP_WRAPPER_SO="$SO" cargo test --features devnet --test p4_wave_d -- --ignored pin_ 2>&1) || { echo "$OUT" | tail -30; echo "PIN FLAVOUR TESTS: FAIL"; exit 1; }
echo "$OUT" | grep -E "^test |test result"
echo "$OUT" | grep -q "1 passed" || { echo "PIN FLAVOUR TESTS: FAIL (test did not run)"; exit 1; }
echo "PIN FLAVOUR TESTS: OK"
