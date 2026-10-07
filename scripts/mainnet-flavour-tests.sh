#!/usr/bin/env bash
# Release gate: runs the MAINNET-FLAVOUR tests (the `#[ignore]`d ones in tests/p4_wave_d.rs) against a
# NON-devnet wrapper .so. In a normal `cargo test` these are reported as IGNORED (skipped), never as
# passed; this script is the only thing that runs them, and it fails unless every expected test ran.
#   usage: scripts/mainnet-flavour-tests.sh [path/to/non-devnet/percolator_prog.so]
# With no argument it builds the non-devnet .so (no features) into target/mainnet-flavour.
set -euo pipefail
cd "$(dirname "$0")/.."
SO="${1:-}"
if [ -z "$SO" ]; then
  cargo build-sbf --tools-version "${SBF_TOOLS_VERSION:-v1.52}" --sbf-out-dir target/mainnet-flavour
  SO="$PWD/target/mainnet-flavour/percolator_prog.so"
fi
[ -r "$SO" ] || { echo "FATAL: $SO not readable"; exit 2; }
# every expected test must RUN (not be filtered): the count is asserted below
EXPECTED=$(grep -c 'run scripts/mainnet-flavour-tests.sh' tests/p4_wave_d.rs)
OUT=$(INDEP_WRAPPER_SO="$SO" R1_FLAVOUR=mainnet cargo test --features devnet --test p4_wave_d -- --ignored --skip pin_ 2>&1) || { echo "$OUT" | tail -40; echo "MAINNET FLAVOUR TESTS: FAIL"; exit 1; }
echo "$OUT" | grep -E "^test |test result"
PASSED=$(echo "$OUT" | sed -n 's/^test result: ok\. \([0-9]*\) passed.*/\1/p' | head -1)
if [ "${PASSED:-0}" -ne "$EXPECTED" ] || [ "$EXPECTED" -lt 1 ]; then
  echo "MAINNET FLAVOUR TESTS: FAIL (ran ${PASSED:-0}, expected $EXPECTED ignored-marked tests)"; exit 1
fi
echo "MAINNET FLAVOUR TESTS: OK ($PASSED tests, .so $SO)"
