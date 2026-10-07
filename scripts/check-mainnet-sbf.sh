#!/usr/bin/env bash
# Release gate (P-2): accept ONLY a wrapper .so built with `--features mainnet-ids` and the real
# (non-placeholder) ids. Every build carries exactly one pin marker in its read-only data:
#   PCLR-PIN:MAINNET-OK          pinned, all four ids set      -> accepted
#   PCLR-PIN:TEST-PLACEHOLDE...  mainnet-ids-test-placeholders -> REJECTED
#   PCLR-PIN:NONE                no pin (no feature, or devnet)  -> REJECTED
# usage: scripts/check-mainnet-sbf.sh <path/to/percolator_prog.so>
set -euo pipefail
SO="${1:?usage: check-mainnet-sbf.sh <percolator_prog.so>}"
[ -r "$SO" ] || { echo "FATAL: $SO not readable"; exit 2; }
ok=$(grep -a -c "PCLR-PIN:MAINNET-OK" "$SO" || true)
test_ph=$(grep -a -c "PCLR-PIN:TEST" "$SO" || true)
none=$(grep -a -c "PCLR-PIN:NONE" "$SO" || true)
echo "markers: mainnet-ok=$ok test-placeholders=$test_ph none=$none"
if [ "$test_ph" -ne 0 ]; then echo "REJECT: built with mainnet-ids-test-placeholders (dummy ids)"; exit 1; fi
if [ "$none" -ne 0 ]; then echo "REJECT: unpinned build (no --features mainnet-ids, or a devnet build)"; exit 1; fi
if [ "$ok" -ne 1 ]; then echo "REJECT: expected exactly one PCLR-PIN:MAINNET-OK marker"; exit 1; fi
echo "OK: pinned mainnet build ($SO)"
