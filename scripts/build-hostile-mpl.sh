#!/usr/bin/env bash
# Builds the TEST-ONLY hostile Metaplex stand-in (tests/fixtures/hostile_mpl, source committed,
# dependencies pinned by its own Cargo.lock) used by the `*_hostile_metaplex` tests in
# tests/v22_lp_share_mint.rs. Never deployed. Prints the path to pass as HOSTILE_MPL_SO.
set -euo pipefail
cd "$(dirname "$0")/../tests/fixtures/hostile_mpl"
cargo build-sbf -- --locked >&2
SO="$(pwd)/target/deploy/hostile_mpl.so"
[ -f "$SO" ] || { echo "build-hostile-mpl: no artifact at $SO" >&2; exit 1; }
echo "$SO"
