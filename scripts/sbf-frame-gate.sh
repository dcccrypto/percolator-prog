#!/usr/bin/env bash
# SBF stack-frame gate (security round 3, F-1). Builds the wrapper with
# `-Z emit-stack-sizes` into a separate target dir (codegen unchanged; the deploy build is
# untouched) and checks every function's frame against ci/sbf-frame-baseline.txt.
# Local: ./scripts/sbf-frame-gate.sh        CI: .github/workflows/ci.yml job `sbf-frame-gate`.
set -euo pipefail
cd "$(dirname "$0")/.."
TGT="${SBF_FRAME_TARGET_DIR:-target/sbf-frame-gate}"
# R4-1 (security round 4): measure the toolchain that SHIPS. Deploy builds use
# cargo-build-sbf 3.1.15 + platform-tools v1.52 (deployments.md); frame sizes are toolchain
# dependent, so the gate pins the same platform tools and refuses any other cargo-build-sbf.
SBF_TOOLS_VERSION="${SBF_TOOLS_VERSION:-v1.52}"
SBF_CLI_EXPECTED="${SBF_CLI_EXPECTED:-3.1.15}"
if ! cargo build-sbf --version | grep -q "cargo-build-sbf ${SBF_CLI_EXPECTED}"; then
  echo "sbf-frame-gate: cargo-build-sbf ${SBF_CLI_EXPECTED} required (deploy toolchain), got:" >&2
  cargo build-sbf --version >&2
  exit 2
fi
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Z emit-stack-sizes" CARGO_TARGET_DIR="$TGT" \
  cargo build-sbf --tools-version "$SBF_TOOLS_VERSION" --features devnet
python3 scripts/sbf_stack_sizes.py "$TGT/sbpf-solana-solana/release/percolator_prog.so" \
  ci/sbf-frame-baseline.txt --print 12
