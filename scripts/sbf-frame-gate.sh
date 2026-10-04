#!/usr/bin/env bash
# SBF stack-frame gate (security round 3, F-1). Builds the wrapper with
# `-Z emit-stack-sizes` into a separate target dir (codegen unchanged; the deploy build is
# untouched) and checks every function's frame against ci/sbf-frame-baseline.txt.
# Local: ./scripts/sbf-frame-gate.sh        CI: .github/workflows/ci.yml job `sbf-frame-gate`.
set -euo pipefail
cd "$(dirname "$0")/.."
TGT="${SBF_FRAME_TARGET_DIR:-target/sbf-frame-gate}"
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Z emit-stack-sizes" CARGO_TARGET_DIR="$TGT" \
  cargo build-sbf --features devnet
python3 scripts/sbf_stack_sizes.py "$TGT/sbpf-solana-solana/release/percolator_prog.so" \
  ci/sbf-frame-baseline.txt --print 12
