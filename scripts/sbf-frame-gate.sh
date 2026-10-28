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
# night 2026-10-28: Anza deleted the v3.1.15 release (installer + tarballs 404; the tag is gone), so CI
# cannot install it any more. 3.1.14 with the same platform-tools v1.52 / rustc 1.89 builds the rc23
# wrapper (a0c1337d, --features devnet) BYTE-IDENTICAL to 3.1.15 (sha256 1183d57a...04eb both,
# percolator-ops ledger v22-night-2026-10-28.md), so either is accepted; v1.52 stays pinned below.
SBF_CLI_EXPECTED="${SBF_CLI_EXPECTED:-3.1.15|3.1.14}"
if ! cargo build-sbf --version | grep -Eq "cargo-build-sbf (${SBF_CLI_EXPECTED})\b"; then
  echo "sbf-frame-gate: cargo-build-sbf ${SBF_CLI_EXPECTED} required (deploy toolchain), got:" >&2
  cargo build-sbf --version >&2
  exit 2
fi
RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Z emit-stack-sizes" CARGO_TARGET_DIR="$TGT" \
  cargo build-sbf --tools-version "$SBF_TOOLS_VERSION" --features devnet
python3 scripts/sbf_stack_sizes.py "$TGT/sbpf-solana-solana/release/percolator_prog.so" \
  ci/sbf-frame-baseline.txt --print 12
