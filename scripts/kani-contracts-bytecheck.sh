#!/usr/bin/env bash
# Kani contracts must not change the program (security review Q2.3, 2026-10-05). Builds the
# wrapper .so twice with the DEPLOY toolchain (cargo-build-sbf 3.1.15 / platform-tools v1.52):
# once from this tree, once from a copy with every `#[cfg_attr(kani, ...)]` attribute line
# stripped from src/, and fails unless the two .so files are byte-identical.
# Local: ./scripts/kani-contracts-bytecheck.sh        CI: job `kani-contracts-bytecheck`.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TOOLS="${SBF_TOOLS_VERSION:-v1.52}"
SO_NAME="${SO_NAME:-percolator_prog}"
FEATURES="${BUILD_FEATURES---features devnet}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
count() { { grep -rho 'cfg_attr(kani,' "$1" || true; } | wc -l | tr -d ' '; }
n=$(count src)
echo "kani contract attributes in src/: $n"
[ "$n" -gt 0 ] || { echo "no cfg_attr(kani, ...) attributes found; nothing to check"; exit 2; }
# Both builds run from the SAME temp path and target dir (bytecode embeds source paths), and the
# stripped lines are BLANKED, not deleted, so panic-location line numbers are unchanged.
SRC="$WORK/$(basename "$ROOT")"
mkdir -p "$SRC"
cp -R Cargo.toml Cargo.lock src "$SRC/"
for d in tests examples benches; do [ -d "$d" ] && cp -R "$d" "$SRC/"; done
[ -d "$ROOT/../percolator" ] && ln -s "$ROOT/../percolator" "$WORK/percolator"
OUT="$ROOT/target/kani-bytecheck"
mkdir -p "$OUT"
build() { (cd "$SRC" && CARGO_TARGET_DIR="$WORK/target" cargo build-sbf --tools-version "$TOOLS" $FEATURES >"$OUT/build-$1.log" 2>&1) \
  || { echo "build ($1) failed; see $OUT/build-$1.log"; tail -20 "$OUT/build-$1.log"; exit 3; }
  cp "$WORK/target/deploy/$SO_NAME.so" "$OUT/$SO_NAME.$1.so"; }
build with
find "$SRC/src" -name '*.rs' -exec perl -pi -e 's/^[ \t]*#\[cfg_attr\(kani,.*\)\]$//' {} +
left=$(count "$SRC/src")
[ "$left" = 0 ] || { echo "multi-line cfg_attr(kani, ...) left after stripping: $left"; exit 2; }
build without
a="$OUT/$SO_NAME.with.so"; b="$OUT/$SO_NAME.without.so"
shasum -a 256 "$a" "$b"
cmp "$a" "$b"
echo "KANI CONTRACT BYTECHECK: OK ($n attributes, .so byte-identical)"
