#!/usr/bin/env bash
# Release check (security re-review W-M2 / "mainnet SBF without devnet"):
#
#   scripts/check-mainnet-sbf.sh <path/to/percolator_prog.so>
#
# Fails unless the given SBF artifact was built WITHOUT the `devnet` feature. Two independent
# checks:
#
# 1. Artifact: the exported `PERCOLATOR_BUILD_FLAVOR` marker (src/v16_program.rs) must read
#    `mainnet` and must not read `devnet`. A devnet build's band caps are 10x lambda / 70%
#    alpha instead of the mainnet 3x / 60%.
# 2. Source: the mainnet constants themselves (`sec_band_caps_by_build`, run with default
#    features, i.e. without `devnet`).
#
# Negative control: run it on a `cargo build-sbf --features devnet` artifact; it must fail.
set -euo pipefail
SO="${1:?usage: check-mainnet-sbf.sh <percolator_prog.so>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$SO" ] || { echo "check-mainnet-sbf: no such file: $SO" >&2; exit 2; }

python3 - "$SO" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
dev = b"PERCOLATOR_BUILD_FLAVOR=devnet.." in data
main = b"PERCOLATOR_BUILD_FLAVOR=mainnet." in data
if dev or not main:
    print(f"check-mainnet-sbf: FAIL: build flavor marker devnet={dev} mainnet={main} (built with --features devnet, or an old image)")
    sys.exit(1)
print(f"check-mainnet-sbf: artifact OK ({len(data)} B): mainnet build flavor")
PY

# prog#542 / security review R10: the LP share token's metadata uri base is a compile-time
# constant and a ticker record is immutable, so the artifact must carry the MAINNET base and
# must not carry the devnet one. Both strings are read from the source, not repeated here.
python3 - "$SO" "$ROOT/src/lp_share_meta_v22.rs" <<'PY'
import re, sys
data = open(sys.argv[1], "rb").read()
src = open(sys.argv[2]).read()
def const(name):
    m = re.search(r'pub const %s: &str = "([^"]+)";' % name, src)
    if not m:
        print(f"check-mainnet-sbf: FAIL: {name} not found in src/lp_share_meta_v22.rs"); sys.exit(1)
    return m.group(1).encode()
main, dev = const("LP_SHARE_URI_BASE_MAINNET"), const("LP_SHARE_URI_BASE_DEVNET")
# (the 16-byte path is too short to survive as a string: the compiler inlines it as immediates)
ok = main in data and dev not in data
if not ok:
    print(f"check-mainnet-sbf: FAIL: LP share uri base: mainnet {main!r} present={main in data}, devnet {dev!r} present={dev in data}")
    sys.exit(1)
print(f"check-mainnet-sbf: LP share uri base OK ({main.decode()})")
PY

cd "$ROOT"
cargo test --release --test sec_v22b_pure sec_band_caps_by_build -- --exact >/dev/null 2>&1 || {
  echo "check-mainnet-sbf: FAIL: sec_band_caps_by_build without devnet" >&2
  exit 1
}
echo "check-mainnet-sbf: mainnet band caps OK (lambda 3x, alpha 60%)"
"$ROOT/scripts/check-mainnet-pin.sh" "$SO"
echo "check-mainnet-sbf: PASS"
