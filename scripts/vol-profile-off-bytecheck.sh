#!/usr/bin/env bash
# Day1 2026-10-28 (decision 1, P3): the volatility profile is wired into the guarded-open gate as a
# TIGHTEN-ONLY floor, OFF by default (`lev_profile_v22::VOL_PROFILE_LIVE = false`). This proves the OFF
# program is byte-for-byte the UNWIRED program: it builds the wrapper .so twice with the deploy toolchain
# from the same temp path -- once as committed, once with the two wired call-site lines in
# `lev_trade_post` put back to their unwired form (same line count, so panic locations do not move) --
# and fails unless the two .so files are identical. It also refuses to pass if the switch is ON.
# Local: ./scripts/vol-profile-off-bytecheck.sh        CI: job `kani-contracts-bytecheck` (second step).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TOOLS="${SBF_TOOLS_VERSION:-v1.52}"
FEATURES="${BUILD_FEATURES---features devnet}"
grep -q '^pub const VOL_PROFILE_LIVE: bool = false;$' src/lev_profile_v22.rs \
  || { echo "VOL_PROFILE_LIVE is not 'false' in src/lev_profile_v22.rs: this check only certifies the OFF build"; exit 2; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/$(basename "$ROOT")"
mkdir -p "$SRC"
cp -R Cargo.toml Cargo.lock src "$SRC/"
[ -f build.rs ] && cp build.rs "$SRC/"
[ -d ci ] && cp -R ci "$SRC/"
for d in tests examples benches; do [ -d "$d" ] && cp -R "$d" "$SRC/"; done
[ -d "$ROOT/../percolator" ] && ln -s "$ROOT/../percolator" "$WORK/percolator"
OUT="$ROOT/target/vol-profile-bytecheck"
mkdir -p "$OUT"
build() { (cd "$SRC" && CARGO_TARGET_DIR="$WORK/target" cargo build-sbf --tools-version "$TOOLS" $FEATURES >"$OUT/build-$1.log" 2>&1) \
  || { echo "build ($1) failed; see $OUT/build-$1.log"; tail -20 "$OUT/build-$1.log"; exit 3; }
  cp "$WORK/target/deploy/percolator_prog.so" "$OUT/percolator_prog.$1.so"; }
build wired
python3 - "$SRC/src/v16_program.rs" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
edits = [
    ("        let (mmr_lev, imr_floor) = crate::lev_profile_v22::open_gate_floor(mmr, || g.vol_has_data().then(|| lg::burst_var_eff(gd.burst_var_peak_x100, gd.burst_peak_slot, g.vol_var_x100(), now)));\n",
     "\n"),
    ("        let l_tr = lg::l_trader_x100(mmr_lev, sigma_lev, ov.j_dump_bps);\n",
     "        let l_tr = lg::l_trader_x100(mmr, sigma_lev, ov.j_dump_bps);\n"),
    ("        let imr = growth_v19::ceiling_imr_bps(engine_imr, l_eff).ok_or_else(overflow)?.max(imr_floor);\n",
     "        let imr = growth_v19::ceiling_imr_bps(engine_imr, l_eff).ok_or_else(overflow)?;\n"),
]
for old, new in edits:
    if s.count(old) != 1:
        print(f"UNWIRE TARGET NOT FOUND EXACTLY ONCE: {old.strip()!r}"); sys.exit(3)
    s = s.replace(old, new)
open(p, "w").write(s)
PY
grep -v '^[[:space:]]*//' "$SRC/src/v16_program.rs" | grep -q 'open_gate_floor\|imr_floor\|mmr_lev' && { echo "unwiring left a reference behind"; exit 3; }
build unwired
a="$OUT/percolator_prog.wired.so"; b="$OUT/percolator_prog.unwired.so"
shasum -a 256 "$a" "$b"
cmp "$a" "$b"
echo "VOL PROFILE OFF BYTECHECK: OK (wired-but-OFF .so == unwired .so)"
