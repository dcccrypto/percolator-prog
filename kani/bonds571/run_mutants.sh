#!/bin/bash
# GH#571 Kani negative controls: one mutant per key property, each must make its harness FAIL.
# usage: ./run_mutants.sh            (from kani/bonds571; local only, never CI)
set -u
cd "$(dirname "$0")"
SRC=../../src/bond_v20.rs
OUT=mutants/bond_v20_mutant.rs
mkdir -p logs/mutants
run() { # name harness old new
  python3 - "$SRC" "$OUT" "$3" "$4" <<'PY' || { echo "ANCHOR $1"; return; }
import sys
src, out, old, new = sys.argv[1:5]
s = open(src).read()
assert s.count(old) == 1, "anchor not unique"
open(out, "w").write(s.replace(old, new))
PY
  local start=$(date +%s)
  cargo kani -j 2 --features bond_mutant --harness "proofs::$2" --exact > "logs/mutants/$1.log" 2>&1
  local rc=$?
  local v=$(grep -E "VERIFICATION:-" "logs/mutants/$1.log" | tail -1)
  if [ $rc -ne 0 ] && echo "$v" | grep -q FAILED; then echo "$1 | $2 | KILLED | $(( $(date +%s) - start ))s"; else echo "$1 | $2 | SURVIVED rc=$rc $v"; fi
}
run K1_pay_forfeits_rest kani_571_pay_conserves_leg_and_claim \
  '    (coupon, rest, arrears - coupon)' '    (coupon, rest, 0 * arrears)'
run K2_arrears_uncapped kani_571_settle_monotone_capped_no_overflow \
  '    let ceiling = if cap > arrears { cap } else { arrears };' '    let ceiling = u128::MAX; let _ = cap;'
run K3_closed_gate_drops_arrears kani_571_settle_monotone_capped_no_overflow \
  '    if !open {
        return Some(arrears);' '    if !open {
        return Some(0);'
run K4_redemption_ignores_arrears kani_571_redemption_slices_full_claim \
  '    let a_slice = total_slice.checked_sub(c_slice)?;' '    let a_slice = 0u128; let _ = total_slice;'
run K5_accrual_base_principal_only kani_571_newcomer_neutral_within_rounding \
  '    let accrued = coupon_due(coupon_base(k, bond_value), rate_bps, dslots)?;' '    let accrued = coupon_due(coupon_base(bond_principal, bond_value), rate_bps, dslots)?; let _ = k;'
run K6_hold_ignores_cap kani_571_checkpoint_hold_rule \
  '    !open || arrears_after != arrears_before || arrears_before >= cap' '    let _ = cap; !open || arrears_after != arrears_before'
run K7_settle_not_monotone_in_time kani_571_settle_monotone_in_time \
  '    let a = arrears.checked_add(accrued)?;' '    let a = arrears.checked_add(accrued % 7)?;'
rm -f "$OUT"
