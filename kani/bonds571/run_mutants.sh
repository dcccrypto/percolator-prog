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
run K1_pay_forfeits_rest kani_571_pay_conserves_leg_and_receivable \
  '    (coupon, rest, receivable - coupon)' '    (coupon, rest, 0 * receivable)'
run K2_cap_ignored kani_571_settle_cap_closed_exact_remainder \
  '    let room = cap.saturating_sub(unfunded);' '    let room = u128::MAX; let _ = cap;'
run K3_closed_gate_drops_remainder kani_571_settle_cap_closed_exact_remainder \
  '        return Some((0, rem));' '        return Some((0, 0));'
run K4_remainder_dropped kani_571_split_interval_is_exact \
  '        Some((due, u64::try_from(num % denom).ok()?))' '        Some((due, 0))'
run K5_deposit_not_labelled kani_571_deposit_meter_keeps_ratio_and_bound \
  '    unfunded.checked_add(label)' '    unfunded.checked_add(0 * label)'
run K6_exit_keeps_meter kani_571_redemption_slices_k_and_meter \
  '    unfunded.checked_sub(mul_div_floor(shares, unfunded, total_shares)?)' '    let _ = mul_div_floor(shares, unfunded, total_shares)?; Some(unfunded)'
run K7_accrual_base_funded_only kani_571_newcomer_neutral_within_rounding \
  '    let num = coupon_base(bond_claim, bond_value)' '    let num = coupon_base(bond_funded_claim(bond_claim, unfunded), bond_value)'
run K8_gate_memory_ignores_draws kani_571_gate_memory_rule \
  '    seen == coupon_gate_seen(senior_drawn, true)' '    let _ = senior_drawn; seen >> 63 == 0'
run K9_base_ignores_the_claim kani_571_junior_gate_bound_dominates_every_settlement \
  '    let num = coupon_base(bond_claim, bond_value)' '    let num = bond_value'
rm -f "$OUT"
