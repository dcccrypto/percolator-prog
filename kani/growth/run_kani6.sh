#!/bin/zsh
# growth-v19 rev-6 single Kani run (security review A1-A5). ONE queue, one harness at a time
# (machine shared). Order: primitives -> composite contracts -> the rev-5 NO-VERDICT / deferred /
# CONDITIONAL / new harnesses -> re-confirmation of the unchanged harnesses on the final code.
# Watchdog LIMIT secs (default 1500) kills only the PID tree it spawned; a TIMEOUT is NO-VERDICT,
# never a pass. The queue STOPS at the first VERIFICATION FAILED (report, do not iterate).
# usage: ./run_kani6.sh <tag>        -> logs/<tag>/SUMMARY (crate | harness | verdict | covers | secs)
tag=$1
LIMIT=${LIMIT:-1500}
P=/Users/khubair/wt-growth-v19/percolator-prog
M=/Users/khubair/wt-growth-v19/percolator-match
G=$P/kani/growth
L=$G/logs/$tag
mkdir -p $L; : > $L/SUMMARY
F="-Z function-contracts -Z stubbing"
q=()
g() { for h in "$@"; do q+=("growth|$h|$G|cargo kani $F --harness proofs::$h --exact"); done; }
mv2() { for h in "$@"; do q+=("matcher|$h|$M|cargo kani $F --harness v2::proofs::$h --exact"); done; }
mva() { for h in "$@"; do q+=("matcher|$h|$M|cargo kani $F --harness vamm::proofs::$h --exact"); done; }
wt() { for h in "$@"; do q+=("wrapper-tests|$h|$P|cargo kani $F --tests --harness $h --exact"); done; }
# 1. primitives (the only 128-bit dividers, u8 operands)
g kani_growth_c_mul_div_floor kani_growth_c_mul_div_ceil kani_growth_c_mul_div_none_full_width
mv2 proof_div_ceil_contract
mva proof_skew_div_contract
# 2. composite contracts (primitives stubbed by their proven contracts)
g kani_growth_c_n_cap_q kani_growth_c_liquidity_notional_e6 kani_growth_c_dyn_imr_bps \
  kani_growth_c_leg_im_req kani_growth_c_risk_notional_ceil kani_growth_c_utilisation_fee_bps \
  kani_growth_c_util_fee_on_fill_bps
# 3. rev-5 NO-VERDICT / deferred / CONDITIONAL harnesses, re-targeted, plus the new gap harnesses
g kani_growth_t1_requirement_never_below_engine_or_per_asset kani_growth_t1_required_imr_bounds \
  kani_growth_t2_dyn_imr_monotone_in_lp kani_growth_t2_dyn_imr_antitone_in_ncap \
  kani_growth_t2_required_imr_antitone_in_cm kani_growth_t3_reductions_always_pass \
  kani_growth_t3_thin_side_gets_only_the_ceiling kani_growth_t4_zero_price_fails_closed \
  kani_growth_t4_overflow_fails_closed kani_growth_t5_capacity_invariant \
  kani_growth_t5_at_capacity_costs_full_margin kani_growth_r1_close_is_never_capacity_clipped \
  kani_growth_r2_r12_every_open_faces_the_bound_vault_lp kani_growth_r5_eng_leg_le_engine_leg \
  kani_growth_r8_caps_view_agrees_with_gate kani_growth_r11_capacity_invariant_inductive \
  kani_growth_r11b_ungated_transitions kani_growth_h2_admit_iff_within_ncap \
  kani_growth_r15ab_util_fee_shape_and_monotone kani_growth_r15b_util_fee_monotone_in_max \
  kani_growth_r15c_closes_never_pay kani_growth_t7_rule_implies_gap_solvency kani_growth_clip_iff_gate
mv2 proof_growth_depth_reaches_capacity
mva proof_kind1_skew_units_capped_and_monotone proof_kind1_units_only_under_v3
wt kani_growth_r6_tag94_v19_roundtrip kani_growth_r6_tag93_v19_roundtrip
g kani_growth_t6_ceiling_bounded_and_monotone   # non-gating (results file)
# 4. unchanged harnesses, re-confirmed on the final (A1-refactored) code
g kani_growth_t1_ceiling_never_looser kani_growth_t3_flip_is_risk_increasing \
  kani_growth_t6_ratchet_single_step kani_growth_t7_init_margin_rule_exact kani_growth_r9_r_gap_floor \
  kani_growth_h2_reducing_always_allowed kani_growth_sides_never_skip_a_non_lp_taker \
  kani_growth_dials_tighten_only kani_growth_lp_mid_identity kani_growth_r13_reduce_class_effective \
  kani_growth_r15e_trading_cap_rule
wt kani_growth_r15d_fee_channel_conservation
mv2 proof_v3_effective_inventory_min_and_closed proof_v3_effective_liquidity_min \
  proof_v3_closed_mode_only_reduces_lp proof_v3_parse_rejects_over_i128_cap \
  proof_v3_apply_caps_exempt_means_no_clip proof_v3_close_exempt_fill_is_full
mva proof_v3_neutral_caps_equal_v2

# sanity: every growth harness in proofs.rs is queued exactly once
for h in $(grep -o "fn kani_growth_[a-z_0-9]*" $G/src/proofs.rs | sed 's/fn //'); do
  n=0; for j in "${q[@]}"; do [[ "$j" == "growth|$h|"* ]] && n=$((n+1)); done
  [ $n -eq 1 ] || { echo "QUEUE ERROR: $h queued $n times" | tee -a $L/SUMMARY; exit 2; }
done
echo "queued ${#q[@]} harnesses" > $L/QUEUE; printf '%s\n' "${q[@]}" >> $L/QUEUE

killtree() { local p=$1; for c in $(pgrep -P $p); do killtree $c; done; kill $p 2>/dev/null; }
for j in "${q[@]}"; do
  IFS='|' read crate h dir cmd <<< "$j"
  start=$(date +%s)
  (cd $dir && eval "$cmd") > $L/$h.log 2>&1 &
  pid=$!
  while kill -0 $pid 2>/dev/null; do
    if [ $(( $(date +%s) - start )) -ge $LIMIT ]; then killtree $pid; echo "WATCHDOG: killed after ${LIMIT}s" >> $L/$h.log; break; fi
    sleep 5
  done
  wait $pid 2>/dev/null
  secs=$(( $(date +%s) - start ))
  v=$(grep -E "^VERIFICATION:" $L/$h.log | tail -1)
  grep -q "WATCHDOG" $L/$h.log && [ -z "$v" ] && v="TIMEOUT (${LIMIT}s) = NO-VERDICT"
  c=$(grep -E "cover properties satisfied" $L/$h.log | tail -1 | sed 's/^ *//')
  echo "$crate | $h | ${v:-NO VERDICT (see log)} | ${c:-no cover line} | ${secs}s" >> $L/SUMMARY
  if [[ "$v" == *FAILED* ]]; then echo "STOPPED: $h FAILED" >> $L/SUMMARY; exit 1; fi
done
echo DONE >> $L/SUMMARY
