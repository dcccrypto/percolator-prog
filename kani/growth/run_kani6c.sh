#!/bin/zsh
# growth-v19 rev-6c single Kani run (security review V1-V5). ONE queue, one harness at a time.
# Per-harness watchdog: 4000 s where the harness bit-blasts a real 128-bit divider (primitives,
# order lemmas, bounded real-primitive composites), else 1500 s. A TIMEOUT is NO-VERDICT, never a
# pass. The queue STOPS at the first VERIFICATION FAILED (report, do not iterate). Kills only the
# PID tree it spawned.   usage: ./run_kani6c.sh <tag>  -> logs/<tag>/SUMMARY
tag=$1
P=/Users/khubair/wt-growth-v19/percolator-prog
M=/Users/khubair/wt-growth-v19/percolator-match
G=$P/kani/growth
L=$G/logs/$tag
mkdir -p $L; [ -n "$RESUME" ] || : > $L/SUMMARY
F="-Z function-contracts -Z stubbing"
q=()
g() { local lim=$1; shift; for h in "$@"; do q+=("growth|$h|$G|$lim|cargo kani $F --harness proofs::$h --exact"); done; }
mv2() { local lim=$1; shift; for h in "$@"; do q+=("matcher|$h|$M|$lim|cargo kani $F --harness v2::proofs::$h --exact"); done; }
mva() { local lim=$1; shift; for h in "$@"; do q+=("matcher|$h|$M|$lim|cargo kani $F --harness vamm::proofs::$h --exact"); done; }
wt() { local lim=$1; shift; for h in "$@"; do q+=("wrapper-tests|$h|$P|$lim|cargo kani $F --tests --harness $h --exact"); done; }
# 1. primitives (real dividers, u8)
g 4000 kani_growth_c_mul_div_floor kani_growth_c_mul_div_ceil
mv2 1500 proof_div_ceil_contract
mva 1500 proof_skew_div_contract
# 2. Part A order lemmas (real primitives, u8) + L5 = T7 gap solvency
g 4000 kani_growth_l1_ceil_monotone_in_b kani_growth_l2_ceil_monotone_in_a \
  kani_growth_l3_ceil_antitone_in_d kani_growth_l4_floor_monotone_in_a \
  kani_growth_t7_rule_implies_gap_solvency
# 3. full-width guard twins (R2)
g 1500 kani_growth_g_n_cap_q kani_growth_g_liquidity_notional_e6 kani_growth_g_dyn_imr_bps \
  kani_growth_g_leg_im_req kani_growth_g_risk_notional_ceil kani_growth_g_utilisation_fee_bps \
  kani_growth_g_util_fee_on_fill_bps kani_growth_util_fee_caller_bound
# 4. bounded composites on the REAL primitives (V3) + real-primitive bounded gate facts
g 4000 kani_growth_c_n_cap_q kani_growth_c_liquidity_notional_e6 kani_growth_c_dyn_imr_bps \
  kani_growth_c_leg_im_req kani_growth_c_risk_notional_ceil kani_growth_c_utilisation_fee_bps \
  kani_growth_c_util_fee_on_fill_bps kani_growth_r5_eng_leg_le_engine_leg \
  kani_growth_h2_admit_iff_within_ncap kani_growth_t5_at_capacity_costs_full_margin
# 5. shape harnesses (V1: E1 None-monotonicity, E2 engine domain)
g 1500 kani_growth_t2_dyn_shape_in_lp kani_growth_t2_dyn_shape_in_ncap \
  kani_growth_t2_required_shape_engine_domain kani_growth_r15ab_util_fee_shape_and_monotone \
  kani_growth_r15b_util_fee_monotone_in_max
# 6. gate harnesses, ∀ N_cap / notional / leg (V4)
g 1500 kani_growth_t1_required_imr_bounds kani_growth_t1_requirement_never_below_engine_or_per_asset \
  kani_growth_t3_reductions_always_pass kani_growth_t3_thin_side_gets_only_the_ceiling \
  kani_growth_t4_zero_price_fails_closed kani_growth_t4_overflow_fails_closed \
  kani_growth_t5_capacity_invariant kani_growth_r1_close_is_never_capacity_clipped \
  kani_growth_r2_r12_every_open_faces_the_bound_vault_lp kani_growth_r8_caps_view_agrees_with_gate \
  kani_growth_r11_capacity_invariant_inductive kani_growth_r11b_ungated_transitions
# 7. unchanged harnesses on the final code
g 1500 kani_growth_t1_ceiling_never_looser kani_growth_t3_flip_is_risk_increasing \
  kani_growth_t6_ratchet_single_step kani_growth_t7_init_margin_rule_exact kani_growth_r9_r_gap_floor \
  kani_growth_h2_reducing_always_allowed kani_growth_sides_never_skip_a_non_lp_taker \
  kani_growth_dials_tighten_only kani_growth_lp_mid_identity kani_growth_r13_reduce_class_effective \
  kani_growth_r15c_closes_never_pay kani_growth_r15e_trading_cap_rule kani_growth_clip_iff_gate
wt 1500 kani_growth_r6_tag94_v19_roundtrip kani_growth_r6_tag93_v19_roundtrip kani_growth_r15d_fee_channel_conservation
mv2 1500 proof_growth_depth_reaches_capacity proof_v3_effective_inventory_min_and_closed \
  proof_v3_effective_liquidity_min proof_v3_closed_mode_only_reduces_lp \
  proof_v3_parse_rejects_over_i128_cap proof_v3_apply_caps_exempt_means_no_clip \
  proof_v3_close_exempt_fill_is_full
mva 1500 proof_kind1_skew_units_capped_and_monotone proof_kind1_units_only_under_v3 proof_v3_neutral_caps_equal_v2
g 1500 kani_growth_t6_ceiling_bounded_and_monotone   # NON-GATING (graduation off)

for h in $(grep -o "fn kani_growth_[a-z_0-9]*" $G/src/proofs.rs | sed 's/fn //'); do
  n=0; for j in "${q[@]}"; do [[ "$j" == "growth|$h|"* ]] && n=$((n+1)); done
  [ $n -eq 1 ] || { echo "QUEUE ERROR: $h queued $n times" | tee -a $L/SUMMARY; exit 2; }
done
echo "queued ${#q[@]} harnesses" > $L/QUEUE; printf '%s\n' "${q[@]}" >> $L/QUEUE

killtree() { local p=$1; for c in $(pgrep -P $p); do killtree $c; done; kill $p 2>/dev/null; }
for j in "${q[@]}"; do
  IFS='|' read crate h dir lim cmd <<< "$j"
  grep -q "| $h |" $L/SUMMARY && continue
  start=$(date +%s)
  (cd $dir && eval "$cmd") > $L/$h.log 2>&1 &
  pid=$!
  while kill -0 $pid 2>/dev/null; do
    if [ $(( $(date +%s) - start )) -ge $lim ]; then killtree $pid; echo "WATCHDOG: killed after ${lim}s" >> $L/$h.log; break; fi
    sleep 5
  done
  wait $pid 2>/dev/null
  secs=$(( $(date +%s) - start ))
  v=$(grep -E "^VERIFICATION:" $L/$h.log | tail -1)
  grep -q "WATCHDOG" $L/$h.log && [ -z "$v" ] && v="TIMEOUT (${lim}s) = NO-VERDICT"
  c=$(grep -E "cover properties satisfied" $L/$h.log | tail -1 | sed 's/^ *//')
  echo "$crate | $h | ${v:-NO VERDICT (see log)} | ${c:-no cover line} | ${secs}s" >> $L/SUMMARY
  if [[ "$v" == *FAILED* ]]; then echo "STOPPED: $h FAILED" >> $L/SUMMARY; exit 1; fi
done
echo DONE >> $L/SUMMARY
