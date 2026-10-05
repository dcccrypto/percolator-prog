# Mutant matrix, rev 6b (review A4 + C3: primitive mutants target the primitive harnesses; operand
# mutants must turn the composite contract harnesses red. Earlier header (rev 6, A4: every mutant targets the harness that proves the
# mutated code AS IT IS PROVED NOW -- composite internals are caught by their proof_for_contract
# harness, because gate harnesses replace them by the contract). Each mutant keeps the dividers
# the target harness stubs, so a red result is a real counterexample, not a timeout.
# Each: (name, target file, old, new, harness, crate)
# crate: "growth" = this proofs crate with mutants/growth_v19_mutant.rs (--features growth_mutant);
# "vlp" = mutants/vault_lp_v18_mutant.rs (--features vlp_mutant); "lpnet" = harness-model mutant
# (--features lpnet_mutant); "match" = percolator-match src, copied aside, restored byte-identical.
G = "../../src/growth_v19.rs"
V = "../../src/vault_lp_v18.rs"
MV2 = "/Users/khubair/wt-growth-v19/percolator-match/src/v2.rs"
MVA = "/Users/khubair/wt-growth-v19/percolator-match/src/vamm.rs"
MUTANTS = [
 # ── primitives (A1/A2) ──
 ("p-floor", V, "    a.checked_mul(b).map(|p| p / d)", "    a.checked_mul(b).map(|p| p.div_ceil(d))", "kani_growth_c_mul_div_floor", "vlp"),
 ("p-ceil", G, "    Some(a.checked_mul(b)?.div_ceil(d))", "    Some(a.checked_mul(b)? / d)", "kani_growth_c_mul_div_ceil", "growth"),
 ("p-dzero", G, "    if d == 0 {\n        return None;\n    }\n    Some(a.checked_mul(b)?.div_ceil(d))", "    if d == 0 {\n        return Some(0);\n    }\n    Some(a.checked_mul(b)?.div_ceil(d))", "kani_growth_c_mul_div_ceil", "growth"),
 ("m-divceil", MV2, "    a / b + u128::from(!a.is_multiple_of(b))", "    a / b", "proof_div_ceil_contract", "match"),
 ("m-skewdiv", MVA, "fn skew_div(num: u128, den: u128) -> u128 {\n    num / den\n}", "fn skew_div(num: u128, den: u128) -> u128 {\n    num.div_ceil(den)\n}", "proof_skew_div_contract", "match"),
 # ── composite internals -> their contract harnesses (A4) ──
 ("g1", G, "    Some(if c > engine_imr_bps {\n        c\n    } else {\n        engine_imr_bps\n    })", "    Some(c)", "kani_growth_t1_ceiling_never_looser", "growth"),
 ("g2", G, "    let extra = mul_div_ceil_u128(span, lhs - rhs, den)?;", "    let extra = mul_div_ceil_u128(span, lhs - rhs, den)?.saturating_sub(1);", "kani_growth_c_dyn_imr_bps", "growth"),
 ("g3", G, "    if n_cap == 0 || lp_abs_after > n_cap {", "    if n_cap == 0 {", "kani_growth_c_dyn_imr_bps", "growth"),
 ("g3b", G, "    if n_cap == 0 || lp_abs_after > n_cap {", "    if n_cap == 0 || lp_abs_after >= n_cap {", "kani_growth_c_dyn_imr_bps", "growth"),
 ("g4", G, "    if !taker_risk_increasing(g.taker_before_q, g.taker_after_q) {\n        return GrowthVerdict::Allow;\n    }", "", "kani_growth_t3_reductions_always_pass", "growth"),
 ("g5", G, "            if crowd {\n                dyn_imr_bps(", "            if true {\n                dyn_imr_bps(", "kani_growth_t3_thin_side_gets_only_the_ceiling", "growth"),
 ("g6", G, "    if price_e6 == 0 {\n        return None;\n    }\n    let x = c_m", "    if price_e6 == 0 {\n        return Some(u128::MAX);\n    }\n    let x = c_m", "kani_growth_c_n_cap_q", "growth"),
 ("g7", G, "            cert.saturating_sub(eng_leg).checked_add(dyn_leg)", "            let _ = (cert, eng_leg);\n            Some(dyn_leg)", "kani_growth_t1_requirement_never_below_engine_or_per_asset", "growth"),
 ("g8", G, "        let stepped = prev_ceil_x100.saturating_add(RATCHET_STEP_X100);", "        let stepped = prev_ceil_x100.saturating_add(2 * RATCHET_STEP_X100);", "kani_growth_t6_ratchet_single_step", "growth"),
 ("g9", G, "    if r_gap_bps == 0 {\n        return false;\n    }\n    match r_gap_floor_bps", "    match r_gap_floor_bps", "kani_growth_t7_init_margin_rule_exact", "growth"),
 ("g10", G, "    lambda_bps >= 1 && lambda_bps <= lambda_max && kink_bps <= kink_max", "    let _ = (lambda_max, kink_max);\n    lambda_bps >= 1", "kani_growth_dials_tighten_only", "growth"),
 # ── C3 operand mutants: each must turn its COMPOSITE contract harness red ──
 ("c3-ncap-den", G, "    let den = BPS.checked_mul(price_e6 as u128)?;", "    let den = price_e6 as u128;", "kani_growth_c_n_cap_q", "growth"),
 ("c3-ncap-ceil", G, "    crate::vault_lp_v18::mul_div_floor(x, pos_scale, den)", "    mul_div_ceil_u128(x, pos_scale, den)", "kani_growth_c_n_cap_q", "growth"),
 ("c3-dyn-span", G, "    let span = (MAX_IMR_BPS - base_imr_bps) as u128;", "    let span = MAX_IMR_BPS as u128;", "kani_growth_c_dyn_imr_bps", "growth"),
 ("c3-leg-floor", G, "    let r = mul_div_ceil_u128(notional, imr_bps as u128, BPS)?;", "    let r = crate::vault_lp_v18::mul_div_floor(notional, imr_bps as u128, BPS)?;", "kani_growth_c_leg_im_req", "growth"),
 ("c3-fill-o", G, "    let o = if opening_q > fill_abs_q {\n        fill_abs_q\n    } else {\n        opening_q\n    };", "    let o = fill_abs_q;", "kani_growth_c_util_fee_on_fill_bps", "growth"),
 ("g11-leg", G, "    let r = mul_div_ceil_u128(notional, imr_bps as u128, BPS)?;", "    let r = mul_div_ceil_u128(notional, imr_bps as u128, BPS)?.saturating_sub(1);", "kani_growth_c_leg_im_req", "growth"),
 ("g12-risk", G, "    mul_div_ceil_u128(abs_q, price_e6 as u128, pos_scale)", "    mul_div_ceil_u128(abs_q, price_e6 as u128, pos_scale).map(|x| x.saturating_sub(1))", "kani_growth_c_risk_notional_ceil", "growth"),
 # ── gate rules ──
 ("r2", G, "    if g.lp.is_none() {\n        return GrowthVerdict::NoLpCounterparty;\n    }", "", "kani_growth_r2_r12_every_open_faces_the_bound_vault_lp", "growth"),
 ("r9", G, "        Some(floor) if (r_gap_bps as u64) >= floor => {}\n        _ => return false,", "        _ => {}", "kani_growth_r9_r_gap_floor", "growth"),
 ("n1-thin", G, "            } else if lp.users_oi_side_after_q > n {", "            } else if false && lp.users_oi_side_after_q > n {", "kani_growth_r11_capacity_invariant_inductive", "growth"),
 ("r11b-reopen", G, "            } else if lp.users_oi_side_after_q > n {", "            } else if false && lp.users_oi_side_after_q > n {", "kani_growth_r11b_ungated_transitions", "growth"),
 ("n1-bound", G, "    if !g.asset_bound {\n        return GrowthVerdict::NotBound;\n    }", "", "kani_growth_r2_r12_every_open_faces_the_bound_vault_lp", "growth"),
 ("n1-lpnet", None, None, None, "kani_growth_r11_capacity_invariant_inductive", "lpnet"),
 ("q2-raw", G, "    if size_q != 0 && taker_strictly_reduces(taker_eff_before_q, after) {", "    if size_q != 0 && (taker_strictly_reduces(taker_eff_before_q, after) || (taker_eff_before_q != 0 && (taker_eff_before_q > 0) != (size_q > 0) && size_q.unsigned_abs() <= 2 * taker_eff_before_q.unsigned_abs())) {", "kani_growth_r13_reduce_class_effective", "growth"),
 ("clip", G, "    n_cap.saturating_sub(users_oi_side_before_q)", "    n_cap.saturating_sub(users_oi_side_before_q).saturating_add(1)", "kani_growth_clip_iff_gate", "growth"),
 # ── N-2 utilisation fee ──
 ("n2-nofee", G, "    if lhs <= rhs || max_fee_bps == 0 {\n        return Some(0);\n    }", "    if true || lhs <= rhs || max_fee_bps == 0 {\n        return Some(0);\n    }", "kani_growth_c_utilisation_fee_bps", "growth"),
 ("n2-closepays", G, "    if taker_strictly_reduces(taker_before_q, taker_after_q) {\n        0\n    } else if taker_flips(", "    if taker_strictly_reduces(taker_before_q, taker_after_q) {\n        taker_after_q.abs_diff(taker_before_q)\n    } else if taker_flips(", "kani_growth_r15c_closes_never_pay", "growth"),
 ("n2-ceil", G, "        Some(x) => x as u16,", "        Some(x) => (x + 1).min(fee_bps as u128) as u16,", "kani_growth_c_util_fee_on_fill_bps", "growth"),
 # ── matcher ──
 ("m-v3a", MV2, "    if ext_cap == 0 {\n        return None;\n    }", "    if ext_cap == 0 {\n        return Some(ctx_max_inventory_abs);\n    }", "proof_v3_effective_inventory_min_and_closed", "match"),
 ("m-v3b", MV2, "        if ctx_max_inventory_abs == 0 || ext_cap < ctx_max_inventory_abs {", "        if ctx_max_inventory_abs == 0 || ext_cap > ctx_max_inventory_abs {", "proof_v3_effective_inventory_min_and_closed", "match"),
 ("m-v3c", MV2, "    let lp_reduces = (is_buy && inventory_base > 0) || (!is_buy && inventory_base < 0);\n    if lp_reduces {\n        inventory_base.unsigned_abs()", "    let lp_reduces = (is_buy && inventory_base > 0) || (!is_buy && inventory_base < 0);\n    if lp_reduces || true {\n        inventory_base.unsigned_abs()", "proof_v3_closed_mode_only_reduces_lp", "match"),
 ("r1c", MV2, "            max_inventory_abs: if close_exempt { max_inventory_abs } else { m },", "            max_inventory_abs: m,", "proof_v3_apply_caps_exempt_means_no_clip", "match"),
 ("r3", MVA, "    let cap_active = caps.is_some_and(|c| c.inventory_cap_q < SKEW_REF_MAX_INVENTORY_Q);", "    let cap_active = caps.is_some();", "proof_v3_neutral_caps_equal_v2", "match"),
 ("r4", MVA, "    let extra = if v3_units\n        && kind1", "    let extra = if (v3_units || true)\n        && kind1", "proof_kind1_units_only_under_v3", "match"),
 ("m-skew", MVA, "        skew_div(inv_abs.saturating_mul(mult), ctx.max_inventory_abs)\n", "        skew_div(inv_abs.saturating_mul(mult), ctx.max_inventory_abs.saturating_mul(2))\n", "proof_kind1_skew_units_capped_and_monotone", "match"),
]
