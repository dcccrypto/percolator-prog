# Mutant matrix (design note §4 + rev 4/5). Each: (name, target file, old, new, harness, crate)
# crate: "growth" = this proofs crate (production growth_v19.rs copied into
# mutants/growth_v19_mutant.rs, built with --features growth_mutant); "lpnet" = this crate with
# --features lpnet_mutant (harness-model mutant); "match" = percolator-match src, copied aside
# and restored byte-identical.
G = "../../src/growth_v19.rs"
MV2 = "/Users/khubair/wt-growth-v19/percolator-match/src/v2.rs"
MVA = "/Users/khubair/wt-growth-v19/percolator-match/src/vamm.rs"
MUTANTS = [
 ("g1", G, "    Some(if c > engine_imr_bps {\n        c\n    } else {\n        engine_imr_bps\n    })", "    Some(c)", "kani_growth_t1_ceiling_never_looser", "growth"),
 ("g2", G, "    let extra = num.div_ceil(den);", "    let extra = num / den;", "kani_growth_dyn_imr_contract", "growth"),
 ("g3", G, "    if n_cap == 0 || lp_abs_after > n_cap {\n        return None;\n    }\n    let lhs = lp_abs_after.checked_mul(BPS)?;", "    if n_cap == 0 {\n        return None;\n    }\n    let lhs = lp_abs_after.checked_mul(BPS)?;", "kani_growth_dyn_imr_contract", "growth"),
 ("g3b", G, "    if n_cap == 0 || lp_abs_after > n_cap {\n        return None;\n    }\n    let lhs = lp_abs_after.checked_mul(BPS)?;", "    if n_cap == 0 || lp_abs_after >= n_cap {\n        return None;\n    }\n    let lhs = lp_abs_after.checked_mul(BPS)?;", "kani_growth_dyn_imr_contract", "growth"),
 ("g4", G, "    if !taker_risk_increasing(g.taker_before_q, g.taker_after_q) {\n        return GrowthVerdict::Allow;\n    }", "", "kani_growth_t3_reductions_always_pass", "growth"),
 ("g5", G, "            if crowd {\n                dyn_imr_bps(", "            if true {\n                dyn_imr_bps(", "kani_growth_t3_thin_side_gets_only_the_ceiling", "growth"),
 ("g6", G, "    if price_e6 == 0 {\n        return None;\n    }\n    let num = c_m", "    if price_e6 == 0 {\n        return Some(u128::MAX);\n    }\n    let num = c_m", "kani_growth_ncap_exact_floor", "growth"),
 ("g7", G, "            cert.saturating_sub(eng_leg).checked_add(dyn_leg)", "            let _ = (cert, eng_leg);\n            Some(dyn_leg)", "kani_growth_t1_requirement_never_below_engine_or_per_asset", "growth"),
 ("g8", G, "        let stepped = prev_ceil_x100.saturating_add(RATCHET_STEP_X100);", "        let stepped = prev_ceil_x100.saturating_add(2 * RATCHET_STEP_X100);", "kani_growth_t6_ratchet_single_step", "growth"),
 ("g9", G, "    if r_gap_bps == 0 {\n        return false;\n    }\n    match r_gap_floor_bps", "    match r_gap_floor_bps", "kani_growth_t7_init_margin_rule_exact", "growth"),
 ("g10", G, "    lambda_bps >= 1 && lambda_bps <= lambda_max && kink_bps <= kink_max", "    let _ = (lambda_max, kink_max);\n    lambda_bps >= 1", "kani_growth_dials_tighten_only", "growth"),
 ("r2", G, "    if g.lp.is_none() {\n        return GrowthVerdict::NoLpCounterparty;\n    }", "", "kani_growth_r2_r12_every_open_faces_the_bound_vault_lp", "growth"),
 ("r9", G, "        Some(floor) if (r_gap_bps as u64) >= floor => {}\n        _ => return false,", "        _ => {}", "kani_growth_r9_r_gap_floor", "growth"),
 ("n1-thin", G, "            } else if lp.users_oi_side_after_q > n {", "            } else if false && lp.users_oi_side_after_q > n {", "kani_growth_r11_capacity_invariant_inductive", "growth"),
 ("r11b-reopen", G, "            } else if lp.users_oi_side_after_q > n {", "            } else if false && lp.users_oi_side_after_q > n {", "kani_growth_r11b_ungated_transitions", "growth"),
 ("n1-bound", G, "    if !g.asset_bound {\n        return GrowthVerdict::NotBound;\n    }", "", "kani_growth_r2_r12_every_open_faces_the_bound_vault_lp", "growth"),
 ("n1-lpnet", None, None, None, "kani_growth_r11_capacity_invariant_inductive", "lpnet"),
 ("q2-raw", G, "    if size_q != 0 && taker_strictly_reduces(taker_eff_before_q, after) {", "    if size_q != 0 && (taker_strictly_reduces(taker_eff_before_q, after) || (taker_eff_before_q != 0 && (taker_eff_before_q > 0) != (size_q > 0) && size_q.unsigned_abs() <= 2 * taker_eff_before_q.unsigned_abs())) {", "kani_growth_r13_reduce_class_effective", "growth"),
 ("n2-nofee", G, "    if lhs <= rhs || max_fee_bps == 0 {\n        return Some(0);\n    }", "    if true || lhs <= rhs || max_fee_bps == 0 {\n        return Some(0);\n    }", "kani_growth_r15ab_util_fee_shape_and_monotone", "growth"),
 ("n2-closepays", G, "    if taker_strictly_reduces(taker_before_q, taker_after_q) {\n        0\n    } else if taker_flips(", "    if taker_strictly_reduces(taker_before_q, taker_after_q) {\n        taker_after_q.abs_diff(taker_before_q)\n    } else if taker_flips(", "kani_growth_r15c_closes_never_pay", "growth"),
 ("n2-ceil", G, "    ((fee_bps as u128 * o) / fill_abs_q) as u16", "    ((fee_bps as u128 * o).div_ceil(fill_abs_q)) as u16", "kani_growth_r15c_closes_never_pay", "growth"),
 ("m-v3a", MV2, "    if ext_cap == 0 {\n        return None;\n    }", "    if ext_cap == 0 {\n        return Some(ctx_max_inventory_abs);\n    }", "proof_v3_effective_inventory_min_and_closed", "match"),
 ("m-v3b", MV2, "        if ctx_max_inventory_abs == 0 || ext_cap < ctx_max_inventory_abs {", "        if ctx_max_inventory_abs == 0 || ext_cap > ctx_max_inventory_abs {", "proof_v3_effective_inventory_min_and_closed", "match"),
 ("m-v3c", MV2, "    let lp_reduces = (is_buy && inventory_base > 0) || (!is_buy && inventory_base < 0);\n    if lp_reduces {\n        inventory_base.unsigned_abs()", "    let lp_reduces = (is_buy && inventory_base > 0) || (!is_buy && inventory_base < 0);\n    if lp_reduces || true {\n        inventory_base.unsigned_abs()", "proof_v3_closed_mode_only_reduces_lp", "match"),
 ("r1c", MV2, "            max_inventory_abs: if close_exempt { max_inventory_abs } else { m },", "            max_inventory_abs: m,", "proof_v3_apply_caps_exempt_means_no_clip", "match"),
 ("r3", MVA, "    let cap_active = caps.is_some_and(|c| c.inventory_cap_q < SKEW_REF_MAX_INVENTORY_Q);", "    let cap_active = caps.is_some();", "proof_v3_neutral_caps_equal_v2", "match"),
 ("r4", MVA, "    let extra = if v3_units\n        && kind1", "    let extra = if (v3_units || true)\n        && kind1", "proof_kind1_skew_units_capped_and_monotone", "match"),
 ("m-skew", MVA, "        inv_abs.saturating_mul(mult) / ctx.max_inventory_abs\n", "        inv_abs.saturating_mul(mult) / ctx.max_inventory_abs / 10_000\n", "proof_kind1_skew_units_capped_and_monotone", "match"),
]
