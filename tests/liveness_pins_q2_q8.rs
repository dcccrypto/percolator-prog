//! Liveness policy pins (decision 2026-10-22, L2 Q2 and Q8). Pure, no BPF harness.
//!
//! Q2  A stale Hybrid oracle refuses liquidation of every leg until `hybrid_soft_stale_slots`
//!     matures. Kept for v2.2; the bound that matters is that the maturity gate is exact and that
//!     the price-managed AUTH_MARK / EWMA profiles (every seeded v2.2 market is AUTH_MARK) can
//!     never carry a soft-stale value.
//! Q8  The F1 follow-on (`f1_follow_on_wanted`) is all-or-nothing: if the engine's liquidation
//!     refuses, the whole crank instruction reverts, refresh included. Safe only while every
//!     engine refusal on `liquidate_account_not_atomic` is screened out by the follow-on's
//!     decision inputs (`legs_reducible`, `b_stale`, `pending_close`, `recovery_eligible`, ...).
//!     The census below pins the engine function's refusal surface; a new refusal fails this
//!     test and forces the author to extend `f1_follow_on_wanted` (or consciously accept it).
//!
//! Q3 (one account's uncovered loss declares Recovery) and Q5 (the crank liquidates the first
//! slot) are pinned by the engine test
//! `v16_auto_crank_commits_recovery_for_uncovered_cross_margin_liquidation`
//! (`tests/v16_spec_tests.rs`): 2 legs, `selected == Liquidate { asset_index: 0 }`, market
//! mode -> Recovery from a 5-atom uncovered loss.

use percolator_prog::{
    constants::{ORACLE_MODE_AUTH_MARK, ORACLE_MODE_HYBRID_AFTER_HOURS},
    oracle_v16,
    state::AssetOracleProfileV16,
};

fn hybrid_profile(soft_stale: u64, last_good: u64) -> AssetOracleProfileV16 {
    let mut p = AssetOracleProfileV16::default();
    p.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    p.hybrid_soft_stale_slots = soft_stale;
    p.last_good_oracle_slot = last_good;
    p
}

#[test]
fn q2_soft_stale_maturity_is_exact_and_disabled_at_zero() {
    let p = hybrid_profile(100, 1_000);
    // not matured at the boundary, matured one slot later
    assert!(!oracle_v16::profile_hybrid_soft_stale_matured(&p, 1_000));
    assert!(!oracle_v16::profile_hybrid_soft_stale_matured(&p, 1_100));
    assert!(oracle_v16::profile_hybrid_soft_stale_matured(&p, 1_101));
    // a clock that went backwards saturates to zero age: never matured
    assert!(!oracle_v16::profile_hybrid_soft_stale_matured(&p, 5));
    // 0 means "no soft-stale fallback": never matures, however old
    let off = hybrid_profile(0, 1_000);
    assert!(!oracle_v16::profile_hybrid_soft_stale_matured(&off, u64::MAX));
    // a non-Hybrid profile is never soft-stale-matured even with a value set
    let mut auth = hybrid_profile(100, 1_000);
    auth.oracle_mode = ORACLE_MODE_AUTH_MARK;
    assert!(!oracle_v16::profile_hybrid_soft_stale_matured(&auth, u64::MAX));
}

/// The engine function whose refusals the F1 follow-on must pre-screen.
fn engine_liquidate_body() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../percolator/src/v16.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("engine sibling source must be readable at {path:?}: {e}"));
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("pub fn liquidate_account_not_atomic("))
        .expect("engine liquidate_account_not_atomic must exist");
    let end = (start + 1..lines.len())
        .find(|&i| lines[i] == "    }")
        .expect("function end");
    lines[start..=end].join("\n")
}

fn tokens_after(body: &str, prefix: &str, then: Option<char>) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut rest = body;
    while let Some(i) = rest.find(prefix) {
        rest = &rest[i + prefix.len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let after = rest[name.len()..].chars().next();
        if !name.is_empty() && then.map_or(true, |t| after == Some(t)) {
            out.insert(name);
        }
    }
    out.into_iter().collect()
}

#[test]
fn q8_engine_liquidation_refusal_surface_is_pinned() {
    let body = engine_liquidate_body();

    // Every explicit error the function can return. Each is screened by `f1_follow_on_wanted`
    // (see `f1_refresh_liq_v22::F1Inputs`):
    //   BStale / Stale          -> b_stale + the certified-refresh precondition
    //   NonProgress             -> certified_liq_deficit != 0, shortfall_material, legs_reducible
    //                              (zero effective size / empty side = no unilateral close capacity)
    //   LockActive              -> live, legs_reducible (pending domain-loss barrier), mode != 0
    //   RecoveryRequired        -> declares Recovery (the intended Q3 valve; the instruction
    //                              commits it, it is not a reverting refusal)
    //   InvalidLeg / InvalidConfig / ArithmeticOverflow -> structural, not reachable from a
    //                              certified account with a materialized active leg
    let errors = tokens_after(&body, "V16Error::", None);
    assert_eq!(
        errors,
        [
            "ArithmeticOverflow",
            "BStale",
            "InvalidConfig",
            "InvalidLeg",
            "LockActive",
            "NonProgress",
            "RecoveryRequired",
            "Stale",
        ],
        "the engine's liquidate_account_not_atomic gained or lost an explicit refusal: review \
         `f1_follow_on_wanted` (src/v16_program.rs) and update this pin"
    );

    // Every fallible helper the function calls (each can add its own refusal). A new helper in
    // the liquidation path is a new potential refusal the follow-on has to screen.
    let mut helpers = tokens_after(&body, "self.", Some('('));
    helpers.extend(tokens_after(&body, "Self::", Some('(')));
    helpers.sort();
    helpers.dedup();
    assert_eq!(
        helpers,
        [
            "advance_close_progress_ledger",
            "asset_state",
            "begin_close_progress_ledger",
            "begin_zero_oi_residue_resets",
            "book_bankruptcy_residual_chunk_for_account_core",
            "certify_account_after_local_settlement_with_price_override",
            "charge_account_fee_after_full_refresh_not_atomic",
            // engine #299/#302 (a100d54d src/v16.rs liquidate_account_not_atomic ~21690-21760,
            // charge_recorded_domain_up_to_capacity ~23526). Reviewed against `f1_follow_on_wanted`
            // 2026-10-31: the explicit-error set above is unchanged; `domain_asset_side` /
            // `insurance_domain_index` refuse only InvalidLeg / ArithmeticOverflow (structural: the
            // closed leg is a materialized active leg, and a recorded domain is range-checked by
            // `validate_loss_provenance_for_market` at account load);
            // `liquidation_residual_exceeds_single_step_capacity` is the predicate
            // `preflight_liquidation_residual_durability` already ran (read-only);
            // `charge_recorded_domain_up_to_capacity` is composed only of helpers pinned in this
            // list (insurance, close-progress ledger, B chunk, set_account_pnl, h-lock) and declares
            // no Recovery. #302 REMOVES refusals (a locked flat close is resolved live, never
            // RecoveryRequired), so the follow-on screen needs no new input.
            "charge_recorded_domain_up_to_capacity",
            "consume_domain_insurance_for_negative_pnl",
            "declare_permissionless_recovery",
            "domain_asset_side",
            "insurance_domain_index",
            "liquidation_residual_exceeds_single_step_capacity",
            "mark_bankruptcy_hlock_event",
            "position_delta_touches_pending_domain_loss_barrier",
            "preflight_liquidation_residual_durability",
            "reduce_position",
            "refresh_account_and_certify_not_atomic",
            "require_active_leg_slot_for_asset",
            "require_asset_live_reducible",
            "risk_score_unchecked",
            "set_account_pnl",
            "settle_negative_pnl_from_principal_core_not_atomic",
            "try_clear_bankruptcy_hlock_if_healthy",
            "unilateral_close_capacity",
            "validate_account_audit_scan",
            "validate_account_scalar_preflight",
            "validate_liquidation_progress_from_score",
            "validate_shape_audit_scan",
            "x1_diff_charge",
        ],
        "the engine's liquidation path gained or lost a helper: review `f1_follow_on_wanted` and \
         update this pin"
    );
}

/// The census is only meaningful if it reads the SAME engine the wrapper builds against.
#[test]
fn q8_census_reads_a_real_engine_and_the_wrapper_screen_still_names_every_refusal_class() {
    let body = engine_liquidate_body();
    assert!(body.contains("fn liquidate_account_not_atomic"), "census must parse the function");
    assert!(body.lines().count() > 100, "census parsed a real body, not a stub");
    // the wrapper side of the pin: the screening inputs still exist in the decision kernel
    let kernel = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/f1_refresh_liq_v22.rs"),
    )
    .unwrap();
    for input in [
        "b_stale",
        "pending_close",
        "expired_close",
        "recovery_eligible",
        "resolved_winner",
        "legs_reducible",
        "live",
        "certified_liq_deficit",
    ] {
        assert!(
            kernel.contains(&format!("pub {input}:")),
            "F1Inputs lost the screening input `{input}`; the engine refusal list is no longer pinned"
        );
    }
}
