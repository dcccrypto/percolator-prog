// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Fork-bundle adversarial tests against the v16 baseline.
//!
//! Each `#[test]` here belongs to a specific Phase 2.B fork-feature bundle
//! (B-1 .. B-21 per `~/wrapper-engine-deep-audit/FORK_FEATURE_INVENTORY.md`)
//! that the fork adds on top of upstream v16. Tests are tagged with their
//! bundle ID in the function name. Adding to this file is intentionally
//! easier than touching `tests/v16_wrapper.rs` (upstream-imported, prone
//! to merge conflicts on weekly rolling-tip syncs).
//!
//! Coverage by bundle (updated as bundles land):
//! - **B-11** Oracle staleness cap (MAX_ORACLE_STALENESS_SECS = 86_400)

use percolator::MAX_ORACLE_PRICE;
use percolator_prog::{
    constants::{
        DEFAULT_MARK_EWMA_HALFLIFE_SLOTS, MAX_ORACLE_STALENESS_SECS, ORACLE_LEG_CAP,
        ORACLE_MODE_HYBRID_AFTER_HOURS,
    },
    state::{validate_asset_oracle_profile, AssetOracleProfileV16},
};

/// Helper: minimal valid HYBRID_AFTER_HOURS profile with one oracle leg.
/// Tests below tweak `max_staleness_secs` to exercise B-11 bound.
fn hybrid_profile(max_staleness_secs: u64) -> AssetOracleProfileV16 {
    AssetOracleProfileV16 {
        oracle_mode: ORACLE_MODE_HYBRID_AFTER_HOURS,
        oracle_leg_count: 1,
        oracle_leg_flags: 0,
        invert: 0,
        unit_scale: 0,
        conf_filter_bps: 0,
        backing_trade_fee_bps_long: 0,
        backing_trade_fee_bps_short: 0,
        backing_trade_fee_insurance_share_bps_long: 0,
        backing_trade_fee_insurance_share_bps_short: 0,
        _padding0: [0u8; 6],
        insurance_authority: [0u8; 32],
        insurance_operator: [0u8; 32],
        backing_bucket_authority: [0u8; 32],
        oracle_authority: [0u8; 32],
        max_staleness_secs,
        hybrid_soft_stale_slots: 5,
        mark_ewma_e6: MAX_ORACLE_PRICE,
        mark_ewma_last_slot: 1,
        mark_ewma_halflife_slots: DEFAULT_MARK_EWMA_HALFLIFE_SLOTS,
        mark_min_fee: 0,
        oracle_target_price_e6: MAX_ORACLE_PRICE,
        oracle_target_publish_time: 0,
        last_good_oracle_slot: 1,
        oracle_leg_feeds: {
            let mut f = [[0u8; 32]; ORACLE_LEG_CAP];
            f[0] = [7u8; 32];
            f
        },
        oracle_leg_prices_e6: [0u64; ORACLE_LEG_CAP],
        oracle_leg_publish_times: [0i64; ORACLE_LEG_CAP],
        // v17: per-asset cold-storage admin key (collision matrix row N/A).
        asset_admin: [0u8; 32],
        creator_fee_claimable_atoms: 0,
        maintenance_fee_checkpoint_slot: 0,
        maintenance_fee_previous_rate: 0,
    }
}

/// B-11: HYBRID profile with staleness AT the cap is accepted.
#[test]
fn b11_hybrid_profile_accepts_max_staleness_at_cap() {
    let profile = hybrid_profile(MAX_ORACLE_STALENESS_SECS);
    assert!(
        validate_asset_oracle_profile(&profile).is_ok(),
        "B-11: max_staleness_secs == MAX_ORACLE_STALENESS_SECS must validate"
    );
}

/// B-11: HYBRID profile with staleness ABOVE the cap is rejected. This is
/// the additive fork tightening over v16 baseline (which had no upper
/// bound). Without this check, an operator could configure unbounded
/// oracle staleness, loosening every trade / mark / liquidation gate.
#[test]
fn b11_hybrid_profile_rejects_max_staleness_above_cap() {
    let profile = hybrid_profile(MAX_ORACLE_STALENESS_SECS + 1);
    assert!(
        validate_asset_oracle_profile(&profile).is_err(),
        "B-11: max_staleness_secs > MAX_ORACLE_STALENESS_SECS must be rejected"
    );
}

/// B-11: HYBRID profile with staleness at the fork's typical setting (60s)
/// must remain valid — proof the cap doesn't accidentally regress small
/// staleness configurations.
#[test]
fn b11_hybrid_profile_accepts_typical_staleness() {
    let profile = hybrid_profile(60);
    assert!(
        validate_asset_oracle_profile(&profile).is_ok(),
        "B-11: typical max_staleness_secs (60) must validate"
    );
}

/// B-11: HYBRID profile with staleness = 0 is rejected (v16 baseline rule,
/// preserved through fork tightening).
#[test]
fn b11_hybrid_profile_rejects_max_staleness_zero() {
    let profile = hybrid_profile(0);
    assert!(
        validate_asset_oracle_profile(&profile).is_err(),
        "B-11: max_staleness_secs == 0 must be rejected (v16 baseline rule)"
    );
}

/// B-11: HYBRID profile with grossly-excessive staleness (u64::MAX) is
/// rejected. Adversarial sanity: any sane upper bound must hold here.
#[test]
fn b11_hybrid_profile_rejects_max_staleness_u64_max() {
    let profile = hybrid_profile(u64::MAX);
    assert!(
        validate_asset_oracle_profile(&profile).is_err(),
        "B-11: u64::MAX max_staleness_secs must be rejected"
    );
}
