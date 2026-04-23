//! Tests for the three defense-in-depth gaps documented in DISCLOSURE.md.
//!
//! Scope: pure-function tests. Full-handler tests require a compiled program
//! and are deferred until the wrapper↔engine version drift is resolved
//! (see `issue.md` — toolchain pinning doc-nit).
//!
//! One happy path + one failing path per gap.

#![allow(clippy::too_many_arguments)]

use percolator_prog::verify::exec_price_within_band;

// =============================================================================
// Gap C — explicit band bound on matcher exec_price
// =============================================================================

/// Happy path: exec_price within the ±max(2·fee, 100 bps) band passes.
#[test]
fn gap_c_exec_price_within_band_accepts() {
    // Oracle = 1_000_000 (1.0 in e6 units). trading_fee_bps = 10 (0.10%).
    // band_bps = max(2·10, 100) = 100. max_delta = 10_000.
    let oracle = 1_000_000u64;
    let fee_bps = 10u64;
    // Exec at +0.5% of oracle = 1_005_000 — well within 1% band.
    assert!(exec_price_within_band(oracle, 1_005_000, fee_bps));
    // Exec at -1% of oracle (at edge) = 990_000 — accepted.
    assert!(exec_price_within_band(oracle, 990_000, fee_bps));
    // Exec equal to oracle — trivially within band.
    assert!(exec_price_within_band(oracle, 1_000_000, fee_bps));
}

/// Failing path: exec_price outside the band is rejected.
#[test]
fn gap_c_exec_price_outside_band_rejects() {
    let oracle = 1_000_000u64;
    let fee_bps = 10u64;
    // Exec at +2% of oracle = 1_020_000 — outside 1% band.
    assert!(!exec_price_within_band(oracle, 1_020_000, fee_bps));
    // Exec at -5% of oracle = 950_000 — outside 1% band.
    assert!(!exec_price_within_band(oracle, 950_000, fee_bps));
    // Attacker-extreme exec (oracle × 2) — rejected.
    assert!(!exec_price_within_band(oracle, 2_000_000, fee_bps));
}

/// Band scales with fee: at higher trading_fee_bps, the 2×fee floor raises.
#[test]
fn gap_c_band_scales_with_fee() {
    let oracle = 1_000_000u64;
    // fee = 500 bps (5%). band = max(2·500, 100) = 1000 bps (10%). max_delta = 100_000.
    // Exec at +5% of oracle (50_000 delta) — within 10% band.
    assert!(exec_price_within_band(oracle, 1_050_000, 500));
    // Exec at +10% (100_000 delta) — at edge, accepted.
    assert!(exec_price_within_band(oracle, 1_100_000, 500));
    // Exec at +11% (110_000 delta) — rejected.
    assert!(!exec_price_within_band(oracle, 1_110_000, 500));
}

/// Zero oracle rejects regardless of exec_price (band is undefined).
#[test]
fn gap_c_zero_oracle_rejects() {
    assert!(!exec_price_within_band(0, 1_000_000, 10));
    assert!(!exec_price_within_band(0, 0, 10));
}

// =============================================================================
// Gap A + Gap B — full-handler tests deferred
// =============================================================================
//
// Gap A's check sits inside `handle_init_market` (percolator.rs:6282+): the
// branch `if !is_hyperp && min_oracle_price_cap_e2bps == 0 { Err }` requires
// a compiled program to exercise via LiteSVM. Pattern-match to other
// init-rejection tests in `tests/test_oracle.rs` (e.g.
// `test_hyperp_rejects_zero_initial_mark_price`) for the template.
//
// Gap B's check sits inside `read_engine_price_e6_with_pin`. The pin is set
// at InitMarket and validated on every oracle-consuming instruction. Happy
// path: oracle account pubkey matches `config.expected_oracle_pubkey`.
// Failing path: a caller-substituted ephemeral PriceUpdateV2 with matching
// feed_id but different pubkey is rejected with `InvalidOracleKey`. Both
// tests require a compiled program — see `tests/test_oracle.rs`.
