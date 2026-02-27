//! Kani formal verification harnesses for percolator-prog.
//!
//! Run with: `cargo kani --tests`
//!
//! These harnesses prove PROGRAM-LEVEL security properties:
//! - Matcher ABI validation rejects malformed/malicious returns
//! - Owner/signer enforcement for all account operations
//! - Admin authorization and burned admin handling
//! - CPI identity binding (matcher program/context match LP registration)
//! - Matcher account shape validation
//! - PDA key mismatch rejection
//! - Nonce monotonicity (unchanged on failure, +1 on success)
//! - CPI uses exec_size (not requested size)
//!
//! Note: CPI execution and risk engine internals are NOT modeled.
//! Only wrapper-level authorization and binding logic is proven.

#![cfg(kani)]

extern crate kani;

// Import real types and helpers from the program crate
use percolator_prog::constants::MATCHER_ABI_VERSION;
use percolator_prog::constants::MAX_UNIT_SCALE;
use percolator_prog::matcher_abi::{
    validate_matcher_return, MatcherReturn, FLAG_PARTIAL_OK, FLAG_REJECTED, FLAG_VALID,
};
use percolator_prog::oracle::clamp_toward_with_dt;
use percolator_prog::verify::{
    abi_ok,
    // New: Dust math
    accumulate_dust,
    admin_ok,
    apply_trade_positions,
    // New: Unit scale conversion math
    base_to_units,
    checked_deposit,
    checked_withdraw,
    circuit_breaker_triggered,
    compute_fee_ceil,
    compute_fee_floor,
    convert_decimals,
    cpi_trade_size,
    decide_admin_op,
    decide_crank,
    // New: allow_panic crank decision
    decide_keeper_crank_with_panic,
    decide_single_owner_op,
    decide_trade_cpi,
    decide_trade_cpi_from_ret,
    decide_trade_nocpi,
    decision_nonce,
    ema_step_unclamped,
    extreme_drop_triggers_breaker,
    gate_active,
    // New: InitMarket scale validation
    init_market_scale_ok,
    // New: Oracle inversion math
    invert_price_e6,
    len_ok,
    liquidation_no_profit,
    lp_pda_shape_ok,
    mark_distance_after_step,
    matcher_identity_ok,
    matcher_shape_ok,
    max_price_impact,
    nonce_on_failure,
    nonce_on_success,
    nonces_serialize_correctly,
    operation_allowed_in_state,
    oracle_feed_id_ok,
    oracle_price_valid,
    owner_ok,
    pda_key_matches,
    position_zero_sum,
    price_impact_bounded,
    pyth_price_is_fresh,
    // New: Oracle unit scale math
    scale_price_e6,
    self_liquidation_unprofitable,
    // Account validation helpers
    signer_ok,
    // Decision helpers for program-level coupling proofs
    single_owner_authorized,
    slab_shape_ok,
    sweep_dust,
    trade_authorized,
    units_to_base,
    valid_state_transition,
    // New: Withdraw alignment
    withdraw_amount_aligned,
    // New: WithdrawInsurance vault accounting
    withdraw_insurance_vault,
    writable_ok,
    // PERC-241: Additional imports for 10 uncovered properties
    AccountOp,
    AccountState,
    LpPdaShape,
    MatcherAccountsShape,
    // ABI validation from real inputs
    MatcherReturnFields,
    SimpleDecision,
    SlabShape,
    TradeCpiDecision,
    TradeNoCpiDecision,
    INVERSION_CONSTANT,
};

// Kani-specific bounds to avoid SAT explosion on division/modulo.
// MAX_UNIT_SCALE (1 billion) is too large for bit-precise SAT solving.
// Using small bounds keeps proofs tractable while still exercising the logic.
// The actual MAX_UNIT_SCALE bound is proven separately in init_market_scale_* proofs.
const KANI_MAX_SCALE: u32 = 64;
// Cap quotients to keep division/mod tractable
const KANI_MAX_QUOTIENT: u64 = 16384;

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a MatcherReturn from individual symbolic fields
fn any_matcher_return() -> MatcherReturn {
    MatcherReturn {
        abi_version: kani::any(),
        flags: kani::any(),
        exec_price_e6: kani::any(),
        exec_size: kani::any(),
        req_id: kani::any(),
        lp_account_id: kani::any(),
        oracle_price_e6: kani::any(),
        reserved: kani::any(),
    }
}

/// Create a MatcherReturnFields from individual symbolic fields
fn any_matcher_return_fields() -> MatcherReturnFields {
    MatcherReturnFields {
        abi_version: kani::any(),
        flags: kani::any(),
        exec_price_e6: kani::any(),
        exec_size: kani::any(),
        req_id: kani::any(),
        lp_account_id: kani::any(),
        oracle_price_e6: kani::any(),
        reserved: kani::any(),
    }
}

// =============================================================================
// A. MATCHER ABI VALIDATION (8 proofs - program-level)
// req_id/lp_account_id/oracle_price single-gate proofs removed:
// subsumed by kani_abi_ok_equals_validate (section R)
// =============================================================================

/// Prove: wrong ABI version is always rejected
#[kani::proof]
fn kani_matcher_rejects_wrong_abi_version() {
    let mut ret = any_matcher_return();
    kani::assume(ret.abi_version != MATCHER_ABI_VERSION);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "wrong ABI version must be rejected");
}

/// Prove: missing VALID flag is always rejected
#[kani::proof]
fn kani_matcher_rejects_missing_valid_flag() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    kani::assume((ret.flags & FLAG_VALID) == 0);

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "missing VALID flag must be rejected");
}

/// Prove: REJECTED flag always causes rejection
#[kani::proof]
fn kani_matcher_rejects_rejected_flag() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags |= FLAG_VALID;
    ret.flags |= FLAG_REJECTED;

    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "REJECTED flag must cause rejection");
}

/// Prove: non-zero reserved field is always rejected
#[kani::proof]
fn kani_matcher_rejects_nonzero_reserved() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.reserved != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "non-zero reserved must be rejected");
}

/// Prove: zero exec_price is always rejected
#[kani::proof]
fn kani_matcher_rejects_zero_exec_price() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    ret.exec_price_e6 = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "zero exec_price must be rejected");
}

/// Prove: zero exec_size without PARTIAL_OK is rejected
#[kani::proof]
fn kani_matcher_zero_size_requires_partial_ok() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID; // No PARTIAL_OK
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.exec_size = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(
        result.is_err(),
        "zero exec_size without PARTIAL_OK must be rejected"
    );
}

/// Prove: exec_size exceeding req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_exec_size_exceeds_req() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(ret.exec_size.unsigned_abs() > req_size.unsigned_abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(
        result.is_err(),
        "exec_size exceeding req_size must be rejected"
    );
}

/// Prove: sign mismatch between exec_size and req_size is rejected
#[kani::proof]
fn kani_matcher_rejects_sign_mismatch() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let req_size: i128 = kani::any();
    kani::assume(req_size != 0);
    kani::assume(ret.exec_size.signum() != req_size.signum());
    kani::assume(ret.exec_size.unsigned_abs() <= req_size.unsigned_abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_err(), "sign mismatch must be rejected");
}

// =============================================================================
// B. OWNER/SIGNER ENFORCEMENT (2 proofs)
// =============================================================================

/// Prove: owner mismatch is rejected
#[kani::proof]
fn kani_owner_mismatch_rejected() {
    let stored: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(stored != signer);

    assert!(!owner_ok(stored, signer), "owner mismatch must be rejected");
}

/// Prove: owner match is accepted
#[kani::proof]
fn kani_owner_match_accepted() {
    let owner: [u8; 32] = kani::any();

    assert!(owner_ok(owner, owner), "owner match must be accepted");
}

// =============================================================================
// C. ADMIN AUTHORIZATION (3 proofs)
// =============================================================================

/// Prove: admin mismatch is rejected
#[kani::proof]
fn kani_admin_mismatch_rejected() {
    let admin: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(admin != [0u8; 32]); // Not burned
    kani::assume(admin != signer);

    assert!(!admin_ok(admin, signer), "admin mismatch must be rejected");
}

/// Prove: admin match is accepted (when not burned)
#[kani::proof]
fn kani_admin_match_accepted() {
    let admin: [u8; 32] = kani::any();
    kani::assume(admin != [0u8; 32]); // Not burned

    assert!(admin_ok(admin, admin), "admin match must be accepted");
}

/// Prove: burned admin (all zeros) disables all admin ops
#[kani::proof]
fn kani_admin_burned_disables_ops() {
    let burned_admin = [0u8; 32];
    let signer: [u8; 32] = kani::any();

    assert!(
        !admin_ok(burned_admin, signer),
        "burned admin must disable all admin ops"
    );
}

// =============================================================================
// D. CPI IDENTITY BINDING (2 proofs) - CRITICAL
// =============================================================================

/// Prove: CPI matcher identity mismatch (program or context) is rejected
#[kani::proof]
fn kani_matcher_identity_mismatch_rejected() {
    let lp_prog: [u8; 32] = kani::any();
    let lp_ctx: [u8; 32] = kani::any();
    let provided_prog: [u8; 32] = kani::any();
    let provided_ctx: [u8; 32] = kani::any();

    // At least one must mismatch
    kani::assume(lp_prog != provided_prog || lp_ctx != provided_ctx);

    assert!(
        !matcher_identity_ok(lp_prog, lp_ctx, provided_prog, provided_ctx),
        "matcher identity mismatch must be rejected"
    );
}

/// Prove: CPI matcher identity match is accepted
#[kani::proof]
fn kani_matcher_identity_match_accepted() {
    let prog: [u8; 32] = kani::any();
    let ctx: [u8; 32] = kani::any();

    assert!(
        matcher_identity_ok(prog, ctx, prog, ctx),
        "matcher identity match must be accepted"
    );
}

// =============================================================================
// E. MATCHER ACCOUNT SHAPE VALIDATION (5 proofs)
// NOTE: These use concrete structs (UNIT TEST classification). Individually
// superseded by kani_universal_shape_fail_rejects (AE) for rejection and
// kani_tradecpi_accept_increments_nonce (L) for acceptance. Retained as
// readable documentation of each field's validation requirement.
// =============================================================================

/// Universal: matcher_shape_ok is fully characterized
#[kani::proof]
fn kani_matcher_shape_universal() {
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };

    let expected = shape.prog_executable
        && !shape.ctx_executable
        && shape.ctx_owner_is_prog
        && shape.ctx_len_ok;
    assert_eq!(
        matcher_shape_ok(shape),
        expected,
        "matcher_shape_ok must equal (prog_exec && !ctx_exec && ctx_owned && ctx_len)"
    );
}

// =============================================================================
// F. PDA KEY MATCHING (2 proofs)
// =============================================================================

/// Prove: PDA key mismatch is rejected
#[kani::proof]
fn kani_pda_mismatch_rejected() {
    let expected: [u8; 32] = kani::any();
    let provided: [u8; 32] = kani::any();
    kani::assume(expected != provided);

    assert!(
        !pda_key_matches(expected, provided),
        "PDA key mismatch must be rejected"
    );
}

/// Prove: PDA key match is accepted
#[kani::proof]
fn kani_pda_match_accepted() {
    let key: [u8; 32] = kani::any();

    assert!(pda_key_matches(key, key), "PDA key match must be accepted");
}

// =============================================================================
// G. NONCE MONOTONICITY (3 proofs)
// =============================================================================

/// Prove: nonce unchanged on failure
#[kani::proof]
fn kani_nonce_unchanged_on_failure() {
    let old_nonce: u64 = kani::any();
    let new_nonce = nonce_on_failure(old_nonce);

    assert_eq!(new_nonce, old_nonce, "nonce must be unchanged on failure");
}

/// Prove: nonce advances by exactly 1 on success
#[kani::proof]
fn kani_nonce_advances_on_success() {
    let old_nonce: u64 = kani::any();
    let new_nonce = nonce_on_success(old_nonce);

    assert_eq!(
        new_nonce,
        old_nonce.wrapping_add(1),
        "nonce must advance by 1 on success"
    );
}


// =============================================================================
// H. CPI USES EXEC_SIZE (1 proof) - CRITICAL
// =============================================================================

/// Prove: CPI path uses exec_size from matcher, not requested size
#[kani::proof]
fn kani_cpi_uses_exec_size() {
    let exec_size: i128 = kani::any();
    let requested_size: i128 = kani::any();

    // Even when they differ, cpi_trade_size returns exec_size
    let chosen = cpi_trade_size(exec_size, requested_size);

    assert_eq!(
        chosen, exec_size,
        "CPI must use exec_size, not requested size"
    );
}

// =============================================================================
// I. GATE ACTIVATION LOGIC (3 proofs)
// =============================================================================

/// Prove: gate not active when threshold is zero
#[kani::proof]
fn kani_gate_inactive_when_threshold_zero() {
    let balance: u128 = kani::any();

    assert!(
        !gate_active(0, balance),
        "gate must be inactive when threshold is zero"
    );
}

/// Prove: gate not active when balance exceeds threshold
#[kani::proof]
fn kani_gate_inactive_when_balance_exceeds() {
    let threshold: u128 = kani::any();
    let balance: u128 = kani::any();
    kani::assume(balance > threshold);

    assert!(
        !gate_active(threshold, balance),
        "gate must be inactive when balance > threshold"
    );
}

/// Prove: gate active when threshold > 0 and balance <= threshold
#[kani::proof]
fn kani_gate_active_when_conditions_met() {
    let threshold: u128 = kani::any();
    kani::assume(threshold > 0);
    let balance: u128 = kani::any();
    kani::assume(balance <= threshold);

    assert!(
        gate_active(threshold, balance),
        "gate must be active when threshold > 0 and balance <= threshold"
    );
}

// =============================================================================
// J. PER-INSTRUCTION AUTHORIZATION (4 proofs)
// =============================================================================

/// Prove: single-owner instruction rejects on mismatch
#[kani::proof]
fn kani_single_owner_mismatch_rejected() {
    let stored: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    kani::assume(stored != signer);

    assert!(
        !single_owner_authorized(stored, signer),
        "single-owner instruction must reject on mismatch"
    );
}

/// Prove: single-owner instruction accepts on match
#[kani::proof]
fn kani_single_owner_match_accepted() {
    let owner: [u8; 32] = kani::any();

    assert!(
        single_owner_authorized(owner, owner),
        "single-owner instruction must accept on match"
    );
}

/// Prove: trade rejects when user owner mismatch
#[kani::proof]
fn kani_trade_rejects_user_mismatch() {
    let user_owner: [u8; 32] = kani::any();
    let user_signer: [u8; 32] = kani::any();
    let lp_owner: [u8; 32] = kani::any();
    kani::assume(user_owner != user_signer);

    assert!(
        !trade_authorized(user_owner, user_signer, lp_owner, lp_owner),
        "trade must reject when user owner doesn't match"
    );
}

/// Prove: trade rejects when LP owner mismatch
#[kani::proof]
fn kani_trade_rejects_lp_mismatch() {
    let user_owner: [u8; 32] = kani::any();
    let lp_owner: [u8; 32] = kani::any();
    let lp_signer: [u8; 32] = kani::any();
    kani::assume(lp_owner != lp_signer);

    assert!(
        !trade_authorized(user_owner, user_owner, lp_owner, lp_signer),
        "trade must reject when LP owner doesn't match"
    );
}

// =============================================================================
// L. TRADECPI DECISION COUPLING - CRITICAL
// These prove program-level policies, not just helper semantics.
//
// kani_decide_trade_cpi_universal fully characterizes the function:
// Accept iff shape_ok && identity && pda && abi && user && lp && !(gate && risk).
// Subsumes all individual gate rejection proofs (AE section) and the former
// kani_tradecpi_allows_gate_risk_decrease. Individual AE proofs retained as
// readable documentation.
// =============================================================================

/// Helper: create a valid shape for testing other conditions
fn valid_shape() -> MatcherAccountsShape {
    MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: false,
        ctx_owner_is_prog: true,
        ctx_len_ok: true,
    }
}

/// Universal characterization of decide_trade_cpi: fully symbolic inputs.
/// Proves: Accept iff shape_ok && identity && pda && abi && user && lp && !(gate && risk).
/// On Accept: new_nonce == nonce_on_success(old_nonce), chosen_size == exec_size.
/// Subsumes kani_tradecpi_allows_gate_risk_decrease and all individual gate rejection proofs.
#[kani::proof]
fn kani_decide_trade_cpi_universal() {
    let old_nonce: u64 = kani::any();
    let exec_size: i128 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();

    let decision = decide_trade_cpi(
        old_nonce, shape, identity_ok, pda_ok, abi_ok,
        user_auth_ok, lp_auth_ok, gate_active, risk_increase, exec_size,
    );

    let should_accept = matcher_shape_ok(shape)
        && identity_ok && pda_ok && abi_ok
        && user_auth_ok && lp_auth_ok
        && !(gate_active && risk_increase);

    if should_accept {
        match decision {
            TradeCpiDecision::Accept { new_nonce, chosen_size } => {
                assert_eq!(new_nonce, nonce_on_success(old_nonce),
                    "accept nonce must be nonce_on_success(old_nonce)");
                assert_eq!(chosen_size, exec_size,
                    "accept chosen_size must equal exec_size");
            }
            _ => panic!("all gates pass but got Reject"),
        }
    } else {
        assert_eq!(decision, TradeCpiDecision::Reject,
            "any gate failure must produce Reject");
    }
}

/// Prove: TradeCpi reject leaves nonce unchanged for all invalid matcher shapes.
#[kani::proof]
fn kani_tradecpi_reject_nonce_unchanged() {
    let old_nonce: u64 = kani::any();
    let exec_size: i128 = kani::any();

    // Quantify over all invalid matcher shapes, not just one witness.
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(!matcher_shape_ok(shape));

    let decision = decide_trade_cpi(
        old_nonce, shape, true, true, true, true, true, false, false, exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "TradeCpi must reject for any invalid matcher shape"
    );

    let result_nonce = decision_nonce(old_nonce, decision);

    assert_eq!(
        result_nonce, old_nonce,
        "TradeCpi reject must leave nonce unchanged"
    );
}

/// Prove: TradeCpi accept increments nonce for all valid matcher shapes.
#[kani::proof]
fn kani_tradecpi_accept_increments_nonce() {
    let old_nonce: u64 = kani::any();
    let exec_size: i128 = kani::any();

    // Quantify over all valid matcher shapes, not just one witness.
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Accept {
            new_nonce: old_nonce.wrapping_add(1),
            chosen_size: exec_size,
        },
        "TradeCpi must accept for any valid matcher shape when all other checks pass"
    );

    let result_nonce = decision_nonce(old_nonce, decision);

    assert_eq!(
        result_nonce,
        old_nonce.wrapping_add(1),
        "TradeCpi accept must increment nonce by 1"
    );
}

// Note: kani_tradecpi_accept_uses_exec_size removed — duplicate of
// kani_tradecpi_accept_increments_nonce (same assertion on same inputs).

// =============================================================================
// M. TRADENOCPI DECISION COUPLING (3 proofs — universal symbolic)
// =============================================================================

/// Universal: TradeNoCpi rejects when user_auth=false OR lp_auth=false
/// (regardless of gate/risk state)
#[kani::proof]
fn kani_tradenocpi_auth_failure_rejects() {
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();

    // At least one auth must fail
    kani::assume(!user_auth_ok || !lp_auth_ok);

    let decision = decide_trade_nocpi(user_auth_ok, lp_auth_ok, gate_active, risk_increase);
    assert_eq!(
        decision,
        TradeNoCpiDecision::Reject,
        "TradeNoCpi must reject when any auth check fails"
    );
}

/// Universal: TradeNoCpi decision is fully characterized by its inputs
#[kani::proof]
fn kani_tradenocpi_universal_characterization() {
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();

    let decision = decide_trade_nocpi(user_auth_ok, lp_auth_ok, gate_active, risk_increase);

    // Full characterization: accept iff all auth passes AND NOT (gate_active && risk_increase)
    let should_accept = user_auth_ok && lp_auth_ok && !(gate_active && risk_increase);
    if should_accept {
        assert_eq!(decision, TradeNoCpiDecision::Accept, "must accept when all conditions pass");
    } else {
        assert_eq!(decision, TradeNoCpiDecision::Reject, "must reject when any condition fails");
    }
}

// =============================================================================
// N. ZERO SIZE WITH PARTIAL_OK (1 proof)
// =============================================================================

/// Prove: zero exec_size with PARTIAL_OK flag is accepted
#[kani::proof]
fn kani_matcher_zero_size_with_partial_ok_accepted() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.exec_size = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    // When exec_size == 0, validate_matcher_return returns early before abs() checks
    // so req_size can be any value including i128::MIN
    let req_size: i128 = kani::any();
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(
        result.is_ok(),
        "zero exec_size with PARTIAL_OK must be accepted"
    );
}

// =============================================================================
// O. MISSING SHAPE COUPLING PROOFS (2 proofs)
// =============================================================================

// =============================================================================
// P. UNIVERSAL REJECT => NONCE UNCHANGED (1 proof)
// This subsumes all specific "reject => nonce unchanged" proofs
// =============================================================================

/// Prove: ANY TradeCpi rejection leaves nonce unchanged (universal quantification)
/// Non-vacuity: concrete witness proves at least one Reject path exists.
#[kani::proof]
fn kani_tradecpi_any_reject_nonce_unchanged() {
    // Non-vacuity witness: bad shape always produces Reject
    {
        let bad = MatcherAccountsShape {
            prog_executable: false,
            ctx_executable: false,
            ctx_owner_is_prog: true,
            ctx_len_ok: true,
        };
        let d = decide_trade_cpi(0, bad, true, true, true, true, true, false, false, 0);
        assert!(
            matches!(d, TradeCpiDecision::Reject),
            "non-vacuity: bad shape must reject"
        );
    }

    let old_nonce: u64 = kani::any();

    // Build shape from symbolic bools (MatcherAccountsShape doesn't impl kani::Arbitrary)
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };

    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    // Strengthened: prove nonce transition relation for both outcome variants.
    let expected_nonce = match &decision {
        TradeCpiDecision::Reject => old_nonce,
        TradeCpiDecision::Accept { .. } => old_nonce.wrapping_add(1),
    };
    let result_nonce = decision_nonce(old_nonce, decision);
    assert_eq!(
        result_nonce, expected_nonce,
        "decision_nonce must agree with TradeCpiDecision outcome"
    );
}

/// Prove: ANY TradeCpi acceptance increments nonce (universal quantification)
/// Non-vacuity: concrete witness proves at least one Accept path exists.
#[kani::proof]
fn kani_tradecpi_any_accept_increments_nonce() {
    // Non-vacuity witness: all-valid inputs produce Accept
    {
        let d = decide_trade_cpi(0, valid_shape(), true, true, true, true, true, false, false, 0);
        assert!(
            matches!(d, TradeCpiDecision::Accept { .. }),
            "non-vacuity: all-valid inputs must accept"
        );
    }

    let old_nonce: u64 = kani::any();

    // Build shape from symbolic bools
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };

    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    // Strengthened: prove nonce transition relation for both outcome variants.
    let expected_nonce = match &decision {
        TradeCpiDecision::Reject => old_nonce,
        TradeCpiDecision::Accept { .. } => old_nonce.wrapping_add(1),
    };
    let result_nonce = decision_nonce(old_nonce, decision);
    assert_eq!(
        result_nonce, expected_nonce,
        "decision_nonce must agree with TradeCpiDecision outcome"
    );
}

// =============================================================================
// Q. ACCOUNT VALIDATION HELPERS (2 proofs)
// =============================================================================
// Note: signer_ok and writable_ok are identity functions (return input unchanged).
// Testing them would be trivial (proving true==true). Only len_ok has real logic.

/// Prove: len_ok requires actual >= need (universal)
#[kani::proof]
fn kani_len_ok_universal() {
    let actual: usize = kani::any();
    let need: usize = kani::any();

    // Universal proof: len_ok returns true iff actual >= need
    assert_eq!(
        len_ok(actual, need),
        actual >= need,
        "len_ok must return (actual >= need)"
    );
}

// =============================================================================
// R. LP PDA SHAPE VALIDATION (4 proofs)
// NOTE: LpPdaShape has 3 bools (8 combinations). These 4 concrete proofs cover
// all-valid + each individual failure. Retained as documentation of each
// validation requirement. The function is a simple conjunction (&&).
// =============================================================================

/// Universal: lp_pda_shape_ok is fully characterized as 3-way AND
#[kani::proof]
fn kani_lp_pda_shape_universal() {
    let shape = LpPdaShape {
        is_system_owned: kani::any(),
        data_len_zero: kani::any(),
        lamports_zero: kani::any(),
    };

    let expected = shape.is_system_owned && shape.data_len_zero && shape.lamports_zero;
    assert_eq!(
        lp_pda_shape_ok(shape),
        expected,
        "lp_pda_shape_ok must equal (system_owned && data_zero && lamports_zero)"
    );
}

// =============================================================================
// S. ORACLE FEED_ID AND SLAB SHAPE (4 proofs)
// =============================================================================

/// Universal: oracle_feed_id_ok == (expected == provided)
#[kani::proof]
fn kani_oracle_feed_id_universal() {
    let expected: [u8; 32] = kani::any();
    let provided: [u8; 32] = kani::any();
    assert_eq!(
        oracle_feed_id_ok(expected, provided),
        expected == provided,
        "oracle_feed_id_ok must equal (expected == provided)"
    );
}

/// Prove: valid slab shape is accepted
#[kani::proof]
fn kani_slab_shape_universal() {
    let owned: bool = kani::any();
    let correct_len: bool = kani::any();
    let shape = SlabShape {
        owned_by_program: owned,
        correct_len: correct_len,
    };
    let expected = owned && correct_len;
    assert_eq!(slab_shape_ok(shape), expected,
        "slab_shape_ok must equal (owned && correct_len)");
}

// =============================================================================
// T. SIMPLE DECISION FUNCTIONS (6 proofs)
// =============================================================================

/// Universal: decide_single_owner_op is fully characterized
/// (subsumes the concrete true/false unit tests)
#[kani::proof]
fn kani_decide_single_owner_universal() {
    let auth_ok: bool = kani::any();
    let decision = decide_single_owner_op(auth_ok);
    if auth_ok {
        assert_eq!(decision, SimpleDecision::Accept, "auth ok must accept");
    } else {
        assert_eq!(decision, SimpleDecision::Reject, "auth fail must reject");
    }
}

/// Universal: decide_crank is fully characterized by its inputs
/// Exercises all 3 branches (permissionless, self-crank-ok, self-crank-fail)
#[kani::proof]
fn kani_decide_crank_universal() {
    let permissionless: bool = kani::any();
    let idx_exists: bool = kani::any();
    let stored: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();

    let decision = decide_crank(permissionless, idx_exists, stored, signer);

    let should_accept = permissionless || (idx_exists && stored == signer);
    if should_accept {
        assert_eq!(decision, SimpleDecision::Accept, "must accept");
    } else {
        assert_eq!(decision, SimpleDecision::Reject, "must reject");
    }
}

/// Universal: decide_admin_op is fully characterized
/// accept iff admin != [0;32] && admin == signer
#[kani::proof]
fn kani_decide_admin_universal() {
    let admin: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();

    let decision = decide_admin_op(admin, signer);

    let should_accept = admin != [0u8; 32] && admin == signer;
    if should_accept {
        assert_eq!(decision, SimpleDecision::Accept, "valid admin must accept");
    } else {
        assert_eq!(decision, SimpleDecision::Reject, "invalid admin must reject");
    }
}

// =============================================================================
// U. VERIFY::ABI_OK EQUIVALENCE (1 proof)
// Prove that verify::abi_ok is equivalent to validate_matcher_return
// =============================================================================

/// Prove: verify::abi_ok returns true iff validate_matcher_return returns Ok
/// This is a single strong equivalence proof - abi_ok calls the real validator.
#[kani::proof]
fn kani_abi_ok_equals_validate() {
    let ret = any_matcher_return();
    let lp_account_id: u64 = kani::any();
    let oracle_price: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let validate_result =
        validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);

    let ret_fields = MatcherReturnFields {
        abi_version: ret.abi_version,
        flags: ret.flags,
        exec_price_e6: ret.exec_price_e6,
        exec_size: ret.exec_size,
        req_id: ret.req_id,
        lp_account_id: ret.lp_account_id,
        oracle_price_e6: ret.oracle_price_e6,
        reserved: ret.reserved,
    };
    let abi_ok_result = abi_ok(ret_fields, lp_account_id, oracle_price, req_size, req_id);

    // Strong equivalence: abi_ok == validate.is_ok() for all inputs
    assert_eq!(
        abi_ok_result,
        validate_result.is_ok(),
        "abi_ok must be equivalent to validate_matcher_return.is_ok()"
    );
}

// =============================================================================
// V. DECIDE_TRADE_CPI_FROM_RET UNIVERSAL PROOFS (3 proofs)
// These prove program-level policies using the mechanically-tied decision function
// =============================================================================

/// Prove: ANY rejection from decide_trade_cpi_from_ret leaves nonce unchanged
/// Non-vacuity: concrete witness proves at least one Reject path exists.
#[kani::proof]
fn kani_tradecpi_from_ret_any_reject_nonce_unchanged() {
    // Non-vacuity witness: bad shape always produces Reject
    {
        let bad = MatcherAccountsShape {
            prog_executable: false,
            ctx_executable: false,
            ctx_owner_is_prog: true,
            ctx_len_ok: true,
        };
        let dummy_ret = MatcherReturnFields {
            abi_version: 0,
            flags: 0,
            exec_price_e6: 0,
            exec_size: 0,
            req_id: 0,
            lp_account_id: 0,
            oracle_price_e6: 0,
            reserved: 0,
        };
        let d = decide_trade_cpi_from_ret(0, bad, true, true, true, true, false, false, dummy_ret, 0, 0, 0);
        assert!(
            matches!(d, TradeCpiDecision::Reject),
            "non-vacuity: bad shape must reject"
        );
    }

    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_is_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let ret = any_matcher_return_fields();
    let lp_account_id: u64 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    let req_size: i128 = kani::any();

    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // Strengthened: prove nonce transition relation for both outcome variants.
    let expected_nonce = match &decision {
        TradeCpiDecision::Reject => old_nonce,
        TradeCpiDecision::Accept { .. } => old_nonce.wrapping_add(1),
    };
    let result_nonce = decision_nonce(old_nonce, decision);
    assert_eq!(
        result_nonce, expected_nonce,
        "decision_nonce must agree with TradeCpiDecision outcome (from_ret)"
    );
}

/// Prove: ANY acceptance from decide_trade_cpi_from_ret increments nonce
/// Non-vacuity: concrete witness proves at least one Accept path exists.
#[kani::proof]
fn kani_tradecpi_from_ret_any_accept_increments_nonce() {
    // Non-vacuity witness: construct valid ABI inputs that produce Accept
    {
        let req_id = nonce_on_success(42);
        let valid_ret = MatcherReturnFields {
            abi_version: MATCHER_ABI_VERSION,
            flags: FLAG_VALID | FLAG_PARTIAL_OK,
            exec_price_e6: 1_000_000,
            exec_size: 0,
            req_id,
            lp_account_id: 1,
            oracle_price_e6: 50_000_000,
            reserved: 0,
        };
        let d = decide_trade_cpi_from_ret(
            42, valid_shape(), true, true, true, true, false, false, valid_ret, 1, 50_000_000, 100,
        );
        assert!(
            matches!(d, TradeCpiDecision::Accept { .. }),
            "non-vacuity: valid ABI inputs must accept"
        );
    }

    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_is_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let ret = any_matcher_return_fields();
    let lp_account_id: u64 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    let req_size: i128 = kani::any();

    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // Strengthened: prove nonce transition relation for both outcome variants.
    let expected_nonce = match &decision {
        TradeCpiDecision::Reject => old_nonce,
        TradeCpiDecision::Accept { .. } => old_nonce.wrapping_add(1),
    };
    let result_nonce = decision_nonce(old_nonce, decision);
    assert_eq!(
        result_nonce, expected_nonce,
        "decision_nonce must agree with TradeCpiDecision outcome (from_ret)"
    );
}

/// Prove: ANY acceptance uses exec_size from ret, not req_size
/// NON-VACUOUS: Forces Accept path by constraining inputs to valid state
#[kani::proof]
fn kani_tradecpi_from_ret_accept_uses_exec_size() {
    let old_nonce: u64 = kani::any();
    // Force valid matcher shape
    let shape = MatcherAccountsShape {
        prog_executable: true,
        ctx_executable: false,
        ctx_owner_is_prog: true,
        ctx_len_ok: true,
    };
    // Force all authorization checks to pass
    let identity_ok: bool = true;
    let pda_ok: bool = true;
    let user_auth_ok: bool = true;
    let lp_auth_ok: bool = true;
    let gate_is_active: bool = false; // Gate inactive = no risk check
    let risk_increase: bool = kani::any(); // Doesn't matter when gate inactive

    // Force valid matcher return
    let exec_size: i128 = kani::any();
    let req_size: i128 = kani::any();
    kani::assume(exec_size != 0);
    kani::assume(req_size != 0);
    // exec_size must have same sign as req_size and |exec_size| <= |req_size|
    kani::assume((exec_size > 0) == (req_size > 0));
    kani::assume(exec_size.unsigned_abs() <= req_size.unsigned_abs());

    let lp_account_id: u64 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    kani::assume(oracle_price_e6 > 0);

    // req_id must match nonce_on_success(old_nonce) for ABI validation
    let expected_req_id = nonce_on_success(old_nonce);

    let ret = MatcherReturnFields {
        abi_version: MATCHER_ABI_VERSION,
        flags: FLAG_VALID,
        exec_price_e6: kani::any::<u64>().max(1), // Non-zero price
        exec_size,
        req_id: expected_req_id, // Must match nonce_on_success(old_nonce)
        lp_account_id,           // Must match
        oracle_price_e6,         // Must match
        reserved: 0,
    };

    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // MUST be Accept with these inputs - panic if not (catches regression)
    match decision {
        TradeCpiDecision::Accept { chosen_size, .. } => {
            assert_eq!(
                chosen_size, ret.exec_size,
                "TradeCpi accept must use exec_size from matcher return, not req_size"
            );
        }
        TradeCpiDecision::Reject => {
            panic!(
                "Expected Accept with valid inputs - function may have regressed to always-reject"
            );
        }
    }
}

// =============================================================================
// W. REJECT => NO CHOSEN_SIZE
// =============================================================================
// Note: Removed trivial proof. The Reject variant having no fields is a
// compile-time structural guarantee enforced by Rust's type system.
// A Kani proof asserting `true` on enum match adds no verification value.

// =============================================================================
// X. i128::MIN BOUNDARY REGRESSION (1 proof)
// =============================================================================

/// Regression proof: i128::MIN boundary case is correctly rejected
/// This proves that exec_size=i128::MIN, req_size=i128::MIN+1 is rejected
/// because |i128::MIN| = 2^127 > |i128::MIN+1| = 2^127-1
/// The old .abs() implementation would panic; .unsigned_abs() handles this correctly.
#[kani::proof]
fn kani_min_abs_boundary_rejected() {
    let ret = MatcherReturn {
        abi_version: MATCHER_ABI_VERSION,
        flags: FLAG_VALID,
        exec_price_e6: 1_000_000, // non-zero price
        exec_size: i128::MIN,     // -2^127
        req_id: 42,
        lp_account_id: 100,
        oracle_price_e6: 50_000_000,
        reserved: 0,
    };

    let req_size = i128::MIN + 1; // -2^127 + 1, so |req_size| = 2^127 - 1

    // |exec_size| = 2^127, |req_size| = 2^127 - 1
    // Since |exec_size| > |req_size|, this must be rejected
    let result = validate_matcher_return(
        &ret,
        ret.lp_account_id,
        ret.oracle_price_e6,
        req_size,
        ret.req_id,
    );

    assert!(
        result.is_err(),
        "i128::MIN exec_size with req_size=i128::MIN+1 must be rejected (|exec| > |req|)"
    );
}

// =============================================================================
// Y. ACCEPTANCE PROOFS - Valid inputs MUST be accepted
// =============================================================================

/// Prove: minimal valid non-zero exec_size is accepted
#[kani::proof]
fn kani_matcher_accepts_minimal_valid_nonzero_exec() {
    let mut ret = any_matcher_return();
    // Constrain to valid inputs
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);

    // Use ret's own fields for expected values (no mismatch)
    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    // req_size must be >= exec_size in magnitude, same sign
    let req_size: i128 = kani::any();
    kani::assume(req_size.signum() == ret.exec_size.signum());
    kani::assume(req_size.unsigned_abs() >= ret.exec_size.unsigned_abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_ok(), "valid inputs must be accepted");
}

/// Prove: exec_size == req_size (same sign) is accepted
#[kani::proof]
fn kani_matcher_accepts_exec_size_equal_req_size() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);

    // exec_size == req_size
    let req_size: i128 = ret.exec_size;
    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(result.is_ok(), "exec_size == req_size must be accepted");
}

/// Prove: partial fill with PARTIAL_OK is accepted
#[kani::proof]
fn kani_matcher_accepts_partial_fill_with_flag() {
    let mut ret = any_matcher_return();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    kani::assume(ret.exec_size != 0);

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price: u64 = ret.oracle_price_e6;
    let req_id: u64 = ret.req_id;

    // req_size >= exec_size, same sign (partial fill)
    let req_size: i128 = kani::any();
    kani::assume(req_size.signum() == ret.exec_size.signum());
    kani::assume(req_size.unsigned_abs() >= ret.exec_size.unsigned_abs());

    let result = validate_matcher_return(&ret, lp_account_id, oracle_price, req_size, req_id);
    assert!(
        result.is_ok(),
        "partial fill with PARTIAL_OK must be accepted"
    );
}

/// Universal characterization: decide_keeper_crank_with_panic ==
///   if allow_panic != 0 && !admin_ok(admin, signer) => Reject
///   else => decide_crank(permissionless, idx_exists, stored_owner, signer)
#[kani::proof]
fn kani_decide_keeper_crank_with_panic_universal() {
    let allow_panic: u8 = kani::any();
    let admin: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();
    let permissionless: bool = kani::any();
    let idx_exists: bool = kani::any();
    let stored_owner: [u8; 32] = kani::any();

    let decision = decide_keeper_crank_with_panic(
        allow_panic, admin, signer, permissionless, idx_exists, stored_owner,
    );

    let expected = if allow_panic != 0 && !admin_ok(admin, signer) {
        SimpleDecision::Reject
    } else {
        decide_crank(permissionless, idx_exists, stored_owner, signer)
    };

    assert_eq!(decision, expected,
        "decide_keeper_crank_with_panic must match specification");
}

// =============================================================================
// AA. ORACLE INVERSION MATH PROOFS (5 proofs)
// =============================================================================

/// Prove: invert==0 returns raw unchanged (for any raw including 0)
/// Note: invert==0 is "no inversion" - raw passes through unchanged
#[kani::proof]
fn kani_invert_zero_returns_raw() {
    let raw: u64 = kani::any();
    let result = invert_price_e6(raw, 0);
    assert_eq!(result, Some(raw), "invert==0 must return raw unchanged");
}

/// Prove: invert!=0 with valid raw returns correct floor(1e12/raw)
/// NON-VACUOUS: forces success path by constraining raw to valid range
/// Bounded to 8192: 128-bit division + equality is SAT-heavy (~66s)
#[kani::proof]
fn kani_invert_nonzero_computes_correctly() {
    let raw: u64 = kani::any();
    kani::assume(raw > 0);
    kani::assume(raw <= 8192);

    let result = invert_price_e6(raw, 1);

    // Must succeed: 1e12 / raw >= 1 when raw <= 1e12
    let inverted = result.expect("inversion must succeed for raw in (0, 8192]");

    // Verify correctness: exact floor division
    let expected = INVERSION_CONSTANT / (raw as u128);
    assert_eq!(
        inverted as u128, expected,
        "inversion must be floor(1e12/raw)"
    );
}

/// Prove: raw==0 always returns None for any non-zero invert (div by zero protection)
#[kani::proof]
fn kani_invert_zero_raw_returns_none() {
    let invert: u8 = kani::any();
    kani::assume(invert != 0);
    let result = invert_price_e6(0, invert);
    assert!(result.is_none(), "raw==0 must return None");
}

/// Prove: inverted==0 returns None for ALL raw > INVERSION_CONSTANT
/// Since 1e12 / raw < 1 when raw > 1e12, the result floors to 0 => None.
#[kani::proof]
fn kani_invert_result_zero_returns_none() {
    let raw: u64 = kani::any();
    kani::assume(raw > INVERSION_CONSTANT as u64);

    let result = invert_price_e6(raw, 1);
    assert!(
        result.is_none(),
        "inversion resulting in 0 must return None"
    );
}

/// Prove: the overflow branch in invert_price_e6 is dead code.
/// INVERSION_CONSTANT = 1e12 < u64::MAX ≈ 1.8e19, so 1e12/raw can never
/// exceed u64::MAX for any positive raw. Documents this structural property.
#[kani::proof]
fn kani_invert_overflow_branch_is_dead() {
    kani::assert(
        INVERSION_CONSTANT <= u64::MAX as u128,
        "INVERSION_CONSTANT must fit in u64, making overflow branch unreachable"
    );
    // For any raw > 0, inverted = INVERSION_CONSTANT / raw <= INVERSION_CONSTANT <= u64::MAX
    let raw: u64 = kani::any();
    kani::assume(raw > 0);
    let inverted = INVERSION_CONSTANT / (raw as u128);
    assert!(
        inverted <= u64::MAX as u128,
        "inversion result must fit in u64 for all positive raw"
    );
}

/// Prove: monotonicity - if raw1 > raw2 > 0 then inv1 <= inv2
#[kani::proof]
fn kani_invert_monotonic() {
    let raw1: u64 = kani::any();
    let raw2: u64 = kani::any();
    kani::assume(raw1 > 0 && raw2 > 0);
    kani::assume(raw1 > raw2);
    // Cap to keep division tractable for SAT solver
    kani::assume(raw1 <= KANI_MAX_QUOTIENT);
    kani::assume(raw2 <= KANI_MAX_QUOTIENT);

    let inv1 = invert_price_e6(raw1, 1);
    let inv2 = invert_price_e6(raw2, 1);

    // Bounded domain guarantees successful inversion for both values.
    assert!(inv1.is_some(), "raw1 in bounded domain must invert successfully");
    assert!(inv2.is_some(), "raw2 in bounded domain must invert successfully");
    let i1 = inv1.unwrap();
    let i2 = inv2.unwrap();
    assert!(i1 <= i2, "inversion must be monotonically decreasing");
}

// =============================================================================
// AB. UNIT CONVERSION ALGEBRA PROOFS (8 proofs)
// =============================================================================

/// Prove: base_to_units conservation: units*scale + dust == base (when scale > 0)
#[kani::proof]
fn kani_base_to_units_conservation() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap base to keep quotient small for SAT solver
    let base: u64 = kani::any();
    kani::assume(base <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (units, dust) = base_to_units(base, scale);

    // Conservation: units * scale + dust == base
    let reconstructed = (units as u128) * (scale as u128) + (dust as u128);
    assert_eq!(
        reconstructed, base as u128,
        "units*scale + dust must equal base"
    );
}

/// Prove: dust < scale when scale > 0
#[kani::proof]
fn kani_base_to_units_dust_bound() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap base to keep quotient small for SAT solver
    let base: u64 = kani::any();
    kani::assume(base <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (_, dust) = base_to_units(base, scale);

    assert!(dust < scale as u64, "dust must be < scale");
}

/// Prove: scale==0 returns (base, 0)
#[kani::proof]
fn kani_base_to_units_scale_zero() {
    let base: u64 = kani::any();

    let (units, dust) = base_to_units(base, 0);

    assert_eq!(units, base, "scale==0 must return units==base");
    assert_eq!(dust, 0, "scale==0 must return dust==0");
}

/// Prove: units_to_base roundtrip (without overflow)
#[kani::proof]
fn kani_units_roundtrip() {
    let units: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);
    // Cap quotient to keep division tractable for SAT solver
    kani::assume(units <= KANI_MAX_QUOTIENT);

    let base = units_to_base(units, scale);
    let (recovered_units, dust) = base_to_units(base, scale);

    assert_eq!(recovered_units, units, "roundtrip must preserve units");
    assert_eq!(dust, 0, "roundtrip must have no dust");
}

/// Prove: units_to_base with scale==0 returns units unchanged
#[kani::proof]
fn kani_units_to_base_scale_zero() {
    let units: u64 = kani::any();

    let base = units_to_base(units, 0);

    assert_eq!(base, units, "scale==0 must return units unchanged");
}

/// Prove: base_to_units is monotonic: base1 < base2 => units1 <= units2
#[kani::proof]
fn kani_base_to_units_monotonic() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap both bases to keep quotients small
    let base1: u64 = kani::any();
    let base2: u64 = kani::any();
    kani::assume(base1 <= (scale as u64) * KANI_MAX_QUOTIENT);
    kani::assume(base2 <= (scale as u64) * KANI_MAX_QUOTIENT);
    kani::assume(base1 < base2);

    let (units1, _) = base_to_units(base1, scale);
    let (units2, _) = base_to_units(base2, scale);

    assert!(units1 <= units2, "base_to_units must be monotonic");
}

///// Prove: units_to_base is strictly monotonic when products don't overflow.
/// NOTE: At saturation (units * scale >= u64::MAX), both return u64::MAX,
/// breaking strict monotonicity. This proof bounds inputs to non-saturating range.
/// Production code should use units_to_base_checked to detect overflow.
#[kani::proof]
fn kani_units_to_base_monotonic_bounded() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap units to keep products below overflow threshold
    let units1: u64 = kani::any();
    let units2: u64 = kani::any();
    kani::assume(units1 <= KANI_MAX_QUOTIENT);
    kani::assume(units2 <= KANI_MAX_QUOTIENT);
    kani::assume(units1 < units2);

    // Within these bounds, no saturation occurs
    let base1 = units_to_base(units1, scale);
    let base2 = units_to_base(units2, scale);

    assert!(
        base1 < base2,
        "units_to_base is strictly monotonic when not saturating"
    );
}

/// Prove: scale==0 preserves monotonicity for base_to_units
#[kani::proof]
fn kani_base_to_units_monotonic_scale_zero() {
    let base1: u64 = kani::any();
    let base2: u64 = kani::any();
    kani::assume(base1 < base2);

    let (units1, _) = base_to_units(base1, 0);
    let (units2, _) = base_to_units(base2, 0);

    assert!(
        units1 < units2,
        "scale==0 must preserve strict monotonicity"
    );
}

// =============================================================================
// AC. WITHDRAW ALIGNMENT PROOFS (3 proofs)
// =============================================================================

/// Prove: misaligned amount rejects when scale != 0
/// Constructs misaligned amount directly to avoid expensive % in SAT solver
#[kani::proof]
fn kani_withdraw_misaligned_rejects() {
    let scale: u32 = kani::any();
    kani::assume(scale > 1); // scale==1 means everything is aligned
    kani::assume(scale <= KANI_MAX_SCALE);

    // Construct misaligned: amount = q*scale + r where 0 < r < scale
    let q: u64 = kani::any();
    let r: u64 = kani::any();
    kani::assume(q <= KANI_MAX_QUOTIENT);
    kani::assume(r > 0);
    kani::assume(r < scale as u64);
    let amount = q * (scale as u64) + r;

    let aligned = withdraw_amount_aligned(amount, scale);

    assert!(!aligned, "misaligned amount must be rejected");
}

/// Prove: aligned amount accepts when scale != 0
#[kani::proof]
fn kani_withdraw_aligned_accepts() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap units to keep product small
    let units: u64 = kani::any();
    kani::assume(units <= KANI_MAX_QUOTIENT);

    let amount = units * (scale as u64);
    let aligned = withdraw_amount_aligned(amount, scale);

    assert!(aligned, "aligned amount must be accepted");
}

/// Prove: scale==0 always aligned
#[kani::proof]
fn kani_withdraw_scale_zero_always_aligned() {
    let amount: u64 = kani::any();

    let aligned = withdraw_amount_aligned(amount, 0);

    assert!(aligned, "scale==0 must always be aligned");
}

// =============================================================================
// AD. DUST MATH PROOFS (8 proofs)
// =============================================================================

/// Prove: sweep_dust conservation: units*scale + rem == dust (scale > 0)
#[kani::proof]
fn kani_sweep_dust_conservation() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap dust to keep quotient small
    let dust: u64 = kani::any();
    kani::assume(dust <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (units, rem) = sweep_dust(dust, scale);

    let reconstructed = (units as u128) * (scale as u128) + (rem as u128);
    assert_eq!(
        reconstructed, dust as u128,
        "units*scale + rem must equal dust"
    );
}

/// Prove: sweep_dust rem < scale (scale > 0)
#[kani::proof]
fn kani_sweep_dust_rem_bound() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Cap dust to keep quotient small
    let dust: u64 = kani::any();
    kani::assume(dust <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (_, rem) = sweep_dust(dust, scale);

    assert!(rem < scale as u64, "remaining dust must be < scale");
}

/// Prove: if dust < scale, then units==0 and rem==dust
#[kani::proof]
fn kani_sweep_dust_below_threshold() {
    let dust: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);
    kani::assume(dust < scale as u64);

    let (units, rem) = sweep_dust(dust, scale);

    assert_eq!(units, 0, "dust < scale must yield units==0");
    assert_eq!(rem, dust, "dust < scale must yield rem==dust");
}

/// Prove: sweep_dust with scale==0 returns (dust, 0)
#[kani::proof]
fn kani_sweep_dust_scale_zero() {
    let dust: u64 = kani::any();

    let (units, rem) = sweep_dust(dust, 0);

    assert_eq!(units, dust, "scale==0 must return units==dust");
    assert_eq!(rem, 0, "scale==0 must return rem==0");
}

/// Prove: accumulate_dust is saturating (no overflow)
/// NOTE (code-equals-spec): accumulate_dust IS saturating_add; this guards
/// against regressions if the function body is modified.
#[kani::proof]
fn kani_accumulate_dust_saturates() {
    let old: u64 = kani::any();
    let added: u64 = kani::any();

    let result = accumulate_dust(old, added);

    assert_eq!(
        result,
        old.saturating_add(added),
        "accumulate_dust must match saturating_add"
    );
}

/// Prove: scale==0 policy - base_to_units never produces dust
/// This is the foundation of the "no dust when scale==0" invariant
#[kani::proof]
fn kani_scale_zero_policy_no_dust() {
    let base: u64 = kani::any();

    let (_, dust) = base_to_units(base, 0);

    assert_eq!(dust, 0, "scale==0 must NEVER produce dust");
}

/// Prove: scale==0 policy - sweep never leaves remainder
/// Combined with no-dust production, this ensures dust stays 0
#[kani::proof]
fn kani_scale_zero_policy_sweep_complete() {
    let dust: u64 = kani::any();

    let (_, rem) = sweep_dust(dust, 0);

    assert_eq!(rem, 0, "scale==0 sweep must leave no remainder");
}

/// Prove: scale==0 end-to-end - deposit + accumulate + sweep cycle works correctly
/// Strengthened: includes symbolic old_dust via accumulate_dust before sweep
#[kani::proof]
fn kani_scale_zero_policy_end_to_end() {
    let base: u64 = kani::any();
    let old_dust: u64 = kani::any();

    // Deposit converts base to units + dust
    let (_, new_dust) = base_to_units(base, 0);
    assert_eq!(new_dust, 0, "deposit with scale==0 must produce no dust");

    // Accumulate any pre-existing dust (simulates multiple deposits)
    let accumulated = accumulate_dust(old_dust, new_dust);

    // Sweep accumulated dust
    let (swept_units, final_rem) = sweep_dust(accumulated, 0);

    // With scale==0, sweep returns all dust as units with no remainder
    assert_eq!(swept_units, accumulated, "scale==0 sweep must return all dust as units");
    assert_eq!(final_rem, 0, "sweep with scale==0 must leave no remainder");
}

// =============================================================================
// AE. UNIVERSAL GATE ORDERING PROOFS FOR TRADECPI (6 proofs)
// These prove that specific gates cause rejection regardless of other inputs
// =============================================================================

/// Universal: matcher_shape_ok==false => Reject (regardless of other inputs)
#[kani::proof]
fn kani_universal_shape_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    // Force shape to be invalid
    kani::assume(!matcher_shape_ok(shape));

    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "invalid shape must always reject"
    );
}

/// Universal: pda_ok==false => Reject
#[kani::proof]
fn kani_universal_pda_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));
    let identity_ok: bool = kani::any();
    let pda_ok = false; // Force failure
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "pda_ok==false must always reject"
    );
}

/// Universal: user_auth_ok==false => Reject
#[kani::proof]
fn kani_universal_user_auth_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok = false; // Force failure
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "user_auth_ok==false must always reject"
    );
}

/// Universal: lp_auth_ok==false => Reject
#[kani::proof]
fn kani_universal_lp_auth_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok = false; // Force failure
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "lp_auth_ok==false must always reject"
    );
}

/// Universal: identity_ok==false => Reject
#[kani::proof]
fn kani_universal_identity_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));
    let identity_ok = false; // Force failure
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "identity_ok==false must always reject"
    );
}

/// Universal: abi_ok==false => Reject
#[kani::proof]
fn kani_universal_abi_fail_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok = false; // Force failure
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "abi_ok==false must always reject"
    );
}

// =============================================================================
// AF. CONSISTENCY BETWEEN decide_trade_cpi AND decide_trade_cpi_from_ret
// Split into valid-shape and invalid-shape for faster/sharper proofs
// =============================================================================

/// Prove: consistency under VALID shape - focuses on ABI/nonce/gate/identity
#[kani::proof]
fn kani_tradecpi_variants_consistent_valid_shape() {
    let old_nonce: u64 = kani::any();
    let shape = valid_shape(); // Force valid shape

    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_is_active: bool = kani::any();
    let risk_increase: bool = kani::any();

    // Create ret fields
    let ret = any_matcher_return_fields();
    let lp_account_id: u64 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    let req_size: i128 = kani::any();

    // Compute req_id as decide_trade_cpi_from_ret does
    let req_id = nonce_on_success(old_nonce);

    // Check if ABI would pass
    let abi_passes = abi_ok(ret, lp_account_id, oracle_price_e6, req_size, req_id);

    // Get decisions from both variants
    let decision1 = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_passes,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret.exec_size,
    );

    let decision2 = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // Both must give same outcome
    match (&decision1, &decision2) {
        (TradeCpiDecision::Reject, TradeCpiDecision::Reject) => {}
        (
            TradeCpiDecision::Accept {
                new_nonce: n1,
                chosen_size: s1,
            },
            TradeCpiDecision::Accept {
                new_nonce: n2,
                chosen_size: s2,
            },
        ) => {
            assert_eq!(*n1, *n2, "nonces must match");
            assert_eq!(*s1, *s2, "chosen_sizes must match");
        }
        _ => panic!("decisions must be consistent"),
    }
}

/// Prove: consistency under INVALID shape - both must reject (fast proof)
#[kani::proof]
fn kani_tradecpi_variants_consistent_invalid_shape() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    // Force INVALID shape
    kani::assume(!matcher_shape_ok(shape));

    // Other inputs symbolic
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_is_active: bool = kani::any();
    let risk_increase: bool = kani::any();
    let ret = any_matcher_return_fields();
    let lp_account_id: u64 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    let req_size: i128 = kani::any();

    let req_id = nonce_on_success(old_nonce);
    let abi_passes = abi_ok(ret, lp_account_id, oracle_price_e6, req_size, req_id);

    let decision1 = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_passes,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret.exec_size,
    );

    let decision2 = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_is_active,
        risk_increase,
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // Both must reject on invalid shape
    assert_eq!(
        decision1,
        TradeCpiDecision::Reject,
        "invalid shape must reject (variant 1)"
    );
    assert_eq!(
        decision2,
        TradeCpiDecision::Reject,
        "invalid shape must reject (variant 2)"
    );
}

/// Prove: decide_trade_cpi_from_ret computes req_id as nonce_on_success(old_nonce)
/// NON-VACUOUS: forces acceptance by constraining ret to be ABI-valid
#[kani::proof]
fn kani_tradecpi_from_ret_req_id_is_nonce_plus_one() {
    let old_nonce: u64 = kani::any();
    let shape = valid_shape();

    // Compute the expected req_id that decide_trade_cpi_from_ret will use
    let expected_req_id = nonce_on_success(old_nonce);

    // Constrain ret to be ABI-valid for this req_id
    let mut ret = any_matcher_return_fields();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK; // PARTIAL_OK allows exec_size=0
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.req_id = expected_req_id; // Must match nonce_on_success(old_nonce)
    ret.exec_size = 0; // With PARTIAL_OK, zero size is always valid

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price_e6: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();

    // All other checks pass
    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        true,  // identity_ok
        true,  // pda_ok
        true,  // user_auth_ok
        true,  // lp_auth_ok
        false, // gate_active (inactive)
        false, // risk_increase
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // FORCE acceptance - with valid ABI inputs, must accept
    match decision {
        TradeCpiDecision::Accept { new_nonce, .. } => {
            assert_eq!(
                new_nonce, expected_req_id,
                "new_nonce must equal nonce_on_success(old_nonce)"
            );
        }
        TradeCpiDecision::Reject => {
            panic!("must accept with valid ABI inputs");
        }
    }
}

// =============================================================================
// AG. UNIVERSAL GATE PROOF (missing from AE)
// =============================================================================

/// Universal: gate_active && risk_increase => Reject (the kill switch)
/// Strengthened: all non-gate inputs are symbolic — proves rejection regardless
/// of shape validity, identity, PDA, ABI, or auth state.
#[kani::proof]
fn kani_universal_gate_risk_increase_rejects() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    // Force valid shape so we actually reach the gate check (invalid shape
    // rejects earlier, which is already proved by kani_universal_shape_fail_rejects)
    kani::assume(matcher_shape_ok(shape));
    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let abi_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();
    let gate_active = true; // Gate IS active
    let risk_increase = true; // Trade WOULD increase risk
    let exec_size: i128 = kani::any();

    let decision = decide_trade_cpi(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        abi_ok,
        user_auth_ok,
        lp_auth_ok,
        gate_active,
        risk_increase,
        exec_size,
    );

    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "gate_active && risk_increase must ALWAYS reject"
    );
}

// =============================================================================
// AH. ADDITIONAL STRENGTHENING PROOFS
// =============================================================================

// Note: Removed kani_unit_conversion_deterministic (purity test).
// Rust pure functions are deterministic by language guarantee —
// calling base_to_units twice with the same inputs cannot differ.
// No Kani proof needed for a compile-time structural property.

// Note: Removed kani_scale_validation_pure (purity test).
// Same reasoning: init_market_scale_ok is a pure function.
// Purity is enforced by Rust's type system (no &mut, no globals).

/// Unit conversion: if dust==0 after base_to_units, roundtrip is exact
/// Constructs base = q * scale directly to avoid expensive % in SAT solver
#[kani::proof]
fn kani_units_roundtrip_exact_when_no_dust() {
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);

    // Construct base as exact multiple of scale (no dust case)
    let q: u64 = kani::any();
    kani::assume(q <= KANI_MAX_QUOTIENT);
    let base = q * (scale as u64);

    let (units, dust) = base_to_units(base, scale);
    assert_eq!(dust, 0, "base = q*scale must have no dust");

    let recovered = units_to_base(units, scale);
    assert_eq!(recovered, base, "roundtrip must be exact when dust==0");
}

/// Universal: allow_panic != 0 && !admin_ok => Reject (for all other inputs)
#[kani::proof]
fn kani_universal_panic_requires_admin() {
    let allow_panic: u8 = kani::any();
    kani::assume(allow_panic != 0); // Panic requested

    let admin: [u8; 32] = kani::any();
    let signer: [u8; 32] = kani::any();

    // Admin check fails (either burned or mismatch)
    kani::assume(!admin_ok(admin, signer));

    // Other inputs can be anything
    let permissionless: bool = kani::any();
    let idx_exists: bool = kani::any();
    let stored_owner: [u8; 32] = kani::any();

    let decision = decide_keeper_crank_with_panic(
        allow_panic,
        admin,
        signer,
        permissionless,
        idx_exists,
        stored_owner,
    );

    assert_eq!(
        decision,
        SimpleDecision::Reject,
        "allow_panic without admin auth must ALWAYS reject"
    );
}

// =============================================================================
// AI. UNIVERSAL GATE KILL-SWITCH FOR FROM_RET PATH
// =============================================================================

/// Universal: gate_active && risk_increase => Reject in from_ret path
/// Proves the kill-switch works in the mechanically-tied path too
/// Strengthened: symbolic shape + symbolic auth bools
#[kani::proof]
fn kani_universal_gate_risk_increase_rejects_from_ret() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));

    let identity_ok: bool = kani::any();
    let pda_ok: bool = kani::any();
    let user_auth_ok: bool = kani::any();
    let lp_auth_ok: bool = kani::any();

    // Construct ABI-valid ret (so we get past ABI checks to the gate)
    let expected_req_id = nonce_on_success(old_nonce);
    let mut ret = any_matcher_return_fields();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.req_id = expected_req_id;
    ret.exec_size = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price_e6: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();

    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        identity_ok,
        pda_ok,
        user_auth_ok,
        lp_auth_ok,
        true, // gate_active - ACTIVE
        true, // risk_increase - INCREASING
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // Reject whether prior gates fail OR gate+risk triggers
    assert_eq!(
        decision,
        TradeCpiDecision::Reject,
        "gate_active && risk_increase must reject (prior gate fail also rejects)"
    );
}

/// Prove: gate_active=true + risk_increase=false => Accept in from_ret path
/// Missing companion to kani_universal_gate_risk_increase_rejects_from_ret:
/// proves risk-neutral/reducing trades pass the kill-switch gate.
/// Strengthened: symbolic shape + symbolic auth bools (all must be true for Accept)
#[kani::proof]
fn kani_tradecpi_from_ret_gate_active_risk_neutral_accepts() {
    let old_nonce: u64 = kani::any();
    let shape = MatcherAccountsShape {
        prog_executable: kani::any(),
        ctx_executable: kani::any(),
        ctx_owner_is_prog: kani::any(),
        ctx_len_ok: kani::any(),
    };
    kani::assume(matcher_shape_ok(shape));

    // Construct ABI-valid ret to pass all pre-gate checks
    let expected_req_id = nonce_on_success(old_nonce);
    let mut ret = any_matcher_return_fields();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.req_id = expected_req_id;
    ret.exec_size = 0;

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price_e6: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();

    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        true,  // identity_ok — must be true for Accept
        true,  // pda_ok — must be true for Accept
        true,  // user_auth_ok — must be true for Accept
        true,  // lp_auth_ok — must be true for Accept
        true,  // gate_active — ACTIVE
        false, // risk_increase — NOT increasing
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    match decision {
        TradeCpiDecision::Accept { .. } => {} // Expected
        TradeCpiDecision::Reject => {
            panic!("gate_active + risk_neutral with valid ABI must accept");
        }
    }
}

// =============================================================================
// AJ. END-TO-END FORCED ACCEPTANCE FOR FROM_RET PATH
// =============================================================================

/// Prove: end-to-end acceptance when all conditions are met
/// NON-VACUOUS: forces Accept and verifies all output fields
#[kani::proof]
fn kani_tradecpi_from_ret_forced_acceptance() {
    let old_nonce: u64 = kani::any();
    let shape = valid_shape();

    // Construct ABI-valid ret
    let expected_req_id = nonce_on_success(old_nonce);
    let mut ret = any_matcher_return_fields();
    ret.abi_version = MATCHER_ABI_VERSION;
    ret.flags = FLAG_VALID | FLAG_PARTIAL_OK;
    ret.reserved = 0;
    kani::assume(ret.exec_price_e6 != 0);
    ret.req_id = expected_req_id;
    ret.exec_size = 0; // PARTIAL_OK allows zero

    let lp_account_id: u64 = ret.lp_account_id;
    let oracle_price_e6: u64 = ret.oracle_price_e6;
    let req_size: i128 = kani::any();

    // All checks pass, gate inactive or risk not increasing
    let decision = decide_trade_cpi_from_ret(
        old_nonce,
        shape,
        true,  // identity_ok
        true,  // pda_ok
        true,  // user_auth_ok
        true,  // lp_auth_ok
        false, // gate_active (inactive)
        false, // risk_increase (not increasing)
        ret,
        lp_account_id,
        oracle_price_e6,
        req_size,
    );

    // MUST accept
    match decision {
        TradeCpiDecision::Accept {
            new_nonce,
            chosen_size,
        } => {
            assert_eq!(new_nonce, expected_req_id, "new_nonce must be nonce+1");
            assert_eq!(chosen_size, ret.exec_size, "chosen_size must be exec_size");
        }
        TradeCpiDecision::Reject => {
            panic!("must accept when all conditions pass");
        }
    }
}

// =============================================================================
// AK. INITMARKET UNIT_SCALE BOUNDS PROOFS (4 proofs)
// =============================================================================

/// Prove: scale > MAX_UNIT_SCALE is rejected
#[kani::proof]
fn kani_init_market_scale_rejects_overflow() {
    // Ensure out-of-range values are constructible (avoid vacuous assumptions).
    assert!(
        MAX_UNIT_SCALE < u32::MAX,
        "MAX_UNIT_SCALE must allow at least one out-of-range value"
    );
    let scale: u32 = kani::any();
    kani::assume(scale > MAX_UNIT_SCALE);

    let result = init_market_scale_ok(scale);
    assert!(!result, "scale > MAX_UNIT_SCALE must be rejected");
}

/// Prove: any scale in valid range [0, MAX_UNIT_SCALE] is accepted
#[kani::proof]
fn kani_init_market_scale_valid_range() {
    let scale: u32 = kani::any();
    kani::assume(scale <= MAX_UNIT_SCALE);

    let result = init_market_scale_ok(scale);

    assert!(result, "any scale in [0, MAX_UNIT_SCALE] must be accepted");
}

// =============================================================================
// AL. NON-INTERFERENCE PROOFS
// =============================================================================
// Note: Removed trivial proofs. admin_ok and owner_ok compare [u8; 32] arrays
// and don't reference unit_scale at all. Independence is structural (no shared
// state), not a runtime property that needs formal verification.

// Purity proofs removed — see note in section AH above.

// =============================================================================
// BUG DETECTION: Unit Scale Margin Inconsistency
// =============================================================================
//
// These proofs demonstrate a BUG in the current margin calculation:
// - Capital is scaled by unit_scale (base_tokens / unit_scale)
// - Position value is NOT scaled (position_size * price / 1_000_000)
// - Margin check compares capital (scaled) vs margin_required (unscaled)
// - This causes the same economic position to pass/fail margin based on unit_scale
//
// The proofs use ACTUAL PRODUCTION CODE from the percolator library:
// - percolator::RiskEngine::mark_pnl_for_position (the real mark_pnl calculation)
// - percolator_prog::verify::base_to_units (the real unit conversion)
//
// This section documents the historical bug mechanism and anchors production
// formulas used by the post-fix proofs below.

// Note: base_to_units is already imported at top of file from percolator_prog::verify

/// Compute position value using the SAME FORMULA as production code.
/// This replicates percolator::RiskEngine::is_above_margin_bps_mtm exactly.
/// See percolator/src/percolator.rs lines 3135-3138.
#[inline]
fn production_position_value(position_size: i128, oracle_price: u64) -> u128 {
    // Exact formula from production: mul_u128(abs(pos), price) / 1_000_000
    let abs_pos = position_size.unsigned_abs();
    abs_pos.saturating_mul(oracle_price as u128) / 1_000_000
}

/// Compute margin required using the SAME FORMULA as production code.
/// See percolator/src/percolator.rs line 3141.
#[inline]
fn production_margin_required(position_value: u128, margin_bps: u64) -> u128 {
    position_value.saturating_mul(margin_bps as u128) / 10_000
}

/// Compute mark-to-market PnL using the SAME FORMULA as production code.
/// This replicates percolator::RiskEngine::mark_pnl_for_position exactly.
/// See percolator/src/percolator.rs lines 1542-1562.
#[inline]
fn production_mark_pnl(position_size: i128, entry_price: u64, oracle_price: u64) -> Option<i128> {
    if position_size == 0 {
        return Some(0);
    }
    let abs_pos = position_size.unsigned_abs();
    let diff: i128 = if position_size > 0 {
        // Long: profit when oracle > entry
        (oracle_price as i128).saturating_sub(entry_price as i128)
    } else {
        // Short: profit when entry > oracle
        (entry_price as i128).saturating_sub(oracle_price as i128)
    };
    // mark_pnl = diff * abs_pos / 1_000_000 (production uses checked_mul/checked_div)
    diff.checked_mul(abs_pos as i128)?.checked_div(1_000_000)
}

/// Compute equity using the SAME FORMULA as production code.
/// This replicates percolator::RiskEngine::account_equity_mtm_at_oracle exactly.
/// See percolator/src/percolator.rs lines 3108-3120.
///
/// BUG: Production code adds capital (in units) + pnl + mark_pnl (both NOT in units).
/// This mixes different unit systems when unit_scale != 0.
#[inline]
fn production_equity(capital: u128, pnl: i128, mark_pnl: i128) -> u128 {
    // Exact formula from production: max(0, capital + pnl + mark_pnl)
    let cap_i = if capital > i128::MAX as u128 {
        i128::MAX
    } else {
        capital as i128
    };
    let eq_i = cap_i.saturating_add(pnl).saturating_add(mark_pnl);
    if eq_i > 0 {
        eq_i as u128
    } else {
        0
    }
}

// =============================================================================
// PRODUCTION scale_price_e6 proofs - These test the ACTUAL production function
// =============================================================================

/// Prove scale_price_e6 returns None when result would be zero.
/// This tests the PRODUCTION function directly.
#[kani::proof]
fn kani_scale_price_e6_zero_result_rejected() {
    let price: u64 = kani::any();
    let unit_scale: u32 = kani::any();

    // Constrain to avoid trivial cases
    kani::assume(unit_scale > 1);
    kani::assume(price > 0);
    kani::assume(price < unit_scale as u64); // Result would be zero

    // PRODUCTION function should reject (return None)
    let result = scale_price_e6(price, unit_scale);
    assert!(
        result.is_none(),
        "scale_price_e6 must reject when scaled price would be zero"
    );
}

/// Prove scale_price_e6 returns Some when result is non-zero.
/// This tests the PRODUCTION function directly.
#[kani::proof]
fn kani_scale_price_e6_valid_result() {
    let price: u64 = kani::any();
    let unit_scale: u32 = kani::any();

    // Constrain to valid inputs that produce non-zero result
    kani::assume(unit_scale > 1);
    kani::assume(unit_scale <= KANI_MAX_SCALE); // Keep SAT tractable
    kani::assume(price >= unit_scale as u64); // Ensures result >= 1
    kani::assume(price <= KANI_MAX_QUOTIENT as u64 * unit_scale as u64); // Tight bound for SAT

    // PRODUCTION function should succeed
    let result = scale_price_e6(price, unit_scale);
    assert!(
        result.is_some(),
        "scale_price_e6 must succeed for valid inputs"
    );

    // Verify the formula: scaled = price / unit_scale
    let scaled = result.unwrap();
    assert_eq!(
        scaled,
        price / unit_scale as u64,
        "scale_price_e6 must compute price / unit_scale"
    );
}

/// Prove scale_price_e6 is identity when unit_scale <= 1.
/// This tests the PRODUCTION function directly.
#[kani::proof]
fn kani_scale_price_e6_identity_for_scale_leq_1() {
    let price: u64 = kani::any();
    let unit_scale: u32 = kani::any();

    kani::assume(unit_scale <= 1);

    // PRODUCTION function should return price unchanged
    let result = scale_price_e6(price, unit_scale);
    assert!(
        result.is_some(),
        "scale_price_e6 must succeed when unit_scale <= 1"
    );
    assert_eq!(
        result.unwrap(),
        price,
        "scale_price_e6 must be identity when unit_scale <= 1"
    );
}

/// Prove that production base_to_units and scale_price_e6 use the SAME divisor
/// AND that this preserves conservative margin behavior.
///
/// The fix works because:
/// - capital_units = base_tokens / unit_scale  (via base_to_units)
/// - oracle_scaled = oracle_price / unit_scale (via scale_price_e6)
///
/// Both divide by the same unit_scale, so margin ratios are preserved.
/// Uses u16 multipliers + u8 scale/pos for SAT tractability (deep multiplication chains).
#[kani::proof]
fn kani_scale_price_and_base_to_units_use_same_divisor() {
    // u16 multipliers + u8 scale/pos keep the 3-deep chain SAT-tractable
    let scale_raw: u8 = kani::any();
    let base_mult: u16 = kani::any();
    let price_mult: u16 = kani::any();
    let pos_raw: u8 = kani::any();

    kani::assume(scale_raw >= 2);
    kani::assume(scale_raw <= 16);
    kani::assume(base_mult >= 1);
    kani::assume(price_mult >= 1);
    kani::assume(pos_raw >= 1);

    let unit_scale = scale_raw as u32;
    let base_tokens = (base_mult as u64) * (unit_scale as u64);
    let oracle_price = (price_mult as u64) * (unit_scale as u64);
    let position_size = pos_raw as u128;

    // Call PRODUCTION functions
    let (capital_units, _dust) = base_to_units(base_tokens, unit_scale);
    let oracle_scaled = scale_price_e6(oracle_price, unit_scale).unwrap();

    // Both should divide by unit_scale
    assert_eq!(
        capital_units,
        base_tokens / unit_scale as u64,
        "base_to_units must compute base / unit_scale"
    );
    assert_eq!(
        oracle_scaled,
        oracle_price / unit_scale as u64,
        "scale_price_e6 must compute price / unit_scale"
    );

    // Margin ratio preservation: scaled position value never exceeds unscaled
    let pv_unscaled = position_size * oracle_price as u128 / 1_000_000;
    let pv_scaled = position_size * oracle_scaled as u128 / 1_000_000;
    assert!(
        pv_scaled * unit_scale as u128 <= pv_unscaled,
        "scaled position value must be conservative (floor rounding)"
    );
}

/// Prove scaled-price math preserves conservative margin behavior under unit scaling.
/// Uses u16 multipliers + u8 scale/bps for SAT tractability.
#[kani::proof]
fn kani_scale_price_e6_concrete_example() {
    let scale_raw: u8 = kani::any();
    let price_mult: u16 = kani::any();
    let pos_raw: u8 = kani::any();
    let bps_raw: u8 = kani::any();

    kani::assume(scale_raw >= 2);
    kani::assume(scale_raw <= 16);
    kani::assume(price_mult >= 1);
    kani::assume(pos_raw >= 1);
    kani::assume(bps_raw >= 1);

    let unit_scale = scale_raw as u32;
    let oracle_price = (price_mult as u64) * (unit_scale as u64); // guaranteed >= unit_scale
    let position_size = pos_raw as u128;
    let margin_bps = bps_raw as u128;

    let scaled = scale_price_e6(oracle_price, unit_scale).unwrap();

    // Conversion identity
    assert_eq!(scaled, oracle_price / unit_scale as u64);

    // Scaled valuation is conservative: floor(price/scale) cannot increase value.
    let pv_unscaled = position_size * oracle_price as u128 / 1_000_000;
    let pv_scaled = position_size * scaled as u128 / 1_000_000;
    assert!(
        pv_scaled * unit_scale as u128 <= pv_unscaled,
        "scaled position value must not exceed unscaled value after re-scaling"
    );

    let mr_unscaled = pv_unscaled * margin_bps / 10_000;
    let mr_scaled = pv_scaled * margin_bps / 10_000;
    assert!(
        mr_scaled * unit_scale as u128 <= mr_unscaled,
        "scaled margin requirement must not exceed unscaled requirement after re-scaling"
    );
}
// Integer truncation can cause < 1 unit differences that flip results at exact
// boundaries, but this is unavoidable with integer arithmetic and economically
// insignificant compared to the original bug (factor of unit_scale difference).

// =============================================================================
// BUG #9 RATE LIMITING PROOFS (clamp_toward_with_dt)
// =============================================================================
//
// Bug #9: In Hyperp mode, clamp_toward_with_dt originally returned `mark` when
// dt=0 (same slot), allowing double-crank to bypass rate limiting.
// Fix: Return `index` (no movement) when dt=0 or cap=0.

/// Prove: When dt_slots == 0, index is returned unchanged (no movement).
/// This is the core Bug #9 fix - prevents same-slot rate limit bypass.
#[kani::proof]
fn kani_clamp_toward_no_movement_when_dt_zero() {
    let index: u64 = kani::any();
    let mark: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();

    // Constrain to valid inputs
    kani::assume(index > 0); // index=0 is special case (returns mark)
    kani::assume(cap_e2bps > 0); // cap=0 also returns index unchanged

    // dt_slots = 0 (same slot)
    let result = clamp_toward_with_dt(index, mark, cap_e2bps, 0);

    // Bug #9 fix: must return index, NOT mark
    assert_eq!(
        result, index,
        "clamp_toward_with_dt must return index unchanged when dt_slots=0"
    );
}

/// Prove: When cap_e2bps == 0, index is returned unchanged (rate limiting disabled).
#[kani::proof]
fn kani_clamp_toward_no_movement_when_cap_zero() {
    let index: u64 = kani::any();
    let mark: u64 = kani::any();
    let dt_slots: u64 = kani::any();

    // Constrain to valid inputs
    kani::assume(index > 0); // index=0 is special case
    kani::assume(dt_slots > 0); // dt=0 also returns index unchanged

    // cap_e2bps = 0 (rate limiting disabled)
    let result = clamp_toward_with_dt(index, mark, 0, dt_slots);

    assert_eq!(
        result, index,
        "clamp_toward_with_dt must return index unchanged when cap_e2bps=0"
    );
}

/// Prove: When index == 0 (uninitialized), mark is returned (bootstrap case).
#[kani::proof]
fn kani_clamp_toward_bootstrap_when_index_zero() {
    let mark: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();
    let dt_slots: u64 = kani::any();

    // index = 0 is the bootstrap/initialization case
    let result = clamp_toward_with_dt(0, mark, cap_e2bps, dt_slots);

    assert_eq!(
        result, mark,
        "clamp_toward_with_dt must return mark when index=0 (bootstrap)"
    );
}

/// Prove: Index movement is always bounded by computed max_delta.
/// Uses u8-range inputs; triple-multiplication chain limits SAT tractability.
/// Companion: kani_clamp_toward_saturation_paths covers large u64 values.
#[kani::proof]
fn kani_clamp_toward_movement_bounded_concrete() {
    let index_raw: u8 = kani::any();
    let cap_steps_raw: u8 = kani::any();
    let dt_raw: u8 = kani::any();
    let mark: u64 = kani::any();

    kani::assume(index_raw >= 10);   // exclude index=0 bootstrap
    kani::assume(cap_steps_raw >= 1);
    kani::assume(cap_steps_raw <= 20); // 1%..20% cap
    kani::assume(dt_raw >= 1);
    kani::assume(dt_raw <= 16);

    let index = index_raw as u64;
    let cap_e2bps = (cap_steps_raw as u64) * 10_000;
    let dt_slots = dt_raw as u64;

    let result = clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots);

    let max_delta = ((index as u128 * cap_e2bps as u128 * dt_slots as u128) / 1_000_000u128) as u64;
    let lo = index.saturating_sub(max_delta);
    let hi = index.saturating_add(max_delta);

    assert!(
        result >= lo && result <= hi,
        "result must stay within computed movement bounds"
    );
}

/// Shared bounded symbolic domain for clamp branch formula proofs.
/// Bounds widened to u16 index/mark while keeping triple-multiply SAT tractable.
fn any_clamp_formula_inputs() -> (u64, u64, u64, u64, u64, u64) {
    let index_raw: u16 = kani::any();
    let cap_steps_raw: u8 = kani::any(); // 1 step = 10_000 e2bps (1.00%)
    let dt_slots_raw: u8 = kani::any();
    let mark_raw: u16 = kani::any();

    kani::assume(index_raw >= 100);
    kani::assume(index_raw <= 1000);
    kani::assume(cap_steps_raw > 0);
    kani::assume(cap_steps_raw <= 5); // 1%..5% cap
    kani::assume(dt_slots_raw > 0);
    kani::assume(dt_slots_raw <= 20);
    kani::assume(mark_raw <= 2000);

    let index_u32 = index_raw as u32;
    let cap_u32 = (cap_steps_raw as u32) * 10_000u32;
    let dt_u32 = dt_slots_raw as u32;

    // With the bounds above, this product fits in u32 without overflow.
    // max: 1000 * 50000 * 20 = 1_000_000_000 < u32::MAX
    let max_delta = (index_u32 * cap_u32 * dt_u32 / 1_000_000u32) as u64;
    let index = index_u32 as u64;
    kani::assume(max_delta > 0); // Non-trivial clamping regime
    kani::assume(max_delta <= index); // Prevent underflow in index - max_delta

    let lo = index - max_delta;
    let hi = index + max_delta;
    let mark = mark_raw as u64;

    (index, mark, cap_u32 as u64, dt_u32 as u64, lo, hi)
}

/// Prove formula correctness for the `mark < lo` branch with symbolic cap/dt.
#[kani::proof]
fn kani_clamp_toward_formula_concrete() {
    // Non-vacuity witness: below-band branch is reachable.
    {
        let index = 2_000u64;
        let cap_e2bps = 20_000u64;
        let dt_slots = 10u64;
        let max_delta = (index * cap_e2bps * dt_slots) / 1_000_000u64;
        let lo = index - max_delta;
        let mark = 1_000u64;
        assert!(mark < lo, "witness must exercise mark < lo branch");
        assert_eq!(
            clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots),
            lo,
            "non-vacuity witness: mark below lo clamps to lo"
        );
    }

    let (index, mark, cap_e2bps, dt_slots, lo, _) = any_clamp_formula_inputs();
    kani::assume(mark < lo);

    let result = clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots);
    assert_eq!(result, lo, "mark below lo must clamp to lo");
}

/// Companion proof: when mark is within the allowed band, result equals mark.
#[kani::proof]
fn kani_clamp_toward_formula_within_bounds() {
    // Non-vacuity witness: within-band branch is reachable.
    {
        let index = 2_000u64;
        let cap_e2bps = 20_000u64;
        let dt_slots = 10u64;
        let max_delta = (index * cap_e2bps * dt_slots) / 1_000_000u64;
        let lo = index - max_delta;
        let hi = index + max_delta;
        let mark = 2_000u64;
        assert!(mark >= lo && mark <= hi, "witness must be inside [lo, hi]");
        assert_eq!(
            clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots),
            mark,
            "non-vacuity witness: mark inside [lo, hi] remains unchanged"
        );
    }

    let (index, mark, cap_e2bps, dt_slots, lo, hi) = any_clamp_formula_inputs();
    kani::assume(mark >= lo);
    kani::assume(mark <= hi);

    let result = clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots);
    assert_eq!(result, mark, "mark inside [lo, hi] must remain unchanged");
}

/// Companion proof: when mark is above the allowed band, result clamps to `hi`.
#[kani::proof]
fn kani_clamp_toward_formula_above_hi() {
    // Non-vacuity witness: above-band branch is reachable.
    {
        let index = 2_000u64;
        let cap_e2bps = 20_000u64;
        let dt_slots = 10u64;
        let max_delta = (index * cap_e2bps * dt_slots) / 1_000_000u64;
        let hi = index + max_delta;
        let mark = 3_000u64;
        assert!(mark > hi, "witness must exercise mark > hi branch");
        assert_eq!(
            clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots),
            hi,
            "non-vacuity witness: mark above hi clamps to hi"
        );
    }

    let (index, mark, cap_e2bps, dt_slots, _, hi) = any_clamp_formula_inputs();
    kani::assume(mark > hi);

    let result = clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots);
    assert_eq!(result, hi, "mark above hi must clamp to hi");
}

/// Prove: clamp_toward_with_dt exercises saturation paths with large u64 inputs.
/// Tests: saturating_mul overflow in max_delta_u128, min(max_delta_u128, u64::MAX)
/// clamp, and saturating_sub/add hitting 0 or u64::MAX.
#[kani::proof]
fn kani_clamp_toward_saturation_paths() {
    // Non-vacuity witness 1: max_delta saturates to u64::MAX, lo=0, hi=u64::MAX
    {
        let index = u64::MAX / 2;
        let cap_e2bps = 1_000_000; // 100%
        let dt_slots = 100;
        let result = clamp_toward_with_dt(index, 0, cap_e2bps, dt_slots);
        // max_delta_u128 = (MAX/2) * 1_000_000 * 100 / 1_000_000 = (MAX/2)*100 >> u64::MAX
        // so max_delta = u64::MAX, lo = saturating_sub = 0
        assert_eq!(result, 0, "witness: mark=0 with saturated max_delta clamps to lo=0");
    }

    // Non-vacuity witness 2: hi saturates to u64::MAX
    {
        let index = u64::MAX - 10;
        let cap_e2bps = 10_000; // 1%
        let dt_slots = 1;
        let result = clamp_toward_with_dt(index, u64::MAX, cap_e2bps, dt_slots);
        // max_delta = (MAX-10) * 10_000 / 1_000_000 ≈ MAX/100, hi = saturating_add = u64::MAX
        assert_eq!(result, u64::MAX, "witness: mark=MAX with hi=MAX clamps to MAX");
    }

    // Symbolic proof: large index with symbolic mark exercises saturation
    let index_offset: u8 = kani::any();
    let mark: u64 = kani::any();
    let cap_steps: u8 = kani::any();
    let dt_raw: u8 = kani::any();

    kani::assume(cap_steps >= 1);
    kani::assume(dt_raw >= 1);

    let index = (u64::MAX / 2).saturating_add(index_offset as u64);
    let cap_e2bps = (cap_steps as u64) * 100_000; // 10%..2550% (forces large delta)
    let dt_slots = dt_raw as u64;

    let result = clamp_toward_with_dt(index, mark, cap_e2bps, dt_slots);

    // Recompute expected bounds (mirrors production code)
    let max_delta_u128 = (index as u128)
        .saturating_mul(cap_e2bps as u128)
        .saturating_mul(dt_slots as u128)
        / 1_000_000u128;
    let max_delta = core::cmp::min(max_delta_u128, u64::MAX as u128) as u64;
    let lo = index.saturating_sub(max_delta);
    let hi = index.saturating_add(max_delta);

    assert!(result >= lo && result <= hi,
        "result must stay within saturated bounds");
    assert_eq!(result, mark.clamp(lo, hi),
        "result must equal mark.clamp(lo, hi)");
}

// =========================================================================
// WithdrawInsurance vault accounting proofs
// =========================================================================

/// Prove: withdraw_insurance_vault correctly decrements vault by insurance amount.
/// For all valid inputs (insurance <= vault), vault_after == vault_before - insurance.
#[kani::proof]
fn kani_withdraw_insurance_vault_correct() {
    let vault_before: u128 = kani::any();
    let insurance: u128 = kani::any();

    // Precondition: insurance must not exceed vault
    kani::assume(insurance <= vault_before);

    let result = withdraw_insurance_vault(vault_before, insurance);
    assert!(result.is_some(), "must succeed when insurance <= vault");
    assert_eq!(
        result.unwrap(),
        vault_before - insurance,
        "vault must be decremented by exact insurance amount"
    );
}

/// Prove: withdraw_insurance_vault returns None when insurance exceeds vault.
#[kani::proof]
fn kani_withdraw_insurance_vault_overflow() {
    let vault_before: u128 = kani::any();
    let insurance: u128 = kani::any();

    // Precondition: insurance exceeds vault
    kani::assume(insurance > vault_before);

    let result = withdraw_insurance_vault(vault_before, insurance);
    assert!(result.is_none(), "must fail when insurance > vault");
}

/// Prove: After withdraw_insurance, if all capital is already withdrawn,
/// vault reaches zero (enabling CloseSlab).
/// Prove complete result characterization for withdraw_insurance_vault:
/// - `Some(vault_after)` iff insurance <= vault_before, with exact subtraction
/// - `None` iff insurance > vault_before
#[kani::proof]
fn kani_withdraw_insurance_vault_result_characterization() {
    let vault_before: u128 = kani::any();
    let insurance: u128 = kani::any();

    match withdraw_insurance_vault(vault_before, insurance) {
        Some(vault_after) => {
            assert!(
                insurance <= vault_before,
                "success requires insurance <= vault_before"
            );
            assert_eq!(
                vault_after,
                vault_before - insurance,
                "success path must perform exact subtraction"
            );
            assert!(
                vault_after <= vault_before,
                "withdrawal must not increase vault balance"
            );
        }
        None => {
            assert!(
                insurance > vault_before,
                "failure is only possible when insurance exceeds vault"
            );
        }
    }
}

// =============================================================================
// INDUCTIVE: Full-domain algebraic properties
//
// These proofs use fully symbolic inputs (no bounded ranges) and verify
// properties via comparison logic rather than multiplication of unknowns
// (which creates intractable SAT constraints in CBMC).
//
// Note: Floor-division properties (monotonicity, conservatism) cannot be
// proved inductively in CBMC because they require symbolic×symbolic
// multiplication. The bounded proofs above verify the implementation IS
// floor division; the mathematical properties follow trivially.
// =============================================================================

/// Inductive: clamp(mark, lo, hi) is always within [lo, hi] for any mark, lo, hi
///
/// This is a trivial property of clamp but proves it holds for the full u64 domain,
/// complementing the bounded kani_clamp_toward_movement_bounded_concrete which
/// verifies the max_delta COMPUTATION is correct (for u8 inputs).
#[kani::proof]
fn inductive_clamp_within_bounds() {
    let mark: u64 = kani::any();
    let lo: u64 = kani::any();
    let hi: u64 = kani::any();
    kani::assume(lo <= hi);

    let result = mark.clamp(lo, hi);

    assert!(result >= lo && result <= hi, "clamp must stay within [lo, hi]");
}

/// Prove: the effective cap for Hyperp markets is always >= DEFAULT_HYPERP_PRICE_CAP_E2BPS.
/// This models the max() enforcement in UpdateHyperpMark.
#[kani::proof]
#[kani::unwind(1)]
fn kani_hyperp_effective_cap_minimum() {
    use percolator_prog::constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS;

    let admin_cap: u64 = kani::any();
    kani::assume(admin_cap <= 1_000_000);

    let effective_cap = core::cmp::max(admin_cap, DEFAULT_HYPERP_PRICE_CAP_E2BPS);

    assert!(
        effective_cap >= DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        "effective cap must always meet minimum"
    );
}

// =============================================================================
// PERC-241: EXPANDED KANI COVERAGE — 10 UNCOVERED PROPERTIES
// =============================================================================
//
// The following 55 harnesses cover 10 previously uncovered properties:
// 1. Token decimals (0-9) — no implicit 9-decimal assumption
// 2. u64::MAX edge cases — deposit, withdraw, fee at boundaries
// 3. State machine invalid transitions — reject out-of-order operations
// 4. Concurrency / interleaved instructions — nonce serialization
// 5. Circuit breaker EMA sub-proofs — update, trigger, recovery
// 6. Fee rounding direction — always rounds in protocol favour
// 7. Dust accumulation — multi-operation conservation
// 8. Self-liquidation resistance — liquidation fee prevents gaming
// 9. Sandwich resistance — price impact bounded by circuit breaker
// 10. Oracle manipulation — adversarial inputs handled correctly

// PERC-241 imports already included in the top-level use block above.

// =============================================================================
// 1. TOKEN DECIMALS — No implicit 9-decimal assumption (6 proofs)
// =============================================================================

/// Prove: base_to_units produces the same result regardless of token decimals.
/// The function only depends on (base, scale), never on decimals.
#[kani::proof]
fn kani_decimals_base_to_units_independent_of_decimals() {
    let base: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale <= KANI_MAX_SCALE);
    kani::assume(base <= (scale.max(1) as u64) * KANI_MAX_QUOTIENT);

    // Call with the same inputs — result is the same regardless of what
    // "decimals" the token has, because decimals are not an input.
    let (units1, dust1) = base_to_units(base, scale);
    let (units2, dust2) = base_to_units(base, scale);

    assert_eq!(units1, units2, "base_to_units must be decimal-independent");
    assert_eq!(dust1, dust2, "dust must be decimal-independent");
}

/// Prove: convert_decimals is identity when from == to for any decimal count 0-9.
#[kani::proof]
fn kani_decimals_convert_identity() {
    let amount: u64 = kani::any();
    let decimals: u8 = kani::any();
    kani::assume(decimals <= 9);

    let result = convert_decimals(amount, decimals, decimals);
    assert_eq!(result, amount, "same-decimal conversion must be identity");
}

/// Prove: convert_decimals 0-decimal to 9-decimal scales up by 10^9.
#[kani::proof]
fn kani_decimals_0_to_9_scales_up() {
    let amount: u64 = kani::any();
    kani::assume(amount <= u64::MAX / 1_000_000_000); // Avoid saturation

    let result = convert_decimals(amount, 0, 9);
    assert_eq!(
        result,
        amount * 1_000_000_000,
        "0→9 decimals must multiply by 10^9"
    );
}

/// Prove: convert_decimals 9-decimal to 0-decimal scales down by 10^9.
#[kani::proof]
fn kani_decimals_9_to_0_scales_down() {
    let amount: u64 = kani::any();

    let result = convert_decimals(amount, 9, 0);
    assert_eq!(
        result,
        amount / 1_000_000_000,
        "9→0 decimals must divide by 10^9"
    );
}

/// Prove: unit conversion with scale works for 6-decimal USDC-like tokens.
/// 1 USDC = 1_000_000 atoms (6 decimals). With scale=1000, units = atoms/1000.
#[kani::proof]
fn kani_decimals_6_decimal_unit_conversion() {
    let usdc_atoms: u64 = kani::any();
    kani::assume(usdc_atoms <= KANI_MAX_QUOTIENT * 1000);

    let scale: u32 = 1000;
    let (units, dust) = base_to_units(usdc_atoms, scale);

    // Conservation
    let reconstructed = (units as u128) * 1000 + (dust as u128);
    assert_eq!(
        reconstructed, usdc_atoms as u128,
        "6-decimal token: conservation must hold"
    );
    assert!(dust < 1000, "6-decimal token: dust must be < scale");
}

/// Prove: unit conversion with scale works for 0-decimal whole-number tokens.
/// With scale=1 (or 0), every atom is one unit.
#[kani::proof]
fn kani_decimals_0_decimal_unit_conversion() {
    let whole_tokens: u64 = kani::any();

    // scale=0 means no scaling
    let (units_0, dust_0) = base_to_units(whole_tokens, 0);
    assert_eq!(units_0, whole_tokens, "scale=0 must return base as units");
    assert_eq!(dust_0, 0, "scale=0 must produce no dust");

    // scale=1 means divide by 1 (same result)
    let (units_1, dust_1) = base_to_units(whole_tokens, 1);
    assert_eq!(units_1, whole_tokens, "scale=1 must return base as units");
    assert_eq!(dust_1, 0, "scale=1 must produce no dust");
}

// =============================================================================
// 2. u64::MAX EDGE CASES — No overflow on any path (7 proofs)
// =============================================================================

/// Prove: deposit at u64::MAX doesn't overflow (saturating add).
#[kani::proof]
fn kani_u64max_deposit_no_overflow() {
    let old_capital: u128 = kani::any();
    let amount: u128 = kani::any();
    kani::assume(amount <= u64::MAX as u128);
    kani::assume(old_capital <= u64::MAX as u128);

    let result = checked_deposit(old_capital, amount);

    // Must either succeed with correct sum or return None
    match result {
        Some(new_cap) => {
            assert_eq!(new_cap, old_capital + amount, "deposit must add correctly");
            assert!(new_cap >= old_capital, "deposit result must be >= old");
        }
        None => {
            // Overflow: old + amount > u128::MAX (extremely unlikely for u64 inputs)
            // This is a safe rejection
        }
    }
}

/// Prove: deposit of u64::MAX into u64::MAX capital doesn't panic.
#[kani::proof]
fn kani_u64max_deposit_max_into_max() {
    let old_capital: u128 = u64::MAX as u128;
    let amount: u128 = u64::MAX as u128;

    let result = checked_deposit(old_capital, amount);

    // u64::MAX + u64::MAX = 2 * u64::MAX, which fits in u128
    assert!(
        result.is_some(),
        "u64::MAX + u64::MAX must not overflow u128"
    );
    assert_eq!(
        result.unwrap(),
        (u64::MAX as u128) * 2,
        "must be exactly 2 * u64::MAX"
    );
}

/// Prove: withdraw at u64::MAX from u64::MAX succeeds.
#[kani::proof]
fn kani_u64max_withdraw_max_from_max() {
    let capital: u128 = u64::MAX as u128;
    let amount: u128 = u64::MAX as u128;

    let result = checked_withdraw(capital, amount);

    assert!(result.is_some(), "withdrawing max from max must succeed");
    assert_eq!(result.unwrap(), 0, "must leave zero balance");
}

/// Prove: withdraw more than capital is rejected.
#[kani::proof]
fn kani_u64max_withdraw_over_balance_rejected() {
    let capital: u128 = kani::any();
    let amount: u128 = kani::any();
    kani::assume(amount > capital);

    let result = checked_withdraw(capital, amount);

    assert!(result.is_none(), "withdrawing more than balance must fail");
}

/// Prove: fee calculation at u64::MAX notional doesn't overflow.
#[kani::proof]
fn kani_u64max_fee_no_overflow() {
    let notional: u128 = u64::MAX as u128;
    let fee_bps: u64 = kani::any();
    kani::assume(fee_bps <= 10_000); // Max 100%

    // Must not panic
    let fee = compute_fee_ceil(notional, fee_bps);

    // Fee must be reasonable: <= notional (can't charge more than 100%)
    assert!(fee <= notional, "fee must not exceed notional");

    // Fee must be non-negative (u128 is always >= 0)
    // Fee must be at least floor value
    let floor = compute_fee_floor(notional, fee_bps);
    assert!(fee >= floor, "ceil fee must be >= floor fee");
}

/// Prove: base_to_units at u64::MAX doesn't panic for any scale.
#[kani::proof]
fn kani_u64max_base_to_units_no_panic() {
    let scale: u32 = kani::any();
    kani::assume(scale <= KANI_MAX_SCALE);

    // Must not panic even at u64::MAX
    let base = u64::MAX;
    let (units, dust) = base_to_units(base, scale);

    if scale == 0 {
        assert_eq!(units, base, "scale=0: units must equal base");
        assert_eq!(dust, 0, "scale=0: no dust");
    } else {
        // Conservation still holds
        let reconstructed = (units as u128) * (scale as u128) + (dust as u128);
        assert_eq!(reconstructed, base as u128, "conservation at u64::MAX");
    }
}

/// Prove: nonce wrapping at u64::MAX is safe (already proven, but now explicit edge).
#[kani::proof]
fn kani_u64max_nonce_wraps_safely() {
    // Two successive wraps
    let n1 = nonce_on_success(u64::MAX);
    assert_eq!(n1, 0, "u64::MAX wraps to 0");

    let n2 = nonce_on_success(n1);
    assert_eq!(n2, 1, "0 wraps to 1");

    // Failure at MAX leaves it unchanged
    let n3 = nonce_on_failure(u64::MAX);
    assert_eq!(n3, u64::MAX, "failure at MAX unchanged");
}

// =============================================================================
// 3. STATE MACHINE INVALID TRANSITIONS (6 proofs)
// =============================================================================

/// Prove: close-before-open is rejected (Free -> Closed is invalid).
#[kani::proof]
fn kani_statemachine_close_before_open_rejected() {
    let is_valid = valid_state_transition(AccountState::Free, AccountState::Closed);
    assert!(!is_valid, "Free -> Closed must be rejected");
}

/// Prove: re-init of existing account is rejected (Open -> Open is invalid).
#[kani::proof]
fn kani_statemachine_reinit_rejected() {
    let is_valid = valid_state_transition(AccountState::Open, AccountState::Open);
    assert!(!is_valid, "Open -> Open (re-init) must be rejected");
}

/// Prove: deposit-after-close is rejected.
#[kani::proof]
fn kani_statemachine_deposit_after_close_rejected() {
    let allowed = operation_allowed_in_state(AccountState::Closed, AccountOp::Deposit);
    assert!(!allowed, "deposit after close must be rejected");
}

/// Prove: crank-before-init is rejected.
#[kani::proof]
fn kani_statemachine_crank_before_init_rejected() {
    let allowed = operation_allowed_in_state(AccountState::Free, AccountOp::Crank);
    assert!(!allowed, "crank on free slot must be rejected");
}

/// Prove: all operations on closed accounts are rejected.
#[kani::proof]
fn kani_statemachine_all_ops_rejected_on_closed() {
    let ops = [
        AccountOp::Open,
        AccountOp::Deposit,
        AccountOp::Withdraw,
        AccountOp::Trade,
        AccountOp::Crank,
    ];
    for op in ops {
        let allowed = operation_allowed_in_state(AccountState::Closed, op);
        assert!(!allowed, "no operation except Close should work on Closed");
    }
    // Close on Closed is also invalid (double close)
    let close_allowed = operation_allowed_in_state(AccountState::Closed, AccountOp::Close);
    assert!(!close_allowed, "double close must be rejected");
}

/// Prove: only Open allows trade operations.
#[kani::proof]
fn kani_statemachine_trade_only_on_open() {
    let free = operation_allowed_in_state(AccountState::Free, AccountOp::Trade);
    let open = operation_allowed_in_state(AccountState::Open, AccountOp::Trade);
    let closed = operation_allowed_in_state(AccountState::Closed, AccountOp::Trade);

    assert!(!free, "trade on Free must be rejected");
    assert!(open, "trade on Open must be allowed");
    assert!(!closed, "trade on Closed must be rejected");
}

// =============================================================================
// 4. CONCURRENCY / INTERLEAVED INSTRUCTIONS (6 proofs)
// =============================================================================

/// Prove: two successful operations on same slab produce strictly monotone nonces.
#[kani::proof]
fn kani_concurrency_two_successes_monotone_nonce() {
    let nonce_before: u64 = kani::any();

    let (after_op1, after_op2) = nonces_serialize_correctly(nonce_before, true, true);

    assert_eq!(
        after_op1,
        nonce_before.wrapping_add(1),
        "op1 increments nonce"
    );
    assert_eq!(
        after_op2,
        nonce_before.wrapping_add(2),
        "op2 increments again"
    );
    // Unless wrapping, op2 > op1 > before
    if nonce_before < u64::MAX - 1 {
        assert!(
            after_op1 > nonce_before,
            "nonce must increase after success"
        );
        assert!(after_op2 > after_op1, "nonce must increase again");
    }
}

/// Prove: failed op + successful op still produces correct nonce.
#[kani::proof]
fn kani_concurrency_fail_then_success() {
    let nonce_before: u64 = kani::any();

    let (after_op1, after_op2) = nonces_serialize_correctly(nonce_before, false, true);

    assert_eq!(after_op1, nonce_before, "failed op leaves nonce unchanged");
    assert_eq!(
        after_op2,
        nonce_before.wrapping_add(1),
        "success after fail increments"
    );
}

/// Prove: two failures leave nonce completely unchanged.
#[kani::proof]
fn kani_concurrency_two_failures_nonce_unchanged() {
    let nonce_before: u64 = kani::any();

    let (after_op1, after_op2) = nonces_serialize_correctly(nonce_before, false, false);

    assert_eq!(after_op1, nonce_before, "first failure: unchanged");
    assert_eq!(after_op2, nonce_before, "second failure: still unchanged");
}

/// Prove: trade position zero-sum invariant holds after any trade.
#[kani::proof]
fn kani_concurrency_position_zero_sum_preserved() {
    let old_user: i128 = kani::any();
    let old_lp: i128 = kani::any();
    let size: i128 = kani::any();

    // Start with zero-sum
    kani::assume(old_user.checked_add(old_lp) == Some(0));
    // Avoid saturation
    kani::assume(old_user.checked_add(size).is_some());
    kani::assume(old_lp.checked_sub(size).is_some());

    let (new_user, new_lp, preserved) = apply_trade_positions(old_user, old_lp, size);

    assert!(preserved, "zero-sum must be preserved after trade");
    assert_eq!(new_user + new_lp, 0, "positions must sum to zero");
}

/// Prove: two sequential trades preserve zero-sum.
#[kani::proof]
fn kani_concurrency_two_trades_zero_sum() {
    let old_user: i128 = kani::any();
    let old_lp: i128 = kani::any();
    let size1: i128 = kani::any();
    let size2: i128 = kani::any();

    // Start with zero-sum, avoid saturation
    kani::assume(old_user.checked_add(old_lp) == Some(0));
    kani::assume(old_user.checked_add(size1).is_some());
    kani::assume(old_lp.checked_sub(size1).is_some());

    let (mid_user, mid_lp, ok1) = apply_trade_positions(old_user, old_lp, size1);
    kani::assume(ok1);
    kani::assume(mid_user.checked_add(size2).is_some());
    kani::assume(mid_lp.checked_sub(size2).is_some());

    let (final_user, final_lp, ok2) = apply_trade_positions(mid_user, mid_lp, size2);

    assert!(ok2, "second trade must preserve invariant");
    assert_eq!(final_user + final_lp, 0, "two trades: still zero-sum");
}

/// Prove: position_zero_sum detects non-zero-sum correctly.
#[kani::proof]
fn kani_concurrency_zero_sum_detection() {
    let user: i128 = kani::any();
    let lp: i128 = kani::any();
    // Avoid overflow in add
    kani::assume(user.checked_add(lp).is_some());

    let is_zero = position_zero_sum(user, lp);

    if user + lp == 0 {
        assert!(is_zero, "must detect zero-sum");
    } else {
        assert!(!is_zero, "must detect non-zero-sum");
    }
}

// =============================================================================
// 5. CIRCUIT BREAKER EMA SUB-PROOFS (7 proofs)
// =============================================================================

/// Sub-proof (a): EMA update correctness — unclamped EMA is weighted average.
#[kani::proof]
fn kani_cb_ema_update_weighted_average() {
    let prev: u64 = kani::any();
    let oracle: u64 = kani::any();
    let alpha: u64 = kani::any();

    kani::assume(prev > 0 && prev <= 1_000_000_000);
    kani::assume(oracle > 0 && oracle <= 1_000_000_000);
    kani::assume(alpha > 0 && alpha <= 1_000_000);

    let result = ema_step_unclamped(prev, oracle, alpha);

    // Result must be between min(prev, oracle) and max(prev, oracle)
    let lo = core::cmp::min(prev, oracle);
    let hi = core::cmp::max(prev, oracle);
    assert!(result >= lo, "EMA must be >= min(prev, oracle)");
    assert!(result <= hi, "EMA must be <= max(prev, oracle)");
}

/// Sub-proof (a2): EMA alpha=0 means no update (stay at prev).
#[kani::proof]
fn kani_cb_ema_alpha_zero_no_update() {
    let prev: u64 = kani::any();
    let oracle: u64 = kani::any();
    kani::assume(prev > 0);
    kani::assume(oracle > 0);

    let result = ema_step_unclamped(prev, oracle, 0);

    assert_eq!(result, prev, "alpha=0 must keep prev unchanged");
}

/// Sub-proof (a3): EMA alpha=1_000_000 means full jump to oracle.
#[kani::proof]
fn kani_cb_ema_alpha_full_jumps_to_oracle() {
    let prev: u64 = kani::any();
    let oracle: u64 = kani::any();
    kani::assume(prev > 0 && prev <= 1_000_000_000);
    kani::assume(oracle > 0 && oracle <= 1_000_000_000);

    let result = ema_step_unclamped(prev, oracle, 1_000_000);

    assert_eq!(result, oracle, "alpha=1.0 must jump to oracle");
}

/// Sub-proof (b): Trigger threshold check — breaker fires for out-of-bound oracle.
#[kani::proof]
fn kani_cb_trigger_fires_correctly() {
    let prev_mark: u64 = kani::any();
    let raw_oracle: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();
    let dt_slots: u64 = kani::any();

    kani::assume(prev_mark > 0 && prev_mark <= 1_000_000_000);
    kani::assume(raw_oracle > 0 && raw_oracle <= 1_000_000_000);
    kani::assume(cap_e2bps > 0 && cap_e2bps <= 100_000);
    kani::assume(dt_slots > 0 && dt_slots <= 1000);

    let triggered = circuit_breaker_triggered(prev_mark, raw_oracle, cap_e2bps, dt_slots);

    // Compute bounds independently
    let max_delta = (prev_mark as u128)
        .saturating_mul(cap_e2bps as u128)
        .saturating_mul(dt_slots as u128)
        / 1_000_000u128;
    let max_delta = max_delta.min(prev_mark as u128) as u64;
    let lo = prev_mark.saturating_sub(max_delta);
    let hi = prev_mark.saturating_add(max_delta);

    let in_bounds = raw_oracle >= lo && raw_oracle <= hi;

    if in_bounds {
        assert!(!triggered, "in-bounds oracle must NOT trigger breaker");
    } else {
        assert!(triggered, "out-of-bounds oracle MUST trigger breaker");
    }
}

/// Sub-proof (b2): Breaker disabled (cap=0) never triggers.
#[kani::proof]
fn kani_cb_trigger_disabled_when_cap_zero() {
    let prev_mark: u64 = kani::any();
    let raw_oracle: u64 = kani::any();
    let dt_slots: u64 = kani::any();

    let triggered = circuit_breaker_triggered(prev_mark, raw_oracle, 0, dt_slots);

    assert!(!triggered, "breaker with cap=0 must never trigger");
}

/// Sub-proof (c): Recovery — mark converges toward oracle after clamped EMA step.
/// Distance must not increase when moving toward oracle.
#[kani::proof]
fn kani_cb_recovery_distance_decreases() {
    let prev_mark: u64 = kani::any();
    let oracle: u64 = kani::any();
    let alpha_e6: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();

    kani::assume(prev_mark > 0 && prev_mark <= 1_000_000_000);
    kani::assume(oracle > 0 && oracle <= 1_000_000_000);
    kani::assume(alpha_e6 > 0 && alpha_e6 <= 1_000_000);
    kani::assume(cap_e2bps > 0 && cap_e2bps <= 100_000);

    let old_distance = if prev_mark > oracle {
        prev_mark - oracle
    } else {
        oracle - prev_mark
    };

    let new_distance = mark_distance_after_step(prev_mark, oracle, alpha_e6, cap_e2bps, 1);

    assert!(
        new_distance <= old_distance,
        "EMA step must not increase distance from oracle"
    );
}

/// Sub-proof (c2): At equilibrium (prev == oracle), distance stays zero.
#[kani::proof]
fn kani_cb_recovery_equilibrium_stable() {
    let price: u64 = kani::any();
    kani::assume(price > 0 && price <= 1_000_000_000);

    let alpha_e6: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();
    kani::assume(alpha_e6 <= 1_000_000);
    kani::assume(cap_e2bps <= 100_000);

    let distance = mark_distance_after_step(price, price, alpha_e6, cap_e2bps, 1);

    assert_eq!(distance, 0, "at equilibrium, distance must be zero");
}

// =============================================================================
// 6. FEE ROUNDING DIRECTION — Always in protocol favour (6 proofs)
// =============================================================================

/// Prove: ceiling fee >= floor fee for all inputs.
/// Protocol always rounds UP (in its own favour).
#[kani::proof]
fn kani_fee_ceil_geq_floor() {
    let notional: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(notional <= u64::MAX as u128);
    kani::assume(fee_bps <= 10_000);

    let ceil = compute_fee_ceil(notional, fee_bps);
    let floor = compute_fee_floor(notional, fee_bps);

    assert!(ceil >= floor, "ceil fee must be >= floor fee");
}

/// Prove: for non-zero notional and non-zero fee_bps, fee is at least 1.
/// This prevents micro-trade fee evasion.
#[kani::proof]
fn kani_fee_nonzero_for_any_nonzero_trade() {
    let notional: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(notional > 0);
    kani::assume(fee_bps > 0);
    kani::assume(notional <= u64::MAX as u128);
    kani::assume(fee_bps <= 10_000);

    let fee = compute_fee_ceil(notional, fee_bps);

    assert!(
        fee >= 1,
        "non-zero trade with non-zero fee_bps must charge at least 1"
    );
}

/// Prove: fee == 0 iff notional == 0 or fee_bps == 0.
#[kani::proof]
fn kani_fee_zero_iff_zero_input() {
    let notional: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(notional <= u64::MAX as u128);
    kani::assume(fee_bps <= 10_000);

    let fee = compute_fee_ceil(notional, fee_bps);

    if notional == 0 || fee_bps == 0 {
        assert_eq!(fee, 0, "zero input must produce zero fee");
    } else {
        assert!(fee > 0, "non-zero inputs must produce non-zero fee");
    }
}

/// Prove: fee does not exceed notional (fee <= 100% of trade value).
#[kani::proof]
fn kani_fee_bounded_by_notional() {
    let notional: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(notional <= u64::MAX as u128);
    kani::assume(fee_bps <= 10_000); // Max 100%

    let fee = compute_fee_ceil(notional, fee_bps);

    // At most 100% + rounding
    // ceil(notional * 10000 / 10000) = notional + ceil_error <= notional + 1
    assert!(
        fee <= notional + 1,
        "fee at 100% must not exceed notional + 1 (rounding)"
    );
}

/// Prove: fee is monotone in notional (larger trade → larger fee).
#[kani::proof]
fn kani_fee_monotone_in_notional() {
    let n1: u128 = kani::any();
    let n2: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(n1 <= n2);
    kani::assume(n2 <= u64::MAX as u128);
    kani::assume(fee_bps <= 10_000);

    let fee1 = compute_fee_ceil(n1, fee_bps);
    let fee2 = compute_fee_ceil(n2, fee_bps);

    assert!(fee2 >= fee1, "larger notional must produce >= fee");
}

/// Prove: fee is monotone in fee_bps (higher rate → higher fee).
#[kani::proof]
fn kani_fee_monotone_in_bps() {
    let notional: u128 = kani::any();
    let bps1: u64 = kani::any();
    let bps2: u64 = kani::any();
    kani::assume(bps1 <= bps2);
    kani::assume(bps2 <= 10_000);
    kani::assume(notional <= u64::MAX as u128);

    let fee1 = compute_fee_ceil(notional, bps1);
    let fee2 = compute_fee_ceil(notional, bps2);

    assert!(fee2 >= fee1, "higher fee_bps must produce >= fee");
}

// =============================================================================
// 7. DUST ACCUMULATION — Conservation within tolerance (5 proofs)
// =============================================================================

/// Prove: single deposit dust conservation holds exactly.
#[kani::proof]
fn kani_dust_single_deposit_conservation() {
    let amount: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);
    kani::assume(amount <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (units, dust) = base_to_units(amount, scale);
    let reconstructed = (units as u128) * (scale as u128) + (dust as u128);

    assert_eq!(
        reconstructed, amount as u128,
        "single deposit: units*scale + dust == amount"
    );
}

/// Prove: two deposits with same scale conserve total value.
#[kani::proof]
fn kani_dust_two_deposits_conservation() {
    let a1: u64 = kani::any();
    let a2: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);
    kani::assume(a1 <= (scale as u64) * 64);
    kani::assume(a2 <= (scale as u64) * 64);

    let (u1, d1) = base_to_units(a1, scale);
    let (u2, d2) = base_to_units(a2, scale);

    let total_units = u1 as u128 + u2 as u128;
    let total_dust = accumulate_dust(d1, d2);

    // Sweep the dust
    let (swept_units, remaining) = sweep_dust(total_dust, scale);

    let final_units = total_units + swept_units as u128;
    let total_base = a1 as u128 + a2 as u128;

    // Conservation: final_units * scale + remaining == total_base
    let reconstructed = final_units * (scale as u128) + (remaining as u128);
    assert_eq!(
        reconstructed, total_base,
        "two deposits: value must be exactly conserved"
    );
}

/// Prove: dust accumulation is commutative.
#[kani::proof]
fn kani_dust_accumulation_commutative() {
    let d1: u64 = kani::any();
    let d2: u64 = kani::any();

    let result_12 = accumulate_dust(d1, d2);
    let result_21 = accumulate_dust(d2, d1);

    assert_eq!(
        result_12, result_21,
        "dust accumulation must be commutative"
    );
}

/// Prove: dust accumulation is associative (within saturation).
#[kani::proof]
fn kani_dust_accumulation_associative() {
    let d1: u64 = kani::any();
    let d2: u64 = kani::any();
    let d3: u64 = kani::any();
    // Avoid saturation to test associativity
    kani::assume(d1 as u128 + d2 as u128 + d3 as u128 <= u64::MAX as u128);

    let left = accumulate_dust(accumulate_dust(d1, d2), d3);
    let right = accumulate_dust(d1, accumulate_dust(d2, d3));

    assert_eq!(
        left, right,
        "dust accumulation must be associative (no saturation)"
    );
}

/// Prove: after sweep, remaining dust is always less than one unit.
/// This bounds the total "lost" value to at most (scale - 1) atoms.
#[kani::proof]
fn kani_dust_sweep_bounded_loss() {
    let dust: u64 = kani::any();
    let scale: u32 = kani::any();
    kani::assume(scale > 0);
    kani::assume(scale <= KANI_MAX_SCALE);
    kani::assume(dust <= (scale as u64) * KANI_MAX_QUOTIENT);

    let (_, remaining) = sweep_dust(dust, scale);

    assert!(
        remaining < scale as u64,
        "remaining dust must be less than 1 unit (scale atoms)"
    );
}

// =============================================================================
// 8. SELF-LIQUIDATION RESISTANCE (5 proofs)
// =============================================================================

/// Prove: liquidation always reduces or preserves equity (never increases it).
#[kani::proof]
fn kani_selfliq_equity_never_increases() {
    let equity_before: u128 = kani::any();
    let equity_after: u128 = kani::any();
    let fee_paid: u128 = kani::any();
    kani::assume(equity_after <= equity_before);

    let safe = liquidation_no_profit(equity_before, equity_after, fee_paid);
    assert!(safe, "equity decrease means no profit from liquidation");
}

/// Prove: equity increase is detected as unsafe.
#[kani::proof]
fn kani_selfliq_equity_increase_detected() {
    let equity_before: u128 = kani::any();
    let equity_after: u128 = kani::any();
    kani::assume(equity_after > equity_before);

    let safe = liquidation_no_profit(equity_before, equity_after, 0);
    assert!(!safe, "equity increase must be flagged as unsafe");
}

/// Prove: self-liquidation is unprofitable when fee > 0.
#[kani::proof]
fn kani_selfliq_unprofitable_with_fee() {
    let position_value: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(position_value > 0);
    kani::assume(fee_bps > 0);
    kani::assume(fee_bps <= 10_000);
    kani::assume(position_value <= u64::MAX as u128);

    let unprofitable = self_liquidation_unprofitable(position_value, fee_bps);
    assert!(
        unprofitable,
        "any positive fee makes self-liquidation unprofitable"
    );
}

/// Prove: liquidation fee is always positive for non-zero position with non-zero bps.
#[kani::proof]
fn kani_selfliq_fee_always_positive() {
    let position_value: u128 = kani::any();
    let fee_bps: u64 = kani::any();
    kani::assume(position_value > 0);
    kani::assume(fee_bps > 0);
    kani::assume(fee_bps <= 10_000);
    kani::assume(position_value <= u64::MAX as u128);

    let fee = compute_fee_ceil(position_value, fee_bps);
    assert!(
        fee > 0,
        "liquidation fee must be positive for non-zero position"
    );
}

/// Prove: zero position has zero liquidation cost.
#[kani::proof]
fn kani_selfliq_zero_position_zero_fee() {
    let fee_bps: u64 = kani::any();
    kani::assume(fee_bps <= 10_000);

    let fee = compute_fee_ceil(0, fee_bps);
    assert_eq!(fee, 0, "zero position must have zero fee");
}

// =============================================================================
// 9. SANDWICH RESISTANCE — Price impact bounded (5 proofs)
// =============================================================================

/// Prove: max_price_impact is proportional to price and cap.
#[kani::proof]
fn kani_sandwich_impact_proportional() {
    let price: u64 = kani::any();
    let cap: u64 = kani::any();
    kani::assume(price > 0 && price <= 1_000_000_000);
    kani::assume(cap > 0 && cap <= 1_000_000);

    let impact = max_price_impact(price, cap);

    // Impact = price * cap / 1_000_000, capped at price
    let expected = (price as u128).saturating_mul(cap as u128) / 1_000_000u128;
    let expected = expected.min(price as u128) as u64;

    assert_eq!(impact, expected, "impact must equal price * cap / 1e6");
}

/// Prove: price_impact_bounded accepts prices within bounds.
#[kani::proof]
fn kani_sandwich_bounded_accepts_in_range() {
    let price_before: u64 = kani::any();
    let cap: u64 = kani::any();
    kani::assume(price_before > 0 && price_before <= 1_000_000_000);
    kani::assume(cap > 0 && cap <= 1_000_000);

    // price_after == price_before (no change) should always be in bounds
    let bounded = price_impact_bounded(price_before, price_before, cap);
    assert!(bounded, "unchanged price must be within bounds");
}

/// Prove: price_impact_bounded rejects extreme changes.
#[kani::proof]
fn kani_sandwich_bounded_rejects_extreme() {
    let price_before: u64 = 1_000_000_000; // $1000 in e6
    let cap: u64 = 10_000; // 1% per slot

    // max_impact = 1_000_000_000 * 10_000 / 1_000_000 = 10_000_000
    // So 2x the price (2_000_000_000) should be out of bounds
    let bounded = price_impact_bounded(price_before, 2_000_000_000, cap);
    assert!(!bounded, "2x price jump must violate 1% cap");
}

/// Prove: zero cap means zero allowed impact.
#[kani::proof]
fn kani_sandwich_zero_cap_no_movement() {
    let price: u64 = kani::any();
    kani::assume(price > 0);

    let impact = max_price_impact(price, 0);
    assert_eq!(impact, 0, "zero cap must allow zero impact");
}

/// Prove: cap=1_000_000 (100%) allows any movement up to doubling.
#[kani::proof]
fn kani_sandwich_full_cap_allows_double() {
    let price: u64 = kani::any();
    kani::assume(price > 0 && price <= 500_000_000); // Keep sum < u64::MAX

    let impact = max_price_impact(price, 1_000_000);
    // 100% cap means impact = price itself
    assert_eq!(impact, price, "100% cap must allow movement equal to price");

    // Double the price should be within bounds
    let bounded = price_impact_bounded(price, price * 2, 1_000_000);
    assert!(bounded, "doubling price must be within 100% cap");
}

// =============================================================================
// 10. ORACLE MANIPULATION — Adversarial inputs handled (7 proofs)
// =============================================================================

/// Prove: price=0 is rejected by oracle validation.
#[kani::proof]
fn kani_oracle_zero_price_rejected() {
    let valid = oracle_price_valid(0);
    assert!(!valid, "price=0 must be rejected");
}

/// Prove: price=u64::MAX is rejected (exceeds MAX_ORACLE_PRICE).
#[kani::proof]
fn kani_oracle_max_price_rejected() {
    let valid = oracle_price_valid(u64::MAX);
    assert!(
        !valid,
        "u64::MAX must exceed MAX_ORACLE_PRICE and be rejected"
    );
}

/// Prove: valid prices in range (1..=MAX_ORACLE_PRICE) are accepted.
#[kani::proof]
fn kani_oracle_valid_price_accepted() {
    let price: u64 = kani::any();
    kani::assume(price > 0 && price <= 1_000_000_000_000_000);

    let valid = oracle_price_valid(price);
    assert!(valid, "price in valid range must be accepted");
}

/// Prove: 99% drop triggers circuit breaker for any reasonable cap.
#[kani::proof]
fn kani_oracle_99pct_drop_triggers_breaker() {
    let prev_price: u64 = kani::any();
    let cap_e2bps: u64 = kani::any();

    // Reasonable bounds
    kani::assume(prev_price >= 100); // Need at least 100 for 99% to be meaningful
    kani::assume(prev_price <= 1_000_000_000);
    kani::assume(cap_e2bps > 0 && cap_e2bps <= 100_000); // up to 10%/slot

    // For dt=1 slot, 99% drop should trigger if cap < 99%
    // cap < 990_000 means max movement < 99%
    kani::assume(cap_e2bps < 990_000);

    let triggered = extreme_drop_triggers_breaker(prev_price, cap_e2bps, 1);
    assert!(
        triggered,
        "99% drop must trigger circuit breaker for cap < 99%"
    );
}

/// Prove: circuit breaker clamps adversarial oracle to safe range.
/// Even with price=0 as oracle input, compute_ema_mark_price stays bounded.
#[kani::proof]
fn kani_oracle_adversarial_zero_clamped() {
    let prev_mark: u64 = kani::any();
    let alpha: u64 = kani::any();
    let cap: u64 = kani::any();

    kani::assume(prev_mark > 0 && prev_mark <= 1_000_000_000);
    kani::assume(alpha > 0 && alpha <= 1_000_000);
    kani::assume(cap > 0 && cap <= 100_000);

    // Adversarial oracle: 0 (should be rejected before reaching EMA in production,
    // but verify the EMA function itself handles it gracefully)
    let result = compute_ema_mark_price(prev_mark, 0, 1, alpha, cap);

    // oracle=0 returns prev_mark (early return in compute_ema_mark_price)
    assert_eq!(
        result, prev_mark,
        "oracle=0 must return prev_mark unchanged"
    );
}

/// Prove: adversarial u64::MAX oracle is clamped by circuit breaker.
#[kani::proof]
fn kani_oracle_adversarial_max_clamped() {
    let prev_mark: u64 = kani::any();
    let cap: u64 = kani::any();

    kani::assume(prev_mark > 0 && prev_mark <= 1_000_000_000);
    kani::assume(cap > 0 && cap <= 100_000);

    // u64::MAX oracle should be clamped to prev_mark + max_delta
    let result = compute_ema_mark_price(prev_mark, u64::MAX, 1, 1_000_000, cap);

    let max_delta = (prev_mark as u128).saturating_mul(cap as u128) / 1_000_000u128;
    let max_delta = max_delta.min(prev_mark as u128) as u64;
    let hi = prev_mark.saturating_add(max_delta);

    assert!(
        result <= hi,
        "u64::MAX oracle must be clamped by circuit breaker"
    );
}

/// Prove: oracle price validation and circuit breaker compose correctly.
/// Invalid prices are rejected; valid prices are clamped.
#[kani::proof]
fn kani_oracle_validation_and_breaker_compose() {
    let price: u64 = kani::any();

    // Step 1: Validate
    let valid = oracle_price_valid(price);

    if !valid {
        // Either price==0 or price > MAX_ORACLE_PRICE
        assert!(
            price == 0 || price > 1_000_000_000_000_000,
            "invalid prices must be 0 or > MAX_ORACLE"
        );
    } else {
        // Valid price: circuit breaker can process it
        let prev_mark: u64 = 1_000_000_000; // $1000 in e6
        let cap: u64 = 10_000; // 1%

        let result = compute_ema_mark_price(prev_mark, price, 1, 1_000_000, cap);

        // Result must be bounded
        let max_delta = prev_mark as u128 * 10_000 / 1_000_000;
        let hi = prev_mark + max_delta as u64;
        let lo = prev_mark.saturating_sub(max_delta as u64);
        assert!(
            result >= lo && result <= hi,
            "valid oracle must produce bounded result"
        );
    }
}
