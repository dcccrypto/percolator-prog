//! Public-route regressions for issues reported against upstream percolator-prog
//! (aeyakovenko/percolator-prog), ported onto the v2.2 wrapper.
//!
//! Each test drives the built SBF through LiteSVM with public instructions and pins the behavior the
//! corresponding upstream issue requires. Ported from upstream `tests/open_issue_regressions.rs` at
//! d2e99bc8; the upstream `support::v16_svm::V16Svm` fixture is replaced by this repo's
//! `indep_harness::V16CuEnv`, which drives the same instructions.
#![cfg(not(kani))]

mod indep_harness;

use indep_harness::*;

/// `PercolatorError::EngineLockActive`: the custody gate's refusal code.
const ENGINE_LOCK_ACTIVE: u32 = 21;

fn funded_env() -> V16CuEnv {
    let mut env = V16CuEnv::new();
    let admin = env.admin.insecure_clone();
    env.top_up_insurance_domain_with_authority(&admin, 0, 100);
    env.top_up_insurance_domain_with_authority(&admin, 1, 100);
    env
}

/// Injects a pending domain loss barrier on asset 0's long (domain 0) or short (domain 1) side.
fn market_with_barrier(env: &mut V16CuEnv, short_side: bool) {
    use percolator_prog::constants::{
        ASSET_ORACLE_WRAPPER_LEN, MARKET_GROUP_LEN, MARKET_GROUP_OFF,
    };
    let engine = MARKET_GROUP_OFF + MARKET_GROUP_LEN + ASSET_ORACLE_WRAPPER_LEN;
    let field = if short_side {
        core::mem::offset_of!(
            percolator::EngineAssetSlotV16Account,
            pending_domain_loss_barrier_short
        )
    } else {
        core::mem::offset_of!(
            percolator::EngineAssetSlotV16Account,
            pending_domain_loss_barrier_long
        )
    };
    let mut account = env.svm.get_account(&env.market).unwrap();
    account.data[engine + field..engine + field + 8].copy_from_slice(&1u64.to_le_bytes());
    env.svm.set_account(env.market, account).unwrap();
}

/// Issue #438 (upstream d2e99bc8, re-derived from upstream PR #443): WithdrawInsuranceAsset debits
/// both of an asset's insurance domains, so a pending loss barrier on either domain must block it
/// (hardening; the barrier is injected because no public trace is known to reach it with all
/// global loss counters clear).
#[test]
fn issue438_insurance_withdrawal_respects_both_domain_barriers() {
    // Control: with no barrier the same two-domain withdrawal (150 > the long domain's 100)
    // succeeds, so a refusal below can only come from the barrier.
    let mut control = funded_env();
    let admin = control.admin.insecure_clone();
    let (_, cu) = control
        .try_withdraw_insurance_asset_with_authority(&admin, 0, 150)
        .expect("barrier-free withdrawal succeeds");
    eprintln!("issue438 control WithdrawInsuranceAsset CU = {cu}");
    // Run both sides before asserting, so a failure reports every side that is not blocked.
    let mut wrong = Vec::new();
    for short_side in [false, true] {
        let mut env = funded_env();
        market_with_barrier(&mut env, short_side);
        let admin = env.admin.insecure_clone();
        match env.try_withdraw_insurance_asset_with_authority(&admin, 0, 150) {
            Err(err) if custom_code(&err) == Some(ENGINE_LOCK_ACTIVE) => {}
            other => wrong.push(format!("short_side={short_side}: {other:?}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "a pending barrier must block the two-domain debit with EngineLockActive: {wrong:?}"
    );
}
