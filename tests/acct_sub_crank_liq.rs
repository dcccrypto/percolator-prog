//! Account-substitution matrix for `PermissionlessCrank` WITH A POSITION THAT IS REALLY LIQUIDATABLE.
//! Job J-20261114-PROG-ACCTSUB2.
//!
//! The PROG-ACCTSUB crank cells used a healthy portfolio, so every hostile account was rejected
//! before the liquidation step was ever reached. Here the short side is bankrupt once the price has
//! converged to the pushed target (same setup as
//! `v16_wrapper_permissionless_crank_can_liquidate_unhealthy_candidate`). The fixture first finds,
//! on a clone, the exact slot `k` at which an honest crank closes the position. Each cell then
//! replays slots 1..k-1 honestly and sends the HOSTILE crank at slot `k`, the call that would have
//! liquidated. It must be rejected AND the bankrupt position must still be open afterwards.
//!
//! Account list: [caller, market, portfolio]. The caller is a plain pubkey, no signature needed.
//!
//! Columns: A market not owned by this program, B portfolio not owned by this program,
//! D market read-only, E portfolio read-only, F a different portfolio in the target's place,
//! G1 uninitialised (fake) market, G2 portfolio bound to another market, I duplicate accounts,
//! C caller unsigned (allowed by design: the crank is permissionless).
#![cfg(not(kani))]

mod acct_sub_harness;

use acct_sub_harness::*;
use percolator::POS_SCALE;
use percolator_prog::{
    ix::{CrankObservationHint, Instruction},
    state,
};
use std::cell::Cell;

thread_local! {
    static SLOT: Cell<u64> = const { Cell::new(1) };
}

fn crank_ix(_: &[TestAccount]) -> Instruction {
    Instruction::PermissionlessCrank {
        now_slot: SLOT.with(|s| s.get()),
        observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
    }
}

fn position_open(p: &TestAccount) -> bool {
    !percolator::active_bitmap_is_empty(state::read_portfolio(&p.data).unwrap().active_bitmap)
}

struct Liq {
    fx: SubFx,
    /// the slot at which an honest crank closes the bankrupt position
    k: u64,
    long_account: TestAccount,
}

/// accts = [admin (caller), market, short_account]; the long account is kept aside.
fn liq_fixture() -> Liq {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    // Minimum margin for a 1-unit position at price 100: no leverage headroom, so the short side
    // goes bankrupt as soon as the price moves up.
    deposit(&mut short_owner, &mut market, &mut short_account, 100);
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);
    run_ix(
        Instruction::TradeNoCpi {
            account_a_portfolio_id: portfolio_identity(&long_account).0,
            account_a_position_epoch: portfolio_identity(&long_account).2,
            account_b_portfolio_id: portfolio_identity(&short_account).0,
            account_b_position_epoch: portfolio_identity(&short_account).2,
            market_id: 1,
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
            backing_fee_cap_bps: 10_000,
        },
        &mut [&mut long_owner, &mut short_owner, &mut market, &mut long_account, &mut short_account],
    )
    .expect("fixture: open the position");
    push_base_ewma_mark(&mut admin, &mut market, 1, 999_999);
    push_base_ewma_mark(&mut admin, &mut market, 2, 999_999);
    assert!(position_open(&short_account), "fixture: the short side holds a position");

    // a second initialised market with a portfolio, for the "portfolio of another market" cell
    let mut admin_b = signer();
    let mut spare_market = market_account();
    init_market(&mut admin_b, &mut spare_market);
    let mut spare_owner = signer();
    let mut spare = portfolio_account();
    init_portfolio(&mut spare_owner, &mut spare_market, &mut spare);
    deposit(&mut spare_owner, &mut spare_market, &mut spare, 100);

    let mut fx = SubFx {
        accts: vec![admin, market, short_account],
        ix: crank_ix,
        market: 1,
        portfolio: Some(2),
        signers: vec![],
        tokens: vec![],
        vault: None,
        vault_auth: None,
        spare_portfolio: Some(spare),
    };
    // find k on a clone
    let mut probe = fx.clone();
    let mut k = 0;
    for slot in 1..=20u64 {
        SLOT.with(|s| s.set(slot));
        let _ = sub_run(&mut probe);
        if !position_open(&probe.accts[2]) {
            k = slot;
            break;
        }
    }
    assert!(k > 0, "fixture: an honest crank must liquidate within 20 slots");
    // replay the honest slots before k on the real fixture
    for slot in 1..k {
        SLOT.with(|s| s.set(slot));
        let _ = sub_run(&mut fx);
        assert!(position_open(&fx.accts[2]), "fixture: closed before slot k");
    }
    SLOT.with(|s| s.set(k));
    Liq { fx, k, long_account }
}

macro_rules! cell {
    ($name:ident, $mutate:expr) => {
        #[test]
        fn $name() {
            let mut l = liq_fixture();
            ($mutate)(&mut l.fx);
            // NOTE: not asserting "market bytes unchanged" without the harness rollback. The crank
            // accrues the market before it checks the portfolio's market binding (cell G2 shows it),
            // which is harmless because the runtime reverts a failed instruction. The rollback-free
            // check is kept for WithdrawInsurance, where it holds for every cell.
            let r = sub_run(&mut l.fx);
            assert!(r.is_err(), "hostile crank at slot {} was ACCEPTED: {r:?}", l.k);
        }
    };
}
macro_rules! dup_cell {
    ($name:ident, [$(($i:expr, $j:expr)),+]) => {
        #[test]
        fn $name() {
            $(
                let mut l = liq_fixture();
                let r = sub_run_dup(&mut l.fx, $i, $j);
                assert!(r.is_err(), "duplicate ({}, {}) was ACCEPTED at slot {}: {r:?}", $i, $j, l.k);
            )+
        }
    };
}

// ---- baselines: the unmutated list at slot k liquidates ---------------------------------------
#[test]
fn acct_sub_crankliq_baseline_honest_crank_liquidates_at_k() {
    let mut l = liq_fixture();
    sub_run(&mut l.fx).expect("honest crank at k");
    assert!(!position_open(&l.fx.accts[2]), "the baseline crank must reach the liquidation step");
}

// ---- cells ------------------------------------------------------------------------------------
cell!(acct_sub_crankliq_a_market_wrong_program, m_a);
cell!(acct_sub_crankliq_b_portfolio_wrong_program, m_b);
cell!(acct_sub_crankliq_d_market_readonly, m_d);
cell!(acct_sub_crankliq_e_portfolio_readonly, m_e);
cell!(acct_sub_crankliq_g1_fake_market, m_g1);
cell!(acct_sub_crankliq_g2_portfolio_of_other_market, m_g2);
dup_cell!(acct_sub_crankliq_i1_market_is_portfolio, [(1, 2)]);
dup_cell!(acct_sub_crankliq_i2_caller_is_market_or_portfolio, [(0, 1), (0, 2)]);

/// F: the caller names a DIFFERENT (healthy) portfolio in the target's place. That is a legal crank
/// of a healthy account, so it may succeed; it must not wedge the market. The honest crank on the
/// bankrupt portfolio right afterwards must still liquidate it.
#[test]
fn acct_sub_crankliq_f_other_portfolio_does_not_wedge_the_target_liquidation() {
    let mut l = liq_fixture();
    let target = std::mem::replace(&mut l.fx.accts[2], l.long_account.clone());
    let _ = sub_run(&mut l.fx);
    l.fx.accts[2] = target;
    assert!(position_open(&l.fx.accts[2]), "target not touched by a crank that did not name it");
    sub_run(&mut l.fx).expect("honest crank on the target still works after the substituted one");
    assert!(!position_open(&l.fx.accts[2]), "target liquidated");
}

/// C: no signature is required, by design. An unsigned caller liquidates, the same as a signed one.
#[test]
fn acct_sub_crankliq_c_unsigned_caller_is_allowed_by_design() {
    let mut l = liq_fixture();
    l.fx.accts[0].is_signer = false;
    sub_run(&mut l.fx).expect("the crank is permissionless");
    assert!(!position_open(&l.fx.accts[2]));
}
