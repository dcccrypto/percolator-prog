//! INV-045: after an authority push reverses the target, one slot moves the mark by at most the
//! cap of the mark at the push.
//!
//! Adapted from upstream percolator-prog `df29ce20` (batch 15): its new
//! `v16_attack_authority_reversal_after_a_long_walk_moves_within_the_cap_of_the_mark` in
//! `inv_045_no_free_mark_movement.rs`. Upstream's bug was in the engine (fixed in upstream
//! percolator `71076137`, ported to our engine fork in engine PR #389). The staging setter
//! `set_asset_raw_oracle_targets_not_atomic` kept the price-cap anchor (`fund_px_last`) of the
//! earlier target. After a long walk the engine's path accrual could then move the mark by
//! anchor / mark times the per-slot cap in one slot.
//!
//! This fork's crank does not take that route. For an auth-mark or EWMA-mark asset,
//! `hybrid_effective_price_for_crank_view` caps each step from the asset's *current* effective
//! price (`oracle_v16::effective_price_from_target`). It then commits the step through the
//! single-segment accrual, which sets `fund_px_last` to the new mark on every priced step. The
//! anchor therefore follows the mark through the walk; upstream asserts it stays at the walk's
//! start. That single-segment accrual also refuses any step larger than the cap times `dt` of the
//! old mark (`RecoveryRequired`). The one wrapper route that reads `fund_px_last` as an anchor,
//! the zero-move funding hook (`accrue_asset_path_with_rent_to_not_atomic`), commits only when no
//! step changes the price, so it cannot move the mark. The engine setter on `db019142` still keeps
//! the old anchor; no priced crank step on this route reads it. So this test is GREEN on
//! `ENGINE_CI_SIBLING` `db019142` and with engine PR #389. It guards the property, so a future
//! sync cannot bring in a stale-anchor route unnoticed.
//!
//! One crank route does read the anchor since #793: a mark whose single-segment step floors to
//! 0 atoms is priced by the path accrual (`crank_accrue_asset_view`). That route never stages a
//! target through the setter while the asset has open interest. A changed target goes through
//! the path accrual itself (also for a same-slot crank), which restarts the anchor at the mark.
//! `v16_bpf_low_mark_reversal_restarts_the_cap_anchor` in `tests/v16_cu.rs` is this guard for it.
//!
//! Changes from upstream, because this harness runs the SBF program in a debug-mode runner:
//! - the walk cranks one account every 6 slots (the market's `max_accrual_dt_slots`) for 96
//!   slots, not both accounts every slot for 411 slots;
//! - the mark ends about 1.26x below the walk's start instead of 70x. A kept start anchor would
//!   still move the reversal slot about 26% more than the cap allows, far more than the
//!   one-unit rounding the check permits;
//! - the new short gets 100,000 of capital, about 12.6% of the notional at the walk's end (10%
//!   initial margin), instead of 2,000 at a mark near 14,000.
//!
//! The other three files `df29ce20` touches restate upstream INV-039/INV-045 test models that
//! this fork does not carry, so they are not ported.

use super::*;

fn crank_observations(asset_index: u16) -> Vec<CrankObservationHint> {
    vec![CrankObservationHint {
        asset_index,
        oracle_accounts: 0,
    }]
}

fn crank_asset_0(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64) {
    env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            now_slot,
            observations: crank_observations(0),
        },
    );
}

fn funded_actor(env: &mut V16CuEnv, owner: &Keypair, principal: u128) -> Pubkey {
    let portfolio = env.create_portfolio(owner);
    env.deposit(owner, portfolio, principal);
    portfolio
}

/// Capital + PnL + unsettled K of a short leg on asset 0.
fn short_value(env: &V16CuEnv, portfolio: Pubkey) -> i128 {
    let asset = env.market_state().1.assets[0];
    let account = env.portfolio_state(portfolio);
    let leg = active_leg_for_asset(&account, 0);
    let unsettled = leg.basis_pos_q.abs() * (asset.k_short - leg.k_snap);
    account.capital as i128 + account.pnl + unsettled / (POS_SCALE as i128 * ADL_ONE as i128)
}

// The oracle authority walks an auth-mark asset with open interest from 1,000,000 toward 10,000
// (cap 24 bps per slot). It then pushes a target equal to the mark (a risk-increasing trade is
// refused while they differ), and a new account opens a one-lot short at that mark. In the next
// slot the authority pushes 1,000,000 and a crank runs in the same slot, as one transaction can
// carry both. That slot moves the mark by at most the cap of the mark at the push, and the short
// keeps its capital less that move.
#[test]
fn v16_attack_authority_reversal_after_a_long_walk_moves_within_the_cap_of_the_mark() {
    let p0: u64 = 1_000_000;
    let far: u64 = 10_000;
    let cap_bps: u64 = 24;
    let dt: u64 = 6;
    let short_principal: u128 = 100_000;
    let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams {
        initial_price: p0,
        max_price_move_bps_per_slot: cap_bps,
        max_accrual_dt_slots: dt,
        min_funding_lifetime_slots: dt,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        ..V16CuMarketParams::default()
    });
    env.svm.warp_to_slot(0);
    env.configure_auth_mark_with_cu(0, p0);
    let owners = [Keypair::new(), Keypair::new(), Keypair::new()];
    let long = funded_actor(&mut env, &owners[0], 1_000_000_000_000);
    let other = funded_actor(&mut env, &owners[1], 1_000_000_000_000);
    env.trade_with_cu(
        &owners[0],
        long,
        &owners[1],
        other,
        POS_SCALE as i128,
        p0,
        0,
    );
    env.push_auth_mark_with_cu(0, far);

    let mut slot = 0u64;
    while slot < 96 {
        slot += dt;
        env.svm.warp_to_slot(slot);
        crank_asset_0(&mut env, long, slot);
        let asset = env.market_state().1.assets[0];
        assert_eq!(asset.slot_last, slot, "each crank catches the asset up");
        // This fork's crank caps each step from the current mark and restarts the anchor there.
        assert_eq!(
            asset.fund_px_last, asset.effective_price,
            "this fork's crank restarts the anchor at each priced step; if the crank route \
             changed (e.g. upstream's path accrual was adopted), re-derive this guard"
        );
    }
    let walked = env.market_state().1.assets[0];
    let mark = walked.effective_price;
    assert_eq!(walked.raw_oracle_target_price, far);
    assert!(
        mark * 5 < p0 * 4,
        "the walk ends well below its start, so a kept start anchor would show: {mark}"
    );

    // The walk cranked one account; refresh its counterparty before the next trade.
    env.svm.expire_blockhash();
    crank_asset_0(&mut env, other, slot);

    // This fork's PushAuthMark writes the oracle profile; a crank stages it as the engine target.
    // A risk-increasing trade is refused while the engine target and the mark differ.
    env.push_auth_mark_with_cu(slot, mark);
    env.svm.expire_blockhash();
    crank_asset_0(&mut env, long, slot);
    let unlocked = env.market_state().1.assets[0];
    assert_eq!(
        (unlocked.raw_oracle_target_price, unlocked.effective_price),
        (mark, mark)
    );
    assert_eq!(unlocked.fund_px_last, mark, "the anchor is still the mark");
    let short = funded_actor(&mut env, &owners[2], short_principal);
    env.trade_with_cu(
        &owners[0],
        long,
        &owners[2],
        short,
        POS_SCALE as i128,
        mark,
        0,
    );
    assert_eq!(short_value(&env, short), short_principal as i128);

    slot += 1;
    env.svm.warp_to_slot(slot);
    env.push_auth_mark_with_cu(slot, p0);
    assert_eq!(env.market_state().1.assets[0].fund_px_last, mark);
    crank_asset_0(&mut env, long, slot);
    let reversed = env.market_state().1.assets[0];
    assert_eq!(reversed.slot_last, slot);
    let moved = reversed.effective_price - mark;
    assert!(moved > 0, "the mark moves toward the pushed target");
    assert!(
        moved * 10_000 <= mark * cap_bps + 9_999,
        "one slot moves the mark by at most the cap of the mark at the push: {mark} -> {}",
        reversed.effective_price
    );
    assert_eq!(
        short_value(&env, short),
        short_principal as i128 - moved as i128
    );
}
