//! INV-045: one slot moves the mark toward its target by at most the cap of the
//! mark at which that target took effect.
//!
//! Ported from upstream percolator-prog `df29ce20` (batch 15, the new
//! `v16_attack_authority_reversal_after_a_long_walk_moves_within_the_cap_of_the_mark`
//! in `inv_045_no_free_mark_movement.rs`), adapted to this fork's `V16CuEnv`.
//! The fix is in the engine (upstream percolator `71076137`, our engine PR #389):
//! `set_asset_raw_oracle_targets_not_atomic`, which `PushAuthMark` uses to stage a
//! target, now restarts the price-cap anchor (`fund_px_last`) at the mark when the
//! target changes. `ENGINE_CI_SIBLING` `db019142` lacks it, so this test is RED on
//! the current pin and is ignored until the pin moves.
//!
//! The other three files `df29ce20` touches restate upstream INV-039/INV-045 test
//! models that this fork does not carry, so they are not ported.

use super::*;

fn crank_observations(asset_index: u16) -> Vec<CrankObservationHint> {
    vec![CrankObservationHint {
        asset_index,
        oracle_accounts: 0,
    }]
}

/// A crank that may have nothing to do: refusals are ignored, as upstream's
/// `crank_if_actionable` does.
fn crank_if_actionable(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64) {
    let _ = env.send(
        ProgInstruction::PermissionlessCrank {
            now_slot,
            observations: crank_observations(0),
        },
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
        ],
        &[],
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
    account.capital.get() as i128
        + account.pnl.get()
        + unsettled / (POS_SCALE as i128 * ADL_ONE as i128)
}

// The oracle authority walks an auth-mark asset with open interest from 1,000,000 toward 10,000
// (cap 24 bps per slot), with the price-cap anchor at 1,000,000 throughout. It then pushes a
// target equal to the mark, a new account opens a one-lot short at that mark with 2,000 of
// capital, and in the next slot the authority pushes 1,000,000 and a crank runs in the same slot.
// A changed target restarts the anchor at the mark, so that slot moves the mark by at most the
// cap of the mark at the push and the short keeps its capital less that move. With the walk's
// anchor kept, the slot moves the mark by anchor / mark times the cap and takes the short below
// zero.
#[test]
#[ignore = "RED on base: needs engine 71076137 (upstream percolator, our engine PR #389, INV-045); ENGINE_CI_SIBLING db019142 keeps the walk's price-cap anchor when PushAuthMark stages a new target"]
fn v16_attack_authority_reversal_after_a_long_walk_moves_within_the_cap_of_the_mark() {
    let p0: u64 = 1_000_000;
    let far: u64 = 10_000;
    let cap_bps: u64 = 24;
    let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams {
        initial_price: p0,
        max_price_move_bps_per_slot: cap_bps,
        max_accrual_dt_slots: 6,
        min_funding_lifetime_slots: 6,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        ..V16CuMarketParams::default()
    });
    env.svm.warp_to_slot(0);
    env.configure_auth_mark_with_cu(0, p0);
    let owners = [Keypair::new(), Keypair::new(), Keypair::new()];
    let long = funded_actor(&mut env, &owners[0], 1_000_000_000_000);
    let other = funded_actor(&mut env, &owners[1], 1_000_000_000_000);
    env.trade_with_cu(&owners[0], long, &owners[1], other, POS_SCALE as i128, p0, 0);
    env.push_auth_mark_with_cu(0, far);
    let step = p0 * cap_bps / 10_000;
    let mut slot = 0u64;
    while env.market_state().1.assets[0].effective_price > far + 2 * step {
        slot += 1;
        assert!(slot < 1_000, "the walk reaches the far target");
        env.svm.warp_to_slot(slot);
        for portfolio in [long, other] {
            crank_if_actionable(&mut env, portfolio, slot);
        }
    }
    let walked = env.market_state().1.assets[0];
    let mark = walked.effective_price;
    assert_eq!(walked.fund_px_last, p0, "one target, one anchor for the whole walk");
    assert!(p0 / mark > 70, "the walk ends far below its anchor");

    env.push_auth_mark_with_cu(slot, mark);
    let unlocked = env.market_state().1.assets[0];
    assert_eq!(
        (unlocked.raw_oracle_target_price, unlocked.effective_price),
        (mark, mark)
    );
    assert_eq!(
        unlocked.fund_px_last, mark,
        "a changed target restarts the price-cap anchor at the mark"
    );
    let short = funded_actor(&mut env, &owners[2], 2_000);
    env.trade_with_cu(&owners[0], long, &owners[2], short, POS_SCALE as i128, mark, 0);
    assert_eq!(short_value(&env, short), 2_000);

    slot += 1;
    env.svm.warp_to_slot(slot);
    env.push_auth_mark_with_cu(slot, p0);
    assert_eq!(env.market_state().1.assets[0].fund_px_last, mark);
    env.crank(
        long,
        ProgInstruction::PermissionlessCrank {
            now_slot: slot,
            observations: crank_observations(0),
        },
    );
    let reversed = env.market_state().1.assets[0];
    assert_eq!(reversed.slot_last, slot);
    let moved = reversed.effective_price - mark;
    assert!(moved > 0, "the mark moves toward the pushed target");
    assert!(
        moved * 10_000 <= mark * cap_bps + 9_999,
        "one slot moves the mark by at most the cap of the mark at the push: {mark} -> {}",
        reversed.effective_price
    );
    assert_eq!(short_value(&env, short), 2_000 - moved as i128);
}
