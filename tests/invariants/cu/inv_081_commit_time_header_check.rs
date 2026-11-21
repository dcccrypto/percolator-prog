//! INV-081: a market header that fails a shape check cannot be committed by a crank or by
//! RebalanceReduce.
//!
//! Ported from aeyakovenko/percolator-prog `fdd2519c` (#485,
//! `tests/invariants/cu/inv_081_commit_time_header_check.rs`). Adapted to this repo's layout:
//! the module is mounted from `tests/v16_cu.rs` (so `super::*`, not `super::super::*`), the
//! position binding is read with `portfolio_identity`, and the crank observation helper is local.
//!
//! The engine's refresh, B-chunk, pending-close and rebalance transitions validate the market
//! shape only in audit builds, and the program used to repeat the check after a crank only on the
//! cranker-reward path or after a liquidation. A header that failed a check after a plain refresh
//! crank would have been committed, and every later instruction that does validate would then
//! fail. No such state is known. This test pins the backstop: both instructions validate the
//! header before they commit. (RebalanceReduce already did here: this fork's
//! `with_one_portfolio_view` never had upstream's `wrapper_post_validate` flag and validates the
//! header for every caller. The test keeps it covered.)
//!
//! The fault is a harness input: one header total that only `validate_shape` reads is raised by
//! one unit in the market account, which nothing in the engine does. Everything else is public
//! System, SPL and program setup. Upstream's control (its first test below) fails on its previous
//! program. In this fork it passes there too, because an observed crank validates the header when
//! it stages the oracle target, before any engine work; the second, fork-specific test reaches the
//! commit-time check through an observation-free refresh crank, and that one fails on the program
//! before this port (the crank commits the fixture).

use super::*;
use percolator_prog::constants::MARKET_GROUP_OFF;

fn crank_observations(asset_index: u16) -> Vec<CrankObservationHint> {
    vec![CrankObservationHint {
        asset_index,
        oracle_accounts: 0,
    }]
}

fn header_shape(env: &V16CuEnv) -> Result<(), percolator::V16Error> {
    let mut data = env
        .svm
        .get_account(&env.market)
        .expect("market account")
        .data;
    let (_, group) = state::market_view_mut(&mut data).expect("market view");
    group.validate_shape()
}

fn header_u128(data: &[u8], field_offset: usize) -> u128 {
    let start = MARKET_GROUP_OFF + field_offset;
    u128::from_le_bytes(data[start..start + 16].try_into().unwrap())
}

#[test]
fn v16_program_crank_and_rebalance_reduce_cannot_commit_a_header_that_fails_a_shape_check() {
    const CAPITAL: u128 = 10_000;
    const OPEN_Q: u128 = 2 * POS_SCALE;

    let mut env = V16CuEnv::new();
    env.configure_auth_mark_with_cu(0, 100);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long = env.create_portfolio(&long_owner);
    let short = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long, CAPITAL);
    env.deposit(&short_owner, short, CAPITAL);
    env.trade_asset_with_cu(
        0,
        &long_owner,
        long,
        &short_owner,
        short,
        OPEN_Q as i128,
        100,
        0,
    );
    assert_eq!(header_shape(&env), Ok(()));

    let crank_slot = env.svm.get_sysvar::<Clock>().slot + 1;
    env.svm.warp_to_slot(crank_slot);
    let crank = ProgInstruction::PermissionlessCrank {
        now_slot: crank_slot,
        observations: crank_observations(0),
    };
    let crank_accounts = |env: &V16CuEnv| {
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(short, false),
        ]
    };
    let reduce = |env: &V16CuEnv| {
        let (portfolio_id, _, position_epoch) = env.portfolio_identity(long);
        ProgInstruction::RebalanceReduce {
            portfolio_id,
            position_epoch,
            asset_index: 0,
            reduce_q: OPEN_Q / 4,
        }
    };
    let reduce_accounts = |env: &V16CuEnv| {
        vec![
            AccountMeta::new(long_owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(long, false),
        ]
    };

    // The fixture: `source_claim_bound_total_num` one unit above `pnl_pos_bound_tot_num`. Only the
    // header check reads the relation between the two (the junior bound must cover the source
    // claims); no transition below reads either field.
    let canonical = env.svm.get_account(&env.market).expect("market account");
    let bound = header_u128(
        &canonical.data,
        core::mem::offset_of!(
            percolator::MarketGroupV16HeaderAccount,
            pnl_pos_bound_tot_num
        ),
    );
    let mut broken = canonical.clone();
    let field = MARKET_GROUP_OFF
        + core::mem::offset_of!(
            percolator::MarketGroupV16HeaderAccount,
            source_claim_bound_total_num
        );
    broken.data[field..field + 16].copy_from_slice(&(bound + 1).to_le_bytes());
    let rejected = format!("Custom({})", PercolatorError::EngineInvalidConfig as u32);

    for (label, is_crank) in [("crank", true), ("rebalance reduce", false)] {
        env.svm
            .set_account(env.market, broken.clone())
            .expect("install the header fixture");
        assert_eq!(header_shape(&env), Err(percolator::V16Error::InvalidConfig));
        let before = [env.market, long, short].map(|key| env.svm.get_account(&key));
        env.svm.expire_blockhash();
        let result = if is_crank {
            let accounts = crank_accounts(&env);
            env.send(crank.clone(), accounts, &[])
        } else {
            let (ix, accounts) = (reduce(&env), reduce_accounts(&env));
            env.send(ix, accounts, &[&long_owner])
        };
        let error = result.expect_err(&format!("{label} must not commit the fixture"));
        assert!(
            error.contains(&rejected),
            "{label} must fail on the header check: {error}"
        );
        assert_eq!(
            [env.market, long, short].map(|key| env.svm.get_account(&key)),
            before,
            "{label} must roll back exactly"
        );
    }

    // The same two instructions on the market as public instructions left it: both succeed, the
    // crank leaves the position vector alone, and the header still passes.
    env.svm
        .set_account(env.market, canonical)
        .expect("restore the canonical market");
    let positions_before =
        [long, short].map(|key| active_leg_for_asset(&env.portfolio_state(key), 0));
    env.svm.expire_blockhash();
    let accounts = crank_accounts(&env);
    let crank_cu = env
        .send(crank.clone(), accounts, &[])
        .expect("crank on the canonical market");
    assert_eq!(
        [long, short].map(|key| active_leg_for_asset(&env.portfolio_state(key), 0)),
        positions_before,
        "this crank is the case that used to commit without a header check"
    );
    assert_eq!(header_shape(&env), Ok(()));
    env.svm.expire_blockhash();
    let (ix, accounts) = (reduce(&env), reduce_accounts(&env));
    let reduce_cu = env
        .send(ix, accounts, &[&long_owner])
        .expect("rebalance reduce on the canonical market");
    assert_eq!(header_shape(&env), Ok(()));
    println!("INV-081 CU: refresh crank (no position change) {crank_cu}, RebalanceReduce {reduce_cu}");
}

/// Fork-specific companion. In this fork a crank that carries an oracle observation stages the
/// asset's raw oracle target first (`set_asset_raw_oracle_target_not_atomic`), and that engine
/// call ends in `validate_shape`, so a header that was already bad when the crank started is
/// refused before any engine work, and the upstream test above passes on the program before this
/// port as well. What the commit-time check adds is a check AFTER the engine's refresh. This test
/// reaches that point: an observation-free crank (the F1 follow-on form) refreshes an account
/// whose asset another crank has already advanced, so nothing before the engine validates the
/// header. Control: on the program before this port the crank commits the fixture.
#[test]
fn v16_program_observation_free_refresh_crank_cannot_commit_a_header_that_fails_a_shape_check() {
    const CAPITAL: u128 = 10_000;
    const OPEN_Q: u128 = 2 * POS_SCALE;

    let mut env = V16CuEnv::new();
    env.configure_auth_mark_with_cu(0, 100);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long = env.create_portfolio(&long_owner);
    let short = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long, CAPITAL);
    env.deposit(&short_owner, short, CAPITAL);
    env.trade_asset_with_cu(
        0,
        &long_owner,
        long,
        &short_owner,
        short,
        OPEN_Q as i128,
        100,
        0,
    );

    // Move the mark and advance the asset with an observed crank of the long. The short's leg is
    // now behind its asset's K index, so a crank of it has a real refresh to do.
    let crank_slot = env.svm.get_sysvar::<Clock>().slot + 1;
    env.svm.warp_to_slot(crank_slot);
    env.push_auth_mark_for_asset_as_admin(0, crank_slot, 101);
    env.send(
        ProgInstruction::PermissionlessCrank {
            now_slot: crank_slot,
            observations: crank_observations(0),
        },
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(long, false),
        ],
        &[],
    )
    .expect("observed crank of the long");
    assert_eq!(header_shape(&env), Ok(()));

    let refresh = ProgInstruction::PermissionlessCrank {
        now_slot: crank_slot,
        observations: vec![],
    };
    let refresh_accounts = |env: &V16CuEnv| {
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(short, false),
        ]
    };

    // Same fixture as the upstream test.
    let canonical = env.svm.get_account(&env.market).expect("market account");
    let bound = header_u128(
        &canonical.data,
        core::mem::offset_of!(
            percolator::MarketGroupV16HeaderAccount,
            pnl_pos_bound_tot_num
        ),
    );
    let mut broken = canonical.clone();
    let field = MARKET_GROUP_OFF
        + core::mem::offset_of!(
            percolator::MarketGroupV16HeaderAccount,
            source_claim_bound_total_num
        );
    broken.data[field..field + 16].copy_from_slice(&(bound + 1).to_le_bytes());
    env.svm
        .set_account(env.market, broken)
        .expect("install the header fixture");
    assert_eq!(header_shape(&env), Err(percolator::V16Error::InvalidConfig));
    let before = [env.market, long, short].map(|key| env.svm.get_account(&key));
    env.svm.expire_blockhash();
    let accounts = refresh_accounts(&env);
    let error = env
        .send(refresh.clone(), accounts, &[])
        .expect_err("an observation-free refresh crank must not commit the fixture");
    assert!(
        error.contains(&format!(
            "Custom({})",
            PercolatorError::EngineInvalidConfig as u32
        )),
        "the refresh crank must fail on the header check: {error}"
    );
    assert_eq!(
        [env.market, long, short].map(|key| env.svm.get_account(&key)),
        before,
        "the refresh crank must roll back exactly"
    );

    // On the canonical market the same crank is a real refresh step: it succeeds, settles the
    // short's leg to its asset's K index, and leaves the position vector alone.
    env.svm
        .set_account(env.market, canonical)
        .expect("restore the canonical market");
    let position = |env: &V16CuEnv| {
        [long, short].map(|key| {
            let leg = active_leg_for_asset(&env.portfolio_state(key), 0);
            (leg.side, leg.basis_pos_q)
        })
    };
    let positions_before = position(&env);
    let short_k_before = active_leg_for_asset(&env.portfolio_state(short), 0).k_snap;
    env.svm.expire_blockhash();
    let accounts = refresh_accounts(&env);
    let refresh_cu = env
        .send(refresh, accounts, &[])
        .expect("observation-free refresh crank on the canonical market");
    assert_ne!(
        active_leg_for_asset(&env.portfolio_state(short), 0).k_snap,
        short_k_before,
        "the crank refreshed the short"
    );
    assert_eq!(position(&env), positions_before, "the refresh moved no position");
    assert_eq!(header_shape(&env), Ok(()));
    println!("INV-081 CU: observation-free refresh crank {refresh_cu}");
}
