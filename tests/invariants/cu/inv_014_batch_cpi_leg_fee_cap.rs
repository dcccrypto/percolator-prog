//! #453 (upstream aeyakovenko/percolator-prog 9199d869): each BatchTradeCpi leg's signed
//! `fee_bps` is the taker's ceiling for the mutable base fee, whatever aggregate
//! `max_fee_atoms` the instruction carries (here `u128::MAX`, as the instruction builders pass).
//!
//! Equivalent to upstream's `v16_retained_batch_cpi_leg_fee_cap_rejects_policy_increase`,
//! built on this wrapper's `V16CuEnv` fixture (upstream's `inv018_public_spl_market` fixture
//! does not exist here). Base fee 19 bps, leg signed at 99, LP cap 137; the base fee is
//! raised to 100 after the taker signed. The retained instruction is rejected with
//! InvalidInstruction before the matcher is invoked, with exact rollback; a fresh leg signed
//! at 100 executes.

use super::*;

#[test]
fn v16_retained_batch_cpi_leg_fee_cap_rejects_policy_increase() {
    const OLD_BPS: u64 = 19;
    const SIGNED_BPS: u64 = 99;
    const NEW_BPS: u64 = 100;
    const LP_CAP_BPS: u16 = 137;
    const SIZE: i128 = 10 * POS_SCALE as i128;

    let mut sim = V16CuEnv::new();
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    sim.svm.add_program(matcher_program, &matcher_bytes);
    sim.update_trade_fee_policy_with_cu(OLD_BPS);

    let taker = Keypair::new();
    let lp = Keypair::new();
    let taker_account = sim.create_portfolio(&taker);
    let lp_account = sim.create_portfolio(&lp);
    sim.deposit(&taker, taker_account, 1_000_000);
    sim.deposit(&lp, lp_account, 1_000_000);
    let (ctx, delegate, _) = sim.init_matcher_context(&lp, matcher_program, lp_account);
    // LP consent sits above both the old and the new base fee: it must not mask the taker guard.
    sim.issue406_set_matcher_config(matcher_program, &lp, lp_account, ctx, delegate, 1, LP_CAP_BPS)
        .expect("LP authorizes its matcher with cap 137");
    assert_eq!(
        sim.issue406_matcher_config(lp_account).trade_fee_cap_bps(),
        LP_CAP_BPS
    );

    let accounts = vec![
        AccountMeta::new(taker.pubkey(), true),
        AccountMeta::new(sim.market, false),
        AccountMeta::new(taker_account, false),
        AccountMeta::new(lp_account, false),
        AccountMeta::new_readonly(matcher_program, false),
        AccountMeta::new(ctx, false),
        AccountMeta::new_readonly(delegate, false),
    ];
    let batch = |sim: &V16CuEnv, fee_bps: u64| {
        let (taker_portfolio_id, _, taker_position_epoch) = sim.portfolio_identity(taker_account);
        let (lp_portfolio_id, lp_matcher_sequence, lp_position_epoch) =
            sim.portfolio_identity(lp_account);
        ProgInstruction::BatchTradeCpi {
            account_a_portfolio_id: taker_portfolio_id,
            account_a_position_epoch: taker_position_epoch,
            account_b_portfolio_id: lp_portfolio_id,
            account_b_position_epoch: lp_position_epoch,
            account_b_matcher_sequence: lp_matcher_sequence,
            max_slippage_atoms: u128::MAX,
            max_fee_atoms: u128::MAX,
            legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                market_id: 1,
                asset_index: 0,
                size_q: SIZE,
                fee_bps,
                limit_price: 0,
            }],
        }
    };

    // Control: signed above the base fee, the leg executes (the ceiling is not over-strict).
    sim.svm.expire_blockhash();
    let control = batch(&sim, SIGNED_BPS);
    sim.send(control, accounts.clone(), &[&taker])
        .expect("a leg signed at 99 executes under a 19 bps base fee");

    // The base fee is raised after the taker signed 99.
    let policy_sequence = sim.control_sequences(0).trade_fee;
    sim.update_trade_fee_policy_with_cu(NEW_BPS);
    assert_eq!(sim.control_sequences(0).trade_fee, policy_sequence + 1);
    assert_eq!(sim.market_state().0.trade_fee_base_bps, NEW_BPS);
    assert_eq!(
        sim.issue406_matcher_config(lp_account).trade_fee_cap_bps(),
        LP_CAP_BPS,
        "LP consent stays above both policies"
    );

    let frame_keys = [sim.market, taker_account, lp_account, ctx, delegate, sim.vault];
    let frame = |sim: &V16CuEnv| frame_keys.map(|key| sim.svm.get_account(&key));
    let before = frame(&sim);
    sim.svm.expire_blockhash();
    let retained = batch(&sim, SIGNED_BPS);
    let rejection = sim
        .send(retained, accounts.clone(), &[&taker])
        .expect_err("a base fee above the signed leg fee_bps must reject");
    assert!(
        rejection.contains(&format!(
            "Custom({})",
            PercolatorError::InvalidInstruction as u32
        )),
        "base fee 100 > signed 99 must reject with InvalidInstruction: {rejection}"
    );
    assert_eq!(
        frame(&sim),
        before,
        "exact rollback of market, both portfolios, matcher context, delegate and vault \
         (an untouched context also proves the matcher CPI never ran)"
    );

    // Fresh consent exactly at the new base fee executes.
    sim.svm.expire_blockhash();
    let ins0 = sim.market_state().1.insurance;
    let fresh = batch(&sim, NEW_BPS);
    sim.send(fresh, accounts, &[&taker])
        .expect("a leg signed exactly at the new base fee executes");
    let (_, group) = sim.market_state();
    assert!(group.insurance > ins0, "the consented trade is charged");
    assert_eq!(group.vault, group.c_tot + group.insurance, "conservation");
}
