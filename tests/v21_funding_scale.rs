//! fix/v21-funding-scale -- wrapper LiteSVM acceptance.
//!
//! Phase 3 rehearsal finding (v2.1 wrapper c493bbc0): with funding > 0 every accrual opens a
//! K/F settlement cohort over EVERY positioned portfolio, and the engine refused any
//! risk-increasing order (Custom 121 EngineLossStale) until all of them were refreshed in the
//! order's own slot: `[push, LP observation crank, refresh x N, order]`, ~114k CU per refresh,
//! so a market capped out near 8 positioned accounts.
//!
//! With the fix the order needs only its own same-slot accrual, `[push, LP crank, order]`,
//! whenever the worst-case loss the stale portfolios could still recognize is covered by the
//! insurance that would absorb it. These tests run the v2.1 production shape (bound vault LP,
//! skew funding > 0, canonical matcher) with 55 positioned portfolios.
//!
//! Run: INDEP_WRAPPER_SO=<wrapper .so> cargo test --features devnet --test v21_funding_scale -- --nocapture
#![cfg(not(kani))]
#![allow(dead_code, clippy::all)]
mod indep_harness;

use indep_harness::*;
use percolator::POS_SCALE;
use percolator_prog::{ix::CrankObservationHint, ix::Instruction as ProgInstruction, state};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const PRICE: u64 = 1_000_000;
const N_POSITIONED: usize = 55;
const LOSS_STALE: u32 = 121;

struct W {
    env: V16CuEnv,
    matcher: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    ledger0: Pubkey,
    ledger1: Pubkey,
    state_pda: Pubkey,
    lp: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
    upgrade: Keypair,
    program_data: Pubkey,
}

fn raw(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(body);
    v
}

fn params() -> V16CuMarketParams {
    V16CuMarketParams {
        h_max: 50,
        initial_price: PRICE,
        min_nonzero_mm_req: 599,
        min_nonzero_im_req: 600,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        liquidation_fee_bps: 0,
        liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
        max_price_move_bps_per_slot: 20,
        max_accrual_dt_slots: 20,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 10_000_000,
        ..V16CuMarketParams::default()
    }
}

impl W {
    fn new() -> Self {
        let mut env = V16CuEnv::new_with_init_params(params());
        let matcher: Pubkey = "DfTxJUT5BbERs1tR33dP82kaUJ1NLymRxXErXAYXcDam".parse().unwrap();
        let bytes = std::fs::read(matcher_program_path()).expect("matcher so");
        env.svm.add_program(matcher, &bytes);
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
        let pid = env.program_id;
        let market = env.market;
        let (registry, _) = state::derive_lp_vault_registry(&pid, &market);
        let (lp_mint, _) = state::derive_lp_vault_mint(&pid, &market);
        let ledger0 = state::derive_lp_backing_ledger(&pid, &market, 0).0;
        let ledger1 = state::derive_lp_backing_ledger(&pid, &market, 1).0;
        let state_pda = Pubkey::find_program_address(&[b"vault_lp", market.as_ref()], &pid).0;
        let upgrade = Keypair::new();
        env.svm.airdrop(&upgrade.pubkey(), 1_000_000_000).unwrap();
        let program_data = Pubkey::find_program_address(&[pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(upgrade.pubkey().as_ref());
        env.svm
            .set_account(program_data, Account { lamports: 1_000_000_000, data: pd, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 })
            .unwrap();
        W { env, matcher, registry, lp_mint, ledger0, ledger1, state_pda, lp: Pubkey::default(), ctx: Pubkey::default(), delegate: Pubkey::default(), upgrade, program_data }
    }

    fn send(&mut self, ix: ProgInstruction, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        self.env.send(ix, metas, signers)
    }

    fn send_raw(&mut self, data: Vec<u8>, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let ix = Instruction { program_id: self.env.program_id, accounts: metas, data };
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, signers)
    }

    /// One transaction: heap + 1.4M CU limit + `ixs`. Returns total CU or the error string.
    fn bundle(&mut self, ixs: Vec<Instruction>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let payer = self.env.payer.insecure_clone();
        let mut all = vec![heap_ix(), cu_ix()];
        all.extend(ixs);
        let mut s: Vec<&Keypair> = vec![&payer];
        s.extend_from_slice(signers);
        let tx = Transaction::new_signed_with_payer(&all, Some(&payer.pubkey()), &s, self.env.svm.latest_blockhash());
        self.env.svm.send_transaction(tx).map(|m| m.compute_units_consumed).map_err(|e| format!("{e:?}"))
    }

    fn ix(&self, ix: ProgInstruction, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction { program_id: self.env.program_id, accounts, data: ix.encode() }
    }

    fn slot(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    fn token(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        self.env.token_account_for_mint(self.env.mint, owner, amount)
    }

    fn create_vault(&mut self) {
        let admin = self.env.admin.insecure_clone();
        let (m, r, mint) = (self.env.market, self.registry, self.lp_mint);
        self.send(
            ProgInstruction::CreateLpVault { fee_share_bps: 0, redemption_cooldown_slots: 0, oi_reservation_threshold_bps: 0, domain: 0 },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(r, false),
                AccountMeta::new(mint, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(self.env.mint, false), // [6] collateral mint (prog#542)
            ],
            &[&admin],
        )
        .expect("74 CreateLpVault");
    }

    fn earn_deposit(&mut self, who: &Keypair, amount: u64) {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self.env.token_account_for_mint(self.lp_mint, who.pubkey(), 0);
        let src = self.token(who.pubkey(), amount);
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(ata, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.ledger1, false),
        ];
        self.send(ProgInstruction::DepositToLpVault { amount: amount as u128, domain: 0 }, metas, &[who]).expect("75 senior deposit");
    }

    fn init_vault_lp(&mut self) {
        let signer = self.env.admin.insecure_clone();
        let lp = Pubkey::new_unique();
        let len = self.env.portfolio_account_len;
        let pid = self.env.program_id;
        self.env.svm.set_account(lp, Account { lamports: 1_000_000_000, data: vec![0; len], owner: pid, executable: false, rent_epoch: 0 }).unwrap();
        self.lp = lp;
        let ctx = Pubkey::new_unique();
        self.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher, executable: false, rent_epoch: 0 }).unwrap();
        let delegate = Pubkey::find_program_address(
            &[b"matcher", self.env.market.as_ref(), lp.as_ref(), self.registry.as_ref(), self.matcher.as_ref(), ctx.as_ref()],
            &self.env.program_id,
        )
        .0;
        self.env.svm.set_account(delegate, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
        self.ctx = ctx;
        self.delegate = delegate;
        let metas = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
            AccountMeta::new_readonly(self.matcher, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        self.send_raw(raw(94, &2_000u16.to_le_bytes()), metas, &[&signer]).expect("94 InitVaultLp");
    }

    /// 99 SetVaultLpRisk with skew funding ON (slope, max <= max_abs_funding).
    fn set_risk_with_skew(&mut self, slope_e9: u64, max_e9: u64) {
        let up = self.upgrade.insecure_clone();
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&slope_e9.to_le_bytes());
        b.extend_from_slice(&max_e9.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(self.matcher.as_ref());
        let metas = vec![AccountMeta::new(up.pubkey(), true), AccountMeta::new_readonly(self.program_data, false), AccountMeta::new(self.env.market, false)];
        self.send_raw(raw(99, &b), metas, &[&up]).expect("99 SetVaultLpRisk");
    }

    fn junior_deposit(&mut self, amount: u64) {
        let who = self.env.admin.insecure_clone();
        let src = self.token(who.pubkey(), amount);
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(self.lp, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        self.send_raw(raw(96, &(amount as u128).to_le_bytes()), metas, &[&who]).expect("96 junior");
    }

    fn trader(&mut self, capital: u64) -> (Keypair, Pubkey) {
        let k = Keypair::new();
        let p = self.env.create_portfolio(&k);
        let src = self.token(k.pubkey(), capital);
        let (pid, seq, _) = self.env.portfolio_identity(p);
        let (m, v) = (self.env.market, self.env.vault);
        self.send(
            ProgInstruction::Deposit { portfolio_id: pid, expected_sequence: seq, amount: capital as u128 },
            vec![
                AccountMeta::new(k.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
                AccountMeta::new(src, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&k],
        )
        .expect("trader deposit");
        (k, p)
    }

    fn trade_ix(&self, taker: &Keypair, tp: Pubkey, size_q: i128) -> Instruction {
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
        self.ix(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id: 1,
                account_b_matcher_sequence: bseq,
                asset_index: 0,
                size_q,
                fee_bps: 0,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(self.lp, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(self.ctx, false),
                AccountMeta::new_readonly(self.delegate, false),
            ],
        )
    }

    fn push_ix(&self, slot: u64, mark: u64) -> Instruction {
        let seq = self.env.control_sequences(0).oracle_observation + 1;
        self.ix(
            ProgInstruction::PushAuthMark { market_id: 1, asset_index: 0, now_slot: slot, mark_e6: mark, observation_sequence: seq },
            vec![AccountMeta::new(self.env.admin.pubkey(), true), AccountMeta::new(self.env.market, false)],
        )
    }

    /// LP observation crank: accrues the asset to `slot` (the keeper's per-slot step).
    fn lp_crank_ix(&self, slot: u64) -> Instruction {
        self.ix(
            ProgInstruction::PermissionlessCrank { now_slot: slot, observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] },
            vec![AccountMeta::new(self.env.payer.pubkey(), true), AccountMeta::new(self.env.market, false), AccountMeta::new(self.lp, false)],
        )
    }

    /// Refresh crank (no observation) of one portfolio: the keeper's positioned-refresh.
    fn refresh_ix(&self, p: Pubkey) -> Instruction {
        self.ix(
            ProgInstruction::PermissionlessCrank { now_slot: 0, observations: vec![] },
            vec![AccountMeta::new(self.env.payer.pubkey(), true), AccountMeta::new(self.env.market, false), AccountMeta::new(p, false)],
        )
    }

    /// Advance one slot and accrue: [push, LP crank] in one tx.
    fn tick(&mut self) -> u64 {
        let s = self.slot() + 1;
        self.env.svm.warp_to_slot(s);
        let admin = self.env.admin.insecure_clone();
        let ixs = vec![self.push_ix(s, PRICE), self.lp_crank_ix(s)];
        self.bundle(ixs, &[&admin]).expect("push + LP crank")
    }

    fn stale(&self) -> (u64, u64) {
        let a = &self.env.market_state().1.assets[0];
        (a.stale_account_count_long, a.stale_account_count_short)
    }

    fn insurance(&self) -> u128 {
        self.env.market_state().1.insurance
    }
}

/// v2.1 production shape: bound vault LP (seniors + junior), skew funding on, `n` traders each
/// long one unit against the LP, then one more slot so funding opens a cohort over everyone.
fn positioned_market(n: usize, insurance: u128) -> (W, Vec<(Keypair, Pubkey)>) {
    positioned_market_with(n, insurance, 1_000, 1_000)
}

fn positioned_market_with(n: usize, insurance: u128, slope_e9: u64, max_e9: u64) -> (W, Vec<(Keypair, Pubkey)>) {
    let mut w = W::new();
    w.create_vault();
    let seniors: Vec<Keypair> = (0..2).map(|_| Keypair::new()).collect();
    for s in &seniors {
        w.earn_deposit(s, 200_000_000_000);
    }
    w.init_vault_lp();
    w.set_risk_with_skew(slope_e9, max_e9);
    w.junior_deposit(50_000_000_000);
    if insurance != 0 {
        w.env.top_up_insurance(insurance);
    }
    w.tick();
    let mut traders = Vec::with_capacity(n);
    for _ in 0..n {
        let (k, p) = w.trader(1_000_000);
        // All opens land in one slot: one accrual, no cohort between them.
        let ix = w.trade_ix(&k, p, POS_SCALE as i128);
        w.bundle(vec![ix], &[&k]).expect("setup open (same slot, no cohort)");
        traders.push((k, p));
    }
    // Next slot: skew funding accrues (LP is short n units) -> every positioned portfolio stale.
    w.tick();
    let (sl, ss) = w.stale();
    assert_eq!(sl, n as u64, "funding re-stales every long");
    // The LP observation crank settles the vault LP's own leg in the same tx.
    assert_eq!(ss, 0, "the vault LP short is settled by its own observation crank");
    (w, traders)
}

fn entrant_order(w: &mut W) -> (Keypair, Pubkey, Result<u64, String>) {
    let (k, p) = w.trader(1_000_000);
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    let admin = w.env.admin.insecure_clone();
    let ixs = vec![w.push_ix(s, PRICE), w.lp_crank_ix(s), w.trade_ix(&k, p, POS_SCALE as i128)];
    let r = w.bundle(ixs, &[&admin, &k]);
    (k, p, r)
}

#[test]
fn v21_opening_order_lands_in_one_tx_with_55_stale_positioned_accounts() {
    // 1 USDC-atom-denominated insurance well above the funding-only bound for 55 units.
    let (mut w, _traders) = positioned_market(N_POSITIONED, 10_000_000);
    let (_, _, r) = entrant_order(&mut w);
    let cu = r.unwrap_or_else(|e| panic!("covered order [push, LP crank, order] must land: {e}"));
    let (sl, ss) = w.stale();
    eprintln!("v21_funding_scale: {N_POSITIONED} positioned + funding>0: [push, LP crank, order] = {cu} CU; stale after = {sl}/{ss}");
    assert!(cu < 1_400_000);
    assert_eq!(sl, N_POSITIONED as u64, "the 55 positioned longs were never refreshed");

    // Keep trading for several slots with nobody refreshing: every slot re-stales, the
    // drift generation grows, insurance still covers, orders keep landing.
    for _ in 0..5 {
        let (_, _, r) = entrant_order(&mut w);
        let cu = r.unwrap_or_else(|e| panic!("covered order must keep landing: {e}"));
        assert!(cu < 1_400_000);
    }
}

#[test]
fn v21_negative_control_without_insurance_the_order_is_loss_stale() {
    let (mut w, _traders) = positioned_market(N_POSITIONED, 0);
    assert_eq!(w.insurance(), 0);
    let (_, _, r) = entrant_order(&mut w);
    let e = r.expect_err("uncovered hidden K/F loss: the baseline gate applies");
    assert_eq!(custom_code(&e), Some(LOSS_STALE), "{e}");
}

#[test]
fn v21_order_bundle_shapes_with_55_stale_positioned_accounts() {
    // The keeper pushes the mark; the app sends the order. TradeCpi performs the canonical
    // same-slot accrual itself, so neither a push nor an LP crank has to ride in the order tx.
    let (mut w, _traders) = positioned_market(N_POSITIONED, 10_000_000);
    let admin = w.env.admin.insecure_clone();

    // (a) [push, order]
    let (k, p) = w.trader(1_000_000);
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    let ixs = vec![w.push_ix(s, PRICE), w.trade_ix(&k, p, POS_SCALE as i128)];
    let cu_a = w.bundle(ixs, &[&admin, &k]).expect("[push, order]");

    // (b) keeper pushed in an earlier tx of the same slot; the order goes alone
    let (k, p) = w.trader(1_000_000);
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    w.bundle(vec![w.push_ix(s, PRICE)], &[&admin]).unwrap();
    let cu_b = w.bundle(vec![w.trade_ix(&k, p, POS_SCALE as i128)], &[&k]).expect("[order] after an in-slot push");

    // (c) no push at all in this slot: the order alone, mark one slot old
    let (k, p) = w.trader(1_000_000);
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    let r_c = w.bundle(vec![w.trade_ix(&k, p, POS_SCALE as i128)], &[&k]);
    eprintln!("v21_funding_scale: bundle shapes with 55 stale: [push, order] = {cu_a} CU; [order] after in-slot push = {cu_b} CU; [order] with no push this slot = {r_c:?}");
    r_c.expect("[order] alone: TradeCpi accrues the asset itself");
    let (sl, _) = w.stale();
    assert!(sl >= N_POSITIONED as u64, "nobody refreshed the positioned longs");
}

#[test]
fn v21_reduce_and_close_still_need_no_refresh() {
    let (mut w, traders) = positioned_market(N_POSITIONED, 0);
    let (k, p) = &traders[7];
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    let admin = w.env.admin.insecure_clone();
    let ixs = vec![w.push_ix(s, PRICE), w.lp_crank_ix(s), w.trade_ix(k, *p, -((POS_SCALE / 2) as i128))];
    w.bundle(ixs, &[&admin, k]).expect("reduce needs no cover");
    let ixs = vec![w.trade_ix(k, *p, -((POS_SCALE / 2) as i128))];
    w.bundle(ixs, &[k]).expect("close needs no cover");
}

#[test]
fn v21_refresh_cost_and_baseline_bundle_ceiling() {
    // What the baseline needed: one refresh per stale positioned portfolio, in the order's slot.
    let (mut w, traders) = positioned_market(16, 0);
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    let admin = w.env.admin.insecure_clone();
    w.bundle(vec![w.push_ix(s, PRICE), w.lp_crank_ix(s)], &[&admin]).unwrap();
    let mut per = Vec::new();
    for (_, p) in traders.iter().take(4) {
        per.push(w.bundle(vec![w.refresh_ix(*p)], &[]).expect("refresh"));
    }
    eprintln!("v21_funding_scale: refresh crank CU per positioned portfolio = {per:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// v2.2: per-leg K/F settlement remainders (upstream a74b81b2) -- cadence invariance
// ─────────────────────────────────────────────────────────────────────────────

fn equity(w: &W, p: Pubkey) -> i128 {
    let a = w.env.portfolio_state(p);
    a.capital as i128 + a.pnl
}

fn leg0(w: &W, p: Pubkey) -> percolator::PortfolioLegV16 {
    w.env.portfolio_state(p).legs[0]
}

/// Two identical longs on the production shape (bound vault LP, skew funding > 0). Funding accrues
/// one slot at a time for 30 slots. Portfolio A is refreshed by the permissionless crank after
/// EVERY slot (30 one-slot settles); portfolio B once at the end. Each one-slot funding charge is a
/// fraction of an atom, so before the per-leg remainders A paid a whole atom on every settle and
/// B paid only the true total. Now both pay the same and end with the same remainder.
#[test]
fn v22_many_one_slot_settles_equal_one_settle() {
    const SLOTS: usize = 30;
    let (mut w, t) = positioned_market_with(2, 10_000_000, 1_000, 333);
    let (a, b) = (t[0].1, t[1].1);
    let ixs = vec![w.refresh_ix(a), w.refresh_ix(b)];
    w.bundle(ixs, &[]).expect("settle both to a common start");
    let (ea0, eb0) = (equity(&w, a), equity(&w, b));
    let (la0, lb0) = (leg0(&w, a), leg0(&w, b));
    assert_eq!(ea0, eb0);
    assert_eq!((la0.basis_pos_q, la0.a_basis, la0.f_snap, la0.k_snap, la0.k_rem_num, la0.f_rem_num),
               (lb0.basis_pos_q, lb0.a_basis, lb0.f_snap, lb0.k_snap, lb0.k_rem_num, lb0.f_rem_num));

    let f = |w: &W| w.env.market_state().1.assets[0].f_long_num;
    let mut f_prev = f(&w);
    assert_eq!(f_prev, la0.f_snap);
    let mut deltas = Vec::with_capacity(SLOTS);
    for _ in 0..SLOTS {
        w.tick();
        let f_now = f(&w);
        deltas.push(f_now - f_prev);
        f_prev = f_now;
        let ix = w.refresh_ix(a);
        w.bundle(vec![ix], &[]).expect("one-slot refresh of A");
        assert_eq!(leg0(&w, a).f_snap, f_now, "A settled this slot");
        assert_eq!(leg0(&w, b).f_snap, lb0.f_snap, "B not settled yet");
    }
    let ix = w.refresh_ix(b);
    w.bundle(vec![ix], &[]).expect("single refresh of B");

    let (ea, eb) = (equity(&w, a), equity(&w, b));
    let (la, lb) = (leg0(&w, a), leg0(&w, b));
    assert_eq!(ea - ea0, eb - eb0, "30 one-slot settles == one 30-slot settle");
    assert_eq!((la.k_rem_num, la.f_rem_num, la.f_snap, la.k_snap), (lb.k_rem_num, lb.f_rem_num, lb.f_snap, lb.k_snap));

    // The exact value: floor((rem0 + basis * dF_total) / (a_basis * POS_SCALE)), remainder carried.
    let basis = la0.basis_pos_q.unsigned_abs() as i128;
    let den = (la0.a_basis * POS_SCALE) as i128;
    let total: i128 = deltas.iter().sum();
    let num = la0.f_rem_num as i128 + basis * total;
    assert_eq!(la0.k_snap, la.k_snap, "price never moved: funding only");
    assert_eq!(ea - ea0, num.div_euclid(den));
    assert_eq!(la.f_rem_num as i128, num.rem_euclid(den));

    // Negative control (non-vacuity): on these exact per-slot index moves the OLD rule -- floor
    // each settle, drop the fraction -- charges A more than B. Every slot is a fractional charge.
    assert!(deltas.iter().all(|d| *d != 0 && (basis * d).rem_euclid(den) != 0), "every slot is fractional: {deltas:?}");
    let old_many: i128 = deltas.iter().map(|d| (basis * d).div_euclid(den)).sum();
    let old_once = (basis * total).div_euclid(den);
    assert!(old_many < old_once, "old rule: A {old_many} vs B {old_once}");
    eprintln!(
        "v22_kf_leg_remainders: {SLOTS} one-slot settles = one settle = {} atoms (old rule: {old_many} vs {old_once}); f_rem {}",
        ea - ea0, la.f_rem_num
    );
}
