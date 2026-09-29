//! INDEPENDENT SUITE (2026-09-30) — global conservation fuzz.
//!
//! Written from the SPEC, not from any builder's implementation:
//!   * engine spec.md §2 "Global invariants": `C_tot <= V`, `I <= V`, `V >= C_tot + I`;
//!     §10.1 "conservation V >= C_tot + I across all paths"; §10.2 "PnL aggregate and
//!     neg_pnl_account_count consistency".
//!   * wrapper README "Vault token account": the SPL vault is the only custody; the engine
//!     `vault` field must equal it exactly (fee-flow-audit §2 verified this on 19 live markets).
//!   * fee-flow-audit §1: every fee leg is a claim against
//!     `insurance - domain_budget_remaining - source_insurance_credit_reserved`.
//!   * master plan F4: CloseSlab must not burn unclaimed protocol/creator/LP/staker fees.
//!
//! Tokens are an external conservation law the program cannot fake: every collateral atom
//! this harness ever mints into a token account is tracked, and at every step
//!     Σ(tracked token balances) + burned == minted
//! must hold exactly, where `burned` is read from the mint's `supply` delta.
//!
//! Randomised, seeded, multi-threaded, with delta-debugging shrink on failure.
//! Knobs: FUZZ_SEQS (default 64), FUZZ_LEN (default 40), FUZZ_SEED (default 0x5eed),
//! FUZZ_THREADS (default = cores), FUZZ_WINDDOWN (default 1 = run resolve/close tail).
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator::{MarketModeV16, BOUND_SCALE, POS_SCALE};
use percolator_prog::constants::{HEADER_LEN, KIND_CLOSED_MARKET};
use percolator_prog::{ix::CrankObservationHint, ix::Instruction as ProgInstruction, state};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use solana_sdk::{
    account::Account,
    instruction::AccountMeta,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use spl_token::state::{Account as TokenAccount, Mint};

const N_USERS: usize = 4;
const INITIAL_MARK: u64 = 1_000_000;
const MINT_SUPPLY0: u64 = 1 << 62;

#[derive(Clone, Debug)]
pub enum Op {
    Deposit { u: u8, amt: u64 },
    Withdraw { u: u8, frac_bps: u16 },
    TradeNoCpi { a: u8, b: u8, size_tenths: i32, off_bps: i16 },
    TradeCpi { u: u8, size_tenths: i32 },
    Push { delta_bps: i32 },
    Warp { n: u8 },
    Crank { u: u8 },
    Convert { u: u8, frac_bps: u16 },
    TopUpInsurance { amt: u64 },
    Expire { d: u8 },
    Finalize { side: u8 },
    ClaimProtocol,
    ClaimCreator,
    ClosePortfolio { u: u8 },
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub ok: std::collections::BTreeMap<&'static str, u64>,
    pub err: std::collections::BTreeMap<String, u64>,
    pub soft: std::collections::BTreeMap<&'static str, u64>,
    pub burned_at_close: u128,
    pub legs_outstanding_at_close: u128,
    pub winddowns: u64,
    pub closeslab_ok: u64,
}

impl Stats {
    fn merge(&mut self, o: &Stats) {
        for (k, v) in &o.ok {
            *self.ok.entry(k).or_default() += v;
        }
        for (k, v) in &o.err {
            *self.err.entry(k.clone()).or_default() += v;
        }
        for (k, v) in &o.soft {
            *self.soft.entry(k).or_default() += v;
        }
        self.burned_at_close += o.burned_at_close;
        self.legs_outstanding_at_close += o.legs_outstanding_at_close;
        self.winddowns += o.winddowns;
        self.closeslab_ok += o.closeslab_ok;
    }
}

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::Deposit { .. } => "deposit",
        Op::Withdraw { .. } => "withdraw",
        Op::TradeNoCpi { .. } => "trade_nocpi",
        Op::TradeCpi { .. } => "trade_cpi",
        Op::Push { .. } => "push_mark",
        Op::Warp { .. } => "warp",
        Op::Crank { .. } => "crank",
        Op::Convert { .. } => "convert",
        Op::TopUpInsurance { .. } => "topup_ins",
        Op::Expire { .. } => "expire89",
        Op::Finalize { .. } => "finalize45",
        Op::ClaimProtocol => "claim84",
        Op::ClaimCreator => "claim90",
        Op::ClosePortfolio { .. } => "close_portfolio",
    }
}

pub struct World {
    pub env: V16CuEnv,
    pub owners: Vec<Keypair>,
    pub ports: Vec<Pubkey>,
    pub matcher_prog: Pubkey,
    pub ctx: Pubkey,
    pub delegate: Pubkey,
    pub tokens: Vec<Pubkey>,
    pub minted: u128,
    pub mark: u64,
    pub stats: Stats,
    pub closed: Vec<bool>,
    pub fee_bps: u64,
}

impl World {
    pub fn new(fee_bps: u64) -> Self {
        let params = V16CuMarketParams {
            h_max: 50,
            initial_price: INITIAL_MARK,
            min_nonzero_mm_req: 599,
            min_nonzero_im_req: 600,
            maintenance_margin_bps: 500,
            initial_margin_bps: 1_000,
            liquidation_fee_bps: 50,
            liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
            max_price_move_bps_per_slot: 20,
            max_accrual_dt_slots: 20,
            trade_fee_base_bps: fee_bps,
            max_bankrupt_close_lifetime_slots: 100,
            max_abs_funding_e9_per_slot: 1_000,
            min_funding_lifetime_slots: 10_000_000,
            ..V16CuMarketParams::default()
        };
        let mut env = V16CuEnv::new_with_init_params(params);
        // Give the mint a large supply so an SPL Burn can be observed as a supply delta.
        let mut mint_acct = env.svm.get_account(&env.mint).unwrap();
        let mut m = Mint::unpack(&mint_acct.data).unwrap();
        m.supply = MINT_SUPPLY0;
        Mint::pack(m, &mut mint_acct.data).unwrap();
        env.svm.set_account(env.mint, mint_acct).unwrap();

        // Protocol-fee authority -> admin so tag 84 is exercisable (key-only edit;
        // no balance touched).
        {
            let mut acct = env.svm.get_account(&env.market).unwrap();
            let (mut cfg, _, _, _) =
                state::read_market_config_mode_and_capacity(&acct.data).unwrap();
            cfg.protocol_fee_authority = env.admin.pubkey().to_bytes();
            state::write_wrapper_config(&mut acct.data, &cfg).unwrap();
            env.svm.set_account(env.market, acct).unwrap();
        }

        let matcher_prog = Pubkey::new_unique();
        let bytes = std::fs::read(matcher_program_path()).expect("matcher so");
        env.svm.add_program(matcher_prog, &bytes);

        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_MARK);

        let mut owners = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..=N_USERS {
            let k = Keypair::new();
            let p = env.create_portfolio(&k);
            owners.push(k);
            ports.push(p);
        }
        let vault = env.vault;
        let mut w = World {
            env,
            owners,
            ports,
            matcher_prog,
            ctx: Pubkey::default(),
            delegate: Pubkey::default(),
            tokens: vec![vault],
            minted: 0,
            mark: INITIAL_MARK,
            stats: Stats::default(),
            closed: vec![false; N_USERS + 1],
            fee_bps,
        };
        // LP = last portfolio: big deposit + passive matcher (kind 0, spread 0).
        let lp_idx = N_USERS;
        w.do_deposit(lp_idx, 200_000_000).expect("lp deposit");
        for u in 0..N_USERS {
            w.do_deposit(u, 20_000_000).expect("user deposit");
        }
        let lp_owner = w.owners[lp_idx].insecure_clone();
        let lp_port = w.ports[lp_idx];
        let (ctx, delegate, _) = w.env.init_matcher_context(&lp_owner, matcher_prog, lp_port);
        w.ctx = ctx;
        w.delegate = delegate;
        w
    }

    fn slot(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    fn new_token(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        let k = Pubkey::new_unique();
        self.env
            .svm
            .set_account(
                k,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.env.mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.minted += amount as u128;
        self.tokens.push(k);
        k
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        metas: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        self.env.send(ix, metas, signers)
    }

    pub fn do_deposit(&mut self, u: usize, amt: u64) -> Result<u64, String> {
        let owner = self.owners[u].insecure_clone();
        let src = self.new_token(owner.pubkey(), amt);
        let (pid, seq, _) = self.env.portfolio_identity(self.ports[u]);
        let m = self.env.market;
        let v = self.env.vault;
        let p = self.ports[u];
        self.send(
            ProgInstruction::Deposit { portfolio_id: pid, expected_sequence: seq, amount: amt as u128 },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
                AccountMeta::new(src, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&owner],
        )
    }

    fn do_withdraw(&mut self, u: usize, amt: u128) -> Result<u64, String> {
        let owner = self.owners[u].insecure_clone();
        let dst = self.new_token(owner.pubkey(), 0);
        let (pid, seq, _) = self.env.portfolio_identity(self.ports[u]);
        let (m, v, va, p) = (self.env.market, self.env.vault, self.env.vault_authority, self.ports[u]);
        self.send(
            ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: amt },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
                AccountMeta::new(dst, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&owner],
        )
    }

    fn do_trade_nocpi(&mut self, a: usize, b: usize, size_q: i128, exec: u64) -> Result<u64, String> {
        let oa = self.owners[a].insecure_clone();
        let ob = self.owners[b].insecure_clone();
        let (pa, pb) = (self.ports[a], self.ports[b]);
        let (aid, _, aep) = self.env.portfolio_identity(pa);
        let (bid, _, bep) = self.env.portfolio_identity(pb);
        let m = self.env.market;
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id: 1,
                asset_index: 0,
                size_q,
                exec_price: exec,
                fee_bps: self.fee_bps,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(oa.pubkey(), true),
                AccountMeta::new(ob.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(pa, false),
                AccountMeta::new(pb, false),
            ],
            &[&oa, &ob],
        )
    }

    fn do_trade_cpi(&mut self, u: usize, size_q: i128) -> Result<u64, String> {
        let taker = self.owners[u].insecure_clone();
        let pa = self.ports[u];
        let pb = self.ports[N_USERS];
        let (aid, _, aep) = self.env.portfolio_identity(pa);
        let (bid, bseq, bep) = self.env.portfolio_identity(pb);
        let (m, mp, ctx, del) = (self.env.market, self.matcher_prog, self.ctx, self.delegate);
        self.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id: 1,
                account_b_matcher_sequence: bseq,
                asset_index: 0,
                size_q,
                fee_bps: self.fee_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(pa, false),
                AccountMeta::new(pb, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(del, false),
            ],
            &[&taker],
        )
    }

    fn do_push(&mut self, mark: u64) -> Result<u64, String> {
        let slot = self.slot();
        let obs = self.env.control_sequences(0).oracle_observation + 1;
        let admin = self.env.admin.insecure_clone();
        let m = self.env.market;
        let r = self.send(
            ProgInstruction::PushAuthMark {
                market_id: 1,
                asset_index: 0,
                now_slot: slot,
                mark_e6: mark,
                observation_sequence: obs,
            },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        );
        if r.is_ok() {
            self.mark = mark;
        }
        r
    }

    fn do_crank(&mut self, u: usize) -> Result<u64, String> {
        let slot = self.slot();
        let payer = self.env.payer.pubkey();
        let m = self.env.market;
        let p = self.ports[u];
        // Bounded catch-up: a real keeper repeats the crank; so do we (<= 8 tries).
        let mut last = Err("no attempt".to_string());
        for _ in 0..8 {
            last = self.send(
                ProgInstruction::PermissionlessCrank {
                    now_slot: slot,
                    observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
                },
                vec![
                    AccountMeta::new(payer, true),
                    AccountMeta::new(m, false),
                    AccountMeta::new(p, false),
                ],
                &[],
            );
            if last.is_err() {
                break;
            }
            let (_, g) = self.env.market_state();
            if g.assets[0].slot_last >= slot {
                break;
            }
        }
        last
    }

    fn do_convert(&mut self, u: usize, amt: u128) -> Result<u64, String> {
        let owner = self.owners[u].insecure_clone();
        let p = self.ports[u];
        let (pid, _, pep) = self.env.portfolio_identity(p);
        let m = self.env.market;
        self.send(
            ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: amt },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
            ],
            &[&owner],
        )
    }

    fn do_topup_insurance(&mut self, amt: u64) -> Result<u64, String> {
        let admin = self.env.admin.insecure_clone();
        let src = self.new_token(admin.pubkey(), amt);
        let authority_epoch = self.env.control_sequences(0).authority_epoch;
        let (m, v) = (self.env.market, self.env.vault);
        self.send(
            ProgInstruction::TopUpInsurance {
                market_id: 1,
                intent_id: next_intent_id(),
                amount: amt as u128,
                authority_epoch,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(src, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
    }

    fn do_expire(&mut self, d: u16) -> Result<u64, String> {
        let m = self.env.market;
        self.send(ProgInstruction::ExpireBackingBucket { domain: d }, vec![AccountMeta::new(m, false)], &[])
    }

    fn do_finalize(&mut self, side: u8) -> Result<u64, String> {
        let m = self.env.market;
        self.send(
            ProgInstruction::FinalizeResetSide { asset_index: 0, side },
            vec![AccountMeta::new(m, false)],
            &[],
        )
    }

    pub fn do_claim_protocol(&mut self) -> Result<u64, String> {
        let admin = self.env.admin.insecure_clone();
        let dst = self.new_token(admin.pubkey(), 0);
        let epoch = self.env.protocol_fee_authority_epoch();
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        self.send(
            ProgInstruction::WithdrawProtocolFee { amount: 0, authority_epoch: epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(dst, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
    }

    pub fn creator_claimable(&self) -> u128 {
        let mut data = self.env.svm.get_account(&self.env.market).unwrap().data;
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&data).unwrap();
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        let n = core::mem::size_of::<state::AssetOracleProfileV16>();
        let prof: state::AssetOracleProfileV16 =
            bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n]);
        prof.creator_fee_claimable_atoms as u128 + cfg.creator_fee_claimable_atoms as u128
    }

    pub fn do_claim_creator(&mut self) -> Result<u64, String> {
        let amt = {
            let mut data = self.env.svm.get_account(&self.env.market).unwrap().data;
            let (_, group) = state::market_view_mut(&mut data).unwrap();
            let n = core::mem::size_of::<state::AssetOracleProfileV16>();
            let prof: state::AssetOracleProfileV16 =
                bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n]);
            prof.creator_fee_claimable_atoms as u128
        };
        if amt == 0 {
            return Err("nothing claimable".into());
        }
        let admin = self.env.admin.insecure_clone();
        let dst = self.new_token(admin.pubkey(), 0);
        let epoch = self.env.control_sequences(0).authority_epoch;
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        self.send(
            ProgInstruction::WithdrawCreatorFee { amount: amt, asset_index: 0, authority_epoch: epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(dst, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
    }

    fn do_close_portfolio(&mut self, u: usize) -> Result<u64, String> {
        let owner = self.owners[u].insecure_clone();
        let p = self.ports[u];
        let (pid, seq, pep) = self.env.portfolio_identity(p);
        let m = self.env.market;
        let r = self.send(
            ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: pep },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
            ],
            &[&owner],
        );
        if r.is_ok() {
            self.closed[u] = true;
        }
        r
    }

    pub fn do_close_resolved(&mut self, u: usize) -> Result<u64, String> {
        let owner = self.owners[u].pubkey();
        let dst = self.new_token(owner, 0);
        let (m, v, va, p) = (self.env.market, self.env.vault, self.env.vault_authority, self.ports[u]);
        self.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(owner, false),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
                AccountMeta::new(dst, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        )
    }

    pub fn do_resolve(&mut self) -> Result<u64, String> {
        let authority_epoch = self.env.control_sequences(0).authority_epoch;
        let fr = state::read_asset_generation_frontier(
            &self.env.svm.get_account(&self.env.market).unwrap().data,
        )
        .unwrap();
        let admin = self.env.admin.insecure_clone();
        let m = self.env.market;
        self.send(
            ProgInstruction::ResolveMarket { asset_generation_frontier: fr, authority_epoch },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
    }

    pub fn do_close_slab(&mut self) -> Result<u64, String> {
        let admin = self.env.admin.insecure_clone();
        let dst = self.new_token(admin.pubkey(), 0);
        let authority_epoch = self.env.control_sequences(0).authority_epoch;
        let (m, v, va, mint) = (self.env.market, self.env.vault, self.env.vault_authority, self.env.mint);
        self.send(
            ProgInstruction::CloseSlab { authority_epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new(dst, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                // [6] primary mint (writable): needed when CloseSlab retires residue.
                AccountMeta::new(mint, false),
            ],
            &[&admin],
        )
    }

    pub fn is_tombstone(&self) -> bool {
        self.env.svm.get_account(&self.env.market).map_or(true, |a| {
            a.data.len() == HEADER_LEN && a.data[10] == KIND_CLOSED_MARKET
        })
    }

    pub fn token_amount(&self, k: &Pubkey) -> u128 {
        match self.env.svm.get_account(k) {
            Some(a) if a.data.len() >= TokenAccount::LEN => {
                TokenAccount::unpack(&a.data).map(|t| t.amount as u128).unwrap_or(0)
            }
            _ => 0,
        }
    }

    pub fn burned(&self) -> u128 {
        let a = self.env.svm.get_account(&self.env.mint).unwrap();
        (MINT_SUPPLY0 - Mint::unpack(&a.data).unwrap().supply) as u128
    }

    /// Outstanding fee legs (fee-flow-audit §1): protocol + LP + stake reserve + creator.
    pub fn legs_outstanding(&self) -> u128 {
        let acct = self.env.svm.get_account(&self.env.market).unwrap();
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&acct.data).unwrap();
        cfg.protocol_fee_accrued_atoms.saturating_sub(cfg.protocol_fee_withdrawn_atoms)
            + cfg.lp_fee_accrued_atoms.saturating_sub(cfg.lp_fee_withdrawn_atoms)
            + cfg
                .insurance_reserve_accrued_atoms
                .saturating_sub(cfg.insurance_reserve_withdrawn_atoms)
            + self.creator_claimable()
    }

    /// Token-level conservation. Holds even after CloseSlab.
    pub fn check_tokens(&self) -> Result<(), String> {
        let held: u128 = self.tokens.iter().map(|k| self.token_amount(k)).sum();
        let burned = self.burned();
        if held + burned != self.minted {
            return Err(format!(
                "I8 TOKEN CONSERVATION: held {held} + burned {burned} != minted {}",
                self.minted
            ));
        }
        Ok(())
    }

    /// Engine/spec invariants on a live-or-resolved (not closed) market.
    pub fn check(&mut self) -> Result<(), String> {
        self.check_tokens()?;
        if self.is_tombstone() {
            return Ok(());
        }
        let acct = self.env.svm.get_account(&self.env.market).unwrap();
        let (cfg, g) = match state::read_market(&acct.data) {
            Ok(x) => x,
            Err(_) => return Ok(()), // closed-market tombstone
        };
        let vault_tok = self.token_amount(&self.env.vault);
        if vault_tok != g.vault {
            return Err(format!("I1 VAULT SYNC: spl vault {vault_tok} != engine vault {}", g.vault));
        }
        if g.c_tot.checked_add(g.insurance).map_or(true, |s| s > g.vault) {
            return Err(format!(
                "I2 SPEC V>=C_tot+I: V {} < C_tot {} + I {}",
                g.vault, g.c_tot, g.insurance
            ));
        }
        // I4/I5 aggregate consistency over every materialized portfolio.
        let mut cap = 0u128;
        let mut pos = 0u128;
        let mut negs = 0u64;
        for (i, p) in self.ports.iter().enumerate() {
            if self.closed[i] {
                continue;
            }
            if let Some(a) = self.env.svm.get_account(p) {
                if let Ok(pf) = state::read_portfolio(&a.data) {
                    cap += pf.capital;
                    if pf.pnl > 0 {
                        pos += pf.pnl as u128;
                    }
                    if pf.pnl < 0 {
                        negs += 1;
                    }
                }
            }
        }
        if cap != g.c_tot {
            return Err(format!("I4 C_tot AGGREGATE: Σcapital {cap} != c_tot {}", g.c_tot));
        }
        if g.mode == MarketModeV16::Live {
            if pos != g.pnl_pos_tot {
                return Err(format!("I5 PNL_pos_tot AGGREGATE: Σmax(pnl,0) {pos} != {}", g.pnl_pos_tot));
            }
            if negs != g.negative_pnl_account_count {
                return Err(format!(
                    "I5b neg_pnl_account_count: counted {negs} != {}",
                    g.negative_pnl_account_count
                ));
            }
            if g.pnl_matured_pos_tot > g.pnl_pos_tot {
                return Err(format!(
                    "I5c matured {} > pnl_pos_tot {}",
                    g.pnl_matured_pos_tot, g.pnl_pos_tot
                ));
            }
            let a0 = &g.assets[0];
            if a0.oi_eff_long_q != a0.oi_eff_short_q {
                // Spec §2.4: OI symmetry is required for clears; a matched book is symmetric.
                *self.stats.soft.entry("oi_asymmetric").or_default() += 1;
            }
        }
        // Soft (spec §3 says the senior stack may exceed V by design; record it).
        let senior = g
            .c_tot
            .saturating_add(g.insurance)
            .saturating_add(g.backing_provider_earnings_total)
            .saturating_add(g.source_fresh_backing_total_num / BOUND_SCALE);
        if senior > g.vault {
            *self.stats.soft.entry("senior_stack_exceeds_V").or_default() += 1;
        }
        // Soft: fee legs backed by unbudgeted insurance.
        let unbudgeted = g
            .insurance
            .saturating_sub(g.insurance_domain_budget_remaining_total)
            .saturating_sub(g.source_insurance_credit_reserved_total_atoms);
        let _ = cfg;
        if self.legs_outstanding() > unbudgeted {
            *self.stats.soft.entry("fee_legs_exceed_unbudgeted_insurance").or_default() += 1;
        }
        Ok(())
    }

    pub fn apply(&mut self, op: &Op) -> Result<u64, String> {
        match *op {
            Op::Deposit { u, amt } => self.do_deposit(u as usize % (N_USERS + 1), amt),
            Op::Withdraw { u, frac_bps } => {
                let u = u as usize % (N_USERS + 1);
                let cap = self.env.portfolio_state(self.ports[u]).capital;
                let amt = (cap * frac_bps as u128 / 10_000).max(1);
                self.do_withdraw(u, amt)
            }
            Op::TradeNoCpi { a, b, size_tenths, off_bps } => {
                let a = a as usize % (N_USERS + 1);
                let mut b = b as usize % (N_USERS + 1);
                if a == b {
                    b = (b + 1) % (N_USERS + 1);
                }
                let size = size_tenths as i128 * (POS_SCALE as i128 / 10);
                let exec = ((self.mark as i128) * (10_000 + off_bps as i128) / 10_000).max(1) as u64;
                self.do_trade_nocpi(a, b, size, exec)
            }
            Op::TradeCpi { u, size_tenths } => {
                let size = size_tenths as i128 * (POS_SCALE as i128 / 10);
                self.do_trade_cpi(u as usize % N_USERS, size)
            }
            Op::Push { delta_bps } => {
                let m = ((self.mark as i128) * (10_000 + delta_bps as i128) / 10_000).max(1_000) as u64;
                self.do_push(m)
            }
            Op::Warp { n } => {
                let s = self.slot() + n as u64;
                self.env.svm.warp_to_slot(s);
                Ok(0)
            }
            Op::Crank { u } => self.do_crank(u as usize % (N_USERS + 1)),
            Op::Convert { u, frac_bps } => {
                let u = u as usize % (N_USERS + 1);
                let pnl = self.env.portfolio_state(self.ports[u]).pnl;
                if pnl <= 0 {
                    return Err("no positive pnl".into());
                }
                let amt = ((pnl as u128) * frac_bps as u128 / 10_000).max(1);
                self.do_convert(u, amt)
            }
            Op::TopUpInsurance { amt } => self.do_topup_insurance(amt),
            Op::Expire { d } => self.do_expire((d % 2) as u16),
            Op::Finalize { side } => self.do_finalize(side % 2),
            Op::ClaimProtocol => self.do_claim_protocol(),
            Op::ClaimCreator => self.do_claim_creator(),
            Op::ClosePortfolio { u } => {
                let u = u as usize % N_USERS;
                if self.closed[u] {
                    return Err("already closed".into());
                }
                self.do_close_portfolio(u)
            }
        }
    }

    /// Wind-down tail: resolve, close every portfolio, claim fee legs that CAN be claimed
    /// in Resolved mode (84/90), then CloseSlab. Records how much CloseSlab burned versus
    /// how much was still owed on fee legs at the moment of close (F4).
    pub fn wind_down(&mut self) -> Result<(), String> {
        self.stats.winddowns += 1;
        // Let the effective price catch up, then resolve.
        for _ in 0..40 {
            let s = self.slot() + 5;
            self.env.svm.warp_to_slot(s);
            let _ = self.do_push(self.mark);
            let _ = self.do_crank(N_USERS);
            let (_, g) = self.env.market_state();
            if g.assets[0].effective_price == g.assets[0].raw_oracle_target_price {
                break;
            }
        }
        if self.do_resolve().is_err() {
            *self.stats.err.entry("winddown_resolve".into()).or_default() += 1;
            return self.check();
        }
        self.check()?;
        for round in 0..6 {
            for u in 0..=N_USERS {
                if self.closed[u] {
                    continue;
                }
                if self.do_close_resolved(u).is_ok() {
                    *self.stats.ok.entry("close_resolved").or_default() += 1;
                }
                self.check()?;
                let gone = self
                    .env
                    .svm
                    .get_account(&self.ports[u])
                    .map(|a| state::read_portfolio(&a.data).map(|p| p.capital == 0 && p.pnl == 0 && p.active_bitmap == percolator::active_bitmap_empty()).unwrap_or(true))
                    .unwrap_or(true);
                if gone {
                    self.closed[u] = true;
                }
            }
            let s = self.slot() + 10 * (round + 1);
            self.env.svm.warp_to_slot(s);
        }
        let _ = self.do_claim_protocol();
        let _ = self.do_claim_creator();
        self.check()?;
        // Free every portfolio slot (ClosePortfolio is owner-signed; after CloseResolved
        // the account is empty).
        for u in 0..=N_USERS {
            self.closed[u] = false;
            if self.do_close_portfolio(u).is_ok() {
                *self.stats.ok.entry("winddown_close_portfolio").or_default() += 1;
            } else {
                self.closed[u] = true; // still skip in aggregates; CloseResolved emptied it
            }
        }
        self.check()?;
        // Let any loss-opened backing bucket lapse, then expire it (tag 89, permissionless).
        let s = self.slot() + 400;
        self.env.svm.warp_to_slot(s);
        for d in 0..2u16 {
            if self.do_expire(d).is_ok() {
                *self.stats.ok.entry("winddown_expire89").or_default() += 1;
            }
        }
        self.check()?;
        let legs = self.legs_outstanding();
        if std::env::var("FUZZ_DEBUG").is_ok() {
            let (cfg, g) = self.env.market_state();
            eprintln!("pre-close: mode {:?} mat {} vault {} c_tot {} ins {} budget {} pnl_pos {} legs {} blockers {} closed {:?} fresh_backing {}",
                g.mode, g.materialized_portfolio_count, g.vault, g.c_tot, g.insurance, g.insurance_domain_budget_remaining_total, g.pnl_pos_tot, legs, g.resolved_payout_blocker_count, self.closed, g.source_fresh_backing_total_num);
            let _ = cfg;
        }
        let burned_before = self.burned();
        let mut r = self.do_close_slab();
        let mut calls = 1;
        for _ in 0..16 {
            let still_market = !self.is_tombstone();
            if !still_market {
                break;
            }
            calls += 1;
            if std::env::var("FUZZ_DEBUG").is_ok() {
                let a = self.env.svm.get_account(&self.env.market).unwrap();
                eprintln!("closeslab attempt {calls}: prev={:?} len={} kind={} vault_tok={}", r.as_ref().map_err(|e| e.chars().take(300).collect::<String>()), a.data.len(), a.data.get(10).copied().unwrap_or(255), self.token_amount(&self.env.vault));
            }
            let s = self.slot() + 1;
            self.env.svm.warp_to_slot(s);
            r = self.do_close_slab();
        }
        *self.stats.soft.entry(if calls > 1 { "closeslab_needed_multiple_calls" } else { "closeslab_single_call" }).or_default() += 1;
        let closed = self.is_tombstone();
        if r.is_ok() && !closed {
            *self.stats.soft.entry("closeslab_ok_but_market_still_open").or_default() += 1;
        }
        if r.is_ok() && closed {
            self.stats.closeslab_ok += 1;
            let burned = self.burned() - burned_before;
            self.stats.burned_at_close += burned;
            self.stats.legs_outstanding_at_close += legs;
            self.check_tokens()?;
            let v = self.token_amount(&self.env.vault);
            if v != 0 {
                return Err(format!("I9 CLOSED SLAB LEFT {v} ATOMS IN VAULT"));
            }
            if burned > 0 {
                *self.stats.soft.entry("F4_closeslab_burned_atoms>0").or_default() += 1;
            }
        } else {
            let e = r.unwrap_err();
            let code = custom_code(&e).map(|c| c.to_string()).unwrap_or_else(|| e.chars().take(60).collect());
            if std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                let (_, g) = self.env.market_state();
                let b: Vec<String> = g.source_backing_buckets.iter().map(|b| format!("{:?} exp={} fresh={} liened={}", b.status, b.expiry_slot, b.fresh_unliened_backing_num, b.valid_liened_backing_num)).collect();
                eprintln!("CLOSESLAB STUCK code={code} slot={} cur={} vault={} ins={} budget={} spent={:?} fresh_tot={} earn={} buckets={:?} sc={:?}", self.slot(), g.current_slot, g.vault, g.insurance, g.insurance_domain_budget_remaining_total, g.insurance_domain_spent, g.source_fresh_backing_total_num, g.backing_provider_earnings_total, b, g.source_credit);
                let logs: Vec<&str> = e.split("\\\"").filter(|l| l.contains("Program log")).collect();
                eprintln!("   logs: {:?}", logs);
            }
            *self.stats.err.entry(format!("winddown_closeslab:{code}")).or_default() += 1;
        }
        Ok(())
    }
}

pub fn gen_op(rng: &mut XorShiftRng) -> Op {
    let u = rng.gen::<u8>();
    match rng.gen_range(0..100) {
        0..=9 => Op::Deposit { u, amt: rng.gen_range(1_000..30_000_000) },
        10..=17 => Op::Withdraw { u, frac_bps: rng.gen_range(1..=10_000) },
        18..=33 => Op::TradeNoCpi {
            a: u,
            b: rng.gen(),
            size_tenths: rng.gen_range(-400..=400),
            off_bps: rng.gen_range(-3000..=3000),
        },
        34..=47 => Op::TradeCpi { u, size_tenths: rng.gen_range(-400..=400) },
        48..=59 => Op::Push { delta_bps: rng.gen_range(-2500..=2500) },
        60..=67 => Op::Warp { n: rng.gen_range(1..=60) },
        68..=81 => Op::Crank { u },
        82..=85 => Op::Convert { u, frac_bps: rng.gen_range(1..=10_000) },
        86..=87 => Op::TopUpInsurance { amt: rng.gen_range(1..5_000_000) },
        88..=90 => Op::Expire { d: rng.gen() },
        91..=92 => Op::Finalize { side: rng.gen() },
        93..=95 => Op::ClaimProtocol,
        96..=97 => Op::ClaimCreator,
        _ => Op::ClosePortfolio { u },
    }
}

/// Run one sequence; Err(msg) on the first invariant violation.
pub fn run_seq(fee_bps: u64, ops: &[Op], winddown: bool) -> (Result<(), String>, Stats) {
    let mut w = World::new(fee_bps);
    if let Err(e) = w.check() {
        return (Err(format!("at setup: {e}")), w.stats);
    }
    for (i, op) in ops.iter().enumerate() {
        let r = w.apply(op);
        let name = op_name(op);
        match r {
            Ok(_) => *w.stats.ok.entry(name).or_default() += 1,
            Err(e) => {
                let code = custom_code(&e).map(|c| c.to_string()).unwrap_or_else(|| {
                    if e.contains("InvalidAccountData") { "IAD".into() } else if e.len() < 40 { e.clone() } else { "other".into() }
                });
                if std::env::var("FUZZ_DEBUG").is_ok() && code == "other" { eprintln!("{name}: {}", &e[..e.len().min(400)]); }
                *w.stats.err.entry(format!("{name}:{code}")).or_default() += 1
            }
        }
        if let Err(e) = w.check() {
            return (Err(format!("after op #{i} {op:?}: {e}")), w.stats);
        }
    }
    if winddown {
        if let Err(e) = w.wind_down() {
            return (Err(format!("in wind-down: {e}")), w.stats);
        }
    }
    (Ok(()), w.stats)
}

fn inv_tag(e: &str) -> String {
    e.split(':').find(|s| s.trim_start().starts_with('I')).unwrap_or("").chars().take(6).collect()
}

/// Delta-debugging shrink (ddmin) preserving the violated invariant's tag.
pub fn shrink(fee_bps: u64, ops: Vec<Op>, winddown: bool, err: &str) -> (Vec<Op>, String) {
    let tag = inv_tag(err);
    let mut cur = ops;
    let mut last_err = err.to_string();
    let mut n = 2usize;
    let mut budget = 400;
    while cur.len() >= 2 && budget > 0 {
        let chunk = (cur.len() + n - 1) / n;
        let mut reduced = false;
        for start in (0..cur.len()).step_by(chunk) {
            budget -= 1;
            let mut cand = cur.clone();
            cand.drain(start..(start + chunk).min(cand.len()));
            if let (Err(e), _) = run_seq(fee_bps, &cand, winddown) {
                if inv_tag(&e) == tag {
                    cur = cand;
                    last_err = e;
                    n = (n - 1).max(2);
                    reduced = true;
                    break;
                }
            }
            if budget == 0 {
                break;
            }
        }
        if !reduced {
            if n >= cur.len() {
                break;
            }
            n = (n * 2).min(cur.len());
        }
    }
    (cur, last_err)
}

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

#[test]
fn indep_conservation_fuzz_global_invariants() {
    let seqs = env_u64("FUZZ_SEQS", 64);
    let len = env_u64("FUZZ_LEN", 40) as usize;
    let seed0 = env_u64("FUZZ_SEED", 0x5eed);
    let winddown = env_u64("FUZZ_WINDDOWN", 1) == 1;
    let threads = env_u64(
        "FUZZ_THREADS",
        std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(4),
    )
    .max(1);
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let total = std::sync::Arc::new(std::sync::Mutex::new(Stats::default()));
    let mut hs = Vec::new();
    for t in 0..threads {
        let failures = failures.clone();
        let total = total.clone();
        hs.push(
            std::thread::Builder::new()
                .stack_size(64 << 20)
                .spawn(move || {
                    let mut i = t;
                    while i < seqs {
                        let seed = match std::env::var("FUZZ_ONE_SEED").ok().and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()) {
                            Some(s) => s,
                            None => seed0.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)),
                        };
                        let mut rng = XorShiftRng::seed_from_u64(seed);
                        let fee_bps = [0u64, 5, 30][rng.gen_range(0..3)];
                        let ops: Vec<Op> = (0..len).map(|_| gen_op(&mut rng)).collect();
                        let (r, st) = run_seq(fee_bps, &ops, winddown);
                        total.lock().unwrap().merge(&st);
                        if let Err(e) = r {
                            let (min, merr) = shrink(fee_bps, ops, winddown, &e);
                            failures.lock().unwrap().push(format!(
                                "seed={seed:#x} fee_bps={fee_bps}\n  first: {e}\n  shrunk({} ops): {merr}\n  repro ops: {min:?}",
                                min.len()
                            ));
                        }
                        i += threads;
                    }
                })
                .unwrap(),
        );
    }
    for h in hs {
        h.join().expect("fuzz thread panicked");
    }
    let st = total.lock().unwrap().clone();
    eprintln!("== conservation fuzz: {seqs} sequences x {len} ops, seed0={seed0:#x}");
    eprintln!("   ok:   {:?}", st.ok);
    eprintln!("   err:  {:?}", st.err);
    eprintln!("   soft: {:?}", st.soft);
    eprintln!(
        "   winddowns {} closeslab_ok {} burned_at_close {} legs_outstanding_at_close {}",
        st.winddowns, st.closeslab_ok, st.burned_at_close, st.legs_outstanding_at_close
    );
    // Non-vacuity: the fuzz must actually exercise value-moving paths.
    for k in ["deposit", "withdraw", "trade_nocpi", "trade_cpi", "push_mark", "crank"] {
        assert!(st.ok.get(k).copied().unwrap_or(0) > 0, "vacuous fuzz: no successful {k}");
    }
    let f = failures.lock().unwrap();
    assert!(f.is_empty(), "{} invariant violation(s):\n{}", f.len(), f.join("\n\n"));
}
