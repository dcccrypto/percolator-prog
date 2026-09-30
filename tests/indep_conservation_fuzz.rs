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
    LpDeposit { u: u8, amt: u64 },
    LpCrank { d: u8 },
    LpRedeem { u: u8, frac_bps: u16 },
    Stake87Accrue,
    TradeNoCpiA1 { a: u8, b: u8, size_tenths: i32 },
    PushA1 { delta_bps: i32 },
    BatchNoCpi { a: u8, b: u8, s0: i32, s1: i32 },
    P3JuniorDeposit { amt: u64 },
    P3JuniorWithdraw { frac_bps: u16 },
    P3Recall { amt: u64 },
    P3Release { amt: u64 },
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
    pub haircut_then_burn: Vec<String>,
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
        self.haircut_then_burn.extend(o.haircut_then_burn.iter().cloned());
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
        Op::LpDeposit { .. } => "lp_deposit75",
        Op::LpCrank { .. } => "lp_crank78",
        Op::LpRedeem { .. } => "lp_redeem76_77",
        Op::Stake87Accrue => "stake87_accrue12",
        Op::TradeNoCpiA1 { .. } => "trade_nocpi_asset1",
        Op::PushA1 { .. } => "push_mark_asset1",
        Op::BatchNoCpi { .. } => "batch_nocpi",
        Op::P3JuniorDeposit { .. } => "p3_junior_deposit96",
        Op::P3JuniorWithdraw { .. } => "p3_junior_withdraw97",
        Op::P3Recall { .. } => "p3_recall98",
        Op::P3Release { .. } => "p3_release102",
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
    pub shortfall: u128,
    pub lp_vault: Option<(Pubkey, Pubkey, Pubkey)>,
    pub lp_atas: std::collections::BTreeMap<usize, Pubkey>,
    pub stake: Option<(Pubkey, Pubkey, Pubkey)>,
    pub nassets: usize,
    pub mark1: u64,
    pub pending_violation: Option<String>,
    pub p3: Option<P3Ctx>,
    pub minted_by: std::collections::BTreeMap<Pubkey, u128>,
}

impl World {
    pub fn new(fee_bps: u64) -> Self {
        let nassets: usize = std::env::var("FUZZ_ASSETS").ok().and_then(|v| v.parse().ok()).unwrap_or(1).clamp(1, 2);
        let params = V16CuMarketParams {
            max_portfolio_assets: nassets as u16,
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

        // 07a1d0eb auto-pin: the vault LP's matcher must be the CANONICAL program id.
        let matcher_prog = if p3_mode() && !p3_legacy_bind() { p3_canonical_matcher() } else { Pubkey::new_unique() };
        let bytes = std::fs::read(matcher_program_path()).expect("matcher so");
        env.svm.add_program(matcher_prog, &bytes);

        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_MARK);
        if nassets == 2 {
            // With capacity 2, InitMarket already configures slot 1 (activation gives 61).
            env.configure_auth_mark_for_asset_as_admin(1, 1, INITIAL_MARK);
        }

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
            shortfall: 0,
            lp_vault: None,
            lp_atas: Default::default(),
            stake: None,
            nassets,
            mark1: INITIAL_MARK,
            pending_violation: None,
            p3: None,
            minted_by: Default::default(),
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
        if std::env::var("FUZZ_LPVAULT").map_or(true, |v| v != "0") || p3_mode() {
            w.create_lp_vault();
        }
        if p3_mode() {
            w.p3_bind();
        }
        if std::env::var("FUZZ_STAKE").map_or(false, |v| v == "1") {
            // Real-staker vs dead-shares-only pools, 50/50 by market key parity.
            let dead_only = match std::env::var("FUZZ_STAKE_DEAD").ok().as_deref() { Some("1") => true, Some("0") => false, _ => w.env.market.to_bytes().iter().fold(0u8, |a, b| a ^ b) & 1 == 0 };
            w.setup_stake(if dead_only { 1_000 } else { 1_000 + 5_000_000 });
        }
        w
    }

    fn setup_stake(&mut self, total_lp_supply: u64) {
        let stake_id: Pubkey = "GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3".parse().unwrap();
        assert!(self.env.program_id.to_string() == "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv" || std::env::var("INDEP_PROGRAM_ID").is_ok(), "FUZZ_STAKE needs INDEP_MAINNET_ID=1 (plain stake) or INDEP_PROGRAM_ID=<id the stake build allowlists>");
        let so = std::env::var("INDEP_STAKE_SO").unwrap_or_else(|_| format!("{}/wt-indep/so/stake-e0ace2c-plain.so", std::env::var("HOME").unwrap()));
        if self.env.svm.get_account(&stake_id).map_or(true, |a| !a.executable) {
            self.env.svm.add_program(stake_id, &std::fs::read(&so).expect("stake so"));
        }
        let m = self.env.market;
        let (pool, _) = Pubkey::find_program_address(&[b"stake_pool", m.as_ref()], &stake_id);
        let (va, va_bump) = Pubkey::find_program_address(&[b"vault_auth", pool.as_ref()], &stake_id);
        let sv = self.new_token(va, 0);
        let mut d = vec![0u8; 408];
        d[0] = 1; d[1] = 255; d[2] = va_bump;
        d[8..40].copy_from_slice(m.as_ref());
        d[40..72].copy_from_slice(self.env.admin.pubkey().as_ref());
        d[72..104].copy_from_slice(self.env.mint.as_ref());
        d[104..136].copy_from_slice(Pubkey::new_unique().as_ref());
        d[136..168].copy_from_slice(sv.as_ref());
        d[176..184].copy_from_slice(&total_lp_supply.to_le_bytes());
        d[224..256].copy_from_slice(self.env.program_id.as_ref());
        d[320..328].copy_from_slice(b"SPOOL_V1");
        d[328] = 4;
        self.env.svm.set_account(pool, Account { lamports: 1_000_000_000, data: d, owner: stake_id, executable: false, rent_epoch: 0 }).unwrap();
        let admin = self.env.admin.insecure_clone();
        let pid = self.env.program_id;
        let ix = solana_sdk::instruction::Instruction {
            program_id: stake_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new(m, false),
                AccountMeta::new_readonly(pid, false),
            ],
            data: vec![19u8],
        };
        self.env.svm.expire_blockhash();
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, &[&admin]).expect("stake Bind (tag 19)");
        self.stake = Some((pool, va, sv));
    }

    /// (total_deposited, total_lp_supply, total_fees_earned) — stake state.rs offsets.
    fn pool_fields(&self) -> Option<(u64, u64, u64)> {
        let (pool, _, _) = self.stake?;
        let d = self.env.svm.get_account(&pool)?.data;
        let rd = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        Some((rd(168), rd(176), rd(256)))
    }

    fn do_stake87_accrue(&mut self) -> Result<u64, String> {
        let (pool, _va, sv) = self.stake.ok_or("no stake pool")?;
        let stake_id: Pubkey = "GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3".parse().unwrap();
        let payer = self.env.payer.pubkey();
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        let r87 = self.send(
            ProgInstruction::WithdrawInsuranceReserveToStake,
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new_readonly(pool, false),
                AccountMeta::new(sv, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[],
        );
        if let Err(e) = &r87 {
            *self.stats.err.entry(format!("tag87:{:?}", custom_code(e))).or_default() += 1;
        } else {
            *self.stats.ok.entry("tag87").or_default() += 1;
        }
        let before = self.pool_fields();
        let ix = solana_sdk::instruction::Instruction {
            program_id: stake_id,
            accounts: vec![
                AccountMeta::new_readonly(payer, true),
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(sv, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
                AccountMeta::new_readonly(m, false),
            ],
            data: vec![12u8],
        };
        self.env.svm.expire_blockhash();
        let r = send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, &[]);
        if r.is_ok() {
            if let (Some((_, s0, d0)), Some((_, _, d1))) = (before, self.pool_fields()) {
                if s0 <= 1_000 && d1 > d0 {
                    *self.stats.soft.entry("F3_accrue_booked_to_dead_shares").or_default() += 1;
                    if std::env::var("FUZZ_STRICT_F3").map_or(false, |v| v == "1") {
                        return Err(format!("I12 F3: AccrueFees booked {} atoms to a dead-shares-only pool", d1 - d0));
                    }
                }
            }
        }
        r
    }

    fn lp_ledger(&self, d: u16) -> Pubkey {
        state::derive_lp_backing_ledger(&self.env.program_id, &self.env.market, d).0
    }

    fn create_lp_vault(&mut self) {
        let pid = self.env.program_id;
        let m = self.env.market;
        let reg = state::derive_lp_vault_registry(&pid, &m).0;
        let mint = state::derive_lp_vault_mint(&pid, &m).0;
        let esc = state::derive_lp_escrow(&pid, &m).0;
        let admin = self.env.admin.insecure_clone();
        self.env.svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();
        let r = self.send(
            ProgInstruction::CreateLpVault { fee_share_bps: 0, redemption_cooldown_slots: 0, oi_reservation_threshold_bps: 0, domain: 0 },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(reg, false),
                AccountMeta::new(mint, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        );
        match r {
            Ok(_) => self.lp_vault = Some((reg, mint, esc)),
            Err(e) => panic!("CreateLpVault failed in fuzz setup: {}", &e[..e.len().min(400)]),
        }
    }

    fn do_lp_deposit(&mut self, u: usize, amt: u64) -> Result<u64, String> {
        let (reg, lmint, _) = self.lp_vault.ok_or("no lp vault")?;
        let owner = self.owners[u].insecure_clone();
        let ata = match self.lp_atas.get(&u) {
            Some(k) => *k,
            None => {
                let k = Pubkey::new_unique();
                self.env.svm.set_account(k, Account { lamports: 1_000_000_000, data: make_token_data(lmint, owner.pubkey(), 0), owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
                self.lp_atas.insert(u, k);
                k
            }
        };
        let src = self.new_token(owner.pubkey(), amt);
        let (m, v) = (self.env.market, self.env.vault);
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        self.send(
            ProgInstruction::DepositToLpVault { amount: amt as u128, domain: fuzz_lp_domain(amt) },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(reg, false),
                AccountMeta::new(lmint, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(src, false),
                AccountMeta::new(v, false),
                AccountMeta::new(l0, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(l1, false),
            ]
            .into_iter()
            .chain(self.p3.as_ref().map(|c| vec![AccountMeta::new(c.state_pda, false), AccountMeta::new(c.lp, false)]).unwrap_or_default())
            .collect(),
            &[&owner],
        )
        .map(|cu| {
            if let Some(c) = self.p3.as_mut() {
                c.senior_in += amt as u128;
            }
            cu
        })
    }

    fn do_lp_crank(&mut self, d: u16) -> Result<u64, String> {
        let (reg, _, _) = self.lp_vault.ok_or("no lp vault")?;
        let payer = self.env.payer.pubkey();
        let m = self.env.market;
        let (own, sib) = (self.lp_ledger(d), self.lp_ledger(d ^ 1));
        self.send(
            ProgInstruction::LpVaultCrankFees { domain: d },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(reg, false),
                AccountMeta::new(own, false),
                AccountMeta::new(sib, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ]
            .into_iter()
            .chain(self.p3.as_ref().map(|c| vec![AccountMeta::new(c.state_pda, false)]).unwrap_or_default())
            .collect(),
            &[],
        )
    }

    fn do_lp_redeem(&mut self, u: usize, frac_bps: u16) -> Result<u64, String> {
        let (reg, lmint, esc) = self.lp_vault.ok_or("no lp vault")?;
        let ata = *self.lp_atas.get(&u).ok_or("no lp shares")?;
        let held = self.token_amount(&ata);
        if held == 0 {
            return Err("no lp shares".into());
        }
        let shares = (held * frac_bps as u128 / 10_000).max(1);
        if self.p3.is_some() {
            self.p3_prep();
        }
        let owner = self.owners[u].insecure_clone();
        let red = state::derive_lp_redemption(&self.env.program_id, &reg, &owner.pubkey()).0;
        self.send(
            ProgInstruction::RequestRedeemLpShares { shares },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(reg, false),
                AccountMeta::new(lmint, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(esc, false),
                AccountMeta::new(red, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&owner],
        )?;
        self.do_lp_execute(u)
    }

    /// ExecuteRedemption (77) for `u`'s pending redemption PDA (permissionless crank).
    fn do_lp_execute(&mut self, u: usize) -> Result<u64, String> {
        // FUZZ_LP_DOMAINS=2: seniors sit in both pots, so a redeemer tries its pot, then the other.
        let r = self.do_lp_execute_domain(u, 0);
        if r.is_err() && std::env::var("FUZZ_LP_DOMAINS").map_or(false, |v| v == "2") {
            let r1 = self.do_lp_execute_domain(u, 1);
            if r1.is_ok() { return r1; }
        }
        r
    }

    fn do_lp_execute_domain(&mut self, u: usize, domain: u16) -> Result<u64, String> {
        let (reg, lmint, esc) = self.lp_vault.ok_or("no lp vault")?;
        let owner = self.owners[u].insecure_clone();
        let red = state::derive_lp_redemption(&self.env.program_id, &reg, &owner.pubkey()).0;
        let dst = self.new_token(owner.pubkey(), 0);
        let (m, v, va, payer) = (self.env.market, self.env.vault, self.env.vault_authority, self.env.payer.pubkey());
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        self.send(
            ProgInstruction::ExecuteRedemption { domain },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(reg, false),
                AccountMeta::new(red, false),
                AccountMeta::new(lmint, false),
                AccountMeta::new(esc, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new(l0, false),
                AccountMeta::new(dst, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(l1, false),
                AccountMeta::new(owner.pubkey(), false),
            ]
            .into_iter()
            .chain(self.p3.as_ref().map(|c| vec![AccountMeta::new(c.state_pda, false), AccountMeta::new(c.lp, false)]).unwrap_or_default())
            .collect(),
            &[],
        )
        .map(|cu| {
            // Runtime semantics: an account left with 0 lamports is garbage-collected at the
            // end of the transaction. LiteSVM 0.1 keeps it (with its data), which would make
            // the owner's NEXT RequestRedeem fail AlreadyInitialized — a harness artifact.
            if self.env.svm.get_account(&red).map_or(false, |a| a.lamports == 0) {
                let _ = self.env.svm.set_account(red, Account::default());
            }
            let paid = self.token_amount(&dst);
            if let Some(c) = self.p3.as_mut() {
                c.senior_out += paid;
                c.n_redeem += 1;
                c.c_may_drop = true;
            }
            cu
        })
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
        *self.minted_by.entry(owner).or_default() += amount as u128;
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

    fn market_id_of(&self, asset: usize) -> u64 {
        state::read_market_trade_preflight(&self.env.svm.get_account(&self.env.market).unwrap().data, asset)
            .map(|t| t.3)
            .unwrap_or(0)
    }

    fn do_trade_nocpi_asset(&mut self, asset: u16, a: usize, b: usize, size_q: i128, exec: u64) -> Result<u64, String> {
        let oa = self.owners[a].insecure_clone();
        let ob = self.owners[b].insecure_clone();
        let (pa, pb) = (self.ports[a], self.ports[b]);
        let (aid, _, aep) = self.env.portfolio_identity(pa);
        let (bid, _, bep) = self.env.portfolio_identity(pb);
        let m = self.env.market;
        let market_id = self.market_id_of(asset as usize);
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: aid, account_a_position_epoch: aep,
                account_b_portfolio_id: bid, account_b_position_epoch: bep,
                market_id, asset_index: asset, size_q, exec_price: exec, fee_bps: self.fee_bps, backing_fee_cap_bps: 10_000,
            },
            vec![AccountMeta::new(oa.pubkey(), true), AccountMeta::new(ob.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(pa, false), AccountMeta::new(pb, false)],
            &[&oa, &ob],
        )
    }

    fn do_batch_nocpi(&mut self, a: usize, b: usize, s0: i128, s1: i128) -> Result<u64, String> {
        let oa = self.owners[a].insecure_clone();
        let ob = self.owners[b].insecure_clone();
        let (pa, pb) = (self.ports[a], self.ports[b]);
        let (aid, _, aep) = self.env.portfolio_identity(pa);
        let (bid, _, bep) = self.env.portfolio_identity(pb);
        let m = self.env.market;
        let mut legs = vec![percolator_prog::ix::BatchTradeLeg { market_id: self.market_id_of(0), asset_index: 0, size_q: s0, exec_price: self.mark, fee_bps: self.fee_bps }];
        if self.nassets == 2 && s1 != 0 {
            legs.push(percolator_prog::ix::BatchTradeLeg { market_id: self.market_id_of(1), asset_index: 1, size_q: s1, exec_price: self.mark1, fee_bps: self.fee_bps });
        }
        self.send(
            ProgInstruction::BatchTradeNoCpi { account_a_portfolio_id: aid, account_a_position_epoch: aep, account_b_portfolio_id: bid, account_b_position_epoch: bep, legs },
            vec![AccountMeta::new(oa.pubkey(), true), AccountMeta::new(ob.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(pa, false), AccountMeta::new(pb, false)],
            &[&oa, &ob],
        )
    }

    fn do_push_asset1(&mut self, mark: u64) -> Result<u64, String> {
        let slot = self.slot();
        let obs = self.env.control_sequences(1).oracle_observation + 1;
        let admin = self.env.admin.insecure_clone();
        let m = self.env.market;
        let market_id = self.market_id_of(1);
        let r = self.send(
            ProgInstruction::PushAuthMark { market_id, asset_index: 1, now_slot: slot, mark_e6: mark, observation_sequence: obs },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        );
        if r.is_ok() {
            self.mark1 = mark;
        }
        r
    }

    fn do_trade_cpi(&mut self, u: usize, size_q: i128) -> Result<u64, String> {
        if self.p3.is_some() {
            return self.p3_trade_vs_vault_lp(u, size_q);
        }
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
                    observations: (0..self.nassets as u16).map(|a| CrankObservationHint { asset_index: a, oracle_accounts: 0 }).collect(),
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
        let before = self.env.portfolio_state(p);
        let r = self.send(
            ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: amt },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(p, false),
            ],
            &[&owner],
        );
        if r.is_ok() && self.port_alive(u) {
            // Round-trip winner-underpayment probe: face burned at convert = pnl consumed minus
            // capital credited. Under the P3 senior-draw rule a winner is never haircut while the
            // seniors still hold a claim (C > dust).
            let after = self.env.portfolio_state(p);
            let consumed = (before.pnl - after.pnl).max(0) as u128;
            let credited = after.capital.saturating_sub(before.capital);
            let burned = consumed.saturating_sub(credited);
            if burned > 2 {
                *self.stats.soft.entry("convert_haircut_events").or_default() += 1;
                *self.stats.soft.entry("convert_haircut_atoms").or_default() += burned.min(u64::MAX as u128) as u64;
                if self.p3.is_some() {
                    let c = self.p3_c();
                    if c > 3_000 {
                        *self.stats.soft.entry("convert_haircut_while_seniors_hold_C").or_default() += 1;
                        if std::env::var("FUZZ_STRICT_RT").map_or(false, |v| v == "1") && self.pending_violation.is_none() {
                            self.pending_violation = Some(format!("RT-winner-haircut u{u}: convert burned {burned} (consumed {consumed}, credited {credited}) while seniors hold C {c}"));
                        }
                    }
                }
            }
        }
        r
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
        let mut t = cfg.creator_fee_claimable_atoms as u128;
        for a in 0..self.nassets {
            let prof: state::AssetOracleProfileV16 = bytemuck::pod_read_unaligned(&group.markets[a].wrapper[..n]);
            t += prof.creator_fee_claimable_atoms as u128;
        }
        t
    }

    pub fn do_claim_creator(&mut self) -> Result<u64, String> {
        let mut last = Err("nothing claimable".to_string());
        for a in 0..self.nassets {
            let r = self.do_claim_creator_asset(a);
            if r.is_ok() || last.is_err() { last = r; }
        }
        last
    }

    pub fn do_claim_creator_asset(&mut self, asset: usize) -> Result<u64, String> {
        let amt = {
            let mut data = self.env.svm.get_account(&self.env.market).unwrap().data;
            let (_, group) = state::market_view_mut(&mut data).unwrap();
            let n = core::mem::size_of::<state::AssetOracleProfileV16>();
            let prof: state::AssetOracleProfileV16 =
                bytemuck::pod_read_unaligned(&group.markets[asset].wrapper[..n]);
            prof.creator_fee_claimable_atoms as u128
        };
        if amt == 0 {
            return Err("nothing claimable".into());
        }
        let admin = self.env.admin.insecure_clone();
        let dst = self.new_token(admin.pubkey(), 0);
        let epoch = self.env.control_sequences(asset as u16).authority_epoch;
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        self.send(
            ProgInstruction::WithdrawCreatorFee { amount: amt, asset_index: asset as u16, authority_epoch: epoch },
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
        if self.env.svm.get_account(&p).map_or(true, |a| state::read_portfolio(&a.data).is_err()) {
            // Already freed (e.g. P3 permissionless resolved cleanup).
            self.closed[u] = true;
            return Ok(0);
        }
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
        let before = if self.port_alive(u) { Some(self.env.portfolio_state(p)) } else { None };
        let r = self.send(
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
        );
        // Round-trip winner-underpayment probe at the resolved close (flat portfolios only, so
        // the pnl field is the whole claim): value before = capital + positive pnl; value after
        // = what was paid + what the portfolio still holds.
        if let (Ok(_), Some(b)) = (&r, before) {
            if b.legs.iter().all(|l| !l.active) && b.pnl > 0 {
                let paid = self.env.token_amount(dst) as u128;
                let (ac, ap) = if self.port_alive(u) { let a = self.env.portfolio_state(p); (a.capital, a.pnl.max(0) as u128) } else { (0, 0) };
                let before_v = b.capital + b.pnl as u128;
                let after_v = paid + ac + ap;
                if before_v > after_v + 2 {
                    let burned = before_v - after_v;
                    *self.stats.soft.entry("close_resolved_haircut_events").or_default() += 1;
                    if std::env::var("FUZZ_RT_TRACE").is_ok() {
                        let g = self.env.market_state().1;
                        let lp = self.env.portfolio_state(self.ports[N_USERS]);
                        eprintln!("  RTDBG u{u} burned {burned} before cap {} pnl {} claim_bound {:?} | buckets {:?} | sc {:?} | ins {} C {} | vault {} c_tot {} pnl_pos_tot {}", b.capital, b.pnl, b.source_claim_bound_num.iter().map(|x| x / BOUND_SCALE).collect::<Vec<_>>(),
                            g.source_backing_buckets.iter().take(2).map(|x| (x.status, x.fresh_unliened_backing_num / BOUND_SCALE, x.consumed_liened_backing_num / BOUND_SCALE)).collect::<Vec<_>>(),
                            g.source_credit.iter().take(2).map(|c| (c.positive_claim_bound_num / BOUND_SCALE, c.credit_rate_num)).collect::<Vec<_>>(), g.insurance, if self.p3.is_some() { self.p3_c() } else { 0 }, g.vault, g.c_tot, g.pnl_pos_tot);
                        let _ = lp;
                    }
                    *self.stats.soft.entry("close_resolved_haircut_atoms").or_default() += burned.min(u64::MAX as u128) as u64;
                    if self.p3.is_some() {
                        let c = self.p3_c();
                        if c > 3_000 {
                            *self.stats.soft.entry("close_resolved_haircut_while_seniors_hold_C").or_default() += 1;
                            if std::env::var("FUZZ_STRICT_RT").map_or(false, |v| v == "1") && self.pending_violation.is_none() {
                                self.pending_violation = Some(format!("RT-winner-haircut u{u}: CloseResolved burned {burned} (value {before_v} -> paid {paid} + held {}) while seniors hold C {c}", ac + ap));
                            }
                        }
                    }
                }
            }
        }
        r
    }

    pub fn do_claim_topup(&mut self, u: usize) -> Result<u64, String> {
        let owner = self.owners[u].pubkey();
        let dst = self.new_token(owner, 0);
        let (m, v, va, p) = (self.env.market, self.env.vault, self.env.vault_authority, self.ports[u]);
        self.send(
            ProgInstruction::ClaimResolvedPayoutTopup,
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

    pub fn do_withdraw_terminal_insurance(&mut self, amount: u128) -> Result<u64, String> {
        let admin = self.env.admin.insecure_clone();
        let dst = self.new_token(admin.pubkey(), 0);
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        self.send(
            ProgInstruction::WithdrawInsurance { amount },
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
        if let Some(v) = self.pending_violation.take() {
            return Err(v);
        }
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
        if let Some(c) = self.p3.as_ref() {
            if let Some(a) = self.env.svm.get_account(&c.lp) {
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
        // P3-a: senior principal C only drops through senior redemptions.
        if self.p3.is_some() {
            let cnow = self.p3_c();
            let c = self.p3.as_mut().unwrap();
            if cnow < c.c_last && !c.c_may_drop {
                return Err(format!("P3-a SENIOR PRINCIPAL DROPPED without a redemption: C {} -> {cnow}", c.c_last));
            }
            c.c_last = cnow;
            c.c_may_drop = false;
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
            if g.assets.iter().take(self.nassets).any(|a| a.oi_eff_long_q != a.oi_eff_short_q) || a0.oi_eff_long_q != a0.oi_eff_short_q {
                // Spec §2.4: OI symmetry is required for clears; a matched book is symmetric.
                *self.stats.soft.entry("oi_asymmetric").or_default() += 1;
            }
        }
        // I12b stake pool: booked deposits must be backed by stake-vault tokens.
        if let (Some((_, _, sv)), Some((dep, _, _))) = (self.stake, self.pool_fields()) {
            let bal = self.token_amount(&sv);
            if dep as u128 > bal {
                return Err(format!("I12b STAKE POOL UNBACKED: total_deposited {dep} > stake vault {bal}"));
            }
        }
        // I11 LP-vault share accounting: registry outstanding == LP-mint supply + dead floor.
        if let Some((reg, lmint, _)) = self.lp_vault {
            if let (Some(ra), Some(ma)) = (self.env.svm.get_account(&reg), self.env.svm.get_account(&lmint)) {
                if let (Ok(r), Ok(mi)) = (state::read_lp_vault_registry(&ra.data), Mint::unpack(&ma.data)) {
                    let supply = mi.supply as u128;
                    let expect = if r.total_lp_shares_outstanding == 0 { 0 } else { supply + percolator_prog::constants::LP_VAULT_MINIMUM_LIQUIDITY as u128 };
                    if r.total_lp_shares_outstanding != expect {
                        return Err(format!("I11 LP SHARES: registry {} != mint supply {} + dead floor", r.total_lp_shares_outstanding, supply));
                    }
                }
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

    fn port_alive(&self, u: usize) -> bool {
        u < self.ports.len() && self.env.svm.get_account(&self.ports[u]).map_or(false, |a| !a.data.is_empty() && a.lamports > 0)
    }

    pub fn apply(&mut self, op: &Op) -> Result<u64, String> {
        // Runtime-parity GC deletes closed portfolios; ops on them are refused, not panics.
        let dead = |u: u8, n: usize| -> Option<usize> { let i = u as usize % n; if self.port_alive(i) { None } else { Some(i) } };
        match *op {
            Op::Withdraw { u, .. } | Op::Convert { u, .. } | Op::Deposit { u, .. } | Op::Crank { u } => {
                if let Some(i) = dead(u, N_USERS + 1) { return Err(format!("portfolio {i} closed")); }
            }
            _ => {}
        }
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
                let before = (self.pos0(a), self.pos0(b));
                let r = self.do_trade_nocpi(a, b, size, exec);
                self.p3g_check("TradeNoCpi", &r, &[(a, before.0), (b, before.1)]);
                r
            }
            Op::TradeCpi { u, size_tenths } => {
                // P3: the vault LP's 1x capacity (junior-sized) is a few units; scale down.
                let size = if self.p3.is_some() { size_tenths as i128 * (POS_SCALE as i128 / 100) } else { size_tenths as i128 * (POS_SCALE as i128 / 10) };
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
            Op::TradeNoCpiA1 { a, b, size_tenths } => {
                if self.nassets < 2 { return Err("single asset".into()); }
                let a = a as usize % (N_USERS + 1);
                let mut b = b as usize % (N_USERS + 1);
                if a == b { b = (b + 1) % (N_USERS + 1); }
                self.do_trade_nocpi_asset(1, a, b, size_tenths as i128 * (POS_SCALE as i128 / 10), self.mark1)
            }
            Op::PushA1 { delta_bps } => {
                if self.nassets < 2 { return Err("single asset".into()); }
                let m = ((self.mark1 as i128) * (10_000 + delta_bps as i128) / 10_000).max(1_000) as u64;
                self.do_push_asset1(m)
            }
            Op::BatchNoCpi { a, b, s0, s1 } => {
                let a = a as usize % (N_USERS + 1);
                let mut b = b as usize % (N_USERS + 1);
                if a == b { b = (b + 1) % (N_USERS + 1); }
                let q = POS_SCALE as i128 / 10;
                let before = (self.pos0(a), self.pos0(b));
                let r = self.do_batch_nocpi(a, b, s0 as i128 * q, s1 as i128 * q);
                self.p3g_check("BatchTradeNoCpi", &r, &[(a, before.0), (b, before.1)]);
                r
            }
            Op::Stake87Accrue => {
                let r = self.do_stake87_accrue();
                if let Err(e) = &r {
                    if e.starts_with("I12") {
                        self.pending_violation = Some(e.clone());
                    }
                }
                r
            }
            Op::LpDeposit { u, amt } => {
                if self.p3.is_some() {
                    self.p3_prep();
                    self.do_lp_deposit(u as usize % 3 + 1, amt)
                } else {
                    self.do_lp_deposit(u as usize % N_USERS, amt)
                }
            }
            Op::P3JuniorDeposit { amt } => self.p3_junior_deposit(amt),
            Op::P3JuniorWithdraw { frac_bps } => self.p3_junior_withdraw(frac_bps),
            Op::P3Recall { amt } => self.p3_recall(amt as u128),
            Op::P3Release { amt } => self.p3_release(amt as u128, false),
            Op::LpCrank { d } => self.do_lp_crank((d % 2) as u16),
            Op::LpRedeem { u, frac_bps } => {
                let u = if self.p3.is_some() { u as usize % 3 + 1 } else { u as usize % N_USERS };
                self.do_lp_redeem(u, frac_bps)
            }
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
        // P3: the keeper harvests the LP fee leg (tag 78) right before resolution (plan: "crank
        // 78/87 before any ResolveMarket"). FUZZ_P3_PRECRANK=0 reproduces F-12 instead.
        if self.p3.is_some() && std::env::var("FUZZ_P3_PRECRANK").map_or(true, |v| v != "0") {
            self.p3_prep();
        }
        if self.do_resolve().is_err() {
            *self.stats.err.entry("winddown_resolve".into()).or_default() += 1;
            return self.check();
        }
        self.check()?;
        for round in 0..20 {
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
        // Resolved payout top-ups (tag 46, permissionless, pays only the owner's receipt).
        for _ in 0..3 {
            for u in 0..=N_USERS {
                let open_receipt = self
                    .env
                    .svm
                    .get_account(&self.ports[u])
                    .and_then(|a| state::read_portfolio(&a.data).ok())
                    .map_or(false, |p| p.resolved_payout_receipt.present && !p.resolved_payout_receipt.finalized);
                if open_receipt {
                    match self.do_claim_topup(u) {
                        Ok(_) => *self.stats.ok.entry("winddown_topup46").or_default() += 1,
                        Err(e) => {
                            let code = custom_code(&e).map(|c| c.to_string()).unwrap_or_else(|| e.chars().take(40).collect());
                            *self.stats.err.entry(format!("winddown_topup46:{code}")).or_default() += 1;
                        }
                    }
                    self.check()?;
                }
            }
            let s = self.slot() + 5;
            self.env.svm.warp_to_slot(s);
        }
        if self.p3.is_some() {
            self.p3_terminal_settle()?;
        }
        // Earn LP holders redeem everything (76/77 are allowed after resolution per the
        // LP-vault teardown tests).
        let holders: Vec<usize> = self.lp_atas.keys().copied().collect();
        for u in holders {
            let r = self.do_lp_redeem(u, 10_000);
            if std::env::var("FUZZ_DEBUG_P3").is_ok() {
                eprintln!("  WINDDOWN-REDEEM u{u}: {:?} C {}", r.as_ref().map_err(|e| custom_code(e)), self.p3_c());
            }
            if r.is_ok() {
                *self.stats.ok.entry("winddown_lp_redeem").or_default() += 1;
            }
            self.check()?;
        }
        if self.p3.is_some() {
            self.p3_terminal_checks()?;
        }
        let _ = self.do_claim_protocol();
        let _ = self.do_claim_creator();
        self.check()?;
        // Free every portfolio slot (ClosePortfolio is owner-signed; after CloseResolved
        // the account is empty).
        for u in 0..=N_USERS {
            self.closed[u] = false;
            if std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                if let Some(a) = self.env.svm.get_account(&self.ports[u]) {
                    if let Ok(pf) = state::read_portfolio(&a.data) {
                        let r = pf.resolved_payout_receipt;
                        eprintln!("pre-closeportfolio u{u}: cap {} pnl {} receipt present {} face {} paid {} final {}", pf.capital, pf.pnl, r.present, r.terminal_positive_claim_face, r.paid_effective, r.finalized);
                    }
                }
            }
            if let Some(pf) = self.env.svm.get_account(&self.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()) {
                let r = pf.resolved_payout_receipt;
                if r.present {
                    self.shortfall += r.terminal_positive_claim_face.saturating_sub(r.paid_effective);
                }
            }
            let cp = self.do_close_portfolio(u);
            if std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                eprintln!("   closeportfolio u{u}: {:?}", cp.as_ref().map_err(|e| custom_code(e)));
            }
            if cp.is_ok() {
                *self.stats.ok.entry("winddown_close_portfolio").or_default() += 1;
            } else {
                // Skip in aggregates only if CloseResolved really emptied it.
                let empty = self.env.svm.get_account(&self.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()).map_or(true, |p| p.capital == 0 && p.pnl == 0 && p.active_bitmap == percolator::active_bitmap_empty());
                self.closed[u] = empty;
                if !empty && std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                    let pf = self.env.portfolio_state(self.ports[u]);
                    let (_, g) = self.env.market_state();
                    let cr = self.do_close_resolved(u);
                    let crs = cr.as_ref().map_err(|e| e.split("Program log").skip(1).map(|l| l.chars().take(120).collect::<String>()).collect::<Vec<_>>().join(" | ") + &format!(" code {:?}", custom_code(e))).map(|_| ());
                    eprintln!("  retry close_resolved u{u}: {:?}", crs);
                    eprintln!("NOT EMPTY after close-out: u{u} cap {} pnl {} legs {:?} receipt {:?}; assets eff/tgt {:?}", pf.capital, pf.pnl, pf.legs.iter().filter(|l| l.active).map(|l| (l.asset_index, l.basis_pos_q)).collect::<Vec<_>>(), (pf.resolved_payout_receipt.present, pf.resolved_payout_receipt.finalized), g.assets.iter().map(|a| (a.effective_price, a.raw_oracle_target_price)).collect::<Vec<_>>());
                }
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
        // Insurance authority takes back the budgeted (topped-up) insurance: tag 41,
        // resolved + all portfolios closed. Unbudgeted insurance = fee legs stays.
        let budget = {
            let g = self.env.market_state().1;
            // Everything in insurance that is not an owed fee leg belongs to the insurance
            // authority at terminal (README "WithdrawInsurance (tag 41) unbounded resolved").
            let legs = self.legs_outstanding();
            let want = g.insurance.saturating_sub(legs);
            if std::env::var("FUZZ_INS_BUDGET_ONLY").is_ok() { g.insurance_domain_budget_remaining_total } else { want }
        };
        if budget > 0 {
            if std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                let g = self.env.market_state().1;
                eprintln!("pre-ins41: ins {} budget_total {} per-domain {:?} spent {:?} legs {} request {budget}", g.insurance, g.insurance_domain_budget_remaining_total, g.insurance_domain_budget, g.insurance_domain_spent, self.legs_outstanding());
            }
            match self.do_withdraw_terminal_insurance(budget) {
                Ok(_) => *self.stats.ok.entry("winddown_withdraw_ins41").or_default() += 1,
                Err(e) => {
                    let code = custom_code(&e).map(|c| c.to_string()).unwrap_or_else(|| e.chars().take(40).collect());
                    *self.stats.err.entry(format!("winddown_withdraw_ins41:{code}")).or_default() += 1;
                }
            }
            self.check()?;
            // A residual budget atom (rounding) also blocks retirement; take it too.
            let rest = self.env.market_state().1.insurance_domain_budget_remaining_total;
            if rest > 0 {
                let rr = self.do_withdraw_terminal_insurance(rest);
                if std::env::var("FUZZ_DEBUG_CLOSE").is_ok() {
                    let g = self.env.market_state().1;
                    eprintln!("residual ins41({rest}) -> {:?}; after: ins {} budget {} per-domain {:?}", rr.as_ref().map_err(|e| custom_code(e)), g.insurance, g.insurance_domain_budget_remaining_total, g.insurance_domain_budget);
                }
                if rr.is_ok() {
                    *self.stats.ok.entry("winddown_withdraw_ins41_residual").or_default() += 1;
                }
            }
            self.check()?;
        }
        let legs = self.legs_outstanding();
        if std::env::var("FUZZ_DEBUG").is_ok() {
            let (cfg, g) = self.env.market_state();
            eprintln!("pre-close: mode {:?} mat {} vault {} c_tot {} ins {} budget {} pnl_pos {} legs {} blockers {} closed {:?} fresh_backing {}",
                g.mode, g.materialized_portfolio_count, g.vault, g.c_tot, g.insurance, g.insurance_domain_budget_remaining_total, g.pnl_pos_tot, legs, g.resolved_payout_blocker_count, self.closed, g.source_fresh_backing_total_num);
            let _ = cfg;
        }
        let burned_before = self.burned();
        let vault_before_close = self.token_amount(&self.env.vault);
        let mut r = self.do_close_slab();
        let mut calls = 1;
        for _ in 0..16 {
            let still_market = !self.is_tombstone();
            if !still_market {
                break;
            }
            calls += 1;
            let _ = self.do_claim_protocol();
            let _ = self.do_claim_creator();
            // A CloseSlab scan step can re-credit spent insurance into a domain budget;
            // the insurance authority takes it (tag 41) before the next call.
            // P1: tag 87 is allowed on a terminal-empty Resolved market; push the staker leg.
            if self.stake.is_some() {
                let _ = self.do_stake87_accrue();
                self.pending_violation = None;
                // F-9 fix (stake f9b9190): permissionless terminal insurance recovery (tag 29).
                if std::env::var("FUZZ_STAKE_TAG29").map_or(true, |v| v != "0") {
                    let rb = self.env.market_state().1.insurance_domain_budget_remaining_total;
                    if rb > 0 && self.do_stake_recover_terminal(rb as u64, None).is_ok() {
                        *self.stats.ok.entry("winddown_stake_tag29").or_default() += 1;
                    }
                }
            }
            let rb = self.env.market_state().1.insurance_domain_budget_remaining_total;
            if rb > 0 && self.do_withdraw_terminal_insurance(rb).is_ok() {
                *self.stats.ok.entry("winddown_withdraw_ins41_after_scan_recredit").or_default() += 1;
            }
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
            let non_leg_burn = burned.saturating_sub(legs);
            if self.shortfall > 0 && non_leg_burn > 0 {
                self.stats.haircut_then_burn.push(format!(
                    "winners short-paid {} atoms at resolution while CloseSlab burned {} non-fee-leg atoms (fee_bps {})",
                    self.shortfall, non_leg_burn, self.fee_bps
                ));
            }
            // F4 (master plan P1): CloseSlab must never burn an owed fee leg.
            let non_leg = vault_before_close.saturating_sub(legs);
            if burned > non_leg && std::env::var("FUZZ_STRICT_F4").map_or(false, |v| v == "1") {
                return Err(format!(
                    "I10 F4 CLOSESLAB BURNED FEE LEGS: burned {burned} > non-leg residue {non_leg} (legs owed {legs}, vault {vault_before_close})"
                ));
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
            let lp_outstanding = self.lp_vault.and_then(|(reg, _, _)| self.env.svm.get_account(&reg)).and_then(|a| state::read_lp_vault_registry(&a.data).ok()).map_or(0, |r| r.total_lp_shares_outstanding);
            let bound_budget = self.stake.is_some() && self.env.market_state().1.insurance_domain_budget_remaining_total > 0;
            if bound_budget {
                *self.stats.soft.entry("F9_bound_market_insurance_stranded").or_default() += 1;
            } else if lp_outstanding > 0 {
                // By design (v16_fork_lp_vault_redeem): the LP-vault dead-share floor blocks CloseSlab.
                *self.stats.soft.entry("closeslab_blocked_by_lp_vault_shares(by design)").or_default() += 1;
            } else if std::env::var("FUZZ_STRICT_CLOSE").map_or(false, |v| v == "1") {
                let (_, g) = self.env.market_state();
                return Err(format!(
                    "L1 CLOSESLAB WEDGED after full wind-down: code {code}, vault {} ins {} budget {} fresh_backing {} provider_recv {:?} bucket_status {:?} engine_slot {} clock {}",
                    g.vault, g.insurance, g.insurance_domain_budget_remaining_total, g.source_fresh_backing_total_num,
                    g.source_credit.iter().map(|c| c.provider_receivable_num).collect::<Vec<_>>(),
                    g.source_backing_buckets.iter().map(|b| (b.status, b.expiry_slot)).collect::<Vec<_>>(),
                    g.current_slot, self.slot()
                ));
            }
        }
        Ok(())
    }
}

pub fn gen_op(rng: &mut XorShiftRng) -> Op {
    let u = rng.gen::<u8>();
    // FUZZ_INS_HEAVY=1: extra, large insurance top-ups (recredit large relative to residual).
    if std::env::var("FUZZ_INS_HEAVY").map_or(false, |v| v == "1") && rng.gen_range(0..8) == 0 {
        return Op::TopUpInsurance { amt: rng.gen_range(1_000_000..20_000_000) };
    }
    match rng.gen_range(0..if p3_mode() { 132 } else { 124 }) {
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
        98 => Op::ClosePortfolio { u },
        112..=116 => Op::TradeNoCpiA1 { a: u, b: rng.gen(), size_tenths: rng.gen_range(-400..=400) },
        117..=119 => Op::PushA1 { delta_bps: rng.gen_range(-2500..=2500) },
        120..=123 => Op::BatchNoCpi { a: u, b: rng.gen(), s0: rng.gen_range(-300..=300), s1: rng.gen_range(-300..=300) },
        124..=125 => Op::P3JuniorDeposit { amt: rng.gen_range(1_000..3_000_000) },
        126..=127 => Op::P3JuniorWithdraw { frac_bps: rng.gen_range(1..=10_000) },
        128..=129 => Op::P3Recall { amt: rng.gen_range(1..5_000_000) },
        130..=131 => Op::P3Release { amt: rng.gen_range(1..5_000_000) },
        _ => match rng.gen_range(0..4) {
            3 => Op::Stake87Accrue,
            0 => Op::LpDeposit { u, amt: rng.gen_range(1_000..10_000_000) },
            1 => Op::LpCrank { d: rng.gen() },
            _ => Op::LpRedeem { u, frac_bps: rng.gen_range(1..=10_000) },
        },
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
                        // FUZZ_FEE0=1: no trading fees at all (no LP fee leg pending at resolve), so any
                        // claim-free residual can only be cleared by 78's insurance recredit.
                        let fee_bps = if std::env::var("FUZZ_FEE0").map_or(false, |v| v == "1") { 0 } else { [0u64, 5, 30][rng.gen_range(0..3)] };
                        // FUZZ_RANDLEN=1: resolve at a random point (random sequence length),
                        // so wind-down (resolve) lands with fees/positions outstanding anywhere.
                        let n = if std::env::var("FUZZ_RANDLEN").map_or(false, |v| v == "1") { rng.gen_range(1..=len) } else { len };
                        let ops: Vec<Op> = (0..n).map(|_| gen_op(&mut rng)).collect();
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
    eprintln!("   haircut_then_burn: {} cases; first: {:?}", st.haircut_then_burn.len(), st.haircut_then_burn.first());
    eprintln!(
        "   winddowns {} closeslab_ok {} burned_at_close {} legs_outstanding_at_close {}",
        st.winddowns, st.closeslab_ok, st.burned_at_close, st.legs_outstanding_at_close
    );
    // Non-vacuity: the fuzz must actually exercise value-moving paths.
    // P3 mode (F-14 head): NoCpi growth on the bound asset is refused (77), so NoCpi successes
    // are not required there — instead require that the refusal was actually exercised (P3-g).
    if p3_mode() {
        assert!(st.ok.get("p3g_nocpi_growth_refused_77").copied().unwrap_or(0) > 0 || st.ok.get("trade_nocpi").copied().unwrap_or(0) > 0,
            "vacuous P3 fuzz: NoCpi neither succeeded nor was refused with 77");
    }
    for k in ["deposit", "withdraw", "trade_nocpi", "trade_cpi", "push_mark", "crank"] {
        if p3_mode() && k == "trade_nocpi" && st.ok.get("p3g_nocpi_growth_refused_77").copied().unwrap_or(0) > 0 {
            continue; // covered by the P3-g refusal requirement above
        }
        assert!(st.ok.get(k).copied().unwrap_or(0) > 0, "vacuous fuzz: no successful {k}");
    }
    let f = failures.lock().unwrap();
    assert!(f.is_empty(), "{} invariant violation(s):\n{}", f.len(), f.join("\n\n"));
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVENESS: resolved-market retirement (spec §2.4 "retirement" + README
// "Permissionless progress": a public path must either commit progress or return
// a terminal error; no ordinary state may need a privileged operator forever).
// Shrunk from fuzz seed 0x1715609f7c74cb56 (3 ops).
// ═══════════════════════════════════════════════════════════════════════════

fn wedge_prefix(w: &mut World) {
    for op in [
        Op::TradeCpi { u: 219, size_tenths: 175 },
        Op::TradeNoCpi { a: 215, b: 241, size_tenths: -324, off_bps: 2878 },
        Op::Push { delta_bps: 2295 },
    ] {
        let _ = w.apply(&op);
        w.check().expect("invariants during prefix");
    }
    for _ in 0..40 {
        let s = w.slot() + 5;
        w.env.svm.warp_to_slot(s);
        let _ = w.do_push(w.mark);
        let _ = w.do_crank(N_USERS);
        let (_, g) = w.env.market_state();
        if g.assets[0].effective_price == g.assets[0].raw_oracle_target_price {
            break;
        }
    }
    w.do_resolve().expect("resolve");
}

fn close_everyone(w: &mut World, warp_before_last: u64) {
    let mut warped = warp_before_last == 0;
    for _round in 0..12 {
        for u in 0..=N_USERS {
            if w.closed[u] {
                continue;
            }
            let open = w.closed.iter().filter(|c| !**c).count();
            if open == 1 && !warped {
                let s = w.slot() + warp_before_last;
                w.env.svm.warp_to_slot(s);
                warped = true;
            }
            let _ = w.do_close_resolved(u);
            w.check().expect("invariants while closing");
            let _ = w.do_close_portfolio(u);
            w.check().expect("invariants while closing");
        }
        if w.closed.iter().all(|c| *c) {
            break;
        }
        let s = w.slot() + 3;
        w.env.svm.warp_to_slot(s);
    }
    assert!(w.closed.iter().all(|c| *c), "vacuity: portfolios not all closed: {:?}", w.closed);
    let _ = w.do_claim_protocol();
    let _ = w.do_claim_creator();
    let budget = w.env.market_state().1.insurance_domain_budget_remaining_total;
    if budget > 0 {
        let _ = w.do_withdraw_terminal_insurance(budget);
    }
}

/// Every permissionless / authority exit, far in the future. Returns true if retired.
fn try_retire(w: &mut World) -> bool {
    for step in [1u64, 1_000, 1_000_000] {
        let s = w.slot() + step;
        w.env.svm.warp_to_slot(s);
        let _ = w.do_expire(0);
        let _ = w.do_expire(1);
        let _ = w.do_finalize(0);
        let _ = w.do_finalize(1);
        for _ in 0..4 {
            let _ = w.do_close_slab();
            if w.is_tombstone() {
                return true;
            }
            // P1 doc: CloseSlab may re-book orphaned legs onto the protocol leg and
            // return Ok without closing; claim 84/90 and call again.
            let _ = w.do_claim_protocol();
            let _ = w.do_claim_creator();
            if let Ok((_, g)) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.env.market_state())) {
                let rb = g.insurance_domain_budget_remaining_total;
                if rb > 0 {
                    let _ = w.do_withdraw_terminal_insurance(rb);
                }
            }
        }
    }
    false
}

#[test]
fn indep_liveness_resolved_market_retires_even_if_everyone_closes_before_bucket_expiry() {
    let mut w = World::new(0);
    wedge_prefix(&mut w);
    close_everyone(&mut w, 0);
    let (_, g) = w.env.market_state();
    assert_eq!(g.materialized_portfolio_count, 0, "vacuity: every portfolio must be freed");
    let stranded = w.token_amount(&w.env.vault);
    let buckets: Vec<_> = g.source_backing_buckets.iter().map(|b| (b.status, b.expiry_slot)).collect();
    eprintln!("pre-retire: stranded {stranded} buckets {buckets:?} engine_slot {} clock {} recv {:?}", g.current_slot, w.slot(), g.source_credit.iter().map(|c| c.provider_receivable_num).collect::<Vec<_>>());
    let retired = try_retire(&mut w);
    w.check_tokens().unwrap();
    assert!(
        retired,
        "L1 WEDGE: resolved, all portfolios closed, market can never retire: {stranded} atoms stranded in \
         vault (c_tot 0, insurance {}), buckets {buckets:?}, engine slot {} frozen vs clock {}",
        g.insurance,
        g.current_slot,
        w.slot()
    );
}

/// Control: same market, but the last CloseResolved waits past the bucket expiry so it
/// advances the resolved clock (#506). If THIS retires and the test above does not, the
/// wedge is purely an ordering race that any permissionless closer can trigger.
#[test]
fn indep_liveness_control_resolved_market_retires_when_last_close_waits_past_expiry() {
    let mut w = World::new(0);
    wedge_prefix(&mut w);
    close_everyone(&mut w, 400);
    let before = w.token_amount(&w.env.vault);
    let burned0 = w.burned();
    let retired = try_retire(&mut w);
    w.check_tokens().unwrap();
    eprintln!("control: retired={retired} vault_before={before} burned={}", w.burned() - burned0);
    assert!(retired, "control: even the patient ordering cannot retire the market");
}

/// F4 (master plan P1 fee fix): CloseSlab must not burn unclaimed protocol / creator /
/// LP / staker fee legs — pay or reserve them first, or refuse to close.
#[test]
fn indep_f4_closeslab_never_burns_owed_fee_legs() {
    let mut w = World::new(30);
    // Fee-bearing trades, flat afterwards, no price move: no losses, only fee legs.
    w.do_trade_nocpi(0, 1, 50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    w.do_trade_nocpi(0, 1, -50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("close");
    w.check().unwrap();
    let legs_live = w.legs_outstanding();
    assert!(legs_live > 0, "vacuity: trades must accrue fee legs");
    w.do_resolve().expect("resolve");
    close_everyone(&mut w, 0);
    let legs = w.legs_outstanding();
    let vault = w.token_amount(&w.env.vault);
    let burned0 = w.burned();
    let retired = try_retire(&mut w);
    w.check_tokens().unwrap();
    let burned = w.burned() - burned0;
    assert!(retired, "F4 liveness: with every claim path exercised (84/90 between calls) the market must still retire; legs {legs}");
    eprintln!("F4: legs_live {legs_live} legs_at_close {legs} vault {vault} burned {burned} retired {}", w.is_tombstone());
    let non_leg = vault.saturating_sub(legs);
    assert!(
        burned <= non_leg,
        "I10 F4: CloseSlab burned {burned} atoms while {legs} atoms of fee legs were owed (vault {vault})"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// LIVENESS FUZZ (task item 3): after ANY random sequence, the market must be
// recoverable with ONLY permissionless actions (crank 5, ExpireBackingBucket 89,
// FinalizeResetSide 45) plus the keeper re-pushing the CURRENT mark — no admin,
// no user cooperation. "Recovered" = (a) a brand-new pair of wallets can deposit,
// open 1 unit at mark and close it, and (b) every flat user can withdraw all of
// its capital. README "Permissionless progress": a public crank must commit
// bounded progress or return a terminal/recovery error.
// ═══════════════════════════════════════════════════════════════════════════

impl World {
    fn add_user(&mut self) -> usize {
        let k = Keypair::new();
        let p = self.env.create_portfolio(&k);
        self.owners.push(k);
        self.ports.push(p);
        self.closed.push(false);
        self.ports.len() - 1
    }

    fn is_flat(&self, u: usize) -> bool {
        self.env
            .svm
            .get_account(&self.ports[u])
            .and_then(|a| state::read_portfolio(&a.data).ok())
            .map_or(true, |p| p.active_bitmap == percolator::active_bitmap_empty())
    }

    /// Permissionless repair rounds. Returns the codes the repairs hit.
    fn permissionless_repair(&mut self, rounds: usize) -> Vec<String> {
        let mut seen = Vec::new();
        let mut done_extra = 0;
        for r in 0..rounds {
            // Stop once the effective price has caught the target and 3 extra rounds ran.
            let (_, g) = self.env.market_state();
            if g.assets[0].effective_price == g.assets[0].raw_oracle_target_price {
                done_extra += 1;
                if done_extra > 3 && r > 3 {
                    break;
                }
            }
            let s = self.slot() + 20;
            self.env.svm.warp_to_slot(s);
            let _ = self.do_push(self.mark);
            for u in 0..self.ports.len() {
                if self.closed[u] {
                    continue;
                }
                if let Err(e) = self.do_crank(u) {
                    seen.push(format!("crank:{:?}", custom_code(&e)));
                }
            }
            // P3 mode: the vault LP is not in `ports`; a keeper cranks it too (permissionless).
            if let Some(lp) = self.p3.as_ref().map(|c| c.lp) {
                if self.env.svm.get_account(&lp).map_or(false, |a| a.lamports > 0) {
                    let _ = self.p3_crank_port(lp);
                }
            }
            for d in 0..2u16 {
                if std::env::var("INDEP_NO_EXPIRE").is_err() {
                    let _ = self.do_expire(d);
                }
            }
            for sd in 0..2u8 {
                let _ = self.do_finalize(sd);
            }
        }
        seen
    }

    fn probe_recovered(&mut self) -> Result<(), String> {
        let a = self.add_user();
        let b = self.add_user();
        self.do_deposit(a, 5_000_000).map_err(|e| format!("fresh deposit a: {:?}", custom_code(&e)))?;
        self.do_deposit(b, 5_000_000).map_err(|e| format!("fresh deposit b: {:?}", custom_code(&e)))?;
        let q = POS_SCALE as i128;
        if p3_mode() && self.p3.is_some() {
            // P3 asset: all trading goes through the vault LP (NoCpi growth is 77 by design).
            let _ = b;
            let s = self.slot() + 1;
            self.env.svm.warp_to_slot(s);
            let _ = self.do_push(self.mark);
            let _ = self.do_crank(a);
            // Size the probe inside the 1x-equity cap: 1% of LP capital in notional.
            let lp_cap = self.env.svm.get_account(&self.p3.as_ref().unwrap().lp).and_then(|x| state::read_portfolio(&x.data).ok()).map_or(0, |p| p.capital);
            let q = ((lp_cap / 100).max(1) as i128 * POS_SCALE as i128 / self.mark.max(1) as i128).max(1);
            if let Err(e) = self.p3_trade_vs_vault_lp(a, q) {
                let lp = self.p3.as_ref().unwrap().lp;
                let cap = self.env.svm.get_account(&lp).and_then(|x| state::read_portfolio(&x.data).ok()).map(|p| (p.capital, p.pnl));
                // 80 VaultLpExposureCapExceeded with a depleted vault LP (1x-equity cap = 0) is the
                // designed "bounded death" until the junior re-capitalises; report it distinctly.
                return Err(format!("fresh open vs vault LP: {:?} (vault LP capital/pnl {:?})", custom_code(&e), cap));
            }
            self.p3_trade_vs_vault_lp(a, -q).map_err(|e| format!("fresh close vs vault LP: {:?}", custom_code(&e)))?;
            let _ = q;
        } else {
            self.do_trade_nocpi(a, b, q, self.mark).map_err(|e| format!("fresh open at mark: {:?}", custom_code(&e)))?;
            self.do_trade_nocpi(a, b, -q, self.mark).map_err(|e| format!("fresh close at mark: {:?}", custom_code(&e)))?;
        }
        for u in 0..self.ports.len() {
            if self.closed[u] || !self.is_flat(u) {
                continue;
            }
            let _ = self.do_crank(u);
            let cap = self.env.portfolio_state(self.ports[u]).capital;
            if cap > 0 {
                self.do_withdraw(u, cap)
                    .map_err(|e| format!("flat user {u} cannot withdraw its {cap} capital: {:?}", custom_code(&e)))?;
            }
        }
        Ok(())
    }
}

/// SUPERSEDED (F-3 triage): demands a fresh open while A != ADL_ONE, which the spec forbids.
/// Kept as a record; see indep_liveness_fuzz_owner_exits_then_reopen.
#[test]
#[ignore]
fn indep_liveness_fuzz_permissionless_recovery() {
    let seqs = env_u64("FUZZ_LIVE_SEQS", 48);
    let len = env_u64("FUZZ_LEN", 40) as usize;
    let seed0 = env_u64("FUZZ_SEED", 0x11fe);
    let threads = env_u64("FUZZ_THREADS", 4).max(1);
    let fails = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let codes = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<String, u64>::new()));
    let mut hs = Vec::new();
    for t in 0..threads {
        let (fails, codes) = (fails.clone(), codes.clone());
        hs.push(std::thread::Builder::new().stack_size(64 << 20).spawn(move || {
            let mut i = t;
            while i < seqs {
                let seed = seed0.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let mut rng = XorShiftRng::seed_from_u64(seed);
                let fee_bps = [0u64, 5, 30][rng.gen_range(0..3)];
                let ops: Vec<Op> = (0..len).map(|_| gen_op(&mut rng)).collect();
                let mut w = World::new(fee_bps);
                for op in &ops {
                    let _ = w.apply(op);
                    if let Err(e) = w.check() {
                        fails.lock().unwrap().push(format!("seed={seed:#x}: invariant during ops: {e}"));
                        break;
                    }
                }
                let seen = w.permissionless_repair(400);
                for c in seen {
                    *codes.lock().unwrap().entry(c).or_default() += 1;
                }
                if let Err(e) = w.probe_recovered() {
                    let (_, g) = w.env.market_state();
                    fails.lock().unwrap().push(format!(
                        "seed={seed:#x} fee={fee_bps}: L2 NOT RECOVERABLE PERMISSIONLESSLY: {e} | mode {:?} hlock {} stress {} loss_stale {} recovery {:?} eff {} target {} buckets {:?} sides {:?}/{:?}",
                        g.mode, g.bankruptcy_hlock_active, g.threshold_stress_active, g.loss_stale_active, g.recovery_reason,
                        g.assets[0].effective_price, g.assets[0].raw_oracle_target_price,
                        g.source_backing_buckets.iter().map(|b| (b.status, b.expiry_slot)).collect::<Vec<_>>(),
                        g.assets[0].mode_long, g.assets[0].mode_short
                    ));
                }
                if let Err(e) = w.check() {
                    fails.lock().unwrap().push(format!("seed={seed:#x}: invariant after recovery: {e}"));
                }
                i += threads;
            }
        }).unwrap());
    }
    for h in hs {
        h.join().expect("thread");
    }
    eprintln!("== liveness fuzz: {seqs} seqs; repair-time crank errors: {:?}", codes.lock().unwrap());
    let f = fails.lock().unwrap();
    assert!(f.is_empty(), "{} unrecoverable/violating sequence(s):\n{}", f.len(), f.join("\n"));
}

fn live_fails(fee_bps: u64, ops: &[Op]) -> Option<String> {
    let mut w = World::new(fee_bps);
    for op in ops {
        let _ = w.apply(op);
    }
    let _ = w.permissionless_repair(400);
    w.probe_recovered().err()
}

fn ddmin_live(fee_bps: u64, ops: Vec<Op>) -> Vec<Op> {
    let mut cur = ops;
    let mut n = 2usize;
    let mut budget = 300;
    while cur.len() >= 2 && budget > 0 {
        let chunk = (cur.len() + n - 1) / n;
        let mut reduced = false;
        for start in (0..cur.len()).step_by(chunk) {
            budget -= 1;
            let mut cand = cur.clone();
            cand.drain(start..(start + chunk).min(cand.len()));
            if live_fails(fee_bps, &cand).map_or(false, |e| e.contains("fresh open")) {
                cur = cand;
                n = (n - 1).max(2);
                reduced = true;
                break;
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
    cur
}

/// Shrinks one liveness failure given by FUZZ_ONE_SEED (hex) and prints the repro.
#[test]
#[ignore]
fn indep_liveness_shrink_one() {
    let seed = u64::from_str_radix(std::env::var("FUZZ_ONE_SEED").unwrap().trim_start_matches("0x"), 16).unwrap();
    let len = env_u64("FUZZ_LEN", 50) as usize;
    let mut rng = XorShiftRng::seed_from_u64(seed);
    let fee_bps = [0u64, 5, 30][rng.gen_range(0..3)];
    let ops: Vec<Op> = (0..len).map(|_| gen_op(&mut rng)).collect();
    let e = live_fails(fee_bps, &ops).expect("seed does not fail");
    let min = ddmin_live(fee_bps, ops);
    eprintln!("SHRUNK fee={fee_bps} ({} ops) err={:?}\n  ops: {min:?}", min.len(), live_fails(fee_bps, &min));
    let _ = e;
}

/// Shrunk from liveness-fuzz seed 0xfa8cfc37711c3fb7 (fee 0): two opposite positions,
/// then the mark falls ~33% in two keeper pushes (10x leverage => the long is bankrupt).
/// After 400 permissionless repair rounds (8,000 slots; crank every portfolio, 89 on both
/// domains, 45 on both sides) the price has caught up, yet a FRESH pair of wallets
/// cannot open 1 unit at mark. Spec/README: public cranks must make bounded progress,
/// and no ordinary state may need a privileged operator to reopen the market.
/// SUPERSEDED (F-3 triage): probes a spec-forbidden fresh attach in the ADL reduce-only
/// state. See indep_f3_adl_reduce_only_then_owner_exits_reopen_market.
#[test]
#[ignore]
fn indep_liveness_market_reopens_after_single_bankruptcy() {
    let ops = [
        Op::TradeCpi { u: 48, size_tenths: 366 },
        Op::TradeNoCpi { a: 7, b: 90, size_tenths: -214, off_bps: -1908 },
        Op::Push { delta_bps: -2157 },
        Op::Push { delta_bps: -1266 },
    ];
    let mut w = World::new(0);
    for op in &ops {
        let r = w.apply(op);
        eprintln!("op {op:?} -> {:?}", r.map_err(|e| custom_code(&e)));
        w.check().unwrap();
    }
    let codes = w.permissionless_repair(400);
    let mut hist = std::collections::BTreeMap::<String, u64>::new();
    for c in codes { *hist.entry(c).or_default() += 1; }
    let (_, g) = w.env.market_state();
    eprintln!("after repair: crank errs {hist:?}; hlock {} mode {:?} eff {} tgt {} oi {}/{} buckets {:?} sides {:?}/{:?} slot {}/{}",
        g.bankruptcy_hlock_active, g.mode, g.assets[0].effective_price, g.assets[0].raw_oracle_target_price,
        g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q,
        g.source_backing_buckets.iter().map(|b| (b.status, b.expiry_slot, b.fresh_unliened_backing_num)).collect::<Vec<_>>(),
        g.assets[0].mode_long, g.assets[0].mode_short, g.current_slot, w.slot());
    for (i, sc) in g.source_credit.iter().enumerate() {
        eprintln!("  domain {i}: credit_rate {} fresh_reserved {} spent {} recv {} liened {} claim_bound {}", sc.credit_rate_num, sc.fresh_reserved_backing_num, sc.spent_backing_num, sc.provider_receivable_num, sc.valid_liened_backing_num, sc.positive_claim_bound_num);
    }
    for u in 0..w.ports.len() {
        let p = w.env.portfolio_state(w.ports[u]);
        let legs: Vec<_> = p.legs.iter().filter(|l| l.active).map(|l| l.basis_pos_q).collect();
        eprintln!("  u{u}: cap {} pnl {} reserved {} legs {legs:?} stale {} b_stale {} liq_lock {}", p.capital, p.pnl, p.reserved_pnl, p.stale_state, p.b_stale_state, p.liquidation_lock);
    }
    for u in 0..w.ports.len() {
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        eprintln!("  crank u{u}: {:?}", w.do_crank(u).map_err(|e| custom_code(&e)));
    }
    let r = w.probe_recovered();
    if r.is_err() {
        // Diagnose: is there a PRIVILEGED exit? Backing authority tops up domain 0.
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let exp = s + 1_000_000;
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            w.env.top_up_backing_bucket(0, 5_000_000, exp);
        }));
        eprintln!("admin TopUpBackingBucket(domain 0): {}", if res.is_ok() { "ok" } else { "FAILED" });
        let _ = w.permissionless_repair(5);
        for u in 0..w.ports.len() {
            eprintln!("  post-topup crank u{u}: {:?}", w.do_crank(u).map_err(|e| custom_code(&e)));
        }
        let a = w.add_user();
        let b = w.add_user();
        let _ = w.do_deposit(a, 5_000_000);
        let _ = w.do_deposit(b, 5_000_000);
        let q = POS_SCALE as i128;
        let fo = w.do_trade_nocpi(a, b, q, w.mark);
        if let Err(e) = &fo {
            for l in e.split("\", \"") { if l.contains("Program log") || l.contains("failed") { eprintln!("   LOG {}", &l[..l.len().min(300)]); } }
        }
        eprintln!("after privileged top-up, fresh open: {:?}", fo.map_err(|e| custom_code(&e)));
        let (_, g2) = w.env.market_state();
        eprintln!("   hlock {} stress {} loss_stale {} b_stale_cnt {} stale_cert {} neg_cnt {} pending_barriers {:?} a0 stale_long {} ", g2.bankruptcy_hlock_active, g2.threshold_stress_active, g2.loss_stale_active, g2.b_stale_account_count, g2.stale_certificate_count, g2.negative_pnl_account_count, g2.pending_domain_loss_barriers, g2.assets[0].stored_pos_count_long);
        let (_, g3) = w.env.market_state();
        eprintln!("   post-topup domain0 credit_rate {} bucket {:?}", g3.source_credit[0].credit_rate_num, (g3.source_backing_buckets[0].status, g3.source_backing_buckets[0].expiry_slot, g3.source_backing_buckets[0].fresh_unliened_backing_num));
        let refresh = |w: &mut World, us: &[usize]| {
            let s = w.slot() + 1;
            w.env.svm.warp_to_slot(s);
            let _ = w.do_push(w.mark);
            for &u in us { let _ = w.do_crank(u); }
        };
        refresh(&mut w, &[a, b]);
        eprintln!("fresh open after refresh: {:?}", w.do_trade_nocpi(a, b, POS_SCALE as i128, w.mark).map_err(|e| custom_code(&e)));
        refresh(&mut w, &[4]);
        eprintln!("winner u4 withdraw 1 atom of capital: {:?}", w.do_withdraw(4, 1).map_err(|e| custom_code(&e)));
        refresh(&mut w, &[0, 1]);
        eprintln!("winner u4 convert 1 atom pnl: {:?}", w.do_convert(4, 1).map_err(|e| custom_code(&e)));
        eprintln!("loser u0 reduce (sell 1 unit to u1): {:?}", w.do_trade_nocpi(1, 0, POS_SCALE as i128, w.mark).map_err(|e| custom_code(&e)));
        refresh(&mut w, &[3, 4]);
        eprintln!("winner u4 reduce short (buy 1 unit from u3): {:?}", w.do_trade_nocpi(4, 3, POS_SCALE as i128, w.mark).map_err(|e| custom_code(&e)));
    }
    assert!(r.is_ok(), "L2 market cannot reopen permissionlessly after one bankruptcy: {r:?}");
}

/// F-5: shrunk from fuzz seed 0x78dde6e5fd2a4f41 (fee 30; reproduces on v18.2 and P1 eb103309).
/// After a bankruptcy + insurance top-up and a COMPLETE wind-down (every portfolio closed,
/// topups 46, fee claims, tag 41, tag 89), CloseSlab returns Custom(21) forever: an Expired
/// bucket keeps a nonzero provider_receivable with no remaining claimant. Retirement must stay
/// reachable (spec §2.4: retirement clears audit-only state atomically).
#[test]
fn indep_liveness_closeslab_retires_after_bankruptcy_and_insurance_topup() {
    let ops = [
        Op::Withdraw { u: 202, frac_bps: 5924 },
        Op::Push { delta_bps: -2497 },
        Op::TradeNoCpi { a: 142, b: 35, size_tenths: 367, off_bps: 1741 },
        Op::TopUpInsurance { amt: 2_747_414 },
    ];
    let mut w = World::new(30);
    for op in &ops {
        let _ = w.apply(op);
        w.check().unwrap();
    }
    w.wind_down().unwrap();
    if !w.is_tombstone() {
        let (_, g0) = w.env.market_state();
        let b = g0.insurance_domain_budget_remaining_total;
        eprintln!("residual budget {b}: tag41 again -> {:?}; domain budgets {:?}", w.do_withdraw_terminal_insurance(b).map_err(|e| custom_code(&e)), g0.insurance_domain_budget);
        let retired = try_retire(&mut w);
        if retired {
            w.check_tokens().unwrap();
            return;
        }
        let (_, g) = w.env.market_state();
        assert!(
            retired,
            "F-5 CloseSlab wedged forever: vault {} ins {} budget {} provider_recv {:?} buckets {:?} (clock {})",
            g.vault, g.insurance, g.insurance_domain_budget_remaining_total,
            g.source_credit.iter().map(|c| c.provider_receivable_num).collect::<Vec<_>>(),
            g.source_backing_buckets.iter().map(|b| (b.status, b.expiry_slot)).collect::<Vec<_>>(), w.slot()
        );
    }
    w.check_tokens().unwrap();
}

/// F5 (fee-flow audit; P1 "optional"): LP fees accrued before the first Earn depositor
/// must not be captured by that depositor (spec intent: route to insurance). Measures the
/// capture; fails while the first depositor can walk away with the pre-existing backlog.
#[test]
fn indep_f5_first_earn_depositor_does_not_capture_prevault_fee_backlog() {
    let mut w = World::new(30);
    for _ in 0..5 {
        w.do_trade_nocpi(0, 1, 50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
        w.do_trade_nocpi(0, 1, -50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("close");
    }
    let (cfg, _) = w.env.market_state();
    let backlog = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(backlog > 0, "vacuity: LP fee backlog must exist");
    let dep: u64 = 1_000_000;
    w.do_lp_deposit(2, dep).expect("genesis LP deposit");
    let cr = w.do_lp_crank(0);
    eprintln!("F5: backlog {backlog}, crank78 -> {:?}", cr.as_ref().map_err(|e| custom_code(e)));
    w.check().unwrap();
    let before: u128 = w.tokens.iter().map(|k| w.token_amount(k)).sum::<u128>() - w.token_amount(&w.env.vault);
    let r = w.do_lp_redeem(2, 10_000);
    eprintln!("F5: redeem -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    w.check().unwrap();
    let after: u128 = w.tokens.iter().map(|k| w.token_amount(k)).sum::<u128>() - w.token_amount(&w.env.vault);
    let payout = after - before;
    eprintln!("F5: deposited {dep}, redeemed {payout}, captured {}", payout as i128 - dep as i128);
    assert!(
        payout <= dep as u128,
        "F5: first Earn depositor captured {} atoms of pre-deposit LP fees (backlog {backlog})",
        payout - dep as u128
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Coordinator gap 4: permissionless stale resolve as the F-3 escape. The relaunch seed
// sets a non-zero `permissionless_resolve_stale_slots`. Spec intent (README
// "Permissionless progress" / ResolveStalePermissionless): once the stamped
// last_good_oracle_slot is older than stale_slots, ANYONE can resolve, and every user
// can then close and be paid without the admin.
// ═══════════════════════════════════════════════════════════════════════════

impl World {
    fn do_configure_stale_resolve(&mut self, stale_slots: u64, force_close_delay_slots: u64) -> Result<u64, String> {
        let policy_sequence = self.env.control_sequences(0).permissionless_resolve + 1;
        let fr = state::read_asset_generation_frontier(&self.env.svm.get_account(&self.env.market).unwrap().data).unwrap();
        let admin = self.env.admin.insecure_clone();
        let m = self.env.market;
        self.send(
            ProgInstruction::ConfigurePermissionlessResolve { asset_generation_frontier: fr, stale_slots, force_close_delay_slots, policy_sequence },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
    }

    fn do_resolve_stale(&mut self) -> Result<u64, String> {
        let now = self.slot();
        let m = self.env.market;
        self.send(ProgInstruction::ResolveStalePermissionless { now_slot: now }, vec![AccountMeta::new(m, false)], &[])
    }

    /// Permissionless-only close-out: CloseResolved + tag 46 for every portfolio, no admin.
    /// Returns (users paid in total, users still holding capital/positions).
    fn permissionless_close_out(&mut self) -> Result<(u128, Vec<usize>), String> {
        let before: u128 = self.user_token_total();
        for _ in 0..8 {
            for u in 0..self.ports.len() {
                if self.closed[u] {
                    continue;
                }
                let _ = self.do_close_resolved(u);
                let _ = self.do_claim_topup(u);
                self.check()?;
            }
            let s = self.slot() + 60;
            self.env.svm.warp_to_slot(s);
        }
        let mut stuck = Vec::new();
        for u in 0..self.ports.len() {
            let p = self.env.portfolio_state(self.ports[u]);
            let r = p.resolved_payout_receipt;
            if p.capital > 0 || p.active_bitmap != percolator::active_bitmap_empty() || (r.present && !r.finalized) {
                stuck.push(u);
            }
        }
        Ok((self.user_token_total() - before, stuck))
    }

    fn user_token_total_of(&self, u: usize) -> u128 {
        let o = self.owners[u].pubkey();
        self.tokens.iter().filter_map(|k| self.env.svm.get_account(k)).filter_map(|a| TokenAccount::unpack(&a.data).ok()).filter(|t| t.owner == o).map(|t| t.amount as u128).sum()
    }

    fn user_token_total(&self) -> u128 {
        let owners: Vec<Pubkey> = self.owners.iter().map(|k| k.pubkey()).collect();
        self.tokens
            .iter()
            .filter_map(|k| self.env.svm.get_account(k))
            .filter_map(|a| TokenAccount::unpack(&a.data).ok())
            .filter(|t| owners.contains(&t.owner))
            .map(|t| t.amount as u128)
            .sum()
    }
}

fn f3_frozen_world(stale_slots: u64) -> World {
    let mut w = World::new(0);
    w.do_configure_stale_resolve(stale_slots, 100).expect("configure permissionless stale resolve (seed policy)");
    for op in [
        Op::TradeCpi { u: 48, size_tenths: 366 },
        Op::TradeNoCpi { a: 7, b: 90, size_tenths: -214, off_bps: -1908 },
        Op::Push { delta_bps: -2157 },
        Op::Push { delta_bps: -1266 },
    ] {
        let _ = w.apply(&op);
        w.check().unwrap();
    }
    let _ = w.permissionless_repair(400);
    let r = w.probe_recovered();
    assert!(r.is_err(), "vacuity: the F-3 freeze must reproduce before testing its escape");
    w
}

/// While the keeper keeps pushing, the frozen F-3 market is NOT stale, so the escape
/// cannot fire: users stay frozen as long as the keeper is healthy. Records behaviour.
#[test]
fn indep_f3_escape_stale_resolve_blocked_while_keeper_pushes() {
    let mut w = f3_frozen_world(9_000);
    for _ in 0..500 {
        let s = w.slot() + 20;
        w.env.svm.warp_to_slot(s);
        let _ = w.do_push(w.mark);
        let _ = w.do_crank(N_USERS);
    }
    let r = w.do_resolve_stale();
    eprintln!("F3-escape (keeper alive, 10,000 slots > stale 9,000): ResolveStalePermissionless -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    assert!(r.is_err(), "a live keeper keeps the market fresh; stale resolve must not fire");
}

/// The escape: keeper stops pushing; after stale_slots anyone resolves; then every user
/// is closed out and paid with NO admin action, and token conservation holds.
#[test]
fn indep_f3_escape_stale_resolve_unfreezes_and_every_user_is_paid_permissionlessly() {
    let stale = 9_000;
    let mut w = f3_frozen_world(stale);
    let deposited: u128 = w.minted;
    // Keeper dies. Only permissionless cranks continue.
    let s = w.slot() + stale + 5;
    w.env.svm.warp_to_slot(s);
    let _ = w.do_crank(N_USERS);
    let r = w.do_resolve_stale();
    eprintln!("F3-escape: ResolveStalePermissionless -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    r.expect("stale resolve must fire once the oracle is older than stale_slots");
    w.check().unwrap();
    assert_eq!(w.env.market_state().1.mode, MarketModeV16::Resolved);
    let (paid, stuck) = w.permissionless_close_out().unwrap();
    w.check().unwrap();
    let (_, g) = w.env.market_state();
    eprintln!("F3-escape: paid {paid} of {deposited} minted; stuck users {stuck:?}; vault left {} (ins {}, c_tot {})", g.vault, g.insurance, g.c_tot);
    assert!(stuck.is_empty(), "F3-escape: users {stuck:?} still hold capital/positions/unfinalized receipts after permissionless close-out");
    assert_eq!(g.c_tot, 0, "all user capital must have been paid out");
}

/// F3 inside the wrapper flow: fee trades -> tag 87 -> stake AccrueFees on a pool that has
/// only the 1,000 dead shares. Must not book (stake F3 fix). Needs INDEP_MAINNET_ID=1,
/// FUZZ_STAKE=1, FUZZ_STAKE_DEAD=1; stake .so via INDEP_STAKE_SO.
#[test]
#[ignore]
fn indep_f3_wrapper_flow_accrue_to_dead_shares_books_nothing() {
    let mut w = World::new(30);
    assert!(w.stake.is_some(), "run with INDEP_MAINNET_ID=1 FUZZ_STAKE=1 FUZZ_STAKE_DEAD=1");
    w.do_trade_nocpi(0, 1, 50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    w.do_trade_nocpi(0, 1, -50 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("close");
    let before = w.pool_fields().unwrap();
    let r = w.do_stake87_accrue();
    let after = w.pool_fields().unwrap();
    let sv = w.stake.unwrap().2;
    eprintln!("F3-wrapper: accrue -> {:?}; pool (deposited, lp) {before:?} -> {after:?}; stake vault {}", r.as_ref().map_err(|e| custom_code(e)), w.token_amount(&sv));
    w.check().unwrap();
    assert!(w.token_amount(&sv) > 0, "vacuity: tag 87 must move the staker leg into the stake vault");
    assert_eq!(after.2, before.2, "F3: AccrueFees booked {} fee atoms to a dead-shares-only pool", after.2 - before.2);
}

impl World {
    /// F-9 fix: stake tag 29 RecoverTerminalInsurance (percolator-stake
    /// fix/stake-f9-terminal-insurance). Permissionless; `stray` is the optional
    /// account-9 vault_auth-owned token account to sweep.
    fn do_stake_recover_terminal(&mut self, amount: u64, stray: Option<Pubkey>) -> Result<u64, String> {
        let (pool, va, sv) = self.stake.ok_or("no stake pool")?;
        let stake_id: Pubkey = "GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3".parse().unwrap();
        let (m, v, wva, pid) = (self.env.market, self.env.vault, self.env.vault_authority, self.env.program_id);
        let mut accounts = vec![
            AccountMeta::new_readonly(self.env.payer.pubkey(), false),
            AccountMeta::new(pool, false),
            AccountMeta::new(sv, false),
            AccountMeta::new_readonly(va, false),
            AccountMeta::new(m, false),
            AccountMeta::new(v, false),
            AccountMeta::new_readonly(wva, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(pid, false),
        ];
        if let Some(k) = stray {
            accounts.push(AccountMeta::new(k, false));
        }
        let mut data = vec![29u8];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = solana_sdk::instruction::Instruction { program_id: stake_id, accounts, data };
        self.env.svm.expire_blockhash();
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, &[])
    }

    /// Wrapper tag 41 sent DIRECTLY by a third party (no stake program), naming the
    /// stake vault_auth PDA as `authority` (unsigned: tag 41 is permissionless) and
    /// `dest` as the payout account. `dest` must be owned by vault_auth.
    fn do_third_party_tag41(&mut self, amount: u128, dest: Pubkey) -> Result<u64, String> {
        let (_, va, _) = self.stake.ok_or("no stake pool")?;
        let (m, v, wva) = (self.env.market, self.env.vault, self.env.vault_authority);
        self.send(
            ProgInstruction::WithdrawInsurance { amount },
            vec![
                AccountMeta::new_readonly(va, false),
                AccountMeta::new(m, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(wva, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[],
        )
    }
}

/// F-9 shared prefix: bound market, 5M insurance budget, stale resolve, everyone out.
fn f9_bound_resolved_world() -> (World, u128) {
    f9_bound_resolved_world_lp(1_000 + 5_000_000)
}

fn f9_bound_resolved_world_lp(total_lp_supply: u64) -> (World, u128) {
    let mut w = World::new(0);
    w.do_configure_stale_resolve(9_000, 100).expect("stale policy");
    w.do_topup_insurance(5_000_000).expect("insurance top-up");
    w.setup_stake(total_lp_supply);
    w.do_trade_nocpi(0, 1, 10 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    let s = w.slot() + 9_005;
    w.env.svm.warp_to_slot(s);
    let _ = w.do_crank(N_USERS);
    w.do_resolve_stale().expect("stale resolve");
    let (_paid, stuck) = w.permissionless_close_out().unwrap();
    assert!(stuck.is_empty(), "users closed out");
    for u in 0..w.ports.len() {
        let _ = w.do_close_portfolio(u);
    }
    let (_, g) = w.env.market_state();
    assert_eq!(g.materialized_portfolio_count, 0);
    (w, g.insurance_domain_budget_remaining_total)
}

/// F-9 fix, griefing variant 1: a third party pushes the whole terminal budget into
/// pool.vault with a DIRECT wrapper tag 41 (bypassing stake). Stake tag 29 with
/// amount 0 must still book it to stakers, and the market must retire.
#[test]
#[ignore]
fn indep_f9_frontrun_direct_tag41_into_pool_vault_is_still_booked() {
    assert!(std::env::var("INDEP_MAINNET_ID").as_deref() == Ok("1") || std::env::var("INDEP_PROGRAM_ID").is_ok(), "run with INDEP_MAINNET_ID=1 or INDEP_PROGRAM_ID");
    let (mut w, budget) = f9_bound_resolved_world();
    assert_eq!(budget, 5_000_000, "vacuity: the full top-up is the terminal budget");
    let sv = w.stake.unwrap().2;
    let fees0 = w.pool_fields().unwrap().2;
    w.do_third_party_tag41(budget, sv).expect("tag 41 is permissionless into a vault_auth-owned dest");
    assert_eq!(w.token_amount(&sv), budget, "front-run landed in pool.vault");
    assert_eq!(w.pool_fields().unwrap().2, fees0, "PRE: the front-run is unbooked");
    let r = w.do_stake_recover_terminal(0, None);
    eprintln!("F-9 frontrun: tag29(0) -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    r.expect("stake tag 29 books a surplus pushed by a third party");
    assert_eq!(w.pool_fields().unwrap().2, fees0 + budget as u64, "stakers credited the full budget");
    let retired = try_retire(&mut w);
    w.check_tokens().unwrap();
    assert!(retired, "market retires after the front-run + booking");
    // Idempotent: a second call finds nothing to book (31).
    assert_eq!(custom_code(&w.do_stake_recover_terminal(0, None).unwrap_err()), Some(31));
}

/// F-9 fix, griefing variant 2: a third party points the permissionless wrapper tag
/// 41 at a STRAY token account it created with owner = vault_auth (not pool.vault).
/// Stake tag 29 sweeps it (account 9) into pool.vault and books it.
#[test]
#[ignore]
fn indep_f9_stray_vault_auth_account_payout_is_swept_and_booked() {
    assert!(std::env::var("INDEP_MAINNET_ID").as_deref() == Ok("1") || std::env::var("INDEP_PROGRAM_ID").is_ok(), "run with INDEP_MAINNET_ID=1 or INDEP_PROGRAM_ID");
    let (mut w, budget) = f9_bound_resolved_world();
    let (_, va, sv) = w.stake.unwrap();
    let stray = w.new_token(va, 0);
    let fees0 = w.pool_fields().unwrap().2;
    w.do_third_party_tag41(budget, stray).expect("tag 41 into a stray vault_auth-owned account");
    assert_eq!(w.token_amount(&stray), budget, "PRE: budget stranded in the stray account");
    // Without the sweep account there is nothing to book (pool.vault is empty): 31.
    assert_eq!(custom_code(&w.do_stake_recover_terminal(0, None).unwrap_err()), Some(31));
    w.do_stake_recover_terminal(0, Some(stray)).expect("sweep + book");
    assert_eq!(w.token_amount(&stray), 0);
    assert_eq!(w.token_amount(&sv), budget);
    assert_eq!(w.pool_fields().unwrap().2, fees0 + budget as u64);
    w.check_tokens().unwrap();
    assert!(try_retire(&mut w), "market retires");
}

/// F-9 candidate: on a stake-BOUND market the asset-0 insurance authority is the stake
/// pool's vault_auth PDA. The stake program has no CPI for the wrapper's terminal
/// WithdrawInsurance (tag 41) and its RecoverFlushedInsurance (tag 23 -> wrapper 57) is
/// Live-only (percolator-stake src/instruction.rs:440-453, src/cpi.rs:915-918). If the market
/// is resolved by a path that bypasses the stake H-1 gate — ResolveStalePermissionless, the
/// relaunch's F-3 escape — any insurance domain budget is stranded and CloseSlab is blocked.
/// Run alone: INDEP_MAINNET_ID=1 ... --ignored indep_f9
#[test]
#[ignore]
fn indep_f9_bound_market_insurance_budget_recoverable_after_stale_resolve() {
    assert!(std::env::var("INDEP_MAINNET_ID").as_deref() == Ok("1") || std::env::var("INDEP_PROGRAM_ID").is_ok(), "run with INDEP_MAINNET_ID=1 or INDEP_PROGRAM_ID");
    let mut w = World::new(0);
    w.do_configure_stale_resolve(9_000, 100).expect("stale policy");
    w.do_topup_insurance(5_000_000).expect("insurance top-up (e.g. staker flush / seed)");
    w.setup_stake(1_000 + 5_000_000);
    w.do_trade_nocpi(0, 1, 10 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    w.check().unwrap();
    // Keeper stops; anyone resolves.
    let s = w.slot() + 9_005;
    w.env.svm.warp_to_slot(s);
    let _ = w.do_crank(N_USERS);
    w.do_resolve_stale().expect("stale resolve");
    let (_paid, stuck) = w.permissionless_close_out().unwrap();
    assert!(stuck.is_empty(), "users closed out");
    for u in 0..w.ports.len() {
        let _ = w.do_close_portfolio(u);
    }
    let (_, g) = w.env.market_state();
    let budget = g.insurance_domain_budget_remaining_total;
    let r41 = w.do_withdraw_terminal_insurance(budget);
    eprintln!("F-9: mat {} budget {budget}; tag 41 by former admin -> {:?}", g.materialized_portfolio_count, r41.as_ref().map_err(|e| custom_code(e)));
    let ins_auth = state::read_asset_oracle_profile(&w.env.svm.get_account(&w.env.market).unwrap().data, 0).map(|p| Pubkey::new_from_array(p.insurance_authority));
    eprintln!("F-9: asset0 insurance_authority {:?} (stake vault_auth {:?})", ins_auth, w.stake.map(|s| s.1));
    // F-9 FIX: the keeper's wind-down step, stake tag 29 RecoverTerminalInsurance
    // (permissionless). Pays the budget into pool.vault via wrapper tag 41 and books it.
    let sv = w.stake.unwrap().2;
    let (fees0, sv0) = (w.pool_fields().unwrap().2, w.token_amount(&sv));
    let r29 = w.do_stake_recover_terminal(budget as u64, None);
    eprintln!("F-9: stake tag 29 RecoverTerminalInsurance({budget}) -> {:?}", r29.as_ref().map_err(|e| custom_code(e)));
    if r29.is_ok() {
        assert_eq!(w.token_amount(&sv) - sv0, budget, "pool vault receives exactly the released budget");
        assert_eq!(w.pool_fields().unwrap().2 - fees0, budget as u64, "stakers credited exactly the released budget");
    }
    let retired = try_retire(&mut w);
    let vault = if retired { 0 } else { w.token_amount(&w.env.vault) };
    eprintln!("F-9: retired {retired}; vault left {vault}");
    w.check_tokens().unwrap();
    assert!(retired && vault == 0, "F-9: {budget} atoms of insurance budget stranded on a stake-bound market after permissionless resolve; CloseSlab blocked");
}

/// Control for F-9: identical flow on an UNBOUND market (admin is the insurance authority).
#[test]
fn indep_f9_control_unbound_market_insurance_recoverable_after_stale_resolve() {
    let mut w = World::new(0);
    w.do_configure_stale_resolve(9_000, 100).expect("stale policy");
    w.do_topup_insurance(5_000_000).expect("insurance top-up");
    w.do_trade_nocpi(0, 1, 10 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    let s = w.slot() + 9_005;
    w.env.svm.warp_to_slot(s);
    let _ = w.do_crank(N_USERS);
    w.do_resolve_stale().expect("stale resolve");
    let (_paid, stuck) = w.permissionless_close_out().unwrap();
    assert!(stuck.is_empty());
    for u in 0..w.ports.len() {
        let _ = w.do_close_portfolio(u);
    }
    let (_, g) = w.env.market_state();
    let budget = g.insurance_domain_budget_remaining_total;
    let r41 = w.do_withdraw_terminal_insurance(budget);
    eprintln!("F-9 control: mat {} budget {budget}; tag 41 -> {:?}", g.materialized_portfolio_count, r41.as_ref().map_err(|e| custom_code(e)));
    let retired = try_retire(&mut w);
    eprintln!("F-9 control: retired {retired}");
    assert!(retired, "control: unbound market must retire after stale resolve");
}


// ═══════════════════════════════════════════════════════════════════════════
// F-3 CORRECTED (credit: Anvil's triage, f3-market-freeze-triage-2026-09-30.md,
// percolator-prog#519 @ dec380a0). While either side has A != ADL_ONE the engine is in
// the ADL reduce-only state (upstream 6ae709e0): trades may reduce matched risk but MUST
// NOT attach, flip or enlarge a leg. So a fresh open is correctly refused there. The
// liveness property is: every holder can exit on its OWN signature (RebalanceReduce, tag
// 44), after which zero-OI resets restore A = ADL_ONE and the market reopens.
// ═══════════════════════════════════════════════════════════════════════════

impl World {
    /// Signed position on asset 0 (0 if flat/closed).
    fn pos0(&self, u: usize) -> i128 {
        self.env.svm.get_account(&self.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok())
            .and_then(|p| p.legs.iter().find(|l| l.active && l.asset_index == 0).map(|l| l.basis_pos_q)).unwrap_or(0)
    }

    /// P3-g (P3 doc F-14 head, credit: P3 builder 31efd250): on a P3 (bound) asset, TradeNoCpi /
    /// BatchTradeNoCpi that GROW either side are refused (77) — the vault LP is the exclusive
    /// counterparty. A successful NoCpi may only reduce. Hard violation otherwise.
    fn p3g_check(&mut self, what: &str, r: &Result<u64, String>, parties: &[(usize, i128)]) {
        if !p3_mode() || self.p3.is_none() {
            return;
        }
        match r {
            Ok(_) => {
                for &(u, before) in parties {
                    let after = self.pos0(u);
                    // P3 doc row 6 / §113: "unwinding (|pos| not growing) is allowed". A flip that
                    // SHRINKS |pos| is allowed by that rule; record it (soft) but do not fail.
                    if after.unsigned_abs() > before.unsigned_abs() {
                        self.pending_violation = Some(format!("P3-g {what} GREW u{u} on a bound asset: {before} -> {after} (must be refused 77)"));
                    } else if before != 0 && after != 0 && before.signum() != after.signum() {
                        *self.stats.soft.entry("p3g_nocpi_flip_with_shrinking_abs_pos").or_default() += 1;
                    }
                }
            }
            Err(e) => {
                if custom_code(e) == Some(77) {
                    *self.stats.ok.entry("p3g_nocpi_growth_refused_77").or_default() += 1;
                }
            }
        }
    }

    fn do_rebalance_reduce(&mut self, u: usize, asset: u16, reduce_q: u128) -> Result<u64, String> {
        let owner = self.owners[u].insecure_clone();
        let p = self.ports[u];
        let (pid, _, pep) = self.env.portfolio_identity(p);
        let m = self.env.market;
        self.send(
            ProgInstruction::RebalanceReduce { portfolio_id: pid, position_epoch: pep, asset_index: asset, reduce_q },
            vec![AccountMeta::new(owner.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false)],
            &[&owner],
        )
    }

    fn in_adl_reduce_only(&self) -> bool {
        let (_, g) = self.env.market_state();
        g.assets.iter().take(self.nassets).any(|a| a.a_long != percolator::ADL_ONE || a.a_short != percolator::ADL_ONE)
    }

    /// Every holder exits with its own signature (tag 44) on every asset. Returns holders left.
    fn owner_exits(&mut self, rounds: usize) -> usize {
        for _ in 0..rounds {
            let holders: Vec<usize> = (0..self.ports.len()).filter(|&u| !self.closed[u] && !self.is_flat(u)).collect();
            if holders.is_empty() {
                return 0;
            }
            for u in holders {
                let s = self.slot() + 1;
                self.env.svm.warp_to_slot(s);
                let _ = self.do_push(self.mark);
                let _ = self.do_crank(u);
                for a in 0..self.nassets as u16 {
                    let _ = self.do_rebalance_reduce(u, a, u128::MAX / 4);
                }
            }
            let _ = self.permissionless_repair(3);
        }
        (0..self.ports.len()).filter(|&u| !self.closed[u] && !self.is_flat(u)).count()
    }
}

/// Spec rule (triage): in the ADL reduce-only state a fresh attach is refused (21), and every
/// holder can still exit unilaterally; afterwards the market reopens.
#[test]
fn indep_f3_adl_reduce_only_then_owner_exits_reopen_market() {
    let mut w = World::new(0);
    for op in [
        Op::TradeCpi { u: 48, size_tenths: 366 },
        Op::TradeNoCpi { a: 7, b: 90, size_tenths: -214, off_bps: -1908 },
        Op::Push { delta_bps: -2157 },
        Op::Push { delta_bps: -1266 },
    ] {
        let _ = w.apply(&op);
        w.check().unwrap();
    }
    let _ = w.permissionless_repair(400);
    assert!(w.in_adl_reduce_only(), "vacuity: scenario must reach the ADL reduce-only state");
    let a = w.add_user();
    let b = w.add_user();
    w.do_deposit(a, 5_000_000).unwrap();
    w.do_deposit(b, 5_000_000).unwrap();
    let _ = w.do_crank(a);
    let _ = w.do_crank(b);
    assert_eq!(w.do_trade_nocpi(a, b, POS_SCALE as i128, w.mark).map_err(|e| custom_code(&e)), Err(Some(21)), "spec: no fresh attach while A != ADL_ONE");
    let left = w.owner_exits(6);
    assert_eq!(left, 0, "every holder must exit on its own signature (tag 44)");
    assert!(!w.in_adl_reduce_only(), "zero-OI reset must restore A = ADL_ONE");
    w.check().unwrap();
    w.probe_recovered().expect("market reopens after owner exits");
    w.check().unwrap();
}

/// Exit-aware liveness fuzz: after any sequence + permissionless repairs, every holder
/// exits via tag 44 and then the fresh-pair / withdraw probe must pass.
#[test]
fn indep_liveness_fuzz_owner_exits_then_reopen() {
    let seqs = env_u64("FUZZ_LIVE_SEQS", 48);
    let len = env_u64("FUZZ_LEN", 40) as usize;
    let seed0 = env_u64("FUZZ_SEED", 0x11fe);
    let threads = env_u64("FUZZ_THREADS", 4).max(1);
    let fails = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let adl = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut hs = Vec::new();
    for t in 0..threads {
        let (fails, adl) = (fails.clone(), adl.clone());
        hs.push(std::thread::Builder::new().stack_size(64 << 20).spawn(move || {
            let mut i = t;
            while i < seqs {
                let seed = seed0.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let mut rng = XorShiftRng::seed_from_u64(seed);
                let fee_bps = [0u64, 5, 30][rng.gen_range(0..3)];
                let ops: Vec<Op> = (0..len).map(|_| gen_op(&mut rng)).collect();
                let mut w = World::new(fee_bps);
                for op in &ops {
                    let _ = w.apply(op);
                    if let Err(e) = w.check() {
                        fails.lock().unwrap().push(format!("seed={seed:#x}: invariant during ops: {e}"));
                        break;
                    }
                }
                let _ = w.permissionless_repair(400);
                if w.in_adl_reduce_only() {
                    adl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let left = w.owner_exits(6);
                let r = if left != 0 { Err(format!("{left} holder(s) could not exit via tag 44")) } else { w.probe_recovered() };
                if let Err(e) = r {
                    let (_, g) = w.env.market_state();
                    fails.lock().unwrap().push(format!("seed={seed:#x} fee={fee_bps}: L3 {e} | a {}/{} oi {}/{} sides {:?}/{:?}",
                        g.assets[0].a_long, g.assets[0].a_short, g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q, g.assets[0].mode_long, g.assets[0].mode_short));
                }
                if let Err(e) = w.check() {
                    fails.lock().unwrap().push(format!("seed={seed:#x}: invariant after exits: {e}"));
                }
                i += threads;
            }
        }).unwrap());
    }
    for h in hs {
        h.join().expect("thread");
    }
    eprintln!("== exit-aware liveness fuzz: {seqs} seqs; {} reached the ADL reduce-only state", adl.load(std::sync::atomic::Ordering::Relaxed));
    let f = fails.lock().unwrap();
    assert!(f.is_empty(), "{} unrecoverable sequence(s):\n{}", f.len(), f.join("\n"));
}

/// Multi-asset resolved close-out (shrunk from FUZZ_ASSETS=2 seed 0x38454127b0966d17 on
/// v18.2 and P1 3d337101): after Resolve + every permissionless close path, a user with
/// capital ~19.9M and positive PnL ~10.3M, no legs and no receipt, is never paid.
/// Run: FUZZ_ASSETS=2 ... --ignored indep_multi_asset_resolved
#[test]
#[ignore]
fn indep_multi_asset_resolved_closeout_pays_every_user() {
    assert_eq!(std::env::var("FUZZ_ASSETS").as_deref(), Ok("2"));
    let ops = [
        Op::PushA1 { delta_bps: 1350 },
        Op::TradeNoCpiA1 { a: 9, b: 65, size_tenths: -212 },
        Op::Push { delta_bps: -1372 },
        Op::Push { delta_bps: -778 },
        Op::Warp { n: 17 },
        Op::Push { delta_bps: 2424 },
        Op::TradeNoCpi { a: 25, b: 252, size_tenths: -116, off_bps: -1477 },
        Op::Crank { u: 222 },
        Op::TradeCpi { u: 120, size_tenths: 243 },
        Op::Push { delta_bps: 1120 },
    ];
    let mut w = World::new(30);
    for op in &ops {
        let r = w.apply(op);
        eprintln!("op {op:?} -> {:?}", r.map_err(|e| custom_code(&e)));
        w.check().unwrap();
    }
    // catch up both assets, then resolve
    for _ in 0..60 {
        let s = w.slot() + 5;
        w.env.svm.warp_to_slot(s);
        let _ = w.do_push(w.mark);
        let _ = w.do_push_asset1(w.mark1);
        let _ = w.do_crank(N_USERS);
    }
    w.do_resolve().expect("resolve");
    for round in 0..8 {
        for u in 0..w.ports.len() {
            let r = w.do_close_resolved(u);
            let t = w.do_claim_topup(u);
            if round == 7 {
                let p = w.env.portfolio_state(w.ports[u]);
                eprintln!("u{u}: close_resolved {:?} topup {:?} cap {} pnl {} legs {} receipt {:?}", r.map_err(|e| custom_code(&e)), t.map_err(|e| custom_code(&e)), p.capital, p.pnl, p.legs.iter().filter(|l| l.active).count(), (p.resolved_payout_receipt.present, p.resolved_payout_receipt.finalized));
            }
            w.check().unwrap();
        }
        let s = w.slot() + 20;
        w.env.svm.warp_to_slot(s);
    }
    let (_, g) = w.env.market_state();
    assert_eq!(g.c_tot, 0, "every user's capital must be paid after resolution (c_tot {})", g.c_tot);
}

/// Sieve review of the F-9 fix (stake f9b9190): F-9 x F-3 interplay. If the pool has ONLY the
/// 1,000 dead shares when the market resolves, tag 29 must not book the recovered terminal
/// insurance to dead shares (that would make it permanently unredeemable, the F3 class), and
/// the market must still retire (the budget must leave the wrapper vault).
#[test]
#[ignore]
fn indep_f9_recovery_into_dead_shares_only_pool_is_not_booked_to_dead_shares() {
    assert!(std::env::var("INDEP_MAINNET_ID").as_deref() == Ok("1") || std::env::var("INDEP_PROGRAM_ID").is_ok(), "run with INDEP_MAINNET_ID=1 or INDEP_PROGRAM_ID");
    let (mut w, budget) = f9_bound_resolved_world_lp(1_000);
    let sv = w.stake.unwrap().2;
    let fees0 = w.pool_fields().unwrap().2;
    let r = w.do_stake_recover_terminal(budget as u64, None);
    let booked = w.pool_fields().unwrap().2 - fees0;
    eprintln!("F-9 dead-shares: tag29 -> {:?}; booked {booked}; pool vault {}", r.as_ref().map_err(|e| custom_code(e)), w.token_amount(&sv));
    assert_eq!(booked, 0, "terminal insurance booked to the 1,000 dead shares (unredeemable)");
    let retired = try_retire(&mut w);
    eprintln!("F-9 dead-shares: retired {retired}; wrapper vault {}", if retired { 0 } else { w.token_amount(&w.env.vault) });
    w.check_tokens().unwrap();
    assert!(retired, "the terminal budget must leave the wrapper vault and the market retire");
}

// ═══════════════════════════════════════════════════════════════════════════
// P3 MODE (FUZZ_P3=1): relaunch configuration — a vault-owned LP on every market.
// Written from ledger/p3-vault-owned-lp-2026-09-29.md §0.3 (tags 94-102, errors 72-85)
// and §2.2 waterfall: senior = min(V, C_eff), junior = V − senior (junior first loss).
// Setup follows the design bind order: 74 → 75 (genesis senior) → 94 (path B: protocol +
// named signing junior owner = the "creator") → 99 → 95 → 96 junior.
// ═══════════════════════════════════════════════════════════════════════════

/// P3_LEGACY_BIND=1: pre-07a1d0eb flow (94 without the auto-pin tail, then 99 + 95).
pub fn p3_legacy_bind() -> bool {
    std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1")
}

/// CANONICAL_VAULT_LP_MATCHER_PROGRAM (devnet) at 07a1d0eb — the live matcher id.
pub fn p3_canonical_matcher() -> Pubkey {
    "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT".parse().unwrap()
}

pub fn p3_mode() -> bool {
    std::env::var("FUZZ_P3").map_or(false, |v| v == "1")
}

pub struct P3Ctx {
    pub lp: Pubkey,
    pub state_pda: Pubkey,
    pub junior: Keypair,
    pub upgrade: Keypair,
    pub program_data: Pubkey,
    pub ctx: Pubkey,
    pub delegate: Pubkey,
    pub senior_in: u128,
    pub senior_out: u128,
    pub n_redeem: u64,
    pub c_last: u128,
    pub c_may_drop: bool,
    pub fees_credited0: u128,
}

fn p3_raw(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(body);
    v
}

impl World {
    fn p3_send_raw(&mut self, data: Vec<u8>, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let ix = solana_sdk::instruction::Instruction { program_id: self.env.program_id, accounts: metas, data };
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, signers)
    }

    fn p3_state(&self) -> Vec<u8> {
        self.p3.as_ref().and_then(|c| self.env.svm.get_account(&c.state_pda)).map(|a| a.data).unwrap_or_default()
    }

    fn p3_c(&self) -> u128 {
        let d = self.p3_state();
        if d.len() < 160 { 0 } else { u128::from_le_bytes(d[144..160].try_into().unwrap()) }
    }

    fn p3_fees_credited(&self) -> u128 {
        let d = self.p3_state();
        if d.len() < 208 { 0 } else { u128::from_le_bytes(d[192..208].try_into().unwrap()) }
    }

    fn p3_bind(&mut self) {
        let (reg, _, _) = self.lp_vault.expect("74 CreateLpVault first");
        let pid = self.env.program_id;
        let m = self.env.market;
        let state_pda = Pubkey::find_program_address(&[b"vault_lp", m.as_ref()], &pid).0;
        let upgrade = Keypair::new();
        let junior = Keypair::new();
        self.env.svm.airdrop(&upgrade.pubkey(), 10_000_000_000).unwrap();
        self.env.svm.airdrop(&junior.pubkey(), 10_000_000_000).unwrap();
        let program_data = Pubkey::find_program_address(&[pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(upgrade.pubkey().as_ref());
        self.env.svm.set_account(program_data, Account { lamports: 1_000_000_000, data: pd, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 }).unwrap();
        // 75 genesis senior deposit (unbound) by Earn wallet = user 1.
        self.do_lp_deposit(1, 10_000_000).expect("75 genesis senior deposit");
        let genesis = 10_000_000u128;
        // 94 path B.
        let lp = Pubkey::new_unique();
        let len = self.env.portfolio_account_len;
        self.env.svm.set_account(lp, Account { lamports: 1_000_000_000, data: vec![0; len], owner: pid, executable: false, rent_epoch: 0 }).unwrap();
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        let metas = vec![
            AccountMeta::new(upgrade.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new(reg, false),
            AccountMeta::new(state_pda, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(l0, false),
            AccountMeta::new(l1, false),
            AccountMeta::new_readonly(program_data, false),
            AccountMeta::new_readonly(junior.pubkey(), true),
        ];
        // 07a1d0eb auto-pin tail: [8] canonical matcher, [9] ctx (w, zeroed, matcher-owned),
        // [10] delegate ["matcher", market, lp, registry, matcher, ctx].
        let pin_ctx = Pubkey::new_unique();
        self.env.svm.set_account(pin_ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher_prog, executable: false, rent_epoch: 0 }).unwrap();
        let pin_del = Pubkey::find_program_address(&[b"matcher", m.as_ref(), lp.as_ref(), reg.as_ref(), self.matcher_prog.as_ref(), pin_ctx.as_ref()], &pid).0;
        self.env.svm.set_account(pin_del, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
        let pin_tail = vec![
            AccountMeta::new_readonly(self.matcher_prog, false),
            AccountMeta::new(pin_ctx, false),
            AccountMeta::new_readonly(pin_del, false),
        ];
        let up = upgrade.insecure_clone();
        // Path B was REMOVED (user decision 2026-09-30). Default: path A — marketauth binds and
        // becomes the junior owner (the creator). FUZZ_P3_PATH_B=1 keeps the old path for ee29b5ac.
        let junior = if std::env::var("FUZZ_P3_PATH_B").map_or(false, |v| v == "1") {
            let jr = junior.insecure_clone();
            self.p3_send_raw(p3_raw(94, &1_000u16.to_le_bytes()), metas, &[&up, &jr]).unwrap_or_else(|e| panic!("94 InitVaultLp path B: {}", &e[..e.len().min(500)]));
            junior
        } else {
            let admin = self.env.admin.insecure_clone();
            let mut ma = metas[..8].to_vec();
            ma[0] = AccountMeta::new(admin.pubkey(), true);
            if !p3_legacy_bind() {
                ma.extend(pin_tail.clone());
            }
            self.p3_send_raw(p3_raw(94, &1_000u16.to_le_bytes()), ma, &[&admin]).unwrap_or_else(|e| panic!("94 InitVaultLp path A: {}", &e[..e.len().min(500)]));
            admin
        };
        // 99 SetVaultLpRisk: skew on (slope/max 1_000 e9), lev step-down off, 1x cap, approve matcher.
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&1_000u64.to_le_bytes());
        b.extend_from_slice(&1_000u64.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(self.matcher_prog.as_ref());
        let metas = vec![AccountMeta::new(up.pubkey(), true), AccountMeta::new_readonly(program_data, false), AccountMeta::new(m, false)];
        self.p3_send_raw(p3_raw(99, &b), metas, &[&up]).unwrap_or_else(|e| panic!("99 SetVaultLpRisk: {}", &e[..e.len().min(400)]));
        // 95 VaultLpSetMatcher (passive kind 0, finite caps) — LEGACY flow only; 07a1d0eb
        // auto-pins the canonical vAMM at 94 and the market trades right away.
        let (ctx, delegate) = if !p3_legacy_bind() { (pin_ctx, pin_del) } else {
        let ctx = Pubkey::new_unique();
        self.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher_prog, executable: false, rent_epoch: 0 }).unwrap();
        let delegate = Pubkey::find_program_address(&[b"matcher", m.as_ref(), lp.as_ref(), reg.as_ref(), self.matcher_prog.as_ref(), ctx.as_ref()], &pid).0;
        self.env.svm.set_account(delegate, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
        let (_, seq, _) = self.env.portfolio_identity(lp);
        let fr = state::read_market_asset_generation_frontier(&self.env.svm.get_account(&m).unwrap().data).unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&fr.to_le_bytes());
        b.extend_from_slice(&10_000u16.to_le_bytes());
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&(1_000 * POS_SCALE).to_le_bytes());
        b.extend_from_slice(&(1_000 * POS_SCALE).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        let mp = self.matcher_prog;
        let metas = vec![
            AccountMeta::new(up.pubkey(), true),
            AccountMeta::new_readonly(program_data, false),
            AccountMeta::new_readonly(m, false),
            AccountMeta::new_readonly(state_pda, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(mp, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        self.p3_send_raw(p3_raw(95, &b), metas, &[&up]).unwrap_or_else(|e| panic!("95 VaultLpSetMatcher: {}", &e[..e.len().min(400)]));
        (ctx, delegate) };
        self.p3 = Some(P3Ctx {
            lp, state_pda, junior, upgrade, program_data, ctx, delegate,
            senior_in: genesis, senior_out: 0, n_redeem: 0, c_last: 0, c_may_drop: false, fees_credited0: 0,
        });
        // 96 junior deposit (creator first loss).
        self.p3_junior_deposit(3_000_000).unwrap_or_else(|e| panic!("96 junior deposit: {}", &e[..e.len().min(400)]));
        let c0 = self.p3_c();
        let f0 = self.p3_fees_credited();
        let c = self.p3.as_mut().unwrap();
        c.c_last = c0;
        c.fees_credited0 = f0;
    }

    /// K1 + L2 prep: permissionless crank of the vault LP, then bound tag 78.
    fn p3_prep(&mut self) {
        let lp = self.p3.as_ref().unwrap().lp;
        let _ = self.p3_crank_port(lp);
        let _ = self.do_lp_crank(0);
    }

    fn p3_crank_port(&mut self, p: Pubkey) -> Result<u64, String> {
        let slot = self.slot();
        let payer = self.env.payer.pubkey();
        let m = self.env.market;
        self.send(
            ProgInstruction::PermissionlessCrank { now_slot: slot, observations: (0..self.nassets as u16).map(|a| CrankObservationHint { asset_index: a, oracle_accounts: 0 }).collect() },
            vec![AccountMeta::new(payer, true), AccountMeta::new(m, false), AccountMeta::new(p, false)],
            &[],
        )
    }

    fn p3_trade_vs_vault_lp(&mut self, u: usize, size_q: i128) -> Result<u64, String> {
        let (lp, mp, ctx, del) = { let c = self.p3.as_ref().unwrap(); (c.lp, self.matcher_prog, c.ctx, c.delegate) };
        let taker = self.owners[u].insecure_clone();
        let pa = self.ports[u];
        let (aid, _, aep) = self.env.portfolio_identity(pa);
        let (bid, bseq, bep) = self.env.portfolio_identity(lp);
        let m = self.env.market;
        let _ = self.p3_crank_port(lp);
        self.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid, account_a_position_epoch: aep,
                account_b_portfolio_id: bid, account_b_position_epoch: bep,
                market_id: 1, account_b_matcher_sequence: bseq, asset_index: 0, size_q,
                fee_bps: self.fee_bps, limit_price: 0, backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(pa, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(del, false),
            ],
            &[&taker],
        )
    }

    fn p3_junior_deposit(&mut self, amt: u64) -> Result<u64, String> {
        let Some(c) = self.p3.as_ref() else { return Err("not p3".into()) };
        let (jr, st, lp) = (c.junior.insecure_clone(), c.state_pda, c.lp);
        let src = self.new_token(jr.pubkey(), amt);
        let (m, v) = (self.env.market, self.env.vault);
        let metas = vec![
            AccountMeta::new(jr.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new(st, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(src, false),
            AccountMeta::new(v, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        self.p3_send_raw(p3_raw(96, &(amt as u128).to_le_bytes()), metas, &[&jr])
    }

    fn p3_junior_withdraw(&mut self, frac_bps: u16) -> Result<u64, String> {
        let Some(c) = self.p3.as_ref() else { return Err("not p3".into()) };
        let (jr, st, lp) = (c.junior.insecure_clone(), c.state_pda, c.lp);
        let (reg, _, _) = self.lp_vault.unwrap();
        let _ = self.p3_crank_port(lp);
        let cap = self.env.portfolio_state(lp).capital;
        let amt = (cap * frac_bps as u128 / 10_000).max(1);
        let dest = self.new_token(jr.pubkey(), 0);
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        let metas = vec![
            AccountMeta::new(jr.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new_readonly(reg, false),
            AccountMeta::new(st, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(l0, false),
            AccountMeta::new(l1, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(v, false),
            AccountMeta::new_readonly(va, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        self.p3_send_raw(p3_raw(97, &amt.to_le_bytes()), metas, &[&jr])
    }

    fn p3_recall(&mut self, amt: u128) -> Result<u64, String> {
        let Some(c) = self.p3.as_ref() else { return Err("not p3".into()) };
        let (st, lp) = (c.state_pda, c.lp);
        let (reg, _, _) = self.lp_vault.unwrap();
        let cranker = Keypair::new();
        self.env.ensure_signer_account(cranker.pubkey());
        let m = self.env.market;
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        let metas = vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new_readonly(reg, false),
            AccountMeta::new(st, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(l0, false),
            AccountMeta::new(l1, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        let mut b = amt.to_le_bytes().to_vec();
        b.extend_from_slice(&0u16.to_le_bytes());
        self.p3_send_raw(p3_raw(98, &b), metas, &[&cranker])
    }

    /// 102 VaultLpReleaseSurplus (junior owner). `resolved` adds the SPL payout tail.
    fn p3_release(&mut self, amt: u128, resolved: bool) -> Result<u64, String> {
        // FUZZ_LP_DOMAINS=2: the junior surplus can sit in either pot; try pot 0, then pot 1.
        let r = self.p3_release_domain(amt, resolved, 0);
        if r.is_err() && std::env::var("FUZZ_LP_DOMAINS").map_or(false, |v| v == "2") {
            let r1 = self.p3_release_domain(amt, resolved, 1);
            if r1.is_ok() { return r1; }
        }
        r
    }

    fn p3_release_domain(&mut self, amt: u128, resolved: bool, domain: u16) -> Result<u64, String> {
        let Some(c) = self.p3.as_ref() else { return Err("not p3".into()) };
        let (jr, st, lp) = (c.junior.insecure_clone(), c.state_pda, c.lp);
        let (reg, _, _) = self.lp_vault.unwrap();
        let m = self.env.market;
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        let mut metas = vec![
            AccountMeta::new(jr.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new_readonly(reg, false),
            AccountMeta::new(st, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(l0, false),
            AccountMeta::new(l1, false),
        ];
        if resolved {
            let dest = self.new_token(jr.pubkey(), 0);
            let (v, va) = (self.env.vault, self.env.vault_authority);
            metas.extend([
                AccountMeta::new(dest, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ]);
        }
        let mut b = amt.to_le_bytes().to_vec();
        b.extend_from_slice(&domain.to_le_bytes());
        self.p3_send_raw(p3_raw(102, &b), metas, &[&jr])
    }

    fn p3_settle(&mut self, topup: u8) -> Result<u64, String> {
        let (jr, st, lp) = { let c = self.p3.as_ref().unwrap(); (c.junior.pubkey(), c.state_pda, c.lp) };
        let (reg, _, _) = self.lp_vault.unwrap();
        let dest = self.new_token(jr, 0);
        let (m, v, va, payer) = (self.env.market, self.env.vault, self.env.vault_authority, self.env.payer.pubkey());
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        let metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(m, false),
            AccountMeta::new_readonly(reg, false),
            AccountMeta::new(st, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(l0, false),
            AccountMeta::new_readonly(l1, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(v, false),
            AccountMeta::new_readonly(va, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        self.p3_send_raw(p3_raw(101, &[topup]), metas, &[])
    }

    fn holdings_of(&self, owner: &Pubkey) -> u128 {
        self.tokens
            .iter()
            .filter_map(|k| self.env.svm.get_account(k))
            .filter_map(|a| TokenAccount::unpack(&a.data).ok())
            .filter(|t| t.owner == *owner && t.mint == self.env.mint)
            .map(|t| t.amount as u128)
            .sum()
    }

    fn net_of(&self, owner: &Pubkey) -> i128 {
        self.holdings_of(owner) as i128 - *self.minted_by.get(owner).unwrap_or(&0) as i128
    }

    /// Resolved wind-down for the vault LP: settle (101), let winning traders finish their
    /// resolved close, release junior surplus (102 resolved), free the vault LP permissionlessly.
    fn p3_terminal_settle(&mut self) -> Result<(), String> {
        let lp = self.p3.as_ref().unwrap().lp;
        for topup in [0u8, 0, 1, 1] {
            match self.p3_settle(topup) {
                Ok(_) => *self.stats.ok.entry("p3_settle101").or_default() += 1,
                Err(e) => *self.stats.err.entry(format!("p3_settle101:{:?}", custom_code(&e))).or_default() += 1,
            }
            self.check()?;
        }
        for round in 0..8 {
            for u in 0..=N_USERS {
                if self.closed[u] {
                    continue;
                }
                let _ = self.do_close_resolved(u);
                let _ = self.do_claim_topup(u);
                self.check()?;
            }
            // Engine sequencing (P3 doc final pass): the vault-LP settle can be progress-only
            // until counterparties have closed, and vice versa — retry 101 every round.
            for topup in [0u8, 1] {
                if self.p3_settle(topup).is_ok() {
                    *self.stats.ok.entry("p3_settle101_retry").or_default() += 1;
                }
                self.check()?;
            }
            let s = self.slot() + 10 * (round + 1);
            self.env.svm.warp_to_slot(s);
        }
        // Junior surplus (Resolved, terminal-flat only) — try decreasing amounts.
        let mut amt = self.token_amount(&self.env.vault);
        while amt > 0 {
            if self.p3_release(amt, true).is_ok() {
                *self.stats.ok.entry("p3_release102_resolved").or_default() += 1;
                break;
            }
            amt /= 4;
        }
        self.check()?;
        // Permissionless resolved cleanup of the vault LP (F-4 fix: account [3] = owner).
        let (reg, _, _) = self.lp_vault.unwrap();
        let (pid, seq, ep) = self.env.portfolio_identity(lp);
        let m = self.env.market;
        let payer = self.env.payer.insecure_clone();
        let r = self.send(
            ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: ep },
            vec![AccountMeta::new(payer.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(lp, false), AccountMeta::new(reg, false)],
            &[],
        );
        *self.stats.ok.entry(if r.is_ok() { "p3_vault_lp_closed" } else { "p3_vault_lp_close_refused" }).or_default() += 1;
        self.check()
    }

    /// P3-b / P3-d / P3-e terminal checks (after seniors redeemed, junior released).
    fn p3_terminal_checks(&mut self) -> Result<(), String> {
        // Resolved Earn redemption needs a terminal-flat market (#377): free every EMPTY
        // portfolio permissionlessly first (F-4 fix: account [3] = owner).
        for u in 0..=N_USERS {
            if let Some(pf) = self.env.svm.get_account(&self.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()) {
                let (pid, seq, ep) = self.env.portfolio_identity(self.ports[u]);
                let (m, p, owner) = (self.env.market, self.ports[u], Pubkey::new_from_array(pf.owner));
                let payer = self.env.payer.pubkey();
                if self.send(
                    ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: ep },
                    vec![AccountMeta::new(payer, true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(owner, false)],
                    &[],
                ).is_ok() {
                    self.closed[u] = true;
                    *self.stats.ok.entry("p3_permissionless_close").or_default() += 1;
                }
                self.check()?;
            }
        }
        // seniors: execute any pending redemption, then redeem everything
        // (bound, Resolved: senior value = min(physical, C)).
        let holders: Vec<usize> = self.lp_atas.keys().copied().collect();
        for _ in 0..2 {
            for &u in &holders {
                self.p3_prep();
                let a = self.do_lp_execute(u);
                self.check()?;
                let b = self.do_lp_redeem(u, 10_000);
                if std::env::var("FUZZ_DEBUG_P3").is_ok() {
                    let (_, g) = self.env.market_state();
                    eprintln!("  P3EXIT u{u}: execute {:?} redeem {:?} | C {} backing {:?} sc {:?}", a.as_ref().map_err(|e| custom_code(e)), b.as_ref().map_err(|e| custom_code(e)), self.p3_c(), g.source_backing_buckets.iter().map(|x| (x.status, x.fresh_unliened_backing_num / BOUND_SCALE)).collect::<Vec<_>>(), g.source_credit.iter().map(|c| (c.spent_backing_num / BOUND_SCALE, c.provider_receivable_num / BOUND_SCALE)).collect::<Vec<_>>());
                }
                self.check()?;
            }
        }
        // Junior terminal exit (P3 doc row 102 / §128, F-14 head; credit: P3 builder patch
        // indep-fuzz-anvil-f14): the junior owner calls Resolved tag 102 for `physical − C` AFTER
        // the seniors. A real user step. Largest accepted amount first, then halving. P3-a/P3-b still
        // check that it can never take senior value.
        {
            let mut amt = self.token_amount(&self.env.vault);
            while amt > 0 {
                if self.p3_release(amt, true).is_ok() {
                    *self.stats.ok.entry("p3_release102_resolved_after_seniors").or_default() += 1;
                    self.check()?;
                    amt = self.token_amount(&self.env.vault);
                    continue;
                }
                amt /= 2;
            }
        }
        // P3-f: after Resolve every senior must be able to exit (H1). Registry shares left
        // beyond the 1,000 dead floor (+ escrowed pending) = seniors locked.
        if let Some((reg, _, _)) = self.lp_vault {
            if let Some(r) = self.env.svm.get_account(&reg).and_then(|a| state::read_lp_vault_registry(&a.data).ok()) {
                let floor = percolator_prog::constants::LP_VAULT_MINIMUM_LIQUIDITY as u128;
                if r.total_lp_shares_outstanding > floor {
                    let (cfg, _) = self.env.market_state();
                    let h = cfg.lp_fee_accrued_atoms.saturating_sub(cfg.lp_fee_withdrawn_atoms);
                    let mut why = String::new();
                    let hs: Vec<usize> = self.lp_atas.keys().copied().collect();
                    for u in hs {
                        if let Err(e) = self.do_lp_execute(u) { why = format!("{:?}", custom_code(&e)); }
                    }
                    let tag = if h > 0 && why.contains("84") { "P3-f(F-12) SENIORS LOCKED BY HARVEST GATE" } else if why.contains("25") { "P3-f(F-14) SENIOR REDEMPTION UNDERFLOW" } else { "P3-f SENIORS LOCKED" };
                    let g = self.env.market_state().1;
                    let alive_ix: Vec<usize> = (0..=N_USERS).filter(|&u| self.port_alive(u)).collect();
                    let mut closes = Vec::new();
                    for &u in &alive_ix {
                        let mut n = 0; let mut last = None;
                        while self.port_alive(u) && n < 2_000 { let r = self.do_close_resolved(u); last = Some(r.as_ref().map(|_| ()).map_err(|e| custom_code(e))); n += 1; let _ = self.do_close_portfolio(u); }
                        let x = if self.port_alive(u) { let st = self.env.portfolio_state(self.ports[u]); format!("still alive cap {} pnl {} receipt fin {}", st.capital, st.pnl, st.resolved_payout_receipt.finalized) } else { "closed".into() };
                        closes.push(format!("u{u} 30 x{n} last {:?}: {x}", last));
                    }
                    let _ = &closes;
                    if std::env::var("FUZZ_DEBUG_P3").is_ok() { eprintln!("  P3F closes {:?}", closes); }
                    let alive: Vec<String> = (0..=N_USERS).filter(|&u| self.port_alive(u)).map(|u| { let x = self.env.portfolio_state(self.ports[u]); format!("u{u}(cap {} pnl {} legs {} close {})", x.capital, x.pnl, x.legs.iter().filter(|l| l.active).count(), x.close_progress.active) }).collect();
                    let vlp = self.p3.as_ref().map(|c| c.lp).and_then(|k| self.env.svm.get_account(&k).filter(|a| a.lamports > 0).map(|_| { let x = self.env.portfolio_state(k); format!("vaultLP(cap {} pnl {} legs {} close {})", x.capital, x.pnl, x.legs.iter().filter(|l| l.active).count(), x.close_progress.active) })).unwrap_or_else(|| "vaultLP GONE".into());
                    return Err(format!("{tag}: {} senior shares outstanding after Resolve; LP fee leg harvestable {h}; last execute error {why}; C {}; materialized {} c_tot {} neg {} blockers {} snapshot {}; alive {:?} {vlp}", r.total_lp_shares_outstanding - floor, self.p3_c(), g.materialized_portfolio_count, g.c_tot, g.negative_pnl_account_count, g.resolved_payout_blocker_count, g.payout_snapshot_captured, alive));
                }
            }
        }
        let c = self.p3.as_ref().unwrap();
        let (jr, sin, sout, nred, f0) = (c.junior.pubkey(), c.senior_in, c.senior_out, c.n_redeem, c.fees_credited0);
        let credited = self.p3_fees_credited().saturating_sub(f0);
        let c_rem = self.p3_c();
        // Rounding: floor per redemption plus the resolved split; losses below 1,000 atoms are
        // recorded soft (not a waterfall violation).
        let tol = (nred as i128 + 2).max(1_000);
        // P3-b: seniors never extract more than deposits + fee credit.
        if sout > sin + credited + tol as u128 {
            return Err(format!("P3-b SENIOR OVER-EXTRACTION: paid {sout} > deposits {sin} + credited {credited}"));
        }
        let senior_loss = sin as i128 + credited as i128 - sout as i128 - c_rem as i128;
        let junior_received = self.holdings_of(&jr);
        let creator_net = self.net_of(&jr) + self.net_of(&self.owners[0].pubkey());
        if senior_loss > tol {
            *self.stats.soft.entry("p3_senior_loss_events").or_default() += 1;
            if junior_received > 0 {
                return Err(format!("P3-a JUNIOR PAID BEFORE SENIORS WHOLE: senior loss {senior_loss}, junior received {junior_received}"));
            }
            if creator_net > 0 {
                return Err(format!("P3-e CREATOR FREE OPTION: seniors lost {senior_loss} while creator (junior + trader wallet) netted +{creator_net}"));
            }
        }
        // P3-d: after every exit, nothing stranded beyond insurance + remaining senior claim.
        if !self.is_tombstone() {
            let (_, g) = self.env.market_state();
            let v = self.token_amount(&self.env.vault);
            let stranded = v as i128 - g.insurance as i128 - c_rem as i128 - g.c_tot as i128;
            let dust: i128 = std::env::var("FUZZ_P3_DUST").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000);
            if stranded > dust {
                if std::env::var("FUZZ_DEBUG_P3").is_ok() {
                    for u in 0..self.ports.len() {
                        if let Some(pf) = self.env.svm.get_account(&self.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()) {
                            eprintln!("  P3DBG u{u} closed {} cap {} pnl {} legs {} receipt {:?} tokens_net {}", self.closed[u], pf.capital, pf.pnl, pf.legs.iter().filter(|l| l.active).count(), (pf.resolved_payout_receipt.present, pf.resolved_payout_receipt.finalized, pf.resolved_payout_receipt.terminal_positive_claim_face, pf.resolved_payout_receipt.paid_effective), self.net_of(&self.owners[u].pubkey()));
                        } else {
                            eprintln!("  P3DBG u{u} (freed) tokens_net {}", self.net_of(&self.owners[u].pubkey()));
                        }
                    }
                    eprintln!("  P3DBG buckets {:?} sc {:?} budget {} ins {} spent {:?} earn {}", g.source_backing_buckets.iter().map(|b| (b.status, b.fresh_unliened_backing_num / BOUND_SCALE, b.valid_liened_backing_num / BOUND_SCALE)).collect::<Vec<_>>(), g.source_credit.iter().map(|c| (c.fresh_reserved_backing_num / BOUND_SCALE, c.spent_backing_num / BOUND_SCALE, c.provider_receivable_num / BOUND_SCALE, c.positive_claim_bound_num / BOUND_SCALE)).collect::<Vec<_>>(), g.insurance_domain_budget_remaining_total, g.insurance, g.insurance_domain_spent, g.backing_provider_earnings_total);
                    let st = self.p3_state();
                    let rd = |o: usize| u128::from_le_bytes(st[o..o + 16].try_into().unwrap());
                    eprintln!("  P3DBG state C {} jdep {} jwd {} fees {} recalled {}", rd(144), rd(160), rd(176), rd(192), rd(208));
                }
                let lpd = self.env.svm.get_account(&self.p3.as_ref().unwrap().lp).and_then(|a| state::read_portfolio(&a.data).ok())
                    .map(|lp| format!("cap {} pnl {} legs {}", lp.capital, lp.pnl, lp.legs.iter().filter(|l| l.active).count()))
                    .unwrap_or_else(|| "closed".into());
                let fresh = g.source_fresh_backing_total_num / BOUND_SCALE;
                return Err(format!(
                    "P3-d STRANDED: vault {v} − insurance {} − C_rem {c_rem} − c_tot {} = {stranded} (vault LP {lpd}; fresh backing {fresh}; senior in/out {}/{} junior held {})",
                    g.insurance, g.c_tot, sin, sout, junior_received
                ));
            }
        }
        *self.stats.soft.entry("p3_terminal_checked").or_default() += 1;
        Ok(())
    }
}

/// P3 fuzz shrink (seed 0xb54cda58fbbf476b, P3 424fe7e4): no trade ever touches the vault LP,
/// yet after resolve + settle (101) + every exit, junior value is missing and the same atoms
/// sit in the wrapper vault outside C, insurance and c_tot. Run: FUZZ_P3=1 --ignored.
#[test]
#[ignore]
fn indep_p3_no_stranded_value_after_unrelated_bankruptcy() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(30);
    for op in [
        Op::Push { delta_bps: -1350 },
        Op::BatchNoCpi { a: 255, b: 122, s0: -131, s1: 95 },
        Op::Warp { n: 6 },
        Op::Crank { u: 35 },
        Op::Push { delta_bps: 2471 },
    ] {
        let r = w.apply(&op);
        eprintln!("op {op:?} -> {:?}", r.map_err(|e| custom_code(&e)));
        w.check().unwrap();
    }
    let (_, g) = w.env.market_state();
    eprintln!("pre-resolve: sc {:?}", g.source_credit.iter().map(|c| (c.fresh_reserved_backing_num / BOUND_SCALE, c.spent_backing_num / BOUND_SCALE, c.provider_receivable_num / BOUND_SCALE)).collect::<Vec<_>>());
    let r = w.wind_down();
    let jr = w.p3.as_ref().unwrap().junior.pubkey();
    eprintln!("wind_down -> {r:?}; junior net {}", w.net_of(&jr));
    if !w.is_tombstone() {
        // every junior-surplus / recall path once more, with codes
        for amt in [1u128, 1_000, 100_000, 1_000_000] {
            eprintln!("  resolved 102({amt}) -> {:?}", w.p3_release(amt, true).map_err(|e| custom_code(&e)));
        }
        eprintln!("  98 recall -> {:?}", w.p3_recall(1).map_err(|e| custom_code(&e)));
        eprintln!("  101 settle again -> {:?}", w.p3_settle(0).map_err(|e| custom_code(&e)));
        let ata = *w.lp_atas.get(&1).unwrap();
        eprintln!("  senior u1 shares {}", w.token_amount(&ata));
        let c78 = w.do_lp_crank(0);
        let (cfg, g) = w.env.market_state();
        eprintln!("  tag78 after resolve -> {:?}; lp_fee accrued {} withdrawn {}; ins {} budget {}", c78.as_ref().map_err(|e| custom_code(e)), cfg.lp_fee_accrued_atoms, cfg.lp_fee_withdrawn_atoms, g.insurance, g.insurance_domain_budget_remaining_total);
        w.p3_prep();
        let ex = w.do_lp_execute(1);
        eprintln!("  senior u1 execute pending -> {:?}", ex.as_ref().map_err(|e| (custom_code(e), e.chars().filter(|c| c.is_ascii()).collect::<String>().split("Program log: ").skip(1).map(|l| l.chars().take(90).collect::<String>()).collect::<Vec<_>>())));
        for i in 0..3 {
            let cs = w.do_close_slab();
            let _ = w.do_claim_protocol();
            let (cfg2, _) = w.env.market_state();
            let ex2 = w.do_lp_execute(1);
            eprintln!("  closeslab#{i} -> {:?}; lp_fee acc/wd {}/{}; execute -> {:?}", cs.as_ref().map_err(|e| custom_code(e)), cfg2.lp_fee_accrued_atoms, cfg2.lp_fee_withdrawn_atoms, ex2.as_ref().map_err(|e| custom_code(e)));
            if w.is_tombstone() { break; }
        }
        let rr = w.do_lp_redeem(1, 10_000);
        eprintln!("  senior u1 redeem -> {:?}", rr.as_ref().map_err(|e| (custom_code(e), e.split("Program log").skip(1).map(|l| l.chars().take(100).collect::<String>()).collect::<Vec<_>>())));
        let (_, g) = w.env.market_state();
        eprintln!("  mode {:?} mat {} c_tot {}", g.mode, g.materialized_portfolio_count, g.c_tot);
    }
    r.unwrap();
}

/// P3 shrink: one live partial senior redemption, then Resolve; the remaining senior shares
/// cannot be redeemed after resolution. Run: FUZZ_P3=1 --ignored.
#[test]
#[ignore]
fn indep_p3_senior_can_exit_after_resolve_following_partial_redeem() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(30);
    let r = w.apply(&Op::LpRedeem { u: 99, frac_bps: 8721 });
    eprintln!("live partial redeem -> {:?}", r.map_err(|e| custom_code(&e)));
    let (reg, _, _) = w.lp_vault.unwrap();
    let red = state::derive_lp_redemption(&w.env.program_id, &reg, &w.owners[1].pubkey()).0;
    let pa = w.env.svm.get_account(&red);
    eprintln!("redemption PDA after executed live redeem: {:?}", pa.map(|a| (a.lamports, a.data.len(), a.data.iter().any(|b| *b != 0), a.owner)));
    let r2 = w.apply(&Op::LpRedeem { u: 99, frac_bps: 5000 });
    eprintln!("second live redeem -> {:?}", r2.map_err(|e| custom_code(&e)));
    let wd = w.wind_down();
    eprintln!("wind_down -> {wd:?}");
    let u = 99usize % 3 + 1;
    let ata = *w.lp_atas.get(&u).unwrap();
    eprintln!("u{u} shares {}", w.token_amount(&ata));
    w.p3_prep();
    let (cfg, g) = w.env.market_state();
    eprintln!("H {} mode {:?} mat {}", cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms, g.mode, g.materialized_portfolio_count);
    let rr = w.do_lp_redeem(u, 10_000);
    eprintln!("terminal full redeem -> {:?}", rr.as_ref().map_err(|e| custom_code(e)));
    wd.unwrap();
}

/// F-12 (P3): ONE fee-bearing trade, then Resolve. The LP fee leg H > 0 cannot be harvested
/// after Resolve (tag 78 is Live-only -> 21), and bound ExecuteRedemption refuses with 84
/// (VaultLpHarvestPending) while H > 0 — so every senior is locked forever.
/// Design §0.3: "77 in Resolved mode on a bound vault: senior value = min(physical, C)".
/// Run: FUZZ_P3=1 --ignored.
#[test]
#[ignore]
fn indep_p3_f12_seniors_exit_after_resolve_with_unharvested_lp_fee() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(30);
    w.apply(&Op::TradeCpi { u: 128, size_tenths: -300 }).expect("one fee-bearing trade vs the vault LP");
    let (cfg, _) = w.env.market_state();
    let h = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(h > 0, "vacuity: LP fee leg accrued");
    let pre = std::env::var("F12_PRECRANK").is_ok();
    if pre {
        eprintln!("keeper tag 78 before resolve -> {:?}", w.do_lp_crank(0).map_err(|e| custom_code(&e)));
    }
    let r = w.wind_down();
    eprintln!("F-12 (H={h}, precrank={pre}): wind_down -> {r:?}");
    r.expect("seniors must be able to exit after Resolve");
}

/// P3 shrink (seed 0xf1bbcdcbfa543f95, fee 30): a second senior deposits, an unrelated NoCpi
/// trade and a small price move; after Resolve the second senior's redemption fails with
/// Custom(25) EngineCounterUnderflow and its shares are locked. Run: FUZZ_P3=1 --ignored.
#[test]
#[ignore]
fn indep_p3_second_senior_can_exit_after_resolve() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(30);
    for op in [
        Op::LpDeposit { u: 74, amt: 228_224 },
        Op::Push { delta_bps: -285 },
        Op::TradeNoCpi { a: 85, b: 51, size_tenths: -133, off_bps: 2514 },
    ] {
        let r = w.apply(&op);
        eprintln!("op {op:?} -> {:?}", r.map_err(|e| custom_code(&e)));
        w.check().unwrap();
    }
    let (_, g) = w.env.market_state();
    eprintln!("pre-resolve C {} backing {:?}", w.p3_c(), g.source_backing_buckets.iter().map(|b| b.fresh_unliened_backing_num / BOUND_SCALE).collect::<Vec<_>>());
    let r = w.wind_down();
    for (&u, ata) in w.lp_atas.clone().iter() {
        eprintln!("senior u{u}: shares left {} net tokens {}", w.token_amount(ata), w.net_of(&w.owners[u].pubkey()));
    }
    if !w.is_tombstone() {
        let (_, g) = w.env.market_state();
        eprintln!("post: C {} backing {:?} sc {:?}", w.p3_c(), g.source_backing_buckets.iter().map(|b| b.fresh_unliened_backing_num / BOUND_SCALE).collect::<Vec<_>>(), g.source_credit.iter().map(|c| (c.spent_backing_num / BOUND_SCALE, c.provider_receivable_num / BOUND_SCALE)).collect::<Vec<_>>());
    }
    let jr = w.p3.as_ref().unwrap().junior.pubkey();
    eprintln!("junior net {} (deposited 3,000,000); trader nets u0 {} u2 {} u3 {} u4 {}", w.net_of(&jr), w.net_of(&w.owners[0].pubkey()), w.net_of(&w.owners[2].pubkey()), w.net_of(&w.owners[3].pubkey()), w.net_of(&w.owners[4].pubkey()));
    r.expect("every senior exits after Resolve");
}

/// F-14 variants: same 3 ops; (a) Live, both seniors redeem fully before any Resolve;
/// (b) Resolved, the SECOND senior redeems first. Run: FUZZ_P3=1 --ignored.
#[test]
#[ignore]
fn indep_p3_f14_variants() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    for variant in ["live_both", "resolved_second_first", "resolved_genesis_first", "resolved_genesis_first_late", "resolved_pending_before_close"] {
        let mut w = World::new(30);
        for op in [
            Op::LpDeposit { u: 74, amt: 228_224 },
            Op::Push { delta_bps: -285 },
            Op::TradeNoCpi { a: 85, b: 51, size_tenths: -133, off_bps: 2514 },
        ] {
            let _ = w.apply(&op);
        }
        let second = 74usize % 3 + 1;
        if variant == "live_both" {
            for _ in 0..30 { let s = w.slot() + 5; w.env.svm.warp_to_slot(s); let _ = w.do_push(w.mark); let _ = w.do_crank(N_USERS); }
            for u in [1usize, second] {
                w.p3_prep();
                let r = w.do_lp_redeem(u, 10_000);
                eprintln!("F-14 {variant}: senior u{u} live redeem -> {:?}", r.map_err(|e| custom_code(&e)));
            }
        } else {
            w.p3_prep();
            w.do_resolve().unwrap();
            if variant == "resolved_pending_before_close" {
                for u in [1usize, second] {
                    let r = w.do_lp_redeem(u, 10_000);
                    eprintln!("F-14 {variant}: senior u{u} redeem BEFORE close-out -> {:?}", r.map_err(|e| custom_code(&e)));
                }
            }
            let _ = w.p3_terminal_settle();
            if variant == "resolved_genesis_first_late" {
                let s = w.slot() + 3_000;
                w.env.svm.warp_to_slot(s);
            }
            for u in 0..=N_USERS { let _ = w.do_close_resolved(u); let _ = w.do_claim_topup(u); }
            for u in 0..=N_USERS {
                if let Some(pf) = w.env.svm.get_account(&w.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()) {
                    let (pid, seq, ep) = w.env.portfolio_identity(w.ports[u]);
                    let (m, p, owner, payer) = (w.env.market, w.ports[u], Pubkey::new_from_array(pf.owner), w.env.payer.pubkey());
                    let _ = w.send(ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: ep },
                        vec![AccountMeta::new(payer, true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(owner, false)], &[]);
                }
            }
            let order = if variant == "resolved_second_first" { [second, 1usize] } else { [1usize, second] };
            for u in order {
                if variant == "resolved_pending_before_close" {
                    let r = w.do_lp_execute(u);
                    eprintln!("F-14 {variant}: senior u{u} execute pending after close-out -> {:?}", r.map_err(|e| custom_code(&e)));
                    continue;
                }
                let r = w.do_lp_redeem(u, 10_000);
                eprintln!("F-14 {variant}: senior u{u} resolved redeem -> {:?}", r.map_err(|e| custom_code(&e)));
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// B12 (P3 b2b2559e, E2E HIGH): an ABANDONED portfolio cannot strand terminal insurance.
// Resolved mode: a STRANGER runs CloseResolved (permissionless, pays the owner), then
// ClosePortfolio (tag 8) with account [3] = the portfolio's owner (rent to owner), and then
// wrapper tag 41 / stake tag 29 recovers the WHOLE budget. A stranger must NOT be able to
// close a portfolio that still holds a claim, nor redirect its rent.
// ═══════════════════════════════════════════════════════════════════════════

impl World {
    fn do_stranger_close_portfolio(&mut self, u: usize, stranger: &Keypair, rent_to: Pubkey) -> Result<u64, String> {
        let p = self.ports[u];
        let (pid, seq, pep) = self.env.portfolio_identity(p);
        let m = self.env.market;
        self.env.ensure_signer_account(stranger.pubkey());
        self.send(
            ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: pep },
            vec![AccountMeta::new(stranger.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(rent_to, false)],
            &[stranger],
        )
    }
}

fn b12_bound_resolved_world_all_abandoned() -> (World, u128) {
    let mut w = World::new(0);
    w.do_configure_stale_resolve(9_000, 100).expect("stale policy");
    w.do_topup_insurance(5_000_000).expect("insurance top-up");
    w.setup_stake(1_000 + 5_000_000);
    w.do_trade_nocpi(0, 1, 10 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    let s = w.slot() + 9_005;
    w.env.svm.warp_to_slot(s);
    let _ = w.do_crank(N_USERS);
    w.do_resolve_stale().expect("stale resolve (keeper dead)");
    let budget = w.env.market_state().1.insurance_domain_budget_remaining_total;
    (w, budget)
}

/// B12 positive: every owner walked away; only strangers act. Run alone with INDEP_MAINNET_ID=1.
#[test]
#[ignore]
fn indep_b12_stranger_cleanup_then_stake_tag29_recovers_whole_budget() {
    assert!(std::env::var("INDEP_MAINNET_ID").as_deref() == Ok("1") || std::env::var("INDEP_PROGRAM_ID").is_ok());
    let (mut w, budget) = b12_bound_resolved_world_all_abandoned();
    assert!(budget > 0, "vacuity: terminal budget exists");
    let stranger = Keypair::new();
    let owner_bal0: Vec<u128> = (0..w.ports.len()).map(|u| w.user_token_total_of(u)).collect();
    // CloseResolved + tag 46 by anyone (pays only the owner's receipt accounts).
    let (_paid, stuck) = w.permissionless_close_out().unwrap();
    assert!(stuck.is_empty(), "users closed out permissionlessly");
    for u in 0..w.ports.len() {
        let owner = w.owners[u].pubkey();
        let lam0 = w.env.svm.get_account(&owner).map_or(0, |a| a.lamports);
        let r = w.do_stranger_close_portfolio(u, &stranger, owner);
        assert!(r.is_ok(), "B12: stranger ClosePortfolio of empty u{u} with [3]=owner must succeed: {:?}", r.map_err(|e| custom_code(&e)));
        w.closed[u] = true;
        let lam1 = w.env.svm.get_account(&owner).map_or(0, |a| a.lamports);
        assert!(lam1 > lam0, "rent must return to the OWNER");
    }
    let (_, g) = w.env.market_state();
    assert_eq!(g.materialized_portfolio_count, 0);
    let sv = w.stake.unwrap().2;
    let (fees0, sv0) = (w.pool_fields().unwrap().2, w.token_amount(&sv));
    w.do_stake_recover_terminal(budget as u64, None).expect("stake tag 29 recovers the budget");
    assert_eq!(w.token_amount(&sv) - sv0, budget, "whole budget recovered to the pool vault");
    assert_eq!(w.pool_fields().unwrap().2 - fees0, budget as u64, "whole budget booked to stakers");
    assert!(try_retire(&mut w), "market retires");
    w.check_tokens().unwrap();
    for u in 0..w.ports.len() {
        assert!(w.user_token_total_of(u) >= owner_bal0[u], "owners were paid, never debited");
    }
}

/// B12 negative: a stranger cannot close a portfolio that still holds a claim (capital /
/// unfinalized receipt / position), and cannot redirect the rent to itself.
#[test]
fn indep_b12_stranger_cannot_close_claim_holding_portfolio_or_redirect_rent() {
    let mut w = World::new(0);
    w.do_trade_nocpi(0, 1, 10 * (POS_SCALE as i128 / 10), INITIAL_MARK).expect("open");
    w.do_resolve().expect("resolve");
    let stranger = Keypair::new();
    // u2 holds capital (never traded); u0 holds a resolved position/claim.
    for u in [2usize, 0] {
        let before = w.env.svm.get_account(&w.ports[u]).unwrap();
        let owner = w.owners[u].pubkey();
        let r = w.do_stranger_close_portfolio(u, &stranger, owner);
        eprintln!("B12 neg: stranger close of claim-holding u{u} -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
        assert!(r.is_err(), "a stranger must not close a portfolio that still holds a claim (u{u})");
        assert_eq!(w.env.svm.get_account(&w.ports[u]).unwrap().data, before.data);
    }
    // Empty it the permissionless way, then try to steer rent to the stranger.
    for _ in 0..6 {
        let _ = w.do_close_resolved(2);
        let _ = w.do_claim_topup(2);
        let s = w.slot() + 10;
        w.env.svm.warp_to_slot(s);
    }
    let p = w.env.portfolio_state(w.ports[2]);
    assert!(p.capital == 0 && p.active_bitmap == percolator::active_bitmap_empty(), "vacuity: u2 emptied by CloseResolved");
    let lam_s0 = w.env.svm.get_account(&stranger.pubkey()).map_or(0, |a| a.lamports);
    let r = w.do_stranger_close_portfolio(2, &stranger, stranger.pubkey());
    eprintln!("B12 neg: stranger close with [3]=stranger -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    assert!(r.is_err(), "rent must not be redirectable to a stranger");
    assert!(w.env.svm.get_account(&stranger.pubkey()).map_or(0, |a| a.lamports) <= lam_s0);
    let other = Keypair::new();
    let r2 = w.do_stranger_close_portfolio(2, &stranger, other.pubkey());
    assert!(r2.is_err(), "rent must not be redirectable to an arbitrary account");
    w.check().unwrap();
}

/// P3 HIGH (coordinator, = F-12): a market that RESOLVES with unharvested LP fees must still let
/// every senior redeem, and the fee atoms must be conserved (not stranded in the wrapper vault).
/// No keeper tag 78 before resolve. Run alone: FUZZ_P3=1 --ignored indep_p3_resolve_with_pending
#[test]
#[ignore]
fn indep_p3_resolve_with_pending_fees_seniors_redeem_and_fees_conserved() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    std::env::set_var("FUZZ_P3_PRECRANK", "0");
    std::env::set_var("FUZZ_P3_DUST", "2000");
    let mut w = World::new(30);
    for op in [Op::TradeCpi { u: 128, size_tenths: -300 }, Op::TradeCpi { u: 129, size_tenths: 200 }, Op::TradeCpi { u: 130, size_tenths: 100 }] {
        let _ = w.apply(&op);
        w.check().unwrap();
    }
    let (cfg, _) = w.env.market_state();
    let h = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(h > 0, "vacuity: LP fees outstanding at resolve");
    let minted = w.minted;
    let r = w.wind_down();
    eprintln!("resolve-with-pending-fees (H={h}): wind_down -> {r:?}");
    w.check_tokens().unwrap();
    r.expect("seniors must redeem after a resolve with pending LP fees, and no value may be stranded (dust <= 2000)");
    assert!(w.minted >= minted);
}

/// F-12 RESIDUAL on 07a1d0eb (shrunk from the random-resolve P3 fuzz, seed 6161 batch): resolve
/// with LP fees outstanding and no pre-resolve harvest; the new resolved tag 78 should let seniors
/// out, but redemption still returns 84. Run: FUZZ_P3=1 FUZZ_P3_PRECRANK=0 --ignored.
#[test]
#[ignore]
fn indep_p3_f12_residual_two_trades_then_resolve() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(30);
    for op in [Op::TradeCpi { u: 220, size_tenths: -138 }, Op::Warp { n: 40 }, Op::TradeCpi { u: 8, size_tenths: 293 }] {
        let r = w.apply(&op);
        eprintln!("op {op:?} -> {:?}", r.map_err(|e| custom_code(&e)));
        w.check().unwrap();
    }
    let lp = w.p3.as_ref().unwrap().lp;
    let lpst = w.env.portfolio_state(lp);
    eprintln!("pre-resolve vault LP legs {:?} cap {} pnl {}", lpst.legs.iter().filter(|l| l.active).map(|l| l.basis_pos_q).collect::<Vec<_>>(), lpst.capital, lpst.pnl);
    let r = w.wind_down();
    eprintln!("F-12 residual: wind_down -> {r:?}; resolved tag 78 now -> {:?}", w.do_lp_crank(0).map_err(|e| custom_code(&e)));
    if !w.is_tombstone() {
        let (_, g) = w.env.market_state();
        eprintln!("  end state: mode {:?} materialized {} c_tot {} pnl_pos {} oi {}/{} vault LP present {}", g.mode, g.materialized_portfolio_count, g.c_tot, g.pnl_pos_tot, g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q, w.env.svm.get_account(&lp).map_or(false, |a| a.lamports > 0));
        for u in 0..w.ports.len() {
            if let Some(pf) = w.env.svm.get_account(&w.ports[u]).and_then(|a| state::read_portfolio(&a.data).ok()) {
                eprintln!("  u{u}: cap {} pnl {} legs {} receipt {:?}", pf.capital, pf.pnl, pf.legs.iter().filter(|l| l.active).count(), (pf.resolved_payout_receipt.present, pf.resolved_payout_receipt.finalized));
            }
        }
        if let Some(pf) = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()) {
            eprintln!("  vault LP: cap {} pnl {} legs {} receipt {:?}", pf.capital, pf.pnl, pf.legs.iter().filter(|l| l.active).count(), (pf.resolved_payout_receipt.present, pf.resolved_payout_receipt.finalized));
        }
        for t in [0u8, 1] {
            eprintln!("  tag101 settle(topup {t}) now -> {:?}", w.p3_settle(t).map_err(|e| custom_code(&e)));
        }
        eprintln!("  tag78 after settle -> {:?}", w.do_lp_crank(0).map_err(|e| custom_code(&e)));
        eprintln!("  stats err: {:?}", w.stats.err.iter().filter(|(k, _)| k.starts_with("p3") || k.starts_with("lp_")).collect::<Vec<_>>());
    }
    r.expect("seniors exit after resolve with pending fees");
}

/// Tag-98 recall bound (P3 §0.3 row 98 / §149): permissionless; moves vault-LP capital into the
/// backing pot (no SPL move, header.vault nets 0); bounded by the senior liquidity shortfall
/// C_eff − backing; LP must be flat; refused 76 otherwise. Outside NoCpi pairs are refused on a
/// bound asset (F-14 head), so the shortfall is forced THROUGH THE VAULT LP: (1) a trader goes
/// long vs the vault LP and the mark rises (the LP's loss draws the backing pot below C), trader
/// closes; (2) a second trader goes short vs the LP and the mark falls (the LP wins into capital),
/// trader closes -> LP flat, capital > 0, backing < C. Run: FUZZ_P3=1 --ignored indep_p3_recall_bound
#[test]
#[ignore]
fn indep_p3_recall_bound_after_vault_lp_shortfall() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(0);
    let q = POS_SCALE as i128;
    let state = |w: &World| {
        let (_, g) = w.env.market_state();
        let backing: u128 = g.source_backing_buckets.iter().take(2).map(|b| b.fresh_unliened_backing_num / BOUND_SCALE).sum();
        let lp = w.p3.as_ref().unwrap().lp;
        let lpc = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.legs.iter().filter(|l| l.active).count())).unwrap_or((0, 0, 0));
        (w.p3_c(), backing, lpc)
    };
    let step = |w: &mut World, label: &str| {
        let _ = w.permissionless_repair(30);
        eprintln!("recall[{label}]: (C, backing, (lp cap, lp pnl, lp legs)) = {:?}", state(w));
    };
    // Phase 1: trader u2 long, mark up 3x ~+24%; close.
    let r = w.p3_trade_vs_vault_lp(2, 3 * q);
    eprintln!("open long vs LP -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    for _ in 0..7 { let _ = w.apply(&Op::Push { delta_bps: 2400 }); step(&mut w, "up"); }
    let mut r = Err(String::new());
    for _ in 0..6 {
        r = w.p3_trade_vs_vault_lp(2, -3 * q);
        if r.is_ok() { break; }
        step(&mut w, "retry close");
    }
    eprintln!("close long -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    step(&mut w, "after long close");
    // Phase 2: the junior tops the flat vault LP back up (tag 96); that capital is what tag 98
    // may recall into the senior backing pot, bounded by the shortfall.
    let rj = w.p3_junior_deposit(1_000_000);
    eprintln!("junior re-deposit 1,000,000 -> {:?}", rj.as_ref().map_err(|e| custom_code(e)));
    step(&mut w, "after junior re-deposit");
    w.check().unwrap();
    let (c, backing, (lpcap, _, lplegs)) = state(&w);
    let shortfall = c.saturating_sub(backing);
    eprintln!("recall: C {c} backing {backing} shortfall {shortfall} lp capital {lpcap} legs {lplegs}");
    if shortfall == 0 && lplegs == 0 {
        // Senior-draw rule (d119eebd+): a vault-LP loss writes C down instead of leaving a senior
        // shortfall, so this construction has nothing to recall. Pin the refusal (76, or 89
        // while a draw is pending) and record the gap.
        let r = w.p3_recall(1);
        let rc = r.as_ref().err().and_then(|e| custom_code(e));
        eprintln!("RECALL-GAP (senior draw): no shortfall (C {c} backing {backing}); recall(1) -> {rc:?}");
        assert!(rc == Some(76) || rc == Some(89), "no shortfall -> recall refused (76/89), got {rc:?}");
        return;
    }
    assert!(shortfall > 0 && lpcap > 0 && lplegs == 0, "vacuity: need LP flat with capital and a senior shortfall (C {c} backing {backing} lpcap {lpcap} legs {lplegs})");
    let v0 = w.token_amount(&w.env.vault);
    let hv0 = w.env.market_state().1.vault;
    let rec = |w: &World| { let st = w.p3_state(); u128::from_le_bytes(st[208..224].try_into().unwrap()) };
    let r0 = rec(&w);
    let bound = shortfall.min(lpcap);
    let over = w.p3_recall(bound + 1);
    eprintln!("recall bound+1 ({}) -> {:?}", bound + 1, over.as_ref().map_err(|e| custom_code(e)));
    assert!(over.is_err(), "recall above min(shortfall, LP capital) must be refused");
    assert_eq!(custom_code(over.as_ref().unwrap_err()), Some(76), "over-bound recall refused with 76");
    let ok = w.p3_recall(bound);
    eprintln!("recall exact bound ({bound}) -> {:?}", ok.as_ref().map_err(|e| custom_code(e)));
    ok.expect("recall of exactly the bound succeeds");
    w.check().unwrap();
    assert_eq!(rec(&w) - r0, bound, "recalled_atoms counter += exactly the bound");
    assert_eq!(w.token_amount(&w.env.vault), v0, "no SPL moves");
    assert_eq!(w.env.market_state().1.vault, hv0, "header.vault nets 0");
    let (_, backing1, (lpcap1, _, _)) = state(&w);
    assert_eq!(backing1, backing + bound, "backing pot += bound");
    assert_eq!(lpcap1, lpcap - bound, "LP capital -= bound");
    let again = w.p3_recall(1);
    if shortfall == bound { assert!(again.is_err(), "no shortfall left: further recall refused"); }
    // Seniors redeem their full claim afterwards.
    let r = w.wind_down();
    eprintln!("wind-down after recall -> {r:?}");
    r.unwrap();
}

/// Suspected deadlock (coordinator): terminal-flat Resolved, NO LP fees pending, and the only
/// thing that clears the claim-free residual is the engine's insurance recredit inside tag 78.
/// If 78 fails with NoFeesToCrank (38) — reverting the recredit — while 77 returns 84, seniors
/// are locked. Spec (P3 doc §86): 78 "succeeds if either fees or residual were moved".
/// Run: FUZZ_P3=1 --ignored indep_p3_terminal_recredit_only
#[test]
#[ignore]
fn indep_p3_terminal_recredit_only_seniors_can_redeem() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let mut w = World::new(0); // fee 0: no LP fee leg can ever be pending
    w.do_topup_insurance(4_000_000).expect("insurance budget (the recredit source)");
    // A trader loses heavily against the vault LP (insurance/backing absorb), and an
    // outside-flow-free residual can arise from lent-out backing refills.
    let _ = w.apply(&Op::TradeCpi { u: 2, size_tenths: 30 });
    for d in [-2400, -2400, 1800] {
        let _ = w.apply(&Op::Push { delta_bps: d });
        let _ = w.permissionless_repair(30);
    }
    let (cfg, _) = w.env.market_state();
    assert_eq!(cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms, 0, "vacuity: no LP fees pending");
    let r = w.wind_down();
    let e78: Vec<String> = w.stats.err.iter().filter(|(k, _)| k.starts_with("lp_crank78") || k.contains("78")).map(|(k, v)| format!("{k}={v}")).collect();
    eprintln!("terminal-recredit-only: wind_down -> {r:?}; 78 errors {e78:?}");
    r.expect("seniors must always redeem on a terminal-flat Resolved market with no fees pending");
}

/// Round-trip control with an ORDINARY matcher LP (v18.2 shape; non-P3 World): an Earn vault
/// (9M in domain 0), trader long 10 units vs the LP, price 1.0 -> 0.4 (trader -6M) -> 2.05
/// (trader +16.5M), marks fresh; the trader then closes, converts and withdraws. Prints what the
/// trader receives vs owes and the domain buckets (is there a consumed lien in the vault pot, and
/// is the winner haircut?). Run on the v18.2 baseline and on the P3 bytes (non-P3 mode).
#[test]
#[ignore]
fn roundtrip_ordinary_lp_control_probe() {
    let mut w = World::new(0);
    if w.lp_vault.is_none() { w.create_lp_vault(); }
    let r = w.do_lp_deposit(0, 9_000_000);
    eprintln!("RTC 75 senior 9M d0 -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    let u = 1usize;
    let lp = N_USERS;
    let r = w.do_trade_cpi(u, 10 * POS_SCALE as i128);
    eprintln!("RTC open long 10 -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
    let dump = |w: &World, label: &str| {
        let g = w.env.market_state().1;
        let bs = percolator::BOUND_SCALE;
        let t = w.env.portfolio_state(w.ports[u]);
        let l = w.env.portfolio_state(w.ports[lp]);
        let b: Vec<String> = (0..2).map(|d| { let b = &g.source_backing_buckets[d]; let c = &g.source_credit[d];
            format!("d{d} {:?} fresh {} vlien {} consumed {} | sc claim {} rate {}", b.status, b.fresh_unliened_backing_num / bs, b.valid_liened_backing_num / bs, b.consumed_liened_backing_num / bs, c.positive_claim_bound_num / bs, c.credit_rate_num) }).collect();
        eprintln!("RTC[{label}] eff {} | T cap {} pnl {} | LP cap {} pnl {} | {} | ins {} vault {}", g.assets[0].effective_price, t.capital, t.pnl, l.capital, l.pnl, b.join(" | "), g.insurance, w.env.token_amount(w.env.vault));
    };
    let walk = |w: &mut World, target: u64| {
        for _ in 0..400 {
            let s = w.slot() + 20;
            w.env.svm.warp_to_slot(s);
            let _ = w.do_push(target);
            let _ = w.do_crank(u);
            let _ = w.do_crank(lp);
            if w.env.market_state().1.assets[0].effective_price == target { break; }
        }
        for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.do_crank(u); let _ = w.do_crank(lp); }
    };
    walk(&mut w, 400_000);
    dump(&w, "after loss leg");
    walk(&mut w, 2_050_000);
    dump(&w, "after reversal");
    for _ in 0..6 {
        let pos = w.env.portfolio_state(w.ports[u]).legs.iter().find(|l| l.active && l.asset_index == 0).map(|l| l.basis_pos_q).unwrap_or(0);
        if pos == 0 { break; }
        let r = w.do_trade_cpi(u, -pos);
        eprintln!("RTC close -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
        let s = w.slot() + 5; w.env.svm.warp_to_slot(s); let _ = w.do_crank(u); let _ = w.do_crank(lp);
    }
    dump(&w, "after close");
    let t = w.env.portfolio_state(w.ports[u]);
    let owed = t.capital + t.pnl.max(0) as u128;
    for i in 0..4 {
        let pnl = w.env.portfolio_state(w.ports[u]).pnl;
        if pnl <= 0 { break; }
        let r = w.do_convert(u, pnl as u128);
        eprintln!("RTC convert #{i} {pnl} -> {:?}", r.as_ref().map_err(|e| custom_code(e)));
        let s = w.slot() + 5; w.env.svm.warp_to_slot(s); let _ = w.do_crank(u); let _ = w.do_crank(lp);
    }
    dump(&w, "after convert");
    let cap = w.env.portfolio_state(w.ports[u]).capital;
    eprintln!("RTC SUMMARY: trader owed at close {owed}; capital after convert {cap} (haircut {})", owed.saturating_sub(cap));
}

/// Shrunk fuzz repro (seed 0x886b6a9743bb4326, P3 mode, 39b138c8): TradeCpi-only history against the
/// vault LP; at the resolved close a winner is haircut while the seniors still hold C. Run with
/// FUZZ_P3=1 FUZZ_STRICT_RT=1 (FUZZ_RT_TRACE=1 prints the state at the burn).
#[test]
#[ignore]
fn indep_p3_rt_winner_haircut_at_resolved_close_repro() {
    assert!(p3_mode(), "run with FUZZ_P3=1");
    let ops = vec![Op::TradeCpi { u: 22, size_tenths: 74 }, Op::TradeCpi { u: 139, size_tenths: 200 }, Op::Warp { n: 58 }, Op::Push { delta_bps: 608 },
        Op::LpDeposit { u: 218, amt: 8_973_011 }, Op::TradeCpi { u: 176, size_tenths: 232 }, Op::TradeCpi { u: 17, size_tenths: -154 }, Op::Push { delta_bps: 2228 }];
    let (r, st) = run_seq(30, &ops, true);
    eprintln!("soft {:?}", st.soft);
    r.expect("RT: a winner haircut at the resolved close while seniors hold C");
}

/// FUZZ_LP_DOMAINS=2: Earn deposits alternate between pot 0 and pot 1 (by amount parity), like
/// the relaunch seed (LP_VAULT_DEPOSIT_PER_DOMAIN) and users choosing either side's pot.
fn fuzz_lp_domain(amt: u64) -> u16 {
    if std::env::var("FUZZ_LP_DOMAINS").map_or(false, |v| v == "2") { (amt % 2) as u16 } else { 0 }
}
