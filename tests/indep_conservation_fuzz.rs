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

        let matcher_prog = Pubkey::new_unique();
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
        if std::env::var("FUZZ_LPVAULT").map_or(true, |v| v != "0") {
            w.create_lp_vault();
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
        assert_eq!(self.env.program_id.to_string(), "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv", "FUZZ_STAKE needs INDEP_MAINNET_ID=1");
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
            ProgInstruction::DepositToLpVault { amount: amt as u128, domain: 0 },
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
            ],
            &[&owner],
        )
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
            ],
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
        let dst = self.new_token(owner.pubkey(), 0);
        let (m, v, va, payer) = (self.env.market, self.env.vault, self.env.vault_authority, self.env.payer.pubkey());
        let (l0, l1) = (self.lp_ledger(0), self.lp_ledger(1));
        self.send(
            ProgInstruction::ExecuteRedemption { domain: 0 },
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
            ],
            &[],
        )
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
                self.do_batch_nocpi(a, b, s0 as i128 * q, s1 as i128 * q)
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
            Op::LpDeposit { u, amt } => self.do_lp_deposit(u as usize % N_USERS, amt),
            Op::LpCrank { d } => self.do_lp_crank((d % 2) as u16),
            Op::LpRedeem { u, frac_bps } => self.do_lp_redeem(u as usize % N_USERS, frac_bps),
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
        // Earn LP holders redeem everything (76/77 are allowed after resolution per the
        // LP-vault teardown tests).
        let holders: Vec<usize> = self.lp_atas.keys().copied().collect();
        for u in holders {
            if self.do_lp_redeem(u, 10_000).is_ok() {
                *self.stats.ok.entry("winddown_lp_redeem").or_default() += 1;
            }
            self.check()?;
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
    match rng.gen_range(0..124) {
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
    eprintln!("   haircut_then_burn: {} cases; first: {:?}", st.haircut_then_burn.len(), st.haircut_then_burn.first());
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
        self.do_trade_nocpi(a, b, q, self.mark).map_err(|e| format!("fresh open at mark: {:?}", custom_code(&e)))?;
        self.do_trade_nocpi(a, b, -q, self.mark).map_err(|e| format!("fresh close at mark: {:?}", custom_code(&e)))?;
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
    assert_eq!(std::env::var("INDEP_MAINNET_ID").as_deref(), Ok("1"), "run with INDEP_MAINNET_ID=1");
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
