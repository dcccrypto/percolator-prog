//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//!
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//!
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
//! (helpers copied from indep_p3_vault_lp.rs)
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator::POS_SCALE;
use percolator_prog::{ix::CrankObservationHint, ix::Instruction as ProgInstruction, state};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const PRICE: u64 = 1_000_000;
const DEAD: u128 = 1_000;

fn p3_so() -> std::path::PathBuf {
    std::env::var_os("INDEP_WRAPPER_SO")
        .map(Into::into)
        .unwrap_or_else(|| format!("{}/wt-indep/p3-so/current.so", std::env::var("HOME").unwrap()).into())
}

struct P3 {
    env: V16CuEnv,
    matcher: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    escrow: Pubkey,
    ledger0: Pubkey,
    ledger1: Pubkey,
    state_pda: Pubkey,
    lp: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
    upgrade: Keypair,
    program_data: Pubkey,
    minted: u128,
    tokens: Vec<Pubkey>,
}

fn raw(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend_from_slice(body);
    v
}

impl P3 {
    fn send_raw(&mut self, data: Vec<u8>, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let ix = Instruction { program_id: self.env.program_id, accounts: metas, data };
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, signers)
    }
    fn send(&mut self, ix: ProgInstruction, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        self.env.send(ix, metas, signers)
    }
    fn token(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        let k = self.env.token_account_for_mint(self.env.mint, owner, amount);
        self.minted += amount as u128;
        self.tokens.push(k);
        k
    }
    fn lp_share_ata(&mut self, owner: Pubkey) -> Pubkey {
        self.env.token_account_for_mint(self.lp_mint, owner, 0)
    }
    fn tok(&self, k: &Pubkey) -> u64 {
        self.env.token_amount(*k)
    }
    fn state(&self) -> Vec<u8> {
        self.env.svm.get_account(&self.state_pda).map(|a| a.data).unwrap_or_default()
    }
    fn c(&self) -> u128 {
        u128::from_le_bytes(self.state()[144..160].try_into().unwrap())
    }
    fn lp_state(&self) -> state::PortfolioAccountV16 {
        self.env.portfolio_state(self.lp)
    }
    fn slot(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    fn new() -> Self {
        std::env::set_var("INDEP_WRAPPER_SO", p3_so());
        let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams { initial_price: PRICE, ..V16CuMarketParams::default() });
        // 07a1d0eb auto-pin: vault LP matcher must be CANONICAL_VAULT_LP_MATCHER_PROGRAM.
        let matcher = if std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") { Pubkey::new_unique() } else { "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT".parse::<Pubkey>().unwrap() };
        let bytes = std::fs::read(matcher_program_path()).expect("matcher so");
        env.svm.add_program(matcher, &bytes);
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
        let pid = env.program_id;
        let market = env.market;
        let (registry, _) = state::derive_lp_vault_registry(&pid, &market);
        let (lp_mint, _) = state::derive_lp_vault_mint(&pid, &market);
        let (escrow, _) = state::derive_lp_escrow(&pid, &market);
        let ledger0 = state::derive_lp_backing_ledger(&pid, &market, 0).0;
        let ledger1 = state::derive_lp_backing_ledger(&pid, &market, 1).0;
        let state_pda = Pubkey::find_program_address(&[b"vault_lp", market.as_ref()], &pid).0;
        // upgrade authority mock (same ProgramData shape as tests/v16_cu.rs tag-85 fixture)
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
        let vault = env.vault;
        P3 {
            env,
            matcher,
            registry,
            lp_mint,
            escrow,
            ledger0,
            ledger1,
            state_pda,
            lp: Pubkey::default(),
            ctx: Pubkey::default(),
            delegate: Pubkey::default(),
            upgrade,
            program_data,
            minted: 0,
            tokens: vec![vault],
        }
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
            ],
            &[&admin],
        )
        .expect("74 CreateLpVault");
    }

    /// 75 Earn deposit; bound tail per §0.3 when `bound`.
    fn earn_deposit(&mut self, who: &Keypair, amount: u64, bound: bool) -> Result<Pubkey, String> {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self.lp_share_ata(who.pubkey());
        let src = self.token(who.pubkey(), amount);
        let mut metas = vec![
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
        if bound {
            metas.push(AccountMeta::new(self.state_pda, false));
            metas.push(AccountMeta::new(self.lp, false));
        }
        self.send(ProgInstruction::DepositToLpVault { amount: amount as u128, domain: 0 }, metas, &[who]).map(|_| ata)
    }

    fn request_redeem(&mut self, who: &Keypair, ata: Pubkey, shares: u128) -> Result<u64, String> {
        let red = state::derive_lp_redemption(&self.env.program_id, &self.registry, &who.pubkey()).0;
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(ata, false),
            AccountMeta::new(self.escrow, false),
            AccountMeta::new(red, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        self.send(ProgInstruction::RequestRedeemLpShares { shares }, metas, &[who])
    }

    fn execute_redeem(&mut self, who: &Keypair, bound: bool) -> (Pubkey, Result<u64, String>) {
        let red = state::derive_lp_redemption(&self.env.program_id, &self.registry, &who.pubkey()).0;
        let dest = self.token(who.pubkey(), 0);
        let payer = self.env.payer.pubkey();
        let mut metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(red, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(self.escrow, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new_readonly(self.env.vault_authority, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(self.ledger1, false),
            AccountMeta::new(who.pubkey(), false),
        ];
        if bound {
            metas.push(AccountMeta::new(self.state_pda, false));
            metas.push(AccountMeta::new(self.lp, false));
        }
        let r = self.send(ProgInstruction::ExecuteRedemption { domain: 0 }, metas, &[]);
        (dest, r)
    }

    /// 94 InitVaultLp (marketauth).
    fn init_vault_lp(&mut self, signer: &Keypair, floor_bps: u16) -> Result<u64, String> {
        let lp = Pubkey::new_unique();
        let len = self.env.portfolio_account_len;
        let pid = self.env.program_id;
        self.env.svm.set_account(lp, Account { lamports: 1_000_000_000, data: vec![0; len], owner: pid, executable: false, rent_epoch: 0 }).unwrap();
        self.lp = lp;
        let metas = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
        ];
        let mut metas = metas;
        if !std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") {
            // 07a1d0eb auto-pin tail: [8] canonical matcher, [9] ctx (w, zeroed, matcher-owned),
            // [10] delegate ["matcher", market, lp, registry, matcher, ctx].
            let ctx = Pubkey::new_unique();
            self.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher, executable: false, rent_epoch: 0 }).unwrap();
            let delegate = Pubkey::find_program_address(
                &[b"matcher", self.env.market.as_ref(), self.lp.as_ref(), self.registry.as_ref(), self.matcher.as_ref(), ctx.as_ref()],
                &self.env.program_id,
            )
            .0;
            self.env.svm.set_account(delegate, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
            self.ctx = ctx;
            self.delegate = delegate;
            metas.push(AccountMeta::new_readonly(self.matcher, false));
            metas.push(AccountMeta::new(ctx, false));
            metas.push(AccountMeta::new_readonly(delegate, false));
        }
        self.send_raw(raw(94, &floor_bps.to_le_bytes()), metas, &[signer])
    }

    /// 99 SetVaultLpRisk.
    fn set_risk(&mut self, signer: &Keypair, lev_max_bps: u32) -> Result<u64, String> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes()); // skew slope
        b.extend_from_slice(&0u64.to_le_bytes()); // skew max
        b.extend_from_slice(&0u128.to_le_bytes()); // lev cap (off)
        b.extend_from_slice(&0u16.to_le_bytes()); // lev max imr
        b.extend_from_slice(&lev_max_bps.to_le_bytes());
        b.extend_from_slice(self.matcher.as_ref());
        let metas = vec![AccountMeta::new(signer.pubkey(), true), AccountMeta::new_readonly(self.program_data, false), AccountMeta::new(self.env.market, false)];
        self.send_raw(raw(99, &b), metas, &[signer])
    }

    /// 95 VaultLpSetMatcher (passive kind 0, finite caps).
    fn set_matcher(&mut self, signer: &Keypair) -> Result<u64, String> {
        let ctx = Pubkey::new_unique();
        self.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher, executable: false, rent_epoch: 0 }).unwrap();
        let delegate = Pubkey::find_program_address(
            &[b"matcher", self.env.market.as_ref(), self.lp.as_ref(), self.registry.as_ref(), self.matcher.as_ref(), ctx.as_ref()],
            &self.env.program_id,
        )
        .0;
        self.env.svm.set_account(delegate, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
        self.ctx = ctx;
        self.delegate = delegate;
        let (_, seq, _) = self.env.portfolio_identity(self.lp);
        let fr = state::read_market_asset_generation_frontier(&self.env.svm.get_account(&self.env.market).unwrap().data).unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&fr.to_le_bytes());
        b.extend_from_slice(&10_000u16.to_le_bytes());
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        b.push(0); // kind passive
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&100u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&(1_000 * POS_SCALE).to_le_bytes()); // max_fill
        b.extend_from_slice(&(1_000 * POS_SCALE).to_le_bytes()); // max_inventory
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        let metas = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new_readonly(self.program_data, false),
            AccountMeta::new_readonly(self.env.market, false),
            AccountMeta::new_readonly(self.state_pda, false),
            AccountMeta::new(self.lp, false),
            AccountMeta::new_readonly(self.matcher, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        self.send_raw(raw(95, &b), metas, &[signer])
    }

    /// 96 DepositJuniorTranche.
    fn junior_deposit(&mut self, who: &Keypair, amount: u64) -> Result<u64, String> {
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
        self.send_raw(raw(96, &(amount as u128).to_le_bytes()), metas, &[who])
    }

    /// 97 WithdrawJuniorTranche; returns (dest, result).
    fn junior_withdraw(&mut self, who: &Keypair, dest_owner: Pubkey, amount: u128) -> (Pubkey, Result<u64, String>) {
        let dest = self.token(dest_owner, 0);
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(self.lp, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new_readonly(self.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        let r = self.send_raw(raw(97, &amount.to_le_bytes()), metas, &[who]);
        (dest, r)
    }

    /// 101 VaultLpSettleResolved.
    fn settle_resolved(&mut self, junior_owner: Pubkey, topup: u8) -> (Pubkey, Result<u64, String>) {
        let dest = self.token(junior_owner, 0);
        let payer = self.env.payer.pubkey();
        let metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(self.lp, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new_readonly(self.ledger1, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new_readonly(self.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        let r = self.send_raw(raw(101, &[topup]), metas, &[]);
        (dest, r)
    }

    fn crank(&mut self, p: Pubkey) -> Result<u64, String> {
        let slot = self.slot();
        let payer = self.env.payer.pubkey();
        let m = self.env.market;
        self.send(
            ProgInstruction::PermissionlessCrank { now_slot: slot, observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] },
            vec![AccountMeta::new(payer, true), AccountMeta::new(m, false), AccountMeta::new(p, false)],
            &[],
        )
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

    fn trade_vs_lp(&mut self, taker: &Keypair, tp: Pubkey, size_q: i128) -> Result<u64, String> {
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
        let (m, lp, mp, ctx, del) = (self.env.market, self.lp, self.matcher, self.ctx, self.delegate);
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
                fee_bps: 0,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(del, false),
            ],
            &[taker],
        )
    }

    fn push(&mut self, mark: u64) {
        let s = self.slot() + 1;
        self.env.svm.warp_to_slot(s);
        self.env.push_auth_mark_for_asset_as_admin(0, s, mark);
    }

    fn held(&self) -> u128 {
        self.tokens.iter().map(|k| self.env.svm.get_account(k).map(|a| {
            use solana_sdk::program_pack::Pack;
            spl_token::state::Account::unpack(&a.data).map(|t| t.amount as u128).unwrap_or(0)
        }).unwrap_or(0)).sum()
    }

    /// Full bind per §0.3 order: 74 → 75 seniors → 94 → 99 → 95 → 96 junior.
    fn bound(seniors: &[(&Keypair, u64)], junior: u64, floor_bps: u16) -> (Self, Vec<Pubkey>) {
        let mut w = P3::new();
        w.create_vault();
        let mut atas = Vec::new();
        for (k, amt) in seniors {
            atas.push(w.earn_deposit(k, *amt, false).expect("75 senior deposit (unbound)"));
        }
        let admin = w.env.admin.insecure_clone();
        w.init_vault_lp(&admin, floor_bps).unwrap_or_else(|e| panic!("94 InitVaultLp by marketauth: {e}"));
        let up = w.upgrade.insecure_clone();
        w.set_risk(&up, 0).unwrap_or_else(|e| panic!("99 SetVaultLpRisk by upgrade authority: {e}"));
        if std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") { w.set_matcher(&up).unwrap_or_else(|e| panic!("95 VaultLpSetMatcher by upgrade authority: {e}")); }
        if junior > 0 {
            w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96 junior deposit: {e}"));
        }
        (w, atas)
    }
}

fn code(e: &str) -> Option<u32> {
    custom_code(e)
}

/// H2 (a): the creator (marketauth / asset_admin) cannot choose or reprice the vault LP's
/// matcher or risk params — tags 95 and 99 are upgrade-authority-only (design §2.1, §6 P3-H2).

// ═══════════════════════════════════════════════════════════════════════════
// P3 FINAL 07a1d0eb — AUTO-PIN AT TAG 94 (design doc line 8 + vault_lp_v18 PIN_* constants):
// the program approves CANONICAL_VAULT_LP_MATCHER_PROGRAM, keeps the 1x exposure default, and
// initialises the matcher ctx with the protocol's PIN_* vAMM parameters and price-derived FINITE
// caps (max_fill $5k, max_inventory $25k). The creator supplies none of these; the market can
// trade right after tag 94 (+96). Tags 95/99 remain upgrade-authority-only adjustments.
// ═══════════════════════════════════════════════════════════════════════════

const CANONICAL: &str = "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT";
const PIN_MAX_FILL_USD: u128 = 5_000;
const ENGINE_MAX_POSITION_ABS_Q: u128 = 100_000_000_000_000;

fn pos_q(w: &P3, p: Pubkey) -> i128 {
    w.env.portfolio_state(p).legs.iter().find(|l| l.active).map(|l| l.basis_pos_q).unwrap_or(0)
}

/// Bind the market (74 → 75 senior → 94 auto-pin → 96 junior), NO 95 / NO 99.
fn autopinned(senior: u64, junior: u64) -> (P3, Keypair) {
    let s1 = Keypair::new();
    let mut w = P3::new();
    w.create_vault();
    w.earn_deposit(&s1, senior, false).expect("75 senior deposit");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94 auto-pin by marketauth: {e}"));
    if junior > 0 {
        w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96: {e}"));
    }
    (w, s1)
}

/// A market trades immediately after tag 94 (+96): no 95/99 activation step.
#[test]
fn autopin_market_trades_immediately_after_94() {
    let (mut w, _s) = autopinned(10_000_000, 3_000_000);
    assert_eq!(w.matcher.to_string(), CANONICAL, "vacuity: bound to the canonical matcher id");
    let (t, tp) = w.trader(20_000_000);
    let _ = w.crank(w.lp);
    let r = w.trade_vs_lp(&t, tp, POS_SCALE as i128);
    assert!(r.is_ok(), "TradeCpi vs the vault LP right after 94 must fill: {:?}", r.map_err(|e| code(&e)));
    assert_eq!(pos_q(&w, tp), POS_SCALE as i128, "taker filled 1 unit");
    assert_eq!(pos_q(&w, w.lp), -(POS_SCALE as i128), "vault LP took the other side");
}

/// The creator cannot bind a non-canonical matcher: 94 naming any other executable program
/// in [8] is refused (81 VaultLpMatcherNotApproved), with no state change.
#[test]
fn autopin_creator_cannot_bind_non_canonical_matcher() {
    let s1 = Keypair::new();
    let mut w = P3::new();
    w.create_vault();
    w.earn_deposit(&s1, 10_000_000, false).expect("senior");
    let other = Pubkey::new_unique();
    w.env.svm.add_program(other, &std::fs::read(matcher_program_path()).unwrap());
    let canonical = w.matcher;
    w.matcher = other; // init_vault_lp uses self.matcher for [8] and the ctx owner
    let before = (w.env.svm.get_account(&w.env.market).unwrap().data, w.env.svm.get_account(&w.registry).unwrap().data);
    let admin = w.env.admin.insecure_clone();
    let r = w.init_vault_lp(&admin, 1_000);
    eprintln!("94 with non-canonical matcher -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert_eq!(r.as_ref().err().and_then(|e| code(e)), Some(81), "non-canonical matcher must be refused 81");
    assert_eq!((w.env.svm.get_account(&w.env.market).unwrap().data, w.env.svm.get_account(&w.registry).unwrap().data), before);
    assert!(w.env.svm.get_account(&w.state_pda).map_or(true, |a| a.data.iter().all(|b| *b == 0)), "no vault_lp_state created");
    // Control: the canonical program binds.
    w.matcher = canonical;
    w.init_vault_lp(&admin, 1_000).expect("canonical matcher binds");
}

/// The creator cannot supply caps: tag 94's payload is only the junior floor; any extra bytes
/// (an attempt to pass creator caps) are refused, and 95 by the creator is refused.
#[test]
fn autopin_creator_cannot_pass_or_loosen_caps() {
    let s1 = Keypair::new();
    let mut w = P3::new();
    w.create_vault();
    w.earn_deposit(&s1, 10_000_000, false).expect("senior");
    let admin = w.env.admin.insecure_clone();
    // 94 with a creator-chosen cap appended (u128 max_fill = u128::MAX).
    let lp = Pubkey::new_unique();
    let len = w.env.portfolio_account_len;
    let pid = w.env.program_id;
    w.env.svm.set_account(lp, Account { lamports: 1_000_000_000, data: vec![0; len], owner: pid, executable: false, rent_epoch: 0 }).unwrap();
    w.lp = lp;
    let ctx = Pubkey::new_unique();
    w.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: w.matcher, executable: false, rent_epoch: 0 }).unwrap();
    let del = Pubkey::find_program_address(&[b"matcher", w.env.market.as_ref(), lp.as_ref(), w.registry.as_ref(), w.matcher.as_ref(), ctx.as_ref()], &pid).0;
    w.env.svm.set_account(del, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
    let metas = vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(w.registry, false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new(lp, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new(w.ledger1, false),
        AccountMeta::new_readonly(w.matcher, false),
        AccountMeta::new(ctx, false),
        AccountMeta::new_readonly(del, false),
    ];
    let mut data = raw(94, &1_000u16.to_le_bytes());
    data.extend_from_slice(&u128::MAX.to_le_bytes());
    let r = w.send_raw(data, metas.clone(), &[&admin]);
    eprintln!("94 with appended creator caps -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert!(r.is_err(), "tag 94 must not accept creator-supplied cap bytes");
    // Normal 94, then the creator tries to loosen via 95 -> refused.
    w.send_raw(raw(94, &1_000u16.to_le_bytes()), metas, &[&admin]).expect("94 auto-pin");
    w.ctx = ctx;
    w.delegate = del;
    let r95 = w.set_matcher(&admin);
    assert!(r95.is_err(), "creator ran tag 95 (caps/matcher) — must be upgrade-authority only");
    let r99 = w.set_risk(&admin, 50_000);
    assert!(r99.is_err(), "creator ran tag 99 (leverage) — must be upgrade-authority only");
}

/// Pinned caps are FINITE and price-derived: a huge request is clipped to max_fill
/// ($5k at the bind price), never unlimited, and well below ENGINE_MAX_POSITION_ABS_Q.
#[test]
fn autopin_caps_are_finite_and_bind_at_max_fill() {
    // LP equity >> $5k so the matcher's max_fill (not the 1x exposure cap) is the binding limit.
    let (mut w, _s) = autopinned(40_000_000_000, 10_000_000_000);
    let (t, tp) = w.trader(40_000_000_000);
    let _ = w.crank(w.lp);
    let huge = (1_000_000 * POS_SCALE) as i128; // $1M request
    let r = w.trade_vs_lp(&t, tp, huge);
    eprintln!("huge request -> {:?}; filled {}", r.as_ref().map_err(|e| code(e)), pos_q(&w, tp));
    let filled = pos_q(&w, tp).unsigned_abs();
    let max_fill_q = PIN_MAX_FILL_USD * 1_000_000 * POS_SCALE / PRICE as u128; // price e6
    assert!(filled > 0, "vacuity: the pinned matcher filled something");
    assert!(filled <= max_fill_q, "fill {filled} exceeds the pinned max_fill {max_fill_q} ($5k)");
    assert!(filled < ENGINE_MAX_POSITION_ABS_Q, "caps must be finite");
}

/// The upgrade authority may TIGHTEN within protocol bounds (95 with smaller caps); the creator
/// cannot. After tightening, fills respect the tighter cap.
#[test]
fn autopin_upgrade_authority_can_tighten_creator_cannot() {
    let (mut w, _s) = autopinned(10_000_000, 3_000_000);
    let admin = w.env.admin.insecure_clone();
    let up = w.upgrade.insecure_clone();
    assert!(w.set_matcher(&admin).is_err(), "creator 95 refused");
    // set_matcher (helper) pins passive kind-0 with max_fill = 1000 units; as UA that is a
    // protocol adjustment within bounds.
    let r = w.set_matcher(&up);
    eprintln!("95 by upgrade authority -> {:?}", r.as_ref().map_err(|e| code(e)));
    r.expect("upgrade authority may adjust within bounds");
    let (t, tp) = w.trader(20_000_000);
    let _ = w.crank(w.lp);
    w.trade_vs_lp(&t, tp, POS_SCALE as i128).expect("trade after UA re-pin");
    assert_eq!(pos_q(&w, tp), POS_SCALE as i128);
}

/// H2 end to end under AUTO-PINNED settings: the creator (junior owner via path A) plus a second
/// trading wallet cannot profit at the seniors' expense across a size x mark sweep.
#[test]
fn autopin_h2_creator_free_option_fails_end_to_end() {
    for &size in &[3i128, 20, 50] {
        for &mark in &[700_000u64, 1_300_000, 2_000_000, 3_000_000] {
            let (mut w, s1) = autopinned(10_000_000, 3_000_000);
            let _ = s1;
            let c0 = w.c();
            let (t, tp) = w.trader(200_000_000); // creator's second wallet
            let _ = w.crank(w.lp);
            let r = w.trade_vs_lp(&t, tp, size * POS_SCALE as i128);
            let filled = pos_q(&w, tp);
            w.push(mark);
            for _ in 0..3 {
                let _ = w.crank(tp);
                let _ = w.crank(w.lp);
            }
            // Trader closes (reduce-only), whatever it can.
            let _ = w.trade_vs_lp(&t, tp, -filled);
            let _ = w.crank(tp);
            let tr = w.env.portfolio_state(tp);
            let trader_gain = tr.capital as i128 + tr.pnl as i128 - 200_000_000;
            let c1 = w.c();
            let st = w.state();
            let jdep = u128::from_le_bytes(st[160..176].try_into().unwrap());
            let lp = w.env.portfolio_state(w.lp);
            let lp_value = lp.capital as i128 + lp.pnl as i128;
            eprintln!("H2 size {size} mark {mark}: open {:?} filled {filled} trader_gain {trader_gain} C {c0}->{c1} lp_value {lp_value} jdep {jdep}", r.as_ref().map_err(|e| code(e)));
            let senior_loss = c0 as i128 - c1 as i128;
            assert!(senior_loss <= DEAD as i128, "seniors lost {senior_loss} (> dead-share rounding) — H2 free option");
            if senior_loss > 0 {
                assert!(trader_gain <= 0, "creator's wallet gained {trader_gain} while seniors lost {senior_loss}");
            }
        }
    }
}
