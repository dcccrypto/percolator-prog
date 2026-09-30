//! INDEPENDENT SUITE (2026-09-30) — P3 security items F14-Q1 / F14-Q2 (Sentinel), written from the
//! security finding text, not the fix:
//!   Q1: bound-vault NAV = per-domain NAV with impairment FLOORED at each domain's principal, then
//!       SUMMED — overstates cover when one domain's impairment > its principal while the other is
//!       positive. Required: every NAV consumer (97, Live 102, 77, 75) behaves as if
//!       cover = min(floored NAV, physical backing).
//!   Q2: tag 94 refuses a vault-LP bind on a multi-asset market; activating a second asset on a
//!       market with a bound vault is refused.
//! P3 helpers copied from indep_p1p3_combined.rs (07a1d0eb+ auto-pin flow).
#![cfg(not(kani))]
#![cfg(not(kani))]
#![allow(dead_code, unused_imports, unused_variables)]
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

thread_local! {
    /// Atomic-batch capture: when Some, P3::send/send_raw queue the instruction instead of sending.
    static CAPTURE: std::cell::RefCell<Option<(Vec<Instruction>, Vec<Keypair>)>> = std::cell::RefCell::new(None);
    /// (lp matcher-sequence add, taker position-epoch add, lp position-epoch add) for the next TradeCpi.
    static TRADE_ID_BUMP: std::cell::Cell<(u64, u64, u64)> = std::cell::Cell::new((0, 0, 0));
}

impl P3 {
    fn capture_push(ix: Instruction, signers: &[&Keypair]) -> bool {
        CAPTURE.with(|c| {
            let mut c = c.borrow_mut();
            if let Some((ixs, ks)) = c.as_mut() {
                ixs.push(ix);
                for k in signers { if !ks.iter().any(|x| x.pubkey() == k.pubkey()) { ks.push(k.insecure_clone()); } }
                true
            } else { false }
        })
    }
    fn capture_begin() { CAPTURE.with(|c| *c.borrow_mut() = Some((vec![], vec![]))); }
    /// Send every captured instruction in ONE transaction (all-or-nothing).
    fn capture_commit(&mut self) -> Result<u64, String> {
        let (ixs, ks) = CAPTURE.with(|c| c.borrow_mut().take()).expect("capture_begin first");
        self.env.svm.expire_blockhash();
        let payer = self.env.payer.insecure_clone();
        let touched: Vec<Pubkey> = ixs.iter().flat_map(|i| i.accounts.iter().map(|m| m.pubkey)).collect();
        let mut all = vec![heap_ix(), cu_ix()];
        all.extend(ixs);
        let mut signers: Vec<&Keypair> = vec![&payer];
        for k in &ks { signers.push(k); }
        let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(&all, Some(&payer.pubkey()), &signers, self.env.svm.latest_blockhash());
        let r = self.env.svm.send_transaction(tx).map(|m| m.compute_units_consumed).map_err(|e| format!("{e:?}"));
        if r.is_ok() { gc_zero_lamport_accounts(&mut self.env.svm, &touched); }
        log_error_sites(&r);
        r
    }
    fn send_raw(&mut self, data: Vec<u8>, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let ix = Instruction { program_id: self.env.program_id, accounts: metas, data };
        if Self::capture_push(ix.clone(), signers) { return Ok(0); }
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, signers)
    }
    fn send(&mut self, ix: ProgInstruction, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let raw_ix = Instruction { program_id: self.env.program_id, accounts: metas.clone(), data: ix.encode() };
        if Self::capture_push(raw_ix, signers) { return Ok(0); }
        self.env.send(ix, metas, signers)
    }
    fn token(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        let k = self.env.token_account_for_mint(self.env.mint, owner, amount);
        self.minted += amount as u128;
        self.tokens.push(k);
        k
    }
    fn lp_share_ata(&mut self, owner: Pubkey) -> Pubkey {
        if let Some(k) = FORCE_SHARE_ATA.with(|c| c.get()) { return k; }
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
        let mut params = market_params();
        params.max_portfolio_assets = CAP.with(|c| c.get());
        let mut env = V16CuEnv::new_with_init_params(params);
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
            ProgInstruction::CreateLpVault { fee_share_bps: TL_FEE_SHARE.with(|c| c.get()).or_else(|| std::env::var("P3_FEE_SHARE_BPS").ok().and_then(|v| v.parse().ok())).unwrap_or(0), redemption_cooldown_slots: TL_COOLDOWN.with(|c| c.get()), oi_reservation_threshold_bps: 0, domain: 0 },
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

    /// Tag 99 with skew funding on (upgrade authority).
    fn set_risk_skew(&mut self, signer: &Keypair, lev_max_bps: u32, slope_e9: u64, max_e9: u64) -> Result<u64, String> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&slope_e9.to_le_bytes());
        b.extend_from_slice(&max_e9.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
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

    /// Resolved tag 78 (bound tail = vault_lp_state). Valid on a terminal-flat Resolved bound
    /// market (P3 F-14 head): harvests pending LP fees + claim-free residual into the pot.
    fn crank_fees_78(&mut self) -> Result<u64, String> {
        let payer = self.env.payer.pubkey();
        let metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.state_pda, false),
        ];
        self.send(ProgInstruction::LpVaultCrankFees { domain: 0 }, metas, &[])
    }

    /// Permissionless Resolved tag 8 by a stranger: [closer, market, portfolio, owner(=rent)].
    fn close_portfolio_permissionless(&mut self, p: Pubkey, owner: Pubkey) -> Result<u64, String> {
        let closer = Keypair::new();
        self.env.ensure_signer_account(closer.pubkey());
        let (pid, seq, ep) = self.env.portfolio_identity(p);
        let m = self.env.market;
        self.send(
            ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: ep },
            vec![AccountMeta::new(closer.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(owner, false)],
            &[&closer],
        )
    }

    /// Junior's terminal payout: Resolved tag 102 for `physical − C` (junior owner signs; tail
    /// [7] dest, [8] vault, [9] vault authority, [10] token program). Largest accepted amount
    /// first, halving; returns the total SPL paid to the junior.
    fn junior_release_resolved(&mut self, junior: &Keypair) -> u128 {
        let mut paid = 0u128;
        let mut amt = self.tok(&self.env.vault) as u128;
        while amt > 0 {
            let dest = self.token(junior.pubkey(), 0);
            let mut b = amt.to_le_bytes().to_vec();
            b.extend_from_slice(&0u16.to_le_bytes());
            let metas = vec![
                AccountMeta::new(junior.pubkey(), true),
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
            if self.send_raw(raw(102, &b), metas, &[junior]).is_ok() {
                paid += self.tok(&dest) as u128;
                amt = self.tok(&self.env.vault) as u128;
                continue;
            }
            amt /= 2;
        }
        paid
    }

    /// Keeper terminal sequence after 101 + trader CloseResolved (P3 doc §128): permissionless
    /// tag 8 of each empty trader (rent to owner) and of the vault LP ([3] = registry), then
    /// Resolved tag 78. Returns the 78 result.
    fn terminal_cleanup(&mut self, traders: &[(Pubkey, Pubkey)]) -> Result<u64, String> {
        for &(tp, owner) in traders {
            let r = self.close_portfolio_permissionless(tp, owner);
            eprintln!("   tag8 trader (permissionless) -> {:?}", r.as_ref().map_err(|e| code(e)));
        }
        let (lp, reg) = (self.lp, self.registry);
        let r = self.close_portfolio_permissionless(lp, reg);
        eprintln!("   tag8 vault LP (permissionless, [3]=registry) -> {:?}", r.as_ref().map_err(|e| code(e)));
        let r78 = self.crank_fees_78();
        eprintln!("   resolved tag78 -> {:?}", r78.as_ref().map_err(|e| code(e)));
        r78
    }

    /// 98 VaultLpRecall (permissionless), into `target_domain`.
    fn recall_to(&mut self, amount: u128, target_domain: u16) -> Result<u64, String> {
        let cranker = Keypair::new();
        self.env.ensure_signer_account(cranker.pubkey());
        let (own, sib) = if target_domain == 0 { (self.ledger0, self.ledger1) } else { (self.ledger1, self.ledger0) };
        let metas = vec![
            AccountMeta::new(cranker.pubkey(), true), AccountMeta::new(self.env.market, false), AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.state_pda, false), AccountMeta::new(self.lp, false), AccountMeta::new(own, false), AccountMeta::new(sib, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        let mut b = vec![98u8];
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&target_domain.to_le_bytes());
        self.send_raw(b, metas, &[&cranker])
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

    /// Same, with the taker's signed fee consent (>= the market base fee).
    fn trade_vs_lp_fee(&mut self, taker: &Keypair, tp: Pubkey, size_q: i128, fee_bps: u64) -> Result<u64, String> {
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
        let (ds, da, db) = TRADE_ID_BUMP.with(|c| c.replace((0, 0, 0)));
        let (aep, bseq, bep) = (aep + da, bseq + ds, bep + db);
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
                fee_bps,
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

thread_local! { static TL_IM: std::cell::Cell<u64> = std::cell::Cell::new(10_000); }
thread_local! { static C7_STOP_AT_PENDING: std::cell::Cell<bool> = std::cell::Cell::new(false); }
/// Race windows: stop BEFORE the first vault-LP crank (loss unrealised on the LP).
thread_local! { static C7_STOP_BEFORE_LP_CRANK: std::cell::Cell<bool> = std::cell::Cell::new(false); }
/// Put both C-7 seniors in domain 0 (isolates race properties from the per-domain skew).
/// With C7_SINGLE_DOMAIN, skip the 1,000-atom d1 dust deposit that creates the d1 ledger.
thread_local! { static C7_NO_D1_LEDGER: std::cell::Cell<bool> = std::cell::Cell::new(false); }
thread_local! { static C7_SINGLE_DOMAIN: std::cell::Cell<bool> = std::cell::Cell::new(false); }
/// Funding on the TRUMP-param market (max_abs_funding_e9_per_slot); 0 = seed default (off).
thread_local! { static TL_FUNDING: std::cell::Cell<u64> = std::cell::Cell::new(0); }
/// Reuse this LP-share ATA for the next deposits (one wallet holding both domains' shares).
thread_local! { static FORCE_SHARE_ATA: std::cell::Cell<Option<Pubkey>> = std::cell::Cell::new(None); }
/// C-7 variant: ONE senior wallet deposits into BOTH domains (rehearse.sh's seed senior).
thread_local! { static C7_ONE_SENIOR: std::cell::Cell<bool> = std::cell::Cell::new(false); }
/// C-7 variant: configure permissionless stale resolve (rehearsal: 216,000 slots) and resolve by tag 39.
thread_local! { static C7_STALE_RESOLVE: std::cell::Cell<u64> = std::cell::Cell::new(0); }
/// Earn redemption cooldown for CreateLpVault (default 0).
thread_local! { static TL_COOLDOWN: std::cell::Cell<u64> = std::cell::Cell::new(0); }
thread_local! { static TL_FEE_SHARE: std::cell::Cell<Option<u16>> = std::cell::Cell::new(None); }
fn market_params() -> V16CuMarketParams {
    let im = TL_IM.with(|c| c.get());
    if im == 1_000 {
        // Rehearsal-22 TRUMP seed (~/wt/ops-p0a-kit/relaunch/newmarkets-v18.3.ts MARKET_PARAMS +
        // marginParamsFor("TRUMP")), atom amounts scaled 1/1000 like every other amount here.
        return V16CuMarketParams {
            max_portfolio_assets: 1,
            h_min: 1_000,
            h_max: 100_000,
            initial_price: PRICE,
            min_nonzero_mm_req: 1_000,
            min_nonzero_im_req: 2_000,
            maintenance_margin_bps: 600,
            initial_margin_bps: 1_000,
            max_trading_fee_bps: 100,
            trade_fee_base_bps: 30,
            liquidation_fee_bps: 50,
            liquidation_fee_cap: 10_000_000,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 1,
            max_accrual_dt_slots: 500,
            max_abs_funding_e9_per_slot: TL_FUNDING.with(|c| c.get()),
            min_funding_lifetime_slots: 500,
            max_account_b_settlement_chunks: 10,
            max_bankrupt_close_chunks: 10,
            max_bankrupt_close_lifetime_slots: 500,
            // rehearse.sh seeds the h-lock market with SEED_PUBLIC_B_CHUNK_ATOMS=1_000_000 (HLOCK_B_CHUNK).
            public_b_chunk_atoms: 1_000,
            maintenance_fee_per_slot: 0,
        };
    }
    if im >= 10_000 {
        V16CuMarketParams { initial_price: PRICE, ..V16CuMarketParams::default() }
    } else {
        V16CuMarketParams {
            h_max: 50,
            initial_price: PRICE,
            min_nonzero_mm_req: 599,
            min_nonzero_im_req: 600,
            maintenance_margin_bps: im / 2,
            initial_margin_bps: im,
            liquidation_fee_bps: 0,
            liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
            max_price_move_bps_per_slot: 20,
            max_accrual_dt_slots: 20,
            max_abs_funding_e9_per_slot: 1_000,
            min_funding_lifetime_slots: 10_000_000,
            ..V16CuMarketParams::default()
        }
    }
}

impl P3 {
    /// 75 into an explicit domain (0 or 1).
    fn earn_deposit_domain(&mut self, who: &Keypair, amount: u64, bound: bool, domain: u16) -> Result<Pubkey, String> {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self.lp_share_ata(who.pubkey());
        let src = self.token(who.pubkey(), amount);
        // [7] is always the registry domain's ledger (0), [10] the sibling (1); `domain` routes.
        let (own, sib) = (self.ledger0, self.ledger1);
        let mut metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(ata, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new(own, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(sib, false),
        ];
        if bound {
            metas.push(AccountMeta::new(self.state_pda, false));
            metas.push(AccountMeta::new(self.lp, false));
        }
        self.send(ProgInstruction::DepositToLpVault { amount: amount as u128, domain }, metas, &[who]).map(|_| ata)
    }

    fn ledger(&self, d: u16) -> Option<state::BackingDomainLedgerAccountV16> {
        let k = if d == 0 { self.ledger0 } else { self.ledger1 };
        self.env.svm.get_account(&k).and_then(|a| state::read_backing_domain_ledger(&a.data).ok())
    }

    /// Per-domain (principal, loss, recovery, unavailable) and physical fresh backing.
    fn domains(&self) -> [(u128, u128, u128, u128, u128); 2] {
        let (_, g) = self.env.market_state();
        let mut out = [(0, 0, 0, 0, 0); 2];
        for d in 0..2u16 {
            let l = self.ledger(d);
            let phys = g.source_backing_buckets[d as usize].fresh_unliened_backing_num / percolator::BOUND_SCALE;
            out[d as usize] = match l {
                Some(l) => (l.total_principal_atoms, l.cumulative_loss_atoms, l.cumulative_recovery_atoms, l.last_observed_unavailable_principal_atoms, phys),
                None => (0, 0, 0, 0, phys),
            };
        }
        out
    }

    /// Floored-per-domain NAV (the security finding's formula) and the true cover
    /// min(floored NAV, physical). Impairment_d = unavailable_d (booked loss not yet recovered).
    fn cover(&self) -> (u128, u128, u128) {
        let d = self.domains();
        let floored: u128 = d.iter().map(|x| x.0.saturating_sub(x.3)).sum();
        let physical: u128 = d.iter().map(|x| x.4).sum();
        (floored, physical, floored.min(physical))
    }

    fn pos(&self, p: Pubkey) -> i128 {
        self.env.portfolio_state(p).legs.iter().find(|l| l.active && l.asset_index == 0).map(|l| l.basis_pos_q).unwrap_or(0)
    }

    fn catch_up(&mut self, ports: &[Pubkey], rounds: usize) {
        let mark = MARK.with(|c| c.get());
        for _ in 0..rounds {
            let s = self.slot() + 20;
            self.env.svm.warp_to_slot(s);
            if self.env.market_state().1.mode == percolator::MarketModeV16::Live {
                self.env.push_auth_mark_for_asset_as_admin(0, s, mark);
            }
            for p in ports {
                let _ = self.crank(*p);
            }
        }
    }

    fn registry_shares(&self) -> u128 {
        self.env.svm.get_account(&self.registry).and_then(|a| state::read_lp_vault_registry(&a.data).ok()).map_or(0, |r| r.total_lp_shares_outstanding)
    }
}

const U: i128 = POS_SCALE as i128;
thread_local! { static MARK: std::cell::Cell<u64> = std::cell::Cell::new(PRICE); }

thread_local! { static Q1_CLOSE: std::cell::Cell<(u128, i128)> = std::cell::Cell::new((0, 0)); }
/// (capital, pnl) of the q1 trader right after its close, before any ConvertReleasedPnl.
fn q1_close_snapshot() -> (u128, i128) { Q1_CLOSE.with(|c| c.get()) }

/// Builds the Q1 cross-domain state with REAL flows: seniors in BOTH domains (tag 75 domain
/// field), a small junior, then a trader win against the vault LP large enough to exceed the
/// junior so the loss is realised against a backing pot. Returns the world + senior ATAs.
fn q1_world(d0: u64, d1: u64, junior: u64, up_pushes: usize) -> (P3, Vec<(Keypair, Pubkey)>, (Keypair, Pubkey)) {
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    let a0 = w.earn_deposit_domain(&s0, d0, false, 0).expect("75 senior domain 0");
    let a1 = w.earn_deposit_domain(&s1, d1, false, 1).expect("75 senior domain 1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).unwrap_or_else(|e| panic!("99: {e}"));
    w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96: {e}"));
    let (t, tp) = w.trader(50_000_000);
    let r = w.trade_vs_lp(&t, tp, 3 * U);
    eprintln!("Q1 open long 3 vs vault LP -> {:?} pos {}", r.as_ref().map_err(|e| code(e)), w.pos(tp));
    let lp = w.lp;
    MARK.with(|c| c.set(PRICE));
    for _ in 0..up_pushes {
        let m = MARK.with(|c| c.get()) * 124 / 100;
        MARK.with(|c| c.set(m));
        w.push(m);
        w.catch_up(&[tp, lp], 30);
        let g = w.env.market_state().1;
        let t_ = w.env.portfolio_state(tp);
        eprintln!("   push -> eff {} tgt {} | trader pos {} cap {} pnl {} | lp pos {}", g.assets[0].effective_price, g.assets[0].raw_oracle_target_price, w.pos(tp), t_.capital, t_.pnl, w.pos(lp));
    }
    // trader realises: close (retry while lagged)
    for _ in 0..8 {
        let r = w.trade_vs_lp(&t, tp, -w.pos(tp));
        eprintln!("   close -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() { break; }
        w.catch_up(&[tp, lp], 5);
    }
    w.catch_up(&[tp, lp], 5);
    // Snapshot what the winner is OWED at the close, BEFORE any conversion: a build that
    // converts in full leaves pnl = 0 afterwards, so "owed" must not be read after this point.
    {
        let t_ = w.env.portfolio_state(tp);
        Q1_CLOSE.with(|c| c.set((t_.capital, t_.pnl)));
    }
    // The winner realises its PnL (ConvertReleasedPnl, owner-signed) so the LP's loss is paid
    // out of backing; the LP's negative PnL is settled by cranks.
    for _ in 0..6 {
        let tpnl = w.env.portfolio_state(tp).pnl;
        if tpnl > 0 {
            let (pid, _, pep) = w.env.portfolio_identity(tp);
            let m = w.env.market;
            let r = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: tpnl as u128 },
                vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[&t]);
            eprintln!("   trader convert {tpnl} -> {:?}", r.as_ref().map_err(|e| code(e)));
        }
        w.catch_up(&[tp, lp], std::env::var("Q1_WAIT").ok().and_then(|v| v.parse().ok()).unwrap_or(10));
        let s_ = w.slot() + 1;
        w.env.svm.warp_to_slot(s_);
        let rl = w.crank(lp);
        let rt = w.crank(tp);
        eprintln!("   crank lp -> {:?} trader -> {:?}", rl.as_ref().map_err(|e| code(e)), rt.as_ref().map_err(|e| code(e)));
    }
    let t_ = w.env.portfolio_state(tp);
    let g = w.env.market_state().1;
    let sc: Vec<_> = g.source_credit.iter().take(2).map(|c| (c.credit_rate_num, c.positive_claim_bound_num / percolator::BOUND_SCALE, c.fresh_reserved_backing_num / percolator::BOUND_SCALE, c.spent_backing_num / percolator::BOUND_SCALE)).collect();
    eprintln!("   trader after: cap {} pnl {} reserved {} | hlock {} stress {} loss_stale {} b_stale {} neg {} | sc {:?} | buckets {:?} | a {}/{}", t_.capital, t_.pnl, t_.reserved_pnl, g.bankruptcy_hlock_active, g.threshold_stress_active, g.loss_stale_active, g.b_stale_account_count, g.negative_pnl_account_count, sc,
        g.source_backing_buckets.iter().take(2).map(|b| (b.status, b.fresh_unliened_backing_num / percolator::BOUND_SCALE, b.valid_liened_backing_num / percolator::BOUND_SCALE)).collect::<Vec<_>>(), g.assets[0].a_long, g.assets[0].a_short);
    (w, vec![(s0, a0), (s1, a1)], (t, tp))
}

fn q1_report(w: &P3, label: &str) {
    let d = w.domains();
    let (floored, physical, cover) = w.cover();
    let lp = w.env.svm.get_account(&w.lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.legs.iter().filter(|l| l.active).count()));
    eprintln!("Q1[{label}] C {} | d0 (principal, loss, recov, unavail, phys) {:?} | d1 {:?} | floored NAV {floored} physical {physical} cover {cover} | LP {:?} | vault tok {}",
        w.c(), d[0], d[1], lp, w.tok(&w.env.vault));
}

/// Probe: print the cross-domain state reached by real flows (no assertion beyond vacuity).
#[test]
#[ignore]
fn q1_probe_cross_domain_state() {
    for (d0, d1, j, n) in [(9_000_000u64, 1_000_000u64, 1_000_000u64, 6usize), (1_000_000, 9_000_000, 1_000_000, 6)] {
        let (w, _, _) = q1_world(d0, d1, j, n);
        q1_report(&w, &format!("d0 {d0} d1 {d1} junior {j} pushes {n}"));
    }
}

// ─────────────────────────────── F14-Q1 (injected) ───────────────────────────────
// No real flow reached "one domain's net impairment > its principal while the other is
// positive" within the 1× vault-LP cap (a +264% move bankrupts the LP but the market h-locks
// before the winner's claim consumes backing; see q1_probe). So the state is INJECTED,
// consistently across the engine header (bucket fresh backing, header fresh total, per-domain
// fresh reservation, c_tot) and BOTH domain ledgers:
//   seniors: 9,000,000 routed to domain 0, 1,000,000 to domain 1 (C = 10,000,000); junior 1,000,000.
//   A 3,000,000 loss is booked to domain 1's ledger (net impairment 3M > principal 1M), while
//   physically it drained domain 1's pot (1M) AND 2M of domain 0's pot (cross-domain). Domain 0's
//   ledger observed the 2M as unavailable principal but booked no loss. The 3M went to a winning
//   trader's capital (c_tot += 3M; vault tokens unchanged).
//   floored NAV = (9M − 0) + max(0, 1M − 3M) = 9,000,000; physical = 7M + 0 = 7,000,000.
//   cover = min(floored, physical) = 7,000,000.

const BS: u128 = percolator::BOUND_SCALE;

impl P3 {
    fn write_ledger(&mut self, d: u16, f: impl FnOnce(&mut state::BackingDomainLedgerAccountV16)) {
        let k = if d == 0 { self.ledger0 } else { self.ledger1 };
        let mut a = self.env.svm.get_account(&k).expect("ledger exists");
        let mut l = state::read_backing_domain_ledger(&a.data).expect("ledger");
        f(&mut l);
        let hl = percolator_prog::constants::HEADER_LEN;
        let n = core::mem::size_of::<state::BackingDomainLedgerAccountV16>();
        a.data[hl..hl + n].copy_from_slice(bytemuck::bytes_of(&l));
        self.env.svm.set_account(k, a).unwrap();
    }

    fn q1_inject(&mut self, winner: Pubkey) {
        let l0 = self.ledger(0).expect("ledger0");
        let l1 = self.ledger(1).expect("ledger1");
        assert_eq!((l0.total_principal_atoms, l1.total_principal_atoms), (9_000_000, 1_000_000), "vacuity: senior principal per domain");
        // engine header: pots 9M/1M -> 7M/0M, header fresh total -3M, per-domain reservation.
        let mut acct = self.env.svm.get_account(&self.env.market).unwrap();
        let (cfg, mut g) = state::read_market(&acct.data).unwrap();
        let f0 = g.source_backing_buckets[0].fresh_unliened_backing_num;
        let f1 = g.source_backing_buckets[1].fresh_unliened_backing_num;
        assert_eq!((f0 / BS, f1 / BS), (9_000_000, 1_000_000), "vacuity: pots before injection");
        eprintln!("Q1 pre-inject: fresh_total {} sc0 {:?} sc1 {:?} b0 {:?} b1 {:?} c_tot {} vault {}", g.source_fresh_backing_total_num / BS,
            (g.source_credit[0].fresh_reserved_backing_num / BS, g.source_credit[0].spent_backing_num / BS, g.source_credit[0].provider_receivable_num / BS),
            (g.source_credit[1].fresh_reserved_backing_num / BS, g.source_credit[1].spent_backing_num / BS, g.source_credit[1].provider_receivable_num / BS),
            (g.source_backing_buckets[0].status, g.source_backing_buckets[0].valid_liened_backing_num / BS, g.source_backing_buckets[0].consumed_liened_backing_num / BS),
            (g.source_backing_buckets[1].status, g.source_backing_buckets[1].valid_liened_backing_num / BS, g.source_backing_buckets[1].consumed_liened_backing_num / BS), g.c_tot, g.vault);
        // Loss realised as CONSUMED liened backing on domain 1 (3M, the engine's unavailable-
        // principal measure = consumed + impaired liened), while physically 1M came out of domain
        // 1's pot and 2M out of domain 0's pot (cross-domain draw). Domain 0's bucket shows no
        // consumed lien, so its ledger books no loss.
        g.source_backing_buckets[0].fresh_unliened_backing_num = f0 - 2_000_000 * BS;
        g.source_backing_buckets[1].fresh_unliened_backing_num = f1 - 999_999 * BS; // 1 atom left (Fresh bucket)
        g.source_backing_buckets[1].consumed_liened_backing_num += 3_000_000 * BS;
        g.source_fresh_backing_total_num -= 2_999_999 * BS;
        g.source_credit[0].fresh_reserved_backing_num -= 2_000_000 * BS;
        g.source_credit[1].fresh_reserved_backing_num -= 999_999 * BS;
        g.source_credit[1].spent_backing_num += 3_000_000 * BS;
        g.c_tot += 2_999_999;
        let mut pa = self.env.svm.get_account(&winner).unwrap();
        let mut p = state::read_portfolio(&pa.data).unwrap();
        p.capital += 2_999_999;
        state::write_portfolio(&mut pa.data, &p).unwrap();
        state::write_market(&mut acct.data, &cfg, &g).unwrap();
        self.env.svm.set_account(self.env.market, acct).unwrap();
        self.env.svm.set_account(winner, pa).unwrap();
        // ledgers: d1 books the whole 3M loss (> its 1M principal); d0 observed 2M unavailable, no loss.
        // sync-consistent: d1 observed unavailable 3M and booked it as loss; d0 observed nothing.
        self.write_ledger(1, |l| { l.cumulative_loss_atoms += 3_000_000; l.last_observed_unavailable_principal_atoms = 3_000_000; });
    }

    /// Floored NAV exactly as the finding states (impairment = loss − recovery, floored per domain).
    fn q1_nav(&self) -> (u128, u128, u128) {
        let mut floored = 0u128;
        for d in 0..2u16 {
            let l = self.ledger(d).unwrap();
            let imp = l.cumulative_loss_atoms.saturating_sub(l.cumulative_recovery_atoms);
            floored += l.total_principal_atoms.saturating_sub(imp);
        }
        let (_, g) = self.env.market_state();
        let physical: u128 = (0..2).map(|d| g.source_backing_buckets[d].fresh_unliened_backing_num / BS).sum();
        (floored, physical, floored.min(physical))
    }

    fn execute_redeem_domain(&mut self, who: &Keypair, domain: u16) -> (Pubkey, Result<u64, String>) {
        let red = state::derive_lp_redemption(&self.env.program_id, &self.registry, &who.pubkey()).0;
        let dest = self.token(who.pubkey(), 0);
        let payer = self.env.payer.pubkey();
        let metas = vec![
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
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(self.lp, false),
        ];
        let r = self.send(ProgInstruction::ExecuteRedemption { domain }, metas, &[]);
        (dest, r)
    }

    fn live_release_102(&mut self, junior: &Keypair, amount: u128) -> Result<u64, String> {
        let mut b = amount.to_le_bytes().to_vec();
        b.extend_from_slice(&0u16.to_le_bytes());
        let metas = vec![
            AccountMeta::new(junior.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(self.lp, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
        ];
        self.send_raw(raw(102, &b), metas, &[junior])
    }
}

/// Bound world with seniors 9M (domain 0) + 1M (domain 1), junior 1M, and a trader portfolio
/// that receives the injected win. Returns (world, [(s0, ata0), (s1, ata1)], winner).
fn q1_injected_world() -> (P3, Vec<(Keypair, Pubkey)>, Pubkey) {
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    let a0 = w.earn_deposit_domain(&s0, 9_000_000, false, 0).expect("75 senior d0");
    let a1 = w.earn_deposit_domain(&s1, 1_000_000, false, 1).expect("75 senior d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).unwrap_or_else(|e| panic!("99: {e}"));
    w.junior_deposit(&admin, 1_000_000).unwrap_or_else(|e| panic!("96: {e}"));
    let (_t, tp) = w.trader(1_000_000);
    assert_eq!(w.c(), 10_000_000, "vacuity: C seeded to combined NAV");
    if std::env::var("Q1_NO_INJECT").is_err() {
        w.q1_inject(tp);
    }
    let (floored, physical, cover) = w.q1_nav();
    eprintln!("Q1 injected: floored NAV {floored} physical {physical} cover {cover} C {}", w.c());
    assert!(std::env::var("Q1_NO_INJECT").is_ok() || floored > physical, "vacuity: the injected state must overstate (floored {floored} > physical {physical})");
    (w, vec![(s0, a0), (s1, a1)], tp)
}

fn q1_prep(w: &mut P3) {
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    w.env.push_auth_mark_for_asset_as_admin(0, s, PRICE);
    let lp = w.lp;
    let _ = w.crank(lp);
    let _ = w.crank_fees_78();
}

/// 77: seniors are paid pro rata to cover = min(floored NAV, physical); the FIRST redeemer must
/// not be paid out of phantom (floored-only) NAV and the LAST must not be shorted.
/// IGNORED: the injected cross-domain state is not yet fully engine-consistent (75 and Live 102
/// refuse with 40, 77 aborts ProgramFailedToComplete on 31efd250), so a pass/fail here does
/// not yet speak to F14-Q1. Needs a builder-supplied real flow or a consistent injector.
#[test]
#[ignore]
fn q1_injected_77_senior_redeem_pays_at_cover_not_floored_nav() {
    let (mut w, seniors, _) = q1_injected_world();
    let (floored, physical, cover) = w.q1_nav();
    let c = w.c();
    let s_total = w.registry_shares();
    let per = cover.min(c);
    let mut paid = Vec::new();
    for (i, (who, ata)) in seniors.iter().enumerate() {
        let who = who.insecure_clone();
        let shares = w.tok(ata) as u128;
        q1_prep(&mut w);
        w.request_redeem(&who, *ata, shares).expect("76 request");
        q1_prep(&mut w);
        let dom = i as u16;
        let (dest, r) = w.execute_redeem_domain(&who, dom);
        let (dest, r) = if r.is_err() { w.execute_redeem_domain(&who, 1 - dom) } else { (dest, r) };
        let got = w.tok(&dest) as u128;
        if let Err(e) = &r { eprintln!("   77 err: {}", e.split("err: ").nth(1).unwrap_or("").chars().take(120).collect::<String>()); }
        let fair = shares * per / s_total;
        eprintln!("Q1-77 senior {i}: shares {shares}/{s_total} -> {:?} paid {got}; fair at cover {fair}; at floored NAV {}", r.as_ref().map_err(|e| code(e)), shares * floored.min(c) / s_total);
        paid.push((got, fair, r.is_ok()));
    }
    let (g0, f0, _) = paid[0];
    assert!(g0 <= f0 + 2, "Q1: first senior paid {g0} > its share of cover {f0} (paid from phantom floored NAV; floored {floored} physical {physical})");
    let (g1, f1, ok1) = paid[1];
    assert!(ok1 && g1 + 2 >= f1, "Q1: later senior shorted: paid {g1} (ok={ok1}) < fair share of cover {f1}");
}

/// 75: a new depositor must be priced at cover, not the overstated floored NAV (no over-payment).
/// IGNORED: the injected cross-domain state is not yet fully engine-consistent (75 and Live 102
/// refuse with 40, 77 aborts ProgramFailedToComplete on 31efd250), so a pass/fail here does
/// not yet speak to F14-Q1. Needs a builder-supplied real flow or a consistent injector.
#[test]
#[ignore]
fn q1_injected_75_deposit_is_priced_at_cover_or_refused() {
    let (mut w, _, _) = q1_injected_world();
    let (floored, physical, cover) = w.q1_nav();
    let c = w.c();
    let s_total = w.registry_shares();
    let who = Keypair::new();
    q1_prep(&mut w);
    let r = w.earn_deposit_domain(&who, 1_000_000, true, 0);
    match r {
        Err(e) => eprintln!("Q1-75 deposit refused -> {:?} (acceptable)", code(&e)),
        Ok(ata) => {
            let minted = w.tok(&ata) as u128;
            let fair = 1_000_000u128 * s_total / cover.min(c);
            let at_floored = 1_000_000u128 * s_total / floored.min(c);
            eprintln!("Q1-75 deposit 1,000,000 minted {minted}; fair at cover {fair}; at floored NAV {at_floored} (floored {floored} physical {physical})");
            assert!(minted + 2 >= fair, "Q1: depositor priced at the overstated NAV: minted {minted} < fair {fair} (value transferred to existing seniors)");
        }
    }
}

/// 97 and Live 102: the junior can take at most (cover − C)+ (= 0 here) while seniors are impaired.
#[test]
fn q1_injected_97_and_live_102_bounded_by_cover_minus_c() {
    let (mut w, _, _) = q1_injected_world();
    let (_, _, cover) = w.q1_nav();
    let bound = cover.saturating_sub(w.c());
    let admin = w.env.admin.insecure_clone();
    q1_prep(&mut w);
    let vault0 = w.tok(&w.env.vault) as u128;
    for amt in [1u128, 100_000, 500_000, 1_000_000] {
        let (dest, r) = w.junior_withdraw(&admin, admin.pubkey(), amt);
        let got = w.tok(&dest) as u128;
        eprintln!("Q1-97 junior withdraw {amt} -> {:?} got {got} (bound {bound})", r.as_ref().map_err(|e| code(e)));
        assert!(got <= bound, "Q1: junior withdrew {got} > (cover − C)+ = {bound}");
    }
    let lpcap0 = w.env.portfolio_state(w.lp).capital;
    for amt in [1u128, 100_000, 1_000_000] {
        let r = w.live_release_102(&admin, amt);
        eprintln!("Q1-102 live release {amt} -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() {
            assert!(amt <= bound, "Q1: Live 102 released {amt} of backing > (cover − C)+ = {bound}");
        }
    }
    let _ = lpcap0;
    assert_eq!(w.tok(&w.env.vault) as u128, vault0, "no SPL left the vault via 97/102");
}

// ─────────────────────────────── F14-Q2 ───────────────────────────────

fn market_with_capacity(cap: u16) -> P3 {
    CAP.with(|c| c.set(cap));
    let w = P3::new();
    CAP.with(|c| c.set(1));
    w
}
thread_local! { static CAP: std::cell::Cell<u16> = std::cell::Cell::new(1); }

/// Positive control: a single-asset market binds.
#[test]
fn q2_control_single_asset_market_binds() {
    let mut w = P3::new();
    w.create_vault();
    let s = Keypair::new();
    w.earn_deposit_domain(&s, 1_000_000, false, 0).expect("75");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).expect("94 binds on a single-asset market");
}

/// 94 must refuse on a multi-asset market (capacity 2), with no state change.
#[test]
fn q2_tag94_refuses_bind_on_multi_asset_market() {
    let mut w = market_with_capacity(2);
    w.create_vault();
    let s = Keypair::new();
    w.earn_deposit_domain(&s, 1_000_000, false, 0).expect("75");
    let admin = w.env.admin.insecure_clone();
    let st0 = w.env.svm.get_account(&w.state_pda).map(|a| a.data);
    let m0 = w.env.svm.get_account(&w.env.market).unwrap().data;
    let r = w.init_vault_lp(&admin, 1_000);
    eprintln!("Q2 94 on capacity-2 market -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert!(r.is_err(), "Q2: tag 94 must refuse a vault-LP bind on a multi-asset market");
    assert_eq!(w.env.svm.get_account(&w.state_pda).map(|a| a.data), st0, "no vault_lp_state created");
    assert_eq!(w.env.svm.get_account(&w.env.market).unwrap().data, m0, "market unchanged");
}

/// Enabling a second asset on a market that already has a bound vault must be refused, on every
/// path the wrapper exposes (activate a fresh slot; permissionless append/activation).
#[test]
fn q2_second_asset_activation_refused_on_bound_market() {
    // Bind on capacity-1, then try to grow the market to a second asset.
    let mut w = P3::new();
    w.create_vault();
    let s = Keypair::new();
    w.earn_deposit_domain(&s, 1_000_000, false, 0).expect("75");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).expect("94 single asset");
    // Path 1: grow the account (capacity 2) and activate slot 1 as marketauth.
    w.env.grow_market_capacity_for_test(2);
    let m0 = w.env.svm.get_account(&w.env.market).unwrap().data;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let slot = w.slot() + 1;
        w.env.activate_asset(1, slot, PRICE)
    }));
    eprintln!("Q2 activate asset 1 on bound market -> {}", if r.is_ok() { "SUCCEEDED" } else { "refused" });
    assert!(r.is_err(), "Q2: activating a second asset on a market with a bound vault must be refused");
    assert_eq!(w.env.svm.get_account(&w.env.market).unwrap().data, m0, "market unchanged");
    // Path 2: permissionless append/activation (market-init fee policy on, fee paid).
    let r2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = w.env.update_market_init_fee_policy_with_cu(1);
        let creator = Keypair::new();
        let k = creator.pubkey();
        let slot = w.slot() + 2;
        w.env.activate_permissionless_asset_with_fee(&creator, 1, slot, PRICE, k, k, k, k, 1)
    }));
    eprintln!("Q2 permissionless activation on bound market -> {}", if r2.is_ok() { "SUCCEEDED" } else { "refused" });
    assert!(r2.is_err(), "Q2: permissionless activation of a second asset on a bound market must be refused");
}

// ─────────────── H-lock liveness candidate (coordinator follow-up) ───────────────
// After a vault-LP loss larger than the junior (+264%), the market sat h-locked with
// loss_stale and the winner's conversion returned 21 for >1,200 slots. Try every PERMISSIONLESS
// progress path in escalating phases and record which (if any) clears it within N slots.
#[test]
#[ignore]
fn hlock_after_vault_lp_bankruptcy_permissionless_exits() {
    let (mut w, _seniors, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let lp = w.lp;
    let m = w.env.market;
    let status = |w: &P3| {
        let g = w.env.market_state().1;
        let tr = w.env.portfolio_state(tp);
        (g.bankruptcy_hlock_active, g.loss_stale_active, g.threshold_stress_active, tr.pnl, tr.capital, g.current_slot)
    };
    let try_convert = |w: &mut P3| -> Option<u32> {
        let pnl = w.env.portfolio_state(tp).pnl;
        if pnl <= 0 { return Some(0); }
        let (pid, _, pep) = w.env.portfolio_identity(tp);
        let r = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[&t]);
        r.err().map(|e| code(&e).unwrap_or(u32::MAX))
    };
    eprintln!("HLOCK start: (hlock, loss_stale, stress, trader pnl, cap, slot) = {:?}; convert -> {:?}", status(&w), try_convert(&mut w));
    {
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let rl = w.crank(lp);
        let rt = w.crank(tp);
        let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok());
        let g = w.env.market_state().1;
        eprintln!("HLOCK diag: crank lp -> {:?}, trader -> {:?}; LP {:?}; eff {} tgt {}; a {}/{} oi {}/{} modes {:?}/{:?}; neg {} b_stale {} stale_cert {}",
            rl.as_ref().map_err(|e| code(e)), rt.as_ref().map_err(|e| code(e)),
            lpp.map(|p| (p.capital, p.pnl, p.legs.iter().filter(|l| l.active).map(|l| l.basis_pos_q).collect::<Vec<_>>(), p.stale_state, p.b_stale_state, p.close_progress)),
            g.assets[0].effective_price, g.assets[0].raw_oracle_target_price, g.assets[0].a_long, g.assets[0].a_short, g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q, g.assets[0].mode_long, g.assets[0].mode_short,
            g.negative_pnl_account_count, g.b_stale_account_count, g.stale_certificate_count);
    }
    let mut log = Vec::new();
    let phases: [(&str, u64); 4] = [("A crank burst (trader+LP every slot)", 2_000), ("B + 45 FinalizeResetSide + 89 Expire each slot", 2_000), ("C keeper refresh: push same mark + crank every 20 slots", 20_000), ("D long wait + crank every 500 slots", 200_000)];
    for (name, n) in phases {
        let step = if name.starts_with('C') { 20 } else if name.starts_with('D') { 500 } else { 1 };
        let mut t0 = 0u64;
        let mut cleared_at = None;
        while t0 < n {
            t0 += step;
            let s = w.slot() + step;
            w.env.svm.warp_to_slot(s);
            if (name.starts_with('C') || name.starts_with('D')) && w.env.market_state().1.mode == percolator::MarketModeV16::Live {
                let mk = MARK.with(|c| c.get());
                w.push(mk);
            }
            let _ = w.crank(lp);
            let _ = w.crank(tp);
            if name.starts_with('B') {
                for side in 0..2u8 { let _ = w.send(ProgInstruction::FinalizeResetSide { asset_index: 0, side }, vec![AccountMeta::new(m, false)], &[]); }
                for d in 0..2u16 { let _ = w.send(ProgInstruction::ExpireBackingBucket { domain: d }, vec![AccountMeta::new(m, false)], &[]); }
            }
            let st = status(&w);
            if (!st.0 && !st.1) || w.env.market_state().1.mode == percolator::MarketModeV16::Resolved {
                cleared_at = Some(t0);
                break;
            }
        }
        let conv = try_convert(&mut w);
        let line = format!("phase {name}: cleared {:?} (slots), status {:?}, convert -> {:?}", cleared_at, status(&w), conv);
        eprintln!("HLOCK {line}");
        log.push(line);
        if cleared_at.is_some() && conv.map_or(true, |c| c == 0) {
            break;
        }
    }
    let st = status(&w);
    eprintln!("HLOCK final: {:?}", st);
    if (st.0 || st.1) && w.env.market_state().1.mode != percolator::MarketModeV16::Resolved {
        log.push("privileged probe used".to_string());
        // Privileged escape probe (NOT counted as a permissionless exit): admin ResolveMarket.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
        let g = w.env.market_state().1;
        eprintln!("HLOCK privileged probe: admin ResolveMarket -> {}; mode {:?} hlock {}", if r.is_ok() { "ok" } else { "FAILED" }, g.mode, g.bankruptcy_hlock_active);
    }
    // Review of the P3 builder's note (credit: Anvil, indep-f14q-anvil-hlock.patch): the engine
    // keeps the h-lock FLAG set in Resolved by design, so the liveness criterion is PROGRESS —
    // either the h-lock clears in Live, or the market reaches Resolved WITHOUT any privileged
    // instruction (the payout side is asserted in hlock_exit_via_recovery_everyone_paid).
    let resolved_permissionlessly = w.env.market_state().1.mode == percolator::MarketModeV16::Resolved && !log.iter().any(|l| l.contains("privileged"));
    assert!((!st.0 && !st.1) || resolved_permissionlessly, "no permissionless progress out of the h-lock: {log:?}");
}

/// H-lock exit on the fixed head (test by the P3 builder, Anvil — indep-f14q-anvil-hlock.patch;
/// reviewed and tightened by Sieve: nothing stranded, seniors paid, token totals conserved).
/// Original note:: the expired bankrupt close of the vault LP
/// escalates to Recovery through the permissionless crank (upstream expired-close valve), the
/// Recovery step reaches Resolved, and then every claim is paid permissionlessly: the winner
/// (resolved close), the seniors (77 at min(physical, C)), the junior (102, nothing left).
#[test]
#[ignore]
fn hlock_exit_via_recovery_everyone_paid() {
    let (mut w, seniors, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let lp = w.lp;
    let v_tokens0 = w.tok(&w.env.vault) as u128;
    let mut modes = vec![];
    for _ in 0..40 {
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
        let _ = w.crank(tp);
        let m = w.env.market_state().1.mode;
        if modes.last() != Some(&m) { modes.push(m); }
        if m == percolator::MarketModeV16::Resolved { break; }
    }
    eprintln!("ANVIL hlock modes: {modes:?}");
    assert_eq!(w.env.market_state().1.mode, percolator::MarketModeV16::Resolved, "reached Resolved permissionlessly");
    // Winner: permissionless resolved close (pays the owner) — loop, progress-only first.
    let t_cap0 = w.env.portfolio_state(tp).capital;
    let t_pnl0 = w.env.portfolio_state(tp).pnl;
    let mut paid_t = 0u128;
    for _ in 0..6 {
        let jo = w.env.admin.pubkey();
        let (_, r0) = w.settle_resolved(jo, 0);
        let (_, r1) = w.settle_resolved(jo, 1);
        let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok());
        let ps = w.env.portfolio_state(tp);
        eprintln!("   101 -> {:?}/{:?}; LP {:?}; winner cap {} pnl {} receipt {:?}", r0.as_ref().map_err(|e| code(e)), r1.as_ref().map_err(|e| code(e)),
            lpp.map(|p| (p.capital, p.pnl, p.close_progress.residual_remaining, p.close_progress.active)), ps.capital, ps.pnl, (ps.resolved_payout_receipt.present, ps.resolved_payout_receipt.finalized));
        let dest = w.token(t.pubkey(), 0);
        let payer = w.env.payer.pubkey();
        let m = w.env.market;
        let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
        let r = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(t.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(tp, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
        let _ = payer;
        paid_t += w.tok(&dest) as u128;
        eprintln!("   winner CloseResolved -> {:?} paid so far {paid_t}", r.as_ref().map_err(|e| code(e)));
        let ps = w.env.portfolio_state(tp);
        if ps.capital == 0 && ps.pnl == 0 { break; }
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
    }
    eprintln!("ANVIL hlock: winner cap0 {t_cap0} pnl0 {t_pnl0} paid {paid_t}; hlock {}", w.env.market_state().1.bankruptcy_hlock_active);
    assert!(paid_t >= t_cap0 as u128, "winner gets at least its capital back");
    let r = w.terminal_cleanup(&[(tp, t.pubkey())]);
    eprintln!("ANVIL hlock terminal cleanup 78 -> {:?}", r.as_ref().map_err(|e| code(e)));
    let mut senior_paid = 0u128;
    for (k, ata) in &seniors {
        let shares = w.tok(ata) as u128;
        if shares == 0 { continue; }
        let _ = w.request_redeem(k, *ata, shares);
        let (mut dest, mut r) = w.execute_redeem(k, true);
        if r.is_err() {
            // the redeemer picks the pot the payout is drawn from; try the sibling pot
            let x = w.execute_redeem_domain(k, 1);
            dest = x.0;
            r = x.1;
        }
        eprintln!("   senior 77 -> {:?}", r.as_ref().map_err(|e| code(e)));
        r.expect("every senior exits");
        senior_paid += w.tok(&dest) as u128;
    }
    let jr = w.env.admin.insecure_clone(); // path A: the junior is the marketauth
    let junior_paid = w.junior_release_resolved(&jr);
    let left = w.tok(&w.env.vault) as u128;
    eprintln!("ANVIL hlock: vault tokens {v_tokens0} -> {left}; winner {paid_t} seniors {senior_paid} junior {junior_paid}");
    // Sieve additions: no value stranded and seniors actually paid.
    assert!(senior_paid > 0, "seniors must be paid after the Recovery exit");
    assert!(left <= 2_000, "value stranded after every exit: {left} atoms left in the vault");
}

// ═════════════ NEW P3 LOSS RULE (user decision 2026-09-30): junior first, then Earn seniors
// pro rata; winners are NEVER haircut. h-lock/bankrupt only once seniors are exhausted. ═════════════

/// Runs the full exit (Live convert+withdraw if possible, else resolve path) and returns
/// (winner_received, senior_paid_per_senior, junior_paid, vault_left).
fn lossrule_exit(w: &mut P3, seniors: &[(Keypair, Pubkey)], t: &Keypair, tp: Pubkey) -> (u128, Vec<u128>, u128, u128) {
    let m = w.env.market;
    let lp = w.lp;
    let mut winner = 0u128;
    // Live: winner converts its whole PnL and withdraws everything.
    for _ in 0..10 {
        let s = w.slot() + 5;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
        let _ = w.crank(tp);
        let pnl = w.env.portfolio_state(tp).pnl;
        if pnl > 0 {
            let (pid, _, pep) = w.env.portfolio_identity(tp);
            let _ = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
                vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[t]);
        }
        if w.env.portfolio_state(tp).pnl <= 0 { break; }
    }
    let cap = w.env.portfolio_state(tp).capital;
    if cap > 0 && w.env.portfolio_state(tp).pnl <= 0 {
        let dest = w.token(t.pubkey(), 0);
        let (pid, seq, _) = w.env.portfolio_identity(tp);
        let r = w.send(ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: cap },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false), AccountMeta::new(dest, false),
                 AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false)], &[t]);
        if r.is_ok() { winner += w.tok(&dest) as u128; }
    }
    eprintln!("lossrule: Live winner received {winner}; trader pnl now {}", w.env.portfolio_state(tp).pnl);
    // Resolve (admin) and finish everyone on the resolved path.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
    let jo = w.env.admin.pubkey();
    for _ in 0..6 {
        let _ = w.settle_resolved(jo, 0);
        let _ = w.settle_resolved(jo, 1);
        let dest = w.token(t.pubkey(), 0);
        let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
        let _ = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(t.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(tp, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
        winner += w.tok(&dest) as u128;
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
    }
    let _ = w.terminal_cleanup(&[(tp, t.pubkey())]);
    let mut per = Vec::new();
    for (k, ata) in seniors {
        let shares = w.tok(ata) as u128;
        if shares == 0 { per.push(0); continue; }
        let _ = w.request_redeem(k, *ata, shares);
        let (mut dest, mut r) = w.execute_redeem(k, true);
        if r.is_err() { let x = w.execute_redeem_domain(k, 1); dest = x.0; r = x.1; }
        per.push(if r.is_ok() { w.tok(&dest) as u128 } else { 0 });
    }
    let jr = w.env.admin.insecure_clone();
    let junior = w.junior_release_resolved(&jr);
    let left = w.tok(&w.env.vault) as u128;
    (winner, per, junior, left)
}

/// Rule 1: a winner is paid IN FULL after a vault-LP loss beyond the junior; seniors absorb
/// exactly the shortfall, pro rata; conservation (<= dust left).
#[test]
fn lossrule_winner_paid_in_full_seniors_absorb_exact_shortfall_pro_rata() {
    let (d0, d1, junior) = (9_000_000u64, 1_000_000u64, 1_000_000u64);
    let (mut w, seniors, (t, tp)) = q1_world(d0, d1, junior, 6);
    // "Owed" is the winner's (capital, pnl) at the close, snapshotted before any conversion.
    let (cap0, pnl0) = { let (c, p) = q1_close_snapshot(); (c, p.max(0) as u128) };
    let t0 = w.env.portfolio_state(tp);
    eprintln!("lossrule: trader now cap {} pnl {} (after q1's conversions)", t0.capital, t0.pnl);
    let lpp = w.env.svm.get_account(&w.lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl));
    let g = w.env.market_state().1;
    eprintln!("lossrule start: trader cap {cap0} pnl {pnl0}; LP {:?}; hlock {} C {}", lpp, g.bankruptcy_hlock_active, w.c());
    assert!(pnl0 > junior as u128, "vacuity: the LP loss must exceed the junior");
    let (winner, per, jr_paid, left) = lossrule_exit(&mut w, &seniors, &t, tp);
    let shortfall = pnl0 - junior as u128;
    let c = (d0 + d1) as u128;
    let expected_total = c - shortfall;
    let senior_total: u128 = per.iter().sum();
    eprintln!("lossrule: winner {winner} (owed {} = cap {cap0} + pnl {pnl0}); seniors {per:?} total {senior_total} (expected {expected_total} = C {c} - shortfall {shortfall}); junior {jr_paid}; left {left}", cap0 + pnl0);
    assert!(winner + 2 >= cap0 + pnl0, "RULE: winners are never haircut: received {winner} < owed {}", cap0 + pnl0);
    assert!(senior_total + 2_000 >= expected_total && senior_total <= expected_total + 2_000, "RULE: seniors absorb exactly the shortfall: {senior_total} vs {expected_total}");
    // pro rata: each senior's loss share proportional to its principal (+-2 atoms rounding, dead shares)
    let shares = [d0 as u128, d1 as u128];
    for (i, p) in per.iter().enumerate() {
        let fair = shares[i] * expected_total / c;
        assert!((*p as i128 - fair as i128).abs() <= 2_000, "RULE: senior {i} paid {p}, pro-rata share {fair}");
    }
    assert_eq!(jr_paid, 0, "junior is wiped first");
    assert!(left <= 2_000, "conservation: {left} left in the vault");
}

/// Rule 2: while seniors still cover the loss, the market must NOT enter bankruptcy h-lock.
/// Then with tiny seniors (loss > junior + seniors) h-lock/bankruptcy is reachable.
#[test]
fn lossrule_hlock_only_after_seniors_exhausted() {
    let (w, _s, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let g = w.env.market_state().1;
    eprintln!("lossrule big seniors: hlock {} loss_stale {}", g.bankruptcy_hlock_active, g.loss_stale_active);
    assert!(!g.bankruptcy_hlock_active, "RULE: seniors (C 10M) cover a ~1.6M shortfall, so no bankruptcy h-lock");
    // Exhausted leg: seniors SMALLER than the junior. The 1x vault-LP cap sizes the position on
    // the junior (a 100k junior allowed only 0.1 unit, a 263,521 loss < J + C = 400k: vacuous),
    // so keep a 1M junior (1 unit, ~2.635M loss) and shrink C to 100k: loss > J + C = 1.1M.
    let (jr2, c2) = (1_000_000u64, 100_000u64);
    let (w2, _s2, (_t2, _tp2)) = q1_world(50_000, 50_000, jr2, 6);
    let g2 = w2.env.market_state().1;
    let pnl = q1_close_snapshot().1;
    eprintln!("lossrule tiny seniors: hlock {} loss_stale {} trader pnl at close {pnl} (J {jr2} + C {c2}) C now {}", g2.bankruptcy_hlock_active, g2.loss_stale_active, w2.c());
    // Vacuity: the loss must exceed junior + seniors for the second leg to mean anything.
    assert!(pnl > (jr2 + c2) as i128, "vacuity: loss {pnl} must exceed junior + seniors {}", jr2 + c2);
    assert!(g2.bankruptcy_hlock_active || g2.loss_stale_active, "RULE: once junior + seniors are exhausted, the bankrupt/h-lock path is reachable");
}

// ═════════════ C-7 (rehearsal-22, real validator): immediate-Recovery wind-down lock ═════════════
// Rehearsal shape (hlock-drill.log): vault LP max leverage 5x (tag 99), small junior vs a big
// senior C, trader opens long vs the LP, then +450 bps pushes with ~524-slot gaps and ONLY the
// TRADER cranked each time (the keeper does not refresh the LP during the move). The LP's whole
// loss (> junior) is realised at once by the first LP crank -> the engine goes straight to
// Recovery (no bankrupt close stays open) -> a stranger crank -> Resolved. Then the documented
// wind-down (101, tag 8, CloseResolved, 78, 76/77, 102) must pay everyone. On the validator it
// returned 21/84 everywhere with 12.3B locked. My earlier LiteSVM probe diverged because
// q1_world cranks the LP after EVERY push (gradual loss -> bankrupt close path, not immediate
// Recovery). This test reproduces the rehearsal ORDER.
/// WIP (does not yet reach the rehearsal state: the vault-LP crank never liquidates in LiteSVM).
/// Precondition-only check for the exhausted leg of `lossrule_hlock_only_after_seniors_exhausted`
/// (runs on any build): the scenario really puts the vault-LP loss above junior + seniors, so
/// that leg can never pass vacuously. No rule assertion here.
#[test]
fn lossrule_exhausted_leg_is_not_vacuous() {
    // LOSSRULE_PROBE="d0,d1,junior" re-sizes the probe (used to check the old 200k/100k/100k shape).
    let v: Vec<u64> = std::env::var("LOSSRULE_PROBE").ok().map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect()).unwrap_or_else(|| vec![50_000, 50_000, 1_000_000]);
    let (jr, c) = (v[2], v[0] + v[1]);
    let (w, _s, (_t, tp)) = q1_world(v[0], v[1], jr, 6);
    let (cap, pnl) = q1_close_snapshot();
    eprintln!("exhausted-leg sizing: trader pos after close {} cap {cap} pnl at close {pnl}; J {jr} C {c}; C now {}", w.pos(tp), w.c());
    assert!(pnl > (jr + c) as i128, "vacuity: loss {pnl} must exceed junior + seniors {}", jr + c);
}

struct C7 { w: P3, admin: Keypair, t: Keypair, tp: Pubkey, seed: Keypair, seedp: Pubkey, s0: Keypair, a0: Pubkey, s1: Keypair, a1: Pubkey, lp: Pubkey, v0: u128, owed: u128, lp_loss_beyond_junior: u128 }

/// The rehearsal-22 state: Recovery reached at the liquidating crank, then Resolved by a stranger.
fn c7_to_resolved() -> C7 { c7_world(5_000_000) }

/// Rehearsal-22 shape with `senior_per_domain` in each of d0/d1; ends in Resolved (via the
/// Recovery valve on the old rule, or an admin resolve when the new senior draw keeps it Live).
fn c7_world(senior_per_domain: u64) -> C7 {
    // Rehearsal-22 TRUMP market params (IM 10% / MM 6%, liq fee 50 bps, move 1 bps/slot,
    // accrual dt 500). The earlier IM-20% variant had max_accrual_dt 20 < every warp, so each
    // crank stopped at the bounded catch-up and never touched the portfolio (the divergence).
    TL_IM.with(|c| c.set(1_000));
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    // rehearse.sh: LP_VAULT_DEPOSIT_PER_DOMAIN = 5e9 (HLOCK_SENIOR_PER_DOMAIN), i.e. C = 1e10 over d0 + d1.
    let a0 = w.earn_deposit_domain(&s0, senior_per_domain, false, 0).expect("75 senior d0");
    let one = C7_ONE_SENIOR.with(|c| c.get());
    let s1 = if one { s0.insecure_clone() } else { Keypair::new() };
    if one { FORCE_SHARE_ATA.with(|c| c.set(Some(a0))); }
    let a1 = w.earn_deposit_domain(&s1, senior_per_domain, false, if C7_SINGLE_DOMAIN.with(|c| c.get()) { 0 } else { 1 }).expect("75 senior d1");
    FORCE_SHARE_ATA.with(|c| c.set(None));
    let stale = C7_STALE_RESOLVE.with(|c| c.get());
    if stale > 0 { w.env.configure_permissionless_resolve_with_cu(stale, stale); } // seed: stale = force-close delay = 216,000
    if C7_SINGLE_DOMAIN.with(|c| c.get()) && !C7_NO_D1_LEDGER.with(|c| c.get()) {
        // A 1,000-atom d1 depositor so the d1 ledger exists (the relaunch seed funds both domains).
        let dust = Keypair::new();
        w.earn_deposit_domain(&dust, 1_000, false, 1).expect("75 dust d1");
    }
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap_or_else(|e| panic!("99 lev 5x: {e}"));
    // (Rehearsal did not set tag 93: at IM 10% the P1 LP cap default k = 1e8/IM = 10x.)
    w.junior_deposit(&admin, 300_000).unwrap_or_else(|e| panic!("96: {e}"));
    let (seed, seedp) = w.trader(500_000); // an unrelated flat trader (rehearsal's seed trader)
    let (t, tp) = w.trader(2_000_000);
    let lp = w.lp;
    let v0 = w.tok(&w.env.vault) as u128;
    // Drill H2: fresh push + crank(LP), then T opens ~$1300 notional long vs the vault LP
    // (1.3 units at mark 1.0 in this 1/1000 scale), as fills of <= 500k each (TradeCpi may clip).
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    w.push(PRICE);
    let _ = w.crank(lp);
    let mut want: i128 = 1_300_000;
    for _ in 0..8 {
        if want <= 0 { break; }
        let before = w.pos(tp);
        let r = w.trade_vs_lp_fee(&t, tp, want.min(500_000), 30); // taker consents to the 30 bps base fee
        if let Err(e) = &r { eprintln!("C7 open fill -> {:?} {}", code(e), &e[e.len().saturating_sub(1500)..]); }
        want -= w.pos(tp) - before;
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
    }
    let opened = w.pos(tp);
    eprintln!("C7 open long vs vault LP: pos {opened}");
    assert!(opened > 0, "vacuity: long opened");
    MARK.with(|c| c.set(PRICE));
    for _ in 0..9 {
        let m = MARK.with(|c| c.get()) * 10_450 / 10_000;
        MARK.with(|c| c.set(m));
        let s = w.slot() + 520;
        w.env.svm.warp_to_slot(s);
        w.push(m);
        let _ = w.crank(tp); // trader only — LP not refreshed during the move
    }
    {
        let g = w.env.market_state().1;
        let tr = w.env.portfolio_state(tp);
        eprintln!("C7 after move: eff {} tgt {} | trader pos {} cap {} pnl {}", g.assets[0].effective_price, g.assets[0].raw_oracle_target_price, w.pos(tp), tr.capital, tr.pnl);
    }
    let mut max_beyond = 0u128;
    let mut stopped = C7_STOP_BEFORE_LP_CRANK.with(|c| c.get());
    for i in 0..(if stopped { 0 } else { 3 }) {
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let r = w.crank(lp);
        let g = w.env.market_state().1;
        let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.legs.iter().filter(|l| l.active).count(), p.close_progress.active));
        if let Some(x) = lpp { if x.0 == 0 && x.1 < 0 { max_beyond = max_beyond.max((-x.1) as u128); } }
        eprintln!("C7 crank(LP) #{i} -> {:?}; mode {:?} eff {} tgt {} LP {:?}", r.as_ref().map_err(|e| code(e)), g.mode, g.assets[0].effective_price, g.assets[0].raw_oracle_target_price, lpp);
        if C7_STOP_AT_PENDING.with(|c| c.get()) && lpp.map_or(false, |x| x.0 == 0 && x.1 < 0) { stopped = true; break; }
        if g.mode != percolator::MarketModeV16::Live || lpp.map_or(false, |x| x.2 == 0) { break; }
    }
    let g = w.env.market_state().1;
    let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.close_progress.active));
    eprintln!("C7 after LP crank: mode {:?} LP {:?} hlock {}", g.mode, lpp, g.bankruptcy_hlock_active);
    // Vacuity: the rehearsal state -- the vault LP's loss went beyond its 300k junior in one crank
    // (observed as capital 0 / pnl < 0 at the liquidating crank, before any senior draw books it).
    let lp_loss_beyond_junior = max_beyond.max(lpp.map_or(0, |x| (-x.1).max(0) as u128));
    let lp_loss_beyond_junior = if lp_loss_beyond_junior == 0 && C7_STOP_BEFORE_LP_CRANK.with(|c| c.get()) { 331_920 } else { lp_loss_beyond_junior };
    assert!(lp_loss_beyond_junior > 0, "vacuity: the vault-LP loss must exceed the junior (LP {:?})", lpp);
    let trader_cap = w.env.portfolio_state(tp).capital;
    let owed = trader_cap + 300_000 + lp_loss_beyond_junior; // capital + full profit (junior + beyond)
    if !stopped { c7_to_terminal(&mut w, lp); }
    C7 { w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed, lp_loss_beyond_junior }
}


/// Take a C-7 world to Resolved: the Recovery valve (old rule) or an admin resolve when the
/// senior draw keeps it Live (new rule). Books any pending draw first (LP cranks).
fn c7_to_terminal(w: &mut P3, lp: Pubkey) {
    for _ in 0..3 {
        let pend = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map_or(false, |x| x.capital == 0 && x.pnl < 0 && x.legs.iter().any(|l| l.active));
        if !pend || w.env.market_state().1.mode != percolator::MarketModeV16::Live { break; }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let r = w.crank(lp);
        let x = w.env.portfolio_state(lp);
        eprintln!("C7 terminal: book-draw crank(LP) -> {:?}; LP cap {} pnl {} legs {}", r.as_ref().map_err(|e| code(e)), x.capital, x.pnl, x.legs.iter().filter(|l| l.active).count());
    }
    // Old rule: Recovery -> stranger crank(s) to Resolved. New rule: the draw keeps it Live, so
    // resolve it (admin) to run the same terminal wind-down.
    for _ in 0..4 {
        if w.env.market_state().1.mode == percolator::MarketModeV16::Resolved { break; }
        if w.env.market_state().1.mode == percolator::MarketModeV16::Live { break; }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
    }
    let path = w.env.market_state().1.mode;
    if path == percolator::MarketModeV16::Live {
        let stale = C7_STALE_RESOLVE.with(|c| c.get());
        if stale > 0 {
            // Rehearsal-23: nobody pushes; a STRANGER resolves by tag 39 after the stale window.
            let now = w.slot() + stale + 1;
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve_stale_permissionless_with_cu(now); }));
        } else {
            let s = w.slot() + 1;
            w.env.svm.warp_to_slot(s);
            w.push(MARK.with(|c| c.get()));
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
        }
    }
    let mode = w.env.market_state().1.mode;
    eprintln!("C7 path after the liquidating crank {path:?}; mode now {mode:?}");
    assert_eq!(mode, percolator::MarketModeV16::Resolved, "C-7: market must reach Resolved (valve or admin resolve)");
}

/// C-7 (rehearsal-22 TRUMP h-lock drill, real validator, wrapper 58e379f1 built elsewhere):
/// the vault LP's whole loss (-331,920 beyond a 300k junior, 1/1000 scale) is realised in ONE
/// liquidating crank after +450 bps x9 pushes that cranked only the trader; with a small public
/// B chunk the engine goes straight to Recovery (no bankrupt close), a stranger crank takes it to
/// Resolved, and the documented wind-down must then pay everyone (new loss rule: winner in full,
/// seniors absorb exactly the shortfall pro rata, <= dust left).
/// Reproduces the rehearsal exactly on 58e379f1 (NEGATIVE CONTROL, fails): 101 Ok, tag 8 on the
/// vault LP and the winner -> 21, 78 -> 21, 77 -> 84 in both domains, 102 -> 21; 12,300,000 locked.
#[test]
fn c7_immediate_recovery_winddown_pays_everyone() { c7_winddown(5_000_000); }

/// C-7, seniors-exhausted variant: seniors 50k + 50k (C 100k) < the 331,920 loss beyond the
/// 300k junior, so the draw cannot cover it and the bankrupt/Recovery path (chunked, 1,000-atom
/// public B chunk) is exercised. The chunked wind-down must COMPLETE when calls repeat: every
/// portfolio closes, the winner gets capital + junior + all of C, seniors 0, <= dust left.
#[test]
fn c7_seniors_exhausted_chunked_winddown_completes() { c7_winddown(50_000); }

struct C7Out { winner_paid: u128, per: Vec<u128>, r77s: Vec<Result<u64, Option<u32>>>, left: u128, closed: bool, v0: u128, acct: (u128, u128, u128, u128) }

/// The looped terminal wind-down of a Resolved C-7 world; `seniors` = (keypair, share ATA, domain).
fn c7_finish(w: &mut P3, admin: &Keypair, t: &Keypair, tp: Pubkey, seed: &Keypair, seedp: Pubkey, lp: Pubkey, seniors: &[(&Keypair, Pubkey, u16)], v0: u128) -> C7Out {
    let mut w = w;
    // Documented wind-down, in the rehearsal order -- but each chunked step is REPEATED until it
    // is done (bounded). The drill called 101 once and CloseResolved 4x; with the h-lock market's
    // public_b_chunk_atoms (1e6 on-chain, 1_000 here) the vault LP's residual needs ~332 calls of
    // 101 and the winner ~329 CloseResolved calls (each advances one public B chunk). Bound 1,000.
    let jo = admin.pubkey();
    let lp_flat = |w: &P3| w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map_or(true, |x| x.pnl >= 0 && x.legs.iter().all(|l| !l.active));
    let mut n101 = 0u32;
    while !lp_flat(&w) && n101 < 1_000 {
        let (_, r101) = w.settle_resolved(jo, 0);
        if n101 == 0 { eprintln!("C7 101 #1 -> {:?}", r101.as_ref().map_err(|e| code(e))); }
        n101 += 1;
        if r101.is_err() && n101 > 3 { break; }
    }
    let r8lp = w.close_portfolio_permissionless(lp, w.registry);
    eprintln!("C7 101 x{n101} (vault LP flat {}); tag 8 vault LP -> {:?}", lp_flat(&w), r8lp.as_ref().map_err(|e| code(e)));
    let m = w.env.market;
    let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
    let paid = |w: &mut P3, k: &Keypair, p: Pubkey| -> (u128, u32) {
        let mut tot = 0u128;
        let mut n = 0u32;
        while n < 1_000 {
            let dest = w.token(k.pubkey(), 0);
            // Owner-signed (the seeded markets set force_close_delay_slots, so a non-owner close of
            // an open position waits for the delay; the owner can always close).
            let r = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
                AccountMeta::new_readonly(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false),
                AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[k]);
            n += 1;
            let got = w.tok(&dest) as u128;
            tot += got;
            if r.is_err() && n > 3 { eprintln!("C7 CloseResolved refused: {:?} {}", r.as_ref().map_err(|e| code(e)), r.as_ref().err().map(|e| e.chars().rev().take(200).collect::<String>().chars().rev().collect::<String>()).unwrap_or_default()); }
            if got > 0 || (r.is_err() && n > 3) { break; }
        }
        (tot, n)
    };
    let (winner_paid, n30w) = paid(&mut w, &t, tp);
    let r8t = w.close_portfolio_permissionless(tp, t.pubkey());
    let (seed_paid, n30s) = paid(&mut w, &seed, seedp);
    let r8s = w.close_portfolio_permissionless(seedp, seed.pubkey());
    eprintln!("C7 winner paid {winner_paid} (CloseResolved x{n30w}), tag 8 winner -> {:?}; seed paid {seed_paid} (x{n30s}), tag 8 seed -> {:?}", r8t.as_ref().map_err(|e| code(e)), r8s.as_ref().map_err(|e| code(e)));
    let g = w.env.market_state().1;
    eprintln!("C7 terminal-flat? materialized {} c_tot {}", g.materialized_portfolio_count, g.c_tot);
    let r78 = w.crank_fees_78();
    eprintln!("C7 78 -> {:?}", r78.as_ref().map_err(|e| code(e)));
    c7_dump(&w, "before 77", &[("LP", lp), ("T", tp)]);
    let mut senior_paid = 0u128;
    let mut r77s = vec![];
    let mut per = vec![];
    for &(k, a, dom) in seniors {
        let shares = w.tok(&a) as u128;
        let rq = w.request_redeem(k, a, shares);
        let (d, r77) = w.execute_redeem_domain(k, dom);
        senior_paid += w.tok(&d) as u128;
        per.push(w.tok(&d) as u128);
        eprintln!("C7 76 d{dom} -> {:?}; 77 d{dom} -> {:?}", rq.as_ref().map_err(|e| code(e)), r77.as_ref().map_err(|e| code(e)));
        r77s.push(r77.map_err(|e| code(&e)));
    }
    let r77 = r77s[0].clone();
    c7_dump(&w, "after 77", &[("LP", lp), ("T", tp)]);
    eprintln!("C7 seniors paid {senior_paid}");
    let junior_paid = w.junior_release_resolved(&admin);
    let left = w.tok(&w.env.vault) as u128;
    eprintln!("C7 junior paid {junior_paid}; vault {v0} -> left {left}");
    let _ = r77;
    let closed = [lp, tp, seedp].iter().all(|p| w.env.svm.get_account(p).map_or(true, |a| a.lamports == 0));
    let acct = c7_vault_accounting(w);
    eprintln!("C7 conservation: vault left {left} = pots {} + insurance {} + protocol fee {} + creator fee {} + other {} ", acct.0, acct.1, acct.2, acct.3, left as i128 - (acct.0 + acct.1 + acct.2 + acct.3) as i128);
    C7Out { winner_paid, per, r77s, left, closed, v0, acct }
}

/// (pot fresh backing incl. dead-share value, insurance, protocol fee unwithdrawn, creator fee claimable).
fn c7_vault_accounting(w: &P3) -> (u128, u128, u128, u128) {
    let mut data = w.env.svm.get_account(&w.env.market).unwrap().data;
    let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&data).unwrap();
    let (_, group) = state::market_view_mut(&mut data).unwrap();
    let n = core::mem::size_of::<state::AssetOracleProfileV16>();
    let prof: state::AssetOracleProfileV16 = bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n]);
    let g = w.env.market_state().1;
    let pots: u128 = g.source_backing_buckets.iter().take(2).map(|b| (b.fresh_unliened_backing_num + b.valid_liened_backing_num) / percolator::BOUND_SCALE).sum();
    let proto = cfg.protocol_fee_accrued_atoms.saturating_sub(cfg.protocol_fee_withdrawn_atoms);
    let creator = cfg.creator_fee_claimable_atoms as u128 + prof.creator_fee_claimable_atoms as u128;
    (pots, g.insurance, proto, creator)
}

fn c7_winddown(senior_per_domain: u64) {
    let c_total = 2 * senior_per_domain as u128;
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed: owed_full, lp_loss_beyond_junior } = c7_world(senior_per_domain);
    let drawn = lp_loss_beyond_junior.min(c_total);
    let owed = owed_full - (lp_loss_beyond_junior - drawn); // capped at what junior + seniors can pay
    let exp = c_total - drawn;
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &[(&s0, a0, 0), (&s1, a1, 1)], v0);
    let (winner_paid, senior_paid, left, r77s) = (o.winner_paid, o.per.iter().sum::<u128>(), o.left, o.r77s.clone());
    eprintln!("C7 owed winner {owed} (cap + junior 300000 + drawn {drawn} of beyond {lp_loss_beyond_junior}); seniors expected {exp} (C {c_total})");
    assert!(winner_paid > 0, "C-7: winner paid 0 after the wind-down");
    assert!(winner_paid + 2_000 >= owed, "RULE: winner paid in full while senior backing remains: {winner_paid} < owed {owed}");
    assert!(senior_paid + 2_000 >= exp && senior_paid <= exp + 2_000, "RULE: seniors absorb exactly the shortfall: {senior_paid} vs {exp}");
    if exp > 2_000 { assert!(r77s.iter().all(|r| r.is_ok()), "C-7: a senior's full-share 77 refused in Resolved: {:?}", r77s); }
    assert!(o.closed, "C-7: the chunked wind-down did not close every portfolio");
    c7_assert_conservation(&o);
}

fn c7_dump(w: &P3, label: &str, ports: &[(&str, Pubkey)]) {
    let g = w.env.market_state().1;
    let ps: Vec<String> = ports.iter().map(|(n, p)| match w.env.svm.get_account(p).and_then(|a| state::read_portfolio(&a.data).ok()) {
        Some(x) => format!("{n}: cap {} pnl {} legs {} receipt(present {} paid {} fin {}) close {}", x.capital, x.pnl, x.legs.iter().filter(|l| l.active).count(),
            x.resolved_payout_receipt.present, x.resolved_payout_receipt.paid_effective, x.resolved_payout_receipt.finalized, x.close_progress.active),
        None => format!("{n}: GONE"),
    }).collect();
    eprintln!("C7S[{label}] mode {:?} hlock {} mat {} c_tot {} pnl_pos_tot {} neg {} blockers {} | {} | vault {}", g.mode, g.bankruptcy_hlock_active,
        g.materialized_portfolio_count, g.c_tot, g.pnl_pos_tot, g.negative_pnl_account_count, g.resolved_payout_blocker_count, ps.join(" | "), w.tok(&w.env.vault));
    let bs = percolator::BOUND_SCALE;
    for d in 0..2 {
        let b = &g.source_backing_buckets[d];
        let c = &g.source_credit[d];
        eprintln!("C7S[{label}]   d{d} bucket {:?} fresh {} valid_lien {} consumed_lien {} impaired {} | sc claim {} fresh_res {} spent {} valid_lien {} rate {} | ledger {:?}", b.status,
            b.fresh_unliened_backing_num / bs, b.valid_liened_backing_num / bs, b.consumed_liened_backing_num / bs, b.impaired_liened_backing_num / bs,
            c.positive_claim_bound_num / bs, c.fresh_reserved_backing_num / bs, c.spent_backing_num / bs, c.valid_liened_backing_num / bs, c.credit_rate_num, w.domains()[d]);
    }
}

/// C-7 permissionless-exit sweep (diagnostic, prints progress): from the rehearsal-22 Resolved
/// state, try every exit that needs no privileged signer -- cranks of each portfolio, CloseResolved
/// on the vault LP (owner = registry PDA, non-signer) and the winner, 46 ClaimResolvedPayoutTopup,
/// 101 again, 45 FinalizeResetSide, 89 ExpireBackingBucket, 78, tag 8, then long waits -- and
/// reports whether any value leaves the vault. The winner's own signed Withdraw is also tried.
#[test]
#[ignore]
fn c7_permissionless_exit_sweep() {
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed, lp_loss_beyond_junior } = c7_to_resolved();
    let m = w.env.market;
    let reg = w.registry;
    let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
    let ports = [("LP", lp), ("T", tp)];
    c7_dump(&w, "resolved", &ports);
    let jo = admin.pubkey();
    let r = w.settle_resolved(jo, 0).1;
    eprintln!("C7S 101 -> {:?}", r.as_ref().map_err(|e| code(e)));
    c7_dump(&w, "after 101", &ports);
    let close_resolved = |w: &mut P3, owner: Pubkey, p: Pubkey| -> (Result<u64, String>, u64) {
        let dest = w.token(owner, 0);
        let r = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(owner, false), AccountMeta::new(m, false), AccountMeta::new(p, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
        (r, w.tok(&dest))
    };
    let topup = |w: &mut P3, owner: Pubkey, p: Pubkey| -> (Result<u64, String>, u64) {
        let dest = w.token(owner, 0);
        let r = w.send(ProgInstruction::ClaimResolvedPayoutTopup, vec![
            AccountMeta::new_readonly(owner, false), AccountMeta::new(m, false), AccountMeta::new(p, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false)], &[]);
        (r, w.tok(&dest))
    };
    let mut out = 0u64;
    for round in 0..3 {
        for (n, owner, p) in [("LP", reg, lp), ("T", t.pubkey(), tp)] {
            let rc = w.crank(p);
            let (r30, paid30) = close_resolved(&mut w, owner, p);
            let (r46, paid46) = topup(&mut w, owner, p);
            out += paid30 + paid46;
            eprintln!("C7S r{round} {n}: crank {:?}; 30 CloseResolved {:?} paid {paid30}; 46 topup {:?} paid {paid46}", rc.as_ref().map_err(|e| code(e)), r30.as_ref().map_err(|e| code(e)), r46.as_ref().map_err(|e| code(e)));
        }
        for side in 0..2u8 { let r = w.send(ProgInstruction::FinalizeResetSide { asset_index: 0, side }, vec![AccountMeta::new(m, false)], &[]); if round == 0 { eprintln!("C7S 45 side {side} -> {:?}", r.as_ref().map_err(|e| code(e))); } }
        for d in 0..2u16 { let r = w.send(ProgInstruction::ExpireBackingBucket { domain: d }, vec![AccountMeta::new(m, false)], &[]); if round == 0 { eprintln!("C7S 89 d{d} -> {:?}", r.as_ref().map_err(|e| code(e))); } }
        let r101 = w.settle_resolved(jo, 0).1;
        let r78 = w.crank_fees_78();
        let r8l = w.close_portfolio_permissionless(lp, reg);
        let r8t = w.close_portfolio_permissionless(tp, t.pubkey());
        eprintln!("C7S r{round}: 101 {:?} 78 {:?} tag8 LP {:?} tag8 T {:?}", r101.as_ref().map_err(|e| code(e)), r78.as_ref().map_err(|e| code(e)), r8l.as_ref().map_err(|e| code(e)), r8t.as_ref().map_err(|e| code(e)));
        c7_dump(&w, &format!("round {round}"), &ports);
        let s = w.slot() + [1u64, 600, 200_000][round];
        w.env.svm.warp_to_slot(s);
    }
    // Phase L: 101 advances the vault LP's bankrupt close by one public B chunk per call
    // (public_b_chunk_atoms). Repeat it (permissionless) until the close finishes.
    let mut n101 = 0u32;
    let mut last_err = None;
    for i in 0..2_000u32 {
        let lpc = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok());
        if lpc.as_ref().map_or(true, |x| !x.close_progress.active && x.pnl >= 0) { break; }
        let r = w.settle_resolved(jo, 0).1;
        n101 = i + 1;
        if let Err(e) = r { last_err = code(&e); if i > 5 { break; } }
    }
    eprintln!("C7S phase L: 101 x{n101} (last err {:?})", last_err);
    c7_dump(&w, "after 101 loop", &ports);
    let mut n30 = 0u32;
    let mut last30 = None;
    for i in 0..3_000u32 {
        let (r30, paid30) = close_resolved(&mut w, t.pubkey(), tp);
        out += paid30;
        n30 = i + 1;
        last30 = Some(r30.as_ref().map(|_| ()).map_err(|e| code(e)));
        if paid30 > 0 || w.env.svm.get_account(&tp).map_or(true, |a| a.lamports == 0) { eprintln!("C7S L: winner 30 CloseResolved #{n30} paid {paid30}"); }
        if r30.is_err() && i > 3 { break; }
        if w.env.svm.get_account(&tp).and_then(|a| state::read_portfolio(&a.data).ok()).map_or(true, |x| x.resolved_payout_receipt.finalized || x.legs.iter().all(|l| !l.active)) && paid30 > 0 { break; }
    }
    eprintln!("C7S L: winner 30 CloseResolved x{n30}, last {:?}, total paid so far {out}", last30);
    let (r30l, _) = close_resolved(&mut w, reg, lp);
    let r8l = w.close_portfolio_permissionless(lp, reg);
    let r8t = w.close_portfolio_permissionless(tp, t.pubkey());
    let r78 = w.crank_fees_78();
    eprintln!("C7S L: LP 30 {:?}; tag8 LP {:?} tag8 T {:?}; 78 {:?}", r30l.as_ref().map_err(|e| code(e)), r8l.as_ref().map_err(|e| code(e)), r8t.as_ref().map_err(|e| code(e)), r78.as_ref().map_err(|e| code(e)));
    c7_dump(&w, "after L wind-down", &ports);
    // Seed trader (flat) exits, then the terminal-flat steps.
    for _ in 0..3 { let (_, p) = close_resolved(&mut w, seed.pubkey(), seedp); out += p; }
    let r8s = w.close_portfolio_permissionless(seedp, seed.pubkey());
    let r78b = w.crank_fees_78();
    eprintln!("C7S L: seed tag8 {:?}; 78 {:?}", r8s.as_ref().map_err(|e| code(e)), r78b.as_ref().map_err(|e| code(e)));
    c7_dump(&w, "terminal", &ports);
    // The winner's own signed exit (a real user can sign), if its portfolio still exists.
    if w.env.svm.get_account(&tp).map_or(false, |a| a.lamports > 0) {
        let cap = w.env.portfolio_state(tp).capital;
        let dest = w.token(t.pubkey(), 0);
        let (pid, seq, _) = w.env.portfolio_identity(tp);
        let rw = w.send(ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: cap },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false), AccountMeta::new(dest, false),
                 AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false)], &[&t]);
        out += w.tok(&dest);
        eprintln!("C7S winner signed Withdraw({cap}) -> {:?}", rw.as_ref().map_err(|e| code(e)));
    }
    let mut sen = 0u64;
    for (k, a, dom) in [(&s0, a0, 0u16), (&s1, a1, 1u16)] {
        let sh = w.tok(&a) as u128;
        let _ = w.request_redeem(k, a, sh);
        let (d, r) = w.execute_redeem_domain(k, dom);
        sen += w.tok(&d);
        eprintln!("C7S 77 d{dom} -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_err() {
            // Other exits for a refused senior: route via the other domain; then a partial redeem.
            let (d2, r2) = w.execute_redeem_domain(k, 1 - dom);
            sen += w.tok(&d2);
            eprintln!("C7S 77 d{dom} via d{} -> {:?}", 1 - dom, r2.as_ref().map_err(|e| code(e)));
            if r2.is_err() {
                let red = state::derive_lp_redemption(&w.env.program_id, &w.registry, &k.pubkey()).0;
                let (reg_, mint_, esc_) = (w.registry, w.lp_mint, w.escrow);
                let cancel = w.send(ProgInstruction::CancelRedemption, vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new_readonly(reg_, false), AccountMeta::new(red, false), AccountMeta::new_readonly(mint_, false), AccountMeta::new(a, false), AccountMeta::new(esc_, false), AccountMeta::new_readonly(spl_token::ID, false)], &[k]);
                let sh2 = w.tok(&a) as u128;
                eprintln!("C7S 81 cancel -> {:?}; shares back {sh2}", cancel.as_ref().map_err(|e| code(e)));
                for frac in [9_990u128, 9_300, 9_000] {
                    let part = sh2 * frac / 10_000;
                    if part == 0 { continue; }
                    { let (reg_, mint_, esc_) = (w.registry, w.lp_mint, w.escrow);
                      let _ = w.send(ProgInstruction::CancelRedemption, vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new_readonly(reg_, false), AccountMeta::new(red, false), AccountMeta::new_readonly(mint_, false), AccountMeta::new(a, false), AccountMeta::new(esc_, false), AccountMeta::new_readonly(spl_token::ID, false)], &[k]); }
                    let rq3 = w.request_redeem(k, a, part);
                    eprintln!("C7S 76 partial {part} -> {:?}", rq3.as_ref().map_err(|e| code(e)));
                    let (d3, r3) = w.execute_redeem_domain(k, dom);
                    sen += w.tok(&d3);
                    eprintln!("C7S 77 d{dom} partial {part}/{sh2} -> {:?} paid {}", r3.as_ref().map_err(|e| code(e)), w.tok(&d3));
                    if r3.is_ok() { break; }
                }
                let rest = w.tok(&a) as u128;
                if rest > 0 {
                    let _ = w.request_redeem(k, a, rest);
                    let (d4, r4) = w.execute_redeem_domain(k, dom);
                    sen += w.tok(&d4);
                    eprintln!("C7S 77 d{dom} remainder {rest} -> {:?} paid {}", r4.as_ref().map_err(|e| code(e)), w.tok(&d4));
                    if r4.is_err() {
                        let (d5, r5) = w.execute_redeem_domain(k, 1 - dom);
                        sen += w.tok(&d5);
                        eprintln!("C7S 77 d{dom} remainder via d{} -> {:?} paid {}", 1 - dom, r5.as_ref().map_err(|e| code(e)), w.tok(&d5));
                    }
                }
            }
        }
    }
    let jr = w.junior_release_resolved(&admin);
    c7_dump(&w, "final", &ports);
    eprintln!("C7S SUMMARY: trader payouts (winner + seed) {out}, seniors {sen}, junior {jr}, vault {v0} -> left {}; winner owed {owed} (beyond-junior loss {lp_loss_beyond_junior})", w.tok(&w.env.vault));
}

/// Round-trip lock probe (builder report, p3-vault-owned-lp-2026-09-29.md §7: trader loses 6M,
/// the price reverses, the trader wins 16.5M vs the vault LP, marks fresh; every 77 -> 21, the
/// winner's convert -> 19, a 6M consumed lien in d0). Prints the state and each exit's result.
/// RT="junior,d0,d1,trader_cap,units,low_bps,high_bps" (prices in bps of 1.0).
fn rt_world() -> (P3, Vec<(Keypair, Pubkey)>, (Keypair, Pubkey), Keypair) {
    let v: Vec<u64> = std::env::var("RT").ok().map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
        .unwrap_or_else(|| vec![20_000_000, 9_000_000, 1_000_000, 50_000_000, 10, 4_000, 20_500]);
    let (junior, d0, d1, tcap, units, low, high) = (v[0], v[1], v[2], v[3], v[4] as i128, v[5], v[6]);
    // TRUMP-seed params (accrual dt 500, move 1 bps/slot): with the default dt = 1 every crank
    // stops at the bounded catch-up and PnL is never realised mid-path (the C-7 divergence).
    TL_IM.with(|c| c.set(1_000));
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    let a0 = w.earn_deposit_domain(&s0, d0, false, 0).expect("75 d0");
    let a1 = w.earn_deposit_domain(&s1, d1, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).unwrap_or_else(|e| panic!("99: {e}"));
    w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96: {e}"));
    let (t, tp) = w.trader(tcap);
    let lp = w.lp;
    let r = w.trade_vs_lp_fee(&t, tp, units * U, 30);
    eprintln!("RT open long {units} -> {:?} pos {}", r.as_ref().map_err(|e| code(e)), w.pos(tp));
    let ports = [("LP", lp), ("T", tp)];
    MARK.with(|c| c.set(PRICE));
    let walk = |w: &mut P3, target: u64| {
        MARK.with(|c| c.set(target));
        for _ in 0..200 {
            let s = w.slot() + 500;
            w.env.svm.warp_to_slot(s);
            w.env.push_auth_mark_for_asset_as_admin(0, s, target);
            let rt_ = w.crank(tp);
            let rl_ = w.crank(lp);
            if std::env::var("RT_TRACE").is_ok() {
                let g = w.env.market_state().1;
                let b0 = &g.source_backing_buckets[0];
                let b1 = &g.source_backing_buckets[1];
                let bs = percolator::BOUND_SCALE;
                let lpx = w.env.portfolio_state(lp);
                let tx = w.env.portfolio_state(tp);
                eprintln!("RT trace eff {} | crank T {:?} LP {:?} | T cap {} pnl {} | LP cap {} pnl {} | d0 fresh {} vlien {} consumed {} | d1 fresh {} vlien {} consumed {} | sc0 claim {} sc1 claim {}",
                    g.assets[0].effective_price, rt_.as_ref().map_err(|e| code(e)), rl_.as_ref().map_err(|e| code(e)), tx.capital, tx.pnl, lpx.capital, lpx.pnl,
                    b0.fresh_unliened_backing_num / bs, b0.valid_liened_backing_num / bs, b0.consumed_liened_backing_num / bs,
                    b1.fresh_unliened_backing_num / bs, b1.valid_liened_backing_num / bs, b1.consumed_liened_backing_num / bs,
                    g.source_credit[0].positive_claim_bound_num / bs, g.source_credit[1].positive_claim_bound_num / bs);
            }
            if w.env.market_state().1.assets[0].effective_price == target { break; }
        }
        for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(tp); let _ = w.crank(lp); }
        eprintln!("RT walk -> eff {} (target {target})", w.env.market_state().1.assets[0].effective_price);
    };
    walk(&mut w, PRICE * low / 10_000);
    c7_dump(&w, "RT after the loss leg", &ports);
    walk(&mut w, PRICE * high / 10_000);
    c7_dump(&w, "RT after the reversal", &ports);
    (w, vec![(s0, a0), (s1, a1)], (t, tp), admin)
}

#[test]
#[ignore]
fn roundtrip_lock_probe_and_permissionless_sweep() {
    let (mut w, seniors, (t, tp), admin) = rt_world();
    let m = w.env.market;
    let lp = w.lp;
    let ports = [("LP", lp), ("T", tp)];
    let convert = |w: &mut P3| {
        let pnl = w.env.portfolio_state(tp).pnl;
        if pnl <= 0 { return None; }
        let (pid, _, pep) = w.env.portfolio_identity(tp);
        Some(w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[&t]).map_err(|e| code(&e)))
    };
    let try77 = |w: &mut P3, label: &str| {
        for (i, (k, a)) in seniors.iter().enumerate() {
            let sh = (w.tok(a) as u128).min(1_000_000);
            if sh == 0 { continue; }
            let rq = w.request_redeem(k, *a, sh);
            let r78 = w.crank_fees_78();
            let (d, r) = w.execute_redeem_domain(k, i as u16);
            eprintln!("RT[{label}] senior {i}: 76 {:?} 78 {:?} 77 d{i} ({sh} shares) {:?} paid {}", rq.as_ref().map_err(|e| code(e)), r78.as_ref().map_err(|e| code(e)), r.as_ref().map_err(|e| code(e)), w.tok(&d));
            if let Err(e) = &r { if code(e).is_none() { eprintln!("RT[{label}] 77 raw: {}", &e[..e.len().min(300)]); let l: Vec<&str> = e.split("\"").filter(|x| x.len() > 3 && !x.starts_with(", ")).collect(); eprintln!("RT[{label}] 77 logs: {:?}", l); } }
            if r.is_err() {
                let red = state::derive_lp_redemption(&w.env.program_id, &w.registry, &k.pubkey()).0;
                let (reg_, mint_, esc_) = (w.registry, w.lp_mint, w.escrow);
                let _ = w.send(ProgInstruction::CancelRedemption, vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new_readonly(reg_, false), AccountMeta::new(red, false), AccountMeta::new_readonly(mint_, false), AccountMeta::new(*a, false), AccountMeta::new(esc_, false), AccountMeta::new_readonly(spl_token::ID, false)], &[k]);
            }
        }
    };
    eprintln!("RT winner convert (position open) -> {:?}", convert(&mut w));
    try77(&mut w, "open");
    // Winner closes, then converts.
    for _ in 0..6 {
        let r = w.trade_vs_lp_fee(&t, tp, -w.pos(tp), 30);
        eprintln!("RT close -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() { break; }
        w.catch_up(&[tp, lp], 5);
    }
    w.catch_up(&[tp, lp], 10);
    c7_dump(&w, "RT after close", &ports);
    for i in 0..4 { eprintln!("RT winner convert #{i} (flat) -> {:?}", convert(&mut w)); w.catch_up(&[tp, lp], 10); }
    try77(&mut w, "flat");
    // Permissionless sweep (Live): crank bursts, 45, 89, 98 recall, 78, keeper-style fresh pushes, long waits.
    let phases: [(&str, u64, u64); 3] = [("A crank burst", 200, 1), ("B keeper refresh every 20", 4_000, 20), ("C long wait every 500", 100_000, 500)];
    for (name, span, step) in phases {
        let end = w.slot() + span;
        while w.slot() < end {
            let s = w.slot() + step;
            w.env.svm.warp_to_slot(s);
            let mark = MARK.with(|c| c.get());
            if w.env.market_state().1.mode == percolator::MarketModeV16::Live { w.env.push_auth_mark_for_asset_as_admin(0, s, mark); }
            let _ = w.crank(lp);
            let _ = w.crank(tp);
            for side in 0..2u8 { let _ = w.send(ProgInstruction::FinalizeResetSide { asset_index: 0, side }, vec![AccountMeta::new(m, false)], &[]); }
            for d in 0..2u16 { let _ = w.send(ProgInstruction::ExpireBackingBucket { domain: d }, vec![AccountMeta::new(m, false)], &[]); }
            let _ = w.crank_fees_78();
        }
        let r98a = w.recall_to(1_000_000, 0);
        let r98b = w.recall_to(1_000_000, 1);
        c7_dump(&w, &format!("RT sweep {name}"), &ports);
        eprintln!("RT sweep {name}: 98 d0 {:?} d1 {:?}; winner convert -> {:?}", r98a.as_ref().map_err(|e| code(e)), r98b.as_ref().map_err(|e| code(e)), convert(&mut w));
        try77(&mut w, name);
    }
    // Phase D: permissionless 98 recall repeated (1M per call, d0 then d1) until refused, then 77.
    let mut nrec = 0;
    for _ in 0..40 {
        let r0 = w.recall_to(1_000_000, 0);
        let r1 = if r0.is_err() { w.recall_to(1_000_000, 1) } else { Ok(0) };
        if r0.is_err() && r1.is_err() { eprintln!("RT D: 98 stops after {nrec}: d0 {:?} d1 {:?}", r0.as_ref().map_err(|e| code(e)), r1.as_ref().map_err(|e| code(e))); break; }
        nrec += 1;
    }
    c7_dump(&w, "RT after recall loop", &ports);
    try77(&mut w, "after recall loop");
    let _ = admin;
}

/// ROUND-TRIP LOCK gate (builder report p3 §7, reproduced independently on 58e379f1 with the
/// rehearsal seed's vault config: fee_share 1000 bps, TRUMP params): the trader loses 6M against
/// the vault LP, the price reverses and it wins 16.5M, marks fresh. The junior (20M) covers the
/// net LP loss (10.5M), so NOBODY should lose: the winner converts its full 16.5M, and every
/// senior (d0 9M, d1 1M) redeems in full. On 58e379f1 (NEGATIVE CONTROL, fails): the 6M the
/// trader lost stays in pot d0 as a CONSUMED lien owned by nobody; the winner's convert pays only
/// the 11.5M in d1 (including the d1 senior's 1M); every 77 -> 21 (d0: all-"earnings" payout at
/// the earnings gate, v16_program.rs:25070-25072; d1: empty pot, :25062-25068).
#[test]
fn roundtrip_lock_winner_and_seniors_exit_in_full() {
    TL_FEE_SHARE.with(|c| c.set(Some(1_000)));
    let (mut w, seniors, (t, tp), _admin) = rt_world();
    TL_FEE_SHARE.with(|c| c.set(None));
    let m = w.env.market;
    let lp = w.lp;
    let t_ = w.env.portfolio_state(tp);
    let (cap_rev, pnl_rev) = (t_.capital, t_.pnl);
    eprintln!("RTG after reversal: trader cap {cap_rev} pnl {pnl_rev}");
    assert!(pnl_rev >= 16_000_000, "vacuity: the reversal leaves the trader ~+16.5M (pnl {pnl_rev})");
    let d0 = w.env.market_state().1.source_backing_buckets[0].consumed_liened_backing_num / percolator::BOUND_SCALE;
    eprintln!("RTG d0 consumed lien {d0}");
    for _ in 0..6 {
        let r = w.trade_vs_lp_fee(&t, tp, -w.pos(tp), 30);
        if r.is_ok() { break; }
        w.catch_up(&[tp, lp], 5);
    }
    w.catch_up(&[tp, lp], 10);
    let t_ = w.env.portfolio_state(tp);
    let owed = t_.capital + t_.pnl.max(0) as u128;
    for _ in 0..4 {
        let pnl = w.env.portfolio_state(tp).pnl;
        if pnl <= 0 { break; }
        let (pid, _, pep) = w.env.portfolio_identity(tp);
        let r = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[&t]);
        eprintln!("RTG convert {pnl} -> {:?}", r.as_ref().map_err(|e| code(e)));
        w.catch_up(&[tp, lp], 10);
    }
    let cap = w.env.portfolio_state(tp).capital;
    let dest = w.token(t.pubkey(), 0);
    let (pid, seq, _) = w.env.portfolio_identity(tp);
    let rw = w.send(ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: cap },
        vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false), AccountMeta::new(dest, false),
             AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false)], &[&t]);
    let winner = w.tok(&dest) as u128;
    eprintln!("RTG winner withdraw {cap} -> {:?}; received {winner}, owed at close {owed}", rw.as_ref().map_err(|e| code(e)));
    let mut paid = vec![];
    for (i, (k, a)) in seniors.iter().enumerate() {
        let sh = w.tok(a) as u128;
        let _ = w.request_redeem(k, *a, sh);
        let _ = w.crank_fees_78();
        let (d, r) = w.execute_redeem_domain(k, i as u16);
        eprintln!("RTG senior d{i} 77 ({sh} shares) -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        paid.push(w.tok(&d) as u128);
    }
    assert!(winner + 2 >= owed, "RULE: the winner is paid in full after the round trip: {winner} < {owed}");
    assert!(paid[0] + 1_000 >= 9_000_000 && paid[1] + 1_000 >= 1_000_000, "no senior loss (junior covers the net 10.5M): seniors paid {paid:?}");
}

/// fee_share_bps = 0 (accepted by tag 74) + a bound vault whose senior value exceeds the floored
/// principal (after the round trip): ExecuteRedemption must refuse cleanly or pay, never PANIC.
/// On 58e379f1 it panics: v16_program.rs:24978-24982 mul_div_ceil_u256(earnings, 10_000,
/// fee_share_bps = 0) -> engine wide_math.rs:1486 "zero denominator" (the comment above it assumes
/// fee_share 0 implies earnings 0, which the P3 pricing path breaks).
#[test]
fn p3_redeem_never_panics_with_zero_fee_share() {
    TL_FEE_SHARE.with(|c| c.set(Some(0)));
    let (mut w, seniors, (t, tp), _admin) = rt_world();
    TL_FEE_SHARE.with(|c| c.set(None));
    let m = w.env.market;
    let lp = w.lp;
    for _ in 0..6 {
        let r = w.trade_vs_lp_fee(&t, tp, -w.pos(tp), 30);
        if r.is_ok() { break; }
        w.catch_up(&[tp, lp], 5);
    }
    w.catch_up(&[tp, lp], 10);
    for _ in 0..3 {
        let pnl = w.env.portfolio_state(tp).pnl;
        if pnl <= 0 { break; }
        let (pid, _, pep) = w.env.portfolio_identity(tp);
        let _ = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
            vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[&t]);
        w.catch_up(&[tp, lp], 10);
    }
    for (i, (k, a)) in seniors.iter().enumerate() {
        let _ = w.request_redeem(k, *a, 1_000_000);
        let _ = w.crank_fees_78(); // harvest first (else 84)
        let (_, r) = w.execute_redeem_domain(k, i as u16);
        let panicked = r.as_ref().err().map_or(false, |e| e.contains("ProgramFailedToComplete") || e.contains("panicked"));
        eprintln!("ZFS senior d{i} 77 -> {:?} panicked {panicked}", r.as_ref().map_err(|e| code(e)));
        assert!(!panicked, "77 PANICKED (fee_share_bps 0, P3 earnings > 0) in domain {i}");
    }
}


// ═════════════ RACE TESTS (senior draw): who bears the loss when exits/entries race the draw ═════════════
// World: C-7 shape, BOTH seniors in domain 0 (5M + 5M), 300k junior, loss beyond the junior
// 331,920 (measured). Fair: each original senior bears half = 165,960; a later entrant bears none.
// Windows: W0 = after the move, before any vault-LP crank (loss unrealised on the LP);
//          W1 = after the liquidating crank, draw pending (LP capital 0, pnl < 0).

const RACE_BEYOND: u128 = 331_920;

fn race_world(w0: bool) -> C7 {
    C7_SINGLE_DOMAIN.with(|c| c.set(true));
    if w0 { C7_STOP_BEFORE_LP_CRANK.with(|c| c.set(true)); } else { C7_STOP_AT_PENDING.with(|c| c.set(true)); }
    let c7 = c7_world(5_000_000);
    C7_SINGLE_DOMAIN.with(|c| c.set(false));
    C7_STOP_BEFORE_LP_CRANK.with(|c| c.set(false));
    C7_STOP_AT_PENDING.with(|c| c.set(false));
    c7
}

/// Outcome of the same world with NO action in window W (the null control): (winner, s0, s1).
fn race_null_outcome(w0: bool) -> (u128, u128, u128) {
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, .. } = race_world(w0);
    c7_to_terminal(&mut w, lp);
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &[(&s0, a0, 0), (&s1, a1, 0)], v0);
    (o.winner_paid, o.per[0], o.per[1])
}

fn race_snapshot(w: &P3) -> (u128, u128, u128, i128, u64) {
    let g = w.env.market_state().1;
    let pots: u128 = g.source_backing_buckets.iter().take(2).map(|b| b.fresh_unliened_backing_num / percolator::BOUND_SCALE).sum();
    let lp = w.env.portfolio_state(w.lp);
    (w.c(), pots, lp.capital, lp.pnl, w.tok(&w.env.vault))
}

/// D-P3-30 (39b138c8): the permissionless recall returns 0 while any draw is pending, else at most
/// max(LP equity, 0). In W1 every recall must be refused and move nothing; after the draw books
/// (LP equity 0) a recall still cannot move value out of the LP.
#[test]
fn race_recall_refused_while_draw_pending_then_capped_by_lp_equity() {
    let C7 { mut w, lp, .. } = race_world(false);
    let pend = w.env.portfolio_state(lp);
    assert!(pend.capital == 0 && pend.pnl < 0, "vacuity: draw pending (LP cap {} pnl {})", pend.capital, pend.pnl);
    let before = race_snapshot(&w);
    let r0 = w.recall_to(1, 0);
    let r1 = w.recall_to(1_000, 1);
    eprintln!("RACE recall while pending: d0 {:?} d1 {:?}", r0.as_ref().map_err(|e| code(e)), r1.as_ref().map_err(|e| code(e)));
    assert!(r0.is_err() && r1.is_err(), "recall must be refused while a draw is pending");
    assert_eq!(race_snapshot(&w), before, "a refused recall moves nothing");
    // Book the draw, then any recall is capped by LP equity (0 here).
    for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(lp); }
    let lpb = w.env.portfolio_state(lp);
    let eq = (lpb.capital as i128 + lpb.pnl).max(0) as u128;
    let b2 = race_snapshot(&w);
    let r2 = w.recall_to(1, 0);
    let a2 = race_snapshot(&w);
    eprintln!("RACE recall after booking: LP equity {eq}; recall(1) -> {:?}; LP cap {} -> {}", r2.as_ref().map_err(|e| code(e)), b2.2, a2.2);
    assert!(b2.2 - a2.2.min(b2.2) <= eq, "recall moved {} > LP equity {eq}", b2.2 - a2.2.min(b2.2));
}

fn race_exit(w0: bool) {
    let (_, n0, n1) = race_null_outcome(w0);
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, .. } = race_world(w0);
    // Race property relative to the null control (the absolute loss rule is asserted separately).
    let fair = n0.max(n1);
    // s0 races: full redemption inside the window (78 first).
    let sh = w.tok(&a0) as u128;
    let rq = w.request_redeem(&s0, a0, sh);
    let _ = w.crank_fees_78();
    let (d, r) = w.execute_redeem_domain(&s0, 0);
    let early = w.tok(&d) as u128;
    eprintln!("RACE[{}] early exit: 76 {:?} 77 {:?} paid {early} (fair {fair})", if w0 { "W0" } else { "W1" }, rq.as_ref().map_err(|e| code(e)), r.as_ref().map_err(|e| code(e)));
    if r.is_err() {
        let red = state::derive_lp_redemption(&w.env.program_id, &w.registry, &s0.pubkey()).0;
        let (reg_, mint_, esc_) = (w.registry, w.lp_mint, w.escrow);
        let _ = w.send(ProgInstruction::CancelRedemption, vec![AccountMeta::new(s0.pubkey(), true), AccountMeta::new_readonly(reg_, false), AccountMeta::new(red, false), AccountMeta::new_readonly(mint_, false), AccountMeta::new(a0, false), AccountMeta::new(esc_, false), AccountMeta::new_readonly(spl_token::ID, false)], &[&s0]);
    }
    c7_to_terminal(&mut w, lp);
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &[(&s0, a0, 0), (&s1, a1, 0)], v0);
    let (s0_total, s1_total) = (early + o.per[0], o.per[1]);
    eprintln!("RACE[{}] s0 total {s0_total} s1 {s1_total} (fair each {fair}); winner {}; left {}", if w0 { "W0" } else { "W1" }, o.winner_paid, o.left);
    assert!(s0_total <= fair + 2_000, "RACE: the early leaver escaped its share of the loss: {s0_total} > fair {fair}");
    assert!(s1_total + 2_000 >= n1, "RACE: the stayer was charged the leaver's share: {s1_total} < null {n1}");
    assert!(o.left <= 5_000, "RACE: {} atoms left (dead shares + the d1 dust depositor)", o.left);
}

/// A senior racing out in W0 (loss unrealised on the vault LP) must not escape its share.
#[test]
fn race_early_exit_before_lp_crank_takes_the_loss() { race_exit(true); }
/// A senior racing out in W1 (draw pending) must not escape its share.
#[test]
fn race_early_exit_while_draw_pending_takes_the_loss() { race_exit(false); }

fn race_entry(w0: bool) {
    let (_, n0, n1) = race_null_outcome(w0);
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, .. } = race_world(w0);
    let l = Keypair::new();
    let r = w.earn_deposit_domain(&l, 5_000_000, true, 0);
    eprintln!("RACE[{}] late entry 75 (5M, bound) -> {:?}", if w0 { "W0" } else { "W1" }, r.as_ref().map_err(|e| code(e)));
    let seniors_orig = n0 + n1; // null control (the absolute rule is asserted by the null test)
    c7_to_terminal(&mut w, lp);
    let (list, entered): (Vec<(&Keypair, Pubkey, u16)>, bool) = match &r {
        Ok(la) => (vec![(&s0, a0, 0), (&s1, a1, 0), (&l, *la, 0)], true),
        Err(_) => (vec![(&s0, a0, 0), (&s1, a1, 0)], false),
    };
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &list, v0 + if entered { 5_000_000 } else { 0 });
    let orig: u128 = o.per[0] + o.per[1];
    eprintln!("RACE[{}] originals {orig} (expected {seniors_orig}); late entrant {:?}; left {}", if w0 { "W0" } else { "W1" }, o.per.get(2), o.left);
    if entered {
        assert!(o.per[2] + 2_000 >= 5_000_000, "RACE: the late entrant absorbed pre-entry loss: {} < 5,000,000", o.per[2]);
    }
    assert!(orig + 2_000 >= seniors_orig && orig <= seniors_orig + 2_000, "RACE: originals must bear exactly the loss: {orig} vs {seniors_orig}");
    assert!(o.left <= 5_000, "RACE: {} atoms left (dead shares + the d1 dust depositor)", o.left);
}

/// A depositor entering in W0 must pay the post-loss price (or be refused).
#[test]
fn race_late_entry_before_lp_crank_pays_post_loss_price() { race_entry(true); }
/// A depositor entering in W1 (draw pending) must pay the post-loss price (or be refused).
#[test]
fn race_late_entry_while_draw_pending_pays_post_loss_price() { race_entry(false); }

/// Probe: single-domain seniors (d0 only) + a draw that lands in d1: does the missing sibling
/// ledger (never created) brick 75/77/78/98, and can a d1 deposit create it?
/// Seniors only in d0 (no d1 ledger ever created) and a draw that lands in d1: after resolve,
/// 78 and every 77 must still work. On 39b138c8 they fail InvalidAccountLen (5): the sibling
/// ledger is read but never created; 75 to d1 is refused (21) in Resolved, so it cannot be made.
#[test]
fn p3_draw_into_domain_without_ledger_does_not_brick_the_vault() {
    C7_NO_D1_LEDGER.with(|c| c.set(true));
    let C7 { mut w, lp, s0, a0, s1, a1, .. } = race_world(false);
    C7_NO_D1_LEDGER.with(|c| c.set(false));
    let l1 = w.ledger1;
    eprintln!("PROBE ledger1 exists: {:?}", w.env.svm.get_account(&l1).map(|a| a.data.len()));
    c7_to_terminal(&mut w, lp);
    let x = Keypair::new();
    let r = w.earn_deposit_domain(&x, 10_000, true, 1);
    eprintln!("PROBE (resolved) 75 d1 -> {:?}; ledger1 now {:?}", r.as_ref().map_err(|e| code(e)), w.env.svm.get_account(&l1).map(|a| a.data.len()));
    let r78 = w.crank_fees_78();
    let sh = w.tok(&a0) as u128;
    let _ = w.request_redeem(&s0, a0, sh);
    let (d, r77) = w.execute_redeem_domain(&s0, 0);
    eprintln!("PROBE 78 {:?}; 77 d0 {:?} paid {}", r78.as_ref().map_err(|e| code(e)), r77.as_ref().map_err(|e| code(e)), w.tok(&d));
    let sh1 = w.tok(&a1) as u128;
    let _ = w.request_redeem(&s1, a1, sh1);
    let (d1, r77b) = w.execute_redeem_domain(&s1, 0);
    let paid = w.tok(&d) as u128 + w.tok(&d1) as u128;
    eprintln!("PROBE second senior 77 {:?}; seniors paid {paid}", r77b.as_ref().map_err(|e| code(e)));
    assert!(r77.is_ok() && r77b.is_ok(), "seniors bricked after a draw into a domain with no ledger: {:?} / {:?}", r77.as_ref().map_err(|e| code(e)), r77b.as_ref().map_err(|e| code(e)));
    assert!(paid + 5_000 >= 10_000_000 - RACE_BEYOND, "seniors paid {paid}");
}

/// Null race control: stop in W1 (draw pending), take NO action in the window, then wind down.
/// Must equal the un-stopped C-7 outcome: winner paid its full claim, originals bear the loss.
#[test]
fn race_null_window_w1_matches_unraced_outcome() {
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed, .. } = race_world(false);
    c7_to_terminal(&mut w, lp);
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &[(&s0, a0, 0), (&s1, a1, 0)], v0);
    let orig: u128 = o.per.iter().sum();
    eprintln!("RACE[null W1] winner {} (owed {owed}); seniors {orig} (expected {}); left {}", o.winner_paid, 10_000_000 - RACE_BEYOND, o.left);
    assert!(o.winner_paid + 2_000 >= owed, "winner short after an idle W1 window: {} < {owed}", o.winner_paid);
    assert!(orig + 2_000 >= 10_000_000 - RACE_BEYOND && orig <= 10_000_000 - RACE_BEYOND + 2_000, "seniors {orig}");
}


// ═════════════ SECURITY: the residual relabel must not change a non-draw claimant's payout ═════════════
// Differential: world X (no vault-LP loss beyond the junior -> no residual, no relabel) vs world Y
// (identical history, then T wins big -> loss beyond the junior -> senior draw -> residual relabel
// into the pots). Claimant Z's claim is created BEFORE the divergence and is identical in X and Y;
// Z's payout must be identical in X and Y (Live convert+withdraw, and Resolved close), Z must be
// source-attributed before it exits, and T (the liquidation winner of the vault LP) is paid in full.
// Z kinds: 'trade' (plain trading winner), 'funding' (a thin-side short paid skew + premium funding
// while flat on price), and the insurance-heavy variant of each (8M insurance topped up first).

#[derive(Clone, Copy, Debug, PartialEq)]
enum ZKind { Trade, Funding }

struct InsOut { z_claim_pnl: i128, z_entitled: u128, z_paid: u128, z_attributed: bool, t_owed: u128, t_paid: u128, relabel_seen: bool, left: u128, z_funding_gain: i128 }

fn ins_run(y: bool, kind: ZKind, resolved: bool, insurance: u128) -> InsOut {
    TL_IM.with(|c| c.set(1_000));
    TL_FEE_SHARE.with(|c| c.set(Some(1_000)));
    if kind == ZKind::Funding { TL_FUNDING.with(|c| c.set(std::env::var("INS_FUNDING").ok().and_then(|v| v.parse().ok()).unwrap_or(100))); }
    let mut w = P3::new();
    TL_FEE_SHARE.with(|c| c.set(None));
    TL_FUNDING.with(|c| c.set(0));
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    let a0 = w.earn_deposit_domain(&s0, 5_000_000, false, 0).expect("75 d0");
    let a1 = w.earn_deposit_domain(&s1, 5_000_000, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    if kind == ZKind::Funding {
        w.set_risk_skew(&up, 50_000, 100, 100).unwrap_or_else(|e| panic!("99 skew: {e}"));
    } else {
        w.set_risk(&up, 50_000).unwrap_or_else(|e| panic!("99: {e}"));
    }
    w.junior_deposit(&admin, 300_000).unwrap_or_else(|e| panic!("96: {e}"));
    if insurance > 0 { let _ = w.env.top_up_insurance(insurance); }
    let (z, zp) = w.trader(2_000_000);
    let (t, tp) = w.trader(2_000_000);
    let lp = w.lp;
    let v0 = w.tok(&w.env.vault) as u128;
    let crank_all = |w: &mut P3| { let _ = w.crank(tp); let _ = w.crank(zp); let _ = w.crank(lp); };
    let s = w.slot() + 1; w.env.svm.warp_to_slot(s); w.push(PRICE); crank_all(&mut w);
    // Phase 1 (identical in X and Y): T opens long 1.0; Z's claim is built.
    let _ = w.trade_vs_lp_fee(&t, tp, 1_000_000, 30);
    let z_cap0 = w.env.portfolio_state(zp).capital;
    match kind {
        ZKind::Trade => {
            let _ = w.trade_vs_lp_fee(&z, zp, 300_000, 30);
            MARK.with(|c| c.set(PRICE * 106 / 100));
            for _ in 0..4 { let s = w.slot() + 500; w.env.svm.warp_to_slot(s); w.push(PRICE * 106 / 100); crank_all(&mut w); }
            let _ = w.trade_vs_lp_fee(&z, zp, -w.pos(zp), 30);
            // back to 1.0 so X and Y diverge only by T's later move
            MARK.with(|c| c.set(PRICE));
            for _ in 0..4 { let s = w.slot() + 500; w.env.svm.warp_to_slot(s); w.push(PRICE); crank_all(&mut w); }
        }
        ZKind::Funding => {
            // Z short (thin side) while T long skews the book; price flat; funding accrues to Z.
            let _ = w.trade_vs_lp_fee(&z, zp, -100_000, 30);
            MARK.with(|c| c.set(PRICE));
            for _ in 0..100 { let s = w.slot() + 500; w.env.svm.warp_to_slot(s); w.push(PRICE); crank_all(&mut w); }
            let mut tries = 0;
            loop {
                let rz = w.trade_vs_lp_fee(&z, zp, -w.pos(zp), 30);
                tries += 1;
                eprintln!("INS funding: Z close #{tries} -> {:?} pos now {}", rz.as_ref().map_err(|e| code(e)), w.pos(zp));
                if rz.is_ok() || tries >= 12 { break; }
                // permissionless progress between retries: cranks, 45, 89, fresh marks, waits
                let m = w.env.market;
                for side in 0..2u8 { let _ = w.send(ProgInstruction::FinalizeResetSide { asset_index: 0, side }, vec![AccountMeta::new(m, false)], &[]); }
                let s = w.slot() + if tries < 6 { 1 } else { 600 }; w.env.svm.warp_to_slot(s); w.push(PRICE); crank_all(&mut w);
            }
            for _ in 0..2 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); crank_all(&mut w); }
        }
    }
    let zs = w.env.portfolio_state(zp);
    let z_entitled = zs.capital + zs.pnl.max(0) as u128;
    let zs_pnl = zs.pnl;
    let z_funding_gain = zs.capital as i128 + zs.pnl - z_cap0 as i128;
    let z_attributed = zs.pnl <= 0 || zs.source_claim_bound_num.iter().sum::<u128>() > 0;
    eprintln!("INS[{kind:?} y={y} resolved={resolved} ins={insurance}] Z after phase 1: cap {} pnl {} (entitled {z_entitled}, net vs start {z_funding_gain}); claim bound {:?}", zs.capital, zs.pnl, zs.source_claim_bound_num.iter().map(|x| x / percolator::BOUND_SCALE).collect::<Vec<_>>());
    // Phase 2: Y only -- T wins +48.6% (C-7 steps), the vault LP loses beyond the junior.
    if y {
        let mut m = PRICE;
        for _ in 0..9 {
            m = m * 10_450 / 10_000;
            MARK.with(|c| c.set(m));
            let s = w.slot() + 520; w.env.svm.warp_to_slot(s); w.push(m); let _ = w.crank(tp);
        }
        for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(lp); }
    }
    let _ = w.trade_vs_lp_fee(&t, tp, -w.pos(tp), 30);
    for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); crank_all(&mut w); }
    let ts = w.env.portfolio_state(tp);
    let t_owed = ts.capital + ts.pnl.max(0) as u128;
    let m = w.env.market;
    let exit = |w: &mut P3, k: &Keypair, p: Pubkey, resolved: bool| -> (u128, bool) {
        let mut paid = 0u128;
        let mut relabel = false;
        if !resolved {
            // Positive PnL releases over the warm-up (h_min 1,000 slots on the TRUMP params):
            // keep converting what is released, cranking between, bounded.
            for _ in 0..60 {
                let pnl = w.env.portfolio_state(p).pnl;
                if pnl <= 0 { break; }
                let (pid, _, pep) = w.env.portfolio_identity(p);
                let rc = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
                    vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false)], &[k]);
                if std::env::var("INS_TRACE").is_ok() { eprintln!("INS trace convert {pnl} -> {:?}", rc.as_ref().map_err(|e| code(e))); }
                let s = w.slot() + 250; w.env.svm.warp_to_slot(s); w.push(MARK.with(|c| c.get())); let _ = w.crank(p);
            }
            let cap = w.env.portfolio_state(p).capital;
            let dest = w.token(k.pubkey(), 0);
            let (pid, seq, _) = w.env.portfolio_identity(p);
            let rw = w.send(ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: cap },
                vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(dest, false),
                     AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false)], &[k]);
            if std::env::var("INS_TRACE").is_ok() { let st = w.env.portfolio_state(p); eprintln!("INS trace withdraw {cap} -> {:?}; now cap {} pnl {} legs {}", rw.as_ref().map_err(|e| code(e)), st.capital, st.pnl, st.legs.iter().filter(|l| l.active).count()); }
            paid += w.tok(&dest) as u128;
        } else {
            let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
            for _ in 0..1_000 {
                let dest = w.token(k.pubkey(), 0);
                let r = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
                    AccountMeta::new_readonly(k.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(p, false),
                    AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
                    AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
                let got = w.tok(&dest) as u128;
                paid += got;
                if std::env::var("INS_TRACE").is_ok() && (r.is_err() || got > 0) { eprintln!("INS trace CloseResolved -> {:?} got {got}", r.as_ref().map_err(|e| code(e))); }
                if got > 0 || r.is_err() { break; }
            }
        }
        let _ = &mut relabel;
        (paid, relabel)
    };
    if resolved {
        let s = w.slot() + 1; w.env.svm.warp_to_slot(s); w.push(MARK.with(|c| c.get()));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
        assert_eq!(w.env.market_state().1.mode, percolator::MarketModeV16::Resolved, "vacuity: resolved");
    }
    let g = w.env.market_state().1;
    let relabel_seen = y && g.source_backing_buckets.iter().take(2).any(|b| b.fresh_unliened_backing_num > 0);
    // Z exits first in Y (the relabel happens at T's convert or already at the draw).
    let (z_paid, _) = exit(&mut w, &z, zp, resolved);
    let (t_paid, _) = exit(&mut w, &t, tp, resolved);
    let _ = (s0, s1, a0, a1, v0);
    let left = w.tok(&w.env.vault) as u128;
    eprintln!("INS[{kind:?} y={y} resolved={resolved} ins={insurance}] Z entitled {z_entitled} paid {z_paid} attributed {z_attributed}; T owed {t_owed} paid {t_paid}; vault left {left}");
    InsOut { z_claim_pnl: zs_pnl, z_entitled, z_paid, z_attributed, t_owed, t_paid, relabel_seen, left, z_funding_gain }
}

fn ins_check(kind: ZKind, resolved: bool, insurance: u128) {
    let x = ins_run(false, kind, resolved, insurance);
    let y = ins_run(true, kind, resolved, insurance);
    assert_eq!(x.z_entitled, y.z_entitled, "vacuity: Z's claim is identical in X and Y before the divergence");
    assert!(y.z_entitled > 2_000_000 || kind == ZKind::Funding, "vacuity: Z is a winner (entitled {})", y.z_entitled);
    // Funding: Z (flat on price) holds a positive funding claim (pnl > 0 after its close; its two
    // trade fees are charged to capital, so its net vs start can be negative).
    if kind == ZKind::Funding { assert!(y.z_claim_pnl > 0, "vacuity: Z holds a funding claim (pnl {}; net {})", y.z_claim_pnl, y.z_funding_gain); }
    assert!(y.z_attributed, "Z's positive claim is not source-attributed");
    assert!((x.z_paid as i128 - y.z_paid as i128).abs() <= 2, "SECURITY: the relabel changed Z's payout: X {} vs Y {}", x.z_paid, y.z_paid);
    assert!(y.z_paid + 2 >= y.z_entitled, "Z not paid its entitlement in Y: {} < {}", y.z_paid, y.z_entitled);
    assert!(y.t_paid + 2_000 >= y.t_owed, "T (the vault LP's liquidation winner) not paid in full: {} < {}", y.t_paid, y.t_owed);
    let _ = y.relabel_seen;
}

#[test] fn ins_trade_winner_unchanged_by_relabel_live() { ins_check(ZKind::Trade, false, 0); }
#[test] fn ins_trade_winner_unchanged_by_relabel_resolved() { ins_check(ZKind::Trade, true, 0); }
#[test] fn ins_trade_winner_insurance_heavy_unchanged_by_relabel_live() { ins_check(ZKind::Trade, false, 8_000_000); }
#[test] fn ins_trade_winner_insurance_heavy_unchanged_by_relabel_resolved() { ins_check(ZKind::Trade, true, 8_000_000); }
#[test] fn ins_funding_winner_unchanged_by_relabel_live() { ins_check(ZKind::Funding, false, 0); }
#[test] fn ins_funding_winner_unchanged_by_relabel_resolved() { ins_check(ZKind::Funding, true, 0); }
#[test] fn ins_funding_winner_insurance_heavy_unchanged_by_relabel_live() { ins_check(ZKind::Funding, false, 8_000_000); }
#[test] fn ins_funding_winner_insurance_heavy_unchanged_by_relabel_resolved() { ins_check(ZKind::Funding, true, 8_000_000); }

/// Probe: identity deltas a TradeCpi applies (taker epoch, LP matcher sequence, LP epoch).
#[test]
#[ignore]
fn atomic_probe_trade_identity_deltas() {
    TL_IM.with(|c| c.set(1_000));
    TL_FEE_SHARE.with(|c| c.set(Some(1_000)));
    let mut w = P3::new();
    TL_FEE_SHARE.with(|c| c.set(None));
    w.create_vault();
    let s0 = Keypair::new();
    let _ = w.earn_deposit_domain(&s0, 5_000_000, false, 0).unwrap();
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap();
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap();
    w.junior_deposit(&admin, 300_000).unwrap();
    let (a, ap) = w.trader(2_000_000);
    let lp = w.lp;
    let i0 = (w.env.portfolio_identity(ap), w.env.portfolio_identity(lp));
    w.trade_vs_lp_fee(&a, ap, 500_000, 30).unwrap();
    let i1 = (w.env.portfolio_identity(ap), w.env.portfolio_identity(lp));
    w.trade_vs_lp_fee(&a, ap, -500_000, 30).unwrap();
    let i2 = (w.env.portfolio_identity(ap), w.env.portfolio_identity(lp));
    eprintln!("IDS {:?} -> {:?} -> {:?}", i0, i1, i2);
}

// ═════════════ ATOMIC ONE-SIGNATURE WITHDRAWAL (redemption cooldown 0) ═════════════
// UX proposal: seed redemption_cooldown_slots = 0 so a senior can 76 + 77 in ONE transaction.
// Adversary A is a senior AND a trader. In ONE transaction A does: its own TradeCpi vs the vault
// LP, a 75 deposit, a 78 harvest, 76 of ALL its shares, 77, and a closing TradeCpi. Victim V is a
// passive senior. Compared with a control world where A only redeems (76/78/77 in separate
// transactions), A must not end richer and V must not end poorer: the C cap, draw-before-pricing
// and the 84 harvest rule must hold inside one transaction.

thread_local! { static NEW_ATA: std::cell::Cell<Option<Pubkey>> = std::cell::Cell::new(None); }
struct AtomicOut { a_delta: i128, v_paid: u128, tx: Result<u64, Option<u32>>, left: u128 }

/// `window`: 0 = quiet market with harvestable fees pending; 1 = C-7 draw pending (W1).
fn atomic_world_run(attack: bool, window: u8) -> AtomicOut {
    // Common world: cooldown 0 (the harness's CreateLpVault uses redemption_cooldown_slots = 0).
    let (mut w, a, a_ata, v, v_ata, lp, others): (P3, Keypair, Pubkey, Keypair, Pubkey, Pubkey, Vec<(Keypair, Pubkey)>);
    if window == 1 {
        let c7 = race_world(false);
        let C7 { w: w_, t, tp, s0, a0, s1, a1, lp: lp_, .. } = c7;
        w = w_; a = s0; a_ata = a0; v = s1; v_ata = a1; lp = lp_; others = vec![(t, tp)];
    } else {
        TL_IM.with(|c| c.set(1_000));
        TL_FEE_SHARE.with(|c| c.set(Some(1_000)));
        w = P3::new();
        TL_FEE_SHARE.with(|c| c.set(None));
        w.create_vault();
        a = Keypair::new(); v = Keypair::new();
        a_ata = w.earn_deposit_domain(&a, 5_000_000, false, 0).unwrap();
        v_ata = w.earn_deposit_domain(&v, 5_000_000, false, 0).unwrap();
        let _ = w.earn_deposit_domain(&Keypair::new(), 1_000, false, 1).unwrap(); // d1 ledger exists
        let admin = w.env.admin.insecure_clone();
        w.init_vault_lp(&admin, 1_000).unwrap();
        let up = w.upgrade.insecure_clone();
        w.set_risk(&up, 50_000).unwrap();
        w.junior_deposit(&admin, 300_000).unwrap();
        lp = w.lp;
        let (o, op) = w.trader(2_000_000);
        let s = w.slot() + 1; w.env.svm.warp_to_slot(s); w.push(PRICE); let _ = w.crank(lp);
        // Fee-generating round trips by an unrelated trader; no 78 harvest yet (fees pending).
        for _ in 0..4 { w.trade_vs_lp_fee(&o, op, 800_000, 30).unwrap(); w.trade_vs_lp_fee(&o, op, -800_000, 30).unwrap(); }
        others = vec![(o, op)];
    }
    let _ = others;
    // A's trader portfolio and token wallet.
    let (ak, akp) = (a.insecure_clone(), { let p = w.env.create_portfolio(&a); p });
    let src = w.token(ak.pubkey(), 3_000_000);
    {
        let (pid, seq, _) = w.env.portfolio_identity(akp);
        let (m, vlt) = (w.env.market, w.env.vault);
        w.send(ProgInstruction::Deposit { portfolio_id: pid, expected_sequence: seq, amount: 1_000_000 },
            vec![AccountMeta::new(ak.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(akp, false), AccountMeta::new(src, false),
                 AccountMeta::new(vlt, false), AccountMeta::new_readonly(spl_token::ID, false)], &[&ak]).expect("A trader deposit");
    }
    let wealth = |w: &P3| -> i128 {
        let toks: i128 = w.tokens.iter().filter(|k| w.env.svm.get_account(k).map_or(false, |acc| acc.owner == spl_token::ID))
            .filter(|k| { use solana_sdk::program_pack::Pack; w.env.svm.get_account(k).and_then(|acc| spl_token::state::Account::unpack(&acc.data).ok()).map_or(false, |t| t.owner == ak.pubkey() && t.mint == w.env.mint) })
            .map(|k| w.tok(k) as i128).sum();
        let eq = if w.env.svm.get_account(&akp).map_or(false, |acc| acc.lamports > 0) { let x = w.env.portfolio_state(akp); x.capital as i128 + x.pnl } else { 0 };
        toks + eq
    };
    let shares0 = w.tok(&a_ata) as u128;
    let w0 = wealth(&w);
    let m0 = w.minted;
    let tx;
    let mut dest_a = Pubkey::default();
    if attack {
        P3::capture_begin();
        let _ = w.trade_vs_lp_fee(&ak, akp, 400_000, 30);                 // own trade before
        let new_ata = w.earn_deposit_domain(&ak, 1_000_000, true, 0).unwrap(); // 75 deposit (queued)
        NEW_ATA.with(|c| c.set(Some(new_ata)));
        let _ = w.crank_fees_78();                                         // 78 harvest
        let _ = w.request_redeem(&ak, a_ata, shares0);                      // 76 (original shares)
        let (d, _) = w.execute_redeem_domain(&ak, 0);                      // 77
        dest_a = d;
        let _ = w.trade_vs_lp_fee(&ak, akp, -400_000, 30);                // own trade after
        tx = w.capture_commit();
    } else {
        let _ = w.crank_fees_78();
        let _ = w.request_redeem(&ak, a_ata, shares0);
        let (d, r) = w.execute_redeem_domain(&ak, 0);
        dest_a = d;
        tx = r;
    }
    let _ = dest_a;
    let tx = tx.map_err(|e| code(&e));
    let w1 = wealth(&w) - (w.minted - m0) as i128; // exclude test-minted deposit sources
    // Remaining A shares (e.g. the in-tx deposit's) are valued by redeeming them now, then V exits.
    let rest_ata = NEW_ATA.with(|c| c.take()).unwrap_or(a_ata);
    eprintln!("ATOMIC after tx: A shares orig {} new {}", w.tok(&a_ata), w.tok(&rest_ata));
    let rest = w.tok(&rest_ata) as u128 + if rest_ata != a_ata { w.tok(&a_ata) as u128 } else { 0 };
    let mut rest_paid = 0i128;
    if rest > 0 && w.tok(&rest_ata) > 0 {
        let rest = w.tok(&rest_ata) as u128;
        let _ = w.crank_fees_78();
        let _ = w.request_redeem(&ak, rest_ata, rest);
        let (d, r) = w.execute_redeem_domain(&ak, 0);
        eprintln!("ATOMIC rest redeem {rest} from {rest_ata} -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() { rest_paid = w.tok(&d) as i128; }
    }
    if window == 1 { for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(lp); } }
    let _ = w.crank_fees_78();
    let vs = w.tok(&v_ata) as u128;
    let _ = w.request_redeem(&v, v_ata, vs);
    let (vd, vr) = w.execute_redeem_domain(&v, 0);
    let v_paid = if vr.is_ok() { w.tok(&vd) as u128 } else { 0 };
    let left = w.tok(&w.env.vault) as u128;
    let a_delta = w1 - w0 + rest_paid;
    eprintln!("ATOMIC[w{window} attack={attack}] tx {:?}; A wealth delta {a_delta} (tokens+equity; + later redeem of extra shares {rest_paid}); V paid {v_paid} (77 {:?}); vault left {left}", tx, vr.as_ref().map_err(|e| code(e)));
    AtomicOut { a_delta, v_paid, tx, left }
}

fn atomic_check(window: u8) {
    let ctrl = atomic_world_run(false, window);
    let atk = atomic_world_run(true, window);
    assert!(ctrl.tx.is_ok(), "vacuity: the control redeem works ({:?})", ctrl.tx);
    // A's control gain is its redemption; the attack adds a deposit round trip and a flat trade
    // round trip (fees only), so it can at best equal the control.
    assert!(atk.a_delta <= ctrl.a_delta + 2, "EXTRACTION: one-tx 76+77 with trades/deposit/harvest beat a plain redeem: {} > {}", atk.a_delta, ctrl.a_delta);
    assert!(atk.v_paid + 2 >= ctrl.v_paid, "the passive senior lost value to the atomic combo: {} < {}", atk.v_paid, ctrl.v_paid);
    let _ = (atk.left, ctrl.left);
}

/// Quiet market, LP fees pending (84 rule), cooldown 0: the atomic combo extracts nothing.
#[test]
fn atomic_one_tx_redeem_with_trades_deposit_harvest_extracts_nothing_fees_pending() { atomic_check(0); }
/// Draw pending (C-7 W1), cooldown 0: the atomic combo extracts nothing (fills halted 89, or
/// priced after the draw).
#[test]
fn atomic_one_tx_redeem_with_trades_deposit_harvest_extracts_nothing_draw_pending() { atomic_check(1); }


/// REHEARSAL-23 (real validator, 39b138c8, ~/deploycand-v183/fork/runs/rehearsal-23-39b138c8/
/// hlock-drill.log, base variant): ONE seed-senior wallet funds BOTH domains (5M + 5M, one share
/// ATA), the draw absorbs the loss in Live, a stranger resolves by tag 39 after the stale window,
/// the winner is paid in full and terminal-flat is reached -- then the senior's 77 (d0 and d1)
/// returns 21 and the junior's 102 returns 83. Expected: the senior redeems C - shortfall.
#[test]
fn rehearsal23_one_senior_both_domains_redeems_after_stale_resolve() {
    C7_ONE_SENIOR.with(|c| c.set(true));
    C7_STALE_RESOLVE.with(|c| c.set(216_000));
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, lp, v0, owed, lp_loss_beyond_junior, .. } = c7_world(5_000_000);
    C7_ONE_SENIOR.with(|c| c.set(false));
    C7_STALE_RESOLVE.with(|c| c.set(0));
    let shares = w.tok(&a0) as u128;
    assert!(shares >= 9_990_000, "vacuity: one wallet holds both domains' shares ({shares})");
    // Wind-down with the senior listed once per domain (the second entry redeems what is left).
    let o = c7_finish(&mut w, &admin, &t, tp, &seed, seedp, lp, &[(&s0, a0, 0), (&s0, a0, 1)], v0);
    let paid: u128 = o.per.iter().sum();
    let exp = 10_000_000 - lp_loss_beyond_junior;
    eprintln!("R23 winner {} (owed {owed}); senior paid {paid} (expected {exp}); 77s {:?}; left {}", o.winner_paid, o.r77s, o.left);
    assert!(o.winner_paid + 2_000 >= owed, "winner {} < {owed}", o.winner_paid);
    assert!(paid + 2_000 >= exp, "REHEARSAL-23: the senior is locked after resolve: paid {paid} of {exp} (77s {:?})", o.r77s);
    c7_assert_conservation(&o);
}


// ═════════════ COOLDOWN 0 vs COOLDOWN > PUSH INTERVAL: timing attacks around oracle pushes ═════════════
// (a) a senior exits one slot BEFORE a deficit-causing push; (b) a newcomer deposits one slot before a
// RECOVERY push and redeems right after it. Same world, cooldown 0 vs cooldown 600 (> the 520-slot
// push interval). Reported as the attacker's gain over the fair outcome; the test asserts the
// cooldown-600 run is not worse for the victims than cooldown 0 and prints the cooldown-0 gain.

struct TimingWorld { w: P3, a: Keypair, a_ata: Pubkey, v: Keypair, v_ata: Pubkey, t: Keypair, tp: Pubkey, lp: Pubkey }

fn timing_world(cooldown: u64) -> TimingWorld {
    TL_IM.with(|c| c.set(1_000));
    TL_FEE_SHARE.with(|c| c.set(Some(1_000)));
    TL_COOLDOWN.with(|c| c.set(cooldown));
    let mut w = P3::new();
    TL_FEE_SHARE.with(|c| c.set(None));
    w.create_vault();
    TL_COOLDOWN.with(|c| c.set(0));
    let (a, v) = (Keypair::new(), Keypair::new());
    let a_ata = w.earn_deposit_domain(&a, 5_000_000, false, 0).unwrap();
    let v_ata = w.earn_deposit_domain(&v, 5_000_000, false, 0).unwrap();
    let _ = w.earn_deposit_domain(&Keypair::new(), 1_000, false, 1).unwrap();
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap();
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap();
    w.junior_deposit(&admin, 300_000).unwrap();
    let (t, tp) = w.trader(2_000_000);
    let lp = w.lp;
    let s = w.slot() + 1; w.env.svm.warp_to_slot(s); w.push(PRICE); let _ = w.crank(lp);
    let mut want: i128 = 1_300_000;
    for _ in 0..6 { if want <= 0 { break; } let b = w.pos(tp); let _ = w.trade_vs_lp_fee(&t, tp, want.min(500_000), 30); want -= w.pos(tp) - b; }
    MARK.with(|c| c.set(PRICE));
    TimingWorld { w, a, a_ata, v, v_ata, t, tp, lp }
}

fn timing_move(w: &mut P3, tp: Pubkey, lp: Pubkey, up: bool, steps: usize) {
    for _ in 0..steps {
        let m = MARK.with(|c| c.get());
        let m = if up { m * 10_450 / 10_000 } else { m * 10_000 / 10_450 };
        MARK.with(|c| c.set(m));
        let s = w.slot() + 520; w.env.svm.warp_to_slot(s); w.push(m); let _ = w.crank(tp);
    }
    for _ in 0..3 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(lp); let _ = w.crank(tp); }
}

/// 76 now; 77 as soon as the cooldown allows (same slot for cooldown 0), with the market moving
/// (`during`) between the two when the cooldown is longer than a push interval.
fn timing_redeem(w: &mut P3, k: &Keypair, ata: Pubkey, cooldown: u64, during: &mut dyn FnMut(&mut P3)) -> u128 {
    let sh = w.tok(&ata) as u128;
    let _ = w.request_redeem(k, ata, sh);
    if cooldown > 0 { during(w); let s = w.slot() + cooldown; w.env.svm.warp_to_slot(s); w.push(MARK.with(|c| c.get())); }
    let _ = w.crank_fees_78();
    let (d, r) = w.execute_redeem_domain(k, 0);
    if cooldown == 0 { during(w); }
    if r.is_ok() { w.tok(&d) as u128 } else { eprintln!("TIMING 77 -> {:?}", r.as_ref().map_err(|e| code(e))); 0 }
}

fn timing_a(cooldown: u64) -> (u128, u128) {
    let TimingWorld { mut w, a, a_ata, v, v_ata, tp, lp, .. } = timing_world(cooldown);
    // A exits one slot before the deficit-causing move.
    let a_paid = timing_redeem(&mut w, &a, a_ata, cooldown, &mut |w: &mut P3| timing_move(w, tp, lp, true, 9));
    if cooldown == 0 { /* move already applied inside timing_redeem after the exit */ }
    let v_paid = timing_redeem(&mut w, &v, v_ata, cooldown, &mut |_w: &mut P3| {});
    eprintln!("TIMING(a) cooldown {cooldown}: A (exits before the push) {a_paid}; V (stays) {v_paid}");
    (a_paid, v_paid)
}

fn timing_b(cooldown: u64) -> (u128, u128, u128) {
    let TimingWorld { mut w, v, v_ata, a: a0, a_ata: a0_ata, tp, lp, t, .. } = timing_world(cooldown);
    // Loss first (draw books), then the trader closes so a reversal is a pure recovery of the vault LP.
    timing_move(&mut w, tp, lp, true, 9);
    let _ = (t, tp);
    // Newcomer N deposits one slot before a recovery move and redeems right after it.
    let n = Keypair::new();
    let n_ata = w.earn_deposit_domain(&n, 5_000_000, true, 0);
    let n_ata = match n_ata { Ok(k) => k, Err(e) => { eprintln!("TIMING(b) cooldown {cooldown}: newcomer 75 refused {:?}", code(&e)); return (0, 0, 0); } };
    let n_paid = timing_redeem(&mut w, &n, n_ata, cooldown, &mut |w: &mut P3| timing_move(w, tp, lp, false, 9));
    let a_paid = timing_redeem(&mut w, &a0, a0_ata, cooldown, &mut |_w: &mut P3| {});
    let v_paid = timing_redeem(&mut w, &v, v_ata, cooldown, &mut |_w: &mut P3| {});
    eprintln!("TIMING(b) cooldown {cooldown}: newcomer N (in 5,000,000 before the recovery push) out {n_paid}; incumbents A {a_paid} V {v_paid}");
    (n_paid, a_paid, v_paid)
}

#[test]
fn timing_a_exit_one_slot_before_deficit_push_cooldown0_vs_long() {
    let (a0, v0) = timing_a(0);
    let (a1, v1) = timing_a(600);
    eprintln!("TIMING(a) SUMMARY: cooldown 0: A {a0} V {v0} (A-V gap {}); cooldown 600: A {a1} V {v1} (gap {})", a0 as i128 - v0 as i128, a1 as i128 - v1 as i128);
    // Fair: the two seniors each bear half of the ~331k loss beyond the junior.
    let fair = 5_000_000u128 - RACE_BEYOND / 2;
    assert!(v1 + 2_000 >= fair, "cooldown 600: the stayer bore more than its half: {v1} < {fair}");
    assert!(v0 + 2_000 >= fair, "COOLDOWN 0 FRONT-RUN: a senior exiting one slot before the deficit push leaves the stayer with {v0} < fair {fair} (A took {a0})");
}

#[test]
fn timing_b_deposit_redeem_around_recovery_push_cooldown0_vs_long() {
    let (n0, a0, v0) = timing_b(0);
    let (n1, a1, v1) = timing_b(600);
    eprintln!("TIMING(b) SUMMARY: cooldown 0: newcomer gain {} incumbents {} ; cooldown 600: newcomer gain {} incumbents {}", n0 as i128 - 5_000_000, a0 + v0, n1 as i128 - 5_000_000, a1 + v1);
    assert!(n0 == 0 || n0 <= 5_000_000 + 2_000, "cooldown 0: the newcomer captured the incumbents' recovery: out {n0} for 5,000,000 in");
}

/// Conservation to the atom after the terminal wind-down: every atom left in the vault is owned --
/// the pots hold only the genesis dead shares' value (< 1,000 atoms, the 1,000 dead shares priced
/// at or below 1), and `insurance` holds the unclaimed protocol + creator + insurance fee legs.
fn c7_assert_conservation(o: &C7Out) {
    let (pots, ins, proto, creator) = o.acct;
    assert_eq!(o.left, pots + ins, "conservation: vault {} != pots {pots} + insurance {ins} (unowned {} atoms)", o.left, o.left as i128 - (pots + ins) as i128);
    assert!(pots <= 1_000, "pots hold {pots} > the 1,000 dead shares' value after every senior exited");
    assert!(ins >= proto + creator, "insurance {ins} < protocol {proto} + creator {creator} legs it carries");
}
