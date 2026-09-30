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
            ProgInstruction::CreateLpVault { fee_share_bps: TL_FEE_SHARE.with(|c| c.get()).or_else(|| std::env::var("P3_FEE_SHARE_BPS").ok().and_then(|v| v.parse().ok())).unwrap_or(0), redemption_cooldown_slots: 0, oi_reservation_threshold_bps: 0, domain: 0 },
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
            max_abs_funding_e9_per_slot: 0,
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
fn c7_to_resolved() -> C7 {
    // Rehearsal-22 TRUMP market params (IM 10% / MM 6%, liq fee 50 bps, move 1 bps/slot,
    // accrual dt 500). The earlier IM-20% variant had max_accrual_dt 20 < every warp, so each
    // crank stopped at the bounded catch-up and never touched the portfolio (the divergence).
    TL_IM.with(|c| c.set(1_000));
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    // rehearse.sh: LP_VAULT_DEPOSIT_PER_DOMAIN = 5e9 (HLOCK_SENIOR_PER_DOMAIN), i.e. C = 1e10 over d0 + d1.
    let a0 = w.earn_deposit_domain(&s0, 5_000_000, false, 0).expect("75 senior d0");
    let s1 = Keypair::new();
    let a1 = w.earn_deposit_domain(&s1, 5_000_000, false, 1).expect("75 senior d1");
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
    for i in 0..3 {
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let r = w.crank(lp);
        let g = w.env.market_state().1;
        let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.legs.iter().filter(|l| l.active).count(), p.close_progress.active));
        eprintln!("C7 crank(LP) #{i} -> {:?}; mode {:?} eff {} tgt {} LP {:?}", r.as_ref().map_err(|e| code(e)), g.mode, g.assets[0].effective_price, g.assets[0].raw_oracle_target_price, lpp);
        if g.mode != percolator::MarketModeV16::Live || lpp.map_or(false, |x| x.2 == 0) { break; }
    }
    let g = w.env.market_state().1;
    let lpp = w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| (p.capital, p.pnl, p.close_progress.active));
    eprintln!("C7 after LP crank: mode {:?} LP {:?} hlock {}", g.mode, lpp, g.bankruptcy_hlock_active);
    // Vacuity: the rehearsal state -- the vault LP's loss went beyond its 300k junior in one crank.
    let lp_loss_beyond_junior = lpp.map_or(0, |x| (-x.1).max(0) as u128);
    assert!(lp_loss_beyond_junior > 0, "vacuity: the vault-LP loss must exceed the junior (LP {:?})", lpp);
    assert_ne!(g.mode, percolator::MarketModeV16::Live, "vacuity: the rehearsal path leaves Live at the liquidating crank");
    let trader_cap = w.env.portfolio_state(tp).capital;
    let owed = trader_cap + 300_000 + lp_loss_beyond_junior; // capital + full profit (junior + beyond)
    // stranger crank(s) while in Recovery
    for _ in 0..4 {
        if w.env.market_state().1.mode == percolator::MarketModeV16::Resolved { break; }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
    }
    let mode = w.env.market_state().1.mode;
    eprintln!("C7 mode after stranger cranks: {mode:?}");
    C7 { w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed, lp_loss_beyond_junior }
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
fn c7_immediate_recovery_winddown_pays_everyone() {
    let C7 { mut w, admin, t, tp, seed, seedp, s0, a0, s1, a1, lp, v0, owed, lp_loss_beyond_junior } = c7_to_resolved();
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
            let r = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
                AccountMeta::new_readonly(k.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(p, false),
                AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
            n += 1;
            let got = w.tok(&dest) as u128;
            tot += got;
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
    let mut senior_paid = 0u128;
    let mut r77s = vec![];
    for (k, a, dom) in [(&s0, a0, 0u16), (&s1, a1, 1u16)] {
        let shares = w.tok(&a) as u128;
        let rq = w.request_redeem(k, a, shares);
        let (d, r77) = w.execute_redeem_domain(k, dom);
        senior_paid += w.tok(&d) as u128;
        eprintln!("C7 76 d{dom} -> {:?}; 77 d{dom} -> {:?}", rq.as_ref().map_err(|e| code(e)), r77.as_ref().map_err(|e| code(e)));
        r77s.push(r77.map_err(|e| code(&e)));
    }
    let r77 = r77s[0].clone();
    eprintln!("C7 seniors paid {senior_paid}");
    let junior_paid = w.junior_release_resolved(&admin);
    let left = w.tok(&w.env.vault) as u128;
    eprintln!("C7 junior paid {junior_paid}; vault {v0} -> left {left}");
    eprintln!("C7 owed winner {owed} (cap + junior 300000 + beyond {lp_loss_beyond_junior}); seniors expected {}", 10_000_000 - lp_loss_beyond_junior);
    assert!(winner_paid > 0, "C-7: winner paid 0 after immediate-Recovery wind-down");
    assert!(senior_paid > 0, "C-7: seniors paid 0 (77 -> {:?})", r77s);
    assert!(winner_paid + 2 >= owed, "RULE: winner never haircut: {winner_paid} < owed {owed}");
    let exp = 10_000_000 - lp_loss_beyond_junior;
    assert!(senior_paid + 2_000 >= exp && senior_paid <= exp + 2_000, "RULE: seniors absorb exactly the shortfall: {senior_paid} vs {exp}");
    assert!(r77s.iter().all(|r| r.is_ok()), "C-7: a senior's full-share 77 refused in Resolved: {:?}", r77s);
    assert!(left <= 2_000, "C-7: {left} atoms locked after the documented wind-down");
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
                for frac in [9_990u128, 9_000] {
                    let part = sh2 * frac / 10_000;
                    if part == 0 { continue; }
                    let _ = w.request_redeem(k, a, part);
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
