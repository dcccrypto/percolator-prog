//! INDEPENDENT SUITE (2026-09-30) — P1 + P3 COMBINED (creator free option end to end, skew funding,
//! leverage step-down, tranche first-depositor). Helpers copied verbatim from indep_p3_vault_lp.rs
//! (fork-authored, design-derived). Original header:
//! P3 vault-owned LP, from the DESIGN DOC only
//! (ledger/p3-vault-owned-lp-2026-09-29.md §0 interface, §2 waterfall/flows, §6 H1/H2) and the
//! security review BLOCKERS (P3-H1 resolved exit, P3-H2 creator free option).
//!
//! Tags 94..101 are encoded as raw bytes per §0.3 so this file compiles against the BASE host
//! lib (6377376a). Wrapper .so under test: INDEP_WRAPPER_SO (default ~/wt-indep/p3-so/current.so).
//! Negative control: any pre-P3 .so (v18.2 / P1) must fail these tests at tag 94.
//!
//! Properties asserted (design §2.2):
//!   W1 senior + junior == V; junior > 0 ⇒ senior == C_eff (junior is first loss)
//!   W2 a trader win against the vault LP moves only the junior while junior > 0 (C unchanged)
//!   H1 after Resolve seniors can exit; no one extracts more than their NAV share; tokens conserved
//!   H2 the creator cannot pick/reprice the vault LP's matcher (tags 95/99 upgrade-authority only),
//!      cannot pull the junior while the LP carries inventory, and never below the floor.
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
        let mut env = V16CuEnv::new_with_init_params(market_params());
        // 07a1d0eb auto-pin: vault LP matcher must be CANONICAL_VAULT_LP_MATCHER_PROGRAM.
        let matcher = if std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") { Pubkey::new_unique() } else { "DfTxJUT5BbERs1tR33dP82kaUJ1NLymRxXErXAYXcDam".parse::<Pubkey>().unwrap() };
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

/// H2 (a): the creator (marketauth / asset_admin) cannot choose or reprice the vault LP's
/// matcher or risk params — tags 95 and 99 are upgrade-authority-only (design §2.1, §6 P3-H2).
fn indep_p3_h2_creator_cannot_set_vault_lp_matcher_or_risk() {
    let s1 = Keypair::new();
    let mut w = P3::new();
    w.create_vault();
    w.earn_deposit(&s1, 10_000_000, false).expect("senior");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let r = w.set_risk(&admin, 50_000);
    assert!(r.is_err(), "H2: marketauth set tag 99 risk (approved matcher / lev) — must be upgrade-authority only");
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).expect("99 by upgrade authority");
    let r = w.set_matcher(&admin);
    assert!(r.is_err(), "H2: marketauth ran tag 95 VaultLpSetMatcher — creator picks the counterparty pricing");
    let rnd = Keypair::new();
    w.env.ensure_signer_account(rnd.pubkey());
    assert!(w.set_matcher(&rnd).is_err(), "random signer ran tag 95");
    w.set_matcher(&up).expect("95 by upgrade authority");
    // A non-approved matcher program must be refused even for the upgrade authority.
    let other = Pubkey::new_unique();
    let bytes = std::fs::read(matcher_program_path()).unwrap();
    w.env.svm.add_program(other, &bytes);
    let saved = w.matcher;
    w.matcher = other;
    let r = w.set_matcher(&up);
    w.matcher = saved;
    assert_eq!(r.as_ref().err().and_then(|e| code(e)), Some(81), "unapproved matcher must be VaultLpMatcherNotApproved(81): {r:?}");
}

/// W1/W2 + H2 (b): a trader (e.g. the creator's second wallet) wins against the vault LP:
/// the loss is taken by the junior first; C (senior claim) is unchanged; while the LP carries
/// inventory the junior cannot be withdrawn; after flattening, never below the floor.
fn indep_p3_junior_first_loss_and_no_early_junior_exit() {
    let s1 = Keypair::new();
    let (mut w, _atas) = P3::bound(&[(&s1, 10_000_000)], 5_000_000, 2_000);
    let admin = w.env.admin.insecure_clone();
    let c0 = w.c();
    assert!(c0 >= 10_000_000 - DEAD && c0 <= 10_000_000, "C must equal senior principal, got {c0}");
    let lp_cap0 = w.lp_state().capital;
    assert_eq!(lp_cap0, 5_000_000, "junior deposit lands as vault-LP capital");

    // second wallet goes long 2 units at mark against the vault LP
    let (t, tp) = w.trader(5_000_000);
    w.trade_vs_lp(&t, tp, 2 * POS_SCALE as i128).unwrap_or_else(|e| panic!("TradeCpi vs vault LP: {e}"));
    assert!(w.lp_state().legs.iter().any(|l| l.active), "vault LP must hold inventory");

    // loss becomes KNOWN: mark +20%
    w.push(1_200_000);
    let _ = w.crank(tp);
    let _ = w.crank(w.lp);
    // creator's free option: exit the junior now, ahead of the known loss
    let (_d, r) = w.junior_withdraw(&admin, admin.pubkey(), 1);
    assert!(r.is_err(), "H2: junior withdrew while the vault LP carries a losing position");

    // senior claim unchanged by the trader's gain (junior is first loss)
    assert_eq!(w.c(), c0, "W2: C moved on a trader win while junior > 0");

    // trader closes (realizes the win against the LP)
    w.trade_vs_lp(&t, tp, -2 * (POS_SCALE as i128)).unwrap_or_else(|e| panic!("close: {e}"));
    let _ = w.crank(w.lp);
    let lp_after = w.lp_state();
    assert!(!lp_after.legs.iter().any(|l| l.active), "LP flat after trader closes");
    let junior_now = (lp_after.capital as i128 + lp_after.pnl.min(0)) as u128;
    assert!(junior_now < 5_000_000, "the win must have been paid by the junior (LP capital {junior_now})");
    assert_eq!(w.c(), c0, "W2: C unchanged after realized loss");

    // floor: junior may not go below ceil(C_eff * floor_bps / 1e4)
    let floor = (c0 * 2_000 + 9_999) / 10_000;
    let over = junior_now - floor + 1;
    let (_d, r) = w.junior_withdraw(&admin, admin.pubkey(), over);
    assert!(r.is_err(), "junior withdrew below floor ({over} > {junior_now} - {floor})");
    if junior_now > floor {
        let ok_amt = junior_now - floor;
        let (d, r) = w.junior_withdraw(&admin, admin.pubkey(), ok_amt);
        r.unwrap_or_else(|e| panic!("junior withdraw down to exactly the floor must work: {e}"));
        assert_eq!(w.tok(&d) as u128, ok_amt);
    }
    // a non-junior signer can never withdraw the junior
    let thief = Keypair::new();
    w.env.ensure_signer_account(thief.pubkey());
    let (_d, r) = w.junior_withdraw(&thief, thief.pubkey(), 1);
    assert!(r.is_err(), "non-junior signer withdrew junior");
}

/// H1: after Resolve, the vault-LP portfolio (junior + any senior cover) has an exit, seniors
/// redeem, and nobody extracts more than their NAV share. Tokens are conserved exactly.
/// Loss case: the trader win exceeds the junior so seniors take a haircut — the senior payout
/// must be exactly what the waterfall promises (min(V, C) pro-rata), junior gets 0.
fn run_h1(win_mark: u64, junior: u64) -> (u128, u128, u128, u128) {
    let s1 = Keypair::new();
    let s2 = Keypair::new();
    let (mut w, atas) = P3::bound(&[(&s1, 6_000_000), (&s2, 4_000_000)], junior, 1_000);
    let admin = w.env.admin.insecure_clone();
    let c0 = w.c();
    let (t, tp) = w.trader(20_000_000);
    let units = (junior as i128 / PRICE as i128).max(1);
    w.trade_vs_lp(&t, tp, units * POS_SCALE as i128).unwrap_or_else(|e| panic!("open: {e}"));
    w.push(win_mark);
    for _ in 0..3 {
        let _ = w.crank(tp);
        let _ = w.crank(w.lp);
    }
    w.env.resolve();
    // trader exits (CloseResolved permissionless, pays owner)
    let mut trader_out = 0u128;
    for _ in 0..4 {
        let d = w.token(t.pubkey(), 0);
        let (m, v, va) = (w.env.market, w.env.vault, w.env.vault_authority);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(t.pubkey(), false),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        trader_out += w.tok(&d) as u128;
        eprintln!("trader CloseResolved -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
    }
    // tag 30 (CloseResolved) on the vault LP must be refused (82): it would strand funds in a
    // registry-PDA-owned ATA (P3-H1 original shape).
    {
        let reg = w.registry;
        let d = w.token(reg, 0);
        let (m, v, va, lp) = (w.env.market, w.env.vault, w.env.vault_authority, w.lp);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(reg, false),
                AccountMeta::new(m, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        assert!(r.is_err() && w.tok(&d) == 0, "H1: CloseResolved paid the vault LP into a registry-owned ATA: {r:?}");
    }
    // settle the vault LP senior-first (tag 101), repeat until no progress
    let mut junior_out = 0u128;
    let mut settled = false;
    for topup in [0u8, 0, 1, 1] {
        let (d, r) = w.settle_resolved(admin.pubkey(), topup);
        junior_out += w.tok(&d) as u128;
        if r.is_ok() {
            settled = true;
        }
    }
    assert!(settled, "H1: tag 101 VaultLpSettleResolved never succeeded");
    for _ in 0..3 {
        let d = w.token(t.pubkey(), 0);
        let (m, v, va) = (w.env.market, w.env.vault, w.env.vault_authority);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(t.pubkey(), false),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        trader_out += w.tok(&d) as u128;
        eprintln!("post-settle trader CloseResolved -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        let st = w.env.portfolio_state(tp);
        eprintln!("   trader capital {} pnl {} active {}", st.capital, st.pnl, st.legs.iter().any(|l| l.active));
    }
    // Liveness probe: can a senior exit BEFORE marketauth's terminal cleanup? (depends only on
    // permissionless steps so far: CloseResolved + tag 101)
    {
        let shares = w.tok(&atas[1]) as u128;
        w.request_redeem(&s2, atas[1], shares).expect("request");
        let (_d, r) = w.execute_redeem(&s2, true);
        eprintln!("H1-liveness: senior redemption before marketauth ClosePortfolio cleanup -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() {
            eprintln!("H1-liveness: seniors can exit without marketauth");
        }
        // put shares back for the pro-rata check below if the request escrowed them
    }
    // Keeper terminal sequence (P3 doc §128, F-14 head): permissionless tag 8 of the empty
    // trader and the vault LP, then Resolved tag 78 (terminal-flat). No marketauth involved.
    let r78 = w.terminal_cleanup(&[(tp, t.pubkey())]);
    let (_, g) = w.env.market_state();
    assert_eq!(g.materialized_portfolio_count, 0, "terminal-flat after permissionless cleanup");
    let _ = r78;
    // seniors redeem in Resolved mode
    let mut senior_out = [0u128; 2];
    for (i, (k, ata)) in [(&s1, atas[0]), (&s2, atas[1])].into_iter().enumerate() {
        let shares = w.tok(&ata) as u128;
        if shares > 0 {
            w.request_redeem(k, ata, shares).unwrap_or_else(|e| panic!("H1: senior {i} request redeem after resolve: {e}"));
        }
        let (d, r) = w.execute_redeem(k, true);
        r.unwrap_or_else(|e| {
            let logs: Vec<&str> = e.split("\\\"").filter(|l| l.contains("Program log") || l.contains("failed")).collect();
            panic!("H1: senior {i} cannot exit after Resolve: code {:?} logs {:?}", code(&e), logs)
        });
        senior_out[i] = w.tok(&d) as u128;
    }
    // Junior's terminal payout AFTER the seniors: Resolved tag 102 for physical − C.
    let junior_102 = w.junior_release_resolved(&admin);
    eprintln!("   junior Resolved tag102 paid {junior_102}; vault left {}", w.tok(&w.env.vault));
    let junior_out = junior_out + junior_102;
    // No value stranded beyond the 1,000 dead-share atoms (+ rounding).
    assert!((w.tok(&w.env.vault) as u128) <= 2_000, "value stranded after every exit: vault {}", w.tok(&w.env.vault));
    // token conservation (every atom this test minted is somewhere or burned-accounted: no burns here)
    assert_eq!(w.held(), w.minted, "token conservation broke");
    let senior_total = senior_out[0] + senior_out[1];
    // no senior beats their NAV share: s1 has 6/10 of shares (both deposits at 1:1)
    assert!(senior_out[0] * 4 <= senior_out[1] * 6 + 6, "senior 1 got more than pro-rata: {senior_out:?}");
    assert!(senior_total <= c0, "seniors extracted more than C ({senior_total} > {c0})");
    eprintln!("H1 win_mark={win_mark} junior={junior}: C={c0} seniors={senior_out:?} junior_out={junior_out} trader_out={trader_out}");
    (c0, senior_total, junior_out, trader_out)
}


static IM_BPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(10_000);
thread_local! { static TL_IM: std::cell::Cell<u64> = std::cell::Cell::new(10_000); }
fn market_params() -> V16CuMarketParams {
    let im = TL_IM.with(|c| c.get());
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

fn run_exit(win_mark: u64, junior: u64, units_req: i128) -> (u128, u128, u128, u128, i128) {
    let s1 = Keypair::new();
    let s2 = Keypair::new();
    let (mut w, atas) = P3::bound(&[(&s1, 6_000_000), (&s2, 4_000_000)], junior, 1_000);
    let admin = w.env.admin.insecure_clone();
    let c0 = w.c();
    let (t, tp) = w.trader(20_000_000);
    let units = units_req;
    let open_r = w.trade_vs_lp(&t, tp, units * POS_SCALE as i128);
    let filled = w.env.portfolio_state(tp).legs.iter().find(|l| l.active).map(|l| l.basis_pos_q).unwrap_or(0);
    eprintln!("open {units} units -> {:?}, filled {}", open_r.as_ref().map_err(|e| code(e)), filled);
    w.push(win_mark);
    for _ in 0..3 {
        let _ = w.crank(tp);
        let _ = w.crank(w.lp);
    }
    w.env.resolve();
    // trader exits (CloseResolved permissionless, pays owner)
    let mut trader_out = 0u128;
    for _ in 0..4 {
        let d = w.token(t.pubkey(), 0);
        let (m, v, va) = (w.env.market, w.env.vault, w.env.vault_authority);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(t.pubkey(), false),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        trader_out += w.tok(&d) as u128;
        eprintln!("trader CloseResolved -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
    }
    // tag 30 (CloseResolved) on the vault LP must be refused (82): it would strand funds in a
    // registry-PDA-owned ATA (P3-H1 original shape).
    {
        let reg = w.registry;
        let d = w.token(reg, 0);
        let (m, v, va, lp) = (w.env.market, w.env.vault, w.env.vault_authority, w.lp);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(reg, false),
                AccountMeta::new(m, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        assert!(r.is_err() && w.tok(&d) == 0, "H1: CloseResolved paid the vault LP into a registry-owned ATA: {r:?}");
    }
    // settle the vault LP senior-first (tag 101), repeat until no progress
    let mut junior_out = 0u128;
    let mut settled = false;
    for topup in [0u8, 0, 1, 1] {
        let (d, r) = w.settle_resolved(admin.pubkey(), topup);
        junior_out += w.tok(&d) as u128;
        if r.is_ok() {
            settled = true;
        }
    }
    assert!(settled, "H1: tag 101 VaultLpSettleResolved never succeeded");
    for _ in 0..3 {
        let d = w.token(t.pubkey(), 0);
        let (m, v, va) = (w.env.market, w.env.vault, w.env.vault_authority);
        let r = w.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(t.pubkey(), false),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        trader_out += w.tok(&d) as u128;
        eprintln!("post-settle trader CloseResolved -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        let st = w.env.portfolio_state(tp);
        eprintln!("   trader capital {} pnl {} active {}", st.capital, st.pnl, st.legs.iter().any(|l| l.active));
    }
    // Liveness probe: can a senior exit BEFORE marketauth's terminal cleanup? (depends only on
    // permissionless steps so far: CloseResolved + tag 101)
    {
        let shares = w.tok(&atas[1]) as u128;
        w.request_redeem(&s2, atas[1], shares).expect("request");
        let (_d, r) = w.execute_redeem(&s2, true);
        eprintln!("H1-liveness: senior redemption before marketauth ClosePortfolio cleanup -> {:?}", r.as_ref().map_err(|e| code(e)));
        if r.is_ok() {
            eprintln!("H1-liveness: seniors can exit without marketauth");
        }
        // put shares back for the pro-rata check below if the request escrowed them
    }
    // Keeper terminal sequence (P3 doc §128, F-14 head): permissionless tag 8 of the empty
    // trader and the vault LP, then Resolved tag 78 (terminal-flat). No marketauth involved.
    let _ = w.terminal_cleanup(&[(tp, t.pubkey())]);
    let (_, g) = w.env.market_state();
    assert_eq!(g.materialized_portfolio_count, 0, "terminal-flat after permissionless cleanup");
    // seniors redeem in Resolved mode
    let mut senior_out = [0u128; 2];
    for (i, (k, ata)) in [(&s1, atas[0]), (&s2, atas[1])].into_iter().enumerate() {
        let shares = w.tok(&ata) as u128;
        if shares > 0 {
            w.request_redeem(k, ata, shares).unwrap_or_else(|e| panic!("H1: senior {i} request redeem after resolve: {e}"));
        }
        let (d, r) = w.execute_redeem(k, true);
        r.unwrap_or_else(|e| {
            let logs: Vec<&str> = e.split("\\\"").filter(|l| l.contains("Program log") || l.contains("failed")).collect();
            panic!("H1: senior {i} cannot exit after Resolve: code {:?} logs {:?}", code(&e), logs)
        });
        senior_out[i] = w.tok(&d) as u128;
    }
    // Junior's terminal payout AFTER the seniors: Resolved tag 102 for physical − C.
    let junior_102 = w.junior_release_resolved(&admin);
    eprintln!("   junior Resolved tag102 paid {junior_102}; vault left {}", w.tok(&w.env.vault));
    let junior_out = junior_out + junior_102;
    assert!((w.tok(&w.env.vault) as u128) <= 2_000, "value stranded after every exit: vault {}", w.tok(&w.env.vault));
    // token conservation (every atom this test minted is somewhere or burned-accounted: no burns here)
    assert_eq!(w.held(), w.minted, "token conservation broke");
    // Late settlement attempts: can the junior still collect whatever V - senior remains?
    let mut late = 0u128;
    for topup in [0u8, 1, 0, 1] {
        let (d, r) = w.settle_resolved(admin.pubkey(), topup);
        late += w.tok(&d) as u128;
        eprintln!("   late tag101(topup {topup}) -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
    }
    let junior_out = junior_out + late;
    let senior_total = senior_out[0] + senior_out[1];
    eprintln!("   exit detail mark {win_mark}: junior_out {junior_out} trader_out {trader_out} seniors {senior_out:?} vault_left {}", w.tok(&w.env.vault));
    // no senior beats their NAV share: s1 has 6/10 of shares (both deposits at 1:1)
    assert!(senior_out[0] * 4 <= senior_out[1] * 6 + 6, "senior 1 got more than pro-rata: {senior_out:?}");
    assert!(senior_total <= c0, "seniors extracted more than C ({senior_total} > {c0})");
    eprintln!("H1 win_mark={win_mark} junior={junior}: C={c0} seniors={senior_out:?} junior_out={junior_out} trader_out={trader_out}");
    (c0, senior_total, junior_out, trader_out, filled)
}


impl P3 {
    fn set_risk_full(&mut self, signer: &Keypair, slope: u64, max: u64, lev_cap_q: u128, lev_max_imr: u16, max_lev_bps: u32) -> Result<u64, String> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&slope.to_le_bytes());
        b.extend_from_slice(&max.to_le_bytes());
        b.extend_from_slice(&lev_cap_q.to_le_bytes());
        b.extend_from_slice(&lev_max_imr.to_le_bytes());
        b.extend_from_slice(&max_lev_bps.to_le_bytes());
        b.extend_from_slice(self.matcher.as_ref());
        let metas = vec![AccountMeta::new(signer.pubkey(), true), AccountMeta::new_readonly(self.program_data, false), AccountMeta::new(self.env.market, false)];
        self.send_raw(raw(99, &b), metas, &[signer])
    }
    fn bound_with(seniors: &[(&Keypair, u64)], junior: u64, im_bps: u64, slope: u64, max: u64, lev_cap_q: u128, lev_max_imr: u16, max_lev_bps: u32) -> (Self, Vec<Pubkey>) {
        TL_IM.with(|c| c.set(im_bps));
        let mut w = P3::new();
        TL_IM.with(|c| c.set(10_000));
        w.create_vault();
        let mut atas = Vec::new();
        for (k, amt) in seniors {
            atas.push(w.earn_deposit(k, *amt, false).expect("75 senior deposit"));
        }
        let admin = w.env.admin.insecure_clone();
        w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
        let up = w.upgrade.insecure_clone();
        w.set_risk_full(&up, slope, max, lev_cap_q, lev_max_imr, max_lev_bps).unwrap_or_else(|e| panic!("99: {e}"));
        if std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") { w.set_matcher(&up).unwrap_or_else(|e| panic!("95: {e}")); }
        if junior > 0 {
            w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96: {e}"));
        }
        (w, atas)
    }
    fn pos(&self, p: Pubkey) -> i128 {
        self.env.portfolio_state(p).legs.iter().find(|l| l.active && l.asset_index == 0).map(|l| l.basis_pos_q).unwrap_or(0)
    }
    fn pnl_cap(&self, p: Pubkey) -> i128 {
        let s = self.env.portfolio_state(p);
        s.capital as i128 + s.pnl
    }
    fn hold_and_crank(&mut self, slots: u64, ports: &[Pubkey]) {
        let mut left = slots;
        while left > 0 {
            let step = left.min(20);
            let s = self.slot() + step;
            self.env.svm.warp_to_slot(s);
            self.env.push_auth_mark_for_asset_as_admin(0, s, PRICE);
            for p in ports {
                let _ = self.crank(*p);
            }
            left -= step;
        }
    }
}

const U: i128 = POS_SCALE as i128;

// ═════════════ Gap 2: creator free option on seniors, end to end ═════════════

/// P3-H2 end to end. The creator owns the junior tranche (tag 94 signer) AND a second
/// trader wallet. Payoff to the creator = trader P&L + junior payout. If the creator's trader
/// wins, the junior pays first; if it loses, the junior (the creator's own) receives it. The
/// "free option" is: creator net > 0 while seniors lose. Design claim (§2.2): seniors are hit
/// only after the junior is exhausted, and the creator cannot profit at seniors' expense.
/// Asserted across sizes and moves: NOT (creator_net > 0 AND senior_loss > rounding).
#[test]
fn p1p3_creator_cannot_profit_at_seniors_expense_across_moves() {
    let junior: u64 = 3_000_000;
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for &(units, mark) in &[(3i128, 1_300_000u64), (3, 2_000_000), (3, 700_000), (20, 1_300_000), (20, 2_000_000), (50, 3_000_000)] {
        let (c0, seniors, junior_out, trader_out, filled) = run_exit(mark, junior, units);
        let creator_net = junior_out as i128 + trader_out as i128 - junior as i128 - 20_000_000;
        let senior_loss = c0 as i128 - seniors as i128;
        rows.push(format!("units_req {units} filled {} mark {mark}: creator_net {creator_net} senior_loss {senior_loss}", filled / U));
        if creator_net > 0 && senior_loss > 2_000 {
            bad.push(rows.last().unwrap().clone());
        }
        STRANDED.with(|c| c.set(0));
    }
    eprintln!("free-option table:\n  {}", rows.join("\n  "));
    assert!(bad.is_empty(), "P3-H2 creator free option: creator profited while seniors lost:\n  {}", bad.join("\n  "));
}

/// F-2 shape under P3: the vault LP is owned by the registry PDA, so the creator holds no key
/// that can co-sign a TradeNoCpi against it.
#[test]
fn p1p3_creator_cannot_tradenocpi_against_the_vault_lp() {
    let s1 = Keypair::new();
    let (mut w, _atas) = P3::bound(&[(&s1, 10_000_000)], 3_000_000, 1_000);
    let admin = w.env.admin.insecure_clone();
    let (t, tp) = w.trader(20_000_000);
    let lp = w.lp;
    w.env.svm.expire_blockhash();
    let r = w.env.try_trade_asset_with_cu(0, &t, tp, &admin, lp, 5 * U, PRICE, 0);
    eprintln!("NoCpi vs vault LP signed by creator -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert!(r.is_err(), "creator co-signed a TradeNoCpi against the vault LP");
    assert_eq!(w.pos(lp), 0);
}

// ═════════════ Gap 6: skew funding, leverage step-down, tranche first-depositor ═════════════

/// §0.2/§2.3: with the vault LP short (traders crowded long), rate > 0 so longs pay; the
/// payment is zero-sum (trader loss == vault LP gain, ± engine flooring) and bounded by
/// min(skew_max, max_abs_funding) per slot.
#[test]
fn p3_skew_funding_crowded_side_pays_thin_side_zero_sum_and_bounded() {
    let s1 = Keypair::new();
    let slope: u64 = 1_000;
    let max: u64 = 1_000;
    let (mut w, _a) = P3::bound_with(&[(&s1, 10_000_000)], 20_000_000, 1_000, slope, max, 0, 0, 50_000);
    let (t, tp) = w.trader(20_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).expect("trader long 3 vs vault LP");
    let lp = w.lp;
    assert!(w.pos(lp) < 0, "vacuity: vault LP short");
    let t0 = w.pnl_cap(tp);
    let l0 = w.pnl_cap(lp);
    let slots = 200u64;
    w.hold_and_crank(slots, &[tp, lp]);
    let dt = w.pnl_cap(tp) - t0;
    let dl = w.pnl_cap(lp) - l0;
    let bound = (3 * PRICE as i128) * max as i128 * slots as i128 / 1_000_000_000;
    eprintln!("skew funding over {slots} slots: trader {dt}, vault LP {dl}, |bound| {bound}");
    assert!(dt <= 0, "crowded long must PAY, got {dt}");
    assert!(dl >= 0, "thin-side LP must RECEIVE, got {dl}");
    assert!((dt + dl).abs() <= 3, "funding not zero-sum: trader {dt} + LP {dl}");
    assert!(-dt <= bound + 3, "funding {} above max-rate bound {bound}", -dt);
    assert!(dt < 0, "vacuity: skew funding must actually flow (slope {slope})");
}

/// Sign flip: vault LP long (traders crowded short) ⇒ shorts pay.
#[test]
fn p3_skew_funding_sign_flips_with_lp_side() {
    let s1 = Keypair::new();
    let (mut w, _a) = P3::bound_with(&[(&s1, 10_000_000)], 20_000_000, 1_000, 1_000, 1_000, 0, 0, 50_000);
    let (t, tp) = w.trader(20_000_000);
    w.trade_vs_lp(&t, tp, -3 * U).expect("trader short 3");
    let lp = w.lp;
    let t0 = w.pnl_cap(tp);
    w.hold_and_crank(200, &[tp, lp]);
    let dt = w.pnl_cap(tp) - t0;
    eprintln!("crowded short pays: {dt}");
    assert!(dt < 0, "crowded short must pay when the vault LP is long, got {dt}");
}

/// §2.4 leverage step-down: once |lp_net| exceeds N_cap, a crowd-joining fill needs
/// step_imr > base_imr; thin-side (reducing) trades keep base leverage.
#[test]
fn p3_leverage_step_down_tightens_crowd_joining_opens_only() {
    let s1 = Keypair::new();
    // base IM 10%; N_cap = 2 units; max step IMR 50%.
    let (mut w, _a) = P3::bound_with(&[(&s1, 10_000_000)], 20_000_000, 1_000, 0, 0, (2 * U) as u128, 5_000, 50_000);
    let (t, tp) = w.trader(1_500_000); // base 10% => 15 units; 50% => 3 units
    w.trade_vs_lp(&t, tp, U).expect("1 unit at base leverage");
    let r = w.trade_vs_lp(&t, tp, 3 * U);
    eprintln!("grow to 4 units with lp_net 4 > N_cap 2 -> {:?}, pos {}", r.as_ref().map_err(|e| code(e)), w.pos(tp) / U);
    assert!(w.pos(tp) <= 3 * U, "step-down not applied: taker reached {} units on 1.5M equity at step IMR 50%", w.pos(tp) / U);
    // Crowd the book: a well-capitalised trader takes the LP to -10 (step applies; it can afford 50%).
    let (big, bp) = w.trader(20_000_000);
    w.trade_vs_lp(&big, bp, 9 * U).expect("big trader long 9 (step IMR 50% on 20M is fine)");
    let lpn = w.pos(w.lp);
    eprintln!("lp_net after crowding: {}", lpn / U);
    // Thin side: 1M equity shorts 8 units (LP -10 -> -2, REDUCES |lp_net|): needs base 10% = 0.8M.
    let (t2, tp2) = w.trader(1_000_000);
    let r2 = w.trade_vs_lp(&t2, tp2, -8 * U);
    eprintln!("thin-side short 8 on 1.0M -> {:?}, pos {}", r2.as_ref().map_err(|e| code(e)), w.pos(tp2) / U);
    assert!(r2.is_ok() && w.pos(tp2) == -8 * U, "thin-side (LP-reducing) trade must keep base leverage: {:?}", r2.as_ref().map_err(|e| code(e)));
}

/// §0.2 deposit price: genesis senior deposit refused while H (harvestable LP fees) > 0 on a
/// bound vault — otherwise the first senior captures the pre-existing fee backlog (F5 under P3).
#[test]
fn p3_tranche_genesis_senior_cannot_capture_fee_backlog() {
    let mut w = P3::new();
    w.create_vault();
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).expect("94");
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).expect("99");
    w.set_matcher(&up).expect("95");
    w.junior_deposit(&admin, 5_000_000).expect("96");
    let (a, pa) = w.trader(20_000_000);
    let (b, pb) = w.trader(20_000_000);
    // P3-g (F-14 head): NoCpi between two traders that GROWS either side on the bound asset is
    // refused 77 — the vault LP is the exclusive counterparty.
    w.env.svm.expire_blockhash();
    let nocpi = w.env.try_trade_asset_with_cu(0, &a, pa, &b, pb, 5 * U, PRICE, 30);
    eprintln!("NoCpi growth between traders on the bound asset -> {:?}", nocpi.as_ref().map_err(|e| code(e)));
    assert_eq!(nocpi.as_ref().err().and_then(|e| code(e)), Some(77), "P3-g: NoCpi growth on a bound asset must be refused 77");
    // fee-bearing round trips against the vault LP (TradeCpi pins the fee to the market base
    // fee, so set a 30 bps base; the LP leg (48%) accrues as the backlog)
    w.env.svm.expire_blockhash();
    w.env.update_trade_fee_policy_with_cu(30);
    for i in 0..5 {
        let lp = w.lp;
        let _ = w.crank(pa);
        let _ = w.crank(lp);
        let r1 = w.trade_vs_lp_fee(&a, pa, U, 30);
        let _ = w.crank(lp);
        let r2 = w.trade_vs_lp_fee(&a, pa, -U, 30);
        if i == 0 {
            eprintln!("fee round trip vs vault LP -> {:?} / {:?}", r1.as_ref().map_err(|e| code(e)), r2.as_ref().map_err(|e| code(e)));
        }
    }
    let (cfg, _) = w.env.market_state();
    let backlog = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(backlog > 0, "vacuity: LP fee backlog");
    let s1 = Keypair::new();
    let r = w.earn_deposit(&s1, 1_000_000, true);
    eprintln!("genesis senior deposit with backlog {backlog}: {:?}", r.as_ref().map(|_| ()).map_err(|e| code(e)));
    if let Ok(ata) = r {
        // if accepted, the senior must not be able to redeem more than it deposited
        let shares = w.tok(&ata) as u128;
        w.request_redeem(&s1, ata, shares).expect("request");
        let (d, rr) = w.execute_redeem(&s1, true);
        eprintln!("redeem -> {:?} paid {}", rr.as_ref().map_err(|e| code(e)), w.tok(&d));
        assert!(w.tok(&d) as u128 <= 1_000_000, "first senior captured {} of the backlog", w.tok(&d) as i128 - 1_000_000);
    }
}

/// Donation inflation: tokens sent straight to the market vault before/after the first senior
/// deposit must not change share pricing (the engine ignores unbooked tokens), so a second
/// senior is not diluted and the first cannot redeem the donation.
#[test]
fn p3_tranche_donation_does_not_inflate_or_dilute_seniors() {
    let s1 = Keypair::new();
    let s2 = Keypair::new();
    let (mut w, atas) = P3::bound(&[(&s1, 1_000_000)], 3_000_000, 1_000);
    // attacker donates 5M directly to the vault token account
    let v = w.env.vault;
    let mut acct = w.env.svm.get_account(&v).unwrap();
    {
        use solana_sdk::program_pack::Pack;
        let mut ta = spl_token::state::Account::unpack(&acct.data).unwrap();
        ta.amount += 5_000_000;
        spl_token::state::Account::pack(ta, &mut acct.data).unwrap();
    }
    w.env.svm.set_account(v, acct).unwrap();
    w.minted += 5_000_000;
    let ata2 = w.earn_deposit(&s2, 1_000_000, true).expect("second senior deposit");
    let sh1 = w.tok(&atas[0]) as u128;
    let sh2 = w.tok(&ata2) as u128;
    eprintln!("shares: first {sh1} (+1000 dead), second {sh2}");
    assert!(sh2 + 1 >= sh1 + DEAD - 1 && sh2 <= sh1 + DEAD + 1, "second senior diluted/inflated by donation: {sh2} vs {}", sh1 + DEAD);
    w.request_redeem(&s1, atas[0], sh1).expect("request");
    let (d, r) = w.execute_redeem(&s1, true);
    eprintln!("first senior redeem -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
    assert!(w.tok(&d) as u128 <= 1_000_000, "first senior redeemed part of the donation: {}", w.tok(&d));
}

thread_local! { static STRANDED: std::cell::Cell<u128> = std::cell::Cell::new(0); }

/// P3 §2.2: V = senior + junior, and at resolution tag 101 pays "residual SPL to the junior
/// owner". When the vault LP WINS (trader loses), the win belongs to the junior (C fixed).
/// After every party has exited (trader, junior settle, seniors, cleanup) no value may be left
/// stranded in the market vault beyond the 1,000 dead-share atoms.
#[test]
fn p3_vault_lp_win_reaches_junior_at_resolution_not_stranded() {
    let junior: u64 = 3_000_000;
    let (c0, seniors, junior_out, trader_out, filled) = run_exit(700_000, junior, 3);
    let trader_loss = 20_000_000i128 - trader_out as i128;
    let junior_gain = junior_out as i128 - junior as i128;
    eprintln!("LP win: trader lost {trader_loss}, junior gained {junior_gain}, seniors {seniors} of C {c0}, filled {}", filled / U);
    assert!(trader_loss > 0, "vacuity: trader must lose");
    assert!(
        junior_gain + 2_000 >= trader_loss,
        "P3: vault LP's win of {trader_loss} did not reach the junior (junior gained {junior_gain}); value stranded in the vault"
    );
}

impl P3 {
    fn close_resolved_trader(&mut self, t: &Keypair, tp: Pubkey) -> u128 {
        let d = self.token(t.pubkey(), 0);
        let (m, v, va) = (self.env.market, self.env.vault, self.env.vault_authority);
        let _ = self.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new_readonly(t.pubkey(), false),
                AccountMeta::new(m, false),
                AccountMeta::new(tp, false),
                AccountMeta::new(d, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&m), false),
            ],
            &[],
        );
        self.tok(&d) as u128
    }
}

fn lp_win_order(order: &str) -> (i128, i128, u128) {
    let s1 = Keypair::new();
    let (mut w, _atas) = P3::bound(&[(&s1, 10_000_000)], 3_000_000, 1_000);
    let admin = w.env.admin.insecure_clone();
    let (t, tp) = w.trader(20_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).expect("open");
    w.push(700_000);
    for _ in 0..3 {
        let _ = w.crank(tp);
        let lp = w.lp;
        let _ = w.crank(lp);
    }
    w.env.resolve();
    let mut trader_out = 0u128;
    let mut junior_out = 0u128;
    let mut settle = |w: &mut P3, junior_out: &mut u128| {
        for topup in [0u8, 0, 1, 1] {
            let (d, r) = w.settle_resolved(admin.pubkey(), topup);
            *junior_out += w.tok(&d) as u128;
            let _ = r;
        }
    };
    match order {
        "trader_first" | "trader_first_release" => {
            for _ in 0..3 { trader_out += w.close_resolved_trader(&t, tp); let s = w.slot() + 50; w.env.svm.warp_to_slot(s); }
            if order == "trader_first_release" {
                for d in [0u16, 1] {
                    let mut b = Vec::new();
                    b.extend_from_slice(&900_000u128.to_le_bytes());
                    b.extend_from_slice(&d.to_le_bytes());
                    let metas = vec![
                        AccountMeta::new(admin.pubkey(), true),
                        AccountMeta::new(w.env.market, false),
                        AccountMeta::new_readonly(w.registry, false),
                        AccountMeta::new(w.state_pda, false),
                        AccountMeta::new(w.lp, false),
                        AccountMeta::new(w.ledger0, false),
                        AccountMeta::new(w.ledger1, false),
                    ];
                    let r = w.send_raw(raw(102, &b), metas, &[&admin]);
                    eprintln!("   tag102 ReleaseSurplus(900k, domain {d}) -> {:?}", r.as_ref().map_err(|e| code(e)));
                }
            }
            settle(&mut w, &mut junior_out);
            for _ in 0..2 { trader_out += w.close_resolved_trader(&t, tp); }
        }
        "settle_first_then_again" => {
            settle(&mut w, &mut junior_out);
            for _ in 0..3 { trader_out += w.close_resolved_trader(&t, tp); let s = w.slot() + 50; w.env.svm.warp_to_slot(s); }
            settle(&mut w, &mut junior_out);
        }
        _ => unreachable!(),
    }
    // F-14 head: 101 moves no SPL. Keeper terminal sequence, then the junior's Resolved 102.
    let _ = w.terminal_cleanup(&[(tp, t.pubkey())]);
    junior_out += w.junior_release_resolved(&admin);
    let vault_left = w.tok(&w.env.vault) as u128;
    eprintln!("order {order}: trader_out {trader_out} junior_out {junior_out} vault_left {vault_left}");
    (20_000_000 - trader_out as i128, junior_out as i128 - 3_000_000, vault_left)
}

/// Ordering control for the stranded-win finding: tag 101 is permissionless, so if the win only
/// reaches the junior when the TRADER closes first, any stranger calling 101 early strands it.
#[test]
fn p3_vault_lp_win_reaches_junior_trader_first_order() {
    let (loss, gain, left) = lp_win_order("trader_first");
    assert!(loss > 0);
    assert!(gain + 2_000 >= loss, "trader-first: junior gained {gain} of the LP's {loss} win (vault left {left})");
}

#[test]
fn p3_vault_lp_win_reaches_junior_when_settled_again_after_trader_close() {
    let (loss, gain, left) = lp_win_order("settle_first_then_again");
    assert!(loss > 0);
    assert!(gain + 2_000 >= loss, "settle-first: junior gained {gain} of the LP's {loss} win even after a second tag 101 (vault left {left})");
}

#[test]
fn p3_vault_lp_win_reaches_junior_via_release_surplus_then_settle() {
    let (loss, gain, left) = lp_win_order("trader_first_release");
    assert!(loss > 0);
    assert!(gain + 2_000 >= loss, "with tag 102 ReleaseSurplus: junior gained {gain} of the LP's {loss} win (vault left {left})");
}

/// Control (Live): same LP win, but the trader closes while Live; the junior withdraws. Shows
/// whether the win is reachable at all (then the stranding is resolution-path specific).
#[test]
fn p3_control_vault_lp_win_is_withdrawable_by_junior_while_live() {
    let s1 = Keypair::new();
    let (mut w, _atas) = P3::bound(&[(&s1, 10_000_000)], 3_000_000, 1_000);
    let admin = w.env.admin.insecure_clone();
    let (t, tp) = w.trader(20_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).expect("open");
    w.push(700_000);
    for _ in 0..4 {
        let _ = w.crank(tp);
        let lp = w.lp;
        let _ = w.crank(lp);
    }
    let r = w.trade_vs_lp(&t, tp, -3 * U);
    eprintln!("live close -> {:?}; LP pos {} cap {} pnl {}", r.as_ref().map_err(|e| code(e)), w.pos(w.lp), w.env.portfolio_state(w.lp).capital, w.env.portfolio_state(w.lp).pnl);
    let lp = w.lp;
    let _ = w.crank(lp);
    let mut got = 0u128;
    for amt in [3_800_000u128, 3_000_000, 2_900_000, 2_000_000] {
        let (d, rr) = w.junior_withdraw(&admin, admin.pubkey(), amt);
        eprintln!("junior withdraw {amt} -> {:?}", rr.as_ref().map_err(|e| code(e)));
        if rr.is_ok() {
            got = w.tok(&d) as u128;
            break;
        }
    }
    eprintln!("junior withdrew {got} (deposit 3,000,000; LP won 900,000; floor 10% of C)");
    assert!(got > 2_000_000, "vacuity/control: junior could not withdraw anything live");
}
