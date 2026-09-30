//! INDEPENDENT SUITE (2026-09-30) — P3 vault-owned LP, from the DESIGN DOC only
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
        let matcher = if std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") { Pubkey::new_unique() } else { std::env::var("INDEP_CANONICAL_MATCHER").unwrap_or_else(|_| "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT".to_string()).as_str().parse::<Pubkey>().unwrap() };
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
#[test]
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
#[test]
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

#[test]
fn indep_p3_h1_resolved_exit_junior_covers_loss() {
    // loss 10% of 3 units notional = 300k < junior 3M: seniors whole, junior gets the rest
    let (c0, seniors, junior_out, _t) = run_h1(1_100_000, 3_000_000);
    assert!(seniors + 2_000 >= c0, "seniors must be whole when the junior covers the loss: {seniors} vs C {c0}");
    assert!(junior_out > 0 && junior_out <= 3_000_000, "junior residual {junior_out}");
}

#[test]
fn indep_p3_h1_resolved_exit_loss_exceeds_junior() {
    // junior 1M backing 1 unit; mark x3 => LP loses 2M > junior: seniors absorb the excess
    let (c0, seniors, junior_out, _t) = run_h1(3_000_000, 1_000_000);
    assert_eq!(junior_out, 0, "junior must be wiped before seniors take any loss");
    assert!(seniors <= c0, "seniors paid > C");
    assert!(seniors + 1_000_000 + 2_000 >= c0, "senior loss must be at most (loss - junior) ~1M: seniors {seniors} C {c0}");
}

/// H1 liveness (security-review ask: "seniors must be able to exit after Resolve"): using ONLY
/// permissionless steps (CloseResolved, tag 101) plus the senior's own signature — no
/// marketauth cleanup, no cooperation from the (paid-out) trader — a senior must be able to
/// redeem. A walked-away trader leaves an empty materialized portfolio behind.
#[test]
fn indep_p3_h1_senior_exit_needs_no_marketauth_or_trader_cooperation() {
    let s1 = Keypair::new();
    let (mut w, atas) = P3::bound(&[(&s1, 10_000_000)], 3_000_000, 1_000);
    let admin = w.env.admin.insecure_clone();
    let (t, tp) = w.trader(20_000_000);
    w.trade_vs_lp(&t, tp, POS_SCALE as i128).unwrap();
    w.push(1_050_000);
    let _ = w.crank(tp);
    let _ = w.crank(w.lp);
    w.env.resolve();
    let close = |w: &mut P3| {
        let d = w.token(t.pubkey(), 0);
        let (m, v, va) = (w.env.market, w.env.vault, w.env.vault_authority);
        let _ = w.send(
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
    };
    close(&mut w);
    for topup in [0u8, 0, 1] {
        let _ = w.settle_resolved(admin.pubkey(), topup);
    }
    close(&mut w);
    // a stranger may try to free the empty portfolios (permissionless reclaim, if any)
    let stranger = Keypair::new();
    w.env.ensure_signer_account(stranger.pubkey());
    for p in [tp, w.lp] {
        let (pid, seq, ep) = w.env.portfolio_identity(p);
        let m = w.env.market;
        // P3 e8366978 (F-4 fix): in Resolved mode anyone may deregister an EMPTY portfolio if
        // optional account [3] is its owner (rent returns there). Older builds ignore [3].
        let owner = Pubkey::new_from_array(w.env.portfolio_state(p).owner);
        let r = w.send(
            ProgInstruction::ClosePortfolio { portfolio_id: pid, expected_sequence: seq, position_epoch: ep },
            vec![AccountMeta::new(stranger.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false), AccountMeta::new(owner, false)],
            &[&stranger],
        );
        eprintln!("stranger ClosePortfolio -> {:?}", r.as_ref().map_err(|e| code(e)));
    }
    let shares = w.tok(&atas[0]) as u128;
    w.request_redeem(&s1, atas[0], shares).expect("request");
    let (d, r) = w.execute_redeem(&s1, true);
    let (_, g) = w.env.market_state();
    assert!(
        r.is_ok(),
        "H1 LIVENESS: senior cannot redeem after Resolve without marketauth ClosePortfolio cleanup \
         (materialized portfolios {}; err {:?}) — a burned/uncooperative marketauth or a walked-away \
         trader locks every senior",
        g.materialized_portfolio_count,
        r.as_ref().err().map(|e| code(e))
    );
    assert!(w.tok(&d) > 0);
}
