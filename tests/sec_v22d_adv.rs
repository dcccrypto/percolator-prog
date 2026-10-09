// Phase 4 Wave D item 6 (insurance units, tag 116; G9 backstop, tag 111) and bound-vault item 5 checks.
// P3 harness COPIED UNCHANGED from tests/p3_senior_draw.rs lines 1-1470 (struct P3, q1_world,
// underwater_world, ...); new tests at the end of this file.
//! P3 senior-draw FINAL acceptance tests (2026-09-30).
//!
//! The P3 harness below (struct `P3` and its helpers, `q1_world`, `lossrule_exit`, ...) is COPIED
//! UNCHANGED from the independent lane's `tests/indep_p3_f14q.rs` @ c91f36b7 (credit: independent
//! test lane); its own #[test]s are disabled here (they run from the lane's file). New tests are at
//! the end of this file. Run with INDEP_WRAPPER_SO=target/deploy/percolator_prog.so.
#![cfg(not(kani))]
#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::all)]
//! INDEPENDENT SUITE (2026-09-30) — P3 security items F14-Q1 / F14-Q2 (Sentinel), written from the
//! security finding text, not the fix:
//!   Q1: bound-vault NAV = per-domain NAV with impairment FLOORED at each domain's principal, then
//!       SUMMED — overstates cover when one domain's impairment > its principal while the other is
//!       positive. Required: every NAV consumer (97, Live 102, 77, 75) behaves as if
//!       cover = min(floored NAV, physical backing).
//!   Q2: tag 94 refuses a vault-LP bind on a multi-asset market; activating a second asset on a
//!       market with a bound vault is refused.
//! P3 helpers copied from indep_p1p3_combined.rs (07a1d0eb+ auto-pin flow).
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
                AccountMeta::new_readonly(self.env.mint, false), // [6] collateral mint (prog#542)
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
            public_b_chunk_atoms: TL_BCHUNK.with(|c| c.get()),
            ..V16CuMarketParams::default()
        }
    }
}
// (Anvil, copy only) C-7: the seeded market's small public B chunk makes a large bankrupt
// residual exceed the single-step capacity, which is the engine's IMMEDIATE-Recovery path.
thread_local! { static C7_BCHUNK: std::cell::Cell<u128> = const { std::cell::Cell::new(50_000) }; }
thread_local! { static TL_BCHUNK: std::cell::Cell<u128> = const { std::cell::Cell::new(percolator::MAX_VAULT_TVL) }; }

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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn q2_control_single_asset_market_binds() {
    let mut w = P3::new();
    w.create_vault();
    let s = Keypair::new();
    w.earn_deposit_domain(&s, 1_000_000, false, 0).expect("75");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).expect("94 binds on a single-asset market");
}

/// 94 must refuse on a multi-asset market (capacity 2), with no state change.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
fn lossrule_winner_paid_in_full_seniors_absorb_exact_shortfall_pro_rata() {
    let (d0, d1, junior) = (9_000_000u64, 1_000_000u64, 1_000_000u64);
    let (mut w, seniors, (t, tp)) = q1_world(d0, d1, junior, 6);
    let t0 = w.env.portfolio_state(tp);
    let (cap0, pnl0) = (t0.capital, t0.pnl.max(0) as u128);
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
#[allow(dead_code)]
fn lossrule_hlock_only_after_seniors_exhausted() {
    let (w, _s, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let g = w.env.market_state().1;
    eprintln!("lossrule big seniors: hlock {} loss_stale {}", g.bankruptcy_hlock_active, g.loss_stale_active);
    assert!(!g.bankruptcy_hlock_active, "RULE: seniors (C 10M) cover a ~1.6M shortfall, so no bankruptcy h-lock");
    let (w2, _s2, (_t2, tp2)) = q1_world(200_000, 100_000, 100_000, 6);
    let g2 = w2.env.market_state().1;
    let pnl = w2.env.portfolio_state(tp2).pnl;
    eprintln!("lossrule tiny seniors: hlock {} trader pnl {pnl} C {}", g2.bankruptcy_hlock_active, w2.c());
    // Vacuity: the loss must exceed junior + seniors for the second leg to mean anything.
    assert!(pnl as i128 > 400_000, "vacuity: loss must exceed junior + seniors");
    assert!(g2.bankruptcy_hlock_active || g2.loss_stale_active, "RULE: once junior + seniors are exhausted, the bankrupt/h-lock path is reachable");
}

// ═════════════════════════ P3 senior-draw FINAL acceptance tests (Anvil) ═════════════════════════

fn st_u128(w: &P3, off: usize) -> u128 {
    u128::from_le_bytes(w.state()[16 + off..16 + off + 16].try_into().unwrap())
}
/// VaultLpStateV18: C @128, senior_drawn @224, senior_draw_outstanding @240.
fn drawn(w: &P3) -> u128 { st_u128(w, 224) }
fn outstanding(w: &P3) -> u128 { st_u128(w, 240) }

/// Conservation after every step: every minted token is held somewhere we track (the vault is in
/// the set), and the engine's vault counter equals the vault's SPL balance.
fn conserved(w: &P3, tag: &str) {
    let g = w.env.market_state().1;
    assert_eq!(w.held(), w.minted, "{tag}: tokens not conserved");
    assert_eq!(g.vault, w.tok(&w.env.vault) as u128, "{tag}: engine vault != SPL vault");
}

/// World with seniors (d0, d1), a junior, a long vs the vault LP and `pushes` +24% marks with ONLY
/// the trader cranked (the vault LP is NOT refreshed during the move). Returns before any close.
fn underwater_world(d0: u64, d1: u64, junior: u64, pushes: usize) -> (P3, Vec<(Keypair, Pubkey)>, (Keypair, Pubkey)) {
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    let a0 = w.earn_deposit_domain(&s0, d0, false, 0).expect("75 d0");
    let a1 = w.earn_deposit_domain(&s1, d1, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap();
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).unwrap();
    w.junior_deposit(&admin, junior).unwrap();
    let (t, tp) = w.trader(50_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).unwrap();
    MARK.with(|c| c.set(PRICE));
    for _ in 0..pushes {
        let m = MARK.with(|c| c.get()) * 124 / 100;
        MARK.with(|c| c.set(m));
        w.push(m);
        w.catch_up(&[tp], 30);
    }
    (w, vec![(s0, a0), (s1, a1)], (t, tp))
}

fn crank_lp_until_current(w: &mut P3) {
    // max_accrual_dt caps each crank's catch-up; crank at the same slot until the LP is touched.
    let lp = w.lp;
    for _ in 0..60 {
        let _ = w.crank(lp);
        if w.env.market_state().1.assets[0].slot_last >= w.slot() { break; }
    }
    let _ = w.crank(lp);
}

fn redeem_ro(w: &mut P3, who: &Keypair) -> Result<u64, String> {
    let red = state::derive_lp_redemption(&w.env.program_id, &w.registry, &who.pubkey()).0;
    let dest = w.token(who.pubkey(), 0);
    let payer = w.env.payer.pubkey();
    let metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(w.registry, false),
        AccountMeta::new(red, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(w.escrow, false),
        AccountMeta::new(w.env.vault, false),
        AccountMeta::new_readonly(w.env.vault_authority, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new(w.ledger1, false),
        AccountMeta::new(who.pubkey(), false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new_readonly(w.lp, false), // READ-ONLY vault LP (the SDK's shape)
    ];
    w.send(ProgInstruction::ExecuteRedemption { domain: 0 }, metas, &[])
}

fn recall(w: &mut P3, amount: u128) -> Result<u64, String> {
    let payer = w.env.payer.insecure_clone();
    let mut b = amount.to_le_bytes().to_vec();
    b.extend_from_slice(&0u16.to_le_bytes());
    let metas = vec![
        AccountMeta::new(payer.pubkey(), true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new_readonly(w.registry, false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new(w.lp, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new(w.ledger1, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];
    w.send_raw(raw(98, &b), metas, &[&payer])
}

// ═══════════════════════════════ Phase 4 Wave D: tags 116 / 111 / 112 ═══════════════════════════
//
// Spec: `~/percolator-ops/ledger/phase4-design-2026-10-05.md` item 6 (insurance units + G9) and
// item 5 (bound-vault rescue). Run with INDEP_WRAPPER_SO=target/deploy/percolator_prog.so.

const INS_REFUSED: u32 = 116;
const RESCUE_REFUSED_C: u32 = 114;
const RESCUE_FLOOR_C: u32 = 115;

fn units_pda(w: &P3) -> Pubkey {
    state::derive_insurance_units(&w.env.program_id, &w.env.market).0
}
fn units(w: &P3) -> Option<state::InsuranceUnitsV20> {
    w.env.svm.get_account(&units_pda(w)).and_then(|a| state::read_insurance_units(&a.data).ok())
}
fn p4_flags(w: &P3) -> u8 {
    let data = w.env.svm.get_account(&w.env.market).unwrap().data;
    state::read_asset_oracle_profile(&data, 0).unwrap()._padding0[1]
}
fn backstop_st(w: &P3) -> u64 {
    u64::from_le_bytes(w.state()[16 + 216..16 + 224].try_into().unwrap())
}
fn has(r: &Result<u64, String>, c: u32) -> bool {
    r.as_ref().err().map_or(false, |e| code(e) == Some(c))
}
fn set_units(w: &mut P3, f: impl FnOnce(&mut state::InsuranceUnitsV20)) {
    let k = units_pda(w);
    let mut acct = w.env.svm.get_account(&k).unwrap();
    let mut u = state::read_insurance_units(&acct.data).unwrap();
    f(&mut u);
    state::write_insurance_units(&mut acct.data, &u).unwrap();
    w.env.svm.set_account(k, acct).unwrap();
}

/// Tag 9 by the asset-0 insurance authority (the creator: admin), optionally with the units ledger.
fn top_up_9(w: &mut P3, amount: u64, with_units: bool) -> Result<u64, String> {
    let admin = w.env.admin.insecure_clone();
    let src = w.token(admin.pubkey(), amount);
    let authority_epoch = w.env.control_sequences(0).authority_epoch;
    let mut metas = vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(src, false),
        AccountMeta::new(w.env.vault, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ];
    if with_units {
        metas.push(AccountMeta::new(units_pda(w), false));
    }
    w.send(
        ProgInstruction::TopUpInsurance { market_id: 1, intent_id: next_intent_id(), amount: amount as u128, authority_epoch },
        metas,
        &[&admin],
    )
}

/// Tag 57 (asset 0) by `who` (the creator: admin), to a fresh token account it owns.
fn withdraw_57(w: &mut P3, amount: u128, with_units: bool) -> (Pubkey, Result<u64, String>) {
    let admin = w.env.admin.insecure_clone();
    let dest = w.token(admin.pubkey(), 0);
    let authority_epoch = w.env.insurance_withdraw_authority_epoch(0, &admin.pubkey());
    let market_id = state::read_market_trade_preflight(&w.env.svm.get_account(&w.env.market).unwrap().data, 0).unwrap().3;
    let mut metas = vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(dest, false),
        AccountMeta::new(w.env.vault, false),
        AccountMeta::new_readonly(w.env.vault_authority, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ];
    if with_units {
        metas.push(AccountMeta::new(units_pda(w), false));
    }
    let r = w.send(ProgInstruction::WithdrawInsuranceAsset { market_id, asset_index: 0, amount, authority_epoch }, metas, &[&admin]);
    (dest, r)
}

fn init_units(w: &mut P3) -> Result<u64, String> {
    let payer = w.env.payer.pubkey();
    let metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(units_pda(w), false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];
    w.send(ProgInstruction::InitInsuranceUnits, metas, &[])
}

fn backstop_111(w: &mut P3, mode: u8, max_amount: u128, with_units: bool) -> Result<u64, String> {
    let payer = w.env.payer.pubkey();
    let mut metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new_readonly(w.registry, false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new(w.lp, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new(w.ledger1, false),
    ];
    if with_units {
        metas.push(AccountMeta::new(units_pda(w), false));
    }
    w.send(ProgInstruction::InsuranceBackstopDraw { mode, max_amount }, metas, &[])
}

/// Tag 112 on the bound vault (tag-75 accounts + bound tail).
fn rescue_bound(w: &mut P3, who: &Keypair, amount: u64) -> Result<u64, String> {
    w.env.ensure_signer_account(who.pubkey());
    let ata = w.lp_share_ata(who.pubkey());
    let src = w.token(who.pubkey(), amount);
    let metas = vec![
        AccountMeta::new(who.pubkey(), true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new(w.registry, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(ata, false),
        AccountMeta::new(src, false),
        AccountMeta::new(w.env.vault, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(w.ledger1, false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new(w.lp, false),
    ];
    w.send(ProgInstruction::RescueDeposit { tranche: 0, amount, min_shares: 1 }, metas, &[who])
}



/// Seed insurance (creator), create the units ledger, and split the units 50/50 between the two
/// classes, so that pro-rata effects are visible on both.
fn seed_units(w: &mut P3, insurance: u64) {
    top_up_9(w, insurance, false).expect("seed insurance");
    init_units(w).expect("116");
    set_units(w, |u| {
        u.units_stake = u.units_total / 2;
        u.units_creator = u.units_total - u.units_stake;
    });
}





// ═══════════════════════ Phase 4 Wave D: cross-program stake v5 <-> wrapper ══════════════════════
//
// The REAL percolator-stake v5 `.so` (../percolator-stake/target/deploy, built with
// `--features devnet`, i.e. at VmpVUArR, the id this wrapper's devnet build pins) runs against the
// wrapper in the same LiteSVM. Stake pools are crafted at the exact v5 byte layout (480 B; the
// wrapper test crate does not link percolator-stake), then driven through real stake
// instructions: bind (19), burn (21), deposit with consent (1), sync (31), withdraw (2),
// propose/commit target (32/33), the removed flush (3).

const STAKE_PID: Pubkey = solana_sdk::pubkey!("A6DVNubvzMMETQinK6bipekkaTTrkUu2RMw2kBoJrdkE");
const ST_CONSENT_REQUIRED: u32 = 33;
const ST_DEPRECATED_V5: u32 = 34;
const ST_LIQUIDITY_BUFFER: u32 = 36;
const ST_SYNC_COOLDOWN: u32 = 37;
const ST_NOT_PROTOCOL_AUTHORITY: u32 = 39;

fn stake_so() -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../percolator-stake/target/deploy/percolator_stake.so");
    std::fs::read(&p).unwrap_or_else(|e| panic!("stake v5 .so required at {} ({e}); build percolator-stake feat/v22-stake-v5 with --features devnet", p.display()))
}

struct Pool {
    pda: Pubkey,
    vault_auth: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
}

fn sm_mint_data(authority: Pubkey) -> Vec<u8> {
    use solana_sdk::program_pack::Pack;
    let mut d = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint::pack(
        spl_token::state::Mint {
            mint_authority: solana_sdk::program_option::COption::Some(authority),
            supply: 0,
            decimals: 6,
            is_initialized: true,
            freeze_authority: solana_sdk::program_option::COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

/// A v5 StakePool for `w`'s market, crafted at the exact layout (state.rs const asserts:
/// slab@8, vault@136, percolator_program@224, pool_mode@280, _reserved@320, risk_mode@408, 480 B).
fn craft_pool(w: &mut P3, risk_mode: u8, cooldown_slots: u64) -> Pool {
    w.env.svm.add_program(STAKE_PID, &stake_so());
    let market = w.env.market;
    let (pda, pool_bump) = Pubkey::find_program_address(&[b"stake_pool", market.as_ref()], &STAKE_PID);
    let (vault_auth, va_bump) = Pubkey::find_program_address(&[b"vault_auth", pda.as_ref()], &STAKE_PID);
    let vault = w.env.token_account_for_mint(w.env.mint, vault_auth, 0);
    let lp_mint = Pubkey::new_unique();
    w.env.svm.set_account(lp_mint, Account { lamports: 1_000_000_000, data: sm_mint_data(vault_auth), owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    let mut d = vec![0u8; 480];
    d[0] = 1;
    d[1] = pool_bump;
    d[2] = va_bump;
    d[8..40].copy_from_slice(market.as_ref());
    d[40..72].copy_from_slice(w.env.admin.pubkey().as_ref());
    d[72..104].copy_from_slice(w.env.mint.as_ref());
    d[104..136].copy_from_slice(lp_mint.as_ref());
    d[136..168].copy_from_slice(vault.as_ref());
    d[184..192].copy_from_slice(&cooldown_slots.to_le_bytes());
    d[224..256].copy_from_slice(w.env.program_id.as_ref());
    d[320..328].copy_from_slice(b"SPOOL_V1");
    d[328] = 5;
    d[408] = risk_mode;
    d[409] = if risk_mode == 1 { 2 } else { 0 }; // consent version 2 (round 2)
    let target: u16 = if risk_mode == 1 { 5_000 } else { 0 };
    d[410..412].copy_from_slice(&target.to_le_bytes());
    d[412..414].copy_from_slice(&3_000u16.to_le_bytes());
    d[414..416].copy_from_slice(&500u16.to_le_bytes());
    d[440..448].copy_from_slice(&150u64.to_le_bytes());
    w.env.svm.set_account(pda, Account { lamports: 1_000_000_000, data: d, owner: STAKE_PID, executable: false, rent_epoch: 0 }).unwrap();
    Pool { pda, vault_auth, vault, lp_mint }
}

fn pool_u64(w: &P3, p: &Pool, off: usize) -> u64 {
    u64::from_le_bytes(w.env.svm.get_account(&p.pda).unwrap().data[off..off + 8].try_into().unwrap())
}

fn stake_send(w: &mut P3, data: Vec<u8>, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
    w.env.svm.expire_blockhash();
    let ix = Instruction { program_id: STAKE_PID, accounts: metas, data };
    send_raw_tx(&mut w.env.svm, &w.env.payer.insecure_clone(), ix, signers)
}

/// Bind (19) then burn the asset admin (21): the secure-bind sequence, after which no admin key
/// can rotate the insurance authority off the pool.
fn bind_and_burn(w: &mut P3, p: &Pool) {
    let admin = w.env.admin.insecure_clone();
    let (m, pid) = (w.env.market, w.env.program_id);
    stake_send(w, vec![19], vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new_readonly(p.pda, false), AccountMeta::new_readonly(p.vault_auth, false), AccountMeta::new(m, false), AccountMeta::new_readonly(pid, false)], &[&admin]).expect("stake 19 bind");
    stake_send(w, vec![21], vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(p.pda, false), AccountMeta::new_readonly(p.vault_auth, false), AccountMeta::new(m, false), AccountMeta::new_readonly(pid, false)], &[&admin]).expect("stake 21 burn");
}

struct Staker {
    k: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

fn staker(w: &mut P3, p: &Pool, amount: u64) -> Staker {
    let k = Keypair::new();
    w.env.ensure_signer_account(k.pubkey());
    let ata = w.token(k.pubkey(), amount);
    let lp_ata = w.env.token_account_for_mint(p.lp_mint, k.pubkey(), 0);
    Staker { k, ata, lp_ata }
}

fn stake_deposit(w: &mut P3, p: &Pool, s: &Staker, amount: u64, consent: Option<u8>) -> Result<u64, String> {
    let mut data = vec![1u8];
    data.extend_from_slice(&amount.to_le_bytes());
    if consent.is_some() {
        // v5 deposit consent wire (16 B): [1][amount][version 2][target 5,000][buffer 3,000][hysteresis 500]
        data.push(2u8);
        data.extend_from_slice(&5_000u16.to_le_bytes());
        data.extend_from_slice(&3_000u16.to_le_bytes());
        data.extend_from_slice(&500u16.to_le_bytes());
    }
    let dep = Pubkey::find_program_address(&[b"stake_deposit", p.pda.as_ref(), s.k.pubkey().as_ref()], &STAKE_PID).0;
    let (m, pid) = (w.env.market, w.env.program_id);
    let units = units_pda(w);
    let metas = vec![
        AccountMeta::new(s.k.pubkey(), true),
        AccountMeta::new(p.pda, false),
        AccountMeta::new(s.ata, false),
        AccountMeta::new(p.vault, false),
        AccountMeta::new(p.lp_mint, false),
        AccountMeta::new(s.lp_ata, false),
        AccountMeta::new_readonly(p.vault_auth, false),
        AccountMeta::new(dep, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(m, false),
        AccountMeta::new(units, false),
        AccountMeta::new_readonly(pid, false),
    ];
    let k = s.k.insecure_clone();
    stake_send(w, data, metas, &[&k])
}

fn stake_withdraw(w: &mut P3, p: &Pool, s: &Staker, lp: u64) -> Result<u64, String> {
    let mut data = vec![2u8];
    data.extend_from_slice(&lp.to_le_bytes());
    let dep = Pubkey::find_program_address(&[b"stake_deposit", p.pda.as_ref(), s.k.pubkey().as_ref()], &STAKE_PID).0;
    let (m, pid) = (w.env.market, w.env.program_id);
    let units = units_pda(w);
    let metas = vec![
        AccountMeta::new(s.k.pubkey(), true),
        AccountMeta::new(p.pda, false),
        AccountMeta::new(s.lp_ata, false),
        AccountMeta::new(p.lp_mint, false),
        AccountMeta::new(p.vault, false),
        AccountMeta::new(s.ata, false),
        AccountMeta::new_readonly(p.vault_auth, false),
        AccountMeta::new(dep, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::ID, false),
        AccountMeta::new(m, false),
        AccountMeta::new(units, false),
        AccountMeta::new_readonly(pid, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];
    let k = s.k.insecure_clone();
    stake_send(w, data, metas, &[&k])
}

fn stake_sync(w: &mut P3, p: &Pool) -> Result<u64, String> {
    let caller = Keypair::new();
    w.env.ensure_signer_account(caller.pubkey());
    let (m, pid, wv, wva) = (w.env.market, w.env.program_id, w.env.vault, w.env.vault_authority);
    let units = units_pda(w);
    let metas = vec![
        AccountMeta::new(caller.pubkey(), true),
        AccountMeta::new(p.pda, false),
        AccountMeta::new(p.vault, false),
        AccountMeta::new_readonly(p.vault_auth, false),
        AccountMeta::new(m, false),
        AccountMeta::new(wv, false),
        AccountMeta::new_readonly(wva, false),
        AccountMeta::new(units, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(pid, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ];
    stake_send(w, vec![31], metas, &[&caller])
}

/// Stake-side valuation from chain state: (liquid, deployed at EXIT, LP supply).
fn pool_view(w: &P3, p: &Pool) -> (u64, u64, u64) {
    let deposited = pool_u64(w, p, 168);
    let supply = pool_u64(w, p, 176);
    let flushed = pool_u64(w, p, 200);
    let returned = pool_u64(w, p, 208);
    let withdrawn = pool_u64(w, p, 216);
    let fees = pool_u64(w, p, 256);
    let liquid = deposited + returned + fees - withdrawn - flushed;
    let u = units(w).unwrap();
    let deployed = if u.units_total == 0 { 0 } else { (u.units_stake * u.snap_insurance_free_atoms / u.units_total) as u64 };
    (liquid, deployed, supply)
}

fn st_code(r: &Result<u64, String>, c: u32) -> bool {
    r.as_ref().err().map_or(false, |e| code(e) == Some(c))
}




/// Tag 101 with the units ledger appended (after [11] system program).
fn settle_resolved_units(w: &mut P3, junior_owner: Pubkey, topup: u8) -> Result<u64, String> {
    let dest = w.token(junior_owner, 0);
    let payer = w.env.payer.pubkey();
    let metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(w.env.market, false),
        AccountMeta::new_readonly(w.registry, false),
        AccountMeta::new(w.state_pda, false),
        AccountMeta::new(w.lp, false),
        AccountMeta::new(w.ledger0, false),
        AccountMeta::new_readonly(w.ledger1, false),
        AccountMeta::new(dest, false),
        AccountMeta::new(w.env.vault, false),
        AccountMeta::new_readonly(w.env.vault_authority, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(units_pda(w), false),
    ];
    w.send_raw(raw(101, &[topup]), metas, &[])
}


/// W-2 two-step G9 (Wave D round 2): PROPOSE (mode 2), wait the delay with the book kept current,
/// then DRAW (mode 0). The single-step draw this suite was written against no longer exists.
fn g9_two_step(w: &mut P3, ports: &[Pubkey]) -> Result<u64, String> {
    backstop_111(w, 2, 0, true)?;
    let mark = MARK.with(|c| c.get());
    let target = w.slot() + percolator_prog::p4_rescue_ins::G9_DELAY_SLOTS;
    w.env.svm.warp_to_slot(target);
    w.env.push_auth_mark_for_asset_as_admin(0, target, mark);
    let lp = w.lp;
    for _ in 0..2 {
        for p in ports {
            let _ = w.crank(*p);
        }
        let _ = w.crank(lp);
    }
    backstop_111(w, 0, 0, true)
}

// ═════════════════ Sentinel v22 Wave D review (2026-10-05): adversarial tests ═════════════════

/// SEC-D2: first-depositor / donation inflation of the unit ledger. The ledger can be left with a
/// tiny `U` against a large `I` (genesis at a dust balance, then fee growth: simulated here by
/// setting `U = 1` on a 3,000,000-atom fund; fee growth raises I without minting). Then:
///  (a) a creator-class top-up smaller than I/U succeeds and mints ZERO units (donation);
///  (b) the permissionless stake sync deploys the pool's money, mints ZERO stake units, and the
///      stakers' NAV drops by the full deployed amount; the atoms are creator-class value.
#[test]
fn sec_d2_zero_mint_donation_inflation_takes_the_stake_pools_deployment() {
    let mut w = P3::new();
    top_up_9(&mut w, 3_000_000, false).expect("creator seed");
    init_units(&mut w).expect("116");
    // Dust genesis + later fee growth: one unit owns the whole fund.
    set_units(&mut w, |u| {
        u.units_total = 1;
        u.units_creator = 1;
        u.units_stake = 0;
    });
    // (a) donation by a creator-class top-up
    let u0 = { init_units(&mut w).expect("116 refresh"); units(&w).unwrap() };
    let ins0 = w.env.market_state().1.insurance;
    let r = top_up_9(&mut w, 500_000, true);
    let u1 = units(&w).unwrap();
    let ins1 = w.env.market_state().1.insurance;
    eprintln!("SEC-D2a top-up 500,000 on U=1/I={} -> {:?}; insurance {} -> {}; units_total {} -> {}", u0.snap_insurance_mint_atoms, r.as_ref().map_err(|e| code(e)), ins0, ins1, u0.units_total, u1.units_total);
    // FIXED (W-1 / S-1, Wave D round 2): a creator-class top-up that would mint ZERO units is REFUSED
    // (it used to be accepted: the depositor gave 500,000 atoms for nothing and the atoms became
    // creator-class value). Nothing moves.
    assert!(r.is_err(), "the zero-mint top-up is refused");
    assert_eq!(u1.units_total, u0.units_total, "no units minted");
    assert_eq!(ins1, ins0, "no insurance moved");
    // (b) the stake pool: the permissionless sync must not deploy the pool's money for ZERO stake units
    let p = craft_pool(&mut w, 1, 1);
    bind_and_burn(&mut w, &p);
    let a = staker(&mut w, &p, 4_000_000);
    stake_deposit(&mut w, &p, &a, 4_000_000, Some(1)).expect("deposit with consent");
    let (l0, d0, s0) = pool_view(&w, &p);
    let r = stake_sync(&mut w, &p);
    let u2 = units(&w).unwrap();
    let ins2 = w.env.market_state().1.insurance;
    let (l1, d1, s1) = pool_view(&w, &p);
    eprintln!("SEC-D2b sync -> {:?}; insurance {} -> {}; stake units {} (U {}); pool (liquid, deployed@exit, supply) {:?} -> {:?}", r.as_ref().map_err(|e| code(e)), ins1, ins2, u2.units_stake, u2.units_total, (l0, d0, s0), (l1, d1, s1));
    // either the sync refuses (stake InsuranceUnitsInvalid / wrapper refusal) or it mints a non-zero
    // number of stake units; in no case may the stakers' value fall for zero units
    if r.is_ok() {
        assert!(u2.units_stake > 0, "a successful sync mints stake units");
    }
    assert!(l1 + d1 >= l0 + d0 - 1, "stakers' pool value must not fall by a deployed amount for zero units");
}

/// SEC-D4: entry reading includes the G9 receivable at face; exit reading excludes it. With a
/// receivable outstanding, a deposit followed by an immediate withdrawal in the same slot range
/// returns less than deposited, and the difference stays in the pool for incumbents. (The
/// receivable is set directly on the ledger; the snapshot formula is what is exercised.)
#[test]
fn sec_d4_entry_exit_gap_with_receivable_taxes_new_stakers() {
    let mut w = P3::new();
    top_up_9(&mut w, 1_000_000, false).expect("creator seed");
    init_units(&mut w).expect("116");
    let p = craft_pool(&mut w, 1, 1);
    bind_and_burn(&mut w, &p);
    let a = staker(&mut w, &p, 4_000_000);
    stake_deposit(&mut w, &p, &a, 4_000_000, Some(1)).expect("A");
    { let r = stake_sync(&mut w, &p); if let Err(e) = &r { eprintln!("SEC-D4 sync err: {}", e.split("logs:").nth(1).unwrap_or(e).chars().take(1500).collect::<String>()); } r.expect("sync deploys 2M"); }
    // Pretend G9 lent 1,000,000 atoms to the vault LP and nothing came back.
    set_units(&mut w, |u| u.backstop_receivable_atoms = 3_000_000);
    init_units(&mut w).expect("refresh");
    let u = units(&w).unwrap();
    eprintln!("SEC-D4 snapshot: mint reading {} free reading {} U {} stake units {}", u.snap_insurance_mint_atoms, u.snap_insurance_free_atoms, u.units_total, u.units_stake);
    let b = staker(&mut w, &p, 2_000_000);
    // FIXED (W-5 / S-3, Wave D round 2): while the wrapper's mint reading differs from its free reading
    // (here a 3,000,000 receivable is outstanding) a deposit into the deployed units is REFUSED
    // (stake InsuranceReadingsDiverged = 44), so a newcomer can no longer be taxed by the entry/exit
    // gap at all. The balance is untouched.
    let before = w.tok(&b.ata);
    let r = stake_deposit(&mut w, &p, &b, 2_000_000, Some(1));
    eprintln!("SEC-D4 B deposit while the receivable is outstanding -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert_eq!(r.as_ref().err().map(|e| code(e)), Some(Some(44)), "W-5: deposit refused while readings diverge: {r:?}");
    assert_eq!(w.tok(&b.ata), before, "nothing moved");
}

/// SEC-D5: a v4 (408 B, version 4) pool under an in-place upgrade to v5: can its stakers withdraw?
#[test]
fn sec_d5_v4_pool_is_unusable_after_in_place_upgrade() {
    let mut w = P3::new();
    top_up_9(&mut w, 1_000_000, false).expect("seed");
    init_units(&mut w).expect("116");
    let p = craft_pool(&mut w, 1, 1);
    // Rewrite the account as a v4 pool: 408 bytes, version byte 4.
    let mut acct = w.env.svm.get_account(&p.pda).unwrap();
    acct.data.truncate(408);
    acct.data[328] = 4;
    acct.data[168..176].copy_from_slice(&5_000_000u64.to_le_bytes()); // total_deposited
    acct.data[176..184].copy_from_slice(&5_000_000u64.to_le_bytes()); // lp supply
    w.env.svm.set_account(p.pda, acct).unwrap();
    let s = staker(&mut w, &p, 0);
    let r = stake_withdraw(&mut w, &p, &s, 1);
    eprintln!("SEC-D5 withdraw on a 408 B v4 pool -> {:?}", r);
    assert!(r.is_err(), "v4 pool refuses everything (stranded)");
}

/// SEC-D6: after the G9 draw, is the vault LP still halted from RISK-INCREASING fills (as it is
/// while a senior draw is outstanding)? The PR halts 97/98/102/103 but the fill halt reads only
/// the senior draw mirror (`draw.outstanding_mirror_atoms + pending`), not `backstop_outstanding`.
#[test]
fn sec_d6_lp_keeps_taking_risk_on_borrowed_insurance_after_g9() {
    let (mut w, _s, (t, tp)) = underwater_world(90_000, 60_000, 1_000_000, 6);
    seed_units(&mut w, 20_000_000);
    g9_two_step(&mut w, &[tp]).expect("G9 two-step draw");
    let b = backstop_st(&w);
    assert!(b > 0);
    let pos0 = w.pos(w.lp);
    // control: the senior-draw halt itself (outstanding mirror) -- read its state
    eprintln!("SEC-D6 backstop {b}; senior draw outstanding {}; LP pos {pos0}", outstanding(&w));
    let (t2, tp2) = w.trader(50_000_000);
    // New taker opens in the SAME direction as the first (LP gets more short): risk-increasing for the LP.
    let r = w.trade_vs_lp(&t2, tp2, U);
    let pos1 = w.pos(w.lp);
    eprintln!("SEC-D6 new risk-increasing fill -> {:?}; LP pos {pos0} -> {pos1}", r.as_ref().map_err(|e| code(e)));
    // FIXED (W-9, Wave D round 2): while the G9 backstop is outstanding the LP's risk-increasing
    // fills are halted (the outstanding mirror carries the backstop), so the LP cannot keep taking
    // risk on borrowed insurance: the fill is refused and the LP position does not grow.
    assert!(r.is_err(), "W-9: a risk-increasing fill is refused while the backstop is outstanding");
    assert!(pos1.abs() <= pos0.abs(), "the LP position did not grow: {pos0} -> {pos1}");
}

/// SEC-D7: a vault with NO Earn seniors at all (creator junior only). G9's "seniors exhausted"
/// test (`senior_nav == 0`) is vacuously true. The creator's own trader account wins against the
/// LP on a creator-pushed mark; G9 (permissionless) lends asset-0 insurance (stake + creator
/// units) into the LP, which pays the winner. Also: is the LP still halted from new risk?
#[test]
fn sec_d7_junior_only_vault_g9_funds_a_self_dealing_winner() {
    let (mut w, _s) = P3::bound(&[], 1_000_000, 1_000);
    let (t, tp) = w.trader(50_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).unwrap();
    MARK.with(|c| c.set(PRICE));
    for _ in 0..6 {
        let m = MARK.with(|c| c.get()) * 124 / 100;
        MARK.with(|c| c.set(m));
        w.push(m);
        w.catch_up(&[tp], 30);
    }
    seed_units(&mut w, 20_000_000);
    let ins0 = w.env.market_state().1.insurance;
    let t0 = w.env.portfolio_state(tp);
    let r = backstop_111(&mut w, 0, 0, true);
    let t1 = w.env.portfolio_state(tp);
    eprintln!("SEC-D7 G9 -> {:?}; backstop {}; insurance {} -> {}; trader cap/pnl {}/{} -> {}/{}; senior draw outstanding {}", r.as_ref().map_err(|e| code(e)), backstop_st(&w), ins0, w.env.market_state().1.insurance, t0.capital, t0.pnl, t1.capital, t1.pnl, outstanding(&w));
    if r.is_ok() {
        for _ in 0..3 { let _ = w.crank(tp); let _ = w.crank(w.lp); }
        let t2 = w.env.portfolio_state(tp);
        eprintln!("SEC-D7 after cranks trader cap/pnl {}/{}", t2.capital, t2.pnl);
        let (t2k, tp2) = w.trader(50_000_000);
        let pos0 = w.pos(w.lp);
        let r2 = w.trade_vs_lp(&t2k, tp2, U);
        eprintln!("SEC-D7 new risk-increasing fill after G9 -> {:?}; LP pos {} -> {}", r2.as_ref().map_err(|e| code(e)), pos0, w.pos(w.lp));
    }
}
