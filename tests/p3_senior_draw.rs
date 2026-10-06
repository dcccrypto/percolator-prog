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
        // v2.2 (security review, "fixture skew"): default to THIS tree's SBF build. The old
        // default, a pinned prebuilt ~/wt-indep/p3-so/current.so, was a v2.1 program that
        // correctly refuses the v2.2-sized market account this harness creates.
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_prog.so"))
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

/// RULE 1 (the lane's numbers, with owed taken BEFORE the close): the winner is paid IN FULL in
/// Live; seniors take exactly the shortfall pro rata; junior 0; nothing stranded; no h-lock.
#[test]
fn p3_draw_winner_paid_in_full_seniors_take_exact_shortfall() {
    let (mut w, seniors, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    conserved(&w, "after q1_world");
    let g = w.env.market_state().1;
    assert!(!g.bankruptcy_hlock_active, "no h-lock while seniors cover the shortfall");
    let owed = 50_000_000u128 + 2_635_213;
    let (winner, per, junior, left) = lossrule_exit(&mut w, &seniors, &t, tp);
    conserved(&w, "after exit");
    let expected = 10_000_000u128 - 1_635_213;
    let total: u128 = per.iter().sum();
    eprintln!("DRAW-1: winner {winner} (owed {owed}); seniors {per:?} = {total} (expected {expected}); junior {junior}; left {left}; drawn {} outstanding {}", drawn(&w), outstanding(&w));
    assert!(winner >= owed, "winner never haircut: {winner} < {owed}");
    assert!(total + 2_000 >= expected && total <= expected + 2_000, "seniors take exactly the shortfall: {total} vs {expected}");
    for (i, (p, sh)) in per.iter().zip([9_000_000u128, 1_000_000]).enumerate() {
        let fair = sh * expected / 10_000_000;
        assert!((*p as i128 - fair as i128).abs() <= 2_000, "senior {i}: {p} vs pro-rata {fair}");
    }
    assert_eq!(junior, 0, "junior first loss");
    assert!(left <= 2_000, "stranded {left}");
}

/// Booking is idempotent and booked exactly once; conservation after the draw and the booking.
#[test]
fn p3_draw_booked_exactly_once() {
    let (mut w, _s, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    conserved(&w, "after draw");
    let _ = w.crank_fees_78();
    let (c1, d1, o1) = (w.c(), drawn(&w), outstanding(&w));
    conserved(&w, "after booking");
    let _ = w.crank_fees_78();
    let _ = w.crank_fees_78();
    eprintln!("DRAW-book: C {c1} drawn {d1} outstanding {o1}");
    assert_eq!(c1, 10_000_000 - 1_635_213, "C cut by exactly the senior loss");
    assert_eq!((d1, o1), (1_635_213, 1_635_213));
    assert_eq!((w.c(), drawn(&w), outstanding(&w)), (c1, d1, o1), "a second booking changes nothing");
}

/// Security negative: a loss the junior still covers draws NOTHING (C untouched).
#[test]
fn p3_draw_junior_covered_loss_draws_nothing() {
    let (mut w, _s, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 2); // +53.76% on 1 unit < 1M junior
    let _ = w.crank_fees_78();
    conserved(&w, "junior-covered");
    let tr = w.env.portfolio_state(tp);
    eprintln!("JUNIOR-COVERED: trader cap {} pnl {}", tr.capital, tr.pnl);
    assert!(tr.capital > 50_000_000, "vacuity: the trader won and was paid (a real loss hit the vault LP)");
    assert_eq!((w.c(), drawn(&w), outstanding(&w)), (10_000_000, 0, 0), "junior-covered loss must not touch seniors");
}

/// Security negatives: a double crank draws once; a stale mark (no push) draws nothing more.
#[test]
fn p3_draw_double_call_and_stale_mark_do_not_redraw() {
    let (mut w, _s, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let _ = w.crank_fees_78();
    let (c1, d1) = (w.c(), drawn(&w));
    assert!(d1 > 0, "vacuity: the LP was underwater past the junior");
    let lp = w.lp;
    let _ = w.crank(lp);
    let _ = w.crank(lp);
    let _ = w.crank_fees_78();
    assert_eq!((w.c(), drawn(&w)), (c1, d1), "double call");
    // stale mark: warp far, no push; the crank cannot accrue a new price, so nothing is drawn.
    let s = w.slot() + 5_000;
    w.env.svm.warp_to_slot(s);
    let r = w.crank(lp);
    let _ = w.crank_fees_78();
    eprintln!("DRAW-stale crank -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert_eq!((w.c(), drawn(&w)), (c1, d1), "stale mark");
    conserved(&w, "double/stale");
}

/// Race (early exit): right after an underwater move, before any LP crank, a senior redeeming
/// with the vault LP READ-ONLY is refused (fail closed: 85 stale cert or VaultLpSeniorDrawRequired),
/// and with it WRITABLE the draw runs inside 77 so the senior takes its pro-rata share of the loss.
#[test]
fn p3_draw_race_early_exit_takes_the_loss() {
    let (mut w, seniors, _t) = underwater_world(9_000_000, 1_000_000, 1_000_000, 6);
    let (k1, a1) = (&seniors[1].0.insecure_clone(), seniors[1].1);
    let shares = w.tok(&a1) as u128;
    w.request_redeem(k1, a1, shares).unwrap();
    let r = redeem_ro(&mut w, k1);
    eprintln!("RACE-early read-only LP -> {:?}", r.as_ref().map_err(|e| code(e)));
    assert!(r.is_err(), "early exit with an undrawn deficit must fail closed");
    let c0 = w.c();
    let s_before = w.registry_shares();
    let (dest, r) = w.execute_redeem_domain(k1, 1);
    eprintln!("RACE-early writable LP -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&dest));
    let paid = w.tok(&dest) as u128;
    let full = shares * c0 / s_before;
    assert!(r.is_ok(), "the draw must run inside 77 when the LP is writable");
    assert!(paid < full, "early redeemer escaped the loss: paid {paid} vs pre-loss {full}");
    let c_after_draw = w.c() + shares * w.c() / (s_before - shares).max(1); // not used for exactness
    let _ = c_after_draw;
    conserved(&w, "early exit");
}

/// Race (late entry): a depositor entering right after an underwater move is priced after the
/// draw; its shares redeem for what it paid (it neither subsidises nor is subsidised).
#[test]
fn p3_draw_race_late_entry_pays_post_loss_price() {
    let (mut w, _seniors, _t) = underwater_world(9_000_000, 1_000_000, 1_000_000, 6);
    let late = Keypair::new();
    let ata = w.earn_deposit_domain(&late, 1_000_000, true, 0).expect("75 after the move (LP writable -> draw first)");
    let c_after = w.c();
    assert!(c_after < 11_000_000 - 1_000_000, "the draw was booked before pricing: C {c_after}");
    let shares = w.tok(&ata) as u128;
    let s_total = w.registry_shares();
    let value = shares * c_after / s_total;
    eprintln!("RACE-late: minted {shares} of {s_total}, C {c_after}, value {value}");
    assert!(value + 2 >= 1_000_000 && value <= 1_000_000 + 2, "late entry priced at the post-loss claim: value {value}");
    conserved(&w, "late entry");
}

/// Halt: while a draw is outstanding, 97, 102 and 98 are refused, and the vault LP may only
/// reduce; recovery (a junior top-up) restores C FIRST, which lifts the halt.
#[test]
fn p3_draw_halt_then_recovery_restores_seniors_first() {
    const PAUSED: u32 = 89; // VaultLpPausedForSeniorDraw
    let (mut w, _s, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let _ = w.crank_fees_78();
    assert!(outstanding(&w) > 0, "vacuity: a draw is outstanding");
    let admin = w.env.admin.insecure_clone();
    // Junior re-funds 2M so the vault LP has equity (P1's floor halt no longer answers first);
    // no LP-carrying P3 instruction runs yet, so the draw stays outstanding.
    // A PARTIAL re-fund (500k < the 1,635,213 outstanding): restoration is partial, the halt holds.
    w.junior_deposit(&admin, 500_000).unwrap();
    let (t2, tp2) = w.trader(10_000_000);
    let rg = w.trade_vs_lp(&t2, tp2, U / 10);
    let (_, r97) = w.junior_withdraw(&admin, admin.pubkey(), 1);
    let r102 = w.live_release_102(&admin, 1);
    let r98 = recall(&mut w, 1);
    eprintln!("HALT 97 {:?} 102 {:?} 98 {:?} fill {:?}", r97.as_ref().map_err(|e| code(e)), r102.as_ref().map_err(|e| code(e)), r98.as_ref().map_err(|e| code(e)), rg.as_ref().map_err(|e| code(e)));
    assert_eq!(r97.as_ref().err().and_then(|e| code(e)), Some(PAUSED), "97 paused by the draw");
    assert_eq!(r102.as_ref().err().and_then(|e| code(e)), Some(PAUSED), "102 paused by the draw");
    assert_eq!(r98.as_ref().err().and_then(|e| code(e)), Some(PAUSED), "98 paused by the draw");
    assert_eq!(rg.as_ref().err().and_then(|e| code(e)), Some(PAUSED), "vault-LP risk-increasing fill paused by the draw");
    // Recovery: the junior re-funds the rest; the next P3 instruction that carries the vault LP
    // (a small senior deposit) restores C by the FULL outstanding before anything else.
    w.junior_deposit(&admin, 2_000_000).unwrap();
    let late = Keypair::new();
    w.earn_deposit_domain(&late, 1_000, true, 0).expect("75 (vault LP writable)");
    eprintln!("RECOVERY: C {} outstanding {}", w.c(), outstanding(&w));
    assert_eq!(w.c(), 10_000_000 + 1_000, "seniors restored first, in full (then the 1,000 deposit)");
    assert_eq!(outstanding(&w), 0, "halt lifted");
    let rg2 = w.trade_vs_lp(&t2, tp2, U / 10);
    eprintln!("after recovery LP-growing fill -> {:?}", rg2.as_ref().map_err(|e| code(e)));
    assert!(rg2.as_ref().err().and_then(|e| code(e)) != Some(PAUSED), "no longer paused");
    let _ = (t, tp);
    conserved(&w, "recovery");
}

/// D-P3-30: a recall (98) never re-opens a deficit a draw funded. While a draw is pending it is
/// refused outright (and the refusal books nothing); afterwards it is capped by the vault LP's
/// certified equity (`vault_lp_recall_limit`), so it can only move the LP's OWN positive equity.
#[test]
fn p3_draw_recall_never_reopens_a_funded_deficit() {
    let (mut w, _s, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 6);
    let c0 = w.c();
    let r = recall(&mut w, 1);
    eprintln!("RECALL while pending -> {:?}; C {} (booking reverted with the refusal)", r.as_ref().map_err(|e| code(e)), w.c());
    assert_eq!(r.as_ref().err().and_then(|e| code(e)), Some(89), "recall paused while a draw is pending");
    assert_eq!(w.c(), c0, "the refused recall committed nothing");
    let _ = w.crank_fees_78();
    let r = recall(&mut w, 1);
    assert_eq!(r.as_ref().err().and_then(|e| code(e)), Some(89), "recall paused while a senior draw is outstanding");
    // Junior re-funds 2M; the next LP-carrying instruction restores C first (outstanding 0).
    let admin = w.env.admin.insecure_clone();
    w.junior_deposit(&admin, 2_000_000).unwrap();
    let late = Keypair::new();
    w.earn_deposit_domain(&late, 1_000, true, 0).expect("75 restores seniors first");
    assert_eq!(outstanding(&w), 0);
    let eq = w.lp_state().capital;
    // The recall may move LP equity into the pots up to the senior shortfall, never beyond the
    // LP's own equity.
    let r_over = recall(&mut w, eq + 1);
    eprintln!("RECALL over LP equity {eq} -> {:?}", r_over.as_ref().map_err(|e| code(e)));
    assert_eq!(r_over.as_ref().err().and_then(|e| code(e)), Some(76), "recall beyond the vault LP's equity (ordinary cap refusal)");
    conserved(&w, "recall");
}

/// rehearsal-23 (Live) + gate-100: a senior larger than its chosen pot is funded across BOTH pots
/// in one instruction; 88 (VaultLpRedeemNeedsRecall) fires ONLY when both pots together cannot
/// pay (the value really sits in the vault LP).
#[test]
fn p3_live_redeem_spans_both_pots_and_88_only_when_both_short() {
    let (mut w, seniors, _t) = q1_world(9_000_000, 1_000_000, 1_000_000, 2);
    let (k0, a0) = (seniors[0].0.insecure_clone(), seniors[0].1);
    let sh0 = w.tok(&a0) as u128;
    w.request_redeem(&k0, a0, sh0).unwrap();
    let (d0, r0) = w.execute_redeem_domain(&k0, 1); // the 9M-share senior via the 1M pot
    eprintln!("LIVE both-pots: 77 via d1 -> {:?} paid {}", r0.as_ref().map_err(|e| code(e)), w.tok(&d0));
    assert!(r0.is_ok(), "a senior larger than its chosen pot is funded across both pots");
    // STATE POKE: C above what is left in the pots, so the rest of the senior value sits in the
    // vault LP (both pots together are short) -> exactly 88.
    {
        let c_now = w.c();
        let mut acct = w.env.svm.get_account(&w.state_pda).unwrap();
        acct.data[16 + 128..16 + 144].copy_from_slice(&(c_now + 500_000).to_le_bytes());
        w.env.svm.set_account(w.state_pda, acct).unwrap();
    }
    let (k1, a1) = (seniors[1].0.insecure_clone(), seniors[1].1);
    let sh1 = w.tok(&a1) as u128;
    w.request_redeem(&k1, a1, sh1).unwrap();
    let (_, r1) = w.execute_redeem_domain(&k1, 1);
    eprintln!("LIVE both-pots: second senior -> {:?}", r1.as_ref().map_err(|e| code(e)));
    assert_eq!(r1.as_ref().err().and_then(|e| code(e)), Some(88), "88 only when both pots together are short");
}

/// B24: after a junior-covered trader win is converted (consuming the vault LP's settled loss
/// from the pot), every senior still redeems its FULL pro-rata claim on a LIVE market. On
/// 58e379f1 the ledger floor under-priced the pots and the redemption failed with a generic 21.
#[test]
fn p3_b24_live_senior_redeems_full_claim_after_a_converted_win() {
    let (mut w, seniors, (t, tp)) = q1_world(9_000_000, 1_000_000, 1_000_000, 2);
    assert!(w.env.portfolio_state(tp).capital > 50_000_000, "vacuity: the winner converted");
    let lp = w.lp;
    let _ = w.crank(lp);
    let c = w.c();
    let s_total = w.registry_shares();
    let mut paid_total = 0u128;
    for (i, (k, ata)) in seniors.iter().enumerate() {
        let shares = w.tok(ata) as u128;
        w.request_redeem(k, *ata, shares).unwrap();
        let (d, r) = if i == 0 { w.execute_redeem(k, true) } else { w.execute_redeem_domain(k, 1) };
        eprintln!("B24 senior {i}: 77 -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        r.expect("B24: a live senior redemption must not fail with a spurious 21");
        paid_total += w.tok(&d) as u128;
    }
    let fair = c * (s_total - DEAD) / s_total;
    assert!(paid_total + 2 >= fair, "B24: seniors paid {paid_total} < fair {fair}");
    conserved(&w, "b24");
}

/// C-7 world (rehearsal-22 order): 5x market and vault LP, a long accumulated vs the LP, then
/// nine +450 bps pushes ~524 slots apart with ONLY the trader cranked. Returns before any LP crank.
fn c7_world(senior: u64, junior: u64) -> (P3, (Keypair, Pubkey), (Keypair, Pubkey), (Keypair, Pubkey)) {
    TL_IM.with(|c| c.set(2_000));
    TL_BCHUNK.with(|c| c.set(C7_BCHUNK.with(|b| b.get())));
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let d1_part = C7_D1_SENIOR.with(|c| c.get());
    let a0 = w.earn_deposit_domain(&s0, senior - d1_part, false, 0).expect("75 senior");
    if d1_part != 0 {
        // rehearsal seed: the same senior also backs domain 1 (a second pot deposit).
        let s1 = s0.insecure_clone();
        let a1 = w.earn_deposit_domain(&s1, d1_part, false, 1).expect("75 senior d1");
        C7_A1.with(|c| c.set(a1));
    }
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap_or_else(|e| panic!("99 lev 5x: {e}"));
    {
        let mut b = vec![93u8];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&50_000u32.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        let metas = vec![AccountMeta::new(up.pubkey(), true), AccountMeta::new_readonly(w.program_data, false), AccountMeta::new(w.env.market, false)];
        w.send_raw(b, metas, &[&up]).expect("93 k=5x");
    }
    w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96: {e}"));
    let (t, tp) = w.trader(2_000_000);
    let lp = w.lp;
    for _ in 0..12 {
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
        let _ = w.crank(tp);
        let _ = w.trade_vs_lp(&t, tp, 500_000);
    }
    assert!(w.pos(tp) > 0, "vacuity: long opened");
    MARK.with(|c| c.set(PRICE));
    for _ in 0..9 {
        let m = MARK.with(|c| c.get()) * 10_450 / 10_000;
        MARK.with(|c| c.set(m));
        let s = w.slot() + 524;
        w.env.svm.warp_to_slot(s);
        w.push(m);
        for _ in 0..40 { let _ = w.crank(tp); } // trader only; lets the market catch up
    }
    (w, (s0, a0), (t, tp), (admin.insecure_clone(), Pubkey::default()))
}

thread_local! { static C7_STALE_RESOLVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
thread_local! { static C7_A1: std::cell::Cell<Pubkey> = std::cell::Cell::new(Pubkey::default()); }
thread_local! { static C7_D1_SENIOR: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
thread_local! { static C7_WINNER_HOLDS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn c7_winddown(w: &mut P3, s0: &Keypair, a0: Pubkey, t: &Keypair, tp: Pubkey) -> (u128, u128, u128, u128) {
    let lp = w.lp;
    let admin = w.env.admin.insecure_clone();
    // First LP crank(s) after the move: this is where the whole loss is realised at once.
    for i in 0..40 {
        let r = w.crank(lp);
        let g = w.env.market_state().1;
        let l = w.env.portfolio_state(lp);
        if i < 3 || g.mode != percolator::MarketModeV16::Live {
            eprintln!("C7 crank(LP) #{i} -> {:?}; mode {:?} LP cap {} pnl {} close {}", r.as_ref().map_err(|e| code(e)), g.mode, l.capital, l.pnl, l.close_progress.active);
        }
        if g.mode != percolator::MarketModeV16::Live || l.legs.iter().all(|x| !x.active) { break; }
    }
    // Stranger cranks: Recovery -> Resolved (if the market went there).
    for _ in 0..4 {
        if w.env.market_state().1.mode != percolator::MarketModeV16::Recovery { break; }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = w.crank(lp);
    }
    let mode0 = w.env.market_state().1.mode;
    eprintln!("C7 mode after the move: {mode0:?}; hlock {}", w.env.market_state().1.bankruptcy_hlock_active);
    // Live: the winner closes, converts and withdraws.
    let m = w.env.market;
    let mut winner = 0u128;
    if mode0 == percolator::MarketModeV16::Live {
        let holds = C7_WINNER_HOLDS.with(|c| c.get());
        for _ in 0..(if holds { 0 } else { 6 }) {
            let p = w.pos(tp);
            if p == 0 { break; }
            let r = w.trade_vs_lp(t, tp, -p);
            if r.is_err() { let _ = w.crank(lp); let _ = w.crank(tp); }
        }
        for _ in 0..(if holds { 0 } else { 4 }) {
            let pnl = w.env.portfolio_state(tp).pnl;
            if pnl <= 0 { break; }
            let (pid, _, pep) = w.env.portfolio_identity(tp);
            let _ = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
                vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false)], &[t]);
            let _ = w.crank(tp);
        }
        let cap = w.env.portfolio_state(tp).capital;
        if !holds && cap > 0 && w.env.portfolio_state(tp).pnl <= 0 {
            let dest = w.token(t.pubkey(), 0);
            let (pid, seq, _) = w.env.portfolio_identity(tp);
            let r = w.send(ProgInstruction::Withdraw { portfolio_id: pid, expected_sequence: seq, amount: cap },
                vec![AccountMeta::new(t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(tp, false), AccountMeta::new(dest, false),
                     AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false)], &[t]);
            if r.is_ok() { winner += w.tok(&dest) as u128; }
        }
        if C7_STALE_RESOLVE.with(|c| c.get()) {
            // rehearsal-23 order: nobody resolves; a STRANGER's tag 39 after the stale window.
            let s = w.slot() + 9_001;
            w.env.svm.warp_to_slot(s);
            let now = w.slot();
            let r = w.send(ProgInstruction::ResolveStalePermissionless { now_slot: now }, vec![AccountMeta::new(m, false)], &[]);
            eprintln!("C7 stranger tag 39 -> {:?} mode {:?}", r.as_ref().map_err(|e| code(e)), w.env.market_state().1.mode);
            let s = w.slot() + 10; // past force_close_delay
            w.env.svm.warp_to_slot(s);
        } else {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
        }
    }
    // Resolved wind-down, rehearsal order.
    let jo = admin.pubkey();
    let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
    // C-7 ROOT CAUSE: nothing is locked; every resolved bankruptcy step is CHUNKED by the market's
    // `public_b_chunk_atoms` (the vault LP's resolved bankrupt close in 101, the winner's B-loss
    // settlement in CloseResolved), and each exit waits on the one before it. The permissionless
    // order is: repeat 101/0 until the vault LP's close finalizes, then repeat CloseResolved.
    for _ in 0..200 {
        let l = w.env.portfolio_state(w.lp);
        if l.capital == 0 && l.pnl == 0 && l.legs.iter().all(|x| !x.active) { break; }
        let _ = w.settle_resolved(jo, 0);
    }
    for round in 0..200 {
        if w.env.portfolio_state(tp).capital == 0 && w.env.portfolio_state(tp).pnl == 0 { break; }
        let (_, r0) = w.settle_resolved(jo, 0);
        let (_, r1) = w.settle_resolved(jo, 1);
        let dest = w.token(t.pubkey(), 0);
        let rc = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(t.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(tp, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
        winner += w.tok(&dest) as u128;
        if round == 0 { eprintln!("C7 101 {:?}/{:?}; winner CloseResolved {:?}", r0.as_ref().map_err(|e| code(e)), r1.as_ref().map_err(|e| code(e)), rc.as_ref().map_err(|e| code(e))); }
    }
    let r78 = w.terminal_cleanup(&[(tp, t.pubkey())]);
    eprintln!("C7 terminal cleanup 78 -> {:?}", r78.as_ref().map_err(|e| code(e)));
    let shares = w.tok(&a0) as u128;
    let _ = w.request_redeem(s0, a0, shares);
    let (d, r77) = w.execute_redeem(s0, true);
    let mut senior = w.tok(&d) as u128;
    if r77.is_err() { let (d, r) = w.execute_redeem_domain(s0, 1); senior += w.tok(&d) as u128; eprintln!("C7 77 d1 {:?}", r.as_ref().map_err(|e| code(e))); }
    eprintln!("C7 77 -> {:?}", r77.as_ref().map_err(|e| e.split("Program log:").skip(1).map(|x| x.chars().take(90).collect::<String>()).collect::<Vec<_>>()));
    let junior = w.junior_release_resolved(&admin);
    let left = w.tok(&w.env.vault) as u128;
    (winner, senior, junior, left)
}

/// rehearsal-23 BASE (real validator, 39b138c8): loss past the junior, inside junior + C; the
/// winner is paid in full; a STRANGER's tag 39 resolves after the stale window; the wind-down
/// reaches terminal-flat — and then every senior 77 must still pay the reduced C.
#[test]
fn p3_rehearsal23_seniors_exit_after_stranger_stale_resolve() {
    C7_STALE_RESOLVE.with(|c| c.set(true));
    C7_WINNER_HOLDS.with(|c| c.set(true)); // rehearsal-23: the winner holds into resolution
    C7_D1_SENIOR.with(|c| c.set(std::env::var("R23_D1").ok().and_then(|v| v.parse().ok()).unwrap_or(5_000_000)));
    let (mut w, (s0, a0), (t, tp), _) = c7_world(10_000_000, 300_000);
    w.env.configure_permissionless_resolve_with_cu(9_000, 5);
    let (winner, mut senior, junior, mut left) = c7_winddown(&mut w, &s0, a0, &t, tp);
    // The same senior's second holding (its domain-1 deposit), redeemed via EITHER pot choice.
    let a1 = C7_A1.with(|c| c.get());
    let sh1 = w.tok(&a1) as u128;
    if sh1 > 0 {
        let _ = w.request_redeem(&s0, a1, sh1);
        let (d, r) = w.execute_redeem(&s0, true);
        eprintln!("R23 second holding 77 (d0 choice) -> {:?} paid {}", r.as_ref().map_err(|e| code(e)), w.tok(&d));
        senior += w.tok(&d) as u128;
        left = w.tok(&w.env.vault) as u128;
    }
    C7_STALE_RESOLVE.with(|c| c.set(false));
    C7_WINNER_HOLDS.with(|c| c.set(false));
    C7_D1_SENIOR.with(|c| c.set(0));
    eprintln!("R23: winner {winner} senior {senior} junior {junior} left {left} drawn {} C {}", drawn(&w), w.c());
    conserved(&w, "r23");
    assert!(drawn(&w) > 0, "vacuity: the loss went past the junior");
    assert!(senior + 2_000 >= 10_000_000 - drawn(&w) - 1_000, "seniors paid the reduced C after resolve: {senior}");
    assert!(left <= 2_000, "stranded {left}");
}

/// C-7 (b): senior backing EXHAUSTED (tiny seniors) — whatever path the engine takes (immediate
/// Recovery included), the Resolved wind-down completes: everyone exits, nothing is locked.
#[test]
fn p3_c7_winddown_completes_when_seniors_are_exhausted() {
    let (mut w, (s0, a0), (t, tp), _) = c7_world(50_000, 300_000);
    let v0 = w.tok(&w.env.vault) as u128;
    let (winner, senior, junior, left) = c7_winddown(&mut w, &s0, a0, &t, tp);
    eprintln!("C7-b: vault {v0}: winner {winner} senior {senior} junior {junior} left {left}");
    conserved(&w, "c7-b");
    assert!(winner > 2_000_000, "the winner is paid (at least its capital and the junior)");
    assert!(left <= 2_000, "C-7: {left} atoms locked after the wind-down");
}

/// C-7 (a): senior backing covers the loss — the draw keeps the vault LP out of Recovery, the
/// winner is paid in full, seniors take the shortfall.
#[test]
fn p3_c7_draw_keeps_vault_lp_out_of_recovery() {
    let (mut w, (s0, a0), (t, tp), _) = c7_world(10_000_000, 300_000);
    let v0 = w.tok(&w.env.vault) as u128;
    let (winner, senior, junior, left) = c7_winddown(&mut w, &s0, a0, &t, tp);
    eprintln!("C7-a: vault {v0}: winner {winner} senior {senior} junior {junior} left {left} drawn {}", drawn(&w));
    conserved(&w, "c7-a");
    assert!(drawn(&w) > 0, "vacuity: the loss went past the junior");
    assert!(left <= 2_000, "stranded {left}");
    assert_eq!(junior, 0);
}


/// Senior backing EXHAUSTED on the lane's shape (tiny seniors): the engine rule applies only to
/// the unfunded remainder; the whole wind-down still completes permissionlessly (nothing locked).
#[test]
fn p3_draw_exhausted_seniors_winddown_completes() {
    let (mut w, seniors, (t, tp)) = q1_world(90_000, 60_000, 1_000_000, 6);
    let pre = w.env.portfolio_state(tp);
    let (winner, per, junior, left) = lossrule_exit(&mut w, &seniors, &t, tp);
    conserved(&w, "exhausted");
    eprintln!("EXHAUSTED: winner {winner} (cap after q1 {}, pnl {}); seniors {per:?}; junior {junior}; left {left}; drawn {}", pre.capital, pre.pnl, drawn(&w));
    assert!(winner >= 50_000_000 + 1_000_000 + 150_000 - 2_000, "winner gets its capital + the junior + ALL senior backing");
    assert!(per.iter().sum::<u128>() <= 2_000, "seniors exhausted first");
    assert!(left <= 2_000, "stranded {left}");
}

/// IGNORED (not reachable on this shape under the new rule, see the P3 doc 0.8): the expired-close valve after the senior draw (Security item 4): with senior backing
/// EXHAUSTED, the crank-path liquidation opens a bankrupt close; a STRANGER's crank at exactly
/// `max_close_slot` does not escalate, at `max_close_slot + 1` it declares Recovery, and the
/// market then reaches Resolved and winds down with nothing locked.
#[test]
#[ignore]
fn p3_valve_fires_only_after_senior_backing_is_exhausted() {
    C7_BCHUNK.with(|b| b.set(percolator::MAX_VAULT_TVL));
    let (mut w, (s0, a0), (t, tp), _) = c7_world(50_000, 300_000);
    let lp = w.lp;
    let stranger = Keypair::new();
    w.env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let m = w.env.market;
    let stranger_crank = |w: &mut P3| {
        let slot = w.slot();
        let k = stranger.insecure_clone();
        w.send(ProgInstruction::PermissionlessCrank { now_slot: slot, observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] },
            vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(lp, false)], &[&k])
    };
    for _ in 0..40 {
        let _ = stranger_crank(&mut w);
        if w.env.portfolio_state(lp).close_progress.active { break; }
    }
    let cp = w.env.portfolio_state(lp).close_progress;
    eprintln!("VALVE: close active {} residual {} max_close_slot {} now {} drawn {}", cp.active, cp.residual_remaining, cp.max_close_slot, w.slot(), drawn(&w));
    assert!(cp.active && cp.residual_remaining > 0, "vacuity: a bankrupt close opened (senior backing exhausted)");
    w.env.svm.warp_to_slot(cp.max_close_slot);
    let r = stranger_crank(&mut w);
    let mode_at = w.env.market_state().1.mode;
    eprintln!("VALVE at max_close_slot: {:?} mode {:?}", r.as_ref().map_err(|e| code(e)), mode_at);
    assert_eq!(mode_at, percolator::MarketModeV16::Live, "no escalation at exactly max_close_slot");
    w.env.svm.warp_to_slot(cp.max_close_slot + 1);
    let r = stranger_crank(&mut w);
    let mode_after = w.env.market_state().1.mode;
    eprintln!("VALVE at max_close_slot+1: {:?} mode {:?}", r.as_ref().map_err(|e| code(e)), mode_after);
    assert_eq!(mode_after, percolator::MarketModeV16::Recovery, "escalates at max_close_slot + 1");
    for _ in 0..4 {
        if w.env.market_state().1.mode == percolator::MarketModeV16::Resolved { break; }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = stranger_crank(&mut w);
    }
    let (winner, senior, junior, left) = c7_winddown(&mut w, &s0, a0, &t, tp);
    eprintln!("VALVE wind-down: winner {winner} senior {senior} junior {junior} left {left}");
    conserved(&w, "valve");
    assert!(winner >= 2_000_000 + 300_000 + 50_000 - 2_000, "winner gets capital + junior + all senior backing");
    assert!(left <= 2_000, "stranded {left}");
}


// ── D-1 directed test (security delta dfa4559b..3245e861) ──────────────────────────────────────
/// Two longs W (never touched until the end) and W2 against the vault LP; seniors 5M in each pot,
/// junior 300k. Move 1 (+10%): the vault LP's settled loss lands in a pot as backing for BOTH
/// winners (neither registered). `convert_first_order`:
///   * `false` (reviewer's order): W's backing lands, THEN W2 registers and converts (consuming
///     its own loss backing -> provider_receivable rises, owned unchanged), THEN a deficit move and
///     the senior draw.
///   * `true`: W2 converts gains whose counterparty loss has NOT landed yet (the vault LP is
///     un-refreshed), i.e. W2 borrows senior principal, then the draw.
/// Assert: W is paid capital + its full pnl at the resolved close.
fn d1_run(convert_before_lp_refresh: bool, w2_converts: bool) -> (u128, u128) {
    TL_IM.with(|c| c.set(2_000));
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let _a0 = w.earn_deposit_domain(&s0, 5_000_000, false, 0).expect("75 d0");
    let s1 = Keypair::new();
    let _a1 = w.earn_deposit_domain(&s1, 5_000_000, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap_or_else(|e| panic!("99: {e}"));
    {
        let mut b = vec![93u8];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&50_000u32.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        let metas = vec![AccountMeta::new(up.pubkey(), true), AccountMeta::new_readonly(w.program_data, false), AccountMeta::new(w.env.market, false)];
        w.send_raw(b, metas, &[&up]).expect("93");
    }
    w.junior_deposit(&admin, 300_000).unwrap_or_else(|e| panic!("96: {e}"));
    let (wt, wp) = w.trader(2_000_000);
    let (w2t, w2p) = w.trader(2_000_000);
    let lp = w.lp;
    for (t, p) in [(&wt, wp), (&w2t, w2p)] {
        for _ in 0..4 {
            let s = w.slot() + 1;
            w.env.svm.warp_to_slot(s);
            let _ = w.crank(lp);
            let _ = w.crank(p);
            let _ = w.trade_vs_lp(t, p, 300_000);
        }
    }
    assert!(w.pos(wp) > 0 && w.pos(w2p) > 0, "vacuity: both longs open");
    let m = w.env.market;
    let convert = |w: &mut P3, k: &Keypair, p: Pubkey| {
        let _ = w.crank(p);
        let pnl = w.env.portfolio_state(p).pnl;
        if pnl > 0 {
            let (pid, _, pep) = w.env.portfolio_identity(p);
            let r = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
                vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false)], &[k]);
            eprintln!("D1 W2 convert {pnl} -> {:?}", r.as_ref().map_err(|e| code(e)));
        }
    };
    // A dummy portfolio advances the market clock without touching W, W2 or the vault LP.
    let (_dk, dp) = w.trader(1_000);
    let (w2t, w2p) = (w2t, w2p);
    let step = |w: &mut P3, mark: u64| {
        MARK.with(|c| c.set(mark));
        let s = w.slot() + 524;
        w.env.svm.warp_to_slot(s);
        w.push(mark);
        for _ in 0..40 { let _ = w.crank(dp); }
    };
    let dump = |w: &P3, label: &str| {
        let g = w.env.market_state().1;
        let bs = percolator::BOUND_SCALE;
        let l = w.env.portfolio_state(w.lp);
        eprintln!("D1[{label}] pots {:?} pcb {:?} recv {:?} | LP cap {} pnl {} | drawn {}", g.source_backing_buckets.iter().take(2).map(|b| (b.fresh_unliened_backing_num / bs, b.consumed_liened_backing_num / bs)).collect::<Vec<_>>(),
            g.source_credit.iter().take(2).map(|c| c.positive_claim_bound_num / bs).collect::<Vec<_>>(), g.source_credit.iter().take(2).map(|c| c.provider_receivable_num / bs).collect::<Vec<_>>(), l.capital, l.pnl, drawn(w));
    };
    let mut mark = PRICE;
    // Move 1 (+~10%, inside the junior): then a bound Earn deposit runs the draw hook's refresh on
    // the vault LP, so its settled loss LANDS in its side's pot as backing for W and W2, both
    // still untouched (unregistered claims).
    for _ in 0..2 { mark = mark * 10_450 / 10_000; step(&mut w, mark); }
    if !convert_before_lp_refresh {
        let x = Keypair::new();
        let r = w.earn_deposit_domain(&x, 1_000, true, 0);
        eprintln!("D1 refresh via bound 75 -> {:?}", r.as_ref().map_err(|e| code(e)));
    }
    dump(&w, "after move 1");
    // Move 2 (more gain, vault LP NOT refreshed): W2 registers and converts everything, so part
    // of what it consumes is backing whose counterparty loss has not landed (senior principal).
    for _ in 0..2 { mark = mark * 10_450 / 10_000; step(&mut w, mark); }
    let _ = w.crank(w2p); // register W2's claim, close its position, let the profit mature
    for _ in 0..4 {
        let q = w.pos(w2p);
        if q == 0 { break; }
        let r = w.trade_vs_lp(&w2t, w2p, -q.min(300_000));
        if r.is_err() { eprintln!("D1 W2 close -> {:?}", r.as_ref().map_err(|e| code(e))); let _ = w.crank(w2p); }
    }
    for _ in 0..6 { step(&mut w, mark); let _ = w.crank(w2p); }
    if w2_converts { convert(&mut w, &w2t, w2p); }
    dump(&w, "after W2 convert");
    // Move 3: past the junior; the vault LP's crank runs the senior draw.
    for _ in 0..6 { mark = mark * 10_450 / 10_000; step(&mut w, mark); }
    for _ in 0..6 { let _ = w.crank(lp); }
    dump(&w, "after draw");
    let g = w.env.market_state().1;
    let bs = percolator::BOUND_SCALE;
    eprintln!("D1 before resolve: pots {:?} drawn {}", g.source_backing_buckets.iter().take(2).map(|b| (b.fresh_unliened_backing_num / bs, b.consumed_liened_backing_num / bs)).collect::<Vec<_>>(), drawn(&w));
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    w.push(mark);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
    assert_eq!(w.env.market_state().1.mode, percolator::MarketModeV16::Resolved);
    let jo = admin.pubkey();
    for _ in 0..20 {
        let l = w.env.portfolio_state(lp);
        if l.pnl >= 0 && l.legs.iter().all(|x| !x.active) { break; }
        let _ = w.settle_resolved(jo, 0);
    }
    let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
    let mut owed = 0u128;
    let mut paid = 0u128;
    for round in 0..40 {
        let st = w.env.portfolio_state(wp);
        if round == 0 || owed == 0 { owed = st.capital + st.pnl.max(0) as u128; }
        if st.capital == 0 && st.pnl == 0 && st.legs.iter().all(|x| !x.active) { break; }
        let dest = w.token(wt.pubkey(), 0);
        let rc = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(wt.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(wp, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[&wt]);
        if round < 3 { eprintln!("D1 W CloseResolved #{round} -> {:?}", rc.as_ref().map_err(|e| code(e))); }
        paid += w.tok(&dest) as u128;
        let after = w.env.portfolio_state(wp);
        if after.pnl > 0 || after.capital > 0 { owed = owed.max(after.capital + after.pnl.max(0) as u128 + paid); }
        let _ = w.settle_resolved(jo, 0);
    }
    eprintln!("D1 (convert_before_lp_refresh={convert_before_lp_refresh}): W owed {owed} paid {paid}; drawn {}", drawn(&w));
    (owed, paid)
}

/// Assert: W's resolved payout with W2's conversion equals the null control where W2 never
/// converts (W's own claim is identical in both runs), in both orders.
#[test]
fn p3_d1_untouched_winner_paid_in_full_after_registered_winner_converts() {
    for order in [false, true] {
        let (_, paid) = d1_run(order, true);
        let (_, null) = d1_run(order, false);
        eprintln!("D1 order convert_before_lp_refresh={order}: W paid {paid} (null control {null})");
        assert!(null > 2_000_000, "vacuity: W had a profit");
        assert!(paid + 2 >= null, "D-1 (convert_before_lp_refresh={order}): untouched winner W paid {paid} < null {null}");
    }
}

/// D-1 OPPOSITE-POT variant (security review of 592a77e2): W's loss backing sits in the pot the
/// vault LP's later settled loss does NOT route into. W and W2 go SHORT vs the vault LP (it is
/// long); the price falls, a bound 75 refresh lands the vault LP's loss in the LONG-side pot d0 as
/// backing for both (untouched); W2 closes and converts; then T goes long big (vault LP net
/// short) and the price rises past the junior: the senior draw runs and the vault LP's settled
/// loss routes into the SHORT-side pot d1. W's resolved payout must equal the null control.
/// LIMITATION (recorded, 2026-09-30): in this harness T's risk-increasing fill after the move is
/// refused (21) even with eff == target, so the draw phase is NOT reached (drawn 0). The test
/// therefore covers the opposite-pot CONSUMPTION half only (W2 consumes 48,782 from d0, receivable
/// 48,782) and W's payout equals the null control; the draw half is covered by
/// p3_d1_untouched_winner_paid_in_full_after_registered_winner_converts.
fn d1_opposite_run(w2_converts: bool) -> (u128, u128) {
    TL_IM.with(|c| c.set(2_000));
    let mut w = P3::new();
    w.create_vault();
    let _ = w.earn_deposit_domain(&Keypair::new(), 5_000_000, false, 0).expect("75 d0");
    let _ = w.earn_deposit_domain(&Keypair::new(), 5_000_000, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).unwrap_or_else(|e| panic!("94: {e}"));
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 50_000).unwrap_or_else(|e| panic!("99: {e}"));
    {
        let mut b = vec![93u8];
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&50_000u32.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        b.extend_from_slice(&0u128.to_le_bytes());
        let metas = vec![AccountMeta::new(up.pubkey(), true), AccountMeta::new_readonly(w.program_data, false), AccountMeta::new(w.env.market, false)];
        w.send_raw(b, metas, &[&up]).expect("93");
    }
    w.junior_deposit(&admin, 300_000).unwrap_or_else(|e| panic!("96: {e}"));
    let (wt, wp) = w.trader(2_000_000);
    let (w2t, w2p) = w.trader(2_000_000);
    let (tt, tp) = w.trader(4_000_000);
    let (_dk, dp) = w.trader(1_000);
    let lp = w.lp;
    for (t, p) in [(&wt, wp), (&w2t, w2p)] {
        for _ in 0..2 {
            let s = w.slot() + 1; w.env.svm.warp_to_slot(s);
            let _ = w.crank(lp); let _ = w.crank(p);
            let _ = w.trade_vs_lp(t, p, -100_000);
        }
    }
    assert!(w.pos(wp) < 0 && w.pos(w2p) < 0, "vacuity: both shorts open");

    let step = |w: &mut P3, mark: u64| {
        MARK.with(|c| c.set(mark));
        let s = w.slot() + 524; w.env.svm.warp_to_slot(s);
        w.push(mark);
        for _ in 0..40 { let _ = w.crank(dp); }
    };
    let dump = |w: &P3, label: &str| {
        let g = w.env.market_state().1;
        let bs = percolator::BOUND_SCALE;
        let l = w.env.portfolio_state(w.lp);
        eprintln!("D1o[{label}] pots {:?} recv {:?} | LP cap {} pnl {} pos {:?}", g.source_backing_buckets.iter().take(2).map(|b| (b.fresh_unliened_backing_num / bs, b.consumed_liened_backing_num / bs)).collect::<Vec<_>>(),
            g.source_credit.iter().take(2).map(|c| c.provider_receivable_num / bs).collect::<Vec<_>>(), l.capital, l.pnl, l.legs.iter().filter(|x| x.active).map(|x| x.basis_pos_q).collect::<Vec<_>>());
    };
    let mut mark = PRICE;
    for _ in 0..6 { mark = mark * 9_550 / 10_000; step(&mut w, mark); }
    let _ = w.earn_deposit_domain(&Keypair::new(), 1_000, true, 0); // refresh: the vault LP's loss lands
    dump(&w, "after fall + refresh");
    for _ in 0..200 {
        let a = &w.env.market_state().1.assets[0];
        if a.effective_price == a.raw_oracle_target_price { break; }
        let s = w.slot() + 50; w.env.svm.warp_to_slot(s); w.push(mark); let _ = w.crank(dp);
    }
    { let a = &w.env.market_state().1.assets[0]; eprintln!("D1o eff {} tgt {}", a.effective_price, a.raw_oracle_target_price); }
    for i in 0..14 { let s = w.slot() + 1; w.env.svm.warp_to_slot(s); let _ = w.crank(lp); let _ = w.crank(tp); let r = w.trade_vs_lp(&tt, tp, 100_000); if i < 1 { eprintln!("D1o T long -> {:?} :: {}", r.as_ref().map_err(|e| code(e)), r.as_ref().err().map(|e| e.split("Program log:").skip(1).map(|x| x.chars().take(150).collect::<String>()).collect::<Vec<_>>().join(" | ")).unwrap_or_default()); } }
    dump(&w, "after T long");
    let _ = w.crank(w2p);
    for _ in 0..4 { let q = w.pos(w2p); if q == 0 { break; } let _ = w.trade_vs_lp(&w2t, w2p, (-q).min(100_000)); }
    for _ in 0..6 { step(&mut w, mark); let _ = w.crank(w2p); }
    if w2_converts {
        let pnl = w.env.portfolio_state(w2p).pnl;
        if pnl > 0 {
            let m = w.env.market;
            let (pid, _, pep) = w.env.portfolio_identity(w2p);
            let r = w.send(ProgInstruction::ConvertReleasedPnl { portfolio_id: pid, position_epoch: pep, amount: pnl as u128 },
                vec![AccountMeta::new(w2t.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(w2p, false)], &[&w2t]);
            eprintln!("D1o W2 convert {pnl} -> {:?}", r.as_ref().map_err(|e| code(e)));
        }
    }
    dump(&w, "after W2 convert");
    for _ in 0..6 { mark = mark * 10_450 / 10_000; step(&mut w, mark); }
    for _ in 0..6 { let _ = w.crank(lp); }
    dump(&w, "after rise + draw");
    let s = w.slot() + 1; w.env.svm.warp_to_slot(s); w.push(mark);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
    let jo = admin.pubkey();
    for _ in 0..20 { let l = w.env.portfolio_state(lp); if l.pnl >= 0 && l.legs.iter().all(|x| !x.active) { break; } let _ = w.settle_resolved(jo, 0); }
    let m = w.env.market;
    let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
    let mut paid = 0u128;
    // T and W2 close first so W's close can realise (no blockers).
    for round in 0..40 {
        for (k, p) in [(&tt, tp), (&w2t, w2p), (&wt, wp)] {
            if w.env.svm.get_account(&p).map_or(true, |x| x.lamports == 0) { continue; }
            let dest = w.token(k.pubkey(), 0);
            let _ = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
                AccountMeta::new_readonly(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false),
                AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[k]);
            if p == wp { paid += w.tok(&dest) as u128; }
            let _ = w.close_portfolio_permissionless(p, k.pubkey());
        }
        let _ = round;
        let _ = w.settle_resolved(jo, 0);
    }
    eprintln!("D1o (w2_converts={w2_converts}): W paid {paid}; drawn {}", drawn(&w));
    (paid, drawn(&w))
}

#[test]
fn p3_d1_opposite_pot_untouched_winner_paid_in_full() {
    let (paid, drawn_c) = d1_opposite_run(true);
    let (null, drawn_n) = d1_opposite_run(false);
    eprintln!("D1o: W paid {paid} (null control {null}); drawn {drawn_c}/{drawn_n}");
    assert!(null > 2_000_000, "vacuity: W had a profit");
    assert!(paid + 2 >= null, "D-1 opposite pot: untouched winner W paid {paid} < null {null}");
}
