// P3 branch copy of the independent lane's `tests/indep_p3_f14q.rs` (test branch
// `test/independent-suite-2026-09-30@b906dac6`, QA lane) plus the Anvil h-lock liveness tests
// (`anvil_hlock_*`). Harness: `tests/indep_harness/mod.rs` from the same commit.
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
        // [P3 branch copy] default to this crate's own build, as every other suite here does.
        .unwrap_or_else(|| format!("{}/target/deploy/percolator_prog.so", env!("CARGO_MANIFEST_DIR")).into())
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
        let matcher = if std::env::var("P3_LEGACY_BIND").is_ok_and(|v| v == "1") { Pubkey::new_unique() } else { "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT".parse::<Pubkey>().unwrap() };
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
        if !std::env::var("P3_LEGACY_BIND").is_ok_and(|v| v == "1") {
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
        if std::env::var("P3_LEGACY_BIND").is_ok_and(|v| v == "1") { w.set_matcher(&up).unwrap_or_else(|e| panic!("95 VaultLpSetMatcher by upgrade authority: {e}")); }
        if junior > 0 {
            w.junior_deposit(&admin, junior).unwrap_or_else(|e| panic!("96 junior deposit: {e}"));
        }
        (w, atas)
    }
}

fn code(e: &str) -> Option<u32> {
    custom_code(e)
}

thread_local! { static TL_IM: std::cell::Cell<u64> = const { std::cell::Cell::new(10_000) }; }
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
thread_local! { static MARK: std::cell::Cell<u64> = const { std::cell::Cell::new(PRICE) }; }

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
thread_local! { static CAP: std::cell::Cell<u16> = const { std::cell::Cell::new(1) }; }

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
            if name.starts_with('C') || name.starts_with('D') {
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
            if !st.0 && !st.1 {
                cleared_at = Some(t0);
                break;
            }
        }
        let conv = try_convert(&mut w);
        let line = format!("phase {name}: cleared {:?} (slots), status {:?}, convert -> {:?}", cleared_at, status(&w), conv);
        eprintln!("HLOCK {line}");
        log.push(line);
        if cleared_at.is_some() && conv.is_none_or(|c| c == 0) {
            break;
        }
    }
    let st = status(&w);
    eprintln!("HLOCK final: {:?}", st);
    if st.0 || st.1 {
        // Privileged escape probe (NOT counted as a permissionless exit): admin ResolveMarket.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { w.env.resolve(); }));
        let g = w.env.market_state().1;
        eprintln!("HLOCK privileged probe: admin ResolveMarket -> {}; mode {:?} hlock {}", if r.is_ok() { "ok" } else { "FAILED" }, g.mode, g.bankruptcy_hlock_active);
    }
    assert!(!st.0 && !st.1, "H-lock/loss_stale never cleared via permissionless paths: {log:?}");
    assert!(try_convert(&mut w).is_none_or(|c| c == 0), "winner still cannot convert after h-lock cleared");
}

/// [Anvil local] H-lock exit on the fixed head: the expired bankrupt close of the vault LP
/// escalates to Recovery through the permissionless crank (upstream expired-close valve), the
/// Recovery step reaches Resolved, and then every claim is paid permissionlessly: the winner
/// (resolved close), the seniors (77 at min(physical, C)), the junior (102, nothing left).
#[test]
#[ignore = "58e379f1 loss rule (winner haircut via the valve); superseded by p3_senior_draw::p3_draw_* / p3_c7_* under the senior draw"]
fn anvil_hlock_exits_via_recovery_and_everyone_is_paid() {
    // Senior-draw FINAL (2026-09-30): the h-lock/valve path is reachable ONLY once senior backing
    // is exhausted, so the seniors here are tiny (150k vs a ~1.6M shortfall past the junior).
    let (mut w, seniors, (t, tp)) = q1_world(90_000, 60_000, 1_000_000, 6);
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
    assert!(paid_t >= t_cap0, "winner gets at least its capital back");
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
}

/// [Anvil local] Security acceptance for the expired-close valve: a STRANGER's crank on a
/// bankrupt vault LP (close active, residual unabsorbable) does NOT escalate at exactly
/// `max_close_slot`, and DOES declare Recovery at `max_close_slot + 1`; the market then
/// reaches Resolved and every claim pays with seniors whole and tokens conserved.
#[test]
#[ignore = "58e379f1 loss rule (winner haircut via the valve); superseded by p3_senior_draw::p3_draw_* / p3_c7_* under the senior draw"]
fn anvil_hlock_stranger_crank_escalates_only_after_max_close_slot() {
    let mut w = P3::new();
    w.create_vault();
    let s0 = Keypair::new();
    let s1 = Keypair::new();
    // Senior-draw FINAL: tiny seniors, so the valve is reachable (backing exhausted by the draw).
    let a0 = w.earn_deposit_domain(&s0, 90_000, false, 0).expect("75 d0");
    let a1 = w.earn_deposit_domain(&s1, 60_000, false, 1).expect("75 d1");
    let admin = w.env.admin.insecure_clone();
    w.init_vault_lp(&admin, 1_000).expect("94");
    let up = w.upgrade.insecure_clone();
    w.set_risk(&up, 0).expect("99");
    w.junior_deposit(&admin, 1_000_000).expect("96");
    let (t, tp) = w.trader(50_000_000);
    w.trade_vs_lp(&t, tp, 3 * U).expect("open");
    let lp = w.lp;
    let stranger = Keypair::new();
    w.env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let m = w.env.market;
    let stranger_crank = |w: &mut P3, p: Pubkey| {
        let slot = w.slot();
        let k = stranger.insecure_clone();
        w.send(
            ProgInstruction::PermissionlessCrank { now_slot: slot, observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] },
            vec![AccountMeta::new(k.pubkey(), true), AccountMeta::new(m, false), AccountMeta::new(p, false)],
            &[&k],
        )
    };
    let lp_close = |w: &P3| w.env.svm.get_account(&lp).and_then(|a| state::read_portfolio(&a.data).ok()).map(|p| p.close_progress);
    // Same shape as q1_world: six +24% pushes with catch-up, then the winner closes.
    MARK.with(|c| c.set(PRICE));
    for _ in 0..6 {
        let mk = MARK.with(|c| c.get()) * 124 / 100;
        MARK.with(|c| c.set(mk));
        w.push(mk);
        w.catch_up(&[tp, lp], 30);
    }
    for _ in 0..8 {
        let r = w.trade_vs_lp(&t, tp, -w.pos(tp));
        if r.is_ok() { break; }
        w.catch_up(&[tp, lp], 5);
    }
    // Step one slot at a time with STRANGER cranks until the vault LP's bankrupt close starts.
    let mut close = None;
    for _ in 0..400 {
        if let Some(c) = lp_close(&w) { if c.active && c.residual_remaining > 0 { close = Some(c); break; } }
        let s = w.slot() + 1;
        w.env.svm.warp_to_slot(s);
        let _ = stranger_crank(&mut w, lp);
        let _ = stranger_crank(&mut w, tp);
    }
    eprintln!("ANVIL2 lp close {:?} mode {:?} slot {}", lp_close(&w), w.env.market_state().1.mode, w.slot());
    let c = close.expect("vault LP entered a bankrupt close with residual");
    eprintln!("ANVIL2 close active: max_close_slot {} residual {} now {} mode {:?}", c.max_close_slot, c.residual_remaining, w.slot(), w.env.market_state().1.mode);
    let v0 = w.tok(&w.env.vault) as u128;
    // Boundary NEGATIVE: exactly at max_close_slot (the rule is `now > max_close_slot`) -> no
    // escalation.
    assert!(w.slot() < c.max_close_slot, "fixture: close observed before its deadline");
    w.env.svm.warp_to_slot(c.max_close_slot);
    let r = stranger_crank(&mut w, lp);
    let mode_before = w.env.market_state().1.mode;
    eprintln!("ANVIL2 crank at max ({}) -> {:?}; mode {:?}", w.slot(), r.as_ref().map_err(|e| code(e)), mode_before);
    assert_eq!(mode_before, percolator::MarketModeV16::Live, "no escalation at max_close_slot");
    // POSITIVE: past max_close_slot a stranger's crank declares Recovery, then Resolved.
    w.env.svm.warp_to_slot(c.max_close_slot + 1);
    let r = stranger_crank(&mut w, lp);
    let mode_after = w.env.market_state().1.mode;
    eprintln!("ANVIL2 crank at max+1 -> {:?}; mode {:?}", r.as_ref().map_err(|e| code(e)), mode_after);
    assert_eq!(mode_after, percolator::MarketModeV16::Recovery, "stranger's crank declares Recovery");
    for _ in 0..10 {
        let s = w.slot() + 5;
        w.env.svm.warp_to_slot(s);
        let _ = stranger_crank(&mut w, lp);
        let _ = stranger_crank(&mut w, tp);
        if w.env.market_state().1.mode == percolator::MarketModeV16::Resolved { break; }
    }
    assert_eq!(w.env.market_state().1.mode, percolator::MarketModeV16::Resolved, "Recovery -> Resolved permissionlessly");
    // Settle + pay everyone permissionlessly; seniors whole; conservation.
    let jo = admin.pubkey();
    let mut paid_t = 0u128;
    for _ in 0..6 {
        let _ = w.settle_resolved(jo, 0);
        let _ = w.settle_resolved(jo, 1);
        let dest = w.token(t.pubkey(), 0);
        let nft = Pubkey::find_program_address(&[b"nft_registry", m.as_ref()], &w.env.program_id).0;
        let _ = w.send(ProgInstruction::CloseResolved { fee_rate_per_slot: 0 }, vec![
            AccountMeta::new_readonly(t.pubkey(), false), AccountMeta::new(m, false), AccountMeta::new(tp, false),
            AccountMeta::new(dest, false), AccountMeta::new(w.env.vault, false), AccountMeta::new_readonly(w.env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new_readonly(nft, false)], &[]);
        paid_t += w.tok(&dest) as u128;
        let ps = w.env.portfolio_state(tp);
        if ps.capital == 0 && ps.pnl == 0 { break; }
        let s = w.slot() + 50;
        w.env.svm.warp_to_slot(s);
    }
    w.terminal_cleanup(&[(tp, t.pubkey())]).expect("terminal 78");
    let mut senior_paid = 0u128;
    for (k, ata) in [(&s0, a0), (&s1, a1)] {
        let shares = w.tok(&ata) as u128;
        let _ = w.request_redeem(k, ata, shares);
        let (mut dest, mut r) = w.execute_redeem(k, true);
        if r.is_err() { let x = w.execute_redeem_domain(k, 1); dest = x.0; r = x.1; }
        r.expect("every senior exits");
        senior_paid += w.tok(&dest) as u128;
    }
    let junior_paid = w.junior_release_resolved(&admin);
    let left = w.tok(&w.env.vault) as u128;
    eprintln!("ANVIL2: vault {v0} -> {left}; winner {paid_t} seniors {senior_paid} junior {junior_paid}");
    // Senior-draw FINAL: the seniors' whole backing was drawn into the vault LP before the valve
    // (junior first, then seniors); only dead-share dust can remain for them.
    assert!(senior_paid <= 1_000, "seniors' backing drawn first ({senior_paid})");
    assert_eq!(v0, paid_t + senior_paid + junior_paid + left, "token conservation across the wind-down");
    assert!(left <= 1_000, "only dead-share dust left ({left})");
}
