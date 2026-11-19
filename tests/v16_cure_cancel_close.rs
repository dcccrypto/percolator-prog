// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Real-path (BPF / LiteSVM) tests for `handle_cure_and_cancel_close`
//! (`src/v16_program.rs`, tag CureAndCancelClose).
//!
//! Handler checks, in order (line numbers as of base d27f3d73):
//!  1. `expect_signer(owner)`                       -> ExpectedSigner   (:26543)
//!  2. `expect_writable(market/portfolio)`          -> ExpectedWritable (:26544-5)
//!  3. `expect_owner(market/portfolio, program_id)` -> IncorrectProgramId (:26546-7)
//!  4. `portfolio_position_binding_matches`         -> EngineProvenanceMismatch (:26563; covered
//!     by `v16_attack_cure_and_cancel_close_rejects_stale_position_epoch_with_pending_close`)
//!  5. deposit != 0: `verify_token_program`, `verify_user_token_account(source, owner, mint)`
//!     -> InvalidMint / InvalidTokenAccount, `verify_vault_token_account` -> InvalidVaultAccount,
//!     `require_token_balance` -> InvalidTokenAccount (:26577-26587)
//!  6. `group.header.mode != 0`                     -> EngineLockActive (:26597)
//!  7. `reject_permissionless_resolve_matured_live_view` (:26600; covered natively in
//!     `v16_wrapper_cure_and_cancel_close_rejects_after_permissionless_resolve_maturity`)
//!  8. `authorize_owner_or_nft_holder`              -> Unauthorized (:26630)
//!  9. engine `preflight_cure_and_cancel_close`: ledger must be active, not finalized, not
//!     canceled, no irreversible progress, residual == gross, barrier count != 0
//!     -> LockActive (engine v16.rs `preflight_cure_and_cancel_close`)
//! 10. engine: `cured_equity < certified_initial_req` -> InvalidConfig (EngineInvalidConfig)
//!     (note: the bar is the INITIAL requirement, which is above maintenance)
//!
//! Every refusal asserts the exact custom error code and that the market, portfolio, source
//! token and vault token account bytes are unchanged.
use litesvm::LiteSVM;
use percolator::{CloseProgressLedgerV16, MarketModeV16, SideV16, POS_SCALE};
use percolator_prog::{
    error::PercolatorError,
    ix::Instruction as ProgInstruction,
    state,
};
use solana_sdk::{
    account::Account,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::path::PathBuf;

fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("P1_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {:?}. Run `cargo build-sbf --no-default-features` first",
        path
    );
    path
}

fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            home.push(".cargo");
            home
        });
    let registry_src = cargo_home.join("registry/src");
    for registry in std::fs::read_dir(&registry_src).expect("registry/src") {
        let candidate = registry
            .expect("registry entry")
            .path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("could not find LiteSVM SPL Token BPF under {registry_src:?}");
}

fn make_mint_data() -> Vec<u8> {
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}

fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}

fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse()
        .unwrap();
    Pubkey::find_program_address(
        &[
            vault_authority.as_ref(),
            spl_token::ID.as_ref(),
            mint.as_ref(),
        ],
        &ata_program,
    )
    .0
}

fn custom_code(err: &str) -> Option<u32> {
    let marker = "Custom(";
    let start = err.find(marker)? + marker.len();
    let end = start + err[start..].find(')')?;
    err[start..end].parse().ok()
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    portfolio_len: usize,
}

/// Everything a refusal must leave byte-identical.
struct Snapshot(Vec<(Pubkey, Account)>);

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(program_path()).expect("read BPF"));
        svm.add_program(
            spl_token::ID,
            &std::fs::read(spl_token_program_path()).expect("read token BPF"),
        );
        let payer = Keypair::new();
        let admin = Keypair::new();
        let market_kp = Keypair::new();
        let market = market_kp.pubkey();
        let mint = Pubkey::new_unique();
        let vault_authority =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id).0;
        let vault = canonical_vault_ata(&vault_authority, &mint);
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
        let spl_acct = |data: Vec<u8>| Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        };
        svm.set_account(mint, spl_acct(make_mint_data())).unwrap();
        svm.set_account(vault, spl_acct(make_token_data(mint, vault_authority, 0)))
            .unwrap();
        let market_len = state::market_account_len_for_capacity(1).unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; market_len],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let mut env = Self {
            svm,
            program_id,
            payer,
            market,
            mint,
            vault,
            portfolio_len: state::portfolio_account_len_for_market_slots(1).unwrap(),
        };
        env.send(
            ProgInstruction::InitMarket {
                max_portfolio_assets: 1,
                h_min: 0,
                h_max: 10,
                initial_price: 100,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps: 10_000,
                initial_margin_bps: 10_000,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps: 0,
                liquidation_fee_bps: 0,
                liquidation_fee_cap: 0,
                min_liquidation_abs: 0,
                max_price_move_bps_per_slot: 10_000,
                max_accrual_dt_slots: 1,
                max_abs_funding_e9_per_slot: 0,
                min_funding_lifetime_slots: 1,
                max_account_b_settlement_chunks: 1,
                max_bankrupt_close_chunks: 1,
                max_bankrupt_close_lifetime_slots: 100,
                public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
                maintenance_fee_per_slot: 0,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, true),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin, &market_kp],
        )
        .expect("init market");
        env
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<u64, String> {
        let instruction = Instruction {
            program_id: self.program_id,
            accounts,
            data: ix.encode(),
        };
        let mut all = vec![&self.payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::request_heap_frame(128 * 1024),
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instruction,
            ],
            Some(&self.payer.pubkey()),
            &all,
            self.svm.latest_blockhash(),
        );
        match self.svm.send_transaction(tx) {
            Ok(meta) => Ok(meta.compute_units_consumed),
            Err(e) => Err(format!("{:?}", e.err)),
        }
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        let kp = Keypair::new();
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        self.svm
            .set_account(
                kp.pubkey(),
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; self.portfolio_len],
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.send(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(kp.pubkey(), true),
            ],
            &[owner, &kp],
        )
        .expect("init portfolio");
        kp.pubkey()
    }

    fn token_account_for_mint(&mut self, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
        let token = Pubkey::new_unique();
        self.svm
            .set_account(
                token,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        token
    }

    fn token_amount(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }

    /// (portfolio_id, matcher_sequence, position_epoch) read live off the account bytes.
    fn identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
        let source = self.token_account_for_mint(self.mint, owner.pubkey(), amount as u64);
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        self.send(
            ProgInstruction::Deposit {
                portfolio_id,
                expected_sequence,
                amount,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[owner],
        )
        .expect("deposit");
    }

    fn withdraw(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Result<u64, String> {
        let dest = self.token_account_for_mint(self.mint, owner.pubkey(), 0);
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        let vault_authority =
            Pubkey::find_program_address(&[b"vault", self.market.as_ref()], &self.program_id).0;
        self.send(
            ProgInstruction::Withdraw {
                portfolio_id,
                expected_sequence,
                amount,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[owner],
        )
    }

    fn trade(
        &mut self,
        a: (&Keypair, Pubkey),
        b: (&Keypair, Pubkey),
        size_q: i128,
        exec_price: u64,
    ) {
        let (a_id, _, a_epoch) = self.identity(a.1);
        let (b_id, _, b_epoch) = self.identity(b.1);
        let market_id = state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            0,
        )
        .unwrap()
        .3;
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id,
                asset_index: 0,
                size_q,
                exec_price,
                fee_bps: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(a.0.pubkey(), true),
                AccountMeta::new(b.0.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(a.1, false),
                AccountMeta::new(b.1, false),
            ],
            &[a.0, b.0],
        )
        .expect("trade");
    }

    /// STATE POKE (same shape as `V16CuEnv::seed_cancellable_close_progress` in v16_cu.rs): a
    /// genuinely pending, cancellable close ledger plus the matching domain loss barrier.
    fn seed_cancellable_close(&mut self, portfolio: Pubkey) {
        let mut market_account = self.svm.get_account(&self.market).unwrap();
        let mut portfolio_account = self.svm.get_account(&portfolio).unwrap();
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut account = state::read_portfolio(&portfolio_account.data).unwrap();
        account.close_progress = CloseProgressLedgerV16 {
            active: true,
            finalized: false,
            canceled: false,
            close_id: 1,
            asset_index: 0,
            market_id: group.assets[0].market_id,
            domain_side: SideV16::Long,
            gross_loss_at_close_start: 10,
            drift_reference_slot: 0,
            max_close_slot: 10,
            residual_remaining: 10,
            ..CloseProgressLedgerV16::EMPTY
        };
        group.pending_domain_loss_barriers[0] = 1;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_account.data, &account).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio, portfolio_account).unwrap();
    }

    /// STATE POKE: lower an account's capital (and the matching c_tot / vault) so that its
    /// equity sits below the initial requirement of its open position.
    fn drain_capital_to(&mut self, portfolio: Pubkey, new_capital: u128) {
        let mut market_account = self.svm.get_account(&self.market).unwrap();
        let mut portfolio_account = self.svm.get_account(&portfolio).unwrap();
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut account = state::read_portfolio(&portfolio_account.data).unwrap();
        let delta = account.capital - new_capital;
        account.capital = new_capital;
        group.c_tot -= delta;
        group.vault -= delta;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_account.data, &account).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio, portfolio_account).unwrap();
    }

    fn cure_metas(
        &self,
        owner: &Keypair,
        portfolio: Pubkey,
        source: Pubkey,
        vault: Pubkey,
    ) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(portfolio, false),
            AccountMeta::new(source, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ]
    }

    fn cure(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        source: Pubkey,
        amount: u128,
    ) -> Result<u64, String> {
        let metas = self.cure_metas(owner, portfolio, source, self.vault);
        self.cure_with(owner, portfolio, amount, metas)
    }

    fn cure_with(
        &mut self,
        signer: &Keypair,
        portfolio: Pubkey,
        amount: u128,
        metas: Vec<AccountMeta>,
    ) -> Result<u64, String> {
        let (portfolio_id, _, position_epoch) = self.identity(portfolio);
        self.send(
            ProgInstruction::CureAndCancelClose {
                portfolio_id,
                position_epoch,
                optional_deposit: amount,
            },
            metas,
            &[signer],
        )
    }

    fn snapshot(&self, keys: &[Pubkey]) -> Snapshot {
        Snapshot(
            keys.iter()
                .map(|k| (*k, self.svm.get_account(k).unwrap()))
                .collect(),
        )
    }

    fn assert_unchanged(&self, snap: &Snapshot, what: &str) {
        for (key, before) in &snap.0 {
            assert_eq!(
                &self.svm.get_account(key).unwrap(),
                before,
                "{what}: account {key} changed on a rejected CureAndCancelClose"
            );
        }
    }
}

fn assert_code(err: &str, expected: PercolatorError) {
    assert_eq!(
        custom_code(err),
        Some(expected as u32),
        "expected {expected:?} ({}); got {err}",
        expected as u32
    );
}

/// Two funded portfolios holding an opposite POS_SCALE position at price 100 (notional/IM 100,
/// margin 100%). Returns (env, long_owner, long, short_owner, short).
fn env_with_position() -> (Env, Keypair, Pubkey, Keypair, Pubkey) {
    let mut env = Env::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long = env.create_portfolio(&long_owner);
    let short = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long, 10_000);
    env.deposit(&short_owner, short, 10_000);
    env.trade((&long_owner, long), (&short_owner, short), POS_SCALE as i128, 100);
    (env, long_owner, long, short_owner, short)
}

// ───────────────────────────── success paths ─────────────────────────────

#[test]
fn cure_cancel_close_success_flat_account_cancels_close_and_account_is_healthy() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 100);
    env.seed_cancellable_close(portfolio);
    let before = state::read_portfolio(&env.svm.get_account(&portfolio).unwrap().data).unwrap();
    assert!(before.close_progress.active && !before.close_progress.canceled);
    let (_, _, epoch_before) = env.identity(portfolio);
    let (_, group_before) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert_eq!(group_before.pending_domain_loss_barriers[0], 1);

    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 20);
    env.cure(&owner, portfolio, source, 20).expect("cure");

    let account = state::read_portfolio(&env.svm.get_account(&portfolio).unwrap().data).unwrap();
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert!(account.close_progress.canceled, "close must be cancelled");
    assert!(!account.close_progress.active, "cancelled close is no longer active");
    assert_eq!(account.capital, 120, "deposit credited to capital");
    assert_eq!(account.cancel_deposit_escrow, 0);
    assert_eq!(group.c_tot, 120);
    assert_eq!(group.vault, 120);
    assert_eq!(group.pending_domain_loss_barriers[0], 0, "barrier released");
    assert_eq!(env.token_amount(source), 0);
    assert_eq!(env.token_amount(env.vault), 120);
    assert_eq!(env.identity(portfolio).2, epoch_before + 1, "a landed Cure bumps position_epoch");

    // Healthy afterwards: the flat account can withdraw ALL of its capital, and the same
    // Cure cannot be replayed (nothing left to cancel).
    env.withdraw(&owner, portfolio, 120).expect("withdraw after cure");
    let account = state::read_portfolio(&env.svm.get_account(&portfolio).unwrap().data).unwrap();
    assert_eq!(account.capital, 0);
}

#[test]
fn cure_cancel_close_success_with_open_position_meets_initial_requirement() {
    let (mut env, long_owner, long, _short_owner, _short) = env_with_position();
    // Equity (35) is below the position's initial requirement (100) -> a deposit is NEEDED.
    env.drain_capital_to(long, 35);
    env.seed_cancellable_close(long);
    let source = env.token_account_for_mint(env.mint, long_owner.pubkey(), 100);
    // Control: 64 is one short (35 + 64 = 99 < 100) -> refused (also proven in the refusal test);
    // 65 reaches the requirement and cures.
    env.cure(&long_owner, long, source, 65).expect("cure with sufficient deposit");

    let account = state::read_portfolio(&env.svm.get_account(&long).unwrap().data).unwrap();
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert!(account.close_progress.canceled && !account.close_progress.active);
    assert_eq!(account.capital, 100);
    assert_eq!(group.pending_domain_loss_barriers[0], 0);
    assert_eq!(env.token_amount(source), 35);
    // the position is still open and the account stays usable (Deposit lands).
    assert!(!percolator::active_bitmap_is_empty(account.active_bitmap));
    env.deposit(&long_owner, long, 5);
    let account = state::read_portfolio(&env.svm.get_account(&long).unwrap().data).unwrap();
    assert_eq!(account.capital, 105);
}

// ───────────────────────────── refusals ─────────────────────────────

#[test]
fn cure_cancel_close_refuses_wrong_signer() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();
    let source = env.token_account_for_mint(env.mint, attacker.pubkey(), 20);
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
    let metas = env.cure_metas(&attacker, portfolio, source, env.vault);
    let err = env.cure_with(&attacker, portfolio, 20, metas).expect_err("non-owner");
    assert_code(&err, PercolatorError::Unauthorized);
    env.assert_unchanged(&snap, "wrong signer");
}

#[test]
fn cure_cancel_close_refuses_owner_not_signing() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 20);
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
    let mut metas = env.cure_metas(&owner, portfolio, source, env.vault);
    metas[0] = AccountMeta::new(owner.pubkey(), false); // owner present but unsigned
    let payer = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    let err = env.cure_with(&payer, portfolio, 20, metas).expect_err("unsigned owner");
    assert_code(&err, PercolatorError::ExpectedSigner);
    env.assert_unchanged(&snap, "owner not signing");
}

#[test]
fn cure_cancel_close_refuses_when_no_close_is_pending() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 100);
    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 20);
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
    let err = env.cure(&owner, portfolio, source, 20).expect_err("no close pending");
    assert_code(&err, PercolatorError::EngineLockActive);
    env.assert_unchanged(&snap, "no pending close");
}

#[test]
fn cure_cancel_close_refuses_replay_after_cancel() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 40);
    env.cure(&owner, portfolio, source, 20).expect("first cure");
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
    // `cure` re-reads the (bumped) position_epoch, so only the closing-state check can reject.
    let err = env.cure(&owner, portfolio, source, 20).expect_err("already cancelled");
    assert_code(&err, PercolatorError::EngineLockActive);
    env.assert_unchanged(&snap, "replay after cancel");
}

#[test]
fn cure_cancel_close_refuses_cure_that_leaves_account_below_requirement() {
    let (mut env, long_owner, long, _short_owner, _short) = env_with_position();
    env.drain_capital_to(long, 35);
    env.seed_cancellable_close(long);
    let source = env.token_account_for_mint(env.mint, long_owner.pubkey(), 100);
    let snap = env.snapshot(&[env.market, long, source, env.vault]);
    // no deposit at all, then a deposit one atom short of the requirement (35 + 64 = 99 < 100)
    for amount in [0u128, 20, 64] {
        let err = env
            .cure(&long_owner, long, source, amount)
            .expect_err("cure below requirement must refuse");
        assert_code(&err, PercolatorError::EngineInvalidConfig);
        env.assert_unchanged(&snap, "insufficient cure");
    }
    let account = state::read_portfolio(&env.svm.get_account(&long).unwrap().data).unwrap();
    assert!(account.close_progress.active && !account.close_progress.canceled);
}

#[test]
fn cure_cancel_close_refuses_wrong_source_account() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let stranger = Pubkey::new_unique();
    let other_mint = Pubkey::new_unique();
    env.svm
        .set_account(
            other_mint,
            Account {
                lamports: 1_000_000_000,
                data: make_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let foreign_owner_src = env.token_account_for_mint(env.mint, stranger, 20);
    let wrong_mint_src = env.token_account_for_mint(other_mint, owner.pubkey(), 20);
    let short_src = env.token_account_for_mint(env.mint, owner.pubkey(), 19);
    let cases = [
        ("source owned by someone else", foreign_owner_src, PercolatorError::InvalidTokenAccount),
        ("source of the wrong mint", wrong_mint_src, PercolatorError::InvalidMint),
        ("source balance below the cure amount", short_src, PercolatorError::InvalidTokenAccount),
    ];
    for (what, source, code) in cases {
        let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
        let err = env.cure(&owner, portfolio, source, 20).expect_err(what);
        assert_code(&err, code);
        env.assert_unchanged(&snap, what);
    }
}

#[test]
fn cure_cancel_close_refuses_non_canonical_vault() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 20);
    let vault_authority =
        Pubkey::find_program_address(&[b"vault", env.market.as_ref()], &env.program_id).0;
    // right mint and authority, but not the canonical ATA address
    let fake_vault = env.token_account_for_mint(env.mint, vault_authority, 0);
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault, fake_vault]);
    let metas = env.cure_metas(&owner, portfolio, source, fake_vault);
    let err = env.cure_with(&owner, portfolio, 20, metas).expect_err("fake vault");
    assert_code(&err, PercolatorError::InvalidVaultAccount);
    env.assert_unchanged(&snap, "non-canonical vault");
}

#[test]
fn cure_cancel_close_refuses_resolved_market() {
    let mut env = Env::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.seed_cancellable_close(portfolio);
    let mut market_account = env.svm.get_account(&env.market).unwrap();
    let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
    group.mode = MarketModeV16::Resolved;
    group.resolved_slot = group.current_slot;
    state::write_market(&mut market_account.data, &cfg, &group).unwrap();
    env.svm.set_account(env.market, market_account).unwrap();
    let source = env.token_account_for_mint(env.mint, owner.pubkey(), 20);
    let snap = env.snapshot(&[env.market, portfolio, source, env.vault]);
    let err = env.cure(&owner, portfolio, source, 20).expect_err("resolved market");
    assert_code(&err, PercolatorError::EngineLockActive);
    env.assert_unchanged(&snap, "resolved market");
}
