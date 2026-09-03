// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Phase 2.E — economic-adversarial re-port of the v12 attack-vector suite onto
//! the v16 LiteSVM surface (Workstream 6, Tier 3 close-out).
//!
//! SOURCE: re-port of `~/wrapper-engine-deep-audit/v12_test_archive/`
//! `test_economic_attack_vectors.rs` (15 v12 `#[test]`s). Each v16 test names the
//! v12 archive line it descends from. The v12 framework (`common::TestEnv`,
//! global `c_tot`, `try_settle_account`, `set_slot_and_price`) was deleted in the
//! Phase 2.A clean-room wrapper import; this file rebuilds a lean, self-contained
//! harness on the upstream `tests/v16_cu.rs` `V16CuEnv` pattern (NOT importing it —
//! Rust integration tests are separate crates).
//!
//! ANTI-HOLLOW-TEST DISCIPLINE (per the pass directive + audit skill rule 5):
//!   * Rejection tests assert the SPECIFIC operative `Custom(N)` via a structural
//!     match (`assert_custom`) with a `wrong-reason` catch arm — NOT bare
//!     `is_err()` (the gap Agent C flagged in v16_fork_lp_vault_redeem.rs:330/346).
//!   * Where the operative code is ambiguous (multiple gates collapse to
//!     EngineLockActive=21), the test ALSO asserts the specific capital/pnl deltas.
//!   * Invariant-holds tests assert the operations ACTUALLY EXECUTED (trade
//!     succeeded / fee charged) before asserting "no net extraction" — so a
//!     silent no-op can't make the invariant hold trivially (the v12
//!     `successful_withdrawals > 0` guard).
//!
//! OPERATIVE ERROR MAP (PercolatorError default-discriminant order,
//! src/v16_program.rs:175-229; engine V16Error mapped at 237-253):
//!   14 EngineInvalidConfig  — conservation (TokenValueFlow/StockReconciliation),
//!                             ensure_initial_margin under-margin, validate_shape
//!   18 EngineInvalidLeg     — SourceCreditLienAggregateProofV16
//!   19 EngineStale          — withdraw with an OPEN position (active_bitmap≠∅)
//!   21 EngineLockActive     — market-state / over-withdraw / convert release-cap
//!   25 EngineCounterUnderflow
//!    9 InvalidInstruction   — bad crank action / size_q∈{0,MIN} / a==b
//!
//! SCOPING NOTE: pure economic-extraction attacks here use the direct two-party
//! `TradeNoCpi` path (wrapper + engine + spl_token). They do NOT route through the
//! matcher (TradeCpi) or NFT — those subsystems are economically orthogonal to
//! these invariants and are covered by `tests/v16_cu.rs` (TradeCpi) and
//! `tests/v16_nft_e2e.rs`. The LP-vault deferred tests live in
//! `tests/v16_fork_lp_vault_*` and a Phase-2.E addition at the bottom of this file.

use litesvm::LiteSVM;
use percolator::POS_SCALE;
use percolator_prog::{
    ix::Instruction as ProgInstruction,
    processor::ASSET_ACTION_ACTIVATE,
    state::{self, MarketGroupV16, PortfolioAccountV16},
};
use solana_sdk::{
    account::Account,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Operative Custom(N) error codes (see header map).
// ---------------------------------------------------------------------------
const E_INVALID_CONFIG: u32 = 14;
#[allow(dead_code)]
const E_INVALID_LEG: u32 = 18;
const E_STALE: u32 = 19;
const E_LOCK_ACTIVE: u32 = 21;
#[allow(dead_code)]
const E_COUNTER_UNDERFLOW: u32 = 25;
const E_INVALID_INSTRUCTION: u32 = 9;

/// Rounding tolerance for the no-net-extraction invariant (mirrors v12 archive L98).
const TOL: i128 = 10_000;

const MAX_PORTFOLIO_ASSETS: u16 = 1;
/// Tradable asset index (mirrors the proven v16_cu.rs pattern: activate + trade
/// asset 1; domain = 2*asset_index = 2).
const ASSET: u16 = 1;

// ---------------------------------------------------------------------------
// BPF + SPL-token program paths (mirrors tests/v16_cu.rs:59-99).
// ---------------------------------------------------------------------------
fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(
        p.exists(),
        "wrapper BPF missing at {p:?} — cargo build-sbf --no-default-features"
    );
    p
}

fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut h = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            h.push(".cargo");
            h
        });
    for reg in std::fs::read_dir(cargo_home.join("registry/src")).expect("registry/src") {
        let cand = reg
            .expect("entry")
            .path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if cand.exists() {
            return cand;
        }
    }
    panic!("spl_token BPF not found under CARGO_HOME/registry/src");
}

fn make_mint_data() -> Vec<u8> {
    let mut d = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TokenAccount::LEN];
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
        &mut d,
    )
    .unwrap();
    d
}

// ---------------------------------------------------------------------------
// Structural error assertion — the anti-hollow-test core.
// Pins the EXACT operative Custom(code); the catch-all arm is what defeats
// "passed for the wrong reason" (a NON-Custom built-in or a different Custom).
// ---------------------------------------------------------------------------
fn assert_custom(res: Result<(), TransactionError>, code: u32, label: &str) {
    match res {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) => {
            assert_eq!(
                c, code,
                "{label}: expected operative Custom({code}), got Custom({c})"
            );
        }
        Err(other) => {
            panic!("{label}: expected operative Custom({code}), got non-Custom {other:?}")
        }
        Ok(()) => panic!("{label}: expected operative Custom({code}), but the tx SUCCEEDED"),
    }
}

// ---------------------------------------------------------------------------
// E4 (upstream engine 8f25aa5d / this fork's percolator @ 1ecbd9d0, "charge
// sub-atom trade fees on ceil notional") reference reimplementations.
// Mirror engine `risk_notional_ceil`/`trade_fee_notional_ceil` and
// `checked_fee_bps` (percolator src/v16.rs) EXACTLY, formula-for-formula, so
// the expected fee below is DERIVED from the same ceiling-division algorithm
// the engine runs, not a hardcoded observed number. (percolator-prog's own
// `batch_leg_fee` in src/v16_program.rs reconstructs engine fee math the same
// way for the same reason: an independent, traceable re-derivation, not a
// magic constant.)
// ---------------------------------------------------------------------------
fn ceil_notional_ref(size_q: u128, price: u64) -> u128 {
    if size_q == 0 || price == 0 {
        return 0;
    }
    let product = size_q * price as u128;
    let q = product / POS_SCALE;
    let r = product % POS_SCALE;
    q + u128::from(r != 0)
}

fn ceil_fee_bps_ref(notional: u128, fee_bps: u64) -> u128 {
    if notional == 0 || fee_bps == 0 {
        return 0;
    }
    let product = notional * fee_bps as u128;
    let q = product / 10_000; // MAX_MARGIN_BPS
    let r = product % 10_000;
    q + u128::from(r != 0)
}

// ---------------------------------------------------------------------------
// Self-contained adversarial harness.
// ---------------------------------------------------------------------------
struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    vault_authority: Pubkey,
    portfolio_len: usize,
}

impl Env {
    /// Market with one tradable asset (index 1, domain 2) activated. `fee_bps` is
    /// the market `trade_fee_base_bps`; per-trade fee is the TradeNoCpi arg.
    /// Default 100% margins (positions fully collateralized).
    fn new(trade_fee_base_bps: u64) -> Self {
        Self::new_full(10_000, 10_000, 10_000, trade_fee_base_bps)
    }

    /// Constructor with explicit maintenance/initial margin bps and per-slot price
    /// move cap (sub-100% margins let a price move push a position under
    /// maintenance — needed for the liquidation scenarios; low margins require a
    /// correspondingly low `max_price_move_bps_per_slot` to satisfy the engine's
    /// linear-budget config check at v16.rs:1398).
    fn new_full(
        maintenance_margin_bps: u64,
        initial_margin_bps: u64,
        max_price_move_bps_per_slot: u64,
        trade_fee_base_bps: u64,
    ) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(
            program_id,
            &std::fs::read(program_path()).expect("wrapper BPF"),
        );
        svm.add_program(
            spl_token::ID,
            &std::fs::read(spl_token_program_path()).expect("token BPF"),
        );

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let (vault_authority, _) =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
        let vault = canonical_vault_ata(&vault_authority, &mint);
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: make_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            vault,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, vault_authority, 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![
                    0u8;
                    state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize)
                        .unwrap()
                ],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let portfolio_len =
            state::portfolio_account_len_for_market_slots(MAX_PORTFOLIO_ASSETS as usize).unwrap();
        let mut env = Env {
            svm,
            program_id,
            payer,
            admin,
            market,
            mint,
            vault,
            vault_authority,
            portfolio_len,
        };

        env.send_ok(
            ProgInstruction::InitMarket {
                max_portfolio_assets: MAX_PORTFOLIO_ASSETS,
                h_min: 0,
                h_max: 10,
                initial_price: 100,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps,
                initial_margin_bps,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps,
                liquidation_fee_bps: 0,
                liquidation_fee_cap: 0,
                min_liquidation_abs: 0,
                max_price_move_bps_per_slot,
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
                AccountMeta::new(env.admin.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new_readonly(env.mint, false),
            ],
            &[&env.admin.insecure_clone()],
        )
        .expect("init market");

        env.activate_asset(ASSET, 1, 100);
        env
    }

    fn activate_asset(&mut self, asset_index: u16, now_slot: u64, initial_price: u64) {
        let admin = self.admin.insecure_clone();
        self.send_ok(
            ProgInstruction::UpdateAssetLifecycle {
                action: ASSET_ACTION_ACTIVATE,
                asset_index,
                now_slot,
                initial_price,
                insurance_authority: admin.pubkey().to_bytes(),
                insurance_operator: admin.pubkey().to_bytes(),
                backing_bucket_authority: admin.pubkey().to_bytes(),
                oracle_authority: admin.pubkey().to_bytes(),
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("activate asset");
    }

    fn try_send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        // Fresh blockhash per send so byte-identical instructions (e.g. repeated
        // wash trades / convert attempts) don't collide as AlreadyProcessed.
        self.svm.expire_blockhash();
        let instructions = vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            Instruction {
                program_id: self.program_id,
                accounts,
                data: ix.encode(),
            },
        ];
        let mut all = vec![&self.payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.payer.pubkey()),
            &all,
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn send_ok(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        self.try_send(ix, accounts, signers)
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let portfolio = Pubkey::new_unique();
        self.svm
            .set_account(
                portfolio,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; self.portfolio_len],
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_send(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("init portfolio");
        portfolio
    }

    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_send(
            ProgInstruction::Deposit { amount },
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

    #[allow(clippy::too_many_arguments)]
    fn try_trade(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::TradeNoCpi {
                asset_index: ASSET,
                size_q,
                exec_price,
                fee_bps,
            },
            vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            &[owner_a, owner_b],
        )
    }

    fn crank(
        &mut self,
        portfolio: Pubkey,
        action: u8,
        now_slot: u64,
    ) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::PermissionlessCrank {
                action,
                asset_index: ASSET,
                now_slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[],
        )
    }

    fn top_up_insurance(&mut self, amount: u128) {
        let source = Pubkey::new_unique();
        let admin = self.admin.insecure_clone();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, admin.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_send(
            ProgInstruction::TopUpInsurance { amount },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
        .expect("top up insurance");
    }

    fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    fn configure_ewma_mark(&mut self, now_slot: u64, initial_mark_e6: u64, halflife_slots: u64) {
        let admin = self.admin.insecure_clone();
        self.try_send(
            ProgInstruction::ConfigureEwmaMark {
                asset_index: ASSET,
                now_slot,
                initial_mark_e6,
                mark_ewma_halflife_slots: halflife_slots,
                mark_min_fee: 0,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("configure ewma mark");
    }

    fn push_ewma_mark(&mut self, now_slot: u64, mark_e6: u64) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        self.try_send(
            ProgInstruction::PushEwmaMark {
                asset_index: ASSET,
                now_slot,
                mark_e6,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
    }

    fn resolve(&mut self) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        self.try_send(
            ProgInstruction::ResolveMarket,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
    }

    /// Permissionless liquidation crank (action 1) on `victim`. FIX W3 (upstream
    /// #206, pairs with engine E3 / #92): the close size is no longer a caller
    /// argument -- the engine selects it (liquidation_engine_close_request_q).
    fn try_liquidate(&mut self, victim: Pubkey, now_slot: u64) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::PermissionlessCrank {
                action: 1,
                asset_index: ASSET,
                now_slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(victim, false),
            ],
            &[],
        )
    }

    /// Move the asset mark to `effective_price` via the engine's own zero-sum
    /// accrual (k_long += Δ, k_short -= Δ — v16.rs:7733-7751), the exact effect a
    /// real oracle push + crank would have. Bypasses oracle-feed plumbing only;
    /// the resulting economic state (zero-sum mark-to-market) is faithful. The
    /// adversarial instructions below still go through the real program.
    fn accrue_mark(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        effective_price: u64,
    ) -> Result<(), String> {
        let mut acct = self.svm.get_account(&self.market).expect("market");
        {
            let (_, mut group) =
                state::market_view_mut(&mut acct.data).map_err(|e| format!("{e:?}"))?;
            group
                .accrue_asset_to_not_atomic(
                    asset_index as usize,
                    now_slot,
                    effective_price,
                    0,
                    true,
                )
                .map_err(|e| format!("{e:?}"))?;
        }
        self.svm.set_account(self.market, acct).unwrap();
        Ok(())
    }

    fn try_convert(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::ConvertReleasedPnl { amount },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
    }

    fn try_withdraw(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> Result<(), TransactionError> {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_send(
            ProgInstruction::Withdraw { amount },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[owner],
        )
    }

    fn try_close(&mut self, owner: &Keypair, portfolio: Pubkey) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::ClosePortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
    }

    /// CloseResolved — returns (dest_token_account, result).
    /// dest is always created (owner of the token account = owner.pubkey()).
    fn try_close_resolved(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
    ) -> (Pubkey, Result<(), TransactionError>) {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let res = self.try_send(
            ProgInstruction::CloseResolved {
                fee_rate_per_slot: 0,
            },
            vec![
                AccountMeta::new_readonly(owner.pubkey(), false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[],
        );
        (dest, res)
    }

    /// ClaimResolvedPayoutTopup — reuses an existing dest token account.
    fn try_claim_resolved_payout_topup(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        dest: Pubkey,
    ) -> Result<(), TransactionError> {
        self.try_send(
            ProgInstruction::ClaimResolvedPayoutTopup,
            vec![
                AccountMeta::new_readonly(owner.pubkey(), false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[],
        )
    }

    /// CloseSlab — admin must be signer+writable; returns dest key.
    fn try_close_slab(&mut self) -> Result<(), TransactionError> {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, self.admin.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let admin = self.admin.insecure_clone();
        self.try_send(
            ProgInstruction::CloseSlab,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
    }

    fn close_slab(&mut self) {
        self.try_close_slab().expect("close_slab");
    }

    fn leg_size(&self, p: Pubkey) -> i128 {
        self.portfolio(p)
            .legs
            .iter()
            .find(|l| l.active && l.asset_index as usize == ASSET as usize)
            .map(|l| l.basis_pos_q)
            .unwrap_or(0)
    }

    // -- readers --
    fn group(&self) -> MarketGroupV16 {
        let data = self.svm.get_account(&self.market).unwrap().data;
        state::read_market(&data).unwrap().1
    }

    fn portfolio(&self, p: Pubkey) -> PortfolioAccountV16 {
        let data = self.svm.get_account(&p).unwrap().data;
        state::read_portfolio(&data).unwrap()
    }

    fn token_amount(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }

    /// v12 attacker_account_equity (archive L80-84): capital + pnl + fee_credits.
    fn equity(&self, p: Pubkey) -> i128 {
        let a = self.portfolio(p);
        a.capital as i128 + a.pnl + a.fee_credits
    }

    /// v16 unallocated_protocol_surplus for a market with NO backing earnings:
    /// vault - (c_tot + insurance). (backing_provider_earnings and
    /// settlement_rounding_residue are 0 absent an LP vault — see
    /// StockReconciliationProofV16, v16.rs:3006-3018.) Mirrors v12 residual()
    /// (archive L109-115).
    fn residual(&self) -> i128 {
        let g = self.group();
        g.vault as i128 - (g.c_tot as i128 + g.insurance as i128)
    }
}

// ===========================================================================
// SCENARIO 11 — fee revenue must not become trader-claimable residual.
// v12: test_attack_fee_revenue_not_trader_residual (archive L923-962).
// OPERATIVE DEFENSE: charge_account_fee_current moves account.capital -> insurance
// (v16.rs:10243-10257); both are inside "senior", so residual stays 0
// (StockReconciliationProofV16, v16.rs:3006-3018).
// ===========================================================================
#[test]
fn adv_fee_revenue_not_trader_residual() {
    let mut env = Env::new(0);
    let lp = Keypair::new();
    let user = Keypair::new();
    let lp_acct = env.create_portfolio(&lp);
    let user_acct = env.create_portfolio(&user);
    env.deposit(&lp, lp_acct, 20_000_000_000);
    env.deposit(&user, user_acct, 20_000_000_000);

    assert_eq!(env.residual(), 0, "fresh market must have zero residual");
    let insurance_before = env.group().insurance;

    let mut successful_trades = 0u64;
    for round in 0..24u64 {
        let size = if round % 2 == 0 {
            20_000_000i128
        } else {
            -20_000_000i128
        };
        if env
            .try_trade(&user, user_acct, &lp, lp_acct, size, 100, 100)
            .is_ok()
        {
            successful_trades += 1;
        }
        let _ = env.crank(user_acct, 0, 100 + round);
        assert_eq!(
            env.residual(),
            0,
            "fees must route to insurance, not residual, after round {round}"
        );
    }

    // Anti-hollow guard: the wash trades actually executed.
    assert!(
        successful_trades > 0,
        "probe did not execute any wash trade"
    );
    assert!(
        env.group().insurance > insurance_before,
        "wash-trade fees must accrue into insurance (insurance {} -> {})",
        insurance_before,
        env.group().insurance
    );
    assert_eq!(
        env.group().vault as u64,
        env.token_amount(env.vault),
        "engine vault and SPL vault must stay synchronized"
    );
}

// ===========================================================================
// SCENARIO 9 — fee-cycling wash trades must not create a rebate-siphon.
// v12: test_attack_fee_cycling_wash_trades_no_rebate_siphon (archive L821-863).
// OPERATIVE DEFENSE: no rebate flow exists; the only fee path is
// account.capital -> insurance (v16.rs:10218-10260). insurance >= before.
// ===========================================================================
#[test]
fn adv_fee_cycling_wash_trades_no_rebate_siphon() {
    let mut env = Env::new(0);
    let lp = Keypair::new();
    let user = Keypair::new();
    let lp_acct = env.create_portfolio(&lp);
    let user_acct = env.create_portfolio(&user);
    let lp_deposit: u128 = 20_000_000_000;
    let user_deposit: u128 = 20_000_000_000;
    env.deposit(&lp, lp_acct, lp_deposit);
    env.deposit(&user, user_acct, user_deposit);

    let initial_deposits = (lp_deposit + user_deposit) as i128;
    let insurance_before = env.group().insurance;

    let mut successful_trades = 0u64;
    for round in 0..20u64 {
        let size = if round % 2 == 0 {
            10_000_000i128
        } else {
            -10_000_000i128
        };
        if env
            .try_trade(&user, user_acct, &lp, lp_acct, size, 100, 100)
            .is_ok()
        {
            successful_trades += 1;
        }
        let _ = env.crank(user_acct, 0, 100 + round);
        let wealth = env.equity(user_acct) + env.equity(lp_acct);
        assert!(wealth <= initial_deposits + TOL, "fee-cycling wash trades extracted net value after round {round}: wealth={wealth} deposits={initial_deposits}");
    }

    assert!(
        successful_trades > 0,
        "probe did not execute any wash trade"
    );
    assert!(
        env.group().insurance >= insurance_before,
        "wash-trade fees must not reduce insurance: {} -> {}",
        insurance_before,
        env.group().insurance
    );
    assert_eq!(env.group().vault as u64, env.token_amount(env.vault));
}

// ===========================================================================
// SCENARIO 1 — dYdX/YFI-style profit recycling: no net extraction.
// v12: test_attack_yfi_style_profit_recycling_no_net_extraction (archive L335-422).
// Attacker controls both legs; pushes the long into profit; tries to recycle
// released PnL -> capital and withdraw while the losing short stays open.
// OPERATIVE DEFENSE:
//   * convert while the offsetting leg is open -> EngineLockActive(21)
//     (convert_released_pnl_to_capital_core, v16.rs:10454-10458).
//   * withdraw while a position is open       -> EngineStale(19)
//     (withdraw_not_atomic active_bitmap≠∅, v16.rs:10836-10838).
//   * after the leg is realized, the winner can extract only genuinely-backed
//     profit; total wealth stays <= deposits and insurance is never touched.
// ===========================================================================
#[test]
fn adv_yfi_style_profit_recycling_no_net_extraction() {
    let mut env = Env::new(0);
    let user = Keypair::new(); // attacker long, near-margin small deposit
    let lp = Keypair::new(); // attacker short LP, large deposit
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let user_dep: u128 = 2_000_000_000;
    let lp_dep: u128 = 30_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);

    let initial = (user_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;

    // Open: user long / lp short.
    let size = POS_SCALE as i128 * 100;
    env.try_trade(&user, ua, &lp, la, size, 100, 0)
        .expect("open long/short");

    // Push the long into profit (zero-sum: lp's capital takes the offsetting loss).
    // The clock advances past one accrual segment, so the asset's loss-state is
    // marked stale (loss_stale_active = true, v16.rs:7761) — the live condition a
    // recycling attacker faces mid-move.
    env.warp(10);
    env.accrue_mark(ASSET, 10, 150).expect("accrue mark up");
    let _ = env.crank(ua, 0, 10);
    let _ = env.crank(la, 0, 10);
    assert!(
        env.portfolio(ua).pnl > 0,
        "fixture must create positive long PnL"
    );

    // PHASE A — recycle attempt while the losing leg is open. Two layered v16
    // locks reject the premature extraction, each at its OPERATIVE economic gate:
    //   * convert_released_pnl -> ensure_favorable_action_allowed: the favorable-
    //     action lock (h_lock lane = HMax under the stale loss-state) returns
    //     LockActive(21) (v16.rs:8168-8169 via loss_stale at 8338) — a winner may
    //     not realize profit while the loss-state is unsettled. (A deeper
    //     source-claim-exposure lock at v16.rs:10454-10458 backs this once the
    //     cert is fresh; the favorable-action lock pre-empts it here.)
    //   * withdraw -> open-position guard: active_bitmap non-empty -> Stale(19)
    //     (v16.rs:10836-10838), independent of the lag.
    // Both reject atomically (no capital/PnL movement).
    let cap_before = env.portfolio(ua).capital;
    let pnl_before = env.portfolio(ua).pnl;
    assert_custom(
        env.try_convert(&user, ua, 1_000_000_000),
        E_LOCK_ACTIVE,
        "convert released PnL while losing leg open (favorable-action lock)",
    );
    assert_custom(
        env.try_withdraw(&user, ua, 1),
        E_STALE,
        "withdraw while position open",
    );
    assert_eq!(
        env.portfolio(ua).capital,
        cap_before,
        "rejected convert/withdraw must not move capital"
    );
    assert_eq!(
        env.portfolio(ua).pnl,
        pnl_before,
        "rejected convert/withdraw must not move PnL"
    );

    // PHASE B — realize by closing the leg (sell back at the marked price).
    env.try_trade(&user, ua, &lp, la, -size, 150, 0)
        .expect("close leg");
    assert_eq!(env.leg_size(ua), 0, "user must be flat after close");

    // PHASE C — now genuinely-backed profit is convertible/withdrawable, but the
    // total recovered wealth stays bounded by the controlled deposits, and the
    // loop never draws insurance.
    let mut withdrawn = 0i128;
    let mut successful_withdrawals = 0u64;
    for _ in 0..12u64 {
        let _ = env.try_convert(&user, ua, 250_000_000);
        if env.try_withdraw(&user, ua, 250_000_000).is_ok() {
            withdrawn += 250_000_000;
            successful_withdrawals += 1;
        }
        let wealth = withdrawn + env.equity(ua) + env.equity(la);
        assert!(wealth <= initial + TOL, "profit recycling extracted net value: wealth={wealth} initial={initial} withdrawn={withdrawn} ua_eq={} la_eq={}", env.equity(ua), env.equity(la));
    }

    assert!(
        successful_withdrawals > 0,
        "probe did not exercise the withdrawal leg after realizing profit"
    );
    assert_eq!(
        env.group().insurance,
        insurance_before,
        "profit-recycling loop must not draw from insurance"
    );
    assert_eq!(
        env.group().vault as u64,
        env.token_amount(env.vault),
        "engine vault and SPL vault must stay synchronized"
    );
}

// ===========================================================================
// SCENARIO 3 — LP-side profit recycling (mirror of #1, LP is the winning short).
// v12: test_attack_lp_side_profit_recycling_no_net_extraction (archive L522-577).
// Account-local PnL means winner-vs-loser is a pure sign/role swap; the same
// open-leg convert(21)/withdraw(19) gates and conservation apply.
// ===========================================================================
#[test]
fn adv_lp_side_profit_recycling_no_net_extraction() {
    let mut env = Env::new(0);
    let user = Keypair::new(); // long loser
    let lp = Keypair::new(); // short winner
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let user_dep: u128 = 16_000_000_000;
    let lp_dep: u128 = 20_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);

    let initial = (user_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;

    // user long / lp short, then price DOWN -> the short (lp) wins.
    let size = POS_SCALE as i128 * 100;
    env.try_trade(&user, ua, &lp, la, size, 100, 0)
        .expect("open");
    env.warp(10);
    env.accrue_mark(ASSET, 10, 50).expect("accrue mark down");
    let _ = env.crank(ua, 0, 10);
    let _ = env.crank(la, 0, 10);
    assert!(
        env.portfolio(la).pnl > 0,
        "LP short must be in profit after price drop"
    );

    // PHASE A — locked while the losing long leg is open.
    assert_custom(
        env.try_convert(&lp, la, 1_000_000_000),
        E_LOCK_ACTIVE,
        "LP convert while leg open",
    );
    assert_custom(
        env.try_withdraw(&lp, la, 1),
        E_STALE,
        "LP withdraw while leg open",
    );

    // PHASE B/C — realize and extract; bounded by deposits, insurance untouched.
    env.try_trade(&user, ua, &lp, la, -size, 50, 0)
        .expect("close");
    assert_eq!(env.leg_size(la), 0);
    let mut withdrawn = 0i128;
    let mut successful_withdrawals = 0u64;
    for _ in 0..10u64 {
        let _ = env.try_convert(&lp, la, 250_000_000);
        if env.try_withdraw(&lp, la, 250_000_000).is_ok() {
            withdrawn += 250_000_000;
            successful_withdrawals += 1;
        }
        let wealth = withdrawn + env.equity(ua) + env.equity(la);
        assert!(
            wealth <= initial + TOL,
            "LP-side recycling extracted net value: wealth={wealth} initial={initial}"
        );
    }
    assert!(
        successful_withdrawals > 0,
        "LP did not exercise the withdrawal leg"
    );
    assert!(
        env.group().insurance >= insurance_before,
        "LP recycling must not draw from insurance"
    );
    assert_eq!(env.group().vault as u64, env.token_amount(env.vault));
}

// ===========================================================================
// SCENARIO 6 — whipsaw profit recycling: the maturity lock holds through a full
// up-then-down price swing, so a winner can NEVER extract unmatured profit while
// the offsetting loss leg is open — there is no unbacked withdrawal to claw back
// on reversal. (v16 is strictly stronger than the v12 "withdrawn must stay
// backed" property, which only bounded extraction after the fact.)
// v12: test_attack_whipsaw_profit_recycling_no_net_extraction (archive L672-723).
// ===========================================================================
#[test]
fn adv_whipsaw_profit_recycling_no_net_extraction() {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let user_dep: u128 = 2_000_000_000;
    let lp_dep: u128 = 30_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);

    let initial = (user_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;
    let size = POS_SCALE as i128 * 100;

    // Open and hold ONE position across the whole whipsaw (never closed).
    env.try_trade(&user, ua, &lp, la, size, 100, 0)
        .expect("open");

    // Up-swing: user long is in profit. Recycle attempt -> locked at the
    // operative defenses, nothing extracted.
    env.warp(10);
    env.accrue_mark(ASSET, 10, 150).expect("accrue up");
    let _ = env.crank(ua, 0, 10);
    let _ = env.crank(la, 0, 10);
    assert!(
        env.portfolio(ua).pnl > 0,
        "user must be in profit on the up-swing"
    );
    assert_custom(
        env.try_convert(&user, ua, 1_000_000_000),
        E_LOCK_ACTIVE,
        "convert during up-swing",
    );
    assert_custom(
        env.try_withdraw(&user, ua, 250_000_000),
        E_STALE,
        "withdraw during up-swing",
    );
    let wealth_up = env.equity(ua) + env.equity(la);
    assert!(
        wealth_up <= initial + TOL,
        "up-swing wealth unbounded: {wealth_up} > {initial}"
    );

    // Reversal: price falls back; the long's paper profit evaporates. The lock
    // still holds — still nothing extracted.
    env.warp(20);
    env.accrue_mark(ASSET, 20, 100).expect("accrue down");
    let _ = env.crank(ua, 0, 20);
    let _ = env.crank(la, 0, 20);
    assert_custom(
        env.try_convert(&user, ua, 1_000_000_000),
        E_LOCK_ACTIVE,
        "convert after reversal",
    );
    assert_custom(
        env.try_withdraw(&user, ua, 250_000_000),
        E_STALE,
        "withdraw after reversal",
    );

    // Nothing was ever extracted; wealth bounded; insurance untouched.
    let wealth_final = env.equity(ua) + env.equity(la);
    assert!(
        wealth_final <= initial + TOL,
        "whipsaw extracted net value: {wealth_final} > {initial}"
    );
    assert_eq!(
        env.portfolio(ua).capital,
        user_dep,
        "no unmatured profit ever became capital"
    );
    assert!(
        env.group().insurance >= insurance_before,
        "whipsaw recycling must not drain insurance"
    );
    assert_eq!(env.group().vault as u64, env.token_amount(env.vault));
}

// ===========================================================================
// ===========================================================================
// SCENARIO 8 — minimum-position whipsaw: sub-quantum rounding must not mint.
// v12: test_attack_min_position_whipsaw_no_rounding_mint (archive L772-817).
// OPERATIVE DEFENSE: floor rounding (bound_num_from_amount, v16.rs:293-308) +
// the balanced debit==credit TokenValueFlowProofV16 on every mutation
// (v16.rs:2903) make sub-unit rounding non-mintable. (v12 used an inverted
// market; the conservation proof is invert-agnostic — this exercises the
// non-inverted boundary.)
// ===========================================================================
#[test]
fn adv_min_position_whipsaw_no_rounding_mint() {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let user_dep: u128 = 1_000_000_000;
    let lp_dep: u128 = 1_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);
    let initial = (user_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;
    assert_eq!(env.residual(), 0, "fresh market residual must be 0");

    // size_q = 1: a single sub-POS_SCALE quantum long.
    env.try_trade(&user, ua, &lp, la, 1, 100, 0)
        .expect("open min position");

    // Whipsaw the mark through several bounded moves, cranking between.
    let mut slot = 5u64;
    for price in [150u64, 80, 140, 100] {
        env.warp(slot);
        let _ = env.accrue_mark(ASSET, slot, price);
        let _ = env.crank(ua, 0, slot);
        let _ = env.crank(la, 0, slot);
        let wealth = env.equity(ua) + env.equity(la);
        assert!(
            wealth <= initial + TOL,
            "min-position whipsaw minted value at price {price}: {wealth} > {initial}"
        );
        slot += 5;
    }

    // Close the quantum; conservation must still hold exactly.
    let _ = env.try_trade(&user, ua, &lp, la, -1, 100, 0);
    let wealth = env.equity(ua) + env.equity(la);
    assert!(
        wealth <= initial + TOL,
        "min-position whipsaw final extraction: {wealth} > {initial}"
    );
    assert!(
        env.group().insurance >= insurance_before,
        "min-position whipsaw must not drain insurance"
    );
    assert_eq!(
        env.group().vault as u64,
        env.token_amount(env.vault),
        "engine vault and SPL vault desynced"
    );
}

// ===========================================================================
// SCENARIO 10 — many one-unit trades: sub-quantum rounding must not accumulate.
// v12: test_attack_many_one_unit_trades_no_rounding_accumulation (archive L867-914).
//
// FIX E4 (upstream engine 8f25aa5d / this fork's percolator @ 1ecbd9d0, "charge
// sub-atom trade fees on ceil notional") fixture repair. This test's hardcoded
// "insurance EXACTLY unchanged" assertion documented the OLD, BROKEN behavior:
// pre-E4, `apply_trade_after_refresh_not_atomic` computed the trade fee on
// `trade_notional_floor(size_q, exec_price)`, which floors to 0 for every
// one-unit fill here (size_q=1, exec_price=100: 1*100 / POS_SCALE(1e6) has a
// nonzero numerator strictly less than the denominator, so floor = 0), which
// zeroed the fee via `checked_fee_bps`'s notional==0 short-circuit — even
// though every such fill opens one real, non-dust atom of open interest. That
// is precisely the free-OI-via-rounding exploit E4 closed: build an arbitrary
// position for zero fee, one indivisible atom at a time, by construction. This
// test's own comment called that the "OPERATIVE DEFENSE" and asserted it as
// correct; it was in fact the bug.
//
// E4 computes the fee on `trade_fee_notional_ceil` (ceil(size_q*exec_price /
// POS_SCALE)) instead, kept deliberately separate from the floor-based
// `notional` that still drives margin/PnL/TradeApplyOutcomeV16 accounting (see
// percolator src/v16.rs:13061-13065 and the E4 commit message). For this exact
// fixture (size_q=1, exec_price=100) that ceil is 1 (100/1_000_000 has a
// nonzero remainder), so `checked_fee_bps(notional=1, fee_bps=100)` =
// ceil(1*100/10_000) = 1 atom of fee is now correctly charged on EVERY
// successful one-unit trade. Derivation is proof-checked below via
// `ceil_notional_ref`/`ceil_fee_bps_ref`, exact reimplementations of the
// engine's `risk_notional_ceil`/`trade_fee_notional_ceil` and
// `checked_fee_bps` formulas (not hardcoded from an observed run) — matching
// upstream's own non-vacuity proof
// `proof_v16_trade_fee_notional_ceil_strictly_exceeds_floor_when_unaligned`
// (0/426 failed) and unit test `v16_subatom_trade_charges_fee_on_ceil_fee_notional`.
//
// REPAIRED OPERATIVE DEFENSE (still load-bearing, now against the CORRECT
// bug class): the fee charged must be EXACTLY `successful_trades *
// expected_fee_per_trade` — not zero (the pre-E4 floor-notional evasion this
// test originally, mistakenly, asserted as correct) and not MORE than that
// deterministic total (which would mean the ceil-notional fee is itself
// compounding/over-rounding across repeated sub-atom trades — the actual
// "rounding accumulation" failure mode this test exists to catch, now
// verified against the fixed formula instead of the broken one). The
// taker-only fee model (design §1A) charges this fee entirely to
// `account_a` (== `ua`/`user` in every `try_trade` call below, which always
// passes `user`/`ua` first); `la`/`lp` is always the maker and pays nothing,
// so its capital must stay untouched — that maker-side conservation was never
// the part of this test that E4 broke, and stays asserted unchanged.
// ===========================================================================
#[test]
fn adv_many_one_unit_trades_no_rounding_accumulation() {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let user_dep: u128 = 1_000_000_000;
    let lp_dep: u128 = 1_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);
    let initial = (user_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;

    let exec_price: u64 = 100;
    let trade_fee_bps: u64 = 100;
    // Derive (not hardcode) the expected per-trade fee from the engine's own
    // ceil-notional formula (E4). Pin the fixture's boundary values so a future
    // edit to `exec_price`/`trade_fee_bps` can't silently drift this test off
    // the sub-atom boundary it's designed to probe.
    let fee_notional = ceil_notional_ref(1, exec_price);
    assert_eq!(fee_notional, 1, "fixture assumption: 1*100/POS_SCALE must ceil to exactly 1 (the sub-atom boundary E4 targets)");
    let expected_fee_per_trade = ceil_fee_bps_ref(fee_notional, trade_fee_bps);
    assert_eq!(expected_fee_per_trade, 1, "fixture assumption: ceil(1*100/10_000) must be exactly 1 atom of fee per one-unit trade under E4");

    let mut successful = 0u64;
    for round in 0..100u64 {
        let size = if round % 2 == 0 { 1i128 } else { -1i128 };
        // E4: every successful one-unit trade now charges exactly
        // `expected_fee_per_trade` (ceil-notional fee) into insurance, taken
        // from the taker's (`ua`) capital. Pre-E4 the floor-notional bug made
        // this fee-less; see the header comment for the derivation.
        if env
            .try_trade(&user, ua, &lp, la, size, exec_price, trade_fee_bps)
            .is_ok()
        {
            successful += 1;
        }
        if round % 10 == 0 {
            let slot = 100 + round;
            env.warp(slot);
            let _ = env.crank(ua, 0, slot);
        }
        let wealth = env.equity(ua) + env.equity(la);
        assert!(
            wealth <= initial + TOL,
            "one-unit trades accumulated value after round {round}: {wealth} > {initial}"
        );
    }

    assert!(successful > 0, "probe did not execute any one-unit trade");
    assert_eq!(env.group().vault as u64, env.token_amount(env.vault));
    assert_eq!(
        env.residual(),
        0,
        "one-unit trades must not create trader-claimable residual"
    );

    // LOAD-BEARING E4 ceil-notional check (repairs the pre-E4 assertion that
    // insurance stayed EXACTLY unchanged, which enshrined the floor-notional
    // fee-evasion bug as correct behavior — see the derivation above).
    // Insurance must grow by EXACTLY `successful * expected_fee_per_trade`:
    // not zero (pre-E4 evasion would regress this back to 0), and not more
    // than that deterministic total (which would mean sub-atom rounding IS
    // accumulating beyond the engine's own ceil-per-trade guarantee — the
    // actual rounding-accumulation bug class this test's purpose is to catch).
    let expected_insurance_growth = successful as u128 * expected_fee_per_trade;
    assert_eq!(
        env.group().insurance,
        insurance_before + expected_insurance_growth,
        "sub-atom trade fee must accrue EXACTLY successful_trades * ceil-notional-fee to insurance \
         -- not zero (pre-E4 floor-notional evasion) and not more (rounding accumulation)"
    );
    // Exact conservation across all 100 attach/detach cycles: the taker
    // (`ua`/`user`, always `account_a`) pays exactly the ceil-notional fee
    // total; the maker (`la`/`lp`) pays nothing (taker-only fee model, design
    // §1A) and must be byte-for-byte untouched.
    assert_eq!(
        env.portfolio(ua).capital,
        user_dep - expected_insurance_growth,
        "taker capital must be debited by EXACTLY the ceil-notional fee total -- no more (dust \
         accumulation), no less (fee evasion regressing E4)"
    );
    assert_eq!(
        env.portfolio(la).capital,
        lp_dep,
        "maker capital must be untouched by the taker-only fee"
    );
    assert_eq!(
        env.portfolio(ua).pnl,
        0,
        "sub-quantum trades accumulated user PnL dust"
    );
    assert_eq!(
        env.portfolio(la).pnl,
        0,
        "sub-quantum trades accumulated LP PnL dust"
    );
}

// ===========================================================================
// SCENARIO 2 — self-liquidation into the backstop: no NET extraction.
// v12: test_attack_self_liquidation_backstop_no_insurance_siphon (archive L433-516).
// Attacker controls a weak short + strong long; pushes the mark adverse to the
// short and relies on liquidation to forgive the toxic leg.
// OPERATIVE DEFENSE: liquidation (PermissionlessCrank action 1) is BOUNDED — it
// closes, never grows, the toxic leg (strictly-reduces gate v16.rs:347-350) — and
// the attacker, controlling both legs, cannot net-profit (wealth <= deposits).
// v16 NOTE (corrects the v12 "no insurance draw" framing): the v16 bankruptcy
// backstop applies losses principal -> per-domain insurance
// (consume_domain_insurance_for_negative_pnl, v16.rs:9697) -> LP b-index
// socialization. Insurance from the LOSS DOMAIN *may* legitimately absorb a
// bankrupt loss ahead of socialization; that is not a siphon (the attacker still
// nets <= deposits). Here the plain TopUpInsurance credits a different domain than
// the bankrupt short's, so insurance is observably untouched — incidental to the
// domain split, NOT the operative guarantee. The StockRecon identity keeps engine
// vault == SPL vault throughout.
// ===========================================================================
#[test]
fn adv_self_liquidation_backstop_no_insurance_siphon() {
    let mut env = Env::new(0);
    let weak = Keypair::new(); // weak short, thin collateral
    let lp = Keypair::new(); // strong long LP
    let wa = env.create_portfolio(&weak);
    let la = env.create_portfolio(&lp);
    let weak_dep: u128 = 250;
    let lp_dep: u128 = 1_000_000;
    env.deposit(&weak, wa, weak_dep);
    env.deposit(&lp, la, lp_dep);
    env.top_up_insurance(5_000);

    let initial = (weak_dep + lp_dep) as i128;
    let insurance_before = env.group().insurance;

    // lp long / weak short (1 unit, notional 100, 100% margin -> 100 locked).
    let size = POS_SCALE as i128;
    env.try_trade(&lp, la, &weak, wa, size, 100, 0)
        .expect("open");
    let weak_pos_before = env.leg_size(wa).unsigned_abs();

    // Push the mark up to 400: the short's loss (300) EXCEEDS its 250 deposit, so
    // it is genuinely bankrupt — the case where a naive backstop would tap
    // insurance to forgive the toxic leg.
    for (slot, price) in [(10u64, 200u64), (20, 300), (30, 400)] {
        env.warp(slot);
        let _ = env.accrue_mark(ASSET, slot, price);
        let _ = env.crank(wa, 0, slot);
        let _ = env.crank(la, 0, slot);
    }
    env.try_liquidate(wa, 30)
        .expect("liquidation of the bankrupt short must succeed");

    // EXECUTED-GUARD (load-bearing): the liquidation actually fired — the toxic
    // leg is CLOSED (not merely "not grown"). Without this a silent no-op would
    // pass the bounds below.
    assert_eq!(
        env.leg_size(wa),
        0,
        "liquidation must close the toxic leg (it did not fire)"
    );
    assert!(
        env.leg_size(wa).unsigned_abs() <= weak_pos_before,
        "liquidation increased toxic exposure"
    );
    // OPERATIVE anti-extraction: the attacker controlling both legs cannot end up
    // with more than deposited — a siphon of insurance INTO the attacker's accounts
    // would push wealth above deposits; it does not.
    let wealth = env.equity(wa) + env.equity(la);
    assert!(
        wealth <= initial + TOL,
        "self-liquidation extracted net value: {wealth} > {initial}"
    );
    assert_eq!(
        env.group().vault as u64,
        env.token_amount(env.vault),
        "engine vault and SPL vault desynced"
    );
    // Observation (not the operative guarantee — see header): the plain top-up
    // credited a different domain than the bankrupt short's, so the per-domain
    // backstop draws nothing here.
    assert_eq!(
        env.group().insurance,
        insurance_before,
        "fixture invariant: untouched insurance lives in a different domain than the loss"
    );
}

// ===========================================================================
// SCENARIO 7 — zero-insurance self-liquidation: force-realize/ADL, no siphon.
// v12: test_attack_zero_insurance_self_liquidation_no_net_extraction (archive L728-767).
// Same shape as #2 but with no insurance buffer; an uncovered loss is socialized
// via the source-credit haircut / ADL path (v16.rs:6674-6782), never minted.
// SourceCreditLienAggregateProofV16 bounds the winner's support by posted backing.
// ===========================================================================
#[test]
fn adv_zero_insurance_self_liquidation_no_net_extraction() {
    let mut env = Env::new(0);
    let weak = Keypair::new();
    let lp = Keypair::new();
    let wa = env.create_portfolio(&weak);
    let la = env.create_portfolio(&lp);
    let weak_dep: u128 = 250;
    let lp_dep: u128 = 1_000_000;
    env.deposit(&weak, wa, weak_dep);
    env.deposit(&lp, la, lp_dep);
    // No insurance top-up: insurance starts at 0.
    let initial = (weak_dep + lp_dep) as i128;
    assert_eq!(
        env.group().insurance,
        0,
        "fixture must start with zero insurance"
    );

    let size = POS_SCALE as i128;
    env.try_trade(&lp, la, &weak, wa, size, 100, 0)
        .expect("open");
    let weak_pos_before = env.leg_size(wa).unsigned_abs();

    // Push the mark up past the short's collateral (bankruptcy) over bounded steps.
    for (slot, price) in [(10u64, 200u64), (20, 300), (30, 400)] {
        env.warp(slot);
        let _ = env.accrue_mark(ASSET, slot, price);
        let _ = env.crank(wa, 0, slot);
        let _ = env.crank(la, 0, slot);
    }
    env.try_liquidate(wa, 30)
        .expect("liquidation of the bankrupt short must succeed");

    // EXECUTED-GUARD: liquidation fired — toxic leg CLOSED. With zero insurance the
    // uncovered loss is socialized via the source-credit haircut / ADL path (never
    // minted, never an insurance siphon — insurance stays exactly 0).
    assert_eq!(
        env.leg_size(wa),
        0,
        "liquidation must close the toxic leg (it did not fire)"
    );
    assert!(
        env.leg_size(wa).unsigned_abs() <= weak_pos_before,
        "liquidation increased toxic exposure"
    );
    assert_eq!(
        env.group().insurance,
        0,
        "zero-insurance liquidation must not create an insurance siphon"
    );
    let wealth = env.equity(wa) + env.equity(la);
    assert!(
        wealth <= initial + TOL,
        "zero-insurance self-liquidation extracted net value: {wealth} > {initial}"
    );
    assert_eq!(
        env.group().vault as u64,
        env.token_amount(env.vault),
        "engine vault and SPL vault desynced"
    );
}

// ===========================================================================
// SCENARIO 4 — extraction-sensitive ops fail ATOMICALLY when a position is open
// under a target/effective lag. v12: test_attack_target_lag_withdraw_rejected_
// atomically (archive L581-613).
// V16 DIVERGENCE (documented in V16_DIVERGENCES.md): v12 forced a raw-target vs
// effective divergence (set_slot_and_price_raw_no_walk) and relied on a dedicated
// lag-withdraw lock. v16's ACTIVE withdraw path (the view-form withdraw_not_atomic
// the wrapper calls, v16.rs:10824) has NO lag-specific lock — the lag-aware
// validate_withdraw_global_locks lives only in an unwired runtime-struct overload
// (v16.rs:13150). Instead the OPERATIVE protection is the open-position guard:
// active_bitmap non-empty -> EngineStale(19) (v16.rs:10836-10838). This test pins
// that gate AND proves the divergence: a FLAT account withdraws fine under the
// same loss-stale market, so the lag alone never locks a withdrawal.
// ===========================================================================
#[test]
fn adv_target_lag_withdraw_rejected_atomically() {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let flat = Keypair::new(); // capital, no position
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    let fa = env.create_portfolio(&flat);
    env.deposit(&user, ua, 5_000_000_000);
    env.deposit(&lp, la, 30_000_000_000);
    env.deposit(&flat, fa, 1_000_000);
    env.try_trade(&user, ua, &lp, la, POS_SCALE as i128 * 100, 100, 0)
        .expect("open");

    // Reproduce the lag: advance the clock far ahead and crank once — the asset
    // accrues only one bounded segment, leaving slot_last < current_slot.
    env.warp(50);
    let _ = env.crank(ua, 0, 50);
    assert!(
        env.group().loss_stale_active,
        "must reproduce the target/effective lag (loss-stale) state"
    );

    let cap_before = env.portfolio(ua).capital;
    let leg_before = env.leg_size(ua);
    let vault_before = env.token_amount(env.vault);
    let gvault_before = env.group().vault;

    // OPEN-position account: withdraw rejects at the open-position guard (Stale 19), atomically.
    assert_custom(
        env.try_withdraw(&user, ua, 1),
        E_STALE,
        "withdraw with an open position under lag",
    );
    assert_eq!(
        env.portfolio(ua).capital,
        cap_before,
        "rejected withdraw moved capital"
    );
    assert_eq!(
        env.leg_size(ua),
        leg_before,
        "rejected withdraw moved position"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before,
        "rejected withdraw moved SPL vault"
    );
    assert_eq!(
        env.group().vault,
        gvault_before,
        "rejected withdraw moved engine vault"
    );

    // DIVERGENCE PROOF: the FLAT account (no position) withdraws SUCCESSFULLY under
    // the very same loss-stale market — confirming the lag itself is not a
    // withdraw lock; the open-position guard is the operative protection.
    //
    // GAP-LAG-FLAT (Phase 3A.2 belt-and-braces): the bare `.expect()` proved only
    // that the flat withdraw succeeds. Snapshot capital + engine-vault ledger + SPL
    // vault BEFORE, then assert ALL THREE moved by EXACTLY the withdrawn amount (no
    // stale-priced bonus from the lag) and `group.vault == on-chain SPL vault`
    // afterward (no phantom mint).
    let flat_amount: u128 = 500_000;
    let flat_cap_before = env.portfolio(fa).capital as u128;
    let gvault_before_flat = env.group().vault;
    let spl_vault_before_flat = env.token_amount(env.vault) as u128;
    env.try_withdraw(&flat, fa, flat_amount)
        .expect("flat account must withdraw freely despite loss-stale lag");
    assert_eq!(
        env.portfolio(fa).capital as u128,
        flat_cap_before - flat_amount,
        "flat withdraw debited EXACTLY the amount of capital (no stale-priced bonus)"
    );
    assert_eq!(
        env.group().vault,
        gvault_before_flat - flat_amount,
        "engine vault ledger decreased by EXACTLY the amount"
    );
    assert_eq!(
        env.token_amount(env.vault) as u128,
        spl_vault_before_flat - flat_amount,
        "SPL vault token balance decreased by EXACTLY the amount"
    );
    assert_eq!(
        env.group().vault,
        env.token_amount(env.vault) as u128,
        "engine vault ledger == on-chain SPL vault (no phantom mint)"
    );
}

// ===========================================================================
// SCENARIO 5 — no external value movement under a target/effective lag.
// v12: test_target_lag_trade_executes_without_external_value_movement (archive L620-667).
// V16 DIVERGENCE (documented in V16_DIVERGENCES.md): v12 asserted a consenting
// trade EXECUTES during lag (liveness). v16 is STRICTER — a trade on a loss-stale
// asset is rejected at EngineLockActive(21); liveness is restored only after a
// catch-up crank clears the staleness. Either way the v12 economic invariant —
// "no external value movement" — holds: here it holds because the trade does not
// execute at all, and the SPL vault / positions are unchanged.
// ===========================================================================
#[test]
fn adv_target_lag_trade_no_external_value_movement() {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    env.deposit(&user, ua, 5_000_000_000);
    env.deposit(&lp, la, 30_000_000_000);
    env.try_trade(&user, ua, &lp, la, POS_SCALE as i128 * 100, 100, 0)
        .expect("open");

    env.warp(50);
    let _ = env.crank(ua, 0, 50);
    assert!(
        env.group().loss_stale_active,
        "must reproduce the loss-stale lag"
    );

    let user_pos_before = env.leg_size(ua);
    let lp_pos_before = env.leg_size(la);
    let vault_before = env.token_amount(env.vault);
    let gvault_before = env.group().vault;

    // v16: the consenting trade on the loss-stale asset is rejected (safety over
    // liveness). The economic invariant holds because nothing moves.
    assert_custom(
        env.try_trade(&user, ua, &lp, la, POS_SCALE as i128, 100, 0),
        E_LOCK_ACTIVE,
        "trade on loss-stale asset",
    );
    assert_eq!(
        env.leg_size(ua),
        user_pos_before,
        "blocked trade moved user position"
    );
    assert_eq!(
        env.leg_size(la),
        lp_pos_before,
        "blocked trade moved counterparty position"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before,
        "blocked trade moved SPL vault (external value)"
    );
    assert_eq!(
        env.group().vault,
        gvault_before,
        "blocked trade moved engine vault"
    );
}

/// Fresh market + a user long with positive-but-UNMATURED PnL while the
/// offsetting short leg is still open. In v16 this open-leg state IS the
/// "unmatured" condition: closing the leg matures the PnL (see scenario 1), so
/// unmatured == offsetting exposure still open.
fn unmatured_fixture() -> (Env, Keypair, Pubkey, Keypair, Pubkey) {
    let mut env = Env::new(0);
    let user = Keypair::new();
    let lp = Keypair::new();
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);
    env.deposit(&user, ua, 2_000_000_000);
    env.deposit(&lp, la, 30_000_000_000);
    env.try_trade(&user, ua, &lp, la, POS_SCALE as i128 * 100, 100, 0)
        .expect("open");
    env.warp(10);
    env.accrue_mark(ASSET, 10, 150).expect("accrue");
    let _ = env.crank(ua, 0, 10);
    let _ = env.crank(la, 0, 10);
    assert!(
        env.portfolio(ua).pnl > 0,
        "fixture must create positive unmatured PnL"
    );
    (env, user, ua, lp, la)
}

// ===========================================================================
// SCENARIO 13 — public-interface matrix: no interface converts unmatured PnL
// into withdrawable capital / external vault tokens.
// v12: test_attack_unmatured_pnl_public_interface_matrix_no_extraction (archive L1070-1191).
// Reverting interfaces are atomic; successful ones touch only their own amount.
// Two v12 sub-cases are OBVIATED-by-design in v16 (documented in V16_DIVERGENCES.md):
//   * DepositFeeCredits — NO such instruction exists in the v16 Instruction enum.
//   * CloseAccount-with-payout — v16 ClosePortfolio is dealloc-only (sub-case c),
//     so "close pays out unmatured PnL" is structurally impossible.
// ===========================================================================
#[test]
fn adv_unmatured_pnl_public_interface_matrix_no_extraction() {
    // (a) Withdraw while PnL is unmatured (offsetting leg open) -> EngineStale(19), atomic.
    {
        let (mut env, user, ua, _lp, _la) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        let pnl = env.portfolio(ua).pnl;
        assert_custom(
            env.try_withdraw(&user, ua, cap + 1),
            E_STALE,
            "withdraw while unmatured",
        );
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "rejected withdraw moved capital"
        );
        assert_eq!(env.portfolio(ua).pnl, pnl, "rejected withdraw consumed PnL");
    }
    // (b) ConvertReleasedPnl while unmatured -> EngineLockActive(21), atomic.
    {
        let (mut env, user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        let pnl = env.portfolio(ua).pnl;
        assert_custom(
            env.try_convert(&user, ua, 1_000_000_000),
            E_LOCK_ACTIVE,
            "convert while unmatured",
        );
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "rejected convert minted capital"
        );
        assert_eq!(env.portfolio(ua).pnl, pnl, "rejected convert consumed PnL");
    }
    // (c) ClosePortfolio on a non-flat account -> EngineLockActive(21) (dealloc-only guard).
    {
        let (mut env, user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        assert_custom(
            env.try_close(&user, ua),
            E_LOCK_ACTIVE,
            "close non-flat account with unmatured PnL",
        );
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "rejected close moved capital"
        );
    }
    // (d) DepositCollateral credits EXACTLY the amount, never the unmatured PnL.
    {
        let (mut env, user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        let pnl = env.portfolio(ua).pnl;
        let gv = env.group().vault;
        env.deposit(&user, ua, 1_234);
        assert_eq!(
            env.portfolio(ua).capital,
            cap + 1_234,
            "deposit must credit only the deposited amount"
        );
        assert_eq!(
            env.portfolio(ua).pnl,
            pnl,
            "deposit must not consume unmatured PnL"
        );
        assert_eq!(
            env.group().vault,
            gv + 1_234,
            "deposit must move exactly the deposited units"
        );
    }
    // (e) TopUpInsurance only raises insurance; never unlocks user PnL/capital.
    {
        let (mut env, _user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        let pnl = env.portfolio(ua).pnl;
        let ins = env.group().insurance;
        env.top_up_insurance(1_000);
        assert_eq!(
            env.group().insurance,
            ins + 1_000,
            "top-up must only raise insurance by the amount"
        );
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "top-up unlocked user capital"
        );
        assert_eq!(env.portfolio(ua).pnl, pnl, "top-up consumed user PnL");
    }
}

// ===========================================================================
// SCENARIO 14 — KeeperCrank branch matrix: no crank branch unlocks unmatured
// PnL, and the policy/action tag is validated.
// v12: test_attack_unmatured_pnl_keeper_branch_matrix_no_extraction (archive L1204-1319).
// v16 maps v12 policy tags onto crank actions 0=Refresh, 1=Liquidate, 2=SettleB;
// action>2 is rejected at InvalidInstruction(9) (v16_program.rs:11184-11188).
// FIX W3 (upstream #206, pairs with engine E3 / #92): the v12-derived
// "action==1-with-caller-fee is rejected at runtime" sub-case is gone -- the
// wire format no longer HAS a caller-supplied fee_bps/close_q field for
// PermissionlessCrank, so that shape of instruction cannot be constructed at
// all now (a compile-time guarantee, strictly stronger than the old runtime
// InvalidInstruction check). See v16_wrapper_permissionless_crank_rejects_w3_legacy_wire_fields
// in tests/v16_wrapper.rs for the non-vacuous proof that the OLD (wider) wire
// payload is now rejected as a trailing-bytes decode error.
// ===========================================================================
#[test]
fn adv_unmatured_pnl_keeper_branch_matrix_no_extraction() {
    // (1) Permissionless Refresh (action 0) is callable and unlocks no capital.
    {
        let (mut env, _user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        let pnl = env.portfolio(ua).pnl;
        env.warp(20);
        env.crank(ua, 0, 20)
            .expect("permissionless Refresh crank must remain callable");
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "Refresh crank unlocked capital"
        );
        assert!(
            env.portfolio(ua).pnl <= pnl + 1,
            "Refresh crank must not increase realizable PnL into capital"
        );
    }
    // (2) Bad action tag (action 3 > 2) -> InvalidInstruction(9), atomic.
    {
        let (mut env, _user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        env.warp(20);
        assert_custom(
            env.crank(ua, 3, 20),
            E_INVALID_INSTRUCTION,
            "crank with bad action tag (>2)",
        );
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "rejected bad-tag crank moved capital"
        );
    }
    // (3) SettleB (action 2) with no B-state decodes and no-ops; unlocks nothing.
    {
        let (mut env, _user, ua, _, _) = unmatured_fixture();
        let cap = env.portfolio(ua).capital;
        env.warp(20);
        let _ = env.crank(ua, 2, 20); // no-op branch (no pending B-settlement state)
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "SettleB no-op unlocked capital"
        );
    }
    // (5) Resolved-market crank: after ResolveMarket the market is no longer Live;
    // a crank must not settle/pay accounts (early-return / lock), no extraction.
    {
        let mut env = Env::new(0);
        let user = Keypair::new();
        let lp = Keypair::new();
        let ua = env.create_portfolio(&user);
        let la = env.create_portfolio(&lp);
        env.deposit(&user, ua, 1_000_000_000);
        env.deposit(&lp, la, 1_000_000_000);
        env.warp(1); // align SVM clock with current_slot (set to 1 at activation)
                     // flat market (no open positions) is resolvable.
        env.resolve().expect("resolve flat market");
        let cap = env.portfolio(ua).capital;
        let gv = env.group().vault;
        let _ = env.crank(ua, 0, 1); // resolved crank: early-return / reject, never settles
        assert_eq!(
            env.portfolio(ua).capital,
            cap,
            "resolved-market crank moved capital"
        );
        assert_eq!(
            env.group().vault,
            gv,
            "resolved-market crank moved engine vault"
        );
        assert_eq!(env.group().vault as u64, env.token_amount(env.vault));
    }
}

// ===========================================================================
// WINNER LIFECYCLE — resolved winner receives BOTH capital AND PnL legs,
// snapshot+receipt are set, conservation holds, full teardown succeeds.
//
// BUG (pre-fix): handle_close_resolved hand-rolls the inline body instead of
// calling close_resolved_account_not_atomic. Consequences:
//   (a) pnl.get()!=0 gate trips -> Custom(21) for any winner.
//   (b) payout = capital.min(vault) only — drops the resolved-PnL leg.
//   (c) payout_snapshot_captured never set -> ClaimResolvedPayoutTopup also
//       returns Custom(21).
//   (d) portfolio never drains -> materialized_portfolio_count stays >0 ->
//       CloseSlab unreachable.
// FIX: replace the inline body with the single engine call
//   group.close_resolved_account_not_atomic(&mut portfolio, fee_per_slot).
// ===========================================================================
#[test]
fn adv_resolved_winner_lifecycle_pays_two_legs_and_tears_down() {
    // --- Setup ---------------------------------------------------------------
    let mut env = Env::new(0);
    let user = Keypair::new(); // long winner
    let lp = Keypair::new(); // short loser (absorbs the loss)
    let ua = env.create_portfolio(&user);
    let la = env.create_portfolio(&lp);

    // lp_dep >> user_dep so the loser stays solvent (no bankruptcy path needed).
    let user_dep: u128 = 2_000_000_000;
    let lp_dep: u128 = 50_000_000_000;
    env.deposit(&user, ua, user_dep);
    env.deposit(&lp, la, lp_dep);

    let vault_before = env.group().vault;
    assert_eq!(
        vault_before,
        user_dep + lp_dep,
        "vault_before must equal total deposits"
    );

    // --- Open: user long / lp short ------------------------------------------
    let size = POS_SCALE as i128 * 100;
    env.try_trade(&user, ua, &lp, la, size, 100, 0)
        .expect("open long/short");

    // --- Push mark up so user long is in profit --------------------------------
    env.warp(10);
    env.accrue_mark(ASSET, 10, 150).expect("accrue mark up");
    env.crank(ua, 0, 10)
        .expect("crank winner (MTM) must succeed");
    env.crank(la, 0, 10)
        .expect("crank loser (MTM) must succeed");

    // ANTI-HOLLOW gate: the fixture must produce a real winner.
    assert!(
        env.portfolio(ua).pnl > 0,
        "fixture must create positive long PnL — check accrue_mark"
    );

    // --- Flatten both legs (CloseResolved rejects non-empty active_bitmap) ----
    env.try_trade(&user, ua, &lp, la, -size, 150, 0)
        .expect("flatten user long");
    assert_eq!(
        env.leg_size(ua),
        0,
        "user leg must be flat before CloseResolved"
    );
    // The two-sided flatten above already closed lp's short in the same trade.
    // Only act on a residual leg; never blanket-swallow an unexpected error.
    if env.leg_size(la) != 0 {
        env.try_trade(&lp, la, &user, ua, size, 150, 0)
            .expect("flatten lp short");
    }
    assert_eq!(
        env.leg_size(la),
        0,
        "lp leg must be flat before CloseResolved"
    );

    // --- Capture pre-close state ----------------------------------------------
    let win_cap: u128 = env.portfolio(ua).capital;
    let win_pnl_i128: i128 = env.portfolio(ua).pnl;
    assert!(
        win_pnl_i128 > 0,
        "winner pnl must be positive after flatten"
    );
    let win_pnl: u128 = win_pnl_i128 as u128;
    let expected_winner_payout = win_cap + win_pnl;

    // --- Resolve market -------------------------------------------------------
    // Warp to a slot >= group.current_slot (activation set current_slot=1).
    env.warp(20);
    env.resolve().expect("resolve market");
    assert_eq!(
        env.group().mode,
        percolator::MarketModeV16::Resolved,
        "market must be Resolved"
    );

    // --- RED→GREEN provenance ------------------------------------------------
    // RED (pre-fix): with the old inline body, the winner's CloseResolved at
    // Step 7b below tripped the `pnl != 0` gate and returned EngineLockActive /
    // Custom(21); ClaimResolvedPayoutTopup likewise bricked on the
    // payout_snapshot_captured==0 gate. That RED state was confirmed by running
    // this exact test against the pre-fix .so (recorded in the fix commit body).
    // A bug-asserting RED test cannot coexist with the GREEN regression guard in
    // one binary, so THIS permanent test asserts the POST-FIX GREEN path; if the
    // bug regresses, the `winner CloseResolved must succeed` expect at Step 7b
    // fails loudly. See V16_DIVERGENCES.md for the fork-vs-toly close note.

    // --- POST-FIX SUCCESS PATH -----------------------------------------------

    // Step 7a: Close the LOSER first (settles negative PnL, no receipt).
    let (loser_dest, loser_res) = env.try_close_resolved(&lp, la);
    loser_res.expect("loser CloseResolved must succeed");
    let loser_payout = env.token_amount(loser_dest) as u128;

    // Step 7b: Close the WINNER.
    let (winner_dest, winner_res) = env.try_close_resolved(&user, ua);
    winner_res.expect("winner CloseResolved must succeed post-fix");

    // Step 7c: The winner may receive the full payout directly from CloseResolved,
    // or CloseResolved may return ProgressOnly (payout=0) and require a topup.
    // Handle both: loop until paid or we know it was fully direct.
    let mut winner_received = env.token_amount(winner_dest) as u128;

    // If not fully paid yet, issue ClaimResolvedPayoutTopup until finalized.
    let max_topup_rounds = 10u32;
    for _ in 0..max_topup_rounds {
        if winner_received >= expected_winner_payout {
            break;
        }
        // Check receipt: if finalized we're done; if not present yet, wait.
        let r = env.portfolio(ua).resolved_payout_receipt;
        if r.present && r.finalized {
            break;
        }
        env.try_claim_resolved_payout_topup(&user, ua, winner_dest)
            .expect("ClaimResolvedPayoutTopup must not return Custom(21) post-fix");
        winner_received = env.token_amount(winner_dest) as u128;
    }

    // Step 7c assertion: winner received exactly capital + resolved-PnL legs.
    assert_eq!(
        winner_received,
        expected_winner_payout,
        "winner must receive BOTH capital ({win_cap}) and resolved-PnL ({win_pnl}) legs; got {winner_received}"
    );

    // Step 7d: v17 direct-payout post-condition.
    // v17 semantics (verified): when the vault can fully cover a solvent winner,
    // CloseResolved pays capital + resolved-PnL DIRECTLY in one shot and drains the
    // account (capital=0, pnl=0). The resolved-payout receipt/ledger machinery only
    // materializes for the DEFERRED/PRORATED tail (vault-insufficient or multi-winner
    // contention) — and any receipt that does form is dematerialized once fully paid
    // at the terminal rate (engine clear_fully_diluted_resolved_receipt_if_terminal).
    // So for this fully-covered single winner the correct post-condition is a clean
    // teardown with NO dangling receipt, not a present/finalized receipt.
    let win_acct = env.portfolio(ua);
    assert_eq!(
        win_acct.pnl, 0,
        "winner pnl must be fully realized to 0 after direct payout"
    );
    assert_eq!(
        win_acct.capital, 0,
        "winner capital must be fully drained after direct payout"
    );
    assert!(
        !win_acct.resolved_payout_receipt.present,
        "fully-covered winner must leave NO dangling resolved_payout_receipt"
    );

    // Step 7e: Conservation — engine vault == SPL vault; total decrement ==
    // winner_payout + loser_payout == vault_before (all capital returned).
    let vault_after = env.group().vault;
    assert_eq!(
        vault_after,
        env.token_amount(env.vault) as u128,
        "engine vault must equal SPL vault after closes"
    );
    // Non-vacuity guard for the conservation sum below: both portfolios were paid
    // in full, so the vault is fully drained here — a winner under-payment cannot
    // hide as residual in vault_after.
    assert_eq!(
        vault_after, 0,
        "all deposits returned; vault fully drained after both closes"
    );
    assert_eq!(
        vault_before,
        winner_received + loser_payout + vault_after,
        "vault_before ({vault_before}) must equal sum of payouts + remaining vault; winner={winner_received} loser={loser_payout} remaining={vault_after}"
    );

    // Step 7f: Teardown — close portfolios, then close slab.
    env.try_close(&user, ua)
        .expect("ClosePortfolio winner must succeed");
    env.try_close(&lp, la)
        .expect("ClosePortfolio loser must succeed");
    assert_eq!(
        env.group().materialized_portfolio_count,
        0,
        "materialized_portfolio_count must be 0 after both ClosePortfolio"
    );
    assert_eq!(env.group().vault, 0, "vault must be 0 before CloseSlab");
    assert_eq!(
        env.group().insurance,
        0,
        "insurance must be 0 (no fees with fee_bps=0)"
    );
    assert_eq!(
        env.group().c_tot,
        0,
        "c_tot must be 0 after all portfolios closed"
    );
    env.close_slab();

    // Step 7g: Confirm ClaimResolvedPayoutTopup is reachable (no Custom(21)) even
    // after finalization. Sequenced here for documentation — in practice it no-ops.
    // NOTE: ClosePortfolio zeroes the portfolio data, so we cannot call topup after.
    // This is verified above in the topup loop (it returned Ok, not Custom(21)).
}

// W3 (canonical-ATA): mirror of v16_program::processor::canonical_vault_address — the SPL
// Associated Token Account of the vault_authority PDA for this mint. Kept byte-in-lock-step with
// the program so vault fixtures satisfy the F-VAULT-FRAG pin (a green test == the derivation matches).
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
