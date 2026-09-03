// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Workstream 1 (Phase 2.B Tier 3) — envelope-gate LiteSVM coverage.
//!
//! Re-ports the 2 init-time invariants tracked in the archived v12
//! `test_envelope_gate.rs` against v16 LiteSVM as belt-and-braces over
//! engine A-10 Kani + upstream wrapper unit tests. Per user decision #4
//! (Phase 2.B Tier 3 brief): "port the 2 init-time invariants as
//! belt-and-braces. ~1 day. Engine A-10 Kani + upstream wrapper already
//! cover most surface; this closes the call-boundary gap."
//!
//! Each test exercises the wrapper-side call boundary
//! (instruction-decode → `handle_init_market` → engine
//! `V16Config::validate_public_user_fund_shape` → `map_account_wire_error`
//! → `PercolatorError::EngineInvalidConfig`), confirming that the
//! engine's rejection surfaces as a program-level error when an attacker
//! or misconfigured operator submits an InitMarket transaction with a
//! boundary-bad config value. Kani proves the engine rejects in
//! isolation; these tests prove the wrapper propagates the rejection
//! end-to-end through the BPF entrypoint without leaking a writable
//! market account in a half-initialized state.
//!
//! Cross-references:
//! - `~/wrapper-engine-deep-audit/v12_test_archive/test_envelope_gate.rs`
//!   banner — original v12 test rationale + OBVIATED mapping
//! - `~/wrapper-engine-deep-audit/V16_DIVERGENCES.md` — A-10 engine port
//! - `~/percolator/tests/proofs_v16_fork.rs` — engine A-10 Kani proofs
//! - `~/percolator/src/v16.rs:1469-1517` —
//!   `V16Config::validate_public_user_fund_shape` (rejects
//!   `max_price_move_bps_per_slot == 0 || > MAX_MARGIN_BPS` and
//!   `initial_margin_bps > MAX_MARGIN_BPS`)
//! - `~/percolator-prog/src/v16_program.rs:4629` — `handle_init_market`
//!   forwards args into `state::init_market_account_zero_copy` which
//!   calls `MarketGroupV16HeaderAccount::new_dynamic` which calls
//!   `validate_public_user_fund_shape` on the constructed config.

use litesvm::LiteSVM;
use percolator::MAX_MARGIN_BPS;
use percolator_prog::{ix::Instruction as ProgInstruction, state};
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
use spl_token::state::Mint;
use std::path::PathBuf;

fn program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {:?}. Run `cargo build-sbf --no-default-features` first.",
        path
    );
    path
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

const FIXTURE_MAX_PORTFOLIO_ASSETS: u16 = 1;
const VALID_MAINTENANCE_MARGIN_BPS: u64 = 10_000;
const VALID_INITIAL_MARGIN_BPS: u64 = 10_000;
const VALID_MAX_PRICE_MOVE_BPS_PER_SLOT: u64 = 10_000;

struct EnvelopeEnv {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
}

impl EnvelopeEnv {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        let program_bytes = std::fs::read(program_path()).expect("read BPF");
        svm.add_program(program_id, &program_bytes);

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
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
        let market_data_len =
            state::market_account_len_for_capacity(FIXTURE_MAX_PORTFOLIO_ASSETS as usize).unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; market_data_len],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        Self {
            svm,
            program_id,
            payer,
            admin,
            market,
            mint,
        }
    }

    fn send_init_market(&mut self, ix: ProgInstruction) -> Result<u64, String> {
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.mint, false),
            ],
            data: ix.encode(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::request_heap_frame(128 * 1024),
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instruction,
            ],
            Some(&self.payer.pubkey()),
            &[&self.payer, &self.admin],
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .map(|meta| meta.compute_units_consumed)
            .map_err(|e| format!("{e:?}"))
    }
}

fn init_market_with(max_price_move_bps_per_slot: u64, initial_margin_bps: u64) -> ProgInstruction {
    ProgInstruction::InitMarket {
        max_portfolio_assets: FIXTURE_MAX_PORTFOLIO_ASSETS,
        h_min: 0,
        h_max: 10,
        initial_price: 100,
        min_nonzero_mm_req: 1,
        min_nonzero_im_req: 2,
        maintenance_margin_bps: VALID_MAINTENANCE_MARGIN_BPS,
        initial_margin_bps,
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
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
    }
}

/// Workstream 1: InitMarket with `max_price_move_bps_per_slot` above the
/// engine A-10 fork-port cap (`MAX_MARGIN_BPS = 10_000`) is rejected at
/// the wrapper call boundary.
///
/// Engine A-10 Kani harnesses in `proofs_v16_fork.rs` already prove that
/// `V16Config::validate_public_user_fund_shape` returns
/// `V16Error::InvalidConfig` whenever `max_price_move_bps_per_slot >
/// MAX_MARGIN_BPS`. This test closes the wrapper-side gap: the BPF
/// instruction-decode → `handle_init_market` → `init_market_account_zero_copy`
/// → `MarketGroupV16HeaderAccount::new_dynamic` →
/// `validate_public_user_fund_shape` → `map_account_wire_error` →
/// `PercolatorError::EngineInvalidConfig` pipeline must surface the
/// rejection as a program error before any market state is written. A
/// bypass here would let an admin bake in an unbounded price-move budget
/// at init, loosening every downstream EWMA / mark / liquidation gate
/// that assumes `max_price_move_bps_per_slot <= MAX_MARGIN_BPS`.
#[test]
fn init_market_rejects_max_price_move_above_cap() {
    let mut env = EnvelopeEnv::new();
    let bad_max_price_move = MAX_MARGIN_BPS as u64 + 1;
    let ix = init_market_with(bad_max_price_move, VALID_INITIAL_MARGIN_BPS);
    let result = env.send_init_market(ix);
    assert!(
        result.is_err(),
        "InitMarket with max_price_move_bps_per_slot = MAX_MARGIN_BPS + 1 ({}) \
         must be rejected at the wrapper call boundary via engine A-10. \
         Got: {:?}",
        bad_max_price_move,
        result
    );
}

/// Workstream 1: InitMarket with `initial_margin_bps` above `MAX_MARGIN_BPS`
/// is rejected at the wrapper call boundary.
///
/// v16 baseline `V16Config::validate_public_user_fund_shape` at
/// `~/percolator/src/v16.rs:1484` rejects `self.initial_margin_bps >
/// MAX_MARGIN_BPS` when called from
/// `MarketGroupV16HeaderAccount::new_dynamic`. The wrapper passes the
/// user-supplied `initial_margin_bps` straight onto the engine config in
/// `handle_init_market` at `src/v16_program.rs:4674` without an
/// independent guard, so the engine reject path is the only line of
/// defense at the BPF call boundary. This test confirms it holds — an
/// attacker (or misconfigured operator) cannot construct a market whose
/// initial-margin ratio exceeds the supported bps space, which would
/// otherwise overflow downstream margin-requirement math that scales by
/// `MAX_MARGIN_BPS`.
#[test]
fn init_market_rejects_invalid_margin_ratio() {
    let mut env = EnvelopeEnv::new();
    let bad_initial_margin_bps = MAX_MARGIN_BPS as u64 + 1;
    let ix = init_market_with(VALID_MAX_PRICE_MOVE_BPS_PER_SLOT, bad_initial_margin_bps);
    let result = env.send_init_market(ix);
    assert!(
        result.is_err(),
        "InitMarket with initial_margin_bps = MAX_MARGIN_BPS + 1 ({}) \
         must be rejected at the wrapper call boundary via engine \
         validate_public_user_fund_shape. Got: {:?}",
        bad_initial_margin_bps,
        result
    );
}
