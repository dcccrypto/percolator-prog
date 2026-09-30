// Skip this integration-test binary when Kani builds the test suite.
#![allow(dead_code, unused_imports, unused_variables, clippy::all)]
//! Independent-suite harness (2026-09-30). Plumbing lifted from tests/v16_cu.rs
//! (V16CuEnv) at 6377376a so instruction encoding matches the deployed ABI;
//! every ASSERTION in the indep_* suites is written from spec/design docs.
//! Wrapper/matcher .so can be swapped with INDEP_WRAPPER_SO / INDEP_MATCHER_SO.
use litesvm::LiteSVM;
use percolator::{
    AssetLifecycleV16, BackingBucketStatusV16, CloseProgressLedgerV16, MarketModeV16,
    PermissionlessRecoveryReasonV16, ResolvedPayoutLedgerV16, ResolvedPayoutReceiptV16,
    SideModeV16, SideV16, TradeRequestV16, ADL_ONE, BOUND_SCALE, POS_SCALE,
};
use percolator_prog::{
    constants::{
        CLOSED_MARKET_TOMBSTONE_RENT_LAMPORTS, HEADER_LEN, KIND_CLOSED_MARKET, MAGIC,
        MATCHER_ABI_VERSION, ORACLE_LEG_FLAG_DIVIDE_LEG2, ORACLE_LEG_FLAG_DIVIDE_LEG3, VERSION,
    },
    error::PercolatorError,
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    oracle_v16, processor, state,
    state::{MarketGroupV16, PortfolioAccountV16},
};
// v17 convergence: MarketGroupV16 / PortfolioAccountV16 moved from percolator:: (runtime-vec-api)
// into the wrapper's state:: module. Import corrected per v17 auth overhaul migration.
use solana_sdk::{
    account::Account,
    clock::Clock,
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

// sync/w2-tb3 (ADOPT upstream 20f0b9b1, intent_id slice only): test-only
// monotonic nonce generator. Every call returns a value strictly greater
// than the last, guaranteeing intent_id uniqueness across every top-up in
// this test binary regardless of loops, shared helper functions, or how
// many tests run -- so no existing test's outcome changes by acquiring a
// fresh nonce (only a genuine same-value REPLAY is ever rejected).
pub fn next_intent_id() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub const CRANK_CU_LIMIT: u64 = 325_000;
pub const CUSTODY_CU_LIMIT: u64 = 300_000;
pub const TRADE_CU_LIMIT: u64 = 345_000;
pub const MULTI_ASSET_OPEN_TRADE_CU_LIMIT: u64 = 750_000;
pub const MATCHER_CONTEXT_LEN: usize = 320;

/// GH#496: an UNSIGNED terminal payout (`CloseResolved` tag 45,
/// `ClaimResolvedPayoutTopup` tag 46) must present this market group's canonical
/// `NftRegistry` PDA as proof that the portfolio is not NFT-escrowed — otherwise an
/// escrowed position's whole payout could be routed into the escrow PDA's own token
/// account, which nothing can ever spend from. These fixtures never register an NFT
/// program, so the account does not exist and the (System-owned, empty) PDA is
/// itself the proof.
pub fn nft_registry_pda(market: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"nft_registry", market.as_ref()], &harness_program_id()).0
}

/// Sync unit W2-S1b (ADOPT upstream `d57411f8`, "prevent whole-market address
/// reuse"): asserts a just-closed market account carries the permanent
/// `KIND_CLOSED_MARKET` tombstone -- shrunk to `HEADER_LEN`, non-zero header,
/// retaining exactly `CLOSED_MARKET_TOMBSTONE_RENT_LAMPORTS` -- rather than
/// the pre-fix "zeroed and drained to 0 lamports" shape. LiteSVM constructs
/// accounts with the real runtime's serialized layout, so `handle_close_slab`'s
/// `AccountInfo::realloc` call is safe and exercised for real here (unlike
/// the plain-`Vec<u8>` `TestAccount` harness in `tests/v16_wrapper.rs`, where
/// `realloc` is unsound per `AccountInfo::realloc`'s own safety doc and that
/// harness's close-slab tests assert on data/lamports without calling it
/// through to a full close+reinit cycle for that reason).
pub fn assert_market_is_closed_market_tombstone(data: &[u8]) {
    assert_eq!(
        data.len(),
        HEADER_LEN,
        "closed market account should be shrunk to the tombstone header size"
    );
    assert_eq!(&data[0..8], &MAGIC.to_le_bytes());
    assert_eq!(&data[8..10], &VERSION.to_le_bytes());
    assert_eq!(
        data[10], KIND_CLOSED_MARKET,
        "closed market account must be stamped KIND_CLOSED_MARKET, not zeroed"
    );
}

pub fn active_bitmap_with(indices: &[usize]) -> percolator::V16ActiveBitmap {
    let mut bitmap = percolator::active_bitmap_empty();
    for &idx in indices {
        percolator::kani_active_bitmap_set(&mut bitmap, idx).unwrap();
    }
    bitmap
}

pub fn active_leg_for_asset(
    account: &PortfolioAccountV16,
    asset_index: usize,
) -> percolator::PortfolioLegV16 {
    account
        .legs
        .iter()
        .copied()
        .find(|leg| leg.active && leg.asset_index as usize == asset_index)
        .unwrap()
}

pub fn has_active_leg_for_asset(account: &PortfolioAccountV16, asset_index: usize) -> bool {
    account
        .legs
        .iter()
        .any(|leg| leg.active && leg.asset_index as usize == asset_index)
}

/// Wrapper mount id. INDEP_MAINNET_ID=1 mounts at the mainnet id (ESa89R5…), which the
/// stake program's Bind/InitPool allowlist (plain build) requires.
pub fn harness_program_id() -> Pubkey {
    // INDEP_PROGRAM_ID=<base58>: mount the wrapper at an arbitrary id (e.g. the fresh devnet id
    // ETDLAdi… that a --features devnet stake build allowlists).
    if let Ok(k) = std::env::var("INDEP_PROGRAM_ID") {
        return k.parse().expect("INDEP_PROGRAM_ID base58");
    }
    if std::env::var("INDEP_MAINNET_ID").map_or(false, |v| v == "1") {
        "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv".parse().unwrap()
    } else {
        percolator_prog::id()
    }
}

pub fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("INDEP_WRAPPER_SO") {
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

pub fn matcher_program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("INDEP_MATCHER_SO") {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("percolator-match/target/deploy/percolator_match.so");
    assert!(
        path.exists(),
        "matcher BPF not found at {:?}. Run `cd ../percolator-match && cargo build-sbf` first",
        path
    );
    path
}

pub fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            home.push(".cargo");
            home
        });
    let registry_src = cargo_home.join("registry/src");
    for registry in std::fs::read_dir(&registry_src).expect("registry/src") {
        let registry = registry.expect("registry entry").path();
        let candidate = registry.join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("could not find LiteSVM SPL Token BPF under {registry_src:?}");
}

// v17 convergence matrix row: v17-tradecpi-delegate-seed
// derive_matcher_delegate (v16_program.rs:13486) uses seeds:
//   ["matcher", market, maker_portfolio, maker_owner, matcher_prog, matcher_ctx]
// The v16 test helper was missing maker_owner. Updated to match the program.
pub fn matcher_delegate_key(
    program_id: &Pubkey,
    market: &Pubkey,
    maker: &Pubkey,
    maker_owner: &Pubkey,
    matcher_program: &Pubkey,
    matcher_context: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"matcher",
            market.as_ref(),
            maker.as_ref(),
            maker_owner.as_ref(),
            matcher_program.as_ref(),
            matcher_context.as_ref(),
        ],
        program_id,
    )
    .0
}

pub fn encode_matcher_init_passive(max_fill_abs: u128) -> Vec<u8> {
    encode_matcher_init_passive_with_spread(max_fill_abs, 0, 100)
}

pub fn encode_matcher_init_passive_with_spread(
    max_fill_abs: u128,
    base_spread_bps: u32,
    max_total_bps: u32,
) -> Vec<u8> {
    let mut data = vec![0u8; 66];
    data[0] = 2;
    data[1] = 0;
    data[6..10].copy_from_slice(&base_spread_bps.to_le_bytes());
    data[10..14].copy_from_slice(&max_total_bps.to_le_bytes());
    data[34..50].copy_from_slice(&max_fill_abs.to_le_bytes());
    data
}

pub fn make_mint_data() -> Vec<u8> {
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

pub fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
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

pub fn make_delegated_token_data(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: Pubkey,
    delegated_amount: u64,
) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::Some(delegate),
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount,
            close_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}

pub fn make_closable_token_data(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    close_authority: Pubkey,
) -> Vec<u8> {
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
            close_authority: COption::Some(close_authority),
        },
        &mut data,
    )
    .unwrap();
    data
}

pub fn make_pyth_data(
    feed_id: &[u8; 32],
    price: i64,
    expo: i32,
    conf: u64,
    publish_time: i64,
) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[0..8].copy_from_slice(&[0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd]);
    data[40] = 1;
    data[41..73].copy_from_slice(feed_id);
    data[73..81].copy_from_slice(&price.to_le_bytes());
    data[81..89].copy_from_slice(&conf.to_le_bytes());
    data[89..93].copy_from_slice(&expo.to_le_bytes());
    data[93..101].copy_from_slice(&publish_time.to_le_bytes());
    data
}

/// Builds a Switchboard `PullFeed` account layout matching `oracle_v16`'s byte offsets
/// (see `SB_OFF_*` in `src/v16_program.rs`). `submission_idx` selects which of the 32
/// `SB_OFF_SUBMISSION_TIMESTAMPS` slots callers may then poke independently of the
/// account-wide `last_update_timestamp` (offset 2216), which the caller sets separately --
/// that split is exactly the account-write-vs-selected-result distinction issue #405 (upstream
/// `72926689`) closes.
pub fn make_switchboard_data(
    feed_hash: &[u8; 32],
    value: i128,
    std_dev: i128,
    num_samples: u8,
    min_sample_size: u8,
    submission_idx: u8,
    result_slot: u64,
) -> Vec<u8> {
    let mut data = vec![0u8; 3_208];
    data[0..8].copy_from_slice(&[196, 27, 108, 196, 10, 215, 219, 40]);
    data[2_120..2_152].copy_from_slice(feed_hash);
    data[2_215] = min_sample_size;
    data[2_264..2_280].copy_from_slice(&value.to_le_bytes());
    data[2_280..2_296].copy_from_slice(&std_dev.to_le_bytes());
    data[2_360] = num_samples;
    data[2_361] = submission_idx; // SB_OFF_RESULT_SUBMISSION_IDX = 8 + 2_353
    data[2_368..2_376].copy_from_slice(&result_slot.to_le_bytes());
    data
}

pub fn cu_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

pub fn heap_ix() -> Instruction {
    ComputeBudgetInstruction::request_heap_frame(128 * 1024)
}

pub struct V16CuEnv {
    pub svm: LiteSVM,
    pub program_id: Pubkey,
    pub payer: Keypair,
    pub admin: Keypair,
    pub market: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub vault_authority: Pubkey,
    pub portfolio_account_len: usize,
}

#[derive(Clone, Copy)]
pub struct V16CuMarketParams {
    pub max_portfolio_assets: u16,
    pub h_min: u64,
    pub h_max: u64,
    pub initial_price: u64,
    pub min_nonzero_mm_req: u128,
    pub min_nonzero_im_req: u128,
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub max_trading_fee_bps: u64,
    pub trade_fee_base_bps: u64,
    pub liquidation_fee_bps: u64,
    pub liquidation_fee_cap: u128,
    pub min_liquidation_abs: u128,
    pub max_price_move_bps_per_slot: u64,
    pub max_accrual_dt_slots: u64,
    pub max_abs_funding_e9_per_slot: u64,
    pub min_funding_lifetime_slots: u64,
    pub max_account_b_settlement_chunks: u64,
    pub max_bankrupt_close_chunks: u64,
    pub max_bankrupt_close_lifetime_slots: u64,
    pub public_b_chunk_atoms: u128,
    pub maintenance_fee_per_slot: u128,
}

impl Default for V16CuMarketParams {
    fn default() -> Self {
        Self {
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
        }
    }
}

impl V16CuEnv {
    pub fn new() -> Self {
        Self::new_with_market_params_and_price_move(1, 10_000, 10_000, 10_000)
    }

    pub fn new_with_market_params_and_price_move(
        max_portfolio_assets: u16,
        maintenance_margin_bps: u64,
        initial_margin_bps: u64,
        max_price_move_bps_per_slot: u64,
    ) -> Self {
        Self::new_with_market_params_price_move_and_maintenance_fee(
            max_portfolio_assets,
            maintenance_margin_bps,
            initial_margin_bps,
            max_price_move_bps_per_slot,
            0,
        )
    }

    pub fn new_with_market_params_price_move_and_maintenance_fee(
        max_portfolio_assets: u16,
        maintenance_margin_bps: u64,
        initial_margin_bps: u64,
        max_price_move_bps_per_slot: u64,
        maintenance_fee_per_slot: u128,
    ) -> Self {
        Self::new_with_init_params(V16CuMarketParams {
            max_portfolio_assets,
            maintenance_margin_bps,
            initial_margin_bps,
            max_price_move_bps_per_slot,
            maintenance_fee_per_slot,
            ..V16CuMarketParams::default()
        })
    }

    pub fn new_with_init_params(params: V16CuMarketParams) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = harness_program_id();
        let program_bytes = std::fs::read(program_path()).expect("read BPF");
        svm.add_program(program_id, &program_bytes);
        let token_program_bytes = std::fs::read(spl_token_program_path()).expect("read token BPF");
        svm.add_program(spl_token::ID, &token_program_bytes);

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let vault_authority =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id).0;
        let vault = canonical_vault_ata(&vault_authority, &mint);
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
                    state::market_account_len_for_capacity(
                        params.max_portfolio_assets as usize
                    )
                    .unwrap()
                ],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        send_tx(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::InitMarket {
                max_portfolio_assets: params.max_portfolio_assets,
                h_min: params.h_min,
                h_max: params.h_max,
                initial_price: params.initial_price,
                min_nonzero_mm_req: params.min_nonzero_mm_req,
                min_nonzero_im_req: params.min_nonzero_im_req,
                maintenance_margin_bps: params.maintenance_margin_bps,
                initial_margin_bps: params.initial_margin_bps,
                max_trading_fee_bps: params.max_trading_fee_bps,
                trade_fee_base_bps: params.trade_fee_base_bps,
                liquidation_fee_bps: params.liquidation_fee_bps,
                liquidation_fee_cap: params.liquidation_fee_cap,
                min_liquidation_abs: params.min_liquidation_abs,
                max_price_move_bps_per_slot: params.max_price_move_bps_per_slot,
                max_accrual_dt_slots: params.max_accrual_dt_slots,
                max_abs_funding_e9_per_slot: params.max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots: params.min_funding_lifetime_slots,
                max_account_b_settlement_chunks: params.max_account_b_settlement_chunks,
                max_bankrupt_close_chunks: params.max_bankrupt_close_chunks,
                max_bankrupt_close_lifetime_slots: params.max_bankrupt_close_lifetime_slots,
                public_b_chunk_atoms: params.public_b_chunk_atoms,
                maintenance_fee_per_slot: params.maintenance_fee_per_slot,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin],
        )
        .expect("init market");
        Self {
            svm,
            program_id,
            payer,
            admin,
            market,
            mint,
            vault,
            vault_authority,
            portfolio_account_len: state::portfolio_account_len_for_market_slots(
                params.max_portfolio_assets as usize,
            )
            .unwrap(),
        }
    }

    pub fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.create_portfolio_with_cu(owner).0
    }

    pub fn create_portfolio_with_cu(&mut self, owner: &Keypair) -> (Pubkey, u64) {
        let portfolio = Pubkey::new_unique();
        self.ensure_signer_account(owner.pubkey());
        self.svm
            .set_account(
                portfolio,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; self.portfolio_account_len],
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let cu = self
            .send(
                ProgInstruction::InitPortfolio,
                vec![
                    AccountMeta::new(owner.pubkey(), true),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(portfolio, false),
                ],
                &[owner],
            )
            .expect("init portfolio");
        (portfolio, cu)
    }

    /// TB-1b: read the account's CURRENT portfolio_id/sequence/position_epoch
    /// directly off the live SVM account bytes, right before building an
    /// instruction that binds to them. Always correct regardless of how many
    /// prior Deposits/trades/etc. this specific portfolio has already seen in
    /// this test.
    pub fn portfolio_identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        // Runtime-parity GC can DELETE a closed portfolio; an op on it must fail in the program
        // (not panic the harness), so report a zero identity for a missing/emptied account.
        let data = match self.svm.get_account(&portfolio) {
            Some(a) if !a.data.is_empty() => a.data,
            _ => return (0, 0, 0),
        };
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    pub fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
        self.deposit_with_cu(owner, portfolio, amount).0
    }

    pub fn activate_asset(&mut self, asset_index: u16, now_slot: u64, initial_price: u64) -> u64 {
        self.activate_asset_with_authorities(
            asset_index,
            now_slot,
            initial_price,
            self.admin.pubkey(),
            self.admin.pubkey(),
            self.admin.pubkey(),
            self.admin.pubkey(),
        )
    }

    pub fn activate_asset_with_authorities(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
        insurance_authority: Pubkey,
        insurance_operator: Pubkey,
        backing_bucket_authority: Pubkey,
        oracle_authority: Pubkey,
    ) -> u64 {
        let clock = self.svm.get_sysvar::<Clock>();
        if clock.slot < now_slot {
            self.svm.warp_to_slot(now_slot);
        }
        // W3A-2: `self.admin` is marketauth, so this call always keys off
        // asset-0's LIVE authority_epoch (both the append/reuse-by-marketauth
        // path and the in-place-reactivate path use asset-0 -- see
        // `handle_update_asset_lifecycle`'s per-call-site comments). Reads it
        // fresh, mirroring this struct's own `control_sequences` idiom for the
        // other 14 TB-2b-bound lanes just below -- never a hardcoded constant.
        let authority_epoch = self.control_sequences(0).authority_epoch;
        // Wave-2 TB-4: an ACTIVATE binds against the market's live `next_market_id`
        // frontier -- read it, don't hardcode it.
        let (_current, market_id) = state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            true,
        )
        .unwrap_or((0, 0));
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                market_id,
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index,
                authority_epoch,
                now_slot,
                initial_price,
                max_init_fee: u128::MAX,
                insurance_authority: insurance_authority.to_bytes(),
                insurance_operator: insurance_operator.to_bytes(),
                backing_bucket_authority: backing_bucket_authority.to_bytes(),
                oracle_authority: oracle_authority.to_bytes(),
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("activate asset")
    }

    /// TB-2b: reads the LIVE `AssetControlSequencesV16` lanes for `asset_index`
    /// straight off the on-chain market account bytes, so every `..._with_cu`
    /// nonce-bearing helper below can supply a genuinely fresh, strictly-
    /// increasing value (never a hardcoded constant) regardless of how many
    /// times a test has already advanced that lane.
    pub fn control_sequences(&self, asset_index: u16) -> state::AssetControlSequencesV16 {
        let account = self.svm.get_account(&self.market).expect("market account");
        state::read_asset_control_sequences(&account.data, asset_index as usize)
            .expect("read control sequences")
    }

    /// W3A-1: mirrors `handle_withdraw_insurance_asset`'s own `epoch_asset_index`
    /// selection (`if local_authorized { asset_index } else { 0 }`) so every
    /// insurance-withdrawal helper below supplies the LIVE `authority_epoch` for
    /// whichever lane the handler will actually check -- reading the on-chain
    /// `insurance_operator` for `asset_index` directly, rather than assuming which
    /// path a given `authority` takes.
    pub fn insurance_withdraw_authority_epoch(&self, asset_index: u16, authority: &Pubkey) -> u64 {
        let account = self.svm.get_account(&self.market).expect("market account");
        let profile = state::read_asset_oracle_profile(&account.data, asset_index as usize)
            .expect("read oracle profile");
        let local_authorized = profile.insurance_operator == authority.to_bytes();
        let epoch_asset_index = if local_authorized { asset_index } else { 0 };
        self.control_sequences(epoch_asset_index).authority_epoch
    }

    /// W3A-1: same idea as `insurance_withdraw_authority_epoch`, for
    /// `WithdrawBackingBucket[Earnings]`'s `epoch_asset_index` selection
    /// (`if local_authorized { domain_usize / 2 } else { 0 }`).
    pub fn backing_withdraw_authority_epoch(&self, domain: u16, authority: &Pubkey) -> u64 {
        let account = self.svm.get_account(&self.market).expect("market account");
        let profile = state::read_asset_oracle_profile(&account.data, (domain / 2) as usize)
            .expect("read oracle profile");
        let local_authorized = profile.backing_bucket_authority == authority.to_bytes();
        let epoch_asset_index = if local_authorized { domain / 2 } else { 0 };
        self.control_sequences(epoch_asset_index).authority_epoch
    }

    /// W4-AE-84: reads the LIVE market-wide `protocol_fee_authority_epoch`
    /// counter straight off the on-chain market account bytes, mirroring
    /// `control_sequences`'s own "never a hardcoded constant" role for
    /// `WithdrawProtocolFee` (tag 84).
    pub fn protocol_fee_authority_epoch(&self) -> u64 {
        let account = self.svm.get_account(&self.market).expect("market account");
        state::read_protocol_fee_authority_epoch(&account.data)
            .expect("read protocol_fee_authority_epoch")
    }

    pub fn update_market_init_fee_policy_with_cu(&mut self, min_init_fee: u128) -> u64 {
        let policy_sequence = self.control_sequences(0).market_init_fee + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateMarketInitFeePolicy {
                min_init_fee,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update market init fee policy")
    }

    pub fn update_asset_lifecycle_as_admin_with_cu(
        &mut self,
        action: u8,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
    ) -> u64 {
        // W3A-2: `self.admin` is marketauth -- keys off asset-0's LIVE
        // authority_epoch regardless of `action` (ACTIVATE/DRAIN_ONLY/RETIRE/
        // SHUTDOWN-by-marketauth all use asset-0; see
        // `handle_update_asset_lifecycle`'s per-call-site comments).
        let authority_epoch = self.control_sequences(0).authority_epoch;
        // Wave-2 TB-4: compute the caller-supplied generation-binding market_id
        // live from market state -- this helper is shared by append/reuse/
        // retire/drain-only/shutdown callers at every asset_index in the suite.
        let is_activation = action == percolator_prog::processor::ASSET_ACTION_ACTIVATE;
        let (current_market_id, next_market_id) = state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            is_activation,
        )
        .unwrap_or((0, 0));
        let market_id = if is_activation {
            next_market_id
        } else {
            current_market_id
        };
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                market_id,
                action,
                asset_index,
                authority_epoch,
                now_slot,
                initial_price,
                max_init_fee: u128::MAX,
                insurance_authority: self.admin.pubkey().to_bytes(),
                insurance_operator: self.admin.pubkey().to_bytes(),
                backing_bucket_authority: self.admin.pubkey().to_bytes(),
                oracle_authority: self.admin.pubkey().to_bytes(),
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update asset lifecycle as admin")
    }

    pub fn update_liquidation_fee_policy_with_cu(&mut self, cranker_share_bps: u16) -> u64 {
        let policy_sequence = self.control_sequences(0).liquidation_fee + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateLiquidationFeePolicy {
                cranker_share_bps,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update liquidation fee policy")
    }

    pub fn update_backing_fee_policy_with_cu(
        &mut self,
        domain: u16,
        fee_bps: u16,
        insurance_share_bps: u16,
    ) -> u64 {
        let asset_index = domain / 2;
        let long_side = domain % 2 == 0;
        let current = self.control_sequences(asset_index);
        let policy_sequence = if long_side {
            current.backing_fee_long
        } else {
            current.backing_fee_short
        } + 1;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateBackingFeePolicy {
                market_id,
                domain,
                fee_bps,
                insurance_share_bps,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update backing fee policy")
    }

    pub fn update_trade_fee_policy_with_cu(&mut self, trade_fee_base_bps: u64) -> u64 {
        let policy_sequence = self.control_sequences(0).trade_fee + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateTradeFeePolicy {
                trade_fee_base_bps,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update trade fee policy")
    }

    pub fn update_fee_redirect_policy_with_cu(&mut self, redirect_bps: u16) -> u64 {
        let policy_sequence = self.control_sequences(0).fee_redirect + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateFeeRedirectPolicy {
                redirect_bps,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update fee redirect policy")
    }

    pub fn update_asset_authority_with_cu(&mut self, new_authority: &Keypair) -> u64 {
        // v17 convergence: `UpdateAuthority` now rotates the single market-level `marketauth`
        // key (no `kind` field). Per-asset authority rotation uses `UpdateAssetAuthority`.
        // This helper keeps its name; it now rotates `marketauth` (the v17 admin key) to match
        // the v17 single-authority design.
        // Matrix row: v17-auth-overhaul (UpdateAuthority API change, `kind` field removed).
        self.ensure_signer_account(new_authority.pubkey());
        // W3A-1: `UpdateAuthority` now binds asset-0's `authority_epoch` lane (the
        // same slot `UpdateAssetAuthority` uses at asset_index == 0) via strict CAS.
        let authority_epoch = self.control_sequences(0).authority_epoch;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAuthority {
                new_pubkey: new_authority.pubkey().to_bytes(),
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(new_authority.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin, new_authority],
        )
        .expect("update asset authority")
    }

    pub fn update_base_unit_mints_with_cu(
        &mut self,
        primary_mint: Pubkey,
        secondary_mint: Pubkey,
    ) -> u64 {
        // W3A-2: `UpdateBaseUnitMints` keys off asset-0's LIVE authority_epoch
        // unconditionally (single call site).
        let authority_epoch = self.control_sequences(0).authority_epoch;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateBaseUnitMints {
                primary_mint: primary_mint.to_bytes(),
                secondary_mint: secondary_mint.to_bytes(),
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(primary_mint, false),
                AccountMeta::new_readonly(secondary_mint, false),
            ],
            &[&self.admin],
        )
        .expect("update base unit mints")
    }

    pub fn swap_secondary_for_primary_with_cu(
        &mut self,
        primary_source: Pubkey,
        primary_vault: Pubkey,
        secondary_dest: Pubkey,
        secondary_vault: Pubkey,
        amount: u128,
    ) -> u64 {
        // W3A-2: `SwapSecondaryForPrimary` keys off asset-0's LIVE
        // authority_epoch unconditionally (single call site).
        let authority_epoch = self.control_sequences(0).authority_epoch;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SwapSecondaryForPrimary {
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(primary_source, false),
                AccountMeta::new(primary_vault, false),
                AccountMeta::new(secondary_dest, false),
                AccountMeta::new(secondary_vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("swap secondary for primary")
    }

    pub fn token_account(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        let token = Pubkey::new_unique();
        self.svm
            .set_account(
                token,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        token
    }

    pub fn ensure_signer_account(&mut self, key: Pubkey) {
        if self.svm.get_account(&key).is_none() {
            self.svm.airdrop(&key, 1_000_000_000).unwrap();
        }
    }

    pub fn create_mint(&mut self) -> Pubkey {
        let mint = Pubkey::new_unique();
        self.svm
            .set_account(
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
        mint
    }

    pub fn token_account_for_mint(&mut self, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
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

    /// A vault token account at the CANONICAL ATA address for `mint`, owned by vault_authority
    /// (W3 F-VAULT-FRAG pin) — for the secondary-mint vault on the offset-pair swap path.
    pub fn vault_token_for_mint(&mut self, mint: Pubkey, amount: u64) -> Pubkey {
        let token = canonical_vault_ata(&self.vault_authority, &mint);
        self.svm
            .set_account(
                token,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, self.vault_authority, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        token
    }

    pub fn program_account(&mut self, data_len: usize) -> Pubkey {
        let key = Pubkey::new_unique();
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; data_len],
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        key
    }

    pub fn backing_domain_ledger_account(&mut self) -> Pubkey {
        self.program_account(state::backing_domain_ledger_account_len())
    }

    pub fn canonical_backing_domain_ledger_account(&mut self, domain: u16) -> Pubkey {
        let (ledger, _) = state::derive_lp_backing_ledger(&self.program_id, &self.market, domain);
        if self.svm.get_account(&ledger).is_none() {
            self.svm
                .set_account(
                    ledger,
                    Account {
                        lamports: 1_000_000_000,
                        data: vec![0u8; state::backing_domain_ledger_account_len()],
                        owner: self.program_id,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
        }
        ledger
    }

    pub fn insurance_ledger_account(&mut self) -> Pubkey {
        self.program_account(state::insurance_ledger_account_len())
    }

    pub fn set_token_account_amount(
        &mut self,
        token: Pubkey,
        mint: Pubkey,
        owner: Pubkey,
        amount: u64,
    ) {
        let mut account = self.svm.get_account(&token).expect("token account");
        account.data = make_token_data(mint, owner, amount);
        account.owner = spl_token::ID;
        self.svm.set_account(token, account).unwrap();
    }

    pub fn market_state(&self) -> (state::WrapperConfigV16, MarketGroupV16) {
        let account = self.svm.get_account(&self.market).expect("market account");
        state::read_market(&account.data).unwrap()
    }

    pub fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        let account = self.svm.get_account(&portfolio).expect("portfolio account");
        state::read_portfolio(&account.data).unwrap()
    }

    pub fn mutate_market<F>(&mut self, f: F)
    where
        F: FnOnce(&mut state::WrapperConfigV16, &mut MarketGroupV16),
    {
        let mut account = self.svm.get_account(&self.market).expect("market account");
        let (mut cfg, mut group) = state::read_market(&account.data).unwrap();
        f(&mut cfg, &mut group);
        state::write_market(&mut account.data, &cfg, &group).unwrap();
        self.svm.set_account(self.market, account).unwrap();
    }

    // Test-harness-only workaround for a LiteSVM/solana-bpf-loader-program realloc
    // limitation on accounts injected directly via `svm.set_account()` (rather than a
    // real on-chain `CreateAccount`): such accounts cannot be grown past roughly
    // `MAX_PERMITTED_DATA_INCREASE` (10,240) total bytes through the BPF program's own
    // `AccountInfo::realloc()` call, no matter how small the requested delta is or
    // whether the growth is a single jump or a sequence of smaller steps -- this is an
    // absolute ceiling on the resulting length for THIS test environment, not a real
    // Solana/mainnet constraint (a genuinely-created account gets the runtime's usual
    // realloc headroom). `ActivateAsset`'s own on-chain realloc (`market_ai.realloc`,
    // used only when `asset_index >= capacity_pre`) hits exactly this wall once a
    // market's total account size crosses that threshold, which any market with more
    // than a handful of assets already does.
    //
    // This helper grows the market account's raw byte buffer directly through the test
    // harness's own account-injection path (no on-chain realloc involved, so the
    // ceiling above never applies) to the capacity the NEXT `activate_asset` call will
    // need, zero-padding the new tail exactly like a real realloc would. This only
    // changes the account's raw length (`capacity_pre`, derived purely from
    // `data.len()`); it does not touch `configured_slots`/`free_market_slot_count` or
    // any other engine/wrapper bookkeeping, so `ActivateAsset`'s own append-detection
    // (`asset_index == configured_slots_pre`) still fires normally and the instruction
    // still performs every one of its usual checks and writes -- it simply finds
    // `asset_index < capacity_pre` already true and skips its own (here-unusable)
    // realloc call. The resulting account state is byte-identical to what a real
    // devnet/mainnet `ActivateAsset` append would produce.
    pub fn grow_market_capacity_for_test(&mut self, new_capacity: usize) {
        let target_len = state::market_account_len_for_capacity(new_capacity).unwrap();
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        assert!(
            target_len >= market_account.data.len(),
            "grow_market_capacity_for_test must not shrink the market account"
        );
        market_account.data.resize(target_len, 0u8);
        self.svm.set_account(self.market, market_account).unwrap();
    }

    pub fn add_source_positive_pnl(&mut self, portfolio: Pubkey, domain: usize, amount: u128) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut portfolio_account = self.svm.get_account(&portfolio).expect("portfolio account");
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut account = state::read_portfolio(&portfolio_account.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, domain, amount)
            .unwrap();
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_account.data, &account).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio, portfolio_account).unwrap();
    }

    pub fn seed_cancellable_close_progress(&mut self, portfolio: Pubkey) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut portfolio_account = self.svm.get_account(&portfolio).expect("portfolio account");
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

    pub fn activate_permissionless_asset_with_fee(
        &mut self,
        creator: &Keypair,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
        insurance_authority: Pubkey,
        insurance_operator: Pubkey,
        backing_bucket_authority: Pubkey,
        oracle_authority: Pubkey,
        fee: u128,
    ) -> (Pubkey, u64) {
        self.ensure_signer_account(creator.pubkey());
        let source = self.token_account(creator.pubkey(), fee as u64);
        // Wave-2 TB-4: this is always an ACTIVATE (append or reuse), which binds
        // against the market's live `next_market_id` frontier.
        let (_current_market_id, market_id) = state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            true,
        )
        .unwrap_or((0, 0));
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                market_id,
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index,
                // W3A-2: `creator` is not marketauth, so this permissionless
                // lane requires the canonical zero value unconditionally.
                authority_epoch: 0,
                now_slot,
                initial_price,
                max_init_fee: u128::MAX,
                insurance_authority: insurance_authority.to_bytes(),
                insurance_operator: insurance_operator.to_bytes(),
                backing_bucket_authority: backing_bucket_authority.to_bytes(),
                oracle_authority: oracle_authority.to_bytes(),
            },
            vec![
                AccountMeta::new(creator.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[creator],
        )
        .expect("permissionless asset activation with fee");
        (source, cu)
    }

    /// Same wire shape as `activate_permissionless_asset_with_fee`, but exposes the
    /// caller-supplied `max_init_fee` consent cap (W2-4ed3411b) and returns the raw
    /// `Result` instead of panicking, so callers can assert on rejection.
    #[allow(clippy::too_many_arguments)]
    pub fn try_activate_permissionless_asset_with_fee_and_cap(
        &mut self,
        creator: &Keypair,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
        insurance_authority: Pubkey,
        insurance_operator: Pubkey,
        backing_bucket_authority: Pubkey,
        oracle_authority: Pubkey,
        fund_amount: u128,
        max_init_fee: u128,
    ) -> Result<(Pubkey, u64), String> {
        self.ensure_signer_account(creator.pubkey());
        let source = self.token_account(creator.pubkey(), fund_amount as u64);
        // Wave-2 TB-4: an ACTIVATE binds against the market's live `next_market_id`
        // frontier -- read it, don't hardcode it.
        let (_current, market_id) = state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            true,
        )
        .unwrap_or((0, 0));
        let result = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                market_id,
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index,
                // W3A-2: `creator` is not marketauth, so this permissionless
                // lane requires the canonical zero value unconditionally.
                authority_epoch: 0,
                now_slot,
                initial_price,
                max_init_fee,
                insurance_authority: insurance_authority.to_bytes(),
                insurance_operator: insurance_operator.to_bytes(),
                backing_bucket_authority: backing_bucket_authority.to_bytes(),
                oracle_authority: oracle_authority.to_bytes(),
            },
            vec![
                AccountMeta::new(creator.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[creator],
        );
        result.map(|cu| (source, cu))
    }

    pub fn deposit_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> (Pubkey, u64) {
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
        let (portfolio_id, expected_sequence, _) = self.portfolio_identity(portfolio);
        let cu = self
            .send(
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
        (source, cu)
    }

    pub fn trade_with_cu(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> u64 {
        self.trade_asset_with_cu(
            0, owner_a, account_a, owner_b, account_b, size_q, exec_price, fee_bps,
        )
    }

    pub fn trade_asset_with_cu(
        &mut self,
        asset_index: u16,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> u64 {
        self.try_trade_asset_with_cu(
            asset_index,
            owner_a,
            account_a,
            owner_b,
            account_b,
            size_q,
            exec_price,
            fee_bps,
        )
        .expect("trade")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_trade_asset_with_cu(
        &mut self,
        asset_index: u16,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> Result<u64, String> {
        let (account_a_portfolio_id, _, account_a_position_epoch) =
            self.portfolio_identity(account_a);
        let (account_b_portfolio_id, _, account_b_position_epoch) =
            self.portfolio_identity(account_b);
        // Wave-2 TB-4: this helper is shared by every asset_index in the suite
        // (base and appended), so market_id must be read live, not hardcoded.
        let market_id = state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
        )
        .unwrap()
        .3;
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id,
                account_a_position_epoch,
                account_b_portfolio_id,
                account_b_position_epoch,
                market_id,
                asset_index,
                size_q,
                exec_price,
                fee_bps,
                backing_fee_cap_bps: 10_000,
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

    pub fn update_maintenance_fee_policy_with_cu(&mut self, cranker_share_bps: u16) -> u64 {
        let policy_sequence = self.control_sequences(0).maintenance_fee + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateMaintenanceFeePolicy {
                cranker_share_bps,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update maintenance fee policy")
    }

    pub fn sync_maintenance_fee_with_cu(
        &mut self,
        portfolio: Pubkey,
        cranker_portfolio: Option<Pubkey>,
        now_slot: u64,
    ) -> u64 {
        self.try_sync_maintenance_fee_with_cu(portfolio, cranker_portfolio, now_slot)
            .expect("sync maintenance fee")
    }

    pub fn try_sync_maintenance_fee_with_cu(
        &mut self,
        portfolio: Pubkey,
        cranker_portfolio: Option<Pubkey>,
        now_slot: u64,
    ) -> Result<u64, String> {
        let mut accounts = vec![
            AccountMeta::new(self.market, false),
            AccountMeta::new(portfolio, false),
        ];
        if let Some(cranker_portfolio) = cranker_portfolio {
            accounts.push(AccountMeta::new(cranker_portfolio, false));
        }
        self.send(
            ProgInstruction::SyncMaintenanceFee { now_slot },
            accounts,
            &[],
        )
    }

    /// FIX (upstream #400, "require cranker portfolio owner to sign
    /// SyncMaintenanceFee reward claim"): when the maintenance-fee cranker
    /// reward is directed at a THIRD-PARTY portfolio (cranker_portfolio !=
    /// portfolio being synced), the handler requires accounts[3] to be that
    /// cranker portfolio's owner, signing -- otherwise any caller could
    /// direct every user's maintenance-fee reward share to an
    /// attacker-controlled portfolio. `sync_maintenance_fee_with_cu` above
    /// covers the self-crank (cranker_portfolio == portfolio or None) path,
    /// which does not need this signer; use this variant for the
    /// separate-cranker path.
    pub fn sync_maintenance_fee_with_cranker_owner_with_cu(
        &mut self,
        portfolio: Pubkey,
        cranker_portfolio: Pubkey,
        cranker_owner: &Keypair,
        now_slot: u64,
    ) -> u64 {
        self.send(
            ProgInstruction::SyncMaintenanceFee { now_slot },
            vec![
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(cranker_portfolio, false),
                AccountMeta::new_readonly(cranker_owner.pubkey(), true),
            ],
            &[cranker_owner],
        )
        .expect("sync maintenance fee with cranker owner")
    }

    pub fn seed_n_leg_position_for_benchmark(
        &mut self,
        long_account: Pubkey,
        short_account: Pubkey,
        n: usize,
    ) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut long_data = self.svm.get_account(&long_account).expect("long account");
        let mut short_data = self.svm.get_account(&short_account).expect("short account");
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_account.data).unwrap();
        {
            let (_, mut group) = state::market_view_mut(&mut market_account.data).unwrap();
            let mut long =
                state::portfolio_view_mut_for_market_slots(&mut long_data.data, max_market_slots)
                    .unwrap();
            let mut short =
                state::portfolio_view_mut_for_market_slots(&mut short_data.data, max_market_slots)
                    .unwrap();
            for asset_index in 0..n {
                // v17 convergence: execute_trade_with_fee_in_place_not_atomic removed (runtime-vec
                // API dropped). Use execute_trade_with_fee_loss_stale_scoped_not_atomic instead.
                // TradeRequestV16.admit_h_max_consumption_threshold_bps_opt also removed.
                // size_q is now i128. Matrix row: v17-runtime-vec-api-drop.
                group
                    .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                        &mut long,
                        &mut short,
                        TradeRequestV16 {
                            asset_index,
                            size_q: (10 * POS_SCALE) as i128,
                            exec_price: 100,
                            fee_bps: 0,
                        },
                        true,
                    )
                    .unwrap();
            }
            for asset_index in 0..n {
                group
                    .accrue_asset_to_not_atomic(asset_index, 16, 95, 0, true)
                    .unwrap();
                group.markets[asset_index]
                    .engine
                    .asset
                    .raw_oracle_target_price = percolator::V16PodU64::new(95);
            }
            // FIX E-CU-R: this used to zero `active_bitmap_at_cert` on both portfolios so the
            // wrapper's pre-trade currentness gate would short-circuit and the seeded stale
            // portfolio would reach the engine's 2N stale-leg refresh. That made the fixture
            // measure a shape the shipping wrapper refuses -- the CU number it produced was not a
            // statement about any transaction that can land on chain. Upstream's own
            // `seed_n_leg_position_for_benchmark` never did it. The two crank benchmarks that
            // also use this seeder (`..._refresh_crank_...`, `..._liquidation_crank_...`) do not
            // go through the trade gate and are unaffected; the trade benchmark now asserts the
            // refusal instead (`v16_bpf_stale_full_14_leg_tradenocpi_rejects_before_cu_cliff`).
        }
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(long_account, long_data).unwrap();
        self.svm.set_account(short_account, short_data).unwrap();
    }

    /// Accrue ONE asset to `now_slot` at `price` without touching any portfolio. Used by the
    /// fresh-asset E-CU-R regression so the asset the trade opens is exactly as current as the
    /// assets the stale legs sit on -- the refusal then has to be about the portfolio's
    /// staleness and nothing else.
    pub fn accrue_asset_for_benchmark(&mut self, asset_index: usize, now_slot: u64, price: u64) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        {
            let (_, mut group) = state::market_view_mut(&mut market_account.data).unwrap();
            group
                .accrue_asset_to_not_atomic(asset_index, now_slot, price, 0, true)
                .unwrap();
            group.markets[asset_index]
                .engine
                .asset
                .raw_oracle_target_price = percolator::V16PodU64::new(price);
        }
        self.svm.set_account(self.market, market_account).unwrap();
    }

    pub fn seed_current_n_leg_position_for_benchmark(
        &mut self,
        long_account: Pubkey,
        short_account: Pubkey,
        n: usize,
    ) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut long_data = self.svm.get_account(&long_account).expect("long account");
        let mut short_data = self.svm.get_account(&short_account).expect("short account");
        let (_, _, max_market_slots, _) =
            state::read_market_config_mode_and_capacity(&market_account.data).unwrap();
        {
            let (_, mut group) = state::market_view_mut(&mut market_account.data).unwrap();
            let mut long =
                state::portfolio_view_mut_for_market_slots(&mut long_data.data, max_market_slots)
                    .unwrap();
            let mut short =
                state::portfolio_view_mut_for_market_slots(&mut short_data.data, max_market_slots)
                    .unwrap();
            for asset_index in 0..n {
                // v17 convergence: see note above for seed_all_n_leg_position_for_benchmark.
                group
                    .execute_trade_with_fee_loss_stale_scoped_not_atomic(
                        &mut long,
                        &mut short,
                        TradeRequestV16 {
                            asset_index,
                            size_q: (10 * POS_SCALE) as i128,
                            exec_price: 100,
                            fee_bps: 0,
                        },
                        true,
                    )
                    .unwrap();
            }
        }
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(long_account, long_data).unwrap();
        self.svm.set_account(short_account, short_data).unwrap();
    }

    pub fn force_portfolio_capital_for_benchmark(&mut self, portfolio_key: Pubkey, new_capital: u128) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut portfolio_data = self
            .svm
            .get_account(&portfolio_key)
            .expect("portfolio account");
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut portfolio = state::read_portfolio(&portfolio_data.data).unwrap();
        let old_capital = portfolio.capital;
        if new_capital < old_capital {
            let delta = old_capital - new_capital;
            group.c_tot -= delta;
            group.vault -= delta;
        } else {
            let delta = new_capital - old_capital;
            group.c_tot += delta;
            group.vault += delta;
        }
        portfolio.capital = new_capital;
        portfolio.health_cert.valid = false;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_data.data, &portfolio).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio_key, portfolio_data).unwrap();
    }

    pub fn force_portfolio_bankruptcy_for_security_test(&mut self, portfolio_key: Pubkey, loss: u128) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut portfolio_data = self
            .svm
            .get_account(&portfolio_key)
            .expect("portfolio account");
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut portfolio = state::read_portfolio(&portfolio_data.data).unwrap();
        if portfolio.capital != 0 {
            group.c_tot -= portfolio.capital;
            group.vault -= portfolio.capital;
            portfolio.capital = 0;
        }
        assert_eq!(
            portfolio.pnl, 0,
            "security seed expects neutral starting pnl"
        );
        let loss_i128 = i128::try_from(loss).unwrap();
        portfolio.pnl = -loss_i128;
        group.negative_pnl_account_count += 1;
        portfolio.health_cert.valid = false;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_data.data, &portfolio).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio_key, portfolio_data).unwrap();
    }

    pub fn force_portfolio_loss_for_security_test(&mut self, portfolio_key: Pubkey, loss: u128) {
        let mut market_account = self.svm.get_account(&self.market).expect("market account");
        let mut portfolio_data = self
            .svm
            .get_account(&portfolio_key)
            .expect("portfolio account");
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut portfolio = state::read_portfolio(&portfolio_data.data).unwrap();
        assert!(
            portfolio.capital > loss,
            "loss must remain fully covered by capital"
        );
        assert_eq!(
            portfolio.pnl, 0,
            "security seed expects neutral starting pnl"
        );
        let loss_i128 = i128::try_from(loss).unwrap();
        portfolio.pnl = -loss_i128;
        group.negative_pnl_account_count += 1;
        portfolio.health_cert.valid = false;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_data.data, &portfolio).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio_key, portfolio_data).unwrap();
    }

    pub fn init_matcher_context(
        &mut self,
        maker_owner: &Keypair,
        matcher_program: Pubkey,
        maker_account: Pubkey,
    ) -> (Pubkey, Pubkey, u64) {
        self.init_matcher_context_with_data(
            maker_owner,
            matcher_program,
            maker_account,
            encode_matcher_init_passive(u128::MAX),
        )
    }

    pub fn init_matcher_context_with_passive_spread(
        &mut self,
        maker_owner: &Keypair,
        matcher_program: Pubkey,
        maker_account: Pubkey,
        base_spread_bps: u32,
        max_total_bps: u32,
    ) -> (Pubkey, Pubkey, u64) {
        self.init_matcher_context_with_data(
            maker_owner,
            matcher_program,
            maker_account,
            encode_matcher_init_passive_with_spread(u128::MAX, base_spread_bps, max_total_bps),
        )
    }

    // v17 convergence matrix row: v17-tradecpi-set-matcher-config
    // v17 TradeCpi requires maker_account to have LP matcher config (enabled=1)
    // matching the matcher program/context/delegate. Call SetMatcherConfig here so
    // every init_matcher_context correctly registers the LP portfolio.
    pub fn init_matcher_context_with_data(
        &mut self,
        maker_owner: &Keypair,
        matcher_program: Pubkey,
        maker_account: Pubkey,
        init_data: Vec<u8>,
    ) -> (Pubkey, Pubkey, u64) {
        let ctx = Pubkey::new_unique();
        let delegate = matcher_delegate_key(
            &self.program_id,
            &self.market,
            &maker_account,
            &maker_owner.pubkey(),
            &matcher_program,
            &ctx,
        );
        self.svm
            .set_account(
                delegate,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![],
                    owner: Pubkey::default(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.svm
            .set_account(
                ctx,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; MATCHER_CONTEXT_LEN],
                    owner: matcher_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        // Register maker_account as LP portfolio with the matcher config FIRST.
        // SetMatcherConfig stores the derived delegate so handle_trade_cpi can verify it,
        // and InitMatcherCtx requires the (matcher_prog, matcher_ctx, delegate) triple to
        // already be registered on the LP portfolio.
        let (portfolio_id, expected_sequence, _) = self.portfolio_identity(maker_account);
        // W3-matcher (ADOPT upstream `8f62a5c5`): the LIVE asset-generation
        // frontier this grant must be authorized against.
        let asset_generation_frontier = state::read_market_asset_generation_frontier(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
        // TB-1b: `expiry_slot` must be a live future slot for
        // `matcher_capability_config_is_valid`/`matcher_capability_is_live` to accept
        // `enabled: 1` -- this harness never warps anywhere near u64::MAX.
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SetMatcherConfig {
                portfolio_id,
                expected_sequence,
                asset_generation_frontier,
                enabled: 1,
                trade_fee_cap_bps: 10_000,
                expiry_slot: u64::MAX,
            },
            vec![
                AccountMeta::new(maker_owner.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(maker_account, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new_readonly(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[maker_owner],
        )
        .expect("set matcher config");

        // Bootstrap the context through the WRAPPER's InitMatcherCtx (tag 83), not by
        // calling the matcher directly. The matcher requires the context authority to sign
        // process_init, that authority is the wrapper's matcher-delegate PDA, and a PDA can
        // only sign via invoke_signed by its owning program -- which is exactly what tag 83
        // does. Calling the matcher directly (as this helper used to) works only against a
        // matcher build that is missing the lp_pda.is_signer check, i.e. only before
        // BUG-001 was fixed.
        // init_data[0] is the matcher's INIT_VAMM tag (2); the kind is at [1]. The wrapper
        // re-adds the tag itself when it builds the 78-byte CPI payload.
        let kind = init_data[1];
        let trading_fee_bps = u32::from_le_bytes(init_data[2..6].try_into().unwrap());
        let base_spread_bps = u32::from_le_bytes(init_data[6..10].try_into().unwrap());
        let max_total_bps = u32::from_le_bytes(init_data[10..14].try_into().unwrap());
        let impact_k_bps = u32::from_le_bytes(init_data[14..18].try_into().unwrap());
        let liquidity_notional_e6 = u128::from_le_bytes(init_data[18..34].try_into().unwrap());
        let max_fill_abs = u128::from_le_bytes(init_data[34..50].try_into().unwrap());
        let max_inventory_abs = u128::from_le_bytes(init_data[50..66].try_into().unwrap());

        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::InitMatcherCtx {
                kind,
                trading_fee_bps,
                base_spread_bps,
                max_total_bps,
                impact_k_bps,
                liquidity_notional_e6,
                max_fill_abs,
                max_inventory_abs,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                AccountMeta::new(maker_owner.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(maker_account, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[maker_owner],
        )
        .expect("init matcher context via wrapper InitMatcherCtx");
        (ctx, delegate, cu)
    }

    pub fn trade_cpi_with_cu(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        matcher_program: Pubkey,
        matcher_context: Pubkey,
        matcher_delegate: Pubkey,
        size_q: i128,
        fee_bps: u64,
    ) -> u64 {
        self.trade_cpi_with_cu_on_asset(
            owner_a,
            account_a,
            owner_b,
            account_b,
            matcher_program,
            matcher_context,
            matcher_delegate,
            0,
            size_q,
            fee_bps,
        )
    }

    pub fn trade_cpi_with_cu_on_asset(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        matcher_program: Pubkey,
        matcher_context: Pubkey,
        matcher_delegate: Pubkey,
        asset_index: u16,
        size_q: i128,
        fee_bps: u64,
    ) -> u64 {
        self.try_trade_cpi_with_cu_on_asset(
            owner_a,
            account_a,
            owner_b,
            account_b,
            matcher_program,
            matcher_context,
            matcher_delegate,
            asset_index,
            size_q,
            fee_bps,
        )
        .expect("trade cpi")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_trade_cpi_with_cu_on_asset(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        matcher_program: Pubkey,
        matcher_context: Pubkey,
        matcher_delegate: Pubkey,
        asset_index: u16,
        size_q: i128,
        fee_bps: u64,
    ) -> Result<u64, String> {
        // v17 convergence: TradeCpi account layout changed — `signer_b` removed (index 1 was
        // signer_b in v16). v17 layout: [signer_a(signer), market(writable), account_a(writable),
        // account_b(writable), matcher_prog, matcher_ctx(writable), matcher_delegate].
        // Matrix row: v17-tradecpi-layout (signer_b removed, market writable).
        // LiteSVM 0.1 does not enforce signatures for is_signer=true accounts that are not
        // system accounts; writable+is_signer=true is used here to satisfy the LiteSVM
        // transaction signing: with is_signer=false on non-system accounts, LiteSVM still
        // passes the flag through but the solver doesn't add them to signer slots. The
        // on-chain handler only checks signer_a (accounts[0]).
        let _ = owner_b; // signer_b no longer needed in v17 TradeCpi
        let (account_a_portfolio_id, _, account_a_position_epoch) =
            self.portfolio_identity(account_a);
        let (account_b_portfolio_id, account_b_matcher_sequence, account_b_position_epoch) =
            self.portfolio_identity(account_b);
        // Wave-2 TB-4: read live, this helper is shared by every asset_index.
        let market_id = state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
        )
        .unwrap()
        .3;
        self.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id,
                account_a_position_epoch,
                account_b_portfolio_id,
                account_b_position_epoch,
                market_id,
                account_b_matcher_sequence,
                asset_index,
                size_q,
                fee_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new(matcher_context, false),
                AccountMeta::new_readonly(matcher_delegate, false),
            ],
            &[owner_a],
        )
    }

    pub fn withdraw(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
        self.withdraw_with_cu(owner, portfolio, amount).0
    }

    pub fn close_portfolio_with_cu(&mut self, owner: &Keypair, portfolio: Pubkey) -> u64 {
        let (portfolio_id, expected_sequence, position_epoch) =
            self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::ClosePortfolio {
                portfolio_id,
                expected_sequence,
                position_epoch,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("close portfolio")
    }

    pub fn withdraw_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> (Pubkey, u64) {
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
        let (portfolio_id, expected_sequence, _) = self.portfolio_identity(portfolio);
        let cu = self
            .send(
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
                    AccountMeta::new_readonly(self.vault_authority, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
                &[owner],
            )
            .expect("withdraw");
        (dest, cu)
    }

    pub fn resolve(&mut self) -> u64 {
        // W3A-3: LIVE read of asset-0's `authority_epoch` via the existing
        // `control_sequences` helper.
        let authority_epoch = self.control_sequences(0).authority_epoch;
        let asset_generation_frontier =
            state::read_asset_generation_frontier(&self.svm.get_account(&self.market).unwrap().data)
                .unwrap();
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ResolveMarket { asset_generation_frontier: asset_generation_frontier, authority_epoch },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("resolve market")
    }

    pub fn close_slab_with_cu(&mut self) -> u64 {
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
        // W3A-1: CloseSlab binds asset-0's `authority_epoch` (CHECK-only, not advanced).
        let authority_epoch = self.control_sequences(0).authority_epoch;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::CloseSlab { authority_epoch },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("close slab")
    }

    pub fn configure_permissionless_resolve_with_cu(
        &mut self,
        stale_slots: u64,
        force_close_delay_slots: u64,
    ) -> u64 {
        let policy_sequence = self.control_sequences(0).permissionless_resolve + 1;
        let asset_generation_frontier =
            state::read_asset_generation_frontier(&self.svm.get_account(&self.market).unwrap().data)
                .unwrap();
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigurePermissionlessResolve {
                asset_generation_frontier,
                stale_slots,
                force_close_delay_slots,
                policy_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure permissionless resolve")
    }

    pub fn enable_live_insurance_withdrawal(&mut self) {
        // v17 convergence: UpdateInsurancePolicy deleted — live withdrawals are always allowed
        // by the v17 insurance authority model (per-asset oracle profile). This function is now
        // a no-op; the tests that call it will rely on the v17 authority-gated path instead.
        // Matrix row: v17-auth-overhaul (UpdateInsurancePolicy deleted).
    }

    pub fn set_pyth_price(
        &mut self,
        feed: &[u8; 32],
        price: i64,
        expo: i32,
        publish_time: i64,
    ) -> Pubkey {
        self.set_pyth_price_with_conf(feed, price, expo, 1, publish_time)
    }

    pub fn set_pyth_price_with_conf(
        &mut self,
        feed: &[u8; 32],
        price: i64,
        expo: i32,
        conf: u64,
        publish_time: i64,
    ) -> Pubkey {
        let key = Pubkey::new_unique();
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data: make_pyth_data(feed, price, expo, conf, publish_time),
                    owner: oracle_v16::PYTH_RECEIVER_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        key
    }

    pub fn set_switchboard_account(&mut self, key: Pubkey, data: Vec<u8>) -> Pubkey {
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: oracle_v16::SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        key
    }

    pub fn configure_three_leg_hybrid_with_cu(
        &mut self,
        feeds: [[u8; 32]; 3],
        leg0: Pubkey,
        leg1: Pubkey,
        leg2: Pubkey,
        now_slot: u64,
        now_unix_ts: i64,
    ) -> u64 {
        self.try_configure_three_leg_hybrid(feeds, leg0, leg1, leg2, now_slot, now_unix_ts)
            .expect("configure hybrid oracle")
    }

    pub fn try_configure_three_leg_hybrid(
        &mut self,
        feeds: [[u8; 32]; 3],
        leg0: Pubkey,
        leg1: Pubkey,
        leg2: Pubkey,
        now_slot: u64,
        now_unix_ts: i64,
    ) -> Result<u64, String> {
        let observation_sequence = self.control_sequences(0).oracle_observation + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureHybridOracle {
            market_id: 1,
                asset_index: 0,
                now_slot,
                now_unix_ts,
                oracle_leg_count: 3,
                oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
                max_staleness_secs: 60,
                hybrid_soft_stale_slots: 3,
                mark_ewma_halflife_slots: 1,
                mark_min_fee: 0,
                invert: 0,
                unit_scale: 0,
                conf_filter_bps: 500,
                oracle_leg_feeds: feeds,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(leg0, false),
                AccountMeta::new_readonly(leg1, false),
                AccountMeta::new_readonly(leg2, false),
            ],
            &[&self.admin],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_configure_hybrid_with_cu(
        &mut self,
        oracle_leg_count: u8,
        oracle_leg_flags: u8,
        feeds: [[u8; 32]; 3],
        oracle_accounts: &[Pubkey],
        now_slot: u64,
        now_unix_ts: i64,
        invert: u8,
        unit_scale: u32,
        hybrid_soft_stale_slots: u64,
    ) -> Result<u64, String> {
        self.try_configure_hybrid_asset_with_cu(
            0,
            oracle_leg_count,
            oracle_leg_flags,
            feeds,
            oracle_accounts,
            now_slot,
            now_unix_ts,
            invert,
            unit_scale,
            hybrid_soft_stale_slots,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_configure_hybrid_asset_with_cu(
        &mut self,
        asset_index: u16,
        oracle_leg_count: u8,
        oracle_leg_flags: u8,
        feeds: [[u8; 32]; 3],
        oracle_accounts: &[Pubkey],
        now_slot: u64,
        now_unix_ts: i64,
        invert: u8,
        unit_scale: u32,
        hybrid_soft_stale_slots: u64,
    ) -> Result<u64, String> {
        self.try_configure_hybrid_asset_with_conf_filter_cu(
            asset_index,
            oracle_leg_count,
            oracle_leg_flags,
            feeds,
            oracle_accounts,
            now_slot,
            now_unix_ts,
            invert,
            unit_scale,
            hybrid_soft_stale_slots,
            500,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_configure_hybrid_asset_with_conf_filter_cu(
        &mut self,
        asset_index: u16,
        oracle_leg_count: u8,
        oracle_leg_flags: u8,
        feeds: [[u8; 32]; 3],
        oracle_accounts: &[Pubkey],
        now_slot: u64,
        now_unix_ts: i64,
        invert: u8,
        unit_scale: u32,
        hybrid_soft_stale_slots: u64,
        conf_filter_bps: u16,
    ) -> Result<u64, String> {
        let mut accounts = vec![
            AccountMeta::new(self.admin.pubkey(), true),
            AccountMeta::new(self.market, false),
        ];
        accounts.extend(
            oracle_accounts
                .iter()
                .take(oracle_leg_count as usize)
                .copied()
                .map(|key| AccountMeta::new_readonly(key, false)),
        );
        let observation_sequence = self.control_sequences(asset_index).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
        )
        .unwrap()
        .3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureHybridOracle {
                market_id,
                asset_index,
                now_slot,
                now_unix_ts,
                oracle_leg_count,
                oracle_leg_flags,
                max_staleness_secs: 60,
                hybrid_soft_stale_slots,
                mark_ewma_halflife_slots: 1,
                mark_min_fee: 0,
                invert,
                unit_scale,
                conf_filter_bps,
                oracle_leg_feeds: feeds,
                observation_sequence,
            },
            accounts,
            &[&self.admin],
        )
    }

    pub fn configure_ewma_mark_with_cu(
        &mut self,
        now_slot: u64,
        initial_mark_e6: u64,
        halflife_slots: u64,
        mark_min_fee: u64,
    ) -> u64 {
        let observation_sequence = self.control_sequences(0).oracle_observation + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureEwmaMark {
            market_id: 1,
                asset_index: 0,
                now_slot,
                initial_mark_e6,
                mark_ewma_halflife_slots: halflife_slots,
                mark_min_fee,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure ewma_mark mark")
    }

    pub fn push_ewma_mark_with_cu(&mut self, now_slot: u64, mark_e6: u64) -> u64 {
        let observation_sequence = self.control_sequences(0).oracle_observation + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushEwmaMark {
            market_id: 1,
                asset_index: 0,
                now_slot,
                mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push ewma_mark mark")
    }

    pub fn configure_auth_mark_with_cu(&mut self, now_slot: u64, initial_mark_e6: u64) -> u64 {
        let observation_sequence = self.control_sequences(0).oracle_observation + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
            market_id: 1,
                asset_index: 0,
                now_slot,
                initial_mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure auth mark")
    }

    pub fn push_auth_mark_with_cu(&mut self, now_slot: u64, mark_e6: u64) -> u64 {
        let observation_sequence = self.control_sequences(0).oracle_observation + 1;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
            market_id: 1,
                asset_index: 0,
                now_slot,
                mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push auth mark")
    }

    pub fn configure_auth_mark_for_asset_as_admin(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        initial_mark_e6: u64,
    ) -> u64 {
        let observation_sequence = self.control_sequences(asset_index).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
                market_id,
                asset_index,
                now_slot,
                initial_mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure auth mark for asset as admin")
    }

    pub fn push_auth_mark_for_asset_as_admin(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        mark_e6: u64,
    ) -> u64 {
        let observation_sequence = self.control_sequences(asset_index).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
                market_id,
                asset_index,
                now_slot,
                mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push auth mark for asset as admin")
    }

    pub fn configure_auth_mark_for_asset_with_authority(
        &mut self,
        asset_index: u16,
        authority: &Keypair,
        now_slot: u64,
        initial_mark_e6: u64,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        let observation_sequence = self.control_sequences(asset_index).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
                market_id,
                asset_index,
                now_slot,
                initial_mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[authority],
        )
        .expect("configure auth mark for asset")
    }

    pub fn push_auth_mark_for_asset_with_authority(
        &mut self,
        asset_index: u16,
        authority: &Keypair,
        now_slot: u64,
        mark_e6: u64,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        let observation_sequence = self.control_sequences(asset_index).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
                market_id,
                asset_index,
                now_slot,
                mark_e6,
                observation_sequence,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[authority],
        )
        .expect("push auth mark for asset")
    }

    pub fn resolve_stale_permissionless_with_cu(&mut self, now_slot: u64) -> u64 {
        self.svm.warp_to_slot(now_slot);
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ResolveStalePermissionless { now_slot },
            vec![AccountMeta::new(self.market, false)],
            &[],
        )
        .expect("resolve stale permissionless")
    }

    pub fn close_resolved(&mut self, owner: &Keypair, portfolio: Pubkey) -> Pubkey {
        self.close_resolved_with_cu(owner, portfolio).0
    }

    pub fn close_resolved_with_cu(&mut self, owner: &Keypair, portfolio: Pubkey) -> (Pubkey, u64) {
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
        let cu = self
            .send(
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
                    AccountMeta::new_readonly(nft_registry_pda(&self.market), false),
                ],
                &[],
            )
            .expect("close resolved");
        (dest, cu)
    }

    pub fn top_up_insurance(&mut self, amount: u128) -> Pubkey {
        self.top_up_insurance_with_cu(amount).0
    }

    pub fn top_up_insurance_domain_with_authority(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
    ) -> Pubkey {
        self.top_up_insurance_domain_with_authority_and_cu(authority, domain, amount)
            .0
    }

    pub fn top_up_backing_bucket(&mut self, domain: u16, amount: u128, expiry_slot: u64) -> Pubkey {
        self.top_up_backing_bucket_with_cu(domain, amount, expiry_slot)
            .0
    }

    pub fn top_up_insurance_from_admin_token_with_cu(&mut self, source: Pubkey, amount: u128) -> u64 {
        let authority_epoch = self.control_sequences((0) as u16).authority_epoch;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { market_id: 1,
                intent_id: next_intent_id(),
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("top up insurance from admin token")
    }

    pub fn top_up_backing_bucket_from_admin_token_with_cu(
        &mut self,
        source: Pubkey,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        let authority_epoch = self.control_sequences(((domain as usize) / 2) as u16).authority_epoch;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                intent_id: next_intent_id(),
                market_id,
                domain,
                amount,
                expiry_slot,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&self.admin],
        )
        .expect("top up backing bucket from admin token")
    }

    pub fn top_up_insurance_with_cu(&mut self, amount: u128) -> (Pubkey, u64) {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, self.admin.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch = self.control_sequences((0) as u16).authority_epoch;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { market_id: 1,
                intent_id: next_intent_id(),
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("top up insurance");
        (source, cu)
    }

    pub fn top_up_insurance_with_ledger_with_cu(
        &mut self,
        ledger: Pubkey,
        amount: u128,
    ) -> (Pubkey, u64) {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, self.admin.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch = self.control_sequences((0) as u16).authority_epoch;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { market_id: 1,
                intent_id: next_intent_id(),
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
            ],
            &[&self.admin],
        )
        .expect("top up insurance with ledger");
        (source, cu)
    }

    pub fn top_up_insurance_domain_with_authority_and_cu(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
    ) -> (Pubkey, u64) {
        self.ensure_signer_account(authority.pubkey());
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, authority.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch = self.control_sequences(((domain as usize) / 2) as u16).authority_epoch;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsuranceDomain { market_id: market_id,
                intent_id: next_intent_id(),
                domain,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[authority],
        )
        .expect("top up domain insurance");
        (source, cu)
    }

    pub fn top_up_backing_bucket_with_cu(
        &mut self,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> (Pubkey, u64) {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, self.admin.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch = self.control_sequences(((domain as usize) / 2) as u16).authority_epoch;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                intent_id: next_intent_id(),
                market_id,
                domain,
                amount,
                expiry_slot,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&self.admin],
        )
        .expect("top up backing bucket");
        (source, cu)
    }

    pub fn top_up_backing_bucket_with_ledger_with_cu(
        &mut self,
        ledger: Pubkey,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> (Pubkey, u64) {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, self.admin.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch = self.control_sequences(((domain as usize) / 2) as u16).authority_epoch;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                intent_id: next_intent_id(),
                market_id,
                domain,
                amount,
                expiry_slot,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&self.admin],
        )
        .expect("top up backing bucket with ledger");
        (source, cu)
    }

    pub fn top_up_backing_bucket_with_authority(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> Pubkey {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        self.ensure_signer_account(authority.pubkey());
        let source = self.token_account(authority.pubkey(), amount as u64);
        let authority_epoch = self.control_sequences(((domain as usize) / 2) as u16).authority_epoch;
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                intent_id: next_intent_id(),
                market_id,
                domain,
                amount,
                expiry_slot,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[authority],
        )
        .expect("top up backing bucket with authority");
        source
    }

    pub fn withdraw_insurance_with_cu(&mut self, amount: u128) -> (Pubkey, u64) {
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
        let authority_epoch =
            self.insurance_withdraw_authority_epoch(0, &self.admin.pubkey());
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            // v17 convergence: WithdrawInsuranceLimited renamed to WithdrawInsurance.
            // v17 convergence: WithdrawInsuranceLimited deleted. v17 live insurance withdrawal
            // is WithdrawInsuranceAsset { asset_index } gated by per-asset insurance_authority
            // (set to marketauth = admin on market init). Callers must fund the per-asset domain
            // budget via TopUpInsuranceDomain before calling this helper.
            // Matrix row: v17-auth-overhaul (WithdrawInsuranceLimited → WithdrawInsuranceAsset).
            ProgInstruction::WithdrawInsuranceAsset {
            market_id: 1,
                asset_index: 0,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("withdraw insurance");
        (dest, cu)
    }

    pub fn withdraw_insurance_domain_to_admin_token_with_cu(
        &mut self,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        // v17 convergence: WithdrawInsuranceDomain { domain } removed. Use
        // WithdrawInsuranceAsset { asset_index = domain/2 } for the long-domain case.
        // Signed by admin (marketauth); works for asset 0 and for asset N when
        // insurance_authority is zero (see D-STAKE-1 guard). For non-zero insurance_authority
        // assets use withdraw_insurance_asset_with_authority_cu.
        // Matrix row: v17-auth-overhaul (domain-indexed insurance → per-asset-indexed).
        let admin_clone = self.admin.insecure_clone();
        self.withdraw_insurance_asset_with_authority_cu(&admin_clone, dest, domain / 2, amount)
    }

    /// Try to withdraw insurance for an asset; creates an internal dest token account.
    /// Returns Ok((dest, cu)) on success, Err(String) on rejection.
    pub fn try_withdraw_insurance_asset_with_authority(
        &mut self,
        authority: &Keypair,
        asset_index: u16,
        amount: u128,
    ) -> Result<(Pubkey, u64), String> {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, authority.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let authority_epoch =
            self.insurance_withdraw_authority_epoch(asset_index, &authority.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                market_id,
                asset_index,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[authority],
        )?;
        Ok((dest, cu))
    }

    pub fn withdraw_insurance_asset_with_authority_cu(
        &mut self,
        authority: &Keypair,
        dest: Pubkey,
        asset_index: u16,
        amount: u128,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        let authority_epoch =
            self.insurance_withdraw_authority_epoch(asset_index, &authority.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, asset_index as usize).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                market_id,
                asset_index,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[authority],
        )
        .expect("withdraw insurance asset")
    }

    pub fn withdraw_backing_bucket_to_admin_token_with_cu(
        &mut self,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        let authority_epoch = self.backing_withdraw_authority_epoch(domain, &self.admin.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { market_id: market_id,
                domain,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
            ],
            &[&self.admin],
        )
        .expect("withdraw backing bucket to admin token")
    }

    pub fn try_withdraw_backing_bucket_to_admin_token_with_cu(
        &mut self,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> Result<u64, String> {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        let authority_epoch = self.backing_withdraw_authority_epoch(domain, &self.admin.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { market_id: market_id,
                domain,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
            ],
            &[&self.admin],
        )
    }

    /// FIX (upstream #395, F-3 / D-STAKE-1 guard): once a domain's
    /// `backing_bucket_authority` is bound to a non-zero authority (always
    /// true for an activated asset), `marketauth`'s admin shutdown-drain
    /// bypass is blocked -- only the bound `backing_bucket_authority` itself
    /// may withdraw, even after shutdown. `withdraw_backing_bucket_to_admin_token_with_cu`
    /// above (signed by `self.admin`) only remains valid for domains whose
    /// authority was never separately bound; use this variant when the
    /// domain's backing_bucket_authority is a distinct signer.
    pub fn withdraw_backing_bucket_with_authority_cu(
        &mut self,
        authority: &Keypair,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        self.ensure_signer_account(authority.pubkey());
        let authority_epoch = self.backing_withdraw_authority_epoch(domain, &authority.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { market_id: market_id,
                domain,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ledger, false),
            ],
            &[authority],
        )
        .expect("withdraw backing bucket with authority")
    }

    pub fn sync_backing_domain_ledger_with_cu(&mut self, ledger: Pubkey, domain: u16) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SyncBackingDomainLedger { domain },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(ledger, false),
            ],
            &[&self.admin],
        )
        .expect("sync backing domain ledger")
    }

    pub fn withdraw_backing_bucket_earnings_to_admin_token_with_cu(
        &mut self,
        ledger: Pubkey,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        let authority_epoch = self.backing_withdraw_authority_epoch(domain, &self.admin.pubkey());
        let market_id = state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, (domain as usize) / 2).unwrap().3;
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucketEarnings { market_id: market_id,
                domain,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(ledger, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&self.admin],
        )
        .expect("withdraw backing bucket earnings")
    }

    pub fn sync_insurance_ledger_with_cu(&mut self, ledger: Pubkey) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SyncInsuranceLedger,
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(ledger, false),
            ],
            &[&self.admin],
        )
        .expect("sync insurance ledger")
    }

    pub fn try_withdraw_insurance_domain_with_authority(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
    ) -> Result<(Pubkey, u64), String> {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, authority.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        // v17 convergence: WithdrawInsuranceDomain { domain } removed. Use
        // WithdrawInsuranceAsset { asset_index = domain/2 } — tests that pass odd domains
        // will reach asset_index = domain/2 which maps to the same asset, not the short side.
        // Callers that expect rejection (.is_err()) remain correct since the auth check is
        // per-asset regardless of side. Matrix row: v17-auth-overhaul.
        let authority_epoch =
            self.insurance_withdraw_authority_epoch(domain / 2, &authority.pubkey());
        let market_id = state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            (domain / 2) as usize,
        )
        .unwrap()
        .3;
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                market_id,
                asset_index: domain / 2,
                amount,
                authority_epoch,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[authority],
        )?;
        Ok((dest, cu))
    }

    pub fn withdraw_terminal_insurance_with_authority(
        &mut self,
        authority: &Keypair,
        amount: u128,
    ) -> (Pubkey, u64) {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, authority.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsurance { amount },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[authority],
        )
        .expect("withdraw terminal insurance");
        (dest, cu)
    }

    pub fn token_amount(&self, key: Pubkey) -> u64 {
        let account = self.svm.get_account(&key).expect("token account");
        TokenAccount::unpack(&account.data).unwrap().amount
    }

    pub fn convert_released_pnl_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> u64 {
        let (portfolio_id, _, position_epoch) = self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::ConvertReleasedPnl {
                portfolio_id,
                position_epoch,
                amount,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("convert released pnl")
    }

    pub fn cure_and_cancel_close_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        source: Pubkey,
        amount: u128,
    ) -> u64 {
        let (portfolio_id, _, position_epoch) = self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::CureAndCancelClose {
                portfolio_id,
                position_epoch,
                optional_deposit: amount,
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
        .expect("cure and cancel close")
    }

    pub fn forfeit_recovery_leg_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        asset_index: u16,
        b_loss_atom_budget: u128,
    ) -> u64 {
        let (portfolio_id, _, position_epoch) = self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::ForfeitRecoveryLeg {
                portfolio_id,
                position_epoch,
                asset_index,
                b_loss_atom_budget,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("forfeit recovery leg")
    }

    pub fn rebalance_reduce_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        asset_index: u16,
        reduce_q: u128,
    ) -> u64 {
        let (portfolio_id, _, position_epoch) = self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::RebalanceReduce {
                portfolio_id,
                position_epoch,
                asset_index,
                reduce_q,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("rebalance reduce")
    }

    pub fn finalize_reset_side_with_cu(&mut self, asset_index: u16, side: u8) -> u64 {
        self.send(
            ProgInstruction::FinalizeResetSide { asset_index, side },
            vec![AccountMeta::new(self.market, false)],
            &[],
        )
        .expect("finalize reset side")
    }

    pub fn claim_resolved_payout_topup_with_cu(
        &mut self,
        owner: Pubkey,
        portfolio: Pubkey,
        dest: Pubkey,
    ) -> u64 {
        self.send(
            ProgInstruction::ClaimResolvedPayoutTopup,
            vec![
                AccountMeta::new_readonly(owner, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&self.market), false),
            ],
            &[],
        )
        .expect("claim resolved payout topup")
    }

    pub fn refine_resolved_unreceipted_bound_rejected(&mut self, decrease_num: u128) {
        // #313: the external RefineResolvedUnreceiptedBound is disabled — it must be rejected.
        let r = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::RefineResolvedUnreceiptedBound { decrease_num },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        );
        assert!(
            r.is_err(),
            "RefineResolvedUnreceiptedBound must be rejected (disabled, #313)"
        );
    }

    pub fn crank(&mut self, portfolio: Pubkey, ix: ProgInstruction) -> u64 {
        self.send(
            ix,
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[],
        )
        .expect("crank")
    }

    pub fn crank_with_oracle_tail(
        &mut self,
        portfolio: Pubkey,
        ix: ProgInstruction,
        oracle_accounts: &[Pubkey],
    ) -> u64 {
        let mut accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(portfolio, false),
        ];
        accounts.extend(
            oracle_accounts
                .iter()
                .copied()
                .map(|key| AccountMeta::new_readonly(key, false)),
        );
        self.send(ix, accounts, &[])
            .expect("crank with oracle tail")
    }

    pub fn try_force_close_abandoned_asset_with_cu(
        &mut self,
        cranker: &Keypair,
        account_a: Pubkey,
        account_b: Pubkey,
        asset_index: u16,
        now_slot: u64,
        close_q: u128,
    ) -> Result<u64, String> {
        self.ensure_signer_account(cranker.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ForceCloseAbandonedAsset {
                asset_index,
                now_slot,
                close_q,
            },
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            &[cranker],
        )
    }

    pub fn force_close_abandoned_asset_with_cu(
        &mut self,
        cranker: &Keypair,
        account_a: Pubkey,
        account_b: Pubkey,
        asset_index: u16,
        now_slot: u64,
        close_q: u128,
    ) -> u64 {
        self.try_force_close_abandoned_asset_with_cu(
            cranker,
            account_a,
            account_b,
            asset_index,
            now_slot,
            close_q,
        )
        .expect("force close abandoned asset")
    }

    pub fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        extra_signers: &[&Keypair],
    ) -> Result<u64, String> {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ix,
            accounts,
            extra_signers,
        )
    }
}

pub fn send_tx(
    svm: &mut LiteSVM,
    program_id: Pubkey,
    payer: &Keypair,
    ix: ProgInstruction,
    accounts: Vec<AccountMeta>,
    extra_signers: &[&Keypair],
) -> Result<u64, String> {
    let touched: Vec<Pubkey> = accounts.iter().map(|m| m.pubkey).collect();
    let instruction = Instruction {
        program_id,
        accounts,
        data: ix.encode(),
    };
    let mut signer_refs = Vec::with_capacity(1 + extra_signers.len());
    signer_refs.push(payer);
    signer_refs.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[heap_ix(), cu_ix(), instruction],
        Some(&payer.pubkey()),
        &signer_refs,
        svm.latest_blockhash(),
    );
    let r = svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"));
    if r.is_ok() {
        gc_zero_lamport_accounts(svm, &touched);
    }
    log_error_sites(&r);
    r
}

/// Debug aid for instrumented builds: with INDEP_ERR_SITES=1, print the `sol_log_64` error-site
/// lines ("Program log: 0x<tag>, 0x<line>, ...") of a failed transaction.
pub fn log_error_sites(r: &Result<u64, String>) {
    if let Err(e) = r {
        if std::env::var("INDEP_ERR_SITES").map_or(false, |v| v == "1") {
            let sites: Vec<String> = e
                .split("\"")
                .filter(|l| l.starts_with("Program log: 0x"))
                .map(|l| {
                    let v: Vec<u64> = l["Program log: ".len()..]
                        .split(", ")
                        .filter_map(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
                        .collect();
                    if v.first() == Some(&0xB1) { format!("b1{:?}", &v[1..]) } else { format!("{:x}@{}", v.first().copied().unwrap_or(0), v.get(1).copied().unwrap_or(0)) }
                })
                .collect();
            eprintln!("ERR-SITES {:?}", sites);
        }
    }
}

pub fn send_raw_tx(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction: Instruction,
    extra_signers: &[&Keypair],
) -> Result<u64, String> {
    let touched: Vec<Pubkey> = instruction.accounts.iter().map(|m| m.pubkey).collect();
    let mut signer_refs = Vec::with_capacity(1 + extra_signers.len());
    signer_refs.push(payer);
    signer_refs.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[heap_ix(), cu_ix(), instruction],
        Some(&payer.pubkey()),
        &signer_refs,
        svm.latest_blockhash(),
    );
    let r = svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"));
    if r.is_ok() {
        gc_zero_lamport_accounts(svm, &touched);
    }
    log_error_sites(&r);
    r
}

/// Runtime parity (coordinator, C-4b): after a transaction, the real runtime DELETES every
/// account left with 0 lamports; LiteSVM 0.1 keeps it (data + owner intact). Emulate the
/// deletion for every account the transaction touched. INDEP_NO_GC=1 disables it (the
/// LiteSVM-only behaviour, used as a negative control).
pub fn gc_zero_lamport_accounts(svm: &mut LiteSVM, touched: &[Pubkey]) {
    if std::env::var("INDEP_NO_GC").map_or(false, |v| v == "1") {
        return;
    }
    for k in touched {
        if let Some(a) = svm.get_account(k) {
            if a.lamports == 0 && !a.executable && (!a.data.is_empty() || a.owner != Pubkey::default()) {
                let _ = svm.set_account(*k, Account::default());
            }
        }
    }
}

pub fn assert_cu_within(label: &str, cu: u64, limit: u64) {
    assert!(
        cu <= limit,
        "{label} consumed {cu} CU, above the {limit} CU guardrail"
    );
}
pub fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
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
/// Refresh crank on `portfolio`, returning the raw result rather than panicking.
pub fn try_refresh(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64) -> Result<u64, String> {
    let payer = env.payer.pubkey();
    let market = env.market;
    env.send(
ProgInstruction::PermissionlessCrank {
            now_slot: now_slot,
            observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
        },
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(market, false),
            AccountMeta::new(portfolio, false),
        ],
        &[],
    )
}

pub fn try_expire_backing_bucket(env: &mut V16CuEnv, domain: u16) -> Result<u64, String> {
    let market = env.market;
    env.send(
        ProgInstruction::ExpireBackingBucket { domain },
        vec![AccountMeta::new(market, false)],
        &[],
    )
}

/// GATE-2 FIX (bounded_market_catchup_only, cbaf7c6f) fixture helper: pass-1's own
/// single-segment accrual is capped at `max_accrual_dt_slots` per crank call, and the
/// guard now refuses to let a crank reach the unified dispatch (and whatever
/// settlement/liquidation/lock check that dispatch would attempt) until asset 0 is
/// GENUINELY caught up to `now_slot`. Crucially, if the dispatch-reached call itself
/// REVERTS (as every call in this test does, once caught up, against the lapsed
/// backing bucket), the whole transaction rolls back -- including that call's own
/// pass-1 accrual -- so asset 0's `slot_last` can never advance past `target_slot - 1`
/// via a reverting call. This submits successful, dispatch-free catch-up crank calls
/// (bounded, fresh blockhash each time, mirroring a real keeper) until asset 0 sits
/// EXACTLY one segment short of `target_slot`, leaving the caller's own next crank
/// call (already written in the test) as the one that completes catch-up and is the
/// FIRST to reach dispatch -- preserving the original "first post-lapse crank reverts"
/// shape instead of silently absorbing it into an early return.
pub fn catch_up_asset0_to_one_short_of(env: &mut V16CuEnv, portfolio: Pubkey, target_slot: u64) {
    loop {
        let (_, g) = env.market_state();
        let slot_last = g.assets[0].slot_last;
        assert!(
            slot_last < target_slot,
            "catch-up target already reached or overshot: slot_last={slot_last} target={target_slot}"
        );
        if slot_last + 1 >= target_slot {
            break;
        }
        env.svm.expire_blockhash();
        try_refresh(env, portfolio, target_slot)
            .expect("bounded catch-up crank (still short of now_slot) must not revert");
    }
    // Leave a fresh blockhash for the caller's own next call, which is byte-identical
    // in shape to the calls this loop just sent.
    env.svm.expire_blockhash();
}

pub fn custom_code(err: &str) -> Option<u32> {
    let marker = "Custom(";
    let start = err.find(marker)? + marker.len();
    let end = start + err[start..].find(')')?;
    err[start..end].parse().ok()
}
