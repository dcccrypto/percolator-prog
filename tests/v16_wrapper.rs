// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
use percolator::{
    AssetLifecycleV16, AssetStateV16Account, BackingBucketStatusV16, CloseProgressLedgerV16,
    EngineAssetSlotV16Account, MarketGroupV16HeaderAccount, MarketModeV16,
    PermissionlessRecoveryReasonV16, PortfolioAccountV16Account,
    PortfolioLegV16, ResolvedPayoutLedgerV16, ResolvedPayoutReceiptV16, SideModeV16, SideV16,
    V16Config, BOUND_SCALE, POS_SCALE,
};
use percolator_prog::{
    constants::{
        ASSET_ORACLE_WRAPPER_LEN, DEFAULT_MARKET_SLOT_CAPACITY, HEADER_LEN, MARKET_ACCOUNT_LEN,
        MARKET_ASSET_SLOT_LEN, MARKET_GROUP_LEN, ORACLE_LEG_CAP, ORACLE_LEG_FLAG_DIVIDE_LEG2,
        ORACLE_LEG_FLAG_DIVIDE_LEG3, ORACLE_MODE_AUTH_MARK, ORACLE_MODE_EWMA_MARK,
        ORACLE_MODE_HYBRID_AFTER_HOURS, ORACLE_MODE_MANUAL, PORTFOLIO_ACCOUNT_LEN,
        PORTFOLIO_MATCHER_CONFIG_LEN, PORTFOLIO_SOURCE_DOMAIN_LEN, PORTFOLIO_STATE_LEN,
        WRAPPER_CONFIG_LEN,
    },
    ix::Instruction,
    oracle_v16, policy_v16, processor,
    processor::{ASSET_AUTH_BACKING_BUCKET, ASSET_AUTH_INSURANCE, ASSET_AUTH_INSURANCE_OPERATOR,
                ASSET_AUTH_ORACLE, ASSET_AUTH_ADMIN},
    state,
    state::{AssetOracleProfileV16, MarketGroupV16, PortfolioAccountV16},
};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, program_option::COption,
    program_pack::Pack, pubkey::Pubkey,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

struct TestAccount {
    key: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data: Vec<u8>,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
}

impl TestAccount {
    fn new(key: Pubkey, owner: Pubkey, data_len: usize) -> Self {
        Self {
            key,
            owner,
            lamports: 1_000_000,
            data: vec![0u8; data_len],
            is_signer: false,
            is_writable: false,
            executable: false,
        }
    }

    fn new_with_data(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> Self {
        Self {
            key,
            owner,
            lamports: 1_000_000,
            data,
            is_signer: false,
            is_writable: false,
            executable: false,
        }
    }

    fn signer(mut self) -> Self {
        self.is_signer = true;
        self
    }

    fn writable(mut self) -> Self {
        self.is_writable = true;
        self
    }

    fn executable(mut self) -> Self {
        self.is_writable = false;
        self.executable = true;
        self
    }

    fn to_info<'a>(&'a mut self) -> AccountInfo<'a> {
        AccountInfo::new(
            &self.key,
            self.is_signer,
            self.is_writable,
            &mut self.lamports,
            &mut self.data,
            &self.owner,
            self.executable,
            0,
        )
    }
}

fn program_id() -> Pubkey {
    percolator_prog::id()
}

fn active_bitmap_with(indices: &[usize]) -> percolator::V16ActiveBitmap {
    let mut bitmap = percolator::active_bitmap_empty();
    for &idx in indices {
        percolator::kani_active_bitmap_set(&mut bitmap, idx).unwrap();
    }
    bitmap
}

fn active_leg_for_asset(
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

fn has_active_leg_for_asset(account: &PortfolioAccountV16, asset_index: usize) -> bool {
    account
        .legs
        .iter()
        .any(|leg| leg.active && leg.asset_index as usize == asset_index)
}

// ---------------------------------------------------------------------------
// E3 (upstream engine #92 / this fork's percolator @ 052baab9+c87a8978,
// "liquidation min-fee chunking: engine-selected size + config-only fee")
// fixture-repair reference reimplementations. These mirror engine formulas
// EXACTLY, formula-for-formula, so expected liquidation-fee-split values
// below are DERIVED from the same arithmetic the engine runs, not hardcoded
// from an observed run:
//   - `accrue_asset_to_not_atomic` (percolator src/v16.rs:10427 area): a
//     single accrual step clamps the price move to at most
//     `old_price * max_price_move_bps_per_slot * segment_dt / MAX_MARGIN_BPS`
//     (segment_dt capped at `max_accrual_dt_slots`) -- see
//     `clamped_price_move_ref` below.
//   - `liquidation_risk_notional_ceil`/`liquidation_fee_for_close`
//     (percolator src/v16.rs:16057+): fee = ceil(ceil(close_q*price/POS_SCALE)
//     * liquidation_fee_bps / MAX_MARGIN_BPS), clamped to
//     [min_liquidation_abs, liquidation_fee_cap] -- see `ceil_liquidation_fee_ref`.
//   - `maintenance_cranker_reward` (src/v16_program.rs:15423): cranker share
//     floors (`fee_share_floor_ref`), never ceils -- the insurance remainder
//     is `fee - reward`, never the other way around.
// ---------------------------------------------------------------------------
const MAX_MARGIN_BPS_REF: u128 = 10_000;

/// Mirrors `accrue_asset_to_not_atomic`'s linear price-move budget for ONE
/// accrual step starting from `old_price`, clamped to at most
/// `max_accrual_dt_slots` of elapsed time. Additive (not compounding): this
/// is the max a SINGLE crank/liquidate call can move price by, from a fresh
/// (never-yet-accrued-this-target) baseline.
fn clamped_price_after_one_step_ref(
    old_price: u64,
    max_price_move_bps_per_slot: u64,
    elapsed_slots: u64,
    max_accrual_dt_slots: u64,
) -> u64 {
    let segment_dt = elapsed_slots.min(max_accrual_dt_slots) as u128;
    let max_delta = (old_price as u128 * max_price_move_bps_per_slot as u128 * segment_dt)
        / MAX_MARGIN_BPS_REF;
    old_price + max_delta as u64
}

fn ceil_notional_ref(size_q: u128, price: u64) -> u128 {
    if size_q == 0 || price == 0 {
        return 0;
    }
    let product = size_q * price as u128;
    let q = product / POS_SCALE;
    let r = product % POS_SCALE;
    q + u128::from(r != 0)
}

/// Mirrors `liquidation_fee_for_close`/`liquidation_risk_notional_ceil`
/// exactly: ceil(ceil(close_q*price/POS_SCALE) * fee_bps / MAX_MARGIN_BPS),
/// clamped to [min_liquidation_abs, liquidation_fee_cap].
fn ceil_liquidation_fee_ref(
    close_q: u128,
    price: u64,
    fee_bps: u64,
    min_liquidation_abs: u128,
    liquidation_fee_cap: u128,
) -> u128 {
    let notional = ceil_notional_ref(close_q, price);
    let product = notional * fee_bps as u128;
    let q = product / MAX_MARGIN_BPS_REF;
    let r = product % MAX_MARGIN_BPS_REF;
    let raw_fee = q + u128::from(r != 0);
    raw_fee.max(min_liquidation_abs).min(liquidation_fee_cap)
}

/// Mirrors `maintenance_cranker_reward`/`fee_share_floor` exactly: FLOOR
/// division, never ceiling -- the cranker's share must never exceed its
/// nominal bps of the charged fee.
fn fee_share_floor_ref(amount: u128, share_bps: u16) -> u128 {
    (amount * share_bps as u128) / MAX_MARGIN_BPS_REF
}

fn signer() -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0).signer()
}

fn market_account() -> TestAccount {
    market_account_with_capacity(percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize)
}

fn market_account_with_capacity(capacity: usize) -> TestAccount {
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::market_account_len_for_capacity(capacity).unwrap(),
    )
    .writable()
}

fn portfolio_account() -> TestAccount {
    portfolio_account_for_market_slots(
        percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize,
    )
}

fn portfolio_account_for_market_slots(max_market_slots: usize) -> TestAccount {
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::portfolio_account_len_for_market_slots(max_market_slots).unwrap(),
    )
    .writable()
}

fn backing_domain_ledger_account() -> TestAccount {
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::backing_domain_ledger_account_len(),
    )
    .writable()
}

/// The CANONICAL backing-domain ledger for `market`/`domain`, pre-created.
///
/// #433: `TopUpBackingBucket` now pins this account to its PDA and `WithdrawBackingBucket`
/// requires it. `backing_domain_ledger_account()` above returns a RANDOM address, which the
/// pin correctly refuses — that helper is for substitution tests only.
///
/// Pre-created (non-empty data, program-owned) so the handler's `create_pda_account` path is
/// skipped: this harness executes no CPI, so a genuinely absent ledger could not be created
/// here even though it can be on chain.
fn canonical_backing_ledger_account(market: &TestAccount, domain: u16) -> TestAccount {
    let (key, _) = state::derive_lp_backing_ledger(&program_id(), &market.key, domain);
    TestAccount::new(key, program_id(), state::backing_domain_ledger_account_len()).writable()
}

/// System program, passed to `TopUpBackingBucket` so it CAN create the ledger. Never invoked
/// in this harness, because the ledger above is pre-created.
fn system_program_account() -> TestAccount {
    TestAccount::new(solana_program::system_program::ID, Pubkey::default(), 0).executable()
}

fn insurance_ledger_account() -> TestAccount {
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::insurance_ledger_account_len(),
    )
    .writable()
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
    make_token_data_with_controls(mint, owner, amount, COption::None, COption::None)
}

fn make_token_data_with_state(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    state: AccountState,
) -> Vec<u8> {
    make_token_data_full(mint, owner, amount, COption::None, COption::None, state)
}

fn make_token_data_with_controls(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: COption<Pubkey>,
    close_authority: COption<Pubkey>,
) -> Vec<u8> {
    make_token_data_full(
        mint,
        owner,
        amount,
        delegate,
        close_authority,
        AccountState::Initialized,
    )
}

fn make_token_data_full(
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: COption<Pubkey>,
    close_authority: COption<Pubkey>,
    state: AccountState,
) -> Vec<u8> {
    let delegated_amount = if delegate.is_some() { amount } else { 0 };
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate,
            state,
            is_native: COption::None,
            delegated_amount,
            close_authority,
        },
        &mut data,
    )
    .unwrap();
    data
}

fn mint_account() -> TestAccount {
    TestAccount::new_with_data(Pubkey::new_unique(), spl_token::ID, make_mint_data())
}

fn invalid_mint_account() -> TestAccount {
    TestAccount::new_with_data(Pubkey::new_unique(), Pubkey::new_unique(), make_mint_data())
}

fn user_token_account(owner: Pubkey, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data(mint, owner, amount),
    )
    .writable()
}

fn user_token_account_with_state(
    owner: Pubkey,
    mint: Pubkey,
    amount: u64,
    state: AccountState,
) -> TestAccount {
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data_with_state(mint, owner, amount, state),
    )
    .writable()
}

fn vault_authority(market: &TestAccount) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", market.key.as_ref()], &program_id()).0
}

fn vault_token_account(market: &TestAccount, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        canonical_vault_ata(&vault_authority(market), &mint),
        spl_token::ID,
        make_token_data(mint, vault_authority(market), amount),
    )
    .writable()
}

fn vault_token_account_with_state(
    market: &TestAccount,
    mint: Pubkey,
    amount: u64,
    state: AccountState,
) -> TestAccount {
    TestAccount::new_with_data(
        canonical_vault_ata(&vault_authority(market), &mint),
        spl_token::ID,
        make_token_data_with_state(mint, vault_authority(market), amount, state),
    )
    .writable()
}

fn vault_token_account_with_controls(
    market: &TestAccount,
    mint: Pubkey,
    amount: u64,
    delegate: COption<Pubkey>,
    close_authority: COption<Pubkey>,
) -> TestAccount {
    TestAccount::new_with_data(
        canonical_vault_ata(&vault_authority(market), &mint),
        spl_token::ID,
        make_token_data_with_controls(
            mint,
            vault_authority(market),
            amount,
            delegate,
            close_authority,
        ),
    )
    .writable()
}

fn vault_authority_account(market: &TestAccount) -> TestAccount {
    TestAccount::new(vault_authority(market), Pubkey::new_unique(), 0)
}

fn matcher_delegate(
    market: &TestAccount,
    maker: &TestAccount,
    maker_owner: &Pubkey,
    matcher_program: &TestAccount,
    matcher_context: &TestAccount,
) -> Pubkey {
    // v17 derive_matcher_delegate: seeds = ["matcher", market, maker_account, maker_owner,
    // matcher_program, matcher_context].  maker_owner is the wallet that owns the B-side
    // portfolio — it is stored in the portfolio provenance header after InitPortfolio.
    Pubkey::find_program_address(
        &[
            b"matcher",
            market.key.as_ref(),
            maker.key.as_ref(),
            maker_owner.as_ref(),
            matcher_program.key.as_ref(),
            matcher_context.key.as_ref(),
        ],
        &program_id(),
    )
    .0
}

fn matcher_program_account() -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), Pubkey::default(), 0).executable()
}

fn matcher_context_account(matcher_program: &TestAccount) -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), matcher_program.key, 320).writable()
}

fn matcher_delegate_account(
    market: &TestAccount,
    maker: &TestAccount,
    maker_owner: &Pubkey,
    matcher_program: &TestAccount,
    matcher_context: &TestAccount,
) -> TestAccount {
    TestAccount::new(
        matcher_delegate(market, maker, maker_owner, matcher_program, matcher_context),
        Pubkey::default(),
        0,
    )
}

fn write_matcher_return(
    matcher_context: &mut TestAccount,
    exec_price_e6: u64,
    exec_size: i128,
    req_id: u64,
    lp_account_id: u64,
    asset_index: u16,
    oracle_price_e6: u64,
) {
    matcher_context.data[0..4].copy_from_slice(&3u32.to_le_bytes());
    matcher_context.data[4..8].copy_from_slice(&3u32.to_le_bytes());
    matcher_context.data[8..16].copy_from_slice(&exec_price_e6.to_le_bytes());
    matcher_context.data[16..32].copy_from_slice(&exec_size.to_le_bytes());
    matcher_context.data[32..40].copy_from_slice(&req_id.to_le_bytes());
    matcher_context.data[40..48].copy_from_slice(&lp_account_id.to_le_bytes());
    matcher_context.data[48..56].copy_from_slice(&oracle_price_e6.to_le_bytes());
    matcher_context.data[56..64].copy_from_slice(&(asset_index as u64).to_le_bytes());
}

fn run_trade_cpi_with_matcher(
    owner_a: &mut TestAccount,
    owner_b: &mut TestAccount,
    market: &mut TestAccount,
    account_a: &mut TestAccount,
    account_b: &mut TestAccount,
    asset_index: u16,
    req_size: i128,
    exec_size: i128,
    exec_price: u64,
    fee_bps: u64,
    limit_price: u64,
) -> Result<(), ProgramError> {
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: derive_matcher_delegate includes maker_owner in the PDA seeds.
    // Read it from account_b's portfolio header (set during InitPortfolio).
    // Fall back to owner_b.key if the portfolio header is not yet initialised.
    let maker_owner_bytes = state::read_portfolio_owner_preflight(&account_b.data)
        .map(|(_, owner)| Pubkey::new_from_array(owner))
        .unwrap_or(owner_b.key);
    let mut delegate =
        matcher_delegate_account(market, account_b, &maker_owner_bytes, &matcher_program, &matcher_context);

    // v17 behavioral change (matrix row 29 + LP-matcher design): handle_trade_cpi requires the
    // B-side LP to have called SetMatcherConfig first, registering the specific (matcher_prog,
    // matcher_ctx, delegate) triple.  Without this, matcher_tail_start_or_verify_lp_config
    // returns Unauthorized.  Register now; the SetMatcherConfig call is idempotent per trade.
    run_ix(
        Instruction::SetMatcherConfig { enabled: 1 },
        &mut [
            owner_b,
            market,
            account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )?;

    let (_, group) = state::read_market(&market.data).unwrap();
    let req_id = state::next_market_matcher_req_id(&market.data).unwrap();
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(
        &mut matcher_context,
        exec_price,
        exec_size,
        req_id,
        lp_account_id,
        asset_index,
        group.assets[asset_index as usize].effective_price,
    );
    // Account order matches handle_trade_cpi: [signer_a, market, account_a, account_b,
    // matcher_prog, matcher_ctx, matcher_delegate]. owner_b is the B-side signer but is NOT
    // passed as a separate account; account_b must already be writable.
    run_ix(
        Instruction::TradeCpi {
            asset_index,
            size_q: req_size,
            fee_bps,
            limit_price,
        },
        &mut [
            owner_a,
            market,
            account_a,
            account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )
}

fn token_program_account() -> TestAccount {
    TestAccount::new(spl_token::ID, Pubkey::default(), 0).executable()
}

fn non_executable_token_program_account() -> TestAccount {
    TestAccount::new(spl_token::ID, Pubkey::default(), 0)
}

fn make_pyth(feed_id: &[u8; 32], price: i64, expo: i32, conf: u64, publish_time: i64) -> Vec<u8> {
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

fn pyth_account(
    feed_id: &[u8; 32],
    price: i64,
    expo: i32,
    conf: u64,
    publish_time: i64,
) -> TestAccount {
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        oracle_v16::PYTH_RECEIVER_PROGRAM_ID,
        make_pyth(feed_id, price, expo, conf, publish_time),
    )
}

fn switchboard_account(
    key: Pubkey,
    price_e6: u64,
    std_dev_e6: u64,
    publish_time: i64,
) -> TestAccount {
    let mut data = vec![0u8; 3_208];
    data[0..8].copy_from_slice(&[196, 27, 108, 196, 10, 215, 219, 40]);
    data[2_120..2_152].copy_from_slice(&[0x5au8; 32]);
    data[2_215] = 1;
    data[2_216..2_224].copy_from_slice(&publish_time.to_le_bytes());
    let value = (price_e6 as i128) * 1_000_000_000_000i128;
    let std_dev = (std_dev_e6 as i128) * 1_000_000_000_000i128;
    data[2_264..2_280].copy_from_slice(&value.to_le_bytes());
    data[2_280..2_296].copy_from_slice(&std_dev.to_le_bytes());
    data[2_360] = 1;
    data[2_368..2_376].copy_from_slice(&1u64.to_le_bytes());
    TestAccount::new_with_data(
        key,
        oracle_v16::SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID,
        data,
    )
}

fn chainlink_account(key: Pubkey, answer: i128, decimals: u8, publish_time: u32) -> TestAccount {
    let mut data = vec![0u8; 248];
    data[0..8].copy_from_slice(&[96, 179, 69, 66, 128, 129, 73, 117]);
    data[8] = 1;
    data[138] = decimals;
    data[143..147].copy_from_slice(&1u32.to_le_bytes());
    data[148..152].copy_from_slice(&1u32.to_le_bytes());
    data[200..208].copy_from_slice(&1u64.to_le_bytes());
    data[208..212].copy_from_slice(&publish_time.to_le_bytes());
    data[216..232].copy_from_slice(&answer.to_le_bytes());
    TestAccount::new_with_data(key, oracle_v16::CHAINLINK_STORE_PROGRAM_ID, data)
}

/// Pre-taker-only helper name, kept for historical clarity in comments.
/// Taker-only (design §1A) collects exactly ONE side's ceil-rounded fee per
/// fill now, never two — use `taker_only_fee` at every call site instead.
#[allow(dead_code)]
fn two_sided_fee(size_q: u128, price: u64, fee_bps: u64) -> u128 {
    taker_only_fee(size_q, price, fee_bps) * 2
}

/// Expected TOTAL fee credited to `group.insurance` for a single fill under
/// taker-only charging (design §1A): exactly one side's ceil-rounded fee
/// (`checked_fee_bps`'s rounding, mirrored here), since the passive
/// maker/LP side pays nothing.
fn taker_only_fee(size_q: u128, price: u64, fee_bps: u64) -> u128 {
    let notional = size_q * price as u128 / POS_SCALE;
    (notional * fee_bps as u128 + 9_999) / 10_000
}

fn run_ix_data(data: &[u8], accounts: &mut [&mut TestAccount]) -> Result<(), ProgramError> {
    let snapshots: Vec<(u64, Vec<u8>)> = accounts
        .iter()
        .map(|a| (a.lamports, a.data.clone()))
        .collect();
    let result = {
        let infos: Vec<AccountInfo> = accounts.iter_mut().map(|a| a.to_info()).collect();
        processor::process_instruction(&program_id(), &infos, data)
    };
    if result.is_err() {
        for (account, (lamports, data)) in accounts.iter_mut().zip(snapshots) {
            account.lamports = lamports;
            account.data = data;
        }
    }
    result
}

/// FIX W3 (upstream #206, pairs with engine E3 / upstream #92): full-entrypoint,
/// concrete-value companion to
/// `kani_v16_permissionless_crank_rejects_legacy_close_q_fee_bps_wire_payload`
/// (tests/v16_kani.rs) -- proves, via a plain `cargo test` (no CBMC/Kani
/// toolchain required), that `processor::process_instruction` rejects the OLD
/// 53-byte `PermissionlessCrank` payload (tag=5, action=1/Liquidate,
/// asset_index, now_slot, funding_rate_e9, close_q, fee_bps, recovery_reason
/// -- close_q here is 1 atom, the "min-fee chunking" dust value the pre-fix
/// exploit relied on) as InvalidInstructionData. `Instruction::decode` is the
/// first statement of `process_instruction` (unconditional, before any
/// account access), so an empty account slice is safe: decode fails and
/// short-circuits before accounts[0] is ever touched.
#[test]
fn v16_wrapper_permissionless_crank_rejects_w3_legacy_wire_fields() {
    let mut legacy = [0u8; 53];
    legacy[0] = 5; // tag: PermissionlessCrank
    legacy[1] = 1; // action: Liquidate
    legacy[2..4].copy_from_slice(&3u16.to_le_bytes()); // asset_index
    legacy[4..12].copy_from_slice(&10u64.to_le_bytes()); // now_slot
    legacy[12..28].copy_from_slice(&0i128.to_le_bytes()); // funding_rate_e9
    legacy[28..44].copy_from_slice(&1u128.to_le_bytes()); // close_q = 1 atom
    legacy[44..52].copy_from_slice(&0u64.to_le_bytes()); // fee_bps
    legacy[52] = 0; // recovery_reason

    let result = run_ix_data(&legacy, &mut []);
    assert_eq!(result, Err(ProgramError::InvalidInstructionData));
}

fn run_ix(ix: Instruction, accounts: &mut [&mut TestAccount]) -> Result<(), ProgramError> {
    run_ix_data(&ix.encode(), accounts)
}

/// `run_ix` WITHOUT the on-Err snapshot/restore that `run_ix_data` performs.
///
/// WHY THIS EXISTS. `run_ix_data` snapshots `(lamports, data)` for every
/// account before dispatch and RESTORES them whenever the instruction returns
/// `Err` -- before any of the caller's assertions run. That models the real
/// runtime (a failed transaction reverts), but it makes every
/// "rejected-instruction-must-not-mutate-X" assertion written against `run_ix`
/// STRUCTURALLY UNFALSIFIABLE: the harness, not the handler, guarantees the
/// bytes match. Such an assertion passes even against a handler that scribbles
/// over the account and only then errors, so it proves nothing about the code
/// under test.
///
/// This variant hands back exactly what the handler left behind. Assertions
/// written against it are real: they fail if the handler mutates before
/// rejecting.
///
/// WHAT IT DOES AND DOES NOT PROVE. It does NOT claim a mid-handler mutation
/// would be observable on-chain -- it would not; the runtime reverts a failed
/// top-level instruction and a failed CPI alike. What it pins is the handler's
/// FAIL-CLOSED ORDERING: validate fully, then mutate. That discipline is what
/// keeps a future edit (an early write-back, a debit hoisted above its capacity
/// check) from turning a rejection into a partial application the moment the
/// surrounding control flow changes -- e.g. if a caller ever swallows the Err,
/// or if the mutation moves into a path that commits before the check.
///
/// Use `run_ix` for everything else; this is deliberately the exception, not
/// the default.
fn run_ix_no_rollback(
    ix: Instruction,
    accounts: &mut [&mut TestAccount],
) -> Result<(), ProgramError> {
    let infos: Vec<AccountInfo> = accounts.iter_mut().map(|a| a.to_info()).collect();
    processor::process_instruction(&program_id(), &infos, &ix.encode())
}

fn configure_base_ewma_mark(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    now_slot: u64,
    mark_e6: u64,
) {
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot,
            initial_mark_e6: mark_e6,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [admin, market],
    )
    .unwrap();
}

fn push_base_ewma_mark(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    now_slot: u64,
    mark_e6: u64,
) {
    run_ix(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot,
            mark_e6,
        },
        &mut [admin, market],
    )
    .unwrap();
}

fn configure_base_auth_mark(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    now_slot: u64,
    mark_e6: u64,
) {
    run_ix(
        Instruction::ConfigureAuthMark {
            asset_index: 0,
            now_slot,
            initial_mark_e6: mark_e6,
        },
        &mut [admin, market],
    )
    .unwrap();
}

fn push_base_auth_mark(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    now_slot: u64,
    mark_e6: u64,
) {
    run_ix(
        Instruction::PushAuthMark {
            asset_index: 0,
            now_slot,
            mark_e6,
        },
        &mut [admin, market],
    )
    .unwrap();
}

fn default_init_market_ix() -> Instruction {
    Instruction::InitMarket {
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

fn init_market_ix_with(f: impl FnOnce(&mut Instruction)) -> Instruction {
    let mut ix = default_init_market_ix();
    f(&mut ix);
    ix
}

fn init_market(admin: &mut TestAccount, market: &mut TestAccount) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(default_init_market_ix(), &mut [admin, market, &mut mint]).unwrap();
    mint_key
}

fn init_market_with_ix(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    ix: Instruction,
) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(ix, &mut [admin, market, &mut mint]).unwrap();
    mint_key
}

fn configure_base_unit_mints(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    primary_mint: &mut TestAccount,
    secondary_mint: &mut TestAccount,
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::UpdateBaseUnitMints {
            primary_mint: primary_mint.key.to_bytes(),
            secondary_mint: secondary_mint.key.to_bytes(),
        },
        &mut [authority, market, primary_mint, secondary_mint],
    )
}

fn update_asset_lifecycle(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    action: u8,
    asset_index: u16,
    now_slot: u64,
    initial_price: u64,
) -> Result<(), ProgramError> {
    update_asset_lifecycle_with_authorities(
        authority,
        market,
        action,
        asset_index,
        now_slot,
        initial_price,
        authority.key.to_bytes(),
        authority.key.to_bytes(),
        authority.key.to_bytes(),
    )
}

fn update_asset_lifecycle_with_authorities(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    action: u8,
    asset_index: u16,
    now_slot: u64,
    initial_price: u64,
    insurance_authority: [u8; 32],
    insurance_operator: [u8; 32],
    backing_bucket_authority: [u8; 32],
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action,
            asset_index,
            now_slot,
            initial_price,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority: backing_bucket_authority,
        },
        &mut [authority, market],
    )
}

fn force_close_abandoned_asset(
    cranker: &mut TestAccount,
    market: &mut TestAccount,
    account_a: &mut TestAccount,
    account_b: &mut TestAccount,
    asset_index: u16,
    now_slot: u64,
    close_q: u128,
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::ForceCloseAbandonedAsset {
            asset_index,
            now_slot,
            close_q,
        },
        &mut [cranker, market, account_a, account_b],
    )
}

fn init_portfolio(owner: &mut TestAccount, market: &mut TestAccount, portfolio: &mut TestAccount) {
    run_ix(Instruction::InitPortfolio, &mut [owner, market, portfolio]).unwrap();
}

fn sync_maintenance_fee(
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    now_slot: u64,
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::SyncMaintenanceFee { now_slot },
        &mut [market, portfolio],
    )
}

fn sync_maintenance_fee_with_cranker(
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    cranker: &mut TestAccount,
    now_slot: u64,
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::SyncMaintenanceFee { now_slot },
        &mut [market, portfolio, cranker],
    )
}

fn deposit(
    owner: &mut TestAccount,
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    amount: u128,
) {
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let amount_u64 = u64::try_from(amount).unwrap();
    let mut source_token = user_token_account(owner.key, mint, amount_u64);
    let mut vault_token = vault_token_account(market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::Deposit { amount },
        &mut [
            owner,
            market,
            portfolio,
            &mut source_token,
            &mut vault_token,
            &mut token_program,
        ],
    )
    .unwrap();
}

fn top_up_backing_bucket(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    domain: u16,
    amount: u128,
    expiry_slot: u64,
) {
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let amount_u64 = u64::try_from(amount).unwrap();
    let mut source = user_token_account(authority.key, mint, amount_u64);
    let mut vault = vault_token_account(market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg1 = canonical_backing_ledger_account(&market, domain);
    let mut __sp1 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain,
            amount,
            expiry_slot,
        },
        &mut [
            authority,
            market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg1,
        &mut __sp1,
    ],
    )
    .unwrap();
}

fn add_source_positive_pnl(
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    domain: usize,
    amount: u128,
) {
    let (cfg, mut group) = state::read_market(&market.data).unwrap();
    let mut account = state::read_portfolio(&portfolio.data).unwrap();
    group
        .add_account_source_positive_pnl_not_atomic(&mut account, domain, amount)
        .unwrap();
    state::write_market(&mut market.data, &cfg, &group).unwrap();
    state::write_portfolio(&mut portfolio.data, &account).unwrap();
}

fn withdraw(
    owner: &mut TestAccount,
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    amount: u128,
) {
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let amount_u64 = u64::try_from(amount).unwrap();
    let mut dest_token = user_token_account(owner.key, mint, 0);
    let mut vault_token = vault_token_account(market, mint, amount_u64);
    let mut vault_auth = vault_authority_account(market);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::Withdraw { amount },
        &mut [
            owner,
            market,
            portfolio,
            &mut dest_token,
            &mut vault_token,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
}

fn configure_three_leg_hybrid(
    admin: &mut TestAccount,
    market: &mut TestAccount,
    feeds: [[u8; 32]; 3],
    leg0: &mut TestAccount,
    leg1: &mut TestAccount,
    leg2: &mut TestAccount,
    now_slot: u64,
    now_unix_ts: i64,
    soft_stale_slots: u64,
    mark_min_fee: u64,
) {
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot,
            now_unix_ts,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: soft_stale_slots,
            mark_ewma_halflife_slots: 1,
            mark_min_fee,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [admin, market, leg0, leg1, leg2],
    )
    .unwrap();
}

fn close_resolved(
    owner: &mut TestAccount,
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    fee_rate_per_slot: u128,
) {
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let payout = state::read_portfolio(&portfolio.data).unwrap().capital;
    let payout_u64 = u64::try_from(payout).unwrap();
    let mut dest_token = user_token_account(owner.key, mint, 0);
    let mut vault_token = vault_token_account(market, mint, payout_u64);
    let mut vault_auth = vault_authority_account(market);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::CloseResolved { fee_rate_per_slot },
        &mut [
            owner,
            market,
            portfolio,
            &mut dest_token,
            &mut vault_token,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
}

fn close_portfolio(
    closer: &mut TestAccount,
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
) {
    run_ix(
        Instruction::ClosePortfolio,
        &mut [closer, market, portfolio],
    )
    .unwrap();
}

fn assert_err_and_market_unchanged(
    result: Result<(), ProgramError>,
    market: &TestAccount,
    before: &[u8],
) {
    assert!(result.is_err(), "instruction should reject");
    assert_eq!(
        market.data, before,
        "failed wrapper instruction must not persist partial market mutation"
    );
}

fn seed_cancellable_close_progress(market: &mut TestAccount, portfolio: &mut TestAccount) {
    let (cfg, mut group) = state::read_market(&market.data).unwrap();
    let mut account = state::read_portfolio(&portfolio.data).unwrap();
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
    state::write_market(&mut market.data, &cfg, &group).unwrap();
    state::write_portfolio(&mut portfolio.data, &account).unwrap();
}

#[test]
fn v16_wrapper_init_binds_market_and_portfolio_provenance() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let (_, group) = state::read_market(&market.data).unwrap();
    // v17: portfolio is O(1) fixed size; use read_portfolio_boxed_for_market_slots to
    // ensure the runtime Vec is sized to the market's slot count for validate_account_shape.
    let acct = *state::read_portfolio_boxed_for_market_slots(
        &portfolio.data,
        group.config.max_market_slots as usize,
    ).unwrap();
    assert_eq!(group.market_group_id, market.key.to_bytes());
    assert_eq!(group.materialized_portfolio_count, 1);
    assert_eq!(
        acct.provenance_header.market_group_id,
        market.key.to_bytes()
    );
    assert_eq!(
        acct.provenance_header.portfolio_account_id,
        portfolio.key.to_bytes()
    );
    assert_eq!(acct.owner, owner.key.to_bytes());
    assert_eq!(group.validate_account_shape(&acct), Ok(()));

    let mut cfg = V16Config::public_user_fund(1, 0, 10);
    cfg.maintenance_margin_bps = 10_000;
    cfg.initial_margin_bps = 10_000;
    cfg.max_trading_fee_bps = 10_000;
    cfg.max_price_move_bps_per_slot = 10_000;
    cfg.max_accrual_dt_slots = 1;
    cfg.min_funding_lifetime_slots = 1;
    cfg.max_bankrupt_close_lifetime_slots = 100;
    let mut expected = MarketGroupV16::new(market.key.to_bytes(), cfg).unwrap();
    expected.assets[0].raw_oracle_target_price = 100;
    expected.assets[0].effective_price = 100;
    expected.assets[0].fund_px_last = 100;
    expected.materialized_portfolio_count = 1;
    assert_eq!(group.config, expected.config);
    assert_eq!(group.materialized_portfolio_count, 1);
    assert_eq!(
        group.assets[0], expected.assets[0],
        "configured asset must match canonical engine init shape"
    );
    assert_eq!(
        &group.insurance_domain_budget[..2],
        &[0u128, 0u128],
        "configured domain budgets start empty and are funded explicitly"
    );
    assert_eq!(
        &group.source_backing_buckets[..2],
        &expected.source_backing_buckets[..],
        "configured backing buckets must match canonical engine init shape"
    );
    assert!(
        group.assets[1..]
            .iter()
            .all(|asset| asset.market_id == 0 && asset.lifecycle == AssetLifecycleV16::Disabled),
        "extra account capacity must decode as disabled, unreusable slots"
    );
}

#[test]
fn v16_wrapper_init_market_ports_full_engine_config_fields() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();

    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                h_max,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                maintenance_margin_bps,
                initial_margin_bps,
                max_trading_fee_bps,
                trade_fee_base_bps,
                liquidation_fee_bps,
                liquidation_fee_cap,
                min_liquidation_abs,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                max_account_b_settlement_chunks,
                max_bankrupt_close_chunks,
                max_bankrupt_close_lifetime_slots,
                public_b_chunk_atoms,
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *h_max = 30;
                *min_nonzero_mm_req = 5;
                *min_nonzero_im_req = 8;
                *maintenance_margin_bps = 10_000;
                *initial_margin_bps = 10_000;
                *max_trading_fee_bps = 1_000;
                *trade_fee_base_bps = 7;
                *liquidation_fee_bps = 1;
                *liquidation_fee_cap = 1;
                *min_liquidation_abs = 0;
                *max_price_move_bps_per_slot = 1;
                *max_accrual_dt_slots = 1;
                *max_abs_funding_e9_per_slot = 0;
                *min_funding_lifetime_slots = 30;
                *max_account_b_settlement_chunks = 3;
                *max_bankrupt_close_chunks = 4;
                *max_bankrupt_close_lifetime_slots = 50;
                *public_b_chunk_atoms = 12_345;
                *maintenance_fee_per_slot = 7;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let (wrapper, group) = state::read_market(&market.data).unwrap();
    assert_eq!(wrapper.maintenance_fee_per_slot, 7);
    assert_eq!(wrapper.trade_fee_base_bps, 7);
    assert_eq!(group.config.h_max, 30);
    assert_eq!(group.config.min_nonzero_mm_req, 5);
    assert_eq!(group.config.min_nonzero_im_req, 8);
    assert_eq!(group.config.maintenance_margin_bps, 10_000);
    assert_eq!(group.config.initial_margin_bps, 10_000);
    assert_eq!(group.config.max_trading_fee_bps, 1_000);
    assert_eq!(group.config.liquidation_fee_bps, 1);
    assert_eq!(group.config.liquidation_fee_cap, 1);
    assert_eq!(group.config.min_liquidation_abs, 0);
    assert_eq!(group.config.max_price_move_bps_per_slot, 1);
    assert_eq!(group.config.max_accrual_dt_slots, 1);
    assert_eq!(group.config.max_abs_funding_e9_per_slot, 0);
    assert_eq!(group.config.min_funding_lifetime_slots, 30);
    assert_eq!(group.config.max_account_b_settlement_chunks, 3);
    assert_eq!(group.config.max_bankrupt_close_chunks, 4);
    assert_eq!(group.config.max_bankrupt_close_lifetime_slots, 50);
    assert_eq!(group.config.public_b_chunk_atoms, 12_345);
}

#[test]
fn v16_wrapper_permissionless_maintenance_fee_charges_flat_portfolio_to_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 100);

    sync_maintenance_fee(&mut market, &mut portfolio, 10).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 50);
    assert_eq!(account.last_fee_slot, 10);
    assert_eq!(group.insurance, 50);
    assert_eq!(group.c_tot, 50);

    let market_after_first = market.data.clone();
    let portfolio_after_first = portfolio.data.clone();
    sync_maintenance_fee(&mut market, &mut portfolio, 10).unwrap();
    assert_eq!(
        market.data, market_after_first,
        "same-slot fee sync must be idempotent"
    );
    assert_eq!(portfolio.data, portfolio_after_first);
}

#[test]
fn v16_wrapper_init_portfolio_anchors_fee_slot_at_market_current_slot() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 100,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    assert_eq!(
        state::read_market(&market.data).unwrap().1.current_slot,
        100
    );

    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    sync_maintenance_fee(&mut market, &mut portfolio, 110).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        account.capital, 950,
        "new portfolios owe maintenance from creation time, not from slot zero"
    );
    assert_eq!(account.last_fee_slot, 110);
    assert_eq!(group.insurance, 50);
    assert_eq!(group.c_tot, 950);
}

#[test]
fn v16_wrapper_init_portfolio_fee_anchor_tracks_crank_and_asset_lifecycle_time() {
    let assert_new_portfolio_pays_from_creation_slot =
        |market: &mut TestAccount, owner: &mut TestAccount, portfolio: &mut TestAccount| {
            init_portfolio(owner, market, portfolio);
            deposit(owner, market, portfolio, 1_000);
            sync_maintenance_fee(market, portfolio, 110).unwrap();
            let (_, group) = state::read_market(&market.data).unwrap();
            let account = state::read_portfolio(&portfolio.data).unwrap();
            assert_eq!(group.current_slot, 100);
            assert_eq!(account.last_fee_slot, 110);
            assert_eq!(account.capital, 950);
            assert_eq!(group.insurance, 50);
        };

    let mut admin = signer();
    let mut market = market_account();
    let mut old_owner = signer();
    let mut new_owner = signer();
    let mut old_portfolio = portfolio_account();
    let mut new_portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut old_owner, &mut market, &mut old_portfolio);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 100,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut old_owner, &mut market, &mut old_portfolio],
    )
    .unwrap();
    assert_new_portfolio_pays_from_creation_slot(&mut market, &mut new_owner, &mut new_portfolio);

    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        100,
        125,
    )
    .unwrap();
    assert_new_portfolio_pays_from_creation_slot(&mut market, &mut owner, &mut portfolio);
}

#[test]
fn v16_wrapper_maintenance_fee_is_permissionless_and_capital_capped() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 40;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 75);

    let market_lamports_before = market.lamports;
    let portfolio_lamports_before = portfolio.lamports;
    owner.is_signer = false;
    sync_maintenance_fee(&mut market, &mut portfolio, 2).unwrap();
    owner.is_signer = true;

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 75);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.materialized_portfolio_count, 0);
    assert_eq!(
        market.lamports,
        market_lamports_before + portfolio_lamports_before,
        "dust-closed portfolio rent should be swept into the market slab"
    );
    assert_eq!(portfolio.lamports, 0);
    assert!(portfolio.data.iter().all(|b| *b == 0));
    assert!(!state::is_initialized(&portfolio.data));
}

#[test]
fn v16_wrapper_underfunded_flat_sync_sweeps_remaining_capital_once() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 40;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);

    let market_lamports_before = market.lamports;
    let long_lamports_before = long_account.lamports;
    sync_maintenance_fee(&mut market, &mut long_account, 10).unwrap();
    let (_, group_after_flat_sync) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group_after_flat_sync.insurance, 1,
        "underfunded flat sync sweeps the remaining capital into insurance"
    );
    assert_eq!(group_after_flat_sync.materialized_portfolio_count, 1);
    assert_eq!(long_account.lamports, 0);
    assert_eq!(
        market.lamports,
        market_lamports_before + long_lamports_before,
        "closed dust portfolio rent should accrue to the market slab"
    );
    assert!(long_account.data.iter().all(|b| *b == 0));
    assert!(!state::is_initialized(&long_account.data));

    let mut reopened_long_account = portfolio_account();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    init_portfolio(&mut long_owner, &mut market, &mut reopened_long_account);
    deposit(
        &mut long_owner,
        &mut market,
        &mut reopened_long_account,
        1_000,
    );
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut reopened_long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let insurance_before_nonflat_sync = state::read_market(&market.data).unwrap().1.insurance;

    sync_maintenance_fee(&mut market, &mut reopened_long_account, 10).unwrap();
    let (_, group_after_nonflat_sync) = state::read_market(&market.data).unwrap();
    let account_after_nonflat_sync = state::read_portfolio(&reopened_long_account.data).unwrap();
    assert_eq!(account_after_nonflat_sync.capital, 1_000);
    assert_eq!(account_after_nonflat_sync.last_fee_slot, 10);
    assert_eq!(
        group_after_nonflat_sync.insurance, insurance_before_nonflat_sync,
        "later deposits are not charged for an already-swept empty interval"
    );
}

#[test]
fn v16_wrapper_maintenance_fee_policy_splits_optional_cranker_share() {
    let mut admin = signer();
    let mut market = market_account();
    let mut payer_owner = signer();
    let mut cranker_owner = signer();
    let mut payer = portfolio_account();
    let mut cranker = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut payer_owner, &mut market, &mut payer);
    init_portfolio(&mut cranker_owner, &mut market, &mut cranker);
    deposit(&mut payer_owner, &mut market, &mut payer, 100);
    run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    sync_maintenance_fee_with_cranker(&mut market, &mut payer, &mut cranker, 10).unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let payer = state::read_portfolio(&payer.data).unwrap();
    let cranker = state::read_portfolio(&cranker.data).unwrap();
    assert_eq!(payer.capital, 50);
    assert_eq!(payer.last_fee_slot, 10);
    assert_eq!(cranker.capital, 20);
    assert_eq!(
        group.insurance, 30,
        "the configured cranker share is split out and the remaining maintenance fee stays in insurance"
    );
    assert_eq!(group.c_tot, 70);
    assert_eq!(group.vault, 100);
}

#[test]
fn v16_wrapper_maintenance_fee_reward_account_absent_keeps_full_fee_in_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 100);
    run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    sync_maintenance_fee(&mut market, &mut portfolio, 10).unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 50);
    assert_eq!(group.insurance, 50);
    assert_eq!(
        group.c_tot, 50,
        "no optional cranker account means no internal cranker reward is minted"
    );
}

#[test]
fn v16_wrapper_maintenance_fee_same_cranker_key_still_leaves_insurance_share() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 100);
    run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut duplicate_same_key = portfolio_account();
    duplicate_same_key.key = portfolio.key;
    sync_maintenance_fee_with_cranker(&mut market, &mut portfolio, &mut duplicate_same_key, 10)
        .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        account.capital, 70,
        "same-key cranker receives only the configured reward share after paying the full fee"
    );
    assert_eq!(
        group.insurance, 30,
        "same-key reward is not a noop because the unsplit insurance share remains collected"
    );
    assert_eq!(group.c_tot, 70);
    assert_eq!(group.vault, 100);
}

#[test]
fn v16_wrapper_maintenance_fee_policy_is_admin_gated_and_bounds_share() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    let before = market.data.clone();

    let rejected = run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 10_001,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);

    let rejected = run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);

    run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.maintenance_cranker_fee_share_bps, 4_000);
}

#[test]
fn v16_wrapper_trade_fee_policy_is_insurance_authority_gated_and_bounds_fee() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut insurance_authority = signer();
    let mut market = market_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                ..
            } = ix
            {
                *max_trading_fee_bps = 100;
                *trade_fee_base_bps = 1;
            }
        }),
    );
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: insurance_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut insurance_authority, &mut market],
    )
    .unwrap();
    let before = market.data.clone();

    let rejected_attacker = run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 2,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(rejected_attacker, &market, &before);

    let rejected_admin_after_rotation = run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 2,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected_admin_after_rotation, &market, &before);

    let rejected_over_engine_cap = run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 101,
        },
        &mut [&mut insurance_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_over_engine_cap, &market, &before);

    run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 25,
        },
        &mut [&mut insurance_authority, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.trade_fee_base_bps, 25);
}

/// RENAMED 2026-07-24 (was
/// `..._is_admin_gated_and_redirects_non_main_fees_to_market_zero`): the
/// redirect half of that name has been false for TRADE fees since the
/// creator-fee-claim change removed `credit_fee_to_domain_budget_view`. What
/// this test still proves is (a) `UpdateFeeRedirectPolicy`'s admin gate and
/// bps cap, and (b) that a non-main asset's trade fee now bypasses the domain
/// budgets entirely.
#[test]
fn v16_wrapper_fee_redirect_policy_is_admin_gated_and_trade_fees_bypass_domain_budgets() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
    )
    .unwrap();

    let before = market.data.clone();
    let rejected_attacker = run_ix(
        Instruction::UpdateFeeRedirectPolicy {
            redirect_bps: 2_500,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(rejected_attacker, &market, &before);

    let rejected_over_cap = run_ix(
        Instruction::UpdateFeeRedirectPolicy {
            redirect_bps: 10_001,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected_over_cap, &market, &before);

    run_ix(
        Instruction::UpdateFeeRedirectPolicy {
            redirect_bps: 2_500,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.fee_redirect_to_market_0_bps, 2_500);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 20_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 20_000);

    let size_q = 100 * POS_SCALE;
    let exec_price = 100;
    let fee_bps = 100;
    // Taker-only charging (design §1A): exactly ONE side's ceil-rounded fee per
    // fill. (`two_sided_fee`, used here until 2026-07-24, has been the wrong
    // model since the taker-only rewrite.)
    let expected_fee_total = taker_only_fee(size_q, exec_price, fee_bps);
    let (_, group_before_trade) = state::read_market(&market.data).unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: size_q as i128,
            exec_price,
            fee_bps,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (cfg_after_trade, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, expected_fee_total);
    // CURRENT CONTRACT (creator-fee claim, 2026-07-23). Until then this block
    // asserted
    //     insurance_domain_budget[2] == insurance_domain_budget[3]
    //         == fee_per_side - redirect_per_side
    //     insurance - budget[2] - budget[3] == redirect_per_side * 2
    // i.e. "a non-main asset's trade fee lands in ITS domain budgets, minus a
    // `fee_redirect_to_market_0_bps` skim to market 0". That contract is GONE:
    // the trade-fee creator leg -- the only leg that ever reached a domain
    // budget, and therefore the only leg the redirect ever skimmed on this path
    // -- now accrues to `creator_fee_claimable_atoms` instead, and
    // `credit_fee_to_domain_budget_view` was deleted outright.
    //
    // `fee_redirect_to_market_0_bps` is NOT dead: the maintenance-fee and
    // backing-fee paths still apply it via
    // `credit_market_fee_split_across_domains_view`. It simply no longer has
    // any effect on TRADE fees, which is what this fixture drives.
    let expected_creator_cut =
        expected_fee_total * cfg_after_trade.creator_share_bps as u128 / 10_000;
    assert_ne!(
        expected_creator_cut, 0,
        "the fixture must produce a nonzero creator leg, or the assertions below are no-ops"
    );
    assert_eq!(
        cfg_after_trade.creator_fee_claimable_atoms, expected_creator_cut as u64,
        "the non-main asset's creator leg accrues to the claimable counter"
    );
    assert_eq!(
        group.insurance_domain_budget, group_before_trade.insurance_domain_budget,
        "NO domain budget moves on a trade any more -- not asset 1's own (domains 2/3), and \
         not asset 0's redirect target (domains 0/1)"
    );
    assert_eq!(
        group.insurance_domain_budget[2], 0,
        "asset 1's long domain budget must still be unfunded"
    );
    assert_eq!(
        group.insurance_domain_budget[3], 0,
        "asset 1's short domain budget must still be unfunded"
    );

    // v17: UpdateInsurancePolicy (tag 33) deleted (matrix row 35). Live withdrawal is
    // impossible; terminal withdrawal is domain-budget-gated.
    //
    // CONSEQUENCE OF THE ABOVE, and the reason the rest of this test changed
    // shape: with every domain budget at 0, a trade fee is no longer reachable
    // through the terminal `WithdrawInsurance` (tag 41) exit AT ALL. The old
    // tail withdrew `expected_domain_per_side * 2` successfully; there is now
    // nothing to withdraw, and an attempt must be refused.
    //
    // HARNESS LIMIT (pre-existing, and why this test is one of this file's
    // long-standing failures): `handle_withdraw_insurance`'s first statement is
    // `Clock::get()?`, and this in-process harness has no Clock sysvar, so
    // every call below returns `UnsupportedSysvar` BEFORE any gate is
    // evaluated. The assertions are written against the real contract so they
    // become live the moment a Clock stub lands; they are not claimed to hold
    // today.
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    // v17: handle_withdraw_insurance requires materialized_portfolio_count == 0 && c_tot == 0.
    // Close both portfolios so the market is fully drained before testing insurance withdrawal.
    close_resolved(&mut long_owner, &mut market, &mut long_account, 0);
    close_resolved(&mut short_owner, &mut market, &mut short_account, 0);
    // ClosePortfolio deregisters the empty (post-close_resolved) portfolio accounts, decrementing
    // materialized_portfolio_count to 0 so WithdrawInsurance's terminal-gate passes.
    close_portfolio(&mut long_owner, &mut market, &mut long_account);
    close_portfolio(&mut short_owner, &mut market, &mut short_account);

    // In v17, admin controls insurance_authority for ALL domains (asset-0 and asset-1) because
    // update_asset_lifecycle uses the caller (admin) as insurance_authority for every new asset.
    // Even so, its terminal withdraw capacity is the SUM OF THE DOMAIN BUDGETS, which the trade
    // above no longer funds -- so admin's capacity is 0 and every amount is an overdraw.
    let vault_balance = state::read_market(&market.data).unwrap().1.vault;
    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, vault_balance as u64);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    // Overdraw beyond the total available insurance is rejected.
    let over_total = run_ix(
        Instruction::WithdrawInsurance {
            amount: expected_fee_total + 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_eq!(
        over_total,
        Err(ProgramError::Custom(21)), // EngineLockActive
        "an overdraw beyond the (now zero) domain-budget capacity must be refused"
    );

    // ...and so is a SINGLE ATOM: the whole fee sits in unbudgeted insurance
    // (protocol / creator / LP / insurance-reserve counters), none of which the
    // domain-budget-gated terminal exit can reach. This is the load-bearing
    // half of the creator-fee re-route -- if a creator could still sweep the
    // leg out through tag 41, moving it off the domain budget bought nothing.
    let one_atom = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_eq!(
        one_atom,
        Err(ProgramError::Custom(21)), // EngineLockActive
        "no domain budget was funded, so not one atom of the trade fee is terminally withdrawable"
    );
    let (cfg_end, group_end) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group_end.insurance, expected_fee_total,
        "the whole fee stays in insurance, unreachable through the domain-budget exit"
    );
    assert_eq!(
        cfg_end.creator_fee_claimable_atoms, expected_creator_cut as u64,
        "and the creator's leg is still sitting on its own counter, claimable only via tag 90"
    );
}

#[test]
fn v16_wrapper_permissionless_market_init_fee_policy_gates_and_funds_base_market() {
    let mut admin = signer();
    let mut creator = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let insurance_authority = Pubkey::new_unique().to_bytes();
    let insurance_operator = Pubkey::new_unique().to_bytes();
    let backing_bucket_authority = Pubkey::new_unique().to_bytes();
    let oracle_authority = Pubkey::new_unique().to_bytes();

    let before_disabled = market.data.clone();
    let disabled = run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 1,
            initial_price: 100,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [&mut creator, &mut market],
    );
    assert_err_and_market_unchanged(disabled, &market, &before_disabled);

    let rejected_attacker = run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        &mut [&mut creator, &mut market],
    );
    assert_err_and_market_unchanged(rejected_attacker, &market, &before_disabled);

    let rejected_over_u64 = run_ix(
        Instruction::UpdateMarketInitFeePolicy {
            min_init_fee: u64::MAX as u128 + 1,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected_over_u64, &market, &before_disabled);

    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.permissionless_market_init_fee, 50);

    let mut source = user_token_account(creator.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 1,
            initial_price: 100,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(profile.insurance_authority, insurance_authority);
    assert_eq!(profile.insurance_operator, insurance_operator);
    assert_eq!(profile.backing_bucket_authority, backing_bucket_authority);
    assert_eq!(profile.oracle_authority, oracle_authority);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 50);
    assert_eq!(group.vault, 50);
    assert_eq!(group.insurance_domain_budget[0], 25);
    assert_eq!(group.insurance_domain_budget[1], 25);
    assert_eq!(group.insurance_domain_budget[2], 0);
    assert_eq!(group.insurance_domain_budget[3], 0);
}

#[test]
fn v16_wrapper_permissionless_market_init_fee_doubles_every_32_markets() {
    let mut admin = signer();
    let mut creator = signer();
    let mut market = market_account_with_capacity(33);
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    for asset_index in 1..32 {
        update_asset_lifecycle(
            &mut admin,
            &mut market,
            processor::ASSET_ACTION_ACTIVATE,
            asset_index as u16,
            asset_index as u64,
            100 + asset_index as u64,
        )
        .unwrap();
    }

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.config.max_market_slots, 32);
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);

    let insurance_authority = Pubkey::new_unique().to_bytes();
    let insurance_operator = Pubkey::new_unique().to_bytes();
    let backing_bucket_authority = Pubkey::new_unique().to_bytes();
    let oracle_authority = Pubkey::new_unique().to_bytes();

    let mut short_source = user_token_account(creator.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before_boundary = market.data.clone();
    let underpaid = run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 32,
            now_slot: 32,
            initial_price: 132,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut short_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(underpaid, &market, &before_boundary);

    let mut source = user_token_account(creator.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 32,
            now_slot: 32,
            initial_price: 132,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let profile = state::read_asset_oracle_profile(&market.data, 32).unwrap();
    assert_eq!(profile.insurance_authority, insurance_authority);
    assert_eq!(profile.insurance_operator, insurance_operator);
    assert_eq!(profile.backing_bucket_authority, backing_bucket_authority);
    assert_eq!(profile.oracle_authority, oracle_authority);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.config.max_market_slots, 33);
    assert_eq!(group.insurance, 100);
    assert_eq!(group.vault, 100);
    assert_eq!(group.insurance_domain_budget[0], 50);
    assert_eq!(group.insurance_domain_budget[1], 50);
}

#[test]
fn v16_wrapper_permissionless_market_creator_must_reuse_shutdown_slot_before_append() {
    let mut admin = signer();
    let mut creator = signer();
    let mut market = market_account_with_capacity(4);
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        101,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        2,
        102,
    )
    .unwrap();
    let (_, active_group) = state::read_market(&market.data).unwrap();
    assert_eq!(active_group.config.max_market_slots, 3);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        3,
        0,
    )
    .unwrap();
    let (retired_cfg, retired_group) = state::read_market(&market.data).unwrap();
    assert_eq!(retired_cfg.free_market_slot_count, 1);
    assert_eq!(
        retired_group.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );
    assert_eq!(retired_group.config.max_market_slots, 3);
    let old_market_id = retired_group.assets[1].market_id;
    let next_market_id = retired_group.next_market_id;

    let insurance_authority = Pubkey::new_unique().to_bytes();
    let insurance_operator = Pubkey::new_unique().to_bytes();
    let backing_bucket_authority = Pubkey::new_unique().to_bytes();
    let oracle_authority = Pubkey::new_unique().to_bytes();
    let mut append_source = user_token_account(creator.key, mint, 50);
    let mut append_vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before_append = market.data.clone();
    let append = run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 3,
            now_slot: 4,
            initial_price: 103,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut append_source,
            &mut append_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(append, &market, &before_append);

    let mut reuse_source = user_token_account(creator.key, mint, 50);
    let mut reuse_vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 4,
            initial_price: 201,
            insurance_authority,
            insurance_operator,
            backing_bucket_authority,
            oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut reuse_source,
            &mut reuse_vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(profile.insurance_authority, insurance_authority);
    assert_eq!(profile.insurance_operator, insurance_operator);
    assert_eq!(profile.backing_bucket_authority, backing_bucket_authority);
    assert_eq!(profile.oracle_authority, oracle_authority);
    let (reused_cfg, reused_group) = state::read_market(&market.data).unwrap();
    assert_eq!(reused_cfg.free_market_slot_count, 0);
    assert_eq!(reused_group.config.max_market_slots, 3);
    assert_eq!(reused_group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(reused_group.assets[1].market_id, next_market_id);
    assert!(reused_group.assets[1].market_id > old_market_id);
    assert_eq!(reused_group.insurance, 50);
    assert_eq!(reused_group.vault, 50);
    assert_eq!(reused_group.insurance_domain_budget[0], 25);
    assert_eq!(reused_group.insurance_domain_budget[1], 25);
    assert_eq!(reused_group.insurance_domain_budget[2], 0);
    assert_eq!(reused_group.insurance_domain_budget[3], 0);
}

#[test]
fn v16_wrapper_permissionless_dynamic_market_drains_after_positions_close() {
    let mut admin = signer();
    let mut creator = signer();
    let mut insurance_authority = signer();
    let mut insurance_operator = signer();
    let mut backing_authority = signer();
    let mut market = market_account_with_capacity(2);
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account_for_market_slots(2);
    let mut short_account = portfolio_account_for_market_slots(2);
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut init_fee_source = user_token_account(creator.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 1,
            initial_price: 150,
            insurance_authority: insurance_authority.key.to_bytes(),
            insurance_operator: insurance_operator.key.to_bytes(),
            backing_bucket_authority: backing_authority.key.to_bytes(),
            oracle_authority: backing_authority.key.to_bytes(),
        },
        &mut [
            &mut creator,
            &mut market,
            &mut init_fee_source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let mut insurance_source = user_token_account(insurance_authority.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::TopUpInsuranceDomain {
            domain: 2,
            amount: 10,
        },
        &mut [
            &mut insurance_authority,
            &mut market,
            &mut insurance_source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let mut backing_source = user_token_account(backing_authority.key, mint, 25);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut __lg2 = canonical_backing_ledger_account(&market, 2);
    let mut __sp2 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 25,
            expiry_slot: 10,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg2,
        &mut __sp2,
    ],
    )
    .unwrap();

    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let before_open_retire = market.data.clone();
    let open_retire = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        2,
        0,
    );
    assert_err_and_market_unchanged(open_retire, &market, &before_open_retire);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: -(POS_SCALE as i128),
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let closed = state::read_market(&market.data).unwrap().1;
    assert_eq!(closed.assets[1].oi_eff_long_q, 0);
    assert_eq!(closed.assets[1].oi_eff_short_q, 0);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    )
    .unwrap();
    let drained = state::read_market(&market.data).unwrap().1;
    assert_eq!(drained.assets[1].lifecycle, AssetLifecycleV16::DrainOnly);

    let before_funded_retire = market.data.clone();
    let funded_retire = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        3,
        0,
    );
    assert_err_and_market_unchanged(funded_retire, &market, &before_funded_retire);

    let mut insurance_dest = user_token_account(insurance_operator.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 85);
    let mut vault_auth = vault_authority_account(&market);
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 10,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut insurance_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let mut backing_dest = user_token_account(backing_authority.key, mint, 0);
    let mut __lg1 = canonical_backing_ledger_account(&market, 2);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 2,
            amount: 25,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg1,
    ],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        3,
        0,
    )
    .unwrap();
    let retired = state::read_market(&market.data).unwrap().1;
    assert_eq!(retired.assets[1].lifecycle, AssetLifecycleV16::Retired);
    assert_eq!(retired.assets[1].retired_slot, 3);
    assert_eq!(retired.insurance_domain_budget[2], 0);
    assert_eq!(
        retired.source_backing_buckets[2].fresh_unliened_backing_num,
        0
    );
    assert_eq!(retired.insurance, 50);
    assert_eq!(retired.vault, 20_050);
}

#[test]
fn v16_wrapper_shutdown_asset_force_closes_drains_retires_and_reuses_slot() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut creator = signer();
    // v17: asset_authority unified into marketauth — removed separate rotation.
    let mut insurance_authority = signer();
    let mut insurance_operator = signer();
    let mut backing_authority = signer();
    let mut cranker = signer();
    let mut market = market_account_with_capacity(2);
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account_for_market_slots(2);
    let mut short_account = portfolio_account_for_market_slots(2);
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 5,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 10 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        150,
        insurance_authority.key.to_bytes(),
        insurance_operator.key.to_bytes(),
        backing_authority.key.to_bytes(),
    )
    .unwrap();
    // v17: AUTHORITY_ASSET is unified into marketauth — no separate asset_authority rotation needed.
    // admin IS the marketauth and can perform lifecycle operations directly.

    let mut token_program = token_program_account();
    for (domain, amount) in [(2u16, 6u128), (3u16, 4u128)] {
        let mut source = user_token_account(insurance_authority.key, mint, amount as u64);
        let mut vault = vault_token_account(&market, mint, 0);
        run_ix(
            Instruction::TopUpInsuranceDomain { domain, amount },
            &mut [
                &mut insurance_authority,
                &mut market,
                &mut source,
                &mut vault,
                &mut token_program,
            ],
        )
        .unwrap();
    }
    top_up_backing_bucket(&mut backing_authority, &mut market, 2, 20, 20);
    top_up_backing_bucket(&mut backing_authority, &mut market, 3, 25, 20);

    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: (POS_SCALE * 2) as i128,
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let before_unauthorized_shutdown = market.data.clone();
    let unauthorized_shutdown = update_asset_lifecycle(
        &mut attacker,
        &mut market,
        processor::ASSET_ACTION_SHUTDOWN,
        1,
        2,
        0,
    );
    assert_err_and_market_unchanged(
        unauthorized_shutdown,
        &market,
        &before_unauthorized_shutdown,
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_SHUTDOWN,
        1,
        2,
        0,
    )
    .unwrap();
    let shutdown_profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    let (_, shutdown_group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        shutdown_group.assets[1].lifecycle,
        AssetLifecycleV16::Recovery
    );
    assert_eq!(shutdown_profile.last_good_oracle_slot, 2);
    assert_eq!(shutdown_group.assets[1].effective_price, 150);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: -(POS_SCALE as i128),
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let long_after_voluntary = state::read_portfolio(&long_account.data).unwrap();
    let short_after_voluntary = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(
        active_leg_for_asset(&long_after_voluntary, 1)
            .basis_pos_q
            .unsigned_abs(),
        POS_SCALE
    );
    assert_eq!(
        active_leg_for_asset(&short_after_voluntary, 1)
            .basis_pos_q
            .unsigned_abs(),
        POS_SCALE
    );

    let before_timeout_market = market.data.clone();
    let before_timeout_long = long_account.data.clone();
    let before_timeout_short = short_account.data.clone();
    let too_early = force_close_abandoned_asset(
        &mut cranker,
        &mut market,
        &mut long_account,
        &mut short_account,
        1,
        6,
        POS_SCALE,
    );
    assert_err_and_market_unchanged(too_early, &market, &before_timeout_market);
    assert_eq!(long_account.data, before_timeout_long);
    assert_eq!(short_account.data, before_timeout_short);

    force_close_abandoned_asset(
        &mut cranker,
        &mut market,
        &mut long_account,
        &mut short_account,
        1,
        7,
        POS_SCALE,
    )
    .unwrap();
    let long_closed = state::read_portfolio(&long_account.data).unwrap();
    let short_closed = state::read_portfolio(&short_account.data).unwrap();
    assert!(!has_active_leg_for_asset(&long_closed, 1));
    assert!(!has_active_leg_for_asset(&short_closed, 1));
    let (cfg, mut group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.assets[1].oi_eff_long_q, 0);
    assert_eq!(group.assets[1].oi_eff_short_q, 0);
    group.current_slot = 7;
    group.loss_stale_active = true;
    state::write_market(&mut market.data, &cfg, &group).unwrap();

    let mut vault = vault_token_account(&market, mint, 100_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut local_insurance_dest = user_token_account(insurance_operator.key, mint, 0);
    // v17: WithdrawInsuranceAsset handles both long+short domains for the asset;
    // signer must be insurance_operator (D-STAKE-1 guard blocks marketauth when
    // insurance_authority is non-zero).
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 6,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut local_insurance_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 4,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut local_insurance_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let mut local_backing_dest = user_token_account(backing_authority.key, mint, 0);
    let mut __lg2 = canonical_backing_ledger_account(&market, 2);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 2,
            amount: 20,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut local_backing_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg2,
    ],
    )
    .unwrap();
    let mut admin_backing_dest = user_token_account(admin.key, mint, 0);
    let mut __lg3 = canonical_backing_ledger_account(&market, 3);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 3,
            amount: 25,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_backing_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg3,
    ],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        7,
        0,
    )
    .unwrap();
    let (retired_cfg, retired_group) = state::read_market(&market.data).unwrap();
    assert_eq!(retired_cfg.free_market_slot_count, 1);
    assert_eq!(
        retired_group.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );
    let retired_market_id = retired_group.assets[1].market_id;
    let reuse_market_id = retired_group.next_market_id;
    assert_eq!(retired_group.insurance_domain_budget[2], 0);
    assert_eq!(retired_group.insurance_domain_budget[3], 0);
    assert_eq!(
        retired_group.source_backing_buckets[2].fresh_unliened_backing_num,
        0
    );
    assert_eq!(
        retired_group.source_backing_buckets[3].fresh_unliened_backing_num,
        0
    );

    let new_insurance_authority = Pubkey::new_unique().to_bytes();
    let new_insurance_operator = Pubkey::new_unique().to_bytes();
    let new_backing_authority = Pubkey::new_unique().to_bytes();
    let new_oracle_authority = Pubkey::new_unique().to_bytes();
    let mut append_source = user_token_account(creator.key, mint, 10);
    let mut append_vault = vault_token_account(&market, mint, 0);
    let before_append = market.data.clone();
    let append = run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 2,
            now_slot: 8,
            initial_price: 250,
            insurance_authority: new_insurance_authority,
            insurance_operator: new_insurance_operator,
            backing_bucket_authority: new_backing_authority,
            oracle_authority: new_oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut append_source,
            &mut append_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(append, &market, &before_append);

    let mut reuse_source = user_token_account(creator.key, mint, 10);
    let mut reuse_vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 8,
            initial_price: 250,
            insurance_authority: new_insurance_authority,
            insurance_operator: new_insurance_operator,
            backing_bucket_authority: new_backing_authority,
            oracle_authority: new_oracle_authority,
        },
        &mut [
            &mut creator,
            &mut market,
            &mut reuse_source,
            &mut reuse_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(profile.insurance_authority, new_insurance_authority);
    assert_eq!(profile.insurance_operator, new_insurance_operator);
    assert_eq!(profile.backing_bucket_authority, new_backing_authority);
    assert_eq!(profile.oracle_authority, new_oracle_authority);
    let (reused_cfg, reused_group) = state::read_market(&market.data).unwrap();
    assert_eq!(reused_cfg.free_market_slot_count, 0);
    assert_eq!(reused_group.config.max_market_slots, 2);
    assert_eq!(reused_group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(reused_group.assets[1].market_id, reuse_market_id);
    assert!(reused_group.assets[1].market_id > retired_market_id);
    assert_eq!(reused_group.assets[1].effective_price, 250);
    assert_eq!(reused_group.insurance_domain_budget[0], 5);
    assert_eq!(reused_group.insurance_domain_budget[1], 5);
    assert_eq!(reused_group.insurance_domain_budget[2], 0);
    assert_eq!(reused_group.insurance_domain_budget[3], 0);
    assert_eq!(reused_group.insurance, 10);
    assert_eq!(reused_group.vault, 20_010);
}

#[test]
fn v16_wrapper_permissionless_market_shutdown_force_closes_recovers_and_reuses_slot() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut cranker = signer();
    let mut insurance_authority = signer();
    let mut backing_authority = signer();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut market = market_account();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 5,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 25 },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let insurance_operator_key = Pubkey::new_unique();
    let insurance_operator = insurance_operator_key.to_bytes();
    let mut insurance_operator_acct = TestAccount::new(insurance_operator_key, Pubkey::new_unique(), 0).signer();
    let oracle_authority = admin.key.to_bytes();
    let mut init_fee_source = user_token_account(attacker.key, mint, 25);
    let mut init_fee_vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 1,
            initial_price: 100,
            insurance_authority: insurance_authority.key.to_bytes(),
            insurance_operator,
            backing_bucket_authority: backing_authority.key.to_bytes(),
            oracle_authority,
        },
        &mut [
            &mut attacker,
            &mut market,
            &mut init_fee_source,
            &mut init_fee_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let (cfg_after_create, group_after_create) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after_create.permissionless_market_init_fee, 25);
    assert_eq!(
        group_after_create.assets[1].lifecycle,
        AssetLifecycleV16::Active
    );
    assert_eq!(group_after_create.insurance, 25);
    assert_eq!(group_after_create.vault, 25);
    assert_eq!(group_after_create.insurance_domain_budget[0], 12);
    assert_eq!(group_after_create.insurance_domain_budget[1], 13);
    let old_market_id = group_after_create.assets[1].market_id;

    // v17: domain is u16 (matrix row 36).
    for (domain, amount) in [(2u16, 6u128), (3u16, 4u128)] {
        let mut source = user_token_account(insurance_authority.key, mint, amount as u64);
        let mut vault = vault_token_account(&market, mint, 0);
        run_ix(
            Instruction::TopUpInsuranceDomain { domain, amount },
            &mut [
                &mut insurance_authority,
                &mut market,
                &mut source,
                &mut vault,
                &mut token_program,
            ],
        )
        .unwrap();
    }
    top_up_backing_bucket(&mut backing_authority, &mut market, 2, 20, 20);
    top_up_backing_bucket(&mut backing_authority, &mut market, 3, 25, 20);

    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_SHUTDOWN,
        1,
        2,
        0,
    )
    .unwrap();
    let (_, shutdown_group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        shutdown_group.assets[1].lifecycle,
        AssetLifecycleV16::Recovery
    );

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: -(POS_SCALE as i128),
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let long_after_exit_window = state::read_portfolio(&long_account.data).unwrap();
    let short_after_exit_window = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(
        active_leg_for_asset(&long_after_exit_window, 1)
            .basis_pos_q
            .unsigned_abs(),
        POS_SCALE
    );
    assert!(
        active_leg_for_asset(&short_after_exit_window, 1)
            .basis_pos_q
            .unsigned_abs()
            == POS_SCALE
    );

    let before_timeout_market = market.data.clone();
    let before_timeout_long = long_account.data.clone();
    let before_timeout_short = short_account.data.clone();
    let too_early = force_close_abandoned_asset(
        &mut cranker,
        &mut market,
        &mut long_account,
        &mut short_account,
        1,
        6,
        POS_SCALE,
    );
    assert_err_and_market_unchanged(too_early, &market, &before_timeout_market);
    assert_eq!(long_account.data, before_timeout_long);
    assert_eq!(short_account.data, before_timeout_short);

    force_close_abandoned_asset(
        &mut cranker,
        &mut market,
        &mut long_account,
        &mut short_account,
        1,
        7,
        POS_SCALE,
    )
    .unwrap();
    assert!(
        !has_active_leg_for_asset(&state::read_portfolio(&long_account.data).unwrap(), 1),
        "long abandoned account should be closed after the shutdown timeout"
    );
    assert!(
        !has_active_leg_for_asset(&state::read_portfolio(&short_account.data).unwrap(), 1),
        "short abandoned account should be closed after the shutdown timeout"
    );

    let (_, liquidated_group) = state::read_market(&market.data).unwrap();
    assert_eq!(liquidated_group.assets[1].oi_eff_long_q, 0);
    assert_eq!(liquidated_group.assets[1].oi_eff_short_q, 0);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 7;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut vault = vault_token_account(&market, mint, 100_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut insurance_op_dest = user_token_account(insurance_operator_key, mint, 0);
    // v17: WithdrawInsuranceAsset; insurance_operator must sign (D-STAKE-1 blocks marketauth).
    run_ix(
        Instruction::WithdrawInsuranceAsset { asset_index: 1, amount: 6 },
        &mut [
            &mut insurance_operator_acct,
            &mut market,
            &mut insurance_op_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::WithdrawInsuranceAsset { asset_index: 1, amount: 4 },
        &mut [
            &mut insurance_operator_acct,
            &mut market,
            &mut insurance_op_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    // WithdrawBackingBucket: dest token must be owned by the signing authority (backing_authority),
    // not by admin. v17 verify_withdrawable_token_accounts checks dest.owner == signer.key.
    let mut backing_dest = user_token_account(backing_authority.key, mint, 0);
    for (domain, amount) in [(2u16, 20u128), (3u16, 25u128)] {
        let mut __lg4 = canonical_backing_ledger_account(&market, 0);
        run_ix(
            Instruction::WithdrawBackingBucket { domain, amount },
            &mut [
                &mut backing_authority,
                &mut market,
                &mut backing_dest,
                &mut vault,
                &mut vault_auth,
                &mut token_program,
            
            &mut __lg4,
        ],
        )
        .unwrap();
    }

    let mut base_insurance_source = user_token_account(admin.key, mint, 10);
    let mut base_insurance_vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::TopUpInsurance { amount: 10 },
        &mut [
            &mut admin,
            &mut market,
            &mut base_insurance_source,
            &mut base_insurance_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    top_up_backing_bucket(&mut admin, &mut market, 0, 45, 20);
    let (_, recovered_group) = state::read_market(&market.data).unwrap();
    assert_eq!(recovered_group.insurance_domain_budget[2], 0);
    assert_eq!(recovered_group.insurance_domain_budget[3], 0);
    assert_eq!(
        recovered_group.source_backing_buckets[2].fresh_unliened_backing_num,
        0
    );
    assert_eq!(
        recovered_group.source_backing_buckets[3].fresh_unliened_backing_num,
        0
    );
    assert_eq!(recovered_group.insurance_domain_budget[0], 17);
    assert_eq!(recovered_group.insurance_domain_budget[1], 18);
    assert_eq!(
        recovered_group.source_backing_buckets[0].fresh_unliened_backing_num,
        45 * BOUND_SCALE
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        7,
        0,
    )
    .unwrap();
    let (retired_cfg, retired_group) = state::read_market(&market.data).unwrap();
    assert_eq!(retired_cfg.free_market_slot_count, 1);
    assert_eq!(
        retired_group.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );
    let reuse_market_id = retired_group.next_market_id;
    assert!(reuse_market_id > old_market_id);

    let mut reuse_source = user_token_account(attacker.key, mint, 25);
    let mut reuse_vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::UpdateAssetLifecycle {
            action: processor::ASSET_ACTION_ACTIVATE,
            asset_index: 1,
            now_slot: 8,
            initial_price: 250,
            insurance_authority: insurance_authority.key.to_bytes(),
            insurance_operator,
            backing_bucket_authority: backing_authority.key.to_bytes(),
            oracle_authority,
        },
        &mut [
            &mut attacker,
            &mut market,
            &mut reuse_source,
            &mut reuse_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let (reused_cfg, reused_group) = state::read_market(&market.data).unwrap();
    assert_eq!(reused_cfg.free_market_slot_count, 0);
    assert_eq!(reused_group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(reused_group.assets[1].market_id, reuse_market_id);
    assert!(reused_group.assets[1].market_id > old_market_id);
    assert_eq!(reused_group.assets[1].effective_price, 250);
}

#[test]
fn v16_wrapper_shutdown_admin_drain_timeout_ledgers_and_backing_earnings() {
    let mut admin = signer();
    let mut insurance_authority = signer();
    let mut insurance_operator = signer();
    let mut backing_authority = signer();
    let mut market = market_account_with_capacity(2);
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 5,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        150,
        insurance_authority.key.to_bytes(),
        insurance_operator.key.to_bytes(),
        backing_authority.key.to_bytes(),
    )
    .unwrap();

    let mut token_program = token_program_account();
    let mut local_insurance_ledger = insurance_ledger_account();
    let mut insurance_source = user_token_account(insurance_authority.key, mint, 9);
    let mut vault = vault_token_account(&market, mint, 0);
    run_ix(
        Instruction::TopUpInsuranceDomain {
            domain: 2,
            amount: 9,
        },
        &mut [
            &mut insurance_authority,
            &mut market,
            &mut insurance_source,
            &mut vault,
            &mut token_program,
            &mut local_insurance_ledger,
        ],
    )
    .unwrap();

    let mut local_backing_ledger = backing_domain_ledger_account();
    let mut backing_source = user_token_account(backing_authority.key, mint, 20);
    let mut __lg3 = canonical_backing_ledger_account(&market, 2);
    let mut __sp3 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 20,
            expiry_slot: 20,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_source,
            &mut vault,
            &mut token_program,
            &mut local_backing_ledger,
        
        &mut __sp3,
    ],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.source_backing_buckets[2].utilization_fee_earnings = 5;
        group.vault += 5;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_SHUTDOWN,
        1,
        2,
        0,
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 6;
        group.loss_stale_active = true;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut vault = vault_token_account(&market, mint, 34);
    let mut vault_auth = vault_authority_account(&market);
    // v17: insurance_operator must sign (D-STAKE-1 blocks marketauth when insurance_authority != [0;32]).
    let mut ins_op_dest = user_token_account(insurance_operator.key, mint, 0);
    let before_timeout = market.data.clone();
    let too_early = run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 1,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut ins_op_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(too_early, &market, &before_timeout);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 7;
        group.loss_stale_active = true;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_local_insurance_ledger = local_insurance_ledger.data.clone();
    let before_wrong_insurance_ledger = market.data.clone();
    let wrong_insurance_ledger = run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 1,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut ins_op_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut local_insurance_ledger,
        ],
    );
    assert_err_and_market_unchanged(
        wrong_insurance_ledger,
        &market,
        &before_wrong_insurance_ledger,
    );
    assert_eq!(local_insurance_ledger.data, before_local_insurance_ledger);

    let mut op_insurance_ledger = insurance_ledger_account();
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 9,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut ins_op_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut op_insurance_ledger,
        ],
    )
    .unwrap();
    let op_insurance_ledger_state =
        state::read_insurance_ledger(&op_insurance_ledger.data).unwrap();
    assert_eq!(op_insurance_ledger_state.authority, insurance_operator.key.to_bytes());
    assert_eq!(op_insurance_ledger_state.total_withdrawn_atoms, 9);

    // Backing withdrawals use admin (admin is backing_bucket_authority for asset 1).
    let mut admin_dest = user_token_account(admin.key, mint, 0);
    let before_local_backing_ledger = local_backing_ledger.data.clone();
    let before_wrong_backing_ledger = market.data.clone();
    let wrong_backing_ledger = run_ix(
        Instruction::WithdrawBackingBucketEarnings {
            domain: 2,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut local_backing_ledger,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_backing_ledger, &market, &before_wrong_backing_ledger);
    assert_eq!(local_backing_ledger.data, before_local_backing_ledger);

    let mut admin_backing_ledger = backing_domain_ledger_account();
    run_ix(
        Instruction::WithdrawBackingBucketEarnings {
            domain: 2,
            amount: 5,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_backing_ledger,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let admin_backing_ledger_state =
        state::read_backing_domain_ledger(&admin_backing_ledger.data).unwrap();
    assert_eq!(admin_backing_ledger_state.authority, admin.key.to_bytes());
    assert_eq!(admin_backing_ledger_state.total_earnings_withdrawn_atoms, 5);

    let mut __lg5 = canonical_backing_ledger_account(&market, 2);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 2,
            amount: 20,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg5,
    ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.insurance, 0);
    assert_eq!(group.insurance_domain_budget[2], 0);
    assert_eq!(
        group.source_backing_buckets[2].fresh_unliened_backing_num,
        0
    );
    assert_eq!(group.source_backing_buckets[2].utilization_fee_earnings, 0);
}

#[test]
fn v16_wrapper_backing_fee_policy_is_insurance_authority_gated_and_bounds_fee() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut backing_authority = signer();
    let mut insurance_authority = signer();
    let mut market = market_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                ..
            } = ix
            {
                *max_trading_fee_bps = 100;
            }
        }),
    );
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: backing_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut backing_authority, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: insurance_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut insurance_authority, &mut market],
    )
    .unwrap();
    let before = market.data.clone();

    let rejected_attacker = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            insurance_share_bps: 0,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(rejected_attacker, &market, &before);

    let rejected_admin_after_rotation = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            insurance_share_bps: 0,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected_admin_after_rotation, &market, &before);

    let rejected_backing_authority = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            insurance_share_bps: 0,
        },
        &mut [&mut backing_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_backing_authority, &market, &before);

    let rejected_over_engine_cap = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 101,
            insurance_share_bps: 0,
        },
        &mut [&mut insurance_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_over_engine_cap, &market, &before);

    let rejected_inactive_domain = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 2,
            fee_bps: 25,
            insurance_share_bps: 0,
        },
        &mut [&mut insurance_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_inactive_domain, &market, &before);

    let rejected_share_without_fee = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 0,
            insurance_share_bps: 1,
        },
        &mut [&mut insurance_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_share_without_fee, &market, &before);

    let rejected_share_over_bps = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            insurance_share_bps: 10_001,
        },
        &mut [&mut insurance_authority, &mut market],
    );
    assert_err_and_market_unchanged(rejected_share_over_bps, &market, &before);

    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            insurance_share_bps: 2_500,
        },
        &mut [&mut insurance_authority, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.backing_trade_fee_bps_long, 0);
    assert_eq!(cfg.backing_trade_fee_bps_short, 25);
    assert_eq!(cfg.backing_trade_fee_insurance_share_bps_short, 2_500);
    assert_eq!(cfg.backing_trade_fee_policy_count, 1);

    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 0,
            fee_bps: 33,
            insurance_share_bps: 4_000,
        },
        &mut [&mut insurance_authority, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.backing_trade_fee_bps_long, 33);
    assert_eq!(cfg.backing_trade_fee_bps_short, 25);
    assert_eq!(cfg.backing_trade_fee_insurance_share_bps_long, 4_000);
    assert_eq!(cfg.backing_trade_fee_policy_count, 2);

    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 0,
            insurance_share_bps: 0,
        },
        &mut [&mut insurance_authority, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.backing_trade_fee_bps_long, 33);
    assert_eq!(cfg.backing_trade_fee_bps_short, 0);
    assert_eq!(cfg.backing_trade_fee_insurance_share_bps_short, 0);
    assert_eq!(cfg.backing_trade_fee_policy_count, 1);
}

#[test]
fn v16_wrapper_backing_fee_policy_does_not_floor_trades_without_new_backing_lien() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 25,
            // Fee-split floor enforcement (policy_v16::fee_split_floor_ok):
            // insurance_share_bps=0 with a nonzero fee_bps is now rejected
            // (0% insurance < the 15% floor). Use a floor-compliant share;
            // this test's assertions only depend on the TOTAL backing-fee
            // rate (no fee is ever actually charged in this scenario, since
            // no trade here locks new counterparty backing), not on how
            // that fee would split between insurance and LP.
            insurance_share_bps: 2_500,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 20_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 20_000);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (100 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.insurance, 0,
        "domain backing fees are charged only when a trade locks new counterparty backing"
    );
}

#[test]
fn v16_wrapper_backing_fee_rejects_unsafe_charge_and_skips_without_new_lien_nocpi_and_cpi() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    top_up_backing_bucket(&mut admin, &mut market, 1, 1_000, 10);
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 1_000,
            // Fee-split floor enforcement (policy_v16::fee_split_floor_ok):
            // see the sibling test above for why 0 -> 2_500 here doesn't
            // change this test's behavior (total backing-fee rate is
            // unaffected; only the insurance/LP split of any fee actually
            // charged changes, and this scenario never charges one).
            insurance_share_bps: 2_500,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 100);
    deposit(&mut owner_b, &mut market, &mut account_b, 2_000);
    add_source_positive_pnl(&mut market, &mut account_a, 1, 1_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    let too_expensive = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_eq!(
        too_expensive,
        Err(percolator_prog::error::PercolatorError::EngineLockActive.into()),
        "a domain backing fee cannot be charged if it would leave the borrower below initial margin"
    );
    assert_eq!(market.data, before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 100,
            // Fee-split floor enforcement, see note above.
            insurance_share_bps: 2_500,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    deposit(&mut owner_a, &mut market, &mut account_a, 900);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&account_a.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(account.capital, 1_000);
    assert_eq!(
        account.source_lien_counterparty_backing_num[1], 0,
        "no fee is charged when the engine does not create a new source-backed lien"
    );
    assert_eq!(group.source_backing_buckets[1].valid_liened_backing_num, 0);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        1_000 * BOUND_SCALE
    );

    let fresh_before_reduce = group.source_backing_buckets[1].fresh_unliened_backing_num;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: -(5 * POS_SCALE as i128),
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num, fresh_before_reduce,
        "risk-reducing trades that do not lock new backing do not pay a backing reservation fee"
    );

    let mut cpi_market = market_account();
    init_market(&mut admin, &mut cpi_market);
    top_up_backing_bucket(&mut admin, &mut cpi_market, 1, 1_000, 10);
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 100,
            // Fee-split floor enforcement, see note above.
            insurance_share_bps: 2_500,
        },
        &mut [&mut admin, &mut cpi_market],
    )
    .unwrap();
    let mut cpi_owner_a = signer();
    let mut cpi_owner_b = signer();
    let mut cpi_account_a = portfolio_account();
    let mut cpi_account_b = portfolio_account();
    init_portfolio(&mut cpi_owner_a, &mut cpi_market, &mut cpi_account_a);
    init_portfolio(&mut cpi_owner_b, &mut cpi_market, &mut cpi_account_b);
    deposit(&mut cpi_owner_a, &mut cpi_market, &mut cpi_account_a, 1_000);
    deposit(&mut cpi_owner_b, &mut cpi_market, &mut cpi_account_b, 2_000);
    add_source_positive_pnl(&mut cpi_market, &mut cpi_account_a, 1, 1_000);

    run_trade_cpi_with_matcher(
        &mut cpi_owner_a,
        &mut cpi_owner_b,
        &mut cpi_market,
        &mut cpi_account_a,
        &mut cpi_account_b,
        0,
        (10 * POS_SCALE) as i128,
        (10 * POS_SCALE) as i128,
        100,
        0,
        100,
    )
    .unwrap();
    let (_, group) = state::read_market(&cpi_market.data).unwrap();
    let account = state::read_portfolio(&cpi_account_a.data).unwrap();
    assert_eq!(
        account.source_lien_counterparty_backing_num[1], 0,
        "TradeCpi must match TradeNoCpi when no new source-backed lien is created"
    );
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        1_000 * BOUND_SCALE
    );
}

#[test]
fn v16_wrapper_backing_fee_policy_survives_non_base_oracle_reconfiguration() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
    )
    .unwrap();

    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 3,
            fee_bps: 37,
            insurance_share_bps: 3_700,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let before = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(before.backing_trade_fee_bps_long, 0);
    assert_eq!(before.backing_trade_fee_bps_short, 37);
    assert_eq!(before.backing_trade_fee_insurance_share_bps_short, 3_700);

    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 1,
            now_slot: 2,
            initial_mark_e6: 110,
            mark_ewma_halflife_slots: 10,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let after_ewma_mark = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(
        after_ewma_mark.backing_trade_fee_bps_short, 37,
        "oracle profile reconfiguration must not erase the backing authority's domain fee"
    );
    assert_eq!(
        after_ewma_mark.backing_trade_fee_insurance_share_bps_short, 3_700,
        "oracle profile reconfiguration must not erase the insurance fee split"
    );

    let feeds = [[0x71u8; 32], [0x72u8; 32], [0x73u8; 32]];
    let mut leg0 = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 1_000);
    let mut leg1 = pyth_account(&feeds[1], 150_000_000, -6, 1, 1_000);
    let mut leg2 = pyth_account(&feeds[2], 200_000_000, -6, 1, 1_000);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 1,
            now_slot: 3,
            now_unix_ts: 1_000,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 10,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [&mut admin, &mut market, &mut leg0, &mut leg1, &mut leg2],
    )
    .unwrap();
    let after_hybrid = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(after_hybrid.backing_trade_fee_bps_short, 37);
    assert_eq!(
        after_hybrid.backing_trade_fee_insurance_share_bps_short,
        3_700
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        4,
        0,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        5,
        120,
    )
    .unwrap();
    let after_reactivate = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(after_reactivate.oracle_mode, ORACLE_MODE_MANUAL);
    assert_eq!(after_reactivate.oracle_target_price_e6, 120);
    assert_eq!(
        after_reactivate.backing_trade_fee_bps_short, 37,
        "asset lifecycle resets oracle data but must not erase backing-authority fee policy"
    );
    assert_eq!(
        after_reactivate.backing_trade_fee_insurance_share_bps_short, 3_700,
        "asset lifecycle resets oracle data but must not erase backing fee split"
    );
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.backing_trade_fee_policy_count, 1);
}

#[test]
fn v16_wrapper_maintenance_fee_sync_charges_recurring_fee_without_forcing_local_touch() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 10;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    {
        // RESYNC(323c9f2 target-effective-lag): adopt toly 574a7a1's setup —
        // direct slot/price field-set instead of accrue_asset_to_not_atomic,
        // with effective_price aligned to raw_oracle_target_price (=50) so the
        // new adverse-lag penalty is zero. This test exercises ONLY the recurring
        // maintenance fee; our fork's old accrue-based setup left a price lag
        // that now (correctly) levies a +50 penalty.
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 1;
        group.slot_last = 1;
        group.assets[0].raw_oracle_target_price = 50;
        group.assets[0].effective_price = 50;
        group.assets[0].slot_last = 1;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    sync_maintenance_fee(&mut market, &mut long_account, 1).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(account.pnl, 0);
    assert_eq!(
        account.capital, 990,
        "standalone maintenance fee sync charges only the recurring fee; local position settlement remains on lifecycle paths"
    );
    assert_eq!(account.last_fee_slot, 1);
    assert_eq!(group.insurance, 10);
}

#[test]
fn v16_wrapper_maintenance_fee_rejects_recovery_mode_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 100);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Recovery;
        group.recovery_reason = Some(PermissionlessRecoveryReasonV16::BelowProgressFloor);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let result = sync_maintenance_fee(&mut market, &mut portfolio, 10);
    assert_err_and_market_unchanged(result, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_asset_authority_can_append_activate_and_trade_assets() {
    let mut admin = signer();
    let mut market = market_account_with_capacity(3);
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account_for_market_slots(3);
    let mut short_account = portfolio_account_for_market_slots(3);

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 1;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);

    let before = market.data.clone();
    let rejected_before_add = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: POS_SCALE as i128,
            exec_price: 250,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(rejected_before_add, &market, &before);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        150,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        2,
        250,
    )
    .unwrap();
    let (cfg, group) = state::read_market(&market.data).unwrap();
    // v17: no separate asset_authority field; marketauth controls asset activation.
    assert_eq!(cfg.marketauth, admin.key.to_bytes());
    assert_eq!(group.config.max_market_slots, 3);
    assert_eq!(group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(group.assets[2].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(group.assets[2].effective_price, 250);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: POS_SCALE as i128,
            exec_price: 250,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(long.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(short.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(
        active_leg_for_asset(&long, 2).basis_pos_q,
        POS_SCALE as i128
    );
    assert_eq!(
        active_leg_for_asset(&short, 2).basis_pos_q,
        -(POS_SCALE as i128)
    );
}

#[test]
fn v16_wrapper_trade_rejects_corrupt_unconfigured_tail_capacity_fail_closed() {
    let mut admin = signer();
    let mut market = market_account_with_capacity(2);
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account_for_market_slots(2);
    let mut short_account = portfolio_account_for_market_slots(2);

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 1;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);

    let inactive_slot = 1usize;
    let slot_start = HEADER_LEN
        + WRAPPER_CONFIG_LEN
        + MarketGroupV16HeaderAccount::dynamic_asset_slot_offset::<[u8; ASSET_ORACLE_WRAPPER_LEN]>(
            inactive_slot,
        )
        .unwrap()
        + ASSET_ORACLE_WRAPPER_LEN;
    let market_id_offset = core::mem::offset_of!(EngineAssetSlotV16Account, asset)
        + core::mem::offset_of!(AssetStateV16Account, market_id);
    market.data[slot_start + market_id_offset] = 7;
    assert!(
        state::read_market(&market.data).is_err(),
        "full debug decode still rejects corrupt unconfigured tail slots"
    );

    let before_market = market.data.clone();
    let before_long = long_account.data.clone();
    let before_short = short_account.data.clone();
    let result = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_eq!(
        result,
        Err(percolator_prog::error::PercolatorError::EngineInvalidConfig.into())
    );
    assert_eq!(market.data, before_market);
    assert_eq!(long_account.data, before_long);
    assert_eq!(short_account.data, before_short);
}

#[test]
fn v16_wrapper_dynamic_market_account_can_activate_beyond_fixed_runtime_window() {
    let mut admin = signer();
    let base_capacity = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize;
    let grown_capacity = base_capacity + 1;
    let mut market = market_account_with_capacity(grown_capacity);

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS;
            }
        }),
    );
    assert_eq!(
        state::market_slot_capacity(&market.data).unwrap(),
        grown_capacity
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        base_capacity as u16,
        grown_capacity as u64,
        1_000 + base_capacity as u64,
    )
    .unwrap();
    assert_eq!(
        state::market_slot_capacity(&market.data).unwrap(),
        grown_capacity,
        "append activation must consume the next dynamic market slot"
    );

    let (_, mode, current_slot, effective_price, _) =
        state::read_market_trade_preflight(&market.data, grown_capacity - 1).unwrap();
    assert_eq!(mode, MarketModeV16::Live);
    assert_eq!(current_slot, grown_capacity as u64);
    assert_eq!(effective_price, 1_000 + (grown_capacity - 1) as u64);
    let profile = state::read_asset_oracle_profile(&market.data, grown_capacity - 1).unwrap();
    assert_eq!(profile.oracle_target_price_e6, effective_price);
}

#[test]
fn v16_wrapper_existing_portfolio_with_growth_capacity_survives_market_append() {
    let mut admin = signer();
    let base_capacity = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize;
    let grown_capacity = base_capacity + 1;
    let mut market = market_account_with_capacity(grown_capacity);
    let mut owner = signer();
    let mut portfolio = portfolio_account_for_market_slots(grown_capacity);

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS;
            }
        }),
    );
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let initial_portfolio_len = portfolio.data.len();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        base_capacity as u16,
        grown_capacity as u64,
        1_000 + base_capacity as u64,
    )
    .unwrap();
    // v17: portfolios are O(1) fixed-size; market capacity growth never forces a portfolio realloc.
    assert_eq!(portfolio.data.len(), initial_portfolio_len);

    deposit(&mut owner, &mut market, &mut portfolio, 1);
    // v17: portfolio_account_len_for_market_slots returns PORTFOLIO_ACCOUNT_LEN regardless of
    // grown_capacity (sparse O(1) layout). The portfolio len is unchanged by market growth.
    let required_len = state::portfolio_account_len_for_market_slots(grown_capacity).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        portfolio.data.len(),
        required_len,
        "portfolio storage is O(1) fixed-size in v17"
    );
    // v17: source_claim_market_id is a sparse runtime vec sized to occupied entries (0 for fresh).
    // No assertion on its length (it's sparse, not dense-N).
    assert_eq!(account.capital, 1);
}

#[test]
fn v16_wrapper_market_account_capacity_is_declared_by_account_length() {
    let mut admin = signer();
    let mut market = market_account_with_capacity(14);
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 14;
            }
        }),
    );

    assert_eq!(state::market_slot_capacity(&market.data).unwrap(), 14);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.config.max_market_slots, 14);

    let mut too_small = market_account_with_capacity(13);
    let mut mint = mint_account();
    let res = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 14;
            }
        }),
        &mut [&mut admin, &mut too_small, &mut mint],
    );
    assert_eq!(res, Err(ProgramError::InvalidAccountData));
}

#[test]
fn v16_wrapper_one_portfolio_can_hold_multiple_asset_positions_independently() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 3;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(long.active_bitmap, active_bitmap_with(&[0, 1]));
    assert_eq!(short.active_bitmap, active_bitmap_with(&[0, 1]));
    assert_eq!(
        active_leg_for_asset(&long, 0).basis_pos_q,
        POS_SCALE as i128
    );
    assert_eq!(
        active_leg_for_asset(&short, 0).basis_pos_q,
        -(POS_SCALE as i128)
    );
    assert_eq!(
        active_leg_for_asset(&long, 2).basis_pos_q,
        (2 * POS_SCALE) as i128
    );
    assert_eq!(
        active_leg_for_asset(&short, 2).basis_pos_q,
        -((2 * POS_SCALE) as i128)
    );
    assert_eq!(group.assets[0].oi_eff_long_q, POS_SCALE);
    assert_eq!(group.assets[0].oi_eff_short_q, POS_SCALE);
    assert_eq!(group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(group.assets[1].oi_eff_long_q, 0);
    assert_eq!(group.assets[1].oi_eff_short_q, 0);
    assert_eq!(group.assets[2].oi_eff_long_q, 2 * POS_SCALE);
    assert_eq!(group.assets[2].oi_eff_short_q, 2 * POS_SCALE);
}

#[test]
fn v16_wrapper_asset_authority_rotation_and_burn_gate_lifecycle_updates() {
    let mut admin = signer();
    let mut new_asset_authority = signer();
    let mut attacker = signer();
    let mut market = market_account();

    init_market(&mut admin, &mut market);
    let initialized = market.data.clone();
    assert_err_and_market_unchanged(
        update_asset_lifecycle(
            &mut attacker,
            &mut market,
            processor::ASSET_ACTION_ACTIVATE,
            1,
            1,
            101,
        ),
        &market,
        &initialized,
    );

    // v17: UpdateAssetLifecycle is gated by marketauth (single key replacing old
    // asset_authority); rotate marketauth via UpdateAuthority (both current+new must sign).
    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: new_asset_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut new_asset_authority, &mut market],
    )
    .unwrap();
    let rotated = market.data.clone();
    assert_err_and_market_unchanged(
        update_asset_lifecycle(
            &mut admin,
            &mut market,
            processor::ASSET_ACTION_ACTIVATE,
            1,
            1,
            101,
        ),
        &market,
        &rotated,
    );
    update_asset_lifecycle(
        &mut new_asset_authority,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        101,
    )
    .unwrap();

    // v17: marketauth cannot be burned to zero on a live market (UpdateAuthority rejects
    // new_pubkey=0 when mode=Live). Verify zero-burn is rejected.
    let after_activate = market.data.clone();
    let burn_rejected = run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: [0u8; 32],
        },
        &mut [&mut new_asset_authority, &mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(burn_rejected, &market, &after_activate);
}

#[test]
fn v16_wrapper_asset_drain_only_and_retire_enforce_engine_lifecycle() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 1;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        150,
    )
    .unwrap();

    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let before_retire_nonempty = market.data.clone();
    assert_err_and_market_unchanged(
        update_asset_lifecycle(
            &mut admin,
            &mut market,
            processor::ASSET_ACTION_RETIRE,
            1,
            2,
            0,
        ),
        &market,
        &before_retire_nonempty,
    );

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: -(POS_SCALE as i128),
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    )
    .unwrap();
    let drained = state::read_market(&market.data).unwrap().1;
    assert_eq!(drained.assets[1].lifecycle, AssetLifecycleV16::DrainOnly);

    let before_new_position = market.data.clone();
    let new_position = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(new_position, &market, &before_new_position);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        2,
        0,
    )
    .unwrap();
    let retired = state::read_market(&market.data).unwrap().1;
    assert_eq!(retired.assets[1].lifecycle, AssetLifecycleV16::Retired);
}

#[test]
fn v16_wrapper_prediction_asset_can_drain_retire_and_reactivate_without_closing_other_legs() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        1,
        1_000_000,
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    let prediction_q = POS_SCALE / 100;

    // Keep another market leg live while the prediction-style asset is cycled.
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: prediction_q as i128,
            exec_price: 1_000_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        2,
        0,
        0,
    )
    .unwrap();
    let before_blocked_risk_increase = market.data.clone();
    let blocked_risk_increase = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: prediction_q as i128,
            exec_price: 1_000_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(
        blocked_risk_increase,
        &market,
        &before_blocked_risk_increase,
    );

    let before_retire_with_open_legs = market.data.clone();
    let retire_with_open_legs = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        2,
        2,
        0,
    );
    assert_err_and_market_unchanged(
        retire_with_open_legs,
        &market,
        &before_retire_with_open_legs,
    );

    run_ix(
        Instruction::RebalanceReduce {
            asset_index: 2,
            reduce_q: prediction_q,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    )
    .unwrap();
    let after_unilateral_reduce = state::read_portfolio(&short_account.data).unwrap();
    assert!(
        active_leg_for_asset(&after_unilateral_reduce, 2).active,
        "counterparty leg is stale/dead after unilateral reduction and must be explicitly cleared"
    );
    let second_unilateral_reduce = run_ix(
        Instruction::RebalanceReduce {
            asset_index: 2,
            reduce_q: prediction_q,
        },
        &mut [&mut short_owner, &mut market, &mut short_account],
    );
    assert!(
        second_unilateral_reduce.is_err(),
        "once the opposite side is reset-pending, cleanup uses the dead-leg forfeit path"
    );
    run_ix(
        Instruction::ForfeitRecoveryLeg {
            asset_index: 2,
            b_delta_budget: 1,
        },
        &mut [&mut short_owner, &mut market, &mut short_account],
    )
    .unwrap();
    run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 2,
            side: 0,
        },
        &mut [&mut market],
    )
    .unwrap();
    run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 2,
            side: 1,
        },
        &mut [&mut market],
    )
    .unwrap();

    let (cfg, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(long.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(short.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(group.assets[0].oi_eff_long_q, POS_SCALE);
    assert_eq!(group.assets[0].oi_eff_short_q, POS_SCALE);
    assert_eq!(group.assets[2].oi_eff_long_q, 0);
    assert_eq!(group.assets[2].oi_eff_short_q, 0);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        2,
        group.current_slot + 1,
        0,
    )
    .unwrap();
    let retired = state::read_market(&market.data).unwrap().1;
    assert_eq!(retired.assets[2].lifecycle, AssetLifecycleV16::Retired);
    assert_eq!(retired.assets[2].retired_slot, group.current_slot + 1);
    let old_market_id = retired.assets[2].market_id;
    let next_market_id_before = retired.next_market_id;

    let before_early_reuse = market.data.clone();
    assert_err_and_market_unchanged(
        update_asset_lifecycle(
            &mut admin,
            &mut market,
            processor::ASSET_ACTION_ACTIVATE,
            2,
            retired.current_slot,
            500_000,
        ),
        &market,
        &before_early_reuse,
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        retired.current_slot + 1,
        500_000,
    )
    .unwrap();
    let reactivated = state::read_market(&market.data).unwrap().1;
    assert_eq!(reactivated.assets[2].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(reactivated.assets[2].market_id, next_market_id_before);
    assert!(reactivated.assets[2].market_id > old_market_id);
    assert_eq!(reactivated.next_market_id, next_market_id_before + 1);
    assert_eq!(reactivated.assets[2].effective_price, 500_000);

    let mut stale_long = state::read_portfolio(&long_account.data).unwrap();
    stale_long.legs[1] = PortfolioLegV16 {
        active: true,
        asset_index: 2,
        market_id: old_market_id,
        side: SideV16::Long,
        basis_pos_q: prediction_q as i128,
        a_basis: percolator::ADL_ONE,
        k_snap: 0,
        f_snap: 0,
        epoch_snap: 0,
        loss_weight: prediction_q,
        b_snap: 0,
        b_rem: 0,
        b_epoch_snap: 0,
        b_stale: false,
        stale: false,
    };
    stale_long.active_bitmap = active_bitmap_with(&[0, 1]);
    state::write_portfolio(&mut long_account.data, &stale_long).unwrap();
    let before_stale_market_id = market.data.clone();
    let stale_market_id_deposit = {
        let mint =
            Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
        let mut source_token = user_token_account(long_owner.key, mint, 1);
        let mut vault_token = vault_token_account(&market, mint, 0);
        let mut token_program = token_program_account();
        run_ix(
            Instruction::Deposit { amount: 1 },
            &mut [
                &mut long_owner,
                &mut market,
                &mut long_account,
                &mut source_token,
                &mut vault_token,
                &mut token_program,
            ],
        )
    };
    assert_err_and_market_unchanged(stale_market_id_deposit, &market, &before_stale_market_id);
    let mut clean_long = state::read_portfolio(&long_account.data).unwrap();
    clean_long.legs[1] = percolator::PortfolioLegV16::EMPTY;
    clean_long.active_bitmap = active_bitmap_with(&[0]);
    state::write_portfolio(&mut long_account.data, &clean_long).unwrap();

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: prediction_q as i128,
            exec_price: 500_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (_, final_group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(long.active_bitmap, active_bitmap_with(&[0, 1]));
    assert_eq!(short.active_bitmap, active_bitmap_with(&[0, 1]));
    assert_eq!(final_group.assets[0].oi_eff_long_q, POS_SCALE);
    assert_eq!(final_group.assets[0].oi_eff_short_q, POS_SCALE);
    assert_eq!(final_group.assets[2].oi_eff_long_q, prediction_q);
    assert_eq!(final_group.assets[2].oi_eff_short_q, prediction_q);
    // v17: cfg.admin replaced by cfg.marketauth (matrix row 27).
    assert_eq!(cfg.marketauth, state::read_market(&market.data).unwrap().0.marketauth);
}

#[test]
fn v16_wrapper_reactivated_asset_resets_prior_oracle_profile() {
    let mut admin = signer();
    let mut market = market_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        1,
        1_000_000,
    )
    .unwrap();
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 2,
            now_slot: 2,
            initial_mark_e6: 123_000,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    assert_eq!(
        state::read_asset_oracle_profile(&market.data, 2)
            .unwrap()
            .oracle_mode,
        ORACLE_MODE_EWMA_MARK
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        2,
        0,
        0,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        2,
        3,
        0,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        4,
        500_000,
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 2).unwrap();
    assert_eq!(group.assets[2].effective_price, 500_000);
    assert_eq!(
        profile.oracle_mode, ORACLE_MODE_MANUAL,
        "reactivating a retired asset slot must not inherit its previous market's price-managed profile"
    );
    assert_eq!(profile.oracle_target_price_e6, 500_000);
    assert_eq!(profile.mark_ewma_e6, 500_000);
    assert_eq!(profile.last_good_oracle_slot, 4);
}

#[test]
fn v16_wrapper_retired_asset_profile_cannot_refresh_market_liveness() {
    let mut admin = signer();
    let mut market = market_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
            }
        }),
    );
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        1,
        1_000_000,
    )
    .unwrap();
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 2,
            now_slot: 1,
            initial_mark_e6: 123_000,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        2,
        0,
        0,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        2,
        2,
        0,
    )
    .unwrap();

    let retired_profile = state::read_asset_oracle_profile(&market.data, 2).unwrap();
    assert_eq!(
        retired_profile.oracle_mode, ORACLE_MODE_MANUAL,
        "retired slots must not keep a price-managed profile that can refresh global liveness"
    );
    let before_push = market.data.clone();
    let stale_refresh = run_ix(
        Instruction::PushEwmaMark {
            asset_index: 2,
            now_slot: 4,
            mark_e6: 222_000,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(stale_refresh, &market, &before_push);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9001 },
        &mut [&mut market],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
}

#[test]
fn v16_wrapper_three_asset_hybrid_prediction_shutdown_reuses_only_prediction_slot() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *max_portfolio_assets = 3;
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
                *maintenance_fee_per_slot = 3;
            }
        }),
    );

    let feeds = [[0xe1u8; 32], [0xe2u8; 32], [0xe3u8; 32]];
    let mut stoxx_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut stoxx_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        2,
        0,
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    let prediction_q = POS_SCALE / 100;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 133_333,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: prediction_q as i128,
            exec_price: 1_000_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 2,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 250,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    assert_eq!(before_cfg.oracle_mode, ORACLE_MODE_HYBRID_AFTER_HOURS);
    assert_eq!(before_group.assets[0].effective_price, 133_333);
    assert_eq!(before_group.assets[1].effective_price, 100);
    assert_eq!(before_group.assets[2].effective_price, 100);

    // Once the external asset-0 oracle is soft-stale, a prediction-asset
    // crank must still use the prediction asset's own supplied price. The
    // asset-0 hybrid EWMA/composite is not a valid price for asset 1.
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: before_group.current_slot + 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut long_account],
    )
    .unwrap();
    let (after_prediction_crank_cfg, after_prediction_crank) =
        state::read_market(&market.data).unwrap();
    assert_eq!(
        after_prediction_crank.assets[1].effective_price, 100,
        "asset-1 prediction crank must not inherit the asset-0 hybrid fallback mark"
    );
    assert_eq!(
        after_prediction_crank_cfg.mark_ewma_e6, before_cfg.mark_ewma_e6,
        "nonzero-asset crank must not mutate the asset-0 hybrid mark"
    );
    assert_eq!(
        after_prediction_crank.assets[0].effective_price,
        before_group.assets[0].effective_price
    );
    assert_eq!(
        after_prediction_crank.assets[2].effective_price,
        before_group.assets[2].effective_price
    );

    // Drain and clear the prediction slot while the other two assets remain
    // open. This models a resolved prediction market being removed so the slot
    // can host the next prediction market.
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    )
    .unwrap();
    let blocked_new_prediction_risk = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: prediction_q as i128,
            exec_price: 1_000_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert!(blocked_new_prediction_risk.is_err());

    run_ix(
        Instruction::RebalanceReduce {
            asset_index: 1,
            reduce_q: prediction_q,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    )
    .unwrap();
    run_ix(
        Instruction::ForfeitRecoveryLeg {
            asset_index: 1,
            b_delta_budget: 1,
        },
        &mut [&mut short_owner, &mut market, &mut short_account],
    )
    .unwrap();
    run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 1,
            side: 0,
        },
        &mut [&mut market],
    )
    .unwrap();
    run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 1,
            side: 1,
        },
        &mut [&mut market],
    )
    .unwrap();

    let (_, cleared_group) = state::read_market(&market.data).unwrap();
    let long_after_clear = state::read_portfolio(&long_account.data).unwrap();
    let short_after_clear = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(long_after_clear.active_bitmap, active_bitmap_with(&[0, 2]));
    assert_eq!(short_after_clear.active_bitmap, active_bitmap_with(&[0, 2]));
    assert_eq!(cleared_group.assets[1].oi_eff_long_q, 0);
    assert_eq!(cleared_group.assets[1].oi_eff_short_q, 0);
    assert_eq!(cleared_group.assets[0].oi_eff_long_q, POS_SCALE);
    assert_eq!(cleared_group.assets[2].oi_eff_long_q, 2 * POS_SCALE);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let prediction_budget = group.insurance_domain_budget[2] + group.insurance_domain_budget[3];
        group.insurance -= prediction_budget;
        group.vault -= prediction_budget;
        group.insurance_domain_budget[2] = 0;
        group.insurance_domain_budget[3] = 0;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let (_, cleared_group) = state::read_market(&market.data).unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        cleared_group.current_slot + 1,
        0,
    )
    .unwrap();
    let retired = state::read_market(&market.data).unwrap().1;
    let old_prediction_market_id = retired.assets[1].market_id;
    let next_market_id = retired.next_market_id;

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        retired.current_slot + 1,
        750_000,
    )
    .unwrap();
    let (_, reused_group) = state::read_market(&market.data).unwrap();
    assert_eq!(reused_group.assets[1].market_id, next_market_id);
    assert!(reused_group.assets[1].market_id > old_prediction_market_id);
    assert_eq!(reused_group.assets[1].effective_price, 750_000);
    assert_eq!(
        reused_group.assets[0].effective_price,
        before_group.assets[0].effective_price
    );
    assert_eq!(reused_group.assets[2].effective_price, 100);

    let mut stale_prediction_leg = state::read_portfolio(&long_account.data).unwrap();
    stale_prediction_leg.legs[1] = PortfolioLegV16 {
        active: true,
        asset_index: 1,
        market_id: old_prediction_market_id,
        side: SideV16::Long,
        basis_pos_q: prediction_q as i128,
        a_basis: percolator::ADL_ONE,
        k_snap: 0,
        f_snap: 0,
        epoch_snap: 0,
        loss_weight: prediction_q,
        b_snap: 0,
        b_rem: 0,
        b_epoch_snap: 0,
        b_stale: false,
        stale: false,
    };
    stale_prediction_leg.active_bitmap = active_bitmap_with(&[0, 1, 2]);
    state::write_portfolio(&mut long_account.data, &stale_prediction_leg).unwrap();
    let before_stale_trade = market.data.clone();
    let stale_reuse_trade = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: prediction_q as i128,
            exec_price: 750_000,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(stale_reuse_trade, &market, &before_stale_trade);
}

#[test]
fn v16_wrapper_security_sweep_reused_asset_market_ids_fail_closed() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 1;
            }
        }),
    );
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);

    let invalid_index = 3u16;
    let last_asset = 1u16;
    let before_invalid = market.data.clone();
    assert_err_and_market_unchanged(
        update_asset_lifecycle(
            &mut admin,
            &mut market,
            processor::ASSET_ACTION_ACTIVATE,
            invalid_index,
            1,
            200,
        ),
        &market,
        &before_invalid,
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        last_asset,
        1,
        200,
    )
    .unwrap();
    let activated = state::read_market(&market.data).unwrap().1;
    assert_eq!(
        activated.config.max_market_slots as usize, 2,
        "activating the next append slot grows the configured market-slot set"
    );
    let old_market_id = activated.assets[last_asset as usize].market_id;
    let next_market_id_before = activated.next_market_id;

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        last_asset,
        2,
        0,
    )
    .unwrap();
    let retired = state::read_market(&market.data).unwrap().1;
    assert_eq!(
        retired.assets[last_asset as usize].lifecycle,
        AssetLifecycleV16::Retired
    );

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        last_asset,
        retired.current_slot + 1,
        250,
    )
    .unwrap();
    let reactivated = state::read_market(&market.data).unwrap().1;
    let new_market_id = reactivated.assets[last_asset as usize].market_id;
    assert_eq!(new_market_id, next_market_id_before);
    assert!(new_market_id > old_market_id);
    assert_eq!(reactivated.next_market_id, next_market_id_before + 1);

    let mut pass_count = 1usize; // invalid gap append rejection above.
    let mut stale = state::read_portfolio(&long_account.data).unwrap();
    stale.legs[0] = PortfolioLegV16 {
        active: true,
        asset_index: last_asset as u32,
        market_id: old_market_id,
        side: SideV16::Long,
        basis_pos_q: POS_SCALE as i128,
        a_basis: percolator::ADL_ONE,
        k_snap: 0,
        f_snap: 0,
        epoch_snap: 0,
        loss_weight: POS_SCALE,
        b_snap: 0,
        b_rem: 0,
        b_epoch_snap: 0,
        b_stale: false,
        stale: false,
    };
    stale.active_bitmap = active_bitmap_with(&[0]);
    state::write_portfolio(&mut long_account.data, &stale).unwrap();
    let stale_market = market.data.clone();
    let stale_portfolio = long_account.data.clone();

    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let mut source = user_token_account(long_owner.key, mint, 1);
    let mut vault = vault_token_account(&market, mint, 1);
    let mut token_program = token_program_account();
    let deposit_stale = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut long_owner,
            &mut market,
            &mut long_account,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(deposit_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let mut dest = user_token_account(long_owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let withdraw_stale = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut long_owner,
            &mut market,
            &mut long_account,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(withdraw_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let sync_stale = sync_maintenance_fee(&mut market, &mut long_account, 10);
    assert_err_and_market_unchanged(sync_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let refresh_stale = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: last_asset,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(refresh_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let trade_stale = run_ix(
        Instruction::TradeNoCpi {
            asset_index: last_asset,
            size_q: POS_SCALE as i128,
            exec_price: 250,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(trade_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let reduce_stale = run_ix(
        Instruction::RebalanceReduce {
            asset_index: last_asset,
            reduce_q: 1,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(reduce_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let forfeit_stale = run_ix(
        Instruction::ForfeitRecoveryLeg {
            asset_index: last_asset,
            b_delta_budget: 1,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(forfeit_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    let close_stale = run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(close_stale, &market, &stale_market);
    assert_eq!(long_account.data, stale_portfolio);
    pass_count += 1;

    // v17: source_claim_market_id is a sparse vec sized to occupied entries (0 for fresh
    // portfolio). To inject a claim at domain = last_asset * 2 we must read with enough
    // domain capacity so all parallel Vecs have length >= domain + 1.
    let mut source_claim_stale =
        *state::read_portfolio_boxed_for_market_slots(&long_account.data, last_asset as usize + 1)
            .unwrap();
    source_claim_stale.legs[0] = PortfolioLegV16::EMPTY;
    source_claim_stale.active_bitmap = active_bitmap_with(&[]);
    let domain = last_asset as usize * 2;
    source_claim_stale.source_claim_market_id[domain] = old_market_id;
    source_claim_stale.source_claim_bound_num[domain] = BOUND_SCALE;
    state::write_portfolio(&mut long_account.data, &source_claim_stale).unwrap();
    let source_claim_portfolio = long_account.data.clone();
    let source_claim_sync = sync_maintenance_fee(&mut market, &mut long_account, 10);
    assert_err_and_market_unchanged(source_claim_sync, &market, &stale_market);
    assert_eq!(long_account.data, source_claim_portfolio);
    pass_count += 1;

    let mut close_progress_stale = state::read_portfolio(&long_account.data).unwrap();
    close_progress_stale.source_claim_market_id[domain] = 0;
    close_progress_stale.source_claim_bound_num[domain] = 0;
    close_progress_stale.close_progress = CloseProgressLedgerV16 {
        active: true,
        finalized: false,
        canceled: false,
        close_id: 1,
        asset_index: last_asset as u32,
        market_id: old_market_id,
        domain_side: SideV16::Long,
        gross_loss_at_close_start: 1,
        drift_reference_slot: reactivated.current_slot,
        max_close_slot: reactivated.current_slot + 10,
        residual_remaining: 1,
        ..CloseProgressLedgerV16::EMPTY
    };
    state::write_portfolio(&mut long_account.data, &close_progress_stale).unwrap();
    let close_progress_portfolio = long_account.data.clone();
    let close_progress_sync = sync_maintenance_fee(&mut market, &mut long_account, 10);
    assert_err_and_market_unchanged(close_progress_sync, &market, &stale_market);
    assert_eq!(long_account.data, close_progress_portfolio);
    pass_count += 1;

    let mut clean = state::read_portfolio(&long_account.data).unwrap();
    clean.close_progress = CloseProgressLedgerV16::EMPTY;
    state::write_portfolio(&mut long_account.data, &clean).unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: last_asset,
            size_q: POS_SCALE as i128,
            exec_price: 250,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    pass_count += 1;

    assert!(
        pass_count >= 10,
        "security sweep must retain at least ten fail-closed/pass-safe probes for reused market ids"
    );
}

#[test]
fn v16_wrapper_security_sweep_resolved_market_and_fee_branches() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *max_portfolio_assets = 1;
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        125,
    )
    .unwrap();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 100);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved = state::read_market(&market.data).unwrap().1;
    assert_eq!(resolved.mode, MarketModeV16::Resolved);
    assert_eq!(resolved.resolved_slot, 10);

    let before_asset_mutation = market.data.clone();
    let lifecycle_after_resolve = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        11,
        0,
    );
    assert_err_and_market_unchanged(lifecycle_after_resolve, &market, &before_asset_mutation);

    sync_maintenance_fee(&mut market, &mut portfolio, 100).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        account.last_fee_slot, 10,
        "resolved fee sync must anchor at resolved_slot, not caller-supplied now_slot"
    );
    assert_eq!(
        account.capital, 55,
        "resolved fees start at the portfolio creation fee slot"
    );
    assert_eq!(group.insurance, 45);
    assert_eq!(group.c_tot, 55);

    let after_fee = market.data.clone();
    let after_fee_portfolio = portfolio.data.clone();
    sync_maintenance_fee(&mut market, &mut portfolio, 200).unwrap();
    assert_eq!(
        market.data, after_fee,
        "resolved fee sync must be idempotent after resolved_slot is reached"
    );
    assert_eq!(portfolio.data, after_fee_portfolio);
}

#[test]
fn v16_wrapper_account_layout_constants_match_serialized_state() {
    assert_eq!(
        MARKET_GROUP_LEN,
        core::mem::size_of::<MarketGroupV16HeaderAccount>()
    );
    assert_eq!(
        PORTFOLIO_STATE_LEN,
        core::mem::size_of::<PortfolioAccountV16Account>()
    );
    assert_eq!(
        WRAPPER_CONFIG_LEN,
        core::mem::size_of::<state::WrapperConfigV16>()
    );
    assert_eq!(core::mem::align_of::<MarketGroupV16HeaderAccount>(), 1);
    assert_eq!(core::mem::align_of::<PortfolioAccountV16Account>(), 1);
    assert_eq!(
        MARKET_ASSET_SLOT_LEN,
        core::mem::size_of::<percolator::Market<[u8; ASSET_ORACLE_WRAPPER_LEN]>>(),
        "one dynamic market slot stores wrapper oracle storage plus the engine asset slot"
    );
    assert_eq!(
        MARKET_ACCOUNT_LEN,
        HEADER_LEN
            + WRAPPER_CONFIG_LEN
            + MARKET_GROUP_LEN
            + DEFAULT_MARKET_SLOT_CAPACITY * MARKET_ASSET_SLOT_LEN,
        "default market account length must cover wrapper header/config + dynamic engine header + default slot table"
    );
    let grown_capacity = DEFAULT_MARKET_SLOT_CAPACITY + 1;
    assert_eq!(
        state::market_account_len_for_capacity(grown_capacity).unwrap(),
        HEADER_LEN + WRAPPER_CONFIG_LEN + MARKET_GROUP_LEN + grown_capacity * MARKET_ASSET_SLOT_LEN,
        "dynamic market account length must grow linearly with wrapper-supplied slot capacity"
    );
    // v17: PORTFOLIO_ACCOUNT_LEN is FIXED (O(1)) — source-domain storage uses a sparse embedded
    // array inside PORTFOLIO_STATE_LEN (drop runtime-vec / zero-copy convergence). The account
    // size does NOT grow with the number of market asset slots.
    assert_eq!(
        PORTFOLIO_ACCOUNT_LEN,
        HEADER_LEN + PORTFOLIO_STATE_LEN + PORTFOLIO_MATCHER_CONFIG_LEN,
        "PORTFOLIO_ACCOUNT_LEN covers fixed engine+matcher header"
    );
    // portfolio_account_len_for_market_slots returns PORTFOLIO_ACCOUNT_LEN regardless of slots.
    assert_eq!(
        state::portfolio_account_len_for_market_slots(DEFAULT_MARKET_SLOT_CAPACITY).unwrap(),
        PORTFOLIO_ACCOUNT_LEN,
        "v17: portfolio account is O(1) fixed size regardless of market slot count"
    );
    assert_eq!(
        state::portfolio_account_len_for_market_slots(grown_capacity).unwrap(),
        PORTFOLIO_ACCOUNT_LEN,
        "v17: portfolio account is O(1) fixed size regardless of market slot count"
    );
    assert_eq!(state::alignment_note(), 1);

    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let (cfg, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    let market_before = market.data.clone();
    let portfolio_before = portfolio.data.clone();
    state::write_market(&mut market.data, &cfg, &group).unwrap();
    state::write_portfolio(&mut portfolio.data, &account).unwrap();
    assert_eq!(
        market.data, market_before,
        "read/write-copy roundtrip must preserve market account bytes"
    );
    assert_eq!(
        portfolio.data, portfolio_before,
        "read/write-copy roundtrip must preserve portfolio account bytes"
    );

    let mut corrupt_market = market.data.clone();
    let market_bool_off = percolator_prog::constants::MARKET_GROUP_OFF
        + core::mem::offset_of!(MarketGroupV16HeaderAccount, bankruptcy_hlock_active);
    corrupt_market[market_bool_off] = 2;
    assert_eq!(
        state::read_market(&corrupt_market),
        Err(ProgramError::InvalidAccountData),
        "serialized bool fields must be validated before engine state is materialized"
    );
    let mut corrupt_portfolio = portfolio.data.clone();
    let close_progress_active_off = HEADER_LEN
        + core::mem::offset_of!(PortfolioAccountV16Account, close_progress)
        + core::mem::offset_of!(percolator::CloseProgressLedgerV16Account, active);
    corrupt_portfolio[close_progress_active_off] = 2;
    assert_eq!(
        state::read_portfolio(&corrupt_portfolio),
        Err(ProgramError::InvalidAccountData),
        "serialized portfolio bool fields must be validated before engine state is materialized"
    );
}

#[test]
fn v16_wrapper_raw_wrapper_config_invalid_values_fail_closed() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);

    let (cfg, _group) = state::read_market(&market.data).unwrap();
    let assert_bad_cfg = |bad_cfg: state::WrapperConfigV16, label: &str| {
        let mut corrupt = market.data.clone();
        corrupt[HEADER_LEN..HEADER_LEN + WRAPPER_CONFIG_LEN]
            .copy_from_slice(bytemuck::bytes_of(&bad_cfg));
        assert_eq!(
            state::read_market(&corrupt),
            Err(ProgramError::InvalidAccountData),
            "{}",
            label
        );
    };

    let mut bad_reward = cfg;
    bad_reward.liquidation_cranker_fee_share_bps = 10_001;
    assert_bad_cfg(
        bad_reward,
        "corrupt liquidation reward share must not be trusted on read",
    );

    let mut bad_primary_mint = cfg;
    bad_primary_mint.collateral_mint = [0u8; 32];
    assert_bad_cfg(
        bad_primary_mint,
        "primary base-unit mint must not be empty in persisted config",
    );

    let mut bad_secondary_mint = cfg;
    bad_secondary_mint.secondary_collateral_mint = cfg.collateral_mint;
    assert_bad_cfg(
        bad_secondary_mint,
        "secondary base-unit mint must not alias the primary mint",
    );

    let mut bad_maintenance_reward = cfg;
    bad_maintenance_reward.maintenance_cranker_fee_share_bps = 10_001;
    assert_bad_cfg(
        bad_maintenance_reward,
        "corrupt maintenance reward share must not be trusted on read",
    );

    let mut bad_backing_trade_fee = cfg;
    bad_backing_trade_fee.backing_trade_fee_bps_long = 10_001;
    assert_bad_cfg(
        bad_backing_trade_fee,
        "corrupt long-domain backing trade fee must not be trusted on read",
    );

    let mut bad_backing_trade_fee = cfg;
    bad_backing_trade_fee.backing_trade_fee_bps_short = 10_001;
    assert_bad_cfg(
        bad_backing_trade_fee,
        "corrupt short-domain backing trade fee must not be trusted on read",
    );

    let mut bad_oracle_mode = cfg;
    bad_oracle_mode.oracle_mode = 9;
    assert_bad_cfg(
        bad_oracle_mode,
        "retired or unknown oracle modes must fail closed",
    );

    let mut bad_manual_legs = cfg;
    bad_manual_legs.oracle_leg_count = 1;
    assert_bad_cfg(
        bad_manual_legs,
        "manual oracle mode must not carry stale hybrid leg metadata",
    );

    let mut bad_hybrid_leg = cfg;
    bad_hybrid_leg.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    bad_hybrid_leg.oracle_leg_count = 1;
    bad_hybrid_leg.max_staleness_secs = 60;
    bad_hybrid_leg.hybrid_soft_stale_slots = 1;
    bad_hybrid_leg.mark_ewma_e6 = 100;
    assert_bad_cfg(
        bad_hybrid_leg,
        "hybrid oracle mode must reject malformed persisted leg metadata",
    );

    let mut bad_ewma_mark_stale_hybrid_knob = cfg;
    bad_ewma_mark_stale_hybrid_knob.oracle_mode = ORACLE_MODE_EWMA_MARK;
    bad_ewma_mark_stale_hybrid_knob.mark_ewma_e6 = 100;
    bad_ewma_mark_stale_hybrid_knob.mark_ewma_halflife_slots = 1;
    bad_ewma_mark_stale_hybrid_knob.unit_scale = 6;
    assert_bad_cfg(
        bad_ewma_mark_stale_hybrid_knob,
        "EwmaMark oracle mode must not carry stale hybrid conversion knobs",
    );

    let mut bad_bool = cfg;
    bad_bool.insurance_withdraw_deposits_only = 2;
    assert_bad_cfg(
        bad_bool,
        "persistent wrapper booleans must reject invalid byte patterns",
    );

    let mut bad_live_insurance_policy = cfg;
    bad_live_insurance_policy.insurance_withdraw_max_bps = 10_000;
    bad_live_insurance_policy.insurance_withdraw_deposits_only = 0;
    bad_live_insurance_policy.insurance_withdraw_cooldown_slots = 1;
    assert_bad_cfg(
        bad_live_insurance_policy,
        "non-deposit-only live insurance policy must not persist a full-drain cap",
    );

    let mut bad_live_insurance_cooldown = cfg;
    bad_live_insurance_cooldown.insurance_withdraw_max_bps = 5_000;
    bad_live_insurance_cooldown.insurance_withdraw_deposits_only = 0;
    bad_live_insurance_cooldown.insurance_withdraw_cooldown_slots = 0;
    assert_bad_cfg(
        bad_live_insurance_cooldown,
        "non-deposit-only live insurance policy must not persist a zero cooldown",
    );

    let mut bad_padding = cfg;
    bad_padding._padding0 = 1;
    assert_bad_cfg(
        bad_padding,
        "wrapper config padding must stay canonical zero bytes",
    );
}

#[test]
fn v16_wrapper_init_market_rejects_invalid_mint_and_double_init() {
    let mut admin = signer();
    let mut market = market_account();
    let mut bad_mint = invalid_mint_account();

    let before = market.data.clone();
    let invalid_mint = run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut bad_mint],
    );
    assert_err_and_market_unchanged(invalid_mint, &market, &before);

    let mut good_mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut good_mint],
    )
    .unwrap();
    let initialized = market.data.clone();
    let double_init = run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut good_mint],
    );
    assert_err_and_market_unchanged(double_init, &market, &initialized);
}

#[test]
fn v16_wrapper_init_and_account_meta_guards_fail_before_mutation() {
    let mut admin = signer();
    let mut unsigned_admin = TestAccount::new(admin.key, Pubkey::new_unique(), 0);
    let mut market = market_account();
    let mut mint = mint_account();

    let before_market = market.data.clone();
    let missing_admin_signature = run_ix(
        default_init_market_ix(),
        &mut [&mut unsigned_admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(missing_admin_signature, &market, &before_market);

    market.is_writable = false;
    let nonwritable_market = run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(nonwritable_market, &market, &before_market);
    market.is_writable = true;

    market.owner = Pubkey::new_unique();
    let wrong_market_owner = run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(wrong_market_owner, &market, &before_market);
    market.owner = program_id();

    init_market(&mut admin, &mut market);
    let initialized_market = market.data.clone();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    portfolio.is_writable = false;
    let before_portfolio = portfolio.data.clone();
    let nonwritable_portfolio = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(nonwritable_portfolio, &market, &initialized_market);
    assert_eq!(portfolio.data, before_portfolio);

    portfolio.is_writable = true;
    portfolio.owner = Pubkey::new_unique();
    let wrong_portfolio_owner = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(wrong_portfolio_owner, &market, &initialized_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_init_market_rejects_invalid_engine_params_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();

    let before = market.data.clone();
    let zero_price = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket { initial_price, .. } = ix {
                *initial_price = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(zero_price, &market, &before);

    let zero_dt = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_accrual_dt_slots,
                ..
            } = ix
            {
                *max_accrual_dt_slots = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(zero_dt, &market, &before);

    let zero_price_move = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_price_move_bps_per_slot = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(zero_price_move, &market, &before);

    let invalid_min_margin_floor = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                min_nonzero_mm_req, ..
            } = ix
            {
                *min_nonzero_mm_req = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_min_margin_floor, &market, &before);

    let invalid_liq_floor = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                liquidation_fee_cap,
                min_liquidation_abs,
                ..
            } = ix
            {
                *liquidation_fee_cap = 1;
                *min_liquidation_abs = 2;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_liq_floor, &market, &before);

    let invalid_base_fee = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                ..
            } = ix
            {
                *max_trading_fee_bps = 99;
                *trade_fee_base_bps = 100;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_base_fee, &market, &before);

    let invalid_portfolio_leg_cap = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets =
                    percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS + 1;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_portfolio_leg_cap, &market, &before);

    let invalid_funding_cap = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_abs_funding_e9_per_slot,
                ..
            } = ix
            {
                *max_abs_funding_e9_per_slot = 10_001;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_funding_cap, &market, &before);

    let invalid_b_budget = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_account_b_settlement_chunks,
                ..
            } = ix
            {
                *max_account_b_settlement_chunks = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_b_budget, &market, &before);

    let invalid_bankrupt_close_lifetime = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_bankrupt_close_lifetime_slots,
                ..
            } = ix
            {
                *max_bankrupt_close_lifetime_slots = 0;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_bankrupt_close_lifetime, &market, &before);

    let invalid_h_max = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket { h_max, .. } = ix {
                *h_max = (BOUND_SCALE as u64) + 1;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_h_max, &market, &before);

    let invalid_maintenance_fee = run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = percolator::MAX_PROTOCOL_FEE_ABS + 1;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    );
    assert_err_and_market_unchanged(invalid_maintenance_fee, &market, &before);
}

#[test]
fn v16_wrapper_init_portfolio_requires_signer_and_rejects_double_init_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut unsigned_owner = TestAccount::new(owner.key, Pubkey::new_unique(), 0);
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let missing_signature = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut unsigned_owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(missing_signature, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let initialized_market = market.data.clone();
    let initialized_portfolio = portfolio.data.clone();
    let double_init = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(double_init, &market, &initialized_market);
    assert_eq!(
        portfolio.data, initialized_portfolio,
        "double init must fail before market materialized-count mutation"
    );
}

#[test]
fn v16_wrapper_top_up_insurance_requires_authority_and_updates_vault() {
    let mut admin = signer();
    let mut market = market_account();
    let mut attacker = signer();

    let mint = init_market(&mut admin, &mut market);
    let mut attacker_src = user_token_account(attacker.key, mint, 777);
    let mut admin_src = user_token_account(admin.key, mint, 777);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();

    let before = market.data.clone();
    let unauthorized = run_ix(
        Instruction::TopUpInsurance { amount: 777 },
        &mut [
            &mut attacker,
            &mut market,
            &mut attacker_src,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before);

    run_ix(
        Instruction::TopUpInsurance { amount: 777 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_src,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 777);
    assert_eq!(group.vault, 777);
}

#[test]
fn v16_wrapper_top_up_insurance_rejects_wrong_mint_and_insufficient_source_balance() {
    let mut admin = signer();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let mut wrong_source = user_token_account(admin.key, Pubkey::new_unique(), 777);
    let mut short_source = user_token_account(admin.key, mint, 776);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let wrong_mint = run_ix(
        Instruction::TopUpInsurance { amount: 777 },
        &mut [
            &mut admin,
            &mut market,
            &mut wrong_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_mint, &market, &before);

    let short_balance = run_ix(
        Instruction::TopUpInsurance { amount: 777 },
        &mut [
            &mut admin,
            &mut market,
            &mut short_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(short_balance, &market, &before);
}

#[test]
fn v16_wrapper_top_up_paths_reject_after_permissionless_resolve_maturity() {
    let mut admin = signer();
    let mut market = market_account();
    let mut bucket_authority = signer();

    let mint = init_market(&mut admin, &mut market);
    // v17: backing_bucket_authority is a per-asset profile field; rotate via UpdateAssetAuthority.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: bucket_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut bucket_authority, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 9000;
        group.slot_last = 9000;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before = market.data.clone();
    let top_up_insurance = run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(top_up_insurance, &market, &before);

    let mut source = user_token_account(bucket_authority.key, mint, 100);
    let before = market.data.clone();
    let mut __lg4 = canonical_backing_ledger_account(&market, 1);
    let mut __sp4 = system_program_account();
    let top_up_backing = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg4,
        &mut __sp4,
    ],
    );
    assert_err_and_market_unchanged(top_up_backing, &market, &before);
}

#[test]
fn v16_wrapper_resolved_insurance_authority_can_withdraw_all_remaining_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    // v17: UpdateInsurancePolicy (tag 33) deleted — terminal WithdrawInsurance needs no
    // rate-limit config; resolved mode + authority check is sufficient (matrix row 35).

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut vault_auth = vault_authority_account(&market);
    run_ix(
        Instruction::WithdrawInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_wrapper_resolved_insurance_withdraw_rejects_live_wrong_authority_and_open_accounts() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let live = market.data.clone();
    let live_reject = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(live_reject, &market, &live);

    init_portfolio(&mut owner, &mut market, &mut portfolio);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved_with_open = market.data.clone();
    let open_reject = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(open_reject, &market, &resolved_with_open);

    let wrong_auth = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut attacker,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert!(wrong_auth.is_err());
}

#[test]
fn v16_wrapper_update_asset_authority_rejects_after_resolve_to_freeze_terminal_claims() {
    let mut admin = signer();
    let mut admin_cosigner = TestAccount::new(admin.key, Pubkey::new_unique(), 0).signer();
    let mut insurance = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: insurance.key.to_bytes(),
        },
        &mut [&mut admin, &mut insurance, &mut market],
    )
    .unwrap();
    let mut source = user_token_account(insurance.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut insurance,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let resolved = market.data.clone();
    let rotate_after_resolve = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: admin.key.to_bytes(),
        },
        &mut [&mut admin, &mut admin_cosigner, &mut market],
    );
    assert_err_and_market_unchanged(rotate_after_resolve, &market, &resolved);

    let mut vault_auth = vault_authority_account(&market);
    let mut admin_dest = user_token_account(admin.key, mint, 0);
    let admin_terminal = run_ix(
        Instruction::WithdrawInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(admin_terminal, &market, &resolved);

    let mut insurance_dest = user_token_account(insurance.key, mint, 0);
    run_ix(
        Instruction::WithdrawInsurance { amount: 100 },
        &mut [
            &mut insurance,
            &mut market,
            &mut insurance_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_wrapper_dynamic_asset_stores_domain_authorities_and_rejects_zero_authority() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);

    let insurance_authority = Pubkey::new_unique().to_bytes();
    let insurance_operator = Pubkey::new_unique().to_bytes();
    let backing_bucket_authority = Pubkey::new_unique().to_bytes();
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
        insurance_authority,
        insurance_operator,
        backing_bucket_authority,
    )
    .unwrap();

    let profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(profile.insurance_authority, insurance_authority);
    assert_eq!(profile.insurance_operator, insurance_operator);
    assert_eq!(profile.backing_bucket_authority, backing_bucket_authority);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance_domain_budget[2], 0);
    assert_eq!(group.insurance_domain_budget[3], 0);
    assert_eq!(group.insurance_domain_spent[2], 0);
    assert_eq!(group.insurance_domain_spent[3], 0);

    let before = market.data.clone();
    let reject = update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        2,
        100,
        [0u8; 32],
        insurance_operator,
        backing_bucket_authority,
    );
    assert_err_and_market_unchanged(reject, &market, &before);
}

#[test]
fn v16_wrapper_non_main_domain_insurance_isolated_from_global_withdrawals() {
    let mut admin = signer();
    let mut market = market_account();
    let mut insurance_authority = signer();
    let mut insurance_operator = signer();
    let backing_bucket_authority = Pubkey::new_unique().to_bytes();
    let mint = init_market(&mut admin, &mut market);

    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
        insurance_authority.key.to_bytes(),
        insurance_operator.key.to_bytes(),
        backing_bucket_authority,
    )
    .unwrap();

    let mut source = user_token_account(insurance_authority.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsuranceDomain {
            domain: 2,
            amount: 100,
        },
        &mut [
            &mut insurance_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 100);
    assert_eq!(group.vault, 100);
    assert_eq!(group.insurance_domain_budget[2], 100);

    // v17: UpdateInsurancePolicy (tag 33) deleted; global WithdrawInsurance requires
    // resolved mode so always rejected on a live market (matrix row 35). No policy needed.
    let before_global_withdraw = market.data.clone();
    let mut global_dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut vault_auth = vault_authority_account(&market);
    let global_withdraw = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut global_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(global_withdraw, &market, &before_global_withdraw);

    let mut domain_dest = user_token_account(insurance_operator.key, mint, 0);
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 100,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut domain_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);
    assert_eq!(group.insurance_domain_budget[2], 0);
}

#[test]
fn v16_wrapper_domain_withdrawals_reject_admin_before_shutdown_and_accept_secondary_mint() {
    let mut admin = signer();
    let mut market = market_account();
    let mut primary_mint = mint_account();
    let primary_key = primary_mint.key;
    let mut secondary_mint = mint_account();
    let secondary_key = secondary_mint.key;
    let mut insurance_authority = signer();
    let mut insurance_operator = signer();
    let mut backing_authority = signer();

    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut primary_mint],
    )
    .unwrap();
    configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut primary_mint,
        &mut secondary_mint,
    )
    .unwrap();
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
        insurance_authority.key.to_bytes(),
        insurance_operator.key.to_bytes(),
        backing_authority.key.to_bytes(),
    )
    .unwrap();

    let mut token_program = token_program_account();
    let mut insurance_source = user_token_account(insurance_authority.key, primary_key, 11);
    let mut primary_vault = vault_token_account(&market, primary_key, 0);
    run_ix(
        Instruction::TopUpInsuranceDomain {
            domain: 2,
            amount: 11,
        },
        &mut [
            &mut insurance_authority,
            &mut market,
            &mut insurance_source,
            &mut primary_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let mut backing_source = user_token_account(backing_authority.key, primary_key, 30);
    let mut __lg5 = canonical_backing_ledger_account(&market, 2);
    let mut __sp5 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 30,
            expiry_slot: 10,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_source,
            &mut primary_vault,
            &mut token_program,
        
        &mut __lg5,
        &mut __sp5,
    ],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.source_backing_buckets[2].utilization_fee_earnings = 7;
        group.vault += 7;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut vault_auth = vault_authority_account(&market);
    let mut admin_dest = user_token_account(admin.key, secondary_key, 0);
    let mut secondary_vault = vault_token_account(&market, secondary_key, 48);
    let before_admin_insurance = market.data.clone();
    let admin_insurance = run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(admin_insurance, &market, &before_admin_insurance);

    let before_admin_backing = market.data.clone();
    let mut __lg6 = canonical_backing_ledger_account(&market, 2);
    let admin_backing = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 2,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg6,
    ],
    );
    assert_err_and_market_unchanged(admin_backing, &market, &before_admin_backing);

    let mut admin_backing_ledger = backing_domain_ledger_account();
    let before_admin_earnings = market.data.clone();
    let admin_earnings = run_ix(
        Instruction::WithdrawBackingBucketEarnings {
            domain: 2,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_backing_ledger,
            &mut admin_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(admin_earnings, &market, &before_admin_earnings);

    let mut mismatched_dest = user_token_account(insurance_operator.key, secondary_key, 0);
    let mut mismatched_primary_vault = vault_token_account(&market, primary_key, 48);
    let before_mismatched_mints = market.data.clone();
    let mismatched_mints = run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 1,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut mismatched_dest,
            &mut mismatched_primary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(mismatched_mints, &market, &before_mismatched_mints);

    let mut secondary_vault = vault_token_account(&market, secondary_key, 48);
    let mut insurance_dest = user_token_account(insurance_operator.key, secondary_key, 0);
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 1,
            amount: 11,
        },
        &mut [
            &mut insurance_operator,
            &mut market,
            &mut insurance_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let mut backing_ledger = backing_domain_ledger_account();
    let mut backing_dest = user_token_account(backing_authority.key, secondary_key, 0);
    run_ix(
        Instruction::WithdrawBackingBucketEarnings {
            domain: 2,
            amount: 7,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_ledger,
            &mut backing_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let mut __lg7 = canonical_backing_ledger_account(&market, 2);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 2,
            amount: 30,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut backing_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg7,
    ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.insurance, 0);
    assert_eq!(group.insurance_domain_budget[2], 0);
    assert_eq!(
        group.source_backing_buckets[2].fresh_unliened_backing_num,
        0
    );
    assert_eq!(group.source_backing_buckets[2].utilization_fee_earnings, 0);
}

#[test]
fn v16_wrapper_backing_bucket_authority_is_domain_scoped_for_dynamic_assets() {
    let mut admin = signer();
    let mut market = market_account();
    let mut backing_authority = signer();
    let mint = init_market(&mut admin, &mut market);

    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
        Pubkey::new_unique().to_bytes(),
        Pubkey::new_unique().to_bytes(),
        backing_authority.key.to_bytes(),
    )
    .unwrap();

    let before = market.data.clone();
    let mut admin_source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg6 = canonical_backing_ledger_account(&market, 2);
    let mut __sp6 = system_program_account();
    let unauthorized = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 10,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg6,
        &mut __sp6,
    ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before);

    let mut source = user_token_account(backing_authority.key, mint, 10);
    let mut __lg7 = canonical_backing_ledger_account(&market, 2);
    let mut __sp7 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 10,
            expiry_slot: 10,
        },
        &mut [
            &mut backing_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg7,
        &mut __sp7,
    ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.source_backing_buckets[2].fresh_unliened_backing_num,
        10 * BOUND_SCALE
    );
}

#[test]
fn v16_wrapper_asset_zero_cannot_be_retired() {
    let mut admin = signer();
    let mut market = market_account();

    init_market(&mut admin, &mut market);
    let before = market.data.clone();
    let retire_base = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        0,
        1,
        0,
    );
    assert_err_and_market_unchanged(retire_base, &market, &before);

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.free_market_slot_count, 0);
    assert_eq!(group.assets[0].lifecycle, AssetLifecycleV16::Active);
}

#[test]
fn v16_wrapper_asset_retire_rejects_nonzero_domain_insurance_budget() {
    let mut admin = signer();
    let mut market = market_account();
    let mut insurance_authority = signer();
    let mint = init_market(&mut admin, &mut market);

    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
        insurance_authority.key.to_bytes(),
        Pubkey::new_unique().to_bytes(),
        Pubkey::new_unique().to_bytes(),
    )
    .unwrap();
    let mut source = user_token_account(insurance_authority.key, mint, 1);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsuranceDomain {
            domain: 2,
            amount: 1,
        },
        &mut [
            &mut insurance_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    )
    .unwrap();
    let before_retire = market.data.clone();
    let retire = update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_RETIRE,
        1,
        10,
        0,
    );
    assert_err_and_market_unchanged(retire, &market, &before_retire);
}

#[test]
fn v16_wrapper_top_up_backing_bucket_uses_separate_authority_and_domain_ledger() {
    let mut admin = signer();
    let mut market = market_account();
    let mut bucket_authority = signer();
    let mut attacker = signer();

    let mint = init_market(&mut admin, &mut market);
    // v17: backing_bucket_authority is per-asset; use UpdateAssetAuthority for asset-0.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: bucket_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut bucket_authority, &mut market],
    )
    .unwrap();

    let before = market.data.clone();
    let mut attacker_src = user_token_account(attacker.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg8 = canonical_backing_ledger_account(&market, 1);
    let mut __sp8 = system_program_account();
    let unauthorized = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut attacker,
            &mut market,
            &mut attacker_src,
            &mut vault,
            &mut token_program,
        
        &mut __lg8,
        &mut __sp8,
    ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before);

    let mut source = user_token_account(bucket_authority.key, mint, 100);
    let mut __lg9 = canonical_backing_ledger_account(&market, 1);
    let mut __sp9 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg9,
        &mut __sp9,
    ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    // v17: backing_bucket_authority is a per-asset profile field (not on WrapperConfigV16).
    let profile0 = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile0.backing_bucket_authority,
        bucket_authority.key.to_bytes()
    );
    assert_eq!(group.insurance, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.vault, 100);
    assert_eq!(
        group.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh
    );
    assert_eq!(group.source_backing_buckets[1].expiry_slot, 10);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        100 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        100 * BOUND_SCALE
    );

    let before_bad_domain = market.data.clone();
    let mut source = user_token_account(bucket_authority.key, mint, 1);
    let mut __lg10 = canonical_backing_ledger_account(&market, 32);
    let mut __sp10 = system_program_account();
    let bad_domain = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 32,
            amount: 1,
            expiry_slot: 10,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg10,
        &mut __sp10,
    ],
    );
    assert_err_and_market_unchanged(bad_domain, &market, &before_bad_domain);

    let before_inactive_domain = market.data.clone();
    let mut source = user_token_account(bucket_authority.key, mint, 1);
    let mut __lg11 = canonical_backing_ledger_account(&market, 2);
    let mut __sp11 = system_program_account();
    let inactive_domain = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 1,
            expiry_slot: 10,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg11,
        &mut __sp11,
    ],
    );
    assert_err_and_market_unchanged(inactive_domain, &market, &before_inactive_domain);

    let before_bad_expiry = market.data.clone();
    let mut source = user_token_account(bucket_authority.key, mint, 1);
    let mut __lg12 = canonical_backing_ledger_account(&market, 1);
    let mut __sp12 = system_program_account();
    let bad_expiry = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 1,
            expiry_slot: 0,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg12,
        &mut __sp12,
    ],
    );
    assert_err_and_market_unchanged(bad_expiry, &market, &before_bad_expiry);

    // v17: backing_bucket_authority cannot be burned to zero (only ASSET_AUTH_ADMIN is
    // burnable); UpdateAssetAuthority rejects zero new_pubkey for non-admin kinds.
    let mut zero_new = TestAccount::new(Pubkey::default(), Pubkey::new_unique(), 0);
    let burn_rejected = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: [0u8; 32],
        },
        &mut [&mut bucket_authority, &mut zero_new, &mut market],
    );
    assert_err_and_market_unchanged(burn_rejected, &market, &before_bad_expiry);
}

#[test]
fn v16_wrapper_withdraw_backing_bucket_returns_only_unencumbered_backing() {
    let mut admin = signer();
    let mut market = market_account();
    let mut bucket_authority = signer();
    let mut attacker = signer();

    let mint = init_market(&mut admin, &mut market);
    let (ledger_key, _) = state::derive_lp_backing_ledger(&program_id(), &market.key, 1);
    let mut ledger = TestAccount::new(
        ledger_key,
        program_id(),
        state::backing_domain_ledger_account_len(),
    )
    .writable();
    // v17: backing_bucket_authority is per-asset; use UpdateAssetAuthority for asset-0.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: bucket_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut bucket_authority, &mut market],
    )
    .unwrap();

    let mut source = user_token_account(bucket_authority.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    let mut __lg13 = canonical_backing_ledger_account(&market, 1);
    let mut __sp13 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp13,
    ],
    )
    .unwrap();

    let (_, after_topup_group) = state::read_market(&market.data).unwrap();
    let risk_epoch_after_topup = after_topup_group.risk_epoch;
    let source_epoch_after_topup = after_topup_group.source_credit[1].credit_epoch;

    let topped_up = market.data.clone();
    let ledger_before = ledger.data.clone();
    let mut attacker_dest = user_token_account(attacker.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut __lg8 = canonical_backing_ledger_account(&market, 1);
    let unauthorized = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut attacker,
            &mut market,
            &mut attacker_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg8,
    ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &topped_up);
    assert_eq!(ledger.data, ledger_before);

    let mut impostor_ledger = backing_domain_ledger_account();
    let mut substituted_dest = user_token_account(bucket_authority.key, mint, 0);
    let mut __lg9 = canonical_backing_ledger_account(&market, 1);
    let substituted_ledger = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut substituted_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut impostor_ledger,
        
    ],
    );
    assert_err_and_market_unchanged(substituted_ledger, &market, &topped_up);
    assert_eq!(ledger.data, ledger_before);

    let mut dest = user_token_account(bucket_authority.key, mint, 0);
    let mut __lg10 = canonical_backing_ledger_account(&market, 1);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 40,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.vault, 60);
    assert_eq!(group.insurance, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(
        group.risk_epoch,
        risk_epoch_after_topup + 1,
        "withdrawing fresh backing changes risk inputs and must stale existing health certificates"
    );
    assert_eq!(
        group.source_credit[1].credit_epoch,
        source_epoch_after_topup + 1,
        "backing withdrawal must mirror engine source-credit mutation epoch semantics"
    );
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        60 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        60 * BOUND_SCALE
    );
    let ledger_after_withdraw = state::read_backing_domain_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_after_withdraw.total_principal_atoms, 60);
    assert_eq!(ledger_after_withdraw.total_principal_withdrawn_atoms, 40);

    let before_overdraw = market.data.clone();
    let mut __lg11 = canonical_backing_ledger_account(&market, 1);
    let overdraw = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 61,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    );
    assert_err_and_market_unchanged(overdraw, &market, &before_overdraw);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.source_credit[1].positive_claim_bound_num = 40 * BOUND_SCALE;
        group.source_credit[1].exact_positive_claim_num = 40 * BOUND_SCALE;
        group.source_credit[1].credit_rate_num = percolator::CREDIT_RATE_SCALE;
        // RESYNC(4d2ccab/5ebd136): keep the hand-crafted state consistent with the
        // engine's global junior-bound aggregation invariant (validate_shape
        // requires pnl_pos_bound_tot_num >= sum of per-domain
        // positive_claim_bound_num) so the watermark-gated withdraw sees a valid
        // shape (matches toly 574a7a1).
        group.pnl_pos_bound_tot_num = 40 * BOUND_SCALE;
        group.pnl_pos_bound_tot = 40;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let mut __lg12 = canonical_backing_ledger_account(&market, 1);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 20,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        40 * BOUND_SCALE,
        "withdrawal should let the authority lower the domain watermark to live demand"
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        40 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].credit_rate_num,
        percolator::CREDIT_RATE_SCALE,
        "withdrawing above the watermark must not dilute existing claims"
    );

    let claim_backed = market.data.clone();
    let mut __lg13 = canonical_backing_ledger_account(&market, 1);
    let claim_dilution = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut bucket_authority,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    );
    assert_err_and_market_unchanged(claim_dilution, &market, &claim_backed);
}

#[test]
fn v16_wrapper_withdraw_backing_bucket_rejects_stress_and_allows_full_clean_drain() {
    let mut admin = signer();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let (ledger_key, _) = state::derive_lp_backing_ledger(&program_id(), &market.key, 1);
    let mut ledger = TestAccount::new(
        ledger_key,
        program_id(),
        state::backing_domain_ledger_account_len(),
    )
    .writable();
    let mut source = user_token_account(admin.key, mint, 25);
    let mut vault = vault_token_account(&market, mint, 25);
    let mut token_program = token_program_account();
    let mut __lg14 = canonical_backing_ledger_account(&market, 1);
    let mut __sp14 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 25,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp14,
    ],
    )
    .unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut __lg14 = canonical_backing_ledger_account(&market, 1);
    let zero = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 0,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    );
    assert!(zero.is_err());

    let topped_up = market.data.clone();
    let stress_cases: &[fn(&mut MarketGroupV16)] = &[
        |group| group.bankruptcy_hlock_active = true,
        |group| group.threshold_stress_active = true,
        |group| group.loss_stale_active = true,
        |group| group.recovery_reason = Some(PermissionlessRecoveryReasonV16::BelowProgressFloor),
    ];
    for set_stress in stress_cases {
        let (cfg, mut group) = state::read_market(&topped_up).unwrap();
        set_stress(&mut group);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        let stressed = market.data.clone();
        let mut __lg15 = canonical_backing_ledger_account(&market, 1);
        let stressed_withdraw = run_ix(
            Instruction::WithdrawBackingBucket {
                domain: 1,
                amount: 1,
            },
            &mut [
                &mut admin,
                &mut market,
                &mut dest,
                &mut vault,
                &mut vault_auth,
                &mut token_program,
                &mut ledger,
            
        ],
        );
        assert_err_and_market_unchanged(stressed_withdraw, &market, &stressed);
    }
    market.data.copy_from_slice(&topped_up);

    let mut __lg16 = canonical_backing_ledger_account(&market, 1);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 25,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.source_credit[1].fresh_reserved_backing_num, 0);
    assert_eq!(
        group.source_backing_buckets[1].status,
        BackingBucketStatusV16::Empty
    );
    assert_eq!(group.source_backing_buckets[1].expiry_slot, 0);
}

#[test]
fn v16_wrapper_withdraw_backing_bucket_rejects_bad_custody_accounts() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 10);
    let mut token_program = token_program_account();
    let mut __lg15 = canonical_backing_ledger_account(&market, 1);
    let mut __sp15 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 10,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg15,
        &mut __sp15,
    ],
    )
    .unwrap();

    let attacker = signer();
    let mut wrong_dest_owner = user_token_account(attacker.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let before_wrong_dest = market.data.clone();
    let mut __lg17 = canonical_backing_ledger_account(&market, 1);
    let wrong_dest = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut wrong_dest_owner,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg17,
    ],
    );
    assert_err_and_market_unchanged(wrong_dest, &market, &before_wrong_dest);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut wrong_vault_auth = signer();
    let before_wrong_auth = market.data.clone();
    let mut __lg18 = canonical_backing_ledger_account(&market, 1);
    let wrong_auth = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut wrong_vault_auth,
            &mut token_program,
        
        &mut __lg18,
    ],
    );
    assert_err_and_market_unchanged(wrong_auth, &market, &before_wrong_auth);

    let wrong_mint = Pubkey::new_unique();
    let mut wrong_vault = vault_token_account(&market, wrong_mint, 10);
    let before_wrong_vault = market.data.clone();
    let mut __lg19 = canonical_backing_ledger_account(&market, 1);
    let wrong_vault_result = run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut wrong_vault,
            &mut vault_auth,
            &mut token_program,
        
        &mut __lg19,
    ],
    );
    assert_err_and_market_unchanged(wrong_vault_result, &market, &before_wrong_vault);
}

#[test]
fn v16_wrapper_backing_domain_ledger_tracks_authority_topup_earnings_and_withdraw() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let (ledger_key, _) = state::derive_lp_backing_ledger(&program_id(), &market.key, 1);
    let mut ledger = TestAccount::new(
        ledger_key,
        program_id(),
        state::backing_domain_ledger_account_len(),
    )
    .writable();

    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg16 = canonical_backing_ledger_account(&market, 1);
    let mut __sp16 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp16,
    ],
    )
    .unwrap();

    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(ledger_state.market_group, market.key.to_bytes());
    assert_eq!(ledger_state.authority, admin.key.to_bytes());
    assert_eq!(ledger_state.domain, 1);
    assert_eq!(ledger_state.total_principal_atoms, 100);
    assert_eq!(ledger_state.total_deposited_atoms, 100);
    assert_eq!(ledger_state.total_earnings_atoms, 0);
    assert_eq!(ledger_state.last_observed_bucket_earnings_atoms, 0);
    assert_eq!(group.vault, 100);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        100 * BOUND_SCALE
    );

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.source_backing_buckets[1].utilization_fee_earnings = 30;
        group.vault += 30;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    run_ix(
        Instruction::SyncBackingDomainLedger { domain: 1 },
        &mut [&mut admin, &mut market, &mut ledger],
    )
    .unwrap();
    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.last_observed_bucket_earnings_atoms, 30);
    assert_eq!(ledger_state.total_earnings_atoms, 30);

    vault = vault_token_account(&market, mint, 130);
    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    run_ix(
        Instruction::WithdrawBackingBucketEarnings {
            domain: 1,
            amount: 20,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut ledger,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(ledger_state.total_earnings_withdrawn_atoms, 20);
    assert_eq!(ledger_state.total_earnings_atoms, 30);
    assert_eq!(ledger_state.last_observed_bucket_earnings_atoms, 10);
    assert_eq!(group.source_backing_buckets[1].utilization_fee_earnings, 10);
    assert_eq!(group.vault, 110);

    let mut __lg20 = canonical_backing_ledger_account(&market, 1);
    run_ix(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 40,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        
    ],
    )
    .unwrap();
    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(ledger_state.total_principal_atoms, 60);
    assert_eq!(ledger_state.total_principal_withdrawn_atoms, 40);
    assert_eq!(group.vault, 70);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        60 * BOUND_SCALE
    );
}

#[test]
fn v16_wrapper_backing_domain_ledger_tracks_unavailable_principal_loss_and_recovery() {
    let mut admin = signer();
    let mut market = market_account();
    // #433: TopUpBackingBucket pins the ledger to its PDA, so the random-address helper
    // is refused on the SETUP top-up. The wrong-ledger cases below build their own.
    let mut ledger = canonical_backing_ledger_account(&market, 1);
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg17 = canonical_backing_ledger_account(&market, 1);
    let mut __sp17 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 40,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp17,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 1, 40)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    run_ix(
        Instruction::ConvertReleasedPnl { amount: 40 },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    run_ix(
        Instruction::SyncBackingDomainLedger { domain: 1 },
        &mut [&mut admin, &mut market, &mut ledger],
    )
    .unwrap();
    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.cumulative_loss_atoms, 40);
    assert_eq!(ledger_state.cumulative_recovery_atoms, 0);
    assert_eq!(ledger_state.last_observed_unavailable_principal_atoms, 40);

    let mut __lg18 = canonical_backing_ledger_account(&market, 1);
    let mut __sp18 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 10,
            expiry_slot: 20,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp18,
    ],
    )
    .unwrap();
    run_ix(
        Instruction::SyncBackingDomainLedger { domain: 1 },
        &mut [&mut admin, &mut market, &mut ledger],
    )
    .unwrap();
    let ledger_state = state::read_backing_domain_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.total_principal_atoms, 50);
    assert_eq!(ledger_state.cumulative_loss_atoms, 40);
    assert_eq!(ledger_state.cumulative_recovery_atoms, 10);
    assert_eq!(ledger_state.last_observed_unavailable_principal_atoms, 30);
}

#[test]
fn v16_wrapper_backing_domain_ledger_rejects_wrong_authority_and_domain() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    // #433: TopUpBackingBucket pins the ledger to its PDA, so the random-address helper
    // is refused on the SETUP top-up. The wrong-ledger cases below build their own.
    let mut ledger = canonical_backing_ledger_account(&market, 1);
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg19 = canonical_backing_ledger_account(&market, 1);
    let mut __sp19 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 10,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        
        &mut __sp19,
    ],
    )
    .unwrap();

    let before_wrong_authority = market.data.clone();
    let wrong_authority = run_ix(
        Instruction::SyncBackingDomainLedger { domain: 1 },
        &mut [&mut attacker, &mut market, &mut ledger],
    );
    assert_err_and_market_unchanged(wrong_authority, &market, &before_wrong_authority);

    let before_wrong_domain = market.data.clone();
    let wrong_domain = run_ix(
        Instruction::SyncBackingDomainLedger { domain: 0 },
        &mut [&mut admin, &mut market, &mut ledger],
    );
    assert_err_and_market_unchanged(wrong_domain, &market, &before_wrong_domain);
}

#[test]
fn v16_wrapper_insurance_ledger_tracks_topup_profit_loss_and_withdrawal() {
    let mut admin = signer();
    let mut market = market_account();
    let mut ledger = insurance_ledger_account();
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
            &mut ledger,
        ],
    )
    .unwrap();
    let ledger_state = state::read_insurance_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.market_group, market.key.to_bytes());
    assert_eq!(ledger_state.authority, admin.key.to_bytes());
    assert_eq!(ledger_state.total_principal_atoms, 100);
    assert_eq!(ledger_state.total_deposited_atoms, 100);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 100);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.insurance += 30;
        group.vault += 30;
        group.insurance_domain_budget[0] += 15;
        group.insurance_domain_budget[1] += 15;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    run_ix(
        Instruction::SyncInsuranceLedger,
        &mut [&mut admin, &mut market, &mut ledger],
    )
    .unwrap();
    let ledger_state = state::read_insurance_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.cumulative_profit_atoms, 30);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 130);

    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.insurance -= 20;
        group.vault -= 20;
        group.insurance_domain_budget[0] -= 10;
        group.insurance_domain_budget[1] -= 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    run_ix(
        Instruction::SyncInsuranceLedger,
        &mut [&mut admin, &mut market, &mut ledger],
    )
    .unwrap();
    let ledger_state = state::read_insurance_ledger(&ledger.data).unwrap();
    assert_eq!(ledger_state.cumulative_loss_atoms, 20);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 110);

    // v17: UpdateInsurancePolicy (tag 33) deleted; WithdrawInsurance only works in
    // terminal mode (matrix row 35). Resolve the market to enable terminal withdrawal.
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    vault = vault_token_account(&market, mint, 110);
    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    run_ix(
        Instruction::WithdrawInsurance { amount: 10 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
            &mut ledger,
        ],
    )
    .unwrap();
    let ledger_state = state::read_insurance_ledger(&ledger.data).unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(ledger_state.total_withdrawn_atoms, 10);
    assert_eq!(ledger_state.total_principal_atoms, 90);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 100);
    assert_eq!(group.insurance, 100);
    assert_eq!(group.vault, 100);
}

#[test]
fn v16_wrapper_source_backed_positive_pnl_converts_from_backing_not_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 40);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg20 = canonical_backing_ledger_account(&market, 1);
    let mut __sp20 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 40,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg20,
        &mut __sp20,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 1, 40)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    run_ix(
        Instruction::ConvertReleasedPnl { amount: 40 },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 40);
    assert_eq!(account.pnl, 0);
    assert_eq!(group.c_tot, 40);
    assert_eq!(group.vault, 40);
    assert_eq!(
        group.insurance, 0,
        "counterparty backing must support the source claim without spending insurance"
    );
    assert_eq!(
        group.source_backing_buckets[1].consumed_liened_backing_num,
        40 * BOUND_SCALE
    );
    assert_eq!(group.source_credit[1].spent_backing_num, 40 * BOUND_SCALE);

    withdraw(&mut owner, &mut market, &mut portfolio, 40);
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_wrapper_backing_top_up_refills_provider_receivable_in_engine() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg21 = canonical_backing_ledger_account(&market, 1);
    let mut __sp21 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 40,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg21,
        &mut __sp21,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 1, 40)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    run_ix(
        Instruction::ConvertReleasedPnl { amount: 40 },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    {
        let (_, group) = state::read_market(&market.data).unwrap();
        assert_eq!(
            group.source_credit[1].provider_receivable_num,
            40 * BOUND_SCALE
        );
        assert_eq!(
            group.source_backing_buckets[1].consumed_liened_backing_num,
            40 * BOUND_SCALE
        );
        assert_eq!(group.source_credit[1].fresh_reserved_backing_num, 0);
    }

    let mut __lg22 = canonical_backing_ledger_account(&market, 1);
    let mut __sp22 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 10,
            expiry_slot: 20,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        
        &mut __lg22,
        &mut __sp22,
    ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.source_credit[1].provider_receivable_num,
        30 * BOUND_SCALE,
        "backing top-up must automatically repay provider receivable through the engine API"
    );
    assert_eq!(
        group.source_backing_buckets[1].consumed_liened_backing_num,
        30 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        10 * BOUND_SCALE
    );
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        10 * BOUND_SCALE
    );
}

#[test]
fn v16_wrapper_exploited_oracle_pnl_cannot_exit_against_unrelated_backing_or_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
    )
    .unwrap();

    let mut insurance_source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 120);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut insurance_source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let mut unrelated_source = user_token_account(admin.key, mint, 100);
    let mut __lg23 = canonical_backing_ledger_account(&market, 0);
    let mut __sp23 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 0,
            amount: 100,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut unrelated_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg23,
        &mut __sp23,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 20);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 2, 50)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    let before_convert_market = market.data.clone();
    let before_convert_portfolio = portfolio.data.clone();
    let convert = run_ix(
        Instruction::ConvertReleasedPnl { amount: 50 },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(convert, &market, &before_convert_market);
    assert_eq!(portfolio.data, before_convert_portfolio);

    let before_over_withdraw_market = market.data.clone();
    let before_over_withdraw_portfolio = portfolio.data.clone();
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let over_withdraw = run_ix(
        Instruction::Withdraw { amount: 21 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(over_withdraw, &market, &before_over_withdraw_market);
    assert_eq!(portfolio.data, before_over_withdraw_portfolio);

    withdraw(&mut owner, &mut market, &mut portfolio, 20);
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 0);
    assert_eq!(account.pnl, 50);
    assert_eq!(group.insurance, 100);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.source_credit[2].spent_backing_num, 0);
    assert_eq!(group.source_credit[0].spent_backing_num, 0);
    assert_eq!(
        group.source_backing_buckets[0].fresh_unliened_backing_num,
        100 * BOUND_SCALE,
        "unrelated backing must not support an exploited oracle claim"
    );
}

#[test]
fn v16_wrapper_exploited_added_asset_pnl_exit_caps_to_its_source_domain_backing() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
    )
    .unwrap();

    let mut unrelated_source = user_token_account(admin.key, mint, 80);
    let mut corrupt_domain_source = user_token_account(admin.key, mint, 30);
    let mut vault = vault_token_account(&market, mint, 110);
    let mut token_program = token_program_account();
    let mut __lg24 = canonical_backing_ledger_account(&market, 0);
    let mut __sp24 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 0,
            amount: 80,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut unrelated_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg24,
        &mut __sp24,
    ],
    )
    .unwrap();
    let mut __lg25 = canonical_backing_ledger_account(&market, 2);
    let mut __sp25 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 2,
            amount: 30,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut corrupt_domain_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg25,
        &mut __sp25,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 2, 100)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    run_ix(
        Instruction::ConvertReleasedPnl { amount: 100 },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        account.capital, 30,
        "manufactured PnL may exit only up to same-domain backing"
    );
    assert_eq!(account.pnl, 0);
    assert_eq!(group.c_tot, 30);
    assert_eq!(group.vault, 110);
    assert_eq!(group.insurance, 0);
    assert_eq!(
        group.source_backing_buckets[2].consumed_liened_backing_num,
        30 * BOUND_SCALE
    );
    assert_eq!(group.source_credit[2].spent_backing_num, 30 * BOUND_SCALE);
    assert_eq!(
        group.source_backing_buckets[0].fresh_unliened_backing_num,
        80 * BOUND_SCALE,
        "same-account cross-margin must not consume unrelated source backing"
    );
    assert_eq!(group.source_credit[0].spent_backing_num, 0);

    let before_over_withdraw_market = market.data.clone();
    let before_over_withdraw_portfolio = portfolio.data.clone();
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let over_withdraw = run_ix(
        Instruction::Withdraw { amount: 31 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(over_withdraw, &market, &before_over_withdraw_market);
    assert_eq!(portfolio.data, before_over_withdraw_portfolio);

    withdraw(&mut owner, &mut market, &mut portfolio, 30);
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.vault, 80);
    assert_eq!(
        group.source_backing_buckets[0].fresh_unliened_backing_num,
        80 * BOUND_SCALE
    );
}

#[test]
fn v16_wrapper_cross_margin_source_claims_leave_unbacked_corrupt_claim_unconverted() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        100,
    )
    .unwrap();

    let mut legit_source = user_token_account(admin.key, mint, 30);
    let mut vault = vault_token_account(&market, mint, 30);
    let mut token_program = token_program_account();
    let mut __lg26 = canonical_backing_ledger_account(&market, 0);
    let mut __sp26 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 0,
            amount: 30,
            expiry_slot: 10,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut legit_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg26,
        &mut __sp26,
    ],
    )
    .unwrap();

    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 0, 30)
            .unwrap();
        group
            .add_account_source_positive_pnl_not_atomic(&mut account, 2, 100)
            .unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    run_ix(
        Instruction::ConvertReleasedPnl { amount: 130 },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(account.capital, 30);
    assert_eq!(account.pnl, 100);
    assert_eq!(account.source_claim_bound_num[0], 0);
    assert_eq!(account.source_claim_bound_num[2], 100 * BOUND_SCALE);
    assert_eq!(group.source_credit[0].spent_backing_num, 30 * BOUND_SCALE);
    assert_eq!(group.source_credit[2].spent_backing_num, 0);
    assert_eq!(
        group.source_credit[2].credit_rate_num, 0,
        "unbacked corrupt source claim must remain non-withdrawable"
    );

    let before_second_convert_market = market.data.clone();
    let before_second_convert_portfolio = portfolio.data.clone();
    let second_convert = run_ix(
        Instruction::ConvertReleasedPnl { amount: 100 },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(second_convert, &market, &before_second_convert_market);
    assert_eq!(portfolio.data, before_second_convert_portfolio);
}

#[test]
fn v16_wrapper_insurance_policy_deposit_only_leaves_fee_growth_behind() {
    // v17: UpdateInsurancePolicy (tag 33) and live-market WithdrawInsurance (tag 23)
    // deleted (matrix row 35). Re-expressed as: terminal WithdrawInsurance only
    // drains what was deposited as global insurance (domain-0 budget), not fee growth
    // that was credited to non-zero domain budgets.
    let mut admin = signer();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 150);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    // Simulate fee-growth credited to a non-zero domain: group.insurance += 50 but
    // insurance_domain_budget[0] stays unchanged so available-for-admin = domain-0 budget.
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.insurance += 50;
        group.vault += 50;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    // Resolve the market so terminal withdrawal is enabled.
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    // Can withdraw the full domain-0 global insurance (100).
    run_ix(
        Instruction::WithdrawInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 50);
    assert_eq!(group.vault, 50);
}

#[test]
fn v16_wrapper_insurance_withdraw_disabled_by_default() {
    // v17: live-market WithdrawInsurance (tag 23 / UpdateInsurancePolicy tag 33) deleted.
    // Terminal WithdrawInsurance (tag 41) requires mode==Resolved; on a live market it is
    // ALWAYS rejected regardless of any config — no opt-in needed.
    let mut admin = signer();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    // In v17 the config has insurance_withdraw_max_bps=0 but this is vestigial; the
    // actual gate is mode==Resolved check in handle_withdraw_insurance.
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg.insurance_withdraw_max_bps, 0,
        "vestigial field initializes to zero"
    );

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let before = market.data.clone();
    // Always rejected on a live market (mode != Resolved).
    let live_market_withdraw = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(live_market_withdraw, &market, &before);
    let _ = mint; // suppress unused warning
}

#[test]
fn v16_wrapper_insurance_policy_rejects_live_unbounded_or_zero_cooldown() {
    // v17: UpdateInsurancePolicy (tag 33) deleted (matrix row 35). The v17 equivalent
    // invariant is: WithdrawInsurance always rejects on a live market (mode != Resolved).
    // This test verifies that any insurance withdrawal on a live market is rejected.
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let mut source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 10);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 10 },
        &mut [&mut admin, &mut market, &mut source, &mut vault, &mut token_program],
    )
    .unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let before = market.data.clone();
    let live_reject = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [&mut admin, &mut market, &mut dest, &mut vault, &mut vault_auth, &mut token_program],
    );
    assert_err_and_market_unchanged(live_reject, &market, &before);
}

#[test]
fn v16_wrapper_insurance_policy_enforces_bps_cap_and_cooldown() {
    // v17: UpdateInsurancePolicy (tag 33) deleted (matrix row 35). The v17 terminal
    // withdrawal model enforces that you cannot withdraw more than the available
    // terminal insurance (sum of domain budgets net of spends, scoped to the calling
    // authority). This test verifies the overdraw guard in terminal mode.
    let mut admin = signer();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let before = market.data.clone();
    // Overdraw (101 > 100 available) must be rejected.
    let over_cap = run_ix(
        Instruction::WithdrawInsurance { amount: 101 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(over_cap, &market, &before);

    // Exact drain succeeds.
    run_ix(
        Instruction::WithdrawInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_wrapper_withdraw_insurance_requires_operator_and_healthy_market() {
    // v17: UpdateInsurancePolicy (tag 33) deleted; terminal WithdrawInsurance gated by
    // resolved mode + authority + no-overdraw (matrix row 35). Tests: unauthorized caller
    // rejected, zero amount rejected, overdraw rejected, partial drain succeeds, c_tot
    // guard (non-zero materialized portfolios means mode cannot be Resolved via ResolveMarket
    // — tested implicitly here since we have no open portfolios).
    let mut admin = signer();
    let mut market = market_account();
    let mut attacker = signer();

    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 100);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 100 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    // Live market: all withdrawals are rejected regardless of caller.
    let mut attacker_dest = user_token_account(attacker.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let live = market.data.clone();
    let live_reject = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut attacker_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(live_reject, &market, &live);

    // Resolve to enable terminal withdrawal.
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved = market.data.clone();

    // Unauthorized caller rejected in terminal mode.
    let unauthorized = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut attacker,
            &mut market,
            &mut attacker_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &resolved);

    // Zero amount rejected.
    let zero = run_ix(
        Instruction::WithdrawInsurance { amount: 0 },
        &mut [
            &mut admin,
            &mut market,
            &mut attacker_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(zero, &market, &resolved);

    let mut admin_dest = user_token_account(admin.key, mint, 0);
    // Partial drain succeeds.
    run_ix(
        Instruction::WithdrawInsurance { amount: 40 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 60);
    assert_eq!(group.vault, 60);

    // Overdraw is rejected.
    let overdraw = run_ix(
        Instruction::WithdrawInsurance { amount: 61 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert!(overdraw.is_err());
    let _ = mint;
}

#[test]
fn v16_wrapper_withdraw_insurance_limited_is_live_only_and_terminal_uses_authority() {
    // v17: UpdateInsurancePolicy (tag 33) deleted (matrix row 35). The live-only path
    // is gone; only terminal withdrawal exists. Key v17 invariant: only insurance_authority
    // (per asset profile) can do terminal withdrawal; insurance_operator cannot.
    let mut admin = signer().writable();
    let mut market = market_account();
    let mut operator = signer();

    let mint = init_market(&mut admin, &mut market);
    // Rotate the insurance_operator for asset-0 to a separate key; admin keeps insurance_authority.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: operator.key.to_bytes(),
        },
        &mut [&mut admin, &mut operator, &mut market],
    )
    .unwrap();
    let mut source = user_token_account(admin.key, mint, 50);
    let mut vault = vault_token_account(&market, mint, 50);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 50 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut vault_auth = vault_authority_account(&market);
    let resolved = market.data.clone();

    // insurance_operator role cannot do terminal withdrawal (only insurance_authority can).
    let mut operator_dest = user_token_account(operator.key, mint, 0);
    let operator_terminal = run_ix(
        Instruction::WithdrawInsurance { amount: 50 },
        &mut [
            &mut operator,
            &mut market,
            &mut operator_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(operator_terminal, &market, &resolved);

    // insurance_authority (admin) succeeds at terminal withdrawal.
    let mut admin_dest = user_token_account(admin.key, mint, 0);
    run_ix(
        Instruction::WithdrawInsurance { amount: 50 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);

    let mut close_dest = user_token_account(admin.key, mint, 0);
    run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut close_dest,
            &mut token_program,
        ],
    )
    .unwrap();
    assert!(market.data.iter().all(|b| *b == 0));
}

#[test]
fn v16_wrapper_withdraw_insurance_resolved_requires_all_portfolios_closed() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 10);
    let mut source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 20);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 10 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let resolved_with_claims = market.data.clone();
    let rejected = run_ix(
        Instruction::WithdrawInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &resolved_with_claims);
}

#[test]
fn v16_wrapper_update_authority_rotates_admin_with_dual_signature() {
    let mut admin = signer();
    let mut market = market_account();
    let mut new_admin = signer();
    let mut attacker = signer();

    init_market(&mut admin, &mut market);
    let initialized = market.data.clone();

    let missing_new_sig = {
        let mut unsigned_new_admin = TestAccount::new(new_admin.key, Pubkey::new_unique(), 0);
        run_ix(
            Instruction::UpdateAuthority {
                new_pubkey: new_admin.key.to_bytes(),
            },
            &mut [&mut admin, &mut unsigned_new_admin, &mut market],
        )
    };
    assert_err_and_market_unchanged(missing_new_sig, &market, &initialized);

    let unauthorized_current = run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: new_admin.key.to_bytes(),
        },
        &mut [&mut attacker, &mut new_admin, &mut market],
    );
    assert_err_and_market_unchanged(unauthorized_current, &market, &initialized);

    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: new_admin.key.to_bytes(),
        },
        &mut [&mut admin, &mut new_admin, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.marketauth, new_admin.key.to_bytes());

    let rotated = market.data.clone();
    let old_admin_resolve = run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]);
    assert_err_and_market_unchanged(old_admin_resolve, &market, &rotated);
    run_ix(
        Instruction::ResolveMarket,
        &mut [&mut new_admin, &mut market],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
}

#[test]
fn v16_wrapper_update_authority_rotates_insurance_keys_and_supports_operator_burn() {
    // v17: insurance_authority/insurance_operator are per-asset authorities (matrix row 27).
    // UpdateAssetAuthority (tag 65) rotates them. Zero-burn is REJECTED for
    // INSURANCE/INSURANCE_OPERATOR (only ASSET_AUTH_ADMIN allows zero-burn).
    let mut admin = signer();
    let mut market = market_account();
    let mut insurance = signer();
    let mut operator = signer();
    let mut attacker = signer();

    let mint = init_market(&mut admin, &mut market);
    // At InitMarket, marketauth = admin; asset-0 insurance_authority = insurance_operator = admin.
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.marketauth, admin.key.to_bytes());
    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(profile.insurance_authority, admin.key.to_bytes());
    assert_eq!(profile.insurance_operator, admin.key.to_bytes());

    // Rotate insurance_authority and insurance_operator to separate keys via UpdateAssetAuthority.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: insurance.key.to_bytes(),
        },
        &mut [&mut admin, &mut insurance, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: operator.key.to_bytes(),
        },
        &mut [&mut admin, &mut operator, &mut market],
    )
    .unwrap();

    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(profile.insurance_authority, insurance.key.to_bytes());
    assert_eq!(profile.insurance_operator, operator.key.to_bytes());

    // TopUpInsurance requires the current insurance_authority (asset-0) to sign.
    let mut admin_src = user_token_account(admin.key, mint, 1);
    let mut insurance_src = user_token_account(insurance.key, mint, 1);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let rotated = market.data.clone();
    let old_insurance_auth = run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_src,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(old_insurance_auth, &market, &rotated);
    run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut insurance,
            &mut market,
            &mut insurance_src,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();

    // v17: Zero-burn for INSURANCE_OPERATOR is REJECTED (only ASSET_AUTH_ADMIN allows zero-burn).
    // Test that operator can self-rotate to a new key (not zero).
    let mut new_operator = signer();
    let before_burn_attempt = market.data.clone();
    let operator_zero_burn = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: [0u8; 32],
        },
        &mut [&mut operator, &mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(operator_zero_burn, &market, &before_burn_attempt);
    // Operator CAN self-rotate to a live key.
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: new_operator.key.to_bytes(),
        },
        &mut [&mut operator, &mut new_operator, &mut market],
    )
    .unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(profile.insurance_operator, new_operator.key.to_bytes());
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.insurance, 1);

    // v17: Zero-burn for INSURANCE is also REJECTED.
    let mut insurance_src = user_token_account(insurance.key, mint, 1);
    let mut vault = vault_token_account(&market, mint, 1);
    run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut insurance,
            &mut market,
            &mut insurance_src,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let before_ins_burn = market.data.clone();
    let mut zero_new = TestAccount::new(Pubkey::default(), Pubkey::new_unique(), 0);
    let insurance_zero_burn = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: [0u8; 32],
        },
        &mut [&mut insurance, &mut zero_new, &mut market],
    );
    assert_err_and_market_unchanged(insurance_zero_burn, &market, &before_ins_burn);

    // After a non-burn self-rotation, the old key can no longer top-up.
    let mut new_insurance = signer();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: new_insurance.key.to_bytes(),
        },
        &mut [&mut insurance, &mut new_insurance, &mut market],
    )
    .unwrap();
    let after_rotate = market.data.clone();
    let mut dead_src = user_token_account(insurance.key, mint, 1);
    let dead_insurance_auth = run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut insurance,
            &mut market,
            &mut dead_src,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(dead_insurance_auth, &market, &after_rotate);
}

#[test]
fn v16_wrapper_update_authority_rejects_unsupported_kind_and_live_admin_burn() {
    // v17: UpdateAuthority (tag 32) rotates marketauth only (no kind field). Per-asset
    // oracle/mark authority is now ASSET_AUTH_ORACLE in each asset's profile.
    let mut admin = signer();
    let mut market = market_account();
    let mut new_key = signer();

    init_market(&mut admin, &mut market);

    // Rotate oracle_authority for asset-0 (replaces old AUTHORITY_MARK rotation).
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_ORACLE,
            new_pubkey: new_key.key.to_bytes(),
        },
        &mut [&mut admin, &mut new_key, &mut market],
    )
    .unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile.oracle_authority,
        new_key.key.to_bytes(),
        "oracle_authority for asset-0 is rotatable before EwmaMark mode is set"
    );
    let initialized = market.data.clone();

    // Unknown kind is rejected by UpdateAssetAuthority (matrix row 30).
    let unknown = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: 99,
            new_pubkey: new_key.key.to_bytes(),
        },
        &mut [&mut new_key, &mut admin, &mut market],
    );
    assert_err_and_market_unchanged(unknown, &market, &initialized);

    // v17: UpdateAuthority rejects zero new_pubkey (marketauth cannot be burned on a live market).
    let live_admin_burn = run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: [0u8; 32],
        },
        &mut [&mut admin, &mut new_key, &mut market],
    );
    assert_err_and_market_unchanged(live_admin_burn, &market, &initialized);
}

#[test]
fn v16_wrapper_configure_ewma_mark_pushes_and_cranks_from_internal_mark() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_price_move_bps_per_slot = 1_000;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 5,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg.oracle_mode,
        percolator_prog::constants::ORACLE_MODE_EWMA_MARK
    );
    assert_eq!(cfg.mark_ewma_e6, 100);
    assert_eq!(cfg.mark_ewma_last_slot, 5);
    assert_eq!(cfg.last_good_oracle_slot, 5);
    assert_eq!(group.assets[0].effective_price, 100);

    // v17: mark authority is oracle_authority in the asset's profile (matrix row 29).
    let mut new_mark_authority = signer();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_ORACLE,
            new_pubkey: new_mark_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut new_mark_authority, &mut market],
    )
    .unwrap();

    let before_bad_push = market.data.clone();
    let mut wrong_authority = signer();
    let bad_push = run_ix(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot: 10,
            mark_e6: 120,
        },
        &mut [&mut wrong_authority, &mut market],
    );
    assert_err_and_market_unchanged(bad_push, &market, &before_bad_push);

    run_ix(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot: 10,
            mark_e6: 120,
        },
        &mut [&mut new_mark_authority, &mut market],
    )
    .unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile.mark_ewma_e6, 116,
        "full-weight EwmaMark push advances the configured EWMA mark at the authenticated slot"
    );
    assert_eq!(profile.mark_ewma_last_slot, 10);
    assert_eq!(profile.last_good_oracle_slot, 10);

    let mut caller = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut caller, &mut market, &mut portfolio);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 6,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut caller, &mut market, &mut portfolio],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.assets[0].effective_price, 116,
        "EwmaMark crank ignores caller-selected price and walks to the internal mark"
    );
}

#[test]
fn v16_wrapper_configure_auth_mark_pushes_direct_mark_without_ewma_setup() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_price_move_bps_per_slot = 1_000;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    configure_base_auth_mark(&mut admin, &mut market, 5, 100);
    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_mode, ORACLE_MODE_AUTH_MARK);
    assert_eq!(cfg.mark_ewma_e6, 100);
    assert_eq!(cfg.oracle_target_price_e6, 100);
    assert_eq!(cfg.mark_ewma_halflife_slots, 0);
    assert_eq!(cfg.mark_min_fee, 0);
    assert_eq!(cfg.mark_ewma_last_slot, 5);
    assert_eq!(cfg.last_good_oracle_slot, 5);
    assert_eq!(group.assets[0].effective_price, 100);

    // v17: mark/oracle authority is oracle_authority in the per-asset profile.
    let mut new_mark_authority = signer();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_ORACLE,
            new_pubkey: new_mark_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut new_mark_authority, &mut market],
    )
    .unwrap();

    let before_bad_push = market.data.clone();
    let mut wrong_authority = signer();
    let bad_push = run_ix(
        Instruction::PushAuthMark {
            asset_index: 0,
            now_slot: 10,
            mark_e6: 120,
        },
        &mut [&mut wrong_authority, &mut market],
    );
    assert_err_and_market_unchanged(bad_push, &market, &before_bad_push);

    push_base_auth_mark(&mut new_mark_authority, &mut market, 10, 120);
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg.mark_ewma_e6, 120,
        "AuthMark push stores the authority mark directly, without EWMA smoothing"
    );
    assert_eq!(cfg.oracle_target_price_e6, 120);
    assert_eq!(cfg.mark_ewma_last_slot, 10);
    assert_eq!(cfg.last_good_oracle_slot, 10);

    let mut caller = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut caller, &mut market, &mut portfolio);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut caller, &mut market, &mut portfolio],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.assets[0].effective_price, 120,
        "AuthMark crank consumes only the stored authority mark"
    );
}

#[test]
fn v16_wrapper_ewma_mark_profiles_reject_prices_above_engine_max() {
    let mut profile = state::AssetOracleProfileV16 {
        oracle_mode: ORACLE_MODE_EWMA_MARK,
        oracle_leg_count: 0,
        oracle_leg_flags: 0,
        invert: 0,
        unit_scale: 0,
        conf_filter_bps: 0,
        backing_trade_fee_bps_long: 0,
        backing_trade_fee_bps_short: 0,
        backing_trade_fee_insurance_share_bps_long: 0,
        backing_trade_fee_insurance_share_bps_short: 0,
        _padding0: [0u8; 6],
        insurance_authority: [1u8; 32],
        insurance_operator: [1u8; 32],
        backing_bucket_authority: [1u8; 32],
        oracle_authority: [1u8; 32],
        asset_admin: [1u8; 32],  // v17: per-asset cold-storage admin (matrix row 30)
        max_staleness_secs: 0,
        hybrid_soft_stale_slots: 0,
        mark_ewma_e6: percolator::MAX_ORACLE_PRICE + 1,
        mark_ewma_last_slot: 1,
        mark_ewma_halflife_slots: 1,
        mark_min_fee: 0,
        oracle_target_price_e6: percolator::MAX_ORACLE_PRICE,
        oracle_target_publish_time: 0,
        last_good_oracle_slot: 1,
        oracle_leg_feeds: [[0u8; 32]; ORACLE_LEG_CAP],
        oracle_leg_prices_e6: [0u64; ORACLE_LEG_CAP],
        oracle_leg_publish_times: [0i64; ORACLE_LEG_CAP],
    };
    assert!(
        state::validate_asset_oracle_profile(&profile).is_err(),
        "EwmaMark EWMA mark must stay within the engine oracle-price envelope"
    );

    profile.mark_ewma_e6 = percolator::MAX_ORACLE_PRICE;
    profile.oracle_target_price_e6 = percolator::MAX_ORACLE_PRICE + 1;
    assert!(
        state::validate_asset_oracle_profile(&profile).is_err(),
        "EwmaMark target mark must stay within the engine oracle-price envelope"
    );

    profile.oracle_mode = ORACLE_MODE_AUTH_MARK;
    profile.mark_ewma_e6 = percolator::MAX_ORACLE_PRICE;
    profile.oracle_target_price_e6 = percolator::MAX_ORACLE_PRICE;
    profile.mark_ewma_halflife_slots = 1;
    assert!(
        state::validate_asset_oracle_profile(&profile).is_err(),
        "AuthMark must not carry EWMA halflife configuration"
    );

    profile.mark_ewma_halflife_slots = 0;
    profile.oracle_target_price_e6 = percolator::MAX_ORACLE_PRICE - 1;
    assert!(
        state::validate_asset_oracle_profile(&profile).is_err(),
        "AuthMark target and stored mark must match"
    );

    profile.oracle_target_price_e6 = percolator::MAX_ORACLE_PRICE;
    assert!(
        state::validate_asset_oracle_profile(&profile).is_ok(),
        "AuthMark accepts a direct authority mark without EWMA or oracle-leg config"
    );

    profile.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    profile.oracle_leg_count = 1;
    profile.oracle_leg_feeds[0] = [7u8; 32];
    profile.max_staleness_secs = 60;
    profile.hybrid_soft_stale_slots = 5;
    profile.oracle_target_price_e6 = percolator::MAX_ORACLE_PRICE;
    profile.mark_ewma_e6 = percolator::MAX_ORACLE_PRICE + 1;
    assert!(
        state::validate_asset_oracle_profile(&profile).is_err(),
        "hybrid fallback EWMA mark must stay within the engine oracle-price envelope"
    );
}

#[test]
fn v16_wrapper_push_ewma_mark_rejects_over_max_input_and_preserves_state() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 1,
            initial_mark_e6: percolator::MAX_ORACLE_PRICE,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot: 2,
            mark_e6: percolator::MAX_ORACLE_PRICE + 1,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);

    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.mark_ewma_e6, percolator::MAX_ORACLE_PRICE);
}

#[test]
fn v16_wrapper_configure_ewma_mark_clears_prior_hybrid_oracle_metadata() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut leg0 = pyth_account(&feeds[0], 200, 0, 0, 1_000);
    let mut leg1 = pyth_account(&feeds[1], 2, 0, 0, 1_000);
    let mut leg2 = pyth_account(&feeds[2], 4, 0, 0, 1_000);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 10,
            now_unix_ts: 1_000,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 3,
            mark_ewma_halflife_slots: 11,
            mark_min_fee: 7,
            invert: 1,
            unit_scale: 6,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [&mut admin, &mut market, &mut leg0, &mut leg1, &mut leg2],
    )
    .unwrap();

    let (hybrid_cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(hybrid_cfg.oracle_mode, ORACLE_MODE_HYBRID_AFTER_HOURS);
    assert_eq!(hybrid_cfg.invert, 1);
    assert_eq!(hybrid_cfg.unit_scale, 6);
    assert_eq!(hybrid_cfg.conf_filter_bps, 500);
    assert_eq!(hybrid_cfg.oracle_leg_count, 3);

    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 11,
            initial_mark_e6: 123,
            mark_ewma_halflife_slots: 5,
            mark_min_fee: 9,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_mode, ORACLE_MODE_EWMA_MARK);
    assert_eq!(cfg.oracle_leg_count, 0);
    assert_eq!(cfg.oracle_leg_flags, 0);
    assert_eq!(cfg.oracle_leg_feeds, [[0u8; 32]; ORACLE_LEG_CAP]);
    assert_eq!(cfg.oracle_leg_prices_e6, [0u64; ORACLE_LEG_CAP]);
    assert_eq!(cfg.oracle_leg_publish_times, [0i64; ORACLE_LEG_CAP]);
    assert_eq!(cfg.max_staleness_secs, 0);
    assert_eq!(cfg.hybrid_soft_stale_slots, 0);
    assert_eq!(cfg.invert, 0);
    assert_eq!(cfg.unit_scale, 0);
    assert_eq!(cfg.conf_filter_bps, 0);
    assert_eq!(cfg.mark_ewma_e6, 123);
    assert_eq!(cfg.mark_ewma_halflife_slots, 5);
    assert_eq!(cfg.mark_min_fee, 9);
    assert_eq!(group.assets[0].effective_price, 123);
}

#[test]
fn v16_wrapper_ewma_mark_trade_updates_mark_and_charges_dynamic_fee_without_oracle_tail() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 1,
            initial_mark_e6: 100_000,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 10;
        group.slot_last = 10;
        group.assets[0].slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    let base_only_fee = two_sided_fee(size_q, exec_price, 1);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (after_cfg, after_group) = state::read_market(&market.data).unwrap();
    assert!(
        after_group.insurance > before_group.insurance + base_only_fee,
        "direct EwmaMark trades pay dynamic mark-movement surcharge without oracle accounts"
    );
    assert!(
        after_cfg.mark_ewma_e6 > before_cfg.mark_ewma_e6,
        "direct EwmaMark trades move the fallback EWMA mark"
    );
    assert_eq!(
        after_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "execution price flexibility must not rewrite the accepted EwmaMark index"
    );
}

#[test]
fn v16_wrapper_auth_mark_trade_cannot_update_authority_mark() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    configure_base_auth_mark(&mut admin, &mut market, 1, 100_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 10;
        group.slot_last = 10;
        group.assets[0].slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    // W1 (fee-on-mark): the fee is billed on the MARK (effective_price), not the consented
    // exec_price — so the base (no-surcharge) fee an AuthMark trade pays is mark-based.
    // Taker-only (design §1A): total collected is one side's fee, not two.
    let base_only_fee = taker_only_fee(size_q, before_group.assets[0].effective_price, 1);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (after_cfg, after_group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        after_group.insurance,
        before_group.insurance + base_only_fee,
        "AuthMark trades should not pay EWMA mark-movement surcharge"
    );
    assert_eq!(
        after_cfg.mark_ewma_e6, before_cfg.mark_ewma_e6,
        "AuthMark trades must not rewrite the authority mark"
    );
    assert_eq!(
        after_cfg.oracle_target_price_e6, before_cfg.oracle_target_price_e6,
        "AuthMark target only changes through PushAuthMark"
    );
    assert_eq!(
        after_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "execution price flexibility must not rewrite the accepted AuthMark index"
    );
}

#[test]
fn v16_wrapper_permissionless_resolve_policy_is_admin_gated_and_enables_admin_burn() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    let mut new_key = signer();

    init_market(&mut admin, &mut market);
    let initialized = market.data.clone();

    let attacker_update = run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(attacker_update, &market, &initialized);

    for (stale_slots, force_close_delay_slots) in [(0, 1), (1, 0)] {
        let before = market.data.clone();
        let rejected = run_ix(
            Instruction::ConfigurePermissionlessResolve {
                stale_slots,
                force_close_delay_slots,
            },
            &mut [&mut admin, &mut market],
        );
        assert_err_and_market_unchanged(rejected, &market, &before);
    }

    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Live);
    assert_eq!(cfg.permissionless_resolve_stale_slots, 9000);
    assert_eq!(cfg.force_close_delay_slots, 1);

    // v17: admin (marketauth) cannot be burned on a live market; verify rejection instead.
    let burn_rejected = run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: [0u8; 32],
        },
        &mut [&mut admin, &mut new_key, &mut market],
    );
    assert!(burn_rejected.is_err(), "v17: burning marketauth to zero must be rejected on live market");
    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Live);
    // marketauth is still set (non-zero) — burn was rejected.
    assert_ne!(cfg.marketauth, [0u8; 32]);
}

#[test]
fn v16_wrapper_update_authority_allows_chained_admin_rotation_without_old_key_reuse() {
    let mut admin = signer();
    let mut market = market_account();
    let mut admin_b = signer();
    let mut admin_c = signer();

    init_market(&mut admin, &mut market);
    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: admin_b.key.to_bytes(),
        },
        &mut [&mut admin, &mut admin_b, &mut market],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: admin_c.key.to_bytes(),
        },
        &mut [&mut admin_b, &mut admin_c, &mut market],
    )
    .unwrap();

    let rotated = market.data.clone();
    let old_admin = run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]);
    assert_err_and_market_unchanged(old_admin, &market, &rotated);
    let prior_admin = run_ix(Instruction::ResolveMarket, &mut [&mut admin_b, &mut market]);
    assert_err_and_market_unchanged(prior_admin, &market, &rotated);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin_c, &mut market]).unwrap();
}

#[test]
fn v16_wrapper_close_portfolio_rejects_non_empty_and_closes_empty() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);
    assert!(state::read_portfolio(&portfolio.data).is_ok());

    withdraw(&mut owner, &mut market, &mut portfolio, 1_000);
    let market_lamports_before_close = market.lamports;
    let portfolio_lamports_before_close = portfolio.lamports;
    run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.materialized_portfolio_count, 0);
    assert_eq!(
        market.lamports,
        market_lamports_before_close + portfolio_lamports_before_close,
        "portfolio close should send rent into the market slab"
    );
    assert_eq!(portfolio.lamports, 0);
    assert!(portfolio.data.iter().all(|b| *b == 0));
    assert!(!state::is_initialized(&portfolio.data));
}

#[test]
fn v16_wrapper_close_slab_requires_admin_resolved_empty_market() {
    let mut admin = signer().writable();
    let mut market = market_account();
    let mut attacker = signer().writable();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut dest_token = user_token_account(admin.key, mint, 0);
    let mut token_program = token_program_account();

    let live_before = market.data.clone();
    let live_close = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(live_close, &market, &live_before);

    init_portfolio(&mut owner, &mut market, &mut portfolio);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved_before = market.data.clone();
    let non_admin = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut attacker,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(non_admin, &market, &resolved_before);

    let with_portfolio = market.data.clone();
    let nonempty_count = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(nonempty_count, &market, &with_portfolio);

    run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();
    let market_lamports = market.lamports;
    let admin_lamports = admin.lamports;
    run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    )
    .unwrap();
    assert_eq!(market.lamports, 0);
    assert_eq!(admin.lamports, admin_lamports + market_lamports);
    assert!(
        market.data.iter().all(|b| *b == 0),
        "closed market account should be zeroed"
    );
}

#[test]
fn v16_wrapper_close_slab_rejects_burned_admin_zero_key() {
    let mut admin = signer().writable();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    {
        // v17: WrapperConfigV16 uses marketauth (not admin) — matrix row 27.
        let (mut cfg, group) = state::read_market(&market.data).unwrap();
        cfg.marketauth = [0u8; 32];
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut zero_admin = TestAccount::new(Pubkey::default(), Pubkey::new_unique(), 0)
        .signer()
        .writable();
    let mut vault = vault_token_account(&market, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut dest_token = user_token_account(zero_admin.key, mint, 0);
    let mut token_program = token_program_account();

    let burned_admin_market = market.data.clone();
    let rejected = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut zero_admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &burned_admin_market);
}

#[test]
fn v16_wrapper_close_slab_rejects_nonzero_engine_vault_or_insurance() {
    let mut admin = signer().writable();
    let mut market = market_account();

    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, 10);
    let mut vault = vault_token_account(&market, mint, 10);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::TopUpInsurance { amount: 10 },
        &mut [
            &mut admin,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut vault_auth = vault_authority_account(&market);
    let mut dest_token = user_token_account(admin.key, mint, 0);
    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);
}

#[test]
fn v16_wrapper_close_slab_rejects_uninitialized_market_without_rent_drain() {
    let mut admin = signer().writable();
    let mut market = market_account();
    let mint = Pubkey::new_unique();
    let mut vault = vault_token_account(&market, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut dest_token = user_token_account(admin.key, mint, 0);
    let mut token_program = token_program_account();

    let before_market = market.data.clone();
    let before_lamports = (admin.lamports, market.lamports);
    let rejected = run_ix(
        Instruction::CloseSlab,
        &mut [
            &mut admin,
            &mut market,
            &mut vault,
            &mut vault_auth,
            &mut dest_token,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!((admin.lamports, market.lamports), before_lamports);
}

#[test]
fn v16_wrapper_deposit_withdraw_roundtrip_preserves_accounting() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    withdraw(&mut owner, &mut market, &mut portfolio, 400);

    let (_, group) = state::read_market(&market.data).unwrap();
    let acct = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(acct.capital, 600);
    assert_eq!(group.c_tot, 600);
    assert_eq!(group.vault, 600);
    assert_eq!(group.insurance, 0);
}

#[test]
fn v16_wrapper_multiple_portfolios_same_owner_stay_isolated_and_totals_match() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut counterparty_owner = signer();
    let mut portfolio_a = portfolio_account();
    let mut portfolio_b = portfolio_account();
    let mut counterparty = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio_a);
    init_portfolio(&mut owner, &mut market, &mut portfolio_b);
    init_portfolio(&mut counterparty_owner, &mut market, &mut counterparty);
    deposit(&mut owner, &mut market, &mut portfolio_a, 1_000);
    deposit(&mut owner, &mut market, &mut portfolio_a, 2_000);
    deposit(&mut owner, &mut market, &mut portfolio_b, 3_000);
    deposit(
        &mut counterparty_owner,
        &mut market,
        &mut counterparty,
        100_000,
    );

    let untouched_b = portfolio_b.data.clone();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner,
            &mut counterparty_owner,
            &mut market,
            &mut portfolio_a,
            &mut counterparty,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let a = state::read_portfolio(&portfolio_a.data).unwrap();
    let b = state::read_portfolio(&portfolio_b.data).unwrap();
    let c = state::read_portfolio(&counterparty.data).unwrap();
    assert_eq!(b.capital, 3_000);
    assert_eq!(
        portfolio_b.data, untouched_b,
        "touching one portfolio must not mutate a sibling portfolio with the same owner"
    );
    assert_eq!(
        group.c_tot,
        a.capital + b.capital + c.capital,
        "market c_tot must equal the sum of materialized portfolio capital in this scenario"
    );
    assert_eq!(group.materialized_portfolio_count, 3);
}

#[test]
fn v16_wrapper_deposit_rejects_without_token_accounts() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(
        portfolio.data, before_portfolio,
        "ledger-only deposits must not be reachable through the public wrapper"
    );
}

#[test]
fn v16_wrapper_deposit_rejects_wrong_mint_and_insufficient_source_balance() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let mut wrong_source = user_token_account(owner.key, Pubkey::new_unique(), 1_000);
    let mut source_with_dust = user_token_account(owner.key, mint, 999);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_mint = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut wrong_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_mint, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let short_balance = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source_with_dust,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(short_balance, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_deposit_rejects_wrong_owner_and_bad_token_program() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut attacker = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let mut attacker_source = user_token_account(attacker.key, mint, 1_000);
    let mut owner_source = user_token_account(owner.key, mint, 1_000);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut bad_token_program = non_executable_token_program_account();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_owner = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [
            &mut attacker,
            &mut market,
            &mut portfolio,
            &mut attacker_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_owner, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let bad_program = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut owner_source,
            &mut vault,
            &mut bad_token_program,
        ],
    );
    assert_err_and_market_unchanged(bad_program, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_vault_accounts_reject_delegate_and_close_authority() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let mut source = user_token_account(owner.key, mint, 1_000);
    let mut delegated_vault = vault_token_account_with_controls(
        &market,
        mint,
        1_000,
        COption::Some(Pubkey::new_unique()),
        COption::None,
    );
    let mut closeable_vault = vault_token_account_with_controls(
        &market,
        mint,
        1_000,
        COption::None,
        COption::Some(Pubkey::new_unique()),
    );
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();

    let deposit_bad_vault = run_ix(
        Instruction::Deposit { amount: 1_000 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut delegated_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(deposit_bad_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let withdraw_bad_vault = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut closeable_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(withdraw_bad_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 1_000);
    let topup_bad_vault = run_ix(
        Instruction::TopUpInsurance { amount: 1_000 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut delegated_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(topup_bad_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_token_accounts_must_be_initialized_for_custody_paths() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let mut frozen_source =
        user_token_account_with_state(owner.key, mint, 1_000, AccountState::Frozen);
    let mut good_source = user_token_account(owner.key, mint, 1_000);
    let mut frozen_dest = user_token_account_with_state(owner.key, mint, 0, AccountState::Frozen);
    let mut good_dest = user_token_account(owner.key, mint, 0);
    let mut frozen_vault =
        vault_token_account_with_state(&market, mint, 1_000, AccountState::Frozen);
    let mut good_vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();

    let frozen_deposit_source = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut frozen_source,
            &mut good_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(frozen_deposit_source, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let frozen_deposit_vault = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut good_source,
            &mut frozen_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(frozen_deposit_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let frozen_withdraw_dest = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut frozen_dest,
            &mut good_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(frozen_withdraw_dest, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let frozen_withdraw_vault = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut good_dest,
            &mut frozen_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(frozen_withdraw_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 1_000);
    let frozen_topup_vault = run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut frozen_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(frozen_topup_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 1_000);
    let mut __lg27 = canonical_backing_ledger_account(&market, 1);
    let mut __sp27 = system_program_account();
    let frozen_backing_vault = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 1,
            expiry_slot: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut frozen_vault,
            &mut token_program,
        
        &mut __lg27,
        &mut __sp27,
    ],
    );
    assert_err_and_market_unchanged(frozen_backing_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_spl_u64_amount_limit_rejects_before_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let too_large = (u64::MAX as u128) + 1;
    let mut source = user_token_account(owner.key, mint, u64::MAX);
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, u64::MAX);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();

    let deposit_too_large = run_ix(
        Instruction::Deposit { amount: too_large },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(deposit_too_large, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let withdraw_too_large = run_ix(
        Instruction::Withdraw { amount: too_large },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(withdraw_too_large, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, u64::MAX);
    let topup_too_large = run_ix(
        Instruction::TopUpInsurance { amount: too_large },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(topup_too_large, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, u64::MAX);
    let mut __lg28 = canonical_backing_ledger_account(&market, 1);
    let mut __sp28 = system_program_account();
    let backing_too_large = run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: too_large,
            expiry_slot: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg28,
        &mut __sp28,
    ],
    );
    assert_err_and_market_unchanged(backing_too_large, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_zero_amount_custody_paths_are_noop_without_state_drift() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let mut source = user_token_account(owner.key, mint, 0);
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();

    run_ix(
        Instruction::Deposit { amount: 0 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    assert_eq!(market.data, before_market);
    assert_eq!(portfolio.data, before_portfolio);

    run_ix(
        Instruction::Withdraw { amount: 0 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    assert_eq!(market.data, before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 0);
    run_ix(
        Instruction::TopUpInsurance { amount: 0 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    assert_eq!(market.data, before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 0);
    let mut __lg29 = canonical_backing_ledger_account(&market, 1);
    let mut __sp29 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 0,
            expiry_slot: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        
        &mut __lg29,
        &mut __sp29,
    ],
    )
    .unwrap();
    assert_eq!(market.data, before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_withdraw_rejects_wrong_vault_authority_and_wrong_destination_mint() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let mut wrong_dest = user_token_account(owner.key, Pubkey::new_unique(), 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_mint = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut wrong_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_mint, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut dest = user_token_account(owner.key, mint, 0);
    let mut wrong_vault_auth = TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0);
    let wrong_authority = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut wrong_vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_authority, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_withdraw_rejects_wrong_owner_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut attacker = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let mut dest = user_token_account(attacker.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_owner = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut attacker,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_owner, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_withdraw_rejects_over_capital_and_insufficient_vault_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 500);

    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 501);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let over_capital = run_ix(
        Instruction::Withdraw { amount: 501 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(over_capital, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut underfunded_vault = vault_token_account(&market, mint, 399);
    let insufficient_vault = run_ix(
        Instruction::Withdraw { amount: 400 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut underfunded_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(insufficient_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_base_unit_secondary_withdraws_but_primary_only_deposits() {
    let mut admin = signer();
    let mut market = market_account();
    let mut primary_mint = mint_account();
    let primary_key = primary_mint.key;
    let mut secondary_mint = mint_account();
    let secondary_key = secondary_mint.key;
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut primary_mint],
    )
    .unwrap();
    configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut primary_mint,
        &mut secondary_mint,
    )
    .unwrap();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let mut secondary_source = user_token_account(owner.key, secondary_key, 1);
    let mut secondary_vault_for_deposit = vault_token_account(&market, secondary_key, 0);
    let mut token_program = token_program_account();
    let secondary_deposit = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut secondary_source,
            &mut secondary_vault_for_deposit,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(secondary_deposit, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut secondary_dest = user_token_account(owner.key, secondary_key, 0);
    let mut primary_vault = vault_token_account(&market, primary_key, 250);
    let mut vault_auth = vault_authority_account(&market);
    let mismatched_vault = run_ix(
        Instruction::Withdraw { amount: 250 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut secondary_dest,
            &mut primary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(mismatched_vault, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut secondary_dest = user_token_account(owner.key, secondary_key, 0);
    let mut secondary_vault = vault_token_account(&market, secondary_key, 250);
    run_ix(
        Instruction::Withdraw { amount: 250 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut secondary_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.vault, 750);
    assert_eq!(account.capital, 750);
}

#[test]
fn v16_wrapper_base_unit_authority_changes_primary_and_rotates() {
    let mut admin = signer();
    let mut market = market_account();
    let mut old_primary_mint = mint_account();
    let old_primary_key = old_primary_mint.key;
    let mut new_primary_mint = mint_account();
    let new_primary_key = new_primary_mint.key;
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut old_primary_mint],
    )
    .unwrap();
    configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut old_primary_mint,
        &mut new_primary_mint,
    )
    .unwrap();

    // v17: UpdateBaseUnitMints is gated by marketauth only (no separate base_unit_authority).
    // Rotate marketauth to base_unit_authority via UpdateAuthority (matrix row 27/29).
    let mut base_unit_authority = signer();
    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: base_unit_authority.key.to_bytes(),
        },
        &mut [&mut admin, &mut base_unit_authority, &mut market],
    )
    .unwrap();

    let before_rotation = market.data.clone();
    let stale_admin = configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut new_primary_mint,
        &mut old_primary_mint,
    );
    assert_err_and_market_unchanged(stale_admin, &market, &before_rotation);

    configure_base_unit_mints(
        &mut base_unit_authority,
        &mut market,
        &mut new_primary_mint,
        &mut old_primary_mint,
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.collateral_mint, new_primary_key.to_bytes());
    assert_eq!(cfg.secondary_collateral_mint, old_primary_key.to_bytes());
    assert_eq!(cfg.marketauth, base_unit_authority.key.to_bytes());

    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let before_deposit = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let mut old_primary_source = user_token_account(owner.key, old_primary_key, 1);
    let mut old_primary_vault = vault_token_account(&market, old_primary_key, 0);
    let mut token_program = token_program_account();
    let old_primary_deposit = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut old_primary_source,
            &mut old_primary_vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(old_primary_deposit, &market, &before_deposit);
    assert_eq!(portfolio.data, before_portfolio);

    let mut new_primary_source = user_token_account(owner.key, new_primary_key, 1);
    let mut new_primary_vault = vault_token_account(&market, new_primary_key, 0);
    run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut new_primary_source,
            &mut new_primary_vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.vault, 1);
    assert_eq!(account.capital, 1);
}

#[test]
fn v16_wrapper_base_unit_mint_rotation_rejects_nonempty_market_vault() {
    let mut admin = signer();
    let mut market = market_account();
    let mut old_primary_mint = mint_account();
    let mut new_primary_mint = mint_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut old_primary_mint],
    )
    .unwrap();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1);

    let before = market.data.clone();
    let rotate = configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut old_primary_mint,
        &mut new_primary_mint,
    );
    assert_err_and_market_unchanged(rotate, &market, &before);

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.collateral_mint, old_primary_mint.key.to_bytes());
    assert_eq!(group.vault, 1);
    assert_eq!(group.c_tot, 1);
}

#[test]
fn v16_wrapper_base_unit_atomic_swap_requires_primary_in_for_secondary_out() {
    let mut admin = signer();
    let mut market = market_account();
    let mut primary_mint = mint_account();
    let primary_key = primary_mint.key;
    let mut secondary_mint = mint_account();
    let secondary_key = secondary_mint.key;

    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut primary_mint],
    )
    .unwrap();
    configure_base_unit_mints(
        &mut admin,
        &mut market,
        &mut primary_mint,
        &mut secondary_mint,
    )
    .unwrap();

    let mut attacker = signer();
    let mut primary_source = user_token_account(attacker.key, primary_key, 50);
    let mut primary_vault = vault_token_account(&market, primary_key, 0);
    let mut secondary_dest = user_token_account(attacker.key, secondary_key, 0);
    let mut secondary_vault = vault_token_account(&market, secondary_key, 50);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let zero_swap = run_ix(
        Instruction::SwapSecondaryForPrimary { amount: 0 },
        &mut [
            &mut admin,
            &mut market,
            &mut primary_source,
            &mut primary_vault,
            &mut secondary_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(zero_swap, &market, &before_market);

    let unauthorized = run_ix(
        Instruction::SwapSecondaryForPrimary { amount: 50 },
        &mut [
            &mut attacker,
            &mut market,
            &mut primary_source,
            &mut primary_vault,
            &mut secondary_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before_market);

    let mut short_primary = user_token_account(admin.key, primary_key, 49);
    let mut primary_vault = vault_token_account(&market, primary_key, 0);
    let mut secondary_dest = user_token_account(admin.key, secondary_key, 0);
    let mut secondary_vault = vault_token_account(&market, secondary_key, 50);
    let short_primary_in = run_ix(
        Instruction::SwapSecondaryForPrimary { amount: 50 },
        &mut [
            &mut admin,
            &mut market,
            &mut short_primary,
            &mut primary_vault,
            &mut secondary_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(short_primary_in, &market, &before_market);

    let mut primary_source = user_token_account(admin.key, primary_key, 50);
    let mut primary_vault = vault_token_account(&market, primary_key, 0);
    let mut secondary_dest = user_token_account(admin.key, secondary_key, 0);
    let mut secondary_vault = vault_token_account(&market, secondary_key, 50);
    run_ix(
        Instruction::SwapSecondaryForPrimary { amount: 50 },
        &mut [
            &mut admin,
            &mut market,
            &mut primary_source,
            &mut primary_vault,
            &mut secondary_dest,
            &mut secondary_vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    assert_eq!(
        market.data, before_market,
        "base-unit swaps only exchange SPL custody and must not change engine accounting"
    );
}

#[test]
fn v16_wrapper_close_portfolio_rejects_wrong_owner_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut attacker = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut attacker, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_cross_market_portfolio_provenance_is_fail_closed() {
    let mut admin_a = signer();
    let mut admin_b = signer();
    let mut market_a = market_account();
    let mut market_b = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    let _mint_a = init_market(&mut admin_a, &mut market_a);
    let mint_b = init_market(&mut admin_b, &mut market_b);
    init_portfolio(&mut owner_a, &mut market_a, &mut account_a);
    init_portfolio(&mut owner_b, &mut market_b, &mut account_b);
    deposit(&mut owner_a, &mut market_a, &mut account_a, 1_000);
    deposit(&mut owner_b, &mut market_b, &mut account_b, 1_000);

    let before_market_a = market_a.data.clone();
    let before_market_b = market_b.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();

    let mut source_b = user_token_account(owner_a.key, mint_b, 1_000);
    let mut vault_b = vault_token_account(&market_b, mint_b, 1_000);
    let mut token_program = token_program_account();
    let cross_deposit = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner_a,
            &mut market_b,
            &mut account_a,
            &mut source_b,
            &mut vault_b,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(cross_deposit, &market_b, &before_market_b);
    assert_eq!(account_a.data, before_a);

    let cross_crank = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner_a, &mut market_b, &mut account_a],
    );
    assert_err_and_market_unchanged(cross_crank, &market_b, &before_market_b);
    assert_eq!(account_a.data, before_a);

    let cross_close = run_ix(
        Instruction::ClosePortfolio,
        &mut [&mut owner_a, &mut market_b, &mut account_a],
    );
    assert_err_and_market_unchanged(cross_close, &market_b, &before_market_b);
    assert_eq!(account_a.data, before_a);

    let cross_trade = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market_a,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(cross_trade, &market_a, &before_market_a);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_same_owner_can_trade_independent_positions_across_markets() {
    let mut admin_a = signer();
    let mut admin_b = signer();
    let mut market_a = market_account();
    let mut market_b = market_account();
    let mut owner = signer();
    let mut counterparty_owner_a = signer();
    let mut counterparty_owner_b = signer();
    let mut owner_account_a = portfolio_account();
    let mut owner_account_b = portfolio_account();
    let mut counterparty_a = portfolio_account();
    let mut counterparty_b = portfolio_account();

    init_market(&mut admin_a, &mut market_a);
    init_market(&mut admin_b, &mut market_b);
    init_portfolio(&mut owner, &mut market_a, &mut owner_account_a);
    init_portfolio(&mut owner, &mut market_b, &mut owner_account_b);
    init_portfolio(
        &mut counterparty_owner_a,
        &mut market_a,
        &mut counterparty_a,
    );
    init_portfolio(
        &mut counterparty_owner_b,
        &mut market_b,
        &mut counterparty_b,
    );
    deposit(&mut owner, &mut market_a, &mut owner_account_a, 1_000_000);
    deposit(&mut owner, &mut market_b, &mut owner_account_b, 2_000_000);
    deposit(
        &mut counterparty_owner_a,
        &mut market_a,
        &mut counterparty_a,
        1_000_000,
    );
    deposit(
        &mut counterparty_owner_b,
        &mut market_b,
        &mut counterparty_b,
        2_000_000,
    );

    let market_b_before_a_trade = market_b.data.clone();
    let owner_b_before_a_trade = owner_account_b.data.clone();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner,
            &mut counterparty_owner_a,
            &mut market_a,
            &mut owner_account_a,
            &mut counterparty_a,
        ],
    )
    .unwrap();
    assert_eq!(
        market_b.data, market_b_before_a_trade,
        "valid trade in market A must not mutate market B"
    );
    assert_eq!(
        owner_account_b.data, owner_b_before_a_trade,
        "valid trade in market A must not mutate owner's market-B portfolio"
    );

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: -(2 * POS_SCALE as i128),
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner,
            &mut counterparty_owner_b,
            &mut market_b,
            &mut owner_account_b,
            &mut counterparty_b,
        ],
    )
    .unwrap();

    let (_, group_a) = state::read_market(&market_a.data).unwrap();
    let (_, group_b) = state::read_market(&market_b.data).unwrap();
    let owner_a = state::read_portfolio(&owner_account_a.data).unwrap();
    let owner_b = state::read_portfolio(&owner_account_b.data).unwrap();
    assert_eq!(
        owner_a.provenance_header.market_group_id,
        market_a.key.to_bytes()
    );
    assert_eq!(
        owner_b.provenance_header.market_group_id,
        market_b.key.to_bytes()
    );
    assert_eq!(owner_a.owner, owner.key.to_bytes());
    assert_eq!(owner_b.owner, owner.key.to_bytes());
    assert_eq!(owner_a.legs[0].basis_pos_q, POS_SCALE as i128);
    assert_eq!(owner_b.legs[0].basis_pos_q, -(2 * POS_SCALE as i128));
    assert_eq!(group_a.assets[0].oi_eff_long_q, POS_SCALE);
    assert_eq!(group_a.assets[0].oi_eff_short_q, POS_SCALE);
    assert_eq!(group_b.assets[0].oi_eff_long_q, 2 * POS_SCALE);
    assert_eq!(group_b.assets[0].oi_eff_short_q, 2 * POS_SCALE);
}

#[test]
fn v16_wrapper_account_kind_confusion_is_rejected_before_mutation() {
    let mut admin = signer();
    let mut admin_b = signer();
    let mut market = market_account();
    let mut second_market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_market(&mut admin_b, &mut second_market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    let before_market = market.data.clone();
    let before_second_market = second_market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let mut source = user_token_account(owner.key, mint, 1_000);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut token_program = token_program_account();

    let portfolio_as_market = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut portfolio,
            &mut market,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert!(
        portfolio_as_market.is_err(),
        "portfolio-as-market must reject"
    );
    assert_eq!(market.data, before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let market_as_portfolio = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut second_market],
    );
    assert!(
        market_as_portfolio.is_err(),
        "market-as-portfolio must reject"
    );
    assert_eq!(market.data, before_market);
    assert_eq!(second_market.data, before_second_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_portfolio_key_mismatch_and_self_trade_are_rejected() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();

    account_a.key = Pubkey::new_unique();
    let mut source = user_token_account(owner_a.key, mint, 1_000);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut token_program = token_program_account();
    let key_mismatch_deposit = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(key_mismatch_deposit, &market, &before_market);
    assert_eq!(account_a.data, before_a);

    account_a.key = Pubkey::new_from_array(
        state::read_portfolio(&account_a.data)
            .unwrap()
            .provenance_header
            .portfolio_account_id,
    );
    account_b.key = account_a.key;
    let same_key_trade = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(same_key_trade, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradenocpi_negative_size_flips_long_short_roles() {
    let mut admin = signer();
    let mut market = market_account();
    let mut signer_a = signer();
    let mut signer_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut signer_a, &mut market, &mut account_a);
    init_portfolio(&mut signer_b, &mut market, &mut account_b);
    deposit(&mut signer_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut signer_b, &mut market, &mut account_b, 1_000_000);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: -(POS_SCALE as i128),
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut signer_a,
            &mut signer_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    )
    .unwrap();

    let a = state::read_portfolio(&account_a.data).unwrap();
    let b = state::read_portfolio(&account_b.data).unwrap();
    assert_eq!(a.legs[0].basis_pos_q, -(POS_SCALE as i128));
    assert_eq!(b.legs[0].basis_pos_q, POS_SCALE as i128);
}

#[test]
fn v16_wrapper_tradenocpi_accepts_consented_wide_exec_price_without_moving_index() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );

    let (_, before) = state::read_market(&market.data).unwrap();
    assert_eq!(before.assets[0].effective_price, 100);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 150,
            fee_bps: 100,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(
        group.assets[0].effective_price, 100,
        "execution price must not move the oracle/index state"
    );
    assert!(!percolator::active_bitmap_is_empty(long.active_bitmap));
    assert!(!percolator::active_bitmap_is_empty(short.active_bitmap));
    assert_eq!(long.legs[0].basis_pos_q, (10 * POS_SCALE) as i128);
    assert_eq!(short.legs[0].basis_pos_q, -((10 * POS_SCALE) as i128));
    assert_eq!(
        group.insurance, 10,
        "W1 (fee-on-mark): billed on the mark (100), not exec_price (150) — notional=1000 @ 100 bps = 10 (taker-only, one side)"
    );
}

#[test]
fn v16_wrapper_configure_hybrid_oracle_composes_toto_sol_cross_and_rejects_rollbacks() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 101);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 102);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        5,
        102,
        10,
        0,
    );

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_leg_count, 3);
    assert_eq!(
        cfg.oracle_leg_prices_e6,
        [4_000_000_000, 150_000_000, 200_000_000]
    );
    assert_eq!(cfg.mark_ewma_e6, 133_333);
    assert_eq!(cfg.oracle_target_price_e6, 133_333);
    assert_eq!(group.assets[0].effective_price, 133_333);

    let mut keeper = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut keeper, &mut market, &mut portfolio);
    usd_jpy.data = make_pyth(&feeds[1], 150_000_000, -6, 1, 99);
    let before = market.data.clone();
    let rollback = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 6,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [
            &mut keeper,
            &mut market,
            &mut portfolio,
            &mut toto_jpy,
            &mut usd_jpy,
            &mut sol_usd,
        ],
    );
    assert_err_and_market_unchanged(rollback, &market, &before);
}

#[test]
fn v16_wrapper_non_base_asset_profile_converts_stoxx_eur_to_base_sol() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_price_move_bps_per_slot,
                initial_price,
                ..
            } = ix
            {
                *initial_price = 1_000_000;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        1_000_000,
    )
    .unwrap();

    let feeds = [[0x44u8; 32], [0x45u8; 32], [0x46u8; 32]];
    let mut stoxx_eur = pyth_account(&feeds[0], 4_500_000_000, -6, 1, 100);
    let mut eur_usd = pyth_account(&feeds[1], 1_100_000, -6, 1, 101);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 102);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 1,
            now_slot: 5,
            now_unix_ts: 102,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut stoxx_eur,
            &mut eur_usd,
            &mut sol_usd,
        ],
    )
    .unwrap();

    let (cfg, group) = state::read_market(&market.data).unwrap();
    let base_profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    let stoxx_profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(
        cfg.oracle_mode, ORACLE_MODE_MANUAL,
        "config-level oracle fields are only the asset-0 mirror; non-base profiles are per-asset"
    );
    assert_eq!(base_profile.oracle_mode, ORACLE_MODE_MANUAL);
    assert_eq!(group.assets[0].effective_price, 1_000_000);
    assert_eq!(stoxx_profile.oracle_leg_count, 3);
    assert_eq!(stoxx_profile.oracle_leg_flags, ORACLE_LEG_FLAG_DIVIDE_LEG3);
    assert_eq!(
        stoxx_profile.oracle_leg_prices_e6,
        [4_500_000_000, 1_100_000, 200_000_000]
    );
    assert_eq!(stoxx_profile.oracle_target_price_e6, 24_750_000);
    assert_eq!(stoxx_profile.mark_ewma_e6, 24_750_000);
    assert_eq!(group.assets[1].effective_price, 24_750_000);

    let mut keeper = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut keeper, &mut market, &mut portfolio);
    stoxx_eur.data = make_pyth(&feeds[0], 4_600_000_000, -6, 1, 103);
    eur_usd.data = make_pyth(&feeds[1], 1_200_000, -6, 1, 104);
    sol_usd.data = make_pyth(&feeds[2], 200_000_000, -6, 1, 105);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [
            &mut keeper,
            &mut market,
            &mut portfolio,
            &mut stoxx_eur,
            &mut eur_usd,
            &mut sol_usd,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let stoxx_profile = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(group.assets[0].effective_price, 1_000_000);
    assert_eq!(stoxx_profile.oracle_target_price_e6, 27_600_000);
    assert_eq!(stoxx_profile.mark_ewma_e6, 27_600_000);
    assert_eq!(group.assets[1].effective_price, 27_600_000);
}

#[test]
fn v16_wrapper_price_managed_asset_above_portfolio_limit_still_updates_mark_after_trade() {
    let mut admin = signer();
    let mut market = market_account_with_capacity(
        percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize + 1,
    );
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut cranker = signer();
    let mut long_account = portfolio_account_for_market_slots(
        percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize + 1,
    );
    let mut short_account = portfolio_account_for_market_slots(
        percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize + 1,
    );
    let mut crank_account = portfolio_account_for_market_slots(
        percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize + 1,
    );

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                max_trading_fee_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_portfolio_assets = 14;
                *max_trading_fee_bps = 10_000;
                *max_price_move_bps_per_slot = 10_000;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        14,
        1,
        100,
    )
    .unwrap();
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 14,
            now_slot: 1,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    init_portfolio(&mut cranker, &mut market, &mut crank_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 14,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut cranker, &mut market, &mut crank_account],
    )
    .unwrap();
    let before_profile = state::read_asset_oracle_profile(&market.data, 14).unwrap();
    assert_eq!(before_profile.mark_ewma_e6, 100);
    assert_eq!(before_profile.mark_ewma_last_slot, 1);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 14,
            size_q: POS_SCALE as i128,
            exec_price: 200,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let base_profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    let after_profile = state::read_asset_oracle_profile(&market.data, 14).unwrap();
    assert_eq!(base_profile.oracle_mode, ORACLE_MODE_MANUAL);
    assert_eq!(
        after_profile.mark_ewma_e6, 150,
        "valid market slots above the per-portfolio active-position cap still have their own mark"
    );
    assert_eq!(after_profile.mark_ewma_last_slot, 2);
}

#[test]
fn v16_wrapper_hybrid_oracle_accepts_switchboard_and_chainlink_legs() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let switchboard_key = Pubkey::new_unique();
    let chainlink_key = Pubkey::new_unique();
    let mut switchboard = switchboard_account(switchboard_key, 4_000_000_000, 10_000, 100);
    let mut chainlink = chainlink_account(chainlink_key, 150_000_000_000, 8, 100);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 2,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [
                switchboard_key.to_bytes(),
                chainlink_key.to_bytes(),
                [0u8; 32],
            ],
        },
        &mut [&mut admin, &mut market, &mut switchboard, &mut chainlink],
    )
    .unwrap();

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_leg_count, 2);
    assert_eq!(cfg.oracle_leg_prices_e6, [4_000_000_000, 1_500_000_000, 0]);
    assert_eq!(cfg.oracle_target_price_e6, 2_666_666);
    assert_eq!(group.assets[0].effective_price, 2_666_666);
}

#[test]
fn v16_wrapper_switchboard_oracle_rejects_wrong_key_stale_and_conf_wide() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feed_key = Pubkey::new_unique();
    let before = market.data.clone();
    let mut wrong_key = switchboard_account(Pubkey::new_unique(), 100_000_000, 0, 100);
    let wrong_key_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut wrong_key],
    );
    assert_err_and_market_unchanged(wrong_key_result, &market, &before);

    let mut stale = switchboard_account(feed_key, 100_000_000, 0, 39);
    let stale_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut stale],
    );
    assert_err_and_market_unchanged(stale_result, &market, &before);

    let mut wide = switchboard_account(feed_key, 100_000_000, 6_000_000, 100);
    let conf_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut wide],
    );
    assert_err_and_market_unchanged(conf_result, &market, &before);
}

#[test]
fn v16_wrapper_chainlink_oracle_rejects_wrong_key_stale_and_bad_answer() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feed_key = Pubkey::new_unique();
    let before = market.data.clone();
    let mut wrong_key = chainlink_account(Pubkey::new_unique(), 100_000_000, 6, 100);
    let wrong_key_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut wrong_key],
    );
    assert_err_and_market_unchanged(wrong_key_result, &market, &before);

    let mut stale = chainlink_account(feed_key, 100_000_000, 6, 39);
    let stale_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut stale],
    );
    assert_err_and_market_unchanged(stale_result, &market, &before);

    let mut bad_answer = chainlink_account(feed_key, 0, 6, 100);
    let bad_result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed_key.to_bytes(), [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut bad_answer],
    );
    assert_err_and_market_unchanged(bad_result, &market, &before);
}

#[test]
fn v16_wrapper_configure_hybrid_oracle_allows_empty_portfolio_grief_without_blocking_setup() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut griefer = signer();
    let mut empty_portfolio = portfolio_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut griefer, &mut market, &mut empty_portfolio);
    assert_eq!(
        state::read_market(&market.data)
            .unwrap()
            .1
            .materialized_portfolio_count,
        1,
        "test must model a public empty portfolio created before oracle setup"
    );

    let feeds = [[0xb1u8; 32], [0xb2u8; 32], [0xb3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        10,
        0,
    );

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_leg_count, 3);
    assert_eq!(cfg.mark_ewma_e6, 133_333);
    assert_eq!(group.materialized_portfolio_count, 1);
    assert_eq!(group.c_tot, 0);
}

#[test]
fn v16_wrapper_configure_hybrid_oracle_allows_prefunded_flat_portfolio_without_blocking_setup() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1);

    let feeds = [[0xc1u8; 32], [0xc2u8; 32], [0xc3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        10,
        0,
    );

    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.oracle_leg_count, 3);
    assert_eq!(group.c_tot, 1);
    assert_eq!(
        group.assets[0].oi_eff_long_q, 0,
        "test must keep the prefunded account flat"
    );
}

#[test]
fn v16_wrapper_configure_hybrid_oracle_rejects_after_positions_enter_market() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    run_ix(
        default_init_market_ix(),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let feeds = [[0xd4u8; 32], [0xd5u8; 32], [0xd6u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    let before = market.data.clone();
    let result = run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 100,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut toto_jpy,
            &mut usd_jpy,
            &mut sol_usd,
        ],
    );
    assert_err_and_market_unchanged(result, &market, &before);
}

#[test]
fn v16_wrapper_configuring_empty_asset_does_not_advance_other_asset_fee_anchor() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
                *maintenance_fee_per_slot = 1;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (_, before_configure) = state::read_market(&market.data).unwrap();
    assert_eq!(before_configure.slot_last, 0);
    assert_ne!(
        before_configure.assets[0].oi_eff_long_q, 0,
        "asset 0 must be exposed for this regression"
    );
    assert_eq!(
        before_configure.assets[1].oi_eff_long_q, 0,
        "asset 1 must be empty so oracle reconfiguration is targeted"
    );

    // v17: reset_empty_asset_oracle_anchor_not_atomic requires the entire group to have
    // no positions (any asset with OI prevents reconfiguration). This is a stricter guard
    // than the old per-asset check; it preserves the fee-anchor non-advancement invariant
    // by blocking the operation rather than allowing it with a narrow carve-out.
    // Matrix row: v17-oracle-reconfigure-group-wide-guard (PR #v17-convergence).
    //
    // With positions on asset 0, configuring asset 1 is blocked entirely — the fee anchor
    // (slot_last) is NOT advanced because the instruction is rejected.
    let before_blocked = market.data.clone();
    assert_err_and_market_unchanged(
        run_ix(
            Instruction::ConfigureEwmaMark {
                asset_index: 1,
                now_slot: 100,
                initial_mark_e6: 250,
                mark_ewma_halflife_slots: 10,
                mark_min_fee: 0,
            },
            &mut [&mut admin, &mut market],
        ),
        &market,
        &before_blocked,
    );
    // slot_last is still 0: the blocked configure did not advance the fee anchor.
    let (_, blocked_group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        blocked_group.slot_last, 0,
        "blocked configure must not advance the fee anchor"
    );

    // Flatten asset 0 positions (trade back to zero OI) so the group is position-free.
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: -(POS_SCALE as i128),
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (_, flattened) = state::read_market(&market.data).unwrap();
    assert_eq!(flattened.assets[0].oi_eff_long_q, 0, "asset 0 OI must be zero after flattening");

    // With no positions, oracle reconfiguration of the empty asset 1 is permitted and
    // advancing slot_last is safe (there are no exposed positions to misprice fees against).
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 1,
            now_slot: 100,
            initial_mark_e6: 250,
            mark_ewma_halflife_slots: 10,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (_, after_configure) = state::read_market(&market.data).unwrap();
    assert_eq!(after_configure.current_slot, 100);
    assert_eq!(after_configure.assets[1].effective_price, 250);

    let feeds = [[0xe1u8; 32], [0xe2u8; 32], [0xe3u8; 32]];
    let mut leg0 = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 1_000);
    let mut leg1 = pyth_account(&feeds[1], 150_000_000, -6, 1, 1_000);
    let mut leg2 = pyth_account(&feeds[2], 200_000_000, -6, 1, 1_000);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 1,
            now_slot: 101,
            now_unix_ts: 1_000,
            oracle_leg_count: 3,
            oracle_leg_flags: ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 10,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: feeds,
        },
        &mut [&mut admin, &mut market, &mut leg0, &mut leg1, &mut leg2],
    )
    .unwrap();
    let (_, after_hybrid_configure) = state::read_market(&market.data).unwrap();
    assert_eq!(after_hybrid_configure.current_slot, 101);

    // After flattening and configuring, fee sync on the (now-flat) long account charges the
    // maintenance fee for elapsed slots at the full now_slot anchor (v17: flat accounts use
    // now_slot as fee anchor, not slot_last — maintenance fees are always collected for idle
    // capital). This is safe: there are no open positions to misprice against the moved anchor.
    sync_maintenance_fee(&mut market, &mut long_account, 101).unwrap();
}

#[test]
fn v16_wrapper_hybrid_fresh_crank_tracks_external_composite_then_after_hours_trade_moves_mark() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0x44u8; 32], [0x55u8; 32], [0x66u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );

    let mut keeper = signer();
    let mut keeper_portfolio = portfolio_account();
    init_portfolio(&mut keeper, &mut market, &mut keeper_portfolio);
    toto_jpy.data = make_pyth(&feeds[0], 4_200_000_000, -6, 1, 101);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [
            &mut keeper,
            &mut market,
            &mut keeper_portfolio,
            &mut toto_jpy,
            &mut usd_jpy,
            &mut sol_usd,
        ],
    )
    .unwrap();
    let (cfg_after_fresh, group_after_fresh) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group_after_fresh.assets[0].effective_price, 140_000,
        "flat markets accept the fresh composite target directly"
    );
    assert_eq!(cfg_after_fresh.mark_ewma_e6, 140_000);
    assert_eq!(cfg_after_fresh.last_good_oracle_slot, 2);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 0;
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 10;
        group.slot_last = 10;
        group.assets[0].slot_last = 10;
        group.assets[0].raw_oracle_target_price = group.assets[0].effective_price;
        group.loss_stale_active = false;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    let base_only_fee = two_sided_fee(size_q, exec_price, 1);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (after_cfg, after_group) = state::read_market(&market.data).unwrap();
    assert!(
        after_group.insurance > base_only_fee,
        "after-hours hybrid trade must pay dynamic mark-movement surcharge"
    );
    assert!(
        after_cfg.mark_ewma_e6 > before_cfg.mark_ewma_e6,
        "after-hours execution must move the fallback EWMA mark"
    );
    assert_eq!(
        after_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "execution price flexibility must not rewrite the accepted oracle index"
    );
}

#[test]
fn v16_wrapper_hybrid_regular_hours_wide_trade_keeps_mark_pinned_to_external_oracle() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0x77u8; 32], [0x88u8; 32], [0x99u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        100,
        0,
    );
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (after_cfg, after_group) = state::read_market(&market.data).unwrap();
    assert_eq!(after_cfg.mark_ewma_e6, before_cfg.mark_ewma_e6);
    assert_eq!(
        after_cfg.mark_ewma_last_slot,
        before_cfg.mark_ewma_last_slot
    );
    assert_eq!(
        after_group.insurance,
        // W1 (fee-on-mark): billed on the mark (effective_price), not the wide consented exec_price.
        // Taker-only (design §1A): total collected is one side's fee, not two.
        taker_only_fee(size_q, before_group.assets[0].effective_price, 1),
        "regular-hours hybrid pays only the static 1 bp taker-only fee (on the mark)"
    );
}

#[test]
fn v16_wrapper_hybrid_after_hours_downward_mark_moves_effective_price() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0xd1u8; 32], [0xd2u8; 32], [0xd3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(
        &mut long_owner,
        &mut market,
        &mut long_account,
        1_000_000_000,
    );
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        1_000_000_000,
    );
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 0;
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price / 2;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (after_trade_cfg, after_trade_group) = state::read_market(&market.data).unwrap();
    assert!(
        after_trade_cfg.mark_ewma_e6 < before_cfg.mark_ewma_e6,
        "after-hours below-mark trade should move fallback EWMA down"
    );
    assert_eq!(
        after_trade_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "trades update fallback mark, not the accepted engine price"
    );

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 11,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut long_account],
    )
    .unwrap();
    let (_, after_crank_group) = state::read_market(&market.data).unwrap();
    let expected = oracle_v16::effective_price_from_target(
        after_trade_group.assets[0].effective_price,
        after_trade_cfg.mark_ewma_e6,
        after_trade_group.config.max_price_move_bps_per_slot,
        1,
        true,
    );
    assert!(
        expected < after_trade_group.assets[0].effective_price,
        "test must select a fallback mark below the accepted engine price"
    );
    assert_eq!(after_crank_group.assets[0].effective_price, expected);
}

#[test]
fn v16_wrapper_hybrid_after_hours_fee_floor_scales_with_next_crank_segment_budget() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                min_funding_lifetime_slots,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
                *max_accrual_dt_slots = 10;
                *min_funding_lifetime_slots = 10;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0xf1u8; 32], [0xf2u8; 32], [0xf3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        10_000_000,
    );
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 0;
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 11;
        group.slot_last = 1;
        group.loss_stale_active = false;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (_, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price;
    let before_insurance = before_group.insurance;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: size_q as i128,
            exec_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    let (_, after_group) = state::read_market(&market.data).unwrap();
    let fee_delta = after_group.insurance - before_insurance;
    // Taker-only (design §1A): total collected is one side's fee, not two.
    let one_slot_floor = taker_only_fee(size_q, exec_price, 1 + 500);
    let full_segment_floor = taker_only_fee(size_q, exec_price, 1 + 500 * 10);
    assert!(
        fee_delta >= full_segment_floor,
        "stale fallback fee must cover the full price movement budget the next honest crank can consume"
    );
    assert!(
        full_segment_floor > one_slot_floor,
        "test must distinguish a one-slot fee floor from the full bounded segment floor"
    );
}

#[test]
fn v16_wrapper_hybrid_after_hours_max_caller_fee_does_not_bypass_dynamic_fee_rejection() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0xe1u8; 32], [0xe2u8; 32], [0xe3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(
        &mut long_owner,
        &mut market,
        &mut long_account,
        1_000_000_000,
    );
    deposit(
        &mut short_owner,
        &mut market,
        &mut short_account,
        1_000_000_000,
    );

    let initial_price = state::read_market(&market.data).unwrap().1.assets[0].effective_price;
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (100 * POS_SCALE) as i128,
            exec_price: initial_price,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 0;
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_market = market.data.clone();
    let before_long = long_account.data.clone();
    let before_short = short_account.data.clone();
    let (_, before_group) = state::read_market(&market.data).unwrap();
    let probe_size = POS_SCALE / 100;
    let probe_price = before_group.assets[0].effective_price * 2;
    let max_side_q = core::cmp::max(
        before_group.assets[0].oi_eff_long_q,
        before_group.assets[0].oi_eff_short_q,
    );
    let max_side_notional =
        (max_side_q * before_group.assets[0].effective_price as u128 + POS_SCALE - 1) / POS_SCALE;
    let required = policy_v16::dynamic_fee_bps_with_externality_floor(
        10_000,
        state::read_market(&market.data).unwrap().0.mark_ewma_e6,
        oracle_v16::clamp_toward_engine_dt(
            before_group.assets[0].effective_price,
            probe_price,
            before_group.config.max_price_move_bps_per_slot,
            1,
        ),
        1,
        0,
        before_group.current_slot,
        probe_size * probe_price as u128 / POS_SCALE,
        max_side_notional.checked_mul(2).unwrap(),
        0,
        before_group.config.max_price_move_bps_per_slot,
    );
    assert!(
        required.is_none(),
        "test must select a trade whose dynamic externality fee exceeds the market cap"
    );

    let result = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: probe_size as i128,
            exec_price: probe_price,
            fee_bps: 10_000,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(result, &market, &before_market);
    assert_eq!(long_account.data, before_long);
    assert_eq!(short_account.data, before_short);
}

#[test]
fn v16_wrapper_tradenocpi_applies_static_base_fee_floor() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                ..
            } = ix
            {
                *max_trading_fee_bps = 1_000;
                *trade_fee_base_bps = 100;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 150,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.insurance, 10,
        "W1 (fee-on-mark): zero caller fee still pays the 100 bps base fee, billed on the mark (100) \
         not exec_price (150) — notional=1000 @ 100bps = 10 (taker-only, one side)"
    );
}

#[test]
fn v16_wrapper_tradenocpi_rejects_when_consented_price_would_break_margin() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 100);
    deposit(&mut short_owner, &mut market, &mut short_account, 100);

    let result = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );

    assert!(
        result.is_err(),
        "the wrapper may accept any consented price, but the engine must still reject unhealthy accounts"
    );
    let long = state::read_portfolio(&long_account.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert!(percolator::active_bitmap_is_empty(long.active_bitmap));
    assert!(percolator::active_bitmap_is_empty(short.active_bitmap));
}

#[test]
fn v16_wrapper_convert_released_pnl_respects_cap_and_unlocks_withdrawal() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);

    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    push_base_ewma_mark(&mut admin, &mut market, 1, 102);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut long_account],
    )
    .unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 101,
            fee_bps: 0,
        },
        &mut [
            &mut short_owner,
            &mut long_owner,
            &mut market,
            &mut short_account,
            &mut long_account,
        ],
    )
    .unwrap();

    let before_market = market.data.clone();
    let before_long = long_account.data.clone();
    let before_short = short_account.data.clone();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert!(percolator::active_bitmap_is_empty(long.active_bitmap));
    assert_eq!(long.pnl, 2);
    let capital_before_convert = long.capital;

    let too_low_cap = run_ix(
        Instruction::ConvertReleasedPnl { amount: 1 },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(too_low_cap, &market, &before_market);
    assert_eq!(long_account.data, before_long);
    assert_eq!(short_account.data, before_short);

    run_ix(
        Instruction::ConvertReleasedPnl { amount: 2 },
        &mut [&mut long_owner, &mut market, &mut long_account],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(long.pnl, 0);
    assert_eq!(long.capital, capital_before_convert + 2);
    assert_eq!(group.pnl_pos_tot, 0);

    withdraw(&mut long_owner, &mut market, &mut long_account, 2);
    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(long.capital, capital_before_convert);
    assert_eq!(group.vault, 19_998);
}

#[test]
fn v16_wrapper_convert_released_pnl_rejects_resolved_market_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 10);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let market_before = market.data.clone();
    let portfolio_before = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::ConvertReleasedPnl { amount: 1 },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(rejected, &market, &market_before);
    assert_eq!(portfolio.data, portfolio_before);
}

#[test]
fn v16_wrapper_tradenocpi_rejects_bad_size_and_missing_signer_before_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut unsigned_b = TestAccount::new(owner_b.key, Pubkey::new_unique(), 0);
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    let missing_signature = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut unsigned_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(missing_signature, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    let zero_size = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: 0,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(zero_size, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    let min_size = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: i128::MIN,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(min_size, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradenocpi_rejects_wrong_owner_fee_cap_and_invalid_asset() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut attacker = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    let wrong_owner = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut attacker,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(wrong_owner, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    let fee_over_cap = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 10_001,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(fee_over_cap, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    let invalid_asset = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut account_a,
            &mut account_b,
        ],
    );
    assert_err_and_market_unchanged(invalid_asset, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    // NOTE: zero / above-MAX exec_price are NOT rejected here under W1 (fee-on-mark). The engine
    // settles entry + initial margin + fee on the MARK (effective_price); the caller's exec_price
    // has no settlement role (it only feeds clamped + MAX_ORACLE_PRICE-guarded hybrid mark
    // discovery, a no-op for this non-price-managed market). A degenerate exec_price is therefore
    // accepted and pays the FULL mark-based fee — covered by
    // v16_wrapper_tradenocpi_accepts_degenerate_exec_price_billing_on_mark.
}

#[test]
fn v16_wrapper_tradecpi_executes_manual_consented_wide_price() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let (_, before_group) = state::read_market(&market.data).unwrap();
    let size_q = POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        size_q as i128,
        size_q as i128,
        exec_price,
        0,
        0,
    )
    .unwrap();

    let (_, after_group) = state::read_market(&market.data).unwrap();
    let after_a = state::read_portfolio(&account_a.data).unwrap();
    let after_b = state::read_portfolio(&account_b.data).unwrap();
    assert_eq!(
        after_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "consented execution price must not rewrite the accepted engine price"
    );
    assert_eq!(after_a.legs[0].basis_pos_q, size_q as i128);
    assert_eq!(after_b.legs[0].basis_pos_q, -(size_q as i128));
}

#[test]
fn v16_wrapper_tradecpi_executes_on_added_asset_and_binds_matcher_asset_echo() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
            }
        }),
    );
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        1,
        250,
    )
    .unwrap();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let (_, before_group) = state::read_market(&market.data).unwrap();
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        2,
        POS_SCALE as i128,
        POS_SCALE as i128,
        275,
        0,
        0,
    )
    .unwrap();

    let (_, after_group) = state::read_market(&market.data).unwrap();
    let after_a = state::read_portfolio(&account_a.data).unwrap();
    let after_b = state::read_portfolio(&account_b.data).unwrap();
    assert_eq!(
        after_group.assets[2].effective_price, before_group.assets[2].effective_price,
        "CPI execution price for an added asset must not rewrite the accepted index"
    );
    assert_eq!(after_group.assets[0].oi_eff_long_q, 0);
    assert_eq!(after_group.assets[0].oi_eff_short_q, 0);
    assert_eq!(after_group.assets[2].oi_eff_long_q, POS_SCALE);
    assert_eq!(after_group.assets[2].oi_eff_short_q, POS_SCALE);
    assert_eq!(after_a.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(after_b.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(
        active_leg_for_asset(&after_a, 2).basis_pos_q,
        POS_SCALE as i128
    );
    assert_eq!(
        active_leg_for_asset(&after_b, 2).basis_pos_q,
        -(POS_SCALE as i128)
    );
}

#[test]
fn v16_wrapper_tradecpi_hybrid_regular_and_after_hours_follow_mark_policy() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0xc1u8; 32], [0xc2u8; 32], [0xc3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        100,
        0,
    );

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 100_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 100_000_000);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (regular_cfg_before, regular_group_before) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let regular_exec_price = regular_group_before.assets[0].effective_price * 150 / 100;
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        size_q as i128,
        size_q as i128,
        regular_exec_price,
        0,
        0,
    )
    .unwrap();
    let (regular_cfg_after, regular_group_after) = state::read_market(&market.data).unwrap();
    assert_eq!(
        regular_cfg_after.mark_ewma_e6,
        regular_cfg_before.mark_ewma_e6
    );
    assert_eq!(
        regular_cfg_after.mark_ewma_last_slot,
        regular_cfg_before.mark_ewma_last_slot
    );
    assert_eq!(
        regular_group_after.insurance,
        // W1 (fee-on-mark): billed on the mark (effective_price), not the wide consented exec_price.
        // Taker-only (design §1A): total collected is one side's fee, not two.
        taker_only_fee(size_q, regular_group_before.assets[0].effective_price, 1),
        "regular-hours hybrid CPI trades pay only the static fee floor (on the mark)"
    );

    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 0;
        cfg.mark_ewma_last_slot = 0;
        cfg.hybrid_soft_stale_slots = 3;
        group.current_slot = 10;
        group.slot_last = 10;
        group.loss_stale_active = false;
        // v17 test-setup fix: in production the crank advances asset.slot_last to current_slot
        // before the oracle goes stale. Without this, asset_is_loss_stale fires (slot_last=1 <
        // current_slot=10) and blocks the risk-increasing after-hours trade. Simulating a cranked
        // asset state is the correct precondition for the after-hours hybrid EWMA mark test.
        group.assets[0].slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let (stale_cfg_before, stale_group_before) = state::read_market(&market.data).unwrap();
    let stale_exec_price = stale_group_before.assets[0].effective_price * 150 / 100;
    let insurance_before = stale_group_before.insurance;
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        size_q as i128,
        size_q as i128,
        stale_exec_price,
        0,
        0,
    )
    .unwrap();
    let (stale_cfg_after, stale_group_after) = state::read_market(&market.data).unwrap();
    assert!(
        stale_cfg_after.mark_ewma_e6 > stale_cfg_before.mark_ewma_e6,
        "after-hours CPI execution must move the fallback EWMA mark"
    );
    assert!(
        stale_group_after.insurance - insurance_before > two_sided_fee(size_q, stale_exec_price, 1),
        "after-hours CPI execution must pay dynamic mark-movement surcharge"
    );
    assert_eq!(
        stale_group_after.assets[0].effective_price, stale_group_before.assets[0].effective_price,
        "CPI execution price flexibility must not rewrite the accepted index"
    );
}

#[test]
fn v16_wrapper_tradecpi_ewma_mark_trade_moves_mark_without_refreshing_liveness() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 5,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 10_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 10_000_000);
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.mark_ewma_last_slot = 0;
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let (before_cfg, before_group) = state::read_market(&market.data).unwrap();
    let size_q = 10 * POS_SCALE;
    let exec_price = before_group.assets[0].effective_price * 150 / 100;
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        size_q as i128,
        size_q as i128,
        exec_price,
        0,
        0,
    )
    .unwrap();
    let (after_cfg, after_group) = state::read_market(&market.data).unwrap();
    assert!(
        after_cfg.mark_ewma_e6 > before_cfg.mark_ewma_e6,
        "direct EwmaMark CPI trades must use the same dynamic mark path as TradeNoCpi"
    );
    assert_eq!(
        after_cfg.last_good_oracle_slot, before_cfg.last_good_oracle_slot,
        "trade-flow mark movement must not refresh the permissionless stale-resolution liveness stamp"
    );
    assert_eq!(
        after_group.assets[0].effective_price, before_group.assets[0].effective_price,
        "direct EwmaMark CPI trades must not rewrite the accepted effective index"
    );
}

#[test]
fn v16_wrapper_tradecpi_requires_bilateral_signatures_before_matcher_cpi() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut unsigned_b = TestAccount::new(owner_b.key, Pubkey::new_unique(), 0);
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: matcher_delegate includes maker_owner in PDA seeds.  owner_b IS the maker_owner.
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    // v17 TradeCpi: 7 accounts [signer_a, market, account_a, account_b, matcher_prog,
    // matcher_ctx, matcher_delegate].  owner_b (unsigned_b) is NOT in the account list —
    // bilateral-signature check is no longer part of handle_trade_cpi (matrix row 29).
    // The rejection comes from signer_a not signing instead.  This test now verifies that
    // an unsigned owner_a causes Unauthorized (or similar) — use account[0] non-signer path.
    let mut non_signer_a = TestAccount::new(owner_a.key, Pubkey::new_unique(), 0); // not signed
    let _ = unsigned_b; // unused in v17 TradeCpi account list
    let rejected = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut non_signer_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
    assert_eq!(
        matcher_context.data,
        vec![0u8; 320],
        "signature failure must happen before matcher context mutation"
    );
}

#[test]
fn v16_wrapper_tradecpi_rejects_wrong_delegate_and_unsafe_tail_before_cpi() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    let mut wrong_delegate = TestAccount::new(Pubkey::new_unique(), Pubkey::default(), 0);

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    // v17 TradeCpi: 7 accounts. Pass wrong_delegate at slot 6 — handler rejects via expect_key.
    let wrong_delegate_result = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut wrong_delegate,
        ],
    );
    assert_err_and_market_unchanged(wrong_delegate_result, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    // v17: matcher_delegate includes maker_owner in PDA seeds.
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );
    let mut program_owned_tail = TestAccount::new(Pubkey::new_unique(), program_id(), 0).writable();
    let unsafe_tail = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
            &mut program_owned_tail,
        ],
    );
    assert_err_and_market_unchanged(unsafe_tail, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);

    let mut too_many_tail: Vec<TestAccount> = (0..33)
        .map(|_| TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0))
        .collect();
    let oversized_tail = {
        let mut infos = vec![
            owner_a.to_info(),
            market.to_info(),
            account_a.to_info(),
            account_b.to_info(),
            matcher_program.to_info(),
            matcher_context.to_info(),
            delegate.to_info(),
        ];
        infos.extend(too_many_tail.iter_mut().map(TestAccount::to_info));
        processor::process_instruction(
            &program_id(),
            &infos,
            &Instruction::TradeCpi {
                asset_index: 0,
                size_q: POS_SCALE as i128,
                fee_bps: 0,
                limit_price: 0,
            }
            .encode(),
        )
    };
    assert_err_and_market_unchanged(oversized_tail, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradecpi_rejects_wrong_asset_echo_from_matcher() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: matcher_delegate includes maker_owner in PDA seeds.
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    let (_, group) = state::read_market(&market.data).unwrap();
    let req_id = group.current_slot.wrapping_add(1);
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(
        &mut matcher_context,
        100,
        POS_SCALE as i128,
        req_id,
        lp_account_id,
        1,
        100,
    );

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    // v17 TradeCpi: 7 accounts.
    let rejected = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradecpi_rejects_replayed_same_slot_matcher_context_response() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);

    let mut delegate = matcher_delegate_account(
        &market,
        &account_b,
        &owner_b.key,
        &matcher_program,
        &matcher_context,
    );
    deposit(&mut owner_a, &mut market, &mut account_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 1_000_000);

    run_ix(
        Instruction::SetMatcherConfig { enabled: 1 },
        &mut [
            &mut owner_b,
            &mut market,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )
    .unwrap();

    let (_, group_before) = state::read_market(&market.data).unwrap();
    let req_id = state::next_market_matcher_req_id(&market.data).unwrap();
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(
        &mut matcher_context,
        100,
        POS_SCALE as i128,
        req_id,
        lp_account_id,
        0,
        100,
    );

    run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )
    .unwrap();

    let (_, group_after_first) = state::read_market(&market.data).unwrap();
    assert_eq!(group_after_first.current_slot, group_before.current_slot);
    assert_eq!(
        state::next_market_matcher_req_id(&market.data).unwrap(),
        req_id + 1
    );
    let first_a = state::read_portfolio(&account_a.data).unwrap();
    assert_eq!(
        active_leg_for_asset(&first_a, 0).basis_pos_q,
        POS_SCALE as i128
    );

    let before_second_market = market.data.clone();
    let before_second_a = account_a.data.clone();
    let before_second_b = account_b.data.clone();
    let rejected_replay = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_err_and_market_unchanged(rejected_replay, &market, &before_second_market);
    assert_eq!(account_a.data, before_second_a);
    assert_eq!(account_b.data, before_second_b);
}

#[test]
fn v16_wrapper_tradecpi_zero_fill_rejects_resolved_market_before_success() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: matcher_delegate includes maker_owner in PDA seeds.
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let req_id = group.current_slot.wrapping_add(1);
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(&mut matcher_context, 100, 0, req_id, lp_account_id, 0, 100);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    // v17 TradeCpi: 7 accounts.
    let rejected = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradecpi_zero_fill_rejects_fee_above_cap_before_success() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: matcher_delegate includes maker_owner in PDA seeds.
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );
    let (_, group) = state::read_market(&market.data).unwrap();
    let req_id = group.current_slot.wrapping_add(1);
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(&mut matcher_context, 100, 0, req_id, lp_account_id, 0, 100);

    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();
    // v17 TradeCpi: 7 accounts.
    let rejected = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 10_001,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_tradecpi_rejects_corrupt_backing_fee_policy_before_later_checks() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut attacker = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    // v17: matcher_delegate includes maker_owner in PDA seeds.  Derived after init_portfolio below.
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                ..
            } = ix
            {
                *max_trading_fee_bps = 100;
            }
        }),
    );
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    let mut delegate = matcher_delegate_account(
        &market, &account_b, &owner_b.key, &matcher_program, &matcher_context,
    );

    let (mut cfg, _group) = state::read_market(&market.data).unwrap();
    cfg.backing_trade_fee_bps_short = 10_001;
    market.data[HEADER_LEN..HEADER_LEN + WRAPPER_CONFIG_LEN]
        .copy_from_slice(bytemuck::bytes_of(&cfg));
    let before_market = market.data.clone();
    let before_a = account_a.data.clone();
    let before_b = account_b.data.clone();

    // v17 TradeCpi: 7 accounts. attacker is not used — corrupt config is detected
    // before the CPI regardless of who the signer_a is (it's owner_a here; attacker unused).
    let _ = attacker;
    let rejected = run_ix(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::InvalidAccountData),
        "corrupt domain backing fee policy must be rejected before matcher CPI"
    );
    assert_eq!(market.data, before_market);
    assert_eq!(account_a.data, before_a);
    assert_eq!(account_b.data, before_b);
}

#[test]
fn v16_wrapper_permissionless_crank_advances_account_local_market_progress() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    push_base_ewma_mark(&mut admin, &mut market, 1, 102);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut long_account],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(group.slot_last, 1);
    assert_eq!(group.current_slot, 1);
    assert_eq!(group.assets[0].effective_price, 101);
    assert!(long.health_cert.valid);
}

#[test]
fn v16_wrapper_permissionless_crank_does_not_require_owner_signature() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut caller = TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0);
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut caller, &mut market, &mut portfolio],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.current_slot, 1);
    assert!(account.health_cert.valid);
}

#[test]
fn v16_wrapper_permissionless_crank_rejects_stale_now_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    )
    .unwrap();

    let market_before = market.data.clone();
    let portfolio_before = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );

    assert_err_and_market_unchanged(rejected, &market, &market_before);
    assert_eq!(
        portfolio.data, portfolio_before,
        "failed crank must not persist account-local mutation"
    );
}

// FIX E3 (upstream engine #92 / this fork's percolator @ 052baab9+c87a8978)
// fixture repair, reusing the EXACT proven pattern from tests/v16_cu.rs's
// `v16_bpf_permissionless_liquidation_is_bounded` repair (commit cfdd1b73):
// this fixture (deposit 250, single 100->300 EWMA push clamped to 200 by
// max_price_move_bps_per_slot=100%) left the account merely BORDERLINE
// underwater -- a healthy partial close existed (closing part of the leg
// already restores maintenance health at effective_price=200), so
// engine-selected liquidation sizing (E3) correctly preferred that smaller
// partial close over a full close, breaking the old
// `active_bitmap_is_empty` assertion that hard-coded "liquidation always
// fully closes". Repaired identically to cfdd1b73: drop to the MINIMUM
// deposit satisfying initial_margin_bps=10_000 (100%, no leverage headroom
// in this market's default config) so bankruptcy is only reachable via real
// price movement, then drive the account genuinely (not borderline)
// bankrupt via two real EWMA-push+accrual rounds, each capped to the
// market's own max_price_move_bps_per_slot=100% budget (100->200->400),
// landing certified_equity at 100-300=-200 < 0 -- this trips
// `liquidation_engine_close_request_q`'s bankrupt-account early exit
// (`cert.certified_equity < 0`), which forces a full close unconditionally,
// regardless of any partial-close arithmetic. Same "the permissionless crank
// can liquidate an unhealthy candidate, fully" property the test always
// asserted, reached via real price discovery instead of a single push that
// happened to land in the partial-close-eligible region.
#[test]
fn v16_wrapper_permissionless_crank_can_liquidate_unhealthy_candidate() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    // Minimum deposit satisfying initial_margin_bps=10_000 (100%) for a
    // 1-unit position at entry price 100 -- this market has no leverage
    // headroom at entry, so bankruptcy can only be reached via adverse price
    // movement (matches tests/v16_cu.rs::v16_bpf_permissionless_liquidation_is_bounded).
    deposit(&mut short_owner, &mut market, &mut short_account, 100);
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    // Step 1: real EWMA push + accrual crank, capped to a 100% mark move ->
    // effective_price 100 -> 200 (still solvent: capital 100, no loss
    // realized against the fresh leg yet).
    push_base_ewma_mark(&mut admin, &mut market, 1, 999_999);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut short_account],
    )
    .unwrap();
    let short_after_step1 = state::read_portfolio(&short_account.data).unwrap();
    assert!(
        short_after_step1.capital == 100 && short_after_step1.pnl == 0,
        "fixture assumption: position must still be open and solvent after the first accrual round"
    );

    // Step 2: second real EWMA push + accrual, again capped to 100% ->
    // effective_price 200 -> 400 (equity 100-300=-200: genuinely bankrupt).
    push_base_ewma_mark(&mut admin, &mut market, 2, 999_999);
    run_ix(
        Instruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut short_account],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(group.slot_last, 2);
    assert_eq!(group.assets[0].effective_price, 400);
    assert_eq!(short.capital, 0, "bankrupt account's capital must be fully consumed");
    assert_eq!(short.pnl, 0, "settled loss must not leave a dangling pnl balance");
    assert!(
        percolator::active_bitmap_is_empty(short.active_bitmap),
        "a genuinely bankrupt account (certified_equity < 0) must be fully closed through the \
         public crank path, not left with a dangling partial position"
    );
}

#[test]
fn v16_wrapper_liquidation_uses_configured_fee_not_permissionless_caller_fee() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_margin_bps,
                initial_margin_bps,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                liquidation_fee_bps,
                liquidation_fee_cap,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                ..
            } = ix
            {
                *maintenance_margin_bps = 500;
                *initial_margin_bps = 600;
                *min_nonzero_mm_req = 100;
                *min_nonzero_im_req = 101;
                *liquidation_fee_bps = 100;
                *liquidation_fee_cap = percolator::MAX_PROTOCOL_FEE_ABS;
                *max_price_move_bps_per_slot = 3;
                *max_accrual_dt_slots = 100;
                *max_abs_funding_e9_per_slot = 10_000;
                *min_funding_lifetime_slots = 100;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 101);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut short = state::read_portfolio(&short_account.data).unwrap();
        short.capital = 99;
        group.c_tot -= 2;
        group.vault -= 2;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut short_account.data, &short).unwrap();
    }

    run_ix(
        Instruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut short_account],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert!(percolator::active_bitmap_is_empty(short.active_bitmap));
    assert_eq!(
        group.insurance, 1,
        "1% configured liquidation fee on 100 notional must be charged even if caller supplies zero"
    );
}

// FIX E3 (upstream engine #92 / this fork's percolator @ 052baab9+c87a8978)
// fixture repair -- see the detailed derivation comment on
// `v16_wrapper_liquidation_reward_account_is_optional_and_absent_keeps_fee_in_insurance`
// below (identical fixture/root-cause, this test just adds a cranker
// portfolio + a 40% `cranker_share_bps` to verify the SPLIT). Same discipline:
// a real EWMA-driven price move deep enough that no healthy partial close
// exists within `liquidation_partial_search_hi`'s bound, landing on a full
// close with `pnl == 0` throughout (solvent, not bankrupt) so the liquidation
// fee is NOT waived by the `pnl < 0` short-circuit -- the only fixture shape
// where a full close AND a nonzero, cranker-splittable fee coexist.
#[test]
fn v16_wrapper_liquidation_fee_policy_splits_retained_penalty_to_cranker() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut cranker_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    let mut cranker_account = portfolio_account();

    let liquidation_fee_bps = 100u64;
    let max_price_move_bps_per_slot = 3u64;
    let max_accrual_dt_slots = 100u64;
    let cranker_share_bps = 4_000u16;
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_margin_bps,
                initial_margin_bps,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                liquidation_fee_bps: cfg_liquidation_fee_bps,
                liquidation_fee_cap,
                max_price_move_bps_per_slot: cfg_max_price_move_bps_per_slot,
                max_accrual_dt_slots: cfg_max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                ..
            } = ix
            {
                *maintenance_margin_bps = 500;
                *initial_margin_bps = 600;
                *min_nonzero_mm_req = 100;
                *min_nonzero_im_req = 101;
                *cfg_liquidation_fee_bps = liquidation_fee_bps;
                *liquidation_fee_cap = percolator::MAX_PROTOCOL_FEE_ABS;
                *cfg_max_price_move_bps_per_slot = max_price_move_bps_per_slot;
                *cfg_max_accrual_dt_slots = max_accrual_dt_slots;
                *max_abs_funding_e9_per_slot = 10_000;
                *min_funding_lifetime_slots = 100;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    init_portfolio(&mut cranker_owner, &mut market, &mut cranker_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    // Minimum deposit satisfying initial_margin_bps=600 (6%) on a 10,000
    // notional position: no leverage headroom, so underwater is only
    // reachable via a real adverse price move.
    deposit(&mut short_owner, &mut market, &mut short_account, 601);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (100 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateLiquidationFeePolicy { cranker_share_bps },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    // Real adverse EWMA push (target far above any single-step budget so the
    // engine's own linear clamp -- not our target -- determines the landed
    // price); the liquidation crank below performs the clamped accrual and
    // the liquidation in the same instruction.
    push_base_ewma_mark(&mut admin, &mut market, 100, 999_999_999);

    let landed_price =
        clamped_price_after_one_step_ref(100, max_price_move_bps_per_slot, 100, max_accrual_dt_slots);
    let expected_fee = ceil_liquidation_fee_ref(
        100 * POS_SCALE,
        landed_price,
        liquidation_fee_bps,
        0,
        percolator::MAX_PROTOCOL_FEE_ABS,
    );
    let expected_cranker_reward = fee_share_floor_ref(expected_fee, cranker_share_bps);

    let insurance_before = state::read_market(&market.data).unwrap().1.insurance;
    let vault_before = state::read_market(&market.data).unwrap().1.vault;
    run_ix(
        Instruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 100,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [
            &mut cranker_owner,
            &mut market,
            &mut short_account,
            &mut cranker_account,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    let cranker = state::read_portfolio(&cranker_account.data).unwrap();
    assert_eq!(
        group.assets[0].effective_price, landed_price,
        "fixture assumption: the single-step price clamp landed where derived"
    );
    assert_eq!(
        short.pnl, 0,
        "fixture assumption: the account must stay solvent (pnl>=0) through liquidation -- a \
         genuinely bankrupt (pnl<0) account would have its liquidation fee unconditionally \
         waived, making this test's cranker-split premise unreachable"
    );
    assert!(
        percolator::active_bitmap_is_empty(short.active_bitmap),
        "E3 must select a full close when no healthy partial exists within its search bound"
    );
    assert_eq!(
        expected_cranker_reward, 41,
        "fixture assumption: 40% of the derived {expected_fee}-atom liquidation fee floors to a \
         nonzero, easy-to-distinguish-from-the-remainder cranker reward"
    );
    assert_eq!(
        cranker.capital, expected_cranker_reward,
        "cranker reward is credited as Percolator account capital, floor(fee * cranker_share_bps \
         / MAX_MARGIN_BPS) of the derived liquidation fee -- not more (would siphon insurance \
         beyond the configured share) and not less (would starve the cranker incentive)"
    );
    assert_eq!(
        group.insurance,
        insurance_before + expected_fee - expected_cranker_reward,
        "1% liquidation fee on the landed notional is charged in full; the {cranker_share_bps}bps \
         retained-fee share pays {expected_cranker_reward} to the cranker and the remainder stays \
         in insurance -- not the whole fee (would mean the split was skipped) and not less than \
         the remainder (would mean rounding is accumulating beyond the engine's guarantee)"
    );
    assert_eq!(
        group.vault, vault_before,
        "internal cranker reward must not withdraw SPL custody from the vault"
    );
}

// FIX E3 (upstream engine #92 / this fork's percolator @ 052baab9+c87a8978)
// fixture repair. The original fixture directly poked `short.capital = 499`
// (a bare 1-atom deficit under a 500 maintenance requirement, with no real
// price movement and pnl untouched at 0) to represent "unhealthy". Post-E3,
// `liquidation_engine_close_request_q` (percolator src/v16.rs:498) is
// engine-selected: for a deficit that small, a tiny healthy PARTIAL close
// exists and is preferred over a full close, so this fixture's hardcoded
// `active_bitmap_is_empty` assertion broke -- not because liquidation became
// unbounded, but because it became more precise (same root cause as the two
// v16_cu.rs `v16_bpf_permissionless_liquidation_is_bounded`/
// `..._auth_mark_target_effective_lag_...` repairs in commit cfdd1b73).
//
// Repair: replace the raw capital mutation with a REAL short position that
// gets driven underwater via an actual EWMA price push + accrual (matching
// this test's already-EWMA-capable `configure_base_ewma_mark`/
// `push_base_ewma_mark` helpers), landing the deficit deep enough that the
// engine's `liquidation_partial_search_hi`-bounded search finds NO healthy
// partial close and forces a full close instead (see the derivation below --
// this is NOT the separate `certified_equity < 0 || pnl < 0` "genuinely
// bankrupt" branch: verified `short.pnl == 0` throughout below, i.e. the
// account never becomes bankrupt in the engine's sense; a bankrupt account's
// liquidation fee is unconditionally waived by `charge_account_fee_current_
// not_atomic`'s `pnl < 0` short-circuit, which would make this test's whole
// premise -- a NONZERO fee that still gets split with the cranker --
// unreachable. Deep-but-solvent underwater is the only fixture shape where a
// full close AND a nonzero fee coexist).
//
// Numbers are DERIVED, not hardcoded, via `clamped_price_after_one_step_ref`/
// `ceil_liquidation_fee_ref`/`fee_share_floor_ref` above (which mirror the
// engine's `accrue_asset_to_not_atomic`/`liquidation_fee_for_close`/
// `maintenance_cranker_reward` formulas exactly):
//   entry price 100, short 100*POS_SCALE (notional 10,000), deposit 601
//   (exactly the 6% initial-margin minimum, no leverage headroom -- same
//   "no shortcut via a bigger single EWMA push" discipline as the v16_cu fix).
//   One accrual step from slot_last=0 to now_slot=100, max_price_move_bps_
//   per_slot=3, max_accrual_dt_slots=100 clamps price to
//   100 + floor(100*3*100/10_000) = 103 -- a ~41.5%-of-notional maintenance
//   deficit (515 required vs 301 solvent-equity-after-loss-settlement),
//   comfortably beyond what `liquidation_partial_search_hi` allows a partial
//   close to resolve, forcing a full close.
//   fee = ceil(ceil(100*POS_SCALE*103/POS_SCALE)*100/10_000)
//       = ceil(10_300*100/10_000) = 103 (1% liquidation_fee_bps).
// `insurance_before` is read immediately before the liquidation crank (same
// pattern as the pre-existing `vault_before`) because enabling EWMA-mark
// mode via `configure_base_ewma_mark` makes the preceding TradeNoCpi charge
// an incidental hybrid-mode minimum fee despite its `fee_bps: 0` argument --
// unrelated to E3, and isolated by measuring the liquidation's OWN delta
// rather than assuming an absolute-zero baseline.
#[test]
fn v16_wrapper_liquidation_reward_account_is_optional_and_absent_keeps_fee_in_insurance() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    let liquidation_fee_bps = 100u64;
    let max_price_move_bps_per_slot = 3u64;
    let max_accrual_dt_slots = 100u64;
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_margin_bps,
                initial_margin_bps,
                min_nonzero_mm_req,
                min_nonzero_im_req,
                liquidation_fee_bps: cfg_liquidation_fee_bps,
                liquidation_fee_cap,
                max_price_move_bps_per_slot: cfg_max_price_move_bps_per_slot,
                max_accrual_dt_slots: cfg_max_accrual_dt_slots,
                max_abs_funding_e9_per_slot,
                min_funding_lifetime_slots,
                ..
            } = ix
            {
                *maintenance_margin_bps = 500;
                *initial_margin_bps = 600;
                *min_nonzero_mm_req = 100;
                *min_nonzero_im_req = 101;
                *cfg_liquidation_fee_bps = liquidation_fee_bps;
                *liquidation_fee_cap = percolator::MAX_PROTOCOL_FEE_ABS;
                *cfg_max_price_move_bps_per_slot = max_price_move_bps_per_slot;
                *cfg_max_accrual_dt_slots = max_accrual_dt_slots;
                *max_abs_funding_e9_per_slot = 10_000;
                *min_funding_lifetime_slots = 100;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    configure_base_ewma_mark(&mut admin, &mut market, 0, 100);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    // Minimum deposit satisfying initial_margin_bps=600 (6%) on a 10,000
    // notional position: no leverage headroom, so underwater is only
    // reachable via a real adverse price move (same discipline as the v16_cu
    // E3 fixture repairs).
    deposit(&mut short_owner, &mut market, &mut short_account, 601);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (100 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    // Real adverse EWMA push (target far above any single-step budget so the
    // engine's own linear clamp -- not our target -- determines the landed
    // price); the liquidation crank below performs the clamped accrual and
    // the liquidation in the same instruction.
    push_base_ewma_mark(&mut admin, &mut market, 100, 999_999_999);

    let landed_price =
        clamped_price_after_one_step_ref(100, max_price_move_bps_per_slot, 100, max_accrual_dt_slots);
    let expected_fee = ceil_liquidation_fee_ref(
        100 * POS_SCALE,
        landed_price,
        liquidation_fee_bps,
        0,
        percolator::MAX_PROTOCOL_FEE_ABS,
    );

    let insurance_before = state::read_market(&market.data).unwrap().1.insurance;
    let vault_before = state::read_market(&market.data).unwrap().1.vault;
    run_ix(
        Instruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 100,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut short_account],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    assert_eq!(
        group.assets[0].effective_price, landed_price,
        "fixture assumption: the single-step price clamp landed where derived"
    );
    assert_eq!(
        short.pnl, 0,
        "fixture assumption: the account must stay solvent (pnl>=0) through liquidation -- a \
         genuinely bankrupt (pnl<0) account would have its liquidation fee unconditionally \
         waived, making this test's nonzero-fee premise unreachable"
    );
    assert!(
        percolator::active_bitmap_is_empty(short.active_bitmap),
        "E3 must select a full close when no healthy partial exists within its search bound"
    );
    assert_eq!(
        group.insurance,
        insurance_before + expected_fee,
        "without an optional cranker portfolio, the full liquidation penalty (derived: ceil-notional \
         fee at the landed price) remains in insurance -- not zero (would mean the fee was skipped) \
         and not more (would mean rounding is accumulating beyond the engine's own ceil-per-close \
         guarantee)"
    );
    assert_eq!(group.vault, vault_before, "internal liquidation fee must not move SPL vault custody");
}

#[test]
fn v16_wrapper_liquidation_reward_never_spends_insurance_needed_for_losses() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut cranker_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    let mut cranker_account = portfolio_account();

    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                liquidation_fee_bps,
                liquidation_fee_cap,
                ..
            } = ix
            {
                *liquidation_fee_bps = 0;
                *liquidation_fee_cap = 10_000;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    init_portfolio(&mut cranker_owner, &mut market, &mut cranker_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 100);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut short = state::read_portfolio(&short_account.data).unwrap();
        short.capital = 0;
        group.c_tot -= 100;
        group.vault -= 100;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut short_account.data, &short).unwrap();
    }
    run_ix(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    run_ix(
        Instruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [
            &mut cranker_owner,
            &mut market,
            &mut short_account,
            &mut cranker_account,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let short = state::read_portfolio(&short_account.data).unwrap();
    let cranker = state::read_portfolio(&cranker_account.data).unwrap();
    assert!(percolator::active_bitmap_is_empty(short.active_bitmap));
    assert_eq!(
        group.insurance, 0,
        "the liquidation did not increase retained insurance, so no cranker reward is paid"
    );
    assert_eq!(
        group.vault, 1_000_000,
        "loss paths must not leak pre-existing custody out as rewards"
    );
    assert_eq!(
        cranker.capital, 0,
        "no retained-fee growth means no internal cranker reward"
    );
}

#[test]
fn v16_wrapper_liquidation_fee_policy_is_admin_gated_and_bounds_share() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();

    init_market(&mut admin, &mut market);
    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 10_001,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);

    let rejected = run_ix(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);

    run_ix(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.liquidation_cranker_fee_share_bps, 4_000);
}

#[test]
fn v16_wrapper_permissionless_settle_b_without_b_state_is_fail_closed() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let market_before = market.data.clone();
    let portfolio_before = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::PermissionlessCrank {
            action: 2,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );

    assert_err_and_market_unchanged(rejected, &market, &market_before);
    assert_eq!(portfolio.data, portfolio_before);
}

#[test]
fn v16_wrapper_permissionless_crank_rejects_invalid_asset_and_legacy_price_payload_without_mutation(
) {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let invalid_asset = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(invalid_asset, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut legacy_price_payload = Instruction::PermissionlessCrank {
        action: 0,
        asset_index: 0,
        now_slot: 0,
        funding_rate_e9: 0,
        recovery_reason: 0,
    }
    .encode();
    legacy_price_payload.splice(12..12, 1_000_000u64.to_le_bytes().iter().copied());
    let legacy_price = run_ix_data(
        &legacy_price_payload,
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(legacy_price, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_permissionless_recovery_action_is_not_public_kill_switch() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let result = run_ix(
        Instruction::PermissionlessCrank {
            action: 3,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );

    assert_err_and_market_unchanged(result, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Live);
    assert_eq!(
        group.recovery_reason, None,
        "a caller-selected recovery reason must not terminal-lock a healthy market"
    );
}

#[test]
fn v16_wrapper_permissionless_recovery_rejects_every_caller_selected_reason() {
    let reasons = [
        PermissionlessRecoveryReasonV16::BelowProgressFloor,
        PermissionlessRecoveryReasonV16::BlockedSegmentHeadroomOrRepresentability,
        PermissionlessRecoveryReasonV16::AccountBSettlementCannotProgress,
        PermissionlessRecoveryReasonV16::BIndexHeadroomExhausted,
        PermissionlessRecoveryReasonV16::ActiveBankruptCloseCannotProgress,
        PermissionlessRecoveryReasonV16::ExplicitLossOrDustAuditOverflow,
        PermissionlessRecoveryReasonV16::OracleOrTargetUnavailableByAuthenticatedPolicy,
        PermissionlessRecoveryReasonV16::CounterOrEpochOverflowDeclaredRecovery,
    ];

    for (reason, _) in reasons.iter().copied().enumerate() {
        let mut admin = signer();
        let mut market = market_account();
        let mut owner = signer();
        let mut portfolio = portfolio_account();
        init_market(&mut admin, &mut market);
        init_portfolio(&mut owner, &mut market, &mut portfolio);

        let before_market = market.data.clone();
        let before_portfolio = portfolio.data.clone();
        let result = run_ix(
            Instruction::PermissionlessCrank {
                action: 3,
                asset_index: 0,
                now_slot: 0,
                funding_rate_e9: 0,
                recovery_reason: reason as u8,
            },
            &mut [&mut owner, &mut market, &mut portfolio],
        );
        assert_err_and_market_unchanged(result, &market, &before_market);
        assert_eq!(portfolio.data, before_portfolio);
        let (_, group) = state::read_market(&market.data).unwrap();
        assert_eq!(group.mode, MarketModeV16::Live);
        assert_eq!(group.recovery_reason, None);
    }
}

#[test]
fn v16_wrapper_permissionless_crank_rejects_invalid_action_and_recovery_reason() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let bad_action = run_ix(
        Instruction::PermissionlessCrank {
            action: 9,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(bad_action, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let bad_recovery_reason = run_ix(
        Instruction::PermissionlessCrank {
            action: 3,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 99,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(bad_recovery_reason, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_permissionless_crank_rejects_caller_supplied_funding_rate() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_abs_funding_e9_per_slot,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_abs_funding_e9_per_slot = 1;
                *max_price_move_bps_per_slot = 4_999;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    init_portfolio(&mut owner, &mut market, &mut portfolio);

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let result = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 1,
            recovery_reason: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(result, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_permissionless_recovery_rejects_below_progress_floor_kill_switch() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                initial_price,
                max_price_move_bps_per_slot,
                max_trading_fee_bps,
                ..
            } = ix
            {
                *initial_price = 1;
                *max_price_move_bps_per_slot = 1;
                *max_trading_fee_bps = 10_000;
            }
        }),
    );
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 0,
            initial_mark_e6: 1,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 1,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot: 1,
            mark_e6: 3,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let before_market = market.data.clone();
    let before_account = long_account.data.clone();
    let result = run_ix(
        Instruction::PermissionlessCrank {
            action: 3,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(result, &market, &before_market);
    assert_eq!(long_account.data, before_account);
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Live);
    assert_eq!(
        group.recovery_reason,
        None,
        "even a proven below-progress-floor state must not let a public caller select terminal Recovery"
    );
}

#[test]
fn v16_wrapper_rebalance_reduce_is_owner_signed_and_strictly_reduces_risk() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut attacker = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (2 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let before_market = market.data.clone();
    let before_account = long_account.data.clone();
    let unauthorized = run_ix(
        Instruction::RebalanceReduce {
            asset_index: 0,
            reduce_q: POS_SCALE,
        },
        &mut [&mut attacker, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before_market);
    assert_eq!(long_account.data, before_account);

    run_ix(
        Instruction::RebalanceReduce {
            asset_index: 0,
            reduce_q: POS_SCALE,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(long.legs[0].basis_pos_q, POS_SCALE as i128);
    assert_eq!(group.assets[0].oi_eff_long_q, POS_SCALE);
}

#[test]
fn v16_wrapper_dead_leg_forfeit_is_owner_signed_and_detaches_recovery_leg() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut attacker = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Recovery;
        group.recovery_reason = Some(PermissionlessRecoveryReasonV16::BelowProgressFloor);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_market = market.data.clone();
    let before_account = long_account.data.clone();
    let unauthorized = run_ix(
        Instruction::ForfeitRecoveryLeg {
            asset_index: 0,
            b_delta_budget: 1,
        },
        &mut [&mut attacker, &mut market, &mut long_account],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before_market);
    assert_eq!(long_account.data, before_account);

    run_ix(
        Instruction::ForfeitRecoveryLeg {
            asset_index: 0,
            b_delta_budget: 1,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert!(percolator::active_bitmap_is_empty(long.active_bitmap));
    assert_eq!(long.legs[0].basis_pos_q, 0);
    assert_eq!(group.assets[0].oi_eff_long_q, 0);
}

#[test]
fn v16_wrapper_cure_and_cancel_close_uses_owner_deposit_before_support_is_consumed() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    seed_cancellable_close_progress(&mut market, &mut portfolio);
    let mut source = user_token_account(owner.key, mint, 20);
    let mut vault = vault_token_account(&market, mint, 20);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::CureAndCancelClose {
            optional_deposit: 20,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert!(account.close_progress.canceled);
    assert_eq!(account.capital, 20);
    assert_eq!(group.c_tot, 20);
    assert_eq!(group.vault, 20);
    assert_eq!(group.pending_domain_loss_barriers[0], 0);
}

#[test]
fn v16_wrapper_cure_and_cancel_close_rejects_resolved_market() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    seed_cancellable_close_progress(&mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Resolved;
        group.resolved_slot = group.current_slot;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut source = user_token_account(owner.key, mint, 20);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::CureAndCancelClose {
            optional_deposit: 20,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_cure_and_cancel_close_rejects_after_permissionless_resolve_maturity() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    seed_cancellable_close_progress(&mut market, &mut portfolio);
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 9000;
        group.slot_last = 9000;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut source = user_token_account(owner.key, mint, 20);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::CureAndCancelClose {
            optional_deposit: 20,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_finalize_reset_side_is_permissionless_but_validates_side_and_readiness() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.assets[0].mode_long = SideModeV16::ResetPending;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let bad_side = run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 0,
            side: 2,
        },
        &mut [&mut market],
    );
    assert!(bad_side.is_err());

    run_ix(
        Instruction::FinalizeResetSide {
            asset_index: 0,
            side: 0,
        },
        &mut [&mut market],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.assets[0].mode_long, SideModeV16::Normal);
}

#[test]
fn v16_wrapper_claim_resolved_payout_topup_pays_only_stored_owner_receipt() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut attacker_owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        let mut account = state::read_portfolio(&portfolio.data).unwrap();
        group.mode = MarketModeV16::Resolved;
        group.resolved_slot = 1;
        group.current_slot = 1;
        group.vault = 60;
        group.payout_snapshot_captured = true;
        group.payout_snapshot = 100;
        group.resolved_payout_ledger = ResolvedPayoutLedgerV16 {
            snapshot_residual: 100,
            terminal_claim_exact_receipts_num: 100 * BOUND_SCALE,
            terminal_claim_bound_unreceipted_num: 0,
            current_payout_rate_num: 100 * BOUND_SCALE,
            current_payout_rate_den: 100 * BOUND_SCALE,
            snapshot_slot: 1,
            payout_halted: false,
            finalized: false,
        };
        account.resolved_payout_receipt = ResolvedPayoutReceiptV16 {
            present: true,
            prior_bound_contribution_num: 100 * BOUND_SCALE,
            live_released_face_at_receipt: 0,
            terminal_positive_claim_face: 100,
            paid_effective: 40,
            finalized: false,
        };
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio.data, &account).unwrap();
    }
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 60);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_owner = run_ix(
        Instruction::ClaimResolvedPayoutTopup,
        &mut [
            &mut attacker_owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_owner, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    run_ix(
        Instruction::ClaimResolvedPayoutTopup,
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(account.resolved_payout_receipt.paid_effective, 100);
    assert!(account.resolved_payout_receipt.finalized);
}

#[test]
fn v16_wrapper_refine_resolved_unreceipted_bound_is_disabled() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Resolved;
        group.resolved_slot = 1;
        group.current_slot = 1;
        group.payout_snapshot_captured = true;
        group.payout_snapshot = 100;
        group.resolved_payout_ledger = ResolvedPayoutLedgerV16 {
            snapshot_residual: 100,
            terminal_claim_exact_receipts_num: 0,
            terminal_claim_bound_unreceipted_num: 100 * BOUND_SCALE,
            current_payout_rate_num: 100 * BOUND_SCALE,
            current_payout_rate_den: 100 * BOUND_SCALE,
            snapshot_slot: 1,
            payout_halted: false,
            finalized: false,
        };
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before = market.data.clone();
    let unauthorized = run_ix(
        Instruction::RefineResolvedUnreceiptedBound {
            decrease_num: 10 * BOUND_SCALE,
        },
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(unauthorized, &market, &before);

    // SECURITY (#313): the external RefineResolvedUnreceiptedBound is now DISABLED —
    // even the marketauth admin is rejected. An arbitrary decrease passed the monotone-rate
    // guard in the haircut regime and let marketauth over-drain the unreceipted reserve and
    // strand resolved winners; the only accounting-faithful refinement is the internal
    // source-backed-realization path. So both attacker AND admin must now be rejected with
    // the ledger left untouched.
    let admin_attempt = run_ix(
        Instruction::RefineResolvedUnreceiptedBound {
            decrease_num: 10 * BOUND_SCALE,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(admin_attempt, &market, &before);
}

#[test]
fn v16_wrapper_resolve_market_is_admin_only_and_blocks_live_trade() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut portfolio_a = portfolio_account();
    let mut portfolio_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut portfolio_a);
    init_portfolio(&mut owner_b, &mut market, &mut portfolio_b);
    deposit(&mut owner_a, &mut market, &mut portfolio_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut portfolio_b, 1_000_000);

    let before = market.data.clone();
    let non_admin = run_ix(
        Instruction::ResolveMarket,
        &mut [&mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(non_admin, &market, &before);

    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved_market = market.data.clone();
    let before_a = portfolio_a.data.clone();
    let before_b = portfolio_b.data.clone();
    let trade_after_resolve = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut portfolio_a,
            &mut portfolio_b,
        ],
    );
    assert_err_and_market_unchanged(trade_after_resolve, &market, &resolved_market);
    assert_eq!(portfolio_a.data, before_a);
    assert_eq!(portfolio_b.data, before_b);
}

#[test]
fn v16_wrapper_permissionless_stale_resolve_requires_hard_stale_maturity() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut portfolio_a = portfolio_account();
    let mut portfolio_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut portfolio_a);
    init_portfolio(&mut owner_b, &mut market, &mut portfolio_b);
    deposit(&mut owner_a, &mut market, &mut portfolio_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut portfolio_b, 1_000_000);
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let before = market.data.clone();
    let early = run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 8999 },
        &mut [&mut market],
    );
    assert_err_and_market_unchanged(early, &market, &before);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9000 },
        &mut [&mut market],
    )
    .unwrap();
    let (cfg, group) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.last_good_oracle_slot, 0);
    assert_eq!(group.mode, MarketModeV16::Resolved);

    let resolved_market = market.data.clone();
    let before_a = portfolio_a.data.clone();
    let before_b = portfolio_b.data.clone();
    let trade_after_resolve = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut portfolio_a,
            &mut portfolio_b,
        ],
    );
    assert_err_and_market_unchanged(trade_after_resolve, &market, &resolved_market);
    assert_eq!(portfolio_a.data, before_a);
    assert_eq!(portfolio_b.data, before_b);
}

#[test]
fn v16_wrapper_permissionless_stale_resolve_uses_stamped_liveness_not_oracle_tail() {
    let feed = [11u8; 32];
    let mut admin = signer();
    let mut market = market_account();
    let mut fresh_oracle = pyth_account(&feed, 100, 0, 0, 1_000);
    let mut stale_oracle = pyth_account(&feed, 100, 0, 0, 1);

    init_market(&mut admin, &mut market);
    run_ix(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 10,
            now_unix_ts: 1_000,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 2,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [feed, [0u8; 32], [0u8; 32]],
        },
        &mut [&mut admin, &mut market, &mut fresh_oracle],
    )
    .unwrap();
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let before = market.data.clone();
    let caller_chosen_stale_tail = run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9009 },
        &mut [&mut market, &mut stale_oracle],
    );
    assert_err_and_market_unchanged(caller_chosen_stale_tail, &market, &before);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9010 },
        &mut [&mut market, &mut stale_oracle],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
    assert_eq!(group.resolved_slot, 9010);
}

#[test]
fn v16_wrapper_permissionless_resolve_maturity_blocks_manual_live_trade_race() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut portfolio_a = portfolio_account();
    let mut portfolio_b = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut portfolio_a);
    init_portfolio(&mut owner_b, &mut market, &mut portfolio_b);
    deposit(&mut owner_a, &mut market, &mut portfolio_a, 1_000_000);
    deposit(&mut owner_b, &mut market, &mut portfolio_b, 1_000_000);
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 9000;
        group.slot_last = 9000;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_market = market.data.clone();
    let before_a = portfolio_a.data.clone();
    let before_b = portfolio_b.data.clone();
    let trade_after_resolve_maturity = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut owner_a,
            &mut owner_b,
            &mut market,
            &mut portfolio_a,
            &mut portfolio_b,
        ],
    );
    assert_err_and_market_unchanged(trade_after_resolve_maturity, &market, &before_market);
    assert_eq!(portfolio_a.data, before_a);
    assert_eq!(portfolio_b.data, before_b);

    let mut late_owner = signer();
    let mut late_portfolio = portfolio_account();
    let late_init = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut late_owner, &mut market, &mut late_portfolio],
    );
    assert_err_and_market_unchanged(late_init, &market, &before_market);
    assert!(
        late_portfolio.data.iter().all(|b| *b == 0),
        "terminal-resolvable live market must not admit new empty accounts that can grief final cleanup"
    );

    let crank_after_resolve_maturity = run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 5,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut owner_a, &mut market, &mut portfolio_a],
    );
    assert_err_and_market_unchanged(crank_after_resolve_maturity, &market, &before_market);
    assert_eq!(portfolio_a.data, before_a);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9000 },
        &mut [&mut market],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
}

#[test]
fn v16_wrapper_resolved_market_blocks_new_activity_and_double_resolution() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);

    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved_market = market.data.clone();
    let resolved_portfolio = portfolio.data.clone();

    let double_resolve = run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]);
    assert_err_and_market_unchanged(double_resolve, &market, &resolved_market);
    assert_eq!(portfolio.data, resolved_portfolio);

    let mut new_owner = signer();
    let mut new_portfolio = portfolio_account();
    let new_portfolio_before = new_portfolio.data.clone();
    let init_after_resolve = run_ix(
        Instruction::InitPortfolio,
        &mut [&mut new_owner, &mut market, &mut new_portfolio],
    );
    assert_err_and_market_unchanged(init_after_resolve, &market, &resolved_market);
    assert_eq!(new_portfolio.data, new_portfolio_before);

    let mut source = user_token_account(owner.key, mint, 1_000);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut token_program = token_program_account();
    let deposit_after_resolve = run_ix(
        Instruction::Deposit { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(deposit_after_resolve, &market, &resolved_market);
    assert_eq!(portfolio.data, resolved_portfolio);

    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let withdraw_after_resolve = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(withdraw_after_resolve, &market, &resolved_market);
    assert_eq!(portfolio.data, resolved_portfolio);

    let mut admin_source = user_token_account(admin.key, mint, 1_000);
    let topup_after_resolve = run_ix(
        Instruction::TopUpInsurance { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_source,
            &mut vault,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(topup_after_resolve, &market, &resolved_market);
    assert_eq!(portfolio.data, resolved_portfolio);
}

#[test]
fn v16_wrapper_resolved_close_uses_engine_loss_and_fee_ordering_path() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    close_resolved(&mut owner, &mut market, &mut portfolio, 0);

    let (_, group) = state::read_market(&market.data).unwrap();
    let acct = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
    assert_eq!(acct.capital, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_wrapper_close_resolved_uses_configured_fee_not_permissionless_caller_fee() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = 10;
        group.slot_last = 10;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    close_resolved(&mut owner, &mut market, &mut portfolio, 100);

    let (_, group) = state::read_market(&market.data).unwrap();
    let acct = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(
        group.insurance, 0,
        "permissionless resolved close must not let caller redirect payout into fees"
    );
    assert_eq!(group.vault, 0);
    assert_eq!(acct.capital, 0);
}

#[test]
fn v16_wrapper_close_resolved_pays_positive_pnl_through_engine_ledger() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    top_up_backing_bucket(&mut admin, &mut market, 1, 250, 10);
    add_source_positive_pnl(&mut market, &mut portfolio, 1, 250);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_250);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    // The +250 source-backed positive PnL is paid in full: vault and c_tot drain to
    // 0 and the account is torn down (capital=0, pnl=0). These four asserts are the
    // real proof that close_resolved PAID the positive PnL.
    assert_eq!(group.vault, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(account.capital, 0);
    assert_eq!(account.pnl, 0);
    // v17 (historical name notwithstanding): SOURCE-BACKED positive PnL is realized
    // directly into capital and paid out — it does NOT flow through the resolved
    // payout receipt/ledger (that path is reserved for non-source-backed junior-pool
    // PnL that may need proration). So the correct post-condition is NO receipt: the
    // backing guarantee means the winner is paid in one shot with nothing deferred.
    assert!(!account.resolved_payout_receipt.present,
        "source-backed positive PnL pays directly; no resolved_payout_receipt should remain");
}

#[test]
fn v16_wrapper_close_resolved_does_not_double_pay_after_closed_payout() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    close_resolved(&mut owner, &mut market, &mut portfolio, 0);

    let after_first_market = market.data.clone();
    let after_first_portfolio = portfolio.data.clone();
    close_resolved(&mut owner, &mut market, &mut portfolio, 0);
    assert_eq!(
        market.data, after_first_market,
        "a second resolved close must not move market accounting"
    );
    assert_eq!(
        portfolio.data, after_first_portfolio,
        "a second resolved close must not recreate payout state"
    );
}

#[test]
fn v16_wrapper_close_resolved_is_permissionless_but_pays_only_owner_token_account() {
    let mut admin = signer();
    let mut market = market_account();
    let owner = signer();
    let mut owner_meta = TestAccount::new(owner.key, Pubkey::new_unique(), 0);
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    let mut owner_for_init = TestAccount::new(owner.key, Pubkey::new_unique(), 0).signer();
    init_portfolio(&mut owner_for_init, &mut market, &mut portfolio);
    deposit(&mut owner_for_init, &mut market, &mut portfolio, 1_000);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let mut attacker_dest = user_token_account(Pubkey::new_unique(), mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let wrong_destination = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [
            &mut owner_meta,
            &mut market,
            &mut portfolio,
            &mut attacker_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(wrong_destination, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    let mut owner_dest = user_token_account(owner.key, mint, 0);
    run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [
            &mut owner_meta,
            &mut market,
            &mut portfolio,
            &mut owner_dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    let account = state::read_portfolio(&portfolio.data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(account.capital, 0);
}

#[test]
fn v16_wrapper_close_resolved_enforces_configured_force_close_delay() {
    let mut admin = signer();
    let mut market = market_account();
    let owner_key = Pubkey::new_unique();
    let mut owner_for_init = TestAccount::new(owner_key, Pubkey::new_unique(), 0).signer();
    let mut owner_unsigned = TestAccount::new(owner_key, Pubkey::new_unique(), 0);
    let mut owner_signed = TestAccount::new(owner_key, Pubkey::new_unique(), 0).signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_for_init, &mut market, &mut portfolio);
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 5,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let unsigned_before_delay = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [&mut owner_unsigned, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(unsigned_before_delay, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);

    run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [&mut owner_signed, &mut market, &mut portfolio],
    )
    .unwrap();
}

#[test]
fn v16_wrapper_close_resolved_becomes_permissionless_after_force_close_delay() {
    let mut admin = signer();
    let mut market = market_account();
    let owner_key = Pubkey::new_unique();
    let mut owner_for_init = TestAccount::new(owner_key, Pubkey::new_unique(), 0).signer();
    let mut owner_unsigned = TestAccount::new(owner_key, Pubkey::new_unique(), 0);
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_for_init, &mut market, &mut portfolio);
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 5,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.current_slot = group.resolved_slot + 5;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [&mut owner_unsigned, &mut market, &mut portfolio],
    )
    .unwrap();
}

#[test]
fn v16_wrapper_close_resolved_rejects_before_resolution_without_mutation() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    let mut dest = user_token_account(owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let rejected = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut portfolio,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
// RESYNC(323c9f2 detach): the FORK-vs-TOLY ProgressOnly divergence is ELIMINATED
// by this re-sync. Our engine now carries detach_solvent_active_legs_for_resolved_
// close, so a solvent open-position winner closes+pays in the same call (matching
// toly 574a7a1's final test, which superseded the stale 0925ed4 ProgressOnly form).
fn v16_wrapper_close_resolved_active_position_pays_when_engine_clears_exposure() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let mut dest = user_token_account(long_owner.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 2_000_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let result = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [
            &mut long_owner,
            &mut market,
            &mut long_account,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_eq!(result, Ok(()));

    let (_, group) = state::read_market(&market.data).unwrap();
    let long = state::read_portfolio(&long_account.data).unwrap();
    assert_eq!(
        group.vault, 1_000_000,
        "resolved close pays capital once the engine clears account exposure"
    );
    assert!(percolator::active_bitmap_is_empty(long.active_bitmap));
    assert_eq!(long.capital, 0);
}

#[test]
// RESYNC(323c9f2 detach): toly 574a7a1's final form — once the engine clears
// exposure the close becomes a real payout, so omitting the token accounts now
// fails with NotEnoughAccountKeys and leaves market+portfolio untouched (no
// silent ProgressOnly). Supersedes the stale 0925ed4 progress-only variant.
fn v16_wrapper_close_resolved_payout_requires_token_accounts_after_exposure_clears() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let before_market = market.data.clone();
    let before_portfolio = long_account.data.clone();
    let result = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert_eq!(result, Err(ProgramError::NotEnoughAccountKeys));
    assert_eq!(market.data, before_market);
    assert_eq!(long_account.data, before_portfolio);
}

#[test]
fn v16_wrapper_close_resolved_requires_recipient_and_vault_accounts_for_payout() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();

    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();

    let before_market = market.data.clone();
    let before_portfolio = portfolio.data.clone();
    let missing_token_accounts = run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(missing_token_accounts, &market, &before_market);
    assert_eq!(portfolio.data, before_portfolio);
}

#[test]
fn v16_wrapper_hybrid_hard_stale_uses_permissionless_resolve_not_recovery_kill_switch() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();
    let feeds = [[0xc1u8; 32], [0xc2u8; 32], [0xc3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 1;
        cfg.oracle_target_publish_time = 100;
        group.current_slot = 1;
        group.slot_last = 1;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_recovery = market.data.clone();
    let rejected_recovery = run_ix(
        Instruction::PermissionlessCrank {
            action: 3,
            asset_index: 0,
            now_slot: 5,
            funding_rate_e9: 0,
            recovery_reason: 6,
        },
        &mut [&mut owner, &mut market, &mut portfolio],
    );
    assert_err_and_market_unchanged(rejected_recovery, &market, &before_recovery);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9001 },
        &mut [&mut market],
    )
    .unwrap();

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.mode,
        MarketModeV16::Resolved,
        "hard-stale hybrid markets exit through the proof-free stamped stale resolver"
    );
}

#[test]
fn v16_wrapper_hybrid_hard_stale_blocks_live_value_movement_until_resolved() {
    let mut admin = signer();
    let mut market = market_account();
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_trading_fee_bps,
                trade_fee_base_bps,
                max_price_move_bps_per_slot,
                ..
            } = ix
            {
                *max_trading_fee_bps = 10_000;
                *trade_fee_base_bps = 1;
                *max_price_move_bps_per_slot = 500;
            }
        }),
        &mut [&mut admin, &mut market, &mut mint],
    )
    .unwrap();

    let feeds = [[0xd1u8; 32], [0xd2u8; 32], [0xd3u8; 32]];
    let mut toto_jpy = pyth_account(&feeds[0], 4_000_000_000, -6, 1, 100);
    let mut usd_jpy = pyth_account(&feeds[1], 150_000_000, -6, 1, 100);
    let mut sol_usd = pyth_account(&feeds[2], 200_000_000, -6, 1, 100);
    configure_three_leg_hybrid(
        &mut admin,
        &mut market,
        feeds,
        &mut toto_jpy,
        &mut usd_jpy,
        &mut sol_usd,
        1,
        100,
        3,
        0,
    );
    run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 1_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 1_000_000);
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.last_good_oracle_slot = 1;
        cfg.oracle_target_publish_time = 100;
        group.current_slot = 9001;
        group.slot_last = 9001;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before_market = market.data.clone();
    let before_long = long_account.data.clone();
    let before_short = short_account.data.clone();
    let trade_after_hard_stale = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 133_333,
            fee_bps: 10_000,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_err_and_market_unchanged(trade_after_hard_stale, &market, &before_market);
    assert_eq!(long_account.data, before_long);
    assert_eq!(short_account.data, before_short);

    let mut dest = user_token_account(long_owner.key, mint_key, 0);
    let mut vault = vault_token_account(&market, mint_key, 2_000_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let withdraw_after_hard_stale = run_ix(
        Instruction::Withdraw { amount: 1 },
        &mut [
            &mut long_owner,
            &mut market,
            &mut long_account,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(withdraw_after_hard_stale, &market, &before_market);
    assert_eq!(long_account.data, before_long);

    run_ix(
        Instruction::ResolveStalePermissionless { now_slot: 9001 },
        &mut [&mut market],
    )
    .unwrap();
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved);
}

// ============================================================================
// Stress test for the per-domain insurance over-withdrawal surface.
//
// Bug class under test (reported as a prior engine bug): a domain being able
// to withdraw MORE than was accounted to it — i.e., dipping into other
// domains' insurance / the global pool beyond its own allocation. The engine
// guards this in `validate_shape` via
//   Σ_d (insurance_domain_budget[d] − insurance_domain_spent[d]) ≤ insurance
// and the wrapper calls validate_shape after every mutation. This test hammers
// the wrapper's per-domain top-up / withdraw surface with a long randomized
// sequence and independently re-derives the conservation invariants after
// every operation, plus asserts that deliberate over-withdrawals are rejected.
// ============================================================================
fn read_token_amount(acct: &TestAccount) -> u128 {
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap()) as u128
}

#[test]
fn v16_wrapper_stress_per_domain_insurance_never_overdraws_cross_domain() {
    // v17: TopUpInsuranceDomain still uses domain (per-side) index.
    // WithdrawInsuranceDomain is replaced by WithdrawInsuranceAsset (per-asset,
    // drains both long+short).  We track per-domain credited and per-asset
    // withdrawn; the invariant becomes: asset_withdrawn[a] <= credited[2a]+credited[2a+1].
    const N_DOMAINS: usize = 6; // asset 0 -> domains 0,1 ; asset 1 -> 2,3 ; asset 2 -> 4,5
    const N_ASSETS: usize = 3;
    let mut admin = signer().writable();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    // Append assets 1 and 2 with admin as insurance_authority/operator so
    // admin can sign WithdrawInsuranceAsset (local_authorized path).
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        100,
        125,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        200,
        125,
    )
    .unwrap();

    let mut token_program = token_program_account();
    // Persistent token accounts; SPL CPI is not live in the unit harness so
    // balances do not move.  Pre-funded large enough that balance guards pass.
    let mut admin_tok = user_token_account(admin.key, mint, 1_000_000_000);
    let mut vault_tok = vault_token_account(&market, mint, 1_000_000_000);
    let mut vault_auth = vault_authority_account(&market);

    // credited[d]: how much was successfully top-upped to per-side domain d.
    // withdrawn_asset[a]: how much was successfully withdrawn from asset a.
    let mut credited = [0u128; N_DOMAINS];
    let mut withdrawn_asset = [0u128; N_ASSETS];

    // Deterministic xorshift RNG (reproducible).
    let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
    let next = |rng: &mut u64| {
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        *rng
    };

    let check_invariants = |market: &TestAccount,
                            vault_tok: &TestAccount,
                            credited: &[u128; N_DOMAINS],
                            withdrawn_asset: &[u128; N_ASSETS]| {
        let (_, group) = state::read_market(&market.data).unwrap();
        // (1) per-domain budget/spent: no underflow.
        let mut sum_remaining = 0u128;
        for d in 0..N_DOMAINS {
            let budget = group.insurance_domain_budget[d];
            let spent = group.insurance_domain_spent[d];
            assert!(
                budget >= spent,
                "domain {d} spent {spent} > budget {budget}"
            );
            sum_remaining += budget - spent;
        }
        // (2) the core engine invariant: domain budgets never over-allocate
        // the global insurance pool.
        assert!(
            sum_remaining <= group.insurance,
            "Σ domain remaining {sum_remaining} > insurance {}",
            group.insurance
        );
        // (3) per-asset: asset cannot have withdrawn more than was credited to
        // its two domains combined.
        for a in 0..N_ASSETS {
            let asset_credited = credited[2 * a] + credited[2 * a + 1];
            assert!(
                withdrawn_asset[a] <= asset_credited,
                "asset {a} over-withdrew: withdrawn {} > credited {}",
                withdrawn_asset[a],
                asset_credited,
            );
        }
        // (4) insurance is a subset of the vault.
        assert!(group.insurance <= group.vault);
        assert!(
            group.vault <= read_token_amount(vault_tok),
            "wrapper vault accounting {} exceeds physical vault tokens {}",
            group.vault,
            read_token_amount(vault_tok)
        );
    };

    for _ in 0..600 {
        let r = next(&mut rng);
        let op = r % 3;
        // Randomly pick a per-side domain for top-up or a per-asset index for withdraw.
        let domain = (next(&mut rng) % N_DOMAINS as u64) as u16;
        let asset_index = (domain / 2) as usize;
        let amount = ((next(&mut rng) % 250) + 1) as u128;

        match op {
            0 => {
                // Per-domain insurance top-up (TopUpInsuranceDomain still uses domain).
                let res = run_ix(
                    Instruction::TopUpInsuranceDomain { domain, amount },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut token_program,
                    ],
                );
                if res.is_ok() {
                    credited[domain as usize] += amount;
                }
            }
            1 => {
                // Per-asset insurance withdraw (v17: WithdrawInsuranceAsset).
                let res = run_ix(
                    Instruction::WithdrawInsuranceAsset {
                        asset_index: asset_index as u16,
                        amount,
                    },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut vault_auth,
                        &mut token_program,
                    ],
                );
                if res.is_ok() {
                    withdrawn_asset[asset_index] += amount;
                    // Headline invariant: asset can never withdraw more than
                    // its two domains were credited in aggregate.
                    let asset_credited = credited[2 * asset_index] + credited[2 * asset_index + 1];
                    assert!(
                        withdrawn_asset[asset_index] <= asset_credited,
                        "asset {asset_index} over-withdrew: withdrawn {} > credited {}",
                        withdrawn_asset[asset_index],
                        asset_credited,
                    );
                }
            }
            _ => {
                // Deliberate over-withdraw: try to take strictly more than
                // this asset's combined remaining budget.  Must be rejected
                // and must not mutate state, even when OTHER assets hold enough.
                let asset_credited = credited[2 * asset_index] + credited[2 * asset_index + 1];
                let remaining = asset_credited - withdrawn_asset[asset_index];
                let over = remaining + 1 + (next(&mut rng) % 50) as u128;
                let before = market.data.clone();
                let before_vault = vault_tok.data.clone();
                let res = run_ix(
                    Instruction::WithdrawInsuranceAsset {
                        asset_index: asset_index as u16,
                        amount: over,
                    },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut vault_auth,
                        &mut token_program,
                    ],
                );
                assert!(
                    res.is_err(),
                    "asset {asset_index} allowed over-withdraw of {over} (remaining {remaining})"
                );
                assert_eq!(market.data, before, "rejected over-withdraw mutated market");
                assert_eq!(
                    vault_tok.data, before_vault,
                    "rejected over-withdraw moved vault tokens"
                );
            }
        }

        check_invariants(&market, &vault_tok, &credited, &withdrawn_asset);
    }

    // Final settlement check: total withdrawn across all assets never exceeds
    // total credited across all domains.
    let total_credited: u128 = credited.iter().sum();
    let total_withdrawn: u128 = withdrawn_asset.iter().sum();
    assert!(
        total_withdrawn <= total_credited,
        "aggregate over-withdraw: {total_withdrawn} > {total_credited}"
    );
}

// ============================================================================
// Stress test for the per-domain BACKING over-withdrawal surface (the "+
// backing" half of the reported bug class: a domain pulling out more backing
// than was deposited to it). Hammers TopUpBackingBucket / WithdrawBackingBucket
// over domains 2..6 (the appended assets, where admin is the backing
// authority) and asserts that on-chain fresh backing always equals the model,
// that no domain ever withdraws more backing than it deposited, and that
// deliberate over-withdrawals are rejected without mutating state.
// ============================================================================
#[test]
fn v16_wrapper_stress_per_domain_backing_never_overdraws() {
    const N_DOMAINS: usize = 6;
    const FAR_EXPIRY: u64 = 1_000_000;
    let mut admin = signer().writable();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        100,
        125,
    )
    .unwrap();
    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        200,
        125,
    )
    .unwrap();

    let mut token_program = token_program_account();
    let mut admin_tok = user_token_account(admin.key, mint, 1_000_000_000);
    let mut vault_tok = vault_token_account(&market, mint, 1_000_000_000);
    let mut vault_auth = vault_authority_account(&market);

    // Per-domain fresh backing the model believes is held, and gross
    // deposited / withdrawn for the no-overdraw assertion.
    let mut fresh = [0u128; N_DOMAINS];
    let mut deposited = [0u128; N_DOMAINS];
    let mut withdrawn = [0u128; N_DOMAINS];

    let mut rng: u64 = 0xD1B5_4A32_D192_ED03;
    let next = |rng: &mut u64| {
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        *rng
    };

    let check = |market: &TestAccount, fresh: &[u128; N_DOMAINS]| {
        let (_, group) = state::read_market(&market.data).unwrap();
        let mut total_fresh_num = 0u128;
        // Only backing-capable domains (2..6) carry model-tracked backing.
        for d in 2..N_DOMAINS {
            let on_chain = group.source_backing_buckets[d].fresh_unliened_backing_num;
            assert_eq!(
                on_chain,
                fresh[d] * BOUND_SCALE,
                "domain {d} on-chain fresh backing diverged from model"
            );
            total_fresh_num += on_chain;
        }
        // Vault must physically cover insurance + all fresh backing.
        let backing_atoms = total_fresh_num / BOUND_SCALE;
        assert!(
            group.vault >= group.insurance + backing_atoms,
            "vault {} < insurance {} + backing {}",
            group.vault,
            group.insurance,
            backing_atoms
        );
    };

    for _ in 0..600 {
        let op = next(&mut rng) % 3;
        // Restrict to backing-capable domains 2..=5. v17: domain is u16 (matrix row 36).
        let domain = (2 + (next(&mut rng) % 4)) as u16;
        let amount = ((next(&mut rng) % 250) + 1) as u128;
        let d = domain as usize;

        match op {
            0 => {
                let mut __lg30 = canonical_backing_ledger_account(&market, domain);
                let mut __sp30 = system_program_account();
                let res = run_ix(
                    Instruction::TopUpBackingBucket {
                        domain,
                        amount,
                        expiry_slot: FAR_EXPIRY,
                    },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut token_program,
                    
                    &mut __lg30,
                    &mut __sp30,
                ],
                );
                if res.is_ok() {
                    fresh[d] += amount;
                    deposited[d] += amount;
                }
            }
            1 => {
                let mut __lg21 = canonical_backing_ledger_account(&market, 0);
                let res = run_ix(
                    Instruction::WithdrawBackingBucket { domain, amount },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut vault_auth,
                        &mut token_program,
                    
                    &mut __lg21,
                ],
                );
                if res.is_ok() {
                    fresh[d] -= amount;
                    withdrawn[d] += amount;
                    assert!(
                        withdrawn[d] <= deposited[d],
                        "domain {domain} over-withdrew backing: {} > {}",
                        withdrawn[d],
                        deposited[d]
                    );
                }
            }
            _ => {
                // Deliberate over-withdraw beyond fresh backing must be rejected.
                let over = fresh[d] + 1 + (next(&mut rng) % 50) as u128;
                let before = market.data.clone();
                let mut __lg22 = canonical_backing_ledger_account(&market, domain);
                let res = run_ix(
                    Instruction::WithdrawBackingBucket {
                        domain,
                        amount: over,
                    },
                    &mut [
                        &mut admin,
                        &mut market,
                        &mut admin_tok,
                        &mut vault_tok,
                        &mut vault_auth,
                        &mut token_program,
                    
                    &mut __lg22,
                ],
                );
                assert!(
                    res.is_err(),
                    "domain {domain} allowed backing over-withdraw {over} (fresh {})",
                    fresh[d]
                );
                assert_eq!(
                    market.data, before,
                    "rejected backing over-withdraw mutated market"
                );
            }
        }
        check(&market, &fresh);
    }
}

// ============================================================================
// Cross-domain isolation under oracle attack.
//
// Property: an attacker who fully controls one domain's oracle (asset 1 here)
// must NOT be able to extract value from OTHER domains - neither the honest
// domain's insurance/backing nor the capital of a bystander who only trades
// the honest domain - even though the wrapper is cross-margin and the victim
// holds positions. The engine isolates loss absorption per domain
// (consume_domain_insurance_for_negative_pnl is scoped to the bankrupt asset's
// own domain) and the wrapper keeps sum_d (budget - spent) <= insurance, so a
// loss in the attacker's domain can consume at most that domain's insurance +
// the victim's own capital + social loss among that asset's own participants.
//
// This test drives a randomized adversarial sequence on the attacker domain
// (wild oracle pushes, trades against a victim, liquidation cranks, and
// withdrawal attempts) and asserts after EVERY step that the honest domain's
// per-domain insurance budget, its backing bucket, and the bystander's capital
// are byte-for-byte unchanged from the pre-attack snapshot.
// ============================================================================
#[test]
fn v16_wrapper_oracle_attacker_cannot_drain_other_domains() {
    // asset 0 -> domains 0,1 ; asset 1 (ATTACKER) -> 2,3 ; asset 2 (HONEST) -> 4,5
    let mut admin = signer().writable();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    let mut attacker = signer().writable();
    let admin_key = admin.key.to_bytes();
    let attacker_key = attacker.key.to_bytes();
    // Asset 1 = attacker-controlled domain (including oracle authority). Asset
    // 2 = honest domain. Both are activated by admin (the asset authority).
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        100,
        125,
        attacker_key,
        attacker_key,
        attacker_key,
    )
    .unwrap();
    update_asset_lifecycle_with_authorities(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        2,
        200,
        125,
        admin_key,
        admin_key,
        admin_key,
    )
    .unwrap();

    let mut token_program = token_program_account();

    // ---- Fund the HONEST domain (asset 2: domains 4,5) ----
    let mut admin_src = user_token_account(admin.key, mint, 1_000_000_000);
    let mut vault_tok = vault_token_account(&market, mint, 1_000_000_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut attacker_dest = user_token_account(attacker.key, mint, 0);
    // v17: domain is u16 (matrix row 36).
    for dom in [4u16, 5u16] {
        run_ix(
            Instruction::TopUpInsuranceDomain {
                domain: dom,
                amount: 5_000,
            },
            &mut [
                &mut admin,
                &mut market,
                &mut admin_src,
                &mut vault_tok,
                &mut token_program,
            ],
        )
        .unwrap();
    }
    let mut __lg31 = canonical_backing_ledger_account(&market, 4);
    let mut __sp31 = system_program_account();
    run_ix(
        Instruction::TopUpBackingBucket {
            domain: 4,
            amount: 3_000,
            expiry_slot: 1_000_000,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut admin_src,
            &mut vault_tok,
            &mut token_program,
        
        &mut __lg31,
        &mut __sp31,
    ],
    )
    .unwrap();

    // ---- Bystander who only ever touches the HONEST asset 2 ----
    let mut bystander = signer();
    let mut bystander_acct = portfolio_account();
    init_portfolio(&mut bystander, &mut market, &mut bystander_acct);
    deposit(&mut bystander, &mut market, &mut bystander_acct, 200_000);

    // ---- Attacker + victim on asset 1 ----
    let mut victim = signer();
    let mut atk_acct = portfolio_account();
    let mut vic_acct = portfolio_account();
    init_portfolio(&mut attacker, &mut market, &mut atk_acct);
    init_portfolio(&mut victim, &mut market, &mut vic_acct);
    deposit(&mut attacker, &mut market, &mut atk_acct, 1_000_000);
    deposit(&mut victim, &mut market, &mut vic_acct, 300);

    // Snapshot honest-domain state and bystander capital after setup.
    let snap = |market: &TestAccount| {
        let (_, g) = state::read_market(&market.data).unwrap();
        (
            g.insurance_domain_budget[4],
            g.insurance_domain_budget[5],
            g.insurance_domain_spent[4],
            g.insurance_domain_spent[5],
            g.source_backing_buckets[4].fresh_unliened_backing_num,
            g.source_backing_buckets[4].utilization_fee_earnings,
        )
    };
    let honest_before = snap(&market);
    let bystander_before = state::read_portfolio(&bystander_acct.data).unwrap().capital;

    let assert_honest_isolated = |market: &TestAccount, bystander_acct: &TestAccount, tag: &str| {
        assert_eq!(
            snap(market),
            honest_before,
            "honest domain state changed after {tag}"
        );
        let (_, group) = state::read_market(&market.data).unwrap();
        assert!(
            group.vault >= group.insurance + group.c_tot,
            "vault {} < insurance {} + user capital {} after {tag}",
            group.vault,
            group.insurance,
            group.c_tot
        );
        let cap = state::read_portfolio(&bystander_acct.data).unwrap().capital;
        assert_eq!(
            cap, bystander_before,
            "bystander capital changed after {tag}"
        );
    };

    // Configure asset 1 oracle as the attacker-controlled oracle authority.
    run_ix(
        Instruction::ConfigureEwmaMark {
            asset_index: 1,
            now_slot: 300,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        &mut [&mut attacker, &mut market],
    )
    .unwrap();
    assert_honest_isolated(&market, &bystander_acct, "configure asset1 oracle");

    // Open opposing positions on asset 1 between attacker (long) and victim
    // (short) at the honest price.
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut attacker,
            &mut victim,
            &mut market,
            &mut atk_acct,
            &mut vic_acct,
        ],
    )
    .unwrap();
    assert_honest_isolated(&market, &bystander_acct, "open asset1 position");

    // Randomized attack: push the asset-1 mark to wild values and liquidate.
    let mut rng: u64 = 0xA11C_E5_DEAD_BEEFu64;
    let next = |rng: &mut u64| {
        *rng ^= *rng << 13;
        *rng ^= *rng >> 7;
        *rng ^= *rng << 17;
        *rng
    };
    let mut liquidations = 0u32;
    let mut slot = 300u64;
    for _ in 0..200 {
        slot += 1;
        // Wild attacker-chosen price in [1, 1_000_000].
        let mark = 1 + (next(&mut rng) % 1_000_000);
        let _ = run_ix(
            Instruction::PushEwmaMark {
                asset_index: 1,
                now_slot: slot,
                mark_e6: mark,
            },
            &mut [&mut attacker, &mut market],
        );
        assert_honest_isolated(&market, &bystander_acct, "push asset1 mark");

        // Liquidation crank against the victim on asset 1.
        let res = run_ix(
            Instruction::PermissionlessCrank {
                action: 1,
                asset_index: 1,
                now_slot: slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
            &mut [&mut admin, &mut market, &mut vic_acct],
        );
        if res.is_ok() {
            liquidations += 1;
        }
        assert_honest_isolated(&market, &bystander_acct, "liquidate victim on asset1");

        // Attacker tries to realize gains by withdrawing - capped by their real
        // equity; can never pull honest-domain value.
        let _ = run_ix(
            Instruction::Withdraw {
                amount: (next(&mut rng) % 2_000_000) as u128,
            },
            &mut [
                &mut attacker,
                &mut market,
                &mut atk_acct,
                &mut attacker_dest,
                &mut vault_tok,
                &mut vault_auth,
                &mut token_program,
            ],
        );
        assert_honest_isolated(&market, &bystander_acct, "attacker withdraw");
    }

    // Non-vacuity: the attack must have actually moved the asset-1 mark and
    // exercised the liquidation path at least once.
    assert!(
        liquidations > 0,
        "attack never triggered a liquidation; test is vacuous"
    );
    // Non-vacuity: the attack must have actually hurt the victim (drained their
    // capital and/or closed their position), proving the loss-absorption path
    // ran while the honest domain stayed isolated.
    let victim_after = state::read_portfolio(&vic_acct.data).unwrap();
    assert!(
        victim_after.capital < 300
            || percolator::active_bitmap_is_empty(victim_after.active_bitmap),
        "victim was never harmed (capital {}); attack vacuous",
        victim_after.capital
    );
    // Final isolation check.
    assert_honest_isolated(&market, &bystander_acct, "final");
}

// ----------------------------------------------------------------------------
// Per-asset crank clamp dt (regression for the multi-asset clamp/envelope
// mismatch). The wrapper used to clamp the crank price toward the target using
// the GROUP-level dt (`now - header.slot_last`), while the engine accrual
// envelope validates the move against the PER-ASSET dt
// (`now - asset.slot_last`). Because `header.slot_last == min(per-asset
// slot_last)`, a fresher asset in a multi-asset market would get a clamp dt
// strictly larger than its own accrual dt, letting the wrapper hand the engine
// a price the per-asset envelope rejects with RecoveryRequired -- a transient
// crank brick for that asset (it can only be unstuck by cranking the stalest
// asset first). The fix clamps with the per-asset slot_last so the wrapper
// clamp bound exactly matches the engine envelope bound for the cranked asset.
// ----------------------------------------------------------------------------

// Builds a 2-asset market in the exact "group pinned stale, asset-1 fresh"
// state and pushes `target_mark_e6` as asset 1's auth-mark target, leaving the
// market ready for `PermissionlessCrank { asset_index: 1, now_slot: 11 }`.
//
// Slot layout after setup:
//   asset 0: slot_last = 0, has open interest  -> pins header.slot_last to 0
//   asset 1: slot_last = 10, has open interest, auth-mark target pushed
//   header.slot_last = min(0, 10) = 0, current_slot = 10
// So at the crank slot 11:
//   group dt  = 11 - 0  = 11   (what the buggy clamp used)
//   asset dt  = 11 - 10 = 1    (what the engine envelope uses)
// With max_price_move_bps_per_slot = 1000 (10%/slot) and an asset-1 price of
// 100, the per-asset 1-slot envelope only admits a move to 110.
fn setup_pinned_group_fresh_asset1(target_mark_e6: u64) -> (TestAccount, TestAccount, TestAccount) {
    let mut admin = signer();
    let mut market = market_account();
    let mut a0_long_owner = signer();
    let mut a0_short_owner = signer();
    let mut a1_long_owner = signer();
    let mut a1_short_owner = signer();
    let mut a0_long = portfolio_account();
    let mut a0_short = portfolio_account();
    let mut a1_long = portfolio_account();
    let mut a1_short = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                min_funding_lifetime_slots,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
                *max_price_move_bps_per_slot = 1_000;
                // Keep max_price_move_bps_per_slot * max_accrual_dt_slots <= 10_000 so
                // the 100% maintenance-margin solvency envelope admits the config, and
                // max_accrual_dt_slots <= min_funding_lifetime_slots for the engine.
                *max_accrual_dt_slots = 10;
                *min_funding_lifetime_slots = 10;
            }
        }),
    );

    // Asset 0: auth-mark, price 100. Open its interest at slot 0 so it is a
    // live, accruable asset that pins header.slot_last; then never touch it
    // again, so it stays at slot 0 while asset 1 moves ahead.
    configure_base_auth_mark(&mut admin, &mut market, 0, 100);
    init_portfolio(&mut a0_long_owner, &mut market, &mut a0_long);
    init_portfolio(&mut a0_short_owner, &mut market, &mut a0_short);
    deposit(&mut a0_long_owner, &mut market, &mut a0_long, 1_000_000);
    deposit(&mut a0_short_owner, &mut market, &mut a0_short, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut a0_long_owner,
            &mut a0_short_owner,
            &mut market,
            &mut a0_long,
            &mut a0_short,
        ],
    )
    .unwrap();

    // Asset 1: open positions first at clock slot 0 (TradeNoCpi has no slot param;
    // the engine does not advance asset.slot_last on a trade, only on a crank).
    // After the trade we patch the market wire directly to produce the intended
    // pinned-stale / fresh-asset-1 state without going through ConfigureAuthMark,
    // which v17's group-wide oracle reconfiguration guard now blocks whenever ANY
    // asset in the group has open interest.
    //
    // Wire state we target:
    //   asset[0].slot_last = 0  (stale, OI open — pins header.slot_last)
    //   asset[1].slot_last = 5  (fresh — configured as of slot 5)
    //   header.slot_last   = 0  (pinned by asset 0's stale segment)
    //   header.current_slot = 5
    // Matrix row: v17-oracle-reconfigure-group-wide-guard (direct wire patch for
    // cross-asset per-slot-dt test scaffolding).
    init_portfolio(&mut a1_long_owner, &mut market, &mut a1_long);
    init_portfolio(&mut a1_short_owner, &mut market, &mut a1_short);
    deposit(&mut a1_long_owner, &mut market, &mut a1_long, 1_000_000);
    deposit(&mut a1_short_owner, &mut market, &mut a1_short, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut a1_long_owner,
            &mut a1_short_owner,
            &mut market,
            &mut a1_long,
            &mut a1_short,
        ],
    )
    .unwrap();
    // Patch market wire: advance asset 1 to slot 5 and set oracle mode to AUTH_MARK.
    // write_market preserves asset-engine state (OI, PnL, etc.) and only replaces
    // the header/asset fields we touch; write_asset_oracle_profile then overlays
    // the per-asset oracle profile stored in the slot wrapper section.
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.assets[1].slot_last = 5;
        group.assets[1].effective_price = 100;
        group.assets[1].raw_oracle_target_price = 100;
        group.assets[1].fund_px_last = 100;
        group.current_slot = 5;
        // slot_last stays 0 — asset 0's open-position segment pins the header.
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        // Build and store AUTH_MARK oracle profile for asset 1.  oracle_authority
        // is set to admin.key so PushAuthMark passes expect_live_authority.
        let profile1 = state::AssetOracleProfileV16 {
            oracle_mode: ORACLE_MODE_AUTH_MARK,
            oracle_leg_count: 0,
            oracle_leg_flags: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 0,
            backing_trade_fee_bps_long: 0,
            backing_trade_fee_bps_short: 0,
            backing_trade_fee_insurance_share_bps_long: 0,
            backing_trade_fee_insurance_share_bps_short: 0,
            _padding0: [0u8; 6],
            insurance_authority: admin.key.to_bytes(),
            insurance_operator: admin.key.to_bytes(),
            backing_bucket_authority: admin.key.to_bytes(),
            oracle_authority: admin.key.to_bytes(),
            asset_admin: admin.key.to_bytes(),
            max_staleness_secs: 0,
            hybrid_soft_stale_slots: 0,
            mark_ewma_e6: 100,
            mark_ewma_last_slot: 5,
            mark_ewma_halflife_slots: 0,
            mark_min_fee: 0,
            oracle_target_price_e6: 100,
            oracle_target_publish_time: 0,
            last_good_oracle_slot: 5,
            oracle_leg_feeds: [[0u8; 32]; ORACLE_LEG_CAP],
            oracle_leg_prices_e6: [0u64; ORACLE_LEG_CAP],
            oracle_leg_publish_times: [0i64; ORACLE_LEG_CAP],
        };
        state::write_asset_oracle_profile(&mut market.data, 1, &profile1).unwrap();
    }
    {
        let (_, group) = state::read_market(&market.data).unwrap();
        assert_eq!(group.assets[0].slot_last, 0, "asset 0 stays stale at slot 0");
        assert_eq!(group.assets[1].slot_last, 5, "asset 1 is fresh at slot 5");
        assert_eq!(group.slot_last, 0, "header.slot_last is pinned by the stale asset 0");
        assert_eq!(group.current_slot, 5);
        assert_eq!(group.assets[1].effective_price, 100);
    }

    // Push a far auth-mark target for asset 1 at slot 6, leaving the market ready
    // for a crank at slot 6 where group dt = 6 but asset-1 accrual dt = 1.
    run_ix(
        Instruction::PushAuthMark {
            asset_index: 1,
            now_slot: 6,
            mark_e6: target_mark_e6,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    (admin, market, a1_long)
}

#[test]
fn v16_wrapper_crank_clamp_uses_per_asset_dt_not_group_dt() {
    // Target 130 sits outside asset 1's per-slot envelope (max move to 110) but
    // inside the wider group-dt window the buggy clamp used. Before the fix the
    // wrapper clamped toward 130 with group dt = 6 and handed the engine a price
    // the per-asset envelope (dt = 1) rejected -> the crank reverted with
    // RecoveryRequired. After the fix the wrapper clamps with the per-asset dt,
    // so it never proposes a move the engine will reject: the crank advances and
    // the price walks exactly to the per-asset 1-slot bound, 110.
    let (mut admin, mut market, mut a1_long) = setup_pinned_group_fresh_asset1(130);

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 6,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut a1_long],
    )
    .expect("fresh-asset crank must make progress when the group is pinned by a stale asset");

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.assets[1].effective_price, 110,
        "crank price must be clamped to asset 1's own per-slot envelope (100 -> 110), not the wider group window",
    );
    assert_eq!(group.assets[1].slot_last, 6, "asset 1 accrued to the crank slot");
    assert_eq!(group.assets[0].slot_last, 0, "the stale asset is untouched and still recoverable");
    assert_eq!(group.mode, MarketModeV16::Live);
}

#[test]
fn v16_wrapper_crank_per_asset_clamp_still_binds_extreme_target() {
    // The fix tightens the clamp dt; it must not loosen the clamp. Even an
    // absurd target is admitted by the crank only after being clamped to the
    // per-asset 1-slot bound (100 -> 110), so the engine envelope is always
    // satisfied and the price can never jump by the group dt.
    let (mut admin, mut market, mut a1_long) = setup_pinned_group_fresh_asset1(100_000);

    run_ix(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 6,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &mut [&mut admin, &mut market, &mut a1_long],
    )
    .expect("crank must make progress and clamp the extreme target rather than reverting");

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.assets[1].effective_price, 110,
        "per-asset 1-slot clamp must cap the move at 10% regardless of how far the pushed target is",
    );
}

// ----------------------------------------------------------------------------
// Per-asset dt for the dynamic-fee externality floor (same class as the crank
// clamp fix above). `hybrid_trade_fee_bps_view` sized the EwmaMark / matured-
// hybrid externality floor with the GROUP dt (`now - header.slot_last`) instead
// of the per-asset dt (`now - asset.slot_last`). In a multi-asset market pinned
// stale by one asset, a trade on a FRESH EwmaMark asset got a hugely inflated
// fee floor that could exceed max_trading_fee_bps and revert the trade -- a
// liveness footgun on the fresh asset, driven by an unrelated stale co-asset.
// The fix clamps with the per-asset dt so the floor reflects only the traded
// asset's own staleness.
// ----------------------------------------------------------------------------
#[test]
fn v16_wrapper_trade_fee_floor_uses_per_asset_dt_not_group_dt() {
    let mut admin = signer();
    let mut market = market_account();
    let mut a0_long_owner = signer();
    let mut a0_short_owner = signer();
    let mut a1_long_owner = signer();
    let mut a1_short_owner = signer();
    let mut a0_long = portfolio_account();
    let mut a0_short = portfolio_account();
    let mut a1_long = portfolio_account();
    let mut a1_short = portfolio_account();

    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                max_price_move_bps_per_slot,
                max_accrual_dt_slots,
                min_funding_lifetime_slots,
                max_trading_fee_bps,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
                *max_price_move_bps_per_slot = 1_000;
                *max_accrual_dt_slots = 10;
                *min_funding_lifetime_slots = 10;
                // Group dt = 5 => floor 5000 bps > cap; per-asset dt = 1 => floor
                // 1000 bps < cap. So the cap distinguishes the two clamp dts.
                *max_trading_fee_bps = 3_000;
            }
        }),
    );

    // Asset 0: auth-mark with open interest at slot 0 -> pins header.slot_last to 0.
    configure_base_auth_mark(&mut admin, &mut market, 0, 100);
    init_portfolio(&mut a0_long_owner, &mut market, &mut a0_long);
    init_portfolio(&mut a0_short_owner, &mut market, &mut a0_short);
    deposit(&mut a0_long_owner, &mut market, &mut a0_long, 1_000_000);
    deposit(&mut a0_short_owner, &mut market, &mut a0_short, 1_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut a0_long_owner,
            &mut a0_short_owner,
            &mut market,
            &mut a0_long,
            &mut a0_short,
        ],
    )
    .unwrap();

    // Asset 1: patch wire directly to EwmaMark at slot 5 without going through
    // ConfigureEwmaMark, which v17's group-wide oracle reconfiguration guard blocks
    // (asset 0 already holds positions).  The patched state mimics what
    // ConfigureEwmaMark would have produced: asset[1].slot_last = 5,
    // header.current_slot = 5, header.slot_last = 0 (pinned by stale asset 0).
    // Matrix row: v17-oracle-reconfigure-group-wide-guard (direct wire patch).
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.assets[1].slot_last = 5;
        group.assets[1].effective_price = 100;
        group.assets[1].raw_oracle_target_price = 100;
        group.assets[1].fund_px_last = 100;
        group.current_slot = 5;
        // slot_last stays 0 — pinned by asset 0.
        state::write_market(&mut market.data, &cfg, &group).unwrap();
        // EWMA_MARK oracle profile for asset 1 (halflife = 1 as the original
        // ConfigureEwmaMark call specified).
        let profile1 = state::AssetOracleProfileV16 {
            oracle_mode: ORACLE_MODE_EWMA_MARK,
            oracle_leg_count: 0,
            oracle_leg_flags: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 0,
            backing_trade_fee_bps_long: 0,
            backing_trade_fee_bps_short: 0,
            backing_trade_fee_insurance_share_bps_long: 0,
            backing_trade_fee_insurance_share_bps_short: 0,
            _padding0: [0u8; 6],
            insurance_authority: admin.key.to_bytes(),
            insurance_operator: admin.key.to_bytes(),
            backing_bucket_authority: admin.key.to_bytes(),
            oracle_authority: admin.key.to_bytes(),
            asset_admin: admin.key.to_bytes(),
            max_staleness_secs: 0,
            hybrid_soft_stale_slots: 0,
            mark_ewma_e6: 100,
            mark_ewma_last_slot: 5,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            oracle_target_price_e6: 100,
            oracle_target_publish_time: 0,
            last_good_oracle_slot: 5,
            oracle_leg_feeds: [[0u8; 32]; ORACLE_LEG_CAP],
            oracle_leg_prices_e6: [0u64; ORACLE_LEG_CAP],
            oracle_leg_publish_times: [0i64; ORACLE_LEG_CAP],
        };
        state::write_asset_oracle_profile(&mut market.data, 1, &profile1).unwrap();
    }
    init_portfolio(&mut a1_long_owner, &mut market, &mut a1_long);
    init_portfolio(&mut a1_short_owner, &mut market, &mut a1_short);
    deposit(&mut a1_long_owner, &mut market, &mut a1_long, 1_000_000);
    deposit(&mut a1_short_owner, &mut market, &mut a1_short, 1_000_000);
    {
        let (_, group) = state::read_market(&market.data).unwrap();
        assert_eq!(group.assets[0].slot_last, 0, "asset 0 stays stale at slot 0");
        assert_eq!(group.assets[1].slot_last, 5, "asset 1 is fresh at slot 5");
        assert_eq!(group.slot_last, 0, "header.slot_last pinned by stale asset 0 -> group dt = 5");
        assert_eq!(group.current_slot, 5);
    }

    // Trade on the FRESH EwmaMark asset 1 at mark price. The trade's now_slot ==
    // current_slot == 5, so group dt = 5 (floor 5000 > 3000 cap, reverts before
    // the fix) but per-asset dt = 0 -> max(1,..) = 1 (floor 1000 < cap) after it.
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 1,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut a1_long_owner,
            &mut a1_short_owner,
            &mut market,
            &mut a1_long,
            &mut a1_short,
        ],
    )
    .expect("a trade on a fresh asset must not be blocked by an unrelated stale co-asset's group dt");

    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group.assets[1].oi_eff_long_q, POS_SCALE,
        "the fresh-asset trade went through and opened interest",
    );
    assert_eq!(group.assets[0].slot_last, 0, "the stale co-asset is still untouched and recoverable");
}

#[test]
fn v16_wrapper_tradenocpi_accepts_degenerate_exec_price_billing_on_mark() {
    // W1 (fee-on-mark): exec_price has NO settlement role — entry, initial margin, and fee all
    // settle on the MARK (effective_price). A degenerate consented exec_price (0, or above
    // MAX_ORACLE_PRICE) is ACCEPTED and pays the FULL mark-based fee: it can neither evade nor
    // inflate the fee, and for a non-price-managed market mark discovery ignores it entirely.
    for exec_price in [0u64, percolator::MAX_ORACLE_PRICE + 1] {
        let mut admin = signer();
        let mut market = market_account();
        let mut long_owner = signer();
        let mut short_owner = signer();
        let mut long_account = portfolio_account();
        let mut short_account = portfolio_account();
        init_market(&mut admin, &mut market);
        init_portfolio(&mut long_owner, &mut market, &mut long_account);
        init_portfolio(&mut short_owner, &mut market, &mut short_account);
        deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
        deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);
        let (_, before) = state::read_market(&market.data).unwrap();
        assert_eq!(before.assets[0].effective_price, 100);

        run_ix(
            Instruction::TradeNoCpi {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                exec_price,
                fee_bps: 100,
            },
            &mut [
                &mut long_owner,
                &mut short_owner,
                &mut market,
                &mut long_account,
                &mut short_account,
            ],
        )
        .unwrap_or_else(|e| {
            panic!("degenerate exec_price {exec_price} must be accepted (settles on the mark): {e:?}")
        });

        let (_, group) = state::read_market(&market.data).unwrap();
        assert_eq!(
            group.assets[0].effective_price, 100,
            "exec_price {exec_price} must not move the mark"
        );
        assert_eq!(
            group.insurance, 10,
            "exec_price {exec_price}: taker-only full mark-based fee (notional 1000 @ 100 bps = 10, one side) is charged"
        );
    }
}

#[test]
fn v16_attack_tradenocpi_fee_cannot_be_evaded_via_exec_price() {
    // W1 (fee-on-mark) anti-evasion (toly 832dbdf): two cooperating accounts declare a tiny
    // exec_price (1) on a full mark-valued trade (mark = 100). Pre-fix the fee notional used
    // exec_price, so they would pay ~1% of the proper fee; post-fix the fee is pinned to the mark,
    // so the SAME full fee is charged as an honest exec_price=mark trade — the discount is unreachable.
    let charge_at = |exec_price: u64| {
        let mut admin = signer();
        let mut market = market_account();
        let mut long_owner = signer();
        let mut short_owner = signer();
        let mut long_account = portfolio_account();
        let mut short_account = portfolio_account();
        init_market(&mut admin, &mut market);
        init_portfolio(&mut long_owner, &mut market, &mut long_account);
        init_portfolio(&mut short_owner, &mut market, &mut short_account);
        deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
        deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);
        run_ix(
            Instruction::TradeNoCpi {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                exec_price,
                fee_bps: 100,
            },
            &mut [
                &mut long_owner,
                &mut short_owner,
                &mut market,
                &mut long_account,
                &mut short_account,
            ],
        )
        .unwrap();
        let (_, group) = state::read_market(&market.data).unwrap();
        group.insurance
    };
    let lowball = charge_at(1);
    let honest = charge_at(100);
    assert_eq!(
        honest, 10,
        "honest mark trade pays notional 1000 @ 100 bps = 10 (taker-only, one side)"
    );
    assert_eq!(
        lowball, honest,
        "lowball exec_price=1 must pay the SAME full mark-based fee — fee evasion is closed"
    );
}

// W3 (canonical-ATA): mirror of v16_program::processor::canonical_vault_address — the SPL
// Associated Token Account of the vault_authority PDA for this mint. Kept byte-in-lock-step with
// the program so vault fixtures satisfy the F-VAULT-FRAG pin (a green test == the derivation matches).
fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().unwrap();
    Pubkey::find_program_address(
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

// ── W3 (F-VAULT-FRAG) canonical-ATA pin: operative reject-noncanonical / accept-canonical ──
// A vault_authority-owned token account at any address OTHER than the canonical ATA must be
// rejected with the EXACT InvalidVaultAccount (Custom 12) — the wrong-reason guard (assert_eq on
// the exact code) proves the rejection is the address pin, not an unrelated failure. Without the
// pin an attacker funds a second vault-authority-owned account and fragments liquidity.

fn noncanonical_vault_token_account(market: &TestAccount, mint: Pubkey, amount: u64) -> TestAccount {
    // Correct owner + mint + state — ONLY the address is wrong (random, not the canonical ATA).
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data(mint, vault_authority(market), amount),
    )
    .writable()
}

#[test]
fn v16_wrapper_deposit_rejects_noncanonical_vault() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);

    let mut source_token = user_token_account(owner.key, mint, 1_000_000);
    let mut bad_vault = noncanonical_vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let rejected = run_ix(
        Instruction::Deposit { amount: 1_000_000 },
        &mut [&mut owner, &mut market, &mut portfolio, &mut source_token, &mut bad_vault, &mut token_program],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(12)),
        "Deposit to a non-canonical vault must reject with InvalidVaultAccount (Custom 12)"
    );
    // The canonical vault (the ATA) is accepted.
    deposit(&mut owner, &mut market, &mut portfolio, 1_000_000);
}

#[test]
fn v16_wrapper_withdraw_rejects_noncanonical_vault() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000_000);
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);

    let mut dest_token = user_token_account(owner.key, mint, 0);
    let mut bad_vault = noncanonical_vault_token_account(&market, mint, 1_000_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let rejected = run_ix(
        Instruction::Withdraw { amount: 500_000 },
        &mut [&mut owner, &mut market, &mut portfolio, &mut dest_token, &mut bad_vault, &mut vault_auth, &mut token_program],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(12)),
        "Withdraw from a non-canonical vault must reject with InvalidVaultAccount (Custom 12)"
    );
    // The canonical vault is accepted.
    withdraw(&mut owner, &mut market, &mut portfolio, 500_000);
}

#[test]
fn v16_wrapper_topup_backing_bucket_rejects_noncanonical_vault() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);

    let mut source = user_token_account(admin.key, mint, 1_000_000);
    let mut bad_vault = noncanonical_vault_token_account(&market, mint, 0);
    let mut token_program = token_program_account();
    let mut __lg32 = canonical_backing_ledger_account(&market, 0);
    let mut __sp32 = system_program_account();
    let rejected = run_ix(
        Instruction::TopUpBackingBucket { domain: 0, amount: 1_000, expiry_slot: 1_000_000 },
        &mut [&mut admin, &mut market, &mut source, &mut bad_vault, &mut token_program,
        &mut __lg32,
        &mut __sp32,
    ],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(12)),
        "TopUpBackingBucket to a non-canonical vault must reject with InvalidVaultAccount (Custom 12)"
    );
    // The canonical vault is accepted.
    top_up_backing_bucket(&mut admin, &mut market, 0, 1_000, 1_000_000);
}

// ---------------------------------------------------------------------------
// Protocol-fee program change (~/v17/PROTOCOL-FEE-DESIGN.md): the 20% skim
// at the two trade-fee credit sites, taker-only + N1 regression guards, and
// the WithdrawProtocolFee (tag 84) / SetProtocolFeeAuthority (tag 85)
// instructions.
// ---------------------------------------------------------------------------

/// Bumps `trade_fee_base_bps` (and `max_trading_fee_bps` if needed) on an
/// already-initialized market, bypassing the InitMarket wire so tests don't
/// need to thread a custom mint through `init_market_ix_with`.
fn set_trade_fee_base_bps(market: &mut TestAccount, bps: u64) {
    let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
    cfg.trade_fee_base_bps = bps;
    if group.config.max_trading_fee_bps < bps {
        group.config.max_trading_fee_bps = bps;
    }
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

#[test]
fn v16_wrapper_protocol_fee_tradenocpi_skims_20pct_and_accrues_creator_leg_off_the_backstop() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000); // 10%

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_before.protocol_fee_accrued_atoms, 0);

    // account_a (long_owner/long_account) is the taker; size_q > 0 puts it in
    // the engine's long_account slot (domain 0 for asset 0).
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 1_000,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let total_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let expected_protocol_cut = total_fee * 2_000 / 10_000; // fee_share_floor, PROTOCOL_FEE_BPS
    // Four-way split (2026-07-19): the creator no longer gets "the complement"
    // of the protocol cut -- it gets its own configured share, with LP and
    // insurance now also carved out of what used to be 100% creator.
    let expected_creator_cut = total_fee * cfg_before.creator_share_bps as u128 / 10_000;
    let expected_lp_cut = total_fee * cfg_before.lp_share_bps as u128 / 10_000;
    // Insurance is the remainder leg in split_trade_fee (absorbs rounding dust),
    // so compute it the same way rather than re-deriving its bps share.
    let expected_insurance_cut =
        total_fee - expected_protocol_cut - expected_creator_cut - expected_lp_cut;

    assert_eq!(
        group_after.insurance - group_before.insurance,
        total_fee,
        "header.insurance still receives 100% of the fee -- the four-way split only changes routing"
    );
    assert_eq!(
        cfg_after.protocol_fee_accrued_atoms, expected_protocol_cut,
        "protocol accrues exactly fee_share_floor(fee, 2000)"
    );
    // Creator-fee-claim change (2026-07-23, design §2): the creator leg accrues
    // to its own counter. `expected_creator_cut` is nonzero here (16 atoms at
    // the fixture's 1600 bps of a 100-atom fee), so the assertion is not
    // satisfiable by a no-op.
    assert_ne!(expected_creator_cut, 0, "fixture must produce a nonzero creator leg");
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms - cfg_before.creator_fee_claimable_atoms,
        expected_creator_cut as u64,
        "creator accrues exactly split_a.creator + split_b.creator into the claimable counter"
    );
    // The NEGATIVE half, and the entire point of the change: the creator drip
    // no longer lands in the per-domain insurance budget, which IS the loss
    // backstop (`consume_domain_insurance_for_negative_pnl`). Before the change
    // this delta was `expected_creator_cut`.
    assert_eq!(
        group_after.insurance_domain_budget[0], group_before.insurance_domain_budget[0],
        "taker's domain (asset 0 long) budget must be UNCHANGED -- the creator leg left the backstop"
    );
    assert_eq!(
        group_after.insurance_domain_budget[1], group_before.insurance_domain_budget[1],
        "N1/N4 regression guard: maker's domain (asset 0 short) is byte-unchanged"
    );
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "NO domain budget anywhere may move on a trade now that the creator leg is re-routed"
    );
    assert_eq!(
        cfg_after.lp_fee_accrued_atoms - cfg_before.lp_fee_accrued_atoms,
        expected_lp_cut,
        "lp accrues exactly its configured share (Task 4 wiring)"
    );
    assert_eq!(
        cfg_after.insurance_reserve_accrued_atoms - cfg_before.insurance_reserve_accrued_atoms,
        expected_insurance_cut,
        "insurance reserve accrues its configured share plus rounding dust (Task 4 wiring)"
    );
    // Conservation across the four sinks: nothing is silently dropped or
    // double-counted by the re-route.
    assert_eq!(
        expected_protocol_cut
            + cfg_after.creator_fee_claimable_atoms as u128
            + expected_lp_cut
            + expected_insurance_cut,
        total_fee,
        "the four legs must still sum to the whole fee"
    );
}

#[test]
fn v16_wrapper_protocol_fee_tradecpi_skims_20pct_and_accrues_creator_leg_off_the_backstop() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 10_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 10_000_000);

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();

    // TradeCpi delegates to handle_trade_nocpi_zero_copy; account_a is always
    // the taker regardless of the matcher fill's sign convention.
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        (10 * POS_SCALE) as i128,
        (10 * POS_SCALE) as i128,
        100,
        1_000,
        0,
    )
    .unwrap();

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let total_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let expected_protocol_cut = total_fee * 2_000 / 10_000;
    // Four-way split (2026-07-19): the creator no longer gets "the complement"
    // of the protocol cut -- it gets its own configured share, with LP and
    // insurance now also carved out of what used to be 100% creator.
    let expected_creator_cut = total_fee * cfg_before.creator_share_bps as u128 / 10_000;
    let expected_lp_cut = total_fee * cfg_before.lp_share_bps as u128 / 10_000;
    // Insurance is the remainder leg in split_trade_fee (absorbs rounding dust),
    // so compute it the same way rather than re-deriving its bps share.
    let expected_insurance_cut =
        total_fee - expected_protocol_cut - expected_creator_cut - expected_lp_cut;

    assert_eq!(group_after.insurance - group_before.insurance, total_fee);
    assert_eq!(cfg_after.protocol_fee_accrued_atoms, expected_protocol_cut);
    assert_ne!(expected_creator_cut, 0, "fixture must produce a nonzero creator leg");
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms - cfg_before.creator_fee_claimable_atoms,
        expected_creator_cut as u64,
        "creator accrues its configured share into the claimable counter on the CPI path too"
    );
    assert_eq!(
        group_after.insurance_domain_budget[0], group_before.insurance_domain_budget[0],
        "taker's (account_a) domain budget must be UNCHANGED -- the creator leg left the backstop"
    );
    assert_eq!(
        group_after.insurance_domain_budget[1], group_before.insurance_domain_budget[1],
        "N1/N4 regression guard: maker's (account_b) domain is byte-unchanged"
    );
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "NO domain budget anywhere may move on a trade now that the creator leg is re-routed"
    );
    assert_eq!(
        cfg_after.lp_fee_accrued_atoms - cfg_before.lp_fee_accrued_atoms,
        expected_lp_cut,
        "lp accrues exactly its configured share (Task 4 wiring)"
    );
    assert_eq!(
        cfg_after.insurance_reserve_accrued_atoms - cfg_before.insurance_reserve_accrued_atoms,
        expected_insurance_cut,
        "insurance reserve accrues its configured share plus rounding dust (Task 4 wiring)"
    );
}

#[test]
fn v16_wrapper_protocol_fee_batchtradenocpi_skims_20pct_and_accrues_creator_leg_off_the_backstop() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();

    run_ix(
        Instruction::BatchTradeNoCpi {
            legs: vec![percolator_prog::ix::BatchTradeLeg {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                exec_price: 100,
                fee_bps: 1_000,
            }],
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let total_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let expected_protocol_cut = total_fee * 2_000 / 10_000;
    // Four-way split (2026-07-19, Task 5): the creator no longer gets "the
    // complement" of the protocol cut on the batch site either -- it gets its
    // own configured share, with LP and insurance now also carved out of what
    // used to be 100% creator, mirroring the single-trade site (Task 4).
    let expected_creator_cut = total_fee * cfg_before.creator_share_bps as u128 / 10_000;
    let expected_lp_cut = total_fee * cfg_before.lp_share_bps as u128 / 10_000;
    // Insurance is the remainder leg in split_trade_fee (absorbs rounding dust),
    // so compute it the same way rather than re-deriving its bps share.
    let expected_insurance_cut =
        total_fee - expected_protocol_cut - expected_creator_cut - expected_lp_cut;

    assert_eq!(
        group_after.insurance - group_before.insurance,
        total_fee,
        "header.insurance still receives 100% of the fee -- the four-way split only changes routing"
    );
    assert_eq!(
        cfg_after.protocol_fee_accrued_atoms, expected_protocol_cut,
        "protocol accrues exactly fee_share_floor(fee, 2000)"
    );
    // BATCH PATH (design §2): this is the site that does NOT go through
    // `credit_trade_fees_to_market_budgets_view` -- it credited
    // `credit_fee_to_domain_budget_view` DIRECTLY from inside the leg loop, and
    // was nearly missed. It gets its own accrual + its own negative assertion.
    assert_ne!(expected_creator_cut, 0, "fixture must produce a nonzero creator leg");
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms - cfg_before.creator_fee_claimable_atoms,
        expected_creator_cut as u64,
        "batch loop must fold creator_cut_running_total into the claimable counter"
    );
    assert_eq!(
        group_after.insurance_domain_budget[0], group_before.insurance_domain_budget[0],
        "batch taker's domain budget must be UNCHANGED -- the batch creator leg left the backstop too"
    );
    assert_eq!(
        group_after.insurance_domain_budget[1], group_before.insurance_domain_budget[1],
        "N1/N4 regression guard: batch maker's domain is byte-unchanged"
    );
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "NO domain budget anywhere may move on a batch trade"
    );
    assert_eq!(
        cfg_after.lp_fee_accrued_atoms - cfg_before.lp_fee_accrued_atoms,
        expected_lp_cut,
        "lp accrues exactly its configured share (Task 5 wiring)"
    );
    assert_eq!(
        cfg_after.insurance_reserve_accrued_atoms - cfg_before.insurance_reserve_accrued_atoms,
        expected_insurance_cut,
        "insurance reserve accrues its configured share plus rounding dust (Task 5 wiring)"
    );
}

// NOT RUN: this file's native in-process `run_ix`/`TestAccount` harness has no
// real BPF loader, so `invoke_signed` is a stubbed no-op ("SyscallStubs:
// sol_invoke_signed() not available") -- fine for `handle_trade_cpi` (single
// trade), which reads the matcher's fill back by directly borrowing
// `matcher_ctx`'s bytes (pre-seeded by `write_matcher_return` regardless of
// whether invoke_signed actually ran anything), but NOT fine for
// `handle_batch_trade_cpi`, which reads the fill via
// `solana_program::program::get_return_data()` -- a real cross-program
// return-data syscall that only a genuine callee (or a LiteSVM/real-BPF
// harness) can populate. This is a PRE-EXISTING gap: zero BatchTradeCpi tests
// existed anywhere in this file before this change (confirmed by exhaustive
// grep), so this is not a regression. The protocol-fee skim logic itself is
// still covered for the BatchTradeCpi (tag 67) path via (a) code-sharing --
// `handle_batch_trade_cpi` converts the matcher's fills into `BatchTradeLeg`s
// and delegates to the exact same `handle_batch_execute_zero_copy` core
// already exercised (with the skim asserted) by
// `v16_wrapper_protocol_fee_batchtradenocpi_skims_20pct_and_accrues_creator_leg_off_the_backstop`,
// and (b) the engine-level `proof_v16_taker_only_charges_exactly_one_side`
// Kani proof, which is call-site-agnostic. A real fix needs a LiteSVM harness
// with the actual matcher `.so` mounted (see `tests/v16_cu.rs`'s
// `v16_bpf_tradecpi_executes_through_external_matcher_and_is_bounded` for the
// pattern) -- left as follow-up, not attempted here to avoid a half-verified
// LiteSVM matcher-CPI harness under time pressure.
//
// STILL UNRUNNABLE, RE-VERIFIED 2026-07-24: `cargo test --features devnet
// --test v16_wrapper -- --ignored` fails at the `BatchTradeCpi` dispatch with
// `Custom(9)` (InvalidInstruction) -- precisely the
// `get_return_data().ok_or(InvalidInstruction)` arm in `handle_batch_trade_cpi`.
// Nothing about the creator-fee change makes it runnable here; the blocker is
// the missing return-data syscall, not the assertions. The `#[ignore]` stays.
//
// RENAMED 2026-07-24: the old name promised
// `..._credits_taker_domain_only`, which the body has not asserted since the
// creator leg was routed off the per-domain insurance budget -- the assertions
// now pin the claimable counter and require EVERY domain budget to be
// unchanged. A name that contradicts its own body is worse than no name when
// someone finally un-ignores this.
#[test]
#[ignore = "needs a real BPF/LiteSVM harness for get_return_data(); see comment above"]
fn v16_wrapper_protocol_fee_batchtradecpi_skims_20pct_and_accrues_creator_leg_off_the_backstop() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut owner_a = signer();
    let mut owner_b = signer();
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 10_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 10_000_000);

    let mut matcher_program = matcher_program_account();
    let mut matcher_context = matcher_context_account(&matcher_program);
    let maker_owner_bytes = state::read_portfolio_owner_preflight(&account_b.data)
        .map(|(_, owner)| Pubkey::new_from_array(owner))
        .unwrap_or(owner_b.key);
    let mut delegate = matcher_delegate_account(
        &market,
        &account_b,
        &maker_owner_bytes,
        &matcher_program,
        &matcher_context,
    );
    run_ix(
        Instruction::SetMatcherConfig { enabled: 1 },
        &mut [
            &mut owner_b,
            &mut market,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )
    .unwrap();

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();
    let req_id = state::next_market_matcher_req_id(&market.data).unwrap();
    let lp_account_id = {
        let bytes = delegate.key.to_bytes();
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    };
    write_matcher_return(
        &mut matcher_context,
        100,
        (10 * POS_SCALE) as i128,
        req_id,
        lp_account_id,
        0,
        group_before.assets[0].effective_price,
    );

    // Account order matches handle_batch_trade_cpi: [signer_a, market,
    // account_a, account_b, matcher_prog, matcher_ctx, matcher_delegate].
    run_ix(
        Instruction::BatchTradeCpi {
            legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                fee_bps: 1_000,
                limit_price: 0,
            }],
        },
        &mut [
            &mut owner_a,
            &mut market,
            &mut account_a,
            &mut account_b,
            &mut matcher_program,
            &mut matcher_context,
            &mut delegate,
        ],
    )
    .unwrap();

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let total_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let expected_protocol_cut = total_fee * 2_000 / 10_000;
    let expected_creator_cut = total_fee * cfg_before.creator_share_bps as u128 / 10_000;

    assert_eq!(group_after.insurance - group_before.insurance, total_fee);
    assert_eq!(cfg_after.protocol_fee_accrued_atoms, expected_protocol_cut);
    // NOTE: these two assertions were stale twice over while the test sat
    // ignored -- first against the 2026-07-19 four-way split (the taker domain
    // stopped receiving `total_fee - protocol_cut`), then against the
    // 2026-07-23 creator-fee-claim change (the creator leg left the domain
    // budget entirely). Kept current so un-ignoring this test, once a real
    // BPF/LiteSVM harness exists, does not start from a false expectation.
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms - cfg_before.creator_fee_claimable_atoms,
        expected_creator_cut as u64,
        "batch-CPI must accrue the creator leg to the claimable counter"
    );
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "batch-CPI must leave every insurance domain budget unchanged"
    );
}

/// Directly seeds a market's raw insurance/vault/domain-budget/protocol-ledger
/// fields (bypassing a full trade sequence) so WithdrawProtocolFee's
/// authorization/clamping logic can be tested in isolation.
fn seed_protocol_fee_fixture(
    market: &mut TestAccount,
    protocol_fee_authority: [u8; 32],
    accrued: u128,
    withdrawn: u128,
    insurance: u128,
    vault: u128,
) {
    let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
    cfg.protocol_fee_authority = protocol_fee_authority;
    cfg.protocol_fee_accrued_atoms = accrued;
    cfg.protocol_fee_withdrawn_atoms = withdrawn;
    group.insurance = insurance;
    group.vault = vault;
    group.c_tot = 0;
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

#[test]
fn v16_wrapper_withdraw_protocol_fee_unauthorized_signer_rejected() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let mut attacker = signer();
    seed_protocol_fee_fixture(&mut market, admin.key.to_bytes(), 100, 0, 100, 100);

    let mut dest = user_token_account(attacker.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = run_ix(
        Instruction::WithdrawProtocolFee { amount: 50 },
        &mut [
            &mut attacker,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "a signer that isn't cfg.protocol_fee_authority must be rejected"
    );
    assert_eq!(market.data, before, "rejected withdrawal must not mutate the market");
}

#[test]
fn v16_wrapper_withdraw_protocol_fee_clamps_to_surplus_and_double_withdraw_bounded() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    // accrued=100, but the engine's unbudgeted surplus (insurance - reserved -
    // domain_budget_remaining) is only 60 -- the crank-reward-contention clamp
    // (design §1.3/N2) must cap the transfer at 60, not error the whole ix.
    seed_protocol_fee_fixture(&mut market, admin.key.to_bytes(), 100, 0, 60, 60);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 60);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    // amount=0 means "withdraw all currently-available capacity".
    run_ix(
        Instruction::WithdrawProtocolFee { amount: 0 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .unwrap();

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.protocol_fee_withdrawn_atoms, 60,
        "clamped to the actually-available surplus, not the full 100 accrued"
    );
    assert_eq!(group_after.insurance, 0, "surplus fully drained by the clamped transfer");

    // A second withdrawal attempt: claim capacity is now accrued(100) -
    // withdrawn(60) = 40, but there's zero surplus left on-chain -- must be
    // rejected (transfer_amount == 0), never allowed to exceed accrued.
    let over_claim = run_ix(
        Instruction::WithdrawProtocolFee { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert!(
        over_claim.is_err(),
        "double-withdraw beyond the actually-available surplus must be rejected"
    );
    let (cfg_final, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_final.protocol_fee_withdrawn_atoms, 60,
        "a rejected withdrawal must not advance protocol_fee_withdrawn_atoms"
    );
    assert!(
        cfg_final.protocol_fee_withdrawn_atoms <= cfg_final.protocol_fee_accrued_atoms,
        "no-theft invariant: withdrawn can never exceed accrued"
    );
}

#[test]
fn v16_wrapper_withdraw_protocol_fee_rejects_amount_exceeding_accrued_claim() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_protocol_fee_fixture(&mut market, admin.key.to_bytes(), 100, 0, 1_000, 1_000);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    // Plenty of on-chain surplus (1000) but the LEDGER only allows 100 --
    // the ledger, not just the engine surplus check, must bound the payout.
    let rejected = run_ix(
        Instruction::WithdrawProtocolFee { amount: 101 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert!(rejected.is_err(), "amount beyond the accrued claim must be rejected");
    assert_eq!(market.data, before);
}

#[test]
fn v16_wrapper_withdraw_protocol_fee_succeeds_after_resolve_when_fully_wound_down() {
    // W12: ResolveMarket is one-way (no path back to Live). Before the fix,
    // WithdrawProtocolFee was gated Live-only, so any outstanding
    // protocol-fee backlog on a market with NO open portfolios (the common
    // case: fully wound-down before or immediately after resolution) was
    // permanently stranded the instant the market resolved. This proves the
    // new bounded Resolved-mode exit actually pays out in exactly that case.
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_protocol_fee_fixture(&mut market, admin.key.to_bytes(), 100, 0, 100, 100);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Resolved;
        group.resolved_slot = group.current_slot;
        assert_eq!(group.materialized_portfolio_count, 0);
        assert_eq!(group.c_tot, 0);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 100);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::WithdrawProtocolFee { amount: 0 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("bounded surplus withdraw must succeed once Resolved AND fully wound down");
    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.protocol_fee_withdrawn_atoms, 100);
    assert_eq!(group_after.insurance, 0);
    assert_eq!(group_after.vault, 0);
}

#[test]
fn v16_wrapper_withdraw_protocol_fee_resolved_requires_all_portfolios_closed() {
    // W12 non-over-widening control: Resolved mode must NOT become an
    // unconditional pass-through. While ANY portfolio remains open
    // (materialized_portfolio_count != 0) or there is outstanding committed
    // capital (c_tot != 0), the protocol sweep must stay rejected -- exactly
    // mirroring the wind-down precondition tag 41 (WithdrawInsurance) already
    // enforces. The surplus (200) and accrued claim (100) are deliberately
    // generous/non-limiting here so the wind-down guard -- not the
    // engine_available/vault clamp -- is what's actually standing between
    // the request and success.
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 10);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    {
        // Seed the protocol-fee ledger + a generous unbudgeted surplus
        // directly (NOT via seed_protocol_fee_fixture, which unconditionally
        // zeroes c_tot -- this test needs c_tot/materialized_portfolio_count
        // to remain exactly as the real deposit+resolve sequence above left
        // them, since that's the precondition under test).
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        assert_ne!(group.materialized_portfolio_count, 0, "init_portfolio must have materialized one portfolio");
        assert_ne!(group.c_tot, 0, "deposit(10) must have raised c_tot");
        cfg.protocol_fee_authority = admin.key.to_bytes();
        cfg.protocol_fee_accrued_atoms = 100;
        cfg.protocol_fee_withdrawn_atoms = 0;
        group.insurance = 200;
        group.vault = group.vault.checked_add(200).unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 210);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::WithdrawProtocolFee { amount: 1 },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert_err_and_market_unchanged(rejected, &market, &before);
}

/// Raw `UpgradeableLoaderState::ProgramData` bytes matching the manual parse
/// in `read_program_data_upgrade_authority` (45-byte metadata: 4-byte LE
/// discriminant=3, 8-byte slot, 1-byte Option tag, 32-byte pubkey).
fn program_data_account(upgrade_authority: Option<Pubkey>) -> TestAccount {
    let mut data = vec![0u8; 45];
    data[0..4].copy_from_slice(&3u32.to_le_bytes());
    // slot (bytes 4..12) left as 0, unused by the parser.
    match upgrade_authority {
        Some(key) => {
            data[12] = 1;
            data[13..45].copy_from_slice(key.as_ref());
        }
        None => data[12] = 0,
    }
    TestAccount::new_with_data(
        Pubkey::find_program_address(&[program_id().as_ref()], &solana_program::bpf_loader_upgradeable::id()).0,
        solana_program::bpf_loader_upgradeable::id(),
        data,
    )
}

#[test]
fn v16_wrapper_set_protocol_fee_authority_requires_upgrade_authority() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);

    let real_upgrade_authority = signer();
    let mut attacker = signer();
    let new_authority = Pubkey::new_unique();

    // Wrong signer (not the upgrade authority, even though a valid
    // ProgramData account is supplied) must be rejected.
    let mut program_data = program_data_account(Some(real_upgrade_authority.key));
    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::SetProtocolFeeAuthority {
            new_authority: new_authority.to_bytes(),
        },
        &mut [&mut attacker, &mut program_data, &mut market],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "a signer that isn't the program's upgrade authority must be rejected"
    );
    assert_eq!(market.data, before);

    // The real upgrade authority succeeds.
    let mut real_authority_signer = signer();
    real_authority_signer.key = real_upgrade_authority.key;
    run_ix(
        Instruction::SetProtocolFeeAuthority {
            new_authority: new_authority.to_bytes(),
        },
        &mut [&mut real_authority_signer, &mut program_data, &mut market],
    )
    .unwrap();
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.protocol_fee_authority, new_authority.to_bytes());
}

// =============================================================================
// Creator fee claim (2026-07-23 design,
// `docs/superpowers/specs/2026-07-23-creator-fee-claim-design.md`).
//
// The creator's trade-fee leg used to be credited into the per-domain
// insurance budget -- which IS the loss backstop the engine draws down via
// `consume_domain_insurance_for_negative_pnl` -- and its only exit was tag 57
// `WithdrawInsuranceAsset`. A "claim fees" button was therefore a "drain the
// backstop" button. The leg now accrues into
// `WrapperConfigV16::creator_fee_claimable_atoms` (bytes 568..576) and leaves
// only through tag 90 `WithdrawCreatorFee`.
//
// The accrual + negative (budget-unchanged) assertions live in the three
// `..._accrues_creator_leg_off_the_backstop` tests above, one per credit site
// (TradeNoCpi, TradeCpi, BatchTradeNoCpi -- the batch site credited
// `credit_fee_to_domain_budget_view` DIRECTLY and needs its own coverage).
// This block covers write-back, accrual overflow, and the tag-90 withdraw.
// =============================================================================

/// Directly seeds the creator claim counter plus the engine's insurance/vault
/// surplus, so tag 90's authority / capacity / isolation behaviour can be
/// tested without threading a full trade sequence. Mirrors
/// `seed_protocol_fee_fixture`.
///
/// `state::write_market` regenerates asset 0's oracle profile from `cfg` only
/// when `cfg.oracle_mode != ORACLE_MODE_MANUAL`; `InitMarket` writes MANUAL, so
/// this does NOT silently rewrite asset 0's stored authorities (`asset_admin` --
/// the tag-90 claim gate -- or `insurance_operator`) out from under the
/// staked-create-flow test below.
fn seed_creator_fee_fixture(
    market: &mut TestAccount,
    claimable: u64,
    insurance: u128,
    vault: u128,
) {
    let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
    cfg.creator_fee_claimable_atoms = claimable;
    group.insurance = insurance;
    group.vault = vault;
    group.c_tot = 0;
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

/// The six accounts tag 90 takes, in handler order.
fn withdraw_creator_fee(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    dest: &mut TestAccount,
    vault: &mut TestAccount,
    vault_auth: &mut TestAccount,
    token_program: &mut TestAccount,
    amount: u128,
) -> Result<(), ProgramError> {
    run_ix(
        Instruction::WithdrawCreatorFee { amount },
        &mut [authority, market, dest, vault, vault_auth, token_program],
    )
}

/// Same six accounts, but dispatched through `run_ix_no_rollback` so the
/// market account is left EXACTLY as the handler left it on rejection.
///
/// Every "a rejected claim must not mutate the market / must not have wrapped
/// the counter" assertion in this block is routed through here. Through the
/// plain `withdraw_creator_fee` those assertions are unfalsifiable: `run_ix`
/// restores the pre-call bytes on `Err` before the assertion is even reached,
/// so they hold no matter what the handler did.
#[allow(clippy::too_many_arguments)]
fn withdraw_creator_fee_no_rollback(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    dest: &mut TestAccount,
    vault: &mut TestAccount,
    vault_auth: &mut TestAccount,
    token_program: &mut TestAccount,
    amount: u128,
) -> Result<(), ProgramError> {
    run_ix_no_rollback(
        Instruction::WithdrawCreatorFee { amount },
        &mut [authority, market, dest, vault, vault_auth, token_program],
    )
}

/// Ordinal pin for the creator-fee-claim error code. Ordinals are wire-visible
/// (the SDK maps `ProgramError::Custom(n)` back to a name), so an INSERTION
/// rather than an append silently re-points every client's error map. The
/// neighbours are pinned alongside it so this fails loudly rather than
/// mysteriously.
///
/// The other two pins for this tail live in `tests/v16_cu.rs`
/// (`v17_new_error_ordinals_are_appended_at_the_tail`) and
/// `tests/v16_fee_split.rs` (`fee_split_error_ordinals_are_pinned`); this one
/// is here because tag 90's behaviour tests are here.
#[test]
fn v16_wrapper_creator_fee_over_claim_error_ordinal_is_appended_at_the_tail() {
    use percolator_prog::error::PercolatorError;
    assert_eq!(PercolatorError::StakeProgramNotPinned as u32, 60);
    assert_eq!(PercolatorError::AssetSlotAlreadyConfigured as u32, 61);
    assert_eq!(
        PercolatorError::CreatorFeeOverClaim as u32,
        62,
        "CreatorFeeOverClaim must be APPENDED at 62 -- inserting it anywhere \
         earlier renumbers already-shipped codes"
    );
    // The over-claim code must stay DISTINCT from the internal-invariant code
    // it was split out of, or the split is cosmetic.
    assert_ne!(
        PercolatorError::CreatorFeeOverClaim as u32,
        PercolatorError::EngineCounterUnderflow as u32,
        "an over-ask by a caller must not report as an engine ledger underflow"
    );
    assert_eq!(PercolatorError::EngineCounterUnderflow as u32, 25);
}

/// WRITE-BACK regression guard (design §2, "the `cfg_after = Some(cfg)`
/// write-back is load-bearing -- a missed write-back SILENTLY DISCARDS accrued
/// fees").
///
/// Two things are proven that a single-trade counter read cannot:
///   1. the accrual reaches the ACCOUNT BYTES at config offset 568..576 (the
///      wire slot the SDK/frontend will read), not just an in-memory `cfg`;
///   2. it ACCUMULATES across two separate `process_instruction` invocations.
///      A missed write-back leaves the second trade reading 0 and the counter
///      ends at one trade's worth, not two.
#[test]
fn v16_wrapper_creator_fee_accrual_is_written_back_to_the_account_and_accumulates() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);

    let (cfg_before, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_before.creator_fee_claimable_atoms, 0);
    let per_trade_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let per_trade_creator = per_trade_fee * cfg_before.creator_share_bps as u128 / 10_000;
    assert_ne!(per_trade_creator, 0, "fixture must produce a nonzero creator leg");

    // Raw slot in the market account: 16-byte header + 568-byte config prefix.
    const CLAIMABLE_OFF: usize = 16 + 568;
    let raw_counter = |data: &[u8]| -> u64 {
        u64::from_le_bytes(data[CLAIMABLE_OFF..CLAIMABLE_OFF + 8].try_into().unwrap())
    };

    for expected_trades in 1..=2u128 {
        run_ix(
            Instruction::TradeNoCpi {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                exec_price: 100,
                fee_bps: 1_000,
            },
            &mut [
                &mut long_owner,
                &mut short_owner,
                &mut market,
                &mut long_account,
                &mut short_account,
            ],
        )
        .unwrap();
        let expected = (per_trade_creator * expected_trades) as u64;
        assert_eq!(
            raw_counter(&market.data),
            expected,
            "after {expected_trades} trade(s) the RAW account bytes at 568..576 must hold the \
             running creator accrual -- a missed cfg_after write-back reads back as 0/stale here"
        );
        let (cfg_now, _) = state::read_market(&market.data).unwrap();
        assert_eq!(
            cfg_now.creator_fee_claimable_atoms, expected,
            "the parsed view must agree with the raw bytes"
        );
    }
}

/// OVERFLOW, single-trade path: `checked_add` must ERROR, never wrap. Seeded at
/// `u64::MAX` so the next accrual cannot fit. A `wrapping_add` would silently
/// reset the creator's claim to ~0 (and `saturating_add` would silently mint an
/// unbacked ~1.8e19-atom claim), so the whole trade must reject instead.
#[test]
fn v16_wrapper_creator_fee_accrual_overflow_rejects_the_trade_instead_of_wrapping() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);
    {
        let (mut cfg, group) = state::read_market(&market.data).unwrap();
        cfg.creator_fee_claimable_atoms = u64::MAX;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 1_000,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(15)), // EngineArithmeticOverflow
        "an accrual that cannot fit u64 must reject the trade with EngineArithmeticOverflow"
    );
    assert_eq!(market.data, before, "the rejected trade must not mutate the market");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms,
        u64::MAX,
        "the counter must be exactly u64::MAX still -- not wrapped to a small value"
    );
}

/// OVERFLOW, batch path: the post-loop fold of `creator_cut_running_total` has
/// its own `checked_add`, so it needs its own test.
#[test]
fn v16_wrapper_creator_fee_batch_accrual_overflow_rejects_the_batch_instead_of_wrapping() {
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);
    {
        let (mut cfg, group) = state::read_market(&market.data).unwrap();
        cfg.creator_fee_claimable_atoms = u64::MAX;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before = market.data.clone();
    let rejected = run_ix(
        Instruction::BatchTradeNoCpi {
            legs: vec![percolator_prog::ix::BatchTradeLeg {
                asset_index: 0,
                size_q: (10 * POS_SCALE) as i128,
                exec_price: 100,
                fee_bps: 1_000,
            }],
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(15)), // EngineArithmeticOverflow
        "the batch fold must reject with EngineArithmeticOverflow, not wrap"
    );
    assert_eq!(market.data, before, "the rejected batch must not mutate the market");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, u64::MAX);
}

/// A claim BELOW capacity pays out and decrements by exactly `amount`, and the
/// atoms leave both the insurance fund and the engine vault (they are real
/// value, not a bookkeeping entry).
#[test]
fn v16_wrapper_withdraw_creator_fee_below_capacity_decrements_by_exactly_the_amount() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let (_, group_before) = state::read_market(&market.data).unwrap();

    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        40,
    )
    .expect("a claim within capacity must succeed");

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms, 60,
        "the counter must fall by EXACTLY the claimed amount (100 - 40)"
    );
    assert_eq!(
        group_before.insurance - group_after.insurance,
        40,
        "the claimed atoms must leave the insurance fund"
    );
    assert_eq!(
        group_before.vault - group_after.vault,
        40,
        "the claimed atoms must leave the engine vault"
    );

    // A second claim continues from the decremented balance rather than the
    // original one -- i.e. the decrement was persisted, not just computed.
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        60,
    )
    .expect("the remaining balance must still be claimable");
    let (cfg_final, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_final.creator_fee_claimable_atoms, 0);
}

/// A claim of EXACTLY the capacity drains the counter to zero, and a further
/// 1-atom claim is then rejected (the counter is not silently replenished).
#[test]
fn v16_wrapper_withdraw_creator_fee_at_capacity_drains_to_zero_then_rejects() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    )
    .expect("claiming exactly the capacity must succeed");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 0, "capacity must drain to exactly 0");

    let drained = market.data.clone();
    // NO-ROLLBACK harness: the "must not underflow-wrap" claim below is about
    // what the HANDLER leaves behind, so it must not be handed pre-call bytes
    // that `run_ix` restored on `Err`.
    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        1,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(62)), // CreatorFeeOverClaim
        "a claim against a drained counter must reject as an over-claim, not underflow-wrap"
    );
    assert_eq!(
        market.data, drained,
        "the handler itself must leave the drained market untouched"
    );
    let (cfg_drained, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_drained.creator_fee_claimable_atoms, 0,
        "0 - 1 must not have wrapped the counter to ~1.8e19 claimable atoms"
    );
}

/// A claim ABOVE capacity is rejected outright -- not saturated down to the
/// capacity, and not partially filled. The engine surplus (1_000) is
/// deliberately far larger than the claim (101) so that the LEDGER, not the
/// engine's own surplus clamp, is what rejects.
///
/// EVERY rejection here runs through `withdraw_creator_fee_no_rollback`. The
/// point of the test is that the HANDLER declines to touch the counter, and
/// `run_ix`'s restore-on-Err would have supplied that conclusion for free.
#[test]
fn v16_wrapper_withdraw_creator_fee_over_claim_is_rejected_not_saturated() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        101,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(62)), // CreatorFeeOverClaim
        "claiming 101 against a 100-atom counter must reject with the caller-error \
         code, not the engine's internal-invariant EngineCounterUnderflow (25)"
    );
    assert_eq!(
        market.data, before,
        "the handler must not have written a single byte before rejecting"
    );
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms, 100,
        "a rejected over-claim must leave the full balance claimable (no saturation)"
    );

    // An amount above u64::MAX is an over-claim too, not a narrowing accident.
    let huge = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        u64::MAX as u128 + 1,
    );
    assert_eq!(huge, Err(ProgramError::Custom(62)));
    assert_eq!(market.data, before);

    // A zero claim is rejected as a caller bug rather than silently no-op'ing
    // (deliberate divergence from tag 84, where 0 means "withdraw everything").
    let zero = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        0,
    );
    assert_eq!(
        zero,
        Err(ProgramError::Custom(9)), // InvalidInstruction
        "amount == 0 must reject: tag 84's '0 means all' convention is NOT inherited"
    );
    assert_eq!(market.data, before);
}

/// Only asset 0's `asset_admin` may claim (2026-07-24 re-gate). Two rejections
/// pin the gate, then the real `asset_admin` succeeds:
///   1. an arbitrary signer holding NEITHER key, and
///   2. THE REGRESSION that proves the gate actually moved: a signer holding
///      asset 0's `insurance_operator` but NOT its `asset_admin`. Under the old
///      `insurance_operator` gate this signer would have SUCCEEDED and drained
///      the creator's claim; under the new gate it must be Unauthorized.
///
/// `insurance_operator` and `asset_admin` both bootstrap to the creator at
/// `InitMarket`, so the fixture first rotates `insurance_operator` away (via the
/// real `UpdateAssetAuthority`, admin co-signing) to make the two keys distinct
/// -- otherwise case (2) is untestable and the whole test is vacuous w.r.t. the
/// move.
#[test]
fn v16_wrapper_withdraw_creator_fee_rejects_a_signer_who_is_not_the_asset_admin() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    // Split the two keys: rotate asset 0's insurance_operator to a fresh key,
    // leaving asset_admin with the creator. Now `operator` holds ONLY the old
    // gate's key.
    let mut operator = signer();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: operator.key.to_bytes(),
        },
        &mut [&mut admin, &mut operator, &mut market],
    )
    .unwrap();
    let profile = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile.insurance_operator,
        operator.key.to_bytes(),
        "fixture: insurance_operator now held by a key that is NOT the asset_admin"
    );
    assert_eq!(
        profile.asset_admin,
        admin.key.to_bytes(),
        "fixture: rotating insurance_operator must leave asset_admin with the creator"
    );

    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    // (1) An arbitrary signer holding neither key.
    let mut attacker = signer();
    let mut attacker_dest = user_token_account(attacker.key, mint, 0);
    let before = market.data.clone();
    let rejected = withdraw_creator_fee_no_rollback(
        &mut attacker,
        &mut market,
        &mut attacker_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        1,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "a signer that holds neither asset 0's asset_admin nor its insurance_operator must be rejected"
    );
    assert_eq!(
        market.data, before,
        "the handler must reject before touching the market -- asserted through the \
         no-rollback harness, so this is the handler's discipline and not run_ix's restore"
    );

    // (2) THE REGRESSION: the insurance_operator, now DISTINCT from asset_admin,
    // must be rejected. This is the case that fails if the gate is reverted to
    // `insurance_operator`.
    let mut operator_dest = user_token_account(operator.key, mint, 0);
    let before = market.data.clone();
    let operator_rejected = withdraw_creator_fee_no_rollback(
        &mut operator,
        &mut market,
        &mut operator_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        1,
    );
    assert_eq!(
        operator_rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "asset 0's insurance_operator is NO LONGER the creator-fee key -- it must be rejected"
    );
    assert_eq!(market.data, before);

    // The real asset_admin (the creator) still succeeds, proving the rejections
    // above were the authority gate and not an unrelated failure in the fixture.
    let mut admin_dest = user_token_account(admin.key, mint, 0);
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut admin_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        1,
    )
    .expect("asset 0's asset_admin (the creator) must be able to claim");
}

/// STAKED MARKET (design §3): the wizard's full create flow rotates BOTH
/// `cfg.marketauth` (via `StakeInitPool`, to the stake-pool PDA) AND asset 0's
/// `insurance_operator` (via `BindInsuranceAuthority`, to a program PDA nobody
/// can sign for). It leaves `asset_admin` -- the creator's wallet -- alone. So
/// the creator must STILL be able to claim via `asset_admin`, while BOTH rotated
/// authorities are rejected. The `insurance_operator` rejection is the whole
/// reason the gate is `asset_admin` and not `insurance_operator`; the marketauth
/// rejection is why `verify_domain_withdrawal_preflight` (which accepts
/// `marketauth` as an alternate gate) is NOT reused here.
#[test]
fn v16_wrapper_withdraw_creator_fee_survives_the_staked_create_flow_and_only_asset_admin_claims() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    let profile_before = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile_before.asset_admin,
        admin.key.to_bytes(),
        "InitMarket must bootstrap asset 0's asset_admin to the creator"
    );

    // (a) StakeInitPool: `cfg.marketauth = pool_pda`, via the real UpdateAuthority
    // handler (both keys co-sign).
    let mut pool_pda = signer();
    run_ix(
        Instruction::UpdateAuthority {
            new_pubkey: pool_pda.key.to_bytes(),
        },
        &mut [&mut admin, &mut pool_pda, &mut market],
    )
    .unwrap();

    // (b) BindInsuranceAuthority: asset 0's `insurance_operator = <program PDA>`.
    // A throwaway signer stands in for the un-signable PDA precisely so it can
    // still ATTEMPT the claim below -- the point is that holding
    // `insurance_operator` no longer authorizes it.
    let mut operator_pda = signer();
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: operator_pda.key.to_bytes(),
        },
        &mut [&mut admin, &mut operator_pda, &mut market],
    )
    .unwrap();

    let (cfg_rotated, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_rotated.marketauth, pool_pda.key.to_bytes(), "marketauth must have rotated");
    let profile_after = state::read_asset_oracle_profile(&market.data, 0).unwrap();
    assert_eq!(
        profile_after.insurance_operator,
        operator_pda.key.to_bytes(),
        "the stake flow rotated insurance_operator to a PDA"
    );
    assert_eq!(
        profile_after.asset_admin,
        admin.key.to_bytes(),
        "...but must NOT have dragged asset_admin along -- it still tracks the creator"
    );

    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    // The pool PDA is now marketauth. It must NOT be able to claim.
    let mut pool_dest = user_token_account(pool_pda.key, mint, 0);
    let before = market.data.clone();
    let pool_rejected = withdraw_creator_fee_no_rollback(
        &mut pool_pda,
        &mut market,
        &mut pool_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    );
    assert_eq!(
        pool_rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "the staked market's pool PDA (now marketauth) must NOT be able to claim creator revenue"
    );
    assert_eq!(
        market.data, before,
        "the refused pool claim must not debit the counter -- no-rollback harness, so \
         this is the handler's own doing"
    );

    // Nor may the rotated insurance_operator PDA -- THE regression that proves
    // the gate is `asset_admin`, not `insurance_operator` (2026-07-24). On a
    // real staked market this key is a PDA and unsignable; even standing in for
    // it with a signer, the claim must be refused.
    let mut operator_dest = user_token_account(operator_pda.key, mint, 0);
    let before = market.data.clone();
    let operator_rejected = withdraw_creator_fee_no_rollback(
        &mut operator_pda,
        &mut market,
        &mut operator_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    );
    assert_eq!(
        operator_rejected,
        Err(ProgramError::Custom(8)), // Unauthorized
        "asset 0's insurance_operator (a PDA on a staked market) must NOT be able to claim"
    );
    assert_eq!(market.data, before);

    // The creator, who still holds asset_admin, can.
    let mut creator_dest = user_token_account(admin.key, mint, 0);
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut creator_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    )
    .expect("the creator must still claim via asset_admin on a staked market");
    let (cfg_final, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_final.creator_fee_claimable_atoms, 0);
}

/// ISOLATION, direction A (design testing item 6): a creator claim must not
/// reach the loss backstop. Every `insurance_domain_budget` entry -- and the
/// engine's `insurance_domain_budget_remaining_total` aggregate -- must be
/// byte-identical across the claim.
#[test]
fn v16_wrapper_withdraw_creator_fee_cannot_reduce_any_insurance_domain_budget() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    // A funded backstop sitting alongside the creator claim: insurance must
    // cover BOTH the budget (250) and the claim (100), since tag 90 draws only
    // from the UNBUDGETED surplus.
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.creator_fee_claimable_atoms = 100;
        group.insurance_domain_budget[0] = 150;
        group.insurance_domain_budget[1] = 100;
        group.insurance = 1_000;
        group.vault = 1_000;
        group.c_tot = 0;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }
    let (_, group_before) = state::read_market(&market.data).unwrap();
    assert_eq!(group_before.insurance_domain_budget[0], 150, "fixture must fund the backstop");
    assert_eq!(group_before.insurance_domain_budget[1], 100);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    )
    .expect("the full creator claim must succeed alongside a funded backstop");

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 0);
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "WithdrawCreatorFee must not reduce ANY insurance domain budget -- the counter is \
         disjoint from the loss backstop by construction"
    );
    assert_eq!(
        group_before.insurance - group_after.insurance,
        100,
        "the claim comes out of the UNBUDGETED surplus only"
    );
}

/// End-to-end: a real trade accrues, and the creator then claims exactly what
/// that trade produced -- no seeding anywhere. Ties the two halves of the
/// design together and catches a units/scale mismatch between the accrual site
/// (u128 split) and the withdraw site (u64 counter).
#[test]
fn v16_wrapper_creator_fee_end_to_end_trade_accrues_then_creator_claims_exactly_that() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);

    let (cfg_before, _) = state::read_market(&market.data).unwrap();
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: (10 * POS_SCALE) as i128,
            exec_price: 100,
            fee_bps: 1_000,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    let total_fee = taker_only_fee(10 * POS_SCALE, 100, 1_000);
    let earned = total_fee * cfg_before.creator_share_bps as u128 / 10_000;
    assert_ne!(earned, 0);
    let (cfg_accrued, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_accrued.creator_fee_claimable_atoms as u128, earned);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    // One atom more than was earned must be rejected...
    let before = market.data.clone();
    let over = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        earned + 1,
    );
    assert_eq!(
        over,
        Err(ProgramError::Custom(62)), // CreatorFeeOverClaim
        "over-claiming a real accrual is a caller error, not an engine underflow"
    );
    assert_eq!(market.data, before);

    // ...and exactly what was earned must be payable.
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        earned,
    )
    .expect("the creator must be able to claim exactly the fees the trade produced");
    let (cfg_claimed, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_claimed.creator_fee_claimable_atoms, 0);
}

/// SIGNER GATE. `expect_signer(authority)` is the first thing tag 90 does, and
/// nothing else in the handler can substitute for it: the authority check that
/// follows compares KEYS ONLY (`live_authority_matches`), so without the signer
/// requirement anyone could name the creator's pubkey in slot 0 -- a pubkey
/// that is public by definition -- and drain the claim.
///
/// The account here carries the CORRECT `asset_admin` key with
/// `is_signer = false`, so the key comparison passes and only the signer check
/// can reject. Routed through the no-rollback harness so the
/// "market untouched" half is the handler's doing.
#[test]
fn v16_wrapper_withdraw_creator_fee_requires_the_asset_admin_to_actually_sign() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    // Same key as `admin`, but NOT a signer (no `.signer()`).
    let mut unsigned_operator = TestAccount::new(admin.key, Pubkey::new_unique(), 0);
    assert!(!unsigned_operator.is_signer);
    assert_eq!(
        unsigned_operator.key,
        admin.key,
        "the fixture must present the RIGHT key, so only the signer gate can reject"
    );

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut unsigned_operator,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        50,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(6)), // ExpectedSigner
        "naming the creator's pubkey without signing for it must reject with ExpectedSigner"
    );
    assert_eq!(market.data, before, "a non-signed claim must not debit the counter");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 100);

    // Control: the SAME key, signing, succeeds -- so the rejection above was
    // the signer gate and nothing else about the fixture.
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        50,
    )
    .expect("the same key, signing, must be able to claim");
    let (cfg_signed, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_signed.creator_fee_claimable_atoms, 50);
}

/// TOKEN-ACCOUNT GUARD (a): `verify_withdrawable_token_accounts` pins
/// `dest_token.owner == authority`. Without it the creator could pay their
/// claim into ANY token account -- which matters because the authority here
/// (asset 0's `asset_admin`) may be a multisig or cold-storage key whose signer
/// is not the intended beneficiary, and because it is the only thing tying the
/// payout to the signer at all.
///
/// Ported from the tag-87 negatives in `tests/v16_fee_split.rs`
/// (`tag87_rejects_...`), which cover the same helper on the stake leg.
#[test]
fn v16_wrapper_withdraw_creator_fee_rejects_a_dest_token_not_owned_by_the_authority() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    // Correct mint, correct SPL program, initialized -- but owned by someone
    // else, so ONLY the dest-owner pin can reject.
    let attacker = Pubkey::new_unique();
    let mut foreign_dest = user_token_account(attacker, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut foreign_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        40,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(11)), // InvalidTokenAccount
        "a destination the signing authority does not own must be rejected"
    );
    assert_eq!(market.data, before);
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms, 100,
        "not one atom of claim may be spent against a foreign destination"
    );

    // Control: the authority's OWN token account is accepted.
    let mut own_dest = user_token_account(admin.key, mint, 0);
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut own_dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        40,
    )
    .expect("the authority's own token account must be accepted");
}

/// TOKEN-ACCOUNT GUARD (b), the subtle one: a token account whose SPL owner IS
/// the market's `vault_authority` PDA, but which sits at a NON-CANONICAL
/// address (not the vault ATA). `verify_withdrawable_token_accounts` pins
/// `vault_token_ai.key == canonical_vault_address(...)` precisely because an
/// owner-only check would accept this -- F-VAULT-FRAG, vault fragmentation
/// that strands honest withdrawals in side accounts.
///
/// This is the direct tag-90 port of
/// `tag87_rejects_a_vault_auth_owned_impostor_at_the_wrong_address`.
#[test]
fn v16_wrapper_withdraw_creator_fee_rejects_a_vault_authority_owned_impostor_vault() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    // Correct SPL owner (the vault authority PDA), correct mint, funded --
    // wrong ADDRESS. Only the canonical-address pin can reject it.
    let mut impostor_vault = TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data(mint, vault_authority(&market), 1_000),
    )
    .writable();
    assert_ne!(
        impostor_vault.key,
        canonical_vault_ata(&vault_authority(&market), &mint),
        "the impostor must not accidentally be the canonical vault"
    );

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut impostor_vault,
        &mut vault_auth,
        &mut token_program,
        40,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(12)), // InvalidVaultAccount
        "correct SPL owner but wrong address must still be rejected -- the pin is the \
         canonical vault ATA, not merely the owner"
    );
    assert_eq!(market.data, before);
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 100);

    // Control: the canonical vault at the same balance IS accepted.
    let mut real_vault = vault_token_account(&market, mint, 1_000);
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut real_vault,
        &mut vault_auth,
        &mut token_program,
        40,
    )
    .expect("the canonical vault must be accepted");
}

/// VAULT-BALANCE GUARD: `require_token_balance(vault_token, amount)`. The
/// engine's own `withdraw_insurance_surplus_not_atomic` bounds the claim
/// against the engine's BOOK (`header.insurance`/`vault`), which can legitimately
/// exceed what is physically in the SPL vault (e.g. a secondary-mint market, or
/// a vault mid-migration). Without this check the handler would debit the
/// counter and then hand the SPL program a transfer it cannot fill.
///
/// The fixture deliberately makes the BOOK generous (insurance/vault = 1_000)
/// and only the SPL balance thin (10), so `require_token_balance` is the only
/// thing that can reject.
#[test]
fn v16_wrapper_withdraw_creator_fee_rejects_when_the_spl_vault_balance_is_too_thin() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut thin_vault = vault_token_account(&market, mint, 10);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut thin_vault,
        &mut vault_auth,
        &mut token_program,
        40,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(11)), // InvalidTokenAccount
        "a claim larger than the vault's SPL balance must reject before anything is debited"
    );
    assert_eq!(market.data, before);
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms, 100,
        "the counter must not be debited for a transfer the vault cannot fund"
    );

    // Control: the SAME claim against a vault that can fund it succeeds, so the
    // rejection above was the balance guard and not the ledger/authority path.
    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut thin_vault,
        &mut vault_auth,
        &mut token_program,
        10,
    )
    .expect("a claim within the vault's SPL balance must succeed");
}

/// MODE GATE, positive half. Mirrors
/// `v16_wrapper_withdraw_protocol_fee_succeeds_after_resolve_when_fully_wound_down`
/// for tag 90, and for the same W12 reason: `ResolveMarket` is one-way and tag
/// 90 is this counter's ONLY exit, so a Live-only gate would strand every
/// unclaimed creator atom the instant a market resolves.
#[test]
fn v16_wrapper_withdraw_creator_fee_succeeds_after_resolve_when_fully_wound_down() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Resolved;
        group.resolved_slot = group.current_slot;
        assert_eq!(group.materialized_portfolio_count, 0);
        assert_eq!(group.c_tot, 0);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    withdraw_creator_fee(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        100,
    )
    .expect("a fully wound-down Resolved market must still pay the creator's claim");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 0);
}

/// MODE GATE, non-over-widening half. Mirrors
/// `v16_wrapper_withdraw_protocol_fee_resolved_requires_all_portfolios_closed`.
/// Resolved must not become an unconditional pass-through: while ANY portfolio
/// is still materialized or any committed capital remains (`c_tot != 0`), the
/// claim stays rejected, exactly as tag 41 `WithdrawInsurance` requires.
///
/// The claim (1) and the surplus (200) are deliberately non-limiting so the
/// wind-down guard -- not the ledger or the engine's surplus clamp -- is what
/// stands between the request and success.
#[test]
fn v16_wrapper_withdraw_creator_fee_resolved_requires_all_portfolios_closed() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    let mint = init_market(&mut admin, &mut market);
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 10);
    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    {
        // Seeded inline rather than via `seed_creator_fee_fixture`, which
        // unconditionally zeroes `c_tot` -- the very precondition under test.
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        assert_ne!(
            group.materialized_portfolio_count, 0,
            "init_portfolio must have materialized one portfolio"
        );
        assert_ne!(group.c_tot, 0, "deposit(10) must have raised c_tot");
        cfg.creator_fee_claimable_atoms = 100;
        group.insurance = 200;
        group.vault = group.vault.checked_add(200).unwrap();
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 210);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        1,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(21)), // EngineLockActive
        "a Resolved market with an open portfolio must still refuse the claim"
    );
    assert_eq!(market.data, before);
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 100);
}

/// MODE GATE, third arm: neither Live nor Resolved. `Recovery` is the only
/// other `MarketModeV16`, and the handler's gate is written as "not Live and
/// not Resolved -> reject", so this is the arm that proves the gate is a
/// whitelist rather than a Live-only check with a Resolved escape hatch.
#[test]
fn v16_wrapper_withdraw_creator_fee_rejects_in_recovery_mode() {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_creator_fee_fixture(&mut market, 100, 1_000, 1_000);
    {
        let (cfg, mut group) = state::read_market(&market.data).unwrap();
        group.mode = MarketModeV16::Recovery;
        group.recovery_reason = Some(PermissionlessRecoveryReasonV16::BelowProgressFloor);
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 1_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();
    let before = market.data.clone();

    let rejected = withdraw_creator_fee_no_rollback(
        &mut admin,
        &mut market,
        &mut dest,
        &mut vault,
        &mut vault_auth,
        &mut token_program,
        40,
    );
    assert_eq!(
        rejected,
        Err(ProgramError::Custom(21)), // EngineLockActive
        "Recovery is neither Live nor Resolved -- the claim must be refused"
    );
    assert_eq!(market.data, before);
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_after.creator_fee_claimable_atoms, 100);
}

/// BATCH MULTI-LEG FOLD. The batch post-pass accumulates
/// `creator_cut_running_total` INSIDE the leg loop and folds it into the
/// counter ONCE after the loop. Every other batch test in this file submits
/// exactly ONE leg, which makes "accumulate" and "assign" indistinguishable:
/// replacing the in-loop
/// `creator_cut_running_total = creator_cut_running_total.checked_add(split_leg.creator)?`
/// with a plain `= split_leg.creator` leaves a single-leg suite entirely green
/// while silently paying the creator only the LAST leg of every real batch.
///
/// This test submits TWO legs on DISTINCT assets (the batch pre-pass rejects
/// duplicate `asset_index`) with DELIBERATELY UNEQUAL sizes, so the sum
/// (16 + 48 = 64) differs from the last leg alone (48), from the first alone
/// (16), and from the max. It asserts the counter delta equals the SUM.
#[test]
fn v16_wrapper_creator_fee_batch_multi_leg_accrues_the_sum_of_every_leg() {
    let mut admin = signer();
    let mut market = market_account();
    // `max_portfolio_assets = 2` both pre-configures asset slots 0 and 1 as
    // Active at InitMarket and raises each portfolio's active-leg cap to 2, so
    // one batch can carry a leg on each.
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                max_portfolio_assets,
                ..
            } = ix
            {
                *max_portfolio_assets = 2;
            }
        }),
    );
    set_trade_fee_base_bps(&mut market, 1_000);

    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_before.creator_fee_claimable_atoms, 0);

    // Unequal sizes => unequal per-leg creator cuts => the SUM is distinguishable
    // from any single leg.
    let leg0_size = 10 * POS_SCALE;
    let leg1_size = 30 * POS_SCALE;
    run_ix(
        Instruction::BatchTradeNoCpi {
            legs: vec![
                percolator_prog::ix::BatchTradeLeg {
                    asset_index: 0,
                    size_q: leg0_size as i128,
                    exec_price: 100,
                    fee_bps: 1_000,
                },
                percolator_prog::ix::BatchTradeLeg {
                    asset_index: 1,
                    size_q: leg1_size as i128,
                    exec_price: 100,
                    fee_bps: 1_000,
                },
            ],
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .expect("a two-leg batch on distinct assets must execute");

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let fee_leg0 = taker_only_fee(leg0_size, 100, 1_000);
    let fee_leg1 = taker_only_fee(leg1_size, 100, 1_000);
    let creator_leg0 = fee_leg0 * cfg_before.creator_share_bps as u128 / 10_000;
    let creator_leg1 = fee_leg1 * cfg_before.creator_share_bps as u128 / 10_000;
    let creator_sum = creator_leg0 + creator_leg1;

    // Guard the guard: if the two legs ever produced the same cut, or either
    // were zero, the SUM assertion below would stop distinguishing "accumulate"
    // from "assign the last leg".
    assert_ne!(creator_leg0, 0, "leg 0 must produce a nonzero creator cut");
    assert_ne!(creator_leg1, 0, "leg 1 must produce a nonzero creator cut");
    assert_ne!(
        creator_leg0, creator_leg1,
        "the two legs must differ, or an in-loop ASSIGNMENT would be indistinguishable \
         from an ACCUMULATION"
    );
    assert_ne!(
        creator_sum, creator_leg1,
        "the sum must differ from the last leg alone -- that is the whole mutation \
         this test exists to catch"
    );

    assert_eq!(
        cfg_after.creator_fee_claimable_atoms - cfg_before.creator_fee_claimable_atoms,
        creator_sum as u64,
        "the batch fold must credit the SUM of every leg's creator cut, not just one leg"
    );
    // The other three legs are folded the same way, so pin them on the same
    // multi-leg batch: a mis-folded running total in any of them is the same bug.
    assert_eq!(
        group_after.insurance - group_before.insurance,
        fee_leg0 + fee_leg1,
        "header.insurance still receives 100% of BOTH legs' fees"
    );
    assert_eq!(
        cfg_after.protocol_fee_accrued_atoms - cfg_before.protocol_fee_accrued_atoms,
        fee_leg0 * 2_000 / 10_000 + fee_leg1 * 2_000 / 10_000,
        "the protocol fold must also sum across legs"
    );
    assert_eq!(
        cfg_after.lp_fee_accrued_atoms - cfg_before.lp_fee_accrued_atoms,
        fee_leg0 * cfg_before.lp_share_bps as u128 / 10_000
            + fee_leg1 * cfg_before.lp_share_bps as u128 / 10_000,
        "the LP fold must also sum across legs"
    );
    assert_eq!(
        group_after.insurance_domain_budget, group_before.insurance_domain_budget,
        "and no domain budget moves on a multi-leg batch either"
    );
}

// =============================================================================
// Fee-split policy setters, end-to-end through the real
// `UpdateBackingFeePolicy` / `UpdateTradeFeePolicy` handlers.
//
// The `fee_split_floor_ok` two-rate floor these tests originally pinned was
// RETIRED on 2026-07-19: it validated a split of
// `T = trade_fee_base_bps + backing_fee_bps` that no longer exists, and is
// superseded by `validate_fee_split` (tag 86), which is exact rather than
// tolerance-based.
//
// EXACT CHURN in `2b3a6a65` (`git show 2b3a6a65 -- tests/v16_wrapper.rs`):
// three floor-pinning tests were removed and two inverted guards added —
//   deleted: `..._fee_split_floor_low_t_vacuity_shrinks_to_proven_residual`
//   inverted: `..._fee_split_floor_enforced_at_wizard_default_t20`
//             -> `..._update_backing_fee_policy_no_longer_enforces_the_two_rate_floor`
//   inverted: `..._fee_split_floor_update_trade_fee_policy_checks_every_asset_not_just_asset0`
//             -> `..._update_trade_fee_policy_no_longer_enforces_the_two_rate_floor`
// So: TWO inverted, ONE deleted. The commit message's "three ... inverted into
// two regression guards" counts the originals, not the inversions; read as
// "three inverted" it is wrong.
//
// The two inverted guards are the first two tests below. The third test,
// `..._legacy_fee_policy_setters_persist_and_leave_the_tag86_split_untouched`,
// was NOT part of that churn — it predates it and survived unchanged, which
// left it asserting a floor that no longer existed. It was rewritten in the
// branch-review pass (finding 6) to pin persistence plus the independence of
// these legacy setters from the tag-86 split.
// =============================================================================

#[test]
fn v16_wrapper_update_backing_fee_policy_no_longer_enforces_the_two_rate_floor() {
    // RETIRED (2026-07-19 fee-collection design): this replaces
    // `..._fee_split_floor_enforced_at_wizard_default_t20` and
    // `..._fee_split_floor_low_t_vacuity_shrinks_to_proven_residual`, both of
    // which pinned `fee_split_floor_ok` enforcement in this handler. That
    // check validated a split of `T = trade_fee_base_bps + backing_fee_bps`
    // that no longer exists and is superseded by `validate_fee_split`.
    //
    // Inverted and kept as the regression guard: the two splits the old
    // handler rejected at T=20 (0% insurance and 0% LP) must now be ACCEPTED
    // and persist. Re-introducing the floor here fails this test.
    let mut admin = signer();
    let mut market = market_account();
    init_market(&mut admin, &mut market);

    // 0% insurance at T=20 -- formerly rejected against the 15% floor.
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 20,
            insurance_share_bps: 0,
        },
        &mut [&mut admin, &mut market],
    )
    .expect("0% insurance at T=20 must no longer be rejected");
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg.backing_trade_fee_bps_short, 20,
        "the accepted split must actually persist"
    );
    assert_eq!(
        cfg.backing_trade_fee_policy_count, 1,
        "and must be counted as a configured policy"
    );

    // 0% LP (isb=10_000) at T=20 -- formerly rejected against the 40% floor.
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 20,
            insurance_share_bps: 10_000,
        },
        &mut [&mut admin, &mut market],
    )
    .expect("0% LP at T=20 must no longer be rejected");
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.backing_trade_fee_insurance_share_bps_short, 10_000);

    // The SURVIVING shape checks are untouched: an out-of-range fee and the
    // `fee_bps == 0 && insurance_share_bps != 0` guard must still reject.
    let before = market.data.clone();
    let result = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 10_001,
            insurance_share_bps: 5_000,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(result, &market, &before);

    let before = market.data.clone();
    let result = run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 1,
            fee_bps: 0,
            insurance_share_bps: 5_000,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(result, &market, &before);
}

#[test]
fn v16_wrapper_legacy_fee_policy_setters_persist_and_leave_the_tag86_split_untouched() {
    // REWRITTEN (branch review finding 6). This was
    // `v16_wrapper_fee_split_floor_accepts_valid_wizard_splits_via_real_handlers`,
    // whose stated purpose was that "the T-scaled tolerance must never
    // false-reject a genuine wizard output". That claim is now UNFALSIFIABLE:
    // the tolerance it referred to lived in `fee_split_floor_ok`, which both
    // setters stopped calling in `2b3a6a65`. The only surviving range gate is
    // `MAX_DYNAMIC_TRADE_FEE_BPS == 10_000`, and every input below (4, 5, 16,
    // 2_500, 2_727) is trivially inside it, so no code path could reject them.
    // A test whose headline assertion cannot fail is worse than no test: it
    // reads as coverage of the floors while covering nothing.
    //
    // Kept rather than deleted, because two REAL properties are worth pinning
    // here and one of them was never asserted before:
    //
    //   1. PERSISTENCE — the accepted values must actually reach the account,
    //      not be validated and silently dropped.
    //
    //   2. INDEPENDENCE (new) — these legacy two-rate setters must NOT touch
    //      the live tag-86 split (`creator_share_bps` / `lp_share_bps` /
    //      `insurance_share_bps`). Those are now two unrelated mechanisms that
    //      merely share the word "fee split", and the whole retirement rests on
    //      them being decoupled. If anyone re-couples them — e.g. makes
    //      `UpdateTradeFeePolicy` recompute the shares — that would silently
    //      bypass `validate_fee_split`'s floors via a handler that no longer
    //      checks them. THIS is the regression the old test was gesturing at
    //      and never actually caught.
    //
    // The inputs are kept as the wizard's own outputs (its default and its
    // tightest simultaneous 45/40/15 boundary) so the fixture still documents
    // realistic client values.

    // The tag-86 defaults InitMarket hardcodes; nothing in this test may move
    // them. Cross-checked against `tag86_marketauth_sets_a_valid_non_default_
    // split_and_it_persists` in tests/v16_fee_split.rs.
    const DEFAULT_SPLIT: (u16, u16, u16) = (1600, 4800, 1600);
    fn split_of(market: &TestAccount) -> (u16, u16, u16) {
        let (cfg, _) = state::read_market(&market.data).unwrap();
        (
            cfg.creator_share_bps,
            cfg.lp_share_bps,
            cfg.insurance_share_bps,
        )
    }

    // Wizard default: T=20bps, creatorPct=20/lpPct=60/insurancePct=20 ->
    // trade_fee_base_bps=4, backing_fee_bps=16, insurance_share_bps=2_500.
    {
        let mut admin = signer();
        let mut market = market_account();
        init_market(&mut admin, &mut market);
        run_ix(
            Instruction::UpdateTradeFeePolicy { trade_fee_base_bps: 4 },
            &mut [&mut admin, &mut market],
        )
        .unwrap();
        run_ix(
            Instruction::UpdateBackingFeePolicy {
                domain: 1,
                fee_bps: 16,
                insurance_share_bps: 2_500,
            },
            &mut [&mut admin, &mut market],
        )
        .expect("wizard default 20/60/20 split must be accepted");
        let (cfg, _) = state::read_market(&market.data).unwrap();
        // (1) PERSISTENCE.
        assert_eq!(cfg.trade_fee_base_bps, 4);
        assert_eq!(cfg.backing_trade_fee_bps_short, 16);
        assert_eq!(cfg.backing_trade_fee_insurance_share_bps_short, 2_500);
        // (2) INDEPENDENCE — neither setter may disturb the tag-86 split.
        assert_eq!(
            split_of(&market),
            DEFAULT_SPLIT,
            "the legacy two-rate setters must not write the tag-86 fee split; \
             that split is owned solely by UpdateFeeSplit (86), which is the \
             only handler that runs validate_fee_split's floors"
        );
    }

    // Wizard's tightest simultaneous boundary: creatorPct=45/lpPct=40/
    // insurancePct=15 at T=10bps -> trade_fee_base_bps=5 (ideal 4.5, rounds
    // up), backing_fee_bps=5, insurance_share_bps=2_727 (ideal 2727.27).
    // The resulting on-chain split is ACTUALLY 50% creator / 36.365% LP /
    // 13.635% insurance -- all three floors technically violated by
    // rounding alone, yet this is exactly what the wizard's own UI produces
    // for a legitimate boundary input, so it must be accepted.
    {
        let mut admin = signer();
        let mut market = market_account();
        init_market(&mut admin, &mut market);
        run_ix(
            Instruction::UpdateTradeFeePolicy { trade_fee_base_bps: 5 },
            &mut [&mut admin, &mut market],
        )
        .unwrap();
        run_ix(
            Instruction::UpdateBackingFeePolicy {
                domain: 1,
                fee_bps: 5,
                insurance_share_bps: 2_727,
            },
            &mut [&mut admin, &mut market],
        )
        .expect("wizard's own 45/40/15 boundary split at T=10 must be accepted");
        let (cfg, _) = state::read_market(&market.data).unwrap();
        // (1) PERSISTENCE.
        assert_eq!(cfg.trade_fee_base_bps, 5);
        assert_eq!(cfg.backing_trade_fee_bps_short, 5);
        assert_eq!(cfg.backing_trade_fee_insurance_share_bps_short, 2_727);
        // (2) INDEPENDENCE. This case matters most: as the retired comment
        // noted, 5/5/2_727 lands at 50% creator / 36.365% LP / 13.635%
        // insurance — all three OLD floors violated by rounding alone. If a
        // future change ever propagated these two-rate values into the tag-86
        // shares, it would install a split that `validate_fee_split` would
        // reject outright, through a handler that never calls it.
        assert_eq!(
            split_of(&market),
            DEFAULT_SPLIT,
            "a two-rate split that violates every retired floor must still \
             leave the live tag-86 split at its defaults"
        );
    }
}

#[test]
fn v16_wrapper_update_trade_fee_policy_no_longer_enforces_the_two_rate_floor() {
    // RETIRED (2026-07-19 fee-collection design): this used to be
    // `..._fee_split_floor_update_trade_fee_policy_checks_every_asset_not_just_asset0`,
    // pinning the W11 multi-asset floor scan. `fee_split_floor_ok` validated
    // a split of `T = trade_fee_base_bps + backing_fee_bps` that no longer
    // exists; `validate_fee_split` (tag 86) now owns split validation. The
    // scan is gone, so the W11 bypass it guarded is moot.
    //
    // This test is kept, inverted, as the regression guard for that removal:
    // the EXACT input the old handler rejected (creator% at double the 45%
    // cap) must now be ACCEPTED and must actually persist. Re-introducing
    // any floor check in this handler fails here.
    let mut admin = signer();
    let mut market = market_account_with_capacity(2);
    init_market(&mut admin, &mut market);

    update_asset_lifecycle(
        &mut admin,
        &mut market,
        processor::ASSET_ACTION_ACTIVATE,
        1,
        1,
        150,
    )
    .unwrap();

    // Asset 1 LONG domain: bf=1000bps, isb=2000bps.
    run_ix(
        Instruction::UpdateBackingFeePolicy {
            domain: 2,
            fee_bps: 1_000,
            insurance_share_bps: 2_000,
        },
        &mut [&mut admin, &mut market],
    )
    .expect("a well-shaped backing-fee split must still be accepted");

    // tfb=9000 against asset 1's untouched bf=1000 gives T=10000 and
    // creator%=90% -- double the old 45% cap, and decisively outside any
    // rounding boundary. The old handler rejected this; it must now succeed.
    run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 9_000,
        },
        &mut [&mut admin, &mut market],
    )
    .expect("the two-rate floor is retired: this must no longer be rejected");
    let (cfg_after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg_after.trade_fee_base_bps, 9_000,
        "the accepted value must actually persist, not be silently dropped"
    );

    // The SURVIVING shape check is untouched: MAX_DYNAMIC_TRADE_FEE_BPS /
    // max_trading_fee_bps still reject an out-of-range rate. Retiring the
    // floor must not have opened the range gate.
    let before = market.data.clone();
    let result = run_ix(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 10_001,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(result, &market, &before);
}

// =============================================================================
// LP-SENIORITY PIN — this test enforces a DELIBERATE DECISION, not a bug fix.
//
// LP and staker fee claims are JUNIOR to bad-debt / socialized-loss coverage.
// An LP-claim reservation at the `credit_account_from_insurance_not_atomic`
// call sites was implemented (`d2f697fc`, Finding 2) and then deliberately
// REVERTED (`9a6502ae`) for three stated reasons: the drain it defended against
// is arithmetically unreachable (a maintenance crank is `engine_available`-
// neutral), it made LP fees SENIOR to loss coverage, and it reverted the whole
// `SyncMaintenanceFee` on exactly the distressed markets that most need
// cranking.
//
// Nothing enforced that. `9a6502ae` deleted
// `v16_wrapper_maintenance_cranker_reward_reserves_outstanding_lp_fee_claim`
// (which pinned the reservation) and added no replacement, so re-adding the
// reservation would have passed the entire suite. This test is the missing
// counterweight: it is the SAME fixture, INVERTED, and it fails the moment
// anyone reintroduces the reservation.
//
// IF THIS TEST FAILS, do not "fix" it by making the claim senior. Read
// `9a6502ae` first — reversing this is a product decision about who eats
// losses, not a test bug.
// =============================================================================

#[test]
fn v16_wrapper_lp_fee_claim_is_junior_to_bad_debt_coverage() {
    let mut admin = signer();
    let mut market = market_account();
    let mut payer_owner = signer();
    let mut cranker_owner = signer();
    let mut payer = portfolio_account();
    let mut cranker = portfolio_account();
    init_market_with_ix(
        &mut admin,
        &mut market,
        init_market_ix_with(|ix| {
            if let Instruction::InitMarket {
                maintenance_fee_per_slot,
                ..
            } = ix
            {
                *maintenance_fee_per_slot = 5;
            }
        }),
    );
    init_portfolio(&mut payer_owner, &mut market, &mut payer);
    init_portfolio(&mut cranker_owner, &mut market, &mut cranker);
    deposit(&mut payer_owner, &mut market, &mut payer, 100);
    run_ix(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        &mut [&mut admin, &mut market],
    )
    .unwrap();

    // Seed an outstanding LP fee claim. Direct write is the accepted boundary
    // here (the production producer is `split_trade_fee`'s LP leg at the two
    // trade-fee sites, which needs a full trading env).
    //
    // 100 is chosen so the claim CANNOT be satisfied from what remains: the
    // crank leaves only 30 in insurance. If the LP claim were reserved, the
    // engine's reserved-floor check would refuse the reward and the whole
    // instruction would revert with EngineLockActive (Custom 21) — which is
    // precisely what the reverted `d2f697fc` asserted here.
    const LP_CLAIM: u128 = 100;
    {
        let (mut cfg, group) = state::read_market(&market.data).unwrap();
        assert_eq!(group.insurance, 0, "no insurance before the first crank");
        assert_eq!(
            group.insurance_domain_budget_remaining_total, 0,
            "no budgeted insurance either -- the ONLY thing that could reserve \
             anything here is `additional_reserved`, so this test cannot pass \
             for the wrong reason"
        );
        cfg.lp_fee_accrued_atoms = LP_CLAIM;
        cfg.lp_fee_withdrawn_atoms = 0;
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    // THE JUNIOR PROPERTY: the draw must SUCCEED despite the outstanding claim.
    run_ix(
        Instruction::SyncMaintenanceFee { now_slot: 10 },
        &mut [&mut market, &mut payer, &mut cranker, &mut cranker_owner],
    )
    .expect(
        "an outstanding LP fee claim must NOT block a draw against insurance -- \
         LP yield is at-risk junior backing capital, not a senior claim. If this \
         now fails with Custom(21) EngineLockActive, the reservation reverted in \
         9a6502ae has been reintroduced at a \
         credit_account_from_insurance_not_atomic call site.",
    );

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    let payer_after = state::read_portfolio(&payer.data).unwrap();
    let cranker_after = state::read_portfolio(&cranker.data).unwrap();

    // The draw actually happened and paid out.
    assert_eq!(payer_after.capital, 50, "charged 5/slot * 10 slots");
    assert_eq!(cranker_after.capital, 20, "cranker takes 40% of the 50 charged");

    // AND the claimable surplus is now BELOW the outstanding claim. This is the
    // seniority statement itself: the claim was not protected, and what backs it
    // was reduced. A senior claim would have been reserved out of this.
    assert_eq!(
        group_after.insurance, 30,
        "the retained 30 stays in insurance (budgeted to asset 0's domains)"
    );
    let still_owed = cfg_after
        .lp_fee_accrued_atoms
        .saturating_sub(cfg_after.lp_fee_withdrawn_atoms);
    assert_eq!(
        still_owed, LP_CLAIM,
        "the claim itself is untouched -- it is not written down, it is simply \
         not senior"
    );
    assert!(
        group_after.insurance < still_owed,
        "JUNIOR: insurance ({}) must be allowed to fall below the outstanding LP \
         claim ({}). If these were kept in lockstep the claim would be senior.",
        group_after.insurance,
        still_owed,
    );
}

/// END-TO-END WRAPPER VERIFICATION of the LP-drain engine fix.
///
/// Every earlier test of this fix drove the ENGINE LIBRARY directly. This one goes
/// through the real wrapper instruction handlers — InitMarket / InitPortfolio /
/// Deposit / TradeCpi (with the matcher CPI) / PushAuthMark / PermissionlessCrank —
/// i.e. exactly the path the deployed program executes.
///
/// Scenario: an LP holds the matcher counterparty side while the price churns and
/// returns EXACTLY to where it started, and the keeper cranks the LP on every step
/// (production behaviour). A zero-net price path must cost the LP nothing.
/// Pre-fix this bled one full leg of value per direction change.
#[test]
fn v17_wrapper_lp_survives_zero_net_price_churn_end_to_end() {
    let mut admin = signer();
    let mut market = market_account();
    let mut owner_a = signer(); // trader
    let mut owner_b = signer(); // LP / matcher counterparty
    let mut account_a = portfolio_account();
    let mut account_b = portfolio_account();

    // Wide accrual window so a multi-slot churn step is never rejected for staleness.
    // NOTE: config validation rejects min_funding_lifetime_slots < max_accrual_dt_slots,
    // so both must be raised together.
    init_market(&mut admin, &mut market);
    init_portfolio(&mut owner_a, &mut market, &mut account_a);
    init_portfolio(&mut owner_b, &mut market, &mut account_b);
    deposit(&mut owner_a, &mut market, &mut account_a, 5_000_000);
    deposit(&mut owner_b, &mut market, &mut account_b, 5_000_000);

    // Drive price through the AUTH_MARK oracle so PushAuthMark actually moves the mark.
    configure_base_auth_mark(&mut admin, &mut market, 1, 100);

    // Open: trader (A) long, LP (B) short — B is the matcher-enabled counterparty.
    let size_q = POS_SCALE as i128 * 10;
    run_trade_cpi_with_matcher(
        &mut owner_a,
        &mut owner_b,
        &mut market,
        &mut account_a,
        &mut account_b,
        0,
        size_q,
        size_q,
        100,
        0,
        0,
    )
    .unwrap();

    let lp_before = state::read_portfolio(&account_b.data).unwrap();
    let equity_before = lp_before.capital as i128 + lp_before.pnl;
    assert!(
        lp_before.legs.iter().any(|l| l.active),
        "VACUOUS: the LP has no open position, nothing is being settled"
    );
    let pos_before = lp_before
        .legs
        .iter()
        .find(|l| l.active)
        .map(|l| l.basis_pos_q)
        .unwrap();

    // Churn: 100_000 -> 104_000 -> 100_000, twenty times. Net move is EXACTLY zero.
    // Crank the LP on every step, which is what the keeper does in production.
    let mut slot = 10u64;
    let (mut cranks_ok, mut cranks_err) = (0u32, 0u32);
    let mut price_moves = 0u32;
    for cycle in 0..20 {
        for mark in [104u64, 100u64] {
            slot += 10;
            push_base_auth_mark(&mut admin, &mut market, slot, mark);
            price_moves += 1;
            let crank = run_ix(
                Instruction::PermissionlessCrank {
                    action: 0, // Refresh
                    asset_index: 0,
                    now_slot: slot,
                    funding_rate_e9: 0,
                    recovery_reason: 0,
                },
                &mut [&mut owner_b, &mut market, &mut account_b],
            );
            match crank {
                Ok(()) => cranks_ok += 1,
                Err(_) => cranks_err += 1,
            }
            let _ = cycle;
        }
    }
    // Settle the one-step lag: a Refresh settles against the CURRENT k and only THEN
    // accrues, so one extra crank at the unchanged final mark realizes the last delta.
    for _ in 0..2 {
        slot += 10;
        push_base_auth_mark(&mut admin, &mut market, slot, 100);
        let _ = run_ix(
            Instruction::PermissionlessCrank {
                action: 0,
                asset_index: 0,
                now_slot: slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
            &mut [&mut owner_b, &mut market, &mut account_b],
        );
    }

    let lp_after = state::read_portfolio(&account_b.data).unwrap();
    let equity_after = lp_after.capital as i128 + lp_after.pnl;
    let (_, group) = state::read_market(&market.data).unwrap();

    println!(
        "WRAPPER e2e: cranks ok={} err={} price_moves={} | final mark={} \
         | LP capital {} -> {} pnl {} -> {} | equity {} -> {} (delta {})",
        cranks_ok,
        cranks_err,
        price_moves,
        group.assets[0].effective_price,
        lp_before.capital,
        lp_after.capital,
        lp_before.pnl,
        lp_after.pnl,
        equity_before,
        equity_after,
        equity_after - equity_before
    );

    // NON-VACUITY: the scenario must actually have run through the wrapper.
    assert!(cranks_ok >= 30, "VACUOUS: only {cranks_ok} cranks landed");
    assert_eq!(
        group.assets[0].effective_price, 100,
        "price did not return to its starting point — not a zero-net path"
    );
    let pos_after = lp_after
        .legs
        .iter()
        .find(|l| l.active)
        .map(|l| l.basis_pos_q)
        .expect("LP position vanished");
    assert_eq!(pos_after, pos_before, "position changed — baseline invalid");

    // PROPERTY: a zero-net price path must cost the LP nothing.
    assert!(
        (equity_after - equity_before).abs() <= 2,
        "LP moved {} atoms on a ZERO-NET price path through the wrapper (drain regression)",
        equity_after - equity_before
    );
}

/// Issue #428 — `UpdateMaintenanceFeePerSlot` (tag 88) has no MarketMode gate.
///
/// Its sibling `handle_update_backing_fee_policy` rejects with `EngineLockActive`
/// when `mode != Live`. This handler checks only `expect_live_authority(&cfg.marketauth)`,
/// so the rate can be changed after the market has left Live — and a permissionless
/// crank then charges it.
#[test]
fn v16_wrapper_update_maintenance_fee_per_slot_is_live_only() {
    let mut admin = signer().writable();
    let mut market = market_account();
    let _mint = init_market(&mut admin, &mut market);

    // Live: the rate change is legitimate.
    run_ix(
        Instruction::UpdateMaintenanceFeePerSlot {
            maintenance_fee_per_slot: 7,
        },
        &mut [&mut admin, &mut market],
    )
    .expect("rate change must be allowed while Live");

    run_ix(Instruction::ResolveMarket, &mut [&mut admin, &mut market]).unwrap();
    let resolved = market.data.clone();

    // Not Live: the rate change must be refused, and the market left untouched.
    let after_resolve = run_ix(
        Instruction::UpdateMaintenanceFeePerSlot {
            maintenance_fee_per_slot: 999_999,
        },
        &mut [&mut admin, &mut market],
    );
    assert_err_and_market_unchanged(after_resolve, &market, &resolved);
}

/// Issues #416 / #417 — `asset_admin` bypasses current-holder consent on the
/// insurance authority fields.
///
/// `handle_update_asset_authority` skips `expect_live_authority(&current_value, ..)`
/// whenever `admin_signed`, and #424's custody guard is scoped to
/// `ASSET_AUTH_BACKING_BUCKET` only. So an `asset_admin` can take
/// `insurance_authority` (#417) or `insurance_operator` (#416) away from their
/// current holder without that holder ever signing.
#[test]
fn v16_wrapper_asset_admin_cannot_seize_insurance_authority_from_holder() {
    let mut admin = signer().writable();
    let mut market = market_account();
    let mut holder = signer();
    let mut attacker = signer();
    let _mint = init_market(&mut admin, &mut market);

    // Legitimately hand insurance_authority to `holder` (holder co-signs).
    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: holder.key.to_bytes(),
        },
        &mut [&mut admin, &mut holder, &mut market],
    )
    .expect("holder-consented rotation must succeed");

    let held = market.data.clone();

    // asset_admin now tries to take it away. `holder` does NOT sign.
    let seized = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE,
            new_pubkey: attacker.key.to_bytes(),
        },
        &mut [&mut admin, &mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(seized, &market, &held);
}

/// Companion to the above for `insurance_operator` (#416) — the leg that reaches
/// stake-governed insurance through `handle_withdraw_insurance_asset`'s
/// `local_authorized` branch, which the D-STAKE-1 guard does not cover.
#[test]
fn v16_wrapper_asset_admin_cannot_seize_insurance_operator_from_holder() {
    let mut admin = signer().writable();
    let mut market = market_account();
    let mut holder = signer();
    let mut attacker = signer();
    let _mint = init_market(&mut admin, &mut market);

    run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: holder.key.to_bytes(),
        },
        &mut [&mut admin, &mut holder, &mut market],
    )
    .expect("holder-consented rotation must succeed");

    let held = market.data.clone();

    let seized = run_ix(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: ASSET_AUTH_INSURANCE_OPERATOR,
            new_pubkey: attacker.key.to_bytes(),
        },
        &mut [&mut admin, &mut attacker, &mut market],
    );
    assert_err_and_market_unchanged(seized, &market, &held);
}

// ════════════════════════════════════════════════════════════════════════════
// #427 — the insurance-withdrawal rate limit was STRUCTURALLY UNSETTABLE.
//
// `check_insurance_withdraw_cooldown` and `apply_insurance_withdraw_ceiling` are
// correct and are directly unit-tested above. That was never the problem. The
// problem was that both short-circuit on zero, and zero was the ONLY value any
// market could ever hold: the two policy fields were written in exactly one place
// each — `: 0,` in the `handle_init_market` config literal. So #385, #386 and #396
// were closed by adding enforcement that no deployed market could reach.
//
// These tests are about REACHABILITY, not about the helpers' arithmetic. A green
// unit test on a function nothing can invoke is the exact shape of vacuity this
// repo keeps finding.
// ════════════════════════════════════════════════════════════════════════════

/// The core #427 proof: the policy can now hold a non-zero value at all.
#[test]
fn v16_wrapper_insurance_withdraw_policy_is_settable() {
    let mut admin = signer();
    let mut market = market_account();
    let _mint = init_market(&mut admin, &mut market);

    let (before, _) = state::read_market(&market.data).unwrap();
    assert_eq!(before.insurance_withdraw_cooldown_slots, 0, "init writes zero");
    assert_eq!(before.insurance_withdraw_deposits_only, 0, "init writes zero");

    run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 1, cooldown_slots: 100 },
        &mut [&mut admin, &mut market],
    )
    .expect("#427: marketauth must be able to set the insurance-withdrawal policy");

    let (after, _) = state::read_market(&market.data).unwrap();
    assert_eq!(after.insurance_withdraw_cooldown_slots, 100);
    assert_eq!(after.insurance_withdraw_deposits_only, 1);

    // Zero must stay legal — it is how a market turns the limit back OFF. Refusing it
    // would make the policy one-way, which is a different defect in the same family.
    run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 0, cooldown_slots: 0 },
        &mut [&mut admin, &mut market],
    )
    .expect("clearing the policy must remain possible");
    let (cleared, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cleared.insurance_withdraw_cooldown_slots, 0);
}

/// A setter for a DURATION must carry a cap, or closing #427 just opens #440's shape.
#[test]
fn v16_wrapper_insurance_withdraw_cooldown_is_bounded() {
    let mut admin = signer();
    let mut market = market_account();
    let _mint = init_market(&mut admin, &mut market);

    let max = percolator_prog::constants::MAX_INSURANCE_WITHDRAW_COOLDOWN_SLOTS;
    run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 0, cooldown_slots: max },
        &mut [&mut admin, &mut market],
    )
    .expect("the cap itself must be accepted (boundary inclusive)");

    let over = run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 0, cooldown_slots: max + 1 },
        &mut [&mut admin, &mut market],
    );
    assert!(over.is_err(), "cooldown above the cap must be rejected");

    let forever = run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 0, cooldown_slots: u64::MAX },
        &mut [&mut admin, &mut market],
    );
    assert!(forever.is_err(), "u64::MAX would freeze insurance withdrawals permanently");
}

#[test]
fn v16_wrapper_insurance_withdraw_policy_requires_marketauth() {
    let mut admin = signer();
    let mut attacker = signer();
    let mut market = market_account();
    let _mint = init_market(&mut admin, &mut market);

    let seized = run_ix(
        Instruction::UpdateInsuranceWithdrawPolicy { deposits_only: 1, cooldown_slots: 10 },
        &mut [&mut attacker, &mut market],
    );
    assert!(seized.is_err(), "a non-marketauth signer must not set the withdrawal policy");
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.insurance_withdraw_cooldown_slots, 0, "state must be unchanged");
}

// REACHABILITY PROOF: NOT HERE. `handle_withdraw_insurance` /
// `handle_withdraw_insurance_asset` call `Clock::get()` for the cooldown check, and this
// harness has no Clock sysvar — every withdrawal returns `UnsupportedSysvar`, which is why
// the whole `v16_wrapper_*insurance*withdraw*` family already sits in KNOWN_FAILING.
//
// A first draft of the end-to-end test lived here and "failed" for that reason. Its CONTROL
// failed identically, which is the only thing that revealed the harness was the cause rather
// than the policy — without the control it would have looked like proof the gate fires.
//
// The proof lives in `tests/v16_cu.rs`, which runs LiteSVM with a real clock.

// ════════════════════════════════════════════════════════════════════════════
// #410 — `ConfigurePermissionlessResolve` had no lower bound above zero.
//
// The old validation rejected only `stale_slots == 0`, so `1` was accepted. At that
// setting the permissionless-resolve valve fires on a SINGLE missed oracle refresh
// instead of a dead feed, and resolution is one-way. The README describes this timer as
// the user-exit path for when an oracle STOPS WORKING.
//
// Upstream carries the identical missing bound, so there was nothing to port.
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn v16_wrapper_permissionless_resolve_stale_slots_has_a_lower_bound() {
    let min = percolator_prog::constants::MIN_PERMISSIONLESS_RESOLVE_STALE_SLOTS;
    let max = percolator_prog::constants::MAX_PERMISSIONLESS_RESOLVE_STALE_SLOTS;

    // The hair trigger the issue reports, and the value just under the floor.
    for bad in [1u64, 2, min - 1] {
        let mut admin = signer();
        let mut market = market_account();
        let _mint = init_market(&mut admin, &mut market);
        let r = run_ix(
            Instruction::ConfigurePermissionlessResolve {
                stale_slots: bad,
                force_close_delay_slots: 1,
            },
            &mut [&mut admin, &mut market],
        );
        assert!(
            r.is_err(),
            "#410 — stale_slots={bad} was accepted; a single missed oracle refresh can then \
             permanently resolve the market, and resolution is one-way"
        );
        let (cfg, _) = state::read_market(&market.data).unwrap();
        assert_eq!(cfg.permissionless_resolve_stale_slots, 0, "state must be unchanged");
    }

    // PROOF OF LIFE: both boundaries are inclusive and the instruction still works. Without
    // this the rejections above would also pass if the handler simply refused everything.
    for good in [min, min + 1, max] {
        let mut admin = signer();
        let mut market = market_account();
        let _mint = init_market(&mut admin, &mut market);
        run_ix(
            Instruction::ConfigurePermissionlessResolve {
                stale_slots: good,
                force_close_delay_slots: 1,
            },
            &mut [&mut admin, &mut market],
        )
        .unwrap_or_else(|e| panic!("stale_slots={good} must be accepted: {e:?}"));
        let (cfg, _) = state::read_market(&market.data).unwrap();
        assert_eq!(cfg.permissionless_resolve_stale_slots, good);
    }

    // The upper bound still holds — widening the floor must not have widened the ceiling.
    let mut admin = signer();
    let mut market = market_account();
    let _mint = init_market(&mut admin, &mut market);
    let over = run_ix(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: max + 1,
            force_close_delay_slots: 1,
        },
        &mut [&mut admin, &mut market],
    );
    assert!(over.is_err(), "stale_slots above MAX must still be rejected");
}

fn mint_account_with_decimals(decimals: u8) -> TestAccount {
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    TestAccount::new_with_data(Pubkey::new_unique(), spl_token::ID, data)
}

/// #447 — the primary and secondary collateral mints are both denominated in engine
/// base units, so mismatched decimals silently rescale every secondary-mint deposit
/// and withdrawal. Upstream rejects it; our port dropped the check by calling
/// `verify_mint`, which unpacks the mint and discards it.
#[test]
fn v16_wrapper_update_base_unit_mints_rejects_mismatched_decimals() {
    let mut admin = signer();
    let mut market = market_account();
    init_market_with_ix(&mut admin, &mut market, init_market_ix_with(|_| {}));

    let mut primary = mint_account_with_decimals(6);
    let mut mismatched = mint_account_with_decimals(9);
    let rejected = run_ix(
        Instruction::UpdateBaseUnitMints {
            primary_mint: primary.key.to_bytes(),
            secondary_mint: mismatched.key.to_bytes(),
        },
        &mut [&mut admin, &mut market, &mut primary, &mut mismatched],
    );
    assert!(
        rejected.is_err(),
        "#447: mints with different decimals must be rejected"
    );

    let mut matched = mint_account_with_decimals(6);
    let accepted = run_ix(
        Instruction::UpdateBaseUnitMints {
            primary_mint: primary.key.to_bytes(),
            secondary_mint: matched.key.to_bytes(),
        },
        &mut [&mut admin, &mut market, &mut primary, &mut matched],
    );
    assert!(
        accepted.is_ok(),
        "matching decimals must still be accepted: {accepted:?}"
    );
}

/// #446 — upstream gates `RebalanceReduce` on maturity: once a Live market has
/// matured into a permissionless resolve, an owner-signed reduce must not still
/// mutate positions. Our port bound `_cfg` and dropped the two-line gate; the same
/// gate guards the sibling path at `reject_permissionless_resolve_matured_live_view`.
#[test]
fn v16_wrapper_rebalance_reduce_is_blocked_once_resolve_has_matured() {
    let mut admin = signer();
    let mut market = market_account();
    let mut long_owner = signer();
    let mut short_owner = signer();
    let mut long_account = portfolio_account();
    let mut short_account = portfolio_account();

    init_market_with_ix(&mut admin, &mut market, init_market_ix_with(|_| {}));
    init_portfolio(&mut long_owner, &mut market, &mut long_account);
    init_portfolio(&mut short_owner, &mut market, &mut short_account);
    deposit(&mut long_owner, &mut market, &mut long_account, 10_000_000);
    deposit(&mut short_owner, &mut market, &mut short_account, 10_000_000);
    run_ix(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            exec_price: 100,
            fee_bps: 0,
        },
        &mut [
            &mut long_owner,
            &mut short_owner,
            &mut market,
            &mut long_account,
            &mut short_account,
        ],
    )
    .unwrap();

    // Drive the market into a MATURED permissionless resolve while still mode 0 (Live).
    {
        let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
        cfg.permissionless_resolve_stale_slots = 9_000;
        cfg.last_good_oracle_slot = 0;
        group.current_slot = 20_000;
        assert_eq!(group.mode, MarketModeV16::Live, "must still be Live for this gate");
        state::write_market(&mut market.data, &cfg, &group).unwrap();
    }

    let before = market.data.clone();
    let blocked = run_ix(
        Instruction::RebalanceReduce {
            asset_index: 0,
            reduce_q: POS_SCALE / 2,
        },
        &mut [&mut long_owner, &mut market, &mut long_account],
    );
    assert!(
        blocked.is_err(),
        "#446: rebalance-reduce must be blocked once the resolve has matured"
    );
    assert_eq!(
        market.data, before,
        "#446: a blocked reduce must not mutate market state"
    );
}
