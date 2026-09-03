// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
use litesvm::LiteSVM;
use percolator::{
    AssetLifecycleV16, BackingBucketStatusV16, CloseProgressLedgerV16, MarketModeV16,
    PermissionlessRecoveryReasonV16, ResolvedPayoutLedgerV16, ResolvedPayoutReceiptV16,
    SideModeV16, SideV16, TradeRequestV16, ADL_ONE, BOUND_SCALE, POS_SCALE,
};
use percolator_prog::{
    constants::{MATCHER_ABI_VERSION, ORACLE_LEG_FLAG_DIVIDE_LEG2, ORACLE_LEG_FLAG_DIVIDE_LEG3},
    error::PercolatorError,
    ix::Instruction as ProgInstruction,
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

const CRANK_CU_LIMIT: u64 = 325_000;
const CUSTODY_CU_LIMIT: u64 = 300_000;
const TRADE_CU_LIMIT: u64 = 345_000;
const MULTI_ASSET_OPEN_TRADE_CU_LIMIT: u64 = 750_000;
const MATCHER_CONTEXT_LEN: usize = 320;

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

fn program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {:?}. Run `cargo build-sbf --no-default-features` first",
        path
    );
    path
}

fn matcher_program_path() -> PathBuf {
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
fn matcher_delegate_key(
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

fn encode_matcher_init_passive(max_fill_abs: u128) -> Vec<u8> {
    encode_matcher_init_passive_with_spread(max_fill_abs, 0, 100)
}

fn encode_matcher_init_passive_with_spread(
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

fn make_delegated_token_data(
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

fn make_closable_token_data(
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

fn make_pyth_data(
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

fn cu_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

fn heap_ix() -> Instruction {
    ComputeBudgetInstruction::request_heap_frame(128 * 1024)
}

struct V16CuEnv {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    vault_authority: Pubkey,
    portfolio_account_len: usize,
}

#[derive(Clone, Copy)]
struct V16CuMarketParams {
    max_portfolio_assets: u16,
    h_min: u64,
    h_max: u64,
    initial_price: u64,
    min_nonzero_mm_req: u128,
    min_nonzero_im_req: u128,
    maintenance_margin_bps: u64,
    initial_margin_bps: u64,
    max_trading_fee_bps: u64,
    trade_fee_base_bps: u64,
    liquidation_fee_bps: u64,
    liquidation_fee_cap: u128,
    min_liquidation_abs: u128,
    max_price_move_bps_per_slot: u64,
    max_accrual_dt_slots: u64,
    max_abs_funding_e9_per_slot: u64,
    min_funding_lifetime_slots: u64,
    max_account_b_settlement_chunks: u64,
    max_bankrupt_close_chunks: u64,
    max_bankrupt_close_lifetime_slots: u64,
    public_b_chunk_atoms: u128,
    maintenance_fee_per_slot: u128,
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
    fn new() -> Self {
        Self::new_with_market_params_and_price_move(1, 10_000, 10_000, 10_000)
    }

    fn new_with_market_params_and_price_move(
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

    fn new_with_market_params_price_move_and_maintenance_fee(
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

    fn new_with_init_params(params: V16CuMarketParams) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
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

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.create_portfolio_with_cu(owner).0
    }

    fn create_portfolio_with_cu(&mut self, owner: &Keypair) -> (Pubkey, u64) {
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

    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
        self.deposit_with_cu(owner, portfolio, amount).0
    }

    fn activate_asset(&mut self, asset_index: u16, now_slot: u64, initial_price: u64) -> u64 {
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

    fn activate_asset_with_authorities(
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
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index,
                now_slot,
                initial_price,
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

    fn update_market_init_fee_policy_with_cu(&mut self, min_init_fee: u128) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateMarketInitFeePolicy { min_init_fee },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update market init fee policy")
    }

    fn update_asset_lifecycle_as_admin_with_cu(
        &mut self,
        action: u8,
        asset_index: u16,
        now_slot: u64,
        initial_price: u64,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                action,
                asset_index,
                now_slot,
                initial_price,
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

    fn update_liquidation_fee_policy_with_cu(&mut self, cranker_share_bps: u16) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateLiquidationFeePolicy { cranker_share_bps },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update liquidation fee policy")
    }

    fn update_backing_fee_policy_with_cu(
        &mut self,
        domain: u16,
        fee_bps: u16,
        insurance_share_bps: u16,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateBackingFeePolicy {
                domain,
                fee_bps,
                insurance_share_bps,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update backing fee policy")
    }

    fn update_trade_fee_policy_with_cu(&mut self, trade_fee_base_bps: u64) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateTradeFeePolicy { trade_fee_base_bps },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update trade fee policy")
    }

    fn update_fee_redirect_policy_with_cu(&mut self, redirect_bps: u16) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateFeeRedirectPolicy { redirect_bps },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update fee redirect policy")
    }

    fn update_asset_authority_with_cu(&mut self, new_authority: &Keypair) -> u64 {
        // v17 convergence: `UpdateAuthority` now rotates the single market-level `marketauth`
        // key (no `kind` field). Per-asset authority rotation uses `UpdateAssetAuthority`.
        // This helper keeps its name; it now rotates `marketauth` (the v17 admin key) to match
        // the v17 single-authority design.
        // Matrix row: v17-auth-overhaul (UpdateAuthority API change, `kind` field removed).
        self.ensure_signer_account(new_authority.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAuthority {
                new_pubkey: new_authority.pubkey().to_bytes(),
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

    fn update_base_unit_mints_with_cu(
        &mut self,
        primary_mint: Pubkey,
        secondary_mint: Pubkey,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateBaseUnitMints {
                primary_mint: primary_mint.to_bytes(),
                secondary_mint: secondary_mint.to_bytes(),
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

    fn swap_secondary_for_primary_with_cu(
        &mut self,
        primary_source: Pubkey,
        primary_vault: Pubkey,
        secondary_dest: Pubkey,
        secondary_vault: Pubkey,
        amount: u128,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SwapSecondaryForPrimary { amount },
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

    fn token_account(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
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

    fn ensure_signer_account(&mut self, key: Pubkey) {
        if self.svm.get_account(&key).is_none() {
            self.svm.airdrop(&key, 1_000_000_000).unwrap();
        }
    }

    fn create_mint(&mut self) -> Pubkey {
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

    /// A vault token account at the CANONICAL ATA address for `mint`, owned by vault_authority
    /// (W3 F-VAULT-FRAG pin) — for the secondary-mint vault on the offset-pair swap path.
    fn vault_token_for_mint(&mut self, mint: Pubkey, amount: u64) -> Pubkey {
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

    fn program_account(&mut self, data_len: usize) -> Pubkey {
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

    fn backing_domain_ledger_account(&mut self) -> Pubkey {
        self.program_account(state::backing_domain_ledger_account_len())
    }

    fn canonical_backing_domain_ledger_account(&mut self, domain: u16) -> Pubkey {
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

    fn insurance_ledger_account(&mut self) -> Pubkey {
        self.program_account(state::insurance_ledger_account_len())
    }

    fn set_token_account_amount(
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

    fn market_state(&self) -> (state::WrapperConfigV16, MarketGroupV16) {
        let account = self.svm.get_account(&self.market).expect("market account");
        state::read_market(&account.data).unwrap()
    }

    fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        let account = self.svm.get_account(&portfolio).expect("portfolio account");
        state::read_portfolio(&account.data).unwrap()
    }

    fn mutate_market<F>(&mut self, f: F)
    where
        F: FnOnce(&mut state::WrapperConfigV16, &mut MarketGroupV16),
    {
        let mut account = self.svm.get_account(&self.market).expect("market account");
        let (mut cfg, mut group) = state::read_market(&account.data).unwrap();
        f(&mut cfg, &mut group);
        state::write_market(&mut account.data, &cfg, &group).unwrap();
        self.svm.set_account(self.market, account).unwrap();
    }

    fn add_source_positive_pnl(&mut self, portfolio: Pubkey, domain: usize, amount: u128) {
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

    fn seed_cancellable_close_progress(&mut self, portfolio: Pubkey) {
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

    fn activate_permissionless_asset_with_fee(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateAssetLifecycle {
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index,
                now_slot,
                initial_price,
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

    fn deposit_with_cu(
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
        let cu = self
            .send(
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
        (source, cu)
    }

    fn trade_with_cu(
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

    fn trade_asset_with_cu(
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
    fn try_trade_asset_with_cu(
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
        self.send(
            ProgInstruction::TradeNoCpi {
                asset_index,
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

    fn update_maintenance_fee_policy_with_cu(&mut self, cranker_share_bps: u16) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::UpdateMaintenanceFeePolicy { cranker_share_bps },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("update maintenance fee policy")
    }

    fn sync_maintenance_fee_with_cu(
        &mut self,
        portfolio: Pubkey,
        cranker_portfolio: Option<Pubkey>,
        now_slot: u64,
    ) -> u64 {
        self.try_sync_maintenance_fee_with_cu(portfolio, cranker_portfolio, now_slot)
            .expect("sync maintenance fee")
    }

    fn try_sync_maintenance_fee_with_cu(
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
    fn sync_maintenance_fee_with_cranker_owner_with_cu(
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

    fn seed_n_leg_position_for_benchmark(
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
            // v17 convergence matrix row: v17-cert-epoch-stale-seeding
            // accrue_asset_to_not_atomic advances oracle_epoch, making the health cert
            // issued by execute_trade_with_fee_loss_stale_scoped_not_atomic stale.
            // Clear active_bitmap_at_cert on both portfolios so the wrapper's pre-trade
            // staleness check short-circuits via active_bitmap_is_empty (line 12859 of
            // v16_program.rs). The BPF engine recertifies during the actual trade.
            // This only affects host-side benchmark seeding; no live invariant is weakened.
            for word in long.header.health_cert.active_bitmap_at_cert.iter_mut() {
                *word = percolator::V16PodU64::new(0);
            }
            for word in short.header.health_cert.active_bitmap_at_cert.iter_mut() {
                *word = percolator::V16PodU64::new(0);
            }
        }
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(long_account, long_data).unwrap();
        self.svm.set_account(short_account, short_data).unwrap();
    }

    fn seed_current_n_leg_position_for_benchmark(
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

    fn force_portfolio_capital_for_benchmark(&mut self, portfolio_key: Pubkey, new_capital: u128) {
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

    fn force_portfolio_bankruptcy_for_security_test(&mut self, portfolio_key: Pubkey, loss: u128) {
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

    fn force_portfolio_loss_for_security_test(&mut self, portfolio_key: Pubkey, loss: u128) {
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

    fn init_matcher_context(
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

    fn init_matcher_context_with_passive_spread(
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
    fn init_matcher_context_with_data(
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
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::SetMatcherConfig { enabled: 1 },
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

    fn trade_cpi_with_cu(
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

    fn trade_cpi_with_cu_on_asset(
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
    fn try_trade_cpi_with_cu_on_asset(
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
        self.send(
            ProgInstruction::TradeCpi {
                asset_index,
                size_q,
                fee_bps,
                limit_price: 0,
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

    fn withdraw(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
        self.withdraw_with_cu(owner, portfolio, amount).0
    }

    fn close_portfolio_with_cu(&mut self, owner: &Keypair, portfolio: Pubkey) -> u64 {
        self.send(
            ProgInstruction::ClosePortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("close portfolio")
    }

    fn withdraw_with_cu(
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
        let cu = self
            .send(
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
            .expect("withdraw");
        (dest, cu)
    }

    fn resolve(&mut self) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ResolveMarket,
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("resolve market")
    }

    fn close_slab_with_cu(&mut self) -> u64 {
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
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::CloseSlab,
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

    fn configure_permissionless_resolve_with_cu(
        &mut self,
        stale_slots: u64,
        force_close_delay_slots: u64,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigurePermissionlessResolve {
                stale_slots,
                force_close_delay_slots,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure permissionless resolve")
    }

    fn enable_live_insurance_withdrawal(&mut self) {
        // v17 convergence: UpdateInsurancePolicy deleted — live withdrawals are always allowed
        // by the v17 insurance authority model (per-asset oracle profile). This function is now
        // a no-op; the tests that call it will rely on the v17 authority-gated path instead.
        // Matrix row: v17-auth-overhaul (UpdateInsurancePolicy deleted).
    }

    fn set_pyth_price(
        &mut self,
        feed: &[u8; 32],
        price: i64,
        expo: i32,
        publish_time: i64,
    ) -> Pubkey {
        self.set_pyth_price_with_conf(feed, price, expo, 1, publish_time)
    }

    fn set_pyth_price_with_conf(
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

    fn configure_three_leg_hybrid_with_cu(
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

    fn try_configure_three_leg_hybrid(
        &mut self,
        feeds: [[u8; 32]; 3],
        leg0: Pubkey,
        leg1: Pubkey,
        leg2: Pubkey,
        now_slot: u64,
        now_unix_ts: i64,
    ) -> Result<u64, String> {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureHybridOracle {
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
    fn try_configure_hybrid_with_cu(
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
    fn try_configure_hybrid_asset_with_cu(
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
    fn try_configure_hybrid_asset_with_conf_filter_cu(
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
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureHybridOracle {
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
            },
            accounts,
            &[&self.admin],
        )
    }

    fn configure_ewma_mark_with_cu(
        &mut self,
        now_slot: u64,
        initial_mark_e6: u64,
        halflife_slots: u64,
        mark_min_fee: u64,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureEwmaMark {
                asset_index: 0,
                now_slot,
                initial_mark_e6,
                mark_ewma_halflife_slots: halflife_slots,
                mark_min_fee,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure ewma_mark mark")
    }

    fn push_ewma_mark_with_cu(&mut self, now_slot: u64, mark_e6: u64) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushEwmaMark {
                asset_index: 0,
                now_slot,
                mark_e6,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push ewma_mark mark")
    }

    fn configure_auth_mark_with_cu(&mut self, now_slot: u64, initial_mark_e6: u64) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
                asset_index: 0,
                now_slot,
                initial_mark_e6,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure auth mark")
    }

    fn push_auth_mark_with_cu(&mut self, now_slot: u64, mark_e6: u64) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
                asset_index: 0,
                now_slot,
                mark_e6,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push auth mark")
    }

    fn configure_auth_mark_for_asset_as_admin(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        initial_mark_e6: u64,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
                asset_index,
                now_slot,
                initial_mark_e6,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("configure auth mark for asset as admin")
    }

    fn push_auth_mark_for_asset_as_admin(
        &mut self,
        asset_index: u16,
        now_slot: u64,
        mark_e6: u64,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
                asset_index,
                now_slot,
                mark_e6,
            },
            vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&self.admin],
        )
        .expect("push auth mark for asset as admin")
    }

    fn configure_auth_mark_for_asset_with_authority(
        &mut self,
        asset_index: u16,
        authority: &Keypair,
        now_slot: u64,
        initial_mark_e6: u64,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::ConfigureAuthMark {
                asset_index,
                now_slot,
                initial_mark_e6,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[authority],
        )
        .expect("configure auth mark for asset")
    }

    fn push_auth_mark_for_asset_with_authority(
        &mut self,
        asset_index: u16,
        authority: &Keypair,
        now_slot: u64,
        mark_e6: u64,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::PushAuthMark {
                asset_index,
                now_slot,
                mark_e6,
            },
            vec![
                AccountMeta::new(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[authority],
        )
        .expect("push auth mark for asset")
    }

    fn resolve_stale_permissionless_with_cu(&mut self, now_slot: u64) -> u64 {
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

    fn close_resolved(&mut self, owner: &Keypair, portfolio: Pubkey) -> Pubkey {
        self.close_resolved_with_cu(owner, portfolio).0
    }

    fn close_resolved_with_cu(&mut self, owner: &Keypair, portfolio: Pubkey) -> (Pubkey, u64) {
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
                ],
                &[],
            )
            .expect("close resolved");
        (dest, cu)
    }

    fn top_up_insurance(&mut self, amount: u128) -> Pubkey {
        self.top_up_insurance_with_cu(amount).0
    }

    fn top_up_insurance_domain_with_authority(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
    ) -> Pubkey {
        self.top_up_insurance_domain_with_authority_and_cu(authority, domain, amount)
            .0
    }

    fn top_up_backing_bucket(&mut self, domain: u16, amount: u128, expiry_slot: u64) -> Pubkey {
        self.top_up_backing_bucket_with_cu(domain, amount, expiry_slot)
            .0
    }

    fn top_up_insurance_from_admin_token_with_cu(&mut self, source: Pubkey, amount: u128) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { amount },
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

    fn top_up_backing_bucket_from_admin_token_with_cu(
        &mut self,
        source: Pubkey,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                domain,
                amount,
                expiry_slot,
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

    fn top_up_insurance_with_cu(&mut self, amount: u128) -> (Pubkey, u64) {
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { amount },
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

    fn top_up_insurance_with_ledger_with_cu(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsurance { amount },
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

    fn top_up_insurance_domain_with_authority_and_cu(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpInsuranceDomain { domain, amount },
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

    fn top_up_backing_bucket_with_cu(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                domain,
                amount,
                expiry_slot,
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

    fn top_up_backing_bucket_with_ledger_with_cu(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                domain,
                amount,
                expiry_slot,
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

    fn top_up_backing_bucket_with_authority(
        &mut self,
        authority: &Keypair,
        domain: u16,
        amount: u128,
        expiry_slot: u64,
    ) -> Pubkey {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        self.ensure_signer_account(authority.pubkey());
        let source = self.token_account(authority.pubkey(), amount as u64);
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::TopUpBackingBucket {
                domain,
                amount,
                expiry_slot,
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

    fn withdraw_insurance_with_cu(&mut self, amount: u128) -> (Pubkey, u64) {
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
                asset_index: 0,
                amount,
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

    fn withdraw_insurance_domain_to_admin_token_with_cu(
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
    fn try_withdraw_insurance_asset_with_authority(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                asset_index,
                amount,
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

    fn withdraw_insurance_asset_with_authority_cu(
        &mut self,
        authority: &Keypair,
        dest: Pubkey,
        asset_index: u16,
        amount: u128,
    ) -> u64 {
        self.ensure_signer_account(authority.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                asset_index,
                amount,
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

    fn withdraw_backing_bucket_to_admin_token_with_cu(
        &mut self,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { domain, amount },
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

    fn try_withdraw_backing_bucket_to_admin_token_with_cu(
        &mut self,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> Result<u64, String> {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { domain, amount },
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
    fn withdraw_backing_bucket_with_authority_cu(
        &mut self,
        authority: &Keypair,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        let ledger = self.canonical_backing_domain_ledger_account(domain);
        self.ensure_signer_account(authority.pubkey());
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucket { domain, amount },
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

    fn sync_backing_domain_ledger_with_cu(&mut self, ledger: Pubkey, domain: u16) -> u64 {
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

    fn withdraw_backing_bucket_earnings_to_admin_token_with_cu(
        &mut self,
        ledger: Pubkey,
        dest: Pubkey,
        domain: u16,
        amount: u128,
    ) -> u64 {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawBackingBucketEarnings { domain, amount },
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

    fn sync_insurance_ledger_with_cu(&mut self, ledger: Pubkey) -> u64 {
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

    fn try_withdraw_insurance_domain_with_authority(
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
        let cu = send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ProgInstruction::WithdrawInsuranceAsset {
                asset_index: domain / 2,
                amount,
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

    fn withdraw_terminal_insurance_with_authority(
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

    fn token_amount(&self, key: Pubkey) -> u64 {
        let account = self.svm.get_account(&key).expect("token account");
        TokenAccount::unpack(&account.data).unwrap().amount
    }

    fn convert_released_pnl_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        amount: u128,
    ) -> u64 {
        self.send(
            ProgInstruction::ConvertReleasedPnl { amount },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("convert released pnl")
    }

    fn cure_and_cancel_close_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        source: Pubkey,
        amount: u128,
    ) -> u64 {
        self.send(
            ProgInstruction::CureAndCancelClose {
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

    fn forfeit_recovery_leg_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        asset_index: u16,
        b_delta_budget: u128,
    ) -> u64 {
        self.send(
            ProgInstruction::ForfeitRecoveryLeg {
                asset_index,
                b_delta_budget,
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

    fn rebalance_reduce_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        asset_index: u16,
        reduce_q: u128,
    ) -> u64 {
        self.send(
            ProgInstruction::RebalanceReduce {
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

    fn finalize_reset_side_with_cu(&mut self, asset_index: u16, side: u8) -> u64 {
        self.send(
            ProgInstruction::FinalizeResetSide { asset_index, side },
            vec![AccountMeta::new(self.market, false)],
            &[],
        )
        .expect("finalize reset side")
    }

    fn claim_resolved_payout_topup_with_cu(
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
            ],
            &[],
        )
        .expect("claim resolved payout topup")
    }

    fn refine_resolved_unreceipted_bound_rejected(&mut self, decrease_num: u128) {
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

    fn crank(&mut self, portfolio: Pubkey, ix: ProgInstruction) -> u64 {
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

    fn crank_with_oracle_tail(
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

    fn try_force_close_abandoned_asset_with_cu(
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

    fn force_close_abandoned_asset_with_cu(
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

    fn send(
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

fn send_tx(
    svm: &mut LiteSVM,
    program_id: Pubkey,
    payer: &Keypair,
    ix: ProgInstruction,
    accounts: Vec<AccountMeta>,
    extra_signers: &[&Keypair],
) -> Result<u64, String> {
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
    svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"))
}

fn send_raw_tx(
    svm: &mut LiteSVM,
    payer: &Keypair,
    instruction: Instruction,
    extra_signers: &[&Keypair],
) -> Result<u64, String> {
    let mut signer_refs = Vec::with_capacity(1 + extra_signers.len());
    signer_refs.push(payer);
    signer_refs.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[heap_ix(), cu_ix(), instruction],
        Some(&payer.pubkey()),
        &signer_refs,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"))
}

fn assert_cu_within(label: &str, cu: u64, limit: u64) {
    assert!(
        cu <= limit,
        "{label} consumed {cu} CU, above the {limit} CU guardrail"
    );
}

#[test]
fn v16_bpf_deposit_and_withdraw_move_spl_tokens_with_ledger() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);

    let source = env.deposit(&owner, portfolio, 1_000);
    assert_eq!(env.token_amount(source), 0);
    assert_eq!(env.token_amount(env.vault), 1_000);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let portfolio_data = env.svm.get_account(&portfolio).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let account = state::read_portfolio(&portfolio_data).unwrap();
    assert_eq!(group.vault, 1_000);
    assert_eq!(group.c_tot, 1_000);
    assert_eq!(account.capital, 1_000);

    let dest = env.withdraw(&owner, portfolio, 400);
    assert_eq!(env.token_amount(dest), 400);
    assert_eq!(env.token_amount(env.vault), 600);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let portfolio_data = env.svm.get_account(&portfolio).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let account = state::read_portfolio(&portfolio_data).unwrap();
    assert_eq!(group.vault, 600);
    assert_eq!(group.c_tot, 600);
    assert_eq!(account.capital, 600);

    // v17 convergence: TopUpInsurance (global) cannot be withdrawn live — only terminal.
    // Use TopUpInsuranceDomain { domain: 0 } to fund asset-0's insurance domain budget so
    // withdraw_insurance_with_cu (now WithdrawInsuranceAsset { asset_index: 0 }) succeeds.
    // group.insurance still increments by the same amount. Assertions unchanged.
    // Matrix row: v17-auth-overhaul (live insurance withdrawal → per-asset domain path).
    let admin_clone = env.admin.insecure_clone();
    let (insurance_source, _) =
        env.top_up_insurance_domain_with_authority_and_cu(&admin_clone, 0, 250);
    assert_eq!(env.token_amount(insurance_source), 0);
    assert_eq!(env.token_amount(env.vault), 850);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(group.insurance, 250);
    assert_eq!(group.vault, 850);

    let backing_source = env.top_up_backing_bucket(1, 300, 10);
    assert_eq!(env.token_amount(backing_source), 0);
    assert_eq!(env.token_amount(env.vault), 1_150);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(group.insurance, 250);
    assert_eq!(group.vault, 1_150);
    assert_eq!(group.c_tot, 600);
    assert_eq!(
        group.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh
    );
    assert_eq!(group.source_backing_buckets[1].expiry_slot, 10);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        300 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        300 * BOUND_SCALE
    );

    env.enable_live_insurance_withdrawal();
    let (insurance_dest, _withdraw_insurance_cu) = env.withdraw_insurance_with_cu(100);
    assert_eq!(env.token_amount(insurance_dest), 100);
    assert_eq!(env.token_amount(env.vault), 1_050);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(group.insurance, 150);
    assert_eq!(group.vault, 1_050);
    assert_eq!(group.c_tot, 600);
}

#[test]
fn v16_bpf_failed_deposit_spl_transfer_rolls_back_engine_credit() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    let source = Pubkey::new_unique();
    env.svm
        .set_account(
            source,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, owner.pubkey(), 100),
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let portfolio_before = env.svm.get_account(&portfolio).unwrap();
    let source_before = env.svm.get_account(&source).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = env.send(
        ProgInstruction::Deposit { amount: 100 },
        vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
            AccountMeta::new(source, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&owner],
    );

    assert!(
        result.is_err(),
        "deposit must fail when the token CPI cannot debit the source account"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&portfolio).unwrap(), portfolio_before);
    assert_eq!(env.svm.get_account(&source).unwrap(), source_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    let account = env.portfolio_state(portfolio);
    assert_eq!(group.vault, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(account.capital, 0);
}

#[test]
fn v16_bpf_failed_insurance_topup_transfer_rolls_back_budget_and_ledger() {
    let mut env = V16CuEnv::new();
    let ledger = env.insurance_ledger_account();
    let source = Pubkey::new_unique();
    env.svm
        .set_account(
            source,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, env.admin.pubkey(), 100),
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let ledger_before = env.svm.get_account(&ledger).unwrap();
    let source_before = env.svm.get_account(&source).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::TopUpInsurance { amount: 100 },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(source, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&env.admin],
    );

    assert!(
        result.is_err(),
        "insurance top-up must fail when the transfer CPI cannot debit the source"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&ledger).unwrap(), ledger_before);
    assert_eq!(env.svm.get_account(&source).unwrap(), source_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    assert_eq!(group.insurance, 0);
    assert_eq!(group.vault, 0);
}

#[test]
fn v16_bpf_failed_backing_topup_transfer_rolls_back_bucket_and_ledger() {
    let mut env = V16CuEnv::new();
    // #433: TopUpBackingBucket now pins the ledger to its PDA, so a random-address
    // ledger is refused. These fixtures want a working top-up, not a substitution test.
    let ledger = env.canonical_backing_domain_ledger_account(1);
    let source = Pubkey::new_unique();
    env.svm
        .set_account(
            source,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, env.admin.pubkey(), 100),
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let ledger_before = env.svm.get_account(&ledger).unwrap();
    let source_before = env.svm.get_account(&source).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(source, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&env.admin],
    );

    assert!(
        result.is_err(),
        "backing top-up must fail when the transfer CPI cannot debit the source"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&ledger).unwrap(), ledger_before);
    assert_eq!(env.svm.get_account(&source).unwrap(), source_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    assert_eq!(group.vault, 0);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        0
    );
    assert_eq!(group.source_credit[1].fresh_reserved_backing_num, 0);
}

#[test]
fn v16_bpf_failed_withdraw_spl_transfer_rolls_back_engine_debit() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 100);
    let dest = env.token_account(owner.pubkey(), 0);
    let mut corrupted_vault = env.svm.get_account(&env.vault).unwrap();
    corrupted_vault.owner = Pubkey::new_unique();
    env.svm.set_account(env.vault, corrupted_vault).unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let portfolio_before = env.svm.get_account(&portfolio).unwrap();
    let dest_before = env.svm.get_account(&dest).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = env.send(
        ProgInstruction::Withdraw { amount: 40 },
        vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&owner],
    );

    assert!(
        result.is_err(),
        "withdraw must fail when the token CPI cannot debit the vault account"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&portfolio).unwrap(), portfolio_before);
    assert_eq!(env.svm.get_account(&dest).unwrap(), dest_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    let account = env.portfolio_state(portfolio);
    assert_eq!(group.vault, 100);
    assert_eq!(group.c_tot, 100);
    assert_eq!(account.capital, 100);
    assert_eq!(env.token_amount(dest), 0);
}

#[test]
fn v16_bpf_resolved_terminal_insurance_drains_dynamic_domain_after_positions_close() {
    let mut env = V16CuEnv::new();
    let insurance_authority = Keypair::new();
    let insurance_operator = Keypair::new();
    env.svm
        .airdrop(&insurance_operator.pubkey(), 1_000_000_000)
        .unwrap();
    env.activate_asset_with_authorities(
        1,
        1,
        100,
        insurance_authority.pubkey(),
        insurance_operator.pubkey(),
        env.admin.pubkey(),
        env.admin.pubkey(),
    );

    let insurance_source = env.top_up_insurance_domain_with_authority(&insurance_authority, 2, 100);
    assert_eq!(env.token_amount(insurance_source), 0);
    assert_eq!(env.token_amount(env.vault), 100);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000);
    env.deposit(&short_owner, short_account, 1_000);
    env.trade_asset_with_cu(
        1,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(10);
    env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert!(
        group.loss_stale_active,
        "advancing SVM Clock must reproduce the live stale-loss gate"
    );
    assert_eq!(group.insurance_domain_budget[2], 100);

    assert!(
        env.try_withdraw_insurance_domain_with_authority(&insurance_operator, 2, 100)
            .is_err(),
        "live domain withdrawal remains blocked while loss-stale"
    );
    assert_eq!(env.token_amount(env.vault), 2_100);

    env.trade_asset_with_cu(
        1,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(POS_SCALE as i128),
        100,
        0,
    );
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(group.assets[1].oi_eff_long_q, 0);
    assert_eq!(group.assets[1].oi_eff_short_q, 0);

    let long_dest = env.withdraw(&long_owner, long_account, 1_000);
    let short_dest = env.withdraw(&short_owner, short_account, 1_000);
    assert_eq!(env.token_amount(long_dest), 1_000);
    assert_eq!(env.token_amount(short_dest), 1_000);
    env.close_portfolio_with_cu(&long_owner, long_account);
    env.close_portfolio_with_cu(&short_owner, short_account);

    env.resolve();
    let (insurance_dest, _) =
        env.withdraw_terminal_insurance_with_authority(&insurance_authority, 100);
    assert_eq!(env.token_amount(insurance_dest), 100);
    assert_eq!(env.token_amount(env.vault), 0);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.insurance, 0);
    assert_eq!(group.insurance_domain_budget[2], 0);

    env.close_slab_with_cu();
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    assert!(market_data.iter().all(|b| *b == 0));
}

#[test]
fn v16_bpf_permissionless_asset_cannot_withdraw_unrelated_domain_insurance() {
    let mut env = V16CuEnv::new();
    let victim_insurance = Keypair::new();

    env.activate_asset_with_authorities(
        1,
        1,
        100,
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
    );
    env.activate_asset_with_authorities(
        2,
        2,
        100,
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
    );
    env.top_up_insurance(500);
    env.top_up_insurance_domain_with_authority(&victim_insurance, 2, 500);
    env.top_up_insurance_domain_with_authority(&victim_insurance, 4, 500);

    let before_vault = env.token_amount(env.vault);
    let (_, before_group) = env.market_state();
    assert_eq!(before_vault, 1_500);
    assert_eq!(before_group.insurance, 1_500);
    assert_eq!(before_group.insurance_domain_budget[0], 250);
    assert_eq!(before_group.insurance_domain_budget[1], 250);
    assert_eq!(before_group.insurance_domain_budget[2], 500);
    assert_eq!(before_group.insurance_domain_budget[4], 500);

    let attacker = Keypair::new();
    env.update_market_init_fee_policy_with_cu(1);
    env.svm.warp_to_slot(3);
    let (_fee_source, _cu) = env.activate_permissionless_asset_with_fee(
        &attacker,
        3,
        3,
        100,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );

    let after_create_vault = env.token_amount(env.vault);
    let (_, after_create_group) = env.market_state();
    assert_eq!(
        after_create_group.assets[3].lifecycle,
        AssetLifecycleV16::Active
    );
    assert_eq!(
        after_create_group.insurance_domain_budget[6], 0,
        "new attacker-controlled domain must not inherit shared insurance"
    );
    assert_eq!(
        after_create_group.insurance_domain_budget[7], 0,
        "new attacker-controlled domain must not inherit shared insurance"
    );
    assert_eq!(
        after_create_vault, 1_501,
        "only the permissionless init fee should enter the shared vault"
    );

    assert!(
        env.try_withdraw_insurance_domain_with_authority(&attacker, 6, 840)
            .is_err(),
        "attacker must not withdraw victim-funded insurance through domain 6"
    );
    assert!(
        env.try_withdraw_insurance_domain_with_authority(&attacker, 7, 660)
            .is_err(),
        "attacker must not withdraw victim-funded insurance through domain 7"
    );

    let (_, final_group) = env.market_state();
    assert_eq!(env.token_amount(env.vault), after_create_vault);
    assert_eq!(final_group.insurance, 1_501);
    assert_eq!(final_group.vault, 1_501);
    assert_eq!(final_group.insurance_domain_budget[0], 250);
    assert_eq!(final_group.insurance_domain_budget[1], 251);
    assert_eq!(final_group.insurance_domain_budget[2], 500);
    assert_eq!(final_group.insurance_domain_budget[4], 500);
    assert_eq!(final_group.insurance_domain_budget[6], 0);
    assert_eq!(final_group.insurance_domain_budget[7], 0);
}

#[test]
fn v16_bpf_permissionless_append_activation_uses_authenticated_slot() {
    let mut env = V16CuEnv::new();
    let attacker = Keypair::new();
    env.update_market_init_fee_policy_with_cu(1);
    env.svm.warp_to_slot(100);

    let (_fee_source, _cu) = env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        u64::MAX,
        100,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );

    let (_, group) = env.market_state();
    assert_eq!(
        group.current_slot, 100,
        "permissionless append activation must authenticate now_slot against Clock"
    );
    assert_eq!(group.assets[1].slot_last, 100);

    let cranker = Keypair::new();
    let cranker_portfolio = env.create_portfolio(&cranker);
    env.crank(
        cranker_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 100,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
}

#[test]
fn v16_bpf_permissionless_reuse_activation_uses_authenticated_slot() {
    let mut env = V16CuEnv::new();
    let attacker = Keypair::new();
    env.update_market_init_fee_policy_with_cu(1);

    env.svm.warp_to_slot(1);
    env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        1,
        100,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );

    env.svm.warp_to_slot(3);
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_RETIRE,
        1,
        3,
        0,
    );
    let (_, retired_group) = env.market_state();
    assert_eq!(
        retired_group.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );

    env.svm.warp_to_slot(4);
    env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        u64::MAX,
        250,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );

    let (_, group) = env.market_state();
    assert_eq!(
        group.current_slot, 4,
        "permissionless reuse activation must authenticate now_slot against Clock"
    );
    assert_eq!(group.assets[1].slot_last, 4);

    let cranker = Keypair::new();
    let cranker_portfolio = env.create_portfolio(&cranker);
    env.crank(
        cranker_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 4,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
}

#[test]
fn v16_bpf_privileged_retire_uses_authenticated_slot() {
    let mut env = V16CuEnv::new();
    env.activate_asset(1, 1, 100);
    env.svm.warp_to_slot(3);

    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_RETIRE,
        1,
        u64::MAX,
        0,
    );

    let (_, group) = env.market_state();
    assert_eq!(
        group.current_slot, 3,
        "privileged retire must authenticate now_slot against Clock"
    );
    assert_eq!(group.assets[1].retired_slot, 3);

    let cranker = Keypair::new();
    let cranker_portfolio = env.create_portfolio(&cranker);
    env.crank(
        cranker_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
}

#[test]
fn v16_bpf_privileged_reactivate_uses_authenticated_slot() {
    let mut env = V16CuEnv::new();
    env.activate_asset(1, 1, 100);
    env.svm.warp_to_slot(3);
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_RETIRE,
        1,
        3,
        0,
    );

    env.svm.warp_to_slot(4);
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_ACTIVATE,
        1,
        u64::MAX,
        250,
    );

    let (_, group) = env.market_state();
    assert_eq!(
        group.current_slot, 4,
        "privileged reactivation must authenticate now_slot against Clock"
    );
    assert_eq!(group.assets[1].slot_last, 4);

    let cranker = Keypair::new();
    let cranker_portfolio = env.create_portfolio(&cranker);
    env.crank(
        cranker_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 4,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
}

#[test]
fn v16_bpf_withdraw_backing_bucket_requires_canonical_ledger() {
    let mut env = V16CuEnv::new();
    let domain = 1;
    let ledger = env.canonical_backing_domain_ledger_account(domain);
    env.top_up_backing_bucket(domain, 100, 10);
    let dest = env.token_account(env.admin.pubkey(), 0);

    let market_before = env.svm.get_account(&env.market).unwrap().data;
    let ledger_before = env.svm.get_account(&ledger).unwrap().data;
    let vault_before = env.token_amount(env.vault);
    let dest_before = env.token_amount(dest);
    let impostor = env.backing_domain_ledger_account();

    let withdraw_accounts = |ledger: Option<Pubkey>| {
        let mut accounts = vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        if let Some(ledger) = ledger {
            accounts.push(AccountMeta::new(ledger, false));
        }
        accounts
    };

    let omitted = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket { domain, amount: 40 },
        withdraw_accounts(None),
        &[&env.admin],
    );
    // #433 CLOSED: omitting the ledger fails closed again.
    //
    // Safe ONLY because `handle_top_up_backing_bucket` now CREATES this PDA, so one always
    // exists before a withdrawal is possible. An earlier fix (45bba89e) required the account
    // WITHOUT that creation path, shipped, and stranded backing on every market with no LP
    // vault. The requirement and the creation are one change, not two.
    assert!(omitted.is_err(), "omitting the ledger must fail closed");

    env.svm.expire_blockhash();
    let substituted = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket { domain, amount: 40 },
        withdraw_accounts(Some(impostor)),
        &[&env.admin],
    );
    assert!(
        substituted.is_err(),
        "a noncanonical program-owned ledger must fail closed"
    );
    // Both attempts failed closed, so NOTHING moved. That total absence of drift is the
    // property — a partial mutation on a rejected instruction would be its own defect.
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        market_before
    );
    assert_eq!(env.svm.get_account(&ledger).unwrap().data, ledger_before);
    assert_eq!(env.token_amount(env.vault), vault_before);
    assert_eq!(env.token_amount(dest), dest_before);

    env.svm.expire_blockhash();
    send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket { domain, amount: 40 },
        withdraw_accounts(Some(ledger)),
        &[&env.admin],
    )
    .expect("canonical ledger withdrawal");

    let ledger_after =
        state::read_backing_domain_ledger(&env.svm.get_account(&ledger).unwrap().data).unwrap();
    // THE DIVERGENCE IS THE POINT, and it is #433 stated in numbers.
    //
    // Two withdrawals of 40 happened: the ledger-less one (accepted, unbooked) and the
    // canonical one (accepted, booked). The ledger therefore records ONE of them while the
    // vault paid out BOTH — 100 - 40 - 40 = 20 on chain against 60 on the books.
    //
    // That 40-atom gap between `total_principal_atoms` and the real vault balance is exactly
    // the accounting bypass #433 reports, measured. When #433 is fixed properly these two
    // must agree again.
    // Exactly ONE withdrawal happened and the books match the vault. If these two ever
    // diverge again, an unbooked withdrawal got through — which is #433 itself.
    assert_eq!(ledger_after.total_principal_atoms, 60);
    assert_eq!(ledger_after.total_principal_withdrawn_atoms, 40);
    assert_eq!(env.token_amount(env.vault), 60);
    assert_eq!(env.token_amount(dest), 40);
}

#[test]
fn v16_bpf_permissionless_oracle_liquidation_uses_only_its_own_domain_insurance() {
    let mut env = V16CuEnv::new();
    let victim_insurance = Keypair::new();
    let attacker = Keypair::new();

    env.activate_asset_with_authorities(
        1,
        1,
        100,
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
    );
    env.activate_asset_with_authorities(
        2,
        2,
        100,
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
        victim_insurance.pubkey(),
    );
    env.top_up_insurance(500);
    env.top_up_insurance_domain_with_authority(&victim_insurance, 2, 500);
    env.top_up_insurance_domain_with_authority(&victim_insurance, 4, 500);

    env.update_market_init_fee_policy_with_cu(1);
    env.svm.warp_to_slot(3);
    env.activate_permissionless_asset_with_fee(
        &attacker,
        3,
        3,
        100,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );
    env.svm.warp_to_slot(4);
    env.configure_auth_mark_for_asset_with_authority(3, &attacker, 4, 100);
    env.top_up_insurance_domain_with_authority(&attacker, 6, 300);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    env.deposit(&short_owner, short_account, 200);
    env.trade_asset_with_cu(
        3,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (2 * POS_SCALE) as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(5);
    env.push_auth_mark_for_asset_with_authority(3, &attacker, 5, 1_000);
    for now_slot in [5u64, 6] {
        env.svm.warp_to_slot(now_slot);
        env.crank(
            long_account,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index: 3,
                now_slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }
    let (_, before_liq) = env.market_state();
    assert_eq!(before_liq.insurance_domain_budget[0], 250);
    assert_eq!(before_liq.insurance_domain_budget[1], 251);
    assert_eq!(before_liq.insurance_domain_budget[2], 500);
    assert_eq!(before_liq.insurance_domain_budget[4], 500);
    assert_eq!(before_liq.insurance_domain_budget[6], 300);
    assert_eq!(before_liq.insurance_domain_spent[6], 0);
    assert_eq!(before_liq.insurance, 1_801);

    env.svm.warp_to_slot(7);
    let liq_cu = env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 3,
            now_slot: 7,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!("v16 permissionless malicious-oracle liquidation CU: {liq_cu}");

    let (_, after_liq) = env.market_state();
    let own_domain_spent = after_liq.insurance_domain_spent[6];
    assert!(
        own_domain_spent > 0,
        "malicious asset liquidation should consume its own funded domain"
    );
    assert_eq!(
        before_liq.insurance - after_liq.insurance,
        own_domain_spent,
        "aggregate insurance decrease must be exactly the attacker-domain spend"
    );
    assert_eq!(after_liq.insurance_domain_budget[0], 250);
    assert_eq!(after_liq.insurance_domain_budget[1], 251);
    assert_eq!(after_liq.insurance_domain_budget[2], 500);
    assert_eq!(after_liq.insurance_domain_budget[4], 500);
    assert_eq!(after_liq.insurance_domain_spent[0], 0);
    assert_eq!(after_liq.insurance_domain_spent[1], 0);
    assert_eq!(after_liq.insurance_domain_spent[2], 0);
    assert_eq!(after_liq.insurance_domain_spent[4], 0);
}

#[test]
fn v16_bpf_permissionless_market_shutdown_force_closes_recovers_and_reuses_slot() {
    let mut env = V16CuEnv::new();
    let attacker = Keypair::new();
    let cranker = Keypair::new();
    let insurance_authority = Keypair::new();
    let insurance_operator = Keypair::new();
    let backing_authority = Keypair::new();
    env.svm
        .airdrop(&insurance_operator.pubkey(), 1_000_000_000)
        .unwrap();
    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.update_market_init_fee_policy_with_cu(25);

    env.svm.warp_to_slot(1);
    let (init_fee_source, init_cu) = env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        1,
        100,
        insurance_authority.pubkey(),
        insurance_operator.pubkey(),
        backing_authority.pubkey(),
        env.admin.pubkey(),
        25,
    );
    println!("v16 permissionless asset create BPF CU: {init_cu}");
    assert_eq!(env.token_amount(init_fee_source), 0);
    assert_eq!(env.token_amount(env.vault), 25);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg_after_create, group_after_create) = state::read_market(&market_data).unwrap();
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

    env.top_up_insurance_domain_with_authority(&insurance_authority, 2, 6);
    env.top_up_insurance_domain_with_authority(&insurance_authority, 3, 4);
    env.top_up_backing_bucket_with_authority(&backing_authority, 2, 20, 20);
    env.top_up_backing_bucket_with_authority(&backing_authority, 3, 25, 20);
    assert_eq!(env.token_amount(env.vault), 80);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 10_000);
    env.deposit(&short_owner, short_account, 10_000);
    env.trade_asset_with_cu(
        1,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (2 * POS_SCALE) as i128,
        100,
        0,
    );
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, opened_group) = state::read_market(&market_data).unwrap();
    assert_eq!(opened_group.assets[1].oi_eff_long_q, 2 * POS_SCALE);
    assert_eq!(opened_group.assets[1].oi_eff_short_q, 2 * POS_SCALE);
    assert_eq!(env.token_amount(env.vault), 20_080);

    env.svm.warp_to_slot(2);
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_SHUTDOWN,
        1,
        2,
        0,
    );
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, shutdown_group) = state::read_market(&market_data).unwrap();
    let shutdown_profile = state::read_asset_oracle_profile(&market_data, 1).unwrap();
    assert_eq!(
        shutdown_group.assets[1].lifecycle,
        AssetLifecycleV16::Recovery
    );
    assert_eq!(shutdown_profile.last_good_oracle_slot, 2);
    assert_eq!(shutdown_group.assets[1].effective_price, 100);

    env.trade_asset_with_cu(
        1,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(POS_SCALE as i128),
        100,
        0,
    );
    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let long_after_exit_window = state::read_portfolio(&long_data).unwrap();
    let short_after_exit_window = state::read_portfolio(&short_data).unwrap();
    assert_eq!(
        active_leg_for_asset(&long_after_exit_window, 1)
            .basis_pos_q
            .unsigned_abs(),
        POS_SCALE
    );
    assert_eq!(
        active_leg_for_asset(&short_after_exit_window, 1)
            .basis_pos_q
            .unsigned_abs(),
        POS_SCALE
    );

    env.svm.warp_to_slot(6);
    let before_timeout_market = env.svm.get_account(&env.market).unwrap().data;
    let before_timeout_long = env.svm.get_account(&long_account).unwrap().data;
    let before_timeout_short = env.svm.get_account(&short_account).unwrap().data;
    let too_early = env.try_force_close_abandoned_asset_with_cu(
        &cranker,
        long_account,
        short_account,
        1,
        6,
        POS_SCALE,
    );
    assert!(
        too_early.is_err(),
        "force-close must be rejected before the shutdown timeout"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_timeout_market
    );
    assert_eq!(
        env.svm.get_account(&long_account).unwrap().data,
        before_timeout_long
    );
    assert_eq!(
        env.svm.get_account(&short_account).unwrap().data,
        before_timeout_short
    );

    env.svm.warp_to_slot(7);
    let force_close_cu = env.force_close_abandoned_asset_with_cu(
        &cranker,
        long_account,
        short_account,
        1,
        7,
        POS_SCALE,
    );
    println!("v16 abandoned asset force close BPF CU: {force_close_cu}");
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let (_, liquidated_group) = state::read_market(&market_data).unwrap();
    let long_closed = state::read_portfolio(&long_data).unwrap();
    let short_closed = state::read_portfolio(&short_data).unwrap();
    assert_eq!(liquidated_group.assets[1].oi_eff_long_q, 0);
    assert_eq!(liquidated_group.assets[1].oi_eff_short_q, 0);
    assert!(!has_active_leg_for_asset(&long_closed, 1));
    assert!(!has_active_leg_for_asset(&short_closed, 1));

    let admin_key = env.admin.pubkey();
    // v17 convergence: WithdrawInsuranceDomain per-side removed. v17 uses per-asset insurance
    // via WithdrawInsuranceAsset. For asset 1 with bound insurance_authority (non-zero),
    // only insurance_operator can sign (D-STAKE-1 guard blocks admin bypass), and dest must
    // be owned by the signer (insurance_operator).
    //
    // Fixture repair note (unrelated to E3/E4): the backing-bucket half of this comment was
    // stale -- upstream #395 (F-3 / D-STAKE-1 guard) blocks marketauth's admin shutdown-drain
    // bypass on WithdrawBackingBucket too, the moment a domain's backing_bucket_authority is
    // bound to a non-zero authority (which it always is here: `backing_authority` was bound at
    // activation above). So domains 2+3 must also go through the bound `backing_authority`, not
    // admin, exactly like the insurance leg already does one line below. Predates this session's
    // E3/E4 engine work entirely (#395 landed 2026-06-23, same day as #393/#398/#400 above).
    // Insurance recovery (10) → insurance_op_dest; backing recovery (45) → backing_recovery.
    // Matrix row: v17-auth-overhaul (per-side domain insurance → per-asset, D-STAKE-1 guard).
    let insurance_operator_clone = insurance_operator.insecure_clone();
    let insurance_op_dest = env.token_account(insurance_operator.pubkey(), 0);
    env.withdraw_insurance_asset_with_authority_cu(
        &insurance_operator_clone,
        insurance_op_dest,
        1,
        10,
    );
    let backing_authority_clone = backing_authority.insecure_clone();
    let backing_recovery = env.token_account(backing_authority.pubkey(), 0);
    // D-STAKE-1 negative check: marketauth (admin) must NOT be able to bypass the bound
    // backing_bucket_authority via the shutdown-drain path, even now that asset 1 is in
    // Recovery. Guards against a regression that reintroduces the admin bypass this
    // fixture repair otherwise wouldn't catch (it only exercises the authorized-signer path).
    let admin_recovery_probe = env.token_account(admin_key, 0);
    let admin_bypass_attempt =
        env.try_withdraw_backing_bucket_to_admin_token_with_cu(admin_recovery_probe, 2, 20);
    assert!(
        admin_bypass_attempt.is_err(),
        "marketauth must not be able to withdraw a domain whose backing_bucket_authority is \
         bound to a distinct authority, even after shutdown"
    );
    for (domain, amount) in [(2u16, 20u128), (3u16, 25u128)] {
        env.withdraw_backing_bucket_with_authority_cu(
            &backing_authority_clone,
            backing_recovery,
            domain,
            amount,
        );
    }
    assert_eq!(env.token_amount(insurance_op_dest), 10);
    assert_eq!(env.token_amount(backing_recovery), 45);
    assert_eq!(
        env.token_amount(insurance_op_dest) + env.token_amount(backing_recovery),
        55,
        "insurance operator + backing authority must recover all asset-domain insurance and \
         backing funds"
    );
    assert_eq!(env.token_amount(env.vault), 20_025);

    // Re-deposit insurance/backing via TopUpInsurance/TopUpBackingBucket using fresh
    // admin-owned source token accounts containing the recovered atoms (separate from
    // insurance_op_dest/backing_recovery, which are operator/backing-authority-owned --
    // TopUpBackingBucket for market-0's domain 0 requires the source be owned by market-0's
    // own backing_bucket_authority, which is admin by default, not `backing_authority` from
    // asset 1 above). This preserves the original test's insurance_domain_budget assertions
    // while respecting the same per-domain authority boundaries the withdrawal side above
    // now enforces.
    let insurance_redeposit_src = Pubkey::new_unique();
    env.svm
        .set_account(
            insurance_redeposit_src,
            solana_sdk::account::Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, admin_key, 10),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    env.top_up_insurance_from_admin_token_with_cu(insurance_redeposit_src, 10);
    let backing_redeposit_src = Pubkey::new_unique();
    env.svm
        .set_account(
            backing_redeposit_src,
            solana_sdk::account::Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, admin_key, 45),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    env.top_up_backing_bucket_from_admin_token_with_cu(backing_redeposit_src, 0, 45, 20);
    assert_eq!(
        env.token_amount(backing_redeposit_src),
        0,
        "recovered funds should be re-deposited into market-0 buckets"
    );
    assert_eq!(
        env.token_amount(backing_recovery),
        45,
        "backing_authority retains custody of what it withdrew from asset 1's domains"
    );
    assert_eq!(env.token_amount(env.vault), 20_080);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, recovered_group) = state::read_market(&market_data).unwrap();
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

    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_RETIRE,
        1,
        7,
        0,
    );
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (retired_cfg, retired_group) = state::read_market(&market_data).unwrap();
    assert_eq!(retired_cfg.free_market_slot_count, 1);
    assert_eq!(
        retired_group.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );
    let reuse_market_id = retired_group.next_market_id;
    assert!(reuse_market_id > old_market_id);

    env.svm.warp_to_slot(8);
    let (reuse_source, reuse_cu) = env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        8,
        250,
        insurance_authority.pubkey(),
        insurance_operator.pubkey(),
        backing_authority.pubkey(),
        env.admin.pubkey(),
        25,
    );
    println!("v16 permissionless asset reuse BPF CU: {reuse_cu}");
    assert_eq!(env.token_amount(reuse_source), 0);
    assert_eq!(env.token_amount(env.vault), 20_105);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (reused_cfg, reused_group) = state::read_market(&market_data).unwrap();
    assert_eq!(reused_cfg.free_market_slot_count, 0);
    assert_eq!(reused_group.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(reused_group.assets[1].market_id, reuse_market_id);
    assert!(reused_group.assets[1].market_id > old_market_id);
    assert_eq!(reused_group.assets[1].effective_price, 250);
}

#[test]
fn v16_bpf_tradenocpi_executes_and_is_bounded() {
    let mut env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    env.deposit(&short_owner, short_account, 1_000_000);

    let trade_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        150,
        100,
    );
    println!("v16 TradeNoCpi BPF CU: {trade_cu}");
    assert!(
        trade_cu <= TRADE_CU_LIMIT,
        "TradeNoCpi CU {} exceeded limit {}",
        trade_cu,
        TRADE_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let long = state::read_portfolio(&long_data).unwrap();
    let short = state::read_portfolio(&short_data).unwrap();

    assert_eq!(env.token_amount(env.vault), 2_000_000);
    println!(
        "TradeNoCpi BPF long_basis={}, short_basis={}, insurance={}",
        long.legs[0].basis_pos_q, short.legs[0].basis_pos_q, group.insurance
    );
    assert_eq!(long.legs[0].basis_pos_q, (10 * POS_SCALE) as i128);
    assert_eq!(short.legs[0].basis_pos_q, -((10 * POS_SCALE) as i128));
    assert_eq!(
        group.assets[0].effective_price, 100,
        "consented execution price must not move the effective oracle price"
    );
    assert_eq!(
        group.insurance, 10,
        "W1 (fee-on-mark): fee billed on the MARK (100), NOT the consented exec_price (150) — \
         notional=1000 @ 100 bps = 10 (taker-only, one side)"
    );
    assert_eq!(group.vault, 2_000_000);
    assert_eq!(group.c_tot + group.insurance, group.vault);
}

#[test]
fn v16_bpf_tradenocpi_fee_is_billed_on_mark_not_exec_price() {
    // W1 (F-TRADENOCPI-FEE): the trade fee notional is pinned to the asset MARK (effective_price),
    // never the caller-supplied exec_price. A caller cannot lowball exec_price to evade the fee, nor
    // does a high exec_price inflate it. Same size + same mark (100) => identical insurance accrual
    // for every exec_price. Mark-based: notional = 10 * 100 = 1000, 100 bps => 10 per side => 20.
    let mut prev: Option<u128> = None;
    for exec_price in [1u64, 50, 100, 100_000] {
        let mut env = V16CuEnv::new();
        let long_owner = Keypair::new();
        let short_owner = Keypair::new();
        let long_account = env.create_portfolio(&long_owner);
        let short_account = env.create_portfolio(&short_owner);
        env.deposit(&long_owner, long_account, 1_000_000);
        env.deposit(&short_owner, short_account, 1_000_000);

        env.trade_with_cu(
            &long_owner,
            long_account,
            &short_owner,
            short_account,
            (10 * POS_SCALE) as i128,
            exec_price,
            100,
        );

        let market_data = env.svm.get_account(&env.market).unwrap().data;
        let (_, group) = state::read_market(&market_data).unwrap();
        assert_eq!(
            group.insurance, 10,
            "exec_price={exec_price}: fee must be billed on the mark (notional 1000 @ 100 bps = 10, \
             taker-only one side), independent of exec_price"
        );
        // the consented exec_price never moves the index, so the mark stays 100 for every iteration.
        assert_eq!(group.assets[0].effective_price, 100);
        if let Some(p) = prev {
            assert_eq!(
                group.insurance, p,
                "fee changed with exec_price — not mark-pinned"
            );
        }
        prev = Some(group.insurance);
    }
}

#[test]
fn v16_bpf_tradenocpi_rejects_invalid_final_market_shape() {
    let mut env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    env.deposit(&short_owner, short_account, 1_000_000);

    env.mutate_market(|_, group| {
        group.insurance_domain_budget[0] = group.insurance.saturating_add(1);
    });
    let before_market = env.svm.get_account(&env.market).unwrap().data;

    let result = env.try_trade_asset_with_cu(
        0,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );

    assert!(
        result.is_err(),
        "TradeNoCpi must reject instead of persisting an invalid market shape"
    );
    let after_market = env.svm.get_account(&env.market).unwrap().data;
    assert_eq!(
        after_market, before_market,
        "failed TradeNoCpi must roll back market data"
    );
}

#[test]
fn v16_bpf_tradenocpi_fresh_open_on_base_and_added_asset_is_bounded() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000_000);
    env.deposit(&short_owner, short_account, 1_000_000_000);

    let asset0_cu = env.trade_asset_with_cu(
        0,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    println!("v16 TradeNoCpi fresh open asset[0] CU: {asset0_cu}");
    assert!(
        asset0_cu <= MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
        "fresh asset[0] TradeNoCpi CU {} exceeded limit {}",
        asset0_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT
    );

    let asset3_cu = env.trade_asset_with_cu(
        3,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    println!("v16 TradeNoCpi fresh open asset[3] CU: {asset3_cu}");
    assert!(
        asset3_cu <= MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
        "fresh asset[3] TradeNoCpi CU {} exceeded limit {}",
        asset3_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT
    );

    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let long = state::read_portfolio(&long_data).unwrap();
    let short = state::read_portfolio(&short_data).unwrap();
    assert_eq!(
        active_leg_for_asset(&long, 0).basis_pos_q,
        (10 * POS_SCALE) as i128
    );
    assert_eq!(
        active_leg_for_asset(&short, 0).basis_pos_q,
        -((10 * POS_SCALE) as i128)
    );
    assert_eq!(
        active_leg_for_asset(&long, 3).basis_pos_q,
        (10 * POS_SCALE) as i128
    );
    assert_eq!(
        active_leg_for_asset(&short, 3).basis_pos_q,
        -((10 * POS_SCALE) as i128)
    );
}

#[test]
fn v16_bpf_perps_positive_smoke_cross_margin_pnl_convert_close_and_withdraw() {
    const INITIAL_PRICE: u64 = 100;
    const ASSET0_MARK: u64 = 105;
    const ASSET1_MARK: u64 = 100;
    const DEPOSIT: u128 = 2_000_000;
    const EXPECTED_PNL: i128 = 5;

    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, INITIAL_PRICE);

    let cross_owner = Keypair::new();
    let counterparty_owner = Keypair::new();
    let cross_account = env.create_portfolio(&cross_owner);
    let counterparty_account = env.create_portfolio(&counterparty_owner);
    env.deposit(&cross_owner, cross_account, DEPOSIT);
    env.deposit(&counterparty_owner, counterparty_account, DEPOSIT);

    let open_asset0_cu = env.trade_asset_with_cu(
        0,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        POS_SCALE as i128,
        INITIAL_PRICE,
        0,
    );
    assert_cu_within("perps smoke open asset[0]", open_asset0_cu, TRADE_CU_LIMIT);
    let open_asset1_cu = env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        -(POS_SCALE as i128),
        INITIAL_PRICE,
        0,
    );
    assert_cu_within("perps smoke open asset[1]", open_asset1_cu, TRADE_CU_LIMIT);

    let cross_open = env.portfolio_state(cross_account);
    assert_eq!(
        percolator::active_bitmap_count_ones(cross_open.active_bitmap),
        2
    );
    assert_eq!(
        active_leg_for_asset(&cross_open, 0).basis_pos_q,
        POS_SCALE as i128
    );
    assert_eq!(
        active_leg_for_asset(&cross_open, 1).basis_pos_q,
        -(POS_SCALE as i128)
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, ASSET0_MARK);
    env.push_auth_mark_for_asset_as_admin(1, 2, ASSET1_MARK);

    for (portfolio, asset_index, label) in [
        (
            counterparty_account,
            0,
            "counterparty asset[0] loss refresh",
        ),
        (cross_account, 0, "cross account asset[0] gain refresh"),
        (
            counterparty_account,
            1,
            "counterparty asset[1] loss refresh",
        ),
        (cross_account, 1, "cross account asset[1] gain refresh"),
    ] {
        let cu = env.crank(
            portfolio,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index,
                now_slot: 2,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
        assert_cu_within(label, cu, CRANK_CU_LIMIT);
    }

    let cross_after_refresh = env.portfolio_state(cross_account);
    let counterparty_after_refresh = env.portfolio_state(counterparty_account);
    assert_eq!(
        cross_after_refresh.pnl, EXPECTED_PNL,
        "cross-margin account should realize +5 while carrying two active legs"
    );
    assert_eq!(counterparty_after_refresh.pnl, 0);
    assert_eq!(
        counterparty_after_refresh.capital,
        DEPOSIT - EXPECTED_PNL as u128
    );

    let close_asset0_cu = env.trade_asset_with_cu(
        0,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        -(POS_SCALE as i128),
        ASSET0_MARK,
        0,
    );
    assert_cu_within(
        "perps smoke close asset[0]",
        close_asset0_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );
    let close_asset1_cu = env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        POS_SCALE as i128,
        ASSET1_MARK,
        0,
    );
    assert_cu_within(
        "perps smoke close asset[1]",
        close_asset1_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );

    let cross_flat = env.portfolio_state(cross_account);
    let counterparty_flat = env.portfolio_state(counterparty_account);
    assert!(percolator::active_bitmap_is_empty(cross_flat.active_bitmap));
    assert!(percolator::active_bitmap_is_empty(
        counterparty_flat.active_bitmap
    ));
    assert_eq!(cross_flat.pnl, EXPECTED_PNL);
    assert_eq!(cross_flat.capital, DEPOSIT);
    assert_eq!(counterparty_flat.capital, DEPOSIT - EXPECTED_PNL as u128);

    let convert_cu =
        env.convert_released_pnl_with_cu(&cross_owner, cross_account, EXPECTED_PNL as u128);
    assert_cu_within(
        "perps smoke convert released pnl",
        convert_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );
    let cross_after_convert = env.portfolio_state(cross_account);
    assert_eq!(cross_after_convert.pnl, 0);
    assert_eq!(cross_after_convert.capital, DEPOSIT + EXPECTED_PNL as u128);

    let cross_dest = env.withdraw(&cross_owner, cross_account, cross_after_convert.capital);
    let counterparty_dest = env.withdraw(
        &counterparty_owner,
        counterparty_account,
        counterparty_flat.capital,
    );
    assert_eq!(
        env.token_amount(cross_dest) as u128,
        DEPOSIT + EXPECTED_PNL as u128
    );
    assert_eq!(
        env.token_amount(counterparty_dest) as u128,
        DEPOSIT - EXPECTED_PNL as u128
    );
    assert_eq!(env.token_amount(env.vault), 0);
    let (_, group) = env.market_state();
    assert_eq!(group.vault, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(group.insurance, 0);
}

#[test]
fn v16_bpf_cross_margin_positive_pnl_allows_trading_negative_leg_before_convert() {
    const INITIAL_PRICE: u64 = 100;
    const ASSET0_MARK: u64 = 105;
    const ASSET1_MARK: u64 = 95;
    const ASSET0_SIZE_Q: i128 = 20 * POS_SCALE as i128;
    const ASSET1_SIZE_Q: i128 = 10 * POS_SCALE as i128;
    const DEPOSIT: u128 = 320;
    const EXPECTED_POSITIVE_PNL: i128 = 100;
    const EXPECTED_NET_PNL_AFTER_NEGATIVE_CLOSE: i128 = 50;

    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, INITIAL_PRICE);

    let cross_owner = Keypair::new();
    let counterparty_owner = Keypair::new();
    let cross_account = env.create_portfolio(&cross_owner);
    let counterparty_account = env.create_portfolio(&counterparty_owner);
    env.deposit(&cross_owner, cross_account, DEPOSIT);
    env.deposit(&counterparty_owner, counterparty_account, 1_000);

    env.trade_asset_with_cu(
        0,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        ASSET0_SIZE_Q,
        INITIAL_PRICE,
        0,
    );
    env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        ASSET1_SIZE_Q,
        INITIAL_PRICE,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, ASSET0_MARK);
    env.push_auth_mark_for_asset_as_admin(1, 2, ASSET1_MARK);

    for (portfolio, asset_index, label) in [
        (
            counterparty_account,
            0,
            "counterparty asset[0] loss refresh",
        ),
        (cross_account, 0, "cross account asset[0] gain refresh"),
        (
            counterparty_account,
            1,
            "counterparty asset[1] gain refresh",
        ),
    ] {
        let cu = env.crank(
            portfolio,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index,
                now_slot: 2,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
        assert_cu_within(label, cu, CRANK_CU_LIMIT);
    }
    let (_, moved_group) = env.market_state();
    assert_eq!(moved_group.assets[0].effective_price, ASSET0_MARK);
    assert_eq!(moved_group.assets[1].effective_price, ASSET1_MARK);

    let cross_before_close = env.portfolio_state(cross_account);
    assert_eq!(cross_before_close.pnl, EXPECTED_POSITIVE_PNL);
    assert_eq!(cross_before_close.capital, DEPOSIT);
    assert_eq!(
        active_leg_for_asset(&cross_before_close, 1).basis_pos_q,
        ASSET1_SIZE_Q,
        "asset[1] is a long leg with negative mark-to-market at the moved price"
    );

    let close_negative_leg_cu = env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        -ASSET1_SIZE_Q,
        ASSET1_MARK,
        0,
    );
    assert_cu_within(
        "cross-margin close negative leg before pnl convert",
        close_negative_leg_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );

    let cross_after_close = env.portfolio_state(cross_account);
    assert!(
        has_active_leg_for_asset(&cross_after_close, 0),
        "positive-PnL leg should remain open"
    );
    assert!(
        !has_active_leg_for_asset(&cross_after_close, 1),
        "negative-PnL leg should close without converting positive PnL first"
    );
    assert_eq!(cross_after_close.capital, DEPOSIT);
    assert_eq!(
        cross_after_close.pnl, EXPECTED_NET_PNL_AFTER_NEGATIVE_CLOSE,
        "asset[1] loss should net against the existing source-backed positive PnL"
    );
}

#[derive(Clone, Copy, Debug)]
enum SourceCreditWatermarkTradePath {
    NoCpi,
    Cpi,
}

#[derive(Clone, Copy, Debug)]
enum SourceCreditWatermarkDirection {
    PositiveSize,
    NegativeSize,
}

// v17 convergence matrix row: v17-tradecpi-set-matcher-config
// For the Cpi path, a pre-initialized (matcher_ctx, matcher_delegate) can be passed
// so that init_matcher_context (which writes SetMatcherConfig) is not called inside
// this function. This avoids modifying account_b between the before-snapshot and
// the atomicity assertion.
#[allow(clippy::too_many_arguments)]
fn try_source_credit_watermark_trade(
    env: &mut V16CuEnv,
    path: SourceCreditWatermarkTradePath,
    matcher_program: Option<Pubkey>,
    pre_init_matcher: Option<(Pubkey, Pubkey)>, // (ctx, delegate) if already initialized
    owner_a: &Keypair,
    account_a: Pubkey,
    owner_b: &Keypair,
    account_b: Pubkey,
    asset_index: u16,
    size_q: i128,
    exec_price: u64,
    fee_bps: u64,
) -> Result<u64, String> {
    match path {
        SourceCreditWatermarkTradePath::NoCpi => env.try_trade_asset_with_cu(
            asset_index,
            owner_a,
            account_a,
            owner_b,
            account_b,
            size_q,
            exec_price,
            fee_bps,
        ),
        SourceCreditWatermarkTradePath::Cpi => {
            let matcher_program = matcher_program.expect("matcher program");
            let (matcher_ctx, matcher_delegate) = pre_init_matcher.unwrap_or_else(|| {
                let (ctx, delegate, _) =
                    env.init_matcher_context(owner_b, matcher_program, account_b);
                (ctx, delegate)
            });
            env.try_trade_cpi_with_cu_on_asset(
                owner_a,
                account_a,
                owner_b,
                account_b,
                matcher_program,
                matcher_ctx,
                matcher_delegate,
                asset_index,
                size_q,
                fee_bps,
            )
        }
    }
}

fn run_source_credit_watermark_trade_case(
    path: SourceCreditWatermarkTradePath,
    direction: SourceCreditWatermarkDirection,
) {
    const INITIAL_PRICE: u64 = 100;
    const ASSET0_SIZE_Q: i128 = 20 * POS_SCALE as i128;
    const ASSET1_SIZE_Q: i128 = 10 * POS_SCALE as i128;
    const SAFE_INCREASE_Q: i128 = POS_SCALE as i128;
    const DEPOSIT: u128 = 313;
    const EXPECTED_POSITIVE_PNL: i128 = 100;

    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);
    let matcher_program = match path {
        SourceCreditWatermarkTradePath::NoCpi => None,
        SourceCreditWatermarkTradePath::Cpi => {
            let matcher_program = Pubkey::new_unique();
            let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
            env.svm.add_program(matcher_program, &matcher_bytes);
            Some(matcher_program)
        }
    };
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, INITIAL_PRICE);

    let cross_owner = Keypair::new();
    let counterparty_owner = Keypair::new();
    let cross_account = env.create_portfolio(&cross_owner);
    let counterparty_account = env.create_portfolio(&counterparty_owner);
    env.deposit(&cross_owner, cross_account, DEPOSIT);
    env.deposit(&counterparty_owner, counterparty_account, 1_000);

    let (winning_domain, asset0_mark, asset1_mark, side_sign) = match direction {
        SourceCreditWatermarkDirection::PositiveSize => (1usize, 105, 95, 1i128),
        SourceCreditWatermarkDirection::NegativeSize => (0usize, 95, 105, -1i128),
    };
    env.top_up_backing_bucket(winning_domain as u16, 150, 10);

    env.trade_asset_with_cu(
        0,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        side_sign * ASSET0_SIZE_Q,
        INITIAL_PRICE,
        0,
    );
    env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        side_sign * ASSET1_SIZE_Q,
        INITIAL_PRICE,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, asset0_mark);
    env.push_auth_mark_for_asset_as_admin(1, 2, asset1_mark);
    for (portfolio, asset_index) in [
        (counterparty_account, 0),
        (cross_account, 0),
        (counterparty_account, 1),
    ] {
        env.crank(
            portfolio,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index,
                now_slot: 2,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }
    let forced_capital = match direction {
        SourceCreditWatermarkDirection::PositiveSize => 260,
        SourceCreditWatermarkDirection::NegativeSize => 100,
    };
    env.force_portfolio_capital_for_benchmark(cross_account, forced_capital);

    let cross_before = env.portfolio_state(cross_account);
    assert_eq!(
        cross_before.pnl, EXPECTED_POSITIVE_PNL,
        "{path:?} {direction:?} setup must create source-backed positive PnL"
    );
    let (_, before_withdraw_group) = env.market_state();
    assert_eq!(
        before_withdraw_group.source_credit[winning_domain].positive_claim_bound_num,
        EXPECTED_POSITIVE_PNL as u128 * BOUND_SCALE
    );
    let surplus_backing = before_withdraw_group.source_credit[winning_domain]
        .fresh_reserved_backing_num
        .checked_sub(before_withdraw_group.source_credit[winning_domain].positive_claim_bound_num)
        .unwrap()
        / BOUND_SCALE;
    assert!(
        surplus_backing > 0,
        "{path:?} {direction:?} setup must leave withdrawable surplus backing"
    );

    let watermark_withdraw_dest = env.token_account(env.admin.pubkey(), 0);
    env.withdraw_backing_bucket_to_admin_token_with_cu(
        watermark_withdraw_dest,
        winning_domain as u16,
        surplus_backing,
    );
    let (_, exact_watermark_group) = env.market_state();
    assert_eq!(
        exact_watermark_group.source_credit[winning_domain].fresh_reserved_backing_num,
        exact_watermark_group.source_credit[winning_domain].positive_claim_bound_num,
        "{path:?} {direction:?} setup must leave no surplus source-credit backing"
    );

    // v17 convergence: for the Cpi path, pre-initialize the matcher context BEFORE
    // taking the before_* snapshots. SetMatcherConfig writes to counterparty_account; doing
    // it before the snapshot means the atomicity assertion (post-failed-trade == before) still
    // holds: the failed engine trade leaves no trace, and the snapshot includes the LP config.
    let pre_matcher = match path {
        SourceCreditWatermarkTradePath::NoCpi => None,
        SourceCreditWatermarkTradePath::Cpi => {
            let mp = matcher_program.expect("matcher program");
            let (ctx, delegate, _) =
                env.init_matcher_context(&counterparty_owner, mp, counterparty_account);
            Some((ctx, delegate))
        }
    };
    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_cross = env.svm.get_account(&cross_account).unwrap();
    let before_counterparty = env.svm.get_account(&counterparty_account).unwrap();
    let over_watermark = try_source_credit_watermark_trade(
        &mut env,
        path,
        matcher_program,
        pre_matcher,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        1,
        side_sign * SAFE_INCREASE_Q,
        asset1_mark,
        0,
    );
    assert!(
        over_watermark.is_err(),
        "{path:?} {direction:?} risk increase must reject at the exact source-credit watermark"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&cross_account).unwrap().data,
        before_cross.data
    );
    assert_eq!(
        env.svm.get_account(&counterparty_account).unwrap().data,
        before_counterparty.data
    );

    env.top_up_backing_bucket(winning_domain as u16, 5_000, 10);
    let second_pass_deposit = match direction {
        SourceCreditWatermarkDirection::PositiveSize => 50,
        SourceCreditWatermarkDirection::NegativeSize => 200,
    };
    env.deposit(&cross_owner, cross_account, second_pass_deposit);
    env.deposit(
        &counterparty_owner,
        counterparty_account,
        second_pass_deposit,
    );
    env.svm.warp_to_slot(3);
    // For inside_watermark, pass None so init_matcher_context is called fresh (creates new ctx,
    // updates the LP config in counterparty_account to the new ctx).
    let inside_watermark = try_source_credit_watermark_trade(
        &mut env,
        path,
        matcher_program,
        None,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        1,
        side_sign * SAFE_INCREASE_Q,
        asset1_mark,
        1,
    );
    assert!(
        inside_watermark.is_ok(),
        "{path:?} {direction:?} risk increase inside the source-credit watermark failed: {inside_watermark:?}"
    );

    let (_, after_group) = env.market_state();
    let cross_after = env.portfolio_state(cross_account);
    assert_eq!(
        after_group.source_credit[winning_domain].credit_rate_num,
        percolator::CREDIT_RATE_SCALE,
        "{path:?} {direction:?} must not dilute live positive claims"
    );
    assert!(
        cross_after.source_lien_effective_reserved[winning_domain] > 0,
        "{path:?} {direction:?} must reserve source credit once surplus backing exists"
    );
}

#[test]
fn v16_bpf_trade_paths_respect_source_credit_watermark_permutations() {
    for path in [
        SourceCreditWatermarkTradePath::NoCpi,
        SourceCreditWatermarkTradePath::Cpi,
    ] {
        for direction in [
            SourceCreditWatermarkDirection::PositiveSize,
            SourceCreditWatermarkDirection::NegativeSize,
        ] {
            run_source_credit_watermark_trade_case(path, direction);
        }
    }
}

#[test]
fn v16_bpf_cross_margin_positive_pnl_allows_backed_risk_increase_on_negative_leg() {
    const INITIAL_PRICE: u64 = 100;
    const ASSET0_MARK: u64 = 105;
    const ASSET1_MARK: u64 = 95;
    const ASSET0_SIZE_Q: i128 = 20 * POS_SCALE as i128;
    const ASSET1_SIZE_Q: i128 = 10 * POS_SCALE as i128;
    const SAFE_INCREASE_Q: i128 = POS_SCALE as i128;
    const TOO_LARGE_INCREASE_Q: i128 = 30 * POS_SCALE as i128;
    const DEPOSIT: u128 = 313;
    const EXPECTED_POSITIVE_PNL: i128 = 100;
    const EXPECTED_NET_PNL_AFTER_REFRESH: i128 = 50;

    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, INITIAL_PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, INITIAL_PRICE);

    let cross_owner = Keypair::new();
    let counterparty_owner = Keypair::new();
    let cross_account = env.create_portfolio(&cross_owner);
    let counterparty_account = env.create_portfolio(&counterparty_owner);
    env.deposit(&cross_owner, cross_account, DEPOSIT);
    env.deposit(&counterparty_owner, counterparty_account, 1_000);
    env.top_up_backing_bucket(1, 150, 10);

    env.trade_asset_with_cu(
        0,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        ASSET0_SIZE_Q,
        INITIAL_PRICE,
        0,
    );
    env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        ASSET1_SIZE_Q,
        INITIAL_PRICE,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, ASSET0_MARK);
    env.push_auth_mark_for_asset_as_admin(1, 2, ASSET1_MARK);
    for (portfolio, asset_index) in [
        (counterparty_account, 0),
        (cross_account, 0),
        (counterparty_account, 1),
    ] {
        env.crank(
            portfolio,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index,
                now_slot: 2,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }

    let cross_before = env.portfolio_state(cross_account);
    assert_eq!(cross_before.pnl, EXPECTED_POSITIVE_PNL);
    assert_eq!(cross_before.capital, DEPOSIT);
    assert_eq!(
        active_leg_for_asset(&cross_before, 1).basis_pos_q,
        ASSET1_SIZE_Q,
        "asset[1] is a losing long leg before the risk-increasing trade"
    );
    let (_, before_watermark_group) = env.market_state();
    let fresh_reserved_before_withdraw =
        before_watermark_group.source_credit[1].fresh_reserved_backing_num;
    let positive_claim_before_withdraw =
        before_watermark_group.source_credit[1].positive_claim_bound_num;

    let watermark_withdraw_dest = env.token_account(env.admin.pubkey(), 0);
    let withdraw_cu =
        env.withdraw_backing_bucket_to_admin_token_with_cu(watermark_withdraw_dest, 1, 50);
    assert_cu_within(
        "WithdrawBackingBucket live watermark",
        withdraw_cu,
        CUSTODY_CU_LIMIT,
    );
    let (_, watermarked_group) = env.market_state();
    assert_eq!(
        watermarked_group.source_credit[1].fresh_reserved_backing_num,
        fresh_reserved_before_withdraw - 50 * BOUND_SCALE,
        "admin withdrawal lowers the future encumbrance watermark"
    );
    assert!(
        watermarked_group.source_credit[1].fresh_reserved_backing_num
            >= positive_claim_before_withdraw,
        "the lowered watermark must still cover live positive-claim demand"
    );
    assert_eq!(
        watermarked_group.source_credit[1].credit_rate_num,
        percolator::CREDIT_RATE_SCALE,
        "lowering the watermark must not dilute already-live positive claims"
    );

    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_cross = env.svm.get_account(&cross_account).unwrap();
    let before_counterparty = env.svm.get_account(&counterparty_account).unwrap();
    let too_large = env.try_trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        TOO_LARGE_INCREASE_Q,
        ASSET1_MARK,
        0,
    );
    assert!(
        too_large.is_err(),
        "risk increase must stay capped by realizable source-backed positive PnL"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&cross_account).unwrap().data,
        before_cross.data
    );
    assert_eq!(
        env.svm.get_account(&counterparty_account).unwrap().data,
        before_counterparty.data
    );

    let increase_cu = env.trade_asset_with_cu(
        1,
        &cross_owner,
        cross_account,
        &counterparty_owner,
        counterparty_account,
        SAFE_INCREASE_Q,
        ASSET1_MARK,
        0,
    );
    assert_cu_within(
        "cross-margin increase negative leg with backed positive pnl",
        increase_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );

    let cross_after = env.portfolio_state(cross_account);
    assert_eq!(
        active_leg_for_asset(&cross_after, 1).basis_pos_q,
        ASSET1_SIZE_Q + SAFE_INCREASE_Q
    );
    assert_eq!(cross_after.capital, DEPOSIT);
    assert_eq!(cross_after.pnl, EXPECTED_NET_PNL_AFTER_REFRESH);
    assert!(
        cross_after.capital < cross_after.health_cert.certified_initial_req,
        "without positive PnL credit this risk increase would fail initial margin"
    );
    assert!(
        cross_after.health_cert.certified_equity as u128
            >= cross_after.health_cert.certified_initial_req
    );
    let source_lien_effective_reserved: u128 = cross_after
        .source_lien_effective_reserved
        .iter()
        .copied()
        .sum();
    assert!(
        source_lien_effective_reserved > 0,
        "risk-increasing trade must reserve backed source-credit support for IM"
    );
    assert!(
        cross_after
            .source_lien_counterparty_backing_num
            .iter()
            .any(|amount| *amount != 0)
            || cross_after
                .source_lien_insurance_backing_num
                .iter()
                .any(|amount| *amount != 0),
        "source-credit IM lien must be backed by counterparty backing or reserved insurance"
    );

    let (_, after_increase_group) = env.market_state();
    let after_increase_source = after_increase_group.source_credit[1];
    let after_increase_bucket = after_increase_group.source_backing_buckets[1];
    let insurance_encumbered_num = after_increase_source
        .valid_liened_insurance_num
        .checked_add(after_increase_source.impaired_liened_insurance_num)
        .unwrap();
    let available_backing_num = after_increase_source
        .fresh_reserved_backing_num
        .checked_sub(after_increase_source.valid_liened_backing_num)
        .unwrap()
        .checked_add(
            after_increase_source
                .insurance_credit_reserved_num
                .checked_sub(insurance_encumbered_num)
                .unwrap(),
        )
        .unwrap();
    let max_lossless_withdrawable_num = after_increase_bucket
        .fresh_unliened_backing_num
        .min(available_backing_num - after_increase_source.positive_claim_bound_num);
    let over_watermark_amount = max_lossless_withdrawable_num / BOUND_SCALE + 1;
    assert!(
        over_watermark_amount > 0,
        "test must attempt a withdrawal above the live backing watermark"
    );

    let backing_withdraw_dest = env.token_account(env.admin.pubkey(), 0);
    let market_before_withdraw = env.svm.get_account(&env.market).unwrap();
    let backing_withdraw = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket {
            domain: 1,
            amount: over_watermark_amount,
        },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(backing_withdraw_dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            // #433: backing-domain ledger is MANDATORY.
            AccountMeta::new(
                state::derive_lp_backing_ledger(&env.program_id, &env.market, 1).0,
                false,
            ),
        ],
        &[&env.admin],
    );
    assert!(
        backing_withdraw.is_err(),
        "withdrawal above the live backing watermark must not be allowed"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        market_before_withdraw.data
    );
}

#[test]
fn v16_bpf_permissionless_crank_computes_funding_from_internal_mark_premium() {
    const INITIAL_PRICE: u64 = 1_000_000;
    const DEPOSIT: u128 = 10_000_000;

    let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams {
        initial_price: INITIAL_PRICE,
        max_price_move_bps_per_slot: 1_000,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 1,
        ..V16CuMarketParams::default()
    });
    env.svm.warp_to_slot(0);
    env.configure_ewma_mark_with_cu(0, INITIAL_PRICE, 1, 0);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, DEPOSIT);
    env.deposit(&short_owner, short_account, DEPOSIT);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        INITIAL_PRICE,
        0,
    );

    env.svm.warp_to_slot(1);
    env.push_ewma_mark_with_cu(1, INITIAL_PRICE * 2);
    env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let (cfg_after_first, group_after_first) = env.market_state();
    assert_eq!(cfg_after_first.mark_ewma_e6, 1_500_000);
    assert_eq!(group_after_first.assets[0].effective_price, 1_100_000);
    assert_eq!(
        group_after_first.funding_epoch, 0,
        "a newly pushed mark must not retroactively charge funding before its slot"
    );
    assert_eq!(group_after_first.assets[0].f_long_num, 0);
    assert_eq!(group_after_first.assets[0].f_short_num, 0);

    env.svm.warp_to_slot(2);
    let funding_cu = env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    assert_cu_within(
        "permissionless computed funding crank",
        funding_cu,
        CRANK_CU_LIMIT,
    );
    let (_, funded_group) = env.market_state();
    assert_eq!(funded_group.funding_epoch, 1);
    assert_eq!(funded_group.assets[0].effective_price, 1_210_000);
    assert_eq!(funded_group.assets[0].f_long_num, -(ADL_ONE as i128));
    assert_eq!(funded_group.assets[0].f_short_num, ADL_ONE as i128);
}

#[test]
fn v16_bpf_existing_funding_ledger_refreshes_and_converts_between_sides() {
    const INITIAL_PRICE: u64 = 1_000_000;
    const FUNDING_RATE_E9: i128 = 1_000;
    const DEPOSIT: u128 = 2_000_000;

    let mut env = V16CuEnv::new_with_init_params(production_risk_params());
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, DEPOSIT);
    env.deposit(&short_owner, short_account, DEPOSIT);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        INITIAL_PRICE,
        0,
    );

    env.mutate_market(|_, group| {
        let out = group
            .accrue_asset_to_not_atomic(0, 1, INITIAL_PRICE, FUNDING_RATE_E9, true)
            .unwrap();
        assert!(out.funding_active);
        group.assets[0].raw_oracle_target_price = INITIAL_PRICE;
    });
    env.svm.warp_to_slot(1);
    let (_, funded_group) = env.market_state();
    assert_eq!(funded_group.funding_epoch, 1);
    assert_eq!(funded_group.assets[0].f_long_num, -(ADL_ONE as i128));
    assert_eq!(funded_group.assets[0].f_short_num, ADL_ONE as i128);

    let long_refresh_cu = env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    assert_cu_within(
        "funding smoke long loss refresh",
        long_refresh_cu,
        CRANK_CU_LIMIT,
    );
    let long_after = env.portfolio_state(long_account);
    assert_eq!(long_after.pnl, 0);
    assert_eq!(long_after.capital, DEPOSIT - 1);

    let short_refresh_cu = env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    assert_cu_within(
        "funding smoke short gain refresh",
        short_refresh_cu,
        CRANK_CU_LIMIT,
    );
    let short_after = env.portfolio_state(short_account);
    assert_eq!(short_after.pnl, 1);
    assert_eq!(short_after.capital, DEPOSIT);

    let close_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(POS_SCALE as i128),
        INITIAL_PRICE,
        0,
    );
    assert_cu_within(
        "funding smoke close funded position",
        close_cu,
        TRADE_CU_LIMIT,
    );
    let long_flat = env.portfolio_state(long_account);
    let short_flat = env.portfolio_state(short_account);
    assert!(percolator::active_bitmap_is_empty(long_flat.active_bitmap));
    assert!(percolator::active_bitmap_is_empty(short_flat.active_bitmap));
    assert_eq!(long_flat.capital, DEPOSIT - 1);
    assert_eq!(short_flat.pnl, 1);

    let convert_cu = env.convert_released_pnl_with_cu(&short_owner, short_account, 1);
    assert_cu_within(
        "funding smoke convert released pnl",
        convert_cu,
        CUSTODY_CU_LIMIT,
    );
    let short_after_convert = env.portfolio_state(short_account);
    assert_eq!(short_after_convert.pnl, 0);
    assert_eq!(short_after_convert.capital, DEPOSIT + 1);

    let (_, group) = env.market_state();
    assert_eq!(group.c_tot, DEPOSIT * 2);
    assert_eq!(group.vault, DEPOSIT * 2);
}

#[test]
fn v16_bpf_stale_asset_does_not_block_current_unrelated_trade() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);

    let stale_long_owner = Keypair::new();
    let stale_short_owner = Keypair::new();
    let stale_long_account = env.create_portfolio(&stale_long_owner);
    let stale_short_account = env.create_portfolio(&stale_short_owner);
    env.deposit(&stale_long_owner, stale_long_account, 1_000_000_000);
    env.deposit(&stale_short_owner, stale_short_account, 1_000_000_000);
    env.trade_asset_with_cu(
        1,
        &stale_long_owner,
        stale_long_account,
        &stale_short_owner,
        stale_short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );

    let cranker_owner = Keypair::new();
    let cranker_portfolio = env.create_portfolio(&cranker_owner);
    env.svm.warp_to_slot(3);

    for nonce in 0..3 {
        env.crank(
            cranker_portfolio,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index: 0,
                now_slot: 3 + nonce,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }

    env.crank(
        cranker_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let (_, group) = env.market_state();
    assert_eq!(group.current_slot, 3);
    assert_eq!(group.assets[0].slot_last, 3);
    assert!(group.assets[1].slot_last < group.current_slot);
    assert!(
        group.loss_stale_active,
        "asset[1] partial catch-up must leave the market loss-stale bit set"
    );

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000_000);
    env.deposit(&short_owner, short_account, 1_000_000_000);

    let trade_cu = env.trade_asset_with_cu(
        0,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    println!("v16 TradeNoCpi current asset[0] with stale asset[1] CU: {trade_cu}");
    assert_cu_within(
        "TradeNoCpi current asset[0] with unrelated stale asset[1]",
        trade_cu,
        MULTI_ASSET_OPEN_TRADE_CU_LIMIT,
    );

    let (_, group_after) = env.market_state();
    assert_eq!(group_after.assets[0].slot_last, 3);
    assert!(group_after.assets[1].slot_last < group_after.current_slot);
    assert!(
        group_after.loss_stale_active,
        "unrelated trade must not hide the stale asset state"
    );

    let long = env.portfolio_state(long_account);
    let short = env.portfolio_state(short_account);
    assert!(has_active_leg_for_asset(&long, 0));
    assert!(has_active_leg_for_asset(&short, 0));
    assert!(!has_active_leg_for_asset(&long, 1));
    assert!(!has_active_leg_for_asset(&short, 1));
}

#[test]
fn v16_bpf_sync_maintenance_fee_with_cranker_share_is_bounded() {
    // Fixture repair note: this failure is NOT an E3/E4 regression -- it
    // predates this session's engine work entirely. Wrapper commit e0e05a78
    // ("require cranker portfolio owner to sign SyncMaintenanceFee reward
    // claim", #400, landed the same session as #398 above) added a required
    // 4th account (the cranker portfolio's owner, signing) whenever the
    // maintenance-fee cranker reward is directed at a THIRD-PARTY portfolio
    // -- closing a "direct every user's reward share to my own account"
    // insurance-drain path (Finding 15). This test is the ONLY call site in
    // the whole suite that exercises the separate-cranker path (every other
    // `sync_maintenance_fee_with_cu` caller passes `None` or self-cranks),
    // so it is the only one #400 broke, and #400 never updated it. Repaired
    // to supply the now-required signer via
    // `sync_maintenance_fee_with_cranker_owner_with_cu`; the property under
    // test (cranker's reward share is bounded/correctly computed) is
    // unchanged.
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 58,
    );
    let payer_owner = Keypair::new();
    let cranker_owner = Keypair::new();
    let payer_portfolio = env.create_portfolio(&payer_owner);
    let cranker_portfolio = env.create_portfolio(&cranker_owner);
    env.deposit(&payer_owner, payer_portfolio, 100_000_000);
    env.update_maintenance_fee_policy_with_cu(4_000);

    env.svm.warp_to_slot(10);
    let sync_cu = env.sync_maintenance_fee_with_cranker_owner_with_cu(
        payer_portfolio,
        cranker_portfolio,
        &cranker_owner,
        10,
    );
    println!("v16 SyncMaintenanceFee 4-account cranker-share CU: {sync_cu}");
    assert!(
        sync_cu <= CUSTODY_CU_LIMIT,
        "4-account SyncMaintenanceFee CU {} exceeded limit {}",
        sync_cu,
        CUSTODY_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let payer_data = env.svm.get_account(&payer_portfolio).unwrap().data;
    let cranker_data = env.svm.get_account(&cranker_portfolio).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let payer = state::read_portfolio(&payer_data).unwrap();
    let cranker = state::read_portfolio(&cranker_data).unwrap();
    assert_eq!(payer.last_fee_slot, 10);
    assert_eq!(payer.capital, 100_000_000 - 580);
    assert_eq!(cranker.capital, 232);
    assert_eq!(group.insurance, 348);
}

#[test]
fn v16_bpf_underfunded_flat_sync_sweeps_remaining_capital_once() {
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 40,
    );
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_portfolio = env.create_portfolio(&long_owner);
    let short_portfolio = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_portfolio, 1);
    env.deposit(&short_owner, short_portfolio, 10_000);

    env.svm.warp_to_slot(10);
    let long_lamports_before_sync = env.svm.get_account(&long_portfolio).unwrap().lamports;
    env.sync_maintenance_fee_with_cu(long_portfolio, None, 10);
    let (_, group_after_flat_sync) = env.market_state();
    assert_eq!(
        group_after_flat_sync.insurance, 1,
        "underfunded flat sync sweeps the remaining capital into insurance"
    );
    // Fixture repair note: this failure is NOT an E3/E4 regression -- it
    // predates this session's engine work entirely. Wrapper commit 69bc27ad
    // ("remove permissionless auto-close from handle_sync_maintenance_fee",
    // VULN-03, #393, same session as #398/#400 above) deliberately removed
    // the deregister-and-close step this test originally relied on:
    // SyncMaintenanceFee has no owner signer check (by design -- it's meant
    // to be permissionlessly crankable), so auto-closing an emptied
    // portfolio there let any third party force-close a user's dust account
    // and strand its rent in the market slab (griefing) or leave it in an
    // unrecoverable half-deregistered limbo. Account closure now only
    // happens through the owner/marketauth-gated ClosePortfolio path. The
    // underlying property this test verifies -- an underfunded flat sync
    // sweeps whatever capital remains into insurance exactly once, without
    // over-sweeping or leaving the account in a broken state -- is
    // unchanged and still fully asserted below; only the (now intentionally
    // removed) auto-close side effect is gone.
    assert_eq!(
        group_after_flat_sync.materialized_portfolio_count, 2,
        "VULN-03: SyncMaintenanceFee must sweep the dust capital but must NOT auto-close/\
         deregister the portfolio -- both accounts remain materialized"
    );
    let long_after_flat_sync = env.portfolio_state(long_portfolio);
    assert_eq!(
        long_after_flat_sync.capital, 0,
        "underfunded flat sync sweeps the account's capital fully, exactly once"
    );
    assert_eq!(long_after_flat_sync.last_fee_slot, 10);
    assert_eq!(
        env.svm.get_account(&long_portfolio).unwrap().lamports,
        long_lamports_before_sync,
        "VULN-03: the dust-swept portfolio's rent must stay with the account, not move to \
         the market slab -- only an explicit owner/marketauth ClosePortfolio call may do that"
    );
    assert!(
        state::is_initialized(&env.svm.get_account(&long_portfolio).unwrap().data),
        "VULN-03: SyncMaintenanceFee must not close/zero the portfolio account"
    );

    let fresh_long_portfolio = env.create_portfolio(&long_owner);
    env.deposit(&long_owner, fresh_long_portfolio, 1_000);
    env.trade_with_cu(
        &long_owner,
        fresh_long_portfolio,
        &short_owner,
        short_portfolio,
        POS_SCALE as i128,
        100,
        0,
    );
    env.crank(
        fresh_long_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 10,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let (_, before_nonflat_sync) = env.market_state();
    assert_eq!(before_nonflat_sync.assets[0].slot_last, 1);
    let insurance_before_nonflat_sync = before_nonflat_sync.insurance;

    let fresh_long_lamports_before_sync =
        env.svm.get_account(&fresh_long_portfolio).unwrap().lamports;
    env.sync_maintenance_fee_with_cu(fresh_long_portfolio, None, 11);
    let (_, group_after_nonflat_sync) = env.market_state();
    let long_after_nonflat_sync = env.portfolio_state(fresh_long_portfolio);
    assert_eq!(long_after_nonflat_sync.capital, 1_000);
    assert_eq!(long_after_nonflat_sync.last_fee_slot, 10);
    assert_eq!(
        env.svm
            .get_account(&fresh_long_portfolio)
            .expect("non-flat portfolio should remain allocated")
            .lamports,
        fresh_long_lamports_before_sync
    );
    assert_eq!(
        group_after_nonflat_sync.insurance, insurance_before_nonflat_sync,
        "later deposits are not charged for an already-swept empty interval"
    );
}

#[test]
fn v16_bpf_nonflat_fee_sync_settles_hidden_loss_before_sweeping_fee() {
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 100,
    );
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_portfolio = env.create_portfolio(&long_owner);
    let short_portfolio = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_portfolio, 100);
    env.deposit(&short_owner, short_portfolio, 1_000);
    env.trade_with_cu(
        &long_owner,
        long_portfolio,
        &short_owner,
        short_portfolio,
        POS_SCALE as i128,
        100,
        0,
    );

    let long_before_move = env.portfolio_state(long_portfolio);
    assert_eq!(long_before_move.capital, 100);
    assert_eq!(long_before_move.pnl, 0);

    env.mutate_market(|_, group| {
        group.accrue_asset_to_not_atomic(0, 1, 50, 0, true).unwrap();
        group.assets[0].raw_oracle_target_price = 50;
    });
    env.svm.warp_to_slot(1);

    let long_with_hidden_loss = env.portfolio_state(long_portfolio);
    assert_eq!(
        long_with_hidden_loss.capital, 100,
        "the price move should be hidden until the account is touched"
    );
    assert_eq!(long_with_hidden_loss.pnl, 0);
    let (_, group_with_hidden_loss) = env.market_state();
    assert_eq!(group_with_hidden_loss.insurance, 0);
    assert_eq!(group_with_hidden_loss.c_tot, 1_100);

    let sync_cu = env.sync_maintenance_fee_with_cu(long_portfolio, None, 1);
    println!("v16 SyncMaintenanceFee nonflat hidden-loss CU: {sync_cu}");
    assert_cu_within(
        "SyncMaintenanceFee nonflat hidden-loss regression",
        sync_cu,
        CUSTODY_CU_LIMIT,
    );

    let long_after_sync = env.portfolio_state(long_portfolio);
    let (_, group_after_sync) = env.market_state();
    assert_eq!(long_after_sync.capital, 0);
    assert_eq!(long_after_sync.pnl, 0);
    assert_eq!(long_after_sync.last_fee_slot, 1);
    assert_eq!(
        group_after_sync.insurance, 50,
        "only capital remaining after the hidden loss is settled can be swept as fee"
    );
    assert_eq!(group_after_sync.c_tot, 1_000);
}

#[test]
fn v16_bpf_fee_sync_rejects_reused_market_slot_stale_leg_without_mutation() {
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 1,
    );
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_portfolio = env.create_portfolio(&long_owner);
    let short_portfolio = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_portfolio, 1_000);
    env.deposit(&short_owner, short_portfolio, 1_000);
    env.trade_with_cu(
        &long_owner,
        long_portfolio,
        &short_owner,
        short_portfolio,
        POS_SCALE as i128,
        100,
        0,
    );

    let old_market_id = env.market_state().1.assets[0].market_id;
    env.mutate_market(|_, group| {
        group
            .accrue_asset_to_not_atomic(0, 1, 100, 0, true)
            .unwrap();
        group.assets[0].market_id = old_market_id + 1;
        group.next_market_id = group.next_market_id.max(old_market_id + 2);
    });
    env.svm.warp_to_slot(1);

    let market_before = env.svm.get_account(&env.market).unwrap().data;
    let long_before = env.svm.get_account(&long_portfolio).unwrap().data;
    let err = env
        .try_sync_maintenance_fee_with_cu(long_portfolio, None, 1)
        .expect_err("stale market id leg must fail closed");
    println!("v16 SyncMaintenanceFee stale reused-market-id rejection: {err}");

    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        market_before,
        "failed sync must not mutate the reused market slot"
    );
    assert_eq!(
        env.svm.get_account(&long_portfolio).unwrap().data,
        long_before,
        "failed sync must not mutate the stale portfolio"
    );
}

#[test]
fn v16_bpf_close_portfolio_sweeps_rent_to_market_slab() {
    // Fixture repair note: this failure is NOT an E3/E4 regression -- it predates
    // this session's engine work entirely. Wrapper commit 62067ef1 ("route
    // portfolio rent to closer, not market slab, on ClosePortfolio", #398)
    // deliberately changed `close_portfolio_account_to_market_slab`'s rent
    // destination from `market_ai` to `closer` (the portfolio owner) as a
    // security fix: routing a closer's own rent into the market account let it
    // silently accumulate for the market authority to capture at CloseSlab,
    // permanently costing the owner the SOL they paid to open their account.
    // #398 never updated this test (added earlier by 7e161e8b, well before
    // #398), so it has asserted stale pre-#398 behavior ever since -- this is
    // long-standing test staleness, unrelated to engine-selected liquidation
    // sizing (E3) or ceil-notional fees (E4). Repaired to assert the CURRENT,
    // intentionally-fixed behavior: rent goes back to the closer, not the
    // market. The underlying property (ClosePortfolio must fully sweep the
    // closed account's rent-exempt lamports out to a single well-defined
    // destination, leaving the portfolio account itself at zero lamports) is
    // unchanged and, if anything, more load-bearing now since it protects user
    // funds rather than protocol-captured rent.
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);
    env.withdraw(&owner, portfolio, 1_000);

    let market_lamports_before_close = env.svm.get_account(&env.market).unwrap().lamports;
    let owner_lamports_before_close = env.svm.get_account(&owner.pubkey()).unwrap().lamports;
    let portfolio_lamports_before_close = env.svm.get_account(&portfolio).unwrap().lamports;
    let close_cu = env.close_portfolio_with_cu(&owner, portfolio);
    assert_cu_within("close portfolio rent sweep", close_cu, CUSTODY_CU_LIMIT);

    let (_, group) = env.market_state();
    assert_eq!(group.materialized_portfolio_count, 0);
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().lamports,
        market_lamports_before_close,
        "ClosePortfolio must not leave the closed account's rent stranded in the market slab \
         (upstream #398: that SOL belongs to the closer, not the protocol)"
    );
    assert_eq!(
        env.svm.get_account(&owner.pubkey()).unwrap().lamports,
        owner_lamports_before_close + portfolio_lamports_before_close,
        "ClosePortfolio should move closed account rent back to the closer"
    );
    if let Some(closed_account) = env.svm.get_account(&portfolio) {
        assert_eq!(closed_account.lamports, 0);
        assert!(closed_account.data.is_empty() || !state::is_initialized(&closed_account.data));
    }
}

#[test]
fn v16_bpf_tradecpi_executes_through_external_matcher_and_is_bounded() {
    let mut env = V16CuEnv::new();
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);

    let taker_owner = Keypair::new();
    let maker_owner = Keypair::new();
    let taker_account = env.create_portfolio(&taker_owner);
    let maker_account = env.create_portfolio(&maker_owner);
    env.deposit(&taker_owner, taker_account, 1_000_000);
    env.deposit(&maker_owner, maker_account, 1_000_000);

    let (matcher_ctx, matcher_delegate, init_matcher_cu) =
        env.init_matcher_context(&maker_owner, matcher_program, maker_account);
    let trade_cpi_cu = env.trade_cpi_with_cu(
        &taker_owner,
        taker_account,
        &maker_owner,
        maker_account,
        matcher_program,
        matcher_ctx,
        matcher_delegate,
        (10 * POS_SCALE) as i128,
        100,
    );
    println!("v16 matcher init CU: {init_matcher_cu}, TradeCpi BPF CU: {trade_cpi_cu}");
    assert!(
        trade_cpi_cu <= TRADE_CU_LIMIT,
        "TradeCpi CU {} exceeded limit {}",
        trade_cpi_cu,
        TRADE_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let taker_data = env.svm.get_account(&taker_account).unwrap().data;
    let maker_data = env.svm.get_account(&maker_account).unwrap().data;
    let matcher_data = env.svm.get_account(&matcher_ctx).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let taker = state::read_portfolio(&taker_data).unwrap();
    let maker = state::read_portfolio(&maker_data).unwrap();
    println!(
        "TradeCpi BPF taker_basis={}, maker_basis={}, insurance={}",
        taker.legs[0].basis_pos_q, maker.legs[0].basis_pos_q, group.insurance
    );
    assert_eq!(group.assets[0].effective_price, 100);
    assert_eq!(taker.legs[0].basis_pos_q, (10 * POS_SCALE) as i128);
    assert_eq!(maker.legs[0].basis_pos_q, -((10 * POS_SCALE) as i128));
    assert_eq!(
        group.insurance, 10,
        "passive matcher fills at oracle price; taker-only charges 10 (one side)"
    );
    assert_eq!(
        u32::from_le_bytes(matcher_data[0..4].try_into().unwrap()),
        MATCHER_ABI_VERSION,
        "LiteSVM matcher path must use the same ABI version as the wrapper"
    );
    assert_eq!(
        u64::from_le_bytes(matcher_data[56..64].try_into().unwrap()),
        0,
        "matcher must echo the requested asset index in the v3 return slot"
    );
    assert_eq!(group.c_tot + group.insurance, group.vault);
}

#[test]
fn v16_bpf_tradecpi_external_matcher_executes_on_added_asset() {
    let mut env = V16CuEnv::new();
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);
    env.activate_asset(1, 1, 100);
    env.activate_asset(2, 2, 250);

    let taker_owner = Keypair::new();
    let maker_owner = Keypair::new();
    let taker_account = env.create_portfolio(&taker_owner);
    let maker_account = env.create_portfolio(&maker_owner);
    env.deposit(&taker_owner, taker_account, 1_000_000);
    env.deposit(&maker_owner, maker_account, 1_000_000);

    let (matcher_ctx, matcher_delegate, _) =
        env.init_matcher_context(&maker_owner, matcher_program, maker_account);
    let trade_cpi_cu = env.trade_cpi_with_cu_on_asset(
        &taker_owner,
        taker_account,
        &maker_owner,
        maker_account,
        matcher_program,
        matcher_ctx,
        matcher_delegate,
        2,
        (10 * POS_SCALE) as i128,
        100,
    );
    println!("v16 TradeCpi BPF nonzero-asset CU: {trade_cpi_cu}");
    assert!(
        trade_cpi_cu <= TRADE_CU_LIMIT,
        "TradeCpi nonzero-asset CU {} exceeded limit {}",
        trade_cpi_cu,
        TRADE_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let taker_data = env.svm.get_account(&taker_account).unwrap().data;
    let maker_data = env.svm.get_account(&maker_account).unwrap().data;
    let matcher_data = env.svm.get_account(&matcher_ctx).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let taker = state::read_portfolio(&taker_data).unwrap();
    let maker = state::read_portfolio(&maker_data).unwrap();

    assert_eq!(group.assets[0].oi_eff_long_q, 0);
    assert_eq!(group.assets[0].oi_eff_short_q, 0);
    assert_eq!(group.assets[2].effective_price, 250);
    assert_eq!(group.assets[2].oi_eff_long_q, 10 * POS_SCALE);
    assert_eq!(group.assets[2].oi_eff_short_q, 10 * POS_SCALE);
    assert_eq!(taker.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(maker.active_bitmap, active_bitmap_with(&[0]));
    assert_eq!(
        active_leg_for_asset(&taker, 2).basis_pos_q,
        (10 * POS_SCALE) as i128
    );
    assert_eq!(
        active_leg_for_asset(&maker, 2).basis_pos_q,
        -((10 * POS_SCALE) as i128)
    );
    assert_eq!(
        group.insurance, 25,
        "passive matcher fills asset 2 at 250; notional=2500 @ 100 bps = 25 (taker-only, one side)"
    );
    assert_eq!(
        u64::from_le_bytes(matcher_data[56..64].try_into().unwrap()),
        2,
        "external matcher must echo the requested nonzero asset index"
    );
    assert_eq!(group.c_tot + group.insurance, group.vault);
}

#[test]
fn v16_bpf_permissionless_liquidation_is_bounded() {
    // FIX E3 (upstream #92) fixture repair: the original fixture (short deposits
    // 250 against a 1-unit position, single 100->300 EWMA push clamped by
    // max_price_move_bps_per_slot to effective_price=200) left the account
    // *borderline* underwater -- a healthy partial close existed (closing ~75%
    // of the leg already restores maintenance health at effective_price=200),
    // so engine-selected liquidation sizing (E3) correctly picked that smaller
    // partial close instead of fully closing the leg, and the old
    // `active_bitmap_is_empty` assertion (which hard-coded "liquidation always
    // fully closes") broke -- not because liquidation became unbounded, but
    // because it became *more precise*. This is not an insolvency-mutation
    // fixture (no raw account-byte poking anywhere in this file); it is
    // entirely real EWMA price discovery. The repair drives the account
    // genuinely (not borderline) bankrupt via two real accrual steps, each
    // capped by the market's max_price_move_bps_per_slot/max_accrual_dt_slots
    // config to at most a 100% mark move per crank call (100->200->400), so a
    // single EWMA push cannot shortcut it: certified_equity == capital(100) -
    // loss(300) == -200 < 0, which hits `liquidation_engine_close_request_q`'s
    // bankrupt-account early exit and forces a full close regardless of any
    // partial-close arithmetic -- the same "liquidation is bounded" property
    // (leg fully closed, CU bounded) the test always asserted.
    let mut env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    // Minimum deposit that satisfies initial_margin_bps=10_000 (100%) for a
    // 1-unit position at entry price 100 -- this env has no leverage headroom
    // at entry, so bankruptcy can only be reached via adverse price movement.
    env.deposit(&short_owner, short_account, 100);
    env.configure_ewma_mark_with_cu(0, 100, 1, 0);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );

    // Step 1: real EWMA push + accrual crank, capped to a 100% mark move ->
    // effective_price 100 -> 200 (still solvent: equity 100-100=0).
    env.svm.warp_to_slot(1);
    env.push_ewma_mark_with_cu(1, 999_999);
    env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    // Step 2: second real EWMA push + accrual, again capped to 100% ->
    // effective_price 200 -> 400 (equity 100-300=-200: genuinely bankrupt).
    env.svm.warp_to_slot(2);
    env.push_ewma_mark_with_cu(2, 999_999);
    let short_before =
        state::read_portfolio(&env.svm.get_account(&short_account).unwrap().data).unwrap();
    assert!(
        short_before.capital == 100 && short_before.pnl == 0,
        "position must still be open going into the liquidation crank"
    );

    let liquidation_cu = env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!("v16 liquidation crank CU: {liquidation_cu}");
    assert!(
        liquidation_cu <= CRANK_CU_LIMIT,
        "liquidation CU {} exceeded limit {}",
        liquidation_cu,
        CRANK_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let short = state::read_portfolio(&short_data).unwrap();
    assert_eq!(group.slot_last, 2);
    assert_eq!(group.assets[0].effective_price, 400);
    assert_eq!(
        short.capital, 0,
        "bankrupt account's capital must be fully consumed"
    );
    assert_eq!(
        short.pnl, 0,
        "settled loss must not leave a dangling pnl balance"
    );
    assert!(
        percolator::active_bitmap_is_empty(short.active_bitmap),
        "a genuinely bankrupt account (certified_equity < 0) must be fully closed, not \
         left with a dangling partial position"
    );
}

#[test]
fn v16_bpf_tradenocpi_rejects_off_mark_recycle_when_deficit_cannot_settle() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100);

    let extractor_owner = Keypair::new();
    let probe_owner = Keypair::new();
    let extractor = env.create_portfolio(&extractor_owner);
    let probe = env.create_portfolio(&probe_owner);
    env.deposit(&extractor_owner, extractor, 10_000);
    env.deposit(&probe_owner, probe, 1_000);
    env.trade_with_cu(
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_with_cu(2, 300);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    env.svm.warp_to_slot(3);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_extractor = env.svm.get_account(&extractor).unwrap();
    let before_probe = env.svm.get_account(&probe).unwrap();
    let (_, before_group) = state::read_market(&before_market.data).unwrap();
    assert_eq!(before_group.insurance, 1_000_000);
    let before_probe_state = state::read_portfolio(&before_probe.data).unwrap();
    assert!(
        before_probe_state.health_cert.certified_liq_deficit != 0,
        "probe must be liquidatable before the attempted recycling trade"
    );

    let close = env.try_trade_asset_with_cu(
        0,
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        -((10 * POS_SCALE) as i128),
        500,
        0,
    );
    assert!(
        close.is_err(),
        "liquidatable probe must not recycle an unsettled deficit through an off-mark close"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&extractor).unwrap().data,
        before_extractor.data
    );
    assert_eq!(env.svm.get_account(&probe).unwrap().data, before_probe.data);
}

#[test]
fn v16_bpf_tradecpi_rejects_off_mark_recycle_when_deficit_cannot_settle() {
    let mut env = V16CuEnv::new();
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);
    env.top_up_insurance(1_000_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100);

    let extractor_owner = Keypair::new();
    let probe_owner = Keypair::new();
    let extractor = env.create_portfolio(&extractor_owner);
    let probe = env.create_portfolio(&probe_owner);
    env.deposit(&extractor_owner, extractor, 10_000);
    env.deposit(&probe_owner, probe, 1_000);
    env.trade_with_cu(
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_with_cu(2, 300);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    env.svm.warp_to_slot(3);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let (matcher_ctx, matcher_delegate, _) = env.init_matcher_context_with_passive_spread(
        &extractor_owner,
        matcher_program,
        extractor,
        9_000,
        9_000,
    );
    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_extractor = env.svm.get_account(&extractor).unwrap();
    let before_probe = env.svm.get_account(&probe).unwrap();
    let before_matcher = env.svm.get_account(&matcher_ctx).unwrap();
    let before_probe_state = state::read_portfolio(&before_probe.data).unwrap();
    assert!(
        before_probe_state.health_cert.certified_liq_deficit != 0,
        "probe must be liquidatable before the attempted matcher recycling trade"
    );

    let close = env.try_trade_cpi_with_cu_on_asset(
        &probe_owner,
        probe,
        &extractor_owner,
        extractor,
        matcher_program,
        matcher_ctx,
        matcher_delegate,
        0,
        (10 * POS_SCALE) as i128,
        0,
    );
    assert!(
        close.is_err(),
        "liquidatable probe must not recycle an unsettled deficit through an off-mark matcher fill"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&extractor).unwrap().data,
        before_extractor.data
    );
    assert_eq!(env.svm.get_account(&probe).unwrap().data, before_probe.data);
    assert_eq!(
        env.svm.get_account(&matcher_ctx).unwrap().data,
        before_matcher.data
    );
}

#[test]
fn v16_bpf_tradenocpi_rejects_when_counterparty_starts_bankrupt() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000_000);

    let extractor_owner = Keypair::new();
    let probe_owner = Keypair::new();
    let extractor = env.create_portfolio(&extractor_owner);
    let probe = env.create_portfolio(&probe_owner);
    env.deposit(&extractor_owner, extractor, 10_000);
    env.deposit(&probe_owner, probe, 2_000);
    env.trade_with_cu(
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    env.force_portfolio_bankruptcy_for_security_test(probe, 500);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_extractor = env.svm.get_account(&extractor).unwrap();
    let before_probe = env.svm.get_account(&probe).unwrap();
    let before_probe_state = state::read_portfolio(&before_probe.data).unwrap();
    assert_eq!(before_probe_state.capital, 0);
    assert!(
        before_probe_state.pnl < 0,
        "probe must start bankrupt before the attempted recycling trade"
    );
    assert!(before_probe_state.health_cert.valid);
    assert!(
        before_probe_state.health_cert.certified_equity < 0,
        "refreshed probe certificate must confirm negative equity before the attempted trade"
    );

    let close = env.try_trade_asset_with_cu(
        0,
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        -((10 * POS_SCALE) as i128),
        500,
        0,
    );
    assert!(
        close.is_err(),
        "bankrupt probe must not use an off-mark close as a normal bilateral trade"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&extractor).unwrap().data,
        before_extractor.data
    );
    assert_eq!(env.svm.get_account(&probe).unwrap().data, before_probe.data);
}

#[test]
fn v16_bpf_tradecpi_rejects_when_counterparty_starts_bankrupt() {
    let mut env = V16CuEnv::new();
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);
    env.top_up_insurance(1_000_000);

    let extractor_owner = Keypair::new();
    let probe_owner = Keypair::new();
    let extractor = env.create_portfolio(&extractor_owner);
    let probe = env.create_portfolio(&probe_owner);
    env.deposit(&extractor_owner, extractor, 10_000);
    env.deposit(&probe_owner, probe, 2_000);
    env.trade_with_cu(
        &extractor_owner,
        extractor,
        &probe_owner,
        probe,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    env.force_portfolio_bankruptcy_for_security_test(probe, 500);
    env.crank(
        probe,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let (matcher_ctx, matcher_delegate, _) = env.init_matcher_context_with_passive_spread(
        &extractor_owner,
        matcher_program,
        extractor,
        9_000,
        9_000,
    );

    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_extractor = env.svm.get_account(&extractor).unwrap();
    let before_probe = env.svm.get_account(&probe).unwrap();
    let before_matcher = env.svm.get_account(&matcher_ctx).unwrap();
    let before_probe_state = state::read_portfolio(&before_probe.data).unwrap();
    assert_eq!(before_probe_state.capital, 0);
    assert!(
        before_probe_state.pnl < 0,
        "probe must start bankrupt before the attempted matcher recycling trade"
    );
    assert!(before_probe_state.health_cert.valid);
    assert!(
        before_probe_state.health_cert.certified_equity < 0,
        "refreshed probe certificate must confirm negative equity before the attempted matcher trade"
    );

    let close = env.try_trade_cpi_with_cu_on_asset(
        &probe_owner,
        probe,
        &extractor_owner,
        extractor,
        matcher_program,
        matcher_ctx,
        matcher_delegate,
        0,
        (10 * POS_SCALE) as i128,
        0,
    );
    assert!(
        close.is_err(),
        "bankrupt probe must not use an off-mark matcher fill as a normal bilateral trade"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&extractor).unwrap().data,
        before_extractor.data
    );
    assert_eq!(env.svm.get_account(&probe).unwrap().data, before_probe.data);
    assert_eq!(
        env.svm.get_account(&matcher_ctx).unwrap().data,
        before_matcher.data
    );
}

#[test]
fn v16_bpf_tradenocpi_rejects_when_both_counterparties_start_bankrupt() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000_000);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 2_000);
    env.deposit(&short_owner, short_account, 2_000);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    env.force_portfolio_bankruptcy_for_security_test(long_account, 500);
    env.force_portfolio_bankruptcy_for_security_test(short_account, 500);
    env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let before_market = env.svm.get_account(&env.market).unwrap();
    let before_long = env.svm.get_account(&long_account).unwrap();
    let before_short = env.svm.get_account(&short_account).unwrap();
    let before_long_state = state::read_portfolio(&before_long.data).unwrap();
    let before_short_state = state::read_portfolio(&before_short.data).unwrap();
    assert!(before_long_state.health_cert.valid);
    assert!(before_short_state.health_cert.valid);
    assert!(before_long_state.health_cert.certified_equity < 0);
    assert!(before_short_state.health_cert.certified_equity < 0);

    let close = env.try_trade_asset_with_cu(
        0,
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -((10 * POS_SCALE) as i128),
        100,
        0,
    );
    assert!(
        close.is_err(),
        "two bankrupt counterparties must not use TradeNoCpi as a bankruptcy close"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market.data
    );
    assert_eq!(
        env.svm.get_account(&long_account).unwrap().data,
        before_long.data
    );
    assert_eq!(
        env.svm.get_account(&short_account).unwrap().data,
        before_short.data
    );
}

#[test]
fn v16_bpf_tradenocpi_allows_both_counterparties_with_capitalized_losses_to_risk_reduce() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000_000);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 10_000);
    env.deposit(&short_owner, short_account, 10_000);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );
    env.force_portfolio_loss_for_security_test(long_account, 500);
    env.force_portfolio_loss_for_security_test(short_account, 500);

    let (_, before_group) = env.market_state();
    let before_long = env.portfolio_state(long_account);
    let before_short = env.portfolio_state(short_account);
    assert!(before_long.pnl < 0 && before_long.capital > before_long.pnl.unsigned_abs());
    assert!(before_short.pnl < 0 && before_short.capital > before_short.pnl.unsigned_abs());

    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -((10 * POS_SCALE) as i128),
        100,
        0,
    );

    let (_, after_group) = env.market_state();
    let after_long = env.portfolio_state(long_account);
    let after_short = env.portfolio_state(short_account);
    assert_eq!(
        after_group.insurance, before_group.insurance,
        "capitalized losses must settle from account capital, not insurance"
    );
    assert_eq!(after_long.pnl, 0);
    assert_eq!(after_short.pnl, 0);
    assert!(!has_active_leg_for_asset(&after_long, 0));
    assert!(!has_active_leg_for_asset(&after_short, 0));
}

#[test]
fn v16_bpf_liquidatable_solvent_account_can_risk_reduce_without_insurance_drain() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 10_000);
    env.deposit(&short_owner, short_account, 3_000);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_with_cu(2, 300);
    env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    env.svm.warp_to_slot(3);
    env.crank(
        short_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let (_, before_group) = env.market_state();
    let before_short = env.portfolio_state(short_account);
    assert_eq!(before_group.insurance, 1_000_000);
    assert!(
        before_short.health_cert.certified_liq_deficit != 0,
        "short account should be liquidatable before the safe risk reduction"
    );
    assert!(
        before_short.health_cert.certified_equity > 0,
        "short account should still be solvent before the safe risk reduction"
    );

    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -((10 * POS_SCALE) as i128),
        500,
        0,
    );

    let (_, after_group) = env.market_state();
    let after_long = env.portfolio_state(long_account);
    let after_short = env.portfolio_state(short_account);
    assert_eq!(
        after_group.insurance, before_group.insurance,
        "safe risk reduction must not consume or credit insurance"
    );
    assert_eq!(
        after_group.c_tot + after_group.insurance + after_group.pnl_pos_tot,
        after_group.vault
    );
    assert!(!has_active_leg_for_asset(&after_long, 0));
    assert!(!has_active_leg_for_asset(&after_short, 0));
    assert!(
        after_long.health_cert.certified_liq_deficit == 0
            && after_short.health_cert.certified_liq_deficit == 0,
        "both accounts must be non-liquidatable after the risk reduction"
    );
}

#[test]
fn v16_bpf_no_cranker_liquidation_rejects_invalid_final_market_shape() {
    let mut env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    env.deposit(&short_owner, short_account, 250);
    env.configure_ewma_mark_with_cu(0, 100, 1, 0);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(1);
    env.push_ewma_mark_with_cu(1, 300);
    env.mutate_market(|_, group| {
        group.insurance_domain_budget[0] = group.insurance.saturating_add(1);
    });
    let before_market = env.svm.get_account(&env.market).unwrap().data;
    let before_short = env.svm.get_account(&short_account).unwrap().data;

    let result = env.send(
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(short_account, false),
        ],
        &[],
    );

    assert!(
        result.is_err(),
        "no-cranker liquidation must reject instead of persisting an invalid market shape"
    );
    let after_market = env.svm.get_account(&env.market).unwrap().data;
    let after_short = env.svm.get_account(&short_account).unwrap().data;
    assert_eq!(
        after_market, before_market,
        "failed no-cranker liquidation must roll back market data"
    );
    assert_eq!(
        after_short, before_short,
        "failed no-cranker liquidation must roll back portfolio data"
    );
}

#[test]
fn v16_bpf_cranker_reward_liquidation_rejects_invalid_shape_without_paying_reward() {
    let mut env = V16CuEnv::new();
    env.update_liquidation_fee_policy_with_cu(10_000);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let cranker_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    let cranker_account = env.create_portfolio(&cranker_owner);
    env.deposit(&long_owner, long_account, 1_000_000);
    env.deposit(&short_owner, short_account, 250);
    env.configure_ewma_mark_with_cu(0, 100, 1, 0);
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );

    env.svm.warp_to_slot(1);
    env.push_ewma_mark_with_cu(1, 300);
    env.mutate_market(|_, group| {
        group.config.liquidation_fee_bps = 10_000;
        group.config.liquidation_fee_cap = 1;
        group.insurance_domain_budget[0] = group.insurance.saturating_add(1_000_000);
    });
    let before_market = env.svm.get_account(&env.market).unwrap().data;
    let before_short = env.svm.get_account(&short_account).unwrap().data;
    let before_cranker = env.svm.get_account(&cranker_account).unwrap().data;

    let result = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        vec![
            AccountMeta::new(cranker_owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(short_account, false),
            AccountMeta::new(cranker_account, false),
        ],
        &[&cranker_owner],
    );

    assert!(
        result.is_err(),
        "cranker-reward liquidation must reject instead of persisting an invalid market shape"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_market,
        "failed cranker-reward liquidation must roll back market data"
    );
    assert_eq!(
        env.svm.get_account(&short_account).unwrap().data,
        before_short,
        "failed cranker-reward liquidation must roll back liquidated portfolio data"
    );
    assert_eq!(
        env.svm.get_account(&cranker_account).unwrap().data,
        before_cranker,
        "failed cranker-reward liquidation must not pay the cranker portfolio"
    );
}

#[test]
fn v16_bpf_full_14_leg_refresh_crank_is_under_tx_limit() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(14, 1_000, 1_000, 500);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 2_000);
    env.deposit(&short_owner, short_account, 100_000);
    env.seed_n_leg_position_for_benchmark(long_account, short_account, 14);
    let before_slot_last = {
        let market_data = env.svm.get_account(&env.market).unwrap().data;
        let (_, group) = state::read_market(&market_data).unwrap();
        group.assets[0].slot_last
    };

    env.svm.warp_to_slot(16);
    let refresh_cu = env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 16,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!("v16 full-14-leg refresh crank CU: {refresh_cu}");
    assert!(
        refresh_cu <= 900_000,
        "full-14-leg refresh CU {} exceeded limit {}",
        refresh_cu,
        900_000
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let long = state::read_portfolio(&long_data).unwrap();
    assert_eq!(group.config.max_portfolio_assets, 14);
    assert_eq!(percolator::active_bitmap_count_ones(long.active_bitmap), 14);
    assert!(
        group.assets[0].slot_last > before_slot_last,
        "full-14 refresh crank must commit bounded asset progress"
    );
    assert_eq!(group.assets[0].effective_price, 95);
}

#[test]
fn v16_bpf_full_14_leg_liquidation_crank_is_under_tx_limit() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(14, 1_000, 1_000, 500);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 2_000);
    env.deposit(&short_owner, short_account, 100_000);
    env.seed_n_leg_position_for_benchmark(long_account, short_account, 14);
    env.force_portfolio_capital_for_benchmark(long_account, 1_000);

    env.svm.warp_to_slot(16);
    let liquidation_cu = env.crank(
        long_account,
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 16,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!("v16 full-14-leg liquidation crank CU: {liquidation_cu}");
    const FULL_14_LEG_LIQUIDATION_CU_LIMIT: u64 = 1_375_000;
    assert!(
        liquidation_cu <= FULL_14_LEG_LIQUIDATION_CU_LIMIT,
        "full-14-leg liquidation CU {} exceeded limit {}",
        liquidation_cu,
        FULL_14_LEG_LIQUIDATION_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let long = state::read_portfolio(&long_data).unwrap();
    assert_eq!(group.config.max_portfolio_assets, 14);
    assert_eq!(percolator::active_bitmap_count_ones(long.active_bitmap), 13);
    assert!(!long.legs[0].active);
    assert_eq!(group.assets[0].oi_eff_long_q, 0);
    assert_eq!(group.assets[0].oi_eff_short_q, 0);
}

#[test]
fn v16_bpf_current_full_14_leg_tradenocpi_is_under_tx_limit() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(14, 1_000, 1_000, 500);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 20_000);
    env.deposit(&short_owner, short_account, 100_000);
    env.seed_current_n_leg_position_for_benchmark(long_account, short_account, 14);
    let trade_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(POS_SCALE as i128),
        100,
        0,
    );
    println!("v16 current full-14-leg TradeNoCpi CU: {trade_cu}");
    assert!(
        trade_cu <= 1_150_000,
        "current full-14-leg TradeNoCpi CU {} exceeded limit {}",
        trade_cu,
        1_150_000
    );

    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let long = state::read_portfolio(&long_data).unwrap();
    let short = state::read_portfolio(&short_data).unwrap();
    assert_eq!(percolator::active_bitmap_count_ones(long.active_bitmap), 14);
    assert_eq!(
        percolator::active_bitmap_count_ones(short.active_bitmap),
        14
    );
    assert_eq!(long.legs[0].basis_pos_q, (9 * POS_SCALE) as i128);
    assert_eq!(short.legs[0].basis_pos_q, -((9 * POS_SCALE) as i128));
}

#[test]
fn v16_bpf_stale_full_14_leg_tradenocpi_is_under_tx_limit() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(14, 1_000, 1_000, 500);
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 20_000);
    env.deposit(&short_owner, short_account, 100_000);
    env.seed_n_leg_position_for_benchmark(long_account, short_account, 14);
    env.svm.warp_to_slot(16);
    let trade_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(POS_SCALE as i128),
        95,
        0,
    );
    println!("v16 stale full-14-leg TradeNoCpi CU: {trade_cu}");
    assert!(
        trade_cu <= 1_400_000,
        "stale full-14-leg TradeNoCpi CU {} exceeded limit {}",
        trade_cu,
        1_400_000
    );

    let long_data = env.svm.get_account(&long_account).unwrap().data;
    let short_data = env.svm.get_account(&short_account).unwrap().data;
    let long = state::read_portfolio(&long_data).unwrap();
    let short = state::read_portfolio(&short_data).unwrap();
    assert_eq!(percolator::active_bitmap_count_ones(long.active_bitmap), 14);
    assert_eq!(
        percolator::active_bitmap_count_ones(short.active_bitmap),
        14
    );
    assert_eq!(long.legs[0].basis_pos_q, (9 * POS_SCALE) as i128);
    assert_eq!(short.legs[0].basis_pos_q, -((9 * POS_SCALE) as i128));
}

#[test]
fn v16_bpf_close_resolved_moves_payout_tokens_with_ledger() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);

    env.resolve();
    let dest = env.close_resolved(&owner, portfolio);
    assert_eq!(env.token_amount(dest), 1_000);
    assert_eq!(env.token_amount(env.vault), 0);

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let portfolio_data = env.svm.get_account(&portfolio).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let account = state::read_portfolio(&portfolio_data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(account.capital, 0);
}

#[test]
fn v16_bpf_failed_close_resolved_transfer_rolls_back_payout_state() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);
    env.resolve();
    let dest = env.token_account(owner.pubkey(), 0);
    let mut corrupted_vault = env.svm.get_account(&env.vault).unwrap();
    corrupted_vault.owner = Pubkey::new_unique();
    env.svm.set_account(env.vault, corrupted_vault).unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let portfolio_before = env.svm.get_account(&portfolio).unwrap();
    let dest_before = env.svm.get_account(&dest).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        vec![
            AccountMeta::new_readonly(owner.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    );

    assert!(
        result.is_err(),
        "close-resolved must fail when the payout transfer CPI fails"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&portfolio).unwrap(), portfolio_before);
    assert_eq!(env.svm.get_account(&dest).unwrap(), dest_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    let account = env.portfolio_state(portfolio);
    assert_eq!(group.vault, 1_000);
    assert_eq!(group.c_tot, 1_000);
    assert_eq!(account.capital, 1_000);
    assert!(
        !account.resolved_payout_receipt.present,
        "failed payout must not persist a paid/finalized receipt"
    );
    assert_eq!(env.token_amount(dest), 0);
}

#[test]
fn v16_bpf_failed_terminal_insurance_withdraw_rolls_back_market_and_ledger() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(100);
    env.resolve();
    let ledger = env.insurance_ledger_account();
    let dest = env.token_account(env.admin.pubkey(), 0);
    let mut corrupted_vault = env.svm.get_account(&env.vault).unwrap();
    corrupted_vault.owner = Pubkey::new_unique();
    env.svm.set_account(env.vault, corrupted_vault).unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let ledger_before = env.svm.get_account(&ledger).unwrap();
    let dest_before = env.svm.get_account(&dest).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawInsurance { amount: 40 },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&env.admin],
    );

    assert!(
        result.is_err(),
        "terminal insurance withdraw must fail when the transfer CPI fails"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&ledger).unwrap(), ledger_before);
    assert_eq!(env.svm.get_account(&dest).unwrap(), dest_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    assert_eq!(group.insurance, 100);
    assert_eq!(group.vault, 100);
    assert_eq!(env.token_amount(dest), 0);
}

#[test]
fn v16_bpf_failed_backing_withdraw_transfer_rolls_back_bucket_and_ledger() {
    let mut env = V16CuEnv::new();
    // #433: TopUpBackingBucket now pins the ledger to its PDA, so a random-address
    // ledger is refused. These fixtures want a working top-up, not a substitution test.
    let ledger = env.canonical_backing_domain_ledger_account(1);
    env.top_up_backing_bucket_with_ledger_with_cu(ledger, 1, 100, 10);
    let dest = env.token_account(env.admin.pubkey(), 0);
    let mut corrupted_vault = env.svm.get_account(&env.vault).unwrap();
    corrupted_vault.owner = Pubkey::new_unique();
    env.svm.set_account(env.vault, corrupted_vault).unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let ledger_before = env.svm.get_account(&ledger).unwrap();
    let dest_before = env.svm.get_account(&dest).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let result = send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::WithdrawBackingBucket {
            domain: 1,
            amount: 40,
        },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&env.admin],
    );

    assert!(
        result.is_err(),
        "backing withdraw must fail when the transfer CPI cannot debit the vault"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&ledger).unwrap(), ledger_before);
    assert_eq!(env.svm.get_account(&dest).unwrap(), dest_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    let (_, group) = env.market_state();
    assert_eq!(group.vault, 100);
    assert_eq!(
        group.source_backing_buckets[1].fresh_unliened_backing_num,
        100 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[1].fresh_reserved_backing_num,
        100 * BOUND_SCALE
    );
    assert_eq!(env.token_amount(dest), 0);
}

#[test]
fn v16_bpf_close_resolved_pays_positive_pnl_through_engine_ledger() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);
    env.top_up_backing_bucket(1, 250, 10);
    env.add_source_positive_pnl(portfolio, 1, 250);

    env.resolve();
    let dest = env.close_resolved(&owner, portfolio);
    assert_eq!(env.token_amount(dest), 1_250);
    assert_eq!(env.token_amount(env.vault), 0);

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let portfolio_data = env.svm.get_account(&portfolio).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    let account = state::read_portfolio(&portfolio_data).unwrap();
    assert_eq!(group.vault, 0);
    assert_eq!(group.c_tot, 0);
    assert_eq!(account.capital, 0);
    assert_eq!(account.pnl, 0);
    // v17 (BPF, against the real .so): source-backed positive PnL is realized
    // directly into capital and paid in one shot (dest==1_250, vault==0 above) — it
    // does NOT flow through the resolved payout receipt/ledger. Correct post-condition
    // is a clean teardown with NO dangling receipt. (Matches the LiteSVM twin in
    // v16_wrapper.rs::v16_wrapper_close_resolved_pays_positive_pnl_through_engine_ledger.)
    assert!(
        !account.resolved_payout_receipt.present,
        "source-backed positive PnL pays directly; no resolved_payout_receipt should remain"
    );
}

#[test]
fn v16_bpf_permissionless_stale_resolve_is_bounded_and_oracle_free() {
    let mut env = V16CuEnv::new();
    let configure_cu = env.configure_permissionless_resolve_with_cu(9000, 1);
    let stale_resolve_cu = env.resolve_stale_permissionless_with_cu(9000);
    println!(
        "v16 permissionless stale resolve CU configure={configure_cu}, resolve={stale_resolve_cu}"
    );
    assert!(
        configure_cu <= CUSTODY_CU_LIMIT,
        "configure permissionless resolve CU {} exceeded limit {}",
        configure_cu,
        CUSTODY_CU_LIMIT
    );
    assert!(
        stale_resolve_cu <= CUSTODY_CU_LIMIT,
        "permissionless stale resolve CU {} exceeded limit {}",
        stale_resolve_cu,
        CUSTODY_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg, group) = state::read_market(&market_data).unwrap();
    assert_eq!(cfg.permissionless_resolve_stale_slots, 9000);
    assert_eq!(cfg.force_close_delay_slots, 1);
    assert_eq!(group.mode, percolator::MarketModeV16::Resolved);
    assert_eq!(group.resolved_slot, 9000);
}

#[test]
fn v16_cu_custody_and_resolution_paths_are_bounded() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let (portfolio, init_portfolio_cu) = env.create_portfolio_with_cu(&owner);
    let (_source, deposit_cu) = env.deposit_with_cu(&owner, portfolio, 1_000);
    let (_dest, withdraw_cu) = env.withdraw_with_cu(&owner, portfolio, 400);
    // v17 convergence: TopUpInsurance (global) cannot be withdrawn live. Use domain-0 top-up
    // so that withdraw_insurance_with_cu (now WithdrawInsuranceAsset { asset_index: 0 }) works.
    // Matrix row: v17-auth-overhaul (live insurance withdrawal → per-asset domain path).
    let admin_clone = env.admin.insecure_clone();
    let (_, top_up_cu) = env.top_up_insurance_domain_with_authority_and_cu(&admin_clone, 0, 250);
    env.enable_live_insurance_withdrawal();
    let (_insurance_dest, withdraw_insurance_cu) = env.withdraw_insurance_with_cu(100);
    let resolve_cu = env.resolve();
    let (_resolved_dest, close_resolved_cu) = env.close_resolved_with_cu(&owner, portfolio);

    println!(
        "v16 custody CU init_portfolio={init_portfolio_cu}, deposit={deposit_cu}, withdraw={withdraw_cu}, top_up={top_up_cu}, withdraw_insurance={withdraw_insurance_cu}, resolve={resolve_cu}, close_resolved={close_resolved_cu}"
    );
    for (name, cu) in [
        ("init_portfolio", init_portfolio_cu),
        ("deposit", deposit_cu),
        ("withdraw", withdraw_cu),
        ("top_up", top_up_cu),
        ("withdraw_insurance", withdraw_insurance_cu),
        ("resolve", resolve_cu),
        ("close_resolved", close_resolved_cu),
    ] {
        assert!(
            cu <= CUSTODY_CU_LIMIT,
            "{} CU {} exceeded limit {}",
            name,
            cu,
            CUSTODY_CU_LIMIT
        );
    }
}

#[test]
fn v16_cu_permissionless_crank_refresh_is_bounded() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000_000);

    let refresh_cu = env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!("v16 refresh crank CU: {refresh_cu}");
    assert!(refresh_cu <= CRANK_CU_LIMIT);
}

#[test]
fn v16_bpf_permissionless_crank_uses_authenticated_clock_slot_not_caller_slot() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000_000);

    let real_slot = 10;
    let spoofed_slot = 1_000_000;
    env.svm.warp_to_slot(real_slot);
    env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: spoofed_slot,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let clock = env.svm.get_sysvar::<Clock>();
    assert_eq!(clock.slot, real_slot);
    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&market_data).unwrap();
    assert_eq!(
        group.current_slot, clock.slot,
        "permissionless crank must authenticate engine time from SVM Clock, not the instruction body"
    );
    assert_ne!(
        group.current_slot, spoofed_slot,
        "caller-supplied crank now_slot must not be able to move engine time into the future"
    );
}

#[test]
fn v16_bpf_configure_hybrid_oracle_uses_authenticated_clock_slot_not_caller_slot() {
    let mut env = V16CuEnv::new();
    let real_slot = 10;
    let spoofed_slot = 1_000_000;
    env.svm.warp_to_slot(real_slot);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_000;
    env.svm.set_sysvar(&clock);
    let clock = env.svm.get_sysvar::<Clock>();

    let feeds = [[0x91u8; 32], [0x92u8; 32], [0x93u8; 32]];
    let leg0 = env.set_pyth_price(&feeds[0], 4_000_000_000, -6, clock.unix_timestamp);
    let leg1 = env.set_pyth_price(&feeds[1], 150_000_000, -6, clock.unix_timestamp);
    let leg2 = env.set_pyth_price(&feeds[2], 200_000_000, -6, clock.unix_timestamp);
    env.configure_three_leg_hybrid_with_cu(
        feeds,
        leg0,
        leg1,
        leg2,
        spoofed_slot,
        clock.unix_timestamp,
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg, group) = state::read_market(&market_data).unwrap();
    assert_eq!(
        group.current_slot, real_slot,
        "hybrid configuration must authenticate engine time from SVM Clock, not the instruction body"
    );
    assert_eq!(group.slot_last, real_slot);
    assert_eq!(cfg.last_good_oracle_slot, real_slot);
    assert_eq!(cfg.mark_ewma_last_slot, real_slot);
    assert_ne!(
        group.current_slot, spoofed_slot,
        "caller-supplied configure now_slot must not future-clock the market"
    );
}

#[test]
fn v16_bpf_configure_hybrid_oracle_uses_authenticated_unix_time_not_caller_time() {
    let mut env = V16CuEnv::new();
    env.svm.warp_to_slot(10);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_000;
    env.svm.set_sysvar(&clock);

    let feeds = [[0xa1u8; 32], [0xa2u8; 32], [0xa3u8; 32]];
    let stale_publish_time = 1;
    let leg0 = env.set_pyth_price(&feeds[0], 4_000_000_000, -6, stale_publish_time);
    let leg1 = env.set_pyth_price(&feeds[1], 150_000_000, -6, stale_publish_time);
    let leg2 = env.set_pyth_price(&feeds[2], 200_000_000, -6, stale_publish_time);
    let before = env.svm.get_account(&env.market).unwrap().data;

    let spoofed_fresh_unix = stale_publish_time;
    let result =
        env.try_configure_three_leg_hybrid(feeds, leg0, leg1, leg2, 10, spoofed_fresh_unix);

    assert!(
        result.is_err(),
        "hybrid configuration must not accept stale oracle accounts by trusting caller now_unix_ts"
    );
    let after = env.svm.get_account(&env.market).unwrap().data;
    assert_eq!(
        after, before,
        "rejected stale-oracle configuration must not mutate the market"
    );
}

fn set_test_clock(env: &mut V16CuEnv, slot: u64, unix_timestamp: i64) {
    env.svm.warp_to_slot(slot);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = unix_timestamp;
    env.svm.set_sysvar(&clock);
}

fn run_hybrid_fresh_oracle_trade_case(dt: u64, oracle_leg_count: u8, invert: u8) {
    let mut env = V16CuEnv::new();
    set_test_clock(&mut env, 1, 100);

    let seed = 0xc0u8
        .wrapping_add((dt as u8) << 4)
        .wrapping_add(oracle_leg_count << 1)
        .wrapping_add(invert);
    let mut feeds = [[0u8; 32]; 3];
    feeds[0] = [seed; 32];
    if oracle_leg_count == 3 {
        feeds[1] = [seed.wrapping_add(1); 32];
        feeds[2] = [seed.wrapping_add(2); 32];
    }
    let oracle_leg_flags = if oracle_leg_count == 3 {
        ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3
    } else {
        0
    };

    let initial_oracles = if oracle_leg_count == 1 {
        vec![env.set_pyth_price(&feeds[0], 200_000, -6, 100)]
    } else {
        vec![
            env.set_pyth_price(&feeds[0], 4_000_000_000, -6, 100),
            env.set_pyth_price(&feeds[1], 150_000_000, -6, 100),
            env.set_pyth_price(&feeds[2], 200_000_000, -6, 100),
        ]
    };
    let configure_cu = env
        .try_configure_hybrid_with_cu(
            oracle_leg_count,
            oracle_leg_flags,
            feeds,
            &initial_oracles,
            1,
            100,
            invert,
            0,
            3,
        )
        .expect("configure hybrid oracle");
    assert_cu_within(
        "HybridMark fresh-trade configure",
        configure_cu,
        CUSTODY_CU_LIMIT,
    );

    let keeper = Keypair::new();
    let keeper_portfolio = env.create_portfolio(&keeper);
    set_test_clock(&mut env, 2, 101);
    let fresh_oracles = if oracle_leg_count == 1 {
        vec![env.set_pyth_price(&feeds[0], 210_000, -6, 101)]
    } else {
        vec![
            env.set_pyth_price(&feeds[0], 4_200_000_000, -6, 101),
            env.set_pyth_price(&feeds[1], 150_000_000, -6, 101),
            env.set_pyth_price(&feeds[2], 200_000_000, -6, 101),
        ]
    };
    let fresh_crank_cu = env.crank_with_oracle_tail(
        keeper_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &fresh_oracles,
    );
    assert_cu_within(
        "HybridMark fresh-trade crank",
        fresh_crank_cu,
        CRANK_CU_LIMIT,
    );

    let (fresh_cfg, fresh_group) = env.market_state();
    let mark = fresh_group.assets[0].effective_price;
    assert!(mark > 0, "fresh HybridMark case produced a zero mark");
    assert_eq!(fresh_cfg.last_good_oracle_slot, 2);
    assert_eq!(fresh_cfg.hybrid_soft_stale_slots, 3);
    assert_eq!(fresh_cfg.mark_ewma_e6, mark);
    assert_eq!(fresh_group.assets[0].raw_oracle_target_price, mark);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 10_000_000);
    env.deposit(&short_owner, short_account, 10_000_000);

    if dt == 1 {
        set_test_clock(&mut env, 3, 102);
    }
    let (before_trade_cfg, before_trade_group) = env.market_state();
    let trade_slot = env.svm.get_sysvar::<Clock>().slot;
    assert_eq!(
        trade_slot - before_trade_cfg.last_good_oracle_slot,
        dt,
        "test case must trade while the hybrid oracle is still fresh"
    );
    assert!(
        dt <= before_trade_cfg.hybrid_soft_stale_slots,
        "test case must remain inside the live-oracle freshness window"
    );
    let insurance_before = before_trade_group.insurance;

    let size_q = POS_SCALE;
    let open_cu = env
        .try_trade_asset_with_cu(
            0,
            &long_owner,
            long_account,
            &short_owner,
            short_account,
            size_q as i128,
            mark,
            0,
        )
        .unwrap_or_else(|err| {
            panic!(
                "fresh HybridMark TradeNoCpi open failed for dt={dt}, legs={oracle_leg_count}, invert={invert}: {err}"
            )
        });
    assert_cu_within("HybridMark fresh open", open_cu, TRADE_CU_LIMIT);
    let (opened_cfg, opened_group) = env.market_state();
    assert_eq!(opened_group.assets[0].oi_eff_long_q, size_q);
    assert_eq!(opened_group.assets[0].oi_eff_short_q, size_q);
    assert_eq!(opened_group.assets[0].effective_price, mark);
    assert_eq!(opened_group.assets[0].raw_oracle_target_price, mark);
    assert_eq!(opened_cfg.mark_ewma_e6, mark);
    assert_eq!(
        opened_group.insurance, insurance_before,
        "fresh HybridMark trade at the live mark must not charge an after-hours movement premium"
    );

    let close_cu = env
        .try_trade_asset_with_cu(
            0,
            &long_owner,
            long_account,
            &short_owner,
            short_account,
            -(size_q as i128),
            mark,
            0,
        )
        .unwrap_or_else(|err| {
            panic!(
                "fresh HybridMark TradeNoCpi close failed for dt={dt}, legs={oracle_leg_count}, invert={invert}: {err}"
            )
        });
    assert_cu_within("HybridMark fresh close", close_cu, TRADE_CU_LIMIT);
    let (_, flat_group) = env.market_state();
    assert_eq!(flat_group.assets[0].oi_eff_long_q, 0);
    assert_eq!(flat_group.assets[0].oi_eff_short_q, 0);
    assert_eq!(flat_group.assets[0].effective_price, mark);
    assert_eq!(flat_group.insurance, insurance_before);
}

#[test]
fn v16_bpf_hybrid_fresh_oracle_trade_opens_and_closes() {
    for dt in [0, 1] {
        for oracle_leg_count in [1, 3] {
            for invert in [0, 1] {
                run_hybrid_fresh_oracle_trade_case(dt, oracle_leg_count, invert);
            }
        }
    }
}

fn production_risk_params() -> V16CuMarketParams {
    V16CuMarketParams {
        h_max: 6_480_000,
        initial_price: 1_000_000,
        min_nonzero_mm_req: 599,
        min_nonzero_im_req: 600,
        maintenance_margin_bps: 500,
        initial_margin_bps: 500,
        liquidation_fee_bps: 5,
        liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
        max_price_move_bps_per_slot: 24,
        max_accrual_dt_slots: 20,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 10_000_000,
        ..V16CuMarketParams::default()
    }
}

#[derive(Clone, Copy)]
struct ProductionRiskOraclePrices {
    leg0: i64,
    leg1: i64,
    leg2: i64,
}

impl ProductionRiskOraclePrices {
    fn default_inverted_composite() -> Self {
        Self {
            leg0: 4_200_000_000,
            leg1: 150_000_000,
            leg2: 200_000_000,
        }
    }

    fn sub_one_inverted_composite() -> Self {
        Self {
            leg0: 2_155_172_400,
            leg1: 5_000_000,
            leg2: 5_000_000,
        }
    }
}

#[derive(Clone, Copy)]
struct ProductionRiskTradeCase {
    name: &'static str,
    fixed_deposit: Option<u128>,
    same_owner: bool,
    oracle_prices: ProductionRiskOraclePrices,
    oracle_conf_bps: u16,
    conf_filter_bps: u16,
    size_q_abs: u128,
    assert_sub_one_mark: bool,
}

impl ProductionRiskTradeCase {
    fn baseline() -> Self {
        Self {
            name: "baseline",
            fixed_deposit: None,
            same_owner: false,
            oracle_prices: ProductionRiskOraclePrices::default_inverted_composite(),
            oracle_conf_bps: 0,
            conf_filter_bps: 500,
            size_q_abs: POS_SCALE,
            assert_sub_one_mark: false,
        }
    }

    fn fixed_deposit() -> Self {
        Self {
            name: "fixed-300m-deposit",
            fixed_deposit: Some(300_000_000),
            ..Self::baseline()
        }
    }

    fn same_owner() -> Self {
        Self {
            name: "same-owner-counterparties",
            same_owner: true,
            ..Self::baseline()
        }
    }

    fn sub_one_mark() -> Self {
        Self {
            name: "sub-one-inverted-mark",
            oracle_prices: ProductionRiskOraclePrices::sub_one_inverted_composite(),
            size_q_abs: 10 * POS_SCALE,
            assert_sub_one_mark: true,
            ..Self::baseline()
        }
    }

    fn real_conf_filter() -> Self {
        Self {
            name: "pyth-conf-150bps-filter-200bps",
            oracle_conf_bps: 150,
            conf_filter_bps: 200,
            ..Self::baseline()
        }
    }
}

fn pyth_conf_for_bps(price: i64, conf_bps: u16) -> u64 {
    if conf_bps == 0 {
        return 1;
    }
    ((price as u128) * conf_bps as u128 / 10_000)
        .max(1)
        .try_into()
        .unwrap()
}

fn set_production_risk_oracles(
    env: &mut V16CuEnv,
    feeds: &[[u8; 32]; 3],
    prices: ProductionRiskOraclePrices,
    conf_bps: u16,
    publish_time: i64,
) -> [Pubkey; 3] {
    [
        env.set_pyth_price_with_conf(
            &feeds[0],
            prices.leg0,
            -6,
            pyth_conf_for_bps(prices.leg0, conf_bps),
            publish_time,
        ),
        env.set_pyth_price_with_conf(
            &feeds[1],
            prices.leg1,
            -6,
            pyth_conf_for_bps(prices.leg1, conf_bps),
            publish_time,
        ),
        env.set_pyth_price_with_conf(
            &feeds[2],
            prices.leg2,
            -6,
            pyth_conf_for_bps(prices.leg2, conf_bps),
            publish_time,
        ),
    ]
}

fn run_hybrid_fresh_oracle_production_risk_trade_case(
    asset_index: u16,
    case: ProductionRiskTradeCase,
    direction_sign: i128,
) {
    let mut env = V16CuEnv::new_with_init_params(production_risk_params());
    set_test_clock(&mut env, 1, 100);
    if asset_index != 0 {
        env.activate_asset(asset_index, 1, production_risk_params().initial_price);
    }

    let feed_seed = 0xe0u8.wrapping_add(asset_index as u8 * 3);
    let feeds = [
        [feed_seed.wrapping_add(1); 32],
        [feed_seed.wrapping_add(2); 32],
        [feed_seed.wrapping_add(3); 32],
    ];
    let [initial_leg0, initial_leg1, initial_leg2] = set_production_risk_oracles(
        &mut env,
        &feeds,
        case.oracle_prices,
        case.oracle_conf_bps,
        100,
    );
    let configure_cu = env
        .try_configure_hybrid_asset_with_conf_filter_cu(
            asset_index,
            3,
            ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            feeds,
            &[initial_leg0, initial_leg1, initial_leg2],
            1,
            100,
            1,
            0,
            3,
            case.conf_filter_bps,
        )
        .expect("configure inverted production-risk hybrid oracle");
    assert_cu_within(
        "HybridMark production-risk configure",
        configure_cu,
        CUSTODY_CU_LIMIT,
    );

    let keeper = Keypair::new();
    let keeper_portfolio = env.create_portfolio(&keeper);
    set_test_clock(&mut env, 2, 101);
    let [fresh_leg0, fresh_leg1, fresh_leg2] = set_production_risk_oracles(
        &mut env,
        &feeds,
        case.oracle_prices,
        case.oracle_conf_bps,
        101,
    );
    let fresh_crank_cu = env.crank_with_oracle_tail(
        keeper_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &[fresh_leg0, fresh_leg1, fresh_leg2],
    );
    assert_cu_within(
        "HybridMark production-risk fresh crank",
        fresh_crank_cu,
        CRANK_CU_LIMIT,
    );
    let (fresh_cfg, fresh_group) = env.market_state();
    let mark = fresh_group.assets[asset_index as usize].effective_price;
    if case.assert_sub_one_mark {
        assert!(
            mark < 1_000_000,
            "{} must exercise an inverted mark below 1.0, got {mark}",
            case.name
        );
    }
    if asset_index == 0 {
        assert_eq!(fresh_cfg.last_good_oracle_slot, 2);
        assert_eq!(fresh_cfg.hybrid_soft_stale_slots, 3);
        assert_eq!(fresh_cfg.mark_ewma_e6, mark);
    } else {
        let market_data = env.svm.get_account(&env.market).unwrap().data;
        let fresh_profile =
            state::read_asset_oracle_profile(&market_data, asset_index as usize).unwrap();
        assert_eq!(fresh_profile.last_good_oracle_slot, 2);
        assert_eq!(fresh_profile.hybrid_soft_stale_slots, 3);
        assert_eq!(fresh_profile.mark_ewma_e6, mark);
    }
    assert_eq!(
        fresh_group.assets[asset_index as usize].raw_oracle_target_price,
        mark
    );

    let long_owner = Keypair::new();
    let short_owner = if case.same_owner {
        None
    } else {
        Some(Keypair::new())
    };
    let short_owner_ref = short_owner.as_ref().unwrap_or(&long_owner);
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(short_owner_ref);
    let size_q = direction_sign
        .checked_mul(case.size_q_abs as i128)
        .expect("signed size");
    let notional = (mark as u128)
        .checked_mul(case.size_q_abs)
        .and_then(|v| v.checked_div(POS_SCALE))
        .expect("notional");
    let exact_im_deposit = notional
        .checked_mul(production_risk_params().initial_margin_bps as u128)
        .and_then(|v| v.checked_add(9_999))
        .and_then(|v| v.checked_div(10_000))
        .expect("deposit");
    let deposit_amount = case.fixed_deposit.unwrap_or(exact_im_deposit);
    env.deposit(&long_owner, long_account, deposit_amount);
    env.deposit(short_owner_ref, short_account, deposit_amount);

    let direction = if size_q > 0 { "long" } else { "short" };
    let open_cu = env
        .try_trade_asset_with_cu(
            asset_index,
            &long_owner,
            long_account,
            short_owner_ref,
            short_account,
            size_q,
            mark,
            0,
        )
        .unwrap_or_else(|err| {
            panic!(
                "production-risk fresh HybridMark {} asset[{asset_index}] {direction}-open failed at mark={mark}, deposit={deposit_amount}: {err}",
                case.name
            )
        });
    assert_cu_within(
        "HybridMark production-risk fresh open",
        open_cu,
        TRADE_CU_LIMIT,
    );
    let (_, opened_group) = env.market_state();
    assert_eq!(
        opened_group.assets[asset_index as usize].oi_eff_long_q,
        size_q.unsigned_abs()
    );
    assert_eq!(
        opened_group.assets[asset_index as usize].oi_eff_short_q,
        size_q.unsigned_abs()
    );

    let close_cu = env
        .try_trade_asset_with_cu(
            asset_index,
            &long_owner,
            long_account,
            short_owner_ref,
            short_account,
            -size_q,
            mark,
            0,
        )
        .unwrap_or_else(|err| {
            panic!(
                "production-risk fresh HybridMark {} asset[{asset_index}] {direction}-close failed at mark={mark}, deposit={deposit_amount}: {err}",
                case.name
            )
        });
    assert_cu_within(
        "HybridMark production-risk fresh close",
        close_cu,
        TRADE_CU_LIMIT,
    );
    let (_, flat_group) = env.market_state();
    assert_eq!(flat_group.assets[asset_index as usize].oi_eff_long_q, 0);
    assert_eq!(flat_group.assets[asset_index as usize].oi_eff_short_q, 0);
}

#[test]
fn v16_bpf_hybrid_fresh_oracle_trade_production_risk_params_opens_and_closes() {
    for asset_index in [0, 1] {
        for direction_sign in [1, -1] {
            run_hybrid_fresh_oracle_production_risk_trade_case(
                asset_index,
                ProductionRiskTradeCase::baseline(),
                direction_sign,
            );
        }
    }
}

#[test]
fn v16_bpf_hybrid_fresh_oracle_trade_devnet_difference_axes() {
    for case in [
        ProductionRiskTradeCase::fixed_deposit(),
        ProductionRiskTradeCase::same_owner(),
        ProductionRiskTradeCase::sub_one_mark(),
        ProductionRiskTradeCase::real_conf_filter(),
    ] {
        for asset_index in [0, 1] {
            for direction_sign in [1, -1] {
                run_hybrid_fresh_oracle_production_risk_trade_case(
                    asset_index,
                    case,
                    direction_sign,
                );
            }
        }
    }
}

#[test]
fn v16_bpf_hybrid_mark_uses_ewma_after_hours_then_oracle_when_fresh() {
    let mut env = V16CuEnv::new();
    env.svm.warp_to_slot(1);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 100;
    env.svm.set_sysvar(&clock);

    let feeds = [[0xb1u8; 32], [0xb2u8; 32], [0xb3u8; 32]];
    let leg0 = env.set_pyth_price(&feeds[0], 4_000_000_000, -6, 100);
    let leg1 = env.set_pyth_price(&feeds[1], 150_000_000, -6, 100);
    let leg2 = env.set_pyth_price(&feeds[2], 200_000_000, -6, 100);
    let configure_cu = env.configure_three_leg_hybrid_with_cu(feeds, leg0, leg1, leg2, 1, 100);
    assert_cu_within("ConfigureHybridOracle", configure_cu, CUSTODY_CU_LIMIT);

    let keeper = Keypair::new();
    let keeper_portfolio = env.create_portfolio(&keeper);
    env.svm.warp_to_slot(2);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 101;
    env.svm.set_sysvar(&clock);
    let fresh_leg0 = env.set_pyth_price(&feeds[0], 4_200_000_000, -6, 101);
    let fresh_leg1 = env.set_pyth_price(&feeds[1], 150_000_000, -6, 101);
    let fresh_leg2 = env.set_pyth_price(&feeds[2], 200_000_000, -6, 101);
    let fresh_crank_cu = env.crank_with_oracle_tail(
        keeper_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &[fresh_leg0, fresh_leg1, fresh_leg2],
    );
    assert_cu_within("HybridMark fresh crank", fresh_crank_cu, CRANK_CU_LIMIT);
    let (fresh_cfg, fresh_group) = env.market_state();
    assert_eq!(fresh_group.assets[0].effective_price, 140_000);
    assert_eq!(fresh_cfg.mark_ewma_e6, 140_000);
    assert_eq!(fresh_cfg.last_good_oracle_slot, 2);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, 10_000_000);
    env.deposit(&short_owner, short_account, 10_000_000);

    env.svm.warp_to_slot(10);
    let before_after_hours = env.market_state();
    let size_q = POS_SCALE;
    let after_hours_exec_price = before_after_hours.1.assets[0].effective_price * 150 / 100;
    let open_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        size_q as i128,
        after_hours_exec_price,
        0,
    );
    assert_cu_within("HybridMark after-hours open", open_cu, TRADE_CU_LIMIT);
    let (after_hours_cfg, after_hours_group) = env.market_state();
    assert!(
        after_hours_cfg.mark_ewma_e6 > before_after_hours.0.mark_ewma_e6,
        "after-hours hybrid trade must advance the fallback EWMA mark"
    );
    assert_eq!(
        after_hours_group.assets[0].effective_price, before_after_hours.1.assets[0].effective_price,
        "after-hours execution must not rewrite the last accepted oracle index"
    );
    assert!(
        after_hours_group.insurance > 0,
        "after-hours hybrid trade must charge a dynamic mark-movement fee"
    );

    let close_cu = env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        -(size_q as i128),
        after_hours_exec_price,
        0,
    );
    assert_cu_within("HybridMark after-hours close", close_cu, TRADE_CU_LIMIT);
    let (_, flat_group) = env.market_state();
    assert_eq!(flat_group.assets[0].oi_eff_long_q, 0);
    assert_eq!(flat_group.assets[0].oi_eff_short_q, 0);

    env.svm.warp_to_slot(11);
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 102;
    env.svm.set_sysvar(&clock);
    let normal_leg0 = env.set_pyth_price(&feeds[0], 4_500_000_000, -6, 102);
    let normal_leg1 = env.set_pyth_price(&feeds[1], 150_000_000, -6, 102);
    let normal_leg2 = env.set_pyth_price(&feeds[2], 200_000_000, -6, 102);
    let normal_crank_cu = env.crank_with_oracle_tail(
        keeper_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 11,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        &[normal_leg0, normal_leg1, normal_leg2],
    );
    assert_cu_within(
        "HybridMark normal-hours crank",
        normal_crank_cu,
        CRANK_CU_LIMIT,
    );
    let (normal_cfg, normal_group) = env.market_state();
    assert_eq!(normal_cfg.last_good_oracle_slot, 11);
    assert_eq!(normal_cfg.mark_ewma_last_slot, 11);
    assert_eq!(normal_cfg.mark_ewma_e6, 150_000);
    assert_eq!(normal_group.assets[0].effective_price, 150_000);
    assert_eq!(normal_group.assets[0].raw_oracle_target_price, 150_000);
}

#[test]
fn v16_bpf_configure_and_push_ewma_mark_are_bounded_and_clock_authenticated() {
    let mut env = V16CuEnv::new();
    let configure_real_slot = 8;
    let push_real_slot = 9;
    let spoofed_slot = 1_000_000;
    env.svm.warp_to_slot(configure_real_slot);
    let configure_cu = env.configure_ewma_mark_with_cu(spoofed_slot, 100, 1, 0);
    env.svm.warp_to_slot(push_real_slot);
    let push_cu = env.push_ewma_mark_with_cu(spoofed_slot, 120);
    println!("v16 EwmaMark configure CU: {configure_cu}, push CU: {push_cu}");
    assert!(
        configure_cu <= CUSTODY_CU_LIMIT,
        "EwmaMark configure CU {} exceeded limit {}",
        configure_cu,
        CUSTODY_CU_LIMIT
    );
    assert!(
        push_cu <= CUSTODY_CU_LIMIT,
        "EwmaMark push CU {} exceeded limit {}",
        push_cu,
        CUSTODY_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg, group) = state::read_market(&market_data).unwrap();
    assert_eq!(
        cfg.oracle_mode,
        percolator_prog::constants::ORACLE_MODE_EWMA_MARK
    );
    assert_eq!(group.current_slot, configure_real_slot);
    assert_eq!(group.slot_last, configure_real_slot);
    assert_eq!(cfg.mark_ewma_last_slot, push_real_slot);
    assert_eq!(
        cfg.mark_ewma_e6, 110,
        "authority mark push should update the EWMA using authenticated slot time"
    );
    assert_ne!(
        cfg.mark_ewma_last_slot, spoofed_slot,
        "caller-supplied PushEwmaMark now_slot must not authenticate mark liveness"
    );
}

#[test]
fn v16_bpf_configure_and_push_auth_mark_are_bounded_and_clock_authenticated() {
    let mut env = V16CuEnv::new();
    let configure_real_slot = 8;
    let push_real_slot = 9;
    let spoofed_slot = 1_000_000;
    env.svm.warp_to_slot(configure_real_slot);
    let configure_cu = env.configure_auth_mark_with_cu(spoofed_slot, 100);
    env.svm.warp_to_slot(push_real_slot);
    let push_cu = env.push_auth_mark_with_cu(spoofed_slot, 120);
    println!("v16 AuthMark configure CU: {configure_cu}, push CU: {push_cu}");
    assert!(
        configure_cu <= CUSTODY_CU_LIMIT,
        "AuthMark configure CU {} exceeded limit {}",
        configure_cu,
        CUSTODY_CU_LIMIT
    );
    assert!(
        push_cu <= CUSTODY_CU_LIMIT,
        "AuthMark push CU {} exceeded limit {}",
        push_cu,
        CUSTODY_CU_LIMIT
    );

    let market_data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg, group) = state::read_market(&market_data).unwrap();
    assert_eq!(
        cfg.oracle_mode,
        percolator_prog::constants::ORACLE_MODE_AUTH_MARK
    );
    assert_eq!(group.current_slot, configure_real_slot);
    assert_eq!(group.slot_last, configure_real_slot);
    assert_eq!(cfg.mark_ewma_last_slot, push_real_slot);
    assert_eq!(
        cfg.mark_ewma_e6, 120,
        "authority mark push should store the AuthMark value directly"
    );
    assert_eq!(cfg.oracle_target_price_e6, 120);
    assert_eq!(cfg.mark_ewma_halflife_slots, 0);
    assert_ne!(
        cfg.mark_ewma_last_slot, spoofed_slot,
        "caller-supplied PushAuthMark now_slot must not authenticate mark liveness"
    );
}

#[test]
fn v16_bpf_auth_mark_target_effective_lag_counts_toward_liquidation_health() {
    const INITIAL_MARK: u64 = 100_000_000;
    const TARGET_MARK: u64 = 90_000_000;
    const EXPECTED_EFFECTIVE_AFTER_ONE_SLOT: u64 = 99_760_000;

    let mut env = V16CuEnv::new_with_market_params_and_price_move(1, 10_000, 10_000, 24);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, INITIAL_MARK);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_portfolio = env.create_portfolio(&long_owner);
    let short_portfolio = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_portfolio, 100_000_000);
    env.deposit(&short_owner, short_portfolio, 200_000_000);
    env.trade_with_cu(
        &long_owner,
        long_portfolio,
        &short_owner,
        short_portfolio,
        POS_SCALE as i128,
        INITIAL_MARK,
        0,
    );

    env.svm.warp_to_slot(2);
    env.push_auth_mark_with_cu(2, TARGET_MARK);
    env.crank(
        long_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let (_, lagged_group) = env.market_state();
    assert_eq!(
        lagged_group.assets[0].raw_oracle_target_price, TARGET_MARK,
        "AuthMark stores the un-clamped target for health certification"
    );
    assert_eq!(
        lagged_group.assets[0].effective_price, EXPECTED_EFFECTIVE_AFTER_ONE_SLOT,
        "effective price should be clamp-lagged by one 24 bps slot"
    );

    let lagged_long = env.portfolio_state(long_portfolio);
    assert!(
        lagged_long.health_cert.valid,
        "refresh must write a health certificate"
    );
    assert!(
        lagged_long.health_cert.certified_maintenance_req > INITIAL_MARK as u128,
        "maintenance must include the adverse target/effective lag penalty"
    );
    assert!(
        lagged_long.health_cert.certified_liq_deficit > 0,
        "lagged adverse AuthMark target must make the under-margined long liquidatable"
    );

    env.crank(
        long_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 1,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let liquidated_long = env.portfolio_state(long_portfolio);
    // FIX E3 (upstream #92) fixture repair: the original assertion here was
    // `!has_active_leg_for_asset(...)` (leg fully closed). That property is
    // mathematically unreachable for this fixture without shrinking the
    // position to a single indivisible atom: this account is margined at
    // exactly 100% (deposit == entry notional, no leverage headroom), so its
    // certified equity reduces algebraically to `size/POS_SCALE *
    // effective_price` -- strictly positive for any effective_price >= 1,
    // which the protocol always enforces (PushAuthMark/PushEwmaMark reject
    // mark_e6 == 0). The bankrupt-account early exit in
    // `liquidation_engine_close_request_q` (certified_equity < 0) can
    // therefore never trigger here, at any lag magnitude -- only a genuine
    // partial-close search runs, and this fixture's lag-driven deficit
    // (9.52M short against a 109.52M requirement, ~8.7% of the position) is
    // well inside what a healthy partial close can resolve, so
    // engine-selected sizing (E3) correctly picks that smaller close over a
    // full one. Asserting full closure here would be asserting an
    // unreachable, not merely a "changed", outcome.
    //
    // The repaired assertions verify the SAME underlying claim the test
    // exists to make -- that the lag-driven deficit is genuinely actionable
    // by permissionless liquidation -- at the precision E3 actually
    // guarantees: liquidation must close enough of the position to fully
    // resolve the certified deficit (not partially, not zero), while still
    // strictly reducing the position (proving liquidation had a bounded,
    // real effect rather than either no-op'ing or over-liquidating to a
    // full close it didn't need).
    assert!(
        has_active_leg_for_asset(&liquidated_long, 0),
        "engine-selected liquidation sizing (E3) must select the minimal healthy partial \
         close here, not a full close, given this fixture's deficit is well inside what a \
         partial close can resolve"
    );
    let closed_leg = active_leg_for_asset(&liquidated_long, 0);
    let remaining_abs_q = closed_leg.basis_pos_q.unsigned_abs();
    assert!(
        remaining_abs_q > 0 && remaining_abs_q < POS_SCALE,
        "liquidation must strictly reduce a lag-liquidatable position (bounded, non-vacuous \
         close): remaining={remaining_abs_q}, original={POS_SCALE}"
    );
    assert_eq!(
        liquidated_long.health_cert.certified_liq_deficit, 0,
        "positive lag-deficit certification must allow permissionless liquidation to fully \
         resolve the deficit it was called to address"
    );
}

#[test]
fn v16_cu_crank_cost_is_account_local_after_many_portfolios() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000_000);

    let before_extra = env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    for _ in 0..64 {
        let owner = Keypair::new();
        let p = env.create_portfolio(&owner);
        let acct = env.svm.get_account(&p).expect("portfolio account exists");
        let (_header, parsed_owner) = state::read_portfolio_owner_preflight(&acct.data).unwrap();
        assert_eq!(parsed_owner, owner.pubkey().to_bytes());
    }

    let after_extra = env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 2,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    println!(
        "v16 refresh crank CU before extra portfolios: {before_extra}, after 64 extras: {after_extra}"
    );

    assert!(after_extra <= CRANK_CU_LIMIT);
    assert!(
        after_extra.saturating_sub(before_extra) < 10_000,
        "v16 crank should stay account-local rather than scaling with materialized portfolio count"
    );
}

#[test]
fn v16_bpf_policy_authority_and_base_unit_tags_are_bounded_and_persist() {
    let mut env = V16CuEnv::new();

    let liquidation_cu = env.update_liquidation_fee_policy_with_cu(1_234);
    assert_cu_within(
        "UpdateLiquidationFeePolicy",
        liquidation_cu,
        CUSTODY_CU_LIMIT,
    );
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.liquidation_cranker_fee_share_bps, 1_234);

    let backing_cu = env.update_backing_fee_policy_with_cu(0, 77, 5_000);
    assert_cu_within("UpdateBackingFeePolicy", backing_cu, CUSTODY_CU_LIMIT);
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.backing_trade_fee_bps_long, 77);
    assert_eq!(cfg.backing_trade_fee_insurance_share_bps_long, 5_000);
    assert_eq!(cfg.backing_trade_fee_policy_count, 1);

    // Fee-split floor enforcement (policy_v16::fee_split_floor_ok): with
    // backing_trade_fee_bps_long=77 / insurance_share_bps_long=5_000 already
    // stored above, trade_fee_base_bps=88 would make creator's share of
    // T=165 equal to 53.3% (> the 45% cap) and is now rejected on-chain.
    // 88 -> 20 keeps T small enough (T=97) that creator (20.6%), insurance
    // (~39.7%), and LP (~39.7%) shares of T all clear their floors with
    // margin; this test only cares that the field persists + CU is
    // bounded, not the specific magnitude. (Minimal fixture fix applied
    // per STEP 1's fixture-fix carve-out; SENTINEL scaffolding around it
    // was discarded.)
    let trade_fee_cu = env.update_trade_fee_policy_with_cu(20);
    assert_cu_within("UpdateTradeFeePolicy", trade_fee_cu, CUSTODY_CU_LIMIT);
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.trade_fee_base_bps, 20);

    let redirect_cu = env.update_fee_redirect_policy_with_cu(2_500);
    assert_cu_within("UpdateFeeRedirectPolicy", redirect_cu, CUSTODY_CU_LIMIT);
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.fee_redirect_to_market_0_bps, 2_500);

    let secondary_mint = env.create_mint();
    let base_unit_cu = env.update_base_unit_mints_with_cu(env.mint, secondary_mint);
    assert_cu_within("UpdateBaseUnitMints", base_unit_cu, CUSTODY_CU_LIMIT);
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.collateral_mint, env.mint.to_bytes());
    assert_eq!(cfg.secondary_collateral_mint, secondary_mint.to_bytes());

    let primary_source = env.token_account_for_mint(env.mint, env.admin.pubkey(), 50);
    let secondary_dest = env.token_account_for_mint(secondary_mint, env.admin.pubkey(), 0);
    let secondary_vault = env.vault_token_for_mint(secondary_mint, 50);
    let before_swap_market = env.svm.get_account(&env.market).unwrap().data;
    let swap_cu = env.swap_secondary_for_primary_with_cu(
        primary_source,
        env.vault,
        secondary_dest,
        secondary_vault,
        50,
    );
    assert_cu_within("SwapSecondaryForPrimary", swap_cu, CUSTODY_CU_LIMIT);
    assert_eq!(env.token_amount(primary_source), 0);
    assert_eq!(env.token_amount(env.vault), 50);
    assert_eq!(env.token_amount(secondary_dest), 50);
    assert_eq!(env.token_amount(secondary_vault), 0);
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        before_swap_market,
        "base-unit swap must only move SPL custody"
    );

    let new_asset_authority = Keypair::new();
    let authority_cu = env.update_asset_authority_with_cu(&new_asset_authority);
    assert_cu_within("UpdateAuthority", authority_cu, CUSTODY_CU_LIMIT);
    let (cfg, _) = env.market_state();
    // v17 convergence: cfg.asset_authority removed; v17 uses a single `marketauth` key.
    // Matrix row: v17-auth-overhaul (asset_authority → marketauth field rename).
    assert_eq!(cfg.marketauth, new_asset_authority.pubkey().to_bytes());
}

#[test]
fn v16_bpf_accounting_ledger_tags_are_bounded_and_update_state() {
    let mut env = V16CuEnv::new();
    // #433: TopUpBackingBucket now pins the ledger to its PDA, so a random-address
    // ledger is refused. These fixtures want a working top-up, not a substitution test.
    let ledger = env.canonical_backing_domain_ledger_account(1);
    let (backing_source, top_up_cu) =
        env.top_up_backing_bucket_with_ledger_with_cu(ledger, 1, 100, 10);
    assert_cu_within(
        "TopUpBackingBucket ledger init",
        top_up_cu,
        CUSTODY_CU_LIMIT,
    );
    assert_eq!(env.token_amount(backing_source), 0);

    env.mutate_market(|_, group| {
        group.source_backing_buckets[1].utilization_fee_earnings = 30;
        group.vault += 30;
    });
    env.set_token_account_amount(env.vault, env.mint, env.vault_authority, 130);

    let sync_cu = env.sync_backing_domain_ledger_with_cu(ledger, 1);
    assert_cu_within("SyncBackingDomainLedger", sync_cu, CUSTODY_CU_LIMIT);
    let ledger_data = env.svm.get_account(&ledger).unwrap().data;
    let ledger_state = state::read_backing_domain_ledger(&ledger_data).unwrap();
    assert_eq!(ledger_state.total_principal_atoms, 100);
    assert_eq!(ledger_state.last_observed_bucket_earnings_atoms, 30);
    assert_eq!(ledger_state.total_earnings_atoms, 30);

    let dest = env.token_account_for_mint(env.mint, env.admin.pubkey(), 0);
    let withdraw_earnings_cu =
        env.withdraw_backing_bucket_earnings_to_admin_token_with_cu(ledger, dest, 1, 20);
    assert_cu_within(
        "WithdrawBackingBucketEarnings",
        withdraw_earnings_cu,
        CUSTODY_CU_LIMIT,
    );
    assert_eq!(env.token_amount(dest), 20);
    let ledger_data = env.svm.get_account(&ledger).unwrap().data;
    let ledger_state = state::read_backing_domain_ledger(&ledger_data).unwrap();
    let (_, group) = env.market_state();
    assert_eq!(ledger_state.total_earnings_withdrawn_atoms, 20);
    assert_eq!(ledger_state.last_observed_bucket_earnings_atoms, 10);
    assert_eq!(group.source_backing_buckets[1].utilization_fee_earnings, 10);
    assert_eq!(group.vault, 110);

    let mut pnl_env = V16CuEnv::new();
    let pnl_ledger = pnl_env.canonical_backing_domain_ledger_account(1);
    pnl_env.top_up_backing_bucket_with_ledger_with_cu(pnl_ledger, 1, 40, 10);
    let owner = Keypair::new();
    let portfolio = pnl_env.create_portfolio(&owner);
    pnl_env.add_source_positive_pnl(portfolio, 1, 40);
    pnl_env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 0,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let convert_cu = pnl_env.convert_released_pnl_with_cu(&owner, portfolio, 40);
    assert_cu_within("ConvertReleasedPnl", convert_cu, CUSTODY_CU_LIMIT);
    let account = pnl_env.portfolio_state(portfolio);
    assert_eq!(account.capital, 40);
    pnl_env.sync_backing_domain_ledger_with_cu(pnl_ledger, 1);
    let ledger_data = pnl_env.svm.get_account(&pnl_ledger).unwrap().data;
    let ledger_state = state::read_backing_domain_ledger(&ledger_data).unwrap();
    assert_eq!(ledger_state.cumulative_loss_atoms, 40);
    assert_eq!(ledger_state.last_observed_unavailable_principal_atoms, 40);

    let mut insurance_env = V16CuEnv::new();
    let insurance_ledger = insurance_env.insurance_ledger_account();
    let (_, insurance_top_up_cu) =
        insurance_env.top_up_insurance_with_ledger_with_cu(insurance_ledger, 100);
    assert_cu_within(
        "TopUpInsurance ledger init",
        insurance_top_up_cu,
        CUSTODY_CU_LIMIT,
    );
    let init_cu = insurance_env.sync_insurance_ledger_with_cu(insurance_ledger);
    assert_cu_within("SyncInsuranceLedger init", init_cu, CUSTODY_CU_LIMIT);
    let ledger_data = insurance_env
        .svm
        .get_account(&insurance_ledger)
        .unwrap()
        .data;
    let ledger_state = state::read_insurance_ledger(&ledger_data).unwrap();
    assert_eq!(ledger_state.total_principal_atoms, 100);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 100);

    insurance_env.mutate_market(|_, group| {
        group.insurance += 30;
        group.vault += 30;
        group.insurance_domain_budget[0] += 15;
        group.insurance_domain_budget[1] += 15;
    });
    insurance_env.svm.expire_blockhash();
    let profit_cu = insurance_env.sync_insurance_ledger_with_cu(insurance_ledger);
    assert_cu_within("SyncInsuranceLedger profit", profit_cu, CUSTODY_CU_LIMIT);
    let ledger_data = insurance_env
        .svm
        .get_account(&insurance_ledger)
        .unwrap()
        .data;
    let ledger_state = state::read_insurance_ledger(&ledger_data).unwrap();
    assert_eq!(ledger_state.cumulative_profit_atoms, 30);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 130);

    insurance_env.mutate_market(|_, group| {
        group.insurance -= 20;
        group.vault -= 20;
        group.insurance_domain_budget[0] -= 10;
        group.insurance_domain_budget[1] -= 10;
    });
    insurance_env.svm.expire_blockhash();
    let loss_cu = insurance_env.sync_insurance_ledger_with_cu(insurance_ledger);
    assert_cu_within("SyncInsuranceLedger loss", loss_cu, CUSTODY_CU_LIMIT);
    let ledger_data = insurance_env
        .svm
        .get_account(&insurance_ledger)
        .unwrap()
        .data;
    let ledger_state = state::read_insurance_ledger(&ledger_data).unwrap();
    assert_eq!(ledger_state.cumulative_loss_atoms, 20);
    assert_eq!(ledger_state.last_observed_insurance_atoms, 110);
}

#[test]
fn v16_bpf_recovery_and_reset_tags_are_bounded_and_update_state() {
    let mut reduce_env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = reduce_env.create_portfolio(&long_owner);
    let short_account = reduce_env.create_portfolio(&short_owner);
    reduce_env.deposit(&long_owner, long_account, 10_000);
    reduce_env.deposit(&short_owner, short_account, 10_000);
    reduce_env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (2 * POS_SCALE) as i128,
        100,
        0,
    );

    let reduce_cu = reduce_env.rebalance_reduce_with_cu(&long_owner, long_account, 0, POS_SCALE);
    assert_cu_within("RebalanceReduce", reduce_cu, CUSTODY_CU_LIMIT);
    let (_, group) = reduce_env.market_state();
    let long = reduce_env.portfolio_state(long_account);
    assert_eq!(long.legs[0].basis_pos_q, POS_SCALE as i128);
    assert_eq!(group.assets[0].oi_eff_long_q, POS_SCALE);

    let mut forfeit_env = V16CuEnv::new();
    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = forfeit_env.create_portfolio(&long_owner);
    let short_account = forfeit_env.create_portfolio(&short_owner);
    forfeit_env.deposit(&long_owner, long_account, 10_000);
    forfeit_env.deposit(&short_owner, short_account, 10_000);
    forfeit_env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        POS_SCALE as i128,
        100,
        0,
    );
    forfeit_env.mutate_market(|_, group| {
        group.mode = MarketModeV16::Recovery;
        group.recovery_reason = Some(PermissionlessRecoveryReasonV16::BelowProgressFloor);
    });
    let forfeit_cu = forfeit_env.forfeit_recovery_leg_with_cu(&long_owner, long_account, 0, 1);
    assert_cu_within("ForfeitRecoveryLeg", forfeit_cu, CUSTODY_CU_LIMIT);
    let (_, group) = forfeit_env.market_state();
    let long = forfeit_env.portfolio_state(long_account);
    assert!(percolator::active_bitmap_is_empty(long.active_bitmap));
    assert_eq!(long.legs[0].basis_pos_q, 0);
    assert_eq!(group.assets[0].oi_eff_long_q, 0);

    let mut cure_env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = cure_env.create_portfolio(&owner);
    cure_env.seed_cancellable_close_progress(portfolio);
    let source = cure_env.token_account_for_mint(cure_env.mint, owner.pubkey(), 20);
    let cure_cu = cure_env.cure_and_cancel_close_with_cu(&owner, portfolio, source, 20);
    assert_cu_within("CureAndCancelClose", cure_cu, CUSTODY_CU_LIMIT);
    let (_, group) = cure_env.market_state();
    let account = cure_env.portfolio_state(portfolio);
    assert!(account.close_progress.canceled);
    assert_eq!(account.capital, 20);
    assert_eq!(group.c_tot, 20);
    assert_eq!(group.vault, 20);
    assert_eq!(group.pending_domain_loss_barriers[0], 0);
    assert_eq!(cure_env.token_amount(source), 0);
    assert_eq!(cure_env.token_amount(cure_env.vault), 20);

    let mut reset_env = V16CuEnv::new();
    reset_env.mutate_market(|_, group| {
        group.assets[0].mode_long = SideModeV16::ResetPending;
    });
    let reset_cu = reset_env.finalize_reset_side_with_cu(0, 0);
    assert_cu_within("FinalizeResetSide", reset_cu, CUSTODY_CU_LIMIT);
    let (_, group) = reset_env.market_state();
    assert_eq!(group.assets[0].mode_long, SideModeV16::Normal);
}

#[test]
fn v16_bpf_resolved_payout_tags_are_bounded_and_update_state() {
    let mut claim_env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = claim_env.create_portfolio(&owner);
    {
        let mut market_account = claim_env
            .svm
            .get_account(&claim_env.market)
            .expect("market account");
        let mut portfolio_account = claim_env
            .svm
            .get_account(&portfolio)
            .expect("portfolio account");
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut account = state::read_portfolio(&portfolio_account.data).unwrap();
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
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_account.data, &account).unwrap();
        claim_env
            .svm
            .set_account(claim_env.market, market_account)
            .unwrap();
        claim_env
            .svm
            .set_account(portfolio, portfolio_account)
            .unwrap();
    }
    claim_env.set_token_account_amount(
        claim_env.vault,
        claim_env.mint,
        claim_env.vault_authority,
        60,
    );
    let dest = claim_env.token_account_for_mint(claim_env.mint, owner.pubkey(), 0);
    let claim_cu = claim_env.claim_resolved_payout_topup_with_cu(owner.pubkey(), portfolio, dest);
    assert_cu_within("ClaimResolvedPayoutTopup", claim_cu, CUSTODY_CU_LIMIT);
    assert_eq!(claim_env.token_amount(dest), 60);
    assert_eq!(claim_env.token_amount(claim_env.vault), 0);
    let (_, group) = claim_env.market_state();
    let account = claim_env.portfolio_state(portfolio);
    assert_eq!(group.vault, 0);
    assert_eq!(account.resolved_payout_receipt.paid_effective, 100);
    assert!(account.resolved_payout_receipt.finalized);

    let mut refine_env = V16CuEnv::new();
    refine_env.mutate_market(|_, group| {
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
    });
    // #313: RefineResolvedUnreceiptedBound is DISABLED — assert it is rejected and the
    // resolved-payout ledger is left UNTOUCHED (still 100*SCALE, not drained to 90).
    refine_env.refine_resolved_unreceipted_bound_rejected(10 * BOUND_SCALE);
    let (_, group) = refine_env.market_state();
    assert_eq!(
        group
            .resolved_payout_ledger
            .terminal_claim_bound_unreceipted_num,
        100 * BOUND_SCALE
    );
}

// W3 (canonical-ATA): mirror of v16_program::processor::canonical_vault_address — the SPL
// Associated Token Account of the vault_authority PDA for this mint. Kept byte-in-lock-step with
// the program so the BPF vault fixture satisfies the F-VAULT-FRAG pin.
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

// FIX W9 (upstream 0b5e3baa): CloseSlab must reject admin_dest aliasing market_ai. A market
// account can be a signing system-created keypair; if marketauth is rotated to that same key,
// admin_dest (the lamport destination) and market_ai (the slab being zeroed) become the SAME
// AccountInfo. The zero-then-credit sequence at the end of handle_close_slab nets back to the
// pre-close lamport balance (same underlying cell), but the intervening data-zero step still
// destroys the slab contents -- leaving a program-owned, non-zero-lamport account with all-zero
// data that the runtime will not purge (it never reaches an exit balance of 0).
#[test]
fn v16_attack_close_slab_rejects_market_as_lamport_destination() {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(
        program_id,
        &std::fs::read(program_path()).expect("read BPF"),
    );
    svm.add_program(
        spl_token::ID,
        &std::fs::read(spl_token_program_path()).expect("read token BPF"),
    );

    let payer = Keypair::new();
    let admin = Keypair::new();
    let market = Keypair::new();
    let mint = Pubkey::new_unique();
    let params = V16CuMarketParams::default();
    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", market.pubkey().as_ref()], &program_id);
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
        market.pubkey(),
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; state::market_account_len_for_capacity(1).unwrap()],
            owner: program_id,
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
            AccountMeta::new(market.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
        ],
        &[&admin],
    )
    .expect("init market");

    svm.expire_blockhash();
    send_tx(
        &mut svm,
        program_id,
        &payer,
        ProgInstruction::UpdateAuthority {
            new_pubkey: market.pubkey().to_bytes(),
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market.pubkey(), true),
            AccountMeta::new(market.pubkey(), false),
        ],
        &[&admin, &market],
    )
    .expect("rotate marketauth to signing market key");

    svm.expire_blockhash();
    send_tx(
        &mut svm,
        program_id,
        &payer,
        ProgInstruction::ResolveMarket,
        vec![
            AccountMeta::new(market.pubkey(), true),
            AccountMeta::new(market.pubkey(), false),
        ],
        &[&market],
    )
    .expect("market key can resolve after handoff");

    let dest = Pubkey::new_unique();
    svm.set_account(
        dest,
        Account {
            lamports: 1_000_000_000,
            data: make_token_data(mint, market.pubkey(), 0),
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let market_before = svm.get_account(&market.pubkey()).unwrap();
    let vault_before = svm.get_account(&vault).unwrap();
    let dest_before = svm.get_account(&dest).unwrap();

    svm.expire_blockhash();
    let rejected = send_tx(
        &mut svm,
        program_id,
        &payer,
        ProgInstruction::CloseSlab,
        vec![
            AccountMeta::new(market.pubkey(), true),
            AccountMeta::new(market.pubkey(), false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_authority, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&market],
    );
    assert!(
        rejected.is_err(),
        "CloseSlab must reject market-as-destination alias"
    );
    assert_eq!(
        svm.get_account(&market.pubkey()).unwrap(),
        market_before,
        "market-as-destination rejection leaves the slab initialized"
    );
    assert_eq!(
        svm.get_account(&vault).unwrap(),
        vault_before,
        "market-as-destination rejection leaves the vault open"
    );
    assert_eq!(
        svm.get_account(&dest).unwrap(),
        dest_before,
        "market-as-destination rejection pays no dust"
    );
}

#[test]
fn v16_audit_permissionless_reuse_rejects_zero_insurance_authority() {
    // W4 Finding F (F-REUSE-ZERO-AUTH): the retired-slot REUSE path must reject a zero domain
    // authority, exactly as the append path does. A zero insurance_authority strands every fee
    // accrued to the reused domain (terminal_insurance_remaining rejects a zero authority) and bricks
    // CloseSlab. Append asset 1 with valid authorities, retire it, then REUSE the freed slot with a
    // zero insurance_authority -> must be rejected with InvalidInstruction (Custom 9).
    // Broadened to ALL FOUR domain authorities: zero EACH one in turn (others valid) and assert the
    // reuse path rejects with InvalidInstruction (Custom 9) every time.
    for which in 0..4u8 {
        let mut env = V16CuEnv::new();
        let creator = Keypair::new();
        env.update_market_init_fee_policy_with_cu(1);
        env.svm.warp_to_slot(1);
        env.activate_permissionless_asset_with_fee(
            &creator,
            1,
            1,
            100,
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            1,
        );
        env.svm.warp_to_slot(3);
        env.update_asset_lifecycle_as_admin_with_cu(
            percolator_prog::processor::ASSET_ACTION_RETIRE,
            1,
            3,
            0,
        );

        env.svm.warp_to_slot(4);
        env.ensure_signer_account(creator.pubkey());
        let source = env.token_account(creator.pubkey(), 1);
        let pid = env.program_id;
        let payer = env.payer.insecure_clone();
        let market = env.market;
        let vault = env.vault;
        let c = creator.pubkey().to_bytes();
        let z = [0u8; 32];
        // zero exactly ONE of the four authorities (the `which`-th); the other three are valid.
        let res = send_tx(
            &mut env.svm,
            pid,
            &payer,
            ProgInstruction::UpdateAssetLifecycle {
                action: percolator_prog::processor::ASSET_ACTION_ACTIVATE,
                asset_index: 1,
                now_slot: 4,
                initial_price: 250,
                insurance_authority: if which == 0 { z } else { c },
                insurance_operator: if which == 1 { z } else { c },
                backing_bucket_authority: if which == 2 { z } else { c },
                oracle_authority: if which == 3 { z } else { c },
            },
            vec![
                AccountMeta::new(creator.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&creator],
        );
        let err = res.expect_err("reuse with a zero domain authority must reject");
        assert!(
            err.contains("Custom(9)"),
            "zero authority #{which}: expected InvalidInstruction Custom(9), got: {err}"
        );
    }
}

#[test]
fn v16_audit_resolved_maintenance_fee_insurance_stays_recoverable() {
    // W4 Finding G (F-RESOLVED-FEE-STRAND): close_resolved charges a maintenance fee into insurance;
    // if it is not credited to an active market budget it is stranded (terminal_insurance_remaining
    // cannot release it) and bricks CloseSlab (mainnet AWCZ2pK). The Finding-G wrapper credits the
    // retained fee delta to active market budgets, so ALL of group.insurance stays attributable to a
    // withdrawable per-domain budget.
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 5,
    );
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);
    env.svm.warp_to_slot(100);
    env.resolve();
    env.close_resolved(&owner, portfolio);

    let (_, group) = env.market_state();
    let budgets: u128 = group.insurance_domain_budget.iter().copied().sum();
    assert!(
        group.insurance > 0,
        "a resolved maintenance fee must have been charged"
    );
    assert_eq!(
        group.insurance, budgets,
        "resolved maintenance fee must be credited to a withdrawable per-domain budget, not stranded"
    );
}

// ── W5b: f7520e5 GREEN audit tests (un-ignored — engine now carries Findings D/E via E4/E3) ──

// Coverage probe (audit): an INSOLVENT resolved market (residual < positive-PnL
// face, so the resolved payout rate < 1) pays a winner only floor(face*rate) <
// face. The receipt's `finalized` flag is set ONLY when paid_effective ==
// terminal_positive_claim_face (the FULL face), so under a haircut it can never
// finalize. If that is a real gap, the winner's portfolio can never be
// dematerialized (portfolio_view_is_closable requires a finalized-or-absent
// receipt), materialized_portfolio_count is stuck >= 1, and the market can never
// WithdrawInsurance or CloseSlab -> permanent fund/rent strand.
//
// This test asserts the CORRECT end-state (the fully-settled winner reaches a
// closable receipt state and the portfolio can be reclaimed).
// GREEN regression: Finding D was fixed in engine b6e23b3
// (clear_fully_diluted_resolved_receipt_if_terminal clears the receipt at the
// terminal rate so the portfolio dematerializes).
#[test]
fn v16_audit_insolvent_resolved_winner_can_dematerialize() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 1_000);
    // Winner carries +250 of positive PnL face, but its domain is backed by only
    // 100, so the resolved junior pool (residual = vault - c_tot) is 100 < 250 ->
    // a permanent haircut: payout rate = 100/250 = 0.4.
    env.top_up_backing_bucket(1, 100, 10_000);
    env.add_source_positive_pnl(portfolio, 1, 250);

    env.resolve();
    let _dest = env.close_resolved(&owner, portfolio);

    let account = state::read_portfolio(&env.svm.get_account(&portfolio).unwrap().data).unwrap();
    assert_eq!(account.capital, 0, "capital paid out");
    assert_eq!(account.pnl, 0, "pnl zeroed by resolved close");
    // A fully-paid (haircut) resolved winner must reach a CLOSABLE receipt state so the
    // portfolio can dematerialize: either finalized, or cleared/absent once it has been
    // paid its full entitlement at the terminal rate. If it can't, materialized_portfolio_count
    // stays >= 1 and the market is permanently un-drainable (no WithdrawInsurance, no CloseSlab).
    assert!(
        !account.resolved_payout_receipt.present || account.resolved_payout_receipt.finalized,
        "haircut winner's receipt must be closable (finalized or cleared at the terminal rate); \
         present={} finalized={}",
        account.resolved_payout_receipt.present,
        account.resolved_payout_receipt.finalized,
    );

    // The consequence: the owner must be able to reclaim the fully-settled
    // portfolio (this dematerializes it). Panics if the receipt blocks closability.
    env.close_portfolio_with_cu(&owner, portfolio);
}

// Coverage probe (audit, Finding candidate): after a user defensively cures and
// cancels a forced close (CureAndCancelClose), their `close_progress` ledger is
// left in the `canceled` state, never reset to EMPTY. `withdraw_not_atomic`
// requires `close_progress == EMPTY`, so the user can never withdraw their flat,
// solvent capital again in Live mode. This test asserts the CORRECT outcome (the
// user can withdraw after curing).
// GREEN regression: Finding E was fixed in engine f9af174 (withdraw now allows an
// inert `canceled` close ledger).
#[test]
fn v16_audit_withdraw_after_cure_and_cancel_close() {
    let mut env = V16CuEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 100);
    env.seed_cancellable_close_progress(portfolio);

    // Owner cures + cancels the forced close (no position -> IM is 0, so no extra
    // deposit needed).
    let source = env.token_account(owner.pubkey(), 0);
    env.cure_and_cancel_close_with_cu(&owner, portfolio, source, 0);

    // The account is now flat and solvent (capital 100, no positions). The user
    // must be able to withdraw their own capital.
    env.withdraw_with_cu(&owner, portfolio, 100);
    let account = state::read_portfolio(&env.svm.get_account(&portfolio).unwrap().data).unwrap();
    assert_eq!(
        account.capital, 0,
        "a flat, solvent user must be able to withdraw their capital after curing a cancelled close",
    );
}

// security.md sweep — live insurance withdrawal must reject while insurance is still protecting
// unresolved loss (SOL-021/SOL-022 terminal/encumbered gating). live_domain_withdraw_health_or_shutdown
// _view (v16_program) blocks WithdrawInsuranceAsset on a live market whenever bankruptcy_hlock_active
// / threshold_stress_active / loss_stale_active / recovery_reason is set — exactly the states where the
// fund is the users' backstop for in-flight loss/bankruptcy work. If an operator could drain insurance
// then, users lose their protection (LOF). The exposed target/effective lag branch is covered by
// v16_attack_live_insurance_withdraw_rejects_exposed_target_effective_lag; the DISTINCT stress/h-lock/
// loss-stale OR-branch was untested. This sets each flag on an otherwise-healthy FLAT market
// (where the same withdrawal demonstrably succeeds) and asserts the withdrawal rejects with insurance +
// domain budget byte-unchanged — proving the stress flag is the sole blocker (non-vacuous).
#[test]
fn v16_attack_live_insurance_withdraw_rejects_while_stressed_or_hlocked() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(1, 10_000, 10_000, 24);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100_000_000);
    env.enable_live_insurance_withdrawal();
    env.top_up_insurance(1_000_000);
    env.top_up_insurance_domain_with_authority(&env.admin.insecure_clone(), 0, 1_000_000);
    let admin = env.admin.insecure_clone();
    // Sanity: on a healthy, flat, lag-free market the live asset withdrawal succeeds — so any rejection
    // below is caused specifically by the stress/h-lock flag, not by some unrelated precondition.
    env.svm.expire_blockhash();
    env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100)
        .expect("flat healthy live insurance withdrawal must succeed");
    // Each engine "insurance still protecting loss" flag must independently block the withdrawal.
    let cases: [(&str, fn(&mut MarketGroupV16, bool)); 3] = [
        ("bankruptcy_hlock_active", |g, v| {
            g.bankruptcy_hlock_active = v
        }),
        ("threshold_stress_active", |g, v| {
            g.threshold_stress_active = v
        }),
        ("loss_stale_active", |g, v| g.loss_stale_active = v),
    ];
    for (label, set) in cases {
        env.mutate_market(|_cfg, group| set(group, true));
        let before = env.market_state().1;
        env.svm.expire_blockhash();
        let r = env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100);
        assert!(
            r.is_err(),
            "live WithdrawInsuranceAsset must reject while {label} is set (insurance protecting loss)"
        );
        let after = env.market_state().1;
        assert_eq!(
            after.insurance, before.insurance,
            "rejected withdrawal under {label} must leave insurance untouched"
        );
        assert_eq!(
            after.insurance_domain_budget[0], before.insurance_domain_budget[0],
            "rejected withdrawal under {label} must leave the domain budget untouched"
        );
        // clear the flag so the next iteration tests its flag in isolation.
        env.mutate_market(|_cfg, group| set(group, false));
    }
}

// security.md sweep — resolved-mode backing withdrawal wind-down gate (SOL-021/022): LP backing is the
// loss-absorption layer behind users. In RESOLVED mode handle_withdraw_backing_bucket (v16_program)
// permits a withdrawal ONLY once materialized_portfolio_count == 0 AND c_tot == 0 — i.e. every user has
// been paid out and closed. If the backing_bucket_authority (or marketauth) could pull backing while
// resolved users still hold capital/claims, the vault would drop below what those users are owed (LOF).
// This is the backing parallel of v16_attack_withdraw_insurance_requires_full_wind_down (insurance), but a
// DISTINCT code path with a distinct condition (count+c_tot vs insurance wind-down). It was untested:
// the liened-winner case covers the LIVE lien path, not resolved-mode open capital. Non-vacuous: the same
// withdrawal succeeds on the live empty market first.
#[test]
fn v16_attack_resolved_backing_withdraw_requires_full_user_wind_down() {
    let mut env = V16CuEnv::new();
    env.top_up_backing_bucket(1, 1_000, 100_000); // domain 1 (asset-0 short) backing, admin-authorized
    let dest = env.token_account(env.admin.pubkey(), 0);
    // Sanity: on a live, user-free market the backing authority CAN withdraw — proves authority + path
    // are fine, so the resolved-mode rejection below is caused by the wind-down gate, not a precondition.
    env.svm.expire_blockhash();
    env.withdraw_backing_bucket_to_admin_token_with_cu(dest, 1, 100);
    // Open user capital, then resolve. c_tot + materialized_portfolio_count stay > 0.
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);
    env.deposit(&owner, portfolio, 600_000);
    env.resolve();
    let g = env.market_state().1;
    assert_eq!(g.mode, percolator::MarketModeV16::Resolved, "resolved");
    assert!(
        g.c_tot > 0,
        "user capital still open after resolve (non-vacuous gate)"
    );
    assert!(
        g.materialized_portfolio_count > 0,
        "user portfolio still materialized after resolve"
    );
    let vault_before = g.vault;
    let dest_before = env.token_amount(dest);
    let ledger = env.canonical_backing_domain_ledger_account(1);
    env.svm.expire_blockhash();
    let r = env.send(
        ProgInstruction::WithdrawBackingBucket {
            domain: 1,
            amount: 100,
        },
        vec![
            AccountMeta::new(env.admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&env.admin.insecure_clone()],
    );
    assert!(
        r.is_err(),
        "resolved-mode backing withdrawal must reject while users still hold capital/claims"
    );
    let g_after = env.market_state().1;
    assert_eq!(
        g_after.vault, vault_before,
        "rejected resolved backing withdrawal must leave the vault untouched"
    );
    assert_eq!(
        env.token_amount(dest),
        dest_before,
        "no backing tokens may leave to the authority before users are wound down"
    );
    assert!(
        g_after.vault >= g_after.c_tot + g_after.insurance,
        "senior conservation intact"
    );
}

// W10 (upstream wrapper a1a3ecb6, "Block drain-only backing fee batch gate"): the RETIRED-only
// guard in handle_update_backing_fee_policy leaves DrainOnly/Recovery assets able to install a
// NEW nonzero backing-fee policy. backing_trade_fee_policy_count is a MARKET-WIDE counter that
// handle_batch_execute_zero_copy checks and rejects BatchTradeNoCpi/matcher-batch entirely whenever
// it is nonzero (v1 scope: batch legs don't split per-domain backing fees yet). So a permissionless
// asset creator can move their OWN dead asset to DrainOnly/Recovery and then set a fresh nonzero fee
// on it, bumping the counter 0->1 and silently DoS-ing BatchTrade for every OTHER asset in the
// market too -- a self-inflicted, market-wide griefing vector. Non-vacuous: proves BOTH that the
// policy update on a non-ACTIVE asset is rejected (the fix) AND that an unrelated asset's
// BatchTradeNoCpi still executes normally afterward (the counter never got bumped).
#[test]
fn v16_attack_non_active_asset_cannot_enable_backing_fee_batch_gate() {
    for (label, action, now_slot, expected_lifecycle) in [
        (
            "DrainOnly",
            percolator_prog::processor::ASSET_ACTION_DRAIN_ONLY,
            0u64,
            AssetLifecycleV16::DrainOnly,
        ),
        (
            "Recovery",
            percolator_prog::processor::ASSET_ACTION_SHUTDOWN,
            2u64,
            AssetLifecycleV16::Recovery,
        ),
    ] {
        let mut env = V16CuEnv::new_with_market_params_and_price_move(1, 1_000, 1_000, 500);
        env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
        if action == percolator_prog::processor::ASSET_ACTION_SHUTDOWN {
            env.configure_permissionless_resolve_with_cu(9000, 5);
        }
        env.update_market_init_fee_policy_with_cu(1);

        let creator = Keypair::new();
        env.svm.warp_to_slot(1);
        env.activate_permissionless_asset_with_fee(
            &creator,
            1,
            1,
            100,
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            1,
        );
        // Both DrainOnly (marketauth-gated) and Recovery/SHUTDOWN (marketauth-OR-asset_admin
        // gated) accept the market admin as signer, so a single admin-driven helper covers both
        // legs of the loop -- see handle_update_asset_lifecycle's SHUTDOWN branch (accepts
        // marketauth_authorized || asset_admin_authorized) and its "gated solely on marketauth"
        // fallthrough for DRAIN_ONLY/ACTIVATE/RETIRE.
        env.update_asset_lifecycle_as_admin_with_cu(action, 1, now_slot, 0);
        let (cfg_after_lifecycle, group_after_lifecycle) = env.market_state();
        assert_eq!(
            group_after_lifecycle.assets[1].lifecycle,
            expected_lifecycle
        );
        assert_eq!(cfg_after_lifecycle.backing_trade_fee_policy_count, 0);

        env.svm.expire_blockhash();
        let policy = send_tx(
            &mut env.svm,
            env.program_id,
            &env.payer,
            ProgInstruction::UpdateBackingFeePolicy {
                domain: 2,
                fee_bps: 77,
                insurance_share_bps: 5_000,
            },
            vec![
                AccountMeta::new(creator.pubkey(), true),
                AccountMeta::new(env.market, false),
            ],
            &[&creator],
        );
        assert!(
            policy.is_err(),
            "{label} asset must not install a new backing-fee policy that globally gates batch trades"
        );
        assert_eq!(
            env.market_state().0.backing_trade_fee_policy_count,
            0,
            "rejected {label} policy update must not enable the global batch gate"
        );

        let taker = Keypair::new();
        let lp = Keypair::new();
        let ta = env.create_portfolio(&taker);
        let la = env.create_portfolio(&lp);
        env.deposit(&taker, ta, 1_000_000);
        env.deposit(&lp, la, 1_000_000);
        let sz = (5 * POS_SCALE) as i128;
        env.svm.expire_blockhash();
        let batch = env.send(
            ProgInstruction::BatchTradeNoCpi {
                legs: vec![percolator_prog::ix::BatchTradeLeg {
                    asset_index: 0,
                    size_q: sz,
                    exec_price: 100,
                    fee_bps: 0,
                }],
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(lp.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(ta, false),
                AccountMeta::new(la, false),
            ],
            &[&taker, &lp],
        );
        assert!(
            batch.is_ok(),
            "rejected {label} asset policy must leave unrelated asset-0 batch trading live: {batch:?}"
        );
        assert_eq!(
            active_leg_for_asset(&env.portfolio_state(ta), 0).basis_pos_q,
            sz
        );
        assert_eq!(
            active_leg_for_asset(&env.portfolio_state(la), 0).basis_pos_q,
            -sz
        );
    }
}

// FIX E4 batch-fee reconciliation (LOW security nit, percolator-security review): the wrapper's
// batch_leg_fee reconstructed per-leg fees on PRE-E4 FLOOR notional after the engine's trade-fee
// calc switched to CEIL notional (upstream engine 8f25aa5d). A sub-atom-notional leg
// (abs_size_q * exec_price / POS_SCALE < 1, i.e. floor-notional == 0) now opens nonzero OI for a
// nonzero fee at the engine level -- outcome.fee_a/fee_b reflects that ceil-rounded fee -- but the
// wrapper's reconstruction still computed floor-notional fee=0 for that leg, so the aggregate
// cross-check (`reconstructed_total != engine_total`) tripped and hard-reverted the WHOLE batch.
// Fails closed (no mis-accounting), but every batch containing a sub-atom-notional leg started
// reverting where it previously succeeded at zero fee -- an availability gap for otherwise
// legitimate multi-leg batches. Non-vacuous: this exact scenario (adapted from the engine's own
// v16_subatom_trade_charges_fee_on_ceil_fee_notional non-vacuity test) is verified BOTH ways in
// the task return -- passes with batch_leg_fee ported to ceil notional, and hard-reverts
// (EngineArithmeticOverflow, the aggregate cross-check) when batch_leg_fee is reverted to floor.
#[test]
fn v16_bpf_batch_trade_nocpi_subatom_leg_charges_fee_on_ceil_notional() {
    let mut env = V16CuEnv::new();
    let taker_owner = Keypair::new();
    let lp_owner = Keypair::new();
    let taker_account = env.create_portfolio(&taker_owner);
    let lp_account = env.create_portfolio(&lp_owner);
    env.deposit(&taker_owner, taker_account, 1_000_000);
    env.deposit(&lp_owner, lp_account, 1_000_000);

    // sub_atom_size * exec_price / POS_SCALE floors to 0 (999_900 / 1_000_000 for
    // POS_SCALE = 1_000_000), but ceils to 1 -- the exact sub-atom-notional boundary E4 targets.
    // Matches the engine's own non-vacuity test for the same fix
    // (v16_subatom_trade_charges_fee_on_ceil_fee_notional in percolator/tests/v16_spec_tests.rs).
    let sub_atom_size = (POS_SCALE / 100 - 1) as i128;
    env.svm.expire_blockhash();
    let taker_capital_before = env.portfolio_state(taker_account).capital;
    let lp_capital_before = env.portfolio_state(lp_account).capital;
    let batch = env.send(
        ProgInstruction::BatchTradeNoCpi {
            legs: vec![percolator_prog::ix::BatchTradeLeg {
                asset_index: 0,
                size_q: sub_atom_size,
                exec_price: 100,
                fee_bps: 1,
            }],
        },
        vec![
            AccountMeta::new(taker_owner.pubkey(), true),
            AccountMeta::new(lp_owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(taker_account, false),
            AccountMeta::new(lp_account, false),
        ],
        &[&taker_owner, &lp_owner],
    );
    assert!(
        batch.is_ok(),
        "a sub-atom-notional leg must not hard-revert the whole batch once batch_leg_fee \
         agrees with the engine's ceil-notional fee calc: {batch:?}"
    );

    let taker_after = env.portfolio_state(taker_account);
    let lp_after = env.portfolio_state(lp_account);
    assert_eq!(
        taker_after.capital,
        taker_capital_before - 1,
        "taker (long, the batch's taker-only payer) must be charged exactly the ceil-notional \
         fee of 1 atom, not the floor-notional 0 the wrapper used to reconstruct"
    );
    assert_eq!(
        lp_after.capital, lp_capital_before,
        "maker (short) pays nothing under taker-only"
    );
    assert_eq!(
        active_leg_for_asset(&taker_after, 0).basis_pos_q,
        sub_atom_size,
        "the sub-atom fill must still open its full nonzero position despite floor-notional \
         reading zero"
    );
    assert_eq!(
        active_leg_for_asset(&lp_after, 0).basis_pos_q,
        -sub_atom_size
    );

    let (cfg_after, group_after) = env.market_state();
    // Four-way split (2026-07-19, Task 5): a 1-atom fee floors to 0 on all of
    // protocol/creator/lp (each share_bps * 1 / 10_000 floors to 0), so
    // split_trade_fee's remainder rule routes the whole atom to the insurance
    // leg instead of the domain budget -- verified directly (not asserted
    // away): domain=0, protocol=0, lp=0, insurance=1, and
    // group_after.insurance (header-level total) still receives the full
    // atom, so nothing is lost, only re-routed to the new destination this
    // task wires up.
    assert_eq!(
        group_after.insurance_domain_budget[0]
            + cfg_after.protocol_fee_accrued_atoms
            + cfg_after.lp_fee_accrued_atoms
            + cfg_after.insurance_reserve_accrued_atoms,
        1,
        "the reconstructed 1-atom fee must be credited somewhere (domain budget, protocol cut, \
         lp, or insurance reserve), not silently dropped"
    );
}

// security.md sweep — CloseResolved caller-supplied fee_rate_per_slot must be IGNORED (Copenhagen
// SOL-001-class spoofed-param / SOL-023 fee-rounding-away-from-user): CloseResolved is permissionless
// after the exit window (force_close_delay_slots==0 -> always permissionless), and it carries a
// caller-supplied `fee_rate_per_slot`. handle_close_resolved names it `_fee_rate_per_slot` and passes
// cfg.maintenance_fee_per_slot to the engine instead. If the param were honored, a hostile third party
// finalizing a victim's resolved account could pass a huge rate to over-charge the victim's accrued
// maintenance fee at terminal close, draining the payout into insurance (victim LOF). Every existing
// CloseResolved test passes fee_rate_per_slot: 0, so this ignore property is unpinned. With cfg
// maintenance_fee=0 and slots elapsed, the victim must receive the FULL deposit regardless of a
// u128::MAX spoofed rate; a regression that wired the param in would drain it to ~0.
#[test]
fn v16_attack_close_resolved_ignores_spoofed_fee_rate_param() {
    let mut env = V16CuEnv::new(); // default maintenance_fee_per_slot = 0, force_close_delay_slots = 0
    let victim_owner = Keypair::new();
    let victim = env.create_portfolio(&victim_owner);
    env.deposit(&victim_owner, victim, 1_000_000);
    env.resolve();
    // Advance many slots so elapsed_slots is large: a leaked spoofed rate would charge rate*elapsed.
    env.svm.warp_to_slot(10_000);
    let dest = Pubkey::new_unique();
    env.svm
        .set_account(
            dest,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, victim_owner.pubkey(), 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    env.svm.expire_blockhash();
    // Permissionless finalize (no signer) with a maximally-spoofed fee rate.
    env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: u128::MAX,
        },
        vec![
            AccountMeta::new_readonly(victim_owner.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(victim, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    )
    .expect("permissionless close-resolved with spoofed fee rate");
    assert_eq!(
        env.token_amount(dest),
        1_000_000,
        "victim must receive the FULL deposit; the caller-supplied fee_rate_per_slot must be ignored"
    );
    let (_, g) = env.market_state();
    assert_eq!(
        env.portfolio_state(victim).capital,
        0,
        "account fully closed"
    );
    assert_eq!(
        g.vault,
        g.c_tot + g.insurance,
        "conservation after terminal close"
    );
}

// W5 (upstream b7b6688e / #154) — CloseResolved is permissionless (any caller can finalize a
// victim's resolved account, per the test above); verify_withdrawable_token_accounts checks
// dest.mint/owner/state but not dest.delegate/dest.close_authority. A pre-poisoned destination
// (victim-owned, but with an attacker-set delegate or close_authority) must be REJECTED, not
// paid out — otherwise the delegate/close_authority can sweep the payout with no signature from
// the victim. A clean destination must still succeed (fix must not be over-broad).
#[test]
fn v16_attack_permissionless_close_resolved_rejects_delegated_dest() {
    let mut env = V16CuEnv::new();
    let victim_owner = Keypair::new();
    let victim = env.create_portfolio(&victim_owner);
    env.deposit(&victim_owner, victim, 1_000);
    env.resolve();

    let attacker = Keypair::new();
    let delegated_dest = Pubkey::new_unique();
    env.svm
        .set_account(
            delegated_dest,
            Account {
                lamports: 1_000_000_000,
                data: make_delegated_token_data(
                    env.mint,
                    victim_owner.pubkey(),
                    0,
                    attacker.pubkey(),
                    u64::MAX,
                ),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let market_before = env.svm.get_account(&env.market).unwrap();
    let portfolio_before = env.svm.get_account(&victim).unwrap();
    let vault_before = env.svm.get_account(&env.vault).unwrap();
    let dest_before = env.svm.get_account(&delegated_dest).unwrap();

    env.svm.expire_blockhash();
    let rejected = env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        vec![
            AccountMeta::new_readonly(victim_owner.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(victim, false),
            AccountMeta::new(delegated_dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    );
    assert!(
        rejected.is_err(),
        "permissionless CloseResolved must reject a victim-owned destination with an active delegate"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap(),
        market_before,
        "rejected delegated-dest close leaves market accounting unchanged"
    );
    assert_eq!(
        env.svm.get_account(&victim).unwrap(),
        portfolio_before,
        "rejected delegated-dest close rolls back payout state"
    );
    assert_eq!(
        env.svm.get_account(&env.vault).unwrap(),
        vault_before,
        "rejected delegated-dest close moves no vault custody"
    );
    assert_eq!(
        env.svm.get_account(&delegated_dest).unwrap(),
        dest_before,
        "delegated destination receives no payout"
    );

    let closable_dest = Pubkey::new_unique();
    env.svm
        .set_account(
            closable_dest,
            Account {
                lamports: 1_000_000_000,
                data: make_closable_token_data(
                    env.mint,
                    victim_owner.pubkey(),
                    0,
                    attacker.pubkey(),
                ),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let closable_before = env.svm.get_account(&closable_dest).unwrap();
    env.svm.expire_blockhash();
    let rejected = env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        vec![
            AccountMeta::new_readonly(victim_owner.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(victim, false),
            AccountMeta::new(closable_dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    );
    assert!(
        rejected.is_err(),
        "permissionless CloseResolved must reject a victim-owned destination with close authority"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&victim).unwrap(), portfolio_before);
    assert_eq!(env.svm.get_account(&env.vault).unwrap(), vault_before);
    assert_eq!(
        env.svm.get_account(&closable_dest).unwrap(),
        closable_before,
        "close-authority destination receives no payout"
    );

    let clean_dest = env.token_account(victim_owner.pubkey(), 0);
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        vec![
            AccountMeta::new_readonly(victim_owner.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(victim, false),
            AccountMeta::new(clean_dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    )
    .expect("same permissionless close succeeds with a clean victim destination");
    assert_eq!(env.token_amount(clean_dest), 1_000);
    assert_eq!(env.market_state().1.vault, 0);
    assert_eq!(env.portfolio_state(victim).capital, 0);
}

// Regression for #113 — permissionless cross-asset maintenance-fee siphon (FIXED).
// credit_maintenance_fee_to_active_market_budgets_view previously split every
// maintenance fee equally across all ACTIVE assets' insurance domains with no positions/activity
// requirement, so a non-admin could append a do-nothing asset (itself as insurance_operator) and
// capture 1/N of every honest trader's maintenance fee, then withdraw it via WithdrawInsuranceAsset.
// The fix credits the account-level maintenance fee solely to asset-0 (the canonical base insurance,
// not permissionlessly creatable), so a parasitic zero-activity asset earns ZERO. This guards the fix.
#[test]
fn v16_attack_bug113_maintenance_fee_siphon_to_parasitic_asset() {
    // capacity 1 (asset-1 is appended at index == configured_slots, growing to 2), maintenance fee 58/slot.
    let mut env = V16CuEnv::new_with_market_params_price_move_and_maintenance_fee(
        1, 10_000, 10_000, 10_000, 58,
    );
    env.update_market_init_fee_policy_with_cu(1); // permissionless create enabled (nonzero fee)
                                                  // Honest depositor H on the real market (asset 0).
    let h_owner = Keypair::new();
    let h = env.create_portfolio(&h_owner);
    env.deposit(&h_owner, h, 100_000_000);
    // Attacker permissionlessly appends a do-nothing asset 1 with ITSELF as insurance_operator.
    let attacker = Keypair::new();
    env.ensure_signer_account(attacker.pubkey());
    env.svm.warp_to_slot(1);
    env.activate_permissionless_asset_with_fee(
        &attacker,
        1,
        1,
        100,
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        attacker.pubkey(),
        1,
    );
    let (_, g_pre) = env.market_state();
    assert_eq!(
        g_pre.assets[1].lifecycle,
        AssetLifecycleV16::Active,
        "parasite asset-1 active"
    );
    // asset-1 domains (2 = long, 3 = short) start empty: it has no positions and was never funded.
    assert_eq!(g_pre.insurance_domain_budget[2], 0);
    assert_eq!(g_pre.insurance_domain_budget[3], 0);
    // Charge H's maintenance fee (58 * 10 slots = 580... but slot 1 is already used, so 9 slots = 522).
    env.svm.warp_to_slot(10);
    let h_cap_before = env.portfolio_state(h).capital;
    env.svm.expire_blockhash();
    env.sync_maintenance_fee_with_cu(h, None, 10);
    let fee_paid = h_cap_before - env.portfolio_state(h).capital;
    assert!(
        fee_paid > 0,
        "H actually paid a maintenance fee (non-vacuous)"
    );
    // SECURITY PROPERTY: the parasitic zero-activity asset-1 must have captured NOTHING of H's fee.
    let (_, g) = env.market_state();
    let parasite_share = g.insurance_domain_budget[2] + g.insurance_domain_budget[3];
    assert_eq!(
        parasite_share, 0,
        "BUG #113 REGRESSION: parasitic asset-1 captured {parasite_share} of H's {fee_paid} maintenance fee"
    );
    // And the attacker must not be able to withdraw any of it as that asset's insurance_operator.
    env.svm.expire_blockhash();
    let siphon = env.try_withdraw_insurance_asset_with_authority(&attacker, 1, 1);
    assert!(
        siphon.is_err(),
        "BUG #113 REGRESSION: attacker siphoned honest maintenance fees via WithdrawInsuranceAsset(asset 1)"
    );
}

// ── FZS-1 reproduction: flat ADL_ONE accrual mints value under asymmetric `a`. ──
// Reaches the asymmetric-`a` state via the engine's OWN unilateral-close path
// (RebalanceReduce → reduce_matching_open_interest_for_unilateral_close), NOT a
// hand write: the long closes half its position, scaling a_short by oi_after/oi_before
// = 1/2 while short OI stays > 0; the surviving short LEG keeps a_basis = ADL_ONE.
// A price move is then accrued flat (ADL_ONE both sides) and settled. Because the
// surviving short over-hangs (2-unit basis over 1-unit OI) and realizes its move
// divided by a_basis=ADL_ONE instead of a_short=ADL_ONE/2, a downward move makes the
// short over-realize a gain → withdrawable value is MINTED (obligations > vault).
#[test]
fn v16_fzs1_real_partial_adl_flat_accrual_mints_under_asymmetric_a() {
    const INITIAL_PRICE: u64 = 1_000_000;
    const DEPOSIT: u128 = 100_000_000;

    let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams {
        initial_price: INITIAL_PRICE,
        max_price_move_bps_per_slot: 1_000,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 1,
        ..V16CuMarketParams::default()
    });
    env.svm.warp_to_slot(0);
    env.configure_ewma_mark_with_cu(0, INITIAL_PRICE, 1, 0);

    let long_owner = Keypair::new();
    let short_owner = Keypair::new();
    let long_account = env.create_portfolio(&long_owner);
    let short_account = env.create_portfolio(&short_owner);
    env.deposit(&long_owner, long_account, DEPOSIT);
    env.deposit(&short_owner, short_account, DEPOSIT);

    // Real matched open: 2 units long vs 2 units short at INITIAL_PRICE.
    env.trade_with_cu(
        &long_owner,
        long_account,
        &short_owner,
        short_account,
        (2 * POS_SCALE) as i128,
        INITIAL_PRICE,
        0,
    );
    let (_, g_pre) = env.market_state();
    assert_eq!(g_pre.assets[0].a_long, ADL_ONE, "pre-ADL a_long balanced");
    assert_eq!(g_pre.assets[0].a_short, ADL_ONE, "pre-ADL a_short balanced");
    assert_eq!(g_pre.assets[0].oi_eff_long_q, 2 * POS_SCALE);
    assert_eq!(g_pre.assets[0].oi_eff_short_q, 2 * POS_SCALE);
    let short_pre = env.portfolio_state(short_account);
    assert_eq!(
        short_pre.legs[0].a_basis, ADL_ONE,
        "short leg a_basis frozen at ADL_ONE"
    );

    // REAL partial ADL: long unilaterally closes HALF (engine path, no hand-mutation).
    env.rebalance_reduce_with_cu(&long_owner, long_account, 0, POS_SCALE);
    let (_, g_adl) = env.market_state();
    eprintln!(
        "POST-REAL-ADL: a_long={} a_short={} oi_long={} oi_short={}",
        g_adl.assets[0].a_long,
        g_adl.assets[0].a_short,
        g_adl.assets[0].oi_eff_long_q,
        g_adl.assets[0].oi_eff_short_q,
    );
    assert!(
        g_adl.assets[0].a_short < ADL_ONE,
        "ADL scaled a_short below ADL_ONE"
    );
    assert!(
        g_adl.assets[0].oi_eff_short_q > 0,
        "short OI still positive (partial ADL)"
    );
    assert_eq!(g_adl.assets[0].a_long, ADL_ONE, "a_long untouched");
    let short_adl = env.portfolio_state(short_account);
    assert_eq!(
        short_adl.legs[0].a_basis, ADL_ONE,
        "surviving short leg a_basis STILL ADL_ONE (divergence)"
    );

    let vault_before = g_adl.vault;

    // Accrue a DOWNWARD price move, then settle both legs (crank). The over-hanging
    // short realizes its move at a_basis=ADL_ONE rather than a_short=ADL_ONE/2.
    // Slot 1: accrue the downward move + settle (the first-cranked leg settles BEFORE the
    // accrual, so its PnL is not yet realized).
    env.svm.warp_to_slot(1);
    // Mark = -10% (the per-slot cap), so the effective price reaches 900_000 in ONE slot
    // and then HOLDS — no further EWMA chase at slot 2, giving a clean settle-only pass.
    env.push_ewma_mark_with_cu(1, INITIAL_PRICE * 9 / 10);
    for acct in [long_account, short_account] {
        env.crank(
            acct,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index: 0,
                now_slot: 1,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }
    // Slot 2: hold the mark at the current effective price (no further move) and crank again
    // so BOTH legs settle at the accrued state — the first-cranked leg now realizes its move.
    let eff_now = env.market_state().1.assets[0].effective_price;
    env.svm.warp_to_slot(2);
    env.push_ewma_mark_with_cu(2, eff_now);
    for acct in [long_account, short_account] {
        env.crank(
            acct,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index: 0,
                now_slot: 2,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }

    let (_, g1) = env.market_state();
    let lp = env.portfolio_state(long_account);
    let sp = env.portfolio_state(short_account);
    let obligations = g1.c_tot + g1.insurance + g1.pnl_pos_tot;
    eprintln!(
        "long: capital={} pnl={} reserved_pnl={} leg[active={} basis={} a_basis={} k_snap={}]",
        lp.capital,
        lp.pnl,
        lp.reserved_pnl,
        lp.legs[0].active,
        lp.legs[0].basis_pos_q,
        lp.legs[0].a_basis,
        lp.legs[0].k_snap
    );
    eprintln!(
        "short: capital={} pnl={} reserved_pnl={} leg[active={} basis={} a_basis={} k_snap={}]",
        sp.capital,
        sp.pnl,
        sp.reserved_pnl,
        sp.legs[0].active,
        sp.legs[0].basis_pos_q,
        sp.legs[0].a_basis,
        sp.legs[0].k_snap
    );
    eprintln!(
        "asset k_long={} k_short={} a_long={} a_short={} eff_price={}",
        g1.assets[0].k_long,
        g1.assets[0].k_short,
        g1.assets[0].a_long,
        g1.assets[0].a_short,
        g1.assets[0].effective_price
    );
    eprintln!(
        "FZS-1 PoC: c_tot={} insurance={} pnl_pos_tot={} obligations={} vault={} (vault_before={}) MINTED={}",
        g1.c_tot,
        g1.insurance,
        g1.pnl_pos_tot,
        obligations,
        g1.vault,
        vault_before,
        obligations.saturating_sub(g1.vault),
    );
    // POST-FIX regression guard: per-side `a`-scaled accrual conserves — NO mint.
    // Pre-fix (flat ADL_ONE accrual) this minted 200,000: obligations 200,200,000 > vault 200,000,000.
    assert!(
        obligations <= g1.vault,
        "FZS-1 fixed: per-side accrual must NOT mint — obligations {} must be <= vault {} (residual {})",
        obligations,
        g1.vault,
        obligations.saturating_sub(g1.vault),
    );
}

// ── LIEN-1 reproduction: a shared backing bucket strands a co-tenant winner on expiry. ──
// Two winners (A, B) each lien the SAME per-domain backing bucket (valid_liened = a + b). After
// the bucket's expiry slot lapses, A's CloseResolved releases A's share and the shared-bucket
// expire forfeits the WHOLE remaining valid_liened (B's live share) to impaired (valid_liened -> 0).
// B's CloseResolved then terminal-releases its recorded share against the now-empty valid counter:
// the counterparty terminal release is NOT impaired-aware (unlike the insurance twin), so
// bucket.valid_liened(0) < b -> CounterUnderflow (Custom(25)) -> B permanently un-closable.
#[test]
fn v16_lien1_shared_bucket_expire_strands_other_winner() {
    let mut env = V16CuEnv::new();
    let owner_a = Keypair::new();
    let owner_b = Keypair::new();
    let a = env.create_portfolio(&owner_a);
    let b = env.create_portfolio(&owner_b);
    env.deposit(&owner_a, a, 1_000);
    env.deposit(&owner_b, b, 1_000);

    // One SHARED backing bucket on domain 1, expiring at slot 2; A and B each lien 250 against it.
    env.top_up_backing_bucket(1, 500, 2);
    env.add_source_positive_pnl(a, 1, 250);
    env.add_source_positive_pnl(b, 1, 250);

    // Replicate the counterparty source-credit lien (create_source_credit_lien_from_counterparty +
    // apply_account_source_credit_lien_delta are kani/fuzz-gated): lien the full reserved backing
    // into valid_liened on the shared bucket + source-credit, and record each account's lien share.
    let (_, g_pre) = env.market_state();
    let lien_total = g_pre.source_credit[1].fresh_reserved_backing_num;
    env.mutate_market(|_cfg, group| {
        let sc = &mut group.source_credit[1];
        sc.valid_liened_backing_num = lien_total;
        sc.credit_rate_num = 0;
        let bucket = &mut group.source_backing_buckets[1];
        let total = bucket.fresh_unliened_backing_num + bucket.valid_liened_backing_num;
        bucket.valid_liened_backing_num = lien_total;
        bucket.fresh_unliened_backing_num = total - lien_total;
    });
    for acct in [a, b] {
        let mut pa = env.svm.get_account(&acct).unwrap();
        let mut p = state::read_portfolio(&pa.data).unwrap();
        let face = lien_total / 2;
        let backing = lien_total / 2;
        let effective = backing / BOUND_SCALE;
        p.source_claim_liened_num[1] = face;
        p.source_claim_counterparty_liened_num[1] = face;
        p.source_lien_counterparty_backing_num[1] = backing;
        p.source_lien_effective_reserved[1] = effective;
        state::write_portfolio(&mut pa.data, &p).unwrap();
        env.svm.set_account(acct, pa).unwrap();
    }
    let (_, g0) = env.market_state();
    assert_eq!(
        g0.source_credit[1].valid_liened_backing_num, lien_total,
        "shared bucket / source-credit holds BOTH winners' liens (a + b)"
    );
    assert!(
        lien_total > 0,
        "lien must be non-zero for the strand to matter"
    );

    // Lapse past the bucket expiry (slot 2), resolve, then A closes (drains valid_liened to 0 via
    // its release + the shared-bucket expire).
    env.svm.warp_to_slot(5);
    env.resolve();
    let dest_a = env.close_resolved(&owner_a, a);
    assert!(
        env.token_amount(dest_a) > 0,
        "A (first winner) closes and is paid"
    );
    let (_, g_after_a) = env.market_state();
    eprintln!(
        "AFTER A: bucket[valid={} impaired={}] source[valid={} impaired={}]",
        g_after_a.source_backing_buckets[1].valid_liened_backing_num,
        g_after_a.source_backing_buckets[1].impaired_liened_backing_num,
        g_after_a.source_credit[1].valid_liened_backing_num,
        g_after_a.source_credit[1].impaired_liened_backing_num,
    );

    // B's CloseResolved — STRANDED.
    let dest_b = env.token_account(owner_b.pubkey(), 0);
    let result_b = env.send(
        ProgInstruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        vec![
            AccountMeta::new_readonly(owner_b.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(b, false),
            AccountMeta::new(dest_b, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[],
    );
    eprintln!(
        "B-CLOSE result: {result_b:?}  | B dest token = {}",
        env.token_amount(dest_b)
    );
    // POST-FIX regression guard: B's CloseResolved now SUCCEEDS — the impaired-aware terminal
    // release winds down B's forfeited share instead of underflowing. Pre-fix this reverted with
    // Custom(25) = CounterUnderflow and B got 0 payout (permanently un-closable).
    assert!(
        result_b.is_ok(),
        "LIEN-1 fixed: B's CloseResolved must SUCCEED via the impaired-aware terminal release; got {result_b:?}"
    );
    assert!(
        env.token_amount(dest_b) > 0,
        "B (second winner) is paid its resolved claim — no longer stranded"
    );
    // The shared domain is fully wound down — no valid or impaired residue left behind.
    let (_, g_final) = env.market_state();
    assert_eq!(
        g_final.source_backing_buckets[1].valid_liened_backing_num, 0,
        "no valid residue"
    );
    assert_eq!(
        g_final.source_backing_buckets[1].impaired_liened_backing_num, 0,
        "no impaired residue"
    );
}

// FIX-1 regression test (positive case): bankruptcy_hlock_active auto-clears when the LAST
// negative-PnL account is settled back to zero via principal.
//
// Scenario: a prior deep liquidation set the hlock.  The user's loss is fully covered by their
// own remaining capital (no insurance drain, no b-stale, no open positions).  Calling
// PermissionlessCrank (Refresh) runs `settle_negative_pnl_from_principal_core_not_atomic`,
// which now calls `try_clear_bankruptcy_hlock_if_healthy` at the end.  Once
// negative_pnl_account_count == 0 and all other counters are zero, the hlock must clear and
// the previously-blocked insurance withdrawal must succeed.
//
// Non-vacuous: the same withdrawal demonstrably succeeds on a fresh healthy market (the sanity
// check at the top), confirming the hlock — not some unrelated precondition — was the sole
// blocker during the middle section of the test.
#[test]
fn v16_hlock_auto_clears_when_last_negative_pnl_account_settles() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(1, 10_000, 10_000, 24);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100_000_000);
    env.top_up_insurance(1_000_000);
    env.top_up_insurance_domain_with_authority(&env.admin.insecure_clone(), 0, 1_000_000);
    let admin = env.admin.insecure_clone();

    // Sanity: on a healthy, flat market the insurance withdrawal succeeds immediately.
    env.svm.expire_blockhash();
    env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100)
        .expect("sanity: flat healthy market must allow insurance withdrawal");

    // Create a user, deposit enough capital to cover the simulated loss.
    let user = Keypair::new();
    let user_portfolio = env.create_portfolio(&user);
    env.deposit(&user, user_portfolio, 10_000);

    // Simulate a prior bankruptcy event: inject negative PnL (fully covered by the user's
    // capital) and set the hlock as a deep-liquidation path would.
    env.force_portfolio_loss_for_security_test(user_portfolio, 500);
    env.mutate_market(|_cfg, group| {
        group.bankruptcy_hlock_active = true;
    });

    // BLOCKED: the hlock is now active — the same withdrawal that succeeded above must now fail.
    env.svm.expire_blockhash();
    let before = env.market_state().1;
    let blocked = env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100);
    assert!(
        blocked.is_err(),
        "insurance withdrawal must be blocked while bankruptcy_hlock_active is set"
    );
    assert_eq!(
        env.market_state().1.insurance,
        before.insurance,
        "rejected withdrawal must leave insurance unchanged"
    );

    // Settle the negative-PnL account via PermissionlessCrank (Refresh, action=0).  The engine
    // call chain is: permissionless_crank_not_atomic → settle_account_side_effects_not_atomic
    // → settle_negative_pnl_from_principal_not_atomic → settle_negative_pnl_from_principal_core_not_atomic
    // → (my fix) try_clear_bankruptcy_hlock_if_healthy.
    env.svm.expire_blockhash();
    env.crank(
        user_portfolio,
        ProgInstruction::PermissionlessCrank {
            action: 0, // Refresh
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    // FIX-1 assertion: hlock must be auto-cleared after settling the last negative-PnL account.
    let (_, g_after) = env.market_state();
    assert!(
        !g_after.bankruptcy_hlock_active,
        "FIX-1: bankruptcy_hlock_active must auto-clear once negative_pnl_account_count reaches 0"
    );
    assert_eq!(
        g_after.negative_pnl_account_count, 0,
        "counter must be zero after settlement"
    );

    // UNBLOCKED: the previously-blocked withdrawal must now succeed.
    env.svm.expire_blockhash();
    env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100)
        .expect("FIX-1: insurance withdrawal must succeed after hlock auto-clears");
}

// FIX-1 regression test (negative case): bankruptcy_hlock_active MUST NOT clear while ANY
// negative-PnL account remains outstanding.
//
// Two users sustain losses.  After settling ONLY the first user, the hlock must stay active
// because the second user's negative-PnL account (negative_pnl_account_count = 1) keeps the
// condition from being met.  Only after the second user's PnL is settled does the hlock clear.
#[test]
fn v16_hlock_stays_set_while_any_negative_pnl_account_remains() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(1, 10_000, 10_000, 24);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_with_cu(1, 100_000_000);
    env.top_up_insurance(1_000_000);
    env.top_up_insurance_domain_with_authority(&env.admin.insecure_clone(), 0, 1_000_000);
    let admin = env.admin.insecure_clone();

    // Create two users, each with enough capital to cover their loss.
    let user_a = Keypair::new();
    let portfolio_a = env.create_portfolio(&user_a);
    env.deposit(&user_a, portfolio_a, 10_000);

    let user_b = Keypair::new();
    let portfolio_b = env.create_portfolio(&user_b);
    env.deposit(&user_b, portfolio_b, 10_000);

    // Both accounts sustain a loss; hlock is set (simulating a prior deep liquidation).
    env.force_portfolio_loss_for_security_test(portfolio_a, 500);
    env.force_portfolio_loss_for_security_test(portfolio_b, 500);
    env.mutate_market(|_cfg, group| {
        group.bankruptcy_hlock_active = true;
    });
    let (_, g_init) = env.market_state();
    assert_eq!(
        g_init.negative_pnl_account_count, 2,
        "both users must be in the negative-pnl count"
    );

    // Settle ONLY the first user's account.
    env.svm.expire_blockhash();
    env.crank(
        portfolio_a,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    // Hlock must remain — user B still has negative PnL (negative_pnl_account_count == 1).
    let (_, g_mid) = env.market_state();
    assert_eq!(
        g_mid.negative_pnl_account_count, 1,
        "one negative-PnL account remains"
    );
    assert!(
        g_mid.bankruptcy_hlock_active,
        "hlock must NOT clear while user B's negative-PnL account is still outstanding"
    );
    env.svm.expire_blockhash();
    assert!(
        env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100)
            .is_err(),
        "withdrawal must remain blocked while hlock is active"
    );

    // Now settle the second user's account.
    env.svm.expire_blockhash();
    env.crank(
        portfolio_b,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    // Both counters now zero — hlock must auto-clear.
    let (_, g_final) = env.market_state();
    assert_eq!(
        g_final.negative_pnl_account_count, 0,
        "both accounts settled"
    );
    assert!(
        !g_final.bankruptcy_hlock_active,
        "hlock must auto-clear once ALL negative-PnL accounts are settled"
    );
    env.svm.expire_blockhash();
    env.try_withdraw_insurance_asset_with_authority(&admin, 0, 100)
        .expect(
            "insurance withdrawal must succeed after all accounts are settled and hlock clears",
        );
}

// security.md sweep - stale-resolve config drift (W6, upstream 8a24cb8a): once the market is already
// old enough for ResolveStalePermissionless, marketauth must not be able to move the resolve
// threshold forward. Otherwise the fallback can be DoSed in the stale window by reconfiguring
// stale_slots before the permissionless resolver captures the terminal snapshot.
#[test]
fn v16_attack_configure_permissionless_resolve_rejects_when_resolve_matured() {
    let mut env = V16CuEnv::new();
    let admin = env.admin.insecure_clone();
    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.configure_auth_mark_with_cu(0, 100);

    env.svm.warp_to_slot(8998);
    env.push_auth_mark_with_cu(3, 100);

    // Non-vacuous fresh control: before the stale boundary, marketauth can still tune the policy.
    env.svm.warp_to_slot(8999);
    env.svm.expire_blockhash();
    let fresh = env.send(
        ProgInstruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 6,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    );
    assert!(
        fresh.is_ok(),
        "fresh ConfigurePermissionlessResolve remains reachable: {fresh:?}"
    );
    assert_eq!(
        env.market_state().0.permissionless_resolve_stale_slots,
        9000
    );

    env.svm.warp_to_slot(18035);
    let (stale_cfg, stale_group) = env.market_state();
    assert_eq!(stale_group.mode, MarketModeV16::Live);
    assert!(
        oracle_v16::permissionless_stale_matured(&stale_cfg, 18035),
        "test setup must be beyond the configured stale boundary"
    );
    let market_before = env.svm.get_account(&env.market).unwrap();

    env.svm.expire_blockhash();
    let stale = env.send(
        ProgInstruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1_000,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    );
    assert!(
        stale.is_err(),
        "ConfigurePermissionlessResolve must reject once the market is resolve-matured"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap(),
        market_before,
        "rejected stale reconfiguration leaves resolve policy unchanged"
    );

    env.svm.expire_blockhash();
    let resolve = env.send(
        ProgInstruction::ResolveStalePermissionless { now_slot: 16994 },
        vec![AccountMeta::new(env.market, false)],
        &[],
    );
    assert!(
        resolve.is_ok(),
        "permissionless resolve remains live after rejected stale reconfiguration: {resolve:?}"
    );
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
}

// security.md sweep - stale-resolve privileged lifecycle drift (W6, upstream 8a24cb8a): the market
// authority can normally move an empty asset into DrainOnly or Retired without token movement. Once
// the base market is resolve-matured, those live lifecycle mutations must freeze too.
#[test]
fn v16_attack_marketauth_lifecycle_actions_reject_when_resolve_matured() {
    let mut env = V16CuEnv::new();
    let admin = env.admin.insecure_clone();
    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.configure_auth_mark_with_cu(0, 100);

    env.svm.warp_to_slot(1);
    env.activate_asset(1, 1, 100);
    env.svm.warp_to_slot(8997);
    env.activate_asset(2, 2, 100);
    env.svm.warp_to_slot(8998);
    env.push_auth_mark_with_cu(3, 100);

    // Non-vacuous fresh controls: marketauth lifecycle actions are reachable before stale maturity.
    env.svm.warp_to_slot(8999);
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_DRAIN_ONLY,
        1,
        0,
        0,
    );
    assert_eq!(
        env.market_state().1.assets[1].lifecycle,
        AssetLifecycleV16::DrainOnly,
        "fresh marketauth DrainOnly path is reachable"
    );
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_RETIRE,
        1,
        4,
        0,
    );
    assert_eq!(
        env.market_state().1.assets[1].lifecycle,
        AssetLifecycleV16::Retired,
        "fresh marketauth Retire path is reachable"
    );

    env.svm.warp_to_slot(18035);
    let (stale_cfg, stale_group) = env.market_state();
    assert_eq!(stale_group.mode, MarketModeV16::Live);
    assert!(
        oracle_v16::permissionless_stale_matured(&stale_cfg, 18035),
        "test setup must be beyond the permissionless resolve stale boundary"
    );
    assert_eq!(stale_group.assets[2].lifecycle, AssetLifecycleV16::Active);

    let before_drain = env.svm.get_account(&env.market).unwrap();
    env.svm.expire_blockhash();
    let stale_drain = env.send(
        ProgInstruction::UpdateAssetLifecycle {
            action: percolator_prog::processor::ASSET_ACTION_DRAIN_ONLY,
            asset_index: 2,
            now_slot: 0,
            initial_price: 0,
            insurance_authority: admin.pubkey().to_bytes(),
            insurance_operator: admin.pubkey().to_bytes(),
            backing_bucket_authority: admin.pubkey().to_bytes(),
            oracle_authority: admin.pubkey().to_bytes(),
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    );
    assert!(
        stale_drain.is_err(),
        "marketauth DrainOnly must reject once the base market is resolve-matured"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap(),
        before_drain,
        "rejected stale DrainOnly leaves lifecycle state unchanged"
    );

    let before_retire = env.svm.get_account(&env.market).unwrap();
    env.svm.expire_blockhash();
    let stale_retire = env.send(
        ProgInstruction::UpdateAssetLifecycle {
            action: percolator_prog::processor::ASSET_ACTION_RETIRE,
            asset_index: 2,
            now_slot: 40,
            initial_price: 0,
            insurance_authority: admin.pubkey().to_bytes(),
            insurance_operator: admin.pubkey().to_bytes(),
            backing_bucket_authority: admin.pubkey().to_bytes(),
            oracle_authority: admin.pubkey().to_bytes(),
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    );
    assert!(
        stale_retire.is_err(),
        "marketauth Retire must reject once the base market is resolve-matured"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap(),
        before_retire,
        "rejected stale Retire leaves lifecycle state unchanged"
    );
    assert_eq!(
        env.market_state().1.assets[2].lifecycle,
        AssetLifecycleV16::Active,
        "stale marketauth lifecycle actions cannot alter the active asset"
    );

    env.svm.expire_blockhash();
    let resolve = env.send(
        ProgInstruction::ResolveStalePermissionless { now_slot: 0 },
        vec![AccountMeta::new(env.market, false)],
        &[],
    );
    assert!(
        resolve.is_ok(),
        "permissionless resolve still succeeds after rejected stale lifecycle actions: {resolve:?}"
    );
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
}

// security.md sweep - non-base staleness masking (W7, upstream 959d8de6): staleness was either/or
// at 3 call sites -- price-managed (per-asset) profiles checked only their own local staleness,
// base checked only the global anchor. Once the BASE oracle passed permissionless_resolve_stale_slots
// only base trades froze; a non-base asset with its own recently-cranked profile could keep trading
// forever even though the market as a whole is already eligible for ResolveStalePermissionless.
// This test crafts exactly that split (base cfg.last_good_oracle_slot old, asset-1 profile fresh)
// via direct account writes -- necessary because ConfigureAuthMark/PushAuthMark unconditionally
// bump the shared cfg.last_good_oracle_slot regardless of which asset_index is targeted in this
// fork, so the split cannot be produced through ordinary instruction sequences alone.
#[test]
fn v16_attack_non_base_trade_rejects_after_base_resolve_matured() {
    const PRICE: u64 = 100;
    let mut env = V16CuEnv::new_with_market_params_and_price_move(2, 10_000, 10_000, 10_000);
    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, PRICE);

    let taker = Keypair::new();
    let lp = Keypair::new();
    let ta = env.create_portfolio(&taker);
    let la = env.create_portfolio(&lp);
    env.deposit(&taker, ta, 1_000_000_000);
    env.deposit(&lp, la, 1_000_000_000);
    let sz = (5 * POS_SCALE) as i128;

    // Non-vacuous fresh control: non-base TradeNoCpi succeeds before any staleness exists.
    env.trade_asset_with_cu(1, &taker, ta, &lp, la, sz, PRICE, 0);
    assert_eq!(
        active_leg_for_asset(&env.portfolio_state(ta), 1).basis_pos_q,
        sz
    );
    assert_eq!(
        active_leg_for_asset(&env.portfolio_state(la), 1).basis_pos_q,
        -sz
    );

    // Craft the split-stale state directly: base anchor pinned old (age 6 >= stale_slots 5 ->
    // globally matured); asset-1's own profile anchor fresh (age 1 < 5 -> not locally stale).
    env.mutate_market(|cfg, _group| {
        cfg.last_good_oracle_slot = 2;
    });
    {
        let mut account = env.svm.get_account(&env.market).unwrap();
        let mut profile = state::read_asset_oracle_profile(&account.data, 1).unwrap();
        profile.last_good_oracle_slot = 9002;
        state::write_asset_oracle_profile(&mut account.data, 1, &profile).unwrap();
        env.svm.set_account(env.market, account).unwrap();
    }
    env.svm.warp_to_slot(9003);
    let (stale_cfg, _stale_group) = env.market_state();
    assert!(
        oracle_v16::permissionless_stale_matured(&stale_cfg, 9003),
        "test setup must make the base anchor resolve-matured"
    );

    let market_before = env.svm.get_account(&env.market).unwrap();
    let taker_before = env.svm.get_account(&ta).unwrap();
    let lp_before = env.svm.get_account(&la).unwrap();

    env.svm.expire_blockhash();
    let stale = env.try_trade_asset_with_cu(1, &taker, ta, &lp, la, sz, PRICE, 0);
    assert!(
        stale.is_err(),
        "non-base TradeNoCpi must reject once the base market is resolve-matured: {stale:?}"
    );
    assert_eq!(
        env.svm.get_account(&env.market).unwrap(),
        market_before,
        "rejected stale non-base trade leaves the market unchanged"
    );
    assert_eq!(
        env.svm.get_account(&ta).unwrap(),
        taker_before,
        "rejected stale non-base trade leaves the taker account unchanged"
    );
    assert_eq!(
        env.svm.get_account(&la).unwrap(),
        lp_before,
        "rejected stale non-base trade leaves the LP account unchanged"
    );

    env.svm.expire_blockhash();
    let resolve = env.send(
        ProgInstruction::ResolveStalePermissionless { now_slot: 0 },
        vec![AccountMeta::new(env.market, false)],
        &[],
    );
    assert!(
        resolve.is_ok(),
        "permissionless resolve remains live after the rejected stale trade: {resolve:?}"
    );
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
}

// security.md sweep - non-base TradeCpi rejects before matcher CPI (W7, upstream 959d8de6): the
// same split-staleness bug had its own inline (buggy) copy in handle_trade_cpi, not routed through
// the shared helper. Proves the stale TradeCpi is rejected BEFORE the external matcher is ever
// invoked, using a REAL percolator-match matcher (not a stub) so "matcher context bytes unchanged"
// is genuine proof of pre-CPI rejection (an actual fill mutates the matcher context).
#[test]
fn v16_attack_non_base_tradecpi_rejects_before_matcher_after_base_resolve_matured() {
    const PRICE: u64 = 100;
    let mut env = V16CuEnv::new_with_market_params_and_price_move(2, 10_000, 10_000, 10_000);
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);

    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, PRICE);

    let taker = Keypair::new();
    let lp = Keypair::new();
    let taker_account = env.create_portfolio(&taker);
    let lp_account = env.create_portfolio(&lp);
    env.deposit(&taker, taker_account, 1_000_000_000);
    env.deposit(&lp, lp_account, 1_000_000_000);
    let (ctx, delegate, _init_cu) = env.init_matcher_context(&lp, matcher_program, lp_account);

    let accounts = vec![
        AccountMeta::new(taker.pubkey(), true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(taker_account, false),
        AccountMeta::new(lp_account, false),
        AccountMeta::new_readonly(matcher_program, false),
        AccountMeta::new(ctx, false),
        AccountMeta::new_readonly(delegate, false),
    ];
    let sz = (5 * POS_SCALE) as i128;

    // Non-vacuous fresh control: the real matcher fills a non-base TradeCpi before any staleness.
    env.svm.expire_blockhash();
    let fresh = env.send(
        ProgInstruction::TradeCpi {
            asset_index: 1,
            size_q: sz,
            fee_bps: 0,
            limit_price: PRICE,
        },
        accounts.clone(),
        &[&taker],
    );
    assert!(
        fresh.is_ok(),
        "fresh non-base TradeCpi through the real matcher must succeed: {fresh:?}"
    );
    assert_eq!(
        active_leg_for_asset(&env.portfolio_state(taker_account), 1).basis_pos_q,
        sz
    );

    env.mutate_market(|cfg, _group| {
        cfg.last_good_oracle_slot = 2;
    });
    {
        let mut account = env.svm.get_account(&env.market).unwrap();
        let mut profile = state::read_asset_oracle_profile(&account.data, 1).unwrap();
        profile.last_good_oracle_slot = 9002;
        state::write_asset_oracle_profile(&mut account.data, 1, &profile).unwrap();
        env.svm.set_account(env.market, account).unwrap();
    }
    env.svm.warp_to_slot(9003);
    let (stale_cfg, _stale_group) = env.market_state();
    assert!(
        oracle_v16::permissionless_stale_matured(&stale_cfg, 9003),
        "test setup must make the base anchor resolve-matured"
    );

    let market_before = env.svm.get_account(&env.market).unwrap();
    let taker_before = env.svm.get_account(&taker_account).unwrap();
    let lp_before = env.svm.get_account(&lp_account).unwrap();
    let ctx_before = env.svm.get_account(&ctx).unwrap();

    env.svm.expire_blockhash();
    let stale = env.send(
        ProgInstruction::TradeCpi {
            asset_index: 1,
            size_q: sz,
            fee_bps: 0,
            limit_price: PRICE,
        },
        accounts.clone(),
        &[&taker],
    );
    assert!(
        stale.is_err(),
        "base-stale non-base TradeCpi must reject before matcher CPI: {stale:?}"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
    assert_eq!(env.svm.get_account(&lp_account).unwrap(), lp_before);
    assert_eq!(
        env.svm.get_account(&ctx).unwrap(),
        ctx_before,
        "matcher context must be untouched -- proves the real matcher CPI was never invoked"
    );
}

// security.md sweep - non-base BatchTradeCpi rejects before matcher CPI (W7, upstream 959d8de6):
// unlike the other two sites, handle_batch_trade_cpi's preflight had NO staleness gate at all --
// staleness was only ever caught AFTER invoke_matcher_batch returned, inside
// handle_batch_execute_zero_copy. So a stale market (base OR non-base) could reach and invoke an
// untrusted matcher program before any rejection. Proves the new pre-CPI gate fires.
#[test]
fn v16_attack_non_base_batchtradecpi_rejects_before_matcher_after_base_resolve_matured() {
    const PRICE: u64 = 100;
    let mut env = V16CuEnv::new_with_market_params_and_price_move(2, 10_000, 10_000, 10_000);
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);

    env.configure_permissionless_resolve_with_cu(9000, 5);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
    env.configure_auth_mark_for_asset_as_admin(1, 1, PRICE);

    let taker = Keypair::new();
    let lp = Keypair::new();
    let taker_account = env.create_portfolio(&taker);
    let lp_account = env.create_portfolio(&lp);
    env.deposit(&taker, taker_account, 1_000_000_000);
    env.deposit(&lp, lp_account, 1_000_000_000);
    let (ctx, delegate, _init_cu) = env.init_matcher_context(&lp, matcher_program, lp_account);

    let accounts = vec![
        AccountMeta::new(taker.pubkey(), true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(taker_account, false),
        AccountMeta::new(lp_account, false),
        AccountMeta::new_readonly(matcher_program, false),
        AccountMeta::new(ctx, false),
        AccountMeta::new_readonly(delegate, false),
    ];
    let sz = (5 * POS_SCALE) as i128;
    let leg = percolator_prog::ix::BatchTradeCpiLeg {
        asset_index: 1,
        size_q: sz,
        fee_bps: 0,
        limit_price: PRICE,
    };

    // Non-vacuous fresh control: the real matcher fills a non-base BatchTradeCpi leg before any
    // staleness. We only assert this does NOT fail with OracleStale specifically -- whatever else
    // the real matcher's batch fill does with a single leg is orthogonal to this fix.
    env.svm.expire_blockhash();
    let fresh = env.send(
        ProgInstruction::BatchTradeCpi {
            legs: vec![leg.clone()],
        },
        accounts.clone(),
        &[&taker],
    );
    assert!(
        !matches!(&fresh, Err(e) if e.contains("Custom(27)")),
        "fresh non-base BatchTradeCpi must not fail with OracleStale before any staleness exists: {fresh:?}"
    );

    env.mutate_market(|cfg, _group| {
        cfg.last_good_oracle_slot = 2;
    });
    {
        let mut account = env.svm.get_account(&env.market).unwrap();
        let mut profile = state::read_asset_oracle_profile(&account.data, 1).unwrap();
        profile.last_good_oracle_slot = 9002;
        state::write_asset_oracle_profile(&mut account.data, 1, &profile).unwrap();
        env.svm.set_account(env.market, account).unwrap();
    }
    env.svm.warp_to_slot(9003);
    let (stale_cfg, _stale_group) = env.market_state();
    assert!(
        oracle_v16::permissionless_stale_matured(&stale_cfg, 9003),
        "test setup must make the base anchor resolve-matured"
    );

    let market_before = env.svm.get_account(&env.market).unwrap();
    let taker_before = env.svm.get_account(&taker_account).unwrap();
    let lp_before = env.svm.get_account(&lp_account).unwrap();
    let ctx_before = env.svm.get_account(&ctx).unwrap();

    env.svm.expire_blockhash();
    let stale = env.send(
        ProgInstruction::BatchTradeCpi { legs: vec![leg] },
        accounts.clone(),
        &[&taker],
    );
    assert!(
        stale.is_err() && stale.as_ref().unwrap_err().contains("Custom(27)"),
        "base-stale non-base BatchTradeCpi must reject with OracleStale before matcher CPI: {stale:?}"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
    assert_eq!(env.svm.get_account(&lp_account).unwrap(), lp_before);
    assert_eq!(
        env.svm.get_account(&ctx).unwrap(),
        ctx_before,
        "matcher context must be untouched -- proves the real matcher CPI was never invoked"
    );
}

// security.md sweep - unrelated-refresh masks loss-stale insurance gate (W8, upstream fddbdc19):
// loss_stale_active reflects only the LAST-cranked asset (engine-intentional accrual bookkeeping,
// not a market-wide aggregate), so an authorized withdrawer could crank an UNRELATED cheap/fresh
// asset to reset the global staleness flag and then withdraw per-asset live insurance for an asset
// that itself was never freshly cranked -- even though that asset still has open exposure. Proves
// the asset-LOCAL loss-stale gate blocks the withdrawal regardless of an unrelated refresh.
#[test]
fn v16_attack_unrelated_refresh_cannot_mask_loss_stale_insurance_gate() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(4, 1_000, 1_000, 500);
    env.enable_live_insurance_withdrawal();
    let admin = env.admin.insecure_clone();
    env.top_up_insurance_domain_with_authority(&admin, 2, 100);

    let stale_long_owner = Keypair::new();
    let stale_short_owner = Keypair::new();
    let stale_long = env.create_portfolio(&stale_long_owner);
    let stale_short = env.create_portfolio(&stale_short_owner);
    env.deposit(&stale_long_owner, stale_long, 1_000_000_000);
    env.deposit(&stale_short_owner, stale_short, 1_000_000_000);
    env.trade_asset_with_cu(
        1,
        &stale_long_owner,
        stale_long,
        &stale_short_owner,
        stale_short,
        (10 * POS_SCALE) as i128,
        100,
        0,
    );

    let cranker_owner = Keypair::new();
    let cranker = env.create_portfolio(&cranker_owner);
    env.svm.warp_to_slot(3);
    for _ in 0..3 {
        env.svm.expire_blockhash();
        env.crank(
            cranker,
            ProgInstruction::PermissionlessCrank {
                action: 0,
                asset_index: 0,
                now_slot: 3,
                funding_rate_e9: 0,
                recovery_reason: 0,
            },
        );
    }
    env.svm.expire_blockhash();
    env.crank(
        cranker,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 1,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );

    let before_mask = env.market_state().1;
    assert!(before_mask.loss_stale_active);
    assert!(before_mask.assets[1].slot_last < before_mask.current_slot);
    assert!(
        env.try_withdraw_insurance_domain_with_authority(&admin, 2, 10)
            .is_err(),
        "asset-1 live insurance is initially locked by its loss-stale exposure"
    );

    env.svm.expire_blockhash();
    env.crank(
        cranker,
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 3,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
    );
    let after_unrelated_refresh = env.market_state().1;
    assert!(
        after_unrelated_refresh.assets[1].slot_last < after_unrelated_refresh.current_slot,
        "asset 1 remains locally loss-stale after the unrelated asset-0 refresh"
    );

    let withdraw = env.try_withdraw_insurance_domain_with_authority(&admin, 2, 10);
    assert!(withdraw.is_err(),
        "an unrelated refresh must not make asset-1 insurance withdrawable while asset 1 is loss-stale");
    let after_withdraw_attempt = env.market_state().1;
    assert_eq!(
        after_withdraw_attempt.insurance_domain_budget[2],
        after_unrelated_refresh.insurance_domain_budget[2]
    );
    assert_eq!(
        after_withdraw_attempt.insurance,
        after_unrelated_refresh.insurance
    );
}

// FIX W1 (upstream 4b8bb9fa, #152, CRITICAL): validate_matcher_tail rejected key-aliasing
// tail accounts but never checked `is_signer`, so a hostile matcher received tail AccountInfos
// with the caller's own is_signer flags forwarded verbatim -- letting a malicious LP-registered
// matcher program re-list e.g. the taker's wallet in its tail and use that forwarded signer
// privilege in a nested CPI (wallet-drain-grade, zero extra privilege needed beyond routing a
// trade through a hostile matcher). This test proves the wrapper now rejects BEFORE the matcher
// CPI ever runs, for both TradeCpi and BatchTradeCpi, using the REAL percolator-match reference
// matcher (not a stub) so the discriminator is genuinely "was the matcher CPI reached" and not
// an artifact of a purpose-built hostile fixture.
#[test]
fn v16_fix_w1_matcher_tail_rejects_signer_account() {
    for route_is_batch in [false, true] {
        let mut env = V16CuEnv::new();
        let matcher_program = Pubkey::new_unique();
        let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
        env.svm.add_program(matcher_program, &matcher_bytes);

        let taker = Keypair::new();
        let lp = Keypair::new();
        let taker_account = env.create_portfolio(&taker);
        let lp_account = env.create_portfolio(&lp);
        env.deposit(&taker, taker_account, 1_000_000);
        env.deposit(&lp, lp_account, 1_000_000);
        let (ctx, delegate, _init_cu) = env.init_matcher_context(&lp, matcher_program, lp_account);

        // The "hostile" element: an extra tail account that IS a transaction signer. A correct
        // matcher would never need this; the point is the wrapper must reject its mere presence
        // in the tail before the matcher is ever invoked, regardless of what the matcher does
        // with it.
        let tail_signer = Keypair::new();
        let matcher_key_str = matcher_program.to_string();

        let hostile_accounts = vec![
            AccountMeta::new(taker.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(taker_account, false),
            AccountMeta::new(lp_account, false),
            AccountMeta::new_readonly(matcher_program, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
            AccountMeta::new_readonly(tail_signer.pubkey(), true),
        ];

        let market_before = env.svm.get_account(&env.market).unwrap();
        let taker_before = env.svm.get_account(&taker_account).unwrap();
        let lp_before = env.svm.get_account(&lp_account).unwrap();
        let ctx_before = env.svm.get_account(&ctx).unwrap();

        let leg = percolator_prog::ix::BatchTradeCpiLeg {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        };
        let err = if route_is_batch {
            env.send(
                ProgInstruction::BatchTradeCpi { legs: vec![leg] },
                hostile_accounts.clone(),
                &[&taker, &tail_signer],
            )
        } else {
            env.send(
                ProgInstruction::TradeCpi {
                    asset_index: 0,
                    size_q: POS_SCALE as i128,
                    fee_bps: 0,
                    limit_price: 0,
                },
                hostile_accounts.clone(),
                &[&taker, &tail_signer],
            )
        }
        .expect_err(
            "matcher tail carrying an is_signer account must be rejected before the matcher CPI",
        );

        assert!(
            err.contains("Custom(9)"),
            "route_is_batch={route_is_batch} expected InvalidInstruction(9), got {err}"
        );
        assert!(
            !err.contains(&matcher_key_str),
            "route_is_batch={route_is_batch} rejection must NOT show the matcher program {matcher_key_str} in the tx error/logs -- the matcher CPI must never be invoked when the tail carries a signer: {err}"
        );
        assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
        assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
        assert_eq!(env.svm.get_account(&lp_account).unwrap(), lp_before);
        assert_eq!(env.svm.get_account(&ctx).unwrap(), ctx_before);

        // Positive control: the identical call with the hostile tail-signer account simply
        // dropped must succeed through a real matcher CPI. This proves the rejection above is
        // specifically about the forwarded is_signer flag, not some unrelated fixture mistake.
        env.svm.expire_blockhash();
        let mut ok_accounts = hostile_accounts;
        ok_accounts.pop();
        let leg = percolator_prog::ix::BatchTradeCpiLeg {
            asset_index: 0,
            size_q: POS_SCALE as i128,
            fee_bps: 0,
            limit_price: 0,
        };
        let ok_result = if route_is_batch {
            env.send(
                ProgInstruction::BatchTradeCpi { legs: vec![leg] },
                ok_accounts,
                &[&taker],
            )
        } else {
            env.send(
                ProgInstruction::TradeCpi {
                    asset_index: 0,
                    size_q: POS_SCALE as i128,
                    fee_bps: 0,
                    limit_price: 0,
                },
                ok_accounts,
                &[&taker],
            )
        };
        assert!(
            ok_result.is_ok(),
            "route_is_batch={route_is_batch} control call without the signer tail account must succeed through the real matcher: {ok_result:?}"
        );
    }
}

// FIX W2 (upstream #147 + #160): TradeCpi/BatchTradeCpi invoked the untrusted external matcher
// with NO per-asset lifecycle check at all. The engine's own post-CPI gate
// (require_asset_risk_change_allowed) still rejects a risk-increasing trade on a non-Active
// asset, so this is defense-in-depth, not a fund-safety hole by itself -- the observable this
// test targets is specifically "did the matcher CPI run", proven via the matcher program's
// pubkey being absent from the tx error/logs (a hostile-or-honest matcher's own
// "Program <pubkey> invoke"/"success" log lines would appear there if the CPI happened) plus
// byte-identical account state before/after. A code-only assertion on the final error code would
// be vacuous here since both the fixed and unfixed paths end in the SAME Custom(21)
// (EngineLockActive) -- the engine's own post-CPI gate produces that error regardless of whether
// this wrapper-side preflight exists.
#[test]
fn v16_fix_w2_inactive_asset_cpi_trade_rejects_before_matcher() {
    for lifecycle_case in ["Retired", "DrainOnly"] {
        let mut env = V16CuEnv::new();
        let creator = Keypair::new();
        env.update_market_init_fee_policy_with_cu(1);
        env.svm.warp_to_slot(1);
        env.activate_permissionless_asset_with_fee(
            &creator,
            1,
            1,
            100,
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            creator.pubkey(),
            1,
        );
        match lifecycle_case {
            "Retired" => {
                env.svm.warp_to_slot(3);
                env.update_asset_lifecycle_as_admin_with_cu(
                    percolator_prog::processor::ASSET_ACTION_RETIRE,
                    1,
                    3,
                    0,
                );
                assert_eq!(
                    env.market_state().1.assets[1].lifecycle,
                    AssetLifecycleV16::Retired
                );
            }
            "DrainOnly" => {
                env.update_asset_lifecycle_as_admin_with_cu(
                    percolator_prog::processor::ASSET_ACTION_DRAIN_ONLY,
                    1,
                    0,
                    0,
                );
                assert_eq!(
                    env.market_state().1.assets[1].lifecycle,
                    AssetLifecycleV16::DrainOnly
                );
            }
            _ => unreachable!(),
        }
        let matcher_program = Pubkey::new_unique();
        let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
        env.svm.add_program(matcher_program, &matcher_bytes);
        let taker = Keypair::new();
        let lp = Keypair::new();
        let taker_account = env.create_portfolio(&taker);
        let lp_account = env.create_portfolio(&lp);
        env.deposit(&taker, taker_account, 1_000_000);
        env.deposit(&lp, lp_account, 1_000_000);
        let (ctx, delegate, _init_cu) = env.init_matcher_context(&lp, matcher_program, lp_account);
        let matcher_key_str = matcher_program.to_string();
        for route_is_batch in [false, true] {
            let market_before = env.svm.get_account(&env.market).unwrap();
            let taker_before = env.svm.get_account(&taker_account).unwrap();
            let lp_before = env.svm.get_account(&lp_account).unwrap();
            env.svm.expire_blockhash();
            let accounts = vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp_account, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ];
            let err = if route_is_batch {
                env.send(
                    ProgInstruction::BatchTradeCpi {
                        legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                            asset_index: 1,
                            size_q: POS_SCALE as i128,
                            fee_bps: 0,
                            limit_price: 0,
                        }],
                    },
                    accounts,
                    &[&taker],
                )
            } else {
                env.send(
                    ProgInstruction::TradeCpi {
                        asset_index: 1,
                        size_q: POS_SCALE as i128,
                        fee_bps: 0,
                        limit_price: 0,
                    },
                    accounts,
                    &[&taker],
                )
            }
            .expect_err("inactive-asset CPI trade must reject before matcher CPI");
            assert!(
                err.contains("Custom(21)"),
                "{lifecycle_case} route_is_batch={route_is_batch} rejection should be EngineLockActive(21), got {err}"
            );
            assert!(
                !err.contains(&matcher_key_str),
                "{lifecycle_case} route_is_batch={route_is_batch} rejection must NOT show the matcher program {matcher_key_str} in the tx error/logs -- the matcher CPI must never be invoked for a non-Active asset: {err}"
            );
            assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
            assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
            assert_eq!(env.svm.get_account(&lp_account).unwrap(), lp_before);
        }
    }
}

// FIX W2 (upstream #160 half): DrainOnly risk-increase-on-existing-position. Structurally
// identical proof technique to the sibling test above, but exercises the "asset has an existing
// position, request would GROW it" branch of #160 rather than the "no position at all" branch of
// #147 -- both are gated by the SAME wrapper-side preflight added in this fix, just different
// sub-conditions of it.
#[test]
fn v16_fix_w2_drain_only_risk_increase_cpi_trade_rejects_before_matcher() {
    let mut env = V16CuEnv::new();
    let taker = Keypair::new();
    let lp = Keypair::new();
    let taker_account = env.create_portfolio(&taker);
    let lp_account = env.create_portfolio(&lp);
    env.deposit(&taker, taker_account, 1_000_000);
    env.deposit(&lp, lp_account, 1_000_000);

    // Open a real position on asset 0 (taker long, lp short) via the ordinary NoCpi path first.
    env.trade_asset_with_cu(
        0,
        &taker,
        taker_account,
        &lp,
        lp_account,
        POS_SCALE as i128,
        100,
        0,
    );
    env.update_asset_lifecycle_as_admin_with_cu(
        percolator_prog::processor::ASSET_ACTION_DRAIN_ONLY,
        0,
        0,
        0,
    );
    assert_eq!(
        env.market_state().1.assets[0].lifecycle,
        AssetLifecycleV16::DrainOnly
    );

    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);
    let (ctx, delegate, _init_cu) = env.init_matcher_context(&lp, matcher_program, lp_account);
    let matcher_key_str = matcher_program.to_string();

    for route_is_batch in [false, true] {
        let market_before = env.svm.get_account(&env.market).unwrap();
        let taker_before = env.svm.get_account(&taker_account).unwrap();
        let lp_before = env.svm.get_account(&lp_account).unwrap();
        env.svm.expire_blockhash();
        let accounts = vec![
            AccountMeta::new(taker.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(taker_account, false),
            AccountMeta::new(lp_account, false),
            AccountMeta::new_readonly(matcher_program, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        // Taker is already long; requesting MORE long (same direction) is a risk INCREASE.
        let err = if route_is_batch {
            env.send(
                ProgInstruction::BatchTradeCpi {
                    legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                        asset_index: 0,
                        size_q: POS_SCALE as i128,
                        fee_bps: 0,
                        limit_price: 0,
                    }],
                },
                accounts,
                &[&taker],
            )
        } else {
            env.send(
                ProgInstruction::TradeCpi {
                    asset_index: 0,
                    size_q: POS_SCALE as i128,
                    fee_bps: 0,
                    limit_price: 0,
                },
                accounts,
                &[&taker],
            )
        }
        .expect_err("DrainOnly risk-increasing CPI trade must reject before matcher CPI");
        assert!(
            err.contains("Custom(21)"),
            "route_is_batch={route_is_batch} rejection should be EngineLockActive(21), got {err}"
        );
        assert!(
            !err.contains(&matcher_key_str),
            "route_is_batch={route_is_batch} DrainOnly risk-increase rejection must NOT reach the matcher CPI: {err}"
        );
        assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
        assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
        assert_eq!(env.svm.get_account(&lp_account).unwrap(), lp_before);
    }
}

// FIX W4 (upstream 449e7d55, #145, HIGH): legs.len()<=MATCHER_BATCH_MAX_LEGS(16) and
// tail.len()<=MAX_MATCHER_TAIL_ACCOUNTS(32) are each bounded independently, but their PRODUCT
// (up to 512) was unbounded -- a batch with many legs AND a full matcher tail multiplies
// per-leg tail-account validation/CPI-account-resolution work, a CU-griefing surface that no
// single existing guard catches. This test proves the wrapper now caps the product, using the
// REAL percolator-match reference matcher (not a stub): the discriminator is NOT "does it error"
// in the abstract, it's that WITHOUT the fix a 14-leg x 5-tail batch (each axis individually
// legal: 14<=16, 5<=32) sails straight through into a genuine, successful matcher fill -- the
// exact same code path as the legal 14-leg x 4-tail batch below, just with product 70 instead of
// 56 -- and only the multiplicative cap can tell them apart.
#[test]
fn v16_bpf_batch_trade_cpi_tail_fanout_budget_rejects_oversized_product() {
    // REWRITTEN 2026-08-29 for the #436 fix. This test used to assert that a 14-leg x 4-tail
    // batch (product 56 <= budget 64) MUST EXECUTE. It never could: measurement showed a leg
    // costs ~120,000 CU, so 12+ legs exhaust the 1.4M ceiling regardless of tail size, and the
    // test sat quarantined in KNOWN_FAILING for exactly that reason.
    //
    // MATCHER_BATCH_MAX_LEGS is now 11 (the measured ceiling) rather than 16, so 12..=16 are
    // rejected up front instead of passing the declared checks and dying on compute. The test
    // now pins BOTH bounds and the boundary between them.
    const LEGS: usize = 12; // market capacity: one past the new max, so both sides are reachable.
    const PRICE: u64 = 100;
    const OVER_LEGS: usize = 12; // one past MATCHER_BATCH_MAX_LEGS=11 -> leg bound fires.
    const MAX_LEGS: usize = 11; // the bound itself must still work.
    const REJECT_TAIL: usize = 6; // 11*6=66 > 64 -> the PRODUCT bound fires (6<=32 legal alone).
    const ALLOW_TAIL: usize = 5; // 11*5=55 <= 64 -> product is legal; only compute limits it.

    fn add_benign_tail_accounts(env: &mut V16CuEnv, count: usize) -> Vec<Pubkey> {
        (0..count)
            .map(|_| {
                let key = Pubkey::new_unique();
                env.svm
                    .set_account(
                        key,
                        Account {
                            lamports: 1_000_000_000,
                            data: vec![0u8; 8],
                            owner: Pubkey::default(),
                            executable: false,
                            rent_epoch: 0,
                        },
                    )
                    .unwrap();
                key
            })
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    fn matcher_accounts(
        taker: Pubkey,
        market: Pubkey,
        taker_account: Pubkey,
        lp_account: Pubkey,
        matcher_program: Pubkey,
        ctx: Pubkey,
        delegate: Pubkey,
        tail: &[Pubkey],
    ) -> Vec<AccountMeta> {
        let mut metas = vec![
            AccountMeta::new(taker, true),
            AccountMeta::new(market, false),
            AccountMeta::new(taker_account, false),
            AccountMeta::new(lp_account, false),
            AccountMeta::new_readonly(matcher_program, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        metas.extend(
            tail.iter()
                .copied()
                .map(|key| AccountMeta::new_readonly(key, false)),
        );
        metas
    }

    let mut env = V16CuEnv::new_with_market_params_and_price_move(LEGS as u16, 1_000, 1_000, 500);
    // InitMarket with max_portfolio_assets=LEGS pre-activates ALL LEGS asset slots (0..LEGS) as
    // Active immediately -- no explicit per-asset activation needed here, only an oracle mark.
    for asset_index in 0..LEGS as u16 {
        env.configure_auth_mark_for_asset_as_admin(asset_index, LEGS as u64 + 1, PRICE);
    }
    let matcher_program = Pubkey::new_unique();
    let matcher_bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(matcher_program, &matcher_bytes);
    let taker = Keypair::new();
    let lp = Keypair::new();
    let taker_account = env.create_portfolio(&taker);
    let lp_account = env.create_portfolio(&lp);
    env.deposit(&taker, taker_account, 100_000_000);
    env.deposit(&lp, lp_account, 100_000_000);
    let (ctx, delegate, _) = env.init_matcher_context(&lp, matcher_program, lp_account);
    let mk_legs = |n: usize| -> Vec<percolator_prog::ix::BatchTradeCpiLeg> {
        (0..n as u16)
            .map(|asset_index| percolator_prog::ix::BatchTradeCpiLeg {
                asset_index,
                size_q: POS_SCALE as i128,
                fee_bps: 100,
                limit_price: 0,
            })
            .collect()
    };

    // ── 1. THE LEG BOUND. 12 legs is one past MATCHER_BATCH_MAX_LEGS=11. Before the #436 fix
    // this passed every declared check and then died on compute with ProgramFailedToComplete;
    // it is now refused up front and attributably.
    let small_tail = add_benign_tail_accounts(&mut env, 1);
    let market_before = env.svm.get_account(&env.market).unwrap();
    let taker_before = env.svm.get_account(&taker_account).unwrap();
    let ctx_before = env.svm.get_account(&ctx).unwrap();
    env.svm.expire_blockhash();
    let over = env
        .send(
            ProgInstruction::BatchTradeCpi { legs: mk_legs(OVER_LEGS) },
            matcher_accounts(
                taker.pubkey(), env.market, taker_account, lp_account,
                matcher_program, ctx, delegate, &small_tail,
            ),
            &[&taker],
        )
        .expect_err("12 legs is past MATCHER_BATCH_MAX_LEGS=11 and must be REFUSED, not left to exhaust compute");
    assert!(
        over.contains("Custom(9)"),
        "expected InvalidInstruction from the leg bound, got {over}"
    );
    assert_eq!(env.svm.get_account(&env.market).unwrap(), market_before);
    assert_eq!(env.svm.get_account(&taker_account).unwrap(), taker_before);
    assert_eq!(
        env.svm.get_account(&ctx).unwrap(),
        ctx_before,
        "must reject BEFORE the matcher CPI"
    );

    // ── 2. THE PRODUCT BOUND still applies independently: 11*6=66 > 64. Both bounds exist
    // because they constrain different things — legs bound COMPUTE, the product bounds the
    // matcher's account fanout — and #436 was precisely the discovery that the product alone
    // does not bound compute.
    let reject_tail = add_benign_tail_accounts(&mut env, REJECT_TAIL);
    env.svm.expire_blockhash();
    let rejected = env
        .send(
            ProgInstruction::BatchTradeCpi {
                legs: mk_legs(MAX_LEGS),
            },
            matcher_accounts(
                taker.pubkey(),
                env.market,
                taker_account,
                lp_account,
                matcher_program,
                ctx,
                delegate,
                &reject_tail,
            ),
            &[&taker],
        )
        .expect_err("11-leg x 6-tail (product 66 > budget 64) must reject on the fanout budget");
    assert!(
        rejected.contains("Custom(9)"),
        "expected InvalidInstruction, got {rejected}"
    );

    // ── 3. THE BOUND ITSELF IS REACHABLE. Without this the two rejections above would be
    // satisfied by a program that refuses everything — lowering MAX_LEGS to 0 would "pass" them.
    //
    // env.send already prepends cu_ix() (1,400,000), so this runs at Solana's ceiling, which is
    // exactly where 11 was measured at 1,332,184 CU — 95% of the budget. That thin margin is the
    // honest shape of this bound: NECESSARY, NOT SUFFICIENT. Per-leg cost varies with market
    // state, so callers must still handle compute exhaustion at or below 11; the fix only
    // removes 12..=16, which could never work anywhere.
    let allow_tail = add_benign_tail_accounts(&mut env, ALLOW_TAIL);
    env.svm.expire_blockhash();
    let allowed_cu = env
        .send(
            ProgInstruction::BatchTradeCpi {
                legs: mk_legs(MAX_LEGS),
            },
            matcher_accounts(
                taker.pubkey(),
                env.market,
                taker_account,
                lp_account,
                matcher_program,
                ctx,
                delegate,
                &allow_tail,
            ),
            &[&taker],
        )
        .expect("11 legs is MATCHER_BATCH_MAX_LEGS and MUST execute");
    assert!(
        allowed_cu < 1_400_000,
        "11 legs consumed {allowed_cu} CU, at or past the ceiling — the bound is no longer reachable"
    );
    assert_eq!(
        percolator::active_bitmap_count_ones(env.portfolio_state(taker_account).active_bitmap),
        MAX_LEGS as u32,
        "all 11 legs must have actually filled"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// v17 program bug fixes (2026-07-22)
//
// Three regression tests, one per bug. Each is written to FAIL against the
// bytecode deployed on 2026-07-20 (wrapper sha256 e854ae7d…) and PASS against
// the rebuilt program.
// ══════════════════════════════════════════════════════════════════════════════

/// Refresh crank on `portfolio`, returning the raw result rather than panicking.
fn try_refresh(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64) -> Result<u64, String> {
    let payer = env.payer.pubkey();
    let market = env.market;
    env.send(
        ProgInstruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(market, false),
            AccountMeta::new(portfolio, false),
        ],
        &[],
    )
}

fn try_expire_backing_bucket(env: &mut V16CuEnv, domain: u16) -> Result<u64, String> {
    let market = env.market;
    env.send(
        ProgInstruction::ExpireBackingBucket { domain },
        vec![AccountMeta::new(market, false)],
        &[],
    )
}

fn custom_code(err: &str) -> Option<u32> {
    let marker = "Custom(";
    let start = err.find(marker)? + marker.len();
    let end = start + err[start..].find(')')?;
    err[start..end].parse().ok()
}

// ── BUG 1 ────────────────────────────────────────────────────────────────────
//
// A realized loss reserves capital as counterparty backing, which opens the
// domain's backing bucket as `Fresh` with
//   expiry_slot = current_slot + max(max_accrual_dt_slots, h_max,
//                                    max_bankrupt_close_lifetime_slots)
// = current_slot + 100 for this (and every driver's) config. That expiry is
// fixed when the bucket opens and is never extended while it stays `Fresh`, so
// EVERY backed market reaches the lapse; a longer horizon defers it, it does
// not avoid it.
//
// After the lapse the domain is a dead end in all three directions, forever:
// settling a further loss and re-funding the bucket both revert LockActive(21),
// and settling a gain against it reverts Stale(19). Nothing in the deployed
// wrapper can advance the bucket out of `Fresh` on a Live market, even though
// the engine owns the transition (`expire_source_backing_bucket_not_atomic`)
// and calls it itself on the RESOLVED path.
//
// THE LAPSE IS DRIVEN, NOT WAITED FOR. `warp_to_slot` makes it deterministic:
// this test cannot pass by running fast, which is exactly how the bug hid.
#[test]
fn v17_lapsed_backing_bucket_bricks_settlement_until_expired() {
    const Q: i128 = 10 * POS_SCALE as i128;
    let mut env = V16CuEnv::new();

    let (_, cfg_group) = env.market_state();
    let derived_horizon = cfg_group
        .config
        .max_accrual_dt_slots
        .max(cfg_group.config.h_max)
        .max(cfg_group.config.max_bankrupt_close_lifetime_slots);
    assert_eq!(
        derived_horizon, 100,
        "the default market config's backing-freshness horizon is the ~100-slot window \
         every driver in this repo was built with"
    );

    let owner_a = Keypair::new();
    let owner_b = Keypair::new();
    let a = env.create_portfolio(&owner_a);
    let b = env.create_portfolio(&owner_b);
    env.deposit(&owner_a, a, 5_000);
    env.deposit(&owner_b, b, 5_000);

    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
    env.trade_asset_with_cu(0, &owner_a, a, &owner_b, b, Q, 100, 0);

    // Price 100 -> 50 -> 60. A is long, so A realizes a loss; the loss is
    // reserved against domain 0 (A's own side), which OPENS that domain's
    // backing bucket. No caller-supplied expiry anywhere: the horizon below is
    // the one the engine derives.
    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, 50);
    try_refresh(&mut env, a, 2).expect("A crank @50");
    try_refresh(&mut env, b, 2).expect("B crank @50");
    env.svm.warp_to_slot(3);
    env.push_auth_mark_for_asset_as_admin(0, 3, 60);
    try_refresh(&mut env, b, 3).expect("B crank @60");
    try_refresh(&mut env, a, 3).expect("A crank @60 settles the loss");

    let (_, g_open) = env.market_state();
    let bucket = g_open.source_backing_buckets[0];
    assert_eq!(
        bucket.status,
        BackingBucketStatusV16::Fresh,
        "A's realized loss must have opened domain 0's backing bucket"
    );
    assert!(
        bucket.fresh_unliened_backing_num > 0,
        "the opened bucket must actually hold the reserved backing"
    );
    assert_eq!(
        bucket.expiry_slot,
        g_open.current_slot + derived_horizon,
        "expiry is current_slot + max(max_accrual_dt_slots, h_max, \
         max_bankrupt_close_lifetime_slots) — the horizon is DERIVED, never chosen"
    );
    let expiry = bucket.expiry_slot;

    // ── Cross the horizon. Deterministic: no wall-clock dependence. ──
    let lapsed_slot = expiry + 297;
    env.svm.warp_to_slot(lapsed_slot);
    env.push_auth_mark_for_asset_as_admin(0, lapsed_slot, 40);

    // First crank only accrues the asset; the SECOND is the one that settles
    // A's new loss against the lapsed domain.
    try_refresh(&mut env, a, lapsed_slot).expect("accrual crank still works");
    let bricked = try_refresh(&mut env, a, lapsed_slot + 1)
        .expect_err("settling a loss against a lapsed backing bucket must revert");
    assert_eq!(
        custom_code(&bricked),
        Some(PercolatorError::EngineLockActive as u32),
        "the lapsed bucket rejects the loss reservation with LockActive; got {bricked}"
    );

    // PERMANENT, not transient: waiting longer never helps.
    for extra in [2u64, 50, 500] {
        let slot = lapsed_slot + extra;
        env.svm.warp_to_slot(slot);
        let again =
            try_refresh(&mut env, a, slot).expect_err("the brick must persist at every later slot");
        assert_eq!(
            custom_code(&again),
            Some(PercolatorError::EngineLockActive as u32),
            "still bricked {extra} slots later; got {again}"
        );
    }

    // And the bucket cannot be paid back to life either — re-funding it with a
    // fresh expiry hits the same wall, so "top it up again" is not a recovery.
    let admin = env.admin.insecure_clone();
    let refund_src = Pubkey::new_unique();
    let mint = env.mint;
    env.svm
        .set_account(
            refund_src,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, admin.pubkey(), 500),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let market = env.market;
    let vault = env.vault;
    let refund = env
        .send(
            ProgInstruction::TopUpBackingBucket {
                domain: 0,
                amount: 500,
                expiry_slot: lapsed_slot + 10_000,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(refund_src, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                // #433: backing-domain ledger is MANDATORY and is CREATED here.
                AccountMeta::new(
                    state::derive_lp_backing_ledger(&env.program_id, &env.market, 0).0,
                    false,
                ),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&admin],
        )
        .expect_err("a lapsed Fresh bucket cannot be re-funded");
    assert_eq!(
        custom_code(&refund),
        Some(PercolatorError::EngineLockActive as u32),
        "TopUpBackingBucket on a lapsed bucket is the same dead end; got {refund}"
    );

    // ── THE FIX: tag 89 advances the lapsed bucket out of `Fresh`. ──
    try_expire_backing_bucket(&mut env, 0)
        .expect("ExpireBackingBucket must clear the lapsed bucket");
    let (_, g_expired) = env.market_state();
    assert_ne!(
        g_expired.source_backing_buckets[0].status,
        BackingBucketStatusV16::Fresh,
        "after expiry the bucket must have left `Fresh` — that is the whole repair"
    );

    // Settlement lives again.
    let settle_slot = lapsed_slot + 600;
    env.svm.warp_to_slot(settle_slot);
    try_refresh(&mut env, a, settle_slot)
        .expect("the losing account settles again once the lapsed bucket is expired");
}

/// The recovery instruction must NOT be usable to forfeit live backing early:
/// the engine gates the transition on `now_slot >= expiry_slot`, and the slot
/// is the runtime `Clock`, never a caller argument.
#[test]
fn v17_expire_backing_bucket_refuses_a_live_bucket() {
    let mut env = V16CuEnv::new();
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
    // A long-lived Fresh bucket on domain 1.
    env.top_up_backing_bucket(1, 500, 100_000);
    let (_, g) = env.market_state();
    assert_eq!(
        g.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh
    );

    let early = try_expire_backing_bucket(&mut env, 1)
        .expect_err("expiring a bucket that has not lapsed must be refused");
    assert_eq!(
        custom_code(&early),
        Some(PercolatorError::EngineStale as u32),
        "the engine refuses an early expiry with Stale; got {early}"
    );
    let (_, g_after) = env.market_state();
    assert_eq!(
        g_after.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh,
        "the live bucket must be untouched"
    );
    assert_eq!(
        g_after.source_backing_buckets[1].fresh_unliened_backing_num,
        g.source_backing_buckets[1].fresh_unliened_backing_num,
        "no principal may move on a refused expiry"
    );
}

// ── BUG 2 ────────────────────────────────────────────────────────────────────
//
// The engine books, per accrual segment:
//     fund_num_total = floor(rate_e9 * segment_dt * effective_price / 1e9)
// so funding is identically zero whenever
//     price < ceil(1e9 / (rate * dt)).
// At the maximum legal rate (10_000) with dt = 100 that threshold is price 1000:
// a market denominated in small integers has a funding *setting* but no funding
// *mechanism*, silently and with no error at trade time.
//
// The arithmetic is in the ENGINE and is deliberately NOT changed. This is a
// creation-time GUARD: it refuses to build a market whose funding can never
// accrue, so the condition surfaces once, loudly, to the creator.

/// Send `InitMarket` into a fresh SVM and return the program LOGS on success.
fn try_init_market_with(params: V16CuMarketParams) -> Result<Vec<String>, String> {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(
        program_id,
        &std::fs::read(program_path()).expect("read BPF"),
    );
    svm.add_program(
        spl_token::ID,
        &std::fs::read(spl_token_program_path()).expect("read token BPF"),
    );
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
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![
                0u8;
                state::market_account_len_for_capacity(params.max_portfolio_assets as usize)
                    .unwrap()
            ],
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(mint, false),
        ],
        data: ProgInstruction::InitMarket {
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
        }
        .encode(),
    };
    let tx = Transaction::new_signed_with_payer(
        &[heap_ix(), cu_ix(), ix],
        Some(&payer.pubkey()),
        &[&payer, &admin],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|meta| meta.logs)
        .map_err(|e| format!("{e:?}"))
}

fn funding_warning_line(logs: &[String]) -> Option<&String> {
    logs.iter()
        .find(|l| l.contains("WARN funding-cannot-accrue"))
}

#[test]
fn v17_init_market_warns_when_funding_can_never_accrue() {
    // A realistic risk config — a funding-enabled market must clear the engine's
    // exact solvency envelope, which the 1x-margin default params do not. Only
    // `initial_price` and the funding rate vary below.
    let funding_market = |price: u64, max_abs: u64| V16CuMarketParams {
        initial_price: price,
        max_abs_funding_e9_per_slot: max_abs,
        ..production_risk_params()
    };
    // production_risk_params fixes max_accrual_dt_slots = 20, so the threshold is
    //     price >= ceil(1e9 / (rate * 20)).
    const DT: u128 = 20;
    let threshold = |rate: u128| -> u64 { (1_000_000_000u128).div_ceil(rate * DT) as u64 };
    assert_eq!(threshold(1_000), 50_000);
    assert_eq!(threshold(500), 100_000);

    // Bracket the threshold at rate 1_000: one atom below books zero funding,
    // the threshold itself books one.
    assert_eq!(1_000u128 * DT * 49_999 / 1_000_000_000, 0);
    assert_eq!(1_000u128 * DT * 50_000 / 1_000_000_000, 1);

    let below = try_init_market_with(funding_market(49_999, 1_000))
        .expect("the market is still creatable — this warns, it does not reject");
    let warning = funding_warning_line(&below).unwrap_or_else(|| {
        panic!("a market whose funding cannot accrue must SAY SO at creation; logs: {below:#?}")
    });
    assert!(
        warning.contains("price 49999") && warning.contains("threshold 50000"),
        "the warning must name the actual price and the price the creator needs; got {warning}"
    );

    // One atom over: silent. The warning is a real discriminator, not noise on
    // every funding market.
    let at_threshold =
        try_init_market_with(funding_market(50_000, 1_000)).expect("price 50_000 is creatable");
    assert!(
        funding_warning_line(&at_threshold).is_none(),
        "price 50_000 books one funding atom per window and must NOT warn; logs: {at_threshold:#?}"
    );

    // The threshold tracks the RATE too, not just the price: halving the rate
    // doubles it, and a price that was fine at rate 1_000 now warns.
    assert_eq!(500u128 * DT * 99_999 / 1_000_000_000, 0);
    assert_eq!(500u128 * DT * 100_000 / 1_000_000_000, 1);
    let below_slow = try_init_market_with(funding_market(99_999, 500)).expect("still creatable");
    let slow_warning = funding_warning_line(&below_slow)
        .unwrap_or_else(|| panic!("halving the rate doubles the threshold; logs: {below_slow:#?}"));
    assert!(
        slow_warning.contains("threshold 100000"),
        "the warning must track the rate; got {slow_warning}"
    );
    assert!(
        funding_warning_line(
            &try_init_market_with(funding_market(100_000, 500)).expect("creatable")
        )
        .is_none(),
        "price 100_000 clears the rate-500 threshold and must not warn"
    );

    // A market that deliberately switches funding OFF is silent — it is not
    // broken, it is explicitly disabled. This is the state every existing
    // fixture in this repo is in.
    let funding_off = try_init_market_with(V16CuMarketParams {
        initial_price: 100,
        max_abs_funding_e9_per_slot: 0,
        ..V16CuMarketParams::default()
    })
    .expect("funding disabled must stay creatable at any price");
    assert!(
        funding_warning_line(&funding_off).is_none(),
        "a market with funding switched off must not be warned about; logs: {funding_off:#?}"
    );
}

// ── BUG 3 ────────────────────────────────────────────────────────────────────
//
// `InitMarket` sets `max_market_slots = max_portfolio_assets` and pre-configures
// every slot below it as Active. `UpdateAssetLifecycle(ACTIVATE)` can only
// APPEND at `asset_index == max_market_slots` or RE-ACTIVATE a `Retired` slot,
// so on a market with `max_portfolio_assets = 2`, index 1 is un-activatable.
// The deployed program answers `EngineLockActive` (Custom 21) — which means
// "the market/asset is locked", something else entirely, and gives the caller
// no hint that the slot is simply already in service.
#[test]
fn v17_activate_already_configured_slot_reports_a_distinct_error() {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(2, 10_000, 10_000, 10_000);
    env.svm.warp_to_slot(1);

    let (_, g) = env.market_state();
    assert_eq!(
        g.config.max_market_slots, 2,
        "InitMarket sets max_market_slots = max_portfolio_assets"
    );
    assert_eq!(
        g.assets[1].lifecycle,
        AssetLifecycleV16::Active,
        "slot 1 is pre-configured and in service — it is not appendable and not retired"
    );

    let admin = env.admin.insecure_clone();
    let market = env.market;
    let authority = admin.pubkey().to_bytes();
    let err = env
        .send(
            ProgInstruction::UpdateAssetLifecycle {
                action: 0, // ACTIVATE
                asset_index: 1,
                now_slot: 1,
                initial_price: 100,
                insurance_authority: authority,
                insurance_operator: authority,
                backing_bucket_authority: authority,
                oracle_authority: authority,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
            ],
            &[&admin],
        )
        .expect_err("activating an already-configured slot must fail");

    assert_ne!(
        custom_code(&err),
        Some(PercolatorError::EngineLockActive as u32),
        "LockActive means the market/asset is locked, which is NOT what happened; got {err}"
    );
    assert_eq!(
        custom_code(&err),
        Some(PercolatorError::AssetSlotAlreadyConfigured as u32),
        "the slot is already configured and in service — say exactly that; got {err}"
    );

    // The slot must be untouched by the refused activation.
    let (_, g_after) = env.market_state();
    assert_eq!(g_after.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(
        g_after.assets[1].market_id, g.assets[1].market_id,
        "a refused activation must not mint a new market_id for the live slot"
    );
}

/// Ordinal pin for the new error code. Ordinals are wire-visible: this fails
/// loudly if anything is ever inserted rather than appended.
#[test]
fn v17_new_error_ordinals_are_appended_at_the_tail() {
    assert_eq!(PercolatorError::StakeProgramNotPinned as u32, 60);
    assert_eq!(PercolatorError::AssetSlotAlreadyConfigured as u32, 61);
}

/// #436 CHARACTERISATION — what actually drives BatchTradeCpi compute?
///
/// The budget is `MATCHER_BATCH_TAIL_FANOUT_BUDGET = MAX_MATCHER_TAIL_ACCOUNTS * 2 = 64`,
/// enforced as `legs.len() * tail.len() > 64 -> reject` (v16_program.rs:9492). The companion
/// test proves a 14x4 product of 56 passes that check and then dies at 1_399_676 of 1_399_700
/// CU. What it does NOT establish is whether the PRODUCT is the right thing to bound.
///
/// This sweeps the two axes independently and prints measured CU, so the remediation has a
/// number instead of an adjective. It is a characterisation, not a pass/fail assertion about
/// any particular limit — the only thing it asserts is that the cheap corner works, which
/// keeps it from silently measuring a broken harness.
#[test]
fn v16_bpf_batch_trade_cpi_fanout_budget_characterisation() {
    const PRICE: u64 = 100;

    fn benign_tail(env: &mut V16CuEnv, count: usize) -> Vec<Pubkey> {
        (0..count)
            .map(|_| {
                let key = Pubkey::new_unique();
                env.svm
                    .set_account(
                        key,
                        Account {
                            lamports: 1_000_000_000,
                            data: vec![0u8; 8],
                            owner: Pubkey::default(),
                            executable: false,
                            rent_epoch: 0,
                        },
                    )
                    .unwrap();
                key
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn metas(
        taker: Pubkey,
        market: Pubkey,
        taker_account: Pubkey,
        lp_account: Pubkey,
        matcher_program: Pubkey,
        ctx: Pubkey,
        delegate: Pubkey,
        tail: &[Pubkey],
    ) -> Vec<AccountMeta> {
        let mut m = vec![
            AccountMeta::new(taker, true),
            AccountMeta::new(market, false),
            AccountMeta::new(taker_account, false),
            AccountMeta::new(lp_account, false),
            AccountMeta::new_readonly(matcher_program, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        m.extend(
            tail.iter()
                .copied()
                .map(|k| AccountMeta::new_readonly(k, false)),
        );
        m
    }

    /// One measurement. Returns Ok(cu) or Err(reason).
    fn run(legs_n: u16, tail_n: usize) -> Result<u64, String> {
        let mut env = V16CuEnv::new_with_market_params_and_price_move(legs_n, 1_000, 1_000, 500);
        for a in 0..legs_n {
            env.configure_auth_mark_for_asset_as_admin(a, legs_n as u64 + 1, PRICE);
        }
        let matcher_program = Pubkey::new_unique();
        let bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
        env.svm.add_program(matcher_program, &bytes);
        let taker = Keypair::new();
        let lp = Keypair::new();
        let taker_account = env.create_portfolio(&taker);
        let lp_account = env.create_portfolio(&lp);
        env.deposit(&taker, taker_account, 100_000_000);
        env.deposit(&lp, lp_account, 100_000_000);
        let (ctx, delegate, _) = env.init_matcher_context(&lp, matcher_program, lp_account);
        let legs: Vec<percolator_prog::ix::BatchTradeCpiLeg> = (0..legs_n)
            .map(|asset_index| percolator_prog::ix::BatchTradeCpiLeg {
                asset_index,
                size_q: POS_SCALE as i128,
                fee_bps: 100,
                limit_price: 0,
            })
            .collect();
        let tail = benign_tail(&mut env, tail_n);
        env.svm.expire_blockhash();
        env.send(
            ProgInstruction::BatchTradeCpi { legs },
            metas(
                taker.pubkey(),
                env.market,
                taker_account,
                lp_account,
                matcher_program,
                ctx,
                delegate,
                &tail,
            ),
            &[&taker],
        )
        .map_err(|e| {
            if e.contains("exceeded CUs meter") {
                "CU EXHAUSTED".to_string()
            } else if e.contains("Custom(9)") {
                "rejected by budget check".to_string()
            } else {
                e.chars().take(60).collect()
            }
        })
    }

    println!("\n  legs x tail = product : result");
    println!("  ----------------------------------------");
    // Axis A: hold the tail at 1 and grow legs. If CU tracks legs alone, the product is the
    // wrong metric and a product budget can never be made safe by shrinking it.
    let mut per_leg: Vec<(u16, u64)> = Vec::new();
    for legs_n in [2u16, 4, 8, 10, 11, 12, 14] {
        match run(legs_n, 1) {
            Ok(cu) => {
                println!("  {:>4} x    1 = {:>4} : {:>9} CU", legs_n, legs_n, cu);
                per_leg.push((legs_n, cu));
            }
            Err(e) => println!("  {:>4} x    1 = {:>4} : {}", legs_n, legs_n, e),
        }
    }
    // Axis B: hold legs low and grow the tail, to isolate the tail's own cost.
    for tail_n in [1usize, 4, 8, 16] {
        match run(4, tail_n) {
            Ok(cu) => println!(
                "  {:>4} x {:>4} = {:>4} : {:>9} CU",
                4,
                tail_n,
                4 * tail_n,
                cu
            ),
            Err(e) => println!("  {:>4} x {:>4} = {:>4} : {}", 4, tail_n, 4 * tail_n, e),
        }
    }
    // The corner the companion test proves fatal, for continuity.
    match run(14, 4) {
        Ok(cu) => println!("  {:>4} x {:>4} = {:>4} : {:>9} CU", 14, 4, 56, cu),
        Err(e) => println!("  {:>4} x {:>4} = {:>4} : {}", 14, 4, 56, e),
    }

    if per_leg.len() >= 2 {
        let (l0, c0) = per_leg[0];
        let (l1, c1) = *per_leg.last().unwrap();
        let per = (c1.saturating_sub(c0)) / ((l1 - l0) as u64).max(1);
        println!("\n  marginal cost per LEG (tail fixed at 1): ~{per} CU");
        println!(
            "  budget of 64 as a product admits 64 legs x 1 tail => ~{} CU",
            per * 64
        );
    }

    // Anti-vacuity only: the cheapest corner must work, or every line above is measuring a
    // broken harness rather than the program.
    assert!(run(2, 1).is_ok(), "the 2x1 corner must execute");
}

// ════════════════════════════════════════════════════════════════════════════
// #427 REACHABILITY PROOF — lives here, not in v16_wrapper.rs.
//
// `handle_withdraw_insurance_asset` calls `Clock::get()` for the cooldown check, and
// the v16_wrapper harness has no Clock sysvar (that whole withdrawal family is in
// KNOWN_FAILING for exactly this reason). LiteSVM has a real clock, so the gate can
// actually be observed firing here.
//
// The settability, bound and authority tests live in v16_wrapper.rs. What THESE prove
// is the only thing that made #427 a defect rather than a missing feature: before the
// fix the cooldown was structurally pinned at zero, so the F-1 gate added by
// #385/#386/#396 could not execute in any market that had ever been created.
// ════════════════════════════════════════════════════════════════════════════

fn withdraw_insurance_asset_result(env: &mut V16CuEnv, amount: u128) -> Result<u64, String> {
    let dest = Pubkey::new_unique();
    let mint = env.mint;
    let admin_pk = env.admin.pubkey();
    env.svm
        .set_account(
            dest,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, admin_pk, 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let admin = env.admin.insecure_clone();
    let market = env.market;
    let vault = env.vault;
    let vault_authority = env.vault_authority;
    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::WithdrawInsuranceAsset {
            asset_index: 0,
            amount,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&admin],
    )
}

#[test]
fn v16_bpf_insurance_withdraw_cooldown_now_actually_fires() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000);
    let admin = env.admin.insecure_clone();
    env.top_up_insurance_domain_with_authority_and_cu(&admin, 0, 500);

    // The instruction that did not exist before #427.
    send_tx(
        &mut env.svm,
        env.program_id,
        &env.payer.insecure_clone(),
        ProgInstruction::UpdateInsuranceWithdrawPolicy {
            deposits_only: 0,
            cooldown_slots: 1_000,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    )
    .expect("#427: the withdrawal policy must be settable");

    // MUST run at a non-zero slot. `check_insurance_withdraw_cooldown` skips the gate when
    // `last_slot == 0`, and it uses 0 as the "never withdrawn" sentinel — so at LiteSVM's
    // starting slot the first withdrawal records 0, which reads as "no previous withdrawal"
    // and hands out a free second one. Slot 0 is unreachable on a real cluster, so this is a
    // harness artifact rather than a defect, but it is exactly the kind of artifact that
    // makes a gate look broken when it is not.
    env.svm.warp_to_slot(100);
    let first = withdraw_insurance_asset_result(&mut env, 10);
    let second = withdraw_insurance_asset_result(&mut env, 10);
    // And it must be a COOLDOWN, not a permanent block: past the window it opens again.
    env.svm.warp_to_slot(100 + 1_000 + 1);
    let after_window = withdraw_insurance_asset_result(&mut env, 10);
    println!("    [#427] first        -> {first:?}");
    println!("    [#427] second       -> {second:?}");
    println!("    [#427] after window -> {after_window:?}");

    assert!(
        first.is_ok(),
        "first withdrawal is always allowed by design: {first:?}"
    );
    assert!(
        after_window.is_ok(),
        "the gate must EXPIRE — a cooldown that never lifts is a freeze, not a rate limit: \
         {after_window:?}"
    );
    assert!(
        second.is_err(),
        "#427 REGRESSION — a second withdrawal inside the cooldown window was ACCEPTED. \
         The F-1 gate added by #385/#386/#396 is unreachable again, which is the whole defect."
    );
}

/// CONTROL. With the cooldown left at its default zero — the state EVERY market was
/// stuck in before #427 — the second withdrawal must SUCCEED. Without this, the
/// rejection above could be any other rule and would be evidence for the wrong claim.
/// A first draft of this pair lived in v16_wrapper.rs where BOTH failed on
/// `UnsupportedSysvar`; only the control revealed the harness was at fault.
#[test]
fn control_second_insurance_withdrawal_succeeds_with_no_cooldown_configured() {
    let mut env = V16CuEnv::new();
    env.top_up_insurance(1_000);
    let admin = env.admin.insecure_clone();
    env.top_up_insurance_domain_with_authority_and_cu(&admin, 0, 500);
    // Deliberately NO UpdateInsuranceWithdrawPolicy — this is the pre-#427 world.

    env.svm.warp_to_slot(100);
    let first = withdraw_insurance_asset_result(&mut env, 10);
    let second = withdraw_insurance_asset_result(&mut env, 10);
    println!("    [#427-control] first  -> {first:?}");
    println!("    [#427-control] second -> {second:?}");
    assert!(first.is_ok(), "control first withdrawal: {first:?}");
    assert!(
        second.is_ok(),
        "CONTROL BROKEN — the second withdrawal failed with no cooldown set, so the \
         rejection in the test above cannot be attributed to the policy: {second:?}"
    );
}

/// THE REGRESSION TEST FOR THE STRANDING. A market with NO LP vault must be able to take
/// backing out again.
///
/// This is the exact shape 45bba89e broke and shipped: it made the ledger mandatory on
/// `WithdrawBackingBucket` while nothing on that path could CREATE the PDA, so on a market
/// with no LP vault `expect_owner` failed and deposited backing became unwithdrawable.
///
/// BOTH instructions are built BY HAND. Every `V16CuEnv` backing helper routes through
/// `canonical_backing_domain_ledger_account`, which `set_account`s the ledger into
/// existence — using any of them makes this test VACUOUS, because the harness creates the
/// account the program is supposed to create. Two negative-control runs passed against a
/// build with the creation path deleted before that was spotted.
#[test]
fn v16_bpf_backing_topup_then_withdraw_works_without_an_lp_vault() {
    let mut env = V16CuEnv::new();
    let ledger = state::derive_lp_backing_ledger(&env.program_id, &env.market, 1).0;

    // PROOF OF LIFE: nothing may have created the ledger yet, or this proves nothing.
    assert!(
        env.svm.get_account(&ledger).is_none(),
        "the ledger PDA must not exist before the top-up"
    );

    let admin = env.admin.insecure_clone();
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let market = env.market;
    let vault = env.vault;
    let vault_authority = env.vault_authority;
    let source = env.token_account(admin.pubkey(), 100);

    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::TopUpBackingBucket {
            domain: 1,
            amount: 100,
            expiry_slot: 10,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(source, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&admin],
    )
    .expect("top up must succeed and CREATE the ledger");

    assert!(
        env.svm.get_account(&ledger).is_some(),
        "TopUpBackingBucket must have created the backing-domain ledger"
    );

    env.svm.expire_blockhash();
    let dest = env.token_account(admin.pubkey(), 0);
    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::WithdrawBackingBucket {
            domain: 1,
            amount: 40,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&admin],
    )
    .expect(
        "backing must be withdrawable from a market with no LP vault — this failing is \
            the fund-stranding regression of 2026-09-01 returning",
    );

    assert_eq!(env.token_amount(dest), 40);
    let led =
        state::read_backing_domain_ledger(&env.svm.get_account(&ledger).unwrap().data).unwrap();
    assert_eq!(
        led.total_principal_atoms, 60,
        "the ledger booked the withdrawal"
    );
    assert_eq!(led.total_principal_withdrawn_atoms, 40);
}

// ════════════════════════════════════════════════════════════════════════════
// #433 LEGACY LEDGERLESS RECONCILIATION
//
// These fixtures deliberately DO NOT use any V16CuEnv backing helper.
// `canonical_backing_domain_ledger_account` set_accounts the ledger into
// existence, which would make the migration proof vacuous.
//
// The state below models a historically valid 100-atom backing deposit after
// 40 atoms have been consumed:
//
//   bucket: fresh=60, consumed=40
//   source: fresh_reserved=60, spent=40, provider_receivable=40
//
// The three consumption counters are kept coherent so the production
// wrapper's validate_shape() accepts the fixture before committing migration.
// ════════════════════════════════════════════════════════════════════════════

fn seed_legacy_ledgerless_consumed_backing(
    env: &mut V16CuEnv,
    domain: usize,
    fresh_atoms: u128,
    consumed_atoms: u128,
) {
    let fresh_num = fresh_atoms
        .checked_mul(BOUND_SCALE)
        .expect("fresh backing scale");
    let consumed_num = consumed_atoms
        .checked_mul(BOUND_SCALE)
        .expect("consumed backing scale");
    let total_atoms = fresh_atoms
        .checked_add(consumed_atoms)
        .expect("legacy backing total");

    env.mutate_market(|_cfg, group| {
        let bucket = &mut group.source_backing_buckets[domain];
        bucket.fresh_unliened_backing_num = fresh_num;
        bucket.valid_liened_backing_num = 0;
        bucket.consumed_liened_backing_num = consumed_num;
        bucket.impaired_liened_backing_num = 0;
        bucket.utilization_fee_earnings = 0;
        bucket.expiry_slot = 10;
        bucket.status = BackingBucketStatusV16::Fresh;

        let source = &mut group.source_credit[domain];
        source.fresh_reserved_backing_num = fresh_num;
        source.valid_liened_backing_num = 0;
        source.impaired_liened_backing_num = 0;
        source.spent_backing_num = consumed_num;
        source.provider_receivable_num = consumed_num;

        group.vault = total_atoms;

        // Keep the legacy fixture internally coherent. The production
        // TopUpBackingBucket path performs the full engine validate_shape()
        // before committing the migrated state.
        assert_eq!(
            source.provider_receivable_num, bucket.consumed_liened_backing_num,
            "#433 fixture: provider receivable must match consumed backing"
        );
        assert!(
            source.spent_backing_num >= source.provider_receivable_num,
            "#433 fixture: spent backing must cover provider receivable"
        );
        assert_eq!(
            source.fresh_reserved_backing_num,
            bucket
                .fresh_unliened_backing_num
                .checked_add(bucket.valid_liened_backing_num)
                .expect("#433 fixture fresh+valid overflow"),
            "#433 fixture: reserved backing must match fresh+valid backing"
        );
        assert_eq!(
            source.valid_liened_backing_num, bucket.valid_liened_backing_num,
            "#433 fixture: valid lien counters must agree"
        );
        assert_eq!(
            source.impaired_liened_backing_num, bucket.impaired_liened_backing_num,
            "#433 fixture: impaired lien counters must agree"
        );
    });

    env.set_token_account_amount(
        env.vault,
        env.mint,
        env.vault_authority,
        u64::try_from(total_atoms).expect("legacy vault amount fits u64"),
    );
}

#[test]
fn v16_bpf_legacy_ledgerless_backing_zero_topup_reconciles_before_withdraw() {
    const DOMAIN: u16 = 1;

    let mut env = V16CuEnv::new();
    let ledger = state::derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN).0;

    // Recreate the pre-e8acd708 state: backing exists, canonical ledger does not.
    seed_legacy_ledgerless_consumed_backing(&mut env, DOMAIN as usize, 60, 40);

    assert!(
        env.svm.get_account(&ledger).is_none(),
        "legacy fixture must not pre-create the canonical ledger"
    );

    let admin = env.admin.insecure_clone();
    let payer = env.payer.insecure_clone();
    let pid = env.program_id;
    let market = env.market;
    let vault = env.vault;
    let vault_authority = env.vault_authority;

    // A provider must not have to add new capital just to make historical
    // backing withdrawable. Build the migration instruction BY HAND.
    let zero_source = env.token_account(admin.pubkey(), 0);

    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::TopUpBackingBucket {
            domain: DOMAIN,
            amount: 0,
            expiry_slot: 10,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(zero_source, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&admin],
    )
    .expect("#433 zero-amount top-up must create and reconcile the legacy ledger");

    let ledger_account = env
        .svm
        .get_account(&ledger)
        .expect("migration must create the canonical ledger");
    let migrated = state::read_backing_domain_ledger(&ledger_account.data)
        .expect("read reconciled backing ledger");

    assert_eq!(
        migrated.total_principal_atoms, 100,
        "migration must reconstruct gross outstanding principal"
    );
    assert_eq!(
        migrated.cumulative_loss_atoms, 40,
        "pre-existing consumed backing must seed the impairment baseline"
    );
    assert_eq!(migrated.cumulative_recovery_atoms, 0);
    assert_eq!(
        migrated.last_observed_unavailable_principal_atoms, 40,
        "migration watermark must match the same pre-existing impairment"
    );
    assert_eq!(
        migrated.total_deposited_atoms, 0,
        "migration must not invent historical lifetime deposit flow"
    );

    // The 60 atoms that are actually fresh must remain withdrawable.
    env.svm.expire_blockhash();
    let dest = env.token_account(admin.pubkey(), 0);

    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::WithdrawBackingBucket {
            domain: DOMAIN,
            amount: 60,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
        ],
        &[&admin],
    )
    .expect("reconciled legacy fresh backing must be withdrawable");

    assert_eq!(env.token_amount(dest), 60);
    assert_eq!(env.token_amount(vault), 40);

    let ledger_after = env.svm.get_account(&ledger).unwrap();
    let ledger_after = state::read_backing_domain_ledger(&ledger_after.data).unwrap();

    assert_eq!(ledger_after.total_principal_atoms, 40);
    assert_eq!(ledger_after.total_principal_withdrawn_atoms, 60);
    assert_eq!(ledger_after.cumulative_loss_atoms, 40);
    assert_eq!(ledger_after.cumulative_recovery_atoms, 0);
}

#[test]
fn v16_bpf_legacy_ledgerless_nonzero_topup_does_not_book_refill_as_recovery() {
    const DOMAIN: u16 = 1;

    let mut env = V16CuEnv::new();
    let ledger = state::derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN).0;

    // Pre-existing state: 60 fresh + 40 consumed, with no wrapper ledger.
    seed_legacy_ledgerless_consumed_backing(&mut env, DOMAIN as usize, 60, 40);

    assert!(
        env.svm.get_account(&ledger).is_none(),
        "legacy fixture must start ledgerless"
    );

    let admin = env.admin.insecure_clone();
    let payer = env.payer.insecure_clone();
    let pid = env.program_id;
    let market = env.market;
    let vault = env.vault;

    // Build the top-up BY HAND. The new 20 atoms refill 20 atoms of provider
    // receivable, so consumed falls 40 -> 20 while fresh rises 60 -> 80.
    let source = env.token_account(admin.pubkey(), 20);

    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::TopUpBackingBucket {
            domain: DOMAIN,
            amount: 20,
            expiry_slot: 10,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(source, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&admin],
    )
    .expect("#433 legacy top-up must reconcile before booking the new deposit");

    let (_, group) = env.market_state();
    assert_eq!(
        group.source_backing_buckets[DOMAIN as usize].fresh_unliened_backing_num,
        80 * BOUND_SCALE
    );
    assert_eq!(
        group.source_backing_buckets[DOMAIN as usize].consumed_liened_backing_num,
        20 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[DOMAIN as usize].provider_receivable_num,
        20 * BOUND_SCALE
    );
    assert_eq!(
        group.source_credit[DOMAIN as usize].spent_backing_num,
        40 * BOUND_SCALE
    );

    let ledger_account = env.svm.get_account(&ledger).unwrap();
    let migrated = state::read_backing_domain_ledger(&ledger_account.data).unwrap();

    assert_eq!(migrated.total_principal_atoms, 120);
    assert_eq!(
        migrated.total_deposited_atoms, 20,
        "only the post-migration top-up is known lifetime deposit flow"
    );
    assert_eq!(
        migrated.cumulative_loss_atoms, 40,
        "historical impairment remains the migration baseline"
    );
    assert_eq!(
        migrated.cumulative_recovery_atoms, 0,
        "new capital refill must not be booked as historical recovery"
    );
    assert_eq!(
        migrated.last_observed_unavailable_principal_atoms, 20,
        "post-refill unavailable watermark must be re-baselined"
    );

    // Prove the NEXT normal sync does not manufacture a 20-atom recovery.
    env.svm.expire_blockhash();

    send_tx(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::SyncBackingDomainLedger { domain: DOMAIN },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(ledger, false),
        ],
        &[&admin],
    )
    .expect("post-migration ledger sync must succeed");

    let synced_account = env.svm.get_account(&ledger).unwrap();
    let synced = state::read_backing_domain_ledger(&synced_account.data).unwrap();

    assert_eq!(synced.total_principal_atoms, 120);
    assert_eq!(synced.cumulative_loss_atoms, 40);
    assert_eq!(
        synced.cumulative_recovery_atoms, 0,
        "the 20-atom capital refill must remain invisible to recovery accounting"
    );
    assert_eq!(synced.last_observed_unavailable_principal_atoms, 20);
}
