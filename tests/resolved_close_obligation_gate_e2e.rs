// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! WRAPPER-LEVEL COMPANION to engine PR dcccrypto/percolator#267 — the on-chain
//! reachability of the resolved-close Recovery-obligation gate, EXECUTED.
//!
//! #267 ports hunk (d) of upstream `aeyakovenko/percolator` `94979ede`: six lines in
//! `detach_solvent_active_legs_for_resolved_close` (`percolator:7606c678:src/v16.rs:21090-21095`)
//! that refuse to detach a Recovery pending obligation while the OPPOSITE side still holds real
//! (non-obligation) positions. Its PoC (`percolator/tests/resolved_close_obligation_gate.rs`)
//! drives the engine's own public API in-process; its REACHABILITY section claims the defect is
//! reachable through wrapper instruction tags 3 -> 6 -> 40 -> 43 -> 19 -> 30, source-read only.
//!
//! This file executes that claim against the real SBF program in LiteSVM. Every state transition
//! below is a genuine `percolator_prog` instruction in a signed transaction; every assertion reads
//! the post-state back out of the on-chain market / portfolio accounts or out of SPL token
//! balances. Nothing is poked into an account by the harness.
//!
//! The executed tag sequence (tags per the dispatch table, `src/v16_program.rs:4904-4923`,
//! `:4986`, `:4999`, `:5069`, `:5107`, `:5128`):
//!
//!   tag 38 `ConfigurePermissionlessResolve`  — see the NOTE below; tag 40's shutdown arm is
//!                                        unreachable without it
//!   tag  1 `InitPortfolio`         x3  — L1, L2, S
//!   tag  3 `Deposit`               x3  — L1, L2, S fund their portfolios (real SPL transfers)
//!   tag  6 `TradeNoCpi`            x2  — L1/S and L2/S open: two longs against one short
//!   tag 40 `UpdateAssetLifecycle`  x1  — `ASSET_ACTION_SHUTDOWN` -> asset 0 is `Recovery`
//!                                        while the MARKET is still `Live`
//!   tag 43 `ForfeitRecoveryLeg`    x1  — L1's dead-leg forfeit RETAINS (does not detach):
//!                                        `pending_obligation_count_long == 1`, L1's leg
//!                                        `basis_pos_q == 0`, `loss_weight != 0`
//!   tag 19 `ResolveMarket`         x1  — the group goes `Resolved`; the ASSET stays `Recovery`
//!                                        (that is the reachability)
//!   tag 30 `CloseResolved`             — THE CALL UNDER TEST
//!
//! NOTE — #267's `3 -> 6 -> 40 -> 43 -> 19 -> 30` HOLDS, WITH ONE ADDITION IT DOES NOT NAME.
//! Every tag in the PR's list is correct and in the right order (tag 3 is `Deposit` at `:4905`,
//! tag 6 is `TradeNoCpi` at `:4918`). The one thing the list omits is that tag 40 reaches
//! `force_asset_recovery_not_atomic` ONLY through `ASSET_ACTION_SHUTDOWN` (action 3,
//! `src/v16_program.rs:15364-15400`) — tag 40's other three actions (ACTIVATE / DRAIN_ONLY /
//! RETIRE) never write the `Recovery` lifecycle — and that arm refuses outright while
//! `cfg.force_close_delay_slots == 0` (`:15365`), so tag 38 `ConfigurePermissionlessResolve` must
//! run first. That is a gap in the PR's prose, not in the fix: with it the reachability claim
//! holds exactly, and this file measures it.
//!
//! WHAT THE THREE TESTS PROVE, ALL AT THE PROGRAM LEVEL:
//!   (a) `e2e_resolved_close_must_not_release_a_gated_recovery_obligation`
//!       THE DISCRIMINATOR. L1's tag-30 `CloseResolved` must NOT detach the obligation:
//!       `pending_obligation_count_long` and `loss_weight_sum_long` unchanged in the market
//!       account, L1's leg still active in the portfolio account, and ZERO tokens moved to L1.
//!       RED against the unpatched engine, GREEN against the patched one.
//!   (b) `e2e_gated_obligation_releases_once_the_opposite_side_has_cleared`
//!       THE LIVENESS HALF. S and L2 close through the same tag 30; L1's NEXT tag-30 call then
//!       succeeds and pays out in full. The guard is a wait, not a brick — on chain.
//!   (c) `e2e_an_ordinary_leg_on_the_same_recovery_asset_still_closes_in_one_call`
//!       THE NARROWNESS CONTROL. L2 — real basis, same asset, same `Resolved` market, same
//!       blocked opposite side — still closes in one call and is paid.
//! (b) and (c) pass on both trees by construction; only (a) discriminates.
//!
//! ## SEQUENCING — THIS FILE CANNOT BE GREEN IN dcccrypto CI YET
//! `ci/deployed-refs.env` pins `ENGINE_CI_SIBLING=c141d47f`, which PREDATES the guard, so CI
//! builds this wrapper against an engine WITHOUT hunk (d) and test (a) here would fail exactly the
//! way it is designed to. This is a COMPANION to be filed AFTER dcccrypto/percolator#267 merges
//! and `ENGINE_CI_SIBLING` advances past it — not before. Tests (b) and (c) are pin-independent.
//!
//! ## HARNESS PROVENANCE
//! `V16CuEnv` lives in `tests/v16_cu.rs`, which is its own integration-test crate: its items are
//! private to that crate root and cannot be imported here, and `include!`-ing the file would
//! recompile and re-run its 151 BPF tests inside this binary. The subset below is therefore
//! ported from `tests/v16_cu.rs`, each item carrying the `file:line` it came from. Four of them
//! collapse a forwarding wrapper into the single body it calls (`new`, `create_portfolio`,
//! `deposit`, `trade_asset_with_cu`); each says so at its definition and none changes an argument.
//! The only body whose CONTENT differs from the original is `close_resolved_owner_signed_with_cu`:
//! it signs as the owner, passes the owner as an extra signer, and returns `Result` instead of
//! unwrapping. All three deltas are called out at its definition.
//!
//! ## LINE NUMBERS
//! `percolator:src/v16.rs:NNN` here is the PATCHED tree (`7606c678` and later); #267's own engine
//! PoC anchors its numbers to `e8715152` instead and says so in its header. The two differ by the
//! six lines of hunk (d) at `:21090`, which is why e.g. the `close_q == 0` branch is `:21132` here
//! and `:21126` there. Both are right about their own tree.
//!
//! Run:
//!   cargo test --test resolved_close_obligation_gate_e2e -- --nocapture

use litesvm::LiteSVM;
use percolator::{
    v16_domain_pair_for_asset_index, AssetLifecycleV16, MarketModeV16, PortfolioLegV16, POS_SCALE,
};
use percolator_prog::{
    ix::Instruction as ProgInstruction,
    processor, state,
    state::{MarketGroupV16, PortfolioAccountV16},
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

// =================================================================================================
// HARNESS — verbatim port of the `tests/v16_cu.rs` subset this file needs.
// =================================================================================================

/// `tests/v16_cu.rs:74`
fn active_leg_for_asset(account: &PortfolioAccountV16, asset_index: usize) -> PortfolioLegV16 {
    account
        .legs
        .iter()
        .copied()
        .find(|leg| leg.active && leg.asset_index as usize == asset_index)
        .unwrap()
}

/// `tests/v16_cu.rs:86`
fn has_active_leg_for_asset(account: &PortfolioAccountV16, asset_index: usize) -> bool {
    account
        .legs
        .iter()
        .any(|leg| leg.active && leg.asset_index as usize == asset_index)
}

/// `tests/v16_cu.rs:93`
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

/// `tests/v16_cu.rs:116`
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

/// `tests/v16_cu.rs:179`
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

/// `tests/v16_cu.rs:195`
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

/// `tests/v16_cu.rs:308`
fn cu_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

/// `tests/v16_cu.rs:312`
fn heap_ix() -> Instruction {
    ComputeBudgetInstruction::request_heap_frame(128 * 1024)
}

/// `tests/v16_cu.rs:12433`
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

/// `tests/v16_cu.rs:3217`
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

/// `tests/v16_cu.rs:316`
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

/// `tests/v16_cu.rs:328`
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

/// `tests/v16_cu.rs:354`
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
    /// `tests/v16_cu.rs:384` -> `:388` -> `:403` -> `:420`, collapsed to the one call chain
    /// `V16CuEnv::new()` actually performs.
    fn new() -> Self {
        Self::new_with_init_params(V16CuMarketParams {
            max_portfolio_assets: 1,
            maintenance_margin_bps: 10_000,
            initial_margin_bps: 10_000,
            max_price_move_bps_per_slot: 10_000,
            maintenance_fee_per_slot: 0,
            ..V16CuMarketParams::default()
        })
    }

    /// `tests/v16_cu.rs:420`
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

    /// `tests/v16_cu.rs:529` / `:533`
    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
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
        self.send(
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

    /// `tests/v16_cu.rs:562` / `:1125` — tag 3 `Deposit`.
    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
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
        self.send(
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
        source
    }

    /// `tests/v16_cu.rs:631` — tag 40 `UpdateAssetLifecycle`.
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

    /// `tests/v16_cu.rs:940`
    fn market_state(&self) -> (state::WrapperConfigV16, MarketGroupV16) {
        let account = self.svm.get_account(&self.market).expect("market account");
        state::read_market(&account.data).unwrap()
    }

    /// `tests/v16_cu.rs:945`
    fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        let account = self.svm.get_account(&portfolio).expect("portfolio account");
        state::read_portfolio(&account.data).unwrap()
    }

    /// `tests/v16_cu.rs:1176` / `:1201` — tag 6 `TradeNoCpi`.
    #[allow(clippy::too_many_arguments)]
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
        .expect("trade")
    }

    /// `tests/v16_cu.rs:1804` — tag 19 `ResolveMarket`.
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

    /// `tests/v16_cu.rs:1851` — tag 38 `ConfigurePermissionlessResolve`. Needed only because
    /// tag 40's `ASSET_ACTION_SHUTDOWN` arm refuses outright while `force_close_delay_slots == 0`
    /// (`src/v16_program.rs:15365`).
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

    /// Tag 30 `CloseResolved`. Body is `tests/v16_cu.rs:2289` (`close_resolved_with_cu`) with
    /// exactly ONE change, marked below: the owner is passed as a SIGNER. The harness helper drives
    /// the PERMISSIONLESS variant, which `handle_close_resolved` (`src/v16_program.rs:16779-16785`)
    /// admits only once `force_close_delay_slots` slots have elapsed since `resolved_slot`; this
    /// scenario must set `force_close_delay_slots != 0` to reach tag 40's shutdown arm at all, so
    /// the owner-signed form is both the reachable one and the one the engine PoC models (L1/L2/S
    /// each close their own account). Returns `(dest_token, result)` so callers can assert on the
    /// payout tokens whether or not the instruction succeeded.
    fn close_resolved_owner_signed_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
    ) -> (Pubkey, Result<u64, String>) {
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
        let result = self.send(
            ProgInstruction::CloseResolved {
                fee_rate_per_slot: 0,
            },
            vec![
                // ---- THE ONE DELTA vs v16_cu.rs:2309: `is_signer = true` here, `false` there ----
                AccountMeta::new_readonly(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[owner],
        );
        (dest, result)
    }

    /// `tests/v16_cu.rs:2976`
    fn token_amount(&self, key: Pubkey) -> u64 {
        let account = self.svm.get_account(&key).expect("token account");
        TokenAccount::unpack(&account.data).unwrap().amount
    }

    /// `tests/v16_cu.rs:3023` — tag 43 `ForfeitRecoveryLeg`.
    fn forfeit_recovery_leg_with_cu(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        asset_index: u16,
        b_loss_atom_budget: u128,
    ) -> u64 {
        self.send(
            ProgInstruction::ForfeitRecoveryLeg {
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

    /// `tests/v16_cu.rs:824`
    fn ensure_signer_account(&mut self, key: Pubkey) {
        if self.svm.get_account(&key).is_none() {
            self.svm.airdrop(&key, 1_000_000_000).unwrap();
        }
    }

    /// `tests/v16_cu.rs:3200`
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

// =================================================================================================
// THE SCENARIO
// =================================================================================================

const ASSET: u16 = 0;
const PRICE: u64 = 100;
const LOT: u128 = 2 * POS_SCALE;
const DEPOSIT: u128 = 10_000;
/// `add_open_interest_for_new_position` (`percolator:src/v16.rs:732-769`) books
/// `loss_weight == abs_q` for an opening leg at `a == ADL_ONE`, so each leg weighs `LOT` and the
/// long side starts at `2 * LOT`.
const LEG_WEIGHT: u128 = LOT;
/// The slot tag 40's shutdown arm is authenticated at. Must be non-zero
/// (`src/v16_program.rs:15365`) and `>= group.header.current_slot`.
const SHUTDOWN_SLOT: u64 = 1;

struct Actors {
    l1_owner: Keypair,
    l1: Pubkey,
    l2_owner: Keypair,
    l2: Pubkey,
    s_owner: Keypair,
    s: Pubkey,
}

fn asset_state(env: &V16CuEnv) -> percolator::AssetStateV16 {
    env.market_state().1.assets[ASSET as usize]
}

/// Long/short barrier counters for `ASSET`, read out of the real market account. Domain layout is
/// `v16_domain_pair_for_asset_index` (`percolator:src/v16.rs:193`), the same mapping the wrapper's
/// account decoder uses (`src/v16_program.rs:3082`, `:3104-3107`).
fn barriers(env: &V16CuEnv) -> (u64, u64) {
    let (long_domain, short_domain) = v16_domain_pair_for_asset_index(ASSET as usize).unwrap();
    let group = env.market_state().1;
    (
        group.pending_domain_loss_barriers[long_domain],
        group.pending_domain_loss_barriers[short_domain],
    )
}

/// Drives tags 38 -> 3 -> 6 -> 40 -> 43 -> 19 through the real program, leaving L1's leg parked as
/// a zero-basis Recovery pending obligation inside a `Resolved` market whose asset is still
/// `Recovery`. Every intermediate claim is asserted against state read back from the accounts.
fn drive_to_the_parked_obligation() -> (V16CuEnv, Actors) {
    let mut env = V16CuEnv::new();

    // tag 38 — only so tag 40's shutdown arm is reachable at all.
    env.configure_permissionless_resolve_with_cu(9_000, 5);

    let l1_owner = Keypair::new();
    let l2_owner = Keypair::new();
    let s_owner = Keypair::new();
    let l1 = env.create_portfolio(&l1_owner);
    let l2 = env.create_portfolio(&l2_owner);
    let s = env.create_portfolio(&s_owner);

    // tag 3 x3 — real SPL transfers into the vault.
    env.deposit(&l1_owner, l1, DEPOSIT);
    env.deposit(&l2_owner, l2, DEPOSIT);
    env.deposit(&s_owner, s, DEPOSIT);
    assert_eq!(
        env.token_amount(env.vault),
        3 * DEPOSIT as u64,
        "the three deposits are real token transfers, not bookkeeping"
    );

    // tag 6 x2 — L1 long LOT and L2 long LOT, both against S.
    env.trade_asset_with_cu(ASSET, &l1_owner, l1, &s_owner, s, LOT as i128, PRICE, 0);
    env.trade_asset_with_cu(ASSET, &l2_owner, l2, &s_owner, s, LOT as i128, PRICE, 0);
    let opened = asset_state(&env);
    assert_eq!(opened.oi_eff_long_q, 2 * LOT);
    assert_eq!(opened.oi_eff_short_q, 2 * LOT);
    assert_eq!(opened.loss_weight_sum_long, 2 * LEG_WEIGHT);
    assert_eq!(opened.stored_pos_count_long, 2);
    assert_eq!(opened.stored_pos_count_short, 1);
    assert_eq!(opened.lifecycle, AssetLifecycleV16::Active);

    // tag 40 — `ASSET_ACTION_SHUTDOWN` is the ONLY wrapper route to
    // `force_asset_recovery_not_atomic` (`src/v16_program.rs:15400`).
    env.svm.warp_to_slot(SHUTDOWN_SLOT);
    env.update_asset_lifecycle_as_admin_with_cu(
        processor::ASSET_ACTION_SHUTDOWN,
        ASSET,
        SHUTDOWN_SLOT,
        0,
    );
    let recovered = asset_state(&env);
    assert_eq!(
        recovered.lifecycle,
        AssetLifecycleV16::Recovery,
        "tag 40 must drive the ASSET into Recovery"
    );
    assert_eq!(
        env.market_state().1.mode,
        MarketModeV16::Live,
        "while the MARKET is still Live — asset lifecycle and market mode are independent"
    );

    // tag 43 — L1's owner-signed dead-leg forfeit. On a Recovery asset whose opposite side still
    // holds a real position, `retain_recovery_loss_weight_before_detach`
    // (`percolator:src/v16.rs:16855`) is TRUE, so the leg is PARKED, not detached.
    env.forfeit_recovery_leg_with_cu(&l1_owner, l1, ASSET, u128::MAX);
    let parked = asset_state(&env);
    assert_eq!(
        parked.pending_obligation_count_long, 1,
        "tag 43 must RETAIN the leg as a pending obligation, not detach it"
    );
    assert_eq!(
        parked.loss_weight_sum_long,
        2 * LEG_WEIGHT,
        "retention keeps the obligor's loss weight on the long side"
    );
    assert_eq!(parked.stored_pos_count_long, 2);
    let l1_leg = active_leg_for_asset(&env.portfolio_state(l1), ASSET as usize);
    assert!(l1_leg.active, "L1's leg is still stored after the forfeit");
    assert_eq!(l1_leg.basis_pos_q, 0, "and it is now zero-basis");
    assert_eq!(l1_leg.loss_weight, LEG_WEIGHT, "and still carries weight");

    // tag 19 — the group resolves. `resolve_market_not_atomic`
    // (`percolator:src/v16.rs:20529-20542`) never touches per-asset lifecycle.
    env.resolve();
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
    assert_eq!(
        asset_state(&env).lifecycle,
        AssetLifecycleV16::Recovery,
        "THE REACHABILITY: a Recovery asset survives inside a Resolved market"
    );

    (
        env,
        Actors {
            l1_owner,
            l1,
            l2_owner,
            l2,
            s_owner,
            s,
        },
    )
}

/// Asserts the exact on-chain state the gate keys on, and that nothing ELSE could explain a
/// refusal. Returns L1's leg as read from the portfolio account.
fn non_vacuity(env: &V16CuEnv, a: &Actors) -> PortfolioLegV16 {
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
    let asset = asset_state(env);
    assert_eq!(
        asset.lifecycle,
        AssetLifecycleV16::Recovery,
        "vacuous unless the asset lifecycle is Recovery: \
         kernel_recovery_pending_obligation_release_allowed (percolator:src/v16.rs:1329) admits \
         unconditionally otherwise"
    );
    let (barrier_long, barrier_short) = barriers(env);
    assert_eq!(
        barrier_long, 0,
        "vacuous unless NO long barrier stands: the pre-existing guard at \
         percolator:src/v16.rs:21087 would refuse on its own and this would prove nothing"
    );
    assert_eq!(barrier_short, 0, "and none on the short side either");
    let account = env.portfolio_state(a.l1);
    let leg = active_leg_for_asset(&account, ASSET as usize);
    assert!(leg.active, "vacuous unless the obligor still holds its leg");
    assert_eq!(
        leg.basis_pos_q, 0,
        "vacuous unless the leg is zero-basis — the first conjunct of the gate"
    );
    assert_eq!(
        leg.loss_weight, LEG_WEIGHT,
        "vacuous unless the leg still carries loss weight — the second conjunct"
    );
    assert!(!leg.b_stale && !leg.stale, "the leg is settled and fresh");
    assert_eq!(
        account.pnl, 0,
        "the obligor is solvent, so detach_solvent_active_legs_for_resolved_close \
         (percolator:src/v16.rs:21063) does not bail before reaching the per-leg walk"
    );
    assert_ne!(
        asset.stored_pos_count_short, asset.pending_obligation_count_short,
        "vacuous unless the OPPOSITE side carries REAL positions: \
         kernel_recovery_pending_obligation_release_allowed (:1337-1338) would otherwise admit"
    );
    leg
}

// =================================================================================================
// (a) THE DISCRIMINATOR — RED against the unpatched engine, GREEN against the patched one.
// =================================================================================================

/// L1's tag-30 `CloseResolved`, executed against the real program, must not release the parked
/// obligation while S still holds a real short. Without hunk (d) the walk reaches the
/// `close_q == 0` branch (`percolator:src/v16.rs:21132`), detaches through
/// `clear_leg_at_slot_inner(.., Some(0))` (`:21136`), and `kernel_clear_leg` (`:1412`) decrements
/// `pending_obligation_count_long` (`:1462`) and subtracts the leg's weight from
/// `loss_weight_sum_long` (`:1476`) — and the obligor is paid its full deposit out of the vault,
/// leaving L2 carrying 100% of the long side's loss weight instead of 50%.
#[test]
fn e2e_resolved_close_must_not_release_a_gated_recovery_obligation() {
    let (mut env, a) = drive_to_the_parked_obligation();
    let leg = non_vacuity(&env, &a);
    let before = asset_state(&env);
    let group_before = env.market_state().1;
    let vault_tokens_before = env.token_amount(env.vault);
    let l1_capital_before = env.portfolio_state(a.l1).capital;

    // The gate's own predicate, spelled out against the real market account.
    assert_eq!(before.stored_pos_count_short, 1);
    assert_eq!(before.pending_obligation_count_short, 0);
    assert_eq!(before.pending_obligation_count_long, 1);
    assert_eq!(before.loss_weight_sum_long, 2 * LEG_WEIGHT);
    assert_eq!(before.stored_pos_count_long, 2);
    // `loss_weight_sum_long` is the denominator the NEXT socialized loss is split by, and it is
    // exactly these two halves. Releasing L1 leaves L2 carrying 100% of it instead of 50%.
    assert_eq!(leg.loss_weight, LEG_WEIGHT);
    assert_eq!(
        active_leg_for_asset(&env.portfolio_state(a.l2), ASSET as usize).loss_weight,
        LEG_WEIGHT
    );
    assert_eq!(l1_capital_before, DEPOSIT);
    assert_eq!(vault_tokens_before, 3 * DEPOSIT as u64);

    // ---- the call under test: wrapper tag 30, a real signed transaction ----
    let (dest, result) = env.close_resolved_owner_signed_with_cu(&a.l1_owner, a.l1);
    assert!(
        result.is_ok(),
        "the gated close must be a no-progress SUCCESS, not a revert: {result:?}"
    );

    // ---- THE OBSERVABLE, read back out of the market account ----
    let after = asset_state(&env);
    assert_eq!(
        after.pending_obligation_count_long, 1,
        "kernel_clear_leg (percolator:src/v16.rs:1462) decremented pending_obligation_count_long \
         for a zero-basis obligation whose side had not earned release"
    );
    assert_eq!(
        after.loss_weight_sum_long,
        2 * LEG_WEIGHT,
        "kernel_clear_leg (percolator:src/v16.rs:1476) subtracted the obligor's loss_weight from \
         loss_weight_sum_long, shifting its share of the next socialized loss onto L2"
    );
    assert_eq!(after.stored_pos_count_long, 2);
    assert_eq!(
        active_leg_for_asset(&env.portfolio_state(a.l2), ASSET as usize).loss_weight * 2,
        after.loss_weight_sum_long,
        "L2 must still bear exactly half the long side's loss weight, not all of it"
    );
    assert_eq!(
        after.oi_eff_short_q, before.oi_eff_short_q,
        "the opposite side is untouched"
    );

    // ---- and it was a clean refusal, not a partial mutation ----
    let l1_after = env.portfolio_state(a.l1);
    let leg_after = active_leg_for_asset(&l1_after, ASSET as usize);
    assert!(leg_after.active, "the obligation leg is still stored");
    assert_eq!(leg_after.basis_pos_q, leg.basis_pos_q);
    assert_eq!(leg_after.loss_weight, leg.loss_weight);
    assert_eq!(
        l1_after.capital, DEPOSIT,
        "the obligor's capital was not released ahead of the loss it still owes"
    );
    assert_eq!(
        env.market_state().1.vault,
        group_before.vault,
        "and the market's vault accounting owes no transfer for the refused close"
    );

    // ---- THE MONEY: no tokens moved ----
    assert_eq!(
        env.token_amount(dest),
        0,
        "NO TOKENS may reach the obligor's destination account on a gated close"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_tokens_before,
        "and the vault's real SPL balance is untouched"
    );

    // ---- idempotent: repeating it neither progresses nor corrupts ----
    for round in 0..3 {
        let (dest_again, result_again) = env.close_resolved_owner_signed_with_cu(&a.l1_owner, a.l1);
        assert!(result_again.is_ok(), "round {round}: {result_again:?}");
        assert_eq!(env.token_amount(dest_again), 0, "round {round}");
        assert_eq!(
            asset_state(&env).pending_obligation_count_long,
            1,
            "round {round}"
        );
        assert_eq!(
            asset_state(&env).loss_weight_sum_long,
            2 * LEG_WEIGHT,
            "round {round}"
        );
        assert_eq!(
            env.token_amount(env.vault),
            vault_tokens_before,
            "round {round}"
        );
    }
}

// =================================================================================================
// (b) THE LIVENESS HALF — the refusal has a production exit, at the program level.
// =================================================================================================

/// The gate is a wait, not a brick. S and L2 carry real basis, so the new conjunct never applies to
/// them and they exit through the very same tag 30. Once they are gone the release condition is met
/// and L1's NEXT tag-30 call completes and pays out — with no lifecycle change and no admin action.
#[test]
fn e2e_gated_obligation_releases_once_the_opposite_side_has_cleared() {
    let (mut env, a) = drive_to_the_parked_obligation();
    non_vacuity(&env, &a);

    // NOTE: this test deliberately does NOT re-assert (a)'s refusal first. Its job is to prove
    // the fix is not a brick, and it must therefore pass on BOTH trees — on the unpatched tree
    // L1 is simply not gated, so an L1 close here would succeed early and the rest of this
    // scenario would be unreachable. (a) is the only discriminator; this is the liveness proof.

    // L2 and S close through tag 30. Neither is gated: both legs carry non-zero basis.
    let (l2_dest, l2_result) = env.close_resolved_owner_signed_with_cu(&a.l2_owner, a.l2);
    assert!(l2_result.is_ok(), "L2's close: {l2_result:?}");
    assert_eq!(
        env.token_amount(l2_dest),
        DEPOSIT as u64,
        "L2 is paid in full"
    );
    let (s_dest, s_result) = env.close_resolved_owner_signed_with_cu(&a.s_owner, a.s);
    assert!(s_result.is_ok(), "S's close: {s_result:?}");
    assert_eq!(
        env.token_amount(s_dest),
        DEPOSIT as u64,
        "S is paid in full"
    );

    // The release condition is now met on the long side's opposite (short) side.
    let mid = asset_state(&env);
    assert_eq!(
        (
            mid.stored_pos_count_short,
            mid.pending_obligation_count_short
        ),
        (0, 0),
        "the opposite side is empty, so the obligation has earned its release"
    );
    assert_eq!(mid.pending_obligation_count_long, 1, "still parked");
    assert_eq!(
        mid.loss_weight_sum_long, LEG_WEIGHT,
        "only the obligor's own weight is left on the side"
    );
    assert_eq!(
        mid.lifecycle,
        AssetLifecycleV16::Recovery,
        "and it was reached with NO lifecycle change — the liveness needs no admin action"
    );
    assert_eq!(
        env.token_amount(env.vault),
        DEPOSIT as u64,
        "only L1's deposit is left in the vault"
    );

    // ---- and the call that (a) proves is refused in this very state now completes, first try ----
    let (l1_dest, l1_result) = env.close_resolved_owner_signed_with_cu(&a.l1_owner, a.l1);
    assert!(l1_result.is_ok(), "L1's released close: {l1_result:?}");
    assert_eq!(
        env.token_amount(l1_dest),
        DEPOSIT as u64,
        "LIVENESS: the gate must release the obligation, and pay it, once the opposite side clears"
    );
    let after = asset_state(&env);
    assert_eq!(after.pending_obligation_count_long, 0);
    assert_eq!(after.loss_weight_sum_long, 0);
    assert_eq!(after.stored_pos_count_long, 0);
    assert!(!has_active_leg_for_asset(
        &env.portfolio_state(a.l1),
        ASSET as usize
    ));
    assert_eq!(env.portfolio_state(a.l1).capital, 0);
    assert_eq!(
        env.token_amount(env.vault),
        0,
        "the vault is fully drained — nothing is stranded by the gate"
    );
}

// =================================================================================================
// (c) THE NARROWNESS CONTROL — the gate does not refuse ordinary legs.
// =================================================================================================

/// L2 sits on the SAME Recovery asset, in the SAME Resolved market, with the SAME opposite-side
/// state that refuses L1 in (a) — but its leg carries real basis, so its tag-30 close must still
/// complete in ONE call and pay out. Without this control, (a) would be satisfied by a blanket
/// refusal of every resolved close on a Recovery asset.
#[test]
fn e2e_an_ordinary_leg_on_the_same_recovery_asset_still_closes_in_one_call() {
    let (mut env, a) = drive_to_the_parked_obligation();
    non_vacuity(&env, &a);

    let l2_leg = active_leg_for_asset(&env.portfolio_state(a.l2), ASSET as usize);
    assert!(l2_leg.active);
    assert_ne!(
        l2_leg.basis_pos_q, 0,
        "vacuous unless L2's leg carries real basis — that is the only difference from (a)"
    );
    let before = asset_state(&env);
    assert_ne!(
        before.stored_pos_count_short, before.pending_obligation_count_short,
        "the opposite-side state is the one that refuses L1 in (a)"
    );
    let vault_before = env.token_amount(env.vault);

    let (dest, result) = env.close_resolved_owner_signed_with_cu(&a.l2_owner, a.l2);
    assert!(result.is_ok(), "L2's close must succeed: {result:?}");
    assert_eq!(
        env.token_amount(dest),
        DEPOSIT as u64,
        "an ordinary leg must not be caught by the gate — it closes in ONE call and is paid"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before - DEPOSIT as u64,
        "and the tokens came out of the vault"
    );

    let after = asset_state(&env);
    assert!(!has_active_leg_for_asset(
        &env.portfolio_state(a.l2),
        ASSET as usize
    ));
    assert_eq!(after.stored_pos_count_long, 1);
    assert_eq!(
        after.loss_weight_sum_long, LEG_WEIGHT,
        "L2's own weight left the side; the obligor's did not"
    );
    assert_eq!(
        after.pending_obligation_count_long, 1,
        "and the parked obligation is untouched by L2's close"
    );
}
