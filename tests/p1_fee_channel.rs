// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P1 <-> P2 matcher call extension + fee-request channel on TradeCpi, driven through the REAL
//! wrapper BPF (`target/deploy/percolator_prog.so`, built `cargo build-sbf -- --features devnet`)
//! and the REAL P2 matcher BPF (`dcccrypto/percolator-match` `feat/p2-matcher-v2` @ 4a0f696,
//! plain `cargo build-sbf`) in LiteSVM. Legacy compatibility is also run against the deployed
//! v1 matcher (12bd671).
//!
//! Matcher .so paths (relative to this crate's parent directory, override with env):
//!   P2: `../percolator-match-p2/target/deploy/percolator_match.so`   (`P2_MATCHER_SO`)
//!   v1: `../percolator-match/target/deploy/percolator_match.so`      (`V1_MATCHER_SO`)
//!
//! ABI: `~/percolator-ops/ledger/p1-p2-matcher-call-extension-abi-2026-09-30.md`.
//! Wrapper side: `risk_limits_v17::{encode_matcher_call_ext, requested_fee_permitted,
//! allocate_fee_with_lp_request}`, the TradeCpi handler's `requested_fee_bps` /
//! `accepts_fee_request`, and the executor's `lp_requested_fee_bps` / `lp_fee_credit`.
//!
//! Every expected fee is computed here independently with the engine's rounding
//! (`trade_fee_notional_ceil` then `checked_fee_bps`, both ceil):
//!   fee(size, price, bps) = ceil(ceil(size * price / POS_SCALE) * bps / 10_000).
//! The four-way split of an amount uses the wrapper's `policy_v16::split_trade_fee` at the
//! default shares (the split itself is not what is under test; its INPUT is).
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{ix::Instruction as ProgInstruction, policy_v16, state};
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

const MATCHER_CONTEXT_LEN: usize = 320;
const Q: i128 = POS_SCALE as i128;
/// Off-grid price so the size*price and spread roundings are all exercised (not integer bps).
const PRICE_ODD: u64 = 1_234_567;
/// $1.00 -- every band / spread boundary in bps is an integer atom at this price.
const PRICE_ONE: u64 = 1_000_000;
/// Market base trading fee (bps).
const BASE_BPS: u64 = 10;

/// `PercolatorError::InvalidInstruction` (enum index 9).
const ERR_INVALID_INSTRUCTION: &str = "Custom(9)";
/// `PercolatorError::ExecPriceOutsideOracleBand`.
const ERR_BAND: &str = "Custom(66)";
/// P2 matcher `ERR_STALE_MARK`.
const ERR_STALE_MARK: &str = "Custom(8002)";

const PROTOCOL_FEE_BPS: u16 = 2000;
const CREATOR_SHARE_BPS: u16 = 1600;
const LP_SHARE_BPS: u16 = 4800;
const INSURANCE_SHARE_BPS: u16 = 1600;

const RET_REQUESTED_FEE_SHIFT: u32 = 22;
const RET_REQUESTED_FEE_MASK: u32 = 0x3ff << RET_REQUESTED_FEE_SHIFT;

fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("P1_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {path:?}; run cargo build-sbf -- --features devnet"
    );
    path
}

fn sibling_so(env_var: &str, dir: &str) -> PathBuf {
    if let Some(p) = std::env::var_os(env_var) {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push(dir);
    path.push("target/deploy/percolator_match.so");
    assert!(path.exists(), "matcher BPF not found at {path:?}");
    path
}

fn p2_matcher_path() -> PathBuf {
    sibling_so("P2_MATCHER_SO", "percolator-match-p2")
}

fn v1_matcher_path() -> PathBuf {
    sibling_so("V1_MATCHER_SO", "percolator-match")
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

fn assert_err_code(r: &Result<u64, String>, code: &str, what: &str) {
    match r {
        Err(e) => assert!(
            e.contains(&format!("InstructionError(2, {code})")),
            "{what}: expected InstructionError(2, {code}), got {e}"
        ),
        Ok(_) => panic!("{what}: expected InstructionError(2, {code}), got Ok"),
    }
}

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

// ── independent expected-value arithmetic (engine rounding) ─────────────────────────────

fn div_ceil(n: u128, d: u128) -> u128 {
    n.div_ceil(d)
}

/// Engine fee: ceil(ceil(|size| * price / POS_SCALE) * bps / 10_000).
fn engine_fee(size_abs: u128, price: u64, bps: u64) -> u128 {
    if size_abs == 0 || bps == 0 {
        return 0;
    }
    let notional = div_ceil(size_abs * price as u128, POS_SCALE);
    div_ceil(notional * bps as u128, 10_000)
}

/// P2 kind-0 price at `total_bps` (ceil on the ask, floor on the bid: LP-favourable).
fn passive_price(oracle: u64, total_bps: u128, taker_buys: bool) -> u64 {
    let o = oracle as u128;
    (if taker_buys {
        div_ceil(o * (10_000 + total_bps), 10_000)
    } else {
        o * (10_000 - total_bps) / 10_000
    }) as u64
}

/// The P2 request: ceil(|exec - oracle| * 1e4 / oracle), capped at 1023.
fn requested_bps(oracle: u64, exec: u64) -> u64 {
    let d = (exec as u128).abs_diff(oracle as u128);
    div_ceil(d * 10_000, oracle as u128).min(1023) as u64
}

fn split(fee: u128) -> policy_v16::FeeSplitParts {
    policy_v16::split_trade_fee(
        fee,
        PROTOCOL_FEE_BPS,
        CREATOR_SHARE_BPS,
        LP_SHARE_BPS,
        INSURANCE_SHARE_BPS,
    )
    .unwrap()
}

// ── fixture ──────────────────────────────────────────────────────────────────────────────

struct Lp {
    account: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

#[derive(Clone, Copy)]
struct MatcherParams {
    kind: u8,
    trading_fee_bps: u32,
    base_spread_bps: u32,
    max_total_bps: u32,
    impact_k_bps: u32,
    liquidity_notional_e6: u128,
}

impl MatcherParams {
    fn passive(spread_bps: u32, max_total_bps: u32) -> Self {
        Self {
            kind: 0,
            trading_fee_bps: 0,
            base_spread_bps: spread_bps,
            max_total_bps,
            impact_k_bps: 0,
            liquidity_notional_e6: 0,
        }
    }
}

/// The 64-byte matcher return the P2/v1 matcher left in its context (bytes 0..64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CtxReturn {
    flags: u32,
    exec_price: u64,
    exec_size: i128,
    req_id: u64,
}

impl CtxReturn {
    fn requested_fee_bits(&self) -> u32 {
        (self.flags & RET_REQUESTED_FEE_MASK) >> RET_REQUESTED_FEE_SHIFT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Money {
    taker_capital: u128,
    lp_capital: u128,
    protocol: u128,
    lp_vault: u128,
    insurance_reserve: u128,
    creator: u128,
    header_insurance: u128,
    header_vault: u128,
    c_tot: u128,
    spl_vault: u64,
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    matcher_program: Pubkey,
    upgrade_authority: Keypair,
    program_data: Pubkey,
    portfolio_account_len: usize,
}

impl Env {
    fn new(matcher_so: PathBuf, price: u64, trade_fee_base_bps: u64) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(
            program_id,
            &std::fs::read(program_path()).expect("read wrapper BPF"),
        );
        svm.add_program(
            spl_token::ID,
            &std::fs::read(spl_token_program_path()).expect("read token BPF"),
        );
        let matcher_program = Pubkey::new_unique();
        svm.add_program(
            matcher_program,
            &std::fs::read(&matcher_so).expect("read matcher BPF"),
        );

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let vault_authority =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id).0;
        let vault = canonical_vault_ata(&vault_authority, &mint);
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();
        let acct = |data: Vec<u8>, owner: Pubkey| Account {
            lamports: 1_000_000_000,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        };
        svm.set_account(mint, acct(make_mint_data(), spl_token::ID))
            .unwrap();
        svm.set_account(
            vault,
            acct(make_token_data(mint, vault_authority, 0), spl_token::ID),
        )
        .unwrap();
        svm.set_account(
            market,
            acct(
                vec![0u8; state::market_account_len_for_capacity(1).unwrap()],
                program_id,
            ),
        )
        .unwrap();

        let mut env = Self {
            svm,
            program_id,
            payer,
            market,
            mint,
            vault,
            matcher_program,
            upgrade_authority: Keypair::new(),
            program_data: Pubkey::default(),
            portfolio_account_len: state::portfolio_account_len_for_market_slots(1).unwrap(),
        };
        env.send(
            ProgInstruction::InitMarket {
                max_portfolio_assets: 1,
                h_min: 0,
                h_max: 10,
                initial_price: price,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps: 10_000,
                initial_margin_bps: 10_000,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps,
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
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin],
        )
        .expect("init market");

        // ProgramData mock for the tag-93 upgrade-authority gate (same 45-byte layout the
        // tag-85 test in tests/v16_cu.rs uses).
        let ua = env.upgrade_authority.insecure_clone();
        env.svm.airdrop(&ua.pubkey(), 1_000_000_000).unwrap();
        let (program_data, _) = Pubkey::find_program_address(
            &[program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        );
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(ua.pubkey().as_ref());
        env.svm
            .set_account(
                program_data,
                acct(pd, solana_sdk::bpf_loader_upgradeable::id()),
            )
            .unwrap();
        env.program_data = program_data;
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
        self.svm.expire_blockhash();
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
        self.svm
            .send_transaction(tx)
            .map(|meta| meta.compute_units_consumed)
            .map_err(|e| format!("{e:?}"))
    }

    fn portfolio(&mut self, owner: &Keypair, deposit: u128) -> Pubkey {
        let portfolio = Pubkey::new_unique();
        if self.svm.get_balance(&owner.pubkey()).unwrap_or(0) == 0 {
            self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        }
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
        if deposit > 0 {
            let source = Pubkey::new_unique();
            self.svm
                .set_account(
                    source,
                    Account {
                        lamports: 1_000_000_000,
                        data: make_token_data(self.mint, owner.pubkey(), deposit as u64),
                        owner: spl_token::ID,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
            let (market, vault) = (self.market, self.vault);
            self.send(
                ProgInstruction::Deposit {
                    portfolio_id,
                    expected_sequence,
                    amount: deposit,
                },
                vec![
                    AccountMeta::new(owner.pubkey(), true),
                    AccountMeta::new(market, false),
                    AccountMeta::new(portfolio, false),
                    AccountMeta::new(source, false),
                    AccountMeta::new(vault, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
                &[owner],
            )
            .expect("deposit");
        }
        portfolio
    }

    fn identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    fn market_id(&self) -> u64 {
        state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, 0)
            .unwrap()
            .3
    }

    /// LP portfolio with `deposit` atoms, registered (SetMatcherConfig + wrapper tag 83
    /// InitMatcherCtx) with a context of the given kind/params on this env's matcher program.
    fn lp(&mut self, deposit: u128, m: MatcherParams) -> Lp {
        let owner = Keypair::new();
        let account = self.portfolio(&owner, deposit);
        let ctx = Pubkey::new_unique();
        let delegate = matcher_delegate_key(
            &self.program_id,
            &self.market,
            &account,
            &owner.pubkey(),
            &self.matcher_program,
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
                    owner: self.matcher_program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let (portfolio_id, expected_sequence, _) = self.identity(account);
        let asset_generation_frontier = state::read_market_asset_generation_frontier(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
        let (mp, market) = (self.matcher_program, self.market);
        self.send(
            ProgInstruction::SetMatcherConfig {
                portfolio_id,
                expected_sequence,
                asset_generation_frontier,
                enabled: 1,
                trade_fee_cap_bps: 10_000,
                expiry_slot: u64::MAX,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new_readonly(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[&owner],
        )
        .expect("set matcher config");
        self.send(
            ProgInstruction::InitMatcherCtx {
                kind: m.kind,
                trading_fee_bps: m.trading_fee_bps,
                base_spread_bps: m.base_spread_bps,
                max_total_bps: m.max_total_bps,
                impact_k_bps: m.impact_k_bps,
                liquidity_notional_e6: m.liquidity_notional_e6,
                max_fill_abs: u128::MAX,
                max_inventory_abs: 0,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(account, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[&owner],
        )
        .expect("init matcher ctx");
        Lp {
            account,
            ctx,
            delegate,
        }
    }

    fn trade_cpi(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp: &Lp,
        size_q: i128,
        fee_bps: u64,
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.identity(lp.account);
        let market_id = self.market_id();
        let (mp, market) = (self.matcher_program, self.market);
        self.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id,
                account_b_matcher_sequence: b_seq,
                asset_index: 0,
                size_q,
                fee_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp.account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[taker],
        )
    }

    /// BatchTradeCpi (single asset 0 legs), taker-signed base fee per leg.
    fn batch_cpi(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp: &Lp,
        sizes: &[i128],
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.identity(lp.account);
        let market_id = self.market_id();
        let (mp, market) = (self.matcher_program, self.market);
        let legs = sizes
            .iter()
            .map(|s| percolator_prog::ix::BatchTradeCpiLeg {
                asset_index: 0,
                market_id,
                size_q: *s,
                fee_bps: BASE_BPS,
                limit_price: 0,
            })
            .collect();
        self.send(
            ProgInstruction::BatchTradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                account_b_matcher_sequence: b_seq,
                max_slippage_atoms: u128::MAX,
                max_fee_atoms: u128::MAX,
                legs,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp.account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[taker],
        )
    }

    /// Tag 93 SetAssetRiskLimits (upgrade-authority signed): band, P2 ext mode, fee max.
    fn set_limits(&mut self, exec_band_bps: u16, matcher_ext_mode: u8, max_requested_fee_bps: u16) {
        let ua = self.upgrade_authority.insecure_clone();
        let (pd, market) = (self.program_data, self.market);
        self.send(
            ProgInstruction::SetAssetRiskLimits {
                asset_index: 0,
                exec_band_bps,
                lp_exposure_k_bps: 0,
                lp_floor_atoms: 0,
                side_oi_cap_q: 0,
                matcher_ext_mode,
                max_requested_fee_bps,
            },
            vec![
                AccountMeta::new(ua.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[&ua],
        )
        .expect("tag 93 SetAssetRiskLimits");
        let stored =
            state::read_asset_risk_limits(&self.svm.get_account(&self.market).unwrap().data, 0)
                .unwrap();
        assert_eq!(stored.exec_band_bps, exec_band_bps);
        assert_eq!(stored.matcher_ext_mode, matcher_ext_mode);
        assert_eq!(stored.max_requested_fee_bps, max_requested_fee_bps);
    }

    fn ctx_return(&self, lp: &Lp) -> CtxReturn {
        let d = self.svm.get_account(&lp.ctx).unwrap().data;
        CtxReturn {
            flags: u32::from_le_bytes(d[4..8].try_into().unwrap()),
            exec_price: u64::from_le_bytes(d[8..16].try_into().unwrap()),
            exec_size: i128::from_le_bytes(d[16..32].try_into().unwrap()),
            req_id: u64::from_le_bytes(d[32..40].try_into().unwrap()),
        }
    }

    fn capital(&self, portfolio: Pubkey) -> u128 {
        state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data)
            .unwrap()
            .capital
    }

    fn pos(&self, portfolio: Pubkey) -> i128 {
        let p = state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data).unwrap();
        p.legs
            .iter()
            .find(|l| l.active && l.asset_index == 0)
            .map(|l| match l.side {
                SideV16::Long => l.basis_pos_q.unsigned_abs() as i128,
                SideV16::Short => -(l.basis_pos_q.unsigned_abs() as i128),
            })
            .unwrap_or(0)
    }

    fn money(&self, taker: Pubkey, lp: &Lp) -> Money {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&data).unwrap();
        let p0 = state::read_asset_oracle_profile(&data, 0).unwrap();
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        let spl_vault = TokenAccount::unpack(&self.svm.get_account(&self.vault).unwrap().data)
            .unwrap()
            .amount;
        Money {
            taker_capital: self.capital(taker),
            lp_capital: self.capital(lp.account),
            protocol: cfg.protocol_fee_accrued_atoms,
            lp_vault: cfg.lp_fee_accrued_atoms,
            insurance_reserve: cfg.insurance_reserve_accrued_atoms,
            creator: p0.creator_fee_claimable_atoms as u128,
            header_insurance: group.header.insurance.get(),
            header_vault: group.header.vault.get(),
            c_tot: group.header.c_tot.get(),
            spl_vault,
        }
    }

    fn snapshot(&self, keys: &[Pubkey]) -> Vec<Vec<u8>> {
        keys.iter()
            .map(|k| self.svm.get_account(k).unwrap().data)
            .collect()
    }

    fn slot(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().slot
    }

    fn last_good_oracle_slot(&self) -> u64 {
        state::read_asset_oracle_profile(&self.svm.get_account(&self.market).unwrap().data, 0)
            .unwrap()
            .last_good_oracle_slot
    }
}

/// Assert one filled TradeCpi moved money exactly as the fee channel specifies.
/// `total` = what the engine charged the taker, `base` = the base-rate part, `lp_credit` =
/// `total - base` credited to the LP from the insurance pool the fee just landed in.
fn assert_fee_legs(before: &Money, after: &Money, total: u128, base: u128, what: &str) {
    let lp_credit = total - base;
    let s = split(base);
    assert_eq!(
        before.taker_capital - after.taker_capital,
        total,
        "{what}: taker capital decreases by base + requested (engine ceil)"
    );
    assert_eq!(
        after.lp_capital - before.lp_capital,
        lp_credit,
        "{what}: LP capital increases by exactly the requested part"
    );
    assert_eq!(
        after.protocol - before.protocol,
        s.protocol,
        "{what}: protocol leg"
    );
    assert_eq!(
        after.lp_vault - before.lp_vault,
        s.lp,
        "{what}: LP-vault leg"
    );
    assert_eq!(
        after.insurance_reserve - before.insurance_reserve,
        s.insurance,
        "{what}: insurance-reserve leg"
    );
    assert_eq!(
        after.creator - before.creator,
        s.creator,
        "{what}: creator leg"
    );
    assert_eq!(
        s.protocol + s.lp + s.insurance + s.creator,
        base,
        "{what}: the four legs sum to the BASE fee only"
    );
    // Conservation: no token moved; the base fee sits in the insurance pool (backing the four
    // accrued legs), the requested part went back out of it into the LP's capital.
    assert_eq!(
        after.spl_vault, before.spl_vault,
        "{what}: SPL vault unchanged"
    );
    assert_eq!(
        after.header_vault, before.header_vault,
        "{what}: engine vault unchanged"
    );
    assert_eq!(
        after.header_insurance - before.header_insurance,
        base,
        "{what}: insurance pool nets exactly the base fee"
    );
    assert_eq!(
        before.c_tot - after.c_tot,
        base,
        "{what}: c_tot falls by exactly the base fee (total out of taker, requested into LP)"
    );
    assert_eq!(
        after.c_tot + after.header_insurance,
        before.c_tot + before.header_insurance,
        "{what}: c_tot + insurance conserved"
    );
}

fn setup(
    matcher_so: PathBuf,
    price: u64,
    base_bps: u64,
    m: MatcherParams,
) -> (Env, Keypair, Pubkey, Lp) {
    let mut env = Env::new(matcher_so, price, base_bps);
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000_000);
    let lp = env.lp(1_000_000_000, m);
    (env, taker, taker_account, lp)
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 1. matcher_ext_mode = 1, max_requested_fee_bps = 0: channel OFF.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_fee_channel_off_fills_without_request_bits_and_splits_base_fee_like_legacy() {
    let spread = 30u32;
    let size = 10 * Q + 3; // off-grid size: exercises both ceilings
    let run = |mode: u8| {
        let (mut env, taker, ta, lp) = setup(
            p2_matcher_path(),
            PRICE_ODD,
            BASE_BPS,
            MatcherParams::passive(spread, 100),
        );
        env.set_limits(0, mode, 0);
        let before = env.money(ta, &lp);
        env.trade_cpi(&taker, ta, &lp, size, BASE_BPS)
            .unwrap_or_else(|e| panic!("mode {mode}: channel-off TradeCpi must fill: {e}"));
        let after = env.money(ta, &lp);
        let ret = env.ctx_return(&lp);
        assert_eq!(env.pos(ta), size, "mode {mode}: taker filled in full");
        (before, after, ret)
    };
    let (b1, a1, ret1) = run(1);
    let (b0, a0, ret0) = run(0);

    // Proof of life: the P2 matcher really quoted the spread (it is priced at oracle+30bps)...
    let exec = passive_price(PRICE_ODD, spread as u128, true);
    assert_eq!(ret1.exec_price, exec, "P2 kind-0 ask = ceil(o*(1+30bps))");
    assert_eq!(ret1.exec_size, size);
    assert_eq!(
        requested_bps(PRICE_ODD, exec),
        31,
        "fixture: the quote WOULD request 31 bps"
    );
    // ...but without ACCEPTS_FEE_REQUEST the bits 22..31 are never set.
    assert_eq!(
        ret1.requested_fee_bits(),
        0,
        "channel off: requested-fee bits never set"
    );
    assert_eq!(
        ret0.requested_fee_bits(),
        0,
        "legacy: requested-fee bits never set"
    );
    assert_eq!(
        ret1.exec_price, ret0.exec_price,
        "same quote with/without the extension"
    );

    // The four-way split gets exactly the base fee; the LP gets nothing extra.
    let base = engine_fee(size.unsigned_abs(), PRICE_ODD, BASE_BPS);
    assert!(base > 0);
    assert_fee_legs(&b1, &a1, base, base, "mode 1 channel off");
    assert_fee_legs(&b0, &a0, base, base, "mode 0 legacy");
    // Byte-for-byte the same money movement as legacy.
    let delta = |b: &Money, a: &Money| {
        (
            b.taker_capital - a.taker_capital,
            a.lp_capital - b.lp_capital,
            a.protocol - b.protocol,
            a.lp_vault - b.lp_vault,
            a.insurance_reserve - b.insurance_reserve,
            a.creator - b.creator,
        )
    };
    assert_eq!(
        delta(&b1, &a1),
        delta(&b0, &a0),
        "channel off == legacy, leg by leg"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 2. Channel ON: matcher quote -> requested fee -> LP capital, base -> four-way split.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_fee_channel_on_charges_requested_fee_to_taker_and_credits_lp_exactly() {
    let spread = 30u32;
    let size = 10 * Q + 3;
    let (mut env, taker, ta, lp) = setup(
        p2_matcher_path(),
        PRICE_ODD,
        BASE_BPS,
        MatcherParams::passive(spread, 100),
    );
    env.set_limits(0, 1, 100);

    // Open (taker buys): ask = ceil(o*(1+30bps)) -> request 31 bps (ceil of 30.002).
    let exec_buy = passive_price(PRICE_ODD, spread as u128, true);
    let req_buy = requested_bps(PRICE_ODD, exec_buy);
    assert_eq!(req_buy, 31);
    let before = env.money(ta, &lp);
    env.trade_cpi(&taker, ta, &lp, size, BASE_BPS + req_buy)
        .expect("taker signs base + requested exactly: fills");
    let after = env.money(ta, &lp);
    let ret = env.ctx_return(&lp);
    assert_eq!(ret.exec_price, exec_buy, "matcher ask");
    assert_eq!(ret.exec_size, size, "full fill");
    assert_eq!(
        ret.requested_fee_bits() as u64,
        req_buy,
        "ACCEPTS_FEE_REQUEST sent: matcher returns ceil(|exec-o|*1e4/o) in bits 22..31"
    );
    assert_eq!(env.pos(ta), size);
    assert_eq!(env.pos(lp.account), -size);
    let total = engine_fee(size.unsigned_abs(), PRICE_ODD, BASE_BPS + req_buy);
    let base = engine_fee(size.unsigned_abs(), PRICE_ODD, BASE_BPS);
    assert!(
        total > base,
        "fixture: the request is economically non-zero"
    );
    assert_fee_legs(
        &before,
        &after,
        total,
        base,
        "open, fee_bps = base + requested",
    );

    // Close (taker sells), signing MORE than needed: the charge is base + requested, not the
    // taker's cap. Bid = floor(o*(1-30bps)) -> its own request.
    let exec_sell = passive_price(PRICE_ODD, spread as u128, false);
    let req_sell = requested_bps(PRICE_ODD, exec_sell);
    let before = env.money(ta, &lp);
    env.trade_cpi(&taker, ta, &lp, -size, BASE_BPS + req_sell + 500)
        .expect("taker signs above base + requested: fills");
    let after = env.money(ta, &lp);
    let ret = env.ctx_return(&lp);
    assert_eq!(ret.exec_price, exec_sell, "matcher bid");
    assert_eq!(ret.requested_fee_bits() as u64, req_sell);
    assert_eq!(env.pos(ta), 0, "taker flat");
    let total = engine_fee(size.unsigned_abs(), PRICE_ODD, BASE_BPS + req_sell);
    let base = engine_fee(size.unsigned_abs(), PRICE_ODD, BASE_BPS);
    assert_fee_legs(
        &before,
        &after,
        total,
        base,
        "close, fee_bps above base + requested",
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 3. Consent: taker-signed fee_bps < base + requested, or protocol max < request -> refused.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_fee_channel_refuses_without_taker_consent_or_above_protocol_max() {
    let spread = 30u32;
    let size = 10 * Q + 3;
    let (mut env, taker, ta, lp) = setup(
        p2_matcher_path(),
        PRICE_ODD,
        BASE_BPS,
        MatcherParams::passive(spread, 100),
    );
    let req = requested_bps(PRICE_ODD, passive_price(PRICE_ODD, spread as u128, true));
    assert_eq!(req, 31);
    let keys = [env.market, ta, lp.account, lp.ctx];

    // (a) taker signs one bps short of base + requested.
    env.set_limits(0, 1, 100);
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, ta, &lp, size, BASE_BPS + req - 1);
    assert_err_code(
        &r,
        ERR_INVALID_INSTRUCTION,
        "taker fee_bps < base + requested",
    );
    assert_eq!(
        env.snapshot(&keys),
        before,
        "refused: market, both portfolios, ctx untouched"
    );
    // Only the base fee signed (the legacy value) is refused too.
    let r = env.trade_cpi(&taker, ta, &lp, size, BASE_BPS);
    assert_err_code(&r, ERR_INVALID_INSTRUCTION, "taker fee_bps == base only");
    assert_eq!(env.snapshot(&keys), before);

    // (b) protocol max one below the request: refused even with a generous taker cap.
    env.set_limits(0, 1, (req - 1) as u16);
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, ta, &lp, size, 5_000);
    assert_err_code(&r, ERR_INVALID_INSTRUCTION, "protocol max < requested");
    assert_eq!(env.snapshot(&keys), before, "refused: nothing mutates");

    // Proof of life at the exact boundaries: protocol max == request, taker == base + request.
    env.set_limits(0, 1, req as u16);
    env.trade_cpi(&taker, ta, &lp, size, BASE_BPS + req)
        .expect("protocol max == request and taker == base + request: fills");
    assert_eq!(env.pos(ta), size);
    assert_eq!(env.ctx_return(&lp).requested_fee_bits() as u64, req);
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 4. EXEC_BAND: band narrower than the matcher's max spread -> the P2 matcher prices inside it.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_exec_band_kind0_clamps_spread_inside_wrapper_band() {
    // Kind 0 quoting 300 bps (max_total 400); wrapper band 100 bps.
    let m = MatcherParams::passive(300, 400);
    let size = 10 * Q;

    // Control: legacy bytes (mode 0) -- the matcher does not know the band -> Custom(66).
    let (mut env, taker, ta, lp) = setup(p2_matcher_path(), PRICE_ONE, 0, m);
    env.set_limits(100, 0, 0);
    let keys = [env.market, ta, lp.account];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, ta, &lp, size, 0);
    assert_err_code(
        &r,
        ERR_BAND,
        "mode 0: matcher quotes 300 bps into a 100 bps band",
    );
    assert_eq!(env.snapshot(&keys), before);

    // mode 1: EXEC_BAND = 100 -> kind 0 clamps its total at min(max_total, band) = 100 bps.
    env.set_limits(100, 1, 0);
    env.trade_cpi(&taker, ta, &lp, size, 0)
        .expect("mode 1: EXEC_BAND makes kind 0 clamp inside the band, no Custom(66)");
    let ret = env.ctx_return(&lp);
    println!("kind-0 EXEC_BAND return: {ret:?}");
    assert_eq!(
        ret.exec_price,
        passive_price(PRICE_ONE, 100, true),
        "clamped to exactly band"
    );
    assert_eq!(ret.exec_price, 1_010_000);
    assert_eq!(ret.exec_size, size, "kind 0 clamps PRICE, not size");
    assert_eq!(env.pos(ta), size);
    // Sell side as well.
    env.trade_cpi(&taker, ta, &lp, -size, 0)
        .expect("mode 1: bid side clamps inside the band");
    let ret = env.ctx_return(&lp);
    println!("kind-0 EXEC_BAND bid return: {ret:?}");
    assert_eq!(ret.exec_price, 990_000);
    assert_eq!(env.pos(ta), 0);
}

#[test]
fn p2_exec_band_kind2_clips_size_inside_wrapper_band() {
    // Kind 2 (adaptive): fee cold 10 bps + CP impact k=5000 bps on depth 100 units; max_total
    // 400. A 10-unit request needs > 400 bps; the wrapper band is 100 bps.
    let m = MatcherParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 0,
        max_total_bps: 400,
        impact_k_bps: 5_000,
        liquidity_notional_e6: 100_000_000,
    };
    let size = 10 * Q;

    // Control: legacy bytes -> kind 2 clips only to ITS max_total (400) -> Custom(66).
    let (mut env, taker, ta, lp) = setup(p2_matcher_path(), PRICE_ONE, 0, m);
    env.set_limits(100, 0, 0);
    let keys = [env.market, ta, lp.account];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, ta, &lp, size, 0);
    assert_err_code(
        &r,
        ERR_BAND,
        "mode 0: kind 2 prices up to 400 bps into a 100 bps band",
    );
    assert_eq!(env.snapshot(&keys), before);

    // mode 1: EXEC_BAND 100 -> kind 2 clips SIZE so the total stays <= 100 bps.
    env.set_limits(100, 1, 0);
    env.trade_cpi(&taker, ta, &lp, size, 0)
        .expect("mode 1: EXEC_BAND makes kind 2 clip size inside the band, no Custom(66)");
    let ret = env.ctx_return(&lp);
    println!("kind-2 EXEC_BAND return: {ret:?}");
    assert!(
        ret.exec_size > 0 && ret.exec_size < size,
        "partial fill: {ret:?}"
    );
    assert!(
        (ret.exec_price as u128 - PRICE_ONE as u128) * 10_000 <= PRICE_ONE as u128 * 100,
        "exec inside the 100 bps band: {ret:?}"
    );
    // Largest feasible fill: 10 (fee) + ceil(5000*N/(D-N)) <= 100 with N = fill (price 1.0).
    let d = 100_000_000u128;
    let impact = |n: u128| div_ceil(5_000 * n, d - n);
    let f = ret.exec_size as u128;
    assert!(
        10 + impact(f) <= 100 && 10 + impact(f + 1) > 100,
        "fill is the band-maximal size"
    );
    assert_eq!(
        env.pos(ta),
        ret.exec_size,
        "the wrapper booked exactly the clipped fill"
    );
}

/// FINDING (P2 matcher rounding vs P1 band check). At a price where `oracle * band / 1e4` is
/// not an integer, the P2 EXEC_BAND clamp prices AT the band with LP-favourable rounding
/// (ceil on the ask, floor on the bid), which lands 1 atom OUTSIDE the wrapper's inclusive
/// band check `|exec - o| * 1e4 <= o * band` -> Custom(66), the exact revert EXEC_BAND exists
/// to prevent. This test asserts the ABI doc's promise; it is RED against 4a0f696.
/// Sites: percolator-match `src/vamm.rs:856` (band clamp = min(max_total, band)) priced by
/// `compute_passive_execution` (ceil ask / floor bid) and, for kind 2, `src/v2.rs:696`
/// `price_with_total_bps` (same rounding); wrapper check `src/v16_program.rs:9268`
/// `exec_price_within_band` (inclusive). o=1_234_567, band 100: ask 1_246_913,
/// |ask-o|*1e4 = 123_460_000 > o*band = 123_456_700. Run with `-- --ignored`.
#[test]
fn p2_exec_band_kind0_clamp_stays_inside_band_at_off_grid_price() {
    let (mut env, taker, ta, lp) = setup(
        p2_matcher_path(),
        PRICE_ODD,
        0,
        MatcherParams::passive(300, 400),
    );
    env.set_limits(100, 1, 0);
    let ask = passive_price(PRICE_ODD, 100, true);
    println!(
        "o={PRICE_ODD} band=100: clamp ask={ask} |ask-o|*1e4={} o*band={}",
        (ask - PRICE_ODD) as u128 * 10_000,
        PRICE_ODD as u128 * 100
    );
    let r = env.trade_cpi(&taker, ta, &lp, 10 * Q, 0);
    println!(
        "TradeCpi result: {r:?}; ctx return: {:?}",
        env.ctx_return(&lp)
    );
    r.expect("EXEC_BAND promise: a banded wrapper gets a fill, never Custom(66)");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 5. TAKER_REDUCING (behavioural, P2 stale-mark path): under a stale mark a taker CLOSE
//    that grows the LP's |inventory| fills; a taker OPEN in the same LP direction -> 8002.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_taker_reducing_lets_taker_close_through_stale_mark_open_refused_8002() {
    // Kind 2 default v2 block: max_mark_age_slots = 150, STALE_ALLOW_REDUCING on.
    let m = MatcherParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 0,
        max_total_bps: 100,
        impact_k_bps: 0,
        liquidity_notional_e6: 0,
    };
    let (mut env, taker_a, a, lp) = setup(p2_matcher_path(), PRICE_ONE, 0, m);
    let taker_b = Keypair::new();
    let b = env.portfolio(&taker_b, 1_000_000_000);
    env.set_limits(0, 1, 0);

    // Shape the LP (fresh mark): A long 5, B short 10 -> LP (and matcher inventory) +5.
    env.trade_cpi(&taker_a, a, &lp, 5 * Q, 0)
        .expect("A opens long 5 (fresh)");
    env.trade_cpi(&taker_b, b, &lp, -10 * Q, 0)
        .expect("B opens short 10 (fresh)");
    assert_eq!(env.pos(a), 5 * Q);
    assert_eq!(env.pos(b), -10 * Q);
    assert_eq!(env.pos(lp.account), 5 * Q, "LP long 5");
    let mark_slot = env.last_good_oracle_slot();
    println!(
        "fresh: clock slot {} last_good_oracle_slot {mark_slot}",
        env.slot()
    );

    // Age the mark past 150 slots.
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.slot = mark_slot + 1_000;
    env.svm.set_sysvar::<Clock>(&clock);
    println!(
        "stale: clock slot {} last_good_oracle_slot {}",
        env.slot(),
        env.last_good_oracle_slot()
    );

    // B opens MORE short (sell): not taker-reducing; LP inventory grows -> matcher 8002.
    let keys = [env.market, a, b, lp.account, lp.ctx];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker_b, b, &lp, -Q, 0);
    println!("stale B open: {r:?}");
    assert_err_code(
        &r,
        ERR_STALE_MARK,
        "stale mark: taker open refused by the P2 matcher",
    );
    assert_eq!(env.snapshot(&keys), before, "refused open mutates nothing");

    // A closes its long (sell) -- SAME LP direction (LP inventory grows +5 -> +10), but it is
    // reduce-only for A, so the wrapper sets TAKER_REDUCING and the matcher lets it through.
    let r = env.trade_cpi(&taker_a, a, &lp, -5 * Q, 0);
    println!("stale A close: {r:?} ret {:?}", env.ctx_return(&lp));
    r.expect("stale mark: TAKER_REDUCING close fills");
    assert_eq!(env.pos(a), 0, "A is flat");
    assert_eq!(env.pos(lp.account), 10 * Q, "LP absorbed the close");
    assert_eq!(env.ctx_return(&lp).exec_size, -5 * Q, "unclipped close");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// 6. Legacy compatibility: matcher_ext_mode = 0 against the P2 matcher and the v1 12bd671.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p2_legacy_mode0_trades_against_p2_and_deployed_v1_matcher() {
    for (label, so) in [
        ("P2 4a0f696", p2_matcher_path()),
        ("v1 12bd671", v1_matcher_path()),
    ] {
        let (mut env, taker, ta, lp) =
            setup(so, PRICE_ODD, BASE_BPS, MatcherParams::passive(30, 100));
        env.set_limits(0, 0, 0);
        let before = env.money(ta, &lp);
        env.trade_cpi(&taker, ta, &lp, 10 * Q + 3, BASE_BPS)
            .unwrap_or_else(|e| panic!("{label}: legacy TradeCpi must fill: {e}"));
        let after = env.money(ta, &lp);
        let ret = env.ctx_return(&lp);
        assert_eq!(ret.exec_size, 10 * Q + 3, "{label}: full fill");
        assert_eq!(
            ret.exec_price,
            passive_price(PRICE_ODD, 30, true),
            "{label}: quote"
        );
        assert_eq!(ret.requested_fee_bits(), 0, "{label}: no fee request");
        let base = engine_fee((10 * Q + 3).unsigned_abs(), PRICE_ODD, BASE_BPS);
        assert_fee_legs(&before, &after, base, base, label);
        env.trade_cpi(&taker, ta, &lp, -(10 * Q + 3), BASE_BPS)
            .unwrap_or_else(|e| panic!("{label}: legacy close must fill: {e}"));
        assert_eq!(env.pos(ta), 0, "{label}: round trip");
    }
    // And mode 1 against the v1 matcher is exactly the brick the ABI doc warns about.
    let (mut env, taker, ta, lp) = setup(
        v1_matcher_path(),
        PRICE_ODD,
        BASE_BPS,
        MatcherParams::passive(30, 100),
    );
    env.set_limits(0, 1, 0);
    let r = env.trade_cpi(&taker, ta, &lp, 10 * Q, BASE_BPS);
    println!("mode 1 vs v1 12bd671: {r:?}");
    assert!(
        matches!(&r, Err(e) if e.contains("InstructionError(2, InvalidInstructionData)")),
        "v1 matcher rejects non-zero call bytes 43..67: {r:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// F-10: BatchTradeCpi sends the SAME P1/P2 call extension as TradeCpi (it sent legacy bytes,
//       so a batch filled an opening leg through a stale mark). Mirror of test 5.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[test]
fn p3_f10_batch_stale_mark_refuses_open_allows_taker_reducing_close() {
    let m = MatcherParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 0,
        max_total_bps: 100,
        impact_k_bps: 0,
        liquidity_notional_e6: 0,
    };
    let (mut env, taker_a, a, lp) = setup(p2_matcher_path(), PRICE_ONE, BASE_BPS, m);
    let taker_b = Keypair::new();
    let b = env.portfolio(&taker_b, 1_000_000_000);
    env.set_limits(0, 1, 0);
    // Fresh mark: batches fill; the CU of a single-leg batch with the extension is recorded.
    let cu = env.batch_cpi(&taker_a, a, &lp, &[5 * Q]).expect("fresh batch open (A long 5)");
    println!("F-10: single-leg BatchTradeCpi with ext: {cu} CU");
    assert!(cu < 400_000, "batch CU {cu}");
    env.batch_cpi(&taker_b, b, &lp, &[-10 * Q]).expect("fresh batch open (B short 10)");
    assert_eq!(env.pos(lp.account), 5 * Q, "LP long 5");
    // Age the mark past the P2 ctx's 150-slot max age.
    let mark_slot = env.last_good_oracle_slot();
    let mut clock = env.svm.get_sysvar::<Clock>();
    clock.slot = mark_slot + 1_000;
    env.svm.set_sysvar::<Clock>(&clock);
    // B opens more short via a BATCH: not taker-reducing -> the matcher refuses (stale mark).
    let keys = [env.market, a, b, lp.account, lp.ctx];
    let before = env.snapshot(&keys);
    let r = env.batch_cpi(&taker_b, b, &lp, &[-Q]);
    println!("stale batch B open: {r:?}");
    assert_err_code(&r, ERR_STALE_MARK, "stale mark: a batch open is refused like TradeCpi");
    assert_eq!(env.snapshot(&keys), before, "refused batch mutates nothing");
    // A closes via a BATCH: reduce-only for A -> TAKER_REDUCING -> fills under the stale mark.
    env.batch_cpi(&taker_a, a, &lp, &[-5 * Q]).expect("stale mark: TAKER_REDUCING batch close fills");
    assert_eq!(env.pos(a), 0, "A is flat");
}
