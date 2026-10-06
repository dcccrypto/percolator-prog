// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! v2.2 Phase 4 items 1 + 2 (design `phase4-design-2026-10-05.md`): the per-epoch price band
//! and holding-fee rent, driven through the REAL wrapper BPF (`target/deploy/percolator_prog.so`,
//! `--features devnet`) and the REAL matcher BPF in LiteSVM.
//!
//! Harness = `tests/growth_v19.rs` (the same InitMarket / InitPortfolio / Deposit /
//! SetMatcherConfig / InitMatcherCtx / TradeCpi / PermissionlessCrank wiring, a bound vault LP
//! by state poke) plus AuthMark pushes (`tests/p3_vault_lp.rs`) so the price can move.
//!
//! Market: $1, IMR 1_000 (10x), MMR 500, liquidation fee 100 bps, cap 4 bps/slot over 1 slot,
//! funding 1 e9/slot; band d = 100 bps (G = 304: 304 + ~104 + ~1 <= 500), E = 600, Pmax =
//! 9_000; rent max 23 e9/slot (~50 bps/day) above a 50% kink.
//!
//! Every test carries a negative control (the band-off / rent-off market, or the refused
//! variant next to the accepted one).
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{
    error::PercolatorError,
    ix::{CrankObservationHint, InitMarketPhase4, Instruction as ProgInstruction},
    state,
    state::PortfolioAccountV16,
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

const MATCHER_CONTEXT_LEN: usize = 320;
// v2.2 combined release: Wave A's 1e7 launch floor binds every growth (and so every band) market.
const PRICE: u64 = 10_000_000;
// one test "unit" = 1/10 token so every notional (and so every rent / margin figure) equals the pre-merge
// $1-per-unit fixtures at the 1e7 launch price.
const Q: i128 = POS_SCALE as i128 / 10;
const USD: u128 = 1_000_000;
const ENGINE_IMR: u64 = 1_000;
const MMR: u64 = 500;
const LIQ_FEE: u64 = 100;
const BAND_BPS: u16 = 100;
const BAND_E: u32 = 600;
const BAND_PMAX: u32 = 9_000;
const RENT_MAX: u32 = 23;
const RENT_KINK: u16 = 5_000;
/// Re-review N-1: the program floor for a 6-decimal collateral (10 whole tokens).
const BAND_MIN_LEG: u64 = 10_000_000;

thread_local! {
    /// Genesis price of the next `Env::new` on this thread (E-L1 tests override it).
    static INIT_PRICE: std::cell::Cell<u64> = const { std::cell::Cell::new(PRICE) };
}

fn code(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
}

fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("GROWTH_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(path.exists(), "BPF not found at {path:?}; run cargo build-sbf --features devnet");
    path
}

fn matcher_program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("percolator-match/target/deploy/percolator_match.so");
    assert!(path.exists(), "matcher BPF not found at {path:?}");
    path
}

fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|| {
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
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().unwrap();
    Pubkey::find_program_address(
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
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
            decimals: 6,
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

fn seeded_keypair(tag: u8) -> Keypair {
    solana_sdk::signer::keypair::keypair_from_seed(&[tag; 32]).unwrap()
}

fn assert_err(r: &Result<u64, String>, code: &str, what: &str) {
    match r {
        Err(e) => assert!(e.contains(code), "{what}: expected {code}, got {e}"),
        Ok(_) => panic!("{what}: expected {code}, got Ok"),
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

#[derive(Clone, Copy)]
struct Cfg {
    slots: usize,
    phase4: Option<InitMarketPhase4>,
    r_gap: u16,
}

fn phase4(band_bps: u16, rent_max: u32) -> InitMarketPhase4 {
    InitMarketPhase4 {
        rent_max_e9_per_slot: rent_max,
        rent_kink_bps: RENT_KINK,
        band_bps,
        band_max_epoch_slots: if band_bps != 0 { BAND_E } else { 0 },
        band_max_pin_slots: if band_bps != 0 { BAND_PMAX } else { 0 },
        band_min_leg_notional: if band_bps != 0 { BAND_MIN_LEG } else { 0 },
    }
}

fn init_market_ix(c: &Cfg) -> ProgInstruction {
    let base = ProgInstruction::InitMarket {
        max_portfolio_assets: c.slots as u16,
        h_min: 0,
        h_max: 10,
        initial_price: INIT_PRICE.with(|p| p.get()),
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 20,
        maintenance_margin_bps: MMR,
        initial_margin_bps: ENGINE_IMR,
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: LIQ_FEE,
        liquidation_fee_cap: 1_000_000_000_000_000,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 4,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 1,
        min_funding_lifetime_slots: 1,
        max_account_b_settlement_chunks: 1,
        max_bankrupt_close_chunks: 1,
        // Long freshness horizon so winners' claims stay backed through the long tests.
        max_bankrupt_close_lifetime_slots: 1_000_000,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    };
    match c.phase4 {
        None => ProgInstruction::InitMarketV19 {
            market: Box::new(base),
            growth_r_gap_bps: c.r_gap,
            growth_l_launch_x100: 1_000,
        },
        Some(p) => ProgInstruction::InitMarketV22 {
            market: Box::new(base),
            growth_r_gap_bps: c.r_gap,
            growth_l_launch_x100: 1_000,
            lot_exp: 0,
            phase4: p,
        },
    }
}

struct Lp {
    #[allow(dead_code)]
    owner: Keypair,
    account: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    matcher_program: Pubkey,
    portfolio_account_len: usize,
    next_key: u8,
    slot: u64,
    upgrade_authority: Keypair,
    program_data: Pubkey,
}

impl Env {
    fn try_new(cfg: Cfg) -> Result<Self, String> {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(program_path()).expect("read wrapper BPF"));
        svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).unwrap());
        let matcher_program = Pubkey::new_from_array([0xF0; 32]);
        svm.add_program(matcher_program, &std::fs::read(matcher_program_path()).unwrap());
        let payer = seeded_keypair(1);
        let admin = seeded_keypair(2);
        let market = Pubkey::new_from_array([0x11; 32]);
        let mint = Pubkey::new_from_array([0x12; 32]);
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
        svm.set_account(mint, acct(make_mint_data(), spl_token::ID)).unwrap();
        svm.set_account(vault, acct(make_token_data(mint, vault_authority, 0), spl_token::ID))
            .unwrap();
        svm.set_account(
            market,
            acct(vec![0u8; state::market_account_len_for_capacity(cfg.slots).unwrap()], program_id),
        )
        .unwrap();
        let mut env = Self {
            svm,
            program_id,
            payer,
            admin,
            market,
            mint,
            vault,
            matcher_program,
            portfolio_account_len: state::portfolio_account_len_for_market_slots(cfg.slots)
                .unwrap(),
            next_key: 0x40,
            slot: 1,
            upgrade_authority: seeded_keypair(3),
            program_data: Pubkey::find_program_address(
                &[program_id.as_ref()],
                &solana_sdk::bpf_loader_upgradeable::id(),
            )
            .0,
        };
        // ProgramData mock for the tag-93 upgrade-authority gate (as tests/growth_v19.rs).
        {
            let ua = env.upgrade_authority.pubkey();
            env.svm.airdrop(&ua, 1_000_000_000).unwrap();
            let mut pd = vec![0u8; 45];
            pd[0..4].copy_from_slice(&3u32.to_le_bytes());
            pd[12] = 1;
            pd[13..45].copy_from_slice(ua.as_ref());
            let pdk = env.program_data;
            env.svm
                .set_account(
                    pdk,
                    Account {
                        lamports: 1_000_000_000,
                        data: pd,
                        owner: solana_sdk::bpf_loader_upgradeable::id(),
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
        }
        let admin = env.admin.insecure_clone();
        env.send(
            init_market_ix(&cfg),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin],
        )?;
        Ok(env)
    }

    fn new(cfg: Cfg) -> Self {
        Self::try_new(cfg).expect("init market")
    }

    /// An AuthMark asset so tests can push the price.
    fn auth_mark(&mut self) {
        let admin = self.admin.insecure_clone();
        let seq = self.oracle_seq() + 1;
        let m = self.market;
        self.send(
            ProgInstruction::ConfigureAuthMark {
                market_id: 1,
                asset_index: 0,
                now_slot: self.slot,
                initial_mark_e6: PRICE,
                observation_sequence: seq,
            },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
        .expect("configure auth mark");
    }

    fn oracle_seq(&self) -> u64 {
        let data = self.svm.get_account(&self.market).unwrap().data;
        state::read_asset_control_sequences(&data, 0).unwrap().oracle_observation
    }

    fn push(&mut self, mark_e6: u64) {
        let admin = self.admin.insecure_clone();
        let seq = self.oracle_seq() + 1;
        let (m, slot) = (self.market, self.slot);
        self.send(
            ProgInstruction::PushAuthMark {
                market_id: 1,
                asset_index: 0,
                now_slot: slot,
                mark_e6,
                observation_sequence: seq,
            },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
        .expect("push auth mark");
    }

    fn key(&mut self) -> Pubkey {
        self.next_key = self.next_key.wrapping_add(1);
        assert!(self.next_key < 0xF0);
        Pubkey::new_from_array([self.next_key; 32])
    }

    fn signer(&mut self) -> Keypair {
        self.next_key = self.next_key.wrapping_add(1);
        assert!(self.next_key < 0xF0);
        seeded_keypair(self.next_key)
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<u64, String> {
        let instruction = Instruction { program_id: self.program_id, accounts, data: ix.encode() };
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
            .map(|m| m.compute_units_consumed)
            .map_err(|e| format!("{e:?}"))
    }

    fn portfolio(&mut self, owner: &Keypair, deposit: u128) -> Pubkey {
        let portfolio = self.key();
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
        let m = self.market;
        self.send(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("init portfolio");
        if deposit > 0 {
            let source = self.key();
            let mint = self.mint;
            self.svm
                .set_account(
                    source,
                    Account {
                        lamports: 1_000_000_000,
                        data: make_token_data(mint, owner.pubkey(), deposit as u64),
                        owner: spl_token::ID,
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
            let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
            let (m, v) = (self.market, self.vault);
            self.send(
                ProgInstruction::Deposit { portfolio_id, expected_sequence, amount: deposit },
                vec![
                    AccountMeta::new(owner.pubkey(), true),
                    AccountMeta::new(m, false),
                    AccountMeta::new(portfolio, false),
                    AccountMeta::new(source, false),
                    AccountMeta::new(v, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
                &[owner],
            )
            .expect("deposit");
        }
        portfolio
    }

    fn trader(&mut self, deposit: u128) -> (Keypair, Pubkey) {
        let k = self.signer();
        let p = self.portfolio(&k, deposit);
        (k, p)
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

    /// LP with a passive kind-0 unlimited matcher, bound as asset 0's vault LP (state poke,
    /// as `tests/growth_v19.rs::bind_vault_lp_poke`).
    fn lp(&mut self, deposit: u128) -> Lp {
        let owner = self.signer();
        let account = self.portfolio(&owner, deposit);
        let ctx = self.key();
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
        let mp = self.matcher_program;
        self.svm
            .set_account(
                ctx,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; MATCHER_CONTEXT_LEN],
                    owner: mp,
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
        let m = self.market;
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
                AccountMeta::new_readonly(m, false),
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
                kind: 0,
                trading_fee_bps: 0,
                base_spread_bps: 0,
                max_total_bps: 100,
                impact_k_bps: 0,
                liquidity_notional_e6: 0,
                max_fill_abs: u128::MAX,
                max_inventory_abs: 0,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new_readonly(m, false),
                AccountMeta::new(account, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[&owner],
        )
        .expect("init matcher ctx");
        let mut mk = self.svm.get_account(&self.market).unwrap();
        let r = state::asset_growth_range(&mk.data, 0).unwrap();
        let slot0 = r.start - percolator_prog::constants::ASSET_GROWTH_OFF;
        let rec = state::AssetVaultLpV18 {
            vault_lp_portfolio: account.to_bytes(),
            flags: state::ASSET_VAULT_LP_FLAG_BOUND,
            ..Default::default()
        };
        state::asset_vault_lp_to_wrapper_bytes(
            &mut mk.data[slot0..slot0 + percolator_prog::constants::ASSET_ORACLE_WRAPPER_LEN],
            &rec,
        )
        .unwrap();
        self.svm.set_account(self.market, mk).unwrap();
        Lp { owner, account, ctx, delegate }
    }

    fn trade_cpi(&mut self, taker: &Keypair, taker_account: Pubkey, lp: &Lp, size_q: i128) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.identity(lp.account);
        let market_id = self.market_id();
        let (m, mp) = (self.market, self.matcher_program);
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
                fee_bps: 10_000,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp.account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[taker],
        )
    }

    /// Advance `n` slots (warp) without any transaction.
    fn warp(&mut self, n: u64) {
        self.slot += n;
        self.svm.warp_to_slot(self.slot);
    }

    /// One permissionless crank of `portfolio` at the current slot.
    fn crank(&mut self, portfolio: Pubkey) -> Result<u64, String> {
        let (payer, m, slot) = (self.payer.pubkey(), self.market, self.slot);
        self.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: slot,
                observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
            ],
            &[],
        )
    }

    /// A keeper crank: repeat until the asset clock reaches the wall clock (the bounded
    /// catch-up returns early while it lags) and the portfolio has been refreshed. An
    /// already-current portfolio answers NonProgress, which is not a failure here.
    fn crank_current(&mut self, portfolio: Pubkey) {
        for _ in 0..4 {
            let r = self.crank(portfolio);
            if let Err(e) = &r {
                assert!(e.contains(&code(PercolatorError::EngineNonProgress)), "crank failed: {e}");
            }
            if self.engine_asset().slot_last >= self.slot && r.is_ok() {
                break;
            }
        }
    }

    fn settle_rent(&mut self, portfolio: Pubkey, vault_lp: Pubkey) -> Result<u64, String> {
        let (payer, m, slot) = (self.payer.pubkey(), self.market, self.slot);
        self.send(
            ProgInstruction::SettleHoldingRent { asset_index: 0, now_slot: slot },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(vault_lp, false),
            ],
            &[],
        )
    }

    /// Tag 93 with the growth dial trailer (8-byte form when `util != 0`), signed by the UA.
    fn set_growth_dials(&mut self, lambda_bps: u32, kink_bps: u16, util: u16) -> Result<u64, String> {
        let ua = self.upgrade_authority.insecure_clone();
        let (pd, market) = (self.program_data, self.market);
        self.send(
            ProgInstruction::SetAssetRiskLimitsV19 {
                limits: Box::new(ProgInstruction::SetAssetRiskLimits {
                    asset_index: 0,
                    exec_band_bps: 0,
                    lp_exposure_k_bps: 0,
                    lp_floor_atoms: 0,
                    side_oi_cap_q: 0,
                    matcher_ext_mode: 0,
                    max_requested_fee_bps: 0,
                }),
                growth_lambda_bps: lambda_bps,
                growth_kink_bps: kink_bps,
                growth_util_fee_max_bps: util,
            },
            vec![
                AccountMeta::new(ua.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[&ua],
        )
    }

    fn engine_asset(&self) -> percolator::AssetStateV16 {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, g) = state::market_view_mut(&mut data).unwrap();
        g.markets[0].engine.asset.try_to_runtime().unwrap()
    }

    fn engine_header(&self) -> (u128, u128, u128, u64, u64, u64, u64) {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, g) = state::market_view_mut(&mut data).unwrap();
        let c = g.header.config.try_to_runtime_shape().unwrap();
        (
            g.header.vault.get(),
            g.header.c_tot.get(),
            g.header.insurance.get(),
            c.band_bps,
            c.band_max_epoch_slots,
            c.band_max_pin_slots,
            c.rent_max_e9_per_slot,
        )
    }

    fn wrapper_cfg(&self) -> state::WrapperConfigV16 {
        state::read_market(&self.svm.get_account(&self.market).unwrap().data).unwrap().0
    }

    fn growth(&self) -> state::AssetGrowthV19 {
        state::read_asset_growth(&self.svm.get_account(&self.market).unwrap().data, 0, ENGINE_IMR)
            .unwrap()
            .expect("growth on")
    }

    fn portfolio_state(&self, p: Pubkey) -> PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&p).unwrap().data).unwrap()
    }

    fn pos(&self, p: Pubkey) -> i128 {
        self.portfolio_state(p)
            .legs
            .iter()
            .find(|l| l.active && l.asset_index == 0)
            .map(|l| match l.side {
                SideV16::Long => l.basis_pos_q.unsigned_abs() as i128,
                SideV16::Short => -(l.basis_pos_q.unsigned_abs() as i128),
            })
            .unwrap_or(0)
    }

    fn assert_conservation(&self) {
        let (v, c, i, ..) = self.engine_header();
        assert!(v >= c + i, "V >= C_tot + I violated: {v} < {c} + {i}");
    }
}

fn band_cfg() -> Cfg {
    Cfg { slots: 1, phase4: Some(phase4(BAND_BPS, RENT_MAX)), r_gap: 0 }
}

// ---------------------------------------------------------------------------
// Wire + InitMarket
// ---------------------------------------------------------------------------

#[test]
fn v22_init_market_wire_roundtrip_and_strictness() {
    let base = init_market_ix(&Cfg { slots: 1, phase4: None, r_gap: 400 });
    let ProgInstruction::InitMarketV19 { market, .. } = base.clone() else { panic!() };
    for p in [phase4(0, RENT_MAX), phase4(BAND_BPS, RENT_MAX), phase4(BAND_BPS, 0)] {
        let ix = ProgInstruction::InitMarketV22 {
            market: market.clone(),
            growth_r_gap_bps: if p.band_bps == 0 { 400 } else { 0 },
            growth_l_launch_x100: 1_000,
            lot_exp: 0,
            phase4: p,
        };
        let bytes = ix.encode();
        let legacy_len = market.encode().len();
        assert_eq!(bytes.len(), legacy_len + if p.band_bps == 0 { 10 } else { 28 });
        assert_eq!(ProgInstruction::decode(&bytes).unwrap(), ix, "roundtrip");
    }
    // The 4-byte growth-1 form is unchanged.
    assert_eq!(ProgInstruction::decode(&base.encode()).unwrap(), base);
    let legacy = market.encode();
    let mut bad = legacy.clone();
    bad.extend_from_slice(&[0, 0, 0xE8, 0x03]); // r_gap 0 without a band block: refused
    assert!(ProgInstruction::decode(&bad).is_err());
    let mut bad = legacy.clone();
    bad.extend_from_slice(&[1; 7]); // 7-byte trailer (growth + 3): refused
    assert!(ProgInstruction::decode(&bad).is_err());
    let mut bad = legacy.clone();
    bad.extend_from_slice(&[1; 15]); // growth + rent + 5 of the band block: refused
    assert!(ProgInstruction::decode(&bad).is_err());
    let tag106 = ProgInstruction::SettleHoldingRent { asset_index: 3, now_slot: 77 };
    assert_eq!(tag106.encode().len(), 11);
    assert_eq!(tag106.encode()[0], 106);
    assert_eq!(ProgInstruction::decode(&tag106.encode()).unwrap(), tag106);
}

#[test]
fn v22_init_market_writes_band_rent_and_derived_growth() {
    let env = Env::new(band_cfg());
    let (_, _, _, d, e, pmax, rent) = env.engine_header();
    assert_eq!((d, e, pmax, rent), (BAND_BPS as u64, BAND_E as u64, BAND_PMAX as u64, RENT_MAX as u64));
    let a = env.engine_asset();
    assert_eq!((a.band_epoch, a.band_anchor_price), (1, PRICE), "band armed at activation");
    let g = env.growth();
    let g_bps = percolator::band_rent::band_worst_adverse_bps(BAND_BPS as u64).unwrap();
    assert_eq!(g.r_gap_bps as u64, g_bps, "r_gap derived = G(d), not declared");
    assert_eq!(g.rent_kink_bps, RENT_KINK);
    assert_eq!(g.util_fee_max_bps, percolator_prog::growth_v19::RENT_ENTRY_FLOOR_BPS, "toll = entry floor");
    assert_eq!(env.wrapper_cfg().liquidation_cranker_fee_share_bps, 2_000, "band markets pay liquidators");
    // Negative control: a growth-1 market (no phase-4 block) keeps the v2.1 shape.
    let legacy = Env::new(Cfg { slots: 1, phase4: None, r_gap: 400 });
    let (_, _, _, d0, e0, p0, r0) = legacy.engine_header();
    assert_eq!((d0, e0, p0, r0), (0, 0, 0, 0));
    assert_eq!(legacy.engine_asset().band_epoch, 0, "I-B7: band off");
    assert_eq!(legacy.growth().util_fee_max_bps, 0, "growth-1 toll default unchanged");
    assert_eq!(legacy.wrapper_cfg().liquidation_cranker_fee_share_bps, 0);
}

#[test]
fn v22_init_market_refusals_are_named() {
    // Band too wide for MMR 500 (G(300) = 938): Band Safety Law -> 105.
    let mut c = band_cfg();
    c.phase4 = Some(phase4(300, RENT_MAX));
    assert_err(&Env::try_new(c).map(|_| 0), &code(PercolatorError::PriceBandConfigInvalid), "BSL");
    // Rent above the engine ceiling -> 106.
    let mut c = band_cfg();
    c.phase4 = Some(phase4(BAND_BPS, 10_001));
    assert_err(&Env::try_new(c).map(|_| 0), &code(PercolatorError::HoldingRentConfigInvalid), "rent max");
    // Rent kink above 100% -> 106.
    let mut c = band_cfg();
    let mut p = phase4(BAND_BPS, RENT_MAX);
    p.rent_kink_bps = 10_001;
    c.phase4 = Some(p);
    assert_err(&Env::try_new(c).map(|_| 0), &code(PercolatorError::HoldingRentConfigInvalid), "rent kink");
    // A band on a two-asset market (the law is per single-asset account) -> 105.
    let mut c = band_cfg();
    c.slots = 2;
    assert_err(&Env::try_new(c).map(|_| 0), &code(PercolatorError::PriceBandConfigInvalid), "multi-asset band");
    // Pmax < E -> 105.
    let mut c = band_cfg();
    let mut p = phase4(BAND_BPS, RENT_MAX);
    p.band_max_pin_slots = BAND_E - 1;
    c.phase4 = Some(p);
    assert_err(&Env::try_new(c).map(|_| 0), &code(PercolatorError::PriceBandConfigInvalid), "Pmax < E");
    // Positive control: the preset is accepted.
    assert!(Env::try_new(band_cfg()).is_ok());
}

#[test]
fn v22_band_market_refuses_a_maintenance_fee() {
    // The per-slot maintenance fee is unpriced by the Band Safety Law: refused at init...
    let mut env = Env::new(band_cfg());
    let admin = env.admin.insecure_clone();
    let m = env.market;
    let r = env.send(
        ProgInstruction::UpdateMaintenanceFeePerSlot { maintenance_fee_per_slot: 1 },
        vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
        &[&admin],
    );
    assert_err(&r, &code(PercolatorError::PriceBandConfigInvalid), "maintenance fee on a band market");
    // ...while a band-off growth market accepts it (control).
    let mut legacy = Env::new(Cfg { slots: 1, phase4: None, r_gap: 400 });
    let m = legacy.market;
    let r = legacy.send(
        ProgInstruction::UpdateMaintenanceFeePerSlot { maintenance_fee_per_slot: 1 },
        vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
        &[&admin],
    );
    assert!(r.is_ok(), "control: {r:?}");
}

// ---------------------------------------------------------------------------
// Band on BPF: staircase, edge pin, favourable close, re-anchor
// ---------------------------------------------------------------------------

/// Book: a long taker and a smaller short taker against the bound vault LP (the LP holds the
/// net short, as in a real crowd), price at $1.
fn band_book(env: &mut Env) -> (Lp, (Keypair, Pubkey), (Keypair, Pubkey)) {
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let long = env.trader(1_000 * USD);
    let short = env.trader(1_000 * USD);
    env.trade_cpi(&long.0, long.1, &lp, 200 * Q).expect("open long");
    env.trade_cpi(&short.0, short.1, &lp, -100 * Q).expect("open short");
    assert_eq!(env.pos(lp.account), -100 * Q, "the LP holds the net short");
    (lp, long, short)
}

#[test]
fn v22_band_staircase_pins_at_the_edge_and_refuses_the_favourable_close() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    // Target +30%. The keeper cranks every slot but the LONG is never certified: the epoch
    // cannot advance, so the price stops at hi(A) and pins.
    let target = PRICE * 13 / 10;
    let (_, hi) = percolator::band_rent::band_bounds(PRICE, BAND_BPS as u64).unwrap();
    for _ in 0..60 {
        env.warp(1);
        env.push(target);
        env.crank(short.1).expect("crank short");
        env.crank(lp.account).expect("crank lp");
    }
    let a = env.engine_asset();
    assert!(a.effective_price <= hi, "never beyond the band: {} > {hi}", a.effective_price);
    assert!(a.band_pin_since_slot != 0, "pin clock running at the edge");
    // While pinned (target above P_last): the SHORT's close is the favourable side -> 104.
    let r = env.trade_cpi(&short.0, short.1, &lp, 50 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPinned), "favourable-side close while pinned");
    // The LONG's close is the worse side for it -> allowed. Its counterparty, the vault LP,
    // reduces its short at the same stale price (favourable to the LP, the protected party).
    env.crank(long.1).expect("crank long");
    let r = env.trade_cpi(&long.0, long.1, &lp, -50 * Q);
    assert!(r.is_ok(), "worse-side close while pinned must land: {r:?}");
    assert_eq!(env.pos(long.1), 150 * Q);
    env.assert_conservation();
}

#[test]
fn v22_band_certified_book_advances_the_anchor_and_catches_up() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    let target = PRICE * 103 / 100;
    let e0 = env.engine_asset().band_epoch;
    let mut epochs = 0;
    for _ in 0..400 {
        env.warp(1);
        env.push(target);
        for p in [long.1, short.1, lp.account] {
            // An already-current portfolio may answer NonProgress; that is not a failure.
            let _ = env.crank(p);
        }
        let a = env.engine_asset();
        epochs = a.band_epoch - e0;
        if a.effective_price == target {
            break;
        }
    }
    let a = env.engine_asset();
    assert_eq!(a.effective_price, target, "a fully certified book catches up to the target");
    assert!(epochs >= 3, "a 3% move needs >= 3 band epochs at d = 1% (saw {epochs})");
    env.assert_conservation();
}

// ---------------------------------------------------------------------------
// Rent on BPF: accrual, routing, tag 106
// ---------------------------------------------------------------------------

#[test]
fn v22_rent_accrues_above_the_kink_routes_to_the_vault_lp_and_tag_106_settles() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    // A crowd long at u = 80% of N_cap (1,000 units at lambda 1x), above the 50% kink.
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 800 * Q).expect("crowd open");
    let g = env.growth();
    assert!(g.rent_n_cap_q > 0, "the fill measured the LP's N_cap for rent");
    let cap0 = env.portfolio_state(taker.1).capital;
    for _ in 0..100 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    let a = env.engine_asset();
    assert!(a.rent_index_long_num > 0, "the crowd side pays rent above the kink");
    assert_eq!(a.rent_index_short_num, 0, "the empty short side pays nothing");
    let paid = cap0 - env.portfolio_state(taker.1).capital;
    assert!(paid > 0, "rent charged to the taker");
    let unrouted = env.engine_asset().rent_unrouted_atoms;
    assert_eq!(unrouted, paid, "every charged atom is an LP claim until routed");
    env.assert_conservation();
    // Tag 106 against a portfolio that is NOT the bound vault LP: refused.
    let r = env.settle_rent(taker.1, taker.1);
    assert_err(&r, &code(PercolatorError::VaultLpNotBound), "tag 106 requires the bound vault LP");
    // Tag 106 routes the claim to the vault LP (and settles the taker's newest rent).
    let lp_cap0 = env.portfolio_state(lp.account).capital;
    let taker_cap1 = env.portfolio_state(taker.1).capital;
    env.warp(1);
    env.push(PRICE);
    env.settle_rent(taker.1, lp.account).expect("tag 106");
    let newest = taker_cap1 - env.portfolio_state(taker.1).capital;
    let lp_gain = env.portfolio_state(lp.account).capital - lp_cap0;
    assert_eq!(lp_gain, unrouted + newest, "the vault LP receives every unrouted atom");
    assert_eq!(env.engine_asset().rent_unrouted_atoms, 0);
    env.assert_conservation();
}

#[test]
fn v22_rent_is_zero_at_or_below_the_kink_and_off_without_rent() {
    // Below the kink: u = 40% -> rate 0.
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 400 * Q).expect("open below kink");
    for _ in 0..20 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    assert_eq!(env.engine_asset().rent_index_long_num, 0, "I-R1: 0 at u <= kink");
    // Rent off (rent max 0): the same crowd at u = 80% pays nothing.
    let mut c = band_cfg();
    c.phase4 = Some(phase4(BAND_BPS, 0));
    let mut env = Env::new(c);
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 800 * Q).expect("crowd open");
    for _ in 0..20 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    assert_eq!(env.engine_asset().rent_index_long_num, 0, "no rent ceiling, no rent");
}

// ---------------------------------------------------------------------------
// growth-v19 interaction: the leverage ceiling, lambda, alpha and toll dials vs the band
// ---------------------------------------------------------------------------

#[test]
fn v22_growth_dials_unlock_only_on_a_band_market() {
    use percolator_prog::growth_v19 as gv;
    // Band market (MMR 500, G(100) = 304): lambda may exceed 1x (up to band_lambda_max, capped
    // at MAX_LAMBDA_BPS), kink up to 100%, toll down to 0.
    let mut env = Env::new(band_cfg());
    assert!(env.set_growth_dials(50_000, 9_000, 0).is_ok(), "band: lambda 5x, kink 90%");
    assert_eq!(env.growth().lambda_bps, 50_000);
    assert!(env.set_growth_dials(50_000, 9_000, 1).is_ok(), "band: toll down to 1 bps");
    assert_eq!(env.growth().util_fee_max_bps, 1);
    // Off-band growth market (v2.1 growth-1): tighten-only, lambda <= 1x, toll >= 500 bps.
    let mut legacy = Env::new(Cfg { slots: 1, phase4: None, r_gap: 400 });
    assert_err(&legacy.set_growth_dials(50_000, 5_000, 0), &code(PercolatorError::GrowthInvalidConfig), "off-band lambda > 1x");
    assert_err(&legacy.set_growth_dials(10_000, 9_000, 0), &code(PercolatorError::GrowthInvalidConfig), "off-band kink > 50%");
    assert_err(&legacy.set_growth_dials(10_000, 5_000, 100), &code(PercolatorError::GrowthInvalidConfig), "off-band toll < 500");
    assert!(legacy.set_growth_dials(10_000, 5_000, 0).is_ok(), "control: the growth-1 box");
    // Rent-only market (no band): toll down to the 25 bps entry floor, never below.
    let mut c = band_cfg();
    c.phase4 = Some(phase4(0, RENT_MAX));
    c.r_gap = 400;
    let mut rent_only = Env::new(c);
    assert!(rent_only.set_growth_dials(10_000, 5_000, gv::RENT_ENTRY_FLOOR_BPS).is_ok());
    assert_err(&rent_only.set_growth_dials(10_000, 5_000, gv::RENT_ENTRY_FLOOR_BPS - 1), &code(PercolatorError::GrowthInvalidConfig), "rent market toll < floor");
    assert_err(&rent_only.set_growth_dials(20_000, 5_000, 0), &code(PercolatorError::GrowthInvalidConfig), "no band, no lambda > 1x");
}

#[test]
fn v22_growth_pure_band_gates() {
    use percolator_prog::growth_v19 as gv;
    // Graduation: band AND an on-chain depth tier (item 4 supplies the tier; 0 until then).
    assert!(!gv::graduation_allowed(0, 0) && !gv::graduation_allowed(130, 0) && !gv::graduation_allowed(0, 2));
    assert!(gv::graduation_allowed(130, 1));
    // r_gap derived = G(d).
    assert_eq!(gv::band_r_gap_bps(130), Some(397));
    assert_eq!(gv::band_r_gap_bps(0), None);
    // lambda ceiling: floor(1e4 * 9_500 / (MMR + G)), capped.
    assert_eq!(gv::band_lambda_max_bps(1_000, 938), Some(10_000 * 9_500 / 1_938));
    assert_eq!(gv::band_lambda_max_bps(500, 397), Some(gv::MAX_LAMBDA_BPS), "capped at 10x");
    assert!(gv::growth_dials_ok_for(Some((1_000, 938)), 49_019, 10_000));
    assert!(!gv::growth_dials_ok_for(Some((1_000, 938)), 49_020, 10_000), "above band_lambda_max");
    assert!(!gv::growth_dials_ok_for(None, 10_001, 0), "off-band box unchanged");
    // alpha: 50% off-band, 70% on a band market.
    assert_eq!(gv::alloc_alpha_max_bps(false), 5_000);
    assert_eq!(gv::alloc_alpha_max_bps(true), 7_000);
    // I-1: c_launch never below $1,000.
    assert_eq!(gv::c_launch_atoms_for(1), gv::MIN_C_LAUNCH_ATOMS);
    assert_eq!(gv::c_launch_atoms_for(5 * gv::MIN_C_LAUNCH_ATOMS), 5 * gv::MIN_C_LAUNCH_ATOMS);
    // The toll in force: stored, else 25 bps on a rent market, else the growth-1 500 bps.
    assert_eq!(gv::util_fee_max_effective_bps_for(0, true), gv::RENT_ENTRY_FLOOR_BPS);
    assert_eq!(gv::util_fee_max_effective_bps_for(0, false), gv::GROWTH_UTIL_FEE_DEFAULT_BPS);
    assert_eq!(gv::util_fee_max_effective_bps_for(77, true), 77);
}

#[test]
fn v22_rent_rate_kink_cap_monotone_exhaustive() {
    use percolator_prog::growth_v19::rent_rate_e9;
    // I-R1 on a small exhaustive domain (the Kani twin bounds the same function).
    for n in [1u128, 7, 100, 1_000] {
        for kink in [0u16, 1, 5_000, 9_999, 10_000] {
            for max in [0u64, 1, 23, 10_000] {
                let mut prev = 0u64;
                for users in 0..=(2 * n) {
                    let r = rent_rate_e9(users, n, kink, max).unwrap();
                    assert!(r <= max);
                    assert!(r >= prev, "monotone in users");
                    if users * 10_000 <= kink as u128 * n {
                        assert_eq!(r, 0, "zero at or below the kink");
                    }
                    if users >= n && users * 10_000 > kink as u128 * n {
                        assert_eq!(r, max, "max at u >= 1");
                    }
                    prev = r;
                }
            }
        }
    }
    assert_eq!(rent_rate_e9(5, 0, 5_000, 23), None, "no capacity measured -> no rate");
    assert_eq!(rent_rate_e9(5, 10, 10_001, 23), None, "kink above 100%");
}

// ===========================================================================
// SENTINEL adversarial additions (review of PR #533). Tests named sec_*.
// ===========================================================================

impl Env {
    fn settle_rent_at(&mut self, portfolio: Pubkey, vault_lp: Pubkey, now_slot: u64) -> Result<u64, String> {
        let (payer, m) = (self.payer.pubkey(), self.market);
        self.send(
            ProgInstruction::SettleHoldingRent { asset_index: 0, now_slot },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(vault_lp, false),
            ],
            &[],
        )
    }
    fn total_capital(&self, ps: &[Pubkey]) -> u128 {
        ps.iter().map(|p| self.portfolio_state(*p).capital).sum()
    }
}

#[test]
fn sec_tag106_cannot_be_spoofed_double_charged_or_redirected() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    let attacker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 800 * Q).expect("crowd open");
    for _ in 0..100 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    // (a) redirect: the attacker's own portfolio as the "vault LP" is refused; nothing moves.
    let before = (env.engine_asset(), env.total_capital(&[taker.1, lp.account, attacker.1]));
    let r = env.settle_rent(taker.1, attacker.1);
    assert_err(&r, &code(PercolatorError::VaultLpNotBound), "redirect to attacker portfolio");
    let r = env.settle_rent(attacker.1, attacker.1);
    assert_err(&r, &code(PercolatorError::VaultLpNotBound), "attacker settles itself as LP");
    assert_eq!(before.0.rent_unrouted_atoms, env.engine_asset().rent_unrouted_atoms);
    assert_eq!(before.1, env.total_capital(&[taker.1, lp.account, attacker.1]));
    let attacker_cap = env.portfolio_state(attacker.1).capital;

    // (b) now_slot spoof: the program takes the slot from Clock, never from the argument.
    env.warp(3);
    env.push(PRICE);
    for spoof in [u64::MAX, 0, env.slot + 1_000_000] {
        let _ = env.settle_rent_at(taker.1, lp.account, spoof);
        let a = env.engine_asset();
        assert!(a.slot_last <= env.slot, "asset clock ran ahead of Clock: {} > {}", a.slot_last, env.slot);
        env.assert_conservation();
    }
    let honest_slot_last = env.engine_asset().slot_last;
    assert!(honest_slot_last <= env.slot);

    // (c) double charge: a second tag 106 in the same slot charges nothing more.
    env.warp(2);
    env.push(PRICE);
    env.settle_rent(taker.1, lp.account).expect("first");
    let cap1 = env.portfolio_state(taker.1).capital;
    let idx1 = env.engine_asset().rent_index_long_num;
    let r2 = env.settle_rent(taker.1, lp.account);
    let cap2 = env.portfolio_state(taker.1).capital;
    eprintln!("SEC tag106 second call same slot: {r2:?}, taker capital {cap1} -> {cap2}, idx {idx1}");
    assert_eq!(cap1, cap2, "double charge in one slot");
    assert_eq!(idx1, env.engine_asset().rent_index_long_num);

    // (d) settling the SAME elapsed time in many small calls == one call (no rounding drift in the
    // charged total beyond the carried sub-atom): compare against rent_due math.
    let cap_before = env.portfolio_state(taker.1).capital;
    let idx_before = env.engine_asset().rent_index_long_num;
    for _ in 0..10 {
        env.warp(1);
        env.push(PRICE);
        env.settle_rent(taker.1, lp.account).expect("tag 106");
    }
    let charged = cap_before - env.portfolio_state(taker.1).capital;
    let idx_after = env.engine_asset().rent_index_long_num;
    let q = 800 * POS_SCALE / 10;
    let one_shot = percolator::band_rent::rent_due_atoms(q, idx_after, idx_before).unwrap();
    eprintln!("SEC rent 10 settles charged {charged}, one-shot floor {one_shot}");
    assert!(charged <= one_shot + 1 && charged + 1 >= one_shot, "split settles drift: {charged} vs {one_shot}");
    // a third party never gains or loses: the attacker's capital is untouched throughout
    assert_eq!(attacker_cap, env.portfolio_state(attacker.1).capital);
    env.assert_conservation();
}

#[test]
fn sec_pinned_close_flip_and_open_variants() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    let target = PRICE * 13 / 10;
    for _ in 0..60 {
        env.warp(1);
        env.push(target);
        env.crank(short.1).expect("crank short");
        env.crank(lp.account).expect("crank lp");
    }
    assert!(env.engine_asset().band_pin_since_slot != 0, "pinned");
    let pin = code(PercolatorError::PriceBandPinned);
    // short = -100. Full close, partial, and FLIP (close + open long at the stale-low price) are all
    // favourable for the short side (target above P_last): refused.
    for q in [100 * Q, 50 * Q, 150 * Q, 1 * Q] {
        let r = env.trade_cpi(&short.0, short.1, &lp, q);
        eprintln!("SEC pinned short buys {q}: {r:?}");
        assert!(r.is_err(), "favourable-side exit/flip landed at the stale price: q={q}");
    }
    assert_eq!(env.pos(short.1), -100 * Q);
    // a fresh long OPEN at the stale-low price (the dangerous one) is refused by the lag gate.
    let newbie = env.trader(1_000 * USD);
    let r = env.trade_cpi(&newbie.0, newbie.1, &lp, 10 * Q);
    eprintln!("SEC pinned fresh long open: {r:?}");
    assert!(r.is_err(), "open at the pinned stale price must be refused");
    let _ = (pin, &long);
}

#[test]
fn sec_v21_stamped_accounts_are_refused() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let t = env.trader(1_000 * USD);
    env.trade_cpi(&t.0, t.1, &lp, 10 * Q).expect("open");
    let invalid = code(PercolatorError::InvalidVersion);
    for (name, pk) in [("market", env.market), ("portfolio", t.1)] {
        let mut acc = env.svm.get_account(&pk).unwrap();
        let orig = acc.data[8..10].to_vec();
        acc.data[8..10].copy_from_slice(&18u16.to_le_bytes());
        env.svm.set_account(pk, acc.clone()).unwrap();
        env.warp(1);
        let r = env.crank(t.1);
        eprintln!("SEC v18-stamped {name}: {r:?}");
        assert!(r.is_err() && r.as_ref().unwrap_err().contains(&invalid), "{name}: {r:?}");
        let r = env.settle_rent(t.1, lp.account);
        assert!(r.is_err(), "{name}: tag 106 must refuse a v2.1 image");
        acc.data[8..10].copy_from_slice(&orig);
        env.svm.set_account(pk, acc).unwrap();
    }
}


// ===========================================================================
// v2.2 Wave B security-review fixes (E-M1, E-L1, E-L2, W-M1, W-M2, D-1, rent overflow).
// Every refusal sits next to its accepted control.
// ===========================================================================

impl Env {
    fn trade_nocpi(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(account_a);
        let (b_id, _, b_epoch) = self.identity(account_b);
        let market_id = self.market_id();
        let exec_price = self.engine_asset().effective_price;
        let m = self.market;
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
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            &[owner_a, owner_b],
        )
    }

    fn batch_trade_cpi(&mut self, taker: &Keypair, taker_account: Pubkey, lp: &Lp, size_q: i128) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.identity(lp.account);
        let market_id = self.market_id();
        let (m, mp) = (self.market, self.matcher_program);
        self.send(
            ProgInstruction::BatchTradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                account_b_matcher_sequence: b_seq,
                max_slippage_atoms: u128::MAX,
                max_fee_atoms: u128::MAX,
                legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                    asset_index: 0,
                    market_id,
                    size_q,
                    fee_bps: 10_000,
                    limit_price: 0,
                }],
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp.account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[taker],
        )
    }

    fn withdraw(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Result<u64, String> {
        let dest = self.key();
        let mint = self.mint;
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, owner.pubkey(), 0),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        let (m, v) = (self.market, self.vault);
        let authority = Pubkey::find_program_address(&[b"vault", m.as_ref()], &self.program_id).0;
        self.send(
            ProgInstruction::Withdraw { portfolio_id, expected_sequence, amount },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[owner],
        )
    }
}

/// A band market whose mark LAGS its target by plain cap-law lag (NOT pinned): the target is
/// pushed +0.5% (inside the 1% band); one crank moves the price only the 4 bps the cap allows.
fn lagged_not_pinned(env: &mut Env, short: Pubkey, lp: Pubkey) {
    env.warp(1);
    env.push(PRICE * 1_005 / 1_000);
    env.crank(short).expect("crank short");
    env.crank(lp).expect("crank lp");
    let a = env.engine_asset();
    assert!(a.raw_oracle_target_price > a.effective_price, "lagged: target above P_last");
    assert_eq!(a.band_pin_since_slot, 0, "NOT pinned: inside the band, inside the window");
}

/// Review E-L2 + D-1, per payout-bearing tag: while the mark lags (no pin), the favourable-side
/// close is refused on TradeCpi, BatchTradeCpi and TradeNoCpi (104); the worse-side close and
/// the no-lag control land. (Before the fix the rule fired only while pinned: these landed.)
#[test]
fn v22_lag_without_pin_refuses_the_favourable_close_on_every_trade_tag() {
    // TradeCpi (tag 10) + BatchTradeCpi.
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    lagged_not_pinned(&mut env, short.1, lp.account);
    let r = env.trade_cpi(&short.0, short.1, &lp, 50 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPinned), "TradeCpi favourable close while lagged");
    let r = env.batch_trade_cpi(&short.0, short.1, &lp, 50 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPinned), "BatchTradeCpi favourable close while lagged");
    env.crank(long.1).expect("crank long");
    let r = env.trade_cpi(&long.0, long.1, &lp, -50 * Q);
    assert!(r.is_ok(), "worse-side close while lagged lands: {r:?}");
    // No lag: the same favourable close lands once the staircase has caught up.
    for _ in 0..40 {
        env.warp(1);
        env.push(PRICE * 1_005 / 1_000);
        for p in [long.1, short.1, lp.account] {
            let _ = env.crank(p);
        }
        let a = env.engine_asset();
        if a.effective_price == a.raw_oracle_target_price {
            break;
        }
    }
    let a = env.engine_asset();
    assert_eq!(a.effective_price, a.raw_oracle_target_price, "caught up");
    let r = env.trade_cpi(&short.0, short.1, &lp, 50 * Q);
    assert!(r.is_ok(), "control: no lag, the close lands: {r:?}");
    env.assert_conservation();

    // TradeNoCpi (tag 6): the long and the short close against each other; the short's
    // (favourable) side is refused while lagged.
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    lagged_not_pinned(&mut env, short.1, lp.account);
    env.crank(long.1).expect("crank long");
    let r = env.trade_nocpi(&short.0, short.1, &long.0, long.1, 10 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPinned), "TradeNoCpi favourable close while lagged");
    env.assert_conservation();
}

/// D-1 per-tag: Withdraw pays out only from a FLAT account (engine `withdraw_not_atomic`
/// refuses any active leg), so a lagged mark can never price a withdrawal. Positioned ->
/// refused; the same account after closing -> lands.
#[test]
fn v22_lag_withdraw_needs_a_flat_account() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    lagged_not_pinned(&mut env, short.1, lp.account);
    let r = env.withdraw(&long.0, long.1, 1);
    assert!(r.is_err(), "a positioned account cannot withdraw while lagged: {r:?}");
    // Control: a flat account withdraws while the asset lags.
    let flat = env.trader(10 * USD);
    let r = env.withdraw(&flat.0, flat.1, USD);
    assert!(r.is_ok(), "flat withdraw is not mark-dependent: {r:?}");
    env.assert_conservation();
}

/// D-1: ONE shared lag predicate. Every mark-lag comparison in the wrapper is
/// `asset_target_differs_view` (or `asset_price_lagged_view` on top of it), and every
/// payout-bearing consumer calls it: the favourable-close rule (trade tags), the custody
/// domain-withdraw gate, the ADL wind-down gate (tag 104), the pending-mark fee-sync gate and
/// the Earn senior pricing bounds (tags 75/77). Negative control: an ad-hoc comparison added
/// anywhere turns the count red.
#[test]
fn v22_d1_every_lag_consumer_uses_the_shared_predicate() {
    let src = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/v16_program.rs")).unwrap();
    let body = |name: &str| -> String {
        let start = src.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("fn {name}"));
        let rest = &src[start + 3..];
        let end = rest.find("\n    fn ").or_else(|| rest.find("\n    pub(crate) fn ")).unwrap();
        rest[..end].to_string()
    };
    // The comparison exists exactly once (the predicate), plus the unrelated "did the crank
    // change the target" check in the auto-crank fee attribution.
    let raw = src.matches("raw_oracle_target_price.get() != asset.effective_price.get()").count();
    assert_eq!(raw, 1, "one raw lag comparison: inside asset_target_differs_view");
    assert!(body("asset_target_differs_view").contains("raw_oracle_target_price.get() != asset.effective_price.get()"));
    assert!(body("asset_price_lagged_view").contains("asset_target_differs_view(asset)"));
    for (consumer, uses) in [
        ("reject_band_favourable_close_view", "asset_price_lagged_view("),
        ("reject_exposed_target_effective_lag_view", "asset_price_lagged_view("),
        ("vault_lp_equity_lag_bounds_ro", "asset_price_lagged_view("),
        ("reject_portfolio_pending_price_managed_mark_view", "asset_target_differs_view("),
        ("live_domain_withdraw_health_or_shutdown_view", "reject_exposed_target_effective_lag_view("),
        ("reject_adl_wind_down_unfresh_mark_view", "reject_exposed_target_effective_lag_view("),
    ] {
        assert!(body(consumer).contains(uses), "{consumer} must call {uses}");
    }
    // No other comparison of the raw target against the effective price.
    let ad_hoc = src
        .lines()
        .filter(|l| l.contains("raw_oracle_target_price") && l.contains("effective_price") && !l.trim_start().starts_with("//"))
        .count();
    assert_eq!(ad_hoc, 1, "only the predicate compares target and P_last on one line");
}

/// Review E-M1 (wrapper): InitMarket writes the per-side position cap (256) on a band market
/// and 0 off-band; the two new refusals have pinned codes.
#[test]
fn v22_band_market_carries_the_position_cap_and_codes_are_pinned() {
    let env = Env::new(band_cfg());
    let data = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::read_market(&data).unwrap();
    assert_eq!(group.config.band_max_positions_per_side, 256);
    let env0 = Env::new(Cfg { slots: 1, phase4: Some(phase4(0, RENT_MAX)), r_gap: 400 });
    let data = env0.svm.get_account(&env0.market).unwrap().data;
    let (_, group) = state::read_market(&data).unwrap();
    assert_eq!(group.config.band_max_positions_per_side, 0);
    assert_eq!(PercolatorError::PriceBandPositionCap as u32, 111);
    assert_eq!(PercolatorError::PriceBandTooNarrow as u32, 112);
    assert_eq!(
        percolator_prog::error::map_v16_error(percolator::V16Error::BandPositionCap),
        PercolatorError::PriceBandPositionCap.into()
    );
    assert_eq!(
        percolator_prog::error::map_v16_error(percolator::V16Error::BandTooNarrow),
        PercolatorError::PriceBandTooNarrow.into()
    );
}

/// Review E-L1 (wrapper): a band market whose genesis band is narrower than 32 ticks is
/// refused (105); the same market at a price with a wide-enough band is accepted, and the same
/// tiny price without a band is accepted.
#[test]
fn v22_band_market_refuses_a_too_narrow_genesis_band() {
    let at = |price: u64, cfg: Cfg| {
        INIT_PRICE.with(|p| p.set(price));
        let r = Env::try_new(cfg).map(|_| ());
        INIT_PRICE.with(|p| p.set(PRICE));
        r
    };
    // d = 100 bps: width = floor(1.01 p) - ceil(0.99 p) >= 32 from p ~ 1,600.
    let r = at(1_000, band_cfg());
    assert!(r.as_ref().is_err_and(|e| e.contains(&code(PercolatorError::PriceBandConfigInvalid))), "{r:?}");
    assert!(at(PRICE, band_cfg()).is_ok(), "a launch far above the floor is accepted");
    // band off: no width rule (105); Wave A's 1e7 launch floor (119) is the only price rule left
    let r = at(1_000, Cfg { slots: 1, phase4: Some(phase4(0, RENT_MAX)), r_gap: 400 });
    assert!(r.as_ref().is_err_and(|e| e.contains(&code(PercolatorError::LotConfigInvalid))), "{r:?}");
}

/// Review W-M1: rent must bite on a rent market: `rent_max >= 10 e9/slot` and `kink <= 80%`
/// (106), boundaries accepted; no rent (0) is unaffected.
#[test]
fn v22_rent_floor_and_kink_cap() {
    use percolator_prog::growth_v19 as gv;
    assert!(gv::rent_params_ok(0, 9_999), "rent off");
    assert!(gv::rent_params_ok(gv::RENT_MIN_E9_PER_SLOT, gv::RENT_MAX_KINK_BPS));
    assert!(!gv::rent_params_ok(gv::RENT_MIN_E9_PER_SLOT - 1, 0), "below the floor");
    assert!(!gv::rent_params_ok(1, 9_999), "the review's rent_max = 1, kink = 9999");
    assert!(!gv::rent_params_ok(23, gv::RENT_MAX_KINK_BPS + 1), "kink above 80%");
    let mk = |rent_max: u32, kink: u16| {
        let mut p = phase4(BAND_BPS, rent_max);
        p.rent_kink_bps = kink;
        Env::try_new(Cfg { slots: 1, phase4: Some(p), r_gap: 0 }).map(|_| ())
    };
    let rent_err = code(PercolatorError::HoldingRentConfigInvalid);
    assert!(mk(9, RENT_KINK).is_err_and(|e| e.contains(&rent_err)));
    assert!(mk(23, 8_001).is_err_and(|e| e.contains(&rent_err)));
    assert!(mk(10, 8_000).is_ok(), "both boundaries accepted");
}

/// Review (rent overflow): an out-of-domain rent rate charges the CEILING, never 0.
#[test]
fn v22_rent_rate_overflow_fails_closed() {
    use percolator_prog::growth_v19 as gv;
    assert_eq!(gv::rent_rate_e9(u128::MAX, 1, 0, 23), None, "the raw rate overflows");
    assert_eq!(gv::rent_rate_e9_fail_closed(u128::MAX, 1, 0, 23), 23, "charged at the ceiling");
    assert_eq!(gv::rent_rate_e9_fail_closed(0, 1, 5_000, 23), 0, "in domain: unchanged");
}

/// Review W-M2: mainnet caps (no `devnet` feature): lambda <= 3x and alpha <= 60% on a band
/// market; devnet keeps the design's 10x / 70%. This BPF test binary is built with
/// `--features devnet`; `tests/sec_v22b_pure.rs` pins both builds.
#[test]
fn v22_band_lambda_and_alpha_caps_follow_the_build() {
    use percolator_prog::growth_v19 as gv;
    #[cfg(feature = "devnet")]
    {
        assert_eq!(gv::BAND_LAMBDA_CAP_BPS, 100_000);
        assert_eq!(gv::ALLOC_ALPHA_MAX_BAND_BPS, 7_000);
    }
    #[cfg(not(feature = "devnet"))]
    {
        assert_eq!(gv::BAND_LAMBDA_CAP_BPS, 30_000);
        assert_eq!(gv::ALLOC_ALPHA_MAX_BAND_BPS, 6_000);
    }
    assert!(gv::band_lambda_max_bps(500, 1).unwrap() <= gv::BAND_LAMBDA_CAP_BPS);
    assert_eq!(gv::alloc_alpha_max_bps(true), gv::ALLOC_ALPHA_MAX_BAND_BPS);
    assert!(!gv::graduation_allowed(100, 0), "graduation stays closed until depth tiers exist");
}

// ---------------------------------------------------------------------------
// D-1 completeness (security re-review N-3): every instruction is classified by the
// EXHAUSTIVE `lag_policy::lag_policy` match (a new instruction does not compile until it is),
// and every `Gated` instruction's handler reaches the shared lag predicate in the static call
// graph of `src/v16_program.rs`. Stronger than the earlier per-consumer text check: removing
// the predicate call from any gated handler (or from any helper it relies on) turns this red.
// ---------------------------------------------------------------------------

/// Blank out comments, string and char literals (keeps lifetimes and newlines).
fn strip_rust(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let n = b.len();
    let word = |i: usize| i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
    while i < n {
        let c = b[i];
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut d = 0i32;
            while i < n {
                if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    d += 1;
                    i += 2;
                    continue;
                }
                if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    d -= 1;
                    i += 2;
                    if d == 0 {
                        break;
                    }
                    continue;
                }
                if b[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if c == b'r' && i + 1 < n && (b[i + 1] == b'#' || b[i + 1] == b'"') && !word(i) {
            let mut j = i + 1;
            let mut h = 0usize;
            while j < n && b[j] == b'#' {
                h += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                let end: String = std::iter::once('"').chain(std::iter::repeat('#').take(h)).collect();
                let k = s[j + 1..].find(&end).map(|k| j + 1 + k).unwrap();
                out.push_str("\"\"");
                i = k + end.len();
                continue;
            }
        }
        let (c, i0) = if c == b'b' && i + 1 < n && (b[i + 1] == b'"' || b[i + 1] == b'\'') && !word(i) {
            (b[i + 1], i + 1)
        } else {
            (c, i)
        };
        i = i0;
        if c == b'"' {
            let mut j = i + 1;
            while j < n && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            out.push_str("\"\"");
            i = j + 1;
            continue;
        }
        if c == b'\'' {
            if i + 2 < n && b[i + 1] == b'\\' {
                let k = s[i + 2..].find('\'').map(|k| i + 2 + k).unwrap();
                out.push_str("' '");
                i = k + 1;
                continue;
            }
            if i + 2 < n && b[i + 2] == b'\'' {
                out.push_str("' '");
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// `fn name` -> body, and the set of local fns each body calls.
fn call_graph(src: &str) -> (std::collections::HashMap<String, String>, std::collections::HashMap<String, std::collections::BTreeSet<String>>) {
    let b = src.as_bytes();
    let mut bodies: std::collections::HashMap<String, String> = Default::default();
    let mut i = 0usize;
    while let Some(off) = src[i..].find("fn ") {
        let at = i + off;
        i = at + 3;
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let name: String = src[i..].chars().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').collect();
        if name.is_empty() {
            continue;
        }
        let mut j = i + name.len();
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < b.len() && b[j] == b'<' {
            let mut d = 0i32;
            while j < b.len() {
                if b[j] == b'<' { d += 1 } else if b[j] == b'>' { d -= 1; if d == 0 { j += 1; break } }
                j += 1;
            }
        }
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= b.len() || b[j] != b'(' {
            continue;
        }
        // params
        let mut d = 0i32;
        while j < b.len() {
            match b[j] { b'(' | b'[' => d += 1, b')' | b']' => { d -= 1; if d == 0 { j += 1; break } } _ => {} }
            j += 1;
        }
        // return type up to '{' or ';' at bracket depth <= 0
        let mut d = 0i32;
        while j < b.len() {
            match b[j] {
                b'(' | b'[' | b'<' => d += 1,
                b')' | b']' | b'>' => d -= 1,
                b'{' | b';' if d <= 0 => break,
                _ => {}
            }
            j += 1;
        }
        if j >= b.len() || b[j] == b';' {
            continue;
        }
        let k = j;
        let mut d = 0i32;
        while j < b.len() {
            if b[j] == b'{' { d += 1 } else if b[j] == b'}' { d -= 1; if d == 0 { break } }
            j += 1;
        }
        bodies.entry(name).or_default().push_str(&src[k..j]);
    }
    let names: std::collections::BTreeSet<String> = bodies.keys().cloned().collect();
    let mut calls: std::collections::HashMap<String, std::collections::BTreeSet<String>> = Default::default();
    for (n, body) in &bodies {
        let bb = body.as_bytes();
        let mut set = std::collections::BTreeSet::new();
        let mut p = 0usize;
        while p < bb.len() {
            if (bb[p].is_ascii_lowercase() || bb[p] == b'_') && (p == 0 || !(bb[p - 1].is_ascii_alphanumeric() || bb[p - 1] == b'_')) {
                let start = p;
                while p < bb.len() && (bb[p].is_ascii_lowercase() || bb[p].is_ascii_digit() || bb[p] == b'_') {
                    p += 1;
                }
                let w = &body[start..p];
                let mut q = p;
                if body[q..].starts_with("::<") {
                    let mut d = 0i32;
                    q += 2;
                    while q < bb.len() {
                        if bb[q] == b'<' { d += 1 } else if bb[q] == b'>' { d -= 1; if d == 0 { q += 1; break } }
                        q += 1;
                    }
                }
                while q < bb.len() && bb[q] == b' ' {
                    q += 1;
                }
                if q < bb.len() && bb[q] == b'(' && names.contains(w) {
                    set.insert(w.to_string());
                }
                continue;
            }
            p += 1;
        }
        calls.insert(n.clone(), set);
    }
    (bodies, calls)
}

#[test]
fn v22_d1_lag_policy_is_complete_and_gated_handlers_reach_the_predicate() {
    use percolator_prog::lag_policy::LagPolicy;
    let raw = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/v16_program.rs")).unwrap();
    let src = strip_rust(&raw);
    // 1. The instruction enum's variants.
    let e = src.find("pub enum Instruction {").unwrap();
    let body_start = e + "pub enum Instruction ".len();
    let mut d = 0i32;
    let mut end = body_start;
    for (k, ch) in src[body_start..].char_indices() {
        if ch == '{' { d += 1 } else if ch == '}' { d -= 1; if d == 0 { end = body_start + k; break } }
    }
    let mut variants = std::collections::BTreeSet::new();
    let mut depth = 0i32;
    for line in src[body_start + 1..end].lines() {
        let t = line.trim();
        if depth == 0 {
            let name: String = t.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                variants.insert(name);
            }
        }
        depth += line.matches(['{', '(']).count() as i32 - line.matches(['}', ')']).count() as i32;
    }
    assert!(variants.len() >= 90, "parsed {} variants", variants.len());
    // 2. The exhaustive classification names each exactly once.
    let lp = &raw[raw.find("pub mod lag_policy").unwrap()..];
    let mut classified = std::collections::BTreeMap::new();
    for cap in lp.split("=> entry(\"").skip(1) {
        let name = &cap[..cap.find('"').unwrap()];
        let rest = &cap[cap.find("LagPolicy::").unwrap() + 11..];
        let pol = match &rest[..rest.find(',').unwrap()] {
            "Gated" => LagPolicy::Gated,
            "FlatOnly" => LagPolicy::FlatOnly,
            "MarkDriven" => LagPolicy::MarkDriven,
            "MarkFree" => LagPolicy::MarkFree,
            other => panic!("unknown policy {other}"),
        };
        assert!(classified.insert(name.to_string(), pol).is_none(), "{name} classified twice");
    }
    let names: std::collections::BTreeSet<String> = classified.keys().cloned().collect();
    assert_eq!(names, variants, "lag_policy classifies exactly the instruction set");
    // 3. Dispatch: variant -> handler.
    let disp = &src[src.find("ix @ Instruction::InitMarket { .. } =>").unwrap()..];
    let mut handler = std::collections::BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in disp.lines().take(1200) {
        if let Some(p) = line.find("Instruction::") {
            let v: String = line[p + 13..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if variants.contains(&v) {
                cur = Some(v);
            }
        }
        if let (Some(v), Some(p)) = (cur.as_ref(), line.find("handle_")) {
            let h: String = line[p..].chars().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_').collect();
            handler.entry(v.clone()).or_insert(h);
        }
    }
    // 4. Reachability of the shared predicate (fixed point over the call graph).
    let (bodies, calls) = call_graph(&src);
    let mut reach: std::collections::BTreeSet<String> =
        ["asset_price_lagged_view", "asset_target_differs_view"].iter().map(|s| s.to_string()).collect();
    loop {
        let before = reach.len();
        for (n, cs) in &calls {
            if !reach.contains(n) && cs.iter().any(|c| reach.contains(c)) {
                reach.insert(n.clone());
            }
        }
        if reach.len() == before {
            break;
        }
    }
    let mut gated = 0;
    for (v, pol) in &classified {
        if *pol != LagPolicy::Gated {
            continue;
        }
        gated += 1;
        let h = handler.get(v).unwrap_or_else(|| panic!("no handler found for gated {v}"));
        assert!(bodies.contains_key(h), "handler {h} parsed");
        assert!(reach.contains(h), "{v}: handler {h} does not reach the shared lag predicate");
    }
    assert!(gated >= 21, "gated instructions: {gated}");
}

// ---------------------------------------------------------------------------
// Security re-review N-1 / N-2 (wrapper side).
// ---------------------------------------------------------------------------

impl Env {
    /// STATE POKE (test only): move the still-flat asset's engine price, anchor and funding
    /// reference to `price`, then push the auth mark there, so a book can be opened near the
    /// narrow-band floor without walking a launch price down for hundreds of epochs.
    fn poke_flat_asset_price(&mut self, price: u64) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, g) = state::market_view_mut(&mut acct.data).unwrap();
            let a = &mut g.markets[0].engine.asset;
            assert_eq!(a.oi_eff_long_q.get() + a.oi_eff_short_q.get(), 0, "flat asset only");
            a.effective_price = percolator::V16PodU64::new(price);
            a.raw_oracle_target_price = percolator::V16PodU64::new(price);
            a.fund_px_last = percolator::V16PodU64::new(price);
            a.band_anchor_price = percolator::V16PodU64::new(price);
        }
        self.svm.set_account(self.market, acct).unwrap();
        self.warp(1);
        self.push(price);
    }
}

/// N-1: the band block's minimum leg notional is floored at 10 whole collateral tokens (105),
/// and a trade that would leave a sub-floor leg is refused (113) while the full close lands.
#[test]
fn v22_band_min_leg_notional_floor_and_dust_refusal() {
    let mk = |min: u64| {
        let mut p = phase4(BAND_BPS, RENT_MAX);
        p.band_min_leg_notional = min;
        Env::try_new(Cfg { slots: 1, phase4: Some(p), r_gap: 0 }).map(|_| ())
    };
    let cfg_err = code(PercolatorError::PriceBandConfigInvalid);
    assert!(mk(BAND_MIN_LEG - 1).is_err_and(|e| e.contains(&cfg_err)), "below the 10-token floor");
    assert!(mk(BAND_MIN_LEG).is_ok());
    assert_eq!(percolator_prog::growth_v19::band_min_leg_notional_floor(6), BAND_MIN_LEG);
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let t = env.trader(1_000 * USD);
    // $5 open: below the $10 floor.
    let r = env.trade_cpi(&t.0, t.1, &lp, 5 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandLegBelowMinNotional), "dust open");
    env.trade_cpi(&t.0, t.1, &lp, 30 * Q).expect("$30 open");
    let r = env.trade_cpi(&t.0, t.1, &lp, -25 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandLegBelowMinNotional), "reduce to $5 dust");
    env.trade_cpi(&t.0, t.1, &lp, -20 * Q).expect("reduce to $10");
    // The bound vault LP is exempt: its leg is the NET of its takers and may be any size. A
    // second taker leaves the LP net short $5 (below the minimum) and the fill still lands.
    let u = env.trader(1_000 * USD);
    env.trade_cpi(&u.0, u.1, &lp, -15 * Q).expect("LP net position may be sub-minimum");
    assert_eq!(env.pos(lp.account), 5 * Q, "the LP nets +$5 against a $10 long and a $15 short");
    env.trade_cpi(&u.0, u.1, &lp, 15 * Q).expect("u closes");
    env.trade_cpi(&t.0, t.1, &lp, -10 * Q).expect("full close");
    assert_eq!(env.pos(t.1), 0);
    env.assert_conservation();
}

/// N-2: genesis must be >= 100x the smallest anchor with a 32-tick band (105 below it).
#[test]
fn v22_band_genesis_needs_100x_the_width_floor() {
    let min = percolator::band_rent::band_min_wide_anchor(BAND_BPS as u64).unwrap().unwrap();
    assert_eq!(min, 1_600);
    let at = |price: u64| {
        INIT_PRICE.with(|p| p.set(price));
        let r = Env::try_new(band_cfg()).map(|_| ());
        INIT_PRICE.with(|p| p.set(PRICE));
        r
    };
    let cfg_err = code(PercolatorError::PriceBandConfigInvalid);
    assert!(at(min * 100 - 1).is_err_and(|e| e.contains(&cfg_err)));
    // v2.2 combined release: at d = 100 bps Wave A's 1e7 launch floor (119) is above this rule.
    let lot_err = code(PercolatorError::LotConfigInvalid);
    assert!(at(min * 100).is_err_and(|e| e.contains(&lot_err)), "A's floor binds above B's rule");
    assert!(at(10_000_000).is_ok());
}

/// N-2: Wave A's launch floor (`LOT_PRICE_FLOOR_E6` = 1e7, feat/v22-wave-a) applies to every
/// GROWTH market, and every band market is a growth market (the band block only exists inside
/// `InitMarketV22`, which carries the growth block). At 1e7 the 100x rule above is implied
/// for every d >= 2 bps; at d = 1 this branch's own rule is the binding one, so the check
/// lives here regardless of the merge order.
#[test]
fn v22_band_markets_are_growth_markets_so_wave_a_floor_binds() {
    use percolator::band_rent::{band_min_wide_anchor, BAND_GENESIS_FLOOR_MULTIPLE};
    // Structural: there is no wire form of a band block outside the growth trailer.
    let ProgInstruction::InitMarketV19 { market, .. } = init_market_ix(&Cfg { slots: 1, phase4: None, r_gap: 400 }) else { panic!() };
    let mut legacy_with_band = market.encode();
    legacy_with_band.extend_from_slice(&[0u8; 18]);
    assert!(ProgInstruction::decode(&legacy_with_band).is_err(), "no band without growth");
    // Numeric: Wave A's 1e7 floor vs this branch's genesis rule.
    const WAVE_A_LOT_PRICE_FLOOR_E6: u64 = 10_000_000;
    for d in 2u64..=percolator::band_rent::MAX_BAND_BPS {
        let need = band_min_wide_anchor(d).unwrap().unwrap() * BAND_GENESIS_FLOOR_MULTIPLE;
        assert!(need <= WAVE_A_LOT_PRICE_FLOOR_E6, "d={d}: rule {need} above Wave A's floor");
    }
    let need = band_min_wide_anchor(1).unwrap().unwrap() * BAND_GENESIS_FLOOR_MULTIPLE;
    assert!(need > WAVE_A_LOT_PRICE_FLOOR_E6, "at d = 1 bps this branch's rule binds ({need})");
}

/// N-2: at the narrow-band floor (re-anchoring refused, the price can no longer catch up),
/// existing positions can still EXIT at P_last instead of waiting for BandPinExpired. Above the
/// floor, the same lagged favourable close is refused (104).
#[test]
fn v22_band_floor_keeps_exits_open() {
    // d = 50 bps: the width floor sits at 3,200 ticks, where the 4 bps/slot cap still moves
    // >= 1 tick per slot (at d = 100 the floor, 1,600, is below the cap's own 2,500-tick
    // dead zone and nothing would move at all).
    const D: u64 = 50;
    let mut env = Env::new(Cfg { slots: 1, phase4: Some(phase4(D as u16, RENT_MAX)), r_gap: 0 });
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let long = env.trader(1_000 * USD);
    env.poke_flat_asset_price(3_300);
    env.crank(lp.account).ok();
    env.trade_cpi(&long.0, long.1, &lp, 20_000 * POS_SCALE as i128).expect("open long ($33)");
    let mut refused_above_floor = false;
    let mut refused_narrow_unpinned = false;
    for _ in 0..400 {
        env.warp(1);
        env.push(1);
        let r1 = env.crank(long.1);
        let r2 = env.crank(lp.account);
        let a = env.engine_asset();
        if std::env::var("FLOOR_DBG").is_ok() {
            eprintln!("p={} t={} anchor={} e={} r1={:?} r2={:?}", a.effective_price, a.raw_oracle_target_price, a.band_anchor_price, a.band_epoch, r1.as_ref().map_err(|e| e.split(", meta").next().unwrap().to_string()), r2.as_ref().map_err(|e| e.split(", meta").next().unwrap().to_string()));
        }
        let narrow = !percolator::band_rent::band_width_ok(a.effective_price, D).unwrap();
        let stuck = narrow && a.band_pin_since_slot != 0;
        if !narrow && !refused_above_floor && a.raw_oracle_target_price < a.effective_price {
            let r = env.trade_cpi(&long.0, long.1, &lp, -10_000 * POS_SCALE as i128);
            assert_err(&r, &code(PercolatorError::PriceBandPinned), "lagged favourable close above the floor");
            refused_above_floor = true;
        }
        // Round-2 tightening: a sub-threshold price that can STILL MOVE (not pinned: the epoch
        // window is open and the edge not reached) does not lift the refusal.
        if narrow && !stuck && !refused_narrow_unpinned {
            let r = env.trade_cpi(&long.0, long.1, &lp, -10_000 * Q);
            assert_err(&r, &code(PercolatorError::PriceBandPinned), "narrow but not pinned: still refused");
            refused_narrow_unpinned = true;
        }
        if stuck {
            break;
        }
    }
    assert!(refused_above_floor && refused_narrow_unpinned, "both controls ran");
    let a = env.engine_asset();
    assert!(!percolator::band_rent::band_width_ok(a.effective_price, D).unwrap(), "reached the floor: {}", a.effective_price);
    assert!(a.band_pin_since_slot != 0, "pinned at the edge of the last wide band");
    assert!(a.raw_oracle_target_price < a.effective_price, "still lagged");
    let r = env.trade_cpi(&long.0, long.1, &lp, -20_000 * POS_SCALE as i128);
    assert!(r.is_ok(), "exit at the floor lands: {r:?}");
    assert_eq!(env.pos(long.1), 0);
    env.assert_conservation();
}


/// N-2 companion: at d = 100 the width floor (1,600) is below the cap law's own dead zone
/// (4 bps/slot moves 0 ticks under 2,500), so the price stops there instead; exits must stay
/// open there too. Control: the same favourable close is refused at a price that can move.
#[test]
fn v22_band_cap_dead_zone_keeps_exits_open() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let long = env.trader(1_000 * USD);
    env.poke_flat_asset_price(1_660);
    env.crank(lp.account).ok();
    env.trade_cpi(&long.0, long.1, &lp, 20_000 * POS_SCALE as i128).expect("open long ($33)");
    env.warp(1);
    env.push(1);
    let _ = env.crank(long.1);
    let _ = env.crank(lp.account);
    let a = env.engine_asset();
    assert_eq!(a.effective_price, 1_660, "the cap law cannot move 1,660 at 4 bps/slot");
    assert!(a.raw_oracle_target_price < a.effective_price, "lagged");
    // A 0-tick cap step cannot move the price in either direction, pinned or not (a certified
    // book keeps re-anchoring at the same price, so no pin clock can be required here).
    let r = env.trade_cpi(&long.0, long.1, &lp, -20_000 * POS_SCALE as i128);
    assert!(r.is_ok(), "exit in the cap dead zone lands: {r:?}");
    env.assert_conservation();
}

impl Env {
    fn sweep_dust(&mut self, portfolio: Pubkey, vault_lp: Pubkey) -> Result<u64, String> {
        let (payer, m) = (self.payer.pubkey(), self.market);
        self.send(
            ProgInstruction::SweepBandDustLeg { asset_index: 0 },
            vec![
                AccountMeta::new(payer, false),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(vault_lp, false),
            ],
            &[],
        )
    }

    /// STATE POKE (test only): edit the engine config words of the market account.
    fn poke_engine_config(&mut self, f: impl FnOnce(&mut percolator::V16ConfigAccount)) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, g) = state::market_view_mut(&mut acct.data).unwrap();
            f(&mut g.header.config);
        }
        self.svm.set_account(self.market, acct).unwrap();
    }

    /// Tag 119: evict `victim`, then the taker's TradeCpi of `size_q`.
    fn evict_and_trade(
        &mut self,
        victim: Pubkey,
        taker: &Keypair,
        taker_account: Pubkey,
        lp: &Lp,
        size_q: i128,
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.identity(lp.account);
        let market_id = self.market_id();
        let (m, mp) = (self.market, self.matcher_program);
        self.send(
            ProgInstruction::EvictAndTradeCpi {
                trade: Box::new(ProgInstruction::TradeCpi {
                    account_a_portfolio_id: a_id,
                    account_a_position_epoch: a_epoch,
                    account_b_portfolio_id: b_id,
                    account_b_position_epoch: b_epoch,
                    market_id,
                    account_b_matcher_sequence: b_seq,
                    asset_index: 0,
                    size_q,
                    fee_bps: 10_000,
                    limit_price: 0,
                    backing_fee_cap_bps: 10_000,
                }),
            },
            vec![
                AccountMeta::new(victim, false),
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp.account, false),
                AccountMeta::new_readonly(mp, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[taker],
        )
    }

    fn equity(&self, p: Pubkey) -> i128 {
        let s = self.portfolio_state(p);
        s.capital as i128 + s.pnl
    }
}

/// N-1 dust sweep, tag 118 (wrapper): permissionless, but a leg at or above half the minimum
/// is not sweepable (NonProgress), and nothing is swept while the asset lags (21). The
/// positive case (a dust leg closed, slot freed) is the engine test
/// `band_dust_leg_becomes_sweepable_only_below_half_the_minimum`; the BPF fixture cannot reach
/// a >50% price fall in reasonable time at 4 bps/slot.
#[test]
fn v22_tag118_dust_sweep_refusals() {
    let ix = ProgInstruction::SweepBandDustLeg { asset_index: 3 };
    assert_eq!(ProgInstruction::decode(&ix.encode()).unwrap(), ix, "wire roundtrip");
    assert_eq!(ix.encode(), vec![118, 3, 0]);
    assert_eq!(percolator_prog::constants::TAG_SWEEP_BAND_DUST_LEG, 118, "111 / 112 / 116 / 117 are Wave D's");
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    let r = env.sweep_dust(long.1, lp.account);
    assert_err(&r, &code(PercolatorError::EngineNonProgress), "a $200 leg is not dust");
    // A dust leg can only be closed against the asset's BOUND vault LP.
    env.poke_engine_config(|c| c.band_min_leg_notional = percolator::V16PodU64::new(500 * USD as u64));
    let r = env.sweep_dust(long.1, short.1);
    assert_err(&r, &code(PercolatorError::VaultLpNotBound), "counterparty must be the bound vault LP");
    env.poke_engine_config(|c| c.band_min_leg_notional = percolator::V16PodU64::new(BAND_MIN_LEG));
    lagged_not_pinned(&mut env, short.1, lp.account);
    let r = env.sweep_dust(long.1, lp.account);
    assert_err(&r, &code(PercolatorError::EngineLockActive), "no sweep while lagged");
    assert_eq!(env.pos(long.1), 200 * Q, "untouched");
    env.assert_conservation();
}


/// Round-2 re-review N-6 (fixed): tag 118 closes the dust leg BILATERALLY against the bound
/// vault LP. `A` stays `ADL_ONE` on both sides, the swept account keeps its exact equity, and an
/// honest open still lands afterwards (the old unilateral reduce scaled the opposite side's
/// `A` and left the asset close-only, `AdlReduceOnly`).
#[test]
fn v22_tag118_bilateral_sweep_leaves_a_unchanged_and_the_market_open() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    // Test shortcut for a >50% fall: raise the market minimum so the $200 long is dust.
    env.poke_engine_config(|c| c.band_min_leg_notional = percolator::V16PodU64::new(500 * USD as u64));
    env.crank_current(long.1);
    env.crank_current(lp.account);
    let equity_before = env.equity(long.1);
    let short_leg_before = env.portfolio_state(short.1).legs.iter().find(|l| l.active).cloned().unwrap();
    env.sweep_dust(long.1, lp.account).expect("bilateral dust sweep");
    assert_eq!(env.pos(long.1), 0, "the dust leg is closed");
    assert_eq!(env.equity(long.1), equity_before, "no fee, no value moved: exact equity kept");
    let a = env.engine_asset();
    assert_eq!((a.a_long, a.a_short), (percolator::ADL_ONE, percolator::ADL_ONE), "A unchanged");
    assert_eq!(
        env.portfolio_state(short.1).legs.iter().find(|l| l.active).cloned().unwrap(),
        short_leg_before,
        "nobody else's leg was scaled"
    );
    assert_eq!(env.pos(lp.account), 100 * Q, "the LP absorbed the leg (net of the short taker)");
    // The market is still open: an honest newcomer's open lands.
    env.poke_engine_config(|c| c.band_min_leg_notional = percolator::V16PodU64::new(BAND_MIN_LEG));
    let honest = env.trader(1_000 * USD);
    env.trade_cpi(&honest.0, honest.1, &lp, 30 * Q).expect("honest open after the sweep");
    env.assert_conservation();
}

/// Round-2 re-review N-1b: replace-smallest eviction (tag 119). With the long side full
/// (cap poked to 2 for the test), an honest taker bringing >= 2x the smallest leg gets in: the
/// evicted leg is closed against the bound vault LP at the mark with no fee (its account keeps
/// its exact equity), then the taker's own TradeCpi lands. Too small a fill, a side that is
/// not full, or a victim on the other side are refused (111) and nothing is evicted.
#[test]
fn v22_tag119_eviction_lets_an_honest_trader_into_a_full_side() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let a = env.trader(1_000 * USD);
    let b = env.trader(1_000 * USD);
    let honest = env.trader(1_000 * USD);
    let short = env.trader(1_000 * USD);
    env.trade_cpi(&a.0, a.1, &lp, 10 * Q).expect("filler a ($10, the minimum)");
    env.trade_cpi(&b.0, b.1, &lp, 10 * Q).expect("filler b");
    env.trade_cpi(&short.0, short.1, &lp, -10 * Q).expect("a short, for the wrong-side control");
    env.poke_engine_config(|c| c.band_max_positions_per_side = percolator::V16PodU64::new(2));
    // Locked out without eviction.
    let r = env.trade_cpi(&honest.0, honest.1, &lp, 30 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPositionCap), "the long side is full");
    // Refusals: under 2x the victim, and a victim on the other side.
    let r = env.evict_and_trade(a.1, &honest.0, honest.1, &lp, 19 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPositionCap), "19 < 2 x 10");
    let r = env.evict_and_trade(short.1, &honest.0, honest.1, &lp, 30 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPositionCap), "victim on the other side");
    assert_eq!(env.pos(a.1), 10 * Q, "nothing was evicted by the refused attempts");
    // The eviction.
    let equity_before = env.equity(a.1);
    env.evict_and_trade(a.1, &honest.0, honest.1, &lp, 30 * Q).expect("evict + open");
    assert_eq!(env.pos(a.1), 0, "the smallest leg was closed");
    assert_eq!(env.equity(a.1), equity_before, "the evicted account lost nothing but the position");
    assert_eq!(env.pos(honest.1), 30 * Q, "the honest trader is in");
    let asset = env.engine_asset();
    assert_eq!((asset.a_long, asset.a_short), (percolator::ADL_ONE, percolator::ADL_ONE));
    // Side not full: no eviction (b closes, then the same attempt is refused).
    env.trade_cpi(&b.0, b.1, &lp, -10 * Q).expect("b leaves");
    let late = env.trader(1_000 * USD);
    let r = env.evict_and_trade(honest.1, &late.0, late.1, &lp, 80 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPositionCap), "the side is not full");
    env.trade_cpi(&late.0, late.1, &lp, 80 * Q).expect("an ordinary open lands on a free slot");
    env.assert_conservation();
}
