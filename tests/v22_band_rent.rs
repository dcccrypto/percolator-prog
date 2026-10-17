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

#[path = "support/fill_events.rs"]
mod fill_events;

thread_local! {
    /// v2.2 fill events: logs of the last transaction (success or failure) sent by this thread.
    static LAST_LOGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

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
    /// G8 tests: the growth block's `l_launch` of the next `Env::new` on this thread.
    static L_LAUNCH: std::cell::Cell<u16> = const { std::cell::Cell::new(1_000) };
    /// R2 tier tests: `(engine IMR, MMR, liquidation fee, min_nonzero_mm_req)` of the next
    /// `Env::new` on this thread (default: the 10x market of the module doc); the IM floor is
    /// twice the MM floor.
    /// R2-L2 tests: the collateral mint's decimals of the next `Env::new` on this thread.
    static MINT_DECIMALS: std::cell::Cell<u8> = const { std::cell::Cell::new(6) };
    static MKT: std::cell::Cell<(u64, u64, u64, u128)> = const { std::cell::Cell::new((ENGINE_IMR, MMR, LIQ_FEE, 10)) };
    /// v2.2 F1 tests: `max_abs_funding_e9_per_slot` of the next `Env::new` on this thread.
    static FUNDING_E9: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
}

#[allow(dead_code)]
pub fn cu_rec(data: &[u8], cu: u64) {
    if let Ok(path) = std::env::var("CU_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(format!("CUREC {} {}\n", data.first().copied().unwrap_or(255), cu).as_bytes());
        }
    }
}

fn code(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
}

thread_local! {
    /// v2.2 F1 differential tests: the wrapper binary of the next `Env::new` on this thread
    /// (None = the usual `GROWTH_WRAPPER_SO` / `target/deploy` choice).
    static PROG_SO: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn program_path() -> PathBuf {
    if let Some(p) = PROG_SO.with(|p| p.borrow().clone()) {
        return p;
    }
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
            decimals: MINT_DECIMALS.with(|d| d.get()),
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
        min_nonzero_mm_req: MKT.with(|m| m.get().3),
        min_nonzero_im_req: 2 * MKT.with(|m| m.get().3),
        maintenance_margin_bps: MKT.with(|m| m.get().1),
        initial_margin_bps: MKT.with(|m| m.get().0),
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: MKT.with(|m| m.get().2),
        liquidation_fee_cap: 1_000_000_000_000_000,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 4,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: FUNDING_E9.with(|f| f.get()),
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
            growth_l_launch_x100: L_LAUNCH.with(|l| l.get()),
        },
        Some(p) => ProgInstruction::InitMarketV22 {
            market: Box::new(base),
            growth_r_gap_bps: c.r_gap,
            growth_l_launch_x100: L_LAUNCH.with(|l| l.get()),
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
    /// The engine IMR this market was created with (`MKT`).
    engine_imr: u64,
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
            engine_imr: MKT.with(|m| m.get().0),
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
        let __d = instruction.data.clone();
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
        match self.svm.send_transaction(tx) {
            Ok(m) => {
                LAST_LOGS.with(|l| *l.borrow_mut() = m.logs.clone());
                cu_rec(&__d, m.compute_units_consumed);
                Ok(m.compute_units_consumed)
            }
            Err(e) => {
                LAST_LOGS.with(|l| *l.borrow_mut() = e.meta.logs.clone());
                Err(format!("{e:?}"))
            }
        }
    }

    /// v2.2 fill events the wrapper emitted in the last transaction (frame-attributed).
    fn events(&self) -> Vec<fill_events::Event> {
        fill_events::wrapper_events(&LAST_LOGS.with(|l| l.borrow().clone()), &self.program_id)
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
    /// GH#552: the owner-signed exit (tag 44) -- the close the app actually sends.
    fn rebalance_reduce(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        reduce_q: u128,
    ) -> Result<u64, String> {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        let portfolio_id = state::read_portfolio_id(&data).unwrap();
        let position_epoch = state::read_portfolio_position_epoch(&data).unwrap();
        let m = self.market;
        self.send(
            ProgInstruction::RebalanceReduce {
                portfolio_id,
                position_epoch,
                asset_index: 0,
                reduce_q,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
    }

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
        state::read_asset_growth(&self.svm.get_account(&self.market).unwrap().data, 0, self.engine_imr)
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
    // v2.2 fill events: the MOVE event states exactly the atoms routed to the vault LP.
    assert_eq!(
        env.events(),
        vec![fill_events::Event::Move {
            ix_tag: 106,
            market: env.market,
            sub: 3,
            asset_index: 0,
            a: lp_gain as u64,
            b: 0,
            c: 0,
        }]
    );
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
    /// AUD-S1-4: tag 106 accrues at most one capped segment (`max_accrual_dt_slots`) per call, so
    /// after a gap it is repeated until the asset is caught up (the keeper's catch-up sequence).
    fn settle_rent_caught_up(&mut self, portfolio: Pubkey, vault_lp: Pubkey) {
        for _ in 0..64 {
            self.settle_rent(portfolio, vault_lp).expect("tag 106 (catch-up)");
            if self.engine_asset().slot_last >= self.slot {
                return;
            }
        }
        panic!("tag 106 catch-up did not converge: slot_last {} clock {} env.slot {}", self.engine_asset().slot_last, self.clock_slot(), self.slot);
    }

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

    // (c) double charge: once caught up, a second tag 106 in the same slot charges nothing more.
    // AUD-S1-4: a 2-slot gap is two capped segments (max_accrual_dt_slots = 1); both are
    // rent-bearing, so the catch-up takes two calls (before the fix the second slot was accrued
    // rent-free inside the first call, which is what this step used to rely on).
    env.warp(2);
    env.push(PRICE);
    env.settle_rent_caught_up(taker.1, lp.account);
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

/// AUD-S1-4 (fix-all 2026-10-18): after a gap longer than `max_accrual_dt_slots` (1 in this
/// env), every slot that tag 106 accrues must be rent-bearing, and one call must process at most
/// one capped segment. Before the fix the engine Refresh inside tag 106 accrued a SECOND capped
/// segment with rent 0, so a catch-up driven by tag 106 alone charged rent for about half of the
/// gap (the vault LP lost the rest) and advanced the asset two segments per instruction.
#[test]
fn s1_4_tag106_catch_up_accrues_rent_on_every_slot_one_segment_per_call() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 800 * Q).expect("crowd open");
    for _ in 0..100 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    // Caught up: one slot of rent through tag 106 is the per-slot rate.
    env.warp(1);
    env.push(PRICE);
    let i0 = env.engine_asset().rent_index_long_num;
    env.settle_rent(taker.1, lp.account).expect("tag 106, one slot");
    assert_eq!(env.engine_asset().slot_last, env.slot, "a one-slot gap is caught up in one call");
    let i1 = env.engine_asset().rent_index_long_num;
    let per_slot = i1 - i0;
    assert!(per_slot > 0, "the crowd side pays rent above the kink");
    // A 10-slot gap (10x the accrual cap), caught up by tag 106 calls only.
    const GAP: u64 = 10;
    env.warp(GAP);
    env.push(PRICE);
    let cap0 = env.portfolio_state(taker.1).capital;
    let mut calls = 0u64;
    while env.engine_asset().slot_last < env.slot {
        let before = env.engine_asset().slot_last;
        env.settle_rent(taker.1, lp.account).expect("tag 106 during catch-up");
        calls += 1;
        let after = env.engine_asset().slot_last;
        assert!(after > before, "every call makes progress");
        assert!(after - before <= 1, "one capped segment per call: {before} -> {after}");
        assert!(calls <= 2 * GAP, "catch-up did not converge");
    }
    assert_eq!(calls, GAP, "one call per capped segment");
    let i2 = env.engine_asset().rent_index_long_num;
    let accrued = i2 - i1;
    // The rate is constant here (same price, same OI, same N_cap): allow one slot of drift for
    // the per-slot rounding of the index and nothing more. Before the fix: about GAP/2 slots.
    assert!(
        accrued + per_slot >= GAP as u128 * per_slot,
        "rent accrued on {} of {GAP} slots (index +{accrued}, per slot {per_slot})",
        accrued / per_slot
    );
    // The taker's capital moved by exactly the rent the index says it owes over the gap.
    let charged = cap0 - env.portfolio_state(taker.1).capital;
    let q = 800 * POS_SCALE / 10;
    let due = percolator::band_rent::rent_due_atoms(q, i2, i1).unwrap();
    assert!(charged <= due + 1 && charged + 1 >= due, "charged {charged} vs due {due}");
    // Caught up: a further call in the same slot charges nothing.
    env.settle_rent(taker.1, lp.account).expect("tag 106, same slot");
    assert_eq!(charged, cap0 - env.portfolio_state(taker.1).capital, "no double charge");
    assert_eq!(i2, env.engine_asset().rent_index_long_num);
    env.assert_conservation();
}

/// AUD-FC-A follow-up (fix-all 2026-10-18): a refresh/liquidation crank refused with
/// EngineNonProgress (22) because a held asset lags the clock now says so in a distinct log line
/// (the error code is unchanged), so a third-party liquidator can tell why and run the catch-up.
#[test]
fn fca_lagging_asset_refusal_logs_a_distinct_line() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 100 * Q).expect("open");
    env.warp(5);
    env.push(PRICE);
    // A crank with NO observation hint: nothing can accrue the asset, so the engine refuses.
    let (payer, m, slot) = (env.payer.pubkey(), env.market, env.slot);
    let r = env.send(
        ProgInstruction::PermissionlessCrank { now_slot: slot, observations: vec![] },
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(m, false),
            AccountMeta::new(taker.1, false),
        ],
        &[],
    );
    assert_err(&r, &code(PercolatorError::EngineNonProgress), "lagging asset, no observation");
    let e = r.unwrap_err();
    assert!(
        e.contains("percolator: refresh_refused_asset_lags asset=0 cause="),
        "the refusal names the lagging asset: {e}"
    );
    assert!(e.contains(&format!("now={}", env.clock_slot())), "and the clock: {e}");
    // The documented catch-up (observe-cranks, one capped segment each) then succeeds.
    for _ in 0..20 {
        if env.engine_asset().slot_last >= env.slot {
            break;
        }
        env.crank(taker.1).expect("observe-crank (one capped segment)");
    }
    assert_eq!(env.engine_asset().slot_last, env.slot);
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

/// GH#552: the band's favourable-side close rule must bind the OWNER-SIGNED reduce (tag 44),
/// not only the trade executors. Tag 44 is the exit the app sends, and the owner picks its
/// size and its moment, so it is a user-chosen close in exactly the sense the rule governs —
/// it was classified `MarkDriven` ("engine-driven reduction") and so escaped the gate.
///
/// Same world as `sec_pinned_close_flip_and_open_variants` above: pinned, target ABOVE
/// P_last, so the SHORT is the favourable side. Without the fix every reduce below lands and
/// takes `(P_last - target) x q` from the opposite side and the bound vault LP.
#[test]
fn sec_pinned_close_refused_for_the_owner_signed_rebalance_reduce() {
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

    // The short (-100) buys back at the stale-low P_last while the true target is above it:
    // favourable. Full, partial and dust reduces are all refused, as on the trade path.
    for q in [100 * Q, 50 * Q, Q] {
        let r = env.rebalance_reduce(&short.0, short.1, q as u128);
        eprintln!("GH#552 pinned short tag-44 reduce {q}: {r:?}");
        assert!(
            r.is_err() && r.as_ref().unwrap_err().contains(&pin),
            "tag 44 must refuse the favourable-side exit at the pinned price: q={q}, {r:?}"
        );
    }
    assert_eq!(env.pos(short.1), -100 * Q, "the refused reduces left the position untouched");

    // Control: the LONG is the UNFAVOURABLE side here, so the rule must not touch it. Assert
    // only that it is not refused BY THE BAND — an unrelated engine refusal is not this gate.
    let r = env.rebalance_reduce(&long.0, long.1, (10 * Q) as u128);
    eprintln!("GH#552 pinned long tag-44 reduce (control): {r:?}");
    assert!(
        r.is_ok() || !r.as_ref().unwrap_err().contains(&pin),
        "the unfavourable side must not be refused by the band rule: {r:?}"
    );
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
        // GH#552: the rule is now a predicate (`band_favourable_close_refused_view`) so the
        // trade executors and the owner-signed reduce (tag 44) share ONE copy of it. The lag
        // call lives in the predicate; the `ProgramResult` form delegates to it.
        ("band_favourable_close_refused_view", "asset_price_lagged_view("),
        ("reject_band_favourable_close_view", "band_favourable_close_refused_view("),
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
    let long_pos_before = env.pos(long.1);
    let pe = |env: &Env, k: Pubkey| state::read_portfolio_position_epoch(&env.svm.get_account(&k).unwrap().data).unwrap();
    let (victim_epoch0, lp_epoch0) = (pe(&env, long.1), pe(&env, lp.account));
    env.sweep_dust(long.1, lp.account).expect("bilateral dust sweep");
    // AUD-S1-23: the swept victim's position changed without its owner, so its position_epoch
    // advances (a stale owner-signed action built before the sweep is refused); the vault LP
    // (no owner-signed retained actions) is not advanced.
    assert_eq!(pe(&env, long.1), victim_epoch0 + 1, "S1-23: sweep advances the victim's position_epoch");
    assert_eq!(pe(&env, lp.account), lp_epoch0, "the vault LP's epoch is untouched");
    // v2.2 fill events: one REDUCE (reason 4, tag 118) closing the whole leg against the LP at P_last.
    assert_eq!(
        env.events(),
        vec![fill_events::Event::Reduce {
            ix_tag: 118,
            market: env.market,
            portfolio: long.1,
            counterparty: lp.account,
            asset_index: 0,
            asset_gen: env.market_id(),
            reason: 4,
            signed_reduced_q: -long_pos_before,
            price_e6: env.engine_asset().effective_price,
        }]
    );
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

/// Round-2 re-review N-1b: eviction of a small leg (tag 119). With the long side full
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
    let pe = |env: &Env, k: Pubkey| state::read_portfolio_position_epoch(&env.svm.get_account(&k).unwrap().data).unwrap();
    let victim_epoch0 = pe(&env, a.1);
    env.evict_and_trade(a.1, &honest.0, honest.1, &lp, 30 * Q).expect("evict + open");
    // AUD-S1-23: the evicted victim's position changed without its owner.
    assert_eq!(pe(&env, a.1), victim_epoch0 + 1, "S1-23: eviction advances the victim's position_epoch");
    // v2.2 fill events: REDUCE (the victim's whole leg, tag 119, reason 5) then the taker's FILL
    // (the inner TradeCpi reports its own tag 10), in execution order.
    let evs = env.events();
    assert_eq!(evs.len(), 2, "{evs:?}");
    assert_eq!(
        evs[0],
        fill_events::Event::Reduce {
            ix_tag: 119,
            market: env.market,
            portfolio: a.1,
            counterparty: lp.account,
            asset_index: 0,
            asset_gen: env.market_id(),
            reason: 5,
            signed_reduced_q: -10 * Q,
            price_e6: env.engine_asset().effective_price,
        }
    );
    let fill_events::Event::Fill { ix_tag, taker, lp: ev_lp, recs, .. } = &evs[1] else {
        panic!("expected the inner trade's FILL: {evs:?}")
    };
    assert_eq!((*ix_tag, *taker, *ev_lp), (10, honest.1, lp.account));
    assert_eq!(recs.len(), 1);
    assert_eq!((recs[0].requested_q, recs[0].executed_q), (30 * Q, 30 * Q));
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

// ===========================================================================
// SENTINEL round 3: tag 119 adversarial tests (ported from the review)
// ===========================================================================

fn sec_full_long_side(env: &mut Env) -> (Lp, (Keypair, Pubkey), (Keypair, Pubkey)) {
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let small = env.trader(1_000 * USD);
    let whale = env.trader(1_000 * USD);
    env.trade_cpi(&small.0, small.1, &lp, 10 * Q).expect("filler ($10 = the minimum)");
    env.trade_cpi(&whale.0, whale.1, &lp, 40 * Q).expect("a bigger honest trader ($40)");
    env.poke_engine_config(|c| c.band_max_positions_per_side = percolator::V16PodU64::new(2));
    (lp, small, whale)
}

/// Ported from the round-3 review (N-8 evidence). The victim is caller-chosen, so this $40 leg
/// can be evicted while a $10 leg stays. After the N-8 bound that is only possible because $40
/// is EXACTLY 4x the $10 minimum (the boundary); `v22_tag119_only_small_legs_are_evictable`
/// shows a $41 leg cannot be evicted by anyone.
#[test]
fn sec4_tag119_can_target_a_chosen_larger_victim_not_just_the_smallest() {
    let mut env = Env::new(band_cfg());
    let (lp, small, whale) = sec_full_long_side(&mut env);
    let attacker = env.trader(1_000 * USD);
    let lp_before = env.pos(lp.account);
    // evict the WHALE ($40) with an $80+ open, although a smaller leg ($10) exists on the side
    let r = env.evict_and_trade(whale.1, &attacker.0, attacker.1, &lp, 85 * Q);
    eprintln!("SEC4 targeted eviction of the $40 trader while a $10 leg exists: {r:?}");
    assert!(r.is_ok(), "caller-chosen victim accepted: {r:?}");
    assert_eq!(env.pos(whale.1), 0, "the chosen victim was force-closed");
    assert_eq!(env.pos(small.1), 10 * Q, "the smallest leg was NOT the one evicted");
    // what the LP absorbed: victim's +40 (it buys) and the attacker's -85 (it sells)
    let lp_after = env.pos(lp.account);
    eprintln!("SEC4 LP inventory {} -> {} (delta {} = -85 + 40)", lp_before / Q, lp_after / Q, (lp_after - lp_before) / Q);
    assert_eq!(lp_after - lp_before, -(85 * Q) + 40 * Q);
    env.assert_conservation();
}

#[test]
fn sec4_tag119_refused_while_lagged_and_while_pinned() {
    // lagged, not pinned
    let mut env = Env::new(band_cfg());
    let (lp, small, _w) = sec_full_long_side(&mut env);
    let attacker = env.trader(1_000 * USD);
    env.warp(1);
    env.push(PRICE * 1_005 / 1_000);
    env.crank(small.1).expect("crank");
    env.crank(lp.account).expect("crank lp");
    let a = env.engine_asset();
    assert!(a.raw_oracle_target_price != a.effective_price);
    let r = env.evict_and_trade(small.1, &attacker.0, attacker.1, &lp, 25 * Q);
    assert_err(&r, &code(PercolatorError::EngineLockActive), "tag 119 while lagged");
    assert_eq!(env.pos(small.1), 10 * Q, "nothing evicted");
    // pinned at the band edge (uncertified book, target +30%)
    let mut env = Env::new(band_cfg());
    let (lp, small, _w) = sec_full_long_side(&mut env);
    let attacker = env.trader(1_000 * USD);
    let target = PRICE * 13 / 10;
    for _ in 0..60 {
        env.warp(1);
        env.push(target);
        let _ = env.crank(lp.account);
    }
    assert!(env.engine_asset().band_pin_since_slot != 0, "pinned");
    let r = env.evict_and_trade(small.1, &attacker.0, attacker.1, &lp, 25 * Q);
    assert_err(&r, &code(PercolatorError::EngineLockActive), "tag 119 while pinned");
}

/// A self-hedging cap-filler cannot starve honest entrants any more, but it can re-fill: each
/// eviction costs the filler its slot, and an honest entrant pays >= 2x the smallest notional.
/// Cost of evicting a victim of notional N: the evictor's own trade fee and exposure on 2N.
#[test]
fn sec4_tag119_evictor_cost_and_no_profit_from_evict_then_reverse() {
    let mut env = Env::new(band_cfg());
    let (lp, small, _w) = sec_full_long_side(&mut env);
    let attacker = env.trader(1_000 * USD);
    let eq_attacker = env.equity(attacker.1);
    let eq_victim = env.equity(small.1);
    env.evict_and_trade(small.1, &attacker.0, attacker.1, &lp, 25 * Q).expect("evict + open");
    assert_eq!(env.equity(small.1), eq_victim, "victim equity untouched (no fee, mark price)");
    // reverse immediately: close the new leg
    env.trade_cpi(&attacker.0, attacker.1, &lp, -25 * Q).expect("evictor closes at the same mark");
    let eq_after = env.equity(attacker.1);
    eprintln!("SEC4 evict->open->close round trip: attacker equity {} -> {} (fees paid {})", eq_attacker, eq_after, eq_attacker - eq_after);
    assert!(eq_after <= eq_attacker, "round trip must not profit");
    env.assert_conservation();
}


/// Round-3 re-review N-8: only a SMALL leg is evictable (notional <= 4x the market minimum).
/// A $41 trader on a full side cannot be displaced even by a taker bringing 20x its size
/// (111, nothing evicted), while the $10 filler next to it can; $40 (exactly 4x) is the
/// boundary and is still evictable.
#[test]
fn v22_tag119_only_small_legs_are_evictable() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(100_000 * USD);
    let small = env.trader(1_000 * USD);
    let big = env.trader(1_000 * USD);
    env.trade_cpi(&small.0, small.1, &lp, 10 * Q).expect("filler at the $10 minimum");
    env.trade_cpi(&big.0, big.1, &lp, 41 * Q).expect("an honest $41 trader (> 4x the minimum)");
    env.poke_engine_config(|c| c.band_max_positions_per_side = percolator::V16PodU64::new(2));
    let whale = env.trader(10_000 * USD);
    // 20x the victim: still refused, because the victim is above 4x the minimum.
    let r = env.evict_and_trade(big.1, &whale.0, whale.1, &lp, 820 * Q);
    assert_err(&r, &code(PercolatorError::PriceBandPositionCap), "a $41 leg is not evictable");
    assert_eq!(env.pos(big.1), 41 * Q, "nothing was evicted");
    // The same taker can take the small filler's slot instead.
    env.evict_and_trade(small.1, &whale.0, whale.1, &lp, 820 * Q).expect("evict the $10 filler");
    assert_eq!(env.pos(small.1), 0);
    assert_eq!(env.pos(big.1), 41 * Q, "the larger honest trader is untouched");
    assert_eq!(env.pos(whale.1), 820 * Q);
    env.assert_conservation();
}

/// Round-3 re-review, LP exemptions (wrapper half): only the asset's RECORDED bound vault LP is
/// the exempt maker. A second matcher LP that is not the bound one cannot take a new fill on
/// the bound asset at all, and cannot be named as the counterparty of a forced close
/// (`VaultLpNotBound`, pinned in `v22_tag118_dust_sweep_refusals`).
#[test]
fn v22_only_the_bound_vault_lp_is_the_exempt_maker() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let other = env.lp(10_000 * USD); // bound first ...
    let lp = env.lp(10_000 * USD); // ... then the binding moves to this LP (state poke)
    let t = env.trader(1_000 * USD);
    let r = env.trade_cpi(&t.0, t.1, &other, 30 * Q);
    assert!(r.is_err(), "a non-bound LP is not a counterparty on a bound band asset: {r:?}");
    env.trade_cpi(&t.0, t.1, &lp, 30 * Q).expect("the bound vault LP fills");
    // Sub-minimum NET position: allowed for the bound LP only (the taker leg stays >= minimum).
    let u = env.trader(1_000 * USD);
    env.trade_cpi(&u.0, u.1, &lp, -25 * Q).expect("bound LP nets to $5");
    assert_eq!(env.pos(lp.account), -5 * Q);
    env.assert_conservation();
}

/// S10 CU probe: tag 106 (`handle_settle_holding_rent`) is the second production entry point that
/// runs the engine's Refresh crank, so it carries the S10 move budget. Prints the cost of the
/// trader settle and of the vault-LP settle; the same probe on the base tree gives the delta.
#[test]
fn s10_cu_settle_holding_rent() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let taker = env.trader(1_000 * USD);
    env.trade_cpi(&taker.0, taker.1, &lp, 800 * Q).expect("crowd open");
    for _ in 0..100 {
        env.warp(1);
        env.push(PRICE);
        env.crank_current(taker.1);
    }
    env.warp(1);
    env.push(PRICE);
    let cu_taker = env.settle_rent(taker.1, lp.account).expect("tag 106, taker");
    env.warp(1);
    env.push(PRICE);
    let cu_lp = env.settle_rent(lp.account, lp.account).expect("tag 106, vault LP");
    println!("S10RENT tag 106 settle_holding_rent: taker {cu_taker} CU, vault LP {cu_lp} CU");
    assert!(cu_taker < 400_000 && cu_lp < 400_000, "tag 106 stays far inside the budget even with two firings (+66k)");
}

// ---------------------------------------------------------------------------
// v2.2 growth overnight (2026-10-14) §1.1-1.3: G8 depth, per-market clamp predicate,
// graduation ceiling + ratchet. Every test pairs the refused / unchanged case with its
// control.
// ---------------------------------------------------------------------------

const DEPTH_T1: u64 = percolator_prog::growth_v19::DEPTH_TIER1_E6;
const DEPTH_EVER: u8 = percolator_prog::growth_v19::DEPTH_EVER;
const DEPTH_PREV_REAL: u8 = percolator_prog::growth_v19::DEPTH_PREV_REAL;

impl Env {
    /// Tag 63's 44-byte form `[depth_mode u8][depth_e6 u64]`, at the current slot.
    fn push_depth(&mut self, mark_e6: u64, depth_mode: u8, depth_e6: u64) -> Result<u64, String> {
        let admin = self.admin.insecure_clone();
        let seq = self.oracle_seq() + 1;
        let (m, slot) = (self.market, self.slot);
        self.send(
            ProgInstruction::PushAuthMarkDepth {
                market_id: 1,
                asset_index: 0,
                now_slot: slot,
                mark_e6,
                observation_sequence: seq,
                depth_mode,
                depth_e6,
            },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
    }

    /// Raw tag-63 bytes (any length), signed by the oracle authority.
    fn push_raw(&mut self, data: Vec<u8>) -> Result<u64, String> {
        let admin = self.admin.insecure_clone();
        let m = self.market;
        let instruction = Instruction {
            program_id: self.program_id,
            accounts: vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            data,
        };
        self.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&self.payer.pubkey()),
            &[&self.payer, &admin],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).map(|m| m.compute_units_consumed).map_err(|e| format!("{e:?}"))
    }

    /// Two attested pushes of the same depth in two consecutive slots (the effective depth is
    /// the min of the last two samples, which W-L2 requires to be in distinct slots). Advances
    /// the clock by one slot.
    fn depth_twice(&mut self, depth_e6: u64) {
        self.push_depth(PRICE, 1, depth_e6).expect("attested push 1");
        self.warp(1);
        self.push_depth(PRICE, 1, depth_e6).expect("attested push 2");
    }

    /// A further deposit into an existing portfolio.
    fn deposit_to(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
        let source = self.key();
        let mint = self.mint;
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, owner.pubkey(), amount as u64),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        let (m, v) = (self.market, self.vault);
        self.send(
            ProgInstruction::Deposit { portfolio_id, expected_sequence, amount },
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

    fn growth_raw(&self) -> Option<state::AssetGrowthV19> {
        state::read_asset_growth(&self.svm.get_account(&self.market).unwrap().data, 0, self.engine_imr).unwrap()
    }

    fn clock_slot(&self) -> u64 {
        self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }
}

fn env_with_launch(cfg: Cfg, l_launch: u16) -> Env {
    L_LAUNCH.with(|l| l.set(l_launch));
    let env = Env::new(cfg);
    L_LAUNCH.with(|l| l.set(1_000));
    env
}

/// (a) Tag 63 wire: the 35 B form still works and ZEROES the stored depth (moving the old one to
/// `depth_prev_e6`); the 44 B attested form stores depth, source 1 and the authenticated slot;
/// mode 2 (and mode 0 with a non-zero depth) is refused with DepthInputInvalid (128); a length
/// other than 35 / 44 is refused; on a growth-OFF asset (STATE POKE: growth record zeroed) a
/// 44 B push lands and writes NO growth byte.
#[test]
fn g8_push_auth_mark_wire_35_44_and_mode_refusals() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let g0 = env.growth();
    assert_eq!((g0.depth_e6, g0.depth_prev_e6, g0.depth_slot, g0.depth_source), (0, 0, 0, 0));
    env.warp(3);
    env.push_depth(PRICE, 1, 30_000_000_000).expect("44 B attested push");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6, g.depth_source), (30_000_000_000, 0, 1));
    assert_eq!(g.depth_slot, env.clock_slot(), "stamped with the authenticated slot");
    env.warp(1);
    env.push_depth(PRICE, 1, 40_000_000_000).expect("second attested push");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6), (40_000_000_000, 30_000_000_000), "previous depth moves to prev");
    // R2.1: the pair (30k, 40k) in two slots was a fresh effective depth: DEPTH_EVER is set
    // and the last good depth is min(30k, 40k).
    assert_eq!(g.depth_source, 1 | DEPTH_PREV_REAL | DEPTH_EVER);
    // R2-M1: the market's FIRST fresh reading is clamped below T1 (tier 0): T1 - 1
    assert_eq!((g.depth_last_good_e6, g.depth_last_good_slot), (DEPTH_T1 - 1, env.clock_slot()));
    // The 35 B form zeroes the depth (absent is never stale-but-trusted); DEPTH_EVER and the
    // last good depth stay (the sticky cap's input).
    env.warp(1);
    env.push(PRICE);
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6, g.depth_source), (0, 40_000_000_000, DEPTH_EVER | DEPTH_PREV_REAL));
    assert_eq!(g.depth_last_good_e6, DEPTH_T1 - 1);
    assert_eq!(g.depth_slot, env.clock_slot());
    // 44 B with mode 0 and depth 0 is the explicit "none" form.
    env.push_depth(PRICE, 0, 0).expect("44 B mode 0");
    assert_eq!(env.growth().depth_e6, 0);
    // Refusals: mode 2, mode 255, mode 0 with a depth; the sequence is not consumed.
    let seq = env.oracle_seq();
    for (mode, d) in [(2u8, 1u64), (255, 0), (0, 1)] {
        let r = env.push_depth(PRICE, mode, d);
        assert_err(&r, &code(PercolatorError::DepthInputInvalid), "invalid depth mode");
    }
    assert_eq!(code(PercolatorError::DepthInputInvalid), "Custom(128)");
    assert_eq!(env.oracle_seq(), seq, "a refused push changes nothing");
    // Lengths other than 35 / 44: refused (InvalidInstructionData), never decoded as a depth.
    let full = ProgInstruction::PushAuthMarkDepth {
        market_id: 1, asset_index: 0, now_slot: env.slot, mark_e6: PRICE,
        observation_sequence: seq + 1, depth_mode: 1, depth_e6: 5,
    }
    .encode();
    assert_eq!(full.len(), 44);
    for len in [36usize, 40, 43, 45] {
        let mut d = full.clone();
        d.resize(len, 0);
        let r = env.push_raw(d);
        assert!(r.as_ref().is_err_and(|e| e.contains("InvalidInstructionData")), "len {len}: {r:?}");
    }
    let short = ProgInstruction::PushAuthMark {
        market_id: 1, asset_index: 0, now_slot: env.slot, mark_e6: PRICE, observation_sequence: seq + 1,
    }
    .encode();
    assert_eq!(short.len(), 35);
    // Growth OFF (STATE POKE: zero the record): a 44 B push lands and writes no growth byte.
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let r = state::asset_growth_range(&acc.data, 0).unwrap();
    for b in &mut acc.data[r.clone()] {
        *b = 0;
    }
    env.svm.set_account(env.market, acc).unwrap();
    env.warp(1);
    env.push_depth(PRICE, 1, 30_000_000_000).expect("44 B push on a growth-OFF asset");
    let acc = env.svm.get_account(&env.market).unwrap();
    assert!(acc.data[r].iter().all(|b| *b == 0), "growth OFF: the record stays all-zero");
    assert!(env.growth_raw().is_none());
}

/// (b) NEGATIVE CONTROL for (c): an OFF-BAND growth market (r_gap declared, no engine band, so
/// the clamp predicate is false). Whatever the depth (tier 1, fresh) and the capital (8x the
/// launch reference), the ceiling stays at L_launch = 3x: the record's graduation fields are
/// never written by the ratchet, and a 3.5x open is refused while a 2.9x open lands.
#[test]
fn g8_off_band_ceiling_stays_launch_whatever_depth_and_capital() {
    let mut env = env_with_launch(Cfg { slots: 1, phase4: None, r_gap: 400 }, 300);
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let lp_owner = lp.owner.insecure_clone();
    let g0 = env.growth();
    assert_eq!((g0.l_launch_x100, g0.ceil_x100, g0.c_launch_atoms), (300, 300, 0));
    env.depth_twice(5 * DEPTH_T1);
    env.deposit_to(&lp_owner, lp.account, 7_000 * USD);
    env.warp(9_001);
    env.depth_twice(5 * DEPTH_T1);
    let taker = env.trader(100 * USD);
    let r = env.trade_cpi(&taker.0, taker.1, &lp, 350 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "off-band: 3.5x over the 3x launch ceiling");
    env.trade_cpi(&taker.0, taker.1, &lp, 290 * Q).expect("control: 2.9x inside the launch ceiling");
    let g = env.growth();
    assert_eq!((g.ceil_x100, g.ceil_slot, g.c_launch_atoms), (g0.ceil_x100, g0.ceil_slot, 0), "never ratcheted off-band");
    assert_eq!(g.depth_source, 1 | DEPTH_PREV_REAL | DEPTH_EVER, "the depth is stored (and ignored) off-band");
}

/// (c) Band market (clamp-enforced, L_tier 10x), L_launch 3x, tier-1 attested depth (venue tier
/// 1), LP book $30k (book tier 1, `>= $25k`): tier = min(1, 1) = 1, target = L1 = 5x (R2.1). The
/// ceiling climbs at most +1x per 9,000 slots (3x -> 4x -> 5x and stops at L_table(1)), and falls
/// at once when the depth becomes absent (35 B push) and when it goes stale (> 150 slots); the
/// gate follows (3.5x refused at 3x, admitted at 5x, refused again after the fall).
#[test]
fn g8_band_ceiling_climbs_one_step_per_epoch_and_falls_on_absent_or_stale_depth() {
    let mut env = env_with_launch(band_cfg(), 300);
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let lp_owner = lp.owner.insecure_clone();
    let g0 = env.growth();
    assert_eq!((g0.l_launch_x100, g0.ceil_x100, g0.c_launch_atoms), (300, 300, 0));
    let s0 = g0.ceil_slot;
    env.depth_twice(5 * DEPTH_T1);
    // First evaluation: c_launch snapshotted (floored at $1,000), no climb in that call.
    env.settle_rent(lp.account, lp.account).expect("tag 106: ratchet site");
    let g = env.growth();
    assert_eq!((g.c_launch_atoms, g.ceil_x100, g.ceil_slot), (1_000 * USD as u64, 300, s0));
    env.deposit_to(&lp_owner, lp.account, 29_000 * USD); // C_m $30k: book tier 1
    // The gate reads min(stored 3x, target 5x): 3.5x is still refused.
    let taker = env.trader(100 * USD);
    let r = env.trade_cpi(&taker.0, taker.1, &lp, 350 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "stored ceiling 3x binds");
    // Up to one slot before the epoch boundary: no climb.
    let to = s0 + 8_998 - env.slot;
    env.warp(to);
    env.depth_twice(5 * DEPTH_T1); // ends at s0 + 8,999
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 300, "inside the epoch: no climb");
    // R2-M1 / D-L2: the venue depth is still the tier-0 first reading (T1 - 1) here; it may
    // double only 9,000 slots after that rise. At that slot (past the ceiling's epoch too) the
    // depth reaches tier 1 and the ceiling takes one step.
    let w = env.next_rise_slot();
    env.warp(w - 1 - env.slot);
    env.depth_twice(5 * DEPTH_T1);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    let g = env.growth();
    assert!(g.depth_last_good_e6 >= DEPTH_T1, "depth tier 1 after one window");
    assert_eq!((g.ceil_x100, g.ceil_slot), (400, env.clock_slot()), "one step at the boundary");
    env.settle_rent(lp.account, lp.account).expect("tag 106 again, same slot");
    assert_eq!(env.growth().ceil_x100, 400, "one step per epoch, not per call");
    env.warp(9_000);
    env.depth_twice(5 * DEPTH_T1);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 500);
    env.warp(9_000);
    env.depth_twice(5 * DEPTH_T1);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 500, "capped at L_table(1) = 5x, not 6x");
    // Stale depth (no position held yet, same slot): the stored ceiling is 5x but the depth's
    // stamp is 151 slots old (STATE POKE: one past DEPTH_MAX_AGE_SLOTS), so the GATE alone
    // (min(stored, live target)) refuses 3.5x.
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let mut g = state::read_asset_growth(&acc.data, 0, ENGINE_IMR).unwrap().unwrap();
    let fresh_slot = g.depth_slot;
    g.depth_slot = env.clock_slot() - 151;
    state::write_asset_growth(&mut acc.data, 0, &g, ENGINE_IMR).unwrap();
    env.svm.set_account(env.market, acc).unwrap();
    let r = env.trade_cpi(&taker.0, taker.1, &lp, 350 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "stale depth (151 slots) -> launch at once");
    // Control: 150 slots old is still fresh -> 5x.
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let mut g = state::read_asset_growth(&acc.data, 0, ENGINE_IMR).unwrap().unwrap();
    g.depth_slot = env.clock_slot() - 150;
    state::write_asset_growth(&mut acc.data, 0, &g, ENGINE_IMR).unwrap();
    env.svm.set_account(env.market, acc).unwrap();
    let t3 = env.trader(100 * USD);
    let mut probe = env.svm.get_account(&env.market).unwrap();
    let saved = probe.clone();
    let _ = fresh_slot;
    // Absent depth (a 35 B push): the stored ceiling falls at once (fall-only writer) and the
    // gate refuses 3.5x.
    env.push(PRICE);
    assert_eq!(env.growth().ceil_x100, 300, "absent depth -> launch at once");
    let r = env.trade_cpi(&t3.0, t3.1, &lp, 350 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "after the fall 3.5x is refused");
    // Back to the 150-slot-old fresh depth and the 5x stored ceiling (restore the pre-push
    // market account, STATE POKE): the 3.5x open lands.
    probe.data.copy_from_slice(&saved.data);
    env.svm.set_account(env.market, probe).unwrap();
    env.trade_cpi(&t3.0, t3.1, &lp, 350 * Q).expect("3.5x under the graduated 5x ceiling (depth 150 slots old)");
    env.assert_conservation();
}

/// (e) The κ depth cap clips N_cap, and (R2.1, W-M1) STAYS once the market has had a fresh
/// depth. Band market, LP $1,000 at λ 1x (N_cap 1,000 units). A first 44 B push alone (prev 0,
/// effective 0, DEPTH_EVER not yet set) leaves today's capacity (1,000 units). A fresh tier-0
/// depth of $600 (κ 0.5 -> $300) clips N_cap to 300 units: the rent snapshot reads 300, an open
/// of 301 is refused / clipped and 300 lands. An absent depth (35 B push) KEEPS the cap at the
/// last good $600 (round 1 removed it): a further open gets nothing while a reduce lands; one
/// staleness epoch (9,000 slots) halves it to 150 units. The r_gap-mismatch market (not
/// clamp-enforced) has no depth cap at all.
#[test]
fn g8_kappa_depth_cap_clips_n_cap_only_when_fresh() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let full = 1_000 * Q as u64;
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, full, "no depth: today's capacity");
    env.push_depth(PRICE, 1, 600 * USD as u64).expect("first 44 B push");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, full, "first push: prev 0 -> effective 0 -> no cap");
    env.warp(1); // W-L2: the second sample must be in a later slot
    env.push_depth(PRICE, 1, 600 * USD as u64).expect("second 44 B push");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "fresh $600 at κ 0.5 -> 300 units");
    let taker = env.trader(1_000 * USD);
    // 301 units: the TradeCpi clip and the gate share the 300-unit N_cap, so the request is
    // either clipped to the room or refused; never more than 300 units fill.
    let _ = env.trade_cpi(&taker.0, taker.1, &lp, 301 * Q);
    let got = env.pos(taker.1);
    assert!(got <= 300 * Q, "past the depth cap: {got}");
    if got < 300 * Q {
        env.trade_cpi(&taker.0, taker.1, &lp, 300 * Q - got).expect("up to exactly the depth cap (u = 1)");
    }
    assert_eq!(env.pos(taker.1), 300 * Q);
    let t1 = env.trader(1_000 * USD);
    // The side is full: the clip leaves no room, so nothing fills (refused, or a zero fill).
    let r = env.trade_cpi(&t1.0, t1.1, &lp, Q);
    assert_eq!(env.pos(t1.1), 0, "the side is full at the depth cap: {r:?}");
    // R2.1 (W-M1): absent depth (35 B, same slot) KEEPS the cap: the sticky last good $600 at
    // tier 0 (κ 0.5) -> 300 units, never "uncapped".
    env.push(PRICE);
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_source & DEPTH_EVER), (0, DEPTH_EVER));
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "absent depth: the sticky cap stays");
    let t2 = env.trader(1_000 * USD);
    let r = env.trade_cpi(&t2.0, t2.1, &lp, 100 * Q);
    assert_eq!(env.pos(t2.1), 0, "absent depth: the side stays full at the sticky cap: {r:?}");
    // Reductions are never capacity-checked.
    env.trade_cpi(&taker.0, taker.1, &lp, -100 * Q).expect("reduce at the cap");
    assert_eq!(env.pos(taker.1), 200 * Q);
    // One staleness epoch: the sticky depth halves ($300 -> κ 0.5 -> 150 units).
    let lg = env.growth().depth_last_good_slot;
    env.warp(lg + 9_000 - env.slot);
    env.push(PRICE);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 150 * Q as u64, "k = 1: last_good / 2");
    let r = env.trade_cpi(&t2.0, t2.1, &lp, 10 * Q);
    assert_eq!(env.pos(t2.1), 0, "200 units held > 150 cap: no open: {r:?}");
    env.assert_conservation();
    // §1.1 fail-closed predicate: a band market whose STORED r_gap is not G(d) (STATE POKE:
    // G + 1) is NOT clamp-enforced, so a fresh tier-0 depth does not clip N_cap there either
    // (and nothing else loosens: the off-band growth-1 rules apply).
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let mut g = state::read_asset_growth(&acc.data, 0, ENGINE_IMR).unwrap().unwrap();
    let g_derived = percolator_prog::growth_v19::band_r_gap_bps(BAND_BPS as u64).unwrap();
    assert_eq!(g.r_gap_bps, g_derived, "InitMarket stored the derived G(d)");
    g.r_gap_bps = g_derived + 1;
    state::write_asset_growth(&mut acc.data, 0, &g, ENGINE_IMR).unwrap();
    env.svm.set_account(env.market, acc).unwrap();
    env.depth_twice(600 * USD as u64);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert!(env.growth().rent_n_cap_q >= full, "r_gap mismatch: not enforced, no depth cap");
    assert_err(&env.set_growth_dials(20_000, 5_000, 0), &code(PercolatorError::GrowthInvalidConfig), "r_gap mismatch: no lambda > 1x");
}

/// Security review W-L2: two 44 B pushes in the SAME slot are ONE sample: `depth_prev_e6` is
/// not rotated and the depth cannot rise, so the effective depth stays 0 (no tier, no κ cap);
/// a push in the next slot makes it effective. Same-slot pushes can only lower the depth.
#[test]
fn g8_wl2_two_same_slot_pushes_are_one_sample() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let full = 1_000 * Q as u64;
    env.warp(1);
    env.push_depth(PRICE, 1, 600 * USD as u64).expect("push 1");
    env.push_depth(PRICE, 1, 900 * USD as u64).expect("push 2, same slot");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6), (600 * USD as u64, 0), "same slot: no rotation, no rise");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, full, "one sample: effective 0, no cap");
    env.push_depth(PRICE, 1, 400 * USD as u64).expect("push 3, same slot, lower");
    assert_eq!(env.growth().depth_e6, 400 * USD as u64, "same slot: the depth can fall");
    env.warp(1);
    env.push_depth(PRICE, 1, 600 * USD as u64).expect("push 4, next slot");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6), (600 * USD as u64, 400 * USD as u64));
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 200 * Q as u64, "two slots: min $400 at κ 0.5 -> 200 units");
}

// ---------------------------------------------------------------------------
// v2.2 growth round 2 (R2.1, 2026-10-14 12:52 / 13:10): sticky κ cap (W-M1), per-market tier
// table, tier = min(venue, book), graduation 5x -> 10x -> 20x. Every test carries its control.
// ---------------------------------------------------------------------------

impl Env {
    /// Tag 93 with the R2.1 27-byte trailer (lambda 1x, kink 50%, util unchanged), UA-signed.
    fn set_tiers(&mut self, th: [u32; 3], lev: [u16; 3], attested_max_tier: u8) -> Result<u64, String> {
        let ua = self.upgrade_authority.insecure_clone();
        let (pd, market) = (self.program_data, self.market);
        self.send(
            ProgInstruction::SetAssetRiskLimitsV22Tiers {
                limits: Box::new(ProgInstruction::SetAssetRiskLimits {
                    asset_index: 0,
                    exec_band_bps: 0,
                    lp_exposure_k_bps: 0,
                    lp_floor_atoms: 0,
                    side_oi_cap_q: 0,
                    matcher_ext_mode: 0,
                    max_requested_fee_bps: 0,
                }),
                growth_lambda_bps: 10_000,
                growth_kink_bps: 5_000,
                growth_util_fee_max_bps: 0,
                tiers: percolator_prog::growth_v19::TierConfig { threshold_usd: th, leverage_x100: lev },
                attested_max_tier,
            },
            vec![
                AccountMeta::new(ua.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[&ua],
        )
    }

    /// One ratchet epoch: warp to `ceil_slot + 9,000` AND past the depth's rise window (R2-M1 /
    /// D-L2: the usable depth can rise once per 9,000 slots since its last rise), a fresh
    /// attested pair at `depth`, then the tag-106 ratchet site. Returns the stored ceiling.
    fn epoch_step(&mut self, lp: &Lp, depth: u64) -> u16 {
        let e = percolator_prog::growth_v19::RATCHET_EPOCH_SLOTS;
        let due = core::cmp::max(self.growth().ceil_slot + e, self.next_rise_slot());
        let to = due.saturating_sub(self.slot + 1).max(1);
        self.warp(to);
        self.depth_twice(depth);
        self.settle_rent(lp.account, lp.account).expect("tag 106: ratchet site");
        self.growth().ceil_x100
    }

    /// D-L2: the first slot at which the rate-limited depth may rise again (the stored 64-slot
    /// stamp's latest slot + 9,000), never before the current slot.
    fn next_rise_slot(&self) -> u64 {
        let st = u32::from_le_bytes(self.growth().depth_rise_slot64_le) as u64;
        core::cmp::max(st * 64 + 63 + percolator_prog::growth_v19::RATCHET_EPOCH_SLOTS, self.clock_slot() + 1)
    }

    /// R2-M1: epoch steps at `depth` until the stored ceiling reaches `target` (each step: hold,
    /// or exactly +1x), within `max_steps`. Returns the number of steps taken.
    fn climb_to(&mut self, lp: &Lp, depth: u64, target: u16, max_steps: usize) -> usize {
        let mut c = self.growth().ceil_x100;
        for k in 1..=max_steps {
            let n = self.epoch_step(lp, depth);
            assert!(n == c || n == c + 100, "step {k}: {c} -> {n} (at most +1x per epoch)");
            c = n;
            if c == target {
                return k;
            }
        }
        panic!("ceiling {c} did not reach {target} in {max_steps} epochs");
    }

    fn poke_growth(&mut self, f: impl FnOnce(&mut state::AssetGrowthV19)) {
        let mut acc = self.svm.get_account(&self.market).unwrap();
        let mut g = state::read_asset_growth(&acc.data, 0, self.engine_imr).unwrap().unwrap();
        f(&mut g);
        state::write_asset_growth(&mut acc.data, 0, &g, self.engine_imr).unwrap();
        self.svm.set_account(self.market, acc).unwrap();
    }
}

/// A market with engine `(IMR, MMR, liquidation fee, min_nonzero_mm_req)` and band `band_bps`,
/// launch `l_launch`. (At MMR 250 the Band Safety Law's floor region `N <= mm_floor·1e4/MMR`
/// needs `mm_floor >= ~29` to absorb the per-atom rounding of loss + fee: 100 is used.)
fn env_tiered(imr: u64, mmr: u64, liq: u64, mm_floor: u128, band_bps: u16, l_launch: u16) -> Env {
    MKT.with(|m| m.set((imr, mmr, liq, mm_floor)));
    let env = env_with_launch(Cfg { slots: 1, phase4: Some(phase4(band_bps, RENT_MAX)), r_gap: 0 }, l_launch);
    MKT.with(|m| m.set((ENGINE_IMR, MMR, LIQ_FEE, 10)));
    env
}

const USD_E6: u64 = 1_000_000;

/// R2.1 §1 (W-M1): once a market has had a fresh depth, the κ cap NEVER switches off:
/// * a stale reading (> 150 slots, STATE POKE of the stamp) keeps the last good cap;
/// * the first push of a NEW pair (prev 0 after a 35 B push) keeps it (round 1: uncapped);
/// * a fresh higher pair replaces it;
/// * staleness halves it per 9,000 slots down to 0, where opens get nothing (reduce / close at
///   cap 0: `r2_attested_zero_reading_caps_at_zero_at_once`).
///
/// NEGATIVE CONTROL: before any fresh pair (DEPTH_EVER clear) the market is uncapped.
#[test]
fn r2_sticky_cap_stale_first_push_of_pair_and_decay_to_zero() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    let full = 1_000 * Q as u64;
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, full, "control: never had depth -> no cap");
    env.warp(200);
    env.push(PRICE);
    env.warp(1); // W-L2: the 35 B push and the first attested push must not share a slot
    env.depth_twice(600 * USD_E6);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "fresh $600, κ 0.5");
    // stale: the stamp 151 slots old (no push since)
    let now = env.clock_slot();
    env.poke_growth(|g| g.depth_slot = now - 151);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "stale: the sticky cap stays (round 1: 1,000)");
    // first push of a new pair: 35 B (zero), then ONE attested $2,000 push next slot
    env.warp(1);
    env.push(PRICE);
    env.warp(1);
    env.push_depth(PRICE, 1, 2_000 * USD_E6).expect("first push of the new pair");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6), (2_000 * USD_E6, 0));
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "one sample: still the sticky $600");
    // the second sample makes the higher reading fresh, but R2-M1 rate-limits the RISE: not in
    // the epoch of the last rise (the $600 pair), so the usable depth stays $600
    env.warp(1);
    env.push_depth(PRICE, 1, 2_000 * USD_E6).expect("second push of the pair");
    assert_eq!(env.growth().depth_last_good_e6, 600 * USD_E6, "R2-M1: no second rise in an epoch");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64);
    // the next epoch: one rise, to min(2,000, max(2 x 600, T1/16 = $1,562.49...))
    let g0 = env.growth();
    let seed = percolator_prog::growth_v19::DEPTH_TIER1_E6 - 1;
    let next = env.next_rise_slot();
    env.warp(next - env.slot);
    env.depth_twice(2_000 * USD_E6);
    let g = env.growth();
    let (want, _) = percolator_prog::growth_v19::depth_rate_limited(
        true, g0.depth_last_good_e6, u32::from_le_bytes(g0.depth_rise_slot64_le), 2_000 * USD_E6, next, seed,
    );
    assert_eq!(want, seed / 16, "the bootstrap floor binds here");
    assert_eq!(g.depth_last_good_e6, want);
    let cap_of = |d: u64| d / 2 / 10; // κ 0.5, $1 = 1/10 unit at the 1e7 price
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, cap_of(want));
    // depth goes absent and stays absent: halving per 9,000 slots, never uncapped
    env.push(PRICE);
    let lg = env.growth().depth_last_good_slot;
    let mut prev = u64::MAX;
    for k in 0..4u64 {
        let t = lg + k * 9_000;
        if t > env.slot {
            env.warp(t - env.slot);
        } else {
            env.warp(1);
        }
        env.push(PRICE);
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        let n = env.growth().rent_n_cap_q;
        assert_eq!(n, cap_of(want >> k), "k = {k}: last good >> k at κ 0.5");
        assert!(n <= prev);
        prev = n;
    }
    // ... to 0 after 64 epochs: opens get nothing
    let target = lg + 64 * 9_000;
    env.warp(target - env.slot);
    env.push(PRICE);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    // R2-L1: cap 0 is u = infinity -> the rent snapshot is 1 (maximum rent), not 0
    assert_eq!(env.growth().rent_n_cap_q, 1, "k >= 64: cap 0, not uncapped; rent at the maximum");
    let t2 = env.trader(1_000 * USD);
    let r = env.trade_cpi(&t2.0, t2.1, &lp, 10 * Q);
    assert_eq!(env.pos(t2.1), 0, "cap 0: no open: {r:?}");
    env.assert_conservation();
}

/// R2.1 §3 venue tier: keeper-attested depth is capped at `attested_max_tier` (default 1).
/// 10x band market, launch 5x, LP book $150k (book tier 2 at the default thresholds), attested
/// depth $600k (raw tier 3): at the default the tier is 1 -> L1 = 5x = launch, no climb over a
/// full epoch and 5.5x refused; after the UA sets attested_max_tier 3 the tier is min(3, 2) = 2
/// -> target 10x and the ceiling steps to 6x (5.5x admitted).
#[test]
fn r2_attested_max_tier_1_vs_3() {
    let mut env = env_with_launch(band_cfg(), 500);
    env.auth_mark();
    let lp = env.lp(150_000 * USD);
    env.depth_twice(600_000 * USD_E6);
    env.settle_rent(lp.account, lp.account).expect("snapshot");
    // R2-M1: the first reading starts below T1 and the usable depth doubles per epoch; three
    // epochs take it past T2 ($100k). Attested is capped at tier 1 (L1 = 5x = launch) throughout.
    for _ in 0..3 {
        assert_eq!(env.epoch_step(&lp, 600_000 * USD_E6), 500, "attested capped at tier 1: 5x = launch");
    }
    assert!(env.growth().depth_last_good_e6 >= percolator_prog::growth_v19::DEPTH_TIER2_E6);
    let t = env.trader(100 * USD);
    let r = env.trade_cpi(&t.0, t.1, &lp, 550 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "5.5x over 5x");
    env.set_tiers([0; 3], [0; 3], 3).expect("UA: attested_max_tier 3");
    assert_eq!(env.growth().attested_max_tier, 3);
    env.settle_rent(lp.account, lp.account).expect("tag 106 (epoch already elapsed)");
    assert_eq!(env.growth().ceil_x100, 600, "tier min(3, book 2) = 2: one step toward 10x");
    env.trade_cpi(&t.0, t.1, &lp, 550 * Q).expect("5.5x under 6x");
    env.assert_conservation();
}

/// R2.1 §3: tier = min(venue, book). Venue tier 3 (attested $600k, attested_max_tier 3) but the
/// LP book is $30k (book tier 1): target L1 = 5x = launch, no climb. Deposit to $120k (book tier
/// 2): the ceiling steps to 6x. CONTROL: book tier 3 with venue tier 0 (no depth) never climbs.
#[test]
fn r2_book_tier_limits_venue_tier() {
    let mut env = env_with_launch(band_cfg(), 500);
    env.auth_mark();
    env.set_tiers([0; 3], [0; 3], 3).expect("UA: attested_max_tier 3");
    let lp = env.lp(30_000 * USD);
    let owner = lp.owner.insecure_clone();
    env.depth_twice(600_000 * USD_E6);
    env.settle_rent(lp.account, lp.account).expect("snapshot");
    // four epochs: the rate-limited venue depth reaches ~$400k (tier 2); the book tier 1 holds
    for _ in 0..4 {
        assert_eq!(env.epoch_step(&lp, 600_000 * USD_E6), 500, "book tier 1 holds the venue at 5x");
    }
    assert!(env.growth().depth_last_good_e6 >= percolator_prog::growth_v19::DEPTH_TIER2_E6);
    env.deposit_to(&owner, lp.account, 90_000 * USD);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 600, "book tier 2: one step toward 10x");
    // control: a $600k book with no venue depth never graduates
    let mut c = env_with_launch(band_cfg(), 500);
    c.auth_mark();
    c.set_tiers([0; 3], [0; 3], 3).expect("UA");
    let clp = c.lp(600_000 * USD);
    c.settle_rent(clp.account, clp.account).expect("snapshot");
    c.warp(9_001);
    c.push(PRICE);
    c.settle_rent(clp.account, clp.account).expect("tag 106");
    assert_eq!(c.growth().ceil_x100, 500, "venue tier 0: launch");
}

/// R2.1 + R2.0: a tiered band market (engine IMR 500 = 20x, MMR 250, liquidation fee 50 bps,
/// band 60 bps: G(60) = 182, 182 + ~1 + ~51 <= 250 passes the Band Safety Law), launch 5x, UA
/// tier table at the floors ($5k / $20k / $100k, default 5x/10x/20x) with attested_max_tier 3,
/// LP book $150k (book tier 3). Venue tier 2 ($50k): 5x -> 10x one step per 9,000 slots, holds
/// at 10x; venue tier 3 ($150k): 10x -> 20x one step per epoch, holds at 20x (L_tier); the gate
/// follows (10.5x refused at 10x, 19x admitted at 20x). Depth loss (35 B push): straight back to
/// 5x, and 5.5x is refused.
#[test]
fn r2_band_market_graduates_5x_10x_20x_and_drops_on_depth_loss() {
    let mut env = env_tiered(500, 250, 50, 100, 60, 500);
    env.auth_mark();
    let g0 = env.growth();
    assert_eq!((g0.l_tier_x100, g0.l_launch_x100, g0.ceil_x100), (2_000, 500, 500));
    assert_eq!(g0.r_gap_bps, percolator_prog::growth_v19::band_r_gap_bps(60).unwrap());
    env.set_tiers([5_000, 20_000, 100_000], [0; 3], 3).expect("UA tier table");
    let lp = env.lp(150_000 * USD);
    let tier2 = 50_000 * USD_E6;
    let tier3 = 150_000 * USD_E6;
    env.depth_twice(tier2);
    env.settle_rent(lp.account, lp.account).expect("snapshot");
    assert_eq!(env.growth().ceil_x100, 500);
    // not before the epoch boundary
    let s = env.growth().ceil_slot;
    env.warp(s + 9_000 - 2 - env.slot);
    env.depth_twice(tier2);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 500, "inside the epoch: no climb");
    // R2-M1: the usable depth starts at T1 - 1 ($4,999.99) and doubles per epoch ($10k: tier
    // 1 = 5x = launch, $20k - 4 atoms: still tier 1, $40k: tier 2), so the climb starts in the
    // third epoch; the ceiling never moves more than +1x per epoch.
    let steps = env.climb_to(&lp, tier2, 1_000, 12);
    assert!(steps >= 7, "two epochs of depth warm-up + five +1x steps: {steps}");
    assert_eq!(env.epoch_step(&lp, tier2), 1_000, "venue tier 2: holds at 10x");
    let t = env.trader(100 * USD);
    let r = env.trade_cpi(&t.0, t.1, &lp, 1_050 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "10.5x over 10x");
    env.trade_cpi(&t.0, t.1, &lp, 950 * Q).expect("9.5x under 10x");
    // close it (a leg left uncertified across band epochs would block the market: 121)
    env.trade_cpi(&t.0, t.1, &lp, -950 * Q).expect("close");
    // $50k -> $100k (= T3) in one epoch, then +1x per epoch to 20x
    let steps = env.climb_to(&lp, tier3, 2_000, 14);
    assert!(steps >= 10, "ten +1x steps: {steps}");
    assert_eq!(env.epoch_step(&lp, tier3), 2_000, "holds at L_tier 20x");
    let t2 = env.trader(100 * USD);
    env.trade_cpi(&t2.0, t2.1, &lp, 1_900 * Q).expect("19x under the graduated 20x");
    // depth loss: the 35 B push (same slot: no leg goes stale) zeroes the venue -> the
    // fall-only writer drops the stored ceiling to launch at once
    env.push(PRICE);
    assert_eq!(env.growth().ceil_x100, 500, "depth loss: 5x at once");
    // holders above the new ceiling can still reduce (and close), even while the asset is
    // loss-stale after the push's accrual (reductions are never gated)
    env.trade_cpi(&t2.0, t2.1, &lp, -1_000 * Q).expect("reduce after the drop");
    env.trade_cpi(&t2.0, t2.1, &lp, -900 * Q).expect("close after the drop");
    env.warp(1);
    env.push(PRICE);
    env.crank_current(lp.account);
    env.crank_current(t2.1);
    assert_eq!(env.growth().ceil_x100, 500);
    let t3 = env.trader(100 * USD);
    let r = env.trade_cpi(&t3.0, t3.1, &lp, 550 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "5.5x after the drop");
    env.trade_cpi(&t3.0, t3.1, &lp, 450 * Q).expect("control: 4.5x after the drop");
    env.assert_conservation();
}

/// R2.0: an existing 5x market (engine IMR 2,000: L_tier 5x; MMR 1,000; band 130 bps -- the
/// CHILLHOUSE / swordcat `meme` preset) stays <= 5x whatever the depth, book and table: the
/// default table clamps to 5x, an explicit L1 above L_tier is 130, and after epochs at venue and
/// book tier 3 the ceiling is still 5x (5.5x refused, 4.9x admitted).
#[test]
fn r2_old_5x_market_stays_at_5x() {
    let mut env = env_tiered(2_000, 1_000, LIQ_FEE, 10, 130, 500);
    env.auth_mark();
    assert_eq!(env.growth().l_tier_x100, 500);
    let r = env.set_tiers([0; 3], [600, 0, 0], 3);
    assert_err(&r, &code(PercolatorError::GrowthTierConfigInvalid), "L1 above L_tier 5x");
    env.set_tiers([0; 3], [0; 3], 3).expect("defaults, attested 3");
    let lp = env.lp(600_000 * USD);
    env.depth_twice(600_000 * USD_E6);
    env.settle_rent(lp.account, lp.account).expect("snapshot");
    for _ in 0..3 {
        assert_eq!(env.epoch_step(&lp, 600_000 * USD_E6), 500, "never above L_tier 5x");
    }
    let t = env.trader(100 * USD);
    let r = env.trade_cpi(&t.0, t.1, &lp, 550 * Q);
    // the engine's own IMR (20%) refuses it first (49); never admitted
    assert!(r.is_err() && env.pos(t.1) == 0, "5.5x on a 5x market: {r:?}");
    env.trade_cpi(&t.0, t.1, &lp, 490 * Q).expect("4.9x");
}

/// R2.1 §2: a tier table change never JUMPS the ceiling: raising L2 moves the target and the
/// ratchet climbs +1x per epoch; lowering it takes effect at the next read (the gate applies
/// min(stored, live target)) and the next writer stores it.
#[test]
fn r2_tier_table_change_moves_the_target_not_the_ceiling() {
    let mut env = env_with_launch(band_cfg(), 500);
    env.auth_mark();
    env.set_tiers([0; 3], [500, 600, 1_000], 3).expect("L2 = 6x");
    let lp = env.lp(150_000 * USD);
    env.depth_twice(600_000 * USD_E6);
    env.settle_rent(lp.account, lp.account).expect("snapshot");
    env.climb_to(&lp, 600_000 * USD_E6, 600, 5);
    assert_eq!(env.epoch_step(&lp, 600_000 * USD_E6), 600, "held at L2 = 6x");
    env.set_tiers([0; 3], [500, 1_000, 1_000], 3).expect("L2 = 10x");
    let g = env.growth();
    assert_eq!(g.ceil_x100, 600, "the setter does not move the ceiling");
    assert_eq!(env.epoch_step(&lp, 600_000 * USD_E6), 700, "then +1x per epoch");
    env.set_tiers([0; 3], [500, 500, 1_000], 3).expect("L2 = 5x");
    let t = env.trader(100 * USD);
    let r = env.trade_cpi(&t.0, t.1, &lp, 550 * Q);
    assert_err(&r, &code(PercolatorError::GrowthLeverageExceeded), "lowered table binds at once (stored 7x)");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().ceil_x100, 500, "the next writer stores the fall");
}

/// Coordinator ruling (most conservative wins): an attested (mode 1) reading of 0 is a REAL zero
/// depth, not "absent": the κ cap is 0 AT ONCE (no second sample), DEPTH_EVER is set and the last
/// good depth becomes 0; opens get nothing while a reduce lands. A later positive reading
/// restores the normal rule only after its own min-of-two (the first positive sample's previous
/// sample is the real 0). CONTROL: the 35 B form at the same point is absent, so the sticky
/// last good depth ($600 -> 300 units) applies instead. Also: a market that never had depth is
/// closed at once by an attested 0.
#[test]
fn r2_attested_zero_reading_caps_at_zero_at_once() {
    for absent_control in [false, true] {
        let mut env = Env::new(band_cfg());
        env.auth_mark();
        let lp = env.lp(1_000 * USD);
        env.warp(1);
        env.depth_twice(600 * USD_E6);
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64);
        let taker = env.trader(1_000 * USD);
        env.trade_cpi(&taker.0, taker.1, &lp, 100 * Q).expect("open under the cap");
        env.warp(1);
        if absent_control {
            env.push(PRICE);
        } else {
            env.push_depth(PRICE, 1, 0).expect("attested 0");
        }
        let g = env.growth();
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        if absent_control {
            assert_eq!(g.depth_last_good_e6, 600 * USD_E6, "35 B: absent, last good kept");
            assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "35 B: sticky $600");
            continue;
        }
        assert_eq!((g.depth_e6, g.depth_last_good_e6, g.depth_source & DEPTH_EVER), (0, 0, DEPTH_EVER));
        // the κ cap is 0 at once; R2-L1: the rent snapshot is 1 (u = infinity: maximum rent)
        assert_eq!(env.growth().rent_n_cap_q, 1, "a real 0: cap 0 at once, rent at the maximum");
        let t2 = env.trader(1_000 * USD);
        let r = env.trade_cpi(&t2.0, t2.1, &lp, 10 * Q);
        assert_eq!(env.pos(t2.1), 0, "cap 0: no open: {r:?}");
        // AUD-S1-4: tag 106 no longer runs a second (rent-free) accrual segment inside the call,
        // so the asset moved one segment since the taker was last refreshed: refresh the taker
        // (tag 106 on the taker's own portfolio is the permissionless refresh) before it trades.
        env.settle_rent(taker.1, lp.account).expect("tag 106: refresh the taker");
        env.trade_cpi(&taker.0, taker.1, &lp, -50 * Q).expect("a reduce at cap 0");
        // a positive reading: min with the real 0 -> still 0
        env.warp(1);
        env.push_depth(PRICE, 1, 600 * USD_E6).expect("positive after 0");
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        assert_eq!(env.growth().rent_n_cap_q, 1, "first positive sample after a real 0: still cap 0");
        // its own min-of-two: fresh again, but R2-M1 allows no rise in the epoch of the last rise
        env.warp(1);
        env.push_depth(PRICE, 1, 600 * USD_E6).expect("second positive");
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        assert_eq!(env.growth().rent_n_cap_q, 1, "same epoch: the rate-limited depth stays 0");
        // the next epoch: back to min($600, T1/16), i.e. $600 at κ 0.5 -> 300 units
        let next = env.next_rise_slot();
        env.warp(next - env.slot);
        env.depth_twice(600 * USD_E6);
        env.crank_current(taker.1);
        env.crank_current(lp.account);
        env.settle_rent(lp.account, lp.account).expect("tag 106");
        assert_eq!(env.growth().rent_n_cap_q, 300 * Q as u64, "next epoch: $600 at κ 0.5");
        env.assert_conservation();
    }
    // never had depth: an attested 0 closes opens at once (and sets DEPTH_EVER)
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    env.warp(1);
    env.push_depth(PRICE, 1, 0).expect("attested 0 first");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    let g = env.growth();
    assert_eq!((g.rent_n_cap_q, g.depth_source & DEPTH_EVER), (1, DEPTH_EVER), "cap 0 (rent snapshot 1)");
    let t = env.trader(1_000 * USD);
    let r = env.trade_cpi(&t.0, t.1, &lp, 10 * Q);
    assert_eq!(env.pos(t.1), 0, "cap 0: no open: {r:?}");
}

/// Security review R2-M1, the reviewer's flash-liquidity shape on the attested path: real $2k of
/// ±2% depth; a $50M reading held for two adjacent-slot pushes. Round 2 took it at once (tier 1
/// here, tier 3 on the DEX source). Now the usable depth (min(fresh, rate-limited last good))
/// does not rise in the epoch of its last rise, rises at most 2x per later epoch, and the next
/// honest pair takes it back down at once; the κ cap (rent N_cap snapshot) follows, and the
/// ceiling never moves more than +1x per epoch.
#[test]
fn r2m1_flash_liquidity_is_rate_limited() {
    let mut env = env_with_launch(band_cfg(), 500);
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let real = 2_000 * USD_E6;
    let inflated = 50_000_000 * USD_E6;
    let cap_of = |d: u64| d / 2 / 10; // κ 0.5 at tier 0; $1 = 1/10 unit at the 1e7 price
    env.warp(1);
    env.depth_twice(real);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().depth_last_good_e6, real);
    assert_eq!(env.growth().rent_n_cap_q, cap_of(real));
    // the whale: two adjacent-slot pushes at $50M, same epoch
    env.warp(1);
    env.depth_twice(inflated);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    let g = env.growth();
    assert_eq!(g.depth_last_good_e6, real, "no rise in the epoch of the last rise");
    assert_eq!(g.rent_n_cap_q, cap_of(real), "the κ cap did not move");
    assert_eq!(g.ceil_x100, 500);
    // held into the next epoch: ONE doubling, not 25,000x
    let next = env.next_rise_slot();
    env.warp(next - env.slot);
    env.depth_twice(inflated);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().depth_last_good_e6, 2 * real);
    assert_eq!(env.growth().rent_n_cap_q, cap_of(2 * real));
    // the whale withdraws: the next honest pair takes it down at once
    env.warp(1);
    env.depth_twice(real);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().depth_last_good_e6, real, "down at once");
    // escalation held for several epochs: <= 2x per epoch, ceiling <= +1x per epoch
    let mut prev = real;
    let mut ceil = env.growth().ceil_x100;
    for _ in 0..6 {
        let c = env.epoch_step(&lp, inflated);
        let lg = env.growth().depth_last_good_e6;
        assert!(lg <= prev * 2, "{lg} > 2 x {prev}");
        assert!(c <= ceil + 100);
        prev = lg;
        ceil = c;
    }
    assert_eq!(prev, real << 6, "six epochs of continuous presence: 64x, not 25,000x");
    // the honest reading still takes it down at once
    env.warp(1);
    env.depth_twice(real);
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().depth_last_good_e6, real);
}

/// Security review R2-L1: at a depth cap of 0 the rent is the MAXIMUM (u = OI / 0 = infinity),
/// not 0: the snapshot is 1 and an open book pays `rent_max` per slot. And a band-pinned (D-1
/// duration-pinned, no-move) accrual still charges NO rent, so a stuck price (e.g. a keeper
/// outage pinning the band) never bills holders.
#[test]
fn r2l1_rent_is_max_at_cap_zero_and_zero_while_duration_pinned() {
    let mut env = Env::new(band_cfg());
    let (lp, long, short) = band_book(&mut env);
    env.warp(1);
    env.push_depth(PRICE, 1, 0).expect("attested 0");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 1, "cap 0: rent snapshot 1 (max rent)");
    let i0 = env.engine_asset().rent_index_long_num;
    env.warp(1);
    env.push(PRICE);
    env.crank(long.1).expect("crank");
    let i1 = env.engine_asset().rent_index_long_num;
    let per_slot = percolator::band_rent::rent_index_delta(PRICE, RENT_MAX as u64, 1).unwrap();
    assert!(i1 > i0, "rent charged at cap 0");
    assert_eq!(i1 - i0, per_slot, "exactly rent_max per slot");
    // Pin it: target +30%, the LONG never certified, so the epoch cannot advance; after E
    // (600) slots the accrual is duration-pinned (no move, no funding, no rent).
    let target = PRICE * 13 / 10;
    let mut pinned_at = None;
    let mut pinned_slot = 0u64;
    for k in 0..900u64 {
        env.warp(1);
        env.push(target);
        for who in [short.1, lp.account] {
            if let Err(e) = env.crank(who) {
                // nothing left to advance while pinned: NonProgress is not a failure here
                assert!(e.contains(&code(PercolatorError::EngineNonProgress)), "crank: {e}");
            }
        }
        if pinned_at.is_none() && k > 650 {
            pinned_at = Some(env.engine_asset().rent_index_long_num);
            pinned_slot = env.engine_asset().slot_last;
        }
    }
    let a = env.engine_asset();
    assert!(a.band_pin_since_slot != 0, "pinned");
    assert!(a.slot_last > pinned_slot + 100, "the pinned window WAS accrued ({} -> {})", pinned_slot, a.slot_last);
    assert_eq!(a.rent_index_long_num, pinned_at.unwrap(), "duration-pinned accruals charge no rent");
    assert!(pinned_at.unwrap() > i1, "rent was charged before the pin");
    env.assert_conservation();
}

/// Security review R2-L2: the tier thresholds are whole COLLATERAL TOKENS scaled by the mint's
/// decimals (stored at InitMarket in byte 46 = decimals + 1). 6 decimals: T1 = 25,000 x 1e6
/// atoms; 9 decimals: 25,000 x 1e9 atoms (round 2 compared 25,000 x 1e6 = 25 tokens there).
/// NEGATIVE CONTROL: a record claiming decimals 19 (byte 46 = 20) is refused by the validator.
#[test]
fn r2l2_thresholds_scale_with_collateral_decimals() {
    for dec in [6u8, 9] {
        MINT_DECIMALS.with(|d| d.set(dec));
        let mut p = phase4(BAND_BPS, RENT_MAX);
        p.band_min_leg_notional = 10u64.pow(dec as u32 + 1); // the 10-token floor of this mint
        let env = env_with_launch(Cfg { slots: 1, phase4: Some(p), r_gap: 0 }, 500);
        MINT_DECIMALS.with(|d| d.set(6));
        let g = env.growth();
        assert_eq!(g.collateral_decimals_p1, dec + 1);
        let unit = 10u64.pow(dec as u32);
        assert_eq!(g.tier_thresholds_e6(), [25_000 * unit, 100_000 * unit, 500_000 * unit]);
        assert_eq!(g.depth_seed_e6(), 25_000 * unit - 1);
    }
    let env = Env::new(band_cfg());
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let mut g = state::read_asset_growth(&acc.data, 0, env.engine_imr).unwrap().unwrap();
    g.collateral_decimals_p1 = 20;
    assert!(state::write_asset_growth(&mut acc.data, 0, &g, env.engine_imr).is_err(), "decimals 19 refused");
}

/// Security review D-L2 (the reviewer's straddle): a whale holds the inflated reading for three
/// samples straddling a calendar boundary `k * 9,000` (slots k*9,000 - 2, -1, k*9,000). Round 2
/// (gate on `slot / 9,000`) doubled at the second sample AND again at the third -- 4x one slot
/// apart. Now a rise needs >= 9,000 slots since the last one: exactly one doubling in that
/// window, and the next doubling only 9,000 slots after it.
#[test]
fn d_l2_boundary_straddle_gets_one_doubling() {
    let mut env = env_with_launch(band_cfg(), 500);
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let real = 7_000 * USD_E6;
    let inflated = 50_000_000 * USD_E6;
    env.warp(1);
    env.depth_twice(real);
    assert_eq!(env.growth().depth_last_good_e6, real);
    // past the first window, end right before a calendar boundary
    let w = env.next_rise_slot();
    let k = (w / 9_000 + 1) * 9_000;
    env.warp(k - 3 - env.slot);
    env.push_depth(PRICE, 1, real).expect("honest, k*9000 - 3");
    env.warp(1);
    env.push_depth(PRICE, 1, inflated).expect("inflated, k*9000 - 2");
    env.warp(1);
    env.push_depth(PRICE, 1, inflated).expect("inflated, k*9000 - 1: the pair -> one doubling");
    assert_eq!(env.growth().depth_last_good_e6, 2 * real);
    env.warp(1);
    assert_eq!(env.clock_slot() % 9_000, 0, "a new calendar epoch");
    env.push_depth(PRICE, 1, inflated).expect("inflated, k*9000");
    assert_eq!(env.growth().depth_last_good_e6, 2 * real, "D-L2: no second doubling one slot later");
    env.settle_rent(lp.account, lp.account).expect("tag 106");
    assert_eq!(env.growth().rent_n_cap_q, 2 * real / 2 / 10, "κ cap 2x honest, not 4x");
    // 9,000 slots after the rise: the next doubling
    let rise = env.clock_slot() - 1;
    env.warp(rise + 9_000 + 64 - env.slot);
    env.push_depth(PRICE, 1, inflated).expect("one window later");
    assert_eq!(env.growth().depth_last_good_e6, 4 * real);
}

/// Security review D-L1: growth markets refuse collateral with more than 12 decimals at
/// InitMarket (GrowthInvalidConfig, 94): at >= 14 decimals the thresholds and the depths both
/// saturated u64 and met (tier 3 from ~18 tokens). 12 decimals is accepted; 13 and 18 refused.
#[test]
fn d_l1_collateral_decimals_above_12_refused() {
    for (dec, ok) in [(12u8, true), (13, false), (18, false)] {
        MINT_DECIMALS.with(|d| d.set(dec));
        let mut p = phase4(BAND_BPS, RENT_MAX);
        p.band_min_leg_notional = 10u64.saturating_pow(dec as u32 + 1);
        L_LAUNCH.with(|l| l.set(500));
        let r = Env::try_new(Cfg { slots: 1, phase4: Some(p), r_gap: 0 });
        L_LAUNCH.with(|l| l.set(1_000));
        MINT_DECIMALS.with(|d| d.set(6));
        match (ok, r) {
            (true, Ok(env)) => {
                let g = env.growth();
                assert_eq!(g.collateral_decimals_p1, 13);
                assert_eq!(g.tier_thresholds_e6()[2], 500_000 * 1_000_000_000_000, "no saturation at 12");
            }
            (false, Err(e)) => assert!(e.contains(&code(PercolatorError::GrowthInvalidConfig)), "{dec}: {e}"),
            (ok, r) => panic!("decimals {dec}: expected ok={ok}, got {:?}", r.map(|_| ())),
        }
    }
}

// ---------------------------------------------------------------------------
// v2.2 F1 (2026-10-14): a permissionless refresh that leaves an account below maintenance
// continues into ONE liquidation step in the same instruction (ledger
// `v22-f1-refresh-liquidation-2026-10-14.md`). Negative controls run the DEPLOYED bytes
// (`F1_BASE_SO`, wrapper 8dbcd47a = sha bebb5237...) through the same transactions.
// ---------------------------------------------------------------------------

/// The deployed wrapper for the differential / negative-control tests. Those tests are
/// `#[ignore]`d in the default suite (the path is machine-local) and are run explicitly with
/// `F1_BASE_SO=<deployed .so> cargo test ... -- --ignored v22_f1_`; a missing path is a FAILURE,
/// never a pass.
fn f1_base_so() -> PathBuf {
    let p = PathBuf::from(std::env::var_os("F1_BASE_SO").expect("F1_BASE_SO (the deployed wrapper .so) must be set"));
    assert!(p.exists(), "F1_BASE_SO {p:?} does not exist");
    p
}

fn f1_env(so: Option<PathBuf>, cfg: Cfg) -> Env {
    PROG_SO.with(|p| *p.borrow_mut() = so);
    let env = Env::new(cfg);
    PROG_SO.with(|p| *p.borrow_mut() = None);
    env
}

/// An off-band v2.2 market (phase-4 block, band off, no rent): the deployed SOL/JUP/... shape.
fn f1_off_band_cfg() -> Cfg {
    Cfg { slots: 1, phase4: Some(phase4(0, 0)), r_gap: 400 }
}

fn f1_crank_ix(env: &Env, portfolio: Pubkey, observe: bool) -> Instruction {
    Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
        ],
        data: ProgInstruction::PermissionlessCrank {
            now_slot: env.slot,
            observations: if observe { vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] } else { vec![] },
        }
        .encode(),
    }
}

/// One transaction of crank instructions (after the heap + CU-limit budget instructions, so the
/// first crank is instruction 2).
fn f1_send(env: &mut Env, ixs: &[Instruction], cu_limit: u32) -> Result<u64, String> {
    env.svm.expire_blockhash();
    let mut all = vec![
        ComputeBudgetInstruction::request_heap_frame(128 * 1024),
        ComputeBudgetInstruction::set_compute_unit_limit(cu_limit),
    ];
    all.extend_from_slice(ixs);
    let tx = Transaction::new_signed_with_payer(&all, Some(&env.payer.pubkey()), &[&env.payer], env.svm.latest_blockhash());
    match env.svm.send_transaction(tx) {
        Ok(m) => {
            LAST_LOGS.with(|l| *l.borrow_mut() = m.logs.clone());
            Ok(m.compute_units_consumed)
        }
        Err(e) => {
            LAST_LOGS.with(|l| *l.borrow_mut() = e.meta.logs.clone());
            Err(format!("{:?}", e.err))
        }
    }
}

fn f1_hlock(env: &Env) -> bool {
    let mut data = env.svm.get_account(&env.market).unwrap().data;
    let (_, g) = state::market_view_mut(&mut data).unwrap();
    g.header.bankruptcy_hlock_active != 0
}

fn f1_insurance(env: &Env) -> u128 {
    env.engine_header().2
}

/// (certified equity, certified maintenance requirement, certified deficit) of `p`.
fn f1_cert(env: &Env, p: Pubkey) -> (i128, u128, u128) {
    let c = env.portfolio_state(p).health_cert;
    (c.certified_equity, c.certified_maintenance_req, c.certified_liq_deficit)
}

/// Margin (equity / notional at the effective price) in bps, from the account's certificate.
fn f1_margin_bps(env: &Env, p: Pubkey) -> i128 {
    let pos = env.pos(p).unsigned_abs();
    let eff = env.engine_asset().effective_price as u128;
    let notional = pos * eff / POS_SCALE;
    if notional == 0 {
        return i128::MAX;
    }
    f1_cert(env, p).0 * 10_000 / notional as i128
}

/// Advance one slot and push the mark `step_bps` below the current effective price (inside the
/// 4 bps/slot clamp, so the effective price follows with no target lag: liquidation is driven
/// by price, not by the lag penalty).
fn f1_step_price(env: &mut Env, step_bps: u64) {
    env.warp(1);
    let eff = env.engine_asset().effective_price;
    env.push(eff * (10_000 - step_bps) / 10_000);
}

/// The deployed v2.2 sweep's transaction for one round (`cross-cluster/v22/sweep.ts`:
/// `[observation crank, refresh xN]`): the observation crank goes through the vault LP (the
/// accrue target) and every trader gets ONE plain refresh crank. A refresh refused NonProgress
/// (Custom 22) at a known index is pruned and the rest re-sent, as the keeper does.
fn f1_sweep(env: &mut Env, lp: Pubkey, traders: &[Pubkey]) -> Result<u64, String> {
    f1_sweep_counted(env, lp, traders).map(|(cu, _)| cu)
}

/// `f1_sweep`, also returning how many refreshes the keeper's no-code rule DEFERRED: a failure
/// without a program code (compute exhaustion) cuts the tail by ceil(n/4), at most 3 times
/// (`sweep.ts` shrink); the cut refreshes wait for the next round.
fn f1_sweep_counted(env: &mut Env, lp: Pubkey, traders: &[Pubkey]) -> Result<(u64, usize), String> {
    let mut targets: Vec<Pubkey> = traders.to_vec();
    let mut shrinks = 0;
    let mut deferred = 0usize;
    loop {
        let mut ixs = vec![f1_crank_ix(env, lp, true)];
        ixs.extend(targets.iter().map(|t| f1_crank_ix(env, *t, false)));
        match f1_send(env, &ixs, 1_400_000) {
            Ok(cu) => return Ok((cu, deferred)),
            Err(e) => {
                let pruned = (0..targets.len()).find(|i| e.contains(&format!("InstructionError({}, Custom(22))", i + 3)));
                let no_code = !e.contains("Custom(");
                match pruned {
                    Some(i) => {
                        targets.remove(i);
                    }
                    None if no_code && targets.len() > 1 && shrinks < 3 => {
                        shrinks += 1;
                        let cut = targets.len().div_ceil(4);
                        targets.truncate(targets.len() - cut);
                        deferred += cut;
                    }
                    None => return Err(e),
                }
            }
        }
    }
}

/// Outcome of walking one ~8.3x long down 4 bps a slot on an off-band market, one deployed
/// sweep per slot.
#[derive(Debug)]
struct F1Walk {
    /// Slot index of the first reduction of the long (None = never reduced while solvent).
    reduced_at: Option<usize>,
    /// Margin (bps) the long was certified at in the round BEFORE the reduction.
    margin_before_bps: i128,
    /// Margin (bps) right after the reduction.
    margin_after_bps: i128,
    /// Size before / after the first reduction.
    pos_before: i128,
    pos_after: i128,
    /// Certified equity went negative before any reduction.
    bankrupt: bool,
    hlock: bool,
    insurance_delta: i128,
    rounds: usize,
    max_sweep_cu: u64,
}

fn f1_open_long(env: &mut Env, deposit_usd: u128, units: i128) -> (Lp, (Keypair, Pubkey)) {
    env.auth_mark();
    let lp = env.lp(10_000 * USD);
    let long = env.trader(deposit_usd * USD);
    env.trade_cpi(&long.0, long.1, &lp, units * Q).expect("open long");
    // The keeper's catch-up: the asset clock reaches the wall clock before the walk starts
    // (LiteSVM's clock starts at 0 while `env.slot` starts at 1: sync it first).
    env.warp(0);
    env.crank_current(lp.account);
    assert!(env.engine_asset().slot_last >= env.slot, "asset clock caught up");
    (lp, long)
}

fn f1_walk(so: Option<PathBuf>, cfg: Cfg, max_rounds: usize) -> F1Walk {
    let mut env = f1_env(so, cfg);
    let (lp, long) = f1_open_long(&mut env, 12, 100);
    let mmr_bps = MMR as i128;
    let ins0 = f1_insurance(&env) as i128;
    let mut out = F1Walk {
        reduced_at: None,
        margin_before_bps: 0,
        margin_after_bps: 0,
        pos_before: env.pos(long.1),
        pos_after: env.pos(long.1),
        bankrupt: false,
        hlock: false,
        insurance_delta: 0,
        rounds: 0,
        max_sweep_cu: 0,
    };
    let mut prev_margin = f1_margin_bps(&env, long.1);
    for i in 0..max_rounds {
        out.rounds = i + 1;
        f1_step_price(&mut env, 4);
        let pos_before = env.pos(long.1);
        let cu = f1_sweep(&mut env, lp.account, &[long.1]).unwrap_or_else(|e| panic!("round {i}: sweep failed: {e}\n{:#?}", LAST_LOGS.with(|l| l.borrow().clone())));
        out.max_sweep_cu = out.max_sweep_cu.max(cu);
        let pos = env.pos(long.1);
        let (eq, _, _) = f1_cert(&env, long.1);
        if pos.unsigned_abs() < pos_before.unsigned_abs() {
            out.reduced_at = Some(i);
            out.margin_before_bps = prev_margin;
            out.margin_after_bps = f1_margin_bps(&env, long.1);
            out.pos_before = pos_before;
            out.pos_after = pos;
            break;
        }
        if eq < 0 {
            out.bankrupt = true;
        }
        if f1_hlock(&env) {
            out.hlock = true;
        }
        if out.bankrupt && out.hlock {
            break;
        }
        prev_margin = f1_margin_bps(&env, long.1);
        if std::env::var_os("F1_TRACE").is_some() && i % 50 == 0 {
            let a = env.engine_asset();
            println!("F1TRACE round {i} eff {} target {} margin {prev_margin} cert {:?} cu {cu}", a.effective_price, a.raw_oracle_target_price, f1_cert(&env, long.1));
        }
        let _ = mmr_bps;
    }
    out.hlock |= f1_hlock(&env);
    out.insurance_delta = f1_insurance(&env) as i128 - ins0;
    env.assert_conservation();
    out
}

/// F1 fixed: with ONE plain refresh per round (the deployed keeper's shape), the long is
/// liquidated in the first round it is certified below maintenance (MMR 5%), partially (the
/// engine's own sizing restores maintenance), with no h-lock and no bankruptcy.
#[test]
fn v22_f1_off_band_one_refresh_per_round_liquidates_at_maintenance() {
    let w = f1_walk(None, f1_off_band_cfg(), 600);
    println!("F1WALK patched {w:?}");
    let at = w.reduced_at.unwrap_or_else(|| panic!("never liquidated: {w:?}"));
    assert!(!w.bankrupt, "went bankrupt before the liquidation: {w:?}");
    assert!(!w.hlock, "bankruptcy h-lock latched: {w:?}");
    // The minimum-progress rule lets the shortfall reach 0.5% of the requirement (2.5 bps of
    // notional at MMR 5%) first: the liquidation lands within a few bps of maintenance.
    assert!(w.margin_before_bps >= MMR as i128 - 5, "liquidated late, well below maintenance: {w:?}");
    assert!(w.margin_before_bps < MMR as i128 + 100, "liquidated far above maintenance: {w:?}");
    assert!(w.pos_after != 0 && w.pos_after.unsigned_abs() < w.pos_before.unsigned_abs(), "partial close expected: {w:?}");
    assert!(w.margin_after_bps >= MMR as i128, "the liquidation must restore maintenance: {w:?}");
    assert!(w.insurance_delta > 0, "the liquidation fee reaches insurance: {w:?}");
    assert!(at > 10, "vacuity: the long must start healthy: {w:?}");
}

/// NEGATIVE CONTROL on the deployed bytes: the same transactions never liquidate; the long runs
/// to negative equity and the bankruptcy h-lock latches (F1 as found on devnet).
#[test]
#[ignore = "negative control: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_negative_control_deployed_bytes_run_to_bankruptcy() {
    let w = f1_walk(Some(f1_base_so()), f1_off_band_cfg(), 600);
    println!("F1WALK deployed {w:?}");
    assert!(w.reduced_at.is_none(), "deployed bytes liquidated with one crank per round: {w:?}");
    assert!(w.bankrupt, "expected the long to go bankrupt: {w:?}");
    assert!(w.hlock, "expected the bankruptcy h-lock: {w:?}");
}

/// Every account a differential test compares: the market and the given portfolios.
fn f1_state(env: &Env, keys: &[Pubkey]) -> Vec<Vec<u8>> {
    let mut v = vec![env.svm.get_account(&env.market).unwrap().data];
    v.extend(keys.iter().map(|k| env.svm.get_account(k).unwrap().data));
    v
}

/// Differential walk, deployed bytes vs patched bytes, same seeded keys and the same
/// transactions: one deployed-shape sweep per slot over `traders` (opened long at `deposit_usd`
/// each). Returns the first round whose post-state differs (None = identical throughout), the
/// number of rounds in which any trader was reduced (patched run), and whether any trader was
/// ever certified below maintenance (non-vacuity).
fn f1_diff_walk(cfg: fn() -> Cfg, deposits: &[u128], step_bps: u64, rounds: usize, stop_at_divergence: bool) -> (Option<usize>, usize, bool) {
    f1_diff_walk_with(cfg, deposits, step_bps, rounds, stop_at_divergence, false)
}

/// `f1_diff_walk`; with `second_crank`, every round also sends each trader a lone crank in the
/// same slot after the sweep (separate transactions: the legacy second-crank liquidation path),
/// and state is compared after the sweep AND after the second cranks.
fn f1_diff_walk_with(cfg: fn() -> Cfg, deposits: &[u128], step_bps: u64, rounds: usize, stop_at_divergence: bool, second_crank: bool) -> (Option<usize>, usize, bool) {
    let mut runs: Vec<(Env, Lp, Vec<Pubkey>)> = Vec::new();
    for so in [Some(f1_base_so()), None] {
        let mut env = f1_env(so, cfg());
        env.auth_mark();
        let lp = env.lp(10_000 * USD);
        let mut traders = Vec::new();
        for d in deposits {
            let t = env.trader(*d * USD);
            env.trade_cpi(&t.0, t.1, &lp, 100 * Q).expect("open long");
            traders.push(t.1);
        }
        env.warp(0);
        env.crank_current(lp.account);
        runs.push((env, lp, traders));
    }
    let mut first_div = None;
    let mut reductions = 0usize;
    let mut ever_below = false;
    for r in 0..rounds {
        let mut outs = Vec::new();
        let mut mids = Vec::new();
        let all: Vec<Pubkey> = runs[0].2.iter().copied().chain(std::iter::once(runs[0].1.account)).collect();
        for (env, lp, traders) in runs.iter_mut() {
            f1_step_price(env, step_bps);
            let before: Vec<i128> = traders.iter().map(|t| env.pos(*t)).collect();
            let mut res = f1_sweep(env, lp.account, traders).map(|_| ());
            mids.push(f1_state(env, &all));
            if second_crank {
                for t in traders.iter() {
                    let ix = f1_crank_ix(env, *t, false);
                    let r2 = f1_send(env, &[ix], 1_400_000).map(|_| ());
                    if res.is_ok() {
                        res = r2.or_else(|e| if e.contains("Custom(22)") { Ok(()) } else { Err(e) });
                    }
                }
            }
            let reduced = traders.iter().zip(before.iter()).any(|(t, b)| env.pos(*t).unsigned_abs() < b.unsigned_abs());
            outs.push((res, reduced));
        }
        let (base_env, _, keys) = &runs[0];
        for t in keys {
            let (eq, mm, _) = f1_cert(base_env, *t);
            if eq < 0 || (eq as u128) < mm {
                ever_below = true;
            }
        }
        if outs[1].1 {
            reductions += 1;
        }
        let same = outs[0].0 == outs[1].0 && mids[0] == mids[1] && f1_state(&runs[0].0, &all) == f1_state(&runs[1].0, &all);
        if !same && first_div.is_none() {
            first_div = Some(r);
            if stop_at_divergence {
                break;
            }
        }
    }
    (first_div, reductions, ever_below)
}

/// Healthy accounts are unchanged: three longs that stay above maintenance through a 6% fall
/// get byte-identical market and portfolio state, round by round, on the deployed and the
/// patched bytes (the follow-on never fires on a healthy account).
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_healthy_accounts_are_byte_identical_to_the_deployed_bytes() {
    let (div, reductions, below) = f1_diff_walk(f1_off_band_cfg, &[40, 60, 100], 4, 150, false);
    assert!(!below, "vacuity guard: every account must stay healthy in this test");
    assert_eq!(reductions, 0);
    assert_eq!(div, None, "healthy state diverged from the deployed bytes at round {div:?}");
}

/// The patched bytes diverge from the deployed bytes EXACTLY at the first round an account is
/// certified below maintenance, never earlier.
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_divergence_starts_exactly_at_the_first_below_maintenance_round() {
    let crossing = f1_walk(None, f1_off_band_cfg(), 600).reduced_at.expect("patched liquidates");
    let (div, _, below) = f1_diff_walk(f1_off_band_cfg, &[12], 4, 600, true);
    assert!(below, "vacuity: the long must go below maintenance");
    assert_eq!(div, Some(crossing), "first divergence {div:?} vs first below-maintenance round {crossing}");
}

/// Band markets are unchanged: on a band market the band's own pass liquidates (a pinned
/// accrual keeps certificates current across transactions), and the patched bytes produce
/// byte-identical state round by round, liquidations included (no double liquidation).
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_band_market_is_byte_identical_including_its_liquidations() {
    // Band markets are single-slot (105) and so carry funding (94); while pinned the funding keeps
    // un-currenting certificates, so the band market's liquidation is the SECOND crank of a slot
    // (here a separate same-slot transaction per trader). State is compared after the sweep
    // transaction (the follow-on must NOT have fired there) and after the second cranks (the
    // band liquidations, identical on both builds: nothing liquidated twice).
    let (div, reductions, below) = f1_diff_walk_with(band_cfg, &[12, 13], 4, 300, false, true);
    println!("F1BAND div {div:?} reductions {reductions} below {below}");
    assert!(below, "vacuity: a long must go below maintenance on the band market");
    assert!(reductions >= 1, "vacuity: the band pass must liquidate at least once");
    assert_eq!(div, None, "band market diverged from the deployed bytes at round {div:?}");
}

/// Walk a single ~8.3x long to the round BEFORE it would cross maintenance; returns
/// (env, lp, long) with the price for the crossing round pushed but nothing cranked.
fn f1_to_crossing(so: Option<PathBuf>) -> (Env, Lp, (Keypair, Pubkey)) {
    f1_to_crossing_with(so, |_| {})
}

fn f1_to_crossing_with(so: Option<PathBuf>, setup: impl FnOnce(&mut Env)) -> (Env, Lp, (Keypair, Pubkey)) {
    let crossing = f1_walk(None, f1_off_band_cfg(), 600).reduced_at.expect("patched liquidates");
    let mut env = f1_env(so, f1_off_band_cfg());
    setup(&mut env);
    let (lp, long) = f1_open_long(&mut env, 12, 100);
    for _ in 0..crossing {
        f1_step_price(&mut env, 4);
        f1_sweep(&mut env, lp.account, &[long.1]).expect("sweep");
    }
    f1_step_price(&mut env, 4);
    (env, lp, long)
}

/// The legacy two-crank transaction `[observation, refresh T, crank T]`:
/// - deployed bytes: the second crank of T liquidates (the only way it ever could);
/// - patched bytes: the FIRST crank of T already liquidated, so the second answers
///   NonProgress (Custom 22) at its index and the transaction fails atomically; the keeper's
///   prune (drop the refused index, re-send) lands `[observation, refresh T]`;
/// - and that pruned patched transaction leaves state BYTE-IDENTICAL to the deployed bytes'
///   two-crank transaction: the follow-on is exactly the legacy second crank.
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_two_crank_shape_is_the_follow_on_byte_for_byte() {
    let (mut base, blp, blong) = f1_to_crossing(Some(f1_base_so()));
    let (mut patched, plp, plong) = f1_to_crossing(None);
    let three = |env: &Env, lp: Pubkey, t: Pubkey| vec![f1_crank_ix(env, lp, true), f1_crank_ix(env, t, false), f1_crank_ix(env, t, false)];
    let ixs = three(&base, blp.account, blong.1);
    let pos0 = base.pos(blong.1);
    f1_send(&mut base, &ixs, 1_400_000).expect("deployed: the two-crank shape lands");
    assert!(base.pos(blong.1).unsigned_abs() < pos0.unsigned_abs(), "deployed: second crank liquidates");
    let ixs = three(&patched, plp.account, plong.1);
    let e = f1_send(&mut patched, &ixs, 1_400_000).expect_err("patched: the second crank of T has nothing left");
    assert!(e.contains("InstructionError(4, Custom(22))"), "patched: expected NonProgress at the second crank of T: {e}");
    assert_eq!(patched.pos(plong.1), pos0, "the failed transaction rolled back");
    let pruned = vec![f1_crank_ix(&patched, plp.account, true), f1_crank_ix(&patched, plong.1, false)];
    f1_send(&mut patched, &pruned, 1_400_000).expect("patched: the pruned shape lands");
    let keys = [blong.1, blp.account];
    assert_eq!(f1_state(&base, &keys), f1_state(&patched, &keys), "follow-on != legacy second crank");
    assert!(!f1_hlock(&patched));
}

/// Compute + liveness: the deployed sweep's batched shape `[observation crank, refresh x8]`
/// (keeper `sweep.ts`: weight budget 32, a single-leg refresh weighs 4), all eight longs
/// crossing maintenance together and the price falling on for 80 more slots, so they re-cross
/// every round after each partial liquidation. Ordering as `settle-pairing.ts` (`heaviestFirst`:
/// equal weights, then larger position first, then key), no-code failures shrunk as `sweep.ts`.
/// Every transaction lands under 1.4M; nobody goes bankrupt; no h-lock; every long is liquidated.
#[test]
fn v22_f1_keeper_batch_of_eight_crossing_together_stays_live() {
    let run = |so: Option<PathBuf>, rounds_after: usize| {
        let mut env = f1_env(so, f1_off_band_cfg());
        env.auth_mark();
        let lp = env.lp(20_000 * USD);
        let mut traders = Vec::new();
        for _ in 0..8 {
            let t = env.trader(12 * USD);
            env.trade_cpi(&t.0, t.1, &lp, 100 * Q).expect("open long");
            traders.push(t.1);
        }
        env.warp(0);
        env.crank_current(lp.account);
        let mut max_cu = 0u64;
        let mut first = None;
        let mut liquidated = std::collections::BTreeSet::new();
        let mut deferred_total = 0usize;
        let mut min_margin = i128::MAX;
        let mut bankrupt = false;
        for r in 0..(191 + rounds_after) {
            f1_step_price(&mut env, 4);
            let mut order = traders.clone();
            order.sort_by(|a, b| env.pos(*b).cmp(&env.pos(*a)).then(a.to_string().cmp(&b.to_string())));
            let before: Vec<i128> = traders.iter().map(|t| env.pos(*t)).collect();
            let (cu, deferred) = f1_sweep_counted(&mut env, lp.account, &order)
                .unwrap_or_else(|e| panic!("round {r}: batched sweep failed: {e}"));
            max_cu = max_cu.max(cu);
            deferred_total += deferred;
            for (t, b) in traders.iter().zip(before.iter()) {
                if env.pos(*t).unsigned_abs() < b.unsigned_abs() {
                    liquidated.insert(*t);
                    first.get_or_insert(r);
                }
                let (eq, _, _) = f1_cert(&env, *t);
                bankrupt |= eq < 0;
                if first.is_some() {
                    min_margin = min_margin.min(f1_margin_bps(&env, *t));
                }
            }
        }
        env.assert_conservation();
        (first, liquidated.len(), deferred_total, max_cu, min_margin, bankrupt, f1_hlock(&env))
    };
    let (first, n, deferred, max_cu, min_margin, bankrupt, hlock) = run(None, 80);
    println!("F1BATCH patched: first liquidation round {first:?}, longs liquidated {n}/8, refreshes deferred by the keeper shrink {deferred}, max tx CU {max_cu}, min margin after the first liquidation {min_margin} bps (MMR {MMR}), bankrupt {bankrupt}, hlock {hlock}");
    assert!(max_cu <= 1_400_000);
    assert_eq!(n, 8, "every long liquidated");
    assert!(!bankrupt && !hlock);
    assert!(min_margin > 0, "nobody reaches zero equity");
}

/// NEGATIVE CONTROL for the batch: the deployed bytes, same eight longs, same sweeps: nobody is
/// liquidated and the market latches the bankruptcy h-lock.
#[test]
#[ignore = "negative control: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_negative_control_keeper_batch_on_deployed_bytes() {
    let mut env = f1_env(Some(f1_base_so()), f1_off_band_cfg());
    env.auth_mark();
    let lp = env.lp(20_000 * USD);
    let mut traders = Vec::new();
    for _ in 0..8 {
        let t = env.trader(12 * USD);
        env.trade_cpi(&t.0, t.1, &lp, 100 * Q).expect("open long");
        traders.push(t.1);
    }
    env.warp(0);
    env.crank_current(lp.account);
    let mut reduced = false;
    let mut max_cu = 0;
    for r in 0..340 {
        f1_step_price(&mut env, 4);
        let before: Vec<i128> = traders.iter().map(|t| env.pos(*t)).collect();
        let (cu, _) = f1_sweep_counted(&mut env, lp.account, &traders).unwrap_or_else(|e| panic!("round {r}: {e}"));
        max_cu = max_cu.max(cu);
        reduced |= traders.iter().zip(before.iter()).any(|(t, b)| env.pos(*t).unsigned_abs() < b.unsigned_abs());
    }
    println!("F1BATCH deployed: reduced {reduced}, hlock {}, max tx CU {max_cu}", f1_hlock(&env));
    assert!(!reduced);
    assert!(f1_hlock(&env));
}

/// Residual (recorded, NOT changed by F1, which leaves band markets alone by instruction): on a
/// band market whose funding (or rent) moves while the price is pinned, every accrual bumps
/// `funding_epoch`, so a below-maintenance long stays `band_liq_pending` and a one-crank sweep
/// never liquidates it -- on the deployed bytes and the patched bytes alike (byte-identical).
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_residual_band_with_live_funding_stalls_identically_on_both_builds() {
    let (div, reductions, below) = f1_diff_walk(band_cfg, &[12], 4, 400, false);
    println!("F1BANDFUND div {div:?} reductions {reductions} below {below}");
    assert!(below, "vacuity: the long goes below maintenance");
    assert_eq!(reductions, 0, "the stall: no liquidation on either build");
    assert_eq!(div, None, "band behaviour must be identical on both builds");
}

/// The cranker-reward tail: with a liquidation cranker share on, a refresh crank that carries
/// the caller's reward portfolio as its last account pays the follow-on's reward to it, exactly
/// as the legacy `[refresh T + cranker, crank T + cranker]` pair does on the deployed bytes
/// (byte-identical market, trader, LP and cranker state), and the reward is nonzero.
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_cranker_reward_tail_matches_the_legacy_pair_byte_for_byte() {
    let setup = |env: &mut Env| {
        let admin = env.admin.insecure_clone();
        let m = env.market;
        let data = env.svm.get_account(&m).unwrap().data;
        let seq = state::read_asset_control_sequences(&data, 0).unwrap().liquidation_fee + 1;
        env.send(
            ProgInstruction::UpdateLiquidationFeePolicy { cranker_share_bps: 2_000, policy_sequence: seq },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
        .expect("cranker share on");
    };
    let (mut base, blp, blong) = f1_to_crossing_with(Some(f1_base_so()), setup);
    let (mut patched, plp, plong) = f1_to_crossing_with(None, setup);
    let payer = base.payer.insecure_clone();
    let bc = base.portfolio(&payer, 0);
    let pc = patched.portfolio(&payer, 0);
    assert_eq!(bc, pc);
    let with_cranker = |env: &Env, t: Pubkey| {
        let mut ix = f1_crank_ix(env, t, false);
        ix.accounts.push(AccountMeta::new(bc, false));
        ix
    };
    let cap0 = base.portfolio_state(bc).capital;
    let ixs = vec![f1_crank_ix(&base, blp.account, true), with_cranker(&base, blong.1), with_cranker(&base, blong.1)];
    f1_send(&mut base, &ixs, 1_400_000).expect("deployed: legacy pair with reward tails");
    let ixs = vec![f1_crank_ix(&patched, plp.account, true), with_cranker(&patched, plong.1)];
    f1_send(&mut patched, &ixs, 1_400_000).expect("patched: one refresh with the reward tail");
    let keys = [blong.1, blp.account, bc];
    assert_eq!(f1_state(&base, &keys), f1_state(&patched, &keys), "reward follow-on != legacy pair");
    let cap1 = patched.portfolio_state(pc).capital;
    println!("F1REWARD cranker capital {cap0} -> {cap1}");
    assert!(cap1 > cap0, "vacuity: the cranker must be paid");
}

/// The bound vault LP keeps its own P3 path: the follow-on never runs on it. An LP walked below
/// maintenance (price up against its short) gets byte-identical state on both builds, round by
/// round, including the keeper's legacy same-slot second crank (its senior draw + liquidation).
#[test]
#[ignore = "differential: needs F1_BASE_SO=<deployed wrapper .so>"]
fn v22_f1_vault_lp_is_excluded_and_byte_identical() {
    let mut runs: Vec<(Env, Lp, Pubkey)> = Vec::new();
    for so in [Some(f1_base_so()), None] {
        let mut env = f1_env(so, f1_off_band_cfg());
        env.auth_mark();
        let lp = env.lp(14 * USD);
        let t = env.trader(1_000 * USD);
        env.trade_cpi(&t.0, t.1, &lp, 100 * Q).expect("open long against a thin LP");
        env.warp(0);
        env.crank_current(lp.account);
        // The vault LP's capacity cap keeps it far from maintenance; a TEST-ONLY state poke
        // (identical on both builds) sets its capital to 50,000 atoms above its requirement,
        // conserving vault >= C_tot + I (C_tot and the vault ledger move together).
        let (eq, mm, _) = f1_cert(&env, lp.account);
        let mut mk = env.svm.get_account(&env.market).unwrap();
        let mut pk = env.svm.get_account(&lp.account).unwrap();
        let (cfg, mut g) = state::read_market(&mk.data).unwrap();
        let mut pf = state::read_portfolio(&pk.data).unwrap();
        let cut = (eq as u128).saturating_sub(mm + 50_000);
        pf.capital -= cut;
        g.c_tot -= cut;
        g.vault -= cut;
        pf.health_cert.valid = false;
        state::write_market(&mut mk.data, &cfg, &g).unwrap();
        state::write_portfolio(&mut pk.data, &pf).unwrap();
        env.svm.set_account(env.market, mk).unwrap();
        env.svm.set_account(lp.account, pk).unwrap();
        runs.push((env, lp, t.1));
    }
    let mut lp_below = false;
    let mut lp_reduced = 0;
    for r in 0..120 {
        let mut st = Vec::new();
        for (env, lp, t) in runs.iter_mut() {
            env.warp(1);
            let eff = env.engine_asset().effective_price;
            env.push(eff * 10_004 / 10_000);
            let p0 = env.pos(lp.account);
            let a = f1_sweep(env, lp.account, &[*t]).map(|_| ());
            let mid = f1_state(env, &[lp.account, *t]);
            let ix = f1_crank_ix(env, lp.account, false);
            let b = f1_send(env, &[ix], 1_400_000).map(|_| ());
            if env.pos(lp.account).unsigned_abs() < p0.unsigned_abs() {
                lp_reduced += 1;
            }
            st.push((a, mid, b.map_err(|e| e.contains("Custom(22)")), f1_state(env, &[lp.account, *t])));
        }
        let (eq, mm, _) = f1_cert(&runs[0].0, runs[0].1.account);
        lp_below |= eq < 0 || (eq as u128) < mm;
        if std::env::var_os("F1_TRACE").is_some() && r % 25 == 0 {
            println!("F1TRACE r {r} lp cert {:?} pos {} eff {} res {:?}", f1_cert(&runs[0].0, runs[0].1.account), runs[0].0.pos(runs[0].1.account), runs[0].0.engine_asset().effective_price, st[0].0);
        }
        assert_eq!(st[0], st[1], "vault LP diverged at round {r}");
        if runs[0].0.pos(runs[0].1.account) == 0 {
            break;
        }
    }
    println!("F1VAULTLP lp_below {lp_below} lp reductions (both builds) {}", lp_reduced / 2);
    assert!(lp_below, "vacuity: the vault LP must go below maintenance");
}

/// Minimum progress (dust): once a liquidation restored the long exactly to its requirement, a
/// slow drift (1 bp of price a slot) puts it a dust amount under maintenance every round. The
/// refresh then does NOT liquidate while the shortfall is under 0.5% of the requirement (the
/// account stays solvent and the engine still classifies it liquidatable, so the legacy second
/// crank keeps working), and liquidates as soon as the shortfall is material.
#[test]
fn v22_f1_dust_shortfall_waits_for_material_progress() {
    let (mut env, lp, long) = f1_to_crossing(None);
    f1_sweep(&mut env, lp.account, &[long.1]).expect("crossing sweep");
    // Drive to the first liquidation (4 bps steps).
    let mut guard = 0;
    while f1_cert(&env, long.1).2 != 0 || env.pos(long.1) == 100 * Q {
        f1_step_price(&mut env, 4);
        f1_sweep(&mut env, lp.account, &[long.1]).expect("sweep");
        guard += 1;
        assert!(guard < 20, "no first liquidation");
    }
    let mut dust_rounds = 0usize;
    let mut liquidations = Vec::new();
    for r in 0..60 {
        f1_step_price(&mut env, 1);
        let p0 = env.pos(long.1);
        f1_sweep(&mut env, lp.account, &[long.1]).expect("sweep");
        let (eq, mm, def) = f1_cert(&env, long.1);
        if env.pos(long.1).unsigned_abs() < p0.unsigned_abs() {
            liquidations.push(r);
        } else if def != 0 {
            dust_rounds += 1;
            assert!(eq > 0, "skipped while insolvent");
            let short = mm - eq as u128;
            assert!(short < percolator_prog::f1_refresh_liq_v22::min_shortfall(mm), "a material shortfall was skipped: {short} of {mm}");
        }
    }
    println!("F1DUST dust rounds skipped {dust_rounds}, liquidation rounds {liquidations:?}");
    assert!(dust_rounds >= 5, "vacuity: dust shortfalls must occur");
    assert!(liquidations.len() >= 3, "material shortfalls still liquidate");
    assert!(liquidations.windows(2).all(|w| w[1] - w[0] >= 2), "never a liquidation every round on a 1 bp drift");
    // The legacy second crank still liquidates a dust shortfall (engine predicate unchanged).
    f1_step_price(&mut env, 1);
    f1_sweep(&mut env, lp.account, &[long.1]).expect("sweep");
    if f1_cert(&env, long.1).2 != 0 {
        let p0 = env.pos(long.1);
        let ix = f1_crank_ix(&env, long.1, false);
        f1_send(&mut env, &[ix], 1_400_000).expect("legacy second crank");
        assert!(env.pos(long.1).unsigned_abs() < p0.unsigned_abs());
    }
    assert!(!f1_hlock(&env));
}

// ---------------------------------------------------------------------------
// CONTROLLER ROLLBACK build (fix/v22-controller-rollback-2026-10-17): the deployed v2.2 line
// (aca02ba6 / c659c91d) made tolerant of every growth record the adaptive controller
// (666df893 + ports) can write. The controller's byte patterns (security review
// `security-review-v22-growth-controller-2026-10-15.md` F-3): flags (39) = 0x01 / 0x03, bytes 0..4
// the volatility variance and 4..8 the rent stamp (NOT c_launch), 30..34 / 34..38 the depth
// window (cur / prev) and 118..120 its bucket. A real differential (records written by the real
// controller BPF, then the program swapped for this build) is
// `controller_rollback_differential_from_controller_bpf` (ignored; needs CONTROLLER_SO).
// ---------------------------------------------------------------------------

impl Env {
    /// STATE POKE: overwrite bytes of the growth record at `off` (record-relative).
    fn poke_growth_raw(&mut self, off: usize, bytes: &[u8]) {
        let mut acc = self.svm.get_account(&self.market).unwrap();
        let r = state::asset_growth_range(&acc.data, 0).unwrap();
        acc.data[r.start + off..r.start + off + bytes.len()].copy_from_slice(bytes);
        self.svm.set_account(self.market, acc).unwrap();
    }

    /// The raw 120-byte growth record.
    fn growth_bytes(&self) -> Vec<u8> {
        let acc = self.svm.get_account(&self.market).unwrap();
        let r = state::asset_growth_range(&acc.data, 0).unwrap();
        acc.data[r].to_vec()
    }

    /// Whether the growth record of asset 0 decodes (the production reader).
    fn growth_decodes(&self) -> bool {
        let acc = self.svm.get_account(&self.market).unwrap();
        state::read_asset_growth(&acc.data, 0, self.engine_imr).is_ok()
    }

    /// Everything a rollback must accept: a 35 B push, a 44 B push, a crank, a rent settlement
    /// (reads the record) and a trade (reads the cap).
    fn rollback_exercise(&mut self, lp: &Lp, tag: &str) {
        self.warp(1);
        self.push(PRICE);
        self.warp(1);
        self.push_depth(PRICE, 1, 600 * USD as u64).unwrap_or_else(|e| panic!("{tag}: 44 B push refused: {e}"));
        self.crank(lp.account).unwrap_or_else(|e| panic!("{tag}: crank refused: {e}"));
        self.crank_current(lp.account);
        self.settle_rent(lp.account, lp.account).unwrap_or_else(|e| panic!("{tag}: tag 106 refused: {e}"));
        let t = self.trader(1_000 * USD);
        self.trade_cpi(&t.0, t.1, lp, 10 * Q).unwrap_or_else(|e| panic!("{tag}: trade refused: {e}"));
        self.assert_conservation();
    }

    /// STATE POKE: the shape the controller leaves after a push: flags, variance + rent stamp at
    /// 0..8 (not a c_launch), the depth window at 30..38 and its bucket at 118..120.
    fn poke_controller_record(&mut self, flags: u8) {
        self.poke_growth_raw(0, &1_234_567u32.to_le_bytes()); // variance x100
        self.poke_growth_raw(4, &777u32.to_le_bytes()); // rent stamp
        self.poke_growth_raw(30, &600u32.to_le_bytes()); // window cur
        self.poke_growth_raw(34, &550u32.to_le_bytes()); // window prev
        self.poke_growth_raw(39, &[flags]);
        self.poke_growth_raw(118, &4242u16.to_le_bytes()); // bucket
    }
}

fn assert_controller_bytes_dropped(b: &[u8], tag: &str) {
    assert_eq!(b[39], 0, "{tag}: flags cleared on the rollback's write");
    assert_eq!(&b[30..38], &[0u8; 8], "{tag}: window cur/prev zeroed");
    assert_eq!(&b[118..120], &[0u8; 2], "{tag}: window bucket zeroed together with the window");
}

/// The unmodified (deployed aca02ba6) validator reads these records as corrupt (flags != 0,
/// non-zero 30..38 / 118..120): push, crank, rent and trade all fail InvalidAccountData. The
/// rollback accepts them, runs every core instruction, and its first write drops the controller
/// bytes (zeroing 30..38 and 118..120 together, flags back to 0).
#[test]
fn controller_rollback_accepts_flags_1_record() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    env.depth_twice(600 * USD as u64);
    env.poke_controller_record(0x01);
    assert!(env.growth_decodes(), "the tolerant reader decodes a flags-1 record");
    let before = env.growth_bytes();
    env.rollback_exercise(&lp, "flags 1");
    let after = env.growth_bytes();
    assert_controller_bytes_dropped(&after, "flags 1");
    // Everything else (configuration, ceiling, tier table, decimals) is carried over.
    for (name, r) in [("lambda..r_gap", 16..30usize), ("version", 38..39), ("decimals+1", 46..47), ("tier table", 96..114)] {
        assert_eq!(&after[r.clone()], &before[r.clone()], "{name} untouched");
    }
    assert!(env.growth().ceil_x100 >= 100, "ceiling intact and decodable");
}

#[test]
fn controller_rollback_accepts_flags_3_record() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    env.depth_twice(600 * USD as u64);
    env.poke_controller_record(0x03);
    assert!(env.growth_decodes());
    env.rollback_exercise(&lp, "flags 3");
    assert_controller_bytes_dropped(&env.growth_bytes(), "flags 3");
}

/// A controller record on a market the controller also stamped DEPTH_EVER (the sticky bit the
/// combined line keeps): the rollback keeps the sticky bit (no cap-off) while dropping the window.
#[test]
fn controller_rollback_keeps_depth_ever_and_last_good_from_a_controller_record() {
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    env.depth_twice(600 * USD as u64);
    let slot = env.clock_slot();
    env.poke_controller_record(0x03);
    env.poke_growth_raw(44, &[0x85]);
    env.poke_growth_raw(80, &(600 * USD as u64).to_le_bytes());
    env.poke_growth_raw(88, &slot.to_le_bytes());
    env.poke_growth_raw(114, &((slot / 64) as u32).to_le_bytes());
    env.rollback_exercise(&lp, "flags 3 + EVER");
    let b = env.growth_bytes();
    assert_eq!(b[44] & 0x80, 0x80, "DEPTH_EVER survives");
    assert_eq!(&b[80..88], &(600 * USD as u64).to_le_bytes(), "last-good depth survives");
    assert_controller_bytes_dropped(&b, "flags 3 + EVER");
}

/// Bytes the controller never writes stay refused: flags bit 1 alone, any other flag bit, and a
/// non-zero window on a record whose flags are 0 (the combined shape).
#[test]
fn controller_rollback_still_refuses_records_the_controller_cannot_write() {
    for (flags, why) in [(0x02u8, "bit 1 without bit 0"), (0x04, "bit 2"), (0x05, "bits 0 + 2"), (0x80, "bit 7"), (0xff, "all bits")] {
        let mut env = Env::new(band_cfg());
        env.auth_mark();
        let _lp = env.lp(1_000 * USD);
        assert!(env.growth_decodes(), "control: unpoked record decodes");
        env.poke_growth_raw(39, &[flags]);
        assert!(!env.growth_decodes(), "flags {flags:#04x} ({why}) must be refused");
    }
    // flags 0 with a non-zero window is NOT a controller record: still refused.
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let _lp = env.lp(1_000 * USD);
    env.poke_growth_raw(30, &9u32.to_le_bytes());
    assert!(!env.growth_decodes(), "flags 0 + window bytes is refused as before");
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let _lp = env.lp(1_000 * USD);
    env.poke_growth_raw(118, &9u16.to_le_bytes());
    assert!(!env.growth_decodes(), "flags 0 + bucket is refused as before");
    // A controller record whose other invariants are broken (ceiling above the tier) is refused.
    let mut env = Env::new(band_cfg());
    env.auth_mark();
    let _lp = env.lp(1_000 * USD);
    env.poke_controller_record(0x01);
    env.poke_growth_raw(24, &u16::MAX.to_le_bytes());
    assert!(!env.growth_decodes(), "the remaining validator clauses still bind");
}

/// DIFFERENTIAL (ignored; `CONTROLLER_SO` = the controller wrapper at the IDs this test env
/// mounts, `GROWTH_WRAPPER_SO` or target/deploy = this rollback build): the market is created and
/// driven by the real controller BPF (35 B and 44 B pushes, which write flags / window / variance,
/// cranks, a trade), then the PROGRAM IS SWAPPED for this build in the same LiteSVM and every
/// operation must still land; finally the controller is swapped back (re-upgrade) and lands.
#[test]
#[ignore]
fn controller_rollback_differential_from_controller_bpf() {
    let controller = PathBuf::from(std::env::var_os("CONTROLLER_SO").expect("CONTROLLER_SO"));
    let rollback = std::fs::read(program_path()).expect("rollback .so");
    let mut env = f1_env(Some(controller.clone()), band_cfg());
    let ctrl = std::fs::read(&controller).unwrap();
    env.auth_mark();
    let lp = env.lp(1_000 * USD);
    env.depth_twice(600 * USD as u64);
    for _ in 0..3 {
        env.warp(2);
        env.push(PRICE);
        env.warp(2);
        env.push_depth(PRICE, 1, 600 * USD as u64).expect("controller 44 B push");
    }
    let g = env.growth_bytes();
    println!("controller record: flags={:#04x} 0..8={:?} 30..38={:?} 118..120={:?}", g[39], &g[0..8], &g[30..38], &g[118..120]);
    assert_ne!(g[39] & 1, 0, "the controller flagged the record: this really is its layout");
    let t = env.trader(1_000 * USD);
    env.trade_cpi(&t.0, t.1, &lp, 10 * Q).expect("trade on the controller");
    // Swap to the rollback build (an in-place program upgrade).
    env.svm.add_program(env.program_id, &rollback);
    env.rollback_exercise(&lp, "controller -> rollback");
    assert_controller_bytes_dropped(&env.growth_bytes(), "after the rollback's writes");
    // Re-upgrade to the controller: the legacy-shaped record migrates on the first push.
    env.svm.add_program(env.program_id, &ctrl);
    env.warp(2);
    env.push(PRICE);
    env.warp(2);
    env.push_depth(PRICE, 1, 600 * USD as u64).expect("controller 44 B push after the round trip");
    env.crank(lp.account).expect("controller crank after the round trip");
    env.crank_current(lp.account);
    let t = env.trader(1_000 * USD);
    env.trade_cpi(&t.0, t.1, &lp, 10 * Q).expect("controller trade after the round trip");
}
