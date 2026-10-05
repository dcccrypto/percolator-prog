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
const PRICE: u64 = 1_000_000;
const Q: i128 = POS_SCALE as i128;
const USD: u128 = 1_000_000;
const ENGINE_IMR: u64 = 1_000;
const MMR: u64 = 500;
const LIQ_FEE: u64 = 100;
const BAND_BPS: u16 = 100;
const BAND_E: u32 = 600;
const BAND_PMAX: u32 = 9_000;
const RENT_MAX: u32 = 23;
const RENT_KINK: u16 = 5_000;

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
    }
}

fn init_market_ix(c: &Cfg) -> ProgInstruction {
    let base = ProgInstruction::InitMarket {
        max_portfolio_assets: c.slots as u16,
        h_min: 0,
        h_max: 10,
        initial_price: PRICE,
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
        };
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
            phase4: p,
        };
        let bytes = ix.encode();
        let legacy_len = market.encode().len();
        assert_eq!(bytes.len(), legacy_len + if p.band_bps == 0 { 10 } else { 20 });
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
