// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! growth-v19 (2026-10-04, `~/percolator-ops/ledger/devnet-v2-growth-plan-2026-10-04.md` §2.1,
//! §2.2): dynamic leverage + capacity from capital, driven through the REAL wrapper BPF
//! (`target/deploy/percolator_prog.so`, `--features devnet`) and the REAL matcher BPF
//! (`../percolator-match`) in LiteSVM.
//!
//! Harness = `tests/p1_lp_limits.rs` (InitMarket, InitPortfolio, Deposit, SetMatcherConfig +
//! InitMatcherCtx, TradeCpi / BatchTradeCpi / TradeNoCpi, PermissionlessCrank). The matcher is
//! mounted at a NON-canonical id and configured passive / unlimited, so it never clips: every
//! refusal below is the wrapper's post-fill growth gate (or the P1 headroom, which on a growth
//! asset is the same `N_cap`).
//!
//! Market fixture (both the growth and the legacy control market, identical except the
//! growth block): price $1 (1e6 e6), engine IMR 1_000 (tier 10x), MMR 500, liquidation fee
//! 100 bps, r_gap 400 (MMR >= r_gap + fee holds with equality), funding cap 1 e9/slot,
//! fees 0. 1 unit = POS_SCALE Q = 1 USD = 1e6 atoms.
//!
//! Every test pairs with a NEGATIVE CONTROL: the identical sequence on the legacy market
//! (growth OFF) is accepted where the growth market refuses. File-copy negative controls on
//! the program (gate removed) are recorded in the PR.
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{
    ix::{BatchTradeCpiLeg, CrankObservationHint, Instruction as ProgInstruction},
    state,
    state::PortfolioAccountV16,
};
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
const PRICE: u64 = 1_000_000;
const Q: i128 = POS_SCALE as i128;
const USD: u128 = 1_000_000;

const ENGINE_IMR: u64 = 1_000;
const MMR: u64 = 500;
const LIQ_FEE: u64 = 100;
const R_GAP: u16 = 400;

// Wrapper error ordinals (PercolatorError -> Custom(n)).
const GROWTH_LEVERAGE_EXCEEDED: &str = "Custom(92)";
const GROWTH_CAPACITY_FULL: &str = "Custom(93)";
const GROWTH_INVALID_CONFIG: &str = "Custom(94)";
const GROWTH_NEEDS_LP_COUNTERPARTY: &str = "Custom(95)";
const GROWTH_REQUIRES_BOUND_VAULT_LP: &str = "Custom(97)";
const GROWTH_UTIL_FEE_REQUIRES_TRADE_CPI: &str = "Custom(99)";
const GROWTH_UTIL_FEE_NOT_COVERED: &str = "Custom(98)";
/// The taker's signed fee maximum on TradeCpi. N-2: opens above the kink pay the utilisation
/// fee (base fee 0 here, no matcher request on the kind-0 LP), so the charged fee is exactly
/// the utilisation fee and margin boundaries below add it (`util_fee_atoms`).
const TAKER_MAX_FEE_BPS: u64 = 10_000;
/// P3 F-14: on a bound asset a NoCpi fill may not grow anyone (the vault LP never signs).
const VAULT_LP_EXCLUSIVE_COUNTERPARTY: &str = "Custom(77)";

fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("GROWTH_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {path:?}; run cargo build-sbf --features devnet"
    );
    path
}

/// The growth-1 base wrapper (7c906e45) for the byte-for-byte legacy parity test.
fn base_program_path() -> PathBuf {
    let p = std::env::var_os("GROWTH_BASE_SO")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            p.push("wt-growth-v19-base/percolator-prog/target/deploy/percolator_prog.so");
            p
        });
    assert!(
        p.exists(),
        "base (7c906e45) wrapper .so not found at {p:?}; set GROWTH_BASE_SO. The legacy parity \
         test must not pass without it."
    );
    p
}

fn matcher_program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.push("percolator-match/target/deploy/percolator_match.so");
    assert!(path.exists(), "matcher BPF not found at {path:?}");
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

fn assert_err(r: &Result<u64, String>, code: &str, what: &str) {
    match r {
        Err(e) => assert!(
            e.contains(&format!("InstructionError(2, {code})")),
            "{what}: expected InstructionError(2, {code}), got {e}"
        ),
        Ok(_) => panic!("{what}: expected InstructionError(2, {code}), got Ok"),
    }
}

fn assert_ok(r: &Result<u64, String>, what: &str) {
    if let Err(e) = r {
        panic!("{what}: expected Ok, got {e}");
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

/// Market parameters (the InitMarket fields that vary across these tests).
#[derive(Clone, Copy)]
struct MarketCfg {
    imr: u64,
    mmr: u64,
    liq_fee: u64,
    funding: u64,
    slots: usize,
    /// `Some((r_gap, l_launch_x100))` => InitMarket carries the growth block.
    growth: Option<(u16, u16)>,
    /// Engine `max_trading_fee_bps` (N-2: a growth market needs >= base + 100 + 500).
    max_fee: u64,
    /// Wrapper `trade_fee_base_bps` (0 in most tests: margin boundaries stay exact).
    base_fee: u64,
}

impl MarketCfg {
    fn growth(l_launch_x100: u16) -> Self {
        Self {
            imr: ENGINE_IMR,
            mmr: MMR,
            liq_fee: LIQ_FEE,
            funding: 1,
            slots: 1,
            growth: Some((R_GAP, l_launch_x100)),
            max_fee: 10_000,
            base_fee: 0,
        }
    }
    fn legacy() -> Self {
        Self {
            growth: None,
            ..Self::growth(1_000)
        }
    }
}

fn init_market_ix(c: &MarketCfg) -> ProgInstruction {
    let base = ProgInstruction::InitMarket {
        max_portfolio_assets: c.slots as u16,
        h_min: 0,
        h_max: 10,
        initial_price: PRICE,
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 20,
        maintenance_margin_bps: c.mmr,
        initial_margin_bps: c.imr,
        max_trading_fee_bps: c.max_fee,
        trade_fee_base_bps: c.base_fee,
        liquidation_fee_bps: c.liq_fee,
        liquidation_fee_cap: 1_000_000_000_000_000,
        min_liquidation_abs: 0,
        // 4 bps/slot = the wizard's 10x setting; the L-2 r_gap floor is then 4 x 50 = 200 bps.
        max_price_move_bps_per_slot: 4,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: c.funding,
        min_funding_lifetime_slots: 1,
        max_account_b_settlement_chunks: 1,
        max_bankrupt_close_chunks: 1,
        max_bankrupt_close_lifetime_slots: 100,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    };
    match c.growth {
        None => base,
        Some((r, l)) => ProgInstruction::InitMarketV19 {
            market: Box::new(base),
            growth_r_gap_bps: r,
            growth_l_launch_x100: l,
        },
    }
}

struct Lp {
    owner: Keypair,
    account: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    matcher_program: Pubkey,
    portfolio_account_len: usize,
    /// Deterministic key source (byte-parity runs need identical keys on both programs).
    next_key: u8,
    /// Mocked ProgramData upgrade authority (tag 93).
    upgrade_authority: Keypair,
    program_data: Pubkey,
    /// N-1: `lp()` binds the LP as asset 0's vault LP (STATE POKE, see `bind_vault_lp_poke`) on
    /// a single-slot growth market, the growth-1 shape (new markets are P3-bound by default).
    bind_growth_lp: bool,
}

impl Env {
    fn try_new_with(so: &PathBuf, cfg: MarketCfg) -> Result<Self, String> {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(so).expect("read wrapper BPF"));
        svm.add_program(
            spl_token::ID,
            &std::fs::read(spl_token_program_path()).expect("read token BPF"),
        );
        let matcher_program = Pubkey::new_from_array([0xF0; 32]);
        svm.add_program(
            matcher_program,
            &std::fs::read(matcher_program_path()).expect("read matcher BPF"),
        );
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
                vec![0u8; state::market_account_len_for_capacity(cfg.slots).unwrap()],
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
            portfolio_account_len: state::portfolio_account_len_for_market_slots(cfg.slots)
                .unwrap(),
            next_key: 0x40,
            bind_growth_lp: cfg.growth.is_some() && cfg.slots == 1,
            upgrade_authority: seeded_keypair(3),
            program_data: Pubkey::find_program_address(
                &[program_id.as_ref()],
                &solana_sdk::bpf_loader_upgradeable::id(),
            )
            .0,
        };
        // ProgramData mock for the tag-93 upgrade-authority gate (45-byte layout, as in
        // p1_lp_limits.rs).
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

    fn new(cfg: MarketCfg) -> Self {
        Self::try_new_with(&program_path(), cfg).expect("init market")
    }

    fn key(&mut self) -> Pubkey {
        self.next_key = self.next_key.wrapping_add(1);
        assert!(self.next_key < 0xF0, "deterministic key space exhausted");
        Pubkey::new_from_array([self.next_key; 32])
    }

    fn signer(&mut self) -> Keypair {
        self.next_key = self.next_key.wrapping_add(1);
        assert!(self.next_key < 0xF0, "deterministic key space exhausted");
        seeded_keypair(self.next_key)
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
                ProgInstruction::Deposit {
                    portfolio_id,
                    expected_sequence,
                    amount: deposit,
                },
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

    /// LP with `deposit` atoms and a passive kind-0, unlimited matcher.
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
        if self.bind_growth_lp {
            self.bind_vault_lp_poke(account);
        }
        Lp {
            owner,
            account,
            ctx,
            delegate,
        }
    }

    /// An LP that is NOT the asset's vault LP (no bind poke).
    fn lp_unbound(&mut self, deposit: u128) -> Lp {
        let b = self.bind_growth_lp;
        self.bind_growth_lp = false;
        let lp = self.lp(deposit);
        self.bind_growth_lp = b;
        lp
    }

    /// STATE POKE (harness seed): record `lp` as asset 0's BOUND P3 vault LP
    /// (`AssetVaultLpV18 { vault_lp_portfolio, flags: BOUND }`, everything else 0 = defaults).
    /// Growth-1 admits opens only against a bound vault LP (N-1). A real tag-94 bind also makes
    /// the LP registry-owned, pins the kind-2 matcher and funds it through the junior tranche;
    /// that full path, including the reviewer's N-1 cycle, is exercised in
    /// `tests/p3_vault_lp.rs` (`growth_v19_*`). Here the gate's arithmetic is pinned against
    /// the plain kind-0 LP whose exact fills make the boundaries exact.
    fn bind_vault_lp_poke(&mut self, lp: Pubkey) {
        let mut m = self.svm.get_account(&self.market).unwrap();
        let r = state::asset_growth_range(&m.data, 0).unwrap();
        let slot0 = r.start - percolator_prog::constants::ASSET_GROWTH_OFF;
        let rec = state::AssetVaultLpV18 {
            vault_lp_portfolio: lp.to_bytes(),
            flags: state::ASSET_VAULT_LP_FLAG_BOUND,
            ..Default::default()
        };
        state::asset_vault_lp_to_wrapper_bytes(
            &mut m.data[slot0..slot0 + percolator_prog::constants::ASSET_ORACLE_WRAPPER_LEN],
            &rec,
        )
        .unwrap();
        self.svm.set_account(self.market, m).unwrap();
    }

    fn trade_cpi(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp: &Lp,
        size_q: i128,
    ) -> Result<u64, String> {
        self.trade_cpi_signing(taker, taker_account, lp, size_q, TAKER_MAX_FEE_BPS)
    }

    /// TradeCpi with an explicit signed `fee_bps` (the taker's maximum).
    fn trade_cpi_signing(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp: &Lp,
        size_q: i128,
        signed_fee_bps: u64,
    ) -> Result<u64, String> {
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
                fee_bps: signed_fee_bps,
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

    fn batch_trade_cpi(
        &mut self,
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
            ProgInstruction::BatchTradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                account_b_matcher_sequence: b_seq,
                max_slippage_atoms: u128::MAX,
                max_fee_atoms: u128::MAX,
                legs: vec![BatchTradeCpiLeg {
                    asset_index: 0,
                    market_id,
                    size_q,
                    fee_bps: 0,
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
                exec_price: PRICE,
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

    /// Advance one slot (dt = 1 = max_accrual_dt) and crank `portfolio` (touch / liquidate).
    fn crank(&mut self, portfolio: Pubkey) -> Result<u64, String> {
        let slot = self.svm.get_sysvar::<Clock>().slot + 1;
        self.svm.warp_to_slot(slot);
        let (payer, m) = (self.payer.pubkey(), self.market);
        self.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: slot,
                observations: vec![CrankObservationHint {
                    asset_index: 0,
                    oracle_accounts: 0,
                }],
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(m, false),
                AccountMeta::new(portfolio, false),
            ],
            &[],
        )
    }

    /// Tag 93 with the growth-v19 dial trailer, signed by `signer`.
    fn set_growth_dials(
        &mut self,
        signer: &Keypair,
        lambda_bps: u32,
        kink_bps: u16,
    ) -> Result<u64, String> {
        self.set_growth_dials_util(signer, lambda_bps, kink_bps, 0)
    }

    /// Tag 93 V19 with the N-2 8-byte trailer (`util == 0` -> the 6-byte form).
    fn set_growth_dials_util(
        &mut self,
        signer: &Keypair,
        lambda_bps: u32,
        kink_bps: u16,
        util: u16,
    ) -> Result<u64, String> {
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
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[signer],
        )
    }

    fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data).unwrap()
    }

    fn pos(&self, portfolio: Pubkey) -> i128 {
        let p = self.portfolio_state(portfolio);
        p.legs
            .iter()
            .find(|l| l.active && l.asset_index == 0)
            .map(|l| match l.side {
                SideV16::Long => l.basis_pos_q.unsigned_abs() as i128,
                SideV16::Short => -(l.basis_pos_q.unsigned_abs() as i128),
            })
            .unwrap_or(0)
    }

    /// Test-harness state seed (as `p1_lp_limits.rs::force_capital`): set a portfolio's capital
    /// keeping vault / c_tot conservation.
    fn force_capital(&mut self, portfolio_key: Pubkey, new_capital: u128) {
        let mut market_account = self.svm.get_account(&self.market).unwrap();
        let mut portfolio_data = self.svm.get_account(&portfolio_key).unwrap();
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut portfolio = state::read_portfolio(&portfolio_data.data).unwrap();
        let old = portfolio.capital;
        if new_capital < old {
            group.c_tot -= old - new_capital;
            group.vault -= old - new_capital;
        } else {
            group.c_tot += new_capital - old;
            group.vault += new_capital - old;
        }
        portfolio.capital = new_capital;
        portfolio.health_cert.valid = false;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut portfolio_data.data, &portfolio).unwrap();
        self.svm.set_account(self.market, market_account).unwrap();
        self.svm.set_account(portfolio_key, portfolio_data).unwrap();
    }

    fn market_bytes(&self) -> Vec<u8> {
        self.svm.get_account(&self.market).unwrap().data
    }
}

/// Deterministic keypair from a one-byte seed (byte-parity runs need identical keys).
fn seeded_keypair(tag: u8) -> Keypair {
    solana_sdk::signer::keypair::keypair_from_seed(&[tag; 32]).unwrap()
}

fn units(n: i128) -> i128 {
    n * Q
}

/// The vault LP's N_cap (Q) at its CURRENT conservative equity (lambda 1x, $1). N-2: the
/// utilisation fee is credited to the LP, so C_m and N_cap grow with every fee-paying open.
fn n_cap_now(env: &Env, lp: Pubkey) -> i128 {
    let p = env.portfolio_state(lp);
    let c_m = percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits)
        .unwrap();
    percolator_prog::growth_v19::n_cap_q(c_m, 10_000, PRICE, POS_SCALE).unwrap() as i128
}

/// N-2: the engine fee (atoms) of an open of `open_q` that leaves its side's users OI at
/// `side_after_q`, at the current N_cap: `ceil(ceil(notional) * util_bps / 1e4)` (base fee 0
/// and no matcher request in this env, so this is the whole fee).
fn util_fee_atoms(env: &Env, lp: Pubkey, side_after_q: i128, open_q: i128) -> u128 {
    let n = n_cap_now(env, lp) as u128;
    let bps = percolator_prog::growth_v19::utilisation_fee_bps(
        side_after_q.unsigned_abs(),
        n,
        5_000,
        percolator_prog::growth_v19::GROWTH_UTIL_FEE_DEFAULT_BPS,
    )
    .unwrap() as u128;
    let notional = (open_q.unsigned_abs() * PRICE as u128).div_ceil(POS_SCALE);
    (notional * bps).div_ceil(10_000)
}

/// Deposit a fresh crowd taker needs to open `open_q` that leaves the crowd's users OI at
/// `side_after_q`: the IMR_dyn leg (base 1000, kink 50%) plus the utilisation fee.
fn crowd_open_cost(env: &Env, lp: Pubkey, side_after_q: i128, open_q: i128) -> u128 {
    use percolator_prog::growth_v19 as gv;
    let n = n_cap_now(env, lp) as u128;
    let imr = gv::dyn_imr_bps(side_after_q.unsigned_abs(), n, 1_000, 5_000).unwrap();
    let notional = gv::risk_notional_ceil(open_q.unsigned_abs(), PRICE, POS_SCALE).unwrap();
    gv::leg_im_req(notional, imr, 20).unwrap() + util_fee_atoms(env, lp, side_after_q, open_q)
}

/// Asset 0's growth record straight from the market account bytes.
fn growth_of(env: &Env) -> Option<state::AssetGrowthV19> {
    state::read_asset_growth(&env.market_bytes(), 0, ENGINE_IMR).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// InitMarket rule + storage (and the slab layout diff)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn growth_init_market_rule_and_storage() {
    let env = Env::new(MarketCfg::growth(550));
    let g = growth_of(&env).expect("growth on");
    assert_eq!(g.version, 1);
    assert_eq!(g.l_launch_x100, 550);
    assert_eq!(g.l_tier_x100, 1_000, "tier = floor(1e6 / engine IMR 1000)");
    assert_eq!(g.ceil_x100, 550);
    assert_eq!(g.lambda_bps, 10_000);
    assert_eq!(g.kink_bps, 5_000);
    assert_eq!(g.r_gap_bps, R_GAP);
    // legacy InitMarket: growth OFF
    let legacy = Env::new(MarketCfg::legacy());
    assert!(growth_of(&legacy).is_none());

    // MMR >= r_gap + liquidation fee: 500 >= 400 + 100 passes (above); 401 fails.
    let bad = |c: MarketCfg| Env::try_new_with(&program_path(), c).map(|_| 0u64);
    let mut c = MarketCfg::growth(1_000);
    c.growth = Some((401, 1_000));
    assert_err(&bad(c), GROWTH_INVALID_CONFIG, "MMR < r_gap + fee");
    let mut c = MarketCfg::growth(1_000);
    c.liq_fee = 101;
    assert_err(
        &bad(c),
        GROWTH_INVALID_CONFIG,
        "MMR < r_gap + fee (fee side)",
    );
    // l_launch above the tier (10x) / below 1x
    assert_err(
        &bad(MarketCfg::growth(1_001)),
        GROWTH_INVALID_CONFIG,
        "l_launch above tier",
    );
    assert_err(
        &bad(MarketCfg::growth(99)),
        GROWTH_INVALID_CONFIG,
        "l_launch below 1x",
    );
    // single-slot growth market needs funding > 0
    let mut c = MarketCfg::growth(1_000);
    c.funding = 0;
    assert_err(
        &bad(c),
        GROWTH_INVALID_CONFIG,
        "funding 0 on a 1-slot growth market",
    );
    // ...the same funding 0 is fine on a legacy market (unchanged) and on a 2-slot growth market
    let mut c = MarketCfg::legacy();
    c.funding = 0;
    let r = bad(c);
    assert!(
        r.is_ok(),
        "legacy InitMarket with funding 0 is unchanged: {r:?}"
    );
    let mut c = MarketCfg::growth(1_000);
    c.funding = 0;
    c.slots = 2;
    let r = bad(c);
    assert!(r.is_ok(), "the funding rule is single-slot only: {r:?}");
}

#[test]
fn growth_init_market_wire_is_strict() {
    let base = init_market_ix(&MarketCfg::legacy()).encode();
    let v19 = init_market_ix(&MarketCfg::growth(550)).encode();
    assert_eq!(
        &v19[..base.len()],
        &base[..],
        "the growth block is a pure 4-byte trailer"
    );
    assert_eq!(v19.len(), base.len() + 4);
    assert_eq!(
        ProgInstruction::decode(&v19).unwrap(),
        init_market_ix(&MarketCfg::growth(550))
    );
    assert_eq!(
        ProgInstruction::decode(&base).unwrap(),
        init_market_ix(&MarketCfg::legacy())
    );
    // zero fields / a partial trailer are not a growth block
    for bad in [[0u8, 0, 0x26, 2], [0x90, 1, 0, 0]] {
        let mut d = base.clone();
        d.extend_from_slice(&bad);
        assert!(ProgInstruction::decode(&d).is_err());
    }
    let mut d = base.clone();
    d.extend_from_slice(&[1, 0]);
    assert!(ProgInstruction::decode(&d).is_err(), "2-byte trailer");
    // tag 94: optional 2-byte l_launch; 0 refused
    let v = ProgInstruction::InitVaultLpV19 {
        junior_floor_bps: 2_000,
        l_launch_x100: 550,
    }
    .encode();
    assert_eq!(v, vec![94, 0xd0, 0x07, 0x26, 0x02]);
    assert_eq!(
        ProgInstruction::decode(&v).unwrap(),
        ProgInstruction::InitVaultLpV19 {
            junior_floor_bps: 2_000,
            l_launch_x100: 550
        }
    );
    assert!(ProgInstruction::decode(&[94, 0xd0, 0x07, 0, 0]).is_err());
    assert_eq!(
        ProgInstruction::decode(&[94, 0xd0, 0x07]).unwrap(),
        ProgInstruction::InitVaultLp {
            junior_floor_bps: 2_000
        }
    );
}

/// The slab layout diff: a growth market and a legacy market built from identical inputs differ
/// ONLY inside asset 0's wrapper bytes [672, 792).
#[test]
fn growth_slab_layout_diff_is_confined_to_672_792() {
    let g = Env::new(MarketCfg::growth(550));
    let l = Env::new(MarketCfg::legacy());
    let (a, b) = (g.market_bytes(), l.market_bytes());
    assert_eq!(a.len(), b.len(), "no slab size change");
    let r = state::asset_growth_range(&a, 0).unwrap();
    let (lo, hi) = (r.start, r.end);
    let slot0 = lo - percolator_prog::constants::ASSET_GROWTH_OFF;
    assert_eq!((lo - slot0, hi - slot0), (672, 792));
    let diffs: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert!(
        !diffs.is_empty(),
        "the growth block must be written (non-vacuous)"
    );
    for &i in &diffs {
        assert!(
            i >= lo && i < hi,
            "byte {i} (slot offset {}) differs outside [672, 792)",
            i as isize - slot0 as isize
        );
    }
    eprintln!(
        "growth vs legacy market: {} differing bytes, all in slot-0 [672, 792)",
        diffs.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// §2.1 dynamic leverage
// ─────────────────────────────────────────────────────────────────────────────

/// LP $1,000 at 1x => N_cap = 1,000 units. X opens 600 long (LP short 600, u = 60%). Longs are
/// the crowd: at u = 70% IMR_dyn = 1000 + 0.4 * 9000 = 4600 (2.17x); shorts keep 10x.
fn crowd_book(env: &mut Env) -> Lp {
    let lp = env.lp(1_000 * USD);
    let (x, xp) = env.trader(200 * USD);
    // u 0 -> 60%: IMR_dyn at 60% = 2800 -> 168 USD on 600 units, + the N-2 utilisation fee
    // (100 bps at u = 60%: 6 USD, credited to the LP).
    assert_ok(
        &env.trade_cpi(&x, xp, &lp, units(600)),
        "X opens the crowd to u = 60%",
    );
    assert_eq!(env.pos(lp.account), -units(600));
    lp
}

#[test]
fn growth_thin_side_full_leverage_while_crowd_is_stepped() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = crowd_book(&mut env);
    // Crowd (long) at u -> 70%: needs 46 USD for 100 units; 20 USD (5x) is refused.
    let (a, ap) = env.trader(20 * USD);
    assert_err(
        &env.trade_cpi(&a, ap, &lp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "crowd at 5x",
    );
    assert_eq!(env.pos(ap), 0);
    // exactly the stepped requirement passes, one atom less does not. N-2: plus the utilisation
    // fee at u -> 70% (200 bps), paid to the LP (46 USD + 2 USD at C_m $1,000 + X's fee).
    let need = crowd_open_cost(&env, lp.account, units(700), units(100));
    assert!(need > 46 * USD && need < 49 * USD, "need {need}");
    let (a1, a1p) = env.trader(need - 1);
    assert_err(
        &env.trade_cpi(&a1, a1p, &lp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "crowd 1 atom short",
    );
    let (a2, a2p) = env.trader(need);
    assert_ok(
        &env.trade_cpi(&a2, a2p, &lp, units(100)),
        "crowd at exactly IMR_dyn + the utilisation fee",
    );
    // Thin (short) side at the full launch leverage 10x: 10 USD for 100 units.
    let (b, bp) = env.trader(10 * USD);
    assert_ok(&env.trade_cpi(&b, bp, &lp, -units(100)), "thin side at 10x");
    assert_eq!(env.pos(bp), -units(100));

    // NEGATIVE CONTROL: the same book on the legacy market accepts the 5x crowd open.
    let mut legacy = Env::new(MarketCfg::legacy());
    let llp = crowd_book(&mut legacy);
    let (la, lap) = legacy.trader(20 * USD);
    assert_ok(
        &legacy.trade_cpi(&la, lap, &llp, units(100)),
        "legacy: crowd at 5x accepted",
    );
}

#[test]
fn growth_launch_ceiling_and_whole_position_add() {
    // Engine tier 10x, creator launch cap 5x: the CEILING (IMR 2000) applies to every
    // risk-increasing fill, thin or crowd, even with u ~ 0.
    let mut env = Env::new(MarketCfg::growth(500));
    let lp = env.lp(1_000 * USD);
    let (x, xp) = env.trader(20 * USD + 150_000);
    assert_ok(
        &env.trade_cpi(&x, xp, &lp, units(100)),
        "100 units at 5x (20 USD) with 20.15 USD",
    );
    // Add 1 unit. A DELTA-only check (1 unit * 20% = 0.2 USD <= 20.15 USD) would pass; the
    // whole post-trade position (101 units * 20% = 20.2 USD > 20.15 USD) does not.
    assert_err(
        &env.trade_cpi(&x, xp, &lp, units(1)),
        GROWTH_LEVERAGE_EXCEEDED,
        "add checked on the whole position",
    );
    assert_eq!(env.pos(xp), units(100));
    // A fresh 6x open is refused although the engine (10x) would accept it.
    let (y, yp) = env.trader(16_666_667);
    assert_err(
        &env.trade_cpi(&y, yp, &lp, -units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "6x thin open over the 5x ceiling",
    );
    // NEGATIVE CONTROL: legacy market (engine 10x) accepts both.
    let mut legacy = Env::new(MarketCfg::legacy());
    let llp = legacy.lp(1_000 * USD);
    let (lx, lxp) = legacy.trader(20 * USD + 150_000);
    assert_ok(&legacy.trade_cpi(&lx, lxp, &llp, units(100)), "legacy open");
    assert_ok(&legacy.trade_cpi(&lx, lxp, &llp, units(1)), "legacy add");
    let (ly, lyp) = legacy.trader(16_666_667);
    assert_ok(&legacy.trade_cpi(&ly, lyp, &llp, -units(100)), "legacy 6x");
}

#[test]
fn growth_over_imr_dyn_position_is_not_liquidated_and_can_close() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = env.lp(1_000 * USD);
    let (x, xp) = env.trader(180 * USD);
    assert_ok(
        &env.trade_cpi(&x, xp, &lp, units(600)),
        "X at u = 60% (needs 168 + the 6 USD utilisation fee)",
    );
    // A whale pushes u to 90%: X's position now sits far above IMR_dyn (8200 bps -> 492 USD).
    let (w, wp) = env.trader(10_000 * USD);
    assert_ok(&env.trade_cpi(&w, wp, &lp, units(300)), "whale to u = 90%");
    // X is NOT liquidated (maintenance is the engine's, unchanged: 5% of 600 = 30 USD).
    // Same three cranks the negative control below needs to liquidate an unhealthy position.
    for i in 0..3 {
        assert_ok(&env.crank(xp), "crank X");
        assert_eq!(
            env.pos(xp),
            units(600),
            "X kept its position after crank #{i}"
        );
    }
    // X can still reduce and close (reductions are never gated).
    assert_ok(&env.trade_cpi(&x, xp, &lp, -units(100)), "X reduces");
    assert_ok(&env.trade_cpi(&x, xp, &lp, -units(500)), "X closes");
    assert_eq!(env.pos(xp), 0);
    // ...but X cannot ADD at the crowd while u is high (that is a risk increase).
    // (LP is short 300 after X left; 800 more is clipped by the N_cap headroom to 700 => u = 1.)
    let (x2, x2p) = env.trader(170 * USD);
    assert_err(
        &env.trade_cpi(&x2, x2p, &lp, units(800)),
        GROWTH_LEVERAGE_EXCEEDED,
        "clipped to u == 1: 100% IMR",
    );
    let lp_owner_x = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&x2, x2p, &lp_owner_x, lp.account, units(800)),
        GROWTH_CAPACITY_FULL,
        "u would exceed 1 (NoCpi, unclipped)",
    );
    assert_err(
        &env.trade_cpi(&x2, x2p, &lp, units(600)),
        GROWTH_LEVERAGE_EXCEEDED,
        "u = 90%: 8200 bps",
    );

    // NEGATIVE CONTROL (the crank CAN liquidate here): a maintenance-unhealthy W' is closed by
    // the same crank.
    let (v, vp) = env.trader(1_000 * USD);
    assert_ok(&env.trade_cpi(&v, vp, &lp, -units(100)), "V thin short");
    env.force_capital(vp, 4 * USD); // MMR 5% of 100 = 5 USD > 4 USD
                                    // (the first crank re-certifies the seeded state; liquidation follows within a few cranks)
    let mut liquidated = false;
    for i in 0..3 {
        let r = env.crank(vp);
        eprintln!(
            "NC crank V #{i}: {:?} pos {}",
            r.as_ref()
                .map(|_| ())
                .map_err(|e| e.split(", meta:").next().unwrap_or("").to_string()),
            env.pos(vp)
        );
        if env.pos(vp) != -units(100) {
            liquidated = true;
            break;
        }
    }
    assert!(
        liquidated,
        "an unhealthy position IS liquidated by the same crank"
    );
}

#[test]
fn growth_refuses_crowd_at_u_ge_1_and_keeps_thin_and_closes_open() {
    // Q3: a fill may take the LP exactly TO capacity (u == 1, IMR_dyn = 100%); only u > 1 is
    // refused. The TradeCpi headroom clip (= N_cap) lands exactly there, so clip and gate agree
    // and |LP| never exceeds N_cap.
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = env.lp(1_000 * USD);
    let n_cap = units(1_000);
    // u == 1 needs 100% margin: 50 USD for 100 units at the edge is refused (92), not 93.
    let (m, mp) = env.trader(50 * USD);
    let (w, wp) = env.trader(100_000 * USD);
    assert_ok(&env.trade_cpi(&w, wp, &lp, units(900)), "u = 90%");
    assert_err(
        &env.trade_cpi(&m, mp, &lp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "u == 1 at 2x",
    );
    // A larger request is clipped to exactly N_cap and ADMITTED (u == 1 at 1x). N-2: the
    // whale's 900 paid the utilisation fee to the LP, so N_cap is the CURRENT (pre-fill) one.
    let n_cap = n_cap_now(&env, lp.account);
    assert!(n_cap > units(1_000), "the utilisation fee grew C_m");
    assert_ok(
        &env.trade_cpi(&w, wp, &lp, units(5_000)),
        "clipped to u == 1",
    );
    assert_eq!(env.pos(wp), n_cap, "filled exactly to capacity");
    assert_eq!(env.pos(lp.account), -n_cap, "|LP| == N_cap, never above");
    // Any further crowd growth: TradeCpi is clipped to the room the last fill's own fee added
    // (never past N_cap); the unclipped NoCpi route names the refusal (u > 1).
    assert_ok(
        &env.trade_cpi(&w, wp, &lp, units(100)),
        "clipped at capacity",
    );
    assert!(env.pos(lp.account).unsigned_abs() <= n_cap_now(&env, lp.account).unsigned_abs());
    assert!(env.pos(wp) - n_cap < units(10), "only the fee-funded room");
    let lp_owner = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(100)),
        GROWTH_CAPACITY_FULL,
        "u > 1 (NoCpi)",
    );
    let (c, cp) = env.trader(1_000 * USD);
    assert_err(
        &env.trade_nocpi(&c, cp, &lp_owner, lp.account, units(100)),
        GROWTH_CAPACITY_FULL,
        "a new crowd trader too",
    );
    // thin side open at full leverage
    let (t, tp) = env.trader(10 * USD);
    assert_ok(
        &env.trade_cpi(&t, tp, &lp, -units(100)),
        "thin side at u = 1",
    );
    // LP capital falls to 500 USD (N_cap 500 < |LP| 900): crowd closed, thin + closes open
    env.force_capital(lp.account, 500 * USD);
    assert_ok(&env.trade_cpi(&c, cp, &lp, units(1)), "zero fill");
    assert_eq!(env.pos(cp), 0, "crowd closed: clipped to zero");
    assert_err(
        &env.trade_nocpi(&c, cp, &lp_owner, lp.account, units(1)),
        GROWTH_CAPACITY_FULL,
        "u > 1 after capital loss (NoCpi)",
    );
    let (t2, t2p) = env.trader(10 * USD);
    assert_ok(
        &env.trade_cpi(&t2, t2p, &lp, -units(100)),
        "thin side still open",
    );
    let whale = env.pos(wp);
    assert_ok(&env.trade_cpi(&w, wp, &lp, -whale), "the whale closes");
    // NEGATIVE CONTROL: legacy accepts 5,000 units (default k = 10x, no growth gate).
    let mut legacy = Env::new(MarketCfg::legacy());
    let llp = legacy.lp(1_000 * USD);
    let (lw, lwp) = legacy.trader(100_000 * USD);
    assert_ok(
        &legacy.trade_cpi(&lw, lwp, &llp, units(5_000)),
        "legacy u > 1 accepted",
    );
    assert_eq!(legacy.pos(lwp), units(5_000));
}

#[test]
fn growth_batch_cpi_is_gated() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = crowd_book(&mut env);
    // N-2: above the utilisation kink an open owes the utilisation fee, which only TradeCpi can
    // credit to the LP -> the batch route refuses it up front (99), whatever the margin.
    let (a, ap) = env.trader(20 * USD);
    assert_err(
        &env.batch_trade_cpi(&a, ap, &lp, units(100)),
        GROWTH_UTIL_FEE_REQUIRES_TRADE_CPI,
        "batch crowd above the kink",
    );
    // below the kink the batch route is gated as before: a 5x launch ceiling refuses 6x (92)
    let mut low = Env::new(MarketCfg::growth(500));
    let llp_low = low.lp(1_000 * USD);
    let (y, yp) = low.trader(16_666_667);
    assert_err(
        &low.batch_trade_cpi(&y, yp, &llp_low, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "batch 6x over the 5x ceiling (u = 10%)",
    );
    let (y2, y2p) = low.trader(20 * USD);
    assert_ok(
        &low.batch_trade_cpi(&y2, y2p, &llp_low, units(100)),
        "batch at 5x",
    );
    let (b, bp) = env.trader(10 * USD);
    assert_ok(
        &env.batch_trade_cpi(&b, bp, &lp, -units(100)),
        "batch thin at 10x",
    );
    let mut legacy = Env::new(MarketCfg::legacy());
    let llp = crowd_book(&mut legacy);
    let (la, lap) = legacy.trader(20 * USD);
    assert_ok(
        &legacy.batch_trade_cpi(&la, lap, &llp, units(100)),
        "legacy batch crowd at 5x",
    );
}

#[test]
fn growth_nocpi_is_gated() {
    // Two non-LP portfolios: on a growth asset every OPEN must face an LP (M-1 / P1 F-7), so a
    // trader-vs-trader NoCpi open is refused on BOTH sides, whatever the margin.
    let mut env = Env::new(MarketCfg::growth(500));
    // N-1: before any vault LP is bound, every open is refused (growth-1 = bound only).
    let (p, pp) = env.trader(15 * USD);
    let (q, qp) = env.trader(100 * USD);
    assert_err(
        &env.trade_nocpi(&p, pp, &q, qp, units(100)),
        GROWTH_REQUIRES_BOUND_VAULT_LP,
        "no bound vault LP yet",
    );
    let lp = env.lp(1_000 * USD);
    assert_err(
        &env.trade_nocpi(&p, pp, &q, qp, units(100)),
        GROWTH_NEEDS_LP_COUNTERPARTY,
        "trader-vs-trader open (a side)",
    );
    assert_err(
        &env.trade_nocpi(&q, qp, &p, pp, units(100)),
        GROWTH_NEEDS_LP_COUNTERPARTY,
        "trader-vs-trader open (b side)",
    );
    let (r, rp) = env.trader(1_000 * USD);
    assert_err(
        &env.trade_nocpi(&r, rp, &q, qp, units(10)),
        GROWTH_NEEDS_LP_COUNTERPARTY,
        "even at 1x",
    );
    // NoCpi against the vault LP: the crowd step applies (the gate answers before P3's own
    // NoCpi rule); the admitted size is then refused by P3 F-14 -- a vault LP never takes a
    // NoCpi fill that grows it -- and fills through TradeCpi.
    let (x, xp) = env.trader(1_000 * USD);
    assert_ok(&env.trade_cpi(&x, xp, &lp, units(600)), "u = 60%");
    // base 2000 (5x); u -> 70%: 2000 + 0.4 * 8000 = 5200 -> 52 USD for 100 units
    let (a, ap) = env.trader(51 * USD);
    let lp_owner = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&a, ap, &lp_owner, lp.account, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "NoCpi crowd",
    );
    let (a2, a2p) = env.trader(52 * USD);
    assert_err(
        &env.trade_nocpi(&a2, a2p, &lp_owner, lp.account, units(100)),
        VAULT_LP_EXCLUSIVE_COUNTERPARTY,
        "NoCpi crowd at IMR_dyn passes the gate; P3 refuses the NoCpi route",
    );
    // via TradeCpi the same open also pays the N-2 utilisation fee (u -> 70%: 200 bps)
    let fee = util_fee_atoms(&env, lp.account, units(700), units(100));
    let (a3, a3p) = env.trader(52 * USD + fee);
    assert_ok(
        &env.trade_cpi(&a3, a3p, &lp, units(100)),
        "the same open at IMR_dyn + the utilisation fee via TradeCpi",
    );
    // NEGATIVE CONTROL: legacy (engine 10x) accepts the 6.7x pair.
    let mut legacy = Env::new(MarketCfg::legacy());
    let (lp_, lpp) = legacy.trader(15 * USD);
    let (lq, lqp) = legacy.trader(100 * USD);
    assert_ok(
        &legacy.trade_nocpi(&lp_, lpp, &lq, lqp, units(100)),
        "legacy NoCpi 6.7x",
    );
}

/// The h-lock read is POST-trade: a latched flag the engine itself clears during the trade's
/// touch (no outstanding bankruptcy, `try_clear_bankruptcy_hlock_if_healthy`) does not close
/// the crowd side spuriously. (The latched-and-not-clearable branch is unit-tested in
/// `growth_v19::tests::gate_branches` and is a Kani target: a live h-lock needs a real
/// bankruptcy with an unconverted winner, which this harness does not build.)
#[test]
fn growth_clearable_hlock_does_not_close_the_crowd() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = env.lp(1_000 * USD);
    let (x, xp) = env.trader(1_000 * USD);
    assert_ok(&env.trade_cpi(&x, xp, &lp, units(100)), "u = 10%");
    let mut m = env.svm.get_account(&env.market).unwrap();
    let (cfg, mut group) = state::read_market(&m.data).unwrap();
    group.bankruptcy_hlock_active = true;
    state::write_market(&mut m.data, &cfg, &group).unwrap();
    env.svm.set_account(env.market, m).unwrap();
    let (a, ap) = env.trader(1_000 * USD);
    assert_ok(
        &env.trade_cpi(&a, ap, &lp, units(1)),
        "crowd open: the engine cleared the stale flag",
    );
    let (_, group) = state::read_market(&env.market_bytes()).unwrap();
    assert!(
        !group.bankruptcy_hlock_active,
        "the engine cleared it during the touch"
    );
}

/// Zero means off: a legacy market runs the same transaction sequence with byte-identical
/// account state on the base (7c906e45) wrapper and on this build.
#[test]
fn growth_off_is_byte_for_byte_legacy() {
    fn run(so: &PathBuf) -> Vec<(String, Vec<Vec<u8>>)> {
        let mut env = Env::try_new_with(so, MarketCfg::legacy()).expect("init");
        let mut out = Vec::new();
        let lp = env.lp(1_000 * USD);
        let (x, xp) = env.trader(200 * USD);
        let (y, yp) = env.trader(50 * USD);
        let keys = [env.market, lp.account, xp, yp, lp.ctx];
        let snap = |env: &Env, what: &str, out: &mut Vec<(String, Vec<Vec<u8>>)>| {
            out.push((
                what.to_string(),
                keys.iter()
                    .map(|k| env.svm.get_account(k).unwrap().data)
                    .collect(),
            ));
        };
        snap(&env, "setup", &mut out);
        let steps: Vec<(&str, Result<u64, String>)> = vec![
            ("cpi open", env.trade_cpi(&x, xp, &lp, units(600))),
            ("cpi crowd 5x", env.trade_cpi(&y, yp, &lp, units(100))),
            ("batch", env.batch_trade_cpi(&y, yp, &lp, -units(50))),
            ("nocpi", env.trade_nocpi(&x, xp, &y, yp, units(10))),
            ("crank", env.crank(xp)),
            ("cpi close", env.trade_cpi(&x, xp, &lp, -units(610))),
        ];
        for (what, r) in steps {
            // Outcome only (Ok / the instruction error), never logs: CU differ by design.
            let outcome = match r {
                Ok(_) => "ok".to_string(),
                Err(e) => e.split(", meta:").next().unwrap_or(&e).to_string(),
            };
            out.push((format!("{what}: {outcome}"), vec![]));
            snap(&env, what, &mut out);
        }
        out
    }
    let base = run(&base_program_path());
    let cand = run(&program_path());
    assert_eq!(base.len(), cand.len());
    let mut compared = 0;
    for (b, c) in base.iter().zip(cand.iter()) {
        assert_eq!(b.0, c.0, "outcome diverged");
        assert_eq!(b.1, c.1, "account bytes diverged after: {}", b.0);
        compared += b.1.len();
    }
    assert!(
        compared >= 30,
        "non-vacuous: {compared} account snapshots compared"
    );
    eprintln!(
        "legacy parity: {} steps, {} account snapshots byte-identical",
        base.len(),
        compared
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire parity with the matcher (ext v3) and gate-100-style attribution rows
// ─────────────────────────────────────────────────────────────────────────────

/// The wrapper's ext-v3 bytes equal the matcher's `sdk_parity_fixtures_v2` "call_ext_v3"
/// example (percolator-match feat/growth-v19-dynamic-leverage, `CallExt::encode_v3`) for the
/// same inputs, so the two repos agree on the 72-byte wire.
#[test]
fn growth_ext_v3_bytes_match_the_matcher_fixture() {
    const MATCHER_FIXTURE_HEX: &str = "031ff40118171615141312110807060504030201000000007929edffffffffffffffffffffffffff00ba1dd205000000000000000000000080d81168000000000000000000000000";
    let v2 = percolator_prog::risk_limits_v17::encode_matcher_call_ext_v2(
        1,
        0x1112_1314_1516_1718,
        0x0102_0304_0506_0708,
        500,
        true,
        true,
        -1_234_567,
    );
    let v3 = percolator_prog::growth_v19::encode_ext_v3_from_v2(&v2, 25_000_000_000, 1_746_000_000);
    let hex: String = v3.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, MATCHER_FIXTURE_HEX);
}

/// gate-100-style rows for the three new refusals: for each, the SAME authorised signer is
/// refused in one state and accepted in the other, so the refusal is attributable to STATE
/// (capacity / margin / config), never to authority. (The TS sweep `~/v17/percolator-gate`
/// pins the deployed v18.2 bytes and cannot carry candidate rows; see the PR.)
#[test]
fn growth_gate100_rows_new_refusals_are_state_attributable() {
    // Custom(92) GrowthLeverageExceeded: same taker, same size, margin 1 atom below / at IMR_dyn.
    {
        let mut env = Env::new(MarketCfg::growth(1_000));
        let lp = crowd_book(&mut env);
        let need = crowd_open_cost(&env, lp.account, units(700), units(100));
        let (a, ap) = env.trader(need - 1);
        assert_err(
            &env.trade_cpi(&a, ap, &lp, units(100)),
            GROWTH_LEVERAGE_EXCEEDED,
            "row 92 refused",
        );
        // top up 1 atom through the program's own Deposit (same signer): now accepted
        let src = env.key();
        let mint = env.mint;
        env.svm
            .set_account(
                src,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, a.pubkey(), 1),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let (pid, seq, _) = env.identity(ap);
        let (m, v) = (env.market, env.vault);
        env.send(
            ProgInstruction::Deposit {
                portfolio_id: pid,
                expected_sequence: seq,
                amount: 1,
            },
            vec![
                AccountMeta::new(a.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(ap, false),
                AccountMeta::new(src, false),
                AccountMeta::new(v, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&a],
        )
        .expect("deposit 1 atom");
        assert_ok(
            &env.trade_cpi(&a, ap, &lp, units(100)),
            "row 92 accepted (same signer)",
        );
    }
    // Custom(93) GrowthCapacityFull: same taker, same request, LP capacity full vs not.
    {
        let mut env = Env::new(MarketCfg::growth(1_000));
        let lp = env.lp(1_000 * USD);
        let (w, wp) = env.trader(100_000 * USD);
        // NoCpi is the unclipped route that reaches the gate (the batch route answers 99 first
        // above the kink, N-2); on a bound asset the gate answers before P3's NoCpi rule.
        let lp_owner = lp.owner.insecure_clone();
        assert_err(
            &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(1_001)),
            GROWTH_CAPACITY_FULL,
            "row 93 refused (u > 1)",
        );
        env.force_capital(lp.account, 2_000 * USD); // capacity doubles (harness seed of LP capital)
                                                    // same signers, same request: the GROWTH gate now admits it; the next layer (P3 F-14:
                                                    // a vault LP never takes a NoCpi fill that grows it) answers instead of 93.
        assert_err(
            &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(1_001)),
            VAULT_LP_EXCLUSIVE_COUNTERPARTY,
            "row 93 cleared (same signers)",
        );
        assert_ok(
            &env.trade_cpi(&w, wp, &lp, units(1_001)),
            "and it fills via TradeCpi",
        );
        assert_eq!(env.pos(wp), units(1_001));
    }
    // Custom(94) GrowthInvalidConfig: same admin signer, MMR rule violated vs satisfied.
    {
        let mut bad = MarketCfg::growth(1_000);
        bad.growth = Some((401, 1_000));
        let r = Env::try_new_with(&program_path(), bad).map(|_| 0u64);
        assert_err(&r, GROWTH_INVALID_CONFIG, "row 94 refused");
        assert!(
            Env::try_new_with(&program_path(), MarketCfg::growth(1_000)).is_ok(),
            "row 94 accepted"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Upgrade-authority growth dials (tag 93 trailer): tighten-only until the epoch clamp
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn growth_ua_dials_tighten_only_and_take_effect() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let ua = env.upgrade_authority.insecure_clone();
    // wire: the full legacy body + 6 bytes
    let ix = ProgInstruction::SetAssetRiskLimitsV19 {
        limits: Box::new(ProgInstruction::SetAssetRiskLimits {
            asset_index: 0,
            exec_band_bps: 0,
            lp_exposure_k_bps: 0,
            lp_floor_atoms: 0,
            side_oi_cap_q: 0,
            matcher_ext_mode: 0,
            max_requested_fee_bps: 0,
        }),
        growth_lambda_bps: 5_000,
        growth_kink_bps: 3_000,
        growth_util_fee_max_bps: 0,
    };
    let bytes = ix.encode();
    assert_eq!(bytes.len(), 50);
    assert_eq!(ProgInstruction::decode(&bytes).unwrap(), ix);
    // bounds without the epoch clamp: lambda <= 1x, kink <= 50%
    assert_err(
        &env.set_growth_dials(&ua, 10_001, 5_000),
        GROWTH_INVALID_CONFIG,
        "lambda above 1x",
    );
    assert_err(
        &env.set_growth_dials(&ua, 10_000, 5_001),
        GROWTH_INVALID_CONFIG,
        "kink later than 50%",
    );
    assert_err(
        &env.set_growth_dials(&ua, 0, 5_000),
        GROWTH_INVALID_CONFIG,
        "lambda 0",
    );
    // not the upgrade authority
    let stranger = env.signer();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    assert_err(
        &env.set_growth_dials(&stranger, 5_000, 3_000),
        "Custom(8)",
        "non-UA signer",
    );
    // tighten: lambda 0.5x, kink 30%
    assert_ok(&env.set_growth_dials(&ua, 5_000, 3_000), "tighten");
    let g = growth_of(&env).unwrap();
    assert_eq!((g.lambda_bps, g.kink_bps), (5_000, 3_000));
    // effect: N_cap halves -> the CPI clip lands at 500 units (u == 1) on a $1,000 LP
    let lp = env.lp(1_000 * USD);
    let (w, wp) = env.trader(100_000 * USD);
    assert_ok(&env.trade_cpi(&w, wp, &lp, units(800)), "clipped");
    assert_eq!(env.pos(wp), units(500), "N_cap = 0.5 * C_m / P");
    // back to the default bound is within bounds
    assert_ok(
        &env.set_growth_dials(&ua, 10_000, 5_000),
        "back to defaults",
    );
    // L-4: the dial form touches ONLY the dial bytes -- a non-zero legacy body is refused and a
    // dial change leaves the risk-limits record byte-identical.
    let limits_before = state::read_asset_risk_limits(&env.market_bytes(), 0).unwrap();
    let (pd, market) = (env.program_data, env.market);
    let with_body = ProgInstruction::SetAssetRiskLimitsV19 {
        limits: Box::new(ProgInstruction::SetAssetRiskLimits {
            asset_index: 0,
            exec_band_bps: 0,
            lp_exposure_k_bps: 0,
            lp_floor_atoms: 0,
            side_oi_cap_q: 0,
            matcher_ext_mode: 1,
            max_requested_fee_bps: 0,
        }),
        growth_lambda_bps: 9_000,
        growth_kink_bps: 4_000,
        growth_util_fee_max_bps: 0,
    };
    assert_err(
        &env.send(
            with_body,
            vec![
                AccountMeta::new(ua.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[&ua],
        ),
        "Custom(9)",
        "dial form with a non-zero legacy body",
    );
    assert_ok(&env.set_growth_dials(&ua, 9_000, 4_000), "dials only");
    assert_eq!(
        state::read_asset_risk_limits(&env.market_bytes(), 0).unwrap(),
        limits_before
    );

    // growth OFF market: the dial trailer is refused
    let mut legacy = Env::new(MarketCfg::legacy());
    let lua = legacy.upgrade_authority.insecure_clone();
    assert_err(
        &legacy.set_growth_dials(&lua, 5_000, 3_000),
        GROWTH_INVALID_CONFIG,
        "growth off",
    );
    // NEGATIVE CONTROL (wire): the legacy tag-93 form still decodes as the legacy variant.
    let legacy_bytes = ProgInstruction::SetAssetRiskLimits {
        asset_index: 0,
        exec_band_bps: 0,
        lp_exposure_k_bps: 0,
        lp_floor_atoms: 0,
        side_oi_cap_q: 0,
        matcher_ext_mode: 1,
        max_requested_fee_bps: 7,
    }
    .encode();
    assert!(matches!(
        ProgInstruction::decode(&legacy_bytes).unwrap(),
        ProgInstruction::SetAssetRiskLimits { .. }
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Security review 2026-10-04, M-1: a reducing / closing taker is never refused or zero-filled
// (reviewer repro `sec_thin_side_close_when_lp_at_capacity`, now asserted)
// ─────────────────────────────────────────────────────────────────────────────

/// Book: N_cap 1,000 units. W crowds long to 900, T opens a THIN short 100 (LP -800), W fills
/// the crowd to capacity (LP -1,000). T's close (a buy) GROWS |LP| past N_cap.
fn m1_book(env: &mut Env) -> (Lp, (Keypair, Pubkey), (Keypair, Pubkey)) {
    let lp = env.lp(1_000 * USD);
    let (w, wp) = env.trader(100_000 * USD);
    let (t, tp) = env.trader(100 * USD);
    assert_ok(&env.trade_cpi(&w, wp, &lp, units(900)), "W crowd 900");
    assert_ok(&env.trade_cpi(&t, tp, &lp, -units(100)), "T thin short 100");
    // N-2: W's 900 paid the utilisation fee to the LP, so N_cap is the CURRENT one (> 1,000).
    let n = n_cap_now(env, lp.account);
    assert_ok(
        &env.trade_cpi(&w, wp, &lp, units(5_000)),
        "W clipped to capacity",
    );
    // N-1: capacity is the crowd's users OI (W long == N_cap); the LP nets T's short.
    assert_eq!(env.pos(wp), n, "crowd OI at N_cap");
    assert_eq!(env.pos(lp.account), -(n - units(100)));
    (lp, (w, wp), (t, tp))
}

#[test]
fn growth_m1_closes_are_never_trapped() {
    // 1. TradeCpi close at capacity: filled in full (was a silent ZERO fill).
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (lp, (_wk, wp), (t, tp)) = m1_book(&mut env);
    assert_ok(&env.trade_cpi(&t, tp, &lp, units(100)), "T closes via CPI");
    assert_eq!(env.pos(tp), 0, "close filled in full");
    assert_eq!(
        env.pos(lp.account),
        -env.pos(wp),
        "the LP absorbs the close and still holds at most N_cap (N-1)"
    );
    assert!(env.pos(lp.account).abs() <= n_cap_now(&env, lp.account));
    // ...and the crowd stays closed for NEW growth.
    let (c, cp) = env.trader(1_000 * USD);
    let lp_owner = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&c, cp, &lp_owner, lp.account, units(100)),
        GROWTH_CAPACITY_FULL,
        "crowd still closed (beyond the fee-funded room)",
    );

    // 2. NoCpi close: on a bound asset the vault LP never signs NoCpi (P3 F-14), so the NoCpi
    //    exit is closing INTO another closer -- both reduce, nothing is gated (was Custom(68)
    //    against an LP at capacity).
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (_lp, (w, wp), (t, tp)) = m1_book(&mut env);
    let w0 = env.pos(wp);
    assert_ok(
        &env.trade_nocpi(&t, tp, &w, wp, units(100)),
        "T closes via NoCpi into W who reduces",
    );
    assert_eq!(env.pos(tp), 0);
    assert_eq!(env.pos(wp), w0 - units(100));

    // 3. Partial reduce after a capital loss (N_cap 500 < |LP|), then a close with the LP
    //    deep under capacity (capital 150: N_cap 150 vs |LP| 1,060).
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (lp, _w, (t, tp)) = m1_book(&mut env);
    env.force_capital(lp.account, 500 * USD);
    assert_ok(
        &env.trade_cpi(&t, tp, &lp, units(40)),
        "partial reduce after capital loss",
    );
    assert_eq!(env.pos(tp), -units(60));
    env.force_capital(lp.account, 150 * USD);
    assert_ok(
        &env.trade_cpi(&t, tp, &lp, units(60)),
        "close far past capacity",
    );
    assert_eq!(env.pos(tp), 0);
    // SCOPE: an LP with ZERO capital fails the ENGINE's own initial margin on any LP growth
    // (Custom 49). That is an engine invariant, identical on legacy (control below), not a
    // growth clip; on bound P3 markets the senior-draw pre-fill refills the vault LP first.
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (lp, _w, (t, tp)) = m1_book(&mut env);
    env.force_capital(lp.account, 0);
    assert_err(
        &env.trade_cpi(&t, tp, &lp, units(100)),
        "Custom(49)",
        "engine IM (growth)",
    );
    let mut l0 = Env::new(MarketCfg::legacy());
    let l0lp = l0.lp(1_000 * USD);
    let (l0w, l0wp) = l0.trader(100_000 * USD);
    let (l0t, l0tp) = l0.trader(100 * USD);
    assert_ok(&l0.trade_cpi(&l0w, l0wp, &l0lp, units(900)), "L0 W 900");
    assert_ok(
        &l0.trade_cpi(&l0t, l0tp, &l0lp, -units(100)),
        "L0 T thin 100",
    );
    assert_ok(
        &l0.trade_cpi(&l0w, l0wp, &l0lp, units(100)),
        "L0 W to 900 net",
    );
    l0.force_capital(l0lp.account, 0);
    let r = l0.trade_cpi(&l0t, l0tp, &l0lp, units(100));
    assert!(
        r.is_err() || l0.pos(l0tp) == -units(100),
        "legacy refuses / does not fill it either: {r:?}"
    );

    // 4. FLIP on TradeCpi at capacity: split -- the closing part fills, the opening part (a new
    //    crowd long past N_cap) does not.
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (lp, _w, (t, tp)) = m1_book(&mut env);
    assert_ok(&env.trade_cpi(&t, tp, &lp, units(150)), "flip request");
    assert_eq!(
        env.pos(tp),
        0,
        "the close part filled; the opening part did not"
    );

    // 5. FLIP on NoCpi (cannot clip): the opening part is gated -> refused; a close-only
    //    request passes.
    let mut env = Env::new(MarketCfg::growth(1_000));
    let (lp, _w, (t, tp)) = m1_book(&mut env);
    let lp_owner = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&t, tp, &lp_owner, lp.account, units(150)),
        GROWTH_CAPACITY_FULL,
        "opening part gated",
    );
    assert_eq!(env.pos(tp), -units(100));
    assert_ok(&env.trade_cpi(&t, tp, &lp, units(100)), "close-only passes");

    // NEGATIVE CONTROL (scope): the legacy class is unchanged by this PR -- a legacy LP over
    // its own 10x cap still zero-fills a thin close (reviewer `sec_..._over_its_10x_cap`).
    let mut l2 = Env::new(MarketCfg::legacy());
    let l2lp = l2.lp(1_000 * USD);
    let (l2w, l2wp) = l2.trader(100_000 * USD);
    let (l2t, l2tp) = l2.trader(100 * USD);
    assert_ok(&l2.trade_cpi(&l2w, l2wp, &l2lp, units(900)), "L2 W 900");
    assert_ok(
        &l2.trade_cpi(&l2t, l2tp, &l2lp, -units(100)),
        "L2 T thin 100",
    );
    l2.force_capital(l2lp.account, 50 * USD);
    assert_ok(
        &l2.trade_cpi(&l2t, l2tp, &l2lp, units(100)),
        "legacy zero fill",
    );
    assert_eq!(
        l2.pos(l2tp),
        -units(100),
        "legacy over-cap class unchanged (growth OFF is byte-for-byte legacy)"
    );
}

/// L-2: the r_gap floor (reviewer `sec_r_gap_is_creator_declared_and_unbounded_below`, inverted).
#[test]
fn growth_l2_r_gap_floor() {
    let try_init = |r_gap: u16| {
        let mut c = MarketCfg::growth(1_000);
        c.growth = Some((r_gap, 1_000));
        Env::try_new_with(&program_path(), c).map(|_| 0u64)
    };
    assert_err(&try_init(1), GROWTH_INVALID_CONFIG, "r_gap = 1 bps refused");
    assert_err(
        &try_init(199),
        GROWTH_INVALID_CONFIG,
        "below 4 bps/slot x 50 slots",
    );
    assert!(try_init(200).is_ok(), "at the floor");
    assert!(try_init(400).is_ok());
}

/// N-1 (security re-verification 2026-10-04): the reviewer's repro
/// `sec2_thin_open_crowd_fill_thin_close_cycles_past_ncap`, with assertions. Before the fix a
/// thin open emptied the LP, a fresh crowd portfolio refilled it to N_cap, and the exempt thin
/// close pushed it past: 4 cycles took the LP to 4 x N_cap. Capacity is now the crowd's users
/// OI, so the refill finds no room and |LP| <= OI_crowd <= N_cap after every fill, while the
/// thin close still fills in full (M-1 kept). NEGATIVE CONTROL: mutant `n1-lpnet` (u measured
/// on the LP's net again, OI clip off) -- this test fails (PR description).
#[test]
fn growth_n1_thin_open_crowd_refill_thin_close_cannot_pass_ncap() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = env.lp(1_000 * USD);
    // N-2: every open above the kink pays the utilisation fee to the LP, so C_m and N_cap grow
    // a little each cycle; the bound is N_cap at its CURRENT value, never k x the original.
    let (t, tp) = env.trader(5_000 * USD);
    let mut crowd: Vec<Pubkey> = Vec::new();
    for cycle in 0..4 {
        let (c, cp) = env.trader(100_000 * USD);
        let room_before =
            n_cap_now(&env, lp.account) - crowd.iter().map(|p| env.pos(*p).max(0)).sum::<i128>();
        assert_ok(
            &env.trade_cpi(&c, cp, &lp, units(5_000)),
            "crowd request (clipped)",
        );
        let filled = env.pos(cp);
        if cycle == 0 {
            assert_eq!(filled, units(1_000), "cycle 0: the crowd fills to N_cap");
        } else {
            assert!(
                filled <= room_before && filled < units(100),
                "cycle {cycle}: only the fee-funded room ({filled} vs {room_before}) -- the thin side frees none"
            );
            // the unclipped route names the refusal
            let lp_owner = lp.owner.insecure_clone();
            assert_err(
                &env.trade_nocpi(&c, cp, &lp_owner, lp.account, units(500)),
                GROWTH_CAPACITY_FULL,
                "refill via NoCpi",
            );
        }
        crowd.push(cp);
        let close = -env.pos(tp);
        if close != 0 {
            assert_ok(&env.trade_cpi(&t, tp, &lp, close), "thin close (exempt)");
            assert_eq!(env.pos(tp), 0, "M-1: the close fills in full");
        }
        assert!(
            env.pos(lp.account).unsigned_abs() <= n_cap_now(&env, lp.account).unsigned_abs(),
            "cycle {cycle}: |LP| <= N_cap after the close"
        );
        let lp_now = env.pos(lp.account);
        if lp_now != 0 {
            assert_ok(&env.trade_cpi(&t, tp, &lp, lp_now), "thin open to LP flat");
        }
        let users_long: i128 = crowd.iter().map(|p| env.pos(*p).max(0)).sum();
        let n_cap = n_cap_now(&env, lp.account);
        assert!(users_long <= n_cap, "crowd users OI <= N_cap");
        assert!(env.pos(lp.account).abs() <= n_cap);
    }
    let close = -env.pos(tp);
    assert_ok(&env.trade_cpi(&t, tp, &lp, close), "final thin close");
    assert_eq!(env.pos(tp), 0);
    let lp_abs = env.pos(lp.account).abs();
    assert!(
        lp_abs <= n_cap_now(&env, lp.account) && lp_abs < units(1_300),
        "|LP| ends <= N_cap (grown only by the fees), not 4 x N_cap: {lp_abs}"
    );
}

/// N-1: growth-1 admits opens only against a BOUND vault LP. An unbound growth LP, a growth
/// asset on a multi-slot market (P3 binds single-asset markets only) and an asset whose
/// vault LP was unbound all refuse opens with GrowthRequiresBoundVaultLp (97) and keep every
/// close open. NEGATIVE CONTROL: the same open against the bound LP is admitted.
#[test]
fn growth_n1_opens_only_on_a_bound_vault_lp() {
    let mut env = Env::new(MarketCfg::growth(1_000));
    let free = env.lp_unbound(1_000 * USD);
    let (x, xp) = env.trader(1_000 * USD);
    assert_err(
        &env.trade_cpi(&x, xp, &free, units(10)),
        GROWTH_REQUIRES_BOUND_VAULT_LP,
        "unbound LP",
    );
    assert_eq!(env.pos(xp), 0);
    let bound = env.lp(1_000 * USD);
    assert_err(
        &env.trade_cpi(&x, xp, &free, units(10)),
        GROWTH_NEEDS_LP_COUNTERPARTY,
        "another LP while a vault LP is bound",
    );
    assert_ok(
        &env.trade_cpi(&x, xp, &bound, units(10)),
        "bound vault LP: admitted",
    );
    assert_eq!(env.pos(xp), units(10));
    // the vault LP is unbound again (STATE POKE: zero record): opens refused, the close fills
    let mut m = env.svm.get_account(&env.market).unwrap();
    let r = state::asset_growth_range(&m.data, 0).unwrap();
    let slot0 = r.start - percolator_prog::constants::ASSET_GROWTH_OFF;
    state::asset_vault_lp_to_wrapper_bytes(
        &mut m.data[slot0..slot0 + percolator_prog::constants::ASSET_ORACLE_WRAPPER_LEN],
        &state::AssetVaultLpV18::default(),
    )
    .unwrap();
    env.svm.set_account(env.market, m).unwrap();
    assert_err(
        &env.trade_cpi(&x, xp, &bound, units(10)),
        GROWTH_REQUIRES_BOUND_VAULT_LP,
        "unbound: add",
    );
    assert_ok(
        &env.trade_cpi(&x, xp, &bound, -units(10)),
        "unbound: the close fills",
    );
    assert_eq!(env.pos(xp), 0);
    // multi-slot growth market: no bind is possible, every open is refused
    let mut c2 = MarketCfg::growth(1_000);
    c2.slots = 2;
    let mut env2 = Env::new(c2);
    let lp2 = env2.lp(1_000 * USD);
    let (y, yp) = env2.trader(1_000 * USD);
    assert_err(
        &env2.trade_cpi(&y, yp, &lp2, units(10)),
        GROWTH_REQUIRES_BOUND_VAULT_LP,
        "multi-slot",
    );
    // NEGATIVE CONTROL: legacy multi-slot market opens
    let mut l2 = MarketCfg::legacy();
    l2.slots = 2;
    let mut legacy = Env::new(l2);
    let llp = legacy.lp(1_000 * USD);
    let (z, zp) = legacy.trader(1_000 * USD);
    assert_ok(&legacy.trade_cpi(&z, zp, &llp, units(10)), "legacy opens");
}

/// N-2 (security round 3): the utilisation fee. Opens above the 50% kink pay
/// `500 bps * (u_after - 0.5) / 0.5` of their opening notional to the vault LP through the P2
/// LP-credit channel; the taker must sign for it (98 otherwise); closes never pay it; the UA
/// dial may only RAISE it (500..2000 bps) and only within the market's engine fee cap; a growth
/// InitMarket needs `max_trading_fee_bps >= base + 100 + 500`.
#[test]
fn growth_n2_utilisation_fee_consent_close_dial_and_init_rule() {
    // InitMarket rule (base fee 0 here): 599 refused, 600 accepted
    let mut bad = MarketCfg::growth(1_000);
    bad.max_fee = 599;
    let r = Env::try_new_with(&program_path(), bad).map(|_| 0u64);
    assert_err(&r, GROWTH_INVALID_CONFIG, "fee cap below base + 100 + 500");
    let mut ok = MarketCfg::growth(1_000);
    ok.max_fee = 600;
    assert!(Env::try_new_with(&program_path(), ok).is_ok());

    let mut env = Env::new(MarketCfg::growth(1_000));
    let lp = crowd_book(&mut env); // X long 600 (u 60%), paid 100 bps
                                   // u -> 700 / 1,006 (X's fee grew C_m): 196 bps. Signed 195 -> 98; 196 -> admitted, and the
                                   // LP earns exactly the fee.
    let n = n_cap_now(&env, lp.account) as u128;
    let bps = percolator_prog::growth_v19::utilisation_fee_bps(units(700) as u128, n, 5_000, 500)
        .unwrap() as u64;
    assert_eq!(bps, 196);
    let (a, ap) = env.trader(100 * USD);
    assert_err(
        &env.trade_cpi_signing(&a, ap, &lp, units(100), bps - 1),
        GROWTH_UTIL_FEE_NOT_COVERED,
        "under-signed",
    );
    let fee = util_fee_atoms(&env, lp.account, units(700), units(100));
    assert_eq!(fee, 1_960_000, "196 bps on $100");
    let lp0 = env.portfolio_state(lp.account).capital;
    let a0 = env.portfolio_state(ap).capital;
    assert_ok(
        &env.trade_cpi_signing(&a, ap, &lp, units(100), bps),
        "signed exactly",
    );
    assert_eq!(
        env.portfolio_state(ap).capital,
        a0 - fee,
        "taker paid exactly the fee"
    );
    assert_eq!(
        env.portfolio_state(lp.account).capital,
        lp0 + fee,
        "LP earned it"
    );
    // a close pays nothing (base fee 0, no util): signed 0 is enough
    let a1 = env.portfolio_state(ap).capital;
    assert_ok(
        &env.trade_cpi_signing(&a, ap, &lp, -units(100), 0),
        "close signed 0",
    );
    assert_eq!(env.pos(ap), 0);
    assert_eq!(
        env.portfolio_state(ap).capital,
        a1,
        "closes never pay the utilisation fee"
    );
    // thin side below its kink: no fee either
    let (b, bp) = env.trader(10 * USD);
    assert_ok(
        &env.trade_cpi_signing(&b, bp, &lp, -units(100), 0),
        "thin at u 10%",
    );

    // UA dial: raise to 1000 bps -> the same open now pays 400 bps; cheaper / above max refused
    let ua = env.upgrade_authority.insecure_clone();
    assert_err(
        &env.set_growth_dials_util(&ua, 10_000, 5_000, 499),
        GROWTH_INVALID_CONFIG,
        "below default",
    );
    assert_err(
        &env.set_growth_dials_util(&ua, 10_000, 5_000, 2_001),
        GROWTH_INVALID_CONFIG,
        "above hard max",
    );
    assert_ok(
        &env.set_growth_dials_util(&ua, 10_000, 5_000, 1_000),
        "raise to 1000",
    );
    assert_eq!(growth_of(&env).unwrap().util_fee_max_bps, 1_000);
    assert_ok(
        &env.set_growth_dials(&ua, 10_000, 5_000),
        "6-byte form leaves it",
    );
    assert_eq!(growth_of(&env).unwrap().util_fee_max_bps, 1_000);
    let n = n_cap_now(&env, lp.account) as u128;
    let bps2 = percolator_prog::growth_v19::utilisation_fee_bps(units(700) as u128, n, 5_000, 1_000)
        .unwrap() as u64;
    assert!(
        bps2 > 2 * bps - 10,
        "doubling the dial doubles the fee ({bps2})"
    );
    let (c, cp) = env.trader(100 * USD);
    assert_err(
        &env.trade_cpi_signing(&c, cp, &lp, units(100), bps2 - 1),
        GROWTH_UTIL_FEE_NOT_COVERED,
        "raised",
    );
    assert_ok(
        &env.trade_cpi_signing(&c, cp, &lp, units(100), bps2),
        "signed the raised fee",
    );
    // the dial must fit the market's engine fee cap
    let mut tight = MarketCfg::growth(1_000);
    tight.max_fee = 600;
    let mut t = Env::new(tight);
    let ua = t.upgrade_authority.insecure_clone();
    assert_err(
        &t.set_growth_dials_util(&ua, 10_000, 5_000, 1_000),
        GROWTH_INVALID_CONFIG,
        "over the fee cap",
    );
}

/// F-1 (security round 3) behavioural tripwire: the GOLDEN fee accrual of one single-route
/// TradeCpi. The frame overflow found in round 2 (one extra 32-byte local in
/// `handle_trade_nocpi_zero_copy`) surfaced as Custom(15) / corrupted accruals on exactly this
/// path. The taker pays `ceil(notional * 30 / 1e4)`; cfg protocol / LP / insurance accrue and
/// the asset's creator counter receive exactly `split_trade_fee` of it, conservatively. Legacy
/// and growth markets (growth below the kink: no utilisation fee) must agree to the atom.
#[test]
fn growth_f1_single_route_fee_accrual_is_golden() {
    for growth in [false, true] {
        let mut c = if growth {
            MarketCfg::growth(1_000)
        } else {
            MarketCfg::legacy()
        };
        c.base_fee = 30;
        let mut env = Env::new(c);
        let lp = env.lp(1_000 * USD);
        let (x, xp) = env.trader(100 * USD);
        let (cfg0, _) = state::read_market(&env.market_bytes()).unwrap();
        let p0 = state::read_asset_oracle_profile(&env.market_bytes(), 0).unwrap();
        let cap0 = env.portfolio_state(xp).capital;
        assert_ok(&env.trade_cpi(&x, xp, &lp, units(333)), "open 333 units");
        let fee = (333u128 * USD * 30).div_ceil(10_000);
        assert_eq!(
            cap0 - env.portfolio_state(xp).capital,
            fee,
            "taker paid the base fee only"
        );
        let parts = percolator_prog::policy_v16::split_trade_fee(
            fee,
            percolator_prog::constants::PROTOCOL_FEE_BPS,
            cfg0.creator_share_bps,
            cfg0.lp_share_bps,
            cfg0.insurance_share_bps,
        )
        .unwrap();
        let (cfg1, _) = state::read_market(&env.market_bytes()).unwrap();
        let p1 = state::read_asset_oracle_profile(&env.market_bytes(), 0).unwrap();
        assert_eq!(
            cfg1.protocol_fee_accrued_atoms - cfg0.protocol_fee_accrued_atoms,
            parts.protocol
        );
        assert_eq!(
            cfg1.lp_fee_accrued_atoms - cfg0.lp_fee_accrued_atoms,
            parts.lp
        );
        assert_eq!(
            cfg1.insurance_reserve_accrued_atoms - cfg0.insurance_reserve_accrued_atoms,
            parts.insurance
        );
        assert_eq!(
            (p1.creator_fee_claimable_atoms - p0.creator_fee_claimable_atoms) as u128,
            parts.creator
        );
        assert_eq!(
            parts.protocol + parts.lp + parts.insurance + parts.creator,
            fee,
            "conservative"
        );
        assert!(
            parts.protocol > 0 && parts.lp > 0,
            "non-trivial split (growth {growth})"
        );
    }
}

/// P5 (security review rev-6c): the wrapper's engine-IMR leg (`leg_im_req` over
/// `risk_notional_ceil`, what the gate and Kani R5 reason about) EQUALS the engine certificate's
/// per-leg initial requirement for a single-leg portfolio, at engine 35ddd692 (the CI sibling pin).
/// The engine computes `max(ceil(notional * IMR / 1e4), min_nonzero_im_req)` via
/// `mul_div_ceil_u128_or_wide` (v16.rs:23050) over `liquidation_risk_notional_ceil`, plus the
/// target-lag penalty, which is 0 at a constant mark (effective == target price). Sizes include
/// non-round quantities so the ceil of the notional and of the requirement both bite.
#[test]
fn growth_p5_wrapper_leg_im_equals_engine_cert_per_leg_im() {
    use percolator_prog::growth_v19 as gv;
    let mut env = Env::new(MarketCfg::legacy());
    let lp = env.lp(1_000_000 * USD);
    let sizes: [i128; 6] = [units(1), units(37), -units(250), 1_234_567, -9_999_999, 3];
    let mut checked = 0;
    for &size in sizes.iter() {
        let (x, xp) = env.trader(1_000 * USD);
        assert_ok(&env.trade_cpi(&x, xp, &lp, size), "single-leg open");
        let p = env.portfolio_state(xp);
        let cert = p.health_cert;
        assert!(cert.valid, "the engine certified the fresh single-leg portfolio");
        let notional = gv::risk_notional_ceil(size.unsigned_abs(), PRICE, POS_SCALE).unwrap();
        let wrapper = gv::leg_im_req(notional, ENGINE_IMR, 20).unwrap();
        assert_eq!(
            cert.certified_initial_req, wrapper,
            "size {size}: engine per-leg IM == wrapper leg_im_req (penalty 0 at a constant mark)"
        );
        checked += 1;
    }
    assert_eq!(checked, sizes.len());
}
