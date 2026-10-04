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
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: c.liq_fee,
        liquidation_fee_cap: 1_000_000_000_000_000,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 100,
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
        Lp {
            owner,
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
                fee_bps: 0,
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
    // u 0 -> 60%: IMR_dyn at 60% = 2800 -> 168 USD on 600 units.
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
    // exactly the stepped requirement passes, one atom less does not
    let (a1, a1p) = env.trader(46 * USD - 1);
    assert_err(
        &env.trade_cpi(&a1, a1p, &lp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "crowd 1 atom short",
    );
    let (a2, a2p) = env.trader(46 * USD);
    assert_ok(
        &env.trade_cpi(&a2, a2p, &lp, units(100)),
        "crowd at exactly IMR_dyn 46%",
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
    let (x, xp) = env.trader(170 * USD);
    assert_ok(
        &env.trade_cpi(&x, xp, &lp, units(600)),
        "X at u = 60% (needs 168)",
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
    // A larger request is clipped to exactly N_cap and ADMITTED (u == 1 at 1x).
    assert_ok(
        &env.trade_cpi(&w, wp, &lp, units(5_000)),
        "clipped to u == 1",
    );
    assert_eq!(env.pos(wp), n_cap, "filled exactly to capacity");
    assert_eq!(env.pos(lp.account), -n_cap, "|LP| == N_cap, never above");
    // Any further crowd growth: TradeCpi is clipped to a zero fill; the unclipped NoCpi route
    // names the refusal (u > 1).
    assert_ok(
        &env.trade_cpi(&w, wp, &lp, units(1)),
        "zero fill at capacity",
    );
    assert_eq!(env.pos(lp.account), -n_cap);
    let lp_owner = lp.owner.insecure_clone();
    assert_err(
        &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(1)),
        GROWTH_CAPACITY_FULL,
        "u > 1 (NoCpi)",
    );
    let (c, cp) = env.trader(1_000 * USD);
    assert_err(
        &env.trade_nocpi(&c, cp, &lp_owner, lp.account, units(1)),
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
    assert_ok(&env.trade_cpi(&w, wp, &lp, -n_cap), "the whale closes");
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
    let (a, ap) = env.trader(20 * USD);
    assert_err(
        &env.batch_trade_cpi(&a, ap, &lp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "batch crowd at 5x",
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
    // Two non-LP portfolios (no crowd step): BOTH sides face the 5x launch ceiling.
    let mut env = Env::new(MarketCfg::growth(500));
    let (p, pp) = env.trader(15 * USD);
    let (q, qp) = env.trader(100 * USD);
    assert_err(
        &env.trade_nocpi(&p, pp, &q, qp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "a side at 6.7x",
    );
    assert_err(
        &env.trade_nocpi(&q, qp, &p, pp, units(100)),
        GROWTH_LEVERAGE_EXCEEDED,
        "b side at 6.7x",
    );
    let (r, rp) = env.trader(20 * USD);
    assert_ok(
        &env.trade_nocpi(&r, rp, &q, qp, units(100)),
        "both sides within 5x",
    );
    // NoCpi against an LP portfolio (enabled matcher): the crowd step applies.
    let lp = env.lp(1_000 * USD);
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
    assert_ok(
        &env.trade_nocpi(&a2, a2p, &lp_owner, lp.account, units(100)),
        "NoCpi crowd at IMR_dyn",
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
        let (a, ap) = env.trader(46 * USD - 1);
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
        let lp_owner = lp.owner.insecure_clone();
        assert_err(
            &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(1_001)),
            GROWTH_CAPACITY_FULL,
            "row 93 refused (u > 1)",
        );
        env.force_capital(lp.account, 2_000 * USD); // capacity doubles (harness seed of LP capital)
        assert_ok(
            &env.trade_nocpi(&w, wp, &lp_owner, lp.account, units(1_001)),
            "row 93 accepted (same signers)",
        );
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
