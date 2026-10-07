// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! v2.2 executed-fill / reduce events (`docs/v22-fill-events.md`): every event kind decoded from
//! the transaction logs of the REAL wrapper BPF (`target/deploy/percolator_prog.so`, built
//! `--features devnet`, or `P1_WRAPPER_SO`) and compared with the account-state change, against
//! the REAL passive (kind-0) matcher BPF, in LiteSVM.
//!
//! Setup is the minimum copied from `tests/v16_cu.rs::V16CuEnv` (InitMarket, InitPortfolio,
//! Deposit, SetMatcherConfig + wrapper InitMatcherCtx, TradeCpi / BatchTradeCpi / TradeNoCpi)
//! plus the ProgramData mock from the tag-85 test there, reused for tag 93.
//!
//! Market fixture: price 100 (engine e6 units), initial_margin_bps = 10_000, fees 0, so the
//! default k = 1e8 / 10_000 = 10_000 bps and an LP with IM-lane equity E has
//!   cap_q = floor(E * k * POS_SCALE / (10_000 * price)) = E * POS_SCALE / 100.
//! With E = 1_000 atoms, cap_q = 10 * POS_SCALE.
//!
//! `P1_WRAPPER_SO=<path>` overrides the wrapper .so (used to replay the COLLECT/Murphy shape
//! against the deployed base build `deploy/v18.2-wrapper@6377376a`).
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{
    ix::{BatchTradeCpiLeg, Instruction as ProgInstruction},
    state,
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

#[path = "support/fill_events.rs"]
mod fill_events;
use fill_events::{wrapper_events, Event, FillRecord, FLAG_CLIPPED, FLAG_MATCHER, FLAG_PARTIAL, FLAG_ZERO};

thread_local! {
    /// Logs of the last transaction (success or failure) sent by this test thread.
    static LAST_LOGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn last_logs() -> Vec<String> {
    LAST_LOGS.with(|l| l.borrow().clone())
}

const MATCHER_CONTEXT_LEN: usize = 320;
const PRICE: u64 = 100;
const Q: i128 = POS_SCALE as i128;

const LP_EXPOSURE_CAP_EXCEEDED: &str = "Custom(68)";
const LP_FLOOR_HALT: &str = "Custom(69)";
const PROTOCOL_SIDE_OI_CAP_EXCEEDED: &str = "Custom(70)";

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
    let mut signers = vec![payer];
    signers.extend_from_slice(extra_signers);
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instruction,
        ],
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    match svm.send_transaction(tx) {
        Ok(meta) => {
            LAST_LOGS.with(|l| *l.borrow_mut() = meta.logs.clone());
            Ok(meta.compute_units_consumed)
        }
        Err(e) => {
            LAST_LOGS.with(|l| *l.borrow_mut() = e.meta.logs.clone());
            Err(format!("{:?}", e.err))
        }
    }
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
    upgrade_authority: Keypair,
    program_data: Pubkey,
    portfolio_account_len: usize,
    fee_bps: u64,
}

impl Env {
    fn new() -> Self {
        Self::with_fee(0)
    }

    fn with_fee(fee_bps: u64) -> Self {
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
            &std::fs::read(matcher_program_path()).expect("read matcher BPF"),
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

        send_tx(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::InitMarket {
                max_portfolio_assets: 1,
                h_min: 0,
                h_max: 10,
                initial_price: PRICE,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps: 10_000,
                initial_margin_bps: 10_000,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps: fee_bps,
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
        let upgrade_authority = Keypair::new();
        svm.airdrop(&upgrade_authority.pubkey(), 1_000_000_000)
            .unwrap();
        let (program_data, _) = Pubkey::find_program_address(
            &[program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        );
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(upgrade_authority.pubkey().as_ref());
        svm.set_account(
            program_data,
            acct(pd, solana_sdk::bpf_loader_upgradeable::id()),
        )
        .unwrap();

        Self {
            svm,
            program_id,
            payer,
            market,
            mint,
            vault,
            matcher_program,
            upgrade_authority,
            program_data,
            portfolio_account_len: state::portfolio_account_len_for_market_slots(1).unwrap(),
            fee_bps,
        }
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<u64, String> {
        send_tx(
            &mut self.svm,
            self.program_id,
            &self.payer,
            ix,
            accounts,
            signers,
        )
    }

    fn portfolio(&mut self, owner: &Keypair, deposit: u128) -> Pubkey {
        let portfolio = Pubkey::new_unique();
        // Fund the owner once (LiteSVM airdrops reuse one signature, so a second airdrop to the
        // same key is rejected as AlreadyProcessed).
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
            self.send(
                ProgInstruction::Deposit {
                    portfolio_id,
                    expected_sequence,
                    amount: deposit,
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

    /// LP portfolio with `deposit` atoms, registered with a passive kind-0 matcher
    /// (spread 0, max_fill u128::MAX) via SetMatcherConfig + wrapper InitMatcherCtx.
    fn lp(&mut self, deposit: u128) -> Lp {
        self.lp_with(deposit, u128::MAX)
    }

    fn lp_with(&mut self, deposit: u128, max_fill_abs: u128) -> Lp {
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
        let mp = self.matcher_program;
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
                AccountMeta::new_readonly(self.market, false),
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
                max_fill_abs,
                max_inventory_abs: 0,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
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
        let mp = self.matcher_program;
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
                fee_bps: self.fee_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(self.market, false),
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
        let mp = self.matcher_program;
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
                    fee_bps: self.fee_bps,
                    limit_price: 0,
                }],
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(self.market, false),
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
                fee_bps: self.fee_bps,
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

    /// Tag 93 SetAssetRiskLimits, signed by the mocked ProgramData upgrade authority.
    fn set_risk_limits(
        &mut self,
        lp_exposure_k_bps: u32,
        lp_floor_atoms: u128,
        side_oi_cap_q: u128,
    ) {
        let ua = self.upgrade_authority.insecure_clone();
        let (pd, market) = (self.program_data, self.market);
        self.send(
            ProgInstruction::SetAssetRiskLimits {
                asset_index: 0,
                exec_band_bps: 0,
                lp_exposure_k_bps,
                lp_floor_atoms,
                side_oi_cap_q,
                matcher_ext_mode: 0,
                max_requested_fee_bps: 0,
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
        assert_eq!(stored.lp_exposure_k_bps, lp_exposure_k_bps);
        assert_eq!(stored.lp_floor_atoms, lp_floor_atoms);
        assert_eq!(stored.side_oi_cap_q, side_oi_cap_q);
    }

    fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data).unwrap()
    }

    fn group(&self) -> MarketGroupV16 {
        state::read_market(&self.svm.get_account(&self.market).unwrap().data)
            .unwrap()
            .1
    }

    /// Signed position on asset 0 (same derivation as the program's
    /// `signed_position_for_asset_view`).
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

    fn oi(&self) -> (u128, u128) {
        let g = self.group();
        (g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q)
    }

    /// The market-wide matcher request nonce (last committed req id).
    fn req_nonce(&self) -> u64 {
        state::next_market_matcher_req_id(&self.svm.get_account(&self.market).unwrap().data)
            .unwrap()
            - 1
    }

    /// Test-harness state seed (copied from v16_cu.rs `force_portfolio_capital_for_benchmark`):
    /// sets a portfolio's capital, keeping vault/c_tot conservation.
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

    fn snapshot(&self, keys: &[Pubkey]) -> Vec<Vec<u8>> {
        keys.iter()
            .map(|k| self.svm.get_account(k).unwrap().data)
            .collect()
    }
}

/// cap_q = floor(equity_init * k * POS_SCALE / (10_000 * price)), equity_init from the
/// portfolio (capital + min(pnl, 0); fee credits are 0 in these fixtures).
fn expected_cap_q(p: &PortfolioAccountV16, k_bps: u128) -> u128 {
    assert_eq!(p.fee_credits, 0, "fixture: no fee debt");
    let eq = p.capital as i128 + p.pnl.min(0);
    let eq = if eq <= 0 { 0 } else { eq as u128 };
    eq * k_bps * POS_SCALE / (10_000 * PRICE as u128)
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 4: TradeCpi headroom clip -> partial fill, then ZERO fill at cap.

// ─────────────────────────────────────────────────────────────────────────────
// Event helpers.
// ─────────────────────────────────────────────────────────────────────────────
impl Env {
    fn events(&self) -> Vec<Event> {
        wrapper_events(&last_logs(), &self.program_id)
    }

    fn only_fill(&self) -> (u8, Pubkey, Pubkey, Pubkey, FillRecord) {
        let evs = self.events();
        assert_eq!(evs.len(), 1, "exactly one wrapper event expected, got {evs:?}");
        match evs.into_iter().next().unwrap() {
            Event::Fill { ix_tag, market, taker, lp, mut recs } => {
                assert_eq!(recs.len(), 1);
                (ix_tag, market, taker, lp, recs.remove(0))
            }
            other => panic!("expected a FILL, got {other:?}"),
        }
    }

    fn capital(&self, portfolio: Pubkey) -> u128 {
        self.portfolio_state(portfolio).capital
    }

    fn effective_price(&self) -> u64 {
        self.group().assets[0].effective_price
    }

    /// Tag 44 RebalanceReduce, owner-signed.
    fn reduce(&mut self, owner: &Keypair, portfolio: Pubkey, reduce_q: u128) -> Result<u64, String> {
        let (id, _, epoch) = self.identity(portfolio);
        self.send(
            ProgInstruction::RebalanceReduce {
                portfolio_id: id,
                position_epoch: epoch,
                asset_index: 0,
                reduce_q,
            },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
    }
}

/// The ceiling fee the engine charges: ceil(ceil(|size| * price / POS_SCALE) * bps / 10_000).
fn expected_fee(size_q: i128, price: u64, bps: u64) -> u64 {
    let n = (size_q.unsigned_abs() * price as u128).div_ceil(POS_SCALE);
    (n * bps as u128).div_ceil(10_000) as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// FILL: TradeCpi (tag 10).
// ─────────────────────────────────────────────────────────────────────────────

/// Full fill with a non-zero fee: executed == requested, booked price == effective price, fee ==
/// the engine charge (== the taker's capital drop), position change == executed.
#[test]
fn fill_event_trade_cpi_full_fill_matches_state() {
    let mut env = Env::with_fee(100);
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    let cap_before = env.capital(taker_account);
    let cu = env.trade_cpi(&taker, taker_account, &lp, 10 * Q).expect("trade");
    eprintln!("CU trade_cpi full fill: {cu}");
    let (tag, market, t, l, rec) = env.only_fill();
    assert_eq!((tag, market, t, l), (10, env.market, taker_account, lp.account));
    let fee = expected_fee(10 * Q, PRICE, 100);
    assert!(fee > 0);
    assert_eq!(
        rec,
        FillRecord {
            asset_index: 0,
            asset_gen: env.market_id(),
            flags: FLAG_MATCHER,
            requested_q: 10 * Q,
            executed_q: 10 * Q,
            price_e6: env.effective_price(),
            quoted_price_e6: PRICE,
            fee_atoms: fee,
            backing_fee_atoms: 0,
        }
    );
    // State agrees: position moved by exactly `executed`, taker paid exactly `fee`.
    assert_eq!(env.pos(taker_account), rec.executed_q);
    assert_eq!(env.pos(lp.account), -rec.executed_q);
    assert_eq!(cap_before - env.capital(taker_account), fee as u128);
}

/// Headroom clip, then the at-cap zero fill (no matcher call): both are visible, the zero fill
/// carries size 0 and changes nothing.
#[test]
fn fill_event_trade_cpi_headroom_clip_and_zero_fill() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000); // cap_q = 10 units
    env.trade_cpi(&taker, taker_account, &lp, 15 * Q).expect("clipped trade");
    let (_, _, _, _, rec) = env.only_fill();
    assert_eq!(rec.flags, FLAG_MATCHER | FLAG_CLIPPED);
    assert_eq!((rec.requested_q, rec.executed_q), (15 * Q, 10 * Q));
    assert_eq!(env.pos(taker_account), rec.executed_q, "state agrees with the clipped size");

    let before = env.snapshot(&[taker_account, lp.account]);
    env.trade_cpi(&taker, taker_account, &lp, 3 * Q).expect("zero fill is Ok");
    let (tag, _, t, l, rec) = env.only_fill();
    assert_eq!((tag, t, l), (10, taker_account, lp.account));
    assert_eq!(rec.flags, FLAG_MATCHER | FLAG_CLIPPED | FLAG_ZERO);
    assert_eq!((rec.requested_q, rec.executed_q), (3 * Q, 0));
    assert_eq!((rec.fee_atoms, rec.backing_fee_atoms, rec.quoted_price_e6), (0, 0, 0));
    assert_eq!(rec.price_e6, env.effective_price(), "reference price on a zero fill");
    assert_eq!(env.snapshot(&[taker_account, lp.account]), before, "zero fill: no state change");
}

/// The matcher fills less than asked (its own max_fill): PARTIAL, not CLIPPED.
#[test]
fn fill_event_trade_cpi_matcher_partial() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp_with(1_000_000, 4 * Q as u128);
    env.trade_cpi(&taker, taker_account, &lp, 10 * Q).expect("partial trade");
    let (_, _, _, _, rec) = env.only_fill();
    assert_eq!(rec.flags, FLAG_MATCHER | FLAG_PARTIAL);
    assert_eq!(rec.requested_q, 10 * Q);
    assert!(rec.executed_q != 0 && rec.executed_q < 10 * Q, "partial: {rec:?}");
    assert_eq!(env.pos(taker_account), rec.executed_q, "state agrees with the partial size");
    assert_eq!(env.pos(lp.account), -rec.executed_q);
}

/// A short request: the signs carry through requested / executed / state.
#[test]
fn fill_event_trade_cpi_short_side_sign() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    env.trade_cpi(&taker, taker_account, &lp, -7 * Q).expect("short");
    let (_, _, _, _, rec) = env.only_fill();
    assert_eq!((rec.requested_q, rec.executed_q), (-7 * Q, -7 * Q));
    assert_eq!(env.pos(taker_account), -7 * Q);
}

// ─────────────────────────────────────────────────────────────────────────────
// FILL: TradeNoCpi (tag 6) and BatchTradeCpi (tag 67, one leg here; 11 legs in v16_cu).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn fill_event_trade_nocpi_matches_state() {
    let mut env = Env::with_fee(50);
    let (a, b) = (Keypair::new(), Keypair::new());
    let pa = env.portfolio(&a, 1_000_000);
    let pb = env.portfolio(&b, 1_000_000);
    let cap_a = env.capital(pa);
    let cu = env.trade_nocpi(&a, pa, &b, pb, 6 * Q).expect("nocpi trade");
    eprintln!("CU trade_nocpi: {cu}");
    let (tag, market, t, l, rec) = env.only_fill();
    assert_eq!((tag, market, t, l), (6, env.market, pa, pb));
    let fee = expected_fee(6 * Q, PRICE, 50);
    assert_eq!(rec.flags, 0, "no matcher on NoCpi");
    assert_eq!((rec.requested_q, rec.executed_q), (6 * Q, 6 * Q));
    assert_eq!(rec.quoted_price_e6, PRICE, "the wire exec_price");
    assert_eq!(rec.price_e6, env.effective_price());
    assert_eq!(rec.fee_atoms, fee);
    assert_eq!(env.pos(pa), 6 * Q);
    assert_eq!(cap_a - env.capital(pa), fee as u128, "the taker (account_a) paid the fee");
}

#[test]
fn fill_event_batch_trade_cpi_leg_matches_state() {
    let mut env = Env::with_fee(100);
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    let cap_before = env.capital(taker_account);
    let cu = env.batch_trade_cpi(&taker, taker_account, &lp, 5 * Q).expect("batch");
    eprintln!("CU batch_trade_cpi 1 leg: {cu}");
    let (tag, market, t, l, rec) = env.only_fill();
    assert_eq!((tag, market, t, l), (67, env.market, taker_account, lp.account));
    assert_eq!(rec.flags, FLAG_MATCHER);
    assert_eq!((rec.requested_q, rec.executed_q), (5 * Q, 5 * Q));
    assert_eq!(rec.price_e6, env.effective_price());
    assert_eq!(rec.fee_atoms, expected_fee(5 * Q, PRICE, 100));
    assert_eq!(env.pos(taker_account), rec.executed_q);
    assert_eq!(cap_before - env.capital(taker_account), rec.fee_atoms as u128);
}

// ─────────────────────────────────────────────────────────────────────────────
// REDUCE: RebalanceReduce (tag 44).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn reduce_event_rebalance_reduce_full_and_clipped() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    env.trade_cpi(&taker, taker_account, &lp, 10 * Q).expect("open");

    // Request 4 of 10: executed exactly 4, the long is reduced (negative signed size).
    let cu = env.reduce(&taker, taker_account, 4 * Q as u128).expect("reduce 4");
    eprintln!("CU rebalance_reduce: {cu}");
    let evs = env.events();
    assert_eq!(evs.len(), 1, "{evs:?}");
    let Event::Reduce { ix_tag, market, portfolio, counterparty, asset_index, asset_gen, reason, signed_reduced_q, price_e6 } =
        evs[0].clone()
    else {
        panic!("expected REDUCE, got {evs:?}")
    };
    assert_eq!((ix_tag, market, portfolio), (44, env.market, taker_account));
    assert_eq!(counterparty, Pubkey::default(), "unilateral: no counterparty");
    assert_eq!((asset_index, asset_gen, reason), (0, env.market_id(), 1));
    assert_eq!(signed_reduced_q, -4 * Q);
    assert_eq!(price_e6, env.effective_price());
    assert_eq!(env.pos(taker_account), 6 * Q, "state agrees: 10 - 4");

    // The LP is short 10 but the open interest is now 6 per side (the unilateral reduce took the
    // matching OI with it), so the engine's close capacity is 6: a request for 8 executes 6.
    // The LP is short, so it is reduced the other way (positive signed size).
    env.reduce(&lp.owner, lp.account, 8 * Q as u128).expect("lp reduce past capacity");
    let evs = env.events();
    let Event::Reduce { portfolio, signed_reduced_q, .. } = evs[0].clone() else { panic!("{evs:?}") };
    assert_eq!(portfolio, lp.account);
    assert_eq!(signed_reduced_q, 6 * Q, "executed 6 of the requested 8 (capacity-bound)");
    assert_eq!(env.pos(lp.account), 0, "state agrees: the LP leg is flat");

    // Position-bound clip on a fresh market: request 50 against a 10-unit position.
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    env.trade_cpi(&taker, taker_account, &lp, 10 * Q).expect("open");
    env.reduce(&taker, taker_account, 50 * Q as u128).expect("reduce past the position");
    let evs = env.events();
    let Event::Reduce { signed_reduced_q, .. } = evs[0].clone() else { panic!("{evs:?}") };
    assert_eq!(signed_reduced_q, -10 * Q, "executed 10 of the requested 50");
    assert_eq!(env.pos(taker_account), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribution and failure rules.
// ─────────────────────────────────────────────────────────────────────────────

/// A failed transaction's logs may carry events (logs outlive the revert): the documented rule is
/// that an indexer trusts only successful transactions. Prove the premise: a trade that errors
/// AFTER some wrapper work still yields a failed meta, and the success path is the only one the
/// decoder is applied to in these tests.
#[test]
fn fill_events_only_trusted_on_success() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000);
    let lp = env.lp(1_000_000);
    // Far beyond the taker's margin: the engine refuses it -> the instruction (and tx) fails.
    let r = env.trade_cpi(&taker, taker_account, &lp, 1_000_000 * Q);
    assert!(r.is_err(), "over-margin trade must fail: {r:?}");
}

/// The attribution rule on synthetic logs: a "Program data:" line that another program emits
/// (even one that copies a wrapper event byte for byte) is never attributed to the wrapper, and a
/// wrapper line is attributed even when the wrapper was entered by CPI.
#[test]
fn attribution_rule_is_frame_based() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000);
    env.trade_cpi(&taker, taker_account, &lp, 2 * Q).unwrap();
    let logs = last_logs();
    let tokens = fill_events::wrapper_tokens(&logs, &env.program_id);
    assert_eq!(tokens.len(), 1);
    let w = env.program_id.to_string();
    let other = Pubkey::new_unique().to_string();
    // A forged copy emitted by `other` as the OUTER program, then the real wrapper frame nested
    // in it (CPI), then another forged copy after the wrapper returned.
    let forged = vec![
        format!("Program {other} invoke [1]"),
        format!("Program data: {}", tokens[0]),
        format!("Program {w} invoke [2]"),
        format!("Program data: {}", tokens[0]),
        format!("Program {w} success"),
        format!("Program data: {}", tokens[0]),
        format!("Program {other} success"),
    ];
    let evs = wrapper_events(&forged, &env.program_id);
    assert_eq!(evs.len(), 1, "only the line inside the wrapper's own frame counts: {evs:?}");
}
