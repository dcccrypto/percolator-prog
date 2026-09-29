// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P1 wrapper safety release -- items 3 (LP exposure cap + protocol side-OI cap),
//! 4 (TradeCpi headroom clip / zero fill) and 5 (LP floor auto-halt), driven through the REAL
//! wrapper BPF (`target/deploy/percolator_prog.so`, built `--features devnet`) and the REAL
//! passive (kind-0) matcher BPF (`../percolator-match`, deployed 12bd671) in LiteSVM.
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
    svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"))
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
}

impl Env {
    fn new() -> Self {
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
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
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
                max_fill_abs: u128::MAX,
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
                fee_bps: 0,
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
                    fee_bps: 0,
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
                fee_bps: 0,
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
#[test]
fn p1_trade_cpi_clips_to_lp_headroom_then_zero_fills_at_cap() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);

    let cap_q = expected_cap_q(&env.portfolio_state(lp.account), 10_000);
    assert_eq!(
        cap_q,
        10 * POS_SCALE,
        "cap_q formula for E=1000, k=1e8/IMR, price 100"
    );

    // Request 15 units (> headroom 10): must SUCCEED with the LP moved by exactly the headroom.
    let nonce0 = env.req_nonce();
    let r = env.trade_cpi(&taker, taker_account, &lp, 15 * Q);
    assert!(
        r.is_ok(),
        "over-headroom TradeCpi must clip to a partial fill, not revert: {r:?}"
    );
    assert_eq!(
        env.pos(lp.account),
        -(cap_q as i128),
        "LP moved by exactly headroom"
    );
    assert_eq!(
        env.pos(taker_account),
        cap_q as i128,
        "taker filled exactly headroom"
    );
    assert_eq!(env.req_nonce(), nonce0 + 1);

    // LP now at cap: a further growing request is Ok as a ZERO fill.
    let before = env.snapshot(&[taker_account, lp.account]);
    let nonce1 = env.req_nonce();
    let r = env.trade_cpi(&taker, taker_account, &lp, 3 * Q);
    assert!(
        r.is_ok(),
        "at-cap TradeCpi must be a zero fill, not revert: {r:?}"
    );
    assert_eq!(
        env.snapshot(&[taker_account, lp.account]),
        before,
        "zero fill: neither portfolio changes"
    );
    assert_eq!(env.pos(lp.account), -(cap_q as i128));
    assert_eq!(
        env.req_nonce(),
        nonce1 + 1,
        "zero fill still commits the matcher req id"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 3: LP exposure cap on BatchTradeCpi (atomic, no clip) -> Custom(68).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_batch_trade_cpi_refuses_lp_growth_past_cap() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);
    // k = 0.5x -> cap 5 units, strictly inside what the engine IM gate (10 units) allows,
    // so the refusal is the wrapper cap, not the engine's Custom(49).
    env.set_risk_limits(5_000, 0, 0);
    let cap_q = expected_cap_q(&env.portfolio_state(lp.account), 5_000);
    assert_eq!(cap_q, 5 * POS_SCALE);

    // Proof of life: a within-cap batch leg fills.
    env.batch_trade_cpi(&taker, taker_account, &lp, 4 * Q)
        .expect("within-cap batch leg fills");
    assert_eq!(env.pos(lp.account), -4 * Q);

    // A leg that takes the LP to 6 > cap 5 is refused atomically.
    let keys = [env.market, taker_account, lp.account];
    let before = env.snapshot(&keys);
    let r = env.batch_trade_cpi(&taker, taker_account, &lp, 2 * Q);
    assert_err_code(&r, LP_EXPOSURE_CAP_EXCEEDED, "batch leg past LP cap");
    assert_eq!(env.snapshot(&keys), before, "refused batch mutates nothing");

    // Exactly to the cap is allowed.
    env.batch_trade_cpi(&taker, taker_account, &lp, Q)
        .expect("batch leg to exactly cap fills");
    assert_eq!(env.pos(lp.account), -5 * Q);
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 5: floor / auto-halt -> Custom(69) on growth; reductions still work.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_lp_floor_halts_growth_but_allows_reduction() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);
    env.trade_cpi(&taker, taker_account, &lp, 4 * Q)
        .expect("open LP -4 before the floor is raised");
    assert_eq!(env.pos(lp.account), -4 * Q);

    // Floor above the LP's equity (1000): the LP is halted for risk-increasing fills.
    env.set_risk_limits(0, 2_000, 0);

    let keys = [env.market, taker_account, lp.account];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, taker_account, &lp, Q);
    assert_err_code(&r, LP_FLOOR_HALT, "TradeCpi growth on a floored LP");
    let r = env.batch_trade_cpi(&taker, taker_account, &lp, Q);
    assert_err_code(
        &r,
        LP_FLOOR_HALT,
        "BatchTradeCpi growth on a floored LP (post-fill)",
    );
    assert_eq!(env.snapshot(&keys), before, "halted growth mutates nothing");

    // Reduction (LP -4 -> -2) still succeeds on both CPI routes.
    env.trade_cpi(&taker, taker_account, &lp, -Q)
        .expect("TradeCpi reduction on a floored LP");
    assert_eq!(env.pos(lp.account), -3 * Q);
    env.batch_trade_cpi(&taker, taker_account, &lp, -Q)
        .expect("BatchTradeCpi reduction on a floored LP");
    assert_eq!(env.pos(lp.account), -2 * Q);

    // A request past flat (-2 -> +1) is CLIPPED to flatten on TradeCpi (spec change after the
    // Kani-lane finding P1-K1: refusing the whole request blocked a legitimate reduction).
    env.trade_cpi(&taker, taker_account, &lp, -3 * Q)
        .expect("TradeCpi reduce-through-flat on a floored LP is clipped, not refused");
    assert_eq!(env.pos(lp.account), 0, "clipped exactly to flat");
    // From flat, a floored LP can only grow: every direction is halted.
    let before_flat = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, taker_account, &lp, -Q);
    assert_err_code(&r, LP_FLOOR_HALT, "TradeCpi growth from flat on a floored LP");
    let r = env.trade_cpi(&taker, taker_account, &lp, Q);
    assert_err_code(&r, LP_FLOOR_HALT, "TradeCpi growth from flat on a floored LP (other side)");
    assert_eq!(env.snapshot(&keys), before_flat, "halted growth from flat mutates nothing");
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 3 (second half): protocol side-OI cap, all routes -> Custom(70).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_protocol_side_oi_cap_refuses_growth_allows_shrink_all_routes() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000_000); // LP cap = 10_000 units: never binds here.
    let other = Keypair::new();
    let other_account = env.portfolio(&other, 1_000_000);

    env.trade_cpi(&taker, taker_account, &lp, 5 * Q)
        .expect("open 5 via TradeCpi");
    assert_eq!(env.oi(), (5 * POS_SCALE, 5 * POS_SCALE));

    // Cap 6 units: +2 would make each side 7.
    env.set_risk_limits(0, 0, 6 * POS_SCALE);
    let keys = [env.market, taker_account, lp.account, other_account];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, taker_account, &lp, 2 * Q);
    assert_err_code(
        &r,
        PROTOCOL_SIDE_OI_CAP_EXCEEDED,
        "TradeCpi OI growth past cap",
    );
    let r = env.batch_trade_cpi(&taker, taker_account, &lp, 2 * Q);
    assert_err_code(
        &r,
        PROTOCOL_SIDE_OI_CAP_EXCEEDED,
        "BatchTradeCpi OI growth past cap",
    );
    let r = env.trade_nocpi(&other, other_account, &lp.owner, lp.account, 2 * Q);
    assert_err_code(
        &r,
        PROTOCOL_SIDE_OI_CAP_EXCEEDED,
        "TradeNoCpi OI growth past cap",
    );
    assert_eq!(
        env.snapshot(&keys),
        before,
        "refused OI growth mutates nothing"
    );

    // Growth to exactly the cap is fine (TradeNoCpi: other long 1 vs LP short 1).
    env.trade_nocpi(&other, other_account, &lp.owner, lp.account, Q)
        .expect("TradeNoCpi growth to exactly the cap");
    assert_eq!(env.oi(), (6 * POS_SCALE, 6 * POS_SCALE));

    // Lower the cap BELOW current OI: shrinking trades still succeed on every route.
    env.set_risk_limits(0, 0, 3 * POS_SCALE);
    env.trade_cpi(&taker, taker_account, &lp, -Q)
        .expect("TradeCpi shrink over cap");
    assert_eq!(env.oi(), (5 * POS_SCALE, 5 * POS_SCALE));
    env.batch_trade_cpi(&taker, taker_account, &lp, -Q)
        .expect("BatchTradeCpi shrink over cap");
    assert_eq!(env.oi(), (4 * POS_SCALE, 4 * POS_SCALE));
    env.trade_nocpi(&other, other_account, &lp.owner, lp.account, -Q)
        .expect("TradeNoCpi shrink over cap");
    assert_eq!(env.oi(), (3 * POS_SCALE, 3 * POS_SCALE));
    // At cap 3 now: growth by one more is still refused.
    let r = env.trade_nocpi(&other, other_account, &lp.owner, lp.account, Q);
    assert_err_code(
        &r,
        PROTOCOL_SIDE_OI_CAP_EXCEEDED,
        "TradeNoCpi growth at cap",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 3/4: LP ALREADY over cap (k lowered after positioning): reduce OK, grow clipped to 0.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_lp_already_over_cap_reduce_ok_grow_zero_fill() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);
    env.trade_cpi(&taker, taker_account, &lp, 8 * Q)
        .expect("open LP -8 (default cap 10)");
    assert_eq!(env.pos(lp.account), -8 * Q);

    env.set_risk_limits(5_000, 0, 0); // cap now 5 < |pos| 8
    assert_eq!(
        expected_cap_q(&env.portfolio_state(lp.account), 5_000),
        5 * POS_SCALE
    );

    // Reduce: -8 -> -6 (still over cap, but reducing) succeeds.
    env.trade_cpi(&taker, taker_account, &lp, -2 * Q)
        .expect("reduce an over-cap LP");
    assert_eq!(env.pos(lp.account), -6 * Q);

    // Grow: clipped to a zero fill.
    let before = env.snapshot(&[taker_account, lp.account]);
    let nonce = env.req_nonce();
    let r = env.trade_cpi(&taker, taker_account, &lp, Q);
    assert!(
        r.is_ok(),
        "growing an over-cap LP via TradeCpi must zero-fill, not revert: {r:?}"
    );
    assert_eq!(env.snapshot(&[taker_account, lp.account]), before);
    assert_eq!(env.req_nonce(), nonce + 1);

    // Same growth on BatchTradeCpi (no clip) is refused by name.
    let r = env.batch_trade_cpi(&taker, taker_account, &lp, Q);
    assert_err_code(
        &r,
        LP_EXPOSURE_CAP_EXCEEDED,
        "batch growth of an over-cap LP",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Replay of the COLLECT/Murphy devnet failure shape: depleted LP (capital 0) with an
// existing position; a taker open that grows the LP. Base build: engine revert. P1: named
// LpFloorHalt; closes still work.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_replay_collect_murphy_depleted_lp() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);
    env.trade_cpi(&taker, taker_account, &lp, 4 * Q)
        .expect("open LP -4");
    env.force_capital(lp.account, 0);
    let p = env.portfolio_state(lp.account);
    assert_eq!((p.capital, p.pnl), (0, 0), "depleted LP seed");

    let keys = [env.market, taker_account, lp.account];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, taker_account, &lp, Q);
    eprintln!("MURPHY-REPLAY open-grows-LP result: {r:?}");
    assert_err_code(&r, LP_FLOOR_HALT, "taker open against a depleted LP");
    assert_eq!(env.snapshot(&keys), before);

    // The taker can still close against the depleted LP (LP -4 -> 0).
    let r = env.trade_cpi(&taker, taker_account, &lp, -4 * Q);
    eprintln!("MURPHY-REPLAY close result: {r:?}");
    assert!(r.is_ok(), "close against a depleted LP must succeed: {r:?}");
    assert_eq!(env.pos(lp.account), 0);
    assert_eq!(env.pos(taker_account), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// FINDING (lane lpcap, 2026-09-29): spec item 5 says the floor halt applies "post-fill on
// both CPI routes", but on BatchTradeCpi a DEPLETED LP (equity 0) growth is refused by the
// engine's own IM gate inside the batch executor with Custom(49) BEFORE the wrapper's
// post-fill `ensure_lp_limits_after_fill_view` loop (src/v16_program.rs, the `if lp_limits`
// loop in handle_batch_execute_zero_copy) ever runs, so the named LpFloorHalt = Custom(69)
// never surfaces there. The trade IS still refused (no value path), only the error code is
// the pre-P1 one. Kept as an ignored, un-weakened failing test; run with `-- --ignored`.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_finding_batch_trade_cpi_depleted_lp_growth_reports_lp_floor_halt() {
    let mut env = Env::new();
    let taker = Keypair::new();
    let taker_account = env.portfolio(&taker, 1_000_000);
    let lp = env.lp(1_000);
    env.trade_cpi(&taker, taker_account, &lp, 4 * Q)
        .expect("open LP -4");
    env.force_capital(lp.account, 0);
    let keys = [env.market, taker_account, lp.account];
    let before = env.snapshot(&keys);
    let r = env.batch_trade_cpi(&taker, taker_account, &lp, Q);
    assert_eq!(
        env.snapshot(&keys),
        before,
        "refused either way: nothing mutates"
    );
    assert_err_code(&r, LP_FLOOR_HALT, "batch taker open against a depleted LP");
}
