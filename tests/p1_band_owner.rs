// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P1 wrapper safety release -- LiteSVM integration tests for
//!   item 1 (oracle band, `ExecPriceOutsideOracleBand` = Custom(66)) and
//!   item 2 (same-owner, `SameOwnerTrade` = Custom(67)),
//! against the REAL built `target/deploy/percolator_prog.so` and, for the CPI routes, the REAL
//! `../percolator-match/target/deploy/percolator_match.so` (passive matcher, which quotes
//! `oracle * (1 +- spread)`; its spread is how a matcher-reported exec price is pushed outside
//! the band -- `validate_matcher_return` does not pin `exec_price_e6`).
//!
//! Harness code is the minimum copied from `tests/v16_cu.rs` (`V16CuEnv`).
//!
//! Every rejection asserts the exact `InstructionError(2, Custom(N))` (ix 0/1 are the compute
//! budget ixs) and that the market + both portfolios (+ matcher context on CPI routes) are
//! byte-identical afterwards. Every accept asserts a real position change (proof of life).
//!
//! Rebuild the .so (`cargo build-sbf -- --features devnet`) before running: a stale .so gives
//! a false result.
use litesvm::LiteSVM;
use percolator::POS_SCALE;
use percolator_prog::{
    ix::Instruction as ProgInstruction,
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
/// Reference price used by every market here: 1_000_000 e6, so one price unit == 0.01 bp and
/// the 500 / 501 bps boundary is exactly representable.
const PRICE: u64 = 1_000_000;

const ERR_UNAUTHORIZED: &str = "InstructionError(2, Custom(8))";
const ERR_BAND: &str = "InstructionError(2, Custom(66))";
const ERR_SAME_OWNER: &str = "InstructionError(2, Custom(67))";

// ───────────────────────────── copied harness (from tests/v16_cu.rs) ─────────────────────────────

fn program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(path.exists(), "BPF not found at {path:?}; run cargo build-sbf first");
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
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
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
    let mut signer_refs = Vec::with_capacity(1 + extra_signers.len());
    signer_refs.push(payer);
    signer_refs.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instruction,
        ],
        Some(&payer.pubkey()),
        &signer_refs,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|meta| meta.compute_units_consumed)
        .map_err(|e| format!("{e:?}"))
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    portfolio_account_len: usize,
    matcher_program: Pubkey,
    /// Holder of the (mocked) ProgramData upgrade authority, for tag 93.
    upgrade_authority: Keypair,
    program_data: Pubkey,
}

impl Env {
    /// Market with asset 0 at `PRICE`, IMR = MMR = 100%, zero base fee, real matcher loaded,
    /// and a mocked ProgramData whose upgrade authority is `upgrade_authority` (LiteSVM's
    /// `add_program` uses the non-upgradeable loader; the layout is the one
    /// `read_program_data_upgrade_authority` parses, same as v16_cu.rs's tag-85 test).
    fn new(max_portfolio_assets: u16) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(program_path()).expect("read BPF"));
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
        svm.set_account(mint, acct(make_mint_data(), spl_token::ID)).unwrap();
        svm.set_account(vault, acct(make_token_data(mint, vault_authority, 0), spl_token::ID))
            .unwrap();
        svm.set_account(
            market,
            acct(
                vec![0u8; state::market_account_len_for_capacity(max_portfolio_assets as usize).unwrap()],
                program_id,
            ),
        )
        .unwrap();

        let upgrade_authority = Keypair::new();
        svm.airdrop(&upgrade_authority.pubkey(), 1_000_000_000).unwrap();
        let (program_data, _) = Pubkey::find_program_address(
            &[program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        );
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(upgrade_authority.pubkey().as_ref());
        svm.set_account(program_data, acct(pd, solana_sdk::bpf_loader_upgradeable::id()))
            .unwrap();

        send_tx(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::InitMarket {
                max_portfolio_assets,
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
        Self {
            svm,
            program_id,
            payer,
            admin,
            market,
            mint,
            vault,
            portfolio_account_len: state::portfolio_account_len_for_market_slots(
                max_portfolio_assets as usize,
            )
            .unwrap(),
            matcher_program,
            upgrade_authority,
            program_data,
        }
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<u64, String> {
        self.svm.expire_blockhash();
        send_tx(&mut self.svm, self.program_id, &self.payer, ix, accounts, signers)
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        let portfolio = Pubkey::new_unique();
        if self.svm.get_account(&owner.pubkey()).is_none() {
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
        portfolio
    }

    fn portfolio_identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
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
        let (portfolio_id, expected_sequence, _) = self.portfolio_identity(portfolio);
        self.send(
            ProgInstruction::Deposit {
                portfolio_id,
                expected_sequence,
                amount,
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

    fn funded_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        let p = self.create_portfolio(owner);
        self.deposit(owner, p, 1_000_000_000);
        p
    }

    fn market_id(&self, asset_index: u16) -> u64 {
        state::read_market_trade_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
        )
        .unwrap()
        .3
    }

    fn market_state(&self) -> MarketGroupV16 {
        state::read_market(&self.svm.get_account(&self.market).unwrap().data)
            .unwrap()
            .1
    }

    fn effective_price(&self, asset_index: usize) -> u64 {
        self.market_state().assets[asset_index].effective_price
    }

    fn portfolio_state(&self, portfolio: Pubkey) -> PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data).unwrap()
    }

    fn position(&self, portfolio: Pubkey, asset_index: usize) -> i128 {
        self.portfolio_state(portfolio)
            .legs
            .iter()
            .find(|leg| leg.active && leg.asset_index as usize == asset_index)
            .map(|leg| leg.basis_pos_q)
            .unwrap_or(0)
    }

    fn snapshot(&self, keys: &[Pubkey]) -> Vec<Account> {
        keys.iter().map(|k| self.svm.get_account(k).unwrap()).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn trade_nocpi(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        asset_index: u16,
        size_q: i128,
        exec_price: u64,
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.portfolio_identity(account_a);
        let (b_id, _, b_epoch) = self.portfolio_identity(account_b);
        let market_id = self.market_id(asset_index);
        let signers: Vec<&Keypair> = if owner_a.pubkey() == owner_b.pubkey() {
            vec![owner_a]
        } else {
            vec![owner_a, owner_b]
        };
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id,
                asset_index,
                size_q,
                exec_price,
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
            &signers,
        )
    }

    fn batch_nocpi(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        legs: &[(u16, i128, u64)],
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.portfolio_identity(account_a);
        let (b_id, _, b_epoch) = self.portfolio_identity(account_b);
        let signers: Vec<&Keypair> = if owner_a.pubkey() == owner_b.pubkey() {
            vec![owner_a]
        } else {
            vec![owner_a, owner_b]
        };
        let legs = legs
            .iter()
            .map(|&(asset_index, size_q, exec_price)| percolator_prog::ix::BatchTradeLeg {
                asset_index,
                market_id: self.market_id(asset_index),
                size_q,
                exec_price,
                fee_bps: 0,
            })
            .collect();
        self.send(
            ProgInstruction::BatchTradeNoCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                legs,
            },
            vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            &signers,
        )
    }

    /// Registers `lp_account` (owned by `lp_owner`) as a matcher LP with a passive context of
    /// `spread_bps` (the real matcher fills buys at `ceil(oracle * (1 + spread))`).
    fn init_matcher(&mut self, lp_owner: &Keypair, lp_account: Pubkey, spread_bps: u32) -> (Pubkey, Pubkey) {
        let matcher_program = self.matcher_program;
        let ctx = Pubkey::new_unique();
        let delegate = matcher_delegate_key(
            &self.program_id,
            &self.market,
            &lp_account,
            &lp_owner.pubkey(),
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
        let (portfolio_id, expected_sequence, _) = self.portfolio_identity(lp_account);
        let asset_generation_frontier = state::read_market_asset_generation_frontier(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
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
                AccountMeta::new(lp_owner.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(lp_account, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new_readonly(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[lp_owner],
        )
        .expect("set matcher config");
        self.send(
            ProgInstruction::InitMatcherCtx {
                kind: 0,
                trading_fee_bps: 0,
                base_spread_bps: spread_bps,
                max_total_bps: spread_bps.max(100),
                impact_k_bps: 0,
                liquidity_notional_e6: 0,
                max_fill_abs: u128::MAX,
                max_inventory_abs: 0,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                AccountMeta::new(lp_owner.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(lp_account, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[lp_owner],
        )
        .expect("init matcher context via wrapper InitMatcherCtx");
        (ctx, delegate)
    }

    #[allow(clippy::too_many_arguments)]
    fn trade_cpi(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp_account: Pubkey,
        ctx: Pubkey,
        delegate: Pubkey,
        asset_index: u16,
        size_q: i128,
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.portfolio_identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.portfolio_identity(lp_account);
        let market_id = self.market_id(asset_index);
        let matcher_program = self.matcher_program;
        self.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id,
                account_b_matcher_sequence: b_seq,
                asset_index,
                size_q,
                fee_bps: 0,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(taker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp_account, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[taker],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn batch_cpi(
        &mut self,
        taker: &Keypair,
        taker_account: Pubkey,
        lp_account: Pubkey,
        ctx: Pubkey,
        delegate: Pubkey,
        legs: &[(u16, i128)],
    ) -> Result<u64, String> {
        let (a_id, _, a_epoch) = self.portfolio_identity(taker_account);
        let (b_id, b_seq, b_epoch) = self.portfolio_identity(lp_account);
        let legs = legs
            .iter()
            .map(|&(asset_index, size_q)| percolator_prog::ix::BatchTradeCpiLeg {
                asset_index,
                market_id: self.market_id(asset_index),
                size_q,
                fee_bps: 0,
                limit_price: 0,
            })
            .collect();
        let matcher_program = self.matcher_program;
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
                AccountMeta::new(self.market, false),
                AccountMeta::new(taker_account, false),
                AccountMeta::new(lp_account, false),
                AccountMeta::new_readonly(matcher_program, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[taker],
        )
    }

    fn set_asset_risk_limits(
        &mut self,
        signer: &Keypair,
        asset_index: u16,
        exec_band_bps: u16,
    ) -> Result<u64, String> {
        let program_data = self.program_data;
        self.send(
            ProgInstruction::SetAssetRiskLimits {
                asset_index,
                exec_band_bps,
                lp_exposure_k_bps: 0,
                lp_floor_atoms: 0,
                side_oi_cap_q: 0,
                matcher_ext_mode: 0,
                max_requested_fee_bps: 0,
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new(self.market, false),
            ],
            &[signer],
        )
    }
}

fn assert_err(r: Result<u64, String>, want: &str, what: &str) {
    match r {
        Ok(cu) => panic!("{what}: expected {want}, but the tx SUCCEEDED ({cu} CU)"),
        Err(e) => assert!(e.contains(want), "{what}: expected {want}, got {e}"),
    }
}

/// `reference * (10_000 + bps) / 10_000`, asserted exact so the boundary is not rounded.
fn price_at_bps(reference: u64, bps: i64) -> u64 {
    let num = reference as i128 * (10_000 + bps as i128);
    assert_eq!(num % 10_000, 0, "boundary price must be exact");
    (num / 10_000) as u64
}

const UNIT: i128 = POS_SCALE as i128;


/// The matcher return the wrapper just consumed (read off the ctx after a SUCCESSFUL fill).
fn matcher_return(env: &Env, ctx: Pubkey) -> percolator_prog::matcher_abi::MatcherReturn {
    percolator_prog::matcher_abi::read_matcher_return(&env.svm.get_account(&ctx).unwrap().data)
        .unwrap()
}

// ─────────────────────── item 1: oracle band (matcher-routed routes only) ───────────────────────

/// TradeCpi through the REAL matcher, `limit_price = 0`. The band reference is the exact
/// `oracle_price_e6` handed to the matcher (= the slab's effective price at preflight). A
/// passive spread of s bps makes the matcher report `ceil(oracle*(1+s))` for a buy and
/// `floor(oracle*(1-s))` for a sell:
///   +-600 bps -> Custom(66), every account (market, both portfolios, matcher ctx) untouched;
///   +-501 bps -> Custom(66);  +-500 bps -> fills (exact boundary);  300 bps -> fills.
#[test]
fn p1_band_trade_cpi_matcher_price_boundary_500_passes_501_rejects() {
    let mut env = Env::new(1);
    let (taker, lp) = (Keypair::new(), Keypair::new());
    let ta = env.funded_portfolio(&taker);
    let la = env.funded_portfolio(&lp);
    let oracle = env.effective_price(0);
    assert_eq!(oracle, PRICE, "fixture: reference price read from slab");

    let mut expected_pos = 0i128;
    for (spread, dir) in [(600u32, 1i128), (600, -1), (501, 1), (501, -1)] {
        let (ctx, delegate) = env.init_matcher(&lp, la, spread);
        let keys = [env.market, ta, la, ctx];
        let before = env.snapshot(&keys);
        let r = env.trade_cpi(&taker, ta, la, ctx, delegate, 0, dir * UNIT);
        assert_err(r, ERR_BAND, &format!("TradeCpi, matcher spread {spread} bps, dir {dir}"));
        assert_eq!(env.snapshot(&keys), before, "rejected TradeCpi mutated an account");
    }
    assert_eq!(env.position(ta, 0), 0);

    for (spread, dir) in [(500u32, 1i128), (500, -1), (300, 1)] {
        let (ctx, delegate) = env.init_matcher(&lp, la, spread);
        env.trade_cpi(&taker, ta, la, ctx, delegate, 0, dir * UNIT)
            .unwrap_or_else(|e| panic!("TradeCpi at spread {spread} dir {dir} must fill: {e}"));
        let ret = matcher_return(&env, ctx);
        assert_eq!(ret.oracle_price_e6, oracle, "matcher saw the slab reference price");
        assert_eq!(
            ret.exec_price_e6,
            price_at_bps(oracle, dir as i64 * spread as i64),
            "matcher-reported exec price is exactly {spread} bps off"
        );
        expected_pos += dir * UNIT;
        assert_eq!(env.position(ta, 0), expected_pos, "taker position moved");
        assert_eq!(env.position(la, 0), -expected_pos, "LP position moved");
    }
}

/// BatchTradeCpi through the REAL matcher (300 bps spread on every leg): asset 1's band is
/// narrowed to 100 bps via tag 93, so leg 1 is outside while leg 0 (default 500) is inside ->
/// the WHOLE batch is Custom(66), nothing lands. Restoring asset 1's band (0 = default) ->
/// both legs fill.
#[test]
fn p1_band_batch_trade_cpi_one_leg_outside_rejects_whole_batch() {
    // InitMarket with max_portfolio_assets = 2 already marks slots 0 and 1 Active.
    let mut env = Env::new(2);
    assert_eq!(env.effective_price(1), PRICE, "fixture: asset 1 live at PRICE");
    let (taker, lp) = (Keypair::new(), Keypair::new());
    let ta = env.funded_portfolio(&taker);
    let la = env.funded_portfolio(&lp);
    let (ctx, delegate) = env.init_matcher(&lp, la, 300);
    let ua = env.upgrade_authority.insecure_clone();
    env.set_asset_risk_limits(&ua, 1, 100).expect("narrow asset 1 band");

    let keys = [env.market, ta, la, ctx];
    let before = env.snapshot(&keys);
    let r = env.batch_cpi(&taker, ta, la, ctx, delegate, &[(0, UNIT), (1, UNIT)]);
    assert_err(r, ERR_BAND, "BatchTradeCpi with leg 1 outside its 100 bps band");
    assert_eq!(env.snapshot(&keys), before, "rejected batch mutated an account");

    env.set_asset_risk_limits(&ua, 1, 0).expect("restore default band");
    env.batch_cpi(&taker, ta, la, ctx, delegate, &[(0, UNIT), (1, UNIT)])
        .expect("both legs inside the default band must fill");
    assert_eq!(env.position(ta, 0), UNIT);
    assert_eq!(env.position(ta, 1), UNIT);
    assert_eq!(env.position(la, 0), -UNIT);
    assert_eq!(env.position(la, 1), -UNIT);
}

/// Tag 93: narrowing asset 0's band to 100 bps turns a previously-OK 300 bps matcher fill into
/// Custom(66). A non-upgrade-authority signer (the market admin, or a stranger) ->
/// Unauthorized = Custom(8), market untouched, band unchanged.
#[test]
fn p1_band_set_asset_risk_limits_narrows_band_and_is_upgrade_authority_gated() {
    let mut env = Env::new(1);
    let (taker, lp) = (Keypair::new(), Keypair::new());
    let ta = env.funded_portfolio(&taker);
    let la = env.funded_portfolio(&lp);
    let (ctx, delegate) = env.init_matcher(&lp, la, 300);

    env.trade_cpi(&taker, ta, la, ctx, delegate, 0, UNIT)
        .expect("300 bps matcher fill passes under the default 500 bps band");
    assert_eq!(env.position(ta, 0), UNIT);

    let admin = env.admin.insecure_clone();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    for (who, k) in [("market admin", &admin), ("stranger", &stranger)] {
        let before = env.snapshot(&[env.market]);
        let r = env.set_asset_risk_limits(k, 0, 100);
        assert_err(r, ERR_UNAUTHORIZED, &format!("tag 93 signed by {who}"));
        assert_eq!(env.snapshot(&[env.market]), before, "unauthorized tag 93 mutated market");
    }
    env.trade_cpi(&taker, ta, la, ctx, delegate, 0, UNIT)
        .expect("band unchanged after the refused setters");
    assert_eq!(env.position(ta, 0), 2 * UNIT);

    let ua = env.upgrade_authority.insecure_clone();
    env.set_asset_risk_limits(&ua, 0, 100).expect("upgrade authority narrows band");
    let keys = [env.market, ta, la, ctx];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&taker, ta, la, ctx, delegate, 0, UNIT);
    assert_err(r, ERR_BAND, "300 bps matcher fill after band narrowed to 100 bps");
    assert_eq!(env.snapshot(&keys), before);
    assert_eq!(env.position(ta, 0), 2 * UNIT);

    // Boundary of the narrowed band on the matcher route: 101 fails, exactly 100 passes.
    let (ctx101, d101) = env.init_matcher(&lp, la, 101);
    let r = env.trade_cpi(&taker, ta, la, ctx101, d101, 0, UNIT);
    assert_err(r, ERR_BAND, "101 bps under a 100 bps band");
    let (ctx100, d100) = env.init_matcher(&lp, la, 100);
    env.trade_cpi(&taker, ta, la, ctx100, d100, 0, UNIT)
        .expect("exactly 100 bps under a 100 bps band passes");
    assert_eq!(env.position(ta, 0), 3 * UNIT);
}

/// Scoping pin (spec 4fe62cda): the band does NOT apply to the bilateral routes. Both owners
/// sign the price and the fill settles at the mark, so TradeNoCpi at +6% and a BatchTradeNoCpi
/// with one leg at +6% SUCCEED -- even under a 100 bps protocol band set via tag 93.
#[test]
fn p1_band_does_not_apply_to_nocpi_routes() {
    let mut env = Env::new(2);
    let (a_owner, b_owner) = (Keypair::new(), Keypair::new());
    let a = env.funded_portfolio(&a_owner);
    let b = env.funded_portfolio(&b_owner);
    let eff = env.effective_price(0);
    let ua = env.upgrade_authority.insecure_clone();
    env.set_asset_risk_limits(&ua, 0, 100).expect("narrow asset 0 band");
    env.set_asset_risk_limits(&ua, 1, 100).expect("narrow asset 1 band");

    env.trade_nocpi(&a_owner, a, &b_owner, b, 0, UNIT, price_at_bps(eff, 600))
        .expect("TradeNoCpi at +600 bps is not banded");
    assert_eq!(env.position(a, 0), UNIT);
    assert_eq!(env.position(b, 0), -UNIT);

    let e1 = env.effective_price(1);
    env.batch_nocpi(
        &a_owner,
        a,
        &b_owner,
        b,
        &[(0, UNIT, price_at_bps(eff, 100)), (1, UNIT, price_at_bps(e1, 600))],
    )
    .expect("BatchTradeNoCpi with a leg at +600 bps is not banded");
    assert_eq!(env.position(a, 0), 2 * UNIT);
    assert_eq!(env.position(a, 1), UNIT);
    assert_eq!(env.position(b, 1), -UNIT);
}

// ─────────────────────── item 2: same owner (matcher-routed routes only) ───────────────────────

/// TradeCpi where the taker owns the LP portfolio -> Custom(67) (market, both portfolios and
/// matcher ctx untouched); BatchTradeCpi likewise; a distinct taker fills against the same LP.
#[test]
fn p1_same_owner_cpi_taker_is_lp_owner_rejected() {
    let mut env = Env::new(1);
    let lp = Keypair::new();
    let la = env.funded_portfolio(&lp);
    let own_taker_account = env.funded_portfolio(&lp);
    let (ctx, delegate) = env.init_matcher(&lp, la, 0);

    let keys = [env.market, own_taker_account, la, ctx];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&lp, own_taker_account, la, ctx, delegate, 0, UNIT);
    assert_err(r, ERR_SAME_OWNER, "TradeCpi taker == LP owner");
    assert_eq!(env.snapshot(&keys), before);
    let r = env.batch_cpi(&lp, own_taker_account, la, ctx, delegate, &[(0, UNIT)]);
    assert_err(r, ERR_SAME_OWNER, "BatchTradeCpi taker == LP owner");
    assert_eq!(env.snapshot(&keys), before);

    let taker = Keypair::new();
    let ta = env.funded_portfolio(&taker);
    env.trade_cpi(&taker, ta, la, ctx, delegate, 0, UNIT)
        .expect("distinct taker fills");
    assert_eq!(env.position(ta, 0), UNIT);
    assert_eq!(env.position(la, 0), -UNIT);
}

/// TradeCpi / BatchTradeCpi where the taker is asset 0's `asset_admin` (the market creator =
/// InitMarket signer) trading against someone else's LP -> Custom(67); a non-admin taker fills.
#[test]
fn p1_same_owner_cpi_taker_is_asset_admin_rejected() {
    let mut env = Env::new(1);
    let admin = env.admin.insecure_clone();
    let profile =
        state::read_asset_oracle_profile(&env.svm.get_account(&env.market).unwrap().data, 0)
            .unwrap();
    assert_eq!(profile.asset_admin, admin.pubkey().to_bytes(), "fixture: admin is asset_admin");

    let lp = Keypair::new();
    let la = env.funded_portfolio(&lp);
    let admin_account = env.funded_portfolio(&admin);
    let (ctx, delegate) = env.init_matcher(&lp, la, 0);

    let keys = [env.market, admin_account, la, ctx];
    let before = env.snapshot(&keys);
    let r = env.trade_cpi(&admin, admin_account, la, ctx, delegate, 0, UNIT);
    assert_err(r, ERR_SAME_OWNER, "TradeCpi taker == asset_admin");
    assert_eq!(env.snapshot(&keys), before);
    let r = env.batch_cpi(&admin, admin_account, la, ctx, delegate, &[(0, UNIT)]);
    assert_err(r, ERR_SAME_OWNER, "BatchTradeCpi taker == asset_admin");
    assert_eq!(env.snapshot(&keys), before);

    let taker = Keypair::new();
    let ta = env.funded_portfolio(&taker);
    env.trade_cpi(&taker, ta, la, ctx, delegate, 0, UNIT)
        .expect("non-admin taker fills");
    assert_eq!(env.position(ta, 0), UNIT);
    assert_eq!(env.position(la, 0), -UNIT);
}

/// Scoping pin (spec 4fe62cda): same-owner is NOT refused on the bilateral routes -- the owner
/// signs both sides. TradeNoCpi and BatchTradeNoCpi between two portfolios of one owner fill.
#[test]
fn p1_same_owner_allowed_on_nocpi_routes() {
    let mut env = Env::new(1);
    let owner = Keypair::new();
    let p1 = env.funded_portfolio(&owner);
    let p2 = env.funded_portfolio(&owner);
    env.trade_nocpi(&owner, p1, &owner, p2, 0, UNIT, PRICE)
        .expect("TradeNoCpi same owner is allowed");
    assert_eq!(env.position(p1, 0), UNIT);
    assert_eq!(env.position(p2, 0), -UNIT);
    env.batch_nocpi(&owner, p1, &owner, p2, &[(0, UNIT, PRICE)])
        .expect("BatchTradeNoCpi same owner is allowed");
    assert_eq!(env.position(p1, 0), 2 * UNIT);
    assert_eq!(env.position(p2, 0), -2 * UNIT);
}
