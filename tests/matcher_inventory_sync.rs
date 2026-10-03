// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Matcher-inventory-sync (2026-10-03), end to end through the REAL wrapper BPF
//! (`target/deploy/percolator_prog.so`, `cargo build-sbf --features devnet`) and the REAL
//! matcher BPF, deployed at the canonical devnet matcher id `EDKKgRaV…`.
//!
//! The bug (devnet wrapper ETDLAdi @ 553d76f0 + matcher EDKKgRaV @ 4a0f696): the matcher caps
//! fills with its own `inventory_base` counter, which only matcher fills move. Every
//! out-of-matcher change of the LP's engine position -- a liquidation or RebalanceReduce on the
//! OPPOSITE side (ADL-scales the LP), a side reset, the LP's own liquidation -- leaves it stale.
//! On 2026-10-03, 11 of 44 bound contexts had drifted: closes blocked by phantom caps, whole
//! sides unable to open, and the other direction admitting fills past the LP's configured cap
//! (upstream percolator-prog#406).
//!
//! The fix: the wrapper sends the canonical matcher a 40-byte `ext_version = 2` call extension
//! carrying the LP's real ADL-effective position; the matcher prices and caps against it.
//!
//! Binaries (override with env):
//!   wrapper   `P1_WRAPPER_SO`  (default target/deploy/percolator_prog.so)
//!   matcher   `SYNC_MATCHER_SO` (default ../percolator-match/target/deploy/percolator_match.so)
//! Negative controls: run the same tests with `P1_WRAPPER_SO` = the deployed 553d76f0 build
//! (the drift tests then fail exactly where the bug is), and with `SYNC_MATCHER_SO` = the
//! deployed 4a0f696 matcher (every canonical TradeCpi then fails: deploy order is matcher
//! FIRST).
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{ix::Instruction as ProgInstruction, state};
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
const Q: i128 = POS_SCALE as i128;
const PRICE: u64 = 1_000_000;
const BASE_BPS: u64 = 10;
/// The LP's configured matcher inventory cap.
const CAP: i128 = 40 * Q;
const DEPOSIT: u128 = 1_000_000_000_000;
const CANONICAL_MATCHER: Pubkey =
    solana_sdk::pubkey!("EDKKgRaVHna6FCxiY1kgMzegD9rpaN1nwJNSzAzeBUBX");

fn wrapper_path() -> PathBuf {
    if let Some(p) = std::env::var_os("P1_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(
        p.exists(),
        "wrapper BPF not found at {p:?}; cargo build-sbf --features devnet"
    );
    p
}

fn matcher_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SYNC_MATCHER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-match/target/deploy/percolator_match.so");
    assert!(p.exists(), "matcher BPF not found at {p:?}");
    p
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
        let candidate = registry
            .expect("registry entry")
            .path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
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

fn matcher_delegate_key(
    program_id: &Pubkey,
    market: &Pubkey,
    lp: &Pubkey,
    lp_owner: &Pubkey,
    matcher_program: &Pubkey,
    matcher_ctx: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"matcher",
            market.as_ref(),
            lp.as_ref(),
            lp_owner.as_ref(),
            matcher_program.as_ref(),
            matcher_ctx.as_ref(),
        ],
        program_id,
    )
    .0
}

struct Lp {
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
}

impl Env {
    fn new(matcher_program: Pubkey, matcher_so: PathBuf) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(
            program_id,
            &std::fs::read(wrapper_path()).expect("wrapper BPF"),
        );
        svm.add_program(
            spl_token::ID,
            &std::fs::read(spl_token_program_path()).expect("token BPF"),
        );
        svm.add_program(
            matcher_program,
            &std::fs::read(&matcher_so).expect("matcher BPF"),
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
            portfolio_account_len: state::portfolio_account_len_for_market_slots(1).unwrap(),
        };
        env.send(
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
                trade_fee_base_bps: BASE_BPS,
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
            .map(|m| m.compute_units_consumed)
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

    /// Passive (kind 0) LP with a FINITE matcher inventory cap `cap`.
    fn lp(&mut self, cap: i128) -> Lp {
        let owner = Keypair::new();
        let account = self.portfolio(&owner, DEPOSIT);
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
                kind: 0,
                trading_fee_bps: 0,
                base_spread_bps: 10,
                max_total_bps: 100,
                impact_k_bps: 0,
                liquidity_notional_e6: 0,
                max_fill_abs: u128::MAX >> 1,
                max_inventory_abs: cap as u128,
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

    fn trader(&mut self) -> (Keypair, Pubkey) {
        let k = Keypair::new();
        let p = self.portfolio(&k, DEPOSIT);
        (k, p)
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
                fee_bps: BASE_BPS,
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

    /// Tag 44: the owner's unilateral exit. Closes `reduce_q` of the leg WITHOUT the matcher;
    /// the engine ADL-scales the opposite side (the LP among it) to keep OI balanced.
    fn rebalance_reduce(
        &mut self,
        owner: &Keypair,
        portfolio: Pubkey,
        reduce_q: u128,
    ) -> Result<u64, String> {
        let (pid, _, pep) = self.identity(portfolio);
        let m = self.market;
        self.send(
            ProgInstruction::RebalanceReduce {
                portfolio_id: pid,
                position_epoch: pep,
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
        let slot = self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
        let (payer, m) = (self.payer.pubkey(), self.market);
        self.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: slot,
                observations: vec![percolator_prog::ix::CrankObservationHint {
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

    fn finalize_resets(&mut self) {
        let m = self.market;
        for side in 0..2u8 {
            let _ = self.send(
                ProgInstruction::FinalizeResetSide {
                    asset_index: 0,
                    side,
                },
                vec![AccountMeta::new(m, false)],
                &[],
            );
        }
    }

    /// The portfolio's engine-EFFECTIVE signed position (what the engine trades against).
    fn eff(&self, portfolio: Pubkey) -> i128 {
        let mut md = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut md).unwrap();
        let a = group.markets[0].engine.asset.try_to_runtime().unwrap();
        let p = state::read_portfolio(&self.svm.get_account(&portfolio).unwrap().data).unwrap();
        let Some(l) = p.legs.iter().find(|l| l.active && l.asset_index == 0) else {
            return 0;
        };
        let (ca, ep, mode) = match l.side {
            SideV16::Long => (a.a_long, a.epoch_long, a.mode_long),
            SideV16::Short => (a.a_short, a.epoch_short, a.mode_short),
        };
        let abs = if l.epoch_snap == ep {
            (l.basis_pos_q.unsigned_abs() * ca).div_ceil(l.a_basis)
        } else {
            assert_eq!(mode, percolator::SideModeV16::ResetPending);
            0
        } as i128;
        match l.side {
            SideV16::Long => abs,
            SideV16::Short => -abs,
        }
    }

    fn adl_one(&self) -> bool {
        let mut md = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut md).unwrap();
        let a = group.markets[0].engine.asset.try_to_runtime().unwrap();
        a.a_long == percolator::ADL_ONE && a.a_short == percolator::ADL_ONE
    }

    fn counter(&self, lp: &Lp) -> i128 {
        let d = self.svm.get_account(&lp.ctx).unwrap().data;
        // 64-byte return slot + MatcherCtx.inventory_base at +96
        i128::from_le_bytes(d[64 + 96..64 + 112].try_into().unwrap())
    }

    fn last_exec(&self, lp: &Lp) -> i128 {
        let d = self.svm.get_account(&lp.ctx).unwrap().data;
        i128::from_le_bytes(d[16..32].try_into().unwrap())
    }
}

fn canonical_env() -> Env {
    Env::new(CANONICAL_MATCHER, matcher_path())
}

/// The LP's side fully drains through tag 44 (no matcher): the engine resets that side, the LP
/// is flat, A is back to ADL_ONE on both sides (normal trading), and the counter keeps -CAP.
/// (2i51AtKP / 6Y4bfYLW / CeRP5hdD / Ev5DZC5F / Gprscv7A shape.)
fn drifted_flat_lp() -> (Env, Lp) {
    let mut env = canonical_env();
    let lp = env.lp(CAP);
    let long = env.trader();
    env.trade_cpi(&long.0, long.1, &lp, CAP)
        .expect("long opens to the cap");
    assert_eq!(env.counter(&lp), -CAP);
    env.rebalance_reduce(&long.0, long.1, CAP as u128)
        .expect("tag 44 full exit");
    let _ = env.crank(lp.account);
    env.finalize_resets();
    let _ = env.crank(lp.account);
    assert_eq!(env.eff(lp.account), 0, "LP flat after the side reset");
    assert!(env.adl_one(), "both sides back to ADL_ONE: normal trading");
    assert_eq!(
        env.counter(&lp),
        -CAP,
        "counter still -cap: phantom inventory"
    );
    (env, lp)
}

/// After the drift, a seller opens short CAP/2 and a buyer opens long CAP/2 (LP flat again; on
/// the stale counter the LP now looks pinned at -CAP). The seller then closes: taker BUYS, LP
/// sells to -CAP/2, well inside the cap. The stale counter zero-fills that close.
fn drifted_with_open_short() -> (Env, Lp, (Keypair, Pubkey)) {
    let (mut env, lp) = drifted_flat_lp();
    let short = env.trader();
    let long = env.trader();
    env.trade_cpi(&short.0, short.1, &lp, -CAP / 2)
        .expect("short opens");
    env.trade_cpi(&long.0, long.1, &lp, CAP / 2)
        .expect("long opens");
    assert_eq!(env.eff(short.1), -CAP / 2);
    assert_eq!(env.eff(lp.account), 0);
    (env, lp, short)
}

/// The close that the stale counter blocks: a short trader buying back while the real LP has
/// all its room. (Base 553d76f0 + 4a0f696: zero fill, the trader stays short.)
#[test]
fn sync_short_trader_can_close_after_drift() {
    let (mut env, lp, short) = drifted_with_open_short();
    let r = env.trade_cpi(&short.0, short.1, &lp, CAP / 2);
    assert!(r.is_ok(), "close tx: {r:?}");
    assert_eq!(
        env.eff(short.1),
        0,
        "short fully closed (stale counter zero-fills it: last exec {})",
        env.last_exec(&lp)
    );
    assert_eq!(env.eff(lp.account), -CAP / 2);
    assert_eq!(
        env.counter(&lp),
        env.eff(lp.account),
        "counter re-synchronised by the fill"
    );
}

/// Gprscv7A / percolator-prog#406: with the LP flat and the counter at -cap, stale: nobody can
/// buy (LP sells) and a sell admits 2x cap. Real: both directions get exactly the cap.
#[test]
fn sync_side_reset_restores_both_directions_and_closes_the_cap_bypass() {
    let (mut env, lp) = drifted_flat_lp();
    let seller = env.trader();
    env.trade_cpi(&seller.0, seller.1, &lp, -2 * CAP)
        .expect("sell tx");
    assert_eq!(
        env.eff(lp.account),
        CAP,
        "LP stops at its configured cap (stale counter would let it reach 2x cap)"
    );
    assert_eq!(env.counter(&lp), CAP, "counter == real after the fill");
    let buyer = env.trader();
    env.trade_cpi(&buyer.0, buyer.1, &lp, 2 * CAP)
        .expect("buy tx");
    assert_eq!(
        env.eff(lp.account),
        -CAP,
        "the buy side is open again, up to the cap"
    );
    assert_eq!(env.counter(&lp), env.eff(lp.account));
}

/// The deliberate-grief loop (open via TradeCpi, exit via tag 44, repeat) cannot pin a synced
/// matcher: afterwards a fresh buyer still gets the full cap.
#[test]
fn sync_grief_loop_cannot_pin_the_matcher() {
    let mut env = canonical_env();
    let lp = env.lp(CAP);
    let griefer = env.trader();
    for _ in 0..3 {
        env.trade_cpi(&griefer.0, griefer.1, &lp, CAP)
            .expect("open");
        env.rebalance_reduce(&griefer.0, griefer.1, CAP as u128)
            .expect("exit via 44");
        let _ = env.crank(lp.account);
        env.finalize_resets();
        let _ = env.crank(lp.account);
    }
    let victim = env.trader();
    env.trade_cpi(&victim.0, victim.1, &lp, CAP)
        .expect("victim buy");
    assert_eq!(env.eff(victim.1), CAP, "victim gets the full cap");
}

/// BatchTradeCpi sends the 40-byte v2 block per leg (18 + 26n + 40n wire) and the matcher
/// prices it from the real position. (Same-asset multi-leg carry is covered natively in
/// percolator-match tests/inventory_sync.rs; a 1-asset market's batch executor refuses two legs
/// on one asset with InvalidInstruction on base and fix alike.)
#[test]
fn sync_batch_close_uses_real_position() {
    let (mut env, lp, short) = drifted_with_open_short();
    let r = env.batch_cpi(&short.0, short.1, &lp, &[CAP / 2]);
    assert!(r.is_ok(), "batch close: {r:?}");
    assert_eq!(env.eff(short.1), 0);
    assert_eq!(env.eff(lp.account), -CAP / 2);
    assert_eq!(env.counter(&lp), env.eff(lp.account));
}

/// 4EGvEGdL / 9EPm8nB8 shape: a long exits HALF via tag 44, the engine ADL-scales the short side
/// (LP + a short trader), the counter overstates the LP. A is not ADL_ONE, so the engine refuses
/// every LP-growing fill (21) whatever the matcher says; a REDUCING fill re-synchronises the
/// counter to the real effective position.
#[test]
fn sync_adl_partial_drift_heals_on_the_next_reducing_fill() {
    let mut env = canonical_env();
    let lp = env.lp(CAP);
    let short = env.trader();
    let long = env.trader();
    let s = CAP / 4;
    env.trade_cpi(&short.0, short.1, &lp, -s)
        .expect("short opens");
    env.trade_cpi(&long.0, long.1, &lp, CAP + s)
        .expect("long opens");
    env.rebalance_reduce(&long.0, long.1, (CAP / 2) as u128)
        .expect("tag 44 half exit");
    let lp_real = env.eff(lp.account);
    assert!(
        lp_real > -CAP && lp_real < 0,
        "ADL shrank the LP: {lp_real}"
    );
    assert_eq!(env.counter(&lp), -CAP, "counter did not move");
    assert!(!env.adl_one());
    // engine reduce-only: the short's close grows the LP -> LockActive regardless of matcher
    let close = env.eff(short.1);
    let r = env.trade_cpi(&short.0, short.1, &lp, -close);
    assert!(
        r.unwrap_err().contains("Custom(21)"),
        "engine ADL reduce-only refuses LP growth"
    );
    // the long sells a little (LP buys = reduces): fills, and the counter is now the real LP
    env.trade_cpi(&long.0, long.1, &lp, -Q)
        .expect("reducing fill");
    assert_eq!(env.counter(&lp), env.eff(lp.account), "counter healed");
}

/// No drift => the v2 call is behaviour-identical: same fills, same counter.
#[test]
fn sync_no_drift_is_unchanged() {
    let mut env = canonical_env();
    let lp = env.lp(CAP);
    let t = env.trader();
    env.trade_cpi(&t.0, t.1, &lp, CAP / 2).unwrap();
    env.trade_cpi(&t.0, t.1, &lp, CAP).unwrap(); // clipped at the cap
    assert_eq!(env.eff(lp.account), -CAP);
    assert_eq!(env.counter(&lp), -CAP);
    env.trade_cpi(&t.0, t.1, &lp, -CAP).unwrap();
    assert_eq!(env.eff(lp.account), 0);
    assert_eq!(env.counter(&lp), 0);
}

/// A matcher that is NOT the canonical program keeps receiving the 24-byte (67-byte call)
/// legacy wire -- the fixed wrapper still trades against it, stale counter and all.
#[test]
fn non_canonical_matcher_gets_the_legacy_wire() {
    let mut env = Env::new(Pubkey::new_unique(), matcher_path());
    let lp = env.lp(CAP);
    let t = env.trader();
    env.trade_cpi(&t.0, t.1, &lp, CAP / 2)
        .expect("legacy wire trades");
    assert_eq!(env.eff(lp.account), -CAP / 2);
    assert_eq!(env.counter(&lp), -CAP / 2);
}

/// `adl_effective_abs_q` against the engine's `kernel_adl_effective_quantity_ceil` contract on
/// the boundaries: exact ceiling, never above the basis, no overflow at the extremes, and the
/// engine's InvalidLeg refusals. (A Kani proof of the ceiling over symbolic u128 A values did not
/// finish in 28 min -- nonlinear 128-bit mul/div -- and was withdrawn; the e2e tests above also
/// check the wrapper's value against the engine's own effective position after real ADL.)
#[test]
fn adl_effective_abs_q_matches_engine_contract() {
    use percolator::{ADL_ONE, MAX_POSITION_ABS_Q, MIN_A_SIDE};
    use percolator_prog::risk_limits_v17::adl_effective_abs_q as eff;
    let raws = [
        0u128,
        1,
        2,
        999_999,
        Q as u128,
        123_456_789_012,
        MAX_POSITION_ABS_Q - 1,
        MAX_POSITION_ABS_Q,
    ];
    let bases = [
        MIN_A_SIDE,
        MIN_A_SIDE + 1,
        333_333_333_333_333,
        ADL_ONE - 1,
        ADL_ONE,
    ];
    for &raw in &raws {
        for &a in &bases {
            for c in [1u128, 2, a / 3, a / 2, a - 1, a] {
                if c == 0 {
                    continue;
                }
                let e = eff(raw, a, c).expect("in range");
                let num = raw * c; // <= 1e29, exact
                assert!(
                    e * a >= num && (e == 0 || (e - 1) * a < num),
                    "ceil raw {raw} a {a} c {c}"
                );
                assert!(e <= raw);
                if c == a {
                    assert_eq!(e, raw, "unit ratio keeps the basis");
                }
            }
        }
    }
    assert_eq!(eff(MAX_POSITION_ABS_Q + 1, ADL_ONE, 1), None);
    assert_eq!(eff(1, MIN_A_SIDE - 1, 1), None);
    assert_eq!(eff(1, ADL_ONE + 1, 1), None);
    assert_eq!(eff(1, ADL_ONE, 0), None);
    assert_eq!(
        eff(1, MIN_A_SIDE, MIN_A_SIDE + 1),
        None,
        "current_a above a_basis"
    );
}

// ---- Security review (percolator-security, 2026-10-03) engine-anchored checks ----
fn sec_oi(env: &Env) -> (u128, u128, u128, u128) {
    let mut md = env.svm.get_account(&env.market).unwrap().data;
    let (_, group) = state::market_view_mut(&mut md).unwrap();
    let a = group.markets[0].engine.asset.try_to_runtime().unwrap();
    (a.oi_eff_long_q, a.oi_eff_short_q, a.a_long, a.a_short)
}

/// Anchor the v2 value to the ENGINE's own OI, not the test's re-implemented formula. The LP is
/// the only short; after an uneven tag-44 ADL the LP's real position == engine oi_eff_short.
/// A reducing fill of size Q then must leave counter == -(oi_eff_short after).
#[test]
fn sec_v2_value_matches_engine_oi_after_adl() {
    for frac in [3i128, 7, 13] {
        let mut env = canonical_env();
        let lp = env.lp(CAP);
        let long = env.trader();
        env.trade_cpi(&long.0, long.1, &lp, CAP).expect("long opens");
        env.rebalance_reduce(&long.0, long.1, (CAP / frac + 12_345) as u128)
            .expect("tag 44 partial");
        let (ol, os, al, ash) = sec_oi(&env);
        eprintln!("frac {frac}: oi_long {ol} oi_short {os} a_long {al} a_short {ash} eff_lp {} counter {}", env.eff(lp.account), env.counter(&lp));
        assert!(ash < percolator::ADL_ONE, "short side ADL'd");
        env.trade_cpi(&long.0, long.1, &lp, -Q).expect("reducing fill");
        let (_, os2, _, _) = sec_oi(&env);
        eprintln!("  after reduce: oi_short {os2} counter {} eff_lp {}", env.counter(&lp), env.eff(lp.account));
        assert_eq!(env.counter(&lp), -(os2 as i128), "matcher counter == engine OI (LP sole short)");
    }
}

/// ResetPending window (LP leg = prior-reset obligation, before crank/finalize): the wrapper's
/// effective view must take the obligation branch (0), not fail with InvalidLeg. Print the error
/// so the same test can be compared on the deployed wrapper.
#[test]
fn sec_trade_during_reset_pending_window() {
    let mut env = canonical_env();
    let lp = env.lp(CAP);
    let long = env.trader();
    env.trade_cpi(&long.0, long.1, &lp, CAP).expect("long opens");
    env.rebalance_reduce(&long.0, long.1, CAP as u128).expect("tag 44 full exit");
    let (ol, os, al, ash) = sec_oi(&env);
    eprintln!("after full exit: oi {ol}/{os} a {al}/{ash} eff_lp {} counter {}", env.eff(lp.account), env.counter(&lp));
    let t = env.trader();
    let r1 = env.trade_cpi(&t.0, t.1, &lp, Q);
    let r2 = env.trade_cpi(&t.0, t.1, &lp, -Q);
    let short_err = |r: &Result<u64, String>| match r { Ok(_) => "OK".to_string(), Err(e) => e.split("err: ").nth(1).unwrap_or(e).chars().take(60).collect() };
    eprintln!("RESULT buy: {}", short_err(&r1));
    eprintln!("RESULT sell: {}", short_err(&r2));
    eprintln!("counter after {}", env.counter(&lp));
    // While the short side is ResetPending the engine refuses every risk-increasing fill with
    // LockActive (21). The v2 effective view must take the prior-reset-obligation branch (0)
    // and let the engine refuse; an `InvalidLeg` from the wrapper would brick the market.
    for (dir, r) in [("buy", &r1), ("sell", &r2)] {
        let e = r.as_ref().expect_err("a fill during ResetPending must be refused");
        assert!(e.contains("Custom(21)"), "{dir}: expected LockActive (21), got {e}");
    }
}
