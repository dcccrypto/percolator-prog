// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
#![allow(dead_code)]
//! Phase 4 item 3 (v22 Wave C) CAPACITY BONDS — LiteSVM black-box tests (tags 107-110 and the
//! bond-aware 78 / 97 / 102 / 103) against the REAL wrapper BPF. The harness below is copied
//! verbatim from tests/p3_vault_lp.rs (a test binary cannot import another's helpers); only the
//! bond helpers and tests at the end are new. Negative controls: scripts/v22-bond-mutants.sh.
//!
//! (harness header, verbatim:) P3 vault-owned LP — LiteSVM black-box tests against the REAL wrapper BPF
//! (`target/deploy/percolator_prog.so`, built `cargo build-sbf --features devnet`) and the
//! REAL percolator-match BPF (`../percolator-match/target/deploy/percolator_match.so`).
//!
//! Design: `~/percolator-ops/ledger/p3-vault-owned-lp-2026-09-29.md`.
//!
//! Every test drives real instructions. Direct state pokes are used ONLY where no instruction
//! path exists, and each is marked `STATE POKE:` with the reason.

use litesvm::LiteSVM;
use percolator_prog::{
    error::PercolatorError,
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    state::{
        self, derive_lp_backing_ledger, derive_lp_escrow, derive_lp_redemption,
        derive_lp_vault_mint, derive_lp_vault_registry, derive_vault_lp_state,
    },
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

const DOMAIN: u16 = 0; // asset 0, long side
const MATCHER_CONTEXT_LEN: usize = 320;
/// = `constants::CANONICAL_VAULT_LP_MATCHER_PROGRAM` (devnet build; the test crate's lib is not
/// built with `devnet`, so the id is restated and checked against the program by tag 94 itself).
const CANONICAL_MATCHER: Pubkey = percolator_prog::constants::CANONICAL_VAULT_LP_MATCHER_PROGRAM;
// v2.2 combined release: Wave A's 1e7 launch floor binds every growth market, so the fixtures launch
// at $10.00 e6 and one test "unit" is 1/10 token: every notional equals the pre-merge $1 fixtures.
const PRICE: u64 = 10_000_000; // $10.00 e6

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

fn program_path() -> PathBuf {
    // Negative controls: run the same test against another wrapper binary.
    if let Some(p) = std::env::var_os("P1_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing — cargo build-sbf --features devnet");
    p
}

fn matcher_program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("SYNC_MATCHER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-match/target/deploy/percolator_match.so");
    assert!(p.exists(), "matcher BPF missing at {p:?}");
    p
}

fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut h = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            h.push(".cargo");
            h
        });
    for reg in std::fs::read_dir(cargo_home.join("registry/src")).expect("registry/src") {
        let cand = reg
            .expect("entry")
            .path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if cand.exists() {
            return cand;
        }
    }
    panic!("spl_token BPF not found");
}

fn make_mint_data() -> Vec<u8> {
    let mut d = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TokenAccount::LEN];
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
        &mut d,
    )
    .unwrap();
    d
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

// #569 / D22: a vault BOUND as the vault LP must carry a redemption cooldown of at least
// MIN_BOUND_VAULT_REDEMPTION_COOLDOWN_SLOTS (150). Harness change only: vaults are created with it
// and `earn_execute` lets the clock pass the cooldown (it used to run in the request's slot at 0).
const BOUND_COOLDOWN: u64 = percolator_prog::constants::MIN_BOUND_VAULT_REDEMPTION_COOLDOWN_SLOTS;

#[derive(Clone, Copy)]
struct Params {
    mm_bps: u64,
    im_bps: u64,
    move_bps: u64,
    fee_bps: u64,
    /// Configured asset slots (F14-Q2 tests use 2).
    assets: u16,
    /// Maintenance fee per slot (0 = off).
    maint_fee: u128,
    /// growth-v19: engine funding cap (a single-slot growth market needs > 0).
    funding: u64,
    /// growth-v19: `Some((r_gap_bps, l_launch_x100))` => InitMarket carries the growth block.
    growth: Option<(u16, u16)>,
    /// v2.2 W-L1 tests: `Some(d)` => the growth market is a BAND market (InitMarketV22, band
    /// `d` bps, no rent): clamp-enforced, so λ_eff applies.
    band: Option<u16>,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            mm_bps: 1_000,
            im_bps: 1_000,
            move_bps: 500,
            fee_bps: 0,
            assets: 1,
            maint_fee: 0,
            funding: 0,
            growth: None,
            band: None,
        }
    }
}

struct Env {
    svm: LiteSVM,
    pid: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault_token: Pubkey,
    vault_authority: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    escrow: Pubkey,
    ledger: Pubkey,
    sibling: Pubkey,
    vault_lp: Pubkey,
    matcher: Pubkey,
    plen: usize,
    slot: u64,
    paid_in: u128,
    paid_out: u128,
}

#[allow(dead_code)]
struct Lp {
    portfolio: Pubkey,
    owner_key: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

struct Depositor {
    kp: Keypair,
    source: Pubkey,
    lp_ata: Pubkey,
    dest: Pubkey,
    redemption: Pubkey,
}

struct Trader {
    kp: Keypair,
    portfolio: Pubkey,
}

impl Env {
    fn new(p: Params) -> Env {
        Self::new_with_matcher(p, matcher_program_path())
    }

    fn new_with_matcher(p: Params, matcher_so: PathBuf) -> Env {
        let mut svm = LiteSVM::new();
        let pid = percolator_prog::id();
        svm.add_program(pid, &std::fs::read(program_path()).unwrap());
        svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).unwrap());
        // P3 auto-pin: tag 94 accepts only the protocol's canonical matcher program id.
        let matcher = CANONICAL_MATCHER;
        svm.add_program(matcher, &std::fs::read(&matcher_so).unwrap());
        let payer = Keypair::new();
        let admin = Keypair::new();
        let market_kp = Keypair::new(); // D26: InitMarket requires the market account's signature
        let market = market_kp.pubkey();
        let mint = Pubkey::new_unique();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: make_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; state::market_account_len_for_capacity(p.assets as usize).unwrap()],
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let vault_authority = Pubkey::find_program_address(&[b"vault", market.as_ref()], &pid).0;
        let vault_token = canonical_vault_ata(&vault_authority, &mint);
        svm.set_account(
            vault_token,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, vault_authority, 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let (registry, _) = derive_lp_vault_registry(&pid, &market);
        let (lp_mint, _) = derive_lp_vault_mint(&pid, &market);
        let (escrow, _) = derive_lp_escrow(&pid, &market);
        let (ledger, _) = derive_lp_backing_ledger(&pid, &market, DOMAIN);
        let (sibling, _) = derive_lp_backing_ledger(&pid, &market, DOMAIN ^ 1);
        let (vault_lp, _) = derive_vault_lp_state(&pid, &market);
        let mut env = Env {
            svm,
            pid,
            payer,
            admin,
            market,
            mint,
            vault_token,
            vault_authority,
            registry,
            lp_mint,
            escrow,
            ledger,
            sibling,
            vault_lp,
            matcher,
            plen: state::portfolio_account_len_for_market_slots(p.assets as usize).unwrap(),
            slot: 1,
            paid_in: 0,
            paid_out: 0,
        };
        env.svm.warp_to_slot(1);
        let admin = env.admin.insecure_clone();
        let init = ProgInstruction::InitMarket {
                max_portfolio_assets: p.assets,
                h_min: 0,
                h_max: 10,
                initial_price: PRICE,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps: p.mm_bps,
                initial_margin_bps: p.im_bps,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps: p.fee_bps,
                liquidation_fee_bps: 0,
                liquidation_fee_cap: 0,
                min_liquidation_abs: 0,
                max_price_move_bps_per_slot: p.move_bps,
                max_accrual_dt_slots: 1,
                max_abs_funding_e9_per_slot: p.funding,
                min_funding_lifetime_slots: 1,
                max_account_b_settlement_chunks: 1,
                max_bankrupt_close_chunks: 1,
                max_bankrupt_close_lifetime_slots: 100,
                public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
                maintenance_fee_per_slot: p.maint_fee,
            };
        let init = match (p.growth, p.band) {
            (None, _) => init,
            (Some((r, l)), None) => ProgInstruction::InitMarketV19 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
            },
            (Some((r, l)), Some(d)) => ProgInstruction::InitMarketV22 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
                lot_exp: 0,
                phase4: percolator_prog::ix::InitMarketPhase4 {
                    rent_max_e9_per_slot: 0,
                    rent_kink_bps: 0,
                    band_bps: d,
                    band_max_epoch_slots: 600,
                    band_max_pin_slots: 9_000,
                    band_min_leg_notional: 10_000_000,
                },
            },
        };
        env.send(
            init,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, true),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin, &market_kp],
        )
        .expect("init market");
        let seq = env.oracle_seq() + 1;
        env.send(
            ProgInstruction::ConfigureAuthMark {
                market_id: 1,
                asset_index: 0,
                now_slot: 1,
                initial_mark_e6: PRICE,
                observation_sequence: seq,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
            ],
            &[&admin],
        )
        .expect("configure auth mark");
        env.send(
            ProgInstruction::CreateLpVault {
                fee_share_bps: 5_000,
                redemption_cooldown_slots: BOUND_COOLDOWN,
                oi_reservation_threshold_bps: 0,
                domain: DOMAIN,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new(lp_mint, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(env.mint, false), // [6] collateral mint (prog#542)
            ],
            &[&admin],
        )
        .expect("create lp vault");
        env
    }

    /// N-2 test helper: the harness constructor WITHOUT tag 74 CreateLpVault (so a launch can
    /// create the LP vault, bind it and create the bond tranche in ONE transaction).
    fn new_bare(p: Params, matcher_so: PathBuf) -> Env {
        let mut svm = LiteSVM::new();
        let pid = percolator_prog::id();
        svm.add_program(pid, &std::fs::read(program_path()).unwrap());
        svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).unwrap());
        // P3 auto-pin: tag 94 accepts only the protocol's canonical matcher program id.
        let matcher = CANONICAL_MATCHER;
        svm.add_program(matcher, &std::fs::read(&matcher_so).unwrap());
        let payer = Keypair::new();
        let admin = Keypair::new();
        let market_kp = Keypair::new(); // D26: InitMarket requires the market account's signature
        let market = market_kp.pubkey();
        let mint = Pubkey::new_unique();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: make_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; state::market_account_len_for_capacity(p.assets as usize).unwrap()],
                owner: pid,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let vault_authority = Pubkey::find_program_address(&[b"vault", market.as_ref()], &pid).0;
        let vault_token = canonical_vault_ata(&vault_authority, &mint);
        svm.set_account(
            vault_token,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, vault_authority, 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let (registry, _) = derive_lp_vault_registry(&pid, &market);
        let (lp_mint, _) = derive_lp_vault_mint(&pid, &market);
        let (escrow, _) = derive_lp_escrow(&pid, &market);
        let (ledger, _) = derive_lp_backing_ledger(&pid, &market, DOMAIN);
        let (sibling, _) = derive_lp_backing_ledger(&pid, &market, DOMAIN ^ 1);
        let (vault_lp, _) = derive_vault_lp_state(&pid, &market);
        let mut env = Env {
            svm,
            pid,
            payer,
            admin,
            market,
            mint,
            vault_token,
            vault_authority,
            registry,
            lp_mint,
            escrow,
            ledger,
            sibling,
            vault_lp,
            matcher,
            plen: state::portfolio_account_len_for_market_slots(p.assets as usize).unwrap(),
            slot: 1,
            paid_in: 0,
            paid_out: 0,
        };
        env.svm.warp_to_slot(1);
        let admin = env.admin.insecure_clone();
        let init = ProgInstruction::InitMarket {
                max_portfolio_assets: p.assets,
                h_min: 0,
                h_max: 10,
                initial_price: PRICE,
                min_nonzero_mm_req: 1,
                min_nonzero_im_req: 2,
                maintenance_margin_bps: p.mm_bps,
                initial_margin_bps: p.im_bps,
                max_trading_fee_bps: 10_000,
                trade_fee_base_bps: p.fee_bps,
                liquidation_fee_bps: 0,
                liquidation_fee_cap: 0,
                min_liquidation_abs: 0,
                max_price_move_bps_per_slot: p.move_bps,
                max_accrual_dt_slots: 1,
                max_abs_funding_e9_per_slot: p.funding,
                min_funding_lifetime_slots: 1,
                max_account_b_settlement_chunks: 1,
                max_bankrupt_close_chunks: 1,
                max_bankrupt_close_lifetime_slots: 100,
                public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
                maintenance_fee_per_slot: p.maint_fee,
            };
        let init = match (p.growth, p.band) {
            (None, _) => init,
            (Some((r, l)), None) => ProgInstruction::InitMarketV19 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
            },
            (Some((r, l)), Some(d)) => ProgInstruction::InitMarketV22 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
                lot_exp: 0,
                phase4: percolator_prog::ix::InitMarketPhase4 {
                    rent_max_e9_per_slot: 0,
                    rent_kink_bps: 0,
                    band_bps: d,
                    band_max_epoch_slots: 600,
                    band_max_pin_slots: 9_000,
                    band_min_leg_notional: 10_000_000,
                },
            },
        };
        env.send(
            init,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, true),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin, &market_kp],
        )
        .expect("init market");
        let seq = env.oracle_seq() + 1;
        env.send(
            ProgInstruction::ConfigureAuthMark {
                market_id: 1,
                asset_index: 0,
                now_slot: 1,
                initial_mark_e6: PRICE,
                observation_sequence: seq,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
            ],
            &[&admin],
        )
        .expect("configure auth mark");
        env
    }

    fn send(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        extra: &[&Keypair],
    ) -> Result<(), String> {
        self.send_many(vec![(ix, accounts)], extra)
    }

    fn send_many(
        &mut self,
        ixs: Vec<(ProgInstruction, Vec<AccountMeta>)>,
        extra: &[&Keypair],
    ) -> Result<(), String> {
        let mut instructions = vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ];
        for (ix, accounts) in ixs {
            instructions.push(Instruction {
                program_id: self.pid,
                accounts,
                data: ix.encode(),
            });
        }
        let mut signers = vec![&self.payer];
        signers.extend_from_slice(extra);
        self.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.payer.pubkey()),
            &signers,
            self.svm.latest_blockhash(),
        );
        let __d = instructions.last().map(|i| i.data.clone()).unwrap_or_default();
        self.svm
            .send_transaction(tx)
            .map(|m| { cu_rec(&__d, m.compute_units_consumed); })
            .map_err(|e| format!("{e:?}"))
    }

    fn oracle_seq(&self) -> u64 {
        let data = self.svm.get_account(&self.market).unwrap().data;
        state::read_asset_control_sequences(&data, 0)
            .unwrap()
            .oracle_observation
    }

    fn tok(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }

    fn token_account(&mut self, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
        let key = Pubkey::new_unique();
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        key
    }

    fn market_state(&self) -> (state::WrapperConfigV16, state::MarketGroupV16) {
        state::read_market(&self.svm.get_account(&self.market).unwrap().data).unwrap()
    }

    fn portfolio(&self, key: Pubkey) -> state::PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&key).unwrap().data).unwrap()
    }

    fn registry_state(&self) -> state::LpVaultRegistryV16 {
        state::read_lp_vault_registry(&self.svm.get_account(&self.registry).unwrap().data).unwrap()
    }

    fn vlp(&self) -> state::VaultLpStateV18 {
        state::read_vault_lp_state(&self.svm.get_account(&self.vault_lp).unwrap().data).unwrap()
    }

    fn asset_rec(&self) -> state::AssetVaultLpV18 {
        state::read_asset_vault_lp(&self.svm.get_account(&self.market).unwrap().data, 0).unwrap()
    }

    /// Conservation: SPL vault balance == engine header.vault, and all SPL that ever entered
    /// the vault minus all SPL that left it equals what remains.
    fn assert_conserved(&self, what: &str) {
        let (_, g) = self.market_state();
        let spl = self.tok(self.vault_token) as u128;
        assert_eq!(spl, g.vault, "[{what}] SPL vault {spl} != engine header.vault {}", g.vault);
        assert_eq!(
            self.paid_in - self.paid_out,
            spl,
            "[{what}] paid_in {} - paid_out {} != SPL vault {spl}",
            self.paid_in,
            self.paid_out
        );
    }

    fn identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    fn new_program_account(&mut self, len: usize) -> Pubkey {
        self.new_program_account_kp(len).pubkey()
    }

    /// D26: a program-owned account that HOLDS its keypair, for instructions that require the new
    /// account's signature (InitPortfolio).
    fn new_program_account_kp(&mut self, len: usize) -> Keypair {
        let kp = Keypair::new();
        let key = kp.pubkey();
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; len],
                    owner: self.pid,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        kp
    }

    // ── P3 instructions ─────────────────────────────────────────────────────────────────

    fn init_vault_lp_as(&mut self, signer: &Keypair, floor_bps: u16) -> Result<Pubkey, String> {
        let m = self.matcher;
        self.init_vault_lp_full(signer, floor_bps, m, &[]).map(|l| l.portfolio)
    }

    /// Tag 94 with the auto-pin tail: [8] matcher program, [9] a fresh matcher ctx (owned by
    /// the canonical matcher), [10] the delegate PDA; `extra` appended (must be ignored).
    fn init_vault_lp_full(
        &mut self,
        signer: &Keypair,
        floor_bps: u16,
        matcher_prog: Pubkey,
        extra: &[AccountMeta],
    ) -> Result<Lp, String> {
        self.init_vault_lp_full_launch(signer, floor_bps, matcher_prog, extra, None)
    }

    /// Tag 94 with an optional growth-v19 `l_launch_x100` trailer (`InitVaultLpV19`).
    fn init_vault_lp_full_launch(
        &mut self,
        signer: &Keypair,
        floor_bps: u16,
        matcher_prog: Pubkey,
        extra: &[AccountMeta],
        l_launch_x100: Option<u16>,
    ) -> Result<Lp, String> {
        let lp = self.new_program_account(self.plen);
        let ctx = Pubkey::new_unique();
        self.svm
            .set_account(
                ctx,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; MATCHER_CONTEXT_LEN],
                    owner: self.matcher,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let delegate = Pubkey::find_program_address(
            &[
                b"matcher",
                self.market.as_ref(),
                lp.as_ref(),
                self.registry.as_ref(),
                matcher_prog.as_ref(),
                ctx.as_ref(),
            ],
            &self.pid,
        )
        .0;
        let mut accts = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(self.ledger, false),
            AccountMeta::new_readonly(self.sibling, false),
            AccountMeta::new_readonly(matcher_prog, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ];
        accts.extend_from_slice(extra);
        self.svm.expire_blockhash();
        let ix = match l_launch_x100 {
            None => ProgInstruction::InitVaultLp {
                junior_floor_bps: floor_bps,
            },
            Some(l) => ProgInstruction::InitVaultLpV19 {
                junior_floor_bps: floor_bps,
                l_launch_x100: l,
            },
        };
        self.send(ix, accts, &[signer])
        .map(|_| Lp {
            portfolio: lp,
            owner_key: self.registry,
            ctx,
            delegate,
        })
    }

    fn init_vault_lp(&mut self, floor_bps: u16) -> Pubkey {
        let admin = self.admin.insecure_clone();
        self.init_vault_lp_as(&admin, floor_bps).expect("init vault lp")
    }

    fn vault_lp_set_matcher_as(&mut self, signer: &Keypair, lp: Pubkey) -> Result<Lp, String> {
        self.vault_lp_set_matcher_spread_as(signer, lp, 0)
    }

    fn vault_lp_set_matcher_spread_as(
        &mut self,
        signer: &Keypair,
        lp: Pubkey,
        base_spread_bps: u32,
    ) -> Result<Lp, String> {
        let ctx = Pubkey::new_unique();
        let delegate = Pubkey::find_program_address(
            &[
                b"matcher",
                self.market.as_ref(),
                lp.as_ref(),
                self.registry.as_ref(),
                self.matcher.as_ref(),
                ctx.as_ref(),
            ],
            &self.pid,
        )
        .0;
        self.svm
            .set_account(
                ctx,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; MATCHER_CONTEXT_LEN],
                    owner: self.matcher,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
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
        let (_, expected_sequence, _) = self.identity(lp);
        let frontier = state::read_market_asset_generation_frontier(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
        self.send(
            ProgInstruction::VaultLpSetMatcher {
                expected_sequence,
                asset_generation_frontier: frontier,
                trade_fee_cap_bps: 10_000,
                expiry_slot: u64::MAX,
                kind: 0,
                trading_fee_bps: 0,
                base_spread_bps,
                max_total_bps: 100,
                impact_k_bps: 0,
                liquidity_notional_e6: 0,
                max_fill_abs: percolator_prog::vault_lp_v18::ENGINE_MAX_POSITION_ABS_Q,
                max_inventory_abs: percolator_prog::vault_lp_v18::ENGINE_MAX_POSITION_ABS_Q,
                fee_to_insurance_bps: 0,
                skew_spread_mult_bps: 0,
            },
            vec![
                // P3-H2: tag 95 is signed by the upgrade authority (mocked ProgramData = admin).
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(
                        &[self.pid.as_ref()],
                        &solana_sdk::bpf_loader_upgradeable::ID,
                    )
                    .0,
                    false,
                ),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new_readonly(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            &[signer],
        )
        .map(|_| Lp {
            portfolio: lp,
            owner_key: self.registry,
            ctx,
            delegate,
        })
    }

    /// P3-H2: the protocol (upgrade authority, mocked ProgramData = admin) approves this env's
    /// matcher program for asset 0 before tag 95 may point the vault LP at it.
    /// STATE POKE: the ProgramData account (no instruction creates it; same bytes as tag-85 tests).
    fn approve_matcher(&mut self) {
        let (program_data, _) = Pubkey::find_program_address(
            &[self.pid.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::ID,
        );
        let admin = self.admin.insecure_clone();
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(admin.pubkey().as_ref());
        self.svm
            .set_account(
                program_data,
                Account {
                    lamports: 1_000_000_000,
                    data: pd,
                    owner: solana_sdk::bpf_loader_upgradeable::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.svm.expire_blockhash();
        let market = self.market;
        let matcher = self.matcher;
        self.send(
            ProgInstruction::SetVaultLpRisk {
                asset_index: 0,
                skew_slope_e9: 0,
                skew_max_e9: 0,
                lev_cap_q: 0,
                lev_max_imr_bps: 0,
                vault_lp_max_lev_bps: 0,
                approved_matcher_program: matcher.to_bytes(),
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new(market, false),
            ],
            &[&admin],
        )
        .expect("approve matcher (tag 99)");
    }

    /// Bound vault: tag 94 alone binds the vault LP AND pins the canonical matcher + default caps
    /// (auto-pin). The ProgramData mock (authority = admin) is installed for tests that later
    /// exercise the protocol ADJUSTMENT tags 93/99/95.
    fn bind(&mut self, floor_bps: u16) -> Lp {
        let admin = self.admin.insecure_clone();
        let m = self.matcher;
        let lp = self.init_vault_lp_full(&admin, floor_bps, m, &[]).expect("tag 94 bind + auto-pin");
        let a = admin.pubkey();
        self.set_program_data_authority(&a);
        lp
    }

    fn junior_deposit_as(&mut self, signer: &Keypair, lp: Pubkey, amount: u64) -> Result<(), String> {
        let src = self.token_account(self.mint, signer.pubkey(), amount);
        let r = self.send(
            ProgInstruction::DepositJuniorTranche {
                amount: amount as u128,
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
                AccountMeta::new(state::derive_vault_lp_ext(&self.pid, &self.market).0, false),
            ],
            &[signer],
        );
        if r.is_ok() {
            self.paid_in += amount as u128;
        }
        r
    }

    fn junior_withdraw_as(&mut self, signer: &Keypair, lp: Pubkey, amount: u64) -> Result<(), String> {
        let dest = self.token_account(self.mint, signer.pubkey(), 0);
        let r = self.send(
            ProgInstruction::WithdrawJuniorTranche {
                amount: amount as u128,
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(self.ledger, false),
                AccountMeta::new_readonly(self.sibling, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[signer],
        );
        if r.is_ok() {
            assert_eq!(self.tok(dest), amount, "junior withdraw paid the requested amount");
            self.paid_out += amount as u128;
        }
        r
    }

    fn recall(&mut self, lp: Pubkey, amount: u128, domain: u16) -> Result<(), String> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
        self.send(
            ProgInstruction::VaultLpRecall {
                amount,
                target_domain: domain,
            },
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&cranker],
        )
    }

    #[allow(dead_code)]
    fn convert_pnl(&mut self, lp: Pubkey, amount: u128) -> Result<(), String> {
        let payer_key = self.payer.pubkey();
        self.send(
            ProgInstruction::VaultLpConvertPnl { amount },
            vec![
                AccountMeta::new(payer_key, true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.vault_lp, false),
                AccountMeta::new(lp, false),
            ],
            &[],
        )
    }

    // ── Earn (tags 75-78) ───────────────────────────────────────────────────────────────

    fn deposit_accounts(&self, d: &Depositor, tail: Option<Pubkey>) -> Vec<AccountMeta> {
        let mut v = vec![
            AccountMeta::new(d.kp.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(d.lp_ata, false),
            AccountMeta::new(d.source, false),
            AccountMeta::new(self.vault_token, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.sibling, false),
        ];
        if let Some(lp) = tail {
            v.push(AccountMeta::new(self.vault_lp, false));
            v.push(AccountMeta::new_readonly(lp, false));
        }
        v
    }

    fn new_depositor(&mut self) -> Depositor {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
        let source = self.token_account(self.mint, kp.pubkey(), 1_000_000_000_000);
        let lp_ata = self.token_account(self.lp_mint, kp.pubkey(), 0);
        let dest = self.token_account(self.mint, kp.pubkey(), 0);
        let (redemption, _) = derive_lp_redemption(&self.pid, &self.registry, &kp.pubkey());
        Depositor {
            kp,
            source,
            lp_ata,
            dest,
            redemption,
        }
    }

    fn earn_deposit(&mut self, d: &Depositor, amount: u64, tail: Option<Pubkey>) -> Result<(), String> {
        let accts = self.deposit_accounts(d, tail);
        let kp = d.kp.insecure_clone();
        let r = self.send(
            ProgInstruction::DepositToLpVault {
                amount: amount as u128,
                domain: DOMAIN,
            },
            accts,
            &[&kp],
        );
        if r.is_ok() {
            self.paid_in += amount as u128;
        }
        r
    }

    fn earn_request(&mut self, d: &Depositor, shares: u128) {
        let kp = d.kp.insecure_clone();
        self.send(
            ProgInstruction::RequestRedeemLpSharesV22 { shares, min_payout_atoms: 1, keeper_ok: 0 },
            vec![
                AccountMeta::new(d.kp.pubkey(), true),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(d.lp_ata, false),
                AccountMeta::new(self.escrow, false),
                AccountMeta::new(d.redemption, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&kp],
        )
        .expect("request redeem");
    }

    fn earn_execute(&mut self, d: &Depositor, tail: Option<Pubkey>) -> Result<u64, String> {
        // #569 / D22: a bound vault's cooldown is >= 150 slots; let the request mature first.
        self.slot += BOUND_COOLDOWN;
        self.svm.warp_to_slot(self.slot);
        let before = self.tok(d.dest);
        let mut accts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(d.redemption, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(self.escrow, false),
            AccountMeta::new(self.vault_token, false),
            AccountMeta::new_readonly(self.vault_authority, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new(d.dest, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(self.sibling, false),
            AccountMeta::new(d.kp.pubkey(), false),
        ];
        if let Some(lp) = tail {
            accts.push(AccountMeta::new(self.vault_lp, false));
            accts.push(AccountMeta::new_readonly(lp, false));
        }
        self.send(ProgInstruction::ExecuteRedemption { domain: DOMAIN }, accts, &[])?;
        let paid = self.tok(d.dest) - before;
        self.paid_out += paid as u128;
        Ok(paid)
    }

    fn crank_fees(&mut self, bound: bool) -> Result<(), String> {
        let mut accts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new(self.sibling, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        if bound {
            accts.push(AccountMeta::new(self.vault_lp, false));
        }
        self.send(ProgInstruction::LpVaultCrankFees { domain: DOMAIN }, accts, &[])
    }

    fn lp_shares(&self, d: &Depositor) -> u128 {
        self.tok(d.lp_ata) as u128
    }

    // ── traders / price ─────────────────────────────────────────────────────────────────

    fn new_trader(&mut self, capital: u64) -> Trader {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
        let portfolio_kp = self.new_program_account_kp(self.plen);
        let portfolio = portfolio_kp.pubkey();
        self.send(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, true),
            ],
            &[&kp.insecure_clone(), &portfolio_kp],
        )
        .expect("init portfolio");
        let t = Trader { kp, portfolio };
        if capital > 0 {
            self.trader_deposit(&t, capital);
        }
        t
    }

    fn trader_deposit(&mut self, t: &Trader, amount: u64) {
        let src = self.token_account(self.mint, t.kp.pubkey(), amount);
        let (portfolio_id, expected_sequence, _) = self.identity(t.portfolio);
        let kp = t.kp.insecure_clone();
        self.send(
            ProgInstruction::Deposit {
                portfolio_id,
                expected_sequence,
                amount: amount as u128,
            },
            vec![
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&kp],
        )
        .expect("trader deposit");
        self.paid_in += amount as u128;
    }

    fn trade(&mut self, t: &Trader, lp: &Lp, size_q: i128) -> Result<(), String> {
        let (cfg, _) = self.market_state();
        self.trade_signing_fee(t, lp, size_q, cfg.trade_fee_base_bps)
    }

    fn trade_signing_fee(&mut self, t: &Trader, lp: &Lp, size_q: i128, fee_bps: u64) -> Result<(), String> {
        let (a_id, _, a_epoch) = self.identity(t.portfolio);
        let (b_id, b_seq, b_epoch) = self.identity(lp.portfolio);
        let market_id =
            state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, 0)
                .unwrap()
                .3;
        let kp = t.kp.insecure_clone();
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
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
                AccountMeta::new(lp.portfolio, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
            &[&kp],
        )
    }

    /// Push a new auth mark and advance one slot per `move_bps` step until the engine's
    /// effective price reaches it, cranking every listed portfolio at each step.
    fn move_price(&mut self, target: u64, crank: &[Pubkey]) {
        let admin = self.admin.insecure_clone();
        for _ in 0..200 {
            self.slot += 1;
            self.svm.warp_to_slot(self.slot);
            let seq = self.oracle_seq() + 1;
            self.send(
                ProgInstruction::PushAuthMark {
                    market_id: 1,
                    asset_index: 0,
                    now_slot: self.slot,
                    mark_e6: target,
                    observation_sequence: seq,
                },
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(self.market, false),
                ],
                &[&admin],
            )
            .expect("push auth mark");
            for p in crank {
                self.crank(*p).expect("crank");
            }
            let (_, g) = self.market_state();
            if g.assets[0].effective_price == target {
                break;
            }
        }
        let (_, g) = self.market_state();
        assert_eq!(g.assets[0].effective_price, target, "price never reached target");
    }

    fn crank(&mut self, portfolio: Pubkey) -> Result<(), String> {
        let payer_key = self.payer.pubkey();
        self.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: self.slot,
                observations: vec![CrankObservationHint {
                    asset_index: 0,
                    oracle_accounts: 0,
                }],
            },
            vec![
                AccountMeta::new(payer_key, true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[],
        )
    }

    fn position(&self, portfolio: Pubkey) -> i128 {
        let p = self.portfolio(portfolio);
        for leg in p.legs.iter() {
            if leg.active && leg.asset_index == 0 {
                return match leg.side {
                    percolator::SideV16::Long => leg.basis_pos_q.unsigned_abs() as i128,
                    percolator::SideV16::Short => -(leg.basis_pos_q.unsigned_abs() as i128),
                };
            }
        }
        0
    }
}

fn err_has(r: &Result<impl std::fmt::Debug, String>, e: PercolatorError) {
    let c = code(e);
    match r {
        Ok(v) => panic!("expected {c} but the instruction SUCCEEDED ({v:?})"),
        Err(s) => assert!(s.contains(&c), "expected {c} got {s}"),
    }
}

const POS: i128 = percolator::POS_SCALE as i128;

fn poke_senior_claim(env: &mut Env, c: u128) {
    let mut acct = env.svm.get_account(&env.vault_lp).unwrap();
    let mut st = state::read_vault_lp_state(&acct.data).unwrap();
    st.senior_claim_atoms = c;
    state::write_vault_lp_state(&mut acct.data, &st).unwrap();
    env.svm.set_account(env.vault_lp, acct).unwrap();
}

impl Env {
    fn resolve(&mut self) {
        let data = self.svm.get_account(&self.market).unwrap().data;
        let authority_epoch = state::read_asset_control_sequences(&data, 0).unwrap().authority_epoch;
        let frontier = state::read_asset_generation_frontier(&data).unwrap();
        let admin = self.admin.insecure_clone();
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::ResolveMarket {
                asset_generation_frontier: frontier,
                authority_epoch,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("resolve market");
    }

    /// Tag 30 exactly as a stranger would send it against the vault LP, paying into a
    /// collateral account OWNED BY THE REGISTRY PDA (the stranding PoC shape).
    fn close_resolved_into_registry_ata(&mut self, lp: Pubkey) -> (Result<(), String>, Pubkey) {
        let dest = self.token_account(self.mint, self.registry, 0);
        let r = self.send(
            ProgInstruction::CloseResolved {
                fee_rate_per_slot: 0,
            },
            vec![
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(&[b"nft_registry", self.market.as_ref()], &self.pid)
                        .0,
                    false,
                ),
            ],
            &[],
        );
        (r, dest)
    }

    fn settle_resolved(&mut self, caller: &Keypair, lp: Pubkey, topup: u8, junior_dest: Pubkey) -> Result<(), String> {
        self.svm.airdrop(&caller.pubkey(), 10_000_000_000).unwrap();
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::VaultLpSettleResolved { topup },
            vec![
                AccountMeta::new(caller.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new_readonly(self.sibling, false),
                AccountMeta::new(junior_dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&caller.insecure_clone()],
        )
    }

    /// Backing NAV of the vault's two pots as the program computes it (principal - net
    /// impairment + fee-share earnings), read from the ledgers.
    fn backing_nav(&self) -> u128 {
        let mut nav = 0u128;
        for key in [self.ledger, self.sibling] {
            if let Some(a) = self.svm.get_account(&key) {
                if let Ok(l) = state::read_backing_domain_ledger(&a.data) {
                    nav += l.total_principal_atoms
                        - (l.cumulative_loss_atoms - l.cumulative_recovery_atoms);
                }
            }
        }
        nav
    }
}

impl Env {
    fn release_surplus(&mut self, signer: &Keypair, lp: Pubkey, amount: u128, domain: u16) -> Result<(), String> {
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::VaultLpReleaseSurplus {
                amount,
                source_domain: domain,
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(state::derive_vault_lp_ext(&self.pid, &self.market).0, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
            &[&signer.insecure_clone()],
        )
    }
}

impl Env {
    fn trader_close_resolved(&mut self, t: &Trader) -> u64 {
        let dest = self.token_account(self.mint, t.kp.pubkey(), 0);
        self.svm.expire_blockhash();
        let kp = t.kp.insecure_clone();
        self.send(
            ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
            vec![
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(
                    Pubkey::find_program_address(&[b"nft_registry", self.market.as_ref()], &self.pid).0,
                    false,
                ),
            ],
            &[&kp],
        )
        .expect("trader close resolved");
        let got = self.tok(dest);
        self.paid_out += got as u128;
        got
    }

    /// Tag 8 by a STRANGER in Resolved mode, rent to the portfolio's owner (F-4 path).
    fn permissionless_close_portfolio(&mut self, portfolio: Pubkey, owner: Pubkey) -> Result<(), String> {
        let stranger = Keypair::new();
        self.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
        let (pid_, seq, epoch) = self.identity(portfolio);
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::ClosePortfolio {
                portfolio_id: pid_,
                expected_sequence: seq,
                position_epoch: epoch,
            },
            vec![
                AccountMeta::new(stranger.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(owner, false),
            ],
            &[&stranger],
        )
    }
}

impl Env {
    /// F-14 semantics: at terminal-flat the junior takes `physical - C` through tag 102
    /// (Resolved). Runs the tag-78 terminal step first (harvest + residual absorption; "no
    /// fees" is fine). Returns the amount swept.
    fn junior_terminal_sweep(&mut self, junior: &Keypair, lp: Pubkey, dest: Pubkey) -> u128 {
        self.svm.expire_blockhash();
        let _ = self.crank_fees(true);
        let (_, g) = self.market_state();
        let physical = (g.source_backing_buckets[0].fresh_unliened_backing_num
            + g.source_backing_buckets[1].fresh_unliened_backing_num)
            / percolator::BOUND_SCALE;
        let sweep = physical.saturating_sub(self.vlp().senior_claim_atoms);
        if sweep > 0 {
            self.release_surplus_resolved(junior, lp, sweep, dest).expect("junior terminal sweep");
        }
        sweep
    }

    fn release_surplus_resolved(&mut self, signer: &Keypair, lp: Pubkey, amount: u128, dest: Pubkey) -> Result<(), String> {
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::VaultLpReleaseSurplus { amount, source_domain: DOMAIN },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&signer.insecure_clone()],
        )
    }
}

impl Env {
    /// STATE POKE: the ProgramData account (no instruction creates it; same bytes as tag-85 tests).
    fn set_program_data_authority(&mut self, authority: &Pubkey) -> Pubkey {
        let (program_data, _) = Pubkey::find_program_address(
            &[self.pid.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::ID,
        );
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(authority.as_ref());
        self.svm
            .set_account(
                program_data,
                Account {
                    lamports: 1_000_000_000,
                    data: pd,
                    owner: solana_sdk::bpf_loader_upgradeable::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        program_data
    }

    fn init_vault_lp_protocol(
        &mut self,
        protocol: &Keypair,
        program_data: Pubkey,
        junior: &Keypair,
        junior_signs: bool,
    ) -> Result<Pubkey, String> {
        let lp = self.new_program_account(self.plen);
        self.svm.expire_blockhash();
        let mut signers: Vec<&Keypair> = vec![protocol];
        if junior_signs {
            signers.push(junior);
        }
        self.send(
            ProgInstruction::InitVaultLp {
                junior_floor_bps: 1_000,
            },
            vec![
                AccountMeta::new(protocol.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(self.ledger, false),
                AccountMeta::new_readonly(self.sibling, false),
                AccountMeta::new_readonly(program_data, false),
                AccountMeta::new_readonly(junior.pubkey(), junior_signs),
            ],
            &signers,
        )
        .map(|_| lp)
    }
}

const GROWTH_FEE: u64 = 10_000;

fn growth_params() -> Params {
    Params {
        funding: 1,
        growth: Some((400, 1_000)),
        // L-2: r_gap 400 must clear max_price_move x 50 slots (4 x 50 = 200).
        move_bps: 4,
        ..Params::default()
    }
}

const U: u64 = 1_000_000; // 1 USDC / 1 unit at $1
const UQ: i128 = 100_000; // 1 unit in Q = 1/10 token (POS_SCALE = 1e6)

impl Env {
    fn ext_key(&self) -> Pubkey {
        state::derive_vault_lp_ext(&self.pid, &self.market).0
    }

    fn ext(&self) -> Option<state::VaultLpExtV19> {
        self.svm
            .get_account(&self.ext_key())
            .and_then(|a| state::read_vault_lp_ext(&a.data).ok())
    }

    fn allocated(&self) -> u128 {
        self.ext().map(|x| x.allocated_atoms).unwrap_or(0)
    }

    /// Tag 103 by a random (permissionless) cranker.
    fn allocate(&mut self, lp: Pubkey, amount: u128) -> Result<(), String> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
        let ext = self.ext_key();
        self.send(
            ProgInstruction::VaultLpAllocate { amount },
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new(ext, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
            &[&cranker],
        )
    }

    /// Tag 98 with the Phase 2b ext tail ([8]).
    fn recall_ext(&mut self, lp: Pubkey, amount: u128, domain: u16) -> Result<(), String> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
        let ext = self.ext_key();
        self.send(
            ProgInstruction::VaultLpRecall { amount, target_domain: domain },
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(ext, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
            &[&cranker],
        )
    }

    /// Tag 97 with the Phase 2b ext tail ([11]); returns the result and the SPL paid.
    fn junior_withdraw_ext(&mut self, signer: &Keypair, lp: Pubkey, amount: u64) -> Result<(), String> {
        let dest = self.token_account(self.mint, signer.pubkey(), 0);
        let ext = self.ext_key();
        let r = self.send(
            ProgInstruction::WithdrawJuniorTranche { amount: amount as u128 },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(self.ledger, false),
                AccountMeta::new_readonly(self.sibling, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(ext, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
            &[signer],
        );
        if r.is_ok() {
            assert_eq!(self.tok(dest), amount);
            self.paid_out += amount as u128;
        }
        r
    }

    /// Tag 78 on a bound vault with the Phase 2b tail ([7] ext, [8] vault LP).
    fn crank_fees_ext(&mut self, lp: Pubkey) -> Result<(), String> {
        let ext = self.ext_key();
        self.send(
            ProgInstruction::LpVaultCrankFees { domain: DOMAIN },
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(ext, false),
                AccountMeta::new_readonly(lp, false),
            ],
            &[],
        )
    }

    /// Tag 99 trailing form (Phase 2b dials), signed by `signer` (ProgramData mock = admin).
    fn set_p2b_dials(&mut self, signer: &Keypair, d: [u16; 4]) -> Result<(), String> {
        let pd = Pubkey::find_program_address(&[self.pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::ID).0;
        let rec = self.asset_rec();
        let ext = self.ext_key();
        self.send(
            ProgInstruction::SetVaultLpRiskV19 {
                asset_index: 0,
                skew_slope_e9: rec.skew_slope_e9,
                skew_max_e9: rec.skew_max_e9,
                lev_cap_q: rec.lev_cap_q,
                lev_max_imr_bps: rec.lev_max_imr_bps,
                vault_lp_max_lev_bps: rec.vault_lp_max_lev_bps,
                approved_matcher_program: rec.approved_matcher_program,
                alloc_alpha_bps: d[0],
                alloc_buffer_bps: d[1],
                cushion_target_bps: d[2],
                cushion_share_bps: d[3],
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(ext, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[signer],
        )
    }

    fn trader_convert(&mut self, t: &Trader) -> Result<(), String> {
        let (portfolio_id, _, position_epoch) = self.identity(t.portfolio);
        let kp = t.kp.insecure_clone();
        self.send(
            ProgInstruction::ConvertReleasedPnl { portfolio_id, position_epoch, amount: u64::MAX as u128 },
            vec![
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
            ],
            &[&kp],
        )
    }

    /// Tag 4 of the trader's whole capital; returns the SPL paid.
    fn trader_withdraw_all(&mut self, t: &Trader) -> Result<u64, String> {
        let cap = self.portfolio(t.portfolio).capital;
        let dest = self.token_account(self.mint, t.kp.pubkey(), 0);
        let (pid_, seq, _) = self.identity(t.portfolio);
        let kp = t.kp.insecure_clone();
        self.send(
            ProgInstruction::Withdraw { portfolio_id: pid_, expected_sequence: seq, amount: cap },
            vec![
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&kp],
        )?;
        let paid = self.tok(dest);
        self.paid_out += paid as u128;
        Ok(paid)
    }

    /// Hold the current mark for `n` slots, cranking the listed portfolios (warmup).
    fn hold(&mut self, n: u64, crank: &[Pubkey]) {
        let px = self.market_state().1.assets[0].effective_price;
        let admin = self.admin.insecure_clone();
        for _ in 0..n {
            self.slot += 1;
            self.svm.warp_to_slot(self.slot);
            let seq = self.oracle_seq() + 1;
            self.send(
                ProgInstruction::PushAuthMark {
                    market_id: 1,
                    asset_index: 0,
                    now_slot: self.slot,
                    mark_e6: px,
                    observation_sequence: seq,
                },
                vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(self.market, false)],
                &[&admin],
            )
            .expect("push");
            for p in crank {
                // EngineNonProgress (22) on an already-current portfolio is not a failure here.
                let _ = self.crank(*p);
            }
        }
    }

    /// The vault value split the way the program prices it: (nav, lp_value, C).
    fn p2b_v(&self, lp: Pubkey) -> (u128, u128, u128) {
        let p = self.portfolio(lp);
        let lpv = percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap();
        (self.backing_nav(), lpv, self.vlp().senior_claim_atoms)
    }

    fn n_cap(&self, lp: Pubkey) -> u128 {
        let p = self.portfolio(lp);
        let c_m = percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap();
        percolator_prog::growth_v19::n_cap_q(c_m, 10_000, self.market_state().1.assets[0].effective_price, POS as u128)
            .unwrap()
    }
}

/// Bound vault: `senior` USDC of Earn principal (pot 0, before the bind), floor 20%, `junior`.
fn p2b_world(p: Params, senior: u64, junior: u64) -> (Env, Lp, Depositor) {
    let mut env = Env::new(p);
    let d = env.new_depositor();
    env.earn_deposit(&d, senior * U, None).expect("75 senior (unbound)");
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, junior * U).expect("96 junior");
    (env, lp, d)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Phase 4 item 3 (v22 Wave C): capacity bonds. Tags 107-110.
// Spec: ~/percolator-ops/ledger/phase4-design-2026-10-05.md item 3.
// Everything below drives real instructions against the real BPF; the only STATE POKEs are the
// ones the shared harness above already declares.
// ═══════════════════════════════════════════════════════════════════════════════════════════

use percolator_prog::bond_v20;

const COOLDOWN: u32 = 9_000;

struct BondHolder {
    kp: Keypair,
    source: Pubkey,
    position: Pubkey,
}

impl Env {
    fn tranche_key(&self) -> Pubkey {
        state::derive_bond_tranche(&self.pid, &self.market).0
    }

    fn tranche(&self) -> state::BondTrancheV20 {
        state::read_bond_tranche(&self.svm.get_account(&self.tranche_key()).unwrap().data).unwrap()
    }

    fn bond_pos(&self, h: &BondHolder) -> state::BondPositionV20 {
        state::read_bond_position(&self.svm.get_account(&h.position).unwrap().data).unwrap()
    }

    fn program_data_key(&self) -> Pubkey {
        Pubkey::find_program_address(&[self.pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::ID).0
    }

    /// Tag 107. `dials = (coupon_bps, util_bonus_bps, cooldown, cap_bps)`.
    fn init_bond_tranche_as(&mut self, signer: &Keypair, dials: (u16, u16, u32, u16)) -> Result<(), String> {
        let (ext, tranche, pd) = (self.ext_key(), self.tranche_key(), self.program_data_key());
        let payer = self.payer.pubkey();
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::InitBondTranche {
                coupon_bps: dials.0,
                util_bonus_bps: dials.1,
                cooldown_slots: dials.2,
                cap_bps: dials.3,
            },
            vec![
                AccountMeta::new_readonly(signer.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new_readonly(self.vault_lp, false),
                AccountMeta::new(ext, false),
                AccountMeta::new(tranche, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(pd, false),
            ],
            &[signer],
        )
    }

    fn init_bonds(&mut self, coupon_bps: u16) {
        let admin = self.admin.insecure_clone();
        self.init_bond_tranche_as(&admin, (coupon_bps, 0, COOLDOWN, 5_000)).expect("107 init bond tranche");
    }

    fn new_bond_holder(&mut self) -> BondHolder {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
        let source = self.token_account(self.mint, kp.pubkey(), 1_000_000_000_000);
        let position = state::derive_bond_position(&self.pid, &self.market, &kp.pubkey()).0;
        BondHolder { kp, source, position }
    }

    fn bond_deposit_ix(&self, h: &BondHolder, lp: Pubkey, amount: u64, min_shares: u128) -> (ProgInstruction, Vec<AccountMeta>) {
        (
            ProgInstruction::BondDeposit { amount, min_shares },
            vec![
                AccountMeta::new(h.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new(self.tranche_key(), false),
                AccountMeta::new(h.position, false),
                AccountMeta::new(h.source, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(state::derive_vault_lp_ext(&self.pid, &self.market).0, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
        )
    }

    fn bond_deposit(&mut self, h: &BondHolder, lp: Pubkey, amount: u64, min_shares: u128) -> Result<(), String> {
        let ix = self.bond_deposit_ix(h, lp, amount, min_shares);
        let kp = h.kp.insecure_clone();
        let r = self.send_many(vec![ix], &[&kp]);
        if r.is_ok() {
            self.paid_in += amount as u128;
        }
        r
    }

    fn bond_request(&mut self, h: &BondHolder, shares: u128) -> Result<(), String> {
        let kp = h.kp.insecure_clone();
        let tranche = self.tranche_key();
        self.send(
            ProgInstruction::BondRequestWithdraw { shares },
            vec![
                AccountMeta::new_readonly(h.kp.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new_readonly(tranche, false),
                AccountMeta::new(h.position, false),
            ],
            &[&kp],
        )
    }

    fn bond_execute_ix(&self, h: &BondHolder, lp: Pubkey, dest: Pubkey, min_out: u64) -> (ProgInstruction, Vec<AccountMeta>) {
        (
            ProgInstruction::BondExecuteWithdraw { min_out, source_domain: DOMAIN },
            vec![
                AccountMeta::new_readonly(h.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new(self.tranche_key(), false),
                AccountMeta::new(h.position, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(state::derive_vault_lp_ext(&self.pid, &self.market).0, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
            ],
        )
    }

    /// Tag 110; returns the SPL paid to a fresh destination account.
    fn bond_execute(&mut self, h: &BondHolder, lp: Pubkey, min_out: u64) -> Result<u64, String> {
        let dest = self.token_account(self.mint, h.kp.pubkey(), 0);
        let ix = self.bond_execute_ix(h, lp, dest, min_out);
        let kp = h.kp.insecure_clone();
        self.send_many(vec![ix], &[&kp])?;
        let paid = self.tok(dest);
        self.paid_out += paid as u128;
        Ok(paid)
    }

    /// Tag 78 on a bound vault with the Phase 4 tail ([7] ext, [8] vault LP WRITABLE -- N-1:
    /// 78 re-certifies it before valuing the bonds -- and [9] tranche).
    fn crank_fees_bond(&mut self, lp: Pubkey) -> Result<(), String> {
        self.crank_fees_bond_lp(lp, true)
    }

    fn crank_fees_bond_lp(&mut self, lp: Pubkey, lp_writable: bool) -> Result<(), String> {
        let (ext, tranche) = (self.ext_key(), self.tranche_key());
        let lp_meta = if lp_writable { AccountMeta::new(lp, false) } else { AccountMeta::new_readonly(lp, false) };
        self.send(
            ProgInstruction::LpVaultCrankFees { domain: DOMAIN },
            vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.ledger, false),
                AccountMeta::new(self.sibling, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(ext, false),
                lp_meta,
                AccountMeta::new(tranche, false),
            ],
            &[],
        )
    }

    /// Tag 97 with the Phase 2b ext tail ([11]) and the Phase 4 tranche ([12]) when `tranche`.
    fn junior_withdraw_bond(&mut self, signer: &Keypair, lp: Pubkey, amount: u64, tranche: Option<Pubkey>) -> Result<(), String> {
        let dest = self.token_account(self.mint, signer.pubkey(), 0);
        let ext = self.ext_key();
        let mut accts = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(self.ledger, false),
            AccountMeta::new_readonly(self.sibling, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(self.vault_token, false),
            AccountMeta::new_readonly(self.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ext, false),
        ];
        match tranche {
            Some(t) => accts.push(AccountMeta::new_readonly(t, false)),
            None => accts.push(AccountMeta::new_readonly(solana_sdk::system_program::ID, false)),
        }
        accts.push(AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false));
        let r = self.send(ProgInstruction::WithdrawJuniorTranche { amount: amount as u128 }, accts, &[signer]);
        if r.is_ok() {
            assert_eq!(self.tok(dest), amount);
            self.paid_out += amount as u128;
        }
        r
    }

    /// Largest junior withdrawal the program admits (halving search; failures do not mutate).
    fn max_junior_out_bond(&mut self, lp: Pubkey) -> u128 {
        let admin = self.admin.insecure_clone();
        let t = Some(self.tranche_key());
        let (mut amt, mut total) = (20_000 * U, 0u128);
        while amt > 0 {
            if self.junior_withdraw_bond(&admin, lp, amt, t).is_ok() {
                total += amt as u128;
            } else {
                amt /= 2;
            }
        }
        total
    }

    /// Tag 103 with the Phase 4 tranche tail ([9]) when `tranche`.
    fn allocate_bond(&mut self, lp: Pubkey, amount: u128, tranche: Option<Pubkey>) -> Result<(), String> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
        let ext = self.ext_key();
        let mut accts = vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new(self.sibling, false),
            AccountMeta::new(ext, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ];
        match tranche {
            Some(t) => accts.push(AccountMeta::new_readonly(t, false)),
            None => accts.push(AccountMeta::new_readonly(solana_sdk::system_program::ID, false)),
        }
        accts.push(AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false));
        self.send(ProgInstruction::VaultLpAllocate { amount }, accts, &[&cranker])
    }

    /// Tag 102 Resolved with the Phase 4 tranche ([11]) when `tranche`.
    fn release_surplus_resolved_bond(&mut self, signer: &Keypair, lp: Pubkey, amount: u128, dest: Pubkey, tranche: Option<Pubkey>) -> Result<(), String> {
        let mut accts = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new_readonly(self.registry, false),
            AccountMeta::new(self.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new(self.sibling, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(self.vault_token, false),
            AccountMeta::new_readonly(self.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ];
        if let Some(t) = tranche {
            accts.push(AccountMeta::new_readonly(t, false));
        }
        self.svm.expire_blockhash();
        self.send(ProgInstruction::VaultLpReleaseSurplus { amount, source_domain: DOMAIN }, accts, &[&signer.insecure_clone()])
    }

    /// Advance past the bond cooldown on a market whose price is held (oracle re-pushed after
    /// the jump so the next instruction is current).
    fn wait_cooldown(&mut self, crank: &[Pubkey]) {
        self.slot += COOLDOWN as u64;
        self.svm.warp_to_slot(self.slot);
        self.hold(1, crank);
    }

    /// The three-way split exactly as tag 108/110 price it on a FLAT vault LP: V = pots + LP
    /// conservative equity (no lag on a flat LP), C_s, C_b.
    fn split3(&self, lp: Pubkey) -> bond_v20::TrancheSplit3 {
        let (nav, lpv, c) = self.p2b_v(lp);
        bond_v20::tranche_split3(nav + lpv, c, self.tranche().claim_total().unwrap())
    }

    /// GH#571: the split a Live tag 110 prices at NOW: the claim is first settled to the current
    /// slot (gate open iff the tranche is whole incl. its arrears; base rate, no utilisation term).
    fn split3_settled(&self, lp: Pubkey) -> bond_v20::TrancheSplit3 {
        let (nav, lpv, c) = self.p2b_v(lp);
        let tr = self.tranche();
        let k = tr.claim_total().unwrap();
        let open = tr.c_b_atoms > 0 && !bond_v20::bond_impaired(nav + lpv, c, k);
        let rate = bond_v20::bond_coupon_rate_bps(tr.coupon_bps_per_year, tr.coupon_util_bonus_bps, 0);
        let a = bond_v20::coupon_settle(tr.c_b_atoms, tr.coupon_arrears_atoms, rate, self.slot - tr.last_coupon_slot, open, k).unwrap();
        bond_v20::tranche_split3(nav + lpv, c, tr.c_b_atoms + a)
    }
}

/// Bound vault with `senior` Earn, floor 20%, `junior`, a bond tranche (`coupon_bps`, no bonus,
/// 9,000-slot cooldown, cap 50%) and one bond holder with `bond` deposited.
fn bond_world(p: Params, senior: u64, junior: u64, bond: u64, coupon_bps: u16) -> (Env, Lp, Depositor, BondHolder) {
    // M-2: the tranche must exist BEFORE the first Earn deposit, so: bind, 107, then Earn (75,
    // bound path), then the junior (96), then the bond.
    let mut env = Env::new(p);
    let lp = env.bind(2_000);
    env.init_bonds(coupon_bps);
    let d = env.new_depositor();
    env.earn_deposit(&d, senior * U, Some(lp.portfolio)).expect("75 senior (bound)");
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, junior * U).expect("96 junior");
    let h = env.new_bond_holder();
    if bond > 0 {
        env.bond_deposit(&h, lp.portfolio, bond * U, 1).expect("108 bond deposit");
    }
    (env, lp, d, h)
}

// ── 107 ─────────────────────────────────────────────────────────────────────────────────────

/// Tag 107: market authority or upgrade authority only; protocol-bounded, immutable dials;
/// refused on an unbound vault and on a second init; sets registry flag 2 and creates the ext.
#[test]
fn bond_init_authority_bounds_and_flag() {
    let mut env = Env::new(Params::default());
    let admin = env.admin.insecure_clone();
    let a = admin.pubkey();
    env.set_program_data_authority(&a);
    // unbound vault: refused
    err_has(&env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)), PercolatorError::VaultLpNotBound);
    let lp = env.bind(2_000);
    // stranger (neither market authority nor upgrade authority): refused
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(&env.init_bond_tranche_as(&stranger, (800, 0, COOLDOWN, 5_000)), PercolatorError::Unauthorized);
    // out-of-bounds dials: each refused
    // (800, 300, ..): a non-zero utilisation bonus is refused until a wash-resistant metric
    // exists (security review L-2).
    for bad in [(2_001, 0, COOLDOWN, 5_000), (800, 300, COOLDOWN, 5_000), (800, 1_001, COOLDOWN, 5_000), (800, 0, COOLDOWN - 1, 5_000), (800, 0, 1_512_001, 5_000), (800, 0, COOLDOWN, 0), (800, 0, COOLDOWN, 5_001)] {
        err_has(&env.init_bond_tranche_as(&admin, bad), PercolatorError::BondConfigInvalid);
    }
    assert!(env.svm.get_account(&env.tranche_key()).is_none_or(|a| a.data.is_empty()), "nothing created by a refusal");
    assert_eq!(env.registry_state()._reserved[2], 0, "flag 2 not set by a refusal");
    // market authority: created
    env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 4_000)).expect("marketauth creates");
    let t = env.tranche();
    assert_eq!((t.coupon_bps_per_year, t.coupon_util_bonus_bps, t.bond_cooldown_slots, t.bond_cap_bps_of_c), (800, 0, COOLDOWN, 4_000));
    assert_eq!((t.c_b_atoms, t.b_shares_total), (0, 0));
    assert_eq!(env.registry_state()._reserved[2], 1, "registry flag 2 (BOND_TRANCHE_EXISTS)");
    assert_eq!(env.registry_state()._reserved[1], 1, "the ext slot exists from 107 on");
    assert!(env.ext().is_some());
    // second init refused
    err_has(&env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)), PercolatorError::BondConfigInvalid);
    let _ = lp;

    // upgrade-authority path on a fresh market (UA != market authority)
    let mut env = Env::new(Params::default());
    env.bind(2_000);
    let ua = Keypair::new();
    env.svm.airdrop(&ua.pubkey(), 10_000_000_000).unwrap();
    let k = ua.pubkey();
    env.set_program_data_authority(&k);
    env.init_bond_tranche_as(&ua, (800, 0, COOLDOWN, 5_000)).expect("upgrade authority creates");
}

/// M-2 (security review 2026-10-05): a bond tranche can never be added under existing Earn
/// depositors (coupon-first would change their fee terms after they deposited). Refused once the
/// vault holds any Earn deposit, whether made before or after the bind; the same call on a fresh
/// vault (control) succeeds. Negative control: mutant MB5 (timing check removed).
#[test]
fn bond_tranche_refused_after_the_first_earn_deposit() {
    let (mut env, _lp, _d) = p2b_world(Params::default(), 10_000, 1_000); // Earn before the bind
    let admin = env.admin.insecure_clone();
    err_has(&env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)), PercolatorError::BondConfigInvalid);
    assert_eq!(env.registry_state()._reserved[2], 0);
    let mut env = Env::new(Params::default());
    let lp = env.bind(2_000);
    let d = env.new_depositor();
    env.earn_deposit(&d, 1_000 * U, Some(lp.portfolio)).expect("bound Earn deposit");
    let admin = env.admin.insecure_clone();
    err_has(&env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)), PercolatorError::BondConfigInvalid);
    let mut env = Env::new(Params::default());
    env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)).expect("control: no Earn yet");
}

// ── 108 + N_cap ─────────────────────────────────────────────────────────────────────────────

/// Tag 108: the genesis deposit mints 1:1, the SPL becomes vault-LP ENGINE CAPITAL, and growth's
/// `N_cap` counts junior + allocated Earn (<= alpha * C_eff) + bonds. NEGATIVE CONTROL: the same
/// crowd order without the bond is clipped at junior + alpha*Earn.
#[test]
fn bond_deposit_mints_at_par_and_ncap_counts_junior_alpha_earn_and_bonds() {
    let fill = |bond: bool| -> (u128, i128) {
        let (mut env, lp, _d, _h) = bond_world(growth_params(), 10_000, 1_000, 0, 800);
        let t = Some(env.tranche_key());
        env.allocate_bond(lp.portfolio, u128::MAX, t).expect("103: 5,000 of Earn");
        let cap_before = env.n_cap(lp.portfolio);
        assert_eq!(cap_before, 6_000 * UQ as u128, "junior 1,000 + alpha 50% x Earn 10,000");
        if bond {
            let h = env.new_bond_holder();
            let lp_cap0 = env.portfolio(lp.portfolio).capital;
            let vault0 = env.market_state().1.vault;
            env.bond_deposit(&h, lp.portfolio, 2_000 * U, 2_000 * U as u128).expect("108");
            let t = env.tranche();
            assert_eq!((t.c_b_atoms, t.b_shares_total), (2_000 * U as u128, 2_000 * U as u128), "genesis 1:1");
            assert_eq!(env.bond_pos(&h).shares, 2_000 * U as u128);
            assert_eq!(env.portfolio(lp.portfolio).capital, lp_cap0 + 2_000 * U as u128, "bond = vault-LP capital");
            assert_eq!(env.market_state().1.vault, vault0 + 2_000 * U as u128);
            assert_eq!(t.principal_in_lp_atoms, 2_000 * U as u128);
            let s = env.split3(lp.portfolio);
            assert_eq!(s.bond, 2_000 * U as u128, "the bond is whole");
            assert_eq!(s.senior, 10_000 * U as u128, "seniors untouched");
            env.assert_conserved("after bond deposit");
        }
        let cap = env.n_cap(lp.portfolio);
        let whale = env.new_trader(100_000 * U);
        // tag 103 with the tranche existing: [9] is now required (fail closed), see below.
        env.trade_signing_fee(&whale, &lp, 8_000 * UQ, GROWTH_FEE).expect("crowd order");
        (cap, env.position(whale.portfolio))
    };
    let (cap_off, pos_off) = fill(false);
    let (cap_on, pos_on) = fill(true);
    assert_eq!(cap_on, 8_000 * UQ as u128, "N_cap = junior + alpha*Earn + bonds");
    assert_eq!(cap_off, 6_000 * UQ as u128);
    assert_eq!(pos_off, 6_000 * UQ, "control: clipped without the bond");
    assert_eq!(pos_on, 8_000 * UQ, "the bond-backed capacity fills the whole order");
}

/// Tag 108 refusals and their controls: zero, no tranche, above the cap, fee leg unharvested,
/// slippage (and a zero-share mint).
#[test]
fn bond_deposit_refusals_and_controls() {
    {
        // no tranche: the tranche account does not load
        let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
        let h = env.new_bond_holder();
        err_has(&env.bond_deposit(&h, lp.portfolio, U, 1), PercolatorError::BondConfigInvalid);
    }
    let (mut env, lp, _d, h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 2_000, 0, 800);
    err_has(&env.bond_deposit(&h, lp.portfolio, 0, 0), PercolatorError::LpVaultZeroAmount);
    // cap: 50% x (C 10,000 + junior 2,000) = 6,000
    err_has(&env.bond_deposit(&h, lp.portfolio, 6_000 * U + 1, 1), PercolatorError::BondDepositAboveCap);
    // slippage
    err_has(&env.bond_deposit(&h, lp.portfolio, 1_000 * U, 1_000 * U as u128 + 1), PercolatorError::BondSlippage);
    env.bond_deposit(&h, lp.portfolio, 6_000 * U, 6_000 * U as u128).expect("exactly at the cap");
    err_has(&env.bond_deposit(&h, lp.portfolio, 1, 0), PercolatorError::BondDepositAboveCap);
    // a fee-paying round trip leaves an unharvested LP fee leg: 108 refuses until 78 runs
    let h2 = env.new_bond_holder();
    let t = env.new_trader(1_000 * U);
    env.trade(&t, &lp, 100 * UQ).expect("open");
    env.trade(&t, &lp, -100 * UQ).expect("close");
    // (the cap moved with the fee-free junior; deposit 1 atom-worth well under it)
    let r = env.bond_deposit(&h2, lp.portfolio, U, 1);
    err_has(&r, PercolatorError::VaultLpHarvestPending);
    env.crank_fees_bond(lp.portfolio).expect("78 harvests (coupon first)");
    let _ = env.bond_deposit(&h2, lp.portfolio, U, 1); // may now hit the cap; never HarvestPending
    env.assert_conserved("refusals");
}

// ── 109/110 + the lock ──────────────────────────────────────────────────────────────────────

/// Cooldown and request rules: no request -> 109; more than held -> 110; before the cooldown ->
/// 109; a cancel (0) -> 109; a stranger cannot touch the position (PDA/owner bound).
#[test]
fn bond_request_and_cooldown_rules() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 2_000, 1_000, 0);
    let all = [lp.portfolio];
    err_has(&env.bond_execute(&h, lp.portfolio, 0), PercolatorError::BondWithdrawCooldown);
    err_has(&env.bond_request(&h, 1_000 * U as u128 + 1), PercolatorError::BondConfigInvalid);
    env.bond_request(&h, 400 * U as u128).expect("109");
    err_has(&env.bond_execute(&h, lp.portfolio, 0), PercolatorError::BondWithdrawCooldown);
    env.slot += COOLDOWN as u64 - 2;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &all);
    err_has(&env.bond_execute(&h, lp.portfolio, 0), PercolatorError::BondWithdrawCooldown);
    env.hold(1, &all);
    // a stranger cannot request on (or redeem) this position
    let s = env.new_bond_holder();
    let forged = BondHolder { kp: s.kp.insecure_clone(), source: s.source, position: h.position };
    err_has(&env.bond_request(&forged, 1), PercolatorError::BondConfigInvalid);
    err_has(&env.bond_execute(&forged, lp.portfolio, 0), PercolatorError::BondConfigInvalid);
    // slippage on the exit
    err_has(&env.bond_execute(&h, lp.portfolio, 400 * U + 1), PercolatorError::BondSlippage);
    let paid = env.bond_execute(&h, lp.portfolio, 400 * U).expect("110 after the cooldown");
    assert_eq!(paid, 400 * U, "par");
    let (t, p) = (env.tranche(), env.bond_pos(&h));
    assert_eq!((t.c_b_atoms, t.b_shares_total, p.shares, p.pending_withdraw_shares), (600 * U as u128, 600 * U as u128, 600 * U as u128, 0));
    // cancel: request then 0
    env.bond_request(&h, 100 * U as u128).expect("request");
    env.bond_request(&h, 0).expect("cancel");
    env.wait_cooldown(&all);
    err_has(&env.bond_execute(&h, lp.portfolio, 0), PercolatorError::BondWithdrawCooldown);
    env.assert_conserved("cooldown");
}

/// THE SELF-FUNDING ATTACK (adversarial review 2026-06-01; CSV-FL+ A4): post a bond, let others
/// open against the larger capacity, withdraw the bond, leave the open interest backed by less.
/// Refused while the bond backs OPEN interest -- both with the vault LP holding the inventory and
/// with the vault LP FLAT but users' open interest still open (balanced long/short), where the
/// engine's flat-only withdraw would NOT stop it: only the lock does (mutant control
/// `scripts/v22-bond-mutants.sh` MB1 makes this test fail). Once the OI is closed the same exit
/// pays par.
#[test]
fn bond_self_funding_attack_is_refused() {
    let (mut env, lp, _d, _h) = bond_world(growth_params(), 10_000, 1_000, 0, 0);
    let attacker = env.new_bond_holder();
    env.bond_deposit(&attacker, lp.portfolio, 1_000 * U, 1).expect("attacker posts a 1,000 bond");
    assert_eq!(env.n_cap(lp.portfolio), 2_000 * UQ as u128, "capacity doubled by the bond");
    // the attacker pre-positions the withdrawal while the book is empty
    env.bond_request(&attacker, 1_000 * U as u128).expect("109");
    // Growth markets here run max_accrual_dt_slots = 1: a slot gap must be caught up crank by
    // crank (spec §9.6) before an LP-reducing trade is current, as a keeper that missed slots
    // would. Jump the cooldown, then catch up (batched cranks).
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.catch_up(lp.portfolio);

    // (a) others open the new capacity against the vault LP
    let whale = env.new_trader(100_000 * U);
    env.trade_signing_fee(&whale, &lp, 2_000 * UQ, GROWTH_FEE).expect("open to capacity");
    assert_eq!(env.position(lp.portfolio), -2_000 * UQ);
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio); // 38 when nothing is harvestable
    let (cb0, vault0) = (env.tranche().c_b_atoms, env.tok(env.vault_token));
    err_has(&env.bond_execute(&attacker, lp.portfolio, 0), PercolatorError::BondCapacityLocked);
    assert_eq!(env.tranche().c_b_atoms, cb0, "nothing moved");
    assert_eq!(env.tok(env.vault_token), vault0);

    // (b) the vault LP is flat but users' OI is open (a second trader takes the other side)
    env.hold(1, &[whale.portfolio, lp.portfolio]);
    let thin = env.new_trader(100_000 * U);
    env.trade_signing_fee(&thin, &lp, -2_000 * UQ, GROWTH_FEE).expect("other side");
    assert_eq!(env.position(lp.portfolio), 0, "vault LP flat");
    let g = env.market_state().1;
    assert!(g.assets[0].oi_eff_long_q >= 2_000 * UQ as u128 && g.assets[0].oi_eff_short_q >= 2_000 * UQ as u128, "users' OI still open");
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio); // 38 when nothing is harvestable
    err_has(&env.bond_execute(&attacker, lp.portfolio, 0), PercolatorError::BondCapacityLocked);

    // (c) control: the OI closes, and the identical exit pays par
    env.hold(1, &[whale.portfolio, thin.portfolio, lp.portfolio]);
    env.trade_signing_fee(&whale, &lp, -2_000 * UQ, GROWTH_FEE).expect("whale closes");
    env.trade_signing_fee(&thin, &lp, 2_000 * UQ, GROWTH_FEE).expect("thin closes");
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio); // 38 when nothing is harvestable
    let g = env.market_state().1;
    assert_eq!((g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q), (0, 0));
    let paid = env.bond_execute(&attacker, lp.portfolio, 0).expect("exit once nothing is open");
    assert_eq!(paid, 1_000 * U, "par (coupon 0)");
    env.assert_conserved("self-funding");
}

/// AUD-S1-15 / L-4 (fix-all 2026-10-18): the junior (tag 97) is held to the same open-interest
/// lock as a bond exit (`bond_lock_binds_with_a_flat_vault_lp_and_open_user_oi`). Two identical
/// worlds (senior 10,000, junior 6,000, no bond): in A users hold open interest on both sides against
/// a FLAT vault LP (3,000 open each side); B has no open interest. The largest junior withdrawal the program admits must
/// be strictly smaller in A (its N_cap after the withdrawal must still cover 3,000). Before the
/// fix A admitted at least as much as B (A4 only checks the LP's own inventory, and A's trades
/// only added fee value), so the junior could pull the capacity backing open OI.
#[test]
fn s1_15_junior_withdraw_is_locked_by_open_user_oi() {
    let world = |open: bool| {
        let (mut env, lp, _d, _h) = bond_world(growth_params(), 10_000, 6_000, 0, 0);
        env.hold(1, &[lp.portfolio]);
        env.catch_up(lp.portfolio);
        if open {
            let long = env.new_trader(100_000 * U);
            env.trade_signing_fee(&long, &lp, 3_000 * UQ, GROWTH_FEE).expect("long 3,000");
            let short = env.new_trader(100_000 * U);
            env.trade_signing_fee(&short, &lp, -3_000 * UQ, GROWTH_FEE).expect("short 3,000 (LP back to flat)");
            assert_eq!(env.position(lp.portfolio), 0, "vault LP flat");
        }
        let _ = env.crank(lp.portfolio);
        let _ = env.crank_fees_bond(lp.portfolio);
        let out = env.max_junior_out_bond(lp.portfolio);
        env.assert_conserved("junior OI lock");
        out
    };
    let with_oi = world(true);
    let without = world(false);
    eprintln!("S1-15 max junior withdrawal: with open OI {with_oi}, without {without}");
    assert!(without > 0, "control: the junior can withdraw something with nothing open");
    assert!(with_oi < without, "the open-interest lock binds the junior: {with_oi} vs {without}");
}

/// The lock in isolation: the vault LP is FLAT (the engine's flat-only withdraw would let the
/// capital out) but users' open interest, opened against the capacity the bond created, is still
/// open on both sides. Only `bond_withdraw_lock_ok` refuses here: under mutant MB1 (lock off) the
/// withdrawal SUCCEEDS and this test fails. Control: once the OI is closed the exit pays par.
#[test]
fn bond_lock_binds_with_a_flat_vault_lp_and_open_user_oi() {
    let (mut env, lp, _d, _h) = bond_world(growth_params(), 10_000, 1_000, 0, 0);
    let attacker = env.new_bond_holder();
    env.bond_deposit(&attacker, lp.portfolio, 1_000 * U, 1).expect("bond");
    env.bond_request(&attacker, 1_000 * U as u128).expect("109");
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.catch_up(lp.portfolio);
    let long = env.new_trader(100_000 * U);
    env.trade_signing_fee(&long, &lp, 1_500 * UQ, GROWTH_FEE).expect("long 1,500 (inside N_cap 2,000)");
    let short = env.new_trader(100_000 * U);
    env.trade_signing_fee(&short, &lp, -1_500 * UQ, GROWTH_FEE).expect("short 1,500 (LP back to flat)");
    assert_eq!(env.position(lp.portfolio), 0, "vault LP flat");
    let g = env.market_state().1;
    assert_eq!((g.assets[0].oi_eff_long_q, g.assets[0].oi_eff_short_q), (1_500 * UQ as u128, 1_500 * UQ as u128));
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio);
    // N_cap after the exit would be 1,000 < 1,500 open on each side.
    err_has(&env.bond_execute(&attacker, lp.portfolio, 0), PercolatorError::BondCapacityLocked);
    env.trade_signing_fee(&long, &lp, -1_500 * UQ, GROWTH_FEE).expect("close long");
    env.trade_signing_fee(&short, &lp, 1_500 * UQ, GROWTH_FEE).expect("close short");
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio);
    assert_eq!(env.bond_execute(&attacker, lp.portfolio, 0).expect("control"), 1_000 * U);
    env.assert_conserved("flat-LP lock");
}

// ── loss waterfall ──────────────────────────────────────────────────────────────────────────

/// junior -> bonds -> Earn seniors, on real losses (a winner against the vault LP), with the
/// winner paid in full every time. Seniors 10,000, junior 500, bonds 1,000; a trader long
/// 1,000 units; the price moves +30% (junior absorbs), +100% (junior gone, bonds take the rest)
/// or +200% (junior and bonds gone, the P3 draw takes the remainder from the seniors). The bond
/// exit pays exactly its layer of the split; seniors redeem exactly C.
#[test]
fn bond_waterfall_order_under_losses() {
    for (case, px) in [(0, 13_000_000u64), (1, 20_000_000), (2, 30_000_000)] {
        let (mut env, lp, d, h) = bond_world(Params::default(), 10_000, 500, 1_000, 800);
        let c0 = env.vlp().senior_claim_atoms;
        let t = env.new_trader(5_000 * U);
        env.trade(&t, &lp, 1_000 * UQ).expect("trader long vs the vault LP");
        env.move_price(px, &[t.portfolio, lp.portfolio]);
        env.trade(&t, &lp, -1_000 * UQ).expect("trader closes (vault LP realises)");
        assert_eq!(env.position(lp.portfolio), 0);
        env.hold(12, &[t.portfolio, lp.portfolio]);
        let _ = env.crank_fees_bond(lp.portfolio); // books any draw (78 prices off C)
        env.trader_convert(&t).expect("winner converts");
        let gain = env.portfolio(t.portfolio).capital as i128 - 5_000 * U as i128;
        let paid_w = env.trader_withdraw_all(&t).expect("winner withdraws");
        assert_eq!(paid_w as i128, 5_000 * U as i128 + gain, "winner paid in full");
        assert!(gain > 0, "vacuity: the trader won");
        let (nav, lpv, c) = env.p2b_v(lp.portfolio);
        let tr = env.tranche();
        let s = bond_v20::tranche_split3(nav + lpv, c, tr.c_b_atoms);
        eprintln!("WATERFALL case {case}: gain {gain} nav {nav} lp {lpv} C {c} C_b {} -> senior {} bond {} junior {}", tr.c_b_atoms, s.senior, s.bond, s.junior);
        match case {
            0 => {
                assert!(gain < 500 * U as i128, "vacuity: a junior-sized loss");
                assert_eq!(c, c0, "seniors untouched");
                assert_eq!(s.bond, tr.c_b_atoms, "bonds whole while the junior absorbs");
                assert!(s.junior > 0);
            }
            1 => {
                assert!(gain > 500 * U as i128 && gain < 1_500 * U as i128, "vacuity: junior < loss < junior + bond");
                assert_eq!(c, c0, "seniors untouched while bond value remains");
                assert_eq!(s.junior, 0, "junior exhausted first");
                assert!(s.bond > 0 && s.bond < tr.c_b_atoms, "bonds impaired");
                // the bond's loss is the part of the vault LP's loss the junior could not take
                let lp_loss = (500 + 1_000) * U as u128 - lpv;
                assert_eq!(tr.c_b_atoms - s.bond, lp_loss - 500 * U as u128);
                // an impaired tranche takes no deposits at par
                let h2 = env.new_bond_holder();
                err_has(&env.bond_deposit(&h2, lp.portfolio, U, 1), PercolatorError::BondTrancheImpaired);
            }
            _ => {
                assert!(gain > 1_500 * U as i128, "vacuity: the loss exceeds junior + bonds");
                assert_eq!((s.junior, s.bond), (0, 0), "junior and bonds gone before seniors");
                assert!(c < c0, "seniors took the remainder through the draw");
                assert_eq!(c0 - c, gain as u128 - 1_500 * U as u128, "exactly the loss beyond junior + bonds");
                assert!(env.vlp().senior_draw_outstanding_atoms > 0);
                // the coupon never comes ahead of senior principal: a fee crank pays 0 coupon
                let cb = tr.c_b_atoms;
                let t2 = env.new_trader(1_000 * U);
                let _ = env.trade(&t2, &lp, 10 * UQ);
                let _ = env.crank_fees_bond(lp.portfolio);
                assert_eq!(env.tranche().c_b_atoms, cb, "no coupon while a senior draw is outstanding");
                let h2 = env.new_bond_holder();
                err_has(&env.bond_deposit(&h2, lp.portfolio, U, 1), PercolatorError::VaultLpPausedForSeniorDraw);
                env.bond_request(&h, 1_000 * U as u128).expect("109");
                env.wait_cooldown(&[lp.portfolio]);
                err_has(&env.bond_execute(&h, lp.portfolio, 0), PercolatorError::VaultLpPausedForSeniorDraw);
                env.assert_conserved("waterfall senior case");
                continue;
            }
        }
        // bond exit pays exactly its layer (case 0: par; case 1: the impaired value)
        env.bond_request(&h, 1_000 * U as u128).expect("109");
        env.wait_cooldown(&[lp.portfolio]);
        // GH#571: 110 settles the cooldown's accrual first (case 0, whole); nothing accrues on
        // the impaired tranche (case 1).
        let s = env.split3_settled(lp.portfolio);
        let paid_b = env.bond_execute(&h, lp.portfolio, 0).expect("110");
        assert_eq!(paid_b as u128, s.bond, "bond paid its split layer exactly");
        assert_eq!(env.tranche().c_b_atoms, 0);
        // seniors redeem C in full
        let shares = env.lp_shares(&d);
        env.earn_request(&d, shares);
        let paid_s = env.earn_execute(&d, Some(lp.portfolio)).expect("senior redeems");
        assert_eq!(paid_s as u128, c0 * shares / (shares + 1_000), "seniors whole");
        env.assert_conserved("waterfall");
    }
}

// ── junior gates ────────────────────────────────────────────────────────────────────────────

/// Tag 97 can never reach bond value: with a 2,000 bond in the vault LP, the junior (3,000 over
/// a 2,000 floor) still withdraws at most 1,000. Without the tranche account 97 / 103 / 78 fail
/// closed. NEGATIVE CONTROL: MB2 (97 priced two-tranche) lets the junior take the bond.
#[test]
fn bond_junior_cannot_withdraw_bond_value_and_tranche_is_required() {
    let (mut env, lp, d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    let admin = env.admin.insecure_clone();
    // fail closed without the tranche tail
    assert!(env.junior_withdraw_bond(&admin, lp.portfolio, U, None).is_err(), "97 without [12]");
    let wrong = env.ext_key();
    assert!(env.junior_withdraw_bond(&admin, lp.portfolio, U, Some(wrong)).is_err(), "97 with a wrong [12]");
    assert!(env.allocate_bond(lp.portfolio, U as u128, None).is_err(), "103 without [9]");
    assert!(env.allocate_bond(lp.portfolio, U as u128, Some(wrong)).is_err(), "103 with a wrong [9]");
    // junior max out == junior - floor, NOT junior + bond - floor
    err_has(&env.junior_withdraw_bond(&admin, lp.portfolio, 1_000 * U + 1, Some(env.tranche_key())), PercolatorError::VaultLpJuniorWithdrawRefused);
    let out = env.max_junior_out_bond(lp.portfolio);
    assert_eq!(out, 1_000 * U as u128, "the junior withdraws exactly junior - floor");
    let s = env.split3(lp.portfolio);
    assert_eq!(s.bond, 2_000 * U as u128, "bond value intact");
    // the bond exits at par afterwards; the senior is whole
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    assert_eq!(env.bond_execute(&h, lp.portfolio, 0).expect("110"), 2_000 * U);
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    env.earn_execute(&d, Some(lp.portfolio)).expect("senior");
    env.assert_conserved("junior gate");
}

/// Tag 103 L-3 measures the JUNIOR alone: a bond deposit cannot unlock an allocation on a
/// near-zero junior (a later bond exit would leave Earn capital on no first-loss buffer).
#[test]
fn bond_does_not_count_as_l3_junior() {
    // junior 400 < 5% of C 10,000 = 500: refused with or without bonds.
    let (mut env, lp, _d, _h) = bond_world(Params::default(), 10_000, 400, 2_000, 0);
    let t = Some(env.tranche_key());
    err_has(&env.allocate_bond(lp.portfolio, u128::MAX, t), PercolatorError::VaultLpAllocateRefused);
    // control: junior 600 >= 500 admits it (bonds unchanged)
    let (mut env, lp, _d, _h) = bond_world(Params::default(), 10_000, 600, 2_000, 0);
    let t = Some(env.tranche_key());
    env.allocate_bond(lp.portfolio, u128::MAX, t).expect("junior alone clears L-3");
}

// ── coupon ──────────────────────────────────────────────────────────────────────────────────

/// Coupon first: on tag 78 the bonds take `min(due, half the LP fee leg)` (M-2 cap) before the
/// seniors, credited to C_b (value conserved: coupon + senior credit == the leg); the holder
/// exits at principal + coupon. CUMULATIVE since GH#571: an interval whose leg could not cover the
/// due CARRIES the rest as arrears, paid by the next leg (pre-#571 this test asserted the opposite). Negative control for the cap: mutant MB6 (cap removed) gives the whole thin leg
/// to the coupon and fails this test.
#[test]
fn bond_coupon_first_conserves_and_carries_arrears_gh571() {
    let (mut env, lp, d, h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
    let t = env.new_trader(10_000 * U);
    let round = |env: &mut Env, n: u32| {
        for _ in 0..n {
            env.trade(&t, &lp, 1_000 * UQ).expect("open");
            env.trade(&t, &lp, -1_000 * UQ).expect("close");
        }
    };
    // interval 1: long (500k slots) with a fat fee leg -> the coupon is the full due
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    round(&mut env, 6);
    let tr0 = env.tranche();
    let c0 = env.vlp().senior_claim_atoms;
    let avail = {
        let (cfg, _) = env.market_state();
        cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms
    };
    let due = bond_v20::coupon_due(tr0.c_b_atoms, 2_000, env.slot - tr0.last_coupon_slot).unwrap();
    env.crank_fees_bond(lp.portfolio).expect("78");
    let tr1 = env.tranche();
    let coupon = tr1.c_b_atoms - tr0.c_b_atoms;
    let senior = env.vlp().senior_claim_atoms - c0;
    eprintln!("COUPON 1: leg {avail} due {due} coupon {coupon} senior {senior}");
    assert!(avail > 0 && due > 0, "vacuity");
    assert_eq!(coupon, due.min(avail / 2), "coupon = min(due, leg / 2)");
    assert_eq!(coupon + senior, avail, "coupon + senior credit == the leg (cushion off)");
    assert_eq!(tr1.coupon_paid_total_atoms as u128, coupon);
    assert_eq!(tr1.last_coupon_slot, env.slot);
    // interval 2: long again but a THIN leg -> the coupon is capped at HALF the leg (M-2); the
    // seniors keep the other half ...
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.trade(&t, &lp, 10 * UQ).expect("tiny open");
    env.trade(&t, &lp, -10 * UQ).expect("tiny close");
    let c1 = env.vlp().senior_claim_atoms;
    let leg2 = {
        let (cfg, _) = env.market_state();
        cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms
    };
    let due2 = bond_v20::coupon_due(tr1.c_b_atoms, 2_000, env.slot - tr1.last_coupon_slot).unwrap();
    env.crank_fees_bond(lp.portfolio).expect("78 thin");
    let tr2 = env.tranche();
    assert!(due2 > leg2, "vacuity: the leg cannot cover the due");
    assert_eq!(tr2.c_b_atoms - tr1.c_b_atoms, leg2 / 2, "the coupon takes at most half the leg (M-2)");
    assert_eq!(env.vlp().senior_claim_atoms - c1, leg2 - leg2 / 2, "Earn keeps the other half");
    // GH#571: the unpaid rest is CARRIED as arrears, not forfeited
    assert_eq!(tr2.coupon_arrears_atoms, due2 - leg2 / 2, "carried arrears");
    // ... interval 3: SHORT (1 slot) with a fat leg -> that slot's due on the full claim PLUS the
    // arrears carried from interval 2 (GH#571: cumulative)
    env.hold(1, &[lp.portfolio]);
    round(&mut env, 6);
    let due3 = bond_v20::coupon_settle(
        tr2.c_b_atoms,
        tr2.coupon_arrears_atoms,
        2_000,
        env.slot - tr2.last_coupon_slot,
        true,
        tr2.claim_total().unwrap(),
    )
    .unwrap();
    let c2 = env.vlp().senior_claim_atoms;
    env.crank_fees_bond(lp.portfolio).expect("78 short");
    let tr3 = env.tranche();
    assert!(due3 > tr2.coupon_arrears_atoms, "vacuity: the carry plus this slot");
    assert_eq!(tr3.c_b_atoms - tr2.c_b_atoms, due3, "cumulative: the carried arrears + this interval's due");
    assert_eq!(tr3.coupon_arrears_atoms, 0);
    assert!(env.vlp().senior_claim_atoms > c2, "seniors take the rest");
    // the holder exits at principal + every coupon (+ the accrual 110 settles over the cooldown)
    env.bond_request(&h, 3_000 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    let _ = env.crank_fees_bond(lp.portfolio);
    let tr4 = env.tranche();
    let k = tr4.claim_total().unwrap();
    let settle = bond_v20::coupon_settle(tr4.c_b_atoms, tr4.coupon_arrears_atoms, 2_000, env.slot - tr4.last_coupon_slot, true, k).unwrap();
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110");
    assert_eq!(paid as u128, tr4.c_b_atoms + settle, "principal + coupons + the settled accrual");
    assert!(paid as u128 > 3_000 * U as u128);
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    env.earn_execute(&d, Some(lp.portfolio)).expect("senior");
    env.assert_conserved("coupon");
}

// ── Resolved ────────────────────────────────────────────────────────────────────────────────

/// Resolved: the vault LP settles into the pots (101); the bonds exit from the pots (110,
/// Resolved path) at their layer of the PHYSICAL backing; the junior's terminal sweep (102) is
/// the surplus over the seniors AND the bonds' claim, and fails closed without the tranche.
/// NEGATIVE CONTROL: MB3 (102 two-tranche) lets the junior sweep the bonds' 2,000.
#[test]
fn bond_resolved_exit_and_junior_after_bonds() {
    let (mut env, lp, d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    let admin = env.admin.insecure_clone();
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("101 settle");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("terminal-flat");
    let t = Some(env.tranche_key());
    assert!(env.release_surplus_resolved_bond(&admin, lp.portfolio, 1, junior_dest, None).is_err(), "102 Resolved without [11]");
    let wrong = env.ext_key();
    assert!(env.release_surplus_resolved_bond(&admin, lp.portfolio, 1, junior_dest, Some(wrong)).is_err(), "102 with a wrong [11]");
    // physical 15,000 - C 10,000 - C_b 2,000 = 3,000 for the junior, not 5,000
    err_has(&env.release_surplus_resolved_bond(&admin, lp.portfolio, 3_000 * U as u128 + 1, junior_dest, t), PercolatorError::VaultLpReleaseRefused);
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    let paid_b = env.bond_execute(&h, lp.portfolio, 2_000 * U).expect("110 Resolved, from the pots");
    assert_eq!(paid_b, 2_000 * U, "bonds whole before the junior");
    let before = env.tok(junior_dest);
    env.release_surplus_resolved_bond(&admin, lp.portfolio, 3_000 * U as u128, junior_dest, t).expect("junior sweep");
    assert_eq!(env.tok(junior_dest) - before, 3_000 * U);
    env.paid_out += 3_000 * U as u128;
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let paid_s = env.earn_execute(&d, Some(lp.portfolio)).expect("senior");
    assert_eq!(paid_s as u128, 10_000 * U as u128 * shares / (shares + 1_000));
    env.assert_conserved("resolved");
}

/// Codes are explicit and pinned (SDK error maps).
#[test]
fn bond_error_codes_and_tags_are_pinned() {
    assert_eq!(PercolatorError::BondTrancheImpaired as u32, 107);
    assert_eq!(PercolatorError::BondCapacityLocked as u32, 108);
    assert_eq!(PercolatorError::BondWithdrawCooldown as u32, 109);
    assert_eq!(PercolatorError::BondConfigInvalid as u32, 110);
    assert_eq!(PercolatorError::BondDepositAboveCap as u32, 123);
    assert_eq!(PercolatorError::BondSlippage as u32, 124);
    let enc = |ix: ProgInstruction| ix.encode();
    assert_eq!(enc(ProgInstruction::InitBondTranche { coupon_bps: 1, util_bonus_bps: 2, cooldown_slots: 3, cap_bps: 4 }).len(), 11);
    assert_eq!(enc(ProgInstruction::BondDeposit { amount: 1, min_shares: 2 }).len(), 25);
    assert_eq!(enc(ProgInstruction::BondRequestWithdraw { shares: 1 }).len(), 17);
    assert_eq!(enc(ProgInstruction::BondExecuteWithdraw { min_out: 1, source_domain: 1 }).len(), 11);
    for (ix, tag) in [
        (ProgInstruction::InitBondTranche { coupon_bps: 800, util_bonus_bps: 0, cooldown_slots: 9_000, cap_bps: 5_000 }, 107u8),
        (ProgInstruction::BondDeposit { amount: 7, min_shares: 9 }, 108),
        (ProgInstruction::BondRequestWithdraw { shares: 5 }, 109),
        (ProgInstruction::BondExecuteWithdraw { min_out: 3, source_domain: 1 }, 110),
    ] {
        let e = ix.encode();
        assert_eq!(e[0], tag);
        assert_eq!(ProgInstruction::decode(&e).unwrap().encode(), e, "round trip");
    }
    // GH#571 layout v2: 128 -> 144 (coupon_arrears_atoms appended at 128..144).
    assert_eq!(std::mem::size_of::<state::BondTrancheV20>(), 144);
    assert_eq!(percolator_prog::constants::BOND_TRANCHE_VERSION, 2);
    assert_eq!(std::mem::size_of::<state::BondPositionV20>(), 96);
}

/// Tag 78 fails closed without the tranche once it exists (the coupon cannot be skipped by
/// omitting [9]); with it the leg is harvested. Inert before 107 (control): the P2b tail alone.
#[test]
fn bond_fee_crank_requires_the_tranche() {
    {
        let (mut env, lp, _d) = p2b_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 2_000);
        let t = env.new_trader(1_000 * U);
        env.allocate(lp.portfolio, 1_000 * U as u128).expect("103 creates the ext");
        env.trade(&t, &lp, 100 * UQ).expect("open");
        env.trade(&t, &lp, -100 * UQ).expect("close");
        env.crank_fees_ext(lp.portfolio).expect("control: no tranche, the P2b tail is enough");
    }
    let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 2_000, 0, 800);
    let t = env.new_trader(1_000 * U);
    env.trade(&t, &lp, 100 * UQ).expect("open");
    env.trade(&t, &lp, -100 * UQ).expect("close");
    assert!(env.crank_fees_ext(lp.portfolio).is_err(), "78 without [9] once the tranche exists");
    env.crank_fees_bond(lp.portfolio).expect("78 with [9]");
}


impl Env {
    /// Crank `portfolio` repeatedly at the CURRENT slot (24 cranks per transaction) until the
    /// asset's accrual clock reaches it: the engine catches up one slot per crank here
    /// (max_accrual_dt_slots = 1), exactly what a keeper that missed slots would have to do.
    fn catch_up(&mut self, portfolio: Pubkey) {
        let payer_key = self.payer.pubkey();
        for _ in 0..2_000 {
            if self.market_state().1.assets[0].slot_last >= self.slot {
                return;
            }
            let ix = (
                ProgInstruction::PermissionlessCrank {
                    now_slot: self.slot,
                    observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
                },
                vec![
                    AccountMeta::new(payer_key, true),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(portfolio, false),
                ],
            );
            let r = self.send_many(vec![ix; 24], &[]);
            if r.is_err() {
                // the last partial batch can hit NonProgress once current: one at a time
                let _ = self.crank(portfolio);
            }
        }
        panic!("catch_up did not converge");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Regressions ported from the security review of #530 (Sentinel, 2026-10-05;
// ~/wt-sec-v22c/percolator-prog/tests/sec_v22c_adv.rs). sec_c1 is INVERTED: it demonstrated the
// M-1 finding and now pins the fix.
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// Leave the bond tranche impaired (junior 500 gone, bonds -500) with the vault LP flat.
fn impaired_bond_world(coupon_bps: u16) -> (Env, Lp, Depositor, BondHolder, Trader) {
    let (mut env, lp, d, h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 500, 1_000, coupon_bps);
    let t = env.new_trader(5_000 * U);
    env.trade(&t, &lp, 1_000 * UQ).expect("long");
    env.move_price(20_000_000, &[t.portfolio, lp.portfolio]);
    env.trade(&t, &lp, -1_000 * UQ).expect("close");
    env.hold(12, &[t.portfolio, lp.portfolio]);
    let _ = env.crank_fees_bond(lp.portfolio);
    (env, lp, d, h, t)
}

/// SEC-C1 / M-1: an IMPAIRED tranche earns no coupon (before the fix it earned the coupon on its
/// FULL claim, 2x what its value would earn at 50% impairment, paid out of Earn's fee leg). The
/// whole leg goes to the seniors. CONTROL: the identical crank on a WHOLE tranche pays the
/// coupon. Negative control: mutant MB7 (impairment gate removed, base = C_b) fails this test.
#[test]
fn sec_c1_impaired_bond_earns_no_coupon() {
    let run = |impaired: bool| -> (u128, u128, u128) {
        let (mut env, lp, _d, _h, t) = if impaired {
            impaired_bond_world(2_000)
        } else {
            let (mut env, lp, d, h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 500, 1_000, 2_000);
            let t = env.new_trader(5_000 * U);
            env.hold(1, &[lp.portfolio]);
            (env, lp, d, h, t)
        };
        let s = env.split3(lp.portfolio);
        let tr = env.tranche();
        if impaired {
            assert_eq!(s.junior, 0);
            assert!(s.bond < tr.c_b_atoms, "vacuity: bonds impaired");
        } else {
            assert_eq!(s.bond, tr.c_b_atoms, "control: bonds whole");
        }
        env.slot += 500_000;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio, t.portfolio]);
        let t2 = env.new_trader(20_000 * U);
        for _ in 0..6 {
            env.trade(&t2, &lp, 200 * UQ).expect("open");
            env.trade(&t2, &lp, -200 * UQ).expect("close");
        }
        let tr0 = env.tranche();
        let avail = {
            let (cfg, _) = env.market_state();
            cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms
        };
        let c0 = env.vlp().senior_claim_atoms;
        let k0 = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0);
        env.crank_fees_bond(lp.portfolio).expect("78");
        let coupon = env.tranche().c_b_atoms - tr0.c_b_atoms;
        let senior = env.vlp().senior_claim_atoms - c0;
        // Round 3 (GAP-8): the bond tranche's ext carries the default cushion (20% / 50%), so the
        // Earn side of the leg is seniors + the junior cushion.
        let cushion = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0) - k0;
        eprintln!("SEC-C1 impaired={impaired}: leg {avail} coupon {coupon} senior-credit {senior} cushion {cushion}");
        (avail, coupon, senior + cushion)
    };
    let (leg_i, coupon_i, senior_i) = run(true);
    let (leg_w, coupon_w, senior_w) = run(false);
    assert!(leg_i > 0 && leg_w > 0, "vacuity: fee legs");
    assert_eq!(coupon_i, 0, "M-1: an impaired tranche earns nothing");
    assert_eq!(senior_i, leg_i, "the whole leg goes to Earn's side (seniors + junior cushion), none to bonds");
    assert!(coupon_w > 0, "control: a whole tranche earns its coupon");
    assert_eq!(coupon_w + senior_w, leg_w);
}

/// SEC-M1 / M-3 (accepted, documented): ONE dust position against the vault LP blocks every
/// Live bond exit (the engine's withdraw is flat-only); closing it restores the par exit.
#[test]
fn sec_m1_dust_position_blocks_live_bond_exit() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    let g = env.new_trader(10 * U);
    env.trade(&g, &lp, UQ / 1000).expect("griefer buys 0.001 unit");
    assert_ne!(env.position(lp.portfolio), 0);
    env.wait_cooldown(&[lp.portfolio, g.portfolio]);
    assert!(env.bond_execute(&h, lp.portfolio, 0).is_err(), "M-3: blocked by a dust position");
    env.trade(&g, &lp, -UQ / 1000).expect("griefer closes");
    env.hold(1, &[lp.portfolio, g.portfolio]);
    assert_eq!(env.bond_execute(&h, lp.portfolio, 0).expect("control"), 2_000 * U);
}

/// SEC-A1: a holder cannot execute or request on another holder's position.
#[test]
fn sec_a1_position_substitution_refused() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    let mallory = env.new_bond_holder();
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    let dest = env.token_account(env.mint, mallory.kp.pubkey(), 0);
    let forged = BondHolder { kp: mallory.kp.insecure_clone(), source: mallory.source, position: h.position };
    let ix = env.bond_execute_ix(&forged, lp.portfolio, dest, 0);
    let kp = mallory.kp.insecure_clone();
    err_has(&env.send_many(vec![ix], &[&kp]), PercolatorError::BondConfigInvalid);
    err_has(&env.bond_request(&forged, 1), PercolatorError::BondConfigInvalid);
    assert_eq!(env.bond_execute(&h, lp.portfolio, 0).expect("control: the owner exits"), 2_000 * U);
}

/// SEC-D1: a dust deposit cannot move the coupon checkpoint while a fee leg is pending.
#[test]
fn sec_d1_deposit_requires_harvest() {
    let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
    let t = env.new_trader(10_000 * U);
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.trade(&t, &lp, 1_000 * UQ).expect("open");
    env.trade(&t, &lp, -1_000 * UQ).expect("close");
    let g = env.new_bond_holder();
    let last = env.tranche().last_coupon_slot;
    err_has(&env.bond_deposit(&g, lp.portfolio, 1, 0), PercolatorError::VaultLpHarvestPending);
    assert_eq!(env.tranche().last_coupon_slot, last, "checkpoint untouched");
}

/// SEC-L1: a junior withdrawing ahead of the coupon crank cannot reach bond value.
#[test]
fn sec_l1_junior_ahead_of_the_coupon_crank_cannot_reach_bonds() {
    for crank_first in [true, false] {
        let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
        let t = env.new_trader(10_000 * U);
        env.slot += 500_000;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        for _ in 0..6 {
            env.trade(&t, &lp, 1_000 * UQ).expect("open");
            env.trade(&t, &lp, -1_000 * UQ).expect("close");
        }
        if crank_first {
            env.crank_fees_bond(lp.portfolio).expect("78");
        }
        let _ = env.max_junior_out_bond(lp.portfolio);
        if !crank_first {
            env.crank_fees_bond(lp.portfolio).expect("78");
        }
        let s = env.split3(lp.portfolio);
        assert_eq!(s.bond, env.tranche().c_b_atoms, "bonds whole whatever the order (crank_first {crank_first})");
        env.assert_conserved("sec_l1");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Re-review of #530 @ e2e5653f (2026-10-06): N-1 and N-2.
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// N-1 (ported from sec_v22c_adv2.rs::sec2_deferral_on_stale_lp). MEASURED ROOT CAUSE: tag 78's
/// own harvest advances `risk_epoch`, so once the vault LP holds inventory a certificate taken
/// before 78 is ALWAYS stale inside it. The pre-fix code then DEFERRED the coupon (the bonds got
/// nothing on every such crank, and anyone could force it by cranking 78 ahead of the keeper);
/// failing closed on it would have bricked 78. Fix: 78 RE-CERTIFIES the vault LP
/// (`full_account_refresh_not_atomic`, as tag 5 / 103 do) before valuing the bonds; any failure
/// fails 78 closed, nothing is deferred.
/// (a) the stale-timed crank (inventory, mark moved, NOTHING cranked) pays the full coupon
///     `min(due, leg / 2)` and moves the checkpoint -- the bonds cannot be starved by timing;
/// (b) with the vault LP passed read-only (no refresh possible) 78 FAILS CLOSED: nothing
///     harvested, tranche and Earn untouched.
/// Negative control: mutant MB9 (no in-instruction refresh) fails (a).
#[test]
fn sec2_n1_fee_crank_on_a_stale_vault_lp_pays_or_fails_closed() {
    let setup = || {
        let (mut env, lp, d, h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
        let t = env.new_trader(10_000 * U);
        env.slot += 500_000;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        env.trade(&t, &lp, 500 * UQ).expect("open: the vault LP holds inventory");
        env.hold(1, &[]); // mark re-pushed one slot later, NOTHING cranked
        (env, lp, d, h, t)
    };
    // (b) read-only vault LP: fail closed
    let (mut env, lp, _d, _h, _t) = setup();
    let (tr0, c0) = (env.tranche(), env.vlp().senior_claim_atoms);
    let w0 = env.market_state().0.lp_fee_withdrawn_atoms;
    assert!(env.crank_fees_bond_lp(lp.portfolio, false).is_err(), "N-1: no valuation, no harvest");
    assert_eq!(env.tranche(), tr0);
    assert_eq!(env.vlp().senior_claim_atoms, c0);
    assert_eq!(env.market_state().0.lp_fee_withdrawn_atoms, w0, "leg not harvested");
    // (a) the stale-timed crank pays in full
    let (mut env, lp, _d, _h, _t) = setup();
    let tr0 = env.tranche();
    let (cfg, _) = env.market_state();
    let leg = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    let due = bond_v20::coupon_due(tr0.c_b_atoms, 2_000, env.slot - tr0.last_coupon_slot).unwrap();
    let c0 = env.vlp().senior_claim_atoms;
    env.crank_fees_bond(lp.portfolio).expect("78 re-certifies the vault LP and harvests");
    let tr1 = env.tranche();
    let coupon = tr1.c_b_atoms - tr0.c_b_atoms;
    eprintln!("N-1 stale-timed crank: leg {leg} due {due} coupon {coupon}");
    assert!(leg > 0 && due > 0, "vacuity");
    assert_eq!(coupon, due.min(leg / 2), "full coupon, not deferred");
    assert_eq!(coupon + (env.vlp().senior_claim_atoms - c0), leg);
    assert_eq!(tr1.last_coupon_slot, env.slot, "checkpoint moved");
}

/// N-2: a dust Earn deposit made before tag 107 permanently disables bonds on that market (107
/// is refused once any Earn exists, M-2). The SAFE LAUNCH is atomic: create the LP vault (74),
/// bind it (94) and create the bond tranche (107) in ONE transaction, which leaves no window for
/// any Earn deposit. This test (a) shows the grief on the unbundled path, (b) builds the bundle
/// as a real transaction (the two program-owned accounts tag 94 needs are created by system
/// create_account inside it), checks it fits one packet, and (c) that the market then takes Earn
/// and bonds normally.
#[test]
fn sec2_n2_atomic_launch_bundle_cannot_be_front_run() {
    // (a) unbundled: anyone's dust Earn deposit between 69 and 107 disables bonds for good
    let mut env = Env::new(Params::default());
    let griefer = env.new_depositor();
    env.earn_deposit(&griefer, U, None).expect("minimum-size Earn deposit before the bind");
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    err_has(&env.init_bond_tranche_as(&admin, (800, 0, COOLDOWN, 5_000)), PercolatorError::BondConfigInvalid);
    let _ = lp;

    // (b) the atomic launch bundle
    let mut env = Env::new_bare(Params::default(), matcher_program_path());
    let admin = env.admin.insecure_clone();
    let a = admin.pubkey();
    env.set_program_data_authority(&a);
    let lp_kp = Keypair::new();
    let ctx_kp = Keypair::new();
    let (lp, ctx) = (lp_kp.pubkey(), ctx_kp.pubkey());
    let delegate = Pubkey::find_program_address(
        &[b"matcher", env.market.as_ref(), lp.as_ref(), env.registry.as_ref(), env.matcher.as_ref(), ctx.as_ref()],
        &env.pid,
    )
    .0;
    let rent = |n: usize| env.svm.minimum_balance_for_rent_exemption(n);
    let (plen, plen_rent, ctx_rent) = (env.plen, rent(env.plen), rent(MATCHER_CONTEXT_LEN));
    let ix = |pid: Pubkey, ix: ProgInstruction, accounts: Vec<AccountMeta>| Instruction { program_id: pid, accounts, data: ix.encode() };
    let pd = env.program_data_key();
    let instructions = vec![
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        solana_sdk::system_instruction::create_account(&admin.pubkey(), &lp, plen_rent, plen as u64, &env.pid),
        solana_sdk::system_instruction::create_account(&admin.pubkey(), &ctx, ctx_rent, MATCHER_CONTEXT_LEN as u64, &env.matcher),
        ix(env.pid, ProgInstruction::CreateLpVault { fee_share_bps: 5_000, redemption_cooldown_slots: BOUND_COOLDOWN, oi_reservation_threshold_bps: 0, domain: DOMAIN }, vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new(env.lp_mint, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(env.mint, false), // [6] collateral mint (prog#542)
        ]),
        ix(env.pid, ProgInstruction::InitVaultLp { junior_floor_bps: 2_000 }, vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new(env.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(env.ledger, false),
            AccountMeta::new_readonly(env.sibling, false),
            AccountMeta::new_readonly(env.matcher, false),
            AccountMeta::new(ctx, false),
            AccountMeta::new_readonly(delegate, false),
        ]),
        ix(env.pid, ProgInstruction::InitBondTranche { coupon_bps: 800, util_bonus_bps: 0, cooldown_slots: COOLDOWN, cap_bps: 5_000 }, vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new_readonly(env.vault_lp, false),
            AccountMeta::new(env.ext_key(), false),
            AccountMeta::new(env.tranche_key(), false),
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(pd, false),
        ]),
    ];
    env.svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(&instructions, Some(&admin.pubkey()), &[&admin, &lp_kp, &ctx_kp], env.svm.latest_blockhash());
    let size = bincode::serialize(&tx).unwrap().len();
    eprintln!("N-2 launch bundle (74 + 94 + 107 + 2 create_account): {size} bytes");
    assert!(size <= 1_232, "the launch bundle must fit one packet: {size} B");
    env.svm.send_transaction(tx).map_err(|e| format!("{e:?}")).expect("atomic launch bundle");
    assert_eq!(env.registry_state()._reserved[0], 1, "bound");
    assert_eq!(env.registry_state()._reserved[2], 1, "bond tranche exists");
    // (c) the market then takes Earn and bonds normally
    let lpv = Lp { portfolio: lp, owner_key: env.registry, ctx, delegate };
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000 * U, Some(lpv.portfolio)).expect("Earn after the launch");
    env.junior_deposit_as(&admin, lpv.portfolio, 2_000 * U).expect("junior");
    let h = env.new_bond_holder();
    env.bond_deposit(&h, lpv.portfolio, 1_000 * U, 1).expect("bond");
    assert_eq!(env.tranche().c_b_atoms, 1_000 * U as u128);
    env.assert_conserved("launch bundle");
}


/// Follow-up to the approval of #530 @ 80d3a906: tag 78 values the vault LP at
/// min(certified equity, the LAG-WORSE equity 108/110 use), so the coupon gate cannot open while
/// 108/110 call the tranche impaired. Setup: seniors 10,000, junior 500, bonds 1,000; a trader
/// long 1,000 units vs the vault LP; a fee leg pending; the mark target jumps +100% while the
/// effective price has moved only one 5% step. At the effective price the bonds are whole (LP -50
/// < junior 500); at the worse price they are impaired (LP -1,000 > junior 500). 78 must pay NO
/// coupon, and 108 must call the tranche impaired in the same state. CONTROL: no target jump ->
/// 78 pays the coupon. Negative control: mutant MB10 (no lag-worse term) pays the coupon in the
/// lag case and fails this test.
#[test]
fn bond_coupon_gate_uses_the_lag_worse_value_like_108_110() {
    let run = |lag: bool| -> (u128, u128, Result<(), String>) {
        let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 500, 1_000, 2_000);
        env.slot += 500_000;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        let f = env.new_trader(20_000 * U);
        for _ in 0..6 {
            env.trade(&f, &lp, 200 * UQ).expect("fee open");
            env.trade(&f, &lp, -200 * UQ).expect("fee close");
        }
        let t = env.new_trader(5_000 * U);
        env.trade(&t, &lp, 1_000 * UQ).expect("long 1,000 vs the vault LP");
        let target = if lag { 2 * PRICE } else { PRICE };
        let admin = env.admin.insecure_clone();
        env.slot += 1;
        env.svm.warp_to_slot(env.slot);
        let seq = env.oracle_seq() + 1;
        let m = env.market;
        env.send(
            ProgInstruction::PushAuthMark { market_id: 1, asset_index: 0, now_slot: env.slot, mark_e6: target, observation_sequence: seq },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
        .expect("push mark");
        env.crank(lp.portfolio).expect("crank vault LP");
        env.crank(t.portfolio).expect("crank trader");
        let g = env.market_state().1;
        if lag {
            assert!(g.assets[0].effective_price < g.assets[0].raw_oracle_target_price, "vacuity: a pending lag");
        }
        let cb0 = env.tranche().c_b_atoms;
        let c0 = env.vlp().senior_claim_atoms;
        let (cfg, _) = env.market_state();
        let leg = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
        let k0 = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0);
        env.crank_fees_bond(lp.portfolio).expect("78");
        let coupon = env.tranche().c_b_atoms - cb0;
        // Round 3 (GAP-8): + the default junior cushion's share.
        let cushion = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0) - k0;
        assert_eq!(coupon + (env.vlp().senior_claim_atoms - c0) + cushion, leg);
        let h2 = env.new_bond_holder();
        let r108 = env.bond_deposit(&h2, lp.portfolio, U, 1);
        eprintln!("LAG-WORSE lag={lag}: leg {leg} coupon {coupon} 108 -> {:?}", r108.as_ref().map_err(|e| e.chars().take(70).collect::<String>()));
        (leg, coupon, r108)
    };
    let (leg_l, coupon_l, r108_l) = run(true);
    let (leg_c, coupon_c, _) = run(false);
    assert!(leg_l > 0 && leg_c > 0, "vacuity: fee legs");
    err_has(&r108_l, PercolatorError::BondTrancheImpaired);
    assert_eq!(coupon_l, 0, "78 agrees with 108: impaired at the worse price, no coupon");
    assert!(coupon_c > 0, "control: no lag, the coupon is paid");
}

/// Security review W-L1 (v2.2 growth overnight): on a CLAMP-ENFORCED (band) market the bond
/// withdrawal lock sizes capacity with λ_eff = min(stored λ, λ_depth(tier)), not the stored λ.
/// STATE POKE: the stored λ is set to 2x (the value a band market's UA dial may set, tag 93; this
/// harness has no UA mock). With no depth the tier is 0, so λ_eff = 1x and the gate admits OI up
/// to C_m/P = 2,000 units. 1,500 units open on each side, then a 1,000 bond exit (C_m 2,000 ->
/// 1,000): N_cap after at λ_eff = 1,000 < 1,500 -> BondCapacityLocked. Before W-L1 the lock read
/// the stored 2x (N_cap after 2,000 >= 1,500) and the exit was PAID (file-copy negative control).
/// Control: once the OI closes, the same exit pays par.
#[test]
fn wl1_band_bond_lock_uses_lambda_eff_not_the_stored_lambda() {
    let p = Params { band: Some(100), ..growth_params() };
    let (mut env, lp, _d, _h) = bond_world(p, 10_000, 1_000, 0, 0);
    {
        // STATE POKE: stored λ = 2x on the band market's growth record.
        let mut acc = env.svm.get_account(&env.market).unwrap();
        let mut g = state::read_asset_growth(&acc.data, 0, 1_000).unwrap().expect("growth on");
        assert_eq!(Some(g.r_gap_bps), percolator_prog::growth_v19::band_r_gap_bps(100), "clamp-enforced");
        g.lambda_bps = 20_000;
        state::write_asset_growth(&mut acc.data, 0, &g, 1_000).unwrap();
        env.svm.set_account(env.market, acc).unwrap();
    }
    let attacker = env.new_bond_holder();
    env.bond_deposit(&attacker, lp.portfolio, 1_000 * U, 1).expect("bond");
    env.bond_request(&attacker, 1_000 * U as u128).expect("109");
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.catch_up(lp.portfolio);
    let long = env.new_trader(100_000 * U);
    env.trade_signing_fee(&long, &lp, 1_500 * UQ, GROWTH_FEE).expect("long 1,500 (inside N_cap 2,000 at 1x)");
    let short = env.new_trader(100_000 * U);
    env.trade_signing_fee(&short, &lp, -1_500 * UQ, GROWTH_FEE).expect("short 1,500");
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio);
    err_has(&env.bond_execute(&attacker, lp.portfolio, 0), PercolatorError::BondCapacityLocked);
    env.trade_signing_fee(&long, &lp, -1_500 * UQ, GROWTH_FEE).expect("close long");
    env.trade_signing_fee(&short, &lp, 1_500 * UQ, GROWTH_FEE).expect("close short");
    let _ = env.crank(lp.portfolio);
    let _ = env.crank_fees_bond(lp.portfolio);
    let paid = env.bond_execute(&attacker, lp.portfolio, 0).expect("exit once nothing is open");
    assert_eq!(paid, 1_000 * U, "par (coupon 0)");
    env.assert_conserved("wl1");
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// v2.2 round 3, item 1 (adaptive-controller design GAP-8 / LP-plan audit §4 item 8): Earn
// allocation alpha <= 50% on EVERY market (band or not) until F3 is proven -- a protocol cap the
// upgrade authority cannot exceed.
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// GAP-8 on a CLAMP-ENFORCED band market (where round 2 let the UA set up to 70% on devnet):
/// tag 99 refuses alpha 50.01% and 70% (InvalidInstruction) and accepts 50%. A record written
/// before round 3 that already holds 70% (STATE POKE: the value the round-2 setter accepted)
/// still validates (no read fails) but tag 103 allocates at most floor(50% * C_eff). Negative
/// control (file copy): without `alloc_alpha_in_force_bps` the same allocate moves 7,000 (70%).
#[test]
fn r3_gap8_alpha_capped_at_50_on_a_band_market_until_f3_proven() {
    use percolator_prog::growth_v19 as gv;
    assert_eq!(gv::alloc_alpha_max_bps(true), 5_000, "F3 is not proven in this round");
    let p = Params { band: Some(100), ..growth_params() };
    let (mut env, lp, _d) = p2b_world(p, 10_000, 1_000);
    {
        let acc = env.svm.get_account(&env.market).unwrap();
        let g = state::read_asset_growth(&acc.data, 0, 1_000).unwrap().expect("growth on");
        assert_eq!(Some(g.r_gap_bps), gv::band_r_gap_bps(100), "clamp-enforced band market");
    }
    let admin = env.admin.insecure_clone();
    err_has(&env.set_p2b_dials(&admin, [5_001, 3_000, 2_000, 5_000]), PercolatorError::InvalidInstruction);
    err_has(&env.set_p2b_dials(&admin, [7_000, 3_000, 2_000, 5_000]), PercolatorError::InvalidInstruction);
    env.set_p2b_dials(&admin, [5_000, 3_000, 2_000, 5_000]).expect("50% accepted on a band market");
    // STATE POKE: the pre-round-3 band record at 70%.
    {
        let key = env.ext_key();
        let mut acc = env.svm.get_account(&key).unwrap();
        let mut x = state::read_vault_lp_ext(&acc.data).unwrap();
        x.alloc_alpha_bps = 7_000;
        state::write_vault_lp_ext(&mut acc.data, &x).unwrap();
        env.svm.set_account(key, acc).unwrap();
        assert_eq!(env.ext().unwrap().alloc_alpha_bps, 7_000, "a 70% record still validates");
    }
    let c = env.vlp().senior_claim_atoms;
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    let a = env.allocated();
    eprintln!("GAP-8: C {c} allocated {a}");
    assert!(a > 0, "vacuity: something allocated");
    assert!(a <= c / 2, "alpha in force is 50%: allocated {a} of C {c}");
    assert_eq!(a, c / 2, "the alpha room binds (the buffer room is 70% of C here)");
    env.assert_conserved("gap8 alpha");
}

impl Env {
    /// Tag 63, 44 B attested form (PushAuthMarkDepth), price unchanged.
    fn push_depth_attested(&mut self, depth_e6: u64) -> Result<(), String> {
        let admin = self.admin.insecure_clone();
        let px = self.market_state().1.assets[0].effective_price;
        let seq = self.oracle_seq() + 1;
        let (m, slot) = (self.market, self.slot);
        self.send(
            ProgInstruction::PushAuthMarkDepth { market_id: 1, asset_index: 0, now_slot: slot, mark_e6: px, observation_sequence: seq, depth_mode: 1, depth_e6 },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
    }
}

/// Round 3 item 7 (design GAP-13c): tag 94's bind-time guard. On a clamp-enforced band market
/// that already has a measured depth, one minimum band leg must fit in the tier-0 depth capacity
/// (κ0 = 0.5 x the usable depth), else the bind is refused (GrowthInvalidConfig) instead of
/// creating a market that can never open a leg. This harness's collateral has 0 decimals, so T1
/// = 25,000 atoms and a first reading is clamped to T1/16 = 1,562 atoms (D-I1); the minimum leg
/// is set to 600 atoms (STATE POKE of the engine config). A 1,000-atom pool (capacity 500) is
/// refused; a 5,000-atom pool (usable 1,562 -> capacity 781) binds. CONTROL: no depth measured
/// yet binds.
#[test]
fn r3_item7_bind_guard_min_leg_fits_tier0_depth() {
    let p = Params { band: Some(100), ..growth_params() };
    let poke_min_leg = |env: &mut Env| {
        let mut acc = env.svm.get_account(&env.market).unwrap();
        {
            let (_, g) = state::market_view_mut(&mut acc.data).unwrap();
            g.header.config.band_min_leg_notional = percolator::V16PodU64::new(600);
        }
        env.svm.set_account(env.market, acc).unwrap();
    };
    for (depth, ok) in [(1_000u64, false), (5_000, true)] {
        let mut env = Env::new(p);
        poke_min_leg(&mut env);
        let d = env.new_depositor();
        env.earn_deposit(&d, 1_000 * U, None).expect("75 senior");
        env.slot += 1;
        env.svm.warp_to_slot(env.slot);
        env.push_depth_attested(depth).expect("push 1");
        env.slot += 1;
        env.svm.warp_to_slot(env.slot);
        env.push_depth_attested(depth).expect("push 2 (a fresh pair)");
        let admin = env.admin.insecure_clone();
        let m = env.matcher;
        let r = env.init_vault_lp_full(&admin, 2_000, m, &[]);
        if ok {
            r.expect("usable 1,562 atoms: 781 of capacity fits a 600-atom leg");
        } else {
            err_has(&r.map(|l| l.portfolio), PercolatorError::GrowthInvalidConfig);
            assert!(env.svm.get_account(&env.vault_lp).map(|a| a.data.is_empty()).unwrap_or(true), "the bind reverted");
        }
    }
    // control: never measured -> binds
    let mut env = Env::new(p);
    poke_min_leg(&mut env);
    let admin = env.admin.insecure_clone();
    let m = env.matcher;
    env.init_vault_lp_full(&admin, 2_000, m, &[]).expect("no depth yet: binds");
}

/// Security review F-2: the ratchet touch is BEST-EFFORT. With the growth record made invalid
/// (flags byte 39 = 0x02, STATE POKE) the fee crank with the vault LP at [8] still harvests (Ok)
/// and leaves the growth bytes untouched. Tag 78 reads the growth record ONLY through the touch,
/// so this forces the touch's error path; both sites (tag 5 on the vault LP, tag 78) call the
/// same `growth_ratchet_touch_best_effort`, so this covers the tag-5 site's code too. (Tag 5
/// itself reads the growth record earlier, in the crank's own accrual / clamp checks, which
/// still fail closed on a corrupt record: no state makes ONLY the tag-5 touch fail.)
/// NEGATIVE CONTROL (file copy): with the round-3 `growth_ratchet_touch(..)?` the harvest reverts.
#[test]
fn f2_ratchet_touch_error_never_reverts_the_fee_crank() {
    let p = Params { band: Some(100), growth: Some((400, 500)), fee_bps: 100, ..growth_params() };
    let (mut env, lp, _d) = p2b_world(p, 10_000, 1_000);
    let admin = env.admin.insecure_clone();
    env.set_p2b_dials(&admin, [5_000, 3_000, 0, 0]).expect("ext");
    let t = env.new_trader(5_000 * U);
    env.trade_signing_fee(&t, &lp, 100 * UQ, GROWTH_FEE).expect("open");
    env.trade_signing_fee(&t, &lp, -100 * UQ, GROWTH_FEE).expect("close");
    let mut acc = env.svm.get_account(&env.market).unwrap();
    let r = state::asset_growth_range(&acc.data, 0).unwrap();
    acc.data[r.start + 39] = percolator_prog::growth_v19::GROWTH_FLAG_VOL_DATA;
    let before = acc.data[r.clone()].to_vec();
    env.svm.set_account(env.market, acc).unwrap();
    assert!(state::read_asset_growth(&env.svm.get_account(&env.market).unwrap().data, 0, 1_000).is_err(), "vacuity: the record is refused");
    let (cfg0, _) = env.market_state();
    env.crank_fees_ext(lp.portfolio).expect("F-2: 78 with the LP succeeds despite the growth error");
    let (cfg1, _) = env.market_state();
    assert!(cfg1.lp_fee_withdrawn_atoms > cfg0.lp_fee_withdrawn_atoms, "the leg was harvested");
    let after = env.svm.get_account(&env.market).unwrap().data[r].to_vec();
    assert_eq!(after, before, "the touch wrote nothing");
}

/// Round 3 item 7 (GAP-15): tag 78 with the ext tail (vault LP at [8]) is a ratchet site. A
/// band market (L_tier 10x, launch 5x) whose stored ceiling sits above its live target
/// (STATE POKE: 8x stored, target = launch at tier 0) is lowered to the target AT ONCE (8x -> 5x;
/// security review F-1 fix A) by the fee crank alone. CONTROL: the same crank without the ext tail (no LP account) does not touch it.
#[test]
fn r3_item7_fee_crank_is_a_ratchet_site() {
    let p = Params { band: Some(100), growth: Some((400, 500)), fee_bps: 100, ..growth_params() };
    for with_lp in [true, false] {
        let (mut env, lp, _d) = p2b_world(p, 10_000, 1_000);
        let admin = env.admin.insecure_clone();
        if with_lp {
            env.set_p2b_dials(&admin, [5_000, 3_000, 0, 0]).expect("ext");
        }
        let t = env.new_trader(5_000 * U);
        env.trade_signing_fee(&t, &lp, 100 * UQ, GROWTH_FEE).expect("open");
        env.trade_signing_fee(&t, &lp, -100 * UQ, GROWTH_FEE).expect("close");
        {
            let mut acc = env.svm.get_account(&env.market).unwrap();
            let mut g = state::read_asset_growth(&acc.data, 0, 1_000).unwrap().expect("growth on");
            assert_eq!((g.l_launch_x100, g.l_tier_x100), (500, 1_000));
            g.ceil_x100 = 800;
            state::write_asset_growth(&mut acc.data, 0, &g, 1_000).unwrap();
            env.svm.set_account(env.market, acc).unwrap();
        }
        let r = if with_lp { env.crank_fees_ext(lp.portfolio) } else { env.crank_fees(true) };
        r.expect("78");
        let c = state::read_asset_growth(&env.svm.get_account(&env.market).unwrap().data, 0, 1_000).unwrap().unwrap().ceil_x100;
        if with_lp {
            assert_eq!(c, 500, "78 with the LP: down to the target at once");
        } else {
            assert_eq!(c, 800, "control: no LP account, no ratchet");
        }
    }
}

// ── GH#561: the G9 backstop receivable vs the bond tranche ───────────────────────────────────
//
// `VaultLpStateV18::backstop_outstanding_atoms` is insurance that G9 (tag 111) lent to the bound
// vault LP. Its field doc makes it senior to the Earn seniors and the junior, and bonds sit
// BETWEEN those two (`bond_v20.rs:7-8`), so it is senior to the bonds. Tags 97 / 98 / 102 add it
// to their halt argument and every senior/junior valuation nets it off; the bond paths do neither,
// which GH#561 fixes.
//
// READ THIS BEFORE TRUSTING THESE TESTS. They pass with AND without that fix, and that is not an
// oversight: on the deployed bytes a bond exit with an outstanding backstop is already refused by
// a SECOND-ORDER route. The backstop is netted off the LP's VALUE (`v16_program.rs:30519`,
// `:34420`), so while it is outstanding the LP prices below its senior claim;
// `vault_lp_draw_then_book` (called at `:41219`, before the halt) therefore re-books a senior draw
// via `vault_lp_physical_draw` (`:34625`), and that re-arms the pre-existing
// `senior_draw_outstanding` halt which bonds DO respect. Measured across 13 configurations,
// including a 1-atom backstop against a junior cushion 20x the senior claim.
//
// So these are PROPERTY tests, not regression tests for the fix: they pin "an outstanding backstop
// must not let bond value out", which currently holds by arithmetic coincidence in an unrelated
// helper rather than by an explicit guard. If anyone changes how LP value is computed, the
// second-order route stops firing and these tests are what catches the resulting hole.
//
// UPDATE (landing on feat/v22-rc2-2026-10-21): that has ALREADY happened on the RC2 line. Against
// the RC2 base canonical .so (50a336d4, sha cc720a0e) both tests below FAIL: tag 110 pays 400
// tokens at par with a 50-token backstop outstanding, and tag 108 admits a deposit. The line numbers
// above are from aca02ba6. So on RC2 these are true REGRESSION tests for the netting and halts
// added here, not only property tests.
//
// The backstop is set directly rather than driven through tag 111, the way `poke_senior_claim`
// sets up a senior claim: reaching `backstop_due` needs an exhausted-pot senior draw this suite's
// world does not build. The G9 flow itself is covered in `p4_wave_d.rs`.

/// Set an outstanding G9 backstop CONSISTENTLY: the vault-LP state field AND the asset's fill-time
/// halt mirror, which tag 111 keeps in lockstep (`v16_program.rs:38819-38820`). Setting only the
/// state field leaves the mirror stale, and that mismatch alone books a draw — so a test built on
/// it refuses for a reason unrelated to the subject under test.
fn poke_backstop_consistent(env: &mut Env, b: u64) {
    let mut acct = env.svm.get_account(&env.vault_lp).unwrap();
    let mut st = state::read_vault_lp_state(&acct.data).unwrap();
    st.backstop_outstanding_atoms = b;
    let mirror = st.senior_draw_outstanding_atoms.saturating_add(b as u128);
    state::write_vault_lp_state(&mut acct.data, &st).unwrap();
    env.svm.set_account(env.vault_lp, acct).unwrap();

    let mut m = env.svm.get_account(&env.market).unwrap();
    {
        let (_cfg, mut g) = state::market_view_mut(&mut m.data).unwrap();
        let mut rec =
            state::asset_vault_lp_draw_from_wrapper_bytes(&g.markets[0].wrapper[..]).unwrap();
        rec.outstanding_mirror_atoms = mirror;
        state::asset_vault_lp_draw_to_wrapper_bytes(&mut g.markets[0].wrapper[..], &rec).unwrap();
    }
    env.svm.set_account(env.market, m).unwrap();
}

/// Tag 110: no bond value leaves while a backstop is outstanding, and the exit pays par again once
/// it is repaid. The second assertion is the one that makes the first meaningful — it shows the
/// refusal is caused by the receivable and not by a broken world.
#[test]
fn gh561_no_bond_value_leaves_while_a_backstop_is_outstanding() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 2_000, 1_000, 0);
    let all = [lp.portfolio];
    env.bond_request(&h, 400 * U as u128).expect("109");
    env.wait_cooldown(&all);

    poke_backstop_consistent(&mut env, 50 * U);
    err_has(
        &env.bond_execute(&h, lp.portfolio, 0),
        PercolatorError::VaultLpPausedForSeniorDraw,
    );

    poke_backstop_consistent(&mut env, 0);
    let paid = env
        .bond_execute(&h, lp.portfolio, 400 * U)
        .expect("110 once nothing is owed to insurance");
    assert_eq!(paid, 400 * U, "par once the backstop is repaid");
    env.assert_conserved("gh561 exit");
}

/// Tag 108: no new bond is admitted while a backstop is outstanding — the tranche is impaired once
/// the receivable is netted, so admitting at par would harm the depositor.
#[test]
fn gh561_no_bond_is_admitted_while_a_backstop_is_outstanding() {
    let (mut env, lp, _d, _h) = bond_world(Params::default(), 10_000, 2_000, 0, 0);
    let h = env.new_bond_holder();

    poke_backstop_consistent(&mut env, 50 * U);
    err_has(
        &env.bond_deposit(&h, lp.portfolio, 100 * U, 1),
        PercolatorError::VaultLpPausedForSeniorDraw,
    );

    poke_backstop_consistent(&mut env, 0);
    env.bond_deposit(&h, lp.portfolio, 100 * U, 1)
        .expect("108 once the backstop is repaid");
    env.assert_conserved("gh561 deposit");
}

/// GH#561 review correction (REGRESSION, Resolved): the backstop halt on tag 110 is LIVE-only,
/// exactly as tag 102's. In Resolved every vault-LP payout repays the backstop first at tag 101
/// and whatever is never repaid stays a realised insurance loss that "blocks nothing in Resolved"
/// (tag 101). A residual receivable left after the LP's terminal payout (STATE POKE: 1 token, the
/// shape of a payout that fell short) must not lock the bond holders out of the pots.
/// NEGATIVE CONTROL: with the halt counting the backstop in both modes (the #562 head as
/// submitted) this exit is refused `VaultLpPausedForSeniorDraw` (89).
#[test]
fn gh561_resolved_bond_exit_is_not_halted_by_an_unrepaid_backstop() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    let admin = env.admin.insecure_clone();
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("101 settle");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("terminal-flat");
    poke_backstop_consistent(&mut env, U);
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    let paid_b = env
        .bond_execute(&h, lp.portfolio, 2_000 * U)
        .expect("110 Resolved is not halted by a residual backstop");
    assert_eq!(paid_b, 2_000 * U, "bonds whole from the pots");
    let st = state::read_vault_lp_state(&env.svm.get_account(&env.vault_lp).unwrap().data).unwrap();
    assert_eq!(st.backstop_outstanding_atoms, U, "vacuity: the receivable was outstanding during the exit");
}

/// GH#561 review (Resolved PRICING pin): the Resolved bond payout is NOT netted by a residual
/// backstop. In Resolved, tag 101 repays the backstop first and anything left is a realised
/// insurance loss; `bond_withdraw_resolved_core` prices on `resolved_bond_value(physical, C, C_b)`
/// with no backstop term (the #562 netting sits only in `bond_withdraw_live_core`). The residual
/// here (3,500) exceeds the junior cushion (physical 15,000 - C 10,000 - C_b 2,000 = 3,000), so a
/// netted price would be min(C_b, 15,000 - 3,500 - 10,000) = 1,500, not par.
/// NEGATIVE CONTROL (mutant build: `physical` netted by the backstop in the Resolved core): pays
/// 1,500 and this test fails.
#[test]
fn gh561_resolved_bond_payout_is_not_netted_by_a_residual_backstop() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 0);
    let admin = env.admin.insecure_clone();
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("101 settle");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("terminal-flat");
    poke_backstop_consistent(&mut env, 3_500 * U);
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    let paid_b = env.bond_execute(&h, lp.portfolio, 0).expect("110 Resolved");
    assert_eq!(paid_b, 2_000 * U, "Resolved bonds priced on the un-netted tranche value (par)");
    let st = state::read_vault_lp_state(&env.svm.get_account(&env.vault_lp).unwrap().data).unwrap();
    assert_eq!(st.backstop_outstanding_atoms, 3_500 * U, "vacuity: the residual exceeded the junior cushion during the exit");
}
/// GH#593. seniors 10,000, junior 2,500 (default cushion: 50% of the leg, target 20% of C_eff =
/// 2,000, so the junior is ABOVE target and the creator-fee vesting bit clears), a fee leg
/// harvested by tag 78. With a 1,000 G9 backstop receivable outstanding (STATE POKE on the
/// vault-LP state; it is senior to the junior) the junior level nets to ~1,500 < target: the cushion must still be funded and
/// the vesting bit must STAY set (creator fees locked). Control: receivable 0 -> cushion 0,
/// vested.
#[test]
fn gh593_tag78_junior_level_nets_the_backstop_receivable() {
    let run = |backstop: u64| -> (u128, u8) {
        let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 2_500, 0, 0);
        env.slot += 500_000;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        let f = env.new_trader(20_000 * U);
        for _ in 0..6 {
            env.trade(&f, &lp, 200 * UQ).expect("fee open");
            env.trade(&f, &lp, -200 * UQ).expect("fee close");
        }
        {
            let mut acct = env.svm.get_account(&env.vault_lp).unwrap();
            let mut st = state::read_vault_lp_state(&acct.data).unwrap();
            st.backstop_outstanding_atoms = backstop * U;
            state::write_vault_lp_state(&mut acct.data, &st).unwrap();
            env.svm.set_account(env.vault_lp, acct).unwrap();
        }
        let (cfg, _) = env.market_state();
        let leg = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
        assert!(leg > 0, "vacuity: a fee leg");
        let k0 = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0);
        env.crank_fees_bond(lp.portfolio).expect("78");
        let cushion = env.ext().map(|x| x.cushion_accrued_atoms).unwrap_or(0) - k0;
        let vest = env.asset_rec().p2b_flags & 1;
        eprintln!("GH593 backstop={backstop}: leg {leg} cushion {cushion} vesting-bit {vest}");
        (cushion, vest)
    };
    let (cushion_c, vest_c) = run(0);
    let (cushion_b, vest_b) = run(1_000);
    assert_eq!((cushion_c, vest_c), (0, 0), "control: junior above target, nothing to fund, vested");
    assert!(cushion_b > 0, "backstop outstanding: the junior is below target, the cushion is funded");
    assert_eq!(vest_b, 1, "backstop outstanding: creator fees stay locked");
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Handler-level tests for GH#574 (tag 108 cap read at the worse price) and GH#593 (tag 78
// junior level nets the G9 backstop). They drive the real BPF handlers; reverting ONLY the
// call-site change (the pure helper stays) fails them. Evidence in the PR description.
// ═══════════════════════════════════════════════════════════════════════════════════════════

/// GH#574. seniors 10,000, junior 2,000, no bonds yet, cap 50% of (C + junior). A trader is long
/// 1,000 units against the vault LP and the mark target jumps +100% while the effective price has
/// moved one step: the lag-worse equity sits ~950 below the effective one. At the effective price
/// the cap is ~5,975 (junior ~1,950); at the worse price it is ~5,500 (junior ~1,000). A 5,700
/// deposit passes the old reading and must be refused with BondDepositAboveCap by tag 108. A
/// 5,400 deposit is inside both readings and is admitted (the control), and with NO lag the
/// 5,700 deposit is admitted (vacuity: the refusal is due to the lag, not the size).
#[test]
fn gh574_tag108_cap_is_read_at_the_worse_for_the_vault_price() {
    let run = |lag: bool, amount: u64| -> Result<(), String> {
        let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 2_000, 0, 0);
        env.hold(1, &[lp.portfolio]);
        let t = env.new_trader(5_000 * U);
        env.trade(&t, &lp, 1_000 * UQ).expect("long 1,000 vs the vault LP");
        let target = if lag { 2 * PRICE } else { PRICE };
        let admin = env.admin.insecure_clone();
        env.slot += 1;
        env.svm.warp_to_slot(env.slot);
        let seq = env.oracle_seq() + 1;
        let m = env.market;
        env.send(
            ProgInstruction::PushAuthMark { market_id: 1, asset_index: 0, now_slot: env.slot, mark_e6: target, observation_sequence: seq },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(m, false)],
            &[&admin],
        )
        .expect("push mark");
        if lag {
            env.crank(lp.portfolio).expect("crank vault LP");
            env.crank(t.portfolio).expect("crank trader");
        }
        let g = env.market_state().1;
        if lag {
            assert!(g.assets[0].effective_price < g.assets[0].raw_oracle_target_price, "vacuity: a pending lag");
        }
        let r = env.bond_deposit(&h, lp.portfolio, amount * U, 1);
        eprintln!("GH574 lag={lag} amount={amount}: 108 -> {:?}", r.as_ref().map_err(|e| e.chars().take(70).collect::<String>()));
        r
    };
    err_has(&run(true, 5_700), PercolatorError::BondDepositAboveCap);
    run(true, 5_400).expect("control: inside the worse-price cap too");
    run(false, 5_700).expect("control: no lag, the same deposit is inside the cap");
}
// ===================== #636b: LP-stop NAV vs the counter-less value flows (tags 102 / 108 / 110 / 111) =====================
mod lev_w1 {
    use super::*;
    use percolator_prog::lev_guard_v22 as lg;

    pub fn guard_key(env: &Env) -> Pubkey {
        state::derive_lev_guard(&env.pid, &env.market).0
    }

    fn ix(op: u8) -> ProgInstruction {
        ProgInstruction::LevGuard { op, t0: 0, key: [0; 32], report: [0; 4] }
    }

    /// The upgrade authority (the ProgramData mock points at `admin` after `bind`) binds the guard.
    pub fn init(env: &mut Env) {
        let admin = env.admin.insecure_clone();
        let pd = Pubkey::find_program_address(&[env.pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
        let (m, g) = (env.market, guard_key(env));
        env.send(
            ix(lg::OP_INIT),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(m, false),
                AccountMeta::new(g, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[&admin],
        )
        .expect("guard init");
    }

    fn base_metas(env: &Env, lp: &Lp) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new_readonly(env.admin.pubkey(), false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(guard_key(env), false),
            AccountMeta::new(lp.portfolio, false),
            AccountMeta::new_readonly(env.vault_lp, false),
            AccountMeta::new_readonly(state::derive_vault_lp_ext(&env.pid, &env.market).0, false),
        ]
    }

    pub fn poke(env: &mut Env, lp: &Lp) -> Result<(), String> {
        env.svm.expire_blockhash(); // LiteSVM replays a byte-identical transaction's old result
        let metas = base_metas(env, lp);
        env.send(ix(lg::OP_POKE), metas, &[])
    }

    pub fn w1(env: &mut Env, lp: &Lp, victims: &[Pubkey]) -> Result<(), String> {
        env.svm.expire_blockhash(); // LiteSVM replays a byte-identical transaction's old result
        let mut metas = base_metas(env, lp);
        for v in victims {
            metas.push(AccountMeta::new(*v, false));
        }
        env.send(ix(lg::OP_LP_STOP), metas, &[])
    }

    pub fn guard(env: &Env) -> lg::LevGuardV22 {
        state::read_lev_guard(&env.svm.get_account(&guard_key(env)).unwrap().data).unwrap()
    }

    /// State poke: the LP portfolio loses `(1 - num/den)` of its capital (a loss as far as the
    /// NAV index can tell: no flow counter moves). Market totals follow, as `force_capital`.
    pub fn lose_capital(env: &mut Env, lp: Pubkey, num: u128, den: u128) {
        let mut market_account = env.svm.get_account(&env.market).unwrap();
        let mut pd = env.svm.get_account(&lp).unwrap();
        let (cfg, mut group) = state::read_market(&market_account.data).unwrap();
        let mut p = state::read_portfolio(&pd.data).unwrap();
        let old = p.capital;
        let new = old * num / den;
        group.c_tot -= old - new;
        group.vault -= old - new;
        p.capital = new;
        p.health_cert.valid = false;
        state::write_market(&mut market_account.data, &cfg, &group).unwrap();
        state::write_portfolio(&mut pd.data, &p).unwrap();
        env.svm.set_account(env.market, market_account).unwrap();
        env.svm.set_account(lp, pd).unwrap();
    }
}

fn a640_world(bond_cap_junior: u64) -> (Env, Lp, BondHolder) {
    let (mut env, lp, _d, h) = bond_world(growth_params(), 10_000, bond_cap_junior, 0, 800);
    lev_w1::init(&mut env);
    lev_w1::poke(&mut env, &lp).expect("epoch start");
    (env, lp, h)
}

fn a640_show(tag: &str, env: &Env) {
    let n = lev_w1::guard(env).nav();
    eprintln!("A640 {tag}: navps {} peak {} ref {} last_equity {} trig {}", n.navps, n.peak(), n.ref_navps, n.last_equity,
        percolator_prog::lev_guard_v22::lp_stop_triggered(&n));
}


fn n636b_navps(env: &Env) -> u128 {
    lev_w1::guard(env).nav().navps
}

fn n636b_stop(env: &Env) -> bool {
    percolator_prog::lev_guard_v22::lp_stop_triggered(&lev_w1::guard(env).nav())
}

fn n636b_other(env: &Env) -> (u128, u128) {
    let x = env.ext().expect("ext");
    (x.other_in_atoms(), x.other_out_atoms())
}

/// 108 + 110 are flows. A bond deposit that doubles the LP's equity must leave the index at 1.0;
/// the round trip (deposit, request, cooldown, execute) must not trip the stop. The flow counters
/// read exactly the deposit and the payout.
/// NEGATIVE CONTROL: on the #640 head the deposit reads 2.0 and the withdrawal trips the stop.
#[test]
fn n636b_bond_round_trip_is_a_flow_not_pnl() {
    use percolator_prog::lev_guard_v22 as lg;
    let (mut env, lp, h) = a640_world(2_000);
    env.bond_deposit(&h, lp.portfolio, 2_000 * U, 1).expect("108 doubles the LP equity");
    lev_w1::poke(&mut env, &lp).expect("poke");
    assert_eq!(n636b_navps(&env), lg::NAV_ONE, "a bond deposit is capital, not profit");
    assert_eq!(n636b_other(&env), (2_000 * U as u128, 0), "counter = the deposit");
    env.bond_request(&h, 2_000 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110");
    lev_w1::poke(&mut env, &lp).expect("poke");
    assert_eq!(n636b_navps(&env), lg::NAV_ONE, "a bond withdrawal is capital, not a loss");
    assert!(!n636b_stop(&env), "no loss, no stop");
    assert_eq!(n636b_other(&env), (2_000 * U as u128, paid as u128), "counters = deposit / payout");
    env.assert_conserved("n636b round trip");
}

/// A real 60% loss, then a 3,000 bond deposit BEFORE the next poke: the loss is read in full and
/// the stop fires (it did not on the #640 head: index 1.90).
#[test]
fn n636b_bond_deposit_cannot_mask_a_real_loss() {
    use percolator_prog::lev_guard_v22 as lg;
    let (mut env, lp, h) = a640_world(2_000);
    lev_w1::lose_capital(&mut env, lp.portfolio, 4, 10);
    env.bond_deposit(&h, lp.portfolio, 3_000 * U, 1).expect("108 after the loss");
    lev_w1::poke(&mut env, &lp).expect("poke");
    let n = lev_w1::guard(&env).nav();
    assert!(n.navps <= lg::NAV_ONE * 45 / 100, "the 60% loss is read in full: {}", n.navps);
    assert!(lg::lp_stop_triggered(&n), "stop fires");
}

/// Dilution (mirror image): a big bond deposit first, then a real 60% loss of everything: the
/// loss is not read against an inflated base.
#[test]
fn n636b_bond_deposit_cannot_dilute_a_later_loss() {
    use percolator_prog::lev_guard_v22 as lg;
    let (mut env, lp, h) = a640_world(2_000);
    env.bond_deposit(&h, lp.portfolio, 3_000 * U, 1).expect("108");
    lev_w1::lose_capital(&mut env, lp.portfolio, 4, 10);
    lev_w1::poke(&mut env, &lp).expect("poke");
    let n = lev_w1::guard(&env).nav();
    assert!(n.navps <= lg::NAV_ONE * 45 / 100, "60% loss read as such: {}", n.navps);
    assert!(lg::lp_stop_triggered(&n));
}

/// Tag 102 (surplus release, junior owner): pots -> LP capital is a flow. Index stays 1.0.
#[test]
fn n636b_surplus_release_is_a_flow_not_a_gain() {
    use percolator_prog::lev_guard_v22 as lg;
    let (mut env, lp, _h) = a640_world(2_000);
    let admin = env.admin.insecure_clone();
    poke_senior_claim(&mut env, 6_000 * U as u128);
    env.release_surplus(&admin, lp.portfolio, 3_000 * U as u128, DOMAIN).expect("102");
    lev_w1::poke(&mut env, &lp).expect("poke");
    assert_eq!(n636b_navps(&env), lg::NAV_ONE, "released surplus is capital, not profit");
    assert_eq!(n636b_other(&env), (3_000 * U as u128, 0));
    env.assert_conserved("n636b 102");
}

/// A growth market REQUIRES the guard and the ext on 108 / 110 / 102 (a caller cannot skip the
/// sample by leaving them out). The guard-less call is refused LevGuardInvalid and changes nothing.
#[test]
fn n636b_flows_require_the_guard_and_ext_on_a_growth_market() {
    let (mut env, lp, h) = a640_world(2_000);
    let admin = env.admin.insecure_clone();
    let g = lev_w1::guard_key(&env);
    let x = state::derive_vault_lp_ext(&env.pid, &env.market).0;
    let mut run = |env: &mut Env, ix: (ProgInstruction, Vec<AccountMeta>), kp: &Keypair, drop_key: Pubkey| -> Result<(), String> {
        env.svm.expire_blockhash();
        let (i, m) = ix;
        let m: Vec<AccountMeta> = m.into_iter().filter(|a| a.pubkey != drop_key).collect();
        env.send(i, m, &[kp])
    };
    let hk = h.kp.insecure_clone();
    // 108 without the guard: refused, no state change.
    let before = n636b_other(&env);
    let ix = env.bond_deposit_ix(&h, lp.portfolio, 100 * U, 1);
    err_has(&run(&mut env, ix, &hk, g), PercolatorError::LevGuardInvalid);
    // 108 with the guard but without the ext: refused (the counter has nowhere to go).
    let ix = env.bond_deposit_ix(&h, lp.portfolio, 100 * U, 1);
    assert!(run(&mut env, ix, &hk, x).is_err(), "no ext, no flow");
    assert_eq!(n636b_other(&env), before);
    // 102 without the guard: refused.
    poke_senior_claim(&mut env, 6_000 * U as u128);
    let (i, mut m) = (
        ProgInstruction::VaultLpReleaseSurplus { amount: 100 * U as u128, source_domain: DOMAIN },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new_readonly(env.registry, false),
            AccountMeta::new(env.vault_lp, false),
            AccountMeta::new(lp.portfolio, false),
            AccountMeta::new(env.ledger, false),
            AccountMeta::new(env.sibling, false),
        ],
    );
    env.svm.expire_blockhash();
    let r = env.send(i.clone(), m.clone(), &[&admin]);
    err_has(&r, PercolatorError::LevGuardInvalid);
    for _ in 0..5 {
        m.push(AccountMeta::new_readonly(solana_sdk::system_program::ID, false));
    }
    m.push(AccountMeta::new(x, false));
    m.push(AccountMeta::new(lp.portfolio, false)); // wrong key at the guard slot
    env.svm.expire_blockhash();
    err_has(&env.send(i, m, &[&admin]), PercolatorError::LevGuardInvalid);
    // 110 without the guard (after a clean 108 + cooldown): refused.
    env.bond_deposit(&h, lp.portfolio, 100 * U, 1).expect("108");
    env.bond_request(&h, 100 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    let dest = env.token_account(env.mint, h.kp.pubkey(), 0);
    let ix = env.bond_execute_ix(&h, lp.portfolio, dest, 0);
    err_has(&run(&mut env, ix, &hk, g), PercolatorError::LevGuardInvalid);
}

/// Tag 111 setup on this suite's world: create the insurance-units ledger (tag 116 path, flips the
/// profile flag), then STATE-POKE an outstanding backstop of `b` atoms consistently (vault-LP
/// state, halt mirror, units receivable). Reaching `backstop_due` for a real DRAW needs the G9
/// world of `p4_wave_d.rs`; RESTORE only needs an outstanding receivable.
fn n636b_units_and_backstop(env: &mut Env, b: u64) {
    let payer = env.payer.pubkey();
    let units = state::derive_insurance_units(&env.pid, &env.market).0;
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::InitInsuranceUnits,
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(units, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[],
    )
    .expect("tag 116: units ledger");
    poke_backstop_consistent(env, b);
    let mut a = env.svm.get_account(&units).unwrap();
    let mut u = state::read_insurance_units(&a.data).unwrap();
    u.backstop_receivable_atoms = b as u128;
    state::write_insurance_units(&mut a.data, &u).unwrap();
    env.svm.set_account(units, a).unwrap();
}

/// Tag 111 (permissionless) mode 1 RESTORE: tail = [units, vault ext, lev guard] (any order).
fn n636b_restore(env: &mut Env, lp: &Lp, mode: u8, max_amount: u128, with_guard: bool) -> Result<(), String> {
    let payer = env.payer.pubkey();
    let units = state::derive_insurance_units(&env.pid, &env.market).0;
    let mut m = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(env.market, false),
        AccountMeta::new_readonly(env.registry, false),
        AccountMeta::new(env.vault_lp, false),
        AccountMeta::new(lp.portfolio, false),
        AccountMeta::new(env.ledger, false),
        AccountMeta::new(env.sibling, false),
        AccountMeta::new(units, false),
        AccountMeta::new(state::derive_vault_lp_ext(&env.pid, &env.market).0, false),
    ];
    if with_guard {
        m.push(AccountMeta::new(lev_w1::guard_key(env), false));
    }
    env.svm.expire_blockhash();
    env.send(ProgInstruction::InsuranceBackstopDraw { mode, max_amount }, m, &[])
}

/// Tag 111 RESTORE (modes 1 and 3), permissionless: LP capital -> insurance is a flow OUT. A
/// 600-atom repayment must not read as a 30% loss of a 2,000 LP; the index stays 1.0 and the
/// counter reads the amount. Without the guard on a growth market the call is refused.
#[test]
fn n636b_backstop_restore_is_a_flow_not_a_loss() {
    use percolator_prog::lev_guard_v22 as lg;
    for mode in [1u8, 3u8] {
        let (mut env, lp, _h) = a640_world(2_000);
        n636b_units_and_backstop(&mut env, 600 * U);
        n636b_restore(&mut env, &lp, mode, 0, true).unwrap_or_else(|e| panic!("111 mode {mode}: {e}"));
        let st = state::read_vault_lp_state(&env.svm.get_account(&env.vault_lp).unwrap().data).unwrap();
        let repaid = 600 * U - st.backstop_outstanding_atoms;
        assert!(repaid > 0, "vacuity: the restore moved value (mode {mode})");
        lev_w1::poke(&mut env, &lp).expect("poke");
        assert_eq!(n636b_navps(&env), lg::NAV_ONE, "a repayment to insurance is a flow, not a loss (mode {mode})");
        assert!(!n636b_stop(&env));
        assert_eq!(n636b_other(&env), (0, repaid as u128), "counter = the repayment (mode {mode})");
    }
    // The guard is required on a growth market: refused, nothing changed.
    let (mut env, lp, _h) = a640_world(2_000);
    n636b_units_and_backstop(&mut env, 600 * U);
    err_has(&n636b_restore(&mut env, &lp, 1, 0, false), PercolatorError::LevGuardInvalid);
    let st0 = state::read_vault_lp_state(&env.svm.get_account(&env.vault_lp).unwrap().data).unwrap();
    assert_eq!(st0.backstop_outstanding_atoms, 600 * U, "the refusal changed nothing");
}

/// Growth market, guard live, NO vault ext (bound without [11], no 103 / 107 yet). att-641 found
/// that 102 (Live) and 111 RESTORE, which work on rc23 and on #640, were refused on 2133354 (the
/// counter had no ext to live in). They must keep working (run as before, no sample).
fn n636b_extless_world() -> (Env, Lp) {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000 * U, Some(lp.portfolio)).expect("75");
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 2_000 * U).expect("96");
    lev_w1::init(&mut env);
    lev_w1::poke(&mut env, &lp).expect("epoch start");
    assert!(env.ext().is_none(), "vacuity: no ext in this world");
    (env, lp)
}

#[test]
fn n636b_extless_growth_market_keeps_102_and_111_restore_alive() {
    let (mut env, lp) = n636b_extless_world();
    let admin = env.admin.insecure_clone();
    poke_senior_claim(&mut env, 6_000 * U as u128);
    let cap0 = env.portfolio(lp.portfolio).capital;
    env.release_surplus(&admin, lp.portfolio, 100 * U as u128, DOMAIN).expect("102 on an ext-less growth market");
    assert_eq!(env.portfolio(lp.portfolio).capital, cap0 + 100 * U as u128, "vacuity: the release moved value");
    let (mut env2, lp2) = n636b_extless_world();
    n636b_units_and_backstop(&mut env2, 600 * U);
    n636b_restore(&mut env2, &lp2, 1, 0, true).expect("111 RESTORE on an ext-less growth market");
    let st = state::read_vault_lp_state(&env2.svm.get_account(&env2.vault_lp).unwrap().data).unwrap();
    assert!(st.backstop_outstanding_atoms < 600 * U, "vacuity: the repayment moved value");
    assert!(env2.ext().is_none(), "no ext was created behind the caller's back");
}

// ── GH#571: the carried (cumulative) coupon ────────────────────────────────────────────────
//
// Every test below measures ECONOMICS (SPL paid out, C_b credited at a crank, what the junior can
// withdraw) through a RAW reader that works on both tranche layouts (v1 128 B and v2 144 B), so
// the negative control (`P1_WRAPPER_SO=<780013c .so>`) fails on the economic assertion, not on a
// layout parse.

/// Raw tranche reader: `(C_b, B, last_coupon_slot, arrears)`; arrears read 0 on a v1 account.
fn tranche_raw(env: &Env) -> (u128, u128, u64, u128) {
    let d = env.svm.get_account(&env.tranche_key()).unwrap().data;
    let h = state::bond_tranche_account_len() - core::mem::size_of::<state::BondTrancheV20>();
    let u128_at = |o: usize| u128::from_le_bytes(d[h + o..h + o + 16].try_into().unwrap());
    let last = u64::from_le_bytes(d[h + 96..h + 104].try_into().unwrap());
    let arrears = if d.len() >= h + 144 { u128_at(128) } else { 0 };
    (u128_at(32), u128_at(48), last, arrears)
}

/// The fee leg 78 would harvest now.
fn leg_now(env: &Env) -> u128 {
    let (cfg, _) = env.market_state();
    cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms
}

/// `bond_world` with an explicit junior floor (bps of C).
fn bond_world_floor(p: Params, floor_bps: u16, senior: u64, junior: u64, bond: u64, coupon_bps: u16) -> (Env, Lp, Depositor, BondHolder) {
    let mut env = Env::new(p);
    let lp = env.bind(floor_bps);
    env.init_bonds(coupon_bps);
    let d = env.new_depositor();
    env.earn_deposit(&d, senior * U, Some(lp.portfolio)).expect("75 senior (bound)");
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, junior * U).expect("96 junior");
    let h = env.new_bond_holder();
    if bond > 0 {
        env.bond_deposit(&h, lp.portfolio, bond * U, 1).expect("108 bond deposit");
    }
    (env, lp, d, h)
}

fn fat_leg(env: &mut Env, t: &Trader, lp: &Lp) {
    for _ in 0..6 {
        env.trade(t, lp, 1_000 * UQ).expect("open");
        env.trade(t, lp, -1_000 * UQ).expect("close");
    }
}

/// GH#571 path 1: a 1-atom-class bond deposit (tag 108) during a quiet stretch used to move the
/// coupon checkpoint for every holder and wipe the stretch's coupon. Now it SETTLES the accrual
/// into the arrears; the next harvest pays it. Two worlds, identical except for the grief deposit
/// 1,500 slots before trading resumes: the coupon credited at the harvest must be the same (the
/// grief world pays at most a few atoms more, the griefer's own accrual).
/// NEGATIVE CONTROL (780013c): the grief world's coupon is ~0.35% of the clean one.
#[test]
fn gh571_tiny_bond_deposit_no_longer_wipes_the_accrued_coupon() {
    let run = |grief: bool| -> (u128, u128, u128) {
        let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
        let t = env.new_trader(10_000 * U);
        env.slot += 432_000; // a quiet weekend
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        let mut grief_amt = 0;
        if grief {
            let g = env.new_bond_holder();
            // the smallest deposit that mints a share (K / B > 1 once arrears are carried)
            grief_amt = (1..=8u64).find(|a| env.bond_deposit(&g, lp.portfolio, *a, 1).is_ok()).expect("a tiny deposit mints") as u128;
        }
        env.slot += 1_500;
        env.svm.warp_to_slot(env.slot);
        env.hold(1, &[lp.portfolio]);
        fat_leg(&mut env, &t, &lp);
        let leg = leg_now(&env);
        let (cb0, ..) = tranche_raw(&env);
        env.crank_fees_bond(lp.portfolio).expect("78");
        let (cb1, _, _, a1) = tranche_raw(&env);
        env.assert_conserved("gh571 grief");
        assert!(cb1 - cb0 < leg / 2, "vacuity: the leg covers the whole due");
        (cb1 - cb0, a1, grief_amt)
    };
    let (clean, a_clean, _) = run(false);
    let (grief, a_grief, amt) = run(true);
    eprintln!("GH571 108-grief: clean coupon {clean} grief coupon {grief} (grief deposit {amt} atoms)");
    assert!(clean > 3_000_000, "vacuity: ~2 days of 20% on 3,000 USDC is ~3.3 USDC");
    assert!(grief + 1 >= clean, "a tiny deposit forfeits nothing: grief {grief} vs clean {clean}");
    assert!(grief <= clean + 10, "and adds only the griefer's own dust accrual");
    assert_eq!((a_clean, a_grief), (0, 0), "a fat leg pays every carried atom");
}

/// GH#571 path 2 (explainV item 5): after a quiet stretch, a DUST trade plus a permissionless
/// tag 78 used to pay at most half the dust leg and reset the clock, forfeiting the stretch. Now
/// the unpaid part is CARRIED; the next fat-leg crank pays it. Total paid over the two cranks ==
/// the stretch's due (compounded per settlement, so >= the simple-interest due).
/// NEGATIVE CONTROL (780013c): the total is a few atoms of dust leg + one slot of accrual.
#[test]
fn gh571_dust_trade_crank_carries_instead_of_forfeiting() {
    let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
    let t = env.new_trader(10_000 * U);
    let (cb_start, _, last_start, _) = tranche_raw(&env);
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.trade(&t, &lp, 10 * UQ).expect("dust open");
    env.trade(&t, &lp, -10 * UQ).expect("dust close");
    let dust = leg_now(&env);
    env.crank_fees_bond(lp.portfolio).expect("78 on the dust leg (permissionless)");
    let (cb1, _, _, a1) = tranche_raw(&env);
    let paid1 = cb1 - cb_start;
    assert!(paid1 <= dust / 2, "M-2 still holds: at most half the dust leg");
    env.hold(1, &[lp.portfolio]);
    fat_leg(&mut env, &t, &lp);
    env.crank_fees_bond(lp.portfolio).expect("78 fat");
    let (cb2, _, _, a2) = tranche_raw(&env);
    let total = cb2 - cb_start;
    let simple = bond_v20::coupon_due(cb_start, 2_000, env.slot - last_start).unwrap();
    eprintln!("GH571 dust-crank: dust leg {dust} paid1 {paid1} carried {a1} total {total} simple due {simple}");
    assert!(simple > 3_000_000, "vacuity");
    // two settlement floors can lose one atom against the single-interval floor
    assert!(total + 1 >= simple, "nothing forfeited: total {total} vs simple-interest due {simple}");
    assert!(total <= simple + simple / 1_000, "and only the per-settlement compounding on top");
    assert_eq!(a2, 0);
    assert!(a1 > 0 && a1 + paid1 >= simple - simple / 1_000, "the dust crank carried the rest");
    env.assert_conserved("gh571 dust crank");
}

/// GH#571: tag 110 SETTLES before pricing, so a leaver is paid principal + ITS accrued coupon
/// (out of the vault LP's capital: arrears are a claim senior to the junior), and the stayer
/// keeps exactly its own arrears. No fee leg ever runs in this test.
/// NEGATIVE CONTROL (780013c): the leaver is paid principal only.
#[test]
fn gh571_withdraw_settles_the_leavers_coupon_and_keeps_the_stayers() {
    let (mut env, lp, _d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 2_000);
    let h2 = env.new_bond_holder();
    env.bond_deposit(&h2, lp.portfolio, 2_000 * U, 1).expect("second holder, same slot");
    let (cb0, b0, last0, _) = tranche_raw(&env);
    let sh = env.bond_pos(&h).shares;
    env.bond_request(&h, sh).expect("109");
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    let dt = env.slot - last0;
    let accrued = bond_v20::coupon_due(cb0, 2_000, dt).unwrap();
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110 Live") as u128;
    eprintln!("GH571 110: dt {dt} pool accrual {accrued} leaver paid {paid}");
    assert!(accrued > 5_000_000, "vacuity: 500k slots of 20% on 4,000 USDC ~ 5 USDC");
    let fair = 2_000 * U as u128 + accrued * sh / b0;
    assert!(paid + 2 >= fair && paid <= fair, "leaver gets principal + its half: paid {paid} fair {fair}");
    let (cb1, b1, _, a1) = tranche_raw(&env);
    assert_eq!(b1, b0 - sh);
    assert!((cb1 + a1).abs_diff(cb0 / 2 + accrued / 2) <= 2, "stayer keeps exactly its own claim");
    // the stayer's own exit, later, is principal + its full accrual too (the arrears survived)
    let sh2 = env.bond_pos(&h2).shares;
    env.bond_request(&h2, sh2).expect("109 stayer");
    env.wait_cooldown(&[lp.portfolio]);
    let (_, _, last1, _) = tranche_raw(&env);
    let more = bond_v20::coupon_due(cb1 + a1, 2_000, env.slot - last1).unwrap();
    let paid2 = env.bond_execute(&h2, lp.portfolio, 0).expect("110 stayer") as u128;
    assert!(paid2.abs_diff(cb1 + a1 + more) <= 2, "stayer paid {paid2} want {}", cb1 + a1 + more);
    assert_eq!(tranche_raw(&env), (0, 0, env.slot, 0), "the last exit empties C_b AND the arrears");
    env.assert_conserved("gh571 withdraw");
}

/// GH#571 seniority: unsettled accrual is reserved from the junior. After a long quiet stretch
/// the creator's max tag 97 withdrawal leaves the bonds' accrued coupon behind, and the bond
/// holder exits at principal + the capped (one year) coupon.
/// NEGATIVE CONTROL (780013c): the junior withdraws down to its floor and the holder gets only
/// principal.
#[test]
fn gh571_junior_cannot_withdraw_the_bonds_accrual_and_arrears_cap_at_one_year() {
    let (mut env, lp, _d, h) = bond_world_floor(Params::default(), 100, 10_000, 3_000, 2_000, 2_000);
    let sh = env.bond_pos(&h).shares;
    env.bond_request(&h, sh).expect("109");
    let (cb0, ..) = tranche_raw(&env);
    env.slot += 2 * SLOTS_PER_YEAR_U64; // two years: the cap binds at one year of coupon
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    let cap = bond_v20::coupon_arrears_cap(cb0, 2_000).unwrap();
    assert_eq!(cap, 400 * U as u128, "one year of 20% on 2,000 USDC");
    let out = env.max_junior_out_bond(lp.portfolio);
    eprintln!("GH571 97: junior max out {out} (cap {cap})");
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110") as u128;
    eprintln!("GH571 97: bond exit paid {paid}");
    assert!(paid + 2 >= cb0 + cap && paid <= cb0 + cap, "principal + exactly the one-year cap: {paid}");
    assert!(out + cap <= 3_000 * U as u128 - 100 * U as u128, "the junior left the arrears behind: out {out}");
    env.assert_conserved("gh571 junior");
}
const SLOTS_PER_YEAR_U64: u64 = bond_v20::SLOTS_PER_YEAR as u64;

/// GH#571 resolve path: arrears settled while Live survive resolution as a claim senior to the
/// junior: the junior's terminal sweep (102) is the physical surplus over the seniors AND
/// `C_b + A`, and the Resolved 110 pays principal + carried coupon from the pots.
/// NEGATIVE CONTROL (780013c): the junior may sweep the arrears; the bond gets principal only.
#[test]
fn gh571_resolved_exit_pays_carried_coupon_before_the_junior() {
    let (mut env, lp, d, h) = bond_world(Params::default(), 10_000, 3_000, 2_000, 2_000);
    let admin = env.admin.insecure_clone();
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    // a Live settlement point: another holder's deposit settles the accrual into the arrears
    let h2 = env.new_bond_holder();
    env.bond_deposit(&h2, lp.portfolio, U, 1).expect("108 settles");
    let (cb, b, _, a) = tranche_raw(&env);
    let sh = env.bond_pos(&h).shares;
    env.bond_request(&h, sh).expect("109");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("101 settle");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("terminal-flat");
    let t = Some(env.tranche_key());
    // the pre-#571 junior allowance: physical 15,001 - C 10,000 - C_b 2,001 = 3,000
    let old_allowance = 3_000 * U as u128;
    let expected_a = bond_v20::coupon_due(2_000 * U as u128, 2_000, 500_001).unwrap();
    assert!(expected_a > 2_000_000, "vacuity: ~2.5 USDC carried");
    err_has(&env.release_surplus_resolved_bond(&admin, lp.portfolio, old_allowance, junior_dest, t), PercolatorError::VaultLpReleaseRefused);
    env.slot += COOLDOWN as u64;
    env.svm.warp_to_slot(env.slot);
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110 Resolved") as u128;
    let want = (cb + a) * sh / b;
    eprintln!("GH571 resolved: C_b {cb} A {a} paid {paid} want {want}");
    assert!(paid + 1 >= want && paid <= want && paid > 2_000 * U as u128 + expected_a - 2, "principal + carried coupon from the pots");
    // the junior gets exactly what is left over the seniors and the remaining bond claim
    let (cb2, _, _, a2) = tranche_raw(&env);
    let junior = 15_001 * U as u128 - paid - 10_000 * U as u128 - (cb2 + a2);
    err_has(&env.release_surplus_resolved_bond(&admin, lp.portfolio, junior + 1, junior_dest, t), PercolatorError::VaultLpReleaseRefused);
    let before = env.tok(junior_dest);
    env.release_surplus_resolved_bond(&admin, lp.portfolio, junior, junior_dest, t).expect("junior sweep");
    assert_eq!((env.tok(junior_dest) - before) as u128, junior);
    env.paid_out += junior;
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    env.earn_execute(&d, Some(lp.portfolio)).expect("senior");
    env.assert_conserved("gh571 resolved");
}

/// GH#571 newcomer / leaver fairness on RANDOM sequences against the real BPF: deposits,
/// withdrawals (109 + cooldown + 110), quiet gaps, dust and fat cranks by up to 3 holders. After
/// EVERY step the on-chain tranche (C_b, A, B, checkpoint) and every payout equal an exact
/// integer reference model built from the production pure functions (the same model the pure
/// proptest `v22_bond_carry_571_pure::holders_get_exactly_their_own_accrual` proves fair against
/// an independent per-holder ledger), and each holder's realised value is within rounding of its
/// own compounded claim. Seeds are fixed (deterministic CI).
#[test]
fn gh571_random_sequences_match_the_reference_model_and_are_fair() {
    struct Model {
        cb: u128,
        a: u128,
        b: u128,
        t0: u64,
    }
    impl Model {
        fn settle(&mut self, now: u64, rate: u32) {
            let k = self.cb + self.a;
            self.a = bond_v20::coupon_settle(self.cb, self.a, rate, now - self.t0, self.cb > 0, k).unwrap();
            self.t0 = now;
        }
    }
    let rate = 2_000u32;
    for seed in [571u64, 0x5eed, 0xc0ffee] {
        let mut rng = seed;
        let mut next = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 4_000, 0, 2_000);
        let t = env.new_trader(10_000 * U);
        let holders: Vec<BondHolder> = (0..3).map(|_| env.new_bond_holder()).collect();
        let (_, _, t0, _) = tranche_raw(&env);
        let mut m = Model { cb: 0, a: 0, b: 0, t0 };
        let g = |dt: u64| 1.0 + rate as f64 / 10_000.0 * dt as f64 / bond_v20::SLOTS_PER_YEAR as f64;
        let mut fair = [0f64; 3];
        let mut net = [0f64; 3]; // SPL out - SPL in
        let mut fair_net = [0f64; 3];
        let mut last_ref = t0;
        let mut steps = 0f64;
        for _ in 0..14 {
            let now0 = env.slot;
            // reference compounding is applied at every settlement the program performs
            let settle_ref = |now: u64, fair: &mut [f64; 3], last_ref: &mut u64| {
                let f = g(now - *last_ref);
                for x in fair.iter_mut() { *x *= f; }
                *last_ref = now;
            };
            match next(4) {
                0 => {
                    env.slot += 1 + next(400_000);
                    env.svm.warp_to_slot(env.slot);
                    env.hold(1, &[lp.portfolio]);
                }
                1 => {
                    let i = next(3) as usize;
                    let amt = (1 + next(800)) * U;
                    if env.bond_deposit(&holders[i], lp.portfolio, amt, 1).is_ok() {
                        settle_ref(env.slot, &mut fair, &mut last_ref);
                        m.settle(env.slot, rate);
                        let minted = bond_v20::bond_shares_for_deposit(amt as u128, m.b, m.cb + m.a).unwrap();
                        m.cb += amt as u128;
                        m.b += minted;
                        assert_eq!(env.bond_pos(&holders[i]).shares > 0, true);
                        fair[i] += amt as f64;
                        net[i] -= amt as f64;
                        fair_net[i] -= amt as f64;
                        steps += 1.0;
                    }
                }
                2 => {
                    if next(2) == 0 {
                        env.trade(&t, &lp, 10 * UQ).expect("dust open");
                        env.trade(&t, &lp, -10 * UQ).expect("dust close");
                    } else {
                        fat_leg(&mut env, &t, &lp);
                    }
                    let leg = leg_now(&env);
                    if leg > 0 {
                        env.crank_fees_bond(lp.portfolio).expect("78");
                        settle_ref(env.slot, &mut fair, &mut last_ref);
                        m.settle(env.slot, rate);
                        if m.cb > 0 {
                            let (coupon, _, a2) = bond_v20::coupon_pay_from_leg(leg, m.a);
                            m.cb += coupon;
                            m.a = a2;
                        }
                        steps += 1.0;
                    }
                }
                _ => {
                    let i = next(3) as usize;
                    let held = env.bond_pos(&holders[i]).shares;
                    if held == 0 { continue; }
                    let sh = 1.max(held * (1 + next(4)) as u128 / 4);
                    env.bond_request(&holders[i], sh).expect("109");
                    env.wait_cooldown(&[lp.portfolio]);
                    let paid = env.bond_execute(&holders[i], lp.portfolio, 0).expect("110") as u128;
                    settle_ref(env.slot, &mut fair, &mut last_ref);
                    m.settle(env.slot, rate);
                    let want = bond_v20::bond_atoms_for_redemption(sh, m.b, m.cb + m.a).unwrap();
                    assert_eq!(paid, want, "seed {seed}: 110 payout equals the model");
                    let (cb, a) = bond_v20::bond_claims_after_redemption(m.cb, m.a, sh, m.b).unwrap();
                    m.cb = cb;
                    m.a = a;
                    m.b -= sh;
                    let ref_out = fair[i] * sh as f64 / held as f64;
                    fair[i] -= ref_out;
                    fair_net[i] += ref_out;
                    net[i] += paid as f64;
                    steps += 1.0;
                }
            }
            let (cb, b, last, a) = tranche_raw(&env);
            assert_eq!((cb, a, b), (m.cb, m.a, m.b), "seed {seed}: on-chain tranche == model (slot {} from {now0})", env.slot);
            if m.t0 > t0 { assert_eq!(last, m.t0, "seed {seed}: checkpoint"); }
        }
        // value everything at a final settlement point (no write: value from the model at now)
        let now = env.slot;
        let mut fin = Model { cb: m.cb, a: m.a, b: m.b, t0: m.t0 };
        fin.settle(now, rate);
        let f = g(now - last_ref);
        for (i, h) in holders.iter().enumerate() {
            let sh = env.bond_pos(h).shares;
            let held = if fin.b == 0 { 0 } else { bond_v20::bond_atoms_for_redemption(sh, fin.b, fin.cb + fin.a).unwrap() };
            let got = net[i] + held as f64;
            let want = fair_net[i] + fair[i] * f;
            let tol = 2.0 * steps + 4.0;
            eprintln!("GH571 seed {seed} holder {i}: got {got:.0} want {want:.1} (tol {tol})");
            assert!(got <= want + 1.0, "seed {seed} holder {i}: excess to the holder");
            assert!(got >= want - tol, "seed {seed} holder {i}: holder short-changed");
        }
        env.assert_conserved("gh571 random");
    }
}
