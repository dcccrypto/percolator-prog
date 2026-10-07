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
const CANONICAL_MATCHER: Pubkey = solana_program::pubkey!("DfTxJUT5BbERs1tR33dP82kaUJ1NLymRxXErXAYXcDam");
// combined release: Wave A's 1e7 launch floor binds every growth market; launch at $10.00 e6 and one test
// "unit" is 1/10 token so every notional equals the pre-merge $1 fixtures
const PRICE: u64 = 10_000_000; // $10.00 e6

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
        let market = Pubkey::new_unique();
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
        let init = match p.growth {
            None => init,
            Some((r, l)) => ProgInstruction::InitMarketV19 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
            },
        };
        env.send(
            init,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin],
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
                redemption_cooldown_slots: 0,
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
            ],
            &[&admin],
        )
        .expect("create lp vault");
        env
    }

    /// N-2 test helper: the harness constructor WITHOUT tag 69 CreateLpVault (so a launch can
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
        let market = Pubkey::new_unique();
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
        let init = match p.growth {
            None => init,
            Some((r, l)) => ProgInstruction::InitMarketV19 {
                market: Box::new(init),
                growth_r_gap_bps: r,
                growth_l_launch_x100: l,
            },
        };
        env.send(
            init,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            &[&admin],
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
        self.svm
            .send_transaction(tx)
            .map(|m| { eprintln!("CU {}", m.compute_units_consumed); })
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
        let key = Pubkey::new_unique();
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
        key
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
            ProgInstruction::RequestRedeemLpShares { shares },
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
        let portfolio = self.new_program_account(self.plen);
        self.send(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[&kp.insecure_clone()],
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
const UQ: i128 = 100_000; // 1 unit in Q = 1/10 token

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
        if let Some(t) = tranche {
            accts.push(AccountMeta::new_readonly(t, false));
        }
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
        if let Some(t) = tranche {
            accts.push(AccountMeta::new_readonly(t, false));
        }
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
        bond_v20::tranche_split3(nav + lpv, c, self.tranche().c_b_atoms)
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
        let s = env.split3(lp.portfolio);
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
/// exits at principal + coupon. NON-CUMULATIVE: an interval whose leg could not cover the due is
/// not carried. Negative control for the cap: mutant MB6 (cap removed) gives the whole thin leg
/// to the coupon and fails this test.
#[test]
fn bond_coupon_first_conserves_and_is_noncumulative() {
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
    // ... interval 3: SHORT (1 slot) with a fat leg -> only that slot's due; the shortfall of
    // interval 2 is NOT carried
    env.hold(1, &[lp.portfolio]);
    round(&mut env, 6);
    let due3 = bond_v20::coupon_due(tr2.c_b_atoms, 2_000, env.slot - tr2.last_coupon_slot).unwrap();
    let c2 = env.vlp().senior_claim_atoms;
    env.crank_fees_bond(lp.portfolio).expect("78 short");
    let tr3 = env.tranche();
    assert_eq!(tr3.c_b_atoms - tr2.c_b_atoms, due3, "non-cumulative: only this interval's due");
    assert!(env.vlp().senior_claim_atoms > c2, "seniors take the rest");
    // the holder exits at principal + every coupon
    env.bond_request(&h, 3_000 * U as u128).expect("109");
    env.wait_cooldown(&[lp.portfolio]);
    let _ = env.crank_fees_bond(lp.portfolio);
    let cb = env.tranche().c_b_atoms;
    let paid = env.bond_execute(&h, lp.portfolio, 0).expect("110");
    assert_eq!(paid as u128, cb, "principal + coupons");
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
    assert_eq!(std::mem::size_of::<state::BondTrancheV20>(), 128);
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
        env.crank_fees_bond(lp.portfolio).expect("78");
        let coupon = env.tranche().c_b_atoms - tr0.c_b_atoms;
        let senior = env.vlp().senior_claim_atoms - c0;
        eprintln!("SEC-C1 impaired={impaired}: leg {avail} coupon {coupon} senior-credit {senior}");
        (avail, coupon, senior)
    };
    let (leg_i, coupon_i, senior_i) = run(true);
    let (leg_w, coupon_w, senior_w) = run(false);
    assert!(leg_i > 0 && leg_w > 0, "vacuity: fee legs");
    assert_eq!(coupon_i, 0, "M-1: an impaired tranche earns nothing");
    assert_eq!(senior_i, leg_i, "the whole leg goes to Earn");
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
/// is refused once any Earn exists, M-2). The SAFE LAUNCH is atomic: create the LP vault (69),
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
        ix(env.pid, ProgInstruction::CreateLpVault { fee_share_bps: 5_000, redemption_cooldown_slots: 0, oi_reservation_threshold_bps: 0, domain: DOMAIN }, vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new(env.lp_mint, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
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
    eprintln!("N-2 launch bundle (69 + 94 + 107 + 2 create_account): {size} bytes");
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


#[test]
fn sec4_cu_of_78_with_refresh() {
    let (mut env, lp, _d, _h) = bond_world(Params { fee_bps: 100, ..Params::default() }, 10_000, 3_000, 3_000, 2_000);
    let t = env.new_trader(10_000 * U);
    env.slot += 500_000;
    env.svm.warp_to_slot(env.slot);
    env.hold(1, &[lp.portfolio]);
    env.trade(&t, &lp, 500 * UQ).expect("open");
    let tr0 = env.tranche();
    eprintln!("SEC4 78 with LP inventory:");
    env.crank_fees_bond(lp.portfolio).expect("78");
    let tr1 = env.tranche();
    eprintln!("SEC4 coupon {} moved {}", tr1.c_b_atoms - tr0.c_b_atoms, tr1.last_coupon_slot != tr0.last_coupon_slot);
    // third party: refresh forced at will is already possible via tag 5 (PermissionlessCrank)
}
