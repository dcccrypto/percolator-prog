// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P3 vault-owned LP — LiteSVM black-box tests against the REAL wrapper BPF
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
const CANONICAL_MATCHER: Pubkey = solana_program::pubkey!("EDKKgRaVHna6FCxiY1kgMzegD9rpaN1nwJNSzAzeBUBX");
const PRICE: u64 = 1_000_000; // $1.00 e6

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
            .map(|_| ())
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

// ═══════════════════════════════════════════════════════════════════════════════════════
// 1. InitVaultLp (tag 93)
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_init_vault_lp_binds_a_registry_owned_lp_and_seeds_senior_claim_at_nav() {
    let mut env = Env::new(Params::default());
    // Pre-bind Earn deposit so the senior claim has something to equal.
    let d = env.new_depositor();
    env.earn_deposit(&d, 5_000_000, None).expect("pre-bind earn deposit");
    let lp = env.init_vault_lp(1_000);

    let p = env.portfolio(lp);
    assert_eq!(p.owner, env.registry.to_bytes(), "vault LP owner must be the registry PDA");
    let st = env.vlp();
    assert_eq!(st.senior_claim_atoms, 5_000_000, "C seeded at backing NAV");
    assert_eq!(st.junior_owner, env.admin.pubkey().to_bytes());
    assert_eq!(st.lp_portfolio, lp.to_bytes());
    assert_eq!(env.registry_state()._reserved[0], 1, "registry bound flag");
    let rec = env.asset_rec();
    assert_eq!(rec.vault_lp_portfolio, lp.to_bytes());
    assert_eq!(rec.flags & state::ASSET_VAULT_LP_FLAG_BOUND, 1);
    env.assert_conserved("after bind");

    // Re-bind refused.
    let admin = env.admin.insecure_clone();
    err_has(&env.init_vault_lp_as(&admin, 1_000), PercolatorError::VaultLpAlreadyBound);
}

#[test]
fn p3_init_vault_lp_refuses_non_marketauth_and_thin_floor() {
    let mut env = Env::new(Params::default());
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(&env.init_vault_lp_as(&stranger, 1_000), PercolatorError::Unauthorized);
    let admin = env.admin.insecure_clone();
    err_has(&env.init_vault_lp_as(&admin, 999), PercolatorError::InvalidInstruction);
    // And the honest path still works afterwards (proof of life for the fixture).
    env.init_vault_lp_as(&admin, 1_000).expect("honest bind");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// 2. The vault LP is unreachable through every owner-signed path
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_vault_lp_owner_signed_paths_are_unreachable() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 10_000_000).expect("junior deposit");

    // Withdraw (tag 4) signed by the marketauth / creator.
    let dest = env.token_account(env.mint, admin.pubkey(), 0);
    let (pid_, seq, _) = env.identity(lp.portfolio);
    let r = env.send(
        ProgInstruction::Withdraw {
            portfolio_id: pid_,
            expected_sequence: seq,
            amount: 1,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(lp.portfolio, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault_token, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&admin],
    );
    println!("withdraw by creator: {r:?}");
    err_has(&r, PercolatorError::Unauthorized);

    // SetMatcherConfig (tag 68) signed by the creator.
    let frontier = state::read_market_asset_generation_frontier(
        &env.svm.get_account(&env.market).unwrap().data,
    )
    .unwrap();
    let (pid_, seq, _) = env.identity(lp.portfolio);
    let r = env.send(
        ProgInstruction::SetMatcherConfig {
            portfolio_id: pid_,
            expected_sequence: seq,
            asset_generation_frontier: frontier,
            enabled: 0,
            trade_fee_cap_bps: 0,
            expiry_slot: 0,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),
            AccountMeta::new(lp.portfolio, false),
        ],
        &[&admin],
    );
    println!("set matcher config by creator: {r:?}");
    err_has(&r, PercolatorError::Unauthorized);

    // ClosePortfolio signed by the creator.
    let (pid_, seq, epoch) = env.identity(lp.portfolio);
    let r = env.send(
        ProgInstruction::ClosePortfolio {
            portfolio_id: pid_,
            expected_sequence: seq,
            position_epoch: epoch,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(lp.portfolio, false),
        ],
        &[&admin],
    );
    println!("close portfolio by creator: {r:?}");
    err_has(&r, PercolatorError::Unauthorized);

    // TransferPortfolioOwnership (tag 72) is gated on the NFT program's mint authority and an
    // NFT registry entry that only an OWNER-signed wrap can create; with no wrap it refuses.
    let r = env.send(
        ProgInstruction::TransferPortfolioOwnership {
            new_owner: admin.pubkey().to_bytes(),
            asset_index: 0,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(lp.portfolio, false),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[b"nft_registry", env.market.as_ref()], &env.pid).0,
                false,
            ),
        ],
        &[&admin],
    );
    println!("transfer ownership by creator: {r:?}");
    assert!(r.is_err(), "transfer ownership must refuse");

    // Proof of life: nothing moved, owner still the registry.
    assert_eq!(env.portfolio(lp.portfolio).owner, env.registry.to_bytes());
    assert_eq!(env.portfolio(lp.portfolio).capital, 10_000_000);
    env.assert_conserved("unreachability");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// 3. VaultLpSetMatcher + a real matcher fill
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_vault_lp_set_matcher_then_real_trade_cpi_fill() {
    let mut env = Env::new(Params::default());
    let lp_key = env.init_vault_lp(1_000);
    env.approve_matcher();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(
        &env.vault_lp_set_matcher_as(&stranger, lp_key).map(|_| ()),
        PercolatorError::Unauthorized,
    );
    let admin = env.admin.insecure_clone();
    let lp = env.vault_lp_set_matcher_as(&admin, lp_key).expect("set matcher");
    env.junior_deposit_as(&admin, lp.portfolio, 10_000_000).expect("junior");
    let t = env.new_trader(5_000_000);
    env.trade(&t, &lp, 10 * POS).expect("trade cpi against vault lp");
    assert_eq!(env.position(t.portfolio), 10 * POS);
    assert_eq!(env.position(lp.portfolio), -10 * POS);
    assert_eq!(env.asset_rec().lp_net_q, -10 * POS, "skew snapshot tracks the vault LP");
    env.assert_conserved("after fill");
}

const POS: i128 = percolator::POS_SCALE as i128;

/// Security review S-2 (matcher-inventory-sync build, 2026-10-03): the skew-funding snapshot
/// `lp_net_q` must be the vault LP's ADL-EFFECTIVE position, the same measure as its denominator
/// `max(oi_eff_long_q, oi_eff_short_q)` (`vault_lp_skew_funding_rate`). The vault LP is the only
/// short; the long's tag-44 partial close ADL-scales the short side (A_short < 1), so the LP's
/// raw basis stays -10 while its real position is -7. Both writers are checked against the
/// ENGINE's own `oi_eff_short_q`: the crank refresh (`vault_lp_refresh_snapshot`) and the
/// post-fill snapshot (`vault_lp_post_fill`). Before the fix both stored the raw basis.
#[test]
fn p3_s2_skew_snapshot_is_the_adl_effective_position() {
    let mut env = Env::new(Params::default());
    let lp_key = env.init_vault_lp(1_000);
    env.approve_matcher();
    let admin = env.admin.insecure_clone();
    let lp = env.vault_lp_set_matcher_as(&admin, lp_key).expect("set matcher");
    env.junior_deposit_as(&admin, lp.portfolio, 10_000_000).expect("junior");
    let t = env.new_trader(5_000_000);
    env.trade(&t, &lp, 10 * POS).expect("open long against the vault lp");
    assert_eq!(env.asset_rec().lp_net_q, -10 * POS);

    // The long exits 3 units unilaterally (tag 44): the short side (the vault LP) is ADL-scaled.
    let (pid, _, pep) = env.identity(t.portfolio);
    let kp = t.kp.insecure_clone();
    let m = env.market;
    env.send(
        ProgInstruction::RebalanceReduce {
            portfolio_id: pid,
            position_epoch: pep,
            asset_index: 0,
            reduce_q: (3 * POS) as u128,
        },
        vec![
            AccountMeta::new(kp.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new(t.portfolio, false),
        ],
        &[&kp],
    )
    .expect("tag 44 partial close");
    let (_, g) = env.market_state();
    assert!(g.assets[0].a_short < percolator::ADL_ONE, "short side ADL-scaled");
    let oi_short = g.assets[0].oi_eff_short_q as i128;
    assert_eq!(oi_short, 7 * POS, "engine: the LP's effective short is 7");
    assert_eq!(env.position(lp.portfolio), -10 * POS, "raw basis is untouched by the ADL");

    // (a) crank refresh of the vault LP. A crank needs progress (else EngineNonProgress 22):
    // move the price one step, cranking only the trader, then crank the vault LP.
    let tp = t.portfolio;
    env.move_price(1_010_000, &[tp]);
    env.svm.expire_blockhash();
    env.crank(lp.portfolio).expect("crank the vault lp");
    let (_, g) = env.market_state();
    assert_eq!(g.assets[0].oi_eff_short_q as i128, oi_short, "no fill or ADL since");
    assert_eq!(
        env.asset_rec().lp_net_q,
        -oi_short,
        "refresh: lp_net_q is the engine's effective short, not the raw basis (-10)"
    );

    // (b) a reducing fill (long sells 1, LP buys 1 back): post-fill snapshot.
    env.trade(&t, &lp, -POS).expect("reducing fill");
    let (_, g) = env.market_state();
    let oi_short = g.assets[0].oi_eff_short_q as i128;
    assert!(env.position(lp.portfolio) < -oi_short, "raw basis still overstates |LP|");
    assert_eq!(
        env.asset_rec().lp_net_q,
        -oi_short,
        "post-fill: lp_net_q is the engine's effective short"
    );
    env.assert_conserved("after S-2 sequence");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// 4. Junior tranche (tags 95/96)
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_junior_deposit_grows_lp_capital_and_refuses_non_junior() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(
        &env.junior_deposit_as(&stranger, lp.portfolio, 1_000),
        PercolatorError::Unauthorized,
    );
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 7_000_000).expect("junior");
    assert_eq!(env.portfolio(lp.portfolio).capital, 7_000_000);
    assert_eq!(env.vlp().junior_deposited_atoms, 7_000_000);
    assert_eq!(env.vlp().senior_claim_atoms, 0, "junior never touches C");
    env.assert_conserved("junior deposit");
}

#[test]
fn p3_junior_withdraw_floor_liquidity_and_flat_rules() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000); // floor = 10% of C
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 50_000_000, Some(lp.portfolio)).expect("earn");
    assert_eq!(env.vlp().senior_claim_atoms, 50_000_000);
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    // V = 50M backing + 20M LP; C = 50M; junior 20M; floor = 5M => max 15M.
    err_has(
        &env.junior_withdraw_as(&admin, lp.portfolio, 15_000_001),
        PercolatorError::VaultLpJuniorWithdrawRefused,
    );
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(
        &env.junior_withdraw_as(&stranger, lp.portfolio, 1),
        PercolatorError::Unauthorized,
    );
    env.junior_withdraw_as(&admin, lp.portfolio, 15_000_000).expect("within surplus");
    assert_eq!(env.portfolio(lp.portfolio).capital, 5_000_000);
    env.assert_conserved("junior withdraw");

    // Flat rule: with inventory the engine refuses ANY withdrawal from the vault LP.
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior top-up");
    let t = env.new_trader(5_000_000);
    env.trade(&t, &lp, 10 * POS).expect("fill");
    let r = env.junior_withdraw_as(&admin, lp.portfolio, 1_000);
    println!("withdraw with inventory: {r:?}");
    err_has(&r, PercolatorError::EngineStale);
    env.assert_conserved("flat rule");
}

#[test]
fn p3_junior_withdraw_refused_while_backing_does_not_cover_senior() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 50_000_000).expect("junior");
    // STATE POKE: no instruction can shrink backing below C without an engine loss sequence
    // (covered end-to-end in the ANSEM reconstruction); here we lower the ledger principal's
    // NAV input by inflating the senior claim, which is equivalent for the rule under test
    // (backing 10M < C 20M) and keeps the test to the one guard.
    let mut acct = env.svm.get_account(&env.vault_lp).unwrap();
    let mut st = state::read_vault_lp_state(&acct.data).unwrap();
    st.senior_claim_atoms = 20_000_000;
    state::write_vault_lp_state(&mut acct.data, &st).unwrap();
    env.svm.set_account(env.vault_lp, acct).unwrap();
    // junior = 60M - 20M = 40M, floor 2M => 1M is within the junior surplus, but backing (10M)
    // does not cover C (20M), so the senior-liquidity rule refuses it.
    err_has(
        &env.junior_withdraw_as(&admin, lp.portfolio, 1_000_000),
        PercolatorError::VaultLpJuniorWithdrawRefused,
    );
}

/// STATE POKE helper: set the senior claim C directly. Used ONLY to construct an impaired /
/// under-covered senior in unit tests of a single guard; the natural loss path is exercised
/// end-to-end in the ANSEM reconstruction (R1).
fn poke_senior_claim(env: &mut Env, c: u128) {
    let mut acct = env.svm.get_account(&env.vault_lp).unwrap();
    let mut st = state::read_vault_lp_state(&acct.data).unwrap();
    st.senior_claim_atoms = c;
    state::write_vault_lp_state(&mut acct.data, &st).unwrap();
    env.svm.set_account(env.vault_lp, acct).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// 5. Earn on a bound vault (tags 75/77/78/80)
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_bound_earn_prices_off_senior_claim_fees_credit_c_and_close_refused() {
    let mut env = Env::new(Params {
        fee_bps: 30,
        ..Params::default()
    });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d1 = env.new_depositor();
    // Tail accounts are REQUIRED while bound.
    let r = env.earn_deposit(&d1, 10_000_000, None);
    println!("bound deposit without tail: {r:?}");
    assert!(r.as_ref().unwrap_err().contains("NotEnoughAccountKeys"), "{r:?}");
    env.earn_deposit(&d1, 10_000_000, Some(lp.portfolio)).expect("genesis");
    assert_eq!(env.vlp().senior_claim_atoms, 10_000_000);
    let s = env.registry_state().total_lp_shares_outstanding;
    assert_eq!(s, 10_000_000);
    let d2 = env.new_depositor();
    env.earn_deposit(&d2, 5_000_000, Some(lp.portfolio)).expect("second");
    assert_eq!(env.lp_shares(&d2), 5_000_000, "price == C/S == 1");
    assert_eq!(env.vlp().senior_claim_atoms, 15_000_000);

    // Generate LP fee leg with real fills.
    // Junior sized >= the 50-unit fill's notional: the P3-H2 protocol cap holds the vault LP to
    // 1x its (junior-funded) equity by default.
    env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
    let t = env.new_trader(20_000_000);
    env.trade(&t, &lp, 50 * POS).expect("open");
    env.trade(&t, &lp, -50 * POS).expect("close");
    env.assert_conserved("after fills");
    let (cfg, _) = env.market_state();
    let owed = cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(owed > 0, "fills must accrue an LP fee leg");
    // Crank without the tail on a bound vault fails closed.
    let r = env.crank_fees(false);
    println!("bound crank without tail: {r:?}");
    assert!(r.as_ref().unwrap_err().contains("NotEnoughAccountKeys"), "{r:?}");
    let c0 = env.vlp().senior_claim_atoms;
    env.crank_fees(true).expect("crank fees");
    let (cfg2, _) = env.market_state();
    let harvested = cfg2.lp_fee_withdrawn_atoms - cfg.lp_fee_withdrawn_atoms;
    assert!(harvested > 0);
    assert_eq!(env.vlp().senior_claim_atoms, c0 + harvested, "C += harvested fee leg");
    assert_eq!(env.vlp().senior_fee_credited_atoms, harvested);
    env.assert_conserved("after crank");

    // Redemption pays floor(shares*min(V,C)/S) and C drops by the pro-rata slice.
    let shares = env.lp_shares(&d2);
    env.earn_request(&d2, shares);
    let c_before = env.vlp().senior_claim_atoms;
    let s_before = env.registry_state().total_lp_shares_outstanding;
    let paid = env.earn_execute(&d2, Some(lp.portfolio)).expect("redeem");
    let expect_paid = shares * c_before / s_before;
    assert_eq!(paid as u128, expect_paid, "payout = floor(shares*C/S)");
    assert_eq!(
        env.vlp().senior_claim_atoms,
        c_before - shares * c_before / s_before,
        "C -= pro-rata slice"
    );
    assert!(paid > 5_000_000, "the redeemer earned its share of the fee leg");
    env.assert_conserved("after redemption");

    // Last real depositor leaves; the vault can still never be closed while bound.
    let shares1 = env.lp_shares(&d1);
    env.earn_request(&d1, shares1);
    env.earn_execute(&d1, Some(lp.portfolio)).expect("redeem 1");
    let r = env.send(
        ProgInstruction::CloseLpVault,
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new_readonly(env.lp_mint, false),
        ],
        &[&admin],
    );
    err_has(&r, PercolatorError::VaultLpBoundCannotClose);
    env.assert_conserved("end");
}

#[test]
fn p3_bound_earn_deposit_refused_when_senior_impaired_and_redemption_pays_impaired_value() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("genesis");
    // STATE POKE (see helper): C above V = 10M backing + 0 LP => senior impaired.
    poke_senior_claim(&mut env, 12_000_000);
    let d2 = env.new_depositor();
    err_has(
        &env.earn_deposit(&d2, 1_000_000, Some(lp.portfolio)),
        PercolatorError::VaultLpSeniorImpaired,
    );
    // A redemption now pays floor(shares * V / S) (V < C), never the inflated claim.
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let s = env.registry_state().total_lp_shares_outstanding;
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("redeem impaired");
    assert_eq!(paid as u128, shares * 10_000_000 / s);
    assert_eq!(env.vlp().senior_claim_atoms, 12_000_000 - shares * 12_000_000 / s);
    env.assert_conserved("impaired redemption");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// 6. Recall (97) and VaultLpConvertPnl (99)
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_recall_is_permissionless_and_bounded_by_the_senior_shortfall() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 30_000_000).expect("junior");
    // No shortfall => recall refused.
    err_has(&env.recall(lp.portfolio, 1, DOMAIN), PercolatorError::VaultLpRecallRefused);
    // STATE POKE (see helper): C = 14M vs backing 10M => shortfall 4M.
    poke_senior_claim(&mut env, 14_000_000);
    err_has(
        &env.recall(lp.portfolio, 4_000_001, DOMAIN),
        PercolatorError::VaultLpRecallRefused,
    );
    let (_, g0) = env.market_state();
    env.recall(lp.portfolio, 4_000_000, DOMAIN).expect("recall exactly the shortfall");
    let (_, g1) = env.market_state();
    assert_eq!(g1.vault, g0.vault, "recall moves no SPL: header.vault unchanged");
    assert_eq!(env.portfolio(lp.portfolio).capital, 26_000_000);
    assert_eq!(env.vlp().recalled_atoms, 4_000_000);
    // Backing now covers C exactly => a second recall is refused.
    err_has(&env.recall(lp.portfolio, 1, DOMAIN), PercolatorError::VaultLpRecallRefused);
    // Seniors can now redeem their full claim.
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let s = env.registry_state().total_lp_shares_outstanding;
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("redeem after recall");
    assert_eq!(paid as u128, shares * 14_000_000 / s);
    env.assert_conserved("recall");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Security-review blockers (Sentinel, 2026-09-29): P3-H1 resolved-market exit, P3-H2 creator
// option on seniors. Each test is a PoC that FAILS on the pre-fix program (c7437518 / the
// negative controls below) and passes on the fix.
// ═══════════════════════════════════════════════════════════════════════════════════════

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

/// P3-H1 PoC 1. Before the fix a stranger could CloseResolved the vault LP into a
/// registry-owned token account (from which nothing can ever move it). Now refused.
#[test]
fn p3_h1_close_resolved_refuses_the_vault_lp() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    env.resolve();
    let (r, stuck) = env.close_resolved_into_registry_ata(lp.portfolio);
    println!("P3-H1 tag 30 on vault LP: {r:?}; registry-ATA balance {}", env.tok(stuck));
    err_has(&r, PercolatorError::VaultLpUseSettleResolved);
    assert_eq!(env.tok(stuck), 0, "nothing may reach a registry-owned token account");
}

/// P3-H1 PoC 2. Resolved exit, no senior shortfall: the whole vault-LP payout reaches the
/// junior owner; seniors keep their backing; everything conserves.
#[test]
fn p3_h1_settle_resolved_pays_the_junior_when_seniors_are_covered() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let stranger = Keypair::new();
    env.settle_resolved(&stranger, lp.portfolio, 0, junior_dest).expect("permissionless settle");
    // F-14: tag 101 pays NO SPL; the whole payout returns to the vault's backing.
    assert_eq!(env.tok(junior_dest), 0, "settlement pays the junior nothing directly");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    let swept = env.junior_terminal_sweep(&admin, lp.portfolio, junior_dest);
    let got = env.tok(junior_dest) as u128;
    env.paid_out += got;
    println!("P3-H1 settle (covered): junior swept {swept}, C={} nav={}", env.vlp().senior_claim_atoms, env.backing_nav());
    assert_eq!(got, 20_000_000, "junior receives its full capital at terminal-flat");
    env.assert_conserved("settle resolved, covered");
}

/// P3-H1 PoC 3. Resolved exit WITH a senior shortfall: the shortfall is refilled into backing
/// FIRST, only the residual reaches the junior, and the Earn holder then redeems the full C.
#[test]
fn p3_h1_settle_resolved_refills_the_senior_shortfall_before_the_junior() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    // STATE POKE (see poke_senior_claim): stands in for backing consumed by LP gains the LP still
    // holds (C = 13M, backing 10M => 3M senior shortfall that the vault LP's value must cover).
    poke_senior_claim(&mut env, 13_000_000);
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let stranger = Keypair::new();
    env.settle_resolved(&stranger, lp.portfolio, 0, junior_dest).expect("settle");
    assert_eq!(env.tok(junior_dest), 0, "F-14: settlement pays the junior nothing directly");
    let (_, g) = env.market_state();
    println!("after settle: c_tot {} materialized {}", g.c_tot, g.materialized_portfolio_count);
    // Terminal cleanup (existing rule for EVERY portfolio): resolved redemption needs a
    // terminal-flat market, so marketauth deregisters the now-empty vault LP (tag 8, allowed to
    // marketauth in Resolved mode).
    let (pid_, seq, epoch) = env.identity(lp.portfolio);
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::ClosePortfolio {
            portfolio_id: pid_,
            expected_sequence: seq,
            position_epoch: epoch,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(lp.portfolio, false),
        ],
        &[&admin],
    )
    .expect("terminal cleanup of the settled vault LP");
    let swept = env.junior_terminal_sweep(&admin, lp.portfolio, junior_dest);
    let got = env.tok(junior_dest) as u128;
    env.paid_out += got;
    println!("P3-H1 settle (shortfall): junior {got} (swept {swept}), nav {}", env.backing_nav());
    assert_eq!(got, 17_000_000, "junior gets the payout minus the 3M senior shortfall");
    env.assert_conserved("settle resolved, shortfall");
    // The Earn holder now redeems against the refilled backing (resolved, terminal-flat).
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let s = env.registry_state().total_lp_shares_outstanding;
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("resolved redemption");
    println!("P3-H1 senior redemption after settle: {paid} for {shares}/{s} shares");
    assert_eq!(paid as u128, shares * 13_000_000 / s);
    env.assert_conserved("resolved redemption");
}

/// P3-H2 PoC 1. The creator (marketauth, NOT the upgrade authority) can no longer configure the
/// vault LP's matcher, and even the protocol can only use the approved program with finite caps.
#[test]
fn p3_h2_vault_lp_matcher_is_protocol_only_and_approved() {
    let mut env = Env::new(Params::default());
    let lp = env.init_vault_lp(1_000);
    let admin = env.admin.insecure_clone();
    // Protocol approves the matcher; ProgramData authority = admin here...
    env.approve_matcher();
    // ...now hand the upgrade authority to a separate protocol key: the creator is refused.
    let protocol = Keypair::new();
    env.svm.airdrop(&protocol.pubkey(), 10_000_000_000).unwrap();
    let (pd, _) = Pubkey::find_program_address(&[env.pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::ID);
    let mut acct = env.svm.get_account(&pd).unwrap();
    acct.data[13..45].copy_from_slice(protocol.pubkey().as_ref()); // STATE POKE: ProgramData authority
    env.svm.set_account(pd, acct).unwrap();
    env.svm.expire_blockhash();
    err_has(&env.vault_lp_set_matcher_as(&admin, lp).map(|_| ()), PercolatorError::Unauthorized);
    // An unapproved matcher program is refused even for the protocol.
    let approved = env.matcher;
    let other = Pubkey::new_unique();
    env.svm.add_program(other, &std::fs::read(matcher_program_path()).unwrap());
    env.matcher = other;
    env.svm.expire_blockhash();
    err_has(&env.vault_lp_set_matcher_as(&protocol, lp).map(|_| ()), PercolatorError::VaultLpMatcherNotApproved);
    env.matcher = approved;
    env.svm.expire_blockhash();
    env.vault_lp_set_matcher_as(&protocol, lp).expect("protocol + approved matcher");
}

/// P3-H2 PoC 2. The vault LP cannot take more exposure than 1x its junior-funded equity by
/// default, so a creator's second wallet cannot load it beyond the first-loss capital.
#[test]
fn p3_h2_vault_lp_exposure_capped_at_its_equity() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let t = env.new_trader(20_000_000);
    env.trade(&t, &lp, 20 * POS).expect("20 units = 1x the $20 junior");
    env.svm.expire_blockhash();
    let r = env.trade(&t, &lp, POS);
    println!("P3-H2 21st unit vs vault LP: {r:?}");
    err_has(&r, PercolatorError::VaultLpExposureCapExceeded);
    // Reducing is always allowed.
    env.svm.expire_blockhash();
    env.trade(&t, &lp, -5 * POS).expect("reduce");
}

/// P3-H2 open question (Sentinel): does a trader's win against the vault LP consume SENIOR
/// backing while the junior is solvent? Measured end to end with real price moves: the creator's
/// second wallet goes long vs the vault LP, the price rises, it closes and withdraws.
#[test]
fn p3_h2_trader_win_is_paid_by_the_junior_not_the_seniors() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 50_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let creator_wallet2 = env.new_trader(10_000_000);
    env.trade(&creator_wallet2, &lp, 10 * POS).expect("open long vs vault LP");
    let nav0 = env.backing_nav();
    let c0 = env.vlp().senior_claim_atoms;
    let lp_cap0 = env.portfolio(lp.portfolio).capital;
    let t_cap0 = env.portfolio(creator_wallet2.portfolio).capital;
    // +10%: the trader is up ~$1 on 10 units, the vault LP down the same.
    env.move_price(1_100_000, &[lp.portfolio, creator_wallet2.portfolio]);
    env.svm.expire_blockhash();
    env.trade(&creator_wallet2, &lp, -10 * POS).expect("close");
    for _ in 0..3 {
        env.slot += 1;
        env.svm.warp_to_slot(env.slot);
        let _ = env.crank(lp.portfolio);
        let _ = env.crank(creator_wallet2.portfolio);
    }
    let trader = env.portfolio(creator_wallet2.portfolio);
    let lpp = env.portfolio(lp.portfolio);
    let nav1 = env.backing_nav();
    println!(
        "P3-H2 win: trader cap {}->{} pnl {} | vaultLP cap {}->{} pnl {} | backing nav {}->{} | C {}->{}",
        t_cap0, trader.capital, trader.pnl, lp_cap0, lpp.capital, lpp.pnl, nav0, nav1, c0,
        env.vlp().senior_claim_atoms
    );
    let trader_gain = trader.capital as i128 + trader.pnl - t_cap0 as i128;
    let lp_loss = lp_cap0 as i128 - (lpp.capital as i128 + lpp.pnl);
    assert!(trader_gain > 0, "the creator's second wallet won ({trader_gain})");
    assert_eq!(env.vlp().senior_claim_atoms, c0, "the senior claim never moves on trading PnL");
    assert_eq!(nav1, nav0, "senior backing must not pay the winner while the junior is solvent");
    assert_eq!(lp_loss, trader_gain, "the winner is paid exactly by the vault LP (junior)");
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

/// P3-M1 PoC. Junior value sitting in backing (here: backing above a lowered senior claim) was
/// unreachable before tag 102. Now the junior pulls exactly the surplus `nav - C` back into the
/// vault LP, not one atom more, and nobody else can.
#[test]
fn p3_m1_junior_backing_surplus_is_releasable_exactly() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    // STATE POKE (see poke_senior_claim): C = 6M against 10M backing => 4M of the backing is
    // junior value (e.g. after a recall that over-covered and a later loss reversal).
    poke_senior_claim(&mut env, 6_000_000);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    err_has(&env.release_surplus(&stranger, lp.portfolio, 1, DOMAIN), PercolatorError::Unauthorized);
    err_has(&env.release_surplus(&admin, lp.portfolio, 4_000_001, DOMAIN), PercolatorError::VaultLpReleaseRefused);
    let cap0 = env.portfolio(lp.portfolio).capital;
    env.release_surplus(&admin, lp.portfolio, 4_000_000, DOMAIN).expect("release the surplus");
    println!("P3-M1 release: LP capital {} -> {}, backing nav {}", cap0, env.portfolio(lp.portfolio).capital, env.backing_nav());
    assert_eq!(env.portfolio(lp.portfolio).capital, cap0 + 4_000_000);
    assert_eq!(env.backing_nav(), 6_000_000, "backing left == C exactly");
    env.assert_conserved("release surplus");
    // The junior can now take it out (LP flat, backing still covers C).
    env.junior_withdraw_as(&admin, lp.portfolio, 4_000_000).expect("junior exits the released value");
    env.assert_conserved("junior exit after release");
}

/// P3-L1 PoC. On a bound vault with NO senior shares a harvestable fee backlog must not be
/// bought 1:1 by the first depositor: genesis is refused while fees are harvestable, the crank
/// credits the backlog to the junior (not C), and genesis then prices exactly 1:1 with C = amount.
#[test]
fn p3_l1_genesis_depositor_cannot_buy_the_fee_backlog() {
    let mut env = Env::new(Params {
        fee_bps: 30,
        ..Params::default()
    });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
    let t = env.new_trader(20_000_000);
    env.trade(&t, &lp, 50 * POS).expect("open");
    env.svm.expire_blockhash();
    env.trade(&t, &lp, -50 * POS).expect("close");
    let d = env.new_depositor();
    err_has(&env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)), PercolatorError::VaultLpHarvestPending);
    env.crank_fees(true).expect("crank with no senior shares credits the junior");
    let c = env.vlp().senior_claim_atoms;
    let backlog = env.backing_nav();
    println!("P3-L1: backlog {backlog} credited to backing, C = {c}");
    assert!(backlog > 0, "fees were harvested");
    assert_eq!(c, 0, "no senior claim was created for a backlog no senior paid for");
    env.release_surplus(&admin, lp.portfolio, backlog, DOMAIN).expect("junior reclaims its backlog");
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("genesis after crank");
    assert_eq!(env.vlp().senior_claim_atoms, 10_000_000, "genesis C == amount");
    assert_eq!(env.registry_state().total_lp_shares_outstanding, 10_000_000, "1:1 genesis");
    env.assert_conserved("L1 genesis");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Security final pass (Sentinel, 2026-09-29 late): settle-order independence, F-4 resolved
// cleanup, K1 pending fees, L2 stale valuation.
// ═══════════════════════════════════════════════════════════════════════════════════════

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

/// Runs a resolved market with a trader who WON against the vault LP, settling the vault LP
/// either before or after the trader's own resolved close. Returns (junior payout, trader
/// payout, senior redemption payout, backing nav after both closes).
fn settle_order_run(settle_first: bool) -> (u64, u64, u64, u128) {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 50_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let t = env.new_trader(10_000_000);
    env.trade(&t, &lp, 10 * POS).expect("open long vs vault LP");
    env.move_price(1_100_000, &[lp.portfolio, t.portfolio]);
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let stranger = Keypair::new();
    // A winner's resolved close is progress-only (payout 0) until its losing counterparty has
    // settled, so "trader first" means: trader close (progress) -> vault LP settle -> trader close
    // again. Every call's payout is summed; the comparison is on final outcomes.
    let mut tr = 0u64;
    if settle_first {
        env.settle_resolved(&stranger, lp.portfolio, 0, junior_dest).expect("settle first");
    } else {
        tr += env.trader_close_resolved(&t);
        env.settle_resolved(&stranger, lp.portfolio, 0, junior_dest).expect("settle second");
    }
    for _ in 0..3 {
        let p = env.portfolio(t.portfolio);
        if p.capital == 0 && p.pnl == 0 {
            break;
        }
        tr += env.trader_close_resolved(&t);
    }
    let trader = tr;
    let tp = env.portfolio(t.portfolio);
    println!(
        "settle_first={settle_first}: trader after close cap {} pnl {} bitmap_empty {} receipt {:?}",
        tp.capital,
        tp.pnl,
        percolator::active_bitmap_is_empty(tp.active_bitmap),
        tp.resolved_payout_receipt
    );
    env.assert_conserved("after both resolved closes");
    // F-4: nobody's signature needed to reach terminal-flat.
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    let towner = t.kp.pubkey();
    env.permissionless_close_portfolio(t.portfolio, towner).expect("cleanup trader");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let senior = env.earn_execute(&d, Some(lp.portfolio)).expect("resolved redemption");
    env.junior_terminal_sweep(&admin, lp.portfolio, junior_dest);
    let junior = env.tok(junior_dest);
    env.paid_out += junior as u128;
    env.assert_conserved("after resolved redemption + junior sweep");
    let (_, g) = env.market_state();
    (junior, trader, senior, g.vault)
}

/// Sentinel settle-order question: tag 101 reads backing at settle time — the outcome must not
/// depend on whether a winning trader's resolved close runs before or after it.
#[test]
fn p3_settle_order_does_not_change_anyones_outcome() {
    let a = settle_order_run(true);
    let b = settle_order_run(false);
    println!("P3 settle-order: settle-first {a:?} | trader-first {b:?}");
    assert_eq!(a, b, "junior / trader / senior / residual must be order-independent");
    assert!(a.1 > 10_000_000, "the trader won ({})", a.1);
    assert_eq!(a.2, 49_999_000, "the senior redeems its full claim (less dead shares)");
    assert!(a.3 <= 1_001, "nothing stranded beyond dead-share dust ({})", a.3);
}

/// F-4 PoC: before the fix, a trader who never closes (or whose owner key is gone) blocked every
/// Earn redemption after Resolve (`ExecuteRedemption` -> Custom(21) until terminal-flat). Now a
/// stranger can CloseResolved (permissionless after the delay) and deregister the empty portfolio.
#[test]
fn p3_f4_walked_away_trader_cannot_lock_earn_after_resolve() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    let walked_away = env.new_trader(1_000_000); // funded, never acts again
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("settle");
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("vault LP cleanup");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    // Still locked by the walked-away trader's live portfolio:
    err_has(&env.earn_execute(&d, Some(lp.portfolio)), PercolatorError::EngineLockActive);
    // A stranger cannot close a NON-empty portfolio...
    let wowner = walked_away.kp.pubkey();
    err_has(
        &env.permissionless_close_portfolio(walked_away.portfolio, wowner),
        PercolatorError::EngineLockActive,
    );
    // ...nor redirect the rent of an empty one away from its owner.
    // (the resolved close below is permissionless: owner is not required to sign)
    let dest = env.token_account(env.mint, wowner, 0);
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
        vec![
            AccountMeta::new_readonly(wowner, false),
            AccountMeta::new(env.market, false),
            AccountMeta::new(walked_away.portfolio, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault_token, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(
                Pubkey::find_program_address(&[b"nft_registry", env.market.as_ref()], &env.pid).0,
                false,
            ),
        ],
        &[],
    )
    .expect("permissionless resolved close pays the OWNER");
    env.paid_out += env.tok(dest) as u128;
    assert_eq!(env.tok(dest), 1_000_000);
    let thief = Pubkey::new_unique();
    err_has(&env.permissionless_close_portfolio(walked_away.portfolio, thief), PercolatorError::Unauthorized);
    let owner_lamports_before = env.svm.get_account(&wowner).map(|a| a.lamports).unwrap_or(0);
    env.permissionless_close_portfolio(walked_away.portfolio, wowner).expect("cleanup, rent to owner");
    assert!(env.svm.get_account(&wowner).unwrap().lamports > owner_lamports_before, "rent went to the owner");
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("Earn redeems after permissionless cleanup");
    println!("P3 F-4: Earn redeemed {paid} after permissionless cleanup");
    assert!(paid > 0);
    env.assert_conserved("F-4");
}

/// K1 PoC: a bound redemption refuses while LP fees are harvestable (the redeemer would leave
/// without its share of fees it carried), and succeeds once tag 78 has run.
#[test]
fn p3_k1_bound_redemption_requires_harvest_first() {
    let mut env = Env::new(Params { fee_bps: 30, ..Params::default() });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
    let t = env.new_trader(20_000_000);
    env.trade(&t, &lp, 50 * POS).expect("open");
    env.svm.expire_blockhash();
    env.trade(&t, &lp, -50 * POS).expect("close");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    err_has(&env.earn_execute(&d, Some(lp.portfolio)), PercolatorError::VaultLpHarvestPending);
    let c0 = env.vlp().senior_claim_atoms;
    env.crank_fees(true).expect("harvest");
    let c1 = env.vlp().senior_claim_atoms;
    let s = env.registry_state().total_lp_shares_outstanding;
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("redeem after harvest");
    println!("P3 K1: C {c0} -> {c1} after harvest, paid {paid}");
    assert!(c1 > c0);
    assert_eq!(paid as u128, shares * c1 / s, "redeemer gets its share of the harvested fees");
    env.assert_conserved("K1");
}

/// L2: when backing alone does not cover C and the vault LP holds inventory with a stale
/// certificate, the pricing paths return the dedicated VaultLpValuationStale (not a generic
/// EngineStale) and succeed once the permissionless crank of the vault LP is prepended.
#[test]
fn p3_l2_stale_vault_lp_valuation_has_a_clear_error_and_crank_fixes_it() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let t = env.new_trader(10_000_000);
    env.trade(&t, &lp, 5 * POS).expect("vault LP takes inventory");
    // STATE POKE (see poke_senior_claim): C above backing so the LP must be valued.
    poke_senior_claim(&mut env, 12_000_000);
    // Move the price without cranking the vault LP: its certificate goes stale.
    let tp = t.portfolio;
    env.move_price(1_010_000, &[tp]);
    let d2 = env.new_depositor();
    err_has(&env.earn_deposit(&d2, 1_000_000, Some(lp.portfolio)), PercolatorError::VaultLpValuationStale);
    env.svm.expire_blockhash();
    env.crank(lp.portfolio).expect("prepend the vault LP crank");
    env.earn_deposit(&d2, 1_000_000, Some(lp.portfolio)).expect("deposit once the vault LP is current");
    env.assert_conserved("L2");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Incident regressions — RECONSTRUCTIONS on the P3 program (not forks of live state: live
// slabs have no vault LP). Fee rates follow the live markets (fee-flow audit 2026-09-29:
// COLLECT 5 bps, Murphy 10 bps, TEXTIT 5 bps). Every step is a real instruction.
// ═══════════════════════════════════════════════════════════════════════════════════════

/// R2 — COLLECT / Murphy LP drain. Live: winners pushed the creator-owned matcher LP to 0
/// capital, after which every open reverted Custom(49) and the market died, with Earn backing
/// having paid the LP along the way. On P3: the vault LP's exposure is capped at its junior-
/// funded equity, so as winners drain the junior the market degrades to refusing only
/// crowd-growing opens (Custom(80), never 49); closes keep working; seniors' backing and C never
/// move; a junior top-up restores capacity — the market never dies.
#[test]
fn p3_r2_collect_murphy_lp_drain_reconstruction() {
    let mut env = Env::new(Params { fee_bps: 5, ..Params::default() });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 50_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 5_000_000).expect("junior 5M");
    let winner = env.new_trader(10_000_000);
    env.trade(&winner, &lp, 4 * POS).expect("winner opens 4 units (under the 1x cap)");
    let nav0 = env.backing_nav();
    let c0 = env.vlp().senior_claim_atoms;
    // +50%: the vault LP (short 4) loses $2 of its $5 junior.
    env.move_price(1_500_000, &[lp.portfolio, winner.portfolio]);
    let lp_state = env.portfolio(lp.portfolio);
    println!("R2: after +50%: vault LP cap {} pnl {}", lp_state.capital, lp_state.pnl);
    // A NEW crowd-growing open now exceeds 1x of the drained equity: refused with 80, not 49.
    let late = env.new_trader(10_000_000);
    env.svm.expire_blockhash();
    let r = env.trade(&late, &lp, 2 * POS);
    println!("R2: late crowd-growing open: {r:?}");
    err_has(&r, PercolatorError::VaultLpExposureCapExceeded);
    assert!(!format!("{r:?}").contains("Custom(49)"));
    // Thin-side / reducing flow keeps working: the winner closes and realizes.
    env.svm.expire_blockhash();
    env.trade(&winner, &lp, -4 * POS).expect("winner closes");
    assert_eq!(env.backing_nav(), nav0, "senior backing did not pay the winners");
    assert_eq!(env.vlp().senior_claim_atoms, c0, "C unchanged");
    // Refill: the creator tops the junior up and the market takes risk again.
    env.junior_deposit_as(&admin, lp.portfolio, 10_000_000).expect("junior top-up");
    env.svm.expire_blockhash();
    env.trade(&late, &lp, 2 * POS).expect("capacity restored after the junior refill");
    env.assert_conserved("R2");
}

/// R3 — TEXTIT one-sided death. Live: the LP's lien needed domain-1 (short-side) backing that
/// was empty/expired, so every trade growing the LP's LONG (i.e. every short) reverted
/// Custom(21). On P3 the vault LP carries real first-loss capital, so neither side needs a
/// backing lien to open: with Earn backing ONLY in domain 0, both a long and a short open and
/// close against the vault LP.
#[test]
fn p3_r3_textit_one_sided_reconstruction() {
    let mut env = Env::new(Params { fee_bps: 5, ..Params::default() });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 20_000_000, Some(lp.portfolio)).expect("earn (domain 0 only)");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let (_, g) = env.market_state();
    println!(
        "R3: backing domain0 fresh={} domain1 fresh={}",
        g.source_backing_buckets[0].fresh_unliened_backing_num,
        g.source_backing_buckets[1].fresh_unliened_backing_num
    );
    assert!(g.source_backing_buckets[0].fresh_unliened_backing_num > 0, "domain 0 funded");
    assert_eq!(g.source_backing_buckets[1].fresh_unliened_backing_num, 0, "domain 1 empty, as on TEXTIT");
    let short = env.new_trader(10_000_000);
    env.trade(&short, &lp, -5 * POS).expect("SHORT opens (vault LP goes long) with domain 1 empty");
    let long = env.new_trader(10_000_000);
    env.svm.expire_blockhash();
    env.trade(&long, &lp, 3 * POS).expect("long opens too");
    env.move_price(1_050_000, &[lp.portfolio, short.portfolio, long.portfolio]);
    env.svm.expire_blockhash();
    env.trade(&short, &lp, 5 * POS).expect("short closes");
    env.svm.expire_blockhash();
    env.trade(&long, &lp, -3 * POS).expect("long closes");
    env.assert_conserved("R3");
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

/// Independent QA F-8 (MEDIUM): the vault LP WINS against a trader and the market resolves. Before
/// the fix tag 101 saw a phantom senior shortfall (the Earn ledger books the LP's win against
/// the pot as a "loss" while the trader's loss lands in the same pot unattributed), refilled it
/// out of the junior's payout, and 900,000 atoms stayed in the vault after every party exited.
/// Now: settle values the pots physically, and the junior sweeps any terminal surplus (tag 102,
/// Resolved path). Nothing but dead-share dust is left behind.
#[test]
fn p3_f8_vault_lp_win_reaches_the_junior_at_resolution() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 3_000_000).expect("junior");
    let t = env.new_trader(5_000_000);
    env.trade(&t, &lp, 3 * POS).expect("trader long 3 vs vault LP");
    env.move_price(700_000, &[lp.portfolio, t.portfolio]);
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let tr = env.trader_close_resolved(&t);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("settle");
    let after_settle = env.tok(junior_dest);
    // F-14: the settlement pays no SPL; principal + win reach the junior through the terminal
    // sweep below (after every other claim).
    assert_eq!(after_settle, 0, "tag 101 routes the whole payout to backing");
    // Terminal cleanup (F-4 path), senior exit, then the junior's terminal sweep.
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    let towner = t.kp.pubkey();
    env.permissionless_close_portfolio(t.portfolio, towner).expect("cleanup trader");
    // Terminal 78 first (keeper step): the vault LP's claim-originated payout is recycled as
    // non-owned pot backing at 101 (class-(b) fix); 78 makes it the vault's before 77 (84 until).
    env.crank_fees(true).expect("terminal 78");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let senior = env.earn_execute(&d, Some(lp.portfolio)).expect("senior redeems");
    let (_, g) = env.market_state();
    let physical_left = (g.source_backing_buckets[0].fresh_unliened_backing_num
        + g.source_backing_buckets[1].fresh_unliened_backing_num)
        / percolator::BOUND_SCALE;
    let c_left = env.vlp().senior_claim_atoms;
    let sweep = physical_left.saturating_sub(c_left);
    if sweep > 0 {
        env.release_surplus_resolved(&admin, lp.portfolio, sweep, junior_dest).expect("junior sweeps the terminal surplus");
    }
    let junior_total = env.tok(junior_dest);
    env.paid_out += junior_total as u128;
    let (_, g2) = env.market_state();
    println!(
        "F-8: trader {tr}; junior after settle {after_settle}, after sweep {junior_total}; senior {senior}; left in vault {} (C left {c_left})",
        g2.vault
    );
    assert_eq!(junior_total, 3_900_000, "junior receives principal 3,000,000 + the 900,000 win");
    assert_eq!(senior as u128, 10_000_000 * shares / (shares + 1_000), "senior redeems its full claim (less dead shares)");
    assert!(g2.vault <= 1_000, "only dead-share dust may remain, got {}", g2.vault);
    env.assert_conserved("F-8 terminal");
}

/// F-8, settle-FIRST order (the QA order variants): the vault LP's settlement runs before the
/// losing trader closes, so the trader's loss lands in the pot AFTER tag 101. The junior's win
/// then sits in backing as terminal surplus, which the Resolved path of tag 102 sweeps to it.
#[test]
fn p3_f8_settle_first_then_terminal_sweep_pays_the_junior_its_win() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 3_000_000).expect("junior");
    let t = env.new_trader(5_000_000);
    env.trade(&t, &lp, 3 * POS).expect("trader long 3 vs vault LP");
    env.move_price(700_000, &[lp.portfolio, t.portfolio]);
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    // Settle the (winning) vault LP first; repeat until its resolved close completes.
    for _ in 0..3 {
        env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("settle");
        let p = env.portfolio(lp.portfolio);
        if p.capital == 0 && p.pnl == 0 && percolator::active_bitmap_is_empty(p.active_bitmap) {
            break;
        }
        env.trader_close_resolved(&t);
    }
    for _ in 0..3 {
        let p = env.portfolio(t.portfolio);
        if p.capital == 0 && p.pnl == 0 {
            break;
        }
        env.trader_close_resolved(&t);
    }
    let after_settle = env.tok(junior_dest);
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    let towner = t.kp.pubkey();
    env.permissionless_close_portfolio(t.portfolio, towner).expect("cleanup trader");
    env.crank_fees(true).expect("terminal 78");
    // Before the seniors leave the junior may already take the surplus over C.
    let (_, g) = env.market_state();
    let physical = (g.source_backing_buckets[0].fresh_unliened_backing_num
        + g.source_backing_buckets[1].fresh_unliened_backing_num)
        / percolator::BOUND_SCALE;
    let c = env.vlp().senior_claim_atoms;
    let sweep = physical.saturating_sub(c);
    err_has(
        &env.release_surplus_resolved(&admin, lp.portfolio, sweep + 1, junior_dest),
        PercolatorError::VaultLpReleaseRefused,
    );
    if sweep > 0 {
        env.release_surplus_resolved(&admin, lp.portfolio, sweep, junior_dest).expect("terminal sweep");
    }
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let senior = env.earn_execute(&d, Some(lp.portfolio)).expect("senior redeems after the sweep");
    let junior_total = env.tok(junior_dest);
    env.paid_out += junior_total as u128;
    let (_, g2) = env.market_state();
    println!("F-8 settle-first: junior after settle {after_settle}, swept {sweep}, total {junior_total}; senior {senior}; left {}", g2.vault);
    assert_eq!(junior_total, 3_900_000);
    assert_eq!(senior as u128, 10_000_000 * shares / (shares + 1_000));
    assert!(g2.vault <= 1_000);
    env.assert_conserved("F-8 settle-first");
}

/// Tag 102's Resolved terminal path, positive case: with a terminal surplus over C the junior
/// takes exactly `physical - C` in SPL (1 atom more is refused), and the senior still redeems C.
#[test]
fn p3_f8_terminal_sweep_pays_exactly_the_surplus_over_c() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 3_000_000).expect("junior");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.settle_resolved(&Keypair::new(), lp.portfolio, 0, junior_dest).expect("settle");
    // Resolved but NOT terminal-flat (the settled vault LP is still materialized): refused.
    err_has(&env.release_surplus_resolved(&admin, lp.portfolio, 1, junior_dest), PercolatorError::EngineLockActive);
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    // STATE POKE (see poke_senior_claim): C lowered by 2M, standing in for terminal junior
    // surplus that sits in backing (e.g. a counterparty loss landing after settlement).
    poke_senior_claim(&mut env, 8_000_000);
    // F-14: the settlement returned the whole 3M junior payout to backing, so the terminal
    // surplus is physical 13M - C 8M = 5M.
    err_has(&env.release_surplus_resolved(&admin, lp.portfolio, 5_000_001, junior_dest), PercolatorError::VaultLpReleaseRefused);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    err_has(&env.release_surplus_resolved(&stranger, lp.portfolio, 1, junior_dest), PercolatorError::Unauthorized);
    let before = env.tok(junior_dest);
    env.release_surplus_resolved(&admin, lp.portfolio, 5_000_000, junior_dest).expect("sweep exactly the surplus");
    assert_eq!(env.tok(junior_dest) - before, 5_000_000);
    env.paid_out += env.tok(junior_dest) as u128;
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let senior = env.earn_execute(&d, Some(lp.portfolio)).expect("senior redeems C");
    assert_eq!(senior as u128, 8_000_000 * shares / (shares + 1_000));
    env.assert_conserved("terminal sweep");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Tag 94 is marketauth-only. A protocol path (upgrade authority + ProgramData [8] + signing
// junior [9]) existed briefly and was REMOVED by decision (2026-09-30): relaunch markets are
// created fresh and bound by the marketauth before stake InitPool.
// ═══════════════════════════════════════════════════════════════════════════════════════

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

#[test]
fn p3_init_vault_lp_former_protocol_path_is_refused() {
    // The removed "path B" (upgrade authority signs [0], ProgramData [8], a signing junior at
    // [9]) must be refused: tag 94 is marketauth-only, trailing accounts are ignored.
    let mut env = Env::new(Params::default());
    let protocol = Keypair::new();
    let junior = Keypair::new();
    for k in [&protocol, &junior] {
        env.svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
    }
    let pd = env.set_program_data_authority(&protocol.pubkey());
    err_has(&env.init_vault_lp_protocol(&protocol, pd, &junior, true), PercolatorError::Unauthorized);
    assert!(
        env.svm.get_account(&env.vault_lp).map(|a| a.data.is_empty()).unwrap_or(true),
        "no vault-LP state was created"
    );
    // The marketauth path still binds, and the junior is the marketauth, even with the old
    // path-B tail appended (ignored).
    let admin = env.admin.insecure_clone();
    let m = env.matcher;
    let tail = [AccountMeta::new_readonly(pd, false), AccountMeta::new_readonly(junior.pubkey(), false)];
    let lp = env.init_vault_lp_full(&admin, 1_000, m, &tail).expect("marketauth bind; trailing accounts ignored").portfolio;
    assert_eq!(env.vlp().junior_owner, admin.pubkey().to_bytes());
    assert_eq!(env.vlp().lp_portfolio, lp.to_bytes());
    env.svm.expire_blockhash();
    err_has(&env.junior_deposit_as(&junior, lp, 1_000), PercolatorError::Unauthorized);
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// P2 negotiated fee (P1 fee-request channel) on the vault LP: the requested part is credited
// to the vault LP's capital, i.e. to V and so to the junior; C never moves; the size of the
// request is bounded by the PROTOCOL (tag 93 `max_requested_fee_bps`, upgrade authority) and
// the ctx that produces it is protocol-configured (tag 95). Real P2 matcher BPF.
// ═══════════════════════════════════════════════════════════════════════════════════════

fn p2_matcher_so() -> PathBuf {
    // Same resolution as tests/p1_fee_channel.rs: env, else the CI sibling checkout.
    if let Some(p) = std::env::var_os("P2_MATCHER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-match-p2/target/deploy/percolator_match.so");
    assert!(p.exists(), "P2 matcher BPF not found at {p:?} (set P2_MATCHER_SO)");
    p
}

impl Env {
    /// Tag 93 SetAssetRiskLimits, upgrade-authority signed (ProgramData mocked = admin by
    /// `approve_matcher`).
    fn set_fee_channel(&mut self, matcher_ext_mode: u8, max_requested_fee_bps: u16) -> Result<(), String> {
        let admin = self.admin.insecure_clone();
        let (pd, _) = Pubkey::find_program_address(&[self.pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::ID);
        let market = self.market;
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::SetAssetRiskLimits {
                asset_index: 0,
                exec_band_bps: 0,
                lp_exposure_k_bps: 0,
                lp_floor_atoms: 0,
                side_oi_cap_q: 0,
                matcher_ext_mode,
                max_requested_fee_bps,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(market, false),
            ],
            &[&admin],
        )
        .map(|_| ())
    }
}

/// ceil(ceil(size*price/POS)*bps/1e4) — the engine's fee rounding.
fn engine_fee_atoms(size_abs: u128, price: u64, bps: u64) -> u128 {
    let notional = (size_abs * price as u128).div_ceil(POS as u128);
    (notional * bps as u128).div_ceil(10_000)
}

fn p2_fee_run(ext_mode: u8, max_req: u16) -> (Result<(), String>, i128, i128, u128, u128) {
    let mut env = Env::new_with_matcher(
        Params { fee_bps: 10, ..Params::default() },
        p2_matcher_so(),
    );
    let lpk = env.init_vault_lp(1_000);
    env.approve_matcher();
    let admin = env.admin.insecure_clone();
    let lp = env.vault_lp_set_matcher_spread_as(&admin, lpk, 30).expect("protocol sets a 30 bps spread");
    env.set_fee_channel(ext_mode, max_req).expect("tag 93");
    let d = env.new_depositor();
    env.earn_deposit(&d, 50_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
    let t = env.new_trader(10_000_000);
    let c0 = env.vlp().senior_claim_atoms;
    let nav0 = env.backing_nav();
    let lp0 = env.portfolio(lp.portfolio);
    let t0 = env.portfolio(t.portfolio);
    // Taker signs base 10 + requested 30 = 40 bps.
    let r = env.trade_signing_fee(&t, &lp, 10 * POS, 40);
    let lp1 = env.portfolio(lp.portfolio);
    let t1 = env.portfolio(t.portfolio);
    assert_eq!(env.vlp().senior_claim_atoms, c0, "C never moves on a fill");
    assert_eq!(env.backing_nav(), nav0, "senior backing untouched by the fill");
    (
        r,
        lp1.capital as i128 - lp0.capital as i128,
        t0.capital as i128 - t1.capital as i128,
        c0,
        nav0,
    )
}

#[test]
fn p3_p2_negotiated_fee_accrues_to_vault_nav_junior_and_is_protocol_bounded() {
    let size = 10 * POS as u128;
    let total = engine_fee_atoms(size, PRICE, 40);
    let base = engine_fee_atoms(size, PRICE, 10);
    // Channel ON (P2 ext mode 1, protocol max 100 bps): the requested 30 bps goes to the vault LP.
    let (r, lp_gain, taker_paid, c0, nav0) = p2_fee_run(1, 100);
    r.expect("fill with the fee channel on");
    println!("P2 fee on vault LP: taker paid {taker_paid}, vault LP capital +{lp_gain}, base {base}, total {total}, C {c0}, nav {nav0}");
    assert_eq!(taker_paid as u128, total, "taker pays base + requested");
    assert_eq!(lp_gain as u128, total - base, "the requested part lands in vault-LP capital = V = junior");
    assert!(lp_gain > 0);
    // CONTROL 1: channel OFF — same fill, only the base fee, nothing credited to the vault LP.
    let (r, lp_gain_off, taker_paid_off, _, _) = p2_fee_run(0, 100);
    r.expect("fill with the fee channel off");
    assert_eq!(lp_gain_off, 0, "no request -> no LP credit");
    assert_eq!(taker_paid_off as u128, base);
    // CONTROL 2: the protocol max (20 bps) is below the matcher's 30 bps request -> refused.
    let (r, _, _, _, _) = p2_fee_run(1, 20);
    assert!(r.is_err(), "a request above the protocol max is refused");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// B12 (E2E HIGH, found on 6377376a): terminal insurance recovery (wrapper tag 41, reached by
// stake tag 29) requires `materialized_portfolio_count == 0`, so ONE abandoned portfolio
// stranded the stakers' budget forever. Fixed by the F-4 mechanism: in Resolved mode anyone
// may run the resolved close (pays the OWNER) and then deregister an EMPTY portfolio with
// tag 8 (rent to the OWNER, account [3] pinned to header.owner). A portfolio with anything
// left to claim cannot be deregistered by a stranger (engine emptiness predicate).
// ═══════════════════════════════════════════════════════════════════════════════════════

impl Env {
    fn materialized_count(&self) -> u64 {
        self.market_state().1.materialized_portfolio_count
    }

    fn terminal_insurance_withdraw(&mut self, amount: u128) -> (Result<(), String>, Pubkey) {
        let admin = self.admin.insecure_clone();
        let dest = self.token_account(self.mint, admin.pubkey(), 0);
        self.svm.expire_blockhash();
        let r = self
            .send(
                ProgInstruction::WithdrawInsurance { amount },
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(dest, false),
                    AccountMeta::new(self.vault_token, false),
                    AccountMeta::new_readonly(self.vault_authority, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
                &[&admin],
            )
            .map(|_| ());
        (r, dest)
    }

    /// Tag 56 TopUpInsuranceDomain by the insurance authority (= marketauth here): the
    /// stakers' terminal budget stands in for stake FlushToInsurance.
    fn top_up_insurance_domain0(&mut self, amount: u64) {
        let admin = self.admin.insecure_clone();
        let src = self.token_account(self.mint, admin.pubkey(), amount);
        let data = self.svm.get_account(&self.market).unwrap().data;
        let market_id = state::read_market_trade_preflight(&data, 0).unwrap().3;
        let authority_epoch = state::read_asset_control_sequences(&data, 0).unwrap().authority_epoch;
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::TopUpInsuranceDomain {
                intent_id: 0xB12,
                market_id,
                domain: 0,
                amount: amount as u128,
                authority_epoch,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        )
        .expect("tag 56 top up domain-0 insurance");
        self.paid_in += amount as u128;
    }

    fn stranger_close_resolved(&mut self, portfolio: Pubkey, owner: Pubkey) -> (Result<(), String>, Pubkey) {
        let dest = self.token_account(self.mint, owner, 0);
        self.svm.expire_blockhash();
        let nft_registry = Pubkey::find_program_address(&[b"nft_registry", self.market.as_ref()], &self.pid).0;
        let r = self
            .send(
                ProgInstruction::CloseResolved { fee_rate_per_slot: 0 },
                vec![
                    AccountMeta::new_readonly(owner, false),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(portfolio, false),
                    AccountMeta::new(dest, false),
                    AccountMeta::new(self.vault_token, false),
                    AccountMeta::new_readonly(self.vault_authority, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(nft_registry, false),
                ],
                &[],
            )
            .map(|_| ());
        (r, dest)
    }
}

fn b12_run(bound: bool) {
    let mut env = Env::new(Params { fee_bps: 30, ..Params::default() });
    let admin = env.admin.insecure_clone();
    let walked_away = env.new_trader(5_000_000);
    let lp = if bound {
        let lp = env.bind(1_000);
        env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
        env.trade(&walked_away, &lp, 20 * POS).expect("open; this trader never acts again");
        let (_, g) = env.market_state();
        assert!(g.insurance > 0, "fixture: the trade fee funded insurance");
        Some(lp)
    } else {
        None // P1-only market: the walked-away trader just holds capital
    };
    env.top_up_insurance_domain0(500_000);
    env.resolve();
    if let Some(lp) = lp {
    // Settle and deregister the vault LP (P3's own terminal path).
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    for topup in [0u8, 1u8] {
        let r = env.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        println!("P3 B12 settle topup={topup}: {:?}", r.as_ref().map(|_| ()).map_err(|e| &e[..e.len().min(120)]));
    }
    let registry = env.registry;
    let r = env.permissionless_close_portfolio(lp.portfolio, registry);
    println!("P3 B12 vault LP close: {:?}", r.as_ref().map(|_| ()).map_err(|e| &e[..e.len().min(120)]));
    }
    // B12: the abandoned trader's portfolio blocks terminal insurance recovery.
    let (r, _) = env.terminal_insurance_withdraw(1); // even 1 atom (B12)
    err_has(&r, PercolatorError::EngineLockActive);
    assert!(env.materialized_count() >= 1);
    // A stranger cannot deregister it while it still holds a claim...
    let wowner = walked_away.kp.pubkey();
    err_has(
        &env.permissionless_close_portfolio(walked_away.portfolio, wowner),
        PercolatorError::EngineLockActive,
    );
    // ...runs the resolved close instead (pays the OWNER; loop: progress-only until settled)...
    let mut paid = 0u64;
    for _ in 0..4 {
        let (r, dest) = env.stranger_close_resolved(walked_away.portfolio, wowner);
        paid += env.tok(dest);
        if r.is_ok() && env.portfolio(walked_away.portfolio).capital == 0 {
            break;
        }
    }
    env.paid_out += paid as u128;
    assert!(paid > 0, "the owner, not the stranger, received the resolved payout");
    // ...and cannot redirect the rent...
    err_has(&env.permissionless_close_portfolio(walked_away.portfolio, Pubkey::new_unique()), PercolatorError::Unauthorized);
    // ...but can deregister the now-empty portfolio with rent to the owner.
    env.permissionless_close_portfolio(walked_away.portfolio, wowner).expect("dematerialize the empty portfolio");
    assert_eq!(env.materialized_count(), 0, "materialized_portfolio_count conserved down to 0");
    let (_, g) = env.market_state();
    println!(
        "P3 B12 pre-41: mode {:?} count {} c_tot {} insurance {} vault {}",
        g.mode, g.materialized_portfolio_count, g.c_tot, g.insurance, g.vault
    );
    let (r, dest) = env.terminal_insurance_withdraw(500_000);
    r.expect("terminal insurance recovery is no longer stranded");
    let got = env.tok(dest);
    println!("P3 B12: owner paid {paid}; terminal insurance recovered {got}");
    assert_eq!(got, 500_000, "the whole stakers' budget is recoverable");
    env.paid_out += got as u128;
}

#[test]
fn p3_b12_abandoned_portfolio_cannot_strand_terminal_insurance() {
    b12_run(true);
}

/// Same journey on a market with NO vault LP (P1-only shape): this is the variant that also
/// runs on the P1 FINAL bytes, where it FAILS at the stranger's tag 8 (Custom 8) — B12.
#[test]
fn p3_b12_unbound_market_abandoned_portfolio_cannot_strand_terminal_insurance() {
    b12_run(false);
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Auto-pin at tag 94 (2026-09-30 decision)
// ═══════════════════════════════════════════════════════════════════════════════════════

fn ctx_u128(data: &[u8], off: usize) -> u128 {
    u128::from_le_bytes(data[64 + off..64 + off + 16].try_into().unwrap())
}

#[test]
fn p3_autopin_new_market_trades_immediately_after_bind() {
    let mut env = Env::new(Params::default());
    let admin = env.admin.insecure_clone();
    let m = env.matcher;
    // tag 94 ALONE (no 99/95): canonical matcher approved, 1x cap, ctx initialised by the program.
    let lp = env.init_vault_lp_full(&admin, 1_000, m, &[]).expect("bind + auto-pin");
    let rec = env.asset_rec();
    assert_eq!(rec.approved_matcher_program, CANONICAL_MATCHER.to_bytes());
    assert_eq!(rec.vault_lp_max_lev_bps, 0, "0 = the 1x default");
    let ctx = env.svm.get_account(&lp.ctx).unwrap().data;
    let caps = percolator_prog::vault_lp_v18::pinned_matcher_caps(PRICE).unwrap();
    assert_eq!(ctx[64 + 12], percolator_prog::vault_lp_v18::PIN_MATCHER_KIND, "vAMM kind pinned");
    assert_eq!(ctx_u128(&ctx, 64), caps.liquidity_notional_e6);
    assert_eq!(ctx_u128(&ctx, 80), caps.max_fill_abs, "finite fill cap pinned");
    assert_eq!(ctx_u128(&ctx, 128), caps.max_inventory_abs, "finite inventory cap pinned");
    assert!(caps.max_fill_abs > 0 && caps.max_inventory_abs > 0);
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let t = env.new_trader(10_000_000);
    env.trade(&t, &lp, 10 * POS).expect("trades immediately after tag 94 (no protocol activation)");
    assert_eq!(env.position(t.portfolio), 10 * POS);
    env.svm.expire_blockhash();
    env.trade(&t, &lp, -10 * POS).expect("close");
    // the 1x exposure default binds: 20M junior at $1 => 20 units max.
    let t2 = env.new_trader(50_000_000);
    err_has(&env.trade(&t2, &lp, 21 * POS), PercolatorError::VaultLpExposureCapExceeded);
    env.assert_conserved("auto-pin");
}

#[test]
fn p3_autopin_creator_cannot_choose_matcher_or_caps() {
    let mut env = Env::new(Params::default());
    let admin = env.admin.insecure_clone();
    // Another matcher program (same bytes, different id) is refused.
    let other = Pubkey::new_unique();
    env.svm.add_program(other, &std::fs::read(matcher_program_path()).unwrap());
    err_has(&env.init_vault_lp_full(&admin, 1_000, other, &[]).map(|_| ()), PercolatorError::VaultLpMatcherNotApproved);
    // Caps are not instruction data: appending "looser caps" bytes is refused by the decoder.
    let mut data = ProgInstruction::InitVaultLp { junior_floor_bps: 1_000 }.encode();
    data.extend_from_slice(&u128::MAX.to_le_bytes());
    data.extend_from_slice(&u128::MAX.to_le_bytes());
    let lp = env.new_program_account(env.plen);
    let ix = Instruction {
        program_id: env.pid,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new(env.vault_lp, false),
            AccountMeta::new(lp, false),
        ],
        data,
    };
    env.svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&env.payer.pubkey()), &[&env.payer, &admin], env.svm.latest_blockhash());
    let r = env.svm.send_transaction(tx);
    assert!(
        format!("{:?}", r.as_ref().err()).contains("InvalidInstructionData"),
        "caps in instruction data must be refused: {r:?}"
    );
    // The honest bind still works afterwards and pins the protocol caps.
    let m = env.matcher;
    let lp = env.init_vault_lp_full(&admin, 1_000, m, &[]).expect("canonical bind");
    let ctx = env.svm.get_account(&lp.ctx).unwrap().data;
    assert_eq!(ctx_u128(&ctx, 80), percolator_prog::vault_lp_v18::pinned_matcher_caps(PRICE).unwrap().max_fill_abs);
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Earn redeem-lock (frontend-lane HIGH): fees unharvested at resolution. Tag 78 now runs on a
// TERMINAL-FLAT Resolved bound market, so the fees reach C (seniors) and 77 is unlocked.
// ═══════════════════════════════════════════════════════════════════════════════════════

impl Env {
    fn stranger_wind_down(&mut self, lp: &Lp, traders: &[&Trader]) {
        let admin = self.admin.insecure_clone();
        let junior_dest = self.token_account(self.mint, admin.pubkey(), 0);
        for topup in [0u8, 1u8] {
            let _ = self.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        }
        self.paid_out += self.tok(junior_dest) as u128;
        for t in traders {
            let owner = t.kp.pubkey();
            for _ in 0..4 {
                let (r, dest) = self.stranger_close_resolved(t.portfolio, owner);
                self.paid_out += self.tok(dest) as u128;
                if r.is_ok() && self.portfolio(t.portfolio).capital == 0 {
                    break;
                }
            }
            self.permissionless_close_portfolio(t.portfolio, owner).expect("trader cleanup");
        }
        let registry = self.registry;
        self.permissionless_close_portfolio(lp.portfolio, registry).expect("vault LP cleanup");
        assert_eq!(self.materialized_count(), 0, "terminal-flat");
    }
}

#[test]
fn p3_resolved_fees_reach_seniors_and_unlock_earn_redemption() {
    let mut env = Env::new(Params { fee_bps: 30, ..Params::default() });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 60_000_000).expect("junior");
    let t = env.new_trader(20_000_000);
    env.trade(&t, &lp, 50 * POS).expect("open");
    env.svm.expire_blockhash();
    env.trade(&t, &lp, -50 * POS).expect("close");
    let (cfg0, _) = env.market_state();
    let pending = cfg0.lp_fee_accrued_atoms - cfg0.lp_fee_withdrawn_atoms;
    assert!(pending > 0, "fixture: LP fees unharvested at resolution");
    env.resolve();
    env.stranger_wind_down(&lp, &[&t]);
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    err_has(&env.earn_execute(&d, Some(lp.portfolio)), PercolatorError::VaultLpHarvestPending);
    let c0 = env.vlp().senior_claim_atoms;
    env.svm.expire_blockhash();
    env.crank_fees(true).expect("tag 78 on a terminal-flat Resolved bound market");
    let (cfg1, _) = env.market_state();
    let harvested = cfg1.lp_fee_withdrawn_atoms - cfg0.lp_fee_withdrawn_atoms;
    assert_eq!(harvested, pending, "the whole pending leg is harvested");
    assert_eq!(env.vlp().senior_claim_atoms, c0 + harvested, "fees credited to the seniors' claim");
    env.svm.expire_blockhash();
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("Earn redeems after the resolved harvest");
    println!("P3 redeem-lock: pending {pending}, C {c0}->{}, Earn paid {paid}", c0 + harvested);
    assert!(paid as u128 > 10_000_000, "the senior was paid its principal plus the fees ({paid})");
    env.assert_conserved("resolved harvest + redemption");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// C-4(b): on a real runtime the closed (0-lamport) vault-LP portfolio is garbage-collected
// (system-owned, empty). LiteSVM keeps it, so the GC is EMULATED here by replacing it with
// the default account. Redemption must still work (it never reads the LP in Resolved mode).
// ═══════════════════════════════════════════════════════════════════════════════════════

#[test]
fn p3_c4b_redemption_survives_the_vault_lp_account_being_garbage_collected() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    env.resolve();
    env.stranger_wind_down(&lp, &[]);
    // Runtime GC emulation: the closed account ceases to exist.
    env.svm
        .set_account(
            lp.portfolio,
            Account { lamports: 0, data: vec![], owner: solana_sdk::system_program::ID, executable: false, rent_epoch: 0 },
        )
        .unwrap();
    let gone = env.svm.get_account(&lp.portfolio);
    assert!(gone.map(|a| a.owner == solana_sdk::system_program::ID && a.data.is_empty()).unwrap_or(true));
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    env.svm.expire_blockhash();
    let paid = env.earn_execute(&d, Some(lp.portfolio)).expect("redemption after the vault LP was GC'd");
    println!("P3 C-4(b): Earn paid {paid} with the vault LP account gone");
    assert!(paid > 0);
    // A different key in the LP slot is still refused (the tail stays pinned).
    let d2 = env.new_depositor();
    let _ = d2;
    env.assert_conserved("C-4(b)");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// F-14 root cause: outside NoCpi pairs on a bound asset spent the vault's backing (their
// winner is paid from the same pots). The vault LP is now the EXCLUSIVE counterparty on
// every route: risk-increasing TradeNoCpi / BatchTradeNoCpi on a bound asset -> 77.
// ═══════════════════════════════════════════════════════════════════════════════════════

impl Env {
    fn trade_nocpi(&mut self, a: &Trader, b: &Trader, size_q: i128) -> Result<(), String> {
        let (a_id, _, a_ep) = self.identity(a.portfolio);
        let (b_id, _, b_ep) = self.identity(b.portfolio);
        let market_id =
            state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, 0)
                .unwrap()
                .3;
        let (cfg, _) = self.market_state();
        let (ka, kb) = (a.kp.insecure_clone(), b.kp.insecure_clone());
        self.svm.expire_blockhash();
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_ep,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_ep,
                asset_index: 0,
                market_id,
                size_q,
                exec_price: PRICE,
                fee_bps: cfg.trade_fee_base_bps,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(ka.pubkey(), true),
                AccountMeta::new(kb.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(a.portfolio, false),
                AccountMeta::new(b.portfolio, false),
            ],
            &[&ka, &kb],
        )
        .map(|_| ())
    }
}

#[test]
fn p3_f14_outside_nocpi_cannot_grow_on_a_bound_asset() {
    let mut env = Env::new(Params::default());
    let a = env.new_trader(10_000_000);
    let b = env.new_trader(10_000_000);
    // Before binding, a NoCpi pair may open (the pre-P3 market shape)...
    env.trade_nocpi(&a, &b, 5 * POS).expect("unbound: NoCpi open");
    // ...but a vault can no longer be bound while it is open (gate HIGH lock, 2026-09-30: tag 94
    // refuses with VaultLpBindRequiresFlatAsset while the asset has open interest; see
    // p3_resolved_lock::p3_bind_refused_while_asset_has_open_interest). Unwind it first.
    env.trade_nocpi(&a, &b, -5 * POS).expect("unbound: NoCpi unwind");
    assert_eq!(env.position(a.portfolio), 0);
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    // Bound: growing either outside side is refused.
    err_has(&env.trade_nocpi(&a, &b, POS), PercolatorError::VaultLpExclusiveCounterparty);
    let c = env.new_trader(10_000_000);
    let d = env.new_trader(10_000_000);
    err_has(&env.trade_nocpi(&c, &d, POS), PercolatorError::VaultLpExclusiveCounterparty);
    // Trading still works through the vault LP.
    env.trade(&c, &lp, 2 * POS).expect("vault LP route");
    env.assert_conserved("F-14 NoCpi exclusivity");
}

/// F-14 (independent fuzz, CPI-only shape of `anvil_c`): two traders on opposite sides of the
/// vault LP, a price move, Resolve, closes in either order. Two senior Earn holders exit (in
/// either order), then the junior sweeps. Every senior is paid in full before the junior gets
/// anything, nothing is stranded, and the outcome does not depend on the order.
fn f14_two_trader_run(traders_first: bool, senior_b_first: bool) -> (u64, u64, u64, u128) {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let da = env.new_depositor();
    env.earn_deposit(&da, 10_000_000, Some(lp.portfolio)).expect("earn A");
    let db = env.new_depositor();
    env.earn_deposit(&db, 228_224, Some(lp.portfolio)).expect("earn B");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let t1 = env.new_trader(5_000_000);
    let t2 = env.new_trader(5_000_000);
    env.trade(&t1, &lp, 13 * POS + POS * 8 / 10).expect("t1 long 13.8");
    env.move_price(825_000, &[lp.portfolio, t1.portfolio]);
    env.svm.expire_blockhash();
    env.trade(&t2, &lp, -(15 * POS + POS * 2 / 10)).expect("t2 short 15.2");
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let mut paid_traders = 0u64;
    let close_traders = |env: &mut Env, paid: &mut u64| {
        for t in [&t1, &t2] {
            for _ in 0..4 {
                let (r, dest) = env.stranger_close_resolved(t.portfolio, t.kp.pubkey());
                *paid += env.tok(dest);
                if r.is_ok() && env.portfolio(t.portfolio).capital == 0 && env.portfolio(t.portfolio).pnl == 0 {
                    break;
                }
            }
        }
    };
    if traders_first {
        close_traders(&mut env, &mut paid_traders);
        for topup in [0u8, 1u8] {
            let _ = env.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        }
        close_traders(&mut env, &mut paid_traders);
    } else {
        for topup in [0u8, 1u8] {
            let _ = env.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        }
        close_traders(&mut env, &mut paid_traders);
        for topup in [0u8, 1u8] {
            let _ = env.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        }
    }
    env.paid_out += paid_traders as u128;
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    for t in [&t1, &t2] {
        env.permissionless_close_portfolio(t.portfolio, t.kp.pubkey()).expect("cleanup trader");
    }
    assert_eq!(env.materialized_count(), 0, "terminal-flat");
    env.svm.expire_blockhash();
    let _ = env.crank_fees(true); // terminal harvest + residual absorption (78)
    let order = if senior_b_first { [&db, &da] } else { [&da, &db] };
    let mut senior_paid = [0u64; 2];
    for (i, d) in order.iter().enumerate() {
        let shares = env.lp_shares(d);
        env.earn_request(d, shares);
        env.svm.expire_blockhash();
        senior_paid[i] = env.earn_execute(d, Some(lp.portfolio)).expect("every senior exits after Resolve");
    }
    let (pa, pb) = if senior_b_first { (senior_paid[1], senior_paid[0]) } else { (senior_paid[0], senior_paid[1]) };
    env.junior_terminal_sweep(&admin, lp.portfolio, junior_dest);
    let junior = env.tok(junior_dest);
    env.paid_out += junior as u128;
    env.assert_conserved("F-14 two traders");
    let (_, g) = env.market_state();
    println!(
        "F-14 two-trader traders_first={traders_first} b_first={senior_b_first}: traders {paid_traders}, seniors A {pa} B {pb}, junior {junior}, left vault {} ins {}",
        g.vault, g.insurance
    );
    // Seniors whole before the junior: each gets its full claim less dead-share dust.
    assert!(pa as u128 >= 10_000_000 - 1_000 && pb as u128 >= 228_224 - 25, "seniors whole: {pa} {pb}");
    // Nothing stranded beyond insurance + dead-share dust.
    assert!(g.vault <= g.insurance + 1_100, "stranded {}", g.vault - g.insurance);
    (pa, pb, junior, g.vault)
}

#[test]
fn p3_f14_two_traders_every_senior_exits_nothing_strands_any_order() {
    let base = f14_two_trader_run(false, false);
    for (tf, bf) in [(true, false), (false, true), (true, true)] {
        let r = f14_two_trader_run(tf, bf);
        assert!(r.0.abs_diff(base.0) <= 1 && r.1.abs_diff(base.1) <= 1, "senior payouts order-independent: {r:?} vs {base:?}");
        assert!(r.2.abs_diff(base.2) <= 2, "junior order-independent: {r:?} vs {base:?}");
    }
}


/// F-14 class on tag 98 (independent lane: 25 EngineCounterUnderflow at a 1-atom shortfall on
/// 07a1d0eb). The underflow is the engine NAV's fail-closed `principal - impairment` when the
/// ledger books more impairment than principal (backing lent to a winner still outstanding as a
/// provider receivable). STATE POKE (as `poke_senior_claim`): the own-domain ledger's
/// cumulative loss is set 1 atom above its principal and C above the backing, a real senior
/// shortfall; recall must then be bounded and never underflow (floored NAV = 0).
#[test]
fn p3_f14_recall_with_impairment_above_principal_never_underflows() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 20_000_000).expect("junior");
    let mut acct = env.svm.get_account(&env.ledger).unwrap();
    let mut l = state::read_backing_domain_ledger(&acct.data).unwrap();
    l.cumulative_loss_atoms = l.total_principal_atoms + 1;
    state::write_backing_domain_ledger(&mut acct.data, &l).unwrap();
    env.svm.set_account(env.ledger, acct).unwrap();
    poke_senior_claim(&mut env, 10_000_001);
    // Shortfall = C_eff - floored NAV = 10,000,001 - 0. Over the bound: refused cleanly.
    env.svm.expire_blockhash();
    err_has(&env.recall(lp.portfolio, 10_000_002, DOMAIN), PercolatorError::VaultLpRecallRefused);
    // Within it: recall 1 atom of junior capital (never an underflow).
    env.svm.expire_blockhash();
    let r = env.recall(lp.portfolio, 1, DOMAIN);
    println!("F-14/98: recall 1 with impairment > principal -> {:?}", r.as_ref().map(|_| ()).map_err(|e| &e[..e.len().min(90)]));
    r.expect("recall is bounded by the floored shortfall, never an underflow");
}

/// E2E B9 (HIGH, found on 6377376a): after a resolve, winners' payouts depended on the LP owner
/// signing and on call order. On a P3 market the LP owner is the registry PDA (cannot sign):
/// three winners against the vault LP (loser), NO LP-owner signature anywhere (101 and
/// CloseResolved are both called by strangers), every call order — every winner is paid in full
/// and the payouts are identical across orders.
fn b9_run(order: u8) -> Vec<u64> {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 30_000_000).expect("junior");
    let ts: Vec<Trader> = (0..3).map(|_| env.new_trader(5_000_000)).collect();
    for (i, t) in ts.iter().enumerate() {
        env.svm.expire_blockhash();
        env.trade(t, &lp, (4 + i as i128) * POS).expect("winner opens long vs vault LP");
    }
    let ports: Vec<Pubkey> = std::iter::once(lp.portfolio).chain(ts.iter().map(|t| t.portfolio)).collect();
    env.move_price(1_200_000, &ports);
    env.resolve();
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    let mut paid = vec![0u64; 3];
    let close = |env: &mut Env, paid: &mut Vec<u64>, i: usize| {
        let (_, dest) = env.stranger_close_resolved(ts[i].portfolio, ts[i].kp.pubkey());
        paid[i] += env.tok(dest);
    };
    let settle = |env: &mut Env| {
        for topup in [0u8, 1u8] {
            let _ = env.settle_resolved(&Keypair::new(), lp.portfolio, topup, junior_dest);
        }
    };
    let seq: Vec<i8> = match order {
        0 => vec![-1, 0, 1, 2],
        1 => vec![2, 1, 0, -1, 2, 1, 0],
        2 => vec![1, -1, 2, 0, 1],
        _ => vec![0, 2, -1, 1, 0, 2],
    };
    for step in seq {
        if step < 0 { settle(&mut env) } else { close(&mut env, &mut paid, step as usize) }
    }
    for _ in 0..3 {
        for (i, t) in ts.iter().enumerate() {
            if env.portfolio(t.portfolio).capital != 0 || env.portfolio(t.portfolio).pnl != 0 {
                close(&mut env, &mut paid, i);
            }
        }
        settle(&mut env);
    }
    for (i, t) in ts.iter().enumerate() {
        let p = env.portfolio(t.portfolio);
        assert!(p.capital == 0 && p.pnl == 0, "winner {i} fully paid out (cap {} pnl {})", p.capital, p.pnl);
    }
    env.paid_out += paid.iter().map(|x| *x as u128).sum::<u128>();
    env.assert_conserved("B9");
    println!("B9 order {order}: winners paid {paid:?}");
    paid
}

#[test]
fn p3_b9_every_winner_paid_in_full_without_lp_signature_any_order() {
    let base = b9_run(0);
    for (i, p) in base.iter().enumerate() {
        // capital 5,000,000 + a +20% win on (4+i) units at $1 (less fees at 0 bps)
        assert!(*p >= 5_000_000 + (4 + i as u64) * 200_000 - 1_000, "winner {i} got {p}");
    }
    for order in 1..4 {
        assert_eq!(b9_run(order), base, "winners' payouts must not depend on call order");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// F14-Q2: a vault LP needs a single-asset market (the terminal residual is market-wide and is
// credited to the one vault). 94 refuses while another asset has activity; after binding, no
// other asset may be backed / traded / activated.
// ═══════════════════════════════════════════════════════════════════════════════════════


#[test]
fn p3_q2_bind_refused_on_a_multi_asset_market() {
    // Two configured asset slots (even with asset 1 idle): refused, no state created.
    let mut env = Env::new(Params { assets: 2, ..Params::default() });
    let admin = env.admin.insecure_clone();
    let m = env.matcher;
    let m0 = env.svm.get_account(&env.market).unwrap().data;
    err_has(&env.init_vault_lp_full(&admin, 1_000, m, &[]).map(|_| ()), PercolatorError::VaultLpMultiAssetMarket);
    assert_eq!(env.svm.get_account(&env.market).unwrap().data, m0, "market unchanged");
    assert!(env.svm.get_account(&env.vault_lp).map(|a| a.data.is_empty()).unwrap_or(true), "no vault-LP state");
    // Control: the single-asset market binds.
    let mut env1 = Env::new(Params::default());
    let admin1 = env1.admin.insecure_clone();
    let m1 = env1.matcher;
    env1.init_vault_lp_full(&admin1, 1_000, m1, &[]).expect("single-asset market binds");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// F14-Q1: per-pot NAV floors overstated the combined value when one pot's impairment exceeds
// its principal while the other pot is positive. The bound-vault NAV now floors ONCE across
// both pots (and is capped at the backing the vault still owns).
// ═══════════════════════════════════════════════════════════════════════════════════════

impl Env {
    fn earn_deposit_domain(&mut self, d: &Depositor, amount: u64, domain: u16, tail: Option<Pubkey>) -> Result<(), String> {
        // [7] is always registry.domain's ledger, [10] the sibling's (the target pot is `domain`).
        let accts = self.deposit_accounts(d, tail);
        let kp = d.kp.insecure_clone();
        self.svm.expire_blockhash();
        let r = self.send(ProgInstruction::DepositToLpVault { amount: amount as u128, domain }, accts, &[&kp]);
        if r.is_ok() {
            self.paid_in += amount as u128;
        }
        r
    }
}

#[test]
fn p3_q1_cross_pot_impairment_is_not_overstated() {
    // 2026-09-30 (senior draw FINAL): a bound vault is now priced on the backing it PHYSICALLY
    // owns free of live winner claims, not on the pot ledgers (the ledgers booked consumption of
    // non-principal backing as impairment and under-priced seniors). A ledger-only impairment
    // poke therefore no longer moves the price in EITHER direction: it can neither overstate nor
    // understate the vault. Real consumption (backing lent to a winner) is exercised end to end by
    // `p3_draw_*` (tests/p3_senior_draw.rs).
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let a = env.new_depositor();
    env.earn_deposit(&a, 10_000_000, Some(lp.portfolio)).expect("A into pot 0");
    let b = env.new_depositor();
    env.earn_deposit_domain(&b, 5_000_000, 1, Some(lp.portfolio)).expect("B into pot 1");
    env.junior_deposit_as(&admin, lp.portfolio, 10_200_000).expect("junior 10.2M");
    assert_eq!(env.vlp().senior_claim_atoms, 15_000_000);
    // STATE POKE: pot 0's LEDGER says 0.5M past its principal is impaired; the pots are intact.
    let mut acct = env.svm.get_account(&env.ledger).unwrap();
    let mut l = state::read_backing_domain_ledger(&acct.data).unwrap();
    l.cumulative_loss_atoms = l.total_principal_atoms + 500_000;
    state::write_backing_domain_ledger(&mut acct.data, &l).unwrap();
    env.svm.set_account(env.ledger, acct).unwrap();
    // Physical free backing = 15M = C: not impaired, so a deposit is priced at C/S.
    let c = env.new_depositor();
    env.earn_deposit(&c, 1_000_000, Some(lp.portfolio)).expect("priced on physical backing");
    // 102 live: no surplus over C -> refused.
    env.svm.expire_blockhash();
    err_has(&env.release_surplus(&admin, lp.portfolio, 1, DOMAIN), PercolatorError::VaultLpReleaseRefused);
    // 77 pays the full pro-rata claim (physical backing covers C).
    let shares = env.lp_shares(&a);
    env.earn_request(&a, shares);
    let s = env.registry_state().total_lp_shares_outstanding;
    let cc = env.vlp().senior_claim_atoms;
    env.svm.expire_blockhash();
    let paid = env.earn_execute(&a, Some(lp.portfolio)).expect("redemption");
    assert_eq!(paid as u128, shares * cc / s, "priced on physical backing, not the ledger poke");
}

/// Deadlock review (frontend lane): on a terminal-flat Resolved bound market with nothing to
/// harvest and nothing to absorb (e.g. the engine's own recredit already cleared the residual),
/// tag 78 must SUCCEED as a no-op — it is the step 77 waits for — instead of reverting with
/// NoFeesToCrank (which would also revert that recredit and leave 77 at 84 forever).
#[test]
fn p3_terminal_crank_is_a_noop_success_when_nothing_is_pending() {
    let mut env = Env::new(Params::default());
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("earn");
    env.junior_deposit_as(&admin, lp.portfolio, 5_000_000).expect("junior");
    env.resolve();
    env.stranger_wind_down(&lp, &[]);
    let (cfg, _) = env.market_state();
    assert_eq!(cfg.lp_fee_accrued_atoms, cfg.lp_fee_withdrawn_atoms, "fixture: no fees pending");
    env.svm.expire_blockhash();
    env.crank_fees(true).expect("terminal 78 with nothing pending is a no-op success");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    env.svm.expire_blockhash();
    env.earn_execute(&d, Some(lp.portfolio)).expect("the senior exits");
    let junior_dest = env.token_account(env.mint, admin.pubkey(), 0);
    env.junior_terminal_sweep(&admin, lp.portfolio, junior_dest);
    env.paid_out += env.tok(junior_dest) as u128;
    env.assert_conserved("terminal no-op crank");
}

/// Reviewer LOW (39b138c8): 98 capped the recall at the vault LP's certified equity computed
/// BEFORE the maintenance fee was collected, so recalling the full equity left the LP at -fee.
/// The cap is now taken on POST-fee equity: a recall of the pre-fee equity is refused, and a recall
/// of the post-fee equity leaves the LP at >= 0.
#[test]
fn p3_recall_cap_is_post_maintenance_fee() {
    let mut env = Env::new(Params { maint_fee: 100, ..Params::default() });
    let lp = env.bind(1_000);
    let admin = env.admin.insecure_clone();
    let d = env.new_depositor();
    env.earn_deposit(&d, 10_000_000, Some(lp.portfolio)).expect("senior");
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000).expect("junior");
    // Senior shortfall so the recall limit itself is not the binding constraint.
    poke_senior_claim(&mut env, 12_000_000);
    // Let the maintenance fee accrue on the (flat) vault LP.
    env.slot += 1_000;
    env.svm.warp_to_slot(env.slot);
    let pre = env.portfolio(lp.portfolio);
    let pre_equity = pre.capital as i128 + pre.pnl.min(0) + pre.fee_credits.min(0);
    env.svm.expire_blockhash();
    let r = env.recall(lp.portfolio, pre_equity as u128, DOMAIN);
    let post = env.portfolio(lp.portfolio);
    let post_equity = post.capital as i128 + post.pnl.min(0) + post.fee_credits.min(0);
    println!("recall of pre-fee equity {pre_equity} -> {r:?}; LP capital {} fee_credits {} equity {post_equity}", post.capital, post.fee_credits);
    assert!(post_equity >= 0, "a recall must never leave the vault LP below zero (equity {post_equity})");
    // The wrapper's own post-fee cap refuses it by name (on 39b138c8 the pre-fee cap let it
    // through to the engine, which failed it with a generic 21).
    err_has(&r, PercolatorError::VaultLpRecallRefused);
    // Recalling exactly the post-fee equity succeeds and leaves the LP at >= 0.
    env.svm.expire_blockhash();
    let lp_now = env.portfolio(lp.portfolio);
    let fee_due = 100u128 * 1_000; // maint_fee x slots elapsed (upper bound)
    let post_fee = lp_now.capital.saturating_sub(fee_due);
    let r2 = env.recall(lp.portfolio, post_fee, DOMAIN);
    let after = env.portfolio(lp.portfolio);
    let after_equity = after.capital as i128 + after.pnl.min(0) + after.fee_credits.min(0);
    println!("recall of post-fee equity {post_fee} -> {r2:?}; LP equity after {after_equity}");
    assert!(r2.is_ok(), "the post-fee equity is recallable");
    assert!(after_equity >= 0);
    env.assert_conserved("recall post-fee");
}

// ─────────────────────────────────────────────────────────────────────────────
// growth-v19 on a BOUND (P3) market: tag 94 `l_launch`, the non-binding auto-pin and the
// ext-v3 capital-derived depth (plan §2.1 / §2.2). Each test pairs with a legacy control.
// ─────────────────────────────────────────────────────────────────────────────

/// Matcher context account bytes (context at offset 64; see percolator-match vamm.rs layout).
const CTX_LIQUIDITY_OFF: usize = 64 + 64;
const CTX_MAX_FILL_OFF: usize = 64 + 80;
const CTX_LAST_EXEC_OFF: usize = 64 + 120;
const CTX_MAX_INVENTORY_OFF: usize = 64 + 128;

fn gctx_u128(env: &Env, ctx: Pubkey, off: usize) -> u128 {
    let d = env.svm.get_account(&ctx).unwrap().data;
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

fn ctx_u64(env: &Env, ctx: Pubkey, off: usize) -> u64 {
    let d = env.svm.get_account(&ctx).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

/// N-2: a growth taker signs room for base + the matcher request + the utilisation fee (the
/// charge is what the wrapper computes, never more than this signed maximum).
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

fn growth_rec(env: &Env) -> Option<state::AssetGrowthV19> {
    state::read_asset_growth(&env.svm.get_account(&env.market).unwrap().data, 0, 1_000).unwrap()
}

#[test]
fn growth_v19_tag94_l_launch_rules_and_non_binding_pin() {
    let gerr = "Custom(94)";
    // growth OFF: an l_launch trailer is refused (no growth block to set it on)
    let mut legacy = Env::new(Params::default());
    let admin = legacy.admin.insecure_clone();
    let m = legacy.matcher;
    let r = legacy.init_vault_lp_full_launch(&admin, 2_000, m, &[], Some(500));
    assert!(r.as_ref().err().is_some_and(|e| e.contains(gerr)), "growth off: {r:?}", r = r.as_ref().map(|_| ()));
    // legacy bind (no trailer) pins the fixed $25k inventory / $5k fill caps
    let llp = legacy.init_vault_lp_full_launch(&admin, 2_000, m, &[], None).expect("legacy bind");
    let legacy_inv = gctx_u128(&legacy, llp.ctx, CTX_MAX_INVENTORY_OFF);
    assert_eq!(legacy_inv, 25_000 * 1_000_000, "$25k at $1");
    assert_eq!(gctx_u128(&legacy, llp.ctx, CTX_MAX_FILL_OFF), 5_000 * 1_000_000);

    // growth ON: above the tier (10x) refused; within it, written
    let mut env = Env::new(growth_params());
    let admin = env.admin.insecure_clone();
    let m = env.matcher;
    let r = env.init_vault_lp_full_launch(&admin, 2_000, m, &[], Some(1_001));
    assert!(r.as_ref().err().is_some_and(|e| e.contains(gerr)), "above tier");
    let lp = env.init_vault_lp_full_launch(&admin, 2_000, m, &[], Some(550)).expect("growth bind");
    let g = growth_rec(&env).expect("growth on");
    assert_eq!((g.l_launch_x100, g.ceil_x100, g.l_tier_x100), (550, 550, 1_000));
    // N_cap replaces the fixed caps: the pinned context caps are finite but non-binding
    let engine_max = percolator_prog::vault_lp_v18::ENGINE_MAX_POSITION_ABS_Q;
    assert_eq!(gctx_u128(&env, lp.ctx, CTX_MAX_INVENTORY_OFF), engine_max);
    assert_eq!(gctx_u128(&env, lp.ctx, CTX_MAX_FILL_OFF), engine_max);
    assert_eq!(
        gctx_u128(&env, lp.ctx, CTX_LIQUIDITY_OFF),
        percolator_prog::growth_v19::GROWTH_PIN_LIQUIDITY_E6
    );
    // a growth bind without the trailer keeps the InitMarket l_launch (10x)
    let mut env2 = Env::new(growth_params());
    let admin2 = env2.admin.insecure_clone();
    let m2 = env2.matcher;
    env2.init_vault_lp_full_launch(&admin2, 2_000, m2, &[], None).expect("bind");
    assert_eq!(growth_rec(&env2).unwrap().l_launch_x100, 1_000);
}

/// The ext-v3 depth is `lambda * C_m`: the same fill moves the vAMM quote more on a market with
/// less junior capital. NEGATIVE CONTROL: on the legacy pin (fixed $250k depth, no v3) junior
/// capital does not change the quote.
#[test]
fn growth_v19_bound_quote_depth_scales_with_capital() {
    fn last_exec_after_fill(p: Params, junior: u64) -> u64 {
        let mut env = Env::new(p);
        let lp = env.bind(2_000);
        let admin = env.admin.insecure_clone();
        env.junior_deposit_as(&admin, lp.portfolio, junior).expect("junior");
        let t = env.new_trader(1_000_000_000);
        // G4: a growth bind turns the fee channel on (50 bps cap), so the taker signs a fee
        // that covers base + the matcher's requested fee.
        env.trade_signing_fee(&t, &lp, 100 * 1_000_000, GROWTH_FEE).expect("fill 100 units");
        assert_eq!(env.position(t.portfolio), 100 * 1_000_000, "filled in full");
        ctx_u64(&env, lp.ctx, CTX_LAST_EXEC_OFF)
    }
    let thin = last_exec_after_fill(growth_params(), 1_000_000_000); // $1k junior
    let deep = last_exec_after_fill(growth_params(), 50_000_000_000); // $50k junior
    assert!(thin > deep, "growth: thin {thin} must quote worse than deep {deep}");
    // legacy pin: the junior size does not move the quote
    let l_thin = last_exec_after_fill(Params::default(), 1_000_000_000);
    let l_deep = last_exec_after_fill(Params::default(), 50_000_000_000);
    assert_eq!(l_thin, l_deep, "legacy: depth is the fixed pinned value");
    eprintln!("growth thin {thin} deep {deep}; legacy {l_thin} / {l_deep}");
}

/// The bound vault LP's capacity is `lambda * C_m` with the growth lambda (1x). Q3: a crowd fill
/// may take the LP exactly TO capacity (u == 1), never beyond (the CPI clip lands on N_cap and
/// the next crowd request zero-fills); the thin side stays open.
#[test]
fn growth_v19_bound_capacity_full_and_thin_side_open() {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    let whale = env.new_trader(100_000_000_000);
    // N_cap from the LP's CURRENT conservative equity (the fee channel credits the LP, so C_m
    // and N_cap grow after each fill).
    let n_cap = |env: &Env| -> u128 {
        let p = env.portfolio(lp.portfolio);
        let c_m = percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap();
        percolator_prog::growth_v19::n_cap_q(c_m, 10_000, PRICE, POS as u128).unwrap()
    };
    let cap_before = n_cap(&env);
    assert_eq!(cap_before, 1_000 * 1_000_000);
    env.trade_signing_fee(&whale, &lp, 5_000 * 1_000_000, GROWTH_FEE).expect("clipped to u == 1");
    assert_eq!(env.position(lp.portfolio).unsigned_abs(), cap_before, "|LP| == N_cap (pre-fill C_m) exactly");
    for _ in 0..3 {
        env.trade_signing_fee(&whale, &lp, 5_000 * 1_000_000, GROWTH_FEE).expect("crowd at capacity");
        assert!(env.position(lp.portfolio).unsigned_abs() <= n_cap(&env), "never above N_cap(C_m)");
    }
    let thin = env.new_trader(20_000_000);
    env.trade_signing_fee(&thin, &lp, -(100 * 1_000_000), GROWTH_FEE).expect("thin side open");
    assert_eq!(env.position(thin.portfolio), -(100 * 1_000_000));
}

const CTX_KIND_OFF: usize = 64 + 12;

fn risk_limits(env: &Env) -> state::AssetRiskLimitsV17 {
    state::read_asset_risk_limits(&env.svm.get_account(&env.market).unwrap().data, 0).unwrap()
}

/// G4: a growth bind writes the protocol risk defaults (ext mode 1, fee channel 100 bps, LP floor
/// $1) and pins the kind-2 adaptive matcher; a legacy bind does neither; an upgrade-authority
/// tag-93 record set before the bind is never overwritten.
#[test]
fn growth_v19_tag94_g4_defaults() {
    use percolator_prog::growth_v19 as g;
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let r = risk_limits(&env);
    assert_eq!(r.matcher_ext_mode, g::GROWTH_PIN_MATCHER_EXT_MODE);
    assert_eq!(r.max_requested_fee_bps, g::GROWTH_PIN_MAX_REQUESTED_FEE_BPS);
    assert_eq!(r.lp_floor_atoms, g::GROWTH_PIN_LP_FLOOR_ATOMS);
    assert_eq!((r.side_oi_cap_q, r.lp_exposure_k_bps, r.exec_band_bps), (0, 0, 0));
    let d = env.svm.get_account(&lp.ctx).unwrap().data;
    assert_eq!(d[CTX_KIND_OFF], g::GROWTH_PIN_MATCHER_KIND, "kind-2 adaptive matcher");
    // NEGATIVE CONTROL: legacy bind
    let mut legacy = Env::new(Params::default());
    let llp = legacy.bind(2_000);
    assert_eq!(risk_limits(&legacy), state::AssetRiskLimitsV17::default());
    assert_eq!(legacy.svm.get_account(&llp.ctx).unwrap().data[CTX_KIND_OFF], 1, "kind-1 vAMM");
    // UA preset before the bind is kept
    let mut pre = Env::new(growth_params());
    let a = pre.admin.pubkey();
    pre.set_program_data_authority(&a);
    pre.set_fee_channel(1, 7).expect("UA tag 93 before bind");
    pre.bind(2_000);
    let r = risk_limits(&pre);
    assert_eq!((r.matcher_ext_mode, r.max_requested_fee_bps, r.lp_floor_atoms), (1, 7, percolator_prog::growth_v19::GROWTH_PIN_LP_FLOOR_ATOMS), "L-4: preset fields kept, zero fields defaulted");
}

/// G4 LP floor: a growth vault LP halts risk-increasing fills while its equity is at or below
/// the $1 floor (legacy: only at 0).
#[test]
fn growth_v19_lp_floor_default_halts_before_zero() {
    let run = |p: Params, fee: u64| {
        let mut env = Env::new(p);
        let lp = env.bind(2_000);
        let admin = env.admin.insecure_clone();
        env.junior_deposit_as(&admin, lp.portfolio, 500_000).expect("junior $0.50");
        let t = env.new_trader(10_000_000);
        env.trade_signing_fee(&t, &lp, 100_000, fee)
    };
    let r = run(growth_params(), 100);
    assert!(r.as_ref().err().is_some_and(|e| e.contains("Custom(69)")), "growth: LpFloorHalt, got {r:?}");
    let l = run(Params::default(), 0);
    assert!(l.is_ok(), "legacy: an LP with $0.50 still quotes: {l:?}");
}

/// G4 fee channel: on a growth market the matcher's requested fee needs the taker's consent
/// (signed fee_bps covering it); on a legacy market (channel off) a zero signed fee fills.
#[test]
fn growth_v19_fee_channel_on_requires_taker_consent() {
    let run = |p: Params, fee: u64| {
        let mut env = Env::new(p);
        let lp = env.bind(2_000);
        let admin = env.admin.insecure_clone();
        env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior");
        let t = env.new_trader(100_000_000);
        env.trade_signing_fee(&t, &lp, 10 * 1_000_000, fee)
    };
    let r = run(growth_params(), 0);
    assert!(r.as_ref().err().is_some_and(|e| e.contains("Custom(9)")), "requested fee refused without consent: {r:?}");
    assert!(run(growth_params(), 100).is_ok(), "with consent");
    assert!(run(Params::default(), 0).is_ok(), "legacy: channel off");
}

/// c_launch is recorded ONCE, at the first junior deposit into a growth asset.
#[test]
fn growth_v19_c_launch_recorded_once() {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    assert_eq!(growth_rec(&env).unwrap().c_launch_atoms, 0);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    assert_eq!(growth_rec(&env).unwrap().c_launch_atoms, 1_000_000_000);
    env.junior_deposit_as(&admin, lp.portfolio, 500_000_000).expect("junior +$500");
    assert_eq!(growth_rec(&env).unwrap().c_launch_atoms, 1_000_000_000, "never overwritten");
    // NEGATIVE CONTROL: no growth record on a legacy market
    let mut legacy = Env::new(Params::default());
    let llp = legacy.bind(2_000);
    let la = legacy.admin.insecure_clone();
    legacy.junior_deposit_as(&la, llp.portfolio, 1_000_000_000).expect("junior");
    assert!(state::read_asset_growth(&legacy.svm.get_account(&legacy.market).unwrap().data, 0, 1_000).unwrap().is_none());
}

/// M-1 on a BOUND growth market with the canonical kind-2 matcher: a thin-side close at
/// capacity, and in matcher CLOSED mode (the wrapper sends inventory cap 0 while the market's
/// h-lock reads latched), fills in full. STATE POKE: `bankruptcy_hlock_active` (a real latched
/// h-lock needs a bankruptcy with an unconverted winner; the engine clears this stale flag only
/// later, inside the trade, so the pre-matcher read still sends the closed cap).
#[test]
fn growth_v19_m1_bound_close_at_capacity_and_in_closed_mode() {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    let whale = env.new_trader(100_000_000_000);
    let thin = env.new_trader(100_000_000);
    env.trade_signing_fee(&whale, &lp, 900 * 1_000_000, GROWTH_FEE).expect("crowd 900");
    env.trade_signing_fee(&thin, &lp, -(100 * 1_000_000), GROWTH_FEE).expect("thin short 100");
    env.trade_signing_fee(&whale, &lp, 5_000 * 1_000_000, GROWTH_FEE).expect("crowd to capacity");
    // close at capacity
    env.trade_signing_fee(&thin, &lp, 40 * 1_000_000, GROWTH_FEE).expect("partial close at capacity");
    assert_eq!(env.position(thin.portfolio), -(60 * 1_000_000), "filled in full");
    // closed mode
    let mut m = env.svm.get_account(&env.market).unwrap();
    let (cfg, mut group) = state::read_market(&m.data).unwrap();
    group.bankruptcy_hlock_active = true;
    state::write_market(&mut m.data, &cfg, &group).unwrap();
    env.svm.set_account(env.market, m).unwrap();
    env.trade_signing_fee(&thin, &lp, 60 * 1_000_000, GROWTH_FEE).expect("close in closed mode");
    assert_eq!(env.position(thin.portfolio), 0, "never trapped");
}

/// M-1 with the P2 extension switched OFF afterwards by the upgrade authority (tag 93, mode 0):
/// the v1 block then carries no flags, so the wrapper must mark the v3 block TAKER_REDUCING
/// itself or the matcher's closed mode would zero-fill the close.
#[test]
fn growth_v19_m1_bound_close_in_closed_mode_with_ext_mode_0() {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    let whale = env.new_trader(100_000_000_000);
    let thin = env.new_trader(100_000_000);
    env.trade_signing_fee(&whale, &lp, 900 * 1_000_000, GROWTH_FEE).expect("crowd 900");
    env.trade_signing_fee(&thin, &lp, -(100 * 1_000_000), GROWTH_FEE).expect("thin short 100");
    env.set_fee_channel(0, 0).expect("UA: ext mode 0, fee channel off");
    let mut m = env.svm.get_account(&env.market).unwrap();
    let (cfg, mut group) = state::read_market(&m.data).unwrap();
    group.bankruptcy_hlock_active = true;
    state::write_market(&mut m.data, &cfg, &group).unwrap();
    env.svm.set_account(env.market, m).unwrap();
    env.trade_signing_fee(&thin, &lp, 100 * 1_000_000, 0).expect("close in closed mode, mode 0");
    assert_eq!(env.position(thin.portfolio), 0, "never trapped");
}

/// N-1 on a REAL bound growth market (tag-94 bind, registry-owned vault LP, kind-2 canonical
/// matcher, junior-funded capital): the reviewer's thin-open / crowd-refill / thin-close cycle
/// (`sec2_thin_open_crowd_fill_thin_close_cycles_past_ncap`). Before the fix 4 cycles took the
/// LP to 4 x N_cap; now the refill finds no room (capacity = the crowd's users OI), the thin
/// close still fills in full, and |LP| <= N_cap(C_m) after every fill.
#[test]
fn growth_v19_n1_bound_thin_cycles_cannot_push_lp_past_ncap() {
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    let n_cap = |env: &Env| -> u128 {
        let p = env.portfolio(lp.portfolio);
        let c_m = percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap();
        percolator_prog::growth_v19::n_cap_q(c_m, 10_000, PRICE, POS as u128).unwrap()
    };
    let t = env.new_trader(5_000_000_000);
    let mut crowd: Vec<Pubkey> = Vec::new();
    for cycle in 0..4 {
        let c = env.new_trader(100_000_000_000);
        let users_before: u128 = crowd.iter().map(|p| env.position(*p).max(0).unsigned_abs()).sum();
        let room = n_cap(&env).saturating_sub(users_before);
        env.trade_signing_fee(&c, &lp, 5_000 * 1_000_000, GROWTH_FEE).expect("crowd request (clipped)");
        if cycle > 0 {
            // C_m grows with the fee channel (the N-2 utilisation fee the thin open paid at
            // u = 1 included), so the fee-funded room opens; never the N_cap a thin open used
            // to free.
            let filled = env.position(c.portfolio).unsigned_abs();
            assert!(
                filled <= room && filled < 200 * 1_000_000,
                "cycle {cycle}: the thin side frees no crowd room (filled {filled}, fee room {room})"
            );
        }
        crowd.push(c.portfolio);
        let close = -env.position(t.portfolio);
        if close != 0 {
            env.trade_signing_fee(&t, &lp, close, GROWTH_FEE).expect("thin close (exempt)");
            assert_eq!(env.position(t.portfolio), 0, "M-1: the close fills in full");
        }
        assert!(env.position(lp.portfolio).unsigned_abs() <= n_cap(&env), "cycle {cycle}: |LP| <= N_cap");
        let lp_now = env.position(lp.portfolio);
        if lp_now != 0 {
            env.trade_signing_fee(&t, &lp, lp_now, GROWTH_FEE).expect("thin open");
        }
        let users_long: u128 = crowd.iter().map(|p| env.position(*p).max(0).unsigned_abs()).sum();
        assert!(users_long <= n_cap(&env), "crowd users OI <= N_cap");
    }
    let close = -env.position(t.portfolio);
    env.trade_signing_fee(&t, &lp, close, GROWTH_FEE).expect("final thin close");
    assert_eq!(env.position(t.portfolio), 0);
    let lp_abs = env.position(lp.portfolio).unsigned_abs();
    eprintln!("N-1 bound: final |LP| {lp_abs} vs N_cap {}", n_cap(&env));
    assert!(lp_abs <= n_cap(&env), "|LP| ends <= N_cap, not 4 x N_cap");
}

// N-2 (security round 3): the reviewer's hedged lock-out, with assertions.
/// N-2 (security round 3, reviewer `sec3_hedged_lockout_of_both_sides`, now asserting): one
/// actor fills BOTH sides' users OI to N_cap delta-neutrally (10 Sybil longs of 100 units, one
/// 1,000-unit short), so fresh users cannot open either side. The lock-out itself is the price
/// of the N-1 invariant; the utilisation fee makes it COST: every open above the 50% kink pays
/// `500 bps * (u - 0.5) / 0.5` of its notional to the vault LP, so building this lock-out pays
/// the LP ~$65 on a $1k C_m (before: only base + matcher fees). Closes never pay it.
/// NEGATIVE CONTROL: mutant `n2-nofee` (utilisation fee 0) fails the cost assertions.
#[test]
fn sec3_hedged_lockout_of_both_sides() {
    use percolator_prog::growth_v19 as gv;
    const FEE: u64 = 10_000; // the taker's signed maximum; the charge is base + requested + util
    let mut env = Env::new(growth_params());
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 1_000_000_000).expect("junior $1k");
    let n = 1_000 * POS;
    let c_m = |env: &Env| -> u128 {
        let p = env.portfolio(lp.portfolio);
        percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap()
    };
    let lp_cap0 = env.portfolio(lp.portfolio).capital;
    // expected utilisation fee, leg by leg, from the pure functions at the pre-fill C_m
    let mut expected_util: u128 = 0;
    let mut users_long: u128 = 0;
    let mut actor_deposits: u128 = 0;
    let mut actors: Vec<Pubkey> = Vec::new();
    for i in 0..10 {
        let n_cap = gv::n_cap_q(c_m(&env), 10_000, PRICE, POS as u128).unwrap();
        let bps = gv::utilisation_fee_bps(users_long + (n / 10) as u128, n_cap, 5_000, 500).unwrap();
        expected_util += (n as u128 / 10) * bps as u128 / 10_000; // notional at $1 = units
        let mut dep: u64 = 10_000_000;
        loop {
            let c = env.new_trader(dep);
            let r = env.trade_signing_fee(&c, &lp, n / 10, FEE);
            if r.is_ok() && env.position(c.portfolio) == n / 10 {
                actor_deposits += dep as u128;
                actors.push(c.portfolio);
                break;
            }
            dep += 5_000_000;
            assert!(dep < 400_000_000, "leg {i}: {r:?}");
        }
        users_long += (n / 10) as u128;
    }
    let n_cap = gv::n_cap_q(c_m(&env), 10_000, PRICE, POS as u128).unwrap();
    let bps = gv::utilisation_fee_bps(n as u128, n_cap, 5_000, 500).unwrap();
    expected_util += n as u128 * bps as u128 / 10_000;
    let mut sdep: u64 = 100_000_000;
    let s = loop {
        let s = env.new_trader(sdep);
        let r = env.trade_signing_fee(&s, &lp, -n, FEE);
        if r.is_ok() && env.position(s.portfolio) == -n {
            break s;
        }
        sdep += 10_000_000;
        assert!(sdep < 2_000_000_000, "short: {r:?}");
    };
    actor_deposits += sdep as u128;
    actors.push(s.portfolio);
    let actor_cap: u128 = actors.iter().map(|k| env.portfolio(*k).capital).sum();
    let actor_fees = actor_deposits - actor_cap;
    let lp_gain = env.portfolio(lp.portfolio).capital - lp_cap0;
    eprintln!(
        "SEC3 lockout: actor locked {actor_deposits}, paid fees {actor_fees}, LP capital +{lp_gain}; expected utilisation fee {expected_util} (u_short {bps} bps)"
    );
    // the lock-out costs real money, and the LP earns it
    assert!(expected_util >= 60_000_000, "the model prices the lock-out at >= $60 ({expected_util})");
    assert!(actor_fees >= expected_util, "actor paid {actor_fees} < utilisation fee {expected_util}");
    assert!(lp_gain >= expected_util, "LP earned {lp_gain} < utilisation fee {expected_util}");
    // fresh users still cannot open (the lock-out exists; it is now paid for)
    // ...except for the room the lock-out's OWN fees added to C_m (they fund the LP)
    let room = gv::n_cap_q(c_m(&env), 10_000, PRICE, POS as u128).unwrap() - n as u128;
    let u = env.new_trader(1_000_000_000);
    let r1 = env.trade_signing_fee(&u, &lp, 100 * POS, FEE);
    eprintln!("SEC3 fresh long 100 -> filled {} (fee-funded room {room})", env.position(u.portfolio));
    assert!(r1.is_ok() && env.position(u.portfolio) as u128 <= room, "crowd full: {r1:?}");
    // a close never pays the utilisation fee: base + matcher request only (<= 2% here)
    let cap_before = env.portfolio(s.portfolio).capital;
    env.trade_signing_fee(&s, &lp, n, FEE).expect("actor short closes");
    assert_eq!(env.position(s.portfolio), 0);
    let close_fee = cap_before.saturating_sub(env.portfolio(s.portfolio).capital);
    eprintln!("SEC3 close of 1,000 units paid {close_fee}");
    assert!(close_fee <= 20_000_000, "a close pays no utilisation fee ({close_fee})");
}

// ═══════════════════════════════════════════════════════════════════════════════════════
// Phase 2b (2026-10-05): Earn as the counterparty — tag 103 VaultLpAllocate + VaultLpExtV19
// + A4 lock, G6 fee waterfall (junior cushion), skew-funding defaults.
// Spec: ~/percolator-ops/ledger/devnet-v2-growth-plan-2026-10-04.md §2.3 / §2.5 / §2.4.
// All flows are real instructions; the one STATE POKE-free exception is none.
// ═══════════════════════════════════════════════════════════════════════════════════════

const U: u64 = 1_000_000; // 1 USDC / 1 unit at $1
const UQ: i128 = 1_000_000; // 1 unit in Q (POS_SCALE = 1e6)

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

/// THE HARD PROPERTY, written first (plan §2.3 "prove first"): allocate, trade, win, convert,
/// recall, redeem. A trader wins against a vault LP that is carrying allocated senior capital;
/// the winner converts and withdraws and is paid IN FULL; the loss is the junior's (first
/// loss); seniors and the junior then exit and every token is accounted for.
#[test]
fn p2b_round_trip_allocate_trade_win_convert_recall_redeem() {
    let (mut env, lp, d) = p2b_world(Params::default(), 10_000, 2_000);
    let c0 = env.vlp().senior_claim_atoms;
    assert_eq!(c0, 10_000 * U as u128, "C seeded at NAV");
    let (nav0, lpv0, _) = env.p2b_v(lp.portfolio);
    let vault0 = env.market_state().1.vault;
    let spl0 = env.tok(env.vault_token);

    // ── allocate: min(50% C, pots - 30% C) = 5,000.
    env.allocate(lp.portfolio, u128::MAX).expect("103 allocate");
    let (nav1, lpv1, c1) = env.p2b_v(lp.portfolio);
    assert_eq!(env.allocated(), 5_000 * U as u128, "alpha-bound allocation");
    assert_eq!(c1, c0, "C unchanged by the move");
    assert_eq!(nav1, nav0 - 5_000 * U as u128, "pots -5,000");
    assert_eq!(lpv1, lpv0 + 5_000 * U as u128, "vault LP capital +5,000");
    assert_eq!(nav1 + lpv1, nav0 + lpv0, "V unchanged");
    assert_eq!(env.market_state().1.vault, vault0, "header.vault nets to zero");
    assert_eq!(env.tok(env.vault_token), spl0, "no SPL moved");
    assert!(nav1 * 10_000 >= c1 * 3_000, "pots >= 30% buffer");
    env.assert_conserved("after allocate");

    // ── trade: 5,000 units long vs the vault LP. Without the allocation the vault LP's 1x
    //    exposure cap (P3-H2, equity 2,000) would refuse it (control below).
    let t = env.new_trader(1_000 * U);
    env.trade(&t, &lp, 5_000 * UQ).expect("open 5,000 units against the allocated LP");
    assert_eq!(env.position(lp.portfolio), -5_000 * UQ);

    // ── win: +10% -> trader +500, vault LP -500 (junior's first loss).
    env.move_price(1_100_000, &[t.portfolio, lp.portfolio]);
    env.trade(&t, &lp, -5_000 * UQ).expect("trader closes");
    assert_eq!(env.position(lp.portfolio), 0, "vault LP flat");
    env.hold(12, &[t.portfolio, lp.portfolio]);

    // ── convert + withdraw: paid in full.
    env.trader_convert(&t).expect("winner converts");
    let paid = env.trader_withdraw_all(&t).expect("winner withdraws");
    assert_eq!(paid, 1_500 * U, "winner paid IN FULL (1,000 capital + 500 gain)");

    // ── recall the allocation (LP flat), then the senior redeems everything.
    let (_, lpv2, c2) = env.p2b_v(lp.portfolio);
    assert_eq!(c2, c0, "seniors untouched: the junior took the loss");
    assert_eq!(lpv2, 6_500 * U as u128, "LP = 1,500 junior + 5,000 allocated");
    env.recall_ext(lp.portfolio, 5_000 * U as u128, DOMAIN).expect("98 recall (inverse of 103)");
    assert_eq!(env.allocated(), 0, "recall de-allocates");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let sp = env.earn_execute(&d, Some(lp.portfolio)).expect("senior redeems all");
    let dead = 1_000u128; // LP_VAULT_MINIMUM_LIQUIDITY dead shares (never minted)
    assert_eq!(sp as u128, c0 - dead, "senior paid C in full (less dead shares)");

    // ── the junior leaves with what is left (2,000 - 500), keeping the floor on the dead
    //    shares' residual claim (ceil(20% x 1,000) = 200 atoms).
    let admin = env.admin.insecure_clone();
    env.junior_withdraw_ext(&admin, lp.portfolio, 1_500 * U - 200).expect("junior exits");
    env.assert_conserved("end");
    let left = env.tok(env.vault_token);
    assert!(left as u128 <= dead + 200 + 2, "only dead-share / floor dust left: {left}");
    eprintln!("round trip: winner {paid}, senior {sp}, junior 1,500e6, dust {left}");
}

/// Negative control for the trade above: the identical 5,000-unit open WITHOUT allocation is
/// refused by the vault LP's 1x exposure cap. Allocation is what made the capacity.
#[test]
fn p2b_control_same_trade_refused_without_allocation() {
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
    let t = env.new_trader(1_000 * U);
    let r = env.trade(&t, &lp, 5_000 * UQ);
    err_has(&r, PercolatorError::VaultLpExposureCapExceeded);
    // ... and the same open after a 103 crank is admitted.
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    env.trade(&t, &lp, 5_000 * UQ).expect("admitted once Earn is allocated");
}

/// Refusals (Custom 100) and their controls: no room left, an impaired vault, zero amount.
#[test]
fn p2b_allocate_refusals_and_controls() {
    // no room: alpha is spent after the first crank
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
    env.allocate(lp.portfolio, u128::MAX).expect("first");
    err_has(&env.allocate(lp.portfolio, 1), PercolatorError::VaultLpAllocateRefused);
    err_has(&env.allocate(lp.portfolio, 0), PercolatorError::VaultLpAllocateRefused);

    // impaired: the LP's loss exceeds the junior (V < C) -> refused; control without the move.
    for impair in [false, true] {
        let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 500);
        env.allocate(lp.portfolio, 2_000 * U as u128).expect("partial allocation");
        let t = env.new_trader(2_000 * U);
        env.trade(&t, &lp, 2_000 * UQ).expect("open");
        if impair {
            // +40%: LP -800 > junior 500 => V = C - 300.
            env.move_price(1_400_000, &[t.portfolio, lp.portfolio]);
        } else {
            env.hold(1, &[t.portfolio, lp.portfolio]);
        }
        let _ = env.crank(lp.portfolio);
        let r = env.allocate(lp.portfolio, 1_000 * U as u128);
        if impair {
            let (nav, lpv, c) = env.p2b_v(lp.portfolio);
            assert!(nav + lpv < c, "impaired: V {} < C {c}", nav + lpv);
            err_has(&r, PercolatorError::VaultLpAllocateRefused);
        } else {
            r.expect("control: an unimpaired vault allocates");
        }
    }
}

/// The redemption buffer: after allocation a senior holding 60% of the shares cannot be paid
/// from the pots (50% of C) -> 88; recall (LP flat) and the same redemption pays in full.
#[test]
fn p2b_buffer_then_recall_serves_a_large_redemption() {
    let mut env = Env::new(Params::default());
    let a = env.new_depositor();
    let b = env.new_depositor();
    env.earn_deposit(&a, 6_000 * U, None).expect("a");
    env.earn_deposit(&b, 4_000 * U, None).expect("b");
    let lp = env.bind(2_000);
    let admin = env.admin.insecure_clone();
    env.junior_deposit_as(&admin, lp.portfolio, 2_000 * U).expect("junior");
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    let sa = env.lp_shares(&a);
    env.earn_request(&a, sa);
    err_has(&env.earn_execute(&a, Some(lp.portfolio)), PercolatorError::VaultLpRedeemNeedsRecall);
    env.recall_ext(lp.portfolio, env.allocated(), DOMAIN).expect("recall");
    let paid = env.earn_execute(&a, Some(lp.portfolio)).expect("redeem after recall");
    assert_eq!(paid, 6_000 * U - 1_000, "paid in full (less the 1,000 dead shares)");
    env.assert_conserved("buffer");
}

/// A4: allocated capital is locked while the vault LP holds inventory (recall and junior
/// withdraw refused by the engine's flat-only withdraw); once flat both work.
#[test]
fn p2b_allocated_capital_locked_while_lp_holds_inventory() {
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    let t = env.new_trader(1_000 * U);
    env.trade(&t, &lp, 1_000 * UQ).expect("open");
    let r = env.recall_ext(lp.portfolio, 1_000 * U as u128, DOMAIN);
    assert!(r.is_err(), "recall with inventory must fail: {r:?}");
    let admin = env.admin.insecure_clone();
    assert!(env.junior_withdraw_ext(&admin, lp.portfolio, U).is_err(), "97 with inventory");
    assert_eq!(env.allocated(), 5_000 * U as u128, "still allocated");
    env.trade(&t, &lp, -1_000 * UQ).expect("close");
    env.recall_ext(lp.portfolio, 1_000 * U as u128, DOMAIN).expect("flat: recall works");
    assert_eq!(env.allocated(), 4_000 * U as u128);
}

/// Fail closed: once the ext exists, 98 and 97 without it are refused (the counter cannot be
/// skipped); with it they run. Tag 103 is permissionless (random crankers above).
#[test]
fn p2b_ext_required_once_created() {
    // junior 3,000 over a 2,000 floor (20% of C): 97 has room once the allocation is recalled.
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 3_000);
    env.allocate(lp.portfolio, 1_000 * U as u128).expect("103 creates the ext");
    assert!(env.registry_state()._reserved[1] == 1, "registry ext flag");
    let r = env.recall(lp.portfolio, 500 * U as u128, DOMAIN);
    assert!(r.is_err(), "98 without the ext tail must fail closed: {r:?}");
    env.recall_ext(lp.portfolio, 500 * U as u128, DOMAIN).expect("98 with the ext");
    assert_eq!(env.allocated(), 500 * U as u128);
    env.recall_ext(lp.portfolio, 500 * U as u128, DOMAIN).expect("98 rest");
    assert_eq!(env.allocated(), 0);
    // 97 is now admissible on value (backing covers C again); only the missing ext refuses it.
    let admin = env.admin.insecure_clone();
    let r = env.junior_withdraw_as(&admin, lp.portfolio, U);
    assert!(r.is_err(), "97 without the ext tail must fail closed: {r:?}");
    env.junior_withdraw_ext(&admin, lp.portfolio, U).expect("control: 97 with the ext");
}

/// UA-only dials: a non-authority signer is refused; out-of-range dials are refused; valid
/// dials are written and bound the next allocation.
#[test]
fn p2b_dials_are_upgrade_authority_gated_and_bounded() {
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    err_has(&env.set_p2b_dials(&stranger, [2_000, 3_000, 0, 0]), PercolatorError::Unauthorized);
    let admin = env.admin.insecure_clone();
    err_has(&env.set_p2b_dials(&admin, [5_001, 3_000, 0, 0]), PercolatorError::InvalidInstruction);
    err_has(&env.set_p2b_dials(&admin, [2_000, 2_999, 0, 0]), PercolatorError::InvalidInstruction);
    err_has(&env.set_p2b_dials(&admin, [2_000, 3_000, 1_000, 0]), PercolatorError::InvalidInstruction);
    env.set_p2b_dials(&admin, [2_000, 3_000, 0, 0]).expect("alpha 20%");
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    assert_eq!(env.allocated(), 2_000 * U as u128, "alpha 20% of C");
}

/// growth: N_cap = lambda * C_m / P grows with Earn through the allocation. NEGATIVE CONTROL:
/// the same crowd order without the allocation is clipped at the junior-only capacity.
#[test]
fn p2b_growth_ncap_grows_with_earn() {
    let fill = |alloc: bool| -> (u128, i128) {
        let (mut env, lp, _d) = p2b_world(growth_params(), 10_000, 1_000);
        if alloc {
            env.allocate(lp.portfolio, u128::MAX).expect("103");
        }
        let cap = env.n_cap(lp.portfolio);
        let whale = env.new_trader(100_000 * U);
        env.trade_signing_fee(&whale, &lp, 4_000 * UQ, GROWTH_FEE).expect("crowd order");
        (cap, env.position(whale.portfolio))
    };
    let (cap_off, pos_off) = fill(false);
    let (cap_on, pos_on) = fill(true);
    assert_eq!(cap_off, 1_000 * POS as u128, "junior-only N_cap");
    assert_eq!(cap_on, 6_000 * POS as u128, "junior + 50% of Earn");
    assert_eq!(pos_off, 1_000 * UQ, "control: clipped at the junior-only capacity");
    assert_eq!(pos_on, 4_000 * UQ, "Earn-backed capacity fills the whole order");
}

/// Skew-funding defaults (plan §2.4): a bind on a market with a funding cap pins
/// slope = max(1, cap/2), max = cap; a market without funding keeps skew off.
#[test]
fn p2b_tag94_pins_skew_defaults_inside_the_funding_cap() {
    let mut env = Env::new(Params { funding: 200, ..Params::default() });
    env.bind(2_000);
    let r = env.asset_rec();
    assert_eq!((r.skew_slope_e9, r.skew_max_e9), (100, 200));
    let mut legacy = Env::new(Params::default());
    legacy.bind(2_000);
    let r = legacy.asset_rec();
    assert_eq!((r.skew_slope_e9, r.skew_max_e9), (0, 0), "no funding => skew off");
}

/// G6: with the cushion on, part of the harvested LP fee leg goes to the junior (C is credited
/// less) until the junior is at target; creator fees do not vest below target; the accrued
/// cushion is LOCKED against 97: the junior's maximum withdrawal equals the cushion-off world's
/// (it gained exactly the cushion and may take none of it). NEGATIVE CONTROL: cushion off =>
/// the whole leg goes to C and no vesting lock.
#[test]
fn p2b_g6_fee_waterfall_cushion() {
    // Greedy halving search for the largest total the junior can withdraw (failed attempts do
    // not mutate state).
    fn max_junior_out(env: &mut Env, lp: Pubkey) -> u128 {
        let admin = env.admin.insecure_clone();
        let (mut amt, mut total) = (20_000 * U, 0u128);
        while amt > 0 {
            if env.junior_withdraw_ext(&admin, lp, amt).is_ok() {
                total += amt as u128;
            } else {
                amt /= 2;
            }
        }
        total
    }
    let run = |cushion: bool| -> (u128, u128, u8, u128, Result<(), String>) {
        let p = Params { fee_bps: 100, ..Params::default() };
        let mut env = Env::new(p);
        let d = env.new_depositor();
        env.earn_deposit(&d, 10_000 * U, None).expect("senior");
        let lp = env.bind(1_000); // floor 10% of C
        let admin = env.admin.insecure_clone();
        env.junior_deposit_as(&admin, lp.portfolio, 3_000 * U).expect("junior 3,000");
        // target 40% of C (4,000) > junior 3,000: the cushion accrues.
        let dials = if cushion { [5_000, 3_000, 4_000, 5_000] } else { [5_000, 3_000, 0, 0] };
        env.set_p2b_dials(&admin, dials).expect("dials");
        let t = env.new_trader(5_000 * U);
        for _ in 0..4 {
            env.trade(&t, &lp, 1_000 * UQ).expect("open");
            env.trade(&t, &lp, -1_000 * UQ).expect("close");
        }
        let c_before = env.vlp().senior_claim_atoms;
        let _ = env.crank(lp.portfolio); // 22 (no progress) when already current
        env.crank_fees_ext(lp.portfolio).expect("78");
        let credited = env.vlp().senior_claim_atoms - c_before;
        let k = env.ext().unwrap().cushion_accrued_atoms;
        let vest = env.asset_rec().p2b_flags;
        // Tag 90: the creator (asset 0's asset_admin = admin) claims 1 atom of its fee leg.
        let epoch = state::read_asset_control_sequences(&env.svm.get_account(&env.market).unwrap().data, 0)
            .unwrap()
            .authority_epoch;
        let dst = env.token_account(env.mint, admin.pubkey(), 0);
        let (m, vt, va) = (env.market, env.vault_token, env.vault_authority);
        let r90 = env.send(
            ProgInstruction::WithdrawCreatorFee { amount: 1, asset_index: 0, authority_epoch: epoch },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(m, false),
                AccountMeta::new(dst, false),
                AccountMeta::new(vt, false),
                AccountMeta::new_readonly(va, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            &[&admin],
        );
        if r90.is_ok() {
            env.paid_out += 1;
        }
        let out = max_junior_out(&mut env, lp.portfolio);
        env.assert_conserved("g6");
        (credited, k, vest, out, r90)
    };
    let (c_off, k_off, vest_off, out_off, r90_off) = run(false);
    let (c_on, k_on, vest_on, out_on, r90_on) = run(true);
    r90_off.expect("control: creator fee claim works with the cushion off");
    err_has(&r90_on, PercolatorError::VaultLpCreatorFeeVesting);
    eprintln!("G6: C credit off {c_off} on {c_on}; cushion {k_on}; junior max out off {out_off} on {out_on}");
    assert!(c_off > 0, "fees harvested (vacuity)");
    assert_eq!(k_off, 0, "control: no cushion");
    assert_eq!(vest_off & 1, 0, "control: creator fees vested");
    assert!(k_on > 0 && k_on <= c_off / 2 + 1, "cushion took at most its 50% share: {k_on} of {c_off}");
    assert_eq!(c_on + k_on, c_off, "senior + cushion == the whole leg");
    assert_eq!(vest_on & 1, 1, "creator fees not vested below target");
    // With the lock the junior gains nothing withdrawable from the cushion; only the floor
    // (10% of the smaller C) loosens by k/10. Without the lock it would gain the whole k.
    assert!(
        out_on <= out_off + k_on / 10 + 2,
        "the accrued cushion is locked: junior max out {out_on} with cushion vs {out_off} without (k {k_on})"
    );
    assert!(out_on + 2 >= out_off, "the lock must not trap the junior's own capital: {out_on} vs {out_off}");
}

/// R-2 on an ALLOCATED vault (security requirement: "the R-2 PoC must cover an allocated vault").
/// The R-2 round trip (a zero-sum pair against the vault LP; E deposits after the pair's first
/// leg, redeems after the second) on a bound vault that carries 5,000 of allocated senior
/// capital. Property: E takes out no more than it put in, and the incumbent senior is whole.
/// (Bound pricing is `min(V, C)` with V = pots + harvestable + LP value, so the ledger's I-2
/// attribution never enters it; this pins that allocation does not reopen it.)
#[test]
fn p2b_r2_round_trip_on_an_allocated_vault_cannot_extract() {
    let (mut env, lp, h) = p2b_world(Params::default(), 10_000, 2_000);
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    let a1 = env.new_trader(2_000 * U);
    let a2 = env.new_trader(2_000 * U);
    let all = |a1: &Trader, a2: &Trader, lp: &Lp| [a1.portfolio, a2.portfolio, lp.portfolio];
    // 1. pair open, +18%, both close, A1 converts.
    env.trade(&a1, &lp, 1_000 * UQ).expect("A1 long");
    env.trade(&a2, &lp, -1_000 * UQ).expect("A2 short");
    env.move_price(1_180_000, &all(&a1, &a2, &lp));
    env.trade(&a1, &lp, -1_000 * UQ).expect("A1 close");
    env.trade(&a2, &lp, 1_000 * UQ).expect("A2 close");
    env.hold(12, &all(&a1, &a2, &lp));
    env.trader_convert(&a1).expect("A1 convert #1");
    // 2. E deposits.
    let e = env.new_depositor();
    env.earn_deposit(&e, 1_800 * U, Some(lp.portfolio)).expect("E 75 (bound)");
    // 3. pair again, +15.25%.
    env.trade(&a1, &lp, 1_000 * UQ).expect("A1 long #2");
    env.trade(&a2, &lp, -1_000 * UQ).expect("A2 short #2");
    env.move_price(1_360_000, &all(&a1, &a2, &lp));
    env.trade(&a1, &lp, -1_000 * UQ).expect("A1 close #2");
    env.trade(&a2, &lp, 1_000 * UQ).expect("A2 close #2");
    env.hold(12, &all(&a1, &a2, &lp));
    // 4. E redeems (recalling the allocation first if the pot is short; LP is flat).
    let es = env.lp_shares(&e);
    env.earn_request(&e, es);
    let e_paid = match env.earn_execute(&e, Some(lp.portfolio)) {
        Ok(p) => p,
        Err(_) => {
            let a = env.allocated();
            env.recall_ext(lp.portfolio, a, DOMAIN).expect("recall");
            env.earn_execute(&e, Some(lp.portfolio)).expect("E 77 after recall")
        }
    };
    // 5. A1 converts the second gain; the incumbent redeems.
    env.hold(2, &all(&a1, &a2, &lp));
    env.trader_convert(&a1).expect("A1 convert #2");
    let a = env.allocated();
    if a > 0 {
        env.recall_ext(lp.portfolio, a, DOMAIN).expect("recall rest");
    }
    let hs = env.lp_shares(&h);
    env.earn_request(&h, hs);
    let h_paid = env.earn_execute(&h, Some(lp.portfolio)).expect("H 77");
    eprintln!("R-2 allocated: E deposited 1,800e6 paid {e_paid}; H paid {h_paid}");
    assert!(e_paid as u128 <= 1_800 * U as u128 + 1, "E extracted: paid {e_paid} for 1,800e6");
    assert!(h_paid as u128 >= 10_000 * U as u128 - 1_000 - 2, "incumbent not whole: {h_paid}");
    env.assert_conserved("r2 allocated");
}

/// Security review I-2 (P2b lock exits): the Phase 2b codes are explicit and must never move
/// (SDK error maps, app copy). Growth holds 92..=99; Builder D holds 120..=122.
#[test]
fn p2b_error_codes_are_pinned() {
    assert_eq!(PercolatorError::VaultLpAllocateRefused as u32, 100);
    assert_eq!(PercolatorError::VaultLpCapacityLocked as u32, 101);
    assert_eq!(PercolatorError::VaultLpCreatorFeeVesting as u32, 102);
    assert_eq!(PercolatorError::VaultLpSeniorCapitalHalt as u32, 103);
    assert_eq!(PercolatorError::GrowthUtilisationFeeRequiresTradeCpi as u32, 99);
}

/// Q2 (2026-10-05 decision): once the junior is exhausted (V < C_eff) the vault LP is trading
/// allocated SENIOR capital, so its risk-INCREASING fills are halted (Custom 103); reductions and
/// thin-side opens (which shrink |LP|) are always allowed. CONTROL: the identical book without
/// the adverse move admits the same crowd open.
#[test]
fn p2b_q2_senior_capital_halt_after_junior_exhausted() {
    for exhausted in [false, true] {
        let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 500);
        env.allocate(lp.portfolio, u128::MAX).expect("103: 5,000 allocated");
        let t = env.new_trader(3_000 * U);
        env.trade(&t, &lp, 2_000 * UQ).expect("crowd long vs the LP");
        if exhausted {
            // +40%: the LP (short 2,000) loses 800 > junior 500 => V = C - 300.
            env.move_price(1_400_000, &[t.portfolio, lp.portfolio]);
            let (nav, lpv, c) = env.p2b_v(lp.portfolio);
            assert!(nav + lpv < c, "junior exhausted: V {} < C {c}", nav + lpv);
        } else {
            env.hold(1, &[t.portfolio, lp.portfolio]);
        }
        let _ = env.crank(lp.portfolio);
        let crowd = env.new_trader(1_000 * U);
        let r = env.trade(&crowd, &lp, 100 * UQ);
        if !exhausted {
            r.expect("control: the same crowd open is admitted while the junior covers");
            continue;
        }
        err_has(&r, PercolatorError::VaultLpSeniorCapitalHalt);
        // a reduction of the LP's risk is always allowed
        env.trade(&t, &lp, -500 * UQ).expect("crowd partial close (LP reduces)");
        let thin = env.new_trader(1_000 * U);
        env.trade(&thin, &lp, -100 * UQ).expect("thin-side open (LP reduces)");
        env.trade(&t, &lp, -1_500 * UQ).expect("crowd full close");
    }
}

/// Q2: the senior floor lives in `AssetRiskLimitsV17.p2b_senior_floor_code` (wrapper bytes 650..652);
/// tag 93 rewrites the whole risk record and must not clear it.
#[test]
fn p2b_q2_senior_floor_survives_tag93() {
    fn floor(env: &Env) -> u128 {
        let data = env.svm.get_account(&env.market).unwrap().data;
        let r = state::asset_growth_range(&data, 0).unwrap();
        let slot0 = r.start - percolator_prog::constants::ASSET_GROWTH_OFF;
        state::p2b_senior_floor_from_wrapper_bytes(
            &data[slot0..slot0 + percolator_prog::constants::ASSET_ORACLE_WRAPPER_LEN],
        )
        .unwrap()
    }
    let (mut env, lp, _d) = p2b_world(Params::default(), 10_000, 2_000);
    assert_eq!(floor(&env), 0, "no floor before allocation");
    env.allocate(lp.portfolio, u128::MAX).expect("103");
    let f = floor(&env);
    assert!(f >= 5_000 * U as u128 && f <= 5_000 * U as u128 + 5_000 * U as u128 / 512 + 1, "floor ~= allocated: {f}");
    env.set_fee_channel(1, 50).expect("tag 93");
    assert_eq!(floor(&env), f, "tag 93 preserved the floor");
    env.recall_ext(lp.portfolio, env.allocated(), DOMAIN).expect("98");
    assert_eq!(floor(&env), 0, "recall refreshes the floor");
}
