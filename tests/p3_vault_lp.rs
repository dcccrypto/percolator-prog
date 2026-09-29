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
const PRICE: u64 = 1_000_000; // $1.00 e6

fn code(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
}

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing — cargo build-sbf --features devnet");
    p
}

fn matcher_program_path() -> PathBuf {
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
}

impl Default for Params {
    fn default() -> Self {
        Params {
            mm_bps: 1_000,
            im_bps: 1_000,
            move_bps: 500,
            fee_bps: 0,
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
        let mut svm = LiteSVM::new();
        let pid = percolator_prog::id();
        svm.add_program(pid, &std::fs::read(program_path()).unwrap());
        svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).unwrap());
        let matcher = Pubkey::new_unique();
        svm.add_program(matcher, &std::fs::read(matcher_program_path()).unwrap());
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
                data: vec![0u8; state::market_account_len_for_capacity(1).unwrap()],
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
            plen: state::portfolio_account_len_for_market_slots(1).unwrap(),
            slot: 1,
            paid_in: 0,
            paid_out: 0,
        };
        env.svm.warp_to_slot(1);
        let admin = env.admin.insecure_clone();
        env.send(
            ProgInstruction::InitMarket {
                max_portfolio_assets: 1,
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
        let lp = self.new_program_account(self.plen);
        self.send(
            ProgInstruction::InitVaultLp {
                junior_floor_bps: floor_bps,
            },
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(self.ledger, false),
                AccountMeta::new_readonly(self.sibling, false),
            ],
            &[signer],
        )
        .map(|_| lp)
    }

    fn init_vault_lp(&mut self, floor_bps: u16) -> Pubkey {
        let admin = self.admin.insecure_clone();
        self.init_vault_lp_as(&admin, floor_bps).expect("init vault lp")
    }

    fn vault_lp_set_matcher_as(&mut self, signer: &Keypair, lp: Pubkey) -> Result<Lp, String> {
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
                base_spread_bps: 0,
                max_total_bps: 100,
                impact_k_bps: 0,
                liquidity_notional_e6: 0,
                max_fill_abs: u128::MAX,
                max_inventory_abs: u128::MAX,
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

    /// Bound vault: create + bind vault LP + matcher. Returns the LP handle.
    fn bind(&mut self, floor_bps: u16) -> Lp {
        let lp = self.init_vault_lp(floor_bps);
        self.approve_matcher();
        let admin = self.admin.insecure_clone();
        self.vault_lp_set_matcher_as(&admin, lp).expect("vault lp set matcher")
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
        let (a_id, _, a_epoch) = self.identity(t.portfolio);
        let (b_id, b_seq, b_epoch) = self.identity(lp.portfolio);
        let market_id =
            state::read_market_trade_preflight(&self.svm.get_account(&self.market).unwrap().data, 0)
                .unwrap()
                .3;
        let (cfg, _) = self.market_state();
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
                fee_bps: cfg.trade_fee_base_bps,
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
    let got = env.tok(junior_dest) as u128;
    env.paid_out += got;
    println!("P3-H1 settle (covered): junior received {got}, C={} nav={}", env.vlp().senior_claim_atoms, env.backing_nav());
    assert_eq!(got, 20_000_000, "junior receives its full capital");
    assert_eq!(env.backing_nav(), 10_000_000, "senior backing untouched");
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
    let got = env.tok(junior_dest) as u128;
    env.paid_out += got;
    println!("P3-H1 settle (shortfall): junior {got}, nav {}", env.backing_nav());
    assert_eq!(got, 17_000_000, "junior gets the payout minus the 3M senior shortfall");
    assert_eq!(env.backing_nav(), 13_000_000, "backing refilled to exactly C");
    env.assert_conserved("settle resolved, shortfall");
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
    let (junior, trader) = (env.tok(junior_dest), tr);
    env.paid_out += junior as u128;
    let tp = env.portfolio(t.portfolio);
    println!(
        "settle_first={settle_first}: trader after close cap {} pnl {} bitmap_empty {} receipt {:?}",
        tp.capital,
        tp.pnl,
        percolator::active_bitmap_is_empty(tp.active_bitmap),
        tp.resolved_payout_receipt
    );
    let nav = env.backing_nav();
    env.assert_conserved("after both resolved closes");
    // F-4: nobody's signature needed to reach terminal-flat.
    let registry = env.registry;
    env.permissionless_close_portfolio(lp.portfolio, registry).expect("cleanup vault LP");
    let towner = t.kp.pubkey();
    env.permissionless_close_portfolio(t.portfolio, towner).expect("cleanup trader");
    let shares = env.lp_shares(&d);
    env.earn_request(&d, shares);
    let senior = env.earn_execute(&d, Some(lp.portfolio)).expect("resolved redemption");
    env.assert_conserved("after resolved redemption");
    (junior, trader, senior, nav)
}

/// Sentinel settle-order question: tag 101 reads backing at settle time — the outcome must not
/// depend on whether a winning trader's resolved close runs before or after it.
#[test]
fn p3_settle_order_does_not_change_anyones_outcome() {
    let a = settle_order_run(true);
    let b = settle_order_run(false);
    println!("P3 settle-order: settle-first {a:?} | trader-first {b:?}");
    assert_eq!(a, b, "junior / trader / senior / backing must be order-independent");
    assert!(a.1 > 10_000_000, "the trader won ({})", a.1);
    assert_eq!(a.3, 50_000_000, "senior backing untouched by the trader's win");
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
