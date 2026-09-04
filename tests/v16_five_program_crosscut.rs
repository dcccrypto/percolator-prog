// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Phase 3A.0 — 5-program assembled cross-cut SMOKE (load feasibility + token
//! coexistence). See `~/wrapper-engine-deep-audit/phase3a_crosscut_design.md`.
//!
//! This is the FIRST time wrapper + matcher + NFT + stake + Token-2022 are mounted
//! into ONE litesvm-0.1 instance. It ships before the economic spine (3A.1) to
//! de-risk the genuine unknowns:
//!   * Can all five `.so`s co-load? (stake is GREENFIELD — loaded by ZERO wrapper
//!     tests before now; its id-allowlisting under litesvm 0.1 was unverified.)
//!   * Does `with_spl_programs()` under 0.1 mount BOTH classic SPL (`Tokenkeg`) and
//!     Token-2022 (`TokenzQd`) as distinct, runnable programs?
//!   * Does the wrapper vault accept ONLY classic SPL (`verify_token_program`,
//!     `v16_program.rs:12391`)?
//!
//! # Anti-hollow discipline (carried from Phase 2.E)
//! Each test carries a load-bearing EXECUTED guard, not a silent mount check:
//!   * `coload_executable_and_distinct` — mounts all 7 program accounts and proves
//!     each is `executable`; proves classic ≠ Token-2022 (distinct roles).
//!   * `stake_program_executes_under_litesvm_01` — REAL invocation of the stake
//!     `.so`; an empty-data tx must fail with the stake program's OWN
//!     `InvalidInstructionData` (its `StakeInstruction::unpack` `split_first`
//!     reject), proving the sbpf-v0 stake binary actually runs under the VM — NOT
//!     a loader rejection.
//!   * `classic_and_token2022_mints_coexist` — REAL `InitializeMint2` on EACH token
//!     program in the SAME assembled instance; both succeed and the resulting mints
//!     are owned by their respective (distinct) programs.
//!   * `wrapper_vault_gate_requires_classic_token_program` — REAL `CreateLpVault`
//!     (tag 74) reaching `verify_token_program`: Token-2022 → `Custom(13)`
//!     (`InvalidTokenProgram`) at the gate; classic SPL passes the gate and fails
//!     DOWNSTREAM at market-magic parse (a different code), isolating the gate as
//!     the operative token-program discriminator.

mod common;
use common::*;

use litesvm::LiteSVM;
use percolator::{
    PortfolioAccountV16Account, PortfolioLegV16Account, ProvenanceHeaderV16Account, V16PodI128,
    V16PodU16, V16PodU32, V16PodU64, POS_SCALE, V16_ACCOUNT_VERSION, V16_LAYOUT_DISCRIMINATOR,
};
use percolator_prog::{
    constants::{
        HEADER_LEN, KIND_PORTFOLIO, LP_VAULT_MINIMUM_LIQUIDITY, MAGIC, MATCHER_ABI_VERSION,
        NFT_REGISTRY_SEED, VERSION,
    },
    ix::Instruction as ProgInstruction,
    processor::ASSET_ACTION_ACTIVATE,
    // v17: MarketGroupV16 and PortfolioAccountV16 are wrapper-side types in state (not engine).
    state::{self, MarketGroupV16, PortfolioAccountV16},
};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, Mint};

/// `InvalidTokenProgram` — `PercolatorError` ordinal 13, mapped via
/// `From<PercolatorError> for ProgramError => Custom(value as u32)`
/// (`v16_program.rs:189,231-234`).
const INVALID_TOKEN_PROGRAM: u32 = 13;
/// `NotInitialized` — ordinal 3. The post-gate market-magic parse on a zeroed
/// market returns this (verified by diagnostic at 3A.0), proving the classic
/// token program got PAST `verify_token_program`.
const NOT_INITIALIZED: u32 = 3;
/// `EngineLockActive` — ordinal 21. Market-state guard (e.g. flush/topup into a
/// non-Live market; terminal-reclaim preconditions).
const E_LOCK_ACTIVE: u32 = 21;
/// NFT `TransferBlocked` = Custom(24) — the transfer-hook's `transfer_gate_check`
/// rejecting a locked/stale/resolved portfolio (fires before B-3).
const NFT_TRANSFER_BLOCKED: u32 = 24;
/// `NftInvalidMintAuthority` = Custom(45) — B-3 rejects when the passed mint
/// authority != `derive_nft_mint_authority(registry.nft_program_id)`.
const NFT_INVALID_MINT_AUTHORITY: u32 = 45;
/// `LpVaultOiReservationViolated` = Custom(37) — ExecuteRedemption fail-closed when
/// the post-redemption OI coverage falls below the reservation threshold.
const LP_VAULT_OI_RESERVATION_VIOLATED: u32 = 37;

// ── 3A.0-A: all five co-load executable + distinct token roles ──────────────

#[test]
fn x0_smoke_coload_executable_and_distinct() {
    let matcher_id = Pubkey::new_unique();
    let svm = assemble_five_program_svm(matcher_id);

    for (label, id) in [
        ("wrapper@MAINNET", PERCOLATOR_MAINNET),
        ("nft", NFT_PROGRAM_ID),
        ("stake", STAKE_ID),
        ("matcher", matcher_id),
        ("classic-spl-token", spl_token_classic_id()),
        ("token-2022", TOKEN_2022),
        ("ata", ATA_PROGRAM),
    ] {
        let acct = svm
            .get_account(&id)
            .unwrap_or_else(|| panic!("{label} ({id}) program account missing after load"));
        assert!(
            acct.executable,
            "{label} ({id}) must be mounted as an executable program"
        );
    }

    // Distinct roles — the vault uses classic only; Token-2022 is the NFT mint side.
    assert_ne!(
        spl_token_classic_id(),
        TOKEN_2022,
        "classic SPL and Token-2022 must be distinct programs"
    );
}

// ── 3A.0-B: the greenfield stake .so actually executes under litesvm 0.1 ────

#[test]
fn x0_smoke_stake_program_executes_under_litesvm_01() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    // Empty instruction data → `StakeInstruction::unpack` reaches
    // `data.split_first().ok_or(ProgramError::InvalidInstructionData)`
    // (`instruction.rs:211-213`). A program-level `InvalidInstructionData` (NOT a
    // loader rejection) proves the stake sbpf-v0 binary entered and ran.
    let stake_ix = Instruction {
        program_id: STAKE_ID,
        accounts: vec![],
        data: vec![],
    };
    let res = send_ixs(&mut svm, &payer, vec![stake_ix], &[]);
    assert_instruction_error(
        &res,
        InstructionError::InvalidInstructionData,
        "greenfield stake .so executes (empty-data decode reject)",
    );
}

// ── 3A.0-C: classic SPL + Token-2022 mints coexist in one instance ──────────

#[test]
fn x0_smoke_classic_and_token2022_mints_coexist() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let space = Mint::LEN; // 82 — a no-extension mint (identical base layout in both)

    // (1) Real classic-SPL InitializeMint2 via the canonical builder.
    let classic_mint = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let classic_create = system_instruction::create_account(
        &payer.pubkey(),
        &classic_mint.pubkey(),
        lamports,
        space as u64,
        &spl_token_classic_id(),
    );
    let classic_init = spl_token::instruction::initialize_mint2(
        &spl_token_classic_id(),
        &classic_mint.pubkey(),
        &payer.pubkey(),
        None,
        0,
    )
    .unwrap();
    send_ixs(
        &mut svm,
        &payer,
        vec![classic_create, classic_init],
        &[&classic_mint],
    )
    .expect("classic SPL mint initializes in the assembled 5-program instance");

    let classic_acct = svm
        .get_account(&classic_mint.pubkey())
        .expect("classic mint exists");
    assert_eq!(
        classic_acct.owner,
        spl_token_classic_id(),
        "classic mint owned by Tokenkeg"
    );
    let unpacked = Mint::unpack(&classic_acct.data).expect("classic mint unpacks");
    assert!(unpacked.is_initialized, "classic mint is initialized");

    // (2) Real Token-2022 InitializeMint2 (hand-encoded) on a fresh account, in the
    // SAME svm. Wire: tag(1)=20, decimals(1)=0, mint_authority(32), freeze_opt(1)=0.
    let t22_mint = Keypair::new();
    let t22_create = system_instruction::create_account(
        &payer.pubkey(),
        &t22_mint.pubkey(),
        lamports,
        space as u64,
        &TOKEN_2022,
    );
    let mut t22_init_data = Vec::with_capacity(35);
    t22_init_data.push(20u8); // IX_INITIALIZE_MINT2
    t22_init_data.push(0u8); // decimals
    t22_init_data.extend_from_slice(payer.pubkey().as_ref()); // mint authority
    t22_init_data.push(0u8); // freeze authority = None
    let t22_init = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![AccountMeta::new(t22_mint.pubkey(), false)],
        data: t22_init_data,
    };
    send_ixs(&mut svm, &payer, vec![t22_create, t22_init], &[&t22_mint])
        .expect("Token-2022 mint initializes in the assembled 5-program instance");

    let t22_acct = svm
        .get_account(&t22_mint.pubkey())
        .expect("token-2022 mint exists");
    assert_eq!(
        t22_acct.owner, TOKEN_2022,
        "token-2022 mint owned by TokenzQd"
    );
    // Layout-explicit init check (offset 45 = `is_initialized`) — avoids relying on
    // classic unpack semantics for a Token-2022-owned account.
    assert!(
        t22_acct.data.len() >= 46 && t22_acct.data[45] == 1,
        "token-2022 mint is initialized"
    );
}

// ── 3A.0-D: wrapper vault gate requires classic SPL (verify_token_program) ──

/// `CreateLpVault` (tag 74). `handle_create_lp_vault` (`v16_program.rs`)
/// calls `verify_token_program` at :5286 after only account-flag + owner checks,
/// so it is the lightest honest path to the gate.
fn create_lp_vault_ix(
    market: Pubkey,
    registry: Pubkey,
    mint: Pubkey,
    admin: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id: PERCOLATOR_MAINNET,
        accounts: vec![
            AccountMeta::new(admin, true), // 0 admin (signer, writable)
            // FIND-1 fix: market must be writable — CreateLpVault now writes
            // backing_bucket_authority = registry PDA into the asset's oracle profile.
            AccountMeta::new(market, false), // 1 market (owner==MAINNET; writable)
            AccountMeta::new(registry, false), // 2 registry PDA (writable)
            AccountMeta::new(mint, false),   // 3 mint PDA (writable)
            AccountMeta::new_readonly(system_program::ID, false), // 4 system program
            AccountMeta::new_readonly(token_program, false), // 5 token program (under test)
        ],
        data: ProgInstruction::CreateLpVault {
            fee_share_bps: 0,
            redemption_cooldown_slots: 0,
            oi_reservation_threshold_bps: 0,
            domain: 0,
        }
        .encode(),
    }
}

#[test]
fn x0_smoke_wrapper_vault_gate_requires_classic_token_program() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    // Market owned by the wrapper (passes `expect_owner(market, program_id=MAINNET)`)
    // but with zeroed content (so the classic-token positive path fails downstream
    // at the magic parse, not at the gate).
    let market = Pubkey::new_unique();
    let market_len = percolator_prog::state::market_account_len_for_capacity(1).unwrap();
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; market_len],
            owner: PERCOLATOR_MAINNET,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let registry = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    // NEGATIVE — Token-2022 supplied where the vault demands classic SPL.
    let res_t22 = send_ixs(
        &mut svm,
        &payer,
        vec![create_lp_vault_ix(
            market,
            registry,
            mint,
            payer.pubkey(),
            TOKEN_2022,
        )],
        &[],
    );
    assert_custom(
        res_t22,
        INVALID_TOKEN_PROGRAM,
        "wrapper vault rejects Token-2022 as the token program",
    );

    // POSITIVE — classic SPL passes the gate; the tx fails DOWNSTREAM at the
    // zeroed-market parse with `NotInitialized` (Custom 3), NOT `InvalidTokenProgram`
    // — proving classic SPL is accepted and execution proceeded past the gate into
    // market parsing. Two different operative codes at two different stages isolate
    // `verify_token_program` as the token-program discriminator.
    let res_classic = send_ixs(
        &mut svm,
        &payer,
        vec![create_lp_vault_ix(
            market,
            registry,
            mint,
            payer.pubkey(),
            spl_token_classic_id(),
        )],
        &[],
    );
    assert_custom(
        res_classic,
        NOT_INITIALIZED,
        "wrapper vault accepts classic SPL (gate passed → fails downstream at market parse)",
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 3A.1 — Economic spine. The adversarial `Env` (v16_fork_adversarial.rs:148-486)
// re-keyed to `PERCOLATOR_MAINNET` and hosted in the assembled 5-program svm.
//
// THE GOTCHA (design doc §"load order"): `vault_authority` and every other
// wrapper PDA must be derived under MAINNET, not `percolator_prog::id()`. Because
// `init_matcher_context` derives the matcher delegate from `self.program_id`
// (matcher_delegate_key's FIRST arg, v16_cu.rs:1128), re-keying `program_id` here
// makes the test-side delegate match the wrapper's own derivation automatically.
// ════════════════════════════════════════════════════════════════════════════

const CROSSCUT_MAX_ASSETS: u16 = 1;
/// Tradable asset index (proven v16_cu pattern: activate+trade asset 1, domain 2).
const CROSSCUT_ASSET: u16 = 1;
/// LP-vault domain = long side of the tradable asset (`domain = 2 * asset_index`).
const CROSSCUT_DOMAIN: u16 = 2;

// Fields are consumed incrementally across the 3A.1→3A.5 lifecycle build.
#[allow(dead_code)]
struct CrosscutEnv {
    svm: LiteSVM,
    /// = `PERCOLATOR_MAINNET` (NOT `percolator_prog::id()`).
    program_id: Pubkey,
    matcher_program: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    vault_authority: Pubkey,
    portfolio_len: usize,
    // LP-vault PDAs (all derived under MAINNET).
    lp_registry: Pubkey,
    lp_mint: Pubkey,
    lp_escrow: Pubkey,
    lp_ledger: Pubkey,
}

impl CrosscutEnv {
    /// 100% margins, 0 base trade fee — one tradable asset activated.
    fn new() -> Self {
        let matcher_program = Pubkey::new_unique();
        let mut svm = assemble_five_program_svm(matcher_program);
        let program_id = PERCOLATOR_MAINNET;

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        // PDA derived under MAINNET — the error-prone re-key.
        let (vault_authority, _) =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
        let vault = canonical_vault_ata(&vault_authority, &mint);

        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: make_mint_data(),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            vault,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(mint, vault_authority, 0),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        let market_len =
            state::market_account_len_for_capacity(CROSSCUT_MAX_ASSETS as usize).unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; market_len],
                owner: program_id, // MAINNET — passes expect_owner(market, program_id)
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let portfolio_len =
            state::portfolio_account_len_for_market_slots(CROSSCUT_MAX_ASSETS as usize).unwrap();
        // LP-vault PDAs, derived under MAINNET (program_id).
        let (lp_registry, _) = state::derive_lp_vault_registry(&program_id, &market);
        let (lp_mint, _) = state::derive_lp_vault_mint(&program_id, &market);
        let (lp_escrow, _) = state::derive_lp_escrow(&program_id, &market);
        let (lp_ledger, _) = state::derive_lp_backing_ledger(&program_id, &market, CROSSCUT_DOMAIN);
        let mut env = CrosscutEnv {
            svm,
            program_id,
            matcher_program,
            payer,
            admin,
            market,
            mint,
            vault,
            vault_authority,
            portfolio_len,
            lp_registry,
            lp_mint,
            lp_escrow,
            lp_ledger,
        };

        let admin = env.admin.insecure_clone();
        env.try_wrapper(
            ProgInstruction::InitMarket {
                max_portfolio_assets: CROSSCUT_MAX_ASSETS,
                h_min: 0,
                h_max: 10,
                initial_price: 100,
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
                AccountMeta::new(env.market, false),
                AccountMeta::new_readonly(env.mint, false),
            ],
            &[&admin],
        )
        .expect("init market @ MAINNET");

        env.activate_asset(CROSSCUT_ASSET, 1, 100);
        env
    }

    fn activate_asset(&mut self, asset_index: u16, now_slot: u64, initial_price: u64) {
        let admin = self.admin.insecure_clone();
        // Pre-set backing_bucket_authority = LP registry PDA at activation time.
        // FIND-1 fix: CreateLpVault (v16_program.rs handle_create_lp_vault) now
        // writes this authority itself, atomically with vault creation, so this
        // pre-set is no longer load-bearing for DepositToLpVault — it's kept
        // here only because it's a convenient way for this fixture to seed a
        // non-zero starting value and is idempotent with CreateLpVault's write.
        // Harmless to the trade/user-deposit paths, which never touch it.
        self.try_wrapper(
            ProgInstruction::UpdateAssetLifecycle {
                action: ASSET_ACTION_ACTIVATE,
                asset_index,
                now_slot,
                initial_price,
                insurance_authority: admin.pubkey().to_bytes(),
                insurance_operator: admin.pubkey().to_bytes(),
                backing_bucket_authority: self.lp_registry.to_bytes(),
                oracle_authority: admin.pubkey().to_bytes(),
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("activate asset");
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let portfolio = Pubkey::new_unique();
        self.svm
            .set_account(
                portfolio,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; self.portfolio_len],
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_wrapper(
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

    /// Deposit `amount` collateral; returns the (now-drained) source token account.
    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) -> Pubkey {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner.pubkey(), amount as u64),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.try_wrapper(
            ProgInstruction::Deposit { amount },
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[owner],
        )
        .expect("deposit");
        source
    }

    fn try_wrapper(
        &mut self,
        ix: ProgInstruction,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        let wix = Instruction {
            program_id: self.program_id,
            accounts,
            data: ix.encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], signers)
    }

    // ── readers ──
    fn group(&self) -> MarketGroupV16 {
        state::read_market(&self.svm.get_account(&self.market).unwrap().data)
            .unwrap()
            .1
    }
    fn portfolio(&self, p: Pubkey) -> PortfolioAccountV16 {
        state::read_portfolio(&self.svm.get_account(&p).unwrap().data).unwrap()
    }
    fn token_amount(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }
}

/// 3A.1a — the MAINNET re-key holds in the assembled 5-program instance: a real
/// Deposit moves SPL tokens into the MAINNET-derived vault and credits the
/// portfolio + group ledger in lockstep.
#[test]
fn x0_economic_spine_deposit_moves_tokens_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let owner = Keypair::new();
    let portfolio = env.create_portfolio(&owner);

    let source = env.deposit(&owner, portfolio, 1_000);

    // Executed guard: real token movement into the MAINNET-derived vault.
    assert_eq!(env.token_amount(source), 0, "source token account drained");
    assert_eq!(
        env.token_amount(env.vault),
        1_000,
        "vault (authority derived under MAINNET) credited"
    );
    // Ledger lockstep: group.vault ledger == on-chain vault balance.
    assert_eq!(
        env.group().vault,
        1_000,
        "group.vault ledger == on-chain vault"
    );
    assert_eq!(
        env.portfolio(portfolio).capital,
        1_000,
        "portfolio capital credited"
    );
}

// ── Matcher CPI helpers (mirrors v16_cu.rs:101-128,1121-1234, re-keyed MAINNET) ──

const MATCHER_CONTEXT_LEN: usize = 320;

fn matcher_delegate_key(
    program_id: &Pubkey,
    market: &Pubkey,
    maker: &Pubkey,
    // v17: maker_owner added to delegate derivation (auth overhaul, mirrors
    // processor::derive_matcher_delegate seeds).
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

fn encode_matcher_init_passive(max_fill_abs: u128) -> Vec<u8> {
    let mut data = vec![0u8; 66];
    data[0] = 2;
    data[1] = 0;
    data[10..14].copy_from_slice(&100u32.to_le_bytes());
    data[34..50].copy_from_slice(&max_fill_abs.to_le_bytes());
    data
}

fn active_leg_basis(p: &PortfolioAccountV16, asset_index: u16) -> i128 {
    p.legs
        .iter()
        .find(|l| l.active && l.asset_index as usize == asset_index as usize)
        .map(|l| l.basis_pos_q)
        .expect("active leg for asset present after fill")
}

impl CrosscutEnv {
    /// Create + initialize a passive matcher context bound to `maker_account`, then
    /// call SetMatcherConfig on the maker's portfolio so the wrapper's TradeCpi auth
    /// check (matcher_tail_start_or_verify_lp_config) passes.
    ///
    /// v17: requires maker_owner as a keypair for delegate derivation (auth overhaul)
    /// AND to sign SetMatcherConfig.
    fn init_matcher_context(
        &mut self,
        maker_account: Pubkey,
        maker_owner: &Keypair,
    ) -> (Pubkey, Pubkey) {
        let maker_owner_key = maker_owner.pubkey();
        let ctx = Pubkey::new_unique();
        let delegate = matcher_delegate_key(
            &self.program_id,
            &self.market,
            &maker_account,
            &maker_owner_key,
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
        // v17: SetMatcherConfig registers the matcher context in the maker's portfolio.
        // Required before TradeCpi: matcher_tail_start_or_verify_lp_config checks
        // cfg.matcher_program / .matcher_context / .matcher_delegate. It must also run BEFORE
        // InitMatcherCtx, which requires the triple to be registered already.
        send_ixs(
            &mut self.svm,
            &self.payer,
            vec![Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(maker_owner_key, true),
                    AccountMeta::new_readonly(self.market, false),
                    AccountMeta::new(maker_account, false),
                    AccountMeta::new_readonly(self.matcher_program, false),
                    AccountMeta::new(ctx, false),
                    AccountMeta::new_readonly(delegate, false),
                ],
                data: ProgInstruction::SetMatcherConfig { enabled: 1 }.encode(),
            }],
            &[maker_owner],
        )
        .expect("set matcher config on maker portfolio");

        // Bootstrap the context through the WRAPPER's InitMatcherCtx (tag 83). Calling the
        // matcher's process_init directly only works against a matcher missing the BUG-001
        // lp_pda.is_signer check; the deployed matcher requires the delegate PDA to sign, and
        // only the wrapper can do that via invoke_signed.
        send_ixs(
            &mut self.svm,
            &self.payer,
            vec![Instruction {
                program_id: self.program_id,
                accounts: vec![
                    AccountMeta::new(maker_owner_key, true),
                    AccountMeta::new_readonly(self.market, false),
                    AccountMeta::new(maker_account, false),
                    AccountMeta::new(ctx, false),
                    AccountMeta::new_readonly(self.matcher_program, false),
                    AccountMeta::new_readonly(delegate, false),
                ],
                data: ProgInstruction::InitMatcherCtx {
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
                }
                .encode(),
            }],
            &[maker_owner],
        )
        .expect("init matcher context via wrapper InitMatcherCtx");
        (ctx, delegate)
    }

    #[allow(clippy::too_many_arguments)]
    fn trade_cpi(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        // v17: TradeCpi no longer requires signer_b — matcher-delegate auth replaces it.
        _owner_b: &Keypair,
        account_b: Pubkey,
        ctx: Pubkey,
        delegate: Pubkey,
        asset_index: u16,
        size_q: i128,
        fee_bps: u64,
    ) -> Result<(), TransactionError> {
        let wix = Instruction {
            program_id: self.program_id,
            // v17 account layout: [signer_a, market, account_a, account_b,
            //                       matcher_prog(ro), matcher_ctx, matcher_delegate(ro)]
            accounts: vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
                AccountMeta::new_readonly(self.matcher_program, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            data: ProgInstruction::TradeCpi {
                asset_index,
                size_q,
                fee_bps,
                limit_price: 0,
            }
            .encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], &[owner_a])
    }

    fn account_data(&self, key: Pubkey) -> Vec<u8> {
        self.svm.get_account(&key).unwrap().data
    }
}

// ── Trade / accrual / crank helpers (lifted from v16_fork_adversarial.rs) ────

impl CrosscutEnv {
    /// Two-party TradeNoCpi (no matcher) on CROSSCUT_ASSET.
    #[allow(clippy::too_many_arguments)]
    fn try_trade(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> Result<(), TransactionError> {
        let wix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            data: ProgInstruction::TradeNoCpi {
                asset_index: CROSSCUT_ASSET,
                size_q,
                exec_price,
                fee_bps,
            }
            .encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], &[owner_a, owner_b])
    }

    /// Move the asset mark via the engine's zero-sum accrual (the faithful effect
    /// of a real oracle push + crank). Direct state write (adversarial:404-414).
    fn accrue_mark(&mut self, now_slot: u64, effective_price: u64) {
        let mut acct = self.svm.get_account(&self.market).expect("market");
        {
            let (_, mut group) = state::market_view_mut(&mut acct.data).expect("market view");
            group
                .accrue_asset_to_not_atomic(
                    CROSSCUT_ASSET as usize,
                    now_slot,
                    effective_price,
                    0,
                    true,
                )
                .expect("accrue");
        }
        self.svm.set_account(self.market, acct).unwrap();
    }

    /// PermissionlessCrank on CROSSCUT_ASSET (action 0 = refresh, 1 = liquidate).
    /// FIX W3 (upstream #206, pairs with engine E3 / #92): no caller-supplied
    /// close_q -- the engine selects the liquidation size.
    fn crank(
        &mut self,
        portfolio: Pubkey,
        action: u8,
        now_slot: u64,
    ) -> Result<(), TransactionError> {
        let wix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            data: ProgInstruction::PermissionlessCrank {
                action,
                asset_index: CROSSCUT_ASSET,
                now_slot,
                funding_rate_e9: 0,
                recovery_reason: 0,
            }
            .encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], &[])
    }

    fn leg_basis(&self, p: Pubkey) -> i128 {
        self.portfolio(p)
            .legs
            .iter()
            .find(|l| l.active && l.asset_index as usize == CROSSCUT_ASSET as usize)
            .map(|l| l.basis_pos_q)
            .unwrap_or(0)
    }
}

// ── LP-vault helpers (mirrors v16_fork_lp_vault_*.rs, re-keyed MAINNET) ──────

impl CrosscutEnv {
    /// CreateLpVault (tag 74) on `CROSSCUT_DOMAIN`. Creates the registry + LP mint
    /// PDAs and (FIND-1 fix) writes backing_bucket_authority = registry PDA into
    /// the asset's oracle profile directly, atomically with vault creation.
    fn lp_create(&mut self, fee_share_bps: u16, redemption_cooldown_slots: u64) {
        self.lp_create_full(fee_share_bps, redemption_cooldown_slots, 0);
    }

    fn lp_create_full(
        &mut self,
        fee_share_bps: u16,
        redemption_cooldown_slots: u64,
        oi_reservation_threshold_bps: u16,
    ) {
        let admin = self.admin.insecure_clone();
        self.try_wrapper(
            ProgInstruction::CreateLpVault {
                fee_share_bps,
                redemption_cooldown_slots,
                oi_reservation_threshold_bps,
                domain: CROSSCUT_DOMAIN,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                // FIND-1 fix: market must be writable — CreateLpVault now writes
                // backing_bucket_authority = registry PDA into the asset's oracle profile.
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.lp_registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[&admin],
        )
        .expect("create lp vault");
    }

    /// DepositToLpVault (tag 75). Returns `(lp_share_ata, collateral_source)`.
    fn lp_deposit(&mut self, depositor: &Keypair, amount: u128) -> (Pubkey, Pubkey) {
        let lp_ata = Pubkey::new_unique();
        self.svm
            .set_account(
                lp_ata,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.lp_mint, depositor.pubkey(), 0),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, depositor.pubkey(), amount as u64),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let wix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(depositor.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.lp_registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(lp_ata, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new(self.lp_ledger, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
                AccountMeta::new_readonly(system_program::ID, false),
                // Sibling-domain ledger: NAV spans both pots of the vault's asset.
                AccountMeta::new(
                    state::derive_lp_backing_ledger(
                        &self.program_id,
                        &self.market,
                        CROSSCUT_DOMAIN ^ 1,
                    )
                    .0,
                    false,
                ),
            ],
            data: ProgInstruction::DepositToLpVault {
                amount,
                domain: CROSSCUT_DOMAIN,
            }
            .encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], &[depositor]).expect("lp deposit");
        (lp_ata, source)
    }

    /// RequestRedeemLpShares (tag 76). `redemption` = `derive_lp_redemption(...)`.
    fn lp_request_redeem(
        &mut self,
        depositor: &Keypair,
        redemption: Pubkey,
        lp_ata: Pubkey,
        lp_amount: u128,
    ) {
        let wix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(depositor.pubkey(), true),
                AccountMeta::new(self.lp_registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(lp_ata, false),
                AccountMeta::new(self.lp_escrow, false),
                AccountMeta::new(redemption, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            // v17: RequestRedeemLpShares field renamed lp_amount → shares.
            data: ProgInstruction::RequestRedeemLpShares { shares: lp_amount }.encode(),
        };
        send_ixs(&mut self.svm, &self.payer, vec![wix], &[depositor]).expect("lp request redeem");
    }

    /// ExecuteRedemption (tag 77) — permissionless crank. Expects success.
    fn lp_execute_redeem(&mut self, depositor: &Keypair, redemption: Pubkey) -> Pubkey {
        let (dest, res) = self.lp_try_execute_redeem(depositor, redemption);
        res.expect("lp execute redemption");
        dest
    }

    /// ExecuteRedemption returning the result (for negative scenarios). Returns
    /// (payout dest, result).
    fn lp_try_execute_redeem(
        &mut self,
        depositor: &Keypair,
        redemption: Pubkey,
    ) -> (Pubkey, Result<(), TransactionError>) {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, depositor.pubkey(), 0),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let wix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.lp_registry, false),
                AccountMeta::new(redemption, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(self.lp_escrow, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new(self.lp_ledger, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
                // Sibling-domain ledger: NAV spans both pots of the vault's asset.
                AccountMeta::new(
                    state::derive_lp_backing_ledger(
                        &self.program_id,
                        &self.market,
                        CROSSCUT_DOMAIN ^ 1,
                    )
                    .0,
                    false,
                ),
                // GH#412 (account 12): the redeemer's own SOL account. The
                // redemption PDA's rent returns here rather than to the cranker.
                AccountMeta::new(depositor.pubkey(), false),
            ],
            data: ProgInstruction::ExecuteRedemption {
                domain: CROSSCUT_DOMAIN,
            }
            .encode(),
        };
        let res = send_ixs(&mut self.svm, &self.payer, vec![wix], &[]);
        (dest, res)
    }
}

/// 3A.1c — full LP-vault lifecycle (create → deposit → request → execute) at
/// MAINNET, sharing the market vault with the user-collateral path.
#[test]
fn x0_lp_vault_lifecycle_at_mainnet() {
    // BUG-2 / N7: this depositor is the vault's TRUE genesis depositor, so the
    // wrapper's LP_VAULT_MINIMUM_LIQUIDITY dead-share carve-out applies — it
    // mints MINTED (1_000_000 - LP_VAULT_MINIMUM_LIQUIDITY), not the full
    // amount, and the registry's outstanding-shares count never returns to a
    // literal 0 (it floors at LP_VAULT_MINIMUM_LIQUIDITY, permanently).
    const DEPOSIT_AMOUNT: u128 = 1_000_000;
    let minted: u128 = DEPOSIT_AMOUNT - LP_VAULT_MINIMUM_LIQUIDITY;

    let mut env = CrosscutEnv::new();
    env.lp_create(0, 0); // no fee, zero cooldown (immediate redeem)

    let depositor = Keypair::new();
    env.svm.airdrop(&depositor.pubkey(), 1_000_000_000).unwrap();
    let (lp_ata, source) = env.lp_deposit(&depositor, DEPOSIT_AMOUNT);

    // Executed guard: genesis deposit mints amount - MINIMUM_LIQUIDITY, full
    // collateral still moves into the vault.
    assert_eq!(
        env.token_amount(lp_ata),
        minted as u64,
        "genesis deposit mints amount minus dead-share floor"
    );
    assert_eq!(
        env.token_amount(env.vault),
        DEPOSIT_AMOUNT as u64,
        "vault received LP collateral"
    );
    assert_eq!(env.token_amount(source), 0, "source debited");
    let reg = state::read_lp_vault_registry(&env.account_data(env.lp_registry)).unwrap();
    assert_eq!(
        reg.total_lp_shares_outstanding, DEPOSIT_AMOUNT,
        "registry shares == full genesis amount"
    );

    // Redeem the full REAL position (what the depositor actually holds).
    let redemption =
        state::derive_lp_redemption(&env.program_id, &env.lp_registry, &depositor.pubkey()).0;
    env.lp_request_redeem(&depositor, redemption, lp_ata, minted);
    assert_eq!(env.token_amount(lp_ata), 0, "shares moved to escrow");
    assert_eq!(
        env.token_amount(env.lp_escrow),
        minted as u64,
        "escrow holds the shares"
    );

    let dest = env.lp_execute_redeem(&depositor, redemption);
    assert_eq!(
        env.token_amount(dest),
        minted as u64,
        "redeemer paid 1:1 for the shares they held"
    );
    assert_eq!(env.token_amount(env.lp_escrow), 0, "escrow burned to zero");
    assert_eq!(
        env.token_amount(env.vault),
        LP_VAULT_MINIMUM_LIQUIDITY as u64,
        "vault drained down to the dead-share floor's stranded principal, not fully to 0"
    );
    let reg = state::read_lp_vault_registry(&env.account_data(env.lp_registry)).unwrap();
    assert_eq!(
        reg.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY,
        "registry outstanding floors at the dead-share amount, not 0"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// NFT B-3 ownership transfer (mirrors v16_nft_e2e.rs, in the 5-program instance).
// The Token-2022 mint is real (CPI-initialized with the transfer-hook extension);
// the PositionNft / ExtraAccountMetaList PDAs are crafted (the e2e harness has no
// on-chain MintPositionNft). The TransferChecked → hook → B-3 CPI is REAL: its
// success proves the registry's nft_program_id is byte-correct (else Custom(45)).
// The deep NFT-under-live-trade scenarios are X1/X5/X7 (3A.4).
// ════════════════════════════════════════════════════════════════════════════

const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";
const POSITION_NFT_SEED: &[u8] = b"position_nft";
const POSITION_NFT_V16_MAGIC: u64 = 0x5045_5243_4E46_5400; // "PERCNFT\0"
const POSITION_NFT_V16_VERSION: u8 = 2;
const POSITION_NFT_V16_LEN: usize = 199;
const EXTRA_META_ENTRY_LEN: usize = 35;
const EXTRA_META_COUNT: usize = 7;
const EXTRA_METAS_ACCOUNT_LEN: usize = 8 + 4 + 4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;
const EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
const IX_TRANSFER_CHECKED: u8 = 12;

fn ata_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), TOKEN_2022.as_ref(), mint.as_ref()],
        &ATA_PROGRAM,
    )
    .0
}
fn extra_metas_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EXTRA_METAS_SEED, mint.as_ref()], &NFT_PROGRAM_ID)
}
fn position_nft_pda(portfolio: &Pubkey, market_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            POSITION_NFT_SEED,
            portfolio.as_ref(),
            &market_id.to_le_bytes(),
        ],
        &NFT_PROGRAM_ID,
    )
}
fn mint_auth_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"mint_authority"], &NFT_PROGRAM_ID)
}
fn nft_registry_pda(market: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[NFT_REGISTRY_SEED, market.as_ref()], &PERCOLATOR_MAINNET)
}

/// Craft PositionNftV16 state bytes (199 bytes) — exact on-chain layout.
fn nft_pda_data(
    portfolio: &Pubkey,
    nft_mint: &Pubkey,
    asset_index: u16,
    market_id: u64,
    bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8; POSITION_NFT_V16_LEN];
    d[0..8].copy_from_slice(&POSITION_NFT_V16_MAGIC.to_le_bytes());
    d[8] = POSITION_NFT_V16_VERSION;
    d[9] = bump;
    d[10..42].copy_from_slice(portfolio.as_ref());
    d[42..74].copy_from_slice(nft_mint.as_ref());
    d[74..78].copy_from_slice(&(asset_index as u32).to_le_bytes());
    d[78] = 0; // side_at_mint
    let basis: i128 = 1_000_000;
    d[79..95].copy_from_slice(&basis.to_le_bytes());
    d[95..111].copy_from_slice(&0i128.to_le_bytes());
    d[111..119].copy_from_slice(&market_id.to_le_bytes());
    d[119..127].copy_from_slice(&0u64.to_le_bytes());
    d[159..167].copy_from_slice(&1_700_000_000i64.to_le_bytes());
    d
}

/// Craft an ExtraAccountMetaList account (7 entries) — the exact hook-extra order.
fn extra_metas_data(
    nft_pda: &Pubkey,
    portfolio: &Pubkey,
    mint_auth: &Pubkey,
    registry: &Pubkey,
) -> Vec<u8> {
    let mut d = vec![0u8; EXTRA_METAS_ACCOUNT_LEN];
    d[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);
    let tlv_value_len: u32 = (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
    d[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());
    d[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());
    let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = [
        (*nft_pda, false, true),                    // [5] PositionNft PDA — writable
        (*portfolio, false, true),                  // [6] Portfolio — writable
        (PERCOLATOR_MAINNET, false, false),         // [7] Percolator program
        (*mint_auth, false, false),                 // [8] Mint authority
        (sysvar::instructions::id(), false, false), // [9] Instructions sysvar
        (NFT_PROGRAM_ID, false, false),             // [10] NFT program (self)
        (*registry, false, false),                  // [11] NFT registry
    ];
    for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
        let off = 16 + i * EXTRA_META_ENTRY_LEN;
        d[off] = 0; // FixedPubkey discriminator
        d[off + 1..off + 33].copy_from_slice(key.as_ref());
        d[off + 33] = if *is_signer { 1 } else { 0 };
        d[off + 34] = if *is_writable { 1 } else { 0 };
    }
    d
}

/// Build a minimal valid portfolio account (16-byte header + POD), active leg.
fn portfolio_data(
    portfolio_key: &Pubkey,
    market: &Pubkey,
    owner: &[u8; 32],
    asset_index: u32,
    market_id: u64,
    basis_pos_q: i128,
) -> Vec<u8> {
    let mut p = PortfolioAccountV16Account::default();
    p.provenance_header = ProvenanceHeaderV16Account {
        market_group_id: market.to_bytes(),
        portfolio_account_id: portfolio_key.to_bytes(),
        owner: *owner,
        version: V16PodU16::new(V16_ACCOUNT_VERSION),
        layout_discriminator: V16PodU16::new(V16_LAYOUT_DISCRIMINATOR),
    };
    p.owner = *owner;
    p.legs[0] = PortfolioLegV16Account {
        active: 1,
        asset_index: V16PodU32::new(asset_index),
        market_id: V16PodU64::new(market_id),
        basis_pos_q: V16PodI128::new(basis_pos_q),
        ..Default::default()
    };
    let pod_len = core::mem::size_of::<PortfolioAccountV16Account>();
    let mut data = vec![0u8; HEADER_LEN + pod_len];
    data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    data[8..10].copy_from_slice(&VERSION.to_le_bytes());
    data[10] = KIND_PORTFOLIO;
    data[HEADER_LEN..HEADER_LEN + pod_len].copy_from_slice(bytemuck::bytes_of(&p));
    data
}

fn read_portfolio_owner(data: &[u8]) -> [u8; 32] {
    let owner_off = HEADER_LEN + 100;
    data[owner_off..owner_off + 32].try_into().unwrap()
}
fn read_provenance_owner(data: &[u8]) -> [u8; 32] {
    let prov_owner_off = HEADER_LEN + 64;
    data[prov_owner_off..prov_owner_off + 32]
        .try_into()
        .unwrap()
}

/// Real Token-2022 mint init via CPI: create + InitializeTransferHook +
/// InitializeMintCloseAuthority + InitializeMint2. (verbatim v16_nft_e2e:612-690)
fn initialize_token2022_mint_with_hook(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint_kp: &Keypair,
    hook_program_id: &Pubkey,
) {
    let mint_space: usize = 270;
    let lamports = svm.minimum_balance_for_rent_exemption(mint_space);

    let mut hook_init_data = Vec::with_capacity(66);
    hook_init_data.push(36u8); // TRANSFER_HOOK_EXTENSION_TAG
    hook_init_data.push(0u8); // initialize sub-tag
    hook_init_data.extend_from_slice(&[0u8; 32]); // authority = None
    hook_init_data.extend_from_slice(hook_program_id.as_ref());
    let hook_init_ix = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![AccountMeta::new(mint_kp.pubkey(), false)],
        data: hook_init_data,
    };

    let (nft_mint_auth_key, _) = mint_auth_pda();
    let mut close_auth_data = Vec::with_capacity(34);
    close_auth_data.push(25u8); // IX_INITIALIZE_MINT_CLOSE_AUTHORITY
    close_auth_data.push(1u8); // COption::Some
    close_auth_data.extend_from_slice(nft_mint_auth_key.as_ref());
    let close_auth_ix = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![AccountMeta::new(mint_kp.pubkey(), false)],
        data: close_auth_data,
    };

    let mut init_mint_data = Vec::with_capacity(35);
    init_mint_data.push(20u8); // IX_INITIALIZE_MINT2
    init_mint_data.push(0u8); // decimals
    init_mint_data.extend_from_slice(payer.pubkey().as_ref());
    init_mint_data.push(0u8); // no freeze authority
    let init_mint_ix = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![AccountMeta::new(mint_kp.pubkey(), false)],
        data: init_mint_data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &mint_kp.pubkey(),
                lamports,
                mint_space as u64,
                &TOKEN_2022,
            ),
            hook_init_ix,
            close_auth_ix,
            init_mint_ix,
        ],
        Some(&payer.pubkey()),
        &[payer, mint_kp],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .expect("initialize Token-2022 mint with transfer hook");
}

/// Create a Token-2022 ATA via the ATA program. (verbatim v16_nft_e2e:692-719)
fn create_ata(svm: &mut LiteSVM, payer: &Keypair, wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_key = ata_address(wallet, mint);
    let ix = Instruction {
        program_id: ATA_PROGRAM,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(ata_key, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program::ID, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
        ],
        data: vec![0u8], // Create
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("create ATA");
    ata_key
}

/// Mint 1 NFT to an ATA (payer = mint authority). (verbatim v16_nft_e2e:722-743)
fn mint_one_to_ata(svm: &mut LiteSVM, payer: &Keypair, mint: &Pubkey, ata: &Pubkey) {
    let mut data = Vec::with_capacity(9);
    data.push(7u8); // IX_MINT_TO
    data.extend_from_slice(&1u64.to_le_bytes());
    let ix = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*ata, false),
            AccountMeta::new_readonly(payer.pubkey(), true),
        ],
        data,
    };
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("mint 1 NFT to ATA");
}

/// Token-2022 TransferChecked with the 8 hook extras. (verbatim v16_nft_e2e:1006-1042)
#[allow(clippy::too_many_arguments)]
fn transfer_checked_ix(
    source_ata: &Pubkey,
    nft_mint: &Pubkey,
    dest_ata: &Pubkey,
    source_owner: &Pubkey,
    extra_metas: &Pubkey,
    nft_pda: &Pubkey,
    portfolio: &Pubkey,
    mint_auth: &Pubkey,
    registry: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(IX_TRANSFER_CHECKED);
    data.extend_from_slice(&1u64.to_le_bytes()); // amount = 1
    data.push(0u8); // decimals = 0
    Instruction {
        program_id: TOKEN_2022,
        accounts: vec![
            AccountMeta::new(*source_ata, false),
            AccountMeta::new_readonly(*nft_mint, false),
            AccountMeta::new(*dest_ata, false),
            AccountMeta::new_readonly(*source_owner, true),
            AccountMeta::new_readonly(*extra_metas, false),
            AccountMeta::new(*nft_pda, false),
            AccountMeta::new(*portfolio, false),
            AccountMeta::new_readonly(PERCOLATOR_MAINNET, false),
            AccountMeta::new_readonly(*mint_auth, false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
            AccountMeta::new_readonly(NFT_PROGRAM_ID, false),
            AccountMeta::new_readonly(*registry, false),
        ],
        data,
    }
}

/// Place the full NFT bundle on a fresh crafted portfolio bound to `market`:
/// real Token-2022 mint + ATA + 1 token, plus injected PositionNft / ExtraMetas /
/// mint-authority PDAs. Returns the keys. (adapts place_nft_bundle_real_mint)
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn place_nft_bundle(
    svm: &mut LiteSVM,
    payer: &Keypair,
    market: &Pubkey,
    registry: &Pubkey,
    owner_wallet: &Keypair,
    asset_index: u16,
    market_id: u64,
    basis_pos_q: i128,
    mut portfolio_mutate: impl FnMut(&mut Vec<u8>),
) -> (Pubkey, Pubkey, Pubkey, Pubkey, Pubkey, (Pubkey, u8)) {
    let portfolio_key = Pubkey::new_unique();
    let nft_mint_kp = Keypair::new();
    let nft_mint_key = nft_mint_kp.pubkey();
    let (nft_pda_key, nft_bump) = position_nft_pda(&portfolio_key, market_id);
    let (extra_metas_key, _) = extra_metas_pda(&nft_mint_key);
    let (mint_auth_key, mint_auth_bump) = mint_auth_pda();
    let owner_bytes = owner_wallet.pubkey().to_bytes();
    let source_ata_key = ata_address(&owner_wallet.pubkey(), &nft_mint_key);

    initialize_token2022_mint_with_hook(svm, payer, &nft_mint_kp, &NFT_PROGRAM_ID);
    create_ata(svm, payer, &owner_wallet.pubkey(), &nft_mint_key);
    mint_one_to_ata(svm, payer, &nft_mint_key, &source_ata_key);

    let mut port_data = portfolio_data(
        &portfolio_key,
        market,
        &owner_bytes,
        asset_index as u32,
        market_id,
        basis_pos_q,
    );
    portfolio_mutate(&mut port_data);
    svm.set_account(
        portfolio_key,
        Account {
            lamports: 10_000_000_000,
            data: port_data,
            owner: PERCOLATOR_MAINNET,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    svm.set_account(
        nft_pda_key,
        Account {
            lamports: 2_000_000,
            data: nft_pda_data(
                &portfolio_key,
                &nft_mint_key,
                asset_index,
                market_id,
                nft_bump,
            ),
            owner: NFT_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    svm.set_account(
        extra_metas_key,
        Account {
            lamports: 2_000_000,
            data: extra_metas_data(&nft_pda_key, &portfolio_key, &mint_auth_key, registry),
            owner: NFT_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    svm.set_account(
        mint_auth_key,
        Account {
            lamports: 1_000_000,
            data: vec![],
            owner: NFT_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    (
        portfolio_key,
        nft_pda_key,
        nft_mint_key,
        source_ata_key,
        extra_metas_key,
        (mint_auth_key, mint_auth_bump),
    )
}

impl CrosscutEnv {
    /// SetNftProgramId (tag 73) — registers the NFT program (real id) for this
    /// market and creates the NftRegistry PDA. Returns the registry key.
    fn register_nft_program(&mut self) -> Pubkey {
        self.set_nft_program_id(NFT_PROGRAM_ID)
    }

    /// SetNftProgramId with an arbitrary id (for X7's wrong-id negative).
    fn set_nft_program_id(&mut self, nft_program_id: Pubkey) -> Pubkey {
        let (registry, _) = nft_registry_pda(&self.market);
        let admin = self.admin.insecure_clone();
        self.try_wrapper(
            ProgInstruction::SetNftProgramId {
                nft_program_id: nft_program_id.to_bytes(),
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(self.market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        )
        .expect("SetNftProgramId");
        registry
    }
}

/// 3A.1d — SetNftProgramId + a REAL Token-2022 TransferChecked → transfer-hook →
/// wrapper B-3 ownership change, in the 5-program instance on the CrosscutEnv
/// market (which also hosts the LP vault + matcher). The successful hook→B-3 CPI
/// proves the per-market NftRegistry's nft_program_id is byte-correct.
#[test]
fn x0_nft_transfer_hook_b3_ownership_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let registry = env.register_nft_program();
    assert_eq!(
        env.svm.get_account(&registry).unwrap().owner,
        PERCOLATOR_MAINNET,
        "SetNftProgramId created the registry owned by the wrapper"
    );

    let source_wallet = Keypair::new();
    env.svm
        .airdrop(&source_wallet.pubkey(), 10_000_000_000)
        .unwrap();
    let dest_wallet = Keypair::new();
    env.svm
        .airdrop(&dest_wallet.pubkey(), 10_000_000_000)
        .unwrap();

    let (portfolio, nft_pda, nft_mint, source_ata, extra_metas, (mint_auth, _)) = place_nft_bundle(
        &mut env.svm,
        &env.payer,
        &env.market,
        &registry,
        &source_wallet,
        0,
        42,
        1_000_000,
        |_| {},
    );

    let dest_ata = create_ata(&mut env.svm, &env.payer, &dest_wallet.pubkey(), &nft_mint);

    let transfer_ix = transfer_checked_ix(
        &source_ata,
        &nft_mint,
        &dest_ata,
        &source_wallet.pubkey(),
        &extra_metas,
        &nft_pda,
        &portfolio,
        &mint_auth,
        &registry,
    );
    let res = send_ixs(
        &mut env.svm,
        &env.payer,
        vec![transfer_ix],
        &[&source_wallet],
    );
    assert!(
        res.is_ok(),
        "Token-2022 TransferChecked → hook → B-3 must succeed in the 5-program instance: {res:?}"
    );

    // Executed guard (#105 escrow-at-mint): the transfer hook NO LONGER reassigns
    // portfolio.owner. The position stays escrowed (owner unchanged = source_wallet).
    // Assert portfolio.owner and provenance_header.owner are UNCHANGED by the transfer.
    let port_data = env.account_data(portfolio);
    assert_eq!(
        read_portfolio_owner(&port_data),
        source_wallet.pubkey().to_bytes(),
        "portfolio.owner must be UNCHANGED after transfer (escrow-at-mint: position stays escrowed)"
    );
    assert_eq!(
        read_provenance_owner(&port_data),
        source_wallet.pubkey().to_bytes(),
        "provenance_header.owner must be UNCHANGED after transfer (escrow-at-mint)"
    );
    assert_ne!(
        read_portfolio_owner(&port_data),
        dest_wallet.pubkey().to_bytes(),
        "portfolio.owner must NOT be changed to dest_wallet (no B-3 CPI on transfer under #105)"
    );
    assert_ne!(
        read_portfolio_owner(&port_data),
        dest_ata.to_bytes(),
        "owner must NOT be the ATA address"
    );

    // Executed guard: the NFT actually moved.
    let dest_ata_data = env.account_data(dest_ata);
    assert_eq!(
        u64::from_le_bytes(dest_ata_data[64..72].try_into().unwrap()),
        1,
        "dest ATA holds 1 NFT after transfer"
    );
}

/// 3A.1e — X6-LEDGER: end-to-end COLLATERAL conservation across the assembled
/// lifecycle (user deposits → matcher trade → LP deposit → LP redeem). The
/// collateral mint is never minted/burned by the wrapper — tokens only move — so
/// the sum across every collateral account is invariant. Plus per-checkpoint
/// `group.vault == on-chain vault` and the matcher seam `c_tot + insurance ==
/// vault` (no value created at the cross-program seams).
#[test]
fn x6_ledger_collateral_conservation_across_lifecycle() {
    let mut env = CrosscutEnv::new();
    env.lp_create(0, 0);

    let d: u128 = 1_000_000; // per-trader user deposit
    let l: u128 = 500_000; // LP deposit
    let total_created = 2 * d + l;

    // Traders deposit (user collateral → vault).
    let owner_a = Keypair::new();
    let owner_b = Keypair::new();
    let pa = env.create_portfolio(&owner_a);
    let pb = env.create_portfolio(&owner_b);
    let src_a = env.deposit(&owner_a, pa, d);
    let src_b = env.deposit(&owner_b, pb, d);
    assert_eq!(
        env.token_amount(env.vault),
        (2 * d) as u64,
        "vault holds 2 user deposits"
    );
    assert_eq!(
        env.group().vault,
        2 * d,
        "group.vault ledger == user collateral"
    );

    // Matcher trade — opens positions; fee is internal (capital → insurance),
    // no collateral enters/leaves the vault.
    let (ctx, delegate) = env.init_matcher_context(pb, &owner_b);
    env.trade_cpi(
        &owner_a,
        pa,
        &owner_b,
        pb,
        ctx,
        delegate,
        CROSSCUT_ASSET,
        (10 * POS_SCALE) as i128,
        100,
    )
    .expect("matcher trade");
    // Executed guard: a REAL fill happened (so conservation isn't trivially met by a no-op).
    assert_eq!(
        active_leg_basis(&env.portfolio(pa), CROSSCUT_ASSET),
        (10 * POS_SCALE) as i128,
        "matcher opened a real position (conservation is non-trivial)"
    );
    let g = env.group();
    assert_eq!(
        env.token_amount(env.vault),
        (2 * d) as u64,
        "matcher seam moves no collateral"
    );
    assert_eq!(
        g.c_tot + g.insurance,
        g.vault,
        "c_tot + insurance == vault (no value created)"
    );
    assert_eq!(g.vault, 2 * d, "group.vault conserved through the trade");

    // LP deposit (collateral → same vault, tracked in the backing ledger).
    // BUG-2 / N7: this is the vault's TRUE genesis deposit, so it mints
    // l - LP_VAULT_MINIMUM_LIQUIDITY, not the full l.
    let minted_lp = l - LP_VAULT_MINIMUM_LIQUIDITY;
    let lp = Keypair::new();
    env.svm.airdrop(&lp.pubkey(), 1_000_000_000).unwrap();
    let (lp_ata, src_lp) = env.lp_deposit(&lp, l);
    assert_eq!(
        env.token_amount(env.vault),
        (2 * d + l) as u64,
        "vault now holds user + LP collateral"
    );

    // LP redeem (collateral → dest, 1:1 with no earnings) — the depositor can only
    // redeem the REAL shares they hold (minted_lp), not the full l.
    let redemption = state::derive_lp_redemption(&env.program_id, &env.lp_registry, &lp.pubkey()).0;
    env.lp_request_redeem(&lp, redemption, lp_ata, minted_lp);
    let dest_lp = env.lp_execute_redeem(&lp, redemption);
    assert_eq!(
        env.token_amount(env.vault),
        (2 * d + LP_VAULT_MINIMUM_LIQUIDITY) as u64,
        "vault back to user collateral PLUS the dead-share floor's stranded principal"
    );
    assert_eq!(
        env.token_amount(dest_lp),
        minted_lp as u64,
        "LP redeemed 1:1 for the shares it held"
    );

    // ── Conservation: Σ collateral across every collateral account == created. ──
    // (lp_ata / lp_escrow hold LP SHARES, a different mint — excluded.) Still
    // holds EXACTLY under N7: the LP_VAULT_MINIMUM_LIQUIDITY atoms never left
    // any account — they're just stranded in env.vault instead of dest_lp.
    let sum_collateral = env.token_amount(src_a) as u128
        + env.token_amount(src_b) as u128
        + env.token_amount(src_lp) as u128
        + env.token_amount(dest_lp) as u128
        + env.token_amount(env.vault) as u128;
    assert_eq!(
        sum_collateral, total_created,
        "no collateral created or destroyed across deposit→trade→LP-deposit→redeem"
    );
    // LP-share mint nets to the dead-share floor, not literal zero (N7).
    let reg = state::read_lp_vault_registry(&env.account_data(env.lp_registry)).unwrap();
    assert_eq!(
        reg.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY,
        "LP shares net to the dead-share floor, not zero"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 3A.3 — STAKE greenfield. percolator_stake.so is loaded by ZERO wrapper tests;
// it CANNOT be a dev-dep here (zeroize/solana-2.2 clash), so the StakePool account
// is HAND-CRAFTED (384 bytes) and the stake tags are HAND-ENCODED. The proven
// wiring is lifted from percolator-stake/tests/v16_stake_insurance_e2e.rs (which
// uses the real crate under litesvm 0.6). PoolV16 layout: state.rs:19-114,
// STAKE_POOL_SIZE=408 (`state.rs:237`); discriminator "SPOOL_V1" @320..328,
// version 4 @328, at percolator-stake `origin/main` d0c6ecb.
//
// This craft was stranded at the v2 384-byte shape long after stake moved to v3,
// which is why the four x* tests below sat in KNOWN_FAILING: the real stake `.so`
// refused the bind with Custom(16) before any cross-program behaviour was
// exercised. They were quarantined as flaky wiring, but they were reporting a
// genuine version skew the whole time. #441 is the same skew one version later.
// ════════════════════════════════════════════════════════════════════════════

const STAKE_POOL_SIZE: usize = 408;
const STAKE_POOL_DISCRIMINATOR: &[u8; 8] = b"SPOOL_V1";
const STAKE_POOL_VERSION: u8 = 4;

/// Hand-craft a v16 StakePool in insurance-LP mode (pool_mode=0), bound to
/// `market` + `percolator_program`, with `vault` funded for flush. Mirrors the
/// e2e's `StakePool::zeroed() + fields + set_discriminator` (e2e.rs:232-244) as
/// raw bytes at the exact offsets.
#[allow(clippy::too_many_arguments)]
fn craft_stake_pool_bytes(
    market: &Pubkey,
    admin: &Pubkey,
    collateral_mint: &Pubkey,
    lp_mint: &Pubkey,
    stake_vault: &Pubkey,
    total_deposited: u64,
    percolator_program: &Pubkey,
    vault_authority_bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8; STAKE_POOL_SIZE];
    d[0] = 1; // is_initialized
    d[1] = 255; // pool bump (informational here)
    d[2] = vault_authority_bump;
    d[8..40].copy_from_slice(market.as_ref()); // slab (bound wrapper market)
    d[40..72].copy_from_slice(admin.as_ref());
    d[72..104].copy_from_slice(collateral_mint.as_ref());
    d[104..136].copy_from_slice(lp_mint.as_ref());
    d[136..168].copy_from_slice(stake_vault.as_ref()); // vault (source)
    d[168..176].copy_from_slice(&total_deposited.to_le_bytes()); // available-for-flush
    d[224..256].copy_from_slice(percolator_program.as_ref()); // CPI target (= MAINNET)
                                                              // d[280] pool_mode = 0 (insurance LP) — already zero.
    d[320..328].copy_from_slice(STAKE_POOL_DISCRIMINATOR);
    d[328] = STAKE_POOL_VERSION;
    d
}

struct StakeCtx {
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

impl CrosscutEnv {
    /// Craft a stake pool bound to this market, fund its vault with `deposit`.
    fn setup_stake_pool(&mut self, deposit: u64) -> StakeCtx {
        let (pool_pda, _) =
            Pubkey::find_program_address(&[b"stake_pool", self.market.as_ref()], &STAKE_ID);
        let (vault_auth, vault_auth_bump) =
            Pubkey::find_program_address(&[b"vault_auth", pool_pda.as_ref()], &STAKE_ID);
        let stake_vault = Pubkey::new_unique();
        // Stake vault token account: SPL owner = vault_auth PDA, mint = collateral.
        self.svm
            .set_account(
                stake_vault,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, vault_auth, deposit),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let lp_mint = Pubkey::new_unique();
        let pool_bytes = craft_stake_pool_bytes(
            &self.market,
            &self.admin.pubkey(),
            &self.mint,
            &lp_mint,
            &stake_vault,
            deposit,
            &self.program_id, // = MAINNET (must match the loaded wrapper)
            vault_auth_bump,
        );
        self.svm
            .set_account(
                pool_pda,
                Account {
                    lamports: 1_000_000_000,
                    data: pool_bytes,
                    owner: STAKE_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        StakeCtx {
            pool_pda,
            vault_auth,
            stake_vault,
        }
    }

    /// stake BindInsuranceAuthority (tag 19) — stake CPIs the wrapper's
    /// UpdateAuthority(insurance) to set cfg.insurance_authority = vault_auth PDA.
    fn stake_bind(&mut self, ctx: &StakeCtx) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: STAKE_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(ctx.pool_pda, false),
                AccountMeta::new_readonly(ctx.vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: vec![19u8],
        };
        send_ixs(&mut self.svm, &self.payer, vec![ix], &[&admin])
    }

    /// Advance the SVM clock (ResolveMarket requires `clock_slot >= current_slot`).
    fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    /// wrapper ResolveMarket — transitions the market mode Live -> resolved.
    fn resolve_market(&mut self) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        self.try_wrapper(
            ProgInstruction::ResolveMarket,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
    }

    /// stake FlushToInsurance (tag 3 + u64) — stake CPIs the wrapper's
    /// TopUpInsurance (invoke_signed by vault_auth), moving stake_vault ->
    /// wrapper vault and crediting group.insurance.
    fn stake_flush(&mut self, ctx: &StakeCtx, amount: u64) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: STAKE_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(ctx.pool_pda, false),
                AccountMeta::new(ctx.stake_vault, false),
                AccountMeta::new_readonly(ctx.vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.program_id, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            data,
        };
        send_ixs(&mut self.svm, &self.payer, vec![ix], &[&admin])
    }

    /// stake RotateInsuranceAuthority (tag 20) — the no-lockout escape: stake CPIs
    /// the wrapper's UpdateAuthority with the vault_auth PDA signing as the CURRENT
    /// authority and `new_target` co-signing as the successor.
    fn stake_rotate(
        &mut self,
        ctx: &StakeCtx,
        new_target: &Keypair,
    ) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: STAKE_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(ctx.pool_pda, false),
                AccountMeta::new_readonly(ctx.vault_auth, false),
                AccountMeta::new_readonly(new_target.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.program_id, false),
            ],
            data: vec![20u8],
        };
        send_ixs(&mut self.svm, &self.payer, vec![ix], &[&admin, new_target])
    }

    /// wrapper WithdrawInsurance (tag 41 + u128) — terminal reclaim by the (now
    /// signable) insurance authority. Returns (dest_token, result).
    fn wrapper_withdraw_insurance(
        &mut self,
        authority: &Keypair,
        amount: u128,
    ) -> (Pubkey, Result<(), TransactionError>) {
        let dest = Pubkey::new_unique();
        self.svm
            .set_account(
                dest,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, authority.pubkey(), 0),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let mut data = vec![41u8];
        data.extend_from_slice(&amount.to_le_bytes());
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new_readonly(authority.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            data,
        };
        let res = send_ixs(&mut self.svm, &self.payer, vec![ix], &[authority]);
        (dest, res)
    }
}

/// 3A.3 (foundation) — the hand-crafted stake pool + hand-encoded bind/flush drive
/// the loaded percolator_stake.so under litesvm 0.1: stake CPIs the wrapper at
/// MAINNET to bind the insurance authority to its vault_auth PDA, then flushes
/// collateral stake_vault -> wrapper vault and credits insurance. THE greenfield
/// de-risk (stake was loaded by zero wrapper tests before now).
#[test]
fn x0_stake_flush_to_insurance_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let flush_amount: u64 = 1_000_000;
    let ctx = env.setup_stake_pool(flush_amount);

    let insurance_before = env.group().insurance;
    let vault_before = env.token_amount(env.vault);

    // Bind must precede the first flush (TopUpInsurance is gated by
    // cfg.insurance_authority == signer == vault_auth PDA).
    env.stake_bind(&ctx).expect("BindInsuranceAuthority");
    env.stake_flush(&ctx, flush_amount)
        .expect("FlushToInsurance");

    // Executed guards: real token movement + insurance credit through the CPI.
    assert_eq!(
        env.token_amount(ctx.stake_vault),
        0,
        "stake vault drained by flush"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before + flush_amount,
        "wrapper vault received the flushed collateral"
    );
    assert_eq!(
        env.group().insurance,
        insurance_before + flush_amount as u128,
        "group.insurance credited by exactly the flushed amount"
    );
}

/// X2-FLUSH-RACE (part 1) — a flush into a RESOLVED market reverts mode!=Live
/// (the wrapper's TopUpInsurance Live-gate, v16_program.rs:7566), atomically. Plus
/// the flush-conservation invariant on the Live flush (insurance += exactly the
/// flushed amount; vault conserved).
#[test]
fn x2_flush_race_resolved_market_reverts_mode_not_live() {
    let mut env = CrosscutEnv::new();
    let ctx = env.setup_stake_pool(2_000_000);
    env.stake_bind(&ctx).expect("bind");

    // Live flush — conservation.
    let insurance_before = env.group().insurance;
    let vault_before = env.token_amount(env.vault);
    env.stake_flush(&ctx, 1_000_000).expect("flush while Live");
    assert_eq!(
        env.group().insurance,
        insurance_before + 1_000_000,
        "insurance += exactly the flush"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before + 1_000_000,
        "vault conserved through flush"
    );
    assert_eq!(
        env.token_amount(ctx.stake_vault),
        1_000_000,
        "stake vault retains the un-flushed 1M"
    );

    // Resolve, then a second flush must revert (mode != Live) and change NOTHING.
    env.warp(100); // align SVM clock >= group.current_slot for ResolveMarket
    env.resolve_market().expect("resolve market");
    let insurance_pre = env.group().insurance;
    let vault_pre = env.token_amount(env.vault);
    let stake_pre = env.token_amount(ctx.stake_vault);
    let res = env.stake_flush(&ctx, 1_000_000);
    assert_custom(
        res,
        E_LOCK_ACTIVE,
        "flush into a resolved market reverts mode!=Live",
    );
    assert_eq!(
        env.group().insurance,
        insurance_pre,
        "rejected flush left insurance unchanged"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_pre,
        "rejected flush left wrapper vault unchanged"
    );
    assert_eq!(
        env.token_amount(ctx.stake_vault),
        stake_pre,
        "rejected flush left stake vault unchanged"
    );
}

/// X5-TERMINAL — terminal-reclaim LIVENESS + no-lockout. After a stake flush
/// (insurance credited to asset-0's domain budgets, authority = vault_auth PDA),
/// the insurance would be stranded because a PDA can't sign WithdrawInsurance.
/// The escape is RotateInsuranceAuthority(20): rotate the authority off the PDA to
/// a signable wallet, resolve, then that wallet reclaims EXACTLY the flushed
/// insurance. This is the highest-value gate check: does terminal-reclaim liveness
/// hold in the assembled system?
#[test]
fn x5_terminal_reclaim_liveness_via_rotate_no_lockout() {
    let mut env = CrosscutEnv::new();
    let amount: u64 = 1_000_000;
    let ctx = env.setup_stake_pool(amount);
    env.stake_bind(&ctx).expect("bind");
    env.stake_flush(&ctx, amount).expect("flush");
    assert_eq!(
        env.group().insurance,
        amount as u128,
        "insurance funded by flush"
    );
    assert_eq!(
        env.token_amount(env.vault),
        amount,
        "wrapper vault holds the flushed collateral"
    );

    // No-lockout escape: rotate the insurance authority off the vault_auth PDA to a
    // signable wallet BEFORE decommission (must be done while Live).
    let reclaim_authority = Keypair::new();
    env.svm
        .airdrop(&reclaim_authority.pubkey(), 1_000_000_000)
        .unwrap();
    env.stake_rotate(&ctx, &reclaim_authority)
        .expect("rotate insurance authority off the PDA (no-lockout)");

    // Resolve (mode -> resolved). Market has count==0 && c_tot==0 (no portfolios).
    env.warp(100);
    env.resolve_market().expect("resolve");

    // Terminal reclaim: the rotated authority withdraws the flushed insurance.
    let (dest, res) = env.wrapper_withdraw_insurance(&reclaim_authority, amount as u128);
    res.expect("terminal WithdrawInsurance must succeed (reclaim liveness holds, no lockout)");
    assert_eq!(
        env.token_amount(dest),
        amount,
        "reclaimed EXACTLY the flushed insurance"
    );
    assert_eq!(
        env.token_amount(env.vault),
        0,
        "wrapper vault drained by terminal reclaim"
    );
    assert_eq!(env.group().insurance, 0, "insurance fully reclaimed");
}

/// Run the flush + bankrupt-short-liquidation scenario in a fresh 5-program
/// instance, in the given ordering. Returns (end_insurance, end_vault_token,
/// short_leg_basis_after). Asserts vault lockstep internally.
fn run_flush_liquidation(flush_first: bool, flush_amount: u64) -> (u128, u64, i128) {
    let mut env = CrosscutEnv::new();
    let lp = Keypair::new();
    let weak = Keypair::new();
    let la = env.create_portfolio(&lp);
    let wa = env.create_portfolio(&weak);
    env.deposit(&lp, la, 1_000_000);
    env.deposit(&weak, wa, 250); // thin short — will go bankrupt
    env.try_trade(&lp, la, &weak, wa, POS_SCALE as i128, 100, 0)
        .expect("open lp-long / weak-short");
    // Walk the mark up so the short's loss (≈300) exceeds its 250 deposit.
    for (slot, price) in [(10u64, 200u64), (20, 300), (30, 400)] {
        env.warp(slot);
        env.accrue_mark(slot, price);
        let _ = env.crank(wa, 0, slot);
        let _ = env.crank(la, 0, slot);
    }

    let ctx = env.setup_stake_pool(flush_amount);
    env.stake_bind(&ctx).expect("bind");

    if flush_first {
        env.stake_flush(&ctx, flush_amount).expect("flush");
        env.crank(wa, 1, 30).expect("liquidate bankrupt short");
    } else {
        env.crank(wa, 1, 30).expect("liquidate bankrupt short");
        env.stake_flush(&ctx, flush_amount).expect("flush");
    }

    let g = env.group();
    assert_eq!(
        g.vault,
        env.token_amount(env.vault) as u128,
        "group.vault ledger == on-chain SPL vault (lockstep) at scenario end"
    );
    (g.insurance, env.token_amount(env.vault), env.leg_basis(wa))
}

/// X2-FLUSH-RACE (part 2) — stake flush vs a concurrent liquidation crank. In
/// single-threaded LiteSVM the "race" is order-sensitivity: both interleavings
/// must reach the SAME conserved end state. The flush is cleanly additive to
/// insurance; the liquidation (asset-1 bankrupt short; no liquidation fee, no
/// cranker reward, and the flush funded only asset-0's domain budget) draws
/// nothing from insurance and never moves the vault. Executed guard: the
/// liquidation actually fires (short leg closes) in both orderings.
#[test]
fn x2_flush_race_liquidation_crank_order_independent() {
    let flush: u64 = 1_000_000;
    let (ins_ff, vault_ff, leg_ff) = run_flush_liquidation(true, flush);
    let (ins_lf, vault_lf, leg_lf) = run_flush_liquidation(false, flush);

    // Executed guard: the bankrupt short was actually liquidated (leg closed) both ways.
    assert_eq!(leg_ff, 0, "flush-first: bankrupt short liquidated");
    assert_eq!(leg_lf, 0, "liquidate-first: bankrupt short liquidated");

    // Order independence: identical end state regardless of interleaving.
    assert_eq!(
        ins_ff, ins_lf,
        "insurance order-independent across flush vs liquidation"
    );
    assert_eq!(
        vault_ff, vault_lf,
        "vault order-independent across flush vs liquidation"
    );

    // Flush is cleanly additive: the liquidation drew nothing from the flushed insurance.
    assert_eq!(
        ins_ff, flush as u128,
        "insurance == exactly the flushed amount (no liquidation draw)"
    );
}

/// X5-TERMINAL (NFT-lock half) — an NFT-bundled portfolio that is LOCKED
/// (liquidation_lock=1, the post-resolve/locked condition) rejects the B-3
/// ownership transfer: the transfer-hook gate fires and ownership is NOT rewritten.
/// This proves a locked portfolio's NFT cannot be transferred — so it cannot be
/// used to strand state — in the 5-program instance (combined with X5's proven
/// reclaim liveness, the lock blocks transfer but never the insurance reclaim).
#[test]
fn x5_nft_locked_portfolio_transfer_rejected() {
    let mut env = CrosscutEnv::new();
    let registry = env.register_nft_program();
    let source_wallet = Keypair::new();
    env.svm
        .airdrop(&source_wallet.pubkey(), 10_000_000_000)
        .unwrap();
    let dest_wallet = Keypair::new();
    env.svm
        .airdrop(&dest_wallet.pubkey(), 10_000_000_000)
        .unwrap();

    // Craft an NFT bundle whose portfolio is LOCKED.
    let (portfolio, nft_pda, nft_mint, source_ata, extra_metas, (mint_auth, _)) = place_nft_bundle(
        &mut env.svm,
        &env.payer,
        &env.market,
        &registry,
        &source_wallet,
        0,
        42,
        1_000_000,
        |data| {
            let off = HEADER_LEN;
            let len = core::mem::size_of::<PortfolioAccountV16Account>();
            let p: &mut PortfolioAccountV16Account =
                bytemuck::from_bytes_mut(&mut data[off..off + len]);
            p.liquidation_lock = 1;
        },
    );
    let dest_ata = create_ata(&mut env.svm, &env.payer, &dest_wallet.pubkey(), &nft_mint);
    let owner_before = read_portfolio_owner(&env.account_data(portfolio));

    let transfer_ix = transfer_checked_ix(
        &source_ata,
        &nft_mint,
        &dest_ata,
        &source_wallet.pubkey(),
        &extra_metas,
        &nft_pda,
        &portfolio,
        &mint_auth,
        &registry,
    );
    let res = send_ixs(
        &mut env.svm,
        &env.payer,
        vec![transfer_ix],
        &[&source_wallet],
    );

    // The transfer-hook gate blocks a locked portfolio with the exact operative code;
    // ownership is NOT rewritten.
    assert_custom(
        res,
        NFT_TRANSFER_BLOCKED,
        "locked-portfolio NFT transfer is gate-blocked",
    );
    assert_eq!(
        read_portfolio_owner(&env.account_data(portfolio)),
        owner_before,
        "rejected transfer left portfolio.owner unchanged (no rewrite)"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// 3A.4 — P1 cross-program invariants.
// ════════════════════════════════════════════════════════════════════════════

/// X8-DELEGATE — the matcher-delegate signer is scoped per (market, maker,
/// matcher_program, ctx). A delegate bound to maker Y, presented with maker X's
/// accounts, fails the wrapper's `expect_key` re-derivation (InvalidArgument,
/// v16_program.rs:7352) BEFORE the matcher CPI runs. Positive control: the
/// correctly-bound (maker Y) delegate trades.
#[test]
fn x8_matcher_delegate_scoped_per_maker_rejects_mismatch() {
    let mut env = CrosscutEnv::new();
    let taker_owner = Keypair::new();
    let maker_x_owner = Keypair::new();
    let maker_y_owner = Keypair::new();
    let taker = env.create_portfolio(&taker_owner);
    let maker_x = env.create_portfolio(&maker_x_owner);
    let maker_y = env.create_portfolio(&maker_y_owner);
    env.deposit(&taker_owner, taker, 1_000_000);
    env.deposit(&maker_x_owner, maker_x, 1_000_000);
    env.deposit(&maker_y_owner, maker_y, 1_000_000);

    // Matcher context bound to maker Y (delegate PDA derived for Y).
    let (ctx_y, delegate_y) = env.init_matcher_context(maker_y, &maker_y_owner);

    // Y's delegate with maker X's accounts → delegate PDA mismatch.
    let res = env.trade_cpi(
        &taker_owner,
        taker,
        &maker_x_owner,
        maker_x,
        ctx_y,
        delegate_y,
        CROSSCUT_ASSET,
        (10 * POS_SCALE) as i128,
        100,
    );
    assert_instruction_error(
        &res,
        InstructionError::InvalidArgument,
        "matcher delegate bound to maker Y rejects maker X (expect_key mismatch)",
    );

    // Positive control: the correctly-bound delegate (maker Y) trades.
    env.trade_cpi(
        &taker_owner,
        taker,
        &maker_y_owner,
        maker_y,
        ctx_y,
        delegate_y,
        CROSSCUT_ASSET,
        (10 * POS_SCALE) as i128,
        100,
    )
    .expect("correctly-bound maker-Y delegate trades");
    assert_eq!(
        active_leg_basis(&env.portfolio(taker), CROSSCUT_ASSET),
        (10 * POS_SCALE) as i128,
        "positive control opened the position (delegate scoping is the only blocker)"
    );
}

/// X7-REGISTRY — the per-market NftRegistry binds the NFT program id. (1) The
/// registry PDA derives byte-identically on the wrapper side and the NFT side
/// (both `[b"nft_registry", market]` under MAINNET). (2) A registry pointing at a
/// WRONG nft_program_id causes `NftInvalidMintAuthority Custom(45)` when the
/// wrapper's B-3 / UnwrapEscrowedPortfolio is called: the wrapper derives the
/// expected mint-authority from `registry.nft_program_id` (bogus), and it does not
/// match any real NFT program's signer.
///
/// NOTE (#105 escrow-at-mint): Under the escrow-at-mint model, the transfer hook no
/// longer calls B-3 — the token moves but portfolio.owner stays the escrow PDA.
/// The nft_program_id trust binding is therefore enforced at:
///   (a) MintPositionNft — wrapper reads registry, verifies NFT program on-chain
///   (b) UnwrapEscrowedPortfolio (tag 82) — wrapper re-derives mint_auth from
///       registry.nft_program_id; a bogus id → wrong PDA → Custom(45).
/// This test exercises path (b): calling tag 82 with the real NFT program's
/// mint_auth PDA as signer while the registry names a DIFFERENT program causes
/// NftInvalidMintAuthority. Portfolio.owner must remain the escrow PDA (unchanged).
#[test]
fn x7_registry_wrong_nft_program_id_rejects() {
    let mut env = CrosscutEnv::new();

    // (1) Registry PDA derives byte-identically on both sides (pre-condition check).
    let bogus = Pubkey::new_unique();
    let registry = env.set_nft_program_id(bogus);
    assert_eq!(
        registry,
        nft_registry_pda(&env.market).0,
        "registry PDA derives byte-identically (wrapper == NFT side)"
    );

    // Build a minimal portfolio with owner = NFT program's real mint_auth PDA
    // (the escrow state that UnwrapEscrowedPortfolio expects as a precondition).
    let (real_mint_auth, _) = mint_auth_pda();
    let portfolio_key = Pubkey::new_unique();
    let mint_auth_bytes = real_mint_auth.to_bytes();
    let port_data = {
        let mut d = portfolio_data(
            &portfolio_key,
            &env.market,
            &mint_auth_bytes, // owner = escrow PDA
            0,
            42,
            1_000_000,
        );
        // Ensure provenance_header.owner matches.
        let prov_off = HEADER_LEN + 64;
        d[prov_off..prov_off + 32].copy_from_slice(&mint_auth_bytes);
        d
    };
    env.svm
        .set_account(
            portfolio_key,
            Account {
                lamports: 10_000_000_000,
                data: port_data,
                owner: PERCOLATOR_MAINNET,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    // Attempt UnwrapEscrowedPortfolio (tag 82) with the REAL mint_auth pubkey as
    // the signer-account (using a fresh Keypair whose pubkey matches — but since
    // the registry names a bogus program, the wrapper derives a DIFFERENT expected
    // mint_auth and rejects with NftInvalidMintAuthority).
    //
    // We must use a Keypair that can sign, but whose pubkey matches real_mint_auth.
    // Since that's impossible (PDAs have no secret key), we instead use a random
    // signer — what matters is that the wrapper rejects because it derives
    // `expected_mint_auth = derive_nft_mint_authority(bogus_id)` from the registry,
    // and no signer can present the right PDA as long as bogus_id is wrong.
    // The test proves the BINDING: rejection traces to the bogus nft_program_id in
    // the registry, not to any other unrelated check.
    let caller = Keypair::new();
    env.svm.airdrop(&caller.pubkey(), 10_000_000_000).unwrap();

    let owner_before = read_portfolio_owner(&env.account_data(portfolio_key));

    let res = env.try_wrapper(
        ProgInstruction::UnwrapEscrowedPortfolio {
            new_owner: [0x03u8; 32],
        },
        vec![
            AccountMeta::new_readonly(caller.pubkey(), true), // signer ≠ expected_mint_auth(bogus)
            AccountMeta::new(portfolio_key, false),
            AccountMeta::new_readonly(registry, false),
        ],
        &[&caller],
    );
    assert_custom(
        res,
        NFT_INVALID_MINT_AUTHORITY,
        "registry.nft_program_id binding: bogus program id → wrong expected mint_auth → Custom(45)",
    );
    assert_eq!(
        read_portfolio_owner(&env.account_data(portfolio_key)),
        owner_before,
        "rejected unwrap left portfolio.owner unchanged (still the escrow PDA)"
    );
}

/// X3-LP-LIEN — the LP-redemption OI-reservation guard (Custom 37).
///
/// LP-VAULT-REDEEM-BUG (found + fixed 2026-07-17): prior to the fix,
/// `outstanding_post` in the guard counted ALL remaining fresh (un-liened)
/// backing as "outstanding," not just backing genuinely liened against real
/// open interest -- so this exact test, prior to the fix, asserted that a
/// PARTIAL redemption against a CLEAN (zero-OI) bucket rejects under ANY
/// nonzero threshold. That was the bug: it bricked ordinary, fully-solvent,
/// zero-OI redemption for every real deployed vault (since no wrapper
/// instruction ever writes `valid_liened_backing_num` on a real trade -- see
/// CONSTRUCTIBILITY NOTE below), while protecting nothing. The fix narrows
/// `outstanding_post` to `bucket.valid_liened_backing_num` only. See
/// tests/v16_fork_lp_vault_redeem.rs for the full writeup and the
/// non-vacuous fail-pre-fix/pass-post-fix proof.
///
/// This test now pins the CORRECTED accept-path semantics: a PARTIAL
/// redemption against a CLEAN bucket now SUCCEEDS under a nonzero threshold
/// (there is no real OI to protect). The reject-path (genuine OI lien still
/// blocks an under-backed redemption, Custom 37) is pinned separately below
/// in `x3_lp_redemption_oi_reservation_genuine_lien_still_rejects`.
///
/// CONSTRUCTIBILITY NOTE: the TRUE "matcher/trade OI lien blocks redemption" path
/// is NOT reachable with the real programs — no wrapper instruction writes the
/// engine's `valid_liened_backing_num` (it is mutated only by a `#[cfg(test)]`
/// engine unit path), so a real trade leaves the lien at zero. The reject-path
/// test below hand-crafts the lien field directly (same raw-account-poke
/// technique used throughout tests/v16_fork_lp_vault_redeem.rs) to exercise the
/// guard's real solvency logic despite this. (Logged as a cross-cut divergence:
/// true OI-lien path deferred / not program-constructible.)
#[test]
fn x3_lp_redemption_oi_reservation_guard_fires() {
    let mut env = CrosscutEnv::new();
    env.lp_create_full(0, 0, 5_000); // 50% OI-reservation threshold
    let depositor = Keypair::new();
    env.svm.airdrop(&depositor.pubkey(), 1_000_000_000).unwrap();
    let l: u128 = 1_000_000;
    // BUG-2 / N7: this is the vault's TRUE genesis deposit, so it mints
    // l - LP_VAULT_MINIMUM_LIQUIDITY, not the full l.
    let minted = l - LP_VAULT_MINIMUM_LIQUIDITY;
    let (lp_ata, _src) = env.lp_deposit(&depositor, l);
    // Executed guard: the deposit really minted shares (the guard isn't trivially met).
    assert_eq!(
        env.token_amount(lp_ata),
        minted as u64,
        "deposit minted LP shares"
    );

    // A PARTIAL redemption against a CLEAN (zero-OI) bucket now succeeds under
    // any nonzero threshold — non-vacuously proven to fail pre-fix and pass
    // post-fix in tests/v16_fork_lp_vault_redeem.rs
    // (execute_redemption_oi_reservation_clean_bucket_partial_succeeds).
    let redemption =
        state::derive_lp_redemption(&env.program_id, &env.lp_registry, &depositor.pubkey()).0;
    env.lp_request_redeem(&depositor, redemption, lp_ata, l / 2);
    let dest = env.lp_execute_redeem(&depositor, redemption);
    assert_eq!(
        env.token_amount(dest),
        (l / 2) as u64,
        "clean-bucket partial redemption pays exact pro-rata, no longer fail-closed"
    );
}

/// Hand-crafts a genuine OI lien on `domain`'s backing bucket: moves
/// `lien_atoms` worth of backing from `fresh_unliened_backing_num` into
/// `valid_liened_backing_num` -- the effect a real matcher/trade-CPI lien
/// against LP-vault backing would have (see CONSTRUCTIBILITY NOTE above).
/// Total bucket backing is unchanged, so header/vault aggregates stay in
/// lockstep and `validate_shape()` still passes.
fn set_bucket_oi_lien_for_test(env: &mut CrosscutEnv, domain: u16, lien_atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    let lien_num = lien_atoms * percolator::BOUND_SCALE;
    let bucket = &mut group.source_backing_buckets[domain as usize];
    bucket.fresh_unliened_backing_num = bucket
        .fresh_unliened_backing_num
        .checked_sub(lien_num)
        .expect("enough fresh backing to lien");
    bucket.valid_liened_backing_num = bucket
        .valid_liened_backing_num
        .checked_add(lien_num)
        .expect("no overflow");
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

/// NEGATIVE test (solvency preserved): a redemption that would leave a
/// GENUINE OI lien uncovered by post-redeem NAV at the configured threshold
/// is still rejected at LpVaultOiReservationViolated (Custom 37) after the
/// LP-VAULT-REDEEM-BUG fix.
///
/// Single depositor deposits l=1_000_000 (mints 999_000). Hand-craft a
/// genuine OI lien of 400_000 atoms, leaving fresh_unliened_backing_num =
/// 600_000. Threshold = 5_000 (50%). Redeem 500_000:
///   - Availability gate: fresh_unliened (600_000) >= backing_num (500_000)
///     -> passes (not the gate that fires).
///   - Post-redeem NAV = 1_000_000 - 500_000 = 500_000 (no earnings).
///   - covered = nav_post * 50% = 250_000.
///   - outstanding_post = valid_liened_backing_num = 400_000.
///   - covered (250_000) < outstanding_post (400_000) -> REJECT, Custom(37).
/// This holds under BOTH the old and new formula (old: outstanding_post =
/// (600_000 - 500_000) + 400_000 = 500_000, even larger) — proving the fix
/// did not weaken protection against real OI.
#[test]
fn x3_lp_redemption_oi_reservation_genuine_lien_still_rejects() {
    let mut env = CrosscutEnv::new();
    env.lp_create_full(0, 0, 5_000); // 50% OI-reservation threshold
    let depositor = Keypair::new();
    env.svm.airdrop(&depositor.pubkey(), 1_000_000_000).unwrap();
    let l: u128 = 1_000_000;
    let (lp_ata, _src) = env.lp_deposit(&depositor, l);

    set_bucket_oi_lien_for_test(&mut env, CROSSCUT_DOMAIN, 400_000);

    let redemption =
        state::derive_lp_redemption(&env.program_id, &env.lp_registry, &depositor.pubkey()).0;
    env.lp_request_redeem(&depositor, redemption, lp_ata, l / 2);
    let (dest, res) = env.lp_try_execute_redeem(&depositor, redemption);
    assert_custom(
        res,
        LP_VAULT_OI_RESERVATION_VIOLATED,
        "redemption leaving a genuine OI lien uncovered is still fail-closed (Custom 37)",
    );
    assert_eq!(
        env.token_amount(dest),
        0,
        "no payout on the rejected under-backed redemption"
    );
}

/// 3A.1b — a real matcher `TradeCpi` fires through the loaded `percolator_match`
/// `.so` at MAINNET, coexisting with the Token-2022 / NFT / stake programs in one
/// instance. The matcher-delegate PDA derives under MAINNET on both sides.
#[test]
fn x0_matcher_tradecpi_real_fill_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let taker_owner = Keypair::new();
    let maker_owner = Keypair::new();
    let taker = env.create_portfolio(&taker_owner);
    let maker = env.create_portfolio(&maker_owner);
    env.deposit(&taker_owner, taker, 1_000_000);
    env.deposit(&maker_owner, maker, 1_000_000);

    let (ctx, delegate) = env.init_matcher_context(maker, &maker_owner);
    env.trade_cpi(
        &taker_owner,
        taker,
        &maker_owner,
        maker,
        ctx,
        delegate,
        CROSSCUT_ASSET,
        (10 * POS_SCALE) as i128,
        100,
    )
    .expect("matcher TradeCpi fill");

    // Executed guard: the real matcher fill opened equal-and-opposite positions.
    let taker_leg = active_leg_basis(&env.portfolio(taker), CROSSCUT_ASSET);
    let maker_leg = active_leg_basis(&env.portfolio(maker), CROSSCUT_ASSET);
    assert_eq!(
        taker_leg,
        (10 * POS_SCALE) as i128,
        "taker opened long via matcher"
    );
    assert_eq!(
        maker_leg,
        -((10 * POS_SCALE) as i128),
        "maker opened short via matcher"
    );

    // The loaded matcher .so actually ran (ABI v3 + echoes the requested asset).
    let mdata = env.account_data(ctx);
    assert_eq!(
        u32::from_le_bytes(mdata[0..4].try_into().unwrap()),
        MATCHER_ABI_VERSION,
        "matcher used the v3 ABI"
    );
    assert_eq!(
        u64::from_le_bytes(mdata[56..64].try_into().unwrap()),
        CROSSCUT_ASSET as u64,
        "matcher echoes the requested asset index in the v3 return slot"
    );

    // Conservation through the matcher seam: no value created.
    let g = env.group();
    assert_eq!(g.c_tot + g.insurance, g.vault, "c_tot + insurance == vault");
}

// W3 (canonical-ATA): mirror of v16_program::processor::canonical_vault_address — the SPL
// Associated Token Account of the vault_authority PDA for this mint. Kept byte-in-lock-step with
// the program so vault fixtures satisfy the F-VAULT-FRAG pin (a green test == the derivation matches).
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

// ── E2 cross-program fund-routing integration (debug pass) ──
fn reown_portfolio(env: &mut CrosscutEnv, portfolio: Pubkey, new_owner: &[u8; 32]) {
    let mut d = env.account_data(portfolio);
    d[HEADER_LEN + 100..HEADER_LEN + 132].copy_from_slice(new_owner);
    d[HEADER_LEN + 64..HEADER_LEN + 96].copy_from_slice(new_owner);
    env.svm
        .set_account(
            portfolio,
            Account {
                lamports: 10_000_000_000,
                data: d,
                owner: PERCOLATOR_MAINNET,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
}
fn attach_nft_to_portfolio(
    env: &mut CrosscutEnv,
    holder: &Keypair,
    portfolio: Pubkey,
    market_id: u64,
) -> (Pubkey, Pubkey, Pubkey) {
    let nft_mint_kp = Keypair::new();
    let nft_mint = nft_mint_kp.pubkey();
    let (nft_pda, bump) = position_nft_pda(&portfolio, market_id);
    let holder_ata = ata_address(&holder.pubkey(), &nft_mint);
    initialize_token2022_mint_with_hook(&mut env.svm, &env.payer, &nft_mint_kp, &NFT_PROGRAM_ID);
    create_ata(&mut env.svm, &env.payer, &holder.pubkey(), &nft_mint);
    mint_one_to_ata(&mut env.svm, &env.payer, &nft_mint, &holder_ata);
    env.svm
        .set_account(
            nft_pda,
            Account {
                lamports: 2_000_000,
                data: nft_pda_data(&portfolio, &nft_mint, 0, market_id, bump),
                owner: NFT_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    (nft_pda, nft_mint, holder_ata)
}

/// Construct a holder's collateral destination ATA (classic SPL, amount 0).
fn make_dest_ata(env: &mut CrosscutEnv, owner: Pubkey) -> Pubkey {
    let dest = Pubkey::new_unique();
    env.svm
        .set_account(
            dest,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, owner, 0),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    dest
}

fn e2_withdraw_accounts(
    env: &CrosscutEnv,
    signer: &Keypair,
    portfolio: Pubkey,
    dest: Pubkey,
    registry: Pubkey,
    nft_pda: Pubkey,
    signer_nft_ata: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(signer.pubkey(), true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(portfolio, false),
        AccountMeta::new(dest, false),
        AccountMeta::new(env.vault, false),
        AccountMeta::new_readonly(env.vault_authority, false),
        AccountMeta::new_readonly(spl_token_classic_id(), false),
        // E2 trio:
        AccountMeta::new_readonly(registry, false),
        AccountMeta::new_readonly(nft_pda, false),
        AccountMeta::new_readonly(signer_nft_ata, false),
    ]
}

#[test]
fn x0_e2_nft_holder_withdraws_escrowed_position_to_self_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let registry = env.register_nft_program();
    let (mint_auth, _) = mint_auth_pda();
    let holder = Keypair::new();
    env.svm.airdrop(&holder.pubkey(), 10_000_000_000).unwrap();

    // Fund a holder-owned portfolio, attach its bound NFT (held by the holder),
    // then ESCROW it (owner → mint-auth PDA), preserving capital.
    let portfolio = env.create_portfolio(&holder);
    let amount = 1_000u128;
    env.deposit(&holder, portfolio, amount);
    let (nft_pda, _mint, holder_nft_ata) = attach_nft_to_portfolio(&mut env, &holder, portfolio, 7);
    reown_portfolio(&mut env, portfolio, &mint_auth.to_bytes());

    // E2: the NFT HOLDER withdraws the escrowed position — funds must reach the holder.
    let dest = make_dest_ata(&mut env, holder.pubkey());
    let res = env.try_wrapper(
        ProgInstruction::Withdraw { amount },
        e2_withdraw_accounts(
            &env,
            &holder,
            portfolio,
            dest,
            registry,
            nft_pda,
            holder_nft_ata,
        ),
        &[&holder],
    );
    assert!(
        res.is_ok(),
        "NFT holder must withdraw an escrowed position: {res:?}"
    );
    assert_eq!(
        env.token_amount(dest),
        amount as u64,
        "funds routed to the HOLDER, not the escrow PDA"
    );
    assert_eq!(env.portfolio(portfolio).capital, 0, "capital withdrawn");
}

#[test]
fn x0_e2_escrowed_position_rejects_non_holder_at_mainnet() {
    let mut env = CrosscutEnv::new();
    let registry = env.register_nft_program();
    let (mint_auth, _) = mint_auth_pda();
    let holder = Keypair::new();
    env.svm.airdrop(&holder.pubkey(), 10_000_000_000).unwrap();

    let portfolio = env.create_portfolio(&holder);
    let amount = 1_000u128;
    env.deposit(&holder, portfolio, amount);
    let (nft_pda, _mint, holder_nft_ata) = attach_nft_to_portfolio(&mut env, &holder, portfolio, 7);
    reown_portfolio(&mut env, portfolio, &mint_auth.to_bytes());

    // An ATTACKER signs, passing the HOLDER's NFT ATA (holds 1, but owned by the
    // holder). Auth requires ata.owner == signer → Unauthorized (Custom(8)).
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();
    let dest = make_dest_ata(&mut env, attacker.pubkey());
    let res = env.try_wrapper(
        ProgInstruction::Withdraw { amount },
        e2_withdraw_accounts(
            &env,
            &attacker,
            portfolio,
            dest,
            registry,
            nft_pda,
            holder_nft_ata,
        ),
        &[&attacker],
    );
    let err = res.expect_err("a non-holder must NOT withdraw an escrowed position");
    assert!(
        format!("{err:?}").contains("Custom(8)"),
        "rejection must be Unauthorized (the E2 auth gate), got: {err:?}"
    );
    assert_eq!(
        env.portfolio(portfolio).capital,
        amount,
        "escrowed capital untouched"
    );
    assert_eq!(env.token_amount(dest), 0, "no funds moved to the attacker");
}
