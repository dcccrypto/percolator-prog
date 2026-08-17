// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! LP Vault CreateLpVault integration tests (Phase 2.B Tier 3, Workstream 4B — Phase C).
//!
//! LiteSVM black-box: loads the wrapper BPF + SPL Token BPF, initializes a
//! market, then exercises CreateLpVault (tag 74) — the handler that creates
//! the per-market LpVaultRegistry PDA + the LP-share SPL mint PDA (authority =
//! registry PDA, supply 0, decimals 0).
//!
//! Happy path verifies both accounts are created with the correct shape;
//! adversarial cases verify the admin gate, double-create reject, and
//! out-of-range fee_share_bps reject.
//!
//! Cross-reference: lp_vault_design.md §5/§6/§9; src/v16_program.rs
//! handle_create_lp_vault.

use litesvm::LiteSVM;
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::state::{self, derive_lp_vault_mint, derive_lp_vault_registry};
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
use spl_token::state::Mint;
use std::path::PathBuf;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing — run cargo build-sbf --no-default-features");
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
        let cand = reg.expect("entry").path().join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if cand.exists() {
            return cand;
        }
    }
    panic!("spl_token BPF not found under registry");
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

const MAX_PORTFOLIO_ASSETS: u16 = 1;

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    collateral_mint: Pubkey,
}

fn init_market_ix() -> ProgInstruction {
    ProgInstruction::InitMarket {
        max_portfolio_assets: MAX_PORTFOLIO_ASSETS,
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
    }
}

fn setup() -> Env {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(program_id, &std::fs::read(program_path()).expect("read wrapper BPF"));
    svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).expect("read token BPF"));

    let payer = Keypair::new();
    let admin = Keypair::new();
    let market = Pubkey::new_unique();
    let collateral_mint = Pubkey::new_unique();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
    svm.set_account(
        collateral_mint,
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
            data: vec![
                0u8;
                state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize).unwrap()
            ],
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    send(
        &mut svm,
        program_id,
        &payer,
        init_market_ix(),
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(collateral_mint, false),
        ],
        &[&admin],
    )
    .expect("init market");

    Env { svm, program_id, payer, admin, market, collateral_mint }
}

fn send(
    svm: &mut LiteSVM,
    program_id: Pubkey,
    payer: &Keypair,
    ix: ProgInstruction,
    accounts: Vec<AccountMeta>,
    extra_signers: &[&Keypair],
) -> Result<(), String> {
    let instruction = Instruction { program_id, accounts, data: ix.encode() };
    let mut signers = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &[
            // v16 handlers box large (~80KB) market structs on the heap.
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instruction,
        ],
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn create_lp_vault_accounts(market: Pubkey, registry: Pubkey, mint: Pubkey, admin: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(admin, true),
        // FIND-1 fix: market must be writable — CreateLpVault now writes
        // backing_bucket_authority = registry PDA into the asset's oracle
        // profile as part of vault creation.
        AccountMeta::new(market, false),
        AccountMeta::new(registry, false),
        AccountMeta::new(mint, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ]
}

fn create_lp_vault_ix(fee_share_bps: u16) -> ProgInstruction {
    ProgInstruction::CreateLpVault {
        fee_share_bps,
        redemption_cooldown_slots: 100,
        oi_reservation_threshold_bps: 0,
        domain: 0,
    }
}

#[test]
fn create_lp_vault_happy_path() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let admin = env.admin.insecure_clone();
    let accounts = create_lp_vault_accounts(env.market, registry, mint, admin.pubkey());

    send(&mut env.svm, env.program_id, &env.payer, create_lp_vault_ix(5_000), accounts, &[&admin])
        .expect("create lp vault");

    // Registry account exists with expected config.
    let reg_acct = env.svm.get_account(&registry).expect("registry account exists");
    assert_eq!(reg_acct.owner, env.program_id, "registry owned by wrapper");
    let reg = state::read_lp_vault_registry(&reg_acct.data).expect("registry decodes");
    assert_eq!(reg.market_group, env.market.to_bytes());
    assert_eq!(reg.lp_mint, mint.to_bytes());
    assert_eq!(reg.fee_share_bps, 5_000);
    assert_eq!(reg.redemption_cooldown_slots, 100);
    assert_eq!(reg.total_lp_shares_outstanding, 0);
    assert_eq!(reg.paused, 0);
    assert_eq!(reg.domain, 0);

    // LP mint exists, authority = registry PDA, supply 0, decimals 0.
    let mint_acct = env.svm.get_account(&mint).expect("mint account exists");
    assert_eq!(mint_acct.owner, spl_token::ID, "mint owned by token program");
    let m = Mint::unpack(&mint_acct.data).expect("mint decodes");
    assert_eq!(m.mint_authority, COption::Some(registry), "mint authority is registry PDA");
    assert_eq!(m.supply, 0, "fresh mint supply 0");
    assert_eq!(m.decimals, 0, "LP shares are integer atoms");
    assert_eq!(m.freeze_authority, COption::None, "no freeze authority");
    let _ = env.collateral_mint;

    // FIND-1: CreateLpVault must bind the registry PDA as the asset's
    // backing_bucket_authority directly — no separate UpdateAssetAuthority
    // co-sign step (which is unreachable from a client for a PDA target).
    let market_acct = env.svm.get_account(&env.market).expect("market account exists");
    let profile = state::read_asset_oracle_profile(&market_acct.data, 0)
        .expect("asset 0 oracle profile decodes");
    assert_eq!(
        profile.backing_bucket_authority,
        registry.to_bytes(),
        "CreateLpVault must set backing_bucket_authority = registry PDA"
    );
}

#[test]
fn create_lp_vault_rejects_non_admin() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 100_000_000_000).unwrap();
    let accounts = create_lp_vault_accounts(env.market, registry, mint, attacker.pubkey());

    let res = send(&mut env.svm, env.program_id, &env.payer, create_lp_vault_ix(5_000), accounts, &[&attacker]);
    assert!(res.is_err(), "non-admin CreateLpVault must be rejected: {res:?}");
    assert!(env.svm.get_account(&registry).map(|a| a.data.is_empty()).unwrap_or(true),
        "registry must not be created on a rejected call");
}

#[test]
fn create_lp_vault_double_create_rejected() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let admin = env.admin.insecure_clone();

    send(&mut env.svm, env.program_id, &env.payer, create_lp_vault_ix(5_000),
        create_lp_vault_accounts(env.market, registry, mint, admin.pubkey()), &[&admin])
        .expect("first create");

    let res = send(&mut env.svm, env.program_id, &env.payer, create_lp_vault_ix(5_000),
        create_lp_vault_accounts(env.market, registry, mint, admin.pubkey()), &[&admin]);
    assert!(res.is_err(), "second CreateLpVault on same market must be rejected: {res:?}");
}

#[test]
fn create_lp_vault_rejects_fee_share_above_cap() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let admin = env.admin.insecure_clone();
    let accounts = create_lp_vault_accounts(env.market, registry, mint, admin.pubkey());

    let res = send(&mut env.svm, env.program_id, &env.payer, create_lp_vault_ix(10_001), accounts, &[&admin]);
    assert!(res.is_err(), "fee_share_bps > 10_000 must be rejected: {res:?}");
}

/// Regression for #418: an unprivileged wallet can pre-fund a deterministic
/// LP-vault PDA before initialization. The wrapper must still be able to
/// initialize a System-owned, zero-data PDA that already holds lamports.
#[test]
fn create_lp_vault_succeeds_with_prefunded_registry_and_mint() {
    let mut env = setup();

    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);

    // Simulate an unrelated wallet pre-funding both deterministic PDAs.
    // Neither destination signs the transfer.
    for target in [registry, mint] {
        let ix = solana_sdk::system_instruction::transfer(
            &env.payer.pubkey(),
            &target,
            1,
        );
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&env.payer.pubkey()),
            &[&env.payer],
            env.svm.latest_blockhash(),
        );

        env.svm
            .send_transaction(tx)
            .expect("pre-fund PDA with one lamport");

        let account = env
            .svm
            .get_account(&target)
            .expect("pre-funded PDA must exist");

        assert_eq!(
            account.owner,
            solana_sdk::system_program::ID,
            "pre-funded PDA must remain System-owned"
        );
        assert!(
            account.data.is_empty(),
            "pre-funded PDA must still have zero data"
        );
        assert_eq!(
            account.lamports, 1,
            "pre-funded PDA must hold exactly one lamport"
        );
    }

    let admin = env.admin.insecure_clone();

    let result = send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        create_lp_vault_ix(5_000),
        create_lp_vault_accounts(
            env.market,
            registry,
            mint,
            admin.pubkey(),
        ),
        &[&admin],
    );

    assert!(
        result.is_ok(),
        "CreateLpVault must tolerate pre-funded System-owned zero-data PDAs: {result:?}"
    );

    // Creation must still produce the canonical account ownership.
    let registry_account = env
        .svm
        .get_account(&registry)
        .expect("registry must exist after creation");
    assert_eq!(registry_account.owner, env.program_id);

    let mint_account = env
        .svm
        .get_account(&mint)
        .expect("LP mint must exist after creation");
    assert_eq!(mint_account.owner, spl_token::ID);
}
