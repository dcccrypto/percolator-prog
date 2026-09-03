// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! LP Vault DUAL-DOMAIN tests (v17).
//!
//! The LP vault is welded to ONE domain at CreateLpVault (`registry.domain`),
//! but the house takes whichever side traders leave it and draws its gains from
//! the OPPOSITE domain. spec.md L410 requires refill be "source-domain local",
//! so the vault must be able to reach BOTH domains of its asset.
//!
//! `backing_bucket_authority` is stored PER ASSET, so the registry PDA is
//! already authorised for both domains; only the hardcoded
//! `let domain = registry.domain` blocks it.

use litesvm::LiteSVM;
use percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT;
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::processor::ASSET_ACTION_ACTIVATE;
use percolator_prog::state::{
    self, derive_lp_backing_ledger, derive_lp_vault_mint, derive_lp_vault_registry,
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

const MAX_PORTFOLIO_ASSETS: u16 = 1;
// Asset 0 is the base asset (active at init, authority = admin). Following the
// v16_cu.rs pattern, we APPEND asset 1 via UpdateAssetLifecycle and bind the LP
// vault to its long-side domain (asset_index 1 → domain 1*2+0 = 2). This lets
// us set the backing authority to the registry PDA at append time.
const APPEND_ASSET_INDEX: u16 = 1;
const DOMAIN: u16 = 2;
const DEPOSIT: u128 = 1_000_000;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(
        p.exists(),
        "wrapper BPF missing — cargo build-sbf --no-default-features"
    );
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

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    collateral_mint: Pubkey,
    vault_token: Pubkey,
}

fn set_token(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    svm.set_account(
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
}

fn send(
    svm: &mut LiteSVM,
    program_id: Pubkey,
    payer: &Keypair,
    ix: ProgInstruction,
    accounts: Vec<AccountMeta>,
    extra: &[&Keypair],
) -> Result<(), String> {
    let instruction = Instruction {
        program_id,
        accounts,
        data: ix.encode(),
    };
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
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
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
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

/// Append asset 1 (asset_index == configured_slots == 1) with the given backing
/// authority. admin is the cfg.asset_authority (init default) so the append is
/// fee-free. configured_slots grows 1 → 2, enabling domain 2.
fn activate_asset_ix(backing_authority: Pubkey, admin: Pubkey) -> ProgInstruction {
    ProgInstruction::UpdateAssetLifecycle {
        action: ASSET_ACTION_ACTIVATE,
        asset_index: APPEND_ASSET_INDEX,
        now_slot: 1,
        initial_price: 100,
        insurance_authority: admin.to_bytes(),
        insurance_operator: admin.to_bytes(),
        backing_bucket_authority: backing_authority.to_bytes(),
        oracle_authority: admin.to_bytes(),
    }
}

/// Fresh market + collateral mint + program vault token account. Asset not yet
/// activated (caller activates with the chosen backing authority).
fn setup() -> Env {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(
        program_id,
        &std::fs::read(program_path()).expect("wrapper BPF"),
    );
    svm.add_program(
        spl_token::ID,
        &std::fs::read(spl_token_program_path()).expect("token BPF"),
    );

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
                state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize)
                    .unwrap()
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

    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
    let vault_token = canonical_vault_ata(&vault_authority, &collateral_mint);
    set_token(&mut svm, vault_token, collateral_mint, vault_authority, 0);

    Env {
        svm,
        program_id,
        payer,
        admin,
        market,
        collateral_mint,
        vault_token,
    }
}

fn create_lp_vault(env: &mut Env, registry: Pubkey, mint: Pubkey) {
    let admin = env.admin.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::CreateLpVault {
            fee_share_bps: 5_000,
            redemption_cooldown_slots: 100,
            oi_reservation_threshold_bps: 0,
            domain: DOMAIN,
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(registry, false),
            AccountMeta::new(mint, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&admin],
    )
    .expect("create lp vault");
}

fn activate(env: &mut Env, backing_authority: Pubkey) -> Result<(), String> {
    let admin = env.admin.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        activate_asset_ix(backing_authority, admin.pubkey()),
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    )
}

#[allow(clippy::too_many_arguments)]
fn deposit_accounts(
    market: Pubkey,
    vault_token: Pubkey,
    registry: Pubkey,
    mint: Pubkey,
    lp_ata: Pubkey,
    source: Pubkey,
    ledger: Pubkey,
    depositor: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(depositor, true),
        AccountMeta::new(market, false),
        AccountMeta::new(registry, false),
        AccountMeta::new(mint, false),
        AccountMeta::new(lp_ata, false),
        AccountMeta::new(source, false),
        AccountMeta::new(vault_token, false),
        AccountMeta::new(ledger, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(
            derive_lp_backing_ledger(&percolator_prog::id(), &market, DOMAIN ^ 1).0,
            false,
        ),
    ]
}

/// Build a fully-set-up LP vault (created + activated with registry authority)
/// + a funded depositor. Returns (registry, mint, ledger, depositor, lp_ata, source).
fn ready_vault(env: &mut Env) -> (Pubkey, Pubkey, Pubkey, Keypair, Pubkey, Pubkey) {
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let (ledger, _) = derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN);
    // Append asset 1 with the registry PDA as its backing authority FIRST so
    // configured_slots == 2 (domain 2 valid), then create the vault on domain 2.
    activate(env, registry).expect("append asset 1 with registry authority");
    create_lp_vault(env, registry, mint);

    let depositor = Keypair::new();
    env.svm
        .airdrop(&depositor.pubkey(), 100_000_000_000)
        .unwrap();
    let source = Pubkey::new_unique();
    set_token(
        &mut env.svm,
        source,
        env.collateral_mint,
        depositor.pubkey(),
        10_000_000,
    );
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, mint, depositor.pubkey(), 0);
    (registry, mint, ledger, depositor, lp_ata, source)
}

fn token_amount(svm: &LiteSVM, key: Pubkey) -> u64 {
    let acct = svm.get_account(&key).expect("token account");
    TokenAccount::unpack(&acct.data)
        .expect("token decode")
        .amount
}

/// FIND-1 regression test: DepositToLpVault must succeed immediately after
/// CreateLpVault with NO separate authority-handover step. Before the fix,
/// `handle_create_lp_vault` never wrote `backing_bucket_authority`, so the
/// asset's authority stayed whatever it was set to at activation (here,
/// deliberately the admin's own key — the realistic default, NOT the
/// registry PDA) and DepositToLpVault failed with LpVaultAuthorityMismatch.
/// The only other way to rotate it (UpdateAssetAuthority, tag 65) requires
/// the NEW authority to co-sign, which is impossible for a PDA from a
/// client. This test proves CreateLpVault alone now completes the wiring.

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

/// Sibling domain of the vault's own domain, within the SAME asset.
/// DOMAIN = 2 (asset 1, long) => sibling = 3 (asset 1, short).
const SIBLING_DOMAIN: u16 = DOMAIN + 1;

fn bucket_fresh(svm: &LiteSVM, market: Pubkey, domain: u16) -> u128 {
    let acct = svm.get_account(&market).expect("market");
    let (_cfg, group) = state::read_market(&acct.data).expect("read market");
    group.source_backing_buckets[domain as usize].fresh_unliened_backing_num
}

fn ledger_principal(svm: &LiteSVM, ledger: Pubkey) -> u128 {
    match svm.get_account(&ledger) {
        Some(a) if !a.data.is_empty() => {
            state::read_backing_domain_ledger(&a.data)
                .expect("ledger")
                .total_principal_atoms
        }
        _ => 0,
    }
}

/// RED: idle backing must be movable from the vault's domain to its sibling.
/// Today nothing can do this: `TopUpBackingBucket` is gated on the registry PDA
/// (which cannot sign from a client) and `DepositToLpVault` hardcodes
/// `registry.domain`. Without it, a house sitting on the sibling side can never
/// be funded.
#[test]
fn rebalance_moves_idle_backing_to_sibling_domain() {
    let mut env = setup();
    let (registry, _mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);
    let (sibling_ledger, _) =
        derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);

    // Fund the vault's own domain.
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: DOMAIN,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            _mint,
            lp_ata,
            source,
            ledger,
            depositor.pubkey(),
        ),
        &[&depositor],
    )
    .expect("seed deposit");

    let from_before = bucket_fresh(&env.svm, env.market, DOMAIN);
    let to_before = bucket_fresh(&env.svm, env.market, SIBLING_DOMAIN);
    assert!(from_before > 0, "precondition: vault domain funded");
    assert_eq!(to_before, 0, "precondition: sibling domain empty");

    let move_atoms = DEPOSIT / 2;
    let cranker = Keypair::new();
    env.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();

    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::RebalanceLpVaultBacking {
            from_domain: DOMAIN,
            to_domain: SIBLING_DOMAIN,
            amount: move_atoms,
        },
        vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(registry, false),
            AccountMeta::new(ledger, false),
            AccountMeta::new(sibling_ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&cranker],
    )
    .expect("rebalance idle backing to the sibling domain");

    let moved_num = move_atoms * percolator::BOUND_SCALE;
    assert_eq!(
        bucket_fresh(&env.svm, env.market, DOMAIN),
        from_before - moved_num,
        "source domain must give up exactly the moved backing"
    );
    assert_eq!(
        bucket_fresh(&env.svm, env.market, SIBLING_DOMAIN),
        to_before + moved_num,
        "sibling domain must receive exactly the moved backing"
    );
    // Ledger principal must move in lockstep or NAV desyncs from the buckets.
    assert_eq!(
        ledger_principal(&env.svm, ledger) + ledger_principal(&env.svm, sibling_ledger),
        DEPOSIT,
        "total ledger principal is conserved across the move"
    );
    assert_eq!(
        ledger_principal(&env.svm, sibling_ledger),
        move_atoms,
        "sibling ledger records the principal it now holds"
    );
}

/// Move backing from the vault's domain into `valid_liened_backing_num`, i.e.
/// pledged against real OI. Mirrors `set_bucket_oi_lien_for_test` in
/// tests/v16_five_program_crosscut.rs. Total bucket backing is unchanged so
/// header aggregates stay in lockstep.
fn lien_backing(env: &mut Env, domain: u16, lien_num: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    let b = &mut group.source_backing_buckets[domain as usize];
    b.fresh_unliened_backing_num = b
        .fresh_unliened_backing_num
        .checked_sub(lien_num)
        .expect("enough idle backing");
    b.valid_liened_backing_num = b.valid_liened_backing_num.checked_add(lien_num).unwrap();
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

fn seeded_vault(env: &mut Env) -> (Pubkey, Pubkey, Pubkey, Keypair) {
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(env);
    let (sibling_ledger, _) =
        derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: DOMAIN,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            mint,
            lp_ata,
            source,
            ledger,
            depositor.pubkey(),
        ),
        &[&depositor],
    )
    .expect("seed deposit");
    let cranker = Keypair::new();
    env.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    (registry, ledger, sibling_ledger, cranker)
}

fn try_rebalance(
    env: &mut Env,
    registry: Pubkey,
    from_ledger: Pubkey,
    to_ledger: Pubkey,
    cranker: &Keypair,
    from_domain: u16,
    to_domain: u16,
    amount: u128,
) -> Result<(), String> {
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::RebalanceLpVaultBacking {
            from_domain,
            to_domain,
            amount,
        },
        vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(registry, false),
            AccountMeta::new(from_ledger, false),
            AccountMeta::new(to_ledger, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[cranker],
    )
}

/// SAFETY: backing pledged against real OI is NOT idle and must not be movable.
/// Without this the vault could strip collateral out from under live exposure.
#[test]
fn rebalance_cannot_move_liened_backing() {
    let mut env = setup();
    let (registry, ledger, sibling_ledger, cranker) = seeded_vault(&mut env);
    // Pledge ALL but a quarter of the idle backing against OI.
    let idle = bucket_fresh(&env.svm, env.market, DOMAIN);
    lien_backing(&mut env, DOMAIN, idle - idle / 4);

    // Asking for half the original deposit now exceeds what is still idle.
    let err = try_rebalance(
        &mut env,
        registry,
        ledger,
        sibling_ledger,
        &cranker,
        DOMAIN,
        SIBLING_DOMAIN,
        DEPOSIT / 2,
    )
    .expect_err("must refuse to move liened backing");
    assert!(
        err.contains("Custom"),
        "expected a program error, got {err}"
    );
    assert_eq!(
        bucket_fresh(&env.svm, env.market, SIBLING_DOMAIN),
        0,
        "sibling must receive nothing on a rejected move"
    );
}

/// The per-asset `backing_bucket_authority` only authorises this vault over its
/// OWN asset. Domain 0/1 belong to asset 0, which this vault does not own.
#[test]
fn rebalance_cannot_cross_into_another_asset() {
    let mut env = setup();
    let (registry, ledger, _sibling, cranker) = seeded_vault(&mut env);
    let (foreign_ledger, _) = derive_lp_backing_ledger(&env.program_id, &env.market, 0);
    let err = try_rebalance(
        &mut env,
        registry,
        ledger,
        foreign_ledger,
        &cranker,
        DOMAIN,
        0,
        DEPOSIT / 2,
    )
    .expect_err("must refuse to move backing into another asset");
    assert!(
        err.contains("Custom"),
        "expected a program error, got {err}"
    );
    assert_eq!(
        bucket_fresh(&env.svm, env.market, 0),
        0,
        "foreign asset must receive nothing"
    );
}

/// Over-withdrawal must fail closed rather than underflow.
#[test]
fn rebalance_cannot_move_more_than_is_there() {
    let mut env = setup();
    let (registry, ledger, sibling_ledger, cranker) = seeded_vault(&mut env);
    let err = try_rebalance(
        &mut env,
        registry,
        ledger,
        sibling_ledger,
        &cranker,
        DOMAIN,
        SIBLING_DOMAIN,
        DEPOSIT * 10,
    )
    .expect_err("must refuse to move more backing than the domain holds");
    assert!(
        err.contains("Custom"),
        "expected a program error, got {err}"
    );
}

/// A full move must leave the source domain empty and the sibling holding
/// everything, with total ledger principal conserved.
#[test]
fn rebalance_full_move_conserves_total_principal() {
    let mut env = setup();
    let (registry, ledger, sibling_ledger, cranker) = seeded_vault(&mut env);
    let before = bucket_fresh(&env.svm, env.market, DOMAIN);
    try_rebalance(
        &mut env,
        registry,
        ledger,
        sibling_ledger,
        &cranker,
        DOMAIN,
        SIBLING_DOMAIN,
        DEPOSIT,
    )
    .expect("full move of idle backing");
    assert_eq!(bucket_fresh(&env.svm, env.market, DOMAIN), 0);
    assert_eq!(bucket_fresh(&env.svm, env.market, SIBLING_DOMAIN), before);
    assert_eq!(ledger_principal(&env.svm, ledger), 0);
    assert_eq!(ledger_principal(&env.svm, sibling_ledger), DEPOSIT);
}

/// Second depositor with their own funded source + LP ATA.
fn new_depositor(env: &mut Env, mint: Pubkey) -> (Keypair, Pubkey, Pubkey) {
    let d = Keypair::new();
    env.svm.airdrop(&d.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(
        &mut env.svm,
        source,
        env.collateral_mint,
        d.pubkey(),
        10_000_000,
    );
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, mint, d.pubkey(), 0);
    (d, source, lp_ata)
}

/// RED: NAV must span BOTH domains of the vault.
///
/// Depositor 1 puts in DEPOSIT, so total_shares == DEPOSIT and NAV == DEPOSIT.
/// A rebalance then moves half the backing to the sibling domain. NAV is
/// UNCHANGED — the vault still holds DEPOSIT, just spread over two pots — so
/// depositor 2 putting in the same DEPOSIT must receive the same DEPOSIT shares.
///
/// If NAV is read from `registry.domain`'s ledger alone it now reads DEPOSIT/2,
/// and depositor 2 is minted ~2x the shares they paid for, diluting depositor 1.
#[test]
fn deposit_prices_shares_off_combined_nav_after_rebalance() {
    let mut env = setup();
    let (registry, mint, ledger, d1, lp_ata1, source1) = ready_vault(&mut env);
    let (sibling_ledger, _) =
        derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);

    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: DOMAIN,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            mint,
            lp_ata1,
            source1,
            ledger,
            d1.pubkey(),
        ),
        &[&d1],
    )
    .expect("depositor 1");
    let shares1 = token_amount(&env.svm, lp_ata1) as u128;
    assert!(shares1 > 0, "depositor 1 minted");

    let cranker = Keypair::new();
    env.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    try_rebalance(
        &mut env,
        registry,
        ledger,
        sibling_ledger,
        &cranker,
        DOMAIN,
        SIBLING_DOMAIN,
        DEPOSIT / 2,
    )
    .expect("move half the backing to the sibling pot");

    let (d2, source2, lp_ata2) = new_depositor(&mut env, mint);
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: DOMAIN,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            mint,
            lp_ata2,
            source2,
            ledger,
            d2.pubkey(),
        ),
        &[&d2],
    )
    .expect("depositor 2");
    let shares2 = token_amount(&env.svm, lp_ata2) as u128;

    // Equal money in, equal ownership out. Depositor 1 paid the one-off dead-share
    // floor at genesis, so allow exactly that much slack and no more.
    let floor = percolator_prog::constants::LP_VAULT_MINIMUM_LIQUIDITY;
    assert!(
        shares2 <= shares1 + floor,
        "depositor 2 got {shares2} shares for the same {DEPOSIT} atoms depositor 1 paid \
         {shares1} for — NAV is not counting the sibling pot, so depositor 1 is diluted"
    );
}

/// RED: a deposit must be routable to EITHER pot of the vault's asset.
///
/// Without this, new money can only ever reach `registry.domain`. A house
/// sitting on the sibling side is then permanently unfundable through the
/// product's own flow, which is the whole defect. Shares are still priced off
/// combined NAV, so the depositor is indifferent to which pot they land in.
#[test]
fn deposit_can_be_routed_to_the_sibling_domain() {
    let mut env = setup();
    let (registry, mint, ledger, d1, lp_ata1, source1) = ready_vault(&mut env);
    let (sibling_ledger, _) =
        derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);

    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: SIBLING_DOMAIN,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            mint,
            lp_ata1,
            source1,
            ledger,
            d1.pubkey(),
        ),
        &[&d1],
    )
    .expect("deposit routed to the sibling pot");

    assert_eq!(
        bucket_fresh(&env.svm, env.market, DOMAIN),
        0,
        "the vault's own pot must be untouched"
    );
    assert_eq!(
        bucket_fresh(&env.svm, env.market, SIBLING_DOMAIN),
        DEPOSIT * percolator::BOUND_SCALE,
        "the sibling pot must hold the whole deposit"
    );
    assert_eq!(
        ledger_principal(&env.svm, ledger),
        0,
        "own ledger untouched"
    );
    assert_eq!(
        ledger_principal(&env.svm, sibling_ledger),
        DEPOSIT,
        "sibling ledger records the principal"
    );
    assert!(token_amount(&env.svm, lp_ata1) > 0, "shares still minted");
}

/// A deposit may only target the vault's OWN asset.
#[test]
fn deposit_cannot_be_routed_into_another_asset() {
    let mut env = setup();
    let (registry, mint, ledger, d1, lp_ata1, source1) = ready_vault(&mut env);
    let err = send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: 0,
        },
        deposit_accounts(
            env.market,
            env.vault_token,
            registry,
            mint,
            lp_ata1,
            source1,
            ledger,
            d1.pubkey(),
        ),
        &[&d1],
    )
    .expect_err("must refuse a deposit aimed at another asset");
    // Pin the SAME-ASSET guard specifically (InvalidInstruction = Custom(9)).
    // Asserting only "some error" passes even with the guard deleted, because the
    // per-asset authority check then rejects it instead — real defence in depth,
    // but it makes the test blind to the thing it claims to cover.
    assert!(
        err.contains("Custom(9)"),
        "expected InvalidInstruction from the same-asset guard, got {err}"
    );
    assert_eq!(
        bucket_fresh(&env.svm, env.market, 0),
        0,
        "foreign asset unfunded"
    );
}
