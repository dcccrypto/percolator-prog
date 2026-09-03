// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! LP Vault DepositToLpVault integration tests (Phase 2.B Tier 3, Workstream 4B — Phase D).
//!
//! LiteSVM black-box. Exercises DepositToLpVault (tag 75, Option A inline
//! backing top-up): NAV from ledger counters (Note 2), round-DOWN pro-rata
//! shares, reject-on-zero (Note 1), depositor-signed collateral transfer +
//! registry-signed share mint, lazily-created backing-ledger PDA.
//!
//! MANDATORY Phase-D additions (per the pass directive):
//!   1. DIFFERENTIAL TEST `lp_deposit_backing_state_matches_top_up` — the
//!      BackingDomainLedger value counters + market vault total produced by
//!      LpDeposit(amount) are identical to an equivalent TopUpBackingBucket
//!      (amount) call. Mechanical drift safety-net.
//!   3. EXPIRY OVERFLOW — `lp_deposit_twice_no_expiry_overflow` does two
//!      deposits with the u64::MAX/2 sentinel under overflow-checks=true; any
//!      `expiry_slot + N` in the backing path would panic. (Audit in
//!      lp_vault_design.md §5.5 confirms zero such arithmetic.)
//!
//! Cross-reference: lp_vault_design.md §5.5; src/v16_program.rs
//! handle_deposit_to_lp_vault (mirrors handle_top_up_backing_bucket).

use litesvm::LiteSVM;
use percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT;
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::processor::{ASSET_ACTION_ACTIVATE, ASSET_AUTH_BACKING_BUCKET};
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
        // Sibling-domain ledger: NAV spans both pots of the vault's asset.
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
#[test]
fn create_lp_vault_then_deposit_immediately_no_authority_step() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let (ledger, _) = derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN);
    let admin = env.admin.insecure_clone();

    // Activate asset 1 with backing authority = admin (NOT the registry PDA) —
    // the realistic on-chain default. No pre-set "two-step handover" workaround.
    activate(&mut env, admin.pubkey()).expect("append asset 1 with admin authority");

    // Sanity: before CreateLpVault, the profile's backing authority is admin, not
    // the (not-yet-existing) registry PDA.
    {
        let market_acct = env.svm.get_account(&env.market).unwrap();
        let profile = state::read_asset_oracle_profile(&market_acct.data, 1).unwrap();
        assert_eq!(profile.backing_bucket_authority, admin.pubkey().to_bytes());
    }

    create_lp_vault(&mut env, registry, mint);

    // CreateLpVault alone must have flipped the authority to the registry PDA.
    {
        let market_acct = env.svm.get_account(&env.market).unwrap();
        let profile = state::read_asset_oracle_profile(&market_acct.data, 1).unwrap();
        assert_eq!(
            profile.backing_bucket_authority,
            registry.to_bytes(),
            "CreateLpVault must bind registry PDA as backing_bucket_authority"
        );
    }

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

    // The deposit — with NO intervening UpdateAssetAuthority call — must succeed.
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
    .expect("deposit must succeed immediately after CreateLpVault, no separate authority step");

    assert!(
        token_amount(&env.svm, lp_ata) > 0,
        "depositor received LP shares"
    );
    assert_eq!(
        token_amount(&env.svm, env.vault_token),
        DEPOSIT as u64,
        "vault received collateral"
    );
}

#[test]
fn deposit_happy_first_mints_amount_minus_dead_shares() {
    // BUG-2 / N7: the vault's TRUE genesis deposit is no longer 1:1 — the
    // wrapper carves LP_VAULT_MINIMUM_LIQUIDITY (1_000) out of the minted
    // amount and locks it as permanently-unredeemable dead supply (mints it
    // to nobody, but still counts it in registry.total_lp_shares_outstanding).
    // See percolator-prog::constants::LP_VAULT_MINIMUM_LIQUIDITY.
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);

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
    .expect("deposit");

    const MINIMUM_LIQUIDITY: u64 = 1_000;
    let expected_minted = DEPOSIT as u64 - MINIMUM_LIQUIDITY;

    // First deposit mints amount - MINIMUM_LIQUIDITY to the depositor, NOT 1:1.
    assert_eq!(
        token_amount(&env.svm, lp_ata),
        expected_minted,
        "genesis deposit mints amount - MINIMUM_LIQUIDITY shares to the depositor"
    );
    // Collateral moved into the vault (full amount — the dead-share floor is a
    // share-accounting concept only, it doesn't reduce the collateral taken).
    assert_eq!(
        token_amount(&env.svm, env.vault_token),
        DEPOSIT as u64,
        "vault received collateral"
    );
    assert_eq!(
        token_amount(&env.svm, source),
        10_000_000 - DEPOSIT as u64,
        "source debited"
    );

    // Registry outstanding-shares counts the FULL amount (dead shares included) —
    // the mint's on-chain supply (expected_minted) is now permanently LESS than
    // registry.total_lp_shares_outstanding by MINIMUM_LIQUIDITY; that gap is the
    // dead-share lock and is intentional (never redeemable by anyone).
    let reg = state::read_lp_vault_registry(&env.svm.get_account(&registry).unwrap().data).unwrap();
    assert_eq!(
        reg.total_lp_shares_outstanding, DEPOSIT,
        "registry shares == full genesis amount (mint supply is DEPOSIT - MINIMUM_LIQUIDITY)"
    );
    let mint_acct = env.svm.get_account(&mint).unwrap();
    let m = Mint::unpack(&mint_acct.data).unwrap();
    assert_eq!(
        m.supply, expected_minted,
        "on-chain mint supply == minted amount, strictly less than registry.total_lp_shares_outstanding"
    );

    // Backing ledger recorded the FULL principal — the dead-share lock affects
    // share accounting only, never the collateral/backing side.
    let led =
        state::read_backing_domain_ledger(&env.svm.get_account(&ledger).unwrap().data).unwrap();
    assert_eq!(led.total_principal_atoms, DEPOSIT);
    assert_eq!(led.total_deposited_atoms, DEPOSIT);
}

/// BUG-2 / N7 regression: a genesis deposit at or below
/// LP_VAULT_MINIMUM_LIQUIDITY must be rejected outright (not silently mint 0
/// or underflow) — mirrors percolator-stake's
/// `DepositBelowMinimumLiquidity` guard. This closes the "first depositor
/// deposits a dust amount, then donates/inflates NAV to grief every
/// subsequent depositor" attack at its cheapest entry point: the attacker
/// can no longer become the vault's sole holder for less than
/// LP_VAULT_MINIMUM_LIQUIDITY + 1 atoms.
#[test]
fn deposit_genesis_at_or_below_minimum_liquidity_is_rejected() {
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);

    const MINIMUM_LIQUIDITY: u128 = 1_000;

    // Exactly at the floor: would carve out to 0 real shares minted while
    // still taking the depositor's collateral — must be rejected.
    let res_exact = send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: MINIMUM_LIQUIDITY,
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
    );
    assert!(
        res_exact.is_err(),
        "genesis deposit == MINIMUM_LIQUIDITY must be rejected: {res_exact:?}"
    );

    // Below the floor: checked_sub underflows — must also be rejected, not panic.
    let res_below = send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: MINIMUM_LIQUIDITY - 1,
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
    );
    assert!(
        res_below.is_err(),
        "genesis deposit < MINIMUM_LIQUIDITY must be rejected: {res_below:?}"
    );

    // No shares minted, no collateral taken, no dust left behind by the reject.
    assert_eq!(
        token_amount(&env.svm, lp_ata),
        0,
        "rejected deposit mints nothing"
    );
    assert_eq!(
        token_amount(&env.svm, source),
        10_000_000,
        "rejected deposit takes no collateral"
    );
    let reg = state::read_lp_vault_registry(&env.svm.get_account(&registry).unwrap().data).unwrap();
    assert_eq!(
        reg.total_lp_shares_outstanding, 0,
        "registry untouched by a rejected genesis deposit"
    );

    // A deposit just ABOVE the floor succeeds and mints exactly 1 real share.
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: MINIMUM_LIQUIDITY + 1,
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
    .expect("genesis deposit of MINIMUM_LIQUIDITY + 1 must succeed, minting 1 real share");
    assert_eq!(
        token_amount(&env.svm, lp_ata),
        1,
        "MINIMUM_LIQUIDITY + 1 mints exactly 1 real share"
    );
}

#[test]
fn deposit_rejects_zero_amount() {
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);
    let res = send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::DepositToLpVault {
            amount: 0,
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
    );
    assert!(res.is_err(), "zero-amount deposit must reject: {res:?}");
}

#[test]
fn deposit_succeeds_with_no_separate_authority_handover() {
    // FIND-1 fix (was "deposit_rejects_before_authority_handover" / Note 5):
    // pre-fix, CreateLpVault never wrote backing_bucket_authority, so a deposit
    // right after CreateLpVault + an admin-authority activation would fail closed
    // with LpVaultAuthorityMismatch, and there was no client-reachable way to
    // rotate it (UpdateAssetAuthority requires the new authority — a PDA — to
    // co-sign). CreateLpVault now writes backing_bucket_authority = registry PDA
    // itself, so this exact scenario (asset activated with a NON-registry backing
    // authority, then CreateLpVault, then an immediate deposit) now SUCCEEDS with
    // no separate handover step at all. See also
    // create_lp_vault_then_deposit_immediately_no_authority_step for the
    // sanity-checked, assertion-rich version of this regression test.
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let (mint, _) = derive_lp_vault_mint(&env.program_id, &env.market);
    let (ledger, _) = derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN);
    // Append asset 1 with admin (NOT registry) as the backing authority, then
    // create the vault on domain 2. CreateLpVault itself flips the authority.
    let admin_pk = env.admin.pubkey();
    activate(&mut env, admin_pk).expect("append asset 1 with admin authority");
    create_lp_vault(&mut env, registry, mint);

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

    let res = send(
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
    );
    assert!(
        res.is_ok(),
        "FIND-1: deposit must succeed with no separate authority handover: {res:?}"
    );
    assert_eq!(
        token_amount(&env.svm, env.vault_token),
        DEPOSIT as u64,
        "collateral moved on the now-successful deposit"
    );
}

#[test]
fn lp_deposit_twice_no_expiry_overflow() {
    // EXPIRY OVERFLOW guard: two deposits stamp the u64::MAX/2 sentinel on the
    // backing bucket. With overflow-checks=true, any `expiry_slot + N` in the
    // backing path would panic. Both deposits succeeding proves no such arith.
    assert_eq!(LP_VAULT_BACKING_EXPIRY_SLOT, u64::MAX / 2);
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);
    for _ in 0..2 {
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
        .expect("deposit (no expiry overflow)");
        // Fresh blockhash so the second (otherwise byte-identical) tx is not
        // rejected as AlreadyProcessed.
        env.svm.expire_blockhash();
    }
    // BUG-2 / N7: the FIRST deposit is genesis (mints DEPOSIT - MINIMUM_LIQUIDITY,
    // per the dead-share carve-out); the SECOND deposit is not genesis (total
    // shares outstanding is already nonzero), so it mints 1:1 with no carve-out.
    // Total minted == 2*DEPOSIT - MINIMUM_LIQUIDITY, not 2*DEPOSIT.
    const MINIMUM_LIQUIDITY: u64 = 1_000;
    assert_eq!(
        token_amount(&env.svm, lp_ata),
        2 * DEPOSIT as u64 - MINIMUM_LIQUIDITY
    );
    let led =
        state::read_backing_domain_ledger(&env.svm.get_account(&ledger).unwrap().data).unwrap();
    assert_eq!(led.total_principal_atoms, 2 * DEPOSIT);
}

#[test]
fn lp_deposit_backing_state_matches_top_up() {
    // DIFFERENTIAL drift safety-net: LpDeposit(amount)'s resulting
    // BackingDomainLedger value counters + market vault total are identical to
    // an equivalent TopUpBackingBucket(amount) call (same amount, same expiry
    // sentinel). If the two backing-top-up sequences ever drift, this fails.
    // Identity fields (authority, market_group — two different markets) legitimately
    // differ and are excluded from the comparison.

    // ── Path A: TopUpBackingBucket on a market whose backing authority = admin. ──
    let mut env_a = setup();
    let admin_a = env_a.admin.insecure_clone();
    activate(&mut env_a, admin_a.pubkey()).expect("activate A (admin authority)");
    // admin's source funds + a client-managed ledger account.
    let source_a = Pubkey::new_unique();
    set_token(
        &mut env_a.svm,
        source_a,
        env_a.collateral_mint,
        admin_a.pubkey(),
        10_000_000,
    );
    // #433: the ledger is now pinned to its PDA on TopUpBackingBucket too, so a random
    // address is refused. This test wants a working top-up to compare against LpDeposit,
    // not a substitution check — derive the canonical one.
    let (ledger_a, _) = state::derive_lp_backing_ledger(&env_a.program_id, &env_a.market, DOMAIN);
    env_a
        .svm
        .set_account(
            ledger_a,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; state::backing_domain_ledger_account_len()],
                owner: env_a.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    send(
        &mut env_a.svm,
        env_a.program_id,
        &env_a.payer,
        ProgInstruction::TopUpBackingBucket {
            domain: DOMAIN,
            amount: DEPOSIT,
            expiry_slot: LP_VAULT_BACKING_EXPIRY_SLOT,
        },
        vec![
            AccountMeta::new(admin_a.pubkey(), true),
            AccountMeta::new(env_a.market, false),
            AccountMeta::new(source_a, false),
            AccountMeta::new(env_a.vault_token, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(ledger_a, false),
            // #433: TopUpBackingBucket now creates the ledger PDA when absent, so it takes
            // the system program. Here the ledger already exists, so creation is skipped.
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&admin_a],
    )
    .expect("top up backing bucket");
    let led_a =
        state::read_backing_domain_ledger(&env_a.svm.get_account(&ledger_a).unwrap().data).unwrap();
    let (_, group_a) =
        state::read_market(&env_a.svm.get_account(&env_a.market).unwrap().data).unwrap();
    let vault_a = group_a.vault;

    // ── Path B: LpDeposit on a vault whose backing authority = registry PDA. ──
    let mut env_b = setup();
    let (registry_b, mint_b, ledger_b, depositor_b, lp_ata_b, source_b) = ready_vault(&mut env_b);
    send(
        &mut env_b.svm,
        env_b.program_id,
        &env_b.payer,
        ProgInstruction::DepositToLpVault {
            amount: DEPOSIT,
            domain: DOMAIN,
        },
        deposit_accounts(
            env_b.market,
            env_b.vault_token,
            registry_b,
            mint_b,
            lp_ata_b,
            source_b,
            ledger_b,
            depositor_b.pubkey(),
        ),
        &[&depositor_b],
    )
    .expect("lp deposit");
    let led_b =
        state::read_backing_domain_ledger(&env_b.svm.get_account(&ledger_b).unwrap().data).unwrap();
    let (_, group_b) =
        state::read_market(&env_b.svm.get_account(&env_b.market).unwrap().data).unwrap();
    let vault_b = group_b.vault;

    // Value counters identical (drift detector).
    assert_eq!(
        led_a.total_principal_atoms, led_b.total_principal_atoms,
        "principal drift"
    );
    assert_eq!(
        led_a.total_deposited_atoms, led_b.total_deposited_atoms,
        "deposited drift"
    );
    assert_eq!(
        led_a.total_principal_withdrawn_atoms,
        led_b.total_principal_withdrawn_atoms
    );
    assert_eq!(
        led_a.total_earnings_atoms, led_b.total_earnings_atoms,
        "earnings drift"
    );
    assert_eq!(
        led_a.total_earnings_withdrawn_atoms,
        led_b.total_earnings_withdrawn_atoms
    );
    assert_eq!(
        led_a.cumulative_loss_atoms, led_b.cumulative_loss_atoms,
        "loss drift"
    );
    assert_eq!(
        led_a.cumulative_recovery_atoms, led_b.cumulative_recovery_atoms,
        "recovery drift"
    );
    assert_eq!(
        led_a.last_observed_bucket_earnings_atoms,
        led_b.last_observed_bucket_earnings_atoms
    );
    assert_eq!(
        led_a.last_observed_unavailable_principal_atoms,
        led_b.last_observed_unavailable_principal_atoms
    );
    assert_eq!(led_a.domain, led_b.domain, "domain");
    // Market vault total identical (the backing-bucket collateral effect).
    assert_eq!(
        vault_a, vault_b,
        "market vault total drift between TopUp and LpDeposit"
    );
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

/// Attempt to rotate an asset's backing-bucket authority. `registry` is the
/// optional 4th account the guard consults; `None` omits it.
fn try_rotate_backing_authority(
    env: &mut Env,
    asset_index: u16,
    signer: &Keypair,
    new_authority: &Keypair,
    registry: Option<Pubkey>,
) -> Result<(), String> {
    let mut accounts = vec![
        AccountMeta::new(signer.pubkey(), true),
        AccountMeta::new_readonly(new_authority.pubkey(), true),
        AccountMeta::new(env.market, false),
    ];
    if let Some(registry) = registry {
        accounts.push(AccountMeta::new_readonly(registry, false));
    }
    let mut signers: Vec<&Keypair> = vec![signer];
    if new_authority.pubkey() != signer.pubkey() {
        signers.push(new_authority);
    }
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::UpdateAssetAuthority {
            asset_index,
            kind: ASSET_AUTH_BACKING_BUCKET,
            new_pubkey: new_authority.pubkey().to_bytes(),
        },
        accounts,
        &signers,
    )
}

fn backing_authority_of(env: &Env, asset_index: usize) -> [u8; 32] {
    let market_acct = env.svm.get_account(&env.market).unwrap();
    state::read_asset_oracle_profile(&market_acct.data, asset_index)
        .unwrap()
        .backing_bucket_authority
}

/// An LP vault's custody rests on `backing_bucket_authority == registry_pda`.
/// `handle_update_asset_authority`'s `admin_signed` branch skips the current-holder
/// check, and the registry PDA can never co-sign to defend itself, so without the
/// guard the asset's `asset_admin` could rotate the authority to itself and
/// withdraw every depositor's principal via WithdrawBackingBucket.
///
/// Omitting the registry account must NOT be a way around the guard.
#[test]
fn live_lp_vault_backing_authority_cannot_be_rotated_by_asset_admin() {
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);
    let admin = env.admin.insecure_clone();

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
    .expect("deposit");
    assert_eq!(token_amount(&env.svm, env.vault_token), DEPOSIT as u64);
    assert_eq!(
        backing_authority_of(&env, APPEND_ASSET_INDEX as usize),
        registry.to_bytes()
    );

    let attacker = Keypair::new();
    env.svm
        .airdrop(&attacker.pubkey(), 100_000_000_000)
        .unwrap();

    // With the registry account supplied, the guard sees a live vault and refuses.
    try_rotate_backing_authority(
        &mut env,
        APPEND_ASSET_INDEX,
        &admin,
        &attacker,
        Some(registry),
    )
    .expect_err("rotation away from a live LP vault must be rejected");

    // Omitting it must also fail — the guard rejects on absence rather than
    // skipping, so it cannot be sidestepped by sending fewer accounts.
    try_rotate_backing_authority(&mut env, APPEND_ASSET_INDEX, &admin, &attacker, None)
        .expect_err("omitting the registry account must not bypass the guard");

    assert_eq!(
        backing_authority_of(&env, APPEND_ASSET_INDEX as usize),
        registry.to_bytes(),
        "authority unchanged"
    );
    assert_eq!(
        token_amount(&env.svm, env.vault_token),
        DEPOSIT as u64,
        "depositor principal untouched"
    );
}

/// Same guard, exercised through the delegated role rather than the market
/// authority: `asset_admin` is per-asset and can be handed to a third party, who
/// would otherwise be able to seize the vault with no marketauth signature.
#[test]
fn delegated_asset_admin_cannot_rotate_a_live_lp_vault_backing_authority() {
    let mut env = setup();
    let (registry, mint, ledger, depositor, lp_ata, source) = ready_vault(&mut env);
    let admin = env.admin.insecure_clone();

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
    .expect("deposit");

    let manager = Keypair::new();
    env.svm.airdrop(&manager.pubkey(), 100_000_000_000).unwrap();
    send(
        &mut env.svm,
        env.program_id,
        &env.payer,
        ProgInstruction::UpdateAssetAuthority {
            asset_index: APPEND_ASSET_INDEX,
            kind: percolator_prog::processor::ASSET_AUTH_ADMIN,
            new_pubkey: manager.pubkey().to_bytes(),
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(manager.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin, &manager],
    )
    .expect("delegate asset_admin");

    try_rotate_backing_authority(
        &mut env,
        APPEND_ASSET_INDEX,
        &manager,
        &manager,
        Some(registry),
    )
    .expect_err("delegated asset_admin must not seize a live vault's backing authority");

    assert_eq!(
        backing_authority_of(&env, APPEND_ASSET_INDEX as usize),
        registry.to_bytes()
    );
    assert_eq!(token_amount(&env.svm, env.vault_token), DEPOSIT as u64);
}

/// The guard must key on a LIVE vault, not on the address alone. A lifecycle
/// activation can plant the registry PDA verbatim with no co-signature, and
/// CloseLpVault zeroes the registry while leaving the mint on-chain (so
/// CreateLpVault can never re-run). If the guard welded the value permanently,
/// the bucket could never be re-pointed at a signable key — stranding the
/// dead-share floor's backing residue and, with it, CloseSlab, which requires
/// `header.vault == 0`. With no initialised registry, rotation must be allowed.
#[test]
fn backing_authority_rotation_is_allowed_when_no_lp_vault_registry_exists() {
    let mut env = setup();
    let (registry, _) = derive_lp_vault_registry(&env.program_id, &env.market);
    let admin = env.admin.insecure_clone();

    // Activate the asset with the registry PDA as its backing authority, but
    // never create the vault — the registry account stays uninitialised.
    activate(&mut env, registry).expect("append asset 1 with registry authority");
    assert_eq!(
        backing_authority_of(&env, APPEND_ASSET_INDEX as usize),
        registry.to_bytes()
    );

    let rescue = Keypair::new();
    env.svm.airdrop(&rescue.pubkey(), 100_000_000_000).unwrap();
    try_rotate_backing_authority(
        &mut env,
        APPEND_ASSET_INDEX,
        &admin,
        &rescue,
        Some(registry),
    )
    .expect("rotation must remain possible when no LP vault is bound");

    assert_eq!(
        backing_authority_of(&env, APPEND_ASSET_INDEX as usize),
        rescue.pubkey().to_bytes(),
        "authority re-pointed at a signable key"
    );
}
