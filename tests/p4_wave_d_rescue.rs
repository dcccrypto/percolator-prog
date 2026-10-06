// Phase 4 Wave D item 5 (rescue / recapitalisation), NON-BOUND vaults.
// Harness COPIED UNCHANGED from tests/sec_r1_impairment_pause.rs lines 1-788 (its R-1 impaired-vault
// fixtures are exactly the state a rescue exists for); new tests at the end of this file.
// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
#![allow(dead_code)]
//! Security review of bc228e1b (2026-10-03), required items R-1 and N-1.
//!
//! R-1 (MEDIUM): the 1000x share-price-collapse factor bounded only the ticket price of a
//! NON-bound Earn deposit (tag 75), not the recovery pool it buys into. NAV prices every
//! provider receivable at zero, so a deposit at vault impairment ratio `r` buys a discounted
//! slice of every later recovery: a windfall of up to `r / (1 - r)` per token, paid by the
//! incumbents (reviewer: 2 tokens bought +998 tokens at the collapse threshold). Fix: tag 75 is
//! refused (Custom 91) when
//!     Σ_pot min(loss - recovery, principal) * 10_000 > LP_VAULT_MAX_DEPOSIT_IMPAIRMENT_BPS * Σ_pot principal
//! on the two synced pot ledgers (vault-total ratio; default 1_000 = 10%). Exactly 10% is
//! accepted, one atom more is refused. Tag 77 is never gated by it.
//!
//! N-1 (LOW-MEDIUM): `lp_vault_nav_atoms_floored` inlined into tag 77 produced 55 SBF
//! "overwrites values in the frame" warnings; it is now `#[inline(never)]`. The tag 77 nav_post
//! OI-reservation gate (live config: oi_reservation_threshold_bps = 8000, non-zero earnings,
//! loss and recovery) is pinned here to its analytic boundary, so the same test is a
//! differential between builds (`PERC_PROG_SO`).
//!
//! Harness copied from tests/sec_final_low_nav.rs. `PERC_PROG_SO` overrides the program bytes,
//! so the same tests run as negative controls against other builds (e.g. bc228e1b, which has
//! no R-1 pause: the capture sweep then shows the large windfall).

use litesvm::LiteSVM;
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::processor::ASSET_ACTION_ACTIVATE;
use percolator_prog::state::{
    self, derive_lp_backing_ledger, derive_lp_escrow, derive_lp_redemption, derive_lp_vault_mint,
    derive_lp_vault_registry,
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
const COOLDOWN: u64 = 5;
const BOUND_SCALE: u128 = percolator::BOUND_SCALE;

thread_local! {
    /// `oi_reservation_threshold_bps` for vaults created on this test thread (default 0, as in
    /// sec_final_low_nav.rs; the N-1 differential sets the live 8000).
    static OI_BPS: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

fn program_path() -> PathBuf {
    if let Some(o) = std::env::var_os("PERC_PROG_SO") {
        return PathBuf::from(o);
    }
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
        .map(|m| {
            if std::env::var_os("SEC_CU").is_some() {
                eprintln!("SEC_CU {}", m.compute_units_consumed);
            }
        })
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
        market_id: 2,
        action: ASSET_ACTION_ACTIVATE,
        asset_index: APPEND_ASSET_INDEX,
        // W3A-2: this file's only `UpdateAssetAuthority` mention is a doc
        // comment, not a call -- asset-0's authority_epoch stays at its genesis
        // value (0) here. The correct LIVE value, not a hardcode.
        authority_epoch: 0,
        now_slot: 1,
        initial_price: 100,
        max_init_fee: u128::MAX,
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
            redemption_cooldown_slots: COOLDOWN,
            oi_reservation_threshold_bps: OI_BPS.with(|c| c.get()),
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
        100_000_000_000,
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

fn ledger_of(svm: &LiteSVM, ledger: Pubkey) -> state::BackingDomainLedgerAccountV16 {
    state::read_backing_domain_ledger(&svm.get_account(&ledger).expect("ledger").data)
        .expect("ledger decode")
}

fn with_market(env: &mut Env, f: impl FnOnce(&mut state::MarketGroupV16)) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    f(&mut group);
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

fn market_group(env: &Env) -> state::MarketGroupV16 {
    state::read_market(&env.svm.get_account(&env.market).unwrap().data)
        .unwrap()
        .1
}

/// PHYSICAL consumption (E3, 2026-10-05): `atoms` of pot `domain`'s backing paid a winner who
/// withdrew them (fresh -> consumed lien / provider receivable; the atoms left the vault). If
/// the pot's fresh backing is short, the excess is first ROUTED in (a loser's settled loss
/// landing in the pot) and consumed with it: the only physical way a pot's booked loss can
/// exceed its principal. (This fixture used to book the receivable with fresh untouched -- a
/// physically whole pot, the I-2 shape E3 rightly prices as unimpaired.)
fn consume_pot_backing(env: &mut Env, domain: u16, atoms: u128) {
    let fresh = market_group(env).source_backing_buckets[domain as usize].fresh_unliened_backing_num
        / BOUND_SCALE;
    let routed = atoms.saturating_sub(fresh);
    with_market(env, |g| {
        let (r, n) = (routed * BOUND_SCALE, atoms * BOUND_SCALE);
        let b = &mut g.source_backing_buckets[domain as usize];
        b.fresh_unliened_backing_num = b.fresh_unliened_backing_num + r - n;
        b.consumed_liened_backing_num += n;
        // The program's own rule when a pot's idle backing hits zero (77 / draw decrement).
        if b.fresh_unliened_backing_num == 0 && b.valid_liened_backing_num == 0 {
            b.status = if b.impaired_liened_backing_num != 0 {
                percolator::BackingBucketStatusV16::Impaired
            } else {
                percolator::BackingBucketStatusV16::Expired
            };
        }
        let s = &mut g.source_credit[domain as usize];
        s.fresh_reserved_backing_num = s.fresh_reserved_backing_num + r - n;
        s.spent_backing_num += n;
        s.provider_receivable_num += n;
        g.source_fresh_backing_total_num = g.source_fresh_backing_total_num + r - n;
        g.vault = g.vault + routed - atoms;
    });
    let bal = token_amount(&env.svm, env.vault_token) as u128;
    let (mint, va) = (env.collateral_mint, vault_authority(env));
    set_token(&mut env.svm, env.vault_token, mint, va, (bal + routed - atoms) as u64);
}

/// A live winner claim of `atoms` registered against pot `domain` (live: source d0
/// positive_claim_bound 0.596957). The pot must stay fully backed for it.
fn add_winner_claim(env: &mut Env, domain: u16, atoms: u128) {
    with_market(env, |g| {
        let num = atoms * BOUND_SCALE;
        g.source_credit[domain as usize].positive_claim_bound_num += num;
        g.source_claim_bound_total_num += num;
        // Engine aggregate: the group junior-claim bound never understates the source claims.
        g.pnl_pos_bound_tot_num += num;
        g.pnl_pos_bound_tot = g.pnl_pos_bound_tot_num / BOUND_SCALE;
    });
}

/// Gross utilization-fee earnings collected into pot `domain` (they physically sit in the vault).
fn add_pot_earnings(env: &mut Env, domain: u16, atoms: u128) {
    with_market(env, |g| {
        g.source_backing_buckets[domain as usize].utilization_fee_earnings += atoms;
        g.backing_provider_earnings_total += atoms;
        g.vault += atoms;
    });
    let bal = token_amount(&env.svm, env.vault_token);
    let (mint, va) = (env.collateral_mint, vault_authority(env));
    set_token(&mut env.svm, env.vault_token, mint, va, bal + atoms as u64);
}

fn vault_authority(env: &Env) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", env.market.as_ref()], &env.program_id).0
}

struct Vault {
    registry: Pubkey,
    mint: Pubkey,
    ledger: Pubkey,
    sibling_ledger: Pubkey,
    lp: Keypair,
    lp_ata: Pubkey,
    source: Pubkey,
    dest: Pubkey,
}

fn vault(env: &mut Env) -> Vault {
    let (registry, mint, ledger, lp, lp_ata, source) = ready_vault(env);
    let (sibling_ledger, _) =
        derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);
    let dest = Pubkey::new_unique();
    let (cm, owner) = (env.collateral_mint, lp.pubkey());
    set_token(&mut env.svm, dest, cm, owner, 0);
    Vault {
        registry,
        mint,
        ledger,
        sibling_ledger,
        lp,
        lp_ata,
        source,
        dest,
    }
}

fn deposit(env: &mut Env, v: &Vault, amount: u128, domain: u16) {
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount, domain },
        deposit_accounts(
            env.market,
            env.vault_token,
            v.registry,
            v.mint,
            v.lp_ata,
            v.source,
            v.ledger,
            lp.pubkey(),
        ),
        &[&lp],
    )
    .expect("deposit");
}

fn rebalance(env: &mut Env, v: &Vault, from: u16, to: u16, amount: u128) -> Result<(), String> {
    let (fl, tl) = if from == DOMAIN {
        (v.ledger, v.sibling_ledger)
    } else {
        (v.sibling_ledger, v.ledger)
    };
    let cranker = Keypair::new();
    env.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::RebalanceLpVaultBacking {
            from_domain: from,
            to_domain: to,
            amount,
        },
        vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(v.registry, false),
            AccountMeta::new(fl, false),
            AccountMeta::new(tl, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&cranker],
    )
}

fn request(env: &mut Env, v: &Vault, shares: u128) {
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    let (escrow, _) = derive_lp_escrow(&env.program_id, &env.market);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &v.registry, &lp.pubkey());
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::RequestRedeemLpShares { shares },
        vec![
            AccountMeta::new(lp.pubkey(), true),
            AccountMeta::new(v.registry, false),
            AccountMeta::new(v.mint, false),
            AccountMeta::new(v.lp_ata, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(redemption, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[&lp],
    )
    .expect("request redeem");
    let slot = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    env.svm.warp_to_slot(slot + COOLDOWN + 2);
}

/// Tag 77 exactly as the frontend builds it on a non-bound vault: domain = registry.domain,
/// both pot ledgers writable.
fn execute(env: &mut Env, v: &Vault, domain: u16) -> Result<(), String> {
    let payer = env.payer.insecure_clone();
    let (escrow, _) = derive_lp_escrow(&env.program_id, &env.market);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &v.registry, &v.lp.pubkey());
    let va = vault_authority(env);
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::ExecuteRedemption { domain },
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(v.registry, false),
            AccountMeta::new(redemption, false),
            AccountMeta::new(v.mint, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(env.vault_token, false),
            AccountMeta::new_readonly(va, false),
            AccountMeta::new(v.ledger, false),
            AccountMeta::new(v.dest, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(v.sibling_ledger, false),
            AccountMeta::new(v.lp.pubkey(), true), // H-1(b): the redeemer signs a Live non-bound 77
        ],
        &[&v.lp.insecure_clone()],
    )
}

fn registry_shares(env: &Env, v: &Vault) -> u128 {
    state::read_lp_vault_registry(&env.svm.get_account(&v.registry).unwrap().data)
        .unwrap()
        .total_lp_shares_outstanding
}

fn floor_mul_div(a: u128, b: u128, c: u128) -> u128 {
    a.checked_mul(b).expect("test values fit u128") / c
}

// ─────────────────────────────── helpers specific to this file ───────────────────────────────

const P: u128 = 1_000_000_000; // 1,000 tokens seeded into EACH pot (the launch wizard shape)
/// Net impairment of the over-impaired pot: 500 above its 1,000 principal (OTC/SI shape).
const OVER: u128 = 1_500_000_000;
/// Custom code of `LpVaultTargetPotImpaired` (appended after VaultLpBindRequiresFlatAsset = 90).
const TARGET_IMPAIRED: u32 = 91;
const NEEDS_CODE_25: u32 = 25;

fn code_of(e: &str) -> String {
    // litesvm's debug string carries `Custom(N)`.
    let i = e.find("Custom(").expect("a Custom(..) error");
    let j = e[i..].find(')').unwrap();
    e[i..i + j + 1].to_string()
}
fn has_code(e: &str, code: u32) -> bool {
    e.contains(&format!("Custom({code})"))
}

/// PHYSICAL recovery (E3): a loser's loss of `atoms` lands in pot `domain` and pays its
/// receivable down (fresh +atoms, consumed -atoms; the atoms are in the vault).
fn recover_pot_backing(env: &mut Env, domain: u16, atoms: u128) {
    with_market(env, |g| {
        let n = atoms * BOUND_SCALE;
        let b = &mut g.source_backing_buckets[domain as usize];
        b.fresh_unliened_backing_num += n;
        b.consumed_liened_backing_num -= n;
        // a backing add re-opens a drained pot (the engine add path)
        if b.status == percolator::BackingBucketStatusV16::Expired {
            b.status = percolator::BackingBucketStatusV16::Fresh;
        }
        let s = &mut g.source_credit[domain as usize];
        s.fresh_reserved_backing_num += n;
        s.spent_backing_num -= n;
        s.provider_receivable_num -= n;
        g.source_fresh_backing_total_num += n;
        g.vault += atoms;
    });
    let bal = token_amount(&env.svm, env.vault_token);
    let (mint, va) = (env.collateral_mint, vault_authority(env));
    set_token(&mut env.svm, env.vault_token, mint, va, bal + atoms as u64);
}

/// Pin a pot's LEDGER to the state a live 75/77/91 leaves behind after syncing against a
/// consumed bucket (loss booked, watermark moved). The lazy path (no write yet) is covered by
/// `otc_shape_75_into_the_healthy_pot_*`, which leaves the ledger stale on purpose.
fn book_synced_impairment(env: &mut Env, ledger: Pubkey, consumed: u128) {
    let mut acct = env.svm.get_account(&ledger).expect("ledger");
    let mut l = state::read_backing_domain_ledger(&acct.data).expect("decode");
    l.cumulative_loss_atoms = consumed;
    l.last_observed_unavailable_principal_atoms = consumed;
    state::write_backing_domain_ledger(&mut acct.data, &l).expect("encode");
    env.svm.set_account(ledger, acct).unwrap();
}

fn try_deposit(env: &mut Env, v: &Vault, amount: u128, domain: u16) -> Result<(), String> {
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    env.svm.expire_blockhash();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount, domain },
        deposit_accounts(
            env.market,
            env.vault_token,
            v.registry,
            v.mint,
            v.lp_ata,
            v.source,
            v.ledger,
            lp.pubkey(),
        ),
        &[&lp],
    )
}

/// A second, independent depositor on the same vault.
fn new_actor(env: &mut Env, v: &Vault) -> Vault {
    let lp = Keypair::new();
    env.svm.airdrop(&lp.pubkey(), 100_000_000_000).unwrap();
    let (cm, mint) = (env.collateral_mint, v.mint);
    let source = Pubkey::new_unique();
    set_token(&mut env.svm, source, cm, lp.pubkey(), 100_000_000_000);
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, mint, lp.pubkey(), 0);
    let dest = Pubkey::new_unique();
    set_token(&mut env.svm, dest, cm, lp.pubkey(), 0);
    Vault {
        registry: v.registry,
        mint: v.mint,
        ledger: v.ledger,
        sibling_ledger: v.sibling_ledger,
        lp,
        lp_ata,
        source,
        dest,
    }
}

/// Both pots seeded with `P`, then pot `impaired` carries `consumed` atoms of impairment.
fn otc_env(impaired: u16, consumed: u128) -> (Env, Vault) {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, P, DOMAIN);
    deposit(&mut env, &v, P, SIBLING_DOMAIN);
    consume_pot_backing(&mut env, impaired, consumed);
    (env, v)
}

fn shares_of(env: &Env, ata: Pubkey) -> u128 {
    token_amount(&env.svm, ata) as u128
}

fn net_impairment(l: &state::BackingDomainLedgerAccountV16) -> u128 {
    l.cumulative_loss_atoms - l.cumulative_recovery_atoms
}


// ═══════════════════════════════ Phase 4 Wave D: tag 112 RescueDeposit ═══════════════════════════
//
// Spec: `~/percolator-ops/ledger/phase4-design-2026-10-05.md` item 5. A rescue buys senior shares
// at the certified impaired value (non-bound: the E3 EXIT NAV), never at par:
// m = floor(x_eff * S / v), with x_eff re-measured after the deposit. L-RES: the value per share
// at the exit reading never falls for incumbents.

const RESCUE_REFUSED: u32 = 114;
const RESCUE_NAV_FLOOR: u32 = 115;

/// The exit (E3) reading of a non-bound vault from raw state: per pot
/// `min(ledger principal, physical fresh backing - uncovered claims)` (no LP earnings here).
fn exit_nav(env: &Env, v: &Vault) -> u128 {
    let g = market_group(env);
    let mut total = 0u128;
    for (d, l) in [(DOMAIN, v.ledger), (SIBLING_DOMAIN, v.sibling_ledger)] {
        let principal = env
            .svm
            .get_account(&l)
            .and_then(|a| state::read_backing_domain_ledger(&a.data).ok())
            .map_or(0, |x| x.total_principal_atoms);
        let b = &g.source_backing_buckets[d as usize];
        let s = &g.source_credit[d as usize];
        let held = (b.fresh_unliened_backing_num + b.valid_liened_backing_num) / BOUND_SCALE;
        let owed = s.positive_claim_bound_num.div_ceil(BOUND_SCALE);
        total += principal.min(held.saturating_sub(owed));
    }
    total
}

fn rescue_ix(tranche: u8, amount: u64, min_shares: u128) -> ProgInstruction {
    ProgInstruction::RescueDeposit { tranche, amount, min_shares }
}

/// Tag 112 with the tag-75 account list (non-bound: no tail).
fn try_rescue(env: &mut Env, who: &Vault, amount: u64, min_shares: u128) -> Result<(), String> {
    let lp = who.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    env.svm.expire_blockhash();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        rescue_ix(0, amount, min_shares),
        deposit_accounts(
            env.market,
            env.vault_token,
            who.registry,
            who.mint,
            who.lp_ata,
            who.source,
            who.ledger,
            lp.pubkey(),
        ),
        &[&lp],
    )
}

/// Impaired non-bound vault: both pots seeded with P (1,000 tokens), the registry pot then loses
/// `consumed` atoms physically (a winner withdrew them). Exit NAV = 2P - consumed, par = 2P.
fn impaired(consumed: u128) -> (Env, Vault) {
    let (mut env, v) = otc_env(DOMAIN, consumed);
    // Book it on the ledger the way a live 75/77/91 would after syncing (R-1 reads synced ledgers).
    let l = v.ledger;
    book_synced_impairment(&mut env, l, consumed);
    (env, v)
}

/// RS-1 (I-RS1 / I-RS3): with 15% impairment tag 75 is paused (R-1, Custom 91) and a rescue
/// prices at the EXIT value 0.85 per share, never par: the rescuer gets floor(x * S / v) shares,
/// strictly more than the par mint x * S / par, and the value per share of every incumbent at the
/// exit reading does not fall (L-RES, measured on chain state).
#[test]
fn rescue_buys_at_impaired_exit_nav_never_par() {
    let consumed = 300_000_000u128; // 15% of 2P
    let (mut env, v) = impaired(consumed);
    let rescuer = new_actor(&mut env, &v);
    // Control: the impaired vault refuses a normal Earn deposit (R-1).
    let r75 = try_deposit(&mut env, &rescuer, 200_000_000, DOMAIN);
    assert!(r75.as_ref().err().map_or(false, |e| has_code(e, TARGET_IMPAIRED)), "75 must be paused: {r75:?}");
    let s0 = registry_shares(&env, &v);
    let v0 = exit_nav(&env, &v);
    assert_eq!(v0, 2 * P - consumed, "exit reading");
    let vault0 = token_amount(&env.svm, env.vault_token) as u128;
    let x: u128 = 200_000_000;
    try_rescue(&mut env, &rescuer, x as u64, 1).expect("rescue");
    let s1 = registry_shares(&env, &v);
    let minted = shares_of(&env, rescuer.lp_ata);
    assert_eq!(s1 - s0, minted, "every rescue share is outstanding");
    assert_eq!(minted, floor_mul_div(x, s0, v0), "m = floor(x * S / v)");
    let par_mint = floor_mul_div(x, s0, 2 * P);
    assert!(minted > par_mint, "never at par: {minted} vs par mint {par_mint}");
    let v1 = exit_nav(&env, &v);
    assert_eq!(v1, v0 + x, "the rescue atoms raise the exit reading by exactly x");
    // L-RES: v1 / s1 >= v0 / s0.
    assert!(v1 * s0 >= v0 * s1, "incumbents diluted: {v1}/{s1} < {v0}/{s0}");
    // Conservation: the vault holds exactly the rescue atoms more.
    assert_eq!(token_amount(&env.svm, env.vault_token) as u128, vault0 + x);
    assert_eq!(market_group(&env).vault, vault0 + x, "engine vault == SPL vault");
}

/// RS-2: a rescue on a healthy vault is refused (use tag 75), and nothing moves.
#[test]
fn rescue_refused_when_not_impaired() {
    let (mut env, v) = otc_env(DOMAIN, 0);
    let r = new_actor(&mut env, &v);
    let vault0 = token_amount(&env.svm, env.vault_token);
    let res = try_rescue(&mut env, &r, 200_000_000, 1);
    assert!(res.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{res:?}");
    assert_eq!(token_amount(&env.svm, env.vault_token), vault0);
    assert_eq!(shares_of(&env, r.lp_ata), 0);
}

/// RS-3 (I-RS4): below the 5% NAV floor the vault is dead: 115, never a rescue.
#[test]
fn rescue_refused_below_nav_floor() {
    // Exit NAV = 2P - consumed; 5% of par = 0.1 P. consumed = 1.95 P leaves 0.05 P.
    let consumed = 1_950_000_000u128;
    let (mut env, v) = otc_env(DOMAIN, P);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, consumed - P);
    let (l0, l1) = (v.ledger, v.sibling_ledger);
    book_synced_impairment(&mut env, l0, P);
    book_synced_impairment(&mut env, l1, consumed - P);
    let r = new_actor(&mut env, &v);
    let res = try_rescue(&mut env, &r, 200_000_000, 1);
    assert!(res.as_ref().err().map_or(false, |e| has_code(e, RESCUE_NAV_FLOOR)), "{res:?}");
}

/// RS-4: amount bounds [100e6, 10 v] and the rescuer's slippage floor (min_shares).
#[test]
fn rescue_amount_bounds_and_slippage() {
    let (mut env, v) = impaired(300_000_000);
    let r = new_actor(&mut env, &v);
    let below = try_rescue(&mut env, &r, 99_999_999, 1);
    assert!(below.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{below:?}");
    let v0 = exit_nav(&env, &v);
    let above = try_rescue(&mut env, &r, (10 * v0 + 1) as u64, 1);
    assert!(above.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{above:?}");
    let s0 = registry_shares(&env, &v);
    let expect = floor_mul_div(200_000_000, s0, v0);
    let slip = try_rescue(&mut env, &r, 200_000_000, expect + 1);
    assert!(slip.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{slip:?}");
    try_rescue(&mut env, &r, 200_000_000, expect).expect("exact min_shares accepted");
    // Tranche 1 (bond) does not exist on this branch.
    let payer = env.payer.insecure_clone();
    let lp = r.lp.insecure_clone();
    let bond = send(
        &mut env.svm,
        env.program_id,
        &payer,
        rescue_ix(1, 200_000_000, 1),
        deposit_accounts(env.market, env.vault_token, r.registry, r.mint, r.lp_ata, r.source, r.ledger, lp.pubkey()),
        &[&lp],
    );
    assert!(bond.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{bond:?}");
}

/// RS-5 (I-RS4, the H-1 class): a NON-bound rescue requires the source asset to be
/// loss-current. With an open K/F settlement cohort on the vault's asset (E3 may be mid-way
/// through a touch-order window) it is refused; once the cohort clears it is admitted.
/// Negative control for the mutant "non-bound without loss-current".
#[test]
fn rescue_nonbound_requires_loss_current_source() {
    let (mut env, v) = impaired(300_000_000);
    let r = new_actor(&mut env, &v);
    with_market(&mut env, |g| g.assets[APPEND_ASSET_INDEX as usize].stale_account_count_long = 1);
    let res = try_rescue(&mut env, &r, 200_000_000, 1);
    assert!(res.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)), "{res:?}");
    with_market(&mut env, |g| g.assets[APPEND_ASSET_INDEX as usize].stale_account_count_long = 0);
    try_rescue(&mut env, &r, 200_000_000, 1).expect("admitted once loss-current");
}

/// RS-6 (rescue-then-withdraw, conservation): the rescuer cannot extract value by exiting at
/// once (it redeems at the same exit reading, rounding against it), and every incumbent still
/// redeems at least its pre-rescue value. Every atom is accounted for.
#[test]
fn rescue_then_redeem_extracts_nothing_and_incumbents_whole() {
    let consumed = 300_000_000u128;
    let (mut env, v) = impaired(consumed);
    let s0 = registry_shares(&env, &v);
    let v0 = exit_nav(&env, &v);
    let inc_shares = shares_of(&env, v.lp_ata);
    let inc_value_before = floor_mul_div(inc_shares, v0, s0);
    let r = new_actor(&mut env, &v);
    let x: u128 = 300_000_000;
    let src0 = token_amount(&env.svm, r.source) as u128;
    try_rescue(&mut env, &r, x as u64, 1).expect("rescue");
    let m = shares_of(&env, r.lp_ata);
    // The rescuer exits immediately (after the redemption cooldown).
    request(&mut env, &r, m);
    execute(&mut env, &r, DOMAIN)
        .or_else(|_| execute(&mut env, &r, SIBLING_DOMAIN))
        .expect("rescuer redeem");
    let back = token_amount(&env.svm, r.dest) as u128;
    assert!(back <= x, "rescue-then-redeem extracted value: paid {x} got {back}");
    assert_eq!(token_amount(&env.svm, r.source) as u128, src0 - x);
    // The incumbent's exit value did not fall.
    let s1 = registry_shares(&env, &v);
    let v1 = exit_nav(&env, &v);
    let inc_value_after = floor_mul_div(inc_shares, v1, s1);
    assert!(inc_value_after >= inc_value_before, "incumbent {inc_value_after} < {inc_value_before}");
}

/// R-5 (re-review 2026-10-06): the W-6 predicate (Wave A's `loss_current()`) on tag 112. A pending
/// socialized-loss obligation, a pending B-index settlement, or a domain loss barrier on the
/// vault's asset each refuses a non-bound rescue (114) on their own (the harness cannot reach
/// these states organically, so they are patched into the slab). Control: the same rescue is
/// admitted once every counter is clear. Mutant control: with `rescue_nonbound_loss_current_view`
/// forced true, the patched cases are admitted (MR5).
#[test]
fn rescue_refused_on_pending_obligation_b_stale_or_barrier() {
    let a = APPEND_ASSET_INDEX as usize;
    let patches: [(&str, fn(&mut state::MarketGroupV16, usize, u64)); 3] = [
        ("pending_obligation_count_long", |g, a, v| g.assets[a].pending_obligation_count_long = v),
        ("b_stale_account_count", |g, _a, v| g.b_stale_account_count = v),
        ("pending_domain_loss_barrier (asset's long domain)", |g, a, v| g.pending_domain_loss_barriers[2 * a] = v),
    ];
    let mut admitted = Vec::new();
    for (name, patch) in patches {
        let (mut env, v) = impaired(300_000_000);
        let r = new_actor(&mut env, &v);
        with_market(&mut env, |g| patch(g, a, 1));
        let res = try_rescue(&mut env, &r, 200_000_000, 1);
        eprintln!("R-5 {name} = 1 -> {:?}", res.as_ref().err().map(|e| code_of(e)));
        if !res.as_ref().err().map_or(false, |e| has_code(e, RESCUE_REFUSED)) {
            admitted.push(name);
            continue;
        }
        with_market(&mut env, |g| patch(g, a, 0));
        try_rescue(&mut env, &r, 200_000_000, 1).unwrap_or_else(|e| panic!("{name}: control admitted once clear: {e}"));
    }
    assert!(admitted.is_empty(), "admitted while a loss is pending: {admitted:?}");
}
