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
            AccountMeta::new_readonly(env.collateral_mint, false), // [6] collateral mint (prog#542)
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

// ─────────────────────────────── H-1 / B-2 regression tests ──────────────────────────────────

/// Live OTC shape: sibling pot impairment `sib`, registry pot impairment `P - 3` (3 atoms of
/// available principal). A NEW actor deposits 1,000,000 atoms into the registry pot. Returns
/// (env, vault, attacker, deposit result).
fn low_nav_entry(sib: u128) -> (Env, Vault, Vault, Result<(), String>) {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, sib);
    consume_pot_backing(&mut env, DOMAIN, P - 3);
    let atk = new_actor(&mut env, &v);
    let r = try_deposit(&mut env, &atk, 1_000_000, DOMAIN);
    (env, v, atk, r)
}

fn assert_refused_91_without_side_effects(
    env: &mut Env,
    v: &Vault,
    who: &Vault,
    amount: u128,
    domain: u16,
) {
    let t = registry_shares(env, v);
    let held = shares_of(env, who.lp_ata);
    let src = token_amount(&env.svm, who.source);
    let vault_tok = token_amount(&env.svm, env.vault_token);
    let market_before = env.svm.get_account(&env.market).unwrap().data;
    let l_before = env.svm.get_account(&v.ledger).map(|a| a.data);
    let s_before = env.svm.get_account(&v.sibling_ledger).map(|a| a.data);
    let e = try_deposit(env, who, amount, domain).expect_err("deposit must be refused");
    assert!(
        has_code(&e, TARGET_IMPAIRED),
        "want Custom(91), got {}",
        code_of(&e)
    );
    assert_eq!(registry_shares(env, v), t, "no shares minted");
    assert_eq!(shares_of(env, who.lp_ata), held);
    assert_eq!(token_amount(&env.svm, who.source), src, "no tokens moved");
    assert_eq!(token_amount(&env.svm, env.vault_token), vault_tok);
    assert_eq!(
        env.svm.get_account(&env.market).unwrap().data,
        market_before
    );
    assert_eq!(env.svm.get_account(&v.ledger).map(|a| a.data), l_before);
    assert_eq!(
        env.svm.get_account(&v.sibling_ledger).map(|a| a.data),
        s_before
    );
}

// ─────────────────────────────── R-1 / N-1 helpers ──────────────────────────────────────────

/// Total principal of the two-pot test vault (both pots seeded with P).
const TOTAL_P: u128 = 2 * P;
/// `LP_VAULT_MAX_DEPOSIT_IMPAIRMENT_BPS` boundary on TOTAL_P: exactly 10% = 200,000,000 atoms.
const R1_BOUNDARY: u128 = TOTAL_P * 1_000 / 10_000;
/// Custom code of `LpVaultOiReservationViolated`.
const OI_RESERVATION_VIOLATED: u32 = 37;

/// Both pots seeded with P, then `own` atoms of impairment on the registry pot and `sib` on the
/// sibling (as consumed backing the next ledger sync books).
fn r1_env(own: u128, sib: u128) -> (Env, Vault) {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, sib);
    if own != 0 {
        consume_pot_backing(&mut env, DOMAIN, own);
    }
    (env, v)
}

/// Deposit-then-recovery capture (reviewer's `sen_capture`, generalised): impairment `imp` on
/// pot `at`; an attacker deposits `a` into the registry pot; the whole remaining receivable on
/// both pots recovers; the attacker redeems everything via 77. `None` = the deposit was refused
/// (the error must be Custom 91). `Some((shares, paid))` otherwise.
fn r1_capture(at: u16, imp: u128, a: u128) -> Option<(u128, u128)> {
    let (mut env, v) = otc_env(at, imp);
    let atk = new_actor(&mut env, &v);
    if let Err(e) = try_deposit(&mut env, &atk, a, DOMAIN) {
        assert!(
            has_code(&e, TARGET_IMPAIRED),
            "refusal must be 91, got {}",
            code_of(&e)
        );
        return None;
    }
    let s = shares_of(&env, atk.lp_ata);
    for d in [DOMAIN, SIBLING_DOMAIN] {
        let c = market_group(&env).source_backing_buckets[d as usize].consumed_liened_backing_num
            / BOUND_SCALE;
        if c != 0 {
            recover_pot_backing(&mut env, d, c);
        }
    }
    request(&mut env, &atk, s);
    execute(&mut env, &atk, DOMAIN).unwrap_or_else(|e| panic!("attacker 77: {}", code_of(&e)));
    Some((s, token_amount(&env.svm, atk.dest) as u128))
}

// ─────────────────────────────── R-1 tests ──────────────────────────────────────────────────

/// The pause is a VAULT-TOTAL ratio with an exact boundary: impairment == 10% of total principal
/// is accepted (and priced exactly on the unfloored NAV), one atom more is refused 91 with no
/// side effects, into either pot. (200M, 0) is 20% of the registry pot alone and is accepted:
/// the rule is the vault's ratio, not a per-pot one.
#[test]
fn r1_boundary_is_exact_and_vault_total() {
    let half = R1_BOUNDARY / 2;
    for (own, sib) in [(0, R1_BOUNDARY), (R1_BOUNDARY, 0), (half, half)] {
        for d in [DOMAIN, SIBLING_DOMAIN] {
            let (mut env, v) = r1_env(own, sib);
            let atk = new_actor(&mut env, &v);
            let t = registry_shares(&env, &v);
            try_deposit(&mut env, &atk, 100_000_000, d)
                .unwrap_or_else(|e| panic!("exactly 10% ({own},{sib}) pot {d}: {}", code_of(&e)));
            assert_eq!(
                shares_of(&env, atk.lp_ata),
                // H-1 (2026-10-05): entries price at PAR; R-1 still bounds what an entrant can
                // overpay on a genuine default (here the boundary, 10%).
                floor_mul_div(100_000_000, t, TOTAL_P),
                "priced at par ({own},{sib}) pot {d}"
            );
        }
    }
    for (own, sib) in [(0, R1_BOUNDARY + 1), (R1_BOUNDARY + 1, 0), (half, half + 1)] {
        for d in [DOMAIN, SIBLING_DOMAIN] {
            let (mut env, v) = r1_env(own, sib);
            let atk = new_actor(&mut env, &v);
            for amt in [1u128, 100_000_000, 10 * P] {
                assert_refused_91_without_side_effects(&mut env, &v, &atk, amt, d);
            }
        }
    }
}

/// The pause reads the SYNCED ledgers: a loss already booked (ledger written by a live sync) and
/// a lazy one (bucket only) refuse identically, and a booked recovery reopens deposits.
#[test]
fn r1_reads_synced_ledgers_and_lifts_on_recovery() {
    for booked in [false, true] {
        let (mut env, v) = r1_env(0, 500_000_000); // 25%: paused, no pot over-impaired
        if booked {
            book_synced_impairment(&mut env, v.sibling_ledger, 500_000_000);
        }
        let atk = new_actor(&mut env, &v);
        assert_refused_91_without_side_effects(&mut env, &v, &atk, 100_000_000, DOMAIN);
        // Recover 300M: impairment 200M = exactly 10% -> open again, priced at par (H-1 entry).
        recover_pot_backing(&mut env, SIBLING_DOMAIN, 300_000_000);
        let t = registry_shares(&env, &v);
        try_deposit(&mut env, &atk, 100_000_000, DOMAIN).unwrap_or_else(|e| {
            panic!("booked={booked}: healed vault must reopen: {}", code_of(&e))
        });
        assert_eq!(shares_of(&env, atk.lp_ata), floor_mul_div(100_000_000, t, TOTAL_P));
    }
}

/// Healthy and lightly-impaired vaults are unaffected: both open, and (H-1, 2026-10-05) both
/// price entries at par, into either pot.
#[test]
fn r1_healthy_and_lightly_impaired_vaults_unaffected() {
    for imp in [0u128, TOTAL_P / 100] {
        for d in [DOMAIN, SIBLING_DOMAIN] {
            let (mut env, v) = r1_env(0, imp);
            let atk = new_actor(&mut env, &v);
            let t = registry_shares(&env, &v);
            try_deposit(&mut env, &atk, 100_000_000, d).expect("deposit");
            assert_eq!(
                shares_of(&env, atk.lp_ata),
                floor_mul_div(100_000_000, t, TOTAL_P),
                "imp {imp} pot {d}"
            );
        }
    }
}

/// Tag 77 is never gated by R-1: at 25% impairment (paused for 75, no pot over-impaired) a
/// holder redeems through either pot and is paid exactly shares * NAV / total; the deposit is
/// still refused afterwards.
#[test]
fn r1_tag77_unaffected_while_deposits_pause() {
    for via in [DOMAIN, SIBLING_DOMAIN] {
        let imp = 500_000_000u128;
        let (mut env, v) = r1_env(0, imp);
        let probe = new_actor(&mut env, &v);
        assert_refused_91_without_side_effects(&mut env, &v, &probe, 1_000_000, DOMAIN);
        let t = registry_shares(&env, &v);
        let shares = shares_of(&env, v.lp_ata) / 4;
        request(&mut env, &v, shares);
        execute(&mut env, &v, via)
            .unwrap_or_else(|e| panic!("77 via {via} must not be gated: {}", code_of(&e)));
        assert_eq!(
            token_amount(&env.svm, v.dest) as u128,
            floor_mul_div(shares, TOTAL_P - imp, t),
            "77 via {via} pays the NAV share"
        );
        assert_eq!(registry_shares(&env, &v), t - shares);
        assert_refused_91_without_side_effects(&mut env, &v, &probe, 1_000_000, DOMAIN);
    }
}

/// Capture sweep (reviewer's `sen_threshold_recovery_capture`, over the impairment RATIO): for
/// every accepted deposit the attacker's windfall after a full recovery is at most
/// `r / (1 - r)` per token (exact integer form: (paid - a) * (2P - imp) <= a * imp), i.e. at
/// most 1/9 ≈ 0.111x at the 10% boundary; every deposit above 10% is refused 91. Receivable in
/// either pot.
#[test]
fn r1_capture_sweep_windfall_is_bounded() {
    let ratios = [
        TOTAL_P / 100,        // 1%
        TOTAL_P * 58 / 1_000, // 5.8% (worst live OPEN vault in the review)
        R1_BOUNDARY,          // exactly 10%
        R1_BOUNDARY + 1,      // one atom over
        TOTAL_P / 4,          // 25%
        P,                    // 50% (reviewer's sweep: sibling impairment == P)
    ];
    let mut worst_boundary = 0f64;
    // Violations are collected and asserted at the end, so a negative-control run
    // (`PERC_PROG_SO` = a build without R-1) prints the whole windfall table.
    let mut violations: Vec<String> = vec![];
    for at in [SIBLING_DOMAIN, DOMAIN] {
        for imp in ratios {
            for a in [2_000_000u128, 20_000_000, 200_000_000, 2_000_000_000] {
                let r = imp as f64 / TOTAL_P as f64;
                match r1_capture(at, imp, a) {
                    None => {
                        println!("R1CAP pot={at} r={:.4}% dep={a}: REFUSED 91", r * 100.0);
                        if imp <= R1_BOUNDARY {
                            violations.push(format!("pot={at} imp={imp} dep={a} must be accepted"));
                        }
                    }
                    Some((s, paid)) => {
                        let windfall = (paid as f64 - a as f64) / a as f64;
                        println!(
                            "R1CAP pot={at} r={:.4}% dep={a}: shares={s} paid={paid} windfall={:+.4}x (bound r/(1-r)={:.4}x)",
                            r * 100.0,
                            windfall,
                            r / (1.0 - r)
                        );
                        if imp > R1_BOUNDARY {
                            violations.push(format!(
                                "pot={at} imp={imp} dep={a} must be refused (windfall {windfall:+.4}x)"
                            ));
                        }
                        if paid.saturating_sub(a) * (TOTAL_P - imp) > a * imp {
                            violations.push(format!(
                                "windfall above r/(1-r): pot={at} imp={imp} dep={a} paid={paid}"
                            ));
                        }
                        if imp == R1_BOUNDARY {
                            if paid * 9 > a * 10 {
                                violations
                                    .push(format!("boundary windfall > 1/9: dep={a} paid={paid}"));
                            }
                            worst_boundary = worst_boundary.max(windfall);
                        }
                    }
                }
            }
        }
    }
    println!("R1CAP worst windfall at the 10% boundary = {worst_boundary:+.4}x per token");
    assert!(
        violations.is_empty(),
        "R-1 violations:\n{}",
        violations.join("\n")
    );
}

/// The reviewer's exact R-1 shapes (sibling impairment == P, registry pot keeps `avail`; 0.1% to
/// 50% of genesis price, deposits 2 to 2,000 tokens): bc228e1b accepted all of them (windfall up
/// to 500x); every one is now refused 91.
#[test]
fn r1_reviewer_threshold_shapes_are_all_refused() {
    for avail in [2_000_000u128, 20_000_000, 200_000_000, 1_000_000_000] {
        for a in [2_000_000u128, 20_000_000, 200_000_000, 2_000_000_000] {
            let (mut env, v) = otc_env(SIBLING_DOMAIN, P);
            consume_pot_backing(&mut env, DOMAIN, P - avail);
            let atk = new_actor(&mut env, &v);
            assert_refused_91_without_side_effects(&mut env, &v, &atk, a, DOMAIN);
        }
    }
}

// ─────────────────────────────── N-1: tag 77 nav_post differential ──────────────────────────

/// Floored single-pot NAV, recomputed in the test (same formula as the wrapper's
/// `lp_vault_nav_atoms_floored`, fee_share 5_000).
fn test_nav_floored(l: &state::BackingDomainLedgerAccountV16) -> u128 {
    let avail = l.total_principal_atoms.saturating_sub(
        l.cumulative_loss_atoms
            .saturating_sub(l.cumulative_recovery_atoms),
    );
    avail + (l.total_earnings_atoms - l.total_earnings_withdrawn_atoms) * 5_000 / 10_000
}

/// Live-config tag 77 (oi_reservation_threshold_bps = 8000) with non-zero earnings, loss and
/// recovery booked on the source pot, then `valid_liened = vl` atoms of open interest against it.
/// Returns the payout, or the error code. The vault is built so every 75 stays at or under the
/// R-1 boundary (the reviewer's sen_oi77 synced a 15%-impaired pot with a 75, now refused).
fn n1_oi_try(vl: u128) -> Result<(u128, state::BackingDomainLedgerAccountV16), String> {
    n1_oi_try_shape(vl, R1_BOUNDARY)
}

/// `consumed` = loss consumed on the source pot before the first syncing 75. `R1_BOUNDARY`
/// (10%) is this file's shape; 300,000,000 (15%) is the reviewer's exact sen_oi77 shape.
fn n1_oi_try_shape(
    vl: u128,
    consumed: u128,
) -> Result<(u128, state::BackingDomainLedgerAccountV16), String> {
    OI_BPS.with(|c| c.set(8_000));
    let (mut env, v) = otc_env(SIBLING_DOMAIN, 0);
    OI_BPS.with(|c| c.set(0));
    add_pot_earnings(&mut env, DOMAIN, 50_000_000);
    consume_pot_backing(&mut env, DOMAIN, consumed);
    try_deposit(&mut env, &v, 1_000, DOMAIN).map_err(|e| format!("sync 1: {}", code_of(&e)))?;
    recover_pot_backing(&mut env, DOMAIN, 100_000_000);
    try_deposit(&mut env, &v, 1_000, DOMAIN).map_err(|e| format!("sync 2: {}", code_of(&e)))?;
    let l = ledger_of(&env.svm, v.ledger);
    assert!(
        l.cumulative_loss_atoms > 0
            && l.cumulative_recovery_atoms > 0
            && l.total_earnings_atoms > 0,
        "loss, recovery and earnings booked"
    );
    let reg =
        state::read_lp_vault_registry(&env.svm.get_account(&v.registry).unwrap().data).unwrap();
    assert_eq!(reg.oi_reservation_threshold_bps, 8_000, "live config");
    let s = shares_of(&env, v.lp_ata) / 10;
    request(&mut env, &v, s);
    // A CONSISTENT lien (the engine's own lien step): fresh -> valid on the bucket, and the
    // source's valid_liened mirrors it (fresh_reserved = fresh + valid is unchanged).
    with_market(&mut env, |g| {
        let num = vl * BOUND_SCALE;
        let b = &mut g.source_backing_buckets[DOMAIN as usize];
        b.fresh_unliened_backing_num = b.fresh_unliened_backing_num.saturating_sub(num);
        b.valid_liened_backing_num += num;
        g.source_credit[DOMAIN as usize].valid_liened_backing_num += num;
    });
    execute(&mut env, &v, DOMAIN).map_err(|e| code_of(&e))?;
    Ok((
        token_amount(&env.svm, v.dest) as u128,
        ledger_of(&env.svm, v.ledger),
    ))
}

/// N-1 differential: the nav_post OI gate accepts exactly up to its analytic boundary
/// `floor(nav_post * BOUND_SCALE * 8000 / 10000) / BOUND_SCALE` (nav_post recomputed by the test
/// from the post-77 ledger) and refuses one atom more with Custom 37. Run with `PERC_PROG_SO`
/// set to the inline variant / deployed bytes for the cross-build comparison; it prints the
/// boundary.
#[test]
fn n1_tag77_nav_post_oi_gate_boundary_at_live_config() {
    let (paid0, post) = n1_oi_try(0).expect("77 with no OI");
    assert!(paid0 > 0);
    let nav_post = test_nav_floored(&post);
    let expected = (nav_post * BOUND_SCALE * 8_000 / 10_000) / BOUND_SCALE;
    let (mut lo, mut hi) = (0u128, 10_000_000_000u128);
    assert!(n1_oi_try(hi).is_err());
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if n1_oi_try(mid).is_ok() {
            lo = mid
        } else {
            hi = mid
        }
    }
    let refused = n1_oi_try(hi).expect_err("first refused");
    println!(
        "N1OI nav_post={nav_post} max accepted valid_liened={lo} first refused={hi} -> {refused} (paid at vl=0: {paid0})"
    );
    assert_eq!(lo, expected, "boundary == nav_post * 0.8");
    assert_eq!(hi, expected + 1);
    assert_eq!(refused, format!("Custom({OI_RESERVATION_VIOLATED})"));
    // At the boundary the payout is identical to the no-OI payout (the gate only gates).
    assert_eq!(n1_oi_try(lo).expect("boundary accepted").0, paid0);
}

/// The reviewer's EXACT sen_oi77 shape (15% consumed before the first syncing 75). On bytes
/// without R-1 (bc228e1b 45e24eb3, deployed f2fbf36d, or the N-1 variant) it pins the reviewer's
/// boundary: 514,001,513 accepted / 514,001,514 refused Custom 37. On R-1 bytes the shape cannot
/// be built (its first 75 is at 15% impairment) and that refusal is pinned instead; the
/// R-1-compatible boundary is `n1_tag77_nav_post_oi_gate_boundary_at_live_config`.
#[test]
fn n1_reviewer_exact_oi77_shape() {
    const REVIEWER_CONSUMED: u128 = 300_000_000;
    match n1_oi_try_shape(0, REVIEWER_CONSUMED) {
        Err(e) => {
            println!("N1OI-REVIEWER shape not buildable: {e}");
            assert_eq!(
                e,
                format!("sync 1: Custom({TARGET_IMPAIRED})"),
                "R-1 refuses the 15% sync 75"
            );
        }
        Ok((paid0, _)) => {
            let ok = |vl| n1_oi_try_shape(vl, REVIEWER_CONSUMED);
            let accepted = ok(514_001_513).expect("reviewer boundary accepted");
            assert_eq!(accepted.0, paid0);
            let refused = ok(514_001_514).expect_err("reviewer boundary + 1 refused");
            println!("N1OI-REVIEWER 514001513 OK, 514001514 -> {refused}");
            assert_eq!(refused, format!("Custom({OI_RESERVATION_VIOLATED})"));
        }
    }
}
