// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
#![allow(dead_code)]
//! Security review 2026-10-03 (wrapper 7a3ac04c), regression tests for H-1 and B-2.
//!
//! H-1 (HIGH): on a NON-bound Earn vault a tag 75 priced at a collapsed NAV bought the existing
//! holders' recoverable receivable for dust. Live OTC (6Y4bfYLW, slot 507,133,571): registry pot
//! available principal 3 atoms, sibling pot over-impaired (floored to 0), 2e9 shares. The
//! reviewer's PoC (`sec_final_low_nav_entry`) minted a 1,000,000-atom depositor 99.9997% of the
//! supply. Fix: refuse (Custom 91) when EITHER pot is over-impaired, and when
//! `nav * LP_VAULT_MAX_PRICE_COLLAPSE (1,000) < total shares` on the final pricing NAV.
//! R-1 (review of bc228e1b) adds a vault impairment-ratio pause (> 10% of total principal);
//! see tests/sec_r1_impairment_pause.rs. Tests here that priced deposits above 10% now pin it.
//!
//! B-2 (MEDIUM): permissionless tag 91 into an over-impaired pot moved Earn holders' backing into
//! a pot priced at 0, lowering NAV. Fix: refuse an over-impaired DESTINATION (Custom 91).
//!
//! Tag 77 (redemption) is never gated by either guard.
//!
//! Harness copied verbatim from tests/nonbound_nav_floor.rs. `PERC_PROG_SO` overrides the
//! program bytes, so the same tests run as negative controls against other builds.
//! Harness copied from tests/nonbound_redeem_cross_pot.rs. `PERC_PROG_SO` overrides the program
//! bytes, so the same tests run as a negative control against the pre-fix build.

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

/// THE REVIEWER'S EXPLOIT (sec_final_low_nav_entry, OTC row): refused 91. Both guards fire here
/// (sibling over-impaired, and NAV 3 * 1000 < 2e9); each is pinned on its own below.
#[test]
fn sec_otc_live_shape_low_nav_entry_is_refused_91() {
    let (mut env, v, atk, r) = low_nav_entry(OVER);
    let e = r.expect_err("7a3ac04c minted 99.9997% here; must refuse");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    assert_eq!(shares_of(&env, atk.lp_ata), 0);
    assert_eq!(registry_shares(&env, &v), 2 * P);
    // Either pot, any size.
    for d in [DOMAIN, SIBLING_DOMAIN] {
        for amt in [1u128, 1_000_000, 10 * P] {
            assert_refused_91_without_side_effects(&mut env, &v, &atk, amt, d);
        }
    }
}

/// The PRE-EXISTING half of H-1 (present on deployed f2fbf36d): no pot is over-impaired
/// (sibling impairment == principal exactly), but NAV = 3 atoms against 2e9 shares. The
/// share-price-collapse guard refuses it, and since R-1 so does the vault impairment-ratio
/// pause (~100% > 10%), which now runs first.
#[test]
fn sec_collapsed_price_with_no_over_impaired_pot_is_refused_91() {
    let (mut env, v, atk, r) = low_nav_entry(P);
    for l in [v.ledger, v.sibling_ledger] {
        if let Some(a) = env.svm.get_account(&l) {
            let led = state::read_backing_domain_ledger(&a.data).expect("ledger");
            assert!(
                net_impairment(&led) <= led.total_principal_atoms,
                "no pot over-impaired"
            );
        }
    }
    let e = r.expect_err("collapsed NAV must refuse");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    assert_eq!(shares_of(&env, atk.lp_ata), 0);
    assert_refused_91_without_side_effects(&mut env, &v, &atk, 1_000_000, SIBLING_DOMAIN);
}

/// Inflate the registry's outstanding share count (no impairment anywhere). Since R-1 an
/// impairment-driven collapse is refused by the ratio pause long before `nav * 1000 < shares`,
/// so the collapse BACKSTOP is pinned on a synthetic share supply instead.
fn set_registry_shares(env: &mut Env, v: &Vault, total: u128) {
    let mut acct = env.svm.get_account(&v.registry).expect("registry");
    let mut r = state::read_lp_vault_registry(&acct.data).expect("registry decode");
    r.total_lp_shares_outstanding = total;
    state::write_lp_vault_registry(&mut acct.data, &r).expect("registry encode");
    env.svm.set_account(v.registry, acct).unwrap();
}

/// Collapse-backstop boundary (`LP_VAULT_MAX_PRICE_COLLAPSE`), on an UNIMPAIRED vault (NAV = 2P,
/// so R-1 does not fire): total shares T = nav * 1000 is accepted and priced exactly; one share
/// more is refused 91.
#[test]
fn sec_price_collapse_threshold_is_exact() {
    let at = |t: u128| {
        let (mut env, v) = otc_env(SIBLING_DOMAIN, 0);
        set_registry_shares(&mut env, &v, t);
        let atk = new_actor(&mut env, &v);
        let r = try_deposit(&mut env, &atk, 1_000_000, DOMAIN);
        (r, shares_of(&env, atk.lp_ata))
    };
    let t = 2 * P * 1_000;
    let (r, s) = at(t);
    r.expect("nav * 1000 == shares is NOT collapsed");
    assert_eq!(s, floor_mul_div(1_000_000, t, 2 * P));
    let (r, s) = at(t + 1);
    let e = r.expect_err("nav * 1000 < shares is collapsed");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    assert_eq!(s, 0);
}

/// The collapse test uses the FINAL pricing NAV: harvestable LP fees (#411) count. Unimpaired
/// vault, T = 1000 * (2P + 1,000,000): NAV before fees = 2P (refused); with 1,000,000
/// harvestable it is exactly T / 1000 (accepted, priced on the fee-inclusive NAV).
#[test]
fn sec_harvestable_fees_count_toward_the_collapse_threshold() {
    let t = 1_000 * (2 * P + 1_000_000);
    let setup_at = |fees: u128| {
        let (mut env, v) = otc_env(SIBLING_DOMAIN, 0);
        set_registry_shares(&mut env, &v, t);
        if fees != 0 {
            let mut acct = env.svm.get_account(&env.market).expect("market");
            let (mut cfg, mut g) = state::read_market(&acct.data).expect("read market");
            cfg.lp_fee_accrued_atoms += fees;
            g.insurance += fees;
            g.vault += fees;
            state::write_market(&mut acct.data, &cfg, &g).expect("write market");
            env.svm.set_account(env.market, acct).unwrap();
            let bal = token_amount(&env.svm, env.vault_token);
            let (mint, va) = (env.collateral_mint, vault_authority(&env));
            set_token(&mut env.svm, env.vault_token, mint, va, bal + fees as u64);
        }
        let atk = new_actor(&mut env, &v);
        let r = try_deposit(&mut env, &atk, 1_000_000, DOMAIN);
        (r, shares_of(&env, atk.lp_ata))
    };
    let (r, _) = setup_at(0);
    assert!(has_code(&r.expect_err("2P * 1000 < T"), TARGET_IMPAIRED));
    let (r, s) = setup_at(1_000_000);
    r.expect("fees lift NAV to the threshold");
    assert_eq!(
        s,
        floor_mul_div(1_000_000, t, 2 * P + 1_000_000),
        "priced on the fee-inclusive NAV"
    );
}

/// Reviewer's third row: registry pot nearly empty but the sibling is healthy (NAV = P + 3).
/// Not collapsed and no pot over-impaired, but the vault is ~50% impaired: since R-1 the
/// deposit is refused 91 with no side effects, into either pot (bc228e1b accepted it at the
/// ordinary price, buying half of the registry pot's later recovery at a discount).
#[test]
fn sec_low_registry_pot_with_healthy_sibling_is_paused_by_r1() {
    let (mut env, v, atk, r) = low_nav_entry(0);
    let e = r.expect_err("R-1: vault impairment ~50% > 10%");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    assert_eq!(shares_of(&env, atk.lp_ata), 0);
    for d in [DOMAIN, SIBLING_DOMAIN] {
        assert_refused_91_without_side_effects(&mut env, &v, &atk, 1_000_000, d);
    }
}

/// A fully healthy vault: deposits into either pot accepted, priced 1:1 on NAV.
#[test]
fn sec_healthy_vault_accepts_deposits_into_both_pots() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, P, DOMAIN);
    deposit(&mut env, &v, P, SIBLING_DOMAIN);
    let atk = new_actor(&mut env, &v);
    try_deposit(&mut env, &atk, 100_000_000, DOMAIN).expect("registry pot");
    try_deposit(&mut env, &atk, 100_000_000, SIBLING_DOMAIN).expect("sibling pot");
    assert_eq!(shares_of(&env, atk.lp_ata), 200_000_000);
}

/// Tag 77 stays open while deposits are paused: in the over-impaired state a holder exits through
/// the healthy pot and is paid exactly the floored NAV share; the paused deposit is still refused
/// afterwards.
#[test]
fn sec_77_redeems_while_deposits_are_paused() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    let probe = new_actor(&mut env, &v);
    assert_refused_91_without_side_effects(&mut env, &v, &probe, 1_000_000, DOMAIN);
    let t = registry_shares(&env, &v);
    let shares = shares_of(&env, v.lp_ata);
    let owed = floor_mul_div(shares, P, t);
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 through the healthy pot must work while 75 is paused");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, owed);
    assert_eq!(registry_shares(&env, &v), t - shares);
    assert_refused_91_without_side_effects(&mut env, &v, &probe, 1_000_000, DOMAIN);
}

/// Same, in the exact live OTC shape (3 atoms in the registry pot): 77 is not refused by any
/// 91 guard (whatever it pays, it never fails with Custom 91).
#[test]
fn sec_77_is_never_refused_91_in_the_live_otc_shape() {
    let (mut env, v, _atk, _) = low_nav_entry(OVER);
    let shares = shares_of(&env, v.lp_ata);
    request(&mut env, &v, shares);
    let r = execute(&mut env, &v, DOMAIN);
    eprintln!(
        "77 in the live OTC shape: {:?}",
        r.as_ref().map_err(|e| code_of(e))
    );
    match r {
        Ok(()) => assert_eq!(
            token_amount(&env.svm, v.dest) as u128,
            floor_mul_div(shares, 3, 2 * P)
        ),
        Err(e) => assert!(
            !has_code(&e, TARGET_IMPAIRED),
            "77 must never be gated by 91: {}",
            code_of(&e)
        ),
    }
}

/// B-2: tag 91 INTO an over-impaired pot is refused 91 with no state change, both when the loss
/// is only visible after the in-instruction sync (lazy ledger) and when it is already booked.
/// Amounts: a small move and the SI-style "deficit + 0.1%" repair the app used to prepend.
#[test]
fn sec_91_refuses_an_over_impaired_destination() {
    for booked in [false, true] {
        let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
        if booked {
            book_synced_impairment(&mut env, v.sibling_ledger, OVER);
        }
        for amt in [1_000_000u128, (OVER - P) + (OVER - P) / 1000] {
            let market_before = env.svm.get_account(&env.market).unwrap().data;
            let l_before = env.svm.get_account(&v.ledger).unwrap().data;
            let s_before = env.svm.get_account(&v.sibling_ledger).unwrap().data;
            let e = rebalance(&mut env, &v, DOMAIN, SIBLING_DOMAIN, amt).expect_err("must refuse");
            assert!(
                has_code(&e, TARGET_IMPAIRED),
                "booked={booked} amt={amt}: {}",
                code_of(&e)
            );
            assert_eq!(
                env.svm.get_account(&env.market).unwrap().data,
                market_before
            );
            assert_eq!(env.svm.get_account(&v.ledger).unwrap().data, l_before);
            assert_eq!(
                env.svm.get_account(&v.sibling_ledger).unwrap().data,
                s_before
            );
        }
    }
    // Mirrored: registry pot over-impaired, move from the sibling into it.
    let (mut env, v) = otc_env(DOMAIN, OVER);
    let e = rebalance(&mut env, &v, SIBLING_DOMAIN, DOMAIN, 1_000_000).expect_err("must refuse");
    assert!(has_code(&e, TARGET_IMPAIRED), "mirrored: {}", code_of(&e));
}

/// Tag 91 still works into a healthy, a merely-impaired (impairment < principal) and a boundary
/// (impairment == principal) destination; principal moves 1:1 and NAV is unchanged. Up to the
/// R-1 limit (10% of total principal = 200,000,000) a deposit after the move prices at par (H-1
/// entry reading); above it the deposit is paused (91) while 91 itself is unaffected.
#[test]
fn sec_91_still_moves_into_a_non_over_impaired_destination() {
    for dest_impairment in [0u128, 200_000_000, 400_000_000, P] {
        let (mut env, v) = otc_env(SIBLING_DOMAIN, dest_impairment);
        let amt = 100_000_000u128;
        let src_p = ledger_of(&env.svm, v.ledger).total_principal_atoms;
        let dst_p = ledger_of(&env.svm, v.sibling_ledger).total_principal_atoms;
        rebalance(&mut env, &v, DOMAIN, SIBLING_DOMAIN, amt)
            .unwrap_or_else(|e| panic!("dest impairment {dest_impairment}: {}", code_of(&e)));
        assert_eq!(
            ledger_of(&env.svm, v.ledger).total_principal_atoms,
            src_p - amt
        );
        let sl = ledger_of(&env.svm, v.sibling_ledger);
        assert_eq!(sl.total_principal_atoms, dst_p + amt);
        assert_eq!(
            net_impairment(&sl),
            dest_impairment,
            "impairment stays with the pot"
        );
        // H-1 (2026-10-05): an ENTRY after the move prices at PAR (2P), whatever the move did to
        // the destination's receivable. This also pins the closure of the "91 dips the entry"
        // attack: the move pays the destination's receivable down with the vault's own atoms,
        // which dipped the rejected `min(P, held + receivable)` entry reading by up to `amt`.
        let atk = new_actor(&mut env, &v);
        let t = registry_shares(&env, &v);
        if dest_impairment * 10 > 2 * P {
            assert_refused_91_without_side_effects(&mut env, &v, &atk, 100_000_000, DOMAIN);
            continue;
        }
        try_deposit(&mut env, &atk, 100_000_000, DOMAIN).expect("deposit after the move");
        assert_eq!(
            shares_of(&env, atk.lp_ata),
            floor_mul_div(100_000_000, t, 2 * P),
            "dest impairment {dest_impairment}"
        );
    }
}
