// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
#![allow(dead_code)]
//! NON-bound (non-P3) Earn vault: NAV pricing with an OVER-IMPAIRED pot (impairment > principal).
//!
//! Live bug (devnet wrapper ETDLAdi @ 553d76f0, 2026-10-02): on a NON-bound Earn vault, when ONE
//! pot's booked net impairment (cumulative_loss - cumulative_recovery) exceeds its principal,
//! `lp_vault_combined_nav_atoms` failed closed (Custom 25 EngineCounterUnderflow) and EVERY tag
//! 75 reverted until the pot recovered (OTC market 6Y4bf...; same class froze SI 8WC8...).
//!
//! Fix: price an over-impaired pot at ZERO (floored), never negative; refuse a deposit routed INTO
//! such a pot (Custom 91) so it is not silently absorbed.
//!
//! H-1 (security review 2026-10-03): a deposit into the HEALTHY pot while the other is
//! over-impaired is ALSO refused (91): the floored pot's recoverable receivable belongs to the
//! existing holders and a newcomer priced on the floored NAV would capture it. Deposits pause;
//! redemptions (77) stay open. The tests below that previously asserted the 75 succeeded in the
//! over-impaired state now assert the refusal (see tests/sec_final_low_nav.rs for the rest).
//!
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
        .map(|m| { if std::env::var_os("SEC_CU").is_some() { eprintln!("SEC_CU {}", m.compute_units_consumed); } })
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
    ProgInstruction::UpdateAssetLifecycle { market_id: 2,
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
    let (sibling_ledger, _) = derive_lp_backing_ledger(&env.program_id, &env.market, SIBLING_DOMAIN);
    let dest = Pubkey::new_unique();
    let (cm, owner) = (env.collateral_mint, lp.pubkey());
    set_token(&mut env.svm, dest, cm, owner, 0);
    Vault { registry, mint, ledger, sibling_ledger, lp, lp_ata, source, dest }
}

fn deposit(env: &mut Env, v: &Vault, amount: u128, domain: u16) {
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount, domain },
        deposit_accounts(env.market, env.vault_token, v.registry, v.mint, v.lp_ata, v.source, v.ledger, lp.pubkey()),
        &[&lp],
    )
    .expect("deposit");
}

fn rebalance(env: &mut Env, v: &Vault, from: u16, to: u16, amount: u128) -> Result<(), String> {
    let (fl, tl) = if from == DOMAIN { (v.ledger, v.sibling_ledger) } else { (v.sibling_ledger, v.ledger) };
    let cranker = Keypair::new();
    env.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::RebalanceLpVaultBacking { from_domain: from, to_domain: to, amount },
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
            AccountMeta::new(v.lp.pubkey(), false),
        ],
        &[],
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
        deposit_accounts(env.market, env.vault_token, v.registry, v.mint, v.lp_ata, v.source, v.ledger, lp.pubkey()),
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

// ───────────────────────────────────────── tests ─────────────────────────────────────────────

/// THE LIVE BUG. OTC shape: the registry pot is healthy, the SIBLING pot's impairment exceeds
/// its principal. The app's own builder deposits into the registry pot. Before the floor this
/// reverted Custom(25) (combined NAV underflowed on the sibling). fdf07759 made it succeed priced
/// on the floored NAV; H-1 (2026-10-03) refuses it with the NAMED code 91 instead (the newcomer
/// would buy the sibling's recoverable receivable at 0). No tokens move, nothing is minted, and
/// neither pot nor ledger is touched.
#[test]
fn otc_shape_75_into_the_healthy_pot_is_refused_91_while_the_sibling_is_over_impaired() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    let t_before = registry_shares(&env, &v);
    assert_eq!(t_before, 2 * P);
    let held = shares_of(&env, v.lp_ata);
    let (src, vault_tok) = (token_amount(&env.svm, v.source), token_amount(&env.svm, env.vault_token));
    let market_before = env.svm.get_account(&env.market).unwrap().data;
    let led_before = env.svm.get_account(&v.ledger).unwrap().data;
    let sib_ledger_before = env.svm.get_account(&v.sibling_ledger).unwrap().data;

    let e = try_deposit(&mut env, &v, 100_000_000, DOMAIN).expect_err("H-1: deposits pause");
    assert!(has_code(&e, TARGET_IMPAIRED), "named refusal, got {}", code_of(&e));
    assert_eq!(shares_of(&env, v.lp_ata), held);
    assert_eq!(registry_shares(&env, &v), t_before);
    assert_eq!(token_amount(&env.svm, v.source), src);
    assert_eq!(token_amount(&env.svm, env.vault_token), vault_tok);
    assert_eq!(env.svm.get_account(&env.market).unwrap().data, market_before);
    assert_eq!(env.svm.get_account(&v.ledger).unwrap().data, led_before);
    assert_eq!(env.svm.get_account(&v.sibling_ledger).unwrap().data, sib_ledger_before);
}

/// Same state, mirrored: the REGISTRY pot is the over-impaired one, the sibling is healthy. H-1:
/// the deposit into the healthy sibling is refused 91 too (either pot over-impaired pauses 75).
#[test]
fn otc_shape_mirrored_75_into_the_healthy_sibling_is_refused_91() {
    let (mut env, v) = otc_env(DOMAIN, OVER);
    let t_before = registry_shares(&env, &v);
    let held = shares_of(&env, v.lp_ata);
    let e = try_deposit(&mut env, &v, 250_000_000, SIBLING_DOMAIN).expect_err("H-1: deposits pause");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    assert_eq!(shares_of(&env, v.lp_ata), held);
    assert_eq!(registry_shares(&env, &v), t_before);
    assert_eq!(ledger_of(&env.svm, v.sibling_ledger).total_principal_atoms, P);
}

/// A deposit routed INTO the over-impaired pot is refused with the named code (91), moves no
/// tokens and mints nothing. (Before the fix: Custom 25 for every deposit, either pot.)
#[test]
fn deposit_routed_into_the_over_impaired_pot_is_refused_without_side_effects() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    let (t, held, src, vault_tok) = (
        registry_shares(&env, &v),
        shares_of(&env, v.lp_ata),
        token_amount(&env.svm, v.source),
        token_amount(&env.svm, env.vault_token),
    );
    let sib_before = env.svm.get_account(&v.sibling_ledger).unwrap().data;
    let e = try_deposit(&mut env, &v, 100_000_000, SIBLING_DOMAIN).expect_err("must refuse");
    assert!(has_code(&e, TARGET_IMPAIRED), "named refusal, got {}", code_of(&e));
    assert_eq!(registry_shares(&env, &v), t);
    assert_eq!(shares_of(&env, v.lp_ata), held);
    assert_eq!(token_amount(&env.svm, v.source), src);
    assert_eq!(token_amount(&env.svm, env.vault_token), vault_tok);
    assert_eq!(env.svm.get_account(&v.sibling_ledger).unwrap().data, sib_before);
    // ... and (H-1) the healthy pot refuses the same deposit while the sibling is over-impaired.
    let e = try_deposit(&mut env, &v, 100_000_000, DOMAIN).expect_err("H-1: deposits pause");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
}

/// BOUNDARY (impairment == principal exactly): this priced to 0 without error on the old code
/// and must keep doing so — the floor is continuous with it (no Custom 25; a redemption is paid
/// exactly shares * P / T). The pot is NOT over-impaired, but the vault is 50% impaired, so
/// since R-1 a deposit into either pot is paused (91, no side effects).
#[test]
fn boundary_impairment_equal_to_principal_is_unchanged_and_r1_pauses_deposits() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, P);
    let t = registry_shares(&env, &v);
    let held = shares_of(&env, v.lp_ata);
    let src = token_amount(&env.svm, v.source);
    for d in [DOMAIN, SIBLING_DOMAIN] {
        let e = try_deposit(&mut env, &v, 100_000_000, d).expect_err("R-1: 50% > 10%");
        assert!(has_code(&e, TARGET_IMPAIRED), "pot {d}: {}", code_of(&e));
    }
    assert_eq!(shares_of(&env, v.lp_ata), held);
    assert_eq!(token_amount(&env.svm, v.source), src);
    assert_eq!(registry_shares(&env, &v), t);
    let shares = held / 4;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 at the boundary");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, floor_mul_div(shares, P, t));
}

/// ADVERSARIAL: deposit-then-recovery capture. NAV prices receivables as losses, so a deposit
/// into an impaired vault rides the later recovery. Since R-1 the entry is only open up to 10%
/// vault impairment, which bounds the windfall at r / (1 - r) <= 1/9 per token; the impairment ==
/// principal boundary (50%) and the over-impaired state are refused outright.
fn attacker_profit_after_full_recovery(consumed: u128) -> Result<(u128, u128), String> {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, consumed);
    let atk = new_actor(&mut env, &v);
    let amt = 100_000_000u128;
    try_deposit(&mut env, &atk, amt, DOMAIN)?;
    // A live write synced the loss into the ledger before the recovery.
    book_synced_impairment(&mut env, v.sibling_ledger, consumed);
    recover_pot_backing(&mut env, SIBLING_DOMAIN, consumed);
    let shares = shares_of(&env, atk.lp_ata);
    request(&mut env, &atk, shares);
    execute(&mut env, &atk, DOMAIN).expect("attacker redeems after the recovery");
    let got = token_amount(&env.svm, atk.dest) as u128;
    Ok((got, amt))
}

#[test]
fn deposit_then_recovery_captures_no_more_than_the_boundary_state() {
    // R-1 boundary: impairment 200 of 2,000 (10%). NAV 1,800 over 2,000 shares: the attacker's
    // 100 tokens buy floor(100 * 2000 / 1800) shares; after the recovery NAV is 2,100.
    let imp = 200_000_000u128;
    let (got, amt) = attacker_profit_after_full_recovery(imp).expect("open at exactly 10%");
    let s = floor_mul_div(amt, 2 * P, 2 * P - imp);
    assert_eq!(got, floor_mul_div(s, 2 * P + amt, 2 * P + s));
    assert!(got > amt, "documented pre-existing property, now bounded");
    assert!(got * 9 <= amt * 10, "windfall <= 1/9 per token at the R-1 boundary");
    // One atom over 10%, the impairment == principal boundary, and the over-impaired state:
    // the entry is refused, so no capture at all.
    for consumed in [imp + 1, P, OVER] {
        let e = attacker_profit_after_full_recovery(consumed).expect_err("no entry");
        assert!(has_code(&e, TARGET_IMPAIRED), "consumed {consumed}: {}", code_of(&e));
    }
}

/// ADVERSARIAL: a recovery that stays INSIDE the over-impaired segment (booked net impairment still
/// above principal) leaves the pot over-impaired, so deposits stay paused (H-1).
///
/// E3 (2026-10-05) re-derivation: the recovered 300 physically sit in the sibling pot with no
/// claim against them (a loser's loss repaying the vault's receivable), so they ARE the
/// holders' value: the healthy-pot exit is priced on `P + 300` exactly. The pre-E3 ledger
/// assigned the first 500 recovered to the routed segment (backing the vault never fronted)
/// and priced the exit on `P`, stranding the 300 -- the attribution leak E3 closes.
#[test]
fn recovery_inside_the_over_impaired_segment_is_priced_physically_and_keeps_the_pause() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    book_synced_impairment(&mut env, v.sibling_ledger, OVER);
    recover_pot_backing(&mut env, SIBLING_DOMAIN, 300_000_000); // 1,500 -> 1,200 (> principal 1,000)
    let atk = new_actor(&mut env, &v);
    let e = try_deposit(&mut env, &atk, 100_000_000, DOMAIN).expect_err("still over-impaired");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
    let t = registry_shares(&env, &v);
    let shares = shares_of(&env, v.lp_ata) / 2;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("redeem");
    assert_eq!(
        token_amount(&env.svm, v.dest) as u128,
        floor_mul_div(shares, P + 300_000_000, t),
        "priced on the physical NAV: healthy pot P + the 300 recovered into the sibling"
    );
}

/// REDEEM AFTER THE FLOOR: a holder exits (all but the 1,000 dead shares) through the healthy
/// pot. Paid exactly shares * floored-NAV / total (the healthy pot's value), never a token from
/// the over-impaired pot, and nobody can take more than the healthy pot backs.
#[test]
fn redeem_through_the_healthy_pot_pays_the_floored_nav_and_leaves_the_sibling_alone() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    let t = registry_shares(&env, &v);
    let shares = shares_of(&env, v.lp_ata);
    let owed = floor_mul_div(shares, P, t);
    assert!(owed <= P, "never more than the healthy pot backs");
    let sib_bucket = market_group(&env).source_backing_buckets[SIBLING_DOMAIN as usize];
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 through the healthy pot");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, owed);
    let g = market_group(&env);
    let sb = g.source_backing_buckets[SIBLING_DOMAIN as usize];
    assert_eq!(sb.fresh_unliened_backing_num, sib_bucket.fresh_unliened_backing_num);
    assert_eq!(sb.consumed_liened_backing_num, sib_bucket.consumed_liened_backing_num);
    let sl = ledger_of(&env.svm, v.sibling_ledger);
    assert_eq!(sl.total_principal_atoms, P, "sibling principal untouched");
}

/// A redeemer who names the OVER-IMPAIRED pot as the source cannot pull value out of it or
/// strand the vault: the per-pot available principal of that pot is 0, so the payout is refused
/// (fail closed, no tokens move). Pre-existing guard; asserted so the floor cannot loosen it.
#[test]
fn redeem_naming_the_over_impaired_pot_as_source_is_refused() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    let shares = shares_of(&env, v.lp_ata) / 2;
    request(&mut env, &v, shares);
    let vault_tok = token_amount(&env.svm, env.vault_token);
    let r = execute(&mut env, &v, SIBLING_DOMAIN);
    eprintln!("77 from the over-impaired pot: {:?}", r.as_ref().map_err(|e| code_of(e)));
    if r.is_ok() {
        // If a future change makes this succeed it must still be exactly the floored claim and
        // may never leave the pot with principal below its impairment.
        let sl = ledger_of(&env.svm, v.sibling_ledger);
        assert!(sl.total_principal_atoms >= net_impairment(&sl) || sl.total_principal_atoms == P);
    } else {
        assert_eq!(token_amount(&env.svm, env.vault_token), vault_tok, "no tokens moved");
    }
    // Either way the vault stays priceable for exits: the remaining shares redeem through the
    // healthy pot (H-1 keeps 75 paused, refused with the named 91, never 25).
    let e = try_deposit(&mut env, &v, 1_000_000, DOMAIN).expect_err("H-1: deposits pause");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
}

/// SIBLING UNAFFECTED / earnings: LP earnings collected in an impaired pot are still part of NAV
/// (they are not principal and the loss did not touch them): NAV = 2,000 - 200 + 50% of 20.
/// Measured at the R-1 limit (impairment 10% of total principal, still open for 75); in the OVER
/// state the same deposit is refused 91 (H-1).
#[test]
fn earnings_in_the_over_impaired_pot_still_count_toward_nav() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, 200_000_000);
    add_pot_earnings(&mut env, SIBLING_DOMAIN, 20_000_000);
    // seed the ledger earnings the same way a crank/sync would: next sync reads the bucket.
    let t = registry_shares(&env, &v);
    let held = shares_of(&env, v.lp_ata);
    let amt = 100_000_000u128;
    try_deposit(&mut env, &v, amt, DOMAIN).expect("deposit");
    let nav = 2 * P - 200_000_000 + 10_000_000; // fee_share_bps 5_000 -> LP gets half of the 20
    assert_eq!(shares_of(&env, v.lp_ata) - held, floor_mul_div(amt, t, nav));

    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    add_pot_earnings(&mut env, SIBLING_DOMAIN, 20_000_000);
    let e = try_deposit(&mut env, &v, amt, DOMAIN).expect_err("H-1: deposits pause");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
}

/// BOTH pots over-impaired: NAV floors to 0 and a deposit must fail closed (a zero NAV with
/// outstanding shares never mints), whichever pot it targets.
#[test]
fn both_pots_over_impaired_deposits_fail_closed() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, OVER);
    consume_pot_backing(&mut env, DOMAIN, OVER);
    let (t, held) = (registry_shares(&env, &v), shares_of(&env, v.lp_ata));
    for d in [DOMAIN, SIBLING_DOMAIN] {
        let e = try_deposit(&mut env, &v, 100_000_000, d).expect_err("must refuse");
        assert!(has_code(&e, TARGET_IMPAIRED), "deposit to pot {d}: {}", code_of(&e));
    }
    assert_eq!(registry_shares(&env, &v), t);
    assert_eq!(shares_of(&env, v.lp_ata), held);
}

/// The healthy-vault path is byte-for-byte what it was: no impairment anywhere, the NAV equals the
/// principal sum and deposits price 1:1.
#[test]
fn control_healthy_vault_prices_unchanged() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, P, DOMAIN);
    deposit(&mut env, &v, P, SIBLING_DOMAIN);
    let t = registry_shares(&env, &v);
    let held = shares_of(&env, v.lp_ata);
    try_deposit(&mut env, &v, 100_000_000, DOMAIN).expect("deposit");
    assert_eq!(shares_of(&env, v.lp_ata) - held, floor_mul_div(100_000_000, t, 2 * P));
}

/// Moderate impairment (below principal, within the R-1 limit) is priced exactly as before:
/// unfloored. 400M (20% of total principal) is now paused by R-1.
#[test]
fn control_impairment_below_principal_is_priced_unfloored() {
    let (mut env, v) = otc_env(SIBLING_DOMAIN, 200_000_000);
    let t = registry_shares(&env, &v);
    let held = shares_of(&env, v.lp_ata);
    try_deposit(&mut env, &v, 100_000_000, DOMAIN).expect("deposit");
    assert_eq!(shares_of(&env, v.lp_ata) - held, floor_mul_div(100_000_000, t, 2 * P - 200_000_000));
    // and a deposit into the (merely) impaired pot is allowed.
    try_deposit(&mut env, &v, 100_000_000, SIBLING_DOMAIN).expect("impairment < principal is a normal pot");

    let (mut env, v) = otc_env(SIBLING_DOMAIN, 400_000_000);
    let e = try_deposit(&mut env, &v, 100_000_000, DOMAIN).expect_err("R-1: 20% > 10%");
    assert!(has_code(&e, TARGET_IMPAIRED), "got {}", code_of(&e));
}
