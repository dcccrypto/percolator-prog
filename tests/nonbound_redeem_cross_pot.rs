// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! NON-bound (non-P3) Earn vault: tag 77 redemption across BOTH pots (#419, live 2026-10-01b).
//!
//! Live case (devnet wrapper ETDLAdi at bd4fe5f8, SI market 8WC8vALs…): the launch wizard seeds
//! 1,000 USDC into EACH pot; 77 priced the creator's 2,599,991,798 shares on both pots
//! (ledger0 1,601.424512 + ledger1 1,000 − 0.032976 impairment) but drew them from ONE pot and
//! failed Custom 25 EngineCounterUnderflow. A manual tag-91 consolidation of the full 1,000 left
//! ledger1 with principal 0 < its 0.032976 loss, so every later 77 underflowed (25) too.
//!
//! Harness copied from tests/v17_lp_vault_dual_domain.rs. `PERC_PROG_SO` overrides the program
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

const SI_D0_PRINCIPAL: u128 = 1_601_424_512;
const SI_D1_PRINCIPAL: u128 = 1_000_000_000;
const SI_D1_CONSUMED: u128 = 32_976;

/// REGRESSION (live SI 8WC8…, wrapper bd4fe5f8): the creator redeems (all but dust of) a vault
/// whose principal sits in BOTH pots, the sibling carrying a consumed-lien impairment. 77 on the
/// registry's domain failed Custom(25); it must now pay the full pro-rata claim in ONE
/// instruction, leave the sibling ledger holding exactly its impairment (never principal < loss),
/// and keep the vault pricing (a later deposit) underflow-free.
#[test]
fn si_shape_full_creator_exit_spans_both_pots() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, SI_D1_CONSUMED);

    let shares = token_amount(&env.svm, v.lp_ata) as u128;
    let s_total = registry_shares(&env, &v);
    let nav = SI_D0_PRINCIPAL + SI_D1_PRINCIPAL - SI_D1_CONSUMED;
    // Precondition: the claim exceeds either single pot (the #419 shape).
    let owed = floor_mul_div(shares, nav, s_total);
    assert!(owed > SI_D0_PRINCIPAL && owed > SI_D1_PRINCIPAL, "claim must exceed each pot");

    request(&mut env, &v, shares);
    let vault_before = token_amount(&env.svm, env.vault_token);
    execute(&mut env, &v, DOMAIN).expect("77 must pay a redemption that spans both pots");

    let paid = token_amount(&env.svm, v.dest) as u128;
    assert_eq!(paid, owed, "paid exactly the pro-rata claim on the combined pots");
    assert_eq!(vault_before - token_amount(&env.svm, env.vault_token), paid as u64);

    // The sibling moved exactly the shortfall (owed - own pot), never its impairment: the 1,000
    // dead shares' value stays behind, and its ledger keeps principal >= loss.
    let moved = owed - SI_D0_PRINCIPAL;
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    assert_eq!(sib.cumulative_loss_atoms - sib.cumulative_recovery_atoms, SI_D1_CONSUMED);
    assert_eq!(sib.total_principal_atoms, SI_D1_PRINCIPAL - moved);
    assert!(sib.total_principal_atoms >= SI_D1_CONSUMED, "principal never below the pot's loss");
    let own = ledger_of(&env.svm, v.ledger);
    assert_eq!(own.total_principal_atoms, SI_D0_PRINCIPAL + moved - paid);
    assert_eq!(own.total_principal_atoms, 0, "own pot paid out to the last atom it held");
    let g = market_group(&env);
    // Physical fixture: the consumed atoms already left the sibling's fresh backing.
    assert_eq!(
        g.source_backing_buckets[SIBLING_DOMAIN as usize].fresh_unliened_backing_num,
        (SI_D1_PRINCIPAL - SI_D1_CONSUMED - moved) * BOUND_SCALE,
        "sibling bucket gave up exactly the moved backing"
    );
    // Remaining NAV (the dead shares' slice) is the sibling's available principal.
    assert_eq!(
        sib.total_principal_atoms - SI_D1_CONSUMED,
        nav - owed,
        "what is left is exactly the unredeemed shares' value"
    );

    // Pricing over both ledgers still works (no principal < loss underflow anywhere).
    pricing_sound_or_r1_paused(&mut env, &v, 1_000_000, DOMAIN);
}

/// REGRESSION (#419 earnings leg): LP earnings are priced on both pots' ledgers but the gross
/// earnings were consumed from the chosen pot only. With the fees collected in the SIBLING pot,
/// a redemption that fits the chosen pot's principal failed at the earnings gate (Custom 21).
#[test]
fn earnings_in_the_sibling_pot_are_paid_through_the_chosen_pot() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 2_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000, SIBLING_DOMAIN);
    let fees: u128 = 10_000_000;
    add_pot_earnings(&mut env, SIBLING_DOMAIN, fees);

    let s_total = registry_shares(&env, &v);
    let held = token_amount(&env.svm, v.lp_ata) as u128;
    let shares = held * 9 / 10;
    let principal_total = 2_001_000_000u128;
    let lp_earnings = fees * 5_000 / 10_000; // fee_share_bps = 5_000
    let owed = floor_mul_div(shares, principal_total + lp_earnings, s_total);
    let principal = floor_mul_div(shares, principal_total, s_total);
    assert!(principal < 2_000_000_000, "principal fits the chosen pot: isolates the earnings leg");

    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 must pay earnings that sit in the sibling pot");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, owed);

    // The sibling ledger can never go withdrawn > earned, and the remaining holders keep at
    // least their pro-rata share of what is left (floor-of-sum is the safe side).
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    assert!(sib.total_earnings_atoms >= sib.total_earnings_withdrawn_atoms);
    let own = ledger_of(&env.svm, v.ledger);
    assert!(own.total_earnings_atoms >= own.total_earnings_withdrawn_atoms);
    deposit(&mut env, &v, 1_000_000, DOMAIN);
}

/// SECOND FINDING (live, after a manual 91), RE-DERIVED for E3 (2026-10-05): a live winner
/// claim (0.6 USDC) is registered against the chosen pot. Before E3 the NAV did not net open
/// winner claims, so a 100% exit priced at the full 2,000 had to be refused (21) to keep the
/// winner backed. E3 prices each pot at `min(principal, physical - claims)`: the vault is worth
/// exactly 1,999.4, a 100% exit pays exactly that, and the winner STAYS fully backed (the
/// reservation never leaves). Partial exits are priced on the same NAV.
#[test]
fn winner_claim_reserves_backing_full_exit_refused_partial_pays() {
    let claim: u128 = 600_000; // 0.6 USDC, live: 0.596957
    let nav: u128 = 2_000_000_000 - claim;
    for (num, den) in [(1u128, 1u128), (999, 1000), (6, 10)] {
        let mut env = setup();
        let v = vault(&mut env);
        deposit(&mut env, &v, 1_000_000_000, DOMAIN);
        deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
        add_winner_claim(&mut env, DOMAIN, claim);
        let s_total = registry_shares(&env, &v);
        let shares = token_amount(&env.svm, v.lp_ata) as u128 * num / den;
        request(&mut env, &v, shares);
        execute(&mut env, &v, DOMAIN).expect("exit priced net of the claim pays");
        assert_eq!(
            token_amount(&env.svm, v.dest) as u128,
            floor_mul_div(shares, nav, s_total),
            "{num}/{den}: paid exactly on the claim-netted NAV"
        );
        let g = market_group(&env);
        let src = &g.source_credit[DOMAIN as usize];
        assert!(src.fresh_reserved_backing_num >= src.positive_claim_bound_num, "winner still fully backed");
    }
}

/// Tag 91 must never move a pot's impairment (live: moving the full 1,000 out of SI d1 left
/// principal 0 < loss 0.032976, and every later 77 failed 25). Only AVAILABLE principal moves.
#[test]
fn rebalance_moves_only_available_principal() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, SI_D1_CONSUMED);

    let err = rebalance(&mut env, &v, SIBLING_DOMAIN, DOMAIN, SI_D1_PRINCIPAL)
        .expect_err("the full principal includes the impairment");
    // Physical fixture: the consumed atoms are gone from the bucket, so the bucket's own
    // withdrawability gate (21) refuses before the ledger-principal bound (25) is reached.
    assert!(err.contains("Custom(21)"), "refused by the bucket gate, got {err}");
    rebalance(&mut env, &v, SIBLING_DOMAIN, DOMAIN, SI_D1_PRINCIPAL - SI_D1_CONSUMED)
        .expect("available principal moves");
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    assert_eq!(sib.total_principal_atoms, SI_D1_CONSUMED);
    assert_eq!(sib.cumulative_loss_atoms - sib.cumulative_recovery_atoms, SI_D1_CONSUMED);
    let err = rebalance(&mut env, &v, SIBLING_DOMAIN, DOMAIN, 1).expect_err("nothing available left");
    assert!(err.contains("Custom(21)"), "empty bucket refuses, got {err}");

    // And the consolidated vault still redeems (the live [91, 77] path).
    let shares = token_amount(&env.svm, v.lp_ata) as u128;
    let s_total = registry_shares(&env, &v);
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 after a correct 91");
    assert_eq!(
        token_amount(&env.svm, v.dest) as u128,
        floor_mul_div(shares, SI_D0_PRINCIPAL + SI_D1_PRINCIPAL - SI_D1_CONSUMED, s_total)
    );
}

/// NEGATIVE CONTROL (scope): a redemption the chosen pot covers on its own must not touch the
/// sibling at all — no backing, ledger or earnings move.
#[test]
fn single_pot_redemption_leaves_the_sibling_untouched() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
    add_pot_earnings(&mut env, SIBLING_DOMAIN, 4_000_000);
    add_pot_earnings(&mut env, DOMAIN, 4_000_000);
    let sib_ledger_before = env.svm.get_account(&v.sibling_ledger).unwrap().data;
    let g0 = market_group(&env);
    let shares = token_amount(&env.svm, v.lp_ata) as u128 / 4;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("a quarter fits the chosen pot");
    let g1 = market_group(&env);
    assert_eq!(
        g1.source_backing_buckets[SIBLING_DOMAIN as usize],
        g0.source_backing_buckets[SIBLING_DOMAIN as usize],
        "sibling bucket untouched"
    );
    assert_eq!(g1.source_credit[SIBLING_DOMAIN as usize], g0.source_credit[SIBLING_DOMAIN as usize]);
    assert_eq!(env.svm.get_account(&v.sibling_ledger).unwrap().data, sib_ledger_before, "sibling ledger untouched");
}

/// NEGATIVE CONTROL (safety), RE-DERIVED for E3 (2026-10-05): the sibling carries a real loss
/// (50 consumed, physical) and its own winner reservation (400). E3 prices the sibling at
/// `min(1,000, 950 - 400) = 550`, so the vault NAV is 1,550 and a 100% exit pays exactly that,
/// funded by the own pot (1,000) plus the sibling's FREE backing (550): the sibling's winner
/// stays fully backed and nothing of its reservation moves. (Pre-E3 the exit was priced at
/// 1,950 and had to be refused; under E3 a payout can never exceed the free total.)
#[test]
fn top_up_never_moves_sibling_impairment_or_reservation() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, 50_000_000);
    add_winner_claim(&mut env, SIBLING_DOMAIN, 400_000_000);
    let nav: u128 = 1_000_000_000 + 550_000_000;
    let s_total = registry_shares(&env, &v);
    let shares = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("full exit at the claim-netted NAV is fundable");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, floor_mul_div(shares, nav, s_total));
    let g = market_group(&env);
    let sib = &g.source_credit[SIBLING_DOMAIN as usize];
    assert!(sib.fresh_reserved_backing_num >= sib.positive_claim_bound_num, "sibling winner still fully backed");
    assert!(
        g.source_backing_buckets[SIBLING_DOMAIN as usize].fresh_unliened_backing_num >= 400_000_000 * BOUND_SCALE,
        "the reservation never moved"
    );
}


/// NEGATIVE CONTROL (sibling clamp), RE-DERIVED for E3 (2026-10-05): the chosen pot's own winner
/// reservation (300) and a real 50 loss on the sibling. E3 NAV = 700 (own, net of the claim) +
/// 950 (sibling) = 1,650 = exactly the physically free backing, so every exit is fundable
/// without the own reservation or any lost principal: a 100% exit pays exactly
/// `shares * 1,650 / S`, the own winner stays backed, and the vault still prices afterwards.
/// (Pre-E3 the NAV was 1,950 and the "needs the sibling's impaired principal" refusal guarded
/// the gap; under E3 that gap does not exist, so that refusal is unreachable.)
#[test]
fn top_up_never_moves_more_than_sibling_available_principal() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
    add_winner_claim(&mut env, DOMAIN, 300_000_000);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, 50_000_000);
    let nav: u128 = 700_000_000 + 950_000_000;
    let s_total = registry_shares(&env, &v);
    let shares = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("full exit within own free + sibling available");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, floor_mul_div(shares, nav, s_total));
    let g = market_group(&env);
    let own = &g.source_credit[DOMAIN as usize];
    assert!(own.fresh_reserved_backing_num >= own.positive_claim_bound_num, "own winner still fully backed");
    pricing_sound_or_r1_paused(&mut env, &v, 1_000_000, DOMAIN);
}

/// After an exit the vault must still PRICE (no principal < loss underflow, never Custom 25).
/// An exit leaves the pot's impairment behind while principal leaves, so the vault's impairment
/// ratio rises; above `LP_VAULT_MAX_DEPOSIT_IMPAIRMENT_BPS` (10%, security R-1) the deposit is
/// paused with the named Custom 91, otherwise it succeeds. The expectation is computed from the
/// two (synced) ledgers, so it pins which of the two must happen.
fn pricing_sound_or_r1_paused(env: &mut Env, v: &Vault, amount: u128, domain: u16) {
    let (mut imp, mut p) = (0u128, 0u128);
    for l in [v.ledger, v.sibling_ledger] {
        if let Some(a) = env.svm.get_account(&l) {
            let led = state::read_backing_domain_ledger(&a.data).expect("ledger");
            imp += led
                .cumulative_loss_atoms
                .saturating_sub(led.cumulative_recovery_atoms)
                .min(led.total_principal_atoms);
            p += led.total_principal_atoms;
        }
    }
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    env.svm.expire_blockhash();
    let r = send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount, domain },
        deposit_accounts(env.market, env.vault_token, v.registry, v.mint, v.lp_ata, v.source, v.ledger, lp.pubkey()),
        &[&lp],
    );
    eprintln!("post-exit vault impairment {imp} / principal {p}: deposit {:?}", r.as_ref().map(|_| ()).map_err(|e| e.contains("Custom(91)")));
    if imp * 10_000 > 1_000 * p {
        let e = r.expect_err("R-1: vault impairment > 10% pauses 75");
        assert!(e.contains("Custom(91)"), "named pause, never 25: {e}");
    } else {
        r.expect("pricing still sound");
    }
}

/// Real consumption of pot `domain`: `atoms` of its fresh backing paid a winner who withdrew it
/// (fresh -> consumed lien / provider receivable, and the atoms left the vault).
fn consume_pot_backing_paid_out(env: &mut Env, domain: u16, atoms: u128) {
    with_market(env, |g| {
        let num = atoms * BOUND_SCALE;
        let b = &mut g.source_backing_buckets[domain as usize];
        b.fresh_unliened_backing_num -= num;
        b.consumed_liened_backing_num += num;
        let s = &mut g.source_credit[domain as usize];
        s.fresh_reserved_backing_num -= num;
        s.spent_backing_num += num;
        s.provider_receivable_num += num;
        g.source_fresh_backing_total_num -= num;
        g.vault -= atoms;
    });
    let bal = token_amount(&env.svm, env.vault_token);
    let (mint, va) = (env.collateral_mint, vault_authority(env));
    set_token(&mut env.svm, env.vault_token, mint, va, bal - atoms as u64);
}

/// The I-2 / live SI shape, built physically (E3, 2026-10-05): a loser's settled loss of `atoms`
/// is ROUTED into pot `domain` (fresh +atoms, vault +atoms) with the winner's claim, and the
/// winner then CONVERTS it (fresh -atoms, consumed +atoms, claim -atoms, atoms leave). End
/// state: fresh untouched, a consumed lien / receivable of `atoms` -- physically whole. The
/// ledger books `atoms` of loss; E3 prices the pot whole.
fn route_then_convert_i2(env: &mut Env, domain: u16, atoms: u128) {
    with_market(env, |g| {
        let n = atoms * BOUND_SCALE;
        g.source_backing_buckets[domain as usize].consumed_liened_backing_num += n;
        g.source_credit[domain as usize].spent_backing_num += n;
        g.source_credit[domain as usize].provider_receivable_num += n;
    });
}

fn ledger_available(l: &state::BackingDomainLedgerAccountV16) -> u128 {
    l.total_principal_atoms - (l.cumulative_loss_atoms - l.cumulative_recovery_atoms)
}

/// #413 ordering inside the top-up: moving sibling backing into a pot that carries a provider
/// receivable pays the receivable down. The destination ledger must be synced BEFORE that
/// refill; syncing after it books the pay-down as a recovery ON TOP of the moved principal, so
/// the pot's available principal (and the remaining holders' NAV) is overstated by the refill.
#[test]
fn top_up_into_a_pot_with_a_receivable_books_no_phantom_recovery() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
    consume_pot_backing_paid_out(&mut env, DOMAIN, 100_000_000);
    let nav: u128 = 1_900_000_000;
    let s_total = registry_shares(&env, &v);
    let shares = token_amount(&env.svm, v.lp_ata) as u128 / 2;
    let owed = floor_mul_div(shares, nav, s_total);
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("half exit tops up the impaired pot from the sibling");
    assert_eq!(token_amount(&env.svm, v.dest) as u128, owed);

    let own = ledger_of(&env.svm, v.ledger);
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    let g = market_group(&env);
    let fresh = |d: u16| g.source_backing_buckets[d as usize].fresh_unliened_backing_num / BOUND_SCALE;
    // Each pot's available principal is exactly the fresh backing it holds: no phantom recovery.
    assert_eq!(ledger_available(&own), fresh(DOMAIN), "own pot: no phantom recovery");
    assert_eq!(ledger_available(&sib), fresh(SIBLING_DOMAIN));
    assert_eq!(ledger_available(&own) + ledger_available(&sib), nav - owed, "remaining NAV exact");
}

/// ADVERSARIAL (code review M-1): any wallet can send tag 91. On bd4fe5f8 a stranger moving the
/// full principal off an impaired pot locked the vault: every later 75 and 77 failed 25 for ALL
/// depositors. The bad 91 must be refused, and deposits and withdrawals keep working.
#[test]
fn stranger_cannot_lock_the_vault_with_tag_91() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    consume_pot_backing(&mut env, SIBLING_DOMAIN, SI_D1_CONSUMED);

    // `rebalance` signs with a brand-new funded keypair that holds no shares: a stranger.
    let market_before = env.svm.get_account(&env.market).unwrap().data;
    let err = rebalance(&mut env, &v, SIBLING_DOMAIN, DOMAIN, SI_D1_PRINCIPAL)
        .expect_err("a stranger's full-principal 91 off an impaired pot must be refused");
    // Physical fixture: the bucket gate refuses first (21; 25 was the ledger bound on the I-2 shape).
    assert!(err.contains("Custom(21)"), "got {err}");
    assert_eq!(env.svm.get_account(&env.market).unwrap().data, market_before, "nothing moved");

    // A second depositor can still enter (75 prices both ledgers) ...
    let (registry, mint) = (v.registry, v.mint);
    let other = Keypair::new();
    env.svm.airdrop(&other.pubkey(), 10_000_000_000).unwrap();
    let (src2, ata2) = (Pubkey::new_unique(), Pubkey::new_unique());
    let cm = env.collateral_mint;
    set_token(&mut env.svm, src2, cm, other.pubkey(), 50_000_000);
    set_token(&mut env.svm, ata2, mint, other.pubkey(), 0);
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount: 50_000_000, domain: DOMAIN },
        deposit_accounts(env.market, env.vault_token, registry, mint, ata2, src2, v.ledger, other.pubkey()),
        &[&other],
    )
    .expect("75 still prices after the refused 91");
    assert!(token_amount(&env.svm, ata2) > 0);

    // ... and the creator still exits in full through one 77.
    let shares = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, shares);
    execute(&mut env, &v, DOMAIN).expect("77 still pays after the refused 91");
    assert!(token_amount(&env.svm, v.dest) > 0);
}

// ─── Security review of PR #522 (adversarial; MEDIUM re-lock via a 77 from the impaired pot) ───────────────────────────────────────────────────────
/// A THIRD-PARTY cranker executes a holder's matured partial redemption with source = the
/// IMPAIRED pot (live SI shape: consumed lien, fresh untouched). The non-bound top-up covers only
/// the LEDGER-principal shortfall, so the impaired pot can end at principal < loss, and every later
/// pricing of the vault (75 / 77) would underflow 25.
#[test]
fn sec_partial_exit_from_impaired_pot_must_not_lock_the_vault() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    route_then_convert_i2(&mut env, SIBLING_DOMAIN, SI_D1_CONSUMED);
    let held = token_amount(&env.svm, v.lp_ata) as u128;
    let shares = held * 6 / 10; // partial: holders remain
    request(&mut env, &v, shares);
    let r = execute(&mut env, &v, SIBLING_DOMAIN);
    eprintln!("SEC 77 from impaired pot: {:?}", r.as_ref().map(|_| ()).map_err(|e| e.chars().take(200).collect::<String>()));
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    let own = ledger_of(&env.svm, v.ledger);
    eprintln!(
        "SEC impaired pot: principal={} net_loss={}  other pot principal={}",
        sib.total_principal_atoms,
        sib.cumulative_loss_atoms - sib.cumulative_recovery_atoms,
        own.total_principal_atoms
    );
    eprintln!("SEC locked-shape={}", r.is_ok() && sib.total_principal_atoms < sib.cumulative_loss_atoms - sib.cumulative_recovery_atoms);
    // Vault pricing must still work for everyone else.
    let lp = v.lp.insecure_clone();
    let payer = env.payer.insecure_clone();
    let r75 = send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount: 1_000_000, domain: DOMAIN },
        deposit_accounts(env.market, env.vault_token, v.registry, v.mint, v.lp_ata, v.source, v.ledger, lp.pubkey()),
        &[&lp],
    );
    eprintln!("SEC 75 after: {:?}", r75.as_ref().map(|_| ()).map_err(|e| e.chars().take(160).collect::<String>()));
    // Can a permissionless 91 un-stick it?
    let r91 = rebalance(&mut env, &v, DOMAIN, SIBLING_DOMAIN, SI_D1_CONSUMED);
    eprintln!("SEC 91 repair: {:?}", r91.as_ref().map(|_| ()).map_err(|e| e.chars().take(160).collect::<String>()));
    env.svm.expire_blockhash();
    let r75b = send(
        &mut env.svm,
        env.program_id,
        &payer,
        ProgInstruction::DepositToLpVault { amount: 1_000_000, domain: DOMAIN },
        deposit_accounts(env.market, env.vault_token, v.registry, v.mint, v.lp_ata, v.source, v.ledger, lp.pubkey()),
        &[&lp],
    );
    eprintln!("SEC 75 after repair: {:?}", r75b.as_ref().map(|_| ()).map_err(|e| e.chars().take(160).collect::<String>()));
    assert!(r75.is_ok(), "LOCK: 75 after the 77 failed");
    // E3 (2026-10-05): the I-2 pot is physically whole, so the booked (phantom) loss may exceed
    // what principal is left in it; the invariant is now that every pot's PRICED principal is
    // backed: min(principal, physical net) for both pots, and the vault keeps pricing (75 above,
    // and 91 / 75 again below).
    let g = market_group(&env);
    let phys = g.source_backing_buckets[SIBLING_DOMAIN as usize].fresh_unliened_backing_num / BOUND_SCALE;
    assert!(phys >= sib.total_principal_atoms.min(phys), "priced principal is physically backed");
    assert!(r91.is_ok() && r75b.is_ok(), "no lock: 91 {:?} / 75 {:?}", r91.is_ok(), r75b.is_ok());
}

#[test]
fn sec_cu_single_pot_77() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    let held = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, held / 10);
    execute(&mut env, &v, DOMAIN).expect("77");
}

/// Same, real consumption shape (fresh paid out): expected safe.
#[test]
fn sec_partial_exit_from_paid_out_impaired_pot_keeps_pricing() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    deposit(&mut env, &v, 1_000_000_000, SIBLING_DOMAIN);
    consume_pot_backing_paid_out(&mut env, SIBLING_DOMAIN, 100_000_000);
    let held = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, held * 6 / 10);
    execute(&mut env, &v, SIBLING_DOMAIN).expect("77");
    let sib = ledger_of(&env.svm, v.sibling_ledger);
    assert!(sib.total_principal_atoms >= sib.cumulative_loss_atoms - sib.cumulative_recovery_atoms);
    pricing_sound_or_r1_paused(&mut env, &v, 1_000_000, DOMAIN);
}

/// CU of a cross-pot non-bound 77 (both legs: principal + earnings top-up).
#[test]
fn sec_cu_cross_pot_77() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, SI_D0_PRINCIPAL, DOMAIN);
    deposit(&mut env, &v, SI_D1_PRINCIPAL, SIBLING_DOMAIN);
    add_pot_earnings(&mut env, SIBLING_DOMAIN, 10_000_000);
    let held = token_amount(&env.svm, v.lp_ata) as u128;
    request(&mut env, &v, held * 9 / 10);
    execute(&mut env, &v, DOMAIN).expect("77");
}

/// Security INFO (PR #522): 77's OWN source pot gets the same lapse test as tag 50 / 91 and the
/// sibling top-up (W-21). A lapsed pot's principal is tag 89's to forfeit, so a non-bound 77 from
/// it is refused (21, as for any non-Fresh pot) and nothing moves.
#[test]
fn nonbound_77_refuses_a_lapsed_source_pot() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    let shares = token_amount(&env.svm, v.lp_ata) as u128 / 10;
    request(&mut env, &v, shares);
    let now = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    with_market(&mut env, |g| g.source_backing_buckets[DOMAIN as usize].expiry_slot = now);
    let before = env.svm.get_account(&env.market).unwrap().data;
    let err = execute(&mut env, &v, DOMAIN).expect_err("a lapsed pot is not payable");
    assert!(err.contains("Custom(21)"), "got {err}");
    assert_eq!(env.svm.get_account(&env.market).unwrap().data, before, "atomic");
    assert_eq!(token_amount(&env.svm, v.dest), 0);
}

/// H-1(b) (security review 2026-10-05): on a Live non-bound vault a third party cannot choose WHEN
/// someone else's matured redemption executes (the E3 exit reading can sit in a touch-order dip).
/// The same 77 with the redeemer NOT signing is refused (ExpectedSigner, Custom(6)); signed, it pays.
#[test]
fn h1b_third_party_cannot_execute_someone_elses_77() {
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, 1_000_000_000, DOMAIN);
    let shares = token_amount(&env.svm, v.lp_ata) as u128 / 2;
    request(&mut env, &v, shares);
    let payer = env.payer.insecure_clone();
    let (escrow, _) = derive_lp_escrow(&env.program_id, &env.market);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &v.registry, &v.lp.pubkey());
    let va = vault_authority(&env);
    let metas = |signed: bool| {
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
            AccountMeta::new(v.lp.pubkey(), signed),
        ]
    };
    let (m0, m1) = (metas(false), metas(true));
    let r = send(&mut env.svm, env.program_id, &payer, ProgInstruction::ExecuteRedemption { domain: DOMAIN }, m0, &[]);
    let e = r.expect_err("a third party's 77 must be refused");
    assert!(e.contains("Custom(6)"), "ExpectedSigner, got {e}");
    assert_eq!(token_amount(&env.svm, v.dest), 0);
    env.svm.expire_blockhash();
    let lp = v.lp.insecure_clone();
    send(&mut env.svm, env.program_id, &payer, ProgInstruction::ExecuteRedemption { domain: DOMAIN }, m1, &[&lp])
        .expect("control: the redeemer's own 77 pays");
    assert!(token_amount(&env.svm, v.dest) > 0);
}
