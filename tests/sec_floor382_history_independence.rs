// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
#![allow(dead_code)]
//! Upstream aeyakovenko/percolator-prog #382 ("automatic source-claim protection floor"), engine
//! fix aeyakovenko/percolator #271, program fix #486: a backing-domain loss that is claimed,
//! refilled by a loser payment and consumed again BETWEEN two depositor actions nets out in the
//! ledger's watermark counters (`cumulative_loss_atoms` / `cumulative_recovery_atoms`), so a
//! payout that read those counters depended on WHEN anyone looked.
//!
//! Our LP vault (Earn, tag 75 / tag 77) prices shares from the same backing-domain ledger
//! (`lp_vault_nav_atoms_floored`, `lp_vault_domain_available_principal_atoms` in
//! src/v16_program.rs). This file checks, on the real BPF program, that two histories with the
//! same loss -> refill -> second loss give the same NAV, share price and withdrawal payouts
//! whether or not a depositor action checkpointed the pot's ledger after the first loss, and that
//! owner + protocol value is conserved in both.
//!
//! Histories (same actions, only the position of B's deposit differs):
//!   CHECKPOINTED: A seeds both pots; loss X; B deposits d into the lossy pot (syncs + re-baselines
//!                 its ledger); loser refill R; second loss X2.
//!   AFTER REFILL: A seeds both pots; loss X; loser refill R; B deposits d; second loss X2.
//!   DELAYED:      A seeds both pots; loss X; loser refill R; second loss X2; B deposits d.
//! Then A and B each redeem all of their shares (tag 77). Entries (75) price at par (H-1), so
//! B's share count is timing-independent by construction; the property under test is the EXIT
//! side (NAV, share price, payouts) plus conservation.
//!
//! Harness copied from tests/nonbound_nav_floor.rs (same fixtures for physical consumption and
//! refill). Test only: no source change.

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
    let market_kp = Keypair::new(); // D26: InitMarket requires the market account's signature
    let market = market_kp.pubkey();
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
            AccountMeta::new(market, true),
            AccountMeta::new_readonly(collateral_mint, false),
        ],
        &[&admin, &market_kp],
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
        ProgInstruction::RequestRedeemLpSharesV22 { shares, min_payout_atoms: 1, keeper_ok: 0 },
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

// ───────────────────────────── #382 two-history helpers and tests ─────────────────────────────

/// A's seed in EACH pot.
const P: u128 = 1_000_000_000;
/// First loss: a winner's claim is paid out of the vault's pot (consumed lien, atoms leave).
const X: u128 = 60_000_000;
/// A loser's payment lands in the pot and pays the receivable down (refill).
const R: u128 = 50_000_000;
/// The refilled backing is consumed again by a second winner.
const X2: u128 = 60_000_000;
/// Starting collateral balance of each actor's source token account (see `ready_vault` / `new_actor`).
const START_BAL: u128 = 100_000_000_000;
/// Genesis dead-share floor: counted in `total_lp_shares_outstanding`, minted to nobody.
const DEAD: u128 = percolator_prog::constants::LP_VAULT_MINIMUM_LIQUIDITY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum History {
    /// B's deposit lands right after the first loss: it syncs the lossy pot's ledger (books X)
    /// and re-baselines its watermark, before the refill and the second loss.
    Checkpointed,
    /// B's deposit lands after the loser refill, before the second loss: the checkpoint sees the
    /// pot partly refilled (books X - R) and the second loss lands on the re-baselined watermark.
    CheckpointedAfterRefill,
    /// The same deposit lands only after the second loss: the ledger sees one net observation.
    Delayed,
    /// No depositor action at all between seed and redemption.
    None,
}

/// Everything a holder can observe, taken just before redemptions and after them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observed {
    // pricing, right before any redemption
    exit_nav: u128,
    supply: u128,
    /// exit NAV per share, scaled 1e9 (floor)
    price_e9: u128,
    a_shares: u128,
    b_shares: u128,
    // pot state right before redemption (physical)
    pot_fresh_atoms: u128,
    pot_consumed_atoms: u128,
    pot_principal: u128,
    sib_principal: u128,
    // redemption outcome
    a_payout: u128,
    b_payout: u128,
    /// NAV per share (1e9) after A redeemed, before B redeems (B's shares only; 0 if no B shares).
    price_e9_after_a: u128,
    supply_end: u128,
    vault_token_end: u128,
    /// Custom code tag 77 refused B's redemption with (0 = paid).
    b_redeem_refused_code: u32,
}

fn has_code(e: &str, code: u32) -> bool {
    e.contains(&format!("Custom({code})"))
}

/// Ledger counters as stored right before redemption. These are farm-facing and are asserted to
/// DIFFER between histories (proof each checkpoint happened); pricing never reads them.
#[derive(Clone, Copy, Debug)]
struct Counters {
    loss: u128,
    recovery: u128,
    watermark: u128,
}

/// Exit NAV of the non-bound vault computed from the public pricing functions the program uses
/// for tag 77 (`nonbound_available_e3` = `vault_lp_v18::nonbound_pot_available(principal,
/// pot_physical_net_atoms(..))` per pot; no earnings in these histories).
fn exit_nav(env: &Env, v: &Vault) -> u128 {
    let g = market_group(env);
    let mut nav = 0u128;
    for (d, l) in [(DOMAIN, v.ledger), (SIBLING_DOMAIN, v.sibling_ledger)] {
        let principal = match env.svm.get_account(&l) {
            Some(a) if !a.data.is_empty() => {
                state::read_backing_domain_ledger(&a.data).unwrap().total_principal_atoms
            }
            _ => 0,
        };
        let b = &g.source_backing_buckets[d as usize];
        let s = &g.source_credit[d as usize];
        let ins_cover = s
            .insurance_credit_reserved_num
            .saturating_sub(s.valid_liened_insurance_num.saturating_add(s.impaired_liened_insurance_num));
        let physical = percolator_prog::vault_lp_v18::pot_physical_net_atoms(
            b.fresh_unliened_backing_num,
            b.valid_liened_backing_num,
            s.positive_claim_bound_num,
            ins_cover,
            BOUND_SCALE,
        );
        nav += percolator_prog::vault_lp_v18::nonbound_pot_available(principal, physical);
    }
    // The program's earnings term is `earnings - withdrawn` scaled by fee share; assert it is 0.
    for d in [DOMAIN, SIBLING_DOMAIN] {
        assert_eq!(g.source_backing_buckets[d as usize].utilization_fee_earnings, 0);
    }
    nav
}

fn floor_mul_div(a: u128, b: u128, c: u128) -> u128 {
    a.checked_mul(b).expect("test values fit u128") / c
}

fn price_e9(nav: u128, supply: u128) -> u128 {
    if supply == 0 {
        0
    } else {
        floor_mul_div(nav, 1_000_000_000, supply)
    }
}

fn run_history(h: History, d: u128) -> (Observed, Counters) {
    let mut env = setup();
    let a = vault(&mut env);
    deposit(&mut env, &a, P, DOMAIN);
    deposit(&mut env, &a, P, SIBLING_DOMAIN);
    let b = new_actor(&mut env, &a);

    // B's deposit into the lossy pot. It must really checkpoint the pot ledger: tag 75 syncs it
    // (booking the unavailable principal seen so far as loss; no earlier sync happened, so the
    // watermark was 0) and re-baselines the watermark to the bucket AFTER the receivable paydown.
    let checkpoint = |env: &mut Env, booked: u128| {
        try_deposit(env, &b, d, DOMAIN).expect("checkpoint deposit");
        let l = ledger_of(&env.svm, a.ledger);
        let pb = market_group(env).source_backing_buckets[DOMAIN as usize];
        let unavailable =
            (pb.consumed_liened_backing_num + pb.impaired_liened_backing_num) / BOUND_SCALE;
        assert_eq!(l.cumulative_loss_atoms, booked, "{h:?}: checkpoint booked the loss");
        assert_eq!(l.cumulative_recovery_atoms, 0, "{h:?}: no recovery booked");
        assert_eq!(l.last_observed_unavailable_principal_atoms, unavailable, "{h:?}: re-baselined");
        assert_eq!(unavailable, booked - d, "{h:?}: the deposit paid the receivable down by d");
    };

    consume_pot_backing(&mut env, DOMAIN, X); // loss 1 (claimed)
    if h == History::Checkpointed {
        checkpoint(&mut env, X);
    }
    recover_pot_backing(&mut env, DOMAIN, R); // loser payment refills the pot
    if h == History::CheckpointedAfterRefill {
        checkpoint(&mut env, X - R);
    }
    consume_pot_backing(&mut env, DOMAIN, X2); // consumed again
    if h == History::Delayed {
        checkpoint(&mut env, X - R + X2);
    }

    let nav = exit_nav(&env, &a);
    let supply = registry_shares(&env, &a);
    let (a_shares, b_shares) = (shares_of(&env, a.lp_ata), shares_of(&env, b.lp_ata));
    // The genesis dead-share floor is counted in supply but minted to nobody.
    assert_eq!(a_shares + b_shares + DEAD, supply, "every live share is held by A or B");
    let g = market_group(&env);
    let pb = &g.source_backing_buckets[DOMAIN as usize];
    let l = ledger_of(&env.svm, a.ledger);
    let counters = Counters {
        loss: l.cumulative_loss_atoms,
        recovery: l.cumulative_recovery_atoms,
        watermark: l.last_observed_unavailable_principal_atoms,
    };
    let pot_principal = l.total_principal_atoms;
    let sib_principal = ledger_of(&env.svm, a.sibling_ledger).total_principal_atoms;
    let (pot_fresh_atoms, pot_consumed_atoms) = (
        pb.fresh_unliened_backing_num / BOUND_SCALE,
        pb.consumed_liened_backing_num / BOUND_SCALE,
    );

    // A redeems everything.
    let a_before = token_amount(&env.svm, a.dest) as u128;
    request(&mut env, &a, a_shares);
    execute(&mut env, &a, DOMAIN).expect("A's redemption");
    let a_payout = token_amount(&env.svm, a.dest) as u128 - a_before;

    let (nav_after_a, supply_after_a) = (exit_nav(&env, &a), registry_shares(&env, &a));
    let price_e9_after_a = price_e9(nav_after_a, supply_after_a);

    // B redeems everything (if B holds anything).
    // A redemption worth 0 atoms (B's single share at d = 1) is refused by tag 77 with
    // Custom(34) `LpVaultZeroAmount`; that is recorded, and must also match across histories.
    let mut b_payout = 0u128;
    let mut b_redeem_refused_code = 0u32;
    if b_shares != 0 {
        let b_before = token_amount(&env.svm, b.dest) as u128;
        request(&mut env, &b, b_shares);
        match execute(&mut env, &b, DOMAIN) {
            Ok(()) => b_payout = token_amount(&env.svm, b.dest) as u128 - b_before,
            Err(e) => {
                assert!(
                    has_code(&e, 34) && floor_mul_div(nav_after_a, b_shares, supply_after_a) == 0,
                    "B's redemption failed unexpectedly: {e}"
                );
                b_redeem_refused_code = 34;
            }
        }
    }

    let obs = Observed {
        exit_nav: nav,
        supply,
        price_e9: price_e9(nav, supply),
        a_shares,
        b_shares,
        pot_fresh_atoms,
        pot_consumed_atoms,
        pot_principal,
        sib_principal,
        a_payout,
        b_payout,
        price_e9_after_a,
        supply_end: registry_shares(&env, &a),
        vault_token_end: token_amount(&env.svm, env.vault_token) as u128,
        b_redeem_refused_code,
    };

    // Owner + protocol conservation, per history. Into the vault: A's 2P, B's deposit, the loser's
    // R. Out: the two winners' X + X2 (the fixture moves those tokens out) and A/B's payouts.
    // This token identity is bookkeeping (tokens only move by SPL transfer); the checks that the
    // program could get wrong follow it: pro-rata payouts, engine vault counter, residual == NAV
    // of the shares still outstanding.
    let b_in = if h == History::None { 0 } else { d };
    assert_eq!(
        START_BAL - token_amount(&env.svm, a.source) as u128,
        2 * P,
        "A's spend"
    );
    assert_eq!(START_BAL - token_amount(&env.svm, b.source) as u128, b_in, "B's spend");
    assert_eq!(
        a_payout + b_payout + obs.vault_token_end,
        2 * P + b_in + R - X - X2,
        "{h:?}: owner payouts + what stays in the vault == inflows - winner withdrawals"
    );
    // Every live share was redeemed (except a refused 0-atom one); the dead floor remains.
    let b_left = if b_redeem_refused_code != 0 { b_shares } else { 0 };
    assert_eq!(obs.supply_end, DEAD + b_left, "{h:?}: all live shares redeemed");
    // Each holder is paid its pro-rata share of the exit NAV (floor); nobody is paid more.
    assert!(a_payout <= floor_mul_div(nav, a_shares, supply), "{h:?}: A overpaid");
    assert!(a_payout + 1 >= floor_mul_div(nav, a_shares, supply), "{h:?}: A underpaid");
    let b_fair = floor_mul_div(nav_after_a, b_shares, supply_after_a);
    assert!(b_payout <= b_fair && b_payout + 1 >= b_fair, "{h:?}: B paid {b_payout}, fair {b_fair}");
    // The program's own vault counter matches the token balance it holds.
    let g_end = market_group(&env);
    assert_eq!(g_end.vault, obs.vault_token_end, "{h:?}: engine vault == token balance");
    // What stays behind is exactly what the remaining (dead + refused) shares are worth plus
    // floor dust from the redemptions: no owner value is stranded and none was overpaid.
    let nav_end = exit_nav(&env, &a);
    assert!(
        nav_end <= obs.vault_token_end && obs.vault_token_end - nav_end <= 2,
        "{h:?}: residual {} vs remaining NAV {nav_end}",
        obs.vault_token_end
    );
    eprintln!("#382 {h:?} d={d}: remaining NAV {nav_end} for {} shares", obs.supply_end);
    eprintln!("#382 {h:?} d={d}: {obs:?}");
    eprintln!("#382 {h:?} d={d}: ledger counters before redemption {counters:?}");
    (obs, counters)
}

/// The core #382 invariant: the same loss -> refill -> second loss prices and pays the same
/// whether the depositor action checkpoints the pot ledger after the first loss, after the
/// refill, or only after the second loss. `exit_nav` is the test's copy of the E3 formula; the
/// ±1 payout bounds in `run_history` are what tie it to the program's actual tag 77 payouts.
fn assert_history_independent(d: u128) {
    let (cp, cp_c) = run_history(History::Checkpointed, d);
    let (dl, dl_c) = run_history(History::Delayed, d);
    let (cr, cr_c) = run_history(History::CheckpointedAfterRefill, d);
    // The three histories really did observe the pot differently: the stored (farm-facing)
    // counters differ, because each checkpoint booked what it saw at that moment.
    assert_eq!((cp_c.loss, dl_c.loss, cr_c.loss), (X, X - R + X2, X - R), "booked loss");
    assert_eq!((cp_c.recovery, dl_c.recovery, cr_c.recovery), (0, 0, 0), "booked recovery");
    // ...and yet everything a holder can observe is identical.
    assert_eq!(cr, cp, "checkpoint after the refill vs after the first loss");
    // Same physical end state and same par principal in all three (cr == cp checked above).
    assert_eq!(cp.pot_fresh_atoms, dl.pot_fresh_atoms, "pot fresh");
    assert_eq!(cp.pot_consumed_atoms, dl.pot_consumed_atoms, "pot consumed");
    assert_eq!(cp.pot_principal, dl.pot_principal, "pot principal");
    // Pricing and payouts: identical.
    assert_eq!(cp.exit_nav, dl.exit_nav, "exit NAV depends on when the ledger was checkpointed");
    assert_eq!(cp.supply, dl.supply, "supply");
    assert_eq!(cp.price_e9, dl.price_e9, "share price");
    assert_eq!((cp.a_shares, cp.b_shares), (dl.a_shares, dl.b_shares), "share split");
    assert_eq!(cp.a_payout, dl.a_payout, "A's payout depends on when anyone looked");
    assert_eq!(cp.b_payout, dl.b_payout, "B's payout depends on when B deposited");
    assert_eq!(cp.price_e9_after_a, dl.price_e9_after_a, "share price after A's exit");
    assert_eq!(cp.vault_token_end, dl.vault_token_end, "vault residual");
    assert_eq!(cp, dl);
    // The exit NAV is exactly the physical value the pots hold for the vault (E3), not the
    // counter-derived `principal - (loss - recovery)`.
    assert_eq!(cp.exit_nav, 2 * P + d + R - X - X2);
    // The stored counters are stale snapshots (the next sync brings each to the same net
    // loss - recovery); pricing does not read them (`lp_vault_domain_nav_atoms` passes 0, 0).
    eprintln!(
        "#382 d={d}: counters checkpointed={cp_c:?} after_refill={cr_c:?} delayed={dl_c:?}"
    );
}

#[test]
fn floor382_checkpointed_vs_delayed_one_atom_deposit() {
    assert_history_independent(1);
}

#[test]
fn floor382_checkpointed_vs_delayed_one_token_deposit() {
    assert_history_independent(1_000_000);
}

/// The minimal (1-atom) checkpoint against NO depositor action at all: the incumbent's payout
/// moves by at most the checkpoint's own value (rounding), and per-share price matches.
#[test]
fn floor382_one_atom_checkpoint_vs_no_depositor_action() {
    let (cp, _) = run_history(History::Checkpointed, 1);
    let (none, none_c) = run_history(History::None, 1);
    assert_eq!(none.b_shares, 0);
    assert_eq!(none.exit_nav, 2 * P + R - X - X2);
    assert!(none.a_payout <= none.exit_nav, "sole live holder is paid at most the exit NAV");
    assert!(
        cp.a_payout.abs_diff(none.a_payout) <= 1,
        "A: checkpointed {} vs no action {}",
        cp.a_payout,
        none.a_payout
    );
    assert!(cp.price_e9.abs_diff(none.price_e9) <= 1, "price {} vs {}", cp.price_e9, none.price_e9);
    eprintln!("#382 none counters {none_c:?}");
}

/// A zero-amount depositor action is not an available checkpoint: tag 75 refuses it with
/// Custom(34) `LpVaultZeroAmount`, so the smallest real checkpoint is the 1-atom deposit above.
#[test]
fn floor382_zero_amount_deposit_is_refused() {
    let (mut env, v) = otc_env(DOMAIN, X);
    let b = new_actor(&mut env, &v);
    let e = try_deposit(&mut env, &b, 0, DOMAIN).expect_err("zero deposit must be refused");
    assert!(has_code(&e, 34), "expected LpVaultZeroAmount (34): {e}");
}
