// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! GOLDEN TABLE for the non-bound (non-P3) Earn vault tag 77 ExecuteRedemption.
//!
//! The app (`app/lib/limits/earn-withdrawable.ts`) and the SDK (`nonboundVaultPricingFromAccountsP2b`)
//! predict the payout of a non-bound redemption off-chain. This file drives the REAL program over a
//! seeded grid (own pot only, sibling top-up, sibling lapsed, vault cap binding, OI-reservation
//! guard thr 0/5000/10000) and records shares in, atoms paid and the post-state per pot into
//! `tests/fixtures/nonbound_redeem_golden.json`, asserting conservation on every case.
//!
//! Regenerate: `NONBOUND_GOLDEN_UPDATE=1 cargo test --release --test nonbound_redeem_golden`.
//! Without the env var the run diffs against the committed fixture (a program change that moves any
//! payout fails here). Harness copied from tests/nonbound_redeem_cross_pot.rs (itself from
//! tests/v17_lp_vault_dual_domain.rs). `PERC_PROG_SO` overrides the program bytes.

thread_local! {
    static OI_THR: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
}

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
            oi_reservation_threshold_bps: OI_THR.with(|c| c.get()),
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

/// A pot ledger is created lazily on its first deposit; an uncreated (empty) one reads as zero.
fn ledger_of(svm: &LiteSVM, ledger: Pubkey) -> state::BackingDomainLedgerAccountV16 {
    match svm.get_account(&ledger) {
        Some(a) if !a.data.is_empty() => {
            state::read_backing_domain_ledger(&a.data).expect("ledger decode")
        }
        _ => state::BackingDomainLedgerAccountV16::default(),
    }
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

// ───────────────────────────── golden grid ─────────────────────────────

const USDC: u128 = 1_000_000;

#[derive(Clone, Debug)]
struct Case {
    name: String,
    group: &'static str,
    own_dep: u128,
    sib_dep: u128,
    own_claim: u128,
    sib_claim: u128,
    sib_consumed: u128,
    own_earn: u128,
    sib_earn: u128,
    sib_lapsed: bool,
    /// Atoms removed from the program vault (header + token) before the exit: binds `atoms > vault`.
    vault_trim: u128,
    oi_thr: u16,
    /// Own-bucket valid lien (atoms) moved out of fresh backing: the OI the guard must cover.
    oi_lien: u128,
    /// shares requested = held * num / den
    num: u128,
    den: u128,
}

fn base(name: String, group: &'static str, num: u128, den: u128) -> Case {
    Case {
        name,
        group,
        own_dep: 1_000 * USDC,
        sib_dep: 0,
        own_claim: 0,
        sib_claim: 0,
        sib_consumed: 0,
        own_earn: 0,
        sib_earn: 0,
        sib_lapsed: false,
        vault_trim: 0,
        oi_thr: 0,
        oi_lien: 0,
        num,
        den,
    }
}

fn grid() -> Vec<Case> {
    let fr: [(u128, u128); 4] = [(1, 10), (1, 2), (999, 1000), (1, 1)];
    let mut v = Vec::new();
    // A. own pot only (sibling empty): plain / with earnings / with a winner claim.
    for &(n, d) in &fr {
        v.push(base(format!("own_only_{n}_{d}"), "own_pot_only", n, d));
        let mut c = base(format!("own_only_earn_{n}_{d}"), "own_pot_only", n, d);
        c.own_earn = 40 * USDC;
        v.push(c);
        let mut c = base(format!("own_only_claim_{n}_{d}"), "own_pot_only", n, d);
        c.own_claim = 100 * USDC;
        v.push(c);
    }
    // B. sibling top-up: exit exceeds the own pot's principal.
    for &(n, d) in &fr {
        let mut c = base(format!("topup_plain_{n}_{d}"), "sibling_top_up", n, d);
        c.sib_dep = 600 * USDC;
        v.push(c);
        let mut c = base(format!("topup_sib_loss_{n}_{d}"), "sibling_top_up", n, d);
        c.sib_dep = 600 * USDC;
        c.sib_consumed = 50 * USDC;
        v.push(c);
        let mut c = base(format!("topup_sib_claim_earn_{n}_{d}"), "sibling_top_up", n, d);
        c.sib_dep = 600 * USDC;
        c.sib_claim = 100 * USDC;
        c.sib_earn = 20 * USDC;
        v.push(c);
    }
    // C. sibling lapsed (not Fresh): top-up must not draw from it.
    for &(n, d) in &fr {
        let mut c = base(format!("lapsed_sib_topup_{n}_{d}"), "sibling_lapsed", n, d);
        c.sib_dep = 600 * USDC;
        c.sib_lapsed = true;
        v.push(c);
    }
    let mut c = base("lapsed_sib_small_exit".into(), "sibling_lapsed", 1, 20);
    c.sib_dep = 600 * USDC;
    c.sib_lapsed = true;
    v.push(c);
    // D. vault cap binding: the physical vault is short of the priced payout.
    for &(n, d) in &fr {
        let mut c = base(format!("vault_cap_{n}_{d}"), "vault_cap", n, d);
        c.sib_dep = 400 * USDC;
        c.vault_trim = 1_000 * USDC;
        v.push(c);
    }
    let mut c = base("vault_cap_slight_half".into(), "vault_cap", 1, 2);
    c.sib_dep = 400 * USDC;
    c.vault_trim = 1;
    v.push(c);
    // E. OI-reservation guard thr 0 / 5000 / 10000 with a real lien on the own bucket.
    for &thr in &[0u16, 5_000, 10_000] {
        for &(n, d) in &[(1u128, 10u128), (1, 2), (9, 10), (1, 1)] {
            let mut c = base(format!("oi_thr{thr}_{n}_{d}"), "oi_reservation", n, d);
            c.sib_dep = 600 * USDC;
            c.oi_thr = thr;
            c.oi_lien = 300 * USDC;
            v.push(c);
        }
        let mut c = base(format!("oi_thr{thr}_nolien_1_1"), "oi_reservation", 1, 1);
        c.oi_thr = thr;
        v.push(c);
    }
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PotSnap {
    principal: u128,
    deposited: u128,
    principal_withdrawn: u128,
    earnings: u128,
    earnings_withdrawn: u128,
    /// Bucket fee earnings the ledger has not synced yet (77 books them into `earnings` first).
    pending_earnings: u128,
    loss: u128,
    recovery: u128,
    /// ledger available NAV: principal - min(loss - recovery, principal)
    nav: u128,
    fresh_backing_atoms: u128,
    liened_backing_atoms: u128,
}

fn pot_snap(env: &Env, ledger: Pubkey, domain: u16) -> PotSnap {
    let l = ledger_of(&env.svm, ledger);
    let g = market_group(env);
    let b = &g.source_backing_buckets[domain as usize];
    let imp = l.cumulative_loss_atoms.saturating_sub(l.cumulative_recovery_atoms);
    PotSnap {
        principal: l.total_principal_atoms,
        deposited: l.total_deposited_atoms,
        principal_withdrawn: l.total_principal_withdrawn_atoms,
        earnings: l.total_earnings_atoms,
        earnings_withdrawn: l.total_earnings_withdrawn_atoms,
        pending_earnings: b.utilization_fee_earnings.saturating_sub(l.last_observed_bucket_earnings_atoms),
        loss: l.cumulative_loss_atoms,
        recovery: l.cumulative_recovery_atoms,
        nav: l.total_principal_atoms - imp.min(l.total_principal_atoms),
        fresh_backing_atoms: b.fresh_unliened_backing_num / BOUND_SCALE,
        liened_backing_atoms: b.valid_liened_backing_num / BOUND_SCALE,
    }
}

fn pot_json(p: &PotSnap) -> serde_json::Value {
    serde_json::json!({
        "principal": p.principal.to_string(),
        "deposited": p.deposited.to_string(),
        "principal_withdrawn": p.principal_withdrawn.to_string(),
        "earnings": p.earnings.to_string(),
        "earnings_withdrawn": p.earnings_withdrawn.to_string(),
        "pending_earnings": p.pending_earnings.to_string(),
        "loss": p.loss.to_string(),
        "recovery": p.recovery.to_string(),
        "nav": p.nav.to_string(),
        "fresh_backing_atoms": p.fresh_backing_atoms.to_string(),
        "liened_backing_atoms": p.liened_backing_atoms.to_string(),
    })
}

fn custom_code(err: &str) -> Option<u32> {
    let i = err.find("Custom(")? + "Custom(".len();
    let j = err[i..].find(')')? + i;
    err[i..j].parse().ok()
}

fn run_case(c: &Case) -> serde_json::Value {
    OI_THR.with(|t| t.set(c.oi_thr));
    let mut env = setup();
    let v = vault(&mut env);
    deposit(&mut env, &v, c.own_dep, DOMAIN);
    if c.sib_dep > 0 {
        deposit(&mut env, &v, c.sib_dep, SIBLING_DOMAIN);
    }
    if c.sib_consumed > 0 {
        consume_pot_backing(&mut env, SIBLING_DOMAIN, c.sib_consumed);
    }
    if c.own_claim > 0 {
        add_winner_claim(&mut env, DOMAIN, c.own_claim);
    }
    if c.sib_claim > 0 {
        add_winner_claim(&mut env, SIBLING_DOMAIN, c.sib_claim);
    }
    if c.own_earn > 0 {
        add_pot_earnings(&mut env, DOMAIN, c.own_earn);
    }
    if c.sib_earn > 0 {
        add_pot_earnings(&mut env, SIBLING_DOMAIN, c.sib_earn);
    }
    if c.oi_lien > 0 {
        with_market(&mut env, |g| {
            let n = c.oi_lien * BOUND_SCALE;
            let b = &mut g.source_backing_buckets[DOMAIN as usize];
            b.fresh_unliened_backing_num -= n;
            b.valid_liened_backing_num += n;
        });
    }

    let held = token_amount(&env.svm, v.lp_ata) as u128;
    let shares = held * c.num / c.den;
    assert!(shares > 0, "{}: zero shares", c.name);
    request(&mut env, &v, shares);

    // Request time is after setup so the sibling lapse (expiry == now) is evaluated at 77's slot.
    if c.sib_lapsed {
        let now = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
        with_market(&mut env, |g| g.source_backing_buckets[SIBLING_DOMAIN as usize].expiry_slot = now);
    }
    if c.vault_trim > 0 {
        with_market(&mut env, |g| g.vault -= c.vault_trim);
        let bal = token_amount(&env.svm, env.vault_token) as u128;
        let (mint, va) = (env.collateral_mint, vault_authority(&env));
        set_token(&mut env.svm, env.vault_token, mint, va, (bal - c.vault_trim) as u64);
    }

    let s_before = registry_shares(&env, &v);
    let own_b = pot_snap(&env, v.ledger, DOMAIN);
    let sib_b = pot_snap(&env, v.sibling_ledger, SIBLING_DOMAIN);
    let vault_tok_b = token_amount(&env.svm, env.vault_token) as u128;
    let vault_grp_b = market_group(&env).vault;

    let res = execute(&mut env, &v, DOMAIN);

    let s_after = registry_shares(&env, &v);
    let own_a = pot_snap(&env, v.ledger, DOMAIN);
    let sib_a = pot_snap(&env, v.sibling_ledger, SIBLING_DOMAIN);
    let vault_tok_a = token_amount(&env.svm, env.vault_token) as u128;
    let vault_grp_a = market_group(&env).vault;
    let paid = token_amount(&env.svm, v.dest) as u128;

    // ── Conservation, asserted on EVERY case (success and refusal) ──
    // 1. atoms paid + remaining == before, on the token vault and on the engine vault counter.
    assert_eq!(paid + vault_tok_a, vault_tok_b, "{}: token vault conservation", c.name);
    assert_eq!(paid + vault_grp_a, vault_grp_b, "{}: engine vault conservation", c.name);
    // 2. the principal + net earnings (synced or still pending in the bucket) both pots held
    //    before covers paid + what they hold after. The gap is the insurance stub of the gross
    //    earnings chunk, which leaves the earnings counters but stays in the vault.
    let held = |p: &PotSnap| p.principal + (p.earnings - p.earnings_withdrawn) + p.pending_earnings;
    let held_b = held(&own_b) + held(&sib_b);
    let held_a = held(&own_a) + held(&sib_a);
    assert!(paid + held_a <= held_b, "{}: ledger conservation {paid}+{held_a} vs {held_b}", c.name);
    let ok = res.is_ok();
    if ok {
        assert!(paid > 0, "{}: ok but paid 0", c.name);
        assert!(s_after < s_before, "{}: shares not burned", c.name);
        assert_eq!(s_before - s_after, shares, "{}: burned != requested", c.name);
    } else {
        assert_eq!(paid, 0, "{}: refused but paid", c.name);
        assert_eq!(s_after, s_before, "{}: refused but shares burned", c.name);
        assert_eq!((&own_a, &sib_a), (&own_b, &sib_b), "{}: refused but a pot moved", c.name);
    }

    let (result, code) = match &res {
        Ok(()) => ("ok".to_string(), serde_json::Value::Null),
        Err(e) => ("err".to_string(), custom_code(e).map_or(serde_json::Value::Null, |x| x.into())),
    };
    serde_json::json!({
        "name": c.name,
        "group": c.group,
        "input": {
            "own_dep": c.own_dep.to_string(), "sib_dep": c.sib_dep.to_string(),
            "own_claim": c.own_claim.to_string(), "sib_claim": c.sib_claim.to_string(),
            "sib_consumed": c.sib_consumed.to_string(),
            "own_earn": c.own_earn.to_string(), "sib_earn": c.sib_earn.to_string(),
            "sib_lapsed": c.sib_lapsed, "vault_trim": c.vault_trim.to_string(),
            "oi_thr_bps": c.oi_thr, "oi_lien": c.oi_lien.to_string(),
            "shares_num": c.num.to_string(), "shares_den": c.den.to_string(),
        },
        "shares_total_before": s_before.to_string(),
        "shares_in": shares.to_string(),
        "result": result,
        "custom_code": code,
        "atoms_paid": paid.to_string(),
        "shares_total_after": s_after.to_string(),
        "vault_token_before": vault_tok_b.to_string(),
        "vault_token_after": vault_tok_a.to_string(),
        "own_pot_before": pot_json(&own_b),
        "sib_pot_before": pot_json(&sib_b),
        "own_pot_after": pot_json(&own_a),
        "sib_pot_after": pot_json(&sib_a),
    })
}

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/nonbound_redeem_golden.json");
    p
}

#[test]
fn nonbound_redeem_golden_table() {
    let cases = grid();
    assert!(cases.len() >= 40, "grid must hold >= 40 cases, has {}", cases.len());
    let mut names = std::collections::BTreeSet::new();
    for c in &cases {
        assert!(names.insert(c.name.clone()), "duplicate case {}", c.name);
    }
    let rows: Vec<serde_json::Value> = cases.iter().map(run_case).collect();
    let n_ok = rows.iter().filter(|r| r["result"] == "ok").count();
    let n_err = rows.len() - n_ok;
    // The grid must exercise both outcomes and every group.
    assert!(n_ok >= 20 && n_err >= 5, "grid coverage: ok {n_ok} err {n_err}");
    let doc = serde_json::json!({
        "schema": "nonbound_redeem_golden/v1",
        "tag": 77,
        "case_count": rows.len(),
        "ok_count": n_ok,
        "err_count": n_err,
        "note": "regenerate with NONBOUND_GOLDEN_UPDATE=1; amounts are decimal strings in token atoms (6 dp)",
        "cases": rows,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let path = fixture_path();
    if std::env::var_os("NONBOUND_GOLDEN_UPDATE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
        eprintln!("wrote {} cases to {}", n_ok + n_err, path.display());
    } else {
        let want = std::fs::read_to_string(&path).expect("fixture missing; run with NONBOUND_GOLDEN_UPDATE=1");
        let want: serde_json::Value = serde_json::from_str(&want).unwrap();
        assert_eq!(doc, want, "program output drifted from tests/fixtures/nonbound_redeem_golden.json");
    }
}
