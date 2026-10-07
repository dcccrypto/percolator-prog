//! prog#542: the LP / Earn share mint takes the collateral mint's decimals, and tag 122
//! `InitLpShareMetadata` gives it a wallet-visible name.
//!
//! What this file proves, against the BUILT .so in LiteSVM:
//!   * the mint's `decimals` read back from the mint == the collateral mint's (0 / 6 / 9);
//!   * tag 74 without the collateral mint, or with a different mint, is refused and creates
//!     nothing (negative controls);
//!   * share counts, payouts, registry and ledger for a fixed deposit / earnings / redeem script
//!     are pinned to literals, are the SAME for a 0-decimal and a 6-decimal collateral mint, and
//!     (ignored test, needs `LP_SHARE_BASE_SO`) the SAME as the base .so produces: the share
//!     price arithmetic does not read `decimals`;
//!   * first deposit (dead-share floor), second deposit, a donation attack and redeem rounding
//!     (against the redeemer);
//!   * tag 122: the pre-CPI refusals (no Metaplex binary needed) and, in ignored tests that need
//!     `MPL_TOKEN_METADATA_SO` (`solana program dump -u m metaqbxx... <file>`), the real
//!     Metaplex program creating the account with the fixed name, and refusing a second call.
//!
//! Harness adapted from `tests/v16_fork_lp_vault_redeem.rs` (same market, same vault).
#![cfg(not(kani))]

use litesvm::LiteSVM;
use percolator_prog::constants::{LP_VAULT_MINIMUM_LIQUIDITY, MPL_TOKEN_METADATA_PROGRAM_ID};
use percolator_prog::error::PercolatorError;
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
use std::cell::{Cell, RefCell};
use std::path::PathBuf;

const MAX_PORTFOLIO_ASSETS: u16 = 1;
const APPEND_ASSET_INDEX: u16 = 1;
const DOMAIN: u16 = 2;
/// One whole token at 6 decimals.
const U: u128 = 1_000_000;

thread_local! {
    /// Wrapper .so override (the differential test loads the base build).
    static SO_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    /// Decimals of the collateral mint the fixture creates.
    static COLLATERAL_DECIMALS: Cell<u8> = const { Cell::new(6) };
    /// Fixed market address (compute comparisons: PDA bump searches cost the same on both runs).
    static FIXED_MARKET: Cell<Option<Pubkey>> = const { Cell::new(None) };
}

fn program_path() -> PathBuf {
    if let Some(p) = SO_OVERRIDE.with(|c| c.borrow().clone()) {
        assert!(p.exists(), "override .so missing: {p:?}");
        return p;
    }
    // Negative controls: LP_SHARE_WRAPPER_SO runs this whole file against another build (the
    // base build, or a mutant) to show which tests notice.
    if let Ok(p) = std::env::var("LP_SHARE_WRAPPER_SO") {
        let p = PathBuf::from(p);
        assert!(p.exists(), "LP_SHARE_WRAPPER_SO missing: {p:?}");
        return p;
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing: cargo build-sbf --features devnet");
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
            decimals: COLLATERAL_DECIMALS.with(|c| c.get()),
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}
fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TokenAccount::LEN];
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
        &mut d,
    )
    .unwrap();
    d
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

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    collateral_mint: Pubkey,
    vault_token: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    ledger: Pubkey,
    escrow: Pubkey,
    vault_authority: Pubkey,
}
fn send(
    svm: &mut LiteSVM,
    program_id: Pubkey,
    payer: &Keypair,
    ixs: Vec<(ProgInstruction, Vec<AccountMeta>)>,
    extra: &[&Keypair],
) -> Result<u64, String> {
    let mut instructions = vec![
        ComputeBudgetInstruction::request_heap_frame(128 * 1024),
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
    ];
    for (ix, accounts) in ixs {
        instructions.push(Instruction {
            program_id,
            accounts,
            data: ix.encode(),
        });
    }
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|m| m.compute_units_consumed)
        .map_err(|e| format!("{e:?}"))
}

fn custom(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
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


/// Market with asset 1 appended (backing authority = the registry PDA), NO vault yet.
fn setup_market() -> Env {
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
    let market = FIXED_MARKET.with(|c| c.get()).unwrap_or_else(Pubkey::new_unique);
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
        vec![(
            init_market_ix(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(collateral_mint, false),
            ],
        )],
        &[&admin],
    )
    .expect("init market");

    let (registry, _) = derive_lp_vault_registry(&program_id, &market);
    let (lp_mint, _) = derive_lp_vault_mint(&program_id, &market);
    let (ledger, _) = derive_lp_backing_ledger(&program_id, &market, DOMAIN);
    let (escrow, _) = derive_lp_escrow(&program_id, &market);
    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
    let vault_token = canonical_vault_ata(&vault_authority, &collateral_mint);
    set_token(&mut svm, vault_token, collateral_mint, vault_authority, 0);

    send(
        &mut svm,
        program_id,
        &payer,
        vec![(
            ProgInstruction::UpdateAssetLifecycle {
                market_id: 2,
                action: ASSET_ACTION_ACTIVATE,
                asset_index: APPEND_ASSET_INDEX,
                authority_epoch: 0,
                now_slot: 1,
                initial_price: 100,
                max_init_fee: u128::MAX,
                insurance_authority: admin.pubkey().to_bytes(),
                insurance_operator: admin.pubkey().to_bytes(),
                backing_bucket_authority: registry.to_bytes(),
                oracle_authority: admin.pubkey().to_bytes(),
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
            ],
        )],
        &[&admin],
    )
    .expect("append asset 1");

    Env {
        svm,
        program_id,
        payer,
        admin,
        market,
        collateral_mint,
        vault_token,
        registry,
        lp_mint,
        ledger,
        escrow,
        vault_authority,
    }
}

/// Tag 74 with the six pre-v2.2 accounts plus `tail` (the v2.2 form passes the collateral mint).
fn create_vault_with(env: &mut Env, tail: Vec<AccountMeta>) -> Result<u64, String> {
    let admin = env.admin.insecure_clone();
    let payer = env.payer.insecure_clone();
    let mut accounts = vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(env.registry, false),
        AccountMeta::new(env.lp_mint, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ];
    accounts.extend(tail);
    send(
        &mut env.svm,
        env.program_id,
        &payer,
        vec![(
            ProgInstruction::CreateLpVault {
                fee_share_bps: 5_000,
                redemption_cooldown_slots: 0,
                oi_reservation_threshold_bps: 0,
                domain: DOMAIN,
            },
            accounts,
        )],
        &[&admin],
    )
}

/// Market + vault. The collateral mint is always passed: the base build ignores a 7th account.
fn setup_vault() -> Env {
    let mut env = setup_market();
    let mint = env.collateral_mint;
    create_vault_with(&mut env, vec![AccountMeta::new_readonly(mint, false)])
        .expect("create lp vault");
    env
}

fn lp_mint_state(env: &Env) -> Mint {
    let a = env.svm.get_account(&env.lp_mint).expect("lp mint");
    assert_eq!(a.owner, spl_token::ID, "the share mint is a classic SPL mint");
    assert_eq!(a.data.len(), Mint::LEN);
    Mint::unpack(&a.data).expect("mint")
}

struct Depositor {
    kp: Keypair,
    lp_ata: Pubkey,
    dest: Pubkey,
    redemption: Pubkey,
}

fn deposit_accounts(env: &Env, lp_ata: Pubkey, source: Pubkey, depositor: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(depositor, true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(env.registry, false),
        AccountMeta::new(env.lp_mint, false),
        AccountMeta::new(lp_ata, false),
        AccountMeta::new(source, false),
        AccountMeta::new(env.vault_token, false),
        AccountMeta::new(env.ledger, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new(
            derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN ^ 1).0,
            false,
        ),
    ]
}

/// A fresh wallet depositing `amount` atoms of collateral through tag 75.
fn try_deposit(env: &mut Env, amount: u128) -> Result<Depositor, String> {
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(&mut env.svm, source, env.collateral_mint, kp.pubkey(), amount as u64);
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, env.lp_mint, kp.pubkey(), 0);
    let dest = Pubkey::new_unique();
    set_token(&mut env.svm, dest, env.collateral_mint, kp.pubkey(), 0);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &env.registry, &kp.pubkey());
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = deposit_accounts(env, lp_ata, source, kp.pubkey());
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(ProgInstruction::DepositToLpVault { amount, domain: DOMAIN }, accts)],
        &[&kp],
    )?;
    Ok(Depositor { kp, lp_ata, dest, redemption })
}

fn deposit(env: &mut Env, amount: u128) -> Depositor {
    try_deposit(env, amount).expect("deposit")
}

fn tok(svm: &LiteSVM, key: Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(&key).expect("acct").data)
        .expect("decode")
        .amount
}

/// Tag 76 then tag 77 (cooldown 0): returns the collateral atoms paid for `shares`.
fn try_redeem(env: &mut Env, d: &Depositor, shares: u128) -> Result<u64, String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let kp = d.kp.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::RequestRedeemLpShares { shares },
            vec![
                AccountMeta::new(kp.pubkey(), true),
                AccountMeta::new(env.registry, false),
                AccountMeta::new(env.lp_mint, false),
                AccountMeta::new(d.lp_ata, false),
                AccountMeta::new(env.escrow, false),
                AccountMeta::new(d.redemption, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
        )],
        &[&kp],
    )?;
    let before = tok(&env.svm, d.dest);
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::ExecuteRedemption { domain: DOMAIN },
            vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(env.registry, false),
                AccountMeta::new(d.redemption, false),
                AccountMeta::new(env.lp_mint, false),
                AccountMeta::new(env.escrow, false),
                AccountMeta::new(env.vault_token, false),
                AccountMeta::new_readonly(env.vault_authority, false),
                AccountMeta::new(env.ledger, false),
                AccountMeta::new(d.dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(
                    derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN ^ 1).0,
                    false,
                ),
                AccountMeta::new(kp.pubkey(), true),
            ],
        )],
        &[&kp],
    )?;
    // The consumed request PDA is left with 0 lamports; a real validator purges such an account
    // when the transaction ends, LiteSVM 0.1 keeps its bytes. Purge it here (asserting it IS a
    // 0-lamport account) so the same wallet can request again, as it can on chain.
    let r = env.svm.get_account(&d.redemption).expect("request PDA");
    assert_eq!(r.lamports, 0, "consumed request PDA must hold no lamports");
    env.svm.set_account(d.redemption, Account::default()).unwrap();
    Ok(tok(&env.svm, d.dest) - before)
}

fn redeem(env: &mut Env, d: &Depositor, shares: u128) -> u64 {
    try_redeem(env, d, shares).expect("redeem")
}

/// Fee earnings on the vault's bucket plus the tokens. The vault was created with
/// `fee_share_bps = 5,000`, so NAV rises by HALF of `earnings` (the LP slice).
fn seed_earnings(env: &mut Env, earnings: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.source_backing_buckets[DOMAIN as usize].utilization_fee_earnings += earnings;
    group.vault += earnings;
    group.backing_provider_earnings_total += earnings;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
    add_vault_tokens(env, earnings as u64);
}

/// A raw token transfer INTO the vault token account (a "donation": no instruction of the
/// program runs, no ledger moves).
fn add_vault_tokens(env: &mut Env, atoms: u64) {
    let mut tok_acct = env.svm.get_account(&env.vault_token).expect("vault_token");
    let mut t = TokenAccount::unpack(&tok_acct.data).expect("unpack vault token");
    t.amount = t.amount.checked_add(atoms).expect("no overflow");
    let mut new_data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(t, &mut new_data).expect("pack");
    tok_acct.data = new_data;
    env.svm.set_account(env.vault_token, tok_acct).unwrap();
}

fn ledger(env: &Env) -> state::BackingDomainLedgerAccountV16 {
    state::read_backing_domain_ledger(&env.svm.get_account(&env.ledger).unwrap().data).unwrap()
}

fn reg(env: &Env) -> state::LpVaultRegistryV16 {
    state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap()
}

// ── 1. decimals ──────────────────────────────────────────────────────────────────────────────

#[test]
fn share_mint_decimals_equal_the_collateral_mints() {
    for d in [0u8, 6, 9] {
        COLLATERAL_DECIMALS.with(|c| c.set(d));
        let env = setup_vault();
        let m = lp_mint_state(&env);
        assert_eq!(m.decimals, d, "share mint decimals read back from the mint");
        assert_eq!(m.mint_authority, COption::Some(env.registry), "authority = registry PDA");
        assert_eq!(m.freeze_authority, COption::None, "no freeze authority");
        assert_eq!(m.supply, 0);
        assert!(m.is_initialized);
    }
    COLLATERAL_DECIMALS.with(|c| c.set(6));
}

/// What the creator in prog#542 saw, and what they see now: 1,000 tokens seeded.
#[test]
fn a_1000_token_seed_reads_as_about_1000_shares_in_a_wallet() {
    let mut env = setup_vault();
    let a = deposit(&mut env, 1_000 * U);
    let raw = tok(&env.svm, a.lp_ata);
    assert_eq!(raw, 999_999_000, "raw share count is what it always was");
    let decimals = lp_mint_state(&env).decimals;
    assert_eq!(decimals, 6);
    // what `uiAmountString` is: raw / 10^decimals
    let ui = format!("{}.{:06}", raw / 1_000_000, raw % 1_000_000);
    assert_eq!(ui, "999.999000", "a wallet shows 999.999 shares, not 999,999,000");
}

// ── 2. negative controls on tag 74 ───────────────────────────────────────────────────────────

fn assert_nothing_created(env: &Env) {
    for k in [env.registry, env.lp_mint] {
        let a = env.svm.get_account(&k);
        assert!(a.map(|a| a.data.is_empty()).unwrap_or(true), "a refused 74 creates nothing");
    }
}

#[test]
fn create_without_the_collateral_mint_is_refused() {
    let mut env = setup_market();
    let r = create_vault_with(&mut env, vec![]);
    let e = r.expect_err("the pre-v2.2 six-account form must be refused");
    assert!(e.contains("NotEnoughAccountKeys"), "{e}");
    assert_nothing_created(&env);
}

#[test]
fn create_with_a_different_mint_is_refused() {
    let mut env = setup_market();
    // a perfectly valid classic SPL mint with other decimals, but not this market's collateral
    let other = Pubkey::new_unique();
    COLLATERAL_DECIMALS.with(|c| c.set(2));
    let data = make_mint_data();
    COLLATERAL_DECIMALS.with(|c| c.set(6));
    env.svm
        .set_account(other, Account { lamports: 1_000_000_000, data, owner: spl_token::ID, executable: false, rent_epoch: 0 })
        .unwrap();
    let e = create_vault_with(&mut env, vec![AccountMeta::new_readonly(other, false)])
        .expect_err("a mint that is not the market's collateral mint must be refused");
    assert!(e.contains("InvalidArgument"), "{e}");
    assert_nothing_created(&env);
    // and the right mint then works (the refusal was the mint, not the fixture)
    let mint = env.collateral_mint;
    create_vault_with(&mut env, vec![AccountMeta::new_readonly(mint, false)]).expect("create");
    assert_eq!(lp_mint_state(&env).decimals, 6);
}

/// The key is right but the account is not a classic SPL mint any more (owner changed under the
/// test): `unpack_mint` refuses, so decimals are never read from a foreign layout.
#[test]
fn create_with_a_non_spl_collateral_account_is_refused() {
    let mut env = setup_market();
    let mint = env.collateral_mint;
    let mut a = env.svm.get_account(&mint).unwrap();
    a.owner = Pubkey::new_unique();
    env.svm.set_account(mint, a).unwrap();
    let e = create_vault_with(&mut env, vec![AccountMeta::new_readonly(mint, false)])
        .expect_err("a non-SPL-owned collateral mint account must be refused");
    assert!(e.contains(&custom(PercolatorError::InvalidMint)), "{e}");
    assert_nothing_created(&env);
}

// ── 3. share counts and prices: pinned, decimals-independent, base-identical ─────────────────

/// Every number a fixed script produces. `decimals` is deliberately NOT part of it.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Trace {
    steps: Vec<(&'static str, u128)>,
    registry: state::LpVaultRegistryV16,
    ledger: state::BackingDomainLedgerAccountV16,
}

fn run_script() -> (Trace, u8) {
    let mut env = setup_vault();
    let mut steps: Vec<(&'static str, u128)> = Vec::new();
    let decimals = lp_mint_state(&env).decimals;
    macro_rules! snap {
        ($label:expr) => {{
            steps.push(($label, reg(&env).total_lp_shares_outstanding));
            steps.push(("mint supply", lp_mint_state(&env).supply as u128));
            steps.push(("vault tokens", tok(&env.svm, env.vault_token) as u128));
        }};
    }
    // first deposit: 1,000 tokens
    let a = deposit(&mut env, 1_000 * U);
    steps.push(("A shares", tok(&env.svm, a.lp_ata) as u128));
    snap!("outstanding after A");
    // second deposit at price 1: 500 tokens
    let b = deposit(&mut env, 500 * U);
    steps.push(("B shares", tok(&env.svm, b.lp_ata) as u128));
    snap!("outstanding after B");
    // earnings make the price a non-integer ratio
    seed_earnings(&mut env, 2 * 333_333_337);
    // third deposit: rounds DOWN
    let c = deposit(&mut env, 777_777_777);
    steps.push(("C shares", tok(&env.svm, c.lp_ata) as u128));
    snap!("outstanding after C");
    // a 1-atom deposit at price > 1 would mint 0 shares: refused, nothing absorbed
    let dust = try_deposit(&mut env, 1);
    steps.push(("1-atom deposit refused", dust.is_err() as u128));
    snap!("outstanding after dust");
    // redemptions: partial, 1 share, then everything
    steps.push(("B paid for 123,456,789 shares", redeem(&mut env, &b, 123_456_789) as u128));
    steps.push(("B paid for 1 share", redeem(&mut env, &b, 1) as u128));
    snap!("outstanding after B exits");
    let a_all = tok(&env.svm, a.lp_ata) as u128;
    steps.push(("A paid for all", redeem(&mut env, &a, a_all) as u128));
    let c_all = tok(&env.svm, c.lp_ata) as u128;
    steps.push(("C paid for all", redeem(&mut env, &c, c_all) as u128));
    let b_all = tok(&env.svm, b.lp_ata) as u128;
    steps.push(("B paid for the rest", redeem(&mut env, &b, b_all) as u128));
    snap!("outstanding at the end");
    let mut registry = reg(&env);
    registry.market_group = [0; 32];
    registry.lp_mint = [0; 32];
    // PDA bumps depend on the (random) market address, not on the program
    registry.bump = 0;
    registry.mint_bump = 0;
    let mut l = ledger(&env);
    l.market_group = [0; 32];
    l.authority = [0; 32];
    (Trace { steps, registry, ledger: l }, decimals)
}

fn step(t: &Trace, label: &str) -> u128 {
    t.steps.iter().find(|(l, _)| *l == label).unwrap_or_else(|| panic!("no step {label}")).1
}

/// The literals below are the share price arithmetic of the base build (`floor(amount * S /
/// NAV)` on deposit, `floor(shares * NAV / S)` on redeem, 1,000 dead shares at genesis),
/// worked by hand in the comments. They hold for a 0-decimal AND a 6-decimal collateral mint.
#[test]
fn share_counts_and_payouts_are_pinned_and_do_not_depend_on_decimals() {
    COLLATERAL_DECIMALS.with(|c| c.set(6));
    let (t6, d6) = run_script();
    COLLATERAL_DECIMALS.with(|c| c.set(0));
    let (t0, d0) = run_script();
    COLLATERAL_DECIMALS.with(|c| c.set(6));
    assert_eq!((d6, d0), (6, 0));
    assert_eq!(t6, t0, "identical trace whatever the mint's decimals");
    for (l, v) in &t6.steps {
        println!("{l:>34}: {v}");
    }
    // genesis: 1 share per atom, 1,000 dead shares counted but never minted
    assert_eq!(step(&t6, "A shares"), 1_000 * U - LP_VAULT_MINIMUM_LIQUIDITY);
    assert_eq!(step(&t6, "outstanding after A"), 1_000 * U);
    // second deposit at NAV == S: exactly pro rata, no dead shares
    assert_eq!(step(&t6, "B shares"), 500 * U);
    assert_eq!(step(&t6, "outstanding after B"), 1_500 * U);
    // S = 1,500,000,000; NAV = 1,500,000,000 + 333,333,337 (the LP half of the earnings)
    let (s, nav) = (1_500_000_000u128, 1_833_333_337u128);
    let c_amount = 777_777_777u128;
    let c_shares = c_amount * s / nav; // floor
    assert_eq!(step(&t6, "C shares"), c_shares);
    assert_eq!(c_shares, 636_363_634, "hand value");
    assert!(c_shares * nav <= c_amount * s && (c_shares + 1) * nav > c_amount * s, "floor, against the depositor");
    assert_eq!(step(&t6, "1-atom deposit refused"), 1);
    // after C: S2 = S + c_shares, NAV2 = NAV + c_amount
    let (s2, nav2) = (s + c_shares, nav + c_amount);
    assert_eq!(step(&t6, "outstanding after C"), s2);
    let p1 = 123_456_789u128 * nav2 / s2;
    assert_eq!(step(&t6, "B paid for 123,456,789 shares"), p1);
    assert!(p1 * s2 <= 123_456_789 * nav2 && (p1 + 1) * s2 > 123_456_789 * nav2, "floor, against the redeemer");
    let (s3, nav3) = (s2 - 123_456_789, nav2 - p1);
    // one share is worth 1.22 atoms: pays 1, the 0.22 stays in the vault
    assert_eq!(step(&t6, "B paid for 1 share"), nav3 / s3);
    assert_eq!(nav3 / s3, 1);
    // the vault never pays out more than came in, and the dust it keeps is the dead shares' slice
    let paid: u128 = ["B paid for 123,456,789 shares", "B paid for 1 share", "A paid for all", "C paid for all", "B paid for the rest"]
        .iter()
        .map(|l| step(&t6, l))
        .sum();
    let put_in = 1_000 * U + 500 * U + c_amount + 2 * 333_333_337;
    assert!(paid < put_in, "paid {paid} < in {put_in}");
    assert_eq!(step(&t6, "outstanding at the end"), LP_VAULT_MINIMUM_LIQUIDITY, "only the dead shares remain");
    assert_eq!(t6.registry.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY);
}

/// Differential against the BASE build (release/v22-wrapper-rem before this change): the same
/// script, the same collateral mint (6 decimals), on both .so files. Everything except the
/// mint's `decimals` byte must be equal.
#[test]
#[ignore = "needs LP_SHARE_BASE_SO=<base percolator_prog.so> (the build of the commit this branch is based on)"]
fn share_counts_and_payouts_equal_the_base_build() {
    let base = PathBuf::from(std::env::var("LP_SHARE_BASE_SO").expect("LP_SHARE_BASE_SO"));
    COLLATERAL_DECIMALS.with(|c| c.set(6));
    let (new, d_new) = run_script();
    SO_OVERRIDE.with(|c| *c.borrow_mut() = Some(base));
    let (old, d_old) = run_script();
    SO_OVERRIDE.with(|c| *c.borrow_mut() = None);
    assert_eq!(d_old, 0, "the base build creates a 0-decimal share mint (control: this IS the old binary)");
    assert_eq!(d_new, 6);
    assert_eq!(new, old, "share counts, payouts, registry and ledger are identical to the base build");
    println!("base == branch over {} recorded values", new.steps.len());
}

// ── 4. first-depositor / donation attack ─────────────────────────────────────────────────────

#[test]
fn first_deposit_must_exceed_the_dead_share_floor() {
    let mut env = setup_vault();
    let e = try_deposit(&mut env, 1_000).err().expect("exactly the floor mints nothing: refused");
    assert!(e.contains(&custom(PercolatorError::LpVaultDepositBelowMinimumLiquidity)), "{e}");
    assert_eq!(reg(&env).total_lp_shares_outstanding, 0);
    let a = deposit(&mut env, 1_001);
    assert_eq!(tok(&env.svm, a.lp_ata), 1, "1,001 atoms: 1 share minted, 1,000 dead");
    assert_eq!(reg(&env).total_lp_shares_outstanding, 1_001);
}

/// The ERC-4626 inflation attack: be first with the smallest deposit, donate a large amount
/// straight into the vault token account to inflate the share price, and let the victim's
/// deposit round down to nothing. It does not work here, for two independent reasons that this
/// change does not touch: NAV is read from the backing ledgers (a raw token transfer moves no
/// ledger), and the genesis deposit leaves 1,000 dead shares.
#[test]
fn donation_attack_gains_nothing_and_the_victim_is_whole() {
    let mut env = setup_vault();
    let attacker = deposit(&mut env, 1_001);
    assert_eq!(tok(&env.svm, attacker.lp_ata), 1);
    let donation = 1_000 * U as u64;
    add_vault_tokens(&mut env, donation);
    // the victim deposits the same size as the donation
    let victim = deposit(&mut env, 1_000 * U);
    let victim_shares = tok(&env.svm, victim.lp_ata) as u128;
    assert_eq!(victim_shares, 1_000 * U, "the donation did not move the price: 1 share per atom");
    // the attacker's one share is still worth one atom
    assert_eq!(redeem(&mut env, &attacker, 1), 1, "attacker gets 1 atom for the 1 share");
    // the victim gets everything back
    assert_eq!(redeem(&mut env, &victim, victim_shares), 1_000 * U as u64, "victim made whole");
    // the donation is still sitting in the vault token account: the attacker lost it
    assert_eq!(tok(&env.svm, env.vault_token), donation + 1_000, "donation + the dead shares' 1,000 atoms");
    assert_eq!(reg(&env).total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY);
}

/// Same attack through the one channel that DOES move NAV (fee earnings, which an attacker
/// cannot mint at will; modelled here at the attacker's best case). The dead shares bound the
/// victim's rounding loss: with S = 1,001 the loss is under NAV / S atoms per deposit, and the
/// 1,000 dead shares take 1,000/1,001 of the "donated" value, not the attacker.
#[test]
fn inflating_nav_before_the_victim_costs_the_attacker_more_than_it_takes() {
    let mut env = setup_vault();
    let attacker = deposit(&mut env, 1_001);
    let inflate = 1_000 * U;
    seed_earnings(&mut env, 2 * inflate); // NAV = 1,000,001,001 over S = 1,001 (LP half)
    let victim_in = 1_000 * U;
    let victim = deposit(&mut env, victim_in);
    let (s, nav) = (1_001u128, 1_001 + inflate);
    let victim_shares = tok(&env.svm, victim.lp_ata) as u128;
    assert_eq!(victim_shares, victim_in * s / nav);
    assert_eq!(victim_shares, 1_000);
    let attacker_out = redeem(&mut env, &attacker, 1) as u128;
    let victim_out = redeem(&mut env, &victim, victim_shares) as u128;
    println!("attacker: in {} (1,001 + {inflate} of NAV inflation), out {attacker_out}; victim: in {victim_in}, out {victim_out}", 1_001 + inflate);
    // the attacker recovers about 1/2001 of the pot: a loss of ~99.9% of what it put in
    assert!(attacker_out < (1_001 + inflate) / 500, "attacker out {attacker_out}");
    // the victim's rounding loss is bounded by one share's price (~0.1% here), not its deposit
    assert!(victim_in - victim_out <= (nav + victim_in) / (s + victim_shares) + 1, "victim lost {}", victim_in - victim_out);
    assert!(victim_out * 1_000 >= victim_in * 998, "victim keeps >= 99.8%: {victim_out}");
}

// ── 5. redeem rounding ───────────────────────────────────────────────────────────────────────

#[test]
fn redeem_rounds_down_against_the_redeemer_and_never_pays_zero() {
    let mut env = setup_vault();
    let a = deposit(&mut env, 1_000 * U);
    seed_earnings(&mut env, 14); // NAV = 1,000,000,007 over S = 1,000,000,000 (LP half)
    let (s, nav) = (1_000 * U, 1_000 * U + 7);
    // 3 shares are worth 3.000000021 atoms: pays 3
    assert_eq!(redeem(&mut env, &a, 3) as u128, 3 * nav / s);
    assert_eq!(3 * nav / s, 3);
    // 142,857,143 shares are worth 142,857,144.000000001 atoms: pays 142,857,144, never ...145
    let (s1, nav1) = (s - 3, nav - 3);
    let sh = 142_857_143u128;
    let paid = redeem(&mut env, &a, sh) as u128;
    assert_eq!(paid, sh * nav1 / s1);
    assert!(paid * s1 <= sh * nav1, "never more than pro rata");
    assert!((paid + 1) * s1 > sh * nav1, "and exactly the floor");
    // the registry and the mint moved by exactly the burned shares
    assert_eq!(reg(&env).total_lp_shares_outstanding, s1 - sh);
    assert_eq!(lp_mint_state(&env).supply as u128, s1 - sh - LP_VAULT_MINIMUM_LIQUIDITY);
}

/// When a share is worth LESS than one atom, a 1-share redemption would burn it for nothing:
/// refused (the shares stay in escrow, cancellable), not rounded to a 0 payout.
#[test]
fn redeeming_dust_that_rounds_to_zero_atoms_is_refused() {
    let mut env = setup_vault();
    let a = deposit(&mut env, 1_000 * U);
    // halve the price by doubling the share count against the same NAV (state edit: a loss)
    let mut acct = env.svm.get_account(&env.registry).unwrap();
    let mut r = reg(&env);
    r.total_lp_shares_outstanding *= 2;
    state::write_lp_vault_registry(&mut acct.data, &r).unwrap();
    env.svm.set_account(env.registry, acct).unwrap();
    let e = try_redeem(&mut env, &a, 1).expect_err("1 share = 0.5 atom must not be burned for 0");
    assert!(e.contains(&custom(PercolatorError::LpVaultZeroAmount)), "{e}");
}

// ── 6. tag 122 InitLpShareMetadata ───────────────────────────────────────────────────────────

fn metadata_pda(mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[b"metadata", MPL_TOKEN_METADATA_PROGRAM_ID.as_ref(), mint.as_ref()],
        &MPL_TOKEN_METADATA_PROGRAM_ID,
    )
    .0
}

fn metadata_accounts(env: &Env, caller: Pubkey) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(caller, true),
        AccountMeta::new_readonly(env.registry, false),
        AccountMeta::new_readonly(env.lp_mint, false),
        AccountMeta::new(metadata_pda(&env.lp_mint), false),
        AccountMeta::new_readonly(MPL_TOKEN_METADATA_PROGRAM_ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ]
}

fn init_metadata(env: &mut Env, accounts: Vec<AccountMeta>, caller: &Keypair) -> Result<u64, String> {
    let payer = env.payer.insecure_clone();
    send(&mut env.svm, env.program_id, &payer, vec![(ProgInstruction::InitLpShareMetadata, accounts)], &[caller])
}

/// A stand-in executable (the SPL Token ELF) at an arbitrary address (NOT the Metaplex id).
fn fake_program(env: &mut Env) -> Pubkey {
    let k = Pubkey::new_unique();
    env.svm.add_program(k, &std::fs::read(spl_token_program_path()).unwrap());
    k
}

#[test]
fn tag_122_wire_is_one_byte() {
    assert_eq!(ProgInstruction::InitLpShareMetadata.encode(), vec![122u8]);
    assert!(ProgInstruction::decode(&[122]).is_ok());
    assert!(ProgInstruction::decode(&[122, 0]).is_err(), "no arguments: trailing bytes refused");
}

#[test]
fn metadata_refuses_any_program_but_metaplex() {
    let mut env = setup_vault();
    let caller = Keypair::new();
    env.svm.airdrop(&caller.pubkey(), 10_000_000_000).unwrap();
    let fake = fake_program(&mut env);
    let mut accts = metadata_accounts(&env, caller.pubkey());
    accts[4] = AccountMeta::new_readonly(fake, false);
    let e = init_metadata(&mut env, accts, &caller).expect_err("a caller-chosen program must never get the registry PDA's signature");
    assert!(e.contains("IncorrectProgramId"), "{e}");
}

#[test]
fn metadata_refuses_a_wrong_metadata_address_mint_or_registry() {
    let mut env = setup_vault();
    let caller = Keypair::new();
    env.svm.airdrop(&caller.pubkey(), 10_000_000_000).unwrap();
    // The pinned program id must be an executable account for the checks under test to be
    // reached; the stand-in is never invoked because each case is refused before the CPI.
    env.svm.add_program(MPL_TOKEN_METADATA_PROGRAM_ID, &std::fs::read(spl_token_program_path()).unwrap());
    // (a) a metadata address that is not the mint's PDA
    let mut accts = metadata_accounts(&env, caller.pubkey());
    accts[3] = AccountMeta::new(Pubkey::new_unique(), false);
    let e = init_metadata(&mut env, accts, &caller).expect_err("wrong metadata PDA");
    assert!(e.contains("InvalidArgument"), "{e}");
    // (b) a mint that is not this registry's share mint (the collateral mint)
    let mut accts = metadata_accounts(&env, caller.pubkey());
    accts[2] = AccountMeta::new_readonly(env.collateral_mint, false);
    accts[3] = AccountMeta::new(metadata_pda(&env.collateral_mint), false);
    let e = init_metadata(&mut env, accts, &caller).expect_err("a mint that is not the share mint");
    assert!(e.contains("InvalidArgument"), "{e}");
    // (c) a registry that is not a program-owned LP vault registry (the market account)
    let mut accts = metadata_accounts(&env, caller.pubkey());
    accts[1] = AccountMeta::new_readonly(env.market, false);
    let e = init_metadata(&mut env, accts, &caller).expect_err("not a registry");
    assert!(!e.contains("IncorrectProgramId"), "{e}");
    // (d) another market's registry with this market's mint
    let other = setup_vault();
    let mut a = other.svm.get_account(&other.registry).unwrap();
    a.owner = env.program_id;
    env.svm.set_account(other.registry, a).unwrap();
    let mut accts = metadata_accounts(&env, caller.pubkey());
    accts[1] = AccountMeta::new_readonly(other.registry, false);
    let e = init_metadata(&mut env, accts, &caller).expect_err("another market's registry");
    assert!(e.contains("InvalidArgument"), "{e}");
    // nothing was created
    assert!(env.svm.get_account(&metadata_pda(&env.lp_mint)).map(|a| a.data.is_empty()).unwrap_or(true));
}

fn mpl_so() -> PathBuf {
    let p = PathBuf::from(std::env::var("MPL_TOKEN_METADATA_SO").expect("MPL_TOKEN_METADATA_SO"));
    assert!(p.exists(), "{p:?}");
    p
}

fn borsh_str(data: &[u8], o: &mut usize) -> String {
    let n = u32::from_le_bytes(data[*o..*o + 4].try_into().unwrap()) as usize;
    let s = String::from_utf8(data[*o + 4..*o + 4 + n].to_vec()).unwrap();
    *o += 4 + n;
    s.trim_end_matches('\0').to_string()
}

/// The REAL Metaplex Token Metadata program (dumped from mainnet), called through tag 122 by a
/// stranger: the metadata account exists, carries the fixed name, and no account of this
/// program changed.
#[test]
#[ignore = "needs MPL_TOKEN_METADATA_SO=<dump of metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s>"]
fn metadata_is_created_by_the_real_metaplex_program_with_the_fixed_name() {
    let mut env = setup_vault();
    env.svm.add_program(MPL_TOKEN_METADATA_PROGRAM_ID, &std::fs::read(mpl_so()).unwrap());
    let a = deposit(&mut env, 1_000 * U);
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let before = (
        env.svm.get_account(&env.registry).unwrap().data,
        env.svm.get_account(&env.lp_mint).unwrap().data,
        env.svm.get_account(&env.market).unwrap().data,
        env.svm.get_account(&env.ledger).unwrap().data,
    );
    let lamports_before = env.svm.get_account(&stranger.pubkey()).unwrap().lamports;
    let accts = metadata_accounts(&env, stranger.pubkey());
    let cu = init_metadata(&mut env, accts.clone(), &stranger).expect("tag 122");
    let cost = lamports_before - env.svm.get_account(&stranger.pubkey()).unwrap().lamports;
    println!("tag 122 InitLpShareMetadata: {cu} CU (whole tx); caller paid {cost} lamports (rent + Metaplex fee)");
    let md = env.svm.get_account(&metadata_pda(&env.lp_mint)).expect("metadata account");
    assert_eq!(md.owner, MPL_TOKEN_METADATA_PROGRAM_ID);
    assert_eq!(md.data[0], 4, "Key::MetadataV1");
    assert_eq!(&md.data[1..33], env.registry.as_ref(), "update authority = registry PDA");
    assert_eq!(&md.data[33..65], env.lp_mint.as_ref(), "mint");
    let mut o = 65;
    let name = borsh_str(&md.data, &mut o);
    let symbol = borsh_str(&md.data, &mut o);
    let uri = borsh_str(&md.data, &mut o);
    println!("name={name:?} symbol={symbol:?} uri={uri:?} metadata len={}", md.data.len());
    assert_eq!(name, format!("Percolator Earn Share {}", &env.market.to_string()[..8]));
    assert_eq!(symbol, "pEARN");
    assert_eq!(uri, "");
    assert_eq!(u16::from_le_bytes([md.data[o], md.data[o + 1]]), 0, "seller fee");
    assert_eq!(md.data[o + 2], 0, "no creators");
    assert_eq!(md.data[o + 3], 0, "primary_sale_happened = false");
    assert_eq!(md.data[o + 4], 0, "is_mutable = false");
    let after = (
        env.svm.get_account(&env.registry).unwrap().data,
        env.svm.get_account(&env.lp_mint).unwrap().data,
        env.svm.get_account(&env.market).unwrap().data,
        env.svm.get_account(&env.ledger).unwrap().data,
    );
    assert!(before == after, "registry, mint, market and ledger are byte-identical after tag 122");
    // second call: Metaplex refuses an existing metadata account
    let e = init_metadata(&mut env, accts, &stranger).expect_err("runs once per mint");
    println!("second tag 122 -> {}", &e[..e.len().min(160)]);
    // shares still mint, burn and price exactly as before
    assert_eq!(redeem(&mut env, &a, 999_999_000), 999_999_000);
}

/// Tag 122 needs the caller's signature (it pays) and works with no deposit yet.
#[test]
#[ignore = "needs MPL_TOKEN_METADATA_SO"]
fn metadata_needs_a_signing_payer_and_works_on_an_empty_vault() {
    let mut env = setup_vault();
    env.svm.add_program(MPL_TOKEN_METADATA_PROGRAM_ID, &std::fs::read(mpl_so()).unwrap());
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 10_000_000_000).unwrap();
    let mut accts = metadata_accounts(&env, stranger.pubkey());
    accts[0] = AccountMeta::new(stranger.pubkey(), false);
    let payer = env.payer.insecure_clone();
    let e = send(&mut env.svm, env.program_id, &payer, vec![(ProgInstruction::InitLpShareMetadata, accts)], &[])
        .expect_err("unsigned payer");
    assert!(e.contains(&custom(PercolatorError::ExpectedSigner)), "{e}");
    let accts = metadata_accounts(&env, stranger.pubkey());
    init_metadata(&mut env, accts, &stranger).expect("tag 122 on an empty vault");
    assert_eq!(lp_mint_state(&env).supply, 0);
}

// ── 7. compute ───────────────────────────────────────────────────────────────────────────────

#[test]
fn print_tag_74_compute_units() {
    FIXED_MARKET.with(|c| c.set(Some(Pubkey::new_from_array([7u8; 32]))));
    let mut env = setup_market();
    let mint = env.collateral_mint;
    let cu = create_vault_with(&mut env, vec![AccountMeta::new_readonly(mint, false)]).expect("create");
    println!("tag 74 CreateLpVault (7 accounts): {cu} CU (whole tx incl. 2 compute-budget ixs)");
    if let Ok(base) = std::env::var("LP_SHARE_BASE_SO") {
        SO_OVERRIDE.with(|c| *c.borrow_mut() = Some(PathBuf::from(base)));
        let mut env = setup_market();
        let cu_base = create_vault_with(&mut env, vec![]).expect("base create (6 accounts)");
        SO_OVERRIDE.with(|c| *c.borrow_mut() = None);
        println!("tag 74 CreateLpVault on the BASE build (6 accounts), same market address: {cu_base} CU; delta {}", cu as i64 - cu_base as i64);
    }
    FIXED_MARKET.with(|c| c.set(None));
}
