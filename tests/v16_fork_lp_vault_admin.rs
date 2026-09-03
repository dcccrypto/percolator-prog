// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! LP Vault crank + admin tests (Phase 2.B Tier 3, Workstream 4B — Phases F + G).
//!
//! F — LpVaultCrankFees (tag 78): no-new-fees reject (happy path needs bucket
//!     utilization earnings, i.e. trades → Phase 2.E assembled-system test).
//! G — SetLpVaultPaused (79) + CloseLpVault (80): pause blocks deposit, unpause
//!     restores, close-with-shares rejects, close-empty ok, non-admin rejects.
//!
//! Cross-reference: lp_vault_design.md §5.3/§5; src/v16_program.rs
//! handle_lp_vault_crank_fees / handle_set_lp_vault_paused / handle_close_lp_vault.

use litesvm::LiteSVM;
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
const APPEND_ASSET_INDEX: u16 = 1;
const DOMAIN: u16 = 2;
const DEPOSIT: u128 = 1_000_000;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing");
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
        let c = reg
            .expect("e")
            .path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if c.exists() {
            return c;
        }
    }
    panic!("spl_token BPF not found");
}
fn make_mint_data() -> Vec<u8> {
    let mut d = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
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
}

fn send(
    svm: &mut LiteSVM,
    pid: Pubkey,
    payer: &Keypair,
    ix: ProgInstruction,
    accounts: Vec<AccountMeta>,
    extra: &[&Keypair],
) -> Result<(), String> {
    let instruction = Instruction {
        program_id: pid,
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

fn setup_vault() -> Env {
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

    let (registry, _) = derive_lp_vault_registry(&program_id, &market);
    let (lp_mint, _) = derive_lp_vault_mint(&program_id, &market);
    let (ledger, _) = derive_lp_backing_ledger(&program_id, &market, DOMAIN);
    let (vault_authority, _) =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
    let vault_token = canonical_vault_ata(&vault_authority, &collateral_mint);
    set_token(&mut svm, vault_token, collateral_mint, vault_authority, 0);

    send(
        &mut svm,
        program_id,
        &payer,
        ProgInstruction::UpdateAssetLifecycle {
            action: ASSET_ACTION_ACTIVATE,
            asset_index: APPEND_ASSET_INDEX,
            now_slot: 1,
            initial_price: 100,
            insurance_authority: admin.pubkey().to_bytes(),
            insurance_operator: admin.pubkey().to_bytes(),
            backing_bucket_authority: registry.to_bytes(),
            oracle_authority: admin.pubkey().to_bytes(),
        },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
        ],
        &[&admin],
    )
    .expect("append asset 1");

    send(
        &mut svm,
        program_id,
        &payer,
        ProgInstruction::CreateLpVault {
            fee_share_bps: 5_000,
            redemption_cooldown_slots: 0,
            oi_reservation_threshold_bps: 0,
            domain: DOMAIN,
        },
        // FIND-1 fix: market must be writable — CreateLpVault now writes
        // backing_bucket_authority = registry PDA into the asset's oracle profile.
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(registry, false),
            AccountMeta::new(lp_mint, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&admin],
    )
    .expect("create lp vault");

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
    }
}

/// Make a depositor + deposit `amount`. Returns (kp, lp_ata, source).
fn deposit(env: &mut Env, amount: u128) -> (Keypair, Pubkey, Pubkey) {
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(
        &mut env.svm,
        source,
        env.collateral_mint,
        kp.pubkey(),
        10_000_000,
    );
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, env.lp_mint, kp.pubkey(), 0);
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = vec![
        AccountMeta::new(kp.pubkey(), true),
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
    ];
    send(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::DepositToLpVault {
            amount,
            domain: DOMAIN,
        },
        accts,
        &[&kp],
    )
    .expect("deposit");
    (kp, lp_ata, source)
}

fn try_deposit(
    env: &mut Env,
    kp: &Keypair,
    lp_ata: Pubkey,
    source: Pubkey,
    amount: u128,
) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = vec![
        AccountMeta::new(kp.pubkey(), true),
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
    ];
    send(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::DepositToLpVault {
            amount,
            domain: DOMAIN,
        },
        accts,
        &[kp],
    )
}

fn set_paused(env: &mut Env, signer: &Keypair, paused: u8) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::SetLpVaultPaused { paused },
        vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),
            AccountMeta::new(env.registry, false),
        ],
        &[signer],
    )
}

fn close_vault(env: &mut Env, signer: &Keypair) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::CloseLpVault,
        vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new_readonly(env.lp_mint, false),
        ],
        &[signer],
    )
}

fn crank_fees(env: &mut Env) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        ProgInstruction::LpVaultCrankFees { domain: DOMAIN },
        vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(env.registry, false),
            AccountMeta::new(env.ledger, false),
            AccountMeta::new(
                derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN ^ 1).0,
                false,
            ),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        &[],
    )
}

// ── F: CrankFees ────────────────────────────────────────────────────

#[test]
fn crank_fees_no_new_fees_rejects() {
    // FEE-SPLIT REPOINT (Task 7): the crank now keys off the wrapper-side LP
    // fee counter, not the backing bucket. No trades → lp_fee_accrued_atoms ==
    // lp_fee_withdrawn_atoms == 0 → available 0 → LpVaultNoFeesToCrank (38).
    let mut env = setup_vault();
    let _ = deposit(&mut env, DEPOSIT); // creates the backing ledger
    env.svm.expire_blockhash();
    let res = crank_fees(&mut env);
    let err = res.expect_err("crank with no accrued LP fees must reject");
    assert!(
        err.contains("Custom(38)"),
        "zero-available crank must return LpVaultNoFeesToCrank = Custom(38), got: {err}"
    );
}

// ── G: Pause / Unpause / Close ──────────────────────────────────────

#[test]
fn pause_blocks_deposit_unpause_restores() {
    let mut env = setup_vault();
    let admin = env.admin.insecure_clone();
    // Pause.
    set_paused(&mut env, &admin, 1).expect("pause");
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(
        &mut env.svm,
        source,
        env.collateral_mint,
        kp.pubkey(),
        10_000_000,
    );
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, env.lp_mint, kp.pubkey(), 0);
    let res = try_deposit(&mut env, &kp, lp_ata, source, DEPOSIT);
    assert!(
        res.is_err(),
        "deposit while paused must reject (LpVaultPaused): {res:?}"
    );

    // Unpause → deposit ok.
    env.svm.expire_blockhash();
    set_paused(&mut env, &admin, 0).expect("unpause");
    env.svm.expire_blockhash();
    try_deposit(&mut env, &kp, lp_ata, source, DEPOSIT).expect("deposit after unpause");
}

#[test]
fn set_paused_rejects_non_admin() {
    let mut env = setup_vault();
    let attacker = Keypair::new();
    env.svm
        .airdrop(&attacker.pubkey(), 100_000_000_000)
        .unwrap();
    let res = set_paused(&mut env, &attacker, 1);
    assert!(res.is_err(), "non-admin pause must reject: {res:?}");
}

#[test]
fn close_with_shares_outstanding_rejects() {
    let mut env = setup_vault();
    let _ = deposit(&mut env, DEPOSIT); // outstanding shares > 0
    env.svm.expire_blockhash();
    let admin = env.admin.insecure_clone();
    let res = close_vault(&mut env, &admin);
    assert!(
        res.is_err(),
        "close with outstanding shares must reject: {res:?}"
    );
}

#[test]
fn close_empty_vault_ok() {
    // Fresh vault, no deposits → outstanding 0, mint supply 0 → close ok.
    let mut env = setup_vault();
    let admin = env.admin.insecure_clone();
    let lamports_before = env.svm.get_account(&admin.pubkey()).unwrap().lamports;
    close_vault(&mut env, &admin).expect("close empty vault");
    // Registry data zeroed → unreadable.
    let acct = env.svm.get_account(&env.registry).unwrap();
    assert!(
        state::read_lp_vault_registry(&acct.data).is_err(),
        "registry consumed"
    );
    // Rent reclaimed to admin.
    let lamports_after = env.svm.get_account(&admin.pubkey()).unwrap().lamports;
    assert!(lamports_after >= lamports_before, "rent reclaimed to admin");
}

#[test]
fn close_rejects_non_admin() {
    let mut env = setup_vault();
    let attacker = Keypair::new();
    env.svm
        .airdrop(&attacker.pubkey(), 100_000_000_000)
        .unwrap();
    let res = close_vault(&mut env, &attacker);
    assert!(res.is_err(), "non-admin close must reject: {res:?}");
}

// ── Phase 2.E deferred LP test #2: LpVaultCrankFees happy path ──────────────
/// Seed accrued utilization-fee earnings into the domain backing bucket — the
/// EXACT field that real backing trades write and that `sync_backing_domain_ledger`
/// reads (v16_program.rs:7918). `group.vault` is bumped by the same amount so the
/// seeded market stays solvent (senior <= vault). This isolates the crank's
/// distribution bookkeeping (the operative thing under test) from the orthogonal
/// trade-fee-accrual machinery.
fn seed_bucket_earnings(env: &mut Env, earnings: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.source_backing_buckets[DOMAIN as usize].utilization_fee_earnings += earnings;
    group.vault += earnings;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

/// FEE-SPLIT REPOINT (Task 7) counterpart of `seed_bucket_earnings`: seed the
/// wrapper-side LP fee counter tag 78 now drains. Same accepted direct-write
/// boundary (`state::read_market` / `state::write_market`) — the production
/// producer is `split_trade_fee`'s LP leg at the two trade fee sites, which
/// needs a full trading env this file does not build.
///
/// TASK 7 COMPLETION: the counter alone is no longer a faithful fixture. In
/// production the engine credits the WHOLE trade fee into `header.insurance` at
/// constant vault (`c_tot -= charged; insurance += charged`, engine
/// v16.rs:13798) and `split_trade_fee` merely EARMARKS the LP leg in
/// `cfg.lp_fee_accrued_atoms`. The crank now reclassifies those atoms out of
/// insurance into LP backing and clamps to the engine-available surplus, so a
/// counter with no insurance behind it correctly clamps to 0. This env has no
/// traders and therefore no `c_tot` to drain, so the atoms are added to
/// `insurance` AND `vault` instead — same accepted boundary, and it preserves
/// the property that actually matters: the fee atoms sit inside
/// `header.insurance`, inside `header.vault`, before the crank.
fn seed_lp_fee_accrued(env: &mut Env, atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (mut cfg, mut group) = state::read_market(&acct.data).expect("read market");
    cfg.lp_fee_accrued_atoms += atoms;
    group.insurance += atoms;
    group.vault += atoms;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

fn lp_fee_counters(env: &Env) -> (u128, u128) {
    let acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, _) = state::read_market(&acct.data).expect("read market");
    (cfg.lp_fee_accrued_atoms, cfg.lp_fee_withdrawn_atoms)
}

fn registry(env: &Env) -> state::LpVaultRegistryV16 {
    state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap()
}

fn ledger_total_earnings(env: &Env) -> u128 {
    state::read_backing_domain_ledger(&env.svm.get_account(&env.ledger).unwrap().data)
        .unwrap()
        .total_earnings_atoms
}

#[test]
fn crank_fees_distributes_lp_share_after_earnings() {
    let mut env = setup_vault();
    let _ = deposit(&mut env, DEPOSIT); // creates the backing ledger + outstanding shares

    // FEE-SPLIT REPOINT (Task 7): the crank's SOURCE is now
    // `cfg.lp_fee_accrued_atoms - cfg.lp_fee_withdrawn_atoms`, not the backing
    // bucket's utilization earnings. Bucket earnings are still seeded here to
    // pin the ledger-sync half of the handler, which is unchanged.
    let earnings: u128 = 1_000_000;
    seed_bucket_earnings(&mut env, earnings);
    let lp_fees: u128 = 777_777;
    seed_lp_fee_accrued(&mut env, lp_fees);

    let reg_before = registry(&env);
    let te_before = ledger_total_earnings(&env);
    let (accrued_before, withdrawn_before) = lp_fee_counters(&env);
    assert_eq!(
        withdrawn_before, 0,
        "nothing withdrawn before the first crank"
    );
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("crank with accrued LP fees must succeed");
    let reg_after = registry(&env);
    let te_after = ledger_total_earnings(&env);
    let (accrued_after, withdrawn_after) = lp_fee_counters(&env);

    // GAP-CRANKFEES (Phase 3A.2 belt-and-braces): exact ledger sync is unchanged.
    // total_earnings_atoms grew by EXACTLY the accrued bucket earnings.
    assert_eq!(
        te_after - te_before,
        earnings,
        "total_earnings_atoms grew by EXACTLY the accrued earnings: {te_before} -> {te_after}"
    );
    // The snapshot advances to the current total_earnings.
    assert_eq!(
        reg_after.insurance_fee_snapshot_atoms, te_after,
        "fee snapshot must advance to current total_earnings"
    );

    // The crank credits the WHOLE available LP claim — `registry.fee_share_bps`
    // is deliberately NOT re-applied, because `lp_fee_accrued_atoms` is already
    // the LP-designated leg of `split_trade_fee`. A second split would strand
    // atoms with no destination counter.
    let grew = reg_after.fee_distribution_total_atoms - reg_before.fee_distribution_total_atoms;
    // `lp_fees` (777_777) is deliberately NOT any fraction of the seeded bucket
    // `earnings` (1_000_000), so a credit sourced from the bucket cannot
    // coincidentally satisfy this.
    assert_eq!(
        grew, lp_fees,
        "the crank credits the full available LP claim, unsplit"
    );

    // WRITE-BACK PROOF, half 1: `withdrawn` advanced by EXACTLY the credited
    // amount and `accrued` is untouched — so the invariant
    // `lp_fee_withdrawn_atoms <= lp_fee_accrued_atoms` is preserved.
    assert_eq!(
        accrued_after, accrued_before,
        "accrued must not move on a crank"
    );
    assert_eq!(
        withdrawn_after - withdrawn_before,
        grew,
        "lp_fee_withdrawn_atoms must advance by exactly what was credited"
    );

    // WRITE-BACK PROOF, half 2 (the counter-reset trap): a second crank with no
    // new accrual must find available == 0 and reject with Custom(38). If the
    // cfg write-back above were missing, `withdrawn` would have reset to 0 and
    // this crank would credit the SAME atoms a second time.
    env.svm.expire_blockhash();
    let again = crank_fees(&mut env);
    let err = again.expect_err("second crank with no new LP fees must reject");
    assert!(
        err.contains("Custom(38)"),
        "re-crank must return LpVaultNoFeesToCrank = Custom(38), got: {err}"
    );
    assert_eq!(
        registry(&env).fee_distribution_total_atoms,
        reg_after.fee_distribution_total_atoms,
        "a rejected re-crank must not credit anything"
    );
}

#[test]
fn crank_fees_second_accrual_credits_only_the_delta() {
    // Claim capacity is `accrued - withdrawn`, not gross `accrued`: after a
    // first crank drains the counter, a fresh accrual must credit ONLY the new
    // delta. Isolated from `crank_fees_distributes_lp_share_after_earnings` so
    // the delta assertion is reached on its own.
    let mut env = setup_vault();
    let _ = deposit(&mut env, DEPOSIT);

    seed_lp_fee_accrued(&mut env, 777_777);
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("first crank must succeed");
    let after_first = registry(&env).fee_distribution_total_atoms;

    seed_lp_fee_accrued(&mut env, 3);
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("crank after a fresh accrual must succeed");
    assert_eq!(
        registry(&env).fee_distribution_total_atoms - after_first,
        3,
        "only the NEW accrual delta is credited, not gross accrued"
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
