// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! PoC — PERMANENT LP-redemption stranding when the market leaves `Live`
//! while a redemption request is in flight (v17 Solana program).
//!
//! ── The bug ────────────────────────────────────────────────────────────────
//! The LP-vault redemption is a TWO-STEP flow:
//!
//!   1. `RequestRedeemLpShares` (tag 76, src/v16_program.rs handle_request_redeem_lp_shares):
//!        * TRANSFERS the redeemer's LP shares OUT of their LP ATA and INTO the
//!          per-vault registry escrow ATA (`transfer_tokens(... redeemer_lp_ata ->
//!          escrow ...)`).
//!        * Writes an `LpRedemption` PDA recording the pending request.
//!        * Leaves `registry.total_lp_shares_outstanding` UNCHANGED (shares are
//!          escrowed, not burned — comment: "total_lp_shares_outstanding UNCHANGED
//!          (I2 holds)").
//!
//!   2. `ExecuteRedemption` (tag 77, handle_execute_redemption) is the ONLY way to
//!      get those escrowed shares back (as pro-rata collateral). It HARD-REQUIRES
//!      the market be Live:
//!
//!          let (cfg, mode, configured_slots, _) =
//!              state::read_market_config_mode_and_capacity(...)?;
//!          if mode != MarketModeV16::Live {
//!              return Err(PercolatorError::EngineLockActive.into());   // Custom(21)
//!          }
//!
//! There is NO third instruction that cancels a pending request and returns the
//! escrowed shares to the redeemer. A grep across src/ for a cancel/return path on
//! the LP-redemption escrow finds NONE — the only "cancel"-named surfaces are the
//! unrelated `cancel_deposit_escrow` registry field and the portfolio-level
//! `CureAndCancelClose`; neither touches the LP redemption escrow.
//!
//! ── The permanent loss-of-access ───────────────────────────────────────────
//! If the market leaves `Live` (e.g. an admin `ResolveMarket`, tag 19) while a
//! redemption request is pending, then:
//!
//!   * `ExecuteRedemption` can never succeed again (mode != Live → EngineLockActive),
//!     so the redeemer can never receive their pro-rata assets and can never get
//!     their escrowed shares back.
//!   * No cancel/return instruction exists, so the escrowed shares cannot be
//!     clawed back to the redeemer's LP ATA either.
//!   * `total_lp_shares_outstanding` was never decremented and the escrow still
//!     holds the shares, so `CloseLpVault` (which requires
//!     `total_lp_shares_outstanding == 0` AND live mint supply == 0) can never run.
//!
//! Net effect: a redeemer who happens to have an in-flight `RequestRedeemLpShares`
//! at the moment the market is resolved PERMANENTLY loses access to both their LP
//! shares and the pro-rata collateral those shares represent. The funds are stuck
//! in the escrow ATA forever. The only fix is a new `CancelRedemption` instruction
//! (return the escrowed shares to the redeemer + delete the LpRedemption PDA),
//! which does not exist in this program.
//!
//! ── This test ──────────────────────────────────────────────────────────────
//! The harness/imports/helpers below are reused VERBATIM from
//! tests/v16_fork_lp_vault_redeem.rs (the passing full deposit→request→execute
//! suite), so the request/execute account lists are identical to the green tests.
//! The single addition is a `ResolveMarket` instruction builder (account list
//! modeled on tests/v16_wrapper.rs: `[admin (signer), market (writable)]`) and the
//! mode read modeled on tests/v16_wrapper.rs (`state::read_market(..).1.mode`).
//!
//! Sequence (PASSING test that proves the stranding):
//!   1. Set up market + LP vault; depositor deposits and receives LP shares.
//!   2. `RequestRedeemLpShares` → assert depositor's LP ATA is now 0, escrow holds
//!      the shares, the `LpRedemption` PDA exists, and total_lp_shares_outstanding
//!      is UNCHANGED.
//!   3. `ResolveMarket` → assert the market is no longer Live (mode == Resolved).
//!   4. `ExecuteRedemption` → assert it FAILS with EngineLockActive (Custom(21)).
//!   5. Demonstrate no recovery: LP ATA still 0, escrow still holds the shares,
//!      the LpRedemption PDA is still present (request neither executes nor
//!      cancels), and `CloseLpVault` also FAILS (shares still outstanding).
//!
//! Cross-reference: lp_vault_design.md §5.6; src/v16_program.rs
//! handle_request_redeem_lp_shares / handle_execute_redemption / handle_resolve_market.

use litesvm::LiteSVM;
use percolator::MarketModeV16;
use percolator_prog::constants::LP_VAULT_MINIMUM_LIQUIDITY;
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
const APPEND_ASSET_INDEX: u16 = 1;
const DOMAIN: u16 = 2;
const DEPOSIT: u128 = 1_000_000;
// BUG-2 / N7: `new_depositor` below is always the vault's TRUE genesis
// depositor (each test builds a fresh vault via `setup_vault`), so the
// wrapper's LP_VAULT_MINIMUM_LIQUIDITY dead-share carve-out applies — the
// depositor's LP ATA holds DEPOSIT - LP_VAULT_MINIMUM_LIQUIDITY, NOT DEPOSIT
// (registry.total_lp_shares_outstanding is still DEPOSIT; the difference is
// permanently unminted dead supply). Use MINTED wherever a REAL token
// balance (LP ATA / escrow / redemption.shares / redeemed collateral) is
// asserted or requested; DEPOSIT stays correct only for
// total_lp_shares_outstanding and the collateral vault balance.
const MINTED: u128 = DEPOSIT - LP_VAULT_MINIMUM_LIQUIDITY;

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
) -> Result<(), String> {
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
    let tx = Transaction::new_signed_with_payer(
        &instructions,
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

/// Build a vault on domain 2 (asset 1) with backing authority = registry, and a
/// given redemption cooldown. Returns Env. (Verbatim from v16_fork_lp_vault_redeem.rs.)
fn setup_vault(cooldown_slots: u64) -> Env {
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

    // Append asset 1 with registry as backing authority, then create vault.
    send(
        &mut svm,
        program_id,
        &payer,
        vec![(
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
        )],
        &[&admin],
    )
    .expect("append asset 1");

    send(
        &mut svm,
        program_id,
        &payer,
        vec![(
            ProgInstruction::CreateLpVault {
                fee_share_bps: 5_000,
                redemption_cooldown_slots: cooldown_slots,
                oi_reservation_threshold_bps: 0,
                domain: DOMAIN,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                // FIND-1 fix: market must be writable — CreateLpVault now writes
                // backing_bucket_authority = registry PDA into the asset's oracle profile.
                AccountMeta::new(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new(lp_mint, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        )],
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
        escrow,
        vault_authority,
    }
}

/// A depositor with a funded source + LP ATA who has deposited `amount`.
/// (Verbatim from v16_fork_lp_vault_redeem.rs.)
struct Depositor {
    kp: Keypair,
    #[allow(dead_code)]
    source: Pubkey,
    lp_ata: Pubkey,
    dest: Pubkey, // collateral payout destination
    redemption: Pubkey,
}

fn deposit_accounts(
    env: &Env,
    lp_ata: Pubkey,
    source: Pubkey,
    depositor: Pubkey,
) -> Vec<AccountMeta> {
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

fn new_depositor(env: &mut Env, amount: u128) -> Depositor {
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
    let dest = Pubkey::new_unique();
    set_token(&mut env.svm, dest, env.collateral_mint, kp.pubkey(), 0);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &env.registry, &kp.pubkey());

    let market = env.market;
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = deposit_accounts(env, lp_ata, source, kp.pubkey());
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::DepositToLpVault {
                amount,
                domain: DOMAIN,
            },
            accts,
        )],
        &[&kp],
    )
    .expect("deposit");
    let _ = market;
    Depositor {
        kp,
        source,
        lp_ata,
        dest,
        redemption,
    }
}

fn request_accounts(env: &Env, d: &Depositor) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(d.kp.pubkey(), true),
        AccountMeta::new(env.registry, false),
        AccountMeta::new(env.lp_mint, false),
        AccountMeta::new(d.lp_ata, false),
        AccountMeta::new(env.escrow, false),
        AccountMeta::new(d.redemption, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
    ]
}

fn execute_accounts(env: &Env, d: &Depositor) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(env.payer.pubkey(), true),
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
        // Sibling-domain ledger: NAV spans both pots of the vault's asset.
        AccountMeta::new(
            derive_lp_backing_ledger(&env.program_id, &env.market, DOMAIN ^ 1).0,
            false,
        ),
        // GH#412 (account 12): the redeemer's own SOL account. The redemption
        // PDA's rent is returned here rather than to the cranker, matching what
        // CancelRedemption already did.
        AccountMeta::new(d.kp.pubkey(), false),
    ]
}

fn tok(svm: &LiteSVM, key: Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(&key).expect("acct").data)
        .expect("decode")
        .amount
}

fn request(env: &mut Env, d: &Depositor, lp_amount: u128) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let kp = d.kp.insecure_clone();
    let accts = request_accounts(env, d);
    // v17 CHANGE: field renamed from lp_amount → shares.
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::RequestRedeemLpShares { shares: lp_amount },
            accts,
        )],
        &[&kp],
    )
}

fn execute(env: &mut Env, d: &Depositor) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = execute_accounts(env, d);
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(ProgInstruction::ExecuteRedemption { domain: DOMAIN }, accts)],
        &[],
    )
}

// ── PoC-only additions ──────────────────────────────────────────────────────

/// ResolveMarket (tag 19): moves the market out of `Live` (-> Resolved). Account
/// list modeled on tests/v16_wrapper.rs (`[admin (signer, writable), market
/// (writable)]`); handle_resolve_market only needs the market-level authority
/// (cfg.marketauth, which is the InitMarket signer == `env.admin`) and the market
/// account. It sets header.mode = Resolved.
fn resolve_market(env: &mut Env) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let admin = env.admin.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::ResolveMarket,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.market, false),
            ],
        )],
        &[&admin],
    )
}

/// Read the live market mode (modeled on tests/v16_wrapper.rs:
/// `state::read_market(..).unwrap().1.mode`).
fn market_mode(env: &Env) -> MarketModeV16 {
    state::read_market(&env.svm.get_account(&env.market).unwrap().data)
        .unwrap()
        .1
        .mode
}

/// CloseLpVault (tag 80): account list modeled on tests/v16_fork_lp_vault_admin.rs
/// (`[admin (signer, writable), market (readonly), registry (writable), lp_mint
/// (readonly)]`). Requires total_lp_shares_outstanding == 0 AND live mint supply
/// == 0; with shares escrowed-but-not-burned, both stay nonzero, so this rejects.
fn close_vault(env: &mut Env) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let admin = env.admin.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::CloseLpVault,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(env.market, false),
                AccountMeta::new(env.registry, false),
                AccountMeta::new_readonly(env.lp_mint, false),
            ],
        )],
        &[&admin],
    )
}

fn reg(env: &Env) -> state::LpVaultRegistryV16 {
    state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap()
}

/// CancelRedemption (tag 81) account list — matches handle_cancel_redemption:
/// [redeemer(signer,writable), registry, redemption, lp_mint, redeemer_lp_ata, escrow, token].
fn cancel_accounts(env: &Env, d: &Depositor) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(d.kp.pubkey(), true), // 0 redeemer (signer, rent dest)
        AccountMeta::new(env.registry, false), // 1 registry
        AccountMeta::new(d.redemption, false), // 2 redemption PDA (consumed)
        AccountMeta::new(env.lp_mint, false),  // 3 lp mint
        AccountMeta::new(d.lp_ata, false),     // 4 redeemer LP ATA (dest)
        AccountMeta::new(env.escrow, false),   // 5 escrow (source)
        AccountMeta::new_readonly(spl_token::ID, false), // 6 token program
    ]
}

fn cancel(env: &mut Env, d: &Depositor) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let kp = d.kp.insecure_clone();
    let accts = cancel_accounts(env, d);
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(ProgInstruction::CancelRedemption, accts)],
        &[&kp],
    )
}

/// HEADLINE PoC — an in-flight redemption is permanently stranded when the market
/// is resolved out of `Live`.
///
/// This is a PASSING test: every assertion below is satisfied by the buggy
/// program, which is precisely what proves the loss-of-access. The redeemer's
/// shares are escrowed (LP ATA == 0), the only release path (ExecuteRedemption)
/// is permanently gated off (EngineLockActive), and there is no cancel path —
/// so the escrow holds the shares forever and CloseLpVault can never run.
#[test]
fn redemption_executes_in_terminal_flat_resolved() {
    // ── 1. Market + LP vault; depositor deposits and receives LP shares. ──
    // Immediate cooldown (0) so the ONLY thing that can block ExecuteRedemption in
    // this test is the mode gate — not the cooldown gate.
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    // BUG-2 / N7: genesis deposit mints MINTED (DEPOSIT - LP_VAULT_MINIMUM_LIQUIDITY)
    // to the depositor; registry.total_lp_shares_outstanding still counts the FULL
    // DEPOSIT (the dead-share floor is permanently unminted, not un-tracked).
    assert_eq!(
        tok(&env.svm, d.lp_ata),
        MINTED as u64,
        "depositor holds LP shares pre-request"
    );
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        DEPOSIT,
        "shares outstanding after deposit"
    );

    // ── 2. RequestRedeemLpShares: shares escrowed, total_outstanding UNCHANGED. ──
    request(&mut env, &d, MINTED).expect("request");
    // (a) redeemer's LP ATA drained to 0 — they no longer hold the shares.
    assert_eq!(
        tok(&env.svm, d.lp_ata),
        0,
        "PROOF(2a): redeemer LP ATA drained — shares escrowed out"
    );
    // (b) escrow now holds exactly the escrowed shares.
    assert_eq!(
        tok(&env.svm, env.escrow),
        MINTED as u64,
        "PROOF(2b): escrow holds the redeemer's shares"
    );
    // (c) the LpRedemption request PDA exists.
    let pending = state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data)
        .expect("PROOF(2c): LpRedemption PDA written — request is pending");
    assert_eq!(
        pending.shares, MINTED,
        "pending request records the escrowed share count"
    );
    assert_eq!(
        pending.redeemer,
        d.kp.pubkey().to_bytes(),
        "pending request bound to the redeemer"
    );
    // (d) total_lp_shares_outstanding UNCHANGED by the request (shares escrowed, not burned).
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        DEPOSIT,
        "PROOF(2d): total_lp_shares_outstanding UNCHANGED by request"
    );

    // ── 3. Move the market OUT of Live (admin ResolveMarket). ──
    env.svm.expire_blockhash();
    resolve_market(&mut env).expect("resolve market");
    assert_ne!(
        market_mode(&env),
        MarketModeV16::Live,
        "PROOF(3): market is no longer Live"
    );
    assert_eq!(
        market_mode(&env),
        MarketModeV16::Resolved,
        "market resolved"
    );

    // ── 4. ExecuteRedemption now SUCCEEDS in the terminal-flat Resolved state. ──
    // #377/#378: an LP holding shares at resolution must be able to redeem its
    // pro-rata COLLATERAL, not be stranded. This market has no traders, so after
    // ResolveMarket it is terminal-flat (materialized_portfolio_count == 0 && c_tot
    // == 0) — the exact state the loosened ExecuteRedemption gate now permits.
    // Recovery and non-terminal Resolved remain blocked.
    env.svm.expire_blockhash();
    execute(&mut env, &d)
        .expect("PROOF(4): ExecuteRedemption SUCCEEDS in terminal-flat Resolved (#377/#378 fix)");

    // ── 5. The redeemer is made whole and the vault can wind down. ──
    // (a) The redeemer received pro-rata collateral.
    assert!(
        tok(&env.svm, d.dest) > 0,
        "PROOF(5a): redeemer received pro-rata collateral on execute"
    );
    // (b) The escrow was drained — the escrowed shares were consumed.
    assert_eq!(
        tok(&env.svm, env.escrow),
        0,
        "PROOF(5b): escrow drained on execute"
    );
    // (c) total_lp_shares_outstanding burned back down to the LP_VAULT_MINIMUM_LIQUIDITY
    // dead-share floor (this was the sole real depositor; BUG-2 / N7: the floor
    // was counted at genesis but never minted to anyone, so it can never burn
    // below that — see handle_close_lp_vault's matching `> LP_VAULT_MINIMUM_LIQUIDITY`
    // gate below).
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        LP_VAULT_MINIMUM_LIQUIDITY,
        "PROOF(5c): shares burned on execute — outstanding == dead-share floor"
    );
    // (d) The pending request PDA is consumed by execute.
    assert!(
        state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data).is_err(),
        "PROOF(5d): LpRedemption PDA consumed by execute"
    );
    // (e) CloseLpVault can now run — outstanding is at (not above) the dead-share
    //     floor and the stub-credit teardown (#359/#381) leaves no un-owned
    //     residual, so the vault winds down cleanly instead of being stuck forever.
    env.svm.expire_blockhash();
    close_vault(&mut env)
        .expect("PROOF(5e): CloseLpVault succeeds once shares are redeemed and the vault is flat");
}

/// CONTROL — the SAME request executes cleanly when the market stays `Live`.
///
/// This isolates the resolve as the sole cause of the stranding above: with an
/// identical setup but WITHOUT `ResolveMarket`, `ExecuteRedemption` succeeds, the
/// redeemer is paid pro-rata, the escrow burns to zero, and outstanding shares go
/// to zero. So the funds are recoverable iff the market never leaves Live — which
/// is exactly the loss-of-access window the headline test exploits.
#[test]
fn control_redemption_executes_while_market_stays_live() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);

    request(&mut env, &d, MINTED).expect("request");
    assert_eq!(tok(&env.svm, d.lp_ata), 0, "shares escrowed");
    assert_eq!(
        tok(&env.svm, env.escrow),
        MINTED as u64,
        "escrow holds shares"
    );
    assert_eq!(
        market_mode(&env),
        MarketModeV16::Live,
        "market still Live (no resolve)"
    );

    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("execute succeeds while Live");

    // Redeemer paid 1:1 (no earnings) for the shares they actually held (MINTED,
    // not DEPOSIT — BUG-2 / N7 dead-share floor); escrow burned to 0; outstanding
    // -> the dead-share floor, not 0.
    assert_eq!(
        tok(&env.svm, d.dest),
        MINTED as u64,
        "redeemer paid pro-rata"
    );
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow burned to zero");
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        LP_VAULT_MINIMUM_LIQUIDITY,
        "outstanding back to the dead-share floor"
    );
    assert!(
        state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data).is_err(),
        "redemption PDA consumed on successful execute"
    );
}

/// GH#412: the redemption PDA's rent goes to the REDEEMER on execute, not to the
/// cranker.
///
/// It used to go to whoever cranked, while `CancelRedemption` returned it to the
/// redeemer — the same lamports, two different recipients depending on how the
/// request ended. The rent was the redeemer's money either way.
///
/// Asserts BOTH sides of the transfer, not just that the redeemer gained. A test
/// that only checked the credit would still pass if the lamports had been minted
/// from nowhere or taken from the wrong account.
#[test]
fn execute_returns_redemption_rent_to_the_redeemer_not_the_cranker() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);

    request(&mut env, &d, MINTED).expect("request");

    let pda_rent = env
        .svm
        .get_account(&d.redemption)
        .expect("redemption PDA")
        .lamports;
    assert!(
        pda_rent > 0,
        "the redemption PDA must actually hold rent, or this proves nothing"
    );

    let redeemer_before = env
        .svm
        .get_account(&d.kp.pubkey())
        .expect("redeemer")
        .lamports;
    let cranker_before = env
        .svm
        .get_account(&env.payer.pubkey())
        .expect("cranker")
        .lamports;

    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("execute succeeds while Live");

    let redeemer_after = env
        .svm
        .get_account(&d.kp.pubkey())
        .expect("redeemer")
        .lamports;

    // The redeemer receives exactly the PDA's rent. They sign nothing here and pay
    // no fee, so the delta is the reclaim and nothing else.
    assert_eq!(
        redeemer_after - redeemer_before,
        pda_rent,
        "redeemer must receive exactly the redemption PDA's rent"
    );

    // And the cranker does NOT receive it. They pay the tx fee, so their balance
    // falls; the point is that it does not RISE by the rent.
    let cranker_after = env
        .svm
        .get_account(&env.payer.pubkey())
        .expect("cranker")
        .lamports;
    assert!(
        cranker_after < cranker_before + pda_rent,
        "cranker must not collect the redeemer's rent"
    );

    // The PDA is drained, so the lamports came from where we think they did.
    assert!(
        env.svm
            .get_account(&d.redemption)
            .map(|a| a.lamports)
            .unwrap_or(0)
            == 0,
        "redemption PDA must be drained to zero"
    );
}

// ── Regression tests for the CancelRedemption fix (tag 81) ───────────────────

/// FIX: a redemption stranded by the market leaving Live is now recoverable via
/// CancelRedemption — the exact escrowed shares return to the redeemer, the PDA is
/// consumed, and total_lp_shares_outstanding is unchanged (shares were escrowed,
/// not burned). Mirrors the headline stranding scenario, then un-strands it.
#[test]
fn cancel_recovers_stranded_redemption() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    assert_eq!(tok(&env.svm, d.lp_ata), 0, "shares escrowed");
    assert_eq!(
        tok(&env.svm, env.escrow),
        MINTED as u64,
        "escrow holds shares"
    );

    // Resolve the market. (Post-#377/#378, ExecuteRedemption would now SUCCEED here
    // in the terminal-flat state — that path is covered by the headline test. This
    // test instead exercises the ALTERNATIVE recovery: a redeemer who wants their
    // SHARES back rather than executing for collateral.)
    env.svm.expire_blockhash();
    resolve_market(&mut env).expect("resolve");

    // CancelRedemption recovers the shares regardless of market mode.
    env.svm.expire_blockhash();
    cancel(&mut env, &d).expect("cancel must succeed when not Live");
    assert_eq!(
        tok(&env.svm, d.lp_ata),
        MINTED as u64,
        "exact shares returned to redeemer"
    );
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow drained");
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        DEPOSIT,
        "total_lp_shares_outstanding UNCHANGED by cancel"
    );
    assert!(
        state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data).is_err(),
        "redemption PDA consumed by cancel"
    );
}

/// A second cancel is rejected — the consumed redemption PDA prevents double-return.
#[test]
fn cancel_twice_second_rejects() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    cancel(&mut env, &d).expect("first cancel");
    assert_eq!(
        tok(&env.svm, d.lp_ata),
        MINTED as u64,
        "first cancel returned the shares"
    );

    env.svm.expire_blockhash();
    let res = cancel(&mut env, &d);
    assert!(
        res.is_err(),
        "second cancel MUST reject (redemption PDA already consumed): {res:?}"
    );
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64, "no double-return");
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow stays drained");
}

/// Cancel is allowed while the market is Live (it touches no engine state) — a
/// redeemer can change their mind before the cooldown elapses.
#[test]
fn cancel_while_live_succeeds() {
    let mut env = setup_vault(1000); // long cooldown — market stays Live
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    assert_eq!(market_mode(&env), MarketModeV16::Live, "market Live");

    cancel(&mut env, &d).expect("cancel while Live must succeed");
    assert_eq!(
        tok(&env.svm, d.lp_ata),
        MINTED as u64,
        "shares returned to redeemer while Live"
    );
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow drained");
    assert_eq!(
        reg(&env).total_lp_shares_outstanding,
        DEPOSIT,
        "outstanding unchanged"
    );
}

/// Only the recorded redeemer can cancel — a different signer is rejected and the
/// escrow is untouched.
#[test]
fn cancel_wrong_signer_rejected() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");

    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();
    let mut accts = cancel_accounts(&env, &d);
    accts[0] = AccountMeta::new(attacker.pubkey(), true); // attacker signs, victim's redemption PDA
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let res = send(
        &mut env.svm,
        pid,
        &payer,
        vec![(ProgInstruction::CancelRedemption, accts)],
        &[&attacker],
    );
    assert!(
        res.is_err(),
        "a non-redeemer signer must not be able to cancel: {res:?}"
    );
    assert_eq!(
        tok(&env.svm, env.escrow),
        MINTED as u64,
        "escrow untouched by the rejected cancel"
    );
}
