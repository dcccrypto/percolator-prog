// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! LP Vault redeem-flow integration tests (Phase 2.B Tier 3, Workstream 4B — Phase E).
//!
//! RequestRedeemLpShares (tag 76) + ExecuteRedemption (tag 77), B-7 cooldown.
//!
//! HEADLINE invariants (per the pass directive):
//!   - DOUBLE-EXECUTE REPLAY GUARD (data-keyed on the zeroed magic, not lamports):
//!       * `execute_twice_two_tx_second_rejects` — request→execute→execute MUST reject.
//!       * `execute_twice_same_tx_second_rejects` — two ExecuteRedemption ix in ONE
//!         tx → the tx fails (2nd ix rejects on the zeroed magic). This is where a
//!         naive lamport-only close would break.
//!   - I12 escrow == Σ outstanding shares: `multi_redeemer_each_gets_pro_rata` — two
//!     concurrent pending redemptions, execute both, each gets its pro-rata, escrow
//!     zeroes out.
//!   - DIFFERENTIAL `execute_redemption_backing_state_matches_withdraw`.
//!
//! Cross-reference: lp_vault_design.md §5.6; src/v16_program.rs
//! handle_request_redeem_lp_shares / handle_execute_redemption (mirrors
//! handle_withdraw_backing_bucket).

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
// BUG-2 / N7: `new_depositor(env, DEPOSIT)` used as the SOLE depositor in a
// freshly-created vault is always that vault's TRUE genesis deposit, so the
// wrapper's LP_VAULT_MINIMUM_LIQUIDITY dead-share carve-out applies — the
// depositor's LP ATA holds MINTED (DEPOSIT - LP_VAULT_MINIMUM_LIQUIDITY), NOT
// DEPOSIT. registry.total_lp_shares_outstanding still counts the full DEPOSIT.
// Use MINTED wherever a REAL token balance (LP ATA / escrow / redemption
// request/payout) is asserted or requested for a SOLE genesis depositor.
const MINTED: u128 = DEPOSIT - LP_VAULT_MINIMUM_LIQUIDITY;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "wrapper BPF missing — cargo build-sbf --no-default-features");
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
        let cand = reg.expect("entry").path().join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
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

fn set_token(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    svm.set_account(
        key,
        Account { lamports: 1_000_000_000, data: make_token_data(mint, owner, amount), owner: spl_token::ID, executable: false, rent_epoch: 0 },
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

fn send(svm: &mut LiteSVM, program_id: Pubkey, payer: &Keypair, ixs: Vec<(ProgInstruction, Vec<AccountMeta>)>, extra: &[&Keypair]) -> Result<(), String> {
    let mut instructions = vec![
        ComputeBudgetInstruction::request_heap_frame(128 * 1024),
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
    ];
    for (ix, accounts) in ixs {
        instructions.push(Instruction { program_id, accounts, data: ix.encode() });
    }
    let mut signers = vec![payer];
    signers.extend_from_slice(extra);
    let tx = Transaction::new_signed_with_payer(&instructions, Some(&payer.pubkey()), &signers, svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{e:?}"))
}

fn init_market_ix() -> ProgInstruction {
    ProgInstruction::InitMarket {
        max_portfolio_assets: MAX_PORTFOLIO_ASSETS, h_min: 0, h_max: 10, initial_price: 100,
        min_nonzero_mm_req: 1, min_nonzero_im_req: 2, maintenance_margin_bps: 10_000,
        initial_margin_bps: 10_000, max_trading_fee_bps: 10_000, trade_fee_base_bps: 0,
        liquidation_fee_bps: 0, liquidation_fee_cap: 0, min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 10_000, max_accrual_dt_slots: 1, max_abs_funding_e9_per_slot: 0,
        min_funding_lifetime_slots: 1, max_account_b_settlement_chunks: 1, max_bankrupt_close_chunks: 1,
        max_bankrupt_close_lifetime_slots: 100, public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    }
}

/// Build a vault on domain 2 (asset 1) with backing authority = registry, and a
/// given redemption cooldown. Returns Env.
fn setup_vault(cooldown_slots: u64) -> Env {
    setup_vault_oi(cooldown_slots, 0)
}

/// As `setup_vault` but with an explicit OI-reservation threshold (bps). A
/// non-zero threshold arms the I6 guard at ExecuteRedemption (Phase 2.E).
fn setup_vault_oi(cooldown_slots: u64, oi_reservation_threshold_bps: u16) -> Env {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(program_id, &std::fs::read(program_path()).expect("wrapper BPF"));
    svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).expect("token BPF"));

    let payer = Keypair::new();
    let admin = Keypair::new();
    let market = Pubkey::new_unique();
    let collateral_mint = Pubkey::new_unique();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
    svm.set_account(collateral_mint, Account { lamports: 1_000_000_000, data: make_mint_data(), owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    svm.set_account(market, Account { lamports: 1_000_000_000, data: vec![0u8; state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize).unwrap()], owner: program_id, executable: false, rent_epoch: 0 }).unwrap();

    send(&mut svm, program_id, &payer, vec![(init_market_ix(), vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(market, false),
        AccountMeta::new_readonly(collateral_mint, false),
    ])], &[&admin]).expect("init market");

    let (registry, _) = derive_lp_vault_registry(&program_id, &market);
    let (lp_mint, _) = derive_lp_vault_mint(&program_id, &market);
    let (ledger, _) = derive_lp_backing_ledger(&program_id, &market, DOMAIN);
    let (escrow, _) = derive_lp_escrow(&program_id, &market);
    let (vault_authority, _) = Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
    let vault_token = canonical_vault_ata(&vault_authority, &collateral_mint);
    set_token(&mut svm, vault_token, collateral_mint, vault_authority, 0);

    // Append asset 1 with registry as backing authority, then create vault.
    send(&mut svm, program_id, &payer, vec![(ProgInstruction::UpdateAssetLifecycle {
        action: ASSET_ACTION_ACTIVATE, asset_index: APPEND_ASSET_INDEX, now_slot: 1, initial_price: 100,
        insurance_authority: admin.pubkey().to_bytes(), insurance_operator: admin.pubkey().to_bytes(),
        backing_bucket_authority: registry.to_bytes(), oracle_authority: admin.pubkey().to_bytes(),
    }, vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)])], &[&admin]).expect("append asset 1");

    send(&mut svm, program_id, &payer, vec![(ProgInstruction::CreateLpVault {
        fee_share_bps: 5_000, redemption_cooldown_slots: cooldown_slots, oi_reservation_threshold_bps, domain: DOMAIN,
    }, vec![
        AccountMeta::new(admin.pubkey(), true),
        // FIND-1 fix: market must be writable — CreateLpVault now writes
        // backing_bucket_authority = registry PDA into the asset's oracle profile.
        AccountMeta::new(market, false),
        AccountMeta::new(registry, false),
        AccountMeta::new(lp_mint, false),
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        AccountMeta::new_readonly(spl_token::ID, false),
    ])], &[&admin]).expect("create lp vault");

    Env { svm, program_id, payer, admin, market, collateral_mint, vault_token, registry, lp_mint, ledger, escrow, vault_authority }
}

/// A depositor with a funded source + LP ATA who has deposited `amount`.
struct Depositor {
    kp: Keypair,
    source: Pubkey,
    lp_ata: Pubkey,
    dest: Pubkey, // collateral payout destination
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
        // Sibling-domain ledger: NAV spans both pots of the vault's asset.
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
    set_token(&mut env.svm, source, env.collateral_mint, kp.pubkey(), 10_000_000);
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, env.lp_mint, kp.pubkey(), 0);
    let dest = Pubkey::new_unique();
    set_token(&mut env.svm, dest, env.collateral_mint, kp.pubkey(), 0);
    let (redemption, _) = derive_lp_redemption(&env.program_id, &env.registry, &kp.pubkey());

    let market = env.market;
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = deposit_accounts(env, lp_ata, source, kp.pubkey());
    send(&mut env.svm, pid, &payer, vec![(ProgInstruction::DepositToLpVault { amount, domain: DOMAIN }, accts)], &[&kp]).expect("deposit");
    let _ = market;
    Depositor { kp, source, lp_ata, dest, redemption }
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
    ]
}

fn tok(svm: &LiteSVM, key: Pubkey) -> u64 {
    TokenAccount::unpack(&svm.get_account(&key).expect("acct").data).expect("decode").amount
}

fn request(env: &mut Env, d: &Depositor, lp_amount: u128) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let kp = d.kp.insecure_clone();
    let accts = request_accounts(env, d);
    // v17 CHANGE: field renamed from lp_amount → shares.
    send(&mut env.svm, pid, &payer, vec![(ProgInstruction::RequestRedeemLpShares { shares: lp_amount }, accts)], &[&kp])
}

fn execute(env: &mut Env, d: &Depositor) -> Result<(), String> {
    execute_from(env, d, DOMAIN)
}

/// Execute a redemption drawing the payout from a chosen pot of the vault's asset.
fn execute_from(env: &mut Env, d: &Depositor, domain: u16) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accts = execute_accounts(env, d);
    send(&mut env.svm, pid, &payer, vec![(ProgInstruction::ExecuteRedemption { domain }, accts)], &[])
}

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

fn close_lp_vault(env: &mut Env) -> Result<(), String> {
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

fn close_slab(env: &mut Env, dest: Pubkey) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let admin = env.admin.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::CloseSlab,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(env.vault_token, false),
                AccountMeta::new_readonly(env.vault_authority, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        )],
        &[&admin],
    )
}

#[test]
fn request_then_execute_pays_pro_rata() {
    let mut env = setup_vault(0); // immediate
    let d = new_depositor(&mut env, DEPOSIT);
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64);

    request(&mut env, &d, MINTED).expect("request");
    // Shares moved to escrow; redeemer's LP ATA drained.
    assert_eq!(tok(&env.svm, d.lp_ata), 0);
    assert_eq!(tok(&env.svm, env.escrow), MINTED as u64);

    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("execute");
    // Redeemer paid 1:1 (no earnings) for the shares they actually hold; escrow
    // burned to 0; vault drains down to the dead-share floor's principal.
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "redeemer paid pro-rata");
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow burned to zero");
    assert_eq!(
        tok(&env.svm, env.vault_token), (DEPOSIT - MINTED) as u64,
        "vault drained down to the dead-share floor's stranded principal"
    );
    // Registry outstanding back to the dead-share floor, not 0.
    let reg = state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap();
    assert_eq!(reg.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY);
    // Redemption PDA consumed (magic zeroed) → unreadable.
    assert!(state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data).is_err(),
        "redemption PDA consumed");
}

/// FINDING 3 (branch review). `handle_execute_redemption` validated `ledger_ai`
/// with `expect_owner` + `expect_writable` but never `expect_key` — unlike the
/// two other sites that touch the same account, `handle_deposit_to_lp_vault` and
/// `handle_lp_vault_crank_fees`, which both pin the derived address.
///
/// Owner-only is not a real constraint here: this program owns the backing
/// ledger of EVERY (market, domain) pair, so an owner check alone admits any of
/// them. The handler reads `total_principal_atoms` / `cumulative_loss_atoms` off
/// this account to price the redemption and then writes the decremented
/// principal back, so a substituted ledger both misprices the payout and
/// corrupts whichever ledger was swapped in.
///
/// The substitute below is a BYTE-IDENTICAL copy of this market's own real
/// ledger, placed at a non-derived address and still owned by the program.
/// That is deliberate: every other check in the handler — owner, writability,
/// decode, magic, and the market/domain binding stored INSIDE the ledger — still
/// passes on it. The address is the only thing that differs, so the ONLY thing
/// that can reject this transaction is the `expect_key` this finding added. The
/// test therefore isolates that single check and cannot pass for an unrelated
/// reason.
#[test]
fn execute_redemption_rejects_a_substituted_backing_ledger() {
    let mut env = setup_vault(0); // immediate cooldown
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();

    // Byte-identical clone of the real ledger, at an address nobody derives.
    let real = env.svm.get_account(&env.ledger).expect("real ledger exists after deposit");
    assert_eq!(real.owner, env.program_id, "clone source must be program-owned");
    let impostor = Pubkey::new_unique();
    assert_ne!(impostor, env.ledger, "impostor must not be the derived ledger");
    env.svm.set_account(impostor, real.clone()).expect("plant impostor ledger");

    // Swap ONLY the ledger account meta; everything else is the happy path.
    let mut accts = execute_accounts(&env, &d);
    assert_eq!(accts[8].pubkey, env.ledger, "ledger is account index 8");
    accts[8] = AccountMeta::new(impostor, false);

    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let res = send(&mut env.svm, pid, &payer,
        vec![(ProgInstruction::ExecuteRedemption { domain: DOMAIN }, accts)], &[]);

    assert!(res.is_err(), "substituted backing ledger must be rejected, got: {res:?}");
    // `expect_key` returns ProgramError::InvalidArgument.
    let msg = format!("{res:?}");
    assert!(msg.contains("InvalidArgument"),
        "expected InvalidArgument from expect_key(ledger_ai), got: {msg}");

    // Fail-closed: no payout, shares still escrowed, impostor untouched.
    assert_eq!(tok(&env.svm, d.dest), 0, "no payout on a substituted ledger");
    assert_eq!(tok(&env.svm, env.escrow), MINTED as u64, "shares still escrowed");
    assert_eq!(env.svm.get_account(&impostor).expect("impostor").data, real.data,
        "impostor ledger must not have been written");

    // Control: the SAME transaction with the correctly derived ledger succeeds,
    // proving the rejection above is the address check and not broken setup.
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("control: derived ledger still redeems");
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "control payout is pro-rata");
}

#[test]
fn execute_before_cooldown_rejects() {
    let mut env = setup_vault(1000); // long cooldown
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();
    let res = execute(&mut env, &d);
    assert!(res.is_err(), "execute before cooldown must reject (I5): {res:?}");
    assert_eq!(tok(&env.svm, d.dest), 0, "no payout before cooldown");
}

#[test]
fn execute_twice_two_tx_second_rejects() {
    // HEADLINE replay guard (two-tx): request → execute → execute MUST reject, no second payout.
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("first execute");
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64);

    env.svm.expire_blockhash();
    let res = execute(&mut env, &d);
    assert!(res.is_err(), "second execute (2nd tx) MUST reject — replay guard: {res:?}");
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "no second payout");
}

#[test]
fn execute_twice_same_tx_second_rejects() {
    // HEADLINE replay guard (same-tx): two ExecuteRedemption ix in ONE tx. The
    // 2nd reads the magic the 1st zeroed → rejects → whole tx fails atomically.
    // A naive lamport-only close would let a re-funded 2nd execute double-pay;
    // the data-keyed (magic) guard prevents it.
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();

    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let a1 = execute_accounts(&env, &d);
    let a2 = execute_accounts(&env, &d);
    let res = send(&mut env.svm, pid, &payer, vec![
        (ProgInstruction::ExecuteRedemption { domain: DOMAIN }, a1),
        (ProgInstruction::ExecuteRedemption { domain: DOMAIN }, a2),
    ], &[]);
    assert!(res.is_err(), "two ExecuteRedemption in one tx MUST fail (2nd rejects on zeroed magic): {res:?}");
    // Atomic rollback: no payout, redemption PDA intact.
    assert_eq!(tok(&env.svm, d.dest), 0, "no payout — tx rolled back");
    assert!(state::read_lp_redemption(&env.svm.get_account(&d.redemption).unwrap().data).is_ok(),
        "redemption PDA intact after rolled-back tx");
}

#[test]
fn multi_redeemer_each_gets_pro_rata() {
    // I12: escrow == Σ outstanding shares. Two depositors, two concurrent
    // pending redemptions in the shared escrow. Execute both; each gets exactly
    // its pro-rata; escrow zeroes out.
    //
    // BUG-2 / N7: d1 is this vault's TRUE genesis depositor, so it mints only
    // MINTED (999_000, not DEPOSIT) — d2 deposits second (not genesis) and
    // mints the full 2*DEPOSIT, 1:1, unaffected. With no earnings ever seeded,
    // nav == total_shares == available_principal at every step (by induction:
    // every deposit/redemption before this one was exactly 1:1), so BOTH
    // redemptions remain exact — no rounding dust — even with the dead-share
    // floor baked into total_shares.
    let mut env = setup_vault(0);
    let d1 = new_depositor(&mut env, DEPOSIT); // MINTED (999_000) real shares
    let d2 = new_depositor(&mut env, 2 * DEPOSIT); // 2_000_000 shares (1:1, no earnings)

    request(&mut env, &d1, MINTED).expect("request d1");
    request(&mut env, &d2, 2 * DEPOSIT).expect("request d2");
    // I12: escrow holds the sum of both pending redemptions (real shares only).
    assert_eq!(tok(&env.svm, env.escrow), (MINTED + 2 * DEPOSIT) as u64, "escrow == Σ pending shares");

    env.svm.expire_blockhash();
    execute(&mut env, &d1).expect("execute d1");
    env.svm.expire_blockhash();
    execute(&mut env, &d2).expect("execute d2");

    // 1:1, no earnings → each redeems exactly the shares they hold.
    assert_eq!(tok(&env.svm, d1.dest), MINTED as u64, "d1 pro-rata");
    assert_eq!(tok(&env.svm, d2.dest), 2 * DEPOSIT as u64, "d2 pro-rata");
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow zeroes out");
    let reg = state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap();
    assert_eq!(reg.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY, "dead-share floor remains, not 0");
    assert_eq!(
        tok(&env.svm, env.vault_token), (DEPOSIT - MINTED) as u64,
        "vault drained down to the dead-share floor's stranded principal, not fully to 0"
    );
}

#[test]
fn execute_redemption_backing_state_matches_withdraw() {
    // DIFFERENTIAL drift safety-net: ExecuteRedemption's BackingDomainLedger
    // counters + market vault total match an equivalent WithdrawBackingBucket
    // (atoms) call (admin authority). Identity fields (authority/market) differ
    // across the two markets and are excluded.
    //
    // BUG-2 / N7: Path B's depositor is the vault's TRUE genesis depositor, so
    // it can only ever redeem MINTED (999_000), not the full DEPOSIT it put
    // in — the LP_VAULT_MINIMUM_LIQUIDITY dead-share floor stays behind. Both
    // paths top up the bucket with the FULL DEPOSIT (so `total_deposited_atoms`
    // still matches) but withdraw only MINTED, so the two paths' resulting
    // ledger/vault state matches again.

    // Path A: deposit then WithdrawBackingBucket(MINTED) by admin (admin is the
    // backing authority on this market's appended asset).
    let mut env_a = setup_vault_admin_authority();
    // Top up backing via admin so there is principal to withdraw, then withdraw it.
    let admin_a = env_a.admin.insecure_clone();
    let src_a = Pubkey::new_unique();
    set_token(&mut env_a.svm, src_a, env_a.collateral_mint, admin_a.pubkey(), 10_000_000);
    let (ledger_a, _) =
        state::derive_lp_backing_ledger(&env_a.program_id, &env_a.market, DOMAIN);
    env_a.svm.set_account(ledger_a, Account { lamports: 1_000_000_000, data: vec![0u8; state::backing_domain_ledger_account_len()], owner: env_a.program_id, executable: false, rent_epoch: 0 }).unwrap();
    let dest_a = Pubkey::new_unique();
    set_token(&mut env_a.svm, dest_a, env_a.collateral_mint, admin_a.pubkey(), 0);
    let pid_a = env_a.program_id;
    let payer_a = env_a.payer.insecure_clone();
    send(&mut env_a.svm, pid_a, &payer_a, vec![(ProgInstruction::TopUpBackingBucket { domain: DOMAIN, amount: DEPOSIT, expiry_slot: percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT },
        vec![AccountMeta::new(admin_a.pubkey(), true), AccountMeta::new(env_a.market, false), AccountMeta::new(src_a, false), AccountMeta::new(env_a.vault_token, false), AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new(ledger_a, false)])], &[&admin_a]).expect("top up");
    env_a.svm.expire_blockhash();
    send(&mut env_a.svm, pid_a, &payer_a, vec![(ProgInstruction::WithdrawBackingBucket { domain: DOMAIN, amount: MINTED },
        vec![AccountMeta::new(admin_a.pubkey(), true), AccountMeta::new(env_a.market, false), AccountMeta::new(dest_a, false), AccountMeta::new(env_a.vault_token, false), AccountMeta::new_readonly(env_a.vault_authority, false), AccountMeta::new_readonly(spl_token::ID, false), AccountMeta::new(ledger_a, false)])], &[&admin_a]).expect("withdraw");
    let led_a = state::read_backing_domain_ledger(&env_a.svm.get_account(&ledger_a).unwrap().data).unwrap();
    let (_, group_a) = state::read_market(&env_a.svm.get_account(&env_a.market).unwrap().data).unwrap();

    // Path B: deposit then request+execute (registry authority).
    let mut env_b = setup_vault(0);
    let d = new_depositor(&mut env_b, DEPOSIT);
    request(&mut env_b, &d, MINTED).expect("request");
    env_b.svm.expire_blockhash();
    execute(&mut env_b, &d).expect("execute");
    let led_b = state::read_backing_domain_ledger(&env_b.svm.get_account(&env_b.ledger).unwrap().data).unwrap();
    let (_, group_b) = state::read_market(&env_b.svm.get_account(&env_b.market).unwrap().data).unwrap();

    assert_eq!(led_a.total_principal_atoms, led_b.total_principal_atoms, "principal drift");
    assert_eq!(led_a.total_principal_withdrawn_atoms, led_b.total_principal_withdrawn_atoms, "withdrawn drift");
    assert_eq!(led_a.total_deposited_atoms, led_b.total_deposited_atoms, "deposited drift");
    assert_eq!(led_a.total_earnings_atoms, led_b.total_earnings_atoms);
    assert_eq!(led_a.cumulative_loss_atoms, led_b.cumulative_loss_atoms);
    assert_eq!(led_a.cumulative_recovery_atoms, led_b.cumulative_recovery_atoms);
    assert_eq!(group_a.vault, group_b.vault, "vault total drift between Withdraw and ExecuteRedemption");
}

/// Same as setup_vault(0) but the appended asset's backing authority = admin
/// (so admin can drive TopUpBackingBucket / WithdrawBackingBucket directly for
/// the differential reference path).
fn setup_vault_admin_authority() -> Env {
    let mut svm = LiteSVM::new();
    let program_id = percolator_prog::id();
    svm.add_program(program_id, &std::fs::read(program_path()).expect("wrapper BPF"));
    svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).expect("token BPF"));
    let payer = Keypair::new();
    let admin = Keypair::new();
    let market = Pubkey::new_unique();
    let collateral_mint = Pubkey::new_unique();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
    svm.set_account(collateral_mint, Account { lamports: 1_000_000_000, data: make_mint_data(), owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    svm.set_account(market, Account { lamports: 1_000_000_000, data: vec![0u8; state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize).unwrap()], owner: program_id, executable: false, rent_epoch: 0 }).unwrap();
    send(&mut svm, program_id, &payer, vec![(init_market_ix(), vec![
        AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false), AccountMeta::new_readonly(collateral_mint, false),
    ])], &[&admin]).expect("init market");
    let (registry, _) = derive_lp_vault_registry(&program_id, &market);
    let (lp_mint, _) = derive_lp_vault_mint(&program_id, &market);
    let (ledger, _) = derive_lp_backing_ledger(&program_id, &market, DOMAIN);
    let (escrow, _) = derive_lp_escrow(&program_id, &market);
    let (vault_authority, _) = Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
    let vault_token = canonical_vault_ata(&vault_authority, &collateral_mint);
    set_token(&mut svm, vault_token, collateral_mint, vault_authority, 0);
    send(&mut svm, program_id, &payer, vec![(ProgInstruction::UpdateAssetLifecycle {
        action: ASSET_ACTION_ACTIVATE, asset_index: APPEND_ASSET_INDEX, now_slot: 1, initial_price: 100,
        insurance_authority: admin.pubkey().to_bytes(), insurance_operator: admin.pubkey().to_bytes(),
        backing_bucket_authority: admin.pubkey().to_bytes(), oracle_authority: admin.pubkey().to_bytes(),
    }, vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)])], &[&admin]).expect("append asset 1");
    Env { svm, program_id, payer, admin, market, collateral_mint, vault_token, registry, lp_mint, ledger, escrow, vault_authority }
}

// ── Phase 2.E deferred LP test #1: OI-reservation reject (I6) ───────────────
// LP-VAULT-REDEEM-BUG (found + fixed 2026-07-17): `outstanding_post` in the
// OI-reservation guard (v16_program.rs handle_execute_redemption) was
// `(bucket.fresh_unliened_backing_num - backing_num) + bucket.valid_liened_backing_num`
// -- i.e. it counted ALL remaining idle/uncommitted LP capital as
// "outstanding," not just backing genuinely liened against real open
// interest. Because no wrapper instruction in this build ever writes
// `bucket.valid_liened_backing_num` on a real trade (grep-confirmed: the only
// non-test write site is a raw-struct-poke inside a `#[test]` fn), that field
// is always 0 on every deployed vault, so the old formula reduced to an
// unconditional NAV-surplus-over-idle-capital requirement that rejected
// EVERY ordinary, fully-solvent, zero-OI redemption above threshold_bps=0 --
// this exact test, prior to the fix, asserted that broken behavior as
// "expected." The fix narrows `outstanding_post` to `bucket.valid_liened_backing_num`
// only (real OI at risk); see the fix-site comment for the full writeup.
//
// This test now exercises the CORRECTED semantics: a genuine OI lien
// (hand-crafted via `set_bucket_oi_lien_for_test`, the only way to get real
// OI into `valid_liened_backing_num` in this build -- same technique as
// `set_source_credit_lien_for_test` above) that the post-redeem NAV cannot
// cover at the configured threshold is STILL rejected at
// LpVaultOiReservationViolated (Custom 37) -- proving the fix narrows the
// guard to real risk without deleting solvency protection.
//
// The accept path for a CLEAN (zero-OI) bucket at a nonzero threshold --
// i.e. the fix itself, non-vacuously proven to fail pre-fix and pass
// post-fix -- is `execute_redemption_oi_reservation_clean_bucket_partial_succeeds`
// / `execute_redemption_oi_reservation_clean_bucket_full_succeeds` below. The
// threshold=0 (guard fully disabled) accept path is
// `request_then_execute_pays_pro_rata`.

/// Hand-crafts a genuine OI lien on `domain`'s backing bucket: moves
/// `lien_atoms` worth of backing from `fresh_unliened_backing_num` into
/// `valid_liened_backing_num` -- exactly the effect a real matcher/trade-CPI
/// lien against LP-vault backing would have. Total bucket backing
/// (fresh_unliened + valid_liened) is unchanged, so header/vault aggregates
/// stay in lockstep and `validate_shape()` still passes. Same raw-account-poke
/// pattern as `set_source_credit_lien_for_test` / `seed_earnings` above, used
/// because no wrapper instruction in this build opens a real position against
/// LP-vault backing (CONSTRUCTIBILITY NOTE, tests/v16_five_program_crosscut.rs).
fn set_bucket_oi_lien_for_test(env: &mut Env, domain: u16, lien_atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    let lien_num = lien_atoms * percolator::BOUND_SCALE;
    let bucket = &mut group.source_backing_buckets[domain as usize];
    bucket.fresh_unliened_backing_num = bucket
        .fresh_unliened_backing_num
        .checked_sub(lien_num)
        .expect("enough fresh backing to lien");
    bucket.valid_liened_backing_num = bucket
        .valid_liened_backing_num
        .checked_add(lien_num)
        .expect("no overflow");
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

/// NEGATIVE test (solvency preserved): a redemption that would leave a
/// GENUINE OI lien uncovered by post-redeem NAV at the configured threshold
/// is rejected at LpVaultOiReservationViolated (Custom 37), even after the
/// LP-VAULT-REDEEM-BUG fix.
///
/// Two depositors share DOMAIN's backing pool (no earnings -> 1:1):
///   D1 (genesis): deposits DEPOSIT (1_000_000), mints MINTED (999_000).
///   D2: deposits 2*DEPOSIT (2_000_000), mints 2_000_000.
/// Total bucket backing = 3_000_000 atoms.
///
/// Hand-craft a genuine OI lien of 1_500_000 atoms (bucket.valid_liened_backing_num),
/// leaving bucket.fresh_unliened_backing_num = 1_500_000. Threshold = 5_000 (50%).
///
/// D1 redeems its full MINTED (999_000):
///   - Availability gate: fresh_unliened_backing_num (1_500_000) >= backing_num
///     (999_000) -> passes (not the availability gate that fires).
///   - Post-redeem NAV = 3_000_000 - 999_000 = 2_001_000 (no earnings).
///   - covered = nav_post * 50% = 1_000_500.
///   - outstanding_post = valid_liened_backing_num = 1_500_000.
///   - covered (1_000_500) < outstanding_post (1_500_000) -> REJECT, Custom(37).
/// This holds under BOTH the old and new formula (old: outstanding_post =
/// (1_500_000 - 999_000) + 1_500_000 = 2_001_000, even larger) -- proving the
/// fix did not weaken protection against real OI, it only removed the
/// idle-capital term that had nothing to do with real risk.
#[test]
fn execute_redemption_oi_reservation_violation_rejects() {
    let mut env = setup_vault_oi(0, 5_000); // 50% OI reservation, immediate cooldown
    let d1 = new_depositor(&mut env, DEPOSIT);
    let _d2 = new_depositor(&mut env, 2 * DEPOSIT);

    let lien_atoms: u128 = 1_500_000;
    set_bucket_oi_lien_for_test(&mut env, DOMAIN, lien_atoms);

    request(&mut env, &d1, MINTED).expect("request d1 full MINTED");
    env.svm.expire_blockhash();
    let res = execute(&mut env, &d1);
    let msg = format!("{res:?}");
    assert!(msg.contains("Custom(37)"), "expected LpVaultOiReservationViolated Custom(37), got: {msg}");
    // Solvency preserved: no payout, no state mutation on the rejected redemption.
    assert_eq!(tok(&env.svm, d1.dest), 0, "no payout on the rejected under-backed redemption");
}

/// POSITIVE / NON-VACUOUS fix-proof test (S3): a PARTIAL redemption of a
/// CLEAN (zero real-OI) bucket at a conventional nonzero threshold (8_000 bps
/// = 80%, mirroring the observed devnet run-full.ts flow) MUST SUCCEED with
/// an exact pro-rata payout.
///
/// This is the accept-path test that was entirely absent before this fix --
/// every pre-existing nonzero-threshold test asserted only rejection. Before
/// the fix, outstanding_post = (fresh_unliened_backing_num - backing_num) + 0
/// = (1_000_000 - 499_500) = 500_500; nav_post = 500_500; covered = 500_500 *
/// 80% = 400_400 < 500_500 -> REJECT Custom(37) (verified live against the
/// exact hash-verified pre-fix deployed bytecode, sha256
/// 8a833a53c3a18fc8d2c9dee372ce37c62ef06a3e84a4ec8819500061d656b23f, this
/// session). After the fix, outstanding_post = valid_liened_backing_num = 0
/// (no real OI was ever crafted here) -> covered(any) >= 0 always -> ACCEPT.
/// Proves the fix non-vacuously: this test fails against the pre-fix
/// source/bytecode and passes against the post-fix source/bytecode.
#[test]
fn execute_redemption_oi_reservation_clean_bucket_partial_succeeds() {
    let mut env = setup_vault_oi(0, 8_000); // 80% OI reservation, immediate cooldown
    let d = new_depositor(&mut env, DEPOSIT);
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64);

    // Partial redemption: half of MINTED (999_000 / 2 = 499_500, exact).
    let half = MINTED / 2;
    request(&mut env, &d, half).expect("request partial");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect(
        "partial redemption of a CLEAN (zero-OI) bucket must succeed under any \
         oi_reservation_threshold_bps -- there is no real OI to protect",
    );
    assert_eq!(tok(&env.svm, d.dest), half as u64, "partial redeemer paid exactly half of MINTED, no dust");
    let r = reg(&env);
    assert_eq!(r.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY + (MINTED - half), "remaining outstanding shares exact");
}

/// POSITIVE / NON-VACUOUS fix-proof test (S4): a FULL redemption of a CLEAN
/// (zero real-OI) bucket at a conventional nonzero threshold (8_000 bps =
/// 80%) MUST SUCCEED with an exact pro-rata payout, draining down to the
/// dead-share floor exactly like the threshold=0 accept path
/// (`request_then_execute_pays_pro_rata`).
///
/// Separate `Env`/depositor from the partial test above (not a second
/// request on the same redemption PDA) -- LiteSVM 0.1.0 does not reap a
/// zero-lamport-closed PDA between separate `send_transaction` calls within
/// one test process the way a live validator's end-of-transaction account
/// sweep would, so re-deriving the same (registry, redeemer) redemption PDA
/// for a second `RequestRedeemLpShares` in the same env spuriously rejects
/// with AlreadyInitialized (Custom 2) -- an unrelated LiteSVM harness
/// limitation, not a wrapper bug (single request-then-execute cycles are
/// unaffected, as proven throughout this file).
///
/// Before the fix: outstanding_post = (1_000_000 - 999_000) + 0 = 1_000;
/// nav_post = 1_000; covered = 1_000 * 80% = 800 < 1_000 -> REJECT Custom(37)
/// (verified live against the pre-fix bytecode this session -- even the
/// dead-share floor's 1_000-atom margin trips the bug). After the fix:
/// outstanding_post = 0 -> ACCEPT.
#[test]
fn execute_redemption_oi_reservation_clean_bucket_full_succeeds() {
    let mut env = setup_vault_oi(0, 8_000); // 80% OI reservation, immediate cooldown
    let d = new_depositor(&mut env, DEPOSIT);
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64);

    request(&mut env, &d, MINTED).expect("request full MINTED");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect(
        "full redemption of a CLEAN (zero-OI) bucket must succeed under any \
         oi_reservation_threshold_bps -- there is no real OI to protect",
    );
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "redeemer paid pro-rata in full");
    assert_eq!(tok(&env.svm, env.escrow), 0, "escrow burned to zero");
    let r = reg(&env);
    assert_eq!(r.total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY, "dead-share floor remains, not 0");
}

// W3 (canonical-ATA): mirror of v16_program::processor::canonical_vault_address — the SPL
// Associated Token Account of the vault_authority PDA for this mint. Kept byte-in-lock-step with
// the program so vault fixtures satisfy the F-VAULT-FRAG pin (a green test == the derivation matches).
fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().unwrap();
    Pubkey::find_program_address(
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

// ── W3 (F-VAULT-FRAG) canonical-ATA pin on the LP-vault collateral paths ──
// DepositToLpVault and ExecuteRedemption both verify the collateral vault is the canonical ATA of
// the vault_authority for the mint. A vault_authority-owned account at any other address is rejected
// with InvalidVaultAccount (Custom 12), so a fragmenting second vault cannot strand LP redemptions.
// The dual-gate ACCEPT path (a real deposit -> request -> execute that pays pro-rata and DRAINS the
// canonical env.vault_token) is proven by request_then_execute_pays_pro_rata above.

fn noncanonical_vault(env: &mut Env, amount: u64) -> Pubkey {
    let bad = Pubkey::new_unique();
    set_token(&mut env.svm, bad, env.collateral_mint, env.vault_authority, amount);
    bad
}

#[test]
fn deposit_to_lp_vault_rejects_noncanonical_vault() {
    let mut env = setup_vault(0);
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(&mut env.svm, source, env.collateral_mint, kp.pubkey(), 10_000_000);
    let lp_ata = Pubkey::new_unique();
    set_token(&mut env.svm, lp_ata, env.lp_mint, kp.pubkey(), 0);
    let bad_vault = noncanonical_vault(&mut env, 0);

    let mut accts = deposit_accounts(&env, lp_ata, source, kp.pubkey());
    accts[6] = AccountMeta::new(bad_vault, false); // swap the canonical vault for a fragmenting one
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let res = send(&mut env.svm, pid, &payer, vec![(ProgInstruction::DepositToLpVault { amount: DEPOSIT, domain: DOMAIN }, accts)], &[&kp]);
    let msg = res.expect_err("DepositToLpVault to a non-canonical vault must reject");
    assert!(msg.contains("Custom(12)"), "expected InvalidVaultAccount Custom(12), got: {msg}");

    // ACCEPT: the canonical vault deposit goes through (this is the vault's TRUE
    // genesis deposit — the rejected attempt above never committed — so
    // BUG-2 / N7's dead-share carve-out applies: MINTED, not DEPOSIT).
    let d = new_depositor(&mut env, DEPOSIT);
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64, "canonical-vault deposit accepted");
}

#[test]
fn execute_redemption_rejects_noncanonical_vault() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();

    let mut accts = execute_accounts(&env, &d);
    accts[6] = AccountMeta::new(noncanonical_vault(&mut env, DEPOSIT as u64), false); // fragmenting vault
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let res = send(&mut env.svm, pid, &payer, vec![(ProgInstruction::ExecuteRedemption { domain: DOMAIN }, accts)], &[]);
    let msg = res.expect_err("ExecuteRedemption from a non-canonical vault must reject");
    assert!(msg.contains("Custom(12)"), "expected InvalidVaultAccount Custom(12), got: {msg}");

    // The rejected execute reverted; the redemption is still pending and the CANONICAL vault still
    // executes (dual-gate intact) — draining env.vault_token down to the dead-share floor's
    // stranded principal, as proven end-to-end above.
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("canonical-vault execute accepted");
    assert_eq!(
        tok(&env.svm, env.vault_token), (DEPOSIT - MINTED) as u64,
        "canonical vault drained down to the dead-share floor's stranded principal"
    );
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "redeemer paid pro-rata through the canonical vault");
}

// ── Conservation tests for the principal/earnings split (v17 bug fix) ────────
//
// These tests prove the exact accounting invariant for ExecuteRedemption when
// earnings are present.  fee_share_bps = 5_000 (50%).
//
// Setup:
//   - LP A deposits 1_000_000 atoms → 1_000_000 shares (1:1, fresh vault).
//   - LP B deposits 2_000_000 atoms → 2_000_000 shares (1:1, no earnings yet).
//   - Seed 400_000 gross earnings atoms into the domain bucket.
//   - After sync:  total_earnings_atoms = 400_000
//                  lp_earnings           = 200_000   (50%)
//                  insurance_stub        = 200_000   (stays in bucket, not LP NAV)
//                  available_principal   = 3_000_000 (no impairment)
//                  nav                   = 3_200_000
//   - total_shares = 3_000_000
//
// LP A holds 1_000_000/3_000_000 of the vault:
//   atoms_A = floor(1_000_000 * 3_200_000 / 3_000_000) = floor(3_200_000_000 / 3_000_000)
//           = 1_066_666
//   principal_A = floor(1_000_000 * 3_000_000 / 3_000_000) = 1_000_000
//   earnings_A  = 1_066_666 - 1_000_000 = 66_666
//
// After LP A redeems (gross_consumed model):
//   gross_consumed_A = ceil(66_666 * 10_000 / 5_000) = 133_332
//   net_earnings_remaining = 400_000 - 133_332 = 266_668
//   lp_earnings_remaining  = floor(266_668 * 5_000 / 10_000) = 133_334
//   available_principal    = 2_000_000
//   nav_remaining          = 2_133_334
//   total_shares_remaining = 2_000_000
//
// LP B holds all remaining shares (2_000_000) — GROSS_CONSUMED model:
//   atoms_B = floor(2_000_000 * 2_133_334 / 2_000_000) = 2_133_334
//   principal_B = 2_000_000, earnings_B = 133_334
//   gross_consumed_B = ceil(133_334 * 10_000 / 5_000) = 266_668
//
// Total paid out = 1_066_666 + 2_133_334 = 3_200_000
// Vault seeded  = 3_000_000 (deposits) + 400_000 (earnings) = 3_400_000
// Insurance stub = 3_400_000 - 3_200_000 = 200_000 = 50% of 400_000 EXACTLY
//
// Fee_share split PRESERVED: LP total = 200_000 (50%), insurance = 200_000 (50%).
// (89382f1 model gave only 166_667 stub — 33_333 leaked to LPs beyond fee_share.)

/// Seeds bucket earnings by directly writing the market account — same pattern
/// as v16_fork_lp_vault_admin.rs:seed_bucket_earnings. Both `group.vault` (the
/// logical counter) and the SPL vault_token account balance are bumped so that
/// the redemption token-transfer can actually succeed.
fn seed_earnings(env: &mut Env, earnings: u128) {
    // 1. Update the market group account: bucket earnings + logical vault.
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.source_backing_buckets[DOMAIN as usize].utilization_fee_earnings += earnings;
    group.vault += earnings;
    // backing_provider_earnings_total must also increase (validate_shape audit scan).
    group.backing_provider_earnings_total += earnings;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();

    // 2. Bump the SPL vault_token account balance so the transfer in ExecuteRedemption
    //    can succeed. The vault token account is the real SPL token account; seeding
    //    earnings corresponds to fee revenue accruing in the backing vault.
    let earnings_u64 = u64::try_from(earnings).expect("earnings fits u64");
    let mut tok_acct = env.svm.get_account(&env.vault_token).expect("vault_token");
    let mut tok_data = TokenAccount::unpack(&tok_acct.data).expect("unpack vault token");
    tok_data.amount = tok_data.amount.checked_add(earnings_u64).expect("no overflow");
    let mut new_data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(tok_data, &mut new_data).expect("pack");
    tok_acct.data = new_data;
    env.svm.set_account(env.vault_token, tok_acct).unwrap();
}

fn ledger(env: &Env) -> state::BackingDomainLedgerAccountV16 {
    state::read_backing_domain_ledger(&env.svm.get_account(&env.ledger).unwrap().data).unwrap()
}

fn reg(env: &Env) -> state::LpVaultRegistryV16 {
    state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data).unwrap()
}

fn vault_balance(env: &Env) -> u64 {
    tok(&env.svm, env.vault_token)
}

// ── Task 7: LpVaultCrankFees (tag 78) must produce LP-VISIBLE VALUE ──────────
//
// The first repoint (d6b4433c) drained `cfg.lp_fee_accrued_atoms` into
// `registry.fee_distribution_total_atoms` — a counter that is written and never
// read — so it passed its tests while paying nobody. These tests assert on the
// ACTUAL redemption payout, not on a counter.

/// Earmark LP fee atoms on the wrapper counter WITHOUT funding the engine-side
/// insurance surplus behind them. Models the shared-pool race: the protocol
/// (tag 83) or stake leg already drained the surplus, so this claim must clamp.
fn credit_lp_fee_counter(env: &mut Env, atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (mut cfg, group) = state::read_market(&acct.data).expect("read market");
    cfg.lp_fee_accrued_atoms += atoms;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

/// Put `atoms` of real, unreserved surplus into `header.insurance` (and the
/// vault + the real SPL vault_token behind it, so a later redemption transfer
/// can settle). In production the engine does this at constant vault via
/// `c_tot -= charged; insurance += charged` (engine v16.rs:13798); this env has
/// no traders and so no `c_tot` to drain, so `vault` is credited instead —
/// the same accepted direct-write boundary `seed_earnings` uses. What matters
/// for the crank is identical either way: the atoms sit in `header.insurance`,
/// inside `header.vault`, unreserved and unbudgeted.
fn fund_insurance(env: &mut Env, atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.insurance += atoms;
    group.vault += atoms;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();

    let atoms_u64 = u64::try_from(atoms).expect("atoms fits u64");
    let mut tok_acct = env.svm.get_account(&env.vault_token).expect("vault_token");
    let mut tok_data = TokenAccount::unpack(&tok_acct.data).expect("unpack vault token");
    tok_data.amount = tok_data.amount.checked_add(atoms_u64).expect("no overflow");
    let mut new_data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(tok_data, &mut new_data).expect("pack");
    tok_acct.data = new_data;
    env.svm.set_account(env.vault_token, tok_acct).unwrap();
}

/// A faithful LP fee accrual: the counter AND the insurance surplus behind it.
fn seed_lp_fee_accrued(env: &mut Env, atoms: u128) {
    credit_lp_fee_counter(env, atoms);
    fund_insurance(env, atoms);
}

fn crank_fees(env: &mut Env) -> Result<(), String> {
    crank_fees_into(env, DOMAIN)
}

/// Crank accrued LP fees into a chosen pot of the vault's asset.
fn crank_fees_into(env: &mut Env, domain: u16) -> Result<(), String> {
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::LpVaultCrankFees { domain },
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
        )],
        &[],
    )
}

fn lp_fee_counters(env: &Env) -> (u128, u128) {
    let (cfg, _) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    (cfg.lp_fee_accrued_atoms, cfg.lp_fee_withdrawn_atoms)
}

/// `(header.vault, header.insurance)`.
fn vault_and_insurance(env: &Env) -> (u128, u128) {
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    (group.vault, group.insurance)
}

/// HEADLINE (Task 7): a tag-78 crank must make an LP's REDEEMABLE CLAIM strictly
/// larger — not merely move a counter.
///
/// Control and treatment are byte-identical vaults with byte-identical accrued
/// LP fees; the only difference is whether the crank ran. The claim is measured
/// through the real `RequestRedeemLpShares` → `ExecuteRedemption` path and read
/// off the redeemer's SPL destination account, so nothing about this assertion
/// can be satisfied by bookkeeping that pays nobody.
#[test]
fn crank_fees_raises_lp_redeemable_claim() {
    const LP_FEES: u128 = 250_000;

    // ── Control: accrued LP fees present, crank NEVER run. ──
    let mut ctl = setup_vault(0);
    let dc = new_depositor(&mut ctl, DEPOSIT);
    seed_lp_fee_accrued(&mut ctl, LP_FEES);
    request(&mut ctl, &dc, MINTED).expect("control request");
    ctl.svm.expire_blockhash();
    execute(&mut ctl, &dc).expect("control execute");
    let payout_control = tok(&ctl.svm, dc.dest);
    assert_eq!(
        payout_control, MINTED as u64,
        "control: uncranked LP fees are invisible to redemption — payout is bare principal"
    );

    // ── Treatment: identical, but crank tag 78 before redeeming. ──
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    seed_lp_fee_accrued(&mut env, LP_FEES);

    let principal_before = ledger(&env).total_principal_atoms;
    let (vault_before, insurance_before) = vault_and_insurance(&env);
    let (accrued_before, withdrawn_before) = lp_fee_counters(&env);
    assert_eq!(withdrawn_before, 0, "nothing withdrawn before the first crank");

    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("crank with backed, accrued LP fees must succeed");

    let principal_after = ledger(&env).total_principal_atoms;
    let (vault_after, insurance_after) = vault_and_insurance(&env);
    let (accrued_after, withdrawn_after) = lp_fee_counters(&env);

    // ── CONSERVATION. `withdraw_insurance_surplus_not_atomic` does I−a AND V−a;
    //    the handler restores V so no tokens move and the senior sum
    //    C + (I−a) + E + (FB+a) is byte-identical to C + I + E + FB. ──
    assert_eq!(
        vault_after, vault_before,
        "header.vault MUST be unchanged across the crank — the crank moves no tokens"
    );
    assert_eq!(
        vault_balance(&env),
        vault_after as u64,
        "the logical vault still matches the real SPL vault_token balance"
    );
    assert_eq!(
        insurance_before - insurance_after,
        LP_FEES,
        "header.insurance must fall by exactly the cranked amount (reclassified, not spent)"
    );
    // validate_shape(): the handler calls it after the reclassification and
    // propagates failure, so a SUCCESSFUL crank is itself a passing
    // validate_shape. The successful ExecuteRedemption below re-validates the
    // post-crank state through an entirely separate code path.

    // ── The counters, including the invariant. ──
    assert_eq!(principal_after - principal_before, LP_FEES,
        "ledger.total_principal_atoms must rise by exactly the cranked amount");
    assert_eq!(accrued_after, accrued_before, "accrued must not move on a crank");
    assert_eq!(withdrawn_after - withdrawn_before, LP_FEES,
        "withdrawn advances by exactly the amount applied");
    assert!(withdrawn_after <= accrued_after, "invariant: withdrawn <= accrued");

    // ── LP-VISIBLE VALUE: the SAME shares now redeem for strictly more. ──
    request(&mut env, &d, MINTED).expect("treatment request");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("treatment execute");
    let payout_treatment = tok(&env.svm, d.dest);

    assert!(
        payout_treatment > payout_control,
        "the crank must make the SAME shares redeem for strictly MORE: \
         control={payout_control} treatment={payout_treatment}"
    );
    // Exact: NAV rose from DEPOSIT to DEPOSIT+LP_FEES against an unchanged share
    // count, so the redeemer's pro-rata slice of the fees is
    // floor(MINTED * LP_FEES / DEPOSIT). The remainder is the
    // LP_VAULT_MINIMUM_LIQUIDITY dead shares' slice, stranded by design (N7).
    let expected_treatment = MINTED * (DEPOSIT + LP_FEES) / DEPOSIT;
    assert_eq!(
        payout_treatment, expected_treatment as u64,
        "redeemer receives principal + its pro-rata slice of the cranked LP fees"
    );
    assert_eq!(
        payout_treatment - payout_control,
        (MINTED * LP_FEES / DEPOSIT) as u64,
        "the ENTIRE payout delta is the redeemer's pro-rata slice of the LP fees"
    );
}

/// MANDATORY CLAMP (Task 7). The protocol / LP / stake legs share ONE surplus
/// pool with no cross-leg accounting. An unclamped LP claim would fail out of
/// the engine with EngineLockActive whenever another leg got there first. The
/// clamp must instead fill partially AND leave the remainder claimable — the
/// opposite mistake (marking the full claim withdrawn) silently burns LP yield.
#[test]
fn crank_fees_clamps_to_engine_surplus_and_leaves_remainder_claimable() {
    const BACKED: u128 = 100_000;
    const UNBACKED: u128 = 400_000;

    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    // 100_000 of real, backed accrual...
    seed_lp_fee_accrued(&mut env, BACKED);
    // ...plus 400_000 earmarked on the counter with NO insurance behind it.
    credit_lp_fee_counter(&mut env, UNBACKED);

    let principal_before = ledger(&env).total_principal_atoms;
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("a clamped crank must still apply the available part");

    // Only the backed part moved.
    assert_eq!(
        ledger(&env).total_principal_atoms - principal_before,
        BACKED,
        "only the engine-available surplus is applied"
    );
    let (accrued, withdrawn) = lp_fee_counters(&env);
    assert_eq!(accrued, BACKED + UNBACKED, "accrued is untouched by the clamp");
    assert_eq!(
        withdrawn, BACKED,
        "withdrawn advances by the CLAMPED amount actually applied, NOT the requested claim"
    );
    assert!(withdrawn <= accrued, "invariant: withdrawn <= accrued");

    // A re-crank with the pool still dry rejects — and marks nothing.
    env.svm.expire_blockhash();
    let dry = crank_fees(&mut env);
    let err = dry.expect_err("re-crank against a dry surplus pool must reject");
    assert!(
        err.contains("Custom(38)"),
        "a clamped-to-zero crank returns LpVaultNoFeesToCrank = Custom(38), got: {err}"
    );
    assert_eq!(
        lp_fee_counters(&env).1,
        BACKED,
        "a rejected crank must not advance withdrawn"
    );

    // THE POINT: the remainder is still claimable once the pool refills.
    fund_insurance(&mut env, UNBACKED);
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("the clamped remainder must still be claimable");
    assert_eq!(
        ledger(&env).total_principal_atoms - principal_before,
        BACKED + UNBACKED,
        "the full claim eventually reaches the LP ledger across two cranks"
    );
    assert_eq!(lp_fee_counters(&env), (BACKED + UNBACKED, BACKED + UNBACKED), "fully drained");

    // And it is real, redeemable value — not a counter.
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("execute");
    assert_eq!(
        tok(&env.svm, d.dest),
        (MINTED * (DEPOSIT + BACKED + UNBACKED) / DEPOSIT) as u64,
        "both cranked tranches are redeemable"
    );
}

fn set_c_tot_for_test(env: &mut Env, c_tot: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.c_tot = c_tot;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

/// CONSERVATION TEST: deposit → seed_earnings → partial redeem (LP A) → full
/// redeem (LP B).  Asserts exact principal+earnings split, ledger counters,
/// remaining vault (insurance stub), and no-double-redeem.
/// SUPERSEDES 89382f1 conservation test — uses the corrected gross_consumed model.
///
/// SETUP: fee_share_bps = 5_000 (50% LP, 50% insurance).
///   Two depositors: LP A (1_000_000), LP B (2_000_000).
///   Total principal = 3_000_000. Gross earnings seeded = 400_000.
///   lp_earnings_total = floor(400_000 * 5_000 / 10_000) = 200_000.
///   NAV_total = 3_200_000.
///
/// BUG-2 / N7 UPDATE: LP A is this vault's TRUE genesis depositor (deposits
/// 1_000_000 first), so the wrapper's LP_VAULT_MINIMUM_LIQUIDITY (1_000)
/// dead-share carve-out applies to A's mint — A's LP ATA holds only 999_000
/// (MINTED_A), NOT 1_000_000, even though `registry.total_lp_shares_outstanding`
/// still counts the full 1_000_000 (the 1_000 difference is permanently
/// unminted dead supply — see handle_deposit_to_lp_vault). LP B deposits
/// second (not genesis) and mints the full 2_000_000, 1:1, unaffected.
///
/// total_shares stays 3_000_000 (registry counts A's FULL genesis amount, dead
/// shares included) and NAV is unaffected (ledger-counter-derived, not
/// share-count-derived), so the PRICE per share is byte-identical to the
/// pre-N7 numbers below — only the amount LP A can actually REQUEST/REDEEM
/// changes (999_000, not 1_000_000, since that's all they hold). All
/// downstream numbers were re-derived from that single change and
/// cross-checked with a reference script; see the dead-share dust note at the
/// end for how the "insurance stub == exactly 50%" property is affected.
///
/// LP A REDEEM (999_000 / 3_000_000 shares — MINTED_A, not the full genesis amount):
///   atoms_A = floor(999_000 * 3_200_000 / 3_000_000) = 1_065_600 (exact)
///   principal_A = floor(999_000 * 3_000_000 / 3_000_000) = 999_000 (exact)
///   earnings_A = 66_600
///   gross_consumed_A = ceil(66_600 * 10_000 / 5_000) = 133_200 (exact)
///   → net_earnings_remaining = 400_000 - 133_200 = 266_800
///   → lp_earnings_remaining  = floor(266_800 * 5_000/10_000) = 133_400 (exact)
///
/// LP B REDEEM (2_000_000 / 2_001_000 shares — the 1_000 dead shares now
/// permanently dilute B's claim on the remaining pool, since B no longer
/// holds "all remaining shares"):
///   NAV_B = 2_001_000 + 133_400 = 2_134_400
///   atoms_B = floor(2_000_000 * 2_134_400 / 2_001_000) = 2_133_333 (floor; small
///     dead-share dust — NOT the clean 2_133_334 from the pre-N7 all-shares case)
///   principal_B = floor(2_000_000 * 2_001_000 / 2_001_000) = 2_000_000 (exact)
///   earnings_B = 133_333
///   gross_consumed_B = ceil(133_333 * 10_000 / 5_000) = 266_666 (exact)
///
/// CONSERVATION:
///   total_payout = 1_065_600 + 2_133_333 = 3_198_933
///   remainder (insurance stub + dead-share dust) = 3_400_000 - 3_198_933 = 201_067
///   (vs. 200_000 pre-N7 — the extra 1_067 is the LP_VAULT_MINIMUM_LIQUIDITY
///   dead-share floor's principal+earnings share, permanently stranded in the
///   vault rather than paid to anyone — the expected N7 cost, not a bug)
#[test]
fn conservation_with_earnings_partial_then_full_redeem() {
    let mut env = setup_vault(0); // fee_share_bps = 5_000, immediate cooldown

    // ── Setup: two depositors, then seed earnings. ──
    let d_a = new_depositor(&mut env, 1_000_000);
    let d_b = new_depositor(&mut env, 2_000_000);
    const MINTED_A: u128 = 1_000_000 - 1_000; // LP_VAULT_MINIMUM_LIQUIDITY carved out of A's genesis mint
    assert_eq!(tok(&env.svm, d_a.lp_ata), MINTED_A as u64, "A's genesis mint minus dead-share floor");
    assert_eq!(tok(&env.svm, d_b.lp_ata), 2_000_000, "B's non-genesis mint is 1:1, unaffected");
    assert_eq!(vault_balance(&env), 3_000_000, "vault after deposits");
    assert_eq!(reg(&env).total_lp_shares_outstanding, 3_000_000, "shares after deposits (dead shares included)");

    // Seed 400_000 gross earnings into domain bucket.
    seed_earnings(&mut env, 400_000);
    assert_eq!(vault_balance(&env), 3_400_000, "vault after earnings seed");

    // ── LP A redeems all 999_000 shares they actually hold. ──
    request(&mut env, &d_a, MINTED_A).expect("A request");
    env.svm.expire_blockhash();
    execute(&mut env, &d_a).expect("A execute");

    let payout_a = tok(&env.svm, d_a.dest) as u128;
    // atoms_A = floor(999_000 * 3_200_000 / 3_000_000) = 1_065_600
    assert_eq!(payout_a, 1_065_600, "LP A payout = principal + earnings slice");

    // Ledger after A (gross_consumed model):
    //   principal decremented by principal_A = 999_000
    //   total_earnings_withdrawn_atoms += gross_consumed_A = 133_200
    let led_a = ledger(&env);
    assert_eq!(led_a.total_principal_atoms, 2_001_000, "principal remaining after A");
    assert_eq!(led_a.total_principal_withdrawn_atoms, 999_000, "principal withdrawn after A");
    assert_eq!(
        led_a.total_earnings_withdrawn_atoms, 133_200,
        "earnings_withdrawn = gross_consumed_A (133_200), not LP slice (66_600)"
    );
    assert_eq!(led_a.total_earnings_atoms, 400_000, "total_earnings_atoms unchanged by redemption");

    // Remaining shares: 2_001_000 — LP B's 2_000_000 PLUS the 1_000 dead shares.
    assert_eq!(reg(&env).total_lp_shares_outstanding, 2_001_000, "shares after A redeems");

    // Vault after A: 3_400_000 - 1_065_600 = 2_334_400
    assert_eq!(vault_balance(&env), 2_334_400, "vault balance after A redeems");

    // ── LP B redeems all 2_000_000 shares they hold (not "all remaining" —
    // 1_000 dead shares stay behind, permanently unredeemable). ──
    request(&mut env, &d_b, 2_000_000).expect("B request");
    env.svm.expire_blockhash();
    execute(&mut env, &d_b).expect("B execute");

    let payout_b = tok(&env.svm, d_b.dest) as u128;
    // net_earnings_remaining = 400_000 - 133_200 = 266_800
    // lp_earnings_B = floor(266_800 * 5_000 / 10_000) = 133_400
    // NAV_B = 2_001_000 + 133_400 = 2_134_400
    // atoms_B = floor(2_000_000 * 2_134_400 / 2_001_000) = 2_133_333 (dead-share dust)
    assert_eq!(payout_b, 2_133_333, "LP B payout (diluted by the 1_000 dead shares in the denominator)");

    // Ledger after B.
    let led_b = ledger(&env);
    assert_eq!(led_b.total_principal_atoms, 1_000, "dead-share principal remainder, not zero");
    assert_eq!(led_b.total_principal_withdrawn_atoms, 2_999_000, "total principal withdrawn (A + B)");
    // gross_consumed_B = ceil(133_333 * 10_000 / 5_000) = 266_666
    // total_earnings_withdrawn_atoms = 133_200 + 266_666 = 399_866
    assert_eq!(
        led_b.total_earnings_withdrawn_atoms, 399_866,
        "total earnings withdrawn = gross_consumed_A + gross_consumed_B (133_200 + 266_666)"
    );

    // Outstanding shares == the LP_VAULT_MINIMUM_LIQUIDITY dead-share floor, not 0.
    assert_eq!(reg(&env).total_lp_shares_outstanding, 1_000, "dead-share floor remains, not fully zeroed");

    // ── Conservation: vault remainder = insurance stub + dead-share dust. ──
    // Total paid = 1_065_600 + 2_133_333 = 3_198_933
    // Total seeded = 3_400_000
    // Remainder = 201_067 (vs. the pre-N7 clean 200_000 = 50% of 400_000 — the
    // extra 1_067 is the dead-share floor's principal+earnings share,
    // permanently stranded rather than paid to anyone; see doc above).
    let total_payout = payout_a + payout_b;
    assert_eq!(total_payout, 3_198_933, "total payout = both LPs' real principal + earnings slices");
    let remainder = vault_balance(&env) as u128;
    assert_eq!(remainder, 201_067, "vault remainder = insurance stub + dead-share dust");
    assert_eq!(remainder, 3_400_000 - total_payout, "vault remainder = seeded - paid (conservation holds)");

    // ── Double-redeem guard still holds after split. ──
    env.svm.expire_blockhash();
    assert!(execute(&mut env, &d_a).is_err(), "double-redeem A must reject");
    assert!(execute(&mut env, &d_b).is_err(), "double-redeem B must reject");
}

#[test]
fn lp_shares_held_at_resolution_can_redeem_and_teardown_vault() {
    // BUG-2 / N7: `d` is this vault's TRUE genesis depositor, so it can only
    // ever mint/redeem MINTED (999_000), not the full DEPOSIT — the
    // LP_VAULT_MINIMUM_LIQUIDITY dead-share floor (1_000 atoms of BOTH shares
    // AND the underlying collateral they represent) is permanently stranded.
    // handle_close_lp_vault was updated to tolerate exactly the dead-share
    // floor remaining outstanding (`> LP_VAULT_MINIMUM_LIQUIDITY`, not `!= 0`),
    // so CloseLpVault still succeeds. handle_close_slab was NOT changed — it
    // requires the market's `vault == 0` exactly, and the dead-share atoms are
    // permanently un-withdrawable (their `backing_bucket_authority` is the
    // registry PDA, which cannot sign a generic WithdrawBackingBucket outside
    // the wrapper's own instruction-scoped `invoke_signed` calls) — so
    // CloseSlab is now permanently unreachable for any market whose LP vault
    // ever took a real deposit. This is the same trade-off as Uniswap V2 /
    // ERC4626 minimum-liquidity pools, which also never fully drain again.
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED as u64);
    assert_eq!(vault_balance(&env), DEPOSIT as u64);

    resolve_market(&mut env).expect("resolve empty market with LP backing");

    request(&mut env, &d, MINTED).expect("request still succeeds after resolution");
    assert_eq!(tok(&env.svm, d.lp_ata), 0, "shares are escrowed");
    execute(&mut env, &d).expect("terminal resolved redemption should pay out");
    assert_eq!(tok(&env.svm, d.dest), MINTED as u64, "LP receives collateral payout");
    assert_eq!(
        vault_balance(&env), (DEPOSIT - MINTED) as u64,
        "dead-share floor's collateral stays permanently stranded in the vault"
    );

    let admin_dest = Pubkey::new_unique();
    set_token(&mut env.svm, admin_dest, env.collateral_mint, env.admin.pubkey(), 0);
    close_lp_vault(&mut env).expect("registry outstanding at the dead-share floor no longer blocks CloseLpVault");
    let res = close_slab(&mut env, admin_dest);
    assert!(
        res.is_err(),
        "CloseSlab must now stay permanently blocked — the dead-share floor's \
         collateral can never reach vault == 0: {res:?}"
    );
}

#[test]
fn lp_redemption_after_resolution_requires_terminal_flat_state() {
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);

    resolve_market(&mut env).expect("resolve empty market with LP backing");
    request(&mut env, &d, MINTED).expect("request still succeeds after resolution");
    set_c_tot_for_test(&mut env, 1);

    let blocked = execute(&mut env, &d).expect_err("resolved redemption must wait for c_tot = 0");
    assert!(blocked.contains("Custom(21)"), "expected EngineLockActive, got {blocked}");
    assert_eq!(tok(&env.svm, d.dest), 0, "LP payout must not occur before terminal flat state");
}

/// RED CONTROL: verifies that the liveness guard no longer blocks redemption
/// when earnings make atoms > total_principal_atoms.
///
/// Pre-fix: `if atoms > ledger.total_principal_atoms` would reject with
/// EngineCounterUnderflow (Custom 5). Post-fix: guard uses principal_portion
/// (which is <= total_principal_atoms by construction).
///
/// We trigger the old guard by having a single LP whose earnings make their
/// atom payout exceed total_principal_atoms, then assert the redemption SUCCEEDS.
#[test]
fn liveness_not_blocked_when_earnings_exceed_principal() {
    // Single depositor with large earnings relative to deposit.
    // BUG-2 / N7: `d` is this vault's TRUE genesis depositor, so a 100_000
    // deposit mints only MINTED_LOCAL = 99_000 (LP_VAULT_MINIMUM_LIQUIDITY =
    // 1_000 carved out); registry.total_lp_shares_outstanding still counts the
    // full 100_000. All downstream numbers below are re-derived for 99_000
    // real shares against a 100_000-share/100_000-principal denominator.
    //
    // Deposit = 100_000, earnings = 300_000 (50% LP share = 150_000 lp_earnings).
    // NAV = 100_000 + 150_000 = 250_000, total_shares (registry) = 100_000.
    // atoms = floor(99_000 * 250_000 / 100_000) = 247_500 > total_principal_atoms (100_000).
    // Pre-fix: `atoms > total_principal_atoms` → EngineCounterUnderflow.
    // Post-fix: `principal_portion (99_000) > total_principal_atoms (100_000)` → false → proceed.
    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, 100_000);
    const MINTED_LOCAL: u128 = 100_000 - 1_000; // LP_VAULT_MINIMUM_LIQUIDITY carved out
    assert_eq!(tok(&env.svm, d.lp_ata), MINTED_LOCAL as u64, "genesis mint minus dead-share floor");
    assert_eq!(reg(&env).total_lp_shares_outstanding, 100_000, "registry counts the full genesis amount");

    seed_earnings(&mut env, 300_000);
    // NAV = 100_000 (principal) + 150_000 (50% of 300_000) = 250_000
    // atoms = 247_500, principal_portion = 99_000, earnings_portion = 148_500
    // total_principal_atoms = 100_000 — pre-fix guard would reject (247_500 > 100_000)

    request(&mut env, &d, MINTED_LOCAL).expect("request must succeed");
    env.svm.expire_blockhash();
    // POST-FIX: this must succeed. Pre-fix: EngineCounterUnderflow (Custom 5).
    execute(&mut env, &d).expect("execute must succeed (liveness fix — earnings do not block redemption)");

    // LP receives its pro-rata NAV slice: 247_500
    assert_eq!(tok(&env.svm, d.dest), 247_500, "LP paid pro-rata NAV (principal + earnings)");
    // Vault remainder = insurance stub + dead-share dust = 400_000 (100_000 + 300_000) - 247_500 = 152_500
    assert_eq!(vault_balance(&env), 152_500, "insurance stub + dead-share dust stays in vault");
    // Ledger: gross_consumed = ceil(148_500 * 10_000 / 5_000) = 297_000
    let led = ledger(&env);
    assert_eq!(led.total_principal_atoms, 1_000, "dead-share principal remainder, not zero");
    assert_eq!(
        led.total_earnings_withdrawn_atoms, 297_000,
        "earnings_withdrawn = gross_consumed (297_000), not LP slice (148_500)"
    );
    assert_eq!(reg(&env).total_lp_shares_outstanding, 1_000, "dead-share floor remains, not zero");
}

/// RED CONTROL STRUCTURAL CHECK: if the old guard logic `atoms > total_principal`
/// is applied manually, the liveness test above would reject.  This test is a
/// pure-Rust (no BPF) unit assertion confirming the guard logic changed correctly.
/// It does NOT interact with the program; it verifies the fix's guard invariant.
#[test]
fn guard_invariant_principal_portion_le_total_principal_by_construction() {
    // Invariant: principal_portion = floor(shares * available_principal / total_shares)
    // Since available_principal = total_principal_atoms - net_impairment,
    // and net_impairment >= 0, we have available_principal <= total_principal_atoms.
    // Therefore principal_portion <= available_principal <= total_principal_atoms.
    // The guard `principal_portion > total_principal_atoms` can never fire legitimately.
    use percolator::wide_math::wide_mul_div_floor_u128;

    let total_principal_atoms: u128 = 100_000;
    let net_impairment: u128 = 0; // no losses
    let available_principal = total_principal_atoms - net_impairment;
    let shares: u128 = 100_000;
    let total_shares: u128 = 100_000;

    let principal_portion = wide_mul_div_floor_u128(shares, available_principal, total_shares);
    assert!(principal_portion <= total_principal_atoms,
        "principal_portion ({principal_portion}) always <= total_principal_atoms ({total_principal_atoms})");

    // With impairment: available_principal < total_principal_atoms, so even stricter.
    let total_principal_atoms_2: u128 = 100_000;
    let net_impairment_2: u128 = 10_000;
    let available_principal_2 = total_principal_atoms_2 - net_impairment_2;
    let principal_portion_2 = wide_mul_div_floor_u128(shares, available_principal_2, total_shares);
    assert!(principal_portion_2 <= total_principal_atoms_2,
        "impaired case: principal_portion ({principal_portion_2}) <= total_principal_atoms ({total_principal_atoms_2})");
}

// ── LPVAULT-359 regression: insurance stub is tracked + teardown completes ───
/// LPVAULT-359 (HIGH — permanent fund lock-up).
///
/// THE BUG: a full LP-vault redemption pays the LP their fee_share slice of the
/// gross earnings and leaves the insurance (1 − fee_share) slice PHYSICALLY in the
/// vault (the vault decrements only by `atoms` = principal + LP-earnings, not by the
/// full `gross_consumed`). Pre-fix that stub was credited to NO header counter — it
/// sat as an un-owned vault residual. No withdrawal path can touch atoms that aren't
/// tracked in `insurance`/a domain budget, so the stub was undrainable, and
/// `CloseSlab` — gated on `vault==0 && insurance==0 && c_tot==0`
/// (v16_program.rs:8968) — was PERMANENTLY bricked for any vault that had ever
/// earned a fee. The market (and its rent) could never be reclaimed.
///
/// THE FIX (handle_execute_redemption, v16_program.rs ~12321): credit
/// `stub = gross_consumed − earnings_portion` to `header.insurance` AND the
/// redemption domain's per-domain insurance budget. Vault is UNCHANGED (the atoms
/// are already in it), the LP NAV is unchanged (it reads only the backing-domain
/// ledger), and `senior = c_tot + insurance + backing_provider_earnings_total`
/// stays `<= vault` (backing_provider_earnings_total fell by gross_consumed while
/// insurance rose by stub → net senior drop of earnings_portion, the LP payout). The
/// stub now has a withdrawable home (`WithdrawInsuranceAsset`, insurance_operator).
///
/// This test drives the full end-to-end teardown that was impossible pre-fix:
///   deposit → seed earnings → full redeem → drain stub → ResolveMarket → CloseSlab.
///
/// Numbers (fee_share_bps = 5_000): deposit 1_000_000, gross earnings 400_000,
///   lp_earnings = floor(400_000 * 5_000/10_000) = 200_000, NAV = 1_200_000,
///   full redeem pays 1_200_000, gross_consumed = ceil(200_000*10_000/5_000) =
///   400_000, stub = 400_000 − 200_000 = 200_000 → credited to insurance.
#[test]
fn lpvault359_redemption_stub_tracked_and_teardown_completes() {
    // BUG-2 / N7 UPDATE: `d` is this vault's TRUE genesis depositor, so it can
    // only mint/redeem MINTED (999_000, not the full DEPOSIT) —
    // LP_VAULT_MINIMUM_LIQUIDITY (1_000) is permanently carved out of both the
    // minted shares AND (as an unavoidable consequence) the backing collateral
    // it represents, since `registry.total_lp_shares_outstanding` counts the
    // FULL genesis amount so genesis-donation inflation stays unprofitable
    // (see percolator/src/v16.rs lp_vault module design note). All downstream
    // numbers below are re-derived for a 999_000-share redemption against the
    // 1_000_000-share/1_000_000-principal denominator; verified with a
    // reference script alongside conservation_with_earnings_partial_then_full_redeem.
    //
    // IMPORTANT: unlike the LPVAULT-359 earnings stub (which the fix below
    // still correctly tracks into header.insurance and CAN be swept),
    // LP_VAULT_MINIMUM_LIQUIDITY's stranded PRINCIPAL is NOT credited to
    // insurance — crediting it there would double-book it against
    // source_fresh_backing_total_num (which still claims the full genesis
    // amount) and break validate_shape's senior+fresh_backing<=vault
    // invariant. So this 1_000-atom principal remainder has NO withdrawal
    // path at all (same as the dead shares themselves) and CloseSlab —
    // which the original LPVAULT-359 test proved succeeds once the insurance
    // stub is swept — is now PERMANENTLY unreachable for any market whose LP
    // vault ever took a genesis deposit, even after the insurance stub is
    // fully drained. This is the accepted Uniswap-V2/ERC4626
    // minimum-liquidity trade-off (pools/markets with a dead-share floor
    // never fully wind down again), not a regression of the LPVAULT-359 fix
    // itself — the insurance-stub tracking it proved is still exercised and
    // still correct below.
    let mut env = setup_vault(0); // fee_share_bps = 5_000, immediate cooldown, asset-1 operator = admin
    let d = new_depositor(&mut env, DEPOSIT);
    seed_earnings(&mut env, 400_000);
    assert_eq!(vault_balance(&env), 1_400_000, "vault after deposit + earnings seed");

    // ── Full redeem of the real (MINTED) shares → LP paid its pro-rata NAV;
    // insurance stub credited (LPVAULT-359 fix, still exercised here). ──
    request(&mut env, &d, MINTED).expect("request");
    env.svm.expire_blockhash();
    execute(&mut env, &d).expect("execute");
    assert_eq!(tok(&env.svm, d.dest), 1_198_800, "LP paid pro-rata NAV (principal + earnings slice)");
    assert_eq!(reg(&env).total_lp_shares_outstanding, LP_VAULT_MINIMUM_LIQUIDITY, "dead-share floor remains");

    // The 199_800 stub (+ nothing else visible here) physically remains in the vault SPL account...
    assert_eq!(vault_balance(&env), 201_200, "insurance stub + dead-share dust remains in the vault");

    // ...and (THE LPVAULT-359 FIX) the earnings stub IS tracked in header.insurance
    // + the redemption domain's budget, rather than sitting as an un-owned residual.
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert_eq!(group.insurance, 199_800, "FIX: stub credited to header.insurance");
    assert_eq!(group.insurance_domain_budget_remaining_total, 199_800,
        "FIX: stub credited to insurance_domain_budget_remaining_total");
    assert_eq!(group.insurance_domain_budget[DOMAIN as usize], 199_800,
        "FIX: stub credited to the redemption domain's per-domain budget");
    assert_eq!(group.insurance_domain_spent[DOMAIN as usize], 0, "no spend on the domain budget");
    // RESIDUAL NEUTRALITY still holds exactly: vault minus every tracked claim
    // (including the BUG-2 dead-share principal, now nonzero) is ZERO.
    assert_eq!(group.vault, 201_200, "header.vault still holds the stub + dead-share dust atoms");
    assert_eq!(group.c_tot, 0, "no counterparty capital");
    assert_eq!(group.backing_provider_earnings_total, 400, "small earnings dust from the dead-share floor");
    assert_eq!(
        group.source_fresh_backing_total_num,
        LP_VAULT_MINIMUM_LIQUIDITY * percolator::BOUND_SCALE,
        "dead-share floor's principal is still nominally 'fresh backing' — permanently unwithdrawable"
    );
    let residual = group.vault
        - (group.c_tot + group.insurance + group.backing_provider_earnings_total
            + group.source_fresh_backing_total_num / percolator::BOUND_SCALE);
    assert_eq!(residual, 0, "residual neutrality: every vault atom is accounted for by SOME counter");

    // ── Drain the stub via WithdrawInsuranceAsset (insurance_operator = admin). ──
    // Requires Live mode (asset 1, domain 2). The greedy long-first debit drains
    // domain 2 fully because the entire stub lives there.
    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let admin = env.admin.insecure_clone();
    let admin_insurance_dest = Pubkey::new_unique();
    set_token(&mut env.svm, admin_insurance_dest, env.collateral_mint, admin.pubkey(), 0);
    env.svm.expire_blockhash();
    send(&mut env.svm, pid, &payer, vec![(ProgInstruction::WithdrawInsuranceAsset {
        asset_index: APPEND_ASSET_INDEX, amount: 199_800,
    }, vec![
        AccountMeta::new(admin.pubkey(), true),                 // 0 operator (signer)
        AccountMeta::new(env.market, false),                    // 1 market
        AccountMeta::new(admin_insurance_dest, false),          // 2 dest token (operator-owned)
        AccountMeta::new(env.vault_token, false),               // 3 vault token
        AccountMeta::new_readonly(env.vault_authority, false),  // 4 vault authority PDA
        AccountMeta::new_readonly(spl_token::ID, false),        // 5 token program
    ])], &[&admin]).expect("WithdrawInsuranceAsset drains the earnings stub (LPVAULT-359 fix still works)");

    assert_eq!(tok(&env.svm, admin_insurance_dest), 199_800, "operator received the full earnings stub");
    // The dead-share floor's principal (1_000) + earnings dust (400) remain —
    // NOT drained to zero, unlike the pre-BUG-2 LPVAULT-359 test.
    assert_eq!(
        vault_balance(&env), 1_400,
        "dead-share floor's stranded principal + earnings dust remains after the insurance sweep"
    );
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert_eq!(group.insurance, 0, "header.insurance drained to zero");
    assert_eq!(group.vault, 1_400, "header.vault still holds the permanently-stranded dead-share dust");
    assert_eq!(group.insurance_domain_budget_remaining_total, 0, "domain budget drained to zero");

    // ── ResolveMarket → terminal mode; CloseSlab is now PERMANENTLY blocked. ──
    env.svm.expire_blockhash();
    send(&mut env.svm, pid, &payer, vec![(ProgInstruction::ResolveMarket, vec![
        AccountMeta::new(admin.pubkey(), true),
        AccountMeta::new(env.market, false),
    ])], &[&admin]).expect("resolve market");
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    assert_eq!(group.mode, MarketModeV16::Resolved, "market resolved (terminal mode 1)");

    // CloseSlab gates on vault==0 && insurance==0 && c_tot==0. insurance is 0
    // (fully swept above) but vault == 1_400 (dead-share principal + earnings
    // dust) can NEVER reach 0 — no instruction can move it (its
    // backing_bucket_authority is the registry PDA, which cannot sign a
    // generic WithdrawBackingBucket outside the wrapper's own
    // instruction-scoped invoke_signed calls). BUG-2's dead-share defense
    // therefore permanently reverses the LPVAULT-359 fix's teardown guarantee
    // for any market whose LP vault ever took a genesis deposit — an accepted
    // trade-off of the anti-inflation floor, not a bug in either fix.
    let close_dest = Pubkey::new_unique();
    set_token(&mut env.svm, close_dest, env.collateral_mint, admin.pubkey(), 0);
    env.svm.expire_blockhash();
    let res = send(&mut env.svm, pid, &payer, vec![(ProgInstruction::CloseSlab, vec![
        AccountMeta::new(admin.pubkey(), true),                 // 0 admin (signer, writable, rent dest)
        AccountMeta::new(env.market, false),                    // 1 market
        AccountMeta::new(env.vault_token, false),               // 2 vault token
        AccountMeta::new_readonly(env.vault_authority, false),  // 3 vault authority PDA
        AccountMeta::new(close_dest, false),                    // 4 dest token (admin-owned)
        AccountMeta::new_readonly(spl_token::ID, false),        // 5 token program
    ])], &[&admin]);
    assert!(
        res.is_err(),
        "CloseSlab must now stay permanently blocked by the dead-share floor's stranded vault dust: {res:?}"
    );
}

// ── ExecuteRedemption proportional solvency gate (fixes the over-broad
// positive_claim_bound_num!=0 / exact_positive_claim_num!=0 hard-reject) ────
//
// Before the fix, handle_execute_redemption's inline withdraw gate rejected
// ANY redemption on a domain carrying a live source-credit lien outright,
// regardless of whether that lien stayed fully covered afterward -- so once
// any lien existed on an LP-vault domain (e.g. from real trading activity
// against that backing), EVERY redemption on it was permanently bricked,
// even though the domain's own already-present, already-correct proportional
// check (mirroring handle_withdraw_backing_bucket's admin-path watermark
// gate -- see the "RESYNC 5ebd136 DUAL withdraw-gate" block) would have
// allowed it. The fix deletes the two over-broad clauses so that proportional
// check becomes the real (and only) solvency gate, matching the admin path
// byte-for-byte.
//
// Hand-crafts a source-credit lien directly on the market account (same
// technique as `seed_earnings`/`set_c_tot_for_test` above, and the same
// pattern already used for the admin-path equivalent in
// tests/v16_wrapper.rs::v16_wrapper_withdraw_backing_bucket_returns_only_unencumbered_backing)
// since no instruction in this build can open a real position against LP
// vault backing; the lien fields themselves are exactly what the gate reads,
// so this exercises the real gate logic precisely.

/// Sets a source-credit lien on `domain`: `positive_claim_bound_num` =
/// `exact_positive_claim_num` = `claim_atoms * BOUND_SCALE`, `credit_rate_num`
/// = `CREDIT_RATE_SCALE` (i.e. a claim that is, at the moment it's set, fully
/// covered by whatever `fresh_reserved_backing_num` already holds), and bumps
/// the header's `pnl_pos_bound_tot_num` / `pnl_pos_bound_tot` aggregate to
/// stay consistent with `validate_shape`'s `derived_bound ==
/// pnl_pos_bound_tot` check (mirrors the admin-path test's RESYNC comment).
fn set_source_credit_lien_for_test(env: &mut Env, domain: u16, claim_atoms: u128) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    let claim_num = claim_atoms * percolator::BOUND_SCALE;
    group.source_credit[domain as usize].positive_claim_bound_num = claim_num;
    group.source_credit[domain as usize].exact_positive_claim_num = claim_num;
    group.source_credit[domain as usize].credit_rate_num = percolator::CREDIT_RATE_SCALE;
    group.pnl_pos_bound_tot_num = claim_num;
    group.pnl_pos_bound_tot = claim_atoms;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

fn source_credit_fresh_reserved_atoms(env: &Env, domain: u16) -> u128 {
    let (_, group) = state::read_market(&env.svm.get_account(&env.market).unwrap().data).unwrap();
    group.source_credit[domain as usize].fresh_reserved_backing_num / percolator::BOUND_SCALE
}

#[test]
fn execute_redemption_succeeds_against_covered_lien_and_rejects_under_backed_redemption() {
    // Two depositors share the vault's DOMAIN backing pool:
    //   D1 (genesis): deposits DEPOSIT (1_000_000), mints MINTED (999_000).
    //   D2: deposits 2*DEPOSIT (2_000_000), mints 2_000_000 (1:1, not genesis).
    // Total pool backing = 3_000_000 atoms (no earnings seeded, so 1:1 with
    // deposited atoms).
    let mut env = setup_vault(0); // immediate cooldown
    let d1 = new_depositor(&mut env, DEPOSIT);
    let d2 = new_depositor(&mut env, 2 * DEPOSIT);
    let total_backing = source_credit_fresh_reserved_atoms(&env, DOMAIN);
    assert_eq!(total_backing, DEPOSIT + 2 * DEPOSIT, "sanity: pool backing == sum of deposits (no earnings)");

    // Hand-craft a live lien for 2_000_000 atoms -- fully covered right now
    // (3_000_000 available >= 2_000_000 claimed), but leaves only 1_000_000
    // atoms of headroom for redemptions before the domain would go
    // under-backed.
    let claim_atoms: u128 = 2 * DEPOSIT;
    set_source_credit_lien_for_test(&mut env, DOMAIN, claim_atoms);

    // D1 redeems its full MINTED (999_000) balance. Post-redemption backing:
    // 3_000_000 - 999_000 = 2_001_000, still >= the 2_000_000 claim bound
    // (1_000 atoms of margin) -- fully covered, so this MUST SUCCEED even
    // though positive_claim_bound_num != 0 on this domain. Before the fix,
    // this redemption would have been rejected outright by the over-broad
    // `positive_claim_bound_num != 0` clause regardless of coverage.
    request(&mut env, &d1, MINTED).expect("request d1");
    env.svm.expire_blockhash();
    execute(&mut env, &d1).expect(
        "ExecuteRedemption against a fully-covered lien must succeed (proportional gate, not a hard lien-exists reject)",
    );
    assert_eq!(tok(&env.svm, d1.dest), MINTED as u64, "d1 paid in full");
    let after_d1 = source_credit_fresh_reserved_atoms(&env, DOMAIN);
    assert_eq!(after_d1, total_backing - MINTED, "backing decremented by exactly d1's principal");
    assert!(after_d1 >= claim_atoms, "domain must remain fully covered after d1's redemption");

    // D2 now tries to redeem 100_000 of its 2_000_000 shares. Post-redemption
    // backing would be 2_001_000 - 100_000 = 1_901_000 < the 2_000_000 claim
    // bound -- UNDER-BACKED -- so this MUST be REJECTED. This proves the
    // proportional gate still protects solvency: the fix only removed the
    // over-broad "any lien exists" reject, not the actual coverage check.
    request(&mut env, &d2, 100_000).expect("request d2 (partial)");
    env.svm.expire_blockhash();
    let res = execute(&mut env, &d2);
    assert!(
        res.is_err(),
        "ExecuteRedemption that would leave the domain under-backed relative to its claim must be rejected: {res:?}"
    );
    assert_eq!(tok(&env.svm, d2.dest), 0, "no payout on the rejected under-backed redemption");
    let after_rejected = source_credit_fresh_reserved_atoms(&env, DOMAIN);
    assert_eq!(after_rejected, after_d1, "rejected redemption must not mutate backing state (atomic rollback)");

    // Sanity: the SAME 100_000 request, once the lien is relaxed back to 0,
    // executes cleanly -- confirms the D2 rejection above was specifically
    // the solvency gate (not some unrelated account/setup issue) and that
    // the pending redemption request survives a prior rejected execute.
    set_source_credit_lien_for_test(&mut env, DOMAIN, 0);
    env.svm.expire_blockhash();
    execute(&mut env, &d2).expect("same request executes once the lien no longer makes it under-backed");
    assert_eq!(tok(&env.svm, d2.dest), 100_000, "d2 paid once solvency is restored");
}

// ── Finding 1 (mode gate) + Finding 3 (crank with no LPs) ───────────────────

/// Force `header.mode` directly. Accepted direct-write boundary, and the same
/// one `v16_wrapper.rs:3978` / `v16_cu.rs:8421` use to reach Recovery, which no
/// wrapper instruction can enter on demand. Safe here because the mode gate
/// under test returns BEFORE any engine call, so no shape validation is skipped
/// on the rejecting path.
fn set_mode(env: &mut Env, mode: MarketModeV16) {
    let mut acct = env.svm.get_account(&env.market).expect("market");
    let (cfg, mut group) = state::read_market(&acct.data).expect("read market");
    group.mode = mode;
    state::write_market(&mut acct.data, &cfg, &group).expect("write market");
    env.svm.set_account(env.market, acct).unwrap();
}

fn lp_shares_outstanding(env: &Env) -> u128 {
    state::read_lp_vault_registry(&env.svm.get_account(&env.registry).unwrap().data)
        .unwrap()
        .total_lp_shares_outstanding
}

/// FINDING 1: tag 78 is FULLY PERMISSIONLESS -- its only auth is
/// `expect_signer(cranker)` on an arbitrary fee payer -- and before this fix it
/// never read `group.header.mode`. It converts senior `header.insurance` into
/// junior LP backing principal that LPs then redeem out.
///
/// The attack: a market enters Recovery after a solvency event with unbudgeted
/// surplus still sitting in `header.insurance`. That surplus IS the recovery
/// buffer. Any signer could call tag 78 and convert up to
/// `lp_fee_accrued - lp_fee_withdrawn` of it into LP junior backing. Same
/// exposure in Resolved, before trader portfolios are materialised.
///
/// Both are now rejected with `EngineLockActive` = Custom(21), the same code
/// both sibling handlers use. The claim is NOT destroyed by the rejection --
/// the Live control at the end drains it in full, proving the gate defers the
/// crank rather than forfeiting LP yield.
#[test]
fn crank_fees_rejected_outside_live_mode() {
    const LP_FEES: u128 = 250_000;

    // ---- Recovery (mode 2): the headline failure. ----
    let mut env = setup_vault(0);
    let _d = new_depositor(&mut env, DEPOSIT);
    seed_lp_fee_accrued(&mut env, LP_FEES);

    let (vault_before, insurance_before) = vault_and_insurance(&env);
    let counters_before = lp_fee_counters(&env);
    assert_eq!(counters_before, (LP_FEES, 0), "a full claim is outstanding");
    assert!(insurance_before >= LP_FEES, "the claim is fully backed, so ONLY the mode gate can reject");

    set_mode(&mut env, MarketModeV16::Recovery);
    env.svm.expire_blockhash();
    let err = crank_fees(&mut env).expect_err("a permissionless crank in Recovery must reject");
    assert!(
        err.contains("Custom(21)"),
        "Recovery crank must return EngineLockActive = Custom(21), got: {err}"
    );
    assert_eq!(
        vault_and_insurance(&env),
        (vault_before, insurance_before),
        "the recovery buffer must be byte-identical after a rejected crank -- \
         not one atom reclassified out of header.insurance"
    );
    assert_eq!(
        lp_fee_counters(&env),
        counters_before,
        "nothing may be marked withdrawn on a rejected crank"
    );

    // ---- Resolved (mode 1), via the REAL ResolveMarket instruction. ----
    let mut env2 = setup_vault(0);
    let _d2 = new_depositor(&mut env2, DEPOSIT);
    seed_lp_fee_accrued(&mut env2, LP_FEES);
    let (v2_before, i2_before) = vault_and_insurance(&env2);
    resolve_market(&mut env2).expect("resolve empty market with LP backing");
    env2.svm.expire_blockhash();
    let err2 = crank_fees(&mut env2).expect_err("a permissionless crank in Resolved must reject");
    assert!(
        err2.contains("Custom(21)"),
        "Resolved crank must return EngineLockActive = Custom(21), got: {err2}"
    );
    assert_eq!(
        vault_and_insurance(&env2),
        (v2_before, i2_before),
        "Resolved: header.insurance must be untouched by the rejected crank"
    );
    assert_eq!(lp_fee_counters(&env2), (LP_FEES, 0), "Resolved: claim intact");

    // ---- Live-but-MATURED: still mode 0, but past the permissionless
    //      stale-resolve horizon, i.e. a market anyone may resolve and that is
    //      merely waiting for someone to do it. `handle_deposit_to_lp_vault`
    //      refuses permissionless writes here via
    //      `reject_permissionless_resolve_matured_live_view`; so must this. ----
    let mut env3 = setup_vault(0);
    let _d3 = new_depositor(&mut env3, DEPOSIT);
    seed_lp_fee_accrued(&mut env3, LP_FEES);
    let (v3_before, i3_before) = vault_and_insurance(&env3);
    {
        let mut acct = env3.svm.get_account(&env3.market).expect("market");
        let (mut cfg, group) = state::read_market(&acct.data).expect("read market");
        assert_eq!(group.mode, MarketModeV16::Live, "still Live -- only maturity differs");
        // `permissionless_stale_matured`: stale_slots != 0 && now - last_good >= stale_slots.
        cfg.permissionless_resolve_stale_slots = 1;
        cfg.last_good_oracle_slot = 0;
        state::write_market(&mut acct.data, &cfg, &group).expect("write market");
        env3.svm.set_account(env3.market, acct).unwrap();
    }
    // `permissionless_stale_matured` reads
    // `authenticated_market_slot_or_fallback_view` = max(Clock.slot,
    // header.current_slot); both are 0 in a fresh LiteSVM, so the horizon has to
    // be crossed by actually advancing the chain.
    env3.svm.warp_to_slot(50);
    env3.svm.expire_blockhash();
    let err3 = crank_fees(&mut env3).expect_err("a permissionless crank on a matured Live market must reject");
    assert!(
        err3.contains("Custom(27)"),
        "matured-Live crank must return OracleStale = Custom(27), got: {err3}"
    );
    assert_eq!(
        vault_and_insurance(&env3),
        (v3_before, i3_before),
        "matured Live: header.insurance must be untouched by the rejected crank"
    );
    assert_eq!(lp_fee_counters(&env3), (LP_FEES, 0), "matured Live: claim intact");

    // ---- Live control (non-vacuity + claim-not-forfeited). ----
    // The SAME market, SAME claim, SAME backing: only the mode differs. It must
    // succeed and drain the claim IN FULL, which proves the gate defers rather
    // than destroys, and that neither assertion above passed for some unrelated
    // reason.
    set_mode(&mut env, MarketModeV16::Live);
    env.svm.expire_blockhash();
    crank_fees(&mut env).expect("the identical crank in Live mode must succeed");
    let (accrued_live, withdrawn_live) = lp_fee_counters(&env);
    assert_eq!(accrued_live, LP_FEES, "accrued must not move on a crank");
    assert_eq!(
        withdrawn_live, LP_FEES,
        "the deferred claim is drained IN FULL once the market is Live again"
    );
    let (vault_live, insurance_live) = vault_and_insurance(&env);
    assert_eq!(
        vault_live, vault_before,
        "header.vault is unchanged across the crank -- the crank moves no tokens"
    );
    assert_eq!(
        insurance_before - insurance_live,
        LP_FEES,
        "and NOW header.insurance falls by exactly the reclassified claim"
    );
}

/// FINDING 3: a crank with no LPs left orphans the atoms.
///
/// `add_fresh_counterparty_backing_view` accepts an `Empty`/`Expired` bucket, so
/// after every real LP has redeemed (outstanding back to the irreducible
/// `LP_VAULT_MINIMUM_LIQUIDITY` dead-share floor, SPL mint supply 0) a
/// permissionless crank used to move `header.insurance` into
/// `ledger.total_principal_atoms` + `bucket.fresh_unliened_backing_num` with
/// ZERO real shares able to claim it. `handle_close_lp_vault` inspects only
/// shares and mint supply -- never the backing ledger -- so the registry could
/// then be torn down with that principal permanently stranded inside it. No
/// solvency break; the atoms simply leave the insurance fund and belong to
/// nobody.
///
/// Now rejected with `LpVaultZeroSharesMinted` = Custom(41). NOT Custom(38)
/// (`LpVaultNoFeesToCrank`): fees demonstrably DO exist here, and "no fees"
/// would send an operator hunting for a missing accrual instead of a missing LP.
#[test]
fn crank_fees_after_full_lp_exit_rejects_and_leaves_atoms_in_insurance() {
    const LP_FEES: u128 = 250_000;

    let mut env = setup_vault(0);
    let d = new_depositor(&mut env, DEPOSIT);
    seed_lp_fee_accrued(&mut env, LP_FEES);

    // Full LP exit: the sole (genesis) depositor redeems every REAL share.
    request(&mut env, &d, MINTED).expect("request full redemption");
    execute(&mut env, &d).expect("execute full redemption");
    assert_eq!(tok(&env.svm, d.lp_ata), 0, "no real LP shares left in any ATA");
    assert_eq!(
        lp_shares_outstanding(&env),
        LP_VAULT_MINIMUM_LIQUIDITY,
        "outstanding is back at the irreducible dead-share floor -- these were \
         never minted and can never be redeemed, so they cannot claim anything"
    );

    // The fees are still there and still claimable-looking: this is exactly the
    // state in which the pre-fix crank succeeded and orphaned them.
    let (vault_before, insurance_before) = vault_and_insurance(&env);
    let counters_before = lp_fee_counters(&env);
    assert_eq!(counters_before, (LP_FEES, 0), "the full LP fee claim is still outstanding");
    assert!(
        insurance_before >= LP_FEES,
        "and still fully backed -- so ONLY the no-LPs guard can reject this crank"
    );
    let principal_before = ledger(&env).total_principal_atoms;

    env.svm.expire_blockhash();
    let err = crank_fees(&mut env).expect_err("a crank with no real LP shares must reject");
    assert!(
        err.contains("Custom(41)"),
        "crank after full LP exit must return LpVaultZeroSharesMinted = Custom(41), got: {err}"
    );

    // The atoms stayed in the insurance fund -- the whole point of the guard.
    assert_eq!(
        vault_and_insurance(&env),
        (vault_before, insurance_before),
        "header.insurance must still hold the fee atoms; nothing was reclassified"
    );
    assert_eq!(
        ledger(&env).total_principal_atoms,
        principal_before,
        "no unclaimable principal was credited to the backing ledger"
    );
    assert_eq!(lp_fee_counters(&env), counters_before, "nothing marked withdrawn");

    // And the vault can still be torn down cleanly, with no stranded principal.
    close_lp_vault(&mut env).expect("CloseLpVault still succeeds at the dead-share floor");
}

// ── v17 dual-domain: NAV must span BOTH pots on the way OUT as well as in ──

/// A depositor whose collateral is routed to the SIBLING pot of the vault's asset.
fn new_depositor_into_sibling(env: &mut Env, amount: u128) -> Depositor {
    let kp = Keypair::new();
    env.svm.airdrop(&kp.pubkey(), 100_000_000_000).unwrap();
    let source = Pubkey::new_unique();
    set_token(&mut env.svm, source, env.collateral_mint, kp.pubkey(), 10_000_000);
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
        vec![(ProgInstruction::DepositToLpVault { amount, domain: DOMAIN ^ 1 }, accts)],
        &[&kp],
    )
    .expect("sibling deposit");
    Depositor { kp, source, lp_ata, dest, redemption }
}

/// RED: a redemption must value shares against BOTH pots.
///
/// Two equal deposits, one into each pot, so NAV == 2 * DEPOSIT and the share
/// supply is ~2 * DEPOSIT. Redeeming depositor 1's whole stake is therefore worth
/// ~DEPOSIT, and their own pot holds exactly that much, so it can be paid in full.
///
/// If NAV is read from `registry.domain`'s ledger alone it reads DEPOSIT, and the
/// redeemer is paid ~DEPOSIT/2 — half of what they own. The sibling pot's value is
/// silently confiscated from anyone who exits.
#[test]
fn redemption_prices_shares_off_combined_nav() {
    let mut env = setup_vault(0);
    let d1 = new_depositor(&mut env, DEPOSIT);
    let _d2 = new_depositor_into_sibling(&mut env, DEPOSIT);

    let shares = tok(&env.svm, d1.lp_ata) as u128;
    assert!(shares > 0, "depositor 1 holds shares");
    request(&mut env, &d1, shares).expect("request redeem");
    execute(&mut env, &d1).expect("execute redemption");

    let paid = tok(&env.svm, d1.dest) as u128;
    // Depositor 1 paid the one-off dead-share floor at genesis; allow exactly that.
    let floor = LP_VAULT_MINIMUM_LIQUIDITY;
    assert!(
        paid + floor >= DEPOSIT,
        "redeemer was paid {paid} for a stake worth ~{DEPOSIT} — NAV is ignoring the \
         sibling pot, so exiting LPs forfeit whatever sits in it"
    );
    assert!(paid <= DEPOSIT, "must not overpay: got {paid}, stake worth ~{DEPOSIT}");
}

/// Piece 4: does the fee crank still behave when the vault's OWN pot is empty
/// because all the backing was routed to the sibling?
///
/// The crank mints no shares, so it cannot dilute; the question is only whether
/// it still credits value the LP can actually get back out. It credits
/// `registry.domain`'s bucket, which is `Empty` here —
/// `add_fresh_counterparty_backing_view` accepts Empty/Expired and reopens the
/// bucket as Fresh — and combined NAV then picks the credit up from either pot.
#[test]
fn crank_fees_credits_nav_when_all_backing_sits_in_the_sibling_pot() {
    const LP_FEES: u128 = 250_000;
    let mut env = setup_vault(0);
    let d = new_depositor_into_sibling(&mut env, DEPOSIT);
    seed_lp_fee_accrued(&mut env, LP_FEES);

    env.svm.expire_blockhash();
    // Crank into the SIBLING, i.e. the pot that actually holds this vault's money.
    // Before the fix this reverted IncorrectProgramId: the handler unconditionally
    // required the OWN-domain ledger to already exist, and with routed deposits it
    // never had been created.
    crank_fees_into(&mut env, DOMAIN ^ 1).expect("crank into the pot holding the backing");

    let shares = tok(&env.svm, d.lp_ata) as u128;
    request(&mut env, &d, shares).expect("request redeem");
    env.svm.expire_blockhash();
    // Draw the payout from the pot the money is actually in.
    execute_from(&mut env, &d, DOMAIN ^ 1).expect("execute redemption from the sibling pot");

    let paid = tok(&env.svm, d.dest) as u128;
    // The sole LP owns the whole vault: their DEPOSIT plus the cranked fee slice.
    // fee_share_bps is 50% in this harness, so the LP's cut of LP_FEES is half.
    assert!(
        paid > DEPOSIT,
        "cranked fees must reach the redeemer: paid {paid}, deposit {DEPOSIT}"
    );
    assert!(
        paid <= DEPOSIT + LP_FEES,
        "must not overpay: paid {paid} vs deposit {DEPOSIT} + fees {LP_FEES}"
    );
}

/// Isolates the lazy-create path: crank fees into the pot that has NO ledger yet.
/// All the money went to the sibling, so `registry.domain`'s ledger was never
/// created. The handler used to `expect_owner` it unconditionally and reverted
/// IncorrectProgramId; it must now create it on first use.
#[test]
fn crank_fees_creates_the_ledger_of_a_pot_that_has_none() {
    const LP_FEES: u128 = 250_000;
    let mut env = setup_vault(0);
    let _d = new_depositor_into_sibling(&mut env, DEPOSIT);

    let own_ledger = env.svm.get_account(&env.ledger);
    assert!(
        own_ledger.is_none() || own_ledger.unwrap().data.is_empty(),
        "precondition: the vault's own-domain ledger must not exist yet"
    );

    seed_lp_fee_accrued(&mut env, LP_FEES);
    env.svm.expire_blockhash();
    crank_fees_into(&mut env, DOMAIN).expect("crank must create the missing ledger");

    let created = env.svm.get_account(&env.ledger).expect("ledger now exists");
    assert!(!created.data.is_empty(), "ledger was created and written");
    assert!(
        ledger(&env).total_principal_atoms > 0,
        "cranked fees landed in the newly created ledger"
    );
}

#[test]
fn request_redeem_succeeds_with_prefunded_escrow_and_redemption() {
    let mut env = setup_vault(0);
    let depositor = new_depositor(&mut env, DEPOSIT);

    // Simulate the #418 griefing condition:
    // both lazily-created PDAs already hold lamports but still have empty data
    // and are System-owned.
    env.svm
        .set_account(
            env.escrow,
            Account {
                lamports: 1,
                data: vec![],
                owner: solana_sdk::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    env.svm
        .set_account(
            depositor.redemption,
            Account {
                lamports: 1,
                data: vec![],
                owner: solana_sdk::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let pid = env.program_id;
    let payer = env.payer.insecure_clone();
    let accounts = request_accounts(&env, &depositor);

    send(
        &mut env.svm,
        pid,
        &payer,
        vec![(
            ProgInstruction::RequestRedeemLpShares { shares: MINTED },
            accounts,
        )],
        &[&depositor.kp],
    )
    .expect("RequestRedeemLpShares must tolerate pre-funded escrow and redemption PDAs");

    let escrow_acct = env.svm.get_account(&env.escrow).expect("escrow exists");
    assert_eq!(escrow_acct.owner, spl_token::ID, "escrow must become token-owned");
    let escrow = TokenAccount::unpack(&escrow_acct.data).expect("escrow token account decodes");
    assert_eq!(escrow.owner, env.registry, "escrow owner must be registry PDA");
    assert_eq!(escrow.amount, MINTED as u64, "escrow must hold requested LP shares");

    let redemption_acct = env
        .svm
        .get_account(&depositor.redemption)
        .expect("redemption PDA exists");
    assert_eq!(
        redemption_acct.owner, env.program_id,
        "redemption PDA must become program-owned"
    );
    assert!(
        !redemption_acct.data.is_empty(),
        "redemption PDA must be initialized"
    );
}
