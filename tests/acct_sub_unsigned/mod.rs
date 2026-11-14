//! Account-substitution cells that PR #703 (`tests/acct_sub/mod.rs`) left out (job
//! J-20261114-PROG-WITHDRAW-SUB). Same attacker view: the caller picks every account.
//!
//! New columns:
//!   * UNSIGNED `CloseResolved` (permissionless terminal payout, nobody signs): delegated and
//!     close-authority destination, wrong mint (dest and vault), non-canonical vault address,
//!     vault with a delegate, dest == vault, extra tail accounts.
//!   * signed `Withdraw`: wrong mint, non-canonical vault ATA, vault with delegate / close
//!     authority, extra tail accounts, and the exact error code for a few #703 cells.
//!
//! Every rejection cell pins the exact program error code (#703 only asserts `is_err()`). The
//! "state unchanged" asserts are weak: `run_ix` rolls accounts back on Err, so they only confirm
//! the Err came back. SPL balances never move in this native harness (token CPI is stubbed).
//!
//! #703 keeps its helpers private to `tests/acct_sub`, so the few small fixtures needed are
//! rebuilt here from the shared `v16_wrapper` helpers (no #703 file is touched).
use super::*;

const INVALID_MINT: u32 = percolator_prog::error::PercolatorError::InvalidMint as u32;
const INVALID_TOKEN_ACCOUNT: u32 =
    percolator_prog::error::PercolatorError::InvalidTokenAccount as u32;
const INVALID_VAULT_ACCOUNT: u32 =
    percolator_prog::error::PercolatorError::InvalidVaultAccount as u32;

fn code(c: u32) -> Result<(), ProgramError> {
    Err(ProgramError::Custom(c))
}

// ---- unsigned CloseResolved fixture ------------------------------------------------------------
struct Resolved {
    market: TestAccount,
    portfolio: TestAccount,
    /// The portfolio owner's key, NOT a signer (permissionless path).
    owner_meta: TestAccount,
    mint: Pubkey,
}

fn resolved() -> Resolved {
    let mut admin = signer();
    let mut market = market_account();
    let owner = signer();
    let mut owner_for_init = TestAccount::new(owner.key, Pubkey::new_unique(), 0).signer();
    let mut portfolio = portfolio_account();
    let mint =
        resolved_market_with_payout(&mut admin, &mut market, &mut owner_for_init, &mut portfolio);
    let owner_meta = TestAccount::new(owner.key, Pubkey::new_unique(), 0);
    Resolved {
        market,
        portfolio,
        owner_meta,
        mint,
    }
}

/// Runs unsigned CloseResolved. `tail` accounts follow the NFT-registry proof slot.
fn run_close(
    r: &mut Resolved,
    dest: &mut TestAccount,
    vault: &mut TestAccount,
    tail: &mut [&mut TestAccount],
) -> Result<(), ProgramError> {
    let mut va = vault_authority_account(&r.market);
    let mut tp = token_program_account();
    let mut registry = uninitialized_nft_registry_account(&r.market);
    let mut all: Vec<&mut TestAccount> = vec![
        &mut r.owner_meta,
        &mut r.market,
        &mut r.portfolio,
        dest,
        vault,
        &mut va,
        &mut tp,
        &mut registry,
    ];
    for t in tail.iter_mut() {
        all.push(&mut **t);
    }
    run_ix(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        &mut all,
    )
}

fn reject_close(r: &mut Resolved, dest: &mut TestAccount, vault: &mut TestAccount, expect: u32) {
    let (m0, p0) = (r.market.data.clone(), r.portfolio.data.clone());
    let res = run_close(r, dest, vault, &mut []);
    assert_eq!(res, code(expect), "wrong result for substituted account");
    assert_eq!(
        engine_vault_and_capital(&r.market, &r.portfolio),
        (1_000, 1_000),
        "money moved"
    );
    assert_eq!(r.market.data, m0);
    assert_eq!(r.portfolio.data, p0);
}

#[test]
fn acct_sub_unsigned_close_baseline() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    run_close(&mut r, &mut dest, &mut vault, &mut []).expect("unmutated unsigned close must pay");
    assert_eq!(engine_vault_and_capital(&r.market, &r.portfolio), (0, 0));
}

#[test]
fn acct_sub_unsigned_close_dest_delegated() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    dest.data = make_token_data_with_controls(
        r.mint,
        r.owner_meta.key,
        0,
        COption::Some(Pubkey::new_unique()),
        COption::None,
    );
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    reject_close(&mut r, &mut dest, &mut vault, INVALID_TOKEN_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_dest_close_authority_set() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    dest.data = make_token_data_with_controls(
        r.mint,
        r.owner_meta.key,
        0,
        COption::None,
        COption::Some(Pubkey::new_unique()),
    );
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    reject_close(&mut r, &mut dest, &mut vault, INVALID_TOKEN_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_dest_wrong_mint() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, Pubkey::new_unique(), 0);
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    reject_close(&mut r, &mut dest, &mut vault, INVALID_MINT);
}

#[test]
fn acct_sub_unsigned_close_vault_wrong_mint() {
    let mut r = resolved();
    let other = Pubkey::new_unique();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    // vault keeps the canonical address for the real mint but its data says another mint
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    vault.data = make_token_data(other, vault_authority(&r.market), 1_000);
    reject_close(&mut r, &mut dest, &mut vault, INVALID_MINT);
}

#[test]
fn acct_sub_unsigned_close_vault_not_canonical_ata() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    // right mint, right owner (vault authority), funded, but NOT the canonical ATA address
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    vault.key = Pubkey::new_unique();
    reject_close(&mut r, &mut dest, &mut vault, INVALID_VAULT_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_vault_has_delegate() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    let mut vault = vault_token_account_with_controls(
        &r.market,
        r.mint,
        1_000,
        COption::Some(Pubkey::new_unique()),
        COption::None,
    );
    reject_close(&mut r, &mut dest, &mut vault, INVALID_VAULT_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_vault_has_close_authority() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    let mut vault = vault_token_account_with_controls(
        &r.market,
        r.mint,
        1_000,
        COption::None,
        COption::Some(Pubkey::new_unique()),
    );
    reject_close(&mut r, &mut dest, &mut vault, INVALID_VAULT_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_dest_is_the_vault() {
    let mut r = resolved();
    // dest has the vault's KEY but owner-owned token data, so only the key-equality guard rejects
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    let mut dest = TestAccount::new_with_data(
        vault.key,
        spl_token::ID,
        make_token_data(r.mint, r.owner_meta.key, 0),
    )
    .writable();
    reject_close(&mut r, &mut dest, &mut vault, INVALID_TOKEN_ACCOUNT);
}

#[test]
fn acct_sub_unsigned_close_extra_tail_accounts_do_not_redirect_payout() {
    let mut r = resolved();
    let mut dest = user_token_account(r.owner_meta.key, r.mint, 0);
    let mut vault = vault_token_account(&r.market, r.mint, 1_000);
    // attacker token account + its owner appended after the registry slot
    let attacker = Pubkey::new_unique();
    let mut t1 = user_token_account(attacker, r.mint, 0);
    let mut t2 = TestAccount::new(attacker, Pubkey::new_unique(), 0).signer();
    let (t1_before, t2_before) = (t1.data.clone(), t2.data.clone());
    let res = run_close(&mut r, &mut dest, &mut vault, &mut [&mut t1, &mut t2]);
    // Only accounts 3 and 4 drive the payout; a harmless tail is accepted and ignored.
    assert_eq!(res, Ok(()));
    assert_eq!(t1.data, t1_before, "tail token account was written");
    assert_eq!(t2.data, t2_before);
    assert_eq!(engine_vault_and_capital(&r.market, &r.portfolio), (0, 0));
}

// ---- signed Withdraw fixture -------------------------------------------------------------------
struct Live {
    owner: TestAccount,
    market: TestAccount,
    portfolio: TestAccount,
    mint: Pubkey,
}

fn live() -> Live {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    deposit(&mut owner, &mut market, &mut portfolio, 1_000);
    Live {
        owner,
        market,
        portfolio,
        mint,
    }
}

fn run_withdraw(
    l: &mut Live,
    dest: &mut TestAccount,
    vault: &mut TestAccount,
    va: &mut TestAccount,
    tail: &mut [&mut TestAccount],
) -> Result<(), ProgramError> {
    let (portfolio_id, expected_sequence, _) = portfolio_identity(&l.portfolio);
    let mut tp = token_program_account();
    let mut all: Vec<&mut TestAccount> = vec![
        &mut l.owner,
        &mut l.market,
        &mut l.portfolio,
        dest,
        vault,
        va,
        &mut tp,
    ];
    for t in tail.iter_mut() {
        all.push(&mut **t);
    }
    run_ix(
        Instruction::Withdraw {
            portfolio_id,
            expected_sequence,
            amount: 100,
        },
        &mut all,
    )
}

fn reject_withdraw(
    l: &mut Live,
    dest: &mut TestAccount,
    vault: &mut TestAccount,
    va: &mut TestAccount,
    expect: Result<(), ProgramError>,
) {
    let (m0, p0) = (l.market.data.clone(), l.portfolio.data.clone());
    let res = run_withdraw(l, dest, vault, va, &mut []);
    assert_eq!(res, expect, "wrong result for substituted account");
    assert_eq!(
        engine_vault_and_capital(&l.market, &l.portfolio),
        (1_000, 1_000),
        "money moved"
    );
    assert_eq!(l.market.data, m0);
    assert_eq!(l.portfolio.data, p0);
}

#[test]
fn acct_sub_withdraw_ext_baseline() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    run_withdraw(&mut l, &mut dest, &mut vault, &mut va, &mut []).expect("baseline");
    assert_eq!(
        engine_vault_and_capital(&l.market, &l.portfolio),
        (900, 900)
    );
}

#[test]
fn acct_sub_withdraw_dest_wrong_mint() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, Pubkey::new_unique(), 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(&mut l, &mut dest, &mut vault, &mut va, code(INVALID_MINT));
}

#[test]
fn acct_sub_withdraw_vault_wrong_mint() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    vault.data = make_token_data(Pubkey::new_unique(), vault_authority(&l.market), 1_000);
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(&mut l, &mut dest, &mut vault, &mut va, code(INVALID_MINT));
}

#[test]
fn acct_sub_withdraw_vault_not_canonical_ata() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    vault.key = Pubkey::new_unique();
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        code(INVALID_VAULT_ACCOUNT),
    );
}

#[test]
fn acct_sub_withdraw_vault_has_delegate() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account_with_controls(
        &l.market,
        l.mint,
        1_000,
        COption::Some(Pubkey::new_unique()),
        COption::None,
    );
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        code(INVALID_VAULT_ACCOUNT),
    );
}

#[test]
fn acct_sub_withdraw_vault_has_close_authority() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account_with_controls(
        &l.market,
        l.mint,
        1_000,
        COption::None,
        COption::Some(Pubkey::new_unique()),
    );
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        code(INVALID_VAULT_ACCOUNT),
    );
}

#[test]
fn acct_sub_withdraw_dest_is_the_vault() {
    let mut l = live();
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    // vault's KEY with owner-owned token data, so only the key-equality guard rejects
    let mut dest = TestAccount::new_with_data(
        vault.key,
        spl_token::ID,
        make_token_data(l.mint, l.owner.key, 0),
    )
    .writable();
    let mut va = vault_authority_account(&l.market);
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        code(INVALID_TOKEN_ACCOUNT),
    );
}

/// By design, NOT a hole: the owner signs and picks their own destination, so a delegate on it is
/// self-inflicted (see `verify_withdrawable_token_accounts`: only permissionless payouts demand an
/// unencumbered destination). Pinned here so a change in that choice is visible.
#[test]
fn acct_sub_withdraw_delegated_dest_is_accepted_for_the_signing_owner() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    dest.data = make_token_data_with_controls(
        l.mint,
        l.owner.key,
        0,
        COption::Some(Pubkey::new_unique()),
        COption::None,
    );
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    run_withdraw(&mut l, &mut dest, &mut vault, &mut va, &mut []).expect("owner-chosen dest");
    assert_eq!(
        engine_vault_and_capital(&l.market, &l.portfolio),
        (900, 900)
    );
}

#[test]
fn acct_sub_withdraw_extra_tail_accounts_do_not_redirect_payout() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    let attacker = Pubkey::new_unique();
    let mut t1 = user_token_account(attacker, l.mint, 0);
    let mut t2 = TestAccount::new(attacker, Pubkey::new_unique(), 0).signer();
    let (t1_before, t2_before) = (t1.data.clone(), t2.data.clone());
    let res = run_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        &mut [&mut t1, &mut t2],
    );
    assert_eq!(res, Ok(()));
    assert_eq!(t1.data, t1_before, "tail token account was written");
    assert_eq!(t2.data, t2_before);
    assert_eq!(
        engine_vault_and_capital(&l.market, &l.portfolio),
        (900, 900)
    );
}

// ---- exact error codes for #703 cells that are cheap to pin ----------------------------------
#[test]
fn acct_sub_withdraw_wrong_vault_authority_key_error_code() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    va.key = Pubkey::new_unique();
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        Err(ProgramError::InvalidArgument),
    );
}

#[test]
fn acct_sub_withdraw_signer_missing_error_code() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    l.owner.is_signer = false;
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        code(percolator_prog::error::PercolatorError::ExpectedSigner as u32),
    );
}

#[test]
fn acct_sub_withdraw_market_wrong_program_error_code() {
    let mut l = live();
    let mut dest = user_token_account(l.owner.key, l.mint, 0);
    let mut vault = vault_token_account(&l.market, l.mint, 1_000);
    let mut va = vault_authority_account(&l.market);
    l.market.owner = Pubkey::new_unique();
    reject_withdraw(
        &mut l,
        &mut dest,
        &mut vault,
        &mut va,
        Err(ProgramError::IncorrectProgramId),
    );
}
