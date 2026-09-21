//! Structural canary for the W4-TOKEN22 sync unit (adopt upstream cb1dfd43 "refactor:
//! canonicalize token account validation" + 49443633 "test: prove classic SPL boundary
//! composition").
//!
//! IMPORTANT divergence from the unit's stated goal: upstream's commits do NOT add
//! Token-2022 *acceptance* anywhere in the wrapper. Both commits are a pure dedup refactor
//! of the classic-SPL-only vault/user/withdrawable token-account parsers -- collapsing a
//! second unpack of the same account bytes (for a balance check, an empty-vault check, or
//! the permissionless-payout delegate/close-authority check) into the one canonical parse,
//! by threading the already-validated `u64` balance (and a `require_unencumbered_dest: bool`
//! flag) back to the caller instead of `()`. Upstream's own new test/README text is explicit:
//! "production deliberately accepts classic SPL Token only" and "[a]rbitrary future token
//! programs remain out of scope". `Cargo.toml` gains no `spl-token-2022` dependency in either
//! commit. This canary proves the refactor's SHAPE (one gateway parser, reused facts); the
//! accept/reject behavioral proof against the real Token-2022 program id lives in
//! `tests/v16_cu.rs` (`v16_bpf_deposit_source_owned_by_token2022_is_rejected_classic_spl_accepted`).
//!
//! Our fork's `read_nft_holder_token_account` (E2 native NFT-holder auth) is a SEPARATE,
//! pre-existing, intentionally dual-owner (`spl_token::ID` OR the real Token-2022 program id)
//! parser for reading a holder's Position NFT ATA -- Position NFTs are minted via Token-2022.
//! It does not call `unpack_token_account` or `spl_token::state::Account::unpack`, so it does
//! not appear in, and does not violate, the single-gateway count below. That is a different
//! subsystem (NFT holder authorization, not vault/collateral custody) and is out of scope for
//! this unit -- named here only so a future reader does not conflate the two.

#[test]
fn v16_program_classic_spl_vault_parser_is_single_gateway_and_reuses_validated_balances() {
    let source = include_str!("../src/v16_program.rs");

    // Exactly one place in production ever calls the raw SPL account unpack for the
    // vault/collateral path.
    assert_eq!(
        source.matches("spl_token::state::Account::unpack(&data)").count(),
        1,
        "classic SPL account bytes must have exactly one production parser \
         (unpack_token_account); a second raw Account::unpack call site would mean a \
         handler is bypassing the canonical validator",
    );

    // Every occurrence of `unpack_token_account(` -- the definition plus every call --
    // must fall inside the helper block bounded by `fn unpack_token_account(` and the
    // next `fn transfer_tokens` that follows the validator cluster. A call site outside
    // that window would mean some handler re-unpacks token bytes instead of consuming the
    // balance/facts already returned by verify_user_token_account / verify_vault_token_account
    // / verify_withdrawable_token_accounts.
    let gateway_start = source
        .find("fn unpack_token_account(")
        .expect("canonical SPL account parser must exist");
    let gateway_end = source[gateway_start..]
        .find("fn transfer_tokens")
        .map(|offset| gateway_start + offset)
        .expect("token CPI boundary follows the validator helper cluster");
    let parser_sites: Vec<_> = source.match_indices("unpack_token_account(").collect();
    assert_eq!(
        parser_sites.len(),
        5,
        "expected one parser definition plus four canonical validation call sites \
         (verify_user_token_account x1, verify_withdrawable_token_accounts x2 [dest+vault], \
         verify_vault_token_account x1); require_empty_vault_token_account no longer \
         re-unpacks -- it reads verify_vault_token_account's returned balance instead. Got {}",
        parser_sites.len(),
    );
    assert!(
        parser_sites
            .iter()
            .all(|(offset, _)| *offset >= gateway_start && *offset < gateway_end),
        "a handler is unpacking classic SPL token bytes directly instead of going through \
         the canonical validator cluster",
    );

    // The balance-returning signatures upstream's refactor introduced.
    assert!(
        source.contains("fn require_token_balance(balance: u64"),
        "balance checks must consume the already-validated SPL state, not re-derive it",
    );
    assert!(
        source.contains("require_unencumbered_dest: bool"),
        "the permissionless-payout delegate/close-authority check must be folded into \
         verify_withdrawable_token_accounts via a bool flag, not a second separate unpack",
    );
    // Upstream deleted the separate `verify_permissionless_payout_dest_token_account` fn
    // entirely once its check was folded in. Confirm our fork did the same (no orphaned
    // duplicate-parser function left behind).
    assert!(
        !source.contains("fn verify_permissionless_payout_dest_token_account"),
        "the standalone permissionless-payout dest checker should be folded into \
         verify_withdrawable_token_accounts (upstream cb1dfd43), not left as a second \
         parser of the same account",
    );

    // unpack_token_account's classic-SPL-only owner gate is unchanged by this refactor --
    // this is the line that actually rejects a Token-2022 (or any non-classic-SPL) vault
    // account. If this disappears, the accept/reject behavioral test in v16_cu.rs will also
    // fail (belt-and-suspenders: this is the structural half of that proof).
    assert!(
        source.contains("if token_ai.owner != &spl_token::ID {")
            && source.contains("return Err(PercolatorError::InvalidTokenAccount.into());"),
        "unpack_token_account must still hard-reject any account not owned by classic \
         spl_token::ID -- production remains classic-SPL-only by design",
    );
}
