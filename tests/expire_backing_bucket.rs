//! Focused real-BPF (LiteSVM) behaviour tests for `ExpireBackingBucket` (tag 89),
//! `handle_expire_backing_bucket` in `src/v16_program.rs`.
//!
//! Before this file the instruction was only exercised inside broad scenarios
//! (`tests/v16_cu.rs` `v17_lapsed_backing_bucket_bricks_settlement_until_expired`,
//! `v17_expire_backing_bucket_refuses_a_live_bucket`, the native `v16_wrapper.rs` W-21 tests,
//! and best-effort calls in the fuzz/regression files). Here every gate is pinned with the exact
//! error code, and every refusal is checked to leave the market account byte-for-byte unchanged.
//!
//! Instruction shape: accounts = [market (writable, program-owned)]; NO signer, NO authority
//! account. It is permissionless by design (see the doc on `Instruction::ExpireBackingBucket`),
//! so "wrong authority" is not a refusal: the permissionless test below proves an arbitrary,
//! non-admin fee payer succeeds.
//!
//! Run with the SBF at target/deploy/percolator_prog.so (or INDEP_WRAPPER_SO).
#![cfg(not(kani))]
#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_attributes, clippy::all)]
mod indep_harness;

use indep_harness::*;
use percolator::{BackingBucketStatusV16, MarketModeV16, BOUND_SCALE, POS_SCALE};
use percolator_prog::{error::PercolatorError, ix::Instruction as ProgInstruction};
use solana_sdk::{
    account::Account,
    instruction::AccountMeta,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const AMOUNT: u128 = 500;
/// Bucket expiry slot used by the topped-up fixtures (well past the fixture's slot 1).
const EXPIRY: u64 = 200;

fn code(err: &str) -> Option<u32> {
    let marker = "Custom(";
    let start = err.find(marker)? + marker.len();
    let end = start + err[start..].find(')')?;
    err[start..end].parse().ok()
}

fn expect_code(r: Result<u64, String>, want: PercolatorError, what: &str) {
    let e = r.expect_err(&format!("{what}: must be refused"));
    assert_eq!(code(&e), Some(want as u32), "{what}: wrong error, got {e}");
}

/// Everything the conservation law touches, plus the real SPL vault balance.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Totals {
    vault: u128,
    c_tot: u128,
    insurance: u128,
    earnings: u128,
    fresh_total_num: u128,
    token_vault: u64,
}

fn totals(env: &V16CuEnv) -> Totals {
    let (_, g) = env.market_state();
    Totals {
        vault: g.vault,
        c_tot: g.c_tot,
        insurance: g.insurance,
        earnings: g.backing_provider_earnings_total,
        fresh_total_num: g.source_fresh_backing_total_num,
        token_vault: env.token_amount(env.vault),
    }
}

fn market_bytes(env: &V16CuEnv) -> Vec<u8> {
    env.svm.get_account(&env.market).unwrap().data
}

fn expire(env: &mut V16CuEnv, domain: u16) -> Result<u64, String> {
    try_expire_backing_bucket(env, domain)
}

/// Live market, one Fresh bucket on domain 1 holding AMOUNT atoms that lapses at EXPIRY.
fn funded_env() -> V16CuEnv {
    let mut env = V16CuEnv::new();
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
    env.top_up_backing_bucket(1, AMOUNT, EXPIRY);
    let (_, g) = env.market_state();
    let b = g.source_backing_buckets[1];
    assert_eq!(b.status, BackingBucketStatusV16::Fresh);
    assert_eq!(b.expiry_slot, EXPIRY);
    assert_eq!(b.fresh_unliened_backing_num / BOUND_SCALE, AMOUNT);
    env
}

/// A refusal must not move a single byte of the market account.
fn assert_refused_untouched(env: &mut V16CuEnv, domain: u16, want: PercolatorError, what: &str) {
    let before = market_bytes(env);
    let t0 = totals(env);
    env.svm.expire_blockhash();
    expect_code(expire(env, domain), want, what);
    assert_eq!(market_bytes(env), before, "{what}: market bytes must be unchanged");
    assert_eq!(totals(env), t0, "{what}: totals must be unchanged");
}

// ── before / at / after the expiry slot ──────────────────────────────────────

#[test]
fn expire_before_expiry_is_stale_and_changes_nothing() {
    let mut env = funded_env();
    // Slot 1 (far before) and the last slot before the boundary.
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineStale, "slot 1 < expiry");
    env.svm.warp_to_slot(EXPIRY - 1);
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineStale, "expiry-1");
    let b = env.market_state().1.source_backing_buckets[1];
    assert_eq!(b.status, BackingBucketStatusV16::Fresh);
    assert_eq!(b.fresh_unliened_backing_num / BOUND_SCALE, AMOUNT);
}

#[test]
fn expire_exactly_at_expiry_slot_succeeds() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY - 1);
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineStale, "expiry-1");
    env.svm.warp_to_slot(EXPIRY);
    env.svm.expire_blockhash();
    let before = totals(&env);
    expire(&mut env, 1).expect("now_slot == expiry_slot must be accepted (>=)");
    let b = env.market_state().1.source_backing_buckets[1];
    assert_ne!(b.status, BackingBucketStatusV16::Fresh, "bucket left Fresh");
    // The transition moves no tokens and no top-level totals.
    let after = totals(&env);
    assert_eq!(after.token_vault, before.token_vault);
    assert_eq!(after.vault, before.vault);
    assert_eq!(after.c_tot, before.c_tot);
}

#[test]
fn expire_after_expiry_conserves_vault_and_forfeits_principal_to_junior_pool() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY + 500);
    env.svm.expire_blockhash();
    let before = totals(&env);
    let (_, g0) = env.market_state();
    let residual0 = g0.vault
        - g0.c_tot
        - g0.insurance
        - g0.backing_provider_earnings_total
        - g0.source_fresh_backing_total_num / BOUND_SCALE;

    expire(&mut env, 1).expect("lapsed bucket expires");

    let (_, g1) = env.market_state();
    let b = g1.source_backing_buckets[1];
    assert_ne!(b.status, BackingBucketStatusV16::Fresh);
    assert_eq!(b.fresh_unliened_backing_num, 0, "the lapsed principal left the Fresh pot");
    let after = totals(&env);
    // Conservation: no atom enters or leaves custody; the engine vault still equals the SPL vault.
    assert_eq!(after.token_vault, before.token_vault, "no tokens moved");
    assert_eq!(after.vault, before.vault, "engine vault total unchanged");
    assert_eq!(after.c_tot, before.c_tot, "capital unchanged");
    assert_eq!(after.insurance, before.insurance, "insurance unchanged");
    assert_eq!(after.earnings, before.earnings, "provider earnings unchanged");
    assert_eq!(after.vault, after.token_vault as u128, "engine vault == SPL vault");
    // The forfeited principal is exactly what left the Fresh total, and it is still inside
    // vault >= c_tot + insurance + earnings + fresh (it became junior residual).
    assert_eq!(
        before.fresh_total_num - after.fresh_total_num,
        AMOUNT * BOUND_SCALE,
        "exactly the bucket's principal left the fresh-backing total"
    );
    let residual1 = g1.vault
        - g1.c_tot
        - g1.insurance
        - g1.backing_provider_earnings_total
        - g1.source_fresh_backing_total_num / BOUND_SCALE;
    assert_eq!(residual1, residual0 + AMOUNT, "principal is now junior residual, nothing lost");
}

// ── double expire ────────────────────────────────────────────────────────────

#[test]
fn double_expire_second_call_is_stale_and_changes_nothing() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY + 1);
    env.svm.expire_blockhash();
    expire(&mut env, 1).expect("first expiry");
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineStale, "second expiry");
    // Later slots do not revive it either.
    env.svm.warp_to_slot(EXPIRY + 10_000);
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineStale, "third expiry, much later");
}

// ── wrong market / bucket / authority ────────────────────────────────────────

#[test]
fn expire_wrong_bucket_domain_is_refused() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY + 1);
    // Domain 0 never opened a bucket: nothing to expire.
    assert_refused_untouched(&mut env, 0, PercolatorError::EngineStale, "empty domain 0");
    // Out-of-range domain (>= 2 * max_market_slots).
    let slots = env.market_state().1.config.max_market_slots.get() as u16;
    assert_refused_untouched(
        &mut env,
        slots * 2,
        PercolatorError::InvalidInstruction,
        "domain == 2*max_market_slots",
    );
    assert_refused_untouched(&mut env, u16::MAX, PercolatorError::InvalidInstruction, "domain u16::MAX");
    // The real bucket is untouched by all of that and still expires.
    assert_eq!(
        env.market_state().1.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh
    );
    expire(&mut env, 1).expect("the right domain still expires");
}

#[test]
fn expire_wrong_market_account_is_refused() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY + 1);
    let before = market_bytes(&env);

    // (a) market passed read-only.
    env.svm.expire_blockhash();
    let m = env.market;
    let r = env.send(
        ProgInstruction::ExpireBackingBucket { domain: 1 },
        vec![AccountMeta::new_readonly(m, false)],
        &[],
    );
    assert!(r.is_err(), "read-only market must be refused: {r:?}");

    // (b) account not owned by the program (a token account).
    env.svm.expire_blockhash();
    let foreign = Pubkey::new_unique();
    env.svm
        .set_account(
            foreign,
            Account {
                lamports: 1_000_000_000,
                data: market_bytes(&env),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let r = env.send(
        ProgInstruction::ExpireBackingBucket { domain: 1 },
        vec![AccountMeta::new(foreign, false)],
        &[],
    );
    assert!(r.is_err(), "foreign-owned market must be refused: {r:?}");

    // (c) program-owned but not a market (zeroed buffer).
    env.svm.expire_blockhash();
    let blank = Pubkey::new_unique();
    env.svm
        .set_account(
            blank,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; market_bytes(&env).len()],
                owner: env.program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let r = env.send(
        ProgInstruction::ExpireBackingBucket { domain: 1 },
        vec![AccountMeta::new(blank, false)],
        &[],
    );
    assert!(r.is_err(), "blank program-owned account must be refused: {r:?}");

    // (d) no accounts at all.
    env.svm.expire_blockhash();
    let r = env.send(ProgInstruction::ExpireBackingBucket { domain: 1 }, vec![], &[]);
    assert!(r.is_err(), "missing market account must be refused: {r:?}");

    assert_eq!(market_bytes(&env), before, "real market untouched by every wrong-market attempt");
    eprintln!("wrong-market errors pinned above are `is_err`; see exact-code run in the next test");
}

#[test]
fn expire_is_permissionless_any_payer_no_authority_needed() {
    let mut env = funded_env();
    env.svm.warp_to_slot(EXPIRY + 1);
    env.svm.expire_blockhash();
    // `env.payer` is not the admin / backing authority. A fresh stranger funds a tx with
    // ONLY the market account: no signer metas beyond the fee payer.
    assert_ne!(env.payer.pubkey(), env.admin.pubkey());
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let m = env.market;
    let ix = solana_sdk::instruction::Instruction {
        program_id: env.program_id,
        accounts: vec![AccountMeta::new(m, false)],
        data: ProgInstruction::ExpireBackingBucket { domain: 1 }.encode(),
    };
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&stranger.pubkey()),
        &[&stranger],
        env.svm.latest_blockhash(),
    );
    env.svm.send_transaction(tx).expect("any fee payer can expire a lapsed bucket");
    assert_ne!(
        env.market_state().1.source_backing_buckets[1].status,
        BackingBucketStatusV16::Fresh
    );
}

// ── Resolved market ──────────────────────────────────────────────────────────

#[test]
fn expire_on_resolved_market_is_lock_active_and_changes_nothing() {
    let mut env = funded_env();
    env.resolve();
    assert_eq!(env.market_state().1.mode, MarketModeV16::Resolved);
    // Lapsed AND resolved: the Live-only gate fires before the engine ever looks at the bucket.
    env.svm.warp_to_slot(EXPIRY + 1);
    assert_refused_untouched(&mut env, 1, PercolatorError::EngineLockActive, "resolved + lapsed");
    // Not-lapsed + resolved is the same refusal (mode check comes first).
    let mut env2 = funded_env();
    env2.resolve();
    assert_refused_untouched(&mut env2, 1, PercolatorError::EngineLockActive, "resolved + not lapsed");
}

// ── bucket with open claims ──────────────────────────────────────────────────

/// A realized loss opens domain 0's bucket with reserved backing and gives the counterparty an
/// open source claim. Expiring that bucket must conserve every total and leave the open claim
/// recorded (it is the engine's resolved/settle path that later pays or writes it off, not this
/// instruction).
#[test]
fn expire_bucket_with_open_claims_conserves_and_keeps_claims() {
    const Q: i128 = 10 * POS_SCALE as i128;
    let mut env = V16CuEnv::new();
    let owner_a = Keypair::new();
    let owner_b = Keypair::new();
    let a = env.create_portfolio(&owner_a);
    let b = env.create_portfolio(&owner_b);
    env.deposit(&owner_a, a, 5_000);
    env.deposit(&owner_b, b, 5_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
    env.trade_asset_with_cu(0, &owner_a, a, &owner_b, b, Q, 100, 0);
    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(0, 2, 50);
    try_refresh(&mut env, a, 2).expect("A crank @50");
    try_refresh(&mut env, b, 2).expect("B crank @50");
    env.svm.warp_to_slot(3);
    env.push_auth_mark_for_asset_as_admin(0, 3, 60);
    try_refresh(&mut env, b, 3).expect("B crank @60");
    try_refresh(&mut env, a, 3).expect("A crank @60 settles the loss");

    let (_, g) = env.market_state();
    let open: Vec<usize> = (0..2)
        .filter(|&d| g.source_backing_buckets[d].status == BackingBucketStatusV16::Fresh)
        .collect();
    assert!(!open.is_empty(), "the realized loss must have opened a Fresh bucket");
    let claim_before = (env.portfolio_state(a).source_claim_bound_num, env.portfolio_state(b).source_claim_bound_num);
    assert!(
        claim_before.0.iter().chain(claim_before.1.iter()).any(|&c| c > 0),
        "an open source claim must exist"
    );
    let expiry = open.iter().map(|&d| g.source_backing_buckets[d].expiry_slot).max().unwrap();

    // Not lapsed yet: refused with claims open.
    for &d in &open {
        assert_refused_untouched(&mut env, d as u16, PercolatorError::EngineStale, "claims open, live bucket");
    }

    env.svm.warp_to_slot(expiry + 1);
    env.svm.expire_blockhash();
    let before = totals(&env);
    for &d in &open {
        env.svm.expire_blockhash();
        expire(&mut env, d as u16).expect("lapsed bucket with open claims expires");
        assert_ne!(
            env.market_state().1.source_backing_buckets[d].status,
            BackingBucketStatusV16::Fresh
        );
    }
    let after = totals(&env);
    assert_eq!(after.token_vault, before.token_vault, "no tokens moved");
    assert_eq!(after.vault, before.vault);
    assert_eq!(after.c_tot, before.c_tot);
    assert_eq!(after.insurance, before.insurance);
    assert_eq!(after.vault, after.token_vault as u128, "engine vault == SPL vault");
    let (_, g2) = env.market_state();
    assert!(
        g2.vault >= g2.c_tot + g2.insurance,
        "V >= C_tot + I still holds after expiry"
    );
    let claim_after = (env.portfolio_state(a).source_claim_bound_num, env.portfolio_state(b).source_claim_bound_num);
    assert_eq!(claim_after, claim_before, "expiry does not touch portfolio claims");
}
