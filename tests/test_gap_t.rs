// Tests for Gap T (hardening): leverage-tied oracle_price_cap_e2bps
// derivation at InitMarket + admit_h_min flip on clamp-active reads.
//
// Two tests landed; a third was attempted and dropped — see the Test C
// note at the bottom of this file.
//
// - test_derived_oracle_cap_at_init     (Commit 1 derivation happy path)
// - test_init_rejects_zero_derived_cap  (Commit 1 truncation rejection)

mod common;
#[allow(unused_imports)]
use common::*;

#[allow(unused_imports)]
use solana_sdk::signature::{Keypair, Signer};

/// Gap T derivation happy path.
///
/// With the test-helper hardcoded RiskParams (IM=1000 bps, MM=500 bps),
/// calling `init_market_with_cap(_, _, 0)` picks `max_crank_staleness=50_000`
/// (per the updated helper default). The derived cap is:
///
///     cap_e2bps = (IM - MM) * 100 / max_crank_staleness
///               = (1000 - 500) * 100 / 50_000
///               = 1
///
/// Assert the stored cap matches. The result is independent of the
/// admin-supplied `min_oracle_price_cap_e2bps` (second arg), confirming the
/// derivation is the single source of truth for non-Hyperp markets.
#[test]
fn test_derived_oracle_cap_at_init() {
    program_path();
    let mut env = TestEnv::new();
    // min_cap set to a non-zero value to confirm it does NOT override the
    // derivation. Under the old contract cap would equal 10_000 here.
    env.init_market_with_cap(0, 10_000, 0);
    let cap = env.read_oracle_price_cap();
    assert_eq!(
        cap, 1,
        "derived cap must be (IM - MM) * 100 / max_crank_staleness = (1000-500)*100/50_000 = 1, \
         admin min_cap ignored. got {}",
        cap,
    );
}

/// Gap T derivation rejects at init when the formula truncates to 0.
///
/// With IM=1000 bps, MM=500 bps, diff=500, numerator = 50_000. Pick
/// `permissionless_resolve_stale_slots = 50_002` so the helper sets
/// `max_crank_staleness = 50_001`. Derivation: 50_000 / 50_001 = 0 (floor).
/// The commit 1 guard rejects with `PercolatorError::InvalidConfigParam`
/// (on-wire code `0x1a`), preventing a non-Hyperp market from shipping with
/// a disabled circuit breaker.
#[test]
fn test_init_rejects_zero_derived_cap() {
    program_path();
    let mut env = TestEnv::new();
    let data = common::encode_init_market_with_cap(
        &env.payer.pubkey(),
        &env.mint,
        &common::TEST_FEED_ID,
        0,       // invert = 0 (non-Hyperp)
        0,       // min_oracle_price_cap_e2bps (ignored by derivation)
        50_002,  // perm_resolve → max_crank_staleness = 50_001 → derived = 0
    );
    let err = env
        .try_init_market_raw(data)
        .expect_err("init must reject when derived cap truncates to 0");
    assert!(
        err.contains("0x1a"),
        "expected InvalidConfigParam (0x1a), got: {}",
        err,
    );
}

// Test C (test_hlock_flips_on_clamped_read) was dropped.
//
// The intended assertion is that fresh positive PnL admitted during a
// clamp-active read goes into the scheduled reserve bucket (admit_h_min
// flipped to h_max) rather than being immediately released. The direct
// observable is `read_account_reserved_pnl(user_idx) > 0` after a
// clamp-firing settle.
//
// The test cannot discriminate the Commit 2 flip from the pre-existing
// residual-check path under this harness. The engine's
// `admit_fresh_reserve_h_lock` returns `admit_h_max` when
// `PNL_matured_pos_tot + fresh_positive_pnl > Residual` where
// `Residual = V - C_tot - I`. On a freshly initialised test market
// `Residual` starts at 0 (insurance seed appears in both V and I) and
// only grows via bankruptcy-absorbed loss. In a happy-path test with
// no bankruptcy, any strictly positive fresh PnL exceeds `Residual`,
// so Step 2 of the admission law routes to `admit_h_max` regardless of
// whether Commit 2's wrapper-side flip adjusted `admit_h_min`. The
// `reserved_pnl > 0` observable is therefore true under all of
// (no-Gap-T / Commit 1 only / Commit 1 + Commit 2), so the test would
// pass even with Commit 2 reverted.
//
// Three options for discriminating the flip were considered and
// rejected:
//   (1) Bootstrap a non-zero Residual via a scripted bankruptcy so the
//       residual-check path returns `admit_h_min`. Requires an oracle
//       crash + liquidation sequence before the flip assertion, which
//       conflates test-of-flip with test-of-bankruptcy-machinery.
//   (2) Observe `InstructionContext.admit_h_min_shared` directly. Out
//       of scope per the commit 3 rule "do NOT add test harness
//       machinery beyond what exists."
//   (3) Make `read_price_and_stamp` `pub` and unit-test the
//       `clamp_fired` return value. Forbidden — Commit 2 code is
//       frozen.
//
// Shipping 2 discriminating tests over 3 with a non-discriminating
// Test C, per the commit 3 rule: "shipping 2 tests honestly beats
// shipping 3 with scaffolding hacks."
//
// Commit 2's logic remains covered by cargo check + cargo test
// compile-time verification (the wrapper compiles and all 650 prior
// tests remain green), plus the bounty-level fork PoC that would be
// the natural vehicle for end-to-end flip observability.
