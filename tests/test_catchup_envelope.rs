mod common;
#[allow(unused_imports)]
use common::*;

/// Regression for spec §5.5 envelope coverage gap: with zero funding,
/// live OI on both sides, long idle, and a fresh oracle price different
/// from `last_oracle_price`, the engine's §5.5 clause-6 gate fires on
/// `price_move_active` regardless of whether funding is active. The
/// wrapper's `catchup_accrue` helper must therefore chunk in this case
/// too, not skip solely because `funding_rate == 0`.
///
/// This test sets up a market with `funding_max_e9_per_slot = 0` (so
/// `compute_current_funding_rate_e9` always returns 0), creates live OI
/// via a trade, idles for > `max_accrual_dt_slots` with a price change,
/// and cranks. Under the pre-fix code, the crank's own
/// `accrue_market_to` would return `EngineOverflow` because `catchup_accrue`
/// returned early on `!funding_active`, leaving a too-large dt for the
/// main call. Under the fix, `price_move_active` also triggers chunking,
/// so the engine advances legally.
#[test]
fn test_catchup_accrue_covers_price_move_with_zero_funding() {
    program_path();
    let mut env = TestEnv::new();

    // Zero-funding market (funding_max_e9_per_slot = 0 → rate always 0).
    // perm_resolve=10_000 is large enough that our 1500-slot idle does
    // not trip the stale gate. horizon=500, k=100, premium=500 all
    // unused because funding_max_e9=0 pins the rate at 0.
    env.init_market_with_funding(0, 10_000, 500, 100, 500, 0);

    // Seed engine state and establish live OI. init_lp/init_user
    // airdrop internally.
    let lp_kp = solana_sdk::signature::Keypair::new();
    let user_kp = solana_sdk::signature::Keypair::new();
    let lp_idx = env.init_lp(&lp_kp);
    let user_idx = env.init_user(&user_kp);
    env.deposit(&lp_kp, lp_idx, 1_000_000_000);
    env.deposit(&user_kp, user_idx, 1_000_000_000);

    // Trade to create OI on both sides.
    env.trade(&user_kp, &lp_kp, lp_idx, user_idx, 1_000_000);

    // Idle far past `max_accrual_dt_slots = 100` (wrapper constant).
    // Use the raw setter to avoid the walker's interleaved cranks —
    // we want a genuine engine-vs-clock gap. 50_000 slots < CATCHUP_
    // CHUNKS_MAX × max_dt = 20 × 100 = 2000, so this exceeds the
    // in-line cap too — but the fix's price-walk loop converges in
    // ≤ ~40 geometric chunks, and for a 1%-ish move in a few dozen
    // slots a single chunk suffices.
    //
    // Scope down to 1500 slots: > max_dt (100) but well under the
    // in-line cap (2000) and short enough that perm_resolve delays
    // (if any) don't trip.
    let current_px = env.read_oracle_price_e6();
    // 1% price move — exactly 100 bps, well within cap_bps=4 *
    // max_dt=100 = 400 bps-worth of movement at dt=max_dt.
    let new_px = current_px + current_px / 100;
    env.set_slot_and_price_raw_no_walk(1500, new_px);

    // Pre-fix: this crank fails with EngineOverflow because the
    // wrapper's catchup_accrue returned Ok early (funding_rate=0), and
    // the subsequent accrue_market_to saw dt=1500 > max_dt=100 with
    // price_move_active=true → §5.5 clause 6 Overflow.
    //
    // Post-fix: catchup_accrue detects price_move_active, chunks the
    // gap at max_dt steps walking the price toward fresh, and the
    // final residual call succeeds.
    env.crank();

    // If we got here, the fix worked. Sanity: engine not stuck.
    env.crank();
}

/// Companion check: zero-funding + zero-OI + long idle must still be a
/// fast-forward (no chunking needed). Covers the case where neither
/// driver is active and `catchup_accrue` should return Ok immediately.
#[test]
fn test_catchup_accrue_skips_when_no_driver() {
    program_path();
    let mut env = TestEnv::new();
    env.init_market_with_funding(0, 100_000, 500, 100, 500, 0);
    env.crank(); // seed engine

    // No OI. Idle and change price — but stay within perm_resolve to
    // avoid tripping the stale-oracle gate.
    let current_px = env.read_oracle_price_e6();
    env.set_slot_and_price_raw_no_walk(50_000, current_px + current_px / 100);

    // With no OI, price_move_active=false and funding_active=false.
    // Engine must accept any dt in one call. Wrapper must not chunk.
    env.crank();
}

/// Read oracle price via the public interface.
trait OraclePriceProbe {
    fn read_oracle_price_e6(&self) -> i64;
}
impl OraclePriceProbe for TestEnv {
    fn read_oracle_price_e6(&self) -> i64 {
        // Mirrors the private helper in common/mod.rs. Pyth mock layout
        // writes price at bytes [73..81] as little-endian i64.
        let d = self.svm.get_account(&self.pyth_index).unwrap().data;
        i64::from_le_bytes(d[73..81].try_into().unwrap())
    }
}
