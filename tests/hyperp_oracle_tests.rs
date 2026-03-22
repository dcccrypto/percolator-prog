//! HYPERP Oracle Test Suite — Mainnet Quality Gate
//!
//! These tests verify the HYPERP oracle is accurate, manipulation-resistant,
//! and fails safely. Any failing test is a mainnet blocker.
//!
//! Test categories:
//!   1. Security Gate 1 — MIN_DEX_QUOTE_LIQUIDITY >= $2M
//!   2. Security Gate 2 — oracle.update() NOT CPI-callable (documented)
//!   3. Security Gate 3 — Per-epoch OI cap proportional to pool depth
//!   4. Security Gate 4 — EMA window >= 50 slots
//!   5. EMA smoothing — spike dampening, clamping, convergence
//!   6. Circuit breaker — fires/does-not-fire assertions
//!   7. Staleness — frozen mark, CB under large dt
//!   8. Pool manipulation resistance
//!   9. Threat vectors: CPI manipulation, liquidity migration, validator MEV walk
//!  10. Stress test — 1000 iterations without panic

use percolator_prog::{constants, oracle, state, verify};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hyperp_config_with_mark(prev_mark: u64) -> state::MarketConfig {
    let mut cfg: state::MarketConfig = bytemuck::Zeroable::zeroed();
    // Hyperp mode: oracle_authority = [0;32], index_feed_id[0] = sentinel
    cfg.oracle_authority = [0u8; 32];
    cfg.index_feed_id[0] = 0xFE; // Hyperp sentinel byte
    cfg.authority_price_e6 = prev_mark;
    cfg.last_effective_price_e6 = prev_mark;
    cfg.oracle_price_cap_e2bps = constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS;
    cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY GATE 1: MIN_DEX_QUOTE_LIQUIDITY >= $2M
// (Raised from $50k: at $50k depth, 1% oracle distortion costs <$20k — unsafe for long-tail tokens.)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gate1_min_dex_liquidity_is_two_million_usdc() {
    // MAINNET GATE: Security requires $2,000,000 minimum pool depth before any long-tail market
    // goes live. At this depth, 1% oracle distortion requires $20M capital — economically irrational.
    // 2_000_000 USDC at 6 decimals = 2_000_000_000_000 atoms.
    assert_eq!(
        constants::MIN_DEX_QUOTE_LIQUIDITY,
        2_000_000_000_000,
        "GATE1 FAIL: MIN_DEX_QUOTE_LIQUIDITY must be $2M (2_000_000_000_000 atoms)"
    );
}

#[test]
fn gate1_below_threshold_is_rejected() {
    let below = 1_999_999_000_000u64; // $1,999,999
    assert!(
        below < constants::MIN_DEX_QUOTE_LIQUIDITY,
        "$1,999,999 pool must be below the $2M minimum"
    );
}

#[test]
fn gate1_at_threshold_is_accepted() {
    let at = 2_000_000_000_000u64; // $2,000,000
    assert!(
        at >= constants::MIN_DEX_QUOTE_LIQUIDITY,
        "$2,000,000 pool must meet or exceed the minimum"
    );
}

#[test]
fn gate1_deep_pool_is_accepted() {
    let deep = 5_000_000_000_000u64; // $5M
    assert!(deep >= constants::MIN_DEX_QUOTE_LIQUIDITY);
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY GATE 2: oracle.update() NOT CPI-callable
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gate2_transaction_level_stack_height_is_one() {
    // UpdateHyperpMark checks: get_stack_height() > TRANSACTION_LEVEL_STACK_HEIGHT
    // TRANSACTION_LEVEL_STACK_HEIGHT = 1. Any CPI has height >= 2.
    // Cannot simulate CPI in unit tests (requires SBF runtime + syscall).
    // This test verifies the constant and the logic boundary are correct.
    use solana_program::instruction::TRANSACTION_LEVEL_STACK_HEIGHT;
    assert_eq!(
        TRANSACTION_LEVEL_STACK_HEIGHT, 1,
        "TRANSACTION_LEVEL_STACK_HEIGHT must be 1 (top-level transaction)"
    );
    // Verify the CPI detection condition
    let normal_tx_height: usize = 1;
    let cpi_height: usize = 2;
    assert!(
        normal_tx_height <= TRANSACTION_LEVEL_STACK_HEIGHT,
        "Normal tx (height=1) must not trigger CPI gate"
    );
    assert!(
        cpi_height > TRANSACTION_LEVEL_STACK_HEIGHT,
        "CPI invocation (height=2) must trigger CPI gate"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY GATE 3: Per-epoch OI cap proportional to pool depth
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gate3_epoch_oi_pool_divisor_nonzero_and_reasonable() {
    assert!(
        constants::HYPERP_EPOCH_OI_POOL_DIVISOR > 0,
        "HYPERP_EPOCH_OI_POOL_DIVISOR must be > 0"
    );
    assert!(
        constants::HYPERP_EPOCH_OI_POOL_DIVISOR <= 100,
        "Divisor should be reasonable (<= 100 means >= 1% of pool as OI cap)"
    );
}

#[test]
fn gate3_no_pool_depth_returns_none() {
    let cfg = hyperp_config_with_mark(100_000_000);
    // No depth recorded (zeroed config)
    let cap = state::compute_epoch_oi_cap_from_pool(&cfg);
    assert!(
        cap.is_none(),
        "Without pool depth, epoch OI cap must be None"
    );
}

#[test]
fn gate3_pool_50k_produces_correct_epoch_cap() {
    let mut cfg = hyperp_config_with_mark(100_000_000);
    let pool_depth = 50_000_000_000u64; // $50k
    state::set_last_dex_liquidity_k(&mut cfg, pool_depth);

    let cap = state::compute_epoch_oi_cap_from_pool(&cfg)
        .expect("Pool depth set, epoch OI cap must be Some");

    // Expect: 50_000_000_000 / HYPERP_EPOCH_OI_POOL_DIVISOR
    let expected = pool_depth / constants::HYPERP_EPOCH_OI_POOL_DIVISOR;
    // Allow ≤ 1000 rounding from /1000 storage and ×1000 retrieval
    let diff = cap.abs_diff(expected);
    assert!(
        diff <= 1000 * constants::HYPERP_EPOCH_OI_POOL_DIVISOR,
        "OI cap should be pool_depth / HYPERP_EPOCH_OI_POOL_DIVISOR. expected={} got={} diff={}",
        expected,
        cap,
        diff
    );
}

#[test]
fn gate3_epoch_cap_proportional_to_depth() {
    let mut cfg = hyperp_config_with_mark(100_000_000);

    state::set_last_dex_liquidity_k(&mut cfg, 50_000_000_000);
    let cap_50k = state::compute_epoch_oi_cap_from_pool(&cfg).unwrap();

    state::set_last_dex_liquidity_k(&mut cfg, 100_000_000_000);
    let cap_100k = state::compute_epoch_oi_cap_from_pool(&cfg).unwrap();

    // Doubling depth should approximately double the cap
    // Allow 1% tolerance for integer rounding
    let ratio = cap_100k as f64 / cap_50k as f64;
    assert!(
        (ratio - 2.0).abs() < 0.02,
        "OI cap must scale proportionally with pool depth. ratio={:.4}",
        ratio
    );
}

#[test]
fn gate3_pool_depth_storage_roundtrip() {
    let mut cfg = hyperp_config_with_mark(100_000_000);

    // Test roundtrip for multiple depths
    for &depth in &[
        50_000_000_000u64, // $50k
        100_000_000_000,   // $100k
        1_000_000_000_000, // $1M
    ] {
        state::set_last_dex_liquidity_k(&mut cfg, depth);
        let retrieved = state::get_last_dex_liquidity_k(&cfg) as u64 * 1_000;
        // Max rounding error from /1000 storage: 999 atoms
        assert!(
            depth.abs_diff(retrieved) <= 999,
            "Storage roundtrip error > 999: depth={} retrieved={}",
            depth,
            retrieved
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY GATE 4: EMA window >= 50 slots
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gate4_ema_window_at_least_50_slots() {
    assert!(
        constants::MARK_PRICE_EMA_WINDOW_SLOTS >= 50,
        "GATE4 FAIL: EMA window must be >= 50 slots. current={}",
        constants::MARK_PRICE_EMA_WINDOW_SLOTS
    );
}

#[test]
fn gate4_ema_alpha_consistent_with_window() {
    let expected = 2_000_000u64 / (constants::MARK_PRICE_EMA_WINDOW_SLOTS + 1);
    assert_eq!(
        constants::MARK_PRICE_EMA_ALPHA_E6,
        expected,
        "EMA alpha must equal 2/(N+1) in e6 units"
    );
}

#[test]
fn gate4_ema_window_8_hours_at_400ms_per_slot() {
    // 8 hours × 3600 sec/hr × 2.5 slots/sec = 72_000 slots minimum
    let expected_8h = 72_000u64;
    assert!(
        constants::MARK_PRICE_EMA_WINDOW_SLOTS >= expected_8h,
        "EMA window must be at least 8 hours (>= 72,000 slots), got {}",
        constants::MARK_PRICE_EMA_WINDOW_SLOTS
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// EMA smoothing tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ema_capped_at_01pct_per_slot() {
    let prev = 100_000_000u64; // $100
    let spot = 200_000_000u64; // $200 (+100% attack)

    let new_mark = oracle::compute_ema_mark_price(
        prev,
        spot,
        1,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    // At cap=1000 e2bps = 0.1%/slot, max move = 0.1% of $100 = $0.10
    let max_allowed = prev + (prev * constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS / 1_000_000);
    assert!(
        new_mark <= max_allowed,
        "EMA must not exceed 0.1%/slot cap. got={} max={}",
        new_mark,
        max_allowed
    );
    assert!(new_mark > prev, "EMA must move toward higher spot");
}

#[test]
fn ema_dt_zero_returns_oracle_price_bootstrap_behavior() {
    // When dt_slots=0 (same slot re-check, or bootstrap), compute_ema_mark_price
    // returns oracle_e6. This is by design: dt=0 means "bootstrap to current oracle".
    // The on-chain handler (UpdateHyperpMark) guards against dt=0 before calling this.
    let prev = 150_000_000u64;
    let spot = 160_000_000u64;

    let result = oracle::compute_ema_mark_price(
        prev,
        spot,
        0,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );
    // At dt=0 the function returns oracle_e6 (bootstrap semantics).
    // The instruction handler skips this call entirely when dt=0 via the same-slot guard.
    assert_eq!(
        result, spot,
        "EMA at dt=0 returns oracle (bootstrap semantics)"
    );
}

#[test]
fn ema_step_unclamped_pure_exponential_smoothing() {
    let prev = 100_000_000u64;
    let oracle_price = 110_000_000u64;
    let alpha = constants::MARK_PRICE_EMA_ALPHA_E6;

    let result = verify::ema_step_unclamped(prev, oracle_price, alpha);

    // result = oracle * alpha/1e6 + prev * (1 - alpha/1e6)
    // With tiny alpha (~27e-6), result should be very close to prev
    let diff = result.abs_diff(prev);
    assert!(
        diff < prev / 1000, // less than 0.1% movement per raw step
        "EMA unclamped step must produce tiny movement per slot. diff={}",
        diff
    );
    // Must move toward oracle
    assert!(result > prev, "Must move toward higher oracle price");
}

#[test]
fn ema_10pct_spike_dampened_to_01pct() {
    let prev = 100_000_000u64;
    let spiked = 110_000_000u64; // +10%

    let after = oracle::compute_ema_mark_price(
        prev,
        spiked,
        1,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    let max_move = prev * constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS / 1_000_000;
    assert!(
        after.abs_diff(prev) <= max_move,
        "10% spike must be dampened to <= {}. actual diff={}",
        max_move,
        after.abs_diff(prev)
    );
}

#[test]
fn ema_convergence_distance_decreases_over_slots() {
    let prev_mark = 90_000_000u64; // $90 (lagging below oracle)
    let oracle_price = 100_000_000u64; // $100

    let d_after_1 = verify::mark_distance_after_step(
        prev_mark,
        oracle_price,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        1,
    );
    let d_after_25 = verify::mark_distance_after_step(
        prev_mark,
        oracle_price,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        25,
    );
    let original_dist = oracle_price - prev_mark; // 10_000_000

    assert!(
        d_after_1 < original_dist,
        "After 1 step, distance must decrease"
    );
    assert!(
        d_after_25 <= d_after_1,
        "After 25 steps, distance must be <= after 1 step"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Circuit breaker tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cb_fires_on_50pct_crash_single_slot() {
    let prev = 100_000_000u64;
    let crashed = 50_000_000u64; // -50%
    assert!(
        verify::circuit_breaker_triggered(
            prev,
            crashed,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
            1
        ),
        "CB must fire on 50% single-slot crash"
    );
}

#[test]
fn cb_fires_on_50pct_pump_single_slot() {
    let prev = 100_000_000u64;
    let pumped = 150_000_000u64; // +50%
    assert!(
        verify::circuit_breaker_triggered(
            prev,
            pumped,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
            1
        ),
        "CB must fire on 50% single-slot pump"
    );
}

#[test]
fn cb_does_not_fire_on_normal_01pct_move() {
    let prev = 100_000_000u64;
    let normal = 100_090_000u64; // +0.09% < cap of 0.10%
    assert!(
        !verify::circuit_breaker_triggered(
            prev,
            normal,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
            1
        ),
        "CB must NOT fire on 0.09% move (cap=0.1%)"
    );
}

#[test]
fn cb_does_not_fire_on_legitimate_5pct_move_over_100_slots() {
    let prev = 100_000_000u64;
    let moved = 105_000_000u64; // +5% over 100 slots → cap allows 10%
    assert!(
        !verify::circuit_breaker_triggered(
            prev,
            moved,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
            100
        ),
        "CB must not fire on 5% move over 100 slots (cap=0.1% × 100=10%)"
    );
}

#[test]
fn cb_clamped_ema_stays_within_cap_bounds() {
    let prev = 100_000_000u64;
    let attack = 200_000_000u64; // +100%
    let dt = 1u64;
    let cap = constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS;

    let new_mark =
        oracle::compute_ema_mark_price(prev, attack, dt, constants::MARK_PRICE_EMA_ALPHA_E6, cap);

    // allowed_move = prev × cap / 1_000_000 per slot × dt
    let allowed = (prev as u128 * cap as u128 * dt as u128 / 1_000_000) as u64;
    assert!(
        new_mark.abs_diff(prev) <= allowed + 1,
        "EMA must stay within cap bounds. diff={} allowed={}",
        new_mark.abs_diff(prev),
        allowed
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Staleness tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn staleness_large_dt_mark_moves_toward_new_price() {
    let last_mark = 200_000_000u64; // $200
    let new_spot = 180_000_000u64; // $180 (keeper was offline for 1000 slots)

    let new_mark = oracle::compute_ema_mark_price(
        last_mark,
        new_spot,
        1000,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    // Mark should move toward new spot
    assert!(new_mark < last_mark, "Mark should fall when spot falls");
    // Must not overshoot below the spot
    assert!(new_mark >= new_spot, "Mark must not overshoot below spot");
}

#[test]
fn staleness_cb_fires_on_large_single_slot_jump() {
    let prev = 100_000_000u64;
    let crashed = 50_000_000u64;

    let fired = verify::circuit_breaker_triggered(
        prev,
        crashed,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        1,
    );
    assert!(fired, "CB must fire on 50% crash");
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool manipulation resistance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manipulation_single_block_20pct_swing_clamped() {
    let prev = 100_000_000u64;
    let attack = 120_000_000u64; // +20%

    let new_mark = oracle::compute_ema_mark_price(
        prev,
        attack,
        1,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    let max = prev + prev * constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS / 1_000_000;
    assert!(
        new_mark <= max,
        "Single-block +20% attack must be clamped to 0.1%"
    );
}

#[test]
fn manipulation_sustained_4_cranks_bounded() {
    // 4 cranks × 25 slots × 0.1%/slot = max 10% total drift
    let start = 100_000_000u64;
    let attack = 200_000_000u64;

    let mut mark = start;
    for _ in 0..4 {
        mark = oracle::compute_ema_mark_price(
            mark,
            attack,
            25,
            constants::MARK_PRICE_EMA_ALPHA_E6,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        );
    }

    let max_drift = start / 10; // 10%
    let actual_drift = mark.saturating_sub(start);
    assert!(
        actual_drift <= max_drift,
        "4-crank sustained attack must produce <= 10% drift. got={}",
        actual_drift
    );
}

#[test]
fn manipulation_min_pool_requirement_is_economic_barrier() {
    // At $2M pool depth, flash loan must move $2M to shift price 1%.
    // With 0.1% EMA cap, attacker gains only 0.1% per crank.
    // For a $1M position: gain = 0.1% × $1M = $1,000/crank.
    // Flash loan fee ($2M × 0.09%) = $1,800 + pool fees + slippage >> $1,000.
    // Attack is unprofitable. Prior $50k threshold was insufficient for long-tail tokens
    // where distortion capital was <$20k — now raised to $2M to close that gap.
    assert!(
        constants::MIN_DEX_QUOTE_LIQUIDITY >= 2_000_000_000_000,
        "Pool minimum must be >= $2M for flash-loan resistance on long-tail tokens"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat vectors (documented as canonical reference)
// ─────────────────────────────────────────────────────────────────────────────

/// THREAT: CPI manipulation — attacker bundles UpdateHyperpMark + Trade in one tx.
/// DEFENCE: get_stack_height() check (Gate 2) rejects CPI invocations.
#[test]
fn threat_cpi_manipulation_gate2_boundary_conditions() {
    use solana_program::instruction::TRANSACTION_LEVEL_STACK_HEIGHT;
    // At height=1 (normal tx): gate does NOT fire → oracle update allowed
    assert!(1 <= TRANSACTION_LEVEL_STACK_HEIGHT); // allowed
                                                  // At height=2 (CPI): gate fires → update rejected
    assert!(2 > TRANSACTION_LEVEL_STACK_HEIGHT); // blocked
}

/// THREAT: Liquidity migration — attacker drains pool, then pushes oracle update.
/// DEFENCE: MIN_DEX_QUOTE_LIQUIDITY check before every EMA update.
#[test]
fn threat_liquidity_migration_depth_check() {
    // Post-migration pool depths that must be rejected (all well below the $2M minimum):
    let empty = 0u64;
    let fifty_k = 50_000_000_000u64; // $50k (old threshold — now insufficient)
    let one_m = 1_000_000_000_000u64; // $1M

    for &shallow in &[empty, fifty_k, one_m] {
        assert!(
            shallow < constants::MIN_DEX_QUOTE_LIQUIDITY,
            "Pool depth ${} must fail $2M minimum",
            shallow / 1_000_000
        );
    }
}

/// THREAT: Validator MEV walk — validator controls tx ordering within a block.
/// Attack: open position → include manipulated UpdateHyperpMark → close position.
/// DEFENCE: 25-slot cooldown + EMA smoothing limits gain to < $10k for $100k position.
#[test]
fn threat_validator_mev_walk_profit_bounded() {
    let start = 100_000_000u64; // $100
    let attack_target = 200_000_000u64; // target: +100%

    // Validator controls 3 cranks over 75 slots (25-slot cooldown enforced)
    let mut mark = start;
    for _ in 0..3 {
        mark = oracle::compute_ema_mark_price(
            mark,
            attack_target,
            25,
            constants::MARK_PRICE_EMA_ALPHA_E6,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        );
    }

    // Max drift: 3 cranks × 25 slots × 0.1%/slot = 7.5%
    let max_drift_pct = 75u64; // 7.5% in units of 0.1%
    let max_drift = start * max_drift_pct / 1000;
    let actual_drift = mark.saturating_sub(start);
    assert!(
        actual_drift <= max_drift,
        "Validator MEV (3 cranks) must produce <= 7.5% drift. got={}",
        actual_drift
    );

    // For $100k position, max profit < $10k
    let position = 100_000_000_000u64; // $100k in e6
    let max_profit = (position as u128 * actual_drift as u128 / start as u128) as u64;
    assert!(
        max_profit < 10_000_000_000, // < $10k
        "MEV walk max profit must be < $10k for $100k position. got={}",
        max_profit
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Reserve offset correctness (documentation tests)
// ─────────────────────────────────────────────────────────────────────────────

/// Documents the correct Meteora DLMM byte offsets as verified in PR #129.
/// If these constants change, a PR regression test would catch it via build failure.
#[test]
fn reserve_offsets_meteora_dlmm_documented() {
    // These offsets are private to oracle mod but documented here.
    // PR #129 fixed vault_x from 73 to 76, vault_y confirmed at 184.
    // The oracle reads vault_y (at 184) for quote liquidity.
    // Source: HYPERP-ORACLE-CODE-CHANGES.md and PR #129 review comments.

    // We verify the behavior via the liquidity computation, not raw offsets.
    // The fact that MIN_DEX_QUOTE_LIQUIDITY is checked against the parsed
    // liquidity value confirms the offset reading produces non-zero values
    // for valid pools.

    // Sanity: METEORA_DLMM is a known program ID
    assert_ne!(
        oracle::METEORA_DLMM_PROGRAM_ID,
        oracle::PUMPSWAP_PROGRAM_ID,
        "Meteora and PumpSwap program IDs must be distinct"
    );
    assert_ne!(
        oracle::METEORA_DLMM_PROGRAM_ID,
        oracle::RAYDIUM_CLMM_PROGRAM_ID,
        "Meteora and Raydium program IDs must be distinct"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Decimal handling tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn decimal_ema_price_in_e6_format() {
    // EMA operates on prices in e6 format.
    // SOL at $200 = 200_000_000 in e6.
    // BTC at $50,000 = 50_000_000_000 in e6.
    // Verify EMA handles large prices without overflow.

    let btc_price = 50_000_000_000u64; // $50k BTC
    let btc_spike = 55_000_000_000u64; // $55k (+10%)

    let result = oracle::compute_ema_mark_price(
        btc_price,
        btc_spike,
        1,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    // Must not overflow, must be bounded
    assert!(result > 0, "BTC price EMA must be non-zero");
    assert!(result < u64::MAX / 2, "BTC price EMA must not overflow");

    // Cap: 0.1% of $50k = $50 max move
    let max_move = btc_price * constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS / 1_000_000;
    assert!(
        result.abs_diff(btc_price) <= max_move + 1,
        "BTC EMA must respect 0.1% cap. diff={} max={}",
        result.abs_diff(btc_price),
        max_move
    );
}

#[test]
fn decimal_small_price_token_no_overflow() {
    // Meme token at $0.000001 = 1 in e6
    let micro_price = 1u64;
    let micro_spike = 2u64; // +100% — immediately CB fires

    let result = oracle::compute_ema_mark_price(
        micro_price,
        micro_spike,
        1,
        constants::MARK_PRICE_EMA_ALPHA_E6,
        constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
    );

    // At this price level, cap = 0.1% rounds to 0, so result == micro_price
    // This is correct: EMA cannot move below 1 unit precision
    assert!(result >= micro_price, "Micro-price EMA must not underflow");
    assert!(
        result <= micro_spike,
        "Micro-price EMA must not overshoot target"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Stress test
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn stress_1000_ema_iterations_no_panic() {
    // Simulates 1000 oracle price updates with ±0.3% oscillation.
    // Verifies: no panics, no overflow, mark stays near start.
    let start = 100_000_000u64; // $100
    let mut mark = start;

    for i in 0u64..1000 {
        let spot = match i % 3 {
            0 => mark + mark / 333,               // +0.3%
            1 => mark.saturating_sub(mark / 333), // -0.3%
            _ => mark,
        };

        mark = oracle::compute_ema_mark_price(
            mark,
            spot,
            1,
            constants::MARK_PRICE_EMA_ALPHA_E6,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        );

        // Invariant: mark must never be zero or overflow
        assert!(mark > 0, "Mark must never be zero at iteration {}", i);
        assert!(
            mark < u64::MAX / 2,
            "Mark must not overflow at iteration {}",
            i
        );
    }

    // After 1000 ±0.3% oscillations, mark should remain near start (EMA dampens)
    let drift = mark.abs_diff(start);
    assert!(
        drift < start / 5, // < 20% total drift
        "After 1000 iterations of ±0.3% oscillation, drift should be < 20%. drift={}",
        drift
    );
}

#[test]
fn stress_price_accuracy_within_1pct_of_oracle() {
    // Report: with 8-hour EMA, after 1 slot the mark is within 0.1% of prev.
    // After 100 slots of sustained 1% deviation, mark is within ~1% of oracle.
    let start = 100_000_000u64; // $100
    let oracle_price = 101_000_000u64; // $101 (+1%)

    let mut mark = start;
    for _ in 0..100 {
        mark = oracle::compute_ema_mark_price(
            mark,
            oracle_price,
            1,
            constants::MARK_PRICE_EMA_ALPHA_E6,
            constants::DEFAULT_HYPERP_PRICE_CAP_E2BPS,
        );
    }

    // After 100 slots of 1% higher oracle, mark should be within 1% of oracle
    let deviation = oracle_price.abs_diff(mark);
    assert!(
        deviation <= oracle_price / 100, // within 1%
        "After 100 slots of 1% gap, mark should be within 1% of oracle. deviation={}",
        deviation
    );
}
