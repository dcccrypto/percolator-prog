# PERC-622: Three-Phase Oracle Transition Protocol

**Status:** Design + Kani sketch  
**Priority:** P0  
**Author:** coder  
**Date:** 2026-03-10

---

## Problem

New token markets launched on Percolator have no oracle history. Pyth and Switchboard only cover established assets. For freshly-launched SPL tokens (pump.fun, Raydium), we need a safe, self-upgrading oracle path that:

1. Opens trading immediately with conservative risk limits
2. Automatically strengthens the oracle and relaxes limits as the market matures
3. Requires **no admin action** — transitions are triggered by on-chain state
4. Is **formally verifiable** — Kani proofs enforce invariants at each phase boundary

---

## Solution: Three-Phase State Machine

```
Phase 1 (new)      Phase 2 (growing)       Phase 3 (mature)
─────────────────  ───────────────────────  ──────────────────────
0 ... 72h          72h OR $100K vol ... 14d  14d OR $1M cumul vol
OI cap: $10K       OI cap: $100K            OI cap: config.oi_cap
Max lev: 2x        Max lev: 5x              Max lev: config.max_lev
Oracle: DEX TWAP   Oracle: median(3 feeds)  Oracle: Pyth/Switchboard
```

### Phase Transitions

| Transition | Trigger Condition | Action |
|------------|-------------------|--------|
| Phase 1 → Phase 2 | `elapsed_slots ≥ PHASE2_SLOTS` OR (`elapsed_slots ≥ MIN_PHASE1_SLOTS` AND `cumulative_volume_e6 ≥ PHASE2_VOL_THRESHOLD_E6`) | Update `oracle_phase`, set `phase2_start_slot` |
| Phase 2 → Phase 3 | `elapsed_slots ≥ PHASE3_SLOTS` AND `cumulative_volume_e6 ≥ PHASE3_VOL_THRESHOLD_E6` | Update `oracle_phase`, unlock full params |

**One-way transitions only.** A market can never regress to an earlier phase.

---

## On-Chain State Changes

### New Fields in `MarketConfig`

```rust
// ========================================
// Oracle Transition Phase (PERC-622)
// ========================================
/// Current oracle phase: 0=Phase1, 1=Phase2, 2=Phase3.
/// Set once at InitMarket (0). Increments automatically on TradeNoCpi/KeeperCrank.
/// Never decremented.
pub oracle_phase: u8,
/// Padding
pub _oracle_phase_pad: [u8; 7],
/// Cumulative notional volume traded in this market (e6 units, coin-margined).
/// Updated on every trade. Saturates at u64::MAX.
/// Used to trigger Phase 2 (>= PHASE2_VOL_THRESHOLD_E6) and Phase 3 (>= PHASE3_VOL_THRESHOLD_E6).
pub cumulative_volume_e6: u64,
/// Phase 2 OI cap in collateral units (e6). 0 = use default.
/// Set at InitMarket. Keeper cannot override below minimum.
pub phase2_oi_cap_e6: u64,
/// Phase 1 OI cap in collateral units (e6). 0 = use default.
pub phase1_oi_cap_e6: u64,
```

**Impact on CONFIG_LEN:** +32 bytes. BPF: 496 → 528. Native: 512 → 544.  
Compile-time assertion must be updated.

### Constants (in `constants` module)

```rust
/// Slots per hour at ~400ms/slot = 9000 slots/hour.
pub const SLOTS_PER_HOUR: u64 = 9_000;

/// Phase 1 duration: 72 hours.
pub const PHASE2_SLOTS: u64 = 72 * SLOTS_PER_HOUR;        // 648_000

/// Phase 3 minimum elapsed time: 14 days from market creation.
pub const PHASE3_SLOTS: u64 = 14 * 24 * SLOTS_PER_HOUR;  // 3_024_000

/// Phase 2 volume trigger: $100K notional in e6 units.
/// Assuming token price ~$0.001, this ≈ 100B base units. Stored as collateral e6.
pub const PHASE2_VOL_THRESHOLD_E6: u64 = 100_000 * 1_000_000; // 100_000_000_000

/// Phase 3 volume trigger: $1M notional in e6 units.
pub const PHASE3_VOL_THRESHOLD_E6: u64 = 1_000_000 * 1_000_000; // 1_000_000_000_000

/// Phase 1 OI cap default: $10K in e6 units.
pub const PHASE1_OI_CAP_DEFAULT_E6: u64 = 10_000 * 1_000_000; // 10_000_000_000

/// Phase 2 OI cap default: $100K in e6 units.
pub const PHASE2_OI_CAP_DEFAULT_E6: u64 = 100_000 * 1_000_000; // 100_000_000_000

/// Phase 1 max leverage (2x = 50% min margin = 5_000 bps).
pub const PHASE1_MAX_LEVERAGE_MARGIN_BPS: u64 = 5_000; // 50% = 2x

/// Phase 2 max leverage (5x = 20% min margin = 2_000 bps).
pub const PHASE2_MAX_LEVERAGE_MARGIN_BPS: u64 = 2_000; // 20% = 5x

/// Minimum elapsed slots before the volume trigger can fire for Phase 1 → 2.
/// 4 hours at ~400ms/slot = 36_000 slots.
/// Prevents a wash-trader from immediately buying up to Phase 2 at market creation.
/// The time trigger (PHASE2_SLOTS = 72h) is unaffected.
pub const MIN_PHASE1_SLOTS: u64 = 4 * SLOTS_PER_HOUR; // 36_000
```

---

## Oracle Selection Per Phase

### Phase 1
- **Source:** `oracle_authority` set to a trusted admin/keeper for the DEX TWAP
- **Initialization:** At `InitMarket`, `oracle_authority` is set to the pump.fun/DEX price crank.  
  The crank pushes price via `PushOraclePrice` (tag 35). Price is the DEX TWAP over the last 60 minutes.
- **Circuit breaker:** `oracle_price_cap_e2bps` = 50_000 (5% per slot max).

### Phase 2
- **Source:** Median of up to 3 feeds:
  1. DEX TWAP (admin push via oracle_authority)
  2. Hyperp EMA (UpdateHyperpMark tag 34, on-chain DEX pool read)
  3. Switchboard feed (if `switchboard_feed` pubkey set — new optional field)
- **Transition:** At phase-2 entry, `oracle_phase` is set to 1. Trade and crank instructions
  read phase and select the median oracle path.
- **Circuit breaker:** `oracle_price_cap_e2bps` = 25_000 (2.5% per slot max, tighter).

### Phase 3
- **Source:** Full Pyth / Switchboard (`index_feed_id` non-zero) or existing hyperp EMA.
- **Transition:** At phase-3 entry, `oracle_phase` is set to 2. No further auto-progression.
- **Circuit breaker:** `oracle_price_cap_e2bps` = 10_000 (1% per slot max, tightest).

---

## Effective OI Cap Computation

```rust
pub fn effective_oi_cap_e6(config: &MarketConfig, engine: &RiskEngine, current_slot: u64) -> u64 {
    // Phase-based absolute cap
    let phase_cap = match config.oracle_phase {
        0 => if config.phase1_oi_cap_e6 > 0 { config.phase1_oi_cap_e6 } else { PHASE1_OI_CAP_DEFAULT_E6 },
        1 => if config.phase2_oi_cap_e6 > 0 { config.phase2_oi_cap_e6 } else { PHASE2_OI_CAP_DEFAULT_E6 },
        _ => u64::MAX, // Phase 3: no phase cap (existing oi_cap_multiplier_bps governs)
    };

    // Existing vault-relative cap (from oi_cap_multiplier_bps)
    let vault_relative_cap = compute_vault_oi_cap(config, engine, current_slot); // existing logic

    // Effective = min(phase_cap, vault_relative_cap)
    core::cmp::min(phase_cap, vault_relative_cap)
}
```

---

## Leverage Enforcement Per Phase

New helper `effective_min_margin_bps`:

```rust
pub fn effective_min_margin_bps(config: &MarketConfig, base_min_margin_bps: u64) -> u64 {
    match config.oracle_phase {
        0 => core::cmp::max(base_min_margin_bps, PHASE1_MAX_LEVERAGE_MARGIN_BPS), // ≥50%
        1 => core::cmp::max(base_min_margin_bps, PHASE2_MAX_LEVERAGE_MARGIN_BPS), // ≥20%
        _ => base_min_margin_bps, // Phase 3: use configured margin
    }
}
```

---

## Phase Transition Logic

Phase checks are performed at the **beginning of every trade instruction** (TradeNoCpi, TradeCpi)
and **KeeperCrank**. This is a pure read + conditional write — no CPI, no new accounts.

```rust
pub fn maybe_advance_phase(config: &mut MarketConfig, current_slot: u64) {
    let elapsed = current_slot.saturating_sub(config.market_created_slot);
    match config.oracle_phase {
        0 => {
            // Phase 1 → 2: time trigger OR (time-floor-protected) volume trigger.
            // The volume-only path requires elapsed >= MIN_PHASE1_SLOTS (4h floor) to prevent
            // a wash-trader from advancing to Phase 2 immediately at market creation.
            // See security finding: "Phase 1→2 volume-only bypass (no minimum time floor)".
            let vol_trigger_eligible = elapsed >= MIN_PHASE1_SLOTS;
            if elapsed >= PHASE2_SLOTS
                || (vol_trigger_eligible && config.cumulative_volume_e6 >= PHASE2_VOL_THRESHOLD_E6)
            {
                config.oracle_phase = 1;
                // Tighten circuit breaker on oracle price cap
                if config.oracle_price_cap_e2bps == 0 || config.oracle_price_cap_e2bps > 25_000 {
                    config.oracle_price_cap_e2bps = 25_000;
                }
            }
        }
        1 => {
            // Phase 2 → 3: time AND volume triggers (both required)
            if elapsed >= PHASE3_SLOTS && config.cumulative_volume_e6 >= PHASE3_VOL_THRESHOLD_E6 {
                config.oracle_phase = 2;
                // Tighten to mainnet-grade circuit breaker
                if config.oracle_price_cap_e2bps == 0 || config.oracle_price_cap_e2bps > 10_000 {
                    config.oracle_price_cap_e2bps = 10_000;
                }
            }
        }
        _ => {} // Phase 3: no further transitions
    }
}
```

### Volume Accumulation

In `TradeNoCpi`/`TradeCpi`, after a successful trade:

```rust
let notional_e6 = size_lots_abs.saturating_mul(config.lot_size_e6); // e6
config.cumulative_volume_e6 = config.cumulative_volume_e6.saturating_add(notional_e6);
```

---

## Kani Proof Sketch

Key invariants to prove:

### 1. Phase is monotone non-decreasing

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_oracle_phase_monotone() {
    let mut config: MarketConfig = kani::any();
    let current_slot: u64 = kani::any();
    let initial_phase = config.oracle_phase;
    kani::assume(initial_phase <= 2);

    maybe_advance_phase(&mut config, current_slot);

    assert!(config.oracle_phase >= initial_phase, "phase must never decrease");
    assert!(config.oracle_phase <= 2, "phase never exceeds 3");
}
```

### 2. OI cap is weakly non-increasing as phase advances (conservative first)

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase1_oi_cap_most_conservative() {
    let config: MarketConfig = kani::any();
    kani::assume(config.phase1_oi_cap_e6 > 0);
    kani::assume(config.phase2_oi_cap_e6 > 0);
    // Phase 1 cap ≤ Phase 2 cap
    // This is a spec invariant: we don't prove the config is "correct" but
    // we prove that if phase1_oi_cap <= phase2_oi_cap, effective cap in phase1
    // is always <= effective cap in phase2.
    kani::assume(config.phase1_oi_cap_e6 <= config.phase2_oi_cap_e6);

    let mut config_p1 = config;
    config_p1.oracle_phase = 0;
    let mut config_p2 = config;
    config_p2.oracle_phase = 1;

    // Phase 2 OI cap must be >= phase 1 cap (caps loosen as market matures)
    assert!(
        config_p2.phase2_oi_cap_e6 >= config_p1.phase1_oi_cap_e6,
        "phase 2 oi cap must be >= phase 1 cap"
    );
}
```

### 3. Leverage margin is weakly non-increasing (more leverage allowed over time)

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_leverage_loosens_with_phase() {
    let config: MarketConfig = kani::any();
    let base_margin: u64 = kani::any();
    kani::assume(base_margin <= 10_000);

    let mut config_p1 = config;
    config_p1.oracle_phase = 0;
    let mut config_p2 = config;
    config_p2.oracle_phase = 1;
    let mut config_p3 = config;
    config_p3.oracle_phase = 2;

    let margin_p1 = effective_min_margin_bps(&config_p1, base_margin);
    let margin_p2 = effective_min_margin_bps(&config_p2, base_margin);
    let margin_p3 = effective_min_margin_bps(&config_p3, base_margin);

    assert!(margin_p1 >= margin_p2, "phase 1 must be at least as conservative as phase 2");
    assert!(margin_p2 >= margin_p3, "phase 2 must be at least as conservative as phase 3");
}
```

### 4. Phase 3 is terminal (no further transitions)

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase3_terminal() {
    let mut config: MarketConfig = kani::any();
    config.oracle_phase = 2;
    let current_slot: u64 = kani::any();

    maybe_advance_phase(&mut config, current_slot);

    assert_eq!(config.oracle_phase, 2, "phase 3 is terminal");
}
```

### 5. Volume accumulation never underflows (saturating_add)

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_volume_no_overflow() {
    let initial: u64 = kani::any();
    let delta: u64 = kani::any();
    let result = initial.saturating_add(delta);
    assert!(result >= initial, "saturating add never decreases cumulative volume");
}
```

### 6. Phase transition is triggered only when conditions are met

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase1_to_phase2_correct_trigger() {
    let mut config: MarketConfig = kani::any();
    let current_slot: u64 = kani::any();
    kani::assume(config.oracle_phase == 0);
    kani::assume(config.market_created_slot <= current_slot);

    let elapsed = current_slot.saturating_sub(config.market_created_slot);
    let vol_trigger_eligible = elapsed >= MIN_PHASE1_SLOTS;
    let vol_trigger = vol_trigger_eligible && config.cumulative_volume_e6 >= PHASE2_VOL_THRESHOLD_E6;
    let time_trigger = elapsed >= PHASE2_SLOTS;

    maybe_advance_phase(&mut config, current_slot);

    if !vol_trigger && !time_trigger {
        assert_eq!(config.oracle_phase, 0, "phase 1 must not advance if no trigger");
    } else {
        assert!(config.oracle_phase >= 1, "phase must advance when trigger fires");
    }
}
```

---

## Migration & Compatibility

1. **Existing slabs (V1):** `oracle_phase` defaults to 0 on new init. Existing deployed slabs
   use `oracle_phase = 0` (field is zeroed in `Zeroable`). This means existing markets start in 
   Phase 1 behavior — but their `cumulative_volume_e6` is also 0. They will transition to Phase 2
   as soon as either 72h passes OR volume threshold is hit. This is correct and safe.

2. **CONFIG_LEN bump:** From 496 → 528 (BPF). The slab account `SLAB_LEN` calculation uses 
   `ENGINE_OFF = align_up(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN)`. All 3 slab sizes must be 
   verified to still accommodate the larger config. Need devops to redeploy programs.

3. **InitMarket change:** `phase1_oi_cap_e6` and `phase2_oi_cap_e6` become optional init params.
   If not provided, defaults to `PHASE1_OI_CAP_DEFAULT_E6` / `PHASE2_OI_CAP_DEFAULT_E6`.

---

## Instructions Affected

| Instruction | Change | Notes |
|-------------|--------|-------|
| `InitMarket` | Set `oracle_phase=0`, `cumulative_volume_e6=0`, optionally accept `phase1/2_oi_cap_e6` | Backwards compatible if params optional |
| `TradeNoCpi` | Call `maybe_advance_phase()`, accumulate volume, enforce phase OI cap + leverage | Core change |
| `TradeCpi` | Same as TradeNoCpi | Core change |
| `KeeperCrank` | Call `maybe_advance_phase()` | Passive check, no volume accumulation |
| `UpdateMarkPrice` / `UpdateHyperpMark` | No change — oracle mode selection already per-config | |
| `UpdateRiskParams` / `UpdateMarginParams` | Consider: block OI cap relaxation below phase minimum? | Optional guardrail |

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Volume gaming (wash trades to skip Phase 1) | Volume trigger requires `elapsed ≥ MIN_PHASE1_SLOTS` (4h floor) AND $100K notional. Even after 4h, Phase 2 OI cap is $100K — the wash-trade cost exceeds the marginal leverage gain. Time trigger (72h) is the primary path. |
| Oracle manipulation in Phase 1 | Admin oracle authority is trusted (keeper-controlled). Circuit breaker at 5%/slot prevents flash oracle attacks. |
| Frozen markets (volume never reaches threshold) | Time trigger is primary: 72h always triggers Phase 2 regardless of volume. |
| CONFIG_LEN increase breaks existing slabs | Slabs are fixed-size accounts. SLAB_LEN must be checked: all 3 tiers (65KB / 257KB / 1MB) are large enough to absorb 32 bytes of config growth. |

---

## Implementation Plan

1. **[This PR]** Design doc + Kani sketch + constant stubs ← current  
2. **PR 2:** Add fields to `MarketConfig`, update CONFIG_LEN assert, update slab size check  
3. **PR 3:** Implement `maybe_advance_phase()`, `effective_oi_cap_e6()`, `effective_min_margin_bps()`  
4. **PR 4:** Wire into `TradeNoCpi`, `TradeCpi`, `KeeperCrank`  
5. **PR 5:** Implement Kani harnesses (full proofs, not sketches)  
6. **PR 6:** Migration + devnet deployment
