# PERC-622: Three-Phase Oracle Transition Protocol

## Summary

Automatic, on-chain, admin-keyless oracle quality graduation for new permissionless token markets. Markets start with conservative oracle/risk parameters and automatically unlock higher leverage and OI caps as they prove oracle quality through time and volume milestones.

## Problem

Permissionless market creation means any SPL token can get a perp market. New tokens have unreliable oracle sources (low DEX liquidity, no Pyth/Switchboard feed). We need a graduated system that:

1. Protects LPs from manipulation during early low-liquidity phase
2. Automatically relaxes constraints as oracle quality improves
3. Requires zero admin keys — all transitions are on-chain milestones

## Three Phases

### Phase 1: Bootstrap (0–72h from market creation)

| Parameter | Value |
|-----------|-------|
| Oracle sources | DEX TWAP only (PumpSwap/Raydium/Meteora pool) |
| OI cap | $10,000 equivalent |
| Max leverage | 2x |
| Funding | Standard, conservative dampening |
| Transition trigger | `current_slot >= market_created_slot + PHASE1_DURATION_SLOTS` |

- Uses existing `UpdateHyperpMark` (tag 34) DEX pool read
- Initial price seeded via `PushOraclePrice` from market creator
- Circuit breaker active (existing `oracle_price_cap_e2bps`)
- OI ramp from existing PERC-302 runs concurrently but is capped by phase OI limit

### Phase 2: Growth (72h–14d OR $100K cumulative volume)

| Parameter | Value |
|-----------|-------|
| Oracle sources | Median of: DEX TWAP, Hyperp EMA mark, Switchboard (if available) |
| OI cap | $100,000 equivalent |
| Max leverage | 5x |
| Transition trigger | EITHER `current_slot >= market_created_slot + PHASE2_DURATION_SLOTS` OR `cumulative_volume >= PHASE2_VOLUME_THRESHOLD` |

- New instruction `UpdateOracleMedian` (tag 55) computes median of up to 3 sources
- Switchboard feed address stored in new config field `switchboard_feed` (optional, zero = absent)
- Volume tracked in existing engine state (cumulative notional)
- Both time AND volume milestones checked — whichever hits first

### Phase 3: Mature (after Phase 2 exit)

| Parameter | Value |
|-----------|-------|
| Oracle sources | Full Pyth/Switchboard (if available), else Hyperp EMA continues |
| OI cap | Market's configured `oi_cap_multiplier_bps` (full) |
| Max leverage | Market's configured max (full) |
| Transition trigger | N/A (terminal phase) |

- If Pyth feed becomes available, keeper can call `SetPythFeed` to upgrade
- Existing `KeeperCrank` and `UpdateHyperpMark` continue working
- No regression — once Phase 3, market stays Phase 3

## On-Chain State

### New Config Fields

```rust
// ========================================
// Oracle Phase Transition (PERC-622)
// ========================================
/// Current oracle phase: 1 = Bootstrap, 2 = Growth, 3 = Mature.
/// 0 = legacy (pre-PERC-622 market, treated as Phase 3).
pub oracle_phase: u8,
pub _oracle_phase_pad: [u8; 7],

/// Phase 1 duration in slots. Default: ~72h ≈ 518_400 slots (at 2 slots/sec).
/// 0 = skip Phase 1 (start at Phase 2).
pub phase1_duration_slots: u64,

/// Phase 2 duration in slots. Default: ~14d ≈ 4_838_400 slots.
/// Phase 2 exits on EITHER time OR volume milestone.
pub phase2_duration_slots: u64,

/// Cumulative volume threshold (in collateral units) to exit Phase 2 early.
/// 0 = time-only transition.
pub phase2_volume_threshold: u64,

/// Switchboard feed address (optional). Zero = not available.
pub switchboard_feed: [u8; 32],
```

Total new bytes: 8 + 8 + 8 + 8 + 32 = **64 bytes**

### Phase Parameter Overrides

Phase-specific caps are NOT stored on-chain (saves space). Instead, constants:

```rust
// Phase 1 constants
pub const PHASE1_OI_CAP_UNITS: u64 = 10_000_000_000;  // $10K in e6
pub const PHASE1_MAX_LEVERAGE_BPS: u64 = 20_000;       // 2x in bps

// Phase 2 constants
pub const PHASE2_OI_CAP_UNITS: u64 = 100_000_000_000;  // $100K in e6
pub const PHASE2_MAX_LEVERAGE_BPS: u64 = 50_000;        // 5x in bps
pub const PHASE2_DEFAULT_VOLUME_THRESHOLD: u64 = 100_000_000_000; // $100K in e6

// Phase durations (defaults, overridable per-market at creation)
pub const PHASE1_DEFAULT_SLOTS: u64 = 518_400;    // ~72h at 2 slots/sec
pub const PHASE2_DEFAULT_SLOTS: u64 = 4_838_400;  // ~14d at 2 slots/sec
```

### Phase Transition Logic

```rust
/// Compute effective oracle phase. Pure function — no state mutation.
/// Called on every trade/liquidation to enforce phase-appropriate limits.
pub fn effective_oracle_phase(
    oracle_phase: u8,
    market_created_slot: u64,
    current_slot: u64,
    phase1_duration_slots: u64,
    phase2_duration_slots: u64,
    phase2_volume_threshold: u64,
    cumulative_volume: u64,
) -> u8 {
    // Legacy markets (oracle_phase == 0) → Phase 3
    if oracle_phase == 0 { return 3; }

    let elapsed = current_slot.saturating_sub(market_created_slot);

    match oracle_phase {
        1 => {
            if elapsed >= phase1_duration_slots {
                2  // Time milestone → advance to Phase 2
            } else {
                1  // Still in Phase 1
            }
        }
        2 => {
            let time_exit = elapsed >= phase1_duration_slots.saturating_add(phase2_duration_slots);
            let volume_exit = phase2_volume_threshold > 0
                && cumulative_volume >= phase2_volume_threshold;
            if time_exit || volume_exit {
                3  // Either milestone → advance to Phase 3
            } else {
                2  // Still in Phase 2
            }
        }
        _ => 3,  // Phase 3 or any unexpected value → mature
    }
}
```

**Key design decision**: Phase transitions are computed, not stored. The `oracle_phase` field in config stores the *initial* phase (set at InitMarket). The effective phase is derived every time it's needed. When a transition is detected, the crank (or trade instruction) writes back the new `oracle_phase` to config. This makes transitions automatic and irrevocable.

### Phase Advancement Write-Back

On every `TradeNoCpi`, `TradeCpi`, `Liquidate`, and `KeeperCrank`:

```rust
let effective = effective_oracle_phase(config.oracle_phase, ...);
if effective > config.oracle_phase {
    config.oracle_phase = effective;
    msg!("OraclePhaseTransition: {} → {}", old_phase, effective);
}
```

This is a one-way ratchet — phase can only increase, never decrease.

## New Instruction: UpdateOracleMedian (Tag 55)

Used in Phase 2 to aggregate multiple oracle sources:

```
Accounts:
  [0] slab (writable)
  [1] dex_pool (readonly) — PumpSwap/Raydium/Meteora pool
  [2] switchboard_feed (readonly, optional) — Switchboard aggregator
```

Logic:
1. Read DEX price from pool account (existing `dex_price_from_pool()`)
2. Read current Hyperp EMA mark from slab engine state
3. If `switchboard_feed != [0;32]`, read Switchboard aggregator price
4. Compute median of available prices (2 or 3 sources)
5. Apply EMA blend with existing mark price
6. Apply circuit breaker

## Trade/Liquidation Enforcement

Modify `check_position_limits()` (or equivalent) to enforce phase caps:

```rust
let phase = effective_oracle_phase(config.oracle_phase, ...);
let (max_oi, max_leverage) = match phase {
    1 => (PHASE1_OI_CAP_UNITS, PHASE1_MAX_LEVERAGE_BPS),
    2 => (PHASE2_OI_CAP_UNITS, PHASE2_MAX_LEVERAGE_BPS),
    _ => (/* config oi_cap */, /* config max_leverage */),
};
// Enforce: reject trade if would exceed max_oi or max_leverage
```

## Kani Proof Sketch

### Proof 1: Phase monotonicity
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase_monotone() {
    let phase: u8 = kani::any();
    kani::assume(phase >= 1 && phase <= 3);
    let created: u64 = kani::any();
    let current: u64 = kani::any();
    kani::assume(current >= created);
    let p1_dur: u64 = kani::any();
    let p2_dur: u64 = kani::any();
    let p2_vol: u64 = kani::any();
    let vol: u64 = kani::any();

    let result = effective_oracle_phase(phase, created, current, p1_dur, p2_dur, p2_vol, vol);
    assert!(result >= phase, "Phase must never decrease");
}
```

### Proof 2: Phase bounds
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase_bounds() {
    // For any inputs, effective_oracle_phase returns 1, 2, or 3
    let phase: u8 = kani::any();
    let result = effective_oracle_phase(phase, kani::any(), kani::any(),
        kani::any(), kani::any(), kani::any(), kani::any());
    assert!(result >= 1 && result <= 3);
}
```

### Proof 3: Legacy backward compat
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase_legacy_is_mature() {
    let result = effective_oracle_phase(0, kani::any(), kani::any(),
        kani::any(), kani::any(), kani::any(), kani::any());
    assert!(result == 3, "Legacy markets always Phase 3");
}
```

### Proof 4: Phase 1 OI cap enforced
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase1_oi_bounded() {
    let phase = 1u8;
    // After phase enforcement, OI must be <= PHASE1_OI_CAP_UNITS
    // (proven by showing check_position_limits rejects otherwise)
}
```

### Proof 5: Phase 3 terminal
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase3_terminal() {
    let result = effective_oracle_phase(3, kani::any(), kani::any(),
        kani::any(), kani::any(), kani::any(), kani::any());
    assert!(result == 3, "Phase 3 is terminal");
}
```

## Config Layout Impact

Current CONFIG_LEN = 536. Adding 64 bytes → 600. Need to update:
- `CONFIG_LEN` constant
- `ENGINE_OFF` (currently 640 — sufficient if 600 < 640, so NO CHANGE needed)
- SDK layout auto-detection (V0/V1/V2)

**Wait**: ENGINE_OFF is 640 and CONFIG starts at offset 104 (HEADER_LEN). So CONFIG occupies bytes 104..640 = 536 bytes. Adding 64 → 600 bytes, still fits within ENGINE_OFF=640. 640 - 104 = 536 currently used. 536 + 64 = 600 > 536 but we have padding to 640. Actually 640 - 104 = 536 is exactly CONFIG_LEN. If we increase CONFIG_LEN to 600, we need ENGINE_OFF = HEADER_LEN + CONFIG_LEN = 104 + 600 = 704. This is a **slab layout change** (V2).

**Alternative**: Use existing padding/reserved bytes. The `_insurance_isolation_padding` is 14 bytes. `_orphan_pad` is 6 bytes. Various `_pad` fields total ~40+ bytes. Not enough for 64 bytes.

**Decision**: This is a V2 slab layout. New markets get V2. Existing V0/V1 markets remain at Phase 3 (legacy). Auto-detection already handles V0/V1 — extend for V2.

## Implementation Plan

1. **Design doc** (this document) — DONE
2. **Add `effective_oracle_phase()` pure function + Kani proofs** — small, testable
3. **Extend MarketConfig** with new fields, update CONFIG_LEN/ENGINE_OFF for V2
4. **Wire phase enforcement into Trade/Liquidate** — reject exceeding phase limits
5. **Add `UpdateOracleMedian` instruction (tag 55)** — Phase 2 multi-source oracle
6. **InitMarket sets `oracle_phase = 1`** for new markets
7. **SDK: V2 layout detection + new fields**
8. **Keeper: call UpdateOracleMedian in Phase 2, transition detection**

## Risk Assessment

- **Breaking change**: V2 slab layout. Mitigated by existing V0/V1/V2 auto-detection pattern.
- **Cumulative volume source**: Need to identify where cumulative notional is tracked in engine state. If not tracked, add it.
- **Switchboard integration**: New external dependency. Phase 2 works without it (2-source median = average).
- **Constants vs configurable**: Phase caps are constants for simplicity. If per-market customization needed later, can migrate to config fields.

## Open Questions

1. Should phase durations be configurable per-market at InitMarket, or global constants?
   - **Recommendation**: Configurable at InitMarket with defaults. Already reflected in design (config fields).
2. Is cumulative volume already tracked on-chain? Need to check engine state.
3. Switchboard aggregator account layout — need to add deserialization.
