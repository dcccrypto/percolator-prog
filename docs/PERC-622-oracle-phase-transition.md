# PERC-622: Three-Phase Oracle Transition Protocol

## Design Document

### Overview

New token markets (especially memecoins from pump.fun) lack reliable oracle infrastructure at launch. This protocol defines an automatic, on-chain, admin-key-free state machine that transitions markets through three oracle phases as they mature — starting with conservative limits and graduating to full trading parameters.

### State Machine

```
┌─────────────────────┐    72h elapsed AND     ┌─────────────────────┐    14d elapsed OR      ┌─────────────────────┐
│   PHASE 1: NASCENT  │  cumul_vol >= $100K    │  PHASE 2: GROWING   │  Pyth/Switchboard     │  PHASE 3: MATURE    │
│                     │ ─────────────────────► │                     │  feed available       │                     │
│  OI cap: $10K       │                        │  OI cap: $100K      │ ─────────────────────►│  OI cap: full       │
│  Max leverage: 2x   │                        │  Max leverage: 5x   │                        │  Max leverage: full │
│  Oracle: DEX TWAP   │                        │  Oracle: median of   │                        │  Oracle: Pyth/SB    │
│  + pump.fun price   │                        │  DEX TWAP + Hyperp  │                        │                     │
│                     │                        │  + Switchboard(opt) │                        │                     │
└─────────────────────┘                        └─────────────────────┘                        └─────────────────────┘
         │                                              │
         │  Transitions are ONE-WAY, permissionless     │
         │  (anyone can crank), checked on every trade  │
         └──────────────────────────────────────────────┘
```

### On-Chain Storage

We repurpose existing `_insurance_isolation_padding` spare bytes and add a new `OraclePhaseState` packed into the config tail. Alternatively, we use a small extension to MarketConfig if padding is insufficient.

**New fields (packed into config):**

```rust
/// Oracle phase (2 bits): 0=Phase1, 1=Phase2, 2=Phase3
/// Stored in _insurance_isolation_padding[2]
pub oracle_phase: u8,

/// Cumulative volume in collateral units (u64, stored LE in padding[3..11])
/// Incremented on every trade execution
pub cumulative_volume: u64,

/// Phase 2 entry slot (u64, stored LE in padding... or new field)
/// Set when transitioning from Phase 1 → Phase 2
/// Used to check 14-day elapsed for Phase 2 → Phase 3
pub phase2_entry_slot: u64,
```

**Padding budget check:**
- `_insurance_isolation_padding` is 14 bytes
- Bytes [0..2] already used for `mark_oracle_weight_bps`
- Remaining: bytes [2..14] = 12 bytes
- Need: 1 (phase) + 8 (cumulative_volume) = 9 bytes minimum → fits in padding[2..11]
- `phase2_entry_slot` needs 8 more bytes → doesn't fit in remaining 3 bytes

**Solution:** Store `phase2_entry_slot` by repurposing `_adaptive_pad2` (4 bytes, currently unused padding for alignment) + borrowing from `_insurance_isolation_padding[11..14]`. Actually, cleaner approach: use a new instruction tag to set phase2_entry_slot in header `_reserved` bytes which has space.

**Better approach — use `_reserved` in SlabHeader:**
- SlabHeader._reserved is 24 bytes: [0..8]=nonce, [8..16]=last_thr_slot, [16..24]=dust_base
- These are all used. We need a different location.

**Final approach — extend MarketConfig:**
Add 16 bytes to MarketConfig tail for phase state. This bumps CONFIG_LEN from 496→512 (V1 already at 512, confirmed by compile-time assert). Since we have a V0/V1 detection system, this goes into V1 layout only.

Wait — checking the compile-time asserts:
```rust
const _: [(); 496] = [(); CONFIG_LEN]; // V0
const _: [(); 512] = [(); CONFIG_LEN]; // V1
```

These are conditional — only one is active. Current CONFIG_LEN must be one of these. Let me check which is active.

Actually, looking more carefully: both asserts exist simultaneously, but only one can be true. This means the code uses `cfg` to toggle. Let me check the actual config size.

**Revised approach — pack into `_insurance_isolation_padding`:**

Given the 12 usable bytes in padding[2..14]:
- [2]: oracle_phase (u8) — 0/1/2
- [3..11]: cumulative_volume (u64 LE)
- [11..14]: unused (3 bytes)

For phase2_entry_slot, we can derive it: when transitioning to Phase 2, we write `market_created_slot + elapsed` into the existing `market_created_slot` field? No, that's destructive.

**Simplest approach:** Don't store phase2_entry_slot explicitly. Instead, store the slot at which Phase 2 was entered as a delta from market_created_slot, packed into 3 bytes (max ~16M slots ≈ 37 days at 400ms — sufficient since Phase 1 min is 72h = ~648K slots).

- [11..14]: phase2_delta_slots (u24 LE, offset from market_created_slot)

### Phase Transition Logic

```rust
/// Check and execute phase transition. Called on every trade.
/// Returns the current effective phase after any transition.
pub fn check_phase_transition(
    current_slot: u64,
    market_created_slot: u64,
    oracle_phase: u8,
    cumulative_volume: u64,
    phase2_delta_slots: u32, // u24 stored, u32 for computation
    // For Phase 2→3: whether a Pyth/Switchboard feed is now available
    has_mature_oracle: bool,
) -> (u8, bool) { // (new_phase, transitioned)
    match oracle_phase {
        0 => { // Phase 1 → Phase 2
            let elapsed = current_slot.saturating_sub(market_created_slot);
            let min_slots = 72 * 3600 * 1000 / 400; // ~648,000 slots for 72h
            // Volume threshold: $100K in collateral units (scaled by unit_scale)
            if elapsed >= min_slots && cumulative_volume >= PHASE2_VOLUME_THRESHOLD {
                (1, true)
            } else {
                (0, false)
            }
        }
        1 => { // Phase 2 → Phase 3
            let phase2_start = market_created_slot + phase2_delta_slots as u64;
            let elapsed_since_phase2 = current_slot.saturating_sub(phase2_start);
            let maturity_slots = 14 * 24 * 3600 * 1000 / 400; // ~3,024,000 slots for 14d
            if elapsed_since_phase2 >= maturity_slots || has_mature_oracle {
                (2, true)
            } else {
                (1, false)
            }
        }
        _ => (2, false), // Phase 3 is terminal
    }
}
```

### OI Cap & Leverage Enforcement

Phase-dependent caps are enforced in the trade path:

```rust
pub fn phase_oi_cap_collateral(oracle_phase: u8, base_oi_cap: u64) -> u64 {
    match oracle_phase {
        0 => PHASE1_OI_CAP,       // $10K equivalent
        1 => PHASE2_OI_CAP,       // $100K equivalent
        _ => base_oi_cap,          // Full configured cap
    }
}

pub fn phase_max_leverage_bps(oracle_phase: u8, base_max_lev: u64) -> u64 {
    match oracle_phase {
        0 => 20_000,               // 2x
        1 => 50_000,               // 5x
        _ => base_max_lev,         // Full configured leverage
    }
}
```

### Oracle Source Selection

| Phase | Primary | Secondary | Aggregation |
|-------|---------|-----------|-------------|
| 1 | DEX TWAP (PumpSwap/Raydium) | pump.fun final price (if available) | Median of available sources |
| 2 | DEX TWAP | Hyperp mark + Switchboard (optional) | Median of 2-3 sources |
| 3 | Pyth or Switchboard | DEX TWAP fallback | Primary with fallback |

Phase 1 and 2 use the existing Hyperp oracle path (TAG_UPDATE_HYPERP_MARK = 34) which already reads DEX pools. The phase transition only changes the caps/leverage and which additional oracle sources are considered in the median.

### New Instruction: AdvanceOraclePhase (Tag 53)

Permissionless crank instruction. Anyone can call it to advance the phase if conditions are met.

**Accounts:**
1. `[writable]` slab — the market slab
2. `[signer]` payer — fee payer (permissionless, anyone)
3. `[]` clock — Clock sysvar (or use slot from sysvar cache)

**Logic:**
1. Read current oracle_phase from config padding
2. Read cumulative_volume from config padding
3. Compute elapsed slots
4. Check transition conditions
5. If transition: write new phase, set phase2_delta_slots if entering Phase 2
6. Emit log: `OraclePhaseAdvanced { slab, old_phase, new_phase, slot }`

### Cumulative Volume Tracking

Add to trade execution path (TradeNoCpi / TradeCpi):
```rust
// After successful trade, accumulate volume
let trade_notional = size_units * oracle_price_e6 / 1_000_000;
let new_vol = get_cumulative_volume(config).saturating_add(trade_notional);
set_cumulative_volume(config, new_vol);
```

### Constants

```rust
// Phase transition thresholds
pub const PHASE1_MIN_SLOTS: u64 = 648_000;          // ~72h at 400ms slots
pub const PHASE2_VOLUME_THRESHOLD: u64 = 100_000;   // $100K (in collateral units, adjusted by unit_scale)
pub const PHASE2_MATURITY_SLOTS: u64 = 3_024_000;   // ~14 days

// Phase caps
pub const PHASE1_OI_CAP: u64 = 10_000;              // $10K
pub const PHASE1_MAX_LEVERAGE_BPS: u64 = 20_000;    // 2x
pub const PHASE2_OI_CAP: u64 = 100_000;             // $100K
pub const PHASE2_MAX_LEVERAGE_BPS: u64 = 50_000;    // 5x
```

### Migration / Backwards Compatibility

- Existing markets (oracle_phase padding byte = 0) are treated as Phase 1 by default
- Markets that already have Pyth oracles (is_pyth_pinned_mode = true) skip to Phase 3 automatically
- The AdvanceOraclePhase instruction is additive — no existing instruction signatures change
- cumulative_volume starts at 0 for existing markets (they'll need to accumulate volume to advance)

**Special case:** Existing mature markets with Pyth feeds should auto-promote to Phase 3. The AdvanceOraclePhase crank can handle this: if `is_pyth_pinned_mode()` returns true, immediately set phase to 2 (Phase 3).

---

## Kani Proof Sketch

### Proof 1: Phase Monotonicity
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_oracle_phase_monotone() {
    let old_phase: u8 = kani::any();
    kani::assume(old_phase <= 2);
    let slot: u64 = kani::any();
    let created: u64 = kani::any();
    kani::assume(created <= slot);
    let vol: u64 = kani::any();
    let delta: u32 = kani::any();
    let has_oracle: bool = kani::any();

    let (new_phase, _) = check_phase_transition(slot, created, old_phase, vol, delta, has_oracle);
    assert!(new_phase >= old_phase, "phase must never decrease");
    assert!(new_phase <= 2, "phase must be 0, 1, or 2");
}
```

### Proof 2: Phase 1 OI Cap Bounded
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase1_oi_cap_bounded() {
    let phase: u8 = 0; // Phase 1
    let base_cap: u64 = kani::any();
    let cap = phase_oi_cap_collateral(phase, base_cap);
    assert!(cap == PHASE1_OI_CAP);
    assert!(cap <= 10_000);
}
```

### Proof 3: Phase 2 Leverage Bounded
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase2_leverage_bounded() {
    let phase: u8 = 1; // Phase 2
    let base_lev: u64 = kani::any();
    let lev = phase_max_leverage_bps(phase, base_lev);
    assert!(lev == PHASE2_MAX_LEVERAGE_BPS);
    assert!(lev <= 50_000);
}
```

### Proof 4: Phase 3 Terminal
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase3_terminal() {
    let slot: u64 = kani::any();
    let created: u64 = kani::any();
    kani::assume(created <= slot);
    let vol: u64 = kani::any();
    let delta: u32 = kani::any();
    let has_oracle: bool = kani::any();

    let (new_phase, transitioned) = check_phase_transition(slot, created, 2, vol, delta, has_oracle);
    assert!(new_phase == 2, "Phase 3 is terminal");
    assert!(!transitioned, "Phase 3 never transitions");
}
```

### Proof 5: Cumulative Volume Monotone
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_cumulative_volume_monotone() {
    let old_vol: u64 = kani::any();
    let trade_notional: u64 = kani::any();
    let new_vol = old_vol.saturating_add(trade_notional);
    assert!(new_vol >= old_vol, "volume never decreases");
}
```

### Proof 6: Phase Transition Requires Minimum Time
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phase1_requires_min_time() {
    let created: u64 = kani::any();
    let slot: u64 = kani::any();
    kani::assume(created <= slot);
    kani::assume(slot - created < PHASE1_MIN_SLOTS);
    let vol: u64 = kani::any();
    let delta: u32 = kani::any();

    let (new_phase, transitioned) = check_phase_transition(slot, created, 0, vol, delta, false);
    assert!(new_phase == 0, "cannot leave Phase 1 before 72h");
    assert!(!transitioned);
}
```

### Proof 7: Pyth Markets Auto-Promote
```rust
#[cfg(kani)]
#[kani::proof]
fn proof_pyth_market_phase3() {
    let oracle_auth: [u8; 32] = [0u8; 32];
    let feed_id: [u8; 32] = kani::any();
    kani::assume(feed_id != [0u8; 32]);

    // If is_pyth_pinned_mode, market should be Phase 3
    assert!(is_pyth_pinned_mode(oracle_auth, feed_id));
    // AdvanceOraclePhase will set phase=2 for these
}
```

---

## Implementation Plan

1. **Add accessor functions** for oracle_phase, cumulative_volume, phase2_delta_slots in config padding
2. **Add pure transition logic** (`check_phase_transition`, `phase_oi_cap_collateral`, `phase_max_leverage_bps`)
3. **Wire volume accumulation** into TradeNoCpi/TradeCpi paths
4. **Wire phase caps** into OI check and leverage validation in trade paths
5. **Add TAG_ADVANCE_ORACLE_PHASE (53)** permissionless crank instruction
6. **Add Kani proofs** (7 harnesses above)
7. **Add unit tests** for transition logic, edge cases, overflow
8. **SDK update** in percolator-launch: `encodeAdvanceOraclePhase()`, phase display in UI

### Estimated Effort: XL (3-5 sessions)
