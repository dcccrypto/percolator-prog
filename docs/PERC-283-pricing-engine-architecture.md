# PERC-283: Pricing Engine Architecture Proposal

**Author:** coder  
**Date:** 2026-02-28  
**Status:** DRAFT  
**Sprint:** S2 — Pricing Engine (Feb 28 – Mar 21)

---

## 1. Executive Summary

This document covers the design for the on-chain Pricing Engine (PERC-117 through PERC-122). After auditing the codebase, **most of the foundational logic already exists** — what remains is wiring existing helpers into execution paths and adding a few missing pieces.

### Current State vs. Required

| Task | Status | Remaining Work |
|------|--------|----------------|
| PERC-117: Pyth Oracle CPI | ✅ Complete | None — `read_pyth_price_e6`, `SetPythOracle` instruction, Pyth-pinned mode all done |
| PERC-118: Mark Price Formula | ✅ 95% Complete | Mark price crank tag 33 reserved but instruction not wired; add standalone `MarkPriceCrank` |
| PERC-119: Hyperp EMA Oracle | ✅ Complete | `UpdateHyperpMark` instruction, PumpSwap/Raydium CLMM/Meteora DLMM readers all done |
| PERC-120: Dynamic Fee Model | ⚠️ 60% Complete | `compute_dynamic_fee_bps()` and `compute_fee_split()` exist in engine but **not called**; `execute_trade` uses flat fee |
| PERC-121: Funding Rate | ✅ Complete | Inventory + premium blending, `accrue_funding_combined`, settlement intervals all wired |
| PERC-122: Liquidation Engine | ✅ 90% Complete | `liquidate_with_mark_price` + partial liquidation exist; minor gap in cooldown enforcement for edge cases |

**Bottom line:** The critical work is PERC-120 (wiring dynamic fees into the trade path) and polishing PERC-118/122.

---

## 2. Detailed Analysis

### 2.1 PERC-120: Dynamic Fee Model (Primary Work Item)

#### Problem
`RiskEngine::execute_trade()` at line 3542 of `percolator.rs` computes fees as:
```rust
let fee = if notional > 0 && self.params.trading_fee_bps > 0 {
    (mul_u128(notional, self.params.trading_fee_bps as u128) + 9999) / 10_000
} else {
    0
};
```
This ignores the already-implemented tiered fee schedule (`compute_dynamic_fee_bps`) and fee split (`compute_fee_split`).

#### Solution

**Step 1: Wire dynamic fee into `execute_trade`** (percolator core)

Replace the flat fee calculation with:
```rust
let fee_bps = self.compute_dynamic_fee_bps(notional);
let fee = if notional > 0 && fee_bps > 0 {
    (mul_u128(notional, fee_bps as u128) + 9999) / 10_000
} else {
    0
};
```

**Step 2: Add fee split tracking** (percolator core)

The engine's `InsuranceFund` currently lumps all fees into `fee_revenue`. We need separate accumulators so the wrapper can distribute fees correctly.

Add to `InsuranceFund` (or add a new `FeeAccrual` struct on `RiskEngine`):
```rust
pub struct FeeAccrual {
    /// Cumulative fees for the LP vault (PERC-272)
    pub lp_vault_fees: U128,
    /// Cumulative fees for protocol treasury
    pub protocol_fees: U128,
    /// Cumulative fees for market creator
    pub creator_fees: U128,
}
```

After computing the fee in `execute_trade`, split it:
```rust
let (lp_share, protocol_share, creator_share) = self.compute_fee_split(fee);
// Insurance fund gets the LP share (legacy) + anything not explicitly split
self.insurance_fund.balance += lp_share;
self.fee_accrual.lp_vault_fees += lp_share;
self.fee_accrual.protocol_fees += protocol_share;
self.fee_accrual.creator_fees += creator_share;
```

**Step 3: Wire PERC-272 LP vault fee cranking**

The `LpVaultCrankFees` instruction already exists — it reads `fee_revenue` delta. We need it to read from the new `lp_vault_fees` accumulator instead.

**Step 4: SDK updates**

Update `computeTradingFee` in the SDK to accept tier config:
```typescript
export function computeDynamicTradingFee(
  notional: bigint,
  baseBps: bigint,
  tier2Bps: bigint,
  tier3Bps: bigint,
  tier2Threshold: bigint,
  tier3Threshold: bigint,
): bigint
```

#### Impact
- **Slab layout:** No change (FeeAccrual can live within engine's existing padding/reserved space, or we extend the engine struct — both are backward-compatible since slab size is checked at `>= ENGINE_OFF + OLD_ENGINE_LEN`)
- **Backward compatibility:** Markets with `fee_tier2_threshold == 0` automatically get flat fees (existing behavior)
- **CU impact:** Minimal (~10 CU extra for tiered lookup + split math)

---

### 2.2 PERC-118: Mark Price Crank (Minor)

#### Problem
Tag 33 (`TAG_MARK_PRICE_CRANK`) is reserved in constants but the instruction variant doesn't exist. Currently, mark price updates happen inside `KeeperCrank`. A standalone mark price crank would allow:
- More frequent mark price updates without full keeper crank cost
- Third-party permissionless mark price cranking

#### Solution
Add `MarkPriceCrank` instruction that:
1. Reads oracle price from the provided account
2. Applies EMA smoothing via `compute_ema_mark_price`
3. Updates `config.authority_price_e6` (mark price)
4. Updates `config.last_effective_price_e6` (circuit breaker)
5. Updates `engine.mark_price_e6`
6. Permissionless (anyone can call)
7. ~2000 CU (oracle read + EMA math)

```rust
Instruction::MarkPriceCrank => {
    // 1. Read oracle
    // 2. Clamp via circuit breaker
    // 3. EMA smooth
    // 4. Write config + engine.mark_price_e6
}
```

**Decision point:** Is this worth the code/audit surface? The KeeperCrank already does this. We could defer this and treat it as a nice-to-have optimization for post-beta.

→ **Recommendation:** Defer to post-beta. Mark price updates via KeeperCrank are sufficient for launch.

---

### 2.3 PERC-122: Liquidation Polishing (Minor)

#### Current State
- `liquidate_with_mark_price` ✅ fully implemented with partial liquidation
- `compute_liquidation_close_amount` ✅ uses `partial_liquidation_bps` and `min_liquidation_abs`
- Emergency bypass ✅ implemented (skips cooldown when margin < `emergency_liquidation_margin_bps`)

#### Remaining Gap
After careful review: **no gap found**. The two liquidation paths use different strategies:

- `liquidate_at_oracle` — **margin-target** partial close (computes exact amount to restore margin+buffer). No cooldown needed because each call brings margin to target level.
- `liquidate_with_mark_price` — **percentage-based** partial close (`partial_liquidation_bps / 10_000` per period). Cooldown correctly enforced via `last_partial_liquidation_slot`. Emergency bypass for critically underwater accounts works correctly.

Both paths have safety fallbacks: if partial close is insufficient, they escalate to full close.

---

## 3. Implementation Plan

### Phase 1: Wire Dynamic Fees (Days 1-3) — PERC-120
1. [ ] Replace flat fee in `execute_trade` with `compute_dynamic_fee_bps`
2. [ ] Add `FeeAccrual` struct to `RiskEngine` (or use existing fields)
3. [ ] Wire `compute_fee_split` into trade fee handling
4. [ ] Update `LpVaultCrankFees` to use split accumulators
5. [ ] Add unit tests for tiered fee + utilization surge scenarios
6. [ ] SDK: add `computeDynamicTradingFee` helper

### Phase 2: Liquidation Verification (Day 4) — PERC-122
1. [ ] Add test: mark-price partial liq → cooldown → same-slot re-liq blocked
2. [ ] Add test: emergency bypass overrides cooldown correctly
3. [ ] Add test: margin-target partial close brings account to safe margin

### Phase 3: Integration Testing (Days 5-7)
1. [ ] litesvm integration tests for tiered fee scenarios
2. [ ] proptest for fee monotonicity (higher notional → higher fee bps)
3. [ ] Test fee split distribution via LpVaultCrankFees
4. [ ] Regression: ensure all 381 existing tests still pass
5. [ ] CU benchmark comparison (before/after dynamic fees)

### Deferred (Post-Beta)
- TAG_MARK_PRICE_CRANK standalone instruction (PERC-118 Tag 33)
- Multi-source oracle aggregation refinement (PERC-274 is already functional)
- Fee tier configuration via UpdateConfig instruction

---

## 4. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Fee split rounding leaves dust | Low | Use ceiling division for protocol/LP, remainder to creator |
| Dynamic fee changes break existing tests | Medium | Feature-gate behind flag? No — better to update tests to use `fee_tier2_threshold=0` (disables tiering, matches old behavior) |
| Slab layout change breaks existing markets | High | FeeAccrual struct must fit in existing padding OR be additive (new fields at end). Current `OLD_ENGINE_LEN` check handles backward compatibility |
| Partial liquidation cooldown fix changes behavior | Low | Only affects new partial liquidation path (old oracle-only path has no partial liq concept) |

---

## 5. Files to Modify

### Core Engine (percolator crate)
- `src/percolator.rs` — `execute_trade`: wire `compute_dynamic_fee_bps`
- `src/percolator.rs` — `execute_trade`: wire `compute_fee_split`
- `src/percolator.rs` — Add `FeeAccrual` struct or extend `InsuranceFund`
- `src/percolator.rs` — Verify liquidation paths (no code change needed)

### Wrapper Program (percolator-prog crate)
- `src/percolator.rs` — `LpVaultCrankFees` handler: read from split accumulators
- `src/percolator.rs` — `UpdateConfig`: expose dynamic fee params if not already

### SDK (percolator-sdk)
- `src/math/trading.ts` — Add `computeDynamicTradingFee`
- `src/math/trading.ts` — Add `computeFeeSplit`

### Tests
- `tests/unit.rs` — Tiered fee unit tests
- `tests/integration.rs` — Fee split integration tests
- `tests/kani.rs` — Fee monotonicity proof (optional)

---

## 6. Questions for PM/Stakeholders

1. **Fee split configuration:** Should fee split params be settable per-market via `UpdateConfig`, or are they fixed at `InitMarket`? Current: params exist in `RiskParams` which is set at init and updatable via `UpdateConfig`.

2. **TAG_MARK_PRICE_CRANK:** Confirm defer to post-beta?

3. **Fee split destinations:** Where do protocol fees and creator fees get withdrawn? Currently only insurance fund and LP vault have withdrawal paths. Do we need `WithdrawProtocolFees` and `WithdrawCreatorFees` instructions, or do these accumulate in insurance fund with accounting separation?

4. **Backward compatibility:** Should we add a `dynamic_fees_enabled` flag to avoid changing behavior on existing devnet markets, or is it safe to enable globally (since `fee_tier2_threshold=0` means flat fees)?

---

*Awaiting PM review before beginning implementation.*
