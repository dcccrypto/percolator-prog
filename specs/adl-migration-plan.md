# ADL Architecture Migration Plan
## PERC-8261 — dcccrypto/percolator → aeyakovenko/percolator upstream sync

**Author:** Anvil (anchor agent)  
**Date:** 2026-03-30  
**Status:** Draft  
**Commits behind:** 748 commits (as of 2026-03-30 09:00 UTC)  
**Reference:** https://github.com/aeyakovenko/percolator/compare/dcccrypto:master...master

---

## 0. Executive Summary

The `dcccrypto/percolator` risk engine is 748 commits behind `aeyakovenko/percolator` upstream. Upstream has undergone a fundamental redesign across three major areas:

1. **Native 128-bit architecture** — replaces `I128`/`U128` wrapper types with a new `wide_math` module (`I256`, `U256`) and native `i128`/`u128` throughout, removing the BPF alignment workaround layer
2. **Two-phase keeper / InstructionContext** — replaces the single-pass crank with a staged execution model that defers OI side resets and bilateral settlements into an explicit `InstructionContext`
3. **pnl_matured_pos_tot + SideMode + enforce_one_side_margin / enforce_post_trade_margin** — complete rewrite of the ADL/margin enforcement pipeline, adding matured PnL tracking, per-side drain/reset state machines, and spec-accurate post-trade margin checks

This is not a routine rebase. It is a structural migration that touches the memory layout of every slab on-chain. A new deployment to devnet will be required.

**Estimated total effort: 7–10 days (engineering) + 2 days QA/Security**

---

## 1. Scope of Changes

### 1.1 New Files in Upstream

| File | Description |
|------|-------------|
| `src/wide_math.rs` | ~2000 line module: `U256`, `I256`, 128×128→256 wide multiply, `I256` signed division |
| `tests/proofs_arithmetic.rs` | 517 lines — arithmetic overflow/underflow proofs |
| `tests/proofs_audit.rs` | 968 lines — audit findings proofs |
| `tests/proofs_instructions.rs` | 1734 lines — per-instruction proofs |
| `tests/proofs_invariants.rs` | 630 lines — invariant proofs |
| `tests/proofs_lazy_ak.rs` | 617 lines — lazy A/K mechanism proofs |
| `tests/proofs_liveness.rs` | 439 lines — liveness (no-deadlock) proofs |
| `tests/proofs_safety.rs` | 2610 lines — safety proofs |
| `tests/proofs_v1131.rs` | 886 lines — v11.31 spec compliance proofs |
| `tests/common/mod.rs` | 144 lines — shared test helpers |

**Key removal:** `tests/kani.rs` (~10,000 lines) is deleted. All proofs are reorganized into the above per-topic files.

### 1.2 Changed Files

| File | Net change | Impact |
|------|-----------|--------|
| `src/percolator.rs` | -2500 lines (major restructure) | All data structures, all methods |
| `src/wide_math.rs` | +1984 lines (new) | Math layer |
| `tests/unit_tests.rs` | -5000 lines (cleanup) | Tests reorganized |
| `tests/fuzzing.rs` | +/-minor | Updated for new API |
| `tests/amm_tests.rs` | +/-minor | Updated for new API |
| `spec.md` | +2096 lines | Spec to v12.0.2 |
| `Cargo.toml` | minor | Added `small`/`medium`/`fuzz` features |

---

## 2. Key Architectural Changes (Ordered by Impact)

### 2.1 BREAKING: `Account` struct layout change
**Impact: Devnet data migration required**

Upstream `Account`:
- `kind` is now `u8` (was `AccountKind` enum) — ABI change
- `reserved_pnl` is now `u128` (was `u64`) — ABI change, 8 bytes wider
- `position_basis_q: i128` replaces `position_size: I128` (same semantics, different field name/type)
- `entry_price: u64` **removed**
- `funding_index: I128` **removed** 
- `adl_a_basis: u128` and `adl_k_snap: i128` added (lazy A/K attachment state)
- `adl_epoch_snap: u64` added
- `last_partial_liquidation_slot: u64` **removed**
- `fees_earned_total: U128` added
- `fee_credits: I128` stays but as native `I128` (unchanged type here)

**Risk:** SLAB_LEN changes. All existing devnet slabs are invalid after upgrade.

### 2.2 BREAKING: `RiskEngine` struct layout change
**Impact: Devnet data migration required**

Key additions to upstream `RiskEngine`:
- `pnl_matured_pos_tot: u128` — tracks matured (vested) portion of `pnl_pos_tot`
- `side_mode_long: SideMode` and `side_mode_short: SideMode` — per-side state machine
- `stored_pos_count_long/short: u64` — bilateral OI tracking
- `stale_account_count_long/short: u64`
- `phantom_dust_bound_long_q/short_q: u128` — per-side dust bounds
- `oi_eff_long_q: u128`, `oi_eff_short_q: u128` — effective OI (was single `oi_imbalance`)
- `adl_epoch_long/short: u64`, `adl_epoch_start_k_long/short: i128` — epoch tracking
- `insurance_floor: u128` moved from `RiskParams` to `RiskEngine` directly
- `last_oracle_price`, `last_market_slot`, `funding_price_sample_last` — anti-retroactivity
- `materialized_account_count: u64`

Key removals from upstream `RiskEngine`:
- `liq_errors: u64` (was in dcccrypto, not in upstream)
- `oi_imbalance_bps: i64` (replaced by bilateral long/short tracking)

### 2.3 BREAKING: `RiskParams` struct layout change

Upstream adds:
- `maintenance_fee_per_slot: U128`
- `insurance_floor: U128` (moved from engine to params, then synced)

### 2.4 BREAKING: `execute_trade` signature change

Upstream `execute_trade` adds a `funding_rate: i64` parameter (anti-retroactivity).

dcccrypto current:
```rust
pub fn execute_trade(&mut self, a: u16, b: u16, oracle_price: u64, now_slot: u64, ...) -> Result<()>
```

Upstream:
```rust
pub fn execute_trade(&mut self, a: u16, b: u16, oracle_price: u64, now_slot: u64, size_q: i128, exec_price: u64, funding_rate: i64) -> Result<()>
```

All callers in `percolator-prog` must update their CPI call signature.

### 2.5 BREAKING: `keeper_crank` signature change

Upstream:
```rust
pub fn keeper_crank(&mut self, now_slot: u64, oracle_price: u64, ordered_candidates: &[(u16, Option<LiquidationPolicy>)], max_revalidations: u16, funding_rate: i64) -> Result<CrankOutcome>
```

**New:** `ordered_candidates` replaces the old cursor-based scan. Keeper must pass an off-chain sorted liquidation shortlist. This is the "two-phase keeper" model from spec addendum A2.

### 2.6 NEW: `InstructionContext` — two-phase execution

Every crank/trade creates an `InstructionContext` and finalizes it at the end:
```rust
pub struct InstructionContext {
    pending_reset_long: bool,
    pending_reset_short: bool,
}
```

`finalize_instruction` applies deferred OI resets after all per-account state updates. This eliminates ordering bugs in multi-account instructions.

### 2.7 NEW: `SideMode` enum

```rust
pub enum SideMode {
    Normal,
    DrainOnly,
    ResetPending,
}
```

Controls whether a side accepts new positions. `DrainOnly` is set when all ADL-paying accounts on a side are exhausted — prevents new positions from entering a side that has been fully drained.

### 2.8 NEW: `pnl_matured_pos_tot`

Tracks the matured (fully vested) component of `pnl_pos_tot`. Haircut computation uses `pnl_matured_pos_tot` instead of `pnl_pos_tot` when available, preventing immature profits from being included in ADL calculations.

### 2.9 NEW: `enforce_post_trade_margin` / `enforce_one_side_margin`

Post-trade margin is now checked against both the old and new effective position size, using wide `I256` arithmetic to prevent overflow in margin calculations. Flat-close guard uses `account_equity_maint_raw_wide()`.

### 2.10 NEW: `wide_math` module (`I256`, `U256`)

Replaces manual overflow checks with 256-bit intermediate arithmetic for:
- Position notional calculations
- Margin equity calculations
- Funding payment calculations

Dependency: `src/wide_math.rs` must be introduced as a new module.

### 2.11 NEW: `AccountKind` → `u8` (ZC UB fix)

`AccountKind` enum is replaced with `u8` constants `Account::KIND_USER = 0` and `Account::KIND_LP = 1`. This eliminates a zero-copy undefined behavior class where enum discriminants could be set to invalid values by direct slab writes.

### 2.12 NEW: Live premium-based funding (spec v12.0.2)

`accrue_market_to` now accepts a `funding_rate: i64` parameter. Funding is applied to both long and short positions using `pnl_matured_pos_tot`-based bilateral settlement. `recompute_r_last_from_final_state` anti-retroactivity hook is called at end of crank.

### 2.13 NEW: Maintenance fees

`RiskParams.maintenance_fee_per_slot: U128` enables per-slot account fees. `settle_maintenance_fee()` is called in `touch_account_full`. Previously this was a no-op.

### 2.14 NEW: `close_account_resolved`

New instruction for frozen/resolved market paths: closes an account when the market is marked as resolved, bypassing the normal zero-position requirement.

### 2.15 NEW: `reclaim_empty_account`

New instruction for admin-initiated account cleanup (spec §2.6).

### 2.16 NEW: `MIN_NONZERO_MM_REQ` / `MIN_NONZERO_IM_REQ` margin floors

Prevents dust positions from bypassing margin checks.

---

## 3. Ordered Task List

| # | Task ID | Title | Effort | Dependencies | Risk |
|---|---------|-------|--------|--------------|------|
| T1 | PERC-8262 | Introduce `wide_math` module (`U256`, `I256`) | M (1.5d) | none | Low |
| T2 | PERC-8263 | Migrate `Account` struct: `kind→u8`, `reserved_pnl→u128`, add ADL fields, remove dead fields | M (1d) | T1 | HIGH — ABI break |
| T3 | PERC-8264 | Migrate `RiskEngine` struct: add bilateral OI, `pnl_matured_pos_tot`, `SideMode`, `InstructionContext` | L (2d) | T2 | HIGH — ABI break |
| T4 | PERC-8265 | Migrate `RiskParams`: add `maintenance_fee_per_slot`, `insurance_floor` | S (0.5d) | T3 | Low |
| T5 | PERC-8266 | Rewrite `set_pnl` / `set_reserved_pnl` to maintain `pnl_matured_pos_tot` | M (1d) | T3 | HIGH — financial correctness |
| T6 | PERC-8267 | Implement `SideMode` state machine: `DrainOnly`, `ResetPending`, `finalize_instruction` | M (1d) | T3, T5 | HIGH |
| T7 | PERC-8268 | Rewrite `execute_trade`: add `funding_rate` param, `enforce_post_trade_margin`, wide arithmetic | L (2d) | T5, T6 | CRITICAL — trade correctness |
| T8 | PERC-8269 | Rewrite `keeper_crank`: two-phase model, `ordered_candidates`, anti-retroactivity | L (2d) | T6, T7 | CRITICAL |
| T9 | PERC-8270 | Implement maintenance fees: `settle_maintenance_fee`, `deposit_fee_credits` | M (1d) | T4, T3 | Medium |
| T10 | PERC-8271 | Implement `close_account_resolved` and `reclaim_empty_account` | S (0.5d) | T3 | Low |
| T11 | PERC-8272 | Reorganize Kani proofs: delete `tests/kani.rs`, split into `proofs_*.rs` topic files | L (2d) | T5–T10 | Medium |
| T12 | PERC-8273 | Update `percolator-prog` CPI callers: new `execute_trade`/`keeper_crank` signatures | M (1d) | T7, T8 | HIGH |
| T13 | PERC-8274 | Devnet migration script: detect SLAB_LEN change, drain accounts, redeploy | M (1d) | T2–T4 | HIGH |
| T14 | PERC-8275 | QA: full regression suite on new engine against upstream tests | L (2d) | T11 | — |
| T15 | PERC-8276 | Security: audit of new wide_math, SideMode, two-phase crank | M (1d) | T11 | — |

**Total engineering estimate: ~18 developer-days**  
**Critical path: T1 → T2 → T3 → T5 → T6 → T7 → T8 → T12 (8 days)**

---

## 4. Sprint Breakdown

### Sprint A (Week 1): Foundation + Data Structures
**Goal:** All struct migrations done, compiles, old Kani still passes.

| Task | Owner |
|------|-------|
| T1: wide_math | anchor |
| T2: Account migration | anchor |
| T3: RiskEngine migration | anchor |
| T4: RiskParams migration | anchor |

**Done criteria:** `cargo build` passes. Unit tests compile. `SLAB_LEN` recomputed and matches upstream.

### Sprint B (Week 2): Core Logic
**Goal:** All financial logic migrated. New Kani proof files compiling.

| Task | Owner |
|------|-------|
| T5: set_pnl / pnl_matured_pos_tot | anchor |
| T6: SideMode state machine | anchor |
| T7: execute_trade rewrite | anchor |
| T8: keeper_crank rewrite | anchor |
| T9: maintenance fees | anchor |
| T10: close_account_resolved / reclaim_empty | anchor |

**Done criteria:** `cargo test` passes. `execute_trade` and `keeper_crank` tests green.

### Sprint C (Week 2 end): Proof Reorganization + CPI + Migration
**Goal:** Kani proofs migrated, prog CPI updated, devnet migration script ready.

| Task | Owner |
|------|-------|
| T11: Proof reorganization | anchor |
| T12: percolator-prog CPI update | anchor |
| T13: Devnet migration script | anchor + devops |

### Sprint D (QA + Security): Review
**Goal:** Clean audit pass, production-ready.

| Task | Owner |
|------|-------|
| T14: QA full regression | qa |
| T15: Security audit | security |

**Estimated total duration: 2–3 sprints (14–21 calendar days)**

---

## 5. Dependencies

```
T1 (wide_math)
└─► T2 (Account)
    └─► T3 (RiskEngine)
        ├─► T4 (RiskParams)
        │   └─► T9 (maintenance fees)
        ├─► T5 (pnl_matured_pos_tot)
        │   └─► T6 (SideMode)
        │       ├─► T7 (execute_trade)
        │       │   └─► T8 (keeper_crank)
        │       │       └─► T12 (prog CPI)
        │       └─► T11 (proofs reorganization)
        └─► T10 (close_account_resolved)
T13 (devnet migration) depends on T2 + T3 + T4 (SLAB_LEN is known)
T14/T15 depend on T11
```

---

## 6. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| SLAB_LEN change invalidates all devnet state | HIGH | T13: migration script drains + reinits all slabs before upgrade |
| `execute_trade` signature break — percolator-prog CPI desync | HIGH | T12: immediate CPI update in same PR as T7 |
| `pnl_matured_pos_tot` invariant violations in existing tests | HIGH | Run existing kani suite first, identify failing harnesses before migration |
| `wide_math` not no_std compatible | MEDIUM | Copy from upstream verbatim; upstream uses `#![no_std]` already |
| Two-phase crank changes keeper timing assumptions | MEDIUM | Coord with devops on keeper binary update (must ship with T8) |
| AccountKind `u8` migration — percolator-prog reads `kind` by offset | MEDIUM | Verify all `kind` reads in prog use the same byte offset post-migration |
| Proof reorganization (T11) is large but low risk | LOW | Port proofs methodically, run each `proofs_*.rs` file independently |
| Upstream still actively adding commits | MEDIUM | Pin to `6c963dd` for migration baseline; track new upstream changes separately |

---

## 7. Out of Scope (Separate Tracks)

- `percolator-match`, `percolator-stake`, `percolator-vault`, `percolator-nft` — no breaking changes from upstream for these repos
- TypeScript SDK bindings — sdk agent handles IDL regeneration after T2/T3
- Frontend — no changes required (risk engine is pure Rust lib)
- Mainnet deployment — NOT planned for this migration; devnet only

---

## 8. First Action

**Start with T1 (PERC-8262): Introduce `wide_math` module.**

```bash
git checkout -b feat/PERC-8262-wide-math
# Copy src/wide_math.rs verbatim from upstream 6c963dd
# Add `pub mod wide_math;` to src/percolator.rs
# Add imports: use wide_math::{U256, I256};
# Verify: cargo build && cargo test
```

Once `wide_math` compiles cleanly, T2 (Account struct migration) can begin immediately.

---

## 9. Coordination Required

- **pm**: Create Collector tasks PERC-8262 through PERC-8276 (15 tasks)
- **sdk**: Coordinate on IDL regeneration after T2/T3 land (SLAB_LEN changes)
- **devops**: Required for T13 devnet migration; FF7K wallet must be funded (currently ~0.009 SOL, needs ~4.2 SOL for 3 program upgrades)
- **qa**: Assign T14 when T11 is complete
- **security**: Assign T15 in parallel with T14

---

*This plan was authored from direct diff analysis of upstream `6c963dd` vs dcccrypto `HEAD` (2026-03-30).*
