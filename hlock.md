# Engine Change: Dynamic H_lock Admission

## Summary

The engine decides per-reserve-creation whether fresh positive PnL gets instant release (h_min) or full warmup (h_max), based on whether admitting it would preserve h=1. Wrappers pass `(h_min, h_max)` pairs instead of a single `h_lock`. The check runs at the exact moment of reserve creation inside `set_pnl_with_reserve`, after all prior mutations have landed — no stale snapshot, no race.

## What changes

### 1. New method on RiskEngine (~15 lines)

```rust
/// Returns h_min if instant release preserves h=1, h_max otherwise.
/// Pure read — no mutation.
///
/// Admission criterion:
///     pnl_matured_pos_tot + fresh_positive_pnl <= V - C_tot - I
pub fn admit_fresh_reserve_h_lock(
    &self,
    fresh_positive_pnl: u128,
    h_min: u64,
    h_max: u64,
) -> u64 {
    if fresh_positive_pnl == 0 { return h_min; }
    let senior = self.c_tot.get()
        .saturating_add(self.insurance_fund.balance.get());
    let residual = self.vault.get().saturating_sub(senior);
    let matured_if_instant = self.pnl_matured_pos_tot
        .saturating_add(fresh_positive_pnl);
    if matured_if_instant <= residual { h_min } else { h_max }
}
```

### 2. Extend ReserveMode variant

```rust
// Before:
UseHLock(u64),

// After:
UseHLock { h_min: u64, h_max: u64 },
```

### 3. Change set_pnl_with_reserve reserve-creation branch (~5 lines)

At the point where `reserve_add > 0` and mode is `UseHLock`:

```rust
// Before:
ReserveMode::UseHLock(h_lock) => {
    self.append_or_route_new_reserve(idx, reserve_add, self.current_slot, h_lock)?;
}

// After:
ReserveMode::UseHLock { h_min, h_max } => {
    let effective_h = self.admit_fresh_reserve_h_lock(reserve_add, h_min, h_max);
    self.append_or_route_new_reserve(idx, reserve_add, self.current_slot, effective_h)?;
}
```

The key insight: `reserve_add` IS the `fresh_positive_pnl` — the engine just computed it. No new state needed.

### 4. Change all `*_not_atomic` signatures

`h_lock: u64` becomes `h_min: u64, h_max: u64` on:

- `execute_trade_not_atomic`
- `withdraw_not_atomic`
- `close_account_not_atomic`
- `settle_account_not_atomic`
- `convert_released_pnl_not_atomic`
- `keeper_crank_not_atomic`
- `liquidate_at_oracle_not_atomic`

Each threads `(h_min, h_max)` into `ReserveMode::UseHLock { h_min, h_max }`.

### 5. Wrapper change (~12 lines)

Every call site:

```rust
// Before:
let h_lock = engine.params.h_min;
engine.foo_not_atomic(..., h_lock)?;

// After:
engine.foo_not_atomic(..., engine.params.h_min, engine.params.h_max)?;
```

## Why engine-side, not wrapper-side

The wrapper-only approach reads `pnl_matured_pos_tot` and `residual` BEFORE the engine call, but the engine call itself mutates both via mark-to-market settlement, funding accrual, and reserve maturation. By the time the engine actually creates the fresh reserve, the headroom snapshot is stale. Two trades in the same block could both see headroom and both get h_min, collectively overshooting.

The engine-side check runs at the exact moment of reserve creation — inside `set_pnl_with_reserve`, after all prior mutations in that call have landed. It sees the true post-settlement state. No race, no stale snapshot.

## Spec addition

```
§4.8 Dynamic H_lock Admission

Wrappers may request fast release for fresh reserve by passing (h_min, h_max)
as the h_lock parameter pair. The engine checks admission at the moment of
reserve creation:

    if PNL_matured_pos_tot + fresh_positive_pnl_i <= V - C_tot - I:
        effective_h_lock = h_min
    else:
        effective_h_lock = h_max

where fresh_positive_pnl_i is the positive component of the PnL delta being
materialized into account i's reserve.

The admission preserves the h = 1 invariant in the instant-release regime:
after fresh PnL enters matured, total matured claims remain fully backed
by residual.

This check runs inside set_pnl_with_reserve / append_new_reserve and is
transparent to the wrapper. Wrappers pass (h_min, h_max) pairs.

Feature disabled: if h_min == h_max, admission is a no-op.
```

## UX guarantee

| Action | Healthy market | Stressed market |
|--------|---------------|-----------------|
| Deposit | Instant | Instant |
| Withdraw capital (no PnL realized) | Instant | Instant |
| Withdraw capital (touch realizes K-space PnL) | H_min-fast | H_max-slow |
| Close position via trade | H_min-fast | H_max-slow |
| Convert released PnL | H_min-fast | H_max-slow |
| Settle account (standalone) | Admission-checked | Admission-checked |
| Any action with zero fresh positive PnL | H_min-fast | H_min-fast |

## TDD

### Part A: admit_fresh_reserve_h_lock unit tests

Pure function tests against fabricated engine state.

```rust
#[test]
fn admit_h_min_when_zero_fresh_pnl() {
    let e = engine(vault: 1_000_000, c_tot: 400_000, ins: 100_000, matured: 200_000);
    assert_eq!(e.admit_fresh_reserve_h_lock(0, 10, 216_000), 10);
}

#[test]
fn admit_h_min_when_fresh_fits_in_residual() {
    // residual = 1M - 400k - 100k = 500k. matured + 100k = 300k <= 500k
    let e = engine(vault: 1_000_000, c_tot: 400_000, ins: 100_000, matured: 200_000);
    assert_eq!(e.admit_fresh_reserve_h_lock(100_000, 10, 216_000), 10);
}

#[test]
fn admit_h_min_at_exact_boundary() {
    // residual = 200k. matured + 100k = 200k == residual. Still h=1.
    let e = engine(vault: 500_000, c_tot: 200_000, ins: 100_000, matured: 100_000);
    assert_eq!(e.admit_fresh_reserve_h_lock(100_000, 0, 216_000), 0);
}

#[test]
fn admit_h_max_one_over_boundary() {
    let e = engine(vault: 500_000, c_tot: 200_000, ins: 100_000, matured: 100_000);
    assert_eq!(e.admit_fresh_reserve_h_lock(100_001, 0, 216_000), 216_000);
}

#[test]
fn admit_h_max_when_residual_zero() {
    // V == C + I exactly. Any fresh PnL overflows.
    let e = engine(vault: 300_000, c_tot: 200_000, ins: 100_000, matured: 0);
    assert_eq!(e.admit_fresh_reserve_h_lock(1, 0, 216_000), 216_000);
}

#[test]
fn admit_h_max_when_vault_below_senior_saturates() {
    // V < C + I. saturating_sub → residual = 0.
    let e = engine(vault: 100_000, c_tot: 200_000, ins: 100_000, matured: 0);
    assert_eq!(e.admit_fresh_reserve_h_lock(1, 0, 216_000), 216_000);
}

#[test]
fn admit_h_max_when_matured_near_u128_max() {
    // saturating_add clamps. Result > any realistic residual.
    let e = engine(vault: u128::MAX, c_tot: 0, ins: 0, matured: u128::MAX - 100);
    assert_eq!(e.admit_fresh_reserve_h_lock(200, 0, 216_000), 216_000);
}

#[test]
fn admit_noop_when_h_min_equals_h_max() {
    // Feature disabled: always returns the shared value.
    let e = engine_stressed();
    assert_eq!(e.admit_fresh_reserve_h_lock(1_000_000, 216_000, 216_000), 216_000);
}

#[test]
fn admit_h_min_zero_fresh_even_when_stressed() {
    // Zero fresh PnL always returns h_min, regardless of system state.
    let e = engine(vault: 1000, c_tot: 500, ins: 400, matured: 500);
    assert_eq!(e.admit_fresh_reserve_h_lock(0, 10, 216_000), 10);
}

#[test]
fn admit_respects_nonzero_h_min_as_floor() {
    // h_min=10: admitted but not instant.
    let e = engine_healthy();
    assert_eq!(e.admit_fresh_reserve_h_lock(1000, 10, 216_000), 10);
}
```

### Part B: set_pnl_with_reserve integration

```rust
#[test]
fn reserve_matures_instantly_when_admitted_h_min_zero() {
    let mut e = healthy_engine(h_min: 0, h_max: 216_000);
    let idx = e.add_user(1_000_000).unwrap();
    let matured_before = e.pnl_matured_pos_tot;

    e.set_pnl_with_reserve(idx, 50_000,
        UseHLock { h_min: 0, h_max: 216_000 }).unwrap();

    assert!(e.pnl_matured_pos_tot > matured_before,
        "h_min=0 in healthy market → instant maturation");
}

#[test]
fn reserve_enters_warmup_when_admitted_h_max() {
    let mut e = stressed_engine(h_min: 0, h_max: 216_000);
    let idx = e.add_user(1_000_000).unwrap();
    let matured_before = e.pnl_matured_pos_tot;

    e.set_pnl_with_reserve(idx, 50_000,
        UseHLock { h_min: 0, h_max: 216_000 }).unwrap();

    assert_eq!(e.pnl_matured_pos_tot, matured_before,
        "stressed → PnL enters reserve, not matured");
    assert!(e.accounts[idx].sched_present != 0
        || e.accounts[idx].pending_present != 0,
        "PnL must be in reserve buckets");
}

#[test]
fn nonzero_h_min_creates_short_warmup_in_healthy() {
    let mut e = healthy_engine(h_min: 10, h_max: 216_000);
    let idx = e.add_user(1_000_000).unwrap();

    e.set_pnl_with_reserve(idx, 50_000,
        UseHLock { h_min: 10, h_max: 216_000 }).unwrap();

    // In reserve with 10-slot horizon, not instant
    assert!(e.accounts[idx].sched_present != 0
        || e.accounts[idx].pending_present != 0);
}
```

### Part C: end-to-end through `*_not_atomic` methods

```rust
#[test]
fn trade_healthy_instant_release() {
    let mut e = healthy_engine(h_min: 0, h_max: 216_000);
    let a = e.add_user(1_000_000).unwrap();
    let b = e.add_user(1_000_000).unwrap();
    let matured_before = e.pnl_matured_pos_tot;

    // exec < oracle → buyer gets positive PnL
    e.execute_trade_not_atomic(a, b, /*oracle*/110, slot, 1000,
        /*exec*/100, 0, /*h_min*/0, /*h_max*/216_000).unwrap();

    assert!(e.pnl_matured_pos_tot > matured_before);
}

#[test]
fn trade_stressed_deferred_release() {
    let mut e = stressed_engine(h_min: 0, h_max: 216_000);
    let a = e.add_user(1_000_000).unwrap();
    let b = e.add_user(1_000_000).unwrap();
    let matured_before = e.pnl_matured_pos_tot;

    e.execute_trade_not_atomic(a, b, 110, slot, 1000,
        100, 0, 0, 216_000).unwrap();

    assert_eq!(e.pnl_matured_pos_tot, matured_before,
        "stressed trade must defer to reserve");
}

#[test]
fn withdraw_healthy_releases_k_space_pnl() {
    let mut e = healthy_engine_with_long(idx: 5, h_min: 0, h_max: 216_000);
    favorable_mark_move(&mut e);
    let matured_before = e.pnl_matured_pos_tot;

    e.withdraw_not_atomic(5, 1000, /*price*/110, slot, 0,
        /*h_min*/0, /*h_max*/216_000).unwrap();

    assert!(e.pnl_matured_pos_tot > matured_before,
        "healthy withdraw releases K-space PnL immediately");
}

#[test]
fn withdraw_stressed_defers_k_space_pnl() {
    let mut e = stressed_engine_with_long(idx: 5, h_min: 0, h_max: 216_000);
    favorable_mark_move(&mut e);
    let matured_before = e.pnl_matured_pos_tot;

    e.withdraw_not_atomic(5, 1000, 110, slot, 0, 0, 216_000).unwrap();

    assert_eq!(e.pnl_matured_pos_tot, matured_before);
}

#[test]
fn settle_healthy_releases_immediately() {
    let mut e = healthy_engine_with_long(idx: 5, h_min: 0, h_max: 216_000);
    favorable_mark_move(&mut e);

    e.settle_account_not_atomic(5, 110, slot, 0, 0, 216_000).unwrap();

    assert!(e.pnl_matured_pos_tot > 0);
}

#[test]
fn close_healthy_delivers_payout() {
    let mut e = healthy_engine_with_long(idx: 5, h_min: 0, h_max: 216_000);
    favorable_mark_move(&mut e);

    let payout = e.close_account_not_atomic(5, slot, 110, 0, 0, 216_000).unwrap();
    assert!(payout > 0);
}

#[test]
fn crank_uses_admission_per_account() {
    let mut e = healthy_engine_with_many_longs(100, h_min: 0, h_max: 216_000);
    favorable_mark_move(&mut e);

    e.keeper_crank_not_atomic(slot, 110, &candidates, 50,
        0, 0, 216_000).unwrap();

    assert!(e.pnl_matured_pos_tot > 0,
        "healthy crank should release PnL via admission");
}
```

### Part D: h=1 invariant preservation

```rust
#[test]
fn h_equals_one_preserved_under_random_workload() {
    let mut e = setup_fresh_engine();
    let mut rng = seeded_rng(42);

    for _ in 0..10_000 {
        let action = rng.choose_action();
        apply_action(&mut e, action, h_min: 0, h_max: 216_000);

        let senior = e.c_tot.get() + e.insurance_fund.balance.get();
        let residual = e.vault.get().saturating_sub(senior);
        let matured = e.pnl_matured_pos_tot;

        if matured > 0 {
            assert!(matured <= residual,
                "h=1 violated after {:?}: matured={}, residual={}",
                action, matured, residual);
        }
    }
}

#[test]
fn admission_equivalent_to_h_invariant() {
    // For any decision returning h_min, post-state has h=1.
    // For any decision returning h_max, post-state would have h<1.
    for scenario in generate_scenarios() {
        let e = build_engine(scenario);
        let fresh = 100_000u128;
        let decision = e.admit_fresh_reserve_h_lock(fresh, 0, 216_000);

        let matured_if = e.pnl_matured_pos_tot.saturating_add(fresh);
        let senior = e.c_tot.get() + e.insurance_fund.balance.get();
        let residual = e.vault.get().saturating_sub(senior);
        let preserves_h1 = matured_if <= residual;

        if decision == 0 {
            assert!(preserves_h1, "h_min must preserve h=1: {:?}", scenario);
        } else {
            assert!(!preserves_h1, "h_max only when h<1: {:?}", scenario);
        }
    }
}
```

### Part E: anti-grief

```rust
#[test]
fn attacker_cannot_inflate_matured_without_waiting() {
    let mut e = near_capacity_engine(h_min: 0, h_max: 216_000);
    let attacker = e.add_user(100_000_000).unwrap();
    let matured_before = e.pnl_matured_pos_tot;

    for _ in 0..100 {
        // Attacker trades aggressively
        execute_profitable_trade(&mut e, attacker);
    }

    assert_eq!(e.pnl_matured_pos_tot, matured_before,
        "near-capacity: fresh PnL goes to reserve, not matured");
}

#[test]
fn withdrawals_free_headroom_for_future_admission() {
    let mut e = stressed_engine(h_min: 0, h_max: 216_000);
    let existing = user_with_matured_pnl(&e);

    // Currently stressed: trades get h_max
    assert_eq!(e.admit_fresh_reserve_h_lock(1000, 0, 216_000), 216_000);

    // Existing user withdraws matured PnL, freeing residual headroom
    e.close_account_not_atomic(existing, slot, price, 0, 0, 216_000).unwrap();

    // Now healthy: trades get h_min
    assert_eq!(e.admit_fresh_reserve_h_lock(1000, 0, 216_000), 0);
}
```

## CU budget impact

- 3 field reads: ~30 CU
- 1 saturating_add + 1 saturating_sub + 1 comparison: ~20 CU
- Total per reserve creation: ~50 CU
- Current trade CU: ~20k-40k
- Overhead: <0.3%
