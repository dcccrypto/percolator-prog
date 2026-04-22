# Security findings — 2026-04-22 deep sweep

Whitehat deep-dive after the `d19a712` fixes landed. All four findings
below were verified against the actual code at that commit. Each cites
file:line, describes the concrete attack, severity, and fix.

## F1 — CatchupAccrue partial mode rolls back `last_oracle_publish_time` (HIGH, conditional)

**Location:** `src/percolator.rs:8385-8387` (partial-catchup branch of
`Instruction::CatchupAccrue`).

**Code:**
```rust
let mut restored = config_pre;
restored.last_good_oracle_slot = config.last_good_oracle_slot;
state::write_config(&mut data, &restored);
```

**Bug.** The partial branch rolls back `config` to its pre-read value
(`config_pre`) but preserves only `last_good_oracle_slot`. It does NOT
preserve `last_oracle_publish_time`.

After commit `168cc0b`, `clamp_external_price` enforces:
`publish_time > last_oracle_publish_time` for advance. The test
invariant "a single Pyth observation refreshes liveness at most once"
holds in the normal path.

In partial catchup:
1. `read_price_and_stamp` called with publish_time = T. Config sees
   `last_oracle_publish_time → T`, `last_good_oracle_slot → clock.slot`.
2. Engine catches up partially (can't finish because funding-active
   and `gap > max_step_per_call`).
3. Selective rollback: `last_good_oracle_slot` preserved (stamp
   survives), but `last_oracle_publish_time` rolls back to its
   pre-read value.
4. **Next** CatchupAccrue call, same Pyth account: publish_time = T
   is still `> config.last_oracle_publish_time` (rolled back) →
   passes the "fresh observation" gate → advances
   `last_good_oracle_slot` AGAIN.

Invariant break: one observation can refresh liveness multiple times
across partial catchups. An attacker holding a single fresh Pyth
account can keep issuing partial catchups to stamp liveness on every
call, even without ever presenting a genuinely newer observation.

**Severity conditional.** Under the init constraint that
`permissionless_resolve_stale_slots <= max_accrual_dt_slots`, partial
catchup in a perm-resolve market should be hard to reach before
stale maturity — the gap that forces PARTIAL also forces stale
maturity. But the code-level invariant is broken and the fix is
trivial.

**Fix.** Preserve the timestamp atomically with the liveness stamp:
```rust
let mut restored = config_pre;
restored.last_good_oracle_slot = config.last_good_oracle_slot;
restored.last_oracle_publish_time = config.last_oracle_publish_time;
state::write_config(&mut data, &restored);
```

---

## F2 — Hyperp liveness spoofable via cheap self-trades when `mark_min_fee == 0` (HIGH)

**Location:** `src/percolator.rs:6205-6209` (TradeCpi Hyperp branch).

**Code:**
```rust
let full_weight = config.mark_min_fee == 0
    || fee_paid_hyperp >= config.mark_min_fee;
if full_weight {
    config.last_mark_push_slot = clock.slot as u128;
}
```

**Bug.** When `mark_min_fee == 0`, the short-circuit OR makes every
successful Hyperp trade "full-weight" — advances
`last_mark_push_slot`, which is the ONLY hard-timeout liveness
signal for Hyperp (see `permissionless_stale_matured`).

Default Hyperp init (`encode_init_market_hyperp` → `encode_init_market_full_v2`)
sets `mark_min_fee = 0`. A permissionless attacker with their own
LP + matcher can round-trip tiny self-trades (even `trading_fee_bps=0`
markets work) to refresh `last_mark_push_slot` every slot, blocking
`permissionless_stale_matured` from ever tripping.

**Impact.** `ResolvePermissionless` is the terminal exit for users
after admin burns the mark authority. Attacker-blocked resolve =
users stuck in a zombie market.

**Severity HIGH** because:
- Permissionless attack (any user can deploy their own matcher).
- Real bricking vector, not dust accumulation.
- Default config ships with the hole open.

**Fix.** Require a nonzero `mark_min_fee` at InitMarket when the
market is Hyperp AND `permissionless_resolve_stale_slots > 0`. This
is the config-time gate — simpler than decoupling the trade path,
operator-visible, doesn't change the EWMA/trade semantics honest
users rely on. Hyperp markets without perm-resolve (admin-resolve
only) can keep `mark_min_fee = 0` since there's no bricking vector.

---

## F3 — Account-slot exhaustion when `new_account_fee == 0 AND maintenance_fee_per_slot == 0` (documented config-risk, NOT enforced)

**Location:** `src/percolator.rs:4660-4672` (InitUser),
`src/percolator.rs:4774-4785` (InitLP).

**Bug.** Wrapper InitUser/InitLP only require `capital_units > 0`.
With `new_account_fee = 0`, a 1-base-unit deposit materializes a
permanent account slot. Attacker fills `max_accounts` slots for
near-zero cost.

The dust-reclaim fix in commit `b5ddaeb` mitigates this IF
`maintenance_fee_per_slot > 0` (accounts drain → reclaim in the fee
sweep). But with BOTH `new_account_fee = 0` AND
`maintenance_fee_per_slot = 0`, no drain mechanism exists → slots
stay filled indefinitely.

**Decision: documentation-only, not enforced.** Trusted-admin /
KYC'd / demo / test deployments may legitimately want neither gate
on (e.g., admin reviews account creations out-of-band, or the
market is short-lived test infrastructure). Enforcing the
"must-pick-one" rule at init was tried — it broke 84 existing
tests that use both-zero for legitimate test simplicity. Operator
policy instead:

- **Permissionless production markets MUST set at least one gate**
  (`new_account_fee > 0` or `maintenance_fee_per_slot > 0`).
- Otherwise an attacker fills `max_accounts` with 1-unit dust and
  bricks onboarding.

A comment pointing at this doc is placed at the InitMarket validation
site.

---

## F4 — `ForceCloseResolved` payout accepts any owner token account, not the canonical ATA (LOW, doc drift)

**Location:** `src/percolator.rs:7746` (code);
`src/percolator.rs:1402` (stale doc).

**Code:**
```rust
verify_token_account(a_owner_ata, &owner_pubkey, &mint)?;
```

**Bug.** The doc comment at `src/percolator.rs:1402` says "Sends
capital to stored owner ATA." In reality, `verify_token_account`
only checks (a) the account is a valid SPL token account, (b) its
token-owner field equals the stored owner pubkey, (c) its mint
matches. It does NOT derive the canonical Associated Token Address
and compare.

**Impact.** Admin-only op (gated by `require_admin`). An admin can
route payouts to any token account owned by the victim — not just the
ATA. Not a theft vector (the victim owns it), but:
- Payout goes to a non-canonical account the victim may not expect
  or monitor.
- Violates the documented contract.

**Severity LOW.** Low-privilege attacker doesn't have this capability;
admin is already trusted. Documentation/contract-drift issue.

**Fix.** Update the doc to match reality. The flexibility is
operationally useful (victim's canonical ATA might be closed or
broken); the doc is the right place to restore truth.

---

## Confirmed closed from prior review

All the previously-raised oracle-path issues, re-checked against
`d19a712`, are closed in the normal path:

- **Same-publish_time replay** — `clamp_external_price` requires
  `publish_time > last` (strict `<=` short-circuit). Cap-walk
  attempts return the stored baseline.
- **`last_good_oracle_slot` stamped on stale reads** —
  `read_price_and_stamp` snapshots `last_oracle_publish_time` before
  the call and only stamps the liveness cursor when it advanced.
- **Zero-fill TradeCpi ratchet** — rollback preserves
  `last_oracle_publish_time` atomically with `last_effective_price_e6`.
- **`new_account_fee` scale alignment** — InitMarket rejects
  misaligned fee so the InitUser/InitLP split can't create
  unavoidable dust.
- **Dust account slot reclamation** — wrapper's
  `sweep_maintenance_fees` reclaims flat zero-capital accounts in
  the same pass, so crank-only reclamation works when fees are
  enabled.
- **Hyperp EWMA clock on sub-threshold trades** — both TradeCpi
  and TradeNoCpi now gate clock bump on full-weight observation.

That leaves F1–F4 as new findings from this pass. F1/F2/F3 are
actionable fixes; F4 is a doc correction.

## Fix order (TDD)

Each fix lands with a failing regression test first, then the fix,
then test passes, one commit per finding.

1. **F1**: preserve `last_oracle_publish_time` in the partial
   CatchupAccrue rollback. Test: two successive partial-catchup
   calls with the same Pyth account → `last_good_oracle_slot`
   advances only once.
2. **F2**: reject Hyperp init when
   `permissionless_resolve_stale_slots > 0 AND mark_min_fee == 0`.
   Test: init with that combo → rejection.
3. **F3**: reject InitMarket when `new_account_fee == 0 AND
   maintenance_fee_per_slot == 0`. Test: init with both zero →
   rejection.
4. **F4**: update the `ForceCloseResolved` doc to match reality.
