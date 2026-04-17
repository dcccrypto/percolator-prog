# Phase 20 — Perps-Specific Attack Scenarios

Date: 2026-04-17
Scope: 8 perps-native attack scenarios probed against on-chain code.
Format: attack setup, guard (file:line), residual risk.

Absolute paths referenced:
- `/Users/khubair/percolator-prog/src/percolator.rs` (program, tag dispatch, handlers)
- `/Users/khubair/percolator/src/percolator.rs` (RiskEngine, accrual, liquidation)
- `/Users/khubair/percolator/THREAT_MODEL.md` (Phase 5 admin enumeration)

---

## 1. Self-sandwich for risk-free funding income

**Setup:** attacker opens a long on account A and an equal short on account B (same market, same signer / two owners they control) right before funding accrual. Idea is to "capture" funding from both sides.

**Guard:** Funding is a market-level accrual, not a pairwise P2P transfer. `accrue_market_to` moves value between *sides* via `adl_coeff_long` / `adl_coeff_short` applied to each account's effective position (`percolator/src/percolator.rs:1667-1696`). A long + equal short held by one actor has zero net effective position; whatever one account receives the other pays. `KeeperCrank` calls `keeper_crank_not_atomic` which enforces one-and-only-one accrual via `accrue_market_to` at step 5 (`percolator/src/percolator.rs:3856-3857`). TradeCpi is also self-trade-safe: `if user_idx == lp_idx { return Err(...) }` (`percolator-prog/src/percolator.rs:7411-7413`). The "trader trades with themselves via LP" path cannot settle zero-sum profit because matcher-CPI `execute_match` binds `lp_idx != user_idx` and the LP side receives inventory (not a pass-through).

**Verdict:** Blocked.
**Residual:** trading-fee rebates only (attacker still pays `trading_fee_bps` twice; no net extraction).

---

## 2. Oracle manipulation via flash-loan DEX pool for Hyperp

**Setup:** flash-loan into the PumpSwap/Raydium/Meteora pool bound as the Hyperp oracle source, call `UpdateHyperpMark` with distorted pool state, trade against the displaced mark, reverse flash loan.

**Guards** (all in `handle_update_hyperp_mark`, `percolator-prog/src/percolator.rs:12938-13180`):
- CPI rejection (`get_stack_height > TRANSACTION_LEVEL`) at `:12949-12954` — cannot bundle mark update with trade.
- `MIN_HYPERP_UPDATE_INTERVAL_SLOTS = 25` at `:12999-13002` — rate-limits manipulation cadence.
- `MIN_DEX_QUOTE_LIQUIDITY = 2_000_000 USDC` at `:13097-13104` ENFORCED on the source pool via `read_dex_price_with_liquidity` before the EMA writes, so thin-pool pushes revert.
- Pool-key pinning (`config.dex_pool`) at `:13006-13016` — attacker cannot substitute a different pool.
- Owner check (PUMPSWAP/RAYDIUM/METEORA program ids) at `:13018-13025`.
- Mint-binding to `collateral_mint` at `:13030-13086`.
- `MAX_HYPERP_DEVIATION_BPS = 500` (5% band) clamp vs prev_mark at `:13112-13129`.
- Circuit breaker `DEFAULT_HYPERP_PRICE_CAP_E2BPS` always enforced even if admin cap=0 (`:13147-13157`), plus `MARK_PRICE_EMA_ALPHA_E6 = 2 / 72001` gives ~8-hour halflife (`:121-123`).

**Verdict:** Blocked per-push.
**Residual:** an attacker with persistent capital to keep the pool displaced across many 25-slot intervals can drag the EMA at ≤5% per step and ≤1%/slot cap, but each step is rate-limited to the cap, and the bound halflife prevents lasting injection from a single flash-loan.

---

## 3. Sandwich the keeper crank

**Setup:** mempool-observe a `KeeperCrank` tx, front-run with a trade that gains from the post-crank state (funding / liquidation cascade / ADL).

**Guard:** `handle_keeper_crank` is top-level (`percolator-prog/src/percolator.rs:6964-7126`). Per-slot accrual is idempotent: same-slot `accrue_market_to` short-circuits at `percolator/src/percolator.rs:1693-1696`, so a front-run trade in the same slot accrues the same market state the attacker "sees." Funding direction is set by `compute_current_funding_rate_e9` off `mark_ewma` vs `last_effective_price_e6` (`percolator-prog/src/percolator.rs:5471-5494`) and is public. Liquidations are `FullClose` at oracle price (`:7705-7768`) — no price discovery advantage. ADL candidates are required to be below maintenance margin at `percolator/src/percolator.rs:3898-3909` so a same-slot trade cannot opportunistically "upgrade" a candidate.

**Verdict:** Blocked in terms of extractable value from cranking.
**Residual:** the observer learns which candidates are queued; a user whose position is marginal could deposit to escape before the crank lands (classical MEV mitigation — not a protocol loss).

---

## 4. Stale Pyth cliff

**Setup:** push a trade at the staleness boundary, then withhold the next crank until a new Pyth update creates a divergence.

**Guard:** the staleness check is `if age < 0 || age as u64 > max_staleness_secs` (`percolator-prog/src/percolator.rs:2994-2999`), a strict `>` cutoff — `age == max_staleness_secs` is still accepted. `read_price_and_stamp` (`:5376-5393`) re-invokes this on every read, so a trade landing "just fresh" writes the accepted Pyth sample into `last_oracle_price` via `accrue_market_to` at `percolator/src/percolator.rs:1692-1730`. The next crank that comes after Pyth advances re-accrues at the newer price — `delta_p` flows through `A_long * delta_p` and `A_short * delta_p` and is paid out of/into account reserves. Any "divergence" is absorbed by the engine's mark-to-market, not captured by the attacker.

**Verdict:** Blocked for extractable divergence.
**Residual:** at the exact boundary slot the accepted price is any value within the conf-filter band, so a Pyth publisher anomaly still lands. Mitigation lives upstream of the program (`conf_filter_bps` at `:3001-3008`).

---

## 5. Self-liquidation bounty

**Setup:** user positions themselves just below maintenance margin, then liquidates themselves via a second account to capture the liquidation fee.

**Guard:** there is no "liquidator bounty" at all — `liquidate_at_oracle_internal` routes the full fee into the insurance fund via `charge_fee_to_insurance` at `percolator/src/percolator.rs:3751` and `:3788`, not to the caller. `handle_liquidate_at_oracle` (`percolator-prog/src/percolator.rs:7705-7778`) requires only that accounts[0] be a signer (`:7712`); there is no same-owner check because one is not necessary — the fee recipient is the protocol, not the caller.

**Verdict:** Blocked by architecture (no bounty).
**Residual:** the liquidator pays CU fees for the transaction; the victim pays `liquidation_fee_bps` into insurance. No extractable fee path exists for a self-liquidator.

---

## 6. Insurance fund drain via repeated sub-threshold ADL

**Setup:** many small losers, each individually below `max_pnl_cap`, collectively drain insurance faster than LP vault top-ups.

**Guard:** the `max_pnl_cap` check is NOT a per-account threshold — it is evaluated against global `engine.pnl_pos_tot` (`percolator-prog/src/percolator.rs:11379-11390`), which is the aggregate positive PnL across all accounts (`percolator/src/percolator.rs:401, :1029-1143`). ADL cannot execute at all unless insurance is already depleted (`:11367-11374`, "InsuranceFundNotDepleted"). Losses themselves flow through `settle_losses` + `charge_fee_to_insurance` which only adds to insurance; they do not drain it. Insurance drain paths are: admin `WithdrawInsuranceLimited` (rate-limited), ADL pnl top-ups for winners, and the dust-forgive on resolve.

**Verdict:** Blocked as described.
**Residual:** if `max_pnl_cap` is set high (or 0 = disabled), ADL runs every time insurance goes empty; the cumulative winners-hit is bounded by `execute_adl_not_atomic` budget per invocation. A persistent flow of small losers does not bypass the global aggregate check.

---

## 7. Replay attack on TradeCpi nonce / cached matcher response

**Setup:** capture a matcher return-data buffer from a successful trade; replay to force Percolator to accept the same decision twice.

**Guard:** per-tx nonce stored at `_reserved[0..8]` in the slab header, read before CPI and advanced only on success. `read_req_nonce`/`write_req_nonce` at `percolator-prog/src/percolator.rs:2415-2427`. Nonce gen at `:7400-7402` via `nonce_on_success` (overflow → error). Matcher ABI return must echo `req_id`, `lp_account_id`, `oracle_price_e6`, and `exec_size`; `abi_ok` checks all four fields at `:7537-7548` (see also `verify::abi_ok` at `:560-630`). `req_id` is monotonic u64 from the slab nonce, so a replayed matcher buffer from a prior trade will have a stale `req_id` and hard-reject at `:7547-7548`. Additionally, a cached matcher context is overwritten by the fresh CPI before the return-data read (`:7532-7535`); no cross-tx context reuse is possible. FNV `lp_instance_id` at `:7457-7468` further binds to current LP state.

**Verdict:** Blocked.
**Residual:** matcher programs themselves must not issue two returns for one req_id (they are trusted code paths — see THREAT_MODEL line 54-63).

---

## 8. Admin key compromise blast radius (post Phase-E two-step + Phase G oracle removal)

**Setup:** single admin key is compromised; enumerate what attacker does in one transaction.

**One-tx capabilities** (all guarded by `require_admin`):
- `UpdateConfig` (tag 14, admin-only funding knobs)
- ~~`SetOracleAuthority` (tag 16)~~ — **PERMANENTLY REMOVED in Phase G (commit 4ab59f0).** Tag now returns `InvalidInstructionData`. Markets read live oracle (Pyth/Chainlink) or DEX-fed Hyperp EWMA only.
- ~~`PushOraclePrice` (tag 17)~~ — **PERMANENTLY REMOVED in Phase G (commit 4ab59f0).** Tag now returns `InvalidInstructionData`. Hyperp bootstrap moved to first-touch DEX seeding inside `UpdateHyperpMark`.
- `ResolveMarket` (tag 19) — Phase G rewrite: settlement price comes from live Pyth/Chainlink read at resolution time, not from a pushed price. Falls back to `last_effective_price_e6` only if the oracle is dead. Blocked while paused.
- `WithdrawInsurance` / `WithdrawInsuranceLimited` — require RESOLVED AND `num_used_accounts == 0`; cannot drain while users exist.
- `Pause/Unpause`, `SetMaxPnlCap`, `SetDispute*`, `SetLpCollateral*`.
- `UpdateAdmin` — Phase E. In the two-step case the admin can only *set* `pending_admin`; the rotation only completes when the proposed key signs `AcceptAdmin`. Burn path (`new_admin == default`) requires both `permissionless_resolve_stale_slots` AND `force_close_delay_slots` to be nonzero so burning cannot brick funds.

**Confirmed reduction:** a single compromised key cannot rotate admin to an attacker key atomically — the attacker must also produce an `AcceptAdmin` signature from the target key. `WithdrawInsurance*` is gated behind resolve + all-accounts-closed, so a single-tx drain is not reachable. **The previous sharpest single-tx attack — `PushOraclePrice` + `ResolveMarket` — is no longer reachable: the program rejects tag 17 unconditionally.** Settlement is now an admin-triggered call to the live oracle, not an admin-controlled value. See THREAT_MODEL.md:21-35 for the authorized-capabilities enumeration.

**Verdict:** Blast radius reduced per Phase E + Phase G. Admin-driven oracle drift (the Phase G motivator) is fully closed.
**Residual risks:** (a) admin can pause markets indefinitely (DoS, not theft — recovery via Squads multisig); (b) `SetMaxPnlCap` can be set to force/skip ADL; (c) admin can still call `ResolveMarket` at any moment, locking settlement at whatever the live oracle reports — but the price source itself is no longer admin-controlled. Mitigation for residual admin powers: Squads multisig migration (THREAT_MODEL.md:35).

---

## Summary

- All 8 scenarios are blocked by in-program guards with clear file:line citations.
- Scenario 8's "admin oracle drift" residual risk is **fully closed by Phase G** (commits 4ab59f0 + 996b9e1): tags 16 and 17 permanently removed, ResolveMarket now reads the live oracle directly. Remaining admin powers (pause, ADL toggle, resolve trigger) are operational rather than oracle-trust surfaces and are mitigated by Squads multisig migration per THREAT_MODEL.md.
- No novel exploit path surfaced during this review.

## Open inspection targets for a follow-on phase:
- `execute_adl_not_atomic` budget interaction with repeated calls in the same tx (not probed here).
- `ResolveDispute` accept=1 path under admin compromise (`percolator-prog/src/percolator.rs:10626+`).
- Matcher programs' own nonce handling (out of scope — external code).
