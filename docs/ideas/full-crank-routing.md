# Full crank routing through the canonical price path

Status: plan + branch test only (24 Nov 2026). Nothing merged, nothing deployed.
Branches: prog `agent/J-20261124-PROG-FULLROUTE` (base `feat/v22-rc23-2026-10-22` 0a630f3b),
keeper `agent/J-20261124-KEEPER-FULLROUTE` (dcccrypto/percolator-oracle-keeper, base `feat/v22-keeper-growth` b5779d1).

Background: #793 (939b2338) sends only stuck-price cranks through the path. The first full-routing try
(~/oneoff-1123progpin/RESULT.md) broke 21 tests: one path call commits at most 32 slots, our markets catch up
100-500 per crank, the devnet replays failed, and the price law changes from compounding to linear. This doc
is the full version: what changes, what it costs, what it means for prices and users, and how to ship it.

## 1. Program change

`crank_accrue_asset_view` (used by the permissionless crank, and so by liquidation, and by the ADL wind-down /
settle-rent refresh) now always does what upstream's crank does:

1. read the target (`hybrid_target_for_crank_view`, unchanged),
2. build the canonical one-slot path `canonical_accrual_path_for_target_view(.., target, slot_last + 1)`,
3. commit it with `accrue_asset_path_with_rent_to_not_atomic` (the engine re-derives and checks every step).

Removed: the single-segment branch (`effective_price_from_target` + `band_shape_price_view` +
`accrue_asset_to_with_rent_not_atomic`), the `stuck` / `anchor_off_mark` routing rule from #793, the carry drop
on the segment branch, and the now-unused `band_rent_accrual_inputs_view`. Net -97 lines in src.

After this the wrapper has no single-segment price accrual left: the crank and the zero-move funding hook
(trade path) are both path calls.

What one crank does now:

| | before (single segment) | after (path) |
|---|---|---|
| slots committed per crank, per asset | `min(gap, max_accrual_dt_slots)` (100-500 on our markets) | `min(gap, max_accrual_dt_slots, 32)` |
| price step | `floor(P_now * cap * dt / 1e4)` toward target, no carry | per slot `floor((anchor * cap + carry) / 1e4)`, carry kept |
| cap anchor | the current mark, every crank | `fund_px_last`: the mark when the target was staged; restarts only when the target changes |
| funding | one rate for the whole segment | sampled per slot along the path |
| result depends on crank cadence | yes (compounds per crank) | no |

A crank that leaves an asset short returns early (`bounded_market_catchup_only`, already in the code), so the
caller sends another crank at the same slot. Nothing else in the crank changes. The engine pin stays at
58466a0d (it already has the path API and #393).

Not changed here (separate items):
- builder same-side carry rule for engine #393 (the base's `v16_engine_pin_restarts_the_carry_on_a_same_side_target_change`
  tripwire is already red on 0a630f3b since #794 moved the pin; job J-20261124-PROG-FIX-LOWPINCARRY393 owns it);
- upstream's INV-045 catch-up staging rule ("on an exposed asset more than one window behind, a changed target
  waits"), not in our base yet. With full routing it matters more: a target change in the middle of a multi-crank
  catch-up restarts the anchor at that point. Port it next, with its tests.

## 2. Keeper change (percolator-oracle-keeper, v2.2 loop)

dcccrypto/percolator-keeper has no v2.2 branch; the v2.2 crank/catch-up lives in percolator-oracle-keeper
`feat/v22-keeper-growth` (src/cross-cluster/v22/loop.ts, positioned-refresh.ts), so the keeper branch is there.

1. Catch-up past 32 slots (multi-call). `catchupCrankCount(gap, maxDt)` counts in
   `crankWindowSlots = min(max_accrual_dt_slots, KEEPER_V22_CRANK_PATH_STEPS)` windows. Default 32 (full-routing
   wrapper); `0` = the old wrapper (window = `max_accrual_dt_slots`, every old behaviour byte for byte). Used by the
   v2.2 loop, the legacy planner (`planCrankTx`), the recovery cranker and the tag-106 rent hold, so all of them
   now send `floor(gap / 32)` bounded cranks before the accruing one.
2. Crank cadence. A 20 s cycle is ~50 slots, more than one 32-slot window, so in steady state every cycle starts
   one window behind. The old loop sent the catch-up and returned (round on the next cycle), which would skip the
   round on EVERY cycle. New: up to `KEEPER_V22_CATCHUP_TXS_PER_CYCLE` (default 2) paced catch-up txs, re-reading
   the market after each, and when it is inside one window the round runs in the same cycle on the fresh read.
   Keep CRANK_INTERVAL_MS at 20 s: per slot it is the cheapest shape (one bounded 32-step crank + one short full
   crank). Dropping to 10 s (25 slots, no catch-up) costs MORE CU (two full cranks of ~25 steps per 50 slots,
   about 311k vs 243k).
3. Retries. Already in place and kept: a catch-up refused by the program backs off 60 s; a transport failure (429)
   does not. New: a window boundary crossed while a catch-up lands is handled by the re-read + second catch-up tx
   in the same cycle instead of a failed round.
4. CU sizing. The loop sizes catch-up txs from a one-crank simulation (unchanged). The static fallback is now
   120k per crank under full routing (measured 108,574 for a bounded 32-step path, +10%), 45k for the old wrapper.
   So a catch-up tx holds ~10 cranks (1.3M budget) instead of 28.

## 3. What compounding -> linear means for prices and users

The law: while the target holds, the mark moves a fixed `anchor * cap / 1e4` atoms per slot (plus carry) from
the price the target was staged at. Before, each crank moved `cap * dt` of the CURRENT mark, so per-slot cranks
compounded, and the answer depended on how the keeper split slots into cranks.

Measured on the real BPF program (tests/v16_cu.rs, mark 1,000,000, cap 100 bps/slot, fixed target 2x):

| after 20 slots | base (single segment) | full routing |
|---|---|---|
| cranked every slot | 1,220,182 | 1,200,000 |
| every 5 slots | 1,215,506 | 1,200,000 |
| one crank | 1,200,000 | 1,200,000 |

Realistic caps (4-10 bps per slot, 400 ms slots), fixed target, cranked every slot:

| move | cap 10 bps: compounding | linear | cap 4 bps: compounding | linear |
|---|---|---|---|---|
| +20% | 183 slots (73 s) | 200 slots (80 s) | 456 (182 s) | 500 (200 s) |
| -20% | 223 slots (89 s) | 200 slots (80 s) | 558 (223 s) | 500 (200 s) |
| +50% | 406 slots (162 s) | 500 (200 s) | 1,014 (406 s) | 1,250 (500 s) |
| -50% | 693 slots (277 s) | 500 (200 s) | 1,733 (693 s) | 1,250 (500 s) |

So: after a big rise the mark reaches the oracle 9-23% later; after a big fall it reaches it 10-28% sooner.
Under 5% the two laws differ by less than 0.25% of price. Who notices:
- longs in a fall: the mark reaches the fallen oracle sooner, so a long that is only liquidatable at the new
  price is liquidated a little earlier (20% fall at 10 bps: 80 s instead of 89 s);
- shorts in a rise: the mark lags longer, so a short is liquidated a little later; the engine already charges
  the full target lag in maintenance (prior review, v16.rs target-lag penalty), so this is not a solvency hole;
- traders: the trade price and mark move at a constant atom rate instead of a slowly growing one. Small.
- When does it apply: only while the TARGET holds. A live feed that changes the target most slots restarts the
  anchor at the current mark each time, which is compounding again. Linear shows on authority-pushed marks,
  stale / soft-stale oracles, and catch-up after a gap.
- Funding is sampled per slot along the path. A catch-up across a pending mark checkpoint now charges the premium
  slot by slot (the old segment booked one rate, often 0, for the whole window). Totals no longer depend on how
  the slots are split (`v16_bpf_canonical_accrual_path_matches_regardless_of_call_split_*`).
- Low prices: the carry is kept on every crank, so a low mark under a small cap never freezes (the #793 bug class
  is gone everywhere, not only where the old step was 0).

## 4. Cost (CU, measured)

Same machine, cargo build-sbf --features devnet (platform-tools v1.52), tests/v16_cu.rs, real BPF in LiteSVM.
Base = 0a630f3b source, branch = 8a7378d7 source, the SAME (final) test file on both.
Guardrail: 325k per crank (`CRANK_CU_LIMIT`).

| | base | full routing |
|---|---|---|
| refresh crank | 54,108 | 49,572 (-4,536) |
| full 14-leg refresh crank | 20,446 | 17,582 (-2,864) |
| liquidation crank (final call) | 180,958 | 178,362 (-2,596) |
| malicious-oracle liquidation | 213,270 | 210,711 (-2,559) |
| zero-move funding close trade | 186,364 | 187,797 (+1,433) |
| catch-up 1 slot | 1 crank, 85,477 | 1 crank, 82,907 |
| catch-up 32 slots | 1 crank, 88,870 | 1 crank, 176,874 |
| catch-up 100 slots | 1 crank, 88,987 | 4 cranks, max 108,574, total 420,930 |
| catch-up 500 slots | 1 crank, 88,987 | 16 cranks, max 141,956, total 1,770,427 |
| multi-asset X1CAP n=4 worst crank (own limit 1.26M) | 330,554 | 327,685 |

(catch-up market: max_accrual_dt_slots 500, cap 10 bps, open interest, target off the mark.)

Reading it:
- Every single crank stays under 325k. The most expensive single-asset crank is a full crank with a 32-step path
  (~177k). A bounded catch-up crank (returns before the engine dispatch) is ~109k for 32 steps.
- Per path step ~3.0k CU (82,907 for 1 step, 176,874 for 32).
- 1-step cranks (the refresh / liquidation rows) get slightly CHEAPER: the path skips the segment price +
  band shaping. Only catch-up gets more expensive, and it is now ceil(gap / 32) cranks instead of one.
- Risk: a multi-asset crank hints every asset; after a 32-slot gap each hint is a 32-step path. Estimate for 4
  assets: ~328k + 4 x ~94k = ~700k. Under its 1.26M limit, above 325k. Not measured on the branch; the keeper sizes
  multi-asset catch-up from a simulation, so it would pack fewer per tx, not fail.

## 5. Migration and devnet impact

- Order: deploy the wrapper and flip the keeper together. Keeper with the new default (32) against the OLD
  wrapper sends catch-up cranks past the gap (the extra one settles the LP alone). Keeper in legacy mode (0)
  against the NEW wrapper sends too few, so every round's accrue crank stops short and its refreshes are refused
  (Custom 22) until the next cycle. Plan: ship the keeper with `KEEPER_V22_CRANK_PATH_STEPS=0` set in Railway,
  deploy the wrapper, then unset it (or set 32) right after the upgrade lands. One cycle of degraded rounds at most.
- Accounts: no layout change, no new fields. The path uses the existing `price_move_remainder_bps_num` carry in the
  oracle profile and `fund_px_last` in the engine. In-flight state: an asset whose `fund_px_last` differs from its
  mark (after a #793 path walk) continues from that anchor: same as the #793 path branch today.
- Outage / idle recovery: an hour behind = 9,000 slots = 281 bounded cranks + 1 (was 18-90 at windows 500-100).
  At ~10 per tx that is ~28 txs per market, 2 per cycle = ~14 cycles (~5 min) for one market. With the 1.5 s
  cross-market pacing (8 starts per 12 s cycle budget) 20 markets an hour behind need ~70 cycles (~23 min), was
  ~1-3 min. Liquidations on a market wait until it is inside one window. Raise KEEPER_V22_CATCHUP_TXS_PER_CYCLE /
  lower the spacing during a recovery if the RPC key allows it.
- Devnet replays: earn_drain_replay replays devnet history whose market has max_accrual_dt_slots = 100; with a
  32-slot window those replays need multi-crank catch-up; see section 6 for what the tests needed.
- Fees: steady state ~2.7x CU per market per cycle (one bounded 32-step + one ~18-step full crank, ~243k, vs one
  ~89k segment crank). Still one tx per cycle if both fit (they do: 243k << 1.4M).
- Rollback: redeploy the previous wrapper and set `KEEPER_V22_CRANK_PATH_STEPS=0`.

## 6. Tests

Full suite (same env as CI's `build + test`, allowlist tests/KNOWN_FAILING.txt, 21 entries):
- before the test fixes (8a7378d7): 2,343 passed / 55 failed: the 21 allowlisted + 28 new (the set below + the tripwire).
- at 76a67767 (program + fixes except the three replay copies): local 2,370 / 28, GitHub CI 2,374 / 27; new = only
  swordcat/backpack in the three replay copies (+ the tripwire, locally only; CI passes it). Fixed in 46b8b622.

New, prog (tests/v16_cu.rs; all three FAIL on the base, pass on the branch):
- `v16_bpf_fullroute_catch_up_past_32_slots_takes_ceil_gap_over_32_cranks`: gaps 1/32/100/500 on a 500-slot market
  take 1/1/4/16 cranks, each crank that stops short commits exactly 32 slots, each under 325k (base: 1 crank each).
- `v16_bpf_fullroute_price_law_is_linear_from_the_anchor`: +/-10,000 atoms per slot from 1,000,000 at 100 bps, up
  and down, every slot checked (base: compounding).
- `v16_bpf_fullroute_price_does_not_depend_on_crank_cadence`: 1/5/20-slot cadence all land on 1,200,000
  (base: 1,220,182 / 1,215,506 / 1,200,000).

New, keeper (src/cross-cluster/v22/fullroute-catchup.test.ts, 9 tests; the 3 loop tests FAIL on the old loop):
window math, env parsing, static CU estimate, steady state (50-slot gap: catch-up then the round in the same cycle),
a window boundary crossed while landing (second catch-up, then the round), far behind (2 catch-up txs, no round),
legacy mode unchanged.

The tests that full routing broke, and what was done (each reason is also in the test):

| test(s) | why it broke | fix |
|---|---|---|
| earn_drain_replay and its three copies sec_v22a_r3, sec_v22a_replay, sec_v22d_replay: swordcat_earn_loss_bounded_by_open_claims, backpack_winner_keeps_k_gain_and_no_unowned_residual | replays the old keeper's cranks; one crank no longer covers the 100-slot window, trades then refused (121) | harness `fullroute_keeper_catch_up`: send the keeper's floor(lag/32) bounded cranks first (what the new keeper does). 49/0, 46/0, 30/0, sec_v22d see RESULT |
| indep_p3_f14q (18: C-7, race_*, ins_*_relabel_*, s1_5, rehearsal23, roundtrip, atomic_one_tx...) | 500-slot market, one crank per 520-slot warp | crank helper keeps the OLD one-crank meaning: floor(min(lag, window)/32) bounded cranks, and no settling crank when lag > window. 41/0 |
| p2b_adl_wind_down: tag104_arms_then_waits_for_the_episode_bound, tag104_refuses_a_lagging_or_stale_mark | catch-up loops sized 64/256 calls for the 9,000-slot episode bound at the old window | bound 1,024 (loops stop when nothing moves). 9/0 |
| p3_resolved_lock: p3_diluted_receipts_without_post_101_topup_stay_reserved, p3_legacy_orphan_injected_while_live_is_repaired_by_the_refresh_crank, p3_open_receipt_reserved_while_seniors_exit_and_claimable_later | window 20 (unchanged), but the pinned fixture value (d1 backing at resolve) follows the price path | expectation 4,875 -> 4,972 (`LEGACY_175_D1_BACKING`). 17/0 |
| v16_wrapper: liquidation_fee_policy_splits_retained_penalty_to_cranker, liquidation_reward_account_is_optional_and_absent_keeps_fee_in_insurance | price 100 x cap 3 bps over 100 slots in ONE crank; the path covers 32 | 3 bounded catch-up cranks first; the path lands on 103 as before, fee asserts unchanged |
| v16_cu: permissionless_crank_computes_funding_from_internal_mark_premium | 2nd slot 1,210,000 (compounding) -> 1,200,000 (linear) | expectation updated |
| v16_cu: zero_move_funding_accrues_across_trade_without_crank, canonical_accrual_path_matches_regardless_of_call_split_* | setup crank assumed a 50-slot segment and zero setup funding | window 32 / cap 40 bps / setup at 33; funding checked as deltas from the post-setup state |
| inv_045 v16_attack_authority_reversal_after_a_long_walk_* | asserted this fork's anchor follows the mark; it said "re-derive if upstream's path is adopted" | now asserts upstream's form: anchor stays at the walk start; the reversal bound still holds |
| v16_cu v16_engine_pin_restarts_the_carry_on_a_same_side_target_change | already RED on the base (pin moved past engine #393 in #794) | not touched; owned by J-20261124-PROG-FIX-LOWPINCARRY393 |

Finding (not caused by this change, needs its own look): if the C-7 / S1.5 worlds crank the trader the way a real
keeper does (catch up AND settle the trader while the price moves), `c7_seniors_exhausted_winddown_completes`
(winner paid 2,346,100 of 2,396,100 while a senior got 51,353 back) and
`s1_5_tag100_relabels_the_residual_before_converting_the_vault_lp_claim` ("an unowned residual sits in the vault")
fail on the BASE program too (evidence/iso1-base-f14q.txt vs iso2-base-nohelper.txt). The suite only passes because
its single crank per warp never settles the trader during the move.
