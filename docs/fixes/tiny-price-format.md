# Tiny-price format: twelve-decimal oracle legs (a leg below $0.000001 is refused, INV-038)

Status: implemented on `fix/v22-tiny-price-format` (base `feat/v22-rc23-2026-10-22`).
Closes the tiny-price cases pinned by #707 (`tests/oracle_compose_edge.rs`).

## Upstream check

Superseded: upstream b2f3ffe7 (#486, #462) later ported the twelve-decimal legs with a stricter
admissibility rule, adopted here; see "Tightened" below. The original check follows.

`aeyakovenko/percolator-prog` main `8b10d3b2` and `aeyakovenko/percolator` master
`827a125f`: no change to the oracle price format; upstream still reads every leg as a u64
E6 and rejects 0. No fix to port.

## Tightened: a leg below one e6 tick is refused (INV-038, upstream b2f3ffe7)

Superseding part of this note. Upstream aeyakovenko/percolator-prog `b2f3ffe7` (PR #486, issue
#462) reads every leg at six and twelve decimals; the composite is computed from the twelve, and
"the six-decimal value is what is stored per leg and what decides whether a feed is admissible".
We adopt that rule (Khubair, 21 Nov 2026): `leg_e12_in_range` now requires the six-decimal floor
of a leg to be in `1..=MAX_ORACLE_PRICE`, so a leg below $0.000001 is `OracleInvalid` at the
reader and inside the composition, alone or in a composite, at every lot exponent.

What stays from this note: E12 legs (a small but admissible leg such as 0.00041 composes from all
its digits: the #462 tuples give 61,500 and 61,499), the single exact U256 rational floored once,
no per-leg intermediate gate, and the lot exponent applied to the final price.

What changes: the sub-tick examples below (each marked *[superseded by INV-038]*) (Pyth `expo = -10, price = 5_000` at `lot_exp = 6`;
the E12 legs of 10^-12 .. 10^-7) are no longer readable. A token priced below one e6 tick needs a
feed quoted per larger unit (or an AuthMark market) instead. The "same-publish-time equivocation"
open risk below no longer applies to new readings (a stored leg is never 0).

Tests: `tests/inv_038_composite_leg_precision.rs` (the rule, the #462 tuples, the leg scaling for
every exponent -18..=18) and the BPF cases in `tests/v16_cu.rs`
(`v16_bpf_composite_leg_below_one_e6_tick_is_rejected`, the tuples through ConfigureHybridOracle
and a crank, and the finer-report compute bound). `tests/tiny_price_format.rs` and
`tests/oracle_compose_edge.rs` finding 1 now pin the refusal.

## Current representation and its limits

* Every price is a u64 in quote-E6 per base unit, `1 ..= MAX_ORACLE_PRICE` (1e12, $1M).
* Each leg reader (`read_pyth_price_e6`, `read_switchboard_price_e6`,
  `read_chainlink_price_e6`) scales the feed to E6 and **floors**; `< 1e-6` becomes 0 and
  is rejected (`OracleInvalid`). Pyth at `expo = -10`, `price = 3_000` ($3e-7, many
  memecoins) cannot be read at all.
* `compose_price_e6` multiplied the already-floored E6 legs and also gated every
  *intermediate* quotient to `1 ..= MAX`, so a valid product (tiny × large, or a two-step
  cross that dips below 1e-6 mid-way) was refused even when the final price is in range.
* Precision: a leg at 1.5e-6 is floored to 1e-6 (33% error) before composition.
* The engine and every account field consume the E6 u64; changing that type is a
  slab/ABI break.

## Options

1. **Widen the engine price to u128 / E12.** Exact, but changes `AssetStateV16`, every
   cert, every keeper / SDK / indexer decoder; a full migration. Rejected for v2.2.
2. **Per-market price exponent (new field).** Needs a new profile field and layout bump.
3. **Re-use the existing per-market `lot_exp`** (profile byte +19, `LOT_EXP_MAX = 15`,
   immutable, set at InitMarket) as the price scale: the engine price is quote-E6 per
   `10^lot_exp` base units. Read legs at E12 internally, compose exactly in U256, and apply
   `10^lot_exp` once at the end. No layout change.
4. Floor to 1 instead of 0. Silently wrong prices. Rejected.

## Recommendation (implemented): option 3

* Leg readers have E12 forms (`read_pyth_price_e12` scale `expo + 12`,
  `read_switchboard_price_e12`, `read_chainlink_price_e12` via `scale_decimal_to_e12`,
  dispatcher `read_oracle_price_e12`). A leg is valid if its E6 floor is in
  `1 ..= MAX_ORACLE_PRICE` *[INV-038; #711 accepted any leg non-zero at E12]*. The old `*_e6` functions are thin wrappers with the old
  semantics (still reject an E6 floor of 0), so every other caller is unchanged.
* `compose_price_e12_to_e6(legs_e12, flags, invert, unit_scale, lot_exp)` keeps one exact
  U256 rational through all legs, invert (`num' = den * 1e24`), `unit_scale`, and the lot
  (`* 10^lot_exp`), and floors **once**. No intermediate gate; the final price must be
  `1 ..= MAX`. `lot_exp > LOT_EXP_MAX` is `EngineInvalidConfig`.
* `read_external_price_e6` (config path) uses lot 0, so it is bit-identical to the old
  composition whenever the old one succeeded (proptest). `read_external_price_e6_profile`
  uses `profile_lot_exp(profile)`.
* `lot_exp != 0` is now also allowed for `HYBRID_AFTER_HOURS` (external feed + after-hours
  fallback), since tiny-price assets need an external feed. EWMA still refuses it.

*[Superseded by INV-038: Pyth $3e-7 is refused at every lot.]* Example under #711: Pyth $3e-7
with `lot_exp = 6` published `300_000` (=$0.30 per 1e6 tokens); at lot 0 it was refused.

## Layout and migration impact

None. No new field, no size change: `lot_exp` already lives in
`AssetOracleProfileV16._padding0[0]`. Stored `oracle_leg_prices_e6` keep their E6 meaning
(the E6 floor of the leg). Existing markets have lot 0 and compose identically. A tiny-price
market must be created with `lot_exp` at InitMarket (it is immutable; today only asset 0
via the growth forms can set it), and `LOT_PRICE_FLOOR_E6` (1e7) still binds growth
launches.

## CU impact

U256 multiply/divide replaces u128 in composition (at most 3 legs, plus invert, unit and lot
terms), and an extra divide per leg for the E6 floor. Measured with LiteSVM
(`tests/v16_cu.rs` `v16_bpf_composite_oracle_rounds_once_not_per_leg`, 3-leg DIVIDE_LEG2|DIVIDE_LEG3
configure): 12_881 -> 15_582 CU (+2_701). That is the worst case (3 legs); a 1-leg read pays
one U256 mul/div chain. Far below the 1.4M per-transaction limit.

## Tests

* `tests/oracle_compose_edge.rs` (#707): findings 2, 3, 4 un-ignored; finding 1 at lot 6
  gave 500_000 under #711 *[INV-038: now `OracleInvalid` at every lot]*; finding 5 is 1 at lot 0 and 1_666_666 at
  lot 6 (rel err < 1%); `three_leg_at_max_bounds_no_overflow` now returns MAX (no
  intermediate gate).
* `tests/tiny_price_format.rs` (new): round trip, expo finer than E12, composite with lot,
  lot cap at MAX, leg range, three-leg U256 extremes, proptest lot 0 == old composition,
  proptest lot scales exactly, Hybrid / EWMA lot validation, and the #706 interaction
  (`clamp_toward_engine_dt`: at lot 0 a 1-tick price is frozen by the 1 bps cap while a
  $0.000005 token at lot 5 (500_000 e6) moves +50 per slot, so the remainder carry is not
  needed for lot markets).
* `tests/v22_wave_a.rs`: proptests updated for Hybrid now accepting a lot.

## Overlap with engine #357 and prog #706 / #710

Different problem, no duplicated logic, no storage clash:

* **Engine #357** (head `2544c27f`, `AssetStateV16.price_step_carry_bps_num`, +2 bytes per
  asset slot) and **prog #706** (head `1302b543`, persists
  `price_move_remainder_bps_num` on the crank) / **#710** (head `1c342ece`, resets that
  remainder on an EWMA mark target change) fix *motion*: under the 3%/slot cap a price
  below 34 atoms cannot move by a whole atom, so the sub-atom step carry has to persist.
* This PR fixes *representation*: composite legs lose precision by being floored to E6 first
  (and, under #711 only, a feed price below 1e-6 was read; *[INV-038: it is refused again]*).
* They are complementary. A lot market lifts the atom count (e.g. $0.000005 at `lot_exp = 5`
  is 500_000 atoms), so the cap-freeze region (< 34 atoms) is never reached and the
  remainder carry is irrelevant for it; lot-0 markets with prices of 1..33 atoms still need
  #357 / #706 / #710. `tests/tiny_price_format.rs` pins this interaction through
  `clamp_toward_engine_dt` (unchanged by #706 / #710).
* Storage: this PR uses the existing `lot_exp` byte (`_padding0[0]`); #706 uses the existing
  dedicated `price_move_remainder_bps_num` field; #357 adds an engine field. No byte is
  shared. Textual trial merges of this branch with #706 and #710 (`git merge-tree`) are
  clean. Only the prog `ENGINE_CI_SIBLING` pin moves when #357 lands; this PR does not
  depend on it.

## SDK, keeper, indexer, app (follow-up PRs, not built here)

* **SDK**: price and size helpers must be lot-aware (`price_per_token = price_e6 / 1e6 /
  10^lot_exp`, size in lots); InitMarket / profile encoders must allow lot on Hybrid.
* **Keeper**: Manual / AuthMark pushes and marks must be in per-lot units for lot markets;
  liquidation and crank thresholds are unaffected (engine units).
* **Indexer**: decode `lot_exp` from the profile and store/display per-token prices.
* **App**: show per-token price and token sizes (divide/multiply by `10^lot_exp`).

## Open risks

* Same-publish-time equivocation: under #711 the check compared the stored E6 floor, and for
  a leg `< 1e-6` the stored value was 0 and the check was skipped. INV-038 narrows this (a leg
  `< 1e-6` is refused, so a stored leg is never 0) but does not close it: the check still
  compares only the E6 floor, so two same-publish-time readings of one leg that differ by
  less than one tick (e.g. 0.00041000 vs 0.00041099) both pass and can compose to slightly
  different targets. Follow-up: store E12 legs and compare those.
* Feeds with expo finer than -12 are truncated at E12 (tested).
* Off-chain consumers that assume price = per-token E6 will misprice lot markets until the
  SDK / indexer follow-ups land. No existing market changes.
