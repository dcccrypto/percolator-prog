# Tiny-price format: sub-$0.000001 oracle prices no longer round to 0

Status: implemented on `fix/v22-tiny-price-format` (base `feat/v22-rc23-2026-10-22`).
Closes the tiny-price cases pinned by #707 (`tests/oracle_compose_edge.rs`).

## Upstream check

`aeyakovenko/percolator-prog` main `8b10d3b2` and `aeyakovenko/percolator` master
`827a125f`: no change to the oracle price format; upstream still reads every leg as a u64
E6 and rejects 0. No fix to port.

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
  dispatcher `read_oracle_price_e12`). A leg is valid if it is nonzero at E12 and its E6
  floor is `<= MAX_ORACLE_PRICE`. The old `*_e6` functions are thin wrappers with the old
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

Example: Pyth $3e-7 with `lot_exp = 6` publishes `300_000` (=$0.30 per 1e6 tokens);
at lot 0 it is still refused (no silent 0).

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
  gives 500_000, at lot 0 still `OracleInvalid`; finding 5 is 1 at lot 0 and 1_666_666 at
  lot 6 (rel err < 1%); `three_leg_at_max_bounds_no_overflow` now returns MAX (no
  intermediate gate).
* `tests/tiny_price_format.rs` (new): round trip, expo finer than E12, composite with lot,
  lot cap at MAX, leg range, three-leg U256 extremes, proptest lot 0 == old composition,
  proptest lot scales exactly, Hybrid / EWMA lot validation, and the #706 interaction
  (`clamp_toward_engine_dt`: at lot 0 a 1-tick price is frozen by the 1 bps cap while at lot 6
  it moves +50 per slot, so the remainder carry is not needed for lot markets).
* `tests/v22_wave_a.rs`: proptests updated for Hybrid now accepting a lot.

## Overlap with engine #357 and prog #706 / #710

Different problem, no duplicated logic, no storage clash:

* **Engine #357** (head `2544c27f`, `AssetStateV16.price_step_carry_bps_num`, +2 bytes per
  asset slot) and **prog #706** (head `1302b543`, persists
  `price_move_remainder_bps_num` on the crank) / **#710** (head `1c342ece`, resets that
  remainder on an EWMA mark target change) fix *motion*: under the 3%/slot cap a price
  below 34 atoms cannot move by a whole atom, so the sub-atom step carry has to persist.
* This PR fixes *representation*: a feed price below 1e-6 is read as 0 and refused before
  the engine ever sees it, and composite legs lose precision by being floored to E6 first.
* They are complementary. A lot market lifts the atom count (e.g. $3e-7 at `lot_exp = 6`
  is 300_000 atoms), so the cap-freeze region (< 34 atoms) is never reached and the
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

* Same-publish-time equivocation check compares the stored E6 floor; for a leg `< 1e-6`
  the stored value is 0 and the check is skipped (only the publish-time monotonicity
  holds). A follow-up could store E12 legs if a layout change is ever taken.
* Feeds with expo finer than -12 are truncated at E12 (tested).
* Off-chain consumers that assume price = per-token E6 will misprice lot markets until the
  SDK / indexer follow-ups land. No existing market changes.
