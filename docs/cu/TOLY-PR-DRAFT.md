# DRAFT (not posted anywhere) — for Khubair's review

## Title
perf: shape-only config decode on the trade read path

## Developer note
`read_market_trade_preflight` and `read_asset_effective_prices` (`src/v16_program.rs`, ~2787 and ~2819) decode the
market config with `try_to_runtime()`, which also runs the full solvency-envelope check. Both only use
`max_market_slots`, `max_portfolio_assets` and `max_trading_fee_bps`, so the envelope check is wasted work there.
`BatchTradeCpi` calls `read_asset_effective_prices` once per transaction (it parses the config once for all legs),
and `TradeCpi` calls `read_market_trade_preflight` once, so the check was being paid once per transaction.

This change switches those two call sites to `try_to_runtime_shape()` (shape checks only).
The full envelope check still runs on every path that writes the config:
init (`validate_public_user_fund`), slot grow (full decode first; the engine only changes
`max_market_slots` and re-checks shape), and fee updates (they touch the wrapper config only).
Details: `docs/cu/PLAN-tolycu.md`.

Diff: 2 call sites in `src/v16_program.rs` (+4/-2 lines).

## Measured
litesvm `BatchTradeCpi` probe (`cu_probe_trade_cpi_legs`), 3 runs x 3 samples per leg count, median compute units:

| legs | before | after | change |
|---|---|---|---|
| 1 | 154240 | 143576 | -10664 (-6.9%) |
| 2 | 227048 | 216384 | -10664 (-4.7%) |
| 4 | 316672 | 307508 | -9164 (-2.9%) |

The best (min) samples drop by 10664 CU at every leg count. So the saving is a flat ~10.7k CU per transaction,
not per leg; the percentage shrinks as legs are added because the base cost grows. Sample jitter is about 1.5k CU; a later single rerun of the 1-leg case gave 152740 -> 145076 (median), 143576 (min), so read the saving as roughly 8-10.7k CU.

Repro: build the program and the `auth_matcher` fixture with `cargo build-sbf`, then
`cargo test --test v16_cu cu_probe_trade_cpi_legs -- --ignored --nocapture` and read the `CUPROBE` lines,
once on the parent commit and once on this one.

Not measured: full suite, fuzz gates. The probe also panics at 16 legs in market init
(`tests/v16_cu.rs:1203`, `Custom(14)`), identically before and after; unrelated to this change.

## Kani
No Kani harness in `kani/`, `src/` or `tests/invariants` references either function (grep done), so no proof covers the changed lines.
