# DRAFT (not posted anywhere) — for Khubair's review

## Title
perf: decode market config shape only on per-leg trade reads

## Developer note
`read_market_trade_preflight` and `read_asset_effective_prices` decode the market config with
`try_to_runtime()`, which runs the full solvency-envelope check on every call. Both only read
`max_market_slots`, `max_portfolio_assets` and `max_trading_fee_bps`. In `TradeCpi` and
`BatchTradeCpi` this happens once per leg.

This change switches those two call sites to `try_to_runtime_shape()` (shape checks only).
The full envelope check still runs on every path that writes the config:
init (`validate_public_user_fund`), slot grow (full decode first; the engine only changes
`max_market_slots` and re-checks shape), and fee updates (touch the wrapper config only).
Details: `docs/cu/PLAN-tolycu.md`.

Diff: 2 call sites in `src/v16_program.rs` (+4/-2 lines).

## Measured (litesvm, built on da0dfad9, 3 runs each)
See `RESULT.md` for the table. Cells not filled there are "not measured".

## Kani
No Kani harness in `kani/`, `src/` or `tests/invariants` references either function (grep done), so no proof covers the changed lines.
