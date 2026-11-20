# J-20261119-PROG-TOLY-CUSHAPEd (partial, as of 10:10 GMT 20 Nov)

Patch: 2 call sites in src/v16_program.rs switched to try_to_runtime_shape (commit d532c2da). Writers verified keep full validation (docs/cu/PLAN-tolycu.md). Head SBF built OK (/tmp/jtolycu-head.so differs from base .so).

| legs | base CU (3 runs) | head CU (3 runs) |
|---|---|---|
| 1 | not measured | not measured |
| 2 | not measured | not measured |
| 4 | not measured | not measured |

Suite + 2 fuzz gates head vs base: not measured.
Kani: grep of kani/, src/, tests/invariants finds no harness referencing read_market_trade_preflight or read_asset_effective_prices.
Why: host load 40-47; compiling the v16_cu test binary has run 2h+ under with-lock without finishing.
Driver still running: ~/agent-work/toly-cushape/d/drv.sh (progress.txt, *.log). No PR opened, nothing posted anywhere.
