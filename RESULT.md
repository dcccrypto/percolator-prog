# J-20261120-PROG-TOLY-CUSHAPEe (final quiet-slot run, 21 Nov 03:40-04:00 GMT)

Patch: d532c2da (2 call sites in src/v16_program.rs moved to try_to_runtime_shape). Nothing else changed.

## Binaries
- head: /tmp/jtolycu-head.so, built from d532c2da on 20 Nov (sha256 2717828…)
- base: /tmp/jtolycu-base-da0dfad9.so (sha256 3fcd1a7d…). da0dfad9 has the same src/, Cargo.toml and Cargo.lock as
  24bf949b, the parent of d532c2da (checked with `git diff --stat da0dfad9 24bf949b -- src Cargo.toml Cargo.lock`, empty).
- auth_matcher.so rebuilt in this worktree (`cargo build-sbf --tools-version v1.52 -j 4`, exit 0).

## Command (driver: docs/cu/final-run/drv.sh, raw output: docs/cu/final-run/progress.txt)
Each run was this, inside `node ~/agent-worker/with-lock.mjs reserved --wait-min 120 -- bash -c ...`. Head ran first, then base:
`PERCOLATOR_FUZZ_SBF=<so> CARGO_TARGET_DIR=/tmp/jtolycu-target cargo test -j 4 --test v16_cu cu_probe_trade_cpi_legs -- --ignored --nocapture`
Each run takes 3 samples per leg count (fresh env each time), so there are 9 samples per cell.
Every run exits 101. The test panics at tests/v16_cu.rs:1203 ("init market" Custom(14)) when it gets to the
16-leg case, after the 1/2/4/8-leg samples are printed. Base and head fail the same way (the 20 Nov base log does too), so the patch did not cause it.

## BatchTradeCpi CU (litesvm)
| legs | base: min of each run (1/2/3) | base median of 9 | head: min of each run (1/2/3) | head median of 9 | change (median) | change (min) |
|---|---|---|---|---|---|---|
| 1 | 152740 / 152740 / 152740 | 154240 | 143576 / 142076 / 142076 | 143576 | -10664 (-6.9%) | -10664 |
| 2 | 225548 / 225548 / 227048 | 227048 | 214884 / 214884 / 214884 | 216384 | -10664 (-4.7%) | -10664 |
| 4 | 316672 / 316672 / 316672 | 316672 | 306008 / 307508 / 306008 | 307508 | -9164 (-2.9%) | -10664 |

Samples jitter in 1500 CU steps in both builds.
The saving is a flat ~10.7k CU per transaction. It does not grow with the number of legs,
so the "once per leg" cost described in the plan does not show up in this probe.
The base numbers match the 20 Nov base run (~/agent-work/toly-cushape/d/probe-base.log) to the CU.

## Not run
- Full suite and the 2 fuzz gates: not run, out of scope for this final run.
- Kani: no harness covers either function (grep, see docs/cu/TOLY-PR-DRAFT.md); not run.

No PR opened, nothing posted, nothing sent to Toly's repos. The draft stays local for Khubair.
