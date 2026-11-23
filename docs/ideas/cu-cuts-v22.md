# CU cuts across v2.2 (wrapper + engine) — plan

Session cu-cuts-1121, 21 Nov 2026. Plan owner: Opus session (cuts, PRs, gates). Hotspot hunt and
profiling: Fable session (`shared/HUNT.md`). Every number below is measured on the base named in
section 1 unless the line says "estimate" or "not measured".

Hard rule (Khubair, 05:06 GMT 21 Nov): **no change to risk-engine semantics or safety checks.** Cuts are
efficiency only: avoided copies, avoided re-decode, skipped provably-empty work, cheaper arithmetic
that returns the same value. If a change could alter margin, liquidation, ADL, haircut, payout, latch,
any error code, or any safety check, it is dropped.

## 1. What was measured

| item | value |
|---|---|
| wrapper | `feat/v22-rc23-2026-10-22` @ `4a5065f5` (#753) |
| engine | `feat/v22-engine-rc23-2026-10-22` @ `3e5970f3` (#362), built as `../percolator`, `PERCOLATOR_ENGINE_UNPINNED=1` |
| note | the wrapper's CI engine pin is `ENGINE_CI_SIBLING=db019142` (`ci/deployed-refs.env`), 37 commits older than `3e5970f3`. Engine cuts land on `3e5970f3`, so that is the base used here. |
| build | `cargo build-sbf --tools-version v1.52 --features devnet` (platform-tools v1.52) |
| wrapper .so | `shared/so/base-4a5065f5-3e5970f3.so`, sha256 `e3248f16…78aa5a`, 2,886,456 B |
| matcher .so | `/Users/khubair/v22-cu-1113/out/matcher.so` (sha256 `368be0d3…`), read-only prior-art build |
| harness | litesvm 0.1.0, `cargo test --release --features devnet --test v16_cu`, every number is the median of 3 runs |
| per-function profile | `shared/fable/cuprof.py` (Fable): exact per-function CU from the SBF instruction trace of the unmodified base .so; syscall cost estimated, residual vs reported CU < 0.5% |
| probes added | `cu_probe_v22_table`, `cu_probe_trace_trade_add`, `cu_probe_trace_batch_add_4` in `tests/v16_cu.rs` (ignored, measurement only), on `agent/J-20261121-CU-CUTS-PROG` @ `506d0158` |

Noise: tests use random keypairs, so `find_program_address` bump search moves a number by multiples
of 1,500 CU. `[min..max]` is shown where the 3 runs differ. Every tx includes 300 CU for two
compute-budget instructions.

Base suite state: `v16_cu` 282 pass / 1 fail / 9 ignored in all 3 runs. The failure
(`v16_w2_autocrank_d63c4dc9_liquidation_gated_on_all_active_legs`, `tests/v16_cu.rs:25184`) is on the
untouched base and is not a CU matter (probably the engine pin difference above). Cuts are judged
against this same set.

## 2. Baseline CU per instruction

Source: Fable `shared/HUNT.md` section 1 (existing printing tests) and Opus `cu_probe_v22_table`
(raw log `shared/opus-probe_base.log`).

### Trade
| instruction | shape | CU | probe |
|---|---|---|---|
| TradeNoCpi | 1 asset, open | 127,138 | `v16_bpf_tradenocpi_executes_and_is_bounded`, `cu_probe_v22_table` |
| TradeNoCpi | 1 asset, add to the open leg (next tx) | **160,730** | `cu_probe_v22_table` (`trade_nocpi_add_same_slot`) |
| TradeNoCpi | 1 asset, close to flat | 126,188 | `cu_probe_v22_table` |
| TradeNoCpi | asset 0 with 1 / 2 / 4 legs open | 158,096 / 184,734 / 247,754 | `cu_probe_v22_table` (`trade_nocpi_with_n_open`) |
| TradeNoCpi | fresh open asset[0] / asset[3] of 4 | 124,905 / 149,471 | `v16_bpf_tradenocpi_fresh_open_on_base_and_added_asset_is_bounded` |
| TradeNoCpi | "13/14-leg" fixtures | 215,532 / 215,583 | `v16_bpf_current_*` |
| TradeCpi | 1 asset, external matcher | 154,028 | `v16_bpf_tradecpi_executes_through_external_matcher_and_is_bounded` |
| TradeCpi | asset 0 with 1 / 2 / 4 legs open | 178,887 [..181,887] / 192,266 [..195,266] / 223,949 [..225,449] | `cu_probe_v22_table` (`trade_cpi_with_n_open`) |
| TradeCpi | "13-leg" fixture | 362,479 [..371,479] | `v16_bpf_current_thirteen_leg_fresh_asset_trade_still_fills_on_both_routes` |

### Batch trade
| instruction | legs | open (fresh legs) | add (legs already open) | probe |
|---|---|---|---|---|
| BatchTradeNoCpi | 1 | 126,321 | 158,830 | `cu_probe_v22_table` |
| BatchTradeNoCpi | 2 | 197,778 | 279,277 | same |
| BatchTradeNoCpi | 4 | 294,335 | **520,707** | same |
| BatchTradeCpi | 1 / 2 / 4 (legs already open) | — | 202,799 / 325,163 / 569,288 | same |
| BatchTradeCpi (fan-out test, auth mark, fee 100) | 1 / 2 / 3 / 4 | 253,032 / 348,386 / 414,612 / 491,364 | — | `v16_bpf_batch_trade_cpi_fanout_budget_characterisation` |

Per extra leg: ~56k CU when legs are fresh, **~120k CU when legs are already open** (NoCpi and Cpi alike).
The wrapper leg cap is 4 on rc23 (market init refuses `max_portfolio_assets` 8).

### Crank / liquidation / ADL
| instruction | shape | CU | probe |
|---|---|---|---|
| PermissionlessCrank refresh | flat portfolio | 55,934 | `v16_cu_permissionless_crank_refresh_is_bounded` |
| PermissionlessCrank refresh | 1 open leg | 99,282 | `cu_probe_v22_table` |
| PermissionlessCrank liquidation | final call | 268,422 | `v16_bpf_permissionless_liquidation_is_bounded` |
| liquidation, malicious oracle | — | 344,328 | `v16_bpf_permissionless_oracle_liquidation_uses_only_its_own_domain_insurance` |
| worst crank at leg cap n=4 | worst | 655,088 | `v22_bpf_worst_case_liquidation_at_the_leg_cap` |
| lien + ADL n=4 | settle | 941,293 | `v22_bpf_lien_adl_worst_shape_at_the_leg_cap` |
| lien + ADL n=3 | liquidation | **1,064,818** (76% of the 1.4M tx limit) | `v22_f1_static_bound_keeps_the_worst_shapes_inside_the_budget` |

### Custody / close / fees / oracle
| instruction | CU | probe |
|---|---|---|
| InitPortfolio | 26,371 | `cu_probe_v22_table`, custody test |
| Deposit (flat) | 37,227 [..38,727] probe; 40,227 [38,727..49,227] custody test | same |
| Deposit (1 open leg) | 46,332 [..47,832] | `cu_probe_v22_table` |
| Withdraw (flat) | 38,146 [..39,646] probe; 41,146 custody test | same |
| ClosePortfolio (never traded) | 25,171 | `cu_probe_v22_table` |
| CloseResolved | 72,552 [71,052..81,552] | custody test |
| TopUpInsurance / WithdrawInsurance | 27,848 / 36,436 | custody test |
| SyncMaintenanceFee (4-account cranker share / non-flat hidden loss) | 97,513 / 103,310 | `v16_bpf_sync_maintenance_fee_*` |
| Configure / Push EwmaMark | 8,682 / 5,270 | `v16_bpf_configure_and_push_ewma_mark_*` |
| Configure / Push AuthMark | 8,669 / 4,699 | `v16_bpf_configure_and_push_auth_mark_*` |
| abandoned asset force close | 155,791 | `v16_bpf_permissionless_market_shutdown_*` |

Not yet measured (Fable section 5 is adding probes): ConvertReleasedPnl, RebalanceReduce,
CureAndCancelClose, ForfeitRecoveryLeg, FinalizeResetSide, hybrid oracle trade, SwapSecondaryForPrimary,
activate/retire asset, fee-policy updates, slot grow, Earn / vault-LP paths.

## 3. Where the CU goes (per-function, base .so)

Inclusive CU from `cuprof.py` on the base traces. Reports: `reports/cu-cuts-1121.d/prof_*.txt`.

**Worst crank at the leg cap (654,524 program CU)**
- `PortfolioLegV16Account::try_to_runtime` 228,216 incl (35%), almost all of it `validate_active_leg`
  (234,640 incl) -> `loss_weight_for_basis` -> `wide_math::checked_mul_div_ceil_u256` (208,768 incl).
- software u128/u256 arithmetic: `u128_div_rem` 133,028 excl, `__multi3` 120,131 excl, `U512::mul_u256` 53,760 excl.
- `PortfolioV16View::validate_with_market` 118,057 incl; `validate_source_credit_shape_with_market` 47,528 incl.
- `AssetStateV16Account::try_to_runtime` 30,276 excl; `compact_source_domains` 22,468 excl.

**TradeNoCpi (126,838 program CU)**
- `validate_with_market` 24,404 incl; `compact_source_domains` 22,254 incl (inside `PortfolioV16ViewMut::new`, 14,864);
  leg decode 14,053 incl; `checked_mul_div_ceil_u256` 10,704 incl; `AssetStateV16Account::try_to_runtime` 8,004 excl.
- wrapper source-domain scans: `source_lien_effective_reserved_snapshot_for_trade_view` 6,864,
  `reserved_source_domains_snapshot_for_trade_view` 5,538, `source_counterparty_backing_snapshot_view` 3,432,
  `ensure_new_counterparty_backed_liens_fresh_for_trade_view` 3,294 (19,128 together).
- `vault_lp_capture_pre_fill` 7,755 incl.

**TradeCpi (152,754 program CU)**: same engine core (79,703) plus `p1_cpi_preflight_before_matcher` 11,080,
`signed_position_for_asset_view` 8,248, `compact_source_domains` 29,672 incl, `checked_mul_div_ceil_u256` 14,272.

**Deposit (36,679 program CU)**: `validate_with_market` 15,556 incl, of which
`validate_source_credit_shape_with_market` 6,744 (2 calls) on a portfolio with **no** source domains; SPL transfer CPI 6,464;
`compact_source_domains` 3,709; `find_program_address` 3,054.

## 4. Ranked hotspots

### 4.1 Measured so far (Fable, `shared/HUNT.md` 4.1; median of 3, CU per tx)

Two measurement-only builds (nothing pushed): **comb** = engine `3e5970f3` + the open PRs #315/#319/#320
cherry-picked (no conflicts); **p1** = comb + a 12-line prototype of C1 below (`prof/percolator` `507cded4`).
Both: `v16_cu` 282 pass / 1 fail, same test as base.

| probe | base | comb | p1 (comb + C1) | base -> p1 |
|---|---|---|---|---|
| TradeNoCpi 1-asset | 127,138 | 107,532 | 100,350 | -21.1% |
| TradeNoCpi "full-14-leg" fixture | 215,583 | 204,547 | 136,415 | -36.7% |
| TradeCpi 1-asset | 154,028 | 133,504 | 122,384 | -20.5% |
| BatchTradeCpi 4 legs | 491,364 | 463,053 | 390,441 | -20.5% |
| refresh crank | 55,934 | 44,158 | 44,158 | -21.1% |
| liquidation crank (final call) | 268,422 | 245,050 | 193,852 | -27.8% |
| lien+ADL n=3 liquidation (largest tx) | 1,064,818 | 1,028,762 | 828,518 | -22.2% |
| SyncMaintenanceFee 4-account | 97,513 | 74,960 | 74,960 | -23.1% |
| Deposit / Withdraw (custody probe) | 40,227 / 41,146 | 32,628 / 33,547 | = comb | -18.9% / -18.5% |

C1 alone (comb -> p1): largest tx -200,244; liquidation -51,198; 4-leg BatchTradeCpi -72,612; TradeNoCpi -7,182;
TradeCpi -11,120. Trace: 1,782 CU per `checked_mul_div_ceil_u256` call; 164 calls in the largest tx.

### 4.2 Ranked list


"Measured cost" is the CU the profiler attributes to the code the cut touches: an upper bound on the
saving, not the saving. The saving is only claimed after the before/after run.

| # | hotspot | where | measured cost | method | risk | owner |
|---|---|---|---|---|---|---|
| C1 | leg-decode loss weight runs a U512 multiply + U256 division on every active leg | engine `src/v16.rs:29458` `loss_weight_for_basis`, called from `validate_active_leg` `:29390` (every `PortfolioLegV16Account::try_to_runtime`) and `:20904`, `:21264` | `checked_mul_div_ceil_u256` 208,768 incl in worst crank (32%), 14,272 TradeCpi, 10,704 TradeNoCpi; prototype measured -200,244 on the largest tx (4.1) | `abs_basis_q * SOCIAL_WEIGHT_SCALE` fits u128 whenever `abs_basis_q < 2^128/1e15` (always true after `validate_basis`, max 1e14). Compute the same ceil in u128 then; `a_basis == SOCIAL_WEIGHT_SCALE` (no ADL yet) returns `abs_basis_q` exactly. Anything else keeps the wide path. Same value, same errors. | low: pure arithmetic identity | Opus, first |
| C2 | source-domain table scanned by value (196-byte copy per slot) | engine `src/v16.rs:6517` `validate_source_credit_shape_with_market` (`let source = self.source_domains()[slot_index]`), `:6637` `source_claim_bound_sum_num`, other `PortfolioV16View` scans; `is_occupied(self)` `:28094` | 6,744 for the 2 calls in a deposit on an empty table (~3,370 per call, ~105 CU per empty slot vs ~53 in the by-reference wrapper scans); 47,528 incl in worst crank | iterate by reference; `is_occupied`/`has_default_sparse_tag` take `&self`; and/or Fable's R3: one `memcmp` of the all-zero tail (empty slot = all-zero Pod bytes) and fall back to the unchanged loop when it is not all zero. Fable's trace total for empty-slot walks: ~33.8k of the 104.8k comb TradeNoCpi, ~9.3k of a deposit (estimate of saving: not measured yet). Not touching `compact_source_domains` (#319). | low | Opus |
| C3 | the three open engine perf PRs | #319 (compact skip), #320 (empty leg skip), #315 (wide_math digit division) | `compact_source_domains` 22,254 TradeNoCpi / 29,672 TradeCpi; 13 Nov after/before on older engine: TradeCpi -14.4%, TradeNoCpi -15.5% | already written + reviewed APPROVE 13 Nov, MERGEABLE/CLEAN on rc23 today, never gated. Run `merge-gate.mjs` on them as they are; no new PR. Fable re-measures `shared/so/comb-…+315+319+320.so` on today's tree. | low (reviewed) | Opus gates, Fable numbers |
| C4 | wrapper source-domain snapshots: 4 scans of the same 32-slot table per account per trade | prog `src/v16_program.rs:19552`, `:19624`, `:19510`, `:48301` | 19,128 in TradeNoCpi | build the before-trade snapshots in one pass per account where they read the table at the same point; keep the after-trade check as is. | low-medium (must prove no write between the fused reads) | Opus |
| C5 | asset state decoded repeatedly in one instruction | engine `AssetStateV16Account::try_to_runtime` | 30,276 excl worst crank, 8,004 TradeNoCpi | find call sites that decode the same asset twice with no write between; reuse the decoded value. | medium (needs a no-write-between proof per site) | after C1/C2 re-profile |
| C6 | ~120k CU per extra leg when the legs are already open (batch) / +33.6k for a single add vs open | engine batch/settle path | measured totals in section 2; per-function split requested (`cu_probe_trace_batch_add_4`, `cu_probe_trace_trade_add`) | investigate first: if the per-leg cost is full-portfolio work repeated per leg, look for loop-invariant reads only. No reordering of checks. | medium-high; may yield nothing safe | Fable trace, then Opus |
| C7 | software u128/u256 arithmetic outside loss weight | `wide_math`, `__multi3`, `u128_div_rem`, `__udivti3` | 133k + 120k excl in worst crank (part is C1) | re-profile after C1 and #315; then u128 fast paths where the operands provably fit (same pattern as C1) | low per site | after C1 |
| C8 | config decode on trade reads (CUSHAPE) | prog `src/v16_program.rs:6537`, `:6578` | `V16ConfigAccount::try_to_runtime_shape` 5,652 incl in TradeNoCpi (only part is this site) | **not taken here**: same change as the in-flight Toly CUSHAPE work (see 5). | — | dedupe |
| C9 | deposit/withdraw fixed costs | prog `handle_deposit` `:17772`, `handle_withdraw` `:17867` | `find_program_address` 3,054; transfer CPI 6,464 | mostly covered by C2/C3 (validate + compact are 19.3k of 36.7k). PDA bump caching would need a layout change: out of scope. | — | via C2/C3 |

Order of work: C1, C2 (engine, independent hunks), C3 gates, C4 (wrapper), then re-profile and take
C5-C7 by measured size. ADL/liquidation worst shapes are the liveness-critical paths (1,064,818 CU at
n=3), so every cut is also measured on `v22_bpf_worst_case_liquidation_at_the_leg_cap` and the X1/F1
worst-shape tests.

Success measure per cut: median-of-3 `v16_cu` CU drops on the targeted probes, no probe rises by more
than bump noise (1,500), identical pass/fail set on `v16_cu`, and the engine/wrapper suites unchanged.

## 5. Dedupe against in-flight work

1. **Toly CUSHAPE** — `origin/agent/J-20261120-PROG-TOLY-CUSHAPEe` @ `172fcc0d`: shape-only config decode in
   `read_market_trade_preflight` / `read_asset_effective_prices`, flat ~10.7k CU per transaction measured on
   Toly's tree (that branch is not an rc23 branch; merge-base `c447686a`). The same two call sites are unchanged
   on rc23 (`src/v16_program.rs:6537`, `:6578`). That is C8 and it is not redone here. Anything upstream to Toly
   waits for Khubair's yes; nothing is posted or opened on `aeyakovenko/*`.
2. **Engine #382** — `agent/J-20261121-ENG-361RELAND` @ `ec28cd93` (in gate): `src/v16.rs` hunks at
   10714, 11527, 11853, 11871, 16150 (provider principal semantics, not CU). C1 (29383-29470) and C2
   (6517-6650, 28094-28115) do not touch those hunks. Engine cuts branch off rc23 `3e5970f3` and rebase onto
   #382 only after it merges.
3. **Engine #315 / #319 / #320** (13 Nov, `/Users/khubair/v22-cu-1113`, prior art): still OPEN, not in
   `3e5970f3` (today's base numbers equal the 13 Nov "before" numbers). They are C3: gated as they are, not
   re-written. C2 stays out of `compact_source_domains` (#319, hunk at 6311) and the leg loops #320 changes
   (6419, 16925).

## 6. Equivalence evidence required for every cut

- existing tests pass: engine `cargo test --release` (default and `audit-scan`), wrapper `v16_cu` same pass/fail
  set as base, plus the wrapper suite the gate runs;
- a differential test of the new code against the old code (kept as a test-only reference) over edge values and
  random inputs;
- Kani where a harness applies (at most 4 workers): a harness that the fast path equals the reference for all
  inputs in its domain;
- fuzz on the touched paths (`tests/v16_program_stateful_fuzz.rs` / engine proptests);
- before/after CU table (median of 3) in the PR body;
- `merge-gate.mjs` 6 checks; check 2 uses the differential/pinning test.

## 7. Rejected / out of scope

- Caching the vault-authority PDA bump (saves a 1,500 CU syscall per custody call): needs a new stored field = layout change.
- Dropping or merging any `validate_*` call, even when it looks repeated: each is a safety check at a point in
  the flow; only the cost of a check may change, never whether or when it runs.
- Upstream S1-CU restructures (72bfb065 / abe4c54c in the 13 Nov notes): not behaviour-identical.

## 8. Status, 23 Nov 2026 (resumed 05:46 GMT; updated 12:30 GMT)

Baselines (same harness and method as section 1; raw logs and tables in `reports/cu-cuts-1121.d/`):
- base2 = wrapper `4a5065f5` + probes (`506d0158`) on engine `67a4c5b9` (after #382, #383, #384);
- base3 = same wrapper on engine `e2169177` (after #391, #392, #393, #394).
- stack3 = engine `e2169177` + COMPACT + MULDIV + ASSETWIRE2, wrapper + #766 (measurement build, not a PR).

| shape | 21 Nov base | base2 | stack3 |
|---|---|---|---|
| TradeNoCpi, 1 asset | 127,138 | 108,528 | 64,908 |
| TradeCpi, non-zero asset | 154,223 | 133,461 | 84,129 |
| BatchTradeNoCpi, 4 legs already open | 520,707 | 250,321 | 183,716 |
| BatchTradeCpi, 4 legs (probe) | 569,288 | 299,124 | 227,279 |
| refresh crank (flat) | 55,934 | 55,934 | 34,828 |
| liquidation crank, final call | 268,422 | 191,727 | 135,670 |
| lien+ADL n=3 liquidation (largest tx) | 1,064,818 | 738,309 | 519,853 |
| worst crank at the leg cap | 655,088 | 430,934 | 293,852 |
| InitPortfolio / Deposit (custody test) | 26,371 / 40,227 | 18,689 / 32,545 | 15,096 / 25,952 |

| item | what | state |
|---|---|---|
| C1 (R2) | leg loss weight in u128 | merged, engine #384 |
| C2 (R4a) | engine zero-tail source-domain scans | merged, engine #383 |
| C4 (R4b) | wrapper zero-tail scans | prog #766 open, CI green; three gate runs lost to lane contention / an external kill; auto-merge loop has it queued |
| R3 | atom-alignment modulo without `__umodti3` | merged, engine #391 (largest tx -120,836 vs base2) |
| R13 | source-credit rate in u128 | merged, engine #392 (lien+ADL n=4 settle -42,500) |
| R7a | asset-state wire-only validation, 3 readers | merged, engine #394 (Kani-proved same errors) |
| C3 (#319 idea) | skip `compact_source_domains` when already compact | merged, engine #396 (TradeNoCpi -21,642, TradeCpi -30,356, refresh -18,035) |
| new | u128 mul-div: a==d / b==d shortcut, ceil remainder by multiply | engine #397, gating (4-leg batch add -17,124) |
| R7b | `asset_state_wire` for ~15 raw-field readers | engine #398, gating (4-leg batch -7k..-9.5k, trade -2,982) |
| new | inactive-leg emptiness on raw bytes in validate_with_market / refresh | engine #399, gating (TradeCpi -5,620, SyncFee -6,624; Kani-proved) |
| R10 | division-free loss-weight floor | dropped: no win after #384 (measured +12..+820) |
| R5 / C8 | shape-only config decode on the trade read path (CUSHAPE on rc23) | parked for Khubair (drops a read-path re-validation; overlaps Toly work) |
| R6, R8 | repeated validate_active_leg / config shape decode | parked: removes repeated checks |
| R11, R12 | wrapper leg lookup / bitmap-only leg scans | parked: changes which check reports a corrupt slot |
| next | same raw emptiness test in `PositionSlotMapV16::from_account` (src/v16.rs:7548) | after #399 |

All engine savings reach the wrapper only after `ENGINE_CI_SIBLING` (ci/deployed-refs.env, still `db019142`) moves; that pin move is not part of this work.
