# Kani on the wrapper (v2.2 / rc23): how to run it, and what the last full run said

Toolchain: kani 0.67.0 (`cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup`).
Kani is run locally or by the nightly workflow, never in PR CI (too slow).

The wrapper builds only with the engine checked out as the sibling `../percolator` at
`ENGINE_CI_SIBLING` from `ci/deployed-refs.env` (build.rs refuses anything else).

## Commands

| Target | Where | Command |
|---|---|---|
| lib harnesses (`src/`: p1/g8/r2/r3/sync, depth_src_v22, f1_refresh_liq_v22, lev_guard_v22, lev_profile_v22) | repo root | `cargo kani --lib --features devnet -Z stubbing` |
| integration-test harnesses (`tests/v16_kani.rs`, `growth_kani.rs`, `kani_design_p1.rs`, `v16_fee_split.rs`) | repo root | `cargo kani --tests --features devnet -Z stubbing -Z function-contracts` |
| continuous leverage | `kani/contlev` | `cargo kani -Z stubbing -Z function-contracts` |
| P3 vault LP | `kani/p3` | `cargo kani -Z stubbing -Z function-contracts` |
| P3 through the engine kernel | `kani/p3-engine` | `cargo kani -Z stubbing -Z function-contracts` |
| growth v19 | `kani/growth` | `cargo kani -Z stubbing -Z function-contracts` |

Notes:
- `--features devnet` is REQUIRED for `--tests`: without it `tests/common/mod.rs` fails with
  E0425 (`constants::STAKE_PROGRAM_ID` only exists under `devnet` / `mainnet-ids`). It is also the
  deployed feature set for the lib (the depth-source allow-list differs under `devnet`).
- `-Z stubbing` is needed by `#[kani::stub]` harnesses (f1_refresh_liq_v22, kani/contlev,
  kani/growth); `-Z function-contracts` by `stub_verified` / `proof_for_contract` (kani/growth).
  Both flags are harmless where unused, so pass them everywhere.
- One harness: add `--harness <path> --exact`. `--harness` without `--exact` is a substring match.
- `--harness-timeout <T>` needs `-Z unstable-options`; `-j N` needs `--output-format=terse`.
- A TIMEOUT is no verdict: never report it as a pass. A SUCCESSFUL verdict counts only when every
  `kani::cover!` is SATISFIED (`** N of N cover properties satisfied`).
- `kani_audit.md` documents the 81 harnesses of the deleted `tests/kani.rs` (v12 lineage). It is
  history, not the current set.

## Last full run (2026-10-30/31, prog rc23 + engine 292f8e78, 218 harnesses)

Source: `ledger/v22-followup-2026-10-30/kanitriage.md` (ops ledger). 130 SUCCESSFUL, 85 timed out
with no verdict (4-15 min caps), 3 FAILED:

| Harness | Cause | Status |
|---|---|---|
| `r3_kani_proofs::kani_r3_item6_vol_term` | stale oracle: masked bits 0-1, but `growth_flags_ok` accepts bit 2 (`GROWTH_FLAG_LEV_GUARD`, #601) | fixed 2026-10-31 (mask 0x07 + covers); SUCCESSFUL, 7/7 covers; FAILS on mutants "bit 2 dropped from the validator" and "bit 3 accepted" |
| `kani/growth` `proofs::kani_growth_t1_requirement_never_below_engine_or_per_asset` | harness lacked the precondition `dyn IMR >= engine IMR` (and leg monotonicity) that the only production caller guarantees: `growth_required_imr_bps` refuses `ceil_imr_bps < engine_imr_bps` at `src/growth_v19.rs:457` | fixed 2026-10-31 (two justified `kani::assume`s, cited in the harness doc); SUCCESSFUL, 5/5 covers; FAILS on two mutants of `growth_margin_required` |
| `depth_src_v22::kani_proofs::kani_dex_pin_check_all_or_nothing` | **Kani modelling artefact, root cause NOT found** (see below) | still FAILS under Kani; do NOT cite it as a proof of the pin check |

### `kani_dex_pin_check_all_or_nothing` (open)

The harness compares `pin_matches(&pin, &v)` with an oracle that is a line-for-line copy of the
function body, so it can only fail if Kani evaluates the same pure expression two ways. It does:
the 10-30 triage saw `pin_matches` called twice on identical inputs return different values
under Kani (about 12 reruns, bisecting conjuncts did not isolate it; the crate reports
"unsupported constructs: caller_location, foreign function").

2026-10-31: Kani's own counterexample (`--concrete-playback=print`) replayed NATIVELY with
`cargo kani playback -Z concrete-playback --lib --features devnet` runs the identical harness
code and PASSES (`assert_eq!(ok, all)` holds). The trace Kani reports is therefore not a real
execution: the FAILED verdict is a verifier artefact, and equally a future SUCCESSFUL verdict
from this harness would mean nothing until the cause is understood. It is left failing (not
silenced, not in the nightly list). Ideas not yet tried: make `pin_matches` take scalars instead
of `&[u8; 32]` arrays; `--solver minisat` / `kissat`; inspect the goto program for the
array-equality lowering. The pin logic is covered natively by `cargo test --lib depth_src_v22`
(5/5) and `tests/v22_dex_depth.rs`.

## Nightly: the 85 timeouts

`.github/workflows/kani-nightly.yml` runs exactly the harnesses in `ci/kani-nightly-harnesses.tsv`
(the 85 no-verdict harnesses of the run above, names taken from the raw logs), sharded per crate
(`scripts/kani-nightly-shard.sh`), each harness in its own `cargo kani` process with a longer
`--harness-timeout` (default 70m, two per runner, every job under the 6 h limit). Every shard uploads
`verdicts.tsv` + per-harness logs; the summary job uploads `kani-nightly-verdicts` and goes RED
on any FAILED, VACUOUS (SUCCESSFUL with an unsatisfied cover) or ERROR verdict. TIMEOUTs are listed
separately as warnings, never as failures and never as passes.

GitHub only fires `schedule:` from the default branch: the nightly is live only once this file is
on `main`. Until then run it by hand: `gh workflow run kani-nightly.yml --ref <branch>`
(inputs: `harness_timeout`, `chunk`, `jobs_per_runner`, `groups`).

Local equivalent of one shard: `scripts/kani-nightly-shard.sh p3-engine 0 3 30m 2 /tmp/kn`.
