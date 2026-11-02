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
| growth v19 (incl. #572 occupancy `kani_growth_occ_*`; 4 of them use `#[kani::solver(z3)]`, needs a `z3` binary on PATH) | `kani/growth` | `cargo kani -Z stubbing -Z function-contracts` |
| #571 carried bond coupon (prog #649) | `kani/bonds571` | `cargo kani` (add `-Z unstable-options` for `--harness-timeout`) |

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
(the 85 no-verdict harnesses of the run above, names taken from the raw logs), **one GitHub job per
harness** (the plan job builds the matrix: 85 entries, under GitHub's 256 limit; `max_parallel`
default 8), each with a longer `--harness-timeout` (default 70m; watchdog = timeout + 10 min; the plan
refuses a timeout whose build + watchdog would not fit the 350 min job limit) and a **memory cap**
(`mem_cap`, default 13G, applied as a cgroup-v2 `memory.max` with swap 0 via passwordless sudo;
`ulimit -v` fallback) below the 16 GB of the ubuntu-latest VM.

Why: in run 41183972352 (groups=tests, 4 harnesses per shard, 1 at a time) all 6 shards died with
"The runner has received a shutdown signal", exit 143, after 43 min to 5 h 7 min, and lost every row
(artifacts upload at the end of a job). None came near the 350 min job limit, and the one harness
that reached kani's own 70 min timeout (`kani_v16_asset_lifecycle_decode_preserves_wire_fields`) got
its TIMEOUT line; the others died mid-harness at varying times, which points to the VM running out of
memory (CBMC), not to the time limit. With one harness per job, a dying harness can only lose its own
row; with the cap, CBMC is OOM-killed inside its cgroup before the VM is, and the row says OOM (the job
log also gets a memory sample every 2 min and the row records the cgroup's peak MiB).

Verdicts (`scripts/kani-nightly-lib.sh`, `classify`):
- TIMEOUT (no verdict, a warning): only when the log says "CBMC timed out", or the watchdog fired
  (rc 124/137 AND elapsed >= watchdog limit).
- OOM (no verdict, a warning): the memory cap was hit and kani did not exit 0 (cgroup
  `memory.events` oom_kill > 0, or an allocation failure in the log under the `ulimit -v` fallback).
  oom_kill > 0 with exit 0 is ERROR (a process was killed, the success is not trusted).
- ERROR (red): any other kill (SIGKILL 137 / SIGTERM 143 without OOM evidence) before the watchdog
  limit, build failures, name rot, crashes.
- SUCCESSFUL needs rc 0, the VERIFICATION line and "1 successfully verified, 0 failures", and every
  cover satisfied (else VACUOUS, red). FAILED = a real check failed (red).

Per-harness artifacts are named `kani-shard-<group>-<index>`; the summary job downloads only `kani-shard-*`
(never an earlier `kani-nightly-verdicts`), then `scripts/kani-nightly-summary.sh` goes RED unless
there is exactly one verdict row per selected harness (names from the TSV for the selected groups:
missing, duplicate or unselected rows are red), and on any FAILED, VACUOUS or ERROR row, or any
harness job that did not succeed. A missing row (job died) is red. TIMEOUT and OOM rows are listed
separately as warnings, never as failures and
never as passes. A green run therefore means "nothing failed", not "everything proved": read the
SUCCESSFUL count.

### LONG groups: harnesses that time out locally (Khubair R5, 2026-11-02)

Two more groups run with `long_timeout` (default **315m**, watchdog 325m; the plan refuses more than
324m: 15 min setup + watchdog + 1 must fit the 350 min job limit) under the same 13G memory cap:

| Group | Crate / flags | Rows |
|---|---|---|
| `bonds571` | `kani/bonds571`, plain `cargo kani` (no contracts/stubs; solver = the harness attribute, cadical) | the 6 harnesses that hit a 90 min TIMEOUT locally (c571 run r2, 2026-10-31): `kani_571_settle_cap_closed_exact_remainder`, `_split_interval_is_exact`, `_settle_monotone_in_time`, `_newcomer_neutral_within_rounding`, `_redemption_slices_k_and_meter`, `_junior_gate_bound_dominates_every_settlement` |
| `growth-occ` | `kani/growth`, `-Z stubbing -Z function-contracts` | glob row `proofs::kani_growth_occ_*` |

The TSV may hold a **glob** in the last path segment. `scripts/kani-nightly-plan.py` (the plan job;
`--help`-style doc at its top) expands it at run time against the `#[kani::proof]` fns of the group's
source dirs, so the nightly runs whatever occupancy harnesses exist on the branch (the #572 per-notional
redesign may rename or remove them). A glob that matches nothing is a `::warning::`, not a failure; an
exact row with no `fn` is red (name rot). To change the set, edit the TSV rows of the group.

Solver: each harness's `#[kani::solver(..)]` attribute is used unless the `solver` input overrides it
for every selected harness (`--solver`, which kani lets override the attribute). The plan marks every
job whose harness asks for z3 (attribute or override) and the job installs `z3` from apt (kani does
not bundle it; CBMC's `--z3` calls the binary). bonds571 harnesses are written for cadical; the
growth occupancy harnesses `occ_ramp_prod_shape`, `occ_ramp_total`, `occ_charge_step_exact`,
`occ_split_never_charges_more` for z3.

### Schedule

**There is no automatic nightly today.** GitHub fires `schedule:` only from the default branch
(`main`), and a scheduled run checks out main's tree. Under the v2.2 rule that nothing goes to
`main`, the workflow runs by **manual dispatch only**, until a human decides between accepting that
or a main-hosted scheduler that dispatches against the release branch:
`gh workflow run kani-nightly.yml --ref <branch>` (inputs: `harness_timeout`, `long_timeout`,
`mem_cap`, `max_parallel`, `groups`, `solver`). Example for the long groups on the release branch:
`gh workflow run kani-nightly.yml --ref feat/v22-rc23-2026-10-22 -f groups=bonds571,growth-occ`.

Ways to get a real nightly on the v2.2 branch (each needs a human decision; none is in place):
1. Manual dispatch (works today, as above).
2. A small scheduler workflow ON `main` (`on: schedule`) whose only step is
   `gh workflow run kani-nightly.yml --ref feat/v22-rc23-2026-10-22` with `permissions: actions: write`.
   The kani job then runs the release branch's tree. Touches `main` (the v2.2 rule forbids it today).
3. An external cron (a machine or another repo's scheduled workflow) calling the same `gh workflow run`
   with a token that has `actions:write` on this repo. No change to `main`, but needs a credential.
4. Change the repository's default branch to the release branch (schedule fires from it). Affects
   every PR/default-branch behaviour; not recommended.

Local equivalent of one job: `scripts/kani-nightly-shard.sh <group> <harness> 30m /tmp/kn [13G]`
(needs coreutils `timeout`/`gtimeout`). Logic test (no kani; also run by the plan job, where it checks
the real cgroup cap with a fake kani that allocates 1 GiB under 128M): `scripts/kani-nightly-selftest.sh`. Judge locally: `scripts/kani-nightly-summary.sh <shards-dir> <names-file> success /tmp/out`.
