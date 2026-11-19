# EwmaMark push CU: partial report (J-20261118-PROG-CU-EWMAMARKPUSHb)

Baseline: NOT measured. The shared-target SBF build was still compiling dependencies
(anchor-lang-v2) after 70+ min under slot-lock contention; the release test binary was never built.

Candidate (UNMEASURED, NOT applied to src): `ewma-update-u64-fastpath.patch` adds a u64 fast path in
`policy_v16::ewma_update` (u128 division is a libcall on SBF). It falls back to the old u128 path
whenever an intermediate could overflow u64.

Identity test: `tests/ewma_update_diff.rs` (200k random cases vs a verbatim copy of the old
function). Not yet run: no compile finished in time. With the patch unapplied it trivially passes.

Next: build baseline, apply patch, run the v16_cu test
`v16_bpf_configure_and_push_ewma_mark_are_bounded_and_clock_authenticated` with --nocapture
--test-threads=1, 3 runs before and after, compare "push CU".

## Try c (J-20261118-PROG-CU-EWMAMARKPUSHc)
- Host differential with patch applied (debug, private target dir): `ewma_update_matches_u128_reference_200k` ok, 0 mismatches over 200k inputs. Debug dep build took 19m49s.
- Next: baseline build-sbf + release v16_cu at base, then with patch.
- Baseline build at base (patch unapplied), private target dir, slot lock acquired immediately (0s wait):
  `cargo build-sbf --features devnet` finished in 24m52s (08:24). `cargo test --release --features devnet --test v16_cu --no-run -j 4`
  was still compiling deps (~1500 artifacts, around dlopen2_derive/serde_derive_internals) at 09:00, past the 120 min cut-off. Stopped; no CU numbers measured.
- Unapplied patch + passing differential remain on this branch for a follow-up; dep cache in $HOME/agent-work/wt-target-EWMAc is warm for debug and SBF.

## Try 4 (J-20261119-PROG-CU-EWMAMARKPUSHe)
BEFORE (base d27f3d73, unpatched, 3 runs): configure CU 8678, push CU 5270 (identical x3).
(Test needs P1_WRAPPER_SO=<target>/deploy/percolator_prog.so since CARGO_MANIFEST_DIR/target is absent.)
