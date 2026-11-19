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
