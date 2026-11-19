# AuthMark push CU baseline (J-20261118-PROG-CU-AUTHMARKPUSHc, try 3)

Base d27f3d73, `cargo build-sbf --features devnet`, test binary built with
`cargo test --release --features devnet --test v16_cu --no-run -j 4`, private target dir
(APFS clone of the EWMAc dir), run directly with `P1_WRAPPER_SO=<target>/deploy/percolator_prog.so`:

`v16_bpf_configure_and_push_auth_mark_are_bounded_and_clock_authenticated --nocapture --test-threads=1`

| run | configure CU | push CU |
|-----|-------------|---------|
| 1   | 8503        | 4628    |
| 2   | 8503        | 4628    |
| 3   | 8503        | 4628    |

Deterministic. A 5% cut = 231 CU. Build timings: slot lock wait 547s, lib+sbf ~28s warm,
release test compile ~25 min under load. The first build-sbf attempt failed on a toolchain
dir swap (sbpf-solana v1.52 -> v1.53) mid-run; a rerun succeeded.

## Profile (truncation bisect via compile-time early `return Ok(())`, source reverted)

| exit point | push CU |
|---|---|
| full handler | 4628 |
| right after `state::market_view_mut` (cut 2) | 2226 |
| a later cut (believed right after `read_oracle_profile_from_view`, cut 3; build order was racy) | 2491 |

So about 2226 CU (48%) is spent before any AuthMark-specific logic: the two ComputeBudget
instructions, entrypoint account deserialisation, signer/owner checks and `market_view_mut`.
The AuthMark-specific work (profile read, authority/staleness checks, sequence advance,
transition record, profile write, depth view, `validate_shape`, config write) is ~2.4k CU, and
the profile read is only ~265 of that. `market_view_mut` is shared by every handler, so cutting it
is not an AuthMark-local change and is out of scope here (refresh/liquidation/EWMA paths are
excluded). The remaining cuts (4-8) were not measured: each build-sbf took 6-13 min under load
and the release test compile is ~25 min, so a code change plus differential proof did not fit
the 3-hour budget. No code change was made. Verdict: measured no-op for this try.
Next step if retried: cut 4-8 on a quiet machine, and look at `validate_shape` and
`write_wrapper_config` first.
