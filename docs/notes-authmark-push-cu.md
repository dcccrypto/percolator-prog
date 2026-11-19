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
