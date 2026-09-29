# P3 proofs — `src/vault_lp_v18.rs`

Standalone crate (no deps; `proptest` dev-only) that compiles the **production file**
`../../src/vault_lp_v18.rs` via `#[path]`. With `--features p3_mutant` (or `--cfg p3_mutant`)
it compiles `mutants/vault_lp_v18_mutant.rs` instead — a single file that each negative
control overwrites from one of the named mutants (`mutants/m*.rs`). The real file is never
edited.

- Kani (local only, never CI): `./run_kani.sh real` → `logs/real/SUMMARY`.
  Negative controls: `cp mutants/mN_*.rs mutants/vault_lp_v18_mutant.rs && ONLY=<regex> ./run_kani.sh mN --features p3_mutant`.
- proptest: `cargo test --release` (10 000 cases, branch-coverage counters asserted non-zero).
  Negative controls: same mutant swap + `cargo test --release --features p3_mutant`.

All Kani proofs are BOUNDED (u16 inputs where a symbolic u128 multiply+divide occurs, u64
elsewhere). The skew-funding zero-sum harness proves conservation over a transcribed MODEL of
the engine formula (`v16.rs@35ddd692` :14777-14782 and :1626-1641), because
`kernel_adl_scaled_accrual_index_deltas` is `pub(crate)` and not callable from here; per-leg
settlement rounding is not modelled.

Mutants:
| file | breaks | caught by |
|---|---|---|
| m1_waterfall_conservation | junior = V - senior + 1 in surplus | kani waterfall; proptest cash identity |
| m2_redemption_ceil_slice | senior claim slice rounded UP | kani redemption no-dilution; proptest per-share |
| m3_skew_sign_swapped | crowded side RECEIVES | kani skew sign / zero-sum model |
| m4_junior_floor_dropped | junior floor ignored | kani junior floor; proptest floor assert |
