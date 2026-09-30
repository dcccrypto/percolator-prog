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

All Kani proofs are BOUNDED. Input widths, per harness (corrected 2026-09-30 — an earlier version of this
README said "u16" for every multiply+divide harness, which was wrong for the dilution proofs):
u8 (`b()`) for `kani_p3_deposit_no_dilution` and `kani_p3_redemption_no_dilution`; u16 (`u()`) for
`redemption_rejects_bad_inputs`, `junior_withdraw_keeps_floor_and_senior_backing`, `leverage_gate_exact`
and `h2_exposure_cap_exact_and_reducing_always_allowed`; terminal split: < 32 with symbolic shares,
or u32 balances with three fixed share tables; u64 elsewhere. The former skew-funding zero-sum harness (WITHDRAWN as circular, see proofs.rs) modelled
the engine formula (`v16.rs@35ddd692` :14777-14782 and :1626-1641), because
`kernel_adl_scaled_accrual_index_deltas` is `pub(crate)` and not callable from here; per-leg
settlement rounding is not modelled.

Skew conservation now lives in `../p3-engine` (non-circular: the REAL engine kernel
`kani_adl_scaled_accrual_index_deltas`). The 2026-09-30 harnesses `kani_p3e_skew_adl_basis_real_settle_*`
also call the REAL per-leg settlement rule (`kani_scaled_adl_delta_fast`, else
`wide_math::wide_signed_mul_div_floor_from_k_pair`, composed as engine v16.rs:13622-13660), use two A
pairs (longs shrunk to 0.3, shorts shrunk to 0.7) and include a leg opened BEFORE the ADL step
(a_basis = ADL_ONE != live A). Negative controls: `--features neg_flat_a`, `--features neg_settle_live_a`.

Mutants:
| file | breaks | caught by |
|---|---|---|
| m1_waterfall_conservation | junior = V - senior + 1 in surplus | kani waterfall; proptest cash identity |
| m2_redemption_ceil_slice | senior claim slice rounded UP | kani redemption no-dilution; proptest per-share |
| m3_skew_sign_swapped | crowded side RECEIVES | kani skew sign / zero-sum model |
| m4_junior_floor_dropped | junior floor ignored | kani junior floor; proptest floor assert |
