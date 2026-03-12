# Kani Proof Quality Audit — 2026-03-11

**Auditor:** Sentinel (security sub-agent)
**Scope:** `percolator-prog/tests/kani.rs` (303 proofs) + `percolator-core/tests/kani.rs` (153 proofs)
**Total proofs audited:** 456

---

## Summary

| Classification | percolator-prog | percolator-core | Total | % |
|---|---|---|---|---|
| **INDUCTIVE** | 0 | 0 | **0** | 0% |
| **STRONG** | 137 | 73 | **210** | 46% |
| **WEAK** | 65 | 40 | **105** | 23% |
| **UNIT TEST** | 101 | 39 | **140** | 31% |
| **VACUOUS** | 0 | 1 | **1** | 0.2% |
| **Total** | 303 | 153 | **456** | — |

### Critical findings

1. **ZERO inductive proofs** — No proof in either file uses a fully symbolic initial state with `assume(canonical_inv)` as the *sole* precondition on an arbitrary state. Every "INV preservation" proof starts from `RiskEngine::new()` + API construction. This means the canonical invariant is never verified inductively — only for specific reachable states.
2. **1 vacuous proof** — `proof_NEGATIVE_bypass_set_pnl_breaks_invariant` in `percolator-core` is a **negative test designed to fail Kani verification**. It will always report a counterexample when run. Running `cargo kani` across all harnesses will show this as a broken proof, masking real failures. It must be either removed or gated behind a `#[should_panic]`-equivalent annotation.
3. **All 4 primary liquidation proofs (LQ1–LQ4) are UNIT TEST** — The highest-risk security property (liquidation correctness) has no symbolic-input coverage. All use concrete deposit amounts, concrete position sizes, and concrete oracle prices.
4. **Misleading `proof_inductive_*` names** — Three proofs named `proof_inductive_*` in `percolator-prog` are NOT inductive: they prove pure arithmetic identities with no RiskEngine involvement, and one (`proof_inductive_oi_cap_invariant`) contains a tautological assertion.
5. **140 UNIT TEST proofs (31%)** — Nearly a third of all proofs have concrete inputs, providing no symbolic coverage of adjacent states.

---

## Per-Proof Classification Table

### percolator-core/tests/kani.rs

| Proof Name | File | Classification | Criteria Gaps | Recommendation |
|---|---|---|---|---|
| `fast_i2_deposit_preserves_conservation` | core | STRONG | 6a: starts from `new()` not symbolic state; 6f: amount < 10_000 tight bound | Widen amount bound; make initial state fully symbolic |
| `fast_i2_withdraw_preserves_conservation` | core | STRONG | 6a: starts from `new()`; 6b: only tests withdraw <= deposit path | Add symbolic state assumption |
| `i5_warmup_determinism` | core | WEAK | 6f: pnl < 10_000, slope < 100, slots < 200 very tight; 1: no arbitrary engine state; 3: uses constructed state | Widen bounds or add `assume(canonical_inv)` |
| `i5_warmup_monotonicity` | core | WEAK | 6f: all fields tightly bounded; 6a: constructed state only | Widen bounds |
| `i5_warmup_bounded_by_pnl` | core | WEAK | 6f: pnl < 10_000, reserved < 5_000, slope < 100 tight | Widen ranges |
| `i7_user_isolation_deposit` | core | WEAK | 3: no `canonical_inv` assume; 2: concrete second deposit of `100` | Add `assume(canonical_inv)`, make amount symbolic |
| `i7_user_isolation_withdrawal` | core | WEAK | 3: no `canonical_inv` assume; 2: concrete withdraw of `50` | Add `assume(canonical_inv)`, make withdraw symbolic |
| `i8_equity_with_positive_pnl` | core | WEAK | 1: no canonical_inv assume; 6f: capital < 10_000, pnl < 10_000 | Add invariant precondition |
| `i8_equity_with_negative_pnl` | core | WEAK | 1: no canonical_inv assume; 6f: tight bounds | Add invariant precondition |
| `withdrawal_requires_sufficient_balance` | core | STRONG | 6a: manual sync_engine_aggregates (fragile); 3: uses `valid_state` equivalent only | Add canonical_inv check |
| `pnl_withdrawal_requires_warmup` | core | WEAK | 2: slot=0 hardcoded, only tests zero-warmup branch; 6e: capital=0 concrete | Make slot symbolic; add both warmup paths |
| `saturating_arithmetic_prevents_overflow` | core | UNIT TEST | 1: proves Rust stdlib properties only, no application logic | Delete or move to rustdoc test |
| `zero_pnl_withdrawable_is_zero` | core | UNIT TEST | 1: pnl=0 concrete, single path | Replace with symbolic `pnl <= 0` proof |
| `negative_pnl_withdrawable_is_zero` | core | STRONG | — | OK |
| `funding_p1_settlement_idempotent` | core | WEAK | 6f: position.abs() < 1_000_000, index.abs() < 1_000_000_000 tight; 6a: new() only | Widen bounds, document why idempotency holds with overflow |
| `funding_p2_never_touches_principal` | core | WEAK | 6f: tight bounds on all; 6a: constructed | Widen principal bounds |
| `funding_p3_bounded_drift_between_opposite_positions` | core | WEAK | 6f: position 0..100, delta.abs() < 1_000 very tight; 5: rounding `>= -2` asserted but small delta may never reach -2 | Document tight bound necessity or widen |
| `funding_p4_settle_before_position_change` | core | WEAK | 6f: delta < 1_000 tight; 1: no canonical_inv; 4: no non-vacuity for second settlement | Add non-vacuity assertion |
| `funding_p5_bounded_operations_no_overflow` | core | WEAK | 2: only checks no-panic, not correctness; 3: no invariant check on Ok | Add `canonical_inv` check on Ok path |
| `funding_zero_position_no_change` | core | STRONG | 6f: delta.abs() < 1_000_000_000 reasonable | OK |
| `proof_warmup_slope_nonzero_when_positive_pnl` | core | STRONG | 6a: starts from `new()` | Near-good, acceptable |
| `fast_frame_touch_account_only_mutates_one_account` | core | STRONG | 6f: position.abs() < 1_000, delta.abs() < 1_000_000 | OK |
| `fast_frame_deposit_only_mutates_one_account_vault_and_warmup` | core | STRONG | — | OK |
| `fast_frame_withdraw_only_mutates_one_account_vault_and_warmup` | core | STRONG | 6f: withdraw <= deposit forced by assume | OK |
| `fast_frame_execute_trade_only_mutates_two_accounts` | core | STRONG | 6f: delta.abs() < 10 very tight; 6e: hardcoded 1_000_000/2_000_000 capitals | Widen delta range |
| `fast_frame_settle_warmup_only_mutates_one_account_and_warmup_globals` | core | WEAK | 6f: all fields tightly bounded; 1: no canonical_inv assume | Add invariant assume |
| `fast_frame_update_warmup_slope_only_mutates_one_account` | core | WEAK | 6f: pnl < 10_000; 1: no canonical_inv assume | Widen bounds |
| `fast_valid_preserved_by_deposit` | core | STRONG | 6a: starts from `new()`; 6f: amount < 10_000 | Good pattern, but not inductive (concrete initial state) |
| `fast_valid_preserved_by_withdraw` | core | STRONG | 6a: starts from `new()` + prior deposit | OK |
| `fast_valid_preserved_by_execute_trade` | core | STRONG | 6f: delta.abs() < 100 tight; hardcoded 100_000 capitals | Widen delta |
| `fast_valid_preserved_by_settle_warmup_to_capital` | core | WEAK | 6f: all fields < 5_000/2_000/10_000 very tight | Widen all bounds |
| `fast_valid_preserved_by_top_up_insurance_fund` | core | STRONG | — | OK |
| `fast_neg_pnl_settles_into_capital_independent_of_warm_cap` | core | STRONG | — | OK |
| `fast_withdraw_cannot_bypass_losses_when_position_zero` | core | STRONG | — | OK |
| `fast_neg_pnl_after_settle_implies_zero_capital` | core | WEAK | 4: `settle_warmup_to_capital` is called WITHOUT prior `recompute_aggregates` in all paths; 1: no canonical_inv | Ensure aggregates are consistent before settle |
| `neg_pnl_settlement_does_not_depend_on_elapsed_or_slope` | core | STRONG | — | OK |
| `withdraw_calls_settle_enforces_pnl_or_zero_capital_post` | core | STRONG | 6e: position=0 hardcoded | Add symbolic position |
| `fast_maintenance_margin_uses_equity_including_negative_pnl` | core | WEAK | 6f: capital < 10_000, pnl < 10_000, position < 1_000 tight; 5: manually-set aggregates may not match account state | Use `sync_engine_aggregates` before proof assertion |
| `fast_account_equity_computes_correctly` | core | STRONG | — | OK |
| `proof_fee_credits_never_inflate_from_settle` | core | STRONG | — | OK |
| `proof_settle_maintenance_deducts_correctly` | core | STRONG | — | OK |
| `proof_keeper_crank_advances_slot_monotonically` | core | STRONG | 6e: symbolic slot bounded to 0..200 | OK |
| `proof_keeper_crank_best_effort_settle` | core | STRONG | 6e: hardcoded slot values | OK |
| `proof_close_account_requires_flat_and_paid` | core | STRONG | — | OK |
| `proof_total_open_interest_initial` | core | STRONG | — | OK |
| `proof_require_fresh_crank_gates_stale` | core | STRONG | — | OK |
| `proof_stale_crank_blocks_withdraw` | core | STRONG | — | OK |
| `proof_stale_crank_blocks_execute_trade` | core | STRONG | — | OK |
| `proof_close_account_rejects_positive_pnl` | core | STRONG | — | OK |
| `proof_close_account_includes_warmed_pnl` | core | STRONG | — | OK |
| `proof_close_account_negative_pnl_written_off` | core | STRONG | — | OK |
| `proof_set_risk_reduction_threshold_updates` | core | STRONG | — | OK |
| `proof_trading_credits_fee_to_user` | core | STRONG | — | OK |
| `proof_keeper_crank_forgives_half_slots` | core | STRONG | — | OK |
| `proof_net_extraction_bounded_with_fee_credits` | core | STRONG | 6f: fee_credits bounded tightly | Acceptable |
| **`proof_lq1_liquidation_reduces_oi_and_enforces_safety`** | core | **UNIT TEST** | 1: concrete deposit(500), concrete position, concrete oracle; 6b: one scenario only | **HIGH PRIORITY: add symbolic capital/oracle inputs** |
| **`proof_lq2_liquidation_preserves_conservation`** | core | **UNIT TEST** | 1: all concrete inputs; 6b: one scenario | **HIGH PRIORITY: make capital/position symbolic** |
| **`proof_lq3a_profit_routes_through_adl`** | core | **UNIT TEST** | 1: all capital/position/oracle concrete | **HIGH PRIORITY: needs symbolic coverage** |
| **`proof_lq4_liquidation_fee_paid_to_insurance`** | core | **UNIT TEST** | 1: all concrete + hardcoded expected_fee=10_000; 4: vacuity risk if expected_fee wrong | **HIGH PRIORITY: use symbolic position/capital** |
| `proof_keeper_crank_best_effort_liquidation` | core | UNIT TEST | 1: concrete setup throughout | Add symbolic capital |
| `proof_lq6_n1_boundary_after_liquidation` | core | WEAK | 6f: capital tightly bounded; 6e: concrete position; 2: single price scenario | Widen capital range, make position symbolic |
| `proof_liq_partial_1_safety_after_liquidation` | core | WEAK | 6f: user_capital bounded small; 2: `if result.is_ok()` without non-vacuity | Add `assert_ok!(result)` for non-vacuity |
| `proof_liq_partial_2_dust_elimination` | core | UNIT TEST | 1: concrete capital/position/oracle | Needs symbolic inputs |
| `proof_liq_partial_3_routing_is_complete_via_conservation_and_n1` | core | UNIT TEST | 1: all concrete | Needs symbolic inputs |
| `proof_liq_partial_4_conservation_preservation` | core | WEAK | 6e: concrete PNL values (-9_000/9_000); 6f: capital=10_000 hardcoded | Make PNL symbolic |
| `proof_liq_partial_deterministic_reaches_target_or_full_close` | core | UNIT TEST | 1: fully concrete (deposit 200_000, position 10_000_000, oracle 1_000_000) | Convert to symbolic; remove "deterministic" from name |
| `fast_valid_preserved_by_garbage_collect_dust` | core | STRONG | — | OK |
| `withdrawal_maintains_margin_above_maintenance` | core | STRONG | 6f: delta.abs() < 10 tight | Widen delta |
| `withdrawal_rejects_if_below_initial_margin_at_oracle` | core | STRONG | — | OK |
| `proof_inv_holds_for_new_engine` | core | UNIT TEST | 1: concrete (no symbolic inputs, just checks new()) | Acceptable as sanity proof, not a security proof |
| `proof_inv_preserved_by_add_user` | core | STRONG | 6a: starts from `new()`; canonical_inv used as `assert` not `assume` (slight pattern issue) | OK |
| `proof_inv_preserved_by_add_lp` | core | STRONG | 6a: starts from `new()` | OK |
| `proof_execute_trade_preserves_inv` | core | STRONG | 6f: delta -100..100 tight; hardcoded capitals | Widen delta range |
| `proof_execute_trade_conservation` | core | STRONG | 6f: delta -50..50; 6a: uses `conservation_fast_no_funding` not `canonical_inv` | Consider checking full canonical_inv |
| `proof_execute_trade_margin_enforcement` | core | STRONG | — | OK |
| `proof_deposit_preserves_inv` | core | STRONG | 6a: starts from `new()`; canonical_inv assumed after construction | Near-inductive, good |
| `proof_withdraw_preserves_inv` | core | STRONG | 6a: starts from `new()` + deposit | Good |
| `proof_add_user_structural_integrity` | core | STRONG | — | OK |
| `proof_close_account_structural_integrity` | core | STRONG | — | OK |
| `proof_liquidate_preserves_inv` | core | STRONG | 6f: oracle 800k..1.2M tight; 6b: `if result.is_ok()` without forced non-vacuity | Add `assert_ok!(result)` |
| `proof_liquidate_actually_fires` | core | STRONG | 6f: oracle bounded 800k..1.2M; 6e: capital=100 hardcoded | Good non-vacuity pattern |
| `proof_settle_warmup_preserves_inv` | core | WEAK | 6f: capital=5_000, pnl=1_000 concrete; only exercises positive PNL path | Add symbolic negative PNL path |
| `proof_settle_warmup_negative_pnl_immediate` | core | STRONG | — | OK |
| `proof_keeper_crank_preserves_inv` | core | STRONG | — | OK |
| `proof_gc_dust_preserves_inv` | core | STRONG | — | OK |
| `proof_gc_dust_structural_integrity` | core | STRONG | — | OK |
| `proof_close_account_preserves_inv` | core | STRONG | — | OK |
| `proof_sequence_deposit_trade_liquidate` | core | UNIT TEST | 1: concrete deposit 5_000/50_000, concrete delta=25, concrete slot=100 | Add symbolic deposit/delta |
| `proof_sequence_deposit_crank_withdraw` | core | STRONG | 6f: deposit/withdraw tightly bounded | OK |
| `proof_trade_creates_funding_settled_positions` | core | STRONG | 6f: delta 50..200 positive-only; 6e: deposits hardcoded | Good proof |
| `proof_crank_with_funding_preserves_inv` | core | STRONG | 6f: funding_rate -100..100; delta=50 hardcoded | OK |
| `proof_variation_margin_no_pnl_teleport` | core | STRONG | — | OK |
| `proof_trade_pnl_zero_sum` | core | STRONG | 6f: delta bounded tightly | OK |
| `kani_no_teleport_cross_lp_close` | core | WEAK | 6f: tight bounds on all fields; 6e: multiple hardcoded concrete values | Widen symbolic range |
| `kani_rejects_invalid_matcher_output` | core | STRONG | — | OK |
| `kani_cross_lp_close_no_pnl_teleport` | core | WEAK | 6f: all capitals/positions hardcoded | Make symbolic |
| `proof_haircut_ratio_formula_correctness` | core | WEAK | 6f: vault <= 100_000 small; 5: manually sets aggregates (structural inv not checked); 6a: bypasses canonical_inv | Add canonical_inv assume |
| `proof_effective_equity_with_haircut` | core | WEAK | 6f: vault <= 100, pnl < 50 extremely tight; 5: symbolic collapse risk on division | Widen to at least 1_000_000 |
| `proof_principal_protection_across_accounts` | core | STRONG | — | OK |
| `proof_profit_conversion_payout_formula` | core | STRONG | — | OK |
| `proof_rounding_slack_bound` | core | WEAK | 6f: extremely small bounds; 5: symbolic division collapse | Widen significantly |
| `proof_liveness_after_loss_writeoff` | core | STRONG | — | OK |
| `proof_gap1_touch_account_err_no_mutation` | core | UNIT TEST | 1: concrete MAX_POSITION_ABS + 10^19 hardcoded to force overflow | OK as regression proof |
| `proof_gap1_settle_mark_err_no_mutation` | core | UNIT TEST | 1: concrete values; targeted regression | OK as regression proof |
| `proof_gap1_crank_with_fees_preserves_inv` | core | STRONG | 6f: fee_credits -500..500 | OK |
| `proof_gap2_rejects_overfill_matcher` | core | UNIT TEST | 1: concrete 1_000 size, 1_000_000 oracle, 1_000_000 capital | Acceptable for matcher rejection |
| `proof_gap2_rejects_zero_price_matcher` | core | UNIT TEST | 1: concrete | Acceptable |
| `proof_gap2_rejects_max_price_exceeded_matcher` | core | UNIT TEST | 1: concrete | Acceptable |
| `proof_gap2_execute_trade_err_preserves_inv` | core | STRONG | 6f: size 50..500; 3: canonical_inv assumed | Good |
| `proof_gap3_conservation_trade_entry_neq_oracle` | core | STRONG | 6f: oracle 800k..1.2M, size 50..200 | Good coverage |
| `proof_gap3_conservation_crank_funding_positions` | core | STRONG | — | OK |
| `proof_gap3_multi_step_lifecycle_conservation` | core | STRONG | 6f: symbolic variables bounded reasonably | OK |
| **`proof_gap4_trade_extreme_price_no_panic`** | core | **UNIT TEST** | 1: concrete prices {1, 1e6, MAX}; 2: `if result.is_ok()` without forced non-vacuity; 4: vacuity risk if all 3 error | Replace with symbolic price proof |
| **`proof_gap4_trade_extreme_size_no_panic`** | core | **UNIT TEST** | 1: concrete sizes {1, half_max, max}; 4: vacuity risk | Replace with symbolic size proof |
| `proof_gap4_trade_partial_fill_diff_price_no_panic` | core | WEAK | 4: `if result.is_ok()` without non-vacuity check; assertions may never fire | Add `assert!(result.is_ok())` |
| `proof_gap4_margin_extreme_values_no_panic` | core | UNIT TEST | 1: all concrete extreme values; checks no-panic only | OK as no-panic check |
| `proof_gap5_fee_settle_margin_or_err` | core | STRONG | — | OK |
| `proof_gap5_fee_credits_trade_then_settle_bounded` | core | STRONG | — | OK |
| `proof_gap5_fee_credits_saturating_near_max` | core | UNIT TEST | 1: near-max concrete values | OK as boundary check |
| `proof_gap5_deposit_fee_credits_conservation` | core | STRONG | — | OK |
| `proof_set_pnl_maintains_pnl_pos_tot` | core | STRONG | — | OK |
| `proof_set_capital_maintains_c_tot` | core | STRONG | — | OK |
| `proof_force_close_with_set_pnl_preserves_invariant` | core | STRONG | — | OK |
| `proof_multiple_force_close_preserves_invariant` | core | STRONG | — | OK |
| `proof_haircut_ratio_bounded` | core | STRONG | — | OK |
| `proof_effective_pnl_bounded_by_actual` | core | STRONG | — | OK |
| `proof_recompute_aggregates_correct` | core | STRONG | — | OK |
| **`proof_NEGATIVE_bypass_set_pnl_breaks_invariant`** | core | **VACUOUS** | **4: assertion is DESIGNED TO FAIL — Kani always finds counterexample; running this proof breaks CI with a false alarm; misleading as a safety proof** | **CRITICAL: Remove or gate with `#[cfg(not(kani))]` + convert to unit test; never ship as a `#[kani::proof]`** |
| `kani_partial_liquidation_batch_bounded` | core | WEAK | 1: pure inline math, no actual function call; 2: asserts inline calculation against itself | Replace with proof over actual `compute_partial_batch` function |
| `kani_mark_price_trigger_independent_of_oracle` | core | WEAK | 1: `is_healthy_again` is same expression as `is_healthy` — final assert is tautological | Simplify or strengthen with actual trigger function |
| `kani_premium_funding_rate_bounded` | core | STRONG | — | OK |
| `kani_premium_funding_rate_zero_inputs` | core | STRONG | — | OK |
| `kani_combined_funding_rate_bounded` | core | STRONG | — | OK |
| `kani_combined_funding_rate_extremes` | core | STRONG | — | OK |
| `kani_premium_funding_rate_zero_premium` | core | STRONG | — | OK |
| `kani_premium_funding_rate_sign_correctness` | core | STRONG | — | OK |
| `kani_combined_funding_rate_convex` | core | STRONG | — | OK |
| `proof_trade_with_premium_funding_preserves_inv` | core | STRONG | 6f: delta.abs() < 500; oracle 500k..2M | OK |
| `proof_liquidation_with_partial_params_preserves_inv` | core | WEAK | 4: `if result.is_ok()` without non-vacuity check; 6f: user_capital 100..5_000 tight | Add assert_ok! for non-vacuity |
| `proof_trade_with_tiered_fees_preserves_inv` | core | STRONG | — | OK |
| `proof_funding_zero_sum_across_accounts` | core | STRONG | — | OK |
| `proof_stale_sweep_blocks_risk_increasing_trade` | core | STRONG | — | OK |
| `proof_gc_dust_symbolic_criteria` | core | STRONG | — | OK |
| `proof_gap4_trade_extreme_price_symbolic` | core | STRONG | 6f: oracle bounded; replaces concrete gap4 proof | Good improvement |
| `proof_liquidation_must_reset_warmup_on_mark_increase` | core | STRONG | — | OK |

---

### percolator-prog/tests/kani.rs (Selected critical proofs)

| Proof Name | File | Classification | Criteria Gaps | Recommendation |
|---|---|---|---|---|
| `kani_matcher_rejects_wrong_abi_version` | prog | STRONG | — | OK |
| `kani_matcher_rejects_missing_valid_flag` | prog | STRONG | — | OK |
| `kani_matcher_rejects_rejected_flag` | prog | STRONG | — | OK |
| `kani_matcher_rejects_wrong_req_id` | prog | STRONG | — | OK |
| `kani_matcher_rejects_wrong_lp_account_id` | prog | STRONG | — | OK |
| `kani_matcher_rejects_wrong_oracle_price` | prog | STRONG | — | OK |
| `kani_matcher_rejects_nonzero_reserved` | prog | STRONG | — | OK |
| `kani_matcher_rejects_zero_exec_price` | prog | STRONG | — | OK |
| `kani_matcher_zero_size_requires_partial_ok` | prog | STRONG | — | OK |
| `kani_matcher_rejects_exec_size_exceeds_req` | prog | STRONG | — | OK |
| `kani_matcher_rejects_sign_mismatch` | prog | STRONG | — | OK |
| `kani_owner_mismatch_rejected` | prog | STRONG | — | OK |
| `kani_owner_match_accepted` | prog | STRONG | — | OK |
| `kani_admin_mismatch_rejected` | prog | STRONG | — | OK |
| `kani_admin_match_accepted` | prog | STRONG | — | OK |
| `kani_admin_burned_disables_ops` | prog | STRONG | 2: only tests burned case explicitly | OK |
| `kani_matcher_identity_mismatch_rejected` | prog | STRONG | — | OK |
| `kani_matcher_identity_match_accepted` | prog | STRONG | — | OK |
| `kani_matcher_shape_rejects_non_executable_prog` | prog | UNIT TEST | 1: concrete MatcherAccountsShape struct | Merge into universal shape proof |
| `kani_matcher_shape_rejects_executable_ctx` | prog | UNIT TEST | 1: concrete | Merge into universal shape proof |
| `kani_matcher_shape_rejects_wrong_ctx_owner` | prog | UNIT TEST | 1: concrete | Merge into universal shape proof |
| `kani_matcher_shape_rejects_short_ctx` | prog | UNIT TEST | 1: concrete | Merge into universal shape proof |
| `kani_matcher_shape_valid_accepted` | prog | UNIT TEST | 1: concrete struct | Keep, but also add universal shape proof |
| `kani_pda_mismatch_rejected` | prog | STRONG | — | OK |
| `kani_pda_match_accepted` | prog | STRONG | — | OK |
| `kani_nonce_unchanged_on_failure` | prog | STRONG | — | OK |
| `kani_nonce_advances_on_success` | prog | STRONG | — | OK |
| `kani_nonce_wraps_at_max` | prog | STRONG | Note: duplicates `kani_nonce_advances_on_success` exactly | Deduplicate |
| `kani_cpi_uses_exec_size` | prog | STRONG | — | OK |
| `kani_gate_inactive_when_threshold_zero` | prog | STRONG | — | OK |
| `kani_gate_inactive_when_balance_exceeds` | prog | STRONG | — | OK |
| `kani_gate_active_when_conditions_met` | prog | STRONG | — | OK |
| `kani_single_owner_mismatch_rejected` | prog | STRONG | — | OK |
| `kani_single_owner_match_accepted` | prog | STRONG | — | OK |
| `kani_trade_rejects_user_mismatch` | prog | STRONG | — | OK |
| `kani_trade_rejects_lp_mismatch` | prog | STRONG | — | OK |
| `kani_tradecpi_rejects_non_executable_prog` | prog | WEAK | 1: all booleans except nonce/exec_size concrete; 2: only one flag combination | Use universal proof instead |
| `kani_tradecpi_rejects_executable_ctx` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_rejects_pda_mismatch` | prog | WEAK | 1: concrete flags, concrete shape | Use universal proof |
| `kani_tradecpi_rejects_user_auth_failure` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_rejects_lp_auth_failure` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_rejects_identity_mismatch` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_rejects_abi_failure` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_rejects_gate_risk_increase` | prog | WEAK | 1: concrete flags | Use universal proof |
| `kani_tradecpi_allows_gate_risk_decrease` | prog | WEAK | 1: concrete flags | Merge into universal acceptance test |
| `kani_tradecpi_reject_nonce_unchanged` | prog | UNIT TEST | 1: concrete bad_shape, all flags concrete | Superseded by universal proof P |
| `kani_tradecpi_accept_increments_nonce` | prog | WEAK | 1: concrete flags via valid_shape(); only symbolic nonce/exec_size | Superseded by universal proof P |
| `kani_tradecpi_accept_uses_exec_size` | prog | WEAK | 1: concrete flags; only exec_size symbolic | Consider removing (superseded by V section) |
| `kani_tradenocpi_rejects_user_auth_failure` | prog | UNIT TEST | 1: all concrete boolean inputs | Replace with universal nocpi proof |
| `kani_tradenocpi_rejects_lp_auth_failure` | prog | UNIT TEST | 1: all concrete | Replace with universal proof |
| `kani_tradenocpi_rejects_gate_risk_increase` | prog | UNIT TEST | 1: all concrete | Replace with universal proof |
| `kani_tradenocpi_accepts_valid` | prog | UNIT TEST | 1: all concrete | Replace with universal proof |
| `kani_matcher_zero_size_with_partial_ok_accepted` | prog | WEAK | 6e: exec_size=0 concrete; most other fields symbolic | OK as acceptance proof |
| `kani_tradecpi_rejects_ctx_owner_mismatch` | prog | UNIT TEST | 1: concrete shape + concrete flags | Superseded by universal proofs |
| `kani_tradecpi_rejects_ctx_len_short` | prog | UNIT TEST | 1: concrete | Superseded by universal proofs |
| `kani_tradecpi_any_reject_nonce_unchanged` | prog | STRONG | 6c: canonical_inv not involved (prog-level proof) | OK — gold standard for prog |
| `kani_tradecpi_any_accept_increments_nonce` | prog | STRONG | — | OK |
| `kani_len_ok_universal` | prog | STRONG | — | OK |
| `kani_lp_pda_shape_valid` | prog | UNIT TEST | 1: concrete struct | Replace with symbolic fields |
| `kani_lp_pda_rejects_wrong_owner` | prog | UNIT TEST | 1: concrete struct | Replace with symbolic |
| `kani_lp_pda_rejects_has_data` | prog | UNIT TEST | 1: concrete struct | Replace with symbolic |
| `kani_lp_pda_rejects_funded` | prog | UNIT TEST | 1: concrete struct | Replace with symbolic |
| `kani_oracle_feed_id_match` | prog | STRONG | — | OK |
| `kani_oracle_feed_id_mismatch` | prog | STRONG | — | OK |
| `kani_slab_shape_valid` | prog | UNIT TEST | 1: concrete struct | Replace with symbolic |
| `kani_slab_shape_invalid` | prog | STRONG | 1: symbolic bools | OK |
| `kani_decide_single_owner_accepts` | prog | UNIT TEST | 1: concrete true | Superseded by universal proof |
| `kani_decide_single_owner_rejects` | prog | UNIT TEST | 1: concrete false | Superseded by universal proof |
| `kani_decide_crank_permissionless_accepts` | prog | UNIT TEST | 1: concrete permissionless=true | OK as regression |
| `kani_decide_crank_self_accepts` | prog | UNIT TEST | 1: concrete idx_exists=true | OK as regression |
| `kani_decide_crank_rejects_no_idx` | prog | UNIT TEST | 1: concrete idx_exists=false | OK as regression |
| `kani_decide_crank_rejects_wrong_owner` | prog | STRONG | 1: symbolic keys with assume | OK |
| `kani_decide_admin_accepts` | prog | STRONG | — | OK |
| `kani_decide_admin_rejects` | prog | STRONG | — | OK |
| `kani_abi_ok_equals_validate` | prog | STRONG | — | OK, strong equivalence proof |
| `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | prog | STRONG | — | OK — strong universal proof |
| `kani_tradecpi_from_ret_any_accept_increments_nonce` | prog | STRONG | — | OK |
| `kani_tradecpi_from_ret_accept_uses_exec_size` | prog | STRONG | 6e: many flags hardcoded to true/false; 4: non-vacuity via panic if Reject | Good non-vacuity pattern |
| `kani_min_abs_boundary_rejected` | prog | UNIT TEST | 1: concrete i128::MIN boundary | OK as regression proof |
| `kani_matcher_accepts_minimal_valid_nonzero_exec` | prog | STRONG | — | OK |
| `kani_matcher_accepts_exec_size_equal_req_size` | prog | STRONG | — | OK |
| `kani_matcher_accepts_partial_fill_with_flag` | prog | STRONG | — | OK |
| `kani_crank_panic_requires_admin` | prog | STRONG | — | OK |
| `kani_crank_panic_with_admin_permissionless_accepts` | prog | STRONG | — | OK |
| `kani_crank_panic_burned_admin_rejects` | prog | STRONG | — | OK |
| `kani_crank_no_panic_permissionless_accepts` | prog | STRONG | — | OK |
| `kani_crank_no_panic_self_crank_rejects_wrong_owner` | prog | STRONG | — | OK |
| `kani_crank_no_panic_self_crank_accepts_owner_match` | prog | STRONG | — | OK |
| `kani_invert_zero_returns_raw` | prog | STRONG | — | OK |
| `kani_invert_nonzero_computes_correctly` | prog | STRONG | 6f: raw <= KANI_MAX_QUOTIENT tight | Acceptable for SAT performance |
| `kani_invert_zero_raw_returns_none` | prog | UNIT TEST | 1: raw=0 concrete | OK as boundary |
| `kani_invert_result_zero_returns_none` | prog | STRONG | — | OK |
| `kani_invert_monotonic` | prog | STRONG | 6f: both capped to KANI_MAX_QUOTIENT | Acceptable |
| `kani_base_to_units_conservation` | prog | STRONG | 6f: capped for SAT performance | OK |
| `kani_base_to_units_dust_bound` | prog | STRONG | — | OK |
| `kani_base_to_units_scale_zero` | prog | STRONG | — | OK |
| `kani_units_roundtrip` | prog | STRONG | 6f: units <= KANI_MAX_QUOTIENT | OK |
| `kani_units_to_base_scale_zero` | prog | STRONG | — | OK |
| `kani_base_to_units_monotonic` | prog | STRONG | — | OK |
| `kani_units_to_base_monotonic_bounded` | prog | STRONG | 6f: bounded to non-saturating range; comment documents this | OK |
| `kani_base_to_units_monotonic_scale_zero` | prog | STRONG | — | OK |
| `kani_withdraw_misaligned_rejects` | prog | STRONG | — | OK |
| `kani_withdraw_aligned_accepts` | prog | STRONG | — | OK |
| `kani_withdraw_scale_zero_always_aligned` | prog | STRONG | — | OK |
| `kani_decide_trade_cpi_universal` | prog | STRONG | 6c: all conditions combined in one symbolic proof | Gold standard for prog authorization |
| `inductive_clamp_within_bounds` | prog | STRONG | 1: proves stdlib `clamp()` behavior — minimal value | Misleadingly named; rename to `kani_stdlib_clamp_*` |
| `kani_decide_trade_nocpi_universal` | prog | STRONG | — | Gold standard for nocpi |
| `proof_ramp_no_underflow_if_slot_before_created` | prog | STRONG | — | OK |
| `proof_orphan_penalty_no_overflow` | prog | STRONG | 6f: elapsed <= 1_000_000 tight | OK |
| `proof_loyalty_mult_never_exceeds_max_tier_strong` | prog | STRONG | — | OK |
| `nightly_loyalty_applies_only_to_fee_income` | prog | STRONG | moved to nightly CI | OK |
| `proof_loyalty_reset_on_zero_delta` | prog | UNIT TEST | 1: delta=0 concrete | OK as boundary |
| `proof_util_fee_zero_below_kink1` | prog | WEAK | 1: proves an inline hardcoded `0` assertion, not an actual function call; assertion is tautological (`extra_fee_bps = 0; assert_eq!(extra_fee_bps, 0, ...)`) | **WEAK/UNIT TEST: replace with actual function call** |
| `proof_dispute_bond_claimed_at_most_once` | prog | WEAK | 1: inline model, not actual function; 2: models outcome with u8 0/1/2 | Replace with actual claim function |
| `proof_challenge_window_strictly_enforced` | prog | STRONG | — | OK |
| `proof_isolated_balance_never_negative` | prog | STRONG | — | OK |
| `proof_rebalancing_mode_never_permanent` | prog | STRONG | — | OK |
| `proof_tag_no_collision` | prog | STRONG | — | OK |
| `proof_inductive_insurance_fund_nonnegative` | prog | STRONG | 6a: pure math proof, no RiskEngine involved; misleadingly named as "inductive" | Rename; acceptable as pure arithmetic proof |
| `proof_inductive_lp_vault_conservation` | prog | STRONG | 6a: pure math with kani::assume precondition; not connected to RiskEngine | Rename to `proof_pure_*`; acceptable arithmetic proof |
| `proof_inductive_oi_cap_invariant` | prog | WEAK | 6a: pure inline math; `if accepted { assert!(new_oi <= oi_cap) }` where `accepted` is defined as `new_oi <= oi_cap` — **tautological assertion** | Fix tautology: assert before computing `accepted` |
| `kani_reclaim_slab_rent_rejects_initialised_slab` | prog | UNIT TEST | 1: just tests `MAGIC == MAGIC` as a constant | Acceptable as regression |
| `kani_reclaim_slab_rent_accepts_uninitialised_slab` | prog | STRONG | — | OK |
| `kani_reclaim_slab_rent_lamport_conservation` | prog | STRONG | — | OK |
| `kani_reclaim_slab_rent_zero_slab_always_accepted` | prog | STRONG | — | OK |
| `kani_quadratic_funding_disabled_when_k2_zero` | prog | STRONG | — | OK |
| `kani_quadratic_funding_monotonically_increases` | prog | STRONG | 6f: tightly bounded for SAT | OK |
| `kani_quadratic_funding_respects_clamp` | prog | STRONG | — | OK |
| `kani_quadratic_funding_zero_inputs` | prog | STRONG | — | OK |
| `kani_quadratic_funding_sign_follows_position` | prog | STRONG | — | OK |
| `kani_isqrt_u32_correct` | prog | STRONG | — | OK |
| `kani_isqrt_u32_edge_cases` | prog | UNIT TEST | 1: tests 0, 1, 4, u32::MAX concrete values | OK as boundary tests |
| `kani_vram_disabled_returns_base` | prog | STRONG | — | OK |
| `kani_vram_zero_target_returns_base` | prog | STRONG | — | OK |
| `kani_vram_never_reduces_below_base` | prog | STRONG | — | OK |
| `kani_vram_monotonic_in_volatility` | prog | STRONG | — | OK |
| `kani_vram_no_overflow` | prog | STRONG | — | OK |
| `kani_audit_crank_tag_value` | prog | UNIT TEST | 1: concrete tag value check | OK as constant check |
| `kani_tranche_fee_split_conservation` | prog | STRONG | — | OK |
| `kani_tranche_junior_yield_higher` | prog | STRONG | — | OK |
| `kani_tranche_loss_waterfall_junior_first` | prog | STRONG | — | OK |
| `kani_tranche_loss_never_exceeds_capital` | prog | STRONG | — | OK |
| `kani_tranche_loss_capital_conservation` | prog | STRONG | — | OK |
| `kani_tranche_fee_senior_only` | prog | STRONG | — | OK |
| `kani_tranche_disabled_by_default` | prog | UNIT TEST | 1: checks default struct field = false | OK |
| `kani_cmor_disabled_when_offset_zero` | prog | STRONG | — | OK |
| `kani_cmor_same_direction_no_credit` | prog | STRONG | — | OK |
| `kani_cmor_zero_position_no_credit` | prog | STRONG | — | OK |
| `kani_cmor_credit_bounded_by_offset` | prog | STRONG | — | OK |
| `kani_cmor_equal_hedge_full_credit` | prog | STRONG | — | OK |
| `kani_cmor_freshness_check` | prog | STRONG | — | OK |
| `kani_cmor_slab_pair_ordering_commutative` | prog | STRONG | — | OK |
| `kani_cmor_slab_pair_ordering_sorted` | prog | STRONG | — | OK |
| `kani_cmor_offset_pair_magic` | prog | UNIT TEST | 1: concrete magic constant | OK as regression |
| `kani_cmor_attestation_magic` | prog | UNIT TEST | 1: concrete magic constant | OK as regression |
| `kani_new_tags_sequential` | prog | STRONG | — | OK |
| `kani_selfliq_equity_never_increases` | prog | STRONG | — | OK |
| `kani_selfliq_equity_increase_detected` | prog | STRONG | — | OK |
| `kani_selfliq_unprofitable_with_fee` | prog | STRONG | 6f: tight bounds | OK |
| `kani_selfliq_fee_always_positive` | prog | STRONG | — | OK |
| `kani_selfliq_zero_position_zero_fee` | prog | STRONG | — | OK |
| `kani_sandwich_bounded_accepts_in_range` | prog | STRONG | — | OK |
| `kani_sandwich_bounded_rejects_extreme` | prog | STRONG | — | OK |
| `kani_sandwich_zero_cap_no_movement` | prog | STRONG | — | OK |
| `kani_oracle_price_valid_universal` | prog | STRONG | — | OK |
| `kani_oracle_valid_price_accepted` | prog | UNIT TEST | 1: concrete price = 1_000_000 | Add symbolic price |
| `kani_oracle_99pct_drop_triggers_breaker` | prog | UNIT TEST | 1: concrete 99% drop scenario | OK as regression |
| `kani_oracle_adversarial_zero_clamped` | prog | STRONG | — | OK |
| `kani_oracle_validation_and_breaker_compose` | prog | STRONG | — | OK |
| `proof_oi_cap_enforcement` | prog | WEAK | 2: `if exceeds { assert!(current_oi > max_oi) }` is tautological (exceeds = current_oi > max_oi); no actual `check_oi_cap` function call | Call actual function; fix tautology |
| `proof_oi_cap_disabled_when_zero` | prog | UNIT TEST | 1: multiplier=0 concrete; assertion `multiplier == 0` trivially true; no function called | **UNIT TEST: tautological, zero security value** |
| `proof_oi_cap_no_overflow` | prog | WEAK | 2: assertion `max_oi <= u128::MAX` trivially true for u128; no actual safety property | Replace with saturation bound check |
| `proof_margin_params_safety` | prog | STRONG | — | OK |
| `proof_margin_always_requires_positive_collateral` | prog | STRONG | — | OK |
| `proof_median_no_valid_prices` | prog | UNIT TEST | 1: proves behavior with zero valid prices | OK as edge case |
| `proof_deviation_detection` | prog | STRONG | — | OK |
| `proof_deviation_disabled_on_first_price` | prog | STRONG | — | OK |
| `proof_deviation_disabled_when_zero_bps` | prog | STRONG | — | OK |
| `proof_staleness_rejects_old_price` | prog | STRONG | — | OK |
| `proof_ring_buffer_wraps` | prog | STRONG | — | OK |
| `proof_fee_mult_bounded` | prog | STRONG | — | OK |
| `proof_fee_mult_kink_boundaries` | prog | STRONG | — | OK |
| `proof_util_bps_no_panic` | prog | STRONG | — | OK |
| `kani_fee_nonzero_for_any_nonzero_trade` | prog | STRONG | — | OK |
| `kani_fee_zero_iff_zero_input` | prog | STRONG | — | OK |
| `kani_dust_accumulation_commutative` | prog | STRONG | — | OK |
| `kani_dust_accumulation_associative` | prog | STRONG | — | OK |
| `kani_dust_sweep_bounded_loss` | prog | STRONG | — | OK |
| `kani_cb_trigger_disabled_when_cap_zero` | prog | STRONG | — | OK |
| `kani_statemachine_close_before_open_rejected` | prog | UNIT TEST | 1: concrete state transitions | OK as state machine tests |
| `kani_statemachine_reinit_rejected` | prog | UNIT TEST | 1: concrete | OK |
| `kani_statemachine_deposit_after_close_rejected` | prog | UNIT TEST | 1: concrete | OK |
| `kani_statemachine_crank_before_init_rejected` | prog | UNIT TEST | 1: concrete | OK |
| `kani_statemachine_all_ops_rejected_on_closed` | prog | UNIT TEST | 1: concrete | OK |
| `kani_statemachine_trade_only_on_open` | prog | UNIT TEST | 1: concrete | OK |
| `kani_concurrency_two_successes_monotone_nonce` | prog | STRONG | — | OK |
| `kani_concurrency_fail_then_success` | prog | STRONG | — | OK |
| `kani_concurrency_two_failures_nonce_unchanged` | prog | STRONG | — | OK |
| `kani_concurrency_position_zero_sum_preserved` | prog | STRONG | — | OK |
| `kani_concurrency_two_trades_zero_sum` | prog | STRONG | — | OK |
| `kani_concurrency_zero_sum_detection` | prog | STRONG | — | OK |

---

## Priority Remediation Recommendations

### P0 — Fix immediately (CI integrity)

1. **`proof_NEGATIVE_bypass_set_pnl_breaks_invariant`** (`percolator-core`): Remove `#[kani::proof]` attribute. This proof deliberately fails Kani verification (asserts an invariant that is broken by the test setup). Shipping it as a standard harness causes CI to report permanent failures, masking real regressions. Convert to a Rust `#[test]` unit test or a `kani::cover!()` proof.

### P1 — High priority (security coverage gaps)

2. **LQ1–LQ4 liquidation proofs** (`percolator-core`): All four primary liquidation proofs use fully concrete inputs. Liquidation is the highest-risk invariant in the system. Convert to symbolic: make `user_capital: u128 = kani::any()` with `kani::assume(canonical_inv(&engine))`.

3. **`proof_gap4_trade_extreme_price_no_panic` / `proof_gap4_trade_extreme_size_no_panic`** (`percolator-core`): Three concrete engine instances in one proof. `if result.is_ok()` without `assert_ok!` means all assertions may be skipped if all three fail. Replace with symbolic price/size proofs.

4. **No INDUCTIVE proofs exist** in either file. The canonical invariant is never proven over a fully arbitrary initial state. Without inductive closure, the chain of INV-preservation proofs only covers states reachable from `RiskEngine::new()`. Consider adding one true inductive harness per critical operation (deposit, withdraw, execute_trade) that starts from a **fully symbolic** `RiskEngine` state with `kani::assume(canonical_inv)` as the ONLY precondition.

### P2 — Medium priority (proof quality)

5. **Tautological assertions** in `proof_oi_cap_enforcement`, `proof_oi_cap_disabled_when_zero`, `proof_oi_cap_no_overflow`, `proof_inductive_oi_cap_invariant`, `kani_mark_price_trigger_independent_of_oracle` — assertions that are unconditionally true provide no verification value. Fix or remove.

6. **I5/I7 warmup + isolation proofs** (`percolator-core`): All have tight bounds (< 10_000) and no `canonical_inv` precondition. Widen bounds and add invariant assumptions.

7. **L-section TradeCpi rejection proofs** (`percolator-prog`, lines 762–1050): 9 proofs with concrete boolean flags that are superseded by the universal proofs in section P/V. These can be deleted to reduce maintenance burden.

8. **`proof_util_fee_zero_below_kink1`** (`percolator-prog`): Asserts `extra_fee_bps == 0` when that variable was set to `0` on the previous line. Replace with a call to the actual `compute_util_fee_extra_bps()` function.

9. **`proof_gap4_trade_partial_fill_diff_price_no_panic`** (`percolator-core`): Uses `if result.is_ok()` without `assert_ok!`. If `PartialFillDiffPriceMatcher` always returns `Err` for the symbolic inputs, the `canonical_inv` assertion is never evaluated. Add non-vacuity guard.

### P3 — Low priority (cleanup)

10. **`kani_nonce_wraps_at_max`** (`percolator-prog`): Exact duplicate of `kani_nonce_advances_on_success` (both prove `nonce_on_success(x) == x.wrapping_add(1)` for all `x`). Remove one.

11. **`proof_inductive_*` naming in `percolator-prog`**: The three `proof_inductive_*` proofs are not inductive — they are standalone arithmetic proofs. Rename to `proof_arithmetic_*` or `proof_pure_*` to avoid confusion.

12. **`inductive_clamp_within_bounds`** (`percolator-prog`): Proves stdlib `u64::clamp()` behavior. Rename to `kani_stdlib_clamp_within_bounds` or remove.

---

## Nightly-tagged proofs (excluded from PR CI)

The following proofs are prefixed `nightly_` and intentionally excluded from PR CI due to SAT complexity. They provide important properties but carry long run times:
- `nightly_fee_ceil_geq_floor`, `nightly_fee_monotone_in_notional`, `nightly_fee_monotone_in_bps`
- `nightly_cb_ema_update_weighted_average`, `nightly_cb_trigger_fires_correctly`, `nightly_cb_recovery_distance_decreases`
- `nightly_loyalty_applies_only_to_fee_income`
- `nightly_dust_single_deposit_conservation`, `nightly_dust_two_deposits_conservation`
- `nightly_lp_collateral_value_bounded_by_vault_tvl`, `nightly_lp_collateral_liquidation_triggers_on_tvl_drop`
- `nightly_oracle_adversarial_max_clamped`, `nightly_oracle_slot_within_bounds`
- `nightly_skew_adjusted_cap_never_exceeds_base_cap`, `nightly_fee_mult_monotonically_increases_with_utilization`
- `nightly_ramp_never_exceeds_configured_multiplier`, `nightly_ramp_monotonically_increases`

These are classified STRONG and acceptable; no action needed beyond ensuring nightly CI actually runs them.

---

## percolator-stake Audit — 2026-03-12

**Auditor:** Sentinel (security sub-agent)
**Scope:** `percolator-stake/tests/kani.rs` (18 proofs, u64 types) + `percolator-stake/kani-proofs/src/lib.rs` (42 proofs, u32 mirror)
**Total proofs audited:** 60

### Summary

| Classification | kani-proofs/lib.rs | tests/kani.rs | Total | % |
|---|---|---|---|---|
| **INDUCTIVE** | 0 | 0 | **0** | 0% |
| **STRONG** | 9 | 10 | **19** | 32% |
| **WEAK** | 33 | 6 | **39** | 65% |
| **UNIT TEST** | 0 | 2 | **2** | 3% |
| **VACUOUS** | 0 | 0 | **0** | 0% |
| **Total** | 42 | 18 | **60** | — |

### Key findings

1. **ZERO inductive proofs** — No proof in either file uses `assume(INV) + transition + assert(INV)` on a fully symbolic pool state. The core conservation property (anti-inflation) is only verified for bounded input ranges.

2. **kani-proofs/ uses u32 mirror, not production types** — All 42 proofs in `kani-proofs/src/lib.rs` use `u32` inputs with `u64` intermediates, mirroring the `u64/u128` production code. The design rationale ("scale-invariant") is plausible for pure floor-division LP math but is not formally proven. Tight bounds (most proofs: values < 15–100) further limit coverage.

3. **Conservation proofs severely under-bounded** — `proof_deposit_withdraw_no_inflation` (the core anti-inflation proof in kani-proofs/) uses bounds of `< 20`. This proves inflation prevention only for tiny pools. The property should hold for all u32/u64 values but is not demonstrated. Recommend: add unbounded proof using u128 intermediates.

4. **Duplicate proofs between files** — `tests/kani.rs` and `kani-proofs/src/lib.rs` contain overlapping proofs (e.g., `proof_deposit_withdraw_no_inflation`, `proof_first_depositor_exact`). The kani-proofs/ subpackage is the intended canonical location (PR #13). `tests/kani.rs` appears to be a superseded predecessor.

5. **C9 orphaned-value protection proofs (kani-proofs/, §10)** — STRONG. Correctly proves both directions (orphaned value blocks deposits, valueless LP blocks deposits, true first depositor works). These are the best proofs in the set.

6. **Cooldown/cap enforcement proofs (kani-proofs/, §8–9)** — STRONG. Clean implementation, covers boundary cases correctly.

### Per-Proof Classification — kani-proofs/src/lib.rs (42 proofs)

| Proof | Classification | Criteria gaps | Recommendation |
|---|---|---|---|
| proof_deposit_withdraw_no_inflation | WEAK | Bounds < 20; not full u32 range | Extend to unconstrained or prove scale-invariance |
| proof_first_depositor_exact | WEAK | Bounds < 100; concrete path | Acceptable as regression anchor |
| proof_two_depositors_conservation | WEAK | Bounds < 20; not full range | Key property — needs unbounded version |
| proof_no_dilution | WEAK | Bounds < 15 | Important fairness property; extend range |
| proof_flush_full_return_conservation | WEAK | Bounds < 100 | Acceptable |
| proof_lp_deposit_no_panic | STRONG | None — full u32 range | Keep |
| proof_lp_deposit_overflow_guard | STRONG | None — full u32 range, key overflow property | Keep |
| proof_collateral_withdraw_no_panic | STRONG | None | Keep |
| proof_pool_value_no_panic | STRONG | None | Keep |
| proof_flush_available_no_panic | STRONG | None | Keep |
| proof_lp_rounding_favors_pool | WEAK | Bounds < 100 | Good property; extend to full range |
| proof_larger_deposit_more_lp | WEAK | Bounds < 100 | Acceptable |
| proof_larger_burn_more_collateral | WEAK | Bounds < 100 | Acceptable |
| proof_equal_deposits_equal_lp | WEAK | Bounds < 50; concrete path | Acceptable |
| proof_full_burn_bounded | WEAK | Bounds < 100 | Acceptable |
| proof_partial_less_than_full | WEAK | Bounds < 100 | Acceptable |
| proof_flush_preserves_value | WEAK | Bounds < 100 | Acceptable |
| proof_flush_bounded | WEAK | Bounds < 100 | Acceptable |
| proof_flush_max_then_zero | WEAK | Bounds < 100 | Acceptable |
| proof_pool_value_correctness | WEAK | Bounds < 100 | Acceptable |
| proof_deposit_increases_value | WEAK | Bounds < 100 | Acceptable |
| proof_flush_return_conservation | WEAK | Bounds < 100 | Acceptable |
| proof_returns_increase_value | WEAK | Bounds < 50 | Acceptable |
| proof_zero_deposit_zero_lp | WEAK | Bounds < 100 | Good zero-boundary check |
| proof_zero_burn_zero_col | WEAK | Bounds < 100 | Good zero-boundary check |
| proof_cooldown_no_panic | STRONG | None — full u32 range | Keep |
| proof_cooldown_not_immediate | WEAK | Bounds < 100 | Acceptable |
| proof_cooldown_exact_boundary | WEAK | Bounds < 100 | Acceptable |
| proof_cap_zero_uncapped | STRONG | None — full u32 range | Keep |
| proof_cap_at_boundary | WEAK | Bounds < 100 | Acceptable |
| proof_cap_above_boundary | WEAK | Bounds < 100 | Acceptable |
| proof_c9_orphaned_value_blocked | WEAK | Bounds < 100 | Key C9 property; extend to full range |
| proof_c9_valueless_lp_blocked | WEAK | Bounds < 100 | Key C9 property; extend to full range |
| proof_c9_true_first_depositor | WEAK | Bounds < 100 | Acceptable |
| proof_flush_reduces_value_exactly | WEAK | Bounds < 100 | Acceptable |
| proof_determinism_across_states | WEAK | Bounds < 50 | Acceptable |
| proof_roundtrip_under_pool_value_change | WEAK | Bounds < 15 | Important; extend range significantly |
| proof_no_inflation_attack | WEAK | Bounds < 20 | Key attack resistance proof; extend to full range |
| proof_cooldown_boundary_iff | WEAK | Bounds < 1000 | Good bidirectional proof |
| proof_flush_conservation_lp_value | WEAK | Bounds < 20 | Acceptable |
| proof_pool_value_with_flush_no_panic | STRONG | None — full u32 range | Keep |
| proof_exceeds_cap_no_panic | STRONG | None — full u32 range | Keep |

### Per-Proof Classification — tests/kani.rs (18 proofs)

| Proof | Classification | Criteria gaps | Recommendation |
|---|---|---|---|
| proof_deposit_withdraw_no_inflation | WEAK | Bounds ≤ 1B (not full u64) | Deprecated by kani-proofs/ version |
| proof_first_depositor_exact | UNIT TEST | Concrete initial state (supply=0, pv=0) | Deprecated by kani-proofs/ version |
| proof_two_depositors_conservation | WEAK | Bounds ≤ 100M | Deprecated by kani-proofs/ version |
| proof_lp_deposit_no_panic | STRONG | None | Deprecated; keep kani-proofs/ version |
| proof_collateral_withdraw_no_panic | STRONG | None | Deprecated; keep kani-proofs/ version |
| proof_pool_value_no_panic | STRONG | None | Deprecated |
| proof_flush_available_no_panic | STRONG | None | Deprecated |
| proof_equal_deposits_equal_lp | UNIT TEST | Trivially true for pure fn | Deprecated |
| proof_larger_deposit_more_lp | WEAK | Bounds ≤ 1B | Deprecated |
| proof_larger_burn_more_collateral | WEAK | Bounded by supply | Deprecated |
| proof_full_burn_bounded | STRONG | supply > 0 only | Deprecated; superseded |
| proof_partial_burn_less_than_full | STRONG | lp < supply only | Deprecated; superseded |
| proof_flush_bounded_by_deposited | STRONG | None | Deprecated; superseded |
| proof_flush_max_then_zero | STRONG | Constrained (correctly) | Deprecated; superseded |
| proof_pool_value_none_iff_overdrawn | STRONG | None — key correctness proof | Deprecated; superseded |
| proof_deposit_increases_value | STRONG | None | Deprecated; superseded |
| proof_lp_rounds_down | WEAK | Bounds ≤ 1B | Deprecated; superseded |
| proof_withdrawal_rounds_down | WEAK | Bounded | Deprecated; superseded |

### Recommended Tasks (Priority Order)

**P1 — File tasks for coder:**

1. **Add inductive proof** to `kani-proofs/`: `proof_pool_invariant_inductive` — prove that for ANY symbolic pool state satisfying `supply > 0 && pv > 0 && supply == lp_supply`, a deposit+withdraw roundtrip returns ≤ deposited. Should use u32 with NO input bounds (except u32 constraints) and `assume(supply > 0 && pv > 0)` only.

2. **Extend anti-inflation proof to full range** — `proof_deposit_withdraw_no_inflation` currently uses bounds < 20. Verify whether the scale-invariance argument holds for all u32 values by removing the bounds and using u128 intermediates in the proof body. If it times out, document the explicit SAT bound and add a comment justifying scale-invariance.

**P2 — File tasks for coder:**

3. **Deprecate `tests/kani.rs`** — This file predates the `kani-proofs/` subpackage and contains 18 proofs that overlap with or are superseded by the 42 proofs in `kani-proofs/`. Remove `tests/kani.rs` and add a note in `kani-proofs/` README explaining the structure.

4. **Extend C9 proofs to full u32 range** — `proof_c9_orphaned_value_blocked` and `proof_c9_valueless_lp_blocked` use bounds < 100. These are critical security proofs (prevents theft of returned insurance); they should run at full range.
