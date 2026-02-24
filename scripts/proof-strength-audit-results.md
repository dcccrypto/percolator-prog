# Kani Proof Strength Audit Results (percolator-prog)

**Auditor**: Claude Opus 4.6
**Date**: 2026-02-19
**File**: `tests/kani.rs` (4015 lines, 152 proof harnesses)
**Source cross-referenced**: `src/percolator.rs` (verify module lines 261-862, matcher_abi lines 938-1044, oracle lines 1855-2284)
**Methodology**: 6-point analysis per `scripts/audit-proof-strength.md`

---

## Classification Summary

| Classification | Count | Percentage | Description |
|---|---|---|---|
| STRONG | 92 | 60.5% | Symbolic inputs exercise key branches, appropriate property asserted, non-vacuous |
| WEAK | 14 | 9.2% | Symbolic inputs but branch gaps, symbolic collapse, or weaker assertions |
| UNIT TEST | 41 | 27.0% | Concrete inputs or single execution path -- intentional regression/documentation guards |
| CODE-EQUALS-SPEC | 5 | 3.3% | Assertion restates the function body; guards regressions only |
| VACUOUS | 0 | 0.0% | No fully vacuous proofs (previous vacuous proofs removed per cleanup) |
| **Total** | **152** | **100%** | |

---

## WEAK Proofs by Category

### Category A: Branch Coverage Gaps

| # | Proof | Line | Issue | Recommendation |
|---|---|---|---|---|
| 1 | `kani_matcher_rejects_wrong_req_id` | 180 | Over-constrains: sets `lp_account_id = ret.lp_account_id`, `oracle_price = ret.oracle_price_e6`, forces exec_size valid (signum/abs checks). Only `req_id` mismatch fires. The ABI validator has 8 sequential checks; this locks 6 to pass and tests only gate 8. | Acceptable as single-gate proof; subsumed by `kani_abi_ok_equals_validate` for full coverage. |
| 2 | `kani_matcher_rejects_wrong_lp_account_id` | 204 | Same pattern: only `lp_account_id` mismatches. Does not test interaction with later exec_size/signum checks. | Same mitigation. |
| 3 | `kani_matcher_rejects_wrong_oracle_price` | 224 | Same pattern: only `oracle_price` mismatches. | Same mitigation. |
| 4 | `kani_tradecpi_allows_gate_risk_decrease` | 951 | Sets `identity_ok=true`, `pda_ok=true`, `abi_ok=true`, `user_auth_ok=true`, `lp_auth_ok=true` (all concrete). Only gate branch symbolically explored. Shape is symbolic via `assume(matcher_shape_ok(shape))` which is correct. | Subsumable by making prior-gate booleans symbolic and adding `assume` constraints. Already subsumed for rejection by AE/AG universal proofs. |
| 5 | `kani_invert_nonzero_computes_correctly` | 2214 | `raw` bounded to `(0, KANI_MAX_QUOTIENT=4096]`. Misses mid-range and large values. Function has 4 branches (`invert==0`, `raw==0`, `inverted==0`, `inverted > u64::MAX`); only success path exercised here. Other proofs cover the other branches individually. | Add proof with raw in [1e6, 1e9] range for mid-range coverage. Current bounded proof is still valid for its range. |
| 6 | `kani_invert_monotonic` | 2279 | Both `raw1` and `raw2` bounded to `KANI_MAX_QUOTIENT=4096`. Proves monotonicity only within [1, 4096]. Integer division `1e12/raw` is structurally monotonic but this proof cannot verify it beyond 4096. | Extend bound or supplement with proptest. |

### Category B: Weak Assertions

| # | Proof | Line | Issue | Recommendation |
|---|---|---|---|---|
| 7 | `kani_oracle_feed_id_match` | 1428 | Tests `oracle_feed_id_ok(x, x) == true`. Since the function is `expected == provided`, this is reflexivity (`x == x`). Self-labeled "trivially true" in comments. | Acceptable as regression guard against function body changes. |
| 8 | `kani_invert_result_zero_returns_none` | 2244 | Self-labeled WEAK. Tests `raw > 1e12` with offset bounded to `KANI_MAX_QUOTIENT`. Does not test the `inverted > u64::MAX` branch (proven dead by `kani_invert_overflow_branch_is_dead`). | Acceptable -- companion proof completes coverage of remaining branch. |

### Category C: Symbolic Collapse

| # | Proof | Line | Issue | Recommendation |
|---|---|---|---|---|
| 9 | `kani_scale_price_and_base_to_units_use_same_divisor` | 3577 | All inputs `u8`-bounded (`scale_raw: 2..16`, `base_mult/price_mult/pos_raw: 1..255`). Deep multiplication chain forces SAT tractability but collapses coverage to tiny domain. Property (conservative floor rounding) holds structurally for all integers. | Supplement with proptest for wider domain coverage. |
| 10 | `kani_scale_price_e6_concrete_example` | 3623 | Same `u8` bounds (`scale_raw: 2..16`). Proves floor-rounding conservatism only in this tiny domain. | Same recommendation. |
| 11 | `kani_clamp_toward_movement_bounded_concrete` | 3734 | `index_raw: u8 (10..255)`, `cap_steps_raw: u8 (1..20)`, `dt_raw: u8 (1..16)`. Small domain. Has companion saturation proof with larger inputs. | Acceptable given companion `kani_clamp_toward_saturation_paths`. |
| 12 | `kani_clamp_toward_formula_concrete` | 3797 | Uses `any_clamp_formula_inputs()`: `index_raw: 100..200`, `cap_steps_raw: 1..5`, `dt_slots_raw: 1..20`, `mark_raw: 0..400`. Non-vacuity witness exercises concrete point before symbolic part. | Acceptable bounded-domain proof. |
| 13 | `kani_clamp_toward_formula_within_bounds` | 3823 | Same bounded domain. | Same assessment. |
| 14 | `kani_clamp_toward_formula_above_hi` | 3851 | Same bounded domain. | Same assessment. |

### Category D: Trivially True

No proofs are fully trivially true (vacuous). The closest cases are documented in Category B.

---

## UNIT TEST Proofs (41)

All unit test proofs use concrete inputs for the function-under-test. They are self-documented as intentional regression guards and readable documentation of each validation requirement. Each notes which universal proof subsumes it.

| # | Proof | Line | Reason |
|---|---|---|---|
| 1 | `kani_matcher_shape_rejects_non_executable_prog` | 448 | Concrete shape. Subsumed by `kani_matcher_shape_universal`. |
| 2 | `kani_matcher_shape_rejects_executable_ctx` | 464 | Concrete shape. Subsumed by `kani_matcher_shape_universal`. |
| 3 | `kani_matcher_shape_rejects_wrong_ctx_owner` | 480 | Concrete shape. Subsumed by `kani_matcher_shape_universal`. |
| 4 | `kani_matcher_shape_rejects_short_ctx` | 496 | Concrete shape. Subsumed by `kani_matcher_shape_universal`. |
| 5 | `kani_matcher_shape_valid_accepted` | 512 | Concrete shape. Subsumed by `kani_matcher_shape_universal`. |
| 6 | `kani_nonce_wraps_at_max` | 602 | Concrete `old_nonce = u64::MAX`. Subsumed by `kani_nonce_advances_on_success`. |
| 7 | `kani_tradecpi_rejects_non_executable_prog` | 748 | Concrete shape (one bad field). Subsumed by `kani_universal_shape_fail_rejects`. |
| 8 | `kani_tradecpi_rejects_executable_ctx` | 771 | Concrete shape. Subsumed by `kani_universal_shape_fail_rejects`. |
| 9 | `kani_tradecpi_rejects_pda_mismatch` | 794 | Concrete booleans. Subsumed by `kani_universal_pda_fail_rejects`. |
| 10 | `kani_tradecpi_rejects_user_auth_failure` | 820 | Concrete booleans. Subsumed by `kani_universal_user_auth_fail_rejects`. |
| 11 | `kani_tradecpi_rejects_lp_auth_failure` | 846 | Concrete booleans. Subsumed by `kani_universal_lp_auth_fail_rejects`. |
| 12 | `kani_tradecpi_rejects_identity_mismatch` | 872 | Concrete booleans. Subsumed by `kani_universal_identity_fail_rejects`. |
| 13 | `kani_tradecpi_rejects_abi_failure` | 898 | Concrete booleans. Subsumed by `kani_universal_abi_fail_rejects`. |
| 14 | `kani_tradecpi_rejects_gate_risk_increase` | 924 | Concrete booleans. Subsumed by `kani_universal_gate_risk_increase_rejects`. |
| 15 | `kani_tradecpi_rejects_ctx_owner_mismatch` | 1157 | Concrete shape. Subsumed by `kani_universal_shape_fail_rejects`. |
| 16 | `kani_tradecpi_rejects_ctx_len_short` | 1180 | Concrete shape. Subsumed by `kani_universal_shape_fail_rejects`. |
| 17 | `kani_tradenocpi_gate_risk_increase_rejects` | 1090 | All 4 inputs concrete. Subsumed by `kani_tradenocpi_universal_characterization`. |
| 18 | `kani_lp_pda_shape_valid` | 1355 | Concrete shape. Subsumed by `kani_lp_pda_shape_universal`. |
| 19 | `kani_lp_pda_rejects_wrong_owner` | 1369 | Concrete shape. Subsumed by `kani_lp_pda_shape_universal`. |
| 20 | `kani_lp_pda_rejects_has_data` | 1383 | Concrete shape. Subsumed by `kani_lp_pda_shape_universal`. |
| 21 | `kani_lp_pda_rejects_funded` | 1394 | Concrete shape. Subsumed by `kani_lp_pda_shape_universal`. |
| 22 | `kani_slab_shape_valid` | 1450 | Concrete shape. |
| 23 | `kani_decide_crank_permissionless_accepts` | 1490 | `permissionless=true` concrete. Subsumed by `kani_decide_crank_universal`. |
| 24 | `kani_decide_crank_self_accepts` | 1505 | Concrete self-match. Subsumed by `kani_decide_crank_universal`. |
| 25 | `kani_decide_crank_rejects_no_idx` | 1518 | `idx_exists=false` concrete. Subsumed by `kani_decide_crank_universal`. |
| 26 | `kani_decide_crank_rejects_wrong_owner` | 1532 | Specific failure case. Subsumed by `kani_decide_crank_universal`. |
| 27 | `kani_decide_admin_accepts` | 1566 | Concrete match. |
| 28 | `kani_decide_admin_rejects` | 1580 | Two concrete failure cases. |
| 29 | `kani_min_abs_boundary_rejected` | 1884 | Fully concrete `i128::MIN` boundary regression. |
| 30 | `kani_crank_panic_requires_admin` | 1995 | `allow_panic=1` concrete. Subsumed by `kani_universal_panic_requires_admin`. |
| 31 | `kani_crank_panic_with_admin_permissionless_accepts` | 2024 | Multiple concrete values. Subsumed by `kani_decide_keeper_crank_with_panic_universal`. |
| 32 | `kani_crank_panic_burned_admin_rejects` | 2050 | Burned admin concrete. Subsumed by universal. |
| 33 | `kani_crank_no_panic_permissionless_accepts` | 2075 | `allow_panic=0`, `permissionless=true` concrete. Subsumed by universal. |
| 34 | `kani_crank_no_panic_self_crank_rejects_wrong_owner` | 2100 | Specific failure case. Subsumed by universal. |
| 35 | `kani_crank_panic_admin_passes_self_crank_no_idx_rejects` | 2126 | Mostly concrete. Subsumed by universal. |
| 36 | `kani_crank_no_panic_self_crank_accepts_owner_match` | 2152 | Concrete match. Subsumed by universal. |
| 37 | `kani_invert_zero_raw_returns_none` | 2235 | Fully concrete (`raw=0, invert=1`). |
| 38 | `kani_init_market_scale_zero_ok` | 3371 | Concrete `scale=0`. |
| 39 | `kani_init_market_scale_boundary_ok` | 3379 | Concrete `scale=MAX_UNIT_SCALE`. |
| 40 | `kani_init_market_scale_boundary_reject` | 3387 | Concrete `scale=MAX_UNIT_SCALE+1`. |
| 41 | `kani_withdraw_insurance_vault_reaches_zero` | 3973 | Concrete `vault_before = insurance`. Self-labeled trivially true. |

---

## CODE-EQUALS-SPEC Proofs (5)

These proofs assert that a function returns exactly what its body computes. They guard against future refactors changing the short-circuit behavior.

| # | Proof | Line | Issue |
|---|---|---|---|
| 1 | `kani_accumulate_dust_saturates` | 2563 | Asserts `accumulate_dust(a,b) == a.saturating_add(b)`. The function IS `saturating_add`. Self-labeled. |
| 2 | `kani_base_to_units_scale_zero` | 2342 | Asserts `scale==0 => (base, 0)`. Function body: `if scale == 0 { return (base, 0); }`. |
| 3 | `kani_units_to_base_scale_zero` | 2370 | Asserts `scale==0 => units`. Function body: `if scale == 0 { return units; }`. |
| 4 | `kani_sweep_dust_scale_zero` | 2550 | Asserts `scale==0 => (dust, 0)`. Function body: `if scale == 0 { return (dust, 0); }`. |
| 5 | `kani_scale_price_e6_identity_for_scale_leq_1` | 3548 | Asserts `unit_scale <= 1 => Some(price)`. Function body: `if unit_scale <= 1 { return Some(price); }`. |

---

## STRONG Proofs (86)

### Tier 1: Universal Characterization Proofs (8) -- Highest Value

These prove that a function's output is EXACTLY a specific formula for ALL input combinations. They fully characterize the function.

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_matcher_shape_universal` | 528 | `matcher_shape_ok == (prog_exec && !ctx_exec && ctx_owned && ctx_len)` for all 2^4 = 16 combinations. |
| 2 | `kani_lp_pda_shape_universal` | 1405 | `lp_pda_shape_ok == (system_owned && data_zero && lamports_zero)` for all 2^3 = 8 combinations. |
| 3 | `kani_tradenocpi_universal_characterization` | 1106 | Full characterization: accept iff `user_auth && lp_auth && !(gate && risk)`. |
| 4 | `kani_decide_single_owner_universal` | 1478 | Full characterization of `decide_single_owner_op`. |
| 5 | `kani_decide_crank_universal` | 1548 | Full characterization: accept iff `permissionless || (idx_exists && owner_match)`. |
| 6 | `kani_decide_keeper_crank_with_panic_universal` | 2176 | Full characterization with 6 symbolic inputs including `[u8;32]` arrays. |
| 7 | `kani_len_ok_universal` | 1334 | `len_ok(actual, need) == (actual >= need)`. |
| 8 | `kani_withdraw_insurance_vault_result_characterization` | 3987 | Full `Some(vault - ins)` / `None` characterization. |

### Tier 2: Universal Gate Rejection Proofs (9) -- Critical Security

Each proves that a single gate failure causes rejection regardless of ALL other inputs. The "kill switch" for the trade pipeline.

| # | Proof | Line | Gate |
|---|---|---|---|
| 1 | `kani_universal_shape_fail_rejects` | 2627 | `!matcher_shape_ok => Reject` |
| 2 | `kani_universal_pda_fail_rejects` | 2669 | `!pda_ok => Reject` |
| 3 | `kani_universal_user_auth_fail_rejects` | 2709 | `!user_auth_ok => Reject` |
| 4 | `kani_universal_lp_auth_fail_rejects` | 2749 | `!lp_auth_ok => Reject` |
| 5 | `kani_universal_identity_fail_rejects` | 2789 | `!identity_ok => Reject` |
| 6 | `kani_universal_abi_fail_rejects` | 2829 | `!abi_ok => Reject` |
| 7 | `kani_universal_gate_risk_increase_rejects` | 3076 | `gate_active && risk_increase => Reject` |
| 8 | `kani_universal_panic_requires_admin` | 3151 | `allow_panic != 0 && !admin_ok => Reject` |
| 9 | `kani_universal_gate_risk_increase_rejects_from_ret` | 3190 | Kill-switch in `from_ret` path |

### Tier 3: Nonce Transition Relation Proofs (8) -- Critical Correctness

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_nonce_unchanged_on_failure` | 578 | `nonce_on_failure(x) == x` for all u64. |
| 2 | `kani_nonce_advances_on_success` | 587 | `nonce_on_success(x) == x.wrapping_add(1)` for all u64. |
| 3 | `kani_tradecpi_reject_nonce_unchanged` | 983 | Universal invalid shapes: reject => nonce unchanged. |
| 4 | `kani_tradecpi_accept_increments_nonce` | 1016 | Universal valid shapes: accept => nonce+1, chosen_size=exec_size. |
| 5 | `kani_tradecpi_any_reject_nonce_unchanged` | 1209 | Universal over ALL inputs: nonce agrees with decision. Non-vacuity witness. |
| 6 | `kani_tradecpi_any_accept_increments_nonce` | 1272 | Universal over ALL inputs. Non-vacuity witness. |
| 7 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | 1648 | Universal nonce transition for `from_ret`. Non-vacuity witness. |
| 8 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | 1722 | Universal nonce transition for `from_ret` Accept. Non-vacuity witness. |

### Tier 4: ABI Validation Proofs (13) -- Matcher Security

| Proof | Line | Property |
|---|---|---|
| `kani_matcher_rejects_wrong_abi_version` | 132 | Wrong ABI version => Err for all fields |
| `kani_matcher_rejects_missing_valid_flag` | 147 | Missing FLAG_VALID => Err |
| `kani_matcher_rejects_rejected_flag` | 163 | FLAG_REJECTED set => Err |
| `kani_matcher_rejects_nonzero_reserved` | 244 | reserved != 0 => Err |
| `kani_matcher_rejects_zero_exec_price` | 262 | exec_price_e6 == 0 => Err |
| `kani_matcher_zero_size_requires_partial_ok` | 280 | exec_size==0 without PARTIAL_OK => Err |
| `kani_matcher_rejects_exec_size_exceeds_req` | 302 | |exec| > |req| => Err |
| `kani_matcher_rejects_sign_mismatch` | 326 | Sign mismatch => Err |
| `kani_abi_ok_equals_validate` | 1610 | **Critical coupling**: `abi_ok == validate_matcher_return.is_ok()` for ALL inputs |
| `kani_matcher_zero_size_with_partial_ok_accepted` | 1129 | Zero size + PARTIAL_OK => Ok |
| `kani_matcher_accepts_minimal_valid_nonzero_exec` | 1920 | Valid ABI inputs => Ok |
| `kani_matcher_accepts_exec_size_equal_req_size` | 1945 | exec_size == req_size => Ok |
| `kani_matcher_accepts_partial_fill_with_flag` | 1965 | Partial fill + PARTIAL_OK => Ok |

### Tier 5: Authorization Proofs (13) -- Access Control

| Proof | Line | Property |
|---|---|---|
| `kani_owner_mismatch_rejected` | 353 | `stored != signer => false` |
| `kani_owner_match_accepted` | 363 | `owner_ok(x, x) => true` |
| `kani_admin_mismatch_rejected` | 375 | `admin != zero, admin != signer => false` |
| `kani_admin_match_accepted` | 386 | `admin != zero => admin_ok(admin, admin)` |
| `kani_admin_burned_disables_ops` | 395 | Burned admin => false for all signers |
| `kani_matcher_identity_mismatch_rejected` | 411 | Identity mismatch => false |
| `kani_matcher_identity_match_accepted` | 428 | Identity match => true |
| `kani_pda_mismatch_rejected` | 553 | PDA mismatch => false |
| `kani_pda_match_accepted` | 566 | PDA match => true |
| `kani_single_owner_mismatch_rejected` | 676 | Owner mismatch => false |
| `kani_single_owner_match_accepted` | 689 | Owner match => true |
| `kani_trade_rejects_user_mismatch` | 700 | User owner mismatch => false |
| `kani_trade_rejects_lp_mismatch` | 714 | LP owner mismatch => false |

### Tier 6: Gate Logic + CPI Size + Shape (5)

| Proof | Line | Property |
|---|---|---|
| `kani_gate_inactive_when_threshold_zero` | 634 | `threshold=0 => !gate_active` |
| `kani_gate_inactive_when_balance_exceeds` | 645 | `balance > threshold => !gate_active` |
| `kani_gate_active_when_conditions_met` | 658 | `threshold > 0 && balance <= threshold => gate_active` |
| `kani_cpi_uses_exec_size` | 615 | `cpi_trade_size` returns exec_size for all i128 |
| `kani_slab_shape_invalid` | 1460 | `!owned || !correct_len => !slab_shape_ok` |
| `kani_oracle_feed_id_mismatch` | 1438 | Feed ID mismatch => false |

### Tier 7: Consistency and Coupling Proofs (6)

| Proof | Line | Property |
|---|---|---|
| `kani_tradecpi_variants_consistent_valid_shape` | 2874 | `decide_trade_cpi` and `decide_trade_cpi_from_ret` agree under valid shape |
| `kani_tradecpi_variants_consistent_invalid_shape` | 2948 | Both reject under invalid shape |
| `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | 3018 | `from_ret` computes `req_id = nonce_on_success(old_nonce)`. Non-vacuous. |
| `kani_tradecpi_from_ret_accept_uses_exec_size` | 1793 | Accept uses `exec_size` from ret, not `req_size`. Forced Accept. |
| `kani_tradecpi_from_ret_gate_active_risk_neutral_accepts` | 3247 | Gate active but risk-neutral => Accept |
| `kani_tradecpi_from_ret_forced_acceptance` | 3301 | End-to-end forced Accept verifies all output fields |

### Tier 8: Math and Invariant Proofs (24)

| Proof | Line | Property |
|---|---|---|
| `kani_base_to_units_conservation` | 2305 | `units * scale + dust == base` (bounded) |
| `kani_base_to_units_dust_bound` | 2326 | `dust < scale` (bounded) |
| `kani_units_roundtrip` | 2353 | Roundtrip preserves units, zero dust (bounded) |
| `kani_base_to_units_monotonic` | 2380 | `base1 < base2 => units1 <= units2` (bounded) |
| `kani_units_to_base_monotonic_bounded` | 2403 | Strict monotonicity without saturation (bounded) |
| `kani_base_to_units_monotonic_scale_zero` | 2427 | Strict monotonicity, full u64 range |
| `kani_units_roundtrip_exact_when_no_dust` | 3132 | Exact roundtrip when base = q*scale |
| `kani_withdraw_misaligned_rejects` | 2448 | Misaligned amount rejected (bounded) |
| `kani_withdraw_aligned_accepts` | 2468 | Aligned amount accepted (bounded) |
| `kani_withdraw_scale_zero_always_aligned` | 2485 | `scale==0` always aligned, full u64 |
| `kani_sweep_dust_conservation` | 2499 | `units*scale + rem == dust` (bounded) |
| `kani_sweep_dust_rem_bound` | 2519 | `rem < scale` (bounded) |
| `kani_sweep_dust_below_threshold` | 2535 | `dust < scale => units==0, rem==dust` |
| `kani_scale_zero_policy_no_dust` | 2579 | `scale==0` never produces dust, full u64 |
| `kani_scale_zero_policy_sweep_complete` | 2590 | `scale==0` sweep leaves no remainder, full u64 |
| `kani_scale_zero_policy_end_to_end` | 2601 | End-to-end deposit+accumulate+sweep pipeline |
| `kani_init_market_scale_rejects_overflow` | 3356 | `scale > MAX_UNIT_SCALE` rejected |
| `kani_init_market_scale_valid_range` | 3396 | `scale in [0, MAX]` accepted |
| `kani_scale_price_e6_zero_result_rejected` | 3499 | `price < unit_scale => None` |
| `kani_scale_price_e6_valid_result` | 3519 | Formula: `scaled = price / unit_scale` (bounded) |
| `kani_invert_zero_returns_raw` | 2205 | `invert==0 => Some(raw)`, full u64 |
| `kani_invert_overflow_branch_is_dead` | 2262 | Structural: `INVERSION_CONSTANT <= u64::MAX` |
| `kani_withdraw_insurance_vault_correct` | 3938 | `insurance <= vault => Some(vault - insurance)`, full u128 |
| `kani_withdraw_insurance_vault_overflow` | 3956 | `insurance > vault => None`, full u128 |

### Tier 9: Oracle Rate Limiting (Bug #9 Fix) Proofs (4)

| Proof | Line | Property |
|---|---|---|
| `kani_clamp_toward_no_movement_when_dt_zero` | 3676 | **Bug #9 fix**: `dt=0 => index` returned, not mark. Universal for valid inputs. |
| `kani_clamp_toward_no_movement_when_cap_zero` | 3697 | `cap=0 => index` returned. Universal for valid inputs. |
| `kani_clamp_toward_bootstrap_when_index_zero` | 3717 | `index=0 => mark` (bootstrap). Universal. |
| `kani_clamp_toward_saturation_paths` | 3879 | Saturation with large u64 inputs. Non-vacuity witnesses + symbolic. |

---

## Cross-Cutting Observations

### 1. Tiered Proof Architecture (Intentional)

The suite follows a deliberate tiered pattern:
- **Unit tests** (41): Document each individual gate/field with concrete witnesses. Serve as readable documentation and regression guards.
- **Universal proofs** (86): Prove properties hold for ALL valid input combinations. These provide the actual security guarantees.

This is explicitly documented in source comments (e.g., "NOTE: These use concrete structs (UNIT TEST classification). Individually superseded by kani_universal_shape_fail_rejects (AE)..."). The redundancy is intentional and appropriate.

### 2. Bounded SAT Domains

The `KANI_MAX_SCALE=64` and `KANI_MAX_QUOTIENT=4096` bounds are explicitly documented:
- Division/modulo operations are expensive for SAT solvers
- These bounds exercise all branches of the production functions
- `init_market_scale_*` proofs separately verify the full `MAX_UNIT_SCALE=1B` boundary
- Production-scale values are covered by integration tests (67 tests) and proptest fuzzing (19 tests)

This is a well-known Kani limitation and the mitigations are appropriate.

### 3. Non-Vacuity Discipline

The strongest proofs include explicit non-vacuity witnesses -- concrete examples proving the asserted path is reachable BEFORE the universal quantification. This pattern appears in:
- `kani_tradecpi_any_reject_nonce_unchanged` (line 1209)
- `kani_tradecpi_any_accept_increments_nonce` (line 1272)
- `kani_tradecpi_from_ret_any_reject_nonce_unchanged` (line 1648)
- `kani_tradecpi_from_ret_any_accept_increments_nonce` (line 1722)
- `kani_clamp_toward_formula_concrete` (line 3797) and siblings

This is excellent practice that eliminates the risk of vacuous truth in conditional assertions.

### 4. Coupling Completeness

The `verify` module extracts pure decision logic from `mod processor`. Coupling verified by:
- `kani_abi_ok_equals_validate` (line 1610): Proves `verify::abi_ok` calls the real `matcher_abi::validate_matcher_return`
- `kani_tradecpi_variants_consistent_*` (lines 2874, 2948): Proves `decide_trade_cpi` and `decide_trade_cpi_from_ret` agree
- Gate ordering in `decide_trade_cpi` matches production handler's check sequence (documented in comments)

**Gap**: No formal proof that the `processor` handler's actual check sequence matches `decide_trade_cpi`'s gate ordering. This coupling relies on code review only. A mismatch would mean the proofs verify a different policy than production. This is an inherent limitation of the extracted-function verification approach.

### 5. Missing Coverage Areas

The proofs intentionally do NOT cover:
- **Oracle reading** (`read_pyth_price_e6`, `read_chainlink_price_e6`): Requires `AccountInfo` which Kani cannot model
- **Zero-copy access** (`zc::engine_ref`, `zc::engine_mut`): Involves raw pointers
- **CPI invocation** (`zc::invoke_signed_trade`): Solana runtime interaction
- **Risk engine internals**: Covered by the `percolator` crate's own 133 Kani proofs

This is explicitly documented in the file header: "CPI execution and risk engine internals are NOT modeled. Only wrapper-level authorization and binding logic is proven."

### 6. Improvement Opportunities

1. **Expand bounded domains**: `KANI_MAX_QUOTIENT=4096` could be increased to `65536` for lightweight monotonicity proofs without SAT explosion.
2. **Processor coupling proof**: Add a structural check (or test) that the gate ordering in `decide_trade_cpi` matches `processor::process_trade_cpi`.
3. **Full-range `clamp_toward_with_dt`**: Add proof with `index=u64::MAX, cap=1_000_000, dt=1` to exercise `mark.clamp(0, u64::MAX)`.
4. **No-skip gate property**: Prove that if gate N rejects, gates N+1..7 are never evaluated (short-circuit correctness). This is structurally guaranteed by early returns but could be documented.

### 7. Summary Assessment

The proof suite is mature and well-structured. With 86 STRONG proofs (58.9%) and 0 VACUOUS proofs, it provides genuine formal guarantees for wrapper-level security properties: authorization, ABI validation, identity binding, nonce monotonicity, math correctness, and rate limiting. The 14 WEAK proofs are primarily bounded-domain math proofs constrained by SAT tractability -- a well-known and properly mitigated limitation. The 41 UNIT TEST proofs serve as readable documentation and regression guards, each explicitly noting its subsuming universal proof. The suite represents high-quality formal verification coverage for the properties it claims to verify.

---

## Detailed Per-Proof Classification Table

| # | Proof Name | Line | Class |
|---|---|---|---|
| 1 | `kani_matcher_rejects_wrong_abi_version` | 132 | STRONG |
| 2 | `kani_matcher_rejects_missing_valid_flag` | 147 | STRONG |
| 3 | `kani_matcher_rejects_rejected_flag` | 163 | STRONG |
| 4 | `kani_matcher_rejects_wrong_req_id` | 180 | WEAK |
| 5 | `kani_matcher_rejects_wrong_lp_account_id` | 204 | WEAK |
| 6 | `kani_matcher_rejects_wrong_oracle_price` | 224 | WEAK |
| 7 | `kani_matcher_rejects_nonzero_reserved` | 244 | STRONG |
| 8 | `kani_matcher_rejects_zero_exec_price` | 262 | STRONG |
| 9 | `kani_matcher_zero_size_requires_partial_ok` | 280 | STRONG |
| 10 | `kani_matcher_rejects_exec_size_exceeds_req` | 302 | STRONG |
| 11 | `kani_matcher_rejects_sign_mismatch` | 326 | STRONG |
| 12 | `kani_owner_mismatch_rejected` | 353 | STRONG |
| 13 | `kani_owner_match_accepted` | 363 | STRONG |
| 14 | `kani_admin_mismatch_rejected` | 375 | STRONG |
| 15 | `kani_admin_match_accepted` | 386 | STRONG |
| 16 | `kani_admin_burned_disables_ops` | 395 | STRONG |
| 17 | `kani_matcher_identity_mismatch_rejected` | 411 | STRONG |
| 18 | `kani_matcher_identity_match_accepted` | 428 | STRONG |
| 19 | `kani_matcher_shape_rejects_non_executable_prog` | 448 | UNIT TEST |
| 20 | `kani_matcher_shape_rejects_executable_ctx` | 464 | UNIT TEST |
| 21 | `kani_matcher_shape_rejects_wrong_ctx_owner` | 480 | UNIT TEST |
| 22 | `kani_matcher_shape_rejects_short_ctx` | 496 | UNIT TEST |
| 23 | `kani_matcher_shape_valid_accepted` | 512 | UNIT TEST |
| 24 | `kani_matcher_shape_universal` | 528 | STRONG |
| 25 | `kani_pda_mismatch_rejected` | 553 | STRONG |
| 26 | `kani_pda_match_accepted` | 566 | STRONG |
| 27 | `kani_nonce_unchanged_on_failure` | 578 | STRONG |
| 28 | `kani_nonce_advances_on_success` | 587 | STRONG |
| 29 | `kani_nonce_wraps_at_max` | 602 | UNIT TEST |
| 30 | `kani_cpi_uses_exec_size` | 615 | STRONG |
| 31 | `kani_gate_inactive_when_threshold_zero` | 634 | STRONG |
| 32 | `kani_gate_inactive_when_balance_exceeds` | 645 | STRONG |
| 33 | `kani_gate_active_when_conditions_met` | 658 | STRONG |
| 34 | `kani_single_owner_mismatch_rejected` | 676 | STRONG |
| 35 | `kani_single_owner_match_accepted` | 689 | STRONG |
| 36 | `kani_trade_rejects_user_mismatch` | 700 | STRONG |
| 37 | `kani_trade_rejects_lp_mismatch` | 714 | STRONG |
| 38 | `kani_tradecpi_rejects_non_executable_prog` | 748 | UNIT TEST |
| 39 | `kani_tradecpi_rejects_executable_ctx` | 771 | UNIT TEST |
| 40 | `kani_tradecpi_rejects_pda_mismatch` | 794 | UNIT TEST |
| 41 | `kani_tradecpi_rejects_user_auth_failure` | 820 | UNIT TEST |
| 42 | `kani_tradecpi_rejects_lp_auth_failure` | 846 | UNIT TEST |
| 43 | `kani_tradecpi_rejects_identity_mismatch` | 872 | UNIT TEST |
| 44 | `kani_tradecpi_rejects_abi_failure` | 898 | UNIT TEST |
| 45 | `kani_tradecpi_rejects_gate_risk_increase` | 924 | UNIT TEST |
| 46 | `kani_tradecpi_allows_gate_risk_decrease` | 951 | WEAK |
| 47 | `kani_tradecpi_reject_nonce_unchanged` | 983 | STRONG |
| 48 | `kani_tradecpi_accept_increments_nonce` | 1016 | STRONG |
| 49 | `kani_tradenocpi_auth_failure_rejects` | 1070 | STRONG |
| 50 | `kani_tradenocpi_gate_risk_increase_rejects` | 1090 | UNIT TEST |
| 51 | `kani_tradenocpi_universal_characterization` | 1106 | STRONG |
| 52 | `kani_matcher_zero_size_with_partial_ok_accepted` | 1129 | STRONG |
| 53 | `kani_tradecpi_rejects_ctx_owner_mismatch` | 1157 | UNIT TEST |
| 54 | `kani_tradecpi_rejects_ctx_len_short` | 1180 | UNIT TEST |
| 55 | `kani_tradecpi_any_reject_nonce_unchanged` | 1209 | STRONG |
| 56 | `kani_tradecpi_any_accept_increments_nonce` | 1272 | STRONG |
| 57 | `kani_len_ok_universal` | 1334 | STRONG |
| 58 | `kani_lp_pda_shape_valid` | 1355 | UNIT TEST |
| 59 | `kani_lp_pda_rejects_wrong_owner` | 1369 | UNIT TEST |
| 60 | `kani_lp_pda_rejects_has_data` | 1383 | UNIT TEST |
| 61 | `kani_lp_pda_rejects_funded` | 1394 | UNIT TEST |
| 62 | `kani_lp_pda_shape_universal` | 1405 | STRONG |
| 63 | `kani_oracle_feed_id_match` | 1428 | WEAK |
| 64 | `kani_oracle_feed_id_mismatch` | 1438 | STRONG |
| 65 | `kani_slab_shape_valid` | 1450 | UNIT TEST |
| 66 | `kani_slab_shape_invalid` | 1460 | STRONG |
| 67 | `kani_decide_single_owner_universal` | 1478 | STRONG |
| 68 | `kani_decide_crank_permissionless_accepts` | 1490 | UNIT TEST |
| 69 | `kani_decide_crank_self_accepts` | 1505 | UNIT TEST |
| 70 | `kani_decide_crank_rejects_no_idx` | 1518 | UNIT TEST |
| 71 | `kani_decide_crank_rejects_wrong_owner` | 1532 | UNIT TEST |
| 72 | `kani_decide_crank_universal` | 1548 | STRONG |
| 73 | `kani_decide_admin_accepts` | 1566 | UNIT TEST |
| 74 | `kani_decide_admin_rejects` | 1580 | UNIT TEST |
| 75 | `kani_abi_ok_equals_validate` | 1610 | STRONG |
| 76 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | 1648 | STRONG |
| 77 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | 1722 | STRONG |
| 78 | `kani_tradecpi_from_ret_accept_uses_exec_size` | 1793 | STRONG |
| 79 | `kani_min_abs_boundary_rejected` | 1884 | UNIT TEST |
| 80 | `kani_matcher_accepts_minimal_valid_nonzero_exec` | 1920 | STRONG |
| 81 | `kani_matcher_accepts_exec_size_equal_req_size` | 1945 | STRONG |
| 82 | `kani_matcher_accepts_partial_fill_with_flag` | 1965 | STRONG |
| 83 | `kani_crank_panic_requires_admin` | 1995 | UNIT TEST |
| 84 | `kani_crank_panic_with_admin_permissionless_accepts` | 2024 | UNIT TEST |
| 85 | `kani_crank_panic_burned_admin_rejects` | 2050 | UNIT TEST |
| 86 | `kani_crank_no_panic_permissionless_accepts` | 2075 | UNIT TEST |
| 87 | `kani_crank_no_panic_self_crank_rejects_wrong_owner` | 2100 | UNIT TEST |
| 88 | `kani_crank_panic_admin_passes_self_crank_no_idx_rejects` | 2126 | UNIT TEST |
| 89 | `kani_crank_no_panic_self_crank_accepts_owner_match` | 2152 | UNIT TEST |
| 90 | `kani_decide_keeper_crank_with_panic_universal` | 2176 | STRONG |
| 91 | `kani_invert_zero_returns_raw` | 2205 | STRONG |
| 92 | `kani_invert_nonzero_computes_correctly` | 2214 | WEAK |
| 93 | `kani_invert_zero_raw_returns_none` | 2235 | UNIT TEST |
| 94 | `kani_invert_result_zero_returns_none` | 2244 | WEAK |
| 95 | `kani_invert_overflow_branch_is_dead` | 2262 | STRONG |
| 96 | `kani_invert_monotonic` | 2279 | WEAK |
| 97 | `kani_base_to_units_conservation` | 2305 | STRONG |
| 98 | `kani_base_to_units_dust_bound` | 2326 | STRONG |
| 99 | `kani_base_to_units_scale_zero` | 2342 | CODE-EQUALS-SPEC |
| 100 | `kani_units_roundtrip` | 2353 | STRONG |
| 101 | `kani_units_to_base_scale_zero` | 2370 | CODE-EQUALS-SPEC |
| 102 | `kani_base_to_units_monotonic` | 2380 | STRONG |
| 103 | `kani_units_to_base_monotonic_bounded` | 2403 | STRONG |
| 104 | `kani_base_to_units_monotonic_scale_zero` | 2427 | STRONG |
| 105 | `kani_withdraw_misaligned_rejects` | 2448 | STRONG |
| 106 | `kani_withdraw_aligned_accepts` | 2468 | STRONG |
| 107 | `kani_withdraw_scale_zero_always_aligned` | 2485 | STRONG |
| 108 | `kani_sweep_dust_conservation` | 2499 | STRONG |
| 109 | `kani_sweep_dust_rem_bound` | 2519 | STRONG |
| 110 | `kani_sweep_dust_below_threshold` | 2535 | STRONG |
| 111 | `kani_sweep_dust_scale_zero` | 2550 | CODE-EQUALS-SPEC |
| 112 | `kani_accumulate_dust_saturates` | 2563 | CODE-EQUALS-SPEC |
| 113 | `kani_scale_zero_policy_no_dust` | 2579 | STRONG |
| 114 | `kani_scale_zero_policy_sweep_complete` | 2590 | STRONG |
| 115 | `kani_scale_zero_policy_end_to_end` | 2601 | STRONG |
| 116 | `kani_universal_shape_fail_rejects` | 2627 | STRONG |
| 117 | `kani_universal_pda_fail_rejects` | 2669 | STRONG |
| 118 | `kani_universal_user_auth_fail_rejects` | 2709 | STRONG |
| 119 | `kani_universal_lp_auth_fail_rejects` | 2749 | STRONG |
| 120 | `kani_universal_identity_fail_rejects` | 2789 | STRONG |
| 121 | `kani_universal_abi_fail_rejects` | 2829 | STRONG |
| 122 | `kani_tradecpi_variants_consistent_valid_shape` | 2874 | STRONG |
| 123 | `kani_tradecpi_variants_consistent_invalid_shape` | 2948 | STRONG |
| 124 | `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | 3018 | STRONG |
| 125 | `kani_universal_gate_risk_increase_rejects` | 3076 | STRONG |
| 126 | `kani_units_roundtrip_exact_when_no_dust` | 3132 | STRONG |
| 127 | `kani_universal_panic_requires_admin` | 3151 | STRONG |
| 128 | `kani_universal_gate_risk_increase_rejects_from_ret` | 3190 | STRONG |
| 129 | `kani_tradecpi_from_ret_gate_active_risk_neutral_accepts` | 3247 | STRONG |
| 130 | `kani_tradecpi_from_ret_forced_acceptance` | 3301 | STRONG |
| 131 | `kani_init_market_scale_rejects_overflow` | 3356 | STRONG |
| 132 | `kani_init_market_scale_zero_ok` | 3371 | UNIT TEST |
| 133 | `kani_init_market_scale_boundary_ok` | 3379 | UNIT TEST |
| 134 | `kani_init_market_scale_boundary_reject` | 3387 | UNIT TEST |
| 135 | `kani_init_market_scale_valid_range` | 3396 | STRONG |
| 136 | `kani_scale_price_e6_zero_result_rejected` | 3499 | STRONG |
| 137 | `kani_scale_price_e6_valid_result` | 3519 | STRONG |
| 138 | `kani_scale_price_e6_identity_for_scale_leq_1` | 3548 | CODE-EQUALS-SPEC |
| 139 | `kani_scale_price_and_base_to_units_use_same_divisor` | 3577 | WEAK |
| 140 | `kani_scale_price_e6_concrete_example` | 3623 | WEAK |
| 141 | `kani_clamp_toward_no_movement_when_dt_zero` | 3676 | STRONG |
| 142 | `kani_clamp_toward_no_movement_when_cap_zero` | 3697 | STRONG |
| 143 | `kani_clamp_toward_bootstrap_when_index_zero` | 3717 | STRONG |
| 144 | `kani_clamp_toward_movement_bounded_concrete` | 3734 | WEAK |
| 145 | `kani_clamp_toward_formula_concrete` | 3797 | WEAK |
| 146 | `kani_clamp_toward_formula_within_bounds` | 3823 | WEAK |
| 147 | `kani_clamp_toward_formula_above_hi` | 3851 | WEAK |
| 148 | `kani_clamp_toward_saturation_paths` | 3879 | STRONG |
| 149 | `kani_withdraw_insurance_vault_correct` | 3938 | STRONG |
| 150 | `kani_withdraw_insurance_vault_overflow` | 3956 | STRONG |
| 151 | `kani_withdraw_insurance_vault_reaches_zero` | 3973 | UNIT TEST |
| 152 | `kani_withdraw_insurance_vault_result_characterization` | 3987 | STRONG |
