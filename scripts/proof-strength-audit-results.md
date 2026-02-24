# Kani Proof Strength Audit Results (percolator-prog)

**Auditor**: Claude Opus 4.6
**Date**: 2026-02-24
**File**: `tests/kani.rs` (3242 lines, 110 proof harnesses)
**Source cross-referenced**: `src/percolator.rs` (verify module lines 261-862, matcher_abi lines 938-1044, oracle lines 1855-2284)
**Methodology**: 6-point analysis per `scripts/audit-proof-strength.md`

---

## Changes Since Previous Audit (2026-02-19, 152 proofs)

1. **3 matcher single-gate WEAK proofs removed** (`kani_matcher_rejects_wrong_req_id`, `kani_matcher_rejects_wrong_lp_account_id`, `kani_matcher_rejects_wrong_oracle_price`): subsumed by `kani_abi_ok_equals_validate`.
2. **`kani_tradecpi_allows_gate_risk_decrease` replaced** by `kani_decide_trade_cpi_universal` (Tier 1 universal characterization). Former WEAK proof (concrete pre-gate booleans) upgraded to STRONG.
3. **`kani_invert_nonzero_computes_correctly` widened** from 4096 to 8192. Remains WEAK (Category C) but with wider coverage.
4. **`kani_scale_price_and_base_to_units_use_same_divisor` widened** from u8 to u16 multipliers. Remains WEAK (Category C) but with wider coverage.
5. **`kani_scale_price_e6_concrete_example` widened** from u8 to u16 `price_mult`. Remains WEAK (Category C) but with wider coverage.
6. **`kani_clamp_toward_formula_*` inputs widened** from u8/narrow to u16 `[100,1000]` index, u16 `[0,2000]` mark. Remain WEAK (Category C) but with wider coverage.
7. **`kani_invert_result_zero_returns_none` strengthened** to fully symbolic (`raw > INVERSION_CONSTANT as u64`). Upgraded from WEAK to STRONG.
8. **42 unit test proofs removed** (concrete shape, crank, admin, LP PDA, slab proofs): all subsumed by their respective universal proofs which remain.
9. **`kani_oracle_feed_id_universal`** replaces separate match/mismatch proofs. STRONG.
10. **`kani_slab_shape_universal`** replaces separate valid/invalid proofs. STRONG.
11. **`kani_decide_admin_universal`** replaces separate accept/reject proofs. STRONG.

**Net effect**: -42 proofs removed (unit tests + weak), +0 new proofs = 110 total. STRONG percentage improved from 60.5% to 82.7%.

---

## Classification Summary

| Classification | Count | Percentage | Description |
|---|---|---|---|
| STRONG | 91 | 82.7% | Symbolic inputs exercise key branches, appropriate property asserted, non-vacuous |
| WEAK | 9 | 8.2% | Symbolic inputs but SAT-bounded domain reduces coverage (all Category C) |
| UNIT TEST | 5 | 4.5% | Concrete inputs or single execution path -- intentional regression/documentation guards |
| CODE-EQUALS-SPEC | 5 | 4.5% | Assertion restates the function body; guards regressions only |
| VACUOUS | 0 | 0.0% | No vacuous proofs |
| **Total** | **110** | **100%** | |

---

## WEAK Proofs by Category

### Category A: Branch Coverage Gaps

No proofs remain in this category. The previous Category A proofs (single-gate matcher WEAK proofs #1-3 and `kani_tradecpi_allows_gate_risk_decrease` #4) were all removed or replaced.

### Category B: Weak Assertions

No proofs remain in this category. The previous Category B proofs (`kani_oracle_feed_id_match` #7 and `kani_invert_result_zero_returns_none` #8) were either removed (feed_id replaced by universal) or upgraded to STRONG (invert_result_zero now fully symbolic).

### Category C: SAT-Bounded Symbolic Collapse (9 remaining)

All remaining WEAK proofs are constrained by SAT solver tractability limits on division/multiplication chains. The bounded domains are explicitly documented in source comments. Each exercises the correct branches within its domain; the weakness is only that the domain is smaller than production values.

| # | Proof | Line | Bound | Why it cannot be widened further |
|---|---|---|---|---|
| 1 | `kani_invert_nonzero_computes_correctly` | 1481 | `raw in (0, 8192]` | 128-bit division `1e12/raw` + equality check. At 8192 already ~66s. Widening to 16384 doubles SAT time. Other proofs (`kani_invert_overflow_branch_is_dead`, `kani_invert_result_zero_returns_none`, `kani_invert_zero_raw_returns_none`) cover remaining branches at full range. |
| 2 | `kani_invert_monotonic` | 1543 | `raw1, raw2 in (0, 16384]` | Two 128-bit divisions + inequality. SAT-heavy with two independent symbolic quotients. Companion: monotonicity is structurally guaranteed by `floor(1e12/x)` being non-increasing for integer division. |
| 3 | `kani_scale_price_and_base_to_units_use_same_divisor` | 2816 | `scale: u8[2..16]`, `base_mult/price_mult: u16`, `pos: u8` | Three-deep multiplication chain: `position_size * oracle_scaled * unit_scale`. u16 multipliers (widened from u8) keep the 3-deep chain SAT-tractable. Property (conservative floor rounding) holds structurally for all integers. |
| 4 | `kani_scale_price_e6_concrete_example` | 2862 | `scale: u8[2..16]`, `price_mult: u16`, `pos/bps: u8` | Same three-deep chain as #3 with additional margin_bps multiplication. u16 price_mult (widened from u8) provides 65536x more coverage. Structural property: floor division is always conservative. |
| 5 | `kani_clamp_toward_movement_bounded_concrete` | 2973 | `index: u8[10..255]`, `cap_steps: u8[1..20]`, `dt: u8[1..16]` | Triple multiplication: `index * cap_e2bps * dt_slots`. u8-range inputs keep product in bounds. Companion `kani_clamp_toward_saturation_paths` covers large u64 inputs and saturation paths. |
| 6 | `kani_clamp_toward_formula_concrete` | 3037 | `index: u16[100..1000]`, `cap_steps: u8[1..5]`, `dt: u8[1..20]`, `mark: u16[0..2000]` | Triple multiply for `max_delta` computation. Widened from u8 to u16 for index/mark. Further widening would push SAT beyond tractable limit for formula equality assertions. Non-vacuity witness included. |
| 7 | `kani_clamp_toward_formula_within_bounds` | 3063 | Same as #6 | Same bounded domain via `any_clamp_formula_inputs()`. Tests the `mark in [lo, hi]` branch. Non-vacuity witness included. |
| 8 | `kani_clamp_toward_formula_above_hi` | 3091 | Same as #6 | Same bounded domain. Tests the `mark > hi` branch. Non-vacuity witness included. |
| 9 | `kani_clamp_toward_saturation_paths` | 3119 | `index: u64::MAX/2 + u8`, `cap_steps: u8`, `dt: u8` | Uses large u64 base (`u64::MAX/2`) with small symbolic offsets. The symbolic part is u8-bounded, but the base values exercise the saturation paths (`saturating_mul`, `saturating_add`, `saturating_sub`) that small inputs cannot reach. Non-vacuity witnesses included. Classified WEAK rather than STRONG because the symbolic portion is u8-bounded. |

### Category D: Trivially True

No proofs are trivially true or vacuous. All conditional assertions include either:
- Non-vacuity witnesses (concrete examples proving both paths reachable), or
- Universal quantification over both outcomes (e.g., `match &decision { Reject => ..., Accept => ... }`), or
- Explicit `panic!` on unexpected outcomes.

---

## UNIT TEST Proofs (5)

All unit test proofs use fully concrete inputs. They are retained as intentional regression guards and boundary-case documentation.

| # | Proof | Line | Reason |
|---|---|---|---|
| 1 | `kani_min_abs_boundary_rejected` | 1333 | Fully concrete `i128::MIN` boundary regression. Documents that `.unsigned_abs()` handles `i128::MIN` correctly where `.abs()` would panic. Critical historical bug. |
| 2 | `kani_init_market_scale_rejects_overflow` | 2620 | `scale > MAX_UNIT_SCALE` rejected. Includes non-vacuity assertion that `MAX_UNIT_SCALE < u32::MAX`. Symbolic `scale` but with `assume(scale > MAX_UNIT_SCALE)` reducing to edge case. Classified UNIT TEST because the function is a single comparison. |
| 3 | `kani_init_market_scale_valid_range` | 2635 | `scale in [0, MAX_UNIT_SCALE]` accepted. Symbolic but function is `scale <= MAX_UNIT_SCALE`, making this CODE-EQUALS-SPEC-adjacent. Classified UNIT TEST to distinguish from the more complex math proofs. |
| 4 | `kani_tradecpi_from_ret_accept_uses_exec_size` | 1242 | Concrete valid shape + concrete auth booleans. Only exec_size/req_size are symbolic. Forces Accept path to verify `chosen_size == exec_size`. The concrete pre-conditions are necessary to guarantee the Accept path is reached. Subsumed by `kani_decide_trade_cpi_universal` for the general property but retained because it tests the `from_ret` path specifically. |
| 5 | `kani_tradecpi_from_ret_gate_active_risk_neutral_accepts` | 2511 | Concrete `identity_ok=true`, `pda_ok=true`, `user/lp_auth=true`, `gate=true`, `risk=false`. Tests companion accept path to the gate-rejection kill-switch. Symbolic shape (via `assume(matcher_shape_ok)`) + symbolic ABI fields. Borderline STRONG but classified UNIT TEST because auth booleans are concrete. |

---

## CODE-EQUALS-SPEC Proofs (5)

These proofs assert that a function returns exactly what its body computes. They guard against future refactors changing short-circuit behavior or the underlying operation.

| # | Proof | Line | Issue |
|---|---|---|---|
| 1 | `kani_accumulate_dust_saturates` | 1827 | Asserts `accumulate_dust(a,b) == a.saturating_add(b)`. The function IS `saturating_add`. Self-labeled in source. Guards against regression if implementation changes. |
| 2 | `kani_base_to_units_scale_zero` | 1606 | Asserts `scale==0 => (base, 0)`. Function body: `if scale == 0 { return (base, 0); }`. |
| 3 | `kani_units_to_base_scale_zero` | 1634 | Asserts `scale==0 => units`. Function body: `if scale == 0 { return units; }`. |
| 4 | `kani_sweep_dust_scale_zero` | 1814 | Asserts `scale==0 => (dust, 0)`. Function body: `if scale == 0 { return (dust, 0); }`. |
| 5 | `kani_scale_price_e6_identity_for_scale_leq_1` | 2787 | Asserts `unit_scale <= 1 => Some(price)`. Function body: `if unit_scale <= 1 { return Some(price); }`. |

---

## STRONG Proofs (91)

### Tier 1: Universal Characterization Proofs (11) -- Highest Value

These prove that a function's output is EXACTLY a specific formula for ALL input combinations. They fully characterize the function, leaving zero room for behavioral ambiguity.

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_matcher_shape_universal` | 385 | `matcher_shape_ok == (prog_exec && !ctx_exec && ctx_owned && ctx_len)` for all 2^4 = 16 combinations. |
| 2 | `kani_lp_pda_shape_universal` | 953 | `lp_pda_shape_ok == (system_owned && data_zero && lamports_zero)` for all 2^3 = 8 combinations. |
| 3 | `kani_oracle_feed_id_universal` | 974 | `oracle_feed_id_ok(expected, provided) == (expected == provided)` for all `[u8;32]` pairs. |
| 4 | `kani_slab_shape_universal` | 986 | `slab_shape_ok == (owned && correct_len)` for all 2^2 = 4 combinations. |
| 5 | `kani_tradenocpi_universal_characterization` | 750 | Full characterization: accept iff `user_auth && lp_auth && !(gate && risk)`. All 2^4 = 16 combinations. |
| 6 | `kani_decide_single_owner_universal` | 1005 | Full characterization of `decide_single_owner_op(auth_ok)`. Both paths. |
| 7 | `kani_decide_crank_universal` | 1018 | Full characterization: accept iff `permissionless || (idx_exists && owner_match)`. Includes symbolic `[u8;32]` arrays. |
| 8 | `kani_decide_admin_universal` | 1037 | Full characterization: accept iff `admin != [0;32] && admin == signer`. Symbolic `[u8;32]` arrays. |
| 9 | `kani_decide_keeper_crank_with_panic_universal` | 1442 | Full characterization with 6 symbolic inputs including `[u8;32]` arrays. Composes `admin_ok` and `decide_crank`. |
| 10 | `kani_len_ok_universal` | 932 | `len_ok(actual, need) == (actual >= need)` for all `usize` pairs. |
| 11 | `kani_decide_trade_cpi_universal` | 599 | **Critical**: Full characterization of `decide_trade_cpi`. Accept iff `shape_ok && identity && pda && abi && user && lp && !(gate && risk)`. On Accept: `new_nonce == nonce_on_success(old_nonce)`, `chosen_size == exec_size`. All 10 inputs symbolic. Subsumes the former `kani_tradecpi_allows_gate_risk_decrease` (WEAK). |

### Tier 2: Universal Gate Rejection Proofs (8) -- Critical Security

Each proves that a single gate failure causes rejection regardless of ALL other inputs. These are the "kill switch" proofs for the trade pipeline.

| # | Proof | Line | Gate |
|---|---|---|---|
| 1 | `kani_universal_shape_fail_rejects` | 1891 | `!matcher_shape_ok => Reject` (symbolic shape + all other inputs symbolic) |
| 2 | `kani_universal_pda_fail_rejects` | 1933 | `pda_ok==false => Reject` (valid shape forced, all others symbolic) |
| 3 | `kani_universal_user_auth_fail_rejects` | 1973 | `user_auth_ok==false => Reject` |
| 4 | `kani_universal_lp_auth_fail_rejects` | 2013 | `lp_auth_ok==false => Reject` |
| 5 | `kani_universal_identity_fail_rejects` | 2053 | `identity_ok==false => Reject` |
| 6 | `kani_universal_abi_fail_rejects` | 2093 | `abi_ok==false => Reject` |
| 7 | `kani_universal_gate_risk_increase_rejects` | 2340 | `gate_active && risk_increase => Reject` (valid shape forced, all others symbolic) |
| 8 | `kani_universal_panic_requires_admin` | 2415 | `allow_panic != 0 && !admin_ok => Reject` (all other crank inputs symbolic) |

### Tier 3: Nonce Transition Relation Proofs (6) -- Critical Correctness

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_nonce_unchanged_on_failure` | 435 | `nonce_on_failure(x) == x` for all u64. |
| 2 | `kani_nonce_advances_on_success` | 444 | `nonce_on_success(x) == x.wrapping_add(1)` for all u64. |
| 3 | `kani_tradecpi_reject_nonce_unchanged` | 644 | Universal invalid shapes: reject => nonce unchanged. |
| 4 | `kani_tradecpi_accept_increments_nonce` | 677 | Universal valid shapes: accept => nonce+1, chosen_size=exec_size. |
| 5 | `kani_tradecpi_any_reject_nonce_unchanged` | 807 | Universal over ALL inputs: nonce agrees with decision for both outcomes. Non-vacuity witness. |
| 6 | `kani_tradecpi_any_accept_increments_nonce` | 870 | Universal over ALL inputs: nonce agrees with decision for both outcomes. Non-vacuity witness. |

### Tier 4: ABI Validation Proofs (12) -- Matcher Security

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_matcher_rejects_wrong_abi_version` | 133 | Wrong ABI version => Err for all other fields (fully symbolic). |
| 2 | `kani_matcher_rejects_missing_valid_flag` | 148 | Missing FLAG_VALID => Err. ABI version concrete, all others symbolic. |
| 3 | `kani_matcher_rejects_rejected_flag` | 164 | FLAG_REJECTED set => Err. Fully symbolic remaining fields. |
| 4 | `kani_matcher_rejects_nonzero_reserved` | 181 | `reserved != 0` => Err. Other fields constrained to pass prior gates. |
| 5 | `kani_matcher_rejects_zero_exec_price` | 199 | `exec_price_e6 == 0` => Err. Other fields constrained to pass prior gates. |
| 6 | `kani_matcher_zero_size_requires_partial_ok` | 217 | `exec_size==0` without PARTIAL_OK => Err. |
| 7 | `kani_matcher_rejects_exec_size_exceeds_req` | 239 | `|exec| > |req|` => Err. Symbolic i128 values. |
| 8 | `kani_matcher_rejects_sign_mismatch` | 263 | Sign mismatch => Err. Symbolic i128 values with opposing signs. |
| 9 | `kani_abi_ok_equals_validate` | 1059 | **Critical coupling**: `verify::abi_ok == validate_matcher_return.is_ok()` for ALL inputs. Fully symbolic MatcherReturn + request fields. This single proof subsumes the 3 removed single-gate proofs. |
| 10 | `kani_matcher_zero_size_with_partial_ok_accepted` | 773 | Zero size + PARTIAL_OK => Ok. Symbolic `exec_price_e6` and `req_size`. |
| 11 | `kani_matcher_accepts_minimal_valid_nonzero_exec` | 1369 | Valid ABI inputs => Ok. Symbolic exec_size/req_size with sign/magnitude constraints. |
| 12 | `kani_matcher_accepts_exec_size_equal_req_size` | 1394 | `exec_size == req_size` => Ok. Symbolic. |

### Tier 5: Authorization Proofs (11) -- Access Control

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_owner_mismatch_rejected` | 290 | `stored != signer => false` for all `[u8;32]` pairs. |
| 2 | `kani_owner_match_accepted` | 300 | `owner_ok(x, x) => true` for all `[u8;32]`. |
| 3 | `kani_admin_mismatch_rejected` | 312 | `admin != zero, admin != signer => false`. |
| 4 | `kani_admin_match_accepted` | 323 | `admin != zero => admin_ok(admin, admin)`. |
| 5 | `kani_admin_burned_disables_ops` | 332 | Burned admin `[0;32]` => false for all signers. |
| 6 | `kani_matcher_identity_mismatch_rejected` | 348 | Identity mismatch (program or context) => false. Disjunctive assumption. |
| 7 | `kani_matcher_identity_match_accepted` | 365 | Identity match => true. |
| 8 | `kani_pda_mismatch_rejected` | 410 | PDA mismatch => false. |
| 9 | `kani_pda_match_accepted` | 423 | PDA match => true. |
| 10 | `kani_single_owner_mismatch_rejected` | 523 | Owner mismatch => false. |
| 11 | `kani_single_owner_match_accepted` | 536 | Owner match => true. |

### Tier 6: Gate Logic + CPI Size + Trade Auth (7)

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_gate_inactive_when_threshold_zero` | 481 | `threshold=0 => !gate_active` for all u128 balance. |
| 2 | `kani_gate_inactive_when_balance_exceeds` | 492 | `balance > threshold => !gate_active` for all u128 pairs. |
| 3 | `kani_gate_active_when_conditions_met` | 505 | `threshold > 0 && balance <= threshold => gate_active`. |
| 4 | `kani_cpi_uses_exec_size` | 462 | `cpi_trade_size` returns exec_size for all i128 pairs. |
| 5 | `kani_trade_rejects_user_mismatch` | 547 | User owner mismatch => trade rejected. Symbolic `[u8;32]` arrays. |
| 6 | `kani_trade_rejects_lp_mismatch` | 561 | LP owner mismatch => trade rejected. Symbolic `[u8;32]` arrays. |
| 7 | `kani_tradenocpi_auth_failure_rejects` | 731 | Auth failure (either user or LP) => TradeNoCpi rejects. All 4 inputs symbolic. |

### Tier 7: Consistency and Coupling Proofs (8)

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_tradecpi_variants_consistent_valid_shape` | 2138 | `decide_trade_cpi` and `decide_trade_cpi_from_ret` agree under valid shape. All auth/gate inputs symbolic. |
| 2 | `kani_tradecpi_variants_consistent_invalid_shape` | 2212 | Both reject under invalid shape. Symbolic shape + all other inputs. |
| 3 | `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | 2282 | `from_ret` computes `req_id = nonce_on_success(old_nonce)`. Forced Accept via ABI-valid ret. Non-vacuous. |
| 4 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | 1097 | Universal nonce transition for `from_ret`. Non-vacuity witness. Both outcomes tested. |
| 5 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | 1171 | Universal nonce transition for `from_ret` Accept. Non-vacuity witness. Both outcomes tested. |
| 6 | `kani_universal_gate_risk_increase_rejects_from_ret` | 2454 | Kill-switch (`gate_active && risk_increase => Reject`) in `from_ret` path. Symbolic shape + auth. ABI-valid ret constructed. |
| 7 | `kani_tradecpi_from_ret_forced_acceptance` | 2565 | End-to-end forced Accept verifies all output fields (`new_nonce`, `chosen_size`). |
| 8 | `kani_matcher_accepts_partial_fill_with_flag` | 1414 | Partial fill with PARTIAL_OK => Ok. Validates acceptance path. |

### Tier 8: Math and Invariant Proofs (22)

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_base_to_units_conservation` | 1569 | `units * scale + dust == base` (bounded: scale <= 64, quotient <= 16384) |
| 2 | `kani_base_to_units_dust_bound` | 1590 | `dust < scale` (bounded) |
| 3 | `kani_units_roundtrip` | 1617 | Roundtrip preserves units, zero dust (bounded) |
| 4 | `kani_base_to_units_monotonic` | 1644 | `base1 < base2 => units1 <= units2` (bounded) |
| 5 | `kani_units_to_base_monotonic_bounded` | 1667 | Strict monotonicity without saturation (bounded) |
| 6 | `kani_base_to_units_monotonic_scale_zero` | 1691 | Strict monotonicity at scale=0, full u64 range |
| 7 | `kani_units_roundtrip_exact_when_no_dust` | 2396 | Exact roundtrip when `base = q*scale` (bounded) |
| 8 | `kani_withdraw_misaligned_rejects` | 1712 | Misaligned amount rejected (bounded: scale <= 64) |
| 9 | `kani_withdraw_aligned_accepts` | 1732 | Aligned amount accepted (bounded) |
| 10 | `kani_withdraw_scale_zero_always_aligned` | 1749 | `scale==0` always aligned, full u64 range |
| 11 | `kani_sweep_dust_conservation` | 1763 | `units*scale + rem == dust` (bounded) |
| 12 | `kani_sweep_dust_rem_bound` | 1783 | `rem < scale` (bounded) |
| 13 | `kani_sweep_dust_below_threshold` | 1799 | `dust < scale => units==0, rem==dust` |
| 14 | `kani_scale_zero_policy_no_dust` | 1843 | `scale==0` never produces dust, full u64 range |
| 15 | `kani_scale_zero_policy_sweep_complete` | 1854 | `scale==0` sweep leaves no remainder, full u64 range |
| 16 | `kani_scale_zero_policy_end_to_end` | 1865 | End-to-end deposit+accumulate+sweep pipeline. Two symbolic inputs. |
| 17 | `kani_scale_price_e6_zero_result_rejected` | 2738 | `price < unit_scale => None`. Symbolic price and scale. |
| 18 | `kani_scale_price_e6_valid_result` | 2758 | Formula: `scaled = price / unit_scale` (bounded: scale <= 64) |
| 19 | `kani_invert_zero_returns_raw` | 1471 | `invert==0 => Some(raw)` for all u64 raw. |
| 20 | `kani_invert_overflow_branch_is_dead` | 1526 | Structural: `INVERSION_CONSTANT <= u64::MAX` and `floor(1e12/raw) <= u64::MAX` for all positive raw. |
| 21 | `kani_withdraw_insurance_vault_correct` | 3178 | `insurance <= vault => Some(vault - insurance)` for all u128 pairs. |
| 22 | `kani_withdraw_insurance_vault_overflow` | 3196 | `insurance > vault => None` for all u128 pairs. |

### Tier 9: Result Characterization Proofs (3)

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_withdraw_insurance_vault_result_characterization` | 3213 | Complete `Some(vault - ins)` / `None` characterization. Universal over all u128. Subsumes proofs #21 and #22 above but they are retained for readability. |
| 2 | `kani_invert_result_zero_returns_none` | 1511 | `raw > INVERSION_CONSTANT as u64 => None`. **Fully symbolic** (previously WEAK with offset bound). `assume(raw > 1e12)` is tight -- no SAT-bounded collapse. |
| 3 | `kani_invert_zero_raw_returns_none` | 1501 | `raw==0, invert!=0 => None`. Symbolic `invert: u8`. |

### Tier 10: Oracle Rate Limiting (Bug #9 Fix) Proofs (3)

| # | Proof | Line | Property |
|---|---|---|---|
| 1 | `kani_clamp_toward_no_movement_when_dt_zero` | 2914 | **Bug #9 fix**: `dt=0 => index` returned, not mark. Universal for all u64 `index > 0`, `cap > 0`. |
| 2 | `kani_clamp_toward_no_movement_when_cap_zero` | 2935 | `cap=0 => index` returned. Universal for all u64 `index > 0`, `dt > 0`. |
| 3 | `kani_clamp_toward_bootstrap_when_index_zero` | 2955 | `index=0 => mark` (bootstrap). Universal for all u64 `mark`, `cap`, `dt`. |

---

## Detailed Per-Proof Classification Table

| # | Proof Name | Line | Class |
|---|---|---|---|
| 1 | `kani_matcher_rejects_wrong_abi_version` | 133 | STRONG |
| 2 | `kani_matcher_rejects_missing_valid_flag` | 148 | STRONG |
| 3 | `kani_matcher_rejects_rejected_flag` | 164 | STRONG |
| 4 | `kani_matcher_rejects_nonzero_reserved` | 181 | STRONG |
| 5 | `kani_matcher_rejects_zero_exec_price` | 199 | STRONG |
| 6 | `kani_matcher_zero_size_requires_partial_ok` | 217 | STRONG |
| 7 | `kani_matcher_rejects_exec_size_exceeds_req` | 239 | STRONG |
| 8 | `kani_matcher_rejects_sign_mismatch` | 263 | STRONG |
| 9 | `kani_owner_mismatch_rejected` | 290 | STRONG |
| 10 | `kani_owner_match_accepted` | 300 | STRONG |
| 11 | `kani_admin_mismatch_rejected` | 312 | STRONG |
| 12 | `kani_admin_match_accepted` | 323 | STRONG |
| 13 | `kani_admin_burned_disables_ops` | 332 | STRONG |
| 14 | `kani_matcher_identity_mismatch_rejected` | 348 | STRONG |
| 15 | `kani_matcher_identity_match_accepted` | 365 | STRONG |
| 16 | `kani_matcher_shape_universal` | 385 | STRONG |
| 17 | `kani_pda_mismatch_rejected` | 410 | STRONG |
| 18 | `kani_pda_match_accepted` | 423 | STRONG |
| 19 | `kani_nonce_unchanged_on_failure` | 435 | STRONG |
| 20 | `kani_nonce_advances_on_success` | 444 | STRONG |
| 21 | `kani_cpi_uses_exec_size` | 462 | STRONG |
| 22 | `kani_gate_inactive_when_threshold_zero` | 481 | STRONG |
| 23 | `kani_gate_inactive_when_balance_exceeds` | 492 | STRONG |
| 24 | `kani_gate_active_when_conditions_met` | 505 | STRONG |
| 25 | `kani_single_owner_mismatch_rejected` | 523 | STRONG |
| 26 | `kani_single_owner_match_accepted` | 536 | STRONG |
| 27 | `kani_trade_rejects_user_mismatch` | 547 | STRONG |
| 28 | `kani_trade_rejects_lp_mismatch` | 561 | STRONG |
| 29 | `kani_decide_trade_cpi_universal` | 599 | STRONG |
| 30 | `kani_tradecpi_reject_nonce_unchanged` | 644 | STRONG |
| 31 | `kani_tradecpi_accept_increments_nonce` | 677 | STRONG |
| 32 | `kani_tradenocpi_auth_failure_rejects` | 731 | STRONG |
| 33 | `kani_tradenocpi_universal_characterization` | 750 | STRONG |
| 34 | `kani_matcher_zero_size_with_partial_ok_accepted` | 773 | STRONG |
| 35 | `kani_tradecpi_any_reject_nonce_unchanged` | 807 | STRONG |
| 36 | `kani_tradecpi_any_accept_increments_nonce` | 870 | STRONG |
| 37 | `kani_len_ok_universal` | 932 | STRONG |
| 38 | `kani_lp_pda_shape_universal` | 953 | STRONG |
| 39 | `kani_oracle_feed_id_universal` | 974 | STRONG |
| 40 | `kani_slab_shape_universal` | 986 | STRONG |
| 41 | `kani_decide_single_owner_universal` | 1005 | STRONG |
| 42 | `kani_decide_crank_universal` | 1018 | STRONG |
| 43 | `kani_decide_admin_universal` | 1037 | STRONG |
| 44 | `kani_abi_ok_equals_validate` | 1059 | STRONG |
| 45 | `kani_tradecpi_from_ret_any_reject_nonce_unchanged` | 1097 | STRONG |
| 46 | `kani_tradecpi_from_ret_any_accept_increments_nonce` | 1171 | STRONG |
| 47 | `kani_tradecpi_from_ret_accept_uses_exec_size` | 1242 | UNIT TEST |
| 48 | `kani_min_abs_boundary_rejected` | 1333 | UNIT TEST |
| 49 | `kani_matcher_accepts_minimal_valid_nonzero_exec` | 1369 | STRONG |
| 50 | `kani_matcher_accepts_exec_size_equal_req_size` | 1394 | STRONG |
| 51 | `kani_matcher_accepts_partial_fill_with_flag` | 1414 | STRONG |
| 52 | `kani_decide_keeper_crank_with_panic_universal` | 1442 | STRONG |
| 53 | `kani_invert_zero_returns_raw` | 1471 | STRONG |
| 54 | `kani_invert_nonzero_computes_correctly` | 1481 | WEAK |
| 55 | `kani_invert_zero_raw_returns_none` | 1501 | STRONG |
| 56 | `kani_invert_result_zero_returns_none` | 1511 | STRONG |
| 57 | `kani_invert_overflow_branch_is_dead` | 1526 | STRONG |
| 58 | `kani_invert_monotonic` | 1543 | WEAK |
| 59 | `kani_base_to_units_conservation` | 1569 | STRONG |
| 60 | `kani_base_to_units_dust_bound` | 1590 | STRONG |
| 61 | `kani_base_to_units_scale_zero` | 1606 | CODE-EQUALS-SPEC |
| 62 | `kani_units_roundtrip` | 1617 | STRONG |
| 63 | `kani_units_to_base_scale_zero` | 1634 | CODE-EQUALS-SPEC |
| 64 | `kani_base_to_units_monotonic` | 1644 | STRONG |
| 65 | `kani_units_to_base_monotonic_bounded` | 1667 | STRONG |
| 66 | `kani_base_to_units_monotonic_scale_zero` | 1691 | STRONG |
| 67 | `kani_withdraw_misaligned_rejects` | 1712 | STRONG |
| 68 | `kani_withdraw_aligned_accepts` | 1732 | STRONG |
| 69 | `kani_withdraw_scale_zero_always_aligned` | 1749 | STRONG |
| 70 | `kani_sweep_dust_conservation` | 1763 | STRONG |
| 71 | `kani_sweep_dust_rem_bound` | 1783 | STRONG |
| 72 | `kani_sweep_dust_below_threshold` | 1799 | STRONG |
| 73 | `kani_sweep_dust_scale_zero` | 1814 | CODE-EQUALS-SPEC |
| 74 | `kani_accumulate_dust_saturates` | 1827 | CODE-EQUALS-SPEC |
| 75 | `kani_scale_zero_policy_no_dust` | 1843 | STRONG |
| 76 | `kani_scale_zero_policy_sweep_complete` | 1854 | STRONG |
| 77 | `kani_scale_zero_policy_end_to_end` | 1865 | STRONG |
| 78 | `kani_universal_shape_fail_rejects` | 1891 | STRONG |
| 79 | `kani_universal_pda_fail_rejects` | 1933 | STRONG |
| 80 | `kani_universal_user_auth_fail_rejects` | 1973 | STRONG |
| 81 | `kani_universal_lp_auth_fail_rejects` | 2013 | STRONG |
| 82 | `kani_universal_identity_fail_rejects` | 2053 | STRONG |
| 83 | `kani_universal_abi_fail_rejects` | 2093 | STRONG |
| 84 | `kani_tradecpi_variants_consistent_valid_shape` | 2138 | STRONG |
| 85 | `kani_tradecpi_variants_consistent_invalid_shape` | 2212 | STRONG |
| 86 | `kani_tradecpi_from_ret_req_id_is_nonce_plus_one` | 2282 | STRONG |
| 87 | `kani_universal_gate_risk_increase_rejects` | 2340 | STRONG |
| 88 | `kani_units_roundtrip_exact_when_no_dust` | 2396 | STRONG |
| 89 | `kani_universal_panic_requires_admin` | 2415 | STRONG |
| 90 | `kani_universal_gate_risk_increase_rejects_from_ret` | 2454 | STRONG |
| 91 | `kani_tradecpi_from_ret_gate_active_risk_neutral_accepts` | 2511 | UNIT TEST |
| 92 | `kani_tradecpi_from_ret_forced_acceptance` | 2565 | STRONG |
| 93 | `kani_init_market_scale_rejects_overflow` | 2620 | UNIT TEST |
| 94 | `kani_init_market_scale_valid_range` | 2635 | UNIT TEST |
| 95 | `kani_scale_price_e6_zero_result_rejected` | 2738 | STRONG |
| 96 | `kani_scale_price_e6_valid_result` | 2758 | STRONG |
| 97 | `kani_scale_price_e6_identity_for_scale_leq_1` | 2787 | CODE-EQUALS-SPEC |
| 98 | `kani_scale_price_and_base_to_units_use_same_divisor` | 2816 | WEAK |
| 99 | `kani_scale_price_e6_concrete_example` | 2862 | WEAK |
| 100 | `kani_clamp_toward_no_movement_when_dt_zero` | 2914 | STRONG |
| 101 | `kani_clamp_toward_no_movement_when_cap_zero` | 2935 | STRONG |
| 102 | `kani_clamp_toward_bootstrap_when_index_zero` | 2955 | STRONG |
| 103 | `kani_clamp_toward_movement_bounded_concrete` | 2973 | WEAK |
| 104 | `kani_clamp_toward_formula_concrete` | 3037 | WEAK |
| 105 | `kani_clamp_toward_formula_within_bounds` | 3063 | WEAK |
| 106 | `kani_clamp_toward_formula_above_hi` | 3091 | WEAK |
| 107 | `kani_clamp_toward_saturation_paths` | 3119 | WEAK |
| 108 | `kani_withdraw_insurance_vault_correct` | 3178 | STRONG |
| 109 | `kani_withdraw_insurance_vault_overflow` | 3196 | STRONG |
| 110 | `kani_withdraw_insurance_vault_result_characterization` | 3213 | STRONG |

---

## Cross-Cutting Observations

### 1. Proof Suite Maturation

The suite has matured significantly since the previous audit (2026-02-19):
- **152 -> 110 proofs**: 42 proofs removed (primarily concrete unit tests subsumed by universal proofs)
- **STRONG percentage**: 60.5% -> 82.7% (22-point improvement)
- **WEAK count**: 14 -> 9 (all remaining are Category C SAT-bounded)
- **UNIT TEST count**: 41 -> 5 (86% reduction, all subsumed by retained universals)
- **Zero VACUOUS proofs**: Maintained

The removal of redundant unit tests is appropriate. Each removed proof was explicitly subsumed by a retained universal proof, as documented in the source comments.

### 2. Key Upgrades

- **`kani_decide_trade_cpi_universal`** (Tier 1): Replaces the former WEAK `kani_tradecpi_allows_gate_risk_decrease`. The new proof fully characterizes `decide_trade_cpi` with all 10 inputs symbolic, including the gate/risk branch. This is the single most valuable proof in the suite.
- **`kani_invert_result_zero_returns_none`**: Upgraded from WEAK to STRONG by making `raw` fully symbolic with `assume(raw > INVERSION_CONSTANT as u64)`. The assumption is tight (not SAT-bounded) since `INVERSION_CONSTANT = 1e12` is a concrete constant.
- **Clamp formula inputs widened to u16**: The `any_clamp_formula_inputs()` helper now uses `u16[100..1000]` for index and `u16[0..2000]` for mark, providing ~100x more symbolic combinations than the previous u8 bounds.

### 3. Remaining Bounded SAT Domains

The 9 WEAK proofs all share the same fundamental limitation: Kani's CBMC backend encodes integer division/multiplication as bit-level SAT constraints, and deep chains (3+ multiplications) with wide domains cause exponential blowup. The documented bounds are:
- `KANI_MAX_SCALE = 64`: Sufficient to exercise all branches of division-based functions
- `KANI_MAX_QUOTIENT = 16384` (widened from 4096): Keeps two-division chains tractable
- `any_clamp_formula_inputs()`: u16 index/mark, u8 cap/dt -- keeps triple-multiply tractable
- `kani_invert_nonzero_computes_correctly`: raw <= 8192 for single 128-bit division + equality

These bounds are explicitly documented in source comments. Production-scale values are covered by:
- 67 integration tests (LiteSVM with production BPF binaries)
- 19 proptest fuzzing tests (wider random domains)

### 4. Non-Vacuity Discipline

The suite maintains rigorous non-vacuity discipline. Key patterns:
- **Concrete non-vacuity witnesses** before universal quantification (5 proofs: `kani_tradecpi_any_reject_nonce_unchanged`, `kani_tradecpi_any_accept_increments_nonce`, `kani_clamp_toward_formula_*` x3)
- **Forced Accept paths** with `panic!` on unexpected Reject (4 proofs: `kani_tradecpi_from_ret_accept_uses_exec_size`, `kani_tradecpi_from_ret_gate_active_risk_neutral_accepts`, `kani_tradecpi_from_ret_forced_acceptance`, `kani_tradecpi_from_ret_req_id_is_nonce_plus_one`)
- **Both-outcome matching** via `match &decision` with assertions on both `Reject` and `Accept` variants (4 proofs: `kani_tradecpi_any_*`, `kani_tradecpi_from_ret_any_*`)

### 5. Coupling Completeness

The `verify` module extracts pure decision logic from `mod processor`. Coupling is verified by:
- `kani_abi_ok_equals_validate` (line 1059): Proves `verify::abi_ok` calls the real `matcher_abi::validate_matcher_return`
- `kani_tradecpi_variants_consistent_*` (lines 2138, 2212): Proves `decide_trade_cpi` and `decide_trade_cpi_from_ret` agree
- `kani_decide_trade_cpi_universal` (line 599): Fully characterizes the decision function
- Gate ordering in `decide_trade_cpi` matches production handler's check sequence (documented in source comments)

**Residual gap**: No formal proof that the `processor` handler's actual check sequence matches `decide_trade_cpi`'s gate ordering. This coupling relies on code review. A mismatch would mean the proofs verify a different policy than production. This is an inherent limitation of the extracted-function verification approach.

### 6. Missing Coverage Areas (Intentional)

The proofs do NOT cover:
- **Oracle reading** (`read_pyth_price_e6`, `read_chainlink_price_e6`): Requires `AccountInfo` which Kani cannot model
- **Zero-copy access** (`zc::engine_ref`, `zc::engine_mut`): Involves raw pointers
- **CPI invocation** (`zc::invoke_signed_trade`): Solana runtime interaction
- **Risk engine internals**: Covered by the `percolator` crate's own Kani proofs

This is explicitly documented in the file header: "CPI execution and risk engine internals are NOT modeled. Only wrapper-level authorization and binding logic is proven."

### 7. Improvement Opportunities

1. **`kani_invert_nonzero_computes_correctly`**: Could attempt `raw <= 16384` to match `KANI_MAX_QUOTIENT`. If SAT time exceeds 120s, current bound of 8192 is acceptable.
2. **Processor coupling proof**: Add a structural test asserting that the gate ordering in `decide_trade_cpi` matches `processor::process_trade_cpi`. This would close the residual coupling gap.
3. **Consolidate `kani_init_market_scale_*`**: The two UNIT TEST proofs (#93, #94) could be consolidated into a single universal characterization proof: `init_market_scale_ok(scale) == (scale <= MAX_UNIT_SCALE)`.

### 8. Summary Assessment

The proof suite is mature and high-quality. With 91 STRONG proofs (82.7%), 0 VACUOUS proofs, and only 9 WEAK proofs (all SAT-bounded Category C), it provides genuine formal guarantees for wrapper-level security properties: authorization, ABI validation, identity binding, nonce monotonicity, math correctness, and rate limiting. The removal of 42 redundant unit tests has concentrated the suite on proofs that carry real verification weight. The 5 retained UNIT TEST proofs serve specific purposes (boundary regression, forced-path testing) and the 5 CODE-EQUALS-SPEC proofs guard against refactoring regressions. The suite represents high-quality formal verification coverage for the properties it claims to verify.
