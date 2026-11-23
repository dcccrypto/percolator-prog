#!/usr/bin/env bash
# Phase 4 item 3 (capacity bonds): NEGATIVE CONTROLS. Each mutant is applied by COPYING a mutated
# file over the real one (never `git stash`: the stash stack is shared across worktrees), the
# targeted tests are run and MUST FAIL, then the original is copied back and verified by hash.
#
#   scripts/v22-bond-mutants.sh pure   # MP1..MP7 against tests/v22_bonds_pure.rs (native)
#   scripts/v22-bond-mutants.sh bpf    # MB1..MB4: build a mutant BPF, run one LiteSVM test on it
#   scripts/v22-bond-mutants.sh pure571  # GH#571 M571a..g against tests/v22_bond_carry_571_pure.rs
#   scripts/v22-bond-mutants.sh bpf571   # GH#571 MB571a..m: mutant BPF vs the gh571_* / att649_* LiteSVM tests
#
# Exit 0 iff EVERY mutant was killed. Logs: $MUT_LOG_DIR (default ../logs/mutants).
set -uo pipefail
cd "$(dirname "$0")/.."
LOGS="${MUT_LOG_DIR:-../logs/mutants}"
mkdir -p "$LOGS"
BAK="$(mktemp -d)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
FAILS=0

mutate() { # file old new  (exactly one occurrence, else abort)
  python3 - "$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
n = s.count(old)
if n != 1:
    sys.exit(f"mutation anchor found {n} times in {p}")
open(p, "w").write(s.replace(old, new, 1))
PY
}

save()    { cp "$1" "$BAK/$(echo "$1" | tr / _)"; shasum -a 256 "$1" | cut -d' ' -f1 > "$BAK/$(echo "$1" | tr / _).sha"; }
restore() {
  cp "$BAK/$(echo "$1" | tr / _)" "$1"
  [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$(cat "$BAK/$(echo "$1" | tr / _).sha")" ] || { echo "RESTORE FAILED: $1" >&2; exit 3; }
}

expect_killed() { # name log-file rc
  if [ "$3" -ne 0 ] && grep -qE "test result: FAILED|panicked" "$2" && ! grep -qE "^error(\[E[0-9]+\])?: (could not compile|cannot find|mismatched)" "$2"; then
    echo "KILLED   $1"
  else
    echo "SURVIVED $1 (rc=$3)"; FAILS=$((FAILS + 1))
  fi
}

run_pure() { # name file old new
  save "$2"; mutate "$2" "$3" "$4" || { restore "$2"; echo "ANCHOR $1"; FAILS=$((FAILS + 1)); return; }
  cargo test --features devnet --test v22_bonds_pure > "$LOGS/$1.log" 2>&1; rc=$?
  restore "$2"; expect_killed "$1" "$LOGS/$1.log" $rc
}

run_pure571() { # name file old new
  save "$2"; mutate "$2" "$3" "$4" || { restore "$2"; echo "ANCHOR $1"; FAILS=$((FAILS + 1)); return; }
  cargo test --features devnet --test v22_bond_carry_571_pure > "$LOGS/$1.log" 2>&1; rc=$?
  restore "$2"; expect_killed "$1" "$LOGS/$1.log" $rc
}

run_bpf() { # name file old new test-filter
  if [ -n "${ONLY:-}" ] && [ "$ONLY" != "$1" ]; then return; fi
  save "$2"; mutate "$2" "$3" "$4" || { restore "$2"; echo "ANCHOR $1"; FAILS=$((FAILS + 1)); return; }
  cargo build-sbf --features devnet > "$LOGS/$1.build.log" 2>&1; brc=$?
  cp target/deploy/percolator_prog.so "$LOGS/$1.so" 2>/dev/null
  restore "$2"
  if [ $brc -ne 0 ]; then echo "BUILD-FAILED $1"; FAILS=$((FAILS + 1)); return; fi
  # $5 may name several tests (space separated): EVERY one must fail on the mutant.
  rc=0; : > "$LOGS/$1.log"
  for t in $5; do
    P1_WRAPPER_SO="$PWD/$LOGS/$1.so" cargo test --features devnet --test v22_bonds -- --exact "$t" >> "$LOGS/$1.log" 2>&1
    r=$?; if [ $r -eq 0 ]; then rc=0; echo "SURVIVED-TEST $t" >> "$LOGS/$1.log"; break; fi; rc=$r
  done
  expect_killed "$1" "$LOGS/$1.log" $rc
}

B=src/bond_v20.rs
W=src/v16_program.rs
case "${1:-pure}" in
pure)
  run_pure MP1_split_bond_before_senior $B \
'    let senior = if vault_value < senior_claim {
        vault_value
    } else {
        senior_claim
    };
    let rest = vault_value - senior;
    let bond = if rest < bond_claim { rest } else { bond_claim };' \
'    let bond = if vault_value < bond_claim { vault_value } else { bond_claim };
    let senior = if vault_value - bond < senior_claim { vault_value - bond } else { senior_claim };
    let rest = vault_value - senior;'
  run_pure MP2_recovery_bonds_first $B \
'        vault_value.saturating_sub(senior_claim),
    );' \
'        vault_value.saturating_sub(senior_claim).saturating_sub(bond_claim),
    );'
  run_pure MP3_lock_ignores_open_oi $B \
'    let need = if side > lp_eff_abs_q { side } else { lp_eff_abs_q };' \
'    let need = lp_eff_abs_q; let _ = side;'
  run_pure MP4_coupon_not_capped_by_leg $B \
'    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);
    let coupon = if due < cap { due } else { cap };
    (coupon, available - coupon)' \
'    (due, available.saturating_sub(due))'
  run_pure MP5_junior_gate_ignores_bonds $B \
'    let junior = tranche_split3(vault_value, senior_claim_eff, bond_claim).junior;
    let floor = match junior_floor_atoms' \
'    let junior = tranche_split3(vault_value, senior_claim_eff, 0).junior; let _ = bond_claim;
    let floor = match junior_floor_atoms'
  run_pure MP6_deposit_rounds_up $B \
'    mul_div_floor(amount, total_shares, bond_value)
}' \
'    mul_div_floor(amount, total_shares, bond_value).map(|m| m + 1)
}'
  run_pure MP7_draw_bond_before_junior $B \
'    let junior_cover = if sub_cover < junior_in_pots {
        sub_cover
    } else {
        junior_in_pots
    };
    (next, moved, junior_cover, sub_cover - junior_cover, senior_loss)' \
'    let bond_cover = if sub_cover < bond_in_pots { sub_cover } else { bond_in_pots };
    let _ = junior_in_pots;
    (next, moved, sub_cover - bond_cover, bond_cover, senior_loss)'
  # ── security review fixes (2026-10-05) ──
  run_pure MP8_coupon_cap_removed_M2 $B \
'    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);' \
'    let cap = available;'
  run_pure MP9_util_bonus_allowed_L2 $B \
'pub const BOND_UTIL_BONUS_MAX_BPS: u16 = 0;' \
'pub const BOND_UTIL_BONUS_MAX_BPS: u16 = 1_000;'
  run_pure MP10_coupon_gate_ignores_bond_impairment_M1 $B \
'    live && bond_claim > 0 && senior_draw_outstanding == 0 && bond_value >= bond_claim' \
'    let _ = bond_value; live && bond_claim > 0 && senior_draw_outstanding == 0'
  run_pure MP11_coupon_base_full_claim_M1 $B \
'    if bond_value < bond_claim {
        bond_value
    } else {
        bond_claim
    }' \
'    let _ = bond_value;
    bond_claim'
  ;;
bpf)
  run_bpf MB1_lock_disabled $B \
'    match n_cap_after {
        Some(n) => n >= need,
        None => need == 0,
    }' \
'    let _ = (n_cap_after, need);
    true' 'bond_self_funding_attack_is_refused bond_lock_binds_with_a_flat_vault_lp_and_open_user_oi'
  run_bpf MB2_97_two_tranche $W \
'bond_v20::junior_withdraw_allowed3(v, c_eff, bond_claim, cover, gated, st.junior_floor_bps)' \
'bond_v20::junior_withdraw_allowed3(v, c_eff, 0 * bond_claim, cover, gated, st.junior_floor_bps)' \
bond_junior_cannot_withdraw_bond_value_and_tranche_is_required
  run_bpf MB3_102_resolved_two_tranche $W \
'                    st.senior_claim_atoms,
                    bond_claim,
                )
            } else {' \
'                    st.senior_claim_atoms,
                    0 * bond_claim,
                )
            } else {' bond_resolved_exit_and_junior_after_bonds
  run_bpf MB4_no_coupon_first $B \
'    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);
    let coupon = if due < cap { due } else { cap };
    (coupon, available - coupon)' \
'    let _ = due;
    (0, available)' bond_coupon_first_conserves_and_carries_arrears_gh571
  # ── security review fixes (2026-10-05) ──
  run_bpf MB5_107_after_earn_M2 $W \
'        if registry.total_lp_shares_outstanding != 0 || st.senior_claim_atoms != 0 {' \
'        if false && (registry.total_lp_shares_outstanding != 0 || st.senior_claim_atoms != 0) {' \
bond_tranche_refused_after_the_first_earn_deposit
  run_bpf MB6_coupon_cap_removed_M2 $B \
'    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);' \
'    let cap = available;' bond_coupon_first_conserves_and_carries_arrears_gh571
  # MB7: the coupon gate blind to tranche impairment (the base stays min(C_b, value); MP11 covers
  # the base on its own).
  run_bpf MB7_coupon_on_full_claim_while_impaired_M1 $B \
'    live && bond_claim > 0 && senior_draw_outstanding == 0 && bond_value >= bond_claim
}' \
'    let _ = bond_value; live && bond_claim > 0 && senior_draw_outstanding == 0
}' sec_c1_impaired_bond_earns_no_coupon
  run_bpf MB8_util_bonus_allowed_L2 $B \
'pub const BOND_UTIL_BONUS_MAX_BPS: u16 = 0;' \
'pub const BOND_UTIL_BONUS_MAX_BPS: u16 = 1_000;' bond_init_authority_bounds_and_flag
  # MB9: N-1 reverted -- no in-instruction refresh: the bonds are valued on the certificate the
  # harvest just made stale (78 then fails on every crank with vault-LP inventory).
  run_bpf MB9_no_refresh_N1 $W \
'            let certified = group
                .full_account_refresh_not_atomic(&mut lp)
                .map_err(map_v16_error)?
                .certified_equity;' \
'            let certified = i128::try_from(vault_lp_value_atoms(&group, lp.header)?).unwrap_or(0);' \
sec2_n1_fee_crank_on_a_stale_vault_lp_pays_or_fails_closed
  # MB10: 78 values the LP at the certified (effective-price) equity, ignoring the lag-worse term.
  run_bpf MB10_coupon_ignores_lag_worse $W \
'            if worse < certified { worse } else { certified }' \
'            let _ = worse; certified' bond_coupon_gate_uses_the_lag_worse_value_like_108_110
  ;;
pure571)
  # GH#571 (revised after att649): the remainder carry, the cap meter, the base, the payment.
  run_pure571 M571a_remainder_dropped $B \
'        Some((due, u64::try_from(num % denom).ok()?))' \
'        Some((due, 0))'
  run_pure571 M571b_accrual_base_funded_only $B \
'    let num = coupon_base(bond_claim, bond_value)' \
'    let num = coupon_base(bond_funded_claim(bond_claim, unfunded), bond_value)'
  run_pure571 M571c_deposit_not_labelled $B \
'    unfunded.checked_add(label)' \
'    unfunded.checked_add(0 * label)'
  run_pure571 M571d_cap_ignored $B \
'    let room = cap.saturating_sub(unfunded);' \
'    let room = u128::MAX; let _ = cap;'
  run_pure571 M571e_pay_forfeits_rest $B \
'    (coupon, rest, receivable - coupon)' \
'    (coupon, rest, 0 * receivable)'
  run_pure571 M571f_closed_gate_drops_remainder $B \
'        return Some((0, rem));' \
'        return Some((0, 0));'
  run_pure571 M571g_settle_rounds_up $B \
'    let due = num / denom;' \
'    let due = num / denom + 1;'
  ;;
bpf571)
  # MB571a (att649 F1): 110 also slices the receivable pro rata: a round trip cancels the
  # junior's reimbursement again.
  run_bpf MB571a_110_slices_the_receivable $W \
'        // the cap meter leaves with the shares (the stayers'"'"' per-share headroom is unchanged)' \
'        t.coupon_arrears_atoms -= t.coupon_arrears_atoms * shares / total;' \
att649_f1_round_trip_is_neutral_for_the_junior
  # MB571b: 97 reads the stored claim only (no unsettled accrual): the junior can withdraw the
  # coupon the bonds are accruing.
  run_bpf MB571b_97_ignores_unsettled_accrual $W \
'        let bond_claim = match load_bond_tranche_if_flagged(program_id, accounts, 12, market_ai.key, &registry)? {
            Some((_, t)) => t.claim_upper_bound_at(Clock::get()?.slot)?,' \
'        let bond_claim = match load_bond_tranche_if_flagged(program_id, accounts, 12, market_ai.key, &registry)? {
            Some((_, t)) => t.claim_total()?,' \
gh571_junior_cannot_withdraw_the_bonds_accrual_and_arrears_cap_at_one_year
  # MB571c: 78 forfeits the unpaid receivable (the dust-crank grief).
  run_bpf MB571c_78_forfeits_unpaid $W \
'            bond_v20::coupon_pay_from_leg(available, r)' \
'            { let (c, rr, _) = bond_v20::coupon_pay_from_leg(available, r); (c, rr, 0) }' \
gh571_dust_trade_crank_carries_instead_of_forfeiting
  # MB571d (att649 F3): 78 drops the carried remainder: every-slot cranks grind the coupon.
  run_bpf MB571d_78_drops_the_remainder $W \
'        t.coupon_accrual_rem = rem;' \
'        t.coupon_accrual_rem = 0; let _ = rem;' \
gh571_crank_every_slot_cannot_grind_the_coupon
  # MB571e: 78 accrues whatever the gate says (drawn / impaired tranche still earns coupon).
  run_bpf MB571e_78_accrues_through_closed_gate $W \
'            now.saturating_sub(t.last_coupon_slot),
            open,
            bond_value,' \
'            now.saturating_sub(t.last_coupon_slot),
            true,
            k,' \
gh571_no_accrual_while_drawn_or_impaired_and_settled_arrears_are_kept
  # MB571f: 103 reads the stored claim only (no unsettled accrual).
  run_bpf MB571f_103_ignores_unsettled_accrual $W \
'        let bond_claim = match load_bond_tranche_if_flagged(program_id, accounts, 9, market_ai.key, &registry)? {
            Some((_, t)) => t.claim_upper_bound_at(Clock::get()?.slot)?,' \
'        let bond_claim = match load_bond_tranche_if_flagged(program_id, accounts, 9, market_ai.key, &registry)? {
            Some((_, t)) => t.claim_total()?,' \
gh571_103_allocation_reserves_the_bonds_accrual
  # MB571g (att649 F1b): 108 does not label the new shares' meter: a round trip resets the cap.
  run_bpf MB571g_108_meter_not_labelled $W \
'        t.coupon_unfunded_atoms = bond_v20::coupon_meter_after_deposit(t.coupon_unfunded_atoms, t.c_b_atoms, amount)' \
'        t.coupon_unfunded_atoms = Some(t.coupon_unfunded_atoms + 0 * amount)' \
att649_f1b_round_trip_cannot_reset_the_one_year_cap
  # MB571h (att649 F2): no gate memory: the crank after a closed window accrues the window.
  run_bpf MB571h_78_no_gate_memory $W \
'        let open = open_now && bond_interval_clean(&t, st);' \
'        let open = open_now; let _ = bond_interval_clean(&t, st);' \
gh571_no_accrual_while_drawn_or_impaired_and_settled_arrears_are_kept
  # MB571i (#571 follow-up, #678): the Resolved 110 skips the catch-up to resolved_slot: the
  # Live stretch since the last settlement is forfeited again.
  run_bpf MB571i_110_no_resolve_catch_up $W \
'                bond_settle_to_resolve(&mut t, &st, resolved_slot)?;' \
'                let _ = resolved_slot;' \
gh571_followup_tag19_resolve_settles_the_live_stretch
  # MB571j (#571 follow-up, #678): 102 Resolved reserves the stored K only: the junior can
  # sweep the stretch before any settlement runs.
  run_bpf MB571j_102_reserves_stored_k_only $W \
'                Some((_, t)) => bond_claim_at_resolve(&t, &st, state::market_resolved_slot(&market_ai.try_borrow_data()?)?)?,' \
'                Some((_, t)) => t.claim_total()?,' \
gh571_followup_102_first_reserves_it
  # MB571k (#571 follow-up, #678): terminal 78 skips the catch-up to resolved_slot.
  run_bpf MB571k_78_no_resolve_catch_up $W \
'                bond_settle_to_resolve(&mut t, st, state::market_resolved_slot(&d)?)?;' \
'                let _ = st;' \
gh571_followup_terminal78_first_then_idempotent
  # MB571l (#571 follow-up, #678): the catch-up ignores the F2 interval rule (a stretch that
  # started with the gate closed accrues anyway).
  run_bpf MB571l_catch_up_ignores_f2 $W \
'            Some(end) if end > t.last_coupon_slot => bond_settle_coupon_to(t, st, end, t.c_b_atoms > 0, false),' \
'            Some(end) if end > t.last_coupon_slot => { t.coupon_gate_seen = bond_gate_seen(st, true); bond_settle_coupon_to(t, st, end, t.c_b_atoms > 0, false) },' \
gh571_followup_closed_at_last_settlement_forfeits
  # MB571m (#571 follow-up, #678): the Recovery route is not treated as resolved (no catch-up
  # once Recovery finalizes): the stretch to the finalize slot is forfeited.
  run_bpf MB571m_recovery_route_not_resolved $W \
'        Ok(Some(h.resolved_slot.get()))' \
'        if h.recovery_reason.try_to_runtime().ok().flatten().is_some() { return Ok(None); } Ok(Some(h.resolved_slot.get()))' \
gh571_followup_recovery_route_settles_to_the_finalize_slot
  ;;
esac
rm -rf "$BAK"
echo "mutants surviving: $FAILS"
exit $FAILS
