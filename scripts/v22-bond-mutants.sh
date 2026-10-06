#!/usr/bin/env bash
# Phase 4 item 3 (capacity bonds): NEGATIVE CONTROLS. Each mutant is applied by COPYING a mutated
# file over the real one (never `git stash`: the stash stack is shared across worktrees), the
# targeted tests are run and MUST FAIL, then the original is copied back and verified by hash.
#
#   scripts/v22-bond-mutants.sh pure   # MP1..MP7 against tests/v22_bonds_pure.rs (native)
#   scripts/v22-bond-mutants.sh bpf    # MB1..MB4: build a mutant BPF, run one LiteSVM test on it
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
    (0, available)' bond_coupon_first_conserves_and_is_noncumulative
  # ── security review fixes (2026-10-05) ──
  run_bpf MB5_107_after_earn_M2 $W \
'        if registry.total_lp_shares_outstanding != 0 || st.senior_claim_atoms != 0 {' \
'        if false && (registry.total_lp_shares_outstanding != 0 || st.senior_claim_atoms != 0) {' \
bond_tranche_refused_after_the_first_earn_deposit
  run_bpf MB6_coupon_cap_removed_M2 $B \
'    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);' \
'    let cap = available;' bond_coupon_first_conserves_and_is_noncumulative
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
'            group
                .full_account_refresh_not_atomic(&mut lp)
                .map_err(map_v16_error)?
                .certified_equity' \
'            i128::try_from(vault_lp_value_atoms(&group, lp.header)?).unwrap_or(0)' \
sec2_n1_fee_crank_on_a_stale_vault_lp_pays_or_fails_closed
  ;;
esac
rm -rf "$BAK"
echo "mutants surviving: $FAILS"
exit $FAILS
