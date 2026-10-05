// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Phase 4 item 3 (capacity bonds), PURE-FUNCTION tests at full u128 width on the PRODUCTION
//! functions (`percolator_prog::bond_v20`, `percolator_prog::vault_lp_v18`):
//!
//! * I-T1..I-T7 as proptests (the Kani design `~/percolator-ops/ledger/kani-v22-bonds-design-
//!   2026-10-05.md` states the same laws as bounded harnesses; this is the full-width half);
//! * the P3 senior-draw proofs D-P3-20..33 re-run as proptests, plus their three-layer
//!   counterparts on `draw_step3` / `recover3`;
//! * the LAZY representation (two-layer senior booking + `tranche_split3`) equals the EXPLICIT
//!   three-layer model (junior -> bond -> senior cover with a written-down bond claim) on random
//!   loss / recovery sequences;
//! * a five-claimant conservation proptest (winners, seniors, bonds, junior, insurance) over
//!   random loss / gain / fee / deposit / withdrawal sequences, with the waterfall order asserted
//!   at every loss and every recovery.
//!
//! Negative controls: `scripts/v22-bond-mutants.sh` copies a mutated `src/bond_v20.rs` over the
//! real one (never `git stash`), runs this file, and requires it to FAIL for each mutant.

use percolator_prog::bond_v20::*;
use percolator_prog::vault_lp_v18::*;
use proptest::prelude::*;

const BIG: u128 = 1u128 << 90; // state magnitudes: sums of ~60 ops stay far from u128::MAX
/// SPL-representable amounts / shares: the domain the share math is specified on (products of
/// two of them fit u128 exactly; beyond it the functions fail closed, `share_math_fails_closed`).
const SPL: u128 = u64::MAX as u128;

#[test]
fn share_math_fails_closed_beyond_spl_width() {
    let big = 1u128 << 100;
    assert_eq!(bond_shares_for_deposit(big, big, 1), None);
    assert_eq!(bond_atoms_for_redemption(big, big, big), None);
    assert_eq!(bond_claim_after_redemption(big, big, big), None);
    assert_eq!(coupon_due(1u128 << 91, 3_000, u64::MAX), None);
    assert!(coupon_due((1u128 << 90) - 1, 3_000, u64::MAX).is_some());
}

fn min(a: u128, b: u128) -> u128 {
    if a < b { a } else { b }
}

/// Exact 256-bit product `(hi, lo)`: the cross-multiplied dilution checks must not overflow
/// at full width.
fn mul256(a: u128, b: u128) -> (u128, u128) {
    let m = u64::MAX as u128;
    let (a0, a1, b0, b1) = (a & m, a >> 64, b & m, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & m) + (p10 & m);
    let lo = (p00 & m) | ((mid & m) << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// `a * b >= c * d`, exactly.
fn ge(a: u128, b: u128, c: u128, d: u128) -> bool {
    mul256(a, b) >= mul256(c, d)
}

#[test]
fn mul256_sanity() {
    assert_eq!(mul256(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
    assert_eq!(mul256(1 << 64, 1 << 64), (1, 0));
    assert_eq!(mul256(3, 5), (0, 15));
    assert!(ge(u128::MAX, 2, u128::MAX, 1) && !ge(u128::MAX, 1, u128::MAX, 2));
}

fn any_u128() -> impl Strategy<Value = u128> {
    prop_oneof![
        3 => any::<u128>(),
        3 => 0u128..BIG,
        2 => 0u128..1_000_000,
        1 => Just(0u128),
        1 => Just(u128::MAX),
    ]
}

fn small_or_big() -> impl Strategy<Value = u128> {
    prop_oneof![3 => 0u128..BIG, 2 => 0u128..10_000, 1 => Just(0u128)]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4_096, .. ProptestConfig::default() })]

    // ── I-T1 / I-T2 / I-T8: the split ───────────────────────────────────────────────────────
    #[test]
    fn it1_it2_split3_conserves_and_orders(v in any_u128(), cs in any_u128(), cb in any_u128()) {
        let t = tranche_split3(v, cs, cb);
        prop_assert_eq!(t.senior.checked_add(t.bond).and_then(|x| x.checked_add(t.junior)), Some(v));
        prop_assert!(t.senior <= cs && t.bond <= cb);
        if t.junior > 0 { prop_assert!(t.bond == cb && t.senior == cs); }
        if t.bond < cb { prop_assert_eq!(t.junior, 0); }
        if t.senior < cs { prop_assert!(t.bond == 0 && t.junior == 0); }
        // I-T8: with no bond claim it is the P3 two-tranche split, byte for byte.
        let t0 = tranche_split3(v, cs, 0);
        let p3 = tranche_split(v, cs);
        prop_assert_eq!((t0.senior, t0.bond, t0.junior), (p3.senior, 0, p3.junior));
    }

    /// Monotone layering: more value never lowers any layer; a larger bond claim never raises
    /// the junior and never moves the senior.
    #[test]
    fn split3_monotone(v in 0u128..BIG, dv in 0u128..BIG, cs in 0u128..BIG, cb in 0u128..BIG, dcb in 0u128..BIG) {
        let a = tranche_split3(v, cs, cb);
        let b = tranche_split3(v + dv, cs, cb);
        prop_assert!(b.senior >= a.senior && b.bond >= a.bond && b.junior >= a.junior);
        let c = tranche_split3(v, cs, cb + dcb);
        prop_assert!(c.senior == a.senior && c.junior <= a.junior && c.bond >= a.bond);
    }

    // ── I-T5: deposits never dilute; redemptions never dilute ──────────────────────────────
    #[test]
    fn it5_bond_deposit_no_dilution(amount in 1u128..=SPL, b in 0u128..=SPL, value in 0u128..=SPL) {
        if let Some(m) = bond_shares_for_deposit(amount, b, value) {
            if b == 0 {
                prop_assert_eq!(m, amount);
            } else {
                // (value + amount) / (b + m) >= value / b  <=>  (value + amount) * b >= value * (b + m)
                prop_assert!(ge(value + amount, b, value, b + m));
                prop_assert!(ge(amount, b, m, value), "never more shares than paid for");
            }
        } else {
            // fail closed: an impaired-to-zero tranche, or a corrupt (overflowing) input
            prop_assert!((b > 0 && value == 0) || amount.checked_mul(b).is_none());
        }
    }

    #[test]
    fn it5_bond_redemption_no_dilution(b in 1u128..=SPL, sh in 0u128..=SPL, cb in 0u128..=SPL, value in 0u128..=SPL) {
        let sh = sh % (b + 1);
        let value = min(value, cb);
        let (Some(pay), Some(cb2)) = (bond_atoms_for_redemption(sh, b, value), bond_claim_after_redemption(cb, sh, b)) else {
            // fail closed only on an overflowing (corrupt) product
            prop_assert!(sh.checked_mul(value).is_none() || sh.checked_mul(cb).is_none());
            return Ok(());
        };
        prop_assert!(pay <= value && cb2 <= cb);
        prop_assert!(ge(sh, value, pay, b), "payout floors");
        if sh == b { prop_assert_eq!(cb2, 0); }
        if sh < b {
            // remaining per-share CLAIM does not fall: cb2 / (b - sh) >= cb / b
            prop_assert!(ge(cb2, b, cb, b - sh));
            // remaining per-share VALUE does not fall: (value - pay) / (b - sh) >= value / b
            prop_assert!(ge(value - pay, b, value, b - sh));
        }
        prop_assert!(bond_atoms_for_redemption(b + 1, b, value).is_none());
    }

    // ── I-T6: the lock ─────────────────────────────────────────────────────────────────────
    #[test]
    fn it6_lock_never_leaves_ncap_below_open_exposure(
        n in prop::option::of(any_u128()), l in any_u128(), s in any_u128(), lp in any_u128()
    ) {
        let ok = bond_withdraw_lock_ok(n, l, s, lp);
        match n {
            Some(n) => prop_assert_eq!(ok, n >= l && n >= s && n >= lp),
            None => prop_assert_eq!(ok, l == 0 && s == 0 && lp == 0),
        }
    }

    // ── I-T7: coupon ───────────────────────────────────────────────────────────────────────
    #[test]
    fn it7_coupon_bounded_noncumulative_and_ordered(
        avail in any_u128(), cb in 0u128..(1u128 << 90), rate in 0u32..=3_000, dt in any::<u64>(),
        share in 0u16..=10_000, target in 0u16..=10_000, c in 0u128..BIG, level in 0u128..BIG
    ) {
        let due = coupon_due(cb, rate, dt).unwrap();
        // a year's worth at most, whatever the gap (no jumbo arrears crank)
        prop_assert!(due <= cb * rate as u128 / BPS);
        prop_assert_eq!(due, coupon_due(cb, rate, core::cmp::max(dt, SLOTS_PER_YEAR as u64)).unwrap().min(due));
        let (coupon, rest) = bond_coupon_split(avail, due);
        prop_assert!(coupon <= avail && coupon <= due && coupon + rest == avail);
        let (share, target) = if share == 0 || target == 0 { (0, 0) } else { (share, target) };
        if let Some((cp, cu, se)) = fee_waterfall3(avail, due, share, target, c, level) {
            prop_assert_eq!(cp, coupon);
            prop_assert_eq!(cp.checked_add(cu).and_then(|x| x.checked_add(se)), Some(avail));
            // the cushion only ever sees what the coupon left
            prop_assert!(cu <= bps_floor(rest, share).unwrap());
        }
        // gate: never while a senior loss is outstanding, never off Live, never on an empty tranche
        prop_assert!(!coupon_gate_open(true, cb, 1));
        prop_assert!(!coupon_gate_open(false, cb, 0));
        prop_assert_eq!(coupon_gate_open(true, cb, 0), cb > 0);
    }

    #[test]
    fn it7_coupon_monotone_in_time_rate_and_claim(cb in 0u128..BIG, r in 0u32..=3_000, dt in any::<u64>(), e in 0u64..1_000_000) {
        let a = coupon_due(cb, r, dt).unwrap();
        prop_assert!(coupon_due(cb, r, dt.saturating_add(e)).unwrap() >= a);
        prop_assert!(coupon_due(cb, r + 1, dt).unwrap() >= a);
        prop_assert!(coupon_due(cb + 1, r, dt).unwrap() >= a);
        prop_assert_eq!(coupon_due(cb, r, 0).unwrap(), 0);
    }

    #[test]
    fn util_and_rate_bounded(oi in any_u128(), n in any_u128(), base in 0u16..=BOND_COUPON_MAX_BPS, bonus in 0u16..=BOND_UTIL_BONUS_MAX_BPS, u in any::<u16>()) {
        let x = bond_util_bps(oi, n);
        prop_assert!(x as u128 <= BPS);
        if oi == 0 { prop_assert_eq!(x, 0); }
        let r = bond_coupon_rate_bps(base, bonus, u);
        prop_assert!(r >= base as u32 && r <= base as u32 + bonus as u32);
    }

    // ── junior-facing gates ────────────────────────────────────────────────────────────────
    #[test]
    fn junior_gates_never_reach_bond_value(
        v in 0u128..BIG, c in 0u128..BIG, cb in 0u128..BIG, cover in 0u128..BIG, amt in 0u128..BIG, floor in 0u16..=10_000
    ) {
        let ok = junior_withdraw_allowed3(v, c, cb, cover, amt, floor);
        prop_assert_eq!(junior_withdraw_allowed3(v, c, 0, cover, amt, floor), junior_withdraw_allowed(v, c, cover, amt, floor));
        if ok {
            let before = tranche_split3(v, c, cb);
            let after = tranche_split3(v - amt, c, cb);
            prop_assert_eq!(after.bond, before.bond, "a junior withdrawal never touches bond value");
            prop_assert_eq!(after.senior, before.senior, "nor senior value");
            prop_assert!(amt <= before.junior);
        }
        prop_assert_eq!(alloc_junior_ok3(v, c, 0), alloc_junior_ok(v, c));
        if alloc_junior_ok3(v, c, cb) { prop_assert!(alloc_junior_ok(v, c)); } // tighten-only
        prop_assert_eq!(resolved_junior_surplus3(v, c, 0), v.saturating_sub(c));
        prop_assert_eq!(resolved_junior_surplus3(v, c, cb) + resolved_bond_value(v, c, cb), v.saturating_sub(c));
    }

    #[test]
    fn cap_and_cooldown(cb in any_u128(), c in any_u128(), j in any_u128(), cap in 0u16..=10_000, now in any::<u64>(), req in any::<u64>(), cd in any::<u32>()) {
        let ok = bond_cap_ok(cb, c, j, cap);
        if let Some(base) = c.checked_add(j) {
            prop_assert_eq!(ok, cb <= bps_floor(base, cap).unwrap());
        } else {
            prop_assert!(!ok);
        }
        let e = bond_cooldown_elapsed(now, req, cd);
        prop_assert_eq!(e, (now as u128) >= min(req as u128 + cd as u128, u64::MAX as u128));
    }

    #[test]
    fn worse_value_never_above_eff(nav in 0u128..BIG, lpv in 0u128..BIG, w in any::<i128>()) {
        let vw = vault_value_worse(nav, lpv, w);
        prop_assert!(vw <= nav + lpv);
        if w >= lpv as i128 { prop_assert_eq!(vw, nav + lpv); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// D-P3-20..33 re-run as full-width proptests (the Kani harnesses in
// kani/review-p3/src/proofs_senior_draw.rs + proofs_recall.rs @ ff95c5a1), then their
// three-layer counterparts.
// ═══════════════════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig { cases: 4_096, .. ProptestConfig::default() })]

    #[test]
    fn d_p3_20_draw_amount_exact(d in any_u128(), j in any_u128(), b in any_u128(), o in any_u128()) {
        let x = vault_lp_senior_draw_amount(d, j, b, o);
        let owed = d.saturating_sub(min(d, j)).saturating_sub(o);
        prop_assert!(x <= owed && x <= b);
        prop_assert_eq!(x, min(owed, b));
        if o == 0 && j.checked_add(b).is_none_or(|f| f >= d) {
            prop_assert_eq!(min(d, j) + x, d);
        }
    }

    #[test]
    fn d_p3_21m_draw_move_bounded_and_ordered(d in any_u128(), j in any_u128(), b in any_u128()) {
        let (jc, sd) = vault_lp_draw_move(d, j, b);
        prop_assert_eq!(jc, min(min(d, j), b));
        prop_assert_eq!(jc + sd, min(d, b));
        if sd > 0 { prop_assert_eq!(jc, min(d, j)); }
    }

    #[test]
    fn d_p3_22_step_split_invariant(cs in any_u128(), j in any_u128(), dr in any_u128(), d0 in any_u128(), d1 in any_u128(), d2 in any_u128()) {
        let g = DrawState { senior_claim: cs, outstanding: 0, junior_surplus: j, drawable: dr };
        let (s, _, _) = vault_lp_draw_step(g, d0);
        let (z, zm, zl) = vault_lp_draw_step(s, 0);
        prop_assert!(z == s && zm == 0 && zl == 0);
        if let Some(sum) = d1.checked_add(d2) {
            let (one, m, l) = vault_lp_draw_step(s, sum);
            let (a, m1, l1) = vault_lp_draw_step(s, d1);
            let (two, m2, l2) = vault_lp_draw_step(a, d2);
            prop_assert!(one == two);
            prop_assert_eq!(m1 + m2, m);
            prop_assert_eq!(l1 + l2, l);
        }
    }

    #[test]
    fn d_p3_23_claim_falls_by_funded_senior_draw(cs in any_u128(), o in any_u128(), j in any_u128(), dr in any_u128(), d in any_u128()) {
        let s = DrawState { senior_claim: cs, outstanding: o, junior_surplus: j, drawable: dr };
        let (n, moved, loss) = vault_lp_draw_step(s, d);
        let (jc, sd) = vault_lp_draw_move(d, j, dr);
        prop_assert_eq!(moved, jc + sd);
        prop_assert_eq!(n.senior_claim, cs.saturating_sub(sd));
        prop_assert_eq!(loss, cs - n.senior_claim);
        prop_assert_eq!(n.outstanding, o.saturating_add(loss));
        prop_assert_eq!(n.junior_surplus, j - jc);
        prop_assert_eq!(n.drawable, dr - moved);
        if d <= j { prop_assert_eq!(n.senior_claim, cs); }
        if loss > 0 { prop_assert_eq!(n.junior_surplus, 0); }
    }

    #[test]
    fn d_p3_25_recover_seniors_first(cs in 0u128..(u128::MAX >> 1), drawn in 0u128..(u128::MAX >> 1), o in any_u128(), p in any_u128(), v in any_u128()) {
        let o = min(o, drawn);
        let l = DrawLedger { senior_claim: cs, drawn, outstanding: o, pending: p };
        let (n, to_s) = vault_lp_recover(l, v);
        prop_assert_eq!(to_s, min(v, o));
        prop_assert_eq!(n.senior_claim + n.outstanding, cs + o);
        prop_assert!(n.drawn == drawn && n.pending == p && n.outstanding <= n.drawn);
        if v > o { prop_assert_eq!(n.outstanding, 0); }
    }

    #[test]
    fn d_p3_26_draw_halts_owner_rule_with_bond_op(o in any_u128(), op in any::<u8>()) {
        let h = vault_lp_draw_halts(o, op);
        let halted = op == DRAW_OP_LP_RISK_INCREASING_FILL || op == DRAW_OP_JUNIOR_WITHDRAW_97
            || op == DRAW_OP_RECALL_98 || op == DRAW_OP_JUNIOR_RELEASE_102 || op == DRAW_OP_BOND_WITHDRAW;
        let open = op == DRAW_OP_SENIOR_DEPOSIT_75 || op == DRAW_OP_SENIOR_REQUEST_76 || op == DRAW_OP_SENIOR_REDEEM_77;
        if halted { prop_assert_eq!(h, o > 0); }
        if open || o == 0 { prop_assert!(!h); }
        prop_assert_eq!(DRAW_OP_BOND_WITHDRAW, 8);
    }

    #[test]
    fn d_p3_28_pricing_claim_equals_booked_claim(cs in any_u128(), drawn in any_u128(), o in any_u128(), p in any_u128(), j in any_u128()) {
        let l = DrawLedger { senior_claim: cs, drawn, outstanding: o, pending: p };
        let priced = vault_lp_senior_pricing_claim(cs, p, j);
        let (booked, _) = vault_lp_book_pending(l, j);
        prop_assert_eq!(priced, booked.senior_claim);
        prop_assert!(priced <= cs);
    }

    #[test]
    fn d_p3_29_draw_move_conserves_value_three_tranche(nav in 0u128..BIG, h in 0u128..BIG, lp in 0u128..BIG, d in 0u128..BIG, j in 0u128..BIG, c in 0u128..BIG, cb in 0u128..BIG) {
        let (jc, sd) = vault_lp_draw_move(d, j, nav);
        let x = jc + sd;
        let v0 = vault_value(nav, h, lp).unwrap();
        let v1 = vault_value(nav - x, h, lp + x).unwrap();
        prop_assert_eq!(v0, v1);
        prop_assert_eq!(tranche_split3(v0, c, cb), tranche_split3(v1, c, cb));
    }

    #[test]
    fn d_p3_31_book_pending_once_and_conserving(cs in 0u128..(u128::MAX >> 2), drawn in 0u128..(u128::MAX >> 2), o in any_u128(), p in any_u128(), j in any_u128()) {
        let o = min(o, drawn); // reachable-state invariant `outstanding <= drawn`; sums fit
        let l = DrawLedger { senior_claim: cs, drawn, outstanding: o, pending: p };
        let (b, loss) = vault_lp_book_pending(l, j);
        if p == 0 {
            prop_assert!(b == l && loss == 0);
        } else {
            prop_assert_eq!(b.pending, 0);
            prop_assert_eq!(b.senior_claim + b.outstanding, cs + o);
            prop_assert_eq!(b.drawn, drawn + loss);
            prop_assert_eq!(loss, cs - b.senior_claim);
        }
        prop_assert!(b.outstanding <= b.drawn);
        let (b2, loss2) = vault_lp_book_pending(b, j);
        prop_assert!(b2 == b && loss2 == 0);
    }

    #[test]
    fn d_p3_33_recall_capped_and_halted(existing in any_u128(), e in any::<i128>(), pending in any::<bool>()) {
        let r = vault_lp_recall_limit(existing, e, pending);
        let eq = if e > 0 { e as u128 } else { 0 };
        prop_assert!(r <= eq && r <= existing);
        if pending { prop_assert_eq!(r, 0); } else { prop_assert_eq!(r, min(existing, eq)); }
    }

    #[test]
    fn d_p3_33c_no_recall_right_after_any_draw(cs in any_u128(), o in any_u128(), j in any_u128(), dr in any_u128(), d in 0u128..=(i128::MAX as u128), pending in any::<bool>()) {
        let s = DrawState { senior_claim: cs, outstanding: o, junior_surplus: j, drawable: dr };
        let (n, moved, _) = vault_lp_draw_step(s, d);
        let e = moved as i128 - d as i128;
        let raw = recall_limit(n.senior_claim, dr - moved);
        prop_assert_eq!(vault_lp_recall_limit(raw, e, pending), 0);
    }

    // ── three-layer counterparts (I-T3, I-T4) ──────────────────────────────────────────────

    /// I-T3 on the real `draw_step3`: the subordinate cover is junior FIRST; the bond pays only
    /// once the junior's pot value is gone, the seniors only once the bond's is; the senior loss is
    /// EXACTLY the production two-layer step's (the bonds need no booking).
    #[test]
    fn g7_draw3_order(cs in any_u128(), o in any_u128(), surplus in any_u128(), dr in any_u128(), cb in any_u128(), d in any_u128()) {
        let s = DrawState { senior_claim: cs, outstanding: o, junior_surplus: surplus, drawable: dr };
        let (n, moved, jc, bc, sl) = draw_step3(s, cb, d);
        let (n2, moved2, sl2) = vault_lp_draw_step(s, d);
        prop_assert!(n == n2 && moved == moved2 && sl == sl2, "senior books are the two-layer step's");
        let (sub, sd) = vault_lp_draw_move(d, surplus, dr);
        prop_assert_eq!(jc + bc, sub);
        prop_assert_eq!(jc + bc + sd, moved);
        let bond_in = min(surplus, cb);
        let junior_in = surplus - bond_in;
        prop_assert!(jc <= junior_in && bc <= bond_in);
        if bc > 0 { prop_assert_eq!(jc, junior_in, "bond pays only after the junior's pot value is gone"); }
        if sd > 0 { prop_assert_eq!(bc, bond_in, "seniors pay only after the bond's pot value is gone"); }
    }

    /// The lazy split agrees with the explicit draw: across a draw of a deficit `d` with the vault
    /// LP at zero value, the bond's VALUE (split3 on the pots) falls by exactly `bond_cover`, the
    /// junior's by `junior_cover`, and the senior's by the funded senior draw.
    #[test]
    fn g7_lazy_split_equals_explicit_draw(cs in 0u128..BIG, nav in 0u128..BIG, cb in 0u128..BIG, d in 0u128..BIG) {
        let surplus = nav.saturating_sub(cs);
        let s = DrawState { senior_claim: cs, outstanding: 0, junior_surplus: surplus, drawable: nav };
        let (n, moved, jc, bc, _sl) = draw_step3(s, cb, d);
        let before = tranche_split3(nav, cs, cb);
        let after = tranche_split3(nav - moved, n.senior_claim, cb);
        prop_assert_eq!(before.junior - after.junior, jc);
        prop_assert_eq!(before.bond - after.bond, bc);
        // senior VALUE falls by what was drawn from it (its claim falls with it, when whole)
        prop_assert_eq!(before.senior - after.senior, moved - jc - bc);
    }

    /// I-T4 on the real `recover3`: value restores the seniors' booked loss first, then the bonds
    /// up to C_b, then the junior; `C_s + outstanding` is conserved.
    #[test]
    fn g7_recover3_order(v in 0u128..BIG, cs in 0u128..BIG, o in 0u128..BIG, cb in 0u128..BIG) {
        let (cs2, o2, t) = recover3(v, cs, o, cb);
        prop_assert_eq!(cs2 + o2, cs + o);
        prop_assert_eq!(t.senior + t.bond + t.junior, v);
        if t.bond > 0 { prop_assert_eq!(o2, 0, "bonds recover only after the seniors' outstanding is restored"); }
        if t.junior > 0 { prop_assert!(o2 == 0 && t.bond == cb, "junior last"); }
        // monotone: more value never helps a junior layer before a senior one
        let (_, o3, t3) = recover3(v.saturating_add(1), cs, o, cb);
        prop_assert!(o3 <= o2 && t3.bond >= t.bond && t3.junior >= t.junior);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════
// Five-claimant conservation over random sequences (full width), using ONLY production fns.
// ═══════════════════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
enum Op {
    /// The vault LP owes the winners `x` (a trader gain against it).
    LpLoss(u128),
    /// The traders lose `x` to the vault LP (recovery).
    LpGain(u128),
    /// An LP fee leg of `x` lands in the pots after `dt` slots (tag 78).
    Fee(u128, u64),
    BondDeposit(u128),
    /// Redeem `num/16` of the bond shares (paid out of the vault LP's capital).
    BondWithdraw(u8),
    /// Junior withdrawal attempt of `x` (tag 97 admission).
    JuniorWithdraw(u128),
    /// A senior redeems `num/16` of its claim from the pots while whole.
    SeniorRedeem(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => small_or_big().prop_map(Op::LpLoss),
        2 => small_or_big().prop_map(Op::LpGain),
        2 => (small_or_big(), any::<u64>()).prop_map(|(x, t)| Op::Fee(x, t)),
        2 => small_or_big().prop_map(Op::BondDeposit),
        2 => (0u8..=16).prop_map(Op::BondWithdraw),
        1 => small_or_big().prop_map(Op::JuniorWithdraw),
        1 => (0u8..=16).prop_map(Op::SeniorRedeem),
    ]
}

#[derive(Clone, Debug, Default)]
struct World {
    nav: u128,
    lp: u128,
    insurance: u128,
    c_s: u128,
    outstanding: u128,
    c_b: u128,
    b: u128,
    v_in: u128,
    winners: u128,
    haircut: u128,
    seniors_paid: u128,
    bonds_paid: u128,
    junior_paid: u128,
}

impl World {
    fn v(&self) -> u128 {
        self.nav + self.lp
    }
    fn split(&self) -> TrancheSplit3 {
        tranche_split3(self.v(), self.c_s, self.c_b)
    }
    /// v_in == winners + seniors + bonds + junior (paid out) + V (by layer) + insurance.
    fn conserved(&self) -> bool {
        let t = self.split();
        self.v_in
            == self.winners
                + self.seniors_paid
                + self.bonds_paid
                + self.junior_paid
                + t.senior
                + t.bond
                + t.junior
                + self.insurance
    }
}

/// Coverage counters (the proptest analogue of Kani `cover!`): every interesting branch of the
/// waterfall must actually be reached across the run, or the conservation result is vacuous.
#[derive(Default, Debug)]
struct Cov {
    junior_only_loss: u64,
    bond_hit: u64,
    senior_hit: u64,
    insurance_used: u64,
    haircut: u64,
    recovery_to_seniors: u64,
    recovery_to_bonds: u64,
    coupon_paid: u64,
    coupon_gated_by_senior_loss: u64,
    bond_deposit: u64,
    bond_exit: u64,
    bond_exit_impaired: u64,
    junior_withdraw: u64,
    senior_redeem: u64,
}

#[allow(clippy::too_many_arguments)]
fn five_claimant_case(
    senior0: u128,
    junior0: u128,
    ins0: u128,
    coupon_bps: u16,
    share: u16,
    target: u16,
    floor_bps: u16,
    ops: Vec<Op>,
    cov: &mut Cov,
) -> Result<(), TestCaseError> {
    let (share, target) = if share == 0 || target == 0 { (0, 0) } else { (share, target) };
    let mut w = World {
        nav: senior0,
        lp: junior0,
        insurance: ins0,
        c_s: senior0,
        v_in: senior0 + junior0 + ins0,
        ..World::default()
    };
    prop_assert!(w.conserved());
    for o in ops {
        let before = w.split();
        match o {
            Op::LpLoss(x) => {
                let from_lp = min(x, w.lp);
                w.lp -= from_lp;
                w.winners += from_lp;
                let d = x - from_lp;
                let s = DrawState {
                    senior_claim: w.c_s,
                    outstanding: w.outstanding,
                    junior_surplus: w.nav.saturating_sub(w.c_s),
                    drawable: w.nav,
                };
                let (n, moved, jc, bc, sl) = draw_step3(s, w.c_b, d);
                w.nav -= moved;
                w.winners += moved;
                w.c_s = n.senior_claim;
                w.outstanding = n.outstanding;
                let rem = d - moved;
                let ins = min(rem, w.insurance); // spec §4.6: exactly min(loss, I)
                w.insurance -= ins;
                w.winners += ins;
                w.haircut += rem - ins;
                let after = w.split();
                // ORDER: junior -> bonds -> seniors -> insurance -> winner haircut
                if after.bond < before.bond {
                    prop_assert_eq!(after.junior, 0, "bond hit before the junior was gone");
                    cov.bond_hit += 1;
                }
                if after.senior < before.senior {
                    prop_assert!(after.bond == 0 && after.junior == 0, "senior hit before bonds and junior were gone");
                    cov.senior_hit += 1;
                }
                if x > 0 && after.junior < before.junior && after.bond == before.bond && after.senior == before.senior {
                    cov.junior_only_loss += 1;
                }
                if ins > 0 {
                    prop_assert_eq!(w.nav, 0, "insurance used while senior backing remained");
                    cov.insurance_used += 1;
                }
                if rem > ins {
                    prop_assert_eq!(w.insurance, 0, "winner haircut while insurance remained");
                    cov.haircut += 1;
                }
                if sl > 0 {
                    prop_assert!(jc + bc == min(s.junior_surplus, s.drawable));
                }
            }
            Op::LpGain(x) => {
                w.lp += x;
                w.v_in += x;
                let out0 = w.outstanding;
                let (cs, out, after) = recover3(w.v(), w.c_s, w.outstanding, w.c_b);
                w.c_s = cs;
                w.outstanding = out;
                prop_assert_eq!(after, w.split());
                if out < out0 { cov.recovery_to_seniors += 1; }
                if after.bond > before.bond {
                    prop_assert_eq!(w.outstanding, 0, "bond restored before seniors");
                    cov.recovery_to_bonds += 1;
                }
                if after.junior > before.junior {
                    prop_assert!(w.outstanding == 0 && after.bond == w.c_b, "junior restored early");
                }
            }
            Op::Fee(x, dt) => {
                let Some(due0) = coupon_due(w.c_b, coupon_bps as u32, dt) else { continue };
                let open = coupon_gate_open(true, w.c_b, w.outstanding);
                let due = if open { due0 } else { 0 };
                let (coupon, cushion, senior) = fee_waterfall3(x, due, share, target, w.c_s, before.junior)
                    .expect("in-range dials");
                prop_assert_eq!(coupon + cushion + senior, x, "the fee leg is split exactly");
                prop_assert!(coupon <= due && coupon <= x);
                if w.outstanding > 0 {
                    prop_assert_eq!(coupon, 0, "no coupon ahead of senior principal");
                    if due0 > 0 && x > 0 { cov.coupon_gated_by_senior_loss += 1; }
                }
                if coupon > 0 { cov.coupon_paid += 1; }
                w.nav += x;
                w.v_in += x;
                w.c_b += coupon;
                w.c_s += senior;
            }
            Op::BondDeposit(x) => {
                if x == 0 { continue; }
                let t = w.split();
                if w.v() < w.c_s || bond_impaired(w.v(), w.c_s, w.c_b) { continue; }
                if !bond_cap_ok(w.c_b + x, w.c_s, t.junior, BOND_CAP_MAX_BPS) { continue; }
                let Some(m) = bond_shares_for_deposit(x, w.b, t.bond) else { continue };
                if m == 0 { continue; }
                let (vb, bb) = (t.bond, w.b);
                w.lp += x;
                w.v_in += x;
                w.c_b += x;
                w.b += m;
                let after = w.split();
                prop_assert_eq!(after.senior, t.senior);
                prop_assert_eq!(after.junior, t.junior, "a bond deposit is not the junior's");
                if bb > 0 { prop_assert!(ge(after.bond, bb, vb, w.b), "deposit diluted incumbents"); }
                cov.bond_deposit += 1;
            }
            Op::BondWithdraw(k) => {
                if w.b == 0 { continue; }
                let sh = w.b / 16 * k as u128 + (w.b % 16) * k as u128 / 16;
                let t = w.split();
                let cb_before = w.c_b;
                let (Some(pay), Some(cb2)) = (
                    bond_atoms_for_redemption(sh, w.b, t.bond),
                    bond_claim_after_redemption(w.c_b, sh, w.b),
                ) else {
                    continue; // fail closed on an overflowing product: nothing moves
                };
                if pay > w.lp { continue; } // vault-LP liquidity (Live exits are paid from it)
                let (vb, bb) = (t.bond, w.b);
                w.lp -= pay;
                w.bonds_paid += pay;
                w.c_b = cb2;
                w.b -= sh;
                prop_assert_eq!(w.c_b == 0, w.b == 0);
                let after = w.split();
                prop_assert!(after.senior >= t.senior, "a bond exit reached senior value");
                prop_assert!(after.junior >= t.junior, "a bond exit reached junior value");
                if w.b > 0 { prop_assert!(ge(after.bond, bb, vb, w.b), "exit diluted the remaining bonds"); }
                cov.bond_exit += 1;
                if t.bond < cb_before {
                    cov.bond_exit_impaired += 1;
                }
            }
            Op::JuniorWithdraw(x) => {
                if x > w.lp || !junior_withdraw_allowed3(w.v(), w.c_s, w.c_b, w.nav, x, floor_bps) { continue; }
                let t = w.split();
                w.lp -= x;
                w.junior_paid += x;
                let after = w.split();
                prop_assert_eq!((after.senior, after.bond), (t.senior, t.bond), "junior withdrew senior or bond value");
                if x > 0 { cov.junior_withdraw += 1; }
            }
            Op::SeniorRedeem(k) => {
                let t = w.split();
                if t.senior < w.c_s { continue; }
                let y = w.c_s / 16 * k as u128 + (w.c_s % 16) * k as u128 / 16;
                if y > w.nav { continue; }
                w.nav -= y;
                w.c_s -= y;
                w.seniors_paid += y;
                let after = w.split();
                prop_assert_eq!((after.bond, after.junior), (t.bond, t.junior), "senior exit moved subordinate value");
                if y > 0 { cov.senior_redeem += 1; }
            }
        }
        prop_assert!(w.conserved(), "conservation broke: {:?}", w);
    }
    Ok(())
}

/// v0 + everything paid in == winners + seniors + bonds + junior (paid out and held) + insurance,
/// exactly, after every step of 4,096 random sequences of up to 60 operations, with the waterfall
/// order asserted at every loss and recovery. Coverage counters must all be non-zero.
#[test]
fn g7_five_claimant_conservation_and_order() {
    use proptest::test_runner::{Config, TestRunner};
    let mut runner = TestRunner::new(Config { cases: 4_096, ..Config::default() });
    let cov = std::cell::RefCell::new(Cov::default());
    let strat = (
        (1u128..BIG, 0u128..BIG, 0u128..BIG),
        (0u16..=BOND_COUPON_MAX_BPS, 0u16..=10_000, 0u16..=10_000, 1_000u16..=10_000),
        prop::collection::vec(op(), 1..60),
    );
    runner
        .run(&strat, |((s0, j0, i0), (cp, sh, tg, fl), ops)| {
            five_claimant_case(s0, j0, i0, cp, sh, tg, fl, ops, &mut cov.borrow_mut())
        })
        .unwrap();
    let c = cov.into_inner();
    eprintln!("five-claimant coverage: {c:?}");
    for (name, n) in [
        ("junior_only_loss", c.junior_only_loss),
        ("bond_hit", c.bond_hit),
        ("senior_hit", c.senior_hit),
        ("insurance_used", c.insurance_used),
        ("haircut", c.haircut),
        ("recovery_to_seniors", c.recovery_to_seniors),
        ("recovery_to_bonds", c.recovery_to_bonds),
        ("coupon_paid", c.coupon_paid),
        ("coupon_gated_by_senior_loss", c.coupon_gated_by_senior_loss),
        ("bond_deposit", c.bond_deposit),
        ("bond_exit", c.bond_exit),
        ("bond_exit_impaired", c.bond_exit_impaired),
        ("junior_withdraw", c.junior_withdraw),
        ("senior_redeem", c.senior_redeem),
    ] {
        assert!(n > 0, "vacuous: branch `{name}` never reached");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_048, .. ProptestConfig::default() })]

    /// The explicit three-layer model (bond claim written down by every bond cover, restored
    /// second in recovery) and the lazy one agree on every layer's VALUE after any sequence of
    /// losses and recoveries.
    #[test]
    fn g7_lazy_equals_explicit_over_sequences(
        senior0 in 1u128..BIG, cb0 in 0u128..BIG, junior_pots in 0u128..BIG,
        seq in prop::collection::vec((any::<bool>(), 0u128..BIG), 1..40)
    ) {
        // Everything in the pots (vault LP at 0 value): losses draw, gains add to the pots.
        let mut nav = senior0 + cb0 + junior_pots;
        let (mut cs, mut out) = (senior0, 0u128);
        let (mut e_cs, mut e_out, mut e_cb, mut e_bout) = (senior0, 0u128, cb0, 0u128);
        for (loss, x) in seq {
            if loss {
                let s = DrawState { senior_claim: cs, outstanding: out, junior_surplus: nav.saturating_sub(cs), drawable: nav };
                let (n, moved, _jc, _bc, _sl) = draw_step3(s, cb0, x);
                // explicit: same physical move; the bond claim written down by its cover
                let es = DrawState { senior_claim: e_cs, outstanding: e_out, junior_surplus: nav.saturating_sub(e_cs), drawable: nav };
                let (en, emoved, _ejc, ebc, _esl) = draw_step3(es, e_cb, x);
                prop_assert_eq!(moved, emoved);
                nav -= moved;
                cs = n.senior_claim; out = n.outstanding;
                e_cs = en.senior_claim; e_out = en.outstanding;
                e_cb -= ebc; e_bout += ebc;
            } else {
                nav += x;
                let (c2, o2, _) = recover3(nav, cs, out, cb0);
                cs = c2; out = o2;
                // explicit: seniors first (same rule), then the bond's own outstanding
                let (ec2, eo2, _) = recover3(nav, e_cs, e_out, e_cb);
                e_cs = ec2; e_out = eo2;
                let above = nav.saturating_sub(e_cs).saturating_sub(e_cb);
                let to_b = min(above, e_bout);
                e_cb += to_b; e_bout -= to_b;
            }
            let lazy = tranche_split3(nav, cs, cb0);
            let expl = tranche_split3(nav, e_cs, e_cb);
            prop_assert_eq!((cs, out), (e_cs, e_out), "senior books identical");
            prop_assert_eq!(lazy.senior, expl.senior);
            prop_assert_eq!(lazy.bond, expl.bond);
            prop_assert_eq!(lazy.junior, expl.junior);
        }
    }
}
