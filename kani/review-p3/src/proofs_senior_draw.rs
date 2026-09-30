//! Kani design 2026-09-30 (Sentinel) — P3 senior draw, RE-TARGETED to the P3 FINAL `d119eebd`
//! (`src/vault_lp_v18.rs`, path-included). Review items D-4..D-7 applied (design doc §12).
//!
//! FINAL semantics the specs are derived from (the owner rule + the fn docs, not the bodies):
//! * a draw moves `junior_cover + senior_draw` out of drawable backing into the vault LP; the
//!   junior surplus covers first; C falls by the FUNDED senior part only (an unfunded remainder is
//!   the engine's h-lock, not a senior loss) — "winners paid in full while senior backing remains";
//! * a crank records a PENDING move; `vault_lp_book_pending` books it exactly once against the
//!   current junior surplus; 75/76/77 price via `vault_lp_senior_pricing_claim`;
//! * recovery restores C from the ledger's own `outstanding` before the junior.
//! Everything here is linear u128: full width, no stubs.
//! Run: cargo kani --exact --harness proofs_senior_draw::<name>

use crate::vault_lp_v18::*;

fn min(a: u128, b: u128) -> u128 {
    if a < b { a } else { b }
}

/// D-P3-20  Draw amount: exactly min(deficit − junior share − already drawn, owned backing), so
/// never more than owed, never more than owned, never less than both; a deficit the junior plus
/// owned backing can fund is fully covered.
#[kani::proof]
fn kani_design_p3_20_draw_amount_exact() {
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    let o: u128 = kani::any();
    let x = vault_lp_senior_draw_amount(d, j, b, o);
    let owed = d.saturating_sub(min(d, j)).saturating_sub(o);
    assert!(x <= owed && x <= b);
    assert_eq!(x, min(owed, b));
    if o == 0 && j.checked_add(b).map_or(true, |f| f >= d) {
        assert_eq!(min(d, j) + x, d, "fundable deficit fully covered (winners whole while J + B >= D)");
    }
    kani::cover!(x == owed && owed > 0 && owed < b, "full senior share drawn");
    kani::cover!(x == b && b < owed, "backing-limited draw");
    kani::cover!(o == 0 && j.checked_add(b).map_or(false, |f| f < d), "J + B < D: residual left to the engine h-lock");
}

/// D-P3-21m  The physical move (D-P3-29 part 1): junior cover first; total moved never exceeds the
/// deficit or the drawable backing, and equals min(deficit, drawable).
#[kani::proof]
fn kani_design_p3_21m_draw_move_bounded_and_ordered() {
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    let (jc, sd) = vault_lp_draw_move(d, j, b);
    assert_eq!(jc, min(min(d, j), b), "junior covers first, as far as backing allows");
    assert_eq!(jc + sd, min(d, b), "moves exactly min(deficit, drawable)");
    if sd > 0 {
        assert_eq!(jc, min(d, j), "the senior part is touched only after the junior share is covered");
    }
    kani::cover!(jc > 0 && sd > 0, "junior then seniors");
    kani::cover!(jc == 0 && sd > 0 && j == 0, "no junior: all senior");
    kani::cover!(jc > 0 && sd == 0 && d <= j, "junior-only deficit");
}

/// D-P3-22 (D-4)  Step idempotence / split invariance on REACHABLE states: `s` is produced by a
/// step from a genesis state (outstanding 0). A zero deficit is the identity, and a deficit booked
/// in two steps (the second reading the junior surplus the first left) equals one step.
#[kani::proof]
fn kani_design_p3_22_draw_step_split_invariant_reachable() {
    let g = DrawState { senior_claim: kani::any(), outstanding: 0, junior_surplus: kani::any(), drawable: kani::any() };
    let d0: u128 = kani::any();
    let (s, _, _) = vault_lp_draw_step(g, d0);
    let (z, zm, zl) = vault_lp_draw_step(s, 0);
    assert!(z == s && zm == 0 && zl == 0, "zero deficit is a no-op");
    let d1: u128 = kani::any();
    let d2: u128 = kani::any();
    kani::assume(d1.checked_add(d2).is_some());
    let (one, m, l) = vault_lp_draw_step(s, d1 + d2);
    let (a, m1, l1) = vault_lp_draw_step(s, d1);
    let (two, m2, l2) = vault_lp_draw_step(a, d2);
    assert!(one == two, "two steps == one step");
    assert_eq!(m1 + m2, m);
    assert_eq!(l1 + l2, l);
    kani::cover!(m1 > 0 && m2 > 0 && l2 > 0 && a.junior_surplus == 0 && s.junior_surplus > 0, "first step eats the junior, second hits seniors");
}

/// D-P3-23  Claim falls by exactly the FUNDED senior draw, never below 0; untouched while the
/// junior covers; outstanding rises by exactly that loss; junior surplus and drawable fall by what
/// was moved.
#[kani::proof]
fn kani_design_p3_23_step_claim_falls_by_funded_senior_draw() {
    let s = DrawState { senior_claim: kani::any(), outstanding: kani::any(), junior_surplus: kani::any(), drawable: kani::any() };
    let d: u128 = kani::any();
    let (n, moved, loss) = vault_lp_draw_step(s, d);
    let (jc, sd) = vault_lp_draw_move(d, s.junior_surplus, s.drawable);
    assert_eq!(moved, jc + sd);
    assert_eq!(n.senior_claim, s.senior_claim.saturating_sub(sd), "C falls by the funded senior draw only");
    assert_eq!(loss, s.senior_claim - n.senior_claim);
    assert_eq!(n.outstanding, s.outstanding.saturating_add(loss));
    assert_eq!(n.junior_surplus, s.junior_surplus - jc);
    assert_eq!(n.drawable, s.drawable - moved);
    if d <= s.junior_surplus {
        assert_eq!(n.senior_claim, s.senior_claim, "junior-only deficit leaves C intact");
    }
    if loss > 0 {
        assert!(n.junior_surplus == 0 || jc < min(d, s.junior_surplus), "D-P3-27: seniors only after the junior share");
    }
    kani::cover!(loss > 0 && loss < s.senior_claim, "partial senior loss");
    kani::cover!(n.senior_claim == 0 && s.senior_claim > 0, "seniors wiped");
    kani::cover!(d > 0 && d <= s.junior_surplus && moved == d, "junior-only");
}

/// D-P3-25 (D-5)  Recovery on the LEDGER's own outstanding: seniors restored first up to
/// `outstanding`, the rest is junior; C + outstanding conserved; drawn and pending untouched.
#[kani::proof]
fn kani_design_p3_25_recover_seniors_first_from_ledger() {
    let l = DrawLedger { senior_claim: kani::any(), drawn: kani::any(), outstanding: kani::any(), pending: kani::any() };
    kani::assume(l.outstanding <= l.drawn); // documented reachable-state invariant
    kani::assume(l.senior_claim.checked_add(l.outstanding).is_some());
    let v: u128 = kani::any();
    let (n, to_s) = vault_lp_recover(l, v);
    assert_eq!(to_s, min(v, l.outstanding));
    assert_eq!(n.senior_claim + n.outstanding, l.senior_claim + l.outstanding, "C + outstanding conserved");
    assert!(n.drawn == l.drawn && n.pending == l.pending);
    assert!(n.outstanding <= n.drawn, "invariant preserved");
    if v > l.outstanding {
        assert_eq!(n.outstanding, 0, "junior gets value only after the seniors are fully restored");
    }
    kani::cover!(v > l.outstanding && l.outstanding > 0, "seniors restored in full, remainder to junior");
    kani::cover!(v > 0 && v < l.outstanding, "partial recovery all to seniors");
}

/// D-P3-26  Halt predicate (owner rule): outstanding draw halts risk-increasing vault-LP fills, 97,
/// 98 and 102; never 75/76/77; nothing halts with no outstanding draw.
#[kani::proof]
fn kani_design_p3_26_draw_halts_owner_rule() {
    let o: u128 = kani::any();
    let op: u8 = kani::any();
    let h = vault_lp_draw_halts(o, op);
    let halted = op == DRAW_OP_LP_RISK_INCREASING_FILL || op == DRAW_OP_JUNIOR_WITHDRAW_97
        || op == DRAW_OP_RECALL_98 || op == DRAW_OP_JUNIOR_RELEASE_102;
    let open = op == DRAW_OP_SENIOR_DEPOSIT_75 || op == DRAW_OP_SENIOR_REQUEST_76 || op == DRAW_OP_SENIOR_REDEEM_77;
    if halted {
        assert_eq!(h, o > 0);
    }
    if open || o == 0 {
        assert!(!h);
    }
    kani::cover!(h && op == DRAW_OP_RECALL_98, "recall halted during a draw");
    kani::cover!(!h && o > 0 && op == DRAW_OP_SENIOR_REDEEM_77, "redemption open during a draw");
    kani::cover!(!h && o > 0 && op == DRAW_OP_SENIOR_REQUEST_76, "redeem request open during a draw");
}

/// D-P3-28  75/76/77 pricing == the claim after the pending move is booked (production pricing fn
/// vs production booking fn), and never above C: no early-exit / late-entry timing trade.
#[kani::proof]
fn kani_design_p3_28_pricing_claim_equals_booked_claim() {
    let l = DrawLedger { senior_claim: kani::any(), drawn: kani::any(), outstanding: kani::any(), pending: kani::any() };
    let j: u128 = kani::any();
    let priced = vault_lp_senior_pricing_claim(l.senior_claim, l.pending, j);
    let (booked, _) = vault_lp_book_pending(l, j);
    assert_eq!(priced, booked.senior_claim);
    assert!(priced <= l.senior_claim);
    kani::cover!(priced < l.senior_claim, "pending senior loss priced in");
    kani::cover!(l.pending > 0 && l.pending <= j && priced == l.senior_claim, "junior-only pending loss");
}

/// D-P3-29  Atom conservation of the move on the REAL `vault_value`: moving the drawn atoms from
/// backing NAV to LP capital changes neither the vault value nor the tranche split.
#[kani::proof]
fn kani_design_p3_29_draw_move_conserves_vault_value() {
    let nav: u128 = kani::any();
    let h: u128 = kani::any();
    let lp: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let c: u128 = kani::any();
    let (jc, sd) = vault_lp_draw_move(d, j, nav);
    let x = jc + sd;
    kani::assume(lp.checked_add(x).is_some());
    let v0 = vault_value(nav, h, lp);
    let v1 = vault_value(nav - x, h, lp + x);
    assert_eq!(v0, v1);
    if let (Some(a), Some(b)) = (v0, v1) {
        assert!(tranche_split(a, c) == tranche_split(b, c));
    }
    kani::cover!(x > 0 && v0.is_some(), "real move");
}

/// D-P3-30  A draw never enlarges the recall a later tag 98 could make:
/// recall_limit(C', B − moved) <= recall_limit(C, B).
/// PRE-RUN FINDING (design lead, by hand): a JUNIOR-covered move lowers backing without lowering
/// C, so when backing < C + junior surplus this goes RED — e.g. C=100, J=50, B=80, D=50:
/// moved 50 (all junior), C'=100, recall 20 -> 70. Kept as designed so the run records it; the
/// owner must decide (halt recall while ANY draw/pending exists, or make reachable backing >= C+J).
#[kani::proof]
fn kani_design_p3_30_draw_never_enlarges_recall() {
    let s = DrawState { senior_claim: kani::any(), outstanding: kani::any(), junior_surplus: kani::any(), drawable: kani::any() };
    let d: u128 = kani::any();
    let (n, moved, _) = vault_lp_draw_step(s, d);
    assert!(recall_limit(n.senior_claim, s.drawable - moved) <= recall_limit(s.senior_claim, s.drawable));
    kani::cover!(moved > 0 && recall_limit(s.senior_claim, s.drawable) > 0, "shortfall exists and a draw happens");
}

/// D-P3-31 (D-6)  The ONE production booking fn: pending 0 is the identity; otherwise pending is
/// booked exactly once (pending' = 0, a second booking is the identity), C + outstanding is
/// conserved, drawn rises by exactly the booked senior loss, and `outstanding <= drawn` holds.
#[kani::proof]
fn kani_design_p3_31_book_pending_once_and_conserving() {
    let l = DrawLedger { senior_claim: kani::any(), drawn: kani::any(), outstanding: kani::any(), pending: kani::any() };
    kani::assume(l.outstanding <= l.drawn); // documented reachable-state invariant
    kani::assume(l.senior_claim.checked_add(l.outstanding).is_some() && l.drawn.checked_add(l.senior_claim).is_some());
    let j: u128 = kani::any();
    let (b, loss) = vault_lp_book_pending(l, j);
    if l.pending == 0 {
        assert!(b == l && loss == 0);
    } else {
        assert_eq!(b.pending, 0);
        assert_eq!(b.senior_claim + b.outstanding, l.senior_claim + l.outstanding, "C + outstanding conserved");
        assert_eq!(b.drawn, l.drawn + loss);
        assert_eq!(loss, l.senior_claim - b.senior_claim);
    }
    assert!(b.outstanding <= b.drawn, "invariant preserved");
    let (b2, loss2) = vault_lp_book_pending(b, j);
    assert!(b2 == b && loss2 == 0, "booking is idempotent");
    kani::cover!(l.pending > 0 && loss > 0, "pending senior loss booked");
    kani::cover!(l.pending > 0 && loss == 0, "junior-covered pending booked");
}

/// D-P3-13b  Bound-vault NAV (`bound_vault_nav`, the fn production calls; `combined_nav` is no
/// longer called): per pot the vault counts min(principal, held) — never backing above principal
/// (reserved for winners) — plus the earnings; overflow fails closed.
#[kani::proof]
fn kani_design_p3_13b_bound_vault_nav() {
    let p0: u128 = kani::any();
    let h0: u128 = kani::any();
    let p1: u128 = kani::any();
    let h1: u128 = kani::any();
    let e0: u128 = kani::any();
    let e1: u128 = kani::any();
    let r = bound_vault_nav(p0, h0, p1, h1, e0, e1);
    let a = min(p0, h0).checked_add(min(p1, h1));
    let n = a.and_then(|a| e0.checked_add(e1).and_then(|e| a.checked_add(e)));
    match r {
        Some((avail, nav)) => {
            assert_eq!(Some(avail), a);
            assert_eq!(Some(nav), n);
        }
        None => assert!(n.is_none(), "fails closed only on overflow"),
    }
    kani::cover!(matches!(r, Some(_)) && h0 > p0 && p0 > 0, "backing above principal not counted");
    kani::cover!(matches!(r, Some(_)) && h1 < p1, "impaired pot counted at what it holds");
    kani::cover!(r.is_none(), "overflow fails closed");
}
