//! Kani design 2026-09-30 (Sentinel) — P3 senior-draw loss rule (junior first, then seniors pro
//! rata, winners never haircut). Design doc §8, entries D-P3-20..27.
//!
//! STATUS: NOT COMPILED, NOT INCLUDED IN lib.rs. The next P3 FINAL does not exist yet. These
//! harnesses are written against the pure-function INTERFACE in §8.1 of the design doc
//! (revised per the hermetic review, doc §10). At
//! re-target, only the ADAPTER block below changes (names/argument order), then the module is
//! enabled with `#[cfg(kani)] mod proofs_senior_draw;` in lib.rs. The assertions do not change:
//! they are the loss rule stated independently of the implementation.
//!
//! Every property here is LINEAR in u128 (min / sub / add / compare): full width, no division,
//! no stubs, seconds per harness. Pro-rata per-share uniformity is a consequence of C being a
//! pooled claim over S shares (every share's claim is C/S), so "C decreases by exactly the senior
//! loss" IS the pro-rata statement; no per-share division is needed in the proof.

use crate::vault_lp_v18 as v;

// ── ADAPTER (re-target point) ───────────────────────────────────────────────────────────────
/// Draw from the senior-owned backing to cover a trading deficit `deficit` the vault LP owes,
/// after the junior surplus has absorbed what it can; `outstanding` = draw already taken for
/// this same deficit (idempotence input). Returns the atoms to move now.
fn draw_amount(deficit: u128, junior_surplus: u128, owned_backing: u128, outstanding: u128) -> u128 {
    v::vault_lp_senior_draw_amount(deficit, junior_surplus, owned_backing, outstanding)
}
/// Senior claim after the loss of a deficit `deficit` against junior surplus `junior_surplus`.
fn claim_after_loss(c: u128, deficit: u128, junior_surplus: u128) -> Option<u128> {
    v::senior_claim_after_draw(c, deficit, junior_surplus)
}
/// Recovery of `recovery` atoms with `draw_outstanding` still owed back to the seniors:
/// (to_seniors, to_junior).
fn recovery_split(recovery: u128, draw_outstanding: u128) -> (u128, u128) {
    v::vault_lp_recovery_split(recovery, draw_outstanding)
}
/// Operations that must halt while a draw is outstanding (junior withdraw, senior deposit
/// pricing, …): the predicate the processor consults.
fn halts(draw_outstanding: u128, op: u8) -> bool {
    v::vault_lp_draw_halts(draw_outstanding, op)
}
/// Draw state transition (the coordinator REQUIRED the builder's pure `vault_lp_draw_step(state,
/// deficit)`): the junior surplus is read from the STATE, never re-supplied by the caller.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DS {
    c: u128,          // senior claim
    junior: u128,     // junior surplus (V - C)+
    backing: u128,    // senior-owned backing
    drawn: u128,      // cumulative drawn for the open deficit
    deficit: u128,    // cumulative deficit booked
}
fn draw_step(s: DS, delta_deficit: u128) -> Option<DS> {
    let r = v::vault_lp_draw_step(v::VaultDrawState {
        senior_claim: s.c, junior_surplus: s.junior, owned_backing: s.backing,
        drawn: s.drawn, deficit: s.deficit,
    }, delta_deficit)?;
    Some(DS { c: r.senior_claim, junior: r.junior_surplus, backing: r.owned_backing, drawn: r.drawn, deficit: r.deficit })
}
// ────────────────────────────────────────────────────────────────────────────────────────────

/// D-P3-20  Draw bounds: draw <= remaining deficit after the junior, <= owned backing,
/// <= deficit not yet drawn; and it is exactly the covered amount when backing suffices.
#[kani::proof]
fn kani_design_p3_20_draw_bounded() {
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    let o: u128 = kani::any();
    let x = draw_amount(d, j, b, o);
    let need = d.saturating_sub(j).saturating_sub(o);
    assert!(x <= need, "never draws more than the senior share of the deficit still owed");
    assert!(x <= b, "never draws more than the backing the vault owns");
    assert_eq!(x, need.min(b), "draws exactly min(owed, owned): no under-draw");
    kani::cover!(x == need && need > 0 && need < b, "full senior share drawn");
    kani::cover!(x == b && b < need, "backing-limited draw");
    kani::cover!(d > 0 && d <= j && x == 0, "junior absorbs the whole deficit");
    // (merged from the withdrawn D-P3-21) a deficit the junior + owned backing can fund is paid in full
    if o == 0 && j.checked_add(b).map_or(true, |f| f >= d) {
        assert_eq!(d.min(j) + x, d, "fundable deficit fully covered (winners whole while J + B >= D)");
    }
    kani::cover!(o == 0 && j.checked_add(b).map_or(false, |f| f < d), "J + B < D: engine h-lock haircuts winners (claim qualified to J + B >= D)");
}

/// D-P3-22  Idempotence / split-invariance under REAL state evolution (`vault_lp_draw_step`):
/// a zero deficit step is the identity, and booking a deficit in two steps (the junior consumed
/// by the first is read from the state by the second) equals booking it in one. This is the
/// harness that sees the "re-supplied original junior surplus" over-draw by J.
#[kani::proof]
fn kani_design_p3_22_draw_step_idempotent_and_split_invariant() {
    let s = DS { c: kani::any(), junior: kani::any(), backing: kani::any(), drawn: kani::any(), deficit: kani::any() };
    assert!(draw_step(s, 0) == Some(s), "zero deficit is a no-op");
    let d1: u128 = kani::any();
    let d2: u128 = kani::any();
    kani::assume(d1.checked_add(d2).is_some());
    let one = draw_step(s, d1 + d2);
    let two = draw_step(s, d1).and_then(|m| draw_step(m, d2));
    if let (Some(a), Some(b)) = (one, two) {
        assert!(a == b, "two steps == one step");
    }
    assert_eq!(one.is_some(), two.is_some(), "fail-closed behaviour identical");
    kani::cover!(matches!(two, Some(t) if t.drawn > s.drawn) && d1 > 0 && d2 > 0, "genuinely split draw");
    kani::cover!(d1 > 0 && d1 < s.junior && d2 > s.junior, "first step inside the junior, second spills to seniors");
}

/// D-P3-23  Senior claim falls by exactly the senior loss = max(0, D − junior surplus) (the
/// pro-rata rule: every share's claim C/S falls by the same fraction), never below zero, and not
/// at all while the junior absorbs the whole deficit.
#[kani::proof]
fn kani_design_p3_23_claim_falls_by_senior_loss() {
    let c: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let r = claim_after_loss(c, d, j);
    let senior_loss = d.saturating_sub(j);
    match r {
        Some(c2) => {
            assert_eq!(c2, c.saturating_sub(senior_loss));
            assert!(c2 <= c);
            if d <= j {
                assert_eq!(c2, c, "junior-only loss leaves the senior claim intact");
            }
        }
        None => panic!("the claim update is total (saturating); None would strand the market"),
    }
    kani::cover!(matches!(r, Some(c2) if c2 < c && c2 > 0), "partial senior loss");
    kani::cover!(matches!(r, Some(0)) && c > 0, "senior wiped");
    kani::cover!(d > 0 && d <= j, "junior-only loss");
}

/// D-P3-25  Recovery ordering, OWNER RULE (2026-09-30): recovered value restores the seniors up to
/// their FULL cumulative senior loss (drawn + unfunded = C_before − C_after) before any of it
/// reaches the junior; conserves.
#[kani::proof]
fn kani_design_p3_25_recovery_restores_full_senior_loss_first() {
    let rec: u128 = kani::any();
    let c_before: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let c_after = claim_after_loss(c_before, d, j).unwrap();
    let senior_loss = c_before - c_after; // drawn + unfunded
    let (to_s, to_j) = recovery_split(rec, senior_loss);
    assert_eq!(to_s + to_j, rec);
    assert_eq!(to_s, rec.min(senior_loss));
    if to_j > 0 {
        assert_eq!(to_s, senior_loss, "junior paid only after the seniors' FULL loss is restored");
    }
    kani::cover!(to_s > 0 && to_j > 0, "seniors restored in full, remainder to junior");
    kani::cover!(to_j == 0 && rec > 0 && rec < senior_loss, "partial recovery all to seniors");
}

/// D-P3-26  Halt predicate, from the OWNER'S WRITTEN RULE (coordinator 2026-09-30): while a draw is
/// outstanding, HALT the vault LP's risk-increasing fills, junior withdraw (tag 97), junior
/// release (tag 102) and recall (tag 98, owner decision 2026-09-30); NEVER halt senior deposit (75) or senior redemption (76/77), which stay
/// open because they price at the reduced C with the undrawn deficit priced in (D-P3-28).
#[kani::proof]
fn kani_design_p3_26_halt_while_draw_outstanding() {
    let o: u128 = kani::any();
    let op: u8 = kani::any();
    let h = halts(o, op);
    let halted_class = HALTED_OPS.contains(&op);
    let senior_exit_or_entry = NEVER_HALTED_OPS.contains(&op);
    if halted_class {
        assert_eq!(h, o > 0, "risk-increasing fill / 97 / 98 / 102 halt exactly while a draw is outstanding");
    }
    if senior_exit_or_entry {
        assert!(!h, "senior deposit and redemption are never halted: seniors can always exit");
    }
    if o == 0 {
        assert!(!h, "no outstanding draw: the draw rule halts nothing");
    }
    kani::cover!(h && op == v::DRAW_OP_JUNIOR_RELEASE, "junior release halted during a draw");
    kani::cover!(h && op == v::DRAW_OP_RECALL, "recall halted during a draw");
    kani::cover!(!h && o > 0 && op == v::DRAW_OP_SENIOR_REDEEM, "senior redemption open during a draw");
    kani::cover!(!h && o > 0 && op == v::DRAW_OP_SENIOR_DEPOSIT, "senior deposit open during a draw");
}
/// Adapter (re-target point): tag-level op codes from the owner rule.
const HALTED_OPS: [u8; 4] = [v::DRAW_OP_RISK_INCREASING_FILL, v::DRAW_OP_JUNIOR_WITHDRAW /* 97 */, v::DRAW_OP_RECALL /* 98 */, v::DRAW_OP_JUNIOR_RELEASE /* 102 */];
const NEVER_HALTED_OPS: [u8; 3] = [v::DRAW_OP_SENIOR_DEPOSIT /* 75 */, v::DRAW_OP_SENIOR_REDEEM /* 77 */, v::DRAW_OP_SENIOR_REDEEM_ALT /* 76 */];

/// D-P3-28  REQUIRED (coordinator 2026-09-30: the builder must expose
/// `vault_lp_senior_pricing_claim` and 75/76/77 must price through it). Property: tags 75/77 price against a
/// claim that ALREADY nets the undrawn deficit's senior share, i.e. exactly the claim the seniors
/// will hold once the draw is booked (D-P3-23). So entering before / exiting before the booking
/// is priced identically to after it: no early-exit and no late-entry arbitrage. Combined with
/// the deposit/redemption wiring (D-P3-05/06, same claim as the senior value) and L-DIL.
#[kani::proof]
fn kani_design_p3_28_senior_pricing_includes_undrawn_deficit() {
    let c: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let priced = v::vault_lp_senior_pricing_claim(c, d, j);
    let booked = claim_after_loss(c, d, j).unwrap();
    assert_eq!(priced, booked, "pre-booking price == post-booking price (timing-neutral)");
    assert!(priced <= c, "pending loss never priced as a gain");
    kani::cover!(priced < c && d > j, "pending senior loss priced in");
    kani::cover!(priced == c && d > 0 && d <= j, "junior-only pending loss: senior price unchanged");
}

/// D-P3-27  Loss ordering end to end on the REAL waterfall: after a deficit is booked (junior
/// surplus consumed first, then the senior claim reduced), `tranche_split` of the new state gives
/// a zero junior whenever the senior was touched, and an intact senior whenever it was not.
#[kani::proof]
fn kani_design_p3_27_junior_first_then_seniors() {
    let vv: u128 = kani::any();
    let c: u128 = kani::any();
    let d: u128 = kani::any();
    kani::assume(d <= vv);
    let before = v::tranche_split(vv, c);
    let c2 = claim_after_loss(c, d, before.junior).unwrap();
    let after = v::tranche_split(vv - d, c2);
    if d > before.junior {
        assert_eq!(after.junior, 0, "senior touched only after the junior is exhausted");
    } else {
        assert_eq!(after.senior, before.senior, "junior-only loss leaves the senior whole");
    }
    kani::cover!(d > before.junior && before.junior > 0, "loss spills through the junior");
}

// ── Pending → booked draw (design change 2026-09-30) ─────────────────────────────────────────
// The crank records a PENDING draw in the market's spare per-asset wrapper bytes [832, 896);
// the C reduction and the ledger are BOOKED on the next P3 instruction (75/76/77/78/97/98/101/
// 102), and 75/77 book before pricing. The harness state below is the adapter's view of those
// bytes + the vault fields; `book` is the re-target point for `vault_lp_draw_move`.

#[derive(Clone, Copy, PartialEq, Eq)]
struct DrawState {
    c: u128,              // senior claim C
    backing_owned: u128,  // senior-owned backing
    lp_value: u128,       // vault LP value (already net of the crank-time deficit)
    pending_deficit: u128,
    pending_junior_surplus: u128, // junior surplus snapshotted at crank time
    pending: bool,
}

/// ADAPTER (re-target point): book a pending draw through the production `vault_lp_draw_move`
/// (+ `senior_claim_after_draw`, `vault_lp_senior_draw_amount`) exactly as the FINAL's booking
/// helper composes them. If the FINAL exposes the whole booking as one pure fn, call only that.
fn book(s: DrawState) -> DrawState {
    if !s.pending {
        return s;
    }
    let (backing2, lp2) = v::vault_lp_draw_move(
        s.backing_owned,
        s.lp_value,
        s.pending_deficit,
        s.pending_junior_surplus,
    );
    let c2 = claim_after_loss(s.c, s.pending_deficit, s.pending_junior_surplus).unwrap();
    DrawState { c: c2, backing_owned: backing2, lp_value: lp2, pending_deficit: 0, pending_junior_surplus: 0, pending: false }
}

fn any_pending() -> DrawState {
    let s = DrawState {
        c: kani::any(),
        backing_owned: kani::any(),
        lp_value: kani::any(),
        pending_deficit: kani::any(),
        pending_junior_surplus: kani::any(),
        pending: kani::any(),
    };
    // no u128 overflow of the vault total (processor uses checked adds)
    kani::assume(s.backing_owned.checked_add(s.lp_value).is_some());
    s
}

/// D-P3-31  Booking is conservation-preserving and idempotent: the move is internal to the vault
/// (backing + LP value unchanged), exactly the draw amount leaves the senior-owned backing, C
/// falls by exactly the senior loss, the pending record is cleared, and booking a booked state
/// changes nothing (so every one of 75/76/77/78/97/98/101/102 may call it unconditionally).
#[kani::proof]
fn kani_design_p3_31_pending_draw_booking_conserves_and_is_idempotent() {
    let s = any_pending();
    let b = book(s);
    assert_eq!(b.backing_owned + b.lp_value, s.backing_owned + s.lp_value, "draw move is internal");
    if s.pending {
        let x = draw_amount(s.pending_deficit, s.pending_junior_surplus, s.backing_owned, 0);
        assert_eq!(s.backing_owned - b.backing_owned, x, "exactly the draw leaves the backing");
        assert_eq!(b.c, s.c.saturating_sub(s.pending_deficit.saturating_sub(s.pending_junior_surplus)));
        assert!(!b.pending);
    } else {
        assert!(b == s, "nothing pending: booking is a no-op");
    }
    assert!(book(b) == b, "idempotent");
    kani::cover!(s.pending && s.backing_owned > b.backing_owned && b.c < s.c, "real draw booked");
    kani::cover!(s.pending && s.pending_deficit > 0 && s.pending_deficit <= s.pending_junior_surplus, "junior-only pending loss");
}

/// D-P3-32  Pricing between the crank-time draw and its booking equals pricing after booking,
/// through the NAV cap: senior value = min(V, C) (`tranche_split(..).senior`, the REAL waterfall).
/// With V already net of the deficit D at crank time and J the junior surplus snapshotted then,
/// min(V − D, C) == min(V − D, C − max(0, D − J)) for every state: an unbooked draw cannot be
/// front-run by any P3 instruction that prices off the waterfall.
#[kani::proof]
fn kani_design_p3_32_pricing_between_draw_and_booking_equals_after() {
    let vv: u128 = kani::any(); // vault value at crank time, before the deficit
    let c: u128 = kani::any();
    let d: u128 = kani::any();
    kani::assume(d <= vv);
    let j = v::tranche_split(vv, c).junior;
    let v_between = vv - d;
    let senior_between = v::tranche_split(v_between, c).senior;
    let c_booked = claim_after_loss(c, d, j).unwrap();
    let senior_after = v::tranche_split(v_between, c_booked).senior;
    assert_eq!(senior_between, senior_after, "NAV cap makes the unbooked draw price-neutral");
    // and the explicit pricing claim (D-P3-28) agrees with both
    assert_eq!(v::vault_lp_senior_pricing_claim(c, d, j).min(v_between), senior_after);
    kani::cover!(d > j && j > 0, "loss spills into the seniors while pending");
    kani::cover!(vv < c && d > 0, "already-impaired vault");
}

/// D-P3-29  (review M-P3-1) Atom conservation of the draw MOVE on the REAL `vault_value`: moving x
/// atoms from senior-owned backing NAV to LP capital leaves the vault value and the tranche split
/// unchanged (only the loss moves the split).
#[kani::proof]
fn kani_design_p3_29_draw_move_conserves_vault_value() {
    let nav: u128 = kani::any();
    let h: u128 = kani::any();
    let lp: u128 = kani::any();
    let x: u128 = kani::any();
    let c: u128 = kani::any();
    kani::assume(x <= nav && lp.checked_add(x).is_some());
    let v0 = v::vault_value(nav, h, lp);
    let v1 = v::vault_value(nav - x, h, lp + x);
    assert_eq!(v0, v1, "the draw move creates and destroys nothing");
    if let (Some(a), Some(b)) = (v0, v1) {
        assert!(v::tranche_split(a, c) == v::tranche_split(b, c));
    }
    kani::cover!(x > 0 && v0.is_some(), "real move");
    kani::cover!(v0.is_none(), "overflowing vault value fails closed both sides");
}

/// D-P3-30  (review M-P3-4) A draw never enlarges the recall a later (post-draw) tag 98 could make:
/// recall_limit(C', B − x) <= recall_limit(C, B), because C falls by the senior loss >= x.
#[kani::proof]
fn kani_design_p3_30_draw_never_enlarges_recall() {
    let c: u128 = kani::any();
    let b: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let x = draw_amount(d, j, b, 0);
    let c2 = claim_after_loss(c, d, j).unwrap();
    assert!(v::recall_limit(c2, b - x) <= v::recall_limit(c, b));
    kani::cover!(x > 0 && v::recall_limit(c, b) > 0, "shortfall exists and a draw happens");
}
