//! Kani design 2026-09-30 (Sentinel) — P3 senior-draw loss rule (junior first, then seniors pro
//! rata, winners never haircut). Design doc §8, entries D-P3-20..27.
//!
//! STATUS: NOT COMPILED, NOT INCLUDED IN lib.rs. The next P3 FINAL does not exist yet. These
//! harnesses are written against the pure-function INTERFACE in §8.1 of the design doc. At
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
}

/// D-P3-21  Conservation: junior cover + senior draw + unfunded remainder == deficit, and the
/// winners' payout (junior cover + draw) is never less than the deficit whenever the junior
/// surplus plus owned backing can fund it ("winners never haircut").
#[kani::proof]
fn kani_design_p3_21_draw_conserves_and_winners_whole() {
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    let x = draw_amount(d, j, b, 0);
    let junior_cover = d.min(j);
    let unfunded = d - junior_cover - x;
    assert_eq!(junior_cover + x + unfunded, d);
    if j.checked_add(b).map_or(true, |f| f >= d) {
        assert_eq!(unfunded, 0, "fundable deficit is paid in full");
    }
    kani::cover!(junior_cover > 0 && x > 0 && unfunded == 0, "junior then seniors, paid in full");
    kani::cover!(unfunded > 0, "backing exhausted: residual reported, not haircut from winners");
}

/// D-P3-22  Idempotence: a second application for the same deficit, after the first draw is
/// recorded as outstanding, draws nothing more; and splitting one deficit into two draws draws
/// the same total as one draw.
#[kani::proof]
fn kani_design_p3_22_draw_idempotent_and_split_invariant() {
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    let x1 = draw_amount(d, j, b, 0);
    let x2 = draw_amount(d, j, b - x1, x1);
    assert_eq!(x2, 0, "re-running the draw for the same deficit is a no-op");
    let d1: u128 = kani::any();
    kani::assume(d1 <= d);
    let a = draw_amount(d1, j, b, 0);
    let c = draw_amount(d, j, b - a, a);
    assert_eq!(a + c, x1, "draw in two steps == draw in one");
    kani::cover!(x1 > 0 && a > 0 && c > 0, "genuinely split draw");
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

/// D-P3-24  Draw and claim agree: the claim the seniors lose equals the senior share of the
/// deficit (drawn + unfunded), so no senior value is created or destroyed by the pair of updates.
#[kani::proof]
fn kani_design_p3_24_draw_and_claim_consistent() {
    let c: u128 = kani::any();
    let d: u128 = kani::any();
    let j: u128 = kani::any();
    let b: u128 = kani::any();
    kani::assume(d.saturating_sub(j) <= c); // loss within the claim (else D-P3-23's saturation)
    let x = draw_amount(d, j, b, 0);
    let c2 = claim_after_loss(c, d, j).unwrap();
    let unfunded = d - d.min(j) - x;
    assert_eq!(c - c2, x + unfunded);
    kani::cover!(x > 0 && unfunded == 0, "fully drawn");
}

/// D-P3-25  Recovery ordering: recovered value restores the seniors (repays the outstanding
/// draw) before any of it reaches the junior; conserves.
#[kani::proof]
fn kani_design_p3_25_recovery_seniors_first() {
    let rec: u128 = kani::any();
    let o: u128 = kani::any();
    let (to_s, to_j) = recovery_split(rec, o);
    assert_eq!(to_s + to_j, rec);
    assert_eq!(to_s, rec.min(o));
    if to_j > 0 {
        assert_eq!(to_s, o, "junior paid only after the seniors are restored in full");
    }
    kani::cover!(to_s > 0 && to_j > 0, "seniors restored, remainder to junior");
    kani::cover!(to_j == 0 && rec > 0, "all to seniors");
}

/// D-P3-26  Halt predicate: while any draw is outstanding every halted operation halts, and with
/// none outstanding nothing is halted by the draw rule.
#[kani::proof]
fn kani_design_p3_26_halt_while_draw_outstanding() {
    let o: u128 = kani::any();
    let op: u8 = kani::any();
    let h = halts(o, op);
    // The halted set is fixed by §8.1 (junior withdraw, senior deposit, senior redemption at a
    // stale price); `HALTED_OPS` is the adapter's list.
    let in_set = HALTED_OPS.contains(&op);
    assert_eq!(h, o > 0 && in_set);
    kani::cover!(h, "halted while a draw is outstanding");
    kani::cover!(!h && o > 0, "an unaffected op proceeds during a draw");
    kani::cover!(!h && o == 0 && in_set, "no draw: nothing halted");
}
/// Adapter: the op codes §8.1 requires to halt (re-target point).
const HALTED_OPS: [u8; 3] = [v::VAULT_OP_JUNIOR_WITHDRAW, v::VAULT_OP_SENIOR_DEPOSIT, v::VAULT_OP_SENIOR_REDEEM];

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
