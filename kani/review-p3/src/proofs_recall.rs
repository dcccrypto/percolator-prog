//! Kani design 2026-09-30 (Sentinel) — D-P3-33, the recall gate (D-P3-30 retired into it), on the
//! P3 FINAL `39b138c8`: `vault_lp_recall_limit(existing_limit, lp_equity, draw_pending)`
//! (`src/vault_lp_v18.rs`). Tag 98 (`v16_program.rs:28345-28365`) calls it with
//! existing_limit = `recall_limit(c_eff, cover)`, lp_equity = the refreshed certified equity and
//! draw_pending = any of pending_moved / pending_out_even / pending_out_odd read before booking.
//! Owner rule: a recall never takes certified LP equity below 0 (never re-opens a funded deficit)
//! and none runs while a draw is pending. Linear, full width, 15 min.
//! Planned mutations: M1 drop the equity cap; M2 drop the pending halt.
use crate::vault_lp_v18::*;

#[kani::proof]
fn kani_design_p3_33_recall_capped_by_lp_equity_and_halted_while_pending() {
    let existing: u128 = kani::any();
    let e: i128 = kani::any();
    let pending: bool = kani::any();
    let r = vault_lp_recall_limit(existing, e, pending);
    let eq_pos: u128 = if e > 0 { e as u128 } else { 0 };
    assert!(r <= eq_pos, "recall never takes certified LP equity below 0");
    assert!(r <= existing, "never more than the pre-existing senior shortfall limit");
    if pending {
        assert_eq!(r, 0, "no recall while a draw is pending");
    } else {
        assert_eq!(r, existing.min(eq_pos), "otherwise exactly min(shortfall limit, positive equity)");
    }
    kani::cover!(!pending && r > 0 && r == eq_pos && eq_pos < existing, "equity cap binds");
    kani::cover!(!pending && r > 0 && r == existing && existing < eq_pos, "shortfall limit binds");
    kani::cover!(pending && existing > 0 && eq_pos > 0, "pending draw halts a would-be recall");
    kani::cover!(!pending && e < 0 && existing > 0, "negative LP equity: nothing recalled");
}

/// D-P3-33c  The composition tag 98 actually evaluates, on the REAL `recall_limit` as the
/// existing limit: after ANY draw step (including a junior-covered one — the retired D-P3-30
/// counterexample C=100, J=50, B=80, D=50), the recall allowed is bounded by the LP's positive
/// certified equity, whatever the raw shortfall became.
#[kani::proof]
fn kani_design_p3_33c_recall_after_any_draw_bounded_by_equity() {
    let s = DrawState { senior_claim: kani::any(), outstanding: kani::any(), junior_surplus: kani::any(), drawable: kani::any() };
    let d: u128 = kani::any();
    let (n, moved, _) = vault_lp_draw_step(s, d);
    let e: i128 = kani::any();
    let pending: bool = kani::any();
    let r = vault_lp_recall_limit(recall_limit(n.senior_claim, s.drawable - moved), e, pending);
    let eq_pos: u128 = if e > 0 { e as u128 } else { 0 };
    assert!(r <= eq_pos);
    kani::cover!(!pending && moved > 0 && r > 0, "recall after a draw, within equity");
    kani::cover!(recall_limit(n.senior_claim, s.drawable - moved) > recall_limit(s.senior_claim, s.drawable) && r <= eq_pos, "raw shortfall grew (old D-P3-30 case) yet recall stays within equity");
}
