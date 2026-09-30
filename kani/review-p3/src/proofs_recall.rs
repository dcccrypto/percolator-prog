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

/// D-P3-33c (review §11 revision)  The retired D-P3-30 stated on the FIXED code: right after ANY
/// draw step (junior-covered or senior), the vault LP's certified equity is `moved − deficit`
/// (the deficit is −certified_equity, per `vault_lp_senior_draw_amount`'s doc), so the recall tag 98
/// allows — `vault_lp_recall_limit` over the REAL `recall_limit` of the post-draw state — is 0,
/// whatever the raw shortfall became and whether or not a draw is pending.
#[kani::proof]
fn kani_design_p3_33c_no_recall_right_after_any_draw() {
    let s = DrawState { senior_claim: kani::any(), outstanding: kani::any(), junior_surplus: kani::any(), drawable: kani::any() };
    let d: u128 = kani::any();
    kani::assume(d <= i128::MAX as u128);
    let (n, moved, _) = vault_lp_draw_step(s, d);
    let e: i128 = moved as i128 - d as i128; // moved <= d, so e <= 0
    let pending: bool = kani::any();
    let raw = recall_limit(n.senior_claim, s.drawable - moved);
    let r = vault_lp_recall_limit(raw, e, pending);
    assert_eq!(r, 0, "no recall can re-open a deficit a draw just funded");
    kani::cover!(!pending && moved > 0 && moved == d && raw > 0, "fully funded draw, shortfall exists, still no recall");
    kani::cover!(raw > recall_limit(s.senior_claim, s.drawable) && !pending, "raw shortfall grew (old D-P3-30 case) yet no recall");
}
