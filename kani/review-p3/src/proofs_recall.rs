//! Kani design 2026-09-30 (Sentinel) — D-P3-33: recall (tag 98) after the D-P3-30 program fix
//! (owner decision): recall never takes vault-LP certified equity below 0, and is 0 while a draw
//! is PENDING. NOT BUILT until the new P3 FINAL exposes `vault_lp_recall_limit(state, lp_equity)`;
//! at re-target only the ADAPTER changes. Linear, full width, 15 min.
//! Planned mutation: drop the equity cap (return the plain shortfall) — must red.
use crate::vault_lp_v18::*;

// ── ADAPTER (re-target point) ────────────────────────────────────────────────────────────────
/// The recall the processor would make: (senior claim, owned backing, pending draw, LP equity).
fn recall(c: u128, backing: u128, pending: u128, lp_equity: i128) -> u128 {
    vault_lp_recall_limit(
        RecallState { senior_claim: c, owned_backing: backing, pending_draw: pending },
        lp_equity,
    )
}
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[kani::proof]
fn kani_design_p3_33_recall_capped_by_lp_equity_and_halted_while_pending() {
    let c: u128 = kani::any();
    let b: u128 = kani::any();
    let p: u128 = kani::any();
    let e: i128 = kani::any();
    let r = recall(c, b, p, e);
    let eq_pos: u128 = if e > 0 { e as u128 } else { 0 };
    assert!(r <= eq_pos, "recall never takes certified LP equity below 0");
    assert!(r <= recall_limit(c, b), "never more than the senior shortfall");
    if p > 0 {
        assert_eq!(r, 0, "no recall while a draw is pending");
    }
    if p == 0 {
        assert_eq!(r, recall_limit(c, b).min(eq_pos), "otherwise exactly min(shortfall, positive equity)");
    }
    kani::cover!(p == 0 && r > 0 && r == eq_pos && eq_pos < recall_limit(c, b), "equity cap binds");
    kani::cover!(p == 0 && r > 0 && r == recall_limit(c, b), "shortfall fully recalled");
    kani::cover!(p > 0 && recall_limit(c, b) > 0 && eq_pos > 0, "pending draw halts a would-be recall");
    kani::cover!(p == 0 && e < 0 && recall_limit(c, b) > 0, "negative LP equity: nothing recalled");
}
