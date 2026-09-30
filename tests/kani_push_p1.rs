//! Kani push 2026-09-30 (Anvil, formal-verification lane) — P1 wrapper safety release,
//! re-targeted at P1 >= c0ffaefa (F-7) / 71da9917 (band edge rounds out) / 6066399f (P1-K1).
//!
//! Complements the builder's `p1_kani_proofs::kani_p1_*` (in the lib). These state the P1
//! rules against independent formulations and through the COMPOSED gates:
//!  - band edge rounding: completeness, at most one atom of slack, band 0 exact, monotone;
//!  - same-owner rule: a taker close is never refused, any open/grow/flip is;
//!  - F-7: the LP gate's verdict does not depend on the counterparty's direction;
//!  - headroom -> TradeCpi clip -> any matcher answer -> post-fill gate never exceeds the cap;
//!  - a floored LP never grows; every LP-reducing request (incl. through flat) is admitted
//!    pre-matcher and clipped to flatten (P1-K1 fix);
//!  - the cap fast path (`exposure_within_cap_fast` -> cap = u128::MAX) gives the same gate
//!    verdict as the real cap;
//!  - CloseSlab never burns an owed fee atom.
//!
//! The TradeCpi pre-matcher block (`p1_cpi_preflight_before_matcher`) is private and reads
//! AccountInfos; its arithmetic is MIRRORED below on top of the real pub predicates. Every
//! harness declares covers (placed BEFORE the asserts); SUCCESSFUL counts only with every cover
//! SATISFIED. Local only, never CI:  cargo kani --tests --harness kani_push_p1
#![cfg(kani)]

extern crate kani;

use percolator_prog::risk_limits_v17 as p1;
use p1::LpGate;

const POS_SCALE: u128 = percolator::POS_SCALE;
const MAX_POS: u128 = percolator::MAX_POSITION_ABS_Q;
const MAX_TRADE: u128 = percolator::MAX_TRADE_SIZE_Q;

// ── mirrors of the private pre-matcher block (v16_program.rs, p1_cpi_preflight_before_matcher
//    + the TradeCpi clip right after it) ─────────────────────────────────────────────────────

/// Ok(headroom) or Err(()) = LpFloorHalt. `size_q` is the TAKER's signed request.
fn pre_matcher_room(before: i128, size_q: i128, floored: bool, cap: u128) -> Result<u128, ()> {
    let lp_delta_sign: i8 = if size_q > 0 { -1 } else { 1 };
    if floored {
        let room = p1::floored_lp_reducing_room_q(before, lp_delta_sign);
        if room == 0 {
            return Err(());
        }
        return Ok(room);
    }
    Ok(p1::lp_fill_headroom_q(before, lp_delta_sign, cap))
}

fn clip(size_q: i128, room: u128) -> i128 {
    if size_q.unsigned_abs() > room {
        let c = room as i128;
        if size_q > 0 {
            c
        } else {
            -c
        }
    } else {
        size_q
    }
}

fn any_matcher_fill(req: i128) -> i128 {
    let exec_abs: u128 = kani::any();
    kani::assume(exec_abs <= req.unsigned_abs());
    if req > 0 {
        exec_abs as i128
    } else {
        -(exec_abs as i128)
    }
}

// ── Item 1: band edge rounding (71da9917) ───────────────────────────────────────────────

/// accepted <=> ref > 0 and diff <= ceil(ref*band/1e4), stated as: every fill inside the exact
/// real band is accepted (completeness); an accepted fill is at most ONE atom outside the exact
/// real band; band 0 admits only the exact reference; widening the band never rejects.
/// The product `ref*band` and `diff*1e4` are written exactly as the implementation writes them
/// so CBMC shares the multipliers (independent forms of the same claim timed out >30 min).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_band_edge_rounding() {
    let exec: u64 = kani::any();
    let reference: u64 = kani::any();
    let stored: u16 = kani::any();
    let band = p1::effective_exec_band_bps(stored);
    let accepted = p1::exec_price_within_band(exec, reference, band);
    let diff = exec.abs_diff(reference) as u128;
    let d4 = diff * 10_000;
    let rb = (reference as u128) * (band as u128);
    kani::cover!(accepted && d4 > rb, "accepted inside the one-atom rounding slack");
    kani::cover!(!accepted && reference != 0 && d4 >= rb + 10_000, "rejected just past the slack");
    kani::cover!(stored == 0 && accepted && diff > 0, "default band admits an off-reference fill");
    if reference == 0 {
        assert!(!accepted);
    } else {
        assert!(d4 > rb || accepted); // completeness
        assert!(!accepted || d4 < rb + 10_000); // at most one atom of slack
    }
    if band == 0 && accepted {
        assert_eq!(exec, reference);
    }
}

/// Monotone in band (separate harness: two calls of the multiplier-heavy predicate).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_band_monotone_in_band() {
    let exec: u64 = kani::any();
    let reference: u64 = kani::any();
    let b1: u16 = kani::any();
    let b2: u16 = kani::any();
    kani::assume(b1 <= b2);
    let a1 = p1::exec_price_within_band(exec, reference, b1);
    let a2 = p1::exec_price_within_band(exec, reference, b2);
    kani::cover!(!a1 && a2, "wider band admits more");
    assert!(!a1 || a2);
}

// ── Item 2: same-owner rule with the reduce-only exemption (2e7f87de) ─────────────────────

/// The item-2 condition in the preflight is `(owners_equal || taker_is_creator) &&
/// !position_change_reduce_only(before, after)` -> SameOwnerTrade. So a same-owner / creator
/// taker is NEVER refused for a close (flat, or same side no larger), and ALWAYS refused for an
/// open, a growth, or a flip.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_same_owner_close_never_refused() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS && size_q.unsigned_abs() <= MAX_TRADE);
    let after = before + size_q;
    let reduce_only = p1::position_change_reduce_only(before, after);
    let refused = !reduce_only; // with owners_equal || creator
    let is_close = after == 0
        || (before != 0 && (after > 0) == (before > 0) && after.unsigned_abs() <= before.unsigned_abs());
    let opens_grows_or_flips = after != 0
        && (before == 0 || (after > 0) != (before > 0) || after.unsigned_abs() > before.unsigned_abs());
    kani::cover!(before > 0 && after > 0 && after < before, "partial close allowed");
    kani::cover!(before > 0 && after < 0, "flip refused");
    kani::cover!(before == 0 && after != 0, "open refused");
    assert_eq!(is_close, !opens_grows_or_flips);
    if is_close {
        assert!(!refused);
    } else {
        assert!(refused);
    }
}

// ── F-7 (c0ffaefa): the LP gate ignores the counterparty's direction ──────────────────────

#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_lp_gate_ignores_counterparty() {
    let cb1: i128 = kani::any();
    let ca1: i128 = kani::any();
    let cb2: i128 = kani::any();
    let ca2: i128 = kani::any();
    let lb: i128 = kani::any();
    let la: i128 = kani::any();
    let cap: u128 = kani::any();
    let floored: bool = kani::any();
    let g1 = p1::lp_fill_gate(cb1, ca1, lb, la, cap, floored);
    let g2 = p1::lp_fill_gate(cb2, ca2, lb, la, cap, floored);
    let grows = la.unsigned_abs() > lb.unsigned_abs();
    kani::cover!(
        p1::position_change_reduce_only(cb1, ca1) && ca1 != cb1 && grows && la.unsigned_abs() > cap && !floored,
        "taker close that would dump risk past the LP cap"
    );
    kani::cover!(p1::position_change_reduce_only(cb1, ca1) && grows && floored, "taker close into a halted LP");
    assert_eq!(g1, g2);
    if !grows {
        assert_eq!(g1, LpGate::Allow);
    } else if floored {
        assert_eq!(g1, LpGate::FloorHalt);
    } else if la.unsigned_abs() > cap {
        assert_eq!(g1, LpGate::CapExceeded);
    } else {
        assert_eq!(g1, LpGate::Allow);
    }
}

// ── Items 3+4+5 composed ───────────────────────────────────────────────────────────────

/// CAP RESPECTED AFTER ANY FILL: healthy LP, any request, any cap, any matcher answer the
/// wrapper admits -> the post-fill gate (the REAL `lp_fill_gate`) allows it, i.e. the clip alone
/// already keeps the LP inside max(cap, |before|); the clip never grows or flips the request.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_clip_then_any_matcher_fill_respects_cap() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    let cap: u128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let room = pre_matcher_room(before, size_q, false, cap).unwrap();
    let req = clip(size_q, room);
    let exec = any_matcher_fill(req);
    let after = before - exec;
    kani::cover!(req == 0, "zero-fill instead of revert");
    kani::cover!(req != 0 && req != size_q, "partial clip");
    kani::cover!(after.unsigned_abs() > before.unsigned_abs() && after.unsigned_abs() == cap, "grows exactly to the cap");
    kani::cover!(before != 0 && after != 0 && (after > 0) != (before > 0), "flip within cap");
    assert_eq!(p1::lp_fill_gate(0, 0, before, after, cap, false), LpGate::Allow);
    assert!(req.unsigned_abs() <= size_q.unsigned_abs());
    assert!(req == 0 || (req > 0) == (size_q > 0));
}

/// AUTO-HALT 1: a floored LP never grows through the pre-matcher gate + clip + any matcher fill.
/// (Stronger than "the post gate would catch it": the clip alone already prevents growth.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_floored_lp_never_grows() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let r = pre_matcher_room(before, size_q, true, 0);
    kani::cover!(r.is_err(), "pre-matcher halt fires");
    let Ok(room) = r else { return };
    let req = clip(size_q, room);
    let exec = any_matcher_fill(req);
    let after = before - exec;
    kani::cover!(after == 0 && exec != 0, "floored LP flattened");
    assert!(!p1::lp_risk_increasing(before, after));
    assert!(after == 0 || (after > 0) == (before > 0)); // clipped to flatten: never flips
    assert_eq!(p1::lp_fill_gate(0, 0, before, after, 0, true), LpGate::Allow);
}

/// AUTO-HALT 2 (P1-K1 regression, was a FAILING claim test on db2c1505..7f33bfb3): for a
/// floored LP, EVERY request whose full fill would reduce |LP| — including a flip to a smaller
/// opposite position — is admitted pre-matcher (no LpFloorHalt) and is clipped to flatten.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_floored_pre_gate_admits_every_reducing_request() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let after_full = before - size_q;
    let reducing = !p1::lp_risk_increasing(before, after_full);
    let r = pre_matcher_room(before, size_q, true, 0);
    kani::cover!(reducing && after_full != 0 && (after_full > 0) != (before > 0), "reducing flip-through request");
    kani::cover!(!reducing && r.is_err(), "growth refused");
    if reducing {
        assert!(r.is_ok());
        let req = clip(size_q, r.unwrap());
        assert_eq!(before - req == 0, size_q.unsigned_abs() >= before.unsigned_abs());
    }
}

/// AUTO-HALT 3: a fill that does not grow the LP is never refused by the post-fill gate, for
/// any floor / cap / counterparty.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_reducing_fill_never_refused_post_fill() {
    let before: i128 = kani::any();
    let after: i128 = kani::any();
    let floored: bool = kani::any();
    let cap: u128 = kani::any();
    let cb: i128 = kani::any();
    let ca: i128 = kani::any();
    kani::assume(after.unsigned_abs() <= before.unsigned_abs());
    kani::cover!(floored && after.unsigned_abs() < before.unsigned_abs(), "floored, reducing");
    kani::cover!(floored && before != 0 && after != 0 && (after > 0) != (before > 0), "floored, smaller flip");
    assert_eq!(p1::lp_fill_gate(cb, ca, before, after, cap, floored), LpGate::Allow);
}

/// CAP FAST PATH: when `exposure_within_cap_fast(target, ..) == Some(true)` the processor uses
/// cap = u128::MAX instead of dividing. For every LP move whose |after| <= target, the gate
/// verdict with u128::MAX equals the verdict with the real `lp_exposure_cap_q`. Price is the
/// constant $1 (1e6) so the 128-bit division is by a constant (symbolic divisors time out).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_cap_fast_path_same_verdict() {
    let equity: u32 = kani::any();
    let k: u16 = kani::any();
    let target: u64 = kani::any();
    let before: i64 = kani::any();
    let after: i64 = kani::any();
    let price: u64 = 1_000_000;
    kani::assume(after.unsigned_abs() <= target);
    let fast = p1::exposure_within_cap_fast(target as u128, equity as u128, k as u32, price, POS_SCALE);
    kani::cover!(fast == Some(true) && after.unsigned_abs() > before.unsigned_abs(), "fast path on a growing fill");
    if fast == Some(true) {
        let real_cap = p1::lp_exposure_cap_q(equity as u128, k as u32, price, POS_SCALE);
        let g_fast = p1::lp_fill_gate(0, 0, before as i128, after as i128, u128::MAX, false);
        let g_real = p1::lp_fill_gate(0, 0, before as i128, after as i128, real_cap, false);
        assert_eq!(g_fast, g_real);
    }
}

// ── F4: CloseSlab never burns an owed fee atom (close_refused_for_fees, 4fe62cda) ──────────

#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p1_close_never_burns_owed_fees() {
    let pa: u128 = kani::any();
    let pw: u128 = kani::any();
    let la: u128 = kani::any();
    let lw: u128 = kani::any();
    let ia: u128 = kani::any();
    let iw: u128 = kani::any();
    let cr: u128 = kani::any();
    let pool: u128 = kani::any();
    let Some(owed) = p1::outstanding_fee_legs(pa, pw, la, lw, ia, iw, cr) else {
        kani::cover!(true, "corrupt pair fails closed");
        return;
    };
    let refused = p1::close_refused_for_fees(owed, pool);
    kani::cover!(!refused && owed > 0 && pool == 0, "owed but unbacked: close allowed, nothing burned");
    kani::cover!(!refused && owed == 0 && pool > 0, "nothing owed: pool retired");
    kani::cover!(refused, "close refused");
    if !refused {
        assert_eq!(core::cmp::min(owed, pool), 0);
    }
    if let Some((lw2, ia2)) = p1::fold_lp_leg_into_insurance(la, lw, ia) {
        if let Some(owed2) = p1::outstanding_fee_legs(pa, pw, la, lw2, ia2, iw, cr) {
            assert_eq!(owed2, owed);
        }
    }
}
