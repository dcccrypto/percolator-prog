//! Kani design 2026-09-30 (Sentinel, design lead) — P1 wrapper safety release, FINAL code
//! `c0ffaefa` (branch head `3acb34ae`; `src/` byte-identical outside `mod p1_kani_proofs`).
//! Design doc: ~/percolator-ops/ledger/kani-proof-design-2026-09-30.md (entries D-P1-*).
//!
//! Rules applied: every harness calls the production `percolator_prog::risk_limits_v17`
//! functions directly (no copies of processor glue); domains are the ENGINE's own bounds or
//! full width; specs are written independently of the implementation; every meaningful branch
//! has a `kani::cover!`; each harness has a planned mutation that must turn it red.
//! Run locally only: cargo kani --tests --exact --harness <name>
#![cfg(kani)]

extern crate kani;

use percolator_prog::risk_limits_v17 as p1;

const MAX_POS: u128 = percolator::MAX_POSITION_ABS_Q; // 1e14
const MAX_TRADE: u128 = percolator::MAX_TRADE_SIZE_Q; // 1e14
const MAX_PRICE: u64 = percolator::MAX_ORACLE_PRICE; // 1e12
const MAX_TVL: u128 = percolator::MAX_VAULT_TVL; // 1e16
const POS_SCALE: u128 = percolator::POS_SCALE;

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-01  Band: accepted <=> the fill lies in [ref(1-b/1e4), ref(1+b/1e4)] widened outward by
// strictly less than one atom (71da9917 round-out rule), for EVERY u64 exec / reference price
// and EVERY stored u16 band (through the processor's `effective_exec_band_bps`).
// Spec is two one-sided inequalities with no abs_diff. The product ref*band is written as the
// same expression the implementation forms (`(ref as u128) * (band as u128)`), so the solver
// shares it instead of proving two 64x16 multipliers equivalent (this is what made the earlier
// full-width attempts time out); the independent content is the interval form.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p1_band_equals_interval_full_width() {
    let exec: u64 = kani::any();
    let reference: u64 = kani::any();
    let stored: u16 = kani::any();
    let band = p1::effective_exec_band_bps(stored);
    let accepted = p1::exec_price_within_band(exec, reference, band);

    let r = reference as u128;
    let e = exec as u128;
    let p = (reference as u128) * (band as u128); // shared product term
    let above_ok = e < r || (e - r) * 10_000 <= p + 9_999;
    let below_ok = e >= r || (r - e) * 10_000 <= p + 9_999;
    let spec = reference != 0 && above_ok && below_ok;
    assert_eq!(accepted, spec);
    // strictly less than one atom of widening: any accepted fill satisfies the real-number
    // band scaled by 1e4 with slack < 1e4
    if accepted {
        let diff = if e >= r { e - r } else { r - e };
        assert!(diff * 10_000 < p + 10_000);
    }
    assert!(band >= 1 && band <= p1::MAX_EXEC_BAND_BPS);

    kani::cover!(accepted && e > r && (e - r) * 10_000 > p, "accepted only by the one-atom round-out");
    kani::cover!(!accepted && e > r && reference != 0 && (e - 1 - r) * 10_000 <= p + 9_999, "rejected exactly one atom past the last accepted price");
    kani::cover!(accepted && e < r && reference > u32::MAX as u64, "below-reference fill accepted above the u32 range");
    kani::cover!(!accepted && e < r && reference != 0, "below-band fill rejected");
    kani::cover!(stored == 0 && band == p1::DEFAULT_EXEC_BAND_BPS, "zeroed (deployed) slot gets the default band");
    kani::cover!(stored > p1::MAX_EXEC_BAND_BPS, "corrupt over-max slot is clamped");
    kani::cover!(reference == 0, "zero reference fails closed");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-02  The processor decides the LP cap with the division-free `exposure_within_cap_fast`
// (v16_program.rs:26072) and falls back to the u128 division only on `None`. Over the ENGINE
// domain the fast path is never `None` (except price 0, which fails closed): the fallback is
// dead code for every reachable state. (Already PASS 2/2 covers in 34 s as
// kani_review_p1_fast_cap_never_overflows_in_engine_domain; carried here unchanged.)
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p1_fast_cap_total_in_engine_domain() {
    let abs: u128 = kani::any();
    let equity: u128 = kani::any();
    let k: u32 = kani::any();
    let price: u64 = kani::any();
    kani::assume(abs <= MAX_POS && equity <= MAX_TVL && k <= p1::MAX_LP_EXPOSURE_K_BPS);
    kani::assume(price <= MAX_PRICE);
    let v = p1::exposure_within_cap_fast(abs, equity, k, price, POS_SCALE);
    assert_eq!(v.is_none(), price == 0);
    kani::cover!(v == Some(true) && abs > 0 && k >= 10_000 && price > 1_000_000, "within cap at a real k and price");
    kani::cover!(v == Some(false) && k >= 10_000, "over cap at a real k");
    kani::cover!(price == 0, "zero price fails closed");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-03  Post-fill gate on every route (`lp_fill_gate`, v16_program.rs:26012): for ANY cap
// (including the u128::MAX the processor passes when the fast path proved the target within
// the cap) and ANY floor flag, the gate (a) never refuses a fill that does not grow |LP|,
// (b) never admits a growing fill past the cap, (c) never admits growth of a floored LP, and
// (d) ignores the counterparty entirely (F-7: a taker "close" is not an exemption).
// Positions over the engine's full signed bound.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
fn kani_design_p1_post_fill_gate_exact() {
    let cb: i128 = kani::any();
    let ca: i128 = kani::any();
    let before: i128 = kani::any();
    let after: i128 = kani::any();
    let cap: u128 = kani::any();
    let floor: bool = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS && after.unsigned_abs() <= MAX_POS);
    let v = p1::lp_fill_gate(cb, ca, before, after, cap, floor);
    let grows = after.unsigned_abs() > before.unsigned_abs();
    // exact characterisation, stated without calling lp_risk_increasing
    let expect = if !grows {
        p1::LpGate::Allow
    } else if floor {
        p1::LpGate::FloorHalt
    } else if after.unsigned_abs() > cap {
        p1::LpGate::CapExceeded
    } else {
        p1::LpGate::Allow
    };
    assert_eq!(v, expect);
    // (d) counterparty independence: the same LP move with ANY other counterparty change
    let cb2: i128 = kani::any();
    let ca2: i128 = kani::any();
    assert_eq!(p1::lp_fill_gate(cb2, ca2, before, after, cap, floor), v);
    let taker_closes = ca == 0 && cb != 0;
    kani::cover!(taker_closes && grows && floor && v == p1::LpGate::FloorHalt, "F-7: taker close into a halted LP refused");
    kani::cover!(taker_closes && grows && !floor && v == p1::LpGate::CapExceeded, "F-7: taker close past the cap refused");
    kani::cover!(!grows && floor && before != 0 && v == p1::LpGate::Allow, "halted LP may still reduce");
    kani::cover!(grows && !floor && v == p1::LpGate::Allow && cap == u128::MAX, "fast-path u128::MAX cap admits growth");
    kani::cover!(before != 0 && after != 0 && (before > 0) != (after > 0) && !grows && v == p1::LpGate::Allow, "flip to a smaller opposite position allowed");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-04  Floored LP route (TradeCpi pre-matcher, v16_program.rs:26190-26195, then the clip at
// :14129 and the post-fill gate). Property over the REAL `floored_lp_reducing_room_q` and the
// REAL `lp_fill_gate`, with NO copy of the clip: the matcher answer validated by
// `validate_matcher_return` moves the LP by m <= |clipped request| <= room in the LP's delta
// direction, so quantifying over EVERY m <= room is a superset of what can execute.
//   (a) room == 0 exactly when the request cannot reduce the LP (processor refuses LpFloorHalt);
//   (b) for every m <= room: the LP never grows, never flips, and the post-fill gate admits;
//   (c) room == |before| when reducing (so a reduce-THROUGH-flat request is clipped to flatten,
//       P1-K1, not refused).
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
fn kani_design_p1_floored_route() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let lp_delta_sign: i8 = if size_q > 0 { -1 } else { 1 }; // processor :26180
    let room = p1::floored_lp_reducing_room_q(before, lp_delta_sign);
    let reduces = (before > 0 && lp_delta_sign < 0) || (before < 0 && lp_delta_sign > 0);
    assert_eq!(room == 0, !reduces);
    if reduces {
        assert_eq!(room, before.unsigned_abs());
    }
    kani::cover!(room == 0 && before != 0, "pure growth of a floored LP is halted pre-matcher");
    kani::cover!(room == 0 && before == 0, "flat floored LP cannot open");
    if room == 0 {
        return;
    }
    let m: u128 = kani::any();
    kani::assume(m <= room);
    let after = if lp_delta_sign > 0 { before + m as i128 } else { before - m as i128 };
    assert!(after.unsigned_abs() <= before.unsigned_abs());
    assert!(after == 0 || (after > 0) == (before > 0));
    let cap: u128 = kani::any();
    let cb: i128 = kani::any();
    let ca: i128 = kani::any();
    assert_eq!(p1::lp_fill_gate(cb, ca, before, after, cap, true), p1::LpGate::Allow);
    kani::cover!(size_q.unsigned_abs() > before.unsigned_abs() && m == room && after == 0, "reduce-through-flat clipped to flatten (P1-K1)");
    kani::cover!(m > 0 && m < room, "partial matcher fill");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-05  Healthy LP route: REAL `lp_fill_headroom_q` + REAL `lp_fill_gate(floor = false)`.
// For every cap (incl. u128::MAX) and every LP move m <= headroom in the LP's delta direction,
// the post-fill gate admits; and whenever headroom is finite and the move one past it is
// representable in the engine bound, that move is refused (tightness: the clip never
// under-grants).
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
fn kani_design_p1_healthy_route() {
    let before: i128 = kani::any();
    let cap: u128 = kani::any();
    let dir_pos: bool = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    let sign: i8 = if dir_pos { 1 } else { -1 };
    let h = p1::lp_fill_headroom_q(before, sign, cap);
    let m: u128 = kani::any();
    kani::assume(m <= h && m <= MAX_TRADE);
    let mv = |x: u128| -> i128 { if dir_pos { before + x as i128 } else { before - x as i128 } };
    assert_eq!(p1::lp_fill_gate(0, 0, before, mv(m), cap, false), p1::LpGate::Allow);
    if h < MAX_TRADE {
        let nxt = mv(h + 1);
        assert_eq!(p1::lp_fill_gate(0, 0, before, nxt, cap, false), p1::LpGate::CapExceeded);
        kani::cover!(h > 0, "finite positive headroom is tight");
    }
    kani::cover!(h == 0 && cap < before.unsigned_abs(), "over-cap LP has zero growth headroom");
    kani::cover!(before != 0 && (before > 0) != dir_pos && m > before.unsigned_abs(), "reduce-through-flip within headroom");
    kani::cover!(cap == u128::MAX && m == MAX_TRADE, "unbounded cap admits the largest trade");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-06  CloseSlab (F4) never burns an owed fee atom, full u128 (the Kani lane's
// `kani_push_p1_close_never_burns_owed_fees`, PASS 4/4, carried onto the FINAL code), plus the
// LP->insurance fold conserves the owed total exactly.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p1_close_never_burns_owed_fees() {
    let pa: u128 = kani::any();
    let pw: u128 = kani::any();
    let la: u128 = kani::any();
    let lw: u128 = kani::any();
    let ia: u128 = kani::any();
    let iw: u128 = kani::any();
    let cr: u128 = kani::any();
    let pool: u128 = kani::any();
    let owed = p1::outstanding_fee_legs(pa, pw, la, lw, ia, iw, cr);
    if pw > pa || lw > la || iw > ia {
        assert!(owed.is_none(), "corrupt withdrawn>accrued pair fails closed");
    }
    kani::cover!(owed.is_none() && pw <= pa && lw <= la && iw <= ia, "overflow fails closed");
    let Some(owed) = owed else { return };
    let refused = p1::close_refused_for_fees(owed, pool);
    if !refused {
        assert!(owed == 0 || pool == 0, "a permitted close retires no pool atom that is owed");
    } else {
        assert!(owed > 0 && pool > 0);
    }
    if let Some((lw2, ia2)) = p1::fold_lp_leg_into_insurance(la, lw, ia) {
        assert_eq!(lw2, la, "LP leg fully folded");
        if let Some(owed2) = p1::outstanding_fee_legs(pa, pw, la, lw2, ia2, iw, cr) {
            assert_eq!(owed2, owed, "fold never changes the owed total");
        }
    }
    kani::cover!(!refused && owed > 0 && pool == 0, "owed but unbacked: close allowed, nothing burned");
    kani::cover!(!refused && owed == 0 && pool > 0, "nothing owed: pool retired");
    kani::cover!(refused, "close refused");
    kani::cover!(la > lw, "fold moves a nonzero LP leg");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-07  Fee channel (P2 requested fee): consent + allocation conservation over the full
// u128 fee domain the engine hands back (builder harness used u64).
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
fn kani_design_p1_fee_channel_full_width() {
    let req: u64 = kani::any();
    let base: u64 = kani::any();
    let signed: u64 = kani::any();
    let pmax: u16 = kani::any();
    let mmax: u64 = kani::any();
    let ok = p1::requested_fee_permitted(req, base, signed, pmax, mmax);
    if req == 0 {
        assert!(ok);
    } else if ok {
        assert!(pmax != 0 && req <= pmax as u64);
        let total = base as u128 + req as u128;
        assert!(total <= signed as u128 && total <= mmax as u128);
    }
    kani::cover!(ok && req > 0, "consented request");
    kani::cover!(!ok && req > 0 && pmax != 0 && req <= pmax as u64 && base as u128 + req as u128 > signed as u128, "taker cap refuses");
    kani::cover!(!ok && base.checked_add(req).is_none(), "overflowing request refused");
    let fa: u128 = kani::any();
    let fb: u128 = kani::any();
    let owed: u128 = kani::any();
    kani::assume(fa.checked_add(fb).is_some());
    let (ba, bb, lp) = p1::allocate_fee_with_lp_request(fa, fb, owed);
    assert_eq!(ba + bb + lp, fa + fb, "every collected atom allocated exactly once");
    assert!(ba <= fa && bb <= fb && ba + bb <= owed);
    assert!(ba + bb == owed.min(fa + fb), "base covered first, as far as collected fees allow");
    kani::cover!(lp > 0 && ba + bb == owed, "LP credited beyond the base");
    kani::cover!(lp == 0 && ba + bb < owed, "shortfall: all to the base");
    kani::cover!(bb > 0 && ba == fa, "maker fallback covers the base remainder");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-08  Division lemma for the cap over the ENGINE domain (equity <= 1e16, k <= 1e7,
// 0 < price <= 1e12; numerator <= 1e29 never saturates there): `lp_exposure_cap_q` is the exact
// floor of equity*k*POS_SCALE / (1e4*price): cap*den <= num < cap*den + den. KISSAT (the only
// solver that clears 128-bit division lemmas on this box). Replaces the u16/u8-k builder
// harnesses and the 24-case saturation test as evidence for "cap at real k".
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p1_cap_exact_floor_engine_domain() {
    let equity: u128 = kani::any();
    let k: u32 = kani::any();
    let price: u64 = kani::any();
    kani::assume(equity <= MAX_TVL && k <= p1::MAX_LP_EXPOSURE_K_BPS && price > 0 && price <= MAX_PRICE);
    let cap = p1::lp_exposure_cap_q(equity, k, price, POS_SCALE);
    let num = equity * (k as u128) * POS_SCALE; // <= 1e29, no overflow
    let den = 10_000u128 * price as u128;
    let cd = cap * den; // cap <= num/den, so cap*den <= num
    assert!(cd <= num, "never over-grants");
    assert!(num - cd < den, "never under-grants by a whole unit");
    kani::cover!(cap > 0 && num % den != 0 && k >= 10_000, "non-exact floor at a real k");
    kani::cover!(cap == 0 && equity > 0 && k > 0, "positive equity rounds to a zero cap");
}

// ─────────────────────────────────────────────────────────────────────────────────────────
// D-P1-09  The processor's division-free decision agrees with the division form over the engine
// domain: exposure_within_cap_fast(abs, ..) == Some(abs <= lp_exposure_cap_q(..)). This is the
// correctness of `lp_floor_and_cap_q_for_target_view` returning u128::MAX on the fast path
// (v16_program.rs:26072-26079): the post-fill verdict is the same either way. KISSAT.
// ─────────────────────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p1_fast_cap_equals_division_engine_domain() {
    let abs: u128 = kani::any();
    let equity: u128 = kani::any();
    let k: u32 = kani::any();
    let price: u64 = kani::any();
    kani::assume(abs <= MAX_POS && equity <= MAX_TVL && k <= p1::MAX_LP_EXPOSURE_K_BPS);
    kani::assume(price > 0 && price <= MAX_PRICE);
    let fast = p1::exposure_within_cap_fast(abs, equity, k, price, POS_SCALE);
    let cap = p1::lp_exposure_cap_q(equity, k, price, POS_SCALE);
    assert_eq!(fast, Some(abs <= cap));
    kani::cover!(fast == Some(true) && abs == cap && abs > 0, "exactly at the cap");
    kani::cover!(fast == Some(false) && abs == cap + 1, "one past the cap");
}
