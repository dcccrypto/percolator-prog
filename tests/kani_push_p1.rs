//! Kani push 2026-09-30 (Anvil, formal-verification lane) — P1 wrapper safety release.
//!
//! Complements the builder's `kani_p1_*` harnesses in `tests/v16_kani.rs`. Those check the
//! `risk_limits_v17` predicates against their own formulas; the harnesses here check them
//! against an INDEPENDENT formulation (interval form, real-number floor, composed pre- and
//! post-matcher gates) and at FULL width (u128 equity, i128 positions up to the engine's own
//! bounds), which is where rounding-direction and overflow bugs live.
//!
//! Every harness declares `kani::cover!`s; a SUCCESSFUL verdict counts only if every one is
//! SATISFIED. Each has a negative control recorded in
//! `~/percolator-ops/ledger/kani-results-2026-09-30.md`.
//!
//! Run locally only (never CI):  cargo kani --tests --harness kani_push_p1
#![cfg(kani)]

extern crate kani;

use percolator_prog::risk_limits_v17 as p1;

const POS_SCALE: u128 = percolator::POS_SCALE;
const MAX_POS: u128 = percolator::MAX_POSITION_ABS_Q;
const MAX_TRADE: u128 = percolator::MAX_TRADE_SIZE_Q;

// ─────────────────────────────────────────────────────────────────────────────
// Item 1 — price band. No fill outside the band, for ANY mark, exec price and stored band.
// ─────────────────────────────────────────────────────────────────────────────

/// Independent spec: the fill is accepted iff `ref > 0` and exec lies in the closed real
/// interval `[ref·(1 − b/1e4), ref·(1 + b/1e4)]`, written without `abs_diff` as two
/// one-sided inequalities scaled by 1e4 (exact in u128). Band = the EFFECTIVE band the
/// processor applies to ANY stored value (so a zeroed deployed slot, a max slot and a
/// corrupt over-max slot are all covered).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_band_equals_real_interval_for_any_stored_band() {
    let exec: u64 = kani::any();
    let reference: u64 = kani::any();
    let stored: u16 = kani::any();
    let band = p1::effective_exec_band_bps(stored) as u128;
    let accepted = p1::exec_price_within_band(exec, reference, band as u16);

    let e = exec as u128 * 10_000;
    let lo_ok = e + reference as u128 * band >= reference as u128 * 10_000; // e >= ref(1e4-b)
    let hi_ok = e <= reference as u128 * (10_000 + band);
    let spec = reference != 0 && lo_ok && hi_ok;
    assert_eq!(accepted, spec);

    // The effective band is never wider than 100% and a zeroed slot gets the 5% default.
    assert!(band <= p1::MAX_EXEC_BAND_BPS as u128);
    if stored == 0 {
        assert_eq!(band, p1::DEFAULT_EXEC_BAND_BPS as u128);
    }
    // No accepted fill is ever priced at 0 (a band < 100% cannot reach 0; at exactly 100%
    // the interval's lower end IS 0, so the processor relies on the engine's exec>0 check).
    if accepted && band < 10_000 {
        assert!(exec > 0);
    }

    kani::cover!(accepted && exec as u128 * 10_000 == reference as u128 * (10_000 + band) && band > 0,
        "accepted exactly on the upper edge");
    kani::cover!(accepted && e + reference as u128 * band == reference as u128 * 10_000 && band > 0,
        "accepted exactly on the lower edge");
    kani::cover!(!accepted && reference != 0 && e == reference as u128 * (10_000 + band) + 1,
        "rejected one e-4 atom above the upper edge");
    kani::cover!(stored == 0 && !accepted && reference != 0, "default band rejects");
    kani::cover!(stored > p1::MAX_EXEC_BAND_BPS, "corrupt over-max slot is clamped");
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 3 — exposure cap arithmetic, full width.
// ─────────────────────────────────────────────────────────────────────────────

/// `lp_exposure_cap_q` is exactly the real floor of `equity·k·POS_SCALE / (1e4·price)` when it
/// does not saturate (cap·den <= num < (cap+1)·den), never panics for ANY u128 equity / u32 k /
/// u64 price, saturates only when the numerator genuinely overflows u128, and fails closed at
/// price 0.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_exposure_cap_is_exact_floor_full_width() {
    let equity: u128 = kani::any();
    let k: u32 = kani::any();
    let price: u64 = kani::any();
    let cap = p1::lp_exposure_cap_q(equity, k, price, POS_SCALE);
    if price == 0 {
        assert_eq!(cap, 0);
        return;
    }
    let den = 10_000u128 * price as u128;
    match equity.checked_mul(k as u128).and_then(|v| v.checked_mul(POS_SCALE)) {
        None => {
            assert_eq!(cap, u128::MAX);
            kani::cover!(true, "saturation path");
        }
        Some(num) => {
            // lower bound: cap·den <= num (never over-grants)
            let lhs = cap.checked_mul(den);
            assert!(lhs.is_some() && lhs.unwrap() <= num);
            // tightness: (cap+1)·den > num (never under-grants by a whole unit)
            match (cap + 1).checked_mul(den) {
                Some(v) => assert!(v > num),
                None => {} // (cap+1)·den > u128::MAX >= num
            }
            kani::cover!(cap > 0 && num % den != 0, "non-exact floor");
            kani::cover!(cap == 0 && equity > 0 && k > 0, "positive equity rounds to 0");
        }
    }
}

/// Monotone in equity and k, antitone in price, at full width (the builder's version bounds
/// equity to u64).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_exposure_cap_monotone_full_width() {
    let e1: u128 = kani::any();
    let e2: u128 = kani::any();
    let k1: u32 = kani::any();
    let k2: u32 = kani::any();
    let p1_: u64 = kani::any();
    let p2_: u64 = kani::any();
    kani::assume(e1 <= e2 && k1 <= k2 && p1_ >= p2_ && p2_ > 0);
    let a = p1::lp_exposure_cap_q(e1, k1, p1_, POS_SCALE);
    let b = p1::lp_exposure_cap_q(e2, k2, p2_, POS_SCALE);
    assert!(a <= b);
    kani::cover!(a < b && b < u128::MAX, "strict, unsaturated");
    kani::cover!(a < b && b == u128::MAX, "one side saturated");
}

// ─────────────────────────────────────────────────────────────────────────────
// Items 3+4+5 — composed gates. The TradeCpi pre-matcher gate
// (`lp_trade_headroom_before_matcher`, v16_program.rs) is private and reads AccountInfos, so
// its arithmetic is MIRRORED here line for line on top of the real pub predicates. The
// mirror is the weak point of this proof: if the processor changes, this must too.
// Recommendation to the builder: extract the pure core as `risk_limits_v17::pre_matcher_room`.
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of `lp_trade_headroom_before_matcher` after the reads: Ok(room) or Err(()) for
/// LpFloorHalt. `size_q` is the TAKER's signed request.
fn pre_matcher_room(before: i128, size_q: i128, floored: bool, cap: u128) -> Result<u128, ()> {
    let lp_delta_sign: i8 = if size_q > 0 { -1 } else { 1 };
    if floored {
        let room = p1::lp_fill_headroom_q(before, lp_delta_sign, 0);
        let room = room.min(before.unsigned_abs());
        if size_q.unsigned_abs() > room {
            return Err(());
        }
        return Ok(room);
    }
    Ok(p1::lp_fill_headroom_q(before, lp_delta_sign, cap))
}

/// Mirror of the TradeCpi clip right after it.
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

/// Mirror of `ensure_lp_limits_after_fill_view` after the reads: true = Ok.
fn post_fill_ok(before: i128, after: i128, floored_after: bool, cap_after: u128) -> bool {
    if !p1::lp_risk_increasing(before, after) {
        return true;
    }
    if floored_after {
        return false;
    }
    p1::lp_exposure_allowed(before, after, cap_after)
}

/// CAP RESPECTED AFTER ANY FILL. For any engine-bounded LP position, any taker request, any
/// cap, and ANY matcher answer the wrapper's `validate_matcher_return` admits (same sign,
/// |exec| <= |clipped request|), the LP's post-fill position satisfies the exposure predicate
/// under the same cap — i.e. the clip alone already makes the post-fill check pass, so a
/// healthy LP never turns an over-headroom request into Custom(49)/68.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_clip_then_any_matcher_fill_respects_cap() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    let cap: u128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let room = pre_matcher_room(before, size_q, false, cap).unwrap();
    let req = clip(size_q, room);
    // matcher answer admitted by validate_matcher_return
    let exec_abs: u128 = kani::any();
    kani::assume(exec_abs <= req.unsigned_abs());
    let exec: i128 = if req > 0 { exec_abs as i128 } else { -(exec_abs as i128) };
    let after = before - exec; // LP takes the opposite side of the taker
    assert!(p1::lp_exposure_allowed(before, after, cap));
    assert!(post_fill_ok(before, after, false, cap));
    // the clip never grows or flips the request
    assert!(req.unsigned_abs() <= size_q.unsigned_abs());
    assert!(req == 0 || (req > 0) == (size_q > 0));

    kani::cover!(req == 0, "zero-fill instead of revert");
    kani::cover!(req != 0 && req != size_q, "partial clip");
    kani::cover!(p1::lp_risk_increasing(before, after) && after.unsigned_abs() == cap,
        "grows exactly to the cap");
    kani::cover!(before != 0 && (after > 0) != (before > 0) && after != 0, "flip within cap");
}

/// AUTO-HALT, part 1: while the LP is floored (before AND after the fill), NO fill that passes
/// both gates grows the LP's exposure — for any request and any matcher answer.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_floored_lp_never_grows() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    let cap: u128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let Ok(room) = pre_matcher_room(before, size_q, true, cap) else {
        kani::cover!(true, "pre-matcher halt fires");
        return;
    };
    let req = clip(size_q, room);
    let exec_abs: u128 = kani::any();
    kani::assume(exec_abs <= req.unsigned_abs());
    let exec: i128 = if req > 0 { exec_abs as i128 } else { -(exec_abs as i128) };
    let after = before - exec;
    if post_fill_ok(before, after, true, cap) {
        assert!(!p1::lp_risk_increasing(before, after));
        assert!(after.unsigned_abs() <= before.unsigned_abs());
        kani::cover!(after.unsigned_abs() < before.unsigned_abs(), "floored LP reduces");
    }
}

/// AUTO-HALT, part 2: a risk-REDUCING fill is never refused by the post-fill gate, whatever
/// the floor / cap / equity (the builder's predicate proof covers this for `lp_floor_halts`
/// alone; this is the composed post-fill gate).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_reducing_fill_never_refused_post_fill() {
    let before: i128 = kani::any();
    let after: i128 = kani::any();
    let floored: bool = kani::any();
    let cap: u128 = kani::any();
    kani::assume(after.unsigned_abs() <= before.unsigned_abs());
    assert!(post_fill_ok(before, after, floored, cap));
    kani::cover!(floored && after.unsigned_abs() < before.unsigned_abs(), "floored, reducing");
    kani::cover!(floored && before != 0 && after != 0 && (after > 0) != (before > 0),
        "floored, flip to a smaller opposite position");
}

/// AUTO-HALT, part 3 — the PRE-matcher gate. Claim under test: "risk-reducing fills are never
/// halted" also holds BEFORE the matcher: for a floored LP, a taker request whose full fill
/// would REDUCE |LP position| (including a flip to a smaller opposite position) is not refused
/// with LpFloorHalt.
///
/// EXPECTED TO FAIL on db2c1505 — recorded as a finding, not a proof bug: the floored branch
/// grants only `min(room, |before|)` (reduce to flat) and REFUSES the whole request when it is
/// larger, instead of clipping. A taker closing 150 against a floored LP holding -100 gets
/// LpFloorHalt, although the fill would leave the LP at +50 (less exposure).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_floored_pre_gate_admits_every_reducing_request() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let after_full = before - size_q;
    let reducing = !p1::lp_risk_increasing(before, after_full);
    let r = pre_matcher_room(before, size_q, true, 0);
    // covers BEFORE the assert: a failing assert prunes every path after it.
    kani::cover!(reducing && after_full != 0 && (after_full > 0) != (before > 0),
        "reducing flip-through request");
    kani::cover!(reducing && r.is_err(), "reducing request refused (the finding)");
    if reducing {
        assert!(r.is_ok());
    }
}

/// Bounded fallback of the full-width floor proof (u64 equity, u32 price) so a verdict exists
/// even if the u128 x u64 division does not finish on this machine.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_exposure_cap_is_exact_floor_u64() {
    let equity: u64 = kani::any();
    let k: u32 = kani::any();
    let price: u32 = kani::any();
    kani::assume(price > 0);
    let cap = p1::lp_exposure_cap_q(equity as u128, k, price as u64, POS_SCALE);
    let den = 10_000u128 * price as u128;
    let num = equity as u128 * k as u128 * POS_SCALE; // < 2^64 * 2^32 * 2^20: fits
    kani::cover!(cap > 0 && num % den != 0, "non-exact floor");
    kani::cover!(cap == 0 && equity > 0 && k > 0, "positive equity rounds to 0");
    assert!(cap * den <= num);
    assert!((cap + 1) * den > num);
}

// ─────────────────────────────────────────────────────────────────────────────
// F4 — CloseSlab never burns an owed fee atom (rule as of 4fe62cda: refuse iff
// min(outstanding, unbudgeted_pool) > 0), full u128.
// ─────────────────────────────────────────────────────────────────────────────

/// If CloseSlab proceeds, the atoms it retires (the whole unbudgeted pool) and the atoms still
/// owed (every fee leg) are disjoint: either nothing is owed or there is nothing to burn. And
/// the terminal LP->staker fold never changes the owed total (so re-booking cannot turn a
/// refused close into a permitted one).
#[kani::proof]
#[kani::solver(cadical)]
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
        let burned_owed = core::cmp::min(owed, pool);
        assert_eq!(burned_owed, 0);
    }
    if let Some((lw2, ia2)) = p1::fold_lp_leg_into_insurance(la, lw, ia) {
        if let Some(owed2) = p1::outstanding_fee_legs(pa, pw, la, lw2, ia2, iw, cr) {
            assert_eq!(owed2, owed);
        }
    }
}

/// u32-price companion of `kani_push_p1_band_equals_real_interval_for_any_stored_band` (same
/// assertions; the band arithmetic is scale-invariant, and u32 e6 prices reach $4,294).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_band_equals_real_interval_u32() {
    let exec: u32 = kani::any();
    let reference: u32 = kani::any();
    let stored: u16 = kani::any();
    let band = p1::effective_exec_band_bps(stored) as u128;
    let accepted = p1::exec_price_within_band(exec as u64, reference as u64, band as u16);
    let e = exec as u128 * 10_000;
    let r = reference as u128;
    let spec = reference != 0 && e + r * band >= r * 10_000 && e <= r * (10_000 + band);
    kani::cover!(accepted && e == r * (10_000 + band) && band > 0, "upper edge accepted");
    kani::cover!(accepted && e + r * band == r * 10_000 && band > 0, "lower edge accepted");
    kani::cover!(!accepted && reference != 0 && e == r * (10_000 + band) + 1, "just above rejected");
    kani::cover!(stored > p1::MAX_EXEC_BAND_BPS, "corrupt slot clamped");
    assert_eq!(accepted, spec);
    assert!(band <= p1::MAX_EXEC_BAND_BPS as u128);
}

/// u16-price companion (fallback if the u32 multiplier circuits do not finish): same
/// statement, arithmetic in u64 (no u128 multipliers in the spec side).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_push_p1_band_equals_real_interval_u16() {
    let exec: u16 = kani::any();
    let reference: u16 = kani::any();
    let stored: u16 = kani::any();
    let band = p1::effective_exec_band_bps(stored) as u64;
    let accepted = p1::exec_price_within_band(exec as u64, reference as u64, band as u16);
    let e = exec as u64 * 10_000;
    let r = reference as u64;
    let spec = reference != 0 && e + r * band >= r * 10_000 && e <= r * (10_000 + band);
    kani::cover!(accepted && e == r * (10_000 + band) && band > 0, "upper edge accepted");
    kani::cover!(accepted && e + r * band == r * 10_000 && band > 0, "lower edge accepted");
    kani::cover!(!accepted && reference != 0 && e == r * (10_000 + band) + 1, "just above rejected");
    assert_eq!(accepted, spec);
}
