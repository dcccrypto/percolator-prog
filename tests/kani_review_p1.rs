//! Adversarial Kani review 2026-09-30 (Sentinel) — stronger P1 proofs.
//!
//! The builder's `p1_kani_proofs` narrowed the band and cap harnesses to u32 / u16 / u8
//! (3acb34ae) so CBMC would finish. At u8 `k_bps` (<= 255 bps) the cap proofs exclude EVERY
//! real exposure multiplier (the default is `1e8 / imr_bps` >= 10_000 bps). These harnesses
//! re-state the same properties over the ENGINE'S OWN DOMAIN instead:
//!   price  <= MAX_ORACLE_PRICE (1e12), |position| <= MAX_POSITION_ABS_Q (1e14),
//!   equity <= MAX_VAULT_TVL (1e16),   k <= MAX_LP_EXPOSURE_K_BPS (1e7).
//! Where a symbolic multiplier is what stops CBMC, the harness is split per concrete band /
//! k value (one harness per value, so every multiply is by a constant) rather than narrowing
//! the symbolic prices.
//!
//! Composed-gate harnesses call the REAL `risk_limits_v17` predicates. The TradeCpi clip is
//! three lines inside the processor (`v16_program.rs` ~14129) and is mirrored verbatim; that
//! mirror is the only non-production code on the path and is labelled as such.
//!
//! Every harness has covers; a SUCCESSFUL verdict counts only with every cover SATISFIED.
//! Local only (never CI): cargo kani --tests --exact --harness <name>
#![cfg(kani)]

extern crate kani;

use percolator_prog::risk_limits_v17 as p1;

const POS_SCALE: u128 = percolator::POS_SCALE;
const MAX_POS: u128 = percolator::MAX_POSITION_ABS_Q;
const MAX_TRADE: u128 = percolator::MAX_TRADE_SIZE_Q;
const MAX_PRICE: u64 = percolator::MAX_ORACLE_PRICE;
const MAX_TVL: u128 = percolator::MAX_VAULT_TVL;

// ─────────────────────────────────────────────────────────────────────────────
// Item 1 — band, FULL u64 prices, one harness per concrete band.
// Spec is independent of the implementation (no abs_diff; two one-sided inequalities):
// accepted <=> ref > 0 && exec lies in [ref(1 - b/1e4), ref(1 + b/1e4)] widened OUTWARD by
// strictly less than one atom (the documented "edge rounds out to the next atom" rule,
// 71da9917): 1e4*exec <= ref*(1e4+b) + 9999 and 1e4*exec + ref*b + 9999 >= 1e4*ref.
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn band_spec(exec: u64, reference: u64, band: u128) -> bool {
    let e = exec as u128 * 10_000;
    let r = reference as u128;
    reference != 0 && e <= r * (10_000 + band) + 9_999 && e + r * band + 9_999 >= r * 10_000
}

macro_rules! band_full_width {
    ($name:ident, $band:expr) => {
        #[kani::proof]
        #[kani::solver(cadical)]
        fn $name() {
            let exec: u64 = kani::any();
            let reference: u64 = kani::any();
            const B: u16 = $band;
            let accepted = p1::exec_price_within_band(exec, reference, B);
            assert_eq!(accepted, band_spec(exec, reference, B as u128));
            // No fill more than one atom outside the real-number band is ever accepted.
            if accepted {
                let diff = exec.abs_diff(reference) as u128;
                assert!(diff * 10_000 < reference as u128 * B as u128 + 10_000);
            }
            kani::cover!(accepted && exec > reference, "above-reference fill accepted");
            kani::cover!(accepted && exec < reference, "below-reference fill accepted");
            kani::cover!(!accepted && reference != 0, "rejected");
            kani::cover!(reference > u32::MAX as u64 && accepted && exec != reference,
                "accepted above the u32 domain the builder proof covers");
        }
    };
}
band_full_width!(kani_review_p1_band_u64_b0, 0);
band_full_width!(kani_review_p1_band_u64_b1, 1);
band_full_width!(kani_review_p1_band_u64_b500_default, 500);
band_full_width!(kani_review_p1_band_u64_b9999, 9_999);
band_full_width!(kani_review_p1_band_u64_b10000_max, 10_000);

/// The effective band the processor applies, for EVERY stored u16 (exhaustive).
#[kani::proof]
fn kani_review_p1_effective_band_total() {
    let stored: u16 = kani::any();
    let b = p1::effective_exec_band_bps(stored);
    assert!(b >= 1 && b <= p1::MAX_EXEC_BAND_BPS);
    if stored == 0 {
        assert_eq!(b, p1::DEFAULT_EXEC_BAND_BPS);
    } else if stored <= p1::MAX_EXEC_BAND_BPS {
        assert_eq!(b, stored);
    } else {
        assert_eq!(b, p1::MAX_EXEC_BAND_BPS);
    }
    kani::cover!(stored > p1::MAX_EXEC_BAND_BPS, "corrupt slot clamped");
}

// ─────────────────────────────────────────────────────────────────────────────
// Item 3 — the division-free cap check the processor actually decides with
// (`exposure_within_cap_fast`, v16_program.rs ~26072), over the ENGINE domain.
// ─────────────────────────────────────────────────────────────────────────────

/// In the engine domain the fast path NEVER overflows (so the u128-division fallback is dead
/// code for every reachable state) and zero price is the only `None`.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_review_p1_fast_cap_never_overflows_in_engine_domain() {
    let abs: u128 = kani::any();
    let equity: u128 = kani::any();
    let k: u32 = kani::any();
    let price: u64 = kani::any();
    kani::assume(abs <= MAX_POS && equity <= MAX_TVL && k <= p1::MAX_LP_EXPOSURE_K_BPS);
    kani::assume(price <= MAX_PRICE);
    let v = p1::exposure_within_cap_fast(abs, equity, k, price, POS_SCALE);
    assert_eq!(v.is_none(), price == 0);
    kani::cover!(v == Some(true) && abs > 0 && price > 1_000_000, "within cap, real price");
    kani::cover!(v == Some(false) && k >= 10_000, "over cap at a real k");
}

/// Per concrete real k (so the equity·k multiply is by a constant): the fast verdict is
/// monotone — smaller |position|, more equity, lower price never turns "within" into "over".
macro_rules! fast_cap_monotone {
    ($name:ident, $k:expr) => {
        #[kani::proof]
        #[kani::solver(cadical)]
        fn $name() {
            const K: u32 = $k;
            let a1: u128 = kani::any();
            let a2: u128 = kani::any();
            let e1: u128 = kani::any();
            let e2: u128 = kani::any();
            let p1_: u64 = kani::any();
            let p2_: u64 = kani::any();
            kani::assume(a1 <= MAX_POS && a2 <= a1);
            kani::assume(e2 <= MAX_TVL && e1 <= e2);
            kani::assume(p1_ <= MAX_PRICE && p2_ <= p1_ && p2_ > 0);
            let x = p1::exposure_within_cap_fast(a1, e1, K, p1_, POS_SCALE).unwrap();
            let y = p1::exposure_within_cap_fast(a2, e2, K, p2_, POS_SCALE).unwrap();
            if x {
                assert!(y);
            }
            kani::cover!(x && a1 > 0, "non-trivial position within cap");
            kani::cover!(!x && y, "monotone step across the cap");
        }
    };
}
fast_cap_monotone!(kani_review_p1_fast_cap_monotone_k1x, 10_000);
fast_cap_monotone!(kani_review_p1_fast_cap_monotone_k10x, 100_000);
fast_cap_monotone!(kani_review_p1_fast_cap_monotone_kmax, 10_000_000);

/// Saturation edge at FULL u128 equity (the builder's version is 24 concrete cases): for the
/// max k and a unit price, cap(e) <= cap(e+1) for every u128 e, and the saturation branch is
/// hit exactly at the numerator overflow.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_review_p1_cap_saturation_full_u128_equity() {
    let e: u128 = kani::any();
    kani::assume(e < u128::MAX);
    const K: u32 = p1::MAX_LP_EXPOSURE_K_BPS;
    let c0 = p1::lp_exposure_cap_q(e, K, 1, POS_SCALE);
    let c1 = p1::lp_exposure_cap_q(e + 1, K, 1, POS_SCALE);
    assert!(c0 <= c1);
    let overflows = e.checked_mul(K as u128).and_then(|v| v.checked_mul(POS_SCALE)).is_none();
    assert_eq!(c0 == u128::MAX, overflows);
    kani::cover!(!overflows && e > u64::MAX as u128, "unsaturated above u64");
    kani::cover!(overflows && e.checked_sub(1).map_or(false, |p| p
        .checked_mul(K as u128)
        .and_then(|v| v.checked_mul(POS_SCALE))
        .is_some()), "first saturated equity");
}

// ─────────────────────────────────────────────────────────────────────────────
// Items 4 + 5 composed, on the REAL predicates (replaces the Kani lane's stale mirror of the
// pre-6066399f floored branch). Only the TradeCpi clip is mirrored (verbatim, ~14129).
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of the TradeCpi clip (v16_program.rs ~14129-14139).
fn trade_cpi_clip(size_q: i128, lp_headroom_q: u128) -> i128 {
    if size_q.unsigned_abs() > lp_headroom_q {
        let clipped = lp_headroom_q as i128;
        if size_q > 0 {
            clipped
        } else {
            -clipped
        }
    } else {
        size_q
    }
}

/// FLOORED LP (P1-K1 regression + auto-halt), real `floored_lp_reducing_room_q` and real
/// post-fill `lp_fill_gate`: (a) a request is refused pre-matcher iff it cannot reduce the
/// LP; (b) every reducing request (including one that would flip through flat) is clipped,
/// not refused; (c) after ANY matcher fill `validate_matcher_return` admits (same sign,
/// |exec| <= |clipped|), the LP never grows and the post-fill gate never refuses.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_review_p1_floored_route_real_predicates() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let lp_delta_sign: i8 = if size_q > 0 { -1 } else { 1 };
    let room = p1::floored_lp_reducing_room_q(before, lp_delta_sign);
    let reduces_at_all = (before > 0 && lp_delta_sign < 0) || (before < 0 && lp_delta_sign > 0);
    // (a) processor: `if room == 0 { return Err(LpFloorHalt) }`
    assert_eq!(room == 0, !reduces_at_all);
    kani::cover!(room == 0, "pure growth halted");
    if room == 0 {
        return;
    }
    let req = trade_cpi_clip(size_q, room);
    // (b) never refused, never flipped, never grown
    assert!(req != 0 && (req > 0) == (size_q > 0) && req.unsigned_abs() <= size_q.unsigned_abs());
    let exec_abs: u128 = kani::any();
    kani::assume(exec_abs <= req.unsigned_abs());
    let exec: i128 = if req > 0 { exec_abs as i128 } else { -(exec_abs as i128) };
    let after = before - exec;
    // (c) the floored LP never grows and never flips
    assert!(!p1::lp_risk_increasing(before, after));
    assert!(after == 0 || (after > 0) == (before > 0));
    let cap: u128 = kani::any();
    assert_eq!(p1::lp_fill_gate(0, 0, before, after, cap, true), p1::LpGate::Allow);
    kani::cover!(size_q.unsigned_abs() > before.unsigned_abs() && after == 0,
        "reduce-through-flat request clipped to flatten (P1-K1)");
    kani::cover!(exec_abs < req.unsigned_abs() && exec_abs > 0, "partial matcher fill");
}

/// HEALTHY LP, real `lp_fill_headroom_q` + real post-fill `lp_fill_gate` (floor = false):
/// after the clip, ANY admitted matcher fill passes the post-fill gate under the same cap.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_review_p1_healthy_route_real_predicates() {
    let before: i128 = kani::any();
    let size_q: i128 = kani::any();
    let cap: u128 = kani::any();
    // cap unbounded on purpose: the processor passes u128::MAX when the fast path proves
    // the target within the cap (~26079).
    kani::assume(before.unsigned_abs() <= MAX_POS);
    kani::assume(size_q != 0 && size_q.unsigned_abs() <= MAX_TRADE);
    let lp_delta_sign: i8 = if size_q > 0 { -1 } else { 1 };
    let room = p1::lp_fill_headroom_q(before, lp_delta_sign, cap);
    let req = trade_cpi_clip(size_q, room);
    assert!(req.unsigned_abs() <= size_q.unsigned_abs());
    assert!(req == 0 || (req > 0) == (size_q > 0));
    let exec_abs: u128 = kani::any();
    kani::assume(exec_abs <= req.unsigned_abs());
    let exec: i128 = if req > 0 { exec_abs as i128 } else { -(exec_abs as i128) };
    let after = before - exec;
    assert_eq!(p1::lp_fill_gate(0, 0, before, after, cap, false), p1::LpGate::Allow);
    kani::cover!(req == 0, "zero headroom: zero-fill");
    kani::cover!(req != 0 && req != size_q, "partial clip");
    kani::cover!(p1::lp_risk_increasing(before, after) && after.unsigned_abs() == cap,
        "grows exactly to the cap");
}
