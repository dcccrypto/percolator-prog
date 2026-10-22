//! Kani harnesses: v2.2 continuous leverage curve + continuous stress cap (2026-10-19).
//! Design, review and results: ledger v22-continuous-leverage-build-2026-10-19.md §10.
//!
//! Every harness calls the PRODUCTION functions of `growth_v19`. The two nonlinear kernels are
//! proved once and then replaced, in the composite harnesses, by MODELS that assume only the
//! proven properties (a model allows every function with those properties, so it is sound to
//! replace the real one by it):
//! * `log2_frac_q16` (16 chained 64-bit squarings): monotone and `< 2^16` on its domain
//!   `[2^31, 2^32)` (exhaustive native check, `contlev_exhaustive` E1); the in-loop `m < 2^32`
//!   (no wrap) invariant is `kani_contlev_log2_frac_core` + E1 (debug assertions on).
//! * `log2_q16`: monotone, integer part exact, `None` iff 0 (`kani_contlev_log2_monotone`).
//! * `curve_interp` = `floor(span * num / den)` (`kani_contlev_interp_facts` + E2/E3): `<= span`,
//!   0 at `num = 0`, `span` at `num = den`, monotone in `num`, monotone and 1-Lipschitz in `span`.
//! The models are RECORDING models: each call returns a fresh `kani::any()` constrained against
//! every earlier call (same input -> same output, plus the order facts), so the model is any
//! function with the proven properties, consistent across all calls of the harness.
//! Every harness carries `kani::cover!`s; a verdict counts only with every cover SATISFIED.

use crate::growth_v19::*;

// ── recording model of `log2_frac_q16`: any monotone map [2^31, 2^32) -> [0, 2^16) ──────────
const FR_CAP: usize = 4;
static mut FR_N: usize = 0;
static mut FR_M: [u64; FR_CAP] = [0; FR_CAP];
static mut FR_R: [u32; FR_CAP] = [0; FR_CAP];

fn frac_model(m: u64) -> u32 {
    // the caller's obligation: a normalised Q.31 mantissa (also proves `m < 2^32` on entry, the
    // base case of the no-wrap invariant)
    assert!(m >= 1u64 << 31 && m < 1u64 << 32, "log2_frac_q16 called with a normalised mantissa");
    let r: u32 = kani::any();
    kani::assume(r < 1u32 << LOG2_FRAC_BITS);
    unsafe {
        let n = FR_N;
        assert!(n < FR_CAP, "frac model capacity (harness sizing)");
        let mut j = 0;
        while j < n {
            let (mj, rj) = (FR_M[j], FR_R[j]);
            if mj == m {
                kani::assume(rj == r);
            } else if mj < m {
                kani::assume(rj <= r);
            } else {
                kani::assume(rj >= r);
            }
            j += 1;
        }
        FR_M[n] = m;
        FR_R[n] = r;
        FR_N = n + 1;
    }
    r
}

// ── recording model of `log2_q16`: any monotone function, exact integer part, None iff 0 ─────
const LG_CAP: usize = 40;
static mut LG_N: usize = 0;
static mut LG_X: [u64; LG_CAP] = [0; LG_CAP];
static mut LG_R: [u32; LG_CAP] = [0; LG_CAP];

fn log2_model(x: u64) -> Option<u32> {
    if x == 0 {
        return None;
    }
    let r: u32 = kani::any();
    kani::assume(r >> LOG2_FRAC_BITS == 63 - x.leading_zeros());
    unsafe {
        let n = LG_N;
        assert!(n < LG_CAP, "log2 model capacity (harness sizing)");
        let mut j = 0;
        while j < n {
            let (xj, rj) = (LG_X[j], LG_R[j]);
            if xj == x {
                kani::assume(rj == r);
            } else if xj < x {
                kani::assume(rj <= r);
            } else {
                kani::assume(rj >= r);
            }
            j += 1;
        }
        LG_X[n] = x;
        LG_R[n] = r;
        LG_N = n + 1;
    }
    Some(r)
}

// ── recording model of `curve_interp` (floor(span * num / den)) ────────────────────────────
const IP_CAP: usize = 28;
static mut IP_N: usize = 0;
static mut IP_S: [u64; IP_CAP] = [0; IP_CAP];
static mut IP_NUM: [u32; IP_CAP] = [0; IP_CAP];
static mut IP_DEN: [u32; IP_CAP] = [0; IP_CAP];
static mut IP_R: [u64; IP_CAP] = [0; IP_CAP];

fn interp_model(span: u64, num: u32, den: u32) -> u64 {
    // the caller's obligation (`curve_value` / `stress_cap_curve_x100` positions)
    assert!(den > 0 && num <= den, "curve_interp precondition: 0 <= num <= den, den > 0");
    let r: u64 = kani::any();
    kani::assume(r <= span);
    if num == 0 {
        kani::assume(r == 0);
    }
    if num == den {
        kani::assume(r == span);
    }
    unsafe {
        let n = IP_N;
        assert!(n < IP_CAP, "interp model capacity (harness sizing)");
        let mut j = 0;
        while j < n {
            let (sj, nj, dj, rj) = (IP_S[j], IP_NUM[j], IP_DEN[j], IP_R[j]);
            if dj == den && nj == num {
                // same fraction: monotone and 1-Lipschitz in the span (equal span -> equal value)
                if sj <= span {
                    kani::assume(rj <= r && r - rj <= span - sj);
                } else {
                    kani::assume(r <= rj && rj - r <= sj - span);
                }
            } else if dj == den && sj == span {
                // same span and denominator: monotone in num
                if nj <= num {
                    kani::assume(rj <= r);
                } else {
                    kani::assume(r <= rj);
                }
            }
            j += 1;
        }
        IP_S[n] = span;
        IP_NUM[n] = num;
        IP_DEN[n] = den;
        IP_R[n] = r;
        IP_N = n + 1;
    }
    r
}

// ── recording model of `n_cap_q`: any function monotone in (C_m, λ) for the same price and
// scale, `None` iff the price is 0. It claims no overflow, so it asserts the bounds that make
// that true (C_m < 2^64, λ < 2^32, scale < 2^32: C_m·λ·scale < 2^128). Lemma:
// `kani_contlev_n_cap_q_monotone_lemma`.
const NQ_CAP: usize = 8;
static mut NQ_N: usize = 0;
static mut NQ_C: [u128; NQ_CAP] = [0; NQ_CAP];
static mut NQ_L: [u32; NQ_CAP] = [0; NQ_CAP];
static mut NQ_P: [u64; NQ_CAP] = [0; NQ_CAP];
static mut NQ_S: [u128; NQ_CAP] = [0; NQ_CAP];
static mut NQ_R: [u128; NQ_CAP] = [0; NQ_CAP];

fn n_cap_q_model(c_m: u128, lambda_bps: u32, price_e6: u64, pos_scale: u128) -> Option<u128> {
    if price_e6 == 0 {
        return None;
    }
    assert!(c_m <= u64::MAX as u128 && pos_scale <= u32::MAX as u128, "n_cap_q model: inside its no-overflow domain");
    let r: u128 = kani::any();
    unsafe {
        let n = NQ_N;
        assert!(n < NQ_CAP, "n_cap_q model capacity (harness sizing)");
        let mut j = 0;
        while j < n {
            if NQ_P[j] == price_e6 && NQ_S[j] == pos_scale {
                let (cj, lj, rj) = (NQ_C[j], NQ_L[j], NQ_R[j]);
                if cj <= c_m && lj <= lambda_bps {
                    kani::assume(rj <= r);
                }
                if cj >= c_m && lj >= lambda_bps {
                    kani::assume(rj >= r);
                }
            }
            j += 1;
        }
        NQ_C[n] = c_m;
        NQ_L[n] = lambda_bps;
        NQ_P[n] = price_e6;
        NQ_S[n] = pos_scale;
        NQ_R[n] = r;
        NQ_N = n + 1;
    }
    Some(r)
}

/// Monotone thresholds as the program accepts them (`tier_config_ok`: T1 < T2 < T3), with
/// T1 >= 4 so anchor 0 = T1/4 is a real (non-zero) anchor. u32 steps: every realistic config
/// (6- and 9-decimal $ thresholds up to ~$4k-$4M per step on 6 decimals) and well past them;
/// the curve logic is width-independent (comparisons), the models carry the arithmetic.
fn any_thresholds() -> [u64; 3] {
    let a: u32 = kani::any();
    let b: u32 = kani::any();
    let c: u32 = kani::any();
    kani::assume(a >= 4 && b >= 1 && c >= 1);
    [a as u64, a as u64 + b as u64, a as u64 + b as u64 + c as u64]
}

/// A monotone 4-entry x100 table (every `tier_leverage` output is one).
fn any_table() -> [u16; 4] {
    let t: [u16; 4] = kani::any();
    kani::assume(t[0] <= t[1] && t[1] <= t[2] && t[2] <= t[3]);
    t
}

fn u64t(t: [u16; 4]) -> [u64; 4] {
    [t[0] as u64, t[1] as u64, t[2] as u64, t[3] as u64]
}

/// H1. `log2_q16` is MONOTONE at full u64 width and its integer part is exact; `None` iff 0;
/// the fraction core is only ever called with a normalised mantissa (`[2^31, 2^32)`: the model
/// asserts it). Proves the composition for EVERY monotone fraction core into `[0, 2^16)`; the
/// real core is one (E1, exhaustive).
/// Mutants: mantissa normalised to 31 bits (`k >= 30`, `x >> (k - 30)`): the entry assert;
/// `k << 15`: integer part + monotone; `64 - leading_zeros`: integer part.
#[kani::proof]
#[kani::stub(crate::growth_v19::log2_frac_q16, frac_model)]
#[kani::unwind(5)]
fn kani_contlev_log2_monotone() {
    let x: u64 = kani::any();
    let y: u64 = kani::any();
    kani::assume(x >= 1 && x <= y);
    let lx = log2_q16(x).unwrap();
    let ly = log2_q16(y).unwrap();
    assert!(lx <= ly, "monotone");
    assert_eq!(lx >> LOG2_FRAC_BITS, 63 - x.leading_zeros(), "integer part exact (x)");
    assert_eq!(ly >> LOG2_FRAC_BITS, 63 - y.leading_zeros(), "integer part exact (y)");
    assert!(log2_q16(0).is_none());
    assert!(unsafe { FR_N } == 2, "the fraction model ran (stub applied)");
    let (zx, zy) = (x.leading_zeros(), y.leading_zeros());
    kani::cover!(zx > 32 && zx == zy && x < y && lx < ly, "low octave (left-shift branch), same octave, strict");
    kani::cover!(zx < 32 && zx == zy && x < y && lx == ly, "high octave (right-shift branch), x < y with equal logs");
    kani::cover!(zx != zy, "different octaves");
    kani::cover!(x == 1, "x = 1 (k = 0)");
    kani::cover!(y >= 1u64 << 63, "top octave");
}

/// H2. The REAL fraction core on every `m < 2^32` (its domain and more): the result is `< 2^16`
/// and the in-loop `debug_assert!(m < 2^32)` -- the invariant that makes every `wrapping_mul`
/// exact (`m * m < 2^64`) -- holds at every one of the 16 squarings (checked by Kani as an
/// assertion when debug assertions are compiled in: the first cover reports whether they are).
/// Mutants: drop the halving (`m >>= 1`): the in-loop assert fails; `frac |= 1` on `m >= 2^31`
/// (every digit 1 at m = 2^31): the "m = 1.0 reads 0" cover becomes unreachable.
#[kani::proof]
#[kani::unwind(17)]
fn kani_contlev_log2_frac_core() {
    let m: u32 = kani::any();
    let r = log2_frac_q16(m as u64);
    assert!(r < 1u32 << LOG2_FRAC_BITS, "16 fractional bits");
    kani::cover!(cfg!(debug_assertions), "debug assertions compiled in (the no-wrap invariant is checked)");
    kani::cover!(m == 1u32 << 31 && r == 0, "m = 1.0: log 0");
    kani::cover!(m >= 1u32 << 31 && r >= 1u32 << 15, "first digit 1 (m >= sqrt 2)");
}

/// H3. `curve_interp` IS `floor(span * num / den)` and has the facts the `interp_model` assumes:
/// `<= span`; 0 at `num = 0`; `span` at `num = den`; monotone in `num`; monotone and 1-Lipschitz
/// in `span`. Proved on the production function at 8-bit operands (the facts are theorems about
/// `floor(s * n / d)` for `n <= d`, independent of width; the width-dependent part is the
/// product: `span, num < 2^32` gives `span * num < 2^64`, asserted below, and wider spans take
/// the exact u128 form -- E2 checks 10-bit operands exhaustively, E3 the full width at random
/// and at the boundaries against a u128 reference).
/// Mutants: ceil (`(s*n + d - 1) / d`): the floor identity; `num` and `den` swapped: `<= span`;
/// `span * den / num`: div by zero / `<= span`.
#[kani::proof]
fn kani_contlev_interp_facts() {
    let s1: u8 = kani::any();
    let s2: u8 = kani::any();
    let n1: u8 = kani::any();
    let n2: u8 = kani::any();
    let d: u8 = kani::any();
    kani::assume(d >= 1 && n1 <= d && n2 <= d);
    let (s1w, s2w, n1w, dw) = (s1 as u64, s2 as u64, n1 as u64, d as u64);
    let a = curve_interp(s1w, n1 as u32, d as u32);
    assert!(a * dw <= s1w * n1w && s1w * n1w < (a + 1) * dw, "exact floor");
    assert!(a <= s1w);
    if n1 == 0 {
        assert_eq!(a, 0);
    }
    if n1 == d {
        assert_eq!(a, s1w);
    }
    let b = curve_interp(s1w, n2 as u32, d as u32);
    if n1 <= n2 {
        assert!(a <= b, "monotone in num");
    }
    let c = curve_interp(s2w, n1 as u32, d as u32);
    if s1 <= s2 {
        assert!(a <= c && c - a <= s2w - s1w, "monotone and 1-Lipschitz in span");
    }
    // the width bound of the native branch (span <= u32::MAX, num <= u32::MAX)
    assert!((u32::MAX as u64).checked_mul(u32::MAX as u64).is_some());
    kani::cover!(a > 0 && a < s1w, "strictly inside (0, span)");
    kani::cover!((s1w * n1w) % dw != 0, "a rounded (floored) quotient");
    kani::cover!(n1 < n2 && a < b, "strictly increasing in num");
    kani::cover!(s1 < s2 && c - a == s2w - s1w && n1 < d && n1 > 0, "Lipschitz bound tight off the ends");
}

/// H4. The curve on monotone thresholds / tables: EQUAL to the table at every anchor; inside
/// `[t[0], t[3]]`; on a segment inside `[t[seg-1], t[seg]]`, `t[seg-1]` at `num = 0` and
/// `t[seg]` at `num = den` (it meets BOTH neighbouring anchor values: continuity at the anchors);
/// `t[0]` below anchor 0; `t[3]` from T3; a saturated T2 is flat at L1 from T1; the segment
/// contains the depth; `curve_interp` is only called inside its precondition (model assert).
/// Mutants: interpolation swapped for the step (`lo`): "num = den reads t[seg]" FAILS (the
/// mandated mutation check); segment chosen bottom-up: "the segment contains the depth" / "from
/// T3: t3"; interpolating toward a saturated anchor: the saturated-T2 assert; anchor 0 = T1
/// (`CURVE_ANCHOR0_DIV` 1): the "anchor-0 segment is live" cover becomes unreachable. (The
/// `min(num, den)` cap in `curve_pos` is belt and braces: with a monotone log2 it never binds.)
#[kani::proof]
#[kani::stub(crate::growth_v19::log2_q16, log2_model)]
#[kani::stub(crate::growth_v19::curve_interp, interp_model)]
#[kani::unwind(8)]
fn kani_contlev_curve_anchors_and_bounds() {
    let th = any_thresholds();
    let tab = any_table();
    let t = u64t(tab);
    let anc = curve_anchors(th);
    let i: usize = kani::any();
    kani::assume(i < 4);
    if anc[i] > 0 && (i == 0 || anc[i] > anc[i - 1]) {
        assert_eq!(curve_u64(anc[i], th, t), t[i], "equal to the table at each anchor");
    }
    let d: u64 = kani::any();
    let p = curve_pos(d, th);
    let v = curve_value(p, t);
    assert!(p.seg <= 4, "never the failure position on monotone thresholds");
    assert!(v >= t[0] && v <= t[3], "inside [t0, t3]");
    if p.seg >= 1 && p.seg <= 3 {
        let k = p.seg as usize;
        assert!(d >= anc[k - 1] && d < anc[k], "the segment contains the depth");
        assert!(p.num <= p.den);
        assert!(v >= t[k - 1] && v <= t[k], "inside the segment's bracket");
        if p.num == 0 {
            assert_eq!(v, t[k - 1], "num = 0 reads the lower anchor value");
        }
        if p.den > 0 && p.num == p.den {
            assert_eq!(v, t[k], "num = den reads the upper anchor value (continuity from the left)");
        }
    }
    if d < anc[0] {
        assert_eq!(v, t[0], "below anchor 0: t0");
    }
    if d >= th[2] {
        assert_eq!(v, t[3], "from T3: t3");
    }
    if d >= th[0] {
        assert_eq!(curve_u64(d, [th[0], u64::MAX, u64::MAX], t), t[1], "saturated T2: flat at L1 from T1");
    }
    kani::cover!(p.seg == 2 && v > t[1] && v < t[2], "strictly between two anchors");
    kani::cover!(p.seg == 1 && v > t[0], "the anchor-0 segment is live (kappa)");
    kani::cover!(p.seg == 4, "past T3");
    kani::cover!(p.seg == 0 && d > 0, "below anchor 0");
    kani::cover!(p.seg == 3 && p.den > 0 && p.num == p.den && t[2] < t[3], "top of a segment, below the anchor");
    kani::cover!(i == 2 && anc[2] > anc[1] && t[1] < t[2], "anchor T2 checked on a rising table");
    kani::cover!(unsafe { LG_N } > 0 && unsafe { IP_N } > 0, "both models ran (stubs applied)");
}

/// H5. MONOTONE in the depth (the leverage curve and the lagging capacity curve), and the dials
/// of `smooth_dials_and_venue_l`: L = the leverage curve at the smaller depth (venue <= book
/// here), κ / λ_depth = the LAGGING curve there (`curve_pos_lag`), the venue-only value = the
/// venue curve (>= the signal); symmetric in (venue, book).
/// Mutants: `max` for `min` in `m2`: the equalities; venue_l from the book position:
/// `vl == vd`; κ read from the leading position (3198539a): the κ equality (and H7).
#[kani::proof]
#[kani::stub(crate::growth_v19::log2_q16, log2_model)]
#[kani::stub(crate::growth_v19::curve_interp, interp_model)]
#[kani::unwind(41)]
fn kani_contlev_curve_monotone_and_min() {
    let th = any_thresholds();
    let tab = any_table();
    let t = u64t(tab);
    let d: u64 = kani::any();
    let e: u64 = kani::any();
    kani::assume(d <= e);
    let (pd, pe) = (curve_pos(d, th), curve_pos(e, th));
    let (vd, ve) = (curve_value(pd, t), curve_value(pe, t));
    assert!(vd <= ve, "leverage curve monotone in depth");
    let (qd, qe) = (curve_pos_lag(pd, d, th), curve_pos_lag(pe, e, th));
    let (kd, ke) = (curve_value(qd, KAPPA_TABLE_BPS), curve_value(qe, KAPPA_TABLE_BPS));
    let ld = curve_value(qd, LAMBDA_DEPTH_TABLE_BPS);
    assert!(kd <= ke, "lagging κ monotone in depth");
    let (dials, vl) = smooth_dials_and_venue_l(d, e, th, tab);
    assert_eq!(dials.l_signal_x100 as u64, vd, "L signal = curve at the smaller depth");
    assert_eq!(dials.kappa_bps as u64, kd, "κ = lagging curve at the smaller depth");
    assert_eq!(dials.lambda_depth_bps as u64, ld, "λ = lagging curve at the smaller depth");
    assert_eq!(vl as u64, vd);
    let (dials2, vl2) = smooth_dials_and_venue_l(e, d, th, tab);
    assert_eq!(dials2, dials, "symmetric");
    assert_eq!(vl2 as u64, ve, "venue value follows the venue");
    assert!(dials2.l_signal_x100 <= vl2, "venue-only bound >= signal");
    kani::cover!(d < e && vd < ve && pd.seg == pe.seg, "strictly increasing inside one segment");
    kani::cover!(d < e && pd.seg != pe.seg && vd < ve, "strictly increasing across an anchor");
    kani::cover!(kd < ke && qd.seg == 3 && qe.seg == 3, "κ strictly increasing on [T3, 4·T3)");
    kani::cover!(vl2 > dials2.l_signal_x100, "the venue bound strictly above the signal");
    kani::cover!(unsafe { LG_N } > 0 && unsafe { IP_N } > 0, "both models ran (stubs applied)");
}

/// H6 (security review M-2: the stress cap stays STEPPED). Under a draw / real ADL / the h-lock
/// the program's target is `target_ceiling_x100(grad, s, launch, L_tier, signal, stress_cap_x100(s,
/// combined tier))` with `signal` the leverage curve at min(venue, book). The stepped cap is
/// NEVER ABOVE the unstressed curve (the curve is `>= L_table(tier)` of the combined tier), so
/// the stressed target is never above the unstressed one; it is exactly base caf062bd's
/// `max(launch, min(signal, L_table(tier - s)))` capped at L_tier; and the ceiling in force
/// (`min(stored, target)`) takes it at once.
/// The program wiring (the gate's ctx at the combined tier, the push writer at the venue tier)
/// lives in v16_program.rs, outside this crate: the LiteSVM test
/// `contlev_m2_draw_at_200k_300k_400k_stores_the_stepped_5x` pins it (and fails on 3198539a).
/// Mutants: `stress_cap_x100` reading `tier - s + 1`: "= base's stepped formula" (and "never
/// above" at tier 0); the h-lock early return dropped in `target_ceiling_x100`: the h-lock call
/// with no cap (`u16::MAX`) must still read launch; the curve `>= L_table(tier)` broken (e.g.
/// the leverage curve lagging like κ): the first assert.
#[kani::proof]
#[kani::stub(crate::growth_v19::log2_q16, log2_model)]
#[kani::stub(crate::growth_v19::curve_interp, interp_model)]
#[kani::unwind(13)]
fn kani_contlev_stress_cap_stepped_under_curve() {
    let th = any_thresholds();
    let tab = any_table();
    let d: u64 = kani::any();
    let e: u64 = kani::any();
    let st: u8 = kani::any();
    kani::assume(st <= STRESS_HLOCK);
    let tier = combined_tier(depth_tier_for(d, th), depth_tier_for(e, th));
    let (dials, _) = smooth_dials_and_venue_l(d, e, th, tab);
    let sig = dials.l_signal_x100;
    let cap = stress_cap_x100(st, tier, tab);
    let grad = graduation_on(true, 64, tier);
    let (launch, lt) = (tab[0], tab[3]);
    let t = target_ceiling_x100(grad, st, launch, lt, sig, cap);
    let t0 = target_ceiling_x100(grad, STRESS_NONE, launch, lt, sig, stress_cap_x100(STRESS_NONE, tier, tab));
    assert!(sig as u64 >= tab[tier as usize] as u64, "the curve at the smaller depth >= L_table(combined tier)");
    if st >= STRESS_DRAW {
        assert!(cap <= sig, "the stepped stress cap is never above the unstressed curve");
    }
    assert!(t <= t0, "stressed target <= unstressed target");
    if st == STRESS_HLOCK || !grad {
        assert_eq!(t, launch, "h-lock / no graduation: launch");
    } else {
        let stepped = tab[tier.saturating_sub(st) as usize];
        let want = if st == STRESS_NONE { sig } else { core::cmp::min(sig, stepped) };
        assert_eq!(t, core::cmp::min(core::cmp::max(launch, want), lt), "= base caf062bd's stepped formula");
        if st == STRESS_DRAW || st == STRESS_ADL {
            assert_eq!(t, core::cmp::min(core::cmp::max(launch, stepped), lt), "under stress the target does not depend on the curve");
        }
    }
    assert_eq!(target_ceiling_x100(grad, STRESS_HLOCK, launch, lt, sig, u16::MAX), launch, "h-lock: launch whatever the cap");
    let stored: u16 = kani::any();
    let f = ceiling_in_force_x100(true, stored, t, launch, lt);
    assert!(f <= t, "applied at once (in force <= target)");
    kani::cover!(st == STRESS_DRAW && grad && tier == 2 && t < sig && t > launch, "draw at tier 2 binds above launch");
    kani::cover!(st == STRESS_DRAW && grad && tier == 2 && sig > tab[2] && t == tab[1], "draw between T2 and T3: the stepped L1, not the curve");
    kani::cover!(st == STRESS_ADL && grad && tier == 3 && t == tab[1] && tab[1] > launch, "ADL past T3: L1");
    kani::cover!(st == STRESS_HLOCK && grad && t < t0, "h-lock cuts");
    kani::cover!(st == STRESS_NONE && grad && t == sig && sig > tab[tier as usize], "unstressed: the curve, above the step");
    kani::cover!(stored > t && f == t && st >= STRESS_DRAW, "cut at once from a higher stored ceiling");
    kani::cover!(unsafe { LG_N } > 0 && unsafe { IP_N } > 0, "both models ran (stubs applied)");
}

/// H7 (security review M-1). The LAGGING capacity curve (`curve_pos_lag`, κ / λ_depth) on any
/// monotone table: NEVER ABOVE the step value `t[tier(d)]` (so κ <= κ_step and λ <= λ_step at
/// every depth); `>= t[0]`; `t[0]` below T1; at T1 / T2 / T3 the step value of the segment BELOW
/// (`t[0]` / `t[1]` / `t[2]`); `t[3]` from 4·T3; at the top of a segment (`num = den`) the next
/// value (it meets the value the next segment starts from: no jump); monotone in the depth; a
/// saturated T3 never lets it pass `t[2]`. Also on the real κ / λ tables.
/// Mutants: κ from the leading position (3198539a): "never above the step" FAILS (κ 0.9999 at
/// T1 - 1); lag seg 4 read as `t[3]` at once from T3: "at T3: t[2]" FAILS; lag `seg` not
/// shifted (`lead.seg`): "never above the step"; top anchor at T3 (no top segment): "at T3".
#[kani::proof]
#[kani::stub(crate::growth_v19::log2_q16, log2_model)]
#[kani::stub(crate::growth_v19::curve_interp, interp_model)]
#[kani::unwind(13)]
fn kani_contlev_kappa_lambda_lag_never_looser() {
    let th0 = any_thresholds();
    // mode 0: realistic; 1: saturated T3; 2: saturated T2 and T3; 3: a T3 so large that 4·T3
    // saturates (the top segment is flat at t[2], fail closed)
    let mode: u8 = kani::any();
    kani::assume(mode <= 3);
    let big: u64 = kani::any();
    kani::assume(big > u64::MAX / KAPPA_LAG_TOP_MUL && big < u64::MAX);
    let th = match mode {
        0 => th0,
        1 => [th0[0], th0[1], u64::MAX],
        2 => [th0[0], u64::MAX, u64::MAX],
        _ => [th0[0], th0[1], big],
    };
    let sat = mode == 1 || mode == 2;
    let tab = any_table();
    let t = u64t(tab);
    let d: u64 = kani::any();
    let e: u64 = kani::any();
    kani::assume(d <= e);
    let tier = depth_tier_for(d, th) as usize;
    let p = curve_pos(d, th);
    let q = curve_pos_lag(p, d, th);
    let v = curve_value(q, t);
    assert!(q.seg <= 4, "never the failure position on monotone thresholds");
    assert!(v <= t[tier], "never above the step");
    assert!(v >= t[0]);
    assert!(curve_value(q, KAPPA_TABLE_BPS) <= kappa_depth_bps(tier as u8) as u64, "κ <= κ_step");
    assert!(curve_value(q, LAMBDA_DEPTH_TABLE_BPS) <= lambda_depth_bps(tier as u8) as u64, "λ <= λ_step");
    if d < th[0] {
        assert_eq!(v, t[0], "below T1: t0");
    }
    if d == th[0] {
        assert_eq!(v, t[0], "at T1: t0");
    }
    if mode != 2 && d == th[1] {
        assert_eq!(v, t[1], "at T2: t1");
    }
    if !sat && d == th[2] {
        assert_eq!(v, t[2], "at T3: t2");
    }
    if sat || mode == 3 {
        assert!(v <= t[2], "saturated T3 / 4·T3: never past t2");
    }
    if mode == 2 {
        assert!(v <= t[1], "saturated T2: never past t1");
    }
    let top = th0[2] * KAPPA_LAG_TOP_MUL; // th0[2] < 3·2^32: no overflow
    if mode == 0 && d >= top {
        assert_eq!(v, t[3], "from 4·T3: t3");
    }
    if q.seg >= 1 && q.seg <= 3 && q.den > 0 && q.num == q.den {
        assert_eq!(v, t[q.seg as usize], "top of a segment: the next value (continuity)");
    }
    let ve = curve_value(curve_pos_lag(curve_pos(e, th), e, th), t);
    assert!(v <= ve, "monotone");
    kani::cover!(q.seg == 1 && v > t[0] && v < t[1], "strictly inside [T1, T2)");
    kani::cover!(q.seg == 3 && v > t[2] && v < t[3] && mode == 0, "strictly inside [T3, 4·T3)");
    kani::cover!(mode == 0 && d >= top && t[2] < t[3], "past 4·T3");
    kani::cover!(mode == 3 && p.seg == 4 && q.seg == 3 && q.den == 0, "4·T3 saturates: flat top segment");
    kani::cover!(mode == 2 && d >= th[0] && v == t[0] && t[0] < t[1], "saturated T2: flat at t0 from T1");
    kani::cover!(tier == 3 && v < t[3], "past T3 but below the step (lagging)");
    kani::cover!(q.seg == 2 && q.den > 0 && q.num == q.den && t[1] < t[2], "top of [T2, T3), below T3");
    kani::cover!(sat && p.seg == 3 && q.seg == 2, "saturated T3");
    kani::cover!(curve_value(q, KAPPA_TABLE_BPS) > 10_000 && curve_value(q, KAPPA_TABLE_BPS) < 20_000, "κ strictly between 1 and 2");
    kani::cover!(v < ve && q.seg == 3, "strictly increasing on the top segment");
    kani::cover!(unsafe { LG_N } > 0 && unsafe { IP_N } > 0, "both models ran (stubs applied)");
}

/// H8a (security review M-1). The step reader `n_cap_g8_q(tier)` IS `n_cap_g8_q_dials` at the
/// step dials `(lambda_depth_bps(tier), kappa_depth_bps(tier))`, at full u128 width (same terms
/// on both sides: run with `--solver z3`, which collapses them).
/// Mutant: `n_cap_g8_q` passing κ and λ swapped: FAILS.
#[kani::proof]
fn kani_contlev_n_cap_step_identity() {
    let c_m: u128 = kani::any();
    let stored: u32 = kani::any();
    let cap: Option<u64> = kani::any();
    let price: u64 = kani::any();
    let ps: u128 = kani::any();
    let tier: u8 = kani::any();
    kani::assume(tier <= MAX_TIER);
    let a = n_cap_g8_q(true, c_m, stored, tier, cap, price, ps);
    let b = n_cap_g8_q_dials(true, c_m, stored, lambda_depth_bps(tier), kappa_depth_bps(tier), cap, price, ps);
    assert_eq!(a, b, "the step reader is the dials reader at the step dials");
    kani::cover!(a.is_some_and(|x| x > 0) && tier == 3, "positive capacity at tier 3");
    kani::cover!(a.is_none(), "fail closed (zero price / overflow)");
}

/// H8b (security review M-1). `N_cap` is MONOTONE in the dials it reads: with `λ1 <= λ2` and
/// `κ1 <= κ2`, `n_cap_g8_q_dials(.., λ1, κ1, ..) <= n_cap_g8_q_dials(.., λ2, κ2, ..)` (same C_m,
/// stored λ, cap depth, price, scale). `n_cap_q` is replaced by its
/// recording model (monotone in (C_m, λ) for the same price / scale: the lemma H8c); what is
/// left is `min`, the `κ·depth / 1e4` product (monotone in κ for the same depth) and
/// `unwrap_or(0)` (cap depth u8, κ u16 <= 2x: the monotonicity of `floor(d·κ / 1e4)` in κ is
/// width-independent; C_m <= 2^64 and scale <= 2^32 keep the model's no-overflow claim true:
/// C_m·λ·scale < 2^128, asserted in the model). With H7 (lagging κ <= κ_step and λ <= λ_step at the smaller depth, hence <=
/// the step dials of the combined tier) and H8a this gives N_cap_new <= N_cap_step; the native
/// sweep `contlev_m1_n_cap_never_above_base` checks N_cap_new <= base caf062bd's too.
/// Mutants: κ divided instead of multiplied in `depth_cap_q_kappa`: FAILS; `max` for the inner
/// `min(stored λ, λ_depth)`: still monotone (the gate tests own it).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_q_model)]
#[kani::unwind(5)]
fn kani_contlev_n_cap_monotone_in_dials() {
    let c_m: u64 = kani::any();
    let stored: u32 = kani::any();
    let l1: u32 = kani::any();
    let l2: u32 = kani::any();
    let k1: u16 = kani::any();
    let k2: u16 = kani::any();
    kani::assume(l1 <= l2 && k1 <= k2 && k2 <= 20_000);
    let cap: Option<u8> = kani::any();
    let price: u64 = kani::any();
    let ps: u32 = kani::any();
    let n = |l: u32, k: u16| {
        n_cap_g8_q_dials(true, c_m as u128, stored, l, k as u32, cap.map(|x| x as u64), price, ps as u128)
    };
    let a = n(l1, k1);
    let b = n(l2, k2);
    assert_eq!(a.is_none(), price == 0, "None only on a zero price (model: no overflow)");
    assert_eq!(b.is_none(), price == 0);
    if let (Some(x), Some(y)) = (a, b) {
        assert!(x <= y, "N_cap monotone in (λ_depth, κ)");
    }
    kani::cover!(a.is_some() && a < b && l1 == l2, "strictly larger through κ alone");
    kani::cover!(a.is_some() && a < b && k1 == k2, "strictly larger through λ alone");
    kani::cover!(cap.is_some() && a.is_some_and(|x| x > 0), "a depth cap in force, positive capacity");
}

/// H8c (lemma for H8b's model). `n_cap_q` is monotone in (C_m, λ) for the same price and scale
/// (production function, u8 operands: `floor(c·λ·s / (1e4·p))` is monotone in `c·λ` at any
/// width; the width only decides overflow, which needs C_m·λ·scale >= 2^128, unreachable for
/// SPL amounts). `--solver z3`.
/// Mutant: `checked_mul` of C_m by the price instead of λ: FAILS.
#[kani::proof]
fn kani_contlev_n_cap_q_monotone_lemma() {
    let c1: u8 = kani::any();
    let c2: u8 = kani::any();
    let l1: u8 = kani::any();
    let l2: u8 = kani::any();
    kani::assume(c1 <= c2 && l1 <= l2);
    let price: u8 = kani::any();
    let ps: u8 = kani::any();
    kani::assume(price >= 1);
    let a = n_cap_q(c1 as u128, l1 as u32, price as u64, ps as u128).unwrap();
    let b = n_cap_q(c2 as u128, l2 as u32, price as u64, ps as u128).unwrap();
    assert!(a <= b, "monotone in (C_m, λ)");
    assert!(n_cap_q(c1 as u128, l1 as u32, 0, ps as u128).is_none(), "zero price: None");
    kani::cover!(a < b && a > 0, "strictly increasing, positive");
}

// ── P3U (2026-10-20): tag 77's OI guard reads the B24 owned principal of a bound pot ─────────
// (Here, not in kani/p3: that crate compiles vault_lp_v18.rs alone and no longer builds since
// vault_lp_v18 reads growth_v19; this crate compiles both production files.)

/// `vault_lp_v18::bound_pot_available_principal(principal, fresh, valid, scale)` never falls
/// below a payout principal the redemption's gates admit (`pp <= principal`,
/// `pp * scale <= fresh`), so the guard's `available - pp` cannot underflow; and it never exceeds
/// the ledger principal or the held backing (it does not overstate the pot).
/// BOUNDED and scale-generic: u8 inputs and a symbolic u8 `scale >= 1` (the kani/p3 `b()` bound for
/// harnesses that multiply a symbolic value back up against a floor division). Earlier designs
/// gave NO verdict and were killed: production scale 1e12 with u64 inputs (z3, one query 13.6 h /
/// 800 CPU-min) and u16 inputs with a symbolic u16 scale (cadical, 60 min); P3U.md section 7.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3u_bound_pot_available_covers_gated_payout() {
    use crate::vault_lp_v18::bound_pot_available_principal;
    let principal = kani::any::<u8>() as u128;
    let pp = kani::any::<u8>() as u128;
    let fresh_extra = kani::any::<u8>() as u128;
    let valid = kani::any::<u8>() as u128;
    let scale = kani::any::<u8>() as u128;
    kani::assume(scale >= 1);
    kani::assume(pp <= principal);
    // the gate: the pot's fresh idle backing covers the payout principal (in num)
    let fresh = pp * scale + fresh_extra;
    let a = bound_pot_available_principal(principal, fresh, valid, scale);
    let held = (fresh + valid) / scale;
    assert!(a >= pp);
    assert!(a <= principal);
    assert!(a <= held);
    assert!(a == principal || a == held);
    kani::cover!(principal < held && pp > 0, "ledger principal binds");
    kani::cover!(held < principal && pp > 0, "held backing binds");
    kani::cover!(a == pp && pp > 0 && scale > 1, "tight: a full exit of the pot");
    // scale 0 answers 0, never a division by zero
    assert!(bound_pot_available_principal(principal, fresh, valid, 0) == 0);
}
