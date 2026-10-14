//! Overnight 2026-10-14: STRUCTURAL lemmas for the growth-v19 composites, FULL u128 width.
//! Built with `--features nc` (production files minus their cfg(kani) contract attributes;
//! `gen_nc.sh --check`). Each arithmetic primitive is replaced by a RECORDING stub that returns an
//! ARBITRARY value (`kani::any()`, a sound over-approximation of every function), so no 128-bit
//! divider is in the model. Each lemma proves: the composite takes exactly its guarded early
//! exits, otherwise calls the primitive EXACTLY ONCE with exactly the design operands and maps
//! the primitive's result exactly as the design formula says.
//!
//! Composition (ledger v22-kani-overnight-2026-10-14.md §Decomposition): structural lemma (here,
//! full width) + primitive contract (`kani_growth_c_mul_div_floor` / `_ceil`, PASS) + the
//! abstract composition lemmas in `proofs_overnight` ⇒ the composite's exact C1 spec.

use crate::growth_v19::*;

// ── recording stubs ─────────────────────────────────────────────────────────────────────────
static mut F_CALLS: u8 = 0;
static mut F_ARGS: (u128, u128, u128) = (0, 0, 0);
static mut F_RET: Option<u128> = None;
static mut C_CALLS: u8 = 0;
static mut C_ARGS: (u128, u128, u128) = (0, 0, 0);
static mut C_RET: Option<u128> = None;

fn rec_floor(a: u128, b: u128, d: u128) -> Option<u128> {
    unsafe {
        F_CALLS += 1;
        F_ARGS = (a, b, d);
        F_RET
    }
}
fn rec_ceil(a: u128, b: u128, d: u128) -> Option<u128> {
    unsafe {
        C_CALLS += 1;
        C_ARGS = (a, b, d);
        C_RET
    }
}
fn arm() {
    unsafe {
        F_CALLS = 0;
        C_CALLS = 0;
        F_RET = kani::any();
        C_RET = kani::any();
    }
}
fn f_calls() -> u8 {
    unsafe { F_CALLS }
}
fn c_calls() -> u8 {
    unsafe { C_CALLS }
}
fn f_args() -> (u128, u128, u128) {
    unsafe { F_ARGS }
}
fn c_args() -> (u128, u128, u128) {
    unsafe { C_ARGS }
}
fn f_ret() -> Option<u128> {
    unsafe { F_RET }
}
fn c_ret() -> Option<u128> {
    unsafe { C_RET }
}

// ── S1 n_cap_q ─────────────────────────────────────────────────────────────────────────────
/// n_cap_q(c,λ,P,S) = None if P == 0 or c·λ overflows; else mul_div_floor(c·λ, S, 1e4·P)
/// (and 1e4·P never overflows).
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, rec_floor)]
fn kani_growth_s1_n_cap_q_structure() {
    arm();
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = n_cap_q(c, l, p, s);
    let x = c.checked_mul(l as u128);
    if p == 0 || x.is_none() {
        assert!(r.is_none() && f_calls() == 0);
    } else {
        assert!(f_calls() == 1);
        let (a, b, d) = f_args();
        assert!(a == x.unwrap() && b == s && d == 10_000u128 * p as u128);
        assert!(r == f_ret());
    }
    kani::cover!(p == 0, "price 0");
    kani::cover!(p != 0 && x.is_none(), "c*lambda overflow");
    kani::cover!(f_calls() == 1 && r.is_some(), "primitive Some");
    kani::cover!(f_calls() == 1 && r.is_none(), "primitive None");
}

// ── S2 liquidity_notional_e6 ───────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, rec_floor)]
fn kani_growth_s2_liquidity_notional_structure() {
    arm();
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let r = liquidity_notional_e6(c, l);
    let x = c.checked_mul(l as u128);
    match x {
        None => assert!(r.is_none() && f_calls() == 0),
        Some(x) => {
            assert!(f_calls() == 1 && f_args() == (x, DEPTH_MULT, 10_000) && r == f_ret());
        }
    }
    kani::cover!(x.is_none(), "c*lambda overflow");
    kani::cover!(f_calls() == 1 && r.is_some(), "called");
}

// ── S3 risk_notional_ceil ──────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s3_risk_notional_structure() {
    arm();
    let q: u128 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = risk_notional_ceil(q, p, s);
    assert!(c_calls() == 1 && c_args() == (q, p as u128, s) && r == c_ret());
    kani::cover!(r.is_some(), "Some");
    kani::cover!(r.is_none(), "None");
}

// ── S4 leg_im_req ──────────────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s4_leg_im_req_structure() {
    arm();
    let n: u128 = kani::any();
    let imr: u64 = kani::any();
    let m: u128 = kani::any();
    let r = leg_im_req(n, imr, m);
    if n == 0 {
        assert!(r == Some(0) && c_calls() == 0);
    } else if imr > MAX_IMR_BPS {
        assert!(r.is_none() && c_calls() == 0);
    } else {
        assert!(c_calls() == 1 && c_args() == (n, imr as u128, 10_000));
        match c_ret() {
            None => assert!(r.is_none()),
            Some(x) => assert!(r == Some(if x > m { x } else { m })),
        }
    }
    kani::cover!(n == 0, "flat");
    kani::cover!(n > 0 && imr > MAX_IMR_BPS, "imr > 1e4");
    kani::cover!(c_ret().is_some_and(|x| x > m) && r.is_some() && n > 0, "ceil binds");
    kani::cover!(c_ret().is_some_and(|x| x <= m) && r == Some(m) && n > 0, "min binds");
    kani::cover!(n > 0 && imr <= MAX_IMR_BPS && r.is_none(), "primitive None");
}

// ── S5 dyn_imr_bps ─────────────────────────────────────────────────────────────────────────
/// Guards → None; lp·1e4 / k·n overflow → None; lhs <= rhs → Some(base) without a call; else
/// exactly one call ceil(span, lhs − rhs, n·(1e4 − k)) (den overflow → None, no call) and
/// base + extra (overflow → None) clamped at MAX_IMR_BPS.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s5_dyn_imr_structure() {
    arm();
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    let guard = base > MAX_IMR_BPS || k as u128 > 10_000 || n == 0 || lp > n;
    let lhs = lp.checked_mul(10_000);
    let rhs = (k as u128).checked_mul(n);
    if guard || lhs.is_none() || rhs.is_none() {
        assert!(r.is_none() && c_calls() == 0);
    } else if lhs.unwrap() <= rhs.unwrap() {
        assert!(r == Some(base) && c_calls() == 0);
    } else {
        // 1e4 − k never underflows: k <= 1e4 is guarded above.
        let den = n.checked_mul(10_000 - k as u128);
        match den {
            None => assert!(r.is_none() && c_calls() == 0),
            Some(den) => {
                let span = (MAX_IMR_BPS - base) as u128;
                assert!(c_calls() == 1 && c_args() == (span, lhs.unwrap() - rhs.unwrap(), den));
                let exp = c_ret().and_then(|e| (base as u128).checked_add(e)).map(|v| {
                    if v > MAX_IMR_BPS as u128 {
                        MAX_IMR_BPS
                    } else {
                        v as u64
                    }
                });
                assert!(r == exp);
            }
        }
    }
    kani::cover!(guard, "guard");
    kani::cover!(!guard && lhs.is_none(), "lp*1e4 overflow");
    kani::cover!(!guard && r == Some(base) && c_calls() == 0 && lp > 0, "below the kink");
    kani::cover!(!guard && c_calls() == 0 && r.is_none() && lhs.is_some() && rhs.is_some() && lhs > rhs, "den overflow");
    kani::cover!(c_calls() == 1 && r.is_some_and(|v| v > base && v < MAX_IMR_BPS), "stepped");
    kani::cover!(c_calls() == 1 && r == Some(MAX_IMR_BPS), "clamped / full");
    kani::cover!(c_calls() == 1 && r.is_none(), "primitive None / add overflow");
}

// ── S6 utilisation_fee_bps ─────────────────────────────────────────────────────────────────
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s6_utilisation_fee_structure() {
    arm();
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    let r = utilisation_fee_bps(o, n, k, m);
    let lhs = o.checked_mul(10_000);
    let rhs = (k as u128).checked_mul(n);
    if n == 0 || k as u128 > 10_000 || lhs.is_none() || rhs.is_none() {
        assert!(r.is_none() && c_calls() == 0);
    } else if lhs.unwrap() <= rhs.unwrap() || m == 0 {
        assert!(r == Some(0) && c_calls() == 0);
    } else {
        // lhs > rhs = k·n ⇒ k < 1e4 or o > n; 1e4 − k never underflows (k <= 1e4 guarded)
        match n.checked_mul(10_000 - k as u128) {
            None => assert!(r.is_none() && c_calls() == 0),
            Some(den) => {
                assert!(c_calls() == 1 && c_args() == (m as u128, lhs.unwrap() - rhs.unwrap(), den));
                let exp = c_ret().map(|f| if f > m as u128 { m } else { f as u16 });
                assert!(r == exp);
            }
        }
    }
    kani::cover!(n == 0, "n == 0");
    kani::cover!(r == Some(0) && m > 0 && o > 0, "below the kink");
    kani::cover!(c_calls() == 1 && r.is_some_and(|f| f > 0 && f < m), "charged");
    kani::cover!(c_calls() == 1 && r == Some(m) && m > 0, "capped");
    kani::cover!(c_calls() == 0 && r.is_none() && n > 0 && k <= 10_000 && lhs.is_some() && rhs.is_some(), "den overflow");
}

// ── S7 util_fee_on_fill_bps ────────────────────────────────────────────────────────────────
/// Under its `requires` (fee·min(o, fill) fits u128), the floor primitive's result is Some
/// (primitive contract: None ⇔ d == 0 ∨ a·b overflows; here d = fill > 0) — that single fact is
/// assumed of the stub; everything else is the arbitrary value.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, rec_floor)]
fn kani_growth_s7_util_fee_on_fill_structure() {
    arm();
    let f: u16 = kani::any();
    let o: u128 = kani::any();
    let fill: u128 = kani::any();
    kani::assume((f as u128).checked_mul(core::cmp::min(o, fill)).is_some());
    kani::assume(f_ret().is_some());
    let r = util_fee_on_fill_bps(f, o, fill);
    if fill == 0 || o == 0 || f == 0 {
        assert!(r == 0 && f_calls() == 0);
    } else {
        let om = if o > fill { fill } else { o };
        assert!(f_calls() == 1 && f_args() == (f as u128, om, fill));
        let x = f_ret().unwrap();
        assert!(r == if x < f as u128 { x as u16 } else { f });
    }
    kani::cover!(f_calls() == 1 && r > 0 && r < f, "share");
    kani::cover!(f_calls() == 1 && r == f && f > 0, "clamped / full");
    kani::cover!(o > fill && f_calls() == 1, "opening clipped to the fill");
}

// ── S5 split (S5 as one harness: NO-VERDICT 400 s under z3) ────────────────────────────────
// S5a ∧ S5b ⇔ S5: the branches are selected by the same guard / lhs / rhs / den predicates,
// and S5a's premise is the exact complement of S5b's.

/// S5a: every path that does NOT call the primitive.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s5a_dyn_imr_structure_no_call() {
    arm();
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let guard = base > MAX_IMR_BPS || k as u128 > 10_000 || n == 0 || lp > n;
    let lhs = lp.checked_mul(10_000);
    let rhs = (k as u128).checked_mul(n);
    let r = dyn_imr_bps(lp, n, base, k);
    if guard || lhs.is_none() || rhs.is_none() {
        assert!(r.is_none() && c_calls() == 0);
    } else if lhs.unwrap() <= rhs.unwrap() {
        assert!(r == Some(base) && c_calls() == 0);
    } else if n.checked_mul(10_000 - k as u128).is_none() {
        assert!(r.is_none() && c_calls() == 0);
    }
    kani::cover!(guard, "guard");
    kani::cover!(!guard && lhs.is_none(), "lp*1e4 overflow");
    kani::cover!(!guard && r == Some(base) && lp > 0, "below the kink");
}

/// S5b: the stepped path: exactly one call with (span, lhs − rhs, n·(1e4 − k)) and the result
/// base + extra (checked) clamped at MAX_IMR_BPS. Premise = the complement of S5a's cases.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s5b_dyn_imr_structure_stepped() {
    arm();
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(base <= MAX_IMR_BPS && k as u128 <= 10_000 && n > 0 && lp <= n);
    let lhs = lp.checked_mul(10_000);
    let rhs = (k as u128).checked_mul(n);
    kani::assume(lhs.is_some() && rhs.is_some() && lhs.unwrap() > rhs.unwrap());
    let den = n.checked_mul(10_000 - k as u128);
    kani::assume(den.is_some());
    let r = dyn_imr_bps(lp, n, base, k);
    let span = (MAX_IMR_BPS - base) as u128;
    assert!(c_calls() == 1 && c_args() == (span, lhs.unwrap() - rhs.unwrap(), den.unwrap()));
    let exp = c_ret().and_then(|e| (base as u128).checked_add(e)).map(|v| {
        if v > MAX_IMR_BPS as u128 {
            MAX_IMR_BPS
        } else {
            v as u64
        }
    });
    assert!(r == exp);
    kani::cover!(r.is_some_and(|v| v > base && v < MAX_IMR_BPS), "stepped");
    kani::cover!(r == Some(MAX_IMR_BPS), "clamped / full");
    kani::cover!(r.is_none(), "primitive None / add overflow");
}

/// S5c (concrete witness): S5a's `n·(1e4 − k)` overflow branch is reachable and refuses without
/// calling the primitive: n = u128::MAX, lp = 1, k = 0 (lhs = 1e4 > rhs = 0, den overflows).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s5c_dyn_imr_den_overflow_witness() {
    arm();
    let base: u64 = kani::any();
    kani::assume(base <= MAX_IMR_BPS);
    let r = dyn_imr_bps(1, u128::MAX, base, 0);
    assert!(r.is_none() && c_calls() == 0);
    kani::cover!(r.is_none(), "den overflow refused");
}

// ── S5d: the ONLY dyn_imr_bps facts the gate-level nc harnesses consume ─────────────────────
/// With an ARBITRARY ceil primitive: the guard (base > MAX, k > 1e4, n == 0, lp > n) ⇒ None;
/// otherwise the result is None or in [base, MAX_IMR_BPS]. Justifies `dyn_any_guarded`.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, rec_ceil)]
fn kani_growth_s5d_dyn_imr_guard_and_range() {
    arm();
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    if base > MAX_IMR_BPS || k as u128 > 10_000 || n == 0 || lp > n {
        assert!(r.is_none());
    }
    if let Some(v) = r {
        assert!(v >= base && v <= MAX_IMR_BPS);
    }
    kani::cover!(r == Some(base), "base");
    kani::cover!(r.is_some_and(|v| v > base), "stepped");
    kani::cover!(r.is_none() && lp <= n && n > 0 && base <= MAX_IMR_BPS && k <= 10_000, "None inside the guard");
}

// ── gate-level nc variants (originals NO-VERDICT): every composite is a ∀-value stub ───────
// n_cap_q / risk_notional_ceil / leg_im_req: ANY value (V4, as in the originals);
// dyn_imr_bps: ANY value allowed by S5d (None under the guard, else None or [base, MAX]).
static mut G_NCAP: Option<u128> = None;
static mut G_RISK: Option<u128> = None;
static mut G_LEG_KEY: u64 = 0;
static mut G_LEG_AT_KEY: Option<u128> = None;
static mut G_LEG_OTHER: Option<u128> = None;
static mut G_DYN: Option<u64> = None;

fn ncap() -> Option<u128> {
    unsafe { G_NCAP }
}
fn risk() -> Option<u128> {
    unsafe { G_RISK }
}
fn n_cap_any(_c: u128, _l: u32, _p: u64, _s: u128) -> Option<u128> {
    unsafe { G_NCAP }
}
fn risk_any(_q: u128, _p: u64, _s: u128) -> Option<u128> {
    unsafe { G_RISK }
}
fn leg_any(_n: u128, imr: u64, _m: u128) -> Option<u128> {
    unsafe {
        if imr == G_LEG_KEY {
            G_LEG_AT_KEY
        } else {
            G_LEG_OTHER
        }
    }
}
/// Sound by S5d: returns None under the guard, otherwise an arbitrary None-or-[base, MAX] value.
fn dyn_any_guarded(lp: u128, n: u128, base: u64, k: u16) -> Option<u64> {
    if base > MAX_IMR_BPS || k as u128 > 10_000 || n == 0 || lp > n {
        return None;
    }
    let v: Option<u64> = kani::any();
    kani::assume(v.is_none_or(|x| x >= base && x <= MAX_IMR_BPS));
    unsafe { G_DYN = v };
    v
}

fn any_gate_nc(lp_some: bool) -> GrowthGateIn {
    let tb: i128 = kani::any();
    let ta: i128 = kani::any();
    let lp = if lp_some {
        let la: i128 = kani::any();
        Some(GrowthLpIn {
            before_q: kani::any(),
            mid_q: kani::any(),
            after_q: la,
            eff_after_abs_q: la.unsigned_abs(),
            users_oi_side_after_q: kani::any(),
            equity: kani::any(),
        })
    } else {
        None
    };
    let g = GrowthGateIn {
        taker_before_q: tb,
        taker_after_q: ta,
        taker_eff_after_abs_q: ta.unsigned_abs(),
        taker_equity: kani::any(),
        taker_cert_initial_req: kani::any(),
        lp,
        price_e6: kani::any(),
        pos_scale: kani::any(),
        engine_imr_bps: kani::any(),
        min_nonzero_im_req: kani::any(),
        ceil_imr_bps: kani::any(),
        lambda_bps: kani::any(),
        kink_bps: kani::any(),
        crowd_blocked: kani::any(),
        asset_bound: kani::any(),
    };
    unsafe {
        G_NCAP = kani::any();
        G_RISK = kani::any();
        G_LEG_KEY = g.engine_imr_bps;
        G_LEG_AT_KEY = kani::any();
        G_LEG_OTHER = kani::any();
    }
    g
}

/// = kani_growth_t1_required_imr_bounds (same assertions and covers), dyn by S5d.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_t1n_required_imr_bounds() {
    let g = any_gate_nc(kani::any());
    kani::assume(g.engine_imr_bps <= 10_000);
    let r = growth_required_imr_bps(&g);
    if let Ok(r) = r {
        assert!(r >= g.engine_imr_bps && r <= 10_000);
    }
    let crowd = g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q));
    let over = g.lp.is_some_and(|l| ncap().is_some_and(|n| l.users_oi_side_after_q > n));
    kani::cover!(r.is_ok() && g.lp.is_some(), "crowd or thin, admitted");
    kani::cover!(r == Err(GrowthVerdict::LeverageExceeded), "ceil < engine refused");
    kani::cover!(g.lp.is_some() && ncap().is_none() && !(crowd && g.crowd_blocked) && r == Err(GrowthVerdict::CapacityFull), "N_cap None refused");
    kani::cover!(crowd && !g.crowd_blocked && over && r == Err(GrowthVerdict::CapacityFull), "dyn None: crowd past N_cap");
    kani::cover!(crowd && !g.crowd_blocked && r.is_ok_and(|x| x > g.ceil_imr_bps), "dyn Some above the kink");
}

/// = kani_growth_t4_overflow_fails_closed (same assertions and covers), dyn by S5d.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_t4n_overflow_fails_closed() {
    let g = any_gate_nc(true);
    let v = growth_gate(&g);
    let inc = taker_risk_increasing(g.taker_before_q, g.taker_after_q);
    if inc && v == GrowthVerdict::Allow {
        assert!(ncap().is_some() && risk().is_some(), "Allow implies N_cap and notional are Some");
    }
    let l = g.lp.unwrap();
    let crowd = joins_crowd(l.mid_q, l.after_q);
    let gate_ok = inc && g.asset_bound && g.price_e6 != 0 && g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps && !(crowd && g.crowd_blocked);
    kani::cover!(gate_ok && ncap().is_none() && v == GrowthVerdict::CapacityFull, "N_cap None refused");
    kani::cover!(gate_ok && risk().is_none() && v == GrowthVerdict::LeverageExceeded, "notional None refused");
    kani::cover!(gate_ok && risk().is_some() && unsafe { G_LEG_OTHER.is_none() && g.ceil_imr_bps != G_LEG_KEY } && v == GrowthVerdict::LeverageExceeded, "leg None refused");
    kani::cover!(gate_ok && crowd && ncap().is_some_and(|n| n > u64::MAX as u128 && l.users_oi_side_after_q <= n) && v == GrowthVerdict::Allow, "full-width admit");
    // review 2026-10-14: asserted-path covers (inc && Allow) on the thin branch / wide notional
    kani::cover!(gate_ok && !crowd && ncap().is_some_and(|n| n > u64::MAX as u128 && l.users_oi_side_after_q > u64::MAX as u128) && v == GrowthVerdict::Allow, "rv: full-width thin admit");
    kani::cover!(inc && v == GrowthVerdict::Allow && risk().is_some_and(|x| x > u64::MAX as u128), "rv: full-width notional admit");
}

/// = kani_growth_t5_capacity_invariant (same assertion and covers), dyn by S5d.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_t5n_capacity_invariant() {
    let g = any_gate_nc(true);
    kani::assume(taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    let l = g.lp.unwrap();
    let v = growth_gate(&g);
    if v == GrowthVerdict::Allow {
        assert!(ncap().is_some_and(|n| l.users_oi_side_after_q <= n));
    }
    let crowd = joins_crowd(l.mid_q, l.after_q);
    kani::cover!(v == GrowthVerdict::Allow && ncap() == Some(l.users_oi_side_after_q) && l.users_oi_side_after_q > 0, "u == 1 admitted");
    kani::cover!(v == GrowthVerdict::CapacityFull && ncap().is_some_and(|n| l.users_oi_side_after_q > n) && crowd, "dyn None: crowd past N_cap");
    kani::cover!(v == GrowthVerdict::CapacityFull && ncap().is_some_and(|n| l.users_oi_side_after_q > n) && !crowd, "thin past N_cap");
    kani::cover!(v == GrowthVerdict::CapacityFull && ncap() == Some(0) && g.asset_bound, "N_cap 0 refuses");
    kani::cover!(v == GrowthVerdict::CapacityFull && ncap().is_none(), "N_cap None refuses");
    // review 2026-10-14: covers on the ASSERTED path (v == Allow), one per gate branch
    kani::cover!(v == GrowthVerdict::Allow && !crowd && ncap() == Some(l.users_oi_side_after_q) && l.users_oi_side_after_q > 0, "rv: thin open lands exactly on N_cap (Q3)");
    kani::cover!(v == GrowthVerdict::Allow && crowd && ncap() == Some(l.users_oi_side_after_q) && l.users_oi_side_after_q > 0, "rv: crowd open lands exactly on N_cap");
    kani::cover!(v == GrowthVerdict::Allow && ncap().is_some_and(|n| n > u64::MAX as u128) && l.users_oi_side_after_q > u64::MAX as u128, "rv: full-width admit");
    kani::cover!(v == GrowthVerdict::Allow && g.taker_cert_initial_req.is_some(), "rv: admitted through the cert path");
}

/// = kani_growth_r2_r12_every_open_faces_the_bound_vault_lp (same assertions and covers).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_r2n_r12_every_open_faces_the_bound_vault_lp() {
    let g = any_gate_nc(kani::any());
    let v = growth_gate(&g);
    let opens = taker_risk_increasing(g.taker_before_q, g.taker_after_q);
    if v == GrowthVerdict::Allow && opens {
        assert!(g.lp.is_some() && g.asset_bound);
    }
    if opens && !g.asset_bound {
        assert_eq!(v, GrowthVerdict::NotBound);
    }
    kani::cover!(opens && g.asset_bound && g.lp.is_none() && v == GrowthVerdict::NoLpCounterparty, "no LP refused");
    kani::cover!(opens && !g.asset_bound, "unbound refused");
    kani::cover!(!opens && g.lp.is_none() && g.taker_after_q != g.taker_before_q, "close without LP allowed");
    kani::cover!(opens && v == GrowthVerdict::Allow, "admitted open");
    kani::cover!(opens && v == GrowthVerdict::Allow && g.lp.is_some_and(|l| !joins_crowd(l.mid_q, l.after_q)), "rv: admitted thin open");
    kani::cover!(opens && v == GrowthVerdict::Allow && g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q)), "rv: admitted crowd open");
    kani::cover!(opens && g.asset_bound && g.price_e6 != 0 && g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q) && ncap().is_some_and(|n| l.users_oi_side_after_q > n)) && !g.crowd_blocked && v == GrowthVerdict::CapacityFull, "dyn None refused");
    kani::cover!(opens && g.asset_bound && g.price_e6 == 0 && g.lp.is_some() && v == GrowthVerdict::LeverageExceeded, "price 0 refused before n_cap_q");
}

// R11 (inductive capacity invariant) with dyn by S5d. Helpers copied verbatim from proofs.rs
// (`side_oi`, `inv`, `admits`), statics renamed.
fn side_oi(p: &[i128; 3], long: bool) -> u128 {
    let mut s = 0u128;
    for x in p.iter() {
        if (long && *x > 0) || (!long && *x < 0) {
            s += x.unsigned_abs();
        }
    }
    s
}

fn inv(p: &[i128; 3], n: u128) -> bool {
    let l = side_oi(p, true);
    let s = side_oi(p, false);
    let lp = (p[0] + p[1] + p[2]).unsigned_abs();
    l <= n && s <= n && lp <= l.max(s)
}

fn admits(p: &[i128; 3], i: usize, d: i128, n: u128) -> bool {
    unsafe {
        G_NCAP = Some(n);
        G_RISK = kani::any();
        G_LEG_KEY = 1_000;
        G_LEG_AT_KEY = kani::any();
        G_LEG_OTHER = kani::any();
        G_DYN = None;
    }
    let lp = -(p[0] + p[1] + p[2]);
    let before = p[i];
    let after = before + d;
    let mut q = *p;
    q[i] = after;
    let g = GrowthGateIn {
        taker_before_q: before,
        taker_after_q: after,
        taker_eff_after_abs_q: after.unsigned_abs(),
        taker_equity: u128::MAX / 4,
        taker_cert_initial_req: None,
        lp: Some(GrowthLpIn {
            before_q: lp,
            mid_q: lp_mid_q(lp, before, after).unwrap(),
            after_q: lp - d,
            eff_after_abs_q: (lp - d).unsigned_abs(),
            // review 2026-10-14: the lpnet_mutant hook of the original r11 (pre-N-1 |LP| net
            // measure), restored so the nc twin can be watched FAILING on it.
            #[cfg(not(feature = "lpnet_mutant"))]
            users_oi_side_after_q: side_oi(&q, after > 0),
            #[cfg(feature = "lpnet_mutant")]
            users_oi_side_after_q: (lp - d).unsigned_abs(),
            equity: n,
        }),
        price_e6: 1,
        pos_scale: 1,
        engine_imr_bps: 1_000,
        min_nonzero_im_req: 0,
        ceil_imr_bps: 1_000,
        lambda_bps: 10_000,
        kink_bps: 5_000,
        crowd_blocked: false,
        asset_bound: true,
    };
    growth_gate(&g) == GrowthVerdict::Allow
}

/// = kani_growth_r11_capacity_invariant_inductive (same bound: i64 positions/step, u64 n, ANY
/// N_cap value), dyn by S5d.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_r11n_capacity_invariant_inductive() {
    let p = [kani::any::<i64>() as i128, kani::any::<i64>() as i128, kani::any::<i64>() as i128];
    let n = kani::any::<u64>() as u128;
    let i: usize = kani::any();
    kani::assume(i < 3);
    let d = kani::any::<i64>() as i128;
    kani::assume(d != 0 && inv(&p, n));
    let ok = admits(&p, i, d, n);
    let mut q = p;
    q[i] += d;
    if ok {
        assert!(inv(&q, n));
    }
    kani::cover!(ok && side_oi(&q, q[i] > 0) == n && n > 0 && taker_risk_increasing(p[i], q[i]), "open lands on N_cap");
    kani::cover!(!ok && taker_risk_increasing(p[i], q[i]), "open past N_cap refused");
    kani::cover!(ok && taker_strictly_reduces(p[i], q[i]) && (p[0] + p[1] + p[2]).unsigned_abs() as u128 == n, "close from |LP| = N_cap");
    kani::cover!(ok && taker_flips(p[i], q[i]), "flip admitted");
    let lp = -(p[0] + p[1] + p[2]);
    let crowd = joins_crowd(lp_mid_q(lp, p[i], q[i]).unwrap(), lp - d);
    kani::cover!(!ok && crowd && taker_risk_increasing(p[i], q[i]), "dyn -> None (crowd open past N_cap)");
    kani::cover!(ok && crowd && taker_risk_increasing(p[i], q[i]), "dyn -> Some (crowd open admitted)");
    // review 2026-10-14: asserted-path covers for the THIN branch and a tight two-sided state
    kani::cover!(ok && !crowd && taker_risk_increasing(p[i], q[i]) && side_oi(&q, q[i] > 0) == n && n > 0, "rv: thin open lands on N_cap");
    kani::cover!(ok && taker_risk_increasing(p[i], q[i]) && side_oi(&q, true) == n && side_oi(&q, false) == n && n > 0, "rv: both sides full after an admitted open");
}

// ── relational shape harnesses (originals NO-VERDICT): primitives by their SHAPE contract ──
// `*_shape` = the proven primitive contract WITHOUT the exact quotient relation: None ⇔ d == 0 ∨
// a·b overflows; Some(q) otherwise with the range facts (b <= d ⇒ q <= a; ceil also b >= d ⇒
// q >= a). A superset of the real primitive's behaviours (by kani_growth_c_mul_div_*), so sound.
fn ceil_shape(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 || a.checked_mul(b).is_none() {
        return None;
    }
    let q: u128 = kani::any();
    kani::assume((b > d || q <= a) && (b < d || q >= a));
    Some(q)
}
fn floor_shape(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 || a.checked_mul(b).is_none() {
        return None;
    }
    let q: u128 = kani::any();
    kani::assume(b > d || q <= a);
    Some(q)
}

/// = kani_growth_t2_dyn_shape_in_lp (same assertions and covers).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_lp() {
    let lp1: u128 = kani::any();
    let lp2: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(lp1 <= lp2);
    let r1 = dyn_imr_bps(lp1, n, base, k);
    let r2 = dyn_imr_bps(lp2, n, base, k);
    if r1.is_none() {
        assert!(r2.is_none(), "E1: refuse at lp1 => refuse at lp2");
    }
    let rhs = (k as u128).checked_mul(n);
    let below = |lp: u128| lp.checked_mul(10_000).is_some_and(|a| rhs.is_some_and(|b| a <= b));
    if below(lp2) {
        assert!(below(lp1), "branch selection monotone");
    }
    if let (Some(a), Some(b)) = (r1, r2) {
        if below(lp1) {
            assert!(a == base && b >= a, "base <= stepped (P3)");
        }
    }
    kani::cover!(r1.is_none() && lp1 <= n && lp1.checked_mul(10_000).is_none(), "E1: lp*1e4 overflow");
    kani::cover!(r1.is_none() && lp1 <= n && lp1.checked_mul(10_000).is_some() && 10_000u128.checked_sub(k as u128).is_some_and(|f| n.checked_mul(f).is_some()) && base <= 10_000 && k <= 10_000, "E1: span*num overflow");
    kani::cover!(r1.is_some() && r2.is_none() && lp2 > n, "E1: lp > n");
    kani::cover!(r1.is_some_and(|a| a > base) && r2.is_some_and(|b| b > base), "both stepped");
}

/// = kani_growth_t2_dyn_shape_in_ncap (same assertions and covers).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_ncap() {
    let lp: u128 = kani::any();
    let n1: u128 = kani::any();
    let n2: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(n1 <= n2 && n2 <= 100_000_000_000_000_000_000_000 && base <= 10_000 && k <= 10_000);
    let r1 = dyn_imr_bps(lp, n1, base, k);
    let r2 = dyn_imr_bps(lp, n2, base, k);
    if lp <= n1 && n1 > 0 {
        assert!(r1.is_some() && r2.is_some(), "E2-style: no overflow None on the engine domain");
    }
    if r2.is_none() && n2 > 0 {
        assert!(r1.is_none(), "E1: refuse at the larger capacity => refuse at the smaller");
    }
    kani::cover!(r1.is_some_and(|a| r2.is_some_and(|b| b < a)), "more capacity, cheaper");
    kani::cover!(r1.is_none() && r2.is_some() && lp > n1, "capacity opens the crowd");
}

/// = kani_growth_t2_required_shape_engine_domain (same assertions and cover).
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, floor_shape)]
fn kani_growth_t2n_required_shape_engine_domain() {
    let c1: u128 = kani::any();
    let c2: u128 = kani::any();
    let l: u32 = kani::any();
    let p: u64 = kani::any();
    kani::assume(c1 <= c2 && c2 <= 10_000_000_000_000_000 && l <= 100_000 && p >= 1);
    let n1 = n_cap_q(c1, l, p, 1_000_000);
    let n2 = n_cap_q(c2, l, p, 1_000_000);
    assert!(n1.is_some() && n2.is_some(), "no overflow None on the engine domain");
    assert!(c1 * l as u128 <= c2 * l as u128);
    kani::cover!(n1.is_some_and(|a| n2.is_some_and(|b| a < b)), "capacity grows with capital");
}

/// = kani_growth_r15ab_util_fee_shape_and_monotone (same assertions and covers).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_r15abn_util_fee_shape_and_monotone() {
    let o1: u128 = kani::any();
    let o2: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    kani::assume(o1 <= o2);
    let f1 = utilisation_fee_bps(o1, n, k, m);
    let f2 = utilisation_fee_bps(o2, n, k, m);
    if f1.is_none() {
        assert!(f2.is_none(), "E1: None at o1 => None at o2");
    }
    if f2 == Some(0) {
        assert!(f1 == Some(0) || f1.is_none(), "kink selection monotone");
    }
    if let (Some(a), Some(b)) = (f1, f2) {
        assert!(a <= m && b <= m);
        if b == m || a == 0 {
            assert!(a <= b);
        }
    }
    kani::cover!(f1.is_none() && n > 0 && k <= 10_000 && o1.checked_mul(10_000).is_none(), "E1: o*1e4 overflow");
    kani::cover!(f1.is_none() && n > 0 && k <= 10_000 && o1.checked_mul(10_000).is_some(), "E1: inner overflow");
    kani::cover!(f1 == Some(0) && f2.is_some_and(|b| b > 0), "crosses the kink");
    kani::cover!(f1.is_some_and(|a| a > 0 && a < m) && f2 == Some(m), "slope to cap");
}

/// = kani_growth_r15b_util_fee_monotone_in_max (same assertions and covers).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_r15bn_util_fee_monotone_in_max() {
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m1: u16 = kani::any();
    let m2: u16 = kani::any();
    kani::assume(m1 <= m2 && m1 > 0);
    let a = utilisation_fee_bps(o, n, k, m1);
    let b = utilisation_fee_bps(o, n, k, m2);
    if a.is_none() {
        assert!(b.is_none(), "E1: None at m1 => None at m2");
    }
    if let (Some(a), Some(b)) = (a, b) {
        assert!(a <= m1 && b <= m2, "clamped at the dial");
    }
    kani::cover!(a.is_none() && o.checked_mul(10_000).is_some() && n > 0 && k <= 10_000, "E1: max*num overflow");
    kani::cover!(a.is_some_and(|x| b.is_some_and(|y| x < y)), "raised dial charges more");
}

// ── g_* full-width twins (originals NO-VERDICT under cadical 4000 s and z3 300 s): the SAME
// assertions and covers, primitive by its shape contract (sound: see ceil_shape/floor_shape).

/// = kani_growth_g_dyn_imr_bps.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_gn_dyn_imr_bps() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    let valid = base <= 10_000 && k as u128 <= 10_000;
    if !valid || n == 0 || lp > n {
        assert!(r.is_none());
    }
    let lhs = lp.checked_mul(10_000);
    let rhs = (k as u128).checked_mul(n);
    if valid && n > 0 && lp <= n {
        if lhs.is_none() || rhs.is_none() {
            assert!(r.is_none(), "lp*1e4 / k*n overflow -> None");
        } else if lhs.unwrap() <= rhs.unwrap() {
            assert_eq!(r, Some(base), "at or below the kink");
        } else if n.checked_mul(10_000 - k as u128).is_none() {
            assert!(r.is_none(), "n*(1e4-k) overflow -> None");
        }
    }
    if let Some(v) = r {
        assert!(v >= base && v <= 10_000);
    }
    kani::cover!(valid && n > 0 && lp <= n && lhs.is_none() && r.is_none(), "None: lp*1e4 overflow (u128 x const)");
    kani::cover!(valid && lp <= n && lhs.is_some_and(|a| rhs.is_some_and(|b| a > b)) && n.checked_mul(10_000 - k as u128).is_none() && r.is_none(), "None: n*(1e4-k) overflow (u128 x <=1e4)");
    kani::cover!(valid && lp <= n && n.checked_mul(10_000 - k as u128).is_some() && lhs.is_some_and(|a| rhs.is_some_and(|b| a > b)) && r.is_none(), "None: span*num overflow (primitive) / base+extra");
    kani::cover!(r.is_some_and(|v| v > base) && n > u64::MAX as u128, "Some: stepped at full width");
}

/// = kani_growth_g_utilisation_fee_bps.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_gn_utilisation_fee_bps() {
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    let r = utilisation_fee_bps(o, n, k, m);
    if n == 0 || k as u128 > 10_000 {
        assert!(r.is_none());
    } else {
        let lhs = o.checked_mul(10_000);
        let rhs = (k as u128).checked_mul(n);
        if lhs.is_none() || rhs.is_none() {
            assert!(r.is_none(), "o*1e4 / k*n overflow -> None");
        } else if lhs.unwrap() <= rhs.unwrap() || m == 0 {
            assert_eq!(r, Some(0), "at or below the kink, or max 0");
        } else if n.checked_mul(10_000 - k as u128).is_none() {
            assert!(r.is_none(), "n*(1e4-k) overflow -> None");
        }
    }
    if let Some(f) = r {
        assert!(f <= m);
    }
    kani::cover!(n > 0 && k <= 10_000 && o.checked_mul(10_000).is_none() && r.is_none(), "None: o*1e4 overflow (u128 x const)");
    kani::cover!(n > 0 && k <= 10_000 && o.checked_mul(10_000).is_some() && (k as u128).checked_mul(n).is_none() && r.is_none(), "None: k*n overflow (u16 x u128)");
    kani::cover!(n > 0 && k < 10_000 && n.checked_mul(10_000 - k as u128).is_none() && r.is_none() && o.checked_mul(10_000).is_some_and(|a| (k as u128).checked_mul(n).is_some_and(|b| a > b)) && m > 0, "None: n*(1e4-k) overflow (u128 x <=1e4)");
    kani::cover!(r.is_some_and(|f| f > 0) && n > u64::MAX as u128, "Some: charged at full width");
}

/// = kani_growth_g_util_fee_on_fill_bps (its `requires` assumed exactly as in the original).
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, floor_shape)]
fn kani_growth_gn_util_fee_on_fill_bps() {
    let f: u16 = kani::any();
    let o: u128 = kani::any();
    let fill: u128 = kani::any();
    kani::assume((f as u128).checked_mul(core::cmp::min(o, fill)).is_some());
    let r = util_fee_on_fill_bps(f, o, fill);
    if fill == 0 || o == 0 || f == 0 {
        assert_eq!(r, 0);
    }
    assert!(r <= f, "cast after the clamp: never above the fee");
    kani::cover!(o > fill && (f as u128).checked_mul(o).is_some_and(|x| x > 65_535u128.saturating_mul(fill)), "opening > fill with fee*opening/fill > 65,535");
    kani::cover!(fill > u64::MAX as u128 && r > 0 && r < f, "Some: full-width flip share");
    kani::cover!(r == f && f > 0 && fill > u64::MAX as u128, "full rate at full width");
}

// ── OV: overflow of a·x is monotone in x (lemma; instantiated in the *_lem harnesses) ────────
/// For every u128 a, x <= y: a·x overflows ⇒ a·y overflows. (Full width.)
#[kani::proof]
fn kani_growth_ov_mul_overflow_monotone() {
    let a: u128 = kani::any();
    let x: u128 = kani::any();
    let y: u128 = kani::any();
    kani::assume(x <= y);
    if a.checked_mul(x).is_none() {
        assert!(a.checked_mul(y).is_none());
    }
    kani::cover!(a.checked_mul(x).is_none(), "overflow at x");
    kani::cover!(a.checked_mul(x).is_some() && a.checked_mul(y).is_none(), "overflow only at y");
}

/// = kani_growth_t2_dyn_shape_in_lp, with ONE instance of lemma OV16 assumed (a = span <= 1e4,
/// x = num(lp1), y = num(lp2); proved for all such values by kani_growth_ov16_mul_overflow_monotone)
/// and DIST instances (kani_growth_dist_num_le_den).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_lp_lem() {
    let lp1: u128 = kani::any();
    let lp2: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(lp1 <= lp2);
    // OV instance (only meaningful on the stepped path; vacuous elsewhere)
    if base <= MAX_IMR_BPS && k as u128 <= 10_000 {
        let span = (MAX_IMR_BPS - base) as u128;
        let rhs0 = (k as u128).checked_mul(n);
        if let (Some(a1), Some(a2), Some(b)) = (lp1.checked_mul(10_000), lp2.checked_mul(10_000), rhs0) {
            if a1 > b {
                kani::assume(span.checked_mul(a1 - b).is_some() || span.checked_mul(a2 - b).is_none());
            }
        }
    }
    dist_instance(lp1, n, k);
    dist_instance(lp2, n, k);
    let r1 = dyn_imr_bps(lp1, n, base, k);
    let r2 = dyn_imr_bps(lp2, n, base, k);
    if r1.is_none() {
        assert!(r2.is_none(), "E1: refuse at lp1 => refuse at lp2");
    }
    let rhs = (k as u128).checked_mul(n);
    let below = |lp: u128| lp.checked_mul(10_000).is_some_and(|a| rhs.is_some_and(|b| a <= b));
    if below(lp2) {
        assert!(below(lp1), "branch selection monotone");
    }
    if let (Some(a), Some(b)) = (r1, r2) {
        if below(lp1) {
            assert!(a == base && b >= a, "base <= stepped (P3)");
        }
    }
    kani::cover!(r1.is_none() && lp1 <= n && lp1.checked_mul(10_000).is_none(), "E1: lp*1e4 overflow");
    kani::cover!(r1.is_none() && lp1 <= n && lp1.checked_mul(10_000).is_some() && 10_000u128.checked_sub(k as u128).is_some_and(|f| n.checked_mul(f).is_some()) && base <= 10_000 && k <= 10_000, "E1: span*num overflow");
    kani::cover!(r1.is_some() && r2.is_none() && lp2 > n, "E1: lp > n");
    kani::cover!(r1.is_some_and(|a| a > base) && r2.is_some_and(|b| b > base), "both stepped");
}

// ── DIST: lp <= n ⇒ lp·1e4 − k·n <= n·(1e4 − k) (num <= den; distributivity) ─────────────────
fn dist_holds(lp: u128, n: u128, k: u16) -> bool {
    if k as u128 > 10_000 || lp > n {
        return true;
    }
    match (lp.checked_mul(10_000), (k as u128).checked_mul(n), n.checked_mul(10_000 - k as u128)) {
        (Some(a), Some(b), Some(d)) if a > b => a - b <= d,
        _ => true,
    }
}
/// Assume ONE instance of DIST (proved for all values by kani_growth_dist_num_le_den).
fn dist_instance(lp: u128, n: u128, k: u16) {
    kani::assume(dist_holds(lp, n, k));
}

/// DIST, full width.
#[kani::proof]
fn kani_growth_dist_num_le_den() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    assert!(dist_holds(lp, n, k));
    kani::cover!(k < 10_000 && lp == n && lp > 0 && n.checked_mul(10_000).is_some(), "num == den at u == 1");
    kani::cover!(k < 10_000 && lp < n && lp.checked_mul(10_000).is_some_and(|a| (k as u128).checked_mul(n).is_some_and(|b| a > b)), "stepped, num < den");
}

/// = kani_growth_t2_dyn_shape_in_ncap, with DIST instances assumed at (lp, n1) and (lp, n2).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_ncap_lem() {
    let lp: u128 = kani::any();
    let n1: u128 = kani::any();
    let n2: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(n1 <= n2 && n2 <= 100_000_000_000_000_000_000_000 && base <= 10_000 && k <= 10_000);
    dist_instance(lp, n1, k);
    dist_instance(lp, n2, k);
    let r1 = dyn_imr_bps(lp, n1, base, k);
    let r2 = dyn_imr_bps(lp, n2, base, k);
    if lp <= n1 && n1 > 0 {
        assert!(r1.is_some() && r2.is_some(), "E2-style: no overflow None on the engine domain");
    }
    if r2.is_none() && n2 > 0 {
        assert!(r1.is_none(), "E1: refuse at the larger capacity => refuse at the smaller");
    }
    kani::cover!(r1.is_some_and(|a| r2.is_some_and(|b| b < a)), "more capacity, cheaper");
    kani::cover!(r1.is_none() && r2.is_some() && lp > n1, "capacity opens the crowd");
}

/// OV at the width every instance uses (a = span <= 1e4 or a = max fee: u16; x, y full u128):
/// a·x overflows ∧ x <= y ⇒ a·y overflows.
#[kani::proof]
fn kani_growth_ov16_mul_overflow_monotone() {
    let a = kani::any::<u16>() as u128;
    let x: u128 = kani::any();
    let y: u128 = kani::any();
    kani::assume(x <= y);
    if a.checked_mul(x).is_none() {
        assert!(a.checked_mul(y).is_none());
    }
    kani::cover!(a.checked_mul(x).is_none(), "overflow at x");
    kani::cover!(a.checked_mul(x).is_some() && a.checked_mul(y).is_none(), "overflow only at y");
}

// ── R15c split (original NO-VERDICT: cadical 4000 s, z3 300 s) ──────────────────────────────
// R15c: closes never pay; a flip's closing part is never charged: r·fill <= fee·min(o, fill).
// (a) here: the REAL opening_part_q / taker predicates, with util_fee_on_fill_bps replaced by a
//     ∀-value stub constrained only by S7 (zero input ⇒ 0; otherwise r = min(floor(..), fee)):
//     strict reductions have o == 0 and pay 0; every o handed to the fee is <= fill for flips
//     and == fill for plain opens.
// (b) S7 (r = min(x, fee), x = floor(fee·min(o,fill)/fill)) + the floor contract
//     (x·fill <= fee·min(o,fill), and x <= fee since min(o,fill) <= fill: range fact) ⇒ r = x and
//     r·fill <= fee·min(o, fill). No further machine step: it is the contract's own relation.
fn fill_fee_s7(fee: u16, o: u128, fill: u128) -> u16 {
    if fill == 0 || o == 0 || fee == 0 {
        return 0;
    }
    let r: u16 = kani::any();
    kani::assume(r <= fee);
    r
}

#[kani::proof]
#[kani::stub(crate::growth_v19::util_fee_on_fill_bps, fill_fee_s7)]
fn kani_growth_r15cn_a_opening_part() {
    let b: i64 = kani::any();
    let a: i64 = kani::any();
    let fee: u16 = kani::any();
    kani::assume(fee <= 2_000);
    let (b, a) = (b as i128, a as i128);
    let o = opening_part_q(b, a);
    let fill = b.abs_diff(a);
    if taker_strictly_reduces(b, a) {
        assert_eq!(o, 0);
        assert_eq!(util_fee_on_fill_bps(fee, o, fill), 0);
    }
    if taker_flips(b, a) {
        assert!(o == a.unsigned_abs() && o <= fill, "flip: only |after| opens");
    } else if !taker_strictly_reduces(b, a) {
        assert!(o == fill, "plain open / grow: the whole fill opens");
    }
    let r = util_fee_on_fill_bps(fee, o, fill);
    assert!(r <= fee);
    kani::cover!(taker_flips(b, a) && o < fill && o > 0, "flip pays only its opening part");
    kani::cover!(taker_strictly_reduces(b, a) && a != b, "reduce pays 0");
    kani::cover!(!taker_strictly_reduces(b, a) && !taker_flips(b, a) && o == fill && fill > 0, "plain open: whole fill");
}

// ── ENGINE-DOMAIN variants (BOUNDED: every position / capacity <= 1e23 = MAX_VAULT_TVL·λmax·POS
// /1e4, the bound kani_growth_t2_dyn_shape_in_ncap already uses). On this domain the primitive
// never overflows (span·num <= 1e4·1e27 < 2^128), so lemma OV is not needed; DIST is used only
// on this domain (kani_growth_dist_dom_num_le_den).
const DOM: u128 = 100_000_000_000_000_000_000_000;

/// DIST on the engine domain (n <= 1e23).
#[kani::proof]
fn kani_growth_dist_dom_num_le_den() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    kani::assume(n <= DOM);
    assert!(dist_holds(lp, n, k));
    kani::cover!(k < 10_000 && lp == n && lp > 0, "num == den at u == 1");
    kani::cover!(k < 10_000 && lp < n && lp.checked_mul(10_000).is_some_and(|a| (k as u128).checked_mul(n).is_some_and(|b| a > b)), "stepped, num < den");
}

/// = kani_growth_t2_dyn_shape_in_lp on the engine domain (lp1, lp2, n <= 1e23); DIST_dom instances.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_lp_dom() {
    let lp1: u128 = kani::any();
    let lp2: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(lp1 <= lp2 && lp2 <= DOM && n <= DOM);
    dist_instance(lp1, n, k);
    dist_instance(lp2, n, k);
    let r1 = dyn_imr_bps(lp1, n, base, k);
    let r2 = dyn_imr_bps(lp2, n, base, k);
    if r1.is_none() {
        assert!(r2.is_none(), "E1: refuse at lp1 => refuse at lp2");
    }
    let rhs = (k as u128).checked_mul(n);
    let below = |lp: u128| lp.checked_mul(10_000).is_some_and(|a| rhs.is_some_and(|b| a <= b));
    if below(lp2) {
        assert!(below(lp1), "branch selection monotone");
    }
    if let (Some(a), Some(b)) = (r1, r2) {
        if below(lp1) {
            assert!(a == base && b >= a, "base <= stepped (P3)");
        }
    }
    kani::cover!(r1.is_some() && r2.is_none() && lp2 > n, "E1: lp > n");
    kani::cover!(r1.is_none() && base > MAX_IMR_BPS, "E1: invalid base");
    kani::cover!(r1 == Some(base) && r2.is_some_and(|b| b > base), "crosses the kink");
    kani::cover!(r1.is_some_and(|a| a > base) && r2.is_some_and(|b| b > base), "both stepped");
}

/// = kani_growth_t2_dyn_shape_in_ncap (its own domain), DIST_dom instances.
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t2n_dyn_shape_in_ncap_dom() {
    let lp: u128 = kani::any();
    let n1: u128 = kani::any();
    let n2: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    kani::assume(n1 <= n2 && n2 <= DOM && base <= 10_000 && k <= 10_000);
    dist_instance(lp, n1, k);
    dist_instance(lp, n2, k);
    let r1 = dyn_imr_bps(lp, n1, base, k);
    let r2 = dyn_imr_bps(lp, n2, base, k);
    if lp <= n1 && n1 > 0 {
        assert!(r1.is_some() && r2.is_some(), "E2-style: no overflow None on the engine domain");
    }
    if r2.is_none() && n2 > 0 {
        assert!(r1.is_none(), "E1: refuse at the larger capacity => refuse at the smaller");
    }
    kani::cover!(r1.is_some_and(|a| r2.is_some_and(|b| b < a)), "more capacity, cheaper");
    kani::cover!(r1.is_none() && r2.is_some() && lp > n1, "capacity opens the crowd");
}

/// = kani_growth_r15ab_util_fee_shape_and_monotone on the engine domain (o1, o2, n <= 1e23).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_r15abn_util_fee_shape_and_monotone_dom() {
    let o1: u128 = kani::any();
    let o2: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    kani::assume(o1 <= o2 && o2 <= DOM && n <= DOM);
    let f1 = utilisation_fee_bps(o1, n, k, m);
    let f2 = utilisation_fee_bps(o2, n, k, m);
    if f1.is_none() {
        assert!(f2.is_none(), "E1: None at o1 => None at o2");
    }
    if f2 == Some(0) {
        assert!(f1 == Some(0) || f1.is_none(), "kink selection monotone");
    }
    if let (Some(a), Some(b)) = (f1, f2) {
        assert!(a <= m && b <= m);
        if b == m || a == 0 {
            assert!(a <= b);
        }
    }
    kani::cover!(f1.is_none() && n == 0, "E1: n == 0");
    kani::cover!(f1 == Some(0) && f2.is_some_and(|b| b > 0), "crosses the kink");
    kani::cover!(f1.is_some_and(|a| a > 0 && a < m) && f2 == Some(m), "slope to cap");
}

/// = kani_growth_r15b_util_fee_monotone_in_max on the engine domain (o, n <= 1e23).
#[kani::proof]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_r15bn_util_fee_monotone_in_max_dom() {
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m1: u16 = kani::any();
    let m2: u16 = kani::any();
    kani::assume(m1 <= m2 && m1 > 0 && o <= DOM && n <= DOM);
    let a = utilisation_fee_bps(o, n, k, m1);
    let b = utilisation_fee_bps(o, n, k, m2);
    if a.is_none() {
        assert!(b.is_none(), "E1: None at m1 => None at m2");
    }
    if let (Some(a), Some(b)) = (a, b) {
        assert!(a <= m1 && b <= m2, "clamped at the dial");
    }
    kani::cover!(a.is_none() && n == 0, "E1: n == 0");
    kani::cover!(a.is_some_and(|x| b.is_some_and(|y| x < y)), "raised dial charges more");
}

/// = kani_growth_t5_at_capacity_costs_full_margin at its ORIGINAL bound (u8 N_cap): the real gate
/// and real `dyn_imr_bps`, N_cap by the ∀-stub set to n (as the original), ceil primitive by its
/// shape contract (at u == 1, num == den and the range facts force ceil == span).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::mul_div_ceil_u128, ceil_shape)]
fn kani_growth_t5n_at_capacity_costs_full_margin() {
    let n = kani::any::<u8>() as u128;
    kani::assume(n > 0);
    unsafe { G_NCAP = Some(n) };
    let lb: i8 = kani::any();
    let la: i8 = kani::any();
    let g = GrowthGateIn {
        taker_before_q: 0,
        taker_after_q: 1,
        taker_eff_after_abs_q: 1,
        taker_equity: 0,
        taker_cert_initial_req: None,
        lp: Some(GrowthLpIn {
            before_q: lb as i128,
            mid_q: lb as i128,
            after_q: la as i128,
            eff_after_abs_q: (la as i128).unsigned_abs(),
            users_oi_side_after_q: n,
            equity: 0,
        }),
        price_e6: 1,
        pos_scale: 1,
        engine_imr_bps: kani::any::<u16>() as u64,
        min_nonzero_im_req: 0,
        ceil_imr_bps: kani::any::<u16>() as u64,
        lambda_bps: 10_000,
        kink_bps: kani::any(),
        crowd_blocked: false,
        asset_bound: true,
    };
    kani::assume(joins_crowd(lb as i128, la as i128));
    kani::assume(g.kink_bps < 10_000 && g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps);
    let r = growth_required_imr_bps(&g);
    assert_eq!(r, Ok(10_000));
    kani::cover!(r == Ok(10_000) && g.ceil_imr_bps < 10_000 && g.kink_bps > 0, "full margin at capacity");
}

/// = kani_growth_w_g2_required_imr_not_below_engine, FULL width (original: u8 operands, real
/// n_cap_q / dyn_imr_bps): `Ok(x) ⇒ engine <= x <= MAX` for EVERY N_cap value (∀-stub) and every
/// gate field; dyn by S5d. No assumption on engine_imr_bps. Same covers as the original.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_any)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_any)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_any)]
#[kani::stub(crate::growth_v19::dyn_imr_bps, dyn_any_guarded)]
fn kani_growth_wn_g2_required_imr_not_below_engine() {
    let g = any_gate_nc(kani::any());
    let r = growth_required_imr_bps(&g);
    if let Ok(x) = r {
        assert!(x >= g.engine_imr_bps, "never below the engine IMR");
        assert!(x <= MAX_IMR_BPS);
    }
    let crowd = g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q));
    kani::cover!(r.is_ok() && g.lp.is_none(), "no LP: ceiling");
    kani::cover!(r.is_ok() && g.lp.is_some() && !crowd, "thin open: ceiling");
    kani::cover!(r.is_ok_and(|x| x > g.ceil_imr_bps) && crowd, "crowd above the kink");
    kani::cover!(r == Err(GrowthVerdict::LeverageExceeded), "ceil below engine refused");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull), "capacity refused");
}

// ── W-G-1 split: growth_margin_required with two legs related ONLY by proven facts ────────────
// leg_mono: a MEMOISED ∀-value stub (same args ⇒ same value, so the harness's legs and the
// production call's legs are the same values), constrained only by
//   S4: n == 0 ⇒ Some(0); imr > 1e4 ⇒ None; else max(ceil(n·imr/1e4), m) >= m, and None only on
//       overflow, which cannot happen at u16 operands (ceil contract: None ⇔ a·b overflows);
//   LEGMONO: ceil(n·i/1e4) monotone in i (exhaustive native test
//       legmono_ceil_bps_monotone_in_imr_all_u16, NOT a Kani verdict), and max(., m) keeps order.
static mut LM: [(bool, u128, u64, u128, u128); 2] = [(false, 0, 0, 0, 0); 2];
fn leg_mono(n: u128, imr: u64, m: u128) -> Option<u128> {
    if n == 0 {
        return Some(0);
    }
    if imr > MAX_IMR_BPS {
        return None;
    }
    unsafe {
        for e in LM.iter() {
            if e.0 && e.1 == n && e.2 == imr && e.3 == m {
                return Some(e.4);
            }
        }
        let v: u128 = kani::any();
        kani::assume(v >= m);
        for e in LM.iter() {
            if e.0 && e.1 == n && e.3 == m {
                if imr >= e.2 {
                    kani::assume(v >= e.4);
                }
                if imr <= e.2 {
                    kani::assume(v <= e.4);
                }
            }
        }
        let slot = if LM[0].0 { 1 } else { 0 };
        assert!(!LM[slot].0, "at most two distinct leg calls");
        LM[slot] = (true, n, imr, m, v);
        Some(v)
    }
}

/// = kani_growth_t1_requirement_never_below_engine_or_per_asset (same bounds: u16 notional /
/// IMRs / min; same assertions and covers) on the REAL growth_margin_required, legs by S4 + LEGMONO.
#[kani::proof]
#[kani::stub(crate::growth_v19::leg_im_req, leg_mono)]
fn kani_growth_wn_g1_requirement_never_below_engine_or_per_asset() {
    unsafe { LM = [(false, 0, 0, 0, 0); 2] };
    let n = kani::any::<u16>() as u128;
    let eng = kani::any::<u16>() as u64;
    let dy = kani::any::<u16>() as u64;
    let m = kani::any::<u16>() as u128;
    let cert: Option<u128> = kani::any();
    kani::assume(eng <= 10_000 && dy <= 10_000);
    kani::assume(dy >= eng);
    let dyn_leg = leg_im_req(n, dy, m);
    let eng_leg = leg_im_req(n, eng, m);
    let r = growth_margin_required(cert, n, eng, dy, m);
    if let Some(r) = r {
        assert!(dyn_leg.is_some_and(|d| r >= d), "never below the per-asset (dyn) leg");
        if let (Some(c), Some(_e)) = (cert, eng_leg) {
            assert!(r >= c, "never below the engine certificate");
        }
    } else {
        assert!(cert.is_some() && cert.unwrap().saturating_sub(eng_leg.unwrap()).checked_add(dyn_leg.unwrap()).is_none());
    }
    kani::cover!(cert.is_some() && dy > eng && r.is_some_and(|x| x > cert.unwrap()), "cert path, dyn above engine");
    kani::cover!(cert.is_some_and(|c| eng_leg.is_some_and(|e| c < e)) && r.is_some(), "saturating path");
    kani::cover!(cert.is_none() && r.is_some() && n > 0, "no cert");
    kani::cover!(r.is_none(), "None refused (overflow)");
    // review 2026-10-14: tight cases of both asserted bounds
    kani::cover!(cert.is_some() && dy == eng && n > 0 && r.is_some_and(|x| x == cert.unwrap()), "rv: equal IMRs, r == cert (cert bound tight)");
    kani::cover!(cert.is_some() && n > 0 && r.is_some_and(|x| dyn_leg == Some(x) && x > 0), "rv: saturating, r == dyn leg (per-asset bound tight)");
}

// ── Review 2026-10-14 (growth lane): new harnesses ─────────────────────────────────────────

/// F5 link (ledger v22-market-simulations F5: N_cap applies to GROSS user OI per side). The
/// production `users_side_oi_q` (growth_v19.rs:525), fed the engine's per-side effective OI (the
/// sum over EVERY account on that side, users and the vault LP) and the vault LP's own effective
/// position, equals the GROSS users OI of that side -- exactly the measure `side_oi` that
/// r11n / R11 use as their model. Before this harness no growth proof referenced
/// `users_side_oi_q`, so a defect there (LP net, LP on the wrong side) survived every harness.
/// Bound: i64 positions (same as r11n), 3 users + the LP.
#[kani::proof]
fn kani_growth_rv_f5_users_side_oi_is_gross_users_oi() {
    let p = [kani::any::<i64>() as i128, kani::any::<i64>() as i128, kani::any::<i64>() as i128];
    let lp = kani::any::<i64>() as i128;
    let all = [p[0], p[1], p[2], lp];
    let mut oi_l = 0u128;
    let mut oi_s = 0u128;
    for x in all.iter() {
        if *x > 0 {
            oi_l += x.unsigned_abs();
        } else if *x < 0 {
            oi_s += x.unsigned_abs();
        }
    }
    let ul = users_side_oi_q(oi_l, lp, true);
    let us = users_side_oi_q(oi_s, lp, false);
    assert_eq!(ul, side_oi(&p, true), "long side: gross users OI");
    assert_eq!(us, side_oi(&p, false), "short side: gross users OI");
    let net = (p[0] + p[1] + p[2]).unsigned_abs();
    kani::cover!(lp > 0 && ul > 0 && us > 0, "LP long, both user sides open");
    kani::cover!(lp < 0 && ul > 0 && us > 0, "LP short, both user sides open");
    kani::cover!(lp == 0 && ul == us && ul > 0, "balanced book: both sides still count (F5)");
    kani::cover!(ul.max(us) != net, "gross per side differs from the users' net");
}

/// The primitive contracts (`kani_growth_c_mul_div_*`) run at u8 operands, where `a*b` NEVER
/// overflows, so their `None <=> d == 0 || a*b overflows` branch was never exercised. The
/// `*_shape` stubs and every overflow -> None composition step rely on it. Full u128 width here.
#[kani::proof]
fn kani_growth_rv_primitives_none_iff_full_width() {
    let a: u128 = kani::any();
    let b: u128 = kani::any();
    let d: u128 = kani::any();
    let ov = a.checked_mul(b).is_none();
    let f = crate::vault_lp_v18::mul_div_floor(a, b, d);
    let c = mul_div_ceil_u128(a, b, d);
    assert_eq!(f.is_none(), d == 0 || ov, "floor: None iff d == 0 or overflow");
    assert_eq!(c.is_none(), d == 0 || ov, "ceil: None iff d == 0 or overflow");
    kani::cover!(ov && d != 0 && f.is_none() && c.is_none(), "overflow -> None (unreachable at u8)");
    kani::cover!(!ov && d != 0 && a > u64::MAX as u128 && f.is_some() && c.is_some(), "wide, no overflow -> Some");
    kani::cover!(d == 0 && f.is_none(), "d == 0 -> None");
}

/// The range facts the compositions C15/C16/C17/R18 and the `*_shape` stubs use, at FULL u128
/// width (the v22 contracts prove them at u8 only + a paper width lift).
#[kani::proof]
fn kani_growth_rv_primitive_range_facts_full_width() {
    let a: u128 = kani::any();
    let b: u128 = kani::any();
    let d: u128 = kani::any();
    let f = crate::vault_lp_v18::mul_div_floor(a, b, d);
    let c = mul_div_ceil_u128(a, b, d);
    if let Some(q) = f {
        if b <= d {
            assert!(q <= a, "floor fact b <= d => q <= a");
        }
    }
    if let Some(q) = c {
        if b <= d {
            assert!(q <= a, "ceil fact b <= d => q <= a");
        }
        if b >= d {
            assert!(q >= a, "ceil fact b >= d => q >= a");
        }
    }
    kani::cover!(f.is_some_and(|q| b < d && q < a && a > u64::MAX as u128), "floor fact, wide");
    kani::cover!(c.is_some_and(|q| b > d && q > a && a > u64::MAX as u128), "ceil fact b > d, wide");
    kani::cover!(c.is_some_and(|q| b == d && q == a && a > 0), "ceil b == d");
}

// ── Review 2026-10-14: division-free order lemmas (one decisive attempt for L1/L3/L4) ───────
// L_i ⇐ (u8 primitive contract `kani_growth_c_mul_div_*`, PASS: the result satisfies the exact
// remainder relation) ∧ the lemma below, which states the order fact over ANY quotients that
// satisfy that relation -- multiplications of a u32 quotient by a u8 divisor only, no divider in
// the model. L2 = L1 by commutativity of `a.checked_mul(b)` (f(a, b, d) = f(b, a, d)).
fn rv_ceil_rel(p: u32, d: u32, q: u32) -> bool {
    // = spec::ceil_rel on this domain (d > 0): q·d >= p and (q − 1)·d < p (q == 0 iff p == 0)
    q.checked_mul(d).is_some_and(|x| x >= p) && (q == 0 || (q - 1) * d < p)
}
fn rv_floor_rel(p: u32, d: u32, q: u32) -> bool {
    q.checked_mul(d).is_some_and(|x| x <= p && p - x < d)
}

#[kani::proof]
fn kani_growth_rv_l1d_ceil_monotone_in_b_rel() {
    let (a, b1, b2, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    let (q1, q2): (u32, u32) = (kani::any(), kani::any());
    kani::assume(b1 <= b2 && d > 0 && q1 <= 65_025 && q2 <= 65_025);
    kani::assume(rv_ceil_rel(a * b1, d, q1) && rv_ceil_rel(a * b2, d, q2));
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && b1 < b2 && a > 0, "plateau");
}

#[kani::proof]
fn kani_growth_rv_l3d_ceil_antitone_in_d_rel() {
    let (a, b, d1, d2) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    let (q1, q2): (u32, u32) = (kani::any(), kani::any());
    kani::assume(d1 > 0 && d1 <= d2 && q1 <= 65_025 && q2 <= 65_025);
    kani::assume(rv_ceil_rel(a * b, d1, q1) && rv_ceil_rel(a * b, d2, q2));
    assert!(q2 <= q1);
    kani::cover!(q2 < q1, "strict");
    kani::cover!(q2 == q1 && d1 < d2 && a * b > 0, "plateau");
}

#[kani::proof]
fn kani_growth_rv_l4d_floor_monotone_in_a_rel() {
    let (a1, a2, b, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    let (q1, q2): (u32, u32) = (kani::any(), kani::any());
    kani::assume(a1 <= a2 && d > 0 && q1 <= 65_025 && q2 <= 65_025);
    kani::assume(rv_floor_rel(a1 * b, d, q1) && rv_floor_rel(a2 * b, d, q2));
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && a1 < a2 && b > 0, "plateau");
}

/// Negative control for the relation lemmas (must FAIL): same as L1d with the order reversed
/// on the inputs (b1 >= b2), proving the relation model admits counterexamples.
#[cfg(feature = "negctl")]
#[kani::proof]
fn kani_growth_rv_neg_l1d_reversed() {
    let (a, b1, b2, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    let (q1, q2): (u32, u32) = (kani::any(), kani::any());
    kani::assume(b1 >= b2 && d > 0 && q1 <= 65_025 && q2 <= 65_025);
    kani::assume(rv_ceil_rel(a * b1, d, q1) && rv_ceil_rel(a * b2, d, q2));
    assert!(q1 <= q2);
}
