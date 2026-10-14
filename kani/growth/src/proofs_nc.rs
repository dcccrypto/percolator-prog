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
