//! Kani harnesses for growth-v19 (production `growth_v19.rs` / `vault_lp_v18.rs`).
//! Design: ~/percolator-ops/ledger/kani-growth-v19-design-2026-10-04.md (rev 5) + the rev-6
//! redesign approved with amendments A1-A5 in kani-growth-v19-results-2026-10-04.md. Run ONCE:
//!   ./run_kani6.sh rev6          then          ./run_mutants.py rev6
//! Flags: `-Z function-contracts -Z stubbing`. Every harness carries `kani::cover!` witnesses;
//! SUCCESSFUL with an unsatisfied cover is VACUOUS and does not count.
//!
//! Assume-guarantee: only the `kani_growth_c_mul_div_*` primitive harnesses bit-blast a 128-bit
//! divider (u8 operands; width lift = the paper step in the results file). Every other harness
//! replaces the primitives / composite functions by their PROVEN exact contracts
//! (`#[kani::stub_verified]`), and every stubbed harness covers each reachable stub branch,
//! `None` included (unreachable branches are named in a comment at the harness).

use crate::growth_v19::*;
use crate::vault_lp_v18;

// ── contract helpers ───────────────────────────────────────────────────────────────────
// Rev 6 (security review A1-A5): the hand-written stubs are GONE. Gate-level harnesses use
// `#[kani::stub_verified(..)]` on functions whose EXACT contracts (`growth_v19::spec`,
// `vault_lp_v18::mul_div_floor_spec`) are proved by the `kani_growth_c_*` proof_for_contract
// harnesses below. Gate harnesses fix lambda = 1x and pos_scale = 1 and draw price in {0, 1},
// so N_cap == equity exactly (floor(equity * 1e4 / 1e4)) and every property about N_cap can be
// read off `lp.equity`; relational harnesses (t2_required, r8) draw price freely.

use crate::growth_v19::spec;

// ── V4 (security review, rev-6c): ∀-value stubs ─────────────────────────────────────────────
// Gate properties that hold for EVERY capacity / notional / requirement value replace those
// functions by a harness-set static (a sound over-approximation: the harness draws the value
// freely, the production code sees exactly that value, and the harness reads it back). No contract
// and no floor relation is consumed. (Kani 0.67 cannot `#[kani::stub]` a function that carries a
// contract -- "Failed to find contract closure" -- so the four stubbed composites carry none; their
// exact specs are asserted by the bounded `kani_growth_c_*` harnesses.)
static mut NCAP: Option<u128> = None;
static mut LIQ: Option<u128> = None;
static mut RISK: Option<u128> = None;
static mut LEG_KEY: u64 = 0;
static mut LEG_AT_KEY: Option<u128> = None;
static mut LEG_OTHER: Option<u128> = None;

fn ncap() -> Option<u128> {
    unsafe { NCAP }
}
fn set_ncap(v: Option<u128>) {
    unsafe { NCAP = v }
}
fn n_cap_static(_c: u128, _l: u32, _p: u64, _s: u128) -> Option<u128> {
    unsafe { NCAP }
}
fn liq_static(_c: u128, _l: u32) -> Option<u128> {
    unsafe { LIQ }
}
fn risk_static(_q: u128, _p: u64, _s: u128) -> Option<u128> {
    unsafe { RISK }
}
/// `leg_im_req` as an ARBITRARY function of its IMR argument (both legs of one requirement share
/// the notional and the min, so this over-approximates every real leg value).
fn leg_static(_n: u128, imr: u64, _m: u128) -> Option<u128> {
    unsafe {
        if imr == LEG_KEY {
            LEG_AT_KEY
        } else {
            LEG_OTHER
        }
    }
}


/// A gate input with every field symbolic at FULL width (V4, rev 6c). Capacity, risk notional
/// and the per-leg requirements are harness-set statics drawn freely (`kani::any()`), so every
/// gate property below holds for EVERY N_cap / notional / leg value (incl. `None`); `dyn_imr_bps`
/// runs for real with its ceil primitive `stub_verified` (only its linear guards and clamp, and
/// the F1/F2 facts, are consumed).
fn any_gate(lp_some: bool) -> GrowthGateIn {
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
    set_ncap(kani::any());
    unsafe {
        RISK = kani::any();
        LEG_KEY = g.engine_imr_bps;
        LEG_AT_KEY = kani::any();
        LEG_OTHER = kani::any();
    }
    g
}

fn risk() -> Option<u128> {
    unsafe { RISK }
}

// ── §1 contracts (rev 6b: proof_for_contract on the PRODUCTION functions) ────────────────
// Primitives: the only harnesses that bit-blast a divider. Bounded domain (u8 operands,
// widened). The lift to u128 is the ONE paper step (results file): the primitive bodies are
// two-line wrappers over core u128 `checked_mul`, `/` and `div_ceil` (trusted base: core u128
// arithmetic); their own logic (d == 0 guard, floor vs ceil, the None mapping, the range facts)
// is width-independent.

#[kani::proof_for_contract(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(cadical)]
fn kani_growth_c_mul_div_floor() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    let r = crate::vault_lp_v18::mul_div_floor(a, b, d);
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "inexact floor");
    kani::cover!(r == Some(0) && a * b > 0, "rounds to 0");
    kani::cover!(r.is_some_and(|q| b < d && q < a), "fact b <= d: q <= a (strict)");
    kani::cover!(r.is_some_and(|q| b == d && q == a && a > 0), "fact b == d: q == a");
}

#[kani::proof_for_contract(crate::growth_v19::mul_div_ceil_u128)]
#[kani::solver(cadical)]
fn kani_growth_c_mul_div_ceil() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    let r = mul_div_ceil_u128(a, b, d);
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "rounds up");
    kani::cover!(r == Some(0), "zero product");
    kani::cover!(r.is_some_and(|q| b < d && q < a), "fact b <= d: q <= a (strict)");
    kani::cover!(r.is_some_and(|q| b > d && q > a), "fact b >= d: q >= a (strict)");
    kani::cover!(r.is_some_and(|q| b == d && q == a && a > 0), "facts at b == d: q == a");
}

// Composite contracts, rev 6c (proposal (3), review R2/R3 + V3). Two harnesses per composite:
// * `kani_growth_c_<fn>`: the EXACT C1 contract (proof_for_contract on the production u128
//   function) with the REAL primitives (V3: computed, not stubbed) at u8 operand draws, widened
//   only where a branch needs it (bps dials u16); every in-range spec branch covered; the exact
//   value relation lifts to u128 like the primitives (P1). 4000 s watchdog.
// * `kani_growth_g_<fn>`: FULL-width twin, primitives stub_verified, asserting only what changes
//   with width: guard -> result, overflow -> None of each narrow-by-wide checked_mul, the
//   guarded subtractions, the casts after their clamps, 1e4*P. The overflow -> None covers that
//   cannot be reached at u32/u64 live HERE, named one by one.

#[kani::proof] // exact C1 spec asserted on the real result (V4: no contract attr, so gate harnesses can stub it)
#[kani::solver(cadical)]
fn kani_growth_c_n_cap_q() {
    let c = kani::any::<u8>() as u128;
    let l = kani::any::<u8>() as u32;
    let p = kani::any::<u8>() as u64;
    let s = kani::any::<u8>() as u128;
    let r = n_cap_q(c, l, p, s);
    assert!(spec::n_cap_q(c, l, p, s, r), "exact C1 spec");
    kani::cover!(p == 0 && r.is_none(), "None: price 0");
    kani::cover!(r.is_some_and(|n| n > 0), "Some: capacity");
    kani::cover!(r == Some(0) && c > 0 && l > 0 && s > 0, "Some: rounds to 0");
}

#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_g_n_cap_q() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    assert!(10_000u128.checked_mul(p as u128).is_some(), "1e4 * price never overflows");
    let r = n_cap_q(c, l, p, s);
    let ovf = c.checked_mul(l as u128).is_none();
    if p == 0 || ovf {
        assert!(r.is_none());
    }
    kani::cover!(p == 0 && r.is_none(), "None: price 0");
    kani::cover!(p != 0 && ovf && r.is_none(), "None: C_m*lambda overflow (u128 x u32)");
    kani::cover!(p != 0 && !ovf && r.is_none(), "None: C_m*lambda*POS overflow (primitive)");
    kani::cover!(r.is_some_and(|n| n > u64::MAX as u128), "Some: full-width capacity");
}

#[kani::proof] // exact C1 spec asserted on the real result (V4: no contract attr, so gate harnesses can stub it)
#[kani::solver(cadical)]
fn kani_growth_c_liquidity_notional_e6() {
    let c = kani::any::<u8>() as u128;
    let l = kani::any::<u8>() as u32;
    let r = liquidity_notional_e6(c, l);
    assert!(spec::liquidity_notional_e6(c, l, r), "exact C1 spec");
    kani::cover!(r.is_some_and(|x| x > 0), "Some: depth");
    kani::cover!(r == Some(0) && c > 0 && l > 0, "Some: rounds to 0");
}

#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_g_liquidity_notional_e6() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let r = liquidity_notional_e6(c, l);
    let x = c.checked_mul(l as u128);
    if x.is_none() || x.is_some_and(|x| x.checked_mul(4).is_none()) {
        assert!(r.is_none());
    }
    kani::cover!(x.is_none() && r.is_none(), "None: C_m*lambda overflow (u128 x u32)");
    kani::cover!(x.is_some_and(|x| x.checked_mul(4).is_none()) && r.is_none(), "None: *DEPTH_MULT overflow");
    kani::cover!(r.is_some_and(|d| d > u64::MAX as u128), "Some: full-width depth");
}

#[kani::proof_for_contract(crate::growth_v19::dyn_imr_bps)]
#[kani::solver(cadical)]
fn kani_growth_c_dyn_imr_bps() {
    // u8 positions; base / kink u16 (the kink and 1e4 branches need bps range)
    let lp = kani::any::<u8>() as u128;
    let n = kani::any::<u8>() as u128;
    let base: u64 = kani::any::<u16>() as u64;
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    let valid = base <= 10_000 && k <= 10_000;
    kani::cover!(valid && n > 0 && lp > 0 && lp <= n && r == Some(base), "Some: below the kink");
    kani::cover!(valid && lp < n && r.is_some_and(|x| x > base && x < 10_000), "Some: between the kink and u == 1");
    kani::cover!(valid && lp == n && k < 10_000 && base < 10_000 && r == Some(10_000), "Some: exactly 10,000 at u == 1");
    kani::cover!(valid && lp > n && r.is_none(), "None: lp > n");
    kani::cover!(valid && n == 0 && r.is_none(), "None: n == 0");
    kani::cover!(!valid && r.is_none(), "None: invalid dials");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_g_dyn_imr_bps() {
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
        // the clamp precedes `as u64`: the cast never truncates
        assert!(v >= base && v <= 10_000);
    }
    kani::cover!(valid && n > 0 && lp <= n && lhs.is_none() && r.is_none(), "None: lp*1e4 overflow (u128 x const)");
    kani::cover!(valid && lp <= n && lhs.is_some_and(|a| rhs.is_some_and(|b| a > b)) && n.checked_mul(10_000 - k as u128).is_none() && r.is_none(), "None: n*(1e4-k) overflow (u128 x <=1e4)");
    kani::cover!(valid && lp <= n && n.checked_mul(10_000 - k as u128).is_some() && lhs.is_some_and(|a| rhs.is_some_and(|b| a > b)) && r.is_none(), "None: span*num overflow (primitive) / base+extra");
    kani::cover!(r.is_some_and(|v| v > base) && n > u64::MAX as u128, "Some: stepped at full width");
}

#[kani::proof] // exact C1 spec asserted on the real result (V4: no contract attr, so gate harnesses can stub it)
#[kani::solver(cadical)]
fn kani_growth_c_leg_im_req() {
    // u8 notional / min; imr u16 (the imr > 1e4 branch)
    let n = kani::any::<u8>() as u128;
    let imr: u64 = kani::any::<u16>() as u64;
    let m = kani::any::<u8>() as u128;
    let r = leg_im_req(n, imr, m);
    assert!(spec::leg_im_req(n, imr, m, r), "exact C1 spec");
    kani::cover!(n == 0 && r == Some(0), "Some(0): flat");
    kani::cover!(n > 0 && imr > 10_000 && r.is_none(), "None: imr > 10,000");
    kani::cover!(r.is_some_and(|v| v == m && m > 0 && n > 0 && imr > 0), "Some: min binds");
    kani::cover!(r.is_some_and(|v| v > m && n > 0), "Some: ceil binds");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_g_leg_im_req() {
    let n: u128 = kani::any();
    let imr: u64 = kani::any();
    let m: u128 = kani::any();
    let r = leg_im_req(n, imr, m);
    if n == 0 {
        assert_eq!(r, Some(0));
    } else if imr > 10_000 {
        assert!(r.is_none());
    } else if n.checked_mul(imr as u128).is_none() {
        assert!(r.is_none(), "notional*imr overflow (u128 x <=1e4) -> None");
    }
    if let Some(v) = r {
        assert!(n == 0 || v >= m, "max(., min)");
    }
    kani::cover!(n > 0 && imr <= 10_000 && r.is_none(), "None: notional*imr overflow");
    kani::cover!(r.is_some_and(|v| v > u64::MAX as u128 && v > m), "Some: full-width requirement");
}

#[kani::proof] // exact C1 spec asserted on the real result (V4: no contract attr, so gate harnesses can stub it)
#[kani::solver(cadical)]
fn kani_growth_c_risk_notional_ceil() {
    let q = kani::any::<u8>() as u128;
    let p = kani::any::<u8>() as u64;
    let s = kani::any::<u8>() as u128;
    let r = risk_notional_ceil(q, p, s);
    assert!(spec::risk_notional_ceil(q, p, s, r), "exact C1 spec");
    kani::cover!(s == 0 && r.is_none(), "None: scale 0");
    kani::cover!(r.is_some_and(|x| x > 0), "Some: notional");
    kani::cover!(r == Some(0) && s > 0, "Some: flat");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_g_risk_notional_ceil() {
    let q: u128 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = risk_notional_ceil(q, p, s);
    if s == 0 {
        assert!(r.is_none());
    }
    kani::cover!(s > 0 && r.is_none(), "None: |q|*price overflow (primitive)");
    kani::cover!(r.is_some_and(|x| x > u64::MAX as u128), "Some: full-width notional");
}

#[kani::proof_for_contract(crate::growth_v19::utilisation_fee_bps)]
#[kani::solver(cadical)]
fn kani_growth_c_utilisation_fee_bps() {
    // u8 OI / capacity; kink and max fee u16 (bps range)
    let o = kani::any::<u8>() as u128;
    let n = kani::any::<u8>() as u128;
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    let r = utilisation_fee_bps(o, n, k, m);
    kani::cover!(n == 0 && r.is_none(), "None: n == 0");
    kani::cover!(n > 0 && k > 10_000 && r.is_none(), "None: k > 10,000");
    kani::cover!(r == Some(0) && m > 0 && o > 0, "Some(0): at/below the kink");
    kani::cover!(r.is_some_and(|f| f > 0 && f < m) && o < n, "Some: between the kink and u == 1");
    kani::cover!(r.is_some_and(|f| f == m && m > 0) && o == n && k < 10_000, "Some(max): u == 1");
    kani::cover!(r.is_some_and(|f| f == m && m > 0) && o > n, "Some(max): u > 1 (capped)");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_g_utilisation_fee_bps() {
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
        // the clamp precedes `as u16`: the cast never truncates
        assert!(f <= m);
    }
    kani::cover!(n > 0 && k <= 10_000 && o.checked_mul(10_000).is_none() && r.is_none(), "None: o*1e4 overflow (u128 x const)");
    kani::cover!(n > 0 && k <= 10_000 && o.checked_mul(10_000).is_some() && (k as u128).checked_mul(n).is_none() && r.is_none(), "None: k*n overflow (u16 x u128)");
    kani::cover!(n > 0 && k < 10_000 && n.checked_mul(10_000 - k as u128).is_none() && r.is_none() && o.checked_mul(10_000).is_some_and(|a| (k as u128).checked_mul(n).is_some_and(|b| a > b)) && m > 0, "None: n*(1e4-k) overflow (u128 x <=1e4)");
    kani::cover!(r.is_some_and(|f| f > 0) && n > u64::MAX as u128, "Some: charged at full width");
}

#[kani::proof_for_contract(crate::growth_v19::util_fee_on_fill_bps)]
#[kani::solver(cadical)]
fn kani_growth_c_util_fee_on_fill_bps() {
    // fee u16 (bps); u8 opening / fill
    let f: u16 = kani::any();
    let o = kani::any::<u8>() as u128;
    let fill = kani::any::<u8>() as u128;
    let r = util_fee_on_fill_bps(f, o, fill);
    kani::cover!(r == f && f > 0, "plain open: full rate");
    kani::cover!(r > 0 && r < f, "flip: opening share");
    kani::cover!(fill > 0 && o > 0 && f > 0 && r == 0, "rounds to 0");
    kani::cover!(fill == 0 || o == 0 || f == 0, "zero input");
}

/// Full-width twin (R1/R2): with the R1 clamp the narrowing cast is a LINEAR fact. The
/// `requires` is assumed here exactly as `stub_verified` callers assert it; its discharge at
/// the real caller is `kani_growth_util_fee_caller_bound`.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_g_util_fee_on_fill_bps() {
    let f: u16 = kani::any();
    let o: u128 = kani::any();
    let fill: u128 = kani::any();
    kani::assume((f as u128).checked_mul(core::cmp::min(o, fill)).is_some());
    let r = util_fee_on_fill_bps(f, o, fill);
    if fill == 0 || o == 0 || f == 0 {
        assert_eq!(r, 0);
    }
    assert!(r <= f, "cast after the clamp: never above the fee");
    // V2: the truncating path must be drawable (live under mutant r1-noclamp-o)
    kani::cover!(o > fill && (f as u128).checked_mul(o).is_some_and(|x| x > 65_535u128.saturating_mul(fill)), "opening > fill with fee*opening/fill > 65,535");
    kani::cover!(fill > u64::MAX as u128 && r > 0 && r < f, "Some: full-width flip share");
    kani::cover!(r == f && f > 0 && fill > u64::MAX as u128, "full rate at full width");
}

/// C2: `util_fee_on_fill_bps`'s precondition at its real caller `growth_util_fee_for_fill_bps`
/// (v16_program.rs:33492). There `fee <= u16::MAX` and `min(opening, fill) <= fill =
/// |exec_size|`, where `validate_matcher_return` bounds `|exec_size| <= |requested size|` but NOT
/// by the engine's MAX_POSITION_ABS_Q (1e14). Proved here: the requires holds for every
/// `|exec_size| <= u128::MAX / u16::MAX` (~5.2e33, >> 1e14); above it the tx aborts, as the
/// pre-A1 multiply did (fail closed; such a fill cannot pass the engine anyway).
#[kani::proof]
fn kani_growth_util_fee_caller_bound() {
    let fee: u16 = kani::any();
    let opening: u128 = kani::any();
    let fill: u128 = kani::any();
    kani::assume(fill <= u128::MAX / u16::MAX as u128);
    assert!((fee as u128).checked_mul(core::cmp::min(opening, fill)).is_some());
    assert!(100_000_000_000_000u128 <= u128::MAX / u16::MAX as u128, "engine bound inside");
    kani::cover!(fee == u16::MAX && fill == u128::MAX / u16::MAX as u128 && opening >= fill, "at the bound");
}

// ── Target 1 ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
fn kani_growth_t1_ceiling_never_looser() {
    let e: u16 = kani::any();
    let l: u16 = kani::any();
    kani::assume(e <= 10_000);
    let c = ceiling_imr_bps(e as u64, l);
    if l < 100 {
        assert!(c.is_none());
    }
    if let Some(c) = c {
        assert!(c >= e as u64 && c <= 10_000);
    }
    // tier round trip, exhaustive over the 10^4 IMR values
    let i: u16 = kani::any();
    kani::assume(i >= 1 && i <= 10_000);
    let t = leverage_x100_for_imr_bps(i as u64).unwrap();
    assert!(imr_bps_for_leverage_x100(t).unwrap() >= i as u64);
    kani::cover!(c == Some(e as u64) && l >= 100, "the engine binds");
    kani::cover!(c.is_some_and(|x| x > e as u64), "the launch cap binds");
    kani::cover!(l < 100, "below 1x");
}

#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t1_required_imr_bounds() {
    let g = any_gate(kani::any());
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

/// W-G-1 (design rev 2 R1.11, P-6 ruling 2026-10-09; label: BOUNDED, u16 operands): the composition
/// `growth_margin_required` with the REAL `leg_im_req` (and its real ceil primitive; no stub, the R5
/// pattern), so the two legs are computed values, not two free stub instances. The rev-6c FAILED
/// verdict (6 s) was the harness: with `leg_static` the dyn and engine legs were unrelated, so
/// `r >= cert` could not hold. The gate only ever passes `dy >= eng`: `growth_required_imr_bps`
/// refuses `ceil < engine` and returns `base` or `dyn_imr_bps(.., base, ..) >= base` (W-G-2, W-G-3).
/// Mutant W-G-1-M1 (swap `eng_leg`/`dyn_leg` in `growth_margin_required`) must turn assertion 1 red.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_t1_requirement_never_below_engine_or_per_asset() {
    let n = kani::any::<u16>() as u128;
    let eng = kani::any::<u16>() as u64;
    let dy = kani::any::<u16>() as u64;
    let m = kani::any::<u16>() as u128;
    let cert: Option<u128> = kani::any();
    kani::assume(eng <= 10_000 && dy <= 10_000);
    // growth_required_imr_bps never returns an IMR below the engine IMR (W-G-2).
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
        // None -> the gate refuses: only an overflow of cert - eng + dyn.
        assert!(cert.is_some() && cert.unwrap().saturating_sub(eng_leg.unwrap()).checked_add(dyn_leg.unwrap()).is_none());
    }
    kani::cover!(cert.is_some() && dy > eng && r.is_some_and(|x| x > cert.unwrap()), "cert path, dyn above engine");
    kani::cover!(cert.is_some_and(|c| eng_leg.is_some_and(|e| c < e)) && r.is_some(), "saturating path");
    kani::cover!(cert.is_none() && r.is_some() && n > 0, "no cert");
    kani::cover!(r.is_none(), "None refused (overflow)");
}

/// W-G-3 (design rev 2 R1.11; label: BOUNDED, u8 lp / n_cap, u16 dials): `dyn_imr_bps` never returns
/// below its base and never above MAX_IMR_BPS. Real function and real ceil primitive (no stub).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_w_g3_dyn_imr_not_below_base() {
    let lp = kani::any::<u8>() as u128;
    let n = kani::any::<u8>() as u128;
    let base = kani::any::<u16>() as u64;
    let kink: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, kink);
    if let Some(x) = r {
        assert!(x >= base, "dyn IMR >= base");
        assert!(x <= MAX_IMR_BPS);
    }
    kani::cover!(r == Some(base) && lp > 0, "at or below the kink");
    kani::cover!(r.is_some_and(|x| x > base), "above the kink");
    kani::cover!(r.is_none(), "refused");
}

/// W-G-2 (design rev 2 R1.11; label: BOUNDED): `growth_required_imr_bps(g) == Ok(r)` implies
/// `r >= g.engine_imr_bps` (and `<= MAX_IMR_BPS`), on the REAL `n_cap_q` and `dyn_imr_bps` (no stubs)
/// at bounded operands (u8 equity / lambda / price / pos_scale / users OI, u16 IMR dials). This is the
/// premise W-G-1 assumes.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_w_g2_required_imr_not_below_engine() {
    let lp_some: bool = kani::any();
    let lp = if lp_some {
        Some(GrowthLpIn {
            before_q: kani::any::<i8>() as i128,
            mid_q: kani::any::<i8>() as i128,
            after_q: kani::any::<i8>() as i128,
            eff_after_abs_q: kani::any::<u8>() as u128,
            users_oi_side_after_q: kani::any::<u8>() as u128,
            equity: kani::any::<u8>() as u128,
        })
    } else {
        None
    };
    let g = GrowthGateIn {
        taker_before_q: kani::any::<i8>() as i128,
        taker_after_q: kani::any::<i8>() as i128,
        taker_eff_after_abs_q: kani::any::<u8>() as u128,
        taker_equity: kani::any::<u8>() as u128,
        taker_cert_initial_req: None,
        lp,
        price_e6: kani::any::<u8>() as u64,
        pos_scale: kani::any::<u8>() as u128,
        engine_imr_bps: kani::any::<u16>() as u64,
        min_nonzero_im_req: 0,
        ceil_imr_bps: kani::any::<u16>() as u64,
        lambda_bps: kani::any::<u8>() as u32,
        kink_bps: kani::any::<u16>(),
        crowd_blocked: kani::any(),
        asset_bound: true,
    };
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

// ── Target 2 ──────────────────────────────────────────────────────────────────────────────

// Part A (rev 6c): ORDER lemmas on the REAL primitives (computed, not stubbed), u8 operands; the
// lift is P1. Each is the two-instance fact the paper compositions (P2/P3) consume.

#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_l1_ceil_monotone_in_b() {
    let a = kani::any::<u8>() as u128;
    let b1 = kani::any::<u8>() as u128;
    let b2 = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(b1 <= b2 && d > 0);
    let q1 = mul_div_ceil_u128(a, b1, d).unwrap();
    let q2 = mul_div_ceil_u128(a, b2, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && b1 < b2 && a > 0, "equal (ceil plateau)");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_l2_ceil_monotone_in_a() {
    let a1 = kani::any::<u8>() as u128;
    let a2 = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(a1 <= a2 && d > 0);
    let q1 = mul_div_ceil_u128(a1, b, d).unwrap();
    let q2 = mul_div_ceil_u128(a2, b, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && a1 < a2 && b > 0, "equal");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_l3_ceil_antitone_in_d() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d1 = kani::any::<u8>() as u128;
    let d2 = kani::any::<u8>() as u128;
    kani::assume(d1 > 0 && d1 <= d2);
    let q1 = mul_div_ceil_u128(a, b, d1).unwrap();
    let q2 = mul_div_ceil_u128(a, b, d2).unwrap();
    assert!(q2 <= q1);
    kani::cover!(q2 < q1, "strict");
    kani::cover!(q2 == q1 && d1 < d2 && a * b > 0, "equal");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_l4_floor_monotone_in_a() {
    let a1 = kani::any::<u8>() as u128;
    let a2 = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(a1 <= a2 && d > 0);
    let q1 = crate::vault_lp_v18::mul_div_floor(a1, b, d).unwrap();
    let q2 = crate::vault_lp_v18::mul_div_floor(a2, b, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && a1 < a2 && b > 0, "equal (floor plateau)");
}

// Shape harnesses (V1): full width, the ceil primitive `stub_verified` (None ⇔ overflow and the
// F1/F2 facts only; no q*d relation consumed). E1 = None-monotonicity with None (refuse) as the
// top of the order; the stepped-vs-stepped order is P3 + L1/L3 on the operands asserted here.

/// t2 / E1 (dyn, in |LP|): lp1 <= lp2 ⇒ (dyn(lp1) refuses ⇒ dyn(lp2) refuses); below-kink at lp2
/// ⇒ below-kink at lp1 (branch selection monotone); both stepped ⇒ same span, same den, num1 <=
/// num2 (L1 then gives extra1 <= extra2: P3).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t2_dyn_shape_in_lp() {
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
    kani::cover!(r1.is_none() && lp1 <= n && lp1.checked_mul(10_000).is_some() && n.checked_mul(10_000 - k as u128).is_some() && base <= 10_000 && k <= 10_000, "E1: span*num overflow");
    kani::cover!(r1.is_some() && r2.is_none() && lp2 > n, "E1: lp > n");
    kani::cover!(r1.is_some_and(|a| a > base) && r2.is_some_and(|b| b > base), "both stepped");
}

/// t2 / E1 (dyn, antitone in N_cap) on the ENGINE domain (n <= 1e23 = MAX_VAULT_TVL·λmax·POS/1e4,
/// so no overflow None exists there -- asserted): n1 <= n2 ⇒ num(n2) <= num(n1), den(n1) <=
/// den(n2), branch selection monotone (L1 + L3 then order the stepped values: P2).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t2_dyn_shape_in_ncap() {
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

/// E2 (V1): t2_required antitone in C_m holds on the ENGINE domain (C <= MAX_VAULT_TVL = 1e16,
/// λ <= 1e5, POS = 1e6, price >= 1): there `n_cap_q` never returns an overflow None (asserted at
/// full width over that domain) and C1 <= C2 ⇒ C1·λ <= C2·λ (the floor's numerator; L4 orders
/// the floors: P2). Above the domain it refuses (fail closed).
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_t2_required_shape_engine_domain() {
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

// ── Target 3 ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t3_reductions_always_pass() {
    let g = any_gate(kani::any());
    kani::assume(!taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
    kani::cover!(g.taker_equity == 0 && g.taker_after_q != 0, "reduce with zero equity");
    kani::cover!(g.crowd_blocked && !g.asset_bound, "reduce under h-lock, unbound");
    kani::cover!(g.taker_after_q == 0 && g.taker_before_q != 0, "close to flat");
    kani::cover!(g.lp.is_some_and(|l| ncap().is_some_and(|n| l.users_oi_side_after_q > n)), "reduce while the side is over capacity");
}

/// A thin open pays only the ceiling and is never stepped; it is refused (CapacityFull) only
/// when its OWN side's users OI would pass N_cap, or N_cap is None. ∀ N_cap (V4).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t3_thin_side_gets_only_the_ceiling() {
    let g = any_gate(true);
    let l = g.lp.unwrap();
    kani::assume(!joins_crowd(l.mid_q, l.after_q));
    kani::assume(g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps);
    let r = growth_required_imr_bps(&g);
    match ncap() {
        Some(n) if l.users_oi_side_after_q <= n => assert_eq!(r, Ok(g.ceil_imr_bps)),
        _ => assert_eq!(r, Err(GrowthVerdict::CapacityFull)),
    }
    kani::cover!(r == Ok(g.ceil_imr_bps) && g.crowd_blocked, "thin under the h-lock");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull) && ncap().is_some(), "thin side over its own cap");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull) && ncap().is_none(), "N_cap None");
    kani::cover!(r.is_ok() && ncap() == Some(l.users_oi_side_after_q) && l.users_oi_side_after_q > 0, "thin lands on N_cap");
}

#[kani::proof]
fn kani_growth_t3_flip_is_risk_increasing() {
    let b: i64 = kani::any();
    let a: i64 = kani::any();
    kani::assume(b != 0 && a != 0 && (b > 0) != (a > 0));
    assert!(taker_risk_increasing(b as i128, a as i128));
    kani::cover!(a.unsigned_abs() < b.unsigned_abs(), "smaller opposite position");
}

// ── Target 4 ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t4_zero_price_fails_closed() {
    let mut g = any_gate(kani::any());
    g.price_e6 = 0;
    kani::assume(taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    assert_ne!(growth_gate(&g), GrowthVerdict::Allow);
    kani::cover!(g.lp.is_none(), "no LP");
    kani::cover!(g.lp.is_some() && g.asset_bound, "bound crowd");
}

/// Every None (N_cap, risk notional, a leg requirement, an overflow) maps to a refusal, nothing
/// panics. Full width, ∀ values (V4).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t4_overflow_fails_closed() {
    let g = any_gate(true);
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
    kani::cover!(gate_ok && risk().is_some() && unsafe { LEG_OTHER.is_none() && g.ceil_imr_bps != LEG_KEY } && v == GrowthVerdict::LeverageExceeded, "leg None refused");
    kani::cover!(gate_ok && crowd && ncap().is_some_and(|n| n > u64::MAX as u128 && l.users_oi_side_after_q <= n) && v == GrowthVerdict::Allow, "full-width admit");
}

// ── Target 5 (rev 4: users OI) ────────────────────────────────────────────────────────────

/// Any admitted risk-increasing fill leaves its side's users OI <= N_cap, for EVERY N_cap (V4).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_t5_capacity_invariant() {
    let g = any_gate(true);
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
}

/// u == 1 on the crowd side costs 100% margin. Uses the at-cap FACT (num == den ⇒ ceil == span),
/// so `dyn_imr_bps` and its primitive run for REAL at a bounded capacity (u8; R3: the fact
/// holds where nothing overflows, which the engine bound guarantees: lp*1e4 < 2^91). 4000 s.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
fn kani_growth_t5_at_capacity_costs_full_margin() {
    let n = kani::any::<u8>() as u128;
    kani::assume(n > 0);
    set_ncap(Some(n));
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

// ── Target 6 ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::unwind(18)]
#[kani::solver(cadical)]
fn kani_growth_t6_ceiling_bounded_and_monotone() {
    let en: bool = kani::any();
    let la: u16 = kani::any();
    let lt: u16 = kani::any();
    let c1: u16 = kani::any();
    let c2: u16 = kani::any();
    let cl: u16 = kani::any();
    kani::assume(c1 <= c2);
    let a = graduated_ceiling_x100(en, la, lt, c1 as u128, cl as u128);
    let b = graduated_ceiling_x100(en, la, lt, c2 as u128, cl as u128);
    assert!(a <= lt && b <= lt && a <= b);
    if !en {
        assert_eq!(a, la.min(lt));
    }
    kani::cover!(en && b > la.min(lt) && b < lt, "enabled and stepped");
    kani::cover!(en && b == lt && la < lt, "clamped at the tier");
    kani::cover!(!en, "disabled");
}

#[kani::proof]
fn kani_growth_t6_ratchet_single_step() {
    let prev: u16 = kani::any();
    let ps: u64 = kani::any();
    let tgt: u16 = kani::any();
    let fl: u16 = kani::any();
    let force: bool = kani::any();
    let now: u64 = kani::any();
    let (out, _) = ratchet_ceiling_x100(prev, ps, tgt, fl, force, now);
    assert!(out <= prev.max(tgt));
    if out > prev {
        assert!(out as u32 <= prev as u32 + RATCHET_STEP_X100 as u32);
        assert!(now >= ps.saturating_add(RATCHET_EPOCH_SLOTS));
    }
    let eff_t = if force && fl < tgt { fl } else { tgt };
    if eff_t <= prev {
        assert_eq!(out, eff_t);
    }
    if force && fl < tgt {
        assert!(out <= fl.max(prev.min(fl)) || out <= prev.saturating_add(RATCHET_STEP_X100).min(fl));
        assert!(out <= fl || out == prev);
    }
    kani::cover!(out == prev && tgt > prev && !force, "rise blocked within the epoch");
    kani::cover!(out > prev, "one-step rise");
    kani::cover!(tgt < prev && !force && out == tgt, "immediate fall");
    kani::cover!(force && fl < tgt && fl < prev && out == fl, "forced fall");
}

// ── Target 7 + R9 ─────────────────────────────────────────────────────────────────────────

#[kani::proof]
fn kani_growth_t7_init_margin_rule_exact() {
    let mmr: u64 = kani::any();
    let r: u16 = kani::any();
    let fee: u64 = kani::any();
    let mv: u64 = kani::any();
    let ok = init_margin_rule_ok(mmr, r, fee, mv);
    let floor = mv.checked_mul(R_GAP_MIN_LIQUIDATION_SLOTS);
    let exp = r > 0
        && floor.is_some_and(|f| r as u64 >= f)
        && (r as u64).checked_add(fee).is_some_and(|need| mmr >= need);
    assert_eq!(ok, exp);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok && r == 0, "r_gap 0");
    kani::cover!((r as u64).checked_add(fee).is_none(), "checked_add overflow");
    kani::cover!(floor.is_none(), "floor overflow fails closed");
}

/// L5 (Part A) = T7 gap solvency: mmr >= r_gap + fee ⇒ ceil(N·mmr/1e4) >= floor(N·r/1e4) +
/// ceil(N·f/1e4), on the REAL primitives (computed). Bound: u8 notional, bps <= 1e4; lift P1.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_t7_rule_implies_gap_solvency() {
    let n = kani::any::<u8>() as u128;
    let r: u16 = kani::any();
    let f: u16 = kani::any();
    let mmr: u16 = kani::any();
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let mm = mul_div_ceil_u128(n, mmr as u128, 10_000).unwrap();
    let gap = crate::vault_lp_v18::mul_div_floor(n, r as u128, 10_000).unwrap();
    let fee = mul_div_ceil_u128(n, f as u128, 10_000).unwrap();
    assert!(mm >= gap + fee);
    kani::cover!(mm == gap + fee && n > 0 && r > 0 && f > 0, "tight");
    kani::cover!(mm > gap + fee, "slack");
}

#[kani::proof]
fn kani_growth_r9_r_gap_floor() {
    let mmr: u64 = kani::any();
    let r: u16 = kani::any();
    let fee: u64 = kani::any();
    let mv: u64 = kani::any();
    if init_margin_rule_ok(mmr, r, fee, mv) {
        assert!(r as u128 >= mv as u128 * R_GAP_MIN_LIQUIDATION_SLOTS as u128);
        assert!(mmr as u128 >= r as u128 + fee as u128);
    }
    kani::cover!(init_margin_rule_ok(mmr, r, fee, mv) && mv > 0, "floor met");
    kani::cover!(!init_margin_rule_ok(mmr, r, fee, mv) && r > 0 && mmr >= 10_000 && fee == 0, "floor refuses");
}

// ── §3: H2 port, sides, dials, depth ──────────────────────────────────────────────────────

#[kani::proof]
fn kani_growth_h2_reducing_always_allowed() {
    let b: i64 = kani::any();
    let a: i64 = kani::any();
    let eq: u128 = kani::any();
    let lev: u32 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    kani::assume(!vault_lp_v18::joins_crowd(b as i128, a as i128));
    assert!(vault_lp_v18::vault_lp_exposure_allowed(b as i128, a as i128, eq, lev, p, s));
    kani::cover!(eq == 0 && a != 0, "reduce with zero equity");
}

/// Bound: u8 positions / equity / price, lev u16, scale 1. V3: the REAL `mul_div_floor` (computed);
/// lift P1. 4000 s.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_h2_admit_iff_within_ncap() {
    let b: i8 = kani::any();
    let a: i8 = kani::any();
    let eq: u8 = kani::any();
    let lev: u16 = kani::any();
    let p: u8 = kani::any();
    kani::assume(vault_lp_v18::joins_crowd(b as i128, a as i128));
    let ok = vault_lp_v18::vault_lp_exposure_allowed(b as i128, a as i128, eq as u128, lev as u32, p as u64, 1);
    let notional = (a as i128).unsigned_abs() * p as u128;
    // x <= floor(E / 1e4)  ⇔  x * 1e4 <= E (naturals): no divider in the harness
    assert_eq!(ok, notional * 10_000 <= eq as u128 * lev as u128);
    kani::cover!(ok, "admitted");
    kani::cover!(!ok, "refused");
}

#[kani::proof]
fn kani_growth_sides_never_skip_a_non_lp_taker() {
    let cpi: bool = kani::any();
    let a_lp: bool = kani::any();
    let b_lp: bool = kani::any();
    let (at, bt, lp_is_b) = growth_sides(cpi, a_lp, b_lp);
    if cpi {
        assert!(at && lp_is_b == Some(true));
    } else {
        if !a_lp || (a_lp && b_lp) {
            assert!(at);
        }
        if !b_lp || (a_lp && b_lp) {
            assert!(bt);
        }
    }
    if lp_is_b == Some(true) {
        assert!(!bt);
    }
    if lp_is_b == Some(false) {
        assert!(!at);
    }
    kani::cover!(cpi && a_lp, "CPI taker with its own matcher config is still checked");
    kani::cover!(!cpi && a_lp && b_lp && at && bt, "NoCpi LP-LP: both checked");
    kani::cover!(!cpi && !a_lp && !b_lp && lp_is_b.is_none(), "NoCpi no LP");
    kani::cover!(!cpi && a_lp && !b_lp && lp_is_b == Some(false), "NoCpi LP is a");
}

/// Dials (rev 2) + R15f utilisation-fee dial.
#[kani::proof]
fn kani_growth_dials_tighten_only() {
    let lam: u32 = kani::any();
    let k: u16 = kani::any();
    let clamp: bool = kani::any();
    let ok = growth_dials_ok(clamp, lam, k);
    if clamp {
        assert_eq!(ok, lam >= 1 && lam <= MAX_LAMBDA_BPS && k <= 10_000);
    } else {
        assert_eq!(ok, lam >= 1 && lam <= DEFAULT_LAMBDA_BPS && k <= DEFAULT_KINK_BPS);
    }
    let u: u16 = kani::any();
    let uok = util_fee_dial_ok(clamp, u);
    if !clamp {
        assert_eq!(uok, u >= GROWTH_UTIL_FEE_DEFAULT_BPS && u <= GROWTH_UTIL_FEE_HARD_MAX_BPS);
    } else {
        assert_eq!(uok, u <= GROWTH_UTIL_FEE_HARD_MAX_BPS);
    }
    assert_eq!(util_fee_max_effective_bps(0), GROWTH_UTIL_FEE_DEFAULT_BPS);
    kani::cover!(!clamp && lam == DEFAULT_LAMBDA_BPS + 1 && !ok, "lambda boundary +1");
    kani::cover!(!clamp && ok && lam == DEFAULT_LAMBDA_BPS && k == DEFAULT_KINK_BPS, "boundary admitted");
    kani::cover!(!clamp && u == GROWTH_UTIL_FEE_DEFAULT_BPS - 1 && !uok, "cheaper util fee refused");
    kani::cover!(clamp && ok && lam > DEFAULT_LAMBDA_BPS, "clamp widens");
}

// ── Revision 3 ────────────────────────────────────────────────────────────────────────────

/// R1 (wrapper conjuncts): a strict reduction is classified reducing with headroom |size| (the
/// preflight), the LP's mid equals its after (P1 / P3 post-fill exemption) and the gate admits.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r1_close_is_never_capacity_clipped() {
    let tb: i64 = kani::any();
    let sz: i64 = kani::any();
    let lb: i64 = kani::any();
    let (tb, sz, lb) = (tb as i128, sz as i128, lb as i128);
    let ta = tb + sz;
    kani::assume(sz != 0 && taker_strictly_reduces(tb, ta));
    let cls = growth_leg_reduce_class(tb, sz, kani::any()).unwrap();
    assert_eq!(cls, (true, Some(sz.unsigned_abs())));
    let lp_after = lb - sz;
    assert_eq!(lp_mid_q(lb, tb, ta), Some(lp_after));
    let mut g = any_gate(true);
    g.taker_before_q = tb;
    g.taker_after_q = ta;
    g.taker_equity = 0;
    assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
    kani::cover!(ta == 0, "full close");
    kani::cover!(ta != 0 && lp_after.unsigned_abs() > lb.unsigned_abs(), "a close that GROWS |LP|");
}

/// R1 lemma: lp_mid identity. i64 inputs.
#[kani::proof]
fn kani_growth_lp_mid_identity() {
    let lb: i64 = kani::any();
    let tb: i64 = kani::any();
    let ta: i64 = kani::any();
    let (lb, tb, ta) = (lb as i128, tb as i128, ta as i128);
    let m = lp_mid_q(lb, tb, ta).unwrap();
    if taker_strictly_reduces(tb, ta) {
        assert_eq!(m, lb + tb - ta);
    } else if taker_flips(tb, ta) {
        assert_eq!(m, lb + tb);
    } else {
        assert_eq!(m, lb);
    }
    kani::cover!(taker_flips(tb, ta), "flip");
    kani::cover!(taker_strictly_reduces(tb, ta) && ta != 0, "partial reduce");
    kani::cover!(!taker_strictly_reduces(tb, ta) && !taker_flips(tb, ta), "open");
}

/// R2 + R12: every admitted open faces the bound vault LP.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r2_r12_every_open_faces_the_bound_vault_lp() {
    let g = any_gate(kani::any());
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
    kani::cover!(opens && g.asset_bound && g.price_e6 != 0 && g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q) && ncap().is_some_and(|n| l.users_oi_side_after_q > n)) && !g.crowd_blocked && v == GrowthVerdict::CapacityFull, "dyn None refused");
    kani::cover!(opens && g.asset_bound && g.price_e6 == 0 && g.lp.is_some() && v == GrowthVerdict::LeverageExceeded, "price 0 refused before n_cap_q");
}

/// R5: the wrapper's engine-IMR leg equals the engine's per-leg IM formula
/// `max(ceil(notional·bps/1e4), floor)`, 0 when flat (percolator src/v16.rs:23050-23056), checked
/// on the COMPUTED value of the real `leg_im_req` (no free q); `target_lag_penalty >= 0`
/// (src/v16.rs:3325-3365) then gives leg <= engine leg + penalty. The engine's own
/// `mul_div_ceil_u128_or_wide` is P5 (LiteSVM equality at 35ddd692). Bound: u8 notional / min,
/// bps <= 1e4; lift P1. 4000 s.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_growth_r5_eng_leg_le_engine_leg() {
    let n = kani::any::<u8>() as u128;
    let imr = kani::any::<u16>() as u64;
    let m = kani::any::<u8>() as u128;
    kani::assume(imr <= 10_000);
    let w = leg_im_req(n, imr, m).unwrap();
    let p = n * imr as u128;
    if n == 0 {
        assert_eq!(w, 0);
    } else if w > m {
        assert!(spec::ceil_rel(p, 10_000, w), "w == ceil(n*imr/1e4) > floor");
    } else {
        assert!(w == m && p <= m * 10_000, "w == floor >= ceil(n*imr/1e4)");
    }
    let penalty: u128 = kani::any();
    kani::assume(w.checked_add(penalty).is_some());
    assert!(w <= w + penalty);
    kani::cover!(w > m && n > 0, "ceil binds");
    kani::cover!(w == m && m > 0 && n > 0 && imr > 0, "floor binds");
}

/// R8: the ext-v3 caps say CLOSED exactly when the gate's N_cap (the same `n_cap_q`, here ANY
/// value: V4) is None / 0 or the h-lock is latched; otherwise they ARE N_cap (clamped to the
/// engine position cap) and the depth. Full width.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::liquidity_notional_e6, liq_static)]
fn kani_growth_r8_caps_view_agrees_with_gate() {
    let hlock: bool = kani::any();
    let c: u128 = kani::any();
    let p: u64 = kani::any();
    let maxq: u128 = kani::any();
    set_ncap(kani::any());
    unsafe { LIQ = kani::any() };
    let (cap, liq) = growth_matcher_caps(hlock, c, 10_000, p, 1_000_000, maxq);
    if hlock {
        assert_eq!((cap, liq), (0, 0));
    } else {
        match ncap() {
            None | Some(0) => assert_eq!((cap, liq), (0, 0)),
            Some(n) => {
                assert_eq!(cap, if n > maxq { maxq } else { n });
                if cap > 0 {
                    assert_eq!(liq, unsafe { LIQ }.unwrap_or(0));
                }
            }
        }
    }
    kani::cover!(hlock, "h-lock closes");
    kani::cover!(!hlock && ncap().is_none(), "None closes");
    kani::cover!(!hlock && ncap() == Some(0), "0 closes");
    kani::cover!(cap > 0 && liq > 0 && cap < maxq, "open");
    kani::cover!(cap == maxq && maxq > 0 && ncap().is_some_and(|n| n > maxq), "clamped to the position cap");
}

// ── Revision 4 / 5: R11 (inductive capacity invariant) ────────────────────────────────────

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

/// The production gate fed exactly as `growth_post_fill_view` feeds it (users OI on the
/// taker's side after the step, LP = -sum users). `n` = N_cap, handed to the gate through the
/// static `n_cap_q` stub (V4: any capacity); risk notional / legs are free statics.
fn admits(p: &[i128; 3], i: usize, d: i128, n: u128) -> bool {
    set_ncap(Some(n));
    unsafe {
        RISK = kani::any();
        LEG_KEY = 1_000;
        LEG_AT_KEY = kani::any();
        LEG_OTHER = kani::any();
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
            // the production view's measure; `lpnet_mutant` = the pre-N-1 measure (|LP| net)
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

/// R11: INV(p, n) ∧ admitted gated fill ⇒ INV(p', n). Bound (rev 6c, V4): i64 positions, i64 step,
/// u64 n, ANY N_cap value (static stub).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r11_capacity_invariant_inductive() {
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
    kani::cover!(!ok && crowd && taker_risk_increasing(p[i], q[i]), "stub dyn_imr_bps -> None (crowd open past N_cap)");
    kani::cover!(ok && crowd && taker_risk_increasing(p[i], q[i]), "stub dyn_imr_bps -> Some (crowd open admitted)");
}

/// R11b: the ungated transitions. (i) user-user close, (ii) OI-lowering scaling of one side;
/// both preserve INV by the identity |LP| = |L - S|. (iii) while a side is over, every open on
/// it is refused. (iv) is (iii) after an n decrease. Bound (rev 6c, V4): i64 positions, u64 n.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_static)]
#[kani::stub(crate::growth_v19::risk_notional_ceil, risk_static)]
#[kani::stub(crate::growth_v19::leg_im_req, leg_static)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r11b_ungated_transitions() {
    let p = [kani::any::<i64>() as i128, kani::any::<i64>() as i128, kani::any::<i64>() as i128];
    let n = kani::any::<u64>() as u128;
    let which: u8 = kani::any();
    if which == 0 {
        // (i) user i closes into user j, both strictly reducing
        let d = kani::any::<i64>() as i128;
        kani::assume(inv(&p, n) && d != 0);
        let (i, j) = (0usize, 1usize);
        kani::assume(taker_strictly_reduces(p[i], p[i] + d) && taker_strictly_reduces(p[j], p[j] - d));
        let q = [p[0] + d, p[1] - d, p[2]];
        assert!(inv(&q, n));
        kani::cover!(true, "user-user close");
    } else if which == 1 {
        // (ii) ADL / liquidation / reset: every position on the long side shrinks toward 0
        kani::assume(inv(&p, n));
        let mut q = p;
        for k in 0..3 {
            if q[k] > 0 {
                let s = kani::any::<i64>() as i128;
                kani::assume(s >= 0 && s <= q[k]);
                q[k] = s;
            }
        }
        // the identity half of INV survives any OI-lowering move; the caps trivially do
        let l = side_oi(&q, true);
        let sh = side_oi(&q, false);
        assert!((q[0] + q[1] + q[2]).unsigned_abs() <= l.max(sh));
        assert!(l <= side_oi(&p, true) && sh == side_oi(&p, false));
        assert!(inv(&q, n));
        kani::cover!(l < side_oi(&p, true), "OI lowered");
    } else {
        // (iii)/(iv): side over the (possibly decreased) cap -> no open on it is admitted
        let i: usize = kani::any();
        kani::assume(i < 3);
        let d = kani::any::<i64>() as i128;
        kani::assume(d != 0);
        let after = p[i] + d;
        kani::assume(taker_risk_increasing(p[i], after) && side_oi(&p, after > 0) > n);
        assert!(!admits(&p, i, d, n));
        kani::cover!(n > 0, "open refused while over");
    }
}

/// R13: the reduce class is made on the EFFECTIVE position: (true, Some(r)) only for a strict
/// reduction (r == |size|) or a single-route flip clipped to its close (r == |eff|).
#[kani::proof]
fn kani_growth_r13_reduce_class_effective() {
    let e: i64 = kani::any();
    let s: i64 = kani::any();
    let clip: bool = kani::any();
    let (e, s) = (e as i128, s as i128);
    let (red, room) = growth_leg_reduce_class(e, s, clip).unwrap();
    if red {
        let r = room.unwrap();
        let strict = s != 0 && taker_strictly_reduces(e, e + s);
        assert!((strict && r == s.unsigned_abs()) || (clip && taker_flips(e, e + s) && r == e.unsigned_abs()));
        assert!(r <= e.unsigned_abs());
    } else {
        assert!(room.is_none());
    }
    kani::cover!(!red && s.unsigned_abs() > e.unsigned_abs() && e != 0 && (e > 0) != (s > 0) && !clip, "over-close not marked");
    kani::cover!(red && clip && taker_flips(e, e + s), "flip clipped to its close");
}

// ── R15: N-2 utilisation fee ──────────────────────────────────────────────────────────────

/// R15a / E1 (fee monotone in users OI): o1 <= o2 ⇒ (None at o1 ⇒ None at o2); 0 at o2 ⇒ 0 at
/// o1 (kink selection monotone); both on the slope ⇒ same den, num1 <= num2 (L1: P3); the cap
/// (u >= 1) is the top. Full width, ceil primitive stub_verified.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r15ab_util_fee_shape_and_monotone() {
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

/// R15b / E1 (fee monotone in the max dial): m1 <= m2 ⇒ (None at m1 ⇒ None at m2); both on
/// the slope ⇒ same num, den (L2 orders ceil(m·num/den): P3); clamp at the dial monotone.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_r15b_util_fee_monotone_in_max() {
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

/// R15c: closes never pay; a flip's closing part is never charged. `util_fee_on_fill_bps` by
/// its proven contract (floor); `opening_part_q` runs for real.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::util_fee_on_fill_bps)]
fn kani_growth_r15c_closes_never_pay() {
    let b: i64 = kani::any();
    let a: i64 = kani::any();
    let fee: u16 = kani::any();
    kani::assume(fee <= 2_000);
    let (b, a) = (b as i128, a as i128);
    let o = opening_part_q(b, a);
    if taker_strictly_reduces(b, a) {
        assert_eq!(o, 0);
        assert_eq!(util_fee_on_fill_bps(fee, o, b.abs_diff(a)), 0);
    }
    let fill = b.abs_diff(a);
    let r = util_fee_on_fill_bps(fee, o, fill);
    // charged rate * fill <= fee * opening (the closing part pays nothing)
    assert!(r as u128 * fill <= fee as u128 * o.min(fill));
    kani::cover!(taker_flips(b, a) && r > 0 && (r as u128) < fee as u128, "flip pays only its opening part");
    kani::cover!(taker_strictly_reduces(b, a) && a != b, "reduce pays 0");
    kani::cover!(!taker_strictly_reduces(b, a) && !taker_flips(b, a) && r == fee && fee > 0, "plain open pays the full rate");
}

/// R15e (wrapper composition, pure part): the fee a TradeCpi fill owes is 0 for closes, <= max,
/// and the trading-cap rule bounds base + matcher + util.
#[kani::proof]
fn kani_growth_r15e_trading_cap_rule() {
    let cap: u64 = kani::any();
    let base: u64 = kani::any();
    let u: u16 = kani::any();
    let ok = util_fee_fits_trading_cap(cap, base, u);
    let need = (base as u128) + GROWTH_PIN_MAX_REQUESTED_FEE_BPS as u128 + u as u128;
    assert_eq!(ok, need <= u64::MAX as u128 && cap as u128 >= need);
    kani::cover!(ok, "fits");
    kani::cover!(!ok && need > u64::MAX as u128, "overflow fails closed");
}

/// "One number", restated (security review Q3): since N-1 the TradeCpi preflight clip is
/// `growth_open_room_q(n, users_before)`, and the gate admits iff `users_before + opening <= n`.
/// For an opening leg the clip and the gate agree: `size <= room ⇔ users + size <= n`, and a
/// side already over the cap gets room 0. Full u128, no division.
#[kani::proof]
fn kani_growth_clip_iff_gate() {
    let n: u128 = kani::any();
    let users: u128 = kani::any();
    let size: u128 = kani::any();
    kani::assume(users.checked_add(size).is_some());
    let room = growth_open_room_q(n, users);
    if users <= n {
        assert_eq!(size <= room, users + size <= n);
    } else {
        assert_eq!(room, 0);
        assert!(users + size > n);
    }
    kani::cover!(users <= n && size == room && size > 0, "clip lands exactly on N_cap");
    kani::cover!(users <= n && size > room, "over the room");
    kani::cover!(users > n, "side already over");
}

