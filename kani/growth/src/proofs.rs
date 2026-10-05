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

/// A gate input with every field symbolic (positions i16-wide, the rest bounded as stated by
/// the caller through `kani::assume`).
fn any_gate(lp_some: bool) -> GrowthGateIn {
    let tb: i16 = kani::any();
    let ta: i16 = kani::any();
    let lb: i16 = kani::any();
    let lm: i16 = kani::any();
    let la: i16 = kani::any();
    let ua: u16 = kani::any();
    let eq: u16 = kani::any();
    let lp = if lp_some {
        Some(GrowthLpIn {
            before_q: lb as i128,
            mid_q: lm as i128,
            after_q: la as i128,
            eff_after_abs_q: (la as i128).unsigned_abs(),
            users_oi_side_after_q: ua as u128,
            equity: eq as u128,
        })
    } else {
        None
    };
    GrowthGateIn {
        taker_before_q: tb as i128,
        taker_after_q: ta as i128,
        taker_eff_after_abs_q: (ta as i128).unsigned_abs(),
        taker_equity: kani::any::<u64>() as u128,
        taker_cert_initial_req: if kani::any() { Some(kani::any::<u64>() as u128) } else { None },
        lp,
        price_e6: if kani::any() { 1 } else { 0 },
        pos_scale: 1,
        engine_imr_bps: kani::any::<u16>() as u64,
        min_nonzero_im_req: kani::any::<u8>() as u128,
        ceil_imr_bps: kani::any::<u16>() as u64,
        lambda_bps: 10_000,
        kink_bps: kani::any(),
        crowd_blocked: kani::any(),
        asset_bound: kani::any(),
    }
}

// ── §1 contracts (rev 6: proof_for_contract on the PRODUCTION functions) ─────────────────
// Primitives: the only harnesses that bit-blast a divider. Bounded domain (u8 operands,
// widened); the lift to u128 is the paper step in the results file (exact floor / ceil of
// naturals is width-independent wherever the product does not overflow, and every overflow is
// `None`, proved at FULL width by the `_none_full_width` harnesses, which contain no divider
// on any reachable path).

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
}

/// The overflow `None` branch at FULL u128 width (no divider is reachable: `checked_mul` fails).
#[kani::proof]
fn kani_growth_c_mul_div_none_full_width() {
    let a: u128 = kani::any();
    let b: u128 = kani::any();
    let d: u128 = kani::any();
    kani::assume(d > 0 && a.checked_mul(b).is_none());
    assert!(crate::vault_lp_v18::mul_div_floor(a, b, d).is_none());
    assert!(mul_div_ceil_u128(a, b, d).is_none());
    assert!(crate::vault_lp_v18::mul_div_floor(a, b, 0).is_none());
    kani::cover!(a > 0 && b > 0, "overflow reached");
}

// Composite contracts: the primitives are stubbed by their PROVEN contracts, so no divider
// remains; full-width u128 operands unless stated.

#[kani::proof_for_contract(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_c_n_cap_q() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = n_cap_q(c, l, p, s);
    kani::cover!(p == 0, "price 0 -> None");
    kani::cover!(p != 0 && r.is_none(), "overflow -> None");
    kani::cover!(r.is_some_and(|n| n > 0), "capacity");
}

#[kani::proof_for_contract(crate::growth_v19::liquidity_notional_e6)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_c_liquidity_notional_e6() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let r = liquidity_notional_e6(c, l);
    kani::cover!(r.is_none(), "overflow");
    kani::cover!(r.is_some_and(|x| x > 0), "depth");
}

#[kani::proof_for_contract(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_c_dyn_imr_bps() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    kani::cover!(base <= 10_000 && k <= 10_000 && n > 0 && lp <= n && r == Some(base) && lp > 0, "below the kink");
    kani::cover!(r.is_some_and(|x| x > base && x < 10_000), "on the slope");
    kani::cover!(lp == n && n > 0 && k < 10_000 && r == Some(10_000), "u == 1 at 100%");
    kani::cover!(base <= 10_000 && k <= 10_000 && lp > n, "u > 1 refused");
    kani::cover!(base <= 10_000 && k <= 10_000 && n > 0 && lp <= n && r.is_none(), "overflow refused");
}

#[kani::proof_for_contract(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_c_leg_im_req() {
    let n: u128 = kani::any();
    let imr: u64 = kani::any();
    let m: u128 = kani::any();
    let r = leg_im_req(n, imr, m);
    kani::cover!(n == 0, "flat");
    kani::cover!(n > 0 && imr <= 10_000 && r.is_none(), "overflow");
    kani::cover!(r.is_some_and(|v| v == m && m > 0 && n > 0), "min binds");
    kani::cover!(r.is_some_and(|v| v > m && n > 0), "ceil binds");
}

#[kani::proof_for_contract(crate::growth_v19::risk_notional_ceil)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_c_risk_notional_ceil() {
    let q: u128 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = risk_notional_ceil(q, p, s);
    kani::cover!(s == 0, "zero scale");
    kani::cover!(s > 0 && r.is_none(), "overflow");
    kani::cover!(r.is_some_and(|x| x > 0), "notional");
}

#[kani::proof_for_contract(crate::growth_v19::utilisation_fee_bps)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_c_utilisation_fee_bps() {
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    let r = utilisation_fee_bps(o, n, k, m);
    kani::cover!(n == 0, "n 0 -> None");
    kani::cover!(r == Some(0) && m > 0 && o > 0, "at/below the kink");
    kani::cover!(r.is_some_and(|f| f > 0 && f < m), "on the slope");
    kani::cover!(r.is_some_and(|f| f == m && m > 0), "capped at max");
}

#[kani::proof_for_contract(crate::growth_v19::util_fee_on_fill_bps)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_c_util_fee_on_fill_bps() {
    let f: u16 = kani::any();
    let o: u128 = kani::any();
    let fill: u128 = kani::any();
    let r = util_fee_on_fill_bps(f, o, fill);
    kani::cover!(r == f && f > 0, "plain open: full rate");
    kani::cover!(r > 0 && r < f, "flip: opening share");
    kani::cover!(fill > 0 && o > 0 && f > 0 && r == 0, "rounds to 0");
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
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t1_required_imr_bounds() {
    let g = any_gate(kani::any());
    kani::assume(g.engine_imr_bps <= 10_000);
    let r = growth_required_imr_bps(&g);
    if let Ok(r) = r {
        assert!(r >= g.engine_imr_bps && r <= 10_000);
    }
    kani::cover!(r.is_ok() && g.lp.is_some(), "crowd or thin, admitted");
    kani::cover!(r == Err(GrowthVerdict::LeverageExceeded), "ceil < engine refused");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull), "capacity refusal");
    // A5 / amendment 9: each stub branch, including None
    let crowd = g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q));
    kani::cover!(g.lp.is_some() && g.price_e6 == 0 && !(crowd && g.crowd_blocked) && r == Err(GrowthVerdict::CapacityFull), "stub n_cap_q -> None (price 0)");
    kani::cover!(g.price_e6 == 1 && crowd && !g.crowd_blocked && g.lp.is_some_and(|l| l.users_oi_side_after_q > l.equity) && r == Err(GrowthVerdict::CapacityFull), "stub dyn_imr_bps -> None (crowd past N_cap)");
    kani::cover!(g.price_e6 == 1 && crowd && !g.crowd_blocked && r.is_ok_and(|x| x > g.ceil_imr_bps), "stub dyn_imr_bps -> Some (above the kink)");
}

/// Bound: u16 notional, u64 cert, dyn >= eng. `leg_im_req` by its proven contract.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
fn kani_growth_t1_requirement_never_below_engine_or_per_asset() {
    let n: u16 = kani::any();
    let eng: u16 = kani::any();
    let dy: u16 = kani::any();
    let m: u8 = kani::any();
    kani::assume(eng <= dy && dy <= 10_000);
    let cert: Option<u64> = if kani::any() { Some(kani::any()) } else { None };
    let r = growth_margin_required(cert.map(|c| c as u128), n as u128, eng as u64, dy as u64, m as u128);
    // exact contract values (spec relations, not re-computation)
    let per_asset: u128 = kani::any();
    kani::assume(spec::leg_im_req(n as u128, dy as u64, m as u128, Some(per_asset)));
    let eng_leg: u128 = kani::any();
    kani::assume(spec::leg_im_req(n as u128, eng as u64, m as u128, Some(eng_leg)));
    let r = r.unwrap();
    assert!(r >= per_asset);
    if let Some(c) = cert {
        if c as u128 >= eng_leg {
            assert!(r >= c as u128);
        }
    }
    kani::cover!(cert.is_some_and(|c| c as u128 >= eng_leg) && n > 0, "cert path");
    kani::cover!(cert.is_none() && n > 0, "no cert");
    kani::cover!(cert.is_some_and(|c| (c as u128) < eng_leg), "saturating path");
}

// ── Target 2 ──────────────────────────────────────────────────────────────────────────────

/// A3: monotone in |LP| from two EXACT contract instances (no division). Bound: u8 lp, n.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
fn kani_growth_t2_dyn_imr_monotone_in_lp() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let n: u8 = kani::any();
    let base: u16 = kani::any();
    let k: u16 = kani::any();
    kani::assume(a <= b && b <= n && n > 0 && base <= 10_000 && k <= 10_000);
    let ra = dyn_imr_bps(a as u128, n as u128, base as u64, k).unwrap();
    let rb = dyn_imr_bps(b as u128, n as u128, base as u64, k).unwrap();
    assert!(ra <= rb);
    kani::cover!(ra == base as u64 && rb == base as u64 && a < b, "both below the kink");
    kani::cover!(ra == base as u64 && rb > base as u64, "straddles the kink");
    kani::cover!(ra > base as u64 && rb > ra, "both above, strict");
    kani::cover!(ra > base as u64 && rb == ra && a < b, "equal above the kink (ceil plateau)");
}

/// A3: antitone in N_cap from two exact contract instances (None = +inf). Bound: u8.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
fn kani_growth_t2_dyn_imr_antitone_in_ncap() {
    let lp: u8 = kani::any();
    let n1: u8 = kani::any();
    let n2: u8 = kani::any();
    let base: u16 = kani::any();
    let k: u16 = kani::any();
    kani::assume(n1 <= n2 && base <= 10_000 && k <= 10_000);
    let r1 = dyn_imr_bps(lp as u128, n1 as u128, base as u64, k);
    let r2 = dyn_imr_bps(lp as u128, n2 as u128, base as u64, k);
    match (r1, r2) {
        (Some(a), Some(b)) => assert!(b <= a),
        (Some(_), None) => panic!("more capacity refused"),
        _ => {}
    }
    kani::cover!(r1.is_none() && r2.is_some(), "capital opens the crowd");
    kani::cover!(r1.is_some_and(|a| r2.is_some_and(|b| b < a)), "strictly cheaper");
    kani::cover!(r1.is_some_and(|a| r2 == Some(a)) && n1 < n2, "equal");
}

/// Gate level, relational: more conservative equity never tightens the required IMR. Real
/// `n_cap_q` / `dyn_imr_bps` CONTRACTS (price drawn freely). Bound: u8 equity / users / price.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
fn kani_growth_t2_required_imr_antitone_in_cm() {
    let mut g = any_gate(true);
    g.price_e6 = kani::any::<u8>() as u64;
    let e2: u8 = kani::any();
    let mut l = g.lp.unwrap();
    kani::assume(l.equity <= e2 as u128 && l.users_oi_side_after_q <= 255);
    kani::assume(g.ceil_imr_bps <= 10_000 && g.engine_imr_bps <= g.ceil_imr_bps && g.kink_bps <= 10_000);
    let r1 = growth_required_imr_bps(&g);
    l.equity = e2 as u128;
    g.lp = Some(l);
    let r2 = growth_required_imr_bps(&g);
    match (r1, r2) {
        (Ok(a), Ok(b)) => assert!(b <= a),
        (Ok(_), Err(_)) => panic!("more capital refused"),
        _ => {}
    }
    kani::cover!(r1.is_err() && r2.is_ok(), "capital opens");
    kani::cover!(matches!((r1, r2), (Ok(a), Ok(b)) if b < a), "capital cheapens");
    kani::cover!(matches!((r1, r2), (Ok(a), Ok(b)) if b == a) && l.equity > 0, "equal");
    kani::cover!(g.price_e6 == 0, "price 0 (both refused)");
}

// ── Target 3 ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t3_reductions_always_pass() {
    let g = any_gate(kani::any());
    kani::assume(!taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
    kani::cover!(g.taker_equity == 0 && g.taker_after_q != 0, "reduce with zero equity");
    kani::cover!(g.crowd_blocked && !g.asset_bound, "reduce under h-lock, unbound");
    kani::cover!(g.taker_after_q == 0 && g.taker_before_q != 0, "close to flat");
    kani::cover!(
        g.lp.is_some_and(|l| l.users_oi_side_after_q > l.equity),
        "reduce while the side is over capacity"
    );
}

/// Restated in rev 4: a thin open pays only the ceiling and is never stepped; it is refused
/// (CapacityFull) only when its OWN side's users OI would pass N_cap.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t3_thin_side_gets_only_the_ceiling() {
    let g = any_gate(true);
    let l = g.lp.unwrap();
    kani::assume(!joins_crowd(l.mid_q, l.after_q));
    kani::assume(g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps);
    kani::assume(g.price_e6 != 0 && l.equity != u128::MAX);
    let r = growth_required_imr_bps(&g);
    if l.users_oi_side_after_q <= l.equity {
        assert_eq!(r, Ok(g.ceil_imr_bps));
    } else {
        assert_eq!(r, Err(GrowthVerdict::CapacityFull));
    }
    kani::cover!(r == Ok(g.ceil_imr_bps) && g.crowd_blocked, "thin under the h-lock");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull), "thin side over its own cap");
    kani::cover!(r.is_ok() && l.users_oi_side_after_q == l.equity && l.equity > 0, "thin lands on N_cap");
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
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t4_zero_price_fails_closed() {
    let mut g = any_gate(kani::any());
    g.price_e6 = 0;
    kani::assume(taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    assert_ne!(growth_gate(&g), GrowthVerdict::Allow);
    kani::cover!(g.lp.is_none(), "no LP");
    kani::cover!(g.lp.is_some() && g.asset_bound, "bound crowd");
}

/// Unbounded u128 inputs on the multiply paths: every None maps to a refusal, nothing panics.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t4_overflow_fails_closed() {
    let mut g = any_gate(true);
    let mut l = g.lp.unwrap();
    l.equity = kani::any();
    g.lp = Some(l);
    g.taker_eff_after_abs_q = kani::any();
    g.taker_cert_initial_req = if kani::any() { Some(kani::any()) } else { None };
    g.taker_equity = kani::any();
    g.price_e6 = kani::any();
    let v = growth_gate(&g);
    let notional = risk_notional_ceil(g.taker_eff_after_abs_q, g.price_e6, g.pos_scale);
    if notional.is_none() && taker_risk_increasing(g.taker_before_q, g.taker_after_q) {
        assert_ne!(v, GrowthVerdict::Allow);
    }
    kani::cover!(notional.is_none() && v == GrowthVerdict::LeverageExceeded, "notional overflow refused");
    kani::cover!(g.lp.unwrap().equity > u128::MAX / 10_000 && g.price_e6 > 0 && g.asset_bound && v == GrowthVerdict::CapacityFull, "N_cap overflow (None) refused");
    kani::cover!(g.price_e6 > 0 && g.asset_bound && notional.is_some() && v == GrowthVerdict::LeverageExceeded, "requirement refused");
    kani::cover!(v == GrowthVerdict::Allow, "admitted");
    let crowd = joins_crowd(l.mid_q, l.after_q);
    kani::cover!(!crowd && g.asset_bound && notional.is_some_and(|x| x.checked_mul(g.ceil_imr_bps as u128).is_none()) && v == GrowthVerdict::LeverageExceeded, "stub leg_im_req -> None (overflow) refused");
    kani::cover!(crowd && !g.crowd_blocked && g.asset_bound && g.price_e6 > 0 && g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps && l.users_oi_side_after_q > l.equity && taker_risk_increasing(g.taker_before_q, g.taker_after_q) && v == GrowthVerdict::CapacityFull, "stub dyn_imr_bps -> None refused");
}

// ── Target 5 (rev 4: users OI) ────────────────────────────────────────────────────────────

/// Any admitted risk-increasing fill leaves its side's users OI <= N_cap, for ANY equity.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t5_capacity_invariant() {
    let mut g = any_gate(true);
    g.taker_equity = u128::MAX / 4;
    kani::assume(taker_risk_increasing(g.taker_before_q, g.taker_after_q));
    let l = g.lp.unwrap();
    let v = growth_gate(&g);
    if v == GrowthVerdict::Allow {
        assert!(l.users_oi_side_after_q <= l.equity);
    }
    kani::cover!(v == GrowthVerdict::Allow && l.users_oi_side_after_q == l.equity && l.equity > 0, "u == 1 admitted");
    kani::cover!(v == GrowthVerdict::CapacityFull && l.users_oi_side_after_q > l.equity, "u > 1 refused");
    kani::cover!(v == GrowthVerdict::CapacityFull && l.equity == 0 && g.asset_bound, "N_cap 0 refuses");
    // stub branches: n_cap_q is never None here (the gate returns at price 0; lambda 1x, scale 1,
    // u16 equity cannot overflow) -- its None branch is covered at full width in t4_overflow.
    kani::cover!(v == GrowthVerdict::CapacityFull && joins_crowd(l.mid_q, l.after_q) && !g.crowd_blocked && l.users_oi_side_after_q > l.equity, "stub dyn_imr_bps -> None (crowd past N_cap)");
    kani::cover!(v == GrowthVerdict::Allow && joins_crowd(l.mid_q, l.after_q), "stub dyn_imr_bps -> Some");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_t5_at_capacity_costs_full_margin() {
    let mut g = any_gate(true);
    let mut l = g.lp.unwrap();
    kani::assume(joins_crowd(l.mid_q, l.after_q) && !g.crowd_blocked && g.price_e6 != 0);
    kani::assume(l.equity > 0 && l.equity != u128::MAX);
    l.users_oi_side_after_q = l.equity;
    g.lp = Some(l);
    kani::assume(g.kink_bps < 10_000 && g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps);
    let r = growth_required_imr_bps(&g);
    assert_eq!(r, Ok(10_000));
    kani::cover!(r == Ok(10_000), "full margin at capacity");
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

/// mmr >= r_gap + fee ⇒ the maintenance requirement covers the gap loss plus the liquidation
/// fee EXACTLY, on the PRODUCTION primitives (contracts): ceil(N*mmr) >= floor(N*r) + ceil(N*f)
/// (all /1e4). Bound: u16 notional, bps <= 1e4.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_t7_rule_implies_gap_solvency() {
    let n: u16 = kani::any();
    let r: u16 = kani::any();
    let f: u16 = kani::any();
    let mmr: u16 = kani::any();
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let n = n as u128;
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

/// Bound: u8 positions / equity / price, lev u16, scale 1. `notional_atoms` -> `mul_div_floor`
/// by its proven contract.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_h2_admit_iff_within_ncap() {
    let b: i8 = kani::any();
    let a: i8 = kani::any();
    let eq: u8 = kani::any();
    let lev: u16 = kani::any();
    let p: u8 = kani::any();
    kani::assume(vault_lp_v18::joins_crowd(b as i128, a as i128));
    let ok = vault_lp_v18::vault_lp_exposure_allowed(b as i128, a as i128, eq as u128, lev as u32, p as u64, 1);
    let notional = (a as i128).unsigned_abs() * p as u128;
    assert_eq!(ok, notional <= eq as u128 * lev as u128 / 10_000);
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
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
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
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
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
    kani::cover!(opens && g.asset_bound && g.price_e6 == 1 && g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q) && l.users_oi_side_after_q > l.equity) && !g.crowd_blocked && v == GrowthVerdict::CapacityFull, "stub dyn_imr_bps -> None refused");
    kani::cover!(opens && g.asset_bound && g.price_e6 == 0 && g.lp.is_some() && v == GrowthVerdict::LeverageExceeded, "price 0 refused before n_cap_q");
}

/// R5: the wrapper's engine-IMR leg (`leg_im_req`, proven contract) is <= the engine's per-leg
/// IM: engine `margin_requirement(notional, bps, floor) = max(ceil(notional*bps/1e4), floor)`
/// (0 when flat; percolator src/v16.rs:23050-23056, mul_div_ceil_u128_or_wide: never None) plus
/// `target_lag_penalty >= 0` (src/v16.rs:3325-3365). Stated as the engine's CONTRACT (the same
/// exact ceil relation), not a copy of its code. Full u128; the wrapper fails closed (None) where
/// the engine goes wide.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
fn kani_growth_r5_eng_leg_le_engine_leg() {
    let n: u128 = kani::any();
    let imr: u64 = kani::any();
    let m: u128 = kani::any();
    kani::assume(imr <= 10_000);
    let penalty: u128 = kani::any();
    let engine: u128 = kani::any();
    // engine contract (non-overflow domain of the u128 product)
    let engine_ok = if n == 0 {
        engine == 0
    } else {
        match n.checked_mul(imr as u128) {
            None => false,
            Some(p) => {
                let c: u128 = kani::any();
                spec::ceil_rel(p, 10_000, c) && engine == if c > m { c } else { m }
            }
        }
    };
    kani::assume(engine_ok);
    let total = engine.checked_add(penalty);
    kani::assume(total.is_some());
    let w = leg_im_req(n, imr, m);
    if let Some(w) = w {
        assert!(w <= total.unwrap());
        assert_eq!(w, engine);
    }
    kani::cover!(w.is_some_and(|x| x > 0) && penalty == 0, "equal at zero penalty");
    kani::cover!(w.is_some() && penalty > 0, "penalty slack");
}

/// R8: the ext-v3 caps say CLOSED exactly when the gate's N_cap is 0 / None or the h-lock is
/// latched; otherwise they ARE N_cap (its exact contract) and a positive depth.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::liquidity_notional_e6)]
fn kani_growth_r8_caps_view_agrees_with_gate() {
    let hlock: bool = kani::any();
    let c: u128 = kani::any();
    let p: u64 = kani::any();
    let (cap, liq) = growth_matcher_caps(hlock, c, 10_000, p, 1_000_000, u128::MAX);
    if hlock {
        assert_eq!((cap, liq), (0, 0));
    } else if cap == 0 {
        assert_eq!(liq, 0);
        // closed only when the contract's N_cap is None or 0
        assert!(spec::n_cap_q(c, 10_000, p, 1_000_000, None) || spec::n_cap_q(c, 10_000, p, 1_000_000, Some(0)));
    } else {
        assert!(spec::n_cap_q(c, 10_000, p, 1_000_000, Some(cap)));
    }
    kani::cover!(hlock, "h-lock closes");
    kani::cover!(!hlock && c == 0 && p > 0, "C_m 0 closes");
    kani::cover!(!hlock && p == 0, "price 0 closes");
    kani::cover!(cap > 0 && liq > 0, "open");
    kani::cover!(!hlock && p > 0 && c > 0 && cap == 0 && c.checked_mul(10_000).is_none(), "overflow closes");
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
/// taker's side after the step, LP = -sum users). `n` = N_cap via the n_cap_q stub (= equity).
fn admits(p: &[i128; 3], i: usize, d: i128, n: u128) -> bool {
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

/// R11: INV(p, n) ∧ admitted gated fill ⇒ INV(p', n). Bound: i8 positions, i8 step, u8 n.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_r11_capacity_invariant_inductive() {
    let p = [kani::any::<i8>() as i128, kani::any::<i8>() as i128, kani::any::<i8>() as i128];
    let n = kani::any::<u8>() as u128;
    let i: usize = kani::any();
    kani::assume(i < 3);
    let d = kani::any::<i8>() as i128;
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
/// it is refused. (iv) is (iii) after an n decrease. Bound: i8 positions, u8 n.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::n_cap_q)]
#[kani::stub_verified(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::leg_im_req)]
#[kani::stub_verified(crate::growth_v19::risk_notional_ceil)]
fn kani_growth_r11b_ungated_transitions() {
    let p = [kani::any::<i8>() as i128, kani::any::<i8>() as i128, kani::any::<i8>() as i128];
    let n = kani::any::<u8>() as u128;
    let which: u8 = kani::any();
    if which == 0 {
        // (i) user i closes into user j, both strictly reducing
        let d = kani::any::<i8>() as i128;
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
                let s = kani::any::<i8>() as i128;
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
        let d = kani::any::<i8>() as i128;
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

/// R15a + R15b, from two EXACT contract instances (A3). Bound: u8 users OI / n, max <= 2000.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub_verified(crate::growth_v19::utilisation_fee_bps)]
fn kani_growth_r15ab_util_fee_shape_and_monotone() {
    let o1: u8 = kani::any();
    let o2: u8 = kani::any();
    let n: u8 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    kani::assume(o1 <= o2 && n > 0 && k <= 10_000 && m <= 2_000);
    let f1 = utilisation_fee_bps(o1 as u128, n as u128, k, m).unwrap();
    let f2 = utilisation_fee_bps(o2 as u128, n as u128, k, m).unwrap();
    if o1 as u128 * 10_000 <= k as u128 * n as u128 {
        assert_eq!(f1, 0);
    }
    if o2 == n && k < 10_000 {
        assert_eq!(f2, m, "the full rate at u == 1");
    }
    assert!(f1 <= m && f2 <= m && f1 <= f2);
    assert!(utilisation_fee_bps(1, 0, k, m).is_none());
    kani::cover!(f1 == 0 && f2 > 0, "crosses the kink");
    kani::cover!(f2 == m && m > 0, "capped at max");
    kani::cover!(f1 > 0 && f1 < f2, "strictly rising");
    kani::cover!(f1 > 0 && f1 == f2 && o1 < o2, "equal (ceil plateau)");
}

/// R15b (max): a raised dial never charges less (two exact contract instances). Bound: u8.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::stub_verified(crate::growth_v19::utilisation_fee_bps)]
fn kani_growth_r15b_util_fee_monotone_in_max() {
    let o: u8 = kani::any();
    let n: u8 = kani::any();
    let k: u16 = kani::any();
    let m1: u16 = kani::any();
    let m2: u16 = kani::any();
    kani::assume(n > 0 && k <= 10_000 && m1 <= m2 && m2 <= 2_000);
    let a = utilisation_fee_bps(o as u128, n as u128, k, m1).unwrap();
    let b = utilisation_fee_bps(o as u128, n as u128, k, m2).unwrap();
    assert!(a <= b);
    kani::cover!(a < b, "raised dial charges more");
    kani::cover!(a == b && m1 < m2 && a > 0, "equal");
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

