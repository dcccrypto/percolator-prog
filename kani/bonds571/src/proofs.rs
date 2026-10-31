//! Kani harnesses for the GH#571 carried coupon (production `bond_v20`). Local only:
//!   cargo kani -j 2 --harness <name>
//! Every harness carries `kani::cover!` witnesses; a harness whose covers are not ALL satisfied
//! is vacuous and does not count as a pass. BOUNDED proofs: symbolic values are u8 / u16 / u32
//! (cast to u128) wherever a symbolic u128 multiply + divide occurs; the full-width statement of
//! each law is the proptest in `tests/v22_bond_carry_571_pure.rs`.

use crate::bond_v20::*;

const D: u128 = 10_000 * SLOTS_PER_YEAR; // the coupon denominator BPS * 1y

/// Settlement: no overflow on the bounded domain; closed keeps A exactly; open is monotone
/// (A' >= A), capped (A' <= max(A, cap)), adds at most one interval's coupon on K, and adds
/// EXACTLY that coupon when the cap does not bind.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_settle_monotone_capped_no_overflow() {
    let cb: u8 = kani::any();
    let a: u8 = kani::any();
    let rate: u16 = kani::any();
    kani::assume(rate <= 2_000);
    let dt: u32 = kani::any();
    let open: bool = kani::any();
    let (cb, a) = (cb as u128, a as u128);
    let k = cb + a;
    let r = coupon_settle(cb, a, rate as u32, dt as u64, open, k);
    assert!(r.is_some(), "no overflow");
    let a2 = r.unwrap();
    if !open {
        assert!(a2 == a);
    } else {
        let cap = coupon_arrears_cap(cb, rate as u32).unwrap();
        let due = coupon_due(k, rate as u32, dt as u64).unwrap();
        assert!(a2 >= a);
        assert!(a2 <= if cap > a { cap } else { a });
        assert!(a2 - a <= due);
        if a + due <= cap {
            assert!(a2 == a + due);
        }
    }
    kani::cover!(open && a2 > a, "accrues");
    kani::cover!(open && a2 > a && a2 == coupon_arrears_cap(cb, rate as u32).unwrap(), "cap binds");
    kani::cover!(!open && a > 0, "closed keeps arrears");
}

/// Settlement is monotone in elapsed time.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_settle_monotone_in_time() {
    let cb: u8 = kani::any();
    let a: u8 = kani::any();
    let rate: u16 = kani::any();
    kani::assume(rate <= 2_000);
    let dt: u32 = kani::any();
    let e: u32 = kani::any();
    let (cb, a) = (cb as u128, a as u128);
    let x = coupon_settle(cb, a, rate as u32, dt as u64, true, cb + a).unwrap();
    let y = coupon_settle(cb, a, rate as u32, dt as u64 + e as u64, true, cb + a).unwrap();
    assert!(y >= x);
    kani::cover!(y > x, "strictly later accrues more");
}

/// Paying from a leg conserves the leg AND the bonds' claim (coupon moves A -> C_b).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_pay_conserves_leg_and_claim() {
    let avail: u64 = kani::any();
    let a: u64 = kani::any();
    let cb: u64 = kani::any();
    let (avail, a, cb) = (avail as u128, a as u128, cb as u128);
    let (coupon, rest, a2) = coupon_pay_from_leg(avail, a);
    assert!(coupon + rest == avail);
    assert!(coupon + a2 == a);
    assert!(coupon <= avail / 2);
    // claim before == claim after the credit
    assert!(bond_claim_total(cb + coupon, a2) == bond_claim_total(cb, a));
    kani::cover!(a2 > 0 && coupon > 0, "partial payment carries the rest");
    kani::cover!(a2 == 0 && coupon > 0, "full payment");
}

/// Redemption: the removed claim is exactly the whole-tranche payout; the C_b slice equals the
/// pre-#571 slice; full redemption empties both; partial keeps C_b > 0; arrears never grow;
/// remaining holders are never diluted.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_redemption_slices_full_claim() {
    let cb: u8 = kani::any();
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let sh: u8 = kani::any();
    let (cb, a, b, sh) = (cb as u128, a as u128, b as u128, sh as u128);
    kani::assume(cb > 0 && b > 0); // reachable: C_b == 0 <=> B == 0
    let r = bond_claims_after_redemption(cb, a, sh, b);
    if sh > b {
        assert!(r.is_none());
        return;
    }
    let (cb2, a2) = r.unwrap();
    let k = cb + a;
    let pay = bond_atoms_for_redemption(sh, b, k).unwrap();
    assert!(cb2 + a2 + pay == k);
    assert!(cb2 == bond_claim_after_redemption(cb, sh, b).unwrap());
    assert!(a2 <= a);
    if sh == b {
        assert!(cb2 == 0 && a2 == 0);
    } else {
        assert!(cb2 > 0);
        assert!((cb2 + a2) * b >= k * (b - sh));
    }
    kani::cover!(sh > 0 && sh < b && a > 0 && a2 < a, "partial with arrears");
    kani::cover!(sh == b && a > 0, "last redeemer takes the arrears");
}

/// NEWCOMER NEUTRALITY over one deposit + one settlement (the whole-tranche case the processor
/// admits): incumbents hold `b` shares of claim `k = cb + a`; a newcomer deposits `d` and mints
/// `m = bond_shares_for_deposit(d, b, k)`; then `dt` slots accrue on the new claim. Then
///   newcomer value  <= d * (1 + r dt)            (takes nothing of the incumbents' accrual)
///   incumbents value >= k * (1 + r dt) - 1        (keep theirs, up to one settlement floor)
/// with `r dt = rate * dt / D`, stated cross-multiplied (exact, no division).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_newcomer_neutral_within_rounding() {
    let cb: u8 = kani::any();
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let d: u8 = kani::any();
    let rate: u16 = kani::any();
    let dt: u32 = kani::any();
    kani::assume(cb > 0 && b > 0 && d > 0 && rate <= 2_000);
    kani::assume(dt as u128 <= SLOTS_PER_YEAR); // coupon_due clamps longer intervals at one year
    let (cb, a, b, d, rate) = (cb as u128, a as u128, b as u128, d as u128, rate as u32);
    let k = cb + a;
    let m = bond_shares_for_deposit(d, b, k).unwrap();
    kani::assume(m > 0); // m == 0 is refused (BondSlippage)
    let (cb1, a1) = (cb + d, a);
    let k1 = cb1 + a1;
    let a2 = coupon_settle(cb1, a1, rate, dt as u64, true, k1).unwrap();
    // the cap does not bind (its effect is pro rata on every share; covered separately)
    kani::assume(a2 == a1 + coupon_due(k1, rate, dt as u64).unwrap());
    let k2 = cb1 + a2;
    let bt = b + m;
    let growth = rate as u128 * dt as u128; // r dt = growth / D
    // newcomer: m * k2 / bt <= d * (D + growth) / D
    assert!(m * k2 * D <= bt * d * (D + growth));
    // incumbents: b * k2 / bt >= k * (D + growth) / D - 1
    assert!(b * k2 * D + bt * D >= bt * k * (D + growth));
    kani::cover!(a > 0 && growth > 0 && a2 > a1, "carried arrears + new accrual");
}
