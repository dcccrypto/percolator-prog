// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! Reference-model property tests for the pure bond maths in `src/bond_v20.rs`.
//!
//! Each helper is compared with a SEPARATE, deliberately naive reference written differently
//! from the production code (branch-free min/max algebra, `i128`-free sign split, decomposed
//! multiplication instead of `checked_mul`). Scope: `tranche_split3`, `bond_impaired`,
//! `vault_value_worse`, `bond_util_bps`, `bond_coupon_rate_bps`, `coupon_due`.
//! Does not touch `coupon_settle` (#679).

use percolator_prog::bond_v20::*;
use proptest::prelude::*;

const BPS_U: u128 = 10_000;

/// Mix of edge values and uniform u128 so boundaries are hit often.
fn wide() -> impl Strategy<Value = u128> {
    prop_oneof![
        3 => any::<u128>(),
        3 => any::<u64>().prop_map(|x| x as u128),
        2 => 0u128..64,
        1 => Just(u128::MAX),
        1 => Just(u128::MAX - 1),
        1 => Just(1u128 << 90),
        1 => Just((1u128 << 90) - 1),
    ]
}

fn cfg() -> ProptestConfig {
    ProptestConfig { cases: 20_000, ..ProptestConfig::default() }
}

// ── references ──────────────────────────────────────────────────────────────────────────────

/// Reference waterfall: senior takes first, bond second, junior the remainder.
fn ref_split(v: u128, cs: u128, cb: u128) -> (u128, u128, u128) {
    let senior = v.min(cs);
    let bond = (v - senior).min(cb);
    (senior, bond, v - senior - bond)
}

/// Reference `a*b` fits u128 (division form).
fn mul_fits(a: u128, b: u128) -> bool {
    a == 0 || b <= u128::MAX / a
}

/// Reference `floor(bond*rate*dt / (BPS*SPY))` with dt clamped to one year, computed without a
/// 256-bit product: floor(a*dt/D) = (a/D)*dt + (a%D)*dt/D. `None` iff the production overflow
/// conditions (`bond*rate` or `(bond*rate)*dt` outside u128) hold, or the result exceeds u128.
fn ref_coupon_due(bond: u128, rate: u32, dslots: u64) -> Option<u128> {
    let dt = (dslots as u128).min(SLOTS_PER_YEAR);
    let d = BPS_U * SLOTS_PER_YEAR;
    if !mul_fits(bond, rate as u128) {
        return None;
    }
    let a = bond * rate as u128;
    if !mul_fits(a, dt) {
        return None;
    }
    Some((a / d) * dt + ((a % d) * dt) / d)
}


/// Exact floor(a*b/d) (d>0) via 256-bit product + bitwise long division; result saturates at u128::MAX.
fn ref_mul_div_floor(a: u128, b: u128, d: u128) -> u128 {
    let (a_hi, a_lo) = (a >> 64, a & u64::MAX as u128);
    let (b_hi, b_lo) = (b >> 64, b & u64::MAX as u128);
    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;
    let mid = (ll >> 64) + (lh & u64::MAX as u128) + (hl & u64::MAX as u128);
    let lo = (ll & u64::MAX as u128) | (mid << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    // long division of (hi:lo) by d
    let (mut r, mut q) = (0u128, 0u128);
    let mut overflow = false;
    for i in (0..256).rev() {
        let bit = if i >= 128 { (hi >> (i - 128)) & 1 } else { (lo >> i) & 1 };
        let carry = r >> 127;
        r = (r << 1) | bit;
        let ge = carry == 1 || r >= d;
        if ge { r = r.wrapping_sub(d); }
        if i >= 128 { if ge { overflow = true; } } else { q |= (ge as u128) << i; }
    }
    if overflow { u128::MAX } else { q }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn split3_matches_reference(v in wide(), cs in wide(), cb in wide()) {
        let s = tranche_split3(v, cs, cb);
        let (rs, rb, rj) = ref_split(v, cs, cb);
        prop_assert_eq!((s.senior, s.bond, s.junior), (rs, rb, rj));
        // conservation + seniority
        prop_assert_eq!(s.senior + s.bond + s.junior, v);
        prop_assert!(s.senior <= cs && s.bond <= cb);
        if s.junior > 0 { prop_assert!(s.senior == cs && s.bond == cb); }
        if s.senior < cs { prop_assert!(s.bond == 0 && s.junior == 0); }
        // senior paid first: raising senior claim never lowers senior payout
        prop_assert!(tranche_split3(v, cs.saturating_add(1), cb).senior >= s.senior);
    }

    #[test]
    fn impaired_matches_reference(v in wide(), cs in wide(), cb in wide()) {
        // independent form: impaired iff cb > 0 and V < cs + cb (in 256-bit-safe terms)
        let total_exceeds = match cs.checked_add(cb) { Some(t) => v < t, None => true };
        let r = cb > 0 && total_exceeds;
        prop_assert_eq!(bond_impaired(v, cs, cb), r);
    }

    #[test]
    fn worse_matches_reference(nav in wide(), lpv in wide(), w in any::<i128>()) {
        let got = vault_value_worse(nav, lpv, w);
        let want = if w >= 0 {
            // add min(w, lpv), saturating at u128::MAX
            let add = (w as u128).min(lpv);
            nav.checked_add(add).unwrap_or(u128::MAX)
        } else {
            // saturating deficit: |w| computed via two's complement without unsigned_abs
            let mag = (!(w as u128)).wrapping_add(1);
            nav.checked_sub(mag).unwrap_or(0)
        };
        prop_assert_eq!(got, want);
        if w >= 0 { prop_assert!(got >= nav && got - nav <= lpv); } else { prop_assert!(got <= nav); }
    }

    #[test]
    fn util_matches_reference(oi in wide(), n in wide()) {
        let got = bond_util_bps(oi, n);
        prop_assert!(got as u128 <= BPS_U);
        let want: u128 = if oi == 0 { 0 } else if n == 0 { BPS_U } else { ref_mul_div_floor(oi, BPS_U, n).min(BPS_U) };
        prop_assert_eq!(got as u128, want, "oi={} n={}", oi, n);
    }

    #[test]
    fn rate_matches_reference(base in any::<u16>(), bonus in any::<u16>(), u in any::<u16>()) {
        let uc = (u as u64).min(10_000);
        let want = base as u64 + (bonus as u64 * uc) / 10_000;
        prop_assert_eq!(bond_coupon_rate_bps(base, bonus, u) as u64, want);
        // zero bonus (the production setting) => rate is exactly base
        prop_assert_eq!(bond_coupon_rate_bps(base, 0, u), base as u32);
        // monotone in utilisation
        prop_assert!(bond_coupon_rate_bps(base, bonus, u) <= bond_coupon_rate_bps(base, bonus, u.saturating_add(1)));
    }

    #[test]
    fn coupon_due_matches_reference(bond in wide(), rate in prop_oneof![0u32..5_000, any::<u32>()], dt in prop_oneof![any::<u64>(), 0u64..200_000_000]) {
        prop_assert_eq!(coupon_due(bond, rate, dt), ref_coupon_due(bond, rate, dt));
    }

    #[test]
    fn coupon_due_one_year_clamp_and_bound(bond in 0u128..(1u128 << 90), rate in 0u32..=3_000, dt in any::<u64>()) {
        // documented: None only above 2^90 (rate <= 3000), so below it must be Some
        let due = coupon_due(bond, rate, dt);
        prop_assert!(due.is_some());
        let year = coupon_due(bond, rate, SLOTS_PER_YEAR as u64).unwrap();
        if dt as u128 >= SLOTS_PER_YEAR { prop_assert_eq!(due.unwrap(), year); }
        // one year at rate bps accrues at most bond*rate/10000
        prop_assert!(year <= bond * rate as u128 / BPS_U);
    }
}

#[test]
fn coupon_due_bound_pins() {
    assert_eq!(coupon_due(1u128 << 91, 3_000, u64::MAX), None);
    assert!(coupon_due((1u128 << 90) - 1, 3_000, u64::MAX).is_some());
    assert_eq!(coupon_due(u128::MAX, 0, 5), Some(0));
    assert_eq!(coupon_due(0, u32::MAX, u64::MAX), Some(0));
    // exact: 1e12 at 10% (1000 bps) for exactly one year = 1e11
    assert_eq!(coupon_due(1_000_000_000_000, 1_000, SLOTS_PER_YEAR as u64), Some(100_000_000_000));
}

#[test]
fn util_pins() {
    assert_eq!(bond_util_bps(0, 0), 0);
    assert_eq!(bond_util_bps(0, 99), 0);
    assert_eq!(bond_util_bps(1, 0), 10_000);
    assert_eq!(bond_util_bps(u128::MAX, 1), 10_000);
    assert_eq!(bond_util_bps(u128::MAX, u128::MAX), 10_000);
    assert_eq!(bond_util_bps(1, 2), 5_000);
    assert_eq!(bond_util_bps(1, 3), 3_333);
}
