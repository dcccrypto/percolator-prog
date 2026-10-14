//! NOT KANI. Supplementary evidence for the v2.2 overnight wrapper Kani splits (2026-10-14): exhaustive
//! NATIVE enumeration of the ORIGINAL W-C-5 / W-C-6 / W-D-1 / W-D-2 assertions on the REAL production
//! functions over small domains (stated per test), for the algebra halves whose Kani lemma had no verdict.
//! Every assertion is copied from the original harness.
#![cfg(not(kani))]

use percolator_prog::bond_v20::*;
use percolator_prog::p4_rescue_ins as p4;

/// W-C-5, amount / shares / value all in 0..=255 (16.7M points).
#[test]
fn enum_wc5_bond_deposit_no_dilution_u8() {
    let mut exact = 0u64;
    let mut floored = 0u64;
    for amount in 1u128..=255 {
        for b in 0u128..=255 {
            for value in 0u128..=255 {
                let m = bond_shares_for_deposit(amount, b, value);
                if b == 0 {
                    assert_eq!(m, Some(amount));
                } else if value == 0 {
                    assert!(m.is_none());
                } else {
                    let m = m.unwrap();
                    assert!((value + amount) * b >= value * (b + m), "incumbents not diluted");
                    assert!(m * value <= amount * b, "rounds down");
                    if (amount * b) % value == 0 { exact += 1 } else { floored += 1 }
                }
            }
        }
    }
    assert!(exact > 0 && floored > 0);
}

/// W-C-6, b / sh / cb / value all in 0..=63 (16.7M points; the original is u8).
#[test]
fn enum_wc6_bond_redemption_no_dilution_u6() {
    for b in 1u128..=63 {
        for sh in 0u128..=63 {
            for cb in 0u128..=63 {
                for value in 0u128..=cb {
                    let pay = bond_atoms_for_redemption(sh, b, value);
                    let cb2 = bond_claim_after_redemption(cb, sh, b);
                    if sh > b {
                        assert!(pay.is_none() && cb2.is_none());
                        continue;
                    }
                    let (pay, cb2) = (pay.unwrap(), cb2.unwrap());
                    assert!(pay <= value && pay * b <= sh * value);
                    if sh == b {
                        assert_eq!(cb2, 0);
                    } else {
                        assert!(cb2 * b >= cb * (b - sh));
                        assert!((value - pay) * b >= value * (b - sh));
                        if cb > 0 {
                            assert!(cb2 > 0);
                        }
                    }
                }
            }
        }
    }
}

/// W-D-1, v / c / s / x all in 0..=63 under the original's shape assumptions.
#[test]
fn enum_wd1_rescue_no_dilution_u6() {
    for v in 1u128..=63 {
        for c in (v + 1)..=63 {
            for s in 1u128..=63 {
                for x in 1u128..=(10 * v).min(63) {
                    let m = p4::rescue_shares(x, s, v).unwrap();
                    let dc = p4::rescue_claim_delta(m, c, s).unwrap();
                    assert!(p4::rescue_value_no_dilution(v, x, s, m));
                    assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
                }
            }
        }
    }
}

/// W-D-2, c / s / m all in 0..=255 (16.7M points).
#[test]
fn enum_wd2_rescue_par_per_share_u8() {
    for c in 0u128..=255 {
        for s in 1u128..=255 {
            for m in 0u128..=255 {
                let dc = p4::rescue_claim_delta(m, c, s).unwrap();
                assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
                assert!((c + dc) * s + s > c * (s + m));
            }
        }
    }
}
