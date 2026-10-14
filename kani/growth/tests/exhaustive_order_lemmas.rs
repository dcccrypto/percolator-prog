//! Overnight 2026-10-14: EXHAUSTIVE native check (not Kani) of the order lemmas L1-L4 on the
//! production primitives over the FULL u8 operand domain of the original Kani harnesses
//! (kani_growth_l1..l4, NO-VERDICT in the v22 run). Monotonicity over all pairs x1 <= x2 is
//! equivalent to the adjacent step x -> x+1 (transitivity of <= on a finite chain), so each
//! lemma is 2^24 evaluations per side. Run: cargo test --release --test exhaustive_order_lemmas
use growth_v19_proofs::growth_v19::mul_div_ceil_u128 as ceil;
use growth_v19_proofs::vault_lp_v18::mul_div_floor as floor;

#[test]
fn l1_ceil_monotone_in_b_all_u8() {
    let mut n = 0u64;
    for a in 0..=255u128 {
        for d in 1..=255u128 {
            for b in 0..255u128 {
                assert!(ceil(a, b, d).unwrap() <= ceil(a, b + 1, d).unwrap(), "a={a} b={b} d={d}");
                n += 1;
            }
        }
    }
    assert_eq!(n, 256 * 255 * 255);
}

#[test]
fn l2_ceil_monotone_in_a_all_u8() {
    for b in 0..=255u128 {
        for d in 1..=255u128 {
            for a in 0..255u128 {
                assert!(ceil(a, b, d).unwrap() <= ceil(a + 1, b, d).unwrap(), "a={a} b={b} d={d}");
            }
        }
    }
}

#[test]
fn l3_ceil_antitone_in_d_all_u8() {
    for a in 0..=255u128 {
        for b in 0..=255u128 {
            for d in 1..255u128 {
                assert!(ceil(a, b, d + 1).unwrap() <= ceil(a, b, d).unwrap(), "a={a} b={b} d={d}");
            }
        }
    }
}

#[test]
fn l4_floor_monotone_in_a_all_u8() {
    for b in 0..=255u128 {
        for d in 1..=255u128 {
            for a in 0..255u128 {
                assert!(floor(a, b, d).unwrap() <= floor(a + 1, b, d).unwrap(), "a={a} b={b} d={d}");
            }
        }
    }
}

/// Negative control: the strict version of L1 must find a plateau (so the loop really runs).
#[test]
fn l1_negative_control_plateau_exists() {
    let mut plateau = false;
    'o: for a in 1..=255u128 {
        for d in 2..=255u128 {
            for b in 0..255u128 {
                if ceil(a, b, d) == ceil(a, b + 1, d) {
                    plateau = true;
                    break 'o;
                }
            }
        }
    }
    assert!(plateau);
}
