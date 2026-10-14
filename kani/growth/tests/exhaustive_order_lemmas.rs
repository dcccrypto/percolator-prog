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

/// LEGMONO (consumed by kani_growth_wn_g1_*): for every u16 notional n and IMR i in 0..1e4,
/// ceil(n·i/1e4) <= ceil(n·(i+1)/1e4) (adjacent ⇒ all pairs by transitivity). 6.5e8 evaluations.
#[test]
fn legmono_ceil_bps_monotone_in_imr_all_u16() {
    for n in 0..=65_535u128 {
        let mut prev = ceil(n, 0, 10_000).unwrap();
        for i in 1..=10_000u128 {
            let q = ceil(n, i, 10_000).unwrap();
            assert!(prev <= q, "n={n} i={i}");
            prev = q;
        }
    }
}

/// T7m (consumed by the T7 split; kani_growth_t7m NO-VERDICT): for every n in u8 and r, f with
/// r + f <= 1e4: ceil(n(r+f)/1e4) >= floor(nr/1e4) + ceil(nf/1e4). mmr > r + f reduces to this by
/// LEGMONO (ceil(n·i/1e4) monotone in i). Run on the REAL primitives. 1.3e10 cases, 8 threads.
#[test]
fn t7m_gap_solvency_all_u8_notional() {
    let hs: Vec<_> = (0..8u128)
        .map(|t| {
            std::thread::spawn(move || {
                for n in (0..=255u128).filter(|n| n % 8 == t) {
                    for r in 0..=10_000u128 {
                        let gap = floor(n, r, 10_000).unwrap();
                        for f in 0..=(10_000 - r) {
                            let mm = ceil(n, r + f, 10_000).unwrap();
                            let fee = ceil(n, f, 10_000).unwrap();
                            assert!(mm >= gap + fee, "n={n} r={r} f={f}");
                        }
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
}
