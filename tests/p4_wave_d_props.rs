//! Phase 4 Wave D property tests (items 5 + 6) on the REAL pure functions in
//! `src/p4_rescue_ins.rs`, at wide widths (the Kani harnesses in the design note bound the same
//! functions to u8/u16/u32 inputs; neither alone is the claim). Each property has the design's
//! mutant as a NEGATIVE CONTROL: a deterministic search shows the mutant violates it, so the
//! property is not vacuous.
#![cfg(not(kani))]

use percolator_prog::p4_rescue_ins as p4;
use proptest::prelude::*;

const CAP: u128 = 1u128 << 64; // atoms / shares / units are u64-bounded on chain

fn floor(a: u128, b: u128, d: u128) -> u128 {
    a * b / d
}

// ── Item 5: L-RES ────────────────────────────────────────────────────────────────────────────

/// MUTANT: dC rounded UP.
fn claim_delta_ceil(m: u128, c: u128, s: u128) -> u128 {
    (m * c).div_ceil(s)
}
/// MUTANT: rescue priced at PAR (C) instead of the impaired value v.
fn rescue_shares_at_par(x: u128, s: u128, c: u128) -> u128 {
    floor(x, s, c)
}
/// MUTANT: one extra share (ceil mint).
fn rescue_shares_ceil(x: u128, s: u128, v: u128) -> u128 {
    (x * s).div_ceil(v)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8192))]

    /// I-RS1 (L-RES) + I-RS2 + I-RS3 on every admitted rescue: incumbents' value per share at the
    /// rescue reading never falls (value AND claim halves), par per share is not raised, and the
    /// rescuer buys at v, strictly cheaper than par whenever impaired.
    #[test]
    fn l_res_holds_for_every_admitted_rescue(
        // 2^60 atoms / shares is ~10^6 x any real token supply; above it the cross-multiplied
        // checks themselves overflow and FAIL CLOSED (see `l_res_checks_fail_closed_on_overflow`).
        c in 1_000_000u128..1u128 << 60,
        s in 1u128..1u128 << 60,
        v_frac in 500u128..10_000,
        x_mult in 1u128..1_000,
    ) {
        let v = c * v_frac / 10_000; // 5% <= v/C < 100%
        let x = (v / 100).max(p4::RESCUE_MIN_ATOMS) * x_mult / 10;
        prop_assume!(v > 0 && v < c);
        if p4::rescue_admitted(x, v, c, s).is_err() {
            return Ok(());
        }
        let m = p4::rescue_shares(x, s, v).unwrap();
        let dc = p4::rescue_claim_delta(m, c, s).unwrap();
        prop_assert!(p4::rescue_value_no_dilution(v, x, s, m), "value half");
        prop_assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc), "claim half");
        prop_assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc), "par per share");
        prop_assert!(m >= floor(x, s, c), "never above par");
        prop_assert!(v >= c * p4::RESCUE_NAV_FLOOR_BPS as u128 / 10_000, "floor");
    }

    /// Rescue, then a random later loss or recovery of the vault value: the rescuer and the
    /// incumbents share it pro rata (same value per share), and value is conserved.
    #[test]
    fn rescue_then_loss_or_recovery_conserves_and_is_pro_rata(
        v in 1_000_000u128..1u128 << 50,
        s in 1u128..1u128 << 50,
        x in 1_000_000u128..1u128 << 50,
        delta_bps in 0u128..20_000,
    ) {
        let m = p4::rescue_shares(x, s, v).unwrap();
        prop_assume!(m > 0);
        let v1 = v + x;
        let v2 = v1 * delta_bps / 10_000; // -100% .. +100%
        let s2 = s + m;
        let incumbents = floor(s, v2, s2);
        let rescuer = floor(m, v2, s2);
        prop_assert!(incumbents + rescuer <= v2, "conservation (floors never over-pay)");
        prop_assert!(v2 - incumbents - rescuer <= 2, "only rounding dust is left");
        // At the rescue moment (delta = 100%) the incumbents keep at least their pre-rescue value.
        if delta_bps == 10_000 {
            prop_assert!(incumbents >= floor(s, v, s) - 1, "incumbents diluted");
        }
    }
}

/// At absurd widths the lemma checks overflow and return false, which the processor maps to
/// RescueRefused: fail closed, never a silent accept.
#[test]
fn l_res_checks_fail_closed_on_overflow() {
    let big = u128::MAX / 2;
    assert!(!p4::rescue_claim_no_dilution(1, big, big, big, big));
    assert!(!p4::rescue_value_no_dilution(big, big, big, big));
    assert_eq!(p4::rescue_shares(u128::MAX, u128::MAX, 1), None);
}

/// NEGATIVE CONTROLS for item 5 (each mutant violates a property above on concrete inputs).
#[test]
fn mutants_item5_are_caught() {
    // dC ceil raises par per share.
    let (c, s, m) = (1_000_000_007u128, 3u128, 1u128);
    assert!(!p4::rescue_par_per_share_not_raised(c, s, m, claim_delta_ceil(m, c, s)), "ceil dC caught");
    // Mint at par: the rescuer is not priced at the impaired value (the never-par law).
    let (x, s, v, c) = (310_000_000u128, 1_000_000_000u128, 620_000_000u128, 1_000_000_000u128);
    assert_ne!(rescue_shares_at_par(x, s, c), p4::rescue_shares(x, s, v).unwrap(), "par mint caught");
    // Ceil mint dilutes the incumbents on a boundary.
    let (v, x, s) = (3u128, 1u128, 2u128);
    let m = rescue_shares_ceil(x, s, v);
    assert!(!p4::rescue_value_no_dilution(v, x, s, m), "ceil mint caught");
    // No NAV floor: a rescue at 4.99% of par would be admitted.
    assert_eq!(
        p4::rescue_admitted(200_000_000, 49_900_000, 1_000_000_000, 1),
        Err(p4::RescueRefusal::NavFloor),
        "the real rule refuses below the floor"
    );
}

// ── Item 6: insurance units ──────────────────────────────────────────────────────────────────

/// MUTANT: burn rounded DOWN (better price for the withdrawer).
fn burn_floor(a: u128, u: u128, i: u128) -> u128 {
    floor(a, u, i)
}
/// MUTANT: mint rounded UP.
fn mint_ceil(x: u128, u: u128, i: u128) -> u128 {
    (x * u).div_ceil(i)
}

#[derive(Clone, Debug)]
enum Op {
    TopUp { class: u8, x: u64 },
    Withdraw { class: u8, frac_bps: u16 },
    Loss { bps: u16 },
    Gain { x: u64 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..2, 1u64..1u64 << 40).prop_map(|(class, x)| Op::TopUp { class, x }),
        (0u8..2, 1u16..=10_000).prop_map(|(class, frac_bps)| Op::Withdraw { class, frac_bps }),
        (1u16..=10_000).prop_map(|bps| Op::Loss { bps }),
        (1u64..1u64 << 40).prop_map(|x| Op::Gain { x }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// I-S3 over random sequences of top-ups / withdrawals / losses / fee gains on two classes:
    /// * mint never dilutes, burn is at a price no better than the incumbents' (both per op);
    /// * a loss or gain moves every class's value by the same fraction (pro rata);
    /// * a class can never withdraw more than its own units' value;
    /// * the classes' values never sum above the fund.
    #[test]
    fn units_conserve_and_spread_losses_pro_rata(ops in prop::collection::vec(op(), 1..40)) {
        let (mut i, mut u, mut cls) = (0u128, 0u128, [0u128; 2]);
        for o in ops {
            match o {
                Op::TopUp { class, x } => {
                    let x = x as u128;
                    if p4::ins_units_reset_needed(u, i) {
                        u = 0;
                        cls = [0, 0];
                    }
                    let m = p4::ins_units_for_topup(x, u, i).unwrap();
                    if u > 0 {
                        prop_assert!(p4::ins_mint_no_dilution(i, u, x, m));
                    }
                    u += m;
                    cls[class as usize] += m;
                    i += x;
                }
                Op::Withdraw { class, frac_bps } => {
                    if u == 0 || i == 0 { continue; }
                    let value = p4::ins_units_value(cls[class as usize], u, i).unwrap();
                    let a = value * frac_bps as u128 / 10_000;
                    if a == 0 { continue; }
                    let b = p4::ins_units_to_burn(a, u, i).unwrap();
                    prop_assert!(b <= cls[class as usize], "a class's own value always covers its burn");
                    prop_assert!(p4::ins_burn_no_dilution(i, u, a, b));
                    let other = 1 - class as usize;
                    let other_before = p4::ins_units_value(cls[other], u, i).unwrap();
                    cls[class as usize] -= b;
                    u -= b;
                    i -= a;
                    let other_after = p4::ins_units_value(cls[other], u, i).unwrap();
                    prop_assert!(other_after + 1 >= other_before, "a withdrawal never takes the other class's value");
                }
                Op::Loss { bps } => {
                    if u == 0 || i == 0 { continue; }
                    let v0: Vec<u128> = cls.iter().map(|c| p4::ins_units_value(*c, u, i).unwrap()).collect();
                    let loss = i * bps as u128 / 10_000;
                    i -= loss;
                    let v1: Vec<u128> = cls.iter().map(|c| p4::ins_units_value(*c, u, i).unwrap()).collect();
                    // Same fraction for both classes (cross-multiplied, rounding tolerance).
                    prop_assert!((v1[0] * v0[1]).abs_diff(v1[1] * v0[0]) <= v0[0] + v0[1] + 1, "pro rata {v0:?} -> {v1:?}");
                }
                Op::Gain { x } => {
                    i += x as u128;
                }
            }
            let total: u128 = cls.iter().map(|c| p4::ins_units_value(*c, u, i).unwrap()).sum();
            prop_assert!(total <= i, "class values never exceed the fund");
            prop_assert_eq!(cls[0] + cls[1], u, "class invariant");
        }
    }

    /// G9 (I-S5): the backstop never moves more than the deficit, the withdrawable insurance, or
    /// the cumulative cap; and it is due only when the seniors hold nothing.
    #[test]
    fn backstop_bounded(
        deficit in 0u128..CAP,
        free in 0u128..CAP,
        gross_extra in 0u128..CAP,
        outstanding in 0u128..CAP,
        cap in 0u16..=10_000,
    ) {
        let gross = free + gross_extra;
        let m = p4::backstop_draw_amount(deficit, free, gross, outstanding, cap);
        prop_assert!(m <= deficit && m <= free);
        prop_assert!((outstanding + m) * 10_000 <= (gross + outstanding) * cap as u128 || m == 0);
    }
}

/// NEGATIVE CONTROLS for item 6.
#[test]
fn mutants_item6_are_caught() {
    // Burn at the BETTER price (floor) dilutes the remaining holders.
    let (i, u, a) = (3u128, 2u128, 1u128);
    assert!(!p4::ins_burn_no_dilution(i, u, a, burn_floor(a, u, i)), "floor burn caught");
    // Mint at ceil dilutes the incumbents.
    let (i, u, x) = (3u128, 2u128, 1u128);
    assert!(!p4::ins_mint_no_dilution(i, u, x, mint_ceil(x, u, i)), "ceil mint caught");
    // G9 BEFORE the seniors are exhausted (the reserved-backing case): the real rule refuses.
    assert!(!p4::backstop_due(10, 0, 0, 1), "G9 refused while senior NAV remains");
    let mutant_due = |d: u128, drawable: u128, pending: u128, _nav: u128| d != 0 && drawable == 0 && pending == 0;
    assert!(mutant_due(10, 0, 0, 1), "the mutant would have lent insurance ahead of the seniors");
}
