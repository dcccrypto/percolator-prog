//! Phase 4 rescue / insurance-unit / G9 backstop properties on the REAL pure functions of
//! `src/p4_rescue_ins.rs`. Fixed seed (deterministic RNG), 20_000 cases per property.
//!
//! 1. rescue never mints shares below NAV (L-RES: incumbents are never diluted);
//! 2. insurance units: sum of holder claims never exceeds the pot over any loss/top-up/withdraw
//!    sequence, and every rounding favours the pot;
//! 3. backstop repay ordering: insurance is repaid before juniors/seniors;
//! 4. overflow / zero-denominator inputs return None (or a safe value), never panic.
#![cfg(not(kani))]

use percolator_prog::p4_rescue_ins as p4;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

const CASES: u32 = 20_000;

fn run<S: Strategy>(strat: S, f: impl Fn(S::Value) -> Result<(), TestCaseError>) {
    let cfg = Config { cases: CASES, failure_persistence: None, ..Config::default() };
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &[0x5Au8; 32]);
    let mut runner = TestRunner::new_with_rng(cfg, rng);
    if let Err(e) = runner.run(&strat, f) {
        panic!("{e}");
    }
}

/// Wide but non-overflowing: 2^62 atoms / shares (products fit u128).
const W: u128 = 1u128 << 62;

#[test]
fn p1_rescue_never_mints_below_nav() {
    run((1..W, 1..W, 1..W, 0..W), |(x, s, v, c_extra)| {
        // Admission caps x <= RESCUE_MAX_MULT * v (rescue_admitted); stay inside it.
        let x = 1 + (x - 1) % (p4::RESCUE_MAX_MULT * v);
        let m = p4::rescue_shares(x, s, v).expect("in range");
        // L-RES value half: (v+x)*S >= v*(S+m)
        prop_assert!(p4::rescue_value_no_dilution(v, x, s, m));
        // Independent check, not via helper.
        prop_assert!((v + x) * s >= v * (s + m));
        // Rounded against the rescuer: one more share would dilute.
        prop_assert!((v + x) * s < v * (s + m + 1));
        // Claim half, bound vault: v <= C.
        let c = v + c_extra;
        let dc = p4::rescue_claim_delta(m, c, s).expect("in range");
        prop_assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
        prop_assert!((c + dc) * s >= v * (s + m));
        prop_assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
        // Cheaper than par: price at par never mints more shares than at NAV.
        let m_par = p4::rescue_shares(x, s, c).expect("in range");
        prop_assert!(m_par <= m);
        Ok(())
    });
}

#[derive(Clone, Debug)]
enum Op {
    Topup(u128, usize),
    Loss(u128),
    Withdraw(u128, usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1u128..5_000_000_000, 0usize..4).prop_map(|(x, h)| Op::Topup(x, h)),
        (0u128..2_000_000_000).prop_map(Op::Loss),
        (1u128..5_000_000_000, 0usize..4).prop_map(|(a, h)| Op::Withdraw(a, h)),
    ]
}

#[test]
fn p2_insurance_units_claims_never_exceed_pot() {
    run(prop::collection::vec(op(), 1..40), |ops| {
        let mut pot: u128 = 0;
        let mut total: u128 = 0;
        let mut held = [0u128; 4];
        for o in ops {
            // Reset / genesis as the processor hooks do.
            if p4::ins_units_reset_needed(total, pot) {
                total = 0;
                held = [0; 4];
            }
            if p4::ins_units_genesis_due(total, pot, false, 0) {
                total = pot;
                held[0] = pot;
            }
            match o {
                Op::Topup(x, h) => {
                    let minted = p4::ins_units_for_topup(x, total, pot).expect("reset handled");
                    let (i0, u0) = (pot, total);
                    pot += x;
                    total += minted;
                    held[h] += minted;
                    // Rounding favours the pot: incumbents' value per unit never falls.
                    prop_assert!(pot * u0 >= i0 * total || u0 == 0);
                    prop_assert!(p4::ins_mint_no_dilution(i0, u0, x, minted) || u0 == 0);
                }
                Op::Loss(l) => {
                    pot -= l.min(pot);
                }
                Op::Withdraw(a, h) => {
                    let a = a.min(pot);
                    if a == 0 {
                        continue;
                    }
                    let Some(b) = p4::ins_units_to_burn(a, total, pot) else { continue };
                    // Bounded by the withdrawer's own units: otherwise refused.
                    if b > held[h] {
                        continue;
                    }
                    let (i0, u0) = (pot, total);
                    pot -= a;
                    total -= b;
                    held[h] -= b;
                    prop_assert!(pot * u0 >= i0 * total);
                    prop_assert!(p4::ins_burn_no_dilution(i0, u0, a, b));
                }
            }
            // Sum of claims <= pot (values floored), and unit bookkeeping consistent.
            prop_assert_eq!(held.iter().sum::<u128>(), total);
            let claims: u128 = held
                .iter()
                .map(|u| p4::ins_units_value(*u, total, pot).expect("u<=U"))
                .sum();
            prop_assert!(claims <= pot, "claims {} > pot {}", claims, pot);
        }
        Ok(())
    });
}

#[test]
fn p3_backstop_repaid_before_juniors() {
    run((0..u128::MAX, 0..u128::MAX), |(recovery, outstanding)| {
        let (to_b, rest) = p4::backstop_recovery_split(recovery, outstanding);
        prop_assert_eq!(to_b + rest, recovery);
        prop_assert!(to_b <= outstanding);
        // Insurance first: nothing flows to others until the receivable is cleared.
        if rest > 0 {
            prop_assert_eq!(to_b, outstanding);
        }
        prop_assert_eq!(to_b, recovery.min(outstanding));
        Ok(())
    });
    // Vault value pricing seniors/juniors is net of the receivable first.
    run((0..u128::MAX, 0..u128::MAX, 0..u128::MAX, 0..u128::MAX, 0..u128::MAX), |(v, b, c, l, bc)| {
        let net = p4::vault_value_net_of_backstop(v, b);
        prop_assert!(net <= v);
        prop_assert_eq!(net, v.saturating_sub(b));
        let j = p4::waterfall_junior_level(v, b, c, l, bc);
        prop_assert!(j <= net);
        if v <= b {
            prop_assert_eq!(j, 0);
        }
        Ok(())
    });
}

#[test]
fn p4_overflow_and_zero_denominator_return_none() {
    let edge = prop_oneof![
        Just(0u128),
        Just(1u128),
        Just(u128::MAX),
        Just(u128::MAX - 1),
        Just(1u128 << 64),
        Just(1u128 << 127),
        any::<u128>(),
    ];
    run((edge.clone(), edge.clone(), edge.clone(), edge.clone()), |(a, b, c, d)| {
        // Zero denominators.
        prop_assert!(p4::mul_div_ceil(a, b, 0).is_none());
        prop_assert!(p4::rescue_shares(a, 0, c).is_none());
        prop_assert!(p4::rescue_shares(a, b, 0).is_none());
        prop_assert!(p4::rescue_claim_delta(a, b, 0).is_none());
        prop_assert!(p4::ins_units_to_burn(a, 0, c).is_none());
        prop_assert!(p4::ins_units_to_burn(a, b, 0).is_none());
        if b != 0 {
            prop_assert!(p4::ins_units_for_topup(a, b, 0).is_none());
        }
        // Overflow: result is None exactly when the u128 product overflows / quotient too big.
        let r = p4::mul_div_ceil(a, b, c);
        match (c, a.checked_mul(b)) {
            (0, _) | (_, None) => prop_assert!(r.is_none()),
            (_, Some(p)) => prop_assert_eq!(r, Some(p / c + u128::from(p % c != 0))),
        }
        // None of these may panic for any input.
        let _ = p4::rescue_shares(a, b, c);
        let _ = p4::rescue_claim_delta(a, b, c);
        let _ = p4::ins_units_for_topup(a, b, c);
        let _ = p4::ins_units_to_burn(a, b, c);
        let _ = p4::ins_units_value(a, b, c);
        let _ = p4::ins_units_genesis_due(a, b, true, c);
        let _ = p4::ins_mint_admissible(a, b, c, d);
        let _ = p4::backstop_draw_amount(a, b, c, d, 5000);
        let _ = p4::backstop_draw_amount(a, b, c, d, u16::MAX);
        let _ = p4::backstop_recovery_split(a, b);
        let _ = p4::live_exit_senior_value_net_backstop(a, b, c, d as i128, a);
        let _ = p4::rescue_admitted(a, b, c, d);
        let _ = p4::rescue_value_no_dilution(a, b, c, d);
        let _ = p4::rescue_claim_no_dilution(a, b, c, d, a);
        let _ = p4::rescue_par_per_share_not_raised(a, b, c, d);
        // Overflowing no-dilution checks fail closed (false), never true.
        if a.checked_add(b).and_then(|t| t.checked_mul(c)).is_none() {
            prop_assert!(!p4::rescue_value_no_dilution(a, b, c, 0));
        }
        Ok(())
    });
}
