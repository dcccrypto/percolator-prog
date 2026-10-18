//! NATIVE twins (not Kani) of the money-path proofs: the FACTORED no-dilution claims, checked
//! exactly in 256-bit arithmetic on the REAL production functions -- exhaustive on small boxes,
//! proptest at full u64 width (and the admitted rescue region). These are what tie the expanded
//! (Kani) form to the factored form without trusting the paper step alone, and they cover the
//! order facts the Kani harnesses leave out (pay <= value, slice <= C_b, v <= I, monotonicity,
//! the rescue claim half). Run: `cargo test --release --features devnet --test native` in kani/money.
use money_paths_proofs::bond_v20::*;
use money_paths_proofs::p4_rescue_ins::*;
use money_paths_proofs::stake_math;
use percolator::wide_math::U256;
use proptest::prelude::*;

fn w(x: u128) -> U256 {
    U256::from_u128(x)
}
/// `(p + q) * r` exactly (inputs < 2^126 keep it below 2^256).
fn sm(p: u128, q: u128, r: u128) -> U256 {
    (w(p) + w(q)) * w(r)
}
fn m2(p: u128, q: u128) -> U256 {
    w(p) * w(q)
}

fn bond_deposit(amount: u128, b: u128, v: u128) {
    let Some(m) = bond_shares_for_deposit(amount, b, v) else {
        assert!(b > 0 && (v == 0 || amount.checked_mul(b).is_none()));
        return;
    };
    if b == 0 {
        assert_eq!(m, amount);
        return;
    }
    // incumbents not diluted: (V + amount) / (B + m) >= V / B
    assert!(sm(v, amount, b) >= m2(v, b) + m2(v, m), "diluted: a={amount} B={b} V={v} m={m}");
    // new shares worth at most what was paid: m * (V + amount) / (B + m) <= amount
    assert!(sm(v, amount, m) <= sm(b, m, amount));
}

fn bond_redeem(sh: u128, b: u128, value: u128, cb: u128) {
    let pay = bond_atoms_for_redemption(sh, b, value);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if b == 0 || sh > b {
        assert!(pay.is_none() && cb2.is_none());
        return;
    }
    let pay = pay.expect("u64-bounded inputs never overflow");
    let cb2 = cb2.expect("slice <= C_b whenever sh <= B (order fact)");
    assert!(pay <= value, "pay <= value");
    // remaining value per share not lowered: (value - pay) / (B - sh) >= value / B
    assert!(m2(value - pay, b) >= m2(value, b - sh));
    // remaining claim per share not lowered
    assert!(m2(cb2, b) >= m2(cb, b - sh));
    if sh == b {
        assert!(cb2 == 0 && pay == value, "full redemption clears the tranche");
    }
}

fn ins_mint(x: u128, u: u128, i: u128) {
    let Some(m) = ins_units_for_topup(x, u, i) else {
        assert!(u > 0 && (i == 0 || x.checked_mul(u).is_none()));
        return;
    };
    if u == 0 {
        assert_eq!(m, x);
        return;
    }
    if sm(i, x, u) <= w(u128::MAX) && sm(u, m, i) <= w(u128::MAX) {
        assert!(ins_mint_no_dilution(i, u, x, m), "production predicate agrees");
    }
    assert!(sm(i, x, u) >= sm(u, m, i), "incumbents not diluted");
    assert!(sm(i, x, m) <= sm(u, m, x), "new units worth <= paid");
}

fn ins_burn(a: u128, u: u128, i: u128) {
    let Some(b) = ins_units_to_burn(a, u, i) else {
        return;
    };
    assert!(b <= u);
    assert!(m2(b, i) >= m2(a, u), "burned units worth >= paid out");
    assert!(m2(i - a, u) >= m2(i, u - b), "stayers not diluted");
}

fn ins_value(us: u128, u: u128, i: u128, i2: u128) {
    if us > u || u == 0 {
        return;
    }
    let v = ins_units_value(us, u, i).unwrap();
    assert!(v <= i, "never worth more than the fund");
    if i2 <= i {
        assert!(ins_units_value(us, u, i2).unwrap() <= v, "a loss never raises the value");
    }
}

fn stake_equal(a: u64, u: u128, i: u128) {
    let a1 = a as u128;
    assert_eq!(
        stake_math::expected_topup_units(a, u, i),
        ins_units_for_topup(a1, if i == 0 { 0 } else { u }, i)
    );
    assert_eq!(
        ins_units_to_burn(a1, u, i),
        stake_math::expected_recover_burn(a, u, i).filter(|b| *b <= u)
    );
    assert_eq!(
        stake_math::deployed_value(a1, u, i),
        ins_units_value(a1, u, i).and_then(|v| u64::try_from(v).ok())
    );
}

/// Admitted rescue: the processor's runtime L-RES / I-RS2 / claim checks never refuse it
/// (no false refusal) and the factored claims hold exactly.
fn rescue(x: u128, v: u128, par: u128, s: u128, x_eff: u128) {
    if rescue_admitted(x, v, par, s).is_err() || x_eff > x {
        return;
    }
    let Some(m) = rescue_shares(x_eff, s, v) else { return };
    if m == 0 {
        return; // the processor refuses m == 0
    }
    assert!(sm(v, x_eff, s) >= sm(s, m, v), "L-RES value not diluted");
    let Some(dc) = rescue_claim_delta(m, par, s) else { return };
    assert!(sm(par, dc, s) <= m2(par, s) + m2(par, m), "I-RS2 par per share not raised");
    assert!(sm(par, dc, s) >= sm(s, m, v), "claim half: C'/S' >= v/S (uses v < C)");
    // the processor's own checks (they return false only on u128 overflow of the products)
    if sm(v, x_eff, s) <= w(u128::MAX) && sm(s, m, par) <= w(u128::MAX) && sm(par, dc, s) <= w(u128::MAX) {
        assert!(rescue_value_no_dilution(v, x_eff, s, m));
        assert!(rescue_claim_no_dilution(v, par, s, m, dc));
        assert!(rescue_par_per_share_not_raised(par, s, m, dc));
    }
}

#[test]
fn exhaustive_bond_deposit_0_96() {
    for a in 0..=96u128 { for b in 0..=96u128 { for v in 0..=96u128 { bond_deposit(a, b, v) } } }
}
#[test]
fn exhaustive_bond_redeem_0_40() {
    for sh in 0..=40u128 { for b in 0..=40u128 { for value in 0..=40u128 { for cb in value..=40u128 {
        bond_redeem(sh, b, value, cb)
    } } } }
}
#[test]
fn exhaustive_ins_0_96() {
    for x in 0..=96u128 { for u in 0..=96u128 { for i in 0..=96u128 {
        ins_mint(x, u, i);
        ins_burn(x, u, i);
        stake_equal(x as u64, u, i);
    } } }
}
#[test]
fn exhaustive_ins_value_0_40() {
    for us in 0..=40u128 { for u in 0..=40u128 { for i in 0..=40u128 { for i2 in 0..=40u128 {
        ins_value(us, u, i, i2)
    } } } }
}
/// Every admitted rescue in a box at the admission floor: x in [1e8, 1e8 + 63], v in the
/// smallest admitted values, par just above v and up to 20 v, S in 1..=64, x_eff in a grid.
#[test]
fn exhaustive_rescue_admitted_box() {
    let mut admitted = 0u64;
    for dv in 0..16u128 {
        let v = 10_000_000 + dv * 1_000_003; // 1e7 .. ~2.5e7 (x <= 10 v admits x = 1e8 + dx)
        for par in [v + 1, v + 7, 2 * v, 20 * v - 1, 20 * v] {
            for s in 1..=64u128 {
                for dx in [0u128, 1, 13, 63] {
                    let x = 100_000_000 + dx;
                    if rescue_admitted(x, v, par, s).is_ok() {
                        admitted += 1;
                    }
                    for x_eff in [x, x - 1, x / 2, 1, 0] {
                        rescue(x, v, par, s, x_eff);
                    }
                }
            }
        }
    }
    assert!(admitted > 1_000, "the box must contain admitted rescues (got {admitted})");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50_000))]
    #[test]
    fn prop_bond_deposit_u64(a in any::<u64>(), b in any::<u64>(), v in any::<u64>()) {
        bond_deposit(a as u128, b as u128, v as u128);
    }
    #[test]
    fn prop_bond_redeem_u64(sh in any::<u64>(), b in any::<u64>(), value in any::<u64>(), extra in any::<u64>()) {
        bond_redeem(sh as u128 % (b as u128 + 1), b as u128, value as u128, (value as u128).max(extra as u128)); // C_b >= value, both SPL u64
    }
    #[test]
    fn prop_ins_u64(x in any::<u64>(), u in any::<u64>(), i in any::<u64>(), i2 in any::<u64>()) {
        ins_mint(x as u128, u as u128, i as u128);
        ins_burn(x as u128, u as u128, i as u128);
        ins_value(x as u128 % (u as u128 + 1), u as u128, i as u128, i2 as u128);
        stake_equal(x, u as u128, i as u128);
    }
    #[test]
    fn prop_rescue_admitted_region(
        v in 10_000_000u128..=(1u128 << 60),
        par_mult in 1u128..=20_000,
        s in 1u128..=(1u128 << 60),
        x_frac in 0u128..=1_000_000,
        eff_frac in 0u128..=1_000_000,
    ) {
        let par = (v + 1).max(v * par_mult / 1_000); // v < par <= 20 v
        let x = 100_000_000 + (10 * v - 100_000_000).saturating_mul(x_frac) / 1_000_000;
        let x_eff = x * eff_frac / 1_000_000;
        prop_assume!(rescue_admitted(x, v, par, s).is_ok());
        rescue(x, v, par, s, x_eff);
    }
}
