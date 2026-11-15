// Oracle price composition edge cases (multi-leg feeds, invert, unit_scale, Pyth exponents,
// confidence filter) at tiny and huge prices.
//
// Code under test (src/v16_program.rs):
//   - `oracle_v16::read_pyth_price_e6`            (~line 12529): one Pyth leg -> e6 price
//   - `oracle_v16::compose_price_e6`              (~line 12781, private): legs -> final e6 price
//   - `oracle_v16::read_external_price_e6_profile` (~line 12945, pub): reads legs, calls compose
// compose_price_e6 is private, so every case goes through the public
// read_external_price_e6_profile with real Pyth PriceUpdateV2 account bytes.
//
// The FINDINGS below were #[ignore]d real bugs (#707). The tiny-price format fix
// (docs/fixes/tiny-price-format.md) reads legs at E12, composes in U256 without the per-leg
// intermediate gate, and scales the final price by the asset's lot exponent (10^lot_exp tokens
// per quoted unit). Findings 1 and 5 are output-precision limits of a per-token e6 price, so
// they pass on a lot market; the lot-0 behaviour is pinned next to each.
#![cfg(not(kani))]

use percolator_prog::{
    constants::{
        ORACLE_LEG_FLAG_DIVIDE_LEG2, ORACLE_LEG_FLAG_DIVIDE_LEG3, ORACLE_MODE_HYBRID_AFTER_HOURS,
    },
    error::PercolatorError,
    oracle_v16,
    state::{manual_asset_oracle_profile, AssetOracleProfileV16},
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const NOW: i64 = 1_000_000;
const MAX_PRICE_E6: u64 = 1_000_000_000_000; // percolator::MAX_ORACLE_PRICE

#[derive(Clone, Copy)]
struct Leg {
    price: i64,
    expo: i32,
    conf: u64,
}

fn leg(price: i64, expo: i32) -> Leg {
    Leg {
        price,
        expo,
        conf: 0,
    }
}

/// e6 leg: `value_e6 / 1e6` in real terms.
fn e6(value_e6: i64) -> Leg {
    leg(value_e6, -6)
}

fn pyth_bytes(feed_id: &[u8; 32], l: Leg) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[0..8].copy_from_slice(&[0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd]);
    data[40] = 1;
    data[41..73].copy_from_slice(feed_id);
    data[73..81].copy_from_slice(&l.price.to_le_bytes());
    data[81..89].copy_from_slice(&l.conf.to_le_bytes());
    data[89..93].copy_from_slice(&l.expo.to_le_bytes());
    data[93..101].copy_from_slice(&NOW.to_le_bytes());
    data
}

fn profile(
    count: u8,
    flags: u8,
    invert: u8,
    unit_scale: u32,
    conf_bps: u16,
) -> AssetOracleProfileV16 {
    let mut p = *manual_asset_oracle_profile(1_000_000, 1);
    p.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    p.oracle_leg_count = count;
    p.oracle_leg_flags = flags;
    p.invert = invert;
    p.unit_scale = unit_scale;
    p.conf_filter_bps = conf_bps;
    p.max_staleness_secs = 60;
    for i in 0..count as usize {
        p.oracle_leg_feeds[i] = [0x40 + i as u8; 32];
    }
    p
}

fn run(
    legs: &[Leg],
    flags: u8,
    invert: u8,
    unit_scale: u32,
    conf_bps: u16,
) -> Result<u64, ProgramError> {
    run_lot(legs, flags, invert, unit_scale, conf_bps, 0)
}

/// `run` on an asset whose lot exponent is `lot_exp` (profile byte +19).
fn run_lot(
    legs: &[Leg],
    flags: u8,
    invert: u8,
    unit_scale: u32,
    conf_bps: u16,
    lot_exp: u8,
) -> Result<u64, ProgramError> {
    let mut p = profile(legs.len() as u8, flags, invert, unit_scale, conf_bps);
    p._padding0[percolator_prog::constants::PROFILE_LOT_EXP_IDX] = lot_exp;
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let keys: Vec<Pubkey> = legs.iter().map(|_| Pubkey::new_unique()).collect();
    let mut datas: Vec<Vec<u8>> = legs
        .iter()
        .enumerate()
        .map(|(i, l)| pyth_bytes(&p.oracle_leg_feeds[i], *l))
        .collect();
    let mut lamports: Vec<u64> = legs.iter().map(|_| 1).collect();
    let infos: Vec<AccountInfo> = keys
        .iter()
        .zip(datas.iter_mut())
        .zip(lamports.iter_mut())
        .map(|((k, d), lam)| AccountInfo::new(k, false, false, lam, d, &owner, false, 0))
        .collect();
    oracle_v16::read_external_price_e6_profile(&mut p, &infos, NOW).map(|(price, _, _)| price)
}

fn err_code(r: Result<u64, ProgramError>) -> ProgramError {
    r.expect_err("expected an error")
}

fn oracle_invalid() -> ProgramError {
    PercolatorError::OracleInvalid.into()
}

/// Real value of a leg.
fn real(l: Leg) -> f64 {
    l.price as f64 * 10f64.powi(l.expo)
}

/// Exact (floating, no per-step rounding) composite in real units.
fn exact(legs: &[Leg], flags: u8, invert: bool, unit_scale: u32) -> f64 {
    let mut v = real(legs[0]);
    for (i, l) in legs.iter().enumerate().skip(1) {
        let div = match i {
            1 => flags & ORACLE_LEG_FLAG_DIVIDE_LEG2 != 0,
            _ => flags & ORACLE_LEG_FLAG_DIVIDE_LEG3 != 0,
        };
        v = if div { v / real(*l) } else { v * real(*l) };
    }
    if invert {
        v = 1.0 / v;
    }
    if unit_scale > 1 {
        v /= unit_scale as f64;
    }
    v
}

fn rel_err(got_e6: u64, want_real: f64) -> f64 {
    let got = got_e6 as f64 / 1e6;
    ((got - want_real) / want_real).abs()
}

// ---------------------------------------------------------------- single leg / exponents

#[test]
fn single_leg_expo_minus6_passthrough() {
    assert_eq!(run(&[e6(123_456)], 0, 0, 0, 0).unwrap(), 123_456);
}

#[test]
fn single_leg_expo_minus8_truncates_to_e6() {
    // 0.00123456 USD at expo -8 -> 1234 e6 (floor of 1234.56)
    assert_eq!(run(&[leg(123_456, -8)], 0, 0, 0, 0).unwrap(), 1_234);
}

#[test]
fn single_leg_expo_minus18_large_mantissa() {
    // $0.50 at expo -18 = 5e17, still fits i64
    assert_eq!(
        run(&[leg(500_000_000_000_000_000, -18)], 0, 0, 0, 0).unwrap(),
        500_000
    );
}

#[test]
fn expo_beyond_range_rejected_not_panicking() {
    assert_eq!(err_code(run(&[leg(1, -19)], 0, 0, 0, 0)), oracle_invalid());
    assert_eq!(err_code(run(&[leg(1, 19)], 0, 0, 0, 0)), oracle_invalid());
}

#[test]
fn positive_expo_18_overflow_is_error_not_panic() {
    // i64::MAX * 10^24 overflows u128; must be a clean error.
    let r = run(&[leg(i64::MAX, 18)], 0, 0, 0, 0);
    assert!(r.is_err());
}

#[test]
fn positive_expo_small_price_ok() {
    // 5 * 10^1 = $50
    assert_eq!(run(&[leg(5, 1)], 0, 0, 0, 0).unwrap(), 50_000_000);
}

#[test]
fn single_leg_exactly_max_price_accepted_and_above_rejected() {
    assert_eq!(
        run(&[e6(MAX_PRICE_E6 as i64)], 0, 0, 0, 0).unwrap(),
        MAX_PRICE_E6
    );
    assert_eq!(
        err_code(run(&[e6(MAX_PRICE_E6 as i64 + 1)], 0, 0, 0, 0)),
        oracle_invalid()
    );
}

#[test]
fn single_leg_min_representable_price_is_one() {
    assert_eq!(run(&[leg(1_000, -9)], 0, 0, 0, 0).unwrap(), 1);
}

#[test]
fn non_positive_price_rejected() {
    assert_eq!(err_code(run(&[leg(0, -6)], 0, 0, 0, 0)), oracle_invalid());
    assert_eq!(err_code(run(&[leg(-5, -6)], 0, 0, 0, 0)), oracle_invalid());
}

// ---------------------------------------------------------------- confidence filter

#[test]
fn conf_filter_tiny_price_zero_conf_passes() {
    // price = 1 e6 ($0.000001), conf 0, 1% filter
    assert_eq!(
        run(
            &[Leg {
                price: 1,
                expo: -6,
                conf: 0
            }],
            0,
            0,
            0,
            100
        )
        .unwrap(),
        1
    );
}

#[test]
fn conf_filter_tiny_price_one_tick_conf_rejected() {
    // conf of 1 tick on a price of 3 ticks is 33%, > 5% filter
    let r = run(
        &[Leg {
            price: 3,
            expo: -6,
            conf: 1,
        }],
        0,
        0,
        0,
        500,
    );
    assert_eq!(
        err_code(r),
        ProgramError::from(PercolatorError::OracleConfTooWide)
    );
}

#[test]
fn conf_filter_boundary_is_inclusive() {
    // conf/price == exactly 1% passes, one tick more fails
    assert!(run(
        &[Leg {
            price: 10_000,
            expo: -6,
            conf: 100
        }],
        0,
        0,
        0,
        100
    )
    .is_ok());
    assert!(run(
        &[Leg {
            price: 10_000,
            expo: -6,
            conf: 101
        }],
        0,
        0,
        0,
        100
    )
    .is_err());
}

#[test]
fn conf_filter_huge_price_and_max_bps_no_overflow() {
    let r = run(
        &[Leg {
            price: i64::MAX,
            expo: -18,
            conf: u64::MAX,
        }],
        0,
        0,
        0,
        100,
    );
    // conf is ~2x the price, so it must be a clean ConfTooWide
    assert_eq!(
        err_code(r),
        ProgramError::from(PercolatorError::OracleConfTooWide)
    );
}

#[test]
fn conf_filter_applies_per_leg_in_multi_leg() {
    // leg 2 is too wide even though leg 1 is perfect and the product would be fine
    let r = run(
        &[
            e6(2_000_000),
            Leg {
                price: 150_000_000,
                expo: -6,
                conf: 50_000_000,
            },
        ],
        0,
        0,
        0,
        500,
    );
    assert_eq!(
        err_code(r),
        ProgramError::from(PercolatorError::OracleConfTooWide)
    );
}

// ---------------------------------------------------------------- memecoin via SOL leg

#[test]
fn memecoin_via_sol_leg_normal() {
    // TOKEN/SOL = 0.00002 SOL (expo -9: 20_000), SOL/USD = 150.00 -> $0.003
    let legs = [leg(20_000, -9), e6(150_000_000)];
    let got = run(&legs, 0, 0, 0, 0).unwrap();
    // 20_000e-9 = 20 e6 (exact), 20 * 150e6 / 1e6 = 3000 e6
    assert_eq!(got, 3_000);
    assert!(rel_err(got, exact(&legs, 0, false, 0)) < 0.01);
}

#[test]
fn memecoin_via_sol_leg_exact_when_legs_are_e6_aligned() {
    let legs = [e6(1_234), e6(163_210_000)];
    let got = run(&legs, 0, 0, 0, 0).unwrap();
    assert!(rel_err(got, exact(&legs, 0, false, 0)) < 0.001);
}

#[test]
fn memecoin_divide_leg_usd_over_sol() {
    // TOKEN/USD = 0.30, SOL/USD = 150 -> TOKEN/SOL = 0.002
    let legs = [e6(300_000), e6(150_000_000)];
    let got = run(&legs, ORACLE_LEG_FLAG_DIVIDE_LEG2, 0, 0, 0).unwrap();
    assert_eq!(got, 2_000);
}

#[test]
fn composed_rounds_once_not_per_leg() {
    // 3 legs, each is x.5-ish: single final truncation must beat per-leg truncation.
    // (7 * 1_500_000 / 1e6) = 10 (10.5 trunc) then * 1_500_000 / 1e6 = 15, but exact
    // composite 7*1.5*1.5 = 15.75 -> 15 (final truncation only).
    let legs = [e6(7), e6(1_500_000), e6(1_500_000)];
    assert_eq!(run(&legs, 0, 0, 0, 0).unwrap(), 15);
}

#[test]
fn three_leg_at_max_bounds_no_overflow() {
    // MAX * MAX / MAX with every leg at the cap: numerator ~1e36*1e6 fits u128
    let m = MAX_PRICE_E6 as i64;
    let legs = [e6(m), e6(m), e6(m)];
    // flags: divide leg3 -> MAX * MAX / MAX = MAX. The partial product is above MAX after leg 2;
    // the per-leg intermediate gate that refused this is gone with the tiny-price format
    // (finding 4), so the in-range final price is accepted and nothing overflows (U256).
    let r = run(&legs, ORACLE_LEG_FLAG_DIVIDE_LEG3, 0, 0, 0);
    assert_eq!(r, Ok(MAX_PRICE_E6));
    // all multiply: also out of range, must be a clean error rather than a panic
    assert!(run(&legs, 0, 0, 0, 0).is_err());
}

#[test]
fn three_leg_divide_both_with_max_denominators_no_overflow() {
    let m = MAX_PRICE_E6 as i64;
    // numerator ~1e12 * 1e6 * 1e6, denominator m*m = 1e24 -> within u128
    let legs = [e6(m), e6(m), e6(m)];
    let r = run(
        &legs,
        ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
        0,
        0,
        0,
    );
    // 1e6 / 1e6 / 1e6 = 1e-6 real = exactly one e6 tick: accepted, no overflow
    assert_eq!(r.unwrap(), 1);
}

// ---------------------------------------------------------------- invert

#[test]
fn invert_basic() {
    // 1 / 4.0 = 0.25
    assert_eq!(run(&[e6(4_000_000)], 0, 1, 0, 0).unwrap(), 250_000);
}

#[test]
fn invert_of_one_tick_hits_max_price_exactly() {
    // 1 / 0.000001 = 1_000_000 -> 1e12 e6 = MAX, accepted
    assert_eq!(run(&[e6(1)], 0, 1, 0, 0).unwrap(), MAX_PRICE_E6);
}

#[test]
fn invert_of_max_price_is_one_tick() {
    assert_eq!(run(&[e6(MAX_PRICE_E6 as i64)], 0, 1, 0, 0).unwrap(), 1);
}

#[test]
fn invert_of_composite_sol_leg() {
    // SOL per TOKEN: TOKEN/USD 0.30 over SOL/USD 150 = 0.002 TOKEN/SOL -> invert = 500 SOL
    let legs = [e6(300_000), e6(150_000_000)];
    let got = run(&legs, ORACLE_LEG_FLAG_DIVIDE_LEG2, 1, 0, 0).unwrap();
    assert_eq!(got, 500_000_000);
}

#[test]
fn invert_bad_flag_rejected_without_panic() {
    // invert > 1 never reaches compose in a valid profile, but a raw profile can carry it
    let r = run(&[e6(1_000_000)], 0, 2, 0, 0);
    assert!(r.is_err());
}

// ---------------------------------------------------------------- unit_scale

#[test]
fn unit_scale_divides_final_price() {
    // 3.0 / 1000 = 0.003
    assert_eq!(run(&[e6(3_000_000)], 0, 0, 1_000, 0).unwrap(), 3_000);
}

#[test]
fn unit_scale_zero_and_one_are_identity() {
    assert_eq!(run(&[e6(3_000_000)], 0, 0, 0, 0).unwrap(), 3_000_000);
    assert_eq!(run(&[e6(3_000_000)], 0, 0, 1, 0).unwrap(), 3_000_000);
}

#[test]
fn unit_scale_u32_max_on_max_price_is_valid() {
    // 1e12 / 4_294_967_295 = 232
    assert_eq!(
        run(&[e6(MAX_PRICE_E6 as i64)], 0, 0, u32::MAX, 0).unwrap(),
        232
    );
}

#[test]
fn unit_scale_with_invert_order_is_invert_then_scale() {
    // 1/4 = 0.25 then /10 = 0.025
    assert_eq!(run(&[e6(4_000_000)], 0, 1, 10, 0).unwrap(), 25_000);
}

#[test]
fn unit_scale_pushing_price_below_one_tick_is_rejected_cleanly() {
    // 0.5 e6-tick can't be represented; documented as OracleInvalid, not a panic
    assert_eq!(
        err_code(run(&[e6(500_000)], 0, 0, 1_000_000, 0)),
        oracle_invalid()
    );
}

// ---------------------------------------------------------------- FINDINGS (fixed)

/// FINDING 1. src/v16_program.rs:12545-12580 (`read_pyth_price_e6`, `price_u / 10^(-scale)`,
/// `out == 0` -> OracleInvalid). A real memecoin price below $0.000001 (for example $0.0000005,
/// Pyth expo -10, price 5_000) is a valid positive Pyth price, but it truncates to 0 e6 and is
/// rejected as OracleInvalid, so any market on that feed cannot take a price and freezes.
/// FIX: a per-token e6 price cannot hold it (it is half a tick), so such a market is created with
/// a lot exponent: lot 6 quotes 10^6 tokens = $0.5 = 500_000 e6, six significant digits.
#[test]
fn bug_tiny_memecoin_price_below_one_e6_tick_is_rejected() {
    // $0.0000005
    let r = run_lot(&[leg(5_000, -10)], 0, 0, 0, 0, 6);
    assert_eq!(r, Ok(500_000), "legit $0.0000005 price on a lot-6 market");
    // lot 0 still cannot represent it and refuses cleanly (not a silent 0)
    assert_eq!(err_code(run(&[leg(5_000, -10)], 0, 0, 0, 0)), oracle_invalid());
}

/// FINDING 2. src/v16_program.rs:12529 `read_pyth_price_e6` truncates every leg to whole e6 before
/// compose_price_e6 (src/v16_program.rs:12781) sees it, so the "exact rational, round once"
/// design is defeated for small legs. TOKEN/SOL = 0.0000019 SOL (expo -9, 1_900) reads as 1 e6
/// (47% low); times SOL/USD 150 gives $0.000150 instead of $0.000285.
#[test]
fn bug_small_leg_precision_loss_over_one_percent() {
    let legs = [leg(1_900, -9), e6(150_000_000)];
    let got = run(&legs, 0, 0, 0, 0).unwrap();
    let err = rel_err(got, exact(&legs, 0, false, 0));
    assert!(
        err < 0.01,
        "composite {} e6 vs exact 285 e6, error {:.1}%",
        got,
        err * 100.0
    );
}

/// FINDING 3. src/v16_program.rs:12832 (the per-leg `intermediate` gate in
/// compose_price_e6). The gate runs on the partial product after every leg, so a leg order whose
/// partial result dips under 1 e6 is rejected even though the final price is fine.
/// [1 e6, 0.5, 5000] = 1e-6 * 0.5 * 5000 = $0.0025 passes only if the legs are reordered.
#[test]
fn bug_intermediate_rounds_to_zero_but_final_is_fine() {
    let a = e6(1);
    let b = e6(500_000);
    let c = e6(5_000_000_000);
    // same product, legs reordered: accepted
    let reordered = run(&[a, c, b], 0, 0, 0, 0);
    assert_eq!(reordered.unwrap(), 2_500);
    // original order: rejected
    let r = run(&[a, b, c], 0, 0, 0, 0);
    assert_eq!(
        r.unwrap(),
        2_500,
        "same composite price rejected only because of leg order"
    );
}

/// FINDING 4. Same gate, other side: the partial product exceeds MAX_ORACLE_PRICE after leg 2
/// but leg 3 divides it back into range. $900k * $900k / $900k = $900k is a fine final price.
#[test]
fn bug_intermediate_above_max_but_final_is_fine() {
    let m = e6(900_000_000_000);
    let r = run(&[m, m, m], ORACLE_LEG_FLAG_DIVIDE_LEG3, 0, 0, 0);
    assert_eq!(r.unwrap(), 900_000_000_000);
}

/// FINDING 5. src/v16_program.rs:12838-12846 (invert): `numerator / denominator` truncates the
/// inverse to whole e6 only after the legs were already truncated; for large prices the inverse is
/// tiny and loses most of its value. 1 / $600k = 0.00000166 -> 1 e6 (40% low).
/// FIX: the inverse is $0.00000166, an output below 2 e6 ticks, so like finding 1 it needs a
/// lot market; at lot 6 it is 1_666_666 e6 per 10^6 units. Lot 0 still floors to 1 e6.
#[test]
fn bug_invert_large_price_precision_loss() {
    let legs = [e6(600_000_000_000)];
    assert_eq!(run(&legs, 0, 1, 0, 0).unwrap(), 1, "lot 0: one tick (the e6 limit)");
    let got = run_lot(&legs, 0, 1, 0, 0, 6).unwrap();
    assert_eq!(got, 1_666_666);
    let err = rel_err(got, exact(&legs, 0, true, 0) * 1e6);
    assert!(
        err < 0.01,
        "inverted {} e6 vs exact 1.6667 e6, error {:.1}%",
        got,
        err * 100.0
    );
}
