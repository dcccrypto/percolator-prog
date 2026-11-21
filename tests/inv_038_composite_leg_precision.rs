// INV-038: a composite price is rounded once, from legs that carry enough digits, and a leg
// below one e6 tick is not admissible.
//
// Ported from aeyakovenko/percolator-prog b2f3ffe7 (PR #486, issue #462),
// tests/invariants/cu/inv_038_composite_leg_precision.rs. Upstream reads every leg at six and
// at twelve decimals: the composite is computed from the twelve-decimal values, and "the
// six-decimal value is what is stored per leg and what decides whether a feed is admissible".
//
// This tightens our #711 (b370b7e1), which admitted a leg below one e6 tick (a non-zero
// twelve-decimal value whose six-decimal floor is 0) into a composite. Such a leg is now
// refused as OracleInvalid, at the reader and in the composition, at every lot exponent.
//
// The program-level (BPF) halves of these cases are in tests/v16_cu.rs:
// v16_bpf_composite_leg_below_one_e6_tick_is_rejected,
// v16_bpf_composite_target_does_not_move_on_the_rounding_of_a_low_priced_leg and
// v16_bpf_composite_from_finer_reports_costs_a_bounded_amount_more.
#![cfg(not(kani))]

use percolator_prog::{
    constants::{
        ORACLE_LEG_FLAG_DIVIDE_LEG2, ORACLE_LEG_FLAG_DIVIDE_LEG3, ORACLE_MODE_HYBRID_AFTER_HOURS,
        PROFILE_LOT_EXP_IDX,
    },
    error::PercolatorError,
    oracle_v16,
    state::manual_asset_oracle_profile,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const NOW: i64 = 1_000_000;
const MAX_E6: u64 = 1_000_000_000_000; // percolator::MAX_ORACLE_PRICE

fn pyth_bytes(feed_id: &[u8; 32], price: i64, expo: i32) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[0..8].copy_from_slice(&[0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd]);
    data[40] = 1; // fully verified
    data[41..73].copy_from_slice(feed_id);
    data[73..81].copy_from_slice(&price.to_le_bytes());
    data[81..89].copy_from_slice(&0u64.to_le_bytes());
    data[89..93].copy_from_slice(&expo.to_le_bytes());
    data[93..101].copy_from_slice(&NOW.to_le_bytes());
    data
}

/// Composite target of Pyth legs `(mantissa, expo)` through the public profile reader, which
/// reads every leg and composes them (`compose_price_e12_to_e6`).
fn compose(legs: &[(i64, i32)], flags: u8, invert: u8, lot_exp: u8) -> Result<u64, ProgramError> {
    let mut p = *manual_asset_oracle_profile(1_000_000, 1);
    p.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    p.oracle_leg_count = legs.len() as u8;
    p.oracle_leg_flags = flags;
    p.invert = invert;
    p.unit_scale = 1;
    p.max_staleness_secs = 60;
    p._padding0[PROFILE_LOT_EXP_IDX] = lot_exp;
    for i in 0..legs.len() {
        p.oracle_leg_feeds[i] = [0x60 + i as u8; 32];
    }
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let keys: Vec<Pubkey> = legs.iter().map(|_| Pubkey::new_unique()).collect();
    let mut datas: Vec<Vec<u8>> = legs
        .iter()
        .enumerate()
        .map(|(i, l)| pyth_bytes(&p.oracle_leg_feeds[i], l.0, l.1))
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

fn oracle_invalid() -> ProgramError {
    PercolatorError::OracleInvalid.into()
}

// ------------------------------------------------------------------ the tightened rule

/// A composite with a leg below one e6 tick is refused (OracleInvalid), wherever the leg sits,
/// whether it multiplies or divides, and whatever the lot exponent, even where the composite
/// itself would be a fine price. On the #711 base each of these was accepted with the price in
/// the comment.
#[test]
fn composite_leg_below_one_e6_tick_is_rejected() {
    let cases: [(&[(i64, i32)], u8, u8, &str); 6] = [
        // 0.0000005 * 2000 = 0.001: #711 gave 1_000
        (&[(500, -9), (2_000_000_000, -6)], 0, 0, "first leg 5e-7, multiplied"),
        // 0.0000019 SOL * 150 = 2.85e-7 per token, lot 9: #711 gave 285_000_000
        (&[(1_900, -12), (150_000_000, -6)], 0, 9, "first leg 1.9e-9 on a lot-9 market"),
        // 0.0000005 / 0.5 = 0.000001: #711 gave 1
        (&[(500, -9), (500_000, -6)], ORACLE_LEG_FLAG_DIVIDE_LEG2, 0, "first leg 5e-7, then divided"),
        // 1000 * 0.0000004 = 0.0004: #711 gave 400
        (&[(1_000_000_000, -6), (400, -9)], 0, 0, "second leg 4e-7, multiplied"),
        // 1 * 1000 * 0.000000999999 = 0.000999999: #711 gave 999
        (
            &[(1_000_000, -6), (1_000_000_000, -6), (999_999, -12)],
            0,
            0,
            "third leg one twelve-decimal unit below a tick",
        ),
        // 0.001 / 0.0000005 = 2000: #711 gave 2_000_000_000
        (&[(1_000, -6), (5_000, -10)], ORACLE_LEG_FLAG_DIVIDE_LEG2, 0, "second leg 5e-7, divided"),
    ];
    for (legs, flags, lot_exp, what) in cases {
        assert_eq!(compose(legs, flags, 0, lot_exp), Err(oracle_invalid()), "{what}");
        // inverted too
        assert_eq!(compose(legs, flags, 1, lot_exp), Err(oracle_invalid()), "{what}, inverted");
    }
    // A single feed below one tick is refused as well, at lot 0 and at a lot exponent.
    assert_eq!(compose(&[(5_000, -10)], 0, 0, 0), Err(oracle_invalid()));
    assert_eq!(compose(&[(5_000, -10)], 0, 0, 6), Err(oracle_invalid()));
    assert_eq!(compose(&[(5_000, -10)], 0, 1, 0), Err(oracle_invalid()));
}

/// The edge of the rule: a leg of exactly one tick is admissible and composes from all of its
/// twelve decimals; one twelve-decimal unit less is not.
#[test]
fn composite_leg_of_exactly_one_e6_tick_is_admitted() {
    // 0.000001 * 2000 = 0.002
    assert_eq!(compose(&[(1_000_000, -12), (2_000_000_000, -6)], 0, 0, 0), Ok(2_000));
    assert_eq!(compose(&[(1, -6), (2_000_000_000, -6)], 0, 0, 0), Ok(2_000));
    assert_eq!(
        compose(&[(999_999, -12), (2_000_000_000, -6)], 0, 0, 0),
        Err(oracle_invalid())
    );
    // 0.0000019 is admissible (six-decimal floor 1) and composes from 1.9, not 1:
    // 0.0000019 * 150 = 0.000285
    assert_eq!(compose(&[(1_900, -9), (150_000_000, -6)], 0, 0, 0), Ok(285));
}

// ------------------------------------------------------------------ upstream #462 tuples

/// The two feed tuples of #462. Their cross-rate is the same to seven digits:
/// 0.00041000 * 150.000000 = 0.0615000000 and 0.00041099 * 149.638677 = 0.0614999999.
/// From six-decimal legs the second was 61,351, a move of 24 bps no feed reported.
const TUPLES: [((i64, i32), (i64, i32), u64, u64); 2] = [
    ((4_100_000, -10), (150_000_000, -6), 61_500, 61_500),
    ((4_109_900, -10), (149_638_677, -6), 61_499, 61_351),
];

#[test]
fn composite_of_a_low_priced_leg_follows_the_cross_rate() {
    for (x, y, exact_floor, from_six_decimals) in TUPLES {
        assert_eq!(compose(&[x, y], 0, 0, 0), Ok(exact_floor), "{x:?} * {y:?}");
        // What the same legs floored to six decimals give.
        let six = |(m, e): (i64, i32)| (floor_scaled(m as u128, e + 6).unwrap() as i64, -6);
        assert_eq!(
            compose(&[six(x), six(y)], 0, 0, 0),
            Ok(from_six_decimals),
            "what the six-decimal legs gave"
        );
    }
    // The inverse of a low-priced single feed had the same defect: 1 / 0.00041099.
    assert_eq!(compose(&[(4_109_900, -10)], 0, 1, 0), Ok(2_433_149_225));
    assert_eq!(compose(&[(410, -6)], 0, 1, 0), Ok(2_439_024_390));
}

// ------------------------------------------------------------------ leg scaling

/// A fixed, dependency-free generator (upstream's): every run sees the same cases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// `floor(mantissa * 10^shift)`, or `None` when it does not fit `u128` (then it is far above
/// any admissible price).
fn floor_scaled(mantissa: u128, shift: i32) -> Option<u128> {
    if shift >= 0 {
        mantissa.checked_mul(10u128.checked_pow(shift as u32)?)
    } else if shift < -38 {
        Some(0)
    } else {
        Some(mantissa / 10u128.pow((-shift) as u32))
    }
}

/// A feed value at both scales, through the byte-level Pyth reader: for every exponent a feed
/// may carry (-18..=18) and mantissas across the range, the twelve-decimal value is the floor of
/// the feed value, the six-decimal value is its floor again, and a value whose six-decimal floor
/// is outside `1..=MAX_ORACLE_PRICE` (below 0.000001 or above 1,000,000) is refused at either
/// scale.
#[test]
fn oracle_leg_at_twelve_decimals_is_the_floor_of_the_feed_value() {
    let feed = [7u8; 32];
    let key = Pubkey::new_unique();
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let mut rng = Rng(0x4622);
    let (mut admitted, mut refused, mut sub_tick, mut floored) = (0u32, 0u32, 0u32, 0u32);
    for exponent in -18i32..=18 {
        for _ in 0..600 {
            let mantissa = match rng.below(4) {
                0 => 1 + rng.below(2_000) as i64,
                1 => 10i64.pow(rng.below(19) as u32) + rng.below(3) as i64 - 1,
                _ => (rng.next() >> (1 + rng.below(63))) as i64,
            }
            .max(1);
            let mut data = pyth_bytes(&feed, mantissa, exponent);
            let mut lamports = 1u64;
            let info = AccountInfo::new(&key, false, false, &mut lamports, &mut data, &owner, false, 0);
            let e12_read = oracle_v16::read_pyth_price_e12(&info, &feed, NOW, 60, 0);
            let e6_read = oracle_v16::read_oracle_price_e6(&info, &feed, NOW, 60, 0);
            let e6 = floor_scaled(mantissa as u128, exponent + 6);
            let e12 = floor_scaled(mantissa as u128, exponent + 12);
            match e6 {
                Some(e6) if e6 != 0 && e6 <= MAX_E6 as u128 => {
                    let (leg, publish_time) =
                        e12_read.unwrap_or_else(|e| panic!("{mantissa}e{exponent}: {e:?}"));
                    assert_eq!(Some(leg), e12, "{mantissa}e{exponent}");
                    assert_eq!(leg / 1_000_000, e6, "{mantissa}e{exponent}");
                    assert_eq!(publish_time, NOW);
                    assert_eq!(e6_read, Ok((e6 as u64, NOW)), "{mantissa}e{exponent}");
                    admitted += 1;
                    floored += u32::from(leg % 1_000_000 != 0);
                }
                _ => {
                    // OracleInvalid, or EngineArithmeticOverflow for a value far above the range
                    assert!(e12_read.is_err(), "{mantissa}e{exponent}: {e12_read:?}");
                    assert!(e6_read.is_err(), "{mantissa}e{exponent}: {e6_read:?}");
                    if e6 == Some(0) {
                        assert_eq!(e12_read, Err(oracle_invalid()), "{mantissa}e{exponent}");
                        assert_eq!(e6_read, Err(oracle_invalid()), "{mantissa}e{exponent}");
                    }
                    refused += 1;
                    sub_tick += u32::from(e6 == Some(0) && e12.is_some_and(|v| v != 0));
                }
            }
        }
    }
    assert!(
        admitted > 3_000 && refused > 3_000 && floored > 1_000 && sub_tick > 500,
        "admitted {admitted} refused {refused} floored {floored} sub-tick {sub_tick}"
    );
}

/// Feeds that carry digits beyond the sixth decimal compose to the same target as the same
/// values at six decimals (upstream's three-leg compute-bound composite, at the arithmetic level).
#[test]
fn three_leg_divide_both_of_admissible_legs_still_composes() {
    // 2.85 / 150 / 200 = 0.000095
    assert_eq!(
        compose(
            &[(2_850_000, -6), (150_000_000, -6), (200_000_000, -6)],
            ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            0,
            0
        ),
        Ok(95)
    );
    // the same from exponent -10 reports
    assert_eq!(
        compose(
            &[(28_500_000_000, -10), (1_500_000_000_000, -10), (2_000_000_000_000, -10)],
            ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3,
            0,
            0
        ),
        Ok(95)
    );
}
