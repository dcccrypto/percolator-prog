// Tiny-price format (docs/fixes/tiny-price-format.md): oracle legs read at E12, composed once in
// U256, and the final price scaled by the asset's lot exponent (one quoted unit = 10^lot_exp
// tokens). Round-trip, cap behaviour, e6 compatibility, lot validation, and the interaction with
// the per-slot price-move clamp that the #706 remainder carry works on.
//
// INV-038 (port of upstream aeyakovenko/percolator-prog b2f3ffe7, #462): a leg's six-decimal floor
// decides whether the feed is admissible (`1..=MAX_ORACLE_PRICE`). #711 admitted a leg below one
// e6 tick on a lot market; that is tightened, so every case here uses admissible legs and the
// sub-tick ones are pinned as refused (tests/inv_038_composite_leg_precision.rs has the rest).
#![cfg(not(kani))]

use percolator_prog::{
    constants::{
        LOT_EXP_MAX, ORACLE_LEG_FLAG_DIVIDE_LEG2, ORACLE_LEG_FLAG_DIVIDE_LEG3,
        ORACLE_MODE_AUTH_MARK, ORACLE_MODE_EWMA_MARK, ORACLE_MODE_HYBRID_AFTER_HOURS,
        ORACLE_MODE_MANUAL, PROFILE_LOT_EXP_IDX,
    },
    error::PercolatorError,
    oracle_v16,
    state::{self, manual_asset_oracle_profile, AssetOracleProfileV16},
};
use proptest::prelude::*;
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const NOW: i64 = 1_000_000;
const MAX_PRICE_E6: u64 = 1_000_000_000_000;

fn pyth_bytes(feed_id: &[u8; 32], price: i64, expo: i32) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[0..8].copy_from_slice(&[0x22, 0xf1, 0x23, 0x63, 0x9d, 0x7e, 0xf4, 0xcd]);
    data[40] = 1;
    data[41..73].copy_from_slice(feed_id);
    data[73..81].copy_from_slice(&price.to_le_bytes());
    data[81..89].copy_from_slice(&0u64.to_le_bytes());
    data[89..93].copy_from_slice(&expo.to_le_bytes());
    data[93..101].copy_from_slice(&NOW.to_le_bytes());
    data
}

fn read(legs: &[(i64, i32)], flags: u8, invert: u8, unit_scale: u32, lot_exp: u8) -> Result<u64, ProgramError> {
    let mut p = *manual_asset_oracle_profile(1_000_000, 1);
    p.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    p.oracle_leg_count = legs.len() as u8;
    p.oracle_leg_flags = flags;
    p.invert = invert;
    p.unit_scale = unit_scale;
    p.max_staleness_secs = 60;
    p._padding0[PROFILE_LOT_EXP_IDX] = lot_exp;
    for i in 0..legs.len() {
        p.oracle_leg_feeds[i] = [0x40 + i as u8; 32];
    }
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let keys: Vec<Pubkey> = legs.iter().map(|_| Pubkey::new_unique()).collect();
    let mut datas: Vec<Vec<u8>> =
        legs.iter().enumerate().map(|(i, l)| pyth_bytes(&p.oracle_leg_feeds[i], l.0, l.1)).collect();
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

// ------------------------------------------------------------------------ round trip

/// Pyth price -> e6 per lot -> real price per token, against the exact value.
#[test]
fn tiny_price_round_trip_per_token_value() {
    // (mantissa, expo, lot_exp, expected e6 per lot)
    let cases: [(i64, i32, u8, u64); 6] = [
        (5_000, -9, 5, 500_000),                 // $0.000005   -> lot 10^5 = $0.5
        (1_234_567, -12, 9, 1_234_567_000),      // $0.000001234567 -> lot 10^9 = $1_234.567
        (999_999_999, -8, 0, 9_999_999),         // $9.99999999, lot 0: one floor
        (1, -6, 0, 1),                           // one e6 tick, lot 0
        (1_000_042, -12, 6, 1_000_042),          // $0.000001000042 -> lot 10^6 = $1.000042
        (7_777, -9, 3, 7_777),                   // $0.000007777 -> lot 10^3 = $0.007777
    ];
    for (m, e, lot, want) in cases {
        let got = read(&[(m, e)], 0, 0, 0, lot).unwrap_or_else(|err| panic!("{m}e{e} lot {lot}: {err:?}"));
        assert_eq!(got, want, "{m}e{e} lot {lot}");
        // back to per-token real value
        let per_token = got as f64 / 1e6 / 10f64.powi(lot as i32);
        let exact = m as f64 * 10f64.powi(e);
        assert!(((per_token - exact) / exact).abs() < 1e-6 || lot == 0, "{m}e{e} lot {lot}");
    }
}

/// Exponents finer than 10^-12 are truncated to E12 per leg: at least 7 significant digits for an
/// admissible leg (>= 10^-6), documented in the design note.
#[test]
fn tiny_price_expo_finer_than_e12_keeps_seven_digits() {
    // $1.234567891e-6 at expo -15 -> E12 leg 1_234_567 (1.234567e-6); lot 9 -> $1_234.567
    let got = read(&[(1_234_567_891, -15)], 0, 0, 0, 9).unwrap();
    assert_eq!(got, 1_234_567_000);
    let rel = ((got as f64 / 1e15) - 1.234567891e-6).abs() / 1.234567891e-6;
    assert!(rel < 1e-6, "rel {rel}");
    // $1.23456789e-7 is below one e6 tick: refused even at lot 12 (#711 gave 123_456_000_000)
    assert_eq!(read(&[(123_456_789, -15)], 0, 0, 0, 12), Err(oracle_invalid()));
}

/// A composite of a small TOKEN/SOL leg and SOL/USD, on a lot market: the small leg enters with
/// its twelve decimals, so the composite is exact to the e6 tick.
#[test]
fn tiny_price_composite_with_lot() {
    // 0.0000019 SOL (expo -9, 1_900; six-decimal floor 1) * $150 = $0.000285 per token;
    // lot 6 -> $285
    let got = read(&[(1_900, -9), (150_000_000, -6)], 0, 0, 0, 6).unwrap();
    assert_eq!(got, 285_000_000);
    // the same divided: USD/SOL inverted leg 2 -> TOKEN/SOL / (SOL/USD)^-1 path
    let got = read(&[(1_900, -9), (6_666_667, -9)], ORACLE_LEG_FLAG_DIVIDE_LEG2, 0, 0, 6).unwrap();
    assert!((284_999_000..=285_000_000).contains(&got), "{got}");
    // a TOKEN/SOL leg below one e6 tick (0.0000000019 SOL) is refused, even though the
    // composite ($2.85e-7 per token, $285 per lot of 10^9) would be in range (#711 admitted it)
    assert_eq!(read(&[(1_900, -12), (150_000_000, -6)], 0, 0, 0, 9), Err(oracle_invalid()));
}

// ------------------------------------------------------------------------ caps

#[test]
fn tiny_price_lot_cap_at_max_oracle_price() {
    // $1 at lot 6 = 10^12 e6 = MAX_ORACLE_PRICE exactly: accepted
    assert_eq!(read(&[(1_000_000, -6)], 0, 0, 0, 6), Ok(MAX_PRICE_E6));
    // one tick more is refused, not wrapped or saturated
    assert_eq!(read(&[(1_000_001, -6)], 0, 0, 0, 6), Err(oracle_invalid()));
    // lot 7 on $1 is 10^13 e6: refused
    assert_eq!(read(&[(1_000_000, -6)], 0, 0, 0, 7), Err(oracle_invalid()));
    // the smallest admissible leg (one tick, 10^-6) at lot 12 is $1M = MAX exactly
    assert_eq!(read(&[(1, -6)], 0, 0, 0, 12), Ok(MAX_PRICE_E6));
    // and at the largest lot exponent it is out of range
    assert_eq!(read(&[(1, -6)], 0, 0, 0, LOT_EXP_MAX), Err(oracle_invalid()));
    // above LOT_EXP_MAX is a configuration error
    assert_eq!(
        read(&[(1, -6)], 0, 0, 0, LOT_EXP_MAX + 1),
        Err(PercolatorError::EngineInvalidConfig.into())
    );
}

#[test]
fn tiny_price_leg_below_e12_or_above_max_is_refused() {
    // 10^-13 truncates to 0 at E12: refused even with a lot exponent
    assert_eq!(read(&[(1, -13)], 0, 0, 0, 15), Err(oracle_invalid()));
    // non-zero at E12 but below one e6 tick: refused at every lot (INV-038; #711 admitted these)
    for (m, e) in [(1i64, -12), (999_999, -12), (5_000, -10), (9, -7)] {
        for lot in [0u8, 6, LOT_EXP_MAX] {
            assert_eq!(read(&[(m, e)], 0, 0, 0, lot), Err(oracle_invalid()), "{m}e{e} lot {lot}");
        }
    }
    // a leg above $1M is refused regardless of lot (legs are range-checked per token)
    assert_eq!(read(&[(1_000_001, 0)], 0, 0, 0, 0), Err(oracle_invalid()));
}

#[test]
fn tiny_price_three_leg_extremes_do_not_overflow_u256() {
    let max = (1_000_000_000_000i64, -6); // $1M
    let min = (1i64, -6); // $1e-6, the smallest admissible leg
    // max * max / min overflows the price range (refused), never the arithmetic (no panic)
    assert_eq!(read(&[max, max, min], ORACLE_LEG_FLAG_DIVIDE_LEG3, 0, 0, 0), Err(oracle_invalid()));
    // min / max / max, inverted, lot 15: refused as out of range, not an overflow panic
    let r = read(&[min, max, max], ORACLE_LEG_FLAG_DIVIDE_LEG2 | ORACLE_LEG_FLAG_DIVIDE_LEG3, 1, u32::MAX, 15);
    assert!(r.is_err());
    // max * max * max inverted, lot 15, unit_scale max: tiny, refused cleanly
    assert!(read(&[max, max, max], 0, 1, u32::MAX, 15).is_err());
}

// ------------------------------------------------------------------------ e6 compatibility

/// The pre-fix composition (e6 legs, exact u128 rational, per-leg gate, floor once, then
/// unit_scale), for comparison on e6-aligned inputs.
fn old_compose(legs_e6: &[u64], flags: u8, invert: u8, unit_scale: u32) -> Option<u64> {
    let mut n = legs_e6[0] as u128;
    let mut d = 1u128;
    for (i, p) in legs_e6.iter().enumerate().skip(1) {
        let div = if i == 1 { flags & ORACLE_LEG_FLAG_DIVIDE_LEG2 != 0 } else { flags & ORACLE_LEG_FLAG_DIVIDE_LEG3 != 0 };
        if div {
            n = n.checked_mul(1_000_000)?;
            d = d.checked_mul(*p as u128)?;
        } else {
            n = n.checked_mul(*p as u128)?;
            d = d.checked_mul(1_000_000)?;
        }
        let inter = n / d;
        if inter == 0 || inter > MAX_PRICE_E6 as u128 {
            return None;
        }
    }
    if invert != 0 {
        let nn = d.checked_mul(1_000_000_000_000)?;
        d = n;
        n = nn;
    }
    let mut price = n / d;
    if unit_scale > 1 {
        price /= unit_scale as u128;
    }
    if price == 0 || price > MAX_PRICE_E6 as u128 {
        return None;
    }
    Some(price as u64)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_048, .. ProptestConfig::default() })]
    /// Lot 0, e6-aligned legs: wherever the old composition produced a price, the new one
    /// produces the same price (the format change is invisible to existing markets).
    #[test]
    fn tiny_price_lot0_e6_legs_match_the_old_composition(
        a in 1u64..=MAX_PRICE_E6, b in 1u64..=MAX_PRICE_E6, c in 1u64..=MAX_PRICE_E6,
        n in 1usize..=3, flags in 0u8..4, invert in 0u8..2, unit_scale in prop_oneof![Just(0u32), Just(1u32), 2u32..1_000_000],
    ) {
        let legs = [a, b, c];
        let legs = &legs[..n];
        let flags = match n { 1 => 0, 2 => flags & ORACLE_LEG_FLAG_DIVIDE_LEG2, _ => flags };
        if let Some(old) = old_compose(legs, flags, invert, unit_scale) {
            let pyth: Vec<(i64, i32)> = legs.iter().map(|p| (*p as i64, -6)).collect();
            prop_assert_eq!(read(&pyth, flags, invert, unit_scale, 0), Ok(old));
        }
    }

    /// Scaling: lot k multiplies an e6-aligned single leg by exactly 10^k, or refuses above MAX.
    #[test]
    fn tiny_price_lot_scales_exactly(p in 1u64..=MAX_PRICE_E6, lot in 0u8..=LOT_EXP_MAX) {
        let scaled = (p as u128) * 10u128.pow(lot as u32);
        let r = read(&[(p as i64, -6)], 0, 0, 0, lot);
        if scaled <= MAX_PRICE_E6 as u128 {
            prop_assert_eq!(r, Ok(scaled as u64));
        } else {
            prop_assert_eq!(r, Err(oracle_invalid()));
        }
    }
}

// ------------------------------------------------------------------------ lot validation

#[test]
fn tiny_price_hybrid_may_carry_a_lot_ewma_may_not() {
    let mut p: AssetOracleProfileV16 = bytemuck::Zeroable::zeroed();
    p._padding0[PROFILE_LOT_EXP_IDX] = 6;
    for (mode, ok) in [
        (ORACLE_MODE_MANUAL, true),
        (ORACLE_MODE_HYBRID_AFTER_HOURS, true),
        (ORACLE_MODE_EWMA_MARK, false),
        (ORACLE_MODE_AUTH_MARK, true),
    ] {
        p.oracle_mode = mode;
        assert_eq!(state::profile_lot_and_p4_bytes_ok(&p), ok, "mode {mode}");
        // reconfiguring a lot-6 profile into `mode`
        p.oracle_mode = ORACLE_MODE_AUTH_MARK;
        assert_eq!(state::carried_profile_padding0(&p, mode).is_ok(), ok, "to mode {mode}");
    }
    // the lot is carried, never cleared
    assert_eq!(
        state::carried_profile_padding0(&p, ORACLE_MODE_HYBRID_AFTER_HOURS).unwrap()[PROFILE_LOT_EXP_IDX],
        6
    );
}

// ------------------------------------------------------------------------ #706 interaction

/// The per-slot move clamp `floor(P * cap_bps * dt / 10^4)` freezes a price below 10^4 e6 at a
/// 1 bps cap (the tiny-price freeze #706 fixes with a remainder carry). A small token priced
/// per lot sits far above that: at lot 5 a $0.000005 token is 500_000 e6 and moves 50 e6 per
/// slot at 1 bps, so the carry is never needed for it. A token below one e6 tick cannot be read
/// at any lot (INV-038; see oracle_compose_edge finding 1).
#[test]
fn tiny_price_lot_market_never_needs_the_remainder_carry() {
    let p_lot0 = 1u64; // the closest a lot-0 market gets: one tick
    assert_eq!(oracle_v16::clamp_toward_engine_dt(p_lot0, 2, 1, 1), p_lot0, "frozen at 1 bps");
    let p_lot5 = read(&[(5_000, -9)], 0, 0, 0, 5).unwrap();
    assert_eq!(p_lot5, 500_000);
    let next = oracle_v16::clamp_toward_engine_dt(p_lot5, 2 * p_lot5, 1, 1);
    assert_eq!(next, p_lot5 + 50, "moves every slot at 1 bps");
    // and for every lot price at or above 10^4 e6 a 1 bps cap moves at least one tick per slot
    for p in [10_000u64, 10_001, 99_999, 500_000, MAX_PRICE_E6 - 1] {
        assert!(oracle_v16::clamp_toward_engine_dt(p, p + 1_000_000, 1, 1) > p, "p {p}");
    }
}
