//! INV-038: a composite price is rounded once, from legs that carry enough digits.
//!
//! Ported (tests only) from upstream percolator-prog `b2f3ffe7` (upstream PR 486,
//! issue 462, "compose composite oracle prices from twelve-decimal legs"),
//! `tests/invariants/cu/inv_038_composite_leg_precision.rs`.
//!
//! A composite is a product or a quotient of feed values, so the relative error of a
//! rounded leg carries into it whole. A leg worth 0.00041 is 410 at six decimals,
//! known to one part in 410 (24 bps). Two feed tuples with the same cross-rate to
//! seven digits used to store targets 24 bps apart: 61,500 and 61,351.
//!
//! Our code already composes at twelve decimals and floors once (#711, `b370b7e1`,
//! `oracle_v16::compose_price_e12_to_e6`, tiny-price format,
//! docs/fixes/tiny-price-format.md), so only the tests are ported. They run against
//! our readers and our composition unchanged and expect upstream's values.
//!
//! Adapted, not copied:
//! - Upstream's byte-level `read_oracle_leg_price_from_bytes`, `compose_price_e6`,
//!   `floor_ratio_of_u64_products` and `floor_scaled_ratio_of_u64_products` do not
//!   exist here (our composition is one U256 ratio). The leg reader is exercised
//!   through the public `read_pyth_price_e12` / `read_pyth_price_e6`, the arithmetic
//!   tuples through the public `read_external_price_e6_profile`. The two limb-routine
//!   bigint fuzzers have no counterpart to run against and are not ported.
//! - Reference values are computed in `u128` (`checked_mul`; an overflow is a value
//!   far above `MAX_ORACLE_PRICE`), so no `num-bigint` dev-dependency is added.
//!
//! Deliberate divergence (pinned below, see
//! `v16_program_composite_admits_a_leg_below_one_e6_tick_divergence_from_upstream`):
//! upstream refuses any leg whose six-decimal floor is 0. Ours (tiny-price format)
//! admits such a leg at twelve decimals inside a composite and stores its per-leg e6
//! record as 0; only the final price must be in `1..=MAX_ORACLE_PRICE`. The e6 reader
//! (`read_pyth_price_e6`) still refuses it, exactly as upstream does.

use super::*;
use percolator_prog::constants::ORACLE_MODE_HYBRID_AFTER_HOURS;
use solana_program::{account_info::AccountInfo, program_error::ProgramError};

const MAX_E6: u64 = percolator::MAX_ORACLE_PRICE;
const E12_PER_E6: u128 = 1_000_000;
const DIVIDE_LEG2: u8 = ORACLE_LEG_FLAG_DIVIDE_LEG2;
const DIVIDE_LEG3: u8 = ORACLE_LEG_FLAG_DIVIDE_LEG3;

/// Upstream's fixed, dependency-free generator: every run sees the same cases.
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

/// floor(mantissa * 10^shift) in u128; `None` when it does not fit (far above any
/// admissible price at either scale).
fn floor_scaled(mantissa: u64, shift: i32) -> Option<u128> {
    let power = 10u128.checked_pow(shift.unsigned_abs())?;
    if shift >= 0 {
        (mantissa as u128).checked_mul(power)
    } else {
        Some(mantissa as u128 / power)
    }
}

/// One Pyth PriceUpdateV2 leg, read through the program's public readers at E12 and e6.
fn read_pyth_leg(
    feed: &[u8; 32],
    mantissa: i64,
    exponent: i32,
    now: i64,
) -> (
    Result<(u128, i64), ProgramError>,
    Result<(u64, i64), ProgramError>,
) {
    let key = Pubkey::new_unique();
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let mut data = make_pyth_data(feed, mantissa, exponent, 0, now);
    let mut lamports = 1u64;
    let info = AccountInfo::new(
        &key,
        false,
        false,
        &mut lamports,
        &mut data,
        &owner,
        false,
        0,
    );
    (
        oracle_v16::read_pyth_price_e12(&info, feed, now, 60, 10_000),
        oracle_v16::read_pyth_price_e6(&info, feed, now, 60, 10_000),
    )
}

/// A feed value at both scales, through the program's Pyth reader: for every exponent
/// a feed may carry (-18..=18) and mantissas across the range, the twelve-decimal value
/// is the floor of the feed value and the six-decimal value is its floor again.
///
/// Upstream refuses a value outside `0.000001..=1,000,000` at either scale. Ours
/// refuses at E12 only a value that floors to 0 at twelve decimals or is above
/// `MAX_ORACLE_PRICE` at six; a value in `0.000000000001..0.000001` is admitted at E12
/// (the tiny-price divergence, counted as `sub_tick`) and refused by the e6 reader, as
/// upstream refuses it.
#[test]
fn v16_program_oracle_leg_at_twelve_decimals_is_the_floor_of_the_feed_value() {
    const NOW: i64 = 1_000;
    let feed = [7u8; 32];
    let mut rng = Rng(0x4622);
    let (mut admitted, mut refused, mut floored, mut sub_tick) = (0u32, 0u32, 0u32, 0u32);
    for exponent in -18i32..=18 {
        for _ in 0..600 {
            let mantissa = match rng.below(4) {
                0 => 1 + rng.below(2_000) as i64,
                1 => 10i64.pow(rng.below(19) as u32) + rng.below(3) as i64 - 1,
                _ => (rng.next() >> (1 + rng.below(63))) as i64,
            }
            .max(1);
            let (read_e12, read_e6) = read_pyth_leg(&feed, mantissa, exponent, NOW);
            let e12 = floor_scaled(mantissa as u64, exponent + 12);
            let e6 = floor_scaled(mantissa as u64, exponent + 6);
            let above_max = match e6 {
                Some(v) => v > MAX_E6 as u128,
                None => true,
            };
            let e6_zero = e6 == Some(0);
            if above_max || e12 == Some(0) {
                assert!(read_e12.is_err(), "{mantissa}e{exponent}: {read_e12:?}");
                assert!(read_e6.is_err(), "{mantissa}e{exponent}: {read_e6:?}");
                refused += 1;
                continue;
            }
            let (got_e12, publish_time) =
                read_e12.unwrap_or_else(|e| panic!("{mantissa}e{exponent}: {e:?}"));
            assert_eq!(Some(got_e12), e12, "{mantissa}e{exponent}");
            assert_eq!(publish_time, NOW);
            if e6_zero {
                // Below one e6 tick: admitted at E12 (ours), refused at e6 (as upstream).
                assert_eq!(
                    read_e6,
                    Err(PercolatorError::OracleInvalid.into()),
                    "{mantissa}e{exponent}"
                );
                sub_tick += 1;
                continue;
            }
            let (got_e6, _) = read_e6.unwrap_or_else(|e| panic!("{mantissa}e{exponent}: {e:?}"));
            assert_eq!(Some(got_e6 as u128), e6, "{mantissa}e{exponent}");
            assert_eq!(got_e12 / E12_PER_E6, got_e6 as u128);
            admitted += 1;
            floored += u32::from(got_e12 % E12_PER_E6 != 0);
        }
    }
    println!(
        "leg reader: {admitted} admitted, {refused} refused, {floored} with digits past e6, \
         {sub_tick} below one e6 tick (admitted at E12 only)"
    );
    assert!(admitted > 3_000 && refused > 3_000 && floored > 1_000 && sub_tick > 100);
}

/// A Hybrid oracle profile with `legs.len()` Pyth legs, read by the program's public
/// `read_external_price_e6_profile` (which composes through `compose_price_e12_to_e6`).
fn compose_through_profile(
    legs: &[(i64, i32)],
    flags: u8,
    invert: u8,
    unit_scale: u32,
) -> Result<u64, ProgramError> {
    const NOW: i64 = 1_000_000;
    let mut profile = *state::manual_asset_oracle_profile(1_000_000, 1);
    profile.oracle_mode = ORACLE_MODE_HYBRID_AFTER_HOURS;
    profile.oracle_leg_count = legs.len() as u8;
    profile.oracle_leg_flags = flags;
    profile.invert = invert;
    profile.unit_scale = unit_scale;
    profile.conf_filter_bps = 0;
    profile.max_staleness_secs = 60;
    for i in 0..legs.len() {
        profile.oracle_leg_feeds[i] = [0x40 + i as u8; 32];
    }
    let owner = oracle_v16::PYTH_RECEIVER_PROGRAM_ID;
    let keys: Vec<Pubkey> = legs.iter().map(|_| Pubkey::new_unique()).collect();
    let mut datas: Vec<Vec<u8>> = legs
        .iter()
        .enumerate()
        .map(|(i, (mantissa, expo))| {
            make_pyth_data(&profile.oracle_leg_feeds[i], *mantissa, *expo, 0, NOW)
        })
        .collect();
    let mut lamports: Vec<u64> = legs.iter().map(|_| 1).collect();
    let infos: Vec<AccountInfo> = keys
        .iter()
        .zip(datas.iter_mut())
        .zip(lamports.iter_mut())
        .map(|((k, d), lam)| AccountInfo::new(k, false, false, lam, d, &owner, false, 0))
        .collect();
    oracle_v16::read_external_price_e6_profile(&mut profile, &infos, NOW).map(|(price, _, _)| price)
}

/// Upstream's two feed tuples. Their cross-rate is the same to seven digits:
/// 0.00041000 * 150.000000 = 0.0615000000 and 0.00041099 * 149.638677 =
/// 0.0614999999. From six-decimal legs the second was stored as 61,351.
/// (leg x, leg jpy, exact floor, what six-decimal legs gave)
const TUPLES: [((i64, i32), (i64, i32), u64, u64); 2] = [
    ((4_100_000, -10), (150_000_000, -6), 61_500, 61_500),
    ((4_109_900, -10), (149_638_677, -6), 61_499, 61_351),
];

/// The tuples at the arithmetic level (upstream's
/// `v16_program_composite_of_a_low_priced_leg_follows_the_cross_rate`): our
/// composition gives upstream's exact floor, and the same code fed the legs already
/// floored to six decimals gives what the old composition gave.
#[test]
fn v16_program_composite_of_a_low_priced_leg_follows_the_cross_rate() {
    for ((x, x_expo), (jpy, jpy_expo), exact_floor, from_six_decimals) in TUPLES {
        assert_eq!(
            compose_through_profile(&[(x, x_expo), (jpy, jpy_expo)], 0, 0, 1),
            Ok(exact_floor),
            "{x}e{x_expo} * {jpy}e{jpy_expo}"
        );
        let to_e6 =
            |mantissa: i64, expo: i32| floor_scaled(mantissa as u64, expo + 6).unwrap() as i64;
        assert_eq!(
            compose_through_profile(
                &[(to_e6(x, x_expo), -6), (to_e6(jpy, jpy_expo), -6)],
                0,
                0,
                1
            ),
            Ok(from_six_decimals),
            "what the six-decimal legs gave"
        );
    }
    // The inverse of a low-priced single feed had the same defect: 1 / 0.00041099.
    assert_eq!(
        compose_through_profile(&[(41_099, -8)], 0, 1, 1),
        Ok(2_433_149_225)
    );
    assert_eq!(
        compose_through_profile(&[(410, -6)], 0, 1, 1),
        Ok(2_439_024_390)
    );
}

fn crank_with_reports(
    env: &mut V16CuEnv,
    portfolio: Pubkey,
    slot: u64,
    oracle_accounts: &[Pubkey],
) -> Result<u64, String> {
    let mut accounts = vec![
        AccountMeta::new(env.payer.pubkey(), true),
        AccountMeta::new(env.market, false),
        AccountMeta::new(portfolio, false),
    ];
    accounts.extend(
        oracle_accounts
            .iter()
            .copied()
            .map(|key| AccountMeta::new_readonly(key, false)),
    );
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::PermissionlessCrank {
            now_slot: slot,
            observations: vec![CrankObservationHint {
                asset_index: 0,
                oracle_accounts: oracle_accounts.len() as u8,
            }],
        },
        accounts,
        &[],
    )
}

/// The same two tuples through the program: two fully verified Pyth reports per tuple,
/// a two-leg product configured by `ConfigureHybridOracle` and observed by a
/// permissionless crank. The stored target follows the cross-rate, 61,500 and then
/// 61,499, where it used to fall to 61,351.
#[test]
fn v16_program_composite_target_does_not_move_on_the_rounding_of_a_low_priced_leg() {
    let mut env = V16CuEnv::new();
    let keeper = Keypair::new();
    let keeper_portfolio = env.create_portfolio(&keeper);
    let feed_x = [0x46; 32];
    let feed_jpy = [0x62; 32];

    let (slot, time) = (10u64, 1_000i64);
    set_test_clock(&mut env, slot, time);
    let ((x, x_expo), (jpy, jpy_expo), first, _) = TUPLES[0];
    let reports = [
        env.set_pyth_price(&feed_x, x, x_expo, time),
        env.set_pyth_price(&feed_jpy, jpy, jpy_expo, time),
    ];
    let configure_cu = env
        .try_configure_hybrid_asset_with_conf_filter_cu(
            0,
            2,
            0,
            [feed_x, feed_jpy, [0u8; 32]],
            &reports,
            slot,
            time,
            0,
            1,
            3,
            100,
        )
        .expect("a two-leg product of a low-priced feed and a currency feed");
    let config = env.market_state().0;
    assert_eq!(config.oracle_target_price_e6, first);
    // What is stored per leg is still the six-decimal value.
    assert_eq!(config.oracle_leg_prices_e6[..2], [410, 150_000_000]);

    let (slot, time) = (slot + 1, time + 1);
    set_test_clock(&mut env, slot, time);
    let ((x, x_expo), (jpy, jpy_expo), second, from_six_decimals) = TUPLES[1];
    let reports = [
        env.set_pyth_price(&feed_x, x, x_expo, time),
        env.set_pyth_price(&feed_jpy, jpy, jpy_expo, time),
    ];
    let crank_cu = crank_with_reports(&mut env, keeper_portfolio, slot, &reports)
        .expect("the second tuple is observed");
    let config = env.market_state().0;
    assert_eq!(config.oracle_target_publish_time, time);
    assert_eq!(config.oracle_leg_prices_e6[..2], [410, 149_638_677]);
    assert_eq!(
        config.oracle_target_price_e6, second,
        "the cross-rate moved by less than one unit of the sixth decimal"
    );
    assert_ne!(config.oracle_target_price_e6, from_six_decimals);
    println!(
        "two-leg composite: ConfigureHybridOracle {configure_cu} CU, PermissionlessCrank {crank_cu} CU"
    );
}

/// What the extra digits cost (upstream's
/// `v16_program_composite_from_finer_reports_costs_a_bounded_amount_more`). The same
/// three-leg composite is observed by a crank from exponent -6 reports and from
/// exponent -10 reports of the same values: the stored target is the same, and the
/// finer reports cost at most 1,000 CU more for the whole composite.
///
/// Adapted bound: upstream also asserts `fine_cu >= coarse_cu`. Our Pyth reader
/// scales by one `checked_mul(10^(exponent + 12))` for every exponent >= -12, so the
/// finer report may cost the same or a few CU less (a smaller power of ten); the
/// bound here is `|fine - coarse| <= 1,000`.
#[test]
fn v16_program_composite_from_finer_reports_costs_a_bounded_amount_more() {
    const VALUES_E6: [i64; 3] = [3_000_000, 150_000_000, 200_000_000];
    let observe = |exponent: i32| {
        let scale = 10i64.pow((-6 - exponent) as u32);
        let mut env = V16CuEnv::new();
        let keeper = Keypair::new();
        let keeper_portfolio = env.create_portfolio(&keeper);
        let feeds = [[0x31u8; 32], [0x32u8; 32], [0x33u8; 32]];
        let (slot, time) = (10u64, 1_000i64);
        set_test_clock(&mut env, slot, time);
        let reports: Vec<Pubkey> = (0..3)
            .map(|leg| env.set_pyth_price(&feeds[leg], VALUES_E6[leg] * scale, exponent, time))
            .collect();
        env.try_configure_hybrid_asset_with_conf_filter_cu(
            0,
            3,
            DIVIDE_LEG2 | DIVIDE_LEG3,
            feeds,
            &reports,
            slot,
            time,
            0,
            1,
            3,
            100,
        )
        .expect("a three-leg composite");
        let (slot, time) = (slot + 1, time + 1);
        set_test_clock(&mut env, slot, time);
        // 2.850000 / 150 / 200 = 0.000095
        let reports: Vec<Pubkey> = (0..3)
            .map(|leg| {
                let value = if leg == 0 { 2_850_000 } else { VALUES_E6[leg] };
                env.set_pyth_price(&feeds[leg], value * scale, exponent, time)
            })
            .collect();
        let cu = crank_with_reports(&mut env, keeper_portfolio, slot, &reports)
            .expect("the composite is observed");
        (env.market_state().0.oracle_target_price_e6, cu)
    };
    let (coarse_target, coarse_cu) = observe(-6);
    let (fine_target, fine_cu) = observe(-10);
    assert_eq!(coarse_target, 95);
    assert_eq!(fine_target, coarse_target);
    println!("three-leg composite crank: {coarse_cu} CU from exponent -6, {fine_cu} from -10");
    assert!(
        fine_cu.abs_diff(coarse_cu) <= 1_000,
        "finer reports cost {fine_cu} against {coarse_cu}"
    );
}

/// DELIBERATE DIVERGENCE from upstream `b2f3ffe7`, pinned. Upstream refuses a leg whose
/// six-decimal floor is 0 (`OracleInvalid`), so it cannot price a composite with a leg
/// below 0.000001. Ours (tiny-price format, #711) reads the leg at twelve decimals,
/// admits it, composes the exact ratio and range-checks only the final price; the
/// per-leg e6 record stores the leg's floor, 0.
///
/// 0.0000005 * 2,000 = 0.001 -> 1,000 at e6. The same leg alone floors to 0 at e6 and
/// is still refused (the final price must be at least one e6 tick).
#[test]
fn v16_program_composite_admits_a_leg_below_one_e6_tick_divergence_from_upstream() {
    // Arithmetic level: what upstream refuses, ours prices.
    assert_eq!(
        compose_through_profile(&[(5, -7), (2_000_000_000, -6)], 0, 0, 1),
        Ok(1_000)
    );
    // 0.0000005 / 0.000002 = 0.25
    assert_eq!(
        compose_through_profile(&[(5, -7), (2, -6)], DIVIDE_LEG2, 0, 1),
        Ok(250_000)
    );
    assert_eq!(
        compose_through_profile(&[(5, -7)], 0, 0, 1),
        Err(PercolatorError::OracleInvalid.into()),
        "a lone sub-tick leg is a sub-tick price"
    );
    // The e6 reader refuses the leg exactly as upstream's six-decimal gate does.
    let (read_e12, read_e6) = read_pyth_leg(&[9u8; 32], 5, -7, 1_000);
    assert_eq!(read_e12, Ok((500_000, 1_000)));
    assert_eq!(read_e6, Err(PercolatorError::OracleInvalid.into()));

    // Program level: ConfigureHybridOracle admits the composite and stores leg e6 = 0.
    let mut env = V16CuEnv::new();
    let feed_tiny = [0x71; 32];
    let feed_big = [0x72; 32];
    let (slot, time) = (10u64, 1_000i64);
    set_test_clock(&mut env, slot, time);
    let reports = [
        // conf 0: a conf of 1 on a mantissa of 5 is 20% wide and the filter would refuse it.
        env.set_pyth_price_with_conf(&feed_tiny, 5, -7, 0, time),
        env.set_pyth_price(&feed_big, 2_000_000_000, -6, time),
    ];
    env.try_configure_hybrid_asset_with_conf_filter_cu(
        0,
        2,
        0,
        [feed_tiny, feed_big, [0u8; 32]],
        &reports,
        slot,
        time,
        0,
        1,
        3,
        100,
    )
    .expect("ours admits a sub-tick leg inside a composite (upstream refuses it)");
    let config = env.market_state().0;
    assert_eq!(config.oracle_target_price_e6, 1_000);
    assert_eq!(config.oracle_leg_prices_e6[..2], [0, 2_000_000_000]);
}
