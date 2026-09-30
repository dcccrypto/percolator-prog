//! Skew funding conservation through the real engine kernel. Covers must be SATISFIED.
use crate::vault_lp_v18::*;
use percolator::wide_math::floor_div_signed_conservative_i128;
#[allow(unused_imports)]
use percolator::{ADL_ONE, FUNDING_DEN, MIN_A_SIDE, POS_SCALE};

/// SKEW FUNDING IS ZERO-SUM (conservative). The wrapper's combined rate (premium + skew,
/// clamped) is turned into a funding index delta by the engine formula (v16.rs:14777-14782,
/// the engine's own `floor_div_signed_conservative_i128`), then into per-side F deltas by the
/// REAL engine kernel `kani_adl_scaled_accrual_index_deltas`, for ANY per-side A in
/// [MIN_A_SIDE, ADL_ONE] (asymmetric after ADL). Two matched legs of equal effective size,
/// each settled as `floor(q * dF / (a_side * POS_SCALE))` (the engine's realize rule, with
/// a_basis = the live side A), sum to a value in [-1, 0]: funding never mints, and destroys at
/// most one atom of rounding dust. Also: the crowded side pays.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3e_skew_funding_conserves_through_engine_kernel() {
    let premium: i16 = kani::any();
    let lp_net: i32 = kani::any();
    let oi: u32 = kani::any();
    let slope: u16 = kani::any();
    let cap: u16 = kani::any();
    let max_abs: u16 = kani::any();
    let dt: u8 = kani::any();
    let price: u32 = kani::any();
    let q: u16 = kani::any();
    let a_long: u128 = kani::any();
    let a_short: u128 = kani::any();
    kani::assume(a_long >= MIN_A_SIDE && a_long <= ADL_ONE);
    kani::assume(a_short >= MIN_A_SIDE && a_short <= ADL_ONE);
    kani::assume(price > 0);

    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    assert!(rate.unsigned_abs() <= max_abs as u128);
    let n = rate * dt as i128 * price as i128;
    let fid = floor_div_signed_conservative_i128(n, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);

    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    assert!(net <= 0 && net >= -1);
    // the crowded side pays: vault LP short (traders long) and no premium => longs pay
    if premium == 0 && lp_net < 0 && fid > 0 && q > 0 {
        assert!(long_pnl <= 0 && short_pnl >= 0);
    }
    kani::cover!(a_long != a_short && fid != 0 && q > 0 && long_pnl != 0, "asymmetric-A transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
}

/// NOT A RELEASE-GATE PROOF: the Kani lane's negative control showed this grid domain is too
/// weak (flat-A survives: |fid| <= 4 rounds into [-1, 0]). Kept for the record only; the gate is
/// `kani_p3e_skew_funding_conserves_fixed_asym_a` below.
///
/// Bounded companion of the harness above (in case the full symbolic A does not finish): the
/// per-side A ranges over the ten asymmetric grid points k·MIN_A_SIDE (k = 1..=10, i.e. 0.1 ..
/// 1.0 of ADL_ONE) and the size/price/rate fields are narrower. Same assertions, same kernel.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3e_skew_funding_conserves_grid_a() {
    let premium: i8 = kani::any();
    let lp_net: i16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u8 = kani::any();
    let cap: u8 = kani::any();
    let max_abs: u8 = kani::any();
    let dt: u8 = kani::any();
    let price: u16 = kani::any();
    let q: u8 = kani::any();
    let kl: u8 = kani::any();
    let ks: u8 = kani::any();
    kani::assume(kl >= 1 && kl <= 10 && ks >= 1 && ks <= 10 && price > 0);
    let a_long = MIN_A_SIDE * kl as u128;
    let a_short = MIN_A_SIDE * ks as u128;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(kl != ks && fid != 0 && q > 0 && long_pnl != 0, "asymmetric-A transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}


/// Audit fix for `_grid_a` (its negative control SURVIVED: with u8/u16 magnitudes the funding
/// index delta is ≤ 4, so even the flat-A bug rounds to [-1, 0] and the grid domain cannot see
/// the bug class). Here the per-side A is a fixed ASYMMETRIC pair (0.3 vs 1.0 of ADL_ONE; the
/// constant divisors keep CBMC tractable) and the magnitudes are realistic: rate up to the
/// u16 bound, dt up to 65 535 slots, e6 price up to 4.29e9, |q| up to 4.29e9 Q.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3e_skew_funding_conserves_fixed_asym_a() {
    let premium: i16 = kani::any();
    let lp_net: i32 = kani::any();
    let oi: u32 = kani::any();
    let slope: u16 = kani::any();
    let cap: u16 = kani::any();
    let max_abs: u16 = kani::any();
    let dt: u16 = kani::any();
    let price: u32 = kani::any();
    let q: u32 = kani::any();
    kani::assume(price > 0);
    let a_long = MIN_A_SIDE * 3;
    let a_short = ADL_ONE;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(fid != 0 && long_pnl < -1_000, "material transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}

