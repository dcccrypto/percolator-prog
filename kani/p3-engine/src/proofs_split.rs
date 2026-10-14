//! v2.2 Kani overnight (2026-10-14): SPLIT replacements for the skew-funding conservation rows
//! (`kani_p3e_skew_funding_conserves_{const_divisor, fixed_asym_a, through_engine_kernel}` in `proofs.rs`,
//! NO VERDICT at 600-8003 s; kept unchanged).
//!
//! The originals push a bilinear product (`q * fid * A`) through two 128-bit floor divisions. SAT cannot
//! see associativity / cancellation at those widths. The chain is split at its natural joints:
//!
//!   rate path --(S0)--> |rate| bound ;  fid = floor(n / FUNDING_DEN) --(S1)--> |fid| bound
//!   kernel (S2): f_long = -(fid * a_long), f_short = fid * a_short      (REAL engine kernel)
//!   realize (S3): floor((-K) * a / (a * POS_SCALE)) == floor(-K / POS_SCALE) and
//!                 floor(K * a / (a * POS_SCALE))   == floor(K / POS_SCALE)  (REAL engine floor-div)
//!   sign (S4): floor(-K / P) + floor(K / P) in [-1, 0]                         (REAL engine floor-div)
//!
//! with K = q * fid. The ONE paper step is the ring identity q * (-(fid * a)) == -((q * fid) * a) for
//! machine integers whose products do not overflow (every product here is checked or bounded below
//! i128::MAX, so the machine value IS the integer value). S5 corroborates the composed chain end-to-end
//! on the real kernel + realize with `q` narrowed to u8 (no paper step there).
use crate::vault_lp_v18::*;
use percolator::wide_math::floor_div_signed_conservative_i128 as fdiv;
#[allow(unused_imports)]
use percolator::{ADL_ONE, FUNDING_DEN, MIN_A_SIDE, POS_SCALE};

const A_LONG_FIXED: u128 = MIN_A_SIDE * 3; // the fixed asymmetric pair of the originals
const A_SHORT_FIXED: u128 = ADL_ONE;

/// S0 (rate path, REAL `skew_funding_rate_e9` + `combine_funding_rate_e9`, the input types of
/// `fixed_asym_a` / `through_engine_kernel`): the combined rate is within the engine cap, so
/// `|rate| < 2^16`. (The const-divisor row takes `rate: i32` directly.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s0_rate_within_cap() {
    let premium: i16 = kani::any();
    let lp_net: i32 = kani::any();
    let oi: u32 = kani::any();
    let slope: u16 = kani::any();
    let cap: u16 = kani::any();
    let max_abs: u16 = kani::any();
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    assert!(rate.unsigned_abs() <= max_abs as u128);
    assert!(skew.unsigned_abs() <= cap as u128);
    if lp_net < 0 {
        assert!(skew >= 0, "vault LP short (traders long): skew charges the longs");
    }
    kani::cover!(skew != 0 && premium == 0 && rate == skew, "skew alone sets the rate");
    kani::cover!(rate == max_abs as i128 && max_abs > 0, "clamped at the cap");
}

/// S1 (REAL engine `floor_div_signed_conservative_i128`, constant FUNDING_DEN): exact floor in remainder
/// form for every |n| < 2^79 (S0b: |rate*dt*price| < 2^31 * 2^16 * 2^32 = 2^79). Hence
/// |fid| <= |n| / 1e9 + 1 < 2^50 (and |fid| < 2^35 when |n| < 2^64, S0c; < 2^27 when |n| < 2^56).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s1_fid_floor_exact() {
    let n: i128 = kani::any();
    kani::assume(n.unsigned_abs() < (1u128 << 79)); // BOUNDED: the rate-path numerators (S0b)
    let fid = fdiv(n, FUNDING_DEN);
    let d = FUNDING_DEN as i128;
    assert!(fid * d <= n && n < fid * d + d, "exact floor");
    assert!(fid.unsigned_abs() < (1u128 << 50));
    kani::cover!(n < 0 && n % d != 0, "negative, rounded down");
    kani::cover!(n > 0 && fid > 0, "positive");
}

/// S0b: the numerator bound used by S1 for the const-divisor row: |rate * dt * price| < 2^79 for
/// rate i32, dt u16, price u32 (bit-width fact, machine-checked).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s0b_numerator_width() {
    let rate: i32 = kani::any();
    let dt: u16 = kani::any();
    let price: u32 = kani::any();
    let n = rate as i128 * dt as i128 * price as i128;
    assert!(n.unsigned_abs() < (1u128 << 79));
    kani::cover!(n != 0, "non-zero");
}

/// S0c: with |rate| <= max_abs < 2^16 (S0), dt u16, price u32: |rate * dt * price| < 2^64 (the
/// fixed_asym_a domain; the through_engine_kernel domain has dt u8, a subset).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s0c_numerator_width_capped_rate() {
    let rate: i32 = kani::any();
    let dt: u16 = kani::any();
    let price: u32 = kani::any();
    kani::assume(rate.unsigned_abs() < (1u32 << 16)); // S0
    let n = rate as i128 * dt as i128 * price as i128;
    assert!(n.unsigned_abs() < (1u128 << 64));
    kani::cover!(n != 0, "non-zero");
}

/// S2 (REAL engine kernel `kani_adl_scaled_accrual_index_deltas`, the fixed asymmetric A pair): for every
/// |fid| < 2^50 the kernel is Ok and returns exactly (0, 0, -(fid * a_long), fid * a_short).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s2_kernel_shape_fixed_a() {
    let fid: i128 = kani::any();
    kani::assume(fid.unsigned_abs() < (1u128 << 50)); // S1's bound
    let r = percolator::kani_adl_scaled_accrual_index_deltas(0, fid, A_LONG_FIXED, A_SHORT_FIXED);
    let (kl, ks, fl, fs) = r.unwrap();
    #[cfg(not(feature = "neg_flat_a"))]
    let (el, es) = (-(fid * A_LONG_FIXED as i128), fid * A_SHORT_FIXED as i128);
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 flat-A expectation must FAIL against the kernel.
    #[cfg(feature = "neg_flat_a")]
    let (el, es) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    assert!(kl == 0 && ks == 0);
    assert!(fl == el && fs == es);
    kani::cover!(fid > 0 && fl < 0, "longs debited");
    kani::cover!(fid < 0 && fs < 0, "shorts debited");
}

/// S2 with SYMBOLIC per-side A in [MIN_A_SIDE, ADL_ONE] (the `through_engine_kernel` domain:
/// |fid| < 2^27 since |rate| < 2^16, dt < 2^8, price < 2^32).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s2_kernel_shape_sym_a() {
    let fid: i128 = kani::any();
    let a_long: u128 = kani::any();
    let a_short: u128 = kani::any();
    kani::assume(fid.unsigned_abs() < (1u128 << 27)); // BOUNDED: through_engine_kernel's fid range
    kani::assume(a_long >= MIN_A_SIDE && a_long <= ADL_ONE); // the original's assume
    kani::assume(a_short >= MIN_A_SIDE && a_short <= ADL_ONE); // the original's assume
    let (kl, ks, fl, fs) = percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    assert!(kl == 0 && ks == 0);
    assert!(fl == -(fid * a_long as i128) && fs == fid * a_short as i128);
    kani::cover!(a_long != a_short && fid != 0, "asymmetric A");
}

/// S3 (REAL engine floor-div): exact cancellation of the side's A in the realize rule, per fixed A, for
/// every K whose scaled numerator fits i128 (the realize rule's own precondition: the original checks
/// `q * dF` and the kernel checks `fid * a`).
macro_rules! s3_cancel {
    ($name:ident, $a:expr) => {
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $name() {
            let k: i128 = kani::any();
            let a = $a as i128;
            let Some(ka) = k.checked_mul(a) else {
                return; // outside the i128 realize model (the original returns there too)
            };
            let lhs = fdiv(ka, $a * POS_SCALE);
            let rhs = fdiv(k, POS_SCALE);
            assert_eq!(lhs, rhs, "A cancels exactly");
            kani::cover!(k < 0 && k % POS_SCALE as i128 != 0, "negative, rounded");
            kani::cover!(k > 0 && rhs > 0, "positive");
        }
    };
}
s3_cancel!(kani_p3e_split_s3_cancel_a_long_fixed, A_LONG_FIXED);
s3_cancel!(kani_p3e_split_s3_cancel_a_short_fixed, A_SHORT_FIXED);

/// S3 with SYMBOLIC A in [MIN_A_SIDE, ADL_ONE] (through_engine_kernel). BOUNDED: |K| < 2^43
/// (q u16 times |fid| < 2^27).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s3_cancel_sym_a() {
    let k: i128 = kani::any();
    let a: u128 = kani::any();
    kani::assume(k.unsigned_abs() < (1u128 << 43)); // BOUNDED (doc)
    kani::assume(a >= MIN_A_SIDE && a <= ADL_ONE); // the original's assume
    let lhs = fdiv(k * a as i128, a * POS_SCALE);
    let rhs = fdiv(k, POS_SCALE);
    assert_eq!(lhs, rhs, "A cancels exactly");
    kani::cover!(k < 0 && k % POS_SCALE as i128 != 0 && a != ADL_ONE, "negative, rounded, A < 1");
    kani::cover!(k > 0 && rhs > 0 && a != ADL_ONE, "positive, A < 1");
}

/// S4 (REAL engine floor-div): two matched legs settle to a sum in [-1, 0]: floor(-K/P) + floor(K/P).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s4_sign_pair() {
    let k: i128 = kani::any();
    kani::assume(k != i128::MIN); // -K must exist (|K| < 2^127 on every path: K * a fits i128, a >= 1e14)
    let p = POS_SCALE;
    let long_pnl = fdiv(-k, p);
    let short_pnl = fdiv(k, p);
    let net = long_pnl + short_pnl;
    assert!(net <= 0 && net >= -1);
    if k > 0 {
        assert!(long_pnl <= 0 && short_pnl >= 0, "the paying side never gains");
    }
    kani::cover!(net == -1, "one atom of dust destroyed");
    kani::cover!(net == 0 && k != 0, "exact transfer");
    kani::cover!(long_pnl < -1_000, "material transfer");
}

/// S5 (corroboration, no paper step): the composed kernel + realize chain end-to-end on the REAL kernel
/// and REAL floor-div, fixed A pair, |fid| < 2^50, q narrowed to u8. BOUNDED: q u8.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_split_s5_chain_q_u8_fixed_a() {
    let fid: i128 = kani::any();
    let q: u8 = kani::any();
    kani::assume(fid.unsigned_abs() < (1u128 << 50)); // S1's bound
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, A_LONG_FIXED, A_SHORT_FIXED).unwrap();
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = fdiv(q * f_long, A_LONG_FIXED * POS_SCALE);
    let short_pnl = fdiv(q * f_short, A_SHORT_FIXED * POS_SCALE);
    let net = long_pnl + short_pnl;
    assert!(net <= 0 && net >= -1);
    kani::cover!(fid != 0 && long_pnl < -1_000, "material transfer, longs pay");
    kani::cover!(fid < 0 && short_pnl < -1_000, "material transfer, shorts pay");
}

/// Review 2026-10-14: S4 restricted to the chain's actual domain |K| = |q * fid| < 2^82 (q u32, |fid| < 2^50,
/// S1). The unbounded S4 has no verdict (z3 300 s overnight, kissat 400 s in review).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_p3e_rev_s4_sign_pair_k82() {
    let k: i128 = kani::any();
    kani::assume(k.unsigned_abs() < (1u128 << 82)); // BOUNDED: the chain's |q * fid|
    let p = POS_SCALE;
    let long_pnl = fdiv(-k, p);
    let short_pnl = fdiv(k, p);
    let net = long_pnl + short_pnl;
    assert!(net <= 0 && net >= -1);
    if k > 0 {
        assert!(long_pnl <= 0 && short_pnl >= 0, "the paying side never gains");
    }
    kani::cover!(net == -1, "one atom of dust destroyed");
    kani::cover!(net == 0 && k != 0, "exact transfer");
    kani::cover!(long_pnl < -1_000, "material transfer");
}
