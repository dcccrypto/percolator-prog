//! Wiring + smoke coverage for `tests/support/reference_math.rs` (T-ref, wrapper-sync
//! loop, ported verbatim from upstream `aeyakovenko/percolator-prog`
//! `358162c72fe94acf71ad062b1e853f8fd431932d:tests/support/reference_math.rs`).
//!
//! This unit is test-support only: it brings a reference math oracle (exact
//! `mul_div_floor` / `mul_div_floor_with_remainder` / `mul_div_ceil` computed without
//! the engine's wide-arithmetic helpers) for later differential/invariant tests to
//! check the engine's rounding against. Nothing under `src/` changes.
//!
//! `tests/support/*` is a subdirectory module tree, and Cargo only auto-discovers
//! `.rs` files directly under `tests/` as their own test binaries -- a subdirectory
//! is invisible to `cargo test` unless something at the `tests/` root declares
//! `mod support;`. This file is that declaration, so the port is actually
//! typechecked and exercised rather than sitting dead and unverified. It does not
//! modify any pre-existing test file.

mod support;

use support::reference_math::{mul_div_ceil, mul_div_floor, mul_div_floor_with_remainder};

#[test]
fn mul_div_floor_matches_exact_integer_division() {
    // 6 * 7 / 2 = 21 exactly.
    assert_eq!(mul_div_floor(6, 7, 2).unwrap(), 21);
    // 7 * 5 / 3 = 11.666... -> floors to 11.
    assert_eq!(mul_div_floor(7, 5, 3).unwrap(), 11);
    // Identity: x * 1 / 1 == x.
    assert_eq!(mul_div_floor(u128::MAX, 1, 1).unwrap(), u128::MAX);
}

#[test]
fn mul_div_floor_with_remainder_reconstructs_the_exact_product() {
    let lhs: u128 = 123_456_789_012_345;
    let rhs: u128 = 987_654_321_098_765;
    let denominator: u128 = 424_242;
    let (quotient, remainder) =
        mul_div_floor_with_remainder(lhs, rhs, denominator).unwrap();
    // quotient * denominator + remainder must equal the exact 256-bit product,
    // computed independently here via u128 widening (both operands are far
    // below u128::MAX / denominator so this multiplication does not overflow).
    let exact_product = lhs * rhs;
    assert_eq!(quotient * denominator + remainder, exact_product);
    assert!(remainder < denominator);
}

#[test]
fn mul_div_ceil_rounds_up_only_when_there_is_a_remainder() {
    // Exact division: floor == ceil.
    assert_eq!(mul_div_ceil(6, 7, 2).unwrap(), mul_div_floor(6, 7, 2).unwrap());
    assert_eq!(mul_div_ceil(6, 7, 2).unwrap(), 21);
    // Inexact division: ceil is floor + 1.
    assert_eq!(mul_div_floor(7, 5, 3).unwrap(), 11);
    assert_eq!(mul_div_ceil(7, 5, 3).unwrap(), 12);
}

#[test]
fn mul_div_floor_rejects_zero_denominator() {
    assert!(mul_div_floor(1, 1, 0).is_err());
}

#[test]
fn mul_div_ceil_rejects_zero_denominator() {
    assert!(mul_div_ceil(1, 1, 0).is_err());
}
