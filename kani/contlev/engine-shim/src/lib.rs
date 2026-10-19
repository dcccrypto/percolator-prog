#![allow(dead_code)]
pub const POS_SCALE: u128 = 1_000_000;
pub const MAX_ORACLE_PRICE: u64 = 1_000_000_000_000;

#[path = "../../../../../percolator/src/wide_math.rs"]
pub mod wide_math;

#[path = "../../../../../percolator/src/band_rent.rs"]
pub mod band_rent;
