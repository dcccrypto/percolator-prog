//! Native exhaustive / boundary checks of the two nonlinear kernels the Kani models replace
//! (ledger §10). Run ONCE in release WITH debug assertions and overflow checks:
//!   CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true \
//!     cargo run --release --bin contlev_exhaustive
//! E1: `log2_frac_q16` on EVERY mantissa m in [2^31, 2^32): `< 2^16`, MONOTONE (consecutive
//!     pairs, so for all pairs), 0 at 2^31, and the in-loop `debug_assert!(m < 2^32)` (no
//!     wrap) holds at every squaring of every input.
//! E2: `curve_interp` on EVERY (span, num, den) with span, den < 2^10, num <= den: exact
//!     floor, `<= span`, monotone in num, monotone and 1-Lipschitz in span.
//! E3: `curve_interp` at full width (boundaries + 50M xorshift samples, both branches) against
//!     an independent u128 reference.
use contlev_proofs::growth_v19::{curve_interp, log2_frac_q16, log2_q16, LOG2_FRAC_BITS};
use std::time::Instant;

fn main() {
    assert!(cfg!(debug_assertions), "build with CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true");
    let src = include_str!("../../../../src/depth_src_v22.rs");
    assert!(src.contains("pub const DEPTH_MODE_DEX: u8 = 2;"), "the depth_src_v22 shim matches production");

    // E1
    let t0 = Instant::now();
    let mut prev = 0u32;
    let mut rises = 0u64;
    let mut m = 1u64 << 31;
    while m < 1u64 << 32 {
        let r = log2_frac_q16(m);
        assert!(r < 1u32 << LOG2_FRAC_BITS, "range at {m}");
        assert!(r >= prev, "monotone at {m}: {r} < {prev}");
        if r > prev {
            rises += 1;
        }
        prev = r;
        m += 1;
    }
    assert_eq!(log2_frac_q16(1u64 << 31), 0);
    assert_eq!(log2_q16(1u64 << 40), Some(40 << 16), "exact at a power of two");
    println!(
        "E1 PASS: 2^31 mantissas, monotone, < 2^16, no-wrap debug_assert held; top fraction {prev:#x}, {rises} rises ({:.1}s)",
        t0.elapsed().as_secs_f64()
    );

    // E2
    let t1 = Instant::now();
    let mut calls = 0u64;
    for d in 1u32..1024 {
        for s in 0u64..1024 {
            let mut pv = 0u64;
            for n in 0..=d {
                let r = curve_interp(s, n, d);
                assert_eq!(r, s * n as u64 / d as u64, "floor at s {s} n {n} d {d}");
                assert!(r <= s);
                assert!(r >= pv, "monotone in num");
                pv = r;
                calls += 1;
            }
            assert_eq!(pv, s, "num = den reads span");
        }
        for n in 0..=d {
            let mut pv = curve_interp(0, n, d);
            assert_eq!(pv, 0);
            for s in 1u64..1024 {
                let r = curve_interp(s, n, d);
                assert!(r >= pv && r - pv <= 1, "monotone and 1-Lipschitz in span at s {s} n {n} d {d}");
                pv = r;
                calls += 1;
            }
        }
    }
    println!("E2 PASS: {calls} calls, 10-bit operands exhaustive ({:.1}s)", t1.elapsed().as_secs_f64());

    // E3
    let t2 = Instant::now();
    let reference = |s: u64, n: u32, d: u32| -> u64 { ((s as u128 * n as u128) / d as u128) as u64 };
    let spans = [0u64, 1, 2, 65_535, u32::MAX as u64 - 1, u32::MAX as u64, u32::MAX as u64 + 1, 1 << 40, u64::MAX - 1, u64::MAX];
    let dens = [1u32, 2, 3, 65_536, u32::MAX - 1, u32::MAX];
    let mut checked = 0u64;
    for &s in &spans {
        for &d in &dens {
            for n in [0u32, 1, d / 2, d.saturating_sub(1), d] {
                assert_eq!(curve_interp(s, n, d), reference(s, n, d), "boundary s {s} n {n} d {d}");
                checked += 1;
            }
        }
    }
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..50_000_000u64 {
        let raw = next();
        let s = if i % 2 == 0 { raw >> 32 } else { raw >> (next() % 64) };
        let d = ((next() >> 32) as u32).max(1);
        let n = ((next() >> 32) as u32) % d.saturating_add(1).max(1);
        let n = if n > d { d } else { n };
        let r = curve_interp(s, n, d);
        assert_eq!(r, reference(s, n, d), "random s {s} n {n} d {d}");
        assert!(r <= s);
        checked += 1;
    }
    println!("E3 PASS: {checked} full-width checks against u128 ({:.1}s)", t2.elapsed().as_secs_f64());
    println!("ALL PASS");
}
