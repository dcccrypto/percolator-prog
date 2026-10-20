//! NATIVE (not Kani). Exhaustive / structured checks of the production `isqrt_u128` and
//! `plus2pct_depth_e6` (src/extracted.rs = verbatim copy, `extract.sh --check`).
//! Release profile keeps overflow checks ON (any overflow in production code panics).
#[allow(dead_code)]
mod extracted;
use extracted::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn isqrt_ok(n: u128, x: u128) -> bool {
    x.checked_mul(x).is_some_and(|s| s <= n) && (x + 1).checked_mul(x + 1).map_or(true, |s| s > n)
}

/// 51·m² >= 50·r² over 256-bit (hi, lo) arithmetic, independent of production's `depth_pred`.
fn wide_mul_small(x: u128, k: u128) -> (u128, u128) {
    let lo = x & u64::MAX as u128;
    let hi = x >> 64;
    let a = lo * k; // < 2^64 * 2^7
    let b = hi * k;
    let lo_out = (a & u64::MAX as u128) | ((b + (a >> 64)) << 64);
    let hi_out = (b + (a >> 64)) >> 64;
    (hi_out, lo_out)
}
fn ge51_50(m: u64, r: u64) -> bool {
    let a = wide_mul_small((m as u128) * (m as u128), 51);
    let b = wide_mul_small((r as u128) * (r as u128), 50);
    a >= b
}
fn depth_ok(r: u64, d: u64) -> bool {
    if d > r {
        return false;
    }
    let m = r - d;
    ge51_50(m, r) && (m == 0 || !ge51_50(m - 1, r)) && (d as u128) * 100 <= r as u128
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn par(total: u64, threads: u64, f: impl Fn(u64, u64) -> u64 + Sync) -> u64 {
    let bad = AtomicU64::new(0);
    std::thread::scope(|s| {
        for t in 0..threads {
            let (bad, f) = (&bad, &f);
            s.spawn(move || {
                let lo = total / threads * t;
                let hi = if t + 1 == threads { total } else { total / threads * (t + 1) };
                bad.fetch_add(f(lo, hi), Ordering::Relaxed);
            });
        }
    });
    bad.into_inner()
}

fn main() {
    let threads: u64 = std::env::var("THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    let which = std::env::args().nth(1).unwrap_or_default();
    let t0 = std::time::Instant::now();
    // checker self-test (negative controls for the oracles themselves)
    let (r, want) = (1_000_000u64 * 1_000_000, 9_852_457_023u64);
    assert!(depth_ok(r, want) && !depth_ok(r, want + 1) && !depth_ok(r, want - 1));
    assert!(depth_ok(u64::MAX, 181_745_753_206_511_237) && !depth_ok(u64::MAX, 181_745_753_206_511_238));
    assert!(isqrt_ok(16, 4) && !isqrt_ok(15, 4) && !isqrt_ok(25, 4) && isqrt_ok(u128::MAX, u64::MAX as u128));
    if which == "isqrt32" || which == "all" {
        let bad = par(1u64 << 32, threads, |lo, hi| (lo..hi).filter(|&n| !isqrt_ok(n as u128, isqrt_u128(n as u128))).count() as u64);
        println!("isqrt exhaustive n < 2^32: {} cases, {} bad, {:?}", 1u64 << 32, bad, t0.elapsed());
    }
    if which == "isqrt128" || which == "all" {
        // structured u128 boundaries: n in {s^2 - 1, s^2, s^2 + 1, s^2 + 2s} for every s < 2^22 and
        // 2^24 random s < 2^64 (incl. s near 2^64), plus u128::MAX.
        let mut checked = 0u64;
        let mut bad = 0u64;
        let mut chk = |s: u128| {
            let sq = s * s;
            for n in [sq.wrapping_sub(1), sq, sq + 1, sq + 2 * s] {
                if s == 0 && n == u128::MAX {
                    continue;
                }
                checked += 1;
                if !isqrt_ok(n, isqrt_u128(n)) {
                    bad += 1;
                    eprintln!("BAD isqrt n={n}");
                }
            }
        };
        for s in 0u128..(1 << 22) {
            chk(s);
        }
        let mut g = Rng(0x9E37_79B9_7F4A_7C15);
        for i in 0..(1u64 << 24) {
            let s = if i % 4 == 0 { u64::MAX - (g.next() >> 40) } else { g.next() };
            chk(s as u128);
        }
        checked += 1;
        if !isqrt_ok(u128::MAX, isqrt_u128(u128::MAX)) {
            bad += 1;
        }
        println!("isqrt u128 boundaries: {checked} cases, {bad} bad, {:?}", t0.elapsed());
    }
    if which == "depth32" || which == "all" {
        let bad = par(1u64 << 32, threads, |lo, hi| (lo..hi).filter(|&r| !depth_ok(r, plus2pct_depth_e6(r))).count() as u64);
        println!("plus2pct exhaustive r < 2^32: {} cases, {} bad, {:?}", 1u64 << 32, bad, t0.elapsed());
    }
    if which == "depth64" || which == "all" {
        let n = 1u64 << 26;
        let bad = par(n, threads, |lo, hi| {
            let mut g = Rng(0xD1B5_4A32_D192_ED03 ^ lo.wrapping_mul(0x2545F4914F6CDD1D) | 1);
            (lo..hi)
                .filter(|&i| {
                    let r = match i % 4 {
                        0 => u64::MAX - (g.next() >> 32),
                        1 => g.next() >> (g.next() % 64),
                        _ => g.next(),
                    };
                    !depth_ok(r, plus2pct_depth_e6(r))
                })
                .count() as u64
        });
        println!("plus2pct random u64 (2^26 cases, 1/4 near u64::MAX): {bad} bad, {:?}", t0.elapsed());
    }
}
