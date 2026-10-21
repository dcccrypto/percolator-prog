//! Native exhaustive check of the REAL `bps_floor` / `bps_ceil` (production vault_lp_v18.rs) against
//! the exact floor / ceiling relation, over every residue pair (r < 1e4, b <= 1e4) at three
//! quotients q (0, 1, the u32 maximum), plus 2^24 sampled (x: u32, b) and 2^20 sampled u64 x.
//! Also checks the two Rust div/rem identities the Kani remainder-form lemmas assume.
use rck_proofs::vault_lp_v18::{bps_ceil, bps_floor};
const B: u128 = 10_000;

fn check(x: u128, b: u16) {
    let xb = x * b as u128;
    let f = bps_floor(x, b).unwrap();
    let c = bps_ceil(x, b).unwrap();
    assert!(f * B <= xb && xb < f * B + B, "floor x={x} b={b}");
    assert!(xb <= c * B && c * B < xb + B, "ceil x={x} b={b}");
    let (q, r) = (x / B, x % B);
    assert!(x == B * q + r && r < B);
    let t = r * b as u128;
    assert!(t == B * (t / B) + t % B && t % B < B);
}

#[test]
fn bps_exhaustive_residues() {
    let qmax = (u32::MAX as u128) / B;
    for b in 0..=10_000u16 {
        assert!(bps_floor(1, 10_001).is_none() && bps_ceil(1, 10_001).is_none());
        for r in 0..10_000u128 {
            for q in [0u128, 1, qmax] {
                let x = q * B + r;
                if x <= u32::MAX as u128 { check(x, b); }
            }
        }
    }
}

#[test]
fn bps_sampled() {
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || { s ^= s << 13; s ^= s >> 7; s ^= s << 17; s };
    for _ in 0..(1u32 << 24) {
        let v = next();
        check((v >> 32) as u128, ((v as u32) % 10_001) as u16);
    }
    for _ in 0..(1u32 << 20) {
        let v = next();
        check(v as u128, (next() % 10_001) as u16);
    }
}
