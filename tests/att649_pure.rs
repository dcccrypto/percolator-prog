//! att649 round 2 pure repros (production bond_v20).
use percolator_prog::bond_v20::*;

/// ATT649-R2-C: U-meter rounding loop. A tiny deposit is labelled ceil(d*U/K) (>= 1 atom) and the
/// same shares' exit removes floor(sh*U/B) (0 atoms): each round trip leaves +1 atom in U, i.e.
/// takes 1 atom of cap headroom from the stayers (in the junior's favour). Dust grief only.
#[test]
fn att649_r2c_meter_rounding_loop_pumps_u_by_one_atom_per_round_trip() {
    let (mut k, mut b, mut u) = (2_000_000_000u128, 2_000_000_000u128, 200_000_000u128); // U/K = 10%
    let u0 = u;
    for _ in 0..100 {
        let d = 2u128;
        let m = bond_shares_for_deposit(d, b, k).unwrap();
        assert!(m > 0);
        u = coupon_meter_after_deposit(u, k, d).unwrap();
        k += d;
        b += m;
        let u2 = coupon_meter_after_redemption(u, m, b).unwrap();
        let k2 = bond_claim_after_redemption(k, m, b).unwrap();
        b -= m;
        u = u2;
        k = k2;
    }
    eprintln!("ATT649-R2-C: after 100 round trips U {u0} -> {u} (K {k})");
    assert!(u >= u0 + 90, "each tiny round trip leaves ~1 atom of U behind");
}
