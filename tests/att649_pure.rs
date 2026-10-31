//! att649 (independent attacker, PR #649): pure-function repros on the production `bond_v20`.
use percolator_prog::bond_v20::*;

/// ATT649-F3: the checkpoint hold only covers intervals that floor to 0 atoms. A tranche whose
/// per-slot accrual is in [1, 2) atoms, settled every slot (permissionless dust trade + tag 78),
/// floors each slot to 1 and moves the checkpoint: up to ~half the coupon is ground away.
#[test]
fn att649_f3_every_slot_settlement_grinds_when_per_slot_accrual_is_between_1_and_2_atoms() {
    let rate = 2_000u32;
    // per-slot due = K * 2000 / (1e4 * 78.84e6) = 1.95 atoms
    let cb: u128 = 768_690_000; // ~769 USDC
    let slots = 10_000u64;
    let (mut a, mut last) = (0u128, 0u64);
    for now in 1..=slots {
        let open = true;
        let a1 = coupon_settle(cb, a, rate, now - last, open, cb + a).unwrap();
        let cap = coupon_arrears_cap(cb, rate).unwrap();
        if coupon_checkpoint_moves(open, a, a1, cap) {
            last = now;
        }
        a = a1;
    }
    let once = coupon_settle(cb, 0, rate, slots, true, cb).unwrap();
    eprintln!("ATT649-F3: every-slot settlement {a} atoms vs one settlement {once} ({}% lost)", 100 - a * 100 / once);
    assert!(a * 100 < once * 55, "about half the coupon is ground away: {a} vs {once}");
}
