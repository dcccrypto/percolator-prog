//! Differential: `policy_v16::ewma_update` (u64 fast path) vs the pre-optimisation
//! u128 reference (copied verbatim from d27f3d73). Must be bit-identical.
use percolator_prog::policy_v16::ewma_update;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

fn reference(
    old: u64,
    price: u64,
    halflife_slots: u64,
    last_slot: u64,
    now_slot: u64,
    fee_paid: u64,
    mark_min_fee: u64,
) -> u64 {
    if old == 0 {
        if mark_min_fee > 0 && fee_paid < mark_min_fee {
            return 0;
        }
        return price;
    }
    let dt = now_slot.saturating_sub(last_slot);
    if dt == 0 {
        return old;
    }
    if halflife_slots == 0 {
        return price;
    }
    if fee_paid == 0 && mark_min_fee > 0 {
        return old;
    }
    let alpha_bps = (10_000u128 * dt as u128) / (dt as u128 + halflife_slots as u128);
    let alpha_bps = if mark_min_fee == 0 || fee_paid >= mark_min_fee {
        alpha_bps
    } else {
        alpha_bps.saturating_mul(fee_paid as u128) / mark_min_fee as u128
    };
    let old128 = old as u128;
    let price128 = price as u128;
    let out = if price >= old {
        old128 + ((price128 - old128) * alpha_bps / 10_000)
    } else {
        old128 - ((old128 - price128) * alpha_bps / 10_000)
    };
    core::cmp::min(out, u64::MAX as u128) as u64
}

fn pick(rng: &mut XorShiftRng) -> u64 {
    match rng.gen_range(0..6) {
        0 => rng.gen_range(0..=3),
        1 => rng.gen_range(0..=1_000_000_000_000u64),
        2 => rng.gen(),
        3 => u64::MAX - rng.gen_range(0..=3),
        4 => u64::MAX / 10_000 + rng.gen_range(0..=3) - 1,
        _ => rng.gen_range(0..=1_000_000u64),
    }
}

#[test]
fn ewma_update_matches_u128_reference_200k() {
    let mut rng = XorShiftRng::seed_from_u64(0xE3AA_0001);
    for _ in 0..200_000 {
        let (old, price, hl, last, now) = (pick(&mut rng), pick(&mut rng), pick(&mut rng), pick(&mut rng), pick(&mut rng));
        let min_fee = if rng.gen_bool(0.3) { 0 } else { pick(&mut rng) };
        let fee = match rng.gen_range(0..3) {
            0 => min_fee,
            1 => pick(&mut rng),
            _ => 0,
        };
        assert_eq!(
            ewma_update(old, price, hl, last, now, fee, min_fee),
            reference(old, price, hl, last, now, fee, min_fee),
            "old={old} price={price} hl={hl} last={last} now={now} fee={fee} min={min_fee}"
        );
    }
}
