//! 2026-10-30 independent attack pass over #629/#630/#631 (pure-function level).
use percolator_prog::lev_guard_v22::{
    lp_stop_triggered, nav_epoch_start, nav_sample, nav_stop_reset, NavState, NAV_ONE,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn wiped() -> NavState {
    // stored by op 4 after the vault LP went insolvent: index 0, reference/peaks at 1.0
    NavState { navps: 0, last_equity: 5_000, last_in: 5_000, last_out: 0, peak_cur: NAV_ONE, peak_prev: NAV_ONE, bucket_start: 0, ref_navps: NAV_ONE, last_slot: 0 }
}

/// #631: whatever op 4 samples arrive (any equity, any monotone flows, any slots), a pending stop
/// is never erased and the index/peaks never move until op 5 acknowledges.
#[test]
fn held_stop_survives_any_monotone_sample_sequence() {
    let mut r = Rng(0xdead_beef_1234_5678);
    for case in 0..2000u64 {
        let mut s = nav_sample(&wiped(), 0, 5_000, 5_000, 10); // equity 0 after outflows
        assert!(lp_stop_triggered(&s), "case {case}");
        let (mut fi, mut fo) = (s.last_in, s.last_out);
        for k in 0..50u64 {
            fi += (r.next() % 3) as u128 * (r.next() % 1_000_000) as u128;
            fo += (r.next() % 3) as u128 * (r.next() % 1_000_000) as u128;
            let eq = if r.next() % 3 == 0 { 0 } else { (r.next() % 1u64 << 40) as u128 };
            let slot = 10 + k * 100_000; // crosses the 24h bucket boundaries too
            s = nav_sample(&s, eq, fi, fo, slot);
            assert!(lp_stop_triggered(&s), "stop erased at case {case} step {k}");
            assert_eq!(s.navps, 0);
            assert_eq!(s.ref_navps, NAV_ONE);
        }
        // acknowledgement then a clean restart
        let a = nav_stop_reset(&s);
        assert!(!a.initialised() || !lp_stop_triggered(&a) || a.navps == 0);
        let n = nav_sample(&a, 777, fi, fo, 9_999_999);
        assert!(!lp_stop_triggered(&n), "post-ack epoch must restart clean");
        assert_eq!(n.navps, NAV_ONE);
    }
}

/// 1-atom base: a loss in the same interval as any inflow, and 1-atom gains, never wrap/saturate;
/// a real 50% loss on a 1-atom base without flows fires.
#[test]
fn one_atom_base_edges() {
    let s = nav_epoch_start(1, 0, 0, 0);
    let up = nav_sample(&s, 2, 0, 0, 1);
    assert_eq!(up.navps, 2 * NAV_ONE);
    let down = nav_sample(&s, 0, 0, 0, 1);
    assert!(lp_stop_triggered(&down));
    // 1-atom LP, enormous round trip, +1 atom of P&L: gain credited on the gross base only
    let big = 1u128 << 62;
    let g = nav_sample(&s, 1 + 1, big, big, 1);
    assert!(g.navps >= NAV_ONE && g.navps <= NAV_ONE + NAV_ONE / (big / 2), "diluted, never amplified: {}", g.navps);
}

/// Known residual (not a #631 regression): a counter that goes backwards restarts the epoch even
/// on a triggered state. Pinned so a change is noticed; the engine's flow counters are monotone.
#[test]
fn residual_backwards_counters_restart_even_a_triggered_state() {
    let w = wiped();
    let n = nav_sample(&w, 0, 4_999, 0, 10);
    assert!(!lp_stop_triggered(&n), "pinned: flow counters going backwards restart the epoch");
}

/// C1: a >= 2-day gap between samples must not launder a fall that happened inside the gap.
#[test]
fn c1_two_day_gap_does_not_launder_the_peak() {
    use percolator_prog::lev_guard_v22::SLOTS_PER_DAY;
    let st = nav_epoch_start(1_000_000, 0, 0, 0);
    let st = nav_sample(&st, 2_000_000, 0, 0, 10); // index 2.0
    // 2.0 -> 0.9 (55% from the peak, only 10% from the reference), first sample 2 days later
    let late = nav_sample(&st, 900_000, 0, 0, 2 * SLOTS_PER_DAY + 1);
    assert!(lp_stop_triggered(&late), "the fall inside the gap must be seen");
    // no fall: the peak restarts at the current value and nothing fires
    let calm = nav_sample(&st, 1_900_000, 0, 0, 2 * SLOTS_PER_DAY + 1);
    assert!(!lp_stop_triggered(&calm));
    // a gain over the gap: the peak is the new (higher) index
    let up = nav_sample(&st, 3_000_000, 0, 0, 2 * SLOTS_PER_DAY + 1);
    assert_eq!(up.peak(), up.navps);
    // a LATER rise does not erase it: after the gap the carried peak decays only by the window
    let after = nav_sample(&calm, 1_900_000, 0, 0, 2 * SLOTS_PER_DAY + 2);
    assert!(!lp_stop_triggered(&after));
}
