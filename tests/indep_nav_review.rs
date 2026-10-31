//! Independent adversarial review of prog #629/#630/#631 (LP-stop NAV index), 2026-10-30.
//! Pure-function: real `nav_sample` / `lp_stop_triggered` / `nav_stop_reset`.
use percolator_prog::lev_guard_v22::*;

const D: u128 = SLOTS_PER_DAY as u128;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn mag(&mut self, bits: u32) -> u128 {
        let b = (self.next() % (bits as u64 + 1)) as u32;
        if b == 0 { return 0; }
        let v = (self.next() as u128) << 64 | self.next() as u128;
        if b >= 128 { v } else { v & ((1u128 << b) - 1) }
    }
}

/// P1 (holds): monotonicity. A gain interval (P>=0) never lowers the index, a loss interval
/// (P<0) never raises it, whatever the flow pattern -- so no flow ordering can false-trip on a gain
/// or fake a recovery on a loss. Also: no panic anywhere in u64-scale and 2^100-scale inputs.
#[test]
fn p1_sign_monotonicity_random() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..400_000 {
        let bits = if r.next() % 4 == 0 { 100 } else { 64 };
        let last = r.mag(bits);
        let (lin, lout) = (r.mag(bits), r.mag(bits));
        let (din, dout) = (r.mag(bits), r.mag(bits));
        let eq = r.mag(bits);
        let navps = (r.mag(70)).max(1);
        let st = NavState { navps, last_equity: last, last_in: lin, last_out: lout, peak_cur: navps, peak_prev: navps, ref_navps: navps, bucket_start: 0, last_slot: 0 };
        let n = nav_sample(&st, eq, lin + din, lout + dout, 1);
        if last == 0 { continue; }
        let p = eq as i128 + dout as i128 - din as i128 - last as i128;
        if bits == 64 {
            if p >= 0 { assert!(n.navps >= navps, "gain lowered: {st:?} eq {eq} din {din} dout {dout} -> {}", n.navps); }
            if p < 0 { assert!(n.navps <= navps, "loss raised: {st:?} eq {eq} din {din} dout {dout} -> {}", n.navps); }
        }
    }
}

/// A1 (BROKEN, pre-existing F1, not touched by #629-631; severity MEDIUM): the loss mask is
/// UNBOUNDED in the inflow and PERMANENT. A real 60 % loss is read ~0 %, and a later
/// pure-flow interval (outflow of the same atoms) never repairs the index. The inflow source is a
/// permissionless tag 103 allocation (bounded by alpha*C_eff) or the junior owner's own deposit.
#[test]
fn a1_inflow_masks_real_loss_permanently() {
    let l = 1_000_000_000u128;
    let st = nav_epoch_start(l, 0, 0, 0);
    let x = 1_000_000 * l; // senior capital >> junior
    // real equity after a 60% loss is 0.4 l; inflow x lands before the sample
    let masked = nav_sample(&st, 4 * l / 10 + x, x, 0, 10);
    assert!(!lp_stop_triggered(&masked));
    assert!(masked.navps > NAV_ONE - NAV_ONE / 1_000_000, "60% loss read as {}", masked.navps);
    // the inflow leaves again (pure outflow, no P&L): index unchanged -> stays at ~1.0 while truth is 0.4
    let after = nav_sample(&masked, 4 * l / 10, x, x, 20);
    assert_eq!(after.navps, masked.navps);
    // truth 0.25 of the peak (a 75% real drawdown): still no stop
    let again = nav_sample(&after, 25 * l / 100, x, x, 30);
    assert!(!lp_stop_triggered(&again), "truth is 0.25 of the peak, index reads {}", again.navps);
}

/// B1 (BROKEN, introduced/aggravated by #630 cap; severity LOW-MEDIUM, needs a flow round trip
/// in each gain interval, i.e. the junior owner with flash liquidity): volatility drag. The real
/// NAV oscillates +2 % / -1.96 % (flat). Gains are diluted to ~0 by a k=100L in/out round trip
/// in the same interval as the gain, losses read in full. Index decays ~2 %/cycle and the D-i
/// reference arm fires after ~35 cycles with NO real loss. Honest control never fires.
#[test]
fn b1_round_trip_dilution_gives_volatility_drag_false_trip() {
    let run = |grief: bool| -> (bool, u32) {
        let l0 = 10_000_000_000u128;
        let mut cap = l0;
        let mut st = nav_epoch_start(l0, 0, 0, 0);
        let (mut fin, mut fout) = (0u128, 0u128);
        let mut slot = 0u64;
        for i in 0..200u32 {
            slot += 600; // ~4 min apart; stays inside one 24 h bucket for the first cycles
            let up = i % 2 == 0;
            let next = if up { cap * 102 / 100 } else { cap * 100 / 102 };
            if grief && up { let k = 100 * cap; fin += k; fout += k; }
            cap = next;
            st = nav_sample(&st, cap, fin, fout, slot);
            if lp_stop_triggered(&st) { return (true, i); }
        }
        (false, 200)
    };
    assert_eq!(run(false).0, false, "honest control: flat NAV never stops");
    let (fired, at) = run(true);
    assert!(fired, "diluted gains + full losses should false-trip");
    eprintln!("B1 false trip after {at} samples with flat real NAV");
}

/// C1 (BROKEN, pre-existing; severity LOW, needs a >=48 h sampling gap, e.g. a dead keeper):
// C1 (2-day gap launders the peak) is FIXED: see tests/onchain_1030_nav_attacks.rs::c1_*.
// A1 / B1 below pin the behaviour of the SINGLE-SAMPLE function `nav_sample` (unchanged by #636).
// The on-chain fix (#636) is that the flow handlers 96/97/98/103 sample the NAV AT the flow
// (`nav_sample_at_flow`), so a flow no longer lands inside an unsampled interval: see
// tests/nav636_flow_sample.rs and `navcheck_636_*` / `lev_w1_a1_*_636` in tests/p3_vault_lp.rs.

/// W1 (held, by design): a wiped LP that is refilled stays triggered until op 5 acknowledges --
/// no number of pokes/deposits/gains clears it. Documents the stale-latch exposure window.
#[test]
fn w1_wipe_then_refill_stays_latched_until_op5() {
    let st = nav_epoch_start(1_000, 0, 0, 0);
    let w = nav_sample(&st, 0, 0, 0, 5);
    assert!(lp_stop_triggered(&w));
    let mut s = w;
    let (mut fin, mut slot) = (0u128, 5u64);
    for i in 0..50u128 {
        slot += SLOTS_PER_DAY / 2;
        fin += 10_000_000;
        s = nav_sample(&s, 10_000_000 * (i + 1) * 2, fin, 0, slot); // deposits AND gains
        assert!(lp_stop_triggered(&s), "latched through refill at sample {i}");
    }
    // op 5 ack then clears it (navps 0 -> uninitialised -> fresh epoch)
    let ack = nav_stop_reset(&s);
    assert!(!lp_stop_triggered(&ack));
    let fresh = nav_sample(&ack, 10_000_000, fin, 0, slot + 1);
    assert_eq!(fresh.navps, NAV_ONE);
}

/// E1 (held): extremes. index at MAX with each flow shape; dust base; same-slot repeated samples.
#[test]
fn e1_extremes_and_same_slot_samples_hold() {
    let mut r = Rng(7);
    for _ in 0..200_000 {
        let navps = if r.next() % 3 == 0 { u128::MAX - (r.next() % 3) as u128 } else { r.mag(128).max(1) };
        let last = r.mag(128);
        let st = NavState { navps, last_equity: last, last_in: 0, last_out: 0, peak_cur: navps, peak_prev: navps, ref_navps: navps, bucket_start: 0, last_slot: 5 };
        let (fi, fo, eq) = (r.mag(128), r.mag(128), r.mag(128));
        let a = nav_sample(&st, eq, fi, fo, 5); // same slot
        let b = nav_sample(&a, eq, fi, fo, 5); // repeated sample, no change
        if a.last_equity != 0 && a.navps != 0 { assert_eq!(a.navps, b.navps, "idempotent same-slot resample"); }
        let _ = lp_stop_triggered(&a);
    }
    // dust: 1-atom base, a 1-atom loss is a wipe (index 0): documented, fires -- needs W1 net>target to bite
    let st = nav_epoch_start(1, 0, 0, 0);
    assert!(lp_stop_triggered(&nav_sample(&st, 0, 0, 0, 1)));
}
