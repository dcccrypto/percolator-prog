//! Independent adversarial review of prog #630 (the GH#627 gross-reading cap on the LP-stop NAV
//! index), 2026-10-29. Pure-function level: the real `nav_sample` / `lp_stop_triggered` /
//! `mul_div_floor_sat` from `percolator_prog::lev_guard_v22`, no harness.
//!
//! What is attacked: rounding and overflow at the extremes, zero / dust equity, the first deposit,
//! flows sandwiched around a sample, many flows between two samples, repeated small cycles, and
//! griefing that keeps a real profit from being credited. And the property the stop exists for:
//! a real loss must trigger it.
//!
//! Tests named `residual_*` PIN a behaviour that is known and accepted for rc23 (it can only be
//! removed by sampling the NAV at every flow, v2.3). They assert the CURRENT numbers on purpose,
//! so the day the flow-sampling lands they fail and get rewritten, instead of the gap being
//! forgotten.

use percolator_prog::lev_guard_v22::{
    lp_stop_triggered, mul_div_floor_sat, nav_epoch_start, nav_sample, nav_scale, nav_stop_reset, NavState,
    NAV_ONE, SLOTS_PER_DAY,
};

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn u128(&mut self) -> u128 {
        ((self.next() as u128) << 64) | self.next() as u128
    }
    /// log-uniform-ish in [0, 2^bits): dust, mid and huge magnitudes all show up.
    fn mag(&mut self, bits: u32) -> u128 {
        let b = (self.next() % (bits as u64 + 1)) as u32;
        if b == 0 {
            return 0;
        }
        let v = self.u128();
        if b >= 128 { v } else { v & ((1u128 << b) - 1) }
    }
}

/// Exact `floor(a·b/d)` in 256 bits (schoolbook multiply, shift-subtract divide); `None` when the
/// quotient does not fit in u128.
fn muldiv_exact(a: u128, b: u128, d: u128) -> Option<u128> {
    assert!(d != 0);
    let (a1, a0) = (a >> 64, a & u64::MAX as u128);
    let (b1, b0) = (b >> 64, b & u64::MAX as u128);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & u64::MAX as u128) + (p10 & u64::MAX as u128);
    let lo = (p00 & u64::MAX as u128) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    if hi >= d {
        return None; // quotient >= 2^128
    }
    // 256 / 128 long division, one bit at a time (hi < d keeps the remainder < 2^129).
    let (mut rem, mut q) = (hi, 0u128);
    for i in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> i) & 1);
        q <<= 1;
        if carry == 1 || rem >= d {
            rem = rem.wrapping_sub(d);
            q |= 1;
        }
    }
    Some(q)
}

/// The rc23 reading before #630 (F1 alone), as the reference the cap is compared against.
fn f1_reading(st: &NavState, equity: u128, flow_in: u128, flow_out: u128) -> u128 {
    let din = flow_in - st.last_in;
    let dout = flow_out - st.last_out;
    let econ = equity.saturating_add(dout).saturating_sub(din);
    let mut navps = nav_scale(st.navps, econ, st.last_equity);
    if din != 0 || dout != 0 {
        let base = st.last_equity.saturating_add(din).saturating_sub(dout);
        if base != 0 {
            let start = nav_scale(st.navps, equity, base);
            if start > navps {
                navps = start;
            }
        }
    }
    navps
}

fn state(navps: u128, last: u128, lin: u128, lout: u128) -> NavState {
    NavState {
        navps,
        last_equity: last,
        last_in: lin,
        last_out: lout,
        peak_cur: navps,
        peak_prev: navps,
        bucket_start: 0,
        ref_navps: navps,
        last_slot: 0,
    }
}

// ── 1. arithmetic: rounding and overflow at the extremes ──────────────────────────────────────

/// `mul_div_floor_sat` is EXACT (or saturates only when the true quotient does not fit) whenever
/// the multiplier and divisor fit in u64 -- which every NAV input does: equity is engine capital
/// backed by an SPL vault (u64), and a counter delta within one interval cannot pass 2^64 atoms
/// without 2^64 atoms of flow in one interval. The index itself (`a`) is the full u128 range.
#[test]
fn muldiv_is_exact_for_u64_operands_and_any_index() {
    let mut r = Rng(0xA5A5_1234_DEAD_BEEF);
    let edges = [0u128, 1, 2, 3, NAV_ONE - 1, NAV_ONE, NAV_ONE + 1, u64::MAX as u128 - 1, u64::MAX as u128];
    let mut cases = 0u64;
    for i in 0..400_000u64 {
        let a = if i % 7 == 0 { u128::MAX - (r.next() % 3) as u128 } else { r.mag(128) };
        let b = if i % 5 == 0 { edges[(r.next() % edges.len() as u64) as usize] } else { r.mag(64) };
        let mut d = if i % 3 == 0 { edges[(r.next() % edges.len() as u64) as usize] } else { r.mag(64) };
        if d == 0 {
            d = 1;
        }
        let got = mul_div_floor_sat(a, b, d);
        match muldiv_exact(a, b, d) {
            Some(q) => assert_eq!(got, q, "a {a} b {b} d {d}"),
            None => assert_eq!(got, u128::MAX, "a {a} b {b} d {d}: true quotient >= 2^128"),
        }
        cases += 1;
    }
    assert_eq!(cases, 400_000);
}

/// Latent, not reachable through the NAV: with BOTH the multiplier and the divisor above 2^64 the
/// low term `(a % d)·b` can overflow and the function returns `u128::MAX` for a quotient that
/// fits. Pinned so nobody feeds it u128-sized operands believing it is exact there.
#[test]
fn muldiv_overestimates_only_with_operands_beyond_u64() {
    let d = (1u128 << 100) + 1;
    let b = 1u128 << 100;
    let a = d - 1; // a < d, so the true quotient is < b < 2^128
    let exact = muldiv_exact(a, b, d).expect("fits");
    assert!(exact < b);
    assert_eq!(mul_div_floor_sat(a, b, d), u128::MAX, "saturates although the quotient fits");
}

/// `nav_sample` is total at the extremes (no panic for any u128 input, including counters that
/// went backwards and a saturated index), and within the realistic range (u64 equity and flow
/// deltas, any index) every #630 invariant holds exactly: I1 flow neutrality, I2 a gain never
/// above the gross reading nor the no-flow reading, I3 a loss reads F1 exactly, I4 no flow reads
/// F1, I5 monotone in equity, I6 a gain never reads below the start.
#[test]
fn nav_sample_is_total_and_keeps_every_invariant_at_the_extremes() {
    let mut r = Rng(0x0BAD_F00D_CAFE_0001);
    let idx_edges = [1u128, 2, 3, 7, NAV_ONE / 2, NAV_ONE, 1u128 << 64, 1u128 << 100, u128::MAX / 2, u128::MAX - 1, u128::MAX];
    let amt_edges = [0u128, 1, 2, 3, 999, 1_000, 1_000_000, NAV_ONE, u64::MAX as u128 / 2, u64::MAX as u128 - 1, u64::MAX as u128];
    let pick = |r: &mut Rng, e: &[u128]| e[(r.next() % e.len() as u64) as usize];
    let mut gains_capped = 0u64;
    for i in 0..300_000u64 {
        // totality: arbitrary u128 everywhere, including backwards counters
        if i % 10 == 0 {
            let st = state(r.u128(), r.u128(), r.u128(), r.u128());
            let _ = nav_sample(&st, r.u128(), r.u128(), r.u128(), r.next());
            continue;
        }
        let navps = if i % 3 == 0 { pick(&mut r, &idx_edges) } else { 1 + r.mag(127) };
        let last = if i % 4 == 0 { pick(&mut r, &amt_edges).max(1) } else { 1 + r.mag(63) };
        let (lin, lout) = (r.mag(100), r.mag(100));
        let st = state(navps, last, lin, lout);
        let kind = r.next() % 4;
        let din = if kind & 1 == 1 { if i % 5 == 0 { pick(&mut r, &amt_edges) } else { r.mag(64) } } else { 0 };
        let dout = if kind & 2 == 2 { r.mag(64) % (last + din + 1) } else { 0 };
        let cap = last + din - dout;
        let gain = r.next() % 2 == 0;
        let equity = if gain {
            cap + (r.mag(64) % (u64::MAX as u128 - cap.min(u64::MAX as u128) + 1))
        } else {
            cap - r.mag(64) % (cap + 1)
        };
        let n = nav_sample(&st, equity, lin + din, lout + dout, 10);
        // Realistic range only (u64 operand sums; see `muldiv_overestimates_only_with_operands_
        // beyond_u64` for what happens past it): the index itself is still any u128.
        if last + din > u64::MAX as u128 || equity + dout > u64::MAX as u128 {
            continue;
        }
        let f1 = f1_reading(&st, equity, lin + din, lout + dout);
        let pnl_pos = equity > cap;
        let gross = nav_scale(navps, equity + dout, last + din);
        if equity == cap {
            assert_eq!(n.navps, navps, "I1 case {i}");
        }
        if pnl_pos {
            assert!(n.navps <= gross, "I2 gross case {i}");
            assert!(n.navps <= nav_scale(navps, last + (equity - cap), last), "I2 no-flow case {i}");
            assert!(n.navps >= navps, "I6 case {i}");
            if n.navps < f1 {
                gains_capped += 1;
            }
        } else {
            assert_eq!(n.navps, f1, "I3 case {i}");
        }
        if din == 0 && dout == 0 {
            assert_eq!(n.navps, f1, "I4 case {i}");
        }
        if equity < u128::MAX {
            let m = nav_sample(&st, equity + 1, lin + din, lout + dout, 10).navps;
            assert!(m >= n.navps, "I5 case {i}: navps {navps} last {last} din {din} dout {dout} eq {equity}: {} -> {m}; f1 {f1} gross {gross}", n.navps);
        }
    }
    assert!(gains_capped > 10_000, "the capped branch must be exercised: {gains_capped}");
}

/// A saturated or near-saturated index: a gain stays at `u128::MAX` (never wraps), a loss reads
/// lower, and a pure flow is exact. Saturation is the only non-exact case and it is upward-only.
#[test]
fn a_saturated_index_never_wraps_and_still_reads_losses() {
    for navps in [u128::MAX, u128::MAX - 1, u128::MAX / 2 + 1] {
        let st = state(navps, 1_000_000, 0, 0);
        assert_eq!(nav_sample(&st, 2_000_000, 0, 0, 1).navps, u128::MAX, "gain saturates, no wrap");
        let loss = nav_sample(&st, 400_000, 0, 0, 1);
        assert!(loss.navps < navps / 2 && lp_stop_triggered(&loss), "a 60 % loss reads and fires");
        assert_eq!(nav_sample(&st, 1_500_000, 500_000, 0, 1).navps, navps, "pure flow exact");
    }
}

// ── 2. many flows between samples, splitting, sandwiching ────────────────────────────────────

/// However a FIXED interval P&L is split across any number of deposits / withdrawals, in any
/// order, and however the flows are sandwiched around it, one sample can never credit more than
/// the no-flow reading `(L + P) / L`. 20k random multi-flow intervals per L, L from 1 atom up.
#[test]
fn no_split_or_order_of_flows_credits_more_than_the_no_flow_gain() {
    let mut r = Rng(0x5EED_0000_0000_0630);
    for &l in &[1u128, 2, 10, 1_000, 1_000_000, 1_000_000_000_000] {
        let quiet_st = nav_epoch_start(l, 0, 0, 0);
        for _ in 0..20_000 {
            let p = 1 + r.mag(40); // the interval's real P&L
            let no_flow = nav_sample(&quiet_st, l + p, 0, 0, 1).navps;
            // walk a random path of k flows; the P&L lands somewhere along it
            let k = 1 + r.next() % 40;
            let p_at = r.next() % (k + 1);
            let (mut cap, mut fin, mut fout) = (l, 0u128, 0u128);
            for j in 0..k {
                if j == p_at {
                    cap += p;
                }
                if r.next() % 2 == 0 {
                    let x = r.mag(45);
                    cap += x;
                    fin += x;
                } else {
                    let x = r.mag(45) % (cap + 1);
                    cap -= x;
                    fout += x;
                }
            }
            if p_at == k {
                cap += p;
            }
            let n = nav_sample(&quiet_st, cap, fin, fout, 1);
            assert!(n.navps <= no_flow, "L {l} P {p}: {} > no-flow {no_flow}", n.navps);
            assert!(n.navps >= NAV_ONE, "a gain never reads as a loss");
        }
    }
}

/// Repeated tiny cycles: 100k samples alternating a 1-atom gain and a 1-atom loss on a $1k LP,
/// with a deposit / withdrawal cycle in between. Floor rounding drifts the index down by at most
/// one unit (1e-12) per sample, so it can never manufacture a stop: 5e11 samples would be needed.
#[test]
fn many_small_cycles_drift_at_most_one_unit_per_sample() {
    let e = 1_000_000_000u128; // $1k at 6 decimals
    let mut st = nav_epoch_start(e, 0, 0, 0);
    let (mut fin, mut fout) = (0u128, 0u128);
    let mut cap = e;
    let mut samples = 0u128;
    for k in 0..100_000u64 {
        if k % 3 == 0 {
            fin += 777;
            cap += 777;
        } else if k % 3 == 1 {
            fout += 777;
            cap -= 777;
        }
        cap = if k % 2 == 0 { cap + 1 } else { cap - 1 };
        st = nav_sample(&st, cap, fin, fout, k);
        samples += 1;
    }
    assert!(st.navps <= NAV_ONE, "no gain created by rounding");
    assert!(NAV_ONE - st.navps <= samples, "drift {} > one unit per sample", NAV_ONE - st.navps);
    assert!(!lp_stop_triggered(&st));
}

// ── 3. zero / dust equity and the first deposit ──────────────────────────────────────────────

/// The guard can be bound before the LP has capital (epoch at 1.0 on zero equity). The first
/// deposit -- and a first deposit that lands together with a gain -- restarts the epoch at 1.0:
/// nothing is credited from a zero base, and no stop can be read off it.
#[test]
fn first_deposit_restarts_cleanly_from_zero_equity() {
    let st = nav_epoch_start(0, 0, 0, 0);
    for (eq, fin) in [(10_000u128, 10_000u128), (10_500, 10_000), (1, 1), (9_000, 10_000)] {
        let n = nav_sample(&st, eq, fin, 0, 5);
        assert_eq!((n.navps, n.ref_navps, n.peak()), (NAV_ONE, NAV_ONE, NAV_ONE), "eq {eq} fin {fin}");
        assert_eq!(n.last_equity, eq);
        assert!(!lp_stop_triggered(&n));
    }
}

/// A dust LP with NO flows: the index is exact for every gain and loss (the cap never binds
/// without a flow), so a 1-atom LP doubling reads as a doubling and a halving fires.
#[test]
fn dust_lp_without_flows_reads_exactly() {
    let st = nav_epoch_start(1, 0, 0, 0);
    assert_eq!(nav_sample(&st, 2, 0, 0, 1).navps, 2 * NAV_ONE);
    let st = nav_epoch_start(2, 0, 0, 0);
    let h = nav_sample(&st, 1, 0, 0, 1);
    assert_eq!(h.navps, NAV_ONE / 2);
    assert!(lp_stop_triggered(&h));
}

// ── 4. a real loss must trigger the stop ─────────────────────────────────────────────────────

/// Any loss of at least half, with no flow, fires; from any index and any base.
#[test]
fn every_real_half_loss_without_flows_fires() {
    let mut r = Rng(0x1055_0000_0000_0001);
    for _ in 0..200_000 {
        let navps = 2 + r.mag(100);
        let last = 1 + r.mag(63);
        let st = state(navps, last, r.mag(60), r.mag(60));
        let eq = r.mag(63) % (last / 2 + 1); // <= half
        let n = nav_sample(&st, eq, st.last_in, st.last_out, 1);
        assert!(lp_stop_triggered(&n), "navps {navps} last {last} eq {eq} -> {}", n.navps);
    }
}

/// THE BUG (pre-#630, still on 686d98d0): an insolvent LP reads conservative equity 0, so the
/// sample stores NAV/share 0 -- the deepest stop there is. But `nav_sample` restarts the epoch at
/// 1.0 whenever the STORED index is 0 or the stored equity is 0, and op 5 samples before it
/// decides. So once op 4 (the keeper's routine poke, which D19 orders BEFORE W1) has sampled the
/// wipe, every op 5 re-samples, restarts the epoch, reads 1.0 and refuses (Custom 135): the stop
/// for a wiped LP can never open, and the next poke stores the restart, erasing it for good.
/// The same holds when the senior draw refills the LP before op 5 runs.
#[test]
fn a_wiped_lp_stays_stopped_until_acknowledged() {
    let e = 10_000_000_000u128; // $10k
    let st = nav_epoch_start(e, 0, 0, 0);
    // op 4 samples the wipe
    let poked = nav_sample(&st, 0, 0, 0, 10);
    assert_eq!(poked.navps, 0);
    assert!(lp_stop_triggered(&poked), "the poke itself reads the stop");
    // op 5 samples again before deciding: equity still 0, then after a senior draw refilled it
    for (eq, drawn) in [(0u128, 0u128), (0, 3_000_000_000), (5_000_000, 3_005_000_000)] {
        let at_op5 = nav_sample(&poked, eq, drawn, 0, 11);
        assert!(lp_stop_triggered(&at_op5), "eq {eq} drawn {drawn}: the wipe must still fire W1 ({})", at_op5.navps);
    }
    // a later poke does not erase it either
    let again = nav_sample(&nav_sample(&poked, 0, 0, 0, 20), 0, 0, 0, 30);
    assert!(lp_stop_triggered(&again), "a second poke must not erase a pending wipe");
    // once op 5 acknowledges (nav_stop_reset), the next sample starts a clean epoch at 1.0
    let acked = nav_stop_reset(&again);
    let fresh = nav_sample(&acked, 7_000_000_000, 7_000_000_000, 0, 40);
    assert_eq!((fresh.navps, fresh.ref_navps), (NAV_ONE, NAV_ONE));
    assert!(!lp_stop_triggered(&fresh));
}

/// Same root cause, the other restart condition: an interval whose outflow carried most of the
/// capital and whose P&L lost the rest leaves a TRIGGERED index with a stored equity of 0. The next
/// sample used to restart (stored equity 0) and drop the pending stop.
#[test]
fn a_triggered_index_on_zero_equity_is_not_erased_by_the_next_sample() {
    let e = 10_000u128;
    let st = nav_epoch_start(e, 0, 0, 0);
    // 4,000 recalled, the remaining 6,000 lost: econ = 0 + 4,000 = 4,000 -> NAV/share 0.4
    let n = nav_sample(&st, 0, 0, 4_000, 1);
    assert_eq!(n.last_equity, 0);
    assert!(lp_stop_triggered(&n), "0.4: triggered");
    let next = nav_sample(&n, 0, 0, 4_000, 2);
    assert!(lp_stop_triggered(&next), "the next sample must not erase the pending stop ({})", next.navps);
}

/// Not a stop to keep: an untriggered epoch on zero equity (everybody left at a healthy index)
/// still restarts at 1.0 on the next capital, exactly as before.
#[test]
fn an_untriggered_empty_pool_still_restarts() {
    let st = nav_epoch_start(10_000, 0, 0, 0);
    let emptied = nav_sample(&st, 0, 0, 10_000, 1); // full withdrawal: pure flow
    assert_eq!((emptied.navps, emptied.last_equity), (NAV_ONE, 0));
    assert!(!lp_stop_triggered(&emptied));
    let refill = nav_sample(&emptied, 3_000, 3_000, 10_000, 2);
    assert_eq!((refill.navps, refill.ref_navps, refill.last_equity), (NAV_ONE, NAV_ONE, 3_000));
}

// ── 5. residuals: what one sample per interval cannot tell apart (v2.3: sample at every flow) ──

/// Why no closed-form rule on (last, Δin, Δout, equity) can be exact: two histories with the SAME
/// inputs and different truths. A: the LP earns 10 % on its own 10k, then a 1M round trip passes
/// through. B: the 1M arrives first, the 1.01M earns the same 1k, then leaves. Truth A = 1.1,
/// truth B = 1.000990. F1 reads A (and so a round trip FROM DUST that withdraws the gain reads
/// ×P -- #627); #630 reads B (so a round trip can DILUTE an honest gain). Only a sample at the
/// flow knows which.
#[test]
fn residual_one_sample_cannot_tell_a_round_trip_before_from_after_the_gain() {
    let (l, k, p) = (10_000u128, 1_000_000u128, 1_000u128);
    let st = nav_epoch_start(l, 0, 0, 0);
    let n = nav_sample(&st, l + p, k, k, 1); // the same inputs for A and B
    let truth_a = NAV_ONE * (l + p) / l;
    let truth_b = NAV_ONE * (l + k + p) / (l + k);
    assert_eq!(f1_reading(&st, l + p, k, k), truth_a, "F1 reads history A");
    assert_eq!(n.navps, truth_b, "#630 reads history B");
}

/// #630 residual (new): a balanced round trip in the same interval as a real gain dilutes the
/// gain toward 0, and tags 103 (allocate) / 98 (recall, flat LP only) are PERMISSIONLESS, so a
/// third party can do it in one transaction before the sample. The honest keeper ordering
/// (poke first) is exact; an adversary just does not poke first. Pinned numbers: a 10 % gain read
/// as 0.0999 % after a 100× round trip.
#[test]
fn residual_630_a_round_trip_dilutes_a_real_gain() {
    let l = 10_000_000_000u128;
    let p = l / 10;
    let st = nav_epoch_start(l, 0, 0, 0);
    let honest = nav_sample(&st, l + p, 0, 0, 1).navps;
    assert_eq!(honest, NAV_ONE * 11 / 10);
    let k = 100 * l;
    let griefed = nav_sample(&st, l + p, k, k, 1).navps;
    assert_eq!(griefed, mul_div_floor_sat(NAV_ONE, l + p + k, l + k));
    assert!(griefed < NAV_ONE + NAV_ONE / 1_000, "a 10 % gain read as < 0.1 %: {griefed}");
    assert_eq!(f1_reading(&st, l + p, k, k), honest, "F1 alone was exact here");
}

/// What the dilution can be turned into: a FALSE W1 trip on the D-i reference arm. Honest
/// path: the LP doubles over a week, then gives back half over the next week (slow, so the
/// 24-48 h peak arm never sees 50 %): NAV/share ends at 1.0 = the reference, no stop. Griefed
/// path: every gain sample is diluted by a 100× round trip. Over a week up and eight days down
/// the honest index ends ~9 % below the reference (no stop); the griefed one ends below half of
/// it and op 5 (permissionless) force-cuts every user opposite the LP.
#[test]
fn residual_630_diluted_gains_turn_a_round_trip_to_breakeven_into_a_stop() {
    let l0 = 10_000_000_000u128;
    let run = |grief: bool| -> NavState {
        let mut st = nav_epoch_start(l0, 0, 0, 0);
        let (mut fin, mut fout) = (0u128, 0u128);
        let mut cap = l0;
        let mut slot = 0u64;
        // 7 days up: ×2^(1/7) per day; 7 days down: ×2^(-1/7) per day (rounded per step)
        for day in 0..15u32 {
            slot += SLOTS_PER_DAY / 2;
            let next = if day < 7 { cap * 110_409 / 100_000 } else { cap * 100_000 / 110_409 };
            if grief && next > cap {
                let k = 100 * cap;
                fin += k;
                fout += k;
            }
            cap = next;
            st = nav_sample(&st, cap, fin, fout, slot);
            slot += SLOTS_PER_DAY / 2;
            st = nav_sample(&st, cap, fin, fout, slot); // a quiet keeper poke
        }
        st
    };
    let honest = run(false);
    let griefed = run(true);
    eprintln!("honest navps {} ref {}; griefed navps {} ref {}", honest.navps, honest.ref_navps, griefed.navps, griefed.ref_navps);
    assert!(!lp_stop_triggered(&honest), "honest: ~0.906 of the reference, no stop");
    assert!(honest.navps > NAV_ONE * 90 / 100);
    assert!(lp_stop_triggered(&griefed), "griefed: the same LP reads ~0.5 of the reference");
}

/// Pre-existing F1 residual (night audit 2026-10-28, NOT changed by #630): a loss in the same
/// interval as an inflow is read on the larger base, without bound in the inflow. Tag 103 is
/// permissionless, so anyone can allocate senior capital into a losing (still solvent) LP and
/// sample in the same transaction: a 60 % loss on the junior's 10k reads as 40 % after a 5k
/// allocation (alpha 50 % of a 10k senior claim) and the stop does not open. Inflow needed to
/// hide a loss ℓ: X > L·(2ℓ − 1).
#[test]
fn residual_f1_an_inflow_before_the_sample_masks_a_real_loss() {
    let l = 10_000u128;
    let st = nav_epoch_start(l, 0, 0, 0);
    let truth = nav_sample(&st, 4_000, 0, 0, 1);
    assert!(lp_stop_triggered(&truth), "no flow: 0.4 fires");
    let masked = nav_sample(&st, 4_000 + 5_000, 5_000, 0, 1);
    assert_eq!(masked.navps, NAV_ONE * 9_000 / 15_000, "read as 0.6");
    assert!(!lp_stop_triggered(&masked), "the same 60 % loss is hidden by a 5k allocation");
    // the bound: X = L·(2ℓ − 1) = 2,000 is exactly the edge (0.5 still fires), 2,001 hides it
    assert!(lp_stop_triggered(&nav_sample(&st, 4_000 + 2_000, 2_000, 0, 1)));
    assert!(!lp_stop_triggered(&nav_sample(&st, 4_000 + 2_001, 2_001, 0, 1)));
}
