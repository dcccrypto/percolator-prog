//! #636 (A1 / B1): the NAV sample taken AT a flow (`nav_sample_at_flow`), pure-function level.
//! The handler-level (on-chain) tests live in `tests/p3_vault_lp.rs` (`lev_w1` module).
use percolator_prog::lev_guard_v22::*;

const L: u128 = 1_000_000_000;

/// A tiny model of an LP the handlers sample: equity moves by P&L (`pnl`) and by flows
/// (`deposit` / `withdraw`, each sampled at the flow like the handlers do).
struct Lp {
    st: NavState,
    eq: u128,
    fin: u128,
    fout: u128,
    slot: u64,
}
impl Lp {
    fn new(eq: u128) -> Self {
        Lp { st: nav_epoch_start(eq, 0, 0, 0), eq, fin: 0, fout: 0, slot: 0 }
    }
    fn tick(&mut self) {
        self.slot += 600;
    }
    fn pnl(&mut self, new_eq: u128) {
        self.eq = new_eq;
    }
    /// A flow handler: samples before, moves value, samples after.
    fn deposit(&mut self, k: u128) {
        let before = (self.fin, self.fout);
        self.eq += k;
        self.fin += k;
        self.st = nav_sample_at_flow(&self.st, before, (self.eq, self.fin, self.fout), self.slot);
    }
    fn withdraw(&mut self, k: u128) {
        let before = (self.fin, self.fout);
        self.eq -= k;
        self.fout += k;
        self.st = nav_sample_at_flow(&self.st, before, (self.eq, self.fin, self.fout), self.slot);
    }
    /// The keeper's poke (tag 124 op 4).
    fn poke(&mut self) {
        self.st = nav_sample(&self.st, self.eq, self.fin, self.fout, self.slot);
    }
}

/// A1: a 60 % loss, then a huge inflow BEFORE anyone sampled. One end-of-interval sample reads the
/// loss against the inflow's base (-0.0001 %); the sample at the flow reads it in full and the
/// stop holds. Negative control: the single-sample reading of the same events does not trip.
#[test]
fn a1_loss_then_inflow_trips_at_the_flow_and_masks_without_it() {
    let x = 1_000_000 * L;
    // without the flow sample (the old behaviour, what the poke alone sees)
    let st = nav_epoch_start(L, 0, 0, 0);
    let masked = nav_sample(&st, 4 * L / 10 + x, x, 0, 10);
    assert!(!lp_stop_triggered(&masked), "negative control: one sample masks the loss");
    // with the flow sample
    let mut lp = Lp::new(L);
    lp.tick();
    lp.pnl(4 * L / 10);
    lp.deposit(x);
    assert!(lp_stop_triggered(&lp.st), "the loss is seen at the flow: navps {}", lp.st.navps);
    assert_eq!(lp.st.navps, NAV_ONE * 4 / 10);
    // the inflow leaving again is a pure flow: the index stays where the loss put it
    lp.tick();
    lp.withdraw(x);
    assert_eq!(lp.st.navps, NAV_ONE * 4 / 10);
    lp.tick();
    lp.poke();
    assert_eq!(lp.st.navps, NAV_ONE * 4 / 10);
}

/// A1 with the loss AFTER the flow: the flow is a pure flow, the later loss is read against the
/// post-flow baseline in full (F1 case: a routine inflow, then a small loss, is a SMALL loss).
#[test]
fn f1_inflow_then_small_loss_reads_small_and_a_real_loss_reads_real() {
    let mut lp = Lp::new(L);
    lp.tick();
    lp.deposit(9 * L); // 10 L now
    assert_eq!(lp.st.navps, NAV_ONE, "a flow alone moves nothing");
    lp.tick();
    lp.pnl(10 * L - 6 * L / 10); // lose 0.6 L = 6 % of the post-flow equity
    lp.poke();
    assert!(!lp_stop_triggered(&lp.st));
    assert_eq!(lp.st.navps, NAV_ONE * 94 / 100);
    lp.tick();
    lp.pnl(4 * L); // 60 % down from 10 L
    lp.poke();
    assert!(lp_stop_triggered(&lp.st));
}

/// Pure flows (any amounts, any order, any number) never move the index or the peaks.
#[test]
fn pure_flows_are_neutral() {
    let mut lp = Lp::new(5 * L);
    let ref0 = lp.st;
    let mut x = 0x1234_5678u64;
    for _ in 0..500 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        lp.tick();
        let k = (x % 1_000_000) as u128 * L / 1000 + 1;
        if x % 2 == 0 || lp.eq <= k {
            lp.deposit(k);
        } else {
            lp.withdraw(k);
        }
    }
    assert_eq!(lp.st.navps, ref0.navps);
    assert_eq!(lp.st.peak(), ref0.peak());
    assert_eq!(lp.st.ref_navps, ref0.ref_navps);
    assert!(!lp_stop_triggered(&lp.st));
}

/// Whatever the handler did to the equity beyond the flow (a fee, a realised loss) is P&L BEFORE the
/// flow and is read in full, never against the flow's base: a deposit of 100 that also realises a
/// 20 loss (equity 1,000 -> 1,080) reads as a 2 % loss on 1,000, not 1.8 % on 1,100.
#[test]
fn equity_change_inside_the_handler_reads_as_pnl_before_the_flow() {
    let st = nav_epoch_start(1_000, 0, 0, 0);
    let n = nav_sample_at_flow(&st, (0, 0), (1_080, 100, 0), 5);
    assert_eq!(n.navps, NAV_ONE * 98 / 100);
    assert_eq!(n.last_equity, 1_080);
    // a handler that moves nothing is a plain sample
    let plain = nav_sample(&st, 900, 0, 0, 5);
    let same = nav_sample_at_flow(&st, (0, 0), (900, 0, 0), 5);
    assert_eq!(plain, same);
}

/// B1, honestly: sampling at the flow does NOT remove the volatility drag of a flow that brackets
/// every gain, because that capital really was in the LP for the gain (a time-weighted index
/// charges the gain to all capital present). Pinned with the numbers so nobody reads this fix as a
/// B1 fix. The attacker needs the junior-owner path (97 needs a flat book) and large capital.
#[test]
fn b1_is_not_a_timing_problem_residual_drag_pinned() {
    let run = |k_mult: u128| -> Option<u32> {
        let mut lp = Lp::new(10 * L);
        let mut cap = 10 * L;
        for i in 0..400u32 {
            lp.tick();
            let up = i % 2 == 0;
            if up {
                let k = k_mult * cap;
                lp.deposit(k); // the flow lands before the gain
                cap = cap * 102 / 100;
                lp.pnl(cap + k); // the flow capital earns nothing, the pool's P&L is +2 % of cap
                lp.tick();
                lp.withdraw(k);
            } else {
                cap = cap * 100 / 102;
                lp.pnl(cap);
            }
            lp.tick();
            lp.poke();
            if lp_stop_triggered(&lp.st) {
                return Some(i);
            }
        }
        None
    };
    assert_eq!(run(0), None, "honest control: flat NAV never stops");
    // k = 100 x: still drags (pinned: residual, see the report); a small k drags far less
    let at = run(100);
    eprintln!("B1 residual (flows bracketing every gain, k = 100 x equity): false trip at cycle {at:?}; k = 2 x: {:?}", run(2));
    assert!(at.is_some(), "residual B1: a flow bracketing every gain still dilutes it");
}

/// Attack pass (self): random event sequences of P&L moves, deposits and withdrawals, each flow
/// sampled by the handler model and a poke now and then. The index must equal the exact
/// time-weighted return (chain of sub-period returns, flows at the boundaries, an f64 reference)
/// whatever the order, sizes and sampling of the flows: no placement of a flow can mask a loss
/// or dilute a gain any more.
#[test]
fn random_sequences_match_the_exact_time_weighted_return() {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for case in 0..3_000u32 {
        let mut lp = Lp::new(1_000_000 * L / 1_000_000 + 10 * L);
        let mut twr = 1.0f64;
        let mut base = lp.eq as f64; // equity at the last boundary (post-flow)
        for _ in 0..40 {
            lp.tick();
            match next() % 4 {
                0 | 1 => {
                    // P&L: equity * (0.5 .. 1.5), never to 0
                    let f = 0.5 + (next() % 1000) as f64 / 1000.0;
                    let new_eq = ((lp.eq as f64) * f).max(1.0) as u128;
                    lp.pnl(new_eq);
                }
                2 => {
                    let k = 1 + (next() as u128 % (3 * lp.eq));
                    // sub-period ends at the flow: return = eq / base
                    twr *= lp.eq as f64 / base;
                    lp.deposit(k);
                    base = lp.eq as f64;
                }
                _ => {
                    if lp.eq > 2 {
                        let k = 1 + (next() as u128 % (lp.eq - 1));
                        twr *= lp.eq as f64 / base;
                        lp.withdraw(k);
                        base = lp.eq as f64;
                    }
                }
            }
            if next() % 3 == 0 {
                lp.poke();
                twr *= lp.eq as f64 / base;
                base = lp.eq as f64;
            }
            if lp.st.navps == 0 || lp.eq < 1_000 {
                break; // wiped / dust: out of the reference's float range
            }
            let got = lp.st.navps as f64 / NAV_ONE as f64;
            let rel = ((got - twr) / twr).abs();
            assert!(rel < 1e-6, "case {case}: index {got} vs time-weighted {twr}");
        }
    }
}
