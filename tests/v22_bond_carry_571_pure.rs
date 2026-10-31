// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! GH#571 (2026-10-31): the CUMULATIVE ("carried-over") bond coupon, pure-function tests on the
//! PRODUCTION functions (`percolator_prog::bond_v20`).
//!
//! * `coupon_settle` / `coupon_pay_from_leg` / `bond_claims_after_redemption` laws at full width;
//! * explainV's sim (`~/wt-followup-1030/explainV/sim/sim571.py`, "E+B" row: 25k incumbents, 25k
//!   newcomer, 2-day quiet stretch, harvest 1,500 slots after the deposit) reproduced in atoms on
//!   the production integer functions: newcomer excess 0 and incumbents' loss 0 within rounding;
//! * newcomer / leaver fairness on RANDOM sequences of deposits, withdrawals, quiet gaps and
//!   (fat or dust) fee cranks against an independent per-holder reference model (each holder's
//!   claim compounds at the coupon rate over every settled interval; nobody ever reads `K / B`).
//!   No excess either way beyond the stated rounding bound.
//!
//! Negative controls: the mutants in `scripts/v22-bond-mutants.sh` (M571a..M571g) must make this
//! file FAIL.

use percolator_prog::bond_v20::*;
use proptest::prelude::*;

const Y: u64 = SLOTS_PER_YEAR as u64;
const SPL: u128 = u64::MAX as u128;

// ── Laws ──────────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    /// Settlement: closed forfeits only the interval (A kept); open never lowers A, never passes
    /// max(A, cap), and adds at most one interval's coupon on the full claim.
    #[test]
    fn settle_bounds(cb in 0u128..=SPL, a in 0u128..=SPL / 4, rate in 0u32..=2_000, dt in any::<u64>(), open in any::<bool>()) {
        let k = cb + a;
        let a2 = coupon_settle(cb, a, rate, dt, open, k).unwrap();
        if !open {
            prop_assert_eq!(a2, a);
        } else {
            let cap = coupon_arrears_cap(cb, rate).unwrap();
            prop_assert!(a2 >= a);
            prop_assert!(a2 <= a.max(cap));
            prop_assert!(a2 - a <= coupon_due(k, rate, dt).unwrap());
            // un-capped: exactly the interval's coupon on K
            if a + coupon_due(k, rate, dt).unwrap() <= cap {
                prop_assert_eq!(a2, a + coupon_due(k, rate, dt).unwrap());
            }
        }
    }

    /// Settlement is monotone in elapsed time (a later settlement never owes less).
    #[test]
    fn settle_monotone_in_time(cb in 0u128..=SPL, a in 0u128..=SPL / 4, rate in 0u32..=2_000, dt in any::<u64>(), e in any::<u64>()) {
        let k = cb + a;
        let x = coupon_settle(cb, a, rate, dt, true, k).unwrap();
        let y = coupon_settle(cb, a, rate, dt.saturating_add(e), true, k).unwrap();
        prop_assert!(y >= x);
    }

    /// The base never exceeds the bonds' value (M-1): an impaired layer accrues on the layer.
    #[test]
    fn settle_base_is_capped_by_the_layer(cb in 1u128..=SPL, a in 0u128..=SPL / 4, rate in 0u32..=2_000, dt in 0u64..=Y, layer in 0u128..=SPL) {
        let k = cb + a;
        let a2 = coupon_settle(cb, a, rate, dt, true, layer).unwrap();
        prop_assert!(a2 - a <= coupon_due(k.min(layer), rate, dt).unwrap());
    }

    /// Paying from a leg: conserves the leg, conserves the claim (coupon moves A -> C_b), never
    /// more than A, never more than half the leg (M-2).
    #[test]
    fn pay_from_leg_conserves(avail in any::<u128>(), a in any::<u128>()) {
        let (coupon, rest, a2) = coupon_pay_from_leg(avail, a);
        prop_assert_eq!(coupon + rest, avail);
        prop_assert_eq!(coupon + a2, a);
        prop_assert!(coupon <= avail / 2);
        prop_assert_eq!(coupon, a.min(avail / 2));
    }

    /// Redemption slices the full claim; remaining per-share claim never falls; the C_b slice is
    /// exactly the pre-#571 slice; C_b == 0 <=> B == 0 and B == 0 => A == 0 survive.
    #[test]
    fn redemption_slices_the_full_claim(cb in 1u128..=SPL, a0 in 0u128..=SPL / 4, b in 1u128..=SPL, sh_frac in 0u128..=1_000_000) {
        // domain: the claim fits the token supply, K <= u64::MAX (see the fn doc)
        let a = a0.min(SPL - cb);
        let sh = b / 1_000_000 * sh_frac + (b % 1_000_000) * sh_frac / 1_000_000;
        let (cb2, a2) = bond_claims_after_redemption(cb, a, sh, b).unwrap();
        let k = cb + a;
        let removed = k - (cb2 + a2);
        prop_assert_eq!(removed, bond_atoms_for_redemption(sh, b, k).unwrap(), "removed == whole payout");
        prop_assert_eq!(cb2, bond_claim_after_redemption(cb, sh, b).unwrap());
        prop_assert!(a2 <= a);
        if sh == b {
            prop_assert_eq!((cb2, a2), (0, 0));
        } else {
            prop_assert!(cb2 > 0, "C_b == 0 <=> B == 0");
            // (K - removed) / (B - sh) >= K / B, cross-multiplied in u128 is safe below 2^64 * 2^64?
            // use 256-bit compare via u128 halves:
            let lhs = mul(cb2 + a2, b);
            let rhs = mul(k, b - sh);
            prop_assert!(lhs >= rhs, "remaining holders never diluted");
        }
    }

    #[test]
    fn redemption_rejects_bad_inputs(cb in any::<u64>(), a in any::<u64>(), sh in any::<u64>(), b in any::<u64>()) {
        let r = bond_claims_after_redemption(cb as u128, a as u128, sh as u128, b as u128);
        if b == 0 || sh > b {
            prop_assert!(r.is_none());
        } else if cb as u128 + a as u128 <= SPL {
            prop_assert!(r.is_some());
        } else {
            // a claim above the token supply: fails closed exactly when sh * K overflows u128
            prop_assert_eq!(r.is_none(), (sh as u128).checked_mul(cb as u128 + a as u128).is_none());
        }
    }
}

/// Exact 256-bit product as (hi, lo) for ordering comparisons.
fn mul(a: u128, b: u128) -> (u128, u128) {
    let m = u64::MAX as u128;
    let (a0, a1, b0, b1) = (a & m, a >> 64, b & m, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & m) + (p10 & m);
    ((p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64)), (p00 & m) | ((mid & m) << 64))
}

// ── explainV's sim, in atoms, on the production functions ─────────────────────────────────

/// A pooled tranche driven ONLY through the production functions (what tags 78 / 108 / 110 do,
/// with the tranche whole and the gate open).
#[derive(Clone, Debug, Default)]
struct Pool {
    cb: u128,
    a: u128,
    b: u128,
    t0: u64,
    rate: u32,
}

impl Pool {
    fn k(&self) -> u128 {
        bond_claim_total(self.cb, self.a).unwrap()
    }
    /// `may_hold`: tags 78 / 110 hold the checkpoint on a sub-atom interval
    /// (`coupon_checkpoint_moves`); tag 108 always moves it.
    fn settle_h(&mut self, now: u64, may_hold: bool) {
        let k = self.k();
        let before = self.a;
        self.a = coupon_settle(self.cb, before, self.rate, now - self.t0, self.cb > 0, k).unwrap();
        let cap = coupon_arrears_cap(self.cb, self.rate).unwrap();
        if !may_hold || coupon_checkpoint_moves(self.cb > 0, before, self.a, cap) {
            self.t0 = now;
        }
    }
    fn settle(&mut self, now: u64) {
        self.settle_h(now, false)
    }
    /// tag 108 (settle, price at K, credit principal). Returns shares minted (0 = refused).
    fn deposit(&mut self, now: u64, amount: u128) -> u128 {
        self.settle(now);
        let m = bond_shares_for_deposit(amount, self.b, self.k()).unwrap();
        if m == 0 {
            return 0;
        }
        self.cb += amount;
        self.b += m;
        m
    }
    /// tag 78 with a leg of `leg` atoms. Returns the coupon credited.
    fn crank(&mut self, now: u64, leg: u128) -> u128 {
        self.settle_h(now, true);
        let (coupon, _rest, a2) = coupon_pay_from_leg(leg, self.a);
        self.cb += coupon;
        self.a = a2;
        coupon
    }
    /// tag 110 (settle, pay the whole-tranche value of `sh`, slice the full claim).
    fn redeem(&mut self, now: u64, sh: u128) -> u128 {
        self.settle_h(now, true);
        let pay = bond_atoms_for_redemption(sh, self.b, self.k()).unwrap();
        let (cb, a) = bond_claims_after_redemption(self.cb, self.a, sh, self.b).unwrap();
        self.cb = cb;
        self.a = a;
        self.b -= sh;
        pay
    }
    fn value_of(&self, sh: u128) -> u128 {
        bond_atoms_for_redemption(sh, self.b, self.k()).unwrap()
    }
}

/// explainV "E+B": incumbents C = 25,000 USDC, newcomer D, 8%/yr, quiet H = 432,000 slots, the
/// newcomer arrives at td = H - 1,500, harvest at H with a fat leg. sim571.py reports excess
/// 0.000 for the newcomer and 0.00 loss for the incumbents (rounded); in atoms both are within
/// the rounding bound (a few atoms), and the 1-atom grief no longer wipes anything.
#[test]
fn explainv_sim_reproduced_newcomer_neutral_in_atoms() {
    const USDC: u128 = 1_000_000;
    let h: u64 = 432_000;
    let td = h - 1_500;
    for d in [25_000 * USDC, 1, 5_000 * USDC, 100_000 * USDC] {
        let mut p = Pool { rate: 800, ..Default::default() };
        let inc = p.deposit(0, 25_000 * USDC);
        let new = p.deposit(td, d);
        let coupon = p.crank(h, 1_000_000 * USDC);
        assert_eq!(p.a, 0, "fat leg pays every carried atom");
        // continuous fair values (sim571.py's fair_old / fair_new), floor / ceil bracketing
        let r = 800f64 / 10_000f64 / Y as f64;
        let fair_inc = 25_000f64 * USDC as f64 * (1.0 + r * td as f64) * (1.0 + r * (h - td) as f64);
        let fair_new = d as f64 * (1.0 + r * (h - td) as f64);
        let (vi, vn) = (p.value_of(inc) as f64, p.value_of(new) as f64);
        eprintln!(
            "D={d}: coupon {coupon} incumbents {vi} (fair {fair_inc:.1}, diff {:.2}) newcomer {vn} (fair {fair_new:.2}, diff {:.2})",
            vi - fair_inc,
            vn - fair_new
        );
        assert!(vn <= fair_new + 1e-6, "newcomer takes nothing of the incumbents' accrual");
        assert!(vn >= fair_new - 3.0, "newcomer does not pay for it twice (within 3 atoms)");
        assert!(vi >= fair_inc - 3.0, "incumbents keep their accrual (within 3 atoms)");
        if d == 1 {
            // the grief deposit: 1 atom mints 0 shares at K/B > 1 and is refused outright
            assert_eq!(new, 0);
        }
    }
    // The old behaviour for comparison (not production any more): resetting the clock at td
    // would pay only 1,500 slots on 50k: ~ 0.076 USDC instead of ~ 10.96 + 0.08.
    let mut p = Pool { rate: 800, ..Default::default() };
    p.deposit(0, 25_000 * USDC);
    p.settle(td);
    assert!(p.a > 10_900_000 && p.a < 11_000_000, "2 days less 1,500 slots at 8% on 25k = 10.92 USDC, carried: {}", p.a);
}

// ── Random sequences vs an independent per-holder reference ──────────────────────────────

#[derive(Clone, Debug)]
enum Op {
    Wait(u64),
    Deposit(usize, u64),
    Crank(u64),
    Redeem(usize, u16),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u64..800_000).prop_map(Op::Wait),
        3 => (0usize..4, 1u64..=50_000_000_000).prop_map(|(h, x)| Op::Deposit(h, x)),
        2 => prop_oneof![Just(0u64), 1u64..=100, 1_000_000_000u64..=10_000_000_000].prop_map(Op::Crank),
        2 => (0usize..4, 1u16..=10_000).prop_map(|(h, f)| Op::Redeem(h, f)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// Every holder's realised value (payouts + remaining shares' value) equals its OWN claim
    /// compounded at the coupon rate over every interval it held (the reference never looks at
    /// the pool), within a rounding bound, in BOTH directions -- whatever the order of
    /// deposits, withdrawals, dust cranks and quiet gaps. Total time stays below the arrears cap.
    #[test]
    fn holders_get_exactly_their_own_accrual(ops in prop::collection::vec(op(), 1..40), rate in 1u32..=2_000) {
        let mut p = Pool { rate, ..Default::default() };
        let mut now = 0u64;
        let mut shares = [0u128; 4];
        let mut fair = [0f64; 4]; // reference claim of each holder (atoms, real-valued)
        let mut realised = [0f64; 4];
        let mut fair_paid = [0f64; 4];
        let mut rounding_ops = 0f64;
        let g = |dt: u64| 1.0 + rate as f64 / 10_000.0 * dt as f64 / Y as f64;
        let mut last = 0u64;
        // reference: every settlement compounds every holder's claim over (now - last)
        let settle_ref = |now: u64, fair: &mut [f64; 4], last: &mut u64| {
            let f = g(now - *last);
            for x in fair.iter_mut() { *x *= f; }
            *last = now;
        };
        for o in ops {
            match o {
                Op::Wait(dt) => now += dt,
                Op::Deposit(h, x) => {
                    settle_ref(now, &mut fair, &mut last);
                    let m = p.deposit(now, x as u128);
                    if m > 0 {
                        shares[h] += m;
                        fair[h] += x as f64;
                        realised[h] -= x as f64;
                        fair_paid[h] -= x as f64;
                    }
                    rounding_ops += 1.0;
                }
                Op::Crank(leg) => {
                    settle_ref(now, &mut fair, &mut last);
                    p.crank(now, leg as u128);
                    rounding_ops += 1.0;
                }
                Op::Redeem(h, frac) => {
                    if shares[h] == 0 { continue; }
                    settle_ref(now, &mut fair, &mut last);
                    let sh = shares[h] * frac as u128 / 10_000;
                    if sh == 0 { continue; }
                    let ref_out = fair[h] * sh as f64 / shares[h] as f64;
                    let pay = p.redeem(now, sh);
                    shares[h] -= sh;
                    fair[h] -= ref_out;
                    realised[h] += pay as f64;
                    fair_paid[h] += ref_out;
                    rounding_ops += 1.0;
                }
            }
            prop_assert!(now < Y / 2, "keep below the arrears cap");
            // conservation of the pool: the remaining holders' shares are exactly B
            prop_assert_eq!(shares.iter().sum::<u128>(), p.b);
            prop_assert!(p.b != 0 || (p.cb == 0 && p.a == 0));
        }
        settle_ref(now, &mut fair, &mut last);
        p.settle(now);
        for h in 0..4 {
            let held = if p.b == 0 { 0.0 } else { p.value_of(shares[h]) as f64 };
            let got = realised[h] + held;
            let want = fair_paid[h] + fair[h];
            let scale = fair[h].abs().max(fair_paid[h].abs()).max(1.0);
            // rounding: <= ~2 atoms per op (share mint floor at K/B <= 1.2, settlement floor,
            // redemption floor), plus f64 noise
            let tol = 2.0 * rounding_ops + 4.0 + scale * 1e-9;
            prop_assert!(got <= want + 1.0 + scale * 1e-9, "holder {} takes more than its own accrual: got {} want {}", h, got, want);
            prop_assert!(got >= want - tol, "holder {} loses accrual: got {} want {} tol {}", h, got, want, tol);
        }
    }

    /// The 1-atom grief and the dust-crank grief, on random sizes: the carried claim after either
    /// equals the untouched path's carried claim (the grief deposit is refused or mints at K/B;
    /// the dust crank pays at most half its leg and carries the rest).
    #[test]
    fn grief_paths_forfeit_nothing(c in 1_000_000u64..=50_000_000_000, quiet in 1u64..=1_000_000, rate in 1u32..=2_000, dust_leg in 0u64..=1_000) {
        let mut clean = Pool { rate, ..Default::default() };
        clean.deposit(0, c as u128);
        clean.settle(quiet);
        // grief 1: smallest deposit that mints, just before trading resumes
        let mut g1 = Pool { rate, ..Default::default() };
        let inc = g1.deposit(0, c as u128);
        let px = g1.k().div_ceil(g1.b).max(1); // atoms for one share at K/B, upper bound
        let m = g1.deposit(quiet, px + 1);
        prop_assert!(g1.value_of(inc) + 1 >= clean.k(), "incumbent keeps every accrued atom");
        let _ = m;
        // grief 2: a dust crank
        let mut g2 = Pool { rate, ..Default::default() };
        g2.deposit(0, c as u128);
        let paid = g2.crank(quiet, dust_leg as u128);
        prop_assert!(paid <= dust_leg as u128 / 2);
        prop_assert_eq!(g2.k(), clean.k(), "the claim survives the dust crank exactly");
    }
}

// ── Grinding and rounding direction ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A permissionless crank EVERY `step` slots (dust legs) on a small tranche cannot grind the
    /// coupon away: the checkpoint holds while an interval floors to 0, so the arrears after
    /// `n` cranks are within one atom per checkpoint move of the single-settlement accrual.
    /// Without the hold (every crank moves the checkpoint) a tranche whose per-step accrual is
    /// below one atom earns NOTHING.
    #[test]
    fn crank_every_slot_cannot_grind_the_coupon(c in 1_000u64..=400_000_000, rate in 1u32..=2_000, step in 1u64..=50, n in 1u64..=400) {
        let mut ground = Pool { rate, ..Default::default() };
        ground.deposit(0, c as u128);
        let mut moves = 0u128;
        for i in 1..=n {
            let t0 = ground.t0;
            ground.crank(i * step, 0);
            if ground.t0 != t0 { moves += 1; }
        }
        let mut once = Pool { rate, ..Default::default() };
        once.deposit(0, c as u128);
        once.crank(n * step, 0);
        // the unsettled tail since the held checkpoint is still owed (settled at the next point)
        ground.settle(n * step);
        prop_assert!(ground.a <= once.a + 1 + once.a / 1_000, "never more than compounding: {} vs {}", ground.a, once.a);
        prop_assert!(ground.a + moves + 1 >= once.a, "at most one atom lost per settlement that moves: {} + {} vs {}", ground.a, moves, once.a);
        // the checkpoint only moves on an interval worth >= 1 atom, and floor(x) >= x / 2 there:
        // the ground total is at least half the single-settlement accrual (the no-hold mutant
        // earns 0 and fails this whenever `once.a >= 2`)
        prop_assert!(moves <= ground.a, "moves {} only on >= 1 atom intervals (a {})", moves, ground.a);
        prop_assert!(2 * ground.a + 1 >= once.a, "grind: {} vs {}", ground.a, once.a);
    }

    /// Rounding is always against the actor: the 108 newcomer never receives shares worth more
    /// than it paid; the 110 leaver is never paid more than the claim it gives up, and the claim
    /// removed is at least the payout; the 78 coupon never exceeds A or half the leg; one
    /// settlement never credits more than the exact (real) accrual.
    #[test]
    fn rounding_is_against_the_actor(cb in 1u128..=SPL, a in 0u128..=SPL / 4, b in 1u128..=SPL, d in 1u128..=SPL, sh_frac in 0u128..=1_000_000, leg in any::<u64>(), rate in 0u32..=2_000, dt in 0u64..=Y) {
        let k = cb + a;
        // 108: m * K <= d * B (the newcomer pays at least K / B per share)
        let m = bond_shares_for_deposit(d, b, k).unwrap();
        prop_assert!(mul(m, k) <= mul(d, b));
        // 110: pay * B <= sh * K, removed claim >= pay
        let sh = b * sh_frac / 1_000_000;
        let pay = bond_atoms_for_redemption(sh, b, k).unwrap();
        prop_assert!(mul(pay, b) <= mul(sh, k));
        let (cb2, a2) = bond_claims_after_redemption(cb, a, sh, b).unwrap();
        prop_assert!(k - (cb2 + a2) >= pay);
        // 78
        let (coupon, rest, a3) = coupon_pay_from_leg(leg as u128, a);
        prop_assert!(coupon <= a && coupon <= leg as u128 / 2 && coupon + rest == leg as u128 && a3 == a - coupon);
        // settlement: accrued * D <= K * rate * dt (floor)
        let a4 = coupon_settle(cb, a, rate, dt, true, k).unwrap();
        prop_assert!(mul(a4 - a, 10_000 * SLOTS_PER_YEAR) <= mul(k, rate as u128 * dt as u128));
    }
}

/// The hold rule itself: moves unless (open, nothing accrued, below the cap).
#[test]
fn checkpoint_hold_rule() {
    assert!(coupon_checkpoint_moves(false, 5, 5, 100), "closed: always moves (forfeit)");
    assert!(coupon_checkpoint_moves(true, 5, 6, 100), "accrued: moves");
    assert!(!coupon_checkpoint_moves(true, 5, 5, 100), "open, floored to 0: holds");
    assert!(coupon_checkpoint_moves(true, 100, 100, 100), "at the cap: moves (accrual forfeited)");
}
