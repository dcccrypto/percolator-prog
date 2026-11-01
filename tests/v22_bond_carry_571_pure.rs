// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! GH#571 (2026-10-31, revised after att649): the CUMULATIVE ("carried-over") bond coupon,
//! pure-function tests on the PRODUCTION functions (`percolator_prog::bond_v20`).
//!
//! Model (I-T7): `K` = the bonds' whole claim (`c_b_atoms`), `R` = the coupon receivable the fee
//! legs still owe the junior (`coupon_arrears_atoms`), `U` = the per-share cap meter
//! (`coupon_unfunded_atoms`), `rem` = the carried sub-atom numerator.
//! * `coupon_settle` / `coupon_pay_from_leg` laws at full width, incl. the exact remainder carry
//!   (att649 F3: splitting an interval never loses an atom) and the cap on the funded claim;
//! * att649 F1: a deposit/redeem round trip leaves `R` untouched and cannot add cap headroom;
//! * explainV's sim ("E+B" row) reproduced in atoms: newcomer excess 0, incumbents' loss 0
//!   within rounding;
//! * newcomer / leaver fairness on RANDOM sequences against an independent per-holder reference.
//!
//! Negative controls: the mutants in `scripts/v22-bond-mutants.sh` (M571a..) must make this file
//! FAIL.

use percolator_prog::bond_v20::*;
use proptest::prelude::*;

const Y: u64 = SLOTS_PER_YEAR as u64;
const SPL: u128 = u64::MAX as u128;
const D: u128 = COUPON_DENOM;

// ── Laws ──────────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    /// Settlement: closed forfeits only the interval (nothing settled touched, rem kept); open adds
    /// `x = min(floor((min(K, value) * rate * dt' + rem) / D), cap - R)` with the exact remainder
    /// carried when the cap does not bind (dropped when it does). `r` is the cap meter `U` here.
    #[test]
    fn settle_bounds(k in 0u128..=SPL, r in 0u128..=SPL / 4, rem0 in 0u64..(D as u64), rate in 0u32..=2_000, dt in any::<u64>(), open in any::<bool>(), value in 0u128..=SPL) {
        let (x, rem) = coupon_settle(k, r, rem0, rate, dt, open, value).unwrap();
        if !open {
            prop_assert_eq!((x, rem), (0, rem0));
        } else {
            let dt1 = dt.min(Y) as u128;
            let num = k.min(value) * rate as u128 * dt1 + rem0 as u128;
            let room = coupon_arrears_cap(k.saturating_sub(r), rate).unwrap().saturating_sub(r);
            prop_assert!((rem as u128) < D);
            if num / D <= room {
                prop_assert_eq!(x, num / D);
                prop_assert_eq!(rem as u128, num % D);
            } else {
                prop_assert_eq!((x, rem), (room, 0));
            }
            prop_assert!(r + x <= r.max(coupon_arrears_cap(k.saturating_sub(r), rate).unwrap()), "capped");
        }
    }

    /// Settlement is monotone in elapsed time (a later settlement never owes less).
    #[test]
    fn settle_monotone_in_time(k in 0u128..=SPL, r in 0u128..=SPL / 4, rem0 in 0u64..(D as u64), rate in 0u32..=2_000, dt in any::<u64>(), e in any::<u64>()) {
        let (x, _) = coupon_settle(k, r, rem0, rate, dt, true, k).unwrap();
        let (y, _) = coupon_settle(k, r, rem0, rate, dt.saturating_add(e), true, k).unwrap();
        prop_assert!(y >= x);
    }

    /// att649 F3: settling an interval in TWO steps (carrying the remainder) yields exactly the
    /// one-step accrual on the same base, so a crank every slot loses nothing (the base is held
    /// fixed by the layer here; in production the base grows by the first step, which only adds).
    #[test]
    fn split_interval_loses_nothing(k in 1u128..=SPL, rate in 1u32..=2_000, d1 in 0u64..=Y / 2, d2 in 0u64..=Y / 2) {
        let (x1, rem1) = coupon_settle(k, 0, 0, rate, d1, true, k).unwrap();
        let (x2, rem2) = coupon_settle(k + x1, x1, rem1, rate, d2, true, k).unwrap();
        let (xo, remo) = coupon_settle(k, 0, 0, rate, d1 + d2, true, k).unwrap();
        // the cap (one year on K - R) never binds within one year on the funded claim k
        prop_assert_eq!((x1 + x2, rem2), (xo, remo));
    }

    /// The base never exceeds the bonds' value (M-1): an impaired layer accrues on the layer.
    #[test]
    fn settle_base_is_capped_by_the_layer(k in 1u128..=SPL, r in 0u128..=SPL / 4, rate in 0u32..=2_000, dt in 0u64..=Y, layer in 0u128..=SPL) {
        let (x, _) = coupon_settle(k, r, 0, rate, dt, true, layer).unwrap();
        prop_assert!(x <= coupon_due(k.min(layer), rate, dt).unwrap());
    }

    /// Paying from a leg: conserves the leg, lowers only the receivable (K is not an input: the
    /// claim is unchanged), never more than R, never more than half the leg (M-2).
    #[test]
    fn pay_from_leg_conserves(avail in any::<u128>(), r in any::<u128>()) {
        let (coupon, rest, r2) = coupon_pay_from_leg(avail, r);
        prop_assert_eq!(coupon + rest, avail);
        prop_assert_eq!(coupon + r2, r);
        prop_assert!(coupon <= avail / 2);
        prop_assert_eq!(coupon, r.min(avail / 2));
    }

    /// att649 F1 / F1b: a third party's deposit d followed by the redemption of exactly the minted
    /// shares (same slot) returns at most d, leaves the claim of everyone else at least where it
    /// was, never touches the receivable R (not an input of 108 / 110) and cannot add cap
    /// headroom beyond what the stayers' rounding gain itself earns: the per-share meter `U` is
    /// labelled in and sliced out at the pool ratio.
    #[test]
    fn round_trip_is_neutral(k in 1u128..=SPL / 4, u0 in 0u128..=SPL / 16, b0 in 1u128..=SPL / 4, d0 in 0u128..=SPL / 4, rate in 1u32..=2_000) {
        let u = u0.min(k);
        let b = 1 + (b0 - 1) % k; // reachable: shares mint at K/B >= 1 (par at genesis, K only grows per share)
        let d = d0 + k.div_ceil(b); // a deposit that mints (>= one share's price)
        let m = bond_shares_for_deposit(d, b, k).unwrap();
        prop_assert!(m > 0);
        let (k1, b1) = (k + d, b + m);
        let u1 = coupon_meter_after_deposit(u, k, d).unwrap();
        let pay = bond_atoms_for_redemption(m, b1, k1).unwrap();
        let k2 = bond_claim_after_redemption(k1, m, b1).unwrap();
        let u2 = coupon_meter_after_redemption(u1, m, b1).unwrap();
        prop_assert!(pay <= d, "the round-tripper gets back at most what it paid");
        prop_assert!(k2 >= k, "the others' claim is not diluted: {} vs {}", k2, k);
        // ... and gains only the round-tripper's own rounding (< one share's worth, K / B, plus 2)
        prop_assert!(k2 - k <= k / b + 2, "and gains only rounding: {} vs {}", k2, k);
        // the meter's per-share ratio is preserved against the actor: U2 / k2 >= U / k ...
        prop_assert!(mul(u2, k) >= mul(u, k2) || u2 + 1 >= u, "meter ratio not diluted");
        prop_assert!(u2 >= u, "the stayers' meter never drops: {} vs {}", u2, u);
        // ... so the headroom (one year on K - U, minus U) grows at most by the coupon on the
        // stayers' rounding gain (k2 - k), never by the round-tripper's money
        let room = |kk: u128, uu: u128| coupon_arrears_cap(kk.saturating_sub(uu), rate).unwrap().saturating_sub(uu);
        prop_assert!(room(k2, u2) <= room(k, u) + coupon_due(k2 - k, rate, Y).unwrap() + 1, "no cap reset");
    }

    /// Exits use the pre-#571 slice of K; the remaining holders are never diluted; a full exit
    /// empties K (the receivable R is untouched and outlives it).
    #[test]
    fn redemption_slices_k(k in 1u128..=SPL, b in 1u128..=SPL, sh_frac in 0u128..=1_000_000) {
        let sh = b / 1_000_000 * sh_frac + (b % 1_000_000) * sh_frac / 1_000_000;
        let k2 = bond_claim_after_redemption(k, sh, b).unwrap();
        let pay = bond_atoms_for_redemption(sh, b, k).unwrap();
        prop_assert_eq!(k - k2, pay, "removed == whole-tranche payout");
        if sh == b {
            prop_assert_eq!(k2, 0);
        } else {
            prop_assert!(k2 > 0, "K == 0 <=> B == 0");
            prop_assert!(mul(k2, b) >= mul(k, b - sh), "remaining holders never diluted");
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
    k: u128,
    r: u128,
    u: u128,
    rem: u64,
    b: u128,
    t0: u64,
    rate: u32,
}

impl Pool {
    fn k(&self) -> u128 {
        self.k
    }
    /// One settlement to `now` (every settlement moves the checkpoint; 108 drops the remainder).
    fn settle_z(&mut self, now: u64, zero_rem: bool) {
        let (x, rem) = coupon_settle(self.k, self.u, self.rem, self.rate, now - self.t0, self.k > 0, self.k).unwrap();
        self.k += x;
        self.r += x;
        self.u += x;
        self.rem = if zero_rem { 0 } else { rem };
        self.t0 = now;
    }
    fn settle(&mut self, now: u64) {
        self.settle_z(now, false)
    }
    /// tag 108 (settle, price at K, credit the claim). Returns shares minted (0 = refused, and
    /// a refused deposit reverts: nothing changes).
    fn deposit(&mut self, now: u64, amount: u128) -> u128 {
        let mut next = self.clone();
        next.settle_z(now, true);
        let m = bond_shares_for_deposit(amount, next.b, next.k).unwrap();
        if m == 0 {
            return 0;
        }
        next.u = coupon_meter_after_deposit(next.u, next.k, amount).unwrap();
        next.k += amount;
        next.b += m;
        *self = next;
        m
    }
    /// tag 78 with a leg of `leg` atoms. Returns the coupon paid to the junior's reimbursement.
    fn crank(&mut self, now: u64, leg: u128) -> u128 {
        self.settle(now);
        let (coupon, _rest, r2) = coupon_pay_from_leg(leg, self.r);
        self.r = r2;
        self.u = self.u.saturating_sub(coupon);
        coupon
    }
    /// tag 110 (settle, pay the whole-tranche value of `sh`, remove its slice of K; R untouched).
    fn redeem(&mut self, now: u64, sh: u128) -> u128 {
        self.settle(now);
        let pay = bond_atoms_for_redemption(sh, self.b, self.k).unwrap();
        self.k = bond_claim_after_redemption(self.k, sh, self.b).unwrap();
        self.u = coupon_meter_after_redemption(self.u, sh, self.b).unwrap();
        self.b -= sh;
        pay
    }
    fn value_of(&self, sh: u128) -> u128 {
        bond_atoms_for_redemption(sh, self.b, self.k).unwrap()
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
        assert_eq!(p.r, 0, "fat leg pays every receivable atom");
        let r = 800f64 / 10_000f64 / Y as f64;
        // compounding at td only if the deposit happened (a refused deposit reverts: no settlement)
        let fair_inc = if new == 0 {
            25_000f64 * USDC as f64 * (1.0 + r * h as f64)
        } else {
            25_000f64 * USDC as f64 * (1.0 + r * td as f64) * (1.0 + r * (h - td) as f64)
        };
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
    assert!(p.r > 10_900_000 && p.r < 11_000_000, "2 days less 1,500 slots at 8% on 25k = 10.92 USDC, carried: {}", p.r);
    assert_eq!(p.k, 25_000 * USDC + p.r, "the settled coupon is in the claim");
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
        let mut own_ops = [0f64; 4]; // ops by holder h (its own rounding goes to the others)
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
                    own_ops[h] += 1.0;
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
                    own_ops[h] += 1.0;
                }
            }
            prop_assert!(now < Y / 2, "keep below the arrears cap");
            // conservation of the pool: the remaining holders' shares are exactly B
            prop_assert_eq!(shares.iter().sum::<u128>(), p.b);
            prop_assert!(p.b != 0 || p.k == 0, "K == 0 <=> B == 0 (the receivable may outlive it)");
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
            // upward: rounding is against the ACTOR, so a holder can only gain the floor
            // remainders of OTHER holders' ops (a leaver's payout / slice floor and its forfeited
            // sub-atom held interval, a newcomer's mint floor), <= ~2 atoms per such op. The
            // tight +1 bound was wrong (CI run 41238512989 seed: a stayer got +1.996 after six
            // redemptions by others).
            let others = rounding_ops - own_ops[h];
            prop_assert!(got <= want + 1.0 + 2.0 * others + scale * 1e-9, "holder {} takes more than its own accrual: got {} want {} (others' ops {})", h, got, want, others);
            prop_assert!(got >= want - tol, "holder {} loses accrual: got {} want {} tol {}", h, got, want, tol);
        }
    }

    /// The 1-atom grief and the dust-crank grief, on random sizes: the claim after either equals
    /// the untouched path's claim (the grief deposit is refused or mints at K/B and drops only the
    /// incumbents' sub-atom; the dust crank pays at most half its leg and leaves K exactly).
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
        prop_assert_eq!(g2.r + paid, clean.r, "the unpaid rest is carried as receivable");
    }
}

// ── Grinding and rounding direction ──────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// att649 F3: a permissionless crank EVERY `step` slots (zero legs) cannot grind the coupon
    /// away, at ANY per-slot accrual (sub-atom, 1-2 atoms, many): the carried remainder makes `n`
    /// settlements earn at least the single settlement over the same span (and at most that plus
    /// the per-settlement compounding).
    #[test]
    fn crank_every_slot_cannot_grind_the_coupon(c in 1_000u64..=5_000_000_000, rate in 1u32..=2_000, step in 1u64..=50, n in 1u64..=400) {
        let mut ground = Pool { rate, ..Default::default() };
        ground.deposit(0, c as u128);
        for i in 1..=n {
            ground.crank(i * step, 0);
        }
        let mut once = Pool { rate, ..Default::default() };
        once.deposit(0, c as u128);
        once.crank(n * step, 0);
        prop_assert!(ground.r >= once.r, "no grind at all: {} vs {}", ground.r, once.r);
        prop_assert!(ground.r <= once.r + 1 + once.r / 1_000, "only compounding on top: {} vs {}", ground.r, once.r);
    }

    /// Rounding is always against the actor: the 108 newcomer never receives shares worth more
    /// than it paid; the 110 leaver is never paid more than the claim it gives up; the 78 coupon
    /// never exceeds R or half the leg; one settlement never credits more than the exact accrual
    /// plus the carried remainder.
    #[test]
    fn rounding_is_against_the_actor(k in 1u128..=SPL, r in 0u128..=SPL / 4, b in 1u128..=SPL, d in 1u128..=SPL, sh_frac in 0u128..=1_000_000, leg in any::<u64>(), rate in 0u32..=2_000, dt in 0u64..=Y, rem0 in 0u64..(D as u64)) {
        // 108: m * K <= d * B (the newcomer pays at least K / B per share)
        let m = bond_shares_for_deposit(d, b, k).unwrap();
        prop_assert!(mul(m, k) <= mul(d, b));
        // 110: pay * B <= sh * K, removed claim >= pay (K <= u64::MAX: the 110 helpers' domain)
        let sh = b * sh_frac / 1_000_000;
        let pay = bond_atoms_for_redemption(sh, b, k).unwrap();
        prop_assert!(mul(pay, b) <= mul(sh, k));
        prop_assert!(k - bond_claim_after_redemption(k, sh, b).unwrap() >= pay);
        // 78
        let (coupon, rest, r3) = coupon_pay_from_leg(leg as u128, r);
        prop_assert!(coupon <= r && coupon <= leg as u128 / 2 && coupon + rest == leg as u128 && r3 == r - coupon);
        // settlement: x * D <= K * rate * dt + rem (floor; the remainder is carried, not lost)
        let (x, rem) = coupon_settle(k, r, rem0, rate, dt, true, k).unwrap();
        let exact = k * rate as u128 * dt as u128 + rem0 as u128;
        prop_assert!(x * D + rem as u128 <= exact);
    }
}
