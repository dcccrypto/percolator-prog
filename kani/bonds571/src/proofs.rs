//! Kani harnesses for the GH#571 carried coupon (production `bond_v20`, revised after att649).
//! Local only:  cargo kani -j 2 --output-format terse   (from kani/bonds571)
//!
//! Every harness carries `kani::cover!` witnesses; a harness whose covers are not ALL satisfied
//! is vacuous and does not count as a pass.
//!
//! BOUNDED proofs. Symbolic values are u8 (cast to u128) wherever a symbolic u128 multiply +
//! divide occurs (the repo's p3 crate needed the same bound for CBMC to terminate). The settlement
//! law is proved on `coupon_settle_in` over a FAMILY of small one-year lengths `year` and
//! denominators `denom` (production `coupon_settle` = `coupon_settle_in` at
//! `(SLOTS_PER_YEAR, COUPON_DENOM)`, whose denominator ~7.9e11 no u8 input can reach); the
//! full-width proptests in `tests/v22_bond_carry_571_pure.rs` check the production constants.

use crate::bond_v20::*;

fn b(x: u8) -> u128 {
    x as u128
}

/// Settlement (cap, closed gate, exact remainder): closed keeps everything; open never passes the
/// cap on the meter (`U + x <= max(U, cap)`), keeps the remainder below `denom`, and when the cap
/// does not bind credits EXACTLY `floor(num / denom)` with `num = min(K, value) * rate * dt' +
/// rem` (`x * denom + rem' == num`, nothing lost); when it binds, `x` = the room and rem' = 0.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_settle_cap_closed_exact_remainder() {
    let (k, u, value) = (b(kani::any()), b(kani::any()), b(kani::any()));
    let (rate, dslots, rem, year, denom): (u8, u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let open: bool = kani::any();
    kani::assume(u <= k && year > 0 && denom > 0 && (rem as u128) < b(denom));
    let r = coupon_settle_in(k, u, rem as u64, rate as u32, dslots as u64, open, value, b(year), b(denom));
    assert!(r.is_some(), "no overflow on the bounded domain");
    let (x, rem2) = r.unwrap();
    if !open {
        assert!(x == 0 && rem2 == rem as u64);
    } else {
        let dt = if b(dslots) > b(year) { b(year) } else { b(dslots) };
        let base = if value < k { value } else { k };
        let num = base * rate as u128 * dt + rem as u128;
        let cap = (k - u) * rate as u128 * b(year) / b(denom);
        let ceiling = if cap > u { cap } else { u };
        assert!(u + x <= ceiling, "the meter never passes the cap");
        assert!((rem2 as u128) < b(denom));
        if num / b(denom) + u <= ceiling {
            assert!(x * b(denom) + rem2 as u128 == num, "exact: nothing lost, the remainder carried");
        } else {
            assert!(u + x == ceiling && rem2 == 0, "cap binds: the excess is forfeited");
        }
    }
    kani::cover!(open && x > 0 && rem2 > 0, "accrues and carries a remainder");
    kani::cover!(open && x > 0 && rem2 == 0 && u + x == if (k - u) * rate as u128 * b(year) / b(denom) > u { (k - u) * rate as u128 * b(year) / b(denom) } else { u }, "cap binds");
    kani::cover!(!open && rem > 0, "closed keeps the remainder");
}

/// att649 F3 (no grinding): settling an interval in TWO steps, carrying the remainder, credits
/// EXACTLY the one-step accrual on the same base (cap not binding). So a crank every slot loses
/// nothing at any per-slot accrual.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_split_interval_is_exact() {
    let k = b(kani::any());
    let (rate, d1, d2, year, denom): (u8, u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(k > 0 && denom > 0 && year > 0 && (d1 as u128 + d2 as u128) <= b(year));
    let (x1, r1) = coupon_settle_in(k, 0, 0, rate as u32, d1 as u64, true, k, b(year), b(denom)).unwrap();
    let (x2, r2) = coupon_settle_in(k + x1, x1, r1, rate as u32, d2 as u64, true, k, b(year), b(denom)).unwrap();
    let (xo, ro) = coupon_settle_in(k, 0, 0, rate as u32, d1 as u64 + d2 as u64, true, k, b(year), b(denom)).unwrap();
    // the cap (one year on K - U at the same base) does not bind within one year
    kani::assume(xo <= k * rate as u128 * b(year) / b(denom));
    assert!(x1 + x2 == xo && r2 == ro);
    kani::cover!(x1 > 0 && x2 > 0, "both steps accrue");
    kani::cover!(x1 == 0 && x2 > 0, "a sub-atom first step is carried, not ground away");
}

/// Settlement is monotone in elapsed time (a later settlement never owes less).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_settle_monotone_in_time() {
    let (k, u) = (b(kani::any()), b(kani::any()));
    let (rate, dt, e, rem, year, denom): (u8, u8, u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(u <= k && year > 0 && denom > 0 && (rem as u128) < b(denom));
    let (x, _) = coupon_settle_in(k, u, rem as u64, rate as u32, dt as u64, true, k, b(year), b(denom)).unwrap();
    let (y, _) = coupon_settle_in(k, u, rem as u64, rate as u32, dt as u64 + e as u64, true, k, b(year), b(denom)).unwrap();
    assert!(y >= x);
    kani::cover!(y > x, "strictly later accrues more");
}

/// Tag 78 payment: conserves the leg (coupon + rest == leg), lowers ONLY the receivable
/// (coupon + R' == R; the claim K is not an input), never more than R, never more than half the
/// leg (M-2).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_pay_conserves_leg_and_receivable() {
    let (avail, r) = (b(kani::any()), b(kani::any()));
    let (coupon, rest, r2) = coupon_pay_from_leg(avail, r);
    assert!(coupon + rest == avail);
    assert!(coupon + r2 == r);
    assert!(coupon <= avail / 2 && coupon <= r);
    assert!(coupon == if r < avail / 2 { r } else { avail / 2 });
    kani::cover!(r2 > 0 && coupon > 0, "partial payment carries the rest");
    kani::cover!(r2 == 0 && coupon > 0, "full payment");
}

/// Tag 108 meter (att649 F1b): a deposit labels the new shares at least at the pool's ratio
/// (`U' / K' >= U / K`, rounded against the depositor) and keeps the invariant `U' <= K'` that
/// `validate_bond_tranche` requires.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_deposit_meter_keeps_ratio_and_bound() {
    let (k, u, d) = (b(kani::any()), b(kani::any()), b(kani::any()));
    kani::assume(u <= k);
    let u1 = coupon_meter_after_deposit(u, k, d).unwrap();
    let k1 = k + d;
    assert!(u <= u1 && u1 <= k1, "U <= K preserved");
    if k > 0 {
        assert!(u1 * k >= u * k1, "the new shares carry at least the pool's ratio");
        assert!(u1 * k < u * k1 + k, "and at most one atom more (ceil)");
    }
    kani::cover!(k > 0 && u > 0 && d > 0 && u1 > u, "labelled");
}

/// Tag 110 (att649 F1): the exit removes exactly the whole-tranche payout from K (the pre-#571
/// slice), its slice of the meter, and NOTHING from the receivable (not an input). Full exit
/// empties K and U; a partial exit keeps K > 0 (K == 0 <=> B == 0) and `U' <= K'`; the stayers'
/// per-share claim never falls.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_redemption_slices_k_and_meter() {
    let (k, u, bb, sh) = (b(kani::any()), b(kani::any()), b(kani::any()), b(kani::any()));
    kani::assume(k > 0 && bb > 0 && u <= k && sh <= bb);
    let k2 = bond_claim_after_redemption(k, sh, bb).unwrap();
    let u2 = coupon_meter_after_redemption(u, sh, bb).unwrap();
    let pay = bond_atoms_for_redemption(sh, bb, k).unwrap();
    assert!(k - k2 == pay, "removed == the whole-tranche payout");
    assert!(u2 <= u && u2 <= k2, "U <= K preserved");
    if sh == bb {
        assert!(k2 == 0 && u2 == 0);
    } else {
        assert!(k2 > 0, "K == 0 <=> B == 0");
        assert!(k2 * bb >= k * (bb - sh), "stayers never diluted");
    }
    kani::cover!(sh > 0 && sh < bb && u > 0 && u2 < u, "partial exit takes its meter slice");
    kani::cover!(sh == bb && u > 0, "full exit empties the meter");
}

/// NEWCOMER NEUTRALITY over one deposit + one settlement (whole tranche, cap not binding):
/// incumbents hold `bb` shares of claim `k`; a newcomer deposits `d` and mints
/// `m = bond_shares_for_deposit(d, bb, k)`; then `dt` slots accrue on the new claim. Then
///   newcomer value   <= d * (1 + r dt)          (takes nothing of the incumbents' accrual)
///   incumbents value >= k * (1 + r dt) - 1      (keep theirs, up to one floor)
/// with `r dt = rate * dt / denom`, cross-multiplied (exact).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_newcomer_neutral_within_rounding() {
    let (k, u, bb, d) = (b(kani::any()), b(kani::any()), b(kani::any()), b(kani::any()));
    let (rate, dt, year, denom): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(k > 0 && bb > 0 && d > 0 && u <= k && year > 0 && denom > 0 && dt <= year);
    let m = bond_shares_for_deposit(d, bb, k).unwrap();
    kani::assume(m > 0); // m == 0 is refused (BondSlippage)
    let u1 = coupon_meter_after_deposit(u, k, d).unwrap();
    let k1 = k + d;
    let (x, _) = coupon_settle_in(k1, u1, 0, rate as u32, dt as u64, true, k1, b(year), b(denom)).unwrap();
    let growth = rate as u128 * dt as u128;
    kani::assume(x == k1 * growth / b(denom)); // the cap does not bind
    let k2 = k1 + x;
    let bt = bb + m;
    assert!(m * k2 * b(denom) <= bt * d * (b(denom) + growth), "newcomer: nothing of the incumbents'");
    assert!(bb * k2 * b(denom) + bt * b(denom) >= bt * k * (b(denom) + growth), "incumbents keep theirs");
    kani::cover!(x > 0 && u > 0, "accrual with a labelled meter");
}

/// The read-only junior gates (97 / 103) reserve `claim_upper_bound_at`: a settlement at the
/// MAXIMUM rate, gate assumed open, base = the full claim. Every real settlement (78 at
/// `min(u_last, u_now)`, 108 / 110 at utilisation 0, any gate state, any base `min(K, value)`)
/// credits at most that bound, so the junior can never withdraw value the next settlement hands
/// to the bonds.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_junior_gate_bound_dominates_every_settlement() {
    let (k, u, value) = (b(kani::any()), b(kani::any()), b(kani::any()));
    let (base, bonus, util, dt, rem, year, denom): (u8, u8, u16, u8, u8, u8, u8) =
        (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let open: bool = kani::any();
    kani::assume(u <= k && year > 0 && denom > 0 && (rem as u128) < b(denom));
    kani::assume(util as u128 <= crate::vault_lp_v18::BPS);
    let r_real = bond_coupon_rate_bps(base as u16, bonus as u16, util);
    let r_max = bond_coupon_rate_bps(base as u16, bonus as u16, crate::vault_lp_v18::BPS as u16);
    assert!(r_real <= r_max);
    let (real, _) = coupon_settle_in(k, u, rem as u64, r_real, dt as u64, open, value, b(year), b(denom)).unwrap();
    let (bound, _) = coupon_settle_in(k, u, rem as u64, r_max, dt as u64, k > 0, k, b(year), b(denom)).unwrap();
    if k > 0 {
        assert!(real <= bound);
    }
    kani::cover!(k > 0 && open && real > 0 && real < bound, "strictly inside the bound");
    kani::cover!(k > 0 && open && real == bound && real > 0, "bound tight");
}

/// att649 F2 gate memory: an interval is clean (may accrue) iff the previous settlement saw the
/// gate OPEN and the cumulative drawn counter has not moved since. Any closed settlement makes
/// the next interval unclean; a new draw does too; an open settlement with no draw since makes
/// it clean.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_571_gate_memory_rule() {
    let drawn: u128 = kani::any();
    let more: u64 = kani::any();
    let open_then: bool = kani::any();
    kani::assume(drawn < (1u128 << 100));
    let seen = coupon_gate_seen(drawn, open_then);
    // no draw since
    assert!(coupon_interval_clean(seen, drawn) == open_then);
    // a draw booked since (the cumulative counter moved by less than 2^63)
    kani::assume(more > 0 && more < (1u64 << 63));
    assert!(!coupon_interval_clean(seen, drawn + more as u128), "a draw inside the interval forfeits it");
    kani::cover!(open_then, "clean interval");
    kani::cover!(!open_then, "closed at the start");
}
