//! v22kani LIVE (2026-10-20), audit gap G9 at the wrapper: liquidation liveness of the tag-5
//! instruction-level decisions. cfg(kani) only; every harness calls the REAL production fn.
//! Design / assumptions / covers / mutants: ~/wt-v22kani-1020/reports/LIVE.md.
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use core::sync::atomic::{AtomicU64, Ordering};
use percolator_prog::f1_refresh_liq_v22::{
    below_maintenance, follow_on_eligible, follow_on_liquidation, shape_within_budget, shortfall_material,
    F1Inputs, F1_MAX_FOLLOW_ON_LEGS,
};
use percolator_prog::state::next_portfolio_position_control;

// ---------------------------------------------------------------------------------------------
// LV-W1 (replaces the NO-VERDICT row kani_f1_always_when_below_and_eligible as the liveness
// proof): the F1 follow-on is attempted for EVERY eligible, engine-liquidatable account whose
// fresh certificate is below maintenance by a material shortfall, for every threshold value; an
// insolvent account (equity <= 0) is never skipped; and every veto is one of the listed ones.
//
// `min_shortfall` (u128 division, the reason the original row timed out) is replaced by ONE
// symbolic threshold t >= 1 fixed per run (deterministic: the stub returns the same t on every
// call). This proves the claims for every t; the real threshold is pinned separately by
// `kani_f1_min_shortfall_is_ceil` (PASS 6/6 at the head).
// ---------------------------------------------------------------------------------------------

static W1_T_HI: AtomicU64 = AtomicU64::new(1);
static W1_T_LO: AtomicU64 = AtomicU64::new(1);

fn w1_threshold_fixed(_certified_maintenance_req: u128) -> u128 {
    ((W1_T_HI.load(Ordering::Relaxed) as u128) << 64) | W1_T_LO.load(Ordering::Relaxed) as u128
}

#[kani::proof]
#[kani::stub(percolator_prog::f1_refresh_liq_v22::min_shortfall, w1_threshold_fixed)]
fn kani_live_w1_f1_follow_on_whenever_below_and_eligible() {
    let t: u128 = kani::any();
    kani::assume(t >= 1);
    W1_T_HI.store((t >> 64) as u64, Ordering::Relaxed);
    W1_T_LO.store(t as u64, Ordering::Relaxed);

    let i: F1Inputs = kani::any();
    let d = follow_on_liquidation(&i);
    let below = below_maintenance(i.certified_equity, i.certified_maintenance_req);
    let material = i.certified_equity <= 0
        || ((i.certified_equity as u128) < i.certified_maintenance_req
            && i.certified_maintenance_req - i.certified_equity as u128 >= t);
    // the threshold rule is exactly "insolvent, or shortfall >= t" (independent restatement)
    assert_eq!(shortfall_material(i.certified_equity, i.certified_maintenance_req), material);
    // the documented vetoes, each stated on its own input
    let vetoes_clear = i.first_step_certified_refresh
        && i.steps_taken == 0
        && i.live
        && !i.b_stale
        && !i.pending_close
        && !i.expired_close
        && !i.recovery_eligible
        && !i.resolved_winner
        && !i.band_on
        && !i.vault_lp
        && i.legs_reducible
        && i.active_legs <= F1_MAX_FOLLOW_ON_LEGS
        && (i.occupied_source_domains as u16) <= 2 * (i.active_legs as u16);
    assert_eq!(follow_on_eligible(&i), vetoes_clear, "an undocumented veto (or a missing one)");
    // LIVENESS: below maintenance, material, engine-liquidatable, no veto => the follow-on runs
    if vetoes_clear && i.engine_liquidatable && i.certified_liq_deficit != 0 && below && material {
        assert!(d, "eligible below-maintenance account not liquidated");
    }
    // insolvent accounts are never skipped by the dust rule
    if vetoes_clear && i.engine_liquidatable && i.certified_liq_deficit != 0 && i.certified_equity < 0 {
        assert!(d, "insolvent account skipped");
    }
    // and only then (safety half, so the liveness assertion is not satisfied by "always true")
    if d {
        assert!(vetoes_clear && i.engine_liquidatable && i.certified_liq_deficit != 0 && below && material);
    }
    kani::cover!(d && t > 1 && i.certified_equity > 0, "material positive-equity shortfall: follows on");
    kani::cover!(d && i.certified_equity < 0, "insolvent: follows on");
    kani::cover!(!d && vetoes_clear && i.engine_liquidatable && i.certified_liq_deficit != 0 && below && !material, "dust shortfall skipped (legacy second crank)");
    kani::cover!(!d && below && i.engine_liquidatable && !i.legs_reducible, "a leg the engine would refuse: no follow-on");
    kani::cover!(!d && below && i.engine_liquidatable && i.active_legs == F1_MAX_FOLLOW_ON_LEGS + 1, "over the compute envelope: legacy two-crank");
    kani::cover!(shape_within_budget(3, 6) && !shape_within_budget(3, 7), "budget edge");
}

// ---------------------------------------------------------------------------------------------
// LV-W2 (S1-23, wrapper c1228c48): the position_epoch advance that tag 5 now performs after a
// liquidation reshaped the portfolio can refuse the instruction ONLY at the 49-bit episode limit
// (2^49 - 1 episodes), and on success it changes only the episode bits.
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn kani_live_w2_position_epoch_bump_refuses_only_at_the_episode_limit() {
    let control: u64 = kani::any();
    let enabled = control & 1;
    let epoch = (control >> 1) & ((1u64 << 49) - 1);
    let fee_cap = control >> 50;
    // a stored control word was written through the validated setters (fee cap <= 10_000)
    kani::assume(fee_cap <= 10_000);
    let r = next_portfolio_position_control(control);
    if epoch < (1u64 << 49) - 1 {
        assert!(r.is_ok(), "epoch bump refused below the limit");
        if let Ok((next, next_control)) = r {
            assert_eq!(next, epoch + 1);
            assert_eq!(next_control & 1, enabled, "enabled bit changed");
            assert_eq!(next_control >> 50, fee_cap, "fee-cap bits changed");
            assert_eq!((next_control >> 1) & ((1u64 << 49) - 1), epoch + 1);
        }
    } else {
        assert!(r.is_err(), "episode counter wrapped");
    }
    kani::cover!(r.is_ok() && epoch == 0, "first episode");
    kani::cover!(r.is_ok() && epoch == (1u64 << 49) - 2, "last admissible episode");
    kani::cover!(r.is_err(), "limit reached: refused");
}
