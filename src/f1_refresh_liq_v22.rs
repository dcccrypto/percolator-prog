//! v2.2 F1 (2026-10-14, `~/percolator-ops/ledger/v22-f1-refresh-liquidation-2026-10-14.md`):
//! the permissionless crank's refresh of a positioned account continues into ONE liquidation
//! step, in the same instruction, when the refresh leaves the account below maintenance.
//!
//! Why this is needed. The engine's auto-crank is one bounded step per call, chosen from the
//! account's certificate as it stood BEFORE the call (certify first, act next): `Liquidate` needs a
//! CURRENT certificate with a nonzero deficit, and every price-moving accrual or mark push bumps
//! `oracle_epoch` (funding / rent bump `funding_epoch`), which un-currents every certificate. On a
//! live cluster each keeper transaction lands in a later slot and has to accrue first (the Hybrid
//! gate wants an in-slot report; AuthMark wants the pending mark segment observed), so the
//! certificate the previous refresh wrote is stale again before any later transaction could act
//! on it. Only a second crank in the SAME transaction (same slot, no accrual between) found the
//! certificate current. The deployed keeper sends one crank per account, so off-band positions ran
//! to bankruptcy. Band markets were unaffected: a pinned accrual moves no price, so their
//! certificates stay current across transactions and the next crank liquidates.
//!
//! This module is the pure decision kernel. Free of `AccountInfo`, syscalls and engine types so
//! every function is a Kani target. The processor gathers the inputs AFTER the first step and,
//! when [`follow_on_liquidation`] says so, runs the SAME public crank once more with no
//! observations (exactly the second instruction of the two-crank shape), which the engine's own
//! plan selector turns into its existing `Liquidate` step with its existing partial sizing.

// Compute. No run-time compute gate: the `sol_remaining_compute_units` syscall is NOT active on
// devnet (feature 5TuppMutoyzhUSfuYdhgzD47F92GL1g89KpCZQKqedxP inactive; a build that called it
// failed every follow-on crank with "unsupported BPF instruction" on a devnet clone). The bound is
// static instead: the follow-on is ONE engine liquidation step, measured at most 369,633 CU at the
// wrapper leg cap (4 legs, worst pending K + F + fee), so a refresh crank with its follow-on is at
// most 1,098,281 CU (+66k stranded-backing hook = 1.164M), inside the repo's 10% rule (1,260,000 of
// 1.4M). A batched keeper transaction that overruns fails with no program code and is shrunk by the
// keeper's simulate-first rule (`sweep.ts`); nothing lands partially.

/// Minimum progress (hysteresis): below maintenance, the follow-on runs only when the shortfall
/// `requirement - equity` is at least this many bps OF THE REQUIREMENT (or equity is <= 0). An
/// account that a liquidation restored exactly to its requirement and that funding then drags a
/// fraction of a bp under would otherwise pay a dust liquidation on every keeper refresh
/// (observed live on PENGU 7Jbxvqfk...: -60 to -83 atoms per crank, 13 times in 90 s). 50 bps of
/// the requirement is 2.5 bps of notional at a 5% MMR; the engine's sizing then closes about
/// 0.6% of the position (the keeper's own 0.5% screen). A skipped account always has equity
/// > 0 (Kani `kani_f1_skip_only_while_solvent`), and the legacy second crank still liquidates it.
pub const F1_MIN_SHORTFALL_BPS_OF_REQ: u128 = 50;

/// `ceil(requirement * F1_MIN_SHORTFALL_BPS_OF_REQ / 10_000)`, at least 1, without overflow
/// (50 / 10_000 = 1 / 200).
#[inline]
pub fn min_shortfall(certified_maintenance_req: u128) -> u128 {
    let q = certified_maintenance_req / 200;
    let r = certified_maintenance_req % 200;
    let t = if r != 0 { q + 1 } else { q };
    if t == 0 { 1 } else { t }
}

/// Enough progress to be worth a liquidation step: equity <= 0 (insolvent: always), or the
/// shortfall to the requirement is at least [`min_shortfall`].
#[inline]
pub fn shortfall_material(certified_equity: i128, certified_maintenance_req: u128) -> bool {
    if certified_equity <= 0 {
        return true;
    }
    let e = certified_equity as u128;
    e < certified_maintenance_req && certified_maintenance_req - e >= min_shortfall(certified_maintenance_req)
}

/// Everything the decision needs, read after the first step of the instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct F1Inputs {
    /// The first step was the engine's `RefreshAccount` and it certified the account
    /// (`Progressed(AccountCurrent)`), not a B chunk, a source-backing expiry or another plan.
    pub first_step_certified_refresh: bool,
    /// Follow-on steps already taken for this account in this instruction.
    pub steps_taken: u8,
    /// Market mode is Live.
    pub live: bool,
    /// The engine's own classifier says `liquidatable` (current certificate, nonzero deficit,
    /// open risk, no reset obligation).
    pub engine_liquidatable: bool,
    /// Signals the engine's plan selector ranks ABOVE `Liquidate`; any of them means the next
    /// step would not be a liquidation.
    pub b_stale: bool,
    pub pending_close: bool,
    pub expired_close: bool,
    pub recovery_eligible: bool,
    pub resolved_winner: bool,
    /// The certificate the refresh just wrote.
    pub certified_equity: i128,
    pub certified_maintenance_req: u128,
    pub certified_liq_deficit: u128,
    /// Some active leg is on a band market (band_epoch != 0): the band's own pass liquidates.
    pub band_on: bool,
    /// The account is a bound vault LP: its own P3 path (senior draw first) stays unchanged.
    pub vault_lp: bool,
    /// Every active leg has a nonzero effective size, both sides of its asset hold effective OI,
    /// and no pending domain-loss barrier sits on either side of its asset (the engine's
    /// liquidation would refuse otherwise, which would fail the whole instruction).
    pub legs_reducible: bool,
}

/// Strictly below maintenance: `equity < maintenance_req`, compared without overflow.
#[inline]
pub fn below_maintenance(certified_equity: i128, certified_maintenance_req: u128) -> bool {
    if certified_equity < 0 {
        true
    } else {
        (certified_equity as u128) < certified_maintenance_req
    }
}

/// The engine's certified deficit, mirrored from `refresh_account_and_certify_not_atomic`
/// (engine 3ce4cbd1 `src/v16.rs`, `certified_liq_deficit`): `|equity|` when equity is negative,
/// else `maintenance_req - equity` saturating at 0.
#[inline]
pub fn engine_certified_liq_deficit(certified_equity: i128, certified_maintenance_req: u128) -> u128 {
    if certified_equity < 0 {
        certified_equity.unsigned_abs()
    } else {
        certified_maintenance_req.saturating_sub(certified_equity as u128)
    }
}

/// Everything except account health: may this account take a follow-on step at all?
#[inline]
pub fn follow_on_eligible(i: &F1Inputs) -> bool {
    i.first_step_certified_refresh
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
}

/// The decision: one liquidation step iff the account is eligible, the engine classifies it
/// liquidatable, its fresh certificate is strictly below maintenance with a nonzero deficit, and
/// the shortfall is material (not dust).
#[inline]
pub fn follow_on_liquidation(i: &F1Inputs) -> bool {
    follow_on_eligible(i)
        && i.engine_liquidatable
        && i.certified_liq_deficit != 0
        && below_maintenance(i.certified_equity, i.certified_maintenance_req)
        && shortfall_material(i.certified_equity, i.certified_maintenance_req)
}

/// The bounded step counter: at most one follow-on per account per instruction.
#[inline]
pub fn steps_after(steps_taken: u8, liquidated: bool) -> u8 {
    if liquidated {
        steps_taken.saturating_add(1)
    } else {
        steps_taken
    }
}

/// Kani harnesses (design first, run ONCE on the final code, one at a time):
/// `cargo kani --features devnet --harness kani_f1_<name>`. Every harness carries
/// `kani::cover!` for both branches; a verdict counts only with every cover SATISFIED.
#[cfg(kani)]
mod f1_kani_proofs {
    use super::*;

    /// Never liquidate at or above maintenance (any inputs, including inconsistent deficit
    /// fields), and the engine's deficit formula is nonzero exactly below maintenance.
    /// Mutants: `<=` in `below_maintenance`; drop the health conjunct; deficit test alone with a
    /// stale deficit field.
    #[kani::proof]
    fn kani_f1_never_at_or_above_maintenance() {
        let i: F1Inputs = kani::any();
        let d = follow_on_liquidation(&i);
        let at_or_above = i.certified_equity >= 0
            && (i.certified_equity as u128) >= i.certified_maintenance_req;
        if at_or_above {
            assert!(!d, "liquidated at or above maintenance");
        }
        let formula = engine_certified_liq_deficit(i.certified_equity, i.certified_maintenance_req);
        assert_eq!(formula != 0, below_maintenance(i.certified_equity, i.certified_maintenance_req));
        kani::cover!(d, "liquidates below maintenance");
        kani::cover!(!d && at_or_above && follow_on_eligible(&i) && i.engine_liquidatable && i.certified_liq_deficit != 0,
            "eligible, engine says liquidatable, stale deficit field, but at maintenance: refused");
        kani::cover!(i.certified_equity >= 0 && (i.certified_equity as u128) == i.certified_maintenance_req && !d,
            "exactly at maintenance: refused");
        kani::cover!(i.certified_equity < 0 && d, "negative equity liquidates");
    }

    /// Always attempt when below maintenance and eligible (liveness of the fix), and only then.
    /// Mutants: an extra veto; `steps_taken <= 1`; drop the legs-reducible veto.
    #[kani::proof]
    fn kani_f1_always_when_below_and_eligible() {
        let i: F1Inputs = kani::any();
        let below = below_maintenance(i.certified_equity, i.certified_maintenance_req)
            && shortfall_material(i.certified_equity, i.certified_maintenance_req);
        let want = follow_on_eligible(&i) && i.engine_liquidatable && i.certified_liq_deficit != 0 && below;
        assert_eq!(follow_on_liquidation(&i), want);
        if follow_on_liquidation(&i) {
            assert!(i.live && i.first_step_certified_refresh && !i.band_on && !i.vault_lp);
            assert!(!i.b_stale && !i.pending_close && !i.expired_close && !i.recovery_eligible && !i.resolved_winner);
            assert!(i.legs_reducible && i.steps_taken == 0);
        }
        kani::cover!(want, "below and eligible: attempted");
        kani::cover!(below && i.engine_liquidatable && i.certified_liq_deficit != 0 && !follow_on_eligible(&i),
            "below but ineligible: not attempted");
        kani::cover!(below && follow_on_eligible(&i) && !i.engine_liquidatable, "engine disagrees: not attempted");
        kani::cover!(i.band_on && below && i.engine_liquidatable, "band market: never");
        kani::cover!(!i.legs_reducible && below && i.engine_liquidatable && i.certified_liq_deficit != 0, "a leg not reducible: never");
        kani::cover!(follow_on_eligible(&i) && i.engine_liquidatable && i.certified_liq_deficit != 0
            && below_maintenance(i.certified_equity, i.certified_maintenance_req)
            && !shortfall_material(i.certified_equity, i.certified_maintenance_req), "dust shortfall: skipped");
    }

    /// Stub for `min_shortfall`: ANY threshold >= 1. With it the harness below proves its
    /// properties for every threshold value (no u128 division in the formula: the first design
    /// with the real `min_shortfall` hit the 1,500 s watchdog, NO-VERDICT). The real threshold is
    /// pinned separately by `kani_f1_min_shortfall_is_ceil`.
    #[cfg(kani)]
    fn min_shortfall_any_threshold(_certified_maintenance_req: u128) -> u128 {
        let t: u128 = kani::any();
        kani::assume(t >= 1);
        t
    }

    /// No path to bankruptcy skips it: whenever the rule declines an eligible, engine-liquidatable
    /// account that is below maintenance, that account is strictly solvent (equity > 0); every
    /// account with equity <= 0 is liquidated. Holds for EVERY threshold >= 1 (stubbed).
    /// Mutants: drop the `equity <= 0` arm; `equity < 0` instead of `<= 0`.
    #[kani::proof]
    #[kani::stub(super::min_shortfall, min_shortfall_any_threshold)]
    fn kani_f1_skip_only_while_solvent() {
        let i: F1Inputs = kani::any();
        let ready = follow_on_eligible(&i) && i.engine_liquidatable && i.certified_liq_deficit != 0;
        let below = below_maintenance(i.certified_equity, i.certified_maintenance_req);
        let d = follow_on_liquidation(&i);
        if ready && below && !d {
            assert!(i.certified_equity > 0, "skipped an insolvent account");
            assert!((i.certified_equity as u128) < i.certified_maintenance_req, "skip is only ever below maintenance");
        }
        // Below maintenance with equity <= 0 always liquidates. (First run FAILED on this assertion
        // without the `below` premise: equity 0 with requirement 0 is AT maintenance, which
        // `kani_f1_never_at_or_above_maintenance` proves must not liquidate. Equity < 0 is always
        // below maintenance since the requirement is unsigned.)
        if ready && below && i.certified_equity <= 0 {
            assert!(d, "insolvent account not liquidated");
        }
        if ready && i.certified_equity < 0 {
            assert!(d, "negative equity not liquidated");
        }
        kani::cover!(ready && below && !d, "dust skipped while solvent");
        kani::cover!(ready && i.certified_equity == 0 && d, "zero equity liquidated");
        kani::cover!(ready && i.certified_equity == 0 && i.certified_maintenance_req == 0 && !d, "zero equity AT a zero requirement: not liquidated");
        kani::cover!(ready && i.certified_equity < 0 && d, "negative equity liquidated");
        kani::cover!(ready && i.certified_equity > 0 && below && d, "material shortfall liquidated");
    }

    /// The real threshold is exactly ceil(requirement / 200) (= 50 bps of the requirement),
    /// at least 1. Requirements bounded to u64 (cast up), as the g8 harnesses bound their inputs;
    /// run with `--solver z3` (u128 division by a constant).
    /// Mutants: floor instead of ceil; `/ 20`; no `max(1)`.
    #[kani::proof]
    fn kani_f1_min_shortfall_is_ceil() {
        let m: u64 = kani::any();
        let m = m as u128;
        let t = min_shortfall(m);
        assert!(t >= 1);
        assert!(t * 200 >= m, "below the ceiling");
        if m > 0 {
            assert!((t - 1) * 200 < m, "above the ceiling");
        }
        kani::cover!(m == 0 && t == 1, "zero requirement: 1 atom");
        kani::cover!(m > 0 && m % 200 == 0, "exact multiple");
        kani::cover!(m % 200 != 0 && m > 200, "rounded up");
    }

    /// At most one step per account per instruction: after one step the decision is false for
    /// every state, and the counter never exceeds 1 from 0 nor wraps.
    /// Mutants: `steps_taken < 2`; counter `wrapping_add`; counter not advanced.
    #[kani::proof]
    fn kani_f1_at_most_one_step() {
        let mut i: F1Inputs = kani::any();
        kani::assume(i.steps_taken == 0);
        let first = follow_on_liquidation(&i);
        let after = steps_after(i.steps_taken, first);
        assert!(after <= 1);
        assert_eq!(after == 1, first);
        i.steps_taken = after;
        if first {
            assert!(!follow_on_liquidation(&i), "a second step in the same instruction");
        }
        let any_taken: u8 = kani::any();
        assert!(steps_after(any_taken, kani::any()) >= any_taken, "counter wrapped");
        kani::cover!(first, "one step taken");
        kani::cover!(!first, "no step taken");
    }

    /// No overflow or panic anywhere in the kernel, for every input (Kani checks arithmetic
    /// overflow on every operation by default; the harness just drives every function).
    #[kani::proof]
    fn kani_f1_no_overflow() {
        let i: F1Inputs = kani::any();
        let b = below_maintenance(i.certified_equity, i.certified_maintenance_req);
        let f = engine_certified_liq_deficit(i.certified_equity, i.certified_maintenance_req);
        let e = follow_on_eligible(&i);
        let d = follow_on_liquidation(&i);
        let m = min_shortfall(i.certified_maintenance_req);
        let sm = shortfall_material(i.certified_equity, i.certified_maintenance_req);
        let s = steps_after(i.steps_taken, d);
        kani::cover!(i.certified_maintenance_req == u128::MAX && m == u128::MAX / 200 + 1, "threshold at u128::MAX");
        kani::cover!(sm && i.certified_equity > 0, "material positive shortfall");
        assert!(s >= i.steps_taken);
        kani::cover!(i.certified_equity == i128::MIN && b && f == i128::MIN.unsigned_abs(), "equity i128::MIN");
        kani::cover!(i.certified_maintenance_req == u128::MAX && i.certified_equity == i128::MAX && b, "max requirement");
        kani::cover!(i.steps_taken == u8::MAX && s == u8::MAX, "counter saturates, never wraps");
        kani::cover!(e && d, "decision true");
        kani::cover!(!d, "decision false");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_shortfall_is_ceil_half_percent_of_the_requirement() {
        assert_eq!(min_shortfall(0), 1);
        assert_eq!(min_shortfall(1), 1);
        assert_eq!(min_shortfall(200), 1);
        assert_eq!(min_shortfall(201), 2);
        assert_eq!(min_shortfall(5_000_000), 25_000);
        assert_eq!(min_shortfall(u128::MAX), u128::MAX / 200 + 1);
    }

    #[test]
    fn shortfall_rule_examples() {
        // requirement 5,000,000: threshold 25,000.
        assert!(!shortfall_material(5_000_000, 5_000_000), "at the requirement");
        assert!(!shortfall_material(4_975_001, 5_000_000), "dust below");
        assert!(shortfall_material(4_975_000, 5_000_000), "exactly the threshold");
        assert!(shortfall_material(0, 5_000_000) && shortfall_material(-1, 5_000_000), "insolvent always");
        assert!(!shortfall_material(6_000_000, 5_000_000), "above");
    }
}
