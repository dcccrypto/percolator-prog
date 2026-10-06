//! Phase 4 items 5 and 6 (2026-10-05, `~/percolator-ops/ledger/phase4-design-2026-10-05.md`):
//! pure, integer-only math behind
//!
//! * item 5, the RESCUE tranche: senior shares bought at the certified impaired NAV, never at
//!   par, with the dilution lemma L-RES;
//! * item 6, the INSURANCE UNIT ledger (`InsuranceUnitsV20`): asset-0 insurance is unitised so
//!   that every loss is spread pro rata over the unit holders, and a withdrawal is bounded by the
//!   withdrawer's own class of units;
//! * item 6 G9, the INSURANCE BACKSTOP: insurance moved into the vault LP's capital once the
//!   junior and every senior pot are exhausted, repaid FIRST on recovery.
//!
//! Like `vault_lp_v18`, everything here is free of `AccountInfo`, syscalls and engine types so
//! that every function is a Kani / proptest target. `None` always means "fail closed" (overflow,
//! a zero denominator or a corrupt input), never "allow".
//!
//! Units: collateral atoms for every value, claim and insurance amount; shares are LP-share base
//! units; insurance units are ledger units (genesis 1 unit = 1 atom); bps are out of 10_000.

use crate::vault_lp_v18::{bps_floor, mul_div_floor, BPS};

// ── Item 6: insurance unit ledger ──────────────────────────────────────────────────────────────

/// Unit class of the market's bound stake pool (`vault_auth` PDA of `["stake_pool", market]`
/// under the pinned stake program).
pub const INS_UNIT_CLASS_STAKE: u8 = 0;
/// Unit class of everyone else who can top up or withdraw asset-0 insurance (the creator's seed
/// before the stake binds, a creator-held insurance authority, ...).
pub const INS_UNIT_CLASS_CREATOR: u8 = 1;

/// Ceiling of `a * b / d`; `None` on `d == 0` or overflow.
pub fn mul_div_ceil(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    let p = a.checked_mul(b)?;
    Some(p / d + u128::from(p % d != 0))
}

/// The MINT reading resets the ledger when the fund (including the backstop receivable) is worth
/// nothing while units are outstanding: every existing unit is then worth exactly 0, so the next
/// top-up is a genesis.
pub fn ins_units_reset_needed(units_total: u128, insurance_mint_reading: u128) -> bool {
    units_total != 0 && insurance_mint_reading == 0
}

/// Units minted for a top-up of `x` atoms: `floor(x * U / I_mint)`, genesis 1:1.
///
/// `I_mint` is the HIGHER (entry) reading of the fund: the asset-0 domain budgets remaining plus
/// the outstanding backstop receivable (insurance lent to the vault LP by G9 and owed back FIRST
/// on recovery). Pricing a top-up at the higher reading and flooring the result means a newcomer
/// can never buy units below the incumbents' value (Kani `kani_s3_units_mint_burn_no_dilution`):
/// `(I_mint + x) * U >= I_mint * (U + minted)`.
///
/// The caller resets the ledger first when `ins_units_reset_needed` (U > 0, I_mint == 0).
pub fn ins_units_for_topup(x: u128, units_total: u128, insurance_mint_reading: u128) -> Option<u128> {
    if units_total == 0 {
        return Some(x);
    }
    if insurance_mint_reading == 0 {
        // Corrupt call: the caller must reset first.
        return None;
    }
    mul_div_floor(x, units_total, insurance_mint_reading)
}

/// Units burned to withdraw `a` atoms: `ceil(a * U / I_free)`, at the LOWER (exit) reading of the
/// fund (what can actually be withdrawn now). Rounding up means the withdrawer always pays at a
/// price no better than the incumbents' value: `(I_free - a) * U >= I_free * (U - burned)`.
/// `None` when nothing can be withdrawn (`I_free == 0`, `U == 0`) or `a > I_free`.
pub fn ins_units_to_burn(a: u128, units_total: u128, insurance_free: u128) -> Option<u128> {
    if units_total == 0 || insurance_free == 0 || a > insurance_free {
        return None;
    }
    let b = mul_div_ceil(a, units_total, insurance_free)?;
    if b > units_total {
        return None;
    }
    Some(b)
}

/// The value of `units` of `U`: `floor(units * I / U)` (0 when `U == 0`).
pub fn ins_units_value(units: u128, units_total: u128, insurance: u128) -> Option<u128> {
    if units_total == 0 {
        return Some(0);
    }
    if units > units_total {
        return None;
    }
    mul_div_floor(units, insurance, units_total)
}

/// W-1 (security review 2026-10-05): the smallest genesis of the unit ledger (1 token at 6
/// decimals). A dust genesis (`U` tiny) lets later fee growth push `I / U` so high that every
/// top-up rounds to zero units.
pub const INS_UNITS_GENESIS_MIN_ATOMS: u128 = 1_000_000;

/// W-1: a top-up of `x` that mints `minted` units against `(U, I_mint)` (pre-top-up) is admitted
/// only if it mints something AND loses at most 1 bp (+1 atom) of `x` to rounding:
/// `x - floor(minted * I / U) <= floor(x / 10_000) + 1`. At genesis (`U == 0`) `x` must be at
/// least `INS_UNITS_GENESIS_MIN_ATOMS`. Together these bound any first-depositor / donation
/// inflation to 1 bp of each top-up, whatever `I / U` has grown to.
pub fn ins_mint_admissible(x: u128, minted: u128, units_total: u128, insurance_mint_reading: u128) -> bool {
    if x == 0 {
        return true;
    }
    if minted == 0 {
        return false;
    }
    if units_total == 0 {
        return x >= INS_UNITS_GENESIS_MIN_ATOMS;
    }
    let value = match minted.checked_mul(insurance_mint_reading) {
        Some(p) => p / units_total,
        None => return false,
    };
    let loss = x.saturating_sub(value);
    loss <= x / 10_000 + 1
}

/// R-2 (re-review 2026-10-06): the burn side of `ins_mint_admissible`. A withdrawal of `a` atoms
/// that burns `burned` units against `(U, I_free)` (pre-withdrawal) is admitted only if the burned
/// units are worth at most 1 bp (+1 atom) more than `a`: `floor(burned * I / U) - a <=
/// floor(a / 10_000) + 1`, unless the caller burns its WHOLE class (`burned == class_units`, a full
/// exit: there is nothing of its own left to protect, and refusing would strand its last value).
/// Without it, `ceil(a*U/I)` can burn a whole unit (`I/U` atoms) for a 1-atom withdrawal.
pub fn ins_burn_admissible(
    a: u128,
    burned: u128,
    units_total: u128,
    insurance_free: u128,
    class_units: u128,
) -> bool {
    if a == 0 || burned == class_units {
        return true;
    }
    if units_total == 0 {
        return false;
    }
    let value = match burned.checked_mul(insurance_free) {
        Some(p) => p / units_total,
        None => return false,
    };
    value.saturating_sub(a) <= a / 10_000 + 1
}

/// Mint no-dilution, cross-multiplied (no division): the per-unit value after a top-up of `x`
/// minting `minted` is at least the value before.
pub fn ins_mint_no_dilution(insurance: u128, units_total: u128, x: u128, minted: u128) -> bool {
    match (
        insurance.checked_add(x).and_then(|v| v.checked_mul(units_total)),
        units_total
            .checked_add(minted)
            .and_then(|u| u.checked_mul(insurance)),
    ) {
        (Some(lhs), Some(rhs)) => lhs >= rhs,
        _ => false,
    }
}

/// Burn at the worse price, cross-multiplied: the per-unit value of the units LEFT after a
/// withdrawal of `a` burning `burned` is at least the value before.
pub fn ins_burn_no_dilution(insurance: u128, units_total: u128, a: u128, burned: u128) -> bool {
    if a > insurance || burned > units_total {
        return false;
    }
    match (
        (insurance - a).checked_mul(units_total),
        (units_total - burned).checked_mul(insurance),
    ) {
        (Some(lhs), Some(rhs)) => lhs >= rhs,
        _ => false,
    }
}

// ── Item 6 G9: insurance backstop of the vault LP ──────────────────────────────────────────────

/// Cumulative share of the market's asset-0 insurance that the G9 backstop may have lent to the
/// vault LP at any time (`outstanding <= cap * (I + outstanding)`). Founder decision pending;
/// 50% keeps half of the fund for trader-bankruptcy residuals.
pub const BACKSTOP_CAP_BPS: u16 = 5_000;

/// G9 is due only when the vault LP has a certified deficit that the junior and the seniors can
/// no longer fund: the draw has run (nothing pending), found NO drawable pot backing, AND the
/// seniors' pots are worth nothing (`senior_nav == 0`). The last clause matters: pot backing that
/// is merely RESERVED against a winner's registered claim is not drawable, but it is still the
/// seniors' and still backs that winner; lending insurance then would shield the seniors from a
/// loss the waterfall assigns to them (junior -> seniors -> backstop).
pub fn backstop_due(deficit: u128, drawable_backing: u128, pending: u128, senior_nav: u128) -> bool {
    deficit != 0 && drawable_backing == 0 && pending == 0 && senior_nav == 0
}

/// Atoms G9 moves now: `min(deficit, I_free, cap_room)` where
/// `cap_room = floor(cap_bps * (I_gross + outstanding)) - outstanding` (saturating).
/// `I_gross` is the asset-0 budgets remaining (what the loss would come out of); `I_free` the
/// withdrawable part of it (net of source-credit reservations, the vault and the domain
/// reservations). Kani `kani_g9_backstop_bounded_by_insurance_and_deficit`.
pub fn backstop_draw_amount(
    deficit: u128,
    insurance_free: u128,
    insurance_gross: u128,
    outstanding: u128,
    cap_bps: u16,
) -> u128 {
    let base = insurance_gross.saturating_add(outstanding);
    let cap_total = bps_floor(base, cap_bps).unwrap_or(0);
    let room = cap_total.saturating_sub(outstanding);
    deficit.min(insurance_free).min(room)
}

/// W-2: G9 is two-step. A permissionless PROPOSE records the slot; the DRAW executes no earlier
/// than `G9_DELAY_SLOTS` later (an exit window for stakers before their insurance is lent).
pub const G9_DELAY_SLOTS: u64 = 9_000;
/// W-2: per-epoch cap on what G9 may lend: at most `G9_EPOCH_CAP_BPS` of `(I_gross +
/// outstanding)` per `G9_EPOCH_SLOTS` (~1 day), on top of the cumulative `BACKSTOP_CAP_BPS`.
pub const G9_EPOCH_SLOTS: u64 = 216_000;
pub const G9_EPOCH_CAP_BPS: u16 = 2_000;

/// W-2: an executable proposal lapses `G9_EXEC_WINDOW_SLOTS` after its delay ends, so an old
/// proposal can never turn a later crisis into an instant (undelayed) draw.
pub const G9_EXEC_WINDOW_SLOTS: u64 = 9_000;

/// W-2: the proposal is executable: `pending != 0`, the delay elapsed, the window not lapsed.
pub fn g9_delay_elapsed(pending_slot: u64, now: u64) -> bool {
    let start = pending_slot.saturating_add(G9_DELAY_SLOTS);
    pending_slot != 0 && now >= start && now < start.saturating_add(G9_EXEC_WINDOW_SLOTS)
}

/// W-2: a proposal is still open (pending or executable); a new proposal is refused meanwhile,
/// so nobody can restart (and so postpone) the stakers' exit window.
pub fn g9_proposal_open(pending_slot: u64, now: u64) -> bool {
    pending_slot != 0
        && now
            < pending_slot
                .saturating_add(G9_DELAY_SLOTS)
                .saturating_add(G9_EXEC_WINDOW_SLOTS)
}

/// W-2: what is left of this epoch's G9 allowance: `floor(cap * base) - drawn_this_epoch`.
pub fn g9_epoch_room(base: u128, drawn_this_epoch: u128, cap_bps: u16) -> u128 {
    bps_floor(base, cap_bps).unwrap_or(0).saturating_sub(drawn_this_epoch)
}

/// W-2: G9 only for a vault that HAS Earn seniors and whose seniors have actually taken a booked
/// draw. A junior-only vault has `senior_nav == 0` vacuously; without this, G9 would fund a
/// (possibly self-dealing) winner straight from insurance.
pub fn g9_vault_eligible(senior_shares: u128, senior_drawn: u128) -> bool {
    senior_shares > 0 && senior_drawn > 0
}

/// R-1 (re-review 2026-10-06, mainnet blocker): G9 lends insurance only on a market whose asset-0
/// price is EXTERNALLY sourced: Hybrid (oracle legs) or an EWMA mark with an external leg. Manual
/// and AuthMark are creator-pushed (and a leg-less EWMA mark follows the market's own trades), so a
/// creator could manufacture the deficit G9 pays. `allow_creator_oracle` is the devnet-only
/// override (`cfg!(feature = "devnet")` at the call site; never on a mainnet build).
pub fn g9_oracle_allowed(oracle_mode: u8, oracle_leg_count: u8, allow_creator_oracle: bool) -> bool {
    const HYBRID: u8 = 1;
    const EWMA: u8 = 2;
    let external = (oracle_mode == HYBRID || oracle_mode == EWMA) && oracle_leg_count > 0;
    external || allow_creator_oracle
}

/// R-1 (2): insurance never lends more, in total, than the Earn seniors have already lost to
/// booked draws: the room is `senior_drawn - outstanding`. Dust seniors therefore unlock dust.
pub fn g9_senior_drawn_room(senior_drawn: u128, outstanding: u128) -> u128 {
    senior_drawn.saturating_sub(outstanding)
}

/// R-6 (re-review 2026-10-06): the permissionless RESTORE leaves the vault LP this much above its
/// initial margin (bps of IM), so a repayment never parks the LP exactly on its margin floor.
pub const RESTORE_IM_BUFFER_BPS: u16 = 1_000;

/// R-6: the LP's capital that RESTORE may repay: `min(capital, equity - IM - buffer)`, with
/// `buffer = ceil(IM * RESTORE_IM_BUFFER_BPS / 10_000)`. 0 on overflow (fail closed).
pub fn backstop_restore_free(equity: u128, initial_req: u128, capital: u128) -> u128 {
    let buffer = match initial_req.checked_mul(RESTORE_IM_BUFFER_BPS as u128) {
        Some(p) => p.div_ceil(10_000),
        None => return 0,
    };
    match initial_req.checked_add(buffer) {
        Some(floor) => equity.saturating_sub(floor).min(capital),
        None => 0,
    }
}

/// Repayment of the backstop from the vault LP's free equity, FIRST on recovery:
/// `min(outstanding, lp_equity_free, requested)` (`requested == 0` = no caller cap).
pub fn backstop_restore_amount(outstanding: u128, lp_equity_free: u128, requested: u128) -> u128 {
    let r = outstanding.min(lp_equity_free);
    if requested == 0 {
        r
    } else {
        r.min(requested)
    }
}

/// The vault value Earn seniors and the junior price against while a backstop is outstanding:
/// the backstop is SENIOR to both in recovery (I-S6), so its receivable comes off the vault value
/// first. `V_eff = V - outstanding`, saturating.
pub fn vault_value_net_of_backstop(vault_value: u128, outstanding: u128) -> u128 {
    vault_value.saturating_sub(outstanding)
}

/// Recovery split with the backstop FIRST: `(to_backstop, rest)`, `to_backstop + rest ==
/// recovery`. `rest` then goes seniors-first (`vault_lp_v18::vault_lp_recovery_split`).
pub fn backstop_recovery_split(recovery: u128, outstanding: u128) -> (u128, u128) {
    let b = recovery.min(outstanding);
    (b, recovery - b)
}

/// `vault_lp_v18::live_exit_senior_value` with the backstop receivable netted off the vault value
/// first (I-S6). Identical to it when `backstop == 0`:
///   worse >= 0: senior = min(nav + min(lpv, worse) - b, C)
///   worse <  0: senior = min(nav - |worse| - b, C_p),  C_p = the booking-rule pricing claim.
pub fn live_exit_senior_value_net_backstop(
    c: u128,
    nav: u128,
    lp_value_at_eff: u128,
    lp_equity_worse: i128,
    backstop: u128,
) -> u128 {
    if lp_equity_worse >= 0 {
        let v = nav.saturating_add(lp_value_at_eff.min(lp_equity_worse as u128));
        vault_value_net_of_backstop(v, backstop).min(c)
    } else {
        let d = lp_equity_worse.unsigned_abs();
        let c_p = crate::vault_lp_v18::vault_lp_senior_pricing_claim(c, d, nav.saturating_sub(c));
        vault_value_net_of_backstop(nav.saturating_sub(d), backstop).min(c_p)
    }
}

/// Item 5, bound vault: the rescue reading at the price BETTER for the vault LP (the tag-75 entry
/// fairness rule, so a rescuer cannot buy at the lagging worse price and redeem after the oracle
/// catches up), net of the backstop. Returns `(uncapped V, v)` where `v = min(V, C_p)`; the
/// processor prices shares on `v` and measures the value a rescue actually adds on `V`.
pub fn rescue_bound_readings(
    c: u128,
    nav: u128,
    lp_equity_better: i128,
    backstop: u128,
) -> (u128, u128) {
    if lp_equity_better >= 0 {
        let v_raw = vault_value_net_of_backstop(
            nav.saturating_add(lp_equity_better as u128),
            backstop,
        );
        (v_raw, v_raw.min(c))
    } else {
        let d = lp_equity_better.unsigned_abs();
        let c_p = crate::vault_lp_v18::vault_lp_senior_pricing_claim(c, d, nav.saturating_sub(c));
        let v_raw = vault_value_net_of_backstop(nav.saturating_sub(d), backstop);
        (v_raw, v_raw.min(c_p))
    }
}

// ── Item 5: rescue tranche ─────────────────────────────────────────────────────────────────────

/// Below `RESCUE_NAV_FLOOR_BPS` of par the vault is dead: resolve or wind down, never rescue.
pub const RESCUE_NAV_FLOOR_BPS: u16 = 500;
/// Smallest rescue (100 units of a 6-decimal collateral).
pub const RESCUE_MIN_ATOMS: u128 = 100_000_000;
/// Largest rescue relative to the certified impaired value: `x <= 10 * v`.
pub const RESCUE_MAX_MULT: u128 = 10;

/// Why a rescue is refused (the processor maps these onto wrapper errors 114 / 115).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RescueRefusal {
    /// The vault is not impaired (`v >= par`): use tag 75.
    NotImpaired,
    /// `v < floor * par`: the vault is dead (error 115).
    NavFloor,
    /// `x` outside `[RESCUE_MIN_ATOMS, RESCUE_MAX_MULT * v]`.
    Amount,
    /// No incumbent shares (nothing to rescue) or a corrupt input.
    Shape,
}

/// Rescue admission on the certified readings: `v` = the impaired value the vault's shares can
/// exit at NOW (bound: the tag-77 live senior value; non-bound: the E3 exit NAV), `par` = what
/// those shares are owed at par (bound: C; non-bound: the entry/par NAV), `s` = shares
/// outstanding, `x` = the rescue amount. Kani `kani_rescue_refuses_floor_stale_pending` covers the
/// floor arm (the stale / pending arms are processor checks before this is called).
pub fn rescue_admitted(x: u128, v: u128, par: u128, s: u128) -> Result<(), RescueRefusal> {
    if s == 0 || par == 0 {
        return Err(RescueRefusal::Shape);
    }
    if v >= par {
        return Err(RescueRefusal::NotImpaired);
    }
    // v * 10_000 < par * floor_bps  <=>  v < floor * par  (cross-multiplied, no rounding).
    let lhs = v.checked_mul(BPS).ok_or(RescueRefusal::Shape)?;
    let rhs = par
        .checked_mul(RESCUE_NAV_FLOOR_BPS as u128)
        .ok_or(RescueRefusal::Shape)?;
    if lhs < rhs || v == 0 {
        return Err(RescueRefusal::NavFloor);
    }
    let max = v.checked_mul(RESCUE_MAX_MULT).ok_or(RescueRefusal::Shape)?;
    if x < RESCUE_MIN_ATOMS || x > max {
        return Err(RescueRefusal::Amount);
    }
    Ok(())
}

/// Shares minted to the rescuer: `m = floor(x * S / v)` (rounded against the rescuer). `None` on
/// `S == 0`, `v == 0` or overflow.
pub fn rescue_shares(x: u128, s: u128, v: u128) -> Option<u128> {
    if s == 0 || v == 0 {
        return None;
    }
    mul_div_floor(x, s, v)
}

/// The senior claim (par) added with `m` new shares: `floor(m * C / S)`, so `C / S` (par per
/// share) is unchanged up to rounding down (I-RS2). Bound vaults only. `None` on `S == 0` or
/// overflow.
pub fn rescue_claim_delta(m: u128, c: u128, s: u128) -> Option<u128> {
    if s == 0 {
        return None;
    }
    mul_div_floor(m, c, s)
}

/// L-RES (the dilution lemma), cross-multiplied: after a rescue of `x` atoms minting `m` shares
/// at the impaired value `v` of `S` shares, the value per share at the same reading is not lower
/// than before: `(v + x) * S >= v * (S + m)`. Holds for every `m <= floor(x * S / v)`.
pub fn rescue_value_no_dilution(v: u128, x: u128, s: u128, m: u128) -> bool {
    match (
        v.checked_add(x).and_then(|a| a.checked_mul(s)),
        s.checked_add(m).and_then(|b| b.checked_mul(v)),
    ) {
        (Some(lhs), Some(rhs)) => lhs >= rhs,
        _ => false,
    }
}

/// L-RES, claim half: `C' / S' >= v / S` with `C' = C + floor(m * C / S)` and `v < C`:
/// `(C + dC) * S >= v * (S + m)`.
pub fn rescue_claim_no_dilution(v: u128, c: u128, s: u128, m: u128, dc: u128) -> bool {
    match (
        c.checked_add(dc).and_then(|a| a.checked_mul(s)),
        s.checked_add(m).and_then(|b| b.checked_mul(v)),
    ) {
        (Some(lhs), Some(rhs)) => lhs >= rhs,
        _ => false,
    }
}

/// I-RS2: par per share is not raised by a rescue: `(C + dC) * S <= C * (S + m)`.
pub fn rescue_par_per_share_not_raised(c: u128, s: u128, m: u128, dc: u128) -> bool {
    match (
        c.checked_add(dc).and_then(|a| a.checked_mul(s)),
        s.checked_add(m).and_then(|b| b.checked_mul(c)),
    ) {
        (Some(lhs), Some(rhs)) => lhs <= rhs,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_genesis_and_pro_rata() {
        assert_eq!(ins_units_for_topup(1_000, 0, 0), Some(1_000));
        // 1_000 units over 1_000 atoms; a 30% loss: every unit loses 30%.
        assert_eq!(ins_units_value(400, 1_000, 700), Some(280));
        assert_eq!(ins_units_value(600, 1_000, 700), Some(420));
        // Top-up after the loss buys at the post-loss price.
        let m = ins_units_for_topup(700, 1_000, 700).unwrap();
        assert_eq!(m, 1_000);
        assert!(ins_mint_no_dilution(700, 1_000, 700, m));
        // Burn rounds up.
        assert_eq!(ins_units_to_burn(1, 3, 2), Some(2));
        assert!(ins_burn_no_dilution(2, 3, 1, 2));
        assert_eq!(ins_units_to_burn(3, 3, 2), None);
        assert!(ins_units_reset_needed(5, 0));
        assert!(!ins_units_reset_needed(0, 0));
        assert_eq!(ins_units_for_topup(5, 5, 0), None);
    }

    #[test]
    fn w1_mint_admissible() {
        assert!(!ins_mint_admissible(500_000, 0, 1, 3_000_000), "zero mint refused");
        assert!(!ins_mint_admissible(1_000_000, 1, 3, 2_000_000), "lossy mint refused (1 unit = 666,666 for 1,000,000)");
        assert!(ins_mint_admissible(1_000_000, 1_000_000, 1_000_000, 1_000_000));
        assert!(ins_mint_admissible(1_000_000, 666_666, 1_000_000, 1_500_000), "1-atom loss ok");
        assert!(!ins_mint_admissible(999_999, 999_999, 0, 0), "genesis below minimum");
        assert!(ins_mint_admissible(1_000_000, 1_000_000, 0, 0));
        assert!(ins_mint_admissible(0, 0, 5, 5));
    }

    #[test]
    fn r1_r2_r6_rules() {
        // R-1: only externally sourced asset-0 prices, unless the devnet override.
        assert!(!g9_oracle_allowed(0, 0, false), "Manual refused");
        assert!(!g9_oracle_allowed(3, 0, false), "AuthMark refused");
        assert!(!g9_oracle_allowed(2, 0, false), "leg-less EWMA refused");
        assert!(g9_oracle_allowed(1, 1, false), "Hybrid with a leg allowed");
        assert!(g9_oracle_allowed(2, 1, false), "EWMA with an external leg allowed");
        assert!(!g9_oracle_allowed(1, 0, false));
        assert!(g9_oracle_allowed(3, 0, true), "devnet override");
        assert_eq!(g9_senior_drawn_room(150, 100), 50);
        assert_eq!(g9_senior_drawn_room(100, 150), 0);
        // R-2: 1 atom that burns 1 unit worth 428,571 atoms is refused; a full-class exit is not.
        assert!(!ins_burn_admissible(1, 1, 7, 3_000_000, 7));
        assert!(ins_burn_admissible(1, 7, 7, 3_000_000, 7), "full-class exit");
        assert!(ins_burn_admissible(1_000_000, 1_000_000, 1_000_000, 1_000_000, 2_000_000));
        assert!(ins_burn_admissible(0, 0, 0, 0, 0));
        // R-6: 10% of IM stays above the floor.
        assert_eq!(backstop_restore_free(1_600_000, 1_000_000, 5_000_000), 500_000);
        assert_eq!(backstop_restore_free(1_050_000, 1_000_000, 5_000_000), 0);
        assert_eq!(backstop_restore_free(3_000_000, 0, 400_000), 400_000, "flat LP: capital");
        assert_eq!(backstop_restore_free(1_000, 1, 5_000), 998, "buffer rounds up");
    }

    /// R-1, both build flavours: the handler's gate is `g9_oracle_allowed(.., cfg!(devnet))`, so a
    /// mainnet build (no `devnet`) has NO override and a creator-pushed oracle is always refused.
    #[test]
    fn r1_build_flavour() {
        let devnet = cfg!(feature = "devnet");
        assert_eq!(g9_oracle_allowed(3, 0, devnet), devnet, "AuthMark: devnet only");
        assert_eq!(g9_oracle_allowed(0, 0, devnet), devnet, "Manual: devnet only");
        assert!(g9_oracle_allowed(1, 1, devnet), "Hybrid: both flavours");
    }

    #[test]
    fn w2_g9_gates() {
        assert!(!g9_delay_elapsed(0, u64::MAX));
        assert!(!g9_delay_elapsed(100, 100 + G9_DELAY_SLOTS - 1));
        assert!(g9_delay_elapsed(100, 100 + G9_DELAY_SLOTS));
        assert!(!g9_delay_elapsed(100, 100 + G9_DELAY_SLOTS + G9_EXEC_WINDOW_SLOTS), "lapsed");
        assert!(g9_proposal_open(100, 100));
        assert!(!g9_proposal_open(0, 100));
        assert!(!g9_proposal_open(100, 100 + G9_DELAY_SLOTS + G9_EXEC_WINDOW_SLOTS));
        assert_eq!(g9_epoch_room(1_000, 0, 2_000), 200);
        assert_eq!(g9_epoch_room(1_000, 150, 2_000), 50);
        assert_eq!(g9_epoch_room(1_000, 250, 2_000), 0);
        assert!(!g9_vault_eligible(0, 5));
        assert!(!g9_vault_eligible(5, 0));
        assert!(g9_vault_eligible(5, 5));
    }

    #[test]
    fn backstop_bounds() {
        assert!(backstop_due(10, 0, 0, 0));
        assert!(!backstop_due(10, 1, 0, 0));
        assert!(!backstop_due(10, 0, 1, 0));
        assert!(!backstop_due(0, 0, 0, 0));
        // Reserved-but-not-drawable senior backing: not due.
        assert!(!backstop_due(10, 0, 0, 1));
        // cap 50% of (I + outstanding) = 50 of 100.
        assert_eq!(backstop_draw_amount(1_000, 100, 100, 0, 5_000), 50);
        assert_eq!(backstop_draw_amount(1_000, 100, 60, 40, 5_000), 10);
        assert_eq!(backstop_draw_amount(5, 100, 100, 0, 5_000), 5);
        assert_eq!(backstop_draw_amount(1_000, 7, 100, 0, 5_000), 7);
        assert_eq!(backstop_restore_amount(10, 4, 0), 4);
        assert_eq!(backstop_restore_amount(10, 40, 3), 3);
        assert_eq!(backstop_recovery_split(7, 10), (7, 0));
        assert_eq!(backstop_recovery_split(17, 10), (10, 7));
        assert_eq!(vault_value_net_of_backstop(5, 10), 0);
    }

    #[test]
    fn rescue_rules() {
        let (v, c, s) = (620_000_000u128, 1_000_000_000u128, 1_000_000_000u128);
        assert_eq!(rescue_admitted(200_000_000, v, c, s), Ok(()));
        assert_eq!(rescue_admitted(200_000_000, c, c, s), Err(RescueRefusal::NotImpaired));
        assert_eq!(rescue_admitted(200_000_000, 49_999_999, c, s), Err(RescueRefusal::NavFloor));
        assert_eq!(rescue_admitted(99_999_999, v, c, s), Err(RescueRefusal::Amount));
        assert_eq!(rescue_admitted(v * 10 + 1, v, c, s), Err(RescueRefusal::Amount));
        assert_eq!(rescue_admitted(200_000_000, v, c, 0), Err(RescueRefusal::Shape));
        let x = 310_000_000u128;
        let m = rescue_shares(x, s, v).unwrap();
        // Bought at 0.62 per share, never at par: m > x * S / C.
        assert_eq!(m, 500_000_000);
        assert!(m > x * s / c);
        let dc = rescue_claim_delta(m, c, s).unwrap();
        assert_eq!(dc, 500_000_000);
        assert!(rescue_value_no_dilution(v, x, s, m));
        assert!(rescue_claim_no_dilution(v, c, s, m, dc));
        assert!(rescue_par_per_share_not_raised(c, s, m, dc));
        // Negative control: one share too many (a ceil mint at an exact boundary) breaks L-RES.
        assert!(!rescue_value_no_dilution(1, 1, 1, 3));
    }
}
