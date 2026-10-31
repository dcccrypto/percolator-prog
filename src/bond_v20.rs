//! Phase 4 item 3 (2026-10-05): capacity bonds, the mezzanine tranche of a bound vault.
//!
//! Spec: `~/percolator-ops/ledger/phase4-design-2026-10-05.md` item 3. Pure, integer-only math,
//! free of `AccountInfo`, syscalls and engine types, so every function is a Kani / proptest
//! target. `None` always means "fail closed" (overflow or a corrupt input), never "allow".
//!
//! # Loss waterfall
//! junior (creator) -> **bonds** -> Earn seniors -> insurance -> winner haircut last.
//!
//! # Representation (lazy, path-independent)
//! The bond tranche holds ONE pooled principal claim `C_b` over `B` bond shares. `C_b` moves
//! only with bond deposits (+amount), bond redemptions (-pro-rata slice) and credited coupons
//! (+coupon). It is NOT written down by a senior draw. The bond's VALUE is the middle layer of the
//! three-way split of the vault value `V` (`tranche_split3`):
//!
//! ```text
//! senior = min(V, C_s)          // C_s = the senior claim C (C_eff where pending fees count)
//! bond   = min(V - senior, C_b)
//! junior = V - senior - bond
//! ```
//!
//! Why no booking is needed: the P3 senior draw books
//! `senior_loss = max(0, moved - (cover - C_eff))`, i.e. it already treats EVERY atom of the pots
//! above `C_eff` (junior AND bond value) as subordinate to the seniors. So the seniors' ledger is
//! identical with or without bonds, and the split hands any loss beyond the junior to the bonds
//! before the seniors (I-T3) and any recovery to the seniors' booked outstanding first, then to
//! the bonds up to `C_b`, then to the junior (I-T4). `draw_step3` / `recover3` below are the
//! explicit three-layer model; tests and the Kani design prove the lazy representation equal to it.
//!
//! Units: collateral atoms for value/claims, bond-share base units for shares, engine Q for
//! open interest and `N_cap`, bps out of 10_000, slots for time.

use crate::vault_lp_v18::{
    bps_ceil, bps_floor, cushion_split, junior_floor_atoms, mul_div_floor, vault_lp_draw_move,
    vault_lp_draw_step, vault_lp_recover, DrawLedger, DrawState, ALLOC_MIN_JUNIOR_BPS, BPS,
};

// ── Protocol bounds (founder decision 3: coupon 8%/yr + utilisation bonus, cap 50%, cooldown
//    9,000 slots). `InitBondTranche` (tag 107) refuses anything outside them. ──────────────────

/// Solana slots per year at 400 ms (2.5 slots/s * 86,400 * 365).
pub const SLOTS_PER_YEAR: u128 = 78_840_000;
/// Base coupon ceiling: 20%/yr. Coupons are paid from the LP fee leg BEFORE the seniors, so an
/// unbounded coupon would let a creator holding bonds redirect every Earn fee to itself.
pub const BOND_COUPON_MAX_BPS: u16 = 2_000;
/// Utilisation-bonus ceiling: 0 (security review L-2, 2026-10-05). Max-side OI is washable with
/// self-hedged positions, so `InitBondTranche` REJECTS any non-zero bonus until a wash-resistant
/// utilisation metric exists. The rate plumbing stays (inert at 0).
pub const BOND_UTIL_BONUS_MAX_BPS: u16 = 0;
/// Coupon ceiling per crank, bps of the harvested LP fee leg (security review M-2, safe default
/// pending founder review): the coupon can never take more than half of a fee leg, so Earn keeps
/// at least half of every leg whatever the bond rate.
pub const BOND_COUPON_MAX_LEG_BPS: u16 = 5_000;
/// Withdrawal cooldown floor (~1 h): coupon farming around a fee crank is worthless.
pub const BOND_COOLDOWN_MIN_SLOTS: u32 = 9_000;
/// Withdrawal cooldown ceiling (~7 days).
pub const BOND_COOLDOWN_MAX_SLOTS: u32 = 1_512_000;
/// Concentration cap ceiling: bonds may never exceed 50% of `C_eff + junior`.
pub const BOND_CAP_MAX_BPS: u16 = 5_000;

/// `InitBondTranche` parameter bounds. A cap of 0 would make the tranche permanently unusable;
/// it is refused as a config error rather than silently accepted.
pub fn bond_config_ok(coupon_bps: u16, util_bonus_bps: u16, cooldown_slots: u32, cap_bps: u16) -> bool {
    coupon_bps <= BOND_COUPON_MAX_BPS
        // `bonus <= BOND_UTIL_BONUS_MAX_BPS`, written so it stays meaningful while the ceiling is 0.
        && BOND_UTIL_BONUS_MAX_BPS.checked_sub(util_bonus_bps).is_some()
        && (BOND_COOLDOWN_MIN_SLOTS..=BOND_COOLDOWN_MAX_SLOTS).contains(&cooldown_slots)
        && (1..=BOND_CAP_MAX_BPS).contains(&cap_bps)
}

// ── Three-tranche split (I-T1, I-T2) ────────────────────────────────────────────────────────

/// The vault's value split senior / bond / junior. `senior + bond + junior == V` always.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrancheSplit3 {
    pub senior: u128,
    pub bond: u128,
    pub junior: u128,
}

/// `senior = min(V, C_s)`, `bond = min(V - senior, C_b)`, `junior = V - senior - bond`.
///
/// Properties (`kani_g7_waterfall_junior_bond_senior_order`): conservation; `senior <= C_s`,
/// `bond <= C_b`; `junior > 0 => bond == C_b && senior == C_s`; `bond < C_b => junior == 0`;
/// `senior < C_s => bond == 0 && junior == 0`. With `C_b == 0` it is exactly the P3 two-tranche
/// `tranche_split` (I-T8: bonds are inert until a tranche exists). Path-independent: a function
/// of `(V, C_s, C_b)` only, so crank timing cannot move value between the tranches.
pub fn tranche_split3(vault_value: u128, senior_claim: u128, bond_claim: u128) -> TrancheSplit3 {
    let senior = if vault_value < senior_claim {
        vault_value
    } else {
        senior_claim
    };
    let rest = vault_value - senior;
    let bond = if rest < bond_claim { rest } else { bond_claim };
    TrancheSplit3 {
        senior,
        bond,
        junior: rest - bond,
    }
}

/// The bond tranche is impaired iff its value is below its claim.
pub fn bond_impaired(vault_value: u128, senior_claim: u128, bond_claim: u128) -> bool {
    tranche_split3(vault_value, senior_claim, bond_claim).bond < bond_claim
}

/// The vault value at the price WORSE for the vault LP (the E-1 rule tag 77 uses): a positive
/// worse equity counts at most the LP's value at the effective price; a negative one is a deficit
/// that comes out of the pots. `nav_plus_h` is backing NAV plus the harvestable fee leg.
pub fn vault_value_worse(nav_plus_h: u128, lp_value_at_eff: u128, lp_equity_worse: i128) -> u128 {
    if lp_equity_worse >= 0 {
        let w = lp_equity_worse as u128;
        nav_plus_h.saturating_add(if lp_value_at_eff < w { lp_value_at_eff } else { w })
    } else {
        nav_plus_h.saturating_sub(lp_equity_worse.unsigned_abs())
    }
}

// ── Junior-facing gates generalised to three tranches ────────────────────────────────────────

/// Tag 97 junior withdrawal with bonds: (a) the seniors are covered by the pots alone
/// (`backing_cover >= C_eff`; the junior and the bonds exit through the vault LP, never from
/// senior backing) and (b) `amount + floor <= junior` where `junior` is the THREE-way residual
/// `V - senior - bond`, so the junior can never withdraw bond value. `C_b == 0` is exactly
/// `vault_lp_v18::junior_withdraw_allowed`.
pub fn junior_withdraw_allowed3(
    vault_value: u128,
    senior_claim_eff: u128,
    bond_claim: u128,
    backing_cover: u128,
    amount: u128,
    junior_floor_bps: u16,
) -> bool {
    if backing_cover < senior_claim_eff {
        return false;
    }
    let junior = tranche_split3(vault_value, senior_claim_eff, bond_claim).junior;
    let floor = match junior_floor_atoms(senior_claim_eff, junior_floor_bps) {
        Some(f) => f,
        None => return false,
    };
    match amount.checked_add(floor) {
        Some(need) => need <= junior,
        None => false,
    }
}

/// Tag 103 L-3 with bonds: the JUNIOR alone (not junior + bonds) must be at least
/// `ALLOC_MIN_JUNIOR_BPS` of `C_eff`. Bonds can leave (subject to the lock), so counting them as
/// the first-loss buffer would let a bond deposit unlock an allocation and a later bond exit leave
/// Earn capital in the vault LP on a near-zero junior. Tighten-only. `C_b == 0` is exactly
/// `vault_lp_v18::alloc_junior_ok`.
pub fn alloc_junior_ok3(vault_value: u128, senior_claim_eff: u128, bond_claim: u128) -> bool {
    let junior = tranche_split3(vault_value, senior_claim_eff, bond_claim).junior;
    match bps_ceil(senior_claim_eff, ALLOC_MIN_JUNIOR_BPS) {
        Some(need) => junior >= need,
        None => false,
    }
}

/// Tag 102 Resolved (terminal) junior surplus with bonds: what the pots physically hold over the
/// seniors' claim AND the bonds' full claim. The junior is paid only after every bond is whole.
pub fn resolved_junior_surplus3(physical: u128, senior_claim: u128, bond_claim: u128) -> u128 {
    tranche_split3(physical, senior_claim, bond_claim).junior
}

/// Tag 110 Resolved (terminal) bond value: the bonds' layer of the pots' physical backing.
pub fn resolved_bond_value(physical: u128, senior_claim: u128, bond_claim: u128) -> u128 {
    tranche_split3(physical, senior_claim, bond_claim).bond
}

// ── Pricing (I-T5) ───────────────────────────────────────────────────────────────────────────

/// Bond shares minted for `amount` against the bond tranche value. Genesis (`B == 0`) mints 1:1.
/// A zero value with outstanding shares fails closed (the processor refuses deposits into an
/// impaired tranche anyway). Rounds DOWN, so incumbents are never diluted:
/// `(bond + amount) / (B + minted) >= bond / B` (`kani_g7_bond_deposit_no_dilution`).
pub fn bond_shares_for_deposit(amount: u128, total_shares: u128, bond_value: u128) -> Option<u128> {
    if total_shares == 0 {
        return Some(amount);
    }
    if bond_value == 0 {
        return None;
    }
    mul_div_floor(amount, total_shares, bond_value)
}

/// Bond redemption payout `floor(shares * bond_value / B)` (the caller passes the value at the
/// price worse for the vault). `shares > B` or `B == 0` fails closed.
pub fn bond_atoms_for_redemption(shares: u128, total_shares: u128, bond_value: u128) -> Option<u128> {
    if total_shares == 0 || shares > total_shares {
        return None;
    }
    mul_div_floor(shares, bond_value, total_shares)
}

/// `C_b` after `shares` of `B` are redeemed: `C_b - floor(shares * C_b / B)`. Removing exactly
/// the pro-rata slice (rounded DOWN) keeps every remaining share's claim non-decreasing; when
/// the tranche is whole the slice equals the payout. Redeeming every share leaves `C_b == 0`.
pub fn bond_claim_after_redemption(bond_claim: u128, shares: u128, total_shares: u128) -> Option<u128> {
    if total_shares == 0 || shares > total_shares {
        return None;
    }
    let slice = mul_div_floor(shares, bond_claim, total_shares)?;
    bond_claim.checked_sub(slice)
}

/// Concentration cap (tag 108): `C_b after <= floor(cap * (C_eff + junior))`.
pub fn bond_cap_ok(bond_claim_after: u128, senior_claim_eff: u128, junior: u128, cap_bps: u16) -> bool {
    let base = match senior_claim_eff.checked_add(junior) {
        Some(b) => b,
        None => return false,
    };
    match bps_floor(base, cap_bps) {
        Some(cap) => bond_claim_after <= cap,
        None => false,
    }
}

/// Tag 108 concentration cap read at the price WORSE for the vault (GH#574): the junior is
/// `tranche_split3(v_worse, ..).junior`, the same reading the impairment check uses, so a lagging
/// price cannot admit a deposit the worse-price reading would refuse. `v_worse` must already be
/// net of any G9 backstop receivable.
pub fn bond_deposit_cap_ok_at_worse(
    v_worse: u128,
    senior_claim_eff: u128,
    bond_claim_before: u128,
    bond_claim_after: u128,
    cap_bps: u16,
) -> bool {
    let junior = tranche_split3(v_worse, senior_claim_eff, bond_claim_before).junior;
    bond_cap_ok(bond_claim_after, senior_claim_eff, junior, cap_bps)
}

// ── Lock against open interest (I-T6, the self-funding attack) ───────────────────────────────

/// A bond withdrawal (tag 110) executes only if the vault LP's growth capacity AFTER the
/// withdrawal still covers the market's open interest on EITHER side and the vault LP's own
/// ADL-effective inventory: `N_cap(C_m - x) >= max(OI_long, OI_short, |LP_eff|)`.
///
/// This is the A4 lock applied to OPEN exposure, not to converted claims: the adversarial review
/// (2026-06-01) showed a bond that can leave while the OI it enabled is open is ~10x B/S of free
/// amplification (post bond, others open against the larger capacity, withdraw, gap). `None`
/// (growth OFF on the asset: no capacity number) is refused unless nothing is open at all.
pub fn bond_withdraw_lock_ok(
    n_cap_after: Option<u128>,
    oi_long_q: u128,
    oi_short_q: u128,
    lp_eff_abs_q: u128,
) -> bool {
    let side = if oi_long_q > oi_short_q { oi_long_q } else { oi_short_q };
    let need = if side > lp_eff_abs_q { side } else { lp_eff_abs_q };
    match n_cap_after {
        Some(n) => n >= need,
        None => need == 0,
    }
}

/// The request-then-execute cooldown has elapsed. Saturating: a request slot near `u64::MAX`
/// never elapses early.
pub fn bond_cooldown_elapsed(now_slot: u64, request_slot: u64, cooldown_slots: u32) -> bool {
    now_slot >= request_slot.saturating_add(cooldown_slots as u64)
}

// ── Coupon (I-T7, cumulative since GH#571) ─────────────────────────────────────────────────
//
// I-T7 (GH#571, 2026-10-31, founder decision "carried-over coupon"; revised after the att649
// review): the coupon is CUMULATIVE and is never forfeited by a settlement, a deposit, a dust
// crank or an exit. Two numbers in `BondTrancheV20`:
//
// * `K = c_b_atoms`: the bonds' WHOLE claim (deposits + every settled coupon - redeemed slices).
//   Every tranche split reads `K`; shares are priced at `K / B`.
// * `R = coupon_arrears_atoms`: the coupon RECEIVABLE, i.e. settled coupon the fee legs have not
//   yet funded. Until a fee leg pays it, the junior has fronted it (it sits in `K`, above the
//   junior in `tranche_split3`), so `R` is what the fee legs still owe the junior. Exits never
//   reduce it (it can outlive the last bond).
// * `U = coupon_unfunded_atoms`: the CAP METER, the unfunded coupon carried by the CURRENT
//   shares, kept at the pool's per-share ratio: a deposit labels the new shares at that ratio,
//   an exit removes its pro-rata slice, a fee payment lowers it. So the cap is per share: a
//   round trip, a newcomer or a leaver never resets or starves anyone's headroom.
//
// * Accrual (gate open, `coupon_gate_open` on `K`: Live, non-empty, no senior draw outstanding,
//   tranche whole): `x = floor((min(K, value) * rate * dt + rem) / D)`, `D = 1e4 * 1y`, and
//   `K += x`, `R += x`, `U += x`; the sub-atom remainder `rem` is CARRIED in `coupon_accrual_rem`, so
//   settling often (a crank every slot) loses nothing. The base is the whole claim `K`, so every
//   atom of claim earns the same rate: pricing at `K / B` is newcomer-neutral. Gate closed: the
//   interval is forfeited (M-1, unchanged); `K`, `R`, `U`, `rem` are kept.
// * Cap: `U <= coupon_due(K - U, rate, 1y)`, one year of coupon on the current shares' funded
//   claim. Accrual beyond it is forfeited (and `rem` dropped). Every share fronts at most one
//   year of unfunded coupon, so the junior's exposure is bounded per share.
// * Payment (tag 78): `min(R, floor(leg / 2))` (M-2 unchanged) is paid off the top of the fee leg:
//   `R` drops by the coupon and `U` by `min(U, coupon)`, `K` does NOT change, so the coupon atoms
//   land in the junior's residual: the junior is reimbursed. Paid while Live with no senior draw outstanding and the tranche whole;
//   ALSO when the tranche is empty (`K == 0`): the receivable outlives the last bond.
// * Deposit (108): settles to now (`rem` zeroed: the INCUMBENTS forfeit < 1 atom, the newcomer
//   never shares their unsettled interval), mints `floor(d * B / K)`, `K += d`,
//   `U += ceil(d * U / K)` (the new shares carry the pool's ratio); `R` unchanged.
// * Exit (110): settles to now, pays `floor(sh * layer(K) / B)`, removes `floor(sh * K / B)` from
//   `K` (`bond_claim_after_redemption`, the pre-#571 slice) and `floor(sh * U / B)` from `U`; `R`
//   is NOT touched. A deposit/redeem round trip is therefore neutral (att649 F1): it cannot turn
//   the receivable into funded claim, cannot cancel the junior's reimbursement and cannot reset
//   the per-share cap (the ratio `U / K` is preserved up to rounding against the actor).
// * Rounding: always against the actor (108 mint floor, 110 payout floor, 78 coupon floor);
//   accrual floors only the final sub-atom (carried).
// * Seniority: `K` sits in the bond layer of `tranche_split3`, JUNIOR to the Earn seniors and the
//   G9 backstop, SENIOR to the junior (creator) tranche and its cushion (tags 97 / 102 / 103 and
//   the G6 cushion level read `K`). A 110 exit takes settled coupon out of the junior's capital
//   when the fee legs have not funded it; `R` records that and later fee legs repay it.
// * Closed windows (att649 F2): an interval accrues only if the gate is open at BOTH of its ends
//   (now, and as recorded by the previous settlement in `coupon_gate_seen`) and no senior draw
//   was booked inside it (the cumulative `senior_drawn_atoms` is unchanged). So a draw window, or
//   an impairment seen at a settlement, is forfeited even if it reopened before anyone settled;
//   nobody needs to crank inside the window. Conservative for the junior: the whole interval
//   that touches a closed sample is forfeited. Not seen: an impairment that starts and ends
//   strictly between two settlements without a draw (inherent to sampling).
// * Resolve: nothing accrues once the market is not Live; terminal 78 pays no coupon. Settled
//   coupon stays in `K` and is paid by the Resolved 110 before the junior (102); an unpaid `R`
//   is not repaid to the junior after resolution (no more fee legs).

/// Utilisation of the bond-backed capacity, bps: `min(1, max side OI / N_cap)`. 0 with no OI;
/// full with OI but no capacity number.
pub fn bond_util_bps(max_side_oi_q: u128, n_cap_q: u128) -> u16 {
    if max_side_oi_q == 0 {
        return 0;
    }
    if n_cap_q == 0 {
        return BPS as u16;
    }
    match max_side_oi_q.checked_mul(BPS) {
        Some(p) => {
            let u = p / n_cap_q;
            if u >= BPS {
                BPS as u16
            } else {
                u as u16
            }
        }
        None => BPS as u16,
    }
}

/// The annual coupon rate for one accrual interval: `base + floor(bonus * u / 10_000)` with the
/// interval's utilisation `u` taken as `min(u_last, u_now)` by the caller (a single crank can
/// never pick a favourable endpoint on its own).
pub fn bond_coupon_rate_bps(base_bps: u16, util_bonus_bps: u16, util_bps: u16) -> u32 {
    let u = if (util_bps as u128) > BPS { BPS as u32 } else { util_bps as u32 };
    base_bps as u32 + (util_bonus_bps as u32 * u) / BPS as u32
}

/// Coupon accrued over `dslots` on the pooled principal claim `C_b`:
/// `floor(C_b * rate * min(dslots, 1y) / (10_000 * SLOTS_PER_YEAR))`.
///
/// One accrual interval, floored (`coupon_settle` carries the remainder and the receivable,
/// GH#571 I-T7 above; this is the cap and the pre-#571 form). Clamped to one year.
/// `None` only on a corrupt `C_b`: the product
/// `C_b * rate * SLOTS_PER_YEAR` must fit u128, i.e. `C_b < 2^128 / (3_000 * 78.84e6) ~ 2^90.2`,
/// ~2^26 above any SPL-representable (u64) claim.
pub fn coupon_due(bond_claim: u128, rate_bps: u32, dslots: u64) -> Option<u128> {
    let dt = if (dslots as u128) > SLOTS_PER_YEAR {
        SLOTS_PER_YEAR
    } else {
        dslots as u128
    };
    let num = bond_claim.checked_mul(rate_bps as u128)?;
    mul_div_floor(num, dt, BPS.checked_mul(SLOTS_PER_YEAR)?)
}

/// Coupon gate: paid only on a Live market, from a non-empty tranche, while NO senior principal
/// loss is outstanding (the coupon never takes priority over Earn principal) AND while the bond
/// tranche itself is whole (`bond_value >= bond_claim`, security review M-1): an impaired tranche
/// earns nothing, so Earn's fee leg never recapitalises it. `bond_value` is the bonds' layer of the
/// vault value BEFORE this crank's fee leg. GH#571: `bond_claim = K` includes the settled coupon,
/// so a tranche whose settled coupon is not backed is impaired and accrues nothing more.
pub fn coupon_gate_open(live: bool, bond_claim: u128, senior_draw_outstanding: u128, bond_value: u128) -> bool {
    live && bond_claim > 0 && senior_draw_outstanding == 0 && bond_value >= bond_claim
}

/// The claim the coupon accrues on: `min(bond_claim, bond value)` (security review M-1; equals the
/// explicit model's written-down principal). GH#571: `bond_claim = K`, and with the gate above
/// the base is `K` whenever anything accrues; kept separate so the base can never exceed
/// the bond's value even if the gate is relaxed later.
pub fn coupon_base(bond_claim: u128, bond_value: u128) -> u128 {
    if bond_value < bond_claim {
        bond_value
    } else {
        bond_claim
    }
}

/// Take the coupon off the TOP of one harvested LP fee leg: `(coupon, rest)` with
/// `coupon = min(due, floor(available * BOND_COUPON_MAX_LEG_BPS / 1e4))` and
/// `coupon + rest == available`. Paid only from the fee leg, never from principal, never more than
/// half of it (M-2). Tag 78 passes the receivable `R` as `due`; the unpaid part stays in `R`
/// (GH#571, cumulative), `coupon_pay_from_leg`.
pub fn bond_coupon_split(available: u128, due: u128) -> (u128, u128) {
    let cap = bps_floor(available, BOND_COUPON_MAX_LEG_BPS).unwrap_or(0);
    let coupon = if due < cap { due } else { cap };
    (coupon, available - coupon)
}

/// GH#571: the accrual denominator `BPS * SLOTS_PER_YEAR`; a numerator below it is a sub-atom.
pub const COUPON_DENOM: u128 = BPS * SLOTS_PER_YEAR;

/// GH#571: the FUNDED part of the current shares' claim, `K - U` (saturating).
pub fn bond_funded_claim(bond_claim: u128, unfunded: u128) -> u128 {
    bond_claim.saturating_sub(unfunded)
}

/// GH#571: the cap on the meter `U`, one year of coupon on the funded claim `K - U` at `rate_bps`.
pub fn coupon_arrears_cap(funded_claim: u128, rate_bps: u32) -> Option<u128> {
    coupon_due(funded_claim, rate_bps, SLOTS_PER_YEAR as u64)
}

/// GH#571: settle the coupon accrued over `dslots` (I-T7 above). Returns `(x, rem')`: the atoms
/// to add to the claim `K`, the receivable `R` and the meter `U`, and the new carried sub-atom
/// remainder.
///
/// * gate closed: `(0, rem)` (the interval is forfeited; nothing settled is touched);
/// * gate open: `num = min(K, bond_value) * rate * min(dslots, 1y) + rem`,
///   `x = min(floor(num / D), cap - U)` with `cap = coupon_arrears_cap(K - U, rate)`;
///   `rem' = num mod D` when the cap does not bind, else 0 (the excess is forfeited).
///
/// `None` (fail closed) on overflow: needs `min(K, value) * rate * 1y < 2^128` (`K < ~2^90`).
pub fn coupon_settle(
    bond_claim: u128,
    unfunded: u128,
    rem: u64,
    rate_bps: u32,
    dslots: u64,
    open: bool,
    bond_value: u128,
) -> Option<(u128, u64)> {
    coupon_settle_in(bond_claim, unfunded, rem, rate_bps, dslots, open, bond_value, SLOTS_PER_YEAR, COUPON_DENOM)
}

/// `coupon_settle` for a general one-year length `year` and denominator `denom` (production:
/// `SLOTS_PER_YEAR`, `COUPON_DENOM = BPS * year`). The same law at every `(year, denom)`; the
/// Kani harnesses (`kani/bonds571`) prove it over a bounded family of small parameters, the
/// full-width proptests check the production constants. The cap here is
/// `floor((K - U) * rate * year / denom)` = `coupon_arrears_cap` at the production constants.
#[allow(clippy::too_many_arguments)]
pub fn coupon_settle_in(
    bond_claim: u128,
    unfunded: u128,
    rem: u64,
    rate_bps: u32,
    dslots: u64,
    open: bool,
    bond_value: u128,
    year: u128,
    denom: u128,
) -> Option<(u128, u64)> {
    if !open {
        return Some((0, rem));
    }
    if denom == 0 {
        return None;
    }
    let dt = if (dslots as u128) > year { year } else { dslots as u128 };
    let num = coupon_base(bond_claim, bond_value)
        .checked_mul(rate_bps as u128)?
        .checked_mul(dt)?
        .checked_add(rem as u128)?;
    let due = num / denom;
    let cap = bond_funded_claim(bond_claim, unfunded)
        .checked_mul(rate_bps as u128)?
        .checked_mul(year)?
        / denom;
    let room = cap.saturating_sub(unfunded);
    if due > room {
        Some((room, 0))
    } else {
        Some((due, u64::try_from(num % denom).ok()?))
    }
}

/// GH#571 (att649 F2): the gate memory a settlement leaves behind (`coupon_gate_seen`): the low
/// 63 bits of the cumulative, monotone `senior_drawn_atoms`, and bit 63 set iff the coupon gate
/// is CLOSED as of this settlement.
pub fn coupon_gate_seen(senior_drawn: u128, open_now: bool) -> u64 {
    let drawn = senior_drawn as u64 & !(1u64 << 63);
    if open_now { drawn } else { drawn | (1u64 << 63) }
}

/// GH#571 (att649 F2): may the interval since the last settlement accrue? Only if the gate was
/// OPEN at that settlement and no senior draw was booked since (the drawn counter is unchanged).
/// With the gate open NOW (checked by the caller) the interval is open at both ends; a window
/// that closed and reopened between settlements is forfeited. (Conservative: an impairment that
/// both starts and ends strictly inside one interval without a draw is not seen, inherent to
/// sampling at settlement points.)
pub fn coupon_interval_clean(seen: u64, senior_drawn: u128) -> bool {
    seen == coupon_gate_seen(senior_drawn, true)
}

/// GH#571, tag 78: pay the receivable `R` off the top of one fee leg.
/// Returns `(coupon, rest, R - coupon)`; `coupon + rest == available`, `coupon <= R`,
/// `coupon <= floor(available / 2)` (M-2). The claim `K` is unchanged by the payment.
pub fn coupon_pay_from_leg(available: u128, receivable: u128) -> (u128, u128, u128) {
    let (coupon, rest) = bond_coupon_split(available, receivable);
    (coupon, rest, receivable - coupon)
}

/// GH#571, tag 108: the meter after a deposit of `amount` into a claim `bond_claim` (before the
/// deposit): `U + ceil(amount * U / K)`, the new shares carry the pool's ratio (rounded against
/// the depositor). `K == 0` (genesis): `U` (0). `None` on overflow.
pub fn coupon_meter_after_deposit(unfunded: u128, bond_claim: u128, amount: u128) -> Option<u128> {
    if bond_claim == 0 {
        return Some(unfunded);
    }
    let label = amount.checked_mul(unfunded)?.div_ceil(bond_claim);
    unfunded.checked_add(label)
}

/// GH#571, tag 110: the meter after `shares` of `total_shares` are redeemed: `U - floor(sh * U / B)`
/// (the stayers keep the rounding; a full exit leaves 0). `None` on `B == 0`, `sh > B`, overflow.
pub fn coupon_meter_after_redemption(unfunded: u128, shares: u128, total_shares: u128) -> Option<u128> {
    if total_shares == 0 || shares > total_shares {
        return None;
    }
    unfunded.checked_sub(mul_div_floor(shares, unfunded, total_shares)?)
}

/// GH#571, tag 78: may this crank PAY the receivable? Live and no senior draw outstanding
/// (the coupon never takes priority over Earn principal), and either the accrual gate is open
/// (tranche whole, M-1) or the tranche is EMPTY (`K == 0`: nothing to recapitalise, the
/// receivable outlives the last bond and is still the junior's).
pub fn coupon_pay_open(accrual_open: bool, live: bool, bond_claim: u128, senior_draw_outstanding: u128) -> bool {
    accrual_open || (live && bond_claim == 0 && senior_draw_outstanding == 0)
}

/// The full Phase 4 fee waterfall of one harvested LP leg (the composition tag 78 runs):
/// coupon first (`bond_coupon_split`), then the P2b G6 split of the rest (`cushion_split`: up to
/// `cushion_share` to the junior cushion until the target, the rest to the seniors).
/// Returns `(coupon, cushion, senior)`, summing to `available` exactly.
pub fn fee_waterfall3(
    available: u128,
    coupon_due_atoms: u128,
    cushion_share_bps: u16,
    cushion_target_bps: u16,
    c_eff: u128,
    junior_level: u128,
) -> Option<(u128, u128, u128)> {
    let (coupon, rest) = bond_coupon_split(available, coupon_due_atoms);
    let (senior, cushion) = cushion_split(rest, cushion_share_bps, cushion_target_bps, c_eff, junior_level)?;
    Some((coupon, cushion, senior))
}

// ── Explicit three-layer model of the draw and of recovery (proof targets) ───────────────────

/// One P3 draw step decomposed into the three layers. `s.junior_surplus` is the pots' value over
/// the senior claim (junior AND bond value, exactly what the processor's booking reads);
/// `bond_claim` is `C_b`. The physical move and the senior loss are the PRODUCTION
/// `vault_lp_draw_step`; the subordinate cover is split junior-first:
/// `junior_cover = min(sub_cover, s.junior_surplus - min(s.junior_surplus, C_b))`,
/// `bond_cover = sub_cover - junior_cover`.
/// Returns `(next, moved, junior_cover, bond_cover, senior_loss)`.
pub fn draw_step3(
    s: DrawState,
    bond_claim: u128,
    current_deficit: u128,
) -> (DrawState, u128, u128, u128, u128) {
    let (sub_cover, _senior_draw) = vault_lp_draw_move(current_deficit, s.junior_surplus, s.drawable);
    let (next, moved, senior_loss) = vault_lp_draw_step(s, current_deficit);
    let bond_in_pots = if s.junior_surplus < bond_claim {
        s.junior_surplus
    } else {
        bond_claim
    };
    let junior_in_pots = s.junior_surplus - bond_in_pots;
    let junior_cover = if sub_cover < junior_in_pots {
        sub_cover
    } else {
        junior_in_pots
    };
    (next, moved, junior_cover, sub_cover - junior_cover, senior_loss)
}

/// Recovery in the three-layer order with the LEDGER's own senior outstanding: the value above
/// `C_s` restores the seniors' booked loss FIRST (production `vault_lp_recover`), then the split
/// hands the bonds up to `C_b`, then the junior. (Item 6's insurance backstop, when built, sits
/// before the seniors.) Returns `(senior_claim', senior_outstanding', split)`.
pub fn recover3(
    vault_value: u128,
    senior_claim: u128,
    senior_outstanding: u128,
    bond_claim: u128,
) -> (u128, u128, TrancheSplit3) {
    let (l, _to_seniors) = vault_lp_recover(
        DrawLedger {
            senior_claim,
            drawn: senior_outstanding,
            outstanding: senior_outstanding,
            pending: 0,
        },
        vault_value.saturating_sub(senior_claim),
    );
    (
        l.senior_claim,
        l.outstanding,
        tranche_split3(vault_value, l.senior_claim, bond_claim),
    )
}

/// The impairment the tranche shows right now (`C_b - bond value`), stored in
/// `BondTrancheV20::bond_drawn_outstanding_atoms` as an informational mirror for clients. The
/// split is authoritative; nothing prices off the mirror.
pub fn bond_impairment(vault_value: u128, senior_claim: u128, bond_claim: u128) -> u128 {
    bond_claim - tranche_split3(vault_value, senior_claim, bond_claim).bond
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_lp_v18::{alloc_junior_ok, junior_withdraw_allowed, tranche_split};

    #[test]
    fn gh574_cap_is_read_at_the_worse_price() {
        // nav 10,000 + LP at eff 5,000, worse-lag equity 2,000: v = 15,000, v_worse = 12,000.
        let (nav, lp_eff, worse) = (10_000u128, 5_000u128, 2_000i128);
        let (c_eff, c_b, after, cap) = (9_000u128, 1_000u128, 2_500u128, 2_000u16);
        let v = nav + lp_eff;
        let v_worse = vault_value_worse(nav, lp_eff, worse);
        assert_eq!(v_worse, 12_000);
        // The old reading (junior at v, 5,000 -> cap 2,800) admits; the worse reading
        // (junior 2,000 -> cap 2,200) refuses.
        assert!(bond_cap_ok(after, c_eff, tranche_split3(v, c_eff, c_b).junior, cap));
        assert!(!bond_deposit_cap_ok_at_worse(v_worse, c_eff, c_b, after, cap));
        // No lag: both readings agree and the helper admits within the cap.
        assert!(bond_deposit_cap_ok_at_worse(v, c_eff, c_b, 2_800, cap));
        assert!(!bond_deposit_cap_ok_at_worse(v, c_eff, c_b, 2_801, cap));
    }


    #[test]
    fn split3_examples_and_two_tranche_equivalence() {
        // junior first, then bond, then senior
        assert_eq!(tranche_split3(1_000, 800, 150), TrancheSplit3 { senior: 800, bond: 150, junior: 50 });
        assert_eq!(tranche_split3(880, 800, 150), TrancheSplit3 { senior: 800, bond: 80, junior: 0 });
        assert_eq!(tranche_split3(700, 800, 150), TrancheSplit3 { senior: 700, bond: 0, junior: 0 });
        for (v, c) in [(0u128, 0u128), (5, 9), (9, 5), (u128::MAX, 1), (1, u128::MAX)] {
            let t = tranche_split(v, c);
            assert_eq!(tranche_split3(v, c, 0), TrancheSplit3 { senior: t.senior, bond: 0, junior: t.junior });
        }
    }

    #[test]
    fn junior_gates_equal_p3_without_bonds_and_exclude_bonds_with() {
        assert_eq!(
            junior_withdraw_allowed3(2_000, 1_000, 0, 1_000, 800, 1_000),
            junior_withdraw_allowed(2_000, 1_000, 1_000, 800, 1_000)
        );
        // V 2,000, C 1,000, floor 10% = 100: junior 1,000 -> 900 out. A 500 bond leaves 500 -> 400.
        assert!(junior_withdraw_allowed3(2_000, 1_000, 0, 1_000, 900, 1_000));
        assert!(!junior_withdraw_allowed3(2_000, 1_000, 500, 1_000, 401, 1_000));
        assert!(junior_withdraw_allowed3(2_000, 1_000, 500, 1_000, 400, 1_000));
        assert_eq!(alloc_junior_ok3(10_500, 10_000, 0), alloc_junior_ok(10_500, 10_000));
        assert!(!alloc_junior_ok3(10_500, 10_000, 1));
        assert_eq!(resolved_junior_surplus3(1_000, 600, 300), 100);
        assert_eq!(resolved_bond_value(800, 600, 300), 200);
    }

    #[test]
    fn coupon_examples() {
        // 1,000,000 atoms at 8%/yr for a full year = 80,000.
        assert_eq!(coupon_due(1_000_000, 800, SLOTS_PER_YEAR as u64), Some(80_000));
        // clamped at one year
        assert_eq!(coupon_due(1_000_000, 800, u64::MAX), Some(80_000));
        // one hour at 8% on 1e9: 1e9 * 800 * 9,000 / (1e4 * 78.84e6) = 9,132.42 -> 9,132
        assert_eq!(coupon_due(1_000_000_000, 800, 9_000), Some(9_132));
        assert_eq!(bond_coupon_rate_bps(800, 0, 5_000), 800);
        assert_eq!(bond_coupon_rate_bps(800, 1_000, 5_000), 1_300);
        assert_eq!(bond_coupon_rate_bps(800, 1_000, u16::MAX), 1_800);
        assert_eq!(bond_coupon_split(100, 30), (30, 70));
        assert_eq!(bond_coupon_split(100, 300), (50, 50), "never more than half the leg (M-2)");
        assert_eq!(bond_coupon_split(101, 300), (50, 51));
        assert_eq!(fee_waterfall3(1_000, 100, 5_000, 1_000, 10_000, 900), Some((100, 100, 800)));
        assert!(!coupon_gate_open(true, 1, 1, 1));
        assert!(!coupon_gate_open(false, 1, 0, 1));
        assert!(coupon_gate_open(true, 1, 0, 1));
        assert!(!coupon_gate_open(true, 10, 0, 9), "impaired tranche earns nothing (M-1)");
        assert_eq!(coupon_base(10, 4), 4);
        assert_eq!(coupon_base(10, 40), 10);
        assert_eq!(bond_util_bps(0, 0), 0);
        assert_eq!(bond_util_bps(1, 0), 10_000);
        assert_eq!(bond_util_bps(50, 100), 5_000);
        assert_eq!(bond_util_bps(500, 100), 10_000);
    }

    #[test]
    fn lock_and_config() {
        assert!(bond_withdraw_lock_ok(Some(100), 100, 40, 0));
        assert!(!bond_withdraw_lock_ok(Some(99), 100, 40, 0));
        assert!(!bond_withdraw_lock_ok(Some(99), 0, 0, 100));
        assert!(bond_withdraw_lock_ok(None, 0, 0, 0));
        assert!(!bond_withdraw_lock_ok(None, 1, 0, 0));
        assert!(bond_config_ok(800, 0, 9_000, 5_000));
        assert!(!bond_config_ok(800, 1, 9_000, 5_000), "non-zero utilisation bonus refused (L-2)");
        assert!(!bond_config_ok(2_001, 0, 9_000, 5_000));
        assert!(!bond_config_ok(800, 0, 8_999, 5_000));
        assert!(!bond_config_ok(800, 0, 9_000, 0));
        assert!(!bond_config_ok(800, 0, 9_000, 5_001));
        assert!(bond_cooldown_elapsed(9_000, 0, 9_000));
        assert!(!bond_cooldown_elapsed(8_999, 0, 9_000));
        assert!(!bond_cooldown_elapsed(u64::MAX - 1, u64::MAX - 5, 9_000));
        assert!(bond_cap_ok(500, 800, 200, 5_000));
        assert!(!bond_cap_ok(501, 800, 200, 5_000));
    }

    #[test]
    fn draw3_and_recover3_examples() {
        // pots 1,000 over C_s 800 -> surplus 200 = bond 150 + junior 50; deficit 120.
        let s = DrawState { senior_claim: 800, outstanding: 0, junior_surplus: 200, drawable: 1_000 };
        let (n, moved, jc, bc, sl) = draw_step3(s, 150, 120);
        assert_eq!((moved, jc, bc, sl, n.senior_claim), (120, 50, 70, 0, 800));
        // bond claim 200 but only 100 of surplus: the bond layer takes 100, seniors 50.
        let s = DrawState { senior_claim: 900, outstanding: 0, junior_surplus: 100, drawable: 1_000 };
        let (n, moved, jc, bc, sl) = draw_step3(s, 200, 150);
        assert_eq!((moved, jc, bc, sl, n.senior_claim, n.outstanding), (150, 0, 100, 50, 850, 50));
        // recovery to 1,150: seniors back to 900 first, bond 200 whole, junior 50.
        let (c, o, t) = recover3(1_150, 850, 50, 200);
        assert_eq!((c, o, t), (900, 0, TrancheSplit3 { senior: 900, bond: 200, junior: 50 }));
        // partial: 1,000 -> seniors 900 whole, bond 100 (impaired), junior 0.
        let (c, o, t) = recover3(1_000, 850, 50, 200);
        assert_eq!((c, o, t), (900, 0, TrancheSplit3 { senior: 900, bond: 100, junior: 0 }));
        assert_eq!(bond_impairment(1_000, 900, 200), 100);
    }

    #[test]
    fn pricing_examples() {
        assert_eq!(bond_shares_for_deposit(100, 0, 0), Some(100));
        assert_eq!(bond_shares_for_deposit(100, 1_000, 1_100), Some(90));
        assert_eq!(bond_shares_for_deposit(100, 1_000, 0), None);
        assert_eq!(bond_atoms_for_redemption(500, 1_000, 1_100), Some(550));
        assert_eq!(bond_atoms_for_redemption(1_001, 1_000, 1_100), None);
        assert_eq!(bond_claim_after_redemption(1_100, 1_000, 1_000), Some(0));
        assert_eq!(bond_claim_after_redemption(1_100, 333, 1_000), Some(1_100 - 366));
        assert_eq!(vault_value_worse(1_000, 300, 200), 1_200);
        assert_eq!(vault_value_worse(1_000, 300, 400), 1_300);
        assert_eq!(vault_value_worse(1_000, 0, -400), 600);
        assert_eq!(vault_value_worse(100, 0, -400), 0);
    }
}
