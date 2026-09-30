//! P3 (2026-09-29, `~/percolator-ops/ledger/p3-vault-owned-lp-2026-09-29.md`): pure,
//! integer-only math behind the vault-owned LP, the senior/junior tranche waterfall, skew
//! funding and the leverage step-down.
//!
//! Everything here is free of `AccountInfo`, syscalls and engine types so that every function
//! is a Kani / proptest target. The processor gathers inputs, calls these, and maps a `None` /
//! `false` onto a `PercolatorError`. `None` always means "fail closed" (overflow or a corrupt
//! input), never "allow".
//!
//! Units: collateral atoms for every value/claim/fee, shares are LP-share base units, positions
//! are engine Q (`POS_SCALE` per unit), prices are e6, bps are out of 10_000, funding rates are
//! e9-per-slot (the engine's `FUNDING_DEN` scale).

pub const BPS: u128 = 10_000;

/// Floor of `a * b / d`, `None` on `d == 0` or on an overflowing product. Every caller works in
/// SPL-u64-bounded quantities (amounts, shares), so `a * b` is `u64 * u64` and fits `u128`; an
/// overflow therefore means a corrupt input and fails closed.
pub fn mul_div_floor(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    a.checked_mul(b).map(|p| p / d)
}

/// `floor(x * bps / 10_000)` for `bps <= 10_000`, exact and overflow-free for every `u128` `x`:
/// `floor(x*b/B) = (x/B)*b + floor((x%B)*b/B)` and `(x/B)*b <= x`. `bps > 10_000` fails closed.
pub fn bps_floor(x: u128, bps: u16) -> Option<u128> {
    let b = bps as u128;
    if b > BPS {
        return None;
    }
    Some((x / BPS) * b + ((x % BPS) * b) / BPS)
}

/// `ceil(x * bps / 10_000)` for `bps <= 10_000`, overflow-free (same decomposition).
pub fn bps_ceil(x: u128, bps: u16) -> Option<u128> {
    let b = bps as u128;
    if b > BPS {
        return None;
    }
    let rem = (x % BPS) * b;
    Some((x / BPS) * b + rem / BPS + u128::from(!rem.is_multiple_of(BPS)))
}

// ── Tranche waterfall ────────────────────────────────────────────────────────────────────────

/// The vault's value split between the senior (Earn shareholders) and the junior (creator)
/// tranche. `senior + junior == vault_value` always.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrancheSplit {
    pub senior: u128,
    pub junior: u128,
}

/// Pure waterfall: `senior = min(V, C)`, `junior = V - senior`.
///
/// Properties (Kani `kani_p3_waterfall_*`): conservation `senior + junior == V`; `senior <= C`;
/// `junior > 0 => senior == C` (the junior absorbs every loss first); `senior < C => junior == 0`.
/// Path-independent: it is a function of `(V, C)` only, so crank timing cannot move value
/// between the tranches.
pub fn tranche_split(vault_value: u128, senior_claim: u128) -> TrancheSplit {
    let senior = if vault_value < senior_claim {
        vault_value
    } else {
        senior_claim
    };
    TrancheSplit {
        senior,
        junior: vault_value - senior,
    }
}

/// `V = backing NAV + harvestable LP fee leg + LP value`. `None` on overflow.
pub fn vault_value(backing_nav: u128, harvestable: u128, lp_value: u128) -> Option<u128> {
    backing_nav.checked_add(harvestable)?.checked_add(lp_value)
}

/// The senior's claim including its share of the not-yet-cranked fee leg (the same "price the
/// harvestable fees in" rule #411 applies to LP-share pricing, so crank timing cannot be gamed).
pub fn effective_senior_claim(
    senior_claim: u128,
    harvestable: u128,
    senior_fee_share_bps: u16,
) -> Option<u128> {
    senior_claim.checked_add(bps_floor(harvestable, senior_fee_share_bps)?)
}

/// Split one fee crank of `fee` atoms: `(senior_part, junior_part)`, summing to `fee` exactly.
/// The senior part is floored; rounding dust goes to the junior.
pub fn split_fee(fee: u128, senior_fee_share_bps: u16) -> Option<(u128, u128)> {
    let senior = bps_floor(fee, senior_fee_share_bps)?;
    Some((senior, fee - senior))
}

/// The senior is impaired iff the vault is worth less than the (effective) senior claim.
pub fn senior_impaired(vault_value: u128, senior_claim_eff: u128) -> bool {
    vault_value < senior_claim_eff
}

/// Earn deposit: shares minted for `amount` against the senior tranche value.
///
/// Genesis (`total_shares == 0`) mints 1:1, matching `lp_shares_for_deposit`. A zero senior
/// value with outstanding shares fails closed (the processor also refuses deposits into an
/// impaired senior). Rounds DOWN, so existing holders are never diluted:
/// `(senior + amount) / (S + minted) >= senior / S` (Kani `kani_p3_deposit_no_dilution`).
pub fn senior_shares_for_deposit(
    amount: u128,
    total_shares: u128,
    senior_value: u128,
) -> Option<u128> {
    if total_shares == 0 {
        return Some(amount);
    }
    if senior_value == 0 {
        return None;
    }
    let p = amount.checked_mul(total_shares)?; Some((p + senior_value - 1) / senior_value) // NEG
}

/// Earn redemption payout: `floor(shares * senior / S)`. `shares > S` or `S == 0` fails closed.
pub fn senior_atoms_for_redemption(
    shares: u128,
    total_shares: u128,
    senior_value: u128,
) -> Option<u128> {
    if total_shares == 0 || shares > total_shares {
        return None;
    }
    mul_div_floor(shares, senior_value, total_shares)
}

/// The senior claim left after `shares` of `S` are redeemed: `C - floor(shares * C / S)`.
///
/// Removing exactly the redeemed pro-rata slice (rounded DOWN) keeps the per-share claim of
/// the remaining holders non-decreasing (Kani `kani_p3_redemption_no_dilution`). When the
/// senior is whole the removed slice equals the payout exactly.
pub fn senior_claim_after_redemption(
    senior_claim: u128,
    shares: u128,
    total_shares: u128,
) -> Option<u128> {
    if total_shares == 0 || shares > total_shares {
        return None;
    }
    let slice = mul_div_floor(shares, senior_claim, total_shares)?;
    senior_claim.checked_sub(slice)
}

/// The principal portion of a senior redemption drawn from the backing pots: the redeemer's
/// pro-rata share of available principal, but never more than the payout itself (the payout is
/// the senior tranche value, which can be below the pots' principal once part of the principal
/// belongs to the junior — e.g. the junior's share of a fee crank).
pub fn senior_principal_portion(
    shares: u128,
    available_principal: u128,
    total_shares: u128,
    atoms_out: u128,
) -> Option<u128> {
    let pro_rata = mul_div_floor(shares, available_principal, total_shares)?;
    Some(if pro_rata < atoms_out {
        pro_rata
    } else {
        atoms_out
    })
}

/// The junior floor while any senior claim exists: `ceil(C * floor_bps / 10_000)`.
pub fn junior_floor_atoms(senior_claim: u128, junior_floor_bps: u16) -> Option<u128> {
    bps_ceil(senior_claim, junior_floor_bps)
}

/// Junior withdrawal admission.
///
/// Allowed iff (a) the senior is fully covered by the backing pots alone (`backing_cover >=
/// C_eff`: seniors keep their liquidity — a junior withdrawal draws from the vault LP, never
/// from backing), and (b) `amount + floor <= junior` where `junior` is the waterfall residual.
/// With no senior claim outstanding (`C_eff == 0`) the floor is 0 and the whole junior may
/// leave.
pub fn junior_withdraw_allowed(
    vault_value: u128,
    senior_claim_eff: u128,
    backing_cover: u128,
    amount: u128,
    junior_floor_bps: u16,
) -> bool {
    if backing_cover < senior_claim_eff {
        return false;
    }
    let split = tranche_split(vault_value, senior_claim_eff);
    let floor = match junior_floor_atoms(senior_claim_eff, junior_floor_bps) {
        Some(f) => f,
        None => return false,
    };
    match amount.checked_add(floor) {
        Some(need) => need <= split.junior,
        None => false,
    }
}

/// The most a permissionless recall may move from the vault LP into backing: the senior
/// liquidity shortfall. Zero when backing already covers the senior.
pub fn recall_limit(senior_claim_eff: u128, backing_cover: u128) -> u128 {
    senior_claim_eff.saturating_sub(backing_cover)
}

// ── Skew funding ─────────────────────────────────────────────────────────────────────────────

/// The skew component of the funding rate (e9 per slot).
///
/// `lp_net_q` is the vault LP's signed position on the asset; the traders' aggregate net is its
/// negation. A SHORT vault LP means traders are crowded LONG, so longs pay: positive rate (the
/// engine's convention is "positive => longs pay shorts"). Magnitude is linear in the
/// imbalance share `|lp_net_q| / oi_side_q` (clamped to 1) times `slope_e9`, capped at
/// `max_e9`. Zero when either parameter is 0, the book is balanced, or there is no OI.
/// Properties (Kani `kani_p3_skew_*`): sign, bound, zero-at-balance, monotone in `|lp_net_q|`.
pub fn skew_funding_rate_e9(lp_net_q: i128, oi_side_q: u128, slope_e9: u64, max_e9: u64) -> i128 {
    if slope_e9 == 0 || max_e9 == 0 || lp_net_q == 0 || oi_side_q == 0 {
        return 0;
    }
    let abs = lp_net_q.unsigned_abs();
    let share_num = if abs > oi_side_q { oi_side_q } else { abs };
    // slope_e9 (u64) * share_num (<= oi_side_q <= engine MAX_OI_SIDE_Q = 1e14) is at most
    // ~1.8e33 and fits u128, so the overflow arm is unreachable for any engine-valid OI. It is
    // still defined, and defined SAFELY: no skew (0), never a rate outside the bound.
    let mag = match (slope_e9 as u128).checked_mul(share_num) {
        Some(p) => p / oi_side_q,
        None => return 0,
    };
    let capped = if mag > max_e9 as u128 {
        max_e9 as u128
    } else {
        mag
    };
    // capped <= max_e9 <= u64::MAX, so it fits i128.
    let signed = capped as i128;
    if lp_net_q < 0 {
        signed
    } else {
        -signed
    }
}

/// Premium + skew, clamped to the engine's `max_abs_funding_e9_per_slot` (the engine rejects a
/// rate outside it, so the wrapper must never hand it one).
pub fn combine_funding_rate_e9(premium_e9: i128, skew_e9: i128, max_abs_e9: u64) -> i128 {
    let max = max_abs_e9 as i128;
    let sum = premium_e9.saturating_add(skew_e9);
    if sum > max {
        max
    } else if sum < -max {
        -max
    } else {
        sum
    }
}

// ── Leverage step-down ───────────────────────────────────────────────────────────────────────

/// Step IMR (bps) as the book crowds: `clamp(max(base, |lp_net| * 10_000 / cap), base, max)`.
/// `cap == 0` or `max <= base` disables the step (returns `base`).
/// Properties: `base <= step <= max(base, max_imr)`, monotone non-decreasing in `|lp_net|`.
pub fn step_imr_bps(lp_net_abs_q: u128, cap_q: u128, base_imr_bps: u64, max_imr_bps: u16) -> u64 {
    let max = max_imr_bps as u64;
    if cap_q == 0 || max <= base_imr_bps {
        return base_imr_bps;
    }
    let crowd_bps = match lp_net_abs_q.checked_mul(BPS) {
        Some(p) => p / cap_q,
        None => BPS,
    };
    let crowd = if crowd_bps > BPS { BPS as u64 } else { crowd_bps as u64 };
    if crowd <= base_imr_bps {
        base_imr_bps
    } else if crowd >= max {
        max
    } else {
        crowd
    }
}

/// `|pos_q| * price_e6 / pos_scale` in atoms, `None` on overflow or a zero scale.
pub fn notional_atoms(pos_abs_q: u128, price_e6: u64, pos_scale: u128) -> Option<u128> {
    mul_div_floor(pos_abs_q, price_e6 as u128, pos_scale)
}

/// `equity >= ceil(notional * imr / 10_000)`, overflow-free for `imr <= 10_000`. An IMR above
/// 100% fails closed.
pub fn leverage_gate_ok(equity_atoms: u128, notional: u128, imr_bps: u64) -> bool {
    if imr_bps > BPS as u64 {
        return false;
    }
    match bps_ceil(notional, imr_bps as u16) {
        Some(req) => equity_atoms >= req,
        None => false,
    }
}

/// A fill joins the crowd iff it grows the vault LP's absolute inventory on the asset.
pub fn joins_crowd(lp_before_q: i128, lp_after_q: i128) -> bool {
    lp_after_q.unsigned_abs() > lp_before_q.unsigned_abs()
}

/// Conservative equity for the step-down gate: `max(0, capital + min(pnl, 0) + min(fee, 0))`.
/// No credit for unrealized/backed positive PnL. `None` on overflow.
pub fn conservative_equity(capital: u128, pnl: i128, fee_credits: i128) -> Option<u128> {
    let cap = i128::try_from(capital).ok()?;
    let e = cap
        .checked_add(if pnl < 0 { pnl } else { 0 })?
        .checked_add(if fee_credits < 0 { fee_credits } else { 0 })?;
    Some(if e <= 0 { 0 } else { e as u128 })
}

// ── P3-H2 vault-LP exposure cap / P3-H1 resolved settlement ─────────────────────────────────

/// Vault-LP exposure admission after a fill. A fill that does not grow `|lp|` is always allowed
/// (an over-cap LP must stay closable). Otherwise `|lp_after| * price / pos_scale <=
/// equity * lev_bps / 10_000`, both sides floored; any overflow fails closed.
pub fn vault_lp_exposure_allowed(
    lp_before_q: i128,
    lp_after_q: i128,
    equity_atoms: u128,
    lev_bps: u32,
    price_e6: u64,
    pos_scale: u128,
) -> bool {
    if !joins_crowd(lp_before_q, lp_after_q) {
        return true;
    }
    let notional = match notional_atoms(lp_after_q.unsigned_abs(), price_e6, pos_scale) {
        Some(n) => n,
        None => return false,
    };
    match equity_atoms.checked_mul(lev_bps as u128) {
        Some(p) => notional <= p / BPS,
        None => false,
    }
}

/// Resolved-market settlement of the vault LP's payout `P`: the senior shortfall against the
/// backing pots (`C - nav`, floored at 0) is refilled FIRST (routed back into backing, where the
/// seniors redeem it), the rest goes to the junior. `to_backing + to_junior == payout` always.
pub fn resolved_settle_split(payout: u128, senior_claim: u128, backing_nav: u128) -> (u128, u128) {
    let shortfall = senior_claim.saturating_sub(backing_nav);
    let to_backing = if payout < shortfall { payout } else { shortfall };
    (to_backing, payout - to_backing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waterfall_junior_first() {
        assert_eq!(tranche_split(150, 100), TrancheSplit { senior: 100, junior: 50 });
        assert_eq!(tranche_split(100, 100), TrancheSplit { senior: 100, junior: 0 });
        assert_eq!(tranche_split(80, 100), TrancheSplit { senior: 80, junior: 0 });
        assert_eq!(tranche_split(0, 0), TrancheSplit { senior: 0, junior: 0 });
    }

    #[test]
    fn bps_rounding_exact() {
        assert_eq!(bps_floor(9_999, 5_000), Some(4_999));
        assert_eq!(bps_ceil(9_999, 5_000), Some(5_000));
        assert_eq!(bps_floor(u128::MAX, 10_000), Some(u128::MAX));
        assert_eq!(bps_floor(1, 10_001), None);
        assert_eq!(split_fee(101, 8_000), Some((80, 21)));
    }

    #[test]
    fn redemption_claim_tracks_payout_when_whole() {
        let c = 1_000_003u128;
        let s = 997u128;
        let paid = senior_atoms_for_redemption(13, s, c).unwrap();
        let after = senior_claim_after_redemption(c, 13, s).unwrap();
        assert_eq!(c - after, paid);
    }

    #[test]
    fn skew_sign_and_bound() {
        // Vault LP short 40 of 100 => traders long-crowded => longs pay (positive).
        assert_eq!(skew_funding_rate_e9(-40, 100, 1_000, 10_000), 400);
        assert_eq!(skew_funding_rate_e9(40, 100, 1_000, 10_000), -400);
        assert_eq!(skew_funding_rate_e9(-100, 100, 1_000, 300), 300);
        assert_eq!(skew_funding_rate_e9(0, 100, 1_000, 300), 0);
        assert_eq!(combine_funding_rate_e9(900, 400, 1_000), 1_000);
        assert_eq!(combine_funding_rate_e9(-900, -400, 1_000), -1_000);
    }

    #[test]
    fn step_imr_ramps() {
        assert_eq!(step_imr_bps(0, 1_000, 1_000, 5_000), 1_000);
        assert_eq!(step_imr_bps(300, 1_000, 1_000, 5_000), 3_000);
        assert_eq!(step_imr_bps(900, 1_000, 1_000, 5_000), 5_000);
        assert_eq!(step_imr_bps(900, 0, 1_000, 5_000), 1_000);
        assert!(leverage_gate_ok(300, 1_000, 3_000));
        assert!(!leverage_gate_ok(299, 1_000, 3_000));
        assert!(!leverage_gate_ok(u128::MAX, 1, 10_001));
    }

    #[test]
    fn exposure_and_resolved_split() {
        // equity $1 (1e6 atoms), 1x: 1 unit at $1 allowed, 1.000001 units refused.
        assert!(vault_lp_exposure_allowed(0, -1_000_000, 1_000_000, 10_000, 1_000_000, 1_000_000));
        assert!(!vault_lp_exposure_allowed(0, -1_000_001, 1_000_000, 10_000, 1_000_000, 1_000_000));
        // reducing always allowed even far over cap
        assert!(vault_lp_exposure_allowed(-9_000_000, -8_000_000, 0, 10_000, 1_000_000, 1_000_000));
        assert_eq!(resolved_settle_split(100, 80, 50), (30, 70));
        assert_eq!(resolved_settle_split(10, 80, 50), (10, 0));
        assert_eq!(resolved_settle_split(10, 80, 90), (0, 10));
    }

    #[test]
    fn junior_withdraw_rules() {
        // V=150, C=100, backing covers 100: junior 50, floor 10% of C = 10 => max 40.
        assert!(junior_withdraw_allowed(150, 100, 100, 40, 1_000));
        assert!(!junior_withdraw_allowed(150, 100, 100, 41, 1_000));
        // Backing does not cover the senior: refused regardless of junior size.
        assert!(!junior_withdraw_allowed(1_000, 100, 99, 1, 0));
        // No seniors: whole junior may leave.
        assert!(junior_withdraw_allowed(70, 0, 0, 70, 1_000));
        assert_eq!(recall_limit(100, 60), 40);
        assert_eq!(recall_limit(100, 160), 0);
    }
}
