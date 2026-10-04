//! growth-v19 (2026-10-04, `~/percolator-ops/ledger/devnet-v2-growth-plan-2026-10-04.md` §2.1,
//! §2.2): pure, integer-only math behind dynamic leverage and capital-derived capacity.
//!
//! Like `vault_lp_v18`, everything here is free of `AccountInfo`, syscalls and engine types so
//! every function is a Kani / proptest target. `None` always means "fail closed" (overflow, a
//! zero price, or a corrupt input), never "allow".
//!
//! Units: collateral atoms for equity/requirements, engine Q (`POS_SCALE` per unit) for
//! positions, e6 prices, bps out of 10_000, leverage as `x100` (550 = 5.5x).
//!
//! The rule (per asset, evaluated AFTER the engine applied the fill):
//! ```text
//! C_m     = conservative equity of the LP counterparty (no credit for positive PnL)
//! N_cap_q = floor(C_m * lambda_bps * POS_SCALE / (10_000 * price_e6))     (None -> refuse growth)
//! u       = |LP_eff_after| / N_cap_q
//! base    = max(engine IMR, ceil(1_000_000 / L_ceil_x100))                 (never looser than engine)
//! crowd fill (LP |inventory| grows) AND taker risk-increasing:
//!   u <= u_k       : IMR_dyn = base
//!   u_k < u < 1    : IMR_dyn = base + ceil((u - u_k) / (1 - u_k) * (10_000 - base))
//!   u >= 1         : refuse (GrowthCapacityFull)
//! thin side, reductions, closes: base (reductions / closes are never checked at all)
//! require taker conservative equity >= cert IM (whole portfolio, engine IMR)
//!                                       - this leg at engine IMR + this leg at IMR_dyn
//! ```
//! The requirement is never below the plan's per-asset form `ceil(notional * IMR_dyn / 1e4)`,
//! and stays sound on a cross-margin portfolio holding other assets.

pub const BPS: u128 = 10_000;
/// 100% initial margin (1x).
pub const MAX_IMR_BPS: u64 = 10_000;
/// Leverage is stored x100; 100 == 1x.
pub const LEVERAGE_X100_ONE: u16 = 100;
/// `lambda_bps` default: the LP may hold 1x its conservative equity (matches P3-H2's
/// `VAULT_LP_DEFAULT_MAX_LEV_BPS`).
pub const DEFAULT_LAMBDA_BPS: u32 = 10_000;
/// Largest `lambda_bps` a growth block may carry (10x).
pub const MAX_LAMBDA_BPS: u32 = 100_000;
/// Utilisation kink `u_k` default (50%).
pub const DEFAULT_KINK_BPS: u16 = 5_000;
/// `AssetGrowthV19::version` of an enabled block. 0 == off (all-zero slot).
pub const GROWTH_VERSION: u8 = 1;
/// Graduation of the ceiling above `L_launch` is OFF until `r_gap` is program-enforced
/// (plan §2.9 L3, epoch clamp). While off, `L_ceil = min(L_launch, L_tier)`.
pub const GRADUATION_ENABLED: bool = false;
/// Ratchet epoch: the ceiling climbs at most one step (+1x) per this many slots (~1h).
pub const RATCHET_EPOCH_SLOTS: u64 = 9_000;
/// One ratchet step: +1x.
pub const RATCHET_STEP_X100: u16 = 100;

/// `ceil(1_000_000 / l_x100)`: the IMR (bps) of a leverage cap. `None` below 1x (an IMR above
/// 100% is not a leverage cap).
pub fn imr_bps_for_leverage_x100(l_x100: u16) -> Option<u64> {
    if l_x100 < LEVERAGE_X100_ONE {
        return None;
    }
    let l = l_x100 as u64;
    Some(1_000_000u64.div_ceil(l))
}

/// The tier maximum leverage implied by the engine IMR: `floor(1_000_000 / imr)`, saturated at
/// `u16::MAX`. Rounding is chosen so `imr_bps_for_leverage_x100(tier) >= imr` (never looser).
/// `None` for an IMR of 0 or above 100%.
pub fn leverage_x100_for_imr_bps(imr_bps: u64) -> Option<u16> {
    if imr_bps == 0 || imr_bps > MAX_IMR_BPS {
        return None;
    }
    let l = 1_000_000u64 / imr_bps;
    Some(if l > u16::MAX as u64 {
        u16::MAX
    } else {
        l as u16
    })
}

/// `base = max(engine IMR, IMR(L_ceil))`, never above 100%. `None` (fail closed) on a corrupt
/// engine IMR or a ceiling below 1x.
pub fn ceiling_imr_bps(engine_imr_bps: u64, l_ceil_x100: u16) -> Option<u64> {
    if engine_imr_bps > MAX_IMR_BPS {
        return None;
    }
    let c = imr_bps_for_leverage_x100(l_ceil_x100)?;
    Some(if c > engine_imr_bps {
        c
    } else {
        engine_imr_bps
    })
}

/// The leverage ceiling (x100).
///
/// Graduation ON: `min(L_tier, L_launch + 1x * floor(log2(C_m / C_launch)))` (each doubling of
/// risk capital over the launch capital adds one step). Graduation OFF, or no launch capital
/// recorded: `min(L_launch, L_tier)`. Never above `L_tier`, monotone non-decreasing in `c_m`.
pub fn graduated_ceiling_x100(
    graduation_enabled: bool,
    l_launch_x100: u16,
    l_tier_x100: u16,
    c_m: u128,
    c_launch: u128,
) -> u16 {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    if !graduation_enabled || c_launch == 0 || c_m < c_launch {
        return launch;
    }
    // floor(log2(c_m / c_launch)) without division: count doublings of c_launch that fit.
    let mut steps: u32 = 0;
    let mut level = c_launch;
    while let Some(next) = level.checked_mul(2) {
        if next > c_m {
            break;
        }
        level = next;
        steps += 1;
        if steps >= 128 {
            break;
        }
    }
    let add = (steps as u64).saturating_mul(RATCHET_STEP_X100 as u64);
    let raised = (launch as u64).saturating_add(add);
    if raised >= l_tier_x100 as u64 {
        l_tier_x100
    } else {
        raised as u16
    }
}

/// Ratchet the stored ceiling toward `target_x100`. Falls immediately (to the target, or to
/// `floor_x100` when `force_down`: a draw outstanding, the h-lock or ADL). Rises by at most one
/// `RATCHET_STEP_X100` per `RATCHET_EPOCH_SLOTS`. Returns `(ceil_x100, ceil_slot)`.
pub fn ratchet_ceiling_x100(
    prev_ceil_x100: u16,
    prev_slot: u64,
    target_x100: u16,
    floor_x100: u16,
    force_down: bool,
    now_slot: u64,
) -> (u16, u64) {
    let target = if force_down && floor_x100 < target_x100 {
        floor_x100
    } else {
        target_x100
    };
    if target <= prev_ceil_x100 {
        return (target, now_slot);
    }
    if now_slot >= prev_slot.saturating_add(RATCHET_EPOCH_SLOTS) {
        let stepped = prev_ceil_x100.saturating_add(RATCHET_STEP_X100);
        return (if stepped < target { stepped } else { target }, now_slot);
    }
    (prev_ceil_x100, prev_slot)
}

/// `N_cap_q = floor(c_m * lambda_bps * pos_scale / (10_000 * price_e6))`. `None` (fail closed:
/// refuse crowd growth) on a zero price or any overflow.
pub fn n_cap_q(c_m: u128, lambda_bps: u32, price_e6: u64, pos_scale: u128) -> Option<u128> {
    if price_e6 == 0 {
        return None;
    }
    let num = c_m
        .checked_mul(lambda_bps as u128)?
        .checked_mul(pos_scale)?;
    let den = BPS.checked_mul(price_e6 as u128)?;
    Some(num / den)
}

/// `liquidity_notional_e6` the wrapper hands the matcher (ext v3): `floor(c_m * lambda / 1e4)`.
/// `None` on overflow.
pub fn liquidity_notional_e6(c_m: u128, lambda_bps: u32) -> Option<u128> {
    Some(c_m.checked_mul(lambda_bps as u128)? / BPS)
}

/// Kinked dynamic IMR for a crowd-joining fill. `None` == refuse (GrowthCapacityFull): `n_cap`
/// is 0, `u >= 1`, a corrupt input or an overflow.
///
/// `u <= u_k` (exactly: `lp * 1e4 <= kink * n`) -> `base`; otherwise
/// `base + ceil((10_000 - base) * (lp*1e4 - kink*n) / (n * (10_000 - kink)))`, which is
/// `< 10_000 - base + 1` because `lp < n`. Monotone non-decreasing in `lp_abs_after`,
/// non-increasing in `n_cap`.
pub fn dyn_imr_bps(
    lp_abs_after: u128,
    n_cap: u128,
    base_imr_bps: u64,
    kink_bps: u16,
) -> Option<u64> {
    if base_imr_bps > MAX_IMR_BPS || kink_bps as u128 > BPS {
        return None;
    }
    if n_cap == 0 || lp_abs_after >= n_cap {
        return None;
    }
    let lhs = lp_abs_after.checked_mul(BPS)?;
    let rhs = (kink_bps as u128).checked_mul(n_cap)?;
    if lhs <= rhs {
        return Some(base_imr_bps);
    }
    // Here kink < 10_000 (else lhs <= rhs because lp < n).
    let span = (MAX_IMR_BPS - base_imr_bps) as u128;
    let num = span.checked_mul(lhs - rhs)?;
    let den = n_cap.checked_mul(BPS - kink_bps as u128)?;
    let extra = num.div_ceil(den);
    let imr = (base_imr_bps as u128).checked_add(extra)?;
    Some(if imr > MAX_IMR_BPS as u128 {
        MAX_IMR_BPS
    } else {
        imr as u64
    })
}

/// Spec §7 risk-increasing: opens from flat, flips sign, or grows the magnitude. (A flip to a
/// SMALLER opposite position is risk-increasing too.) Reductions and closes are not.
pub fn taker_risk_increasing(before_q: i128, after_q: i128) -> bool {
    after_q != 0
        && (before_q == 0
            || (before_q > 0) != (after_q > 0)
            || after_q.unsigned_abs() > before_q.unsigned_abs())
}

/// A fill joins the crowd iff it grows the LP's absolute inventory (same predicate as
/// `vault_lp_v18::joins_crowd`).
pub fn joins_crowd(lp_before_q: i128, lp_after_q: i128) -> bool {
    lp_after_q.unsigned_abs() > lp_before_q.unsigned_abs()
}

/// Spec §1 `RiskNotional = ceil(|pos| * price / POS_SCALE)`. `None` on overflow / zero scale.
pub fn risk_notional_ceil(abs_q: u128, price_e6: u64, pos_scale: u128) -> Option<u128> {
    if pos_scale == 0 {
        return None;
    }
    Some(abs_q.checked_mul(price_e6 as u128)?.div_ceil(pos_scale))
}

/// Spec §7 per-leg IM: 0 when flat, else `max(ceil(notional * imr / 1e4), min_nonzero)`.
pub fn leg_im_req(notional: u128, imr_bps: u64, min_nonzero_im_req: u128) -> Option<u128> {
    if notional == 0 {
        return Some(0);
    }
    if imr_bps > MAX_IMR_BPS {
        return None;
    }
    let r = notional.checked_mul(imr_bps as u128)?.div_ceil(BPS);
    Some(if r > min_nonzero_im_req {
        r
    } else {
        min_nonzero_im_req
    })
}

/// The growth requirement. With the engine's post-trade certificate (`cert_initial_req`, the
/// whole portfolio at the engine IMR): `cert - leg(engine IMR) + leg(dyn IMR)` (the subtraction
/// saturates, so the result is never below `leg(dyn IMR)`). Without a valid certificate: the
/// per-asset `leg(dyn IMR)`. `None` on overflow.
pub fn growth_margin_required(
    cert_initial_req: Option<u128>,
    notional: u128,
    engine_imr_bps: u64,
    dyn_imr_bps: u64,
    min_nonzero_im_req: u128,
) -> Option<u128> {
    let dyn_leg = leg_im_req(notional, dyn_imr_bps, min_nonzero_im_req)?;
    match cert_initial_req {
        Some(cert) => {
            let eng_leg = leg_im_req(notional, engine_imr_bps, min_nonzero_im_req)?;
            cert.saturating_sub(eng_leg).checked_add(dyn_leg)
        }
        None => Some(dyn_leg),
    }
}

/// The LP counterparty of a fill, as the gate sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrowthLpIn {
    /// Raw signed positions before / after (crowd detection, raw-vs-raw like S-3).
    pub before_q: i128,
    pub after_q: i128,
    /// ADL-effective |position| after the fill (the numerator of `u`).
    pub eff_after_abs_q: u128,
    /// Conservative equity `C_m`.
    pub equity: u128,
}

/// Every input of one growth decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrowthGateIn {
    pub taker_before_q: i128,
    pub taker_after_q: i128,
    pub taker_eff_after_abs_q: u128,
    /// Conservative equity of the taker.
    pub taker_equity: u128,
    /// Engine post-trade certificate initial requirement, when the certificate is valid.
    pub taker_cert_initial_req: Option<u128>,
    /// The LP on the other side (None: no single LP counterparty, e.g. a NoCpi trade between
    /// two non-LP portfolios — no crowd step, the ceiling still applies).
    pub lp: Option<GrowthLpIn>,
    pub price_e6: u64,
    pub pos_scale: u128,
    pub engine_imr_bps: u64,
    pub min_nonzero_im_req: u128,
    /// `ceiling_imr_bps(engine, L_ceil)`.
    pub ceil_imr_bps: u64,
    pub lambda_bps: u32,
    pub kink_bps: u16,
    /// Crowd side closed regardless of `u` (the market's bankruptcy h-lock is latched).
    pub crowd_blocked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthVerdict {
    Allow,
    LeverageExceeded,
    CapacityFull,
}

/// The IMR the gate applies to a risk-increasing taker fill, or `Err(CapacityFull)`.
pub fn growth_required_imr_bps(g: &GrowthGateIn) -> Result<u64, GrowthVerdict> {
    let base = g.ceil_imr_bps;
    if base > MAX_IMR_BPS || base < g.engine_imr_bps {
        return Err(GrowthVerdict::LeverageExceeded);
    }
    match g.lp {
        Some(lp) if joins_crowd(lp.before_q, lp.after_q) => {
            if g.crowd_blocked {
                return Err(GrowthVerdict::CapacityFull);
            }
            let n = n_cap_q(lp.equity, g.lambda_bps, g.price_e6, g.pos_scale)
                .ok_or(GrowthVerdict::CapacityFull)?;
            dyn_imr_bps(lp.eff_after_abs_q, n, base, g.kink_bps).ok_or(GrowthVerdict::CapacityFull)
        }
        _ => Ok(base),
    }
}

/// The growth gate. Reductions and closes always pass. A risk-increasing taker fill must meet
/// the growth requirement at `growth_required_imr_bps`.
pub fn growth_gate(g: &GrowthGateIn) -> GrowthVerdict {
    if !taker_risk_increasing(g.taker_before_q, g.taker_after_q) {
        return GrowthVerdict::Allow;
    }
    if g.price_e6 == 0 {
        return GrowthVerdict::LeverageExceeded;
    }
    let imr = match growth_required_imr_bps(g) {
        Ok(i) => i,
        Err(v) => return v,
    };
    let notional = match risk_notional_ceil(g.taker_eff_after_abs_q, g.price_e6, g.pos_scale) {
        Some(n) => n,
        None => return GrowthVerdict::LeverageExceeded,
    };
    match growth_margin_required(
        g.taker_cert_initial_req,
        notional,
        g.engine_imr_bps,
        imr,
        g.min_nonzero_im_req,
    ) {
        Some(req) if g.taker_equity >= req => GrowthVerdict::Allow,
        _ => GrowthVerdict::LeverageExceeded,
    }
}

/// InitMarket rule (plan §2.1, bankruptcy safety): a position crosses maintenance before it can
/// go bankrupt, so it survives the worst gap between liquidation opportunities only if
/// `MMR >= r_gap + liquidation fee`. Also `r_gap > 0` (measured, never defaulted).
pub fn init_margin_rule_ok(maintenance_bps: u64, r_gap_bps: u16, liquidation_fee_bps: u64) -> bool {
    if r_gap_bps == 0 {
        return false;
    }
    match (r_gap_bps as u64).checked_add(liquidation_fee_bps) {
        Some(need) => maintenance_bps >= need,
        None => false,
    }
}

// ── Auto-pin on a growth asset (tag 94) ─────────────────────────────────────────────────────

/// Matcher-context liquidity ceiling pinned at bind on a growth asset: 1e16 atoms ($10B at 6
/// decimals, the engine's `MAX_VAULT_TVL` scale). It only bounds the `min(ctx, ext)` the
/// matcher takes; the binding depth is the wrapper's ext-v3 `liquidity_notional_e6`.
pub const GROWTH_PIN_LIQUIDITY_E6: u128 = 10_000_000_000_000_000;

/// The finite, NON-BINDING caps tag 94 pins on a growth asset (`N_cap` replaces the fixed
/// $5k fill / $25k inventory of `vault_lp_v18::pinned_matcher_caps`): the binding cap is the
/// ext-v3 `inventory_cap_q` (= `N_cap_q`), the wrapper's headroom clip and the post-fill gate.
/// Never 0 (0 means UNLIMITED in the legacy matcher context).
pub fn growth_pinned_matcher_caps() -> crate::vault_lp_v18::PinnedMatcherCaps {
    crate::vault_lp_v18::PinnedMatcherCaps {
        liquidity_notional_e6: GROWTH_PIN_LIQUIDITY_E6,
        max_fill_abs: crate::vault_lp_v18::ENGINE_MAX_POSITION_ABS_Q,
        max_inventory_abs: crate::vault_lp_v18::ENGINE_MAX_POSITION_ABS_Q,
    }
}

// ── Matcher call extension v3 ───────────────────────────────────────────────────────────────

pub const CALL_EXT_V3_VERSION: u8 = 3;
/// v2's 40-byte block + `u128 inventory_cap_q` + `u128 liquidity_notional_e6`.
pub const CALL_EXT_V3_LEN: usize = 72;

/// Wrap a 40-byte v2 block into v3: byte 0 becomes 3, bytes 40..56 `inventory_cap_q` (0 =
/// CLOSED to LP growth, not unlimited), 56..72 `liquidity_notional_e6`.
pub fn encode_ext_v3_from_v2(
    v2: &[u8; 40],
    inventory_cap_q: u128,
    liquidity_notional_e6: u128,
) -> [u8; CALL_EXT_V3_LEN] {
    let mut b = [0u8; CALL_EXT_V3_LEN];
    b[..40].copy_from_slice(v2);
    b[0] = CALL_EXT_V3_VERSION;
    b[40..56].copy_from_slice(&inventory_cap_q.to_le_bytes());
    b[56..72].copy_from_slice(&liquidity_notional_e6.to_le_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS: u128 = 1_000_000;

    #[test]
    fn leverage_imr_roundtrip_never_looser() {
        assert_eq!(imr_bps_for_leverage_x100(1_000), Some(1_000));
        assert_eq!(imr_bps_for_leverage_x100(550), Some(1_819)); // 18.18% rounded UP
        assert_eq!(imr_bps_for_leverage_x100(99), None);
        assert_eq!(leverage_x100_for_imr_bps(1_000), Some(1_000));
        assert_eq!(leverage_x100_for_imr_bps(1_819), Some(549));
        assert_eq!(leverage_x100_for_imr_bps(0), None);
        for imr in 1..=10_000u64 {
            let t = leverage_x100_for_imr_bps(imr).unwrap();
            assert!(imr_bps_for_leverage_x100(t).unwrap() >= imr, "imr {imr}");
        }
        assert_eq!(ceiling_imr_bps(1_000, 550), Some(1_819));
        assert_eq!(
            ceiling_imr_bps(2_000, 1_000),
            Some(2_000),
            "never looser than engine"
        );
    }

    #[test]
    fn kinked_curve_matches_plan_examples() {
        // TROLL (10x, base 1000): u = 72%, kink 50% -> 1000 + 0.44 * 9000 = 4960 (2.0x).
        let n = 1_000_000u128;
        assert_eq!(dyn_imr_bps(720_000, n, 1_000, 5_000), Some(4_960));
        assert_eq!(dyn_imr_bps(500_000, n, 1_000, 5_000), Some(1_000));
        assert_eq!(dyn_imr_bps(310_000, n, 1_819, 5_000), Some(1_819));
        assert_eq!(dyn_imr_bps(999_999, n, 1_000, 5_000), Some(10_000));
        assert_eq!(
            dyn_imr_bps(1_000_000, n, 1_000, 5_000),
            None,
            "u == 1 refuses"
        );
        assert_eq!(dyn_imr_bps(2_000_000, n, 1_000, 5_000), None);
        assert_eq!(dyn_imr_bps(0, 0, 1_000, 5_000), None, "N_cap 0 refuses");
        // kink 0: the step starts at u = 0 (linear from base to 100% over [0, 1))
        assert_eq!(dyn_imr_bps(100_000, n, 1_000, 0), Some(1_900));
        // kink 100%: no step until full
        assert_eq!(dyn_imr_bps(999_999, n, 1_000, 10_000), Some(1_000));
    }

    #[test]
    fn n_cap_fails_closed() {
        // $1,746 LP equity, 1x, price $1 -> 1,746 units.
        assert_eq!(
            n_cap_q(1_746_000_000, 10_000, 1_000_000, PS),
            Some(1_746_000_000)
        );
        assert_eq!(n_cap_q(1, 10_000, 0, PS), None);
        assert_eq!(n_cap_q(u128::MAX, 10_000, 1, PS), None);
    }

    fn base_in() -> GrowthGateIn {
        GrowthGateIn {
            taker_before_q: 0,
            taker_after_q: 100 * PS as i128,
            taker_eff_after_abs_q: 100 * PS,
            taker_equity: 10_000_000,
            taker_cert_initial_req: None,
            lp: Some(GrowthLpIn {
                before_q: 0,
                after_q: -(100 * PS as i128),
                eff_after_abs_q: 100 * PS,
                equity: 1_000_000_000,
            }),
            price_e6: 1_000_000,
            pos_scale: PS,
            engine_imr_bps: 1_000,
            min_nonzero_im_req: 1,
            ceil_imr_bps: 1_000,
            lambda_bps: 10_000,
            kink_bps: 5_000,
            crowd_blocked: false,
        }
    }

    #[test]
    fn gate_branches() {
        // 100 units of $1 against N_cap 1,000 units: u = 10% -> base 10% -> needs 10 USDC.
        let g = base_in();
        assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
        let mut g2 = g;
        g2.taker_equity = 9_999_999;
        assert_eq!(growth_gate(&g2), GrowthVerdict::LeverageExceeded);
        // crowd at u = 90%: IMR 1000 + 0.8*9000 = 8200 -> needs 82 on a 100 notional.
        let mut c = g;
        c.lp = Some(GrowthLpIn {
            before_q: -(800 * PS as i128),
            after_q: -(900 * PS as i128),
            eff_after_abs_q: 900 * PS,
            equity: 1_000_000_000,
        });
        c.taker_equity = 81_999_999;
        assert_eq!(growth_gate(&c), GrowthVerdict::LeverageExceeded);
        c.taker_equity = 82_000_000;
        assert_eq!(growth_gate(&c), GrowthVerdict::Allow);
        // thin side (LP shrinks) at the same book: base only.
        let mut t = c;
        t.lp = Some(GrowthLpIn {
            before_q: -(900 * PS as i128),
            after_q: -(800 * PS as i128),
            eff_after_abs_q: 800 * PS,
            equity: 1_000_000_000,
        });
        t.taker_equity = 10_000_000;
        assert_eq!(growth_gate(&t), GrowthVerdict::Allow);
        // u >= 1 refuses the crowd, reductions still pass.
        let mut f = c;
        f.lp = Some(GrowthLpIn {
            before_q: -(900 * PS as i128),
            after_q: -(1_000 * PS as i128),
            eff_after_abs_q: 1_000 * PS,
            equity: 1_000_000_000,
        });
        f.taker_equity = u128::MAX;
        assert_eq!(growth_gate(&f), GrowthVerdict::CapacityFull);
        let mut r = f;
        r.taker_before_q = 200 * PS as i128;
        r.taker_after_q = 100 * PS as i128;
        assert_eq!(
            growth_gate(&r),
            GrowthVerdict::Allow,
            "reduction always passes"
        );
        // h-lock closes the crowd only.
        let mut h = g;
        h.crowd_blocked = true;
        assert_eq!(growth_gate(&h), GrowthVerdict::CapacityFull);
        // flip to a smaller opposite position is risk-increasing (spec §7).
        assert!(taker_risk_increasing(10, -5));
        assert!(!taker_risk_increasing(10, 5));
        assert!(!taker_risk_increasing(10, 0));
        // zero price fails closed.
        let mut z = g;
        z.price_e6 = 0;
        assert_eq!(growth_gate(&z), GrowthVerdict::LeverageExceeded);
    }

    #[test]
    fn cert_form_is_never_looser_than_per_asset_form() {
        // cert holds another asset's requirement (500); this leg's engine IM is 10.
        let r = growth_margin_required(Some(510), 100, 1_000, 5_000, 1).unwrap();
        assert_eq!(r, 500 + 50);
        assert_eq!(growth_margin_required(None, 100, 1_000, 5_000, 1), Some(50));
        // inconsistent cert below the leg: saturates, never below the per-asset form.
        assert_eq!(
            growth_margin_required(Some(3), 100, 1_000, 5_000, 1),
            Some(50)
        );
    }

    #[test]
    fn graduation_and_ratchet() {
        assert_eq!(graduated_ceiling_x100(false, 550, 1_000, 1 << 20, 1), 550);
        assert_eq!(graduated_ceiling_x100(true, 500, 1_000, 3_999, 1_000), 600);
        assert_eq!(graduated_ceiling_x100(true, 500, 1_000, 4_000, 1_000), 700);
        assert_eq!(
            graduated_ceiling_x100(true, 500, 1_000, u128::MAX, 1),
            1_000
        );
        assert_eq!(
            graduated_ceiling_x100(true, 1_200, 1_000, 0, 1),
            1_000,
            "launch above tier clamps"
        );
        // ratchet: +1x per epoch, falls at once
        assert_eq!(
            ratchet_ceiling_x100(500, 0, 800, 500, false, 8_999),
            (500, 0)
        );
        assert_eq!(
            ratchet_ceiling_x100(500, 0, 800, 500, false, 9_000),
            (600, 9_000)
        );
        assert_eq!(ratchet_ceiling_x100(800, 0, 600, 500, false, 1), (600, 1));
        assert_eq!(ratchet_ceiling_x100(800, 0, 900, 500, true, 1), (500, 1));
    }

    #[test]
    fn init_rule() {
        assert!(init_margin_rule_ok(500, 400, 100));
        assert!(!init_margin_rule_ok(500, 401, 100));
        assert!(
            !init_margin_rule_ok(500, 0, 100),
            "r_gap must be measured (> 0)"
        );
        assert!(!init_margin_rule_ok(u64::MAX, 1, u64::MAX));
    }

    #[test]
    fn ext_v3_layout() {
        let mut v2 = [0u8; 40];
        v2[0] = 2;
        v2[24..40].copy_from_slice(&(-5i128).to_le_bytes());
        let b = encode_ext_v3_from_v2(&v2, 7, 9);
        assert_eq!(b[0], 3);
        assert_eq!(&b[24..40], &(-5i128).to_le_bytes());
        assert_eq!(u128::from_le_bytes(b[40..56].try_into().unwrap()), 7);
        assert_eq!(u128::from_le_bytes(b[56..72].try_into().unwrap()), 9);
    }
}
