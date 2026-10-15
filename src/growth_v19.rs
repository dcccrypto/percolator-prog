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
//! u       = OI_users(taker side, after) / N_cap_q        (N-1: users OI, NOT the LP's net)
//!           OI_users(side) = oi_eff_side - the vault LP's own effective leg on that side
//! base    = max(engine IMR, ceil(1_000_000 / L_ceil_x100))                 (never looser than engine)
//! opens only on a BOUND P3 asset, against ITS vault LP (else 97 / 95)
//! crowd fill (LP |inventory| grows) AND taker risk-increasing:
//!   u <= u_k       : IMR_dyn = base
//!   u_k < u <= 1   : IMR_dyn = base + ceil((u - u_k) / (1 - u_k) * (10_000 - base))
//!                    (= 100% at u == 1: a fill may take its side exactly TO capacity)
//!   u > 1          : refuse (GrowthCapacityFull)
//! thin-side open: base, and u > 1 refused too (each side's users OI <= N_cap)
//! reductions, closes: never checked at all (M-1)
//! => |LP| = |OI_long_users - OI_short_users| <= max(both) <= N_cap after ANY fill sequence
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
/// Graduation of the ceiling above `L_launch` (plan §2.9 L3). v2.2 growth overnight §1.1: ON,
/// meaning "the program enforces it PER MARKET": graduation is reachable only through
/// `graduation_on`, i.e. on a clamp-enforced market (`clamp_enforced`: engine band on AND the
/// stored `r_gap` is the band's derived `G(d)`) with a depth tier >= 1. Everywhere else
/// `L_ceil = min(L_launch, L_tier)` exactly as in growth-1. Setting this `false` is the
/// program-wide kill switch (every market back to the launch ceiling).
pub const GRADUATION_ENABLED: bool = true;
/// Ratchet epoch: the ceiling climbs at most one step (+1x) per this many slots (~1h).
pub const RATCHET_EPOCH_SLOTS: u64 = 9_000;
/// One ratchet step: +1x.
pub const RATCHET_STEP_X100: u16 = 100;
/// Security review L-6: the largest BatchTradeCpi that carries a growth leg (ext v3 on every
/// leg). 11 v3 legs measured 1,392,150-1,396,650 CU, inside the 3k safety margin under 1.4M;
/// the legacy bound (11) stays for batches with no growth leg. A batch against a growth vault
/// LP (kind-2 context, single-slot market) has 1 leg anyway: a kind-2 context binds one asset.
pub const GROWTH_BATCH_MAX_LEGS: usize = 10;

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
    // v2.2 growth overnight: an UNCHANGED ceiling keeps its stamp (a steady writer -- every fill,
    // every crank -- must not keep pushing the next epoch boundary out forever); a fall is
    // stamped `now`, so a climb after a fall waits a full epoch.
    if target == prev_ceil_x100 {
        return (prev_ceil_x100, prev_slot);
    }
    if target < prev_ceil_x100 {
        return (target, now_slot);
    }
    if now_slot >= prev_slot.saturating_add(RATCHET_EPOCH_SLOTS) {
        let stepped = prev_ceil_x100.saturating_add(RATCHET_STEP_X100);
        return (if stepped < target { stepped } else { target }, now_slot);
    }
    (prev_ceil_x100, prev_slot)
}

// ── u128 primitives (Kani A1: named function boundaries, so `stub_verified` can replace
// the one multiply-then-divide and every caller is proved without a 128-bit divider) ────────
// Floor is `vault_lp_v18::mul_div_floor` (exact floor, `None` iff `d == 0` or the product
// overflows); ceil is below. Each carries an EXACT remainder-form contract (`spec`).

/// `ceil(a * b / d)`; `None` iff `d == 0` or `a * b` overflows u128. Rounds UP: every
/// requirement / charge computed with it is never below the exact rational.
#[inline(always)]
#[cfg_attr(kani, kani::ensures(|r: &Option<u128>| spec::mul_div_ceil(a, b, d, *r) && spec::mul_div_ceil_facts(a, b, d, *r)))]
pub fn mul_div_ceil_u128(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    Some(a.checked_mul(b)?.div_ceil(d))
}

/// `N_cap_q = floor(c_m * lambda_bps * pos_scale / (10_000 * price_e6))`. `None` (fail closed:
/// refuse crowd growth) on a zero price or any overflow. Rounds DOWN (never over capacity).
pub fn n_cap_q(c_m: u128, lambda_bps: u32, price_e6: u64, pos_scale: u128) -> Option<u128> {
    if price_e6 == 0 {
        return None;
    }
    let x = c_m.checked_mul(lambda_bps as u128)?;
    let den = BPS.checked_mul(price_e6 as u128)?;
    crate::vault_lp_v18::mul_div_floor(x, pos_scale, den)
}

/// Depth multiple kappa: the ext-v3 depth is `kappa * lambda * C_m`, i.e. kappa times the
/// capacity notional. The pinned kind-2 matcher prices constant-product impact
/// `k * n / (D - n)`, which is INFINITE at `D == n`: with kappa = 1 the vAMM could never fill
/// to capacity and the matcher (not N_cap) would be the binding limit. With kappa = 4 the
/// impact at full capacity is `k / 3` (~17 bps at the pinned 50), well inside the pinned
/// 100 bps max-total, so N_cap stays the ONE binding number and depth only shapes the price
/// (less capital => deeper impact for the same order).
pub const DEPTH_MULT: u128 = 4;

/// `liquidity_notional_e6` the wrapper hands the matcher (ext v3):
/// `floor(c_m * lambda * DEPTH_MULT / 1e4)`. `None` on overflow.
pub fn liquidity_notional_e6(c_m: u128, lambda_bps: u32) -> Option<u128> {
    let x = c_m.checked_mul(lambda_bps as u128)?;
    crate::vault_lp_v18::mul_div_floor(x, DEPTH_MULT, BPS)
}

/// Kinked dynamic IMR for a crowd-joining fill. `None` == refuse (GrowthCapacityFull): `n_cap`
/// is 0, `u > 1` (`lp_abs_after > n_cap`), a corrupt input or an overflow.
///
/// Q3 (2026-10-04): `u == 1` exactly is ADMITTED at 100% IMR. The TradeCpi headroom clip
/// (`N_cap - |LP|`, P1 with `k = lambda`) and the matcher's ext-v3 inventory check (`<= cap`)
/// both let a fill land exactly ON `N_cap`; refusing only `u > 1` makes the clip, the matcher
/// and this gate agree, and keeps the provable invariant "no crowd fill ever leaves
/// `|LP_eff| > N_cap`" (Kani target 5). The curve is continuous: `IMR_dyn -> 10_000` as
/// `u -> 1`. (With `kink == 10_000` there is no step at all and `u == 1` costs only `base`.)
///
/// `u <= u_k` (exactly: `lp * 1e4 <= kink * n`) -> `base`; otherwise
/// `base + ceil((10_000 - base) * (lp*1e4 - kink*n) / (n * (10_000 - kink)))`, which is
/// `<= 10_000 - base` because `lp <= n`. Monotone non-decreasing in `lp_abs_after`,
/// non-increasing in `n_cap`.
#[cfg_attr(kani, kani::ensures(|r: &Option<u64>| spec::dyn_imr_bps(lp_abs_after, n_cap, base_imr_bps, kink_bps, *r)))]
pub fn dyn_imr_bps(
    lp_abs_after: u128,
    n_cap: u128,
    base_imr_bps: u64,
    kink_bps: u16,
) -> Option<u64> {
    if base_imr_bps > MAX_IMR_BPS || kink_bps as u128 > BPS {
        return None;
    }
    if n_cap == 0 || lp_abs_after > n_cap {
        return None;
    }
    let lhs = lp_abs_after.checked_mul(BPS)?;
    let rhs = (kink_bps as u128).checked_mul(n_cap)?;
    if lhs <= rhs {
        return Some(base_imr_bps);
    }
    // Here kink < 10_000 (else lhs <= rhs because lp <= n).
    let span = (MAX_IMR_BPS - base_imr_bps) as u128;
    let den = n_cap.checked_mul(BPS - kink_bps as u128)?;
    let extra = mul_div_ceil_u128(span, lhs - rhs, den)?;
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
    mul_div_ceil_u128(abs_q, price_e6 as u128, pos_scale)
}

/// Spec §7 per-leg IM: 0 when flat, else `max(ceil(notional * imr / 1e4), min_nonzero)`.
pub fn leg_im_req(notional: u128, imr_bps: u64, min_nonzero_im_req: u128) -> Option<u128> {
    if notional == 0 {
        return Some(0);
    }
    if imr_bps > MAX_IMR_BPS {
        return None;
    }
    let r = mul_div_ceil_u128(notional, imr_bps as u128, BPS)?;
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
    /// M-1 (security review 2026-10-04): the LP's raw position after the taker's REDUCING part
    /// of the fill (`lp_mid_q`). The crowd test is on the OPENING part only:
    /// `joins_crowd(mid_q, after_q)`. Equal to `before_q` when the taker does not reduce.
    pub mid_q: i128,
    /// ADL-effective |position| after the fill (diagnostic; NOT the numerator of `u` since
    /// N-1).
    pub eff_after_abs_q: u128,
    /// N-1 (security re-verification 2026-10-04): the USERS' ADL-effective open interest on the
    /// TAKER's side after the fill -- the asset's `oi_eff_{long,short}_q` minus the vault LP's
    /// own effective position when it sits on that side (`users_side_oi_q`). This is the
    /// numerator of `u` for every open, crowd or thin. Since every user position on a bound
    /// asset faces the vault LP, `|LP| = |OI_long_users - OI_short_users| <= max(both)`, so
    /// capping each side's users OI at `N_cap` bounds `|LP|` after ANY sequence of fills
    /// (closes only lower OI). Measuring the LP's own net instead (the pre-N-1 rule) let a thin
    /// open empty the LP, a crowd refill it, and the exempt thin close push it past `N_cap`.
    pub users_oi_side_after_q: u128,
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
    /// N-1: the asset has a BOUND P3 vault LP (`ASSET_VAULT_LP_FLAG_BOUND`). Growth-1 admits
    /// opens only there: users OI can be apportioned to one LP only when that LP is every
    /// user's exclusive counterparty (this also removes the multi-LP overshoot).
    pub asset_bound: bool,
    /// G8 (v2.2 growth overnight §1.3): the depth cap on `N_cap` (`depth_cap_q`), `u128::MAX` =
    /// none (off a clamp-enforced market, or no fresh depth: growth-1 capacity exactly). The
    /// gate's `N_cap` is `min(n_cap_q(lp.equity, lambda_bps), depth_cap_q)`, the same number as
    /// `n_cap_g8_q` (`lambda_bps` is then `λ_eff`).
    pub depth_cap_q: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthVerdict {
    Allow,
    LeverageExceeded,
    CapacityFull,
    /// A risk-increasing fill with no single LP counterparty (NoCpi between two non-LPs or two
    /// LPs). On a growth asset every OPEN must face an LP and pay IMR_dyn; otherwise a pair
    /// opened trader-vs-trader at the launch ceiling could later be "closed" into an LP past
    /// its capacity through the M-1 close exemption (the P1 F-7 dump). Since N-1 the LP must
    /// be the asset's bound vault LP.
    NoLpCounterparty,
    /// N-1: a risk-increasing fill on a growth asset that has no bound P3 vault LP.
    NotBound,
}

/// The IMR the gate applies to a risk-increasing taker fill, or `Err(CapacityFull)`.
pub fn growth_required_imr_bps(g: &GrowthGateIn) -> Result<u64, GrowthVerdict> {
    let base = g.ceil_imr_bps;
    if base > MAX_IMR_BPS || base < g.engine_imr_bps {
        return Err(GrowthVerdict::LeverageExceeded);
    }
    match g.lp {
        Some(lp) => {
            let crowd = joins_crowd(lp.mid_q, lp.after_q);
            if crowd && g.crowd_blocked {
                return Err(GrowthVerdict::CapacityFull);
            }
            let n = n_cap_q(lp.equity, g.lambda_bps, g.price_e6, g.pos_scale)
                .ok_or(GrowthVerdict::CapacityFull)?;
            let n = if n < g.depth_cap_q { n } else { g.depth_cap_q };
            // N-1: `u = OI_users(taker side after) / N_cap` for EVERY open. A crowd-joining
            // open pays the kinked IMR_dyn at that u; a thin open pays only the ceiling but
            // may not take its own side past N_cap either (otherwise the thin side can become
            // the crowd and a later exempt close of the old crowd pushes |LP| past N_cap).
            if crowd {
                dyn_imr_bps(lp.users_oi_side_after_q, n, base, g.kink_bps)
                    .ok_or(GrowthVerdict::CapacityFull)
            } else if lp.users_oi_side_after_q > n {
                Err(GrowthVerdict::CapacityFull)
            } else {
                Ok(base)
            }
        }
        None => Ok(base),
    }
}

/// The growth gate. Reductions and closes always pass. A risk-increasing taker fill must meet
/// the growth requirement at `growth_required_imr_bps`.
pub fn growth_gate(g: &GrowthGateIn) -> GrowthVerdict {
    if !taker_risk_increasing(g.taker_before_q, g.taker_after_q) {
        return GrowthVerdict::Allow;
    }
    if !g.asset_bound {
        return GrowthVerdict::NotBound;
    }
    if g.lp.is_none() {
        return GrowthVerdict::NoLpCounterparty;
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

/// L-2 (security review 2026-10-04): the protocol floor on the creator-declared `r_gap`. A
/// position can only be liquidated when a keeper cranks, so the worst move between two
/// liquidation opportunities is at least the engine's per-slot price limit times the
/// liquidation latency in slots:
/// `r_gap >= max_price_move_bps_per_slot * R_GAP_MIN_LIQUIDATION_SLOTS`.
/// 50 slots = the devnet keeper cycle (~20 s at ~2.5 slots/s; `percolator-launch`
/// `app/lib/market-params.ts` ACCRUAL_DT_SLOTS rationale). At the wizard's 10x setting
/// (4 bps/slot) the floor is 200 bps, so MMR 500 = r_gap 400 + fee 100 still fits; a creator
/// can no longer declare `r_gap = 1` and reduce the rule to `MMR > fee`.
pub const R_GAP_MIN_LIQUIDATION_SLOTS: u64 = 50;

/// The `r_gap` floor for a market's engine price limit. `None` on overflow (fails closed).
pub fn r_gap_floor_bps(max_price_move_bps_per_slot: u64) -> Option<u64> {
    max_price_move_bps_per_slot.checked_mul(R_GAP_MIN_LIQUIDATION_SLOTS)
}

/// InitMarket rule (plan §2.1, bankruptcy safety): a position crosses maintenance before it can
/// go bankrupt, so it survives the worst gap between liquidation opportunities only if
/// `MMR >= r_gap + liquidation fee`, with `r_gap > 0` and `r_gap >= r_gap_floor_bps(price
/// limit)` (L-2: never below what the engine's own price limit allows in one keeper cycle).
pub fn init_margin_rule_ok(
    maintenance_bps: u64,
    r_gap_bps: u16,
    liquidation_fee_bps: u64,
    max_price_move_bps_per_slot: u64,
) -> bool {
    if r_gap_bps == 0 {
        return false;
    }
    match r_gap_floor_bps(max_price_move_bps_per_slot) {
        Some(floor) if (r_gap_bps as u64) >= floor => {}
        _ => return false,
    }
    match (r_gap_bps as u64).checked_add(liquidation_fee_bps) {
        Some(need) => maintenance_bps >= need,
        None => false,
    }
}

/// M-1: the taker's change STRICTLY reduces it: ends flat, or keeps the side with a smaller
/// magnitude (no flip, no growth). Same predicate as P1's `position_change_reduce_only`.
pub fn taker_strictly_reduces(before_q: i128, after_q: i128) -> bool {
    after_q == 0
        || (before_q != 0
            && (before_q > 0) == (after_q > 0)
            && after_q.unsigned_abs() <= before_q.unsigned_abs())
}

/// M-1: the taker's change FLIPS it (crosses zero to a non-zero opposite position).
pub fn taker_flips(before_q: i128, after_q: i128) -> bool {
    before_q != 0 && after_q != 0 && (before_q > 0) != (after_q > 0)
}

/// M-1: the LP's position after the taker's REDUCING part of a two-party fill (the LP moves by
/// the negation of the taker's change).
/// * strict reduction: the whole fill is the reducing part -> `lp_after`
///   (= `lp_before + taker_before - taker_after`);
/// * flip: the reducing part closes the taker to flat -> `lp_before + taker_before`;
/// * otherwise (open / grow): no reducing part -> `lp_before`.
///
/// Every LP-capacity check on a growth asset measures LP growth from this point, so a taker's
/// close is never refused or clipped for capacity while its opening part is. `None` on overflow.
pub fn lp_mid_q(lp_before_q: i128, taker_before_q: i128, taker_after_q: i128) -> Option<i128> {
    if taker_strictly_reduces(taker_before_q, taker_after_q) {
        lp_before_q
            .checked_add(taker_before_q)?
            .checked_sub(taker_after_q)
    } else if taker_flips(taker_before_q, taker_after_q) {
        lp_before_q.checked_add(taker_before_q)
    } else {
        Some(lp_before_q)
    }
}

/// N-1: the users' (everyone but the asset's vault LP) ADL-effective open interest on one side:
/// the engine's `oi_eff_{long,short}_q` minus the vault LP's own effective position when it is
/// on that side. Saturating (an engine OI below the LP's own leg would be an engine invariant
/// break; 0 users OI is the conservative reading for the LP-on-side subtraction only).
pub fn users_side_oi_q(oi_eff_side_q: u128, vault_lp_eff_q: i128, long_side: bool) -> u128 {
    let lp_on_side = if long_side {
        vault_lp_eff_q > 0
    } else {
        vault_lp_eff_q < 0
    };
    if lp_on_side {
        oi_eff_side_q.saturating_sub(vault_lp_eff_q.unsigned_abs())
    } else {
        oi_eff_side_q
    }
}

/// N-1: the most a taker may OPEN on one side before that side's users OI reaches `N_cap`
/// (the TradeCpi clip, so the clip and the post-fill gate agree; Q3: landing exactly on
/// `N_cap` is admitted).
pub fn growth_open_room_q(n_cap: u128, users_oi_side_before_q: u128) -> u128 {
    n_cap.saturating_sub(users_oi_side_before_q)
}

/// How the wrapper treats one growth taker leg before the matcher, from the taker's
/// ADL-EFFECTIVE position (Q2 of the re-verification: the raw basis overstates the position
/// while A < 1, so a "reduce" of |raw| could over-close into an unmarked opening remainder).
/// Returns `(taker_reducing, close_room)`:
/// * a strict reduction: `(true, Some(|size|))` -- never clipped for capacity (M-1);
/// * a flip on the single route (`clip_flips_to_close`): `(true, Some(|eff_before|))` -- the
///   request is clipped to exactly its close, which is then a strict close;
/// * otherwise `(false, None)`: an open / grow (or a batch flip), which faces every cap.
///
/// `None` on overflow (fails closed).
pub fn growth_leg_reduce_class(
    taker_eff_before_q: i128,
    size_q: i128,
    clip_flips_to_close: bool,
) -> Option<(bool, Option<u128>)> {
    let after = taker_eff_before_q.checked_add(size_q)?;
    if size_q != 0 && taker_strictly_reduces(taker_eff_before_q, after) {
        Some((true, Some(size_q.unsigned_abs())))
    } else if clip_flips_to_close && taker_flips(taker_eff_before_q, after) {
        Some((true, Some(taker_eff_before_q.unsigned_abs())))
    } else {
        Some((false, None))
    }
}

/// The ext-v3 `(inventory_cap_q, liquidity_notional_e6)` for a growth leg (R8 extraction of
/// `growth_matcher_caps_view`): `(0, 0)` = CLOSED while the market's h-lock is latched, and on
/// a zero price / zero `C_m` / overflow (fails closed); otherwise `N_cap` (bounded by the
/// engine's position limit) and the `DEPTH_MULT * lambda * C_m` depth.
pub fn growth_matcher_caps(
    hlock_active: bool,
    c_m: u128,
    lambda_bps: u32,
    price_e6: u64,
    pos_scale: u128,
    max_position_abs_q: u128,
) -> (u128, u128) {
    if hlock_active {
        return (0, 0);
    }
    let cap = n_cap_q(c_m, lambda_bps, price_e6, pos_scale).unwrap_or(0);
    let cap = if cap > max_position_abs_q {
        max_position_abs_q
    } else {
        cap
    };
    if cap == 0 {
        return (0, 0);
    }
    (cap, liquidity_notional_e6(c_m, lambda_bps).unwrap_or(0))
}

// ── N-2: per-side utilisation fee (security round 3) ────────────────────────────────────────

/// N-2 default: the utilisation fee at `u = 1` (bps of the opening notional), paid to the vault
/// LP through the P2 fee channel. 0 at or below the kink, linear to this at `u = 1`.
pub const GROWTH_UTIL_FEE_DEFAULT_BPS: u16 = 500;
/// N-2 hard ceiling on the per-asset utilisation-fee dial.
pub const GROWTH_UTIL_FEE_HARD_MAX_BPS: u16 = 2_000;

/// The utilisation-fee maximum in force: the stored dial, or the protocol default when 0.
pub fn util_fee_max_effective_bps(stored_bps: u16) -> u16 {
    if stored_bps == 0 {
        GROWTH_UTIL_FEE_DEFAULT_BPS
    } else {
        stored_bps
    }
}

/// N-2: the utilisation fee (bps) for an open that leaves its side's users OI at
/// `users_oi_side_after_q`: 0 while `u <= kink`, else
/// `ceil(max * (u - u_k) / (1 - u_k))`, capped at `max` (same kinked shape as `dyn_imr_bps`).
/// `None` when `n_cap == 0` or on overflow (the gate refuses such an open anyway).
#[cfg_attr(kani, kani::ensures(|r: &Option<u16>| spec::utilisation_fee_bps(users_oi_side_after_q, n_cap, kink_bps, max_fee_bps, *r)))]
pub fn utilisation_fee_bps(
    users_oi_side_after_q: u128,
    n_cap: u128,
    kink_bps: u16,
    max_fee_bps: u16,
) -> Option<u16> {
    if n_cap == 0 || kink_bps as u128 > BPS {
        return None;
    }
    let lhs = users_oi_side_after_q.checked_mul(BPS)?;
    let rhs = (kink_bps as u128).checked_mul(n_cap)?;
    if lhs <= rhs || max_fee_bps == 0 {
        return Some(0);
    }
    let den = n_cap.checked_mul(BPS - kink_bps as u128)?;
    let fee = mul_div_ceil_u128(max_fee_bps as u128, lhs - rhs, den)?;
    Some(if fee > max_fee_bps as u128 {
        max_fee_bps
    } else {
        fee as u16
    })
}

/// N-2: the OPENING part of a taker fill (`|after|` for a flip, `|size|` for an open / grow, 0
/// for a strict reduction or close). Only this part ever pays the utilisation fee.
pub fn opening_part_q(taker_before_q: i128, taker_after_q: i128) -> u128 {
    if taker_strictly_reduces(taker_before_q, taker_after_q) {
        0
    } else if taker_flips(taker_before_q, taker_after_q) {
        taker_after_q.unsigned_abs()
    } else {
        taker_after_q.abs_diff(taker_before_q)
    }
}

/// N-2: the utilisation fee as a rate on the WHOLE fill (the fee channel charges bps on the
/// executed notional): `floor(fee_bps * opening / |fill|)`, so the closing part of a flip is
/// never charged (it rounds in the taker's favour by < 1 bps of the opening part).
#[cfg_attr(kani, kani::requires((fee_bps as u128).checked_mul(core::cmp::min(opening_q, fill_abs_q)).is_some()))]
#[cfg_attr(kani, kani::ensures(|r: &u16| spec::util_fee_on_fill_bps(fee_bps, opening_q, fill_abs_q, *r)))]
pub fn util_fee_on_fill_bps(fee_bps: u16, opening_q: u128, fill_abs_q: u128) -> u16 {
    if fill_abs_q == 0 || opening_q == 0 || fee_bps == 0 {
        return 0;
    }
    let o = if opening_q > fill_abs_q {
        fill_abs_q
    } else {
        opening_q
    };
    // Rounds DOWN (the closing part of a flip is never charged). `fee * o` cannot overflow at
    // engine-bounded sizes (fee <= 65535, |q| <= 2e17); if it ever did, the tx ABORTS exactly as
    // the pre-A1 multiply did under `overflow-checks = true`: fail closed, never a free open.
    // R1 (security review, proposal 3): `x <= fee` holds (o <= fill), but the clamp makes the
    // narrowing cast a LINEAR fact, machine-checked at full width, instead of a silent
    // truncation path if that ever failed.
    match crate::vault_lp_v18::mul_div_floor(fee_bps as u128, o, fill_abs_q) {
        Some(x) => core::cmp::min(x, fee_bps as u128) as u16,
        None => panic!("util fee overflow"),
    }
}

/// N-2: the market's engine `max_trading_fee_bps` must leave room for the base fee, the pinned
/// matcher request and the utilisation fee at its maximum (InitMarket and the dial setter).
pub fn util_fee_fits_trading_cap(
    max_trading_fee_bps: u64,
    base_fee_bps: u64,
    util_max_bps: u16,
) -> bool {
    match base_fee_bps
        .checked_add(GROWTH_PIN_MAX_REQUESTED_FEE_BPS as u64)
        .and_then(|v| v.checked_add(util_max_bps as u64))
    {
        Some(need) => max_trading_fee_bps >= need,
        None => false,
    }
}

/// N-2 dial bounds: without the epoch clamp the utilisation fee may only be RAISED from the
/// default (tighten-only: a cheaper lock-out is never allowed); always `<= HARD_MAX`.
pub fn util_fee_dial_ok(epoch_clamp_enforced: bool, util_max_bps: u16) -> bool {
    let lo = if epoch_clamp_enforced {
        0
    } else {
        GROWTH_UTIL_FEE_DEFAULT_BPS
    };
    util_max_bps >= lo && util_max_bps <= GROWTH_UTIL_FEE_HARD_MAX_BPS
}

/// L-4 (security review): G4 protocol defaults are applied FIELD BY FIELD at the tag-94 bind:
/// a field the upgrade authority preset (non-zero) is kept, a zero field gets its default.
pub fn g4_default_if_zero(current: u128, default: u128) -> u128 {
    if current == 0 {
        default
    } else {
        current
    }
}

/// Which sides of a fill the growth gate checks, from the P1 roles. Returns
/// `(a_is_taker, b_is_taker, lp_is_b)` where `lp_is_b` is `Some(true)` when account_b is the
/// fill's LP counterparty, `Some(false)` when account_a is, `None` when there is no single LP
/// (NoCpi between two non-LPs or two LPs: no crowd step, both sides face the ceiling).
///
/// * CPI routes: account_b is the matcher LP; account_a is ALWAYS checked, even if it has its
///   own enabled matcher config (registering a matcher cannot escape the ceiling).
/// * NoCpi: every side that is not THE single LP is checked.
pub fn growth_sides(cpi: bool, a_is_lp: bool, b_is_lp: bool) -> (bool, bool, Option<bool>) {
    let lp_is_b = if cpi {
        Some(true)
    } else {
        match (a_is_lp, b_is_lp) {
            (false, true) => Some(true),
            (true, false) => Some(false),
            _ => None,
        }
    };
    (lp_is_b != Some(false), lp_is_b != Some(true), lp_is_b)
}

// ── Upgrade-authority dials (tag 93 growth trailer) ─────────────────────────────────────────

/// Plan §2.9 L3: until the epoch return clamp makes `r_gap` program-enforced, the dials may
/// only TIGHTEN (or stay at) the growth-1 defaults: `lambda <= 1x`, `kink <= 50%`.
/// v2.2 growth overnight §1.1: ON, meaning "enforced PER MARKET" through `clamp_enforced` (the
/// engine band is the program-enforced epoch clamp). Off-band markets keep the growth-1
/// tighten-only box exactly. Setting this `false` is the program-wide kill switch: no market is
/// then clamp-enforced (no loosening anywhere).
pub const EPOCH_CLAMP_ENFORCED: bool = true;

/// Bounds for the UA setters. Without the epoch clamp: `lambda in [1, DEFAULT_LAMBDA_BPS]`
/// (never more LP leverage than 1x) and `kink in [0, DEFAULT_KINK_BPS]` (the step never starts
/// later than u = 50%). With it: `lambda in [1, MAX_LAMBDA_BPS]`, `kink in [0, 10_000]`.
pub fn growth_dials_ok(epoch_clamp_enforced: bool, lambda_bps: u32, kink_bps: u16) -> bool {
    let (lambda_max, kink_max) = if epoch_clamp_enforced {
        (MAX_LAMBDA_BPS, BPS as u16)
    } else {
        (DEFAULT_LAMBDA_BPS, DEFAULT_KINK_BPS)
    };
    lambda_bps >= 1 && lambda_bps <= lambda_max && kink_bps <= kink_max
}

// ── Auto-pin on a growth asset (tag 94) ─────────────────────────────────────────────────────

/// Matcher-context liquidity ceiling pinned at bind on a growth asset: 1e16 atoms ($10B at 6
/// decimals, the engine's `MAX_VAULT_TVL` scale). It only bounds the `min(ctx, ext)` the
/// matcher takes; the binding depth is the wrapper's ext-v3 `liquidity_notional_e6`.
pub const GROWTH_PIN_LIQUIDITY_E6: u128 = 10_000_000_000_000_000;

/// G4 (plan §2.3 step 5 / §2.5): the protocol defaults tag 94 writes into a growth asset's
/// `AssetRiskLimitsV17` when the record is still all-zero (an upgrade-authority tag-93 value
/// set before the bind is never overwritten):
/// * `matcher_ext_mode = 1`: the P2 call extension (mark slot, headroom, band) is on;
pub const GROWTH_PIN_MATCHER_EXT_MODE: u8 = 1;
/// * the fee channel ON (the spread now pays the LP instead of nobody), capped at the pinned
///   matcher's own `max_total_bps` (100 bps, inside the plan's 50-100 range). The matcher's
///   requested fee is `|exec - oracle| / oracle <= max_total`, so a cap BELOW max_total would
///   refuse every large fill the matcher legitimately prices at its clamp (found by
///   `growth_v19_bound_capacity_full_and_thin_side_open` with a 50 bps cap: Custom(9)).
pub const GROWTH_PIN_MAX_REQUESTED_FEE_BPS: u16 = 100;
const _: () =
    assert!(GROWTH_PIN_MAX_REQUESTED_FEE_BPS as u32 >= crate::vault_lp_v18::PIN_MAX_TOTAL_BPS);
/// * an LP floor > 0 (plan §2.9 L4): the vault LP halts risk-increasing fills before its equity
///   reaches 0 instead of at 0. 1e6 atoms = $1 for a 6-decimal collateral mint.
pub const GROWTH_PIN_LP_FLOOR_ATOMS: u128 = 1_000_000;
/// * and the matcher context kind 2 (v2 adaptive fee, size impact, skew surcharge / thin
///   rebate, stale-mark guard) instead of the kind-1 vAMM.
pub const GROWTH_PIN_MATCHER_KIND: u8 = 2;

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

// ── v2.2 Phase 4 items 1 + 2: band-gated growth and holding-fee rent ──────────────────────────

/// Graduation of the leverage ceiling above `L_launch` (design §1.1 "Graduation unlock").
/// Replaces the `GRADUATION_ENABLED` constant: allowed only on a band market (the Band Safety
/// Law, validated at InitMarket, is the program-enforced epoch clamp `r_gap` waited for) AND
/// with a depth tier >= 1 (item 4 / G8). v2.2 growth overnight: the only caller is
/// `graduation_on`, with the REAL engine `band_bps` and the REAL `depth_tier` (I-D1: stale or
/// absent depth is tier 0, never looser).
pub fn graduation_allowed(band_bps: u64, depth_tier: u8) -> bool {
    band_bps != 0 && depth_tier >= 1
}

/// v2.2: on a band market `r_gap` is DERIVED, `r_gap := G(d)` (the worst two-epoch adverse
/// move), no longer creator-declared. `None` when `d` is out of range or `G` does not fit u16.
pub fn band_r_gap_bps(band_bps: u64) -> Option<u16> {
    let g = percolator::band_rent::band_worst_adverse_bps(band_bps).ok()?;
    u16::try_from(g).ok()
}

/// v2.2 growth overnight §1.1: the per-market clamp predicate (pure core; Kani target). A market
/// is clamp-enforced iff the program-wide switch is on, the engine band is on (`band_bps != 0`;
/// the Band Safety Law was validated at InitMarket) AND the stored growth `r_gap` equals the
/// band's derived `G(d)` (`derived_r_gap_bps`, i.e. `band_r_gap_bps(band_bps)`). Every mismatch
/// (an off-band market, a growth record written by an older rule, an underivable `G`) fails
/// CLOSED: not enforced, so no loosening (graduation above `L_launch`, lambda > 1, alpha > 50%,
/// a utilisation fee below the default, the depth tiers) is reachable.
pub fn clamp_enforced(band_bps: u64, stored_r_gap_bps: u16, derived_r_gap_bps: Option<u16>) -> bool {
    EPOCH_CLAMP_ENFORCED && band_bps != 0 && derived_r_gap_bps == Some(stored_r_gap_bps)
}

/// `clamp_enforced` with `G(d)` derived here (re-checked at every read).
pub fn clamp_enforced_for(band_bps: u64, stored_r_gap_bps: u16) -> bool {
    band_bps != 0 && clamp_enforced(band_bps, stored_r_gap_bps, band_r_gap_bps(band_bps))
}

/// v2.2 growth overnight §1.1: graduation in force on one market right now: the program-wide
/// switch, the clamp predicate, and `graduation_allowed` on the REAL engine band and the REAL
/// depth tier (`depth_tier`).
pub fn graduation_on(clamp: bool, band_bps: u64, depth_tier: u8) -> bool {
    GRADUATION_ENABLED && clamp && graduation_allowed(band_bps, depth_tier)
}

/// v2.2: the vault-LP leverage ceiling a band market allows:
/// `floor(10_000 * (10_000 - 500) / (MMR + G))` bps, capped at `MAX_LAMBDA_BPS`, so the vault
/// LP itself stays at least 5% clear of its own maintenance over two epochs. `None` on a zero
/// denominator.
pub fn band_lambda_max_bps(maintenance_bps: u64, g_bps: u64) -> Option<u32> {
    let den = (maintenance_bps as u128).checked_add(g_bps as u128)?;
    if den == 0 {
        return None;
    }
    let v = BPS * (BPS - 500) / den;
    Some(if v > BAND_LAMBDA_CAP_BPS as u128 {
        BAND_LAMBDA_CAP_BPS
    } else {
        v as u32
    })
}

/// Review W-M2: the band-market lambda ceiling. Devnet keeps the design's 10x; mainnet builds
/// cap at 3x until the oracle has a second source and fraud checks.
#[cfg(feature = "devnet")]
pub const BAND_LAMBDA_CAP_BPS: u32 = MAX_LAMBDA_BPS;
#[cfg(not(feature = "devnet"))]
pub const BAND_LAMBDA_CAP_BPS: u32 = 30_000;

/// v2.2: the UA dial bounds. Off-band (no epoch clamp): the growth-1 tighten-only box
/// (`growth_dials_ok(false, ..)`). On a band market: `lambda in [1, band_lambda_max]`, kink
/// in [0, 100%]. v2.2 growth overnight §1.1: `band` is `Some` only on a CLAMP-ENFORCED market
/// (`clamp_enforced`); the effective lambda is still `min(lambda, λ_depth(tier))` at every read.
pub fn growth_dials_ok_for(band: Option<(u64, u64)>, lambda_bps: u32, kink_bps: u16) -> bool {
    match band {
        None => growth_dials_ok(false, lambda_bps, kink_bps),
        Some((maintenance_bps, g_bps)) => match band_lambda_max_bps(maintenance_bps, g_bps) {
            Some(max) => lambda_bps >= 1 && lambda_bps <= max && kink_bps as u128 <= BPS,
            None => false,
        },
    }
}

/// v2.2: alpha (Earn allocation) above 50% only on a band market, up to 70% on devnet.
/// Review W-M2: on mainnet builds (no `devnet` feature) at most 60% until the oracle has a
/// second source and fraud checks (the band bounds bad debt, not LP principal).
#[cfg(feature = "devnet")]
pub const ALLOC_ALPHA_MAX_BAND_BPS: u16 = 7_000;
#[cfg(not(feature = "devnet"))]
pub const ALLOC_ALPHA_MAX_BAND_BPS: u16 = 6_000;
/// v2.2 growth overnight §1.1: `band_on` is the per-market CLAMP predicate (`clamp_enforced`),
/// not the band alone (callers: tag 99's dial trailer).
pub fn alloc_alpha_max_bps(band_on: bool) -> u16 {
    if band_on {
        ALLOC_ALPHA_MAX_BAND_BPS
    } else {
        crate::vault_lp_v18::ALLOC_ALPHA_MAX_BPS
    }
}

/// v2.2 (security review I-1): the graduation reference `c_launch` is never below $1,000 of
/// 6-decimal collateral, so a 1-atom first junior deposit cannot pin it and graduate the
/// ceiling on the first real deposit.
pub const MIN_C_LAUNCH_ATOMS: u128 = 1_000_000_000;
pub fn c_launch_atoms_for(c_m: u128) -> u128 {
    if c_m > MIN_C_LAUNCH_ATOMS {
        c_m
    } else {
        MIN_C_LAUNCH_ATOMS
    }
}

// ── v2.2 growth overnight §1.4: I-1 graduation reset ──────────────────────────────────────

/// The graduation / depth part of an asset's growth record (`AssetGrowthV19` bytes 0..16,
/// 24..26, 44, 56..80). Everything else in the record (version, lambda, kink, l_tier, l_launch,
/// r_gap, the dials, the rent snapshot) is the market's CONFIGURATION and survives a restart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraduationFields {
    pub c_launch_atoms: u64,
    pub ceil_x100: u16,
    pub ceil_slot: u64,
    pub depth_e6: u64,
    pub depth_slot: u64,
    pub depth_prev_e6: u64,
    pub depth_source: u8,
}

/// Security review I-1 (security-review-v21-combination §8): a restarted asset, a reused slot,
/// an append activation and a retired re-activation are NEW markets on an old slot. Their
/// graduation state starts from scratch: no launch capital (`c_launch = 0`, re-snapshotted at
/// the first graduation evaluation), the ceiling at `min(L_launch, L_tier)` stamped `now` (so
/// the first climb waits a full ratchet epoch), and no depth (tier 0: I-D1). Kani:
/// `kani_g8_i1_reset_postconditions`.
pub fn graduation_reset(l_launch_x100: u16, l_tier_x100: u16, now_slot: u64) -> GraduationFields {
    GraduationFields {
        c_launch_atoms: 0,
        ceil_x100: if l_launch_x100 < l_tier_x100 {
            l_launch_x100
        } else {
            l_tier_x100
        },
        ceil_slot: now_slot,
        depth_e6: 0,
        depth_slot: 0,
        depth_prev_e6: 0,
        depth_source: 0,
    }
}

// ── v2.2 growth overnight §1.3: G8 depth input and liquidity tiers ─────────────────────────

/// A stored depth older than this many slots reads as absent (~60 s at 400 ms slots; the keeper
/// pushes every few seconds), the same bound as the ADL wind-down's mark age.
pub const DEPTH_MAX_AGE_SLOTS: u64 = 150;
/// `AssetGrowthV19::depth_source`: no depth (a 35 B push, or never pushed).
pub const DEPTH_SOURCE_NONE: u8 = 0;
/// `AssetGrowthV19::depth_source`: keeper-attested (PushAuthMark 44 B, mode 1). Trusted, and
/// capped at tier 1 (I-D3). An on-chain pool source (tiers 2 and 3) is not built: no source
/// value other than these two is accepted by the decoder or the record validator.
pub const DEPTH_SOURCE_ATTESTED: u8 = 1;
/// PushAuthMark 44 B `depth_mode`: 0 = none (the depth must be 0), 1 = keeper-attested. Any
/// other value is refused with `DepthInputInvalid` (128).
pub const DEPTH_MODE_NONE: u8 = 0;
pub const DEPTH_MODE_ATTESTED: u8 = 1;
/// Tier thresholds: USD of ±2% depth in collateral atoms (6 decimals): $25k / $100k / $500k.
pub const DEPTH_TIER1_E6: u64 = 25_000_000_000;
pub const DEPTH_TIER2_E6: u64 = 100_000_000_000;
pub const DEPTH_TIER3_E6: u64 = 500_000_000_000;

/// The effective depth: `min(depth_e6, depth_prev_e6)` (a one-push spike buys nothing), and 0
/// (absent) when either read is 0, when the last push is older than `DEPTH_MAX_AGE_SLOTS`, or
/// when `depth_slot` is AFTER `now` (a clock that went backwards is not trusted: fail closed).
pub fn effective_depth_e6(depth_e6: u64, depth_prev_e6: u64, depth_slot: u64, now_slot: u64) -> u64 {
    if depth_e6 == 0 || depth_prev_e6 == 0 {
        return 0;
    }
    match now_slot.checked_sub(depth_slot) {
        Some(age) if age <= DEPTH_MAX_AGE_SLOTS => {
            if depth_e6 < depth_prev_e6 {
                depth_e6
            } else {
                depth_prev_e6
            }
        }
        _ => 0,
    }
}

/// The stored depth after a PushAuthMark (35 B: `new_depth_e6 = 0`). Returns
/// `(depth_e6, depth_prev_e6, depth_slot)`.
/// * A push in a LATER slot than the stored sample: the stored depth becomes `depth_prev_e6`
///   and the new one is stored, stamped `now`.
/// * Security review W-L2: a push in the SAME slot as the stored sample (`now == depth_slot`,
///   e.g. two pushes in one slot or one transaction) is not a second point in time: `prev` is
///   kept and the stored depth can only FALL, `min(depth_e6, new)`. So the "min of two reads"
///   always spans two distinct slots, and a same-slot repeat can never raise the depth.
/// * A push stamped BEFORE the stored sample (`now < depth_slot`; the handler refuses a slot
///   regression, so this is defensive) is treated like the same slot (fall only).
pub fn depth_push_update(
    depth_e6: u64,
    depth_prev_e6: u64,
    depth_slot: u64,
    new_depth_e6: u64,
    now_slot: u64,
) -> (u64, u64, u64) {
    if depth_slot != 0 && now_slot <= depth_slot {
        let d = if new_depth_e6 < depth_e6 {
            new_depth_e6
        } else {
            depth_e6
        };
        (d, depth_prev_e6, depth_slot)
    } else {
        (new_depth_e6, depth_e6, now_slot)
    }
}

/// The liquidity tier of an EFFECTIVE depth: 0 below $25k (or absent / stale: I-D1), 1 from
/// $25k, 2 from $100k, 3 from $500k, but keeper-attested depth is capped at tier 1 (I-D3) and
/// any other source (none, or an unbuilt on-chain source) is tier 0 (fail closed).
pub fn depth_tier(effective_depth_e6: u64, source: u8) -> u8 {
    let raw = if effective_depth_e6 >= DEPTH_TIER3_E6 {
        3
    } else if effective_depth_e6 >= DEPTH_TIER2_E6 {
        2
    } else if effective_depth_e6 >= DEPTH_TIER1_E6 {
        1
    } else {
        0
    };
    if source == DEPTH_SOURCE_ATTESTED {
        if raw > 1 {
            1
        } else {
            raw
        }
    } else {
        0
    }
}

// ── ROLLBACK (tolerant of the v2.2 combined / growth round 2 record) ───────────────────────
// This build is the rollback target for the combined wrapper (growth round 2). The combined
// writes more into the growth record than f6e7180d knows: byte 44 bit 2 (`DEPTH_PREV_REAL`),
// bit 7 (`DEPTH_EVER`), source 2 (on-chain DEX), bytes 45..47 (`attested_max_tier`, collateral
// decimals + 1), 80..96 (`depth_last_good_*`), 96..114 (tier table) and 114..118 (rise stamp).
// Nothing below changes what an f6e7180d-written record does; it only (a) lets the validator
// accept the combined's records, (b) reads every source this build does not know as NO source,
// and (c) never lets a missing depth switch the kappa cap off once the combined saw one (W-M1).

/// Byte 44 bits 0-1: the source of the stored `depth_e6`.
pub const DEPTH_SOURCE_MASK: u8 = 0x03;
/// Byte 44 bit 2 (combined): the PREVIOUS sample was a real reading.
pub const DEPTH_PREV_REAL: u8 = 0x04;
/// Byte 44 bit 7 (combined, sticky): a fresh effective depth was seen once on this market.
pub const DEPTH_EVER: u8 = 0x80;
/// The largest source value the combined writes (2 = on-chain DEX).
pub const DEPTH_SOURCE_DEX: u8 = 2;
/// Combined `attested_max_tier` bound, and `collateral_decimals_p1` bound (12 + 1).
pub const ROLLBACK_ATTESTED_MAX_TIER: u8 = 3;
pub const ROLLBACK_DECIMALS_P1_MAX: u8 = 13;
/// The combined's sticky cap halves once per ratchet epoch of staleness.
pub const ROLLBACK_STICKY_EPOCH_SLOTS: u64 = RATCHET_EPOCH_SLOTS;

/// Validator for byte 44: only bits 0-1 (source 0..=2), bit 2 and bit 7 may be set.
pub fn depth_source_byte_tolerant_ok(b: u8) -> bool {
    b & !(DEPTH_SOURCE_MASK | DEPTH_PREV_REAL | DEPTH_EVER) == 0
        && (b & DEPTH_SOURCE_MASK) <= DEPTH_SOURCE_DEX
}

/// The source this build understands: keeper-attested (1) is itself; none (0), the on-chain DEX
/// (2) and anything else read as NONE (tier 0). Flag bits are ignored.
pub fn depth_source_known(b: u8) -> u8 {
    if b & DEPTH_SOURCE_MASK == DEPTH_SOURCE_ATTESTED {
        DEPTH_SOURCE_ATTESTED
    } else {
        DEPTH_SOURCE_NONE
    }
}

/// The new byte 44 after a PushAuthMark: `new_source` (this build's own 0 / 1) with the combined's
/// sticky `DEPTH_EVER` carried through untouched, so a later re-upgrade still sees that a
/// depth was once seen (W-M1). `DEPTH_PREV_REAL` is cleared: this build keeps no previous-real
/// claim (it reads `depth_prev_e6 != 0`), and the combined re-derives the bit on its first push
/// from the stored source bits; a clear bit only reads the pair as absent (sticky cap / no new
/// cap), never as a stale "real" one. For a record this build wrote alone the byte is exactly
/// f6e7180d's (0 / 1).
pub fn depth_source_after_push(old: u8, new_source: u8) -> u8 {
    (new_source & DEPTH_SOURCE_MASK) | (old & DEPTH_EVER)
}

/// The combined's sticky depth: `last_good >> floor((now - last_good_slot) / 9,000)`, 0 from 64
/// epochs on. A `last_good_slot` after `now` reads as age 0 (no decay: still a cap).
pub fn rollback_sticky_depth_e6(last_good_e6: u64, last_good_slot: u64, now_slot: u64) -> u64 {
    let k = now_slot.saturating_sub(last_good_slot) / ROLLBACK_STICKY_EPOCH_SLOTS;
    if k >= 64 {
        0
    } else {
        last_good_e6 >> k
    }
}

/// The depth the kappa cap on `N_cap` reads (0 = no cap, as `depth_cap_q`). W-M1: a missing
/// depth never switches the cap off once the combined saw one.
/// * a fresh effective depth (this build's own `effective_depth_e6`): itself, whatever source
///   wrote it (a DEX reading caps at tier 0, kappa 0.5: tighter than ignoring it);
/// * a fresh REAL zero (source bits non-zero, `depth_e6 == 0`, stamp fresh): 1 atom, i.e. a cap
///   of 0 (opens closed), as the combined. f6e7180d never stores this (a 0 is source NONE);
/// * none fresh but `DEPTH_EVER`: the sticky depth, floored at 1 atom (a decayed sticky depth is
///   a cap of 0, never "uncapped");
/// * otherwise 0: never had a depth, no depth cap (f6e7180d exactly).
pub fn rollback_cap_depth_e6(
    effective_depth_e6: u64,
    depth_source_byte: u8,
    depth_e6: u64,
    depth_slot: u64,
    last_good_e6: u64,
    last_good_slot: u64,
    now_slot: u64,
) -> u64 {
    if effective_depth_e6 > 0 {
        return effective_depth_e6;
    }
    let fresh = matches!(now_slot.checked_sub(depth_slot), Some(age) if age <= DEPTH_MAX_AGE_SLOTS);
    if fresh && depth_source_byte & DEPTH_SOURCE_MASK != 0 && depth_e6 == 0 {
        return 1;
    }
    if depth_source_byte & DEPTH_EVER != 0 {
        let s = rollback_sticky_depth_e6(last_good_e6, last_good_slot, now_slot);
        return if s == 0 { 1 } else { s };
    }
    0
}

/// Whether the combined's tier table is the protocol default: thresholds `[0|25k, 0|100k,
/// 0|500k]` whole tokens, leverage `[0|500, 0|1000, 0|2000]` and 6-decimal collateral (stored
/// decimals + 1 of 0 or 7). Only then does this build's fixed tier table apply; a market with a
/// custom table (or other decimals) is held at tier 0 (launch leverage, the minimum of any
/// table), because this build cannot honour the custom table and must never be looser than it.
pub fn rollback_tier_config_is_default(
    threshold_usd: [u32; 3],
    leverage_x100: [u16; 3],
    collateral_decimals_p1: u8,
) -> bool {
    if collateral_decimals_p1 != 0 && collateral_decimals_p1 != 7 {
        return false;
    }
    let mut i = 0;
    while i < 3 {
        if threshold_usd[i] != 0 && threshold_usd[i] != [25_000u32, 100_000, 500_000][i] {
            return false;
        }
        if leverage_x100[i] != 0 && leverage_x100[i] != [500u16, 1_000, 2_000][i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `L_depth` (x100): tier 0 -> `L_launch`, 1 -> 5x, 2 -> 10x, 3 -> 20x.
pub fn l_depth_x100(tier: u8, l_launch_x100: u16) -> u16 {
    match tier {
        1 => 500,
        2 => 1_000,
        3 => 2_000,
        _ => l_launch_x100,
    }
}

/// `λ_depth` (bps): 1x at tiers 0 and 1, 2x at tier 2, 3x at tier 3.
pub fn lambda_depth_bps(tier: u8) -> u32 {
    match tier {
        2 => 20_000,
        3 => 30_000,
        _ => DEFAULT_LAMBDA_BPS,
    }
}

/// `κ_depth` (bps of the depth): 0.5 at tier 0, 1 at tiers 1 and 2, 2 at tier 3.
pub fn kappa_depth_bps(tier: u8) -> u32 {
    match tier {
        1 | 2 => 10_000,
        3 => 20_000,
        _ => 5_000,
    }
}

/// `λ_eff = min(stored λ, λ_depth(tier))`.
pub fn lambda_eff_bps(stored_lambda_bps: u32, tier: u8) -> u32 {
    let d = lambda_depth_bps(tier);
    if stored_lambda_bps < d {
        stored_lambda_bps
    } else {
        d
    }
}

/// The depth capacity notional `floor(κ_depth · depth / 1e4)` (collateral atoms), or `None`
/// when the effective depth is 0 (absent / stale: no depth cap, today's capacity). Never
/// overflows (`u64 · 2e4 < 2^79`).
pub fn depth_notional_cap_e6(tier: u8, effective_depth_e6: u64) -> Option<u128> {
    if effective_depth_e6 == 0 {
        return None;
    }
    Some((effective_depth_e6 as u128) * (kappa_depth_bps(tier) as u128) / BPS)
}

/// The depth cap on `N_cap` in engine Q: `floor(depth_notional * POS_SCALE / price)` (rounds
/// DOWN, so `<= κ·depth/P`, I-D4), `u128::MAX` (no cap) when the depth is absent, and 0 (fail
/// closed) on a zero price.
pub fn depth_cap_q(tier: u8, effective_depth_e6: u64, price_e6: u64, pos_scale: u128) -> u128 {
    match depth_notional_cap_e6(tier, effective_depth_e6) {
        None => u128::MAX,
        Some(nd) => n_cap_q(nd, DEFAULT_LAMBDA_BPS, price_e6, pos_scale).unwrap_or(0),
    }
}

/// G8 `N_cap` (every reader: the post-fill gate, the TradeCpi open-room clip, the matcher ext
/// v3 caps, the rent `N_cap` snapshot). Off a clamp-enforced market: EXACTLY growth-1's
/// `n_cap_q(C_m, stored λ)` (depth is stored but never read there). On one:
/// `min(n_cap_q(C_m, λ_eff), depth cap)`, the depth cap only while the depth is fresh.
/// `None` (refuse crowd growth) exactly where `n_cap_q` is.
pub fn n_cap_g8_q(
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    tier: u8,
    effective_depth_e6: u64,
    price_e6: u64,
    pos_scale: u128,
) -> Option<u128> {
    if !clamp {
        return n_cap_q(c_m, stored_lambda_bps, price_e6, pos_scale);
    }
    let n = n_cap_q(c_m, lambda_eff_bps(stored_lambda_bps, tier), price_e6, pos_scale)?;
    let d = depth_cap_q(tier, effective_depth_e6, price_e6, pos_scale);
    Some(if n < d { n } else { d })
}

/// G8 ext-v3 `(inventory_cap_q, liquidity_notional_e6)`. Off a clamp-enforced market, or with
/// no fresh depth: `growth_matcher_caps` at the lambda `n_cap_g8_q` uses (byte-identical off
/// the clamp). With a fresh depth: the cap is `min(N_cap(λ_eff), depth cap, engine limit)` and
/// the liquidity is `DEPTH_MULT` times the SMALLER capacity notional, so the matcher's impact
/// stays finite at the cap and `N_cap` stays the one binding number.
#[allow(clippy::too_many_arguments)]
pub fn growth_matcher_caps_g8(
    hlock_active: bool,
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    tier: u8,
    effective_depth_e6: u64,
    price_e6: u64,
    pos_scale: u128,
    max_position_abs_q: u128,
) -> (u128, u128) {
    if !clamp {
        return growth_matcher_caps(
            hlock_active,
            c_m,
            stored_lambda_bps,
            price_e6,
            pos_scale,
            max_position_abs_q,
        );
    }
    let lam = lambda_eff_bps(stored_lambda_bps, tier);
    let nd = match depth_notional_cap_e6(tier, effective_depth_e6) {
        None => {
            return growth_matcher_caps(hlock_active, c_m, lam, price_e6, pos_scale, max_position_abs_q)
        }
        Some(nd) => nd,
    };
    if hlock_active {
        return (0, 0);
    }
    let cap = n_cap_g8_q(true, c_m, stored_lambda_bps, tier, effective_depth_e6, price_e6, pos_scale)
        .unwrap_or(0);
    let cap = if cap > max_position_abs_q {
        max_position_abs_q
    } else {
        cap
    };
    if cap == 0 {
        return (0, 0);
    }
    let liq_capital = liquidity_notional_e6(c_m, lam).unwrap_or(0);
    let liq_depth = nd.saturating_mul(DEPTH_MULT);
    (cap, if liq_capital < liq_depth { liq_capital } else { liq_depth })
}

// ── v2.2 growth overnight §1.2: ceiling target, force-down, ratchet ────────────────────────

/// The live ceiling target (x100):
/// ```text
/// graduation on, no force-down: min(L_tier, max(L_launch, min(L_depth, L_launch + steps·1x)))
/// otherwise:                    min(L_launch, L_tier)
/// ```
/// `steps = floor(log2(C_m / C_launch))` (0 when `C_launch == 0` or `C_m < C_launch`), via
/// `graduated_ceiling_x100`. Never above `L_tier` or `max(launch, L_depth)` (I-D2), never below
/// the launch ceiling. `force_down`: a senior draw / backstop outstanding, the bankruptcy h-lock
/// latched, or ADL on either side.
pub fn target_ceiling_x100(
    graduation: bool,
    force_down: bool,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_depth_x100: u16,
    c_m: u128,
    c_launch: u128,
) -> u16 {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    if !graduation || force_down {
        return launch;
    }
    // min(L_tier, launch + steps), == launch with no launch capital.
    let stepped = graduated_ceiling_x100(true, l_launch_x100, l_tier_x100, c_m, c_launch);
    let capped = if l_depth_x100 < stepped {
        l_depth_x100
    } else {
        stepped
    };
    if capped > launch {
        capped
    } else {
        launch
    }
}

/// The ceiling the gate applies (x100). Off a clamp-enforced market: `min(L_launch, L_tier)`,
/// exactly growth-1 (off-band identity). On one: `min(stored ratcheted ceil, live target)`, so
/// it is never looser than the target now (a stale stored ceiling cannot outlive the depth,
/// capital or force-down that justified it).
pub fn ceiling_in_force_x100(
    clamp: bool,
    stored_ceil_x100: u16,
    target_x100: u16,
    l_launch_x100: u16,
    l_tier_x100: u16,
) -> u16 {
    if !clamp {
        return if l_launch_x100 < l_tier_x100 {
            l_launch_x100
        } else {
            l_tier_x100
        };
    }
    if stored_ceil_x100 < target_x100 {
        stored_ceil_x100
    } else {
        target_x100
    }
}

/// The ratchet WRITER at a site with the bound vault LP's `C_m` in hand (clamp-enforced markets
/// only). Returns `(ceil_x100, ceil_slot, c_launch_atoms)`:
/// * `c_launch == 0` (never recorded, or reset by I-1): snapshot `c_launch_atoms_for(C_m)` when
///   `C_m > 0`, and the ceiling does NOT climb in this call (target = launch);
/// * otherwise ratchet toward `target_ceiling_x100` (falls at once, rises <= +1x per epoch).
#[allow(clippy::too_many_arguments)]
pub fn graduation_ratchet(
    prev_ceil_x100: u16,
    prev_slot: u64,
    c_launch_atoms: u64,
    c_m: u128,
    graduation: bool,
    force_down: bool,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_depth_x100: u16,
    now_slot: u64,
) -> (u16, u64, u64) {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    if c_launch_atoms == 0 {
        let c_launch = if c_m > 0 {
            u64::try_from(c_launch_atoms_for(c_m)).unwrap_or(u64::MAX)
        } else {
            0
        };
        // No climb in this call, not even toward launch from a ceiling below it: the target is
        // min(prev, launch), so the ceiling can only fall (to launch) or stay.
        let hold = if launch < prev_ceil_x100 {
            launch
        } else {
            prev_ceil_x100
        };
        let (c, s) = ratchet_ceiling_x100(prev_ceil_x100, prev_slot, hold, launch, force_down, now_slot);
        return (c, s, c_launch);
    }
    let target = target_ceiling_x100(
        graduation,
        force_down,
        l_launch_x100,
        l_tier_x100,
        l_depth_x100,
        c_m,
        c_launch_atoms as u128,
    );
    let (c, s) = ratchet_ceiling_x100(prev_ceil_x100, prev_slot, target, launch, force_down, now_slot);
    (c, s, c_launch_atoms)
}

/// The FALL-ONLY ratchet (PushAuthMark: the depth changed but no `C_m` is in hand). The upper
/// bound is the target at unbounded capital, so the stored ceiling only ever falls here (at
/// once, stamped `now`); it never rises without the LP's equity.
#[allow(clippy::too_many_arguments)]
pub fn graduation_fall_only(
    prev_ceil_x100: u16,
    prev_slot: u64,
    c_launch_atoms: u64,
    graduation: bool,
    force_down: bool,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_depth_x100: u16,
    now_slot: u64,
) -> (u16, u64) {
    let upper = target_ceiling_x100(
        graduation,
        force_down,
        l_launch_x100,
        l_tier_x100,
        l_depth_x100,
        u128::MAX,
        c_launch_atoms as u128,
    );
    if upper < prev_ceil_x100 {
        (upper, now_slot)
    } else {
        (prev_ceil_x100, prev_slot)
    }
}

/// v2.2 item 2: on a rent market the one-time utilisation toll is only an ENTRY floor (a
/// one-slot flash lock pays no rent), 25 bps at `u = 1` instead of 500 (closes N-2: rent, not
/// a toll, prices a held lock-out).
pub const RENT_ENTRY_FLOOR_BPS: u16 = 25;

/// Security re-review N-1: the program floor on a band market's minimum leg notional, in
/// whole collateral tokens (the creator may set more; the SDK default is 100). With 256 legs
/// per side, filling the cap locks at least `512 x 10 tokens x IMR` of margin.
pub const BAND_MIN_LEG_NOTIONAL_TOKENS: u128 = 10;
pub fn band_min_leg_notional_floor(collateral_decimals: u8) -> u64 {
    let atoms = BAND_MIN_LEG_NOTIONAL_TOKENS
        .saturating_mul(10u128.saturating_pow(u32::from(collateral_decimals.min(30))));
    u64::try_from(atoms).unwrap_or(u64::MAX)
}

/// Review W-M1: on a rent market (`rent_max != 0`) the rent ceiling is at least
/// `RENT_MIN_E9_PER_SLOT` and the kink at most `RENT_MAX_KINK_BPS`, so the rent that replaces
/// the 500 bps N-2 toll actually bites. `rent_max == 0` (no rent) is always shape-valid here.
pub const RENT_MIN_E9_PER_SLOT: u64 = 10;
pub const RENT_MAX_KINK_BPS: u16 = 8_000;
pub fn rent_params_ok(rent_max_e9_per_slot: u64, rent_kink_bps: u16) -> bool {
    rent_max_e9_per_slot == 0
        || (rent_max_e9_per_slot >= RENT_MIN_E9_PER_SLOT && rent_kink_bps <= RENT_MAX_KINK_BPS)
}

/// Review: rent rate that fails CLOSED. `rent_rate_e9` returns `None` only out of domain
/// (overflow); charging 0 there would let an overflow switch rent off, so it charges the
/// ceiling instead.
pub fn rent_rate_e9_fail_closed(users_q: u128, n_cap_q: u128, kink_bps: u16, rent_max: u64) -> u64 {
    rent_rate_e9(users_q, n_cap_q, kink_bps, rent_max).unwrap_or(rent_max)
}

/// The utilisation-fee maximum in force: the stored dial, or the default when 0 (the rent
/// entry floor on rent markets, `GROWTH_UTIL_FEE_DEFAULT_BPS` elsewhere).
pub fn util_fee_max_effective_bps_for(stored_bps: u16, rent_on: bool) -> u16 {
    if stored_bps != 0 {
        stored_bps
    } else if rent_on {
        RENT_ENTRY_FLOOR_BPS
    } else {
        GROWTH_UTIL_FEE_DEFAULT_BPS
    }
}

/// UA dial bounds for the utilisation fee: tighten-only from the default off-band without
/// rent; down to the rent entry floor on a rent market; down to 0 on a band market.
/// v2.2 growth overnight §1.1: `band_on` is the per-market CLAMP predicate (`clamp_enforced`).
pub fn util_fee_dial_ok_for(band_on: bool, rent_on: bool, util_max_bps: u16) -> bool {
    let lo = if band_on {
        0
    } else if rent_on {
        RENT_ENTRY_FLOOR_BPS
    } else {
        GROWTH_UTIL_FEE_DEFAULT_BPS
    };
    util_max_bps >= lo && util_max_bps <= GROWTH_UTIL_FEE_HARD_MAX_BPS
}

/// v2.2 item 2 (design §2.1): the per-side holding-fee rent rate, e9 of notional per slot.
///
/// ```text
/// u = users_OI_side / N_cap
/// r = 0                                              u <= kink
///   = ceil(max * (u - kink) / (1 - kink))            kink < u < 1
///   = max                                            u >= 1
/// ```
///
/// `None` on `n_cap == 0`, a kink above 100% or an overflow; callers treat `None` as 0 (no
/// capacity measured, no rent; the growth gate refuses opens there anyway). I-R1: 0 at or
/// below the kink, never above `max`, monotone non-decreasing in `users_oi_side_q`.
pub fn rent_rate_e9(
    users_oi_side_q: u128,
    n_cap_q: u128,
    kink_bps: u16,
    max_e9_per_slot: u64,
) -> Option<u64> {
    if n_cap_q == 0 || kink_bps as u128 > BPS {
        return None;
    }
    let lhs = users_oi_side_q.checked_mul(BPS)?;
    let rhs = (kink_bps as u128).checked_mul(n_cap_q)?;
    if lhs <= rhs || max_e9_per_slot == 0 {
        return Some(0);
    }
    if users_oi_side_q >= n_cap_q {
        return Some(max_e9_per_slot);
    }
    // Here kink < 10_000 (else lhs <= rhs because users < n).
    let den = n_cap_q.checked_mul(BPS - kink_bps as u128)?;
    let r = mul_div_ceil_u128(max_e9_per_slot as u128, lhs - rhs, den)?;
    Some(if r > max_e9_per_slot as u128 {
        max_e9_per_slot
    } else {
        r as u64
    })
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

/// The P2 call-extension flag "this request only reduces the taker" (bit 3 of byte 1; same
/// value as `risk_limits_v17::EXT_FLAG_TAKER_REDUCING` and the matcher's).
pub const EXT_FLAG_TAKER_REDUCING: u8 = 1 << 3;

/// M-1: mark a growth leg's v3 block TAKER_REDUCING when the wrapper verified the leg only
/// reduces the taker (strict, or a flip already clipped to its close). The matcher then never
/// clips it for LP capacity (v3 cap, closed mode, kind-2 size budget).
pub fn ext_v3_mark_taker_reducing(
    mut b: [u8; CALL_EXT_V3_LEN],
    taker_reducing: bool,
) -> [u8; CALL_EXT_V3_LEN] {
    if taker_reducing {
        b[1] |= EXT_FLAG_TAKER_REDUCING;
    }
    b
}

/// Kani contracts (security review A2, 2026-10-05): EXACT, overflow-free, remainder-form
/// specifications of the arithmetic above. Compiled only under `cfg(kani)`; the `.so` is
/// unchanged by them (CI `scripts/kani-contracts-bytecheck.sh`).
#[cfg(kani)]
pub mod spec {
    use super::{BPS, MAX_IMR_BPS};

    /// `q == ceil(p / d)`: `q*d == p + r ∧ r < d`, written without the possibly-overflowing
    /// `q*d`: `q == 0 ⇔ p == 0`, else `(q-1)*d < p ∧ p - (q-1)*d <= d`.
    pub fn ceil_rel(p: u128, d: u128, q: u128) -> bool {
        if d == 0 {
            return false;
        }
        if q == 0 {
            return p == 0;
        }
        (q - 1).checked_mul(d).is_some_and(|x| x < p && p - x <= d)
    }

    /// Floor (rounds DOWN): the contract of `vault_lp_v18::mul_div_floor`.
    pub use crate::vault_lp_v18::mul_div_floor_spec as mul_div_floor;

    /// Ceil (rounds UP). `None ⇔ d == 0 ∨ a*b overflows`.
    pub fn mul_div_ceil(a: u128, b: u128, d: u128, r: Option<u128>) -> bool {
        match (d == 0, a.checked_mul(b)) {
            (true, _) | (false, None) => r.is_none(),
            (false, Some(p)) => r.is_some_and(|q| ceil_rel(p, d, q)),
        }
    }

    /// Width-independent range facts of the ceil primitive (proved with the contract at u8,
    /// paper lift): when it returns `Some(q)`, `b <= d ⇒ q <= a` and `b >= d ⇒ q >= a`.
    pub fn mul_div_ceil_facts(a: u128, b: u128, d: u128, r: Option<u128>) -> bool {
        r.is_none_or(|q| (b > d || q <= a) && (b < d || q >= a))
    }

    // ── Composite specs (rev 6b, review C1): each states its DESIGN formula, over the primitive
    // spec applied to the formula's own operands, so a `stub_verified` primitive's assumption and
    // the composite's assertion are the same predicate on the same terms. Branches whose truth is
    // a nonlinear fact are split on a LINEAR test of those operands (num vs den), where the
    // primitive range facts decide them.

    /// Plan §2.1: `N_cap_q = floor(C_m · λ · POS_SCALE / (10_000 · price_e6))`; fails closed
    /// (`None`) on price 0 or overflow. `10_000 · price_e6 <= 1e4 · u64::MAX` never overflows.
    pub fn n_cap_q(
        c_m: u128,
        lambda_bps: u32,
        price_e6: u64,
        pos_scale: u128,
        r: Option<u128>,
    ) -> bool {
        if price_e6 == 0 {
            return r.is_none();
        }
        // same terms as the code; `kani_growth_c_n_cap_q` asserts 1e4 · price never overflows
        match (
            c_m.checked_mul(lambda_bps as u128),
            BPS.checked_mul(price_e6 as u128),
        ) {
            (Some(x), Some(den)) => mul_div_floor(x, pos_scale, den, r),
            _ => r.is_none(),
        }
    }

    /// Plan §2.2 (ext v3 depth): `liquidity_notional_e6 = floor(C_m · λ · DEPTH_MULT / 10_000)`;
    /// `None` on overflow.
    pub fn liquidity_notional_e6(c_m: u128, lambda_bps: u32, r: Option<u128>) -> bool {
        match c_m.checked_mul(lambda_bps as u128) {
            None => r.is_none(),
            Some(x) => mul_div_floor(x, super::DEPTH_MULT, BPS, r),
        }
    }

    /// Plan §2.1 "Require" side: risk notional `= ceil(|q| · price_e6 / POS_SCALE)` (rounds UP,
    /// against the taker); `None` on scale 0 or overflow.
    pub fn risk_notional_ceil(
        abs_q: u128,
        price_e6: u64,
        pos_scale: u128,
        r: Option<u128>,
    ) -> bool {
        mul_div_ceil(abs_q, price_e6 as u128, pos_scale, r)
    }

    /// Plan §2.1 + N-1 (u = users OI on the side / N_cap):
    ///   IMR_dyn = base                                    if u <= k
    ///           = base + ceil(span · (u − k)/(1 − k))     if k < u <= 1   (u == 1 ⇒ 10_000)
    ///           = refuse (None)                           if u > 1
    /// with span = 10_000 − base and, in integers, (u − k)/(1 − k) = (lp·1e4 − k·n)/(n·(1e4 − k)).
    /// Fails closed on n == 0, base > 10_000, k > 10_000, or overflow. The result is in
    /// [base, 10_000]. `num > den` cannot happen while lp <= n; that branch only pins the
    /// fail-closed shape (None or full margin).
    pub fn dyn_imr_bps(lp: u128, n: u128, base: u64, k: u16, r: Option<u64>) -> bool {
        if base > MAX_IMR_BPS || k as u128 > BPS || n == 0 || lp > n {
            return r.is_none();
        }
        let (lhs, rhs) = match (lp.checked_mul(BPS), (k as u128).checked_mul(n)) {
            (Some(a), Some(b)) => (a, b),
            _ => return r.is_none(),
        };
        if lhs <= rhs {
            return r == Some(base);
        }
        let span = (MAX_IMR_BPS - base) as u128;
        let den = match n.checked_mul(BPS - k as u128) {
            Some(d) => d,
            None => return r.is_none(),
        };
        let num = lhs - rhs;
        if num > den {
            return r.is_none() || r == Some(MAX_IMR_BPS);
        }
        match r {
            None => span.checked_mul(num).is_none(),
            Some(v) => {
                v >= base
                    && v <= MAX_IMR_BPS
                    && (num < den || v == MAX_IMR_BPS)
                    && mul_div_ceil(span, num, den, Some((v - base) as u128))
            }
        }
    }

    /// Engine per-leg IM (percolator src/v16.rs:23050-23056): `0` when flat, else
    /// `max(ceil(notional · imr / 10_000), min_nonzero)`; imr > 10_000 fails closed.
    pub fn leg_im_req(n: u128, imr: u64, min: u128, r: Option<u128>) -> bool {
        if n == 0 {
            return r == Some(0);
        }
        if imr > MAX_IMR_BPS {
            return r.is_none();
        }
        match n.checked_mul(imr as u128) {
            None => r.is_none(),
            Some(p) => r.is_some_and(|v| {
                v >= min
                    && if v > min {
                        mul_div_ceil(n, imr as u128, BPS, Some(v))
                    } else {
                        // ceil(p / 1e4) <= min  ⇔  p <= min · 1e4
                        min.checked_mul(BPS).is_none_or(|m| p <= m)
                    }
            }),
        }
    }

    /// Security round 3 N-2 / round 4 Q2: `fee = ceil(max · (u − k)/(1 − k))` capped at `max`;
    /// 0 at or below the kink or when max == 0; `n == 0` (or k > 10_000) → None; `None` on
    /// overflow. `num >= den` is u >= 1: the cap.
    pub fn utilisation_fee_bps(o: u128, n: u128, k: u16, max: u16, r: Option<u16>) -> bool {
        if n == 0 || k as u128 > BPS {
            return r.is_none();
        }
        let (lhs, rhs) = match (o.checked_mul(BPS), (k as u128).checked_mul(n)) {
            (Some(a), Some(b)) => (a, b),
            _ => return r.is_none(),
        };
        if lhs <= rhs || max == 0 {
            return r == Some(0);
        }
        let den = match n.checked_mul(BPS - k as u128) {
            Some(d) => d,
            None => return r.is_none(),
        };
        let num = lhs - rhs;
        match (max as u128).checked_mul(num) {
            None => r.is_none(),
            Some(_) => {
                if num >= den {
                    r == Some(max)
                } else {
                    r.is_some_and(|v| {
                        v <= max && mul_div_ceil(max as u128, num, den, Some(v as u128))
                    })
                }
            }
        }
    }

    /// N-2 (round 4 Q2: never on the closing part): the rate on a fill is
    /// `floor(fee · min(opening, fill) / fill)` (rounds DOWN), 0 on a zero input, never above
    /// `fee`. Precondition (the `requires`): `fee · min(opening, fill)` fits u128; production
    /// aborts otherwise (fail closed).
    pub fn util_fee_on_fill_bps(fee: u16, o: u128, fill: u128, r: u16) -> bool {
        if fill == 0 || o == 0 || fee == 0 {
            return r == 0;
        }
        let o = if o > fill { fill } else { o };
        r <= fee && mul_div_floor(fee as u128, o, fill, Some(r as u128))
    }
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
            Some(10_000),
            "u == 1 admitted at 100%"
        );
        assert_eq!(
            dyn_imr_bps(1_000_001, n, 1_000, 5_000),
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
        // depth = kappa (4) x the capacity notional
        assert_eq!(
            liquidity_notional_e6(1_000_000_000, 10_000),
            Some(4_000_000_000)
        );
        assert_eq!(liquidity_notional_e6(u128::MAX, 10_000), None);
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
                mid_q: 0,
                after_q: -(100 * PS as i128),
                eff_after_abs_q: 100 * PS,
                users_oi_side_after_q: 100 * PS,
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
            asset_bound: true,
            depth_cap_q: u128::MAX,
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
            mid_q: -(800 * PS as i128),
            after_q: -(900 * PS as i128),
            eff_after_abs_q: 900 * PS,
            users_oi_side_after_q: 900 * PS,
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
            mid_q: -(900 * PS as i128),
            after_q: -(800 * PS as i128),
            eff_after_abs_q: 800 * PS,
            users_oi_side_after_q: 800 * PS,
            equity: 1_000_000_000,
        });
        t.taker_equity = 10_000_000;
        assert_eq!(growth_gate(&t), GrowthVerdict::Allow);
        // u == 1 exactly is admitted at 100% IMR (Q3); u > 1 refuses the crowd; reductions pass.
        let mut e = c;
        e.lp = Some(GrowthLpIn {
            before_q: -(900 * PS as i128),
            mid_q: -(900 * PS as i128),
            after_q: -(1_000 * PS as i128),
            eff_after_abs_q: 1_000 * PS,
            users_oi_side_after_q: 1_000 * PS,
            equity: 1_000_000_000,
        });
        e.taker_equity = 100_000_000; // 100% of the 100-unit notional
        assert_eq!(growth_gate(&e), GrowthVerdict::Allow, "u == 1 at 1x");
        e.taker_equity = 99_999_999;
        assert_eq!(growth_gate(&e), GrowthVerdict::LeverageExceeded);
        let mut f = c;
        f.lp = Some(GrowthLpIn {
            before_q: -(900 * PS as i128),
            mid_q: -(900 * PS as i128),
            after_q: -(1_000 * PS as i128 + 1),
            eff_after_abs_q: 1_000 * PS + 1,
            users_oi_side_after_q: 1_000 * PS + 1,
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
    fn i1_graduation_reset_postconditions() {
        let r = graduation_reset(550, 1_000, 77);
        assert_eq!(
            r,
            GraduationFields {
                c_launch_atoms: 0,
                ceil_x100: 550,
                ceil_slot: 77,
                ..Default::default()
            }
        );
        assert_eq!(graduation_reset(1_200, 1_000, 5).ceil_x100, 1_000, "launch above tier clamps");
    }

    #[test]
    fn g8_flags_on_and_clamp_predicate() {
        assert!(GRADUATION_ENABLED && EPOCH_CLAMP_ENFORCED);
        // band on AND r_gap == G(d); every mismatch fails closed
        assert!(clamp_enforced(130, 397, Some(397)));
        assert!(!clamp_enforced(0, 397, Some(397)), "off-band");
        assert!(!clamp_enforced(130, 400, Some(397)), "stored r_gap from another rule");
        assert!(!clamp_enforced(130, 397, None), "underivable G");
        assert!(graduation_on(true, 130, 1));
        assert!(!graduation_on(false, 130, 1), "no clamp, no graduation");
        assert!(!graduation_on(true, 130, 0), "tier 0 (absent depth), no graduation");
    }

    // ── ROLLBACK build: the combined's byte-44 / sticky / tier-table rules ──────────────────
    #[test]
    fn rollback_depth_source_byte_validator_matches_the_combined() {
        // Every byte the combined can write is accepted; everything else is refused.
        for b in 0u16..=255 {
            let b = b as u8;
            let combined = b & !(0x03 | 0x04 | 0x80) == 0 && (b & 0x03) <= 2;
            assert_eq!(depth_source_byte_tolerant_ok(b), combined, "byte {b:#04x}");
        }
        for ok in [0x00u8, 0x01, 0x02, 0x04, 0x05, 0x06, 0x80, 0x81, 0x82, 0x84, 0x85, 0x86] {
            assert!(depth_source_byte_tolerant_ok(ok), "{ok:#04x}");
        }
        for bad in [0x03u8, 0x07, 0x08, 0x10, 0x40, 0x83, 0xFF] {
            assert!(!depth_source_byte_tolerant_ok(bad), "{bad:#04x}");
        }
    }

    #[test]
    fn rollback_unknown_sources_are_no_source() {
        for b in [0x00u8, 0x02, 0x04, 0x06, 0x80, 0x84, 0x86, 0x82] {
            assert_eq!(depth_source_known(b), DEPTH_SOURCE_NONE, "{b:#04x}");
            assert_eq!(depth_tier(DEPTH_TIER3_E6, depth_source_known(b)), 0, "tier 0: {b:#04x}");
        }
        for b in [0x01u8, 0x05, 0x81, 0x85] {
            assert_eq!(depth_source_known(b), DEPTH_SOURCE_ATTESTED, "{b:#04x}");
            assert_eq!(depth_tier(DEPTH_TIER3_E6, depth_source_known(b)), 1, "I-D3 cap: {b:#04x}");
        }
    }

    #[test]
    fn rollback_push_keeps_ever_and_never_claims_prev_real() {
        for old in [0x00u8, 0x01, 0x04, 0x05, 0x80, 0x81, 0x84, 0x85, 0x82, 0x86, 0x02] {
            for src in [DEPTH_SOURCE_NONE, DEPTH_SOURCE_ATTESTED] {
                let n = depth_source_after_push(old, src);
                assert_eq!(n & DEPTH_SOURCE_MASK, src);
                assert_eq!(n & DEPTH_EVER, old & DEPTH_EVER, "EVER is sticky");
                assert_eq!(n & DEPTH_PREV_REAL, 0);
                assert!(depth_source_byte_tolerant_ok(n));
            }
        }
        // A record this build wrote alone is f6e7180d's byte exactly.
        assert_eq!(depth_source_after_push(0, 1), 1);
        assert_eq!(depth_source_after_push(1, 0), 0);
    }

    #[test]
    fn rollback_sticky_depth_halves_per_epoch_and_decays_to_zero() {
        assert_eq!(rollback_sticky_depth_e6(800, 1_000, 1_000), 800);
        assert_eq!(rollback_sticky_depth_e6(800, 1_000, 1_000 + 8_999), 800);
        assert_eq!(rollback_sticky_depth_e6(800, 1_000, 1_000 + 9_000), 400);
        assert_eq!(rollback_sticky_depth_e6(800, 1_000, 1_000 + 27_000), 100);
        assert_eq!(rollback_sticky_depth_e6(800, 1_000, 1_000 + 9_000 * 64), 0);
        assert_eq!(rollback_sticky_depth_e6(800, 5_000, 1_000), 800, "a future stamp reads as age 0");
        // matches the combined's formula over a sweep
        for k in 0u64..70 {
            let want = if k >= 64 { 0 } else { 123_456_789u64 >> k };
            assert_eq!(rollback_sticky_depth_e6(123_456_789, 10, 10 + k * 9_000), want);
        }
    }

    #[test]
    fn rollback_cap_depth_never_uncaps_a_market_the_combined_saw_a_depth_on() {
        let now = 1_000_000u64;
        // fresh effective depth: itself, whatever the source
        assert_eq!(rollback_cap_depth_e6(7, 0x86, 9, now, 5, 5, now), 7);
        // never had a depth (no EVER), nothing fresh: no cap (f6e7180d)
        assert_eq!(rollback_cap_depth_e6(0, 0x00, 0, 0, 0, 0, now), 0);
        assert_eq!(rollback_cap_depth_e6(0, 0x01, 100, now, 0, 0, now), 0, "first sample of a pair");
        // EVER, nothing fresh: the sticky cap, never 0 (= uncapped)
        assert_eq!(rollback_cap_depth_e6(0, 0x80, 0, now - 10_000, 800, now - 100, now), 800);
        assert_eq!(rollback_cap_depth_e6(0, 0x80, 0, 0, 800, now - 9_100, now), 400);
        assert_eq!(rollback_cap_depth_e6(0, 0x84, 0, 0, 800, 0, now), 1, "fully decayed: a cap of 0, not none");
        assert_eq!(rollback_cap_depth_e6(0, 0x80, 0, 0, 0, 0, now), 1, "EVER with last good 0");
        // a fresh REAL zero (the combined's "opens closed at once"), with or without EVER
        assert_eq!(rollback_cap_depth_e6(0, 0x01, 0, now - 3, 0, 0, now), 1);
        assert_eq!(rollback_cap_depth_e6(0, 0x82, 0, now, 800, now, now), 1);
        // the same zero but stale (> 150 slots) is just absent
        assert_eq!(rollback_cap_depth_e6(0, 0x01, 0, now - 151, 0, 0, now), 0);
        // depth cap with the mapped value: 1 atom caps at 0 notional at every tier-0 kappa
        assert_eq!(depth_cap_q(0, 1, 10_000_000, 1_000_000), 0);
    }

    #[test]
    fn rollback_tier_config_default_predicate() {
        let d_t = [0u32, 0, 0];
        let d_l = [0u16, 0, 0];
        assert!(rollback_tier_config_is_default(d_t, d_l, 0));
        assert!(rollback_tier_config_is_default(d_t, d_l, 7));
        assert!(rollback_tier_config_is_default([25_000, 100_000, 500_000], [500, 1_000, 2_000], 7));
        assert!(rollback_tier_config_is_default([25_000, 0, 500_000], [0, 1_000, 0], 0));
        assert!(!rollback_tier_config_is_default([50_000, 0, 0], d_l, 7), "custom T1");
        assert!(!rollback_tier_config_is_default(d_t, [300, 0, 0], 7), "custom L1");
        assert!(!rollback_tier_config_is_default([0, 0, 600_000], d_l, 7), "custom T3");
        assert!(!rollback_tier_config_is_default(d_t, d_l, 10), "9-decimal collateral");
        assert!(!rollback_tier_config_is_default(d_t, d_l, 1), "0-decimal collateral");
    }

    #[test]
    fn g8_effective_depth_and_tiers() {
        let t1 = DEPTH_TIER1_E6;
        // min of the two reads; absent if either is 0
        assert_eq!(effective_depth_e6(5 * t1, 2 * t1, 100, 100), 2 * t1);
        assert_eq!(effective_depth_e6(5 * t1, 0, 100, 100), 0, "first push: prev 0");
        assert_eq!(effective_depth_e6(0, 5 * t1, 100, 100), 0, "35 B push zeroes");
        // freshness: <= 150 slots fresh, 151 stale, a future stamp is stale (fail closed)
        assert_eq!(effective_depth_e6(t1, t1, 100, 250), t1);
        assert_eq!(effective_depth_e6(t1, t1, 100, 251), 0);
        assert_eq!(effective_depth_e6(t1, t1, 101, 100), 0);
        // tiers; attested capped at 1, any other source 0
        assert_eq!(depth_tier(t1 - 1, DEPTH_SOURCE_ATTESTED), 0);
        assert_eq!(depth_tier(t1, DEPTH_SOURCE_ATTESTED), 1);
        assert_eq!(depth_tier(DEPTH_TIER3_E6, DEPTH_SOURCE_ATTESTED), 1, "I-D3");
        assert_eq!(depth_tier(DEPTH_TIER3_E6, DEPTH_SOURCE_NONE), 0);
        assert_eq!(depth_tier(DEPTH_TIER3_E6, 2), 0, "unbuilt on-chain source: fail closed");
        assert_eq!((l_depth_x100(0, 300), l_depth_x100(1, 300), l_depth_x100(2, 300), l_depth_x100(3, 300)), (300, 500, 1_000, 2_000));
        assert_eq!((lambda_depth_bps(0), lambda_depth_bps(1), lambda_depth_bps(2), lambda_depth_bps(3)), (10_000, 10_000, 20_000, 30_000));
        assert_eq!((kappa_depth_bps(0), kappa_depth_bps(1), kappa_depth_bps(2), kappa_depth_bps(3)), (5_000, 10_000, 10_000, 20_000));
        assert_eq!(lambda_eff_bps(30_000, 1), 10_000);
        assert_eq!(lambda_eff_bps(5_000, 3), 5_000);
    }

    #[test]
    fn g8_wl2_same_slot_push_is_not_a_second_sample() {
        let t1 = DEPTH_TIER1_E6;
        // later slot: rotate
        assert_eq!(depth_push_update(t1, 0, 10, 2 * t1, 11), (2 * t1, t1, 11));
        // first ever push (slot 0 = never): rotate
        assert_eq!(depth_push_update(0, 0, 0, t1, 5), (t1, 0, 5));
        // same slot: prev kept, depth can only fall
        assert_eq!(depth_push_update(t1, 0, 10, 2 * t1, 10), (t1, 0, 10), "cannot raise");
        assert_eq!(depth_push_update(2 * t1, 7, 10, t1, 10), (t1, 7, 10), "can fall");
        assert_eq!(depth_push_update(2 * t1, 7, 10, 0, 10), (0, 7, 10), "35 B in the same slot zeroes");
        // two same-slot attested pushes from nothing: still one sample -> effective 0
        let (d, p, s) = depth_push_update(0, 0, 0, 5 * t1, 20);
        let (d, p, s) = depth_push_update(d, p, s, 5 * t1, 20);
        assert_eq!(effective_depth_e6(d, p, s, 20), 0, "W-L2: one slot is one sample");
        let (d, p, s) = depth_push_update(d, p, s, 5 * t1, 21);
        assert_eq!(effective_depth_e6(d, p, s, 21), 5 * t1, "two slots: effective");
        // MUTANT (pre-W-L2 rotate-always): the same-slot pair becomes effective at once
        let mutant = |d: u64, _p: u64, _s: u64, n: u64, now: u64| (n, d, now);
        let (d, p, s) = mutant(0, 0, 0, 5 * t1, 20);
        let (d, p, s) = mutant(d, p, s, 5 * t1, 20);
        assert_eq!(effective_depth_e6(d, p, s, 20), 5 * t1, "mutant: one-slot spike counts");
        // regression stamp: fall only
        assert_eq!(depth_push_update(t1, 3, 10, 2 * t1, 9), (t1, 3, 10));
    }

    #[test]
    fn g8_n_cap_depth_cap_only_when_fresh_and_identity_off_clamp() {
        let c_m = 1_000_000_000u128; // $1,000
        // off the clamp: n_cap_q with the STORED lambda, depth ignored entirely
        for (lam, d) in [(10_000u32, 0u64), (30_000, 1), (10_000, DEPTH_TIER1_E6)] {
            assert_eq!(n_cap_g8_q(false, c_m, lam, 1, d, 1_000_000, PS), n_cap_q(c_m, lam, 1_000_000, PS));
            assert_eq!(
                growth_matcher_caps_g8(false, false, c_m, lam, 1, d, 1_000_000, PS, u128::MAX),
                growth_matcher_caps(false, c_m, lam, 1_000_000, PS, u128::MAX)
            );
        }
        // on the clamp, no fresh depth: n_cap at λ_eff (a stored 3x reads 1x at tier 0/1)
        assert_eq!(n_cap_g8_q(true, c_m, 30_000, 0, 0, 1_000_000, PS), n_cap_q(c_m, 10_000, 1_000_000, PS));
        // fresh depth $100 at tier 0 (κ 0.5): cap = $50 of notional, below the capital's $1,000
        assert_eq!(n_cap_g8_q(true, c_m, 10_000, 0, 100_000_000, 1_000_000, PS), Some(50_000_000));
        assert_eq!(depth_cap_q(0, 0, 1_000_000, PS), u128::MAX, "absent: no cap");
        assert_eq!(depth_cap_q(1, 100_000_000, 0, PS), 0, "price 0: fail closed");
        // matcher: cap and liquidity follow the binding (depth) notional, x DEPTH_MULT
        assert_eq!(
            growth_matcher_caps_g8(false, true, c_m, 10_000, 0, 100_000_000, 1_000_000, PS, u128::MAX),
            (50_000_000, 200_000_000)
        );
        assert_eq!(
            growth_matcher_caps_g8(true, true, c_m, 10_000, 0, 100_000_000, 1_000_000, PS, u128::MAX),
            (0, 0),
            "h-lock closes"
        );
        // the gate uses the same number
        let mut g = base_in();
        g.depth_cap_q = 50 * PS; // 50 units, the taker opens 100
        assert_eq!(growth_gate(&g), GrowthVerdict::CapacityFull);
        g.depth_cap_q = 100 * PS; // u == 1 exactly: admitted only at 100% IMR (Q3)
        assert_eq!(growth_gate(&g), GrowthVerdict::LeverageExceeded);
        g.depth_cap_q = 200 * PS; // u = 50% <= kink: the ceiling only
        assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
    }

    #[test]
    fn g8_target_ceiling_ratchet_and_force_down() {
        let cl = 1_000u128;
        // off graduation / forced: launch
        assert_eq!(target_ceiling_x100(false, false, 300, 1_000, 500, 1 << 40, cl), 300);
        assert_eq!(target_ceiling_x100(true, true, 300, 1_000, 500, 1 << 40, cl), 300);
        // capital doubling twice -> launch + 2x, capped by L_depth (5x at tier 1)
        assert_eq!(target_ceiling_x100(true, false, 300, 1_000, 500, 4_000, cl), 500);
        assert_eq!(target_ceiling_x100(true, false, 300, 1_000, 500, 2_000, cl), 400);
        assert_eq!(target_ceiling_x100(true, false, 300, 1_000, 2_000, 1 << 40, cl), 1_000, "L_tier");
        assert_eq!(target_ceiling_x100(true, false, 800, 1_000, 500, 1 << 40, cl), 800, "never below launch");
        assert_eq!(target_ceiling_x100(true, false, 300, 1_000, 500, 1 << 40, 0), 300, "no C_launch");
        // ceiling in force: off clamp == launch whatever is stored
        assert_eq!(ceiling_in_force_x100(false, 900, 900, 300, 1_000), 300);
        assert_eq!(ceiling_in_force_x100(true, 900, 400, 300, 1_000), 400);
        assert_eq!(ceiling_in_force_x100(true, 400, 900, 300, 1_000), 400);
        // ratchet writer: c_launch snapshot, no climb in that call
        assert_eq!(
            graduation_ratchet(300, 0, 0, 5_000_000_000, true, false, 300, 1_000, 500, 50_000),
            (300, 0, 5_000_000_000)
        );
        assert_eq!(
            graduation_ratchet(300, 0, 0, 1, true, false, 300, 1_000, 500, 50_000),
            (300, 0, MIN_C_LAUNCH_ATOMS as u64),
            "floored snapshot"
        );
        // +1x per 9,000 slots, falls at once, unchanged keeps its stamp
        let c = 1_000_000_000u64;
        let cm = 8 * c as u128; // 3 doublings
        assert_eq!(graduation_ratchet(300, 0, c, cm, true, false, 300, 1_000, 500, 8_999), (300, 0, c));
        assert_eq!(graduation_ratchet(300, 0, c, cm, true, false, 300, 1_000, 500, 9_000), (400, 9_000, c));
        assert_eq!(graduation_ratchet(400, 9_000, c, cm, true, false, 300, 1_000, 500, 18_000), (500, 18_000, c));
        assert_eq!(graduation_ratchet(500, 18_000, c, cm, true, false, 300, 1_000, 500, 40_000), (500, 18_000, c), "at target: stamp kept");
        assert_eq!(graduation_ratchet(500, 18_000, c, cm, false, false, 300, 1_000, 300, 40_001), (300, 40_001, c), "depth gone: falls at once");
        assert_eq!(graduation_ratchet(500, 18_000, c, cm, true, true, 300, 1_000, 500, 40_001), (300, 40_001, c), "force-down");
        // fall-only (push): never rises
        assert_eq!(graduation_fall_only(300, 7, c, true, false, 300, 1_000, 500, 99), (300, 7));
        assert_eq!(graduation_fall_only(500, 7, c, false, false, 300, 1_000, 300, 99), (300, 99));
        assert_eq!(graduation_fall_only(500, 7, c, true, false, 300, 1_000, 400, 99), (400, 99));
    }

    #[test]
    fn m1_mid_and_counterparty() {
        // strict close of a short 100: the LP goes from -900 to -1000 (the close grows |LP|)
        assert_eq!(lp_mid_q(-900, -100, 0), Some(-1_000));
        assert_eq!(lp_mid_q(-900, -100, -40), Some(-960));
        // flip short 100 -> long 50: the reducing part takes the LP to -1000
        assert_eq!(lp_mid_q(-900, -100, 50), Some(-1_000));
        // open / grow: no reducing part
        assert_eq!(lp_mid_q(-900, 0, 50), Some(-900));
        assert_eq!(lp_mid_q(-900, 50, 80), Some(-900));
        assert!(taker_strictly_reduces(-100, 0) && taker_strictly_reduces(-100, -1));
        assert!(!taker_strictly_reduces(-100, 1) && !taker_strictly_reduces(0, 1));
        assert!(taker_flips(-100, 1) && !taker_flips(-100, 0) && !taker_flips(0, 5));
        // the gate measures crowd growth from mid: the flip's opening long grows a short LP
        let mut g = GrowthGateIn {
            taker_before_q: -100,
            taker_after_q: 50,
            taker_eff_after_abs_q: 50,
            taker_equity: u128::MAX / 4,
            taker_cert_initial_req: None,
            lp: Some(GrowthLpIn {
                before_q: -900,
                mid_q: -1_000,
                after_q: -1_050,
                eff_after_abs_q: 1_050,
                users_oi_side_after_q: 1_050,
                equity: 1_000,
            }),
            price_e6: 1_000_000,
            pos_scale: 1_000_000,
            engine_imr_bps: 1_000,
            min_nonzero_im_req: 0,
            ceil_imr_bps: 1_000,
            lambda_bps: 10_000,
            kink_bps: 5_000,
            crowd_blocked: false,
            asset_bound: true,
            depth_cap_q: u128::MAX,
        };
        assert_eq!(
            growth_gate(&g),
            GrowthVerdict::CapacityFull,
            "opening part past N_cap gated"
        );
        // no LP counterparty: a risk-increasing side is refused, a close is not
        g.lp = None;
        assert_eq!(growth_gate(&g), GrowthVerdict::NoLpCounterparty);
        g.taker_after_q = 0;
        assert_eq!(growth_gate(&g), GrowthVerdict::Allow);
        assert_eq!(g4_default_if_zero(0, 100), 100);
        assert_eq!(g4_default_if_zero(7, 100), 7);
    }

    #[test]
    fn sides_and_dials() {
        // CPI: a always checked (even if it is itself an LP), b is the LP
        assert_eq!(growth_sides(true, false, true), (true, false, Some(true)));
        assert_eq!(growth_sides(true, true, true), (true, false, Some(true)));
        // NoCpi
        assert_eq!(growth_sides(false, false, true), (true, false, Some(true)));
        assert_eq!(growth_sides(false, true, false), (false, true, Some(false)));
        assert_eq!(growth_sides(false, false, false), (true, true, None));
        assert_eq!(growth_sides(false, true, true), (true, true, None));
        // dials: tighten-only without the epoch clamp
        assert!(growth_dials_ok(false, 10_000, 5_000));
        assert!(growth_dials_ok(false, 1, 0));
        assert!(!growth_dials_ok(false, 10_001, 5_000), "lambda above 1x");
        assert!(
            !growth_dials_ok(false, 10_000, 5_001),
            "kink later than 50%"
        );
        assert!(!growth_dials_ok(false, 0, 0), "lambda 0");
        assert!(growth_dials_ok(true, MAX_LAMBDA_BPS, 10_000));
        assert!(!growth_dials_ok(true, MAX_LAMBDA_BPS + 1, 0));
    }

    #[test]
    fn init_rule() {
        assert!(init_margin_rule_ok(500, 400, 100, 4));
        assert!(!init_margin_rule_ok(500, 401, 100, 4));
        assert!(
            !init_margin_rule_ok(500, 0, 100, 0),
            "r_gap must be measured (> 0)"
        );
        assert!(!init_margin_rule_ok(u64::MAX, 1, u64::MAX, 0));
        // L-2 floor: 4 bps/slot x 50 slots = 200 bps
        assert!(init_margin_rule_ok(500, 200, 100, 4));
        assert!(
            !init_margin_rule_ok(500, 199, 100, 4),
            "below price-limit x latency"
        );
        assert!(
            !init_margin_rule_ok(10_000, 1, 100, 4),
            "r_gap = 1 bps refused"
        );
        assert!(
            !init_margin_rule_ok(10_000, 400, 0, u64::MAX),
            "floor overflow fails closed"
        );
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
    #[test]
    fn n1_pure_pieces() {
        // users OI: the vault LP's own leg is removed only from ITS side
        assert_eq!(users_side_oi_q(1_000, -400, true), 1_000);
        assert_eq!(users_side_oi_q(1_000, 400, true), 600);
        assert_eq!(users_side_oi_q(1_000, -400, false), 600);
        assert_eq!(users_side_oi_q(300, 400, true), 0, "saturates");
        assert_eq!(growth_open_room_q(1_000, 600), 400);
        assert_eq!(growth_open_room_q(1_000, 1_200), 0);
        // reduce class from the EFFECTIVE position (Q2)
        assert_eq!(
            growth_leg_reduce_class(-100, 40, true),
            Some((true, Some(40)))
        );
        assert_eq!(
            growth_leg_reduce_class(-100, 100, false),
            Some((true, Some(100)))
        );
        assert_eq!(
            growth_leg_reduce_class(-100, 150, true),
            Some((true, Some(100))),
            "single-route flip -> its close"
        );
        assert_eq!(
            growth_leg_reduce_class(-100, 150, false),
            Some((false, None)),
            "batch flip is an open"
        );
        assert_eq!(
            growth_leg_reduce_class(-80, 100, false),
            Some((false, None)),
            "|raw| 100 over-closes |eff| 80: NOT marked reducing"
        );
        assert_eq!(growth_leg_reduce_class(0, 5, true), Some((false, None)));
        assert_eq!(growth_leg_reduce_class(10, 5, true), Some((false, None)));
        assert_eq!(growth_leg_reduce_class(i128::MAX, 1, true), None);
        // ext v3 caps (R8): closed under the h-lock, on C_m 0 and on price 0
        assert_eq!(
            growth_matcher_caps(true, 1_000_000_000, 10_000, 1_000_000, PS, u128::MAX),
            (0, 0)
        );
        assert_eq!(
            growth_matcher_caps(false, 0, 10_000, 1_000_000, PS, u128::MAX),
            (0, 0)
        );
        assert_eq!(
            growth_matcher_caps(false, 1_000_000_000, 10_000, 0, PS, u128::MAX),
            (0, 0)
        );
        assert_eq!(
            growth_matcher_caps(false, 1_000_000_000, 10_000, 1_000_000, PS, u128::MAX),
            (1_000_000_000, 4_000_000_000)
        );
        assert_eq!(
            growth_matcher_caps(false, 1_000_000_000, 10_000, 1_000_000, PS, 7).0,
            7
        );
    }

    #[test]
    fn n1_thin_open_counts_against_its_side_and_unbound_refuses_opens() {
        // thin open (the LP shrinks) whose own side would pass N_cap: refused
        let mut t = base_in();
        t.lp = Some(GrowthLpIn {
            before_q: -(900 * PS as i128),
            mid_q: -(900 * PS as i128),
            after_q: -(800 * PS as i128),
            eff_after_abs_q: 800 * PS,
            users_oi_side_after_q: 1_000 * PS + 1,
            equity: 1_000_000_000,
        });
        t.taker_after_q = -(100 * PS as i128);
        assert_eq!(growth_gate(&t), GrowthVerdict::CapacityFull);
        if let Some(l) = t.lp.as_mut() {
            l.users_oi_side_after_q = 1_000 * PS;
        }
        assert_eq!(
            growth_gate(&t),
            GrowthVerdict::Allow,
            "landing on N_cap is admitted"
        );
        // crowd u is measured on users OI, not on the LP's net: LP -500 but crowd OI 1,001
        let mut c = base_in();
        c.lp = Some(GrowthLpIn {
            before_q: -(400 * PS as i128),
            mid_q: -(400 * PS as i128),
            after_q: -(500 * PS as i128),
            eff_after_abs_q: 500 * PS,
            users_oi_side_after_q: 1_000 * PS + 1,
            equity: 1_000_000_000,
        });
        c.taker_equity = u128::MAX;
        assert_eq!(growth_gate(&c), GrowthVerdict::CapacityFull);
        // unbound growth asset: opens refused, closes never
        let mut u = base_in();
        u.asset_bound = false;
        assert_eq!(growth_gate(&u), GrowthVerdict::NotBound);
        u.taker_before_q = 100 * PS as i128;
        u.taker_after_q = 0;
        assert_eq!(growth_gate(&u), GrowthVerdict::Allow);
    }

    /// The N-1 capacity model: `users` hold effective positions against ONE vault LP
    /// (`LP = -sum(users)`), every fill is a user vs the LP, and admission is the PRODUCTION
    /// `growth_gate` fed exactly as `growth_post_fill_view` feeds it (`users_oi` = the users OI
    /// on the taker's side after; `measure_lp_net` = the pre-N-1 measure, the mutant).
    fn n1_admits(users: &[i128], i: usize, d: i128, n_cap: u128, measure_lp_net: bool) -> bool {
        let lp: i128 = -users.iter().sum::<i128>();
        let before = users[i];
        let after = before + d;
        let mut next = users.to_vec();
        next[i] = after;
        let lp_after = lp - d;
        let side_oi = |v: &[i128], long: bool| -> u128 {
            v.iter()
                .map(|p| {
                    if (long && *p > 0) || (!long && *p < 0) {
                        p.unsigned_abs()
                    } else {
                        0
                    }
                })
                .sum()
        };
        let users_oi = if measure_lp_net {
            lp_after.unsigned_abs()
        } else {
            side_oi(&next, after > 0)
        };
        let g = GrowthGateIn {
            taker_before_q: before,
            taker_after_q: after,
            taker_eff_after_abs_q: after.unsigned_abs(),
            taker_equity: u128::MAX / 4,
            taker_cert_initial_req: None,
            lp: Some(GrowthLpIn {
                before_q: lp,
                mid_q: lp_mid_q(lp, before, after).unwrap(),
                after_q: lp_after,
                eff_after_abs_q: lp_after.unsigned_abs(),
                users_oi_side_after_q: users_oi,
                // lambda 1x, $1 (1e6), POS_SCALE 1: N_cap = C_m / 1e6
                equity: n_cap * 1_000_000,
            }),
            price_e6: 1_000_000,
            pos_scale: 1,
            engine_imr_bps: 1_000,
            min_nonzero_im_req: 0,
            ceil_imr_bps: 1_000,
            lambda_bps: 10_000,
            kink_bps: 5_000,
            crowd_blocked: false,
            asset_bound: true,
            depth_cap_q: u128::MAX,
        };
        growth_gate(&g) == GrowthVerdict::Allow
    }

    fn n1_inv(users: &[i128], n_cap: u128) -> bool {
        let long: u128 = users
            .iter()
            .filter(|p| **p > 0)
            .map(|p| p.unsigned_abs())
            .sum();
        let short: u128 = users
            .iter()
            .filter(|p| **p < 0)
            .map(|p| p.unsigned_abs())
            .sum();
        let lp = users.iter().sum::<i128>().unsigned_abs();
        long <= n_cap && short <= n_cap && lp <= core::cmp::max(long, short)
    }

    /// N-1 inductive step, exhaustive on a small domain (the Kani harness of note rev 4 is this
    /// statement for symbolic values): from EVERY state satisfying
    /// `OI_long_users <= N_cap ∧ OI_short_users <= N_cap ∧ |LP| <= max(both)`, every fill the
    /// gate admits -- open, grow, reduce, close, flip -- lands in a state satisfying it again.
    /// Hence `|LP| <= N_cap` after ANY admitted sequence.
    #[test]
    fn n1_capacity_invariant_is_inductive() {
        const N: u128 = 4;
        const R: i128 = 6;
        let mut states = 0u64;
        let mut fills = 0u64;
        let mut closes_admitted = 0u64;
        for a in -R..=R {
            for b in -R..=R {
                for c in -R..=R {
                    let users = [a, b, c];
                    if !n1_inv(&users, N) {
                        continue;
                    }
                    states += 1;
                    for i in 0..3 {
                        for d in -2 * R..=2 * R {
                            if d == 0 || !n1_admits(&users, i, d, N, false) {
                                continue;
                            }
                            fills += 1;
                            let mut next = users;
                            next[i] += d;
                            if taker_strictly_reduces(users[i], next[i]) {
                                closes_admitted += 1;
                            }
                            assert!(n1_inv(&next, N), "{users:?} user {i} {d:+} -> {next:?}");
                        }
                    }
                }
            }
        }
        // covers: non-vacuous (opens ARE admitted up to N_cap and refused past it), and every
        // strict reduction is admitted (M-1 liveness kept)
        assert!(
            states > 100 && fills > 1_000,
            "states {states} fills {fills}"
        );
        assert!(
            n1_admits(&[0, 0, 0], 0, N as i128, N, false),
            "open to exactly N_cap"
        );
        assert!(
            !n1_admits(&[0, 0, 0], 0, N as i128 + 1, N, false),
            "N_cap + 1 refused"
        );
        assert!(
            n1_admits(&[3, 0, 0], 1, -4, N, false),
            "thin side opens to N_cap"
        );
        assert!(
            n1_admits(&[3, -4, 0], 2, 1, N, false),
            "crowd lands on N_cap"
        );
        assert!(
            !n1_admits(&[4, -4, 0], 2, 1, N, false),
            "crowd past N_cap refused"
        );
        let mut reductions = 0u64;
        for a in -R..=R {
            for b in -R..=R {
                let users = [a, b, -(a + b).clamp(-R, R)];
                if !n1_inv(&users, N) {
                    continue;
                }
                for i in 0..3 {
                    let p = users[i];
                    for d in 1..=p.unsigned_abs() as i128 {
                        let d = if p > 0 { -d } else { d };
                        assert!(n1_admits(&users, i, d, N, false), "close {users:?} {i} {d}");
                        reductions += 1;
                    }
                }
            }
        }
        assert!(reductions > 0 && closes_admitted > 0);
    }

    /// NEGATIVE CONTROL (mutant `n1-lpnet`): the pre-N-1 measure (u on |LP| net) is NOT
    /// inductive, and the reviewer's thin-open / crowd-refill / thin-close cycle reaches
    /// `|LP| > N_cap` from flat.
    #[test]
    fn n1_mutant_lp_net_measure_breaks_the_invariant() {
        const N: u128 = 4;
        // replay the reviewer's cycle: users [T, C1, C2]
        let mut u = [0i128, 0, 0];
        let step = |u: &mut [i128; 3], i: usize, d: i128, mutant: bool| -> bool {
            let ok = n1_admits(&u[..], i, d, N, mutant);
            if ok {
                u[i] += d;
            }
            ok
        };
        assert!(step(&mut u, 1, 4, true), "crowd C1 to N_cap");
        assert!(step(&mut u, 0, -4, true), "thin T opens: LP back to 0");
        assert!(
            step(&mut u, 2, 4, true),
            "crowd C2 refills (LP net 0 frees room)"
        );
        assert!(step(&mut u, 0, 4, true), "thin close is exempt");
        let lp = u.iter().sum::<i128>().unsigned_abs();
        assert_eq!(lp, 8, "mutant: |LP| = 2 x N_cap");
        // the real rule refuses the refill: C2's open would put users long OI at 8 > N_cap
        let mut r = [0i128, 0, 0];
        assert!(step(&mut r, 1, 4, false));
        assert!(
            step(&mut r, 0, -4, false),
            "thin T: short side OI 4 <= N_cap"
        );
        assert!(!step(&mut r, 2, 4, false), "N-1: refill refused");
        assert!(step(&mut r, 0, 4, false), "thin close still exempt");
        assert!(r.iter().sum::<i128>().unsigned_abs() <= N);
    }

    #[test]
    fn n2_utilisation_fee_shape() {
        let n = 1_000u128;
        // 0 at and below the kink, linear to max at u = 1, capped above
        assert_eq!(utilisation_fee_bps(500, n, 5_000, 500), Some(0));
        assert_eq!(utilisation_fee_bps(501, n, 5_000, 500), Some(1)); // ceil
        assert_eq!(utilisation_fee_bps(600, n, 5_000, 500), Some(100));
        assert_eq!(utilisation_fee_bps(1_000, n, 5_000, 500), Some(500));
        assert_eq!(utilisation_fee_bps(5_000, n, 5_000, 500), Some(500));
        assert_eq!(utilisation_fee_bps(1, 0, 5_000, 500), None);
        assert_eq!(utilisation_fee_bps(900, n, 5_000, 0), Some(0));
        // monotone in u and in max
        let mut prev = 0;
        for oi in 0..=1_200u128 {
            let f = utilisation_fee_bps(oi, n, 5_000, 500).unwrap();
            assert!(f >= prev && f <= 500);
            prev = f;
        }
        // only the OPENING part pays: closes / reduces 0, flips |after|, grows the delta
        assert_eq!(opening_part_q(-100, 0), 0);
        assert_eq!(opening_part_q(-100, -40), 0);
        assert_eq!(opening_part_q(-100, 50), 50);
        assert_eq!(opening_part_q(0, 70), 70);
        assert_eq!(opening_part_q(20, 70), 50);
        assert_eq!(util_fee_on_fill_bps(500, 50, 150), 166); // flip: 1/3 of the fill opens
        assert_eq!(util_fee_on_fill_bps(500, 0, 150), 0);
        assert_eq!(util_fee_on_fill_bps(500, 150, 150), 500);
        // the closing part of a flip is never charged: rate * fill <= fee * opening
        for (o, f) in [(1u128, 3u128), (7, 9), (50, 150), (99, 100)] {
            let r = util_fee_on_fill_bps(333, o, f) as u128;
            assert!(r * f <= 333 * o);
        }
        // defaults, dial bounds (tighten-only) and the trading-cap rule
        assert_eq!(util_fee_max_effective_bps(0), GROWTH_UTIL_FEE_DEFAULT_BPS);
        assert_eq!(util_fee_max_effective_bps(900), 900);
        assert!(util_fee_dial_ok(false, GROWTH_UTIL_FEE_DEFAULT_BPS));
        assert!(
            !util_fee_dial_ok(false, GROWTH_UTIL_FEE_DEFAULT_BPS - 1),
            "cheaper lock-out refused"
        );
        assert!(!util_fee_dial_ok(false, GROWTH_UTIL_FEE_HARD_MAX_BPS + 1));
        assert!(util_fee_dial_ok(true, 0));
        assert!(util_fee_fits_trading_cap(630, 30, 500));
        assert!(!util_fee_fits_trading_cap(629, 30, 500));
        assert!(!util_fee_fits_trading_cap(u64::MAX, u64::MAX, 500));
    }
}
