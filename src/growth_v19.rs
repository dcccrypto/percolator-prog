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

// ── v2.2 round 3 item 3 (design D1(a) GAP-2a + GAP-4): graded stress target ─────────────────────

/// Stress level 0: none.
pub const STRESS_NONE: u8 = 0;
/// Stress level 1: a senior draw / G9 backstop outstanding (a routine event once the F3 backing
/// top-up draw exists): the target is capped ONE tier (knot) below the current tier.
pub const STRESS_DRAW: u8 = 1;
/// Stress level 2: REAL ADL -- an engine side mode is not Normal (DrainOnly / ResetPending).
/// TWO tiers below. (`A != 1` alone, e.g. the LP side scaled by a matched band liquidation with
/// both modes Normal, is NOT ADL: design D1(a).)
pub const STRESS_ADL: u8 = 2;
/// Stress level 3: the bankruptcy h-lock is latched: the target is launch. (Every stress level
/// binds at once: the ceiling in force is `min(stored, target)`, security review F-1 fix A.)
pub const STRESS_HLOCK: u8 = 3;

/// D1(a): real ADL is an engine side mode other than Normal (`SideModeV16::Normal` == 0) on
/// either side; the A factor alone is not read.
pub fn real_adl(mode_long: u8, mode_short: u8) -> bool {
    mode_long != 0 || mode_short != 0
}

/// The graded stress level from the three flags (the highest one wins).
pub fn stress_level(draw_outstanding: bool, real_adl: bool, hlock: bool) -> u8 {
    if hlock {
        STRESS_HLOCK
    } else if real_adl {
        STRESS_ADL
    } else if draw_outstanding {
        STRESS_DRAW
    } else {
        STRESS_NONE
    }
}

/// The stress cap on the ceiling target (x100): none (`u16::MAX`) at level 0; `L_table(tier - s)`
/// for `s` = 1 (draw) and 2 (real ADL) -- `s` knots below the current tier, floored at tier 0
/// (launch); launch (`table[0]`) under the h-lock. Monotone non-increasing in `stress`,
/// non-decreasing in `tier`, and never above `L_table(tier)` once `stress >= 1`.
/// Continuous leverage (2026-10-19, security review M-2, Khubair): STAYS STEPPED. Under stress
/// the target is `min(leverage curve, this)` at the discrete combined tier (venue tier on the
/// push path), exactly base caf062bd's stress cap: never above the unstressed curve (the curve is
/// `>= L_table(tier)`), applied at once.
pub fn stress_cap_x100(stress: u8, tier: u8, table: [u16; 4]) -> u16 {
    if stress == STRESS_NONE {
        return u16::MAX;
    }
    if stress >= STRESS_HLOCK {
        return table[0];
    }
    let t = if tier > MAX_TIER { MAX_TIER } else { tier };
    table[t.saturating_sub(stress) as usize]
}

/// Ratchet the stored ceiling toward `target_x100`: UP GRADUALLY, DOWN AT ONCE (Khubair's
/// 12:52 rule; security review F-1 fix A). A fall goes to the target in the same call, stamped
/// `now`; under the bankruptcy h-lock (`stress >= STRESS_HLOCK`) the target is `floor_x100`
/// (launch). Rises by at most one `RATCHET_STEP_X100` per `RATCHET_EPOCH_SLOTS`. Round 3 item 3's
/// graded stress only chooses the TARGET (`stress_cap_x100`); there is no per-call descent limit.
/// Returns `(ceil_x100, ceil_slot)`.
pub fn ratchet_ceiling_x100(
    prev_ceil_x100: u16,
    prev_slot: u64,
    target_x100: u16,
    floor_x100: u16,
    stress: u8,
    now_slot: u64,
) -> (u16, u64) {
    let hlock = stress >= STRESS_HLOCK;
    let target = if hlock && floor_x100 < target_x100 {
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
    /// none (off a clamp-enforced market, or a market that never had a fresh depth: growth-1
    /// capacity exactly; R2.1: once `DEPTH_EVER` the sticky depth always caps). The
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
/// v2.2 round 3 (adaptive-controller design GAP-8 / LP-plan audit §4 item 8): the backing top-up
/// draw (F3) is what lets Earn take a loss in the designed order (junior, bonds, seniors) BEFORE
/// winners are stuck. Until it is PROVEN (Kani on the draw rule + the +90% / +100% / cascade sims
/// show every layer moving money), Earn allocation stays at the growth-1 50% on EVERY market,
/// band or not: a protocol cap neither the creator nor the upgrade authority can exceed. Flipping
/// this to `true` (a code change, reviewed) restores the band maximum `ALLOC_ALPHA_MAX_BAND_BPS`.
pub const F3_PROVEN: bool = false;
/// The protocol alpha cap while `F3_PROVEN` is false (the growth-1 / off-band 50%).
pub const ALLOC_ALPHA_MAX_UNPROVEN_BPS: u16 = 5_000;
const _: () = assert!(ALLOC_ALPHA_MAX_UNPROVEN_BPS == crate::vault_lp_v18::ALLOC_ALPHA_MAX_BPS);
const _: () = assert!(ALLOC_ALPHA_MAX_UNPROVEN_BPS <= ALLOC_ALPHA_MAX_BAND_BPS);

/// The alpha dial ceiling (pure core, both values of the switch; Kani / proptest target):
/// band (clamp-enforced) markets may go to `ALLOC_ALPHA_MAX_BAND_BPS` only once `f3_proven`;
/// every other case is the 50% cap.
pub fn alloc_alpha_max_bps_for(f3_proven: bool, band_on: bool) -> u16 {
    if band_on && f3_proven {
        ALLOC_ALPHA_MAX_BAND_BPS
    } else if band_on {
        ALLOC_ALPHA_MAX_UNPROVEN_BPS
    } else {
        crate::vault_lp_v18::ALLOC_ALPHA_MAX_BPS
    }
}

/// v2.2 growth overnight §1.1: `band_on` is the per-market CLAMP predicate (`clamp_enforced`),
/// not the band alone (callers: tag 99's dial trailer). Round 3: capped at 50% everywhere until
/// `F3_PROVEN`.
pub fn alloc_alpha_max_bps(band_on: bool) -> u16 {
    alloc_alpha_max_bps_for(F3_PROVEN, band_on)
}

/// Round 3: the alpha tag 103 actually allocates with: the stored dial, capped by the protocol
/// cap in force (`min(stored, 50%)` until `F3_PROVEN`). A record written before round 3 with a
/// band alpha above 50% stays VALID (the validator's ceiling is the band maximum, so no read
/// fails) but cannot allocate past 50%. After the flip the stored dial is used as written (the
/// setter already bounded it per market).
pub fn alloc_alpha_in_force_bps_for(f3_proven: bool, stored_alpha_bps: u16) -> u16 {
    if f3_proven || stored_alpha_bps <= ALLOC_ALPHA_MAX_UNPROVEN_BPS {
        stored_alpha_bps
    } else {
        ALLOC_ALPHA_MAX_UNPROVEN_BPS
    }
}

/// `alloc_alpha_in_force_bps_for` at the program's `F3_PROVEN`.
pub fn alloc_alpha_in_force_bps(stored_alpha_bps: u16) -> u16 {
    alloc_alpha_in_force_bps_for(F3_PROVEN, stored_alpha_bps)
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
/// 24..26, 44, 56..96). The R2.1 tier table (96..114) and `attested_max_tier` (45) are
/// CONFIGURATION and survive a restart, like lambda / kink / l_tier / l_launch / r_gap. Everything else in the record (version, lambda, kink, l_tier, l_launch,
/// r_gap, the dials, the rent snapshot) is the market's CONFIGURATION and survives a restart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraduationFields {
    /// Round 3 item 6: the volatility EWMA (bytes 0..4; was `c_launch_atoms` 0..8 -- retired).
    pub vol_var_x100: u32,
    /// Round 3 item 7: the rent-snapshot stamp (bytes 4..8, `slot / 64`).
    pub rent_stamp64: u32,
    pub ceil_x100: u16,
    pub ceil_slot: u64,
    pub depth_e6: u64,
    pub depth_slot: u64,
    pub depth_prev_e6: u64,
    /// Byte 44: bits 0-1 the last push's source, bit 7 `DEPTH_EVER`.
    pub depth_source: u8,
    /// R2.1 (W-M1): the last fresh effective depth and its slot (the sticky cap's input).
    pub depth_last_good_e6: u64,
    pub depth_last_good_slot: u64,
    /// R2-M1 / D-L2: the last-rise stamp (`slot / 64`) of the rate-limited depth.
    pub depth_rise_slot64: u32,
    /// Round 3 item 4: the time-weighted depth window (bytes 30..38, 118..120).
    pub depth_tw: DepthWindow,
}

/// Security review I-1 (security-review-v21-combination §8): a restarted asset, a reused slot,
/// an append activation and a retired re-activation are NEW markets on an old slot. Their
/// graduation state starts from scratch: no launch capital (`c_launch = 0`, re-snapshotted at
/// the first graduation evaluation), the ceiling at `min(L_launch, L_tier)` stamped `now` (so
/// the first climb waits a full ratchet epoch), and no depth (tier 0: I-D1) -- including the
/// R2.1 sticky state (`DEPTH_EVER` and the last good depth: a new market on an old slot does not
/// inherit the old market's depth history, in either direction). Kani:
/// `kani_g8_i1_reset_postconditions`.
pub fn graduation_reset(l_launch_x100: u16, l_tier_x100: u16, now_slot: u64) -> GraduationFields {
    GraduationFields {
        vol_var_x100: 0,
        rent_stamp64: 0,
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
        depth_last_good_e6: 0,
        depth_last_good_slot: 0,
        depth_rise_slot64: 0,
        depth_tw: DepthWindow { cur_tokens: 0, prev_tokens: 0, bucket_p1: 0 },
    }
}

// ── v2.2 growth overnight §1.3 + round 2 (R2.1): depth input, venue / book tiers, sticky cap ──

/// A stored depth older than this many slots reads as absent (~60 s at 400 ms slots; the keeper
/// pushes every few seconds), the same bound as the ADL wind-down's mark age.
pub const DEPTH_MAX_AGE_SLOTS: u64 = 150;
/// `AssetGrowthV19::depth_source` bits 0-1: no depth (a 35 B push, or never pushed).
pub const DEPTH_SOURCE_NONE: u8 = 0;
/// bits 0-1: keeper-attested (PushAuthMark 44 B, mode 1). Trusted, and capped at the market's
/// `attested_max_tier` (default 1, I-D3).
pub const DEPTH_SOURCE_ATTESTED: u8 = 1;
/// bits 0-1 (R2.1 §4): an on-chain DEX pool read by the wrapper itself (PushAuthMark mode 2,
/// the `DepthSourceV22` reader). No venue-tier cap: the reading is the pool's own reserves.
pub const DEPTH_SOURCE_DEX: u8 = 2;
/// The source bits of byte 44.
pub const DEPTH_SOURCE_MASK: u8 = 0x03;
/// Byte 44 bit 7 (R2.1 §1, W-M1): a FRESH effective depth was seen at least once on this market.
/// Sticky: never cleared except by the I-1 reset (asset restart / slot reuse / re-activation).
/// Once set, an absent or stale reading no longer removes the κ cap (`cap_depth_e6`).
pub const DEPTH_EVER: u8 = 0x80;
/// Byte 44 bit 6 (v2.2 DEATH F-3 / SEC-RC L-2): the market asset's depth is PINNED to an
/// on-chain DEX pool (tag 123 `SetDepthSource` op 1 sets it, op 0 clears it; every PushAuthMark
/// mode-2 reading also sets it, which covers a pin made before this bit existed). While it is set
/// a keeper-attested (mode 1) depth is IGNORED, fail closed for depth: an attested reading can
/// never override or replace the pinned pool's reading. SEC-RC2 L-RC2-1: the push itself is not
/// refused; the depth state is left untouched and the push's mark lands (fail open for the
/// mark). The 35 B form, mode 0 and mode 2 are unchanged. Sticky across the I-1 reset; only
/// tag 123 op 0 clears it. Not a source: `depth_source_of` masks it out.
pub const DEPTH_DEX_PINNED: u8 = 0x40;

/// Whether the asset's depth is pinned to the on-chain DEX source (`DEPTH_DEX_PINNED`).
pub fn depth_dex_pinned(depth_source_byte: u8) -> bool {
    depth_source_byte & DEPTH_DEX_PINNED != 0
}

/// F-3: may the DEPTH of a PushAuthMark carrying depth `mode` (`None` = the 35 B form) be applied
/// to an asset whose depth byte is `depth_source_byte`? Everything is applied except a
/// keeper-attested depth on a DEX-pinned asset, which is ignored (L-RC2-1: the mark still lands).
pub fn depth_push_mode_allowed(depth_source_byte: u8, mode: Option<u8>) -> bool {
    !(depth_dex_pinned(depth_source_byte) && mode == Some(DEPTH_MODE_ATTESTED))
}

/// Byte 44 bit 2 (coordinator ruling 2026-10-14, "most conservative wins"): the PREVIOUS sample
/// (`depth_prev_e6`) was a REAL reading (source 1 or 2, a 0 included), not an absent one (35 B
/// push, mode 0, never). With the source bits (which say the same of the CURRENT sample) it lets
/// a real reading of 0 be told apart from "absent" in both slots of the min-of-two.
pub const DEPTH_PREV_REAL: u8 = 0x04;
/// PushAuthMark 44 B `depth_mode`: 0 = none (the depth must be 0), 1 = keeper-attested, 2 =
/// on-chain DEX (the depth on the wire must be 0; the program computes it from the pool pinned
/// by tag 123). Any other value is refused with `DepthInputInvalid` (128); see
/// `depth_src_v22::decode_depth_mode`.
pub const DEPTH_MODE_NONE: u8 = 0;
pub const DEPTH_MODE_ATTESTED: u8 = 1;
pub const DEPTH_MODE_DEX: u8 = crate::depth_src_v22::DEPTH_MODE_DEX;
/// One whole USD of 6-decimal collateral.
pub const USD_ATOMS: u64 = 1_000_000;
const _: () = assert!(USD_ATOMS == 1_000_000); // whole_token_atoms(6)
/// R2.1 §2 per-market tier thresholds (whole USD of ±2% depth): the defaults a stored 0 means,
/// and the floors an explicit value may not go below (a creator cannot set $1 tiers).
pub const TIER_THRESHOLD_DEFAULT_USD: [u32; 3] = [25_000, 100_000, 500_000];
pub const TIER_THRESHOLD_FLOOR_USD: [u32; 3] = [5_000, 20_000, 100_000];
/// R2.1 §2 per-tier maximum leverage (x100) a stored 0 means (before `min(.., L_tier)`).
pub const TIER_LEVERAGE_DEFAULT_X100: [u16; 3] = [500, 1_000, 2_000];
/// `attested_max_tier` stored 0 = this protocol default (I-D3).
pub const ATTESTED_MAX_TIER_DEFAULT: u8 = 1;
/// Highest liquidity tier.
pub const MAX_TIER: u8 = 3;
/// The sticky cap halves once per this many slots of staleness (one ratchet epoch, ~1 h).
pub const DEPTH_STICKY_EPOCH_SLOTS: u64 = RATCHET_EPOCH_SLOTS;
/// Round-1 names of the default thresholds in collateral atoms ($25k / $100k / $500k).
/// R2-M1: the rate limiter's bootstrap floor is `seed / DEPTH_BOOTSTRAP_DIV` (T1 / 16): the
/// level a market climbs back to, one epoch after a real 0.
pub const DEPTH_BOOTSTRAP_DIV: u64 = 16;
pub const DEPTH_TIER1_E6: u64 = 25_000_000_000;
pub const DEPTH_TIER2_E6: u64 = 100_000_000_000;
pub const DEPTH_TIER3_E6: u64 = 500_000_000_000;
const _: () = assert!(DEPTH_TIER1_E6 == TIER_THRESHOLD_DEFAULT_USD[0] as u64 * USD_ATOMS);
const _: () = assert!(DEPTH_TIER2_E6 == TIER_THRESHOLD_DEFAULT_USD[1] as u64 * USD_ATOMS);
const _: () = assert!(DEPTH_TIER3_E6 == TIER_THRESHOLD_DEFAULT_USD[2] as u64 * USD_ATOMS);
// The defaults satisfy the bounds the validator applies to explicit values.
const _: () = assert!(
    TIER_THRESHOLD_DEFAULT_USD[0] >= TIER_THRESHOLD_FLOOR_USD[0]
        && TIER_THRESHOLD_DEFAULT_USD[1] >= TIER_THRESHOLD_FLOOR_USD[1]
        && TIER_THRESHOLD_DEFAULT_USD[2] >= TIER_THRESHOLD_FLOOR_USD[2]
        && TIER_THRESHOLD_DEFAULT_USD[0] < TIER_THRESHOLD_DEFAULT_USD[1]
        && TIER_THRESHOLD_DEFAULT_USD[1] < TIER_THRESHOLD_DEFAULT_USD[2]
        && TIER_THRESHOLD_FLOOR_USD[0] > 0
);

/// The source bits (0 none, 1 attested, 2 DEX) of `depth_source`.
pub fn depth_source_of(depth_source_byte: u8) -> u8 {
    depth_source_byte & DEPTH_SOURCE_MASK
}

/// Whether `DEPTH_EVER` is set.
pub fn depth_ever(depth_source_byte: u8) -> bool {
    depth_source_byte & DEPTH_EVER != 0
}

/// Validator: only bits 0-1 (a known source, 0..=2), bit 2 (`DEPTH_PREV_REAL`) and bit 7
/// (`DEPTH_EVER`) may be set.
pub fn depth_source_byte_ok(depth_source_byte: u8) -> bool {
    depth_source_byte & !(DEPTH_SOURCE_MASK | DEPTH_PREV_REAL | DEPTH_DEX_PINNED | DEPTH_EVER) == 0
        && depth_source_of(depth_source_byte) <= DEPTH_SOURCE_DEX
}

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

/// The FRESH reading the tiers and the κ cap use (coordinator ruling: most conservative wins).
/// `None` = absent: stale (> `DEPTH_MAX_AGE_SLOTS`), a future stamp, the current sample absent
/// (35 B push / mode 0 / never: source bits NONE), or the first REAL sample of a pair (the
/// previous one absent). Otherwise `Some(min(current, previous))` where a REAL 0 counts as 0:
/// * a real reading of 0 (attested or DEX mode with depth 0) is `Some(0)` AT ONCE (the min of
///   0 and anything is 0; it does not wait for a second sample);
/// * a later positive reading restores a positive value only after its own min-of-two (its
///   previous sample is the real 0, so the min stays 0 until a second positive sample).
pub fn fresh_depth_e6(
    depth_e6: u64,
    depth_prev_e6: u64,
    depth_slot: u64,
    depth_source_byte: u8,
    now_slot: u64,
) -> Option<u64> {
    match now_slot.checked_sub(depth_slot) {
        Some(age) if age <= DEPTH_MAX_AGE_SLOTS => {}
        _ => return None,
    }
    if depth_source_of(depth_source_byte) == DEPTH_SOURCE_NONE {
        return None;
    }
    if depth_e6 == 0 {
        return Some(0);
    }
    if depth_source_byte & DEPTH_PREV_REAL == 0 {
        return None;
    }
    Some(if depth_e6 < depth_prev_e6 {
        depth_e6
    } else {
        depth_prev_e6
    })
}

/// The stored depth state of one asset (`AssetGrowthV19` bytes 44, 56..96).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DepthState {
    pub depth_e6: u64,
    pub depth_slot: u64,
    pub depth_prev_e6: u64,
    /// Byte 44: bits 0-1 source of the stored `depth_e6`, bit 7 `DEPTH_EVER`.
    pub depth_source: u8,
    pub last_good_e6: u64,
    pub last_good_slot: u64,
    /// Security review R2-M1 + D-L2: the slot of the last RISE of `last_good_e6`, in units of
    /// `DEPTH_RISE_STAMP_SLOTS` (64) slots (`slot / 64`, bytes 114..118 of the record).
    pub rise_slot64: u32,
    /// Round 3 item 4 (GAP-5): the time-weighted two-bucket window (bytes 30..38, 118..120).
    pub tw: DepthWindow,
}

/// D-L2: the unit of the stored last-rise stamp. A u32 of 64-slot units wraps after 2^32 * 64 =
/// 2.75e11 slots (~3,500 years at 400 ms); `depth_rise_stamp` saturates instead of wrapping, and
/// a saturated stamp never opens the window again (fails closed).
pub const DEPTH_RISE_STAMP_SLOTS: u64 = 64;

/// D-L2: the stored stamp of a rise at `slot` (`slot / 64`, saturating at `u32::MAX`).
pub fn depth_rise_stamp(slot: u64) -> u32 {
    u32::try_from(slot / DEPTH_RISE_STAMP_SLOTS).unwrap_or(u32::MAX)
}

/// D-L2: whether a new rise is allowed at `slot`: at least `RATCHET_EPOCH_SLOTS` (9,000) slots
/// after the LAST RISE, measured against the latest slot the stamp can stand for
/// (`stamp * 64 + 63`), so the window is never shorter than 9,000 slots whatever the rounding,
/// and independent of calendar-epoch boundaries (round 2 gated on `slot / 9,000`: samples
/// straddling a boundary got two doublings one slot apart). Saturating.
pub fn depth_rise_window_open(rise_slot64: u32, slot: u64) -> bool {
    let last = (rise_slot64 as u64)
        .saturating_mul(DEPTH_RISE_STAMP_SLOTS)
        .saturating_add(DEPTH_RISE_STAMP_SLOTS - 1);
    rise_slot64 != u32::MAX && slot >= last.saturating_add(DEPTH_STICKY_EPOCH_SLOTS)
}

// ── v2.2 round 3 item 4 (design GAP-5, D-I1, D2): time-weighted depth minimum ──────────────────

/// The time-weighted window's bucket: 750 slots (~5 min at 400 ms). The window is the current and
/// the previous bucket, i.e. the minimum of every fresh sample over the last 5-10 minutes.
/// Liveness (security review F-8): a RISE needs a full adjacent bucket pair, so the keeper must
/// push depth at least once per 750 slots or the rate-limited depth can never rise.
pub const DEPTH_TW_BUCKET_SLOTS: u64 = 750;
/// The stored bucket index is `(slot / 750) % DEPTH_TW_BUCKET_RING + 1` (u16; 0 = no window
/// history yet). The ring wraps after 65,535 buckets (~49M slots, ~227 days at 400 ms); a wrapped false
/// "same" / "adjacent" match only ever folds an OLDER minimum in (a min), never raises anything.
pub const DEPTH_TW_BUCKET_RING: u64 = 65_535;
/// `depth_tw_prev_tokens` value meaning "no previous bucket in the window" (a gap of more than
/// one bucket, or the window's first bucket). Real readings saturate at `u32::MAX - 1`.
pub const DEPTH_TW_ABSENT: u32 = u32::MAX;

/// The stored time-weighted window (`AssetGrowthV19` bytes 30..34, 34..38, 118..120).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DepthWindow {
    /// The minimum fresh reading in the current bucket, whole collateral tokens (floor).
    pub cur_tokens: u32,
    /// The minimum of the previous (adjacent) bucket, or `DEPTH_TW_ABSENT`.
    pub prev_tokens: u32,
    /// `bucket % ring + 1`; 0 = no window history (a record from before round 3, or reset).
    pub bucket_p1: u16,
}

/// The stored bucket code of `slot`.
pub fn depth_tw_bucket_p1(slot: u64) -> u16 {
    ((slot / DEPTH_TW_BUCKET_SLOTS) % DEPTH_TW_BUCKET_RING + 1) as u16
}

/// Atoms -> whole tokens (floor), saturating at `u32::MAX - 1` (never the absent marker).
pub fn depth_tokens_floor(depth_atoms: u64, unit_atoms: u64) -> u32 {
    if unit_atoms == 0 {
        return 0;
    }
    let t = depth_atoms / unit_atoms;
    if t >= DEPTH_TW_ABSENT as u64 {
        DEPTH_TW_ABSENT - 1
    } else {
        t as u32
    }
}

/// Fold one FRESH sample (`r_tokens`, at `slot`) into the window:
/// * same bucket: `cur = min(cur, r)`;
/// * the next bucket: `prev = cur`, `cur = r`;
/// * otherwise (the first sample, or a gap of more than one bucket): `prev = ABSENT`, `cur = r`.
pub fn depth_tw_update(w: DepthWindow, r_tokens: u32, slot: u64) -> DepthWindow {
    let b = depth_tw_bucket_p1(slot);
    if w.bucket_p1 != 0 && b == w.bucket_p1 {
        return DepthWindow {
            cur_tokens: if r_tokens < w.cur_tokens { r_tokens } else { w.cur_tokens },
            ..w
        };
    }
    let next = if w.bucket_p1 == 0 {
        0
    } else if w.bucket_p1 as u64 == DEPTH_TW_BUCKET_RING {
        1
    } else {
        w.bucket_p1 + 1
    };
    let prev = if w.bucket_p1 != 0 && b == next { w.cur_tokens } else { DEPTH_TW_ABSENT };
    DepthWindow { cur_tokens: r_tokens, prev_tokens: prev, bucket_p1: b }
}

/// The window minimum in ATOMS: `min(cur, prev)` (absent prev ignored), `None` without history.
/// Saturating multiply (a saturated value is an upper bound only ever min-ed with real ones).
pub fn depth_tw_min_atoms(w: DepthWindow, unit_atoms: u64) -> Option<u64> {
    if w.bucket_p1 == 0 {
        return None;
    }
    let m = if w.prev_tokens < w.cur_tokens { w.prev_tokens } else { w.cur_tokens };
    Some((m as u64).saturating_mul(unit_atoms))
}

/// Validator: no history (bucket 0) means an all-zero window (every pre-round-3 record: bytes
/// 30..38 were validated 0); with history the current minimum is a real reading (never the
/// absent marker) and the bucket code is in `1..=ring`.
pub fn depth_tw_window_ok(w: DepthWindow) -> bool {
    if w.bucket_p1 == 0 {
        w.cur_tokens == 0 && w.prev_tokens == 0
    } else {
        w.cur_tokens != DEPTH_TW_ABSENT && (w.bucket_p1 as u64) <= DEPTH_TW_BUCKET_RING
    }
}

/// SEC-RC L-1: a depth window (bucket code != 0) exists only in the round-3 layout (flags bit 0).
/// A record with flags 0 and a window is refused, fail closed: the controller rollback reads a
/// flags-0 record as pre-controller and refuses a window there, so both sides agree on the shape.
pub fn depth_tw_layout_ok(flags: u8, w: DepthWindow) -> bool {
    w.bucket_p1 == 0 || flags & GROWTH_FLAG_R3_LAYOUT != 0
}

/// Whether the window spans a full adjacent bucket pair (a RISE of the rate-limited depth needs
/// it: liquidity must have been the minimum over >= one whole previous bucket, not one push).
pub fn depth_tw_full(w: DepthWindow) -> bool {
    w.bucket_p1 != 0 && w.prev_tokens != DEPTH_TW_ABSENT
}

/// Security review R2-M1 ("up slowly, down at once" for the depth itself) + round 3 item 4
/// (GAP-5: fed the TIME-WEIGHTED window minimum `w`, D-I1, D2). The rate-limited depth
/// `last_good` after a fresh sample folded into the window (sample slot `slot`). `seed_e6` = the
/// market's T1 in atoms minus 1. `rise_ok` = the window spans a full adjacent bucket pair
/// (`depth_tw_full`). Returns `(last_good, rise_slot64, last_good_slot)`:
/// * the market's FIRST fresh reading (`DEPTH_EVER` not yet set): `min(w, seed / 16)` (D-I1:
///   round 2 seeded `T1 - 1`, ~12x a $2k pool's honest κ cap on a first-pair flash), a rise;
/// * `w == 0` (a REAL zero inside the window): `last_good` and its slot are HELD (D2). The zero
///   still caps every reader at 0 at once through the window (`usable_depth_e6`,
///   `cap_depth_e6`), and keeps doing so while it is inside the 5-10 min window, so a one-sample
///   glitch no longer costs a deep market ~7 h of doublings from T1/16;
/// * otherwise against `base = sticky_depth_e6(last_good, last_good_slot, slot)` (equal to
///   `last_good` in steady state; a value held through a long zero decays at the sticky rate,
///   halving per 9,000 slots of zero, so a zero lasting hours recovers only to `last_good / 2^k`):
///   * `w <= base`: `w` at once (down at once); the rise clock is kept;
///   * `w > base`, `rise_ok` and >= 9,000 slots after the last rise (`depth_rise_window_open`,
///     D-L2): `min(w, max(2 * base, seed / 16))`, a rise -- at most one doubling per 9,000 slots;
///   * otherwise: `base`.
#[allow(clippy::too_many_arguments)]
pub fn depth_rate_limited(
    ever: bool,
    last_good_e6: u64,
    last_good_slot: u64,
    rise_slot64: u32,
    w: u64,
    rise_ok: bool,
    slot: u64,
    seed_e6: u64,
) -> (u64, u32, u64) {
    let e = depth_rise_stamp(slot);
    let floor = seed_e6 / DEPTH_BOOTSTRAP_DIV;
    if !ever {
        return (if w < floor { w } else { floor }, e, slot);
    }
    if w == 0 {
        return (last_good_e6, rise_slot64, last_good_slot);
    }
    let base = sticky_depth_e6(last_good_e6, last_good_slot, slot);
    if w <= base {
        return (w, rise_slot64, slot);
    }
    if rise_ok && depth_rise_window_open(rise_slot64, slot) {
        let doubled = base.saturating_mul(2);
        let up = if doubled > floor { doubled } else { floor };
        return (if w < up { w } else { up }, e, slot);
    }
    (base, rise_slot64, slot)
}

/// The depth every reader uses (tiers and the κ cap): `min(fresh reading, rate-limited
/// last_good, time-weighted window minimum)`; `None` while there is no fresh reading (the
/// sticky path then applies). `tw_min_e6` `None` = no window history (a pre-round-3 record):
/// round 2's `min(fresh, last_good)` exactly.
pub fn usable_depth_e6(fresh: Option<u64>, last_good_e6: u64, tw_min_e6: Option<u64>) -> Option<u64> {
    let tw = tw_min_e6.unwrap_or(u64::MAX);
    fresh.map(|f| {
        let m = if f < last_good_e6 { f } else { last_good_e6 };
        if m < tw {
            m
        } else {
            tw
        }
    })
}

/// THE depth writer (every PushAuthMark form: 35 B, 44 B mode 0/1, and the on-chain DEX mode 2,
/// which calls it with `source = DEPTH_SOURCE_DEX`). `source` is the new reading's source;
/// `DEPTH_SOURCE_NONE` or an unknown source is an ABSENT sample (`new_depth_e6` is ignored). A
/// REAL reading (source 1 or 2) of 0 is a real zero depth, not absent (coordinator ruling).
/// * A push in a LATER slot than the stored sample: the stored sample becomes the previous one
///   (`depth_prev_e6`, with `DEPTH_PREV_REAL` = whether it was real) and the new one is stored,
///   stamped `now`.
/// * Security review W-L2: a push in the SAME slot as the stored sample (`now == depth_slot`,
///   e.g. two pushes in one slot or one transaction) is not a second point in time: `prev` is
///   kept and the stored depth can only FALL, `min(depth_e6, new)`; the source follows the
///   value that is kept (a same-slot DEX push cannot relabel an attested value as DEX), and at
///   a tie of zeros the REAL zero wins over an absent one (more conservative).
/// * A push stamped BEFORE the stored sample (`now < depth_slot`; the handler refuses a slot
///   regression, so this is defensive) is treated like the same slot (fall only).
/// * The source bits describe the stored `depth_e6`: NONE for an absent sample.
/// * R2.1 (W-M1) + R2-M1: when the result is a FRESH reading (`fresh_depth_e6` is `Some`, a
///   real 0 included), the last good depth becomes its RATE-LIMITED value
///   (`depth_rate_limited`: down at once, up <= 2x per epoch, the first reading below T1),
///   stamped with the sample's slot, and `DEPTH_EVER` is set. Otherwise the last good depth,
///   its rise epoch and `DEPTH_EVER` are kept.
/// * `seed_e6`: the market's T1 in atoms minus 1 (`tier_thresholds(..)[0] - 1`).
pub fn depth_push_update(
    st: DepthState,
    source: u8,
    new_depth_e6: u64,
    now_slot: u64,
    seed_e6: u64,
    unit_atoms: u64,
) -> DepthState {
    let (source, new_depth_e6) = if source == DEPTH_SOURCE_NONE || source > DEPTH_SOURCE_DEX {
        (DEPTH_SOURCE_NONE, 0)
    } else {
        (source, new_depth_e6)
    };
    let old_source = depth_source_of(st.depth_source);
    let old_prev_real = st.depth_source & DEPTH_PREV_REAL;
    let (d, prev, slot, src, prev_real) = if st.depth_slot != 0 && now_slot <= st.depth_slot {
        let take_new = new_depth_e6 < st.depth_e6
            || (new_depth_e6 == 0
                && st.depth_e6 == 0
                && source != DEPTH_SOURCE_NONE
                && old_source == DEPTH_SOURCE_NONE);
        if take_new {
            (new_depth_e6, st.depth_prev_e6, st.depth_slot, source, old_prev_real)
        } else {
            (st.depth_e6, st.depth_prev_e6, st.depth_slot, old_source, old_prev_real)
        }
    } else {
        let was_real = if old_source != DEPTH_SOURCE_NONE {
            DEPTH_PREV_REAL
        } else {
            0
        };
        (new_depth_e6, st.depth_e6, now_slot, source, was_real)
    };
    let mut out = DepthState {
        depth_e6: d,
        depth_slot: slot,
        depth_prev_e6: prev,
        depth_source: src | prev_real | (st.depth_source & DEPTH_EVER),
        last_good_e6: st.last_good_e6,
        last_good_slot: st.last_good_slot,
        rise_slot64: st.rise_slot64,
        tw: st.tw,
    };
    if let Some(f) = fresh_depth_e6(d, prev, slot, out.depth_source, now_slot) {
        // Round 3 item 4: the fresh reading enters the time-weighted window (whole tokens,
        // floor); the rate limiter is fed the WINDOW minimum, so a rise needs liquidity held over
        // the whole window (>= one full bucket), not two pushes.
        out.tw = depth_tw_update(st.tw, depth_tokens_floor(f, unit_atoms), slot);
        let w = depth_tw_min_atoms(out.tw, unit_atoms).unwrap_or(0);
        let w = if w < f { w } else { f };
        // R2-M1: last_good is the RATE-LIMITED depth (rises <= 2x per 9,000 slots, falls at
        // once, a real zero held and gated through the window -- D2).
        let (lg, re, lgs) = depth_rate_limited(
            depth_ever(st.depth_source),
            st.last_good_e6,
            st.last_good_slot,
            st.rise_slot64,
            w,
            depth_tw_full(out.tw),
            slot,
            seed_e6,
        );
        out.depth_source |= DEPTH_EVER;
        out.last_good_e6 = lg;
        // The sticky decay clock: the slot of the last fresh POSITIVE sample (held through a
        // real zero, D2): the first halving is 9,000 slots after it.
        out.last_good_slot = lgs;
        out.rise_slot64 = re;
    }
    out
}

/// R2.1 §1 (W-M1): the sticky depth `last_good × 2^-k`, `k = floor((now − last_good_slot) /
/// 9,000)`; 0 once `k >= 64`. Monotone non-increasing in `now`. A `last_good_slot` after `now`
/// reads as age 0 (no decay; still a cap, never "uncapped").
pub fn sticky_depth_e6(last_good_e6: u64, last_good_slot: u64, now_slot: u64) -> u64 {
    let k = now_slot.saturating_sub(last_good_slot) / DEPTH_STICKY_EPOCH_SLOTS;
    if k >= 64 {
        0
    } else {
        last_good_e6 >> k
    }
}

/// The depth the κ cap on `N_cap` uses (clamp-enforced markets), from the FRESH reading
/// (`fresh_depth_e6`):
/// * a fresh reading: `Some(it)` -- a real 0 included (cap 0: opens closed at once);
/// * none fresh but `DEPTH_EVER`: `Some(sticky_depth_e6(..))` -- the cap stays, decaying to 0
///   (opens closed; reductions and closes are never capacity-checked), NEVER uncapped;
/// * never had a fresh depth: `None` (no depth cap, the capital rule alone: a market is not
///   closed before its first pair of readings).
pub fn cap_depth_e6(
    depth_source_byte: u8,
    fresh_depth_e6: Option<u64>,
    last_good_e6: u64,
    last_good_slot: u64,
    now_slot: u64,
    tw_min_e6: Option<u64>,
) -> Option<u64> {
    if fresh_depth_e6.is_some() {
        fresh_depth_e6
    } else if depth_ever(depth_source_byte) {
        // Round 3 item 4: never above the last window minimum either (a real zero still in the
        // window keeps the sticky cap at 0: the fresh-zero ruling survives the held last_good).
        let st = sticky_depth_e6(last_good_e6, last_good_slot, now_slot);
        let tw = tw_min_e6.unwrap_or(u64::MAX);
        Some(if st < tw { st } else { tw })
    } else {
        None
    }
}

/// Security review R2-L2: the collateral mint's decimals as stored in the growth record (byte
/// 46 = decimals + 1, written at InitMarket from the mint). 0 = a record written before R2-L2:
/// read as 6 (every such market is on 6-decimal sUSDC/USDC, the round-1 assumption).
pub fn collateral_decimals_of(stored_p1: u8) -> u8 {
    if stored_p1 == 0 {
        6
    } else {
        stored_p1 - 1
    }
}

/// Security review D-L1: the largest collateral decimals a GROWTH market accepts (InitMarket
/// refuses more with `GrowthInvalidConfig`; the validator bounds byte 46 at 12 + 1). At 12
/// decimals the default thresholds (<= 500,000 tokens = 5e17 atoms) never saturate u64 (const
/// assert below). An explicit threshold near `u32::MAX` tokens can still saturate; a saturated
/// threshold is never met (`depth_tier_for`). At >= 14 decimals round 2's defaults saturated and
/// met saturated depths (tier 3 from ~18 tokens).
pub const MAX_COLLATERAL_DECIMALS: u8 = 12;
const _: () = assert!(
    (TIER_THRESHOLD_DEFAULT_USD[2] as u128) * 1_000_000_000_000 < u64::MAX as u128
);

/// `10^decimals` as u64 (saturating; decimals are bounded at `MAX_COLLATERAL_DECIMALS` = 12).
pub fn whole_token_atoms(decimals: u8) -> u64 {
    10u64.saturating_pow(u32::from(decimals.min(MAX_COLLATERAL_DECIMALS)))
}

/// R2.1 §2 + R2-L2: the per-market thresholds in collateral ATOMS: the stored values are WHOLE
/// COLLATERAL TOKENS (0 = the default 25,000 / 100,000 / 500,000 tokens; on 6-decimal USD
/// collateral these are $25k / $100k / $500k), scaled by the collateral mint's decimals.
/// Saturates at `u64::MAX` (a threshold no depth reaches: fail closed to a lower tier).
pub fn tier_thresholds(stored_tokens: [u32; 3], collateral_decimals: u8) -> [u64; 3] {
    let unit = whole_token_atoms(collateral_decimals);
    let mut t = [0u64; 3];
    let mut i = 0;
    while i < 3 {
        let v = if stored_tokens[i] == 0 {
            TIER_THRESHOLD_DEFAULT_USD[i]
        } else {
            stored_tokens[i]
        };
        t[i] = (v as u64).saturating_mul(unit);
        i += 1;
    }
    t
}

/// The raw tier of a depth against thresholds: 0 below T1 (and always 0 for a depth of 0), 1
/// from T1, 2 from T2, 3 from T3. D-L1 (belt and braces): a SATURATED threshold (`u64::MAX`) is
/// never met -- depths saturate at `u64::MAX` too (book depth, DEX valuation, a u64 attestation),
/// and a saturated depth meeting a saturated threshold failed open.
pub fn depth_tier_for(depth_e6: u64, thresholds_e6: [u64; 3]) -> u8 {
    let met = |t: u64| t != u64::MAX && depth_e6 >= t;
    if depth_e6 == 0 {
        0
    } else if met(thresholds_e6[2]) {
        3
    } else if met(thresholds_e6[1]) {
        2
    } else if met(thresholds_e6[0]) {
        1
    } else {
        0
    }
}

/// `attested_max_tier` in force: stored 0 = `ATTESTED_MAX_TIER_DEFAULT` (1), at most 3.
pub fn attested_max_tier_eff(stored: u8) -> u8 {
    if stored == 0 {
        ATTESTED_MAX_TIER_DEFAULT
    } else if stored > MAX_TIER {
        MAX_TIER
    } else {
        stored
    }
}

/// R2.1 §3 venue tier (how hard the price source is to move), from the EFFECTIVE depth (0 when
/// absent / stale: I-D1) and the stored depth's source: DEX (2) no cap; keeper-attested (1)
/// capped at `attested_max_tier`; none -> 0.
pub fn venue_tier(
    effective_depth_e6: u64,
    depth_source_byte: u8,
    thresholds_e6: [u64; 3],
    attested_max_tier_stored: u8,
) -> u8 {
    let raw = depth_tier_for(effective_depth_e6, thresholds_e6);
    match depth_source_of(depth_source_byte) {
        DEPTH_SOURCE_DEX => raw,
        DEPTH_SOURCE_ATTESTED => {
            let m = attested_max_tier_eff(attested_max_tier_stored);
            if raw > m {
                m
            } else {
                raw
            }
        }
        _ => 0,
    }
}

/// The band the book depth is measured in (±2%, the same band as the venue depth).
pub const BOOK_DEPTH_BAND_BPS: u32 = 200;

/// R2.1 §3 book depth from the pinned matcher model (pure core): the notional the LP book fills
/// within ±`BOOK_DEPTH_BAND_BPS` of the oracle, given its capacity notional `cap_e6`.
/// The pinned kind-2 matcher quotes `oracle · (1 ± min(max_total, fixed + impact(n)))` with the
/// constant-product impact `impact(n) = k · n / (D − n)` over the ext-v3 depth
/// `D = DEPTH_MULT · cap` (`liquidity_notional_e6`), and the wrapper refuses any fill past
/// `cap` (N_cap). So:
/// * `max_total < 200`: no quote is ever 2% away -> the whole capacity, `cap`;
/// * else `fixed >= 200`: nothing fills inside 2% -> 0;
/// * else the `n*` where `fixed + k·n*/(D − n*) = 200`, i.e.
///   `n* = D · (200 − fixed) / (k + 200 − fixed)` (floor), and the result is `min(cap, n*)`.
pub fn book_depth_from_pins(cap_e6: u128, fixed_bps: u32, impact_k_bps: u32, max_total_bps: u32) -> u128 {
    if max_total_bps < BOOK_DEPTH_BAND_BPS {
        return cap_e6;
    }
    if fixed_bps >= BOOK_DEPTH_BAND_BPS {
        return 0;
    }
    let room = (BOOK_DEPTH_BAND_BPS - fixed_bps) as u128;
    let d = cap_e6.saturating_mul(DEPTH_MULT);
    let n = crate::vault_lp_v18::mul_div_floor(d, room, (impact_k_bps as u128) + room).unwrap_or(0);
    if n < cap_e6 {
        n
    } else {
        cap_e6
    }
}

/// The book's capacity notional for the book tier: `floor(C_m · min(stored λ, 1x) / 1e4)`.
/// `min(stored λ, 1x)` is the λ_eff of tiers 0 and 1 and never above the λ_eff of any tier, so
/// the measure is never circular (it does not depend on the tier it decides) and never above
/// the LP's real capacity. Exact and overflow-free at every `c_m` (`lam <= 1e4`):
/// `floor(c·lam/1e4) = (c / 1e4)·lam + floor((c % 1e4)·lam / 1e4)`, so it is monotone in `C_m`.
pub fn book_capacity_e6(c_m: u128, stored_lambda_bps: u32) -> u128 {
    let lam = if stored_lambda_bps < DEFAULT_LAMBDA_BPS {
        stored_lambda_bps
    } else {
        DEFAULT_LAMBDA_BPS
    } as u128;
    (c_m / BPS) * lam + (c_m % BPS) * lam / BPS
}

/// R2.1 §3 book depth of the bound vault LP with conservative equity `c_m`, from the PINNED
/// kind-2 parameters tag 94 writes (`vault_lp_v18::PIN_*`; fixed = base spread + trading fee).
/// With the pins (max_total 100 bps < 200) this is exactly `book_capacity_e6` (the
/// `const` below pins that fact). Saturates at `u64::MAX`.
pub fn book_depth_e6(c_m: u128, stored_lambda_bps: u32) -> u64 {
    let b = book_depth_from_pins(
        book_capacity_e6(c_m, stored_lambda_bps),
        crate::vault_lp_v18::PIN_BASE_SPREAD_BPS + crate::vault_lp_v18::PIN_TRADING_FEE_BPS,
        crate::vault_lp_v18::PIN_IMPACT_K_BPS,
        crate::vault_lp_v18::PIN_MAX_TOTAL_BPS,
    );
    u64::try_from(b).unwrap_or(u64::MAX)
}
// The pinned quote can never be 2% away (and the wrapper's requested-fee cap is the same 100 bps):
// the book depth is the capacity notional.
const _: () = assert!(crate::vault_lp_v18::PIN_MAX_TOTAL_BPS < BOOK_DEPTH_BAND_BPS);
const _: () = assert!((GROWTH_PIN_MAX_REQUESTED_FEE_BPS as u32) < BOOK_DEPTH_BAND_BPS);

/// The book tier: `depth_tier_for(book_depth_e6(C_m, λ), thresholds)`.
pub fn book_tier(c_m: u128, stored_lambda_bps: u32, thresholds_e6: [u64; 3]) -> u8 {
    depth_tier_for(book_depth_e6(c_m, stored_lambda_bps), thresholds_e6)
}

/// R2.1 §3: `tier = min(venue_tier, book_tier)`.
pub fn combined_tier(venue: u8, book: u8) -> u8 {
    if venue < book {
        venue
    } else {
        book
    }
}

/// R2.1 §2: the per-market leverage table (x100) `[L0, L1, L2, L3]`. `L0 = min(L_launch, L_tier)`
/// (tier 0 never graduates); `Li` = the stored value, or `min(default_i, L_tier)` when 0, then
/// clamped into `[L_{i-1}, L_tier]`, so the table is monotone and never above `L_tier` on ANY
/// record (on a validated explicit table the clamps are no-ops).
pub fn tier_leverage(stored_x100: [u16; 3], l_launch_x100: u16, l_tier_x100: u16) -> [u16; 4] {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    let mut t = [launch; 4];
    let mut prev = launch;
    let mut i = 0;
    while i < 3 {
        let v = if stored_x100[i] == 0 {
            TIER_LEVERAGE_DEFAULT_X100[i]
        } else {
            stored_x100[i]
        };
        let v = if v > l_tier_x100 { l_tier_x100 } else { v };
        let v = if v < prev { prev } else { v };
        t[i + 1] = v;
        prev = v;
        i += 1;
    }
    t
}

/// `L_table(tier)` (tiers above 3 read as 3).
pub fn l_table_x100(tier: u8, table: [u16; 4]) -> u16 {
    table[if tier > MAX_TIER { MAX_TIER } else { tier } as usize]
}

/// R2.1 §2 tier-config bounds (the setters refuse with `GrowthTierConfigInvalid` (130); the
/// record validator refuses with `InvalidAccountData`). Each group is all-zero (protocol
/// defaults) or, with its zeros read as the defaults:
/// * thresholds: `T1 < T2 < T3`, `T1 >= $5k`, `T2 >= $20k`, `T3 >= $100k`;
/// * leverage: `L_launch <= L1 <= L2 <= L3 <= L_tier` (a 0 reads as `min(default, L_tier)`).
pub fn tier_config_ok(
    thresholds_usd: [u32; 3],
    leverage_x100: [u16; 3],
    l_launch_x100: u16,
    l_tier_x100: u16,
) -> bool {
    if thresholds_usd != [0u32; 3] {
        let mut w = [0u32; 3];
        let mut i = 0;
        while i < 3 {
            w[i] = if thresholds_usd[i] == 0 {
                TIER_THRESHOLD_DEFAULT_USD[i]
            } else {
                thresholds_usd[i]
            };
            if w[i] < TIER_THRESHOLD_FLOOR_USD[i] {
                return false;
            }
            i += 1;
        }
        if !(w[0] < w[1] && w[1] < w[2]) {
            return false;
        }
    }
    if leverage_x100 != [0u16; 3] {
        let mut prev = l_launch_x100;
        let mut i = 0;
        while i < 3 {
            let v = if leverage_x100[i] == 0 {
                let d = TIER_LEVERAGE_DEFAULT_X100[i];
                if d > l_tier_x100 {
                    l_tier_x100
                } else {
                    d
                }
            } else {
                leverage_x100[i]
            };
            if v < prev || v > l_tier_x100 {
                return false;
            }
            prev = v;
            i += 1;
        }
    }
    true
}

/// R2.1 §2 tier block on the wire (tag 94 bind block: 18 B; tag 93 tier trailer: these 18 B +
/// `attested_max_tier`). Little-endian `[T1 u32][T2 u32][T3 u32][L1 u16][L2 u16][L3 u16]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TierConfig {
    pub threshold_usd: [u32; 3],
    pub leverage_x100: [u16; 3],
}

/// Wire length of a `TierConfig` block.
pub const TIER_CONFIG_WIRE_LEN: usize = 18;

/// R2.1 §2, tag 94 (creator at bind): merge the creator's block into the stored tier table
/// FIELD BY FIELD, the same rule as the G4 risk defaults (security review L-4): a field the
/// upgrade authority preset (non-zero) before the bind is kept; a zero field takes the
/// creator's value. The caller bounds the merged result (`tier_config_ok`, else 130).
pub fn tier_config_merge_at_bind(stored: TierConfig, creator: TierConfig) -> TierConfig {
    let mut out = stored;
    let mut i = 0;
    while i < 3 {
        if out.threshold_usd[i] == 0 {
            out.threshold_usd[i] = creator.threshold_usd[i];
        }
        if out.leverage_x100[i] == 0 {
            out.leverage_x100[i] = creator.leverage_x100[i];
        }
        i += 1;
    }
    out
}

/// `attested_max_tier` bound: 0 (default) ..= 3.
pub fn attested_max_tier_ok(v: u8) -> bool {
    v <= MAX_TIER
}

// ── v2.2 continuous leverage (2026-10-19, Khubair: "it should be able to go to 6x etc"):
// leverage / κ / λ_depth as ONE continuous curve of depth, interpolated on log2(depth) between
// the tier anchors. Replaces round 3 item 5's 25% ramps (which were "never looser than the step
// table"); this curve IS looser than the step table between anchors (e.g. ~7.4x at $50k on the
// default 5x / 10x / 20x table vs the 5x step) -- the decided trade-off -- and equal to it AT
// every anchor.

/// Fractional bits of the fixed-point `log2` (`log2_q16`).
pub const LOG2_FRAC_BITS: u32 = 16;

/// The implicit anchor 0 sits `T1 / CURVE_ANCHOR0_DIV` (one default tier spacing, 4x, below T1).
/// It carries the tier-0 value of each table (launch leverage, κ 0.5, λ 1x), so the κ term rises
/// continuously from 0.5 at `T1 / 4` to 1 at `T1` instead of doubling at `T1`. Leverage is not
/// loosened below `T1` by it: graduation still needs the discrete tier >= 1 (`graduation_on`),
/// i.e. both depths >= `T1`, so the leverage target below `T1` stays launch.
pub const CURVE_ANCHOR0_DIV: u64 = 4;

/// Fixed-point `log2(x)` in Q.16 (`(floor(log2 x) << 16) | 16 fractional bits`), `None` for 0.
/// The integer part is exact (leading zeros); the fraction is the first 16 binary digits of
/// `log2(m)` for the 32-bit normalised mantissa `m in [1, 2)`, by repeated squaring with a
/// floor at every step. MONOTONE NON-DECREASING in `x` (a larger mantissa squares to a larger
/// or equal value at every step, so its digit string is lexicographically >=), exact at powers
/// of two, and below the true value by < 2^-16 + the mantissa truncation. All products are
/// `< 2^32 * 2^32 = 2^64` (the mantissa invariant), so none can wrap.
pub fn log2_q16(x: u64) -> Option<u32> {
    if x == 0 {
        return None;
    }
    let k = 63 - x.leading_zeros();
    // m in [2^31, 2^32): Q.31 mantissa of x / 2^k.
    let m: u64 = if k >= 31 { x >> (k - 31) } else { x << (31 - k) };
    Some((k << LOG2_FRAC_BITS) | log2_frac_q16(m))
}

/// The 16 fractional binary digits of `log2(m / 2^31)` for a Q.31 mantissa `m in [2^31, 2^32)`
/// (`log2_q16`'s fraction; a named function so Kani can replace it by its proven properties).
/// Result `< 2^16`, monotone non-decreasing in `m`, 0 at `m = 2^31`. Requires `m < 2^32`
/// (`log2_q16` passes the normalised mantissa): every product below is then `< 2^64`.
#[inline(always)]
pub fn log2_frac_q16(mut m: u64) -> u32 {
    let mut frac: u32 = 0;
    let mut i = 0;
    while i < LOG2_FRAC_BITS {
        // m < 2^32 (loop invariant: it starts in [2^31, 2^32) and is halved whenever it reaches
        // 2^32), so m * m < 2^64 never wraps; `wrapping_mul` is the native SBF multiply
        // (`checked_mul` lowers to a 128-bit overflow-checked multiply; measured on a first,
        // one-live-position version of the CU probe `contlev_cu_probe_controller_paths`: a
        // vault-LP open cost +20,260 CU over the base with it, +3,802 CU with this).
        debug_assert!(m < 1u64 << 32);
        m = m.wrapping_mul(m) >> 31; // in [2^31, 2^33)
        frac <<= 1;
        if m >= 1u64 << 32 {
            frac |= 1;
            m >>= 1;
        }
        i += 1;
    }
    frac
}

/// The four curve anchors (atoms) of a market's thresholds: `[T1 / 4, T1, T2, T3]`.
pub fn curve_anchors(thresholds_e6: [u64; 3]) -> [u64; 4] {
    [thresholds_e6[0] / CURVE_ANCHOR0_DIV, thresholds_e6[0], thresholds_e6[1], thresholds_e6[2]]
}

/// Where a depth sits on the curve: `seg` = how many anchors it has met (0 = below anchor 0,
/// 4 = at or past T3); for `seg in 1..=3` the value is `t[seg-1] + (t[seg] - t[seg-1]) * num /
/// den` (floor) with `num <= den`; `den == 0` means "flat at `t[seg-1]`" (a saturated or
/// non-increasing next anchor: fail closed to the lower value). `seg == 0xFF` = an arithmetic
/// failure: the curve reads `t[0]` (launch, κ 0.5, λ 1x).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurvePos {
    pub seg: u8,
    pub num: u32,
    pub den: u32,
}

/// `CurvePos` of a failed computation (reads `t[0]`).
pub const CURVE_POS_FAIL: CurvePos = CurvePos { seg: 0xFF, num: 0, den: 0 };

/// The curve position of depth `d` (atoms) over `thresholds_e6`. An anchor is met when
/// `d >= anchor` and the anchor is not saturated (`u64::MAX`, D-L1: never met, as
/// `depth_tier_for`); a depth of 0 meets nothing. Interpolation is on `log2`: `num = log2(d) -
/// log2(a_lo)`, `den = log2(a_hi) - log2(a_lo)` (Q.16), so the value is EXACTLY `t[i]` at every
/// anchor `a_i` (`num = 0` there).
pub fn curve_pos(d: u64, thresholds_e6: [u64; 3]) -> CurvePos {
    let a = curve_anchors(thresholds_e6);
    let met = |x: u64| x != u64::MAX && x != 0 && d >= x;
    if d == 0 {
        return CurvePos { seg: 0, num: 0, den: 0 };
    }
    // highest anchor met (top-down, the same order as `depth_tier_for`)
    let seg: u8 = if met(a[3]) {
        4
    } else if met(a[2]) {
        3
    } else if met(a[1]) {
        2
    } else if met(a[0]) {
        1
    } else {
        0
    };
    if seg == 0 || seg == 4 {
        return CurvePos { seg, num: 0, den: 0 };
    }
    let lo = a[(seg - 1) as usize];
    let hi = a[seg as usize];
    if hi == u64::MAX || hi <= lo {
        return CurvePos { seg, num: 0, den: 0 };
    }
    let (Some(ld), Some(llo), Some(lhi)) = (log2_q16(d), log2_q16(lo), log2_q16(hi)) else {
        return CURVE_POS_FAIL;
    };
    let (Some(num), Some(den)) = (ld.checked_sub(llo), lhi.checked_sub(llo)) else {
        return CURVE_POS_FAIL;
    };
    CurvePos { seg, num: if num < den { num } else { den }, den }
}

/// The curve value of a 4-entry table (index = tier) at a position. Monotone tables (every
/// table the program uses: `tier_leverage`, `KAPPA_TABLE_BPS`, `LAMBDA_DEPTH_TABLE_BPS`) give a
/// value in `[t[seg-1], t[seg]]`; a decreasing pair (never produced) reads the smaller of the
/// two. Never above `max(t)`, so the leverage curve is never above `L_tier` (`tier_leverage`
/// clamps every entry to it).
pub fn curve_value(p: CurvePos, t: [u64; 4]) -> u64 {
    match p.seg {
        0 => t[0],
        4 => t[3],
        1..=3 => {
            let (lo, hi) = (t[(p.seg - 1) as usize], t[p.seg as usize]);
            if hi < lo {
                return hi;
            }
            if p.den == 0 || hi == lo {
                return lo;
            }
            lo + curve_interp(hi - lo, p.num, p.den)
        }
        _ => t[0],
    }
}

/// `floor(span * num / den)` for `num <= den`, `den > 0` (`curve_value`'s interpolation step; a
/// named function so Kani can replace it by its proven properties). Then the result is `<= span`
/// (so `lo + result <= hi` never overflows), 0 at `num = 0`, `span` at `num = den`, monotone in
/// `num`, and monotone and 1-Lipschitz in `span`. Every program table spans < 2^32 (x100 / bps),
/// so the product fits u64 (u32 * u32) and the native u64 divide is used (SBF has no native u128
/// divide; this path saved 3,762 CU on that probe's vault-LP open); a wider span (never
/// produced) takes the exact u128 form, u64 * u32 < 2^96.
#[inline(always)]
pub fn curve_interp(span: u64, num: u32, den: u32) -> u64 {
    if span <= u32::MAX as u64 {
        // span < 2^32 and num <= den < 2^32: the product is < 2^64 (no wrap).
        span.wrapping_mul(num as u64) / (den as u64)
    } else {
        ((span as u128) * (num as u128) / (den as u128)) as u64
    }
}

/// `curve_value(curve_pos(d, th), t)`.
pub fn curve_u64(d: u64, thresholds_e6: [u64; 3], t: [u64; 4]) -> u64 {
    curve_value(curve_pos(d, thresholds_e6), t)
}

/// Capacity dials (κ, λ_depth) LAG the anchors (2026-10-19, security review M-1, Khubair: Toly's
/// fail-closed principle): continuous but NEVER LOOSER than the round-2 step anywhere. The jump
/// the step makes at `T_i` is spread over the NEXT segment instead: below T1 `t[0]`; on
/// `[T1, T2)` log2-interpolated from `t[0]` up to `t[1]`; on `[T2, T3)` from `t[1]` up to `t[2]`;
/// on `[T3, T3 * KAPPA_LAG_TOP_MUL)` from `t[2]` up to `t[3]`; `t[3]` from there. So the value is
/// `<=` the step value of the segment it is in, equals the step value of the segment BELOW at
/// each anchor (a continuous curve cannot equal a rising step at the anchor itself without
/// being looser just below it), and reaches each step value at the next anchor.
pub const KAPPA_LAG_TOP_MUL: u64 = 4;

/// The lagging position (κ / λ_depth) of a depth `d`, from its LEADING position `lead =
/// curve_pos(d, thresholds_e6)` (the leverage curve's). The lag anchors `[T1, T2, T3, 4·T3]` are
/// the leading anchors `[T1/4, T1, T2, T3]` shifted one place, so for `lead.seg` in 1..=3 the lag
/// position is the same interval and fraction one segment down (no `log2`); only `d >= T3`
/// (`lead.seg == 4`) computes its place on `[T3, 4·T3)` (`4·T3` saturating: a saturated top
/// anchor is never met and the segment is flat at `t[2]`, fail closed). The failure position
/// stays the failure position (reads `t[0]`).
pub fn curve_pos_lag(lead: CurvePos, d: u64, thresholds_e6: [u64; 3]) -> CurvePos {
    match lead.seg {
        1..=3 => CurvePos { seg: lead.seg - 1, num: lead.num, den: lead.den },
        4 => {
            let lo = thresholds_e6[2];
            let hi = lo.saturating_mul(KAPPA_LAG_TOP_MUL);
            if hi == u64::MAX || hi <= lo {
                return CurvePos { seg: 3, num: 0, den: 0 };
            }
            if d >= hi {
                return CurvePos { seg: 4, num: 0, den: 0 };
            }
            let (Some(ld), Some(llo), Some(lhi)) = (log2_q16(d), log2_q16(lo), log2_q16(hi)) else {
                return CURVE_POS_FAIL;
            };
            let (Some(num), Some(den)) = (ld.checked_sub(llo), lhi.checked_sub(llo)) else {
                return CURVE_POS_FAIL;
            };
            CurvePos { seg: 3, num: if num < den { num } else { den }, den }
        }
        0 => CurvePos { seg: 0, num: 0, den: 0 },
        _ => CURVE_POS_FAIL,
    }
}

/// `curve_value(curve_pos_lag(curve_pos(d, th), d, th), t)`: the lagging capacity curve.
pub fn curve_lag_u64(d: u64, thresholds_e6: [u64; 3], t: [u64; 4]) -> u64 {
    curve_value(curve_pos_lag(curve_pos(d, thresholds_e6), d, thresholds_e6), t)
}

// ── v2.2 round 3 item 6 (design GAP-6): a volatility input to the leverage target ───────────

/// The EWMA weight of a new sample: `1 / 2^4`, PER PUSH (not per unit of time): the memory is
/// ~16 pushes whatever their spacing (security review F-4, accepted for devnet).
pub const VOL_EWMA_SHIFT: u32 = 4;
/// z of the volatility term (protocol constant, conservative).
pub const VOL_Z: u64 = 3;
/// One move is capped at 100% for the arithmetic (u64 squares never overflow); a larger move
/// still saturates the variance far above any leverage it could allow.
pub const VOL_MOVE_CAP_BPS: u64 = 10_000;
/// The variance a market's FIRST sample is seeded at (no data -> no loosening): (5 bps)^2 per
/// slot, x100 -- about 5x a calm major's per-slot volatility, so the EWMA can only fall toward the
/// measured level (~16 calm pushes per e-fold), never start below it.
pub const VOL_VAR_SEED_X100: u32 = 2_500;
/// `AssetGrowthV19::flags` bit 0 (round 3): bytes 0..8 hold round-3 data (the variance 0..4 and
/// the rent-snapshot stamp 4..8). Clear = a record from before round 3 whose 0..8 are the
/// retired `c_launch_atoms`: no volatility data, no rent stamp.
pub const GROWTH_FLAG_R3_LAYOUT: u8 = 0x01;
/// `flags` bit 1: the variance has at least one sample (requires bit 0).
pub const GROWTH_FLAG_VOL_DATA: u8 = 0x02;

/// Validator for the `flags` byte: only bits 0-1, and bit 1 only with bit 0.
pub fn growth_flags_ok(flags: u8) -> bool {
    flags & !(GROWTH_FLAG_R3_LAYOUT | GROWTH_FLAG_VOL_DATA) == 0
        && (flags & GROWTH_FLAG_VOL_DATA == 0 || flags & GROWTH_FLAG_R3_LAYOUT != 0)
}

/// One squared move, bps^2 per slot x100: `min(|p - p0| * 1e4 / p0, cap)^2 * 100 / dt` (ceil:
/// never understates). `None` (no sample) with no previous mark or `dt == 0` (same-slot pushes
/// are skipped).
pub fn vol_sample_x100(prev_mark_e6: u64, mark_e6: u64, dt_slots: u64) -> Option<u64> {
    if prev_mark_e6 == 0 || dt_slots == 0 {
        return None;
    }
    let diff = (mark_e6 as u128).abs_diff(prev_mark_e6 as u128);
    let mv = (diff * BPS).div_ceil(prev_mark_e6 as u128);
    let mv = if mv > VOL_MOVE_CAP_BPS as u128 { VOL_MOVE_CAP_BPS as u128 } else { mv };
    Some(((mv * mv * 100).div_ceil(dt_slots as u128)) as u64)
}

/// The EWMA update (stored u32, saturating): the first sample seeds `max(sample, seed)`; later
/// `var + (sample - var) / 16` (rounded toward the sample on a rise, toward var on a fall: never
/// understates).
pub fn vol_update_x100(var_x100: u32, has_data: bool, sample_x100: u64) -> u32 {
    let sample = if sample_x100 > u32::MAX as u64 { u32::MAX } else { sample_x100 as u32 };
    if !has_data {
        return if sample > VOL_VAR_SEED_X100 { sample } else { VOL_VAR_SEED_X100 };
    }
    if sample >= var_x100 {
        let up = (sample - var_x100) as u64;
        let step = up.div_ceil(1u64 << VOL_EWMA_SHIFT);
        let v = var_x100 as u64 + step;
        if v > u32::MAX as u64 { u32::MAX } else { v as u32 }
    } else {
        var_x100 - (var_x100 - sample) / (1u32 << VOL_EWMA_SHIFT)
    }
}

/// `ceil(sqrt(x))` for u128 (Newton from above; exact). Security review F-8: the first iterate
/// is now `ceil(x / 2) = (x + x / x) / 2` (was `x / 2 + 1`, which equals `x` at `x = 2` and stopped
/// the loop at once: `isqrt_ceil(2)` was 3).
pub fn isqrt_ceil_u128(x: u128) -> u128 {
    if x < 2 {
        return x;
    }
    // floor sqrt by Newton
    let mut r = x;
    let mut y = x / 2 + (x & 1); // ceil(x / 2) < x for x >= 2, and never overflows
    while y < r {
        r = y;
        y = (r + x / r) / 2;
    }
    if r * r == x { r } else { r + 1 }
}

/// σ over the horizon, bps: `ceil(sqrt(var_x100 * h / 100))`.
pub fn sigma_h_bps(var_x100: u32, h_slots: u64) -> u64 {
    let v = (var_x100 as u128) * (h_slots as u128);
    let s = isqrt_ceil_u128(v.div_ceil(100));
    if s > u64::MAX as u128 { u64::MAX } else { s as u64 }
}

/// The volatility leverage ceiling (x100): `floor(1e6 / max(engine IMR, z * σ_H + liq fee))`,
/// saturating at u16. `None` (no data) -> the caller uses LAUNCH (fails closed: no volatility
/// measured, no loosening above launch). Monotone non-increasing in σ.
pub fn l_vol_x100(engine_imr_bps: u64, sigma_h_bps: u64, liq_fee_bps: u64) -> u16 {
    let need = VOL_Z.saturating_mul(sigma_h_bps).saturating_add(liq_fee_bps);
    let den = if need > engine_imr_bps { need } else { engine_imr_bps };
    if den == 0 {
        return u16::MAX;
    }
    let l = 1_000_000u64 / den;
    if l > u16::MAX as u64 { u16::MAX } else { l as u16 }
}

/// The leverage signal with the volatility term: `min(l_signal, L_vol)`; no data -> `launch`.
pub fn l_signal_with_vol(l_signal_x100: u16, vol: Option<u16>, launch_x100: u16) -> u16 {
    let v = vol.unwrap_or(launch_x100);
    if v < l_signal_x100 { v } else { l_signal_x100 }
}

/// The κ table (bps of the depth) by tier: 0.5 / 1 / 1 / 2 (`kappa_depth_bps`).
pub const KAPPA_TABLE_BPS: [u64; 4] = [5_000, 10_000, 10_000, 20_000];
/// The λ_depth table (bps) by tier: 1x / 1x / 2x / 3x (`lambda_depth_bps`).
pub const LAMBDA_DEPTH_TABLE_BPS: [u64; 4] = [10_000, 10_000, 20_000, 30_000];
const _: () = assert!(KAPPA_TABLE_BPS[0] == 5_000 && KAPPA_TABLE_BPS[3] == 20_000);

/// The venue depth the curve reads: a DEX reading as is; a keeper-attested one clamped to the
/// anchor of `attested_max_tier` (`T_m`, so the curve value never exceeds `L_m` -- the same cap
/// `venue_tier` applies to the tier integer; continuous leverage: the cap is the anchor itself,
/// where the curve equals the table); no source: 0.
pub fn venue_depth_capped(effective_depth_e6: u64, depth_source_byte: u8, thresholds_e6: [u64; 3], attested_max_tier_stored: u8) -> u64 {
    match depth_source_of(depth_source_byte) {
        DEPTH_SOURCE_DEX => effective_depth_e6,
        DEPTH_SOURCE_ATTESTED => {
            let m = attested_max_tier_eff(attested_max_tier_stored) as usize;
            if m >= MAX_TIER as usize {
                effective_depth_e6
            } else {
                // m >= 1 (`attested_max_tier_eff`): anchor m is T_m = thresholds_e6[m - 1].
                let cap = thresholds_e6[m - 1];
                if effective_depth_e6 < cap {
                    effective_depth_e6
                } else {
                    cap
                }
            }
        }
        _ => 0,
    }
}

/// The growth dials of one market at a (venue, book) depth pair: the leverage signal
/// `min(curve_L(venue), curve_L(book))` (x100; log-interpolated, equal to the table at each
/// anchor, looser than the step between anchors by design), and κ / λ_depth as the same min of
/// the LAGGING curves (`curve_pos_lag`: continuous, never looser than the step, review M-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmoothDials {
    pub l_signal_x100: u16,
    pub kappa_bps: u32,
    pub lambda_depth_bps: u32,
}

/// `smooth_dials` plus the venue-only leverage curve value (the push writer's fall-only upper
/// bound: `>= l_signal_x100`). Two leading curve positions (venue, book) serve all four values;
/// κ / λ_depth read the LAGGING positions derived from them (`curve_pos_lag`, never looser than
/// the step; extra `log2` only at or past T3).
pub fn smooth_dials_and_venue_l(
    venue_depth_e6: u64,
    book_depth_e6: u64,
    thresholds_e6: [u64; 3],
    l_table_x100: [u16; 4],
) -> (SmoothDials, u16) {
    let lt = [l_table_x100[0] as u64, l_table_x100[1] as u64, l_table_x100[2] as u64, l_table_x100[3] as u64];
    let pv = curve_pos(venue_depth_e6, thresholds_e6);
    let pb = curve_pos(book_depth_e6, thresholds_e6);
    let qv = curve_pos_lag(pv, venue_depth_e6, thresholds_e6);
    let qb = curve_pos_lag(pb, book_depth_e6, thresholds_e6);
    let m2 = |p: CurvePos, q: CurvePos, t: [u64; 4]| core::cmp::min(curve_value(p, t), curve_value(q, t));
    let venue_l = curve_value(pv, lt);
    (
        SmoothDials {
            l_signal_x100: m2(pv, pb, lt) as u16,
            kappa_bps: m2(qv, qb, KAPPA_TABLE_BPS) as u32,
            lambda_depth_bps: m2(qv, qb, LAMBDA_DEPTH_TABLE_BPS) as u32,
        },
        venue_l as u16,
    )
}

pub fn smooth_dials(venue_depth_e6: u64, book_depth_e6: u64, thresholds_e6: [u64; 3], l_table_x100: [u16; 4]) -> SmoothDials {
    smooth_dials_and_venue_l(venue_depth_e6, book_depth_e6, thresholds_e6, l_table_x100).0
}

/// `N_cap` with explicit (smoothed) dials: `min(n_cap_q(C_m, min(stored λ, λ_depth)), κ·depth/P)`
/// on a clamp-enforced market; growth-1's `n_cap_q(C_m, stored λ)` off it. `n_cap_g8_q` is this at
/// the step dials of a tier.
#[allow(clippy::too_many_arguments)]
pub fn n_cap_g8_q_dials(
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    lambda_depth_bps: u32,
    kappa_bps: u32,
    cap_depth_e6: Option<u64>,
    price_e6: u64,
    pos_scale: u128,
) -> Option<u128> {
    if !clamp {
        return n_cap_q(c_m, stored_lambda_bps, price_e6, pos_scale);
    }
    let lam = if stored_lambda_bps < lambda_depth_bps { stored_lambda_bps } else { lambda_depth_bps };
    let n = n_cap_q(c_m, lam, price_e6, pos_scale)?;
    let d = depth_cap_q_kappa(kappa_bps, cap_depth_e6, price_e6, pos_scale);
    Some(if n < d { n } else { d })
}

/// `depth_cap_q` with an explicit κ (bps).
pub fn depth_cap_q_kappa(kappa_bps: u32, cap_depth_e6: Option<u64>, price_e6: u64, pos_scale: u128) -> u128 {
    match cap_depth_e6 {
        None => u128::MAX,
        Some(d) => n_cap_q((d as u128) * (kappa_bps as u128) / BPS, DEFAULT_LAMBDA_BPS, price_e6, pos_scale).unwrap_or(0),
    }
}

/// `λ_depth` (bps): 1x at tiers 0 and 1, 2x at tier 2, 3x at tier 3 (protocol constants).
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

/// Interim κ cap (S-3 spot push, `v22-leverage-sims-2026-10-25.md`): `κ_eff = min(κ_tier,
/// η · 101.5 · f)` with `η = 1/2` (half the attacker's no-leak break-even) and `f` the oracle spot
/// pool's fee as a fraction. In bps of the depth: `floor(fee_bps · 1015 / 20)`
/// (`KAPPA_CAP_NUM / KAPPA_CAP_DEN`): 5 bps -> 253, 25 -> 1268, 30 -> 1522, 100 -> 5075.
pub const KAPPA_CAP_NUM: u32 = 1_015;
pub const KAPPA_CAP_DEN: u32 = 20;
/// The pool fee (bps) assumed when the fee is not known. FAIL SAFE: the smallest fee of the S-3
/// grid (0.05%), so the cap is the TIGHTEST plausible one (253 bps = 0.0253x of depth). Neither
/// PumpSwap (fees live in its GlobalConfig, not the `Pool`) nor Raydium CPMM (fee lives in the
/// `AmmConfig` the pool points at, not the `PoolState`) carries the fee in the pinned pool account,
/// and the pin record has no fee field, so today every market reads this value until the fee is
/// plumbed (`growth_g8_ctx_view`: `pool_fee_bps`). It can only tighten (see `kappa_eff_bps`).
pub const KAPPA_CAP_FALLBACK_FEE_BPS: u16 = 5;
// The S-3 reference values (fee 5 / 25 / 30 / 100 bps).
const _: () = assert!(
    (5u32 * KAPPA_CAP_NUM / KAPPA_CAP_DEN) == 253
        && (25u32 * KAPPA_CAP_NUM / KAPPA_CAP_DEN) == 1_268
        && (30u32 * KAPPA_CAP_NUM / KAPPA_CAP_DEN) == 1_522
        && (100u32 * KAPPA_CAP_NUM / KAPPA_CAP_DEN) == 5_075
);

/// The κ cap (bps of the depth) of a pool with fee `fee_bps`: `floor(fee_bps · 1015 / 20)`
/// (rounds DOWN: tighter). `u16 · 1015 < 2^26`, never overflows. A fee of 0 gives 0 (closed).
#[cfg_attr(kani, kani::ensures(|r: &u32| spec::kappa_cap_bps(fee_bps, *r)))]
pub fn kappa_cap_bps(fee_bps: u16) -> u32 {
    (fee_bps as u32) * KAPPA_CAP_NUM / KAPPA_CAP_DEN
}

/// `κ_eff = min(κ_tier, kappa_cap_bps(fee))`; an unknown fee (`None`) reads
/// `KAPPA_CAP_FALLBACK_FEE_BPS`. Tighten-only: never above `kappa_tier_bps` (so never above
/// HEAD's κ and never above the tier table), whatever the fee.
#[cfg_attr(kani, kani::ensures(|r: &u32| spec::kappa_eff_bps(kappa_tier_bps, fee_bps, *r)))]
pub fn kappa_eff_bps(kappa_tier_bps: u32, fee_bps: Option<u16>) -> u32 {
    let cap = kappa_cap_bps(match fee_bps {
        Some(f) => f,
        None => KAPPA_CAP_FALLBACK_FEE_BPS,
    });
    if kappa_tier_bps < cap {
        kappa_tier_bps
    } else {
        cap
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

/// The depth capacity notional `floor(κ_depth · depth / 1e4)` (collateral atoms) of the cap
/// depth (`cap_depth_e6`); `None` = no depth cap (never had a fresh depth). Never overflows
/// (`u64 · 2e4 < 2^79`). `Some(0)` stays `Some(0)` (closed to opens).
pub fn depth_notional_cap_e6(tier: u8, cap_depth_e6: Option<u64>) -> Option<u128> {
    cap_depth_e6.map(|d| (d as u128) * (kappa_depth_bps(tier) as u128) / BPS)
}

/// The depth cap on `N_cap` in engine Q: `floor(depth_notional * POS_SCALE / price)` (rounds
/// DOWN, so `<= κ·depth/P`, I-D4), `u128::MAX` only when there is no cap depth (never had a
/// fresh one), and 0 (fail closed) on a zero price.
pub fn depth_cap_q(tier: u8, cap_depth_e6: Option<u64>, price_e6: u64, pos_scale: u128) -> u128 {
    depth_cap_q_kappa(kappa_depth_bps(tier), cap_depth_e6, price_e6, pos_scale)
}

/// G8 `N_cap` (every reader: the post-fill gate, the TradeCpi open-room clip, the matcher ext
/// v3 caps, the rent `N_cap` snapshot). Off a clamp-enforced market: EXACTLY growth-1's
/// `n_cap_q(C_m, stored λ)` (depth is stored but never read there). On one:
/// `min(n_cap_q(C_m, λ_eff), depth cap)` with the cap depth of `cap_depth_e6` (fresh, or sticky
/// once `DEPTH_EVER`). `None` (refuse crowd growth) exactly where `n_cap_q` is.
pub fn n_cap_g8_q(
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    tier: u8,
    cap_depth_e6: Option<u64>,
    price_e6: u64,
    pos_scale: u128,
) -> Option<u128> {
    n_cap_g8_q_dials(
        clamp,
        c_m,
        stored_lambda_bps,
        lambda_depth_bps(tier),
        kappa_depth_bps(tier),
        cap_depth_e6,
        price_e6,
        pos_scale,
    )
}

/// G8 ext-v3 `(inventory_cap_q, liquidity_notional_e6)`. Off a clamp-enforced market, or with
/// no cap depth: `growth_matcher_caps` at the lambda `n_cap_g8_q` uses (byte-identical off the
/// clamp). With a cap depth (fresh or sticky): the cap is `min(N_cap(λ_eff), depth cap, engine
/// limit)` and the liquidity is `DEPTH_MULT` times the SMALLER capacity notional, so the
/// matcher's impact stays finite at the cap and `N_cap` stays the one binding number.
#[allow(clippy::too_many_arguments)]
pub fn growth_matcher_caps_g8(
    hlock_active: bool,
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    tier: u8,
    cap_depth_e6: Option<u64>,
    price_e6: u64,
    pos_scale: u128,
    max_position_abs_q: u128,
) -> (u128, u128) {
    growth_matcher_caps_g8_dials(
        hlock_active,
        clamp,
        c_m,
        stored_lambda_bps,
        lambda_depth_bps(tier),
        kappa_depth_bps(tier),
        cap_depth_e6,
        price_e6,
        pos_scale,
        max_position_abs_q,
    )
}

/// `growth_matcher_caps_g8` with explicit (round 3: smoothed) λ_depth / κ dials.
#[allow(clippy::too_many_arguments)]
pub fn growth_matcher_caps_g8_dials(
    hlock_active: bool,
    clamp: bool,
    c_m: u128,
    stored_lambda_bps: u32,
    lambda_depth_bps: u32,
    kappa_bps: u32,
    cap_depth_e6: Option<u64>,
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
    let lam = if stored_lambda_bps < lambda_depth_bps { stored_lambda_bps } else { lambda_depth_bps };
    let nd = match cap_depth_e6.map(|d| (d as u128) * (kappa_bps as u128) / BPS) {
        None => {
            return growth_matcher_caps(hlock_active, c_m, lam, price_e6, pos_scale, max_position_abs_q)
        }
        Some(nd) => nd,
    };
    if hlock_active {
        return (0, 0);
    }
    let cap = n_cap_g8_q_dials(true, c_m, stored_lambda_bps, lambda_depth_bps, kappa_bps, cap_depth_e6, price_e6, pos_scale)
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

// ── v2.2 growth overnight §1.2 + R2.1 amendment (13:10): ceiling target, force-down, ratchet ──

/// The live ceiling target (x100), R2.1 amendment (13:10 coordinator ruling) + round 3 item 3:
/// ```text
/// graduation on, stress < h-lock: min(L_tier, max(L_launch, min(L_signal, stress_cap)))
/// otherwise:                      min(L_launch, L_tier)
/// ```
/// `l_table_tier_x100` is the SIGNAL leverage (continuous leverage, 2026-10-19: every program
/// caller passes the log-interpolated depth curve `smooth_dials(..).l_signal_x100`, capped by
/// the volatility term; it equals `L_table(tier)` at each anchor and lies between the two
/// neighbouring table values elsewhere, so I-D2 below now reads "never above `L_tier` or
/// `max(launch, signal)`") and `stress_cap_x100` the
/// graded stress cap (`stress_cap_x100`: none / one tier down for a draw / two for real ADL,
/// stepped at the discrete tier); the h-lock is launch.
/// with `tier = min(venue_tier, book_tier)` (the book tier IS the capital term now: absolute LP
/// book depth vs the per-market thresholds) and `l_table_tier_x100 = L_table(tier)`
/// (`tier_leverage`). Round 1's doublings term `L_launch + floor(log2(C_m / C_launch))·1x` is
/// gone from the target (it made 10x need 32x the launch capital and 20x ~32,768x); round 3
/// item 6 retired `c_launch` (its bytes carry the volatility EWMA and the rent stamp). Never above `L_tier` or
/// `max(launch, L_table(tier))` (I-D2), never below the launch ceiling, and never above the
/// stress cap unless that is below launch.
pub fn target_ceiling_x100(
    graduation: bool,
    stress: u8,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_table_tier_x100: u16,
    stress_cap_x100: u16,
) -> u16 {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    if !graduation || stress >= STRESS_HLOCK {
        return launch;
    }
    let sig = if l_table_tier_x100 < stress_cap_x100 {
        l_table_tier_x100
    } else {
        stress_cap_x100
    };
    let up = if sig > launch { sig } else { launch };
    if up < l_tier_x100 {
        up
    } else {
        l_tier_x100
    }
}

/// The ceiling the gate applies (x100). Off a clamp-enforced market: `min(L_launch, L_tier)`,
/// exactly growth-1 (off-band identity). On one: `min(stored, live target)` -- leverage goes UP
/// gradually (the stored ceiling climbs only through the ratchet, +1x per epoch) and DOWN AT
/// ONCE: a depth collapse, stale / zero / missing depth (tier 0 -> launch), draw or real-ADL
/// stress (graded target), the h-lock (launch) or a lower upper-authority tier table all bind in
/// the same slot, before any writer runs (security review F-1, fix A; round 3's 1x-per-call
/// descent is removed).
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
    if stored_ceil_x100 <= target_x100 {
        stored_ceil_x100
    } else {
        target_x100
    }
}

/// The ratchet WRITER at a site with the bound vault LP's `C_m` in hand (clamp-enforced markets
/// only; the target's book tier was built from it). Returns `(ceil_x100, ceil_slot)`: ratchet
/// toward `target_ceiling_x100` (falls to it at once; rises <= +1x per epoch). Round 3 item 6: the retired `c_launch` snapshot (R2.1 stopped reading it; its
/// "no climb in the snapshot call" hold is redundant with the I-1 / bind stamp `ceil_slot = now`,
/// which already makes the first climb wait a full epoch) is gone, and its bytes 0..8 carry the
/// volatility EWMA and the rent stamp.
#[allow(clippy::too_many_arguments)]
pub fn graduation_ratchet(
    prev_ceil_x100: u16,
    prev_slot: u64,
    graduation: bool,
    stress: u8,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_table_tier_x100: u16,
    stress_cap_x100: u16,
    now_slot: u64,
) -> (u16, u64) {
    let launch = if l_launch_x100 < l_tier_x100 {
        l_launch_x100
    } else {
        l_tier_x100
    };
    let target = target_ceiling_x100(
        graduation,
        stress,
        l_launch_x100,
        l_tier_x100,
        l_table_tier_x100,
        stress_cap_x100,
    );
    ratchet_ceiling_x100(prev_ceil_x100, prev_slot, target, launch, stress, now_slot)
}

/// The FALL-ONLY ratchet (PushAuthMark: the depth changed but no `C_m` is in hand). The caller
/// passes the VENUE tier's graduation, `L_table(venue_tier)` and the stress cap at the venue
/// tier: the venue tier bounds `min(venue, book)` from above, so this upper bound is never below
/// the real target and the stored ceiling only ever falls here, stamped `now`, to that bound at
/// once (security review F-1 fix A); it never rises without the LP's equity.
#[allow(clippy::too_many_arguments)]
pub fn graduation_fall_only(
    prev_ceil_x100: u16,
    prev_slot: u64,
    graduation: bool,
    stress: u8,
    l_launch_x100: u16,
    l_tier_x100: u16,
    l_table_tier_x100: u16,
    stress_cap_x100: u16,
    now_slot: u64,
) -> (u16, u64) {
    let upper = target_ceiling_x100(
        graduation,
        stress,
        l_launch_x100,
        l_tier_x100,
        l_table_tier_x100,
        stress_cap_x100,
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

/// Security review R2-L1: the rent `N_cap` snapshot (`AssetGrowthV19::rent_n_cap_q`, where 0
/// means "not measured", rent 0). When the DEPTH cap is what makes N_cap 0 (a real 0 reading or
/// a fully decayed sticky cap on a clamp-enforced market), the snapshot is 1 so `u = OI / 1 >= 1`
/// charges the maximum rent (u = OI / 0 = infinity), never 0. Otherwise `min(n_cap, u64::MAX)`
/// exactly as before (a C_m of 0 still reads "not measured").
pub fn rent_snapshot_n_cap_q(n_cap_q: u128, depth_cap_zero: bool) -> u64 {
    if n_cap_q == 0 && depth_cap_zero {
        return 1;
    }
    u64::try_from(n_cap_q).unwrap_or(u64::MAX)
}

/// Round 3 item 7 (design GAP-10): the rent `N_cap` snapshot may FALL (rent rises on open
/// positions) at most 2x per this many slots since its last applied fall.
pub const RENT_SNAPSHOT_FALL_SLOTS: u64 = 900;

/// Round 3 item 7 (GAP-10, "never cliff-edge on open positions"): the snapshot a writer stores.
/// `stamp64` = `slot / 64 + 1` of the last applied FALL (bytes 4..8; 0 = never -- the `+ 1` keeps a
/// fall in slots 0..63 distinguishable from "never").
/// * a rise (rent falls) or a first measurement (`prev == 0`): `new` at once, stamp kept;
/// * a fall: `max(new, prev >> k)` with `k` = whole 900-slot windows since the latest slot the
///   stamp can stand for (`(stamp - 1) * 64 + 63`; a never-stamped snapshot gets one halving at once),
///   stamped `now`; `k == 0` holds `prev`.
///
/// So rent on open positions climbs at most 2x per 900 slots (~6 min) toward the new rate --
/// a real 0 depth (snapshot 1 = maximum rent, R2-L1) is still reached, in about log2(N_cap / OI)
/// windows. The capacity GATE still uses the instant `N_cap` (opens are refused at once).
pub fn rent_snapshot_smooth(prev: u64, stamp64: u32, new: u64, now_slot: u64) -> (u64, u32) {
    if prev == 0 || new >= prev {
        return (new, stamp64);
    }
    let k = if stamp64 == 0 {
        1
    } else {
        let last = ((stamp64 - 1) as u64).saturating_mul(DEPTH_RISE_STAMP_SLOTS).saturating_add(DEPTH_RISE_STAMP_SLOTS - 1);
        now_slot.saturating_sub(last) / RENT_SNAPSHOT_FALL_SLOTS
    };
    if k == 0 {
        return (prev, stamp64);
    }
    let floor = if k >= 64 { 0 } else { prev >> k };
    (if new > floor { new } else { floor }, rent_stamp64_of(now_slot))
}

/// The rent stamp of `slot`: `slot / 64 + 1`, saturating (never 0).
pub fn rent_stamp64_of(slot: u64) -> u32 {
    depth_rise_stamp(slot).saturating_add(1)
}

/// Round 3 item 7 (design GAP-13c): the bind-time guard -- on a clamp-enforced market with a
/// measured depth, one minimum band leg must fit in the tier-0 depth capacity:
/// `band_min_leg_notional <= floor(κ0 * cap_depth)`. `None` (never measured) passes.
///
/// Interim κ cap: this guard deliberately keeps the UNCAPPED tier-0 κ. Using `kappa_eff_bps` here
/// would TIGHTEN it (a smaller RHS refuses more binds, at a 5 bps fallback fee 0.0253x instead of
/// 0.5x), a new bind-time liveness refusal and not an N_cap bound. The N_cap readers already apply
/// the cap (an N_cap below one band leg stays closed to opens there). Switching it is a human
/// call.
pub fn band_min_leg_fits_depth(band_min_leg_notional: u64, cap_depth_e6: Option<u64>) -> bool {
    match cap_depth_e6 {
        None => true,
        Some(d) => (band_min_leg_notional as u128) <= (d as u128) * (KAPPA_TABLE_BPS[0] as u128) / BPS,
    }
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

    /// `r == floor(fee · 1015 / 20)`.
    pub fn kappa_cap_bps(fee: u16, r: u32) -> bool {
        mul_div_floor(fee as u128, super::KAPPA_CAP_NUM as u128, super::KAPPA_CAP_DEN as u128, Some(r as u128))
    }

    /// `r == min(κ_tier, cap(fee or the fallback fee))`; in particular `r <= κ_tier` (tighten-only).
    pub fn kappa_eff_bps(tier: u32, fee: Option<u16>, r: u32) -> bool {
        let f = match fee {
            Some(f) => f,
            None => super::KAPPA_CAP_FALLBACK_FEE_BPS,
        };
        let cap = (f as u32) * super::KAPPA_CAP_NUM / super::KAPPA_CAP_DEN;
        r <= tier && r == if tier < cap { tier } else { cap }
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
    // ── interim κ cap: κ_eff = min(κ_tier, floor(fee_bps · 1015 / 20)) ──────────────────────────

    #[test]
    fn kappa_cap_values_at_fee_bps() {
        assert_eq!(kappa_cap_bps(5), 253);
        assert_eq!(kappa_cap_bps(25), 1_268);
        assert_eq!(kappa_cap_bps(30), 1_522);
        assert_eq!(kappa_cap_bps(100), 5_075);
        assert_eq!(kappa_cap_bps(0), 0);
        // no overflow at the u16 extreme: 65535 * 1015 / 20
        assert_eq!(kappa_cap_bps(u16::MAX), 3_325_901);
    }

    #[test]
    fn kappa_eff_is_min_with_each_tier() {
        // fee 25 bps (cap 1268): below every tier value -> the cap binds at all four tiers
        for t in 0..4u8 {
            assert_eq!(kappa_eff_bps(kappa_depth_bps(t), Some(25)), 1_268);
        }
        // fee 100 bps (cap 5075): below tier 0 (5000)? no, 5075 > 5000 -> tier 0 binds, others the cap
        assert_eq!(kappa_eff_bps(kappa_depth_bps(0), Some(100)), 5_000);
        for t in 1..4u8 {
            assert_eq!(kappa_eff_bps(kappa_depth_bps(t), Some(100)), 5_075);
        }
        // a large fee never lifts κ above the tier table
        for t in 0..4u8 {
            assert_eq!(kappa_eff_bps(kappa_depth_bps(t), Some(1_000)), kappa_depth_bps(t));
            assert_eq!(kappa_eff_bps(kappa_depth_bps(t), Some(u16::MAX)), kappa_depth_bps(t));
        }
        // the same on the smoothed (curve) dial: any value between the table anchors
        assert_eq!(kappa_eff_bps(6_695, Some(30)), 1_522);
        assert_eq!(kappa_eff_bps(1_000, Some(30)), 1_000);
    }

    #[test]
    fn kappa_eff_tighten_only_all_tiers_and_fees() {
        for t in 0..4u8 {
            let k = kappa_depth_bps(t);
            for fee in (0..=u16::MAX).step_by(7).chain([1, 5, 25, 30, 100, 197, 198, 199, 200, u16::MAX]) {
                let e = kappa_eff_bps(k, Some(fee));
                assert!(e <= k, "tier {t} fee {fee}: {e} > {k}");
                assert!(e <= kappa_cap_bps(fee));
                assert_eq!(e, core::cmp::min(k, kappa_cap_bps(fee)));
            }
            assert!(kappa_eff_bps(k, None) <= k);
        }
        // monotone in the fee (a lower fee never gives a looser κ)
        for fee in 0..2_000u16 {
            assert!(kappa_cap_bps(fee) <= kappa_cap_bps(fee + 1));
        }
    }

    #[test]
    fn kappa_eff_fee_unknown_fails_safe() {
        // unknown fee reads the smallest S-3 grid fee (5 bps -> 253): the tightest plausible cap,
        // and never above the fee-known value at any real pool fee >= 5 bps.
        assert_eq!(KAPPA_CAP_FALLBACK_FEE_BPS, 5);
        for t in 0..4u8 {
            assert_eq!(kappa_eff_bps(kappa_depth_bps(t), None), 253);
            for fee in [5u16, 25, 30, 100] {
                assert!(kappa_eff_bps(kappa_depth_bps(t), None) <= kappa_eff_bps(kappa_depth_bps(t), Some(fee)));
            }
        }
    }

    #[test]
    fn kappa_cap_tightens_n_cap_never_loosens() {
        let ps = 1_000_000u128;
        let (price, depth) = (1_000_000u64, Some(10_000_000_000u64));
        for t in 0..4u8 {
            let base = n_cap_g8_q(true, 1_000_000_000_000u128, 30_000, t, depth, price, ps).unwrap();
            for fee in [None, Some(5u16), Some(25), Some(30), Some(100)] {
                let k = kappa_eff_bps(kappa_depth_bps(t), fee);
                let n = n_cap_g8_q_dials(true, 1_000_000_000_000u128, 30_000, lambda_depth_bps(t), k, depth, price, ps).unwrap();
                assert!(n <= base, "tier {t} fee {fee:?}");
            }
            // fee 25 bps: depth cap = 0.1268 * depth / price (floor), the κ term binds here
            let n25 = n_cap_g8_q_dials(true, 1_000_000_000_000u128, 30_000, lambda_depth_bps(t), kappa_eff_bps(kappa_depth_bps(t), Some(25)), depth, price, ps).unwrap();
            assert_eq!(n25, depth_cap_q_kappa(1_268, depth, price, ps));
            // the clip's caps (ext-v3) take the same dial
            let k = kappa_eff_bps(kappa_depth_bps(t), Some(25));
            let (cap_capped, _) = growth_matcher_caps_g8_dials(false, true, 1_000_000_000_000u128, 30_000, lambda_depth_bps(t), k, depth, price, ps, u128::MAX);
            let (cap_base, _) = growth_matcher_caps_g8(false, true, 1_000_000_000_000u128, 30_000, t, depth, price, ps, u128::MAX);
            assert!(cap_capped <= cap_base);
        }
    }

    use super::*;

    const PS: u128 = 1_000_000;

    /// Round 3 item 7 (GAP-10, GAP-13c).
    #[test]
    fn r3_item7_rent_snapshot_and_min_leg() {
        // rises at once; a first measurement at once
        assert_eq!(rent_snapshot_smooth(100, 0, 500, 10), (500, 0));
        assert_eq!(rent_snapshot_smooth(0, 0, 1, 10), (1, 0));
        // a never-stamped fall: one halving at once, stamped slot/64 + 1
        assert_eq!(rent_snapshot_smooth(1_000, 0, 1, 6_400), (500, 101));
        // a fall in slots 0..63 is stamped 1, not "never": the next call holds
        assert_eq!(rent_snapshot_smooth(1_000, 0, 1, 5), (500, 1));
        assert_eq!(rent_snapshot_smooth(500, 1, 1, 6), (500, 1));
        // inside 900 slots of the last fall (stamp 101 = slots 6,400..6,463): held
        assert_eq!(rent_snapshot_smooth(500, 101, 1, 6_463 + 899), (500, 101));
        // one window later: one more halving; three windows: an eighth
        assert_eq!(rent_snapshot_smooth(500, 101, 1, 6_463 + 900), (250, rent_stamp64_of(6_463 + 900)));
        assert_eq!(rent_snapshot_smooth(800, 101, 1, 6_463 + 2_700), (100, rent_stamp64_of(6_463 + 2_700)));
        // never below the new value
        assert_eq!(rent_snapshot_smooth(800, 101, 300, 6_463 + 2_700).0, 300);
        // k >= 64: straight to the new value
        assert_eq!(rent_snapshot_smooth(u64::MAX, 1, 1, 64 * 900 + 200).0, 1);
        // min leg guard: 10 tokens fit in 0.5 x $40 = $20; not in 0.5 x $10
        assert!(band_min_leg_fits_depth(10_000_000, Some(40_000_000)));
        assert!(!band_min_leg_fits_depth(10_000_000, Some(10_000_000)));
        assert!(band_min_leg_fits_depth(10_000_000, None), "never measured: passes");
    }

    /// Round 3 item 6 (GAP-6): the volatility term.
    #[test]
    fn r3_item6_vol_term() {
        assert_eq!(vol_sample_x100(0, 5, 1), None, "no previous mark");
        assert_eq!(vol_sample_x100(5, 6, 0), None, "same slot");
        // 1% over 10 slots: 100^2 * 100 / 10 = 100,000
        assert_eq!(vol_sample_x100(1_000_000, 1_010_000, 10), Some(100_000));
        // capped at 100%
        assert_eq!(vol_sample_x100(1_000_000, 9_000_000, 1), Some(10_000u64 * 10_000 * 100));
        // seed and EWMA
        assert_eq!(vol_update_x100(0, false, 0), VOL_VAR_SEED_X100);
        assert_eq!(vol_update_x100(0, false, 99_999), 99_999);
        assert_eq!(vol_update_x100(1_600, true, 0), 1_500);
        assert_eq!(vol_update_x100(0, true, 17), 2, "ceil toward a rise");
        // sigma over 1,200 slots of the seed: sqrt(2,500 * 1,200 / 100) = sqrt(30,000) -> 174
        assert_eq!(sigma_h_bps(VOL_VAR_SEED_X100, 1_200), 174);
        assert_eq!(isqrt_ceil_u128(u128::MAX), 1u128 << 64);
        assert_eq!(isqrt_ceil_u128(16), 4);
        assert_eq!(isqrt_ceil_u128(17), 5);
        assert_eq!(isqrt_ceil_u128(2), 2, "F-8: was 3");
        for x in 0u128..200_000 {
            let r = isqrt_ceil_u128(x);
            assert!(r * r >= x && (r == 0 || (r - 1) * (r - 1) < x), "ceil sqrt({x}) = {r}");
        }
        for k in [u64::MAX as u128, (1u128 << 64) + 1, u128::MAX - 1, (1u128 << 127) + 12_345] {
            let r = isqrt_ceil_u128(k);
            assert!(r.checked_mul(r).is_none_or(|p| p >= k) && (r - 1) * (r - 1) < k, "ceil sqrt({k}) = {r}");
        }
        // L_vol: 1e6 / max(IMR 500, 3 * 174 + 50 = 572) = 1,748 (17.48x)
        assert_eq!(l_vol_x100(500, 174, 50), 1_748);
        assert_eq!(l_vol_x100(500, 0, 50), 2_000, "calm: the engine IMR binds (20x)");
        assert_eq!(l_vol_x100(500, 1_000, 50), 327, "storm: 1e6 / 3,050 = 3.27x");
        assert_eq!(l_signal_with_vol(2_000, None, 500), 500, "no data: launch");
        assert_eq!(l_signal_with_vol(2_000, Some(1_748), 500), 1_748);
        assert!(growth_flags_ok(0) && growth_flags_ok(1) && growth_flags_ok(3));
        assert!(!growth_flags_ok(2) && !growth_flags_ok(4));
    }

    /// Continuous leverage (2026-10-19): the log-interpolated depth curve.
    #[test]
    fn contlev_curve_unit() {
        // log2 Q.16: exact integer part, exact at powers of two, None at 0
        assert_eq!(log2_q16(0), None);
        assert_eq!(log2_q16(1), Some(0));
        assert_eq!(log2_q16(2), Some(1 << 16));
        assert_eq!(log2_q16(3), Some(103_872), "floor(log2(3) * 2^16) = 103,872");
        assert_eq!(log2_q16(1_024), Some(10 << 16));
        assert_eq!(log2_q16(u64::MAX), Some((63 << 16) | 0xFFFF));
        let th = [25_000u64, 100_000, 500_000];
        let l = [500u64, 500, 1_000, 2_000];
        // below anchor 0 (T1 / 4) and past T3: the end values
        assert_eq!(curve_u64(0, th, l), 500);
        assert_eq!(curve_u64(6_249, th, l), 500);
        assert_eq!(curve_u64(u64::MAX, th, l), 2_000);
        // AT each anchor: exactly the table
        assert_eq!(curve_u64(25_000, th, l), 500);
        assert_eq!(curve_u64(100_000, th, l), 1_000);
        assert_eq!(curve_u64(500_000, th, l), 2_000);
        // between anchors: log-interpolated (the step table reads 5x / 5x / 10x here)
        assert_eq!(curve_u64(50_000, th, l), 750, "half-way in log between $25k and $100k: 7.5x");
        assert_eq!(curve_u64(99_999, th, l), 999);
        assert_eq!(curve_u64(110_000, th, l), 1_059);
        assert_eq!(curve_u64(200_000, th, l), 1_430);
        // κ rises 0.5 -> 1 between T1 / 4 and T1 (no doubling at T1)
        assert_eq!(curve_u64(6_250, th, KAPPA_TABLE_BPS), 5_000);
        assert_eq!(curve_u64(10_000, th, KAPPA_TABLE_BPS), 6_695);
        assert_eq!(curve_u64(24_999, th, KAPPA_TABLE_BPS), 9_999);
        assert_eq!(curve_u64(25_000, th, KAPPA_TABLE_BPS), 10_000);
        assert_eq!(curve_u64(50_000, th, LAMBDA_DEPTH_TABLE_BPS), 15_000);
        // ...but the PROGRAM's κ / λ_depth LAG (security review M-1): t[0] up to T1, the step
        // value of the segment below at each anchor, the next value at the next anchor, never
        // above the step; the top segment is [T3, 4·T3)
        assert_eq!(curve_lag_u64(24_999, th, KAPPA_TABLE_BPS), 5_000);
        assert_eq!(curve_lag_u64(25_000, th, KAPPA_TABLE_BPS), 5_000);
        assert_eq!(curve_lag_u64(50_000, th, KAPPA_TABLE_BPS), 7_500);
        assert_eq!(curve_lag_u64(100_000, th, KAPPA_TABLE_BPS), 10_000);
        assert_eq!(curve_lag_u64(500_000, th, KAPPA_TABLE_BPS), 10_000);
        assert_eq!(curve_lag_u64(1_000_000, th, KAPPA_TABLE_BPS), 15_000);
        assert_eq!(curve_lag_u64(2_000_000, th, KAPPA_TABLE_BPS), 20_000);
        assert_eq!(curve_lag_u64(50_000, th, LAMBDA_DEPTH_TABLE_BPS), 10_000);
        assert_eq!(curve_lag_u64(200_000, th, LAMBDA_DEPTH_TABLE_BPS), 14_306);
        assert_eq!(curve_lag_u64(u64::MAX, th, LAMBDA_DEPTH_TABLE_BPS), 30_000);
        // a saturating 4·T3 (T3 > u64::MAX / 4): flat at t[2] past T3, fail closed
        assert_eq!(curve_lag_u64(u64::MAX - 1, [25_000, 100_000, u64::MAX / 2], KAPPA_TABLE_BPS), 10_000);
        // fail closed: a saturated next anchor is flat at the lower value (never met, D-L1)
        assert_eq!(curve_u64(u64::MAX - 1, [25_000, u64::MAX, u64::MAX], l), 500);
        assert_eq!(curve_u64(u64::MAX, [25_000, u64::MAX, u64::MAX], l), 500);
        assert_eq!(curve_u64(u64::MAX, [u64::MAX; 3], l), 500);
        // a non-increasing pair of thresholds: flat (never produced by `tier_config_ok`)
        assert_eq!(curve_u64(150, [100, 100, 1_000], [1, 2, 3, 4]), 3);
        assert_eq!(curve_value(CURVE_POS_FAIL, l), 500, "arithmetic failure reads t[0]");
        // venue cap: attested (default max tier 1) clamps to the anchor T1 -> exactly L1
        assert_eq!(venue_depth_capped(600_000, DEPTH_SOURCE_ATTESTED, th, 0), 25_000);
        assert_eq!(venue_depth_capped(600_000, DEPTH_SOURCE_ATTESTED, th, 2), 100_000);
        assert_eq!(venue_depth_capped(20_000, DEPTH_SOURCE_ATTESTED, th, 1), 20_000);
        assert_eq!(venue_depth_capped(600_000, DEPTH_SOURCE_DEX, th, 0), 600_000);
        assert_eq!(venue_depth_capped(600_000, DEPTH_SOURCE_ATTESTED, th, 3), 600_000);
        assert_eq!(venue_depth_capped(600_000, DEPTH_SOURCE_NONE, th, 3), 0);
        // the dials: min of the two curves; the venue-only value for the fall-only writer
        let (d, vl) = smooth_dials_and_venue_l(110_000, 600_000, th, [500, 500, 1_000, 2_000]);
        assert_eq!(d, SmoothDials { l_signal_x100: 1_059, kappa_bps: 10_000, lambda_depth_bps: 10_592 });
        assert_eq!(vl, 1_059);
        let (d, vl) = smooth_dials_and_venue_l(600_000, 50_000, th, [500, 500, 1_000, 2_000]);
        assert_eq!(d, SmoothDials { l_signal_x100: 750, kappa_bps: 7_500, lambda_depth_bps: 10_000 }, "book binds");
        assert_eq!(vl, 2_000, "venue alone");
        // the step functions are the dials at a tier
        for t in 0..=3u8 {
            assert_eq!(n_cap_g8_q(true, 1_000_000, 30_000, t, Some(777), 1_000_000, PS), n_cap_g8_q_dials(true, 1_000_000, 30_000, lambda_depth_bps(t), kappa_depth_bps(t), Some(777), 1_000_000, PS));
        }
    }

    /// Round 3 item 1 (GAP-8): alpha <= 50% on every market until F3 is proven.
    #[test]
    fn r3_gap8_alpha_cap_truth_table() {
        for band in [false, true] {
            assert_eq!(alloc_alpha_max_bps_for(false, band), 5_000);
        }
        assert_eq!(alloc_alpha_max_bps_for(true, false), 5_000);
        assert_eq!(alloc_alpha_max_bps_for(true, true), ALLOC_ALPHA_MAX_BAND_BPS);
        assert_eq!(alloc_alpha_max_bps(true), 5_000, "F3 not proven in this round");
        assert_eq!(alloc_alpha_in_force_bps(7_000), 5_000);
        assert_eq!(alloc_alpha_in_force_bps(5_000), 5_000);
        assert_eq!(alloc_alpha_in_force_bps(1), 1);
        assert_eq!(alloc_alpha_in_force_bps_for(true, 7_000), 7_000);
    }

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
            ratchet_ceiling_x100(500, 0, 800, 500, STRESS_NONE, 8_999),
            (500, 0)
        );
        assert_eq!(
            ratchet_ceiling_x100(500, 0, 800, 500, STRESS_NONE, 9_000),
            (600, 9_000)
        );
        // F-1 fix A: a fall goes to the target AT ONCE (800 -> 600 in one call); the h-lock goes
        // to the floor (launch); draw / ADL stress falls to its (graded) target at once
        assert_eq!(ratchet_ceiling_x100(800, 0, 600, 500, STRESS_NONE, 1), (600, 1));
        assert_eq!(ratchet_ceiling_x100(800, 0, 900, 500, STRESS_HLOCK, 1), (500, 1));
        assert_eq!(ratchet_ceiling_x100(800, 0, 500, 500, STRESS_ADL, 1), (500, 1));
    }

    #[test]
    fn i1_graduation_reset_postconditions() {
        let r = graduation_reset(550, 1_000, 77);
        assert_eq!(
            r,
            GraduationFields {
                vol_var_x100: 0,
                rent_stamp64: 0,
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

    #[test]
    fn g8_effective_depth_and_tiers() {
        let t1 = DEPTH_TIER1_E6;
        let th = tier_thresholds([0; 3], 6);
        assert_eq!(th, [DEPTH_TIER1_E6, DEPTH_TIER2_E6, DEPTH_TIER3_E6], "0 = defaults");
        // min of the two reads; absent if either is 0
        assert_eq!(effective_depth_e6(5 * t1, 2 * t1, 100, 100), 2 * t1);
        assert_eq!(effective_depth_e6(5 * t1, 0, 100, 100), 0, "first push: prev 0");
        assert_eq!(effective_depth_e6(0, 5 * t1, 100, 100), 0, "35 B push zeroes");
        // freshness: <= 150 slots fresh, 151 stale, a future stamp is stale (fail closed)
        assert_eq!(effective_depth_e6(t1, t1, 100, 250), t1);
        assert_eq!(effective_depth_e6(t1, t1, 100, 251), 0);
        assert_eq!(effective_depth_e6(t1, t1, 101, 100), 0);
        // venue tier: attested capped at attested_max_tier (default 1), DEX uncapped, none 0
        let a = DEPTH_SOURCE_ATTESTED;
        assert_eq!(venue_tier(t1 - 1, a, th, 0), 0);
        assert_eq!(venue_tier(t1, a, th, 0), 1);
        assert_eq!(venue_tier(DEPTH_TIER3_E6, a, th, 0), 1, "I-D3: default attested max 1");
        assert_eq!(venue_tier(DEPTH_TIER3_E6, a, th, 3), 3, "attested_max_tier 3");
        assert_eq!(venue_tier(DEPTH_TIER3_E6, a | DEPTH_EVER, th, 2), 2);
        assert_eq!(venue_tier(DEPTH_TIER3_E6, DEPTH_SOURCE_DEX, th, 0), 3, "DEX: no cap");
        assert_eq!(venue_tier(DEPTH_TIER3_E6, DEPTH_SOURCE_NONE | DEPTH_EVER, th, 3), 0);
        assert_eq!(venue_tier(0, DEPTH_SOURCE_DEX, th, 3), 0, "stale / absent: 0");
        // per-market thresholds
        let th2 = tier_thresholds([5_000, 20_000, 100_000], 6);
        assert_eq!(depth_tier_for(5_000_000_000, th2), 1);
        assert_eq!(depth_tier_for(100_000_000_000, th2), 3);
        // λ / κ per tier stay protocol constants
        assert_eq!((lambda_depth_bps(0), lambda_depth_bps(1), lambda_depth_bps(2), lambda_depth_bps(3)), (10_000, 10_000, 20_000, 30_000));
        assert_eq!((kappa_depth_bps(0), kappa_depth_bps(1), kappa_depth_bps(2), kappa_depth_bps(3)), (5_000, 10_000, 10_000, 20_000));
        assert_eq!(lambda_eff_bps(30_000, 1), 10_000);
        assert_eq!(lambda_eff_bps(5_000, 3), 5_000);
        // book depth: the pinned quote never leaves ±1%, so it is the 1x capacity notional
        assert_eq!(book_depth_e6(100_000_000_000, 30_000), 100_000_000_000);
        assert_eq!(book_depth_e6(100_000_000_000, 5_000), 50_000_000_000);
        assert_eq!(book_tier(100_000_000_000, 10_000, th), 2);
        assert_eq!(book_tier(99_999_999_999, 10_000, th), 1);
        // the general model: max_total >= 2% solves fixed + k·n/(D−n) = 200
        assert_eq!(book_depth_from_pins(1_000, 20, 50, 100), 1_000);
        assert_eq!(book_depth_from_pins(1_000, 20, 50, 300), 1_000, "n* = 4000·180/230 > cap");
        assert_eq!(book_depth_from_pins(1_000, 20, 2_000, 300), 330, "n* = floor(4000·180/2180)");
        assert_eq!(book_depth_from_pins(1_000, 200, 50, 300), 0);
        assert_eq!(combined_tier(3, 1), 1);
        assert_eq!(combined_tier(0, 3), 0);
    }

    #[test]
    fn r2_tier_table_and_bounds() {
        // defaults: min(5x/10x/20x, L_tier), floored at launch, monotone
        assert_eq!(tier_leverage([0; 3], 500, 2_000), [500, 500, 1_000, 2_000]);
        assert_eq!(tier_leverage([0; 3], 500, 500), [500, 500, 500, 500], "old 5x market");
        assert_eq!(tier_leverage([0; 3], 700, 1_000), [700, 700, 1_000, 1_000], "launch above 5x");
        assert_eq!(tier_leverage([600, 900, 1_500], 500, 2_000), [500, 600, 900, 1_500]);
        // corrupt (unvalidated) input still yields a monotone table <= L_tier
        assert_eq!(tier_leverage([3_000, 100, 0], 500, 2_000), [500, 2_000, 2_000, 2_000]);
        assert_eq!(l_table_x100(9, [1, 2, 3, 4]), 4);
        // bounds
        assert!(tier_config_ok([0; 3], [0; 3], 500, 500), "all defaults");
        assert!(tier_config_ok([5_000, 20_000, 100_000], [500, 1_000, 2_000], 500, 2_000));
        assert!(!tier_config_ok([4_999, 20_000, 100_000], [0; 3], 500, 2_000), "T1 floor");
        assert!(!tier_config_ok([5_000, 19_999, 100_000], [0; 3], 500, 2_000), "T2 floor");
        assert!(!tier_config_ok([5_000, 20_000, 99_999], [0; 3], 500, 2_000), "T3 floor");
        assert!(!tier_config_ok([30_000, 30_000, 500_000], [0; 3], 500, 2_000), "T1 < T2");
        assert!(!tier_config_ok([0, 600_000, 0], [0; 3], 500, 2_000), "T2 < T3 with defaults");
        assert!(!tier_config_ok([0; 3], [400, 0, 0], 500, 2_000), "L1 < L_launch");
        assert!(!tier_config_ok([0; 3], [1_000, 900, 2_000], 500, 2_000), "L1 <= L2");
        assert!(!tier_config_ok([0; 3], [0, 0, 2_001], 500, 2_000), "L3 <= L_tier");
        assert!(!tier_config_ok([0; 3], [600, 0, 0], 700, 2_000), "default L2 = 10x ok, L1 600 < launch");
        assert!(tier_config_ok([0; 3], [700, 0, 0], 700, 2_000));
        assert!(attested_max_tier_ok(3) && !attested_max_tier_ok(4));
        assert_eq!((attested_max_tier_eff(0), attested_max_tier_eff(2), attested_max_tier_eff(9)), (1, 2, 3));
    }

    /// Round 3 item 4: the one depth writer at 6-decimal collateral.
    fn up(st: DepthState, src: u8, d: u64, now: u64, seed: u64) -> DepthState {
        depth_push_update(st, src, d, now, seed, USD_ATOMS)
    }

    /// Every reader's depth from a state at `now`.
    fn usable_of(x: DepthState, now: u64) -> Option<u64> {
        usable_depth_e6(
            fresh_depth_e6(x.depth_e6, x.depth_prev_e6, x.depth_slot, x.depth_source, now),
            x.last_good_e6,
            depth_tw_min_atoms(x.tw, USD_ATOMS),
        )
    }

    #[test]
    fn g8_wl2_same_slot_push_is_not_a_second_sample() {
        let t1 = DEPTH_TIER1_E6;
        let a = DEPTH_SOURCE_ATTESTED;
        let st = |d, p, s| DepthState { depth_e6: d, depth_prev_e6: p, depth_slot: s, depth_source: if d == 0 { 0 } else { a }, ..Default::default() };
        let tri = |x: DepthState| (x.depth_e6, x.depth_prev_e6, x.depth_slot);
        // later slot: rotate
        assert_eq!(tri(up(st(t1, 0, 10), a, 2 * t1, 11, u64::MAX)), (2 * t1, t1, 11));
        // first ever push (slot 0 = never): rotate
        assert_eq!(tri(up(st(0, 0, 0), a, t1, 5, u64::MAX)), (t1, 0, 5));
        // same slot: prev kept, depth can only fall
        assert_eq!(tri(up(st(t1, 0, 10), a, 2 * t1, 10, u64::MAX)), (t1, 0, 10), "cannot raise");
        assert_eq!(tri(up(st(2 * t1, 7, 10), a, t1, 10, u64::MAX)), (t1, 7, 10), "can fall");
        assert_eq!(tri(up(st(2 * t1, 7, 10), 0, 0, 10, u64::MAX)), (0, 7, 10), "35 B in the same slot zeroes");
        // a same-slot DEX push that does not lower the value keeps the attested label
        let x = up(st(t1, 7, 10), DEPTH_SOURCE_DEX, 2 * t1, 10, u64::MAX);
        assert_eq!(depth_source_of(x.depth_source), a);
        let x = up(st(2 * t1, 7, 10), DEPTH_SOURCE_DEX, t1, 10, u64::MAX);
        assert_eq!(depth_source_of(x.depth_source), DEPTH_SOURCE_DEX);
        // two same-slot attested pushes from nothing: still one sample -> effective 0
        let s = up(st(0, 0, 0), a, 5 * t1, 20, u64::MAX);
        let s = up(s, a, 5 * t1, 20, u64::MAX);
        assert_eq!(effective_depth_e6(s.depth_e6, s.depth_prev_e6, s.depth_slot, 20), 0, "W-L2: one slot is one sample");
        assert!(!depth_ever(s.depth_source), "no fresh depth yet");
        assert_eq!(s.tw, DepthWindow::default(), "no fresh sample: the window is untouched");
        let s = up(s, a, 5 * t1, 21, u64::MAX);
        assert_eq!(effective_depth_e6(s.depth_e6, s.depth_prev_e6, s.depth_slot, 21), 5 * t1, "two slots: effective");
        // regression stamp: fall only
        assert_eq!(tri(up(st(t1, 3, 10), a, 2 * t1, 9, u64::MAX)), (t1, 3, 10));
        // unknown source stores nothing
        assert_eq!(tri(up(st(t1, 3, 10), 3, 2 * t1, 11, u64::MAX)), (0, t1, 11));
    }

    /// Round 3 item 4: the two-bucket window primitives.
    #[test]
    fn r3_item4_window_primitives() {
        let b = DEPTH_TW_BUCKET_SLOTS;
        let w0 = DepthWindow::default();
        assert_eq!(depth_tw_min_atoms(w0, USD_ATOMS), None, "no history");
        assert!(!depth_tw_full(w0) && depth_tw_window_ok(w0));
        // first sample: prev absent, min = the sample
        let w = depth_tw_update(w0, 100, 5);
        assert_eq!(w, DepthWindow { cur_tokens: 100, prev_tokens: DEPTH_TW_ABSENT, bucket_p1: 1 });
        assert_eq!(depth_tw_min_atoms(w, USD_ATOMS), Some(100 * USD_ATOMS));
        assert!(!depth_tw_full(w));
        // same bucket: min
        let w = depth_tw_update(w, 300, b - 1);
        assert_eq!(w.cur_tokens, 100);
        let w = depth_tw_update(w, 40, b - 1);
        assert_eq!(w.cur_tokens, 40);
        // the next bucket rotates: prev = 40, cur = the new sample
        let w = depth_tw_update(w, 500, b);
        assert_eq!((w.cur_tokens, w.prev_tokens, w.bucket_p1), (500, 40, 2));
        assert!(depth_tw_full(w));
        assert_eq!(depth_tw_min_atoms(w, USD_ATOMS), Some(40 * USD_ATOMS), "the older bucket's min still binds");
        // a gap of more than one bucket: prev absent again
        let g = depth_tw_update(w, 700, 3 * b);
        assert_eq!((g.cur_tokens, g.prev_tokens), (700, DEPTH_TW_ABSENT));
        // ring wrap: bucket 65,535 -> 1 is adjacent
        let r = DepthWindow { cur_tokens: 9, prev_tokens: DEPTH_TW_ABSENT, bucket_p1: 65_535 };
        let r2 = depth_tw_update(r, 11, 65_535 * b);
        assert_eq!((r2.bucket_p1, r2.prev_tokens), (1, 9));
        // tokens: floor, saturating below the absent marker
        assert_eq!(depth_tokens_floor(1_999_999, USD_ATOMS), 1);
        assert_eq!(depth_tokens_floor(u64::MAX, 1), DEPTH_TW_ABSENT - 1);
        // validator
        assert!(!depth_tw_window_ok(DepthWindow { cur_tokens: 1, prev_tokens: 0, bucket_p1: 0 }));
        assert!(!depth_tw_window_ok(DepthWindow { cur_tokens: DEPTH_TW_ABSENT, prev_tokens: 0, bucket_p1: 3 }));
        assert!(depth_tw_window_ok(DepthWindow { cur_tokens: 0, prev_tokens: DEPTH_TW_ABSENT, bucket_p1: 3 }));
    }

    #[test]
    fn r2_sticky_depth_cap_w_m1() {
        let t1 = DEPTH_TIER1_E6;
        let a = DEPTH_SOURCE_ATTESTED;
        // two later-slot pushes: fresh -> DEPTH_EVER + last good (seed MAX: no D-I1 clamp here)
        let s = up(DepthState::default(), a, 4 * t1, 100, u64::MAX);
        let s = up(s, a, 2 * t1, 101, u64::MAX);
        assert!(depth_ever(s.depth_source));
        assert_eq!((s.last_good_e6, s.last_good_slot), (2 * t1, 101));
        // 35 B push: depth 0, DEPTH_EVER, last good and the window kept
        let z = up(s, DEPTH_SOURCE_NONE, 0, 102, u64::MAX);
        assert_eq!(z.depth_e6, 0);
        assert_eq!(z.depth_source, DEPTH_EVER | DEPTH_PREV_REAL, "absent current, real previous");
        assert_eq!((z.last_good_e6, z.last_good_slot, z.tw), (2 * t1, 101, s.tw));
        // first push of a new pair (prev 0): effective 0, sticky stays
        let f = up(z, a, 9 * t1, 103, u64::MAX);
        assert_eq!(effective_depth_e6(f.depth_e6, f.depth_prev_e6, f.depth_slot, 103), 0);
        assert_eq!(f.last_good_e6, 2 * t1);
        // next pair: a LOWER fresh reading replaces it
        let g = up(f, a, t1, 104, u64::MAX);
        assert_eq!((g.last_good_e6, g.last_good_slot), (t1, 104), "fresh replaces, lower too");
        // cap depth: fresh -> eff; absent + ever -> min(last_good >> k, window min); never -> None
        assert_eq!(cap_depth_e6(a, Some(7), 0, 0, 0, None), Some(7));
        assert_eq!(cap_depth_e6(a | DEPTH_EVER, Some(0), 1_000, 0, 0, None), Some(0), "a fresh real 0 caps at 0");
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 100, 100 + 8_999, None), Some(1_000));
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 100, 100 + 9_000, None), Some(500), "halves per epoch");
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 100, 100 + 18_000, None), Some(250));
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, u64::MAX, 0, 64 * 9_000, None), Some(0), "k >= 64 -> 0");
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 500, 100, None), Some(1_000), "future stamp: no decay, still capped");
        assert_eq!(cap_depth_e6(0, None, 1_000, 100, 200, None), None, "never had depth: no cap");
        // round 3: the sticky cap is never above the last window minimum (a zero in it: 0)
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 100, 200, Some(300)), Some(300));
        assert_eq!(cap_depth_e6(DEPTH_EVER, None, 1_000, 100, 200, Some(0)), Some(0));
        // N_cap at the sticky depth, tier 0 (κ 0.5): never uncapped, 0 closes opens
        let c_m = 1_000_000_000_000u128;
        assert_eq!(n_cap_g8_q(true, c_m, 10_000, 0, Some(100_000_000), 1_000_000, PS), Some(50_000_000));
        assert_eq!(n_cap_g8_q(true, c_m, 10_000, 0, Some(0), 1_000_000, PS), Some(0));
        assert_eq!(growth_matcher_caps_g8(false, true, c_m, 10_000, 0, Some(0), 1_000_000, PS, u128::MAX), (0, 0));
        // I-1 reset clears the sticky state and the window
        let r = graduation_reset(500, 2_000, 9);
        assert_eq!((r.depth_source, r.depth_last_good_e6, r.depth_last_good_slot), (0, 0, 0));
        assert_eq!(r.depth_tw, DepthWindow::default());
        // MUTANT (round-1 rule: absent depth = no cap): the market goes uncapped
        let mutant = |eff: u64| if eff > 0 { Some(eff) } else { None };
        assert_eq!(depth_cap_q(0, mutant(0), 1_000_000, PS), u128::MAX, "mutant: uncapped");
        assert_ne!(depth_cap_q(0, cap_depth_e6(DEPTH_EVER, None, 1, 0, 0, None), 1_000_000, PS), u128::MAX);
    }

    /// R2-M1 + D-L2 kept, plus round 3 item 4 (GAP-5, D-I1, D2): the rate-limited depth rises
    /// at most 2x per 9,000 slots and ONLY on liquidity held over a full window (>= one whole
    /// 750-slot bucket), falls at once, starts at T1 / 16, and a real zero glitch recovers in
    /// one window instead of ~7 h.
    #[test]
    fn r2m1_depth_rises_at_most_2x_per_epoch_and_falls_at_once() {
        let th = tier_thresholds([0; 3], 6);
        let seed = th[0] - 1; // $24,999.999999
        let floor = seed / DEPTH_BOOTSTRAP_DIV; // ~$1,562.5
        let a = DEPTH_SOURCE_DEX;
        let b = DEPTH_TW_BUCKET_SLOTS;
        let real = 2_000 * USD_ATOMS;
        let inflated = 500_000_000 * USD_ATOMS;
        // D-I1: a market's FIRST reading is min(r, T1/16): a first-pair flash of $500M reads
        // ~$1,562 (round 2: T1 - 1, ~12x a $2k pool), tier 0.
        let f0 = up(up(DepthState::default(), a, inflated, 1_000, seed), a, inflated, 1_001, seed);
        assert_eq!(f0.last_good_e6, floor);
        assert_eq!(venue_tier(usable_of(f0, 1_001).unwrap(), f0.depth_source, th, 0), 0);
        // The reviewer's flash scenario on a real $2k pool: two adjacent-slot inflated reads in
        // the same bucket add nothing (the window minimum is still the real $2k and a rise needs
        // a full window anyway).
        let s1 = up(up(DepthState::default(), a, real, 1_000, seed), a, real, 1_001, seed);
        assert_eq!(s1.last_good_e6, floor, "first reading: T1/16");
        let w2 = up(up(s1, a, inflated, 1_014, seed), a, inflated, 1_015, seed);
        assert_eq!(usable_of(w2, 1_015), Some(floor), "the spike adds nothing");
        assert_eq!(depth_tw_min_atoms(w2.tw, USD_ATOMS), Some(real), "the window keeps the real min");
        // A whale must HOLD the liquidity over a whole bucket pair AND wait 9,000 slots per
        // doubling: pushes every 10 slots from the window opening through the next bucket.
        let mut st = s1;
        // the first rise window opens at stamp(1,001) * 64 + 63 + 9,000 = 10,023
        let mut s = 10_100u64;
        let hold = |mut st: DepthState, from: u64, to: u64, d: u64| {
            let mut x = from;
            while x <= to {
                st = up(st, a, d, x, seed);
                x += 10;
            }
            st
        };
        let mut prev = st.last_good_e6;
        for k in 1..=4u64 {
            // fill the window with the held liquidity BEFORE the rise window opens (the first
            // sample of a new window is min-of-two with the previous, honest-or-not, sample)
            st = hold(st, s - 2 * b, s - 80, inflated);
            assert_eq!(st.last_good_e6, prev, "window {k}: no rise before 9,000 slots");
            st = hold(st, s, s + 2 * b, inflated);
            assert_eq!(st.last_good_e6, prev * 2, "window {k}: exactly one doubling");
            // more held liquidity inside the same 9,000 slots adds nothing
            st = hold(st, s + 2 * b + 10, s + 4_000, inflated);
            assert_eq!(st.last_good_e6, prev * 2, "window {k}: no second rise");
            prev = st.last_good_e6;
            // the rise was stamped at `s`: the next window opens at <= s + 9,063
            s += 9_064;
        }
        // an honest reading takes it down at once (min-of-two, then the window)
        let h = up(up(st, a, real, s, seed), a, real, s + 1, seed);
        assert_eq!(usable_of(h, s + 1), Some(real));
        assert_eq!(h.last_good_e6, real, "down at once");
        // D2: a real 0 caps at 0 AT ONCE but last_good is HELD (not zeroed) ...
        let deep = 150_000 * USD_ATOMS;
        let mut d = DepthState { last_good_e6: deep, last_good_slot: 50_000, rise_slot64: 0, depth_source: DEPTH_EVER | a | DEPTH_PREV_REAL, depth_e6: deep, depth_prev_e6: deep, depth_slot: 50_000, tw: DepthWindow { cur_tokens: 150_000, prev_tokens: 150_000, bucket_p1: depth_tw_bucket_p1(50_000) } };
        d = up(d, a, 0, 50_010, seed);
        assert_eq!(usable_of(d, 50_010), Some(0), "fresh-zero: 0 at once");
        assert_eq!((d.last_good_e6, d.last_good_slot), (deep, 50_000), "held through the zero");
        assert_eq!(cap_depth_e6(d.depth_source, None, d.last_good_e6, d.last_good_slot, 50_300, depth_tw_min_atoms(d.tw, USD_ATOMS)), Some(0), "stale after a zero: still 0");
        // ... honest readings again: 0 while the zero is inside the window, then the full depth
        let r1 = hold(d, 50_020, 50_020 + 300, deep);
        assert_eq!(usable_of(r1, 50_320), Some(0), "the zero is still in the window");
        let r2 = hold(r1, 50_330, 50_000 + 3 * b, deep);
        assert_eq!(usable_of(r2, r2.depth_slot), Some(deep), "D2: recovered within ~10 min, not ~7 h");
        // round-2 rule (MUTANT): last_good = 0 at the zero, then T1/16 doubling per 9,000 slots
        assert!(floor * 32 < deep, "round 2 needed > 6 doublings (~7 h) to get back");
        // a zero lasting k epochs recovers only to last_good >> k (the held value decays)
        let long = hold(d, 50_020, 50_000 + 9_000 * 2 + 500, 0);
        let back = hold(long, 50_000 + 9_000 * 2 + 510, 50_000 + 9_000 * 2 + 510 + 3 * b, deep);
        assert_eq!(back.last_good_e6, (deep >> 2) * 2, "two epochs of zero: back to a quarter, then one doubling (rise window open)");
        // direct limiter checks (D-L2 kept): one doubling per 9,000 slots
        // (last_good_slot = the slot before: no staleness decay)
        let (a1, s1_, _) = depth_rate_limited(true, seed, 9_062, 0, inflated, true, 63 + 9_000, seed);
        assert_eq!(a1, 2 * seed);
        let (a2, _, _) = depth_rate_limited(true, a1, 63 + 9_000, s1_, inflated, true, 63 + 9_001, seed);
        assert_eq!(a2, a1, "one slot later: no second doubling");
        let (a3, _, _) = depth_rate_limited(true, seed, 9_062, 0, inflated, false, 63 + 9_000, seed);
        assert_eq!(a3, seed, "no full window: no rise");
        assert!(!depth_rise_window_open(depth_rise_stamp(8_999), 9_000));
        assert!(depth_rise_window_open(depth_rise_stamp(8_999), 8_999 / 64 * 64 + 63 + 9_000));
        // D-L1 belt and braces: a saturated threshold is never met
        assert_eq!(depth_tier_for(u64::MAX, [u64::MAX; 3]), 0);
        assert_eq!(depth_tier_for(u64::MAX, [1, 2, u64::MAX]), 2);
        assert_eq!(tier_thresholds([0; 3], 12)[2], 500_000 * 1_000_000_000_000);
        // 6 and 9 decimals (R2-L2): thresholds are whole collateral tokens
        assert_eq!(tier_thresholds([0; 3], 9)[0], 25_000 * 1_000_000_000);
        assert_eq!(tier_thresholds([5_000, 20_000, 100_000], 6), [5_000_000_000, 20_000_000_000, 100_000_000_000]);
        assert_eq!(tier_thresholds([u32::MAX; 3], 18)[2], u64::MAX, "saturates (fail closed)");
        assert_eq!(collateral_decimals_of(0), 6, "pre-R2-L2 record");
        assert_eq!(collateral_decimals_of(10), 9);
        // R2-L1 rent snapshot
        assert_eq!(rent_snapshot_n_cap_q(0, true), 1, "depth cap 0: max rent");
        assert_eq!(rent_snapshot_n_cap_q(0, false), 0, "C_m 0: not measured");
        assert_eq!(rent_snapshot_n_cap_q(7, true), 7);
        assert_eq!(rent_rate_e9(1, 1, 5_000, 23), Some(23), "u >= 1: the maximum");
    }

    #[test]
    fn r2_fresh_real_zero_reading_closes_at_once() {
        let t1 = DEPTH_TIER1_E6;
        let a = DEPTH_SOURCE_ATTESTED;
        let fresh = |x: DepthState, now: u64| fresh_depth_e6(x.depth_e6, x.depth_prev_e6, x.depth_slot, x.depth_source, now);
        // a healthy pair, then an attested 0: fresh Some(0) AT ONCE (no second sample needed)
        let s = up(DepthState::default(), a, 4 * t1, 100, u64::MAX);
        let s = up(s, a, 4 * t1, 101, u64::MAX);
        assert_eq!(fresh(s, 101), Some(4 * t1));
        let z = up(s, a, 0, 102, u64::MAX);
        assert_eq!(fresh(z, 102), Some(0), "a real 0 takes effect at once");
        assert_eq!(usable_of(z, 102), Some(0));
        assert_eq!((z.last_good_e6, z.last_good_slot), (4 * t1, 101), "round 3 D2: last_good held");
        assert_eq!(cap_depth_e6(z.depth_source, usable_of(z, 102), z.last_good_e6, z.last_good_slot, 102, depth_tw_min_atoms(z.tw, USD_ATOMS)), Some(0));
        assert_eq!(venue_tier(0, z.depth_source, tier_thresholds([0; 3], 6), 3), 0);
        // DEX 0 too, and from a market that never had depth (sets DEPTH_EVER)
        let d = up(DepthState::default(), DEPTH_SOURCE_DEX, 0, 7, u64::MAX);
        assert_eq!((fresh(d, 7), depth_ever(d.depth_source)), (Some(0), true));
        // a later positive reading: its previous sample is the real 0 -> min stays 0
        let p1 = up(z, a, 4 * t1, 103, u64::MAX);
        assert_eq!(fresh(p1, 103), Some(0), "positive after a real 0: min(4t1, 0) = 0");
        let p2 = up(p1, a, 4 * t1, 104, u64::MAX);
        assert_eq!(fresh(p2, 104), Some(4 * t1), "its own min-of-two restores the fresh reading");
        assert_eq!(usable_of(p2, 104), Some(0), "but the zero is still inside the window");
        // contrast: absent samples (35 B / mode 0) are NOT zero readings -> sticky last good
        let ab = up(s, DEPTH_SOURCE_NONE, 0, 102, u64::MAX);
        assert_eq!(fresh(ab, 102), None);
        assert_eq!(ab.last_good_e6, 4 * t1);
        let ab2 = up(ab, a, 4 * t1, 103, u64::MAX);
        assert_eq!(fresh(ab2, 103), None, "first real sample after an absent one: one sample");
        // same slot: a real 0 beats an absent 0 (more conservative); an absent push cannot
        // undo a real 0 in the same slot
        let x = up(ab, a, 0, 102, u64::MAX);
        assert_eq!(fresh(x, 102), Some(0));
        let y = up(z, DEPTH_SOURCE_NONE, 0, 102, u64::MAX);
        assert_eq!(fresh(y, 102), Some(0), "same-slot absent keeps the real 0");
        // stale real 0 -> absent; the sticky cap is still 0 (the window holds the zero)
        assert_eq!(fresh(z, 102 + DEPTH_MAX_AGE_SLOTS + 1), None);
        assert_eq!(cap_depth_e6(z.depth_source, None, z.last_good_e6, z.last_good_slot, 102 + 200, depth_tw_min_atoms(z.tw, USD_ATOMS)), Some(0));
        // validator: bit 2 allowed, bits 3-6 not
        assert!(depth_source_byte_ok(DEPTH_EVER | DEPTH_PREV_REAL | DEPTH_SOURCE_DEX));
        assert!(!depth_source_byte_ok(0x08));
    }

    #[test]
    fn g8_n_cap_depth_cap_only_when_fresh_and_identity_off_clamp() {
        let c_m = 1_000_000_000u128; // $1,000
        // off the clamp: n_cap_q with the STORED lambda, depth ignored entirely
        for (lam, d) in [(10_000u32, None), (30_000, Some(1u64)), (10_000, Some(DEPTH_TIER1_E6)), (10_000, Some(0))] {
            assert_eq!(n_cap_g8_q(false, c_m, lam, 1, d, 1_000_000, PS), n_cap_q(c_m, lam, 1_000_000, PS));
            assert_eq!(
                growth_matcher_caps_g8(false, false, c_m, lam, 1, d, 1_000_000, PS, u128::MAX),
                growth_matcher_caps(false, c_m, lam, 1_000_000, PS, u128::MAX)
            );
        }
        // on the clamp, no cap depth: n_cap at λ_eff (a stored 3x reads 1x at tier 0/1)
        assert_eq!(n_cap_g8_q(true, c_m, 30_000, 0, None, 1_000_000, PS), n_cap_q(c_m, 10_000, 1_000_000, PS));
        // depth $100 at tier 0 (κ 0.5): cap = $50 of notional, below the capital's $1,000
        assert_eq!(n_cap_g8_q(true, c_m, 10_000, 0, Some(100_000_000), 1_000_000, PS), Some(50_000_000));
        assert_eq!(depth_cap_q(0, None, 1_000_000, PS), u128::MAX, "never had depth: no cap");
        assert_eq!(depth_cap_q(1, Some(100_000_000), 0, PS), 0, "price 0: fail closed");
        // matcher: cap and liquidity follow the binding (depth) notional, x DEPTH_MULT
        assert_eq!(
            growth_matcher_caps_g8(false, true, c_m, 10_000, 0, Some(100_000_000), 1_000_000, PS, u128::MAX),
            (50_000_000, 200_000_000)
        );
        assert_eq!(
            growth_matcher_caps_g8(true, true, c_m, 10_000, 0, Some(100_000_000), 1_000_000, PS, u128::MAX),
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
        // reductions pass at cap 0
        g.depth_cap_q = 0;
        g.taker_before_q = 200 * PS as i128;
        g.taker_after_q = 100 * PS as i128;
        assert_eq!(growth_gate(&g), GrowthVerdict::Allow, "reduce at cap 0");
    }

    #[test]
    fn g8_target_ceiling_ratchet_and_force_down() {
        let tab = tier_leverage([0; 3], 500, 2_000); // [5x, 5x, 10x, 20x]
        // off graduation / forced: launch
        assert_eq!(target_ceiling_x100(false, STRESS_NONE, 300, 1_000, 500, u16::MAX), 300);
        assert_eq!(target_ceiling_x100(true, STRESS_HLOCK, 300, 1_000, 500, u16::MAX), 300, "h-lock: launch");
        // R2.1: min(L_tier, max(L_launch, L_table(tier))) (no stress: no cap)
        let n = u16::MAX;
        assert_eq!(target_ceiling_x100(true, STRESS_NONE, 500, 2_000, l_table_x100(2, tab), n), 1_000);
        assert_eq!(target_ceiling_x100(true, STRESS_NONE, 500, 2_000, l_table_x100(3, tab), n), 2_000);
        assert_eq!(target_ceiling_x100(true, STRESS_NONE, 300, 1_000, 2_000, n), 1_000, "L_tier");
        assert_eq!(target_ceiling_x100(true, STRESS_NONE, 800, 1_000, 500, n), 800, "never below launch");
        // round 3 item 3: graded stress at tier 3 (20x): draw -> L_table(2) 10x; real ADL ->
        // L_table(1) 5x; h-lock -> launch
        assert_eq!(stress_cap_x100(STRESS_NONE, 3, tab), u16::MAX);
        assert_eq!(stress_cap_x100(STRESS_DRAW, 3, tab), 1_000);
        assert_eq!(stress_cap_x100(STRESS_ADL, 3, tab), 500);
        assert_eq!(stress_cap_x100(STRESS_ADL, 1, tab), 500, "floored at tier 0");
        assert_eq!(stress_cap_x100(STRESS_HLOCK, 3, tab), 500);
        let l3 = l_table_x100(3, tab);
        assert_eq!(target_ceiling_x100(true, STRESS_DRAW, 500, 2_000, l3, stress_cap_x100(STRESS_DRAW, 3, tab)), 1_000);
        assert_eq!(target_ceiling_x100(true, STRESS_ADL, 500, 2_000, l3, stress_cap_x100(STRESS_ADL, 3, tab)), 500);
        assert_eq!(stress_level(true, false, false), STRESS_DRAW);
        assert_eq!(stress_level(true, true, false), STRESS_ADL);
        assert_eq!(stress_level(true, true, true), STRESS_HLOCK);
        assert_eq!(stress_level(false, false, false), STRESS_NONE);
        // D1(a): A != 1 is not read; only a non-Normal side mode is ADL
        assert!(!real_adl(0, 0) && real_adl(1, 0) && real_adl(0, 2));
        // ceiling in force: off clamp == launch whatever is stored
        assert_eq!(ceiling_in_force_x100(false, 900, 900, 300, 1_000), 300);
        // F-1 fix A: min(stored, target) -- down at once, up only through the ratchet
        assert_eq!(ceiling_in_force_x100(true, 900, 400, 300, 1_000), 400, "down at once");
        assert_eq!(ceiling_in_force_x100(true, 900, 850, 300, 1_000), 850);
        assert_eq!(ceiling_in_force_x100(true, 400, 900, 300, 1_000), 400, "up only via the ratchet");
        // round 3 item 6: no c_launch snapshot any more; a climb waits a full epoch from the
        // stamp (bind / I-1 reset stamp ceil_slot = now)
        assert_eq!(graduation_ratchet(500, 50_000, true, STRESS_NONE, 500, 2_000, 1_000, n, 50_000), (500, 50_000));
        // +1x per 9,000 slots toward 10x; falls to the target at once; unchanged keeps its stamp
        assert_eq!(graduation_ratchet(500, 0, true, STRESS_NONE, 500, 2_000, 1_000, n, 8_999), (500, 0));
        assert_eq!(graduation_ratchet(500, 0, true, STRESS_NONE, 500, 2_000, 1_000, n, 9_000), (600, 9_000));
        assert_eq!(graduation_ratchet(600, 9_000, true, STRESS_NONE, 500, 2_000, 1_000, n, 18_000), (700, 18_000));
        assert_eq!(graduation_ratchet(1_000, 18_000, true, STRESS_NONE, 500, 2_000, 1_000, n, 40_000), (1_000, 18_000), "at target: stamp kept");
        assert_eq!(graduation_ratchet(1_000, 18_000, false, STRESS_NONE, 500, 2_000, 500, n, 40_001), (500, 40_001), "depth gone: launch at once");
        assert_eq!(graduation_ratchet(1_000, 18_000, true, STRESS_HLOCK, 500, 2_000, 1_000, n, 40_001), (500, 40_001), "h-lock: launch at once");
        assert_eq!(graduation_ratchet(2_000, 18_000, true, STRESS_DRAW, 500, 2_000, 2_000, 1_000, 40_001), (1_000, 40_001), "draw: L_table(tier 3 - 1) = 10x at once");
        assert_eq!(graduation_ratchet(2_000, 18_000, true, STRESS_NONE, 500, 2_000, 1_000, n, 40_001), (1_000, 40_001), "tier 3 -> 2: at once");
        // fall-only (push): never rises; falls to the bound at once (the h-lock too)
        assert_eq!(graduation_fall_only(500, 7, true, STRESS_NONE, 500, 2_000, 1_000, n, 99), (500, 7));
        assert_eq!(graduation_fall_only(1_000, 7, false, STRESS_NONE, 500, 2_000, 500, n, 99), (500, 99));
        assert_eq!(graduation_fall_only(2_000, 7, true, STRESS_NONE, 500, 2_000, 1_000, n, 99), (1_000, 99));
        assert_eq!(graduation_fall_only(2_000, 7, true, STRESS_HLOCK, 500, 2_000, 1_000, n, 99), (500, 99));
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
