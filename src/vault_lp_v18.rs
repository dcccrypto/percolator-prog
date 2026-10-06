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
#[cfg_attr(kani, kani::ensures(|r: &Option<u128>| mul_div_floor_spec(a, b, d, *r) && mul_div_floor_facts(a, b, d, *r)))]
pub fn mul_div_floor(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    a.checked_mul(b).map(|p| p / d)
}

/// Kani contract of `mul_div_floor` (security review A2): EXACT floor in remainder form,
/// `q*d + r == a*b ∧ r < d`; `None ⇔ d == 0 ∨ a*b overflows`. `cfg(kani)` only.
#[cfg(kani)]
pub fn mul_div_floor_spec(a: u128, b: u128, d: u128, r: Option<u128>) -> bool {
    match (d == 0, a.checked_mul(b)) {
        (true, _) | (false, None) => r.is_none(),
        (false, Some(p)) => r.is_some_and(|q| q.checked_mul(d).is_some_and(|qd| qd <= p && p - qd < d)),
    }
}

/// Width-independent range fact of the floor primitive (proved with the contract at u8, paper
/// lift): `Some(q)` with `b <= d` has `q <= a`. `cfg(kani)` only.
#[cfg(kani)]
pub fn mul_div_floor_facts(a: u128, b: u128, d: u128, r: Option<u128>) -> bool {
    r.is_none_or(|q| b > d || q <= a)
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
    mul_div_floor(amount, total_shares, senior_value)
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

/// H-2: a LIVE bound senior payout's principal portion: everything the pots can pay, i.e.
/// `min(payout, available)`. Any remainder is not backing (it sits in the vault LP) and needs a
/// recall first. Property: `principal <= payout` and `principal <= available`, and a payout at or
/// below the pots' available principal is paid entirely as principal.
pub fn live_bound_principal_portion(atoms_out: u128, available_principal: u128) -> u128 {
    if atoms_out < available_principal {
        atoms_out
    } else {
        available_principal
    }
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

/// F14-Q1 combined NAV of the vault's two backing pots (extracted, behaviour-identical, from
/// `lp_vault_combined_nav_parts_p3`). Floor ONCE across both pots (a per-pot floor overstates the
/// combined value when one pot is impaired past its principal), cap at the backing the vault
/// still owns, then add LP earnings. Returns `(available_principal, nav)`; `None` on overflow.
pub fn combined_nav(
    p0: u128,
    i0: u128,
    e0: u128,
    p1: u128,
    i1: u128,
    e1: u128,
    owned: u128,
) -> Option<(u128, u128)> {
    let principal = p0.checked_add(p1)?;
    let impairment = i0.checked_add(i1)?;
    let floored = principal.saturating_sub(impairment);
    let available = if floored < owned { floored } else { owned };
    let earnings = e0.checked_add(e1)?;
    let nav = available.checked_add(earnings)?;
    Some((available, nav))
}

/// Bound-vault NAV (2026-09-30): per pot the vault owns `min(principal, held)` (backing above the
/// principal is the vault LP's settled loss reserved for the winners; below it is a real loss),
/// plus the pots' LP earnings. Returns `(available_principal, nav)`; `None` on overflow.
pub fn bound_vault_nav(
    p0: u128,
    held0: u128,
    p1: u128,
    held1: u128,
    e0: u128,
    e1: u128,
) -> Option<(u128, u128)> {
    let a0 = if p0 < held0 { p0 } else { held0 };
    let a1 = if p1 < held1 { p1 } else { held1 };
    let available = a0.checked_add(a1)?;
    let nav = available.checked_add(e0.checked_add(e1)?)?;
    Some((available, nav))
}

// ── P3 senior draw (loss rule 2026-09-30: junior first, then Earn seniors pro rata via C;
//    winners are never haircut while senior backing remains) ──────────────────────────────────

/// Atoms to move from SENIOR-owned backing into the vault LP's capital now:
/// `min(deficit - min(deficit, junior_surplus) - outstanding, owned_backing)` (saturating).
/// `deficit` is the vault LP's realised deficit (`-certified_equity`), `junior_surplus` the
/// junior's value still sitting in the pots (it is spent first), `owned_backing` the senior-owned
/// drawable backing, `outstanding` what was already drawn against this same deficit.
pub fn vault_lp_senior_draw_amount(
    deficit: u128,
    junior_surplus: u128,
    owned_backing: u128,
    outstanding: u128,
) -> u128 {
    let junior_cover = if deficit < junior_surplus { deficit } else { junior_surplus };
    let owed = deficit.saturating_sub(junior_cover).saturating_sub(outstanding);
    if owed < owned_backing {
        owed
    } else {
        owned_backing
    }
}

/// The physical move for one draw: `(junior_cover, senior_draw)`. The junior's surplus in the
/// pots covers first (not a senior loss); the senior part is `vault_lp_senior_draw_amount` over
/// the backing left after the junior cover. Both come out of `drawable_backing`.
pub fn vault_lp_draw_move(deficit: u128, junior_surplus: u128, drawable_backing: u128) -> (u128, u128) {
    let jc = if deficit < junior_surplus { deficit } else { junior_surplus };
    let junior_cover = if jc < drawable_backing { jc } else { drawable_backing };
    let senior = vault_lp_senior_draw_amount(
        deficit,
        junior_surplus,
        drawable_backing - junior_cover,
        0,
    );
    (junior_cover, senior)
}

/// C after a draw: `c - max(0, deficit - junior_surplus)`, saturating at 0. C is one pooled claim
/// over S shares, so this IS the pro-rata rule (every share's C/S falls by the same fraction).
pub fn senior_claim_after_draw(c: u128, deficit: u128, junior_surplus: u128) -> Option<u128> {
    Some(c.saturating_sub(deficit.saturating_sub(junior_surplus)))
}

/// The claim 75/76/77 price against: C with any deficit not yet drawn and booked netted out
/// (== C after that draw is booked), so no depositor or redeemer can trade on the timing.
pub fn vault_lp_senior_pricing_claim(c: u128, undrawn_deficit: u128, junior_surplus: u128) -> u128 {
    senior_claim_after_draw(c, undrawn_deficit, junior_surplus).unwrap_or_default()
}

/// A later vault-LP recovery (value above C) restores the seniors FIRST, up to the outstanding
/// draw; only the rest is junior surplus. `to_seniors + to_junior == recovery`.
pub fn vault_lp_recovery_split(recovery: u128, draw_outstanding: u128) -> (u128, u128) {
    let to_seniors = if recovery < draw_outstanding { recovery } else { draw_outstanding };
    (to_seniors, recovery - to_seniors)
}

/// Operations gated while a senior draw is outstanding.
pub const DRAW_OP_LP_RISK_INCREASING_FILL: u8 = 1;
pub const DRAW_OP_JUNIOR_WITHDRAW_97: u8 = 2;
pub const DRAW_OP_JUNIOR_RELEASE_102: u8 = 3;
pub const DRAW_OP_SENIOR_DEPOSIT_75: u8 = 4;
pub const DRAW_OP_SENIOR_REQUEST_76: u8 = 5;
pub const DRAW_OP_SENIOR_REDEEM_77: u8 = 6;
pub const DRAW_OP_RECALL_98: u8 = 7;
/// Phase 4 item 3: bond withdrawal (tag 110). Halted while a senior draw is outstanding.
pub const DRAW_OP_BOND_WITHDRAW: u8 = 8;

/// Owner rule (2026-09-30): while a draw is outstanding HALT the vault LP's risk-increasing fills,
/// junior withdraw (97), junior release (102), recall (98) and (Phase 4) bond withdrawal (110);
/// NEVER halt senior deposit / request / redeem (75/76/77).
pub fn vault_lp_draw_halts(draw_outstanding: u128, op: u8) -> bool {
    draw_outstanding > 0
        && (op == DRAW_OP_LP_RISK_INCREASING_FILL
            || op == DRAW_OP_JUNIOR_WITHDRAW_97
            || op == DRAW_OP_JUNIOR_RELEASE_102
            || op == DRAW_OP_RECALL_98
            || op == DRAW_OP_BOND_WITHDRAW)
}

/// The persisted draw ledger of one vault (`VaultLpStateV18` fields + the market's pending move).
///
/// REACHABLE-STATE INVARIANT (every processor write preserves it; Kani may assume it):
/// * `outstanding <= drawn` (only booked senior loss can be outstanding; recovery lowers
///   `outstanding` and raises `senior_claim` by the same amount, never `drawn`);
/// * `pending` is the physical move not yet booked; it is booked EXACTLY ONCE
///   (`vault_lp_book_pending` returns `pending == 0`);
/// * every booked unit of senior loss lowered `senior_claim` by the same unit
///   (`senior_claim + outstanding` is invariant across a booking, up to the C == 0 floor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrawLedger {
    pub senior_claim: u128,
    pub drawn: u128,
    pub outstanding: u128,
    pub pending: u128,
}

/// BOOK a pending physical move (the ONE booking rule). Idempotent: with `pending == 0` it is the
/// identity; otherwise it books the move once through `vault_lp_draw_step` on the CURRENT
/// junior surplus and returns `pending == 0`. Returns `(new_ledger, senior_loss)`.
pub fn vault_lp_book_pending(l: DrawLedger, junior_surplus: u128) -> (DrawLedger, u128) {
    if l.pending == 0 {
        return (l, 0);
    }
    let (next, _moved, senior_loss) = vault_lp_draw_step(
        DrawState {
            senior_claim: l.senior_claim,
            outstanding: l.outstanding,
            junior_surplus,
            drawable: l.pending,
        },
        l.pending,
    );
    (
        DrawLedger {
            senior_claim: next.senior_claim,
            drawn: l.drawn.saturating_add(senior_loss),
            outstanding: next.outstanding,
            pending: 0,
        },
        senior_loss,
    )
}

/// RECOVERY, seniors first, from the ledger's OWN outstanding senior loss: `value_above_c` (vault
/// value over C) restores C up to `outstanding`. Returns `(new_ledger, to_seniors)`.
pub fn vault_lp_recover(l: DrawLedger, value_above_c: u128) -> (DrawLedger, u128) {
    let (to_seniors, _to_junior) = vault_lp_recovery_split(value_above_c, l.outstanding);
    (
        DrawLedger {
            senior_claim: l.senior_claim.saturating_add(to_seniors),
            drawn: l.drawn,
            outstanding: l.outstanding - to_seniors,
            pending: l.pending,
        },
        to_seniors,
    )
}

/// D-P3-30 recall cap: `min(existing_limit, max(lp_equity, 0))`, and 0 while any draw is pending.
/// A recall can therefore never take the vault LP's certified equity below zero (never re-opens a
/// deficit a draw just funded, junior-covered or not).
pub fn vault_lp_recall_limit(existing_limit: u128, lp_equity: i128, draw_pending: bool) -> u128 {
    if draw_pending {
        return 0;
    }
    let eq = if lp_equity > 0 { lp_equity as u128 } else { 0 };
    if existing_limit < eq {
        existing_limit
    } else {
        eq
    }
}

/// The draw's state, as the processor holds it at booking time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrawState {
    /// C (the pooled senior claim).
    pub senior_claim: u128,
    /// Cumulative senior loss not yet restored.
    pub outstanding: u128,
    /// The junior's value still in the pots NOW (already net of earlier draws).
    pub junior_surplus: u128,
    /// Drawable backing NOW.
    pub drawable: u128,
}

/// One draw step on the CURRENT state: the junior surplus covers first, then senior backing;
/// `senior_loss` is what C falls by. Returns `(new_state, moved, senior_loss)`, where `moved` is
/// junior cover + senior draw. Repeating a step on its own output with a deficit that the
/// previous step already funded draws nothing: the consumed junior surplus is gone from the state.
pub fn vault_lp_draw_step(s: DrawState, current_deficit: u128) -> (DrawState, u128, u128) {
    let (junior_cover, senior_draw) =
        vault_lp_draw_move(current_deficit, s.junior_surplus, s.drawable);
    let moved = junior_cover + senior_draw;
    let new_c = senior_claim_after_draw(s.senior_claim, moved, s.junior_surplus).unwrap_or_default();
    let senior_loss = s.senior_claim - new_c;
    (
        DrawState {
            senior_claim: new_c,
            outstanding: s.outstanding.saturating_add(senior_loss),
            junior_surplus: s.junior_surplus - junior_cover,
            drawable: s.drawable - moved,
        },
        moved,
        senior_loss,
    )
}

/// P3 auto-pin (2026-09-30 decision): the matcher context tag 94 gives every vault LP. These are
/// PROTOCOL constants (the creator passes none of them); the upgrade authority may later adjust
/// within protocol bounds via tags 99/95. Values = the relaunch seed's vAMM defaults.
pub const PIN_MATCHER_KIND: u8 = 1; // vAMM
pub const PIN_TRADING_FEE_BPS: u32 = 10;
pub const PIN_BASE_SPREAD_BPS: u32 = 10;
pub const PIN_MAX_TOTAL_BPS: u32 = 100;
pub const PIN_IMPACT_K_BPS: u32 = 50;
pub const PIN_FEE_TO_INSURANCE_BPS: u16 = 0;
pub const PIN_SKEW_SPREAD_MULT_BPS: u16 = 1;
pub const PIN_TRADE_FEE_CAP_BPS: u16 = 10_000;
pub const PIN_LIQUIDITY_USD: u128 = 250_000;
pub const PIN_MAX_FILL_USD: u128 = 5_000;
pub const PIN_MAX_INVENTORY_USD: u128 = 25_000;
/// Mirror of the engine's `MAX_POSITION_ABS_Q` (this file is dependency-free for Kani); the
/// wrapper asserts equality at compile time.
pub const ENGINE_MAX_POSITION_ABS_Q: u128 = 100_000_000_000_000;

/// Price-derived, FINITE matcher caps pinned at bind time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedMatcherCaps {
    pub liquidity_notional_e6: u128,
    pub max_fill_abs: u128,
    pub max_inventory_abs: u128,
}

/// `usd` of notional at `price_e6` in engine Q (1e6 per unit): `floor(usd * 1e12 / price)`,
/// clamped to the engine's position bound. `None` when the price is 0 or the result would be
/// 0 (0 means UNLIMITED to the matcher, so it must never be pinned).
pub fn usd_to_q_capped(usd: u128, price_e6: u64) -> Option<u128> {
    if price_e6 == 0 {
        return None;
    }
    let q = usd.checked_mul(1_000_000_000_000)? / price_e6 as u128;
    let q = core::cmp::min(q, ENGINE_MAX_POSITION_ABS_Q);
    if q == 0 {
        None
    } else {
        Some(q)
    }
}

/// The caps tag 94 pins, from the asset's effective price at bind time.
pub fn pinned_matcher_caps(price_e6: u64) -> Option<PinnedMatcherCaps> {
    Some(PinnedMatcherCaps {
        liquidity_notional_e6: PIN_LIQUIDITY_USD.checked_mul(1_000_000)?,
        max_fill_abs: usd_to_q_capped(PIN_MAX_FILL_USD, price_e6)?,
        max_inventory_abs: usd_to_q_capped(PIN_MAX_INVENTORY_USD, price_e6)?,
    })
}

/// P3 Live senior EXIT value (tag 77), priced at the price WORSE for the vault LP (E-1 fix).
/// `lp_equity_worse` is the vault LP's equity re-valued at the worse of eff / pending target
/// (`vault_lp_equity_lag_bounds_ro`), `lp_value_at_eff` its value at eff, `nav` the pots' senior
/// NAV and `c` the claim. A deficit at the worse price is drawn OUT OF THE POTS, junior first:
///   C' = c - max(0, |worse| - (nav - c)+)            (the booking rule), when worse < 0
///   V  = nav + min(lp_value_at_eff, worse)  if worse >= 0
///      = nav - |worse|                      if worse <  0
///   senior value = min(V, C')
pub fn live_exit_senior_value(c: u128, nav: u128, lp_value_at_eff: u128, lp_equity_worse: i128) -> u128 {
    if lp_equity_worse >= 0 {
        let v = nav.saturating_add(lp_value_at_eff.min(lp_equity_worse as u128));
        tranche_split(v, c).senior
    } else {
        let d = lp_equity_worse.unsigned_abs();
        let c_p = vault_lp_senior_pricing_claim(c, d, nav.saturating_sub(c));
        tranche_split(nav.saturating_sub(d), c_p).senior
    }
}

// ── Phase 2b (2026-10-05): Earn as the counterparty ─────────────────────────────────────────
//
// Spec: `~/percolator-ops/ledger/devnet-v2-growth-plan-2026-10-04.md` §2.3 / §2.5 / §2.8 and
// `markets-grow-plan-2026-10-04.md` P1-B. Tag 103 `VaultLpAllocate` is the exact inverse of tag
// 98 recall: it moves senior principal out of the vault's own pots (principal-only decrement,
// the draw's primitive) into the vault LP's engine capital. `header.vault` nets to zero, no SPL
// moves, C is unchanged and V = NAV + H + LP value is unchanged at the moment of the move.

/// Default share of the effective senior claim that may sit in the vault LP's capital.
pub const ALLOC_ALPHA_DEFAULT_BPS: u16 = 5_000;
/// Hard ceiling on alpha until the L3 epoch clamp ships (plan §2.9: L3 gates alpha > 50%).
pub const ALLOC_ALPHA_MAX_BPS: u16 = 5_000;
/// Default (and minimum) redemption buffer kept liquid in the pots, bps of the senior claim.
pub const ALLOC_BUFFER_DEFAULT_BPS: u16 = 3_000;
pub const ALLOC_BUFFER_MIN_BPS: u16 = 3_000;

/// The most tag 103 may move now:
/// `min(alpha * C_eff - allocated, drawable - ceil(buffer * C_eff))`, both saturating at 0.
///
/// `drawable` is the pots' vault-owned, unreserved Fresh backing (`vault_pot_drawable_atoms`
/// summed): backing reserved against winners' claims and loss backing the engine routed in for
/// untouched winners are already excluded, so the buffer is kept ON TOP of the claims reserve
/// (stricter than the plan's `max(buffer, liened reserve)`). `None` on an out-of-range dial.
///
/// Properties (Kani `kani_p2b_alloc_*`): `allocated + limit <= floor(alpha * C_eff)` whenever
/// `allocated <= floor(alpha * C_eff)` (else 0); `drawable - limit >= ceil(buffer * C_eff)`
/// whenever `limit > 0`; monotone non-decreasing in `drawable` and in `C_eff`.
pub fn vault_lp_alloc_limit(
    c_eff: u128,
    allocated: u128,
    drawable: u128,
    alpha_bps: u16,
    buffer_bps: u16,
) -> Option<u128> {
    // v2.2: the hard ceiling is the band-market maximum (70%); the per-market cap (50%
    // off-band) is enforced where alpha is written.
    if alpha_bps > crate::growth_v19::ALLOC_ALPHA_MAX_BAND_BPS
        || buffer_bps < ALLOC_BUFFER_MIN_BPS
        || buffer_bps as u128 > BPS
    {
        return None;
    }
    let alpha_room = bps_floor(c_eff, alpha_bps)?.saturating_sub(allocated);
    let liquid_room = drawable.saturating_sub(bps_ceil(c_eff, buffer_bps)?);
    Some(if alpha_room < liquid_room {
        alpha_room
    } else {
        liquid_room
    })
}

/// Tag 103 admission (spec: refused during a senior draw, an impairment, or with the vault LP
/// insolvent). `draw_outstanding` is the booked, unrecovered senior loss; `draw_pending` any
/// physical draw not yet booked; `lp_equity` the vault LP's certified equity AFTER the
/// instruction's own draw-then-book. Receipts-open is a Resolved state and is excluded by the
/// processor's Live-only gate.
pub fn vault_lp_alloc_admitted(
    draw_outstanding: u128,
    draw_pending: bool,
    vault_value: u128,
    senior_claim_eff: u128,
    lp_equity: i128,
) -> bool {
    draw_outstanding == 0
        && !draw_pending
        && !senior_impaired(vault_value, senior_claim_eff)
        && lp_equity >= 0
}

/// L-3 (security review 2026-10-05): allocation needs a real first-loss buffer. Tag 103 is
/// refused unless the junior (`V - C_eff`) is at least this share of `C_eff` (protocol floor;
/// raising it is a tighten-only code change).
pub const ALLOC_MIN_JUNIOR_BPS: u16 = 500;

pub fn alloc_junior_ok(vault_value: u128, senior_claim_eff: u128) -> bool {
    let junior = vault_value.saturating_sub(senior_claim_eff);
    match bps_ceil(senior_claim_eff, ALLOC_MIN_JUNIOR_BPS) {
        Some(need) => junior >= need,
        None => false,
    }
}

/// L-2: the allocation counter written down to what the vault LP can still be holding of it
/// (its current value). A senior draw that consumed allocated capital otherwise left 103 at
/// "no room" for good.
pub fn alloc_written_down(allocated: u128, lp_value: u128) -> u128 {
    if allocated < lp_value {
        allocated
    } else {
        lp_value
    }
}

/// Per-pot split of one allocation, the SAME rule as the senior draw
/// (`vault_lp_physical_draw`): proportional to each pot's drawable backing, the floor on the
/// SMALLER pot's take so a small pot is never left an atom short of its seniors' pro-rata claim.
/// Returns `(take_even, take_odd)` with `take_even + take_odd == moved`, each within its pot.
/// `None` when `moved` exceeds the two pots together (fail closed).
pub fn vault_lp_alloc_split(moved: u128, d_even: u128, d_odd: u128) -> Option<(u128, u128)> {
    let total = d_even.checked_add(d_odd)?;
    if moved > total {
        return None;
    }
    if moved == 0 {
        return Some((0, 0));
    }
    let small_is_odd = d_odd <= d_even;
    let (d_small, d_large) = if small_is_odd { (d_odd, d_even) } else { (d_even, d_odd) };
    let take_small = mul_div_floor(moved, d_small, total)?.min(d_small);
    let take_large = moved - take_small;
    if take_large > d_large {
        return None;
    }
    Some(if small_is_odd {
        (take_large, take_small)
    } else {
        (take_small, take_large)
    })
}

/// `allocated` after a recall of `recalled` atoms (tag 98 is the inverse of tag 103). A recall
/// can also move junior-held value (its pre-P2b role), so the counter saturates at zero.
pub fn vault_lp_dealloc(allocated: u128, recalled: u128) -> u128 {
    allocated.saturating_sub(recalled)
}

/// A4 capacity lock (plan §2.3): an operation that lowers the vault LP's capital may not leave
/// `N_cap(after) < |LP_eff|`. An operation that does not lower capacity is never refused here
/// (an over-capacity LP must stay closable, M-1). Today the engine's withdraw is flat-only
/// (`withdraw_not_atomic` -> Stale with an active leg), so 97/98 can only run with
/// `|LP_eff| == 0` and this is defence in depth: it pins the invariant if that engine rule moves.
pub fn a4_capacity_lock_ok(n_cap_before: u128, n_cap_after: u128, lp_eff_abs: u128) -> bool {
    n_cap_after >= n_cap_before || n_cap_after >= lp_eff_abs
}

// ── E3 (R-2 / I-2 attribution) ────────────────────────────────────────────────────────────

/// A pot's physical backing net of the claims it still owes, in atoms:
/// `floor((fresh_unliened + valid_liened) / scale) - ceil(max(0, claims - insurance_cover) / scale)`,
/// saturating at 0. `claims` is the source's `positive_claim_bound_num`; `insurance_cover` the
/// part of it reserved on insurance (`insurance_credit_reserved - insurance liens`), which the
/// pot does not owe. Floor on the backing, ceil on the claims: never overstates.
pub fn pot_physical_net_atoms(
    fresh_unliened_num: u128,
    valid_liened_num: u128,
    claim_bound_num: u128,
    insurance_cover_num: u128,
    scale: u128,
) -> u128 {
    if scale == 0 {
        return 0;
    }
    let held = fresh_unliened_num.saturating_add(valid_liened_num) / scale;
    let uncovered = claim_bound_num.saturating_sub(insurance_cover_num);
    held.saturating_sub(uncovered.div_ceil(scale))
}

/// E3: a NON-bound Earn pot's available principal = `min(ledger principal, physical net of
/// claims)`. Replaces `principal - (loss - recovery)` for pricing.
///
/// The ledger books EVERY rise of a pot's consumed backing as the vault's loss and every fall as
/// recovery, whoever's backing it was. Two leaks follow:
/// * R-2: a pair's own loss refills the pot, the winner's conversion then consumes it; the pot is
///   physically whole but the ledger books a loss (NAV depressed), a later refill books it back
///   (NAV restored). A deposit at the low and a redemption at the high extract from incumbents.
/// * deposit refill: a 75/91/78 add pays a receivable down; the add path re-baselines the
///   watermark, so the paydown is never booked as recovery and the value is stranded.
///
/// The physical reading is exact in both: the vault's value in a pot is what the pot holds net
/// of what it owes, never more than the vault put in (`principal`). Loss and recovery counters
/// stay untouched (they are the farm-facing `residual_received` scalars).
pub fn nonbound_pot_available(principal: u128, physical_net: u128) -> u128 {
    if principal < physical_net {
        principal
    } else {
        physical_net
    }
}

/// H-1 (security review 2026-10-05): the ENTRY reading of a non-bound pot (tag 75 pricing) is
/// PAR: the ledger principal the vault put in (plus the usual LP-earnings term).
///
/// E3's claim term is touch-order dependent (a winner's claim registers when the WINNER is
/// touched, the loser's loss arrives when the LOSER is touched), so pricing entries and exits on
/// one reading let a zero-sum pair deposit inside that window and redeem after it (+89.50 per
/// round). Two weaker entry readings were rejected:
/// * `min(principal, held)`: dips when a winner converts against principal before its loser is
///   touched (the residual window);
/// * `min(principal, held + receivable)`: dips when a permissionless tag 91 moves principal into
///   a pot carrying a receivable (the engine add pays the receivable down with the vault's own
///   atoms).
///
/// Par moves only with principal flows, so NO settlement order and no 91 can dip it, and
/// `entry (par) >= exit (E3)` always: every entry-to-exit round trip is non-positive. Cost, by
/// design: on a genuine default an entrant pays par, bounded by the R-1 pause (deposits stop
/// once the physical impairment exceeds 10% of principal).
pub fn nonbound_pot_entry_available(principal: u128) -> u128 {
    principal
}

// ── G6 fee waterfall (junior cushion) ────────────────────────────────────────────────────

/// Split one harvested LP fee leg `available` on a bound vault (plan §2.5 / CSV-FL++ B.6):
/// 1. bond coupon (capacity bonds, G7, are not built: 0);
/// 2. `cushion_share_bps` of it to the junior cushion, but only up to the target gap
///    `ceil(target_bps * C_eff) - junior_level` (nothing once the junior is at target);
/// 3. the rest to the seniors (credited to C).
///
/// Returns `(senior, cushion)`, `senior + cushion == available`. With either dial 0 the whole
/// leg goes to the seniors (today's rule). Creator fees vest only once the cushion is at target
/// (`creator_fee_vested`). `None` on overflow / out-of-range bps.
pub fn cushion_split(
    available: u128,
    cushion_share_bps: u16,
    cushion_target_bps: u16,
    c_eff: u128,
    junior_level: u128,
) -> Option<(u128, u128)> {
    if cushion_share_bps == 0 || cushion_target_bps == 0 {
        return Some((available, 0));
    }
    let need = bps_ceil(c_eff, cushion_target_bps)?.saturating_sub(junior_level);
    let share = bps_floor(available, cushion_share_bps)?;
    let cushion = if share < need { share } else { need };
    Some((available - cushion, cushion))
}

/// The cushion the junior may not withdraw (97): `min(accrued, ceil(target * C_eff))`.
pub fn cushion_locked(cushion_accrued: u128, c_eff: u128, cushion_target_bps: u16) -> Option<u128> {
    let target = bps_ceil(c_eff, cushion_target_bps)?;
    Some(if cushion_accrued < target {
        cushion_accrued
    } else {
        target
    })
}

/// Creator discretionary fees vest only at or above the cushion target (always vested when the
/// cushion is off).
pub fn creator_fee_vested(
    junior_level: u128,
    c_eff: u128,
    cushion_share_bps: u16,
    cushion_target_bps: u16,
) -> bool {
    if cushion_share_bps == 0 || cushion_target_bps == 0 {
        return true;
    }
    match bps_ceil(c_eff, cushion_target_bps) {
        Some(t) => junior_level >= t,
        None => false,
    }
}

// ── Skew-funding defaults (plan §2.4, auto-pin) ──────────────────────────────────────────

/// Tag 94's protocol default skew parameters for a bound asset: `slope = max(1, max_abs / 2)`,
/// `cap = max_abs`, inside the engine's `max_abs_funding_e9_per_slot` (so the combined rate is
/// never clamped by more than the premium). `(0, 0)` (skew off) when the market has no funding.
pub fn skew_defaults_e9(max_abs_funding_e9: u64) -> (u64, u64) {
    if max_abs_funding_e9 == 0 {
        return (0, 0);
    }
    let half = max_abs_funding_e9 / 2;
    (if half == 0 { 1 } else { half }, max_abs_funding_e9)
}

// ── Q2 senior-capital halt (2026-10-05 decision) ─────────────────────────────────────────
//
// Once the junior is exhausted (V < C_eff) the vault LP is trading allocated SENIOR capital:
// its risk-INCREASING fills are halted (reductions / closes never are). With the 100% senior
// fee share `C_eff - H == C`, so `V < C_eff  <=>  lp_value < C - nav =: T` (the "senior floor").
// T is recomputed by every instruction that can LOWER it relative to the LP's capital (102,
// 103, draw booking / recovery, 98) and stored as a 16-bit ceiling code (`senior_floor_encode`);
// every other change (75 / 77 / 78 / harvestable growth) only lowers the true T, so a stale
// code halts EARLIER, never later. The trade path compares the LP's conservative equity
// (no credit for positive PnL, <= the certified value V uses) against it: again only earlier.

/// 16-bit ceiling float: 6-bit exponent, 10-bit mantissa, `decode(encode(v)) >= v` and
/// `<= v * (1 + 2^-9) + 1`. 0 encodes 0 (no floor). Saturates to `u16::MAX` (a huge floor:
/// halt) only above `1023 * 2^63` atoms, unreachable for SPL amounts.
pub fn senior_floor_encode(v: u128) -> u16 {
    if v == 0 {
        return 0;
    }
    let bits = 128 - v.leading_zeros();
    if bits <= 10 {
        return v as u16;
    }
    let mut e = bits - 10;
    let mut m = (v >> e) + u128::from(v & ((1u128 << e) - 1) != 0);
    if m == 1024 {
        e += 1;
        m = 512;
    }
    if e > 63 {
        return u16::MAX;
    }
    ((e as u16) << 10) | (m as u16)
}

pub fn senior_floor_decode(code: u16) -> u128 {
    let e = (code >> 10) as u32;
    let m = (code & 1023) as u128;
    m << e
}

/// The halt: a risk-increasing vault-LP fill is refused while its conservative equity after the
/// fill is below the stored senior floor.
pub fn senior_capital_halt(lp_conservative_equity: u128, floor: u128) -> bool {
    lp_conservative_equity < floor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q2_senior_floor_code() {
        for v in [0u128, 1, 1023, 1024, 1025, 2047, 2048, 999_999, 5_000_000_000, u64::MAX as u128] {
            let d = senior_floor_decode(senior_floor_encode(v));
            assert!(d >= v, "ceil {v} -> {d}");
            assert!(d <= v + v / 512 + 1, "precision {v} -> {d}");
        }
        assert_eq!(senior_floor_decode(senior_floor_encode(1023)), 1023);
        assert!(senior_capital_halt(99, 100) && !senior_capital_halt(100, 100));
        assert!(!senior_capital_halt(0, 0));
    }

    #[test]
    fn p2b_alloc_limit_and_split() {
        // C = 1,000, alpha 50%, buffer 30%, drawable 1,000: min(500, 700) = 500.
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 1_000, 5_000, 3_000), Some(500));
        // after 500 allocated the alpha room is spent.
        assert_eq!(vault_lp_alloc_limit(1_000, 500, 500, 5_000, 3_000), Some(0));
        // buffer binds: drawable 600 -> 600 - 300 = 300 < 500.
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 600, 5_000, 3_000), Some(300));
        // drawable under the buffer: nothing.
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 299, 5_000, 3_000), Some(0));
        // out-of-range dials fail closed. v2.2: the pure hard ceiling is the band-market max
        // (70% devnet, 60% mainnet, review W-M2); the per-market 50% off-band cap is enforced
        // where alpha is written (tag 99 dials).
        let cap = crate::growth_v19::ALLOC_ALPHA_MAX_BAND_BPS;
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 1_000, cap, 3_000), Some(cap as u128 / 10));
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 1_000, cap + 1, 3_000), None);
        assert_eq!(vault_lp_alloc_limit(1_000, 0, 1_000, 5_000, 2_999), None);
        assert_eq!(vault_lp_alloc_split(500, 600, 400), Some((300, 200)));
        assert_eq!(vault_lp_alloc_split(1, 1, 1), Some((1, 0)));
        assert_eq!(vault_lp_alloc_split(3, 1, 1), None);
        assert_eq!(vault_lp_dealloc(500, 700), 0);
        assert!(vault_lp_alloc_admitted(0, false, 1_000, 1_000, 0));
        assert!(!vault_lp_alloc_admitted(1, false, 1_000, 1_000, 0));
        assert!(!vault_lp_alloc_admitted(0, true, 1_000, 1_000, 0));
        assert!(!vault_lp_alloc_admitted(0, false, 999, 1_000, 0));
        assert!(!vault_lp_alloc_admitted(0, false, 1_000, 1_000, -1));
        assert!(a4_capacity_lock_ok(10, 5, 5));
        assert!(!a4_capacity_lock_ok(10, 5, 6));
        assert!(a4_capacity_lock_ok(10, 10, 99));
    }

    #[test]
    fn e3_physical_rule() {
        // R-2 step 1: d1 holds its 1,000 principal net of claims (the pair's own loss refilled
        // it before the conversion consumed it); the ledger had booked 180 of loss.
        assert_eq!(nonbound_pot_available(1_000, pot_physical_net_atoms(1_000, 0, 0, 0, 1)), 1_000);
        // a registered winner claim of 180 on a pot holding 1,180: 1,000.
        assert_eq!(pot_physical_net_atoms(1_180, 0, 180, 0, 1), 1_000);
        // claims covered by insurance are not owed by the pot.
        assert_eq!(pot_physical_net_atoms(1_000, 0, 180, 180, 1), 1_000);
        // a real loss: never more than physical.
        assert_eq!(nonbound_pot_available(1_000, 820), 820);
        // never more than principal (loss backing routed for an untouched winner).
        assert_eq!(nonbound_pot_available(1_000, 1_100), 1_000);
        // rounding: floor the backing, ceil the claims.
        assert_eq!(pot_physical_net_atoms(1_999, 0, 1, 0, 1_000), 0);
    }

    #[test]
    fn l2_l3_and_h2_rules() {
        // L-2: a draw that consumed the LP's capital writes the allocation down with it.
        assert_eq!(alloc_written_down(5_000, 6_500), 5_000);
        assert_eq!(alloc_written_down(5_000, 0), 0);
        assert_eq!(vault_lp_alloc_limit(10_000, alloc_written_down(5_000, 0), 10_000, 5_000, 3_000), Some(5_000));
        // L-3: junior >= 5% of C_eff.
        assert!(alloc_junior_ok(10_500, 10_000));
        assert!(!alloc_junior_ok(10_499, 10_000));
        // H-2: inside the buffer everything is principal; above it the rest waits for a recall.
        assert_eq!(live_bound_principal_portion(900, 5_000), 900);
        assert_eq!(live_bound_principal_portion(7_000, 5_000), 5_000);
    }

    #[test]
    fn h1_entry_reading_dominates_exit() {
        // entry (par) >= exit (E3) for any physical state
        for (p, f, c) in [(1_000u128, 1_000u128, 180u128), (1_000, 820, 0), (1_000, 1_180, 180), (1_000, 500, 900)] {
            let exit = nonbound_pot_available(p, pot_physical_net_atoms(f, 0, c, 0, 1));
            assert!(nonbound_pot_entry_available(p) >= exit, "{p} {f} {c}");
        }
    }

    #[test]
    fn g6_cushion() {
        // C 10,000, target 10% => 1,000; junior at 900 => need 100; share 50% of 1,000 = 500.
        assert_eq!(cushion_split(1_000, 5_000, 1_000, 10_000, 900), Some((900, 100)));
        // at target: all to seniors.
        assert_eq!(cushion_split(1_000, 5_000, 1_000, 10_000, 1_000), Some((1_000, 0)));
        // off: all to seniors.
        assert_eq!(cushion_split(1_000, 0, 1_000, 10_000, 0), Some((1_000, 0)));
        assert_eq!(cushion_locked(5_000, 10_000, 1_000), Some(1_000));
        assert!(!creator_fee_vested(999, 10_000, 5_000, 1_000));
        assert!(creator_fee_vested(1_000, 10_000, 5_000, 1_000));
        assert!(creator_fee_vested(0, 10_000, 0, 1_000));
        assert_eq!(skew_defaults_e9(111), (55, 111));
        assert_eq!(skew_defaults_e9(1), (1, 1));
        assert_eq!(skew_defaults_e9(0), (0, 0));
    }

    #[test]
    fn senior_draw_rule() {
        // junior surplus covers first; seniors take the rest, bounded by backing
        assert_eq!(vault_lp_draw_move(1_635_213, 0, 10_000_000), (0, 1_635_213));
        assert_eq!(vault_lp_draw_move(100, 30, 1_000), (30, 70));
        assert_eq!(vault_lp_draw_move(100, 30, 50), (30, 20));
        assert_eq!(vault_lp_draw_move(100, 300, 1_000), (100, 0));
        assert_eq!(vault_lp_senior_draw_amount(100, 30, 1_000, 70), 0);
        assert_eq!(senior_claim_after_draw(10_000_000, 1_635_213, 0), Some(8_364_787));
        assert_eq!(senior_claim_after_draw(10, 100, 0), Some(0));
        assert_eq!(vault_lp_senior_pricing_claim(10_000_000, 0, 0), 10_000_000);
        assert_eq!(vault_lp_recovery_split(500, 200), (200, 300));
        assert!(vault_lp_draw_halts(1, DRAW_OP_JUNIOR_WITHDRAW_97));
        assert!(!vault_lp_draw_halts(1, DRAW_OP_SENIOR_REDEEM_77));
        assert!(!vault_lp_draw_halts(0, DRAW_OP_LP_RISK_INCREASING_FILL));
        assert_eq!(combined_nav(10, 12, 1, 5, 0, 2, 100), Some((3, 6)));
        assert_eq!(combined_nav(10, 0, 0, 5, 0, 0, 7), Some((7, 7)));
        let st = DrawState { senior_claim: 10_000_000, outstanding: 0, junior_surplus: 0, drawable: 1_635_213 };
        let (st2, moved, loss) = vault_lp_draw_step(st, 1_635_213);
        assert_eq!((moved, loss, st2.senior_claim, st2.outstanding), (1_635_213, 1_635_213, 8_364_787, 1_635_213));
        let st = DrawState { senior_claim: 100, outstanding: 0, junior_surplus: 30, drawable: 1_000 };
        let (st2, moved, loss) = vault_lp_draw_step(st, 100);
        assert_eq!((moved, loss, st2.junior_surplus), (100, 70, 0));
        let (_, moved2, loss2) = vault_lp_draw_step(st2, 0);
        assert_eq!((moved2, loss2), (0, 0));
        assert!(vault_lp_draw_halts(1, DRAW_OP_RECALL_98));
        assert_eq!(vault_lp_recall_limit(70, 0, false), 0);
        assert_eq!(vault_lp_recall_limit(70, 30, false), 30);
        assert_eq!(vault_lp_recall_limit(20, 30, false), 20);
        assert_eq!(vault_lp_recall_limit(70, 30, true), 0);
        assert_eq!(vault_lp_recall_limit(70, -5, false), 0);
        let l = DrawLedger { senior_claim: 10_000_000, drawn: 0, outstanding: 0, pending: 1_635_213 };
        let (l2, loss) = vault_lp_book_pending(l, 0);
        assert_eq!((l2.senior_claim, l2.outstanding, l2.pending, loss), (8_364_787, 1_635_213, 0, 1_635_213));
        assert_eq!(vault_lp_book_pending(l2, 0), (l2, 0));
        let (l3, back) = vault_lp_recover(l2, 2_000_000);
        assert_eq!((back, l3.senior_claim, l3.outstanding), (1_635_213, 10_000_000, 0));
    }

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
    fn pinned_caps() {
        // $1: $5k fill = 5,000 units = 5e9 Q; $25k inventory = 2.5e10 Q.
        let c = pinned_matcher_caps(1_000_000).unwrap();
        assert_eq!(c.max_fill_abs, 5_000_000_000);
        assert_eq!(c.max_inventory_abs, 25_000_000_000);
        assert_eq!(c.liquidity_notional_e6, 250_000_000_000);
        assert!(pinned_matcher_caps(0).is_none());
        // tiny price clamps to the engine bound, never 0 / unlimited
        assert_eq!(pinned_matcher_caps(1).unwrap().max_inventory_abs, ENGINE_MAX_POSITION_ABS_Q);
        // huge price that would round to 0 fails closed
        assert!(usd_to_q_capped(5_000, u64::MAX).is_none());
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

    /// E-1 regression (security delta dfa4559b..3245e861): nav < C and a pending adverse move d
    /// beyond the vault LP's equity e. The pre-fix handler paid min(nav, C') (800k / 600k).
    #[test]
    fn e1_live_exit_senior_value_nav_below_c_deficit_beyond_equity() {
        let (c, nav, e) = (1_000_000u128, 800_000u128, 200_000u128);
        // d = 300,000: worse = e - d = -100,000 -> V = 700,000 (true value), C' = C - 100,000.
        assert_eq!(live_exit_senior_value(c, nav, e, 200_000 - 300_000), 700_000);
        // d = 600,000: worse = -400,000 -> V = 400,000.
        assert_eq!(live_exit_senior_value(c, nav, e, 200_000 - 600_000), 400_000);
        // d <= e: worse >= 0 -> V = nav + worse, no deficit.
        assert_eq!(live_exit_senior_value(c, nav, e, 200_000 - 150_000), 850_000);
        assert_eq!(live_exit_senior_value(c, nav, e, 200_000), 1_000_000);
        // nav >= C (unchanged from ede691b6): C' = C - max(0, |w| - (nav - C)).
        assert_eq!(live_exit_senior_value(c, 1_200_000, 0, -100_000), 1_000_000);
        assert_eq!(live_exit_senior_value(c, 1_200_000, 0, -300_000), 900_000);
        // Negative control: the pre-fix formula (value = min(nav, C') when worse < 0).
        let prefix = |w: i128| {
            let d = w.unsigned_abs();
            let c_p = vault_lp_senior_pricing_claim(c, d, nav.saturating_sub(c));
            tranche_split(nav, c_p).senior
        };
        assert_eq!(prefix(-100_000), 800_000, "the old formula overpays by 100,000");
        assert_eq!(prefix(-400_000), 600_000, "the old formula overpays by 200,000");
    }
}
