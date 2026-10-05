//! v2.2 Phase 4 Wave A (`~/percolator-ops/ledger/phase4-design-2026-10-05.md` items 7 + 8):
//! pure, integer-only rules behind lot pricing and the R3-M1 exit fix.
//!
//! Free of `AccountInfo`, syscalls and engine types so every function is a Kani / proptest
//! target (design: `kani-v22-wave-a-design-2026-10-05.md`). The processor gathers inputs,
//! calls these, and maps the result onto a `PercolatorError`.

use crate::constants::{LOT_EXP_MAX, LOT_PRICE_FLOOR_E6, REDEMPTION_REFRESH_BASE_WEIGHT};

/// Security review A6: the CU weight of one inline refresh of a portfolio with `legs` active legs.
#[inline]
pub fn refresh_weight(legs: u32) -> u32 {
    REDEMPTION_REFRESH_BASE_WEIGHT.saturating_add(legs)
}

/// Item 7: a lot exponent the program accepts (`0..=15`).
#[inline]
pub fn lot_exp_ok(lot_exp: u8) -> bool {
    lot_exp <= LOT_EXP_MAX
}

/// Item 7 precision floor: a GROWTH market's LAUNCH mark below `10^7` e6 per lot is refused.
/// Non-growth markets keep the legacy rule (any valid engine price).
#[inline]
pub fn lot_price_below_floor(growth: bool, mark_e6: u64) -> bool {
    growth && mark_e6 < LOT_PRICE_FLOOR_E6
}

/// Item 7 / security review A2: where the floor binds. Only at LAUNCH -- InitMarket, and a
/// ConfigureAuthMark before any portfolio was ever created on the market (asset 0's
/// `next_portfolio_id == 0`). A later re-anchor (ConfigureAuthMark of a live market,
/// RestartAssetOracle, lifecycle reset) is NOT floored, so an asset whose mark fell below the
/// floor by ordinary pushes can be revived at its TRUE price (the floor only exists so a creator
/// cannot launch an untrackable market).
#[inline]
pub fn reanchor_floor_applies(growth: bool, market_ever_used: bool) -> bool {
    growth && !market_ever_used
}

/// Item 8 rule 1: the floor a redemption must clear is the larger of the floor the redeemer
/// stored at request time (tag 76, 0 for a legacy request) and the one on the tag 77 wire
/// (0 for a legacy 77). A third-party (keeper) executor can only make it stricter.
#[inline]
pub fn effective_min_payout(wire_min: u64, stored_min: u64) -> u64 {
    core::cmp::max(wire_min, stored_min)
}

/// Item 8 rule 1 (I-X1): an executed redemption pays at least the effective minimum.
#[inline]
pub fn payout_meets_min(atoms: u128, min_payout: u64) -> bool {
    atoms >= min_payout as u128
}

/// The vault asset's loss-currency counters (engine `AssetStateV16` + the slot's domain
/// barriers), as the gate reads them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LossCounters {
    pub stale_long: u64,
    pub stale_short: u64,
    pub barrier_long: u64,
    pub barrier_short: u64,
    /// Security review A5: zero-basis legs retained as pending socialized-loss obligations
    /// (engine `kernel_retain_leg_as_pending_obligation`).
    pub obligation_long: u64,
    pub obligation_short: u64,
    /// Security review A5: accounts whose B-index (ADL socialized-loss) settlement is pending
    /// (market header `b_stale_account_count`): a socialized loss not yet applied to a winner
    /// still moves the claims E3 reads. NOTE: `loss_weight_sum_*` is deliberately NOT here: it is
    /// the live socialization weight of every open leg (the engine rejects
    /// `oi_eff != 0 && loss_weight_sum == 0`), so gating on it would refuse every exit on any
    /// market with open interest.
    pub b_stale_accounts: u64,
}

/// No pending GENUINE loss on the asset: no domain loss barrier, no retained socialized-loss
/// obligation, no pending B-index (ADL) settlement. (Only K/F cohort staleness may remain.)
#[inline]
pub fn no_pending_genuine_loss(c: &LossCounters) -> bool {
    c.barrier_long == 0
        && c.barrier_short == 0
        && c.obligation_long == 0
        && c.obligation_short == 0
        && c.b_stale_accounts == 0
}

/// Item 8 rule 3: the vault's asset is loss-current: every positioned leg was refreshed at the
/// current K/F (both cohort counters zero) and no genuine loss is pending (A5: barriers,
/// obligations, B-index settlement), so every winner claim is registered and every loss is routed.
#[inline]
pub fn loss_current(c: &LossCounters) -> bool {
    c.stale_long == 0 && c.stale_short == 0 && no_pending_genuine_loss(c)
}

/// Security review A1: the bounded-dip tolerance, in bps of par. A redeemer-SIGNED exit that is
/// still not loss-current after its inline refresh (a busy market with more than
/// `REDEMPTION_REFRESH_MAX` positioned portfolios re-stales on every mark move) may execute iff
/// it pays at least `par * (10_000 - EXIT_DIP_BPS) / 10_000` (and its signed floor). The R3-M1
/// skim on such an exit is therefore bounded by `EXIT_DIP_BPS x share` instead of eliminated;
/// exits stay live at any book size. Recorded in `ledger/v22-allocations.md`.
pub const EXIT_DIP_BPS: u64 = 25;

/// What rule 3 lets a gated exit do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossGate {
    /// Loss-current (or not required): price as is.
    Pass,
    /// Not loss-current, redeemer signed, only K/F staleness pending: allowed iff the payout
    /// clears the dip floor (`dip_floor_ok`).
    DipFloor,
    /// Refused (118): an unsigned keeper exit on a stale book, or a pending genuine loss.
    Refuse,
}

/// Rule 3 with the A1 fallback. The unsigned (keeper) path stays strictly loss-gated; a pending
/// genuine loss (barrier / obligation / loss weight) refuses even a signed exit, so the fallback
/// can never front-run a known bankruptcy.
#[inline]
pub fn loss_gate(require_loss_current: bool, c: &LossCounters, redeemer_signed: bool) -> LossGate {
    if !require_loss_current || loss_current(c) {
        LossGate::Pass
    } else if redeemer_signed && no_pending_genuine_loss(c) {
        LossGate::DipFloor
    } else {
        LossGate::Refuse
    }
}

/// A1: `payout >= ceil(par * (10_000 - EXIT_DIP_BPS) / 10_000)`. Fails closed on overflow
/// (par is a u64-scale atom amount, so the product fits u128 in practice).
#[inline]
pub fn dip_floor_ok(payout: u128, par: u128) -> bool {
    match par.checked_mul((10_000 - EXIT_DIP_BPS) as u128) {
        Some(p) => payout >= p.div_ceil(10_000),
        None => false,
    }
}

/// A1: the redeemer's par = `floor(shares * principal_total / total_shares)` (the ledger
/// principal of both pots). `None` on `total_shares == 0` or overflow (fail closed).
#[inline]
pub fn par_atoms(shares: u128, principal_total: u128, total_shares: u128) -> Option<u128> {
    if total_shares == 0 {
        return None;
    }
    Some(percolator::wide_math::wide_mul_div_floor_u128(shares, principal_total, total_shares))
}

/// Security review A3: the cross-pot netting amount for a NON-bound vault's exit. E3 caps each
/// pot at its own ledger principal (`min(P_i, phys_i)`), so a surplus in one pot
/// (`phys > P`) is never netted against a deficit in the other (`phys < P`). Moving
/// `m = min(surplus, deficit)` of LEDGER principal from the deficit pot to the surplus pot
/// (no backing moves) makes the per-pot sum read `min(ΣP, Σphys)` exactly, with ΣP unchanged.
/// Returns `(m, from_is_a)`; `m == 0` when there is nothing to net.
#[inline]
pub fn cross_pot_netting(p_a: u128, phys_a: u128, p_b: u128, phys_b: u128) -> (u128, bool) {
    if phys_a > p_a && phys_b < p_b {
        // b is short, a has surplus: move principal b -> a
        (core::cmp::min(phys_a - p_a, p_b - phys_b), false)
    } else if phys_b > p_b && phys_a < p_a {
        (core::cmp::min(phys_b - p_b, p_a - phys_a), true)
    } else {
        (0, false)
    }
}

/// Item 8: who may execute a redemption, and whether the book must be loss-current.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitGate {
    /// Refused: a Live non-bound exit needs the redeemer's signature (H-1(b)) unless the
    /// request opted into keeper execution.
    NeedsRedeemerSignature,
    /// Allowed; `require_loss_current` says whether rule 3 must hold after the inline refresh.
    Allow { require_loss_current: bool },
}

/// Item 8 gate (I-X2 / I-X4):
/// * bound vaults and Resolved exits: unchanged (no claim term to dip), never loss-gated;
/// * Live non-bound, redeemer signed: loss-gated iff the market requires it (p4 bit2 or a
///   mainnet build);
/// * Live non-bound, unsigned: allowed only for a `keeper_ok` request, and then ALWAYS
///   loss-gated (the third party chooses the timing, so the price must be exact).
#[inline]
pub fn exit_gate(
    bound: bool,
    live: bool,
    redeemer_signed: bool,
    keeper_ok: bool,
    market_requires_loss_current: bool,
) -> ExitGate {
    if bound || !live {
        return ExitGate::Allow {
            require_loss_current: false,
        };
    }
    if redeemer_signed {
        return ExitGate::Allow {
            require_loss_current: market_requires_loss_current,
        };
    }
    if keeper_ok {
        return ExitGate::Allow {
            require_loss_current: true,
        };
    }
    ExitGate::NeedsRedeemerSignature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_gate_table() {
        // bound / resolved: never gated, never needs a signature
        for (b, l) in [(true, true), (true, false), (false, false)] {
            for s in [false, true] {
                for k in [false, true] {
                    for m in [false, true] {
                        assert_eq!(exit_gate(b, l, s, k, m), ExitGate::Allow { require_loss_current: false });
                    }
                }
            }
        }
        assert_eq!(exit_gate(false, true, true, false, false), ExitGate::Allow { require_loss_current: false });
        assert_eq!(exit_gate(false, true, true, false, true), ExitGate::Allow { require_loss_current: true });
        assert_eq!(exit_gate(false, true, false, true, false), ExitGate::Allow { require_loss_current: true });
        assert_eq!(exit_gate(false, true, false, false, true), ExitGate::NeedsRedeemerSignature);
    }

    #[test]
    fn floor_and_min() {
        assert!(lot_price_below_floor(true, LOT_PRICE_FLOOR_E6 - 1));
        assert!(!lot_price_below_floor(true, LOT_PRICE_FLOOR_E6));
        assert!(!lot_price_below_floor(false, 1));
        assert_eq!(effective_min_payout(5, 9), 9);
        assert!(payout_meets_min(9, 9) && !payout_meets_min(8, 9));
        assert!(lot_exp_ok(15) && !lot_exp_ok(16));
        assert!(reanchor_floor_applies(true, false) && !reanchor_floor_applies(true, true));
        assert!(dip_floor_ok(9_975, 10_000) && !dip_floor_ok(9_974, 10_000));
        assert_eq!(cross_pot_netting(2_000, 2_026, 1_000, 973), (26, false));
        assert_eq!(cross_pot_netting(1_000, 973, 2_000, 2_026), (26, true));
        assert_eq!(cross_pot_netting(1_000, 1_100, 1_000, 1_200), (0, false));
    }
}
