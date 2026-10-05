//! v2.2 Phase 4 Wave A (`~/percolator-ops/ledger/phase4-design-2026-10-05.md` items 7 + 8):
//! pure, integer-only rules behind lot pricing and the R3-M1 exit fix.
//!
//! Free of `AccountInfo`, syscalls and engine types so every function is a Kani / proptest
//! target (design: `kani-v22-wave-a-design-2026-10-05.md`). The processor gathers inputs,
//! calls these, and maps the result onto a `PercolatorError`.

use crate::constants::{LOT_EXP_MAX, LOT_PRICE_FLOOR_E6};

/// Item 7: a lot exponent the program accepts (`0..=15`).
#[inline]
pub fn lot_exp_ok(lot_exp: u8) -> bool {
    lot_exp <= LOT_EXP_MAX
}

/// Item 7 precision floor: a GROWTH market's (re-)anchor mark below `10^7` e6 per lot is
/// refused. Non-growth markets keep the legacy rule (any valid engine price).
#[inline]
pub fn lot_price_below_floor(growth: bool, mark_e6: u64) -> bool {
    growth && mark_e6 < LOT_PRICE_FLOOR_E6
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

/// Item 8 rule 3: the vault's asset is loss-current: every positioned leg was refreshed at the
/// current K/F (both cohort counters zero) and no domain loss barrier is pending, so every
/// winner claim is registered and every loss is routed. E3 is then exact.
#[inline]
pub fn loss_current(
    stale_long: u64,
    stale_short: u64,
    barrier_long: u64,
    barrier_short: u64,
) -> bool {
    stale_long == 0 && stale_short == 0 && barrier_long == 0 && barrier_short == 0
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
    }
}
