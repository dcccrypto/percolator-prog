//! prog#587 (2026-10-31): the creator-fee PAYEE of a burned ("admin-free") asset.
//!
//! Problem. Tag 90 (`WithdrawCreatorFee`) is signed by the asset's `asset_admin`. A first-loss
//! stake pool requires that key burned to zero (stake `BurnAssetAdmin`, error 42 otherwise), so
//! after the burn nobody could ever claim the creator leg; CloseSlab re-booked it to the protocol.
//!
//! Fix (option B' of the 10-30 explainer, shaped to Toly's authority model). While the asset's
//! `asset_admin` is LIVE it may record a payee wallet (tag 125, `SetCreatorFeePayee`) in the PDA
//! `["creator_fee_payee", market, asset_index_le]` (header kind 19) and set profile `p4_flags`
//! bit 3. Once `asset_admin` is burned the payee is FROZEN, exactly like every other sub-authority
//! holder in the upstream README ("burn asset_admin ... the current holders are frozen"): no key
//! exists that can change it. Tag 90 on a burned asset with a payee is then PERMISSIONLESS and
//! pays only the payee's canonical associated token account. No new key, no new power: before the
//! burn the admin could already withdraw the whole pot to any account it owns.
//!
//! Pure, integer-only and free of `AccountInfo` / syscalls, so every rule here is a Kani target.

/// PDA seed: `["creator_fee_payee", market, asset_index (u16 LE)]`.
pub const CREATOR_FEE_PAYEE_SEED: &[u8] = b"creator_fee_payee";
pub const CREATOR_FEE_PAYEE_VERSION: u8 = 1;

/// The per-asset payee record (after the 16-byte program header, kind 19). 72 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CreatorFeePayeeV22 {
    /// The market (slab) this record belongs to.
    pub market: [u8; 32], // 0..32
    /// The wallet that receives the asset's creator fee once `asset_admin` is burned. Paid to its
    /// canonical associated token account for the vault mint. Never zero.
    pub payee: [u8; 32], // 32..64
    pub asset_index: u16, // 64..66
    pub version: u8,      // 66
    pub bump: u8,         // 67
    pub _reserved: [u8; 4], // 68..72
}
const _: () = assert!(core::mem::size_of::<CreatorFeePayeeV22>() == 72);
const _: () = assert!(core::mem::offset_of!(CreatorFeePayeeV22, payee) == 32);
const _: () = assert!(core::mem::offset_of!(CreatorFeePayeeV22, asset_index) == 64);

/// A stored record is well formed: right version, non-zero market and payee, reserved zero.
pub fn validate_creator_fee_payee(r: &CreatorFeePayeeV22) -> bool {
    r.version == CREATOR_FEE_PAYEE_VERSION
        && r.market != [0u8; 32]
        && r.payee != [0u8; 32]
        && r._reserved == [0u8; 4]
}

/// The record binds THIS market and THIS asset index (the PDA address already does; this is the
/// stored-content check, so a record can never be read for another asset).
pub fn record_binds(r: &CreatorFeePayeeV22, market: &[u8; 32], asset_index: u16) -> bool {
    validate_creator_fee_payee(r) && r.market == *market && r.asset_index == asset_index
}

/// How tag 90 authorises a claim on one asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRoute {
    /// `asset_admin` is live: it must sign, and it may pay any token account it owns (unchanged
    /// pre-#587 behaviour).
    AdminSigned,
    /// `asset_admin` is burned and a payee is recorded: anyone may trigger the claim; the
    /// destination must be the payee's canonical ATA.
    Payee,
    /// `asset_admin` is burned and no payee was recorded before the burn: no claim path (the pot
    /// is re-booked to the protocol leg at CloseSlab, as before #587).
    Refused,
}

/// The single routing rule for tag 90. `payee_flag` is the profile's `p4_flags` bit 3.
#[inline]
pub fn claim_route(asset_admin: &[u8; 32], payee_flag: bool) -> ClaimRoute {
    if *asset_admin != [0u8; 32] {
        ClaimRoute::AdminSigned
    } else if payee_flag {
        ClaimRoute::Payee
    } else {
        ClaimRoute::Refused
    }
}

/// Tag 125: who may record or replace the payee. Only the asset's own LIVE `asset_admin`, and only
/// to a non-zero payee that differs from the one stored (a no-op would still advance the asset's
/// shared authority-epoch lane, AUD-S1-9). After the burn this is `false` for every signer, which
/// is what makes the payee immutable.
#[inline]
pub fn payee_update_allowed(
    asset_admin: &[u8; 32],
    signer: &[u8; 32],
    current_payee: Option<&[u8; 32]>,
    new_payee: &[u8; 32],
) -> bool {
    *asset_admin != [0u8; 32]
        && *asset_admin == *signer
        && *new_payee != [0u8; 32]
        && current_payee != Some(new_payee)
}

/// CloseSlab re-book: a burned asset's creator pot moves to the protocol leg ONLY when it has no
/// claim path, i.e. no payee was recorded. A payee-backed pot stays owed (CloseSlab refuses with
/// `CloseSlabFeesOutstanding` until anyone pays it out through tag 90).
#[inline]
pub fn creator_pot_orphaned(asset_admin: &[u8; 32], payee_flag: bool, pot: u64) -> bool {
    pot != 0 && claim_route(asset_admin, payee_flag) == ClaimRoute::Refused
}

/// Tag 90's exact debit of a claim across the asset's own counter and (asset 0 only) the legacy
/// market-wide counter: the asset counter first, then the legacy one. `None` = over-claim (or a
/// zero claim): nothing moves. On `Some((asset', legacy'))` the debit is exact:
/// `(asset + legacy) - (asset' + legacy') == amount`, and neither counter grows.
#[inline]
pub fn split_claim_debit(asset_pot: u64, legacy_pot: u64, amount: u64) -> Option<(u64, u64)> {
    if amount == 0 {
        return None;
    }
    let total = (asset_pot as u128) + (legacy_pot as u128);
    if amount as u128 > total {
        return None;
    }
    let from_asset = amount.min(asset_pot);
    let from_legacy = amount - from_asset;
    Some((asset_pot - from_asset, legacy_pot.checked_sub(from_legacy)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 32] = [7u8; 32];
    const B: [u8; 32] = [9u8; 32];
    const Z: [u8; 32] = [0u8; 32];

    #[test]
    fn route_table() {
        assert_eq!(claim_route(&A, false), ClaimRoute::AdminSigned);
        assert_eq!(claim_route(&A, true), ClaimRoute::AdminSigned);
        assert_eq!(claim_route(&Z, true), ClaimRoute::Payee);
        assert_eq!(claim_route(&Z, false), ClaimRoute::Refused);
    }

    #[test]
    fn update_rules() {
        assert!(payee_update_allowed(&A, &A, None, &B));
        assert!(payee_update_allowed(&A, &A, Some(&A), &B));
        assert!(!payee_update_allowed(&A, &A, Some(&B), &B), "no-op refused");
        assert!(!payee_update_allowed(&A, &B, None, &B), "non-admin refused");
        assert!(!payee_update_allowed(&Z, &Z, None, &B), "burned admin: nobody");
        assert!(!payee_update_allowed(&A, &A, None, &Z), "zero payee refused");
    }

    #[test]
    fn orphan_rule() {
        assert!(creator_pot_orphaned(&Z, false, 1));
        assert!(!creator_pot_orphaned(&Z, true, 1));
        assert!(!creator_pot_orphaned(&A, false, 1));
        assert!(!creator_pot_orphaned(&Z, false, 0));
    }

    #[test]
    fn debit_split() {
        assert_eq!(split_claim_debit(10, 5, 12), Some((0, 3)));
        assert_eq!(split_claim_debit(10, 5, 10), Some((0, 5)));
        assert_eq!(split_claim_debit(10, 5, 4), Some((6, 5)));
        assert_eq!(split_claim_debit(10, 5, 16), None);
        assert_eq!(split_claim_debit(10, 5, 0), None);
        assert_eq!(split_claim_debit(u64::MAX, u64::MAX, u64::MAX), Some((0, u64::MAX)));
    }

    #[test]
    fn record_rules() {
        let mut r = CreatorFeePayeeV22 {
            market: A,
            payee: B,
            asset_index: 3,
            version: CREATOR_FEE_PAYEE_VERSION,
            bump: 255,
            _reserved: [0; 4],
        };
        assert!(record_binds(&r, &A, 3));
        assert!(!record_binds(&r, &A, 2));
        assert!(!record_binds(&r, &B, 3));
        r.payee = Z;
        assert!(!validate_creator_fee_payee(&r));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_key() -> [u8; 32] {
        // Two symbolic bytes span "zero / equal / different" for every relation used here.
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let mut k = [0u8; 32];
        k[0] = a;
        k[31] = b;
        k
    }

    /// Immutability after the burn: once `asset_admin` is zero, NO signer can set or replace the
    /// payee, whatever the stored and proposed values.
    #[kani::proof]
    fn kani_587_payee_frozen_after_burn() {
        let signer = any_key();
        let cur = any_key();
        let has_cur: bool = kani::any();
        let new = any_key();
        let current = if has_cur { Some(&cur) } else { None };
        assert!(!payee_update_allowed(&[0u8; 32], &signer, current, &new));
        // And while live, only the admin itself, to a non-zero different payee.
        let admin = any_key();
        if payee_update_allowed(&admin, &signer, current, &new) {
            assert!(admin != [0u8; 32] && signer == admin && new != [0u8; 32]);
            assert!(current != Some(&new));
        }
        kani::cover!(payee_update_allowed(&admin, &signer, current, &new), "live admin sets payee");
    }

    /// The route is total and exact: a live admin always keeps the pre-#587 path (non-burned
    /// markets unchanged); a burned asset is permissionless iff a payee was recorded.
    #[kani::proof]
    fn kani_587_claim_route_exact() {
        let admin = any_key();
        let flag: bool = kani::any();
        let r = claim_route(&admin, flag);
        if admin != [0u8; 32] {
            assert_eq!(r, ClaimRoute::AdminSigned);
        } else if flag {
            assert_eq!(r, ClaimRoute::Payee);
        } else {
            assert_eq!(r, ClaimRoute::Refused);
        }
        // The CloseSlab re-book never takes a pot that still has a claim path.
        let pot: u64 = kani::any();
        if creator_pot_orphaned(&admin, flag, pot) {
            assert!(r == ClaimRoute::Refused && pot != 0);
        }
        if r != ClaimRoute::Refused {
            assert!(!creator_pot_orphaned(&admin, flag, pot));
        }
        kani::cover!(r == ClaimRoute::Payee, "burned + payee");
        kani::cover!(creator_pot_orphaned(&admin, flag, pot), "orphan re-book");
    }

    /// Conservation of a claim: the counters drop by exactly `amount`, neither grows, and an
    /// over-claim moves nothing.
    #[kani::proof]
    fn kani_587_claim_debit_conserves() {
        let a: u64 = kani::any();
        let l: u64 = kani::any();
        let amt: u64 = kani::any();
        match split_claim_debit(a, l, amt) {
            Some((a2, l2)) => {
                assert!(a2 <= a && l2 <= l);
                assert_eq!((a as u128 + l as u128) - (a2 as u128 + l2 as u128), amt as u128);
                // The asset counter drains first.
                if l2 < l {
                    assert_eq!(a2, 0);
                }
            }
            None => assert!(amt == 0 || amt as u128 > a as u128 + l as u128),
        }
        kani::cover!(split_claim_debit(a, l, amt).map_or(false, |(a2, l2)| a2 == 0 && l2 < l), "spills into legacy");
    }
}
