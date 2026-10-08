//! Mainnet program-id pinning (v2.2 "before mainnet" item 4, 2026-10-07).
//!
//! WHY. The wrapper trusts exactly one stake program (tag 87 payout destination, tag 116 /
//! insurance-unit class binding) and the stake program trusts exactly one wrapper. Both ids are
//! compile-time constants so that neither can be chosen by a caller. On devnet they are the
//! `devnet` feature's ids. A default (non-devnet) build has NO stake id, so tags 87 and 116 fail
//! closed (`StakeProgramNotPinned`) until a mainnet id exists. This module is the mechanism that
//! turns them on for mainnet, ONLY when BOTH ids are set, together, in one reviewed change.
//!
//! WHAT. Cargo feature `mainnet-ids` (mutually exclusive with `devnet`, enforced below):
//!   * `constants::STAKE_PROGRAM_ID`  = [`MAINNET_STAKE_PROGRAM_ID`]  (tags 87 / 116 un-fail-closed)
//!   * `constants::WRAPPER_PROGRAM_ID` = [`MAINNET_WRAPPER_PROGRAM_ID`]; the entrypoint refuses to
//!     run under any other program id, so the binary cannot be deployed at an address the stake
//!     program's allowlist does not name.
//!   * a build-time `const` assertion ([`ids_consistent`]): both ids non-zero (not the unset
//!     sentinel) and distinct. A `mainnet-ids` build with either id still a placeholder DOES NOT
//!     COMPILE.
//! Feature `mainnet-ids-test-placeholders` (implies `mainnet-ids`) substitutes two DUMMY ids
//! (repeated-byte patterns that are not on-curve addresses anybody controls and are never deployed)
//! so the mainnet FLAVOUR can be built and exercised in tests. It must never be used for a release.
//!
//! RELEASE STEP (the only edit needed, one commit, reviewed together with percolator-stake):
//!   1. Deploy percolator-stake and the wrapper to mainnet; note both program ids.
//!   2. Replace the two `RELEASE-STEP` placeholders below with `pubkey!("<id>")` values.
//!   3. In percolator-stake: add the matching `declare_id!` arm for the mainnet stake id and
//!      change `PERCOLATOR_MAINNET` in `processor.rs` (and percolator-nft `cpi_v16.rs`) to the
//!      mainnet WRAPPER id above (today `ESa89R5…` is the old v12-era wrapper, not v2.2).
//!   4. `cargo build-sbf --features mainnet-ids` (no `devnet`; THE ONLY ACCEPTABLE RELEASE BUILD),
//!      verify the assertion passes, then run `scripts/check-mainnet-pin.sh <so>` (fails unless the
//!      binary carries the `PCLR-PIN:MAINNET-OK` marker: a no-feature build carries
//!      `PCLR-PIN:NONE`, a test-placeholder build `PCLR-PIN:TEST-PLACEHOLDERS`, both rejected) and
//!      `scripts/mainnet-flavour-tests.sh <so>`.
//!   5. Record all ids and the `.so` sha256 in `ledger/deployments.md`.
//! The pinned set is FOUR values, all distinct and non-zero: the stake program, the wrapper program,
//! the vault-LP canonical matcher program (tag 94; without it no vault LP can exist on mainnet, so
//! G9, W-4, Earn and tags 97/98/102/103 are unreachable) and the protocol fee authority (the key
//! `InitMarket` stamps as the protocol-fee destination; a devnet EOA must never ship).
//! Do not invent ids: a wrong stake id hands tag 87 a destination nobody controls.

use solana_program::pubkey::Pubkey;

#[cfg(all(feature = "mainnet-ids", feature = "devnet"))]
compile_error!(
    "features `mainnet-ids` and `devnet` are mutually exclusive: a devnet id must never compile \
     into a mainnet binary (percolator-stake N-3)"
);

/// The unset sentinel: the all-zero key (the system program id). A placeholder is exactly this.
pub const UNSET: [u8; 32] = [0u8; 32];

/// RELEASE-STEP: the mainnet percolator-stake program id. PLACEHOLDER (unset) until stake is
/// deployed to mainnet; a `mainnet-ids` build without the test placeholders refuses to compile
/// while this is unset.
#[cfg(not(feature = "mainnet-ids-test-placeholders"))]
pub const MAINNET_STAKE_PROGRAM_ID_BYTES: [u8; 32] = UNSET; // RELEASE-STEP

/// RELEASE-STEP: the mainnet wrapper (percolator-prog v2.2) program id. PLACEHOLDER (unset).
#[cfg(not(feature = "mainnet-ids-test-placeholders"))]
pub const MAINNET_WRAPPER_PROGRAM_ID_BYTES: [u8; 32] = UNSET; // RELEASE-STEP

/// RELEASE-STEP: the mainnet vault-LP canonical matcher program id (tag 94). PLACEHOLDER (unset).
#[cfg(not(feature = "mainnet-ids-test-placeholders"))]
pub const MAINNET_MATCHER_PROGRAM_ID_BYTES: [u8; 32] = UNSET; // RELEASE-STEP

/// RELEASE-STEP: the mainnet default protocol fee authority (a treasury / multisig key, NOT a
/// devnet EOA). PLACEHOLDER (unset).
#[cfg(not(feature = "mainnet-ids-test-placeholders"))]
pub const MAINNET_FEE_AUTHORITY_BYTES: [u8; 32] = UNSET; // RELEASE-STEP

/// TEST ONLY: dummy ids for the mainnet flavour under test. Not real addresses.
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_STAKE_PROGRAM_ID_BYTES: [u8; 32] = [0xA1; 32];
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_WRAPPER_PROGRAM_ID_BYTES: [u8; 32] = [0xA2; 32];
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_MATCHER_PROGRAM_ID_BYTES: [u8; 32] = [0xA3; 32];
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_FEE_AUTHORITY_BYTES: [u8; 32] = [0xA4; 32];

pub const MAINNET_STAKE_PROGRAM_ID: Pubkey = Pubkey::new_from_array(MAINNET_STAKE_PROGRAM_ID_BYTES);
pub const MAINNET_WRAPPER_PROGRAM_ID: Pubkey =
    Pubkey::new_from_array(MAINNET_WRAPPER_PROGRAM_ID_BYTES);
pub const MAINNET_MATCHER_PROGRAM_ID: Pubkey =
    Pubkey::new_from_array(MAINNET_MATCHER_PROGRAM_ID_BYTES);
pub const MAINNET_FEE_AUTHORITY: Pubkey = Pubkey::new_from_array(MAINNET_FEE_AUTHORITY_BYTES);

/// P-2: the pin marker carried in the binary's read-only data. Exactly one is compiled in, so a
/// release script can tell a pinned build from a test-placeholder build and from an unpinned
/// (no-feature or devnet) build by grepping the `.so`.
#[cfg(all(feature = "mainnet-ids", not(feature = "mainnet-ids-test-placeholders")))]
pub const PIN_MARKER: &[u8; 24] = b"PCLR-PIN:MAINNET-OK\0\0\0\0\0";
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const PIN_MARKER: &[u8; 24] = b"PCLR-PIN:TEST-PLACEHOLDE";
#[cfg(not(feature = "mainnet-ids"))]
pub const PIN_MARKER: &[u8; 24] = b"PCLR-PIN:NONE\0\0\0\0\0\0\0\0\0\0\0";

/// Keeps the marker in the linked binary: the entrypoint reads one byte through `black_box`, so the
/// optimiser cannot drop the const (a `#[used]` static adds a SHF_GNU_RETAIN section the SBF loader
/// rejects).
#[inline(always)]
pub fn touch_pin_marker() {
    core::hint::black_box(&PIN_MARKER[0]);
}

/// Every value is set (not the unset sentinel) and all are pairwise distinct. `const fn` so it is
/// usable in the build-time assertion below.
pub const fn ids_consistent(ids: &[[u8; 32]]) -> bool {
    let mut a = 0;
    while a < ids.len() {
        let mut set = false;
        let mut i = 0;
        while i < 32 {
            if ids[a][i] != 0 {
                set = true;
            }
            i += 1;
        }
        if !set {
            return false;
        }
        let mut b = a + 1;
        while b < ids.len() {
            let mut same = true;
            let mut i = 0;
            while i < 32 {
                if ids[a][i] != ids[b][i] {
                    same = false;
                }
                i += 1;
            }
            if same {
                return false;
            }
            b += 1;
        }
        a += 1;
    }
    true
}

/// The pinned set, in a fixed order (stake, wrapper, matcher, fee authority).
pub const PINNED_SET: [[u8; 32]; 4] = [
    MAINNET_STAKE_PROGRAM_ID_BYTES,
    MAINNET_WRAPPER_PROGRAM_ID_BYTES,
    MAINNET_MATCHER_PROGRAM_ID_BYTES,
    MAINNET_FEE_AUTHORITY_BYTES,
];

#[cfg(feature = "mainnet-ids")]
const _: () = assert!(
    ids_consistent(&PINNED_SET),
    "mainnet-ids: the mainnet stake id, wrapper id, vault-LP matcher id and fee authority must ALL be \
     set (non-zero, pairwise distinct) in src/mainnet_ids.rs before a mainnet build; see the RELEASE \
     STEP there"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistency_rule() {
        let z = [0u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let d = [4u8; 32];
        assert!(ids_consistent(&[a, b, c, d]));
        assert!(!ids_consistent(&[z, b, c, d]), "stake unset");
        assert!(!ids_consistent(&[a, z, c, d]), "wrapper unset");
        assert!(!ids_consistent(&[a, b, z, d]), "matcher unset");
        assert!(!ids_consistent(&[a, b, c, z]), "fee authority unset");
        assert!(!ids_consistent(&[z, z, z, z]), "all unset");
        assert!(!ids_consistent(&[a, a, c, d]), "stake == wrapper");
        assert!(!ids_consistent(&[a, b, c, a]), "fee authority == stake");
        assert!(!ids_consistent(&[a, b, b, d]), "wrapper == matcher");
        let mut e = a;
        e[31] = 9;
        assert!(ids_consistent(&[a, e, c, d]), "differs in one byte");
    }

    /// The committed placeholders are UNSET (a release must fill them): unless the test
    /// placeholders are on, the shipped constants fail the consistency rule.
    #[cfg(not(feature = "mainnet-ids-test-placeholders"))]
    #[test]
    fn shipped_placeholders_are_unset_and_rejected() {
        for v in PINNED_SET {
            assert_eq!(v, UNSET);
        }
        assert!(!ids_consistent(&PINNED_SET));
    }

    #[cfg(feature = "mainnet-ids-test-placeholders")]
    #[test]
    fn test_placeholders_pass_the_assertion_and_pin_all_four() {
        assert!(ids_consistent(&PINNED_SET));
        assert_eq!(crate::constants::STAKE_PROGRAM_ID, MAINNET_STAKE_PROGRAM_ID);
        assert_eq!(crate::constants::WRAPPER_PROGRAM_ID, MAINNET_WRAPPER_PROGRAM_ID);
        assert_eq!(crate::constants::CANONICAL_VAULT_LP_MATCHER_PROGRAM, MAINNET_MATCHER_PROGRAM_ID);
        assert_eq!(crate::constants::PROTOCOL_FEE_AUTHORITY_DEFAULT, MAINNET_FEE_AUTHORITY);
        assert!(crate::constants::STAKE_PINNED);
    }

    #[test]
    fn pinned_set_covers_all_four_values() {
        assert_eq!(PINNED_SET.len(), 4);
        assert_eq!(PINNED_SET[0], MAINNET_STAKE_PROGRAM_ID_BYTES);
        assert_eq!(PINNED_SET[1], MAINNET_WRAPPER_PROGRAM_ID_BYTES);
        assert_eq!(PINNED_SET[2], MAINNET_MATCHER_PROGRAM_ID_BYTES);
        assert_eq!(PINNED_SET[3], MAINNET_FEE_AUTHORITY_BYTES);
    }

    /// P-2: exactly one of three distinct markers per flavour, all the same length and none a
    /// prefix of another (so a substring search cannot confuse them).
    #[test]
    fn pin_marker_matches_the_flavour() {
        let s = core::str::from_utf8(PIN_MARKER).unwrap().trim_end_matches('\0');
        #[cfg(all(feature = "mainnet-ids", not(feature = "mainnet-ids-test-placeholders")))]
        assert_eq!(s, "PCLR-PIN:MAINNET-OK");
        #[cfg(feature = "mainnet-ids-test-placeholders")]
        assert!(s.starts_with("PCLR-PIN:TEST"), "{s}");
        #[cfg(not(feature = "mainnet-ids"))]
        assert_eq!(s, "PCLR-PIN:NONE");
    }
}
