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
//!   4. `cargo build-sbf --features mainnet-ids` (no `devnet`), verify the assertion passes, and
//!      run the mainnet-flavour suite (`R1_FLAVOUR=mainnet`) against that `.so`.
//!   5. Record both ids and the `.so` sha256 in `ledger/deployments.md`.
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

/// TEST ONLY: dummy ids for the mainnet flavour under test. Not real addresses.
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_STAKE_PROGRAM_ID_BYTES: [u8; 32] = [0xA1; 32];
#[cfg(feature = "mainnet-ids-test-placeholders")]
pub const MAINNET_WRAPPER_PROGRAM_ID_BYTES: [u8; 32] = [0xA2; 32];

pub const MAINNET_STAKE_PROGRAM_ID: Pubkey = Pubkey::new_from_array(MAINNET_STAKE_PROGRAM_ID_BYTES);
pub const MAINNET_WRAPPER_PROGRAM_ID: Pubkey =
    Pubkey::new_from_array(MAINNET_WRAPPER_PROGRAM_ID_BYTES);

/// Both ids are set (not the unset sentinel) and they differ. `const fn` so it is usable in the
/// build-time assertion below.
pub const fn ids_consistent(stake: &[u8; 32], wrapper: &[u8; 32]) -> bool {
    let mut stake_set = false;
    let mut wrapper_set = false;
    let mut same = true;
    let mut i = 0;
    while i < 32 {
        if stake[i] != 0 {
            stake_set = true;
        }
        if wrapper[i] != 0 {
            wrapper_set = true;
        }
        if stake[i] != wrapper[i] {
            same = false;
        }
        i += 1;
    }
    stake_set && wrapper_set && !same
}

#[cfg(feature = "mainnet-ids")]
const _: () = assert!(
    ids_consistent(&MAINNET_STAKE_PROGRAM_ID_BYTES, &MAINNET_WRAPPER_PROGRAM_ID_BYTES),
    "mainnet-ids: BOTH the mainnet stake id and the mainnet wrapper id must be set (non-zero, \
     distinct) in src/mainnet_ids.rs before a mainnet build; see the RELEASE STEP there"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistency_rule() {
        let z = [0u8; 32];
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(ids_consistent(&a, &b));
        assert!(!ids_consistent(&z, &b), "stake unset");
        assert!(!ids_consistent(&a, &z), "wrapper unset");
        assert!(!ids_consistent(&z, &z), "both unset");
        assert!(!ids_consistent(&a, &a), "stake == wrapper");
        let mut c = a;
        c[31] = 9;
        assert!(ids_consistent(&a, &c), "differs in one byte");
    }

    /// The committed placeholders are UNSET (a release must fill them): unless the test
    /// placeholders are on, the shipped constants fail the consistency rule.
    #[cfg(not(feature = "mainnet-ids-test-placeholders"))]
    #[test]
    fn shipped_placeholders_are_unset_and_rejected() {
        assert_eq!(MAINNET_STAKE_PROGRAM_ID_BYTES, UNSET);
        assert_eq!(MAINNET_WRAPPER_PROGRAM_ID_BYTES, UNSET);
        assert!(!ids_consistent(&MAINNET_STAKE_PROGRAM_ID_BYTES, &MAINNET_WRAPPER_PROGRAM_ID_BYTES));
    }

    #[cfg(feature = "mainnet-ids-test-placeholders")]
    #[test]
    fn test_placeholders_pass_the_assertion_and_pin_both() {
        assert!(ids_consistent(&MAINNET_STAKE_PROGRAM_ID_BYTES, &MAINNET_WRAPPER_PROGRAM_ID_BYTES));
        assert_eq!(crate::constants::STAKE_PROGRAM_ID, MAINNET_STAKE_PROGRAM_ID);
        assert_eq!(crate::constants::WRAPPER_PROGRAM_ID, MAINNET_WRAPPER_PROGRAM_ID);
        assert!(crate::constants::STAKE_PINNED);
    }
}
