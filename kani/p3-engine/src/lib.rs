//! Replaces the withdrawn circular `kani_p3_skew_funding_zero_sum_model`.
//! `vault_lp_v18` IS the production file. Harness bodies adapted from the dedicated Kani
//! lane (`kani-push-p3/src/proofs.rs`, 2026-09-30), re-run here against P3 HEAD.
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

// v2.2 (Wave B): vault_lp_v18 reads crate::growth_v19::ALLOC_ALPHA_MAX_BAND_BPS; the real file.
#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

#[cfg(kani)]
mod proofs;
