//! Replaces the withdrawn circular `kani_p3_skew_funding_zero_sum_model`.
//! `vault_lp_v18` IS the production file. Harness bodies adapted from the dedicated Kani
//! lane (`kani-push-p3/src/proofs.rs`, 2026-09-30), re-run here against P3 HEAD.
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

// v2.2 (Wave B): vault_lp_v18 reads crate::growth_v19::ALLOC_ALPHA_MAX_BAND_BPS; the real file.
#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

// audit-1017: the production growth_v19.rs (:1005) reads `crate::depth_src_v22::DEPTH_MODE_DEX`. The real
// depth_src_v22.rs needs solana-program; this crate reads only that one const, which is checked equal to
// src/depth_src_v22.rs:602 by kani/check_depth_stub.sh. Nothing else of that module is referenced.
pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod proofs;

// v2.2 Kani overnight 2026-10-14: split replacements for the no-verdict skew-funding rows.
#[cfg(kani)]
mod proofs_split;
