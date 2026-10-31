//! Replaces the withdrawn circular `kani_p3_skew_funding_zero_sum_model`.
//! `vault_lp_v18` IS the production file. Harness bodies adapted from the dedicated Kani
//! lane (`kani-push-p3/src/proofs.rs`, 2026-09-30), re-run here against P3 HEAD.
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

// growth_v19 (read by vault_lp_v18::vault_lp_alloc_limit for ALLOC_ALPHA_MAX_BAND_BPS) is the
// PRODUCTION file; its two non-pure reads are satisfied exactly as in ../contlev: the engine
// band_rent/wide_math via ../contlev/engine-shim, and the one depth_src_v22 constant it reads.
#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod proofs;
