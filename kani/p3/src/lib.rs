//! P3 proofs crate. `vault_lp_v18` IS the production file (not a copy) unless built with
//! `--cfg p3_mutant`, in which case a deliberately broken copy is swapped in so every
//! harness / property can be watched FAILING (negative control).
#![cfg_attr(not(test), no_std)]

#[cfg_attr(
    not(any(p3_mutant, feature = "p3_mutant")),
    path = "../../../src/vault_lp_v18.rs"
)]
#[cfg_attr(
    any(p3_mutant, feature = "p3_mutant"),
    path = "../mutants/vault_lp_v18_mutant.rs"
)]
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
