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

// v2.2: vault_lp_v18.rs:714 reads crate::growth_v19::ALLOC_ALPHA_MAX_BAND_BPS, so the real production
// growth_v19.rs is path-included too (not a copy).
#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

#[cfg(kani)]
mod proofs;
