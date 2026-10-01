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

#[cfg(kani)]
mod proofs;
