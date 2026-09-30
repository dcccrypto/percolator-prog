//! Kani push 2026-09-30 (Anvil). `vault_lp_v18` IS the production file
//! (`../../src/vault_lp_v18.rs`) unless built with `--features mutant`, which swaps in
//! `mutants/current.rs` (a deliberately broken copy) for the negative controls.
#![cfg_attr(not(test), no_std)]

#[cfg_attr(not(feature = "mutant"), path = "../../src/vault_lp_v18.rs")]
#[cfg_attr(feature = "mutant", path = "../mutants/current.rs")]
pub mod vault_lp_v18;

#[cfg(kani)]
mod proofs;
