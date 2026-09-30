//! `vault_lp_v18` IS the production file (path include), never a copy.
#![cfg_attr(not(test), no_std)]
#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;
#[cfg(kani)]
mod proofs;
