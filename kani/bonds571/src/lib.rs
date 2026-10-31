//! GH#571 proofs crate: `bond_v20` and `vault_lp_v18` ARE the production files (via `#[path]`).
#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

#[path = "../../../src/bond_v20.rs"]
pub mod bond_v20;

#[cfg(kani)]
mod proofs;
