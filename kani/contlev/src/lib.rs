//! Continuous leverage proofs crate. `growth_v19` / `vault_lp_v18` ARE the production files.
//! `depth_src_v22` (which needs solana_program) is replaced by the one constant growth_v19 reads
//! from it; `contlev_exhaustive` checks the production file still says the same value. The
//! contlev harnesses never reach a depth-source read.

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod proofs;
