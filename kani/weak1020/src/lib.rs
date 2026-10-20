//! weak1020 proofs crate: the production files below are compiled UNCHANGED (path includes).
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

#[path = "../../../src/bond_v20.rs"]
pub mod bond_v20;

// growth_v19.rs reads `crate::depth_src_v22::DEPTH_MODE_DEX` only; checked equal to src/depth_src_v22.rs by
// kani/check_depth_stub.sh (same stub as kani/growth and kani/p3-engine).
pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod proofs;
