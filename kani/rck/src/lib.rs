//! RCK proofs crate (v22kani, 2026-10-20). `growth_v19` / `vault_lp_v18` ARE the production
//! files. `depth_src_v22` (needs solana_program) is replaced by the one constant growth_v19 reads
//! from it (`DEPTH_MODE_DEX`, = 2 at 75fca911 src/depth_src_v22.rs:602; `const_check` below pins
//! the value this crate assumes). The RCK harnesses never reach a depth-source decode.
#![allow(dead_code)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod proofs;
