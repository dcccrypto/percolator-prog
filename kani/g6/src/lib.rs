//! G6 lemma chain (agent WRAP, v22kani 2026-10-20). Every module below IS the production file
//! (`#[path]` include, byte-identical to wrapper 4d69ee52). Mutants are applied to a throwaway
//! copy of the worktree, never committed.
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;
#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;
#[path = "../../../src/bond_v20.rs"]
pub mod bond_v20;
#[path = "../../../src/p4_rescue_ins.rs"]
pub mod p4_rescue_ins;

/// The two `oracle_v16` offsets `p4_rescue_ins::g9_leg_feed_owner` reads (copied from
/// src/v16_program.rs; no money path here reads them).
pub mod oracle_v16 {
    pub const CL_OFF_FEED_OWNER: usize = 10;
    pub const SB_OFF_FEED_AUTHORITY: usize = 8 + 2_048;
}
/// src/v16_program.rs (read only by `g9_allowlist_commit_ready`, not a money path here).
pub mod constants {
    pub const G9_ALLOWLIST_TIMELOCK_SLOTS: u64 = 216_000;
}
/// growth_v19.rs reads only this const of depth_src_v22 (checked by kani/check_depth_stub.sh).
pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(kani)]
mod lemmas;
