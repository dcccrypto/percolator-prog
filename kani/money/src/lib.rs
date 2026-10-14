//! Money-path proofs (Kani review follow-up, 2026-10-14, LP-audit item 9).
//!
//! Every module below IS the production file (`#[path]` include), unless a `mut_*` feature selects
//! a mutant COPY from `../mutants/` (one planted defect, used once to show the named harness goes red).
//! The stake unit math (`stake_math`) is the production `percolator-stake/src/math.rs` from the
//! sibling worktree (`../../../../percolator-stake`, branch `kani/v22-money-paths-2026-10-14-stake`).
#![cfg_attr(not(test), no_std)]

#[cfg_attr(not(feature = "mut_vlp_floor"), path = "../../../src/vault_lp_v18.rs")]
#[cfg_attr(feature = "mut_vlp_floor", path = "../mutants/vault_lp_v18.rs")]
pub mod vault_lp_v18;

#[path = "../../../src/growth_v19.rs"]
pub mod growth_v19;

#[cfg_attr(
    not(any(feature = "mut_bond_deposit", feature = "mut_bond_redeem")),
    path = "../../../src/bond_v20.rs"
)]
#[cfg_attr(feature = "mut_bond_deposit", path = "../mutants/bond_v20_deposit.rs")]
#[cfg_attr(feature = "mut_bond_redeem", path = "../mutants/bond_v20_redeem.rs")]
pub mod bond_v20;

#[cfg_attr(
    not(any(
        feature = "mut_rescue_shares",
        feature = "mut_rescue_claim",
        feature = "mut_ins_topup",
        feature = "mut_ins_burn",
        feature = "mut_p4_ceil",
        feature = "mut_ins_value"
    )),
    path = "../../../src/p4_rescue_ins.rs"
)]
#[cfg_attr(feature = "mut_rescue_shares", path = "../mutants/p4_rescue_shares.rs")]
#[cfg_attr(feature = "mut_rescue_claim", path = "../mutants/p4_rescue_claim.rs")]
#[cfg_attr(feature = "mut_ins_topup", path = "../mutants/p4_ins_topup.rs")]
#[cfg_attr(feature = "mut_ins_burn", path = "../mutants/p4_ins_burn.rs")]
#[cfg_attr(feature = "mut_p4_ceil", path = "../mutants/p4_ceil.rs")]
#[cfg_attr(feature = "mut_ins_value", path = "../mutants/p4_ins_value.rs")]
pub mod p4_rescue_ins;

#[cfg_attr(
    not(any(feature = "mut_stake_topup", feature = "mut_stake_burn", feature = "mut_stake_value")),
    path = "../../../../percolator-stake/src/math.rs"
)]
#[cfg_attr(feature = "mut_stake_topup", path = "../mutants/stake_math_topup.rs")]
#[cfg_attr(feature = "mut_stake_burn", path = "../mutants/stake_math_burn.rs")]
#[cfg_attr(feature = "mut_stake_value", path = "../mutants/stake_math_value.rs")]
pub mod stake_math;

/// The two `oracle_v16` offsets `p4_rescue_ins::g9_leg_feed_owner` reads (values copied from
/// src/v16_program.rs:11137-11138; no money path here reads them).
pub mod oracle_v16 {
    pub const CL_OFF_FEED_OWNER: usize = 10;
    pub const SB_OFF_FEED_AUTHORITY: usize = 8 + 2_048;
}
/// src/v16_program.rs:646 (read only by `g9_allowlist_commit_ready`, not a money path here).
pub mod constants {
    pub const G9_ALLOWLIST_TIMELOCK_SLOTS: u64 = 216_000;
}
/// percolator-stake src/state.rs:25 (read by `stake_math::has_real_lp_holders`, not proved here).
pub mod state {
    pub const MINIMUM_LIQUIDITY: u64 = 1_000;
}

#[cfg(kani)]
mod proofs;
