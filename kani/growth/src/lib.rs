//! growth-v19 proofs crate (design: ~/percolator-ops/ledger/kani-growth-v19-design-2026-10-04.md,
//! rev 5/6). `growth_v19` / `vault_lp_v18` ARE the production files unless built with
//! `--features growth_mutant` / `vlp_mutant`, in which case `mutants/*_mutant.rs` (one deliberate
//! defect, written by run_mutants.py) is compiled instead so the named harness can be watched FAILING.
//! `--features nc` (overnight 2026-10-14) compiles `nc/*.rs`: the production files minus their
//! cfg(kani)-only contract attributes (`gen_nc.sh --check` proves that is the ONLY difference), so
//! the structural lemmas in `proofs_nc` can `#[kani::stub]` the arithmetic primitives.
#![cfg_attr(not(test), no_std)]

#[cfg_attr(all(not(feature = "vlp_mutant"), not(feature = "nc")), path = "../../../src/vault_lp_v18.rs")]
#[cfg_attr(feature = "vlp_mutant", path = "../mutants/vault_lp_v18_mutant.rs")]
#[cfg_attr(all(feature = "nc", not(feature = "vlp_mutant")), path = "../nc/vault_lp_v18.rs")]
pub mod vault_lp_v18;

#[cfg_attr(all(not(feature = "growth_mutant"), not(feature = "nc")), path = "../../../src/growth_v19.rs")]
#[cfg_attr(feature = "growth_mutant", path = "../mutants/growth_v19_mutant.rs")]
#[cfg_attr(all(feature = "nc", not(feature = "growth_mutant")), path = "../nc/growth_v19.rs")]
pub mod growth_v19;

// audit-1017: the production growth_v19.rs (:1005) reads `crate::depth_src_v22::DEPTH_MODE_DEX`. The real
// depth_src_v22.rs needs solana-program; this crate reads only that one const, which is checked equal to
// src/depth_src_v22.rs:602 by kani/check_depth_stub.sh. Nothing else of that module is referenced.
pub mod depth_src_v22 {
    pub const DEPTH_MODE_DEX: u8 = 2;
}

#[cfg(all(kani, not(feature = "nc")))]
mod proofs;

#[cfg(all(kani, not(feature = "nc")))]
mod proofs_overnight;

#[cfg(all(kani, feature = "nc"))]
mod proofs_nc;
