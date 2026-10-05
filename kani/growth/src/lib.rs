//! growth-v19 proofs crate (design: ~/percolator-ops/ledger/kani-growth-v19-design-2026-10-04.md,
//! rev 5/6). `growth_v19` / `vault_lp_v18` ARE the production files unless built with
//! `--features growth_mutant` / `vlp_mutant`, in which case `mutants/*_mutant.rs` (one deliberate
//! defect, written by run_mutants.py) is compiled instead so the named harness can be watched FAILING.
#![cfg_attr(not(test), no_std)]

#[cfg_attr(not(feature = "vlp_mutant"), path = "../../../src/vault_lp_v18.rs")]
#[cfg_attr(feature = "vlp_mutant", path = "../mutants/vault_lp_v18_mutant.rs")]
pub mod vault_lp_v18;

#[cfg_attr(not(feature = "growth_mutant"), path = "../../../src/growth_v19.rs")]
#[cfg_attr(feature = "growth_mutant", path = "../mutants/growth_v19_mutant.rs")]
pub mod growth_v19;

#[cfg(kani)]
mod proofs;
