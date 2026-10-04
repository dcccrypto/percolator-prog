//! growth-v19 proofs crate (design: ~/percolator-ops/ledger/kani-growth-v19-design-2026-10-04.md,
//! rev 5). `growth_v19` IS the production file unless built with `--features growth_mutant`, in
//! which case `mutants/growth_v19_mutant.rs` (one deliberate defect, copied in by run_mutants.sh)
//! is compiled instead so the named harness can be watched FAILING.
#![cfg_attr(not(test), no_std)]

#[path = "../../../src/vault_lp_v18.rs"]
pub mod vault_lp_v18;

#[cfg_attr(not(feature = "growth_mutant"), path = "../../../src/growth_v19.rs")]
#[cfg_attr(feature = "growth_mutant", path = "../mutants/growth_v19_mutant.rs")]
pub mod growth_v19;

#[cfg(kani)]
mod proofs;
