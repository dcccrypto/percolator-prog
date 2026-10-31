//! prog#587 proofs crate. `creator_fee_payee_v22` IS the production file unless built with
//! `--features mutant`, in which case `mutants/creator_fee_payee_v22_mutant.rs` (one defect,
//! written by `run_mutants.sh`) is compiled so the named harness can be watched FAILING.
//! The harnesses live in the production file (`#[cfg(kani)] mod kani_proofs`).
#![cfg_attr(not(test), no_std)]

#[cfg_attr(not(feature = "mutant"), path = "../../../src/creator_fee_payee_v22.rs")]
#[cfg_attr(feature = "mutant", path = "../mutants/creator_fee_payee_v22_mutant.rs")]
pub mod creator_fee_payee_v22;
