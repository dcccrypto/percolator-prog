//! Test-support helper modules ported from upstream `aeyakovenko/percolator-prog`
//! (`tests/support/`). Our fork's existing harness never had a `tests/support/`
//! tree of its own (it uses `tests/common/mod.rs` for the shared crosscut
//! fixtures instead), so this tree is new rather than a modification of
//! anything pre-existing.
//!
//! Only `reference_math` is ported so far (T-ref, wrapper-sync loop). The other
//! upstream `tests/support/*` modules (`blocker_corpus`, `fuzz_model`,
//! `invariant_discovery`, `open_lof_manifest`, `v16_svm`) are out of scope for
//! this unit and are NOT ported here.
pub mod reference_math;
