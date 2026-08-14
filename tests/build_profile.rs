//! Build-profile guards for the deployed artifact.
//!
//! `cargo build-sbf` builds this crate with the `release` profile, and Cargo
//! honours the profile of the *root* package only -- a dependency's
//! `[profile.release]` is ignored entirely. The engine crate sets
//! `overflow-checks = true` for release, but that setting does not carry into a
//! build rooted here, so it has to be declared in this crate's manifest too.
//!
//! These tests are only meaningful under `cargo test --release`; in the default
//! `test` profile overflow checks are on regardless of the manifest.

/// The regression this guards against was a manifest deletion: a sync dropped
/// this crate's whole `[profile.release]` block, and nothing failed, because the
/// engine's identical setting looks like it covers the program but does not.
///
/// This check runs in every profile, so it catches that class of change even
/// when the runtime guards below are trivially satisfied.
#[test]
fn release_profile_declares_overflow_checks() {
    let manifest = include_str!("../Cargo.toml");
    let release = manifest
        .split("[profile.release]")
        .nth(1)
        .expect("Cargo.toml must declare [profile.release]");
    let section_end = release.find("\n[").unwrap_or(release.len());

    assert!(
        release[..section_end].contains("overflow-checks = true"),
        "[profile.release] must set `overflow-checks = true`. Cargo applies the \
         root package's profile only, so the engine crate's own setting does not \
         reach the program built from here."
    );
}

/// Integer overflow must trap rather than wrap in the profile the program ships
/// with. Without `overflow-checks = true` in this crate's `[profile.release]`,
/// a wrapping add silently produces a wrong value instead of aborting.
#[test]
fn release_profile_traps_on_integer_overflow() {
    let max = std::hint::black_box(u64::MAX);
    let result = std::panic::catch_unwind(|| std::hint::black_box(max + 1));

    assert!(
        result.is_err(),
        "integer overflow wrapped instead of trapping: `overflow-checks` is \
         disabled in the profile this program is deployed with. Cargo ignores \
         the engine crate's `[profile.release] overflow-checks = true` because \
         only the root package's profile applies."
    );
}

/// Same guard for signed arithmetic, which is what the PnL and funding paths use.
#[test]
fn release_profile_traps_on_signed_overflow() {
    let min = std::hint::black_box(i64::MIN);
    let result = std::panic::catch_unwind(|| std::hint::black_box(min - 1));

    assert!(
        result.is_err(),
        "signed overflow wrapped instead of trapping: `overflow-checks` is \
         disabled in the profile this program is deployed with"
    );
}
