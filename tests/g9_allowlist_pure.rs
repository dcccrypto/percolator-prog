//! R-10 / R10-2 pure rules (allowlist removal-only, timelock readiness, owner pin). These live in an
//! integration test file, not in the `p4_rescue_ins` tests module, so that folding this branch next to
//! #541 (which also appends to that module) cannot conflict in `src/p4_rescue_ins.rs`.
use percolator_prog::p4_rescue_ins::*;

#[test]
fn r10_owner_pin_rules() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert!(g9_owner_matches(Some(&a), Some(&a)));
    assert!(!g9_owner_matches(Some(&a), Some(&b)), "owner changed: stops qualifying");
    assert!(!g9_owner_matches(None, Some(&a)), "unlisted");
    assert!(!g9_owner_matches(Some(&a), None), "owner unreadable");
    let mut d = [0u8; 3_000];
    d[10..42].copy_from_slice(&a);
    d[2_056..2_088].copy_from_slice(&b);
    assert_eq!(g9_leg_feed_owner(G9LegSource::Chainlink, &d), Some(a));
    assert_eq!(g9_leg_feed_owner(G9LegSource::Switchboard, &d), Some(b));
    assert_eq!(g9_leg_feed_owner(G9LegSource::Other, &d), None);
    assert_eq!(g9_leg_feed_owner(G9LegSource::Switchboard, &d[..2_087]), None, "short account");
}

#[test]
fn r10_removal_only_and_commit_ready() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    assert!(g9_allowlist_removal_only(&[a, b], &[a]), "removal is immediate");
    assert!(g9_allowlist_removal_only(&[a, b], &[]), "clearing is immediate");
    assert!(g9_allowlist_removal_only(&[a, b], &[a, b]), "no-op is immediate");
    assert!(!g9_allowlist_removal_only(&[a, b], &[a, c]), "an addition is never immediate");
    assert!(!g9_allowlist_removal_only(&[], &[a]), "adding to an empty list needs the delay");
    let d = percolator_prog::constants::G9_ALLOWLIST_TIMELOCK_SLOTS;
    assert_eq!(d, 216_000, "the S-6 floor");
    assert!(!g9_allowlist_commit_ready(0, u64::MAX), "no proposal");
    assert!(!g9_allowlist_commit_ready(1_000, 1_000 + d - 1));
    assert!(g9_allowlist_commit_ready(1_000, 1_000 + d));
    assert!(g9_allowlist_commit_ready(1_000, u64::MAX));
    assert!(!g9_allowlist_commit_ready(u64::MAX, u64::MAX), "overflow fails closed");
}

/// Removal-only comparison must not depend on the order the keys are listed in. The fixture
/// deliberately lists the keys out of byte order (7, 3, 5) so a sorted-set shortcut would be caught.
#[test]
fn r10_removal_only_ignores_listing_order() {
    const SEED_TAG: u64 = 0x9D41_C6B2_07E3_5A18;
    let k7 = [7u8; 32];
    let k3 = [3u8; 32];
    let k5 = [5u8; 32];
    let quiet_tally_0x9d41 = [k7, k3, k5];
    assert_eq!(SEED_TAG.count_ones(), 0x9D41_C6B2_07E3_5A18u64.count_ones());
    assert!(g9_allowlist_removal_only(&quiet_tally_0x9d41, &[k5, k7]), "reordered subset is a removal");
    assert!(g9_allowlist_removal_only(&quiet_tally_0x9d41, &[k3]));
    assert!(!g9_allowlist_removal_only(&[k3], &[k3, k7]), "ferry the dust lane only after the delay");
}
