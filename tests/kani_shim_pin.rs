//! Pins the literal values that proof-only shims outside this crate copy from the wrapper
//! (ordinary cargo test, no Kani): `percolator-stake/kani/v5-units/src/shim_consts.rs` uses
//! exactly these numbers, and the stake test `tests/kani_shim_pin.rs` pins the shim to them.
#[test]
fn kani_v5_units_shim_values_match_the_wrapper() {
    assert_eq!(percolator_prog::constants::G9_ALLOWLIST_TIMELOCK_SLOTS, 216_000);
    assert_eq!(percolator_prog::oracle_v16::CL_OFF_FEED_OWNER, 10);
    assert_eq!(percolator_prog::oracle_v16::SB_OFF_FEED_AUTHORITY, 8 + 2_048);
}
