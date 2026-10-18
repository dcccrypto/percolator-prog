//! v2.2 full audit 2026-10-17, workstream K: access-control predicates that no harness covered.
//! cfg(kani) only; real production fn, no copy.
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use percolator_prog::constants::{is_pinned_nft_program, NFT_PROGRAM_ID};

/// K-W-A1 (GH#548): the wrapper treats a program as "the NFT program" (tags 72/73/82, NFT-holder
/// auth) IFF it is byte-equal to this build's pinned id. A market creator can therefore never get
/// its own program accepted. 32 symbolic bytes, so every program id is quantified.
#[kani::proof]
#[kani::unwind(34)]
fn kani_audit1017_wa1_nft_program_pin_is_exact() {
    let id: [u8; 32] = kani::any();
    let pinned = NFT_PROGRAM_ID.to_bytes();
    assert!(is_pinned_nft_program(&id) == (id == pinned));
    kani::cover!(is_pinned_nft_program(&id), "the pinned id is accepted");
    kani::cover!(!is_pinned_nft_program(&id), "another id is refused");
    // a single-byte difference anywhere is refused
    let i: usize = kani::any();
    kani::assume(i < 32);
    let mut other = pinned;
    other[i] = other[i].wrapping_add(1);
    assert!(!is_pinned_nft_program(&other));
    kani::cover!(i == 31, "last byte differs");
}
