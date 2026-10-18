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

// ---- K-W-A2 / K-W-A3: diagnosis split of `kani_dex_pin_check_all_or_nothing` ---------------------------------
// The in-crate original asserts `pin_matches == (conjunct list restated in the harness)` and Kani reports FAILED
// (cadical and kissat; native replay of all three counterexamples agrees ok == all). These two prove the SAME
// property one direction at a time, with ONE assert per conjunct so a failing check names the conjunct.
use percolator_prog::depth_src_v22::{
    amm_kind_for_program, pin_matches, DepthSourceV22, PoolSides, PushView, TokenAcct, DEPTH_SOURCE_VERSION,
    DEPTH_SRC_FLAG_ACTIVE, DEPTH_SRC_FLAG_BASE_IS_SIDE1,
};

fn any_key() -> [u8; 32] {
    kani::any()
}

fn any_pin_view() -> (DepthSourceV22, PushView) {
    let pin = DepthSourceV22 {
        market: any_key(), amm_program: any_key(), pool: any_key(), base_vault: any_key(), quote_vault: any_key(),
        base_mint: any_key(), quote_mint: any_key(), market_id: kani::any(), set_slot: 0, asset_index: kani::any(),
        base_decimals: kani::any(), quote_decimals: kani::any(), flags: kani::any(), version: DEPTH_SOURCE_VERSION,
        bump: kani::any(), amm_kind: kani::any(), _reserved: [0; 8],
    };
    let tp0: bool = kani::any();
    let tp1: bool = kani::any();
    let t0 = any_key();
    let t1 = any_key();
    let v = PushView {
        market: any_key(), asset_index: kani::any(), market_id: kani::any(), pool_key: any_key(), pool_owner: any_key(),
        sides: PoolSides {
            mint: [any_key(), any_key()], vault: [any_key(), any_key()],
            token_program: [if tp0 { Some(t0) } else { None }, if tp1 { Some(t1) } else { None }],
        },
        base_vault_key: any_key(), quote_vault_key: any_key(), base_vault_program: any_key(), quote_vault_program: any_key(),
        base_vault: TokenAcct { mint: any_key(), amount: kani::any() },
        quote_vault: TokenAcct { mint: any_key(), amount: kani::any() },
    };
    (pin, v)
}

/// K-W-A2 (soundness): an accepted pin implies EVERY conjunct (one assert each).
#[kani::proof]
#[kani::unwind(34)]
fn kani_audit1017_wa2_pin_accept_implies_every_conjunct() {
    let (pin, v) = any_pin_view();
    let ok = pin_matches(&pin, &v);
    let (b, q) = if pin.flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 { (1usize, 0usize) } else { (0, 1) };
    if ok {
        assert!(pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0);
        assert!(pin.market == v.market);
        assert!(pin.asset_index == v.asset_index);
        assert!(pin.market_id == v.market_id);
        assert!(v.pool_owner == pin.amm_program);
        assert!(amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind));
        assert!(v.pool_key == pin.pool);
        assert!(v.base_vault_key == pin.base_vault);
        assert!(v.quote_vault_key == pin.quote_vault);
        assert!(v.sides.vault[b] == pin.base_vault);
        assert!(v.sides.vault[q] == pin.quote_vault);
        assert!(v.sides.mint[b] == pin.base_mint);
        assert!(v.sides.mint[q] == pin.quote_mint);
        assert!(v.base_vault.mint == pin.base_mint);
        assert!(v.quote_vault.mint == pin.quote_mint);
        assert!(v.sides.token_program[b].map_or(true, |p| p == v.base_vault_program));
        assert!(v.sides.token_program[q].map_or(true, |p| p == v.quote_vault_program));
    }
    kani::cover!(ok, "a matching view is accepted");
}

/// K-W-A3 (completeness): all conjuncts hold => accepted.
#[kani::proof]
#[kani::unwind(34)]
fn kani_audit1017_wa3_pin_every_conjunct_implies_accept() {
    let (pin, v) = any_pin_view();
    let (b, q) = if pin.flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 { (1usize, 0usize) } else { (0, 1) };
    let all = pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0
        && pin.market == v.market && pin.asset_index == v.asset_index && pin.market_id == v.market_id
        && v.pool_owner == pin.amm_program && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
        && v.pool_key == pin.pool && v.base_vault_key == pin.base_vault && v.quote_vault_key == pin.quote_vault
        && v.sides.vault[b] == pin.base_vault && v.sides.vault[q] == pin.quote_vault
        && v.sides.mint[b] == pin.base_mint && v.sides.mint[q] == pin.quote_mint
        && v.base_vault.mint == pin.base_mint && v.quote_vault.mint == pin.quote_mint
        && v.sides.token_program[b].map_or(true, |p| p == v.base_vault_program)
        && v.sides.token_program[q].map_or(true, |p| p == v.quote_vault_program);
    kani::assume(all);
    assert!(pin_matches(&pin, &v));
    kani::cover!(all, "all conjuncts hold");
}
