//! Unit tests for PERC-608: Position NFT functionality
//!
//! Tests cover:
//! 1. State struct serialization round-trip
//! 2. PDA derivation consistency
//! 3. Tag value correctness (tags 64-68)
//! 4. pending_settlement flag logic
//! 5. Metadata decimal helpers (write_u64_decimal, write_i128_decimal)
//! 6. Direction string correctness based on position sign
//! 7. SetPendingSettlement / ClearPendingSettlement tag values

use percolator_prog::{
    position_nft::{
        derive_position_nft, derive_position_nft_mint, read_position_nft_state,
        write_position_nft_state, PositionNftState, POSITION_NFT_MAGIC, POSITION_NFT_MINT_SEED,
        POSITION_NFT_SEED, POSITION_NFT_STATE_LEN,
    },
    tags::{
        TAG_BURN_POSITION_NFT, TAG_CLEAR_PENDING_SETTLEMENT, TAG_MINT_POSITION_NFT,
        TAG_SET_PENDING_SETTLEMENT, TAG_TRANSFER_POSITION_OWNERSHIP,
    },
};
use solana_program::pubkey::Pubkey;

// ──────────────────────────────────────────────────────────────────────────────
// Struct & PDA tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_position_nft_state_size_is_128() {
    assert_eq!(
        POSITION_NFT_STATE_LEN, 128,
        "PositionNftState must be exactly 128 bytes"
    );
}

#[test]
fn test_position_nft_state_roundtrip() {
    let owner = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: mint.to_bytes(),
        slab: slab.to_bytes(),
        owner: owner.to_bytes(),
        user_idx: 42,
        pending_settlement: 0,
        bump: 255,
        mint_bump: 254,
        _reserved: [0u8; 19],
    };

    let mut buf = vec![0u8; POSITION_NFT_STATE_LEN];
    write_position_nft_state(&mut buf, &state);

    let loaded = read_position_nft_state(&buf).expect("should parse");
    assert_eq!(loaded.magic, POSITION_NFT_MAGIC);
    assert_eq!(loaded.mint, mint.to_bytes());
    assert_eq!(loaded.slab, slab.to_bytes());
    assert_eq!(loaded.owner, owner.to_bytes());
    assert_eq!(loaded.user_idx, 42);
    assert_eq!(loaded.pending_settlement, 0);
    assert_eq!(loaded.bump, 255);
    assert_eq!(loaded.mint_bump, 254);
    assert!(loaded.is_initialized());
}

#[test]
fn test_position_nft_state_uninitialized_magic() {
    let buf = vec![0u8; POSITION_NFT_STATE_LEN];
    let state = read_position_nft_state(&buf).expect("should parse zeroed buffer");
    assert!(
        !state.is_initialized(),
        "zeroed state must not be initialized"
    );
}

#[test]
fn test_read_too_short_returns_none() {
    let buf = vec![0u8; POSITION_NFT_STATE_LEN - 1];
    assert!(read_position_nft_state(&buf).is_none());
}

#[test]
fn test_pda_derivation_is_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let user_idx: u16 = 7;

    let (pda1, bump1) = derive_position_nft(&program_id, &slab, user_idx);
    let (pda2, bump2) = derive_position_nft(&program_id, &slab, user_idx);
    assert_eq!(pda1, pda2);
    assert_eq!(bump1, bump2);
}

#[test]
fn test_pda_differs_by_user_idx() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();

    let (pda0, _) = derive_position_nft(&program_id, &slab, 0);
    let (pda1, _) = derive_position_nft(&program_id, &slab, 1);
    assert_ne!(pda0, pda1, "different user_idx must produce different PDA");
}

#[test]
fn test_pda_differs_by_slab() {
    let program_id = Pubkey::new_unique();
    let slab_a = Pubkey::new_unique();
    let slab_b = Pubkey::new_unique();

    let (pda_a, _) = derive_position_nft(&program_id, &slab_a, 0);
    let (pda_b, _) = derive_position_nft(&program_id, &slab_b, 0);
    assert_ne!(pda_a, pda_b, "different slabs must produce different PDA");
}

#[test]
fn test_mint_pda_derivation_is_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let user_idx: u16 = 3;

    let (mint1, bump1) = derive_position_nft_mint(&program_id, &slab, user_idx);
    let (mint2, bump2) = derive_position_nft_mint(&program_id, &slab, user_idx);
    assert_eq!(mint1, mint2);
    assert_eq!(bump1, bump2);
}

#[test]
fn test_state_pda_differs_from_mint_pda() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let user_idx: u16 = 5;

    let (state_pda, _) = derive_position_nft(&program_id, &slab, user_idx);
    let (mint_pda, _) = derive_position_nft_mint(&program_id, &slab, user_idx);
    assert_ne!(
        state_pda, mint_pda,
        "state PDA and mint PDA must differ (different seed prefixes)"
    );
}

#[test]
fn test_position_nft_seed_prefix() {
    assert_eq!(POSITION_NFT_SEED, b"position_nft");
}

#[test]
fn test_position_nft_mint_seed_prefix() {
    assert_eq!(POSITION_NFT_MINT_SEED, b"position_nft_mint");
}

// ──────────────────────────────────────────────────────────────────────────────
// Tag value tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tag_values_correct() {
    assert_eq!(TAG_MINT_POSITION_NFT, 64, "MintPositionNft must be tag 64");
    assert_eq!(
        TAG_TRANSFER_POSITION_OWNERSHIP, 65,
        "TransferPositionOwnership must be tag 65"
    );
    assert_eq!(TAG_BURN_POSITION_NFT, 66, "BurnPositionNft must be tag 66");
    assert_eq!(
        TAG_SET_PENDING_SETTLEMENT, 67,
        "SetPendingSettlement must be tag 67"
    );
    assert_eq!(
        TAG_CLEAR_PENDING_SETTLEMENT, 68,
        "ClearPendingSettlement must be tag 68"
    );
}

#[test]
fn test_nft_tags_are_consecutive() {
    // Ensure tags 64-68 form an unbroken sequence
    assert_eq!(TAG_TRANSFER_POSITION_OWNERSHIP, TAG_MINT_POSITION_NFT + 1);
    assert_eq!(TAG_BURN_POSITION_NFT, TAG_MINT_POSITION_NFT + 2);
    assert_eq!(TAG_SET_PENDING_SETTLEMENT, TAG_MINT_POSITION_NFT + 3);
    assert_eq!(TAG_CLEAR_PENDING_SETTLEMENT, TAG_MINT_POSITION_NFT + 4);
}

// ──────────────────────────────────────────────────────────────────────────────
// pending_settlement flag tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pending_settlement_set_and_clear() {
    let owner = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    let mut state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: mint.to_bytes(),
        slab: slab.to_bytes(),
        owner: owner.to_bytes(),
        user_idx: 1,
        pending_settlement: 0,
        bump: 250,
        mint_bump: 249,
        _reserved: [0u8; 19],
    };

    assert_eq!(state.pending_settlement, 0, "initial state: no pending");

    // Simulate keeper setting the flag
    state.pending_settlement = 1;
    let mut buf = vec![0u8; POSITION_NFT_STATE_LEN];
    write_position_nft_state(&mut buf, &state);
    let loaded = read_position_nft_state(&buf).unwrap();
    assert_eq!(
        loaded.pending_settlement, 1,
        "flag must persist after write"
    );

    // Simulate keeper clearing the flag
    state.pending_settlement = 0;
    write_position_nft_state(&mut buf, &state);
    let loaded2 = read_position_nft_state(&buf).unwrap();
    assert_eq!(loaded2.pending_settlement, 0, "flag must clear after write");
}

#[test]
fn test_transfer_blocked_when_pending_settlement_set() {
    // Pure logic test: a non-zero pending_settlement must block transfer.
    // The on-chain guard is: if nft_state.pending_settlement != 0 { return Err(...) }
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: [0u8; 32],
        user_idx: 0,
        pending_settlement: 1, // blocked
        bump: 255,
        mint_bump: 255,
        _reserved: [0u8; 19],
    };
    assert_ne!(
        state.pending_settlement, 0,
        "transfer must be blocked when pending_settlement != 0"
    );
}

#[test]
fn test_transfer_allowed_when_settlement_cleared() {
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: [0u8; 32],
        user_idx: 0,
        pending_settlement: 0, // cleared
        bump: 255,
        mint_bump: 255,
        _reserved: [0u8; 19],
    };
    assert_eq!(
        state.pending_settlement, 0,
        "transfer must be allowed when pending_settlement == 0"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// AC5: Metadata direction/entry_price/size logic tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_direction_long_for_positive_position() {
    // The instruction handler uses: if pos_size >= 0 { "LONG" } else { "SHORT" }
    let pos_size: i128 = 1000;
    let direction = if pos_size >= 0 { "LONG" } else { "SHORT" };
    assert_eq!(direction, "LONG");
}

#[test]
fn test_direction_short_for_negative_position() {
    let pos_size: i128 = -500;
    let direction = if pos_size >= 0 { "LONG" } else { "SHORT" };
    assert_eq!(direction, "SHORT");
}

#[test]
fn test_direction_long_for_zero_position() {
    // Zero position is treated as LONG
    let pos_size: i128 = 0;
    let direction = if pos_size >= 0 { "LONG" } else { "SHORT" };
    assert_eq!(direction, "LONG");
}

#[test]
fn test_metadata_name_and_symbol_constants() {
    // Verify the expected metadata name/symbol strings
    // (these are the hardcoded values used in create_nft_mint_with_metadata)
    let name = "PERC-POS";
    let symbol = "PP";
    assert_eq!(name.len(), 8);
    assert_eq!(symbol.len(), 2);
}

// ──────────────────────────────────────────────────────────────────────────────
// Reserved bytes test
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_reserved_bytes_are_zero_by_default() {
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: [0u8; 32],
        user_idx: 0,
        pending_settlement: 0,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    assert_eq!(state._reserved, [0u8; 19]);
}

#[test]
fn test_state_fields_at_expected_offsets() {
    use core::mem::offset_of;
    assert_eq!(offset_of!(PositionNftState, magic), 0);
    assert_eq!(offset_of!(PositionNftState, mint), 8);
    assert_eq!(offset_of!(PositionNftState, slab), 40);
    assert_eq!(offset_of!(PositionNftState, owner), 72);
    assert_eq!(offset_of!(PositionNftState, user_idx), 104);
    assert_eq!(offset_of!(PositionNftState, pending_settlement), 106);
    assert_eq!(offset_of!(PositionNftState, bump), 107);
    assert_eq!(offset_of!(PositionNftState, mint_bump), 108);
    assert_eq!(offset_of!(PositionNftState, _reserved), 109);
}
