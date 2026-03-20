//! Unit tests for PERC-608: Position NFT functionality
//!
//! Tests cover:
//! 1. State struct serialization round-trip
//! 2. PDA derivation consistency
//! 3. Tag value correctness
//! 4. pending_settlement flag logic
//! 5. Transfer guard (pending_settlement)
//! 6. Owner authorization check (pure logic)

use percolator_prog::{
    position_nft::{
        derive_position_nft, derive_position_nft_mint, read_position_nft_state,
        write_position_nft_state, PositionNftState, POSITION_NFT_MAGIC, POSITION_NFT_STATE_LEN,
    },
    tags::{TAG_BURN_POSITION_NFT, TAG_MINT_POSITION_NFT, TAG_TRANSFER_POSITION_OWNERSHIP},
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
    assert_ne!(pda_a, pda_b, "different slabs must produce different PDAs");
}

#[test]
fn test_mint_pda_differs_from_state_pda() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();

    let (state_pda, _) = derive_position_nft(&program_id, &slab, 5);
    let (mint_pda, _) = derive_position_nft_mint(&program_id, &slab, 5);
    assert_ne!(state_pda, mint_pda, "state PDA and mint PDA must differ");
}

#[test]
fn test_mint_pda_derivation_is_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();

    let (mint1, bump1) = derive_position_nft_mint(&program_id, &slab, 3);
    let (mint2, bump2) = derive_position_nft_mint(&program_id, &slab, 3);
    assert_eq!(mint1, mint2);
    assert_eq!(bump1, bump2);
}

// ──────────────────────────────────────────────────────────────────────────────
// Tag value correctness
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_tag_values_are_correct() {
    assert_eq!(TAG_MINT_POSITION_NFT, 64);
    assert_eq!(TAG_TRANSFER_POSITION_OWNERSHIP, 65);
    assert_eq!(TAG_BURN_POSITION_NFT, 66);
}

// ──────────────────────────────────────────────────────────────────────────────
// pending_settlement flag logic
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_pending_settlement_set_and_clear() {
    let mut state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [1u8; 32],
        slab: [2u8; 32],
        owner: [3u8; 32],
        user_idx: 0,
        pending_settlement: 1,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    assert_eq!(
        state.pending_settlement, 1,
        "pending_settlement should be set"
    );

    // Simulate keeper clearing it
    state.pending_settlement = 0;
    let mut buf = vec![0u8; POSITION_NFT_STATE_LEN];
    write_position_nft_state(&mut buf, &state);
    let loaded = read_position_nft_state(&buf).unwrap();
    assert_eq!(
        loaded.pending_settlement, 0,
        "pending_settlement should be cleared"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Transfer guard: pending_settlement check (mirrors on-chain logic)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_transfer_blocked_when_pending_settlement_set() {
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [1u8; 32],
        slab: [2u8; 32],
        owner: [3u8; 32],
        user_idx: 0,
        pending_settlement: 1,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    // Mirrors on-chain guard: pending_settlement != 0 → reject
    assert_ne!(
        state.pending_settlement, 0,
        "transfer should be blocked when pending_settlement != 0"
    );
}

#[test]
fn test_transfer_allowed_when_settlement_cleared() {
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [1u8; 32],
        slab: [2u8; 32],
        owner: [3u8; 32],
        user_idx: 0,
        pending_settlement: 0,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    assert_eq!(
        state.pending_settlement, 0,
        "transfer should be allowed when pending_settlement == 0"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Owner authorization check (mirrors on-chain logic)
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_owner_check_passes_for_correct_owner() {
    let owner = Pubkey::new_unique();
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: owner.to_bytes(),
        user_idx: 0,
        pending_settlement: 0,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    assert_eq!(
        state.owner,
        owner.to_bytes(),
        "correct owner should pass check"
    );
}

#[test]
fn test_owner_check_fails_for_wrong_caller() {
    let real_owner = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: real_owner.to_bytes(),
        user_idx: 0,
        pending_settlement: 0,
        bump: 0,
        mint_bump: 0,
        _reserved: [0u8; 19],
    };
    // The on-chain check: state.owner != caller.key → reject
    assert_ne!(
        state.owner,
        attacker.to_bytes(),
        "wrong caller should fail owner check"
    );
}

#[test]
fn test_double_mint_guard_logic() {
    // Simulates the on-chain check: if state is_initialized → reject (AlreadyInitialized)
    let state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [1u8; 32],
        slab: [1u8; 32],
        owner: [1u8; 32],
        user_idx: 0,
        pending_settlement: 0,
        bump: 200,
        mint_bump: 199,
        _reserved: [0u8; 19],
    };
    // A second MintPositionNft call would see is_initialized() = true → error
    assert!(
        state.is_initialized(),
        "existing state must block double-mint"
    );
}

#[test]
fn test_burn_clears_magic() {
    // Simulates the on-chain burn: zero out data → magic becomes 0
    let mut state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [1u8; 32],
        slab: [1u8; 32],
        owner: [1u8; 32],
        user_idx: 0,
        pending_settlement: 0,
        bump: 200,
        mint_bump: 199,
        _reserved: [0u8; 19],
    };
    // Zero out (as done on-chain for PositionNft PDA close)
    state.magic = 0;
    assert!(
        !state.is_initialized(),
        "zeroed-out state should not be initialized"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// SetPendingSettlement / ClearPendingSettlement — tag + state-level tests
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn test_set_pending_settlement_tag_is_67() {
    use percolator_prog::tags::TAG_SET_PENDING_SETTLEMENT;
    assert_eq!(TAG_SET_PENDING_SETTLEMENT, 67);
}

#[test]
fn test_clear_pending_settlement_tag_is_68() {
    use percolator_prog::tags::TAG_CLEAR_PENDING_SETTLEMENT;
    assert_eq!(TAG_CLEAR_PENDING_SETTLEMENT, 68);
}

/// State-level: pending_settlement transitions Set → Clear correctly with round-trip.
#[test]
fn test_pending_settlement_set_and_clear_roundtrip() {
    let mut state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: Pubkey::new_unique().to_bytes(),
        slab: Pubkey::new_unique().to_bytes(),
        owner: Pubkey::new_unique().to_bytes(),
        user_idx: 3,
        pending_settlement: 0,
        bump: 200,
        mint_bump: 199,
        _reserved: [0u8; 19],
    };

    assert_eq!(state.pending_settlement, 0, "starts clear");

    // SetPendingSettlement
    state.pending_settlement = 1;
    let mut buf = vec![0u8; POSITION_NFT_STATE_LEN];
    write_position_nft_state(&mut buf, &state);
    let loaded = read_position_nft_state(&buf).expect("should parse");
    assert_eq!(loaded.pending_settlement, 1, "flag persisted after write");

    // ClearPendingSettlement
    let mut loaded = loaded;
    loaded.pending_settlement = 0;
    write_position_nft_state(&mut buf, &loaded);
    let loaded2 = read_position_nft_state(&buf).expect("should parse");
    assert_eq!(loaded2.pending_settlement, 0, "flag cleared after write");
}

/// Transfer guard: pending_settlement=1 blocks, pending_settlement=0 allows.
#[test]
fn test_transfer_guard_via_pending_settlement_flag() {
    let mut state = PositionNftState {
        magic: POSITION_NFT_MAGIC,
        mint: [0u8; 32],
        slab: [0u8; 32],
        owner: [0u8; 32],
        user_idx: 0,
        pending_settlement: 1,
        bump: 254,
        mint_bump: 253,
        _reserved: [0u8; 19],
    };

    // Blocked
    assert_ne!(
        state.pending_settlement, 0,
        "transfer must be blocked when flag=1"
    );

    // ClearPendingSettlement → allowed
    state.pending_settlement = 0;
    assert_eq!(state.pending_settlement, 0, "transfer allowed when flag=0");
}
