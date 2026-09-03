// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! B-3 TransferPortfolioOwnership + SetNftProgramId tests.
//!
//! Coverage:
//!
//! **Data-layer (pure, no runtime) — §7 guardrails via `b3_check_and_rewrite_owner`:**
//!   - `b3_happy_dual_write` — happy path: owner + provenance_header.owner both move;
//!     every other byte is unchanged (conservation proof).
//!   - `b3_rejects_zero_owner` — Guardrail 4.
//!   - `b3_rejects_self_transfer` — Guardrail 4.
//!   - `b3_rejects_no_active_leg` — Guardrail 3: no leg for requested asset_index.
//!   - `b3_rejects_liquidation_lock` — Guardrail 3.
//!   - `b3_rejects_stale_state` — Guardrail 3.
//!   - `b3_rejects_b_stale_state` — Guardrail 3.
//!   - `b3_rejects_resolved_payout` — Guardrail 3.
//!   - `b3_rejects_mid_close` — Guardrail 3.
//!   - `b3_rejects_leg_b_stale` — Guardrail 3.
//!   - `b3_rejects_leg_stale` — Guardrail 3.
//!
//! **NftRegistryV16 data-layer (pure):**
//!   - `nft_registry_struct_size` — 72-byte compile-time assert + runtime.
//!   - `nft_registry_account_len_includes_header` — 16+72 = 88.
//!   - `nft_registry_init_read_write_roundtrip` — init/read/write roundtrip.
//!   - `nft_registry_fail_closed_uninitialized` — uninitialized bytes → Err.
//!   - `nft_registry_zero_market_rejects` — validate catches zeroed market_group.
//!   - `nft_registry_zero_program_id_rejects` — validate catches zeroed nft_program_id.
//!   - `nft_registry_wrong_version_rejects` — validate catches wrong version.
//!   - `nft_registry_nonzero_padding_rejects` — validate catches dirty padding.
//!
//! **PDA derivation:**
//!   - `nft_registry_pda_deterministic` — same inputs → same PDA.
//!   - `nft_registry_pda_distinct_per_market` — different markets → different PDAs.
//!   - `nft_mint_authority_pda_deterministic` — same nft_program_id → same PDA.
//!   - `nft_mint_authority_pda_distinct_per_program` — different programs → different.
//!   - `nft_mint_authority_shared_seed_contract` — `derive_nft_mint_authority(pid)`
//!     returns the same address as `find_program_address([b"mint_authority"], pid)`.
//!     This test IS the cross-repo seed-contract guard.
//!
//! **Instruction wire encoding:**
//!   - `transfer_ownership_encode_decode_roundtrip` — tag 72 wire contract.
//!   - `set_nft_program_id_encode_decode_roundtrip` — tag 73 wire contract.
//!   - `nft_tags_are_correct` — TAG constants match expected values.
//!
//! **LiteSVM wrapper tests (require wrapper BPF):**
//!   - `set_nft_program_id_create` — admin creates registry for a market.
//!   - `set_nft_program_id_update` — admin updates nft_program_id in existing registry.
//!   - `set_nft_program_id_non_admin_rejects` — non-admin signer rejects.
//!   - `set_nft_program_id_zero_program_id_rejects` — zero program ID rejects.
//!   - `b3_wrong_signer_rejects` — random keypair signer != derived mint-auth PDA → reject.
//!   - `b3_fail_closed_uninitialized_registry` — uninitialized registry PDA → reject.
//!
//! Kani harness deferred: `kani_b3_transfer_ownership_pure_meta` — runs
//! `b3_check_and_rewrite_owner` on a symbolic portfolio.  CBMC-capable; see
//! `tests/v16_kani.rs` pattern.  Deferred because LiteSVM + pure unit coverage
//! is sufficient for the audit gate; Kani proof would add CBMC-symbolic
//! exhaustiveness but is not on the CI critical path (per project Kani policy).
//!
//! Cross-reference: `~/wrapper-engine-deep-audit/nft_design.md` §7/§7.0;
//! `src/v16_program.rs` handlers at `handle_transfer_portfolio_ownership` +
//! `handle_set_nft_program_id`.

use percolator::{
    PortfolioAccountV16Account, PortfolioLegV16Account, ProvenanceHeaderV16Account, V16PodU16,
    V16PodU32,
};
use percolator_prog::{
    constants::{
        HEADER_LEN, KIND_NFT_REGISTRY, MAGIC, NFT_MINT_AUTHORITY_SEED, NFT_REGISTRY_VERSION,
        TAG_SET_NFT_PROGRAM_ID, TAG_TRANSFER_PORTFOLIO_OWNERSHIP, VERSION,
    },
    ix::Instruction as ProgInstruction,
    state::{
        derive_nft_mint_authority, derive_nft_registry, init_nft_registry,
        nft_registry_account_len, read_nft_registry, write_nft_registry, NftRegistryV16,
    },
};
use solana_program::pubkey::Pubkey;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal valid `PortfolioAccountV16Account` POD with one active leg
/// at `asset_index = 0`, owned by `owner`.
fn make_portfolio(
    owner: [u8; 32],
    market_group: [u8; 32],
    key: [u8; 32],
) -> PortfolioAccountV16Account {
    let mut p = PortfolioAccountV16Account::default();
    // Provenance header: V16_LAYOUT_DISCRIMINATOR = 16, V16_ACCOUNT_VERSION = 1.
    p.provenance_header = ProvenanceHeaderV16Account {
        market_group_id: market_group,
        portfolio_account_id: key,
        owner,
        version: V16PodU16::new(percolator::V16_ACCOUNT_VERSION),
        layout_discriminator: V16PodU16::new(percolator::V16_LAYOUT_DISCRIMINATOR),
    };
    p.owner = owner;

    // One active leg at asset_index 0.
    p.legs[0] = PortfolioLegV16Account {
        active: 1,
        asset_index: V16PodU32::new(0),
        ..Default::default()
    };

    p
}

/// Build a minimal valid `NftRegistryV16`.
fn sample_registry(market_group: [u8; 32], nft_program_id: [u8; 32]) -> NftRegistryV16 {
    NftRegistryV16 {
        market_group,
        nft_program_id,
        version: NFT_REGISTRY_VERSION,
        bump: 254,
        _padding: [0u8; 6],
    }
}

/// Build raw account data for an `NftRegistryV16`.
fn make_registry_data(reg: &NftRegistryV16) -> Vec<u8> {
    let len = nft_registry_account_len();
    let mut data = vec![0u8; len];
    init_nft_registry(&mut data, reg).expect("init_nft_registry");
    data
}

// ── NftRegistryV16 data-layer tests ──────────────────────────────────────────

#[test]
fn nft_registry_struct_size() {
    assert_eq!(core::mem::size_of::<NftRegistryV16>(), 72);
}

#[test]
fn nft_registry_account_len_includes_header() {
    assert_eq!(nft_registry_account_len(), 16 + 72);
}

#[test]
fn nft_registry_init_read_write_roundtrip() {
    let reg = sample_registry([1u8; 32], [2u8; 32]);
    let mut data = make_registry_data(&reg);
    // Read back.
    let r = read_nft_registry(&data).expect("read_nft_registry");
    assert_eq!(r, reg);
    // Modify and write back.
    let reg2 = NftRegistryV16 {
        nft_program_id: [9u8; 32],
        ..reg
    };
    write_nft_registry(&mut data, &reg2).expect("write_nft_registry");
    let r2 = read_nft_registry(&data).expect("read after write");
    assert_eq!(r2, reg2);
}

#[test]
fn nft_registry_fail_closed_uninitialized() {
    // All-zero bytes have no MAGIC → should fail NotInitialized.
    let data = vec![0u8; nft_registry_account_len()];
    let result = read_nft_registry(&data);
    assert!(result.is_err(), "uninitialized registry must fail");
}

#[test]
fn nft_registry_zero_market_rejects() {
    let reg = NftRegistryV16 {
        market_group: [0u8; 32],
        ..sample_registry([1u8; 32], [2u8; 32])
    };
    // init would fail because is_initialized check is before validate, but
    // write_nft_registry validates so build the buffer manually.
    let len = nft_registry_account_len();
    let mut data = vec![0u8; len];
    // Write a valid header then a bad body.
    data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    data[8..10].copy_from_slice(&VERSION.to_le_bytes());
    data[10] = KIND_NFT_REGISTRY;
    data[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&reg));
    let result = read_nft_registry(&data);
    assert!(result.is_err(), "zero market_group must be rejected");
}

#[test]
fn nft_registry_zero_program_id_rejects() {
    let reg = NftRegistryV16 {
        nft_program_id: [0u8; 32],
        ..sample_registry([1u8; 32], [2u8; 32])
    };
    let len = nft_registry_account_len();
    let mut data = vec![0u8; len];
    data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    data[8..10].copy_from_slice(&VERSION.to_le_bytes());
    data[10] = KIND_NFT_REGISTRY;
    data[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&reg));
    assert!(
        read_nft_registry(&data).is_err(),
        "zero nft_program_id must be rejected"
    );
}

#[test]
fn nft_registry_wrong_version_rejects() {
    let reg = NftRegistryV16 {
        version: 255,
        ..sample_registry([1u8; 32], [2u8; 32])
    };
    let len = nft_registry_account_len();
    let mut data = vec![0u8; len];
    data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    data[8..10].copy_from_slice(&VERSION.to_le_bytes());
    data[10] = KIND_NFT_REGISTRY;
    data[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&reg));
    assert!(
        read_nft_registry(&data).is_err(),
        "wrong version must be rejected"
    );
}

#[test]
fn nft_registry_nonzero_padding_rejects() {
    let reg = NftRegistryV16 {
        _padding: [1u8; 6],
        ..sample_registry([1u8; 32], [2u8; 32])
    };
    let len = nft_registry_account_len();
    let mut data = vec![0u8; len];
    data[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    data[8..10].copy_from_slice(&VERSION.to_le_bytes());
    data[10] = KIND_NFT_REGISTRY;
    data[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&reg));
    assert!(
        read_nft_registry(&data).is_err(),
        "dirty padding must be rejected"
    );
}

// ── PDA derivation tests ──────────────────────────────────────────────────────

#[test]
fn nft_registry_pda_deterministic() {
    let prog = Pubkey::new_unique();
    let market = Pubkey::new_unique();
    let (a, ba) = derive_nft_registry(&prog, &market);
    let (b, bb) = derive_nft_registry(&prog, &market);
    assert_eq!(a, b, "same inputs must give same PDA");
    assert_eq!(ba, bb);
}

#[test]
fn nft_registry_pda_distinct_per_market() {
    let prog = Pubkey::new_unique();
    let m1 = Pubkey::new_unique();
    let m2 = Pubkey::new_unique();
    let (a, _) = derive_nft_registry(&prog, &m1);
    let (b, _) = derive_nft_registry(&prog, &m2);
    assert_ne!(a, b, "different markets must give different registry PDAs");
}

#[test]
fn nft_mint_authority_pda_deterministic() {
    let nft_prog = Pubkey::new_unique();
    let (a, ba) = derive_nft_mint_authority(&nft_prog);
    let (b, bb) = derive_nft_mint_authority(&nft_prog);
    assert_eq!(a, b);
    assert_eq!(ba, bb);
}

#[test]
fn nft_mint_authority_pda_distinct_per_program() {
    let p1 = Pubkey::new_unique();
    let p2 = Pubkey::new_unique();
    let (a, _) = derive_nft_mint_authority(&p1);
    let (b, _) = derive_nft_mint_authority(&p2);
    assert_ne!(
        a, b,
        "different nft programs must give different mint-auth PDAs"
    );
}

/// SEED-CONTRACT GUARD: the wrapper's `derive_nft_mint_authority(pid)` must
/// produce the same address as `find_program_address([b"mint_authority"], pid)`.
/// The NFT program signs B-3 using that derivation; divergence here = silent
/// auth failure.  Cross-reference: `constants::NFT_MINT_AUTHORITY_SEED`.
#[test]
fn nft_mint_authority_shared_seed_contract() {
    let nft_prog = Pubkey::new_unique();
    let (wrapper_pda, _) = derive_nft_mint_authority(&nft_prog);
    let (canonical_pda, _) = Pubkey::find_program_address(&[NFT_MINT_AUTHORITY_SEED], &nft_prog);
    assert_eq!(
        wrapper_pda, canonical_pda,
        "derive_nft_mint_authority must match find_program_address([NFT_MINT_AUTHORITY_SEED])"
    );
}

// ── Instruction wire encoding ─────────────────────────────────────────────────

#[test]
fn nft_tags_are_correct() {
    assert_eq!(TAG_TRANSFER_PORTFOLIO_OWNERSHIP, 72);
    assert_eq!(TAG_SET_NFT_PROGRAM_ID, 73);
}

#[test]
fn transfer_ownership_encode_decode_roundtrip() {
    let new_owner = [0xABu8; 32];
    let asset_index = 7u16;
    let ix = ProgInstruction::TransferPortfolioOwnership {
        new_owner,
        asset_index,
    };
    let encoded = ix.encode();
    assert_eq!(encoded[0], 72);
    assert_eq!(&encoded[1..33], &new_owner);
    assert_eq!(u16::from_le_bytes([encoded[33], encoded[34]]), asset_index);
    let decoded = ProgInstruction::decode(&encoded).expect("decode");
    assert_eq!(decoded, ix);
}

#[test]
fn set_nft_program_id_encode_decode_roundtrip() {
    let nft_program_id = [0xCDu8; 32];
    let ix = ProgInstruction::SetNftProgramId { nft_program_id };
    let encoded = ix.encode();
    assert_eq!(encoded[0], 73);
    assert_eq!(&encoded[1..33], &nft_program_id);
    let decoded = ProgInstruction::decode(&encoded).expect("decode");
    assert_eq!(decoded, ix);
}

// ── b3_check_and_rewrite_owner pure-unit tests ────────────────────────────────

use percolator_prog::processor::b3_check_and_rewrite_owner;

#[test]
fn b3_happy_dual_write() {
    let old_owner = [1u8; 32];
    let new_owner = [2u8; 32];
    let market_group = [3u8; 32];
    let key = [4u8; 32];

    let mut p = make_portfolio(old_owner, market_group, key);
    // Snapshot the entire struct bytes before.
    let before_bytes: Vec<u8> = bytemuck::bytes_of(&p).to_vec();

    b3_check_and_rewrite_owner(&mut p, new_owner, 0).expect("happy path must succeed");

    // ── Guardrail 2: both owner fields updated ───────────────────────────────
    assert_eq!(p.owner, new_owner, "top-level owner must be updated");
    assert_eq!(
        p.provenance_header.owner, new_owner,
        "provenance_header.owner must be updated"
    );
    assert_eq!(
        p.owner, p.provenance_header.owner,
        "dual-write invariant: both fields must be equal"
    );

    // ── Guardrail 6 (conservation): all other bytes unchanged ────────────────
    let after_bytes: Vec<u8> = bytemuck::bytes_of(&p).to_vec();
    // Find offset of provenance_header.owner and p.owner in the POD.
    let prov_owner_off = core::mem::offset_of!(PortfolioAccountV16Account, provenance_header)
        + core::mem::offset_of!(ProvenanceHeaderV16Account, owner);
    let top_owner_off = core::mem::offset_of!(PortfolioAccountV16Account, owner);

    for (i, (b, a)) in before_bytes.iter().zip(after_bytes.iter()).enumerate() {
        let in_prov = i >= prov_owner_off && i < prov_owner_off + 32;
        let in_top = i >= top_owner_off && i < top_owner_off + 32;
        if !in_prov && !in_top {
            assert_eq!(
                b, a,
                "conservation: byte {} changed outside owner fields",
                i
            );
        }
    }
}

#[test]
fn b3_rejects_zero_owner() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    let result = b3_check_and_rewrite_owner(&mut p, [0u8; 32], 0);
    assert!(result.is_err(), "zero new_owner must be rejected");
    // State must be unchanged.
    assert_eq!(p.owner, old_owner, "owner must not change on error");
    assert_eq!(p.provenance_header.owner, old_owner);
}

#[test]
fn b3_rejects_self_transfer() {
    let owner = [1u8; 32];
    let mut p = make_portfolio(owner, [3u8; 32], [4u8; 32]);
    let result = b3_check_and_rewrite_owner(&mut p, owner, 0);
    assert!(result.is_err(), "self-transfer must be rejected");
    assert_eq!(p.owner, owner);
}

#[test]
fn b3_rejects_no_active_leg() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    // asset_index = 5 has no active leg.
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 5);
    assert!(result.is_err(), "missing active leg must be rejected");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_liquidation_lock() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.liquidation_lock = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "liquidation_lock must block transfer");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_stale_state() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.stale_state = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "stale_state must block transfer");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_b_stale_state() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.b_stale_state = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "b_stale_state must block transfer");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_resolved_payout() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.resolved_payout_receipt.present = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(
        result.is_err(),
        "resolved_payout_receipt.present must block transfer"
    );
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_mid_close() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.close_progress.active = 1;
    p.close_progress.asset_index = V16PodU32::new(0); // same asset as the leg
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "mid-close must block transfer");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_mid_close_different_asset() {
    // Close in progress for DIFFERENT asset — must NOT block the transfer.
    let old_owner = [1u8; 32];
    let new_owner = [2u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.close_progress.active = 1;
    p.close_progress.asset_index = V16PodU32::new(99); // different asset
    let result = b3_check_and_rewrite_owner(&mut p, new_owner, 0);
    assert!(
        result.is_ok(),
        "close on different asset must not block transfer"
    );
    assert_eq!(p.owner, new_owner);
}

#[test]
fn b3_rejects_leg_b_stale() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.legs[0].b_stale = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "leg.b_stale must block transfer");
    assert_eq!(p.owner, old_owner);
}

#[test]
fn b3_rejects_leg_stale() {
    let old_owner = [1u8; 32];
    let mut p = make_portfolio(old_owner, [3u8; 32], [4u8; 32]);
    p.legs[0].stale = 1;
    let result = b3_check_and_rewrite_owner(&mut p, [2u8; 32], 0);
    assert!(result.is_err(), "leg.stale must block transfer");
    assert_eq!(p.owner, old_owner);
}

// ── unwrap_check_and_rewrite_owner pure-unit tests (#105 escrow-at-mint) ──────
//
// UnwrapEscrowedPortfolio (tag 82) is the dual of B-3: it releases an
// NFT-escrowed portfolio (owner == the NFT program's mint-authority PDA) back
// to the burning holder. Unlike B-3 it is gated ONLY on the escrow invariant —
// NOT on leg/resolved/liquidation state — so an escrowed position that was
// closed, liquidated, or resolved while wrapped can ALWAYS be released (no
// stranding). These tests pin both that escrow invariant and that the
// terminal-state gates are intentionally absent.

use percolator_prog::processor::unwrap_check_and_rewrite_owner;

const ESCROW_PDA: [u8; 32] = [7u8; 32]; // stands in for the NFT mint-authority PDA

#[test]
fn unwrap_happy_dual_write_and_conservation() {
    let holder = [2u8; 32];
    // Escrowed portfolio: owner == the escrow PDA.
    let mut p = make_portfolio(ESCROW_PDA, [3u8; 32], [4u8; 32]);
    let before_bytes: Vec<u8> = bytemuck::bytes_of(&p).to_vec();

    unwrap_check_and_rewrite_owner(&mut p, holder, ESCROW_PDA)
        .expect("release of an escrowed portfolio must succeed");

    assert_eq!(
        p.owner, holder,
        "top-level owner must be released to holder"
    );
    assert_eq!(p.provenance_header.owner, holder, "provenance owner too");
    assert_eq!(p.owner, p.provenance_header.owner, "dual-write invariant");

    // Conservation: only the two owner fields changed.
    let after_bytes: Vec<u8> = bytemuck::bytes_of(&p).to_vec();
    let prov_owner_off = core::mem::offset_of!(PortfolioAccountV16Account, provenance_header)
        + core::mem::offset_of!(ProvenanceHeaderV16Account, owner);
    let top_owner_off = core::mem::offset_of!(PortfolioAccountV16Account, owner);
    for (i, (b, a)) in before_bytes.iter().zip(after_bytes.iter()).enumerate() {
        let in_prov = i >= prov_owner_off && i < prov_owner_off + 32;
        let in_top = i >= top_owner_off && i < top_owner_off + 32;
        if !in_prov && !in_top {
            assert_eq!(
                b, a,
                "conservation: byte {} changed outside owner fields",
                i
            );
        }
    }
}

#[test]
fn unwrap_rejects_zero_owner() {
    let mut p = make_portfolio(ESCROW_PDA, [3u8; 32], [4u8; 32]);
    let r = unwrap_check_and_rewrite_owner(&mut p, [0u8; 32], ESCROW_PDA);
    assert!(r.is_err(), "zero new_owner must be rejected");
    assert_eq!(p.owner, ESCROW_PDA, "owner unchanged on error");
}

#[test]
fn unwrap_rejects_non_escrowed_portfolio() {
    // A normally-owned portfolio (owner != the escrow PDA) can NEVER be released
    // by unwrap — this is what stops it being used to seize an unrelated account.
    let normal_owner = [1u8; 32];
    let mut p = make_portfolio(normal_owner, [3u8; 32], [4u8; 32]);
    let r = unwrap_check_and_rewrite_owner(&mut p, [2u8; 32], ESCROW_PDA);
    assert!(r.is_err(), "non-escrowed portfolio must be rejected");
    assert_eq!(p.owner, normal_owner, "owner unchanged on error");
}

#[test]
fn unwrap_succeeds_with_no_active_leg() {
    // CRITICAL no-stranding property: a fully closed/liquidated escrowed
    // position (no active leg) must STILL be releasable, unlike B-3.
    let holder = [2u8; 32];
    let mut p = make_portfolio(ESCROW_PDA, [3u8; 32], [4u8; 32]);
    p.legs[0].active = 0; // position closed
                          // Sanity: B-3 would block this exact state...
    assert!(
        b3_check_and_rewrite_owner(&mut p, holder, 0).is_err(),
        "precondition: B-3 blocks a closed position"
    );
    assert_eq!(p.owner, ESCROW_PDA, "B-3 must not have mutated owner");
    // ...but unwrap releases it.
    unwrap_check_and_rewrite_owner(&mut p, holder, ESCROW_PDA)
        .expect("unwrap must release a closed escrowed position");
    assert_eq!(p.owner, holder);
}

#[test]
fn unwrap_succeeds_with_resolved_payout_receipt() {
    // CRITICAL no-stranding property: a resolved-with-payout escrowed position
    // (resolved_payout_receipt.present) must STILL be releasable, unlike B-3.
    let holder = [2u8; 32];
    let mut p = make_portfolio(ESCROW_PDA, [3u8; 32], [4u8; 32]);
    p.resolved_payout_receipt.present = 1;
    assert!(
        b3_check_and_rewrite_owner(&mut p, holder, 0).is_err(),
        "precondition: B-3 blocks a resolved-payout position"
    );
    unwrap_check_and_rewrite_owner(&mut p, holder, ESCROW_PDA)
        .expect("unwrap must release a resolved escrowed position");
    assert_eq!(p.owner, holder);
}

#[test]
fn unwrap_succeeds_despite_liquidation_lock_and_stale() {
    // Releasing the owner mid-settlement is safe (downstream owner-gated
    // instructions keep their own gating); unwrap must not strand on these.
    let holder = [2u8; 32];
    let mut p = make_portfolio(ESCROW_PDA, [3u8; 32], [4u8; 32]);
    p.liquidation_lock = 1;
    p.stale_state = 1;
    p.b_stale_state = 1;
    unwrap_check_and_rewrite_owner(&mut p, holder, ESCROW_PDA)
        .expect("unwrap must not be gated on transient liquidation/stale state");
    assert_eq!(p.owner, holder);
}

#[test]
fn unwrap_encode_decode_roundtrip() {
    let new_owner = [9u8; 32];
    let bytes = ProgInstruction::UnwrapEscrowedPortfolio { new_owner }.encode();
    assert_eq!(bytes[0], 82, "tag must be 82");
    assert_eq!(bytes.len(), 33, "tag(1) + new_owner(32)");
    match ProgInstruction::decode(&bytes).expect("decode must succeed") {
        ProgInstruction::UnwrapEscrowedPortfolio { new_owner: got } => {
            assert_eq!(got, new_owner)
        }
        _ => panic!("decoded to the wrong variant"),
    }
}

// ── LiteSVM integration tests ─────────────────────────────────────────────────
//
// Tests that require the compiled BPF binary.  They are gated on the .so
// existing (the `program_path()` fn panics with a clear message if it does
// not); running `cargo build-sbf` first makes them pass.
//
// B-3 HAPPY-PATH AUTH NOTE: the full B-3 happy-path requires the NFT program
// to CPI with its mint-authority PDA as a signer, which requires the compiled
// NFT program BPF.  That is A.5 (next pass).  The tests below cover the
// wrapper-only guard paths (wrong signer, uninitialized registry) that can be
// tested with random keypairs without the NFT program.  See
// `tests/v16_fork_b3_nft_cpi.rs::LITESVM_B3_HAPPY_PATH_NOTE`.
//
// LITESVM_B3_HAPPY_PATH_NOTE: B-3 happy-path auth test deferred to A.5.  The
// NFT program's `ExecuteTransferHook` CPIs B-3 using `invoke_signed`; that
// requires the NFT program to be deployed in the test SVM.  Deferral is safe:
// the pure unit tests above cover all state-machine correctness; the LiteSVM
// tests below cover the on-chain account validation paths.

#[cfg(test)]
mod litesvm_tests {
    use super::*;
    use litesvm::LiteSVM;
    use percolator_prog::{
        constants::{
            HEADER_LEN as PROG_HEADER_LEN, KIND_PORTFOLIO, MAGIC as PROG_MAGIC,
            VERSION as PROG_VERSION,
        },
        state::{self, derive_nft_registry},
    };
    use solana_sdk::{
        account::Account,
        compute_budget::ComputeBudgetInstruction,
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
        signature::{Keypair, Signer},
        system_program,
        transaction::Transaction,
    };
    use std::path::PathBuf;

    const MAX_PORTFOLIO_ASSETS: u16 = 1;

    fn program_path() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("target/deploy/percolator_prog.so");
        assert!(
            p.exists(),
            "wrapper BPF missing — run `cargo build-sbf` first"
        );
        p
    }

    fn send(
        svm: &mut LiteSVM,
        pid: Pubkey,
        payer: &Keypair,
        data: Vec<u8>,
        accounts: Vec<AccountMeta>,
        extra: &[&Keypair],
    ) -> Result<(), String> {
        let instruction = Instruction {
            program_id: pid,
            accounts,
            data,
        };
        let mut signers = vec![payer];
        signers.extend_from_slice(extra);
        let tx = Transaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::request_heap_frame(128 * 1024),
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                instruction,
            ],
            Some(&payer.pubkey()),
            &signers,
            svm.latest_blockhash(),
        );
        svm.send_transaction(tx)
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    fn init_market_ix() -> ProgInstruction {
        ProgInstruction::InitMarket {
            max_portfolio_assets: MAX_PORTFOLIO_ASSETS,
            h_min: 0,
            h_max: 10,
            initial_price: 100,
            min_nonzero_mm_req: 1,
            min_nonzero_im_req: 2,
            maintenance_margin_bps: 10_000,
            initial_margin_bps: 10_000,
            max_trading_fee_bps: 10_000,
            trade_fee_base_bps: 0,
            liquidation_fee_bps: 0,
            liquidation_fee_cap: 0,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 10_000,
            max_accrual_dt_slots: 1,
            max_abs_funding_e9_per_slot: 0,
            min_funding_lifetime_slots: 1,
            max_account_b_settlement_chunks: 1,
            max_bankrupt_close_chunks: 1,
            max_bankrupt_close_lifetime_slots: 100,
            public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
            maintenance_fee_per_slot: 0,
        }
    }

    fn make_collateral_mint_data() -> Vec<u8> {
        use solana_sdk::{program_option::COption, program_pack::Pack};
        use spl_token::state::Mint;
        let mut d = vec![0u8; Mint::LEN];
        Mint::pack(
            Mint {
                mint_authority: COption::None,
                supply: 0,
                decimals: 0,
                is_initialized: true,
                freeze_authority: COption::None,
            },
            &mut d,
        )
        .unwrap();
        d
    }

    struct Env {
        svm: LiteSVM,
        program_id: Pubkey,
        payer: Keypair,
        admin: Keypair,
        market: Pubkey,
    }

    fn setup() -> Env {
        let bpf = std::fs::read(program_path()).expect("wrapper BPF");
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &bpf);

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let collateral_mint = Pubkey::new_unique();

        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
        svm.set_account(
            collateral_mint,
            Account {
                lamports: 1_000_000_000,
                data: make_collateral_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![
                    0u8;
                    state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize)
                        .unwrap()
                ],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Initialize the market (admin signs).
        send(
            &mut svm,
            program_id,
            &payer,
            init_market_ix().encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(collateral_mint, false),
            ],
            &[&admin],
        )
        .expect("init market");

        Env {
            svm,
            program_id,
            payer,
            admin,
            market,
        }
    }

    // ── SetNftProgramId (tag 73) ──────────────────────────────────────────────

    #[test]
    fn set_nft_program_id_create() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin,
            market,
        } = env;
        let (registry, _) = derive_nft_registry(&program_id, &market);
        let nft_prog = [0xABu8; 32];

        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: nft_prog,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        );
        assert!(
            result.is_ok(),
            "SetNftProgramId create must succeed: {:?}",
            result
        );

        // Verify the registry was written.
        let reg_data = svm.get_account(&registry).expect("registry account").data;
        let reg = read_nft_registry(&reg_data).expect("read registry");
        assert_eq!(reg.nft_program_id, nft_prog);
        assert_eq!(reg.market_group, market.to_bytes());
        assert_eq!(reg.version, NFT_REGISTRY_VERSION);
    }

    #[test]
    fn set_nft_program_id_reject_update_set_once() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin,
            market,
        } = env;
        let (registry, _) = derive_nft_registry(&program_id, &market);
        let nft_prog_v1 = [0x11u8; 32];
        let nft_prog_v2 = [0x22u8; 32];

        // Create.
        send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: nft_prog_v1,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        )
        .expect("create registry");

        // Re-point attempt — must now be REJECTED (set-once trust root): the NFT
        // program id is the custody trust root and is immutable after creation.
        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: nft_prog_v2,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        );
        assert!(
            result.is_err(),
            "set-once: a second SetNftProgramId (re-point) must be rejected, got {:?}",
            result
        );

        let reg_data = svm.get_account(&registry).expect("registry").data;
        let reg = read_nft_registry(&reg_data).expect("read registry after rejected update");
        assert_eq!(
            reg.nft_program_id, nft_prog_v1,
            "trust root must remain the originally-registered program after a rejected re-point"
        );
    }

    #[test]
    fn set_nft_program_id_non_admin_rejects() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin: _,
            market,
        } = env;
        let (registry, _) = derive_nft_registry(&program_id, &market);
        let impostor = Keypair::new();
        svm.airdrop(&impostor.pubkey(), 100_000_000_000).unwrap();

        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: [0x55u8; 32],
            }
            .encode(),
            vec![
                AccountMeta::new(impostor.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&impostor],
        );
        assert!(result.is_err(), "non-admin must be rejected");
    }

    #[test]
    fn set_nft_program_id_zero_program_id_rejects() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin,
            market,
        } = env;
        let (registry, _) = derive_nft_registry(&program_id, &market);

        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: [0u8; 32],
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        );
        assert!(result.is_err(), "zero nft_program_id must be rejected");
    }

    // ── B-3 TransferPortfolioOwnership (tag 72) — guard-path tests ───────────

    /// Build a minimal initialized portfolio account on-chain that can be
    /// used by the B-3 tests (guard paths only; happy path needs NFT CPI).
    fn make_onchain_portfolio(
        svm: &mut LiteSVM,
        program_id: Pubkey,
        portfolio_key: Pubkey,
        owner_bytes: [u8; 32],
        market_group: [u8; 32],
    ) {
        use percolator::V16PodU32;
        // Build POD.
        let mut p = PortfolioAccountV16Account::default();
        p.provenance_header = ProvenanceHeaderV16Account {
            market_group_id: market_group,
            portfolio_account_id: portfolio_key.to_bytes(),
            owner: owner_bytes,
            version: V16PodU16::new(percolator::V16_ACCOUNT_VERSION),
            layout_discriminator: V16PodU16::new(percolator::V16_LAYOUT_DISCRIMINATOR),
        };
        p.owner = owner_bytes;
        // One active leg at asset_index 0.
        p.legs[0] = PortfolioLegV16Account {
            active: 1,
            asset_index: V16PodU32::new(0),
            ..Default::default()
        };

        let pod_len = core::mem::size_of::<PortfolioAccountV16Account>();
        let mut data = vec![0u8; PROG_HEADER_LEN + pod_len];
        data[0..8].copy_from_slice(&PROG_MAGIC.to_le_bytes());
        data[8..10].copy_from_slice(&PROG_VERSION.to_le_bytes());
        data[10] = KIND_PORTFOLIO;
        data[PROG_HEADER_LEN..PROG_HEADER_LEN + pod_len].copy_from_slice(bytemuck::bytes_of(&p));

        svm.set_account(
            portfolio_key,
            Account {
                lamports: 10_000_000_000,
                data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }

    /// B-3 wrong-signer reject: a random keypair whose pubkey != the derived
    /// mint-authority PDA must be rejected.
    ///
    /// This exercises Guardrail 1 (auth): even if the random key signs the tx,
    /// it will not equal `derive_nft_mint_authority(registry.nft_program_id)`,
    /// so the handler rejects with `NftInvalidMintAuthority`.
    #[test]
    fn b3_wrong_signer_rejects() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin,
            market,
        } = env;

        // Create the NFT registry.
        let (registry, _) = derive_nft_registry(&program_id, &market);
        let nft_prog = [0xAAu8; 32];
        send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::SetNftProgramId {
                nft_program_id: nft_prog,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(market, false),
                AccountMeta::new(registry, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            &[&admin],
        )
        .expect("create registry");

        // Create a portfolio.
        let portfolio_key = Pubkey::new_unique();
        let owner = [0x01u8; 32];
        make_onchain_portfolio(
            &mut svm,
            program_id,
            portfolio_key,
            owner,
            market.to_bytes(),
        );

        // Use a random keypair as the "mint_authority" signer — it will NOT equal
        // the derived PDA for the registered nft_program_id.
        let fake_signer = Keypair::new();
        svm.airdrop(&fake_signer.pubkey(), 100_000_000_000).unwrap();

        let new_owner = [0x02u8; 32];
        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::TransferPortfolioOwnership {
                new_owner,
                asset_index: 0,
            }
            .encode(),
            vec![
                AccountMeta::new_readonly(fake_signer.pubkey(), true), // wrong signer
                AccountMeta::new(portfolio_key, false),
                AccountMeta::new_readonly(registry, false),
            ],
            &[&fake_signer],
        );
        assert!(
            result.is_err(),
            "wrong signer (not the derived mint-auth PDA) must be rejected"
        );

        // Verify portfolio.owner unchanged.
        let data = svm.get_account(&portfolio_key).expect("portfolio").data;
        let wire = state::portfolio_wire(&data).expect("portfolio_wire");
        assert_eq!(wire.owner, owner, "owner must not have changed");
    }

    /// B-3 fail-closed uninitialized registry: if the registry PDA has no
    /// data (system-owned, empty), B-3 must reject.
    ///
    /// This exercises Guardrail 1 fail-closed requirement: absence of a
    /// registered NFT program ID must be a hard reject, not an open door.
    #[test]
    fn b3_fail_closed_uninitialized_registry() {
        let env = setup();
        let Env {
            mut svm,
            program_id,
            payer,
            admin: _,
            market,
        } = env;

        // Derive registry address but do NOT initialize it.
        let (registry, _) = derive_nft_registry(&program_id, &market);

        // Create a portfolio.
        let portfolio_key = Pubkey::new_unique();
        let owner = [0x01u8; 32];
        make_onchain_portfolio(
            &mut svm,
            program_id,
            portfolio_key,
            owner,
            market.to_bytes(),
        );

        // Fund the registry address with a system account (no program data).
        svm.set_account(
            registry,
            Account {
                lamports: 1_000_000,
                data: vec![],
                owner: system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Try to call B-3 — should fail because registry is not initialized.
        let caller = Keypair::new();
        svm.airdrop(&caller.pubkey(), 100_000_000_000).unwrap();

        let result = send(
            &mut svm,
            program_id,
            &payer,
            ProgInstruction::TransferPortfolioOwnership {
                new_owner: [0x02u8; 32],
                asset_index: 0,
            }
            .encode(),
            vec![
                AccountMeta::new_readonly(caller.pubkey(), true),
                AccountMeta::new(portfolio_key, false),
                AccountMeta::new_readonly(registry, false),
            ],
            &[&caller],
        );
        assert!(
            result.is_err(),
            "uninitialized registry must cause B-3 to reject (fail-closed)"
        );
    }
}

// ── E2 NFT-holder auth verdict — concrete witness tests (runnable; complements
//    the exhaustive Kani proofs in v16_kani.rs). Each proves the verdict
//    DISCRIMINATES: a valid holder accepts, and flipping ANY single gate rejects.
//    This is the non-vacuity witness — the function is neither constant-true nor
//    constant-false and every gate is load-bearing. ──
use percolator_prog::processor::nft_holder_auth_decision;

const A: [u8; 32] = [1u8; 32]; // owner / mint-auth PDA (escrow)
const PK: [u8; 32] = [2u8; 32]; // portfolio key
const SG: [u8; 32] = [3u8; 32]; // signer / holder
const MT: [u8; 32] = [4u8; 32]; // bound mint
const X: [u8; 32] = [9u8; 32]; // a different key

/// A fully-valid holder. All gates satisfied.
fn accept() -> bool {
    nft_holder_auth_decision(A, A, true, PK, PK, true, MT, MT, SG, SG, 1, true)
}

#[test]
fn e2_auth_accepts_valid_holder() {
    assert!(
        accept(),
        "valid bound-NFT holder of an escrowed position must authorize"
    );
}

#[test]
fn e2_auth_each_gate_is_load_bearing() {
    // Flip exactly one gate from the accepting baseline → must reject. Proves every
    // conjunct matters (not a constant-true predicate ignoring some check).
    assert!(
        !nft_holder_auth_decision(A, X, true, PK, PK, true, MT, MT, SG, SG, 1, true),
        "not escrowed"
    );
    assert!(
        !nft_holder_auth_decision(A, A, false, PK, PK, true, MT, MT, SG, SG, 1, true),
        "fake PDA owner"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, X, PK, true, MT, MT, SG, SG, 1, true),
        "PDA binds other portfolio"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, false, MT, MT, SG, SG, 1, true),
        "non-canonical PDA"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, true, MT, X, SG, SG, 1, true),
        "wrong mint"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, true, MT, MT, SG, X, 1, true),
        "ATA not owned by signer"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, true, MT, MT, SG, SG, 0, true),
        "amount 0"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, true, MT, MT, SG, SG, 2, true),
        "amount 2 (fungible)"
    );
    assert!(
        !nft_holder_auth_decision(A, A, true, PK, PK, true, MT, MT, SG, SG, 1, false),
        "uninitialized ATA"
    );
}
