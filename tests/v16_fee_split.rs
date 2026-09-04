//! Fee-split collection tests (2026-07-19 design).
//! The split is exact: protocol + creator + lp + insurance == fee, always.

use percolator_prog::policy_v16::{split_trade_fee, FeeSplitParts};

const P: u16 = 2000;
const C: u16 = 1600;
const L: u16 = 4800;
const I: u16 = 1600;

#[test]
fn split_is_exactly_conservative_for_round_amount() {
    let parts = split_trade_fee(10_000, P, C, L, I).unwrap();
    assert_eq!(parts.protocol, 2_000);
    assert_eq!(parts.creator, 1_600);
    assert_eq!(parts.lp, 4_800);
    assert_eq!(parts.insurance, 1_600);
    assert_eq!(
        parts.protocol + parts.creator + parts.lp + parts.insurance,
        10_000
    );
}

#[test]
fn dust_goes_to_insurance_and_total_is_still_exact() {
    // 7 atoms: every floor() is 0 or 1; the remainder must land on insurance.
    let parts = split_trade_fee(7, P, C, L, I).unwrap();
    assert_eq!(
        parts.protocol + parts.creator + parts.lp + parts.insurance,
        7,
        "conservation must hold even when every leg rounds down"
    );
    let floor_insurance = 7u128 * I as u128 / 10_000;
    assert!(
        parts.insurance >= floor_insurance,
        "insurance receives its floor plus all dust"
    );
}

#[test]
fn zero_fee_splits_to_all_zeros() {
    let parts = split_trade_fee(0, P, C, L, I).unwrap();
    assert_eq!(
        parts,
        FeeSplitParts {
            protocol: 0,
            creator: 0,
            lp: 0,
            insurance: 0
        }
    );
}

#[test]
fn conservation_holds_across_many_amounts() {
    for fee in 0u128..2_000 {
        let parts = split_trade_fee(fee, P, C, L, I).unwrap();
        assert_eq!(
            parts.protocol + parts.creator + parts.lp + parts.insurance,
            fee,
            "conservation failed at fee={fee}"
        );
    }
}

#[test]
fn config_size_is_576_and_16_byte_aligned() {
    use percolator_prog::constants::WRAPPER_CONFIG_LEN;
    use percolator_prog::state::WrapperConfigV16;
    assert_eq!(core::mem::size_of::<WrapperConfigV16>(), 576);
    assert_eq!(WRAPPER_CONFIG_LEN, 576);
    assert_eq!(576 % core::mem::align_of::<WrapperConfigV16>(), 0);
}

// ════════════════════════════════════════════════════════════════════════════
// Creator-fee-claim layout pins (2026-07-23 design §1 / testing item 1+2).
//
// `creator_fee_claimable_atoms` was squeezed into the ONLY 8-aligned slot of
// the pre-existing 10-byte `_padding_split`, precisely so that
// `WRAPPER_CONFIG_LEN` stays 576 and `MARKET_GROUP_OFF` (and therefore every
// asset-profile offset) does not move under the already-deployed 576-byte
// markets. These tests pin that byte-for-byte: a reorder that moved the three
// share fields, or a re-typing that grew the struct, is exactly the 496->576
// offset incident repeating, and it must break the build's tests loudly rather
// than brick a live market at read time.
// ════════════════════════════════════════════════════════════════════════════

/// Byte-exact placement of the new counter AND non-movement of the three share
/// fields it shares the tail with. Uses distinct magic values per field so a
/// swap between any two of them (not just a shift) is caught.
#[test]
fn creator_fee_counter_is_at_568_and_the_three_share_fields_have_not_moved() {
    use percolator_prog::state::WrapperConfigV16;

    let mut cfg = WrapperConfigV16::default();
    cfg.creator_share_bps = 0x1111;
    cfg.lp_share_bps = 0x2222;
    cfg.insurance_share_bps = 0x3333;
    cfg.creator_fee_claimable_atoms = 0x0102_0304_0506_0708;

    // Named-offset pins first. The byte-magic assertions below already catch a
    // move (mutation-proven 2026-07-24: reordering the tail so the counter sits
    // at 560..568 fails them), but they report it as `left: [8, 7] right: [17,
    // 17]` — these say WHICH field moved and to where.
    assert_eq!(
        core::mem::offset_of!(WrapperConfigV16, creator_share_bps),
        560
    );
    assert_eq!(core::mem::offset_of!(WrapperConfigV16, lp_share_bps), 562);
    assert_eq!(
        core::mem::offset_of!(WrapperConfigV16, insurance_share_bps),
        564
    );
    assert_eq!(core::mem::offset_of!(WrapperConfigV16, _padding_split), 566);
    assert_eq!(
        core::mem::offset_of!(WrapperConfigV16, creator_fee_claimable_atoms),
        568,
        "creator_fee_claimable_atoms must start at byte 568 — deployed 576-byte \
         markets read it there"
    );
    assert_eq!(
        core::mem::size_of_val(&cfg.creator_fee_claimable_atoms),
        8,
        "and must still be 8 bytes wide (568..576)"
    );

    let bytes = bytemuck::bytes_of(&cfg);
    assert_eq!(
        bytes.len(),
        576,
        "config must serialize to exactly 576 bytes"
    );

    assert_eq!(
        &bytes[560..562],
        &0x1111u16.to_le_bytes(),
        "creator_share_bps must still read at 560..562"
    );
    assert_eq!(
        &bytes[562..564],
        &0x2222u16.to_le_bytes(),
        "lp_share_bps must still read at 562..564"
    );
    assert_eq!(
        &bytes[564..566],
        &0x3333u16.to_le_bytes(),
        "insurance_share_bps must still read at 564..566"
    );
    assert_eq!(
        &bytes[566..568],
        &[0u8; 2],
        "the 2-byte remnant of _padding_split must stay zero, not absorb counter bytes"
    );
    assert_eq!(
        &bytes[568..576],
        &0x0102_0304_0506_0708u64.to_le_bytes(),
        "creator_fee_claimable_atoms must occupy bytes 568..576, little-endian"
    );

    // Round-trip through the same unaligned read the on-chain parse uses.
    let reparsed: WrapperConfigV16 = bytemuck::pod_read_unaligned(bytes);
    assert_eq!(reparsed.creator_fee_claimable_atoms, 0x0102_0304_0506_0708);
    assert_eq!(reparsed.creator_share_bps, 0x1111);
    assert_eq!(reparsed.lp_share_bps, 0x2222);
    assert_eq!(reparsed.insurance_share_bps, 0x3333);
}

/// Backward compatibility (design §1): every market deployed before this change
/// has bytes 566..576 zeroed, because they were padding. Parsing such a tail
/// must yield `claimable == 0` -- and, just as importantly, must still yield
/// the three share values, i.e. the counter must not have been carved out of
/// bytes the shares occupy.
#[test]
fn preexisting_market_with_zeroed_pad_tail_parses_as_zero_claimable() {
    use percolator_prog::state::WrapperConfigV16;

    let mut cfg = WrapperConfigV16::default();
    cfg.creator_share_bps = 1600;
    cfg.lp_share_bps = 4800;
    cfg.insurance_share_bps = 1600;
    cfg.creator_fee_claimable_atoms = u64::MAX; // will be zeroed below

    // Reproduce the on-chain shape of a market written by the OLD program:
    // the whole 10-byte `_padding_split` region is zero.
    let mut bytes = bytemuck::bytes_of(&cfg).to_vec();
    for b in bytes[566..576].iter_mut() {
        *b = 0;
    }

    let parsed: WrapperConfigV16 = bytemuck::pod_read_unaligned(&bytes);
    assert_eq!(
        parsed.creator_fee_claimable_atoms, 0,
        "an old market's zeroed pad tail must read as a zero claimable balance"
    );
    assert_eq!(
        parsed.creator_share_bps, 1600,
        "shares must survive the zeroed tail"
    );
    assert_eq!(parsed.lp_share_bps, 4800);
    assert_eq!(parsed.insurance_share_bps, 1600);
}

/// The counter must not have grown the struct: `MARKET_GROUP_OFF` is
/// `HEADER_LEN + WRAPPER_CONFIG_LEN`, so a single byte of growth shifts the
/// entire engine group and every asset-profile offset out from under the
/// deployed markets.
#[test]
fn creator_fee_counter_did_not_shift_market_group_off() {
    use percolator_prog::constants::{HEADER_LEN, MARKET_GROUP_OFF, WRAPPER_CONFIG_LEN};
    use percolator_prog::state::WrapperConfigV16;
    assert_eq!(WRAPPER_CONFIG_LEN, 576);
    assert_eq!(core::mem::size_of::<WrapperConfigV16>(), WRAPPER_CONFIG_LEN);
    assert_eq!(MARKET_GROUP_OFF, HEADER_LEN + 576);
    assert_eq!(
        MARKET_GROUP_OFF, 592,
        "deployed 576-byte markets pin this to 592"
    );
}

#[test]
fn default_shares_sum_to_total_and_satisfy_floors() {
    use percolator_prog::constants::*;
    assert_eq!(
        DEFAULT_CREATOR_SHARE_BPS + DEFAULT_LP_SHARE_BPS + DEFAULT_INSURANCE_SHARE_BPS,
        FEE_SHARE_TOTAL_BPS
    );
    assert!(DEFAULT_CREATOR_SHARE_BPS <= MAX_CREATOR_SHARE_BPS);
    assert!(DEFAULT_LP_SHARE_BPS >= MIN_LP_SHARE_BPS);
    assert!(DEFAULT_INSURANCE_SHARE_BPS >= MIN_INSURANCE_SHARE_BPS);
}

// NOTE: the brief placed this assertion in tests/v16_kani.rs, "alongside the
// existing ordinal assertions." That file opens with `#![cfg(kani)]` at file
// scope, so under plain `cargo test` (no kani cfg) its entire contents --
// including a bare `#[test]` fn -- compile to nothing (verified: "running 0
// tests" even with the file's pre-existing kani proofs present). A plain
// `#[test]` there would silently never execute, and `cargo kani` does not
// run non-`#[kani::proof]` items either, so it would never run at all. It
// lives here instead, alongside this file's other pure constant/ordinal
// checks (`default_shares_sum_to_total_and_satisfy_floors`), where it
// actually executes under `cargo test`.
#[test]
fn fee_split_error_ordinals_are_pinned() {
    use percolator_prog::error::PercolatorError;
    assert_eq!(PercolatorError::FeeSplitFloorViolation as u32, 51);
    assert_eq!(PercolatorError::FeeSplitSumInvalid as u32, 52);
    assert_eq!(PercolatorError::NoInsuranceReserveToClaim as u32, 53);
    // `load_bound_stake_pool` diagnostics — appended, never reordered.
    assert_eq!(PercolatorError::StakePoolNotBound as u32, 54);
    // Slot 55 REUSED: was `StakePoolAssetAdminNotBurned` (an ineffective
    // mitigation, removed), now the forgery gate. Ordinals are wire-visible, so
    // the slot is reused rather than vacated — 56-59 must not shift.
    assert_eq!(PercolatorError::StakePoolOwnerMismatch as u32, 55);
    assert_eq!(PercolatorError::StakePoolAuthorityMismatch as u32, 56);
    assert_eq!(PercolatorError::StakePoolMarketMismatch as u32, 57);
    assert_eq!(PercolatorError::StakePoolWrapperMismatch as u32, 58);
    assert_eq!(PercolatorError::StakePoolModeMismatch as u32, 59);
    // Appended at the tail — nothing above may move.
    assert_eq!(PercolatorError::StakeProgramNotPinned as u32, 60);
    // 2026-07-22/24 additions, appended after 60 in declaration order. Pinned
    // here so that a future variant inserted ABOVE either of them (which would
    // silently renumber every wire-visible ordinal below it) fails loudly.
    assert_eq!(PercolatorError::AssetSlotAlreadyConfigured as u32, 61);
    assert_eq!(PercolatorError::CreatorFeeOverClaim as u32, 62);
}

// ════════════════════════════════════════════════════════════════════════════
// Dispatch-tag wire pin (creator-fee-claim, testing item 3).
//
// PROVEN NEEDED 2026-07-24: renumbering BOTH the encode arm (`out.push(90)`)
// and the decode arm (`90 => Self::WithdrawCreatorFee`) to 91 together left the
// ENTIRE test suite green. Every existing test builds its instruction through
// `Instruction::encode()` and feeds it to `process_instruction`, so encode and
// decode cancel out and the byte on the wire is never observed. The SDK, the
// keeper and every already-signed transaction DO observe it — that is the exact
// shape of the v16/v17 offset drift that has bitten this project before.
// ════════════════════════════════════════════════════════════════════════════

/// The first byte of an encoded `WithdrawCreatorFee` must be exactly 90, and a
/// hand-built 90-tagged payload must decode back to it. Both halves compare
/// against the LITERAL 90 rather than against each other, so a coordinated
/// rename of both arms still fails.
#[test]
fn withdraw_creator_fee_is_dispatch_tag_90_on_the_wire() {
    use percolator_prog::ix::Instruction;

    let encoded = Instruction::WithdrawCreatorFee {
        amount: 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10,
        asset_index: 0x1234,
    }
    .encode();
    assert_eq!(
        encoded[0], 90,
        "WithdrawCreatorFee must encode as dispatch tag 90 — the SDK, the keeper \
         and any pre-signed transaction all hard-code this byte"
    );
    // GH#420: 17 -> 19 bytes. This IS a wire break, and a deliberate one — the
    // creator claim now names WHICH asset's fees it is claiming, because a single
    // market-wide counter could only ever pay one admin. `asset_index` is appended
    // AFTER `amount`, so the tag byte and the u128 keep their offsets and an old
    // 17-byte caller fails to DECODE rather than being silently read as asset 0.
    assert_eq!(
        encoded.len(),
        1 + 16 + 2,
        "tag byte + u128 amount + u16 asset_index; a length change is a wire break"
    );
    assert_eq!(
        &encoded[17..19],
        &0x1234u16.to_le_bytes(),
        "asset_index is a little-endian u16 immediately after the amount"
    );
    assert_eq!(
        &encoded[1..17],
        &0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10u128.to_le_bytes(),
        "amount is a little-endian u128 immediately after the tag"
    );

    // Decode direction, built from the literal byte rather than from encode().
    let mut wire = vec![90u8];
    wire.extend_from_slice(&7u128.to_le_bytes());
    wire.extend_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        Instruction::decode(&wire),
        Ok(Instruction::WithdrawCreatorFee {
            amount: 7,
            asset_index: 3
        }),
        "byte 90 must dispatch to WithdrawCreatorFee"
    );

    // GH#420: the OLD 17-byte form must be REFUSED, not silently accepted as
    // asset 0. A stale caller claiming against the wrong asset's pot is exactly
    // the confusion this change exists to end.
    let mut stale = vec![90u8];
    stale.extend_from_slice(&7u128.to_le_bytes());
    assert!(
        Instruction::decode(&stale).is_err(),
        "the pre-GH#420 17-byte payload must fail to decode"
    );

    // And 90 must not have been taken from a neighbour: pin the two adjacent
    // fee-withdrawal tags this instruction was modelled on.
    assert_eq!(
        Instruction::WithdrawProtocolFee { amount: 1 }.encode()[0],
        84
    );
    assert_eq!(Instruction::WithdrawInsuranceReserveToStake.encode()[0], 87);
}

/// The harness mounts the stake `.so` at `STAKE_ID`; tag 87 pins
/// `constants::STAKE_PROGRAM_ID`. If these ever diverge every tag-87 test
/// starts failing with `StakePoolOwnerMismatch` for a reason that has nothing
/// to do with the behaviour under test, so pin them together, loudly.
///
/// GATED on `devnet` to match `constants::STAKE_PROGRAM_ID` itself
/// (`src/v16_program.rs:303`). A default build has no pin at all — that is the
/// mainnet shape, where tag 87 fails closed with `StakeProgramNotPinned` — so
/// there is nothing to compare against and this assertion is vacuous. Without
/// this gate the whole `v16_fee_split` binary fails to COMPILE under a default
/// `cargo test`, taking the split-conservation tests and the error-ordinal pins
/// down with it.
#[cfg(feature = "devnet")]
#[test]
fn pinned_stake_program_id_matches_the_id_the_harness_mounts() {
    assert_eq!(
        percolator_prog::constants::STAKE_PROGRAM_ID.to_bytes(),
        common::STAKE_ID.to_bytes(),
        "tests/common/mod.rs::STAKE_ID must equal the wrapper's pinned \
         STAKE_PROGRAM_ID (both are the lineage-verified devnet deployment)"
    );
}

#[test]
fn validate_fee_split_accepts_defaults() {
    use percolator_prog::policy_v16::validate_fee_split;
    assert!(validate_fee_split(1600, 4800, 1600).is_ok());
}

#[test]
fn validate_fee_split_accepts_both_floor_extremes() {
    use percolator_prog::policy_v16::validate_fee_split;
    // The three floors sum to exactly 8000, so this is the ONLY point where
    // all three bind simultaneously. It must be accepted, not rejected.
    assert!(validate_fee_split(3600, 3200, 1200).is_ok());
}

#[test]
fn validate_fee_split_rejects_wrong_sum_with_exact_code() {
    use percolator_prog::policy_v16::validate_fee_split;
    use solana_program::program_error::ProgramError;
    // 1600 + 4800 + 1000 = 7400 != 8000
    assert_eq!(
        validate_fee_split(1600, 4800, 1000).unwrap_err(),
        ProgramError::Custom(52),
        "must be FeeSplitSumInvalid, not a generic error"
    );
    // Over-sum must also be rejected, not silently truncated.
    assert_eq!(
        validate_fee_split(1600, 4800, 2000).unwrap_err(),
        ProgramError::Custom(52)
    );
}

#[test]
fn validate_fee_split_rejects_floor_violations_with_exact_code() {
    use percolator_prog::policy_v16::validate_fee_split;
    use solana_program::program_error::ProgramError;
    // LP below floor, sum exactly 8000, no other floor violated.
    assert_eq!(
        validate_fee_split(3600, 3100, 1300).unwrap_err(),
        ProgramError::Custom(51)
    );
    // Insurance below floor, sum exactly 8000, no other floor violated.
    assert_eq!(
        validate_fee_split(3600, 3300, 1100).unwrap_err(),
        ProgramError::Custom(51)
    );
    // Creator above floor. Because the three floors sum to exactly 8000, this
    // necessarily drags another leg under its floor too -- a single-violation
    // creator case does not exist. Same code either way.
    assert_eq!(
        validate_fee_split(3700, 3200, 1100).unwrap_err(),
        ProgramError::Custom(51)
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Tag 87 — WithdrawInsuranceReserveToStake. TOKEN-VISIBLE tests.
//
// Counter-only assertions are exactly how a no-op ships (Task 7). Every test
// below asserts on REAL SPL balances: the stake vault's `amount` must rise by
// the transferred atoms and the market vault's must fall by the same, with
// `header.insurance` tracking it. Conservation is asserted explicitly.
//
// The stake pool here is hand-crafted at the v4 layout (408 B, version 4 --
// `percolator-stake/src/state.rs:237`/`:584` at `origin/main` d0c6ecb). It is NOT decoration: the real
// `percolator_stake.so` is loaded and its BindInsuranceAuthority (tag 19) is
// what establishes `insurance_authority`, so a wrong offset or version in the
// craft fails the bind and the test cannot reach tag 87 at all. That makes the
// bind a live cross-check of the wrapper's own layout constants.
// (`tests/v16_five_program_crosscut.rs:1662` still crafts the stale v2 384-B
// shape, which is why its stake tests fail at baseline.)
// ════════════════════════════════════════════════════════════════════════════

mod common;

use common::{
    assemble_five_program_svm, assert_custom, make_mint_data, make_token_data, send_ixs,
    spl_token_classic_id, PERCOLATOR_MAINNET, STAKE_ID,
};
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::state;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_sdk::{account::Account, pubkey::Pubkey, signature::Keypair, signer::Signer};
use spl_token::solana_program::program_pack::Pack;
use spl_token::state::Account as TokenAccount;

const FS_MAX_ASSETS: u16 = 2;

fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse()
        .unwrap();
    Pubkey::find_program_address(
        &[
            vault_authority.as_ref(),
            spl_token::ID.as_ref(),
            mint.as_ref(),
        ],
        &ata_program,
    )
    .0
}

/// v4 StakePool (408 B). Offsets mirror `percolator-stake/tests/struct_layout.rs`.
///
/// v4, not v3 (#441): stake `origin/main` (d0c6ecb) emits 408 B / version 4 after
/// #280 promoted the #242 cooldown timelock out of `_reserved`. Every offset this
/// craft writes is const-asserted UNCHANGED at `state.rs:209-223`; only the size
/// and the version byte move. The wrapper now pins v4 exclusively, so a v3 craft
/// would be rejected on length (`data.len() < 408`) before the version is read.
#[allow(clippy::too_many_arguments)]
fn craft_stake_pool_v4(
    market: &Pubkey,
    admin: &Pubkey,
    collateral_mint: &Pubkey,
    lp_mint: &Pubkey,
    stake_vault: &Pubkey,
    total_deposited: u64,
    total_lp_supply: u64,
    percolator_program: &Pubkey,
    vault_authority_bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8; 408];
    d[0] = 1; // is_initialized
    d[1] = 255; // pool bump (informational)
    d[2] = vault_authority_bump;
    d[8..40].copy_from_slice(market.as_ref()); // slab
    d[40..72].copy_from_slice(admin.as_ref());
    d[72..104].copy_from_slice(collateral_mint.as_ref());
    d[104..136].copy_from_slice(lp_mint.as_ref());
    d[136..168].copy_from_slice(stake_vault.as_ref()); // vault
    d[168..176].copy_from_slice(&total_deposited.to_le_bytes());
    d[176..184].copy_from_slice(&total_lp_supply.to_le_bytes());
    d[224..256].copy_from_slice(percolator_program.as_ref()); // CPI target
                                                              // d[280] pool_mode = 0 (insurance LP) — already zero.
    d[320..328].copy_from_slice(b"SPOOL_V1"); // discriminator
    d[328] = 4; // CURRENT_VERSION
    d
}

struct FeeEnv {
    svm: litesvm::LiteSVM,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

impl FeeEnv {
    /// Market at MAINNET + a bound v3 stake pool + asset 0's `asset_admin`
    /// BURNED.
    ///
    /// The burn is NO LONGER REQUIRED by tag 87 — the trust root is the pinned
    /// `constants::STAKE_PROGRAM_ID`, not the burn (see the SECURITY section at
    /// the foot of this file, and
    /// `tag87_succeeds_with_asset_admin_live_proving_the_burn_gate_is_gone`,
    /// which asserts the unburned path works). It is kept here only so the
    /// default fixture exercises the burned state too, since a burned
    /// `asset_admin` remains a perfectly legitimate production configuration.
    fn new(insurance_atoms: u64) -> Self {
        Self::build(insurance_atoms, true)
    }

    /// Same, but leaves asset 0's `asset_admin` LIVE — the pre-burn state a
    /// freshly created market is in, and the state the forged-pool exploit
    /// needs. Only the security tests use this.
    fn new_with_asset_admin_live(insurance_atoms: u64) -> Self {
        Self::build(insurance_atoms, false)
    }

    fn build(insurance_atoms: u64, burn_asset_admin: bool) -> Self {
        let matcher_program = Pubkey::new_unique();
        let mut svm = assemble_five_program_svm(matcher_program);
        let program_id = PERCOLATOR_MAINNET;

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let (vault_authority, _) =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
        let vault = canonical_vault_ata(&vault_authority, &mint);

        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        let plant = |svm: &mut litesvm::LiteSVM, key: Pubkey, data: Vec<u8>, owner: Pubkey| {
            svm.set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        };
        plant(&mut svm, mint, make_mint_data(), spl_token_classic_id());
        plant(
            &mut svm,
            vault,
            make_token_data(mint, vault_authority, 0),
            spl_token_classic_id(),
        );
        // Admin's funding account for TopUpInsurance.
        let admin_token = Pubkey::new_unique();
        plant(
            &mut svm,
            admin_token,
            make_token_data(mint, admin.pubkey(), insurance_atoms),
            spl_token_classic_id(),
        );
        let market_len = state::market_account_len_for_capacity(FS_MAX_ASSETS as usize).unwrap();
        plant(&mut svm, market, vec![0u8; market_len], program_id);

        let mut env = FeeEnv {
            svm,
            payer,
            admin,
            market,
            mint,
            vault,
            pool_pda: Pubkey::default(),
            vault_auth: Pubkey::default(),
            stake_vault: Pubkey::default(),
        };
        env.init_market();
        if insurance_atoms > 0 {
            env.top_up_insurance(admin_token, insurance_atoms);
        }
        env.setup_and_bind_stake_pool();
        // MUST come after the bind: BindInsuranceAuthority itself is authorised
        // by asset 0's `asset_admin`/`insurance_authority` (both `marketauth`
        // pre-bind), so burning first would make the bind impossible.
        if burn_asset_admin {
            env.burn_asset_admin();
        }
        env
    }

    /// Burn asset 0's `asset_admin` via the REAL instruction (tag 65,
    /// `UpdateAssetAuthority { asset_index: 0, kind: ASSET_AUTH_ADMIN,
    /// new_pubkey: [0; 32] }`). This is the operational step a market-creation
    /// sequence MUST perform for tag 87 to ever work.
    fn burn_asset_admin(&mut self) {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                // Burning to zero needs no co-signer; this handle is unused.
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            data: ProgInstruction::UpdateAssetAuthority {
                asset_index: 0,
                kind: 0, // ASSET_AUTH_ADMIN
                new_pubkey: [0u8; 32],
            }
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin])
            .expect("burn asset 0 asset_admin (tag 65)");
        assert_eq!(
            self.asset0_profile().asset_admin,
            [0u8; 32],
            "asset_admin must actually be burned"
        );
    }

    fn asset0_profile(&self) -> state::AssetOracleProfileV16 {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        let n = core::mem::size_of::<state::AssetOracleProfileV16>();
        bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n])
    }

    /// Overwrite asset 0's stored profile. Used by the security tests to
    /// construct an exploit's END STATE directly, so the assertion is about what
    /// tag 87 accepts rather than about how the state was reached.
    fn set_asset0_profile(&mut self, profile: &state::AssetOracleProfileV16) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, group) = state::market_view_mut(&mut acct.data).unwrap();
            let n = core::mem::size_of::<state::AssetOracleProfileV16>();
            group.markets[0].wrapper[..n].copy_from_slice(bytemuck::bytes_of(profile));
        }
        self.svm.set_account(self.market, acct).unwrap();
    }

    fn init_market(&mut self) {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.mint, false),
            ],
            data: ProgInstruction::InitMarket {
                max_portfolio_assets: FS_MAX_ASSETS,
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
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect("InitMarket");
    }

    fn top_up_insurance(&mut self, source: Pubkey, amount: u64) {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            data: ProgInstruction::TopUpInsurance {
                amount: amount as u128,
            }
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect("TopUpInsurance");
    }

    /// Plant a v3 pool + its vault, then drive the REAL stake program's
    /// BindInsuranceAuthority so `insurance_authority == vault_auth`.
    fn setup_and_bind_stake_pool(&mut self) {
        let (pool_pda, _) =
            Pubkey::find_program_address(&[b"stake_pool", self.market.as_ref()], &STAKE_ID);
        let (vault_auth, vault_auth_bump) =
            Pubkey::find_program_address(&[b"vault_auth", pool_pda.as_ref()], &STAKE_ID);
        let stake_vault = Pubkey::new_unique();
        self.svm
            .set_account(
                stake_vault,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, vault_auth, 0),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let lp_mint = Pubkey::new_unique();
        let pool_bytes = craft_stake_pool_v4(
            &self.market,
            &self.admin.pubkey(),
            &self.mint,
            &lp_mint,
            &stake_vault,
            0,
            1_000, // non-zero LP supply: a real staker constituency
            &PERCOLATOR_MAINNET,
            vault_auth_bump,
        );
        self.svm
            .set_account(
                pool_pda,
                Account {
                    lamports: 1_000_000_000,
                    data: pool_bytes,
                    owner: STAKE_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();

        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: STAKE_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(pool_pda, false),
                AccountMeta::new_readonly(vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(PERCOLATOR_MAINNET, false),
            ],
            data: vec![19u8],
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect(
            "BindInsuranceAuthority (v3 pool) — layout constants must match the stake program",
        );

        self.pool_pda = pool_pda;
        self.vault_auth = vault_auth;
        self.stake_vault = stake_vault;
    }

    /// Make the market's insurance UNBUDGETED, i.e. the surplus a trade fee
    /// produces.
    ///
    /// `TopUpInsurance` is how real tokens get into the market vault, but it
    /// books the atoms into a DOMAIN BUDGET — and budgeted insurance is
    /// deliberately not surplus, so `engine_available` is 0 and every leg
    /// correctly declines to touch it. Trade fees behave the opposite way: they
    /// raise `header.insurance` without raising any domain budget, which is
    /// precisely what makes the three fee legs claimable. Zeroing the budget
    /// here reproduces that end state while keeping the real SPL tokens that
    /// TopUpInsurance moved. Mirrors `v16_wrapper.rs::seed_protocol_fee_fixture`,
    /// which seeds `group.insurance`/`group.vault` directly for the same reason.
    fn unbudget_insurance(&mut self) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, group) = state::market_view_mut(&mut acct.data).unwrap();
            group.header.insurance_domain_budget_remaining_total = percolator::V16PodU128::new(0);
        }
        self.svm.set_account(self.market, acct).unwrap();
    }

    /// Directly seed the wrapper-side accrual counter. Accrual itself is
    /// Task 3's surface and is exercised by the split tests above; what is
    /// under test here is the WITHDRAW path, and seeding lets the clamp be
    /// driven to an exact boundary.
    fn set_reserve_accrued(&mut self, atoms: u128) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        let (mut cfg, _, _, _) = state::read_market_config_mode_and_capacity(&acct.data).unwrap();
        cfg.insurance_reserve_accrued_atoms = atoms;
        state::write_wrapper_config(&mut acct.data, &cfg).unwrap();
        self.svm.set_account(self.market, acct).unwrap();
    }

    fn reserve_counters(&self) -> (u128, u128) {
        let acct = self.svm.get_account(&self.market).unwrap();
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&acct.data).unwrap();
        (
            cfg.insurance_reserve_accrued_atoms,
            cfg.insurance_reserve_withdrawn_atoms,
        )
    }

    /// `header.insurance` and `header.vault`, read from the live account.
    fn header_insurance_and_vault(&self) -> (u128, u128) {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        (group.header.insurance.get(), group.header.vault.get())
    }

    fn token_amount(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }

    /// `header.insurance_domain_budget_remaining_total`, read from the live
    /// account. The whole point of the real-accrual test is that this stays 0
    /// while `header.insurance` rises.
    fn header_domain_budget(&self) -> u128 {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        group.header.insurance_domain_budget_remaining_total.get()
    }

    /// Zero the creator leg so trade fees produce NO domain budget at all.
    /// `validate_fee_split` has no creator minimum, only a max, so 0/3200/4800
    /// is a legal split (sum 8000 == FEE_SHARE_TOTAL_BPS).
    fn set_fee_split(&mut self, creator: u16, lp: u16, insurance: u16) {
        let admin = self.admin.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            data: ProgInstruction::UpdateFeeSplit {
                creator_share_bps: creator,
                lp_share_bps: lp,
                insurance_share_bps: insurance,
            }
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect("UpdateFeeSplit");
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let portfolio = Pubkey::new_unique();
        let len = state::portfolio_account_len_for_market_slots(FS_MAX_ASSETS as usize).unwrap();
        self.svm
            .set_account(
                portfolio,
                Account {
                    lamports: 1_000_000_000,
                    data: vec![0u8; len],
                    owner: PERCOLATOR_MAINNET,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            data: ProgInstruction::InitPortfolio.encode(),
        };
        send_ixs(&mut self.svm, &payer, vec![ix], &[owner]).expect("InitPortfolio");
        portfolio
    }

    /// Real `Deposit`: moves real SPL tokens into the market vault.
    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
        let source = Pubkey::new_unique();
        self.svm
            .set_account(
                source,
                Account {
                    lamports: 1_000_000_000,
                    data: make_token_data(self.mint, owner.pubkey(), amount as u64),
                    owner: spl_token_classic_id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            data: ProgInstruction::Deposit { amount }.encode(),
        };
        send_ixs(&mut self.svm, &payer, vec![ix], &[owner]).expect("Deposit");
    }

    /// Real `TradeNoCpi`. The effective fee is
    /// `max(fee_bps, cfg.trade_fee_base_bps)`, so passing `fee_bps` directly is
    /// enough to make a market with a zero base fee charge one.
    fn trade(
        &mut self,
        owner_a: &Keypair,
        account_a: Pubkey,
        owner_b: &Keypair,
        account_b: Pubkey,
        size_q: i128,
        exec_price: u64,
        fee_bps: u64,
    ) -> Result<(), solana_sdk::transaction::TransactionError> {
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(account_a, false),
                AccountMeta::new(account_b, false),
            ],
            data: ProgInstruction::TradeNoCpi {
                asset_index: 0,
                size_q,
                exec_price,
                fee_bps,
            }
            .encode(),
        };
        send_ixs(&mut self.svm, &payer, vec![ix], &[owner_a, owner_b])
    }

    fn withdraw_to_stake(&mut self) -> Result<(), solana_sdk::transaction::TransactionError> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
        let (vault_authority, _) =
            Pubkey::find_program_address(&[b"vault", self.market.as_ref()], &PERCOLATOR_MAINNET);
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.pool_pda, false),
                AccountMeta::new(self.stake_vault, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            data: ProgInstruction::WithdrawInsuranceReserveToStake.encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[&cranker])
    }
}

/// THE test: atoms must actually LAND in the stake vault as SPL tokens.
#[test]
fn tag87_moves_real_tokens_into_the_stake_vault_and_conserves_value() {
    const FUNDED: u64 = 1_000_000;
    const ACCRUED: u128 = 250_000;
    let mut env = FeeEnv::new(FUNDED);

    env.unbudget_insurance();
    env.set_reserve_accrued(ACCRUED);

    let stake_before = env.token_amount(env.stake_vault);
    let market_vault_before = env.token_amount(env.vault);
    let (ins_before, vault_before) = env.header_insurance_and_vault();
    let (accrued_before, withdrawn_before) = env.reserve_counters();
    assert_eq!(stake_before, 0, "stake vault starts empty");
    assert_eq!(withdrawn_before, 0, "nothing withdrawn yet");
    assert_eq!(accrued_before, ACCRUED);

    env.withdraw_to_stake().expect("tag 87 must succeed");

    let stake_after = env.token_amount(env.stake_vault);
    let market_vault_after = env.token_amount(env.vault);
    let (ins_after, vault_after) = env.header_insurance_and_vault();
    let (accrued_after, withdrawn_after) = env.reserve_counters();

    // ── TOKEN-VISIBLE: the stake vault's real SPL balance rose. ──
    assert_eq!(
        stake_after - stake_before,
        ACCRUED as u64,
        "stake vault SPL balance must rise by exactly the accrued insurance leg \
         — this is the assertion that a counter-only no-op cannot pass"
    );
    // ── The tokens came OUT of the market vault, not from nowhere. ──
    assert_eq!(
        market_vault_before - market_vault_after,
        ACCRUED as u64,
        "market vault SPL balance must fall by the same amount"
    );
    // ── CONSERVATION: no atoms created or destroyed. ──
    assert_eq!(
        market_vault_before + stake_before,
        market_vault_after + stake_after,
        "total SPL tokens across market vault + stake vault must be conserved"
    );
    // ── header.insurance tracks the real movement. ──
    assert_eq!(
        ins_before - ins_after,
        ACCRUED,
        "header.insurance must fall by exactly the transferred amount"
    );
    assert_eq!(
        vault_before - vault_after,
        ACCRUED,
        "header.vault must fall by exactly the transferred amount"
    );
    // ── The counter advanced by what was TRANSFERRED. ──
    assert_eq!(
        accrued_after, ACCRUED,
        "accrued is monotonic, untouched here"
    );
    assert_eq!(
        withdrawn_after - withdrawn_before,
        stake_after as u128 - stake_before as u128,
        "withdrawn must advance by exactly the amount the stake vault received"
    );
    assert!(
        withdrawn_after <= accrued_after,
        "invariant: withdrawn <= accrued"
    );

    // Fully drained ⇒ a second crank has nothing left and says so.
    assert_custom(env.withdraw_to_stake(), 53, "second crank after full drain");
}

/// THE PRODUCTION TEST. Every other tag-87 test seeds the claim with
/// `set_reserve_accrued()` + `unbudget_insurance()`, which means the
/// production-critical assumption — that a real trade fee raises
/// `header.insurance` WITHOUT raising any domain budget, leaving
/// `engine_available > 0` — was asserted in prose and never executed. That is
/// exactly the seam where the clamp could silently pin to zero forever and
/// every fixture-based test would still pass.
///
/// This test uses NEITHER shortcut. Real deposits, a real `TradeNoCpi`, real
/// fee accrual, then a real tag-87 crank, asserted on the stake vault's real
/// SPL balance.
#[test]
fn tag87_end_to_end_from_a_real_trade_fee_with_no_seeding() {
    // No TopUpInsurance: `header.insurance` must start at zero and rise ONLY
    // from the trade fee. TopUpInsurance would book a domain budget, which is
    // precisely the thing under test.
    let mut env = FeeEnv::new(0);

    // Zero the creator leg so the fee produces no domain budget whatsoever.
    // (With the default 1600 creator share the budget would rise too; the
    // surplus would merely be smaller, not absent. Zeroing makes the
    // "budget stays 0" assertion below exact rather than approximate.)
    env.set_fee_split(0, 3200, 4800);

    let (ins_start, vault_start) = env.header_insurance_and_vault();
    assert_eq!(ins_start, 0, "no insurance before any trade");
    assert_eq!(vault_start, 0, "no vault before any deposit");
    assert_eq!(
        env.header_domain_budget(),
        0,
        "no domain budget to begin with"
    );
    assert_eq!(env.reserve_counters(), (0, 0), "nothing accrued yet");

    // Two real traders with real collateral.
    let taker = Keypair::new();
    let maker = Keypair::new();
    let taker_pf = env.create_portfolio(&taker);
    let maker_pf = env.create_portfolio(&maker);
    const DEPOSIT: u128 = 30_000_000_000;
    env.deposit(&taker, taker_pf, DEPOSIT);
    env.deposit(&maker, maker_pf, DEPOSIT);

    let vault_spl_after_deposits = env.token_amount(env.vault);
    assert_eq!(
        vault_spl_after_deposits as u128,
        DEPOSIT * 2,
        "deposits must be real SPL tokens in the market vault"
    );

    // A real trade. notional = size_q * price / POS_SCALE
    //              = 100_000 * POS_SCALE * 100 / POS_SCALE = 10_000_000
    // fee (taker-only, ceil) = 10_000_000 * 500 / 10_000 = 500_000
    const POS_SCALE: i128 = 1_000_000;
    const SIZE_Q: i128 = POS_SCALE * 100_000;
    const PRICE: u64 = 100;
    const FEE_BPS: u64 = 500;
    env.trade(&taker, taker_pf, &maker, maker_pf, SIZE_Q, PRICE, FEE_BPS)
        .expect("a real trade must execute");

    // ── The production assumption, now EXECUTED rather than asserted in prose ──
    let (accrued, withdrawn) = env.reserve_counters();
    let (ins_after_trade, _) = env.header_insurance_and_vault();
    assert!(
        accrued > 0,
        "a real trade must accrue a real insurance leg; got {accrued}"
    );
    assert_eq!(withdrawn, 0, "nothing withdrawn yet");
    assert!(
        ins_after_trade > 0,
        "the trade fee must raise header.insurance; got {ins_after_trade}"
    );
    assert_eq!(
        env.header_domain_budget(),
        0,
        "THE LOAD-BEARING ASSERTION: a trade fee must NOT raise the insurance \
         domain budget, or engine_available is 0 and the clamp pins this leg to \
         zero forever in production"
    );
    // engine_available, computed exactly as the handler does, must cover the claim.
    assert!(
        ins_after_trade >= accrued,
        "engine_available ({ins_after_trade}) must cover the accrued leg ({accrued})"
    );
    println!(
        "EVIDENCE real-accrual: insurance={ins_after_trade} accrued={accrued} domain_budget=0"
    );

    // ── The crank, on genuinely earned atoms. ──
    let stake_before = env.token_amount(env.stake_vault);
    let market_vault_before = env.token_amount(env.vault);
    assert_eq!(stake_before, 0, "stake vault starts empty");

    env.withdraw_to_stake()
        .expect("tag 87 must succeed on genuinely accrued fees");

    let stake_after = env.token_amount(env.stake_vault);
    let market_vault_after = env.token_amount(env.vault);
    let (accrued_after, withdrawn_after) = env.reserve_counters();

    // THE assertion this test exists for: real SPL tokens actually landed.
    assert!(
        stake_after > stake_before,
        "the stake vault's real SPL balance must RISE — this is the only proof \
         the leg works in production rather than in a fixture"
    );
    assert_eq!(
        (stake_after - stake_before) as u128,
        accrued,
        "and it must rise by exactly the fee-accrued insurance leg"
    );
    assert_eq!(
        market_vault_before - market_vault_after,
        stake_after - stake_before,
        "the tokens came out of the market vault"
    );
    assert_eq!(
        market_vault_before + stake_before,
        market_vault_after + stake_after,
        "conservation across market vault + stake vault"
    );
    assert_eq!(
        withdrawn_after, accrued_after,
        "the whole earned leg is now marked paid, because it was fully paid"
    );
    assert!(
        withdrawn_after <= accrued_after,
        "invariant: withdrawn <= accrued"
    );
    println!(
        "EVIDENCE real-accrual crank: stake_vault_spl {stake_before} -> {stake_after}, \
         market_vault_spl {market_vault_before} -> {market_vault_after}"
    );

    // Nothing left to claim.
    assert_custom(
        env.withdraw_to_stake(),
        53,
        "second crank after the earned leg is fully paid",
    );
}

/// Partial fill: the shared surplus pool is smaller than the claim, so the
/// clamp bites. The remainder MUST stay claimable — marking it paid without
/// paying it is the exact defect this test exists to catch.
#[test]
fn tag87_partial_fill_marks_only_what_was_transferred() {
    const FUNDED: u64 = 100_000;
    // Claim far exceeds what `header.insurance` can supply.
    const ACCRUED: u128 = 400_000;
    let mut env = FeeEnv::new(FUNDED);
    env.unbudget_insurance();
    env.set_reserve_accrued(ACCRUED);

    let stake_before = env.token_amount(env.stake_vault);
    let (ins_before, _) = env.header_insurance_and_vault();
    assert!(
        ins_before < ACCRUED,
        "fixture must actually exercise the clamp"
    );

    env.withdraw_to_stake().expect("partial fill must succeed");

    let stake_after = env.token_amount(env.stake_vault);
    let (_, withdrawn) = env.reserve_counters();
    let moved = (stake_after - stake_before) as u128;

    assert_eq!(
        moved, ins_before,
        "the clamp must fill to the available surplus, not the requested claim"
    );
    assert!(moved < ACCRUED, "this must be a PARTIAL fill");
    assert_eq!(
        withdrawn, moved,
        "withdrawn must advance by the TRANSFERRED amount, never the pre-clamp claim"
    );
    assert_eq!(
        ACCRUED - withdrawn,
        ACCRUED - moved,
        "the unfilled remainder must stay claimable"
    );
    assert!(withdrawn < ACCRUED, "remainder must NOT be marked paid");
}

/// Zero case with the exact code.
#[test]
fn tag87_with_nothing_accrued_returns_custom_53() {
    let mut env = FeeEnv::new(1_000_000);
    let (accrued, withdrawn) = env.reserve_counters();
    assert_eq!(accrued, 0, "no volume ⇒ nothing accrued");
    assert_eq!(withdrawn, 0);
    assert_custom(
        env.withdraw_to_stake(),
        53,
        "NoInsuranceReserveToClaim on a zero-volume market",
    );
}

/// SECURITY: the destination is not the caller's to choose. A well-formed
/// token account of the right mint, at an address that is NOT `pool.vault`,
/// must be rejected — otherwise the whole insurance leg is drainable by
/// anyone, since tag 87 needs no authority signature.
#[test]
fn tag87_rejects_a_caller_supplied_destination() {
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    // An account the attacker controls, correct mint, correct decimals —
    // everything except being the pool's recorded vault.
    let attacker = Keypair::new();
    let attacker_token = Pubkey::new_unique();
    env.svm
        .set_account(
            attacker_token,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, attacker.pubkey(), 0),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let real_stake_vault = env.stake_vault;
    env.stake_vault = attacker_token;

    let res = env.withdraw_to_stake();
    assert!(
        res.is_err(),
        "a destination that is not pool.vault MUST be rejected"
    );
    assert_eq!(
        env.token_amount(attacker_token),
        0,
        "not a single atom may reach an attacker-chosen destination"
    );
    assert_eq!(
        env.token_amount(real_stake_vault),
        0,
        "and the real stake vault must be untouched by the failed attempt"
    );
    let (_, withdrawn) = env.reserve_counters();
    assert_eq!(
        withdrawn, 0,
        "a rejected redirect must not mark anything paid"
    );
}

/// SECURITY: the same, one step subtler — a token account whose SPL owner IS
/// the stake pool's `vault_auth` PDA, but which is not the address the pool
/// recorded. Catches a validation that checks only the owner and forgets the
/// `pool.vault` pin.
#[test]
fn tag87_rejects_a_vault_auth_owned_impostor_at_the_wrong_address() {
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    let impostor = Pubkey::new_unique();
    env.svm
        .set_account(
            impostor,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, env.vault_auth, 0),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    env.stake_vault = impostor;

    assert!(
        env.withdraw_to_stake().is_err(),
        "correct owner but wrong address must still be rejected — the pin is \
         pool.vault, not merely the SPL owner"
    );
    assert_eq!(env.token_amount(impostor), 0);
}

/// SECURITY: a market with no bound stake pool has no staker constituency
/// absorbing its losses, so there is nobody to pay. Fail closed rather than
/// transfer to a caller-supplied "pool".
#[test]
fn tag87_rejects_a_market_with_no_bound_stake_pool() {
    // Build an env, then point it at a market that was never bound.
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    // Zero the pool account's `slab` binding so the derived vault_auth can no
    // longer match the market's recorded insurance_authority.
    let mut pool = env.svm.get_account(&env.pool_pda).unwrap();
    pool.data[8..40].copy_from_slice(Pubkey::new_unique().as_ref());
    env.svm.set_account(env.pool_pda, pool).unwrap();

    assert_custom(
        env.withdraw_to_stake(),
        57, // StakePoolMarketMismatch — NOT a generic Unauthorized
        "a pool whose slab no longer names this market must be rejected",
    );
    let (_, withdrawn) = env.reserve_counters();
    assert_eq!(withdrawn, 0);
}

/// Each `load_bound_stake_pool` rejection must be individually diagnosable — a
/// keeper seeing a bare `Unauthorized` cannot tell "never bound" from "wrong
/// wrapper" from "mode-1 pool". These drive the two remaining pool-content
/// failures and pin their distinct codes.
#[test]
fn tag87_pool_content_failures_have_distinct_codes() {
    // (a) A pool whose recorded CPI target is a DIFFERENT wrapper deployment.
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);
    let mut pool = env.svm.get_account(&env.pool_pda).unwrap();
    pool.data[224..256].copy_from_slice(Pubkey::new_unique().as_ref());
    env.svm.set_account(env.pool_pda, pool).unwrap();
    assert_custom(
        env.withdraw_to_stake(),
        58, // StakePoolWrapperMismatch
        "a pool bound to another wrapper is not this market's constituency",
    );
    assert_eq!(env.token_amount(env.stake_vault), 0);

    // (b) A trading-mode (mode 1) pool: no FlushToInsurance loss exposure, so
    // not owed this leg.
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);
    let mut pool = env.svm.get_account(&env.pool_pda).unwrap();
    pool.data[280] = 1; // pool_mode = trading
    env.svm.set_account(env.pool_pda, pool).unwrap();
    assert_custom(
        env.withdraw_to_stake(),
        59, // StakePoolModeMismatch
        "a trading-mode pool must be refused with its own code",
    );
    assert_eq!(env.token_amount(env.stake_vault), 0);
}

/// MODE GATE: a resolved market must refuse to push surplus out to stakers,
/// even though the sibling protocol leg (tag 84) permits Resolved.
///
/// SCOPE OF THIS TEST — read the name literally. It asserts exactly three
/// things: the call is rejected with `EngineLockActive`, no tokens move, and
/// `insurance_reserve_withdrawn_atoms` is NOT advanced (so the claim is not
/// marked paid without paying). It says NOTHING about whether the claim is
/// still RECOVERABLE, and the earlier name ("...and_strands_nothing") wrongly
/// implied it did. It does not, and in fact the claim IS forfeited: tag 41's
/// capacity is budget-scoped while this leg is unbudgeted by construction of
/// the clamp, and `ResolveMarket` is one-way. See the FORFEITED note in
/// `handle_withdraw_insurance_reserve_to_stake`'s doc comment.
#[test]
fn tag87_on_a_resolved_market_is_rejected_without_marking_the_claim_paid() {
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    let admin = env.admin.insecure_clone();
    let payer = env.payer.insecure_clone();
    env.svm.warp_to_slot(50_000);
    let ix = Instruction {
        program_id: PERCOLATOR_MAINNET,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        data: ProgInstruction::ResolveMarket.encode(),
    };
    send_ixs(&mut env.svm, &payer, vec![ix], &[&admin]).expect("ResolveMarket");

    let stake_before = env.token_amount(env.stake_vault);
    assert_custom(
        env.withdraw_to_stake(),
        21, // EngineLockActive
        "tag 87 on a resolved market",
    );
    assert_eq!(
        env.token_amount(env.stake_vault),
        stake_before,
        "no tokens may move on a rejected mode gate"
    );
    let (accrued, withdrawn) = env.reserve_counters();
    assert_eq!(withdrawn, 0, "a rejected call must not mark anything paid");
    assert_eq!(
        accrued - withdrawn,
        250_000,
        "the whole claim must remain outstanding, not be marked paid"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// SECURITY — the stake program is PINNED, not discovered.
//
// Tag 87's destination used to be reachable by forgery: the handler recovered
// "the stake program" from `*pool_ai.owner` — an account the CALLER supplies —
// and then validated everything else self-consistently against it. A market
// creator could deploy their own program, derive matching PDAs, write a
// well-formed 392-byte pool, and take the payout.
//
// The tests below establish, in order:
//   1. the creator starts out holding `insurance_authority` (`InitMarket`
//      bootstraps it to `marketauth`), so the `== [0;32]` test never fires;
//   2. burning `asset_admin` does NOT stop them rotating it — self-rotation by
//      the current holder is a separate branch — which is why the previous
//      "burn the admin" mitigation bought exactly zero security;
//   3. the forged pool is nevertheless REJECTED, because the owner is pinned;
//   4. and tag 87 works fine with `asset_admin` still LIVE, proving the burn
//      requirement is genuinely gone rather than merely relocated.
// ════════════════════════════════════════════════════════════════════════════

/// PREMISE 1 of the exploit: on a market that has never bound a stake pool,
/// asset 0's `insurance_authority` is NOT zero — `InitMarket` bootstraps it to
/// `marketauth`, i.e. the creator's own wallet. So the `== [0; 32]` test is not
/// what makes an unbound market fail closed.
#[test]
fn unbound_market_has_creator_key_as_insurance_authority_not_zero() {
    let mut env = FeeEnv::new_with_asset_admin_live(0);
    // Undo the harness's bind so we observe the true post-InitMarket state.
    let mut profile = env.asset0_profile();
    profile.insurance_authority = env.admin.pubkey().to_bytes();
    env.set_asset0_profile(&profile);

    assert_ne!(
        env.asset0_profile().insurance_authority,
        [0u8; 32],
        "InitMarket bootstraps insurance_authority to marketauth, so the zero \
         test can never fire on a fresh market"
    );
    assert_eq!(
        env.asset0_profile().insurance_authority,
        env.admin.pubkey().to_bytes(),
        "and the value it holds is the CREATOR'S key"
    );
}

/// PREMISE 2, and THE REASON THE OLD MITIGATION WAS WORTHLESS.
///
/// `handle_update_asset_authority` has two branches: the `admin_signed` branch,
/// and self-rotation by the authority's CURRENT holder. Burning `asset_admin`
/// kills only the first. Because `InitMarket` makes the creator the current
/// holder of `insurance_authority`, the creator can still rotate it AFTER the
/// burn — so requiring the burn never closed the forgery, it only added an
/// ordering footgun.
///
/// This runs the REAL instruction with REAL signatures both before and after
/// the burn, so it is not an argument about the code, it is a demonstration.
#[test]
fn burning_asset_admin_does_not_stop_the_creator_rotating_insurance_authority() {
    let mut env = FeeEnv::new_with_asset_admin_live(0);
    // Put the market in its true post-InitMarket state: the creator holds
    // insurance_authority (the harness's bind would otherwise have moved it).
    let mut profile = env.asset0_profile();
    profile.insurance_authority = env.admin.pubkey().to_bytes();
    env.set_asset0_profile(&profile);

    let admin = env.admin.insecure_clone();
    let payer = env.payer.insecure_clone();
    let rotate_to = |env: &mut FeeEnv, target: &Keypair| {
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(target.pubkey(), true),
                AccountMeta::new(env.market, false),
            ],
            data: ProgInstruction::UpdateAssetAuthority {
                asset_index: 0,
                kind: 1, // ASSET_AUTH_INSURANCE
                new_pubkey: target.pubkey().to_bytes(),
            }
            .encode(),
        };
        send_ixs(&mut env.svm, &payer, vec![ix], &[&admin, target])
    };

    // Before the burn: rotation works (the `admin_signed` branch).
    let first = Keypair::new();
    env.svm.airdrop(&first.pubkey(), 1_000_000_000).unwrap();
    rotate_to(&mut env, &first).expect("a live asset_admin can retarget insurance_authority");
    assert_eq!(
        env.asset0_profile().insurance_authority,
        first.pubkey().to_bytes()
    );

    // Hand the authority back to the creator so they are once again the CURRENT
    // holder, then burn `asset_admin` — the supposed lock.
    let mut profile = env.asset0_profile();
    profile.insurance_authority = admin.pubkey().to_bytes();
    env.set_asset0_profile(&profile);
    env.burn_asset_admin();
    assert_eq!(
        env.asset0_profile().asset_admin,
        [0u8; 32],
        "fixture precondition: asset_admin really is burned"
    );

    // AFTER the burn: rotation STILL works, via self-rotation by the current
    // holder. This is the branch the burn does not touch.
    let second = Keypair::new();
    env.svm.airdrop(&second.pubkey(), 1_000_000_000).unwrap();
    rotate_to(&mut env, &second).expect(
        "THE POINT: burning asset_admin does NOT make insurance_authority \
         unrotatable — the current holder self-rotates, so the old \
         'burn the admin' mitigation closed nothing",
    );
    assert_eq!(
        env.asset0_profile().insurance_authority,
        second.pubkey().to_bytes(),
        "the post-burn rotation really lands"
    );
}

/// THE EXPLOIT, blocked by the OWNER PIN.
///
/// Constructs the exact end state a malicious creator reaches — a fully forged
/// stake-pool binding under a program THEY control — and asserts tag 87 refuses
/// it with not one atom moving.
///
/// CRITICALLY, this fixture BURNS `asset_admin` first. That is what makes it a
/// real regression test rather than a restatement of the old one: with the burn
/// satisfied, the previous `StakePoolAssetAdminNotBurned` gate is out of the
/// way, and every remaining check in the OLD `load_bound_stake_pool` — the
/// `vault_auth` derivation, the pool PDA, discriminator, version, `slab`,
/// `percolator_program`, `pool_mode`, `vault` — passes, because every one of
/// them was derived from `*pool_ai.owner`, i.e. from the attacker's own
/// program. Against the pre-fix build this test DRAINS (250_000 atoms land in
/// `forged_vault`). It passes only because the owner is now pinned.
///
/// `attacker_program` is never CPI'd into by the wrapper; it is only a PDA
/// derivation base and the pool account's owner, so an arbitrary
/// (non-executable) key faithfully models a program the attacker deployed.
#[test]
fn tag87_blocks_the_creator_forged_stake_pool_exploit() {
    // asset_admin BURNED — the old mitigation is satisfied and therefore inert.
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);
    assert_eq!(
        env.asset0_profile().asset_admin,
        [0u8; 32],
        "fixture precondition: asset_admin is burned, so the OLD gate cannot be \
         what blocks this — the owner pin must be"
    );

    // (1) The creator's own program, and the pool/authority it would derive.
    let attacker_program = Pubkey::new_unique();
    let (forged_pool, _) =
        Pubkey::find_program_address(&[b"stake_pool", env.market.as_ref()], &attacker_program);
    let (forged_vault_auth, forged_bump) =
        Pubkey::find_program_address(&[b"vault_auth", forged_pool.as_ref()], &attacker_program);

    // (2) A destination token account owned by that PDA — so the attacker's
    // program can sign for it and sweep afterwards.
    let forged_vault = Pubkey::new_unique();
    env.svm
        .set_account(
            forged_vault,
            Account {
                lamports: 1_000_000_000,
                data: make_token_data(env.mint, forged_vault_auth, 0),
                owner: spl_token_classic_id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    // (3) A byte-perfect pool at the derived address, owned by the attacker's
    // program: right discriminator, version 4, initialized, slab == market,
    // percolator_program == this wrapper, pool_mode == 0.
    //
    // It MUST track the pinned version (#441 moved it to v4). If this craft were
    // left at v3 the forged pool would be refused on its length/version before the
    // program pin was ever consulted, and this test would go green for the wrong
    // reason — proving only that the wrapper rejects stale layouts, not that it
    // rejects an attacker-owned program. Byte-perfect is the whole point.
    let pool_bytes = craft_stake_pool_v4(
        &env.market,
        &env.admin.pubkey(),
        &env.mint,
        &Pubkey::new_unique(),
        &forged_vault,
        0,
        1_000,
        &PERCOLATOR_MAINNET,
        forged_bump,
    );
    env.svm
        .set_account(
            forged_pool,
            Account {
                lamports: 1_000_000_000,
                data: pool_bytes,
                owner: attacker_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    // (4) The rotation (premise 2, proven executable post-burn above): point
    // asset 0's insurance_authority at the forged vault_auth PDA. Written
    // directly because a PDA cannot sign a top-level tx in this harness; the
    // rotation's REACHABILITY is what
    // `burning_asset_admin_does_not_stop_the_creator_rotating_insurance_authority`
    // establishes with real signatures.
    let mut profile = env.asset0_profile();
    profile.insurance_authority = forged_vault_auth.to_bytes();
    env.set_asset0_profile(&profile);

    // (5) Crank tag 87 at the forged pool.
    env.pool_pda = forged_pool;
    env.vault_auth = forged_vault_auth;
    let real_stake_vault = env.stake_vault;
    env.stake_vault = forged_vault;

    assert_custom(
        env.withdraw_to_stake(),
        55, // StakePoolOwnerMismatch
        "the forged-pool exploit must be blocked by the pinned-owner check — \
         every other check in load_bound_stake_pool passes against it",
    );
    assert_eq!(
        env.token_amount(forged_vault),
        0,
        "not one atom may reach the attacker's PDA-owned vault"
    );
    assert_eq!(
        env.token_amount(real_stake_vault),
        0,
        "and the genuine stake vault is untouched"
    );
    let (_, withdrawn) = env.reserve_counters();
    assert_eq!(withdrawn, 0, "nothing may be marked paid");
}

/// The owner pin must fire BEFORE any pool bytes are read, so an attacker's
/// account cannot be probed for pool-shape oracles and no attacker-authored
/// byte can influence anything. A pool owned by the wrong program but otherwise
/// EMPTY (zero-length data, so every field read would panic or mis-parse) must
/// still produce exactly `StakePoolOwnerMismatch`.
#[test]
fn tag87_owner_pin_fires_before_any_pool_byte_is_read() {
    let mut env = FeeEnv::new(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    let attacker_program = Pubkey::new_unique();
    let (forged_pool, _) =
        Pubkey::find_program_address(&[b"stake_pool", env.market.as_ref()], &attacker_program);
    let (forged_vault_auth, _) =
        Pubkey::find_program_address(&[b"vault_auth", forged_pool.as_ref()], &attacker_program);

    // Deliberately EMPTY: no discriminator, no version, not even 392 bytes.
    env.svm
        .set_account(
            forged_pool,
            Account {
                lamports: 1_000_000_000,
                data: Vec::new(),
                owner: attacker_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

    let mut profile = env.asset0_profile();
    profile.insurance_authority = forged_vault_auth.to_bytes();
    env.set_asset0_profile(&profile);

    env.pool_pda = forged_pool;
    env.vault_auth = forged_vault_auth;

    assert_custom(
        env.withdraw_to_stake(),
        55, // StakePoolOwnerMismatch — NOT InvalidInstruction from a length check
        "the owner check must precede the length/discriminator reads, so a \
         wrong-owner account never gets parsed at all",
    );
    let (_, withdrawn) = env.reserve_counters();
    assert_eq!(withdrawn, 0);
}

/// PROOF THE BURN REQUIREMENT IS GONE.
///
/// Tag 87 must succeed end to end on a legitimately bound pool while asset 0's
/// `asset_admin` is still LIVE. Under the previous build this exact scenario
/// failed closed with `StakePoolAssetAdminNotBurned` (Custom(55)), stranding
/// the whole insurance/staker fee leg behind an operational burn step that
/// protected nothing.
///
/// Asserted on REAL SPL balances, not counters: the stake vault must actually
/// receive the atoms and the market vault must actually lose them.
#[test]
fn tag87_succeeds_with_asset_admin_live_proving_the_burn_gate_is_gone() {
    let mut env = FeeEnv::new_with_asset_admin_live(1_000_000);
    env.unbudget_insurance();
    env.set_reserve_accrued(250_000);

    assert_ne!(
        env.asset0_profile().asset_admin,
        [0u8; 32],
        "fixture precondition: asset_admin is LIVE — the old build refused this"
    );

    let stake_before = env.token_amount(env.stake_vault);
    let vault_before = env.token_amount(env.vault);
    let (_, withdrawn_before) = env.reserve_counters();

    env.withdraw_to_stake()
        .expect("tag 87 must work with asset_admin LIVE — the burn gate is gone");

    let stake_after = env.token_amount(env.stake_vault);
    let vault_after = env.token_amount(env.vault);
    let (_, withdrawn_after) = env.reserve_counters();

    assert_eq!(
        stake_after - stake_before,
        250_000,
        "the stake vault must really receive the atoms"
    );
    assert_eq!(
        vault_before - vault_after,
        250_000,
        "and the market vault must really lose them"
    );
    assert_eq!(
        withdrawn_after - withdrawn_before,
        250_000,
        "the claim must be marked paid for exactly what moved"
    );
    // CONSERVATION: nothing created, nothing destroyed.
    assert_eq!(
        stake_after + vault_after,
        stake_before + vault_before,
        "conservation: tokens only moved between the two vaults"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TAG 88 — UpdateMaintenanceFeePerSlot.
//
// `maintenance_fee_per_slot` was an InitMarket constructor argument with NO
// setter anywhere in the dispatch table, so it was frozen for the life of the
// market. Tag 88 restores optionality only; the default stays 0.
// ════════════════════════════════════════════════════════════════════════════

impl FeeEnv {
    /// Send tag 88 as `signer`. Returns the raw result so the negative cases
    /// can pin their code rather than merely observing "some error".
    fn set_maintenance_fee_per_slot_as(
        &mut self,
        signer: &Keypair,
        rate: u128,
    ) -> Result<(), solana_sdk::transaction::TransactionError> {
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            data: ProgInstruction::UpdateMaintenanceFeePerSlot {
                maintenance_fee_per_slot: rate,
            }
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[signer])
    }

    /// `cfg.maintenance_fee_per_slot`, read back from the live account.
    fn maintenance_fee_per_slot(&self) -> u128 {
        let acct = self.svm.get_account(&self.market).unwrap();
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&acct.data).unwrap();
        cfg.maintenance_fee_per_slot
    }
}

/// The defect this closes: the value must actually be settable and must
/// PERSIST to the account, re-read from chain rather than from a local copy.
#[test]
fn tag88_marketauth_sets_maintenance_fee_per_slot_and_it_persists() {
    let mut env = FeeEnv::new(1_000_000);

    assert_eq!(
        env.maintenance_fee_per_slot(),
        0,
        "InitMarket must leave the default at 0"
    );

    let admin = env.admin.insecure_clone();
    env.set_maintenance_fee_per_slot_as(&admin, 7_777)
        .expect("marketauth must be able to set the maintenance fee");

    assert_eq!(
        env.maintenance_fee_per_slot(),
        7_777,
        "the new rate must be readable back from the account"
    );

    // Settable more than once, and back down to 0 — this is a policy lever,
    // not a one-shot latch.
    env.set_maintenance_fee_per_slot_as(&admin, 0)
        .expect("marketauth must be able to set it back to 0");
    assert_eq!(env.maintenance_fee_per_slot(), 0, "must be resettable to 0");
}

/// The payload is a `u128`, matching storage and InitMarket's own encoding. A
/// `u64` payload would silently cap the settable range ~1.8e19 while the
/// accepted bound is MAX_PROTOCOL_FEE_ABS == 1e36. This pins the wire width:
/// a value above u64::MAX must round-trip intact.
#[test]
fn tag88_accepts_a_rate_above_u64_max_proving_the_payload_is_u128() {
    let mut env = FeeEnv::new(1_000_000);
    let admin = env.admin.insecure_clone();

    let big = (u64::MAX as u128) + 1;
    env.set_maintenance_fee_per_slot_as(&admin, big)
        .expect("a u128 rate below MAX_PROTOCOL_FEE_ABS must be accepted");
    assert_eq!(
        env.maintenance_fee_per_slot(),
        big,
        "a value above u64::MAX must round-trip intact, not truncate"
    );
}

/// A setter must not be able to store a value InitMarket itself would reject,
/// and must reject it with InitMarket's own code.
#[test]
fn tag88_rejects_a_rate_above_max_protocol_fee_abs() {
    let mut env = FeeEnv::new(1_000_000);
    let admin = env.admin.insecure_clone();

    assert_custom(
        env.set_maintenance_fee_per_slot_as(&admin, percolator::MAX_PROTOCOL_FEE_ABS + 1),
        14, // EngineInvalidConfig — the same code InitMarket uses for this bound
        "a rate above MAX_PROTOCOL_FEE_ABS",
    );
    assert_eq!(
        env.maintenance_fee_per_slot(),
        0,
        "a rejected call must not have written anything"
    );

    // The boundary itself is accepted — the bound is inclusive, as at InitMarket.
    env.set_maintenance_fee_per_slot_as(&admin, percolator::MAX_PROTOCOL_FEE_ABS)
        .expect("exactly MAX_PROTOCOL_FEE_ABS must be accepted");
    assert_eq!(
        env.maintenance_fee_per_slot(),
        percolator::MAX_PROTOCOL_FEE_ABS
    );
}

/// AUTHORITY: tag 88 is marketauth-gated, with the same code the sibling
/// marketauth setters use. A funded, valid, but unrelated signer must not be
/// able to turn on a recurring fee that drains every portfolio in the market.
#[test]
fn tag88_rejects_a_non_marketauth_signer_with_unauthorized() {
    let mut env = FeeEnv::new(1_000_000);

    let interloper = Keypair::new();
    env.svm
        .airdrop(&interloper.pubkey(), 1_000_000_000)
        .unwrap();

    assert_custom(
        env.set_maintenance_fee_per_slot_as(&interloper, 7_777),
        8, // Unauthorized — same code as the sibling marketauth setters
        "a non-marketauth signer must not set the maintenance fee",
    );
    assert_eq!(
        env.maintenance_fee_per_slot(),
        0,
        "a rejected call must not have written anything"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// TAG 86 (UpdateFeeSplit) — END-TO-END, ON-CHAIN
//
// FINDING 2 (branch review). Tag 86 previously appeared in `tests/` ONLY as the
// `set_fee_split` fixture above, which `.expect()`s success. Nothing exercised
// it on-chain as the subject: no test proved it rejects an invalid split, and
// no test proved it is authority-gated.
//
// That gap mattered specifically because "tag 86 now owns validation" is the
// entire justification for `2b3a6a65` removing `fee_split_floor_ok` from both
// setters. The floors were retired on the strength of a validator whose
// on-chain enforcement was never tested. These tests pay that debt: they are
// the evidence for the claim the removal rests on.
//
// Written to mirror the tag-88 tests directly above (same harness, same
// `assert_custom` code pinning, same read-back-from-chain discipline).
// ════════════════════════════════════════════════════════════════════════════

impl FeeEnv {
    /// Send tag 86 as `signer`, returning the raw result so the negative cases
    /// can pin their exact code rather than merely observing "some error".
    /// The `set_fee_split` fixture above cannot serve here: it hardcodes the
    /// admin and unwraps.
    fn set_fee_split_as(
        &mut self,
        signer: &Keypair,
        creator: u16,
        lp: u16,
        insurance: u16,
    ) -> Result<(), solana_sdk::transaction::TransactionError> {
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts: vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            data: ProgInstruction::UpdateFeeSplit {
                creator_share_bps: creator,
                lp_share_bps: lp,
                insurance_share_bps: insurance,
            }
            .encode(),
        };
        let payer = self.payer.insecure_clone();
        send_ixs(&mut self.svm, &payer, vec![ix], &[signer])
    }

    /// The three share bps, read back from the LIVE account — never from a
    /// local copy. A setter that returns Ok without persisting would pass any
    /// test that trusted its return value.
    fn fee_split_shares(&self) -> (u16, u16, u16) {
        let acct = self.svm.get_account(&self.market).unwrap();
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&acct.data).unwrap();
        (
            cfg.creator_share_bps,
            cfg.lp_share_bps,
            cfg.insurance_share_bps,
        )
    }
}

/// HAPPY PATH: marketauth sets a valid NON-DEFAULT split and it persists.
///
/// Non-default is the point — a test that "sets" the defaults would pass
/// against a handler that writes nothing at all.
#[test]
fn tag86_marketauth_sets_a_valid_non_default_split_and_it_persists() {
    let mut env = FeeEnv::new(1_000_000);

    // InitMarket hardcodes the defaults (spec §1).
    assert_eq!(
        env.fee_split_shares(),
        (1600, 4800, 1600),
        "InitMarket must seed the documented defaults"
    );

    // 800/5600/1600: sums to FEE_SHARE_TOTAL_BPS (8000) and clears every floor
    // (creator 800 <= 3600, lp 5600 >= 3200, insurance 1600 >= 1200). Differs
    // from the defaults in all three legs.
    let admin = env.admin.insecure_clone();
    env.set_fee_split_as(&admin, 800, 5600, 1600)
        .expect("marketauth must be able to set a valid split");
    assert_eq!(
        env.fee_split_shares(),
        (800, 5600, 1600),
        "the new split must be readable back from the account"
    );

    // Settable more than once — a policy lever, not a one-shot latch.
    env.set_fee_split_as(&admin, 3600, 3200, 1200)
        .expect("the exact-floor extreme must be settable");
    assert_eq!(
        env.fee_split_shares(),
        (3600, 3200, 1200),
        "the floor-extreme split must persist too"
    );
}

/// A split that does not sum to `FEE_SHARE_TOTAL_BPS` must be rejected with the
/// exact code, and must leave the stored split untouched.
///
/// 1600/4800/1601 sums to 8001. Every leg individually clears its floor, so the
/// ONLY thing wrong is the sum — this isolates the sum check.
#[test]
fn tag86_rejects_an_invalid_sum_with_custom_52() {
    let mut env = FeeEnv::new(1_000_000);
    let admin = env.admin.insecure_clone();

    assert_custom(
        env.set_fee_split_as(&admin, 1600, 4800, 1601),
        52, // FeeSplitSumInvalid
        "a split summing to 8001 must be rejected",
    );
    assert_eq!(
        env.fee_split_shares(),
        (1600, 4800, 1600),
        "a rejected call must not have written anything"
    );
}

/// A split with the CORRECT sum but a floor violation must be rejected with the
/// floor code — proving the floors are genuinely enforced on-chain at tag 86,
/// which is the claim that justified retiring `fee_split_floor_ok`.
///
/// 1600/3000/3400 sums to exactly 8000, so it passes the sum check and reaches
/// the floor check. Only ONE floor is broken: lp 3000 < MIN_LP_SHARE_BPS 3200
/// (creator 1600 <= 3600, insurance 3400 >= 1200). This is the LP leg being
/// quietly starved while the arithmetic still looks balanced — exactly the case
/// the floors exist to stop.
#[test]
fn tag86_rejects_a_floor_violation_with_custom_51() {
    let mut env = FeeEnv::new(1_000_000);
    let admin = env.admin.insecure_clone();

    assert_custom(
        env.set_fee_split_as(&admin, 1600, 3000, 3400),
        51, // FeeSplitFloorViolation
        "an lp share below MIN_LP_SHARE_BPS must be rejected",
    );
    assert_eq!(
        env.fee_split_shares(),
        (1600, 4800, 1600),
        "a rejected call must not have written anything"
    );

    // The creator ceiling is the other direction of the same guard. 4000/3200/800
    // also sums to 8000: creator 4000 > 3600 AND insurance 800 < 1200, because
    // the floors are precisely complementary (spec §1) — over-paying the creator
    // necessarily starves another leg.
    assert_custom(
        env.set_fee_split_as(&admin, 4000, 3200, 800),
        51,
        "a creator share above MAX_CREATOR_SHARE_BPS must be rejected",
    );
    assert_eq!(
        env.fee_split_shares(),
        (1600, 4800, 1600),
        "the second rejected call must not have written anything either"
    );
}

/// AUTHORITY: tag 86 is marketauth-gated. An unrelated funded signer must not be
/// able to retune the split — that would let anyone redirect the LP and staker
/// legs to the creator.
///
/// NOTE the split passed here is VALID (the defaults). `handle_update_fee_split`
/// runs `validate_fee_split` BEFORE `expect_live_authority`, so an invalid split
/// would fail at 52/51 and this test would pass without the authority check ever
/// being reached — proving nothing. A valid split forces the failure to come
/// from the authority gate.
#[test]
fn tag86_rejects_a_non_marketauth_signer_with_unauthorized() {
    let mut env = FeeEnv::new(1_000_000);

    let interloper = Keypair::new();
    env.svm
        .airdrop(&interloper.pubkey(), 1_000_000_000)
        .unwrap();

    assert_custom(
        env.set_fee_split_as(&interloper, 1600, 4800, 1600),
        8, // Unauthorized — same code as the sibling marketauth setters
        "a non-marketauth signer must not retune the fee split",
    );

    // And a valid, floor-clearing, non-default split from the interloper is
    // rejected for the same reason — the gate is on the signer, not the values.
    assert_custom(
        env.set_fee_split_as(&interloper, 800, 5600, 1600),
        8,
        "authority is checked independently of whether the split is legal",
    );
    assert_eq!(
        env.fee_split_shares(),
        (1600, 4800, 1600),
        "no rejected call may have written anything"
    );
}
