//! v2.1 -> v2.2 fixture upgrader for the live-captured replay fixtures.
//!
//! v2.2 Wave B (engine layout discriminator 18 -> 19, wrapper VERSION 18 -> 19) appended
//! band/rent words to three engine structs: `V16ConfigAccount` (6 x u64, incl. the review position cap and min leg notional),
//! `AssetStateV16Account` (8 x u64 + 3 x u128) and `PortfolioLegV16Account`
//! (u64 + u8 + u128 + u64). The fixtures are v2.1 bytes from band-off markets, whose exact v2.2
//! encoding is the same bytes with the new words zeroed (I-B7: band off <=> band_epoch == 0,
//! rent off <=> rent indices 0). This inserts exactly those zero words, bumps the portfolio's
//! provenance discriminator and every wrapper account's header VERSION, and leaves every other
//! byte untouched, so the replays keep exercising the live v2.1 state. Mirrors the engine's
//! `tests/p2b_live_replay.rs` upgrader.
#![allow(dead_code)]

use percolator::{
    AssetStateV16Account, EngineAssetSlotV16Account, MarketGroupV16HeaderAccount,
    PortfolioAccountV16Account, PortfolioLegV16Account, V16ConfigAccount,
    V16_MAX_PORTFOLIO_ASSETS_N,
};
use percolator_prog::constants::{
    ASSET_ORACLE_WRAPPER_LEN, HEADER_LEN, KIND_MARKET, KIND_PORTFOLIO, MAGIC, MARKET_GROUP_OFF,
    VERSION,
};
use solana_sdk::pubkey::Pubkey;

pub const V21_WRAPPER_VERSION: u16 = 18;
pub const V21_LAYOUT_DISCRIMINATOR: u16 = 18;
pub const V22_CONFIG_EXTRA: usize = 6 * 8;
pub const V22_ASSET_EXTRA: usize = 8 * 8 + 3 * 16;
const V22_LEG_EXTRA: usize = 8 + 1 + 16 + 8;
/// -rem variant: per-leg K/F remainders (`k_rem_num`, `f_rem_num`), 32 B inserted after `f_snap`.
pub const V22_LEG_REM_EXTRA: usize = 32;
/// fix/v21-funding-scale appended this many bytes of K/F drift-generation state to the END of
/// every engine asset slot. A live-captured DEPLOYED slab (7c906e45 / ff65ec50 layout) lacks it:
/// `upgrade_slab` appends the zero tail (what a fresh slab starts with) while widening the slot.
pub const FUNDING_SCALE_TAIL: usize = 160 + 32; // #277 drift tail (160) + #282 R1 equity-cadence words (32) -- both appended last in the engine slot

fn upgrade_slab(old: &[u8]) -> Vec<u8> {
    let new_header_len = core::mem::size_of::<MarketGroupV16HeaderAccount>();
    let old_header_len = new_header_len - V22_CONFIG_EXTRA;
    let config_off = core::mem::offset_of!(MarketGroupV16HeaderAccount, config);
    let old_config_end = config_off + core::mem::size_of::<V16ConfigAccount>() - V22_CONFIG_EXTRA;
    let new_slot_len = core::mem::size_of::<EngineAssetSlotV16Account>();
    let old_slot_len = new_slot_len - V22_ASSET_EXTRA;
    let old_asset_len = core::mem::size_of::<AssetStateV16Account>() - V22_ASSET_EXTRA;
    let old_stride = ASSET_ORACLE_WRAPPER_LEN + old_slot_len;
    let mut out = Vec::with_capacity(old.len() + 4096);
    out.extend_from_slice(&old[..MARKET_GROUP_OFF]);
    let header = &old[MARKET_GROUP_OFF..MARKET_GROUP_OFF + old_header_len];
    out.extend_from_slice(&header[..old_config_end]);
    out.extend_from_slice(&[0u8; V22_CONFIG_EXTRA]);
    out.extend_from_slice(&header[old_config_end..]);
    let rest = &old[MARKET_GROUP_OFF + old_header_len..];
    // A deployed v2.1 slab lacks the funding-scale tail; a v2.1 + tail slab (this tree's v2.1
    // projection) carries it. Exactly one of the two strides divides the length.
    let bare = !rest.len().is_multiple_of(old_stride);
    let stride = if bare { old_stride - FUNDING_SCALE_TAIL } else { old_stride };
    assert_eq!(
        rest.len() % stride,
        0,
        "v2.1 slab length must be header + N slots (with or without the funding-scale tail)"
    );
    for slot in rest.chunks(stride) {
        out.extend_from_slice(&slot[..ASSET_ORACLE_WRAPPER_LEN]);
        let engine = &slot[ASSET_ORACLE_WRAPPER_LEN..];
        out.extend_from_slice(&engine[..old_asset_len]);
        out.extend_from_slice(&[0u8; V22_ASSET_EXTRA]);
        out.extend_from_slice(&engine[old_asset_len..]);
        if bare {
            out.extend_from_slice(&[0u8; FUNDING_SCALE_TAIL]);
        }
    }
    out
}

fn upgrade_portfolio(old: &[u8]) -> Vec<u8> {
    let legs_off = core::mem::offset_of!(PortfolioAccountV16Account, legs);
    let rem_cut = core::mem::offset_of!(PortfolioLegV16Account, k_rem_num);
    let old_leg_len = core::mem::size_of::<PortfolioLegV16Account>() - V22_LEG_EXTRA - V22_LEG_REM_EXTRA;
    let state = &old[HEADER_LEN..];
    let mut out = Vec::with_capacity(old.len() + V16_MAX_PORTFOLIO_ASSETS_N * V22_LEG_EXTRA);
    out.extend_from_slice(&old[..HEADER_LEN]);
    out.extend_from_slice(&state[..legs_off]);
    for i in 0..V16_MAX_PORTFOLIO_ASSETS_N {
        let leg = &state[legs_off + i * old_leg_len..legs_off + (i + 1) * old_leg_len];
        out.extend_from_slice(&leg[..rem_cut]);
        out.extend_from_slice(&[0u8; V22_LEG_REM_EXTRA]);
        out.extend_from_slice(&leg[rem_cut..]);
        out.extend_from_slice(&[0u8; V22_LEG_EXTRA]);
    }
    out.extend_from_slice(&state[legs_off + V16_MAX_PORTFOLIO_ASSETS_N * old_leg_len..]);
    let disc_off = HEADER_LEN
        + core::mem::offset_of!(PortfolioAccountV16Account, provenance_header)
        + core::mem::offset_of!(percolator::ProvenanceHeaderV16Account, layout_discriminator);
    assert_eq!(
        u16::from_le_bytes([out[disc_off], out[disc_off + 1]]),
        V21_LAYOUT_DISCRIMINATOR,
        "fixture portfolio is v2.1"
    );
    out[disc_off..disc_off + 2]
        .copy_from_slice(&percolator::V16_LAYOUT_DISCRIMINATOR.to_le_bytes());
    out
}

/// Upgrade one fixture account's bytes. Accounts not owned by `wrapper_id`, or not carrying
/// the wrapper MAGIC, are returned unchanged.
pub fn upgrade_v21_account(wrapper_id: &Pubkey, owner: &Pubkey, data: Vec<u8>) -> Vec<u8> {
    if owner != wrapper_id || data.len() < HEADER_LEN || data[..8] != MAGIC.to_le_bytes() {
        return data;
    }
    let version = u16::from_le_bytes([data[8], data[9]]);
    if version == VERSION {
        return data;
    }
    assert_eq!(version, V21_WRAPPER_VERSION, "fixture account is v2.1");
    let mut out = match data[10] {
        KIND_MARKET => upgrade_slab(&data),
        KIND_PORTFOLIO => upgrade_portfolio(&data),
        _ => data,
    };
    out[8..10].copy_from_slice(&VERSION.to_le_bytes());
    out
}

/// v2.2 -> v2.1 projection (the inverse of `upgrade_v21_account`): drops the appended band/rent
/// words, ASSERTING they are all zero (a band-off, rent-off market must never write them), and
/// restores the v2.1 discriminator and header VERSION. Used by the growth-off byte-parity test
/// to compare a v2.2 run against the deployed v2.1-layout program.
pub fn project_v22_account_to_v21(data: &[u8]) -> Vec<u8> {
    if data.len() < HEADER_LEN || data[..8] != MAGIC.to_le_bytes() {
        return data.to_vec();
    }
    assert_eq!(
        u16::from_le_bytes([data[8], data[9]]),
        VERSION,
        "account is v2.2"
    );
    let zero = |bytes: &[u8], what: &str| {
        assert!(
            bytes.iter().all(|b| *b == 0),
            "v2.2 {what} words must stay zero on a band-off market"
        );
    };
    let mut out = match data[10] {
        KIND_MARKET => {
            let header_len = core::mem::size_of::<MarketGroupV16HeaderAccount>();
            let config_off = core::mem::offset_of!(MarketGroupV16HeaderAccount, config);
            let config_end = config_off + core::mem::size_of::<V16ConfigAccount>();
            let slot_len = core::mem::size_of::<EngineAssetSlotV16Account>();
            let asset_len = core::mem::size_of::<AssetStateV16Account>();
            let mut out = Vec::with_capacity(data.len());
            out.extend_from_slice(&data[..MARKET_GROUP_OFF]);
            let header = &data[MARKET_GROUP_OFF..MARKET_GROUP_OFF + header_len];
            out.extend_from_slice(&header[..config_end - V22_CONFIG_EXTRA]);
            zero(&header[config_end - V22_CONFIG_EXTRA..config_end], "config");
            out.extend_from_slice(&header[config_end..]);
            let rest = &data[MARKET_GROUP_OFF + header_len..];
            let stride = ASSET_ORACLE_WRAPPER_LEN + slot_len;
            assert_eq!(
                rest.len() % stride,
                0,
                "v2.2 slab length must be header + N slots"
            );
            for slot in rest.chunks(stride) {
                out.extend_from_slice(&slot[..ASSET_ORACLE_WRAPPER_LEN]);
                let engine = &slot[ASSET_ORACLE_WRAPPER_LEN..];
                out.extend_from_slice(&engine[..asset_len - V22_ASSET_EXTRA]);
                zero(&engine[asset_len - V22_ASSET_EXTRA..asset_len], "asset");
                out.extend_from_slice(&engine[asset_len..]);
            }
            out
        }
        KIND_PORTFOLIO => {
            let legs_off = core::mem::offset_of!(PortfolioAccountV16Account, legs);
            let leg_len = core::mem::size_of::<PortfolioLegV16Account>();
            let state = &data[HEADER_LEN..];
            let mut out = Vec::with_capacity(data.len());
            out.extend_from_slice(&data[..HEADER_LEN]);
            out.extend_from_slice(&state[..legs_off]);
            for i in 0..V16_MAX_PORTFOLIO_ASSETS_N {
                let leg = &state[legs_off + i * leg_len..legs_off + (i + 1) * leg_len];
                let rem_cut = core::mem::offset_of!(PortfolioLegV16Account, k_rem_num);
                out.extend_from_slice(&leg[..rem_cut]);
                zero(&leg[rem_cut..rem_cut + V22_LEG_REM_EXTRA], "leg K/F remainder");
                out.extend_from_slice(&leg[rem_cut + V22_LEG_REM_EXTRA..leg_len - V22_LEG_EXTRA]);
                zero(&leg[leg_len - V22_LEG_EXTRA..], "leg");
            }
            out.extend_from_slice(&state[legs_off + V16_MAX_PORTFOLIO_ASSETS_N * leg_len..]);
            let disc_off = HEADER_LEN
                + core::mem::offset_of!(PortfolioAccountV16Account, provenance_header)
                + core::mem::offset_of!(
                    percolator::ProvenanceHeaderV16Account,
                    layout_discriminator
                );
            out[disc_off..disc_off + 2].copy_from_slice(&V21_LAYOUT_DISCRIMINATOR.to_le_bytes());
            out
        }
        _ => data.to_vec(),
    };
    out[8..10].copy_from_slice(&V21_WRAPPER_VERSION.to_le_bytes());
    out
}

/// v2.1 account lengths for the same capacity (v2.2 length minus the appended words).
pub fn v21_market_len(v22_len: usize, slots: usize) -> usize {
    v22_len - V22_CONFIG_EXTRA - slots * V22_ASSET_EXTRA
}

pub fn v21_portfolio_len(v22_len: usize) -> usize {
    v22_len - V16_MAX_PORTFOLIO_ASSETS_N * (V22_LEG_EXTRA + V22_LEG_REM_EXTRA)
}

pub fn deployed_market_len(v22_len: usize, slots: usize) -> usize {
    v22_len - V22_CONFIG_EXTRA - slots * (V22_ASSET_EXTRA + FUNDING_SCALE_TAIL)
}
