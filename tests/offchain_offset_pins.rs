//! Offset pins for the byte offsets the OFF-CHAIN readers hardcode instead of decoding the struct.
//!
//! Keeper (`feat/v22-keeper-growth`), SDK (`feat/v22-sdk-growth`) and indexer (`feat/v22-indexer`)
//! read wrapper accounts by absolute byte offset. A program layout change would silently break
//! them with no prog CI failure, so every such offset is pinned here against the real struct with
//! `core::mem::offset_of!` / `size_of`. A failure here means: update the named off-chain file in
//! lockstep (or the reader mis-decodes live markets).
//!
//! `last_good_oracle_slot` (keeper pusher-role.ts:24, market-state.ts:168) is pinned by
//! tests/v22_last_good_slot.rs (PROG-TEST-ASSETLASTGOODSLOT) and deliberately not repeated here.
//!
//! File:line references are as of keeper `feat/v22-keeper-growth`, SDK `feat/v22-sdk-growth`,
//! indexer `feat/v22-indexer` on 2026-11-19.

use core::mem::{offset_of, size_of};
use percolator::{AssetStateV16Account, V16ConfigAccount};
use percolator_prog::constants::{
    ASSET_CONTROL_SEQUENCES_OFF, ASSET_GROWTH_OFF, ASSET_ORACLE_WRAPPER_LEN, ASSET_RISK_LIMITS_OFF,
    ASSET_VAULT_LP_DRAW_OFF, ASSET_VAULT_LP_OFF, HEADER_LEN, MARKET_ASSET_SLOT_LEN,
    MARKET_GROUP_LEN, MARKET_GROUP_OFF, PROFILE_LOT_EXP_IDX, PROFILE_P4_FLAGS_IDX,
    WRAPPER_CONFIG_LEN,
};
use percolator_prog::lev_guard_v22::{LevGuardV22, LEV_GUARD_BODY_LEN, LEV_GUARD_REC_LEN};
use percolator_prog::state::{AssetOracleProfileV16, WrapperConfigV16};

/// Offset of the `_padding0` lane inside the oracle profile.
const PAD0: usize = offset_of!(AssetOracleProfileV16, _padding0);

#[test]
fn account_header_and_config_geometry() {
    // keeper auth-mark-pusher.ts:89 (V17_HEADER_LEN = 16, MARKET_GROUP_OFF = HEADER + CONFIG);
    // SDK layout.ts:251/271/273 (headerLen 16, wrapperConfigLen 576, marketGroupOff 592);
    // keeper pusher-role.ts:24 / market-state.ts:168 (CONFIG_OFF = 16).
    assert_eq!(HEADER_LEN, 16);
    assert_eq!(WRAPPER_CONFIG_LEN, 576);
    assert_eq!(size_of::<WrapperConfigV16>(), 576);
    assert_eq!(MARKET_GROUP_OFF, 592);
}

#[test]
fn wrapper_config_fields_read_by_keeper_and_indexer() {
    // keeper p2b-wind-down.ts:80 (CFG_COLLATERAL_MINT_OFF = 16 + 32), v22/adl-wind-down.ts:45
    assert_eq!(offset_of!(WrapperConfigV16, collateral_mint), 32);
    // keeper market-state.ts:166 comment: trade fee 30 bps @16+128 (trade_fee_base_bps)
    assert_eq!(offset_of!(WrapperConfigV16, trade_fee_base_bps), 128);
    // keeper market-state.ts:167 CFG_PERMISSIONLESS_RESOLVE_STALE_SLOTS = 136
    assert_eq!(offset_of!(WrapperConfigV16, permissionless_resolve_stale_slots), 136);
    // keeper resolved-loser-force-close.ts:18 (force_close_delay_slots u64 @ +144)
    assert_eq!(offset_of!(WrapperConfigV16, force_close_delay_slots), 144);
    // SDK instructions.ts:5520 (V17_CREATOR_FEE_CLAIMABLE_OFF = 568); also tests/v16_fee_split.rs
    assert_eq!(offset_of!(WrapperConfigV16, creator_fee_claimable_atoms), 568);
    // indexer v17/discovery.ts:207, routes/webhook.ts:1144, services/StatsCollector.ts:86 all say
    // "mark_ewma_e6 at config offset 232 (abs 248)". The SDK decodes by name; the comments (and any
    // reader copying them) assume 232.
    assert_eq!(
        offset_of!(WrapperConfigV16, mark_ewma_e6),
        232,
        "indexer comments (discovery.ts:207, webhook.ts:1144, StatsCollector.ts:86) say 232"
    );
}

#[test]
fn asset_slot_wrapper_prefix_and_profile_bytes() {
    // SDK layout.ts:236-247 WRAPPER_SLOT: oracleProfile 0, controlSequences 512, riskLimits 608,
    // growth 672, vaultLpDraw 832, vaultLp 896, wrapperSlotLen 1024 (layout.ts:276).
    assert_eq!(ASSET_CONTROL_SEQUENCES_OFF, 512);
    assert_eq!(ASSET_RISK_LIMITS_OFF, 608);
    // SDK growth-v19.ts:70 ASSET_GROWTH_SLOT_OFF = 672
    assert_eq!(ASSET_GROWTH_OFF, 672);
    assert_eq!(ASSET_VAULT_LP_DRAW_OFF, 832);
    assert_eq!(ASSET_VAULT_LP_OFF, 896);
    assert_eq!(ASSET_ORACLE_WRAPPER_LEN, 1024);

    // SDK v22-lot.ts:43 (profileLotExp = 19) and keeper auth-mark-pusher.ts:289
    // (PROFILE_LOT_EXP_OFF = 19): lot_exp is `_padding0[PROFILE_LOT_EXP_IDX]`.
    assert_eq!(PROFILE_LOT_EXP_IDX, 0);
    assert_eq!(PAD0 + PROFILE_LOT_EXP_IDX, 19);
    // SDK layout.ts:246-247 profileP4Flags = 20
    assert_eq!(PAD0 + PROFILE_P4_FLAGS_IDX, 20);

    // keeper auth-mark-pusher.ts:185 comment "oracleAuthority (offset 120-152)": the field is read
    // via SDK parseAssetOracleProfileV17, but the comment (and any raw reader) assumes 120.
    assert_eq!(
        offset_of!(AssetOracleProfileV16, oracle_authority),
        120,
        "keeper auth-mark-pusher.ts:185 says oracle_authority is bytes 120-152"
    );
    // keeper auth-mark-pusher.ts:187 V17_ASSET_ORACLE_PROFILE_LEN (400) guard comment
    // "asset_admin offset 368-399" lives in the same profile.
    assert_eq!(offset_of!(AssetOracleProfileV16, asset_admin), 368);
}

#[test]
fn market_group_and_slot_strides() {
    // SDK layout.ts:400-424 LAYOUT_V22 marketGroupLen 806 / assetSlotStride 2661 (v2.2, VERSION 19);
    // keeper auth-mark-pusher.ts:183 "VERSION 19: 806 / 2,661"; keeper positioned-sweep.ts ASSET_SLOTS_OFF.
    assert_eq!(MARKET_GROUP_LEN, 806);
    assert_eq!(MARKET_ASSET_SLOT_LEN, 1024 + 1637);
    assert_eq!(MARKET_ASSET_SLOT_LEN, 2661);
}

#[test]
fn engine_config_and_band_offsets_read_by_sdk() {
    // SDK layout.ts:334-335 BAND_RENT_V22.config (offsets inside V16ConfigAccount) and
    // configLen 297.
    assert_eq!(size_of::<V16ConfigAccount>(), 297);
    assert_eq!(offset_of!(V16ConfigAccount, max_accrual_dt_slots), 118);
    assert_eq!(offset_of!(V16ConfigAccount, max_price_move_bps_per_slot), 142);
    assert_eq!(offset_of!(V16ConfigAccount, band_bps), 249);
    assert_eq!(offset_of!(V16ConfigAccount, band_max_epoch_slots), 257);
    assert_eq!(offset_of!(V16ConfigAccount, band_max_pin_slots), 265);
    assert_eq!(offset_of!(V16ConfigAccount, rent_max_e9_per_slot), 273);
    assert_eq!(offset_of!(V16ConfigAccount, band_max_positions_per_side), 281);
    assert_eq!(offset_of!(V16ConfigAccount, band_min_leg_notional), 289);

    // SDK layout.ts:336 BAND_RENT_V22.assetState (offsets inside AssetStateV16Account); the
    // engine slot starts with the asset state.
    assert_eq!(offset_of!(AssetStateV16Account, band_anchor_price), 515);
    assert_eq!(offset_of!(AssetStateV16Account, band_anchor_slot), 523);
    assert_eq!(offset_of!(AssetStateV16Account, band_epoch), 531);
    assert_eq!(offset_of!(AssetStateV16Account, band_uncertified_long), 539);
    assert_eq!(offset_of!(AssetStateV16Account, band_uncertified_short), 547);
    assert_eq!(offset_of!(AssetStateV16Account, band_liq_pending_long), 555);
    assert_eq!(offset_of!(AssetStateV16Account, band_liq_pending_short), 563);
    assert_eq!(offset_of!(AssetStateV16Account, band_pin_since_slot), 571);
    assert_eq!(offset_of!(AssetStateV16Account, rent_index_long_num), 579);
    assert_eq!(offset_of!(AssetStateV16Account, rent_index_short_num), 595);
    assert_eq!(offset_of!(AssetStateV16Account, rent_unrouted_atoms), 611);
    assert_eq!(offset_of!(AssetStateV16Account, stored_pos_count_long), 321);
    assert_eq!(offset_of!(AssetStateV16Account, stored_pos_count_short), 329);
}

#[test]
fn lev_guard_record_offsets_read_by_sdk_and_keeper() {
    // SDK lev-guard-v22.ts:287-296 LEV_GUARD_FIELD_OFF_V22 ("rustc offset_of!; add 16 for the
    // account"); SDK layout.ts:464 and keeper v22/lev-guard.ts:241 (16 + 360 + 4096).
    assert_eq!(size_of::<LevGuardV22>(), 360);
    assert_eq!(LEV_GUARD_REC_LEN, 360);
    assert_eq!(LEV_GUARD_BODY_LEN, 360 + 4096);
    macro_rules! pin {
        ($($f:ident = $o:expr),* $(,)?) => {$(
            assert_eq!(offset_of!(LevGuardV22, $f), $o, concat!("lev guard field ", stringify!($f)));
        )*};
    }
    pin!(
        market = 0, risk_key = 32, t0_slot = 64, asset_index = 72, version = 74, bump = 75,
        flags = 76, round_active = 77, round_lp_long = 78, _pad0 = 79, rep_j_dump_bps = 80,
        rep_m_ind_bps = 82, rep_l_cap_x100 = 84, rep_n_mult_bps = 86, rep_slot = 88,
        holder_dump_bps = 96, round_keep_bps = 98, touched_n = 100, _pad1 = 102,
        holder_dump_slot = 104, pb_last_px = 112, pb_last_slot = 120, pb_ref_px = 128,
        pb_ref_slot = 136, pb_freeze_until = 144, pb_oracle_until = 152, frozen_l_x100 = 160,
        _pad2 = 162, frozen_n_q = 168, navps = 184, nav_last_equity = 200, nav_last_in = 216,
        nav_last_out = 232, nav_peak_cur = 248, nav_peak_prev = 264, nav_ref = 280,
        nav_bucket_start = 296, nav_last_slot = 304, round_id = 312, round_target_q = 320,
        round_open_slot = 336, burst_var_peak_x100 = 344, _pad3 = 348, burst_peak_slot = 352,
    );
}
