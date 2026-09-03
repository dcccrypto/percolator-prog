#![cfg(kani)]

extern crate kani;

use percolator_prog::ix::Instruction;
use percolator_prog::matcher_abi::{
    validate_matcher_return, MatcherReturn, FLAG_PARTIAL_OK, FLAG_REJECTED, FLAG_VALID,
};
use percolator_prog::policy_v16;

#[kani::proof]
fn kani_v16_premium_funding_rate_is_clamped_and_signed() {
    let mark_raw: u16 = kani::any();
    let index_raw: u16 = kani::any();
    let cap_raw: u16 = kani::any();
    let mark = mark_raw as u64 + 1;
    let index = index_raw as u64 + 1;
    let cap = cap_raw as u64;

    let rate = policy_v16::premium_funding_rate_e9(mark, index, cap).unwrap();
    let abs_rate = if rate < 0 {
        (-rate) as u128
    } else {
        rate as u128
    };
    assert!(abs_rate <= cap as u128);

    if cap == 0 || mark == index {
        assert_eq!(rate, 0);
    } else if mark > index {
        assert!(rate > 0);
    } else {
        assert!(rate < 0);
    }
}

#[kani::proof]
fn kani_v16_init_market_decode_preserves_wire_fields() {
    // Full-width symbolic inputs (audit: avoid the u16->u64/u128 widening collapse so
    // narrow-read / high-byte decode bugs are observable).
    let max_portfolio_assets: u16 = kani::any();
    let h_min: u64 = kani::any();
    let h_max: u64 = kani::any();
    let initial_price: u64 = kani::any();
    let min_nonzero_mm_req: u128 = kani::any();
    let min_nonzero_im_req: u128 = kani::any();
    let maintenance_margin_bps: u64 = kani::any();
    let initial_margin_bps: u64 = kani::any();
    let max_trading_fee_bps: u64 = kani::any();
    let trade_fee_base_bps: u64 = kani::any();
    let liquidation_fee_bps: u64 = kani::any();
    let liquidation_fee_cap: u128 = kani::any();
    let min_liquidation_abs: u128 = kani::any();
    let max_price_move_bps_per_slot: u64 = kani::any();
    let max_accrual_dt_slots: u64 = kani::any();
    let max_abs_funding_e9_per_slot: u64 = kani::any();
    let min_funding_lifetime_slots: u64 = kani::any();
    let max_account_b_settlement_chunks: u64 = kani::any();
    let max_bankrupt_close_chunks: u64 = kani::any();
    let max_bankrupt_close_lifetime_slots: u64 = kani::any();
    let public_b_chunk_atoms: u128 = kani::any();
    let maintenance_fee_per_slot: u128 = kani::any();

    let mut data = [0u8; 219];
    data[0] = 0;
    data[1..3].copy_from_slice(&max_portfolio_assets.to_le_bytes());
    data[3..11].copy_from_slice(&h_min.to_le_bytes());
    data[11..19].copy_from_slice(&h_max.to_le_bytes());
    data[19..27].copy_from_slice(&initial_price.to_le_bytes());
    data[27..43].copy_from_slice(&min_nonzero_mm_req.to_le_bytes());
    data[43..59].copy_from_slice(&min_nonzero_im_req.to_le_bytes());
    data[59..67].copy_from_slice(&maintenance_margin_bps.to_le_bytes());
    data[67..75].copy_from_slice(&initial_margin_bps.to_le_bytes());
    data[75..83].copy_from_slice(&max_trading_fee_bps.to_le_bytes());
    data[83..91].copy_from_slice(&trade_fee_base_bps.to_le_bytes());
    data[91..99].copy_from_slice(&liquidation_fee_bps.to_le_bytes());
    data[99..115].copy_from_slice(&liquidation_fee_cap.to_le_bytes());
    data[115..131].copy_from_slice(&min_liquidation_abs.to_le_bytes());
    data[131..139].copy_from_slice(&max_price_move_bps_per_slot.to_le_bytes());
    data[139..147].copy_from_slice(&max_accrual_dt_slots.to_le_bytes());
    data[147..155].copy_from_slice(&max_abs_funding_e9_per_slot.to_le_bytes());
    data[155..163].copy_from_slice(&min_funding_lifetime_slots.to_le_bytes());
    data[163..171].copy_from_slice(&max_account_b_settlement_chunks.to_le_bytes());
    data[171..179].copy_from_slice(&max_bankrupt_close_chunks.to_le_bytes());
    data[179..187].copy_from_slice(&max_bankrupt_close_lifetime_slots.to_le_bytes());
    data[187..203].copy_from_slice(&public_b_chunk_atoms.to_le_bytes());
    data[203..219].copy_from_slice(&maintenance_fee_per_slot.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::InitMarket {
            max_portfolio_assets: got_max_assets,
            h_min: got_h_min,
            h_max: got_h_max,
            initial_price: got_initial_price,
            min_nonzero_mm_req: got_min_mm,
            min_nonzero_im_req: got_min_im,
            maintenance_margin_bps: got_mm,
            initial_margin_bps: got_im,
            max_trading_fee_bps: got_fee,
            trade_fee_base_bps: got_base_fee,
            liquidation_fee_bps: got_liq_fee,
            liquidation_fee_cap: got_liq_cap,
            min_liquidation_abs: got_min_liq,
            max_price_move_bps_per_slot: got_move,
            max_accrual_dt_slots: got_dt,
            max_abs_funding_e9_per_slot: got_max_funding,
            min_funding_lifetime_slots: got_funding_life,
            max_account_b_settlement_chunks: got_b_chunks,
            max_bankrupt_close_chunks: got_bankrupt_chunks,
            max_bankrupt_close_lifetime_slots: got_bankrupt_lifetime,
            public_b_chunk_atoms: got_public_b,
            maintenance_fee_per_slot: got_maintenance_fee,
        } => {
            assert_eq!(got_max_assets, max_portfolio_assets);
            assert_eq!(got_h_min, h_min);
            assert_eq!(got_h_max, h_max);
            assert_eq!(got_initial_price, initial_price);
            assert_eq!(got_min_mm, min_nonzero_mm_req);
            assert_eq!(got_min_im, min_nonzero_im_req);
            assert_eq!(got_mm, maintenance_margin_bps);
            assert_eq!(got_im, initial_margin_bps);
            assert_eq!(got_fee, max_trading_fee_bps);
            assert_eq!(got_base_fee, trade_fee_base_bps);
            assert_eq!(got_liq_fee, liquidation_fee_bps);
            assert_eq!(got_liq_cap, liquidation_fee_cap);
            assert_eq!(got_min_liq, min_liquidation_abs);
            assert_eq!(got_move, max_price_move_bps_per_slot);
            assert_eq!(got_dt, max_accrual_dt_slots);
            assert_eq!(got_max_funding, max_abs_funding_e9_per_slot);
            assert_eq!(got_funding_life, min_funding_lifetime_slots);
            assert_eq!(got_b_chunks, max_account_b_settlement_chunks);
            assert_eq!(got_bankrupt_chunks, max_bankrupt_close_chunks);
            assert_eq!(got_bankrupt_lifetime, max_bankrupt_close_lifetime_slots);
            assert_eq!(got_public_b, public_b_chunk_atoms);
            assert_eq!(got_maintenance_fee, maintenance_fee_per_slot);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_amount_instructions_decode_preserves_wire_fields() {
    let tag: u8 = kani::any();
    // Note: tag 23 (WithdrawInsuranceLimited) removed in v17 auth overhaul.
    kani::assume(
        tag == 3
            || tag == 4
            || tag == 9
            || tag == 28
            || tag == 30
            || tag == 41
            || tag == 42
            || tag == 47,
    );
    let amount: u128 = kani::any();

    let mut data = [0u8; 17];
    data[0] = tag;
    data[1..17].copy_from_slice(&amount.to_le_bytes());

    match (tag, Instruction::decode(&data).unwrap()) {
        (3, Instruction::Deposit { amount: got }) => assert_eq!(got, amount),
        (4, Instruction::Withdraw { amount: got }) => assert_eq!(got, amount),
        (9, Instruction::TopUpInsurance { amount: got }) => assert_eq!(got, amount),
        (28, Instruction::ConvertReleasedPnl { amount: got }) => assert_eq!(got, amount),
        (30, Instruction::CloseResolved { fee_rate_per_slot }) => {
            assert_eq!(fee_rate_per_slot, amount)
        }
        (41, Instruction::WithdrawInsurance { amount: got }) => assert_eq!(got, amount),
        (
            42,
            Instruction::CureAndCancelClose {
                optional_deposit: got,
            },
        ) => assert_eq!(got, amount),
        (47, Instruction::RefineResolvedUnreceiptedBound { decrease_num }) => {
            assert_eq!(decrease_num, amount)
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_domain_insurance_decode_preserves_wire_fields() {
    // v17: domain fields are u16 (not u8).
    let domain: u16 = kani::any();
    let amount: u128 = kani::any();

    // TopUpInsuranceDomain: tag(1) + domain(u16=2) + amount(u128=16) = 19 bytes.
    let mut top_up = [0u8; 19];
    top_up[0] = 56;
    top_up[1..3].copy_from_slice(&domain.to_le_bytes());
    top_up[3..19].copy_from_slice(&amount.to_le_bytes());
    match Instruction::decode(&top_up).unwrap() {
        Instruction::TopUpInsuranceDomain {
            domain: got_domain,
            amount: got_amount,
        } => {
            assert_eq!(got_domain, domain);
            assert_eq!(got_amount, amount);
        }
        _ => unreachable!(),
    }

    // v17: tag 57 is now WithdrawInsuranceAsset { asset_index: u16, amount: u128 }.
    // (WithdrawInsuranceDomain was removed in the v17 auth overhaul.)
    let mut withdraw = [0u8; 19];
    let asset_index: u16 = kani::any();
    withdraw[0] = 57;
    withdraw[1..3].copy_from_slice(&asset_index.to_le_bytes());
    withdraw[3..19].copy_from_slice(&amount.to_le_bytes());
    match Instruction::decode(&withdraw).unwrap() {
        Instruction::WithdrawInsuranceAsset {
            asset_index: got_asset_index,
            amount: got_amount,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_amount, amount);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_recovery_close_progress_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let side: u8 = kani::any();
    let b_delta_budget: u128 = kani::any();
    let reduce_q: u128 = kani::any();
    let close_q: u128 = kani::any();
    let now_slot: u64 = kani::any();

    let forfeit = Instruction::ForfeitRecoveryLeg {
        asset_index,
        b_delta_budget,
    }
    .encode();
    match Instruction::decode(&forfeit).unwrap() {
        Instruction::ForfeitRecoveryLeg {
            asset_index: got_asset,
            b_delta_budget: got_budget,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_budget, b_delta_budget);
        }
        _ => unreachable!(),
    }

    let rebalance = Instruction::RebalanceReduce {
        asset_index,
        reduce_q,
    }
    .encode();
    match Instruction::decode(&rebalance).unwrap() {
        Instruction::RebalanceReduce {
            asset_index: got_asset,
            reduce_q: got_reduce,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_reduce, reduce_q);
        }
        _ => unreachable!(),
    }

    let finalize = Instruction::FinalizeResetSide { asset_index, side }.encode();
    match Instruction::decode(&finalize).unwrap() {
        Instruction::FinalizeResetSide {
            asset_index: got_asset,
            side: got_side,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_side, side);
        }
        _ => unreachable!(),
    }

    let force_close = Instruction::ForceCloseAbandonedAsset {
        asset_index,
        now_slot,
        close_q,
    }
    .encode();
    match Instruction::decode(&force_close).unwrap() {
        Instruction::ForceCloseAbandonedAsset {
            asset_index: got_asset,
            now_slot: got_slot,
            close_q: got_close,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_slot, now_slot);
            assert_eq!(got_close, close_q);
        }
        _ => unreachable!(),
    }

    match Instruction::decode(&Instruction::ClaimResolvedPayoutTopup.encode()).unwrap() {
        Instruction::ClaimResolvedPayoutTopup => {}
        _ => unreachable!(),
    }

    let sync_fee = Instruction::SyncMaintenanceFee { now_slot }.encode();
    match Instruction::decode(&sync_fee).unwrap() {
        Instruction::SyncMaintenanceFee { now_slot: got } => assert_eq!(got, now_slot),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_top_up_backing_bucket_decode_preserves_wire_fields() {
    // v17: domain is u16. Wire: tag(1) + domain(u16=2) + amount(u128=16) + expiry_slot(u64=8) = 27.
    let domain: u16 = kani::any();
    let amount: u128 = kani::any();
    let expiry_slot: u64 = kani::any();

    let mut data = [0u8; 27];
    data[0] = 24;
    data[1..3].copy_from_slice(&domain.to_le_bytes());
    data[3..19].copy_from_slice(&amount.to_le_bytes());
    data[19..27].copy_from_slice(&expiry_slot.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::TopUpBackingBucket {
            domain: got_domain,
            amount: got_amount,
            expiry_slot: got_expiry,
        } => {
            assert_eq!(got_domain, domain);
            assert_eq!(got_amount, amount);
            assert_eq!(got_expiry, expiry_slot);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_withdraw_backing_bucket_decode_preserves_wire_fields() {
    // v17: domain is u16.
    let domain: u16 = kani::any();
    let amount: u128 = kani::any();

    let data = Instruction::WithdrawBackingBucket { domain, amount }.encode();

    match Instruction::decode(&data).unwrap() {
        Instruction::WithdrawBackingBucket {
            domain: got_domain,
            amount: got_amount,
        } => {
            assert_eq!(got_domain, domain);
            assert_eq!(got_amount, amount);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_asset_lifecycle_decode_preserves_wire_fields() {
    let action: u8 = kani::any();
    let asset_index: u16 = kani::any();
    let now_slot: u64 = kani::any();
    let initial_price: u64 = kani::any();
    let insurance_authority: [u8; 32] = kani::any();
    let insurance_operator: [u8; 32] = kani::any();
    let backing_bucket_authority: [u8; 32] = kani::any();
    let oracle_authority: [u8; 32] = kani::any();

    let data = Instruction::UpdateAssetLifecycle {
        action,
        asset_index,
        now_slot,
        initial_price,
        insurance_authority,
        insurance_operator,
        backing_bucket_authority,
        oracle_authority,
    }
    .encode();

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateAssetLifecycle {
            action: got_action,
            asset_index: got_asset_index,
            now_slot: got_now_slot,
            initial_price: got_initial_price,
            insurance_authority: got_insurance_authority,
            insurance_operator: got_insurance_operator,
            backing_bucket_authority: got_backing_bucket_authority,
            oracle_authority: got_oracle_authority,
        } => {
            assert_eq!(got_action, action);
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now_slot, now_slot);
            assert_eq!(got_initial_price, initial_price);
            assert_eq!(got_insurance_authority, insurance_authority);
            assert_eq!(got_insurance_operator, insurance_operator);
            assert_eq!(got_backing_bucket_authority, backing_bucket_authority);
            assert_eq!(got_oracle_authority, oracle_authority);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_tradenocpi_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let size_q: i128 = kani::any();
    let exec_price: u64 = kani::any();
    let fee_bps: u64 = kani::any();

    let mut data = [0u8; 35];
    data[0] = 6;
    data[1..3].copy_from_slice(&asset_index.to_le_bytes());
    data[3..19].copy_from_slice(&size_q.to_le_bytes());
    data[19..27].copy_from_slice(&exec_price.to_le_bytes());
    data[27..35].copy_from_slice(&fee_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::TradeNoCpi {
            asset_index: got_asset,
            size_q: got_size,
            exec_price: got_price,
            fee_bps: got_fee,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_size, size_q);
            assert_eq!(got_price, exec_price);
            assert_eq!(got_fee, fee_bps);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_tradecpi_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let size_q: i128 = kani::any();
    let fee_bps: u64 = kani::any();
    let limit_price: u64 = kani::any();

    let mut data = [0u8; 35];
    data[0] = 10;
    data[1..3].copy_from_slice(&asset_index.to_le_bytes());
    data[3..19].copy_from_slice(&size_q.to_le_bytes());
    data[19..27].copy_from_slice(&fee_bps.to_le_bytes());
    data[27..35].copy_from_slice(&limit_price.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::TradeCpi {
            asset_index: got_asset,
            size_q: got_size,
            fee_bps: got_fee,
            limit_price: got_limit,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_size, size_q);
            assert_eq!(got_fee, fee_bps);
            assert_eq!(got_limit, limit_price);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_matcher_return_accepts_only_bound_echoed_fills() {
    // Audit fix: the ret's echoed fields and abi_version are drawn INDEPENDENTLY of the
    // expected (bound) params, and sizes are full-width i128, so both the accept path AND
    // every rejection branch (abi mismatch, echoed-field mismatch, zero exec price, flag
    // checks, size guards) are symbolically exercised — not just the accept path.
    let abi_version: u32 = kani::any();
    let flags: u32 = kani::any();
    let exec_price_e6: u64 = kani::any();
    let exec_size: i128 = kani::any();
    let req_id_ret: u64 = kani::any();
    let lp_ret: u64 = kani::any();
    let oracle_ret: u64 = kani::any();
    let asset_ret: u64 = kani::any();
    // Bound (expected) params the validator echoes against — independent symbolics.
    let lp_account_id: u64 = kani::any();
    let asset_index: u16 = kani::any();
    let oracle_price_e6: u64 = kani::any();
    let req_size: i128 = kani::any();
    let req_id: u64 = kani::any();

    let ret = MatcherReturn {
        abi_version,
        flags,
        exec_price_e6,
        exec_size,
        req_id: req_id_ret,
        lp_account_id: lp_ret,
        oracle_price_e6: oracle_ret,
        asset_index: asset_ret,
    };

    let result = validate_matcher_return(
        &ret,
        lp_account_id,
        asset_index,
        oracle_price_e6,
        req_size,
        req_id,
    );

    // Rejection direction (the binding security property): a return with the wrong ABI,
    // a non-VALID/REJECTED flag state, any echoed field not bound to the expected param,
    // or a zero exec price MUST be rejected.
    if abi_version != percolator_prog::constants::MATCHER_ABI_VERSION
        || (flags & FLAG_VALID) == 0
        || (flags & FLAG_REJECTED) != 0
        || lp_ret != lp_account_id
        || oracle_ret != oracle_price_e6
        || asset_ret != asset_index as u64
        || req_id_ret != req_id
        || exec_price_e6 == 0
    {
        assert!(result.is_err());
    }

    // Accept direction: an accepted fill is bound to every expected field and within the
    // requested size, with the partial flag set whenever the fill is short.
    if result.is_ok() {
        assert!((flags & FLAG_VALID) != 0);
        assert!((flags & FLAG_REJECTED) == 0);
        assert_eq!(lp_ret, lp_account_id);
        assert_eq!(oracle_ret, oracle_price_e6);
        assert_eq!(asset_ret, asset_index as u64);
        assert_eq!(req_id_ret, req_id);
        assert!(exec_price_e6 != 0);
        if exec_size == 0 {
            assert!((flags & FLAG_PARTIAL_OK) != 0);
            assert_eq!(exec_price_e6, oracle_price_e6);
        } else {
            assert_eq!(exec_size.signum(), req_size.signum());
            assert!(exec_size.unsigned_abs() <= req_size.unsigned_abs());
            if exec_size.unsigned_abs() < req_size.unsigned_abs() {
                assert!((flags & FLAG_PARTIAL_OK) != 0);
            }
        }
    }
    // Ensure the accept path is reachable (non-vacuity of the accept assertions).
    kani::cover!(result.is_ok());
}

// FIX W3 (upstream #206, pairs with engine E3 / #92): the wire format no
// longer carries caller-supplied close_q/fee_bps -- liquidation size and fee
// are fully engine-selected (v16.rs liquidate_account_not_atomic). The
// payload shrinks from 53 to 29 bytes (1 tag + 1 action + 2 asset_index +
// 8 now_slot + 16 funding_rate_e9 + 1 recovery_reason).
#[kani::proof]
fn kani_v16_permissionless_crank_decode_preserves_wire_fields() {
    let action: u8 = kani::any();
    let asset_index: u16 = kani::any();
    let recovery_reason: u8 = kani::any();
    let now_slot: u64 = kani::any();
    let funding_rate_e9: i128 = kani::any();

    let mut data = [0u8; 29];
    data[0] = 5;
    data[1] = action;
    data[2..4].copy_from_slice(&asset_index.to_le_bytes());
    data[4..12].copy_from_slice(&now_slot.to_le_bytes());
    data[12..28].copy_from_slice(&funding_rate_e9.to_le_bytes());
    data[28] = recovery_reason;

    match Instruction::decode(&data).unwrap() {
        Instruction::PermissionlessCrank {
            action: got_action,
            asset_index: got_asset,
            now_slot: got_slot,
            funding_rate_e9: got_rate,
            recovery_reason: got_recovery,
        } => {
            assert_eq!(got_action, action);
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_slot, now_slot);
            assert_eq!(got_rate, funding_rate_e9);
            assert_eq!(got_recovery, recovery_reason);
        }
        _ => unreachable!(),
    }
}

// FIX W3 non-vacuity companion: proves the OLD (pre-fix, 53-byte) wire
// payload -- the exact shape a keeper would have sent to control close_q/
// fee_bps -- is now REJECTED by decode as trailing bytes, not silently
// accepted with the extra 24 bytes ignored. This is the concrete "the
// keeper-controlled-sizing attack surface is gone at the wire level" proof.
#[kani::proof]
fn kani_v16_permissionless_crank_rejects_legacy_close_q_fee_bps_wire_payload() {
    let action: u8 = kani::any();
    let asset_index: u16 = kani::any();
    let recovery_reason: u8 = kani::any();
    let now_slot: u64 = kani::any();
    let funding_rate_e9: i128 = kani::any();
    let close_q: u128 = kani::any();
    let fee_bps: u64 = kani::any();

    // Reconstruct the OLD 53-byte layout byte-for-byte.
    let mut legacy = [0u8; 53];
    legacy[0] = 5;
    legacy[1] = action;
    legacy[2..4].copy_from_slice(&asset_index.to_le_bytes());
    legacy[4..12].copy_from_slice(&now_slot.to_le_bytes());
    legacy[12..28].copy_from_slice(&funding_rate_e9.to_le_bytes());
    legacy[28..44].copy_from_slice(&close_q.to_le_bytes());
    legacy[44..52].copy_from_slice(&fee_bps.to_le_bytes());
    legacy[52] = recovery_reason;

    assert!(Instruction::decode(&legacy).is_err());
}

// v17 auth overhaul: UpdateAuthority (tag 32) now rotates ONLY the single
// market-level authority (marketauth); the `kind` field was removed.
// Per-asset authority rotation moved to UpdateAssetAuthority (tag 65).
#[kani::proof]
fn kani_v16_update_authority_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let kind: u8 = kani::any();
    let mut new_pubkey = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        new_pubkey[i] = kani::any();
        i += 1;
    }

    // Tag 32: UpdateAuthority — market-level authority rotation (no kind field).
    let data = Instruction::UpdateAuthority { new_pubkey }.encode();
    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateAuthority {
            new_pubkey: got_pubkey,
        } => {
            assert_eq!(got_pubkey, new_pubkey);
        }
        _ => unreachable!(),
    }

    // Tag 65: UpdateAssetAuthority — per-asset authority rotation (kind + asset_index).
    let data65 = Instruction::UpdateAssetAuthority {
        asset_index,
        kind,
        new_pubkey,
    }
    .encode();
    match Instruction::decode(&data65).unwrap() {
        Instruction::UpdateAssetAuthority {
            asset_index: got_asset,
            kind: got_kind,
            new_pubkey: got_pubkey,
        } => {
            assert_eq!(got_asset, asset_index);
            assert_eq!(got_kind, kind);
            assert_eq!(got_pubkey, new_pubkey);
        }
        _ => unreachable!(),
    }
}

// v17: UpdateInsurancePolicy (tag 33) was removed in the auth overhaul.
// Replaced by a proof for SetLpVaultPaused (tag 79) — a v17 LP vault instruction.
#[kani::proof]
fn kani_v16_set_lp_vault_paused_decode_preserves_wire_fields() {
    let paused: u8 = kani::any();

    let data = Instruction::SetLpVaultPaused { paused }.encode();

    match Instruction::decode(&data).unwrap() {
        Instruction::SetLpVaultPaused { paused: got } => {
            assert_eq!(got, paused);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_liquidation_fee_policy_decode_preserves_wire_fields() {
    let cranker_share_bps: u16 = kani::any();

    let mut data = [0u8; 3];
    data[0] = 37;
    data[1..3].copy_from_slice(&cranker_share_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: got,
        } => assert_eq!(got, cranker_share_bps),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_maintenance_fee_policy_decode_preserves_wire_fields() {
    let cranker_share_bps: u16 = kani::any();

    let mut data = [0u8; 3];
    data[0] = 49;
    data[1..3].copy_from_slice(&cranker_share_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: got,
        } => assert_eq!(got, cranker_share_bps),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_backing_fee_policy_decode_preserves_wire_fields() {
    // v17: domain is u16. Wire: tag(1) + domain(u16=2) + fee_bps(u16=2) + insurance_share_bps(u16=2) = 7.
    let domain: u16 = kani::any();
    let fee_bps: u16 = kani::any();
    let insurance_share_bps: u16 = kani::any();

    let mut data = [0u8; 7];
    data[0] = 51;
    data[1..3].copy_from_slice(&domain.to_le_bytes());
    data[3..5].copy_from_slice(&fee_bps.to_le_bytes());
    data[5..7].copy_from_slice(&insurance_share_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateBackingFeePolicy {
            domain: got_domain,
            fee_bps: got_fee_bps,
            insurance_share_bps: got_insurance_share_bps,
        } => {
            assert_eq!(got_domain, domain);
            assert_eq!(got_fee_bps, fee_bps);
            assert_eq!(got_insurance_share_bps, insurance_share_bps);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_trade_fee_policy_decode_preserves_wire_fields() {
    let trade_fee_base_bps: u64 = kani::any();

    let mut data = [0u8; 9];
    data[0] = 55;
    data[1..9].copy_from_slice(&trade_fee_base_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: got,
        } => assert_eq!(got, trade_fee_base_bps),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_fee_redirect_policy_decode_preserves_wire_fields() {
    let redirect_bps: u16 = kani::any();

    let mut data = [0u8; 3];
    data[0] = 58;
    data[1..3].copy_from_slice(&redirect_bps.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateFeeRedirectPolicy { redirect_bps: got } => assert_eq!(got, redirect_bps),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_update_market_init_fee_policy_decode_preserves_wire_fields() {
    let min_init_fee: u128 = kani::any();

    let mut data = [0u8; 17];
    data[0] = 59;
    data[1..17].copy_from_slice(&min_init_fee.to_le_bytes());

    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: got } => {
            assert_eq!(got, min_init_fee)
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_base_unit_payloads_decode_preserves_wire_fields() {
    let primary_mint: [u8; 32] = kani::any();
    let secondary_mint: [u8; 32] = kani::any();
    let amount: u128 = kani::any();

    let mut update = [0u8; 65];
    update[0] = 60;
    update[1..33].copy_from_slice(&primary_mint);
    update[33..65].copy_from_slice(&secondary_mint);
    match Instruction::decode(&update).unwrap() {
        Instruction::UpdateBaseUnitMints {
            primary_mint: got_primary,
            secondary_mint: got_secondary,
        } => {
            assert_eq!(got_primary, primary_mint);
            assert_eq!(got_secondary, secondary_mint);
        }
        _ => unreachable!(),
    }

    let mut swap = [0u8; 17];
    swap[0] = 61;
    swap[1..17].copy_from_slice(&amount.to_le_bytes());
    match Instruction::decode(&swap).unwrap() {
        Instruction::SwapSecondaryForPrimary { amount: got } => assert_eq!(got, amount),
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_permissionless_resolve_decode_preserves_wire_fields() {
    let stale_slots: u64 = kani::any();
    let force_close_delay_slots: u64 = kani::any();
    let now_slot: u64 = kani::any();

    let mut configure = [0u8; 17];
    configure[0] = 38;
    configure[1..9].copy_from_slice(&stale_slots.to_le_bytes());
    configure[9..17].copy_from_slice(&force_close_delay_slots.to_le_bytes());
    match Instruction::decode(&configure).unwrap() {
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: got_stale,
            force_close_delay_slots: got_delay,
        } => {
            assert_eq!(got_stale, stale_slots);
            assert_eq!(got_delay, force_close_delay_slots);
        }
        _ => unreachable!(),
    }

    let mut resolve = [0u8; 9];
    resolve[0] = 39;
    resolve[1..9].copy_from_slice(&now_slot.to_le_bytes());
    match Instruction::decode(&resolve).unwrap() {
        Instruction::ResolveStalePermissionless { now_slot: got } => {
            assert_eq!(got, now_slot);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_configure_hybrid_oracle_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let oracle_leg_count: u8 = kani::any();
    let oracle_leg_flags: u8 = kani::any();
    let invert: u8 = kani::any();
    let conf_filter_bps: u16 = kani::any();
    let now_slot: u64 = kani::any();
    let now_unix_ts: i64 = kani::any();
    let max_staleness_secs: u64 = kani::any();
    let hybrid_soft_stale_slots: u64 = kani::any();
    let mark_ewma_halflife_slots: u64 = kani::any();
    let mark_min_fee: u64 = kani::any();
    let unit_scale: u32 = kani::any();
    let mut feeds = [[0u8; 32]; 3];
    let mut i = 0;
    while i < 3 {
        let mut j = 0;
        while j < 32 {
            feeds[i][j] = kani::any();
            j += 1;
        }
        i += 1;
    }

    let mut data = [0u8; 156];
    data[0] = 34;
    data[1..3].copy_from_slice(&asset_index.to_le_bytes());
    data[3..11].copy_from_slice(&now_slot.to_le_bytes());
    data[11..19].copy_from_slice(&now_unix_ts.to_le_bytes());
    data[19] = oracle_leg_count;
    data[20] = oracle_leg_flags;
    data[21..29].copy_from_slice(&max_staleness_secs.to_le_bytes());
    data[29..37].copy_from_slice(&hybrid_soft_stale_slots.to_le_bytes());
    data[37..45].copy_from_slice(&mark_ewma_halflife_slots.to_le_bytes());
    data[45..53].copy_from_slice(&mark_min_fee.to_le_bytes());
    data[53] = invert;
    data[54..58].copy_from_slice(&unit_scale.to_le_bytes());
    data[58..60].copy_from_slice(&conf_filter_bps.to_le_bytes());
    data[60..92].copy_from_slice(&feeds[0]);
    data[92..124].copy_from_slice(&feeds[1]);
    data[124..156].copy_from_slice(&feeds[2]);

    match Instruction::decode(&data).unwrap() {
        Instruction::ConfigureHybridOracle {
            asset_index: got_asset_index,
            now_slot: got_now_slot,
            now_unix_ts: got_now_unix,
            oracle_leg_count: got_count,
            oracle_leg_flags: got_flags,
            max_staleness_secs: got_max_staleness,
            hybrid_soft_stale_slots: got_soft,
            mark_ewma_halflife_slots: got_halflife,
            mark_min_fee: got_min_fee,
            invert: got_invert,
            unit_scale: got_unit_scale,
            conf_filter_bps: got_conf,
            oracle_leg_feeds: got_feeds,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now_slot, now_slot);
            assert_eq!(got_now_unix, now_unix_ts);
            assert_eq!(got_count, oracle_leg_count);
            assert_eq!(got_flags, oracle_leg_flags);
            assert_eq!(got_max_staleness, max_staleness_secs);
            assert_eq!(got_soft, hybrid_soft_stale_slots);
            assert_eq!(got_halflife, mark_ewma_halflife_slots);
            assert_eq!(got_min_fee, mark_min_fee);
            assert_eq!(got_invert, invert);
            assert_eq!(got_unit_scale, unit_scale);
            assert_eq!(got_conf, conf_filter_bps);
            assert_eq!(got_feeds, feeds);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_ewma_mark_decode_preserves_wire_fields() {
    let asset_index: u16 = kani::any();
    let mark_raw: u16 = kani::any();

    let now_slot: u64 = kani::any();
    let initial_mark_e6: u64 = kani::any();
    let mark_ewma_halflife_slots: u64 = kani::any();
    let mark_min_fee: u64 = kani::any();
    let push_mark_e6: u64 = kani::any();

    let mut configure = [0u8; 35];
    configure[0] = 35;
    configure[1..3].copy_from_slice(&asset_index.to_le_bytes());
    configure[3..11].copy_from_slice(&now_slot.to_le_bytes());
    configure[11..19].copy_from_slice(&initial_mark_e6.to_le_bytes());
    configure[19..27].copy_from_slice(&mark_ewma_halflife_slots.to_le_bytes());
    configure[27..35].copy_from_slice(&mark_min_fee.to_le_bytes());
    match Instruction::decode(&configure).unwrap() {
        Instruction::ConfigureEwmaMark {
            asset_index: got_asset_index,
            now_slot: got_now,
            initial_mark_e6: got_mark,
            mark_ewma_halflife_slots: got_halflife,
            mark_min_fee: got_min_fee,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now, now_slot);
            assert_eq!(got_mark, initial_mark_e6);
            assert_eq!(got_halflife, mark_ewma_halflife_slots);
            assert_eq!(got_min_fee, mark_min_fee);
        }
        _ => unreachable!(),
    }

    let mut push = [0u8; 19];
    push[0] = 36;
    push[1..3].copy_from_slice(&asset_index.to_le_bytes());
    push[3..11].copy_from_slice(&now_slot.to_le_bytes());
    push[11..19].copy_from_slice(&push_mark_e6.to_le_bytes());
    match Instruction::decode(&push).unwrap() {
        Instruction::PushEwmaMark {
            asset_index: got_asset_index,
            now_slot: got_now,
            mark_e6: got_mark,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now, now_slot);
            assert_eq!(got_mark, push_mark_e6);
        }
        _ => unreachable!(),
    }

    let mut configure_auth = [0u8; 19];
    configure_auth[0] = 62;
    configure_auth[1..3].copy_from_slice(&asset_index.to_le_bytes());
    configure_auth[3..11].copy_from_slice(&now_slot.to_le_bytes());
    configure_auth[11..19].copy_from_slice(&initial_mark_e6.to_le_bytes());
    match Instruction::decode(&configure_auth).unwrap() {
        Instruction::ConfigureAuthMark {
            asset_index: got_asset_index,
            now_slot: got_now,
            initial_mark_e6: got_mark,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now, now_slot);
            assert_eq!(got_mark, initial_mark_e6);
        }
        _ => unreachable!(),
    }

    let mut push_auth = [0u8; 19];
    push_auth[0] = 63;
    push_auth[1..3].copy_from_slice(&asset_index.to_le_bytes());
    push_auth[3..11].copy_from_slice(&now_slot.to_le_bytes());
    push_auth[11..19].copy_from_slice(&push_mark_e6.to_le_bytes());
    match Instruction::decode(&push_auth).unwrap() {
        Instruction::PushAuthMark {
            asset_index: got_asset_index,
            now_slot: got_now,
            mark_e6: got_mark,
        } => {
            assert_eq!(got_asset_index, asset_index);
            assert_eq!(got_now, now_slot);
            assert_eq!(got_mark, push_mark_e6);
        }
        _ => unreachable!(),
    }
}

#[kani::proof]
fn kani_v16_decode_rejects_trailing_bytes() {
    let extra: u8 = kani::any();
    let data = [1u8, extra];
    assert!(Instruction::decode(&data).is_err());
}

fn assert_rejects_trailing_byte(ix: Instruction, extra: u8) {
    let mut data = ix.encode();
    data.push(extra);
    assert!(Instruction::decode(&data).is_err());
}

#[kani::proof]
fn kani_v16_init_market_payload_rejects_trailing_byte() {
    let extra: u8 = kani::any();
    assert_rejects_trailing_byte(
        Instruction::InitMarket {
            max_portfolio_assets: 1,
            h_min: 1,
            h_max: 2,
            initial_price: 100,
            min_nonzero_mm_req: 1,
            min_nonzero_im_req: 2,
            maintenance_margin_bps: 500,
            initial_margin_bps: 1_000,
            max_trading_fee_bps: 10_000,
            trade_fee_base_bps: 0,
            liquidation_fee_bps: 0,
            liquidation_fee_cap: 0,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 100,
            max_accrual_dt_slots: 10,
            max_abs_funding_e9_per_slot: 0,
            min_funding_lifetime_slots: 10,
            max_account_b_settlement_chunks: 1,
            max_bankrupt_close_chunks: 1,
            max_bankrupt_close_lifetime_slots: 100,
            public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
            maintenance_fee_per_slot: 0,
        },
        extra,
    );
}

#[kani::proof]
fn kani_v16_custody_payloads_reject_trailing_byte() {
    let extra: u8 = kani::any();

    assert_rejects_trailing_byte(Instruction::InitPortfolio, extra);
    assert_rejects_trailing_byte(Instruction::Deposit { amount: 1 }, extra);
    assert_rejects_trailing_byte(Instruction::Withdraw { amount: 1 }, extra);
    assert_rejects_trailing_byte(Instruction::TopUpInsurance { amount: 1 }, extra);
    assert_rejects_trailing_byte(
        Instruction::TopUpBackingBucket {
            domain: 1,
            amount: 1,
            expiry_slot: 10,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::WithdrawBackingBucket {
            domain: 1,
            amount: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(Instruction::WithdrawInsurance { amount: 1 }, extra);
    // v17: WithdrawInsuranceLimited removed; WithdrawInsuranceAsset replaces domain withdraw.
    assert_rejects_trailing_byte(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 0,
            amount: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(Instruction::SwapSecondaryForPrimary { amount: 1 }, extra);
}

#[kani::proof]
fn kani_v16_trade_and_crank_payloads_reject_trailing_byte() {
    let extra: u8 = kani::any();

    assert_rejects_trailing_byte(
        Instruction::PermissionlessCrank {
            action: 0,
            asset_index: 0,
            now_slot: 1,
            funding_rate_e9: 0,
            recovery_reason: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::TradeNoCpi {
            asset_index: 0,
            size_q: 1,
            exec_price: 100,
            fee_bps: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::TradeCpi {
            asset_index: 0,
            size_q: 1,
            fee_bps: 0,
            limit_price: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(Instruction::SyncMaintenanceFee { now_slot: 1 }, extra);
}

#[kani::proof]
fn kani_v16_admin_policy_payloads_reject_trailing_byte() {
    let extra: u8 = kani::any();

    assert_rejects_trailing_byte(Instruction::CloseSlab, extra);
    assert_rejects_trailing_byte(Instruction::ResolveMarket, extra);
    // v17: UpdateAuthority no longer has `kind`; UpdateAssetAuthority (tag 65) handles per-asset.
    assert_rejects_trailing_byte(
        Instruction::UpdateAuthority {
            new_pubkey: [1u8; 32],
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateAssetAuthority {
            asset_index: 0,
            kind: 0,
            new_pubkey: [1u8; 32],
        },
        extra,
    );
    // v17: UpdateInsurancePolicy (tag 33) removed; SetLpVaultPaused (tag 79) added.
    assert_rejects_trailing_byte(Instruction::SetLpVaultPaused { paused: 0 }, extra);
    assert_rejects_trailing_byte(
        Instruction::UpdateLiquidationFeePolicy {
            cranker_share_bps: 4_000,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateMaintenanceFeePolicy {
            cranker_share_bps: 4_000,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateBackingFeePolicy {
            domain: 0,
            fee_bps: 25,
            insurance_share_bps: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateTradeFeePolicy {
            trade_fee_base_bps: 25,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateFeeRedirectPolicy { redirect_bps: 250 },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateMarketInitFeePolicy { min_init_fee: 50 },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateBaseUnitMints {
            primary_mint: [1u8; 32],
            secondary_mint: [2u8; 32],
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ConfigurePermissionlessResolve {
            stale_slots: 9000,
            force_close_delay_slots: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ResolveStalePermissionless { now_slot: 9000 },
        extra,
    );
}

#[kani::proof]
fn kani_v16_oracle_asset_payloads_reject_trailing_byte() {
    let extra: u8 = kani::any();

    assert_rejects_trailing_byte(
        Instruction::ConfigureHybridOracle {
            asset_index: 0,
            now_slot: 1,
            now_unix_ts: 1,
            oracle_leg_count: 1,
            oracle_leg_flags: 0,
            max_staleness_secs: 60,
            hybrid_soft_stale_slots: 10,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            invert: 0,
            unit_scale: 0,
            conf_filter_bps: 500,
            oracle_leg_feeds: [[1u8; 32], [0u8; 32], [0u8; 32]],
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ConfigureEwmaMark {
            asset_index: 0,
            now_slot: 1,
            initial_mark_e6: 100,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::PushEwmaMark {
            asset_index: 0,
            now_slot: 2,
            mark_e6: 101,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ConfigureAuthMark {
            asset_index: 0,
            now_slot: 1,
            initial_mark_e6: 100,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::PushAuthMark {
            asset_index: 0,
            now_slot: 2,
            mark_e6: 101,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::UpdateAssetLifecycle {
            action: 0,
            asset_index: 1,
            now_slot: 2,
            initial_price: 100,
            insurance_authority: [1u8; 32],
            insurance_operator: [1u8; 32],
            backing_bucket_authority: [1u8; 32],
            oracle_authority: [1u8; 32],
        },
        extra,
    );
}

#[kani::proof]
fn kani_v16_resolved_recovery_payloads_reject_trailing_byte() {
    let extra: u8 = kani::any();

    assert_rejects_trailing_byte(Instruction::ConvertReleasedPnl { amount: 1 }, extra);
    assert_rejects_trailing_byte(
        Instruction::CloseResolved {
            fee_rate_per_slot: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::CureAndCancelClose {
            optional_deposit: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ForfeitRecoveryLeg {
            asset_index: 0,
            b_delta_budget: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::RebalanceReduce {
            asset_index: 0,
            reduce_q: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::FinalizeResetSide {
            asset_index: 0,
            side: 0,
        },
        extra,
    );
    assert_rejects_trailing_byte(
        Instruction::ForceCloseAbandonedAsset {
            asset_index: 0,
            now_slot: 1,
            close_q: 1,
        },
        extra,
    );
    assert_rejects_trailing_byte(Instruction::ClaimResolvedPayoutTopup, extra);
    assert_rejects_trailing_byte(
        Instruction::RefineResolvedUnreceiptedBound { decrease_num: 1 },
        extra,
    );
    assert_rejects_trailing_byte(Instruction::ClosePortfolio, extra);
}

#[kani::proof]
fn kani_v16_unknown_or_truncated_tags_reject() {
    let tag: u8 = kani::any();
    kani::assume(tag != 0);
    kani::assume(tag != 1);
    kani::assume(tag != 3);
    kani::assume(tag != 4);
    kani::assume(tag != 5);
    kani::assume(tag != 6);
    kani::assume(tag != 8);
    kani::assume(tag != 9);
    kani::assume(tag != 10);
    kani::assume(tag != 13);
    kani::assume(tag != 19);
    // v17: tag 23 (WithdrawInsuranceLimited) removed — decode([23]) returns Err, no assume needed.
    kani::assume(tag != 24);
    kani::assume(tag != 28);
    kani::assume(tag != 30);
    kani::assume(tag != 32);
    // v17: tag 33 (UpdateInsurancePolicy) removed — decode([33]) returns Err, no assume needed.
    kani::assume(tag != 34);
    kani::assume(tag != 35);
    kani::assume(tag != 36);
    kani::assume(tag != 37);
    kani::assume(tag != 38);
    kani::assume(tag != 39);
    kani::assume(tag != 40);
    kani::assume(tag != 41);
    kani::assume(tag != 42);
    kani::assume(tag != 43);
    kani::assume(tag != 44);
    kani::assume(tag != 45);
    kani::assume(tag != 46);
    kani::assume(tag != 47);
    kani::assume(tag != 48);
    kani::assume(tag != 49);
    kani::assume(tag != 50);
    kani::assume(tag != 51);
    kani::assume(tag != 52);
    kani::assume(tag != 53);
    kani::assume(tag != 54);
    kani::assume(tag != 55);
    // v17 zero-payload instructions (decode succeeds from a single byte — must exclude):
    kani::assume(tag != 77); // ExecuteRedemption
    kani::assume(tag != 78); // LpVaultCrankFees
    kani::assume(tag != 80); // CloseLpVault
    assert!(Instruction::decode(&[tag]).is_err());

    let deposit_tag_only = [3u8];
    assert!(Instruction::decode(&deposit_tag_only).is_err());
}

#[kani::proof]
fn kani_v16_zero_length_decode_rejects() {
    let data: [u8; 0] = [];
    assert!(Instruction::decode(&data).is_err());
}

#[kani::proof]
fn kani_v16_every_active_payload_rejects_one_byte_truncation() {
    let init_market = [0u8; 80];
    assert!(Instruction::decode(&init_market).is_err());

    let deposit = [3u8; 16];
    assert!(Instruction::decode(&deposit).is_err());

    let withdraw = [4u8; 16];
    assert!(Instruction::decode(&withdraw).is_err());

    let crank = [5u8; 59];
    assert!(Instruction::decode(&crank).is_err());

    let asset_lifecycle = [40u8; 147];
    assert!(Instruction::decode(&asset_lifecycle).is_err());

    let trade = [6u8; 33];
    assert!(Instruction::decode(&trade).is_err());

    let trade_cpi = [10u8; 33];
    assert!(Instruction::decode(&trade_cpi).is_err());

    let top_up = [9u8; 16];
    assert!(Instruction::decode(&top_up).is_err());

    let top_up_domain = [56u8; 17];
    assert!(Instruction::decode(&top_up_domain).is_err());

    let top_up_backing = [24u8; 25];
    assert!(Instruction::decode(&top_up_backing).is_err());

    // v17: tag 23 (WithdrawInsuranceLimited) removed — 16-byte payload still fails (unknown tag).
    let withdraw_insurance = [23u8; 16];
    assert!(Instruction::decode(&withdraw_insurance).is_err());

    // v17: tag 57 is WithdrawInsuranceAsset { asset_index: u16, amount: u128 } = 19 bytes.
    // 17 bytes is one-byte-truncated → fails. (Was WithdrawInsuranceDomain, same truncation test.)
    let withdraw_insurance_domain = [57u8; 17];
    assert!(Instruction::decode(&withdraw_insurance_domain).is_err());

    let convert_pnl = [28u8; 16];
    assert!(Instruction::decode(&convert_pnl).is_err());

    let close_resolved = [30u8; 16];
    assert!(Instruction::decode(&close_resolved).is_err());

    // v17: UpdateAuthority { new_pubkey } = tag(1) + key(32) = 33 bytes total.
    // Use 32 bytes (one-byte truncation) to guarantee decode fails.
    let update_authority = [32u8; 32];
    assert!(Instruction::decode(&update_authority).is_err());

    // v17: tag 33 (UpdateInsurancePolicy) removed — 11-byte payload still fails (unknown tag).
    let update_insurance = [33u8; 11];
    assert!(Instruction::decode(&update_insurance).is_err());

    let configure_hybrid = [34u8; 155];
    assert!(Instruction::decode(&configure_hybrid).is_err());

    let configure_ewma_mark = [35u8; 34];
    assert!(Instruction::decode(&configure_ewma_mark).is_err());

    let push_ewma_mark = [36u8; 18];
    assert!(Instruction::decode(&push_ewma_mark).is_err());

    let configure_auth_mark = [62u8; 18];
    assert!(Instruction::decode(&configure_auth_mark).is_err());

    let push_auth_mark = [63u8; 18];
    assert!(Instruction::decode(&push_auth_mark).is_err());

    let update_liquidation = [37u8; 2];
    assert!(Instruction::decode(&update_liquidation).is_err());

    let update_redirect = [58u8; 2];
    assert!(Instruction::decode(&update_redirect).is_err());

    let update_base_units = [60u8; 64];
    assert!(Instruction::decode(&update_base_units).is_err());

    let swap_base_units = [61u8; 16];
    assert!(Instruction::decode(&swap_base_units).is_err());

    let configure_permissionless = [38u8; 16];
    assert!(Instruction::decode(&configure_permissionless).is_err());

    let resolve_permissionless = [39u8; 8];
    assert!(Instruction::decode(&resolve_permissionless).is_err());

    let withdraw_insurance_full = [41u8; 16];
    assert!(Instruction::decode(&withdraw_insurance_full).is_err());

    let cure = [42u8; 16];
    assert!(Instruction::decode(&cure).is_err());

    let forfeit = [43u8; 16];
    assert!(Instruction::decode(&forfeit).is_err());

    let rebalance = [44u8; 16];
    assert!(Instruction::decode(&rebalance).is_err());

    let finalize = [45u8; 2];
    assert!(Instruction::decode(&finalize).is_err());

    let refine = [47u8; 16];
    assert!(Instruction::decode(&refine).is_err());

    let sync_fee = [48u8; 8];
    assert!(Instruction::decode(&sync_fee).is_err());

    let force_close = [64u8; 26];
    assert!(Instruction::decode(&force_close).is_err());
}

// ── LP Vault redemption split conservation proofs ────────────────────────────
//
// Proves the core invariant of the v17 principal/earnings split fix:
// atoms = principal_portion + earnings_portion  (conservation)
// principal_portion <= available_principal       (no over-draw on principal pool)
// earnings_portion  <= lp_earnings               (no over-draw on LP earnings)
//
// Uses u8-range symbolic inputs (toly-style small-reference) for tractability.
// Cross-ref: src/v16_program.rs handle_execute_redemption; lp_vault_design.md §5.2.

// Uses direct u128 arithmetic (no wide_math FFI) for CBMC tractability.
// For u8-range inputs (a,b,d all <= 255):
//   - a*b <= 65025, fits in u32, no overflow in u128.
//   - wide_mul_div_floor_u128(a, b, d) == (a * b) / d  (exact, no rounding error
//     from intermediate overflow — both paths agree for sub-u16 products).
// Structural properties proven here hold identically at full u128 scale;
// the wide_math primitives are separately proven in the engine's own Kani suite.
// unwind(1): no loops in direct u128 arithmetic.
#[kani::proof]
#[kani::unwind(1)]
fn kani_lp_vault_redemption_split_conservation() {
    // Symbolic small-range inputs (u8 → u32 cast; all products < u32::MAX so CBMC's
    // 32-bit divider is cheap — exact for the conservation algebra, same as toly's
    // u8-small-reference wide-math standard. u128 here triggers CBMC's expensive
    // 128-bit divide circuit under unwind(1) and times out / fails spuriously).
    // Inputs bounded to a small range so CBMC's symbolic*symbolic multipliers stay
    // tiny. The conservation algebra (floor-rounding of the split) is fully exercised
    // at small scale — the same small-reference principle as toly's u8 wide-math
    // proofs. lp_earnings is a FREE symbolic value, NOT pinned through the large
    // ×10_000 fee-share term: the split-conservation properties depend only on
    // nav = available_principal + lp_earnings and shares <= total_shares, so proving
    // them for ALL lp_earnings >= 0 is STRICTLY STRONGER than for fee-share-derived
    // values, and it drops the nonlinear net*fee term that makes CBMC's SAT intractable.
    // (That lp_earnings == floor(net*fee/10_000) and the redemption decrement is
    // fee-share-exact is certified separately by the fee_share_split_preserved proof.)
    let total_principal: u32 = kani::any();
    let lp_earnings: u32 = kani::any();
    let shares: u32 = kani::any();
    let total_shares: u32 = kani::any();
    kani::assume(total_principal <= 64);
    kani::assume(lp_earnings <= 64);
    kani::assume(shares <= 64);
    kani::assume(total_shares >= 1 && total_shares <= 64);
    kani::assume(shares <= total_shares);
    let available_principal = total_principal; // no impairment (net_impairment = 0)

    let nav = available_principal + lp_earnings; // <= 128

    // DIVISION-FREE: model each floor-quotient q = floor(n/d) by the unique
    // characterization  q*d <= n < (q+1)*d  (d = total_shares >= 1). CBMC handles
    // these multiplicative constraints with no divide circuit (no unwinding assertion).
    // Loose upper bounds prevent overflow in (q+1)*d WITHOUT assuming any conclusion.

    // atoms = floor(shares * nav / total_shares)
    let sh_nav = shares * nav; // <= 64 * 128 = 8192
    let atoms: u32 = kani::any();
    kani::assume(atoms <= sh_nav);
    kani::assume(atoms * total_shares <= sh_nav);
    kani::assume(sh_nav < (atoms + 1) * total_shares);

    // principal_portion = floor(shares * available_principal / total_shares)
    let sh_ap = shares * available_principal; // <= 64 * 64 = 4096
    let principal_portion: u32 = kani::any();
    kani::assume(principal_portion <= sh_ap);
    kani::assume(principal_portion * total_shares <= sh_ap);
    kani::assume(sh_ap < (principal_portion + 1) * total_shares);

    // earnings_portion = atoms - principal_portion (must not underflow).
    assert!(
        atoms >= principal_portion,
        "atoms >= principal_portion (earnings_portion is non-negative)"
    );
    let earnings_portion = atoms - principal_portion;

    // CONSERVATION 1: split sums to atoms exactly.
    assert_eq!(
        principal_portion + earnings_portion,
        atoms,
        "principal_portion + earnings_portion == atoms"
    );

    // CONSERVATION 2: principal_portion never exceeds available principal pool.
    assert!(
        principal_portion <= available_principal,
        "no over-draw on principal pool"
    );

    // CONSERVATION 3: earnings_portion never exceeds lp_earnings.
    // LP earns floor(shares/total_shares * lp_earnings) which rounds down;
    // the difference (insurance stub) stays in the bucket.
    assert!(
        earnings_portion <= lp_earnings,
        "no over-draw on lp_earnings; insurance stub preserved"
    );

    // CONSERVATION 4: guard invariant — principal_portion <= total_principal_atoms.
    // This is WHY the old guard `atoms > total_principal_atoms` was wrong:
    // atoms can exceed total_principal (when earnings present), but principal_portion
    // never can (principal_portion <= available_principal <= total_principal_atoms).
    assert!(
        principal_portion <= total_principal,
        "guard invariant: principal_portion always <= total_principal_atoms"
    );

    // Non-vacuity: the interesting states are reachable (the assumptions are not
    // over-constrained into a trivially-true path).
    kani::cover!(
        earnings_portion > 0,
        "reachable: a real earnings split occurs (proof is not vacuous)"
    );
    kani::cover!(
        principal_portion > 0 && earnings_portion > 0,
        "reachable: both principal and earnings portions nonzero"
    );
}

// ── LP Vault fee_share split preservation across redemptions ─────────────────
//
// Certifies the ECONOMICALLY-CORRECT gross_consumed model (v17 Step-3 fix):
//
//   gross_consumed = ceil(earnings_portion * 10_000 / fee_share_bps)
//
// Production-valid invariant (the SAFE direction — no LP over-extraction):
//
//   lp_earnings_after + earnings_portion <= lp_earnings_before
//
// i.e. after a redemption the remaining LPs' claimable earnings drop by AT LEAST
// earnings_portion. The ceil rounds sub-atom dust into the insurance stub
// (gross_consumed - earnings_portion >= 0), which is NOT accessible to future LP
// redemptions. NOTE: this is an INEQUALITY, not the idealized `==`. With a fee that
// does not divide 10_000 evenly (the production case, fee up to 10_000 — e.g. 3333),
// the ceil over-consumes by up to one unit, so equality is FALSE in production; the
// inequality is the honest, production-valid property. (The 89382f1 bug used
// gross_consumed = earnings_portion, which rounds the OTHER way and lets future LPs
// extract the stub — that is what this fix closes.)
//
// Cross-ref: src/v16_program.rs handle_execute_redemption gross_consumed computation.
//
// DIVISION-FREE / scaled small-reference (see body); #[kani::unwind(1)] is correct —
// the multiplicative-characterization formulation has no loops and no divide circuit.
#[kani::proof]
#[kani::unwind(1)]
fn kani_lp_vault_redemption_fee_share_split_preserved() {
    // SCALED small-reference. Production uses DENOM = 10_000 bps; the floor/ceil
    // gross-up algebra is denom-invariant, so we verify at DENOM = 100 to keep CBMC's
    // symbolic*symbolic products tiny. CRUCIALLY this lets `fee` range over values that
    // do NOT divide DENOM evenly (e.g. 3, 7, 33) — exactly the production case where
    // the ceil over-consumes. The previous proof clamped fee to u8 (<=255) and asserted
    // a strict EQUALITY; that equality only holds on that restricted domain and is FALSE
    // in production (fee up to 10_000, e.g. 3333), so it was a masked proof. The correct,
    // production-valid invariant is the INEQUALITY below: the ceil rounds dust into the
    // insurance stub, so remaining LPs' claimable earnings drop by AT LEAST earnings_portion
    // — never less (no LP over-extraction, the safe direction; the exact opposite of the
    // 89382f1 bug). DIVISION-FREE: every floor/ceil quotient is modelled by its
    // multiplicative characterization (no divide circuit, no unwinding-assertion artifact).
    const DENOM: u32 = 100;

    let net_earnings: u32 = kani::any();
    let fee: u32 = kani::any();
    let shares: u32 = kani::any();
    let total_shares: u32 = kani::any();
    let available_principal: u32 = kani::any();
    kani::assume(net_earnings <= 30);
    kani::assume(fee <= DENOM); // 0..=100 (covers non-dividing fees)
    kani::assume(shares <= 30);
    kani::assume(total_shares >= 1 && total_shares <= 30);
    kani::assume(shares <= total_shares);
    kani::assume(available_principal <= 30);

    // lp_earnings_before = floor(net * fee / DENOM)   via  lpb*DENOM <= net*fee < (lpb+1)*DENOM
    let nf = net_earnings * fee; // <= 3000
    let lpb: u32 = kani::any();
    kani::assume(lpb <= nf); // loose overflow guard
    kani::assume(lpb * DENOM <= nf);
    kani::assume(nf < (lpb + 1) * DENOM);

    let nav = available_principal + lpb; // <= 60

    // atoms = floor(shares * nav / total_shares)
    let sh_nav = shares * nav; // <= 30*60 = 1800
    let atoms: u32 = kani::any();
    kani::assume(atoms <= sh_nav);
    kani::assume(atoms * total_shares <= sh_nav);
    kani::assume(sh_nav < (atoms + 1) * total_shares);

    // principal_portion = floor(shares * available_principal / total_shares)
    let sh_ap = shares * available_principal; // <= 900
    let pp: u32 = kani::any();
    kani::assume(pp <= sh_ap);
    kani::assume(pp * total_shares <= sh_ap);
    kani::assume(sh_ap < (pp + 1) * total_shares);

    assert!(atoms >= pp, "no underflow on earnings_portion");
    let earnings_portion = atoms - pp;

    // gross_consumed = ceil(earnings_portion * DENOM / fee)  (0 if earnings_portion == 0)
    // ceil characterization for gc>0:  (gc-1)*fee < earnings*DENOM <= gc*fee
    let ed = earnings_portion * DENOM; // <= 6000
    let gc: u32 = kani::any();
    if earnings_portion == 0 {
        kani::assume(gc == 0);
    } else {
        // fee > 0 here: earnings>0 => atoms>pp => nav>ap => lpb>0 => nf>0 => fee>0.
        kani::assume(gc >= 1);
        kani::assume(gc <= ed); // loose overflow guard (true gc <= net <= 30)
        kani::assume(gc * fee >= ed); // ceil lower bound
        kani::assume((gc - 1) * fee < ed); // ceil upper bound (gc is the smallest such)
    }

    // CONSERVATION 6: insurance stub non-negative — gross_consumed >= earnings_portion.
    // (gc*fee >= earnings*DENOM and DENOM >= fee  =>  gc >= earnings_portion.)
    assert!(
        gc >= earnings_portion,
        "insurance stub non-negative (gross_consumed >= earnings_portion)"
    );

    // gross_consumed never exceeds net_earnings (earnings <= lpb <= net*fee/DENOM => gc <= net).
    assert!(
        gc <= net_earnings,
        "gross_consumed never exceeds net_earnings"
    );

    let net_after = net_earnings - gc;

    // lp_earnings_after = floor(net_after * fee / DENOM)
    let naf = net_after * fee; // <= 3000
    let lpa: u32 = kani::any();
    kani::assume(lpa <= naf);
    kani::assume(lpa * DENOM <= naf);
    kani::assume(naf < (lpa + 1) * DENOM);

    // CONSERVATION 5 (CORRECTED — production-valid INEQUALITY, not the idealized ==):
    // remaining LPs' claimable earnings drop by AT LEAST earnings_portion.
    //   lpa*DENOM <= naf = nf - gc*fee <= nf - earnings*DENOM < (lpb+1-earnings)*DENOM
    //   => lpa + earnings_portion <= lpb
    assert!(
        lpa + earnings_portion <= lpb,
        "fee_share split preserved (LP-safe): lp_earnings_after + earnings_portion <= lp_earnings_before"
    );

    // When fee == DENOM the LP gets everything: gross_consumed == earnings_portion (no stub dust).
    if fee == DENOM {
        assert_eq!(
            gc, earnings_portion,
            "full fee_share: gross_consumed == earnings_portion (no insurance stub)"
        );
    }
    // When fee == 0, no earnings go to LP.
    if fee == 0 {
        assert_eq!(earnings_portion, 0, "zero fee_share: LP gets no earnings");
        assert_eq!(gc, 0, "zero fee_share: no gross consumed");
    }

    // Non-vacuity AND justification for the `<=` (vs the old `==`): prove the strict
    // case is reachable. If `lpa + earnings_portion < lpb` is COVERED, the ceil dust
    // genuinely makes the relation strict for some in-range inputs — i.e. the old
    // equality assertion was false there, confirming the correction is necessary.
    kani::cover!(
        earnings_portion > 0,
        "reachable: a real earnings split occurs (proof is not vacuous)"
    );
    kani::cover!(
        lpa + earnings_portion < lpb,
        "reachable: ceil dust makes the relation STRICT (the old `==` assertion would FAIL here)"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// E2 — native NFT-holder authorization verdict (`nft_holder_auth_decision`).
//
// This is THE fund-safety gate: it decides whether a signer who is NOT the
// portfolio owner may operate an NFT-escrowed position. We prove it is NOT
// vacuous in BOTH senses:
//   • ACCEPT is reachable — an input set exists that authorizes (not constant-false);
//   • every CONJUNCT is load-bearing — flipping any one gate forces reject
//     (not constant-true / not ignoring a check), i.e. each specific attack is
//     provably rejected for ALL other symbolic inputs;
//   • SOUNDNESS — if it authorizes, every gate held.
// Together these show the verdict genuinely discriminates a real holder of the
// bound NFT from every attacker, exhaustively over all inputs.
// ════════════════════════════════════════════════════════════════════════════
use percolator_prog::processor::nft_holder_auth_decision;

/// ACCEPT REACHABLE: when every gate holds, the verdict MUST authorize. Proves the
/// accept path is live (defeats the constant-false vacuity mode).
#[kani::proof]
fn kani_e2_auth_accept_when_all_gates_hold() {
    let owner: [u8; 32] = kani::any(); // portfolio_owner == expected_mint_auth
    let pkey: [u8; 32] = kani::any(); // pda_portfolio_account == portfolio_key
    let signer: [u8; 32] = kani::any(); // ata_owner == signer
    let mint: [u8; 32] = kani::any(); // ata_mint == bound_mint
    let ok = nft_holder_auth_decision(
        owner, owner, true, pkey, pkey, true, mint, mint, signer, signer, 1, true,
    );
    assert!(
        ok,
        "a genuine bound-NFT holder of an escrowed position must authorize"
    );
    kani::cover!(
        ok,
        "NFT-holder accept path is reachable (anti-vacuity witness)"
    );
}

/// SOUNDNESS: authorize ⟹ every gate held (no path authorizes with a gate false).
#[kani::proof]
fn kani_e2_auth_accept_implies_all_gates() {
    let po: [u8; 32] = kani::any();
    let ema: [u8; 32] = kani::any();
    let pob: bool = kani::any();
    let ppa: [u8; 32] = kani::any();
    let pk: [u8; 32] = kani::any();
    let can: bool = kani::any();
    let bm: [u8; 32] = kani::any();
    let am: [u8; 32] = kani::any();
    let sg: [u8; 32] = kani::any();
    let ao: [u8; 32] = kani::any();
    let amt: u64 = kani::any();
    let init: bool = kani::any();
    if nft_holder_auth_decision(po, ema, pob, ppa, pk, can, bm, am, sg, ao, amt, init) {
        assert!(
            po == ema,
            "authorized ⟹ portfolio escrowed under this NFT program"
        );
        assert!(pob, "authorized ⟹ PositionNft PDA is NFT-program-owned");
        assert!(ppa == pk, "authorized ⟹ PDA binds THIS portfolio");
        assert!(can, "authorized ⟹ PDA is canonical");
        assert!(am == bm, "authorized ⟹ token is the BOUND mint");
        assert!(ao == sg, "authorized ⟹ signer owns the token account");
        assert!(amt == 1, "authorized ⟹ holds exactly one");
        assert!(init, "authorized ⟹ token account initialized");
    }
}

// ── Each gate LOAD-BEARING: its failure ⟹ reject, for ALL other inputs ──

#[kani::proof]
fn kani_e2_auth_reject_not_escrowed() {
    let po: [u8; 32] = kani::any();
    let ema: [u8; 32] = kani::any();
    kani::assume(po != ema);
    let ok = nft_holder_auth_decision(
        po,
        ema,
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    assert!(!ok, "non-escrowed (owner != mint-auth PDA) must reject");
}

#[kani::proof]
fn kani_e2_auth_reject_fake_pda_owner() {
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        false,
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    assert!(
        !ok,
        "PositionNft PDA not owned by the NFT program must reject"
    );
}

#[kani::proof]
fn kani_e2_auth_reject_wrong_portfolio() {
    let ppa: [u8; 32] = kani::any();
    let pk: [u8; 32] = kani::any();
    kani::assume(ppa != pk);
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        ppa,
        pk,
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    assert!(!ok, "an NFT bound to a DIFFERENT portfolio must reject");
}

#[kani::proof]
fn kani_e2_auth_reject_noncanonical_pda() {
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        false,
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    assert!(!ok, "a non-canonical PositionNft PDA must reject");
}

#[kani::proof]
fn kani_e2_auth_reject_wrong_mint() {
    let bm: [u8; 32] = kani::any();
    let am: [u8; 32] = kani::any();
    kani::assume(am != bm);
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        bm,
        am,
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
    assert!(
        !ok,
        "holding a DIFFERENT mint (not the bound NFT) must reject"
    );
}

#[kani::proof]
fn kani_e2_auth_reject_wrong_ata_owner() {
    let sg: [u8; 32] = kani::any();
    let ao: [u8; 32] = kani::any();
    kani::assume(ao != sg);
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        sg,
        ao,
        kani::any(),
        kani::any(),
    );
    assert!(!ok, "a token account NOT owned by the signer must reject");
}

#[kani::proof]
fn kani_e2_auth_reject_amount_not_one() {
    let amt: u64 = kani::any();
    kani::assume(amt != 1);
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        amt,
        kani::any(),
    );
    assert!(!ok, "amount != 1 (zero, or a fungible balance) must reject");
}

#[kani::proof]
fn kani_e2_auth_reject_uninitialized_ata() {
    let ok = nft_holder_auth_decision(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        false,
    );
    assert!(!ok, "an uninitialized token account must reject");
}

// ── F-1 / F-2 insurance-withdrawal policy proofs ────────────────────────────
// Non-vacuous: each harness re-derives the spec independently and asserts the
// helper matches it over ALL inputs, plus kani::cover! to prove both the accept
// and reject outcomes are reachable (not constant-true / constant-false).

#[kani::proof]
fn kani_f1_insurance_withdraw_cooldown_gate() {
    let cooldown: u64 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let res = percolator_prog::processor::check_insurance_withdraw_cooldown(cooldown, last, now);

    if cooldown == 0 || last == 0 {
        // Policy off, or first-ever withdrawal ⇒ always allowed.
        assert!(res.is_ok());
    } else {
        match last.checked_add(cooldown) {
            None => assert!(res.is_err()), // overflow ⇒ rejected (never panics)
            Some(earliest) => {
                if now < earliest {
                    assert!(res.is_err()); // window not elapsed ⇒ cooldown active
                } else {
                    assert!(res.is_ok()); // window elapsed ⇒ allowed (boundary inclusive)
                }
            }
        }
    }
    kani::cover!(res.is_ok());
    kani::cover!(res.is_err());
}

#[kani::proof]
fn kani_f2_insurance_withdraw_ceiling() {
    let deposits_only: u8 = kani::any();
    let remaining: u128 = kani::any();
    let amount: u128 = kani::any();
    let res = percolator_prog::processor::apply_insurance_withdraw_ceiling(
        deposits_only,
        remaining,
        amount,
    );

    if deposits_only == 0 {
        // Ceiling off ⇒ remaining returned unchanged.
        assert_eq!(res, Ok(remaining));
    } else if amount > remaining {
        // Over the deposited principal ⇒ rejected.
        assert!(res.is_err());
    } else {
        // Within ceiling ⇒ decremented, and the decrement never underflows.
        assert_eq!(res, Ok(remaining - amount));
    }
    kani::cover!(res.is_ok() && deposits_only != 0);
    kani::cover!(res.is_err());
}

// ── Protocol-fee RESERVE amendment -- wrapper-side Kani obligations ────────
// (~/v17/PROTOCOL-FEE-DESIGN.md §5.2, ~/v17/VERIFICATION-RESULTS.md blocker
// #3). These four harnesses were committed to by the design doc but never
// written; closing that gap here, plus the new reserve property that the
// starvation-attack fix (blocker #1) introduces. All four call the ACTUAL
// `pub` functions used by the real instruction handlers (`fee_share_floor`,
// `maintenance_cranker_reward`, `protocol_fee_withdraw_amount`,
// `parse_program_data_upgrade_authority_bytes` in `processor`, plus the
// engine's own `credit_account_from_insurance_delta` via its `kani_`
// facade) -- not re-derivations of them -- so a bug in the real code is a
// bug in the model.

// (a) Skim conservation: the protocol's cut plus what's left for the
// taker-domain credit always reconstitutes the full fee charged, for both
// legs of a fill.
#[kani::proof]
fn kani_protocol_skim_conserves_total_fee() {
    let fee_a: u128 = kani::any();
    let fee_b: u128 = kani::any();
    let protocol_fee_bps: u16 = percolator_prog::constants::PROTOCOL_FEE_BPS;

    let protocol_cut_a = percolator_prog::processor::fee_share_floor(fee_a, protocol_fee_bps);
    let protocol_cut_b = percolator_prog::processor::fee_share_floor(fee_b, protocol_fee_bps);

    kani::cover!(
        fee_a > 0,
        "skim conservation covers a nonzero taker-side fee"
    );
    kani::cover!(
        fee_a == 0,
        "skim conservation covers the maker side's zero fee (taker-only)"
    );

    if let Ok(protocol_cut_a) = protocol_cut_a {
        // No atom created or destroyed by the skim split: what's left after
        // the protocol's cut is exactly the taker-domain's credit.
        let domain_fee_a = fee_a.checked_sub(protocol_cut_a);
        assert!(
            domain_fee_a.is_some(),
            "protocol cut must never exceed the fee it was skimmed from"
        );
        assert_eq!(domain_fee_a.unwrap() + protocol_cut_a, fee_a);
    }
    if let Ok(protocol_cut_b) = protocol_cut_b {
        let domain_fee_b = fee_b.checked_sub(protocol_cut_b);
        assert!(domain_fee_b.is_some());
        assert_eq!(domain_fee_b.unwrap() + protocol_cut_b, fee_b);
    }
    // Taker-only (§1A): the maker leg's fee is always 0, so skimming 20% of
    // 0 must be 0 -- the maker's domain gets exactly the 0 credit it should,
    // no special-casing needed at the skim site.
    if fee_a == 0 {
        assert_eq!(protocol_cut_a, Ok(0));
    }
    if fee_b == 0 {
        assert_eq!(protocol_cut_b, Ok(0));
    }
}

// (b1) The skim floor never over-collects: the protocol's cut is always
// `<= fee_share_floor(fee, PROTOCOL_FEE_BPS)` -- i.e. it exactly matches
// floor-division rounding, which always favors the domain/creator, never
// the protocol.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn kani_protocol_skim_never_exceeds_fee_share_bps() {
    let fee: u128 = kani::any();
    let share_bps: u16 = kani::any();
    let res = percolator_prog::processor::fee_share_floor(fee, share_bps);

    kani::cover!(
        res.is_ok() && matches!(res, Ok(v) if v > 0),
        "skim floor covers a nonzero cut"
    );
    kani::cover!(
        fee == 0 || share_bps == 0,
        "skim floor covers the zero-fee/zero-bps short-circuit"
    );
    kani::cover!(
        share_bps as u128 == 10_000 && fee > 0,
        "skim floor covers a full-bps (100%) share still floor-dividing correctly"
    );

    if fee == 0 || share_bps == 0 {
        assert_eq!(res, Ok(0));
    } else {
        match fee.checked_mul(share_bps as u128) {
            None => assert!(
                res.is_err(),
                "overflow must be rejected, never wrap/truncate"
            ),
            Some(scaled) => {
                let expected = scaled / 10_000;
                assert_eq!(res, Ok(expected));
                // Floor-division rounds down: the cut can never exceed
                // `fee * share_bps / 10_000` exactly, and for
                // `share_bps <= 10_000` (the only values this program ever
                // configures `PROTOCOL_FEE_BPS` to) it can never exceed `fee`
                // itself -- the protocol never over-collects.
                if share_bps as u128 <= 10_000 {
                    assert!(
                        expected <= fee,
                        "skim must never exceed the fee it was taken from"
                    );
                }
            }
        }
    }
}

// (b2) No-theft: WithdrawProtocolFee's transfer amount can never exceed the
// un-withdrawn protocol claim (`accrued - withdrawn`) at call time, and the
// ledger (`next_withdrawn`) can never exceed `accrued` either -- the ledger
// itself bounds the payout, independent of the engine-level surplus check.
#[kani::proof]
fn kani_protocol_claim_never_exceeds_accrued() {
    let accrued: u128 = kani::any();
    let withdrawn: u128 = kani::any();
    let requested_raw: u128 = kani::any();
    let engine_available: u128 = kani::any();
    let vault: u128 = kani::any();
    // Genuine ledger invariant maintained by every other call site
    // (`protocol_fee_withdrawn_atoms` is only ever incremented by the
    // amount actually transferred, which is itself bounded by the
    // claim capacity) -- not a narrowing of the adversarial input space for
    // `requested_raw`/`engine_available`/`vault`, which stay fully symbolic.
    kani::assume(withdrawn <= accrued);

    let res = percolator_prog::processor::protocol_fee_withdraw_amount(
        accrued,
        withdrawn,
        requested_raw,
        engine_available,
        vault,
    );

    let claim_capacity = accrued - withdrawn;
    kani::cover!(res.is_ok(), "no-theft proof covers a successful withdrawal");
    kani::cover!(res.is_err(), "no-theft proof covers a rejected withdrawal");
    kani::cover!(
        matches!(res, Ok((t, _)) if t > 0 && t < claim_capacity),
        "no-theft proof covers a partial fill (engine_available/vault-clamped, N2)"
    );
    kani::cover!(
        requested_raw == 0 && matches!(res, Ok((t, _)) if t == claim_capacity),
        "no-theft proof covers requested_raw == 0 (withdraw-all) taking the full claim"
    );

    if let Ok((transfer_amount, next_withdrawn)) = res {
        assert!(
            transfer_amount <= claim_capacity,
            "the ledger itself must bound the payout to the un-withdrawn claim"
        );
        assert!(transfer_amount <= engine_available);
        assert!(transfer_amount <= vault);
        assert!(
            transfer_amount > 0,
            "a zero transfer must be rejected, not silently succeed"
        );
        assert_eq!(next_withdrawn, withdrawn + transfer_amount);
        assert!(
            next_withdrawn <= accrued,
            "cumulative withdrawn can never exceed cumulative accrued"
        );
    }
}

// (c) THE RESERVE PROPERTY (blocker #1 fix): a cranker-reward draw --
// composed from the wrapper's real `maintenance_cranker_reward` and the
// engine's real `credit_account_from_insurance_delta` with
// `additional_reserved == protocol_owed` -- can never reduce insurance
// below the protocol's accrued-but-unwithdrawn claim. This is the formal
// statement of the starvation-attack fix: before this fix,
// `credit_account_from_insurance_delta` had no `additional_reserved`
// parameter and this property did not hold (a sufficiently large
// `maintenance_cranker_fee_share_bps` could drain the claim to 0).
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn kani_protocol_fee_reserve_never_starved_by_cranker_reward() {
    let charged: u128 = kani::any();
    let cranker_fee_share_bps: u16 = kani::any();
    let accrued: u128 = kani::any();
    let withdrawn: u128 = kani::any();
    let insurance: u128 = kani::any();
    let budget_remaining: u128 = kani::any();
    let c_tot: u128 = kani::any();
    let capital: u128 = kani::any();
    kani::assume(withdrawn <= accrued);
    kani::assume(c_tot <= u128::MAX - insurance);
    // `maintenance_cranker_fee_share_bps` is a creator-set market policy
    // field, not otherwise range-checked by the caller of this harness's
    // model -- bound it to the same u16 wire width the real field uses
    // (`WrapperConfigV16.maintenance_cranker_fee_share_bps: u16`), which is
    // exactly the adversarial space a malicious creator can reach (up to
    // 100_00 == 1000%, i.e. no narrower than production).
    let protocol_owed = accrued - withdrawn;

    let reward =
        percolator_prog::processor::maintenance_cranker_reward(charged, cranker_fee_share_bps);
    kani::cover!(
        reward.is_ok() && matches!(reward, Ok(r) if r > 0),
        "reserve property covers a nonzero cranker reward"
    );

    if let Ok(reward) = reward {
        let credit_result =
            percolator::MarketGroupV16ViewMut::<u64>::kani_credit_account_from_insurance_delta(
                insurance,
                budget_remaining,
                protocol_owed,
                c_tot,
                capital,
                reward,
            );
        kani::cover!(
            credit_result.is_ok(),
            "reserve property covers a credit that succeeds while a reservation is in effect"
        );
        kani::cover!(
            credit_result.is_err() && protocol_owed > 0,
            "reserve property covers the reserve actually blocking a draw"
        );
        if let Ok((next_insurance, _, _)) = credit_result {
            assert!(
                next_insurance >= protocol_owed,
                "STARVATION FIX: a cranker reward must never dip insurance below the protocol's un-withdrawn claim"
            );
        }
    }
}

// (d) SetProtocolFeeAuthority (tag 85) is gated on the BPF *upgrade*
// authority, never on `marketauth`/any creator-facing key. Two parts: the
// raw-byte parse of the `ProgramData` account's `upgrade_authority_address`
// is decode-faithful (mirrors `kani_v16_init_market_decode_preserves_wire_fields`
// style), and the gate decision itself only accepts an exact match against
// the parsed `Some(authority)` -- a `None` (finalized/immutable program) or
// any mismatched signer is rejected.
#[kani::proof]
fn kani_set_protocol_fee_authority_requires_upgrade_authority() {
    let discriminant: u32 = kani::any();
    let slot: u64 = kani::any();
    let option_tag: u8 = kani::any();
    let authority_bytes: [u8; 32] = kani::any();
    let signer_bytes: [u8; 32] = kani::any();

    let mut data = [0u8; 45];
    data[0..4].copy_from_slice(&discriminant.to_le_bytes());
    data[4..12].copy_from_slice(&slot.to_le_bytes());
    data[12] = option_tag;
    data[13..45].copy_from_slice(&authority_bytes);

    let parsed = percolator_prog::processor::parse_program_data_upgrade_authority_bytes(&data);

    kani::cover!(
        discriminant != 3,
        "upgrade-authority gate covers a non-ProgramData account (rejected)"
    );
    kani::cover!(
        discriminant == 3 && option_tag == 0,
        "upgrade-authority gate covers a finalized/immutable program (None)"
    );
    kani::cover!(
        discriminant == 3 && option_tag == 1,
        "upgrade-authority gate covers a live upgrade authority (Some)"
    );
    kani::cover!(
        discriminant == 3 && option_tag > 1,
        "upgrade-authority gate covers a malformed Option tag (rejected)"
    );

    // Decode fidelity: matches the on-chain `UpgradeableLoaderState::ProgramData`
    // layout exactly (§ read_program_data_upgrade_authority's own doc comment).
    if discriminant != 3 {
        assert!(parsed.is_err());
    } else {
        match option_tag {
            0 => assert_eq!(parsed, Ok(None)),
            1 => {
                let expected = solana_program::pubkey::Pubkey::new_from_array(authority_bytes);
                assert_eq!(parsed, Ok(Some(expected)));
            }
            _ => assert!(parsed.is_err()),
        }
    }

    // Gate decision: `handle_set_protocol_fee_authority` accepts iff the
    // signer is an exact match for the parsed `Some(authority)`. Neither a
    // `None` result nor any non-matching signer can ever authorize the
    // rotation.
    let signer = solana_program::pubkey::Pubkey::new_from_array(signer_bytes);
    let would_authorize = matches!(&parsed, Ok(Some(a)) if *a == signer);
    kani::cover!(
        would_authorize,
        "upgrade-authority gate covers the accept path (exact signer match)"
    );
    kani::cover!(
        !would_authorize,
        "upgrade-authority gate covers a reject path (mismatch, None, or parse error)"
    );
    if option_tag == 0 && discriminant == 3 {
        assert!(
            !would_authorize,
            "an immutable/finalized program can never satisfy the gate"
        );
    }
    if discriminant == 3 && option_tag == 1 && authority_bytes != signer_bytes {
        assert!(
            !would_authorize,
            "a non-upgrade-authority signer must never satisfy the gate"
        );
    }
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ RETIRED CODE. THIS PROOF VERIFIES A FUNCTION NO INSTRUCTION CAN REACH.   ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
// `policy_v16::fee_split_floor_ok` has NO live call sites. `2b3a6a65` removed
// it from `handle_update_backing_fee_policy` and `handle_update_trade_fee_policy`,
// the only two handlers that ever called it. It is retained solely so this
// proof and its unit tests still compile (see the function's own doc comment
// and the as-built spec §7).
//
// READ THIS BEFORE CITING THE PROOF. If you are asking "are the fee-split
// floors formally verified on-chain?", the answer is NO. This harness proves a
// property of dead code. The floors that actually run are enforced by
// `policy_v16::validate_fee_split`, called from `handle_update_fee_split`
// (tag 86) — a different function with different semantics: an EXACT integer
// check on a SINGLE-rate split with no tolerance and no skip path, versus the
// tolerance-based two-rate check proven below. Nothing here transfers to it.
// Tag 86's enforcement is covered by on-chain tests in
// `tests/v16_fee_split.rs` (`tag86_rejects_a_floor_violation_with_custom_51`,
// `tag86_rejects_an_invalid_sum_with_custom_52`), not by formal verification.
//
// Kept rather than deleted because the function is kept: deleting the proof
// would leave retained code entirely unverified, which is worse than a
// correctly-labelled proof of a retired path. Delete both together or neither.
//
// The historical description follows, unchanged, and describes the RETIRED
// two-rate design (`T = trade_fee_base_bps + backing_fee_bps`), which no
// longer matches how fees are split.
//
// (e) fee_split_floor_ok (policy_v16): on-chain enforcement of the launch
// wizard's (feeSplit.ts) fee-split floors -- creator at most 45%, LP at
// least 40%, insurance at least 15%, all as a share of
// `T = trade_fee_base_bps + backing_fee_bps` -- applied by
// `UpdateBackingFeePolicy` / `UpdateTradeFeePolicy` (the latter re-validating
// EVERY configured asset's stored domain against a proposed new
// `trade_fee_base_bps`, not just asset 0's -- see W11/46627c82) so a raw
// instruction can't bypass the client-side-only wizard check. For any input
// in the harness's domain (see BOUND rationale below) that the function
// ACCEPTS, the derived percentages of T satisfy each floor within the
// documented, proven-worst-case tolerance (FEE_SPLIT_CREATOR_TOLERANCE / the
// T-scaled share tolerance built from FEE_SPLIT_SHARE_TOLERANCE_FLAT, see
// their doc comments for the derivation).
// Also proves the wizard's default 20/60/20 example is always accepted,
// and (non-vacuity) that both an accept and a reject are reachable.
//
// BOUND RATIONALE (why this harness is intentionally NOT the full
// `<=10_000` wire-width domain, and why that is still a real, representative
// proof rather than a weakened one):
//
// History: the original unrestricted harness (`trade_fee_base_bps`,
// `backing_fee_bps`, `insurance_share_bps` each a full `kani::any::<u64>()`
// only narrowed post-hoc via `kani::assume(<=10_000)`) never reached a
// verdict across three separate attempts, the longest run 10h57m before
// being killed (CBMC/cadical, "128-bit arithmetic blowup"). Root cause: CBMC
// bit-blasts `u128` multiplication (`fee_split_floor_ok`'s internal
// `tfb.checked_mul(100)`, `bf.checked_mul(isb)`, etc.) into a boolean circuit
// sized by the OPERAND'S BIT WIDTH, not its assumed value range. A
// `kani::any::<u64>()` later constrained via `kani::assume(<= 10_000)` is
// still, structurally, a fully free 64-bit (then zero-extended to 128-bit)
// symbolic word as far as CBMC's own front-end simplification is concerned
// -- the assume() is just extra clauses fed to the SAT solver on top of a
// full-width multiplier circuit, not a narrower circuit. Three independent
// ~10000x10000x10000 symbolic multiplications over that representation is
// what never converged.
//
// Fix: declare the two `T`-contributing inputs with a NARROW native type
// (`u8`, 0..=255) instead of `u64`, then `kani::assume` a small ceiling on
// top. Casting a genuinely 8-bit-wide symbolic value up to `u128` is a
// structural zero-extension CBMC's own front-end constant-folds away before
// the solver ever sees a multiplier circuit -- the upper 120 bits are
// provably-constant zero at the GOTO-program level, not merely SAT-solver-
// derivable. This collapses `tfb`/`bf`'s effective multiplier width from 128
// bits to a handful of bits, which is what makes the proof tractable.
// `insurance_share_bps` is kept at its full on-chain `<=10_000` range (via
// `kani::any::<u16>()`, still narrower than the original `u64`) because it
// is the SMALLER-width operand in every product it appears in once `bf` is
// bounded (`bf * isb` with `bf<=48` is effectively a ~6-bit x 14-bit
// multiply, not 128x128), so widening it back out does not reintroduce the
// blowup.
//
// Domain covered, `trade_fee_base_bps<=48`, `backing_fee_bps<=48` (so
// `T = trade_fee_base_bps + backing_fee_bps` ranges over `0..=96`),
// `insurance_share_bps<=10_000` (full on-chain range):
//   - The previously-vacuous low-T region `T in 1..8` (exhaustive proper
//     subset of `0..=96`).
//   - The launch wizard's default `T=20` example (`tfb=4, bf=16`, both
//     `<=48`) -- reachable symbolically, and additionally pinned by an
//     explicit concrete assertion below.
//   - `T` well past the documented residual carve-out thresholds (insurance
//     no-op at `T in {1,2,3}`, LP no-op at `T=1`) with 32-96x margin, so the
//     proof also confirms the fix's improvement over the old flat-10_000
//     bound (no-op at `T<=6`/`T<=2`) generalizes, not just holds at the
//     single previously-cited boundary.
//   - The W11 multi-asset re-validation path (`handle_update_trade_fee_policy`
//     looping `fee_split_floor_ok` over every configured asset's domain,
//     not just asset 0's): W11 did NOT change `fee_split_floor_ok` itself
//     (confirmed by inspection of 46627c82 -- only the CALLER's loop
//     changed, the predicate is invoked unmodified once per asset/domain).
//     Since this harness proves the predicate itself sound for any input in
//     its domain, and the loop's soundness is exactly "reject the whole
//     instruction if calling this predicate on ANY asset's domain returns
//     false" -- with each call independent and side-effect-free -- proving
//     the predicate once composes trivially across the loop's N calls. The
//     loop's own control flow (does it actually scan
//     `0..configured_market_slots`, does it actually reject on the first
//     `false`) is a wrapper-processor property outside a pure-function
//     harness's scope; that is covered instead by the non-Kani integration
//     test
//     `v16_wrapper_fee_split_floor_update_trade_fee_policy_checks_every_asset_not_just_asset0`
//     (re-run as corroborating evidence for this session, see report).
//
// NOT covered by this harness (stated plainly, per the redesign mandate):
// `T > 96` is not explored symbolically. Representativeness argument (not
// itself Kani-checked, a closed-form monotonicity claim over the exact
// constants above): for all three floors the ratio of `tolerance(T)` to the
// (pre-tolerance) target threshold is monotonically DEcreasing in `T` for
// `T>0` --
//   creator:   tolerance/target = 50            / (45*T)         = O(1/T)
//   insurance: tolerance/target = (T/2+5001)     / (1500*T)  -> 1/3000 + O(1/T)
//   lp:        tolerance/target = (T/2+5001)     / (4000*T)  -> 1/8000 + O(1/T)
// so the RELATIVE slack the tolerance allows (i.e. how large a violation of
// the true, tolerance-free floor the check can still accept, as a fraction
// of the floor itself) is largest at the smallest `T` and only shrinks as
// `T` grows -- this is the same reasoning the source's own
// `FEE_SPLIT_SHARE_TOLERANCE_FLAT` doc comment uses to identify the
// low-T residual carve-out. The fully-covered `0..=96` region is therefore
// argued to be the domain where an under-enforcement bug is MOST likely to
// hide, not an arbitrary slice; `T` in `97..=20_000` is not symbolically
// checked here and a bug specific to that region (e.g. a genuinely
// T-dependent overflow) would not be caught by this harness. All three
// `checked_mul`/`checked_add` calls inside `fee_split_floor_ok` operate on
// `u128` with actual operand magnitudes that never exceed ~1e8 for ANY
// input in the full `<=10_000` wire-width domain (nowhere near `u128::MAX`),
// so arithmetic overflow inside the function is not the residual risk left
// by this bound -- CBMC's proof-engine tractability is.
#[kani::proof]
// Screaming-case RETIRED is deliberate: this name appears in `cargo kani`
// output and in audit evidence, where it must be impossible to mistake this
// proof for coverage of a live path.
#[allow(non_snake_case)]
fn kani_RETIRED_fee_split_floor_ok_matches_tolerant_percentage_floors() {
    let trade_fee_base_bps: u64 = kani::any::<u8>() as u64;
    let backing_fee_bps: u64 = kani::any::<u8>() as u64;
    let insurance_share_bps: u64 = kani::any::<u16>() as u64;
    // BOUNDED domain -- see the BOUND RATIONALE doc comment above this
    // harness for the termination argument and exactly what T range /
    // representativeness claim this buys. `insurance_share_bps` keeps the
    // full on-chain `<=10_000` wire-width range; only the two `T`-forming
    // inputs are narrowed, since they are what drove the u128-multiply
    // blowup.
    kani::assume(trade_fee_base_bps <= 48);
    kani::assume(backing_fee_bps <= 48);
    kani::assume(insurance_share_bps <= 10_000);

    let accepted =
        policy_v16::fee_split_floor_ok(trade_fee_base_bps, backing_fee_bps, insurance_share_bps);

    kani::cover!(accepted, "fee_split_floor_ok covers an accepted split");
    kani::cover!(!accepted, "fee_split_floor_ok covers a rejected split");
    kani::cover!(
        backing_fee_bps == 0,
        "fee_split_floor_ok covers the backing_fee_bps==0 skip path"
    );
    kani::cover!(
        backing_fee_bps > 0 && accepted,
        "fee_split_floor_ok covers a nonzero-backing-fee split that is accepted"
    );

    if backing_fee_bps == 0 {
        assert!(
            accepted,
            "backing_fee_bps==0 must always skip the floor check"
        );
        return;
    }

    if accepted {
        let t = trade_fee_base_bps + backing_fee_bps; // no overflow: both <=48 here (bounded harness)
        assert!(t > 0);
        // creator% <= 45 within tolerance: tfb*100 <= 45*T + CREATOR_TOLERANCE
        assert!(
            trade_fee_base_bps * 100 <= 45 * t + policy_v16::FEE_SPLIT_CREATOR_TOLERANCE,
            "accepted split must satisfy the creator floor within tolerance"
        );
        // T-scaled share tolerance: (t+1)/2 + FEE_SPLIT_SHARE_TOLERANCE_FLAT.
        // t:u64 here, <=20_000, so t+1 and the final sum cannot overflow.
        let share_tolerance = (t + 1) / 2 + policy_v16::FEE_SPLIT_SHARE_TOLERANCE_FLAT as u64;
        // insurance% >= 15 within tolerance: bf*isb >= 15*T*100 - share_tolerance
        let insurance_rhs = (15 * t * 100).saturating_sub(share_tolerance);
        assert!(
            backing_fee_bps * insurance_share_bps >= insurance_rhs,
            "accepted split must satisfy the insurance floor within tolerance"
        );
        // lp% >= 40 within tolerance: bf*(10000-isb) >= 40*T*100 - share_tolerance
        let lp_share = 10_000 - insurance_share_bps;
        let lp_rhs = (40 * t * 100).saturating_sub(share_tolerance);
        assert!(
            backing_fee_bps * lp_share >= lp_rhs,
            "accepted split must satisfy the LP floor within tolerance"
        );
    }

    // Wizard-default example (T=20bps, creatorPct=20/lpPct=60/insurancePct=20):
    // tfb=4, bf=16, isb=2500 -- must always be accepted.
    if trade_fee_base_bps == 4 && backing_fee_bps == 16 && insurance_share_bps == 2_500 {
        assert!(
            accepted,
            "the wizard's default 20/60/20 split must be accepted"
        );
    }
}

// FIX E4 batch-fee reconciliation (LOW security nit): `batch_leg_fee` reconstructs the
// per-leg fee the engine charges for one BatchTradeNoCpi leg, so wrapper-side per-domain fee
// accounting can be split out of the engine's AGGREGATE outcome.fee_a/fee_b. It must compute
// the fee on the same CEIL notional the engine's `trade_fee_notional_ceil` uses (upstream
// engine 8f25aa5d), not the FLOOR notional used for margin/PnL bookkeeping -- the pre-fix bug
// this proof targets used floor notional, which silently reconstructs fee=0 for a sub-atom
// fill that the engine charged a nonzero fee for, tripping the wrapper's aggregate cross-check
// and hard-reverting the whole batch. Bounded to a u16-scale symbolic domain (matching the
// engine's own `proof_v16_trade_fee_notional_ceil_strictly_exceeds_floor_when_unaligned` in
// percolator/tests/proofs_v16_arithmetic.rs) to keep the search space tractable while still
// covering the unaligned/aligned boundary this fix is about.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn kani_batch_leg_fee_uses_ceil_notional_not_floor() {
    let size_raw: u16 = kani::any();
    let price_raw: u16 = kani::any();
    let fee_bps_raw: u16 = kani::any();
    kani::assume((1..=4000).contains(&size_raw));
    kani::assume((1..=4000).contains(&price_raw));
    kani::assume(fee_bps_raw as u64 <= percolator::MAX_MARGIN_BPS);
    let abs_size_q = size_raw as u128;
    let exec_price = price_raw as u64;
    let fee_bps = fee_bps_raw as u64;

    let ceil_fee = percolator_prog::processor::batch_leg_fee(abs_size_q, exec_price, fee_bps)
        .expect("bounded inputs never overflow the fast u128 path");

    // Pre-fix reference: the exact floor-notional computation batch_leg_fee used before this
    // fix (mirrors trade_notional_floor, not trade_fee_notional_ceil).
    let floor_notional = abs_size_q * exec_price as u128 / percolator::POS_SCALE;
    let floor_fee = if floor_notional == 0 || fee_bps == 0 {
        0u128
    } else {
        let product = floor_notional * fee_bps as u128;
        let den = percolator::MAX_MARGIN_BPS as u128;
        (product / den) + u128::from(product % den != 0)
    };

    let product = abs_size_q * exec_price as u128;
    let unaligned_notional = product % percolator::POS_SCALE != 0;

    kani::cover!(
        unaligned_notional && fee_bps > 0,
        "sub-atom-notional leg with a nonzero fee rate: the exact bug class this fix closes"
    );
    kani::cover!(
        !unaligned_notional && fee_bps > 0,
        "POS_SCALE-aligned leg: ceil and floor notional must agree, no spurious fee"
    );

    // The ceil-notional fee must never be less than the (buggy, pre-fix) floor-notional fee --
    // reconciliation can only go up when correcting a rounded-down-to-zero reconstruction,
    // never down, or the aggregate cross-check would start rejecting batches it used to accept.
    // NOTE: this is deliberately NOT asserted as a strict `>` on the unaligned branch -- the
    // bps-share ceil-division composed on top of the notional ceil can absorb the +1-atom
    // notional bump into the same final fee-atom result (e.g. size=5,fee_bps=1 vs size=6,
    // fee_bps=1 at MAX_MARGIN_BPS=10_000 both ceil to fee=1), so strict inequality does not hold
    // universally at the whole-function level even though it always holds at the notional level
    // below. An earlier version of this harness asserted strict inequality here and Kani found
    // the counterexample; the concrete witness beneath it is the non-vacuity check instead.
    assert!(
        ceil_fee >= floor_fee,
        "ceil-notional reconstruction must never under-charge relative to the pre-fix floor \
         computation"
    );
    if !unaligned_notional {
        assert_eq!(
            ceil_fee, floor_fee,
            "POS_SCALE-aligned fills must not be over-charged by the ceil fix"
        );
    }

    // The underlying notional itself (before the bps share is applied) IS always strictly
    // ceil > floor on an unaligned product -- this is the exact property the engine's own
    // `proof_v16_trade_fee_notional_ceil_strictly_exceeds_floor_when_unaligned` proves for
    // `trade_fee_notional_ceil` vs `trade_notional_floor`; batch_leg_fee must compute the same
    // ceil-notional internally.
    let fee_notional =
        (product / percolator::POS_SCALE) + u128::from(product % percolator::POS_SCALE != 0);
    if unaligned_notional {
        assert!(
            fee_notional > floor_notional,
            "unaligned product: the ceil-notional batch_leg_fee computes internally must round \
             up by exactly one atom of notional, matching the engine's trade_fee_notional_ceil"
        );
    } else {
        assert_eq!(fee_notional, floor_notional);
    }

    // Non-vacuity witness at the whole-function (atoms-of-fee) level: a scaled-down analog (the
    // full v16_bpf_batch_trade_nocpi_subatom_leg_charges_fee_on_ceil_notional BPF test in
    // tests/v16_cu.rs uses size=POS_SCALE/100-1=9999, outside this harness's tractable u16-scale
    // symbolic bound) of the exact sub-atom boundary this fix targets -- size=100, price=100
    // gives product=10_000 < POS_SCALE, so floor notional is 0 (fee would silently reconstruct
    // to 0, the exact pre-fix bug) while ceil notional is 1, and with fee_bps=1 the final fee
    // genuinely is strictly greater (0 -> 1). Proves this harness's `ceil_fee >= floor_fee` is
    // not vacuously satisfied by an identity function -- it is sensitive to the actual fix.
    if abs_size_q == 100 && exec_price == 100 && fee_bps == 1 {
        assert_eq!(
            floor_fee, 0,
            "pre-fix reconstruction silently drops this leg's fee to zero"
        );
        assert_eq!(
            ceil_fee, 1,
            "the fix must reconstruct the engine's real ceil-notional fee"
        );
        assert!(ceil_fee > floor_fee);
    }
}

/// Conservation: the four legs sum to exactly the input fee, for EVERY input.
/// This is the invariant `header.insurance` accounting depends on.
///
/// Widths are declared honestly (u16 shares, u128 fee bounded to a realistic
/// range) rather than assumed on wider types -- CBMC bit-blasts by DECLARED
/// width, and an unbounded u128 previously caused a 10h57m non-convergence.
///
/// `fee` is narrowed to u32 (not the brief's original u64): with two
/// symbolic bps operands (creator_bps, lp_bps) each multiplied against
/// `fee` inside u128 `checked_mul`, CBMC bit-blasts the full-width u128
/// multiplier circuit regardless of the symbol's declared bit-width, and
/// the u64 version did not converge inside 11 minutes wall-clock (a single
/// cbmc solve pegged at 100% CPU past the ~10-minute budget). u32 keeps
/// the property meaningful (fee magnitudes here are bps-scaled trade fees,
/// far below u32::MAX) while shrinking the multiplier enough to converge.
#[cfg(kani)]
#[kani::proof]
fn kani_fee_split_conserves() {
    let fee: u32 = kani::any();
    let creator_bps: u16 = kani::any();
    let lp_bps: u16 = kani::any();
    kani::assume(creator_bps <= 8_000);
    kani::assume(lp_bps <= 8_000);
    kani::assume(creator_bps as u32 + lp_bps as u32 <= 8_000);
    let insurance_bps: u16 = 8_000 - creator_bps - lp_bps;

    let parts = percolator_prog::policy_v16::split_trade_fee(
        fee as u128,
        2_000,
        creator_bps,
        lp_bps,
        insurance_bps,
    )
    .unwrap();

    assert!(parts.protocol + parts.creator + parts.lp + parts.insurance == fee as u128);
}

/// No single leg may exceed the whole fee (guards a sign/overflow regression).
#[cfg(kani)]
#[kani::proof]
fn kani_fee_split_no_leg_exceeds_fee() {
    let fee: u64 = kani::any();
    let parts =
        percolator_prog::policy_v16::split_trade_fee(fee as u128, 2_000, 1_600, 4_800, 1_600)
            .unwrap();
    assert!(parts.protocol <= fee as u128);
    assert!(parts.creator <= fee as u128);
    assert!(parts.lp <= fee as u128);
    assert!(parts.insurance <= fee as u128);
}
