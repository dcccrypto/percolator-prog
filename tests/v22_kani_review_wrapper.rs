//! Kani review 2026-10-14 (wrapper lane): strengthened / de-vacuumed companions of existing wrapper
//! harnesses. The originals are unchanged. Lane file: ~/wt-v22-kanirev/review/wrapper.md.
//!
//! Run (serialized runner):
//!   python3 -I ~/wt-v22-kanirev/tools/kh.py <prog> <harness> <s> <logdir> --tests --features devnet \
//!     -Z function-contracts -Z stubbing
//!
//! Every harness here carries `kani::cover!` on the asserted path; SUCCESSFUL counts only with every
//! cover satisfied.
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use percolator_prog::bond_v20::bond_coupon_split;
use percolator_prog::ix::Instruction;
use percolator_prog::p4_rescue_ins as p4;
use percolator_prog::policy_v16;

// ═══════════════════════════════ W-D-1 on ADMITTED inputs (rescue no dilution) ═══════════════════════
//
// `kani_v22_wd1_rescue_no_dilution` runs at u16 and assumes the impaired SHAPE, because admission needs
// `x >= RESCUE_MIN_ATOMS = 1e8` which no u16 reaches: its box contains NO admitted rescue, so it says
// nothing about the admitted path by itself (the bridge W-D-3 is proven at x < 2^34, a disjoint box).
// These harnesses put the box ON the admitted region: every operand is a large base plus a small
// symbolic offset, admission is ASSUMED on the REAL `rescue_admitted` (not a shape), and the REAL
// `rescue_shares` / `rescue_claim_delta` / predicates run. BOUNDED (offset box, stated per harness);
// the cover `admitted` proves the box is non-empty.

/// Admitted box, small share count: x = 1e8 + dx*2^16, v = 2e7 + dv*2^12, c = v + 1 + dc*2^17,
/// s in 1..=255 (dx, dv, dc: u8). Every point of the box satisfies the admission arithmetic
/// (x <= 1.17e8 <= 10 v; c <= v + 3.4e7 <= 20 v), and the assume is the real predicate anyway.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_rev_wd1_admitted_box_small_s() {
    let x = p4::RESCUE_MIN_ATOMS + ((kani::any::<u8>() as u128) << 16);
    let v = 20_000_000u128 + ((kani::any::<u8>() as u128) << 12);
    let c = v + 1 + ((kani::any::<u8>() as u128) << 17);
    let s = kani::any::<u8>() as u128;
    kani::assume(p4::rescue_admitted(x, v, c, s).is_ok()); // the REAL admission (not a shape)
    kani::cover!(true, "admitted rescue in the box");
    let m = p4::rescue_shares(x, s, v).unwrap();
    let dc = p4::rescue_claim_delta(m, c, s).unwrap();
    assert!(p4::rescue_value_no_dilution(v, x, s, m));
    assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
    assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
    kani::cover!(m * c > x * s, "strictly cheaper than par");
    kani::cover!(m > 0 && dc > 0, "shares minted, claim grows");
}

/// Admitted box, realistic share count: s = 1e9 + ds*2^20 (ds: u8), others as above.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_rev_wd1_admitted_box_large_s() {
    let x = p4::RESCUE_MIN_ATOMS + ((kani::any::<u8>() as u128) << 16);
    let v = 20_000_000u128 + ((kani::any::<u8>() as u128) << 12);
    let c = v + 1 + ((kani::any::<u8>() as u128) << 17);
    let s = 1_000_000_000u128 + ((kani::any::<u8>() as u128) << 20);
    kani::assume(p4::rescue_admitted(x, v, c, s).is_ok());
    kani::cover!(true, "admitted rescue in the box");
    let m = p4::rescue_shares(x, s, v).unwrap();
    let dc = p4::rescue_claim_delta(m, c, s).unwrap();
    assert!(p4::rescue_value_no_dilution(v, x, s, m));
    assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
    assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
    kani::cover!(m * c > x * s, "strictly cheaper than par");
    kani::cover!(m > 0 && dc > 0, "shares minted, claim grows");
}

// ═══════════════════════════════ W-C-12 at u32 (cheap mutant target) ═════════════════════════════════

/// `bond_coupon_split` on u32 operands. Same assertions as W-C-12 (u64, PASS in 5291 s): a cheap
/// target so the coupon-cap mutants (BOND-MP4, BOND-MP8) can be run; the W-C-8a split stubs this
/// function with its model, so it cannot see those mutants itself.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_rev_wc12_bond_coupon_split_u32() {
    let avail = kani::any::<u32>() as u128;
    let due = kani::any::<u32>() as u128;
    let (cp, rest) = bond_coupon_split(avail, due);
    assert_eq!(cp + rest, avail);
    let cap = avail / 2;
    assert_eq!(cp, if due < cap { due } else { cap });
    kani::cover!(due < avail / 2 && cp == due && due > 0, "due binds");
    kani::cover!(due > avail / 2 && cp == avail / 2 && avail > 1, "cap binds");
}

// ═══════════════════════════════ premium funding at production width ═════════════════════════════════
//
// `kani_v16_premium_funding_rate_is_clamped_and_signed` (PASS_NOCOVER) takes mark, index in 1..=65_536
// (u16 + 1). It is not vacuous (unwrap + an unconditional clamp assert + an exhaustive if/else), but its
// STRICT sign claim `mark > index => rate > 0` only holds because index_e6 <= 65_536 < 1e9: at production
// width a premium below 1e-9 of the index floors to 0. These harnesses state the property that holds at
// u32 width (index up to $4.29k) and witness the strict claim's counterexample.

/// u32 mark/index/cap: clamp, WEAK sign (never the wrong sign), zero iff no premium or no cap.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_rev_premium_funding_u32_clamp_and_weak_sign() {
    let mark = kani::any::<u32>() as u64;
    let index = kani::any::<u32>() as u64;
    let cap = kani::any::<u32>() as u64;
    let rate = policy_v16::premium_funding_rate_e9(mark, index, cap).unwrap();
    assert!(rate.unsigned_abs() <= cap as u128, "clamped");
    if cap == 0 || mark == 0 || index == 0 || mark == index {
        assert_eq!(rate, 0);
    } else if mark > index {
        assert!(rate >= 0, "longs pay when mark > index (never the wrong sign)");
    } else {
        assert!(rate <= 0, "shorts pay when mark < index (never the wrong sign)");
    }
    kani::cover!(rate > 0, "positive");
    kani::cover!(rate < 0, "negative");
    kani::cover!(cap > 0 && rate == cap as i128, "clamped at the cap");
    kani::cover!(cap > 0 && mark > index && rate == 0, "sub-1e-9 premium floors to zero (strict sign fails)");
}

/// Witness: the original's strict claim `mark > index => rate > 0` is FALSE at production width.
/// Concrete: index $2,000.000000, mark one micro above, cap 1e6 e9/slot: rate == 0.
#[kani::proof]
fn kani_rev_premium_funding_strict_sign_counterexample() {
    let r = policy_v16::premium_funding_rate_e9(2_000_000_001, 2_000_000_000, 1_000_000);
    assert_eq!(r, Some(0));
    kani::cover!(r == Some(0), "reached");
}

// ═══════════════════════════════ trailing-byte rejection, differential ═══════════════════════════════
//
// `assert_rejects_trailing_byte` only asserts `decode(encode(ix) ++ [b]).is_err()`: a decoder that
// rejects EVERYTHING passes it. The differential form also asserts the untruncated encoding decodes.

fn rejects_trailing_byte_diff(ix: Instruction, extra: u8) {
    let mut data = ix.encode();
    let ok = Instruction::decode(&data);
    assert!(ok.is_ok(), "the exact encoding decodes");
    core::mem::forget(ok);
    data.push(extra);
    assert!(Instruction::decode(&data).is_err(), "one trailing byte is rejected");
}

#[kani::proof]
fn kani_rev_custody_payloads_reject_trailing_byte_differential() {
    let extra: u8 = kani::any();
    rejects_trailing_byte_diff(Instruction::InitPortfolio, extra);
    rejects_trailing_byte_diff(Instruction::Deposit { portfolio_id: 1, expected_sequence: 0, amount: 1 }, extra);
    rejects_trailing_byte_diff(Instruction::Withdraw { portfolio_id: 1, expected_sequence: 0, amount: 1 }, extra);
    rejects_trailing_byte_diff(
        Instruction::TopUpInsurance { market_id: 1, intent_id: 1, amount: 1, authority_epoch: 1 },
        extra,
    );
    rejects_trailing_byte_diff(
        Instruction::TopUpBackingBucket {
            market_id: 1,
            intent_id: 1,
            domain: 1,
            amount: 1,
            expiry_slot: 10,
            authority_epoch: 1,
        },
        extra,
    );
    rejects_trailing_byte_diff(
        Instruction::WithdrawBackingBucket { market_id: 1, domain: 1, amount: 1, authority_epoch: 1 },
        extra,
    );
    rejects_trailing_byte_diff(Instruction::WithdrawInsurance { amount: 1 }, extra);
    rejects_trailing_byte_diff(
        Instruction::WithdrawInsuranceAsset { market_id: 1, asset_index: 0, amount: 1, authority_epoch: 1 },
        extra,
    );
    rejects_trailing_byte_diff(Instruction::SwapSecondaryForPrimary { amount: 1, authority_epoch: 1 }, extra);
    kani::cover!(extra == 0xff, "asserted path reached");
}

/// `kani_v16_decode_rejects_trailing_bytes` (`[1, extra]` is_err) with the differential half:
/// `[1]` (InitPortfolio, zero payload) decodes.
#[kani::proof]
fn kani_rev_decode_rejects_trailing_bytes_differential() {
    let extra: u8 = kani::any();
    assert!(matches!(Instruction::decode(&[1u8]), Ok(Instruction::InitPortfolio)));
    assert!(Instruction::decode(&[1u8, extra]).is_err());
    kani::cover!(extra != 0, "asserted path reached");
}

// ═══════════════════════════════ decode round trip, with a cover (representative) ════════════════════

/// `kani_v16_top_up_insurance_decode_preserves_wire_fields` with a cover on the asserted arm
/// (hand-built bytes, so it pins the wire offsets, not only encode/decode symmetry).
#[kani::proof]
fn kani_rev_top_up_insurance_decode_with_cover() {
    let market_id: u64 = kani::any();
    let intent_id: u64 = kani::any();
    let authority_epoch: u64 = kani::any();
    let amount: u128 = kani::any();
    let mut data = [0u8; 41];
    data[0] = 9;
    data[1..9].copy_from_slice(&market_id.to_le_bytes());
    data[9..17].copy_from_slice(&intent_id.to_le_bytes());
    data[17..25].copy_from_slice(&authority_epoch.to_le_bytes());
    data[25..41].copy_from_slice(&amount.to_le_bytes());
    match Instruction::decode(&data).unwrap() {
        Instruction::TopUpInsurance { market_id: a, intent_id: b, amount: c, authority_epoch: d } => {
            assert_eq!(a, market_id);
            assert_eq!(b, intent_id);
            assert_eq!(c, amount);
            assert_eq!(d, authority_epoch);
            kani::cover!(amount > u64::MAX as u128 && market_id != intent_id, "high amount bytes, distinct ids");
        }
        _ => unreachable!(),
    }
}

/// `kani_v16_update_liquidation_fee_policy_decode_preserves_wire_fields` with a cover.
#[kani::proof]
fn kani_rev_update_liquidation_fee_policy_decode_with_cover() {
    let cranker_share_bps: u16 = kani::any();
    let policy_sequence: u64 = kani::any();
    let mut data = [0u8; 11];
    data[0] = 37;
    data[1..3].copy_from_slice(&cranker_share_bps.to_le_bytes());
    data[3..11].copy_from_slice(&policy_sequence.to_le_bytes());
    match Instruction::decode(&data).unwrap() {
        Instruction::UpdateLiquidationFeePolicy { cranker_share_bps: got, policy_sequence: got_seq } => {
            assert_eq!(got, cranker_share_bps);
            assert_eq!(got_seq, policy_sequence);
            kani::cover!(got > 255 && got_seq > u32::MAX as u64, "high bytes decoded");
        }
        _ => unreachable!(),
    }
}

// ═══════════════════════════════ W-D-11 epoch room, STUB-MEMO bps_floor ══════════════════════════════
//
// `kani_v22_wd11_epoch_room` (NO-VERDICT 8004 s, cadical) compares `g9_epoch_room(base, drawn, cap)`
// with `drawn + room <= max(drawn, bps_floor(base, cap))`: the property only needs `bps_floor` to be
// DETERMINISTIC (the room is computed from the same `bps_floor(base, cap)` the harness reads), not its
// value. STUB-MEMO (as in tests/v22_kani_overnight_wrapper.rs): `None` iff `bps > 10_000` (the exact
// production None-condition), otherwise an arbitrary value, consistent for repeated arguments. A pure
// function is one of the behaviours of the stub, so the proof covers the real `bps_floor`. FULL u128.

static mut WD11_USED: [bool; 2] = [false; 2];
static mut WD11_X: [u128; 2] = [0; 2];
static mut WD11_B: [u16; 2] = [0; 2];
static mut WD11_V: [u128; 2] = [0; 2];
#[allow(static_mut_refs)]
fn bps_floor_memo2(x: u128, bps: u16) -> Option<u128> {
    if bps as u128 > 10_000 {
        return None;
    }
    unsafe {
        let mut i = 0;
        while i < 2 {
            if WD11_USED[i] && WD11_X[i] == x && WD11_B[i] == bps {
                return Some(WD11_V[i]);
            }
            i += 1;
        }
        let v: u128 = kani::any();
        let mut j = 0;
        while j < 2 {
            if !WD11_USED[j] {
                WD11_USED[j] = true;
                WD11_X[j] = x;
                WD11_B[j] = bps;
                WD11_V[j] = v;
                break;
            }
            j += 1;
        }
        Some(v)
    }
}

#[allow(unused_imports)]
use percolator_prog::vault_lp_v18::bps_floor as _wd11_t;

#[kani::proof]
#[kani::unwind(3)]
#[kani::stub(percolator_prog::vault_lp_v18::bps_floor, bps_floor_memo2)]
fn kani_rev_wd11_epoch_room_memo() {
    let base: u128 = kani::any();
    let drawn: u128 = kani::any();
    let cap: u16 = kani::any();
    kani::assume(cap <= 10_000); // the original's assume
    let room = p4::g9_epoch_room(base, drawn, cap);
    let lim = percolator_prog::vault_lp_v18::bps_floor(base, cap).unwrap();
    assert!(drawn.checked_add(room).is_some_and(|t| t <= core::cmp::max(drawn, lim)));
    kani::cover!(room > 0, "room left");
    kani::cover!(room == 0 && drawn > 0, "epoch exhausted");
}

// ═══════════════════════════════ negative control for the W-C-5 algebra (w32) ════════════════════════

/// NC for `kani_v22_wc5_split_b_no_dilution_algebra_u8_w32`: a CEIL-rounded mint (`m * value < amount * b
/// + value`) must dilute incumbents somewhere. Expected: FAIL (the overnight u16 NC was never run).
#[kani::proof]
#[kani::solver(kissat)]
fn negctrl_rev_wc5_ceil_mint_dilutes_w32() {
    let amount = kani::any::<u8>() as u32;
    let b = kani::any::<u8>() as u32;
    let value = kani::any::<u8>() as u32;
    let m = kani::any::<u16>() as u32;
    kani::assume(amount > 0 && b > 0 && value > 0);
    kani::assume(m * value < amount * b + value); // MUTANT: ceil instead of floor
    assert!((value + amount) * b >= value * (b + m));
}

/// Reachability witness for the ADMITTED rescue path at full u32 widths (no property: the two
/// admitted-box property harnesses above have NO VERDICT at 900 s). Shows that `rescue_admitted Ok`
/// is satisfiable and reaches the mint/claim computation with m > 0, dc > 0, strictly below par.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_rev_wd1_admitted_reach_u32() {
    let x = kani::any::<u32>() as u128;
    let v = kani::any::<u32>() as u128;
    let c = kani::any::<u32>() as u128;
    let s = kani::any::<u32>() as u128;
    kani::assume(p4::rescue_admitted(x, v, c, s).is_ok());
    let m = p4::rescue_shares(x, s, v);
    let dc = m.and_then(|m| p4::rescue_claim_delta(m, c, s));
    kani::cover!(m.is_some_and(|m| m > 0) && dc.is_some_and(|d| d > 0), "admitted rescue mints and grows the claim");
}
