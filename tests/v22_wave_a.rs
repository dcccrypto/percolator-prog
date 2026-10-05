//! v2.2 Phase 4 Wave A (`~/percolator-ops/ledger/phase4-design-2026-10-05.md` items 7 + 8).
//!
//! * Item 7, lot precision: the lot exponent, the 10^7 e6 precision floor at every growth
//!   (re-)anchor, the 1 bps tick after a 99.9% fall (the real spec §1.7 cap function), and the
//!   immutability of the lot exponent through oracle reconfiguration.
//! * Item 8 wire / pure rules (the R3-M1 replays live in `earn_drain_replay.rs`, next to the
//!   reviewer's `r2_market`).
//! * Full-width proptests of every pure rule (the Kani design pairs each with a bounded
//!   harness on the same production function).
#![cfg(not(kani))]
#![allow(dead_code)]
mod indep_harness;

use indep_harness::*;
use percolator_prog::{
    constants::{
        LOT_EXP_MAX, LOT_PRICE_FLOOR_E6, P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT, PROFILE_LOT_EXP_IDX,
        PROFILE_P4_FLAGS_IDX, REDEMPTION_REFRESH_MAX,
    },
    ix::Instruction as ProgInstruction,
    oracle_v16::clamp_toward_engine_dt,
    state,
    wave_a_v22::{self, ExitGate},
};
use proptest::prelude::*;
use solana_sdk::{
    instruction::AccountMeta,
    signature::Signer,
};

const ERR_LOT: u32 = 119;

// ─────────────────────────────── item 7: pure ───────────────────────────────────────────────

/// "A 99.9% fall still leaves a 1 bps tick": the precision floor 10^7 e6 per lot, down 99.9%,
/// is 10^4 -- where one e6 unit IS one basis point, and the spec §1.7 per-slot cap
/// `floor(P·cap·dt/10^4)` moves the effective price by >= 1 for every cap >= 1 bps, dt >= 1.
/// NEGATIVE CONTROL (in the same test): one unit below, at 9,999, a 1 bps cap cannot move at
/// all (max_delta = 0: spec CatchupRequired) -- the floor is exactly where it must be.
#[test]
fn lot_floor_999_permille_fall_keeps_a_1bps_tick() {
    let crashed = LOT_PRICE_FLOOR_E6 / 1_000; // 99.9% below the floor
    assert_eq!(crashed, 10_000);
    // Up and down, the real clamp moves exactly 1 unit = 1 bps of the price.
    assert_eq!(clamp_toward_engine_dt(crashed, crashed + 500, 1, 1), crashed + 1);
    assert_eq!(clamp_toward_engine_dt(crashed, crashed - 500, 1, 1), crashed - 1);
    // 1 unit at 10^4 is exactly 1 bps (10^4 bps per unit of relative move / 10^4 units).
    assert_eq!(10_000u64 / crashed, 1);
    // Below 10^4 the cap floors to 0: untrackable (the reason for the floor).
    assert_eq!(clamp_toward_engine_dt(crashed - 1, crashed + 500, 1, 1), crashed - 1);
    // Without lot pricing a $0.00001 token marks at 10 e6: 10% tick, cap 0 at any bps < 1,000.
    assert_eq!(clamp_toward_engine_dt(10, 20, 999, 1), 10);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4_096, .. ProptestConfig::default() })]
    /// I-P2 at full u64 width on the production clamp: for every p_last >= 10^4 (the floor
    /// after a 99.9% fall), cap >= 1 bps, dt >= 1 and target != p_last, the effective price
    /// moves by at least 1 toward the target and never overshoots it.
    #[test]
    fn i_p2_progress_at_and_above_the_crashed_floor_full_width(
        p in 10_000u64..=u64::MAX,
        target in 1u64..=u64::MAX,
        cap in 1u64..=u64::MAX,
        dt in 1u64..=u64::MAX,
    ) {
        prop_assume!(target != p);
        let next = clamp_toward_engine_dt(p, target, cap, dt);
        prop_assert!(next != p, "no progress: p {p} target {target} cap {cap} dt {dt}");
        if target > p {
            prop_assert!(next > p && next <= target);
        } else {
            prop_assert!(next < p && next >= target);
        }
    }

    /// The precision-floor predicate at full width: refused iff growth and below 10^7.
    #[test]
    fn lot_floor_predicate_full_width(growth in any::<bool>(), mark in any::<u64>()) {
        prop_assert_eq!(
            wave_a_v22::lot_price_below_floor(growth, mark),
            growth && mark < 10_000_000
        );
    }

    /// Profile bytes +19..+24 at full width: the validator accepts exactly
    /// {lot <= 15, lot != 0 only in Manual/AuthMark, p4 flags within the known mask, rest 0}.
    #[test]
    fn profile_lot_and_p4_shape_full_width(pad in any::<[u8; 5]>(), mode in 0u8..4) {
        let mut p: state::AssetOracleProfileV16 = bytemuck::Zeroable::zeroed();
        p.oracle_mode = mode;
        p._padding0 = pad;
        let lot = pad[PROFILE_LOT_EXP_IDX];
        let expect = lot <= LOT_EXP_MAX
            && (lot == 0 || mode == 0 || mode == 3)
            && pad[PROFILE_P4_FLAGS_IDX] & !P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT == 0
            && pad[2..] == [0, 0, 0];
        prop_assert_eq!(state::profile_lot_and_p4_bytes_ok(&p), expect);
    }

    /// Reconfiguration carries lot and p4 bytes exactly, and refuses a lot on Hybrid / EWMA.
    #[test]
    fn carried_padding_full_width(lot in 0u8..=LOT_EXP_MAX, flags in any::<bool>(), new_mode in 0u8..4) {
        let mut p: state::AssetOracleProfileV16 = bytemuck::Zeroable::zeroed();
        p.oracle_mode = 3;
        p._padding0[PROFILE_LOT_EXP_IDX] = lot;
        p._padding0[PROFILE_P4_FLAGS_IDX] = if flags { P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT } else { 0 };
        let r = state::carried_profile_padding0(&p, new_mode);
        if lot != 0 && (new_mode == 1 || new_mode == 2) {
            prop_assert!(r.is_err());
        } else {
            prop_assert_eq!(r.unwrap(), p._padding0);
        }
    }
}

// ─────────────────────────────── item 8: pure ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 4_096, .. ProptestConfig::default() })]
    /// I-X1 at full width: the effective floor is the max of wire and stored floors, and a
    /// payout meets it iff atoms >= floor (u128 atoms against a u64 floor, no truncation).
    #[test]
    fn i_x1_min_payout_full_width(atoms in any::<u128>(), wire in any::<u64>(), stored in any::<u64>()) {
        let m = wave_a_v22::effective_min_payout(wire, stored);
        prop_assert!(m >= wire && m >= stored && (m == wire || m == stored));
        prop_assert_eq!(wave_a_v22::payout_meets_min(atoms, m), atoms >= m as u128);
    }

    /// Rule 3 at full width: loss-current iff all four counters are zero.
    #[test]
    fn loss_current_full_width(a in any::<u64>(), b in any::<u64>(), c in any::<u64>(), d in any::<u64>()) {
        prop_assert_eq!(wave_a_v22::loss_current(a, b, c, d), a == 0 && b == 0 && c == 0 && d == 0);
    }
}

/// I-X2 / I-X4, exhaustive over all 32 inputs: an unsigned Live non-bound exit happens only
/// with keeper_ok and is then ALWAYS loss-gated; a signed one is gated iff the market says so;
/// bound / Resolved exits are untouched.
#[test]
fn exit_gate_exhaustive() {
    for bits in 0u8..32 {
        let (bound, live, signed, keeper_ok, requires) =
            (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0, bits & 16 != 0);
        let g = wave_a_v22::exit_gate(bound, live, signed, keeper_ok, requires);
        let expect = if bound || !live {
            ExitGate::Allow { require_loss_current: false }
        } else if signed {
            ExitGate::Allow { require_loss_current: requires }
        } else if keeper_ok {
            ExitGate::Allow { require_loss_current: true }
        } else {
            ExitGate::NeedsRedeemerSignature
        };
        assert_eq!(g, expect, "bits {bits:05b}");
        // I-X4: unsigned execution => keeper_ok ∧ loss-gated
        if !bound && live && !signed {
            if let ExitGate::Allow { require_loss_current } = g {
                assert!(keeper_ok && require_loss_current);
            }
        }
    }
}

// ─────────────────────────────── wire ───────────────────────────────────────────────────────

fn base_init(price: u64) -> ProgInstruction {
    ProgInstruction::InitMarket {
        max_portfolio_assets: 1,
        h_min: 0,
        h_max: 10,
        initial_price: price,
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 20,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: 100,
        liquidation_fee_cap: 1_000_000_000_000_000,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 4,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 1,
        min_funding_lifetime_slots: 1,
        max_account_b_settlement_chunks: 1,
        max_bankrupt_close_chunks: 1,
        max_bankrupt_close_lifetime_slots: 100,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    }
}

fn growth_init(price: u64, lot_exp: Option<u8>) -> ProgInstruction {
    match lot_exp {
        None => ProgInstruction::InitMarketV19 {
            market: Box::new(base_init(price)),
            growth_r_gap_bps: 400,
            growth_l_launch_x100: 1_000,
        },
        Some(l) => ProgInstruction::InitMarketLotV22 {
            market: Box::new(base_init(price)),
            growth_r_gap_bps: 400,
            growth_l_launch_x100: 1_000,
            lot_exp: l,
        },
    }
}

#[test]
fn wave_a_wire_round_trips_and_canonical_forms() {
    // InitMarket: 4-byte growth trailer stays V19, 5-byte is the lot form, lot 0 refused.
    for ix in [growth_init(LOT_PRICE_FLOOR_E6, None), growth_init(LOT_PRICE_FLOOR_E6, Some(6))] {
        let b = ix.encode();
        assert_eq!(ProgInstruction::decode(&b).unwrap(), ix);
    }
    let mut zero = growth_init(LOT_PRICE_FLOOR_E6, Some(6)).encode();
    *zero.last_mut().unwrap() = 0;
    assert!(ProgInstruction::decode(&zero).is_err(), "non-canonical lot 0");
    // 76: legacy 17 B; v2.2 26 B; keeper_ok 2 and the all-zero trailer refused.
    let legacy76 = ProgInstruction::RequestRedeemLpShares { shares: 7 }.encode();
    assert_eq!(legacy76.len(), 17);
    let v76 = ProgInstruction::RequestRedeemLpSharesV22 { shares: 7, min_payout_atoms: 9, keeper_ok: 1 };
    assert_eq!(v76.encode().len(), 26);
    assert_eq!(ProgInstruction::decode(&v76.encode()).unwrap(), v76);
    let mut bad = v76.encode();
    *bad.last_mut().unwrap() = 2;
    assert!(ProgInstruction::decode(&bad).is_err());
    let z76 = ProgInstruction::RequestRedeemLpSharesV22 { shares: 7, min_payout_atoms: 0, keeper_ok: 0 };
    assert!(ProgInstruction::decode(&z76.encode()).is_err());
    // 77: legacy 3 B; v2.2 12 B; n_refresh 9 and the all-zero trailer refused.
    assert_eq!(ProgInstruction::ExecuteRedemption { domain: 1 }.encode().len(), 3);
    for n in 0..=REDEMPTION_REFRESH_MAX {
        let v77 = ProgInstruction::ExecuteRedemptionV22 { domain: 1, min_payout_atoms: 5, n_refresh: n };
        assert_eq!(v77.encode().len(), 12);
        assert_eq!(ProgInstruction::decode(&v77.encode()).unwrap(), v77);
    }
    let over = ProgInstruction::ExecuteRedemptionV22 { domain: 1, min_payout_atoms: 5, n_refresh: REDEMPTION_REFRESH_MAX + 1 };
    assert!(ProgInstruction::decode(&over.encode()).is_err());
    let z77 = ProgInstruction::ExecuteRedemptionV22 { domain: 1, min_payout_atoms: 0, n_refresh: 0 };
    assert!(ProgInstruction::decode(&z77.encode()).is_err());
}

// ─────────────────────────────── item 7: on-chain (LiteSVM) ─────────────────────────────────

/// A fresh market account in a harness env, initialised with `ix`. Leaves `env.market`
/// pointing at it on success so the harness helpers (ConfigureAuthMark etc.) target it.
fn init_on_fresh(env: &mut V16CuEnv, ix: ProgInstruction) -> Result<u64, String> {
    let m = env.program_account(state::market_account_len_for_capacity(1).unwrap());
    let admin = env.admin.insecure_clone();
    let mint = env.mint;
    let r = env.send(
        ix,
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(m, false),
            AccountMeta::new_readonly(mint, false),
        ],
        &[&admin],
    );
    if r.is_ok() {
        env.market = m;
    }
    r
}

fn profile0(env: &V16CuEnv) -> state::AssetOracleProfileV16 {
    state::read_asset_oracle_profile(&env.svm.get_account(&env.market).unwrap().data, 0).unwrap()
}

fn code(r: &Result<u64, String>) -> Option<u32> {
    r.as_ref().err().and_then(|e| custom_code(e))
}

/// "A mark below 1e7 is refused": InitMarket on a growth market (both growth forms) refuses
/// an initial per-lot mark of 10^7 - 1 with Custom(119) and accepts 10^7. NEGATIVE CONTROL:
/// a legacy (non-growth) market keeps the legacy rule and still opens at 10^6.
#[test]
fn init_growth_market_below_precision_floor_is_refused() {
    let mut env = V16CuEnv::new();
    for lot in [None, Some(6u8)] {
        let r = init_on_fresh(&mut env, growth_init(LOT_PRICE_FLOOR_E6 - 1, lot));
        assert_eq!(code(&r), Some(ERR_LOT), "lot {lot:?}: {r:?}");
        init_on_fresh(&mut env, growth_init(LOT_PRICE_FLOOR_E6, lot)).expect("at the floor");
    }
    init_on_fresh(&mut env, base_init(1_000_000)).expect("legacy market below the floor");
    assert_eq!(state::profile_lot_exp(&profile0(&env)), 0);
}

/// The lot exponent is written once at InitMarket (profile +19), bounded at 15, and every new
/// market carries EXIT_REQUIRES_LOSS_CURRENT (profile +20 bit2).
#[test]
fn init_lot_market_records_lot_exp_and_p4_default() {
    let mut env = V16CuEnv::new();
    let r = init_on_fresh(&mut env, growth_init(LOT_PRICE_FLOOR_E6, Some(LOT_EXP_MAX + 1)));
    assert_eq!(code(&r), Some(ERR_LOT), "{r:?}");
    init_on_fresh(&mut env, growth_init(50_000_000, Some(LOT_EXP_MAX))).expect("lot 15");
    let p = profile0(&env);
    assert_eq!(state::profile_lot_exp(&p), LOT_EXP_MAX);
    assert_eq!(state::profile_p4_flags(&p), P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT);
}

/// I-P1: the lot exponent survives ConfigureAuthMark; a Hybrid / EWMA reconfiguration (modes
/// that cannot carry a lot) is refused with 119 instead of silently clearing it; and a growth
/// re-anchor below the floor is refused (the creator cannot launch at the floor and re-anchor
/// to an untrackable mark). NEGATIVE CONTROL: the same EWMA reconfiguration on a lot-0 market
/// succeeds.
#[test]
fn lot_exp_is_immutable_and_the_floor_binds_every_reanchor() {
    let mut env = V16CuEnv::new();
    init_on_fresh(&mut env, growth_init(20_000_000, Some(6))).expect("lot 6 market");
    env.svm.warp_to_slot(2);
    env.configure_auth_mark_for_asset_as_admin(0, 2, 30_000_000);
    let p = profile0(&env);
    assert_eq!(p.oracle_mode, 3, "AuthMark");
    assert_eq!(state::profile_lot_exp(&p), 6, "kept by ConfigureAuthMark");
    assert_eq!(state::profile_p4_flags(&p), P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT, "p4 kept");
    // re-anchor below the floor on a growth market
    let seq = env.control_sequences(0).oracle_observation + 1;
    let admin = env.admin.insecure_clone();
    let market = env.market;
    let below = env.send(
        ProgInstruction::ConfigureAuthMark {
            asset_index: 0,
            market_id: 1,
            now_slot: 2,
            initial_mark_e6: LOT_PRICE_FLOOR_E6 - 1,
            observation_sequence: seq,
        },
        vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)],
        &[&admin],
    );
    assert_eq!(code(&below), Some(ERR_LOT), "{below:?}");
    // EWMA cannot carry a lot exponent
    let seq = env.control_sequences(0).oracle_observation + 1;
    let ewma = env.send(
        ProgInstruction::ConfigureEwmaMark {
            market_id: 1,
            asset_index: 0,
            now_slot: 2,
            initial_mark_e6: 30_000_000,
            mark_ewma_halflife_slots: 10,
            mark_min_fee: 0,
            observation_sequence: seq,
        },
        vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)],
        &[&admin],
    );
    assert_eq!(code(&ewma), Some(ERR_LOT), "{ewma:?}");
    assert_eq!(state::profile_lot_exp(&profile0(&env)), 6, "still 6");
    // negative control: lot-0 growth market may move to EWMA
    init_on_fresh(&mut env, growth_init(20_000_000, None)).expect("lot 0 market");
    env.configure_ewma_mark_with_cu(2, 30_000_000, 10, 0);
    assert_eq!(profile0(&env).oracle_mode, 2);
}
