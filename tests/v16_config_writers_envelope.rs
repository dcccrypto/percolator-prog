#![cfg(not(kani))]
//! Every writer of the market engine config refuses an invalid config.
//!
//! The hot readers `read_market_config_mode_and_capacity` and `read_engine_funding_bounds`
//! decode the config with `try_to_runtime_shape`, which skips the solvency-envelope check. That
//! is only sound if no path can leave an envelope-violating config in the market header.
//!
//! Writers of `MarketGroupV16HeaderAccount.config` reachable from the program (audit of
//! `src/v16_program.rs` and the engine, 2026-11-14):
//!   1. `state::init_market_account_zero_copy` (InitMarket) -> `new_dynamic` ->
//!      `validate_public_user_fund` (full envelope).
//!   2. `state::activate_dynamic_asset_slot` (slot growth) -> `grow_asset_slot_capacity_not_atomic`
//!      -> shape check on the candidate. Growth only changes `max_market_slots`, which the
//!      envelope does not read, so an envelope-valid config stays envelope-valid.
//!   3. Engine `apply_fee_policy_update_not_atomic`: full envelope, but no program handler calls it.
//! `write_market_wire` / `init_market_account` / `write_market` write a whole config but are
//! `cfg(not(target_os = "solana"))` test helpers, so they are not reachable on chain.

use percolator::{FeePolicyUpdateV16, MarketGroupV16HeaderAccount, V16Config, V16ConfigAccount};
use percolator_prog::{constants, state};

/// Shape-valid, envelope-invalid: 1% maintenance margin against a 100% worst-case price budget.
fn envelope_invalid_config() -> V16Config {
    let mut cfg = V16Config::public_user_fund(1, 0, 10);
    cfg.maintenance_margin_bps = 100;
    cfg.initial_margin_bps = 200;
    cfg.max_price_move_bps_per_slot = 100;
    cfg.max_accrual_dt_slots = 100;
    cfg.min_funding_lifetime_slots = 100;
    cfg
}

fn valid_config(slots: u32) -> V16Config {
    let mut cfg = V16Config::public_user_fund_with_market_slots(1, slots, 0, 10);
    cfg.max_trading_fee_bps = 10_000;
    cfg
}

fn wrapper_config() -> state::WrapperConfigV16 {
    let mut cfg = state::WrapperConfigV16::default();
    cfg.marketauth = [1u8; 32];
    cfg.collateral_mint = [2u8; 32];
    cfg.oracle_mode = constants::ORACLE_MODE_MANUAL;
    cfg.mark_ewma_e6 = 100;
    cfg.mark_ewma_halflife_slots = constants::DEFAULT_MARK_EWMA_HALFLIFE_SLOTS;
    cfg.oracle_target_price_e6 = 100;
    cfg
}

fn header_of(data: &[u8]) -> MarketGroupV16HeaderAccount {
    let off = constants::MARKET_GROUP_OFF;
    let len = core::mem::size_of::<MarketGroupV16HeaderAccount>();
    bytemuck::pod_read_unaligned(&data[off..off + len])
}

#[test]
fn fixture_is_shape_valid_and_envelope_invalid() {
    let cfg = envelope_invalid_config();
    assert!(V16ConfigAccount::from_runtime(&cfg)
        .try_to_runtime_shape()
        .is_ok());
    assert!(cfg.validate_public_user_fund().is_err());
}

/// Writer 1: InitMarket.
#[test]
fn init_market_refuses_envelope_invalid_config() {
    let mut data = vec![0u8; state::market_account_len_for_capacity(1).unwrap()];
    let r = state::init_market_account_zero_copy(
        &mut data,
        &wrapper_config(),
        envelope_invalid_config(),
        [9u8; 32],
        100,
        0,
    );
    assert!(
        r.is_err(),
        "envelope-invalid config must not initialize a market"
    );

    // And the valid config goes through, so the refusal above is about the config.
    let mut ok = vec![0u8; state::market_account_len_for_capacity(1).unwrap()];
    state::init_market_account_zero_copy(
        &mut ok,
        &wrapper_config(),
        valid_config(1),
        [9u8; 32],
        100,
        0,
    )
    .unwrap();
}

/// Writer 2: slot growth refuses out-of-range growth and keeps the full envelope valid.
#[test]
fn slot_growth_refuses_bad_index_and_preserves_envelope() {
    let mut data = vec![0u8; state::market_account_len_for_capacity(3).unwrap()];
    state::init_market_account_zero_copy(
        &mut data,
        &wrapper_config(),
        valid_config(1),
        [9u8; 32],
        100,
        0,
    )
    .unwrap();
    let a = [7u8; 32];
    // asset_index must equal the current max_market_slots (1); 2 skips a slot, 3 is past capacity.
    for bad in [0usize, 2, 3] {
        assert!(
            state::activate_dynamic_asset_slot(&mut data, bad, 1, 100, a, a, a, a).is_err(),
            "asset_index {bad} must be refused"
        );
    }
    let before = header_of(&data).config;
    assert_eq!(before.try_to_runtime().unwrap().max_market_slots, 1);

    state::activate_dynamic_asset_slot(&mut data, 1, 1, 100, a, a, a, a).unwrap();
    let after = header_of(&data).config;
    let rt = after
        .try_to_runtime()
        .expect("grown config still passes the full envelope");
    assert_eq!(rt.max_market_slots, 2);
    // Only max_market_slots moved.
    let mut expect = before.try_to_runtime().unwrap();
    expect.max_market_slots = 2;
    assert_eq!(rt, expect);
}

/// Writer 3: engine fee-policy update (not called by any program handler today).
#[test]
fn fee_policy_update_refuses_envelope_invalid_fees_and_leaves_config_untouched() {
    let mut header =
        MarketGroupV16HeaderAccount::new_dynamic([9u8; 32], valid_config(1), 1, 0).unwrap();
    let before = header.config;
    // 100% liquidation fee: shape-valid, but the envelope cannot absorb it.
    let bad = FeePolicyUpdateV16 {
        max_trading_fee_bps: 10_000,
        liquidation_fee_bps: 10_000,
        liquidation_fee_cap: 0,
        min_liquidation_abs: 0,
    };
    let mut probe = valid_config(1);
    probe.liquidation_fee_bps = bad.liquidation_fee_bps;
    probe.liquidation_fee_cap = bad.liquidation_fee_cap;
    assert!(
        probe.try_to_runtime_shape_probe_ok(),
        "fixture must be shape-valid"
    );
    assert!(
        probe.validate_public_user_fund().is_err(),
        "fixture must break the envelope"
    );
    assert!(header.apply_fee_policy_update_not_atomic(bad).is_err());
    assert_eq!(
        header.config, before,
        "rejected update leaves the config byte-unchanged"
    );
}

trait ShapeProbe {
    fn try_to_runtime_shape_probe_ok(&self) -> bool;
}
impl ShapeProbe for V16Config {
    fn try_to_runtime_shape_probe_ok(&self) -> bool {
        V16ConfigAccount::from_runtime(self)
            .try_to_runtime_shape()
            .is_ok()
    }
}
