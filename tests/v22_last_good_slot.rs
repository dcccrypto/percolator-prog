#![cfg(not(kani))]
//! Which `last_good_oracle_slot` does a PushAuthMark advance, and which one gates resolve?
//!
//! Liveness question for the off-chain takeover pusher (keeper job K-BUG-PUSHERROLEASSETGAP),
//! which watches only `cfg.last_good_oracle_slot` (account offset 16 + 152). Real instructions
//! through the BPF program on a two-asset market; nothing is poked.
//!
//! Run: INDEP_WRAPPER_SO=<built percolator_prog.so> INDEP_MATCHER_SO=<any matcher .so> \
//!      cargo test --release -j 4 --test v22_last_good_slot
//!
//! ANSWERS (pinned below):
//!  1. PushAuthMark asset 0 advances BOTH `cfg.last_good_oracle_slot` and asset 0's profile slot.
//!     PushAuthMark asset 1 advances ONLY asset 1's profile slot; cfg is untouched.
//!  2. `ResolveStalePermissionless` takes no asset index and tests ONLY the cfg clock
//!     (`permissionless_stale_matured`). While asset 0 keeps being pushed it is refused
//!     (OracleStale) even if asset 1 has been stale far longer than
//!     `permissionless_resolve_stale_slots`. The per-asset profile clock
//!     (`global_or_profile_resolve_matured_at_slot`) only gates trades on that asset (OracleStale):
//!     asset 1 becomes untradeable, NOT resolvable. Resolution needs the cfg (asset 0) clock to
//!     go stale too. So a pusher watching only cfg misses a stale asset 1 (it is not a resolve
//!     risk, but asset 1 trading is frozen until someone pushes asset 1).
//!  3. Layout: cfg field at struct offset 152 (account offset 16 + 152).
use percolator_prog::{ix::Instruction as ProgInstruction, state};
use solana_sdk::{instruction::AccountMeta, signature::Keypair};
use std::mem::offset_of;

mod indep_harness;
use indep_harness::*;

const PX: u64 = 1_000_000;
const STALE: u64 = 200;
const HEADER_LEN: usize = 16;
/// Struct-relative offset of `AssetOracleProfileV16.last_good_oracle_slot`.
const PROFILE_LGS_OFF: usize = 216;

fn world() -> V16CuEnv {
    let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams {
        max_portfolio_assets: 2,
        h_max: 50,
        initial_price: PX,
        min_nonzero_mm_req: 599,
        min_nonzero_im_req: 600,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        max_price_move_bps_per_slot: 20,
        max_accrual_dt_slots: 20,
        max_trading_fee_bps: 1_000,
        max_bankrupt_close_lifetime_slots: 100,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 10_000_000,
        ..V16CuMarketParams::default()
    });
    env.svm.warp_to_slot(1);
    for a in 0..2u16 {
        env.configure_auth_mark_for_asset_as_admin(a, 1, PX);
    }
    env.configure_permissionless_resolve_with_cu(STALE, 50);
    env
}

/// (cfg.last_good_oracle_slot, profile[asset].last_good_oracle_slot)
fn slots(env: &V16CuEnv, asset: usize) -> (u64, u64) {
    let data = env.svm.get_account(&env.market).unwrap().data;
    let (cfg, _) = state::read_market(&data).unwrap();
    let p = state::read_asset_oracle_profile(&data, asset).unwrap();
    (cfg.last_good_oracle_slot, p.last_good_oracle_slot)
}

fn warp(env: &mut V16CuEnv, slot: u64) {
    env.svm.warp_to_slot(slot);
    env.svm.expire_blockhash();
}

fn code_of(r: &Result<u64, String>) -> Option<u32> {
    r.as_ref().err().and_then(|e| custom_code(e))
}

#[test]
fn push_asset0_advances_cfg_and_profile_push_asset1_advances_profile_only() {
    let mut env = world();
    assert_eq!(slots(&env, 0), (1, 1));
    assert_eq!(slots(&env, 1).1, 1, "configure at slot 1 seeds all three clocks");

    warp(&mut env, 10);
    env.push_auth_mark_for_asset_as_admin(1, 10, PX);
    assert_eq!(slots(&env, 1), (1, 10), "asset-1 push: cfg unchanged, profile-1 advanced");
    assert_eq!(slots(&env, 0), (1, 1), "asset-1 push leaves profile 0 alone");

    warp(&mut env, 20);
    env.push_auth_mark_for_asset_as_admin(0, 20, PX);
    assert_eq!(slots(&env, 0), (20, 20), "asset-0 push: cfg and profile-0 both advanced");
    assert_eq!(slots(&env, 1), (20, 10), "asset-0 push leaves profile 1 alone");
}

#[test]
fn asset1_stale_while_asset0_pushed_is_untradeable_not_resolvable() {
    let mut env = world();
    let a = Keypair::new();
    let b = Keypair::new();
    let pa = env.create_portfolio(&a);
    let pb = env.create_portfolio(&b);
    env.deposit(&a, pa, 50_000_000);
    env.deposit(&b, pb, 50_000_000);
    let q: i128 = percolator::POS_SCALE as i128;
    let oracle_stale = percolator_prog::error::PercolatorError::OracleStale as u32;

    // Keep only asset 0 fresh for 3x the window; asset 1 was last pushed at slot 1.
    let mut s = 1;
    while s < 1 + 3 * STALE {
        s += 50;
        warp(&mut env, s);
        env.push_auth_mark_for_asset_as_admin(0, s, PX);
    }
    assert_eq!(slots(&env, 0), (s, s));
    assert_eq!(slots(&env, 1).1, 1);
    assert!(s - 1 >= STALE, "asset 1 has been stale past the resolve window");

    // Permissionless resolve is refused: the cfg (asset 0) clock is fresh.
    let res = env.send(
        ProgInstruction::ResolveStalePermissionless { now_slot: s },
        vec![AccountMeta::new(env.market, false)],
        &[],
    );
    let err = res.expect_err("resolve must be refused while asset 0 is fresh");
    assert_eq!(custom_code(&err), Some(oracle_stale), "{err}");
    assert_eq!(env.market_state().1.mode, percolator::MarketModeV16::Live);

    // Asset 1 trades are refused as stale (profile clock); asset 0 trades are not.
    env.svm.expire_blockhash();
    let r1 = env.try_trade_asset_with_cu(1, &a, pa, &b, pb, q, PX, 0);
    assert_eq!(code_of(&r1), Some(oracle_stale), "asset-1 trade must be OracleStale: {r1:?}");
    env.svm.expire_blockhash();
    env.try_trade_asset_with_cu(0, &a, pa, &b, pb, q, PX, 0)
        .expect("asset-0 trade still works (control)");

    // Once asset 0 also goes stale past the window, resolve succeeds.
    let end = s + STALE;
    warp(&mut env, end);
    env.resolve_stale_permissionless_with_cu(end);
    assert_eq!(env.market_state().1.mode, percolator::MarketModeV16::Resolved);
}

#[test]
fn last_good_slot_layout_pins() {
    assert_eq!(
        offset_of!(state::WrapperConfigV16, last_good_oracle_slot),
        152,
        "keeper pusher-role.ts reads header 16 + 152"
    );
    assert_eq!(
        offset_of!(state::AssetOracleProfileV16, last_good_oracle_slot),
        PROFILE_LGS_OFF,
        "AssetOracleProfileV16.last_good_oracle_slot moved"
    );

    // The real account bytes at 16 + 152 are the cfg clock.
    let mut env = world();
    warp(&mut env, 33);
    env.push_auth_mark_for_asset_as_admin(0, 33, PX);
    let data = env.svm.get_account(&env.market).unwrap().data;
    let raw = u64::from_le_bytes(data[HEADER_LEN + 152..HEADER_LEN + 160].try_into().unwrap());
    assert_eq!(raw, 33);
    assert_eq!(raw, slots(&env, 0).0);
}
