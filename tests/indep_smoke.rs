#![cfg(not(kani))]
mod indep_harness;
use indep_harness::*;
use percolator::POS_SCALE;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn indep_smoke_deposit_trade_withdraw_vault_tracks_engine() {
    let mut env = V16CuEnv::new();
    let a_owner = Keypair::new();
    let b_owner = Keypair::new();
    let a = env.create_portfolio(&a_owner);
    let b = env.create_portfolio(&b_owner);
    env.deposit(&a_owner, a, 10_000);
    env.deposit(&b_owner, b, 10_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(0, 1, 100);
    env.trade_asset_with_cu(0, &a_owner, a, &b_owner, b, POS_SCALE as i128, 100, 0);
    let (_, g) = env.market_state();
    assert_eq!(env.token_amount(env.vault) as u128, g.vault);
}
