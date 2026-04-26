mod common;
use common::*;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn probe_engine_state() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 1_000_000_000);
    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 1_000_000_000);
    env.trade(&user, &lp, lp_idx, user_idx, 100_000_000);

    // Set slot then crank to update last_market_slot.
    env.set_slot(50);
    env.crank();

    let slab = env.svm.get_account(&env.slab).unwrap();

    // last_market_slot should be ~150 (slot+100 effective)
    println!("=== Engine state region (offsets 580..700) ===");
    for i in (580..700).step_by(8) {
        let off = ENGINE_OFFSET - 600 + i; // raw absolute
        let abs = i;
        if abs + 8 > slab.data.len() {
            continue;
        }
        let v = u64::from_le_bytes(slab.data[abs..abs + 8].try_into().unwrap());
        if v != 0 && v < (1u64 << 56) {
            println!("  abs+{}: u64={} (engine_rel={})", abs, v, abs - 600);
        }
    }
    // Also probe oracle_price (should be set by crank)
    println!("=== Oracle reading from default ===");
    let pyth = env.svm.get_account(&env.pyth_index).unwrap();
    let ts = i64::from_le_bytes(pyth.data[93..101].try_into().unwrap());
    println!("Pyth publish_time: {}", ts);
}
