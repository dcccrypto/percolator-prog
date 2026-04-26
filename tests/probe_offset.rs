mod common;
use common::*;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn probe_engine_post_crank() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);
    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 5_000_000_000);
    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 5_000_000_000);
    env.trade(&user, &lp, lp_idx, user_idx, 100_000);

    let s = env.svm.get_account(&env.slab).unwrap();
    println!("=== Engine field scan post-trade ===");
    for i in (220..680).step_by(8) {
        let off = 600 + i;
        let v64 = u64::from_le_bytes(s.data[off..off + 8].try_into().unwrap());
        if v64 != 0 && v64 < (1u64 << 56) {
            println!("  engine+{}: u64={}", i, v64);
        }
    }
}
