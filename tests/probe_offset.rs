mod common;
use common::*;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn probe_last_market_slot() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);
    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 5_000_000_000);
    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 5_000_000_000);
    env.trade(&user, &lp, lp_idx, user_idx, 100_000);

    // Bump slot via set_slot_and_price walk + crank
    env.set_slot_and_price(50, 138_000_000);

    let s = env.svm.get_account(&env.slab).unwrap();
    // last_market_slot should be ~150 (50 + 100 effective offset)
    let needles = [50u64, 51, 100, 150];
    for n in needles {
        let needle = n.to_le_bytes();
        let mut hits = vec![];
        for i in 600..1300 {
            if s.data[i..i + 8] == needle {
                hits.push(i);
            }
        }
        println!("u64={} hits in engine range: {:?}, rel: {:?}",
            n, hits, hits.iter().map(|h| h - 600).collect::<Vec<_>>());
    }
}
