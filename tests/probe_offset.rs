mod common;
use common::*;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn probe_engine_full() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let payer = Keypair::new();
    env.svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    env.top_up_insurance(&payer, 7_000_000_000);

    let s = env.svm.get_account(&env.slab).unwrap();
    println!("=== After 7B insurance topup ===");
    for i in (0..240).step_by(8) {
        let off = 600 + i;
        let v64 = u64::from_le_bytes(s.data[off..off + 8].try_into().unwrap());
        println!("  engine+{}: u64={} (0x{:x})", i, v64, v64);
    }
}
