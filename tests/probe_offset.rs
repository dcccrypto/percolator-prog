mod common;
use common::*;
use solana_sdk::signature::{Keypair, Signer};

#[test]
fn probe_disambiguate_vault_insurance_ctot() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 1_000_000_000);

    println!("=== After 1B deposit ===");
    let slab = env.svm.get_account(&env.slab).unwrap();
    for off in [0u64, 16, 32, 312, 328, 336, 344].iter() {
        let abs = ENGINE_OFFSET + *off as usize;
        let v = u128::from_le_bytes(slab.data[abs..abs + 16].try_into().unwrap());
        println!("  engine+{}: {}", off, v);
    }
    drop(slab);

    // Top up insurance
    let payer = Keypair::new();
    env.svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    env.top_up_insurance(&payer, 7_000_000_000);

    println!("=== After 7B insurance topup ===");
    let slab = env.svm.get_account(&env.slab).unwrap();
    for off in [0u64, 16, 32, 312, 328, 336, 344].iter() {
        let abs = ENGINE_OFFSET + *off as usize;
        let v = u128::from_le_bytes(slab.data[abs..abs + 16].try_into().unwrap());
        println!("  engine+{}: {}", off, v);
    }
}
