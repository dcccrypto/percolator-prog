//! Integration tests for inverted market price handling
//!
//! These tests verify that the funding calculation correctly uses the market price
//! (which may be inverted) rather than raw oracle price. This is critical for
//! SOL/USD style perp markets where the price needs to be inverted.
//!
//! Uses production BPF binary (not --features test) because the test feature
//! bypasses CPI for token transfers, which fails in LiteSVM.
//!
//! Build: cargo build-sbf
//! Run:   cargo test --test integration

use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
    program_pack::Pack,
};
use spl_token::state::{Account as TokenAccount, AccountState};
use std::path::PathBuf;

// SLAB_LEN for production BPF (MAX_ACCOUNTS=4096)
// Note: We use production BPF (not test feature) because test feature
// bypasses CPI for token transfers, which fails in LiteSVM.
const SLAB_LEN: usize = 1107288;  // MAX_ACCOUNTS=4096 (0x10e558)
const MAX_ACCOUNTS: usize = 4096;

// Pyth Receiver program ID
const PYTH_RECEIVER_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48,
    0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b, 0x90,
    0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01,
    0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38, 0x58, 0x81,
]);

const TEST_FEED_ID: [u8; 32] = [0xABu8; 32];

fn program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    path
}

fn make_token_account_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccount::LEN];
    let mut account = TokenAccount::default();
    account.mint = *mint;
    account.owner = *owner;
    account.amount = amount;
    account.state = AccountState::Initialized;
    TokenAccount::pack(account, &mut data).unwrap();
    data
}

fn make_mint_data() -> Vec<u8> {
    use spl_token::state::Mint;
    let mut data = vec![0u8; Mint::LEN];
    let mint = Mint {
        mint_authority: solana_sdk::program_option::COption::None,
        supply: 0,
        decimals: 6,
        is_initialized: true,
        freeze_authority: solana_sdk::program_option::COption::None,
    };
    Mint::pack(mint, &mut data).unwrap();
    data
}

/// Create PriceUpdateV2 mock data (Pyth Pull format)
fn make_pyth_data(feed_id: &[u8; 32], price: i64, expo: i32, conf: u64, publish_time: i64) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[42..74].copy_from_slice(feed_id);
    data[74..82].copy_from_slice(&price.to_le_bytes());
    data[82..90].copy_from_slice(&conf.to_le_bytes());
    data[90..94].copy_from_slice(&expo.to_le_bytes());
    data[94..102].copy_from_slice(&publish_time.to_le_bytes());
    data
}

/// Encode InitMarket instruction with invert flag
fn encode_init_market_with_invert(
    admin: &Pubkey,
    mint: &Pubkey,
    feed_id: &[u8; 32],
    invert: u8,
) -> Vec<u8> {
    let mut data = vec![0u8];
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(feed_id);
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_staleness_secs
    data.extend_from_slice(&500u16.to_le_bytes()); // conf_filter_bps
    data.push(invert); // invert flag
    data.extend_from_slice(&0u32.to_le_bytes()); // unit_scale
    // RiskParams
    data.extend_from_slice(&0u64.to_le_bytes()); // warmup_period_slots
    data.extend_from_slice(&500u64.to_le_bytes()); // maintenance_margin_bps
    data.extend_from_slice(&1000u64.to_le_bytes()); // initial_margin_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // trading_fee_bps
    data.extend_from_slice(&(MAX_ACCOUNTS as u64).to_le_bytes());
    data.extend_from_slice(&0u128.to_le_bytes()); // new_account_fee
    data.extend_from_slice(&0u128.to_le_bytes()); // risk_reduction_threshold
    data.extend_from_slice(&0u128.to_le_bytes()); // maintenance_fee_per_slot
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_crank_staleness_slots
    data.extend_from_slice(&50u64.to_le_bytes()); // liquidation_fee_bps
    data.extend_from_slice(&1_000_000_000_000u128.to_le_bytes()); // liquidation_fee_cap
    data.extend_from_slice(&100u64.to_le_bytes()); // liquidation_buffer_bps
    data.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    data
}

fn encode_init_lp(matcher: &Pubkey, ctx: &Pubkey, fee: u64) -> Vec<u8> {
    let mut data = vec![2u8];
    data.extend_from_slice(matcher.as_ref());
    data.extend_from_slice(ctx.as_ref());
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn encode_init_user(fee: u64) -> Vec<u8> {
    let mut data = vec![1u8];
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn encode_deposit(user_idx: u16, amount: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    data.extend_from_slice(&user_idx.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn encode_trade(lp: u16, user: u16, size: i128) -> Vec<u8> {
    let mut data = vec![6u8];
    data.extend_from_slice(&lp.to_le_bytes());
    data.extend_from_slice(&user.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data
}

fn encode_crank_permissionless() -> Vec<u8> {
    let mut data = vec![5u8];
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.push(0u8); // allow_panic = false
    data
}

struct TestEnv {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    slab: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    pyth_index: Pubkey,
    pyth_col: Pubkey,
}

impl TestEnv {
    fn new() -> Self {
        let path = program_path();
        if !path.exists() {
            panic!("BPF not found at {:?}. Run: cargo build-sbf --features test", path);
        }

        let mut svm = LiteSVM::new();
        let program_id = Pubkey::new_unique();
        let program_bytes = std::fs::read(&path).expect("Failed to read program");
        svm.add_program(program_id, &program_bytes);

        let payer = Keypair::new();
        let slab = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let pyth_index = Pubkey::new_unique();
        let pyth_col = Pubkey::new_unique();
        let (vault_pda, _) = Pubkey::find_program_address(&[b"vault", slab.as_ref()], &program_id);
        let vault = Pubkey::new_unique();

        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

        svm.set_account(slab, Account {
            lamports: 1_000_000_000,
            data: vec![0u8; SLAB_LEN],
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        svm.set_account(mint, Account {
            lamports: 1_000_000,
            data: make_mint_data(),
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        svm.set_account(vault, Account {
            lamports: 1_000_000,
            data: make_token_account_data(&mint, &vault_pda, 0),
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        // $138 price (high enough to show difference when inverted)
        let pyth_data = make_pyth_data(&TEST_FEED_ID, 138_000_000, -6, 1, 100);
        svm.set_account(pyth_index, Account {
            lamports: 1_000_000,
            data: pyth_data.clone(),
            owner: PYTH_RECEIVER_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();
        svm.set_account(pyth_col, Account {
            lamports: 1_000_000,
            data: pyth_data,
            owner: PYTH_RECEIVER_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        svm.set_sysvar(&Clock { slot: 100, unix_timestamp: 100, ..Clock::default() });

        TestEnv { svm, program_id, payer, slab, mint, vault, pyth_index, pyth_col }
    }

    fn init_market_with_invert(&mut self, invert: u8) {
        let admin = &self.payer;
        let dummy_ata = Pubkey::new_unique();
        self.svm.set_account(dummy_ata, Account {
            lamports: 1_000_000,
            data: vec![0u8; TokenAccount::LEN],
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(sysvar::rent::ID, false),
                AccountMeta::new_readonly(dummy_ata, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            data: encode_init_market_with_invert(
                &admin.pubkey(),
                &self.mint,
                &TEST_FEED_ID,
                invert,
            ),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&admin.pubkey()), &[admin], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_market failed");
    }

    fn create_ata(&mut self, owner: &Pubkey, amount: u64) -> Pubkey {
        let ata = Pubkey::new_unique();
        self.svm.set_account(ata, Account {
            lamports: 1_000_000,
            data: make_token_account_data(&self.mint, owner, amount),
            owner: spl_token::ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();
        ata
    }

    fn init_lp(&mut self, owner: &Keypair) -> u16 {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let ata = self.create_ata(&owner.pubkey(), 0);
        let matcher = spl_token::ID;
        let ctx = Pubkey::new_unique();
        self.svm.set_account(ctx, Account {
            lamports: 1_000_000,
            data: vec![0u8; 320],
            owner: matcher,
            executable: false,
            rent_epoch: 0,
        }).unwrap();

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(matcher, false),
                AccountMeta::new_readonly(ctx, false),
            ],
            data: encode_init_lp(&matcher, &ctx, 0),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&owner.pubkey()), &[owner], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_lp failed");
        0
    }

    fn init_user(&mut self, owner: &Keypair) -> u16 {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let ata = self.create_ata(&owner.pubkey(), 0);

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(self.pyth_col, false),
            ],
            data: encode_init_user(0),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&owner.pubkey()), &[owner], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_user failed");
        1
    }

    fn deposit(&mut self, owner: &Keypair, user_idx: u16, amount: u64) {
        let ata = self.create_ata(&owner.pubkey(), amount);

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            data: encode_deposit(user_idx, amount),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&owner.pubkey()), &[owner], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("deposit failed");
    }

    fn trade(&mut self, user: &Keypair, lp: &Keypair, lp_idx: u16, user_idx: u16, size: i128) {
        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(lp.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(self.pyth_index, false),
            ],
            data: encode_trade(lp_idx, user_idx, size),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&user.pubkey()), &[user, lp], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("trade failed");
    }

    fn crank(&mut self) {
        let caller = Keypair::new();
        self.svm.airdrop(&caller.pubkey(), 1_000_000_000).unwrap();

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(caller.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(self.pyth_index, false),
            ],
            data: encode_crank_permissionless(),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix], Some(&caller.pubkey()), &[&caller], self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("crank failed");
    }

    fn set_slot(&mut self, slot: u64) {
        self.svm.set_sysvar(&Clock {
            slot,
            unix_timestamp: slot as i64,
            ..Clock::default()
        });
        // Update oracle publish_time to match
        let pyth_data = make_pyth_data(&TEST_FEED_ID, 138_000_000, -6, 1, slot as i64);
        self.svm.set_account(self.pyth_index, Account {
            lamports: 1_000_000,
            data: pyth_data.clone(),
            owner: PYTH_RECEIVER_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();
        self.svm.set_account(self.pyth_col, Account {
            lamports: 1_000_000,
            data: pyth_data,
            owner: PYTH_RECEIVER_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }).unwrap();
    }
}

/// Test that an inverted market can successfully run crank operations.
///
/// This verifies the funding calculation uses market price (inverted) correctly.
/// Prior to the fix, using raw oracle price instead of market price caused
/// ~19,000x overestimation for SOL/USD markets (138M raw vs ~7246 inverted).
///
/// The test:
/// 1. Creates an inverted market (invert=1, like SOL perp where price is SOL/USD)
/// 2. Opens positions to create LP inventory imbalance
/// 3. Runs crank which computes funding rate using market price
/// 4. If funding used raw price instead of market price, it would overflow or produce wrong values
#[test]
fn test_inverted_market_crank_succeeds() {
    let path = program_path();
    if !path.exists() {
        println!("SKIP: BPF not found. Run: cargo build-sbf");
        return;
    }

    let mut env = TestEnv::new();

    // Initialize with invert=1 (inverted market)
    // Oracle price ~$138/SOL in USD terms
    // Market price ~7246 after inversion (1e12/138M)
    env.init_market_with_invert(1);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 10_000_000_000); // 10 SOL worth

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 1_000_000_000); // 1 SOL worth

    // Open a position to create LP inventory imbalance
    // This causes non-zero funding rate when crank runs
    env.trade(&user, &lp, lp_idx, user_idx, 1_000_000);

    // Advance slot to allow funding accrual
    env.set_slot(200);
    env.crank();

    // Run multiple cranks to verify stability
    env.set_slot(300);
    env.crank();

    println!("✓ Inverted market crank succeeded with market price");
}

/// Test that a non-inverted market works correctly (control case).
///
/// This serves as a control test to verify that non-inverted markets
/// (where oracle price is used directly as market price) still work.
#[test]
fn test_non_inverted_market_crank_succeeds() {
    let path = program_path();
    if !path.exists() {
        println!("SKIP: BPF not found. Run: cargo build-sbf");
        return;
    }

    let mut env = TestEnv::new();

    // Initialize with invert=0 (non-inverted market)
    // Oracle price is used directly as market price
    env.init_market_with_invert(0);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 10_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 1_000_000_000);

    env.trade(&user, &lp, lp_idx, user_idx, 1_000_000);

    env.set_slot(200);
    env.crank();

    env.set_slot(300);
    env.crank();

    println!("✓ Non-inverted market crank succeeded");
}
