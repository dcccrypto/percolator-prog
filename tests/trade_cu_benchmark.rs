//! Trade CU Benchmark — measures compute units for the Trade instruction
//!
//! Tests CU consumption for trade execution path (PERC-154 optimization).
//! Runs locally via LiteSVM — no devnet SOL required.
//!
//! Scenarios tested:
//! 1. Open new long position (no existing position)
//! 2. Open new short position (no existing position)
//! 3. Increase existing long (add to position)
//! 4. Flip position (long → short, short → long)
//! 5. Close position (reduce to zero)
//! 6. Multiple rapid trades (amortized overhead)
//! 7. Large position size vs small position size
//! 8. Trade with many active accounts in slab (contention test)
//!
//! Build BPF: cargo build-sbf
//! Run: cargo test --release --test trade_cu_benchmark -- --nocapture
//!
//! NOTE: Uses production BPF binary (not --features test) because the test
//! feature bypasses CPI for token transfers, which causes
//! ExternalAccountDataModified errors in LiteSVM's BPF runtime.

use litesvm::LiteSVM;
use solana_sdk::{
    account::Account,
    clock::Clock,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState};
use std::path::PathBuf;

// SLAB_LEN for production SBF (MAX_ACCOUNTS=4096).
// Note: struct layouts differ between BPF and native; these are BPF values.
// Use `cargo build-sbf` (NOT --features test) — the test feature bypasses CPI
// for token transfers, which fails in LiteSVM's BPF runtime.
const SLAB_LEN: usize = 1025832; // MAX_ACCOUNTS=4096 (BPF, PERC-328: matches SBF .so output)
const MAX_ACCOUNTS: usize = 4096;

// Pyth Receiver program ID
const PYTH_RECEIVER_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48, 0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b, 0x90,
    0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01, 0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38, 0x58, 0x81,
]);

const BENCHMARK_FEED_ID: [u8; 32] = [0xABu8; 32];

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

fn make_pyth_data(
    feed_id: &[u8; 32],
    price: i64,
    expo: i32,
    conf: u64,
    publish_time: i64,
) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    data[42..74].copy_from_slice(feed_id);
    data[74..82].copy_from_slice(&price.to_le_bytes());
    data[82..90].copy_from_slice(&conf.to_le_bytes());
    data[90..94].copy_from_slice(&expo.to_le_bytes());
    data[94..102].copy_from_slice(&publish_time.to_le_bytes());
    data
}

fn encode_init_market(admin: &Pubkey, mint: &Pubkey, feed_id: &[u8; 32]) -> Vec<u8> {
    let mut data = vec![0u8];
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(feed_id);
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_staleness_secs
    data.extend_from_slice(&500u16.to_le_bytes()); // conf_filter_bps
    data.push(0u8); // invert
    data.extend_from_slice(&0u32.to_le_bytes()); // unit_scale
    data.extend_from_slice(&0u64.to_le_bytes()); // initial_mark_price_e6 (0 = not Hyperp mode)
                                                 // RiskParams
    data.extend_from_slice(&0u64.to_le_bytes()); // warmup_period_slots
    data.extend_from_slice(&500u64.to_le_bytes()); // maintenance_margin_bps (5%)
    data.extend_from_slice(&1000u64.to_le_bytes()); // initial_margin_bps (10%)
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
    data.extend_from_slice(&0u64.to_le_bytes()); // funding_premium_weight_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // funding_settlement_interval_slots
    data.extend_from_slice(&1_000_000u64.to_le_bytes()); // funding_premium_dampening_e6
    data.extend_from_slice(&5i64.to_le_bytes()); // funding_premium_max_bps_per_slot
    data
}

fn encode_init_user(fee: u64) -> Vec<u8> {
    let mut data = vec![1u8];
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn encode_init_lp(matcher: &Pubkey, ctx: &Pubkey, fee: u64) -> Vec<u8> {
    let mut data = vec![2u8];
    data.extend_from_slice(matcher.as_ref());
    data.extend_from_slice(ctx.as_ref());
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

struct TradeTestEnv {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    slab: Pubkey,
    mint: Pubkey,
    vault: Pubkey,
    pyth_index: Pubkey,
    pyth_col: Pubkey,
}

impl TradeTestEnv {
    fn new() -> Self {
        let path = program_path();
        if !path.exists() {
            panic!("BPF not found at {:?}. Run: cargo build-sbf", path);
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

        svm.set_account(
            slab,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; SLAB_LEN],
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000,
                data: make_mint_data(),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        // Pre-fund vault with seed deposit (production BPF requires MIN_INIT_MARKET_SEED = 500 USDC).
        // We add extra tokens as LP liquidity buffer.
        svm.set_account(
            vault,
            Account {
                lamports: 1_000_000,
                data: make_token_account_data(&mint, &vault_pda, 1_000_000_000),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let pyth_data = make_pyth_data(&BENCHMARK_FEED_ID, 100_000_000, -6, 1, 100);
        svm.set_account(
            pyth_index,
            Account {
                lamports: 1_000_000,
                data: pyth_data.clone(),
                owner: PYTH_RECEIVER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        svm.set_account(
            pyth_col,
            Account {
                lamports: 1_000_000,
                data: pyth_data,
                owner: PYTH_RECEIVER_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        svm.set_sysvar(&Clock {
            slot: 100,
            unix_timestamp: 100,
            ..Clock::default()
        });

        TradeTestEnv {
            svm,
            program_id,
            payer,
            slab,
            mint,
            vault,
            pyth_index,
            pyth_col,
        }
    }

    fn init_market(&mut self) {
        let admin = &self.payer;
        let dummy_ata = Pubkey::new_unique();
        self.svm
            .set_account(
                dummy_ata,
                Account {
                    lamports: 1_000_000,
                    data: vec![0u8; TokenAccount::LEN],
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();

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
            data: encode_init_market(&admin.pubkey(), &self.mint, &BENCHMARK_FEED_ID),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&admin.pubkey()),
            &[admin],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_market failed");
        self.svm.expire_blockhash();
    }

    fn create_ata(&mut self, owner: &Pubkey, amount: u64) -> Pubkey {
        let ata = Pubkey::new_unique();
        self.svm
            .set_account(
                ata,
                Account {
                    lamports: 1_000_000,
                    data: make_token_account_data(&self.mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        ata
    }

    fn init_lp(&mut self, owner: &Keypair) -> u16 {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let ata = self.create_ata(&owner.pubkey(), 0);
        let matcher = spl_token::ID;
        let ctx = Pubkey::new_unique();
        self.svm
            .set_account(
                ctx,
                Account {
                    lamports: 1_000_000,
                    data: vec![0u8; 320],
                    owner: matcher,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();

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
            &[ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_lp failed");
        self.svm.expire_blockhash();
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
            &[ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_user failed");
        self.svm.expire_blockhash();
        1 // LP is 0
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
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_deposit(user_idx, amount),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("deposit failed");
        self.svm.expire_blockhash();
    }

    /// Execute a trade and return compute units consumed
    fn trade_with_cu(
        &mut self,
        user: &Keypair,
        lp: &Keypair,
        lp_idx: u16,
        user_idx: u16,
        size: i128,
        cu_limit: u32,
    ) -> Result<(u64, Vec<String>), String> {
        let budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);

        // PERC-199: Clock sysvar removed — Clock::get() syscall used instead.
        let trade_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(lp.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(self.pyth_index, false),
            ],
            data: encode_trade(lp_idx, user_idx, size),
        };

        let tx = Transaction::new_signed_with_payer(
            &[budget_ix, trade_ix],
            Some(&user.pubkey()),
            &[user, lp],
            self.svm.latest_blockhash(),
        );
        match self.svm.send_transaction(tx) {
            Ok(result) => {
                // Advance blockhash so the next transaction isn't rejected as duplicate
                self.svm.expire_blockhash();
                Ok((result.compute_units_consumed, result.logs))
            }
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    fn set_price(&mut self, price_e6: i64, slot: u64) {
        self.svm.set_sysvar(&Clock {
            slot,
            unix_timestamp: slot as i64,
            ..Clock::default()
        });
        let pyth_data = make_pyth_data(&BENCHMARK_FEED_ID, price_e6, -6, 1, slot as i64);

        self.svm
            .set_account(
                self.pyth_index,
                Account {
                    lamports: 1_000_000,
                    data: pyth_data.clone(),
                    owner: PYTH_RECEIVER_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        self.svm
            .set_account(
                self.pyth_col,
                Account {
                    lamports: 1_000_000,
                    data: pyth_data,
                    owner: PYTH_RECEIVER_PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }
}

/// Run a single trade and return CU consumed
fn measure_trade(
    env: &mut TradeTestEnv,
    user: &Keypair,
    lp: &Keypair,
    lp_idx: u16,
    user_idx: u16,
    size: i128,
) -> u64 {
    match env.trade_with_cu(user, lp, lp_idx, user_idx, size, 400_000) {
        Ok((cu, _)) => cu,
        Err(e) => panic!("Trade failed: {}", e),
    }
}

/// Measure N iterations and return (min, max, avg)
fn measure_n_trades(
    env: &mut TradeTestEnv,
    user: &Keypair,
    lp: &Keypair,
    lp_idx: u16,
    user_idx: u16,
    sizes: &[i128],
) -> (u64, u64, u64) {
    let mut min = u64::MAX;
    let mut max = 0u64;
    let mut total = 0u64;

    for &size in sizes {
        let cu = measure_trade(env, user, lp, lp_idx, user_idx, size);
        if cu < min {
            min = cu;
        }
        if cu > max {
            max = cu;
        }
        total += cu;
    }

    if sizes.is_empty() {
        return (0, 0, 0);
    }
    let avg = total / sizes.len() as u64;
    (min, max, avg)
}

#[test]
fn benchmark_trade_cu() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║       TRADE CU BENCHMARK (PERC-154 Optimization)       ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ Measures compute units for trade instruction execution  ║");
    println!("║ Local LiteSVM — no devnet SOL required                  ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);
    println!("SLAB_LEN: {}", SLAB_LEN);

    let path = program_path();
    if !path.exists() {
        println!("SKIP: BPF not found. Run: cargo build-sbf");
        return;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 1: Open new long position (fresh user, no existing position)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 1: 📈 Open new LONG position (fresh user)");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 10_000_000);

        let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 100);
        println!("  Open long 100 contracts: {} CU", cu);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 2: Open new short position
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 2: 📉 Open new SHORT position (fresh user)");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 10_000_000);

        let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -100);
        println!("  Open short 100 contracts: {} CU", cu);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 3: Increase existing position (add to long)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 3: ➕ Increase existing LONG position");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 100_000_000);

        // Open initial position
        measure_trade(&mut env, &user, &lp, 0, user_idx, 100);

        // Add to position
        let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 50);
        println!("  Add 50 contracts to long: {} CU", cu);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 4: Flip position (long → short)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 4: 🔄 Flip position (long → short)");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 100_000_000);

        // Open long
        measure_trade(&mut env, &user, &lp, 0, user_idx, 100);

        // Flip to short (sell 200 = close 100 long + open 100 short)
        let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -200);
        println!("  Flip from +100 to -100: {} CU", cu);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 5: Close position completely
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 5: ❌ Close position completely");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 100_000_000);

        // Open long
        measure_trade(&mut env, &user, &lp, 0, user_idx, 100);

        // Close completely
        let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -100);
        println!("  Close 100 contract long: {} CU", cu);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 6: Multiple rapid trades (round-trip cost)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 6: ⚡ Multiple rapid trades (10 round-trips)");
    {
        let mut env = TradeTestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 10_000_000_000_000);

        let user = Keypair::new();
        let user_idx = env.init_user(&user);
        env.deposit(&user, user_idx, 100_000_000);

        let mut trade_cus = Vec::new();
        // 10 round-trips: open long, close, open short, close, ...
        let sizes: Vec<i128> = (0..20)
            .map(|i| {
                if i % 4 == 0 {
                    100i128
                } else if i % 4 == 1 {
                    -100i128
                } else if i % 4 == 2 {
                    -100i128
                } else {
                    100i128
                }
            })
            .collect();

        for &size in &sizes {
            let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, size);
            trade_cus.push(cu);
        }

        let min = trade_cus.iter().min().unwrap();
        let max = trade_cus.iter().max().unwrap();
        let avg: u64 = trade_cus.iter().sum::<u64>() / trade_cus.len() as u64;
        println!("  20 trades: min={} max={} avg={} CU", min, max, avg);
        println!("  Per-trade CUs: {:?}", trade_cus);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 7: Large position vs small position
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 7: 📊 Position size comparison");
    {
        let sizes_to_test = [1i128, 10, 100, 1000, 10000, 100000];

        for &size in &sizes_to_test {
            let mut env = TradeTestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 100_000_000_000_000);

            let user = Keypair::new();
            let user_idx = env.init_user(&user);
            env.deposit(&user, user_idx, 100_000_000_000);

            let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, size);
            println!("  Size {:>8}: {} CU", size, cu);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Scenario 8: Trade with many active accounts in slab
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 8: 🏋️ Trade with active accounts in slab");
    {
        // Test with increasing numbers of active accounts in slab
        // Limited to smaller counts to keep benchmark runtime reasonable
        let account_counts = [1usize, 10, 100, 500, 1000, 2000, 4000];

        for &num_others in &account_counts {
            if num_others + 2 > MAX_ACCOUNTS {
                break;
            }

            let mut env = TradeTestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 100_000_000_000_000);

            // Create N other users with positions
            for i in 0..num_others {
                let other = Keypair::new();
                env.svm.airdrop(&other.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&other.pubkey(), 0);

                let ix = Instruction {
                    program_id: env.program_id,
                    accounts: vec![
                        AccountMeta::new(other.pubkey(), true),
                        AccountMeta::new(env.slab, false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new(env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                        AccountMeta::new_readonly(sysvar::clock::ID, false),
                        AccountMeta::new_readonly(env.pyth_col, false),
                    ],
                    data: encode_init_user(0),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[ix],
                    Some(&other.pubkey()),
                    &[&other],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();
                env.svm.expire_blockhash();

                let other_idx = (i + 1) as u16;
                env.deposit(&other, other_idx, 10_000_000);

                // Open position for each
                let size = if i % 2 == 0 { 100i128 } else { -100i128 };
                env.trade_with_cu(&other, &lp, 0, other_idx, size, 400_000)
                    .unwrap_or_else(|e| panic!("Preload trade failed for user {}: {}", i, e));
            }

            // Now create OUR user and trade
            let user = Keypair::new();
            let user_idx_raw = num_others + 1;
            env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
            let ata = env.create_ata(&user.pubkey(), 0);

            let ix = Instruction {
                program_id: env.program_id,
                accounts: vec![
                    AccountMeta::new(user.pubkey(), true),
                    AccountMeta::new(env.slab, false),
                    AccountMeta::new(ata, false),
                    AccountMeta::new(env.vault, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                    AccountMeta::new_readonly(env.pyth_col, false),
                ],
                data: encode_init_user(0),
            };
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&user.pubkey()),
                &[&user],
                env.svm.latest_blockhash(),
            );
            env.svm.send_transaction(tx).unwrap();
            env.svm.expire_blockhash();

            let user_idx = user_idx_raw as u16;
            env.deposit(&user, user_idx, 100_000_000);

            let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 100);
            println!("  {:>5} active accounts: {} CU per trade", num_others, cu);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Summary
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("=== TRADE CU BENCHMARK SUMMARY ===");
    println!("• Trade instruction CU should NOT depend on # of accounts in slab");
    println!("  (trade is O(1) — it only touches LP slot + user slot)");
    println!("• Key optimizations in PERC-154:");
    println!("  - TradeCpiV2: stack-allocated CPI data, caller bump");
    println!("  - invoke_signed_unchecked: skip RefCell validation (~200 CU)");
    println!("• Compare these numbers against pre-PERC-154 build to measure savings");
    println!("• To benchmark before optimization:");
    println!("    git stash && git checkout 75bab65 && cargo build-sbf");
    println!("    cargo test --release --test trade_cu_benchmark -- --nocapture");
    println!("    git checkout main && git stash pop && cargo build-sbf");
}

/// Comparative benchmark helper: run the same workload and return results as a struct
#[test]
fn benchmark_trade_cu_summary_table() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║          TRADE CU SUMMARY TABLE                         ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let path = program_path();
    if !path.exists() {
        println!("SKIP: BPF not found. Run: cargo build-sbf");
        return;
    }

    let mut env = TradeTestEnv::new();
    env.init_market();

    let lp = Keypair::new();
    env.init_lp(&lp);
    env.deposit(&lp, 0, 100_000_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 100_000_000_000);

    println!("┌────────────────────────────────┬──────────┐");
    println!("│ Operation                      │    CU    │");
    println!("├────────────────────────────────┼──────────┤");

    // Open long
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 100);
    println!("│ Open long (+100)               │ {:>8} │", cu);

    // Increase
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 50);
    println!("│ Increase long (+50)            │ {:>8} │", cu);

    // Partial close
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -75);
    println!("│ Partial close (-75)            │ {:>8} │", cu);

    // Flip long→short
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -200);
    println!("│ Flip long→short (-200)         │ {:>8} │", cu);

    // Increase short
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -50);
    println!("│ Increase short (-50)           │ {:>8} │", cu);

    // Flip short→long
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 400);
    println!("│ Flip short→long (+400)         │ {:>8} │", cu);

    // Close (position is +225 after flip, so -225 closes it)
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -225);
    println!("│ Close position (-225)          │ {:>8} │", cu);

    // Reopen for another measurement
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 1);
    println!("│ Tiny trade (size=1)            │ {:>8} │", cu);

    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, -1); // close
    let _ = cu;
    let cu = measure_trade(&mut env, &user, &lp, 0, user_idx, 100000);
    println!("│ Large trade (size=100K)        │ {:>8} │", cu);

    println!("└────────────────────────────────┴──────────┘");
    println!();
    println!("To compare pre/post PERC-154 optimization:");
    println!("  PRE:  git checkout 75bab65 && cargo build-sbf && cargo test --release --test trade_cu_benchmark -- --nocapture");
    println!("  POST: git checkout main  && cargo build-sbf && cargo test --release --test trade_cu_benchmark -- --nocapture");
}
