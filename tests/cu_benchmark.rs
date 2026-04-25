#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::too_many_arguments, clippy::field_reassign_with_default, clippy::manual_saturating_arithmetic, clippy::useless_conversion, for_loops_over_fallibles, clippy::unnecessary_cast, clippy::absurd_extreme_comparisons, clippy::manual_abs_diff, clippy::empty_line_after_doc_comments, clippy::doc_lazy_continuation, clippy::needless_range_loop, clippy::implicit_saturating_sub, clippy::wrong_self_convention)]
//! BPF Compute Unit benchmark using LiteSVM
//!
//! Tests worst-case CU scenarios for keeper crank:
//! 1. All empty slots - baseline scan overhead
//! 2. All dust accounts - minimal balances, no positions
//! 3. Few liquidations - some accounts underwater
//! 4. All deeply underwater - socialized losses
//! 5. 4096 knife-edge liquidations - worst case
//!
//! Build BPF: cargo build-sbf (production) or cargo build-sbf --features test (small)
//! Run: cargo test --release --test cu_benchmark -- --nocapture

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
use solana_program_runtime::compute_budget::ComputeBudget;
// Solana's runtime clamps tx-level `ComputeBudgetInstruction::set_compute_unit_limit`
// to 1.4M CU. To measure the real cost of pathological cranks we bypass that via
// LiteSVM's `with_compute_budget(ComputeBudget { compute_unit_limit, ..Default })`
// which sets the VM-level meter directly. Such transactions could never land on
// mainnet — this is diagnostic only.
const MEASUREMENT_CU_CEILING: u64 = 50_000_000;
use spl_token::state::{Account as TokenAccount, AccountState};
use std::path::PathBuf;
// Tier-specific SBF slab sizes — must match what the .so validates at
// `percolator-prog/src/percolator.rs:5531`. We can't reach into the crate with
// `percolator_prog::constants::SLAB_LEN` because that evaluates at *native*
// compile time (x86_64/aarch64 alignment), not BPF alignment — the two
// disagree by ~16 bytes per account. Values below are the actual BPF-side
// SLAB_LEN observed from `sol_log_64` on mismatch.
//
// If any of these drift, the test's runtime InvalidSlabLen probe in
// `init_market` catches it and prints both sides so you know which one is
// wrong.

#[cfg(feature = "test")]
const MAX_ACCOUNTS: usize = 64;
#[cfg(feature = "test")]
const SLAB_LEN: usize = 19640;

#[cfg(feature = "small")]
const MAX_ACCOUNTS: usize = 256;
#[cfg(feature = "small")]
const SLAB_LEN: usize = 94168;

#[cfg(feature = "medium")]
const MAX_ACCOUNTS: usize = 1024;
#[cfg(feature = "medium")]
const SLAB_LEN: usize = 372280;

#[cfg(not(any(feature = "test", feature = "small", feature = "medium")))]
const MAX_ACCOUNTS: usize = 4096;
#[cfg(not(any(feature = "test", feature = "small", feature = "medium")))]
const SLAB_LEN: usize = 1484728;

const ACCOUNTS_PER_CRANK: u16 = 128;
// Keep this in sync with `percolator::LIQ_BUDGET_PER_CRANK`.
// Lowered from 64 → 24 after the MTM density sweep (Scenario 9) proved the
// path blows the 1.4M CU budget above 24 liqs/crank.
const LIQ_BUDGET_PER_CRANK: u16 = 24;

// Pyth Receiver program ID (rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ)
const PYTH_RECEIVER_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48, 0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b, 0x90,
    0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01, 0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38, 0x58, 0x81,
]);

/// Default feed_id for CU benchmarks
const BENCHMARK_FEED_ID: [u8; 32] = [0xABu8; 32];

fn program_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/percolator_prog.so");
    assert!(
        path.exists(),
        "BPF not found at {:?}. Run: cargo build-sbf",
        path
    );
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
/// Layout: discriminator(8) + write_authority(32) + verification_level(2) + feed_id(32) +
///         price(8) + conf(8) + expo(4) + publish_time(8) + ...
fn cu_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

fn make_pyth_data(
    feed_id: &[u8; 32],
    price: i64,
    expo: i32,
    conf: u64,
    publish_time: i64,
) -> Vec<u8> {
    let mut data = vec![0u8; 134];
    // verification_level = Full (1) at offset 40
    data[40..42].copy_from_slice(&1u16.to_le_bytes());
    // feed_id at offset 42
    data[42..74].copy_from_slice(feed_id);
    // price at offset 74
    data[74..82].copy_from_slice(&price.to_le_bytes());
    // conf at offset 82
    data[82..90].copy_from_slice(&conf.to_le_bytes());
    // expo at offset 90
    data[90..94].copy_from_slice(&expo.to_le_bytes());
    // publish_time at offset 94
    data[94..102].copy_from_slice(&publish_time.to_le_bytes());
    data
}

// Instruction encoders
fn encode_init_market_with_params(
    admin: &Pubkey,
    mint: &Pubkey,
    feed_id: &[u8; 32],
    risk_reduction_threshold: u128,
    warmup_period_slots: u64,
) -> Vec<u8> {
    let mut data = vec![0u8];
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(feed_id);
    data.extend_from_slice(&86400u64.to_le_bytes()); // max_staleness_secs (1 day, ≤7d cap)
    data.extend_from_slice(&500u16.to_le_bytes()); // conf_filter_bps
    data.push(0u8); // invert (0 = no inversion)
    data.extend_from_slice(&0u32.to_le_bytes()); // unit_scale (0 = no scaling)
    data.extend_from_slice(&0u64.to_le_bytes()); // initial_mark_price_e6 (0 for non-Hyperp markets)
    // Per-market admin limits (within engine bounds)
    data.extend_from_slice(&0u128.to_le_bytes()); // max_maintenance_fee_per_slot (legacy, ignored)
    data.extend_from_slice(&10_000_000_000_000_000u128.to_le_bytes()); // max_insurance_floor
    data.extend_from_slice(&1_000_000u64.to_le_bytes()); // min_oracle_price_cap_e2bps (resolvability invariant)
    // RiskParams
    data.extend_from_slice(&warmup_period_slots.to_le_bytes()); // h_min
    data.extend_from_slice(&500u64.to_le_bytes()); // maintenance_margin_bps (5%)
    data.extend_from_slice(&1000u64.to_le_bytes()); // initial_margin_bps (10%)
    data.extend_from_slice(&0u64.to_le_bytes()); // trading_fee_bps
    data.extend_from_slice(&(MAX_ACCOUNTS as u64).to_le_bytes());
    data.extend_from_slice(&0u128.to_le_bytes()); // new_account_fee
    data.extend_from_slice(&risk_reduction_threshold.to_le_bytes()); // insurance_floor
    data.extend_from_slice(&warmup_period_slots.to_le_bytes()); // h_max (must be >= h_min)
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_crank_staleness_slots
    data.extend_from_slice(&50u64.to_le_bytes()); // liquidation_fee_bps
    data.extend_from_slice(&1_000_000_000_000u128.to_le_bytes()); // liquidation_fee_cap
    data.extend_from_slice(&1000u64.to_le_bytes()); // resolve_price_deviation_bps
    data.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    data.extend_from_slice(&100u128.to_le_bytes()); // min_initial_deposit
    data.extend_from_slice(&1u128.to_le_bytes()); // min_nonzero_mm_req
    data.extend_from_slice(&2u128.to_le_bytes()); // min_nonzero_im_req
    data.extend_from_slice(&0u16.to_le_bytes()); // insurance_withdraw_max_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // insurance_withdraw_cooldown_slots
    data.extend_from_slice(&0u64.to_le_bytes()); // permissionless_resolve_stale_slots
    data.extend_from_slice(&500u64.to_le_bytes()); // funding_horizon_slots
    data.extend_from_slice(&100u64.to_le_bytes()); // funding_k_bps
    data.extend_from_slice(&500i64.to_le_bytes()); // funding_max_premium_bps
    data.extend_from_slice(&5i64.to_le_bytes()); // funding_max_bps_per_slot
    data.extend_from_slice(&0u64.to_le_bytes()); // mark_min_fee
    data.extend_from_slice(&0u64.to_le_bytes()); // force_close_delay_slots
    data
}

fn encode_init_market(admin: &Pubkey, mint: &Pubkey, feed_id: &[u8; 32]) -> Vec<u8> {
    encode_init_market_with_params(admin, mint, feed_id, 0, 1)
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

/// Encode a permissionless keeper crank covering 128 candidate slots starting
/// at `cursor` (wrapping modulo MAX_ACCOUNTS). Engine will process up to
/// LIQ_BUDGET_PER_CRANK (=64) liquidations from this window.
/// Parse a decimal or 0x-prefixed hex integer emitted by `sol_log_64`.
/// Used by scenarios that scrape the CRANK_STATS log line.
fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn encode_crank_permissionless(cursor: u16) -> Vec<u8> {
    // format_version=1: (u16 idx, u8 tag) per candidate
    let mut data = vec![5u8];
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.push(1u8); // format_version = 1
    let max = MAX_ACCOUNTS as u16;
    for i in 0..ACCOUNTS_PER_CRANK {
        let idx = cursor.wrapping_add(i) % max;
        data.extend_from_slice(&idx.to_le_bytes());
        data.push(0u8); // tag 0 = FullClose
    }
    data
}

fn encode_trade(lp: u16, user: u16, size: i128) -> Vec<u8> {
    let mut data = vec![6u8];
    data.extend_from_slice(&lp.to_le_bytes());
    data.extend_from_slice(&user.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
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
    /// Next crank window start — advances by ACCOUNTS_PER_CRANK after every
    /// crank so a loop of cranks sweeps the slab instead of hitting the same
    /// 128 slots each time.
    crank_cursor: u16,
    /// Slot we last pushed into the Clock sysvar — bumped before each crank so
    /// `now_slot > last_crank_slot` is true and funding/time-dependent paths
    /// actually run.
    current_slot: u64,
}

impl TestEnv {
    fn new() -> Self {
        Self::new_with_cu_ceiling(None)
    }

    /// Scenario-9 variant: bumps the VM-level compute meter above Solana's 1.4M
    /// cap so we can measure the real cost of pathological cranks. Pass `None`
    /// for normal behavior.
    fn new_with_cu_ceiling(cu_limit: Option<u64>) -> Self {
        let path = program_path();
        if !path.exists() {
            panic!("BPF not found at {:?}. Run: cargo build-sbf", path);
        }

        let mut svm = if let Some(limit) = cu_limit {
            let cb = ComputeBudget {
                compute_unit_limit: limit,
                ..ComputeBudget::default()
            };
            LiteSVM::new().with_compute_budget(cb)
        } else {
            LiteSVM::new()
        };
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

        svm.set_account(
            vault,
            Account {
                lamports: 1_000_000,
                data: make_token_account_data(&mint, &vault_pda, 0),
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        let pyth_data = make_pyth_data(&BENCHMARK_FEED_ID, 100_000_000, -6, 1, 100); // $100
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

        TestEnv {
            svm,
            program_id,
            payer,
            slab,
            mint,
            vault,
            pyth_index,
            pyth_col,
            crank_cursor: 0,
            current_slot: 100,
        }
    }

    fn init_market(&mut self) {
        self.init_market_with_params(0, 1);
    }

    fn init_market_with_params(
        &mut self,
        risk_reduction_threshold: u128,
        warmup_period_slots: u64,
    ) {
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

        // InitMarket expects 9 accounts. Slot 7 is the oracle account —
        // InitMarket now requires a successful oracle read at init (no sentinel).
        let _ = dummy_ata;
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
                AccountMeta::new_readonly(self.pyth_index, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            data: encode_init_market_with_params(
                &admin.pubkey(),
                &self.mint,
                &BENCHMARK_FEED_ID,
                risk_reduction_threshold,
                warmup_period_slots,
            ),
        };

        // InitMarket zeroes the full 4096-account engine struct in BPF, which exceeds
        // the 1.4M mainnet CU cap. Temporarily uncap for setup only.
        self.svm.set_compute_budget(ComputeBudget {
            compute_unit_limit: 50_000_000,
            heap_size: 256 * 1024,
            ..ComputeBudget::default()
        });
        let tx = Transaction::new_signed_with_payer(
            &[cu_ix(), ix],
            Some(&admin.pubkey()),
            &[admin],
            self.svm.latest_blockhash(),
        );
        match self.svm.send_transaction(tx) {
            Ok(_) => {}
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("Custom(4)") || err_str.contains("InvalidSlabLen") {
                    // Pull the .so-side SLAB_LEN from the sol_log_64 emitted at
                    // src/percolator.rs:5537 on mismatch. Format is:
                    // "Program log: 0x<so_slab_len>, 0x<data_len>, 0x0, 0x0, 0x0"
                    let mut so_slab_len: Option<u64> = None;
                    for line in err_str.split("\\\"") {
                        if line.starts_with("Program log: 0x") {
                            let parts: Vec<&str> = line
                                .trim_start_matches("Program log: ")
                                .split(", ")
                                .collect();
                            if parts.len() >= 2 {
                                so_slab_len = Some(parse_hex_or_dec(parts[0]));
                                break;
                            }
                        }
                    }
                    let so_report = match so_slab_len {
                        Some(v) => format!("{}", v),
                        None => String::from("(could not parse .so log)"),
                    };
                    panic!(
                        "InitMarket failed with InvalidSlabLen — tier mismatch.\n\
                         Test-side SLAB_LEN = {} (MAX_ACCOUNTS = {})\n\
                         .so-side  SLAB_LEN = {}\n\
                         Rebuild both with matching feature flags, e.g.:\n\
                         \tcargo build-sbf --features small\n\
                         \tcp target/sbpf-solana-solana/release/percolator_prog.so target/deploy/\n\
                         \tcargo test --release --test cu_benchmark --features small -- --nocapture\n\
                         Raw error: {}",
                        SLAB_LEN, MAX_ACCOUNTS, so_report, err_str
                    );
                }
                panic!("init_market failed: {}", err_str);
            }
        }
        // Restore standard 1.4M cap for benchmarking.
        self.svm.set_compute_budget(ComputeBudget::default());
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
        let ata = self.create_ata(&owner.pubkey(), 100);
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
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_init_lp(&matcher, &ctx, 100),
        };

        let tx = Transaction::new_signed_with_payer(
            &[cu_ix(), ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_lp failed");
        0
    }

    fn init_user(&mut self, owner: &Keypair) -> u16 {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let ata = self.create_ata(&owner.pubkey(), 100);

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
            data: encode_init_user(100),
        };

        let tx = Transaction::new_signed_with_payer(
            &[cu_ix(), ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("init_user failed");
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
            &[cu_ix(), ix],
            Some(&owner.pubkey()),
            &[owner],
            self.svm.latest_blockhash(),
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
            &[cu_ix(), ix],
            Some(&user.pubkey()),
            &[user, lp],
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).expect("trade failed");
    }

    fn crank(&mut self) -> u64 {
        self.crank_with_cu_limit(1_400_000)
    }

    fn crank_with_cu_limit(&mut self, cu_limit: u32) -> u64 {
        let caller = Keypair::new();
        self.svm.airdrop(&caller.pubkey(), 1_000_000_000).unwrap();

        // Advance the clock so `now_slot > last_crank_slot` and funding/time-dependent
        // paths actually run on every crank call (the engine short-circuits otherwise).
        self.advance_slot(1);

        let budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(cu_limit);

        let crank_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(caller.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(self.pyth_index, false),
            ],
            data: encode_crank_permissionless(self.crank_cursor),
        };

        let tx = Transaction::new_signed_with_payer(
            &[budget_ix, crank_ix],
            Some(&caller.pubkey()),
            &[&caller],
            self.svm.latest_blockhash(),
        );
        let result = self.svm.send_transaction(tx).expect("crank failed");
        self.advance_cursor();
        result.compute_units_consumed
    }

    fn advance_slot(&mut self, delta: u64) {
        self.current_slot = self.current_slot.saturating_add(delta);
        self.svm.set_sysvar(&Clock {
            slot: self.current_slot,
            unix_timestamp: self.current_slot as i64,
            ..Clock::default()
        });
    }

    fn advance_cursor(&mut self) {
        let max = MAX_ACCOUNTS as u32;
        let next = (self.crank_cursor as u32 + ACCOUNTS_PER_CRANK as u32) % max;
        self.crank_cursor = next as u16;
    }

    fn set_price(&mut self, price_e6: i64, slot: u64) {
        // Set both slot and unix_timestamp (using slot value as unix_timestamp for simplicity)
        self.current_slot = slot;
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

    fn try_crank(&mut self) -> Result<(u64, Vec<String>), String> {
        self.try_crank_inner(Some(1_400_000))
    }

    /// Variant that omits the ComputeBudgetInstruction entirely. LiteSVM's default
    /// block budget (~50M CU) applies instead, so we can *measure* how far a
    /// pathological crank goes past the 1.4M mainnet ceiling. Such a tx could
    /// never land on mainnet — this is diagnostic only.
    fn try_crank_unlimited(&mut self) -> Result<(u64, Vec<String>), String> {
        self.try_crank_inner(None)
    }

    fn try_crank_inner(
        &mut self,
        cu_limit: Option<u32>,
    ) -> Result<(u64, Vec<String>), String> {
        let caller = Keypair::new();
        self.svm.airdrop(&caller.pubkey(), 1_000_000_000).unwrap();

        self.advance_slot(1);

        let crank_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(caller.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(self.pyth_index, false),
            ],
            data: encode_crank_permissionless(self.crank_cursor),
        };

        let ixs: Vec<Instruction> = match cu_limit {
            Some(limit) => vec![
                ComputeBudgetInstruction::set_compute_unit_limit(limit),
                crank_ix,
            ],
            None => vec![crank_ix],
        };

        let tx = Transaction::new_signed_with_payer(
            &ixs,
            Some(&caller.pubkey()),
            &[&caller],
            self.svm.latest_blockhash(),
        );
        match self.svm.send_transaction(tx) {
            Ok(result) => {
                self.advance_cursor();
                Ok((result.compute_units_consumed, result.logs))
            }
            Err(e) => Err(format!("{:?}", e)),
        }
    }

    fn top_up_insurance(&mut self, funder: &Keypair, amount: u64) {
        let ata = self.create_ata(&funder.pubkey(), amount);

        // Instruction 9: TopUpInsurance { amount: u64 }
        let mut data = vec![9u8];
        data.extend_from_slice(&amount.to_le_bytes());

        let ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(funder.pubkey(), true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data,
        };
        let tx = Transaction::new_signed_with_payer(
            &[cu_ix(), ix],
            Some(&funder.pubkey()),
            &[funder],
            self.svm.latest_blockhash(),
        );
        self.svm
            .send_transaction(tx)
            .expect("top_up_insurance failed");
    }
}

// --- Encode helpers for all instruction types ---

fn encode_withdraw(user_idx: u16, amount: u64) -> Vec<u8> {
    let mut data = vec![4u8];
    data.extend_from_slice(&user_idx.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn encode_liquidate(target_idx: u16) -> Vec<u8> {
    let mut data = vec![7u8];
    data.extend_from_slice(&target_idx.to_le_bytes());
    data
}

fn encode_close_account(user_idx: u16) -> Vec<u8> {
    let mut data = vec![8u8];
    data.extend_from_slice(&user_idx.to_le_bytes());
    data
}

fn encode_top_up_insurance(amount: u64) -> Vec<u8> {
    let mut data = vec![9u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn encode_set_risk_threshold(new_threshold: u128) -> Vec<u8> {
    let mut data = vec![11u8];
    data.extend_from_slice(&new_threshold.to_le_bytes());
    data
}

fn encode_update_admin(new_admin: &Pubkey) -> Vec<u8> {
    // UpdateAuthority { kind: AUTHORITY_ADMIN = 0, new_pubkey }
    let mut data = vec![32u8];
    data.push(0u8);
    data.extend_from_slice(new_admin.as_ref());
    data
}

fn encode_close_slab() -> Vec<u8> {
    vec![13u8]
}

fn encode_update_config(
    funding_horizon_slots: u64,
    funding_k_bps: u64,
    funding_max_premium_bps: i64,
    funding_max_bps_per_slot: i64,
) -> Vec<u8> {
    // UpdateConfig wire format in v12.18.1: tag (1) + 4 u64/i64 funding params.
    // Earlier revisions had trailing threshold fields; the decoder now rejects
    // them explicitly so the benchmark must not append them either.
    let mut data = vec![14u8];
    data.extend_from_slice(&funding_horizon_slots.to_le_bytes());
    data.extend_from_slice(&funding_k_bps.to_le_bytes());
    data.extend_from_slice(&funding_max_premium_bps.to_le_bytes());
    data.extend_from_slice(&funding_max_bps_per_slot.to_le_bytes());
    data
}

fn encode_set_maintenance_fee(new_fee: u128) -> Vec<u8> {
    let mut data = vec![15u8];
    data.extend_from_slice(&new_fee.to_le_bytes());
    data
}

fn encode_set_oracle_authority(new_authority: &Pubkey) -> Vec<u8> {
    // UpdateAuthority { kind: AUTHORITY_ORACLE = 1, new_pubkey }
    let mut data = vec![32u8];
    data.push(1u8);
    data.extend_from_slice(new_authority.as_ref());
    data
}

fn encode_push_oracle_price(price_e6: u64, timestamp: i64) -> Vec<u8> {
    let mut data = vec![17u8];
    data.extend_from_slice(&price_e6.to_le_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());
    data
}

fn encode_set_oracle_price_cap(max_change_e2bps: u64) -> Vec<u8> {
    let mut data = vec![18u8];
    data.extend_from_slice(&max_change_e2bps.to_le_bytes());
    data
}

fn encode_resolve_market() -> Vec<u8> {
    vec![19u8]
}

fn encode_withdraw_insurance() -> Vec<u8> {
    vec![20u8]
}

fn encode_admin_force_close_account(user_idx: u16) -> Vec<u8> {
    let mut data = vec![21u8];
    data.extend_from_slice(&user_idx.to_le_bytes());
    data
}

fn encode_query_lp_fees(lp_idx: u16) -> Vec<u8> {
    let mut data = vec![24u8];
    data.extend_from_slice(&lp_idx.to_le_bytes());
    data
}

fn create_users(env: &mut TestEnv, count: usize, deposit_amount: u64) -> Vec<Keypair> {
    let mut users = Vec::with_capacity(count);
    for i in 0..count {
        let user = Keypair::new();
        env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
        let ata = env.create_ata(&user.pubkey(), 100);

        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_init_user(100),
        };
        let tx = Transaction::new_signed_with_payer(
            &[cu_ix(), ix],
            Some(&user.pubkey()),
            &[&user],
            env.svm.latest_blockhash(),
        );
        env.svm.send_transaction(tx).unwrap();

        let user_idx = (i + 1) as u16;
        env.deposit(&user, user_idx, deposit_amount);
        users.push(user);

        if (i + 1) % 500 == 0 {
            println!("    Created {} users...", i + 1);
        }
    }
    users
}

#[cfg(not(feature = "test"))]
#[test]
fn benchmark_worst_case_scenarios() {
    println!("\n=== WORST-CASE CRANK CU BENCHMARK ===");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);
    println!("SLAB_LEN: {}", SLAB_LEN);
    println!("Solana max CU per tx: 1,400,000\n");

    // Tier sanity: MAX_ACCOUNTS must be one of the four supported values.
    // Everything downstream derives from this — the test just reports whichever
    // tier the .so was built with.
    assert!(
        matches!(MAX_ACCOUNTS, 64 | 256 | 1024 | 4096),
        "Unexpected MAX_ACCOUNTS={} — expected 64 (test) / 256 (small) / 1024 (medium) / 4096 (prod)",
        MAX_ACCOUNTS
    );
    let tier_name = match MAX_ACCOUNTS {
        64 => "test",
        256 => "small",
        1024 => "medium",
        4096 => "production",
        _ => unreachable!(),
    };
    println!("Tier: {} (MAX_ACCOUNTS={})", tier_name, MAX_ACCOUNTS);

    let path = program_path();
    if !path.exists() {
        println!("SKIP: BPF not found. Run: cargo build-sbf");
        return;
    }

    // Scenario 1: All empty slots (just LP, no users)
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 1: 🟢 All empty slots (LP only) - LOWEST");
    {
        let mut env = TestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 1_000_000_000);

        env.set_price(100_000_000, 200);
        let cu = env.crank();
        println!(
            "  CU: {:>10} (baseline scan overhead for {} slots)",
            cu, MAX_ACCOUNTS
        );
        let cu_per_slot = cu / MAX_ACCOUNTS as u64;
        println!("  CU/slot: ~{}", cu_per_slot);
    }

    // Scenario 2: All dust accounts (no positions)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 2: 🟡 All dust accounts (no positions)");
    {
        let mut env = TestEnv::new();
        env.init_market();

        let lp = Keypair::new();
        env.init_lp(&lp);
        env.deposit(&lp, 0, 1_000_000_000_000);

        // Create users until we hit CU limit
        let mut users_created = 0;
        for i in 0..(MAX_ACCOUNTS - 1) {
            let user = Keypair::new();
            env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
            let ata = env.create_ata(&user.pubkey(), 100);

            let ix = Instruction {
                program_id: env.program_id,
                accounts: vec![
                    AccountMeta::new(user.pubkey(), true),
                    AccountMeta::new(env.slab, false),
                    AccountMeta::new(ata, false),
                    AccountMeta::new(env.vault, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(sysvar::clock::ID, false),
                ],
                data: encode_init_user(100),
            };
            let tx = Transaction::new_signed_with_payer(
                &[cu_ix(), ix],
                Some(&user.pubkey()),
                &[&user],
                env.svm.latest_blockhash(),
            );
            env.svm.send_transaction(tx).unwrap();
            env.deposit(&user, (i + 1) as u16, 1);
            users_created = i + 1;

            if (i + 1) % 500 == 0 {
                println!("    Created {} users...", i + 1);
            }
        }
        println!("  Created {} dust users total", users_created);

        env.set_price(100_000_000, 200);
        match env.try_crank() {
            Ok((cu, _logs)) => {
                let cu_per_account = cu / (users_created + 1) as u64;
                println!("  CU: {:>10} total, ~{} CU/account", cu, cu_per_account);
            }
            Err(_) => {
                println!("  ⚠️  EXCEEDS 1.4M CU LIMIT with {} users!", users_created);
            }
        }
    }

    // Scenario 3: Find practical limit - binary search for max users
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 3: 📊 Finding practical CU limit");
    {
        let test_sizes = [100, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000];
        let mut last_success_users = 0usize;

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                break;
            }

            let mut env = TestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 1_000_000_000_000);

            // Bulk create users
            for i in 0..num_users {
                let user = Keypair::new();
                env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&user.pubkey(), 100);

                let ix = Instruction {
                    program_id: env.program_id,
                    accounts: vec![
                        AccountMeta::new(user.pubkey(), true),
                        AccountMeta::new(env.slab, false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new(env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                        AccountMeta::new_readonly(sysvar::clock::ID, false),
                    ],
                    data: encode_init_user(100),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[cu_ix(), ix],
                    Some(&user.pubkey()),
                    &[&user],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();
                env.deposit(&user, (i + 1) as u16, 1);
            }

            env.set_price(100_000_000, 200);
            match env.try_crank() {
                Ok((cu, _logs)) => {
                    let cu_per_account = cu / (num_users + 1) as u64;
                    println!(
                        "  {:>4} users: {:>10} CU (~{} CU/user)",
                        num_users, cu, cu_per_account
                    );
                    last_success_users = num_users;
                }
                Err(_) => {
                    println!("  {:>4} users: ❌ EXCEEDS 1.4M CU LIMIT", num_users);
                    break;
                }
            }
        }
        if last_success_users > 0 {
            println!(
                "  → Max practical limit: ~{} users in single tx",
                last_success_users
            );
        }
    }

    // Scenario 4: Healthy accounts with positions (limited users)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 4: 🟡 Healthy accounts with positions");
    {
        // Scale down for positions - they add CU overhead
        let test_sizes = [50, 100, 200, 500, 1000];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                break;
            }

            let mut env = TestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 10_000_000_000_000);

            let users = create_users(&mut env, num_users, 1_000_000);

            // Add positions for each user
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                let size = if i % 2 == 0 { 100i128 } else { -100i128 };
                env.trade(user, &lp, 0, user_idx, size);
            }

            env.set_price(100_000_000, 200);
            match env.try_crank() {
                Ok((cu, _logs)) => {
                    let cu_per_account = cu / (num_users + 1) as u64;
                    println!(
                        "  {:>4} users: {:>10} CU (~{} CU/user)",
                        num_users, cu, cu_per_account
                    );
                }
                Err(_) => {
                    println!("  {:>4} users: ❌ EXCEEDS 1.4M CU LIMIT", num_users);
                    break;
                }
            }
        }
    }

    // Scenario 5: 🟠 Deeply underwater (price crash triggers liquidations)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 5: 🟠 Deeply underwater accounts (liquidations)");
    {
        let test_sizes = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                break;
            }

            let mut env = TestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 100_000_000_000_000);

            let users = create_users(&mut env, num_users, 1_000_000);

            // All users go long with high leverage
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                env.trade(user, &lp, 0, user_idx, 1000i128);
            }

            // Price crashes 50% - all users deeply underwater
            env.set_price(50_000_000, 200);

            match env.try_crank() {
                Ok((cu, _logs)) => {
                    let cu_per_account = cu / (num_users + 1) as u64;
                    println!(
                        "  {:>4} liquidations: {:>10} CU (~{} CU/user)",
                        num_users, cu, cu_per_account
                    );
                }
                Err(_) => {
                    println!("  {:>4} liquidations: ❌ EXCEEDS 1.4M CU LIMIT", num_users);
                    break;
                }
            }
        }
    }

    // Scenario 6: 🔴 Knife-edge liquidations (worst case)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 6: 🔴 Knife-edge liquidations (hardest case)");
    println!("  (mixed long/short at high leverage, price moves 15%)");
    {
        let test_sizes = [10, 25, 50, 100, 200];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                break;
            }

            let mut env = TestEnv::new();
            env.init_market();

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 100_000_000_000_000);

            let users = create_users(&mut env, num_users, 10_000_000);

            // Mix of long and short positions at high leverage
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                let size = if i % 2 == 0 { 5000i128 } else { -5000i128 };
                env.trade(user, &lp, 0, user_idx, size);
            }

            // Price moves 15% - triggers some liquidations
            env.set_price(85_000_000, 200);

            match env.try_crank() {
                Ok((cu, _logs)) => {
                    let cu_per_account = cu / (num_users + 1) as u64;
                    println!(
                        "  {:>4} users at edge: {:>10} CU (~{} CU/user)",
                        num_users, cu, cu_per_account
                    );
                }
                Err(_) => {
                    println!("  {:>4} users at edge: ❌ EXCEEDS 1.4M CU LIMIT", num_users);
                    break;
                }
            }
        }
    }

    // Scenario 7: 🔥 Worst-case ADL (force_realize_losses with unpaid losses)
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 7: 🔥 Worst-case ADL");
    println!("  (half long/half short with varying sizes, 50% crash)");
    println!("  Losers have minimal capital → unpaid losses → apply_adl");
    {
        // Test sizes for ADL scenario
        let test_sizes = [200, 400, 600, 800, 1000, 1100, 1200, 1300, 1400, 1500];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                break;
            }

            let mut env = TestEnv::new();

            // Use normal threshold - insurance starts at 0 which is <= 0 threshold
            // This should trigger force_realize_losses path when there are unpaid losses
            // warmup_period > 0 so winners' PnL stays unwrapped
            env.init_market_with_params(0, 100); // threshold=0, warmup=100 slots

            let lp = Keypair::new();
            env.init_lp(&lp);
            // LP needs huge capital to take the other side of all trades
            env.deposit(&lp, 0, 1_000_000_000_000_000);

            // Create users: half will be winners, half losers
            // Winners (shorts): deposit minimal capital, will have positive PnL after crash
            // Losers (longs): deposit zero/minimal capital, will have unpaid losses
            let half = num_users / 2;

            // Create all users first (without deposits for losers)
            let mut users = Vec::with_capacity(num_users);
            for i in 0..num_users {
                let user = Keypair::new();
                env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&user.pubkey(), 100);

                let ix = Instruction {
                    program_id: env.program_id,
                    accounts: vec![
                        AccountMeta::new(user.pubkey(), true),
                        AccountMeta::new(env.slab, false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new(env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                        AccountMeta::new_readonly(sysvar::clock::ID, false),
                    ],
                    data: encode_init_user(100),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[cu_ix(), ix],
                    Some(&user.pubkey()),
                    &[&user],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();

                let user_idx = (i + 1) as u16;

                // All users need enough margin to open positions
                // But losers will have capital wiped out by the crash
                // Size varies: (i%100+1)*10, so max size ~1000 contracts
                // At $100 price, position value = size * 100 = up to $100,000
                // With 10% initial margin, need ~$10,000 margin
                // Deposit slightly more than minimum so trade succeeds
                let deposit = if i < half {
                    // Losers (longs): just enough margin, will be wiped out
                    100_000 // minimal to pass margin check
                } else {
                    // Winners (shorts): more capital
                    10_000_000
                };
                env.deposit(&user, user_idx, deposit);

                users.push(user);
            }

            // Open positions with varying sizes (for dense remainders in ADL)
            // Longs: will lose on 50% price crash
            // Shorts: will win on 50% price crash
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                // Size varies by index to create different unwrapped PnL values
                let base_size = ((i % 100) + 1) as i128 * 10;
                let size = if i < half {
                    base_size // longs (losers after crash)
                } else {
                    -base_size // shorts (winners after crash)
                };
                env.trade(user, &lp, 0, user_idx, size);
            }

            // Price crashes 50% - longs lose massively, shorts win massively
            // force_realize_losses will be triggered because insurance < threshold
            // Losers have insufficient capital → unpaid losses → apply_adl
            env.set_price(50_000_000, 200); // $100 -> $50

            match env.try_crank() {
                Ok((cu, _logs)) => {
                    let cu_per_account = cu / (num_users + 1) as u64;
                    println!(
                        "  {:>4} ADL accounts: {:>10} CU (~{} CU/user)",
                        num_users, cu, cu_per_account
                    );
                }
                Err(e) => {
                    if e.contains("exceeded CUs") || e.contains("ProgramFailedToComplete") {
                        println!("  {:>4} ADL accounts: ❌ EXCEEDS 1.4M CU LIMIT", num_users);
                    } else {
                        println!("  {:>4} ADL accounts: ❌ {}", num_users, e);
                    }
                    break;
                }
            }
        }
    }

    // Scenario 8: 🔥🔥 Worst single crank across a 16-call sweep.
    // 16 cranks * ACCOUNTS_PER_CRANK=128 = 2048 slots covered per sweep (half of 4096).
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Scenario 8: 🔥🔥 Worst single crank across 16 calls ({} slots/crank)",
        ACCOUNTS_PER_CRANK
    );
    println!("  Cursor advances per call; clock advances per call.");
    println!("  8a: Healthy accounts with positions (no liquidations)");
    {
        // Test with increasing account counts - find threshold
        let test_sizes = [100, 200, 256, 512, 768, 1024, 1536, 2048, 3072, 4095];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                continue;
            }

            let mut env = TestEnv::new();
            env.init_market_with_params(0, 100); // warmup=100 slots

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 1_000_000_000_000_000);

            // Create all users with positions (worst case = all have positions)
            let half = num_users / 2;
            let mut users = Vec::with_capacity(num_users);

            print!("  Creating {} users...", num_users);
            std::io::Write::flush(&mut std::io::stdout()).ok();

            for i in 0..num_users {
                let user = Keypair::new();
                env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&user.pubkey(), 100);

                let ix = Instruction {
                    program_id: env.program_id,
                    accounts: vec![
                        AccountMeta::new(user.pubkey(), true),
                        AccountMeta::new(env.slab, false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new(env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                        AccountMeta::new_readonly(sysvar::clock::ID, false),
                    ],
                    data: encode_init_user(100),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[cu_ix(), ix],
                    Some(&user.pubkey()),
                    &[&user],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();

                let user_idx = (i + 1) as u16;
                // All users get enough margin for positions
                let deposit = if i < half { 100_000 } else { 10_000_000 };
                env.deposit(&user, user_idx, deposit);
                users.push(user);
            }
            println!(" done");

            // Open positions - half long, half short (creates liquidation scenario)
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                let base_size = ((i % 100) + 1) as i128 * 10;
                let size = if i < half { base_size } else { -base_size };
                env.trade(user, &lp, 0, user_idx, size);
            }

            // No price crash - healthy accounts
            env.set_price(100_000_000, 200);

            // Call crank 16 times and track worst CU
            let mut worst_cu: u64 = 0;
            let mut total_cu: u64 = 0;
            let mut any_failed = false;

            for crank_num in 0..16 {
                match env.try_crank() {
                    Ok((cu, _logs)) => {
                        if cu > worst_cu {
                            worst_cu = cu;
                        }
                        total_cu += cu;
                    }
                    Err(e) => {
                        if e.contains("exceeded CUs") || e.contains("ProgramFailedToComplete") {
                            println!("\n    Crank {} EXCEEDED 1.4M CU!", crank_num + 1);
                            any_failed = true;
                            break;
                        }
                        // Other errors might be OK (no work to do)
                    }
                }
            }

            if any_failed {
                println!(
                    "  {:>4} users: ❌ Single crank exceeded 1.4M CU limit",
                    num_users
                );
            } else {
                let pct = (worst_cu as f64 / 1_400_000.0) * 100.0;
                println!("  {:>4} users: worst={:>10} CU ({:.1}% of limit), total={} CU across 16 cranks",
                    num_users, worst_cu, pct, total_cu);
            }
        }
    }

    // Scenario 8b: Full sweep with liquidations - find threshold
    println!("\n  8b: With 50% crash (liquidations/ADL)");
    {
        let test_sizes = [100, 200, 256, 512, 768, 1024, 1536, 2048, 3072, 4095];

        for &num_users in &test_sizes {
            if num_users >= MAX_ACCOUNTS {
                continue;
            }

            let mut env = TestEnv::new();
            env.init_market_with_params(0, 100);

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 1_000_000_000_000_000);

            let half = num_users / 2;
            let mut users = Vec::with_capacity(num_users);

            print!("  Creating {} users...", num_users);
            std::io::Write::flush(&mut std::io::stdout()).ok();

            for i in 0..num_users {
                let user = Keypair::new();
                env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&user.pubkey(), 100);

                let ix = Instruction {
                    program_id: env.program_id,
                    accounts: vec![
                        AccountMeta::new(user.pubkey(), true),
                        AccountMeta::new(env.slab, false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new(env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                        AccountMeta::new_readonly(sysvar::clock::ID, false),
                    ],
                    data: encode_init_user(100),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[cu_ix(), ix],
                    Some(&user.pubkey()),
                    &[&user],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();

                let user_idx = (i + 1) as u16;
                let deposit = if i < half { 100_000 } else { 10_000_000 };
                env.deposit(&user, user_idx, deposit);
                users.push(user);
            }
            println!(" done");

            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                let base_size = ((i % 100) + 1) as i128 * 10;
                let size = if i < half { base_size } else { -base_size };
                env.trade(user, &lp, 0, user_idx, size);
            }

            // 50% price crash - triggers liquidations
            env.set_price(50_000_000, 200);

            let mut worst_cu: u64 = 0;
            let mut total_cu: u64 = 0;
            let mut any_failed = false;
            let mut last_logs: Vec<String> = Vec::new();

            for crank_num in 0..16 {
                match env.try_crank() {
                    Ok((cu, logs)) => {
                        if cu > worst_cu {
                            worst_cu = cu;
                        }
                        total_cu += cu;
                        last_logs = logs;
                    }
                    Err(e) => {
                        if e.contains("exceeded CUs") || e.contains("ProgramFailedToComplete") {
                            println!("\n    Crank {} EXCEEDED 1.4M CU!", crank_num + 1);
                            any_failed = true;
                            break;
                        }
                    }
                }
            }

            if any_failed {
                println!(
                    "  {:>4} users: ❌ Single crank exceeded 1.4M CU limit",
                    num_users
                );
            } else {
                let pct = (worst_cu as f64 / 1_400_000.0) * 100.0;
                // The engine emits sol_log_64(0xC8A4C5, 0, MAX_ACCOUNTS, ins_low, 0)
                // per crank (`src/percolator.rs:7125`). Only `ins_low` (insurance balance)
                // carries scenario-specific data; there is no liq/force counter in the log.
                let mut ins_low: u64 = 0;
                for log in &last_logs {
                    if let Some(rest) = log.strip_prefix("Program log: ") {
                        if rest.starts_with("0xc8a4c5") || rest.starts_with("0xC8A4C5") {
                            let parts: Vec<&str> = rest.split(", ").collect();
                            if parts.len() >= 4 {
                                ins_low = parse_hex_or_dec(parts[3]);
                            }
                        }
                    }
                }
                println!(
                    "  {:>4} users: worst={:>10} CU ({:.1}% of limit), total={} CU across 16 cranks (insurance={})",
                    num_users, worst_cu, pct, total_cu, ins_low
                );
            }
        }
    }

    // Scenario 9: MTM-liquidation density sweep.
    //
    // Solana's compute budget processor caps per-tx CU at 1.4M regardless of
    // what `set_compute_unit_limit` asks for, so we cannot measure past it.
    // Instead we sweep the number of liq candidates in the first 128-slot
    // crank window and report CU at each density. This answers the real
    // engineering question: *how many MTM liquidations can a keeper safely
    // pack into one crank on mainnet?*
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Scenario 9: 🔥🔥🔥 MTM-liquidation density sweep (1 crank each)");
    println!(
        "  Insurance funded → engine takes MTM path (not force_realize). Varies #liq users"
    );
    println!("  within the first 128-candidate window; rest are safe.");
    {
        const MAINNET_CU_BUDGET: u64 = 1_400_000;
        // Densities to probe. The engine caps at LIQ_BUDGET_PER_CRANK=64 per
        // call, so anything above 64 is redundant (first 64 hits the budget).
        let densities = [2usize, 4, 8, 16, 24, 32, 48, 64];
        let mut last_safe_density: Option<usize> = None;
        let mut first_over_density: Option<usize> = None;

        for &num_liqs in &densities {
            assert!(num_liqs < ACCOUNTS_PER_CRANK as usize);
            // Window = 128 slots. Slot 0 = LP. Slots 1..=num_liqs = liq. Rest safe.
            let num_users = (ACCOUNTS_PER_CRANK - 1) as usize;

            let mut env = TestEnv::new();
            env.init_market_with_params(0, 0);

            // Fund insurance so MTM path runs (not force_realize).
            let insurance_funder = Keypair::new();
            env.svm
                .airdrop(&insurance_funder.pubkey(), 1_000_000_000)
                .unwrap();
            env.top_up_insurance(&insurance_funder, 1_000_000_000);

            let lp = Keypair::new();
            env.init_lp(&lp);
            env.deposit(&lp, 0, 10_000_000_000_000);

            let mut users = Vec::with_capacity(num_users);
            for i in 0..num_users {
                let user = Keypair::new();
                env.svm.airdrop(&user.pubkey(), 1_000_000_000).unwrap();
                let ata = env.create_ata(&user.pubkey(), 100);

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
                    data: encode_init_user(100),
                };
                let tx = Transaction::new_signed_with_payer(
                    &[cu_ix(), ix],
                    Some(&user.pubkey()),
                    &[&user],
                    env.svm.latest_blockhash(),
                );
                env.svm.send_transaction(tx).unwrap();

                let user_idx = (i + 1) as u16;
                // First num_liqs users are liquidatable, rest are safe.
                let is_liq_user = i < num_liqs;
                let deposit = if is_liq_user { 50_000u64 } else { 1_000_000u64 };
                env.deposit(&user, user_idx, deposit);
                users.push(user);
            }

            // Open positions: longs at $100 entry.
            for (i, user) in users.iter().enumerate() {
                let user_idx = (i + 1) as u16;
                env.trade(user, &lp, 0, user_idx, 1000i128);
            }

            // 50% crash → liq users go underwater.
            env.set_price(50_000_000, 200);

            // Single crank, cursor=0, hits all num_liqs liquidatable users.
            match env.try_crank() {
                Ok((cu, _)) => {
                    let pct = (cu as f64 / MAINNET_CU_BUDGET as f64) * 100.0;
                    let marker = if cu > MAINNET_CU_BUDGET { "❌" } else { "✓" };
                    println!(
                        "  {} {:>3} liqs/crank: {:>8} CU ({:>5.1}% of 1.4M)",
                        marker, num_liqs, cu, pct
                    );
                    if cu <= MAINNET_CU_BUDGET {
                        last_safe_density = Some(num_liqs);
                    } else if first_over_density.is_none() {
                        first_over_density = Some(num_liqs);
                    }
                }
                Err(e) => {
                    if e.contains("exceeded CUs") || e.contains("ProgramFailedToComplete") {
                        println!(
                            "  ❌ {:>3} liqs/crank: EXCEEDED 1.4M CU (tx rejected by runtime)",
                            num_liqs
                        );
                        if first_over_density.is_none() {
                            first_over_density = Some(num_liqs);
                        }
                    } else {
                        println!("  {:>3} liqs/crank: error {}", num_liqs, e);
                    }
                }
            }
        }

        println!();
        match (last_safe_density, first_over_density) {
            (Some(safe), Some(over)) => println!(
                "  BREAKPOINT: {} liqs/crank OK, {} liqs/crank exceeds 1.4M mainnet budget.",
                safe, over
            ),
            (Some(safe), None) => println!(
                "  ✓ All sampled densities within 1.4M; safely tested up to {} liqs/crank.",
                safe
            ),
            (None, Some(over)) => println!(
                "  ❌ Even {} liqs/crank exceeds 1.4M — MTM path needs optimization.",
                over
            ),
            (None, None) => println!("  (no data)"),
        }
        println!(
            "  NOTE: engine caps at LIQ_BUDGET_PER_CRANK={} per call, but the mainnet CU budget"
            , LIQ_BUDGET_PER_CRANK
        );
        println!(
            "  may bite earlier. Keeper should cap candidates/crank to whichever is smaller."
        );
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("=== SUMMARY ===");
    println!(
        "• Crank submits up to {} candidates per call; engine processes up to {} liquidations.",
        ACCOUNTS_PER_CRANK, LIQ_BUDGET_PER_CRANK
    );
    println!(
        "• Full-slab sweep at MAX_ACCOUNTS={} needs {} cranks.",
        MAX_ACCOUNTS,
        MAX_ACCOUNTS / ACCOUNTS_PER_CRANK as usize
    );
    println!("• Key metric: worst single crank must stay under 1.4M CU.");
    println!("• ADL/liquidation processing adds CU overhead per affected account.");
}

/// Per-instruction CU benchmark covering all instruction types.
/// Measures CU consumed for each instruction under typical conditions.
#[cfg(not(feature = "test"))]
#[test]
fn benchmark_all_instructions() {
    println!("\n=== PER-INSTRUCTION CU BENCHMARK ===\n");

    let mut env = TestEnv::new();
    env.init_market();

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 50_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 10_000_000_000);

    env.set_price(100_000_000, 200);
    env.crank();

    // Helper: send instruction, return CU consumed
    let measure = |svm: &mut LiteSVM, ix: Instruction, signers: &[&Keypair]| -> Result<u64, String> {
        let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
        let payer = signers[0];
        let tx = Transaction::new_signed_with_payer(
            &[budget, ix],
            Some(&payer.pubkey()),
            signers,
            svm.latest_blockhash(),
        );
        match svm.send_transaction(tx) {
            Ok(r) => Ok(r.compute_units_consumed),
            Err(e) => Err(format!("{:?}", e)),
        }
    };

    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"vault", env.slab.as_ref()], &env.program_id);

    // --- TradeNoCpi (Tag 6) ---
    {
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(lp.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_trade(lp_idx, user_idx, 100_000),
        };
        let cu = measure(&mut env.svm, ix, &[&user, &lp]).unwrap();
        println!("TradeNoCpi:            {:>8} CU", cu);
    }

    // --- DepositCollateral (Tag 3) ---
    {
        let ata = env.create_ata(&user.pubkey(), 1_000_000);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_deposit(user_idx, 1_000_000),
        };
        let cu = measure(&mut env.svm, ix, &[&user]).unwrap();
        println!("DepositCollateral:     {:>8} CU", cu);
    }

    // --- WithdrawCollateral (Tag 4) ---
    {
        env.set_price(100_000_000, 300);
        env.crank();
        let ata = env.create_ata(&user.pubkey(), 0);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_withdraw(user_idx, 100_000),
        };
        let cu = measure(&mut env.svm, ix, &[&user]).unwrap();
        println!("WithdrawCollateral:    {:>8} CU", cu);
    }

    // --- KeeperCrank (Tag 5) ---
    {
        env.set_price(100_000_000, 400);
        let cu = env.crank();
        println!("KeeperCrank:           {:>8} CU", cu);
    }

    // --- TopUpInsurance (Tag 9) ---
    {
        let ata = env.create_ata(&admin.pubkey(), 1_000_000);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_top_up_insurance(1_000_000),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("TopUpInsurance:        {:>8} CU", cu);
    }

    // --- SetRiskThreshold (Tag 11) ---
    {
        env.set_price(100_000_000, 500);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_set_risk_threshold(1_000_000),
        };
        // SetRiskThreshold always rejects (I_floor immutable per spec §2.2.1)
        match measure(&mut env.svm, ix, &[&admin]) {
            Ok(cu) => println!("SetRiskThreshold:      {:>8} CU (rejected)", cu),
            Err(_) => println!("SetRiskThreshold:      (rejected — I_floor immutable)"),
        }
    }

    // --- UpdateConfig (Tag 14) ---
    {
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                // Oracle is REQUIRED on non-Hyperp UpdateConfig — admin cannot
                // select the degenerate zero-funding arm by omission.
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_update_config(
                3600,   // funding_horizon_slots
                100,    // funding_k_bps
                500,    // funding_max_premium_bps
                5,      // funding_max_bps_per_slot
            ),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("UpdateConfig:          {:>8} CU", cu);
    }

    // SetMaintenanceFee (Tag 15) — removed per spec §8.2. Decoder rejects.
    // SetOracleAuthority (Tag 16) — removed in Phase G. Decoder rejects.
    // PushOraclePrice    (Tag 17) — removed in Phase G. Decoder rejects.

    // --- SetOraclePriceCap (Tag 18) ---
    {
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
            ],
            data: encode_set_oracle_price_cap(1_000_000), // min_cap=1M at init; cap must be >= min
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("SetOraclePriceCap:     {:>8} CU", cu);
    }

    // --- QueryLpFees (Tag 24) ---
    {
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new_readonly(env.slab, false),
            ],
            data: encode_query_lp_fees(lp_idx),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("QueryLpFees:           {:>8} CU", cu);
    }

    // --- LiquidateAtOracle (Tag 7) ---
    // Make user underwater first
    {
        // Big price drop to make user liquidatable
        env.set_price(50_000_000, 700); // $100 -> $50
        env.crank();
        let caller = Keypair::new();
        env.svm.airdrop(&caller.pubkey(), 1_000_000_000).unwrap();
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(caller.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_liquidate(user_idx),
        };
        match measure(&mut env.svm, ix, &[&caller]) {
            Ok(cu) => println!("LiquidateAtOracle:     {:>8} CU", cu),
            Err(_) => println!("LiquidateAtOracle:     (user not liquidatable at this price)"),
        }
    }

    // --- CloseAccount (Tag 8) ---
    // Close position first, then close account
    {
        // Restore price and flatten position via opposing trade
        env.set_price(100_000_000, 800);
        env.crank();
        // Trade to flatten (negative = close long)
        env.trade(&user, &lp, lp_idx, user_idx, -100_000);
        env.set_price(100_000_000, 810);
        env.crank();

        let user_ata = env.create_ata(&user.pubkey(), 0);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(user.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new(user_ata, false),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_close_account(user_idx),
        };
        match measure(&mut env.svm, ix, &[&user]) {
            Ok(cu) => println!("CloseAccount:          {:>8} CU", cu),
            Err(e) => println!("CloseAccount:          (failed: {})", &e[..80.min(e.len())]),
        }
    }

    // --- UpdateAuthority(ADMIN) (Tag 32) — replaces legacy Tag 12 ---
    {
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
            ],
            data: encode_update_admin(&admin.pubkey()),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("UpdateAuthority(ADMIN): {:>8} CU", cu);
    }

    // --- ResolveMarket + resolved-path instructions ---
    {
        // Top up insurance so WithdrawInsurance has something to withdraw
        env.top_up_insurance(&Keypair::from_bytes(&admin.to_bytes()).unwrap(), 1_000_000);

        env.set_price(100_000_000, 900);
        env.crank();

        // Resolve
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_resolve_market(),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("ResolveMarket:         {:>8} CU", cu);

        // Resolved KeeperCrank
        env.set_price(100_000_000, 1000);
        let cu = env.crank();
        println!("KeeperCrank(resolved): {:>8} CU", cu);

        // AdminForceCloseAccount (Tag 21) - close LP
        let lp_ata = env.create_ata(&lp.pubkey(), 0);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new(lp_ata, false),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(sysvar::clock::ID, false),
                AccountMeta::new_readonly(env.pyth_index, false),
            ],
            data: encode_admin_force_close_account(lp_idx),
        };
        let cu = measure(&mut env.svm, ix, &[&admin]).unwrap();
        println!("AdminForceClose:       {:>8} CU", cu);

        // WithdrawInsurance (Tag 20) - all accounts now closed
        let admin_ata = env.create_ata(&admin.pubkey(), 0);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(admin_ata, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(vault_pda, false),
            ],
            data: encode_withdraw_insurance(),
        };
        match measure(&mut env.svm, ix, &[&admin]) {
            Ok(cu) => println!("WithdrawInsurance:     {:>8} CU", cu),
            Err(e) => println!("WithdrawInsurance:     (failed: {})", &e[..80.min(e.len())]),
        }

        // CloseSlab (Tag 13)
        let admin_ata2 = env.create_ata(&admin.pubkey(), 0);
        let ix = Instruction {
            program_id: env.program_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.slab, false),
                AccountMeta::new(env.vault, false),
                AccountMeta::new_readonly(vault_pda, false),
                AccountMeta::new(admin_ata2, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            data: encode_close_slab(),
        };
        match measure(&mut env.svm, ix, &[&admin]) {
            Ok(cu) => println!("CloseSlab:             {:>8} CU", cu),
            Err(e) => println!("CloseSlab:             (failed: {})", &e[..80.min(e.len())]),
        }
    }

    println!("\n=== END PER-INSTRUCTION CU BENCHMARK ===");
}
