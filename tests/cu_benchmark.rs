//! Worst-case CU benchmark tests for percolator-prog
//!
//! Run with: cargo test --release --test cu_benchmark -- --nocapture
//! For production MAX_ACCOUNTS=4096: cargo test --release --test cu_benchmark -- --nocapture
//! Note: Don't use --features test as that sets MAX_ACCOUNTS=64

use percolator::{RiskEngine, RiskParams, MAX_ACCOUNTS, AccountKind, Account};
use std::time::Instant;

fn default_params() -> RiskParams {
    RiskParams {
        warmup_period_slots: 100,
        maintenance_margin_bps: 500,      // 5%
        initial_margin_bps: 1000,         // 10%
        trading_fee_bps: 10,              // 0.1%
        max_accounts: MAX_ACCOUNTS as u64,
        new_account_fee: 0,               // No fee for test
        risk_reduction_threshold: 0,
        maintenance_fee_per_slot: 0,
        max_crank_staleness_slots: u64::MAX,
        liquidation_fee_bps: 50,          // 0.5%
        liquidation_fee_cap: 1_000_000_000_000,
        liquidation_buffer_bps: 100,      // 1%
        min_liquidation_abs: 1000,
    }
}

/// Create a RiskEngine with all accounts populated with positions
/// Uses heap allocation to avoid stack overflow (RiskEngine is ~1.2MB)
fn setup_full_engine() -> Box<RiskEngine> {
    let params = default_params();

    // Allocate on heap using Box::new_uninit to avoid stack allocation
    let mut engine: Box<RiskEngine> = unsafe {
        let layout = std::alloc::Layout::new::<RiskEngine>();
        let ptr = std::alloc::alloc_zeroed(layout) as *mut RiskEngine;
        Box::from_raw(ptr)
    };

    // Initialize in place
    engine.init_in_place(params);
    engine.current_slot = 1000;
    engine.last_crank_slot = 999;

    // Allocate all accounts using the engine's add_user method
    for i in 0..MAX_ACCOUNTS {
        // Use add_user to properly allocate accounts
        let idx = engine.add_user(0).expect("Failed to add user");

        // Set owner
        let mut owner = [0u8; 32];
        owner[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        engine.accounts[idx as usize].owner = owner;

        // Give it some capital
        engine.accounts[idx as usize].capital = 10_000_000_000; // 10k tokens

        // Give it a position (alternating long/short for balance)
        if i % 2 == 0 {
            engine.accounts[idx as usize].position_size = 1_000_000; // 1 contract long
        } else {
            engine.accounts[idx as usize].position_size = -1_000_000; // 1 contract short
        }

        // Set entry price
        engine.accounts[idx as usize].entry_price = 100_000_000; // $100
    }

    // Update open interest to reflect positions
    engine.total_open_interest = (MAX_ACCOUNTS as u128) * 1_000_000 / 2;

    engine
}

#[test]
fn benchmark_keeper_crank_full() {
    println!("\n=== KEEPER CRANK WORST-CASE BENCHMARK ===");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);

    let mut engine = setup_full_engine();
    println!("Engine setup complete: {} accounts allocated", engine.num_used_accounts);

    // Verify all accounts are populated
    assert_eq!(engine.num_used_accounts as usize, MAX_ACCOUNTS);

    let oracle_price = 100_000_000u64; // $100
    let funding_rate = 1i64; // 0.01% per slot
    let now_slot = 1000u64;

    // Warm up
    for i in 0..3 {
        let _ = engine.keeper_crank(u16::MAX, now_slot + i, oracle_price, funding_rate, false);
    }

    // Benchmark
    let iterations = 10;
    let start = Instant::now();

    for i in 0..iterations {
        let slot = now_slot + 100 + i;
        let result = engine.keeper_crank(u16::MAX, slot, oracle_price, funding_rate, false);
        assert!(result.is_ok());
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / iterations as u128;

    println!("\nBenchmark Results:");
    println!("  Iterations: {}", iterations);
    println!("  Total time: {:?}", elapsed);
    println!("  Average per crank: {} µs", avg_us);
    println!("  Estimated CU (native): ~{}", avg_us * 100);
    println!("");
    println!("Note: Actual Solana BPF CU will be higher due to BPF overhead");
    println!("Typical multiplier: 3-10x for BPF vs native");
    println!("");
}

#[test]
fn benchmark_scan_liquidate_full() {
    println!("\n=== SCAN & LIQUIDATE WORST-CASE BENCHMARK ===");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);

    let mut engine = setup_full_engine();

    // Reduce capital to 0 so all accounts are immediately liquidatable
    for i in 0..MAX_ACCOUNTS {
        if engine.is_used(i) {
            engine.accounts[i].capital = 0; // No capital - guaranteed liquidation
            engine.accounts[i].pnl = -1_000_000_000; // Also negative PnL
        }
    }

    // Price doesn't matter much since accounts have 0 capital
    let oracle_price = 100_000_000u64;

    // Count how many would be liquidated
    let mut longs = 0;
    let mut shorts = 0;
    for i in 0..MAX_ACCOUNTS {
        if engine.is_used(i) {
            let account = &engine.accounts[i];
            if account.position_size > 0 {
                longs += 1;
            } else if account.position_size < 0 {
                shorts += 1;
            }
        }
    }
    println!("Accounts setup: {} longs, {} shorts (minimal capital)", longs, shorts);

    let now_slot = 1001u64;
    engine.last_crank_slot = 1000;

    // Benchmark a single crank with mass liquidations
    let start = Instant::now();
    let result = engine.keeper_crank(u16::MAX, now_slot, oracle_price, 0, false);
    let elapsed = start.elapsed();

    match result {
        Ok(outcome) => {
            println!("\nBenchmark Results:");
            println!("  Time for crank with liquidations: {:?}", elapsed);
            println!("  Num liquidations: {}", outcome.num_liquidations);
            println!("  GC closed: {}", outcome.num_gc_closed);
            println!("  Estimated CU (native): ~{}", elapsed.as_micros() * 100);
            println!("  Estimated CU (BPF): ~{}", elapsed.as_micros() * 500);
        }
        Err(e) => {
            println!("Crank failed: {:?}", e);
        }
    }
    println!("");
}

#[test]
fn benchmark_lp_risk_compute() {
    println!("\n=== LP RISK STATE COMPUTE BENCHMARK ===");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);

    // LpRiskState is defined in percolator-prog, not percolator
    // We'll measure the account scan portion which is the O(n) part

    let engine = setup_full_engine();

    // Simulate what LpRiskState::compute does: scan all accounts
    let iterations = 100;
    let start = Instant::now();

    for _ in 0..iterations {
        // Simulate the O(n) scan
        let mut total_long: i128 = 0;
        let mut total_short: i128 = 0;

        for block in 0..percolator::BITMAP_WORDS {
            let mut w = engine.used[block];
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let idx = block * 64 + bit;
                w &= w - 1;
                if idx >= MAX_ACCOUNTS {
                    continue;
                }

                let pos = engine.accounts[idx].position_size;
                if pos > 0 {
                    total_long += pos;
                } else {
                    total_short += pos;
                }
            }
        }

        std::hint::black_box((total_long, total_short));
    }

    let elapsed = start.elapsed();
    let avg_us = elapsed.as_micros() / iterations as u128;

    println!("\nBenchmark Results (account scan):");
    println!("  Iterations: {}", iterations);
    println!("  Total time: {:?}", elapsed);
    println!("  Average per scan: {} µs", avg_us);
    println!("  Estimated CU (native): ~{}", avg_us * 100);
    println!("  Estimated CU (BPF): ~{}", avg_us * 500);
    println!("");
}

#[test]
fn print_structure_info() {
    println!("\n=== STRUCTURE INFO ===");
    println!("MAX_ACCOUNTS: {}", MAX_ACCOUNTS);
    println!("BITMAP_WORDS: {}", percolator::BITMAP_WORDS);
    println!("Size of Account: {} bytes", std::mem::size_of::<Account>());
    println!("Size of RiskEngine: {} bytes", std::mem::size_of::<RiskEngine>());
    println!("");
}
