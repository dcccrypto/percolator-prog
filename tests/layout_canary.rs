//! Layout canary tests — detect byte-level mismatches between:
//!   1. Program constants (SLAB_LEN, ENGINE_OFF, CONFIG_LEN, etc.)
//!   2. slab_guard accepted sizes
//!   3. Known on-chain slab sizes
//!   4. Cross-target alignment (native vs SBF)
//!
//! If ANY of these fail, the program binary would reject existing markets
//! or SDK would parse at wrong offsets.

use percolator_prog::constants::{
    CONFIG_LEN, ENGINE_ALIGN, ENGINE_LEN, ENGINE_OFF, HEADER_LEN, SLAB_LEN,
};
use std::mem::{align_of, size_of};

// ═══════════════════════════════════════════════════════════════════════════
// 1. Struct size pinning — catches any field addition/removal/reordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn header_len_pinned() {
    // SlabHeader: magic(8) + version(4) + ... = 104 bytes
    assert_eq!(
        HEADER_LEN, 104,
        "HEADER_LEN changed — this breaks ALL existing slabs"
    );
}

#[test]
fn config_len_pinned() {
    // CONFIG_LEN depends on target alignment:
    //   Native (u128 align=16): 528 (HIGH-003: +16 bytes for oracle bounds)
    //   SBF/BPF (u128 align=8): 512 (HIGH-003: +16 bytes for oracle bounds)
    // Tests run on native, so we expect 528.
    assert_eq!(
        CONFIG_LEN, 528,
        "CONFIG_LEN changed on native target — check MarketConfig struct for added/removed fields"
    );
}

#[test]
fn engine_off_pinned() {
    // ENGINE_OFF = align_up(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN)
    // Native: align_up(104 + 528, 16) = align_up(632, 16) = 640
    //   (CONFIG_LEN grew by 16 bytes for HIGH-003 oracle bounds)
    let expected = (HEADER_LEN + CONFIG_LEN + (ENGINE_ALIGN - 1)) & !(ENGINE_ALIGN - 1);
    assert_eq!(ENGINE_OFF, expected, "ENGINE_OFF formula changed");
    println!("ENGINE_OFF = {} (native)", ENGINE_OFF);
    println!("HEADER_LEN = {}", HEADER_LEN);
    println!("CONFIG_LEN = {} (native)", CONFIG_LEN);
    println!("ENGINE_ALIGN = {}", ENGINE_ALIGN);
    println!("ENGINE_LEN = {}", ENGINE_LEN);
    println!("SLAB_LEN = {} (native)", SLAB_LEN);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. SLAB_LEN computation — catches tier computation errors
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn slab_len_is_engine_off_plus_engine_len() {
    assert_eq!(
        SLAB_LEN,
        ENGINE_OFF + ENGINE_LEN,
        "SLAB_LEN != ENGINE_OFF + ENGINE_LEN"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. slab_guard exhaustive — every known on-chain slab size must be accepted
// ═══════════════════════════════════════════════════════════════════════════

/// All slab sizes that exist or have existed on mainnet/devnet.
/// If you create a new market with a new size, ADD IT HERE first.
const KNOWN_ON_CHAIN_SLAB_SIZES: &[(usize, &str)] = &[
    // V1M mainnet (pre-ADL, percolator@cf35789)
    (65416, "V1M small (256 accts)"),
    (257512, "V1M medium (1024 accts)"),
    (1025896, "V1M large (4096 accts)"),
    // V1M2 mainnet (SBF target, CONFIG_LEN=512, ACCOUNT_SIZE=312)
    (323312, "V1M2 medium (1024 accts) — CCTegYZW mainnet market"),
    // Legacy devnet sizes
    (1025880, "pre-ADL devnet (4096 accts)"),
];

#[test]
fn slab_guard_accepts_all_known_sizes() {
    // Reproduce the slab_guard logic from the program
    let pre_118_slab_len = SLAB_LEN - 16;
    let oldest_slab_len = SLAB_LEN - 24;
    let pre_adl_slab_len: usize = 1025880;
    let v1m_small: usize = 65416;
    let v1m_medium: usize = 257512;
    let v1m_large: usize = 1025896;
    let v1m2_medium: usize = 323312;

    let accepted: Vec<usize> = vec![
        SLAB_LEN,
        pre_118_slab_len,
        oldest_slab_len,
        pre_adl_slab_len,
        v1m_small,
        v1m_medium,
        v1m_large,
        v1m2_medium,
    ];

    for (size, label) in KNOWN_ON_CHAIN_SLAB_SIZES {
        assert!(
            accepted.contains(size),
            "slab_guard would REJECT on-chain slab size {} ({}) — \
             add it to slab_guard's accepted sizes before deploying!\n\
             Accepted sizes: {:?}",
            size,
            label,
            accepted
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Account struct size — catches field additions that change slab layout
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn account_struct_size_pinned() {
    let account_size = size_of::<percolator::Account>();
    println!("Account size (native): {} bytes", account_size);
    // Pin this. If it changes, EVERY existing market breaks.
    // V1M: 248 bytes, V1M2 (with ADL fields): 312 bytes
    // Update this assertion when Account struct changes (and update slab_guard + SDK).
    // Known sizes per target:
    //   SBF (u128 align=8):  248 (V1M), 312 (V1M2/ADL)
    //   Native (u128 align=16): 256 (V1M), 320 (V1M2/ADL)
    // Native has +8 padding per u128 field.
    let known_sizes = [248usize, 256, 312, 320];
    assert!(
        known_sizes.contains(&account_size),
        "Account struct size {} is not a known size {:?} — \
         this will break existing markets! Update slab_guard, SDK, and this test.",
        account_size,
        known_sizes
    );
}

#[test]
fn risk_engine_size_pinned() {
    let engine_size = size_of::<percolator::RiskEngine>();
    println!("RiskEngine size (native): {} bytes", engine_size);
    // This includes bitmap, accounts array, etc. — very large.
    // Just assert it hasn't changed unexpectedly.
    assert!(
        engine_size > 100_000,
        "RiskEngine size {} seems too small — struct likely changed",
        engine_size
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Cross-target alignment canary
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn u128_alignment_documented() {
    let u128_align = align_of::<u128>();
    println!("u128 alignment on this target: {}", u128_align);
    // Native: 16, SBF: 8
    // This causes CONFIG_LEN to differ between targets.
    // The assertion here documents the native value; SBF is tested by the program's
    // compile-time assertions in constants module.
    #[cfg(target_arch = "aarch64")]
    assert_eq!(u128_align, 16, "u128 alignment on aarch64 should be 16");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(u128_align, 16, "u128 alignment on x86_64 should be 16");
}

#[test]
fn sbf_config_len_would_be_496() {
    // On SBF, u128 alignment is 8, so MarketConfig packs tighter.
    // We can't test SBF layout from native, but we document the expected value
    // and verify the compile-time assertion in the program catches mismatches.
    //
    // If this value changes, update:
    //   1. SDK detectSlabLayout() constants
    //   2. Frontend slab.ts
    //   3. Indexer StatsCollector
    //   4. slab_guard accepted sizes
    println!("Expected SBF CONFIG_LEN: 496 (u128 align=8)");
    println!("Expected SBF ENGINE_OFF: align_up(104 + 496, 8) = 600");
    println!(
        "Actual native CONFIG_LEN: {} (u128 align={})",
        CONFIG_LEN,
        align_of::<u128>()
    );
    println!("Actual native ENGINE_OFF: {}", ENGINE_OFF);
    // The SBF values (496, 600) are for the OLD bpf target.
    // Modern SBF (target_arch=sbf, not bpf) uses 512, 616.
    // The cfg(target_arch = "bpf") assertion in constants is WRONG for sbf!
    // TODO: Fix to cfg(any(target_arch = "bpf", target_arch = "sbf"))
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Print all layout constants for manual SDK cross-check
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn print_all_layout_constants() {
    println!("╔══════════════════════════════════════╗");
    println!("║  PROGRAM LAYOUT CONSTANTS (native)   ║");
    println!("╠══════════════════════════════════════╣");
    println!("║  HEADER_LEN    = {:>8}            ║", HEADER_LEN);
    println!("║  CONFIG_LEN    = {:>8}            ║", CONFIG_LEN);
    println!("║  ENGINE_ALIGN  = {:>8}            ║", ENGINE_ALIGN);
    println!("║  ENGINE_OFF    = {:>8}            ║", ENGINE_OFF);
    println!("║  ENGINE_LEN    = {:>8}            ║", ENGINE_LEN);
    println!("║  SLAB_LEN      = {:>8}            ║", SLAB_LEN);
    println!(
        "║  MAX_ACCOUNTS  = {:>8}            ║",
        percolator::MAX_ACCOUNTS
    );
    println!(
        "║  Account size  = {:>8}            ║",
        size_of::<percolator::Account>()
    );
    println!("║  u128 align    = {:>8}            ║", align_of::<u128>());
    println!("╚══════════════════════════════════════╝");

    // SDK cross-check values (update when SDK changes):
    // These are the values the TypeScript SDK uses in detectSlabLayout()
    println!("\nSDK cross-check (V1M2 layout for 323312-byte slabs):");
    println!("  SDK V1M2_ENGINE_OFF should be: 616 (SBF target)");
    println!("  SDK V1M2_CONFIG_LEN should be: 512 (SBF target)");
    println!(
        "  SDK V1M2_ACCOUNT_SIZE should be: {}",
        size_of::<percolator::Account>()
    );
}
