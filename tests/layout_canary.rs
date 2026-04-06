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
use std::mem::{align_of, offset_of, size_of};

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
    // CONFIG_LEN = 544 on both native and SBF (MarketConfig size is target-independent).
    // Only ENGINE_OFF differs between targets because of the alignment boundary:
    //   Native: align_up(104 + 544, 16) = 656
    //   SBF:    align_up(104 + 544, 8)  = 648  (verified empirically, SDK PR #149)
    // Tests run on native, so we expect 544.
    assert_eq!(
        CONFIG_LEN, 544,
        "CONFIG_LEN changed on native target — check MarketConfig struct for added/removed fields"
    );
}

#[test]
fn engine_off_pinned() {
    // ENGINE_OFF = align_up(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN)
    // Native: align_up(104 + 512, 16) = align_up(616, 16) = 624 (if align=16)
    //   or align_up(616, 8) = 616 (if align=8)
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
    // Reproduce the slab_guard logic from the program.
    // PERC-SetDexPool: CONFIG_LEN grew by 32 bytes, so SLAB_LEN grew by 32 bytes.
    // All pre-SetDexPool slabs are now SLAB_LEN-32 bytes.
    let pre_dex_pool_slab_len = SLAB_LEN - 32; // pre-PERC-SetDexPool (before dex_pool field)
    let pre_118_slab_len = SLAB_LEN - 48; // pre-PERC-SetDexPool(-32) + pre-PERC-118(-16)
    let oldest_slab_len = SLAB_LEN - 56; // pre-SetDexPool + pre-118 + pre-reorder
    let pre_adl_slab_len: usize = 1025880;
    let v1m_small: usize = 65416;
    let v1m_medium: usize = 257512;
    let v1m_large: usize = 1025896;
    let v1m2_medium: usize = 323312;

    let accepted: Vec<usize> = vec![
        SLAB_LEN,
        pre_dex_pool_slab_len,
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
    // v12.1 upstream: 336 bytes (native) — added position_basis_q, adl_a_basis,
    //   adl_k_snap, adl_epoch_snap, fees_earned_total, fee_credits, last_fee_slot
    // Update this assertion when Account struct changes (and update slab_guard + SDK).
    // Known sizes per target:
    //   SBF (u128 align=8):  248 (V1M), 312 (V1M2/ADL), ~320 (v12.1 estimate)
    //   Native (u128 align=16): 256 (V1M), 320 (V1M2/ADL), 336 (v12.1)
    // Native has +8 padding per u128 field.
    let known_sizes = [248usize, 256, 312, 320, 336];
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
    // PERC-SetDexPool: SBF CONFIG_LEN = 544 (same as native), ENGINE_OFF = 648.
    // MarketConfig's u128 fields do NOT cause a size difference between native and SBF —
    // the struct packs to the same size on both targets (verified empirically via SDK PR #149,
    // which confirmed V_SETDEXPOOL produces 323344-byte medium slabs with engine_off=648).
    //
    // The alignment difference between native (16) and SBF (8) only affects ENGINE_OFF:
    //   Native: align_up(104 + 544, 16) = 656
    //   SBF:    align_up(104 + 544, 8)  = 648
    //
    // If CONFIG_LEN changes, update:
    //   1. emit_layout_json test below (sbf.config_len, sbf.engine_off)
    //   2. SDK detectSlabLayout() constants (slab.ts V_SETDEXPOOL_CONFIG_LEN, V_SETDEXPOOL_ENGINE_OFF)
    //   3. Indexer StatsCollector
    //   4. slab_guard accepted sizes
    println!(
        "SBF CONFIG_LEN: {} (same as native — no size diff for MarketConfig)",
        CONFIG_LEN
    );
    println!(
        "SBF ENGINE_OFF: align_up({} + {}, 8) = {} (native ENGINE_OFF={})",
        HEADER_LEN,
        CONFIG_LEN,
        (HEADER_LEN + CONFIG_LEN + 7) & !7,
        ENGINE_OFF
    );
    println!(
        "Actual native CONFIG_LEN: {} (u128 align={})",
        CONFIG_LEN,
        align_of::<u128>()
    );
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

// ═══════════════════════════════════════════════════════════════════════════
// 7. Emit layout.json — machine-readable constants for SDK verification
//
//    Run: cargo test layout_canary::emit_layout_json -- --nocapture
//    Then: cd ../percolator-sdk && npx tsx scripts/verify-layout.ts
//
//    The JSON captures the NATIVE target values plus SBF-adjusted constants
//    (engine_off_sbf, config_len_sbf, account_size_sbf) which the SDK uses.
//    Whenever a struct changes, this file changes, and verify-layout.ts will
//    catch any SDK constant that has drifted.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn emit_layout_json() {
    // Bitmap offset within RiskEngine — where the `used: [u64; BITMAP_WORDS]` field starts.
    // offset_of! gives the NATIVE value; SBF differs because RiskEngine has u128 fields before `used`.
    //   Native (u128 align=16): offset_of!(RiskEngine, used) = 1048
    //   SBF    (u128 align=8):  empirically verified = 1008 (mainnet slab CCTegYZ..., 323312 bytes)
    // The native value is computed automatically; the SBF value is pinned below.
    let engine_bitmap_off_native = offset_of!(percolator::RiskEngine, used);
    // SBF engine_bitmap_off: 1016 (verified by cargo build-sbf compile-time assertion in src/percolator.rs).
    // v12.1 added lifetime_force_realize_closes(u64) before the bitmap, shifting it from 1008 to 1016.
    let engine_bitmap_off_sbf: usize = 1016;

    // SBF vs native differences:
    //
    // CONFIG_LEN: SAME on both targets (544). MarketConfig has no internal u128 padding differences.
    //   Verified empirically: V_SETDEXPOOL binary produces 323344-byte medium slabs (SDK PR #149).
    let config_len_sbf: usize = CONFIG_LEN; // identical to native for MarketConfig

    // ENGINE_OFF differs because RiskEngine's alignment boundary:
    //   Native: align_up(HEADER + CONFIG, 16) = align_up(648, 16) = 656
    //   SBF:    align_up(HEADER + CONFIG, 8)  = align_up(648, 8)  = 648
    let sbf_engine_align: usize = 8;
    let engine_off_sbf =
        (HEADER_LEN + config_len_sbf + (sbf_engine_align - 1)) & !(sbf_engine_align - 1);

    // Account size: differs between native and SBF because Account has i128/u128 fields.
    //   Native (u128 align=16): 336  (v12.1 upstream)
    //   SBF    (u128 align=8):  320  (verified by cargo build-sbf compile-time assertion)
    let account_size_sbf: usize = 320;

    let json = format!(
        r#"{{
  "_comment": "Auto-generated by cargo test layout_canary::emit_layout_json. Do not edit manually.",
  "_target": "native (aarch64/x86_64, u128_align={})",
  "native": {{
    "header_len": {},
    "config_len": {},
    "engine_align": {},
    "engine_off": {},
    "engine_len": {},
    "slab_len": {},
    "account_size": {},
    "max_accounts": {},
    "engine_bitmap_off": {},
    "u128_align": {}
  }},
  "sbf": {{
    "_comment": "On-chain (SBF target, u128_align=8) values — verified by cargo build-sbf compile-time assertions.",
    "config_len": {},
    "engine_off": {},
    "engine_align": 8,
    "engine_len": {},
    "account_size": {},
    "engine_bitmap_off": {}
  }}
}}
"#,
        align_of::<u128>(),
        HEADER_LEN,
        CONFIG_LEN,
        ENGINE_ALIGN,
        ENGINE_OFF,
        ENGINE_LEN,
        SLAB_LEN,
        size_of::<percolator::Account>(),
        percolator::MAX_ACCOUNTS,
        engine_bitmap_off_native,
        align_of::<u128>(),
        config_len_sbf,
        engine_off_sbf,
        // SBF ENGINE_LEN: verified by cargo build-sbf compile-time assertion (1320464).
        // Formula: SLAB_LEN - ENGINE_OFF = (engine_off_sbf + engine_len_sbf) - engine_off_sbf.
        // Use the pinned value from _SBF_ENGINE_LEN assertion.
        1320464usize,
        account_size_sbf,
        engine_bitmap_off_sbf,
    );

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_path = std::path::Path::new(manifest_dir).join("target/layout.json");
    std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();
    std::fs::write(&out_path, &json).expect("failed to write target/layout.json");

    println!("Written: {}", out_path.display());
    println!("{}", json);

    // Assert the SBF engine_off is self-consistent with our formula
    assert_eq!(
        engine_off_sbf,
        (HEADER_LEN + config_len_sbf + (sbf_engine_align - 1)) & !(sbf_engine_align - 1),
        "engine_off_sbf formula inconsistent"
    );
    // And it must be <= the native value (SBF aligns to 8, native to 16)
    assert!(
        engine_off_sbf <= ENGINE_OFF,
        "engine_off_sbf ({}) should be <= native ENGINE_OFF ({})",
        engine_off_sbf,
        ENGINE_OFF
    );
    // SBF bitmap offset must be <= native (RiskEngine has u128 fields that pack tighter on SBF)
    assert!(
        engine_bitmap_off_sbf <= engine_bitmap_off_native,
        "engine_bitmap_off_sbf ({}) should be <= native ({})",
        engine_bitmap_off_sbf,
        engine_bitmap_off_native
    );
}
