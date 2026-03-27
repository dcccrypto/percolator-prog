mod common;
#[allow(unused_imports)]
use common::*;

use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    sysvar,
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState};

/// Security Issue: Hyperp mode requires non-zero initial_mark_price_e6
///
/// If Hyperp mode is enabled (index_feed_id == [0; 32]) but initial_mark_price_e6 == 0,
/// the market would have no valid price and trades would fail with OracleInvalid.
/// This test verifies the validation in InitMarket rejects this configuration.
#[test]
fn test_hyperp_rejects_zero_initial_mark_price() {
    let path = program_path();

    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    let program_bytes = std::fs::read(&path).expect("Failed to read program");
    svm.add_program(program_id, &program_bytes);

    let payer = Keypair::new();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
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

    let dummy_ata = Pubkey::new_unique();
    svm.set_account(
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

    svm.set_sysvar(&Clock {
        slot: 100,
        unix_timestamp: 100,
        ..Clock::default()
    });

    // Try to init market with Hyperp mode (feed_id = 0) but initial_mark_price = 0
    // This should FAIL because Hyperp mode requires a non-zero initial price
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(dummy_ata, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: encode_init_market_full_v2(
            &payer.pubkey(),
            &mint,
            &[0u8; 32], // Hyperp mode: feed_id = 0
            0,          // invert
            0,          // initial_mark_price_e6 = 0 (INVALID for Hyperp!)
            0,          // warmup
        ),
    };

    // Snapshot state before the failing init attempt.
    // Header+config region should remain unchanged on rejected tx.
    const HEADER_CONFIG_LEN: usize = 520;
    const NUM_USED_OFF: usize = 1640;
    let slab_before = svm.get_account(&slab).unwrap().data;
    let vault_before = {
        let vault_data = svm.get_account(&vault).unwrap().data;
        TokenAccount::unpack(&vault_data).unwrap().amount
    };
    let used_before = u16::from_le_bytes(slab_before[NUM_USED_OFF..NUM_USED_OFF + 2].try_into().unwrap());

    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    assert!(
        result.is_err(),
        "SECURITY: InitMarket should reject Hyperp mode with zero initial_mark_price_e6. \
         Got: {:?}",
        result
    );

    let slab_after = svm.get_account(&slab).unwrap().data;
    let vault_after = {
        let vault_data = svm.get_account(&vault).unwrap().data;
        TokenAccount::unpack(&vault_data).unwrap().amount
    };
    let used_after = u16::from_le_bytes(slab_after[NUM_USED_OFF..NUM_USED_OFF + 2].try_into().unwrap());

    assert_eq!(
        &slab_after[..HEADER_CONFIG_LEN],
        &slab_before[..HEADER_CONFIG_LEN],
        "Rejected Hyperp init must not mutate slab header/config"
    );
    assert_eq!(
        used_after, used_before,
        "Rejected Hyperp init must not change num_used_accounts"
    );
    assert_eq!(
        vault_after, vault_before,
        "Rejected Hyperp init must not move vault tokens"
    );

    println!("HYPERP VALIDATION VERIFIED: Rejects zero initial_mark_price_e6 in Hyperp mode");
}

/// Test: Hyperp mode InitMarket succeeds with valid initial_mark_price
#[test]
fn test_hyperp_init_market_with_valid_price() {
    let path = program_path();

    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    let program_bytes = std::fs::read(&path).expect("Failed to read program");
    svm.add_program(program_id, &program_bytes);

    let payer = Keypair::new();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
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

    let dummy_ata = Pubkey::new_unique();
    svm.set_account(
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

    svm.set_sysvar(&Clock {
        slot: 100,
        unix_timestamp: 100,
        ..Clock::default()
    });

    // Init market with Hyperp mode and valid initial_mark_price
    let initial_price_e6 = 100_000_000u64; // $100 in e6 format

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(dummy_ata, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: encode_init_market_full_v2(
            &payer.pubkey(),
            &mint,
            &[0u8; 32],       // Hyperp mode: feed_id = 0
            0,                // invert
            initial_price_e6, // Valid initial mark price
            0,                // warmup
        ),
    };

    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    assert!(
        result.is_ok(),
        "Hyperp InitMarket with valid initial_mark_price should succeed. Got: {:?}",
        result
    );

    // Verify actual initialized config state, not just tx success.
    const HEADER_MAGIC_OFF: usize = 0;
    const CONFIG_OFF: usize = 72; // size_of::<SlabHeader>()
    const FEED_ID_OFF: usize = CONFIG_OFF + 64;
    const INVERT_OFF: usize = CONFIG_OFF + 107;
    const AUTH_PRICE_OFF: usize = CONFIG_OFF + 288;
    const ORACLE_CAP_OFF: usize = CONFIG_OFF + 304;
    const INDEX_OFF: usize = CONFIG_OFF + 312;
    const NUM_USED_OFF: usize = 1640;

    let slab_data = svm.get_account(&slab).unwrap().data;
    let magic = u64::from_le_bytes(slab_data[HEADER_MAGIC_OFF..HEADER_MAGIC_OFF + 8].try_into().unwrap());
    let mark = u64::from_le_bytes(slab_data[AUTH_PRICE_OFF..AUTH_PRICE_OFF + 8].try_into().unwrap());
    let index = u64::from_le_bytes(slab_data[INDEX_OFF..INDEX_OFF + 8].try_into().unwrap());
    let cap = u64::from_le_bytes(slab_data[ORACLE_CAP_OFF..ORACLE_CAP_OFF + 8].try_into().unwrap());
    let used = u16::from_le_bytes(slab_data[NUM_USED_OFF..NUM_USED_OFF + 2].try_into().unwrap());

    assert_ne!(magic, 0, "InitMarket must write a non-zero slab magic");
    assert_eq!(
        &slab_data[FEED_ID_OFF..FEED_ID_OFF + 32],
        &[0u8; 32],
        "Hyperp market must store zeroed feed id"
    );
    assert_eq!(slab_data[INVERT_OFF], 0, "invert flag should be 0 for this test");
    assert_eq!(
        mark, initial_price_e6,
        "Hyperp mark must equal initial_mark_price_e6 at init"
    );
    assert_eq!(
        index, initial_price_e6,
        "Hyperp index must equal initial_mark_price_e6 at init"
    );
    assert_eq!(cap, 10_000, "Hyperp default oracle cap should be 1% per slot");
    assert_eq!(used, 0, "No user/LP accounts should exist immediately after market init");

    println!("HYPERP INIT VERIFIED: Market initialized with $100 initial mark/index price");
}

/// Test: Hyperp mode with inverted market (e.g., SOL/USD perp)
///
/// For inverted markets, the raw oracle price is inverted: inverted = 1e12 / raw
/// Example: SOL/USD oracle returns ~$138 (138_000_000 in e6)
///          Inverted = 1e12 / 138_000_000 = ~7246 (price in SOL per USD)
///
/// In Hyperp mode with invert=1:
/// - initial_mark_price_e6 provided as raw price (e.g., 138_000_000)
/// - InitMarket applies inversion internally
/// - Stored mark/index are in inverted form (~7246)
#[test]
fn test_hyperp_init_market_with_inverted_price() {
    let path = program_path();

    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    let program_bytes = std::fs::read(&path).expect("Failed to read program");
    svm.add_program(program_id, &program_bytes);

    let payer = Keypair::new();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
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

    let dummy_ata = Pubkey::new_unique();
    svm.set_account(
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

    svm.set_sysvar(&Clock {
        slot: 100,
        unix_timestamp: 100,
        ..Clock::default()
    });

    // Hyperp mode with inverted market
    // Raw price: $138 (SOL/USD) = 138_000_000 in e6
    // After inversion: 1e12 / 138_000_000 = ~7246 (USD/SOL)
    let raw_price_e6 = 138_000_000u64; // $138 in e6 format
    let expected_inverted = 1_000_000_000_000u64 / raw_price_e6; // ~7246

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(dummy_ata, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: encode_init_market_full_v2(
            &payer.pubkey(),
            &mint,
            &[0u8; 32],   // Hyperp mode: feed_id = 0
            1,            // invert = 1 (inverted market)
            raw_price_e6, // Raw price, will be inverted internally
            0,            // warmup
        ),
    };

    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);

    assert!(
        result.is_ok(),
        "Hyperp InitMarket with inverted price should succeed. Got: {:?}",
        result
    );

    // Verify inverted Hyperp initialization state.
    const HEADER_MAGIC_OFF: usize = 0;
    const CONFIG_OFF: usize = 72; // size_of::<SlabHeader>()
    const FEED_ID_OFF: usize = CONFIG_OFF + 64;
    const INVERT_OFF: usize = CONFIG_OFF + 107;
    const AUTH_PRICE_OFF: usize = CONFIG_OFF + 288;
    const ORACLE_CAP_OFF: usize = CONFIG_OFF + 304;
    const INDEX_OFF: usize = CONFIG_OFF + 312;
    const NUM_USED_OFF: usize = 1640;

    let slab_data = svm.get_account(&slab).unwrap().data;
    let magic = u64::from_le_bytes(slab_data[HEADER_MAGIC_OFF..HEADER_MAGIC_OFF + 8].try_into().unwrap());
    let mark = u64::from_le_bytes(slab_data[AUTH_PRICE_OFF..AUTH_PRICE_OFF + 8].try_into().unwrap());
    let index = u64::from_le_bytes(slab_data[INDEX_OFF..INDEX_OFF + 8].try_into().unwrap());
    let cap = u64::from_le_bytes(slab_data[ORACLE_CAP_OFF..ORACLE_CAP_OFF + 8].try_into().unwrap());
    let used = u16::from_le_bytes(slab_data[NUM_USED_OFF..NUM_USED_OFF + 2].try_into().unwrap());

    assert_ne!(magic, 0, "InitMarket must write a non-zero slab magic");
    assert_eq!(
        &slab_data[FEED_ID_OFF..FEED_ID_OFF + 32],
        &[0u8; 32],
        "Hyperp market must store zeroed feed id"
    );
    assert_eq!(slab_data[INVERT_OFF], 1, "invert flag should be 1 for inverted Hyperp init");
    assert_eq!(
        mark, expected_inverted,
        "Hyperp mark must be stored as inverted initial price"
    );
    assert_eq!(
        index, expected_inverted,
        "Hyperp index must be stored as inverted initial price"
    );
    assert_eq!(cap, 10_000, "Hyperp default oracle cap should be 1% per slot");
    assert_eq!(used, 0, "No user/LP accounts should exist immediately after market init");

    println!("HYPERP INVERTED MARKET VERIFIED:");
    println!(
        "  Raw price: {} (${:.2})",
        raw_price_e6,
        raw_price_e6 as f64 / 1_000_000.0
    );
    println!(
        "  Expected inverted: {} (~{:.4} SOL/USD)",
        expected_inverted,
        expected_inverted as f64 / 1_000_000.0
    );
    println!("  Mark/Index stored in inverted form for SOL-denominated perp");
}

/// Test 7: Oracle price impact - crank succeeds at different prices
#[test]
fn test_comprehensive_oracle_price_impact_on_pnl() {
    program_path();

    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 100_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 10_000_000_000);

    // Top up insurance to prevent force-realize and dust-close (must exceed threshold after EWMA update)
    let ins_payer = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&ins_payer, 1_000_000_000);
    let vault_initial = env.vault_balance();

    // Open long at $138
    let size: i128 = 10_000_000;
    env.trade(&user, &lp, lp_idx, user_idx, size);

    // Price goes to $150 - crank. User is long, so mark-to-market PnL should be positive.
    env.set_slot_and_price(200, 150_000_000);
    env.crank();
    assert_eq!(env.vault_balance(), vault_initial, "Vault conserved at $150");
    // For an open position, PnL is tracked in the pnl field (mark-to-market).
    // Capital settles during touch_account (lazy), not during crank.
    // Check that PnL is positive (long position profits at higher price).
    let pnl_at_150 = env.read_account_pnl(user_idx);
    let cap_at_150 = env.read_account_capital(user_idx);
    // Either PnL is positive OR capital increased (if warmup already converted it)
    assert!(
        pnl_at_150 > 0 || cap_at_150 > 10_000_000_000,
        "Long position should have gained value at $150 (up from $138): pnl={} cap={}",
        pnl_at_150, cap_at_150
    );

    // Price drops to $120 - crank. User is long, PnL should be negative.
    env.set_slot_and_price(300, 120_000_000);
    env.crank();
    assert_eq!(env.vault_balance(), vault_initial, "Vault conserved at $120");
    let pnl_at_120 = env.read_account_pnl(user_idx);
    let cap_at_120 = env.read_account_capital(user_idx);
    // At $120 (below entry $138), long position should have negative or reduced PnL
    assert!(
        pnl_at_120 < pnl_at_150,
        "Long position should lose value at $120 (below $150): pnl={} was {}, cap={} was {}",
        pnl_at_120, pnl_at_150, cap_at_120, cap_at_150
    );

    // Price recovers to $140 - crank. PnL should improve from $120 level.
    env.set_slot_and_price(400, 140_000_000);
    env.crank();
    assert_eq!(env.vault_balance(), vault_initial, "Vault conserved at $140");
    let pnl_at_140 = env.read_account_pnl(user_idx);
    assert!(
        pnl_at_140 > pnl_at_120,
        "Long position should gain value at $140 (up from $120): pnl={} was {}",
        pnl_at_140, pnl_at_120
    );

    // Position must still be open
    assert_ne!(env.read_account_position(user_idx), 0, "Position must persist through price changes");
}

/// CRITICAL: Admin oracle mechanism for Hyperp mode
#[test]
fn test_critical_admin_oracle_authority() {
    program_path();

    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    let oracle_authority = Keypair::new();
    let attacker = Keypair::new();
    env.svm
        .airdrop(&oracle_authority.pubkey(), 1_000_000_000)
        .unwrap();
    env.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();

    // Attacker tries to set oracle authority - should fail
    let result = env.try_set_oracle_authority(&attacker, &attacker.pubkey());
    assert!(
        result.is_err(),
        "SECURITY: Non-admin should not set oracle authority"
    );
    println!("SetOracleAuthority by non-admin: REJECTED (correct)");

    // Admin sets oracle authority - should succeed
    let result = env.try_set_oracle_authority(&admin, &oracle_authority.pubkey());
    assert!(
        result.is_ok(),
        "Admin should set oracle authority: {:?}",
        result
    );
    println!("SetOracleAuthority by admin: ACCEPTED (correct)");

    // Attacker tries to push price - should fail
    let result = env.try_push_oracle_price(&attacker, 150_000_000, 200);
    assert!(
        result.is_err(),
        "SECURITY: Non-authority should not push oracle price"
    );
    println!("PushOraclePrice by non-authority: REJECTED (correct)");

    // Oracle authority pushes price - should succeed
    let result = env.try_push_oracle_price(&oracle_authority, 150_000_000, 200);
    assert!(
        result.is_ok(),
        "Oracle authority should push price: {:?}",
        result
    );
    println!("PushOraclePrice by authority: ACCEPTED (correct)");

    println!("CRITICAL TEST PASSED: Admin oracle mechanism verified");
}

/// CRITICAL: SetOraclePriceCap admin-only
#[test]
fn test_critical_set_oracle_price_cap_authorization() {
    program_path();

    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    let attacker = Keypair::new();
    env.svm.airdrop(&attacker.pubkey(), 1_000_000_000).unwrap();

    // Attacker tries to set price cap - should fail
    let result = env.try_set_oracle_price_cap(&attacker, 10000);
    assert!(
        result.is_err(),
        "SECURITY: Non-admin should not set oracle price cap"
    );
    println!("SetOraclePriceCap by non-admin: REJECTED (correct)");

    // Admin sets price cap - should succeed
    let result = env.try_set_oracle_price_cap(&admin, 10000);
    assert!(
        result.is_ok(),
        "Admin should set oracle price cap: {:?}",
        result
    );
    println!("SetOraclePriceCap by admin: ACCEPTED (correct)");

    println!("CRITICAL TEST PASSED: SetOraclePriceCap authorization enforced");
}

/// Test: Hyperp mode index smoothing bypass via multiple cranks in same slot
///
/// SECURITY RESEARCH: In Hyperp mode, the index should smoothly move toward the mark
/// price, rate-limited by oracle_price_cap_e2bps (default 1% per slot).
///
/// Potential issue: If crank is called twice in the same slot:
/// 1. First crank: dt > 0, index rate-limited toward mark
/// 2. Trade: mark moves (clamped against index)
/// 3. Second crank: dt = 0, clamp_toward_with_dt returns index (no movement)
///
/// Bug #9 fix: When dt=0, index stays unchanged instead of jumping to mark.
#[test]
fn test_hyperp_index_smoothing_multiple_cranks_same_slot() {
    let path = program_path();

    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    let program_bytes = std::fs::read(&path).expect("Failed to read program");
    svm.add_program(program_id, &program_bytes);

    let payer = Keypair::new();
    let slab = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let (vault_pda, _) = Pubkey::find_program_address(&[b"vault", slab.as_ref()], &program_id);
    let vault = Pubkey::new_unique();
    let dummy_oracle = Pubkey::new_unique();

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

    // Dummy oracle (not used in Hyperp mode, but account must exist)
    svm.set_account(
        dummy_oracle,
        Account {
            lamports: 1_000_000,
            data: vec![0u8; 100],
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let dummy_ata = Pubkey::new_unique();
    svm.set_account(
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

    // Start at slot 100
    svm.set_sysvar(&Clock {
        slot: 100,
        unix_timestamp: 100,
        ..Clock::default()
    });

    // Init market with Hyperp mode (feed_id = 0)
    let initial_price_e6 = 100_000_000u64; // $100

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(sysvar::rent::ID, false),
            AccountMeta::new_readonly(dummy_ata, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: encode_init_market_hyperp(&payer.pubkey(), &mint, initial_price_e6),
    };

    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).expect("InitMarket failed");
    println!("Hyperp market initialized with mark=index=$100");

    // Advance to slot 200 and crank
    svm.set_sysvar(&Clock {
        slot: 200,
        unix_timestamp: 200,
        ..Clock::default()
    });

    let crank_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(dummy_oracle, false),
        ],
        data: encode_crank_permissionless(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), crank_ix.clone()],
        Some(&payer.pubkey()),
        &[&payer],
        svm.latest_blockhash(),
    );
    let result1 = svm.send_transaction(tx);
    println!("First crank in slot 200: {:?}", result1.is_ok());
    assert!(result1.is_ok(), "First crank should succeed: {:?}", result1);

    // Call crank again in the SAME slot (slot 200)
    // Expire old blockhash and get new one to make transaction distinct
    svm.expire_blockhash();
    let new_blockhash = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), crank_ix.clone()],
        Some(&payer.pubkey()),
        &[&payer],
        new_blockhash,
    );
    let result2 = svm.send_transaction(tx);
    println!("Second crank in slot 200: {:?}", result2);
    if let Err(ref e) = result2 {
        println!("Second crank error: {:?}", e);
    }

    // SECURITY VERIFICATION: Multiple cranks in the same slot are ALLOWED
    // but the index must NOT move (Bug #9 fix).

    assert!(
        result2.is_ok(),
        "Second crank should succeed in same slot: {:?}",
        result2
    );

    // Bug #9 CRITICAL CHECK: Read last_effective_price_e6 (index) from slab.
    // The index must be identical before and after the same-slot crank.
    // Before Bug #9 fix, dt=0 caused clamp_toward_with_dt to return mark
    // instead of index, allowing the index to jump to mark in a single slot.
    let slab_data = svm.get_account(&slab).unwrap().data;
    const INDEX_OFF: usize = 384; // last_effective_price_e6 offset in config
    let index_after = u64::from_le_bytes(slab_data[INDEX_OFF..INDEX_OFF + 8].try_into().unwrap());
    assert_eq!(
        index_after, initial_price_e6,
        "Bug #9 regression: index moved during same-slot crank! \
         expected={} (initial), got={}. Index should not move when dt=0.",
        initial_price_e6, index_after
    );
}

