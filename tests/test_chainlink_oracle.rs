//! Chainlink oracle tests (Phase 3 — pre-audit coverage gap closure).
//!
//! The external audit proposal flagged `read_chainlink_price_e6` as
//! "production-ready with zero test coverage." This file closes that gap.
//!
//! Exercises every failure mode of the Chainlink read path:
//!   - Owner validation (CHAINLINK_OCR2_PROGRAM_ID)
//!   - Feed pubkey binding (expected_feed_pubkey)
//!   - Account length minimum (>= 224 bytes)
//!   - Non-positive price rejection (answer <= 0)
//!   - Decimals out-of-range rejection (> 18)
//!   - Timestamp overflow rejection (> i64::MAX)
//!   - Staleness rejection (age > max_staleness_secs OR age < 0)
//!   - Zero price after scaling rejection
//!   - Engine dispatch via read_engine_price_e6 (owner-based routing)
//!   - Decimal handling at edges (0, 6, 8, 18)
//!
//! Chainlink OCR2 State account layout (from percolator-prog/src/percolator.rs):
//!   offset 138: decimals (u8)
//!   offset 208: timestamp (u64, unix seconds)
//!   offset 216: answer (i128, 16 bytes)
//!   minimum length: 224 bytes

#![allow(
    clippy::assertions_on_constants,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
)]

use percolator_prog::error::PercolatorError;
use percolator_prog::oracle::read_chainlink_price_e6;
use solana_program::account_info::AccountInfo;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

// ── Chainlink OCR2 State program ID (HEvSKofvBgfaexv23kMabbYqxasxU3mQ4ibBMEmJWHny) ──
const CHAINLINK_OCR2_BYTES: [u8; 32] = [
    0xf1, 0x4b, 0xf6, 0x5a, 0xd5, 0x6b, 0xd2, 0xba, 0x71, 0x5e, 0x45, 0x74, 0x2c, 0x23, 0x1f, 0x27,
    0xd6, 0x36, 0x21, 0xcf, 0x5b, 0x77, 0x8f, 0x37, 0xc1, 0xa2, 0x48, 0x95, 0x1d, 0x17, 0x56, 0x02,
];

// ── Pyth Receiver program ID (for cross-oracle dispatch tests) ──
const PYTH_RECEIVER_BYTES: [u8; 32] = [
    0x0c, 0xb7, 0xfa, 0xbb, 0x52, 0xf7, 0xa6, 0x48, 0xbb, 0x5b, 0x31, 0x7d, 0x9a, 0x01, 0x8b, 0x90,
    0x57, 0xcb, 0x02, 0x47, 0x74, 0xfa, 0xfe, 0x01, 0xe6, 0xc4, 0xdf, 0x98, 0xcc, 0x38, 0x58, 0x81,
];

// ── Account layout offsets (from src/percolator.rs) ──
// 2026-04-17 fix: CL_MIN_LEN was 224 pre-audit; raised to 232 to fit the
// 16-byte answer field at offset 216. Previously data[216..232] would
// panic on any account in [224, 232) bytes (slice OOB in try_into).
const CL_MIN_LEN: usize = 232;
const CL_OFF_DECIMALS: usize = 138;
const CL_OFF_TIMESTAMP: usize = 208;
const CL_OFF_ANSWER: usize = 216;

/// A mock AccountInfo carrier compatible with `solana_program::account_info::AccountInfo`.
struct TestAccount {
    key: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data: Vec<u8>,
}

impl TestAccount {
    fn new(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> Self {
        Self {
            key,
            owner,
            lamports: 1_000_000,
            data,
        }
    }

    fn to_info<'a>(&'a mut self) -> AccountInfo<'a> {
        AccountInfo::new(
            &self.key,
            false, // is_signer
            false, // is_writable
            &mut self.lamports,
            &mut self.data,
            &self.owner,
            false, // executable
            0,     // rent_epoch
        )
    }
}

/// Build a 224-byte mock Chainlink OCR2 State account.
///
/// `decimals`:   u8 at offset 138. Real Chainlink feeds typically use 8.
/// `timestamp`:  u64 at offset 208 (unix seconds).
/// `answer`:     i128 at offset 216 (raw price before decimal scaling).
fn make_chainlink_account(decimals: u8, timestamp: u64, answer: i128) -> Vec<u8> {
    let mut data = vec![0u8; CL_MIN_LEN];
    data[CL_OFF_DECIMALS] = decimals;
    data[CL_OFF_TIMESTAMP..CL_OFF_TIMESTAMP + 8].copy_from_slice(&timestamp.to_le_bytes());
    data[CL_OFF_ANSWER..CL_OFF_ANSWER + 16].copy_from_slice(&answer.to_le_bytes());
    data
}

// ============================================================================
// § 1 — Happy-path tests
// ============================================================================

/// Standard BTC feed: $65,432.10 with 8 decimals = 6_543_210_000_000 raw.
/// Expected e6: 65_432_100_000 (scale = 6 - 8 = -2, divide by 100).
#[test]
fn chainlink_happy_path_btc_8_decimals() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();
    let now = 1_700_000_100i64; // slightly after timestamp
    let max_stale = 60u64;

    // Chainlink BTC/USD: 65_432.10 at 8 decimals
    let answer: i128 = 6_543_210_000_000;
    let data = make_chainlink_account(8, 1_700_000_050, answer);
    let mut acct = TestAccount::new(key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, now, max_stale)
        .expect("happy path should succeed");

    // answer * 10^(6-8) = 6_543_210_000_000 / 100 = 65_432_100_000
    assert_eq!(price, 65_432_100_000, "BTC at $65,432.10 e6");
}

/// 6-decimal feed matches e6 directly (no rescaling): $1.50 → 1_500_000.
#[test]
fn chainlink_6_decimals_no_scaling() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(6, 1_000, 1_500_000);
    let mut acct = TestAccount::new(key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect("6-decimal happy path should succeed");

    assert_eq!(price, 1_500_000, "scale=0 when decimals == 6");
}

/// Zero-decimal feed: answer is already integer. $100 → 100 answer, 100_000_000 e6.
#[test]
fn chainlink_0_decimals_scales_up_by_1e6() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Answer = 100 (integer), decimals = 0 → scale up by 10^6.
    let data = make_chainlink_account(0, 1_000, 100);
    let mut acct = TestAccount::new(key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect("0-decimal happy path should succeed");

    assert_eq!(price, 100_000_000, "100 * 10^6 = 100_000_000");
}

/// Max-supported decimals (18) scales DOWN by 10^12: 1e18 → 1e6.
#[test]
fn chainlink_18_decimals_scales_down() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // 1 * 10^18 raw with 18 decimals represents $1.00; e6 result = 1_000_000.
    let data = make_chainlink_account(18, 1_000, 1_000_000_000_000_000_000i128);
    let mut acct = TestAccount::new(key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect("18-decimal happy path should succeed");

    assert_eq!(price, 1_000_000, "1e18 / 10^12 = 1_000_000 ($1.00)");
}

/// Freshest-allowed staleness (age == max) should succeed (boundary inclusive).
#[test]
fn chainlink_staleness_at_boundary_succeeds() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // max_stale = 60, age = exactly 60 → should succeed.
    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_060, 60)
        .expect("boundary staleness should succeed");

    assert_eq!(price, 1_000_000, "scale=-2 * 100_000_000 = 1_000_000");
}

// ============================================================================
// § 2 — Feed pubkey binding (InitMarket-pinned identity)
// ============================================================================

/// Wrong feed pubkey MUST be rejected. This is the primary defense against
/// oracle substitution attacks — the feed pubkey is pinned at InitMarket
/// and any other Chainlink-owned account must fail this check.
#[test]
fn chainlink_wrong_feed_pubkey_rejected() {
    let acct_key = Pubkey::new_unique();
    let expected_feed = Pubkey::new_unique().to_bytes(); // DIFFERENT from acct.key

    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(acct_key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("wrong feed pubkey must be rejected");
    assert_eq!(
        err,
        PercolatorError::InvalidOracleKey.into(),
        "Expected InvalidOracleKey, got {:?}",
        err
    );
}

/// All-zero feed pubkey is still valid if the account key also happens to be
/// all-zero — the check is strict equality, not a special sentinel.
/// (In practice the program rejects all-zero feeds at InitMarket, but the
/// oracle read itself does not enforce a non-zero requirement.)
#[test]
fn chainlink_zero_feed_pubkey_matching_accepted() {
    let acct_key = Pubkey::default(); // all zeros
    let expected_feed = [0u8; 32]; // matches

    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(acct_key, owner, data);

    let (price, _publish_time) = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect("strict equality check does not special-case zero pubkey");
    assert_eq!(price, 1_000_000);
}

// ============================================================================
// § 3 — Account length validation
// ============================================================================

/// Account shorter than CL_MIN_LEN (224 bytes) must be rejected.
#[test]
fn chainlink_account_too_short_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = vec![0u8; CL_MIN_LEN - 1]; // 223 bytes, one short
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("short account must be rejected");
    assert_eq!(err, ProgramError::InvalidAccountData);
}

/// Account at exactly CL_MIN_LEN bytes with zeroed price is rejected by the
/// non-positive-price check (not the length check). This confirms the
/// boundary is inclusive.
#[test]
fn chainlink_account_at_min_len_passes_length_check() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = vec![0u8; CL_MIN_LEN]; // answer = 0, timestamp = 0
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("zero answer should be rejected (not length)");
    // The non-positive price check fires BEFORE staleness, so we expect OracleInvalid.
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

/// REGRESSION (2026-04-17 Phase 3): The pre-fix CL_MIN_LEN of 224 was too
/// small — CL_OFF_ANSWER is at 216 with 16-byte i128, so the slice read
/// data[216..232] would panic on any account of length in [224, 232).
/// Confirm: lengths 224, 225, ..., 231 are now rejected gracefully by the
/// CL_MIN_LEN=232 gate rather than panicking on slice-OOB.
#[test]
fn chainlink_length_in_old_danger_zone_rejected_gracefully() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Sweep the pre-fix danger zone.
    for len in 224..232 {
        let data = vec![0u8; len];
        let mut acct = TestAccount::new(key, owner, data);
        let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
            .expect_err(&format!("length {} must be rejected, not panic", len));
        assert_eq!(
            err, ProgramError::InvalidAccountData,
            "length {} must hit the CL_MIN_LEN gate",
            len
        );
    }
}

// ============================================================================
// § 4 — Price validation (answer must be > 0)
// ============================================================================

#[test]
fn chainlink_negative_price_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Negative price (e.g., Swiss Franc deposit rate era, or corrupt feed)
    let data = make_chainlink_account(8, 1_000, -1i128);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("negative price must be rejected");
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

#[test]
fn chainlink_zero_answer_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(8, 1_000, 0i128);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("zero answer must be rejected");
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

/// Price that scales to zero (e.g., 999 with decimals=12 → 999 / 10^6 = 0)
/// must also be rejected. This catches truncation-to-zero from legitimate
/// feed structure, not just zero raw answer.
#[test]
fn chainlink_price_scales_to_zero_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // decimals=12 → scale = 6 - 12 = -6 → divide by 10^6.
    // answer = 999 → 999 / 10^6 = 0 (integer division).
    let data = make_chainlink_account(12, 1_000, 999i128);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("scale-to-zero must be rejected");
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

// ============================================================================
// § 5 — Decimals validation (must be ≤ 18 = MAX_EXPO_ABS)
// ============================================================================

#[test]
fn chainlink_decimals_above_18_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // decimals = 19 → out of range.
    let data = make_chainlink_account(19, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("decimals > 18 must be rejected");
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

#[test]
fn chainlink_decimals_at_max_18_accepted() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // decimals = 18 (boundary) with a small-enough answer to avoid truncation-to-zero.
    let data = make_chainlink_account(18, 1_000, 1_000_000_000_000_000_000i128);
    let mut acct = TestAccount::new(key, owner, data);

    let result = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100);
    assert!(result.is_ok(), "decimals = 18 must succeed (boundary inclusive)");
}

/// Decimals = u8::MAX (255) is well above 18 and MUST be rejected.
/// Without this guard, 10^255 would overflow the u128 in the scale math.
#[test]
fn chainlink_decimals_u8_max_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(255, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("decimals = 255 must be rejected");
    assert_eq!(err, PercolatorError::OracleInvalid.into());
}

// ============================================================================
// § 6 — Staleness validation
// ============================================================================

#[test]
fn chainlink_stale_timestamp_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Max staleness = 60s, age = 61s → rejected.
    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_061, 60)
        .expect_err("age > max_staleness must be rejected");
    assert_eq!(err, PercolatorError::OracleStale.into());
}

/// Future timestamp (age < 0) must be rejected — a feed claiming to be
/// from the future is corrupt or malicious.
#[test]
fn chainlink_future_timestamp_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Timestamp AFTER now_unix_ts → age is negative.
    let data = make_chainlink_account(8, 2_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_000, 60)
        .expect_err("future timestamp must be rejected");
    assert_eq!(err, PercolatorError::OracleStale.into());
}

/// Timestamp exceeding i64::MAX (year 2262+) must be rejected before the
/// i64 cast, preventing a signed-overflow miscomparison.
#[test]
fn chainlink_timestamp_overflow_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // timestamp = u64::MAX → overflows i64 on cast.
    let data = make_chainlink_account(8, u64::MAX, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_000, 60)
        .expect_err("timestamp overflow must be rejected");
    assert_eq!(err, PercolatorError::OracleStale.into());
}

/// `max_staleness = 0` effectively requires timestamp == now_unix_ts.
/// age = 0 is <= 0, which passes the "age < 0" check and then 0 <= 0 passes
/// the staleness check. So same-second timestamp is accepted with max_stale=0.
#[test]
fn chainlink_zero_max_stale_accepts_current_second() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    // age = 0 with max_stale = 0 → should succeed (0 <= 0).
    let result = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_000, 0);
    assert!(result.is_ok(), "age=0 with max_stale=0 should succeed");
}

/// `max_staleness = 0` rejects even 1-second-old timestamps.
#[test]
fn chainlink_zero_max_stale_rejects_1s_old() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(8, 1_000, 100_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_001, 0)
        .expect_err("age=1 with max_stale=0 must be rejected");
    assert_eq!(err, PercolatorError::OracleStale.into());
}

// ============================================================================
// § 7 — Scale overflow safety (SECURITY C3 regression test)
// ============================================================================

/// Extreme case: decimals=0 means scale = 6, multiply answer by 10^6.
/// answer = i128::MAX means the multiplication overflows u128.
/// Must be rejected with EngineOverflow, not silently wrap.
#[test]
fn chainlink_scale_up_overflow_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // decimals=0 → scale=+6 → answer * 10^6.
    // answer = i128::MAX → overflows u128 on the checked_mul.
    let data = make_chainlink_account(0, 1_000, i128::MAX);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("scale-up overflow must be rejected");
    assert_eq!(err, PercolatorError::EngineOverflow.into());
}

/// A price that fits after scale-up but exceeds u64::MAX must be rejected.
/// u64::MAX ≈ 1.84e19; any e6 price above that is unrepresentable.
#[test]
fn chainlink_price_above_u64_max_rejected() {
    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // decimals=6 → scale=0 → price = answer directly.
    // Pick answer > u64::MAX to hit the `> u64::MAX` check.
    let too_big: i128 = (u64::MAX as i128) + 1;
    let data = make_chainlink_account(6, 1_000, too_big);
    let mut acct = TestAccount::new(key, owner, data);

    let err = read_chainlink_price_e6(&acct.to_info(), &expected_feed, 1_050, 100)
        .expect_err("price > u64::MAX must be rejected");
    assert_eq!(err, PercolatorError::EngineOverflow.into());
}

// ============================================================================
// § 8 — Engine dispatch (read_engine_price_e6 routes to Chainlink)
// ============================================================================

#[test]
fn chainlink_dispatched_via_engine_price_reader() {
    use percolator_prog::oracle::read_engine_price_e6;

    let key = Pubkey::new_unique();
    let owner = Pubkey::new_from_array(CHAINLINK_OCR2_BYTES);
    let expected_feed = key.to_bytes();

    // Standard $100 at 8 decimals = 10_000_000_000 raw.
    let data = make_chainlink_account(8, 1_000, 10_000_000_000);
    let mut acct = TestAccount::new(key, owner, data);

    // read_engine_price_e6(ai, feed, now, max_stale, conf_bps, invert, unit_scale)
    // conf_bps is ignored by Chainlink path; invert=0, unit_scale=0 → raw pass-through.
    let (price, _publish_time) = read_engine_price_e6(&acct.to_info(), &expected_feed, 1_050, 100, 0, 0, 0)
        .expect("dispatch to Chainlink should succeed");

    assert_eq!(price, 100_000_000, "$100 e6");
}

/// Engine dispatch with non-Chainlink owner routes to Pyth path instead.
/// This test confirms the owner-based routing isn't accidentally sending
/// Chainlink reads to the Pyth decoder (which would misinterpret offsets).
#[test]
fn chainlink_wrong_owner_does_not_dispatch_to_chainlink() {
    use percolator_prog::oracle::read_engine_price_e6;

    let key = Pubkey::new_unique();
    // Owner = Pyth, not Chainlink.
    let pyth_owner = Pubkey::new_from_array(PYTH_RECEIVER_BYTES);
    let expected_feed = key.to_bytes();

    // Chainlink-formatted data with Pyth owner → Pyth decoder runs, will find
    // invalid Pyth fields (wrong verification_level, wrong feed_id position, etc.)
    // and must reject, not silently succeed with Chainlink semantics.
    let data = make_chainlink_account(8, 1_000, 10_000_000_000);
    let mut acct = TestAccount::new(key, pyth_owner, data);

    let result = read_engine_price_e6(&acct.to_info(), &expected_feed, 1_050, 100, 0, 0, 0);
    assert!(
        result.is_err(),
        "Chainlink-formatted data under Pyth owner must not succeed"
    );
}

// ============================================================================
// § 9 — Unknown owner (neither Pyth nor Chainlink)
// ============================================================================

/// An account owned by neither Pyth nor Chainlink must be rejected.
/// Prevents a third-party program from serving as an oracle by accident.
/// Note: the test build may allow this via a fallback; we document behavior.
#[test]
#[cfg(not(feature = "test"))]
fn chainlink_unknown_owner_rejected_in_production() {
    use percolator_prog::oracle::read_engine_price_e6;

    let key = Pubkey::new_unique();
    let random_owner = Pubkey::new_unique(); // random third-party program
    let expected_feed = key.to_bytes();

    let data = make_chainlink_account(8, 1_000, 10_000_000_000);
    let mut acct = TestAccount::new(key, random_owner, data);

    let result = read_engine_price_e6(&acct.to_info(), &expected_feed, 1_050, 100, 0, 0, 0);
    assert!(
        result.is_err(),
        "unknown owner must be rejected in production build"
    );
}
