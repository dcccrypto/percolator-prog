# PERC-627: Creator Stake Lock + Adversarial Wallet Tracking

## Overview

Market creators must lock a minimum LP position for 90 days with the same P&L exposure as any LP. On-chain tracking detects if the creator wallet extracts disproportionate value from the LP vault. If extraction exceeds a statistical threshold (>2σ), the creator's fee share auto-redirects to the LP insurance fund.

## Goals
1. **Skin in the game**: Creator must take LP risk on their own market
2. **Anti-manipulation**: Detect and penalize insider extraction
3. **Formally verifiable**: All rules expressible as Kani-provable invariants

## On-Chain Storage

### CreatorStakeLock PDA
Seeds: `["creator_lock", slab_pubkey]`
Size: 96 bytes

```rust
struct CreatorStakeLock {
    magic: u64,              // "CRTRLOCK"
    bump: u8,
    _pad: [u8; 7],
    creator: [u8; 32],       // creator wallet pubkey
    lock_start_slot: u64,    // slot when lock began
    lock_duration_slots: u64,// minimum lock duration (~90 days)
    lp_amount_locked: u64,   // LP tokens locked (cannot withdraw until lock expires)
    cumulative_extracted: u64,// total value extracted from LP vault by creator
    cumulative_deposited: u64,// total value deposited into LP vault by creator
    fee_redirect_active: u8, // 1 = fees redirected to insurance
    _reserved: [u8; 7],
}
```

### How It Works

#### At Market Creation (InitMarket)
1. Creator deposits seed + LP position
2. CreatorStakeLock PDA created with lock_start_slot = current slot
3. lp_amount_locked = creator's initial LP deposit
4. lock_duration_slots = 90 days in slots (~90 * 216_000 = 19_440_000 slots)

#### On LP Withdraw by Creator
1. Check if `current_slot < lock_start_slot + lock_duration_slots`
   - If yes: reject withdraw up to `lp_amount_locked` (can only withdraw excess)
2. Track `cumulative_extracted += withdraw_value`
3. Compute extraction ratio: `extracted / deposited`
4. Compute expected ratio for random LP (simplified: ~1.0 for equal deposit/withdraw)
5. If extraction ratio > threshold (2σ): set `fee_redirect_active = 1`

#### Fee Redirect (in LpVaultCrankFees)
1. If `fee_redirect_active == 1` for this market's creator:
   - Creator's fee share → insurance fund instead of creator
   - Creator still gets LP P&L (same as any LP)

### Statistical Threshold
For simplicity in v1, use a fixed threshold rather than true σ calculation:
- **Extraction threshold**: If `cumulative_extracted > cumulative_deposited * EXTRACTION_LIMIT_BPS / 10_000`
  where `EXTRACTION_LIMIT_BPS = 15_000` (150% — creator extracted 50% more than deposited)
- This is a conservative threshold. Can be tightened later.

## Constants
```rust
pub const CREATOR_LOCK_MAGIC: u64 = 0x4352_5452_4C4F_434B; // "CRTRLOCK"
pub const CREATOR_LOCK_STATE_LEN: usize = 96;
pub const DEFAULT_LOCK_DURATION_SLOTS: u64 = 19_440_000; // ~90 days
pub const EXTRACTION_LIMIT_BPS: u64 = 15_000; // 150% of deposited
```

## Pure Logic Functions
```rust
fn is_lock_expired(current_slot: u64, lock_start: u64, duration: u64) -> bool
fn max_withdrawable(total_lp: u64, locked_lp: u64, lock_expired: bool) -> u64
fn check_extraction(extracted: u64, deposited: u64, limit_bps: u64) -> bool // true = exceeded
fn compute_fee_redirect(fee_amount: u64, redirect_active: bool) -> (u64, u64) // (to_creator, to_insurance)
```

## Kani Proofs
1. Lock never expires early (monotone slot check)
2. Max withdrawable ≤ total_lp
3. Max withdrawable == 0 when total_lp == locked_lp and lock not expired
4. Extraction check monotone: more extraction → more likely to trigger
5. Fee redirect conservation: to_creator + to_insurance == fee_amount

## Implementation Plan
1. Add CreatorStakeLock struct + PDA helpers + pure logic + tests + Kani
2. Wire into InitMarket (create lock PDA)
3. Wire into LpVaultWithdraw (enforce lock + track extraction)
4. Wire into LpVaultCrankFees (fee redirect)
