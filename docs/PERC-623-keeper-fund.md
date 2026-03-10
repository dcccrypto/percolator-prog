# PERC-623: Self-Funding Keeper via Split Creation Deposit

## Overview

At market creation, split the deposit: **70% to creator LP position, 30% to per-market keeper fund PDA**. The keeper fund pays crank rewards automatically. When depleted, the market auto-pauses. Volume-generated fees can top up the fund. This eliminates zombie markets.

## On-Chain Storage

### Option A: New KeeperFund PDA (separate account)
- Seeds: `["keeper_fund", slab_pubkey]`
- Contains: SPL token account owned by vault authority
- Pro: clean separation, no slab layout change
- Con: extra account in every KeeperCrank instruction, PDA rent ~2.4K lamports

### Option B: Pack into existing slab config
- Store keeper_fund_balance (u64) in config
- Tokens stay in the existing vault
- Pro: no extra account, no PDA rent, simpler instruction
- Con: complicates vault accounting (need to distinguish LP capital from keeper fund)

**Decision: Option B** — pack into config padding. The keeper fund is logically separate but physically in the same vault. We track it as a u64 balance in config. When keeper fund is depleted, we set the market to pause mode (close-only).

### Storage Location

We need 8 bytes for keeper_fund_balance. Looking at available space:

The `_adaptive_pad2` field is a 4-byte alignment padding (u32). The `_reserved` in SlabHeader has some gaps. Let me check what's actually free.

Actually, the simplest approach: add `keeper_fund_balance` as a new field at the end of MarketConfig. But CONFIG_LEN is compile-time asserted.

**Better:** Use the existing `_adaptive_pad2` (4 bytes) + steal from another padding. Actually this is too tight.

**Cleanest approach:** Store keeper_fund_balance in the engine's existing reserved/padding fields. The RiskEngine has spare fields.

Let me check RiskEngine for spare space... Actually, let's use a simpler approach: store the keeper fund balance in the slab header's `_reserved` field. Currently:
- [0..8]: nonce
- [8..16]: last_thr_slot  
- [16..24]: dust_base

All 24 bytes used. We can't fit there.

**Final decision:** Extend MarketConfig. This is a V1+ change. Add:
```rust
pub keeper_fund_balance_e6: u64,  // keeper fund in e6 units
pub keeper_reward_per_crank_e6: u64,  // reward per successful crank
```

This bumps CONFIG_LEN by 16 bytes. Since we already have V0/V1 detection, new markets get the larger config. Existing V0 markets ignore keeper fund (balance = 0 = disabled).

Wait — we can't change CONFIG_LEN without changing SLAB sizes across all three tiers. This is a deployment blocker.

**Revised approach — use _insurance_isolation_padding overflow:**

The PERC-622 oracle phase transition uses padding[2..14]. That leaves 0 free bytes in that padding.

**Let's check _adaptive_pad2 more carefully:**
- `_adaptive_pad2: u32` at 4 bytes — pure alignment padding between `adaptive_scale_bps: u16` and `adaptive_max_funding_bps: u64`

We can't repurpose this without breaking alignment.

**Use the engine's reserved fields instead.** The RiskEngine likely has padding or reserved space.

Actually, the simplest approach that doesn't change any layout: **use a PDA account (Option A)**. It's cleaner and doesn't require layout gymnastics.

## Revised Design: KeeperFund PDA

### PDA Layout
```
Seeds: ["keeper_fund", slab_pubkey]
Size: 41 bytes (8 magic + 1 bump + 8 balance + 8 reward_per_crank + 8 total_rewarded + 8 total_topped_up)

struct KeeperFundState {
    magic: u64,           // "KEEPFUND"
    bump: u8,
    _pad: [u8; 7],
    balance: u64,         // current fund balance (in base token lamports)
    reward_per_crank: u64, // reward per KeeperCrank call
    total_rewarded: u64,  // lifetime rewards paid out
    total_topped_up: u64, // lifetime top-ups from fees
}
```
Total: 48 bytes. Rent: ~0.001 SOL.

### InitMarket Changes
1. Accept optional `keeper_fund` PDA account (backwards compatible)
2. If present: split deposit 70/30
   - 70% transferred to vault (existing LP seed logic)
   - 30% transferred to keeper_fund token ATA (derived from keeper_fund PDA + mint)
3. Initialize KeeperFundState PDA
4. Set default `reward_per_crank` (configurable per market)

### KeeperCrank Changes
1. Accept optional trailing `keeper_fund` account
2. After successful crank:
   - Transfer `reward_per_crank` from keeper_fund ATA to caller's ATA
   - Decrement keeper_fund_balance
3. If keeper_fund_balance == 0:
   - Set market to pause mode (FLAG_PAUSED)
   - Emit "KeeperFundDepleted" log

### Fee Top-Up (in LpVaultCrankFees or KeeperCrank)
1. When fees are collected, divert configurable % to keeper fund
2. If market was auto-paused due to depletion AND balance > 0: unpause

### New Instruction: TopUpKeeperFund (tag 57)
Anyone can top up the keeper fund by transferring tokens to its ATA.

## Constants
```rust
pub const KEEPER_FUND_SPLIT_BPS: u64 = 3000;  // 30% of deposit
pub const DEFAULT_REWARD_PER_CRANK: u64 = 1000; // 0.001 SOL equivalent
pub const KEEPER_FUND_MAGIC: u64 = 0x4B454550_46554E44; // "KEEPFUND"
pub const KEEPER_FUND_STATE_LEN: usize = 48;
```

## Implementation Plan
1. Add KeeperFundState struct + PDA derivation helpers
2. Modify InitMarket to accept optional keeper_fund PDA + split deposit
3. Modify KeeperCrank to pay rewards from fund
4. Add auto-pause on depletion
5. Add TopUpKeeperFund instruction
6. Kani proofs: fund balance never negative, reward ≤ balance, split sum = deposit
7. Unit tests

## Kani Proof Sketch
```rust
// Fund balance is always non-negative (u64 — trivially true)
// Split sum equals original deposit
fn proof_deposit_split_conservation(deposit: u64) {
    let lp = deposit * (10_000 - KEEPER_FUND_SPLIT_BPS) / 10_000;
    let fund = deposit - lp; // remainder to fund
    assert!(lp + fund == deposit); // exact conservation
}

// Reward never exceeds balance
fn proof_reward_bounded(balance: u64, reward: u64) {
    if reward <= balance { /* ok */ } else { /* reject */ }
    let new_balance = balance - reward; // only if reward <= balance
    assert!(new_balance <= balance);
}
```
