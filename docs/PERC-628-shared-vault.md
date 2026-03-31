# PERC-628: Elastic Shared Vault + Epoch Withdrawals

## Overview

Single shared LP vault allocates **virtual liquidity** across markets. Hard per-market exposure caps enforced via Kani proofs. Withdrawals processed in **8-hour epochs** proportionally — no first-mover advantage, bank run incentive eliminated by design.

## Key Design Principles

1. **Single vault, many markets**: One SPL token account holds all LP capital. Each market gets a virtual allocation.
2. **Exposure caps**: No single market can draw down more than `MAX_MARKET_EXPOSURE_BPS` of the shared vault (e.g., 20%).
3. **Epoch withdrawals**: All withdrawal requests in an 8-hour epoch are honoured at the same price, proportionally if vault is insufficient.
4. **No first-mover advantage**: Everyone in an epoch gets the same deal, preventing bank runs.

## On-Chain Storage

### SharedVaultState PDA (global, one per program deployment)
Seeds: `["shared_vault"]`
Size: 128 bytes

```rust
struct SharedVaultState {
    magic: u64,                    // "SHRDVALT"
    bump: u8,
    _pad: [u8; 7],
    total_capital: u128,           // total LP capital across all markets
    total_allocated: u128,         // sum of all per-market virtual allocations
    epoch_number: u64,             // current epoch (increments every 8h)
    epoch_start_slot: u64,         // slot when current epoch began
    epoch_duration_slots: u64,     // ~8h = 72_000 slots
    pending_withdrawals: u128,     // total pending withdrawal requests this epoch
    max_market_exposure_bps: u16,  // max % of vault any single market can use
    _reserved: [u8; 22],
}
```
Total: 128 bytes.

### MarketAllocation (per-market, packed into existing config or separate PDA)
Seeds: `["market_alloc", slab_pubkey]`
Size: 48 bytes

```rust
struct MarketAllocation {
    magic: u64,                    // "MKTALLOC"
    bump: u8,
    _pad: [u8; 7],
    allocated_capital: u128,       // virtual allocation to this market
    utilized_capital: u128,        // how much is actually backing positions
}
```

### WithdrawalRequest (per-user per-epoch)
Seeds: `["withdraw_req", shared_vault, user_pubkey, epoch_number_le_bytes]`
Size: 32 bytes

```rust
struct WithdrawalRequest {
    magic: u64,                    // "WTHDRREQ"
    bump: u8,
    _pad: [u8; 3],
    lp_amount: u64,               // LP tokens to withdraw
    claimed: u8,                   // 0 = pending, 1 = claimed
    _reserved: [u8; 10],
}
```

## Pure Logic Functions

### Allocation
```rust
fn allocate_to_market(total_capital: u128, allocation: u128, max_bps: u16) -> u128
fn check_exposure_cap(total_capital: u128, market_allocation: u128, max_bps: u16) -> bool
fn available_for_allocation(total_capital: u128, total_allocated: u128) -> u128
```

### Epoch
```rust
fn current_epoch(slot: u64, start_slot: u64, duration: u64) -> u64
fn is_epoch_elapsed(current_slot: u64, epoch_start: u64, duration: u64) -> bool
fn advance_epoch(state: &mut SharedVaultState, current_slot: u64) -> bool
```

### Withdrawal
```rust
fn compute_proportional_withdrawal(
    request_lp: u64, total_pending_lp: u128, available_capital: u128
) -> u64
fn queue_withdrawal(pending: u128, amount: u64) -> u128
```

## Constants
```rust
pub const SHARED_VAULT_MAGIC: u64 = 0x5348_5244_5641_4C54; // "SHRDVALT"
pub const SHARED_VAULT_STATE_LEN: usize = 128;
pub const SHARED_VAULT_SEED: &[u8] = b"shared_vault";
pub const MARKET_ALLOC_MAGIC: u64 = 0x4D4B_5441_4C4C_4F43; // "MKTALLOC"
pub const MARKET_ALLOC_LEN: usize = 48;
pub const MARKET_ALLOC_SEED: &[u8] = b"market_alloc";
pub const WITHDRAW_REQ_MAGIC: u64 = 0x5754_4844_5252_4551; // "WTHDRREQ"
pub const WITHDRAW_REQ_LEN: usize = 32;
pub const WITHDRAW_REQ_SEED: &[u8] = b"withdraw_req";
pub const DEFAULT_EPOCH_DURATION_SLOTS: u64 = 72_000; // ~8 hours
pub const DEFAULT_MAX_MARKET_EXPOSURE_BPS: u16 = 2_000; // 20%
```

## Kani Proofs
1. Exposure cap: market allocation never exceeds max_bps % of total
2. Allocation conservation: total_allocated <= total_capital
3. Proportional withdrawal fairness: all users in epoch get same price
4. Epoch monotonically increases
5. Pending withdrawals never exceed total capital
6. Available for allocation = total - allocated (no underflow)

## Instruction Authorization Table

> **Authoritative reference for auditors and integrators.**
> The sole guard on AdvanceEpoch is `is_epoch_elapsed()` returning true — there is
> **no signer requirement**. This was an audit finding (GH#1913 / PERC-8314) and is
> intentional: epoch advancement is a permissionless keeper crank, consistent with
> `TAG_ADVANCE_EPOCH` in `tags.rs` and the CRANK_NO_CALLER pattern used elsewhere.

| Instruction          | Signer Required? | Auth Check                        | Notes                                                |
|----------------------|------------------|-----------------------------------|------------------------------------------------------|
| InitSharedVault      | ✅ admin          | `admin_ok()`                      | One-time initialisation; deploy-time first-caller guard (see GH#1915) |
| AllocateMarket       | ✅ admin          | `admin_ok()`                      | Admin-gated market registration                      |
| QueueWithdrawalSV    | ✅ user           | `owner_ok()`                      | User requests epoch withdrawal                       |
| ClaimEpochWithdrawal | ✅ user           | `owner_ok()` + `claimed == 0`    | Kani-proven: no double-claim (C11-A), conservation (C11-B) |
| AdvanceEpoch         | ❌ none           | `is_epoch_elapsed()` only         | **Permissionless crank** — any fee-payer may call once epoch has elapsed |

## Deployment Procedure — InitSharedVault (PERC-8292 / GH#1915)

> **Security note for deployers.** `InitSharedVault` requires a signer but does not
> verify the signer against any stored admin key — it is a **first-caller-wins**
> singleton init. The `AccountAlreadyInitialized` guard prevents double-init, so
> once the PDA is created the design is safe. The race window only exists during
> deployment.

**Required deployment sequence (atomic or guarded):**

1. Deploy the program binary (`solana program deploy`).
2. In the **same transaction** (or immediately in the next block), submit `InitSharedVault`
   signed by the intended admin keypair.
3. Immediately submit `AllocateMarket` for each whitelisted market — this call *does*
   verify `require_admin(header.admin, signer)` against the per-market slab, which
   provides admin-gating for all subsequent market-level operations.

**Why no upgrade-authority check?**  
`SharedVaultState` has no stored admin field (adding one would be a breaking layout change
mid-audit). The upgrade authority lives in the `BpfUpgradeableLoader` programdata account,
which would require an extra account in the instruction and version-gated CPI. The
deploy-time first-caller pattern is simpler, equally secure when the deployment sequence
is followed, and is consistent with the PDA-guard pattern used throughout the program.

**Mitigation for production:**  
Use a multisig or governance program as the signer for `InitSharedVault`. Once init is
confirmed on-chain, further admin ops are protected by per-market `require_admin` checks.

## Implementation Plan
1. Pure logic module + design doc + tests + Kani proofs
2. SharedVaultState + MarketAllocation + WithdrawalRequest PDAs
3. Instructions: InitSharedVault, AllocateMarket, QueueWithdrawal, ClaimEpochWithdrawal, AdvanceEpoch
4. Wire into existing LpVaultDeposit/Withdraw to use shared vault when enabled
