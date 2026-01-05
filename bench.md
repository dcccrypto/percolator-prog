# Crank CU Benchmark Results

LiteSVM benchmark for MAX_ACCOUNTS=4096, Solana max CU per tx: 1,400,000

## Before vs After Engine Optimizations

| Scenario | Before | After | Improvement |
|----------|--------|-------|-------------|
| **Baseline (empty slots)** | 178,455 CU | 181,651 CU | ~same |
| **4095 dust accounts** | >1.4M (fail) | 520,051 CU | **2.7x faster** |
| **Max users per tx** | ~1,500 | ~4,000 | **2.7x more** |
| **500 users w/ positions** | >1.4M (fail) | 959,495 CU | **fits now** |
| **1000 users w/ positions** | n/a | 1,211,035 CU | **fits now** |

## Detailed Results (After)

### Scenario 1: Empty Slots (LP only)
- **181,651 CU** baseline scan overhead for 4096 slots
- ~44 CU/slot

### Scenario 2: All Dust Accounts (no positions)
- 4095 users: **520,051 CU** total
- ~126 CU/account

### Scenario 3: Practical CU Scaling

| Users | CU Total | CU/User |
|-------|----------|---------|
| 100 | 190,756 | 1,888 |
| 500 | 224,981 | 449 |
| 1,000 | 266,021 | 265 |
| 1,500 | 307,061 | 204 |
| 2,000 | 348,101 | 173 |
| 2,500 | 389,141 | 155 |
| 3,000 | 430,176 | 143 |
| 3,500 | 471,216 | 134 |
| 4,000 | 512,256 | 128 |

**Max practical limit: ~4000 users in single tx**

### Scenario 4: Healthy Accounts with Positions

| Users | CU Total | CU/User |
|-------|----------|---------|
| 50 | 310,001 | 6,078 |
| 100 | 438,356 | 4,340 |
| 200 | 695,066 | 3,458 |
| 500 | 959,495 | 1,915 |
| 1,000 | 1,211,035 | 1,209 |

### Scenario 5: Liquidations (50% price crash)

| Liquidations | CU Total | CU/User |
|--------------|----------|---------|
| 100 | 463,237 | 4,586 |
| 200 | 741,847 | 3,690 |
| 300 | 927,883 | 3,082 |
| 400 | 1,000,793 | 2,495 |
| 500 | 1,073,698 | 2,143 |
| 600 | 1,146,608 | 1,907 |
| 700 | 1,219,513 | 1,739 |
| 800 | 1,292,423 | 1,613 |
| 900 | 1,365,333 | 1,515 |
| 1000 | >1.4M | ❌ |

**Max liquidations per tx: ~900**

### Scenario 6: Knife-Edge Liquidations

| Users | CU Total | CU/User |
|-------|----------|---------|
| 10 | 209,037 | 19,003 |
| 25 | 253,154 | 9,736 |
| 50 | 318,597 | 6,247 |
| 100 | 455,552 | 4,510 |
| 200 | 729,462 | 3,629 |

### Scenario 7: Worst-case ADL (force_realize with unpaid losses)

| ADL Accounts | CU Total | CU/User |
|--------------|----------|---------|
| 200 | 729,462 | 3,629 |
| 400 | 976,978 | 2,436 |
| 600 | 1,111,223 | 1,848 |
| 800 | 1,246,238 | 1,555 |
| 1000 | 1,381,253 | 1,379 |
| 1100 | >1.4M | ❌ |

**Max ADL accounts per tx: ~1000**

## Key Findings

1. **Dust accounts now fit**: All 4095 accounts can be cranked in a single tx (520K CU)
2. **Positions scale well**: 1000 users with positions fit in 1.2M CU
3. **Max liquidations per tx**: ~900 (at 1.37M CU)
4. **Max ADL accounts per tx**: ~1000 (at 1.38M CU)
5. **Worst case (4096 all need processing)**: Requires ~4-5 transactions
6. **Fixed overhead**: ~180K CU baseline for bitmap scan regardless of active accounts
