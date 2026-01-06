# Crank CU Benchmark Results

LiteSVM benchmark for MAX_ACCOUNTS=4096, Solana max CU per tx: 1,400,000

## Critical Finding: Per-Sweep Limits

With 512-account sweep window, the **max accounts with positions per sweep** is:
- **512 healthy accounts** (96.5% of CU limit) - fits in single crank!
- **~450 liquidation accounts** (90.7% of CU limit)

If a 512-account sweep window contains more liquidations, a single crank will exceed 1.4M CU.

### Scenario 8a: Healthy Accounts with Positions (no liquidations)

| Users | Worst Crank CU | % of Limit | Status |
|-------|----------------|------------|--------|
| 100 | 285,403 | 20.4% | ✓ |
| 200 | 541,564 | 38.7% | ✓ |
| 256 | 689,467 | 49.2% | ✓ |
| 300 | 803,427 | 57.4% | ✓ |
| 350 | 932,935 | 66.6% | ✓ |
| 400 | 1,059,588 | 75.7% | ✓ |
| 450 | 1,191,951 | 85.1% | ✓ |
| 512 | 1,350,450 | **96.5%** | ✓ |

### Scenario 8b: With 50% Crash (Liquidations/ADL)

| Users | Worst Crank CU | % of Limit | Status |
|-------|----------------|------------|--------|
| 100 | 302,823 | 21.6% | ✓ |
| 200 | 575,960 | 41.1% | ✓ |
| 256 | 733,719 | 52.4% | ✓ |
| 300 | 855,247 | 61.1% | ✓ |
| 350 | 993,355 | 71.0% | ✓ |
| 400 | 1,128,384 | 80.6% | ✓ |
| 450 | 1,269,571 | **90.7%** | ✓ |
| 512 | >1.4M | - | ❌ |

## Other Scenarios

### Scenario 1: Empty Slots (LP only)
- **175,553 CU** baseline scan overhead for 4096 slots
- ~42 CU/slot

### Scenario 2: Dust Accounts (no positions)
- 4095 users: **407,931 CU** total
- ~99 CU/account

### Scenario 3: Dust Account Scaling

| Users | CU Total | CU/User |
|-------|----------|---------|
| 1,000 | 217,030 | 217 |
| 2,000 | 262,594 | 131 |
| 3,000 | 308,150 | 102 |
| 4,000 | 399,278 | 99 |

**All 4000+ dust accounts fit in single tx**

### Scenario 4: Healthy Accounts with Positions (single crank)

| Users | CU Total | CU/User |
|-------|----------|---------|
| 50 | 153,040 | 3,000 |
| 100 | 282,548 | 2,797 |
| 200 | 541,564 | 2,694 |
| 500 | 1,318,596 | 2,631 |
| 1000 | >1.4M | ❌ |

### Scenario 5: Liquidations (single crank)

| Liquidations | CU Total | CU/User |
|--------------|----------|---------|
| 100 | 307,430 | 3,043 |
| 200 | 588,346 | 2,927 |
| 300 | 869,254 | 2,887 |
| 400 | 1,150,170 | 2,868 |
| 500 | >1.4M | ❌ |

## Key Findings

1. **Per-sweep limit with positions**: 512 healthy, ~450 liquidations
2. **Dust accounts scale well**: All 4095 fit in single tx at ~408K CU
3. **512-account sweep window**: Healthy accounts now fit; liquidations may exceed if >450
4. **For 4096 accounts worst case**:
   - If all have positions: fits in 8 cranks (512 per sweep max)
   - If all need liquidation: need ~10 cranks (~450 per sweep max)
5. **Baseline overhead**: ~176K CU for bitmap scan alone

## Optimization: Bitmap Iteration (Step 2)

Replaced O(MAX_ACCOUNTS) loops in `compute_net_lp_pos` and `LpRiskState::compute`
with O(num_used) bitmap iteration via `for_each_used_lp` helper.

**Improvements over previous version:**
- Healthy 512 accounts: Was exceeding 1.4M, now 96.5% ✓
- Liquidation 450 accounts: Was exceeding 1.4M, now 90.7% ✓
- Dust accounts: 426K → 408K CU (-4%)
