# Percolator Verification Matrix

This document provides a comprehensive verification matrix covering all security properties and feature tests for the Percolator perpetual futures protocol.

## Test Summary

**Total Tests: 32**
- Feature Tests: 11 comprehensive + 2 basic crank tests
- Bug Regression Tests: 7
- Security Tests: 8
- Matcher Tests: 4

---

## 1. Market Lifecycle

| Test | Description | Status |
|------|-------------|--------|
| `test_inverted_market_crank_succeeds` | Inverted market (SOL/USD) crank with funding | PASS |
| `test_non_inverted_market_crank_succeeds` | Non-inverted market crank | PASS |

## 2. Trading Lifecycle

| Test | Description | Status |
|------|-------------|--------|
| `test_comprehensive_trading_lifecycle_with_pnl` | Open -> Price move -> Close -> Crank | PASS |
| `test_comprehensive_position_flip_long_to_short` | Long to short position flip | PASS |
| `test_comprehensive_multiple_participants` | Multiple users trading with single LP | PASS |
| `test_comprehensive_oracle_price_impact_on_pnl` | Crank succeeds at various prices | PASS |
| `test_comprehensive_funding_accrual` | 10 cranks with funding accrual | PASS |

## 3. Margin & Risk

| Test | Description | Status |
|------|-------------|--------|
| `test_comprehensive_margin_limit_enforcement` | Small trade OK, huge trade rejected | PASS |
| `test_comprehensive_withdrawal_limits` | Full withdrawal rejected with open position | PASS |
| `test_comprehensive_liquidation_underwater_user` | Liquidation instruction processing | PASS |
| `test_bug_finding_l_margin_check_uses_maintenance_instead_of_initial` | Finding L: maintenance vs initial margin | PASS |

## 4. Account Management

| Test | Description | Status |
|------|-------------|--------|
| `test_comprehensive_close_account_returns_capital` | Close account returns capital to vault | PASS |
| `test_comprehensive_insurance_fund_topup` | Insurance fund top-up transfers to vault | PASS |
| `test_idle_account_can_close_after_crank` | Idle account closure with crank | PASS |
| `test_zombie_pnl_crank_driven_warmup_conversion` | Warmup-driven PnL conversion | PASS |

## 5. Security - Authorization

| Test | Description | Status |
|------|-------------|--------|
| `test_comprehensive_unauthorized_access_rejected` | Unauthorized deposit/withdraw/trade rejected | PASS |
| Trade without LP signature | Rejected with `Custom(15)` | PASS |
| Unauthorized deposit to other account | Rejected with `Custom(15)` | PASS |
| Unauthorized withdrawal from other account | Rejected with `Custom(15)` | PASS |

## 6. Security - Hyperp Mode

| Test | Description | Status |
|------|-------------|--------|
| `test_hyperp_init_market_with_valid_price` | Hyperp market initialization | PASS |
| `test_hyperp_init_market_with_inverted_price` | Hyperp with inverted market | PASS |
| `test_hyperp_rejects_zero_initial_mark_price` | Zero price validation | PASS |
| `test_hyperp_issue_trade_nocpi_sets_mark_equals_index` | TradeNoCpi disabled for Hyperp | PASS |
| `test_hyperp_issue_default_cap_zero_bypasses_smoothing` | Default cap configuration | PASS |
| `test_hyperp_security_no_exec_price_bounds` | exec_price clamping verified | PASS |
| `test_hyperp_security_combined_smoothing_price_risk` | Combined smoothing/price security | PASS |

## 7. Matcher Integration

| Test | Description | Status |
|------|-------------|--------|
| `test_matcher_init_vamm_passive_mode` | Passive mode initialization | PASS |
| `test_matcher_call_after_init` | Matcher call with correct pricing | PASS |
| `test_matcher_rejects_double_init` | Double init rejected | PASS |
| `test_matcher_vamm_mode_with_impact` | vAMM mode with impact pricing | PASS |

## 8. Bug Regressions

| Test | Bug ID | Description | Status |
|------|--------|-------------|--------|
| `test_bug3_close_slab_with_dust_should_fail` | Bug #3 | CloseSlab with dust_base > 0 | PASS |
| `test_bug4_fee_overpayment_should_be_handled` | Bug #4 | Fee overpayment handling | PASS |
| `test_bug6_threshold_slow_ramp_from_zero` | Bug #6 | Threshold ramp from zero | PASS |
| `test_bug7_pending_epoch_wraparound` | Bug #7 | Pending epoch wraparound | PASS |
| `test_bug8_lp_entry_price_updates_on_flip` | Bug #8 | LP entry price on flip | PASS |

---

## Security Properties Verified

### 1. Hyperp Mode Security
- [x] TradeNoCpi disabled for Hyperp markets (returns `HyperpTradeNoCpiDisabled`)
- [x] Mark price clamped via `clamp_oracle_price()` with circuit breaker
- [x] Default `oracle_price_cap_e2bps = 10,000` (1% per slot max)
- [x] Index price smoothing rate-limited via `clamp_toward_with_dt()`
- [x] Inverted market support with `invert_price_e6()`
- [x] Zero initial_mark_price_e6 rejected

### 2. TradeCpi Security
- [x] Matcher identity binding (program + context must match LP registration)
- [x] Nonce discipline (monotonic, echoed in req_id)
- [x] `exec_size` used (never user's requested size)
- [x] ABI validation (version, flags, echoed fields, reserved bytes)
- [x] LP PDA shape validation (system-owned, zero data, zero lamports)

### 3. Authorization
- [x] Owner/signer enforcement on all account operations
- [x] Admin authorization for governance operations
- [x] LP signature required for trades
- [x] User signature required for deposits/withdrawals

### 4. Oracle Security
- [x] Feed ID validation (Pyth/Chainlink)
- [x] Staleness checks (feature-gated for devnet)
- [x] Confidence filter (Pyth)
- [x] Oracle price circuit breaker
- [x] Exponent bounds to prevent overflow

### 5. Margin & Risk
- [x] Margin requirement enforcement (trades rejected when insufficient)
- [x] Withdrawal limits (cannot withdraw beyond equity)
- [x] Liquidation mechanics
- [x] Risk reduction gating when insurance threshold active

### 6. Integer Safety
- [x] Saturating arithmetic throughout
- [x] `i128::MIN` handled with `unsigned_abs()`
- [x] Checked operations for token transfers
- [x] Exponent bounds on oracle prices

---

## Coverage Matrix by Instruction

| Instruction | Unit Test | Integration Test | Security Test |
|-------------|-----------|------------------|---------------|
| InitMarket | - | test_inverted_market_crank | test_hyperp_init_market |
| InitUser | - | test_comprehensive_* | test_unauthorized_access |
| InitLP | - | test_comprehensive_* | test_matcher_init |
| DepositCollateral | - | test_comprehensive_* | test_unauthorized_access |
| WithdrawCollateral | - | test_withdrawal_limits | test_unauthorized_access |
| KeeperCrank | - | test_funding_accrual | test_hyperp_security |
| TradeNoCpi | - | test_trading_lifecycle | test_hyperp_trade_nocpi |
| TradeCpi | - | test_matcher_call | test_hyperp_security |
| LiquidateAtOracle | - | test_liquidation | - |
| CloseAccount | - | test_close_account | - |
| TopUpInsurance | - | test_insurance_fund | - |
| CloseSlab | - | test_bug3_close_slab | - |
| SetOraclePriceCap | - | - | test_hyperp_default_cap |
| SetFundingParams | - | - | - |

---

## How to Run Tests

```bash
# All integration tests
cargo test --test integration

# Comprehensive feature tests only
cargo test --test integration -- test_comprehensive

# Hyperp security tests only
cargo test --test integration -- test_hyperp

# Matcher tests only
cargo test --test integration -- test_matcher

# Bug regression tests only
cargo test --test integration -- test_bug

# With output
cargo test --test integration -- --nocapture
```

---

## Known Limitations

1. **Devnet Feature**: Staleness and confidence checks disabled with `--features devnet`
2. **State Reading**: Internal engine state not directly readable in tests (relies on observable outcomes)
3. **Liquidation**: Requires specific margin conditions to trigger

---

## Audit Findings Addressed

| Finding | Description | Status | Test |
|---------|-------------|--------|------|
| Finding L | Margin check uses maintenance instead of initial | Reproduced | test_bug_finding_l |
| Bug #3 | CloseSlab with dust | Fixed | test_bug3 |
| Bug #4 | Fee overpayment | Fixed | test_bug4 |
| Bug #6 | Threshold ramp from zero | Fixed | test_bug6 |
| Bug #7 | Pending epoch wraparound | Fixed | test_bug7 |
| Bug #8 | LP entry price on flip | Fixed | test_bug8 |
| Hyperp Mark Manipulation | TradeNoCpi sets mark directly | Fixed | test_hyperp_trade_nocpi |
| Hyperp Index Bypass | Default cap=0 bypasses smoothing | Fixed | test_hyperp_default_cap |
| Hyperp exec_price Bounds | No clamping on matcher exec_price | Fixed | test_hyperp_no_exec_price_bounds |

---

## Deployment Verification Checklist

- [ ] Build with production flags: `cargo build-sbf`
- [ ] Run all tests: `cargo test --test integration`
- [ ] Deploy to devnet: `solana program deploy target/deploy/percolator_prog.so`
- [ ] Initialize test market
- [ ] Verify LP can init matcher context
- [ ] Verify trades execute through TradeCpi
- [ ] Verify cranks process funding
- [ ] Monitor for errors in transaction logs
