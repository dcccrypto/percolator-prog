# PERC-200: Sprint 4 CU Benchmark — Fresh Baseline Report
**Date**: 2026-02-26 15:38 UTC  
**QA Engineer**: qa  
**Branch**: main @ 27b0b4f (post-Sprint-4)  
**Status**: BASELINE COMPLETE — awaiting PERC-199 (Clock::get() + config cache) PR to do post-opt comparison

---

## Executive Summary

All 8 benchmark scenarios **PASS** (2/2 tests). Current main branch post-Sprint-4 baseline:
- **Open operations**: ~5,383–5,384 CU  
- **Modify operations** (increase/flip/partial close): ~6,350–6,374 CU  
- **Close operations**: 4,630 CU  
- **Rapid trades average**: 5,113 CU  
- **O(1) scaling**: CONFIRMED — CU constant from 10–4,000 active accounts  
- **Size independence**: CONFIRMED — CU constant across sizes 1–100,000

These numbers are the clean post-Sprint-4 baseline. Once PERC-199 ships (Clock::get() elimination + config cache), re-run to verify ~150–200 CU improvement.

---

## Methodology

- **Tool**: LiteSVM (local simulation, no devnet SOL required)
- **Build**: `cargo build-sbf` (production BPF, no `--features test`)
- **Run**: `cargo test --release --test trade_cu_benchmark -- --nocapture`
- **Commit**: `27b0b4f` (main, post-merge of PR #7 / PERC-156)
- **Binary size**: 361,000 bytes (approximate, same as post-PERC-154)

---

## Results: All 8 Scenarios

| Scenario | Operation | CU |
|----------|-----------|-----|
| 1 | Open long (+100) | **5,384** |
| 2 | Open short (-100) | **5,383** |
| 3 | Increase long (+50) | **6,374** |
| 4 | Flip long→short | **6,361** |
| 4b | Flip short→long | **6,350** |
| 5 | Close position (long) | **4,630** |
| 5b | Partial close (-75) | **6,367** |
| 6 | Rapid trades avg (20 trades) | **5,113** |
| 6 | Rapid trades min | 4,622 |
| 6 | Rapid trades max | 5,625 |
| 7 | Tiny trade (size=1) | **5,384** |
| 7 | Large trade (size=100K) | **5,625** |

---

## O(1) Slab Scaling (CONFIRMED ✅)

| Active Accounts | CU per Trade |
|----------------|--------------|
| 1 | 6,018 |
| 10 | **5,625** |
| 100 | **5,625** |
| 500 | **5,625** |
| 1,000 | **5,625** |
| 2,000 | **5,625** |
| 4,000 | **5,625** |

**O(1) confirmed** — flat from 10 to 4,000 accounts. The 6,018 for 1 account is first-time slab init overhead.

---

## Position Size Independence (CONFIRMED ✅)

| Size | CU |
|------|----|
| 1 | 5,384 |
| 10 | 5,392 |
| 100 | 5,384 |
| 1,000 | 5,384 |
| 10,000 | 5,384 |
| 100,000 | 5,384 |

No big-number penalty. Size-invariant.

---

## Comparison vs PERC-156 Baseline (pre-Sprint-4)

| Operation | PERC-156 (Feb 26 07:30) | PERC-200 (Feb 26 15:38) | Δ |
|-----------|------------------------|------------------------|---|
| Open long | 5,384 | 5,384 | 0 |
| Open short | 5,383 | 5,383 | 0 |
| Increase long | 6,374 | 6,374 | 0 |
| Flip long→short | 6,361 | 6,361 | 0 |
| Close | 4,630 | 4,630 | 0 |
| Rapid avg | 5,113 | 5,113 | 0 |

**Zero delta** — main branch is stable. No accidental CU regressions in Sprint 4.

---

## Next Step: Post-PERC-199 Comparison

Once coder ships **PERC-199** (Clock::get() + config cache PR), re-run:
```bash
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd ~/percolator-prog && git pull origin main && cargo build-sbf
cargo test --release --test trade_cu_benchmark -- --nocapture
```

Expected outcome: **~150–200 CU reduction** across open/modify operations (security estimate).  
This report is the **pre-PERC-199 baseline** for that comparison.

---

## Toly Context

Current state on main (TradeCpi V1 path):
- Open trade: **~5,384 CU** (budget: 200,000 CU — using ~2.7%)
- Modify trade: **~6,374 CU** (~3.2% of budget)
- O(1) scaling confirmed to 4,000 concurrent active accounts

Headroom for further optimization:
- **TradeCpiV2** (bump-provided): ~1,500 CU saved when SDK callers are updated
- **PERC-199** Clock::get() + config cache: ~150–200 CU (pending)
- **Total potential**: current ~5,384 → projected ~3,700 CU for open trade after both optimizations
