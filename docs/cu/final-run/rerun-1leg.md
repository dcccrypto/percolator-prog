# 1-leg rerun, head vs base (job J-20261121-PROG-TOLY-CUSHAPE-DRAFTFIX)

head .so built from d532c2da: sha256 271782833e8c44fc48d3eeb0a5f81218bd3103056b142d5693883ac61093e69f
base .so built from da0dfad9: sha256 3fcd1a7d8da4db3f1b7905abbf0949aeffa45d7eb6ec734dd8a758acfd606872
(SBF build, tools v1.52, -j 4, same toolchain; run under with-lock reserved)

`cu_probe_trade_cpi_legs`, BatchTradeCpi legs=1, 3 samples each:
- head: 146576, 143576, 145076  (median 145076, min 143576)
- base: 152740, 152740, 152740  (median/min 152740)

Saving this run: 7664 CU by median (-5.0%), 9164 CU by min (-6.0%).
Earlier 3x3 runs: 154240 -> 143576 (-10664). Samples are noisy by about 1.5k,
so "about 8-10.7k" is the honest range, flat per transaction.
Both runs exit 101 from the pre-existing 16-leg init-market panic (tests/v16_cu.rs:1203).
