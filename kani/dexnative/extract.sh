#!/bin/zsh
# Extracts the DEX depth math (isqrt_u128, depth_pred, plus2pct_depth_e6) VERBATIM from the production
# file ../../src/depth_src_v22.rs into src/extracted.rs (pure fns, no deps). `--check` fails unless
# src/extracted.rs is byte-identical to a fresh extraction. Run before trusting any result here.
set -e
cd ${0:A:h}
P=../../src/depth_src_v22.rs
out=$(awk '/^\/\/\/ `floor\(sqrt\(n\)\)`, exact/{f=1} /^\/\/\/ Which side gives the reserve value/{f=0} f' $P)
if [[ $1 == --check ]]; then
  [[ "$out" == "$(cat src/extracted.rs)" ]] || { echo "STALE src/extracted.rs"; exit 1; }
  echo "src/extracted.rs OK (byte-identical to $P: $(print -r -- "$out" | wc -l | tr -d ' ') lines)"
else
  print -r -- "$out" > src/extracted.rs
fi
