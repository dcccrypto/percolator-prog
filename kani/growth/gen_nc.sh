#!/bin/zsh
# Generates nc/{growth_v19,vault_lp_v18}.rs = the EXACT production files minus their
# `#[cfg_attr(kani, kani::ensures|requires(..))]` lines (cfg(kani)-only contract attributes, no
# runtime semantics). Needed because Kani 0.67 cannot `#[kani::stub]` a function that carries a
# contract. `./gen_nc.sh --check` fails unless the nc copies are exactly that (run before every
# nc proof run).
set -e
cd ${0:A:h}
P=../../src
for f in growth_v19 vault_lp_v18; do
  out=$(grep -v -E '^#\[cfg_attr\(kani, kani::(ensures|requires)\(' $P/$f.rs)
  if [[ $1 == --check ]]; then
    [[ "$out" == "$(cat nc/$f.rs)" ]] || { echo "STALE nc/$f.rs"; exit 1; }
    n=$(diff $P/$f.rs nc/$f.rs | grep -c '^<' || true)
    d=$(diff $P/$f.rs nc/$f.rs | grep '^[<>]' | grep -v -c -E '^< #\[cfg_attr\(kani, kani::(ensures|requires)\(' || true)
    [[ $d == 0 ]] || { echo "nc/$f.rs differs beyond contract attrs"; exit 1; }
    echo "nc/$f.rs OK ($n contract-attribute lines removed, nothing else)"
  else
    print -r -- "$out" > nc/$f.rs
  fi
done
