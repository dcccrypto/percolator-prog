#!/bin/zsh
# audit-1017: the harness crates' depth_src_v22 stub const must equal production.
cd ${0:A:h}
want=$(grep -E '^pub const DEPTH_MODE_DEX: u8 = ' ../src/depth_src_v22.rs | sed -E 's/.*= ([0-9]+);/\1/')
for c in growth p3 p3-engine money; do
  got=$(grep -E 'pub const DEPTH_MODE_DEX: u8 = ' $c/src/lib.rs | sed -E 's/.*= ([0-9]+);/\1/')
  [[ $got == $want ]] || { echo "MISMATCH $c: $got != $want"; exit 1; }
done
echo "depth stub OK ($want)"
