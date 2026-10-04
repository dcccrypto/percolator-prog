#!/bin/zsh
# growth-v19 single Kani run (design note rev 5). Real harnesses, at most 3 concurrent; each
# harness has a watchdog (LIMIT secs, default 1500) that kills only the PIDs it spawned.
# usage: ./run_kani.sh <tag>        -> logs/<tag>/SUMMARY (harness | verdict | covers | secs)
tag=$1
LIMIT=${LIMIT:-1500}
P=/Users/khubair/wt-growth-v19/percolator-prog
M=/Users/khubair/wt-growth-v19/percolator-match
L=$P/kani/growth/logs/$tag
mkdir -p $L; : > $L/SUMMARY
jobs_list=()
for h in $(grep -o "fn kani_growth_[a-z_0-9]*" $P/kani/growth/src/proofs.rs | sed 's/fn //'); do
  jobs_list+=("growth|$h|$P/kani/growth|cargo kani -Z stubbing --harness proofs::$h --exact")
done
for h in $(grep -o "fn kani_growth_[a-z_0-9]*" $P/tests/growth_kani.rs | sed 's/fn //'); do
  jobs_list+=("wrapper-tests|$h|$P|cargo kani --tests --harness $h --exact")
done
for h in proof_v3_effective_inventory_min_and_closed proof_v3_effective_liquidity_min proof_v3_closed_mode_only_reduces_lp proof_v3_parse_rejects_over_i128_cap proof_v3_apply_caps_exempt_means_no_clip proof_v3_close_exempt_fill_is_full proof_growth_depth_reaches_capacity; do
  jobs_list+=("matcher|$h|$M|cargo kani --harness v2::proofs::$h --exact")
done
for h in proof_kind1_skew_units_capped_and_monotone proof_v3_neutral_caps_equal_v2; do
  jobs_list+=("matcher|$h|$M|cargo kani --harness vamm::proofs::$h --exact")
done
killtree() { local p=$1; for c in $(pgrep -P $p); do killtree $c; done; kill $p 2>/dev/null; }
run_one() {
  local crate=$1 h=$2 dir=$3 cmd=$4
  local start=$(date +%s)
  (cd $dir && eval "$cmd") > $L/$h.log 2>&1 &
  local pid=$!
  while kill -0 $pid 2>/dev/null; do
    if [ $(( $(date +%s) - start )) -ge $LIMIT ]; then killtree $pid; echo "WATCHDOG: killed after ${LIMIT}s" >> $L/$h.log; break; fi
    sleep 5
  done
  wait $pid 2>/dev/null
  local secs=$(( $(date +%s) - start ))
  local v=$(grep -E "^VERIFICATION:" $L/$h.log | tail -1)
  grep -q "WATCHDOG" $L/$h.log && [ -z "$v" ] && v="TIMEOUT (${LIMIT}s)"
  local c=$(grep -E "cover properties satisfied|of [0-9]+ cover properties" $L/$h.log | tail -1)
  echo "$crate | $h | ${v:-NO VERDICT} | ${c:-no cover line} | ${secs}s" >> $L/SUMMARY
}
for j in "${jobs_list[@]}"; do
  IFS='|' read crate h dir cmd <<< "$j"
  while [ $(jobs -r | wc -l) -ge 3 ]; do sleep 3; done
  run_one "$crate" "$h" "$dir" "$cmd" &
done
wait
echo DONE >> $L/SUMMARY
