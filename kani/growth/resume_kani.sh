#!/bin/zsh
# Resume of the single run after the session restart: ONLY harnesses with no SUMMARY entry
# (logs/real/REMAINING.txt). Same code, same flags, same watchdog. Three queues, each on its OWN
# copy of the proofs crate (kani/growth, kani/growth-q2, kani/growth-q3: identical sources,
# separate target dirs -> no same-target concurrency), each sequential: at most 3 harnesses.
LIMIT=${LIMIT:-1500}
P=/Users/khubair/wt-growth-v19/percolator-prog
L=$P/kani/growth/logs/real
killtree() { local p=$1; for c in $(pgrep -P $p); do killtree $c; done; kill $p 2>/dev/null; }
run_one() {
  local dir=$1 h=$2
  local start=$(date +%s)
  (cd $dir && cargo kani -Z stubbing --harness proofs::$h --exact) > $L/$h.log 2>&1 &
  local pid=$!
  while kill -0 $pid 2>/dev/null; do
    if [ $(( $(date +%s) - start )) -ge $LIMIT ]; then killtree $pid; echo "WATCHDOG: killed after ${LIMIT}s" >> $L/$h.log; break; fi
    sleep 5
  done
  wait $pid 2>/dev/null
  local secs=$(( $(date +%s) - start ))
  local v=$(grep -E "^VERIFICATION:" $L/$h.log | tail -1)
  grep -q "WATCHDOG" $L/$h.log && [ -z "$v" ] && v="TIMEOUT (${LIMIT}s)"
  local c=$(grep -E "cover properties satisfied" $L/$h.log | tail -1)
  echo "growth | $h | ${v:-NO VERDICT} | ${c:-no cover line} | ${secs}s" >> $L/SUMMARY
}
hs=($(cat ${LIST:-$L/REMAINING.txt}))
queue() { local dir=$1 k=$2; local i=0; for h in "${hs[@]}"; do if [ $((i % 3)) -eq $k ]; then run_one $dir $h; fi; i=$((i+1)); done; }
if [ -n "$SINGLE" ]; then
  # load-limited mode (coordinator 2026-10-05): ONE sequential queue, list order kept
  for h in "${hs[@]}"; do run_one $P/kani/growth $h; done
else
  queue $P/kani/growth 0 &
  queue $P/kani/growth-q2 1 &
  queue $P/kani/growth-q3 2 &
  wait
fi
echo "DONE ${LIST:-all}" >> $L/SUMMARY
