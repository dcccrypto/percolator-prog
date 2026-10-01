#!/bin/bash
# Runs every P3 harness; full log per harness under logs/<tag>/, summary to logs/<tag>/SUMMARY.
# usage: [ONLY=<regex>] [LIMIT=<secs>] ./run_kani.sh <tag> [cargo kani extra args]
# Watchdog: a harness still running after LIMIT seconds is killed (only the PID this script
# spawned, and its own children) and recorded as TIMEOUT — never as a verdict.
tag=$1; shift
LIMIT=${LIMIT:-1200}
mkdir -p logs/$tag
: > logs/$tag/SUMMARY
killtree() { local p=$1; for c in $(pgrep -P $p); do killtree $c; done; kill $p 2>/dev/null; }
for h in $(grep -o "fn kani_p3_[a-z_0-9]*" src/proofs.rs | sed 's/fn //'); do
  if [ -n "$ONLY" ] && ! echo "$h" | grep -qE "$ONLY"; then continue; fi
  start=$(date +%s)
  cargo kani "$@" --harness "proofs::$h" --exact > logs/$tag/$h.log 2>&1 &
  pid=$!
  while kill -0 $pid 2>/dev/null; do
    if [ $(( $(date +%s) - start )) -ge $LIMIT ]; then killtree $pid; echo "WATCHDOG: killed after ${LIMIT}s" >> logs/$tag/$h.log; break; fi
    sleep 5
  done
  wait $pid 2>/dev/null
  secs=$(( $(date +%s) - start ))
  v=$(grep -E "^VERIFICATION:" logs/$tag/$h.log | tail -1)
  grep -q "WATCHDOG" logs/$tag/$h.log && [ -z "$v" ] && v="TIMEOUT (${LIMIT}s)"
  c=$(grep -E "cover properties satisfied" logs/$tag/$h.log | tail -1)
  echo "$h | ${v:-NO VERDICT} | ${c:-no cover line} | ${secs}s" | tee -a logs/$tag/SUMMARY
done
