#!/bin/bash
W=/Users/khubair/agent-work/wt/J-20261120-PROG-TOLY-CUSHAPEe
O=/Users/khubair/agent-work/toly-cushape/e
export AGENT_JOB_ID=J-20261120-PROG-TOLY-CUSHAPEe
T=/tmp/jtolycu-target
BASE=/tmp/jtolycu-base-da0dfad9.so
HEAD=/tmp/jtolycu-head.so
P() { echo "$(date -u +%H:%M) $*" >> $O/progress.txt; }
L() { node ~/agent-worker/with-lock.mjs reserved --wait-min 120 -- bash -c "cd $W && $2" > $O/$1.log 2>&1; P "$1 exit=$?"; }
cd $W
P start sha256 head=$(shasum -a 256 $HEAD | cut -c1-12) base=$(shasum -a 256 $BASE | cut -c1-12)
L matcher "cd tests/fixtures/auth_matcher && cargo build-sbf --tools-version v1.52 -j 4"
ls -la $W/tests/fixtures/auth_matcher/target/deploy/auth_matcher.so >> $O/progress.txt 2>&1
for which in head base; do
  so=$HEAD; [ $which = base ] && so=$BASE
  for i in 1 2 3; do
    L probe-$which-$i "PERCOLATOR_FUZZ_SBF=$so CARGO_TARGET_DIR=$T cargo test -j 4 --test v16_cu cu_probe_trade_cpi_legs -- --ignored --nocapture"
    grep -E "CUPROBE kind=batch_trade_cpi legs=(1|2|4) " $O/probe-$which-$i.log | sed "s/^/$which RUN$i /" >> $O/progress.txt
  done
done
P done
touch $O/DONE
