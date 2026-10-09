#!/bin/zsh
# Codegen preflight (rev 2 R4.2). Allowed only after the proof code is reviewed and frozen.
# One crate and one flavour at a time. No verification: `--only-codegen`. Confirms no cbmc was spawned.
#   preflight.sh <crate dir> <label> <cargo-kani args...>
set -u
dir=$1; lab=$2; shift 2
OUT=${PREFLIGHT_OUT:-$HOME/percolator-ops/artifacts/kani-v22-final/preflight}; mkdir -p $OUT
while (( $(sysctl -n vm.loadavg | awk '{print int($3)}') >= 8 )) || (( $(df -g $OUT | tail -1 | awk '{print $4}') < 40 )); do sleep 60; done
export CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=$OUT/target/$lab
cd $dir
{ echo "# $(date) $(git rev-parse HEAD) $lab $*"; cargo kani --version; } > $OUT/$lab.log
cargo kani list "$@" --format json >> $OUT/$lab.log 2>&1; cp kani-list.json $OUT/$lab-kani-list.json 2>/dev/null
cargo kani "$@" --only-codegen >> $OUT/$lab.log 2>&1 &
pid=$!; saw=0
tree() { local p=$1; echo $p; for c in $(pgrep -P $p); do tree $c; done; }
while kill -0 $pid 2>/dev/null; do
  # any cbmc in OUR process tree violates --only-codegen: record it, kill only our tree (by PID)
  for q in $(tree $pid); do
    if ps -o comm= -p $q 2>/dev/null | grep -q cbmc; then saw=1; for k in $(tree $pid); do kill -9 $k 2>/dev/null; done; break; fi
  done
  sleep 5
done
wait $pid; rc=$?
echo "rc=$rc cbmc_seen=$saw" >> $OUT/$lab.log
find $CARGO_TARGET_DIR -name '*.out' -size +0 -exec stat -f '%z %N' {} \; 2>/dev/null | sort -n > $OUT/$lab-goto-sizes.txt
[ -n "${NOCOVER:-}" ] && [ -f "$NOCOVER" ] && { echo "# PASS_NOCOVER allow-list (frozen)"; cat "$NOCOVER"; } >> $OUT/$lab.log
