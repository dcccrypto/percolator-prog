#!/bin/zsh
# Codegen preflight (rev 2 R4.2). Allowed only after the proof code is reviewed and frozen.
# One crate and one flavour at a time. No verification: `--only-codegen`. Confirms no cbmc was spawned.
#   [QUEUE=<queue.tsv>] [FLAVOUR=<none|devnet|mainnet>] preflight.sh <crate dir> <label> <cargo-kani args...>
# After `cargo kani list` the queue is diffed name for name against the list (compare_list.py, review M6):
# QUEUE defaults to queue.tsv next to this script; FLAVOUR is required (the queue's flavour column for
# this invocation). Any difference stops the preflight (exit 2) before codegen; a failed list exits 3
# (after kani-list.json is restored/removed). The cargo-kani args must equal the queue rows' args column.
# The HEADs of all five sibling worktrees under the kani-work root (KANI_WORK_ROOT, default: the directory
# holding percolator-prog, three levels above this script) are written to the log.
set -u
dir=$1; lab=$2; shift 2
HERE=${0:A:h}
ROOT=${KANI_WORK_ROOT:-${HERE:h:h:h}}
QUEUE=${QUEUE:-$HERE/queue.tsv}
FLAVOUR=${FLAVOUR:?set FLAVOUR to the queue flavour of this crate/invocation (none, devnet or mainnet)}
OUT=${PREFLIGHT_OUT:-$HOME/percolator-ops/artifacts/kani-v22-final/preflight}; mkdir -p $OUT
while (( $(sysctl -n vm.loadavg | awk '{print int($3)}') >= 8 )) || (( $(df -g $OUT | tail -1 | awk '{print $4}') < 40 )); do sleep 60; done
export CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=$OUT/target/$lab
cd $dir
{ echo "# $(date) $(git rev-parse HEAD) $lab $*"
  echo "# sibling worktree HEADs under $ROOT:"
  for r in percolator percolator-prog percolator-stake percolator-match percolator-nft; do
    echo "#   $r $(git -C $ROOT/$r rev-parse HEAD 2>/dev/null || echo MISSING) dirty=$(git -C $ROOT/$r status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  done
  cargo kani --version; } > $OUT/$lab.log
# review round 3: start from no kani-list.json (the engine tracks a stale copy, restored below), and a
# failed `cargo kani list` stops the preflight instead of comparing a stale or missing file
rm -f kani-list.json $OUT/$lab-kani-list.json
cargo kani list "$@" --format json >> $OUT/$lab.log 2>&1
lrc=$?
echo "cargo kani list rc=$lrc" >> $OUT/$lab.log
[ -f kani-list.json ] && cp kani-list.json $OUT/$lab-kani-list.json
# review round 2 B3: never leave kani-list.json behind in the frozen tree (the engine root tracks one:
# restore it; elsewhere remove it)
if git ls-files --error-unmatch kani-list.json >/dev/null 2>&1; then git checkout -- kani-list.json; else rm -f kani-list.json; fi
if (( lrc != 0 )) || [ ! -s $OUT/$lab-kani-list.json ]; then echo "preflight $lab: cargo kani list failed (rc=$lrc) or wrote no list; codegen not started" >&2; exit 3; fi
# review round 3: the selection key includes this invocation's args (queue args column)
python3 -I $HERE/compare_list.py $QUEUE $OUT/$lab-kani-list.json $dir $FLAVOUR "$*" >> $OUT/$lab.log 2>&1
cl=$?
echo "compare_list rc=$cl" >> $OUT/$lab.log
if (( cl != 0 )); then echo "preflight $lab: queue != cargo kani list (see $OUT/$lab.log); codegen not started" >&2; exit 2; fi
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
# review round 2 B3: the frozen trees must be exactly as frozen when the preflight ends
dirty=0
for r in percolator percolator-prog percolator-stake percolator-match percolator-nft; do
  st=$(git -C $ROOT/$r status --porcelain 2>/dev/null)
  if [ -n "$st" ]; then dirty=1; { echo "DIRTY after preflight: $r"; echo "$st"; } >> $OUT/$lab.log; fi
done
echo "frozen trees clean at exit: $(( dirty == 0 ))" >> $OUT/$lab.log
if (( dirty )); then echo "preflight $lab: a frozen tree is dirty (see $OUT/$lab.log)" >&2; exit 4; fi
