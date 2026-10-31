#!/usr/bin/env bash
# Kani nightly: verify ONE harness of ci/kani-nightly-harnesses.tsv and write exactly one verdict row.
# usage: scripts/kani-nightly-shard.sh <group> <harness> <harness-timeout> <outdir> [mem-cap]
#   group           lib | tests | contlev | p3 | p3-engine | growth (crate + flags below)
#   harness         exact harness name (as listed in the TSV for that group)
#   harness-timeout passed to kani --harness-timeout (e.g. 70m); a hard watchdog adds 10 min
#   mem-cap         memory limit for the verification (e.g. 13G; default none). On Linux with
#                   passwordless sudo this is a cgroup-v2 memory.max (swap 0); otherwise `ulimit -v`.
#                   Must sit below the runner's RAM so CBMC is killed before the runner VM is.
# One harness per job (the workflow's matrix): a dying harness can only lose its own row, and the
# summary job is red on a missing row.
# Verdicts (<outdir>/verdicts.tsv: harness, verdict, seconds, failed checks, covers, peak MiB),
# rules in scripts/kani-nightly-lib.sh (classify):
#   SUCCESSFUL   kani "VERIFICATION:- SUCCESSFUL" and every cover property SATISFIED (or none declared)
#   VACUOUS      SUCCESSFUL but some cover property not satisfied -- the pass proves less than claimed
#   FAILED       a real check failed (a counterexample exists)
#   TIMEOUT      "CBMC timed out" (--harness-timeout), or the watchdog fired at its limit. NO VERDICT
#   OOM          the memory cap was hit (cgroup oom_kill > 0, or an allocation failure in the log under
#                ulimit). NO VERDICT, not a pass, not a failure
#   ERROR        anything else (build failure, name not found, crash, unexplained kill)
# Always exits 0 once the row is written; the workflow's summary job decides red/green.
# Local (from the repo root, engine checked out as ../percolator at ENGINE_CI_SIBLING):
#   scripts/kani-nightly-shard.sh p3-engine <harness> 30m /tmp/kn
set -uo pipefail
group=$1; h=$2; tmo=$3; out=$4; memcap=${5:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=scripts/kani-nightly-lib.sh
. "$ROOT/scripts/kani-nightly-lib.sh"   # classify()
LIST="$ROOT/ci/kani-nightly-harnesses.tsv"
Z="-Z unstable-options -Z function-contracts -Z stubbing"
case "$group" in
  lib)       dir=.;               args="--lib --features devnet $Z" ;;
  tests)     dir=.;               args="--tests --features devnet $Z" ;;
  contlev)   dir=kani/contlev;    args="$Z" ;;
  p3)        dir=kani/p3;         args="$Z" ;;
  p3-engine) dir=kani/p3-engine;  args="$Z" ;;
  growth)    dir=kani/growth;     args="$Z" ;;
  *) echo "unknown group $group" >&2; exit 2 ;;
esac
TMO_BIN=$(command -v timeout || command -v gtimeout) || { echo "need coreutils timeout" >&2; exit 2; }
mkdir -p "$out/logs"
out=$(cd "$out" && pwd)
log="$out/logs/$(echo "$h" | tr ':/' '__').log"
row() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$1" "$2" "$3" "$4" "$5" >> "$out/verdicts.tsv"; echo "$1  $h  ($2 s; $3; $4; peak $5 MiB)"; }
# The name must be a row of this group (the plan already checked; this guards local use).
grep -v '^#' "$LIST" | awk -F'\t' -v g="$group" -v n="$h" '$1==g && $2==n {f=1} END {exit !f}' \
  || { row ERROR 0 "not a row of group $group in ci/kani-nightly-harnesses.tsv" - -; exit 0; }

# minutes for the watchdog (accepts Ns / Nm / Nh)
case "$tmo" in *h) wd=$(( ${tmo%h} * 60 + 10 ));; *m) wd=$(( ${tmo%m} + 10 ));; *s) wd=$(( ${tmo%s} / 60 + 10 ));; *) wd=$(( tmo / 60 + 10 ));; esac
echo "group=$group harness=$h timeout=$tmo watchdog=${wd}m mem-cap=${memcap:-none} dir=$dir"

cd "$ROOT/$dir" || exit 2
# Compile first (outside the watchdog and the memory cap); a compile failure is an ERROR row.
echo "::group::kani build ($group)"
if ! cargo kani $args --only-codegen > "$out/logs/_build.log" 2>&1; then
  tail -40 "$out/logs/_build.log"; echo "::endgroup::"
  row ERROR 0 "build failed (see logs/_build.log)" - -
  exit 0
fi
tail -3 "$out/logs/_build.log"; echo "::endgroup::"

# --- memory cap ---------------------------------------------------------------------------------
cg=""; capmode=none
if [ -n "$memcap" ]; then
  [[ "$memcap" =~ ^[0-9]+[MG]$ ]] || { echo "bad mem-cap $memcap (want e.g. 13G)" >&2; exit 2; }
  if [ -f /sys/fs/cgroup/cgroup.subtree_control ] && grep -qw memory /sys/fs/cgroup/cgroup.subtree_control \
     && sudo -n true 2>/dev/null; then
    cg=/sys/fs/cgroup/kani-nightly-$$
    if sudo -n mkdir "$cg" && echo "$memcap" | sudo -n tee "$cg/memory.max" > /dev/null; then
      echo 0 | sudo -n tee "$cg/memory.swap.max" > /dev/null 2>&1 || echo "note: memory.swap.max not settable"
      capmode="cgroup memory.max=$(cat "$cg/memory.max") swap.max=$(cat "$cg/memory.swap.max" 2>/dev/null || echo n/a)"
    else
      sudo -n rmdir "$cg" 2>/dev/null; cg=""
    fi
  fi
  if [ -z "$cg" ]; then
    case "$memcap" in *G) kb=$(( ${memcap%G} * 1024 * 1024 ));; *M) kb=$(( ${memcap%M} * 1024 ));; esac
    capmode="ulimit -v ${kb} KiB"
  fi
fi
echo "memory cap: $capmode"; free -m 2>/dev/null || true

# Sampler: memory (and disk) use every 2 min to the job log (survives in the log even if the job dies).
(
  while sleep 120; do
    cur=-; [ -n "$cg" ] && cur=$(( $(cat "$cg/memory.current" 2>/dev/null || echo 0) / 1048576 ))
    av=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo -)
    dk=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
    echo "[mem $(date -u +%H:%M:%S)] harness cgroup ${cur} MiB, MemAvailable ${av} MiB, disk free ${dk:-?} MiB"
  done
) & sampler=$!

t0=$(date +%s)
# timeout(1) makes itself a process-group leader; after it returns, kill whatever is left in that
# group (kani's own --harness-timeout can leave cbmc/z3 orphans).
(
  if [ -n "$cg" ]; then sudo -n sh -c "echo $BASHPID > '$cg/cgroup.procs'" || exit 125
  elif [ -n "$memcap" ]; then ulimit -v "$kb" || exit 125
  fi
  exec "$TMO_BIN" --kill-after=60 "${wd}m" cargo kani $args --harness-timeout "$tmo" --harness "$h" --exact
) > "$log" 2>&1 &
pid=$!
wait "$pid"; rc=$?
kill -KILL -- "-$pid" 2>/dev/null || true
t1=$(date +%s)
kill "$sampler" 2>/dev/null || true

oomk=0; peak=-
if [ -n "$cg" ]; then
  oomk=$(awk '$1=="oom_kill" {print $2}' "$cg/memory.events" 2>/dev/null); oomk=${oomk:-0}
  p=$(cat "$cg/memory.peak" 2>/dev/null) && peak=$(( p / 1048576 ))
  echo 1 | sudo -n tee "$cg/cgroup.kill" > /dev/null 2>&1 || true
  sleep 1; sudo -n rmdir "$cg" 2>/dev/null || echo "note: could not remove $cg"
fi
[ "$rc" = 125 ] && echo "could not apply the memory cap" >> "$log"
tail -30 "$log"
classify "$log" "$rc" "$((t1-t0))" "$((wd*60))" "$oomk"
row "$v" "$((t1-t0))" "${fc:--}" "${cov:-no covers}" "$peak"
exit 0
