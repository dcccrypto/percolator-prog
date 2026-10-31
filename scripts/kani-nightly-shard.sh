#!/usr/bin/env bash
# Kani nightly: run ONE shard of ci/kani-nightly-harnesses.tsv and write one verdict per harness.
# usage: scripts/kani-nightly-shard.sh <group> <chunk-index> <chunk-size> <harness-timeout> <jobs> <outdir>
#   group           lib | tests | contlev | p3 | p3-engine | growth (crate + flags below)
#   chunk-index     0-based chunk of that group's rows, chunk-size rows per chunk
#   harness-timeout passed to kani --harness-timeout (e.g. 75m); a hard watchdog adds 10 min
#   jobs            harnesses run concurrently on this runner (one `cargo kani` process each)
# Verdicts (<outdir>/verdicts.tsv: harness, verdict, seconds, failed checks, covers):
#   SUCCESSFUL   kani "VERIFICATION:- SUCCESSFUL" and every cover property SATISFIED (or none declared)
#   VACUOUS      SUCCESSFUL but some cover property not satisfied -- the pass proves less than claimed
#   FAILED       a real check failed (a counterexample exists)
#   TIMEOUT      CBMC hit --harness-timeout (or the watchdog fired): NO VERDICT, not a pass, not a failure
#   ERROR        anything else (compile error, harness name not found, crash)
# Always exits 0 once verdicts are written; the workflow's summary job decides red/green.
# Local (from the repo root, engine checked out as ../percolator at ENGINE_CI_SIBLING):
#   scripts/kani-nightly-shard.sh p3-engine 0 3 30m 2 /tmp/kn
set -uo pipefail
group=$1; chunk=$2; size=$3; tmo=$4; jobs=$5; out=$6
ROOT=$(cd "$(dirname "$0")/.." && pwd)
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
hs=()
while IFS= read -r h; do hs+=("$h"); done < <(grep -v '^#' "$LIST" | awk -F'\t' -v g="$group" '$1==g {print $2}' | sed -n "$((chunk*size+1)),$(((chunk+1)*size))p")
[ "${#hs[@]}" -gt 0 ] || { echo "group $group chunk $chunk is empty" >&2; exit 2; }
echo "group=$group chunk=$chunk harnesses=${#hs[@]} timeout=$tmo jobs=$jobs dir=$dir"
printf '%s\n' "${hs[@]}"

# minutes for the watchdog (accepts Ns / Nm / Nh)
case "$tmo" in *h) wd=$(( ${tmo%h} * 60 + 10 ));; *m) wd=$(( ${tmo%m} + 10 ));; *s) wd=$(( ${tmo%s} / 60 + 10 ));; *) wd=$(( tmo / 60 + 10 ));; esac

cd "$ROOT/$dir" || exit 2
# Compile once up front (every harness run reuses the build); a compile failure is an ERROR row
# for every harness of the shard, not a silent skip.
echo "::group::kani build ($group)"
if ! cargo kani $args --only-codegen > "$out/logs/_build.log" 2>&1; then
  tail -40 "$out/logs/_build.log"; echo "::endgroup::"
  for h in "${hs[@]}"; do printf '%s\tERROR\t0\tbuild failed (see logs/_build.log)\t-\n' "$h" >> "$out/verdicts.tsv"; done
  exit 0
fi
tail -3 "$out/logs/_build.log"; echo "::endgroup::"

run_one() {
  local h=$1 log="$out/logs/$(echo "$1" | tr ':/' '__').log" t0 t1 v fc cov
  t0=$(date +%s)
  "$TMO_BIN" --kill-after=60 "${wd}m" cargo kani $args --harness-timeout "$tmo" --harness "$h" --exact > "$log" 2>&1
  local rc=$?
  t1=$(date +%s)
  cov=$(grep -Eo '[0-9]+ of [0-9]+ cover properties satisfied' "$log" | tail -1)
  fc=$(grep -Eo '\*\* [0-9]+ of [0-9]+ failed' "$log" | tail -1 | sed 's/\*\* //')
  if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then v=TIMEOUT; fc="watchdog ${wd}m"
  elif grep -q 'CBMC timed out' "$log"; then v=TIMEOUT
  elif grep -q 'VERIFICATION:- SUCCESSFUL' "$log" && grep -q 'Complete - 1 successfully verified harnesses, 0 failures' "$log"; then
    v=SUCCESSFUL
    if [ -n "$cov" ]; then set -- $cov; [ "$1" = "$3" ] || v=VACUOUS; fi
  elif echo "$fc" | grep -Eq '^[1-9][0-9]* of'; then v=FAILED
  else v=ERROR; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$h" "$v" "$((t1-t0))" "${fc:--}" "${cov:-no covers}" >> "$out/verdicts.tsv"
  echo "$v  $h  ($((t1-t0)) s; ${fc:--}; ${cov:-no covers})"
}
export -f run_one; export args tmo wd out TMO_BIN
printf '%s\n' "${hs[@]}" | xargs -P "$jobs" -I{} bash -c 'run_one "$@"' _ {}
echo "---"; cat "$out/verdicts.tsv"
exit 0
