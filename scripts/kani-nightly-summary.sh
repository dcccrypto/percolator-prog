#!/usr/bin/env bash
# Kani nightly summary: merge the shard verdicts and decide red/green.
# usage: scripts/kani-nightly-summary.sh <shards-dir> <expected-names-file> <shard-result> <outdir>
#   shards-dir      downloaded per-harness artifacts: <shards-dir>/<artifact>/verdicts.tsv
#   expected-names  one harness name per line: every row of ci/kani-nightly-harnesses.tsv in the
#                   selected groups (written by the plan job)
#   shard-result    needs.shard.result (success | failure | cancelled | skipped); one job per harness.
#                   A harness job is red whenever its row is not SUCCESSFUL, so `failure` is expected
#                   when such a row exists; it is reported as unexplained only when every row passed.
# GREEN (exit 0) only when every selected harness has exactly one row and every row is SUCCESSFUL.
# RED (exit 1) on: any FAILED / VACUOUS / ERROR row; any TIMEOUT or OOM row (no verdict: the wall or
# memory budget ran out, so the harness is NOT proved -- Khubair, 5 Nov 2026: a green nightly must
# mean proved); any expected harness without exactly one row (missing, duplicated, or a row for a
# name that was not selected); a cancelled / skipped / unexplained shard result; an empty selection.
set -uo pipefail
shards=$1; expected=$2; shard_result=$3; out=$4
mkdir -p "$out"
cat "$shards"/*/verdicts.tsv 2>/dev/null | sort > "$out/verdicts.tsv" || true
total=$(wc -l < "$out/verdicts.tsv" | tr -d ' ')
nexp=$(grep -c . "$expected" || true)
cut -f1 "$out/verdicts.tsv" | sort > "$out/_got"
grep . "$expected" | sort > "$out/_want"
missing=$(comm -23 <(sort -u "$out/_want") <(sort -u "$out/_got"))
extra=$(comm -13 <(sort -u "$out/_want") <(sort -u "$out/_got"))
dups=$(uniq -d "$out/_got")
rm -f "$out/_got" "$out/_want"
cnt() { awk -F'\t' -v v="$1" '$2==v' "$out/verdicts.tsv" | wc -l | tr -d ' '; }
{
  echo "## Kani nightly: $total verdict rows for $nexp selected harnesses (shard jobs: $shard_result)"
  echo "Green only if every harness is SUCCESSFUL. TIMEOUT / OOM = not proved = red."
  for v in SUCCESSFUL TIMEOUT OOM FAILED VACUOUS ERROR; do echo "- $v: $(cnt $v)"; done
  [ -n "$missing" ] && { echo; echo "### NO VERDICT ROW (shard died or row lost)"; echo "$missing" | sed 's/^/- `/; s/$/`/'; }
  [ -n "$dups" ] && { echo; echo "### DUPLICATE ROWS"; echo "$dups" | sed 's/^/- `/; s/$/`/'; }
  [ -n "$extra" ] && { echo; echo "### ROWS FOR UNSELECTED NAMES"; echo "$extra" | sed 's/^/- `/; s/$/`/'; }
  for v in FAILED VACUOUS ERROR OOM TIMEOUT SUCCESSFUL; do
    [ "$(cnt $v)" = 0 ] && continue
    echo; echo "### $v"
    awk -F'\t' -v v=$v '$2==v {printf "- `%s` (%s s; %s; %s; peak %s MiB)\n", $1, $3, $4, $5, ($6 == "" ? "-" : $6)}' "$out/verdicts.tsv"
  done
} > "$out/SUMMARY.md"
cat "$out/SUMMARY.md"
rc=0
bad=$(awk -F'\t' '$2=="FAILED" || $2=="VACUOUS" || $2=="ERROR"' "$out/verdicts.tsv")
if [ -n "$bad" ]; then
  echo "$bad" | awk -F'\t' '{print "::error title=Kani " $2 "::" $1 " (" $4 "; " $5 ")"}'; rc=1
fi
# No verdict is not a pass: red, named per harness.
bad=$(awk -F'\t' '$2=="TIMEOUT" || $2=="OOM"' "$out/verdicts.tsv")
if [ -n "$bad" ]; then
  echo "$bad" | awk -F'\t' '{print "::error title=Kani " $2 " (no verdict, not proved)::" $1 " (" $3 " s; " $4 ")"}'; rc=1
fi
bad=$(awk -F'\t' '$2!="SUCCESSFUL" && $2!="TIMEOUT" && $2!="OOM" && $2!="FAILED" && $2!="VACUOUS" && $2!="ERROR"' "$out/verdicts.tsv")
[ -n "$bad" ] && { echo "::error::unknown verdict rows:"; echo "$bad"; rc=1; }
[ "$nexp" -gt 0 ] || { echo "::error::no harnesses selected"; rc=1; }
[ -n "$missing" ] && { echo "$missing" | awk '{print "::error title=Kani no verdict row::" $0}'; rc=1; }
[ -n "$dups" ] && { echo "$dups" | awk '{print "::error title=Kani duplicate verdict rows::" $0}'; rc=1; }
[ -n "$extra" ] && { echo "$extra" | awk '{print "::error title=Kani row for an unselected harness::" $0}'; rc=1; }
if [ "$total" != "$nexp" ]; then echo "::error::$total verdict rows != $nexp selected harnesses"; rc=1; fi
nonpass=$(awk -F'\t' '$2!="SUCCESSFUL"' "$out/verdicts.tsv" | wc -l | tr -d ' ')
case "$shard_result" in
  success) ;;
  # A harness job goes red on its own non-SUCCESSFUL row: that failure is already explained above.
  failure) [ "$nonpass" -gt 0 ] || { echo "::error::a shard job failed but every verdict row is SUCCESSFUL (unexplained)"; rc=1; } ;;
  *) echo "::error::shard jobs did not finish ($shard_result)"; rc=1 ;;
esac
exit $rc
