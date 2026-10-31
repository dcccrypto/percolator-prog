#!/usr/bin/env bash
# Kani nightly summary: merge the shard verdicts and decide red/green.
# usage: scripts/kani-nightly-summary.sh <shards-dir> <expected-names-file> <shard-result> <outdir>
#   shards-dir      downloaded shard artifacts: <shards-dir>/<artifact>/verdicts.tsv
#   expected-names  one harness name per line: every row of ci/kani-nightly-harnesses.tsv in the
#                   selected groups (written by the plan job)
#   shard-result    needs.shard.result (success | failure | cancelled | skipped)
# RED (exit 1) on: any FAILED / VACUOUS / ERROR row; any expected harness without exactly one row
# (missing, duplicated, or a row for a name that was not selected); a shard job that did not
# succeed; an empty selection. TIMEOUT rows are warnings (no verdict), never a pass.
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
  for v in SUCCESSFUL TIMEOUT FAILED VACUOUS ERROR; do echo "- $v: $(cnt $v)"; done
  [ -n "$missing" ] && { echo; echo "### NO VERDICT ROW (shard died or row lost)"; echo "$missing" | sed 's/^/- `/; s/$/`/'; }
  [ -n "$dups" ] && { echo; echo "### DUPLICATE ROWS"; echo "$dups" | sed 's/^/- `/; s/$/`/'; }
  [ -n "$extra" ] && { echo; echo "### ROWS FOR UNSELECTED NAMES"; echo "$extra" | sed 's/^/- `/; s/$/`/'; }
  for v in FAILED VACUOUS ERROR TIMEOUT SUCCESSFUL; do
    [ "$(cnt $v)" = 0 ] && continue
    echo; echo "### $v"
    awk -F'\t' -v v=$v '$2==v {printf "- `%s` (%s s; %s; %s)\n", $1, $3, $4, $5}' "$out/verdicts.tsv"
  done
} > "$out/SUMMARY.md"
cat "$out/SUMMARY.md"
awk -F'\t' '$2=="TIMEOUT" {print "::warning title=Kani TIMEOUT (no verdict)::" $1}' "$out/verdicts.tsv"
rc=0
bad=$(awk -F'\t' '$2=="FAILED" || $2=="VACUOUS" || $2=="ERROR"' "$out/verdicts.tsv")
if [ -n "$bad" ]; then
  echo "$bad" | awk -F'\t' '{print "::error title=Kani " $2 "::" $1 " (" $4 "; " $5 ")"}'; rc=1
fi
bad=$(awk -F'\t' '$2!="SUCCESSFUL" && $2!="TIMEOUT" && $2!="FAILED" && $2!="VACUOUS" && $2!="ERROR"' "$out/verdicts.tsv")
[ -n "$bad" ] && { echo "::error::unknown verdict rows:"; echo "$bad"; rc=1; }
[ "$nexp" -gt 0 ] || { echo "::error::no harnesses selected"; rc=1; }
[ -n "$missing" ] && { echo "$missing" | awk '{print "::error title=Kani no verdict row::" $0}'; rc=1; }
[ -n "$dups" ] && { echo "$dups" | awk '{print "::error title=Kani duplicate verdict rows::" $0}'; rc=1; }
[ -n "$extra" ] && { echo "$extra" | awk '{print "::error title=Kani row for an unselected harness::" $0}'; rc=1; }
if [ "$total" != "$nexp" ]; then echo "::error::$total verdict rows != $nexp selected harnesses"; rc=1; fi
if [ "$shard_result" != "success" ]; then
  echo "::error::a shard job did not finish cleanly ($shard_result)"; rc=1
fi
exit $rc
