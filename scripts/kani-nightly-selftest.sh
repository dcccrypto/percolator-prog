#!/usr/bin/env bash
# Logic test for the Kani nightly verdict rules (no kani needed): classify() in
# scripts/kani-nightly-lib.sh and the summary judge scripts/kani-nightly-summary.sh, fed fake logs
# and fake verdict rows. usage: scripts/kani-nightly-selftest.sh  (exit 0 = all checks pass)
set -u
R=${1:-$(cd "$(dirname "$0")/.." && pwd)}; T=$(mktemp -d); pass=0; fail=0
. "$R/scripts/kani-nightly-lib.sh"
chk() { if [ "$1" = "$2" ]; then pass=$((pass+1)); echo "ok   $3: $1"; else fail=$((fail+1)); echo "FAIL $3: got $1 want $2"; fi; }
L=$T/l.log
# --- classify ---
printf 'CBMC timed out. You may want to rerun\nVERIFICATION:- FAILED\n' > $L;              classify $L 1 4200 4800; chk "$v" TIMEOUT "cbmc-timeout rc1"
: > $L;                                                                                   classify $L 137 300 4800; chk "$v" ERROR "OOM SIGKILL 137 at 300s"
: > $L;                                                                                   classify $L 143 1600 4800; chk "$v" ERROR "runner SIGTERM 143"
: > $L;                                                                                   classify $L 124 4800 4800; chk "$v" TIMEOUT "watchdog 124 at limit"
: > $L;                                                                                   classify $L 137 4861 4800; chk "$v" TIMEOUT "watchdog 137 after kill-after"
: > $L;                                                                                   classify $L 124 4700 4800; chk "$v" ERROR "124 before limit"
printf 'VERIFICATION:- SUCCESSFUL\n ** 3 of 3 cover properties satisfied\nComplete - 1 successfully verified harnesses, 0 failures, 1 total.\n' > $L
                                                                                         classify $L 0 50 4800; chk "$v" SUCCESSFUL "success, covers 3/3"
                                                                                          classify $L 137 50 4800; chk "$v" ERROR "success text but killed rc137"
printf 'VERIFICATION:- SUCCESSFUL\n2 of 3 cover properties satisfied\nComplete - 1 successfully verified harnesses, 0 failures, 1 total.\n' > $L
                                                                                          classify $L 0 50 4800; chk "$v" VACUOUS "success, covers 2/3"
printf ' ** 1 of 102 failed\nVERIFICATION:- FAILED\n' > $L;                             classify $L 1 50 4800; chk "$v" FAILED "real failure"
printf 'error: no harness named x\n' > $L;                                               classify $L 1 5 4800; chk "$v" ERROR "name rot"
# --- summary ---
S="$R/scripts/kani-nightly-summary.sh"
mk() { rm -rf $T/sh $T/out; mkdir -p $T/sh/kani-shard-tests-0 $T/sh/kani-shard-tests-1; printf 'a\nb\nc\n' > $T/exp; }
row() { printf '%s\t%s\t10\t-\tno covers\n' "$2" "$3" >> $T/sh/$1/verdicts.tsv; }
run() { "$S" $T/sh $T/exp "$1" $T/out > $T/judge.log 2>&1; echo $?; }
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run success)" 0 "summary all 3 SUCCESSFUL -> green"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL
chk "$(run success)" 1 "summary missing row c (shard result success) -> red"; grep -q 'no verdict row::c' $T/judge.log; chk $? 0 "  names c as missing"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c ERROR
chk "$(run success)" 1 "summary ERROR (OOM) row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b TIMEOUT; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run success)" 0 "summary TIMEOUT row -> green with warning"; grep -q '::warning title=Kani TIMEOUT (no verdict)::b' $T/judge.log; chk $? 0 "  warning emitted for b"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run success)" 1 "summary duplicate row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL; row kani-shard-tests-1 z SUCCESSFUL
chk "$(run success)" 1 "summary row for unselected name -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run failure)" 1 "summary shard result failure -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b FAILED; row kani-shard-tests-1 c VACUOUS
chk "$(run success)" 1 "summary FAILED+VACUOUS -> red"
mk; : > $T/exp; chk "$(run success)" 1 "summary empty selection -> red"
# end-to-end: classify an OOM log then judge
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; : > $L; classify $L 137 900 4800; row kani-shard-tests-1 c "$v"
chk "$(run success)" 1 "e2e OOM-killed harness -> ERROR row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; printf 'CBMC timed out.\n' > $L; classify $L 1 4210 4800; row kani-shard-tests-1 c "$v"
chk "$(run success)" 0 "e2e CBMC-timeout harness -> TIMEOUT row -> green+warning"
echo "PASS=$pass FAIL=$fail"; rm -rf $T; [ $fail = 0 ]
