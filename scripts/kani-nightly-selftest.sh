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
# OOM (memory cap): cgroup oom_kill count, or an allocation failure under ulimit -v
: > $L;                                                                                   classify $L 137 300 4800 1; chk "$v" OOM "cgroup oom_kill=1, rc137 at 300s"
: > $L;                                                                                   classify $L 1 2400 4800 2; chk "$v" OOM "cgroup oom_kill=2, kani rc1 (cbmc killed)"
: > $L;                                                                                   classify $L 137 300 4800 0; chk "$v" ERROR "rc137, no oom_kill, before watchdog"
printf 'terminate called after throwing an instance of std::bad_alloc\n' > $L;           classify $L 134 900 4800; chk "$v" OOM "ulimit: bad_alloc rc134"
printf 'Out of memory!\n' > $L;                                                         classify $L 1 900 4800; chk "$v" OOM "ulimit: Out of memory rc1"
printf 'VERIFICATION:- SUCCESSFUL\nComplete - 1 successfully verified harnesses, 0 failures, 1 total.\n' > $L
                                                                                          classify $L 0 50 4800 1; chk "$v" ERROR "success text but oom_kill=1 -> not trusted"
printf 'Out of memory in a test name\nVERIFICATION:- SUCCESSFUL\nComplete - 1 successfully verified harnesses, 0 failures, 1 total.\n' > $L
                                                                                          classify $L 0 50 4800; chk "$v" SUCCESSFUL "OOM text but rc0 -> SUCCESSFUL"
printf 'CBMC timed out. You may want to rerun\n' > $L;                                  classify $L 1 4200 4800 0; chk "$v" TIMEOUT "cbmc-timeout, oom_kill=0"
printf ' ** 1 of 102 failed\nVERIFICATION:- FAILED\n' > $L;                             classify $L 1 50 4800 0; chk "$v" FAILED "real failure, oom_kill=0"
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
chk "$(run success)" 1 "summary ERROR row -> red"
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
chk "$(run success)" 1 "e2e unexplained kill (137, no oom_kill) -> ERROR row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; : > $L; classify $L 1 900 4800 1; row kani-shard-tests-1 c "$v"
chk "$(run success)" 0 "e2e capped OOM -> OOM row -> green+warning"; grep -q '::warning title=Kani OOM (no verdict)::c' $T/judge.log; chk $? 0 "  OOM warning emitted for c"
grep -q '^- OOM: 1$' $T/out/SUMMARY.md; chk $? 0 "  OOM counted in SUMMARY.md"
mk; chk "$(run failure)" 1 "summary 0 rows, all jobs died (run 41183972352) -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b OOM; printf 'c\tOOMKILLED\t1\t-\t-\n' >> $T/sh/kani-shard-tests-1/verdicts.tsv
chk "$(run success)" 1 "summary unknown verdict label -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; printf 'CBMC timed out.\n' > $L; classify $L 1 4210 4800; row kani-shard-tests-1 c "$v"
chk "$(run success)" 0 "e2e CBMC-timeout harness -> TIMEOUT row -> green+warning"
# --- the per-harness script end to end, with a fake `cargo` (needs coreutils timeout; Linux CI) ---
SH="$R/scripts/kani-nightly-shard.sh"
H=$(grep -v '^#' "$R/ci/kani-nightly-harnesses.tsv" | awk -F'\t' '$1=="tests" {print $2; exit}')
if command -v timeout > /dev/null || command -v gtimeout > /dev/null; then
  mkdir -p $T/bin
  cat > $T/bin/cargo <<'FAKE'
#!/usr/bin/env bash
case "$*" in *--only-codegen*) exit 0 ;; esac
case "$FAKE_KANI" in
  ok)   echo 'VERIFICATION:- SUCCESSFUL'; echo 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.' ;;
  fail) echo ' ** 2 of 50 failed'; echo 'VERIFICATION:- FAILED'; exit 1 ;;
  hog)  python3 -c 'b = b"x" * (1 << 30); print(len(b))'; echo 'VERIFICATION:- FAILED'; exit 1 ;;
esac
FAKE
  chmod +x $T/bin/cargo
  one() { rm -rf $T/kn; FAKE_KANI=$1 PATH="$T/bin:$PATH" "$SH" tests "$2" 1m $T/kn ${3:-} > $T/shard.log 2>&1; echo $?; }
  chk "$(one ok "$H")" 0 "shard script exits 0"; chk "$(cut -f2 $T/kn/verdicts.tsv)" SUCCESSFUL "shard fake success -> 1 SUCCESSFUL row"
  one fail "$H" > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" FAILED "shard fake counterexample -> FAILED row"
  one ok not_a_listed_harness > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" ERROR "shard unlisted name -> ERROR row"
  chk "$(wc -l < $T/kn/verdicts.tsv | tr -d ' ')" 1 "  exactly one row"
  if [ "$(uname)" = Linux ] && sudo -n true 2>/dev/null && grep -qw memory /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
    one hog "$H" 128M > /dev/null; grep 'memory cap:' $T/shard.log
    chk "$(cut -f2 $T/kn/verdicts.tsv)" OOM "shard 1 GiB allocation under a 128M cgroup cap -> OOM row"
    grep -q 'memory cap: cgroup memory.max=134217728' $T/shard.log; chk $? 0 "  cap applied as a cgroup memory.max"
    one ok "$H" 128M > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" SUCCESSFUL "shard under the cap, small run -> SUCCESSFUL"
    ls -d /sys/fs/cgroup/kani-nightly-* > /dev/null 2>&1; chk $? 2 "  no leftover kani-nightly cgroups"
  else
    echo "skip cgroup OOM case (needs Linux, cgroup v2 memory controller, passwordless sudo)"
  fi
else
  echo "skip shard-script cases (no coreutils timeout here; they run in the workflow's plan job)"
fi
echo "PASS=$pass FAIL=$fail"; rm -rf $T; [ $fail = 0 ]
