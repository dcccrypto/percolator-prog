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
chk "$(run success)" 1 "summary TIMEOUT row -> RED (no verdict is not a pass)"; grep -q '::error title=Kani TIMEOUT (no verdict, not proved)::b' $T/judge.log; chk $? 0 "  error names b"
chk "$(run failure)" 1 "summary TIMEOUT row + its red harness job -> red"; grep -q 'unexplained' $T/judge.log; chk $? 1 "  job failure explained by the TIMEOUT row (no 'unexplained')"
chk "$(run cancelled)" 1 "summary cancelled shard jobs -> red"; grep -q 'did not finish (cancelled)' $T/judge.log; chk $? 0 "  says cancelled"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run success)" 1 "summary duplicate row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL; row kani-shard-tests-1 z SUCCESSFUL
chk "$(run success)" 1 "summary row for unselected name -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; row kani-shard-tests-1 c SUCCESSFUL
chk "$(run failure)" 1 "summary shard result failure with all rows SUCCESSFUL -> red"; grep -q 'unexplained' $T/judge.log; chk $? 0 "  says unexplained"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b FAILED; row kani-shard-tests-1 c VACUOUS
chk "$(run success)" 1 "summary FAILED+VACUOUS -> red"
mk; : > $T/exp; chk "$(run success)" 1 "summary empty selection -> red"
# end-to-end: classify an OOM log then judge
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; : > $L; classify $L 137 900 4800; row kani-shard-tests-1 c "$v"
chk "$(run success)" 1 "e2e unexplained kill (137, no oom_kill) -> ERROR row -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; : > $L; classify $L 1 900 4800 1; row kani-shard-tests-1 c "$v"
chk "$(run success)" 1 "e2e capped OOM -> OOM row -> RED"; grep -q '::error title=Kani OOM (no verdict, not proved)::c' $T/judge.log; chk $? 0 "  OOM error names c"
grep -q '^- OOM: 1$' $T/out/SUMMARY.md; chk $? 0 "  OOM counted in SUMMARY.md"
mk; chk "$(run failure)" 1 "summary 0 rows, all jobs died (run 41183972352) -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b OOM; printf 'c\tOOMKILLED\t1\t-\t-\n' >> $T/sh/kani-shard-tests-1/verdicts.tsv
chk "$(run success)" 1 "summary unknown verdict label -> red"
mk; row kani-shard-tests-0 a SUCCESSFUL; row kani-shard-tests-0 b SUCCESSFUL; printf 'CBMC timed out.\n' > $L; classify $L 1 4210 4800; row kani-shard-tests-1 c "$v"
chk "$(run success)" 1 "e2e CBMC-timeout harness -> TIMEOUT row -> RED"
# --- plan (scripts/kani-nightly-plan.py) on a fake tree: globs, long groups, z3, budget ---
P="$R/scripts/kani-nightly-plan.py"; F=$T/tree
mkdir -p $F/ci $F/kani/growth/src $F/kani/bonds571/src $F/src
cat > $F/kani/growth/src/proofs.rs <<'RS'
#[kani::proof]
#[kani::solver(z3)]
#[kani::stub_verified(crate::m::f)]
fn kani_growth_occ_a() {}
#[kani::proof]
/// doc between attributes
fn kani_growth_occ_b() {}
fn kani_growth_occ_helper_not_a_proof() {}
#[kani::proof]
fn kani_growth_x() {}
RS
printf '#[kani::proof]\n#[kani::solver(cadical)]\nfn kani_571_a() {}\n' > $F/kani/bonds571/src/proofs.rs
printf '#[kani::proof]\nfn kani_lib_a() {}\nfn kani_lib_not_a_proof() {}\n' > $F/src/lib.rs
tsv() { printf '# c\n' > $F/ci/kani-nightly-harnesses.tsv; printf '%b\n' "$@" >> $F/ci/kani-nightly-harnesses.tsv; }
plan() { rm -f $T/po; python3 "$P" --root $F --out $T/po "$@" > $T/plan.log 2>&1; echo $?; }
mx() { python3 -c 'import json,sys; m=json.loads([l[7:] for l in open(sys.argv[1]) if l.startswith("matrix=")][0]); print(" ".join(":".join(str(v) for v in (e["group"], e["harness"], e["timeout"], int(e["z3"]))) for e in m["include"]))' $T/po; }
tsv 'lib\tkani_lib_a' 'growth\tproofs::kani_growth_x' 'bonds571\tproofs::kani_571_a' 'growth-occ\tproofs::kani_growth_occ_*'
chk "$(plan --groups all)" 0 "plan fake tree, all groups"
chk "$(mx)" "lib:kani_lib_a:180m:0 growth:proofs::kani_growth_x:180m:0 bonds571:proofs::kani_571_a:315m:0 growth-occ:proofs::kani_growth_occ_a:315m:1 growth-occ:proofs::kani_growth_occ_b:315m:0" \
  "  glob -> proof fns only (helper skipped), long groups 315m, z3 from the attribute"
chk "$(plan --groups growth-occ --solver z3)" 0 "plan --solver z3"; chk "$(mx)" "growth-occ:proofs::kani_growth_occ_a:315m:1 growth-occ:proofs::kani_growth_occ_b:315m:1" "  override -> z3 for every harness"
chk "$(plan --groups bonds571 --long-timeout 324m)" 0 "plan long 324m fits (15 + 334 + 1 = 350)"
chk "$(plan --groups bonds571 --long-timeout 325m)" 1 "plan long 325m refused"
chk "$(plan --groups lib --timeout 314m)" 0 "plan normal 314m fits (25 + 324 + 1)"
chk "$(plan --groups lib --timeout 315m)" 1 "plan normal 315m refused"
chk "$(plan --groups lib --solver yices)" 1 "plan bad solver refused"
chk "$(plan --groups lib --runner ubuntu-latest-16-cores)" 0 "plan runner label accepted"; grep -q '^runner=ubuntu-latest-16-cores$' $T/po; chk $? 0 "  runner written to the outputs"
chk "$(plan --groups lib)" 0 "plan default runner"; grep -q '^runner=ubuntu-latest$' $T/po; chk $? 0 "  default ubuntu-latest"
chk "$(plan --groups lib --runner 'a b')" 1 "plan runner label with a space refused"
chk "$(plan --groups lib --runner '${{x}}')" 1 "plan runner label with an expression refused"
chk "$(plan --groups nope)" 1 "plan unknown group refused"
# a glob matching nothing is RED even when an exact row keeps the group non-empty (v652 B1)
tsv 'lib\tkani_lib_a' 'growth-occ\tproofs::kani_growth_x' 'growth-occ\tproofs::kani_growth_zzz_*'
chk "$(plan --groups growth-occ)" 1 "plan glob matching nothing, exact row in the group -> red"; grep -q 'glob matches no harness' $T/plan.log; chk $? 0 "  names the glob"
chk "$(plan --groups lib)" 1 "plan glob matching nothing, group not even selected -> red"
tsv 'growth\tproofs::kani_growth_occ_a' 'growth-occ\tproofs::kani_growth_occ_*'
chk "$(plan --groups all)" 1 "plan name listed twice after glob expansion -> red"
tsv 'bonds571\tproofs::kani_571_gone'
chk "$(plan --groups all)" 1 "plan exact row with no fn (name rot) -> red"
tsv 'lib\tkani_lib_not_a_proof'
chk "$(plan --groups all)" 1 "plan exact row naming a non-harness fn -> red"
# harness shapes (v652 B2): none may drop out of a glob, z3 found wherever the attribute sits
PS=$F/kani/growth/src/proofs.rs; cp $PS $T/proofs.keep
cat > $PS <<'RS'
// #[kani::proof] in a comment is not a harness: fn kani_growth_occ_commented() {}
/* #[kani::proof]
   /* nested */ fn kani_growth_occ_block_commented() {} */
const S: &str = "#[kani::proof] fn kani_growth_occ_in_string() {} // not a comment";
const R: &str = r#"#[kani::proof] "quoted" fn kani_growth_occ_in_raw() {}"#;
const C: char = '"';
fn lt<'a>(x: &'a u8) -> &'a u8 { x }
#[kani::proof_for_contract(crate::m::f)]
#[kani::solver(z3)]
fn kani_growth_occ_contract() {}
#[kani::proof]
unsafe fn kani_growth_occ_unsafe() {}
#[kani::proof]
#[kani::stub(a::<[u8; 4]>::b, c)]
fn kani_growth_occ_nested() {}
#[kani::solver(z3)]
#[kani::proof]
pub(crate) fn kani_growth_occ_attr_first() {}
#[cfg_attr(kani, kani::proof)]
#[kani::solver(cadical)]
const fn kani_growth_occ_cfg_attr() {}
#[kani::proof] // trailing comment
/// doc
#[kani::unwind(3)]
fn kani_growth_exact_contract_row() {}
fn kani_growth_occ_helper() {}
RS
tsv 'growth-occ\tproofs::kani_growth_occ_*' 'growth-occ\tproofs::kani_growth_exact_contract_row'
chk "$(plan --groups growth-occ)" 0 "plan harness shapes"
chk "$(mx)" "growth-occ:proofs::kani_growth_occ_attr_first:315m:1 growth-occ:proofs::kani_growth_occ_cfg_attr:315m:0 growth-occ:proofs::kani_growth_occ_contract:315m:1 growth-occ:proofs::kani_growth_occ_nested:315m:0 growth-occ:proofs::kani_growth_occ_unsafe:315m:0 growth-occ:proofs::kani_growth_exact_contract_row:315m:0" \
  "  contract, unsafe, nested brackets, cfg_attr, z3 before proof; comments/strings/helpers skipped"
printf '#[kani::proof_for_contract(crate::m::f)]\n#[kani::solver(z3)]\nfn kani_growth_occ_only() {}\n' > $PS
tsv 'growth-occ\tproofs::kani_growth_occ_only'
chk "$(plan --groups growth-occ)" 0 "plan exact contract row"; chk "$(mx)" "growth-occ:proofs::kani_growth_occ_only:315m:1" "  z3 seen on an exact contract row"
# fail closed: a proof attribute not tied to a fn
printf 'macro_rules! m { ($n:ident) => { #[kani::proof] fn $n() {} } }\n#[kani::proof]\nfn kani_growth_occ_ok() {}\n' > $PS
tsv 'growth-occ\tproofs::kani_growth_occ_*'
chk "$(plan --groups growth-occ)" 1 "plan proof attribute on a macro-generated fn -> red"; grep -q 'not tied to a fn' $T/plan.log; chk $? 0 "  says so"; grep -q 'kani/growth/src/proofs.rs:1' $T/plan.log; chk $? 0 "  file:line"
printf 'kani::proof!(x);\n#[kani::proof]\nfn kani_growth_occ_ok() {}\n' > $PS
chk "$(plan --groups growth-occ)" 1 "plan kani::proof outside an attribute -> red"
printf '#[kani::proof]\nstruct NotAFn;\n#[kani::proof]\nfn kani_growth_occ_ok() {}\n' > $PS
chk "$(plan --groups growth-occ)" 1 "plan proof attribute on a non-fn -> red"
printf '#[kani::proof\nfn kani_growth_occ_ok() {}\n' > $PS
chk "$(plan --groups growth-occ)" 1 "plan unterminated attribute -> red"
cp $T/proofs.keep $PS
chk "$(plan --root "$R" --groups bonds571 --out $T/po)" 0 "plan real tree bonds571"
chk "$(mx | wc -w | tr -d ' ')" 6 "  6 bonds571 jobs"; chk "$(mx | tr ' ' '\n' | cut -d: -f5 | sort -u | tr '\n' ' ')" "315m " "  all at 315m"
chk "$(plan --root "$R" --groups all --out $T/po)" 0 "plan real tree all groups"
chk "$(mx | tr ' ' '\n' | grep -c '^lib:\|^tests:\|^growth:\|^p3:\|^contlev:\|^p3-engine:')" 84 "  the 85 no-verdict harnesses: 84 at 180m (kani_growth_c_mul_div_ceil moved to growth-occ)"
chk "$(mx | tr ' ' '\n' | grep '^lib:\|^tests:\|^growth:\|^p3:\|^contlev:\|^p3-engine:' | awk -F: '{print $(NF-1)}' | sort -u | tr '\n' ' ')" "180m " "  all 84 at the 180m default"
chk "$(mx | tr " " "\n" | grep -c "^growth-occ:proofs::kani_growth_c_mul_div_ceil:315m:")" 1 "  kani_growth_c_mul_div_ceil in growth-occ at 315m"
# --- the per-harness script end to end, with a fake `cargo` (needs coreutils timeout; Linux CI) ---
SH="$R/scripts/kani-nightly-shard.sh"
H=$(grep -v '^#' "$R/ci/kani-nightly-harnesses.tsv" | awk -F'\t' '$1=="tests" {print $2; exit}')
if command -v timeout > /dev/null || command -v gtimeout > /dev/null; then
  mkdir -p $T/bin
  cat > $T/bin/cargo <<'FAKE'
#!/usr/bin/env bash
case "$*" in *--only-codegen*) exit 0 ;; esac
echo "$PWD :: $*" > "$FAKE_ARGS"
case "$FAKE_KANI" in
  ok)   echo 'VERIFICATION:- SUCCESSFUL'; echo 'Complete - 1 successfully verified harnesses, 0 failures, 1 total.' ;;
  fail) echo ' ** 2 of 50 failed'; echo 'VERIFICATION:- FAILED'; exit 1 ;;
  hog)  python3 -c 'b = b"x" * (1 << 30); print(len(b))'; echo 'VERIFICATION:- FAILED'; exit 1 ;;
esac
FAKE
  chmod +x $T/bin/cargo
  export FAKE_ARGS=$T/args
  one() { rm -rf $T/kn; FAKE_KANI=$1 PATH="$T/bin:$PATH" "$SH" ${G:-tests} "$2" ${TM:-1m} $T/kn "${3:-}" "${4:-}" > $T/shard.log 2>&1; echo $?; }
  chk "$(one ok "$H")" 0 "shard script exits 0"; chk "$(cut -f2 $T/kn/verdicts.tsv)" SUCCESSFUL "shard fake success -> 1 SUCCESSFUL row"
  one fail "$H" > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" FAILED "shard fake counterexample -> FAILED row"
  one ok not_a_listed_harness > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" ERROR "shard unlisted name -> ERROR row"
  chk "$(wc -l < $T/kn/verdicts.tsv | tr -d ' ')" 1 "  exactly one row"
  # long groups: glob rows, crate dir + flags, long watchdog, solver override
  G=growth-occ one ok proofs::kani_growth_occ_anything > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" SUCCESSFUL "shard growth-occ name matching the glob row -> runs"
  grep -q '/kani/growth :: kani .*-Z function-contracts -Z stubbing --harness-timeout 1m --harness proofs::kani_growth_occ_anything --exact' $T/args; chk $? 0 "  in kani/growth with -Z function-contracts -Z stubbing"
  G=growth-occ one ok proofs::kani_growth_t5_capacity_invariant > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" ERROR "shard growth-occ name outside the glob -> ERROR row"
  G=bonds571 TM=315m one ok proofs::kani_571_split_interval_is_exact > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" SUCCESSFUL "shard bonds571 listed name -> runs"
  grep -q '/kani/bonds571 :: kani -Z unstable-options --harness-timeout 315m --harness proofs::kani_571_split_interval_is_exact --exact' $T/args; chk $? 0 "  in kani/bonds571, plain flags, 315m"
  grep -q 'timeout=315m watchdog=325m' $T/shard.log; chk $? 0 "  watchdog 325m"
  G=bonds571 one ok proofs::kani_571_pay_conserves_leg_and_receivable > /dev/null; chk "$(cut -f2 $T/kn/verdicts.tsv)" ERROR "shard bonds571 unlisted harness -> ERROR row"
  G=growth-occ one ok proofs::kani_growth_occ_x '' z3 > /dev/null; grep -q -- '--solver z3 --harness-timeout' $T/args; chk $? 0 "shard solver override passed as --solver z3"
  G=growth-occ one ok proofs::kani_growth_occ_x '' yices > /dev/null; chk "$(cat $T/kn/verdicts.tsv 2>/dev/null | wc -l | tr -d ' ')" 0 "shard bad solver -> refused before running"
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
