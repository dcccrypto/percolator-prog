#!/usr/bin/env bash
# Shared by scripts/kani-nightly-shard.sh (verdict per harness) and tested by
# scripts/kani-nightly-selftest.sh. Sourced, not executed.
#
# classify <log> <rc> <elapsed-s> <watchdog-s> [oom-kills]: sets v, fc, cov. Pure function of its
# inputs so the rules can be tested without kani (scripts/kani-nightly-selftest.sh).
#   oom-kills = the harness cgroup's memory.events oom_kill count (0 or absent without a cgroup).
# OOM: the memory cap was hit and the run did not exit 0 -- either the cgroup OOM-killed something,
# or (ulimit -v cap) the log shows an allocation failure. oom_kill > 0 with rc 0 is ERROR (a process
# was killed yet kani claims success: not trusted).
OOM_RE='Out of memory|std::bad_alloc|memory allocation of [0-9]+ bytes failed|Cannot allocate memory'
# shellcheck disable=SC2034  # v, fc, cov are the outputs, read by the caller
classify() {
  local log=$1 rc=$2 el=$3 wds=$4 oomk=${5:-0}
  cov=$(grep -Eo '[0-9]+ of [0-9]+ cover properties satisfied' "$log" | tail -1)
  fc=$(grep -Eo '\*\* [0-9]+ of [0-9]+ failed' "$log" | tail -1 | sed 's/\*\* //')
  if [ "$oomk" -gt 0 ] && [ "$rc" -ne 0 ]; then v=OOM; fc="memory cap hit (cgroup oom_kill=$oomk, rc=$rc, ${el}s)"
  elif [ "$oomk" -gt 0 ]; then v=ERROR; fc="cgroup oom_kill=$oomk but rc 0"
  elif [ "$rc" -ne 0 ] && ! grep -q 'CBMC timed out' "$log" && grep -Eq "$OOM_RE" "$log"; then
    v=OOM; fc="allocation failed under the memory cap (rc=$rc, ${el}s)"
  elif grep -q 'CBMC timed out' "$log"; then v=TIMEOUT
  elif { [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; } && [ "$el" -ge "$wds" ]; then v=TIMEOUT; fc="watchdog $((wds/60))m"
  elif [ "$rc" -ge 124 ]; then v=ERROR; fc="killed rc=$rc after ${el}s, before the watchdog, no OOM evidence"
  elif [ "$rc" -eq 0 ] && grep -q 'VERIFICATION:- SUCCESSFUL' "$log" && grep -q 'Complete - 1 successfully verified harnesses, 0 failures' "$log"; then
    v=SUCCESSFUL
    if [ -n "$cov" ]; then set -- $cov; [ "$1" = "$3" ] || v=VACUOUS; fi
  elif echo "$fc" | grep -Eq '^[1-9][0-9]* of'; then v=FAILED
  else v=ERROR; fi
}
