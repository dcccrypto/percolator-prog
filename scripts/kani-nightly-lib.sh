#!/usr/bin/env bash
# Shared by scripts/kani-nightly-shard.sh (verdict per harness) and tested by
# scripts/kani-nightly-selftest.sh. Sourced, not executed.
#
# classify <log> <rc> <elapsed-s> <watchdog-s>: sets v, fc, cov. Pure function of its inputs so the
# rules can be tested without kani (scripts/kani-nightly-selftest.sh).
classify() {
  local log=$1 rc=$2 el=$3 wds=$4
  cov=$(grep -Eo '[0-9]+ of [0-9]+ cover properties satisfied' "$log" | tail -1)
  fc=$(grep -Eo '\*\* [0-9]+ of [0-9]+ failed' "$log" | tail -1 | sed 's/\*\* //')
  if grep -q 'CBMC timed out' "$log"; then v=TIMEOUT
  elif { [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; } && [ "$el" -ge "$wds" ]; then v=TIMEOUT; fc="watchdog $((wds/60))m"
  elif [ "$rc" -ge 124 ]; then v=ERROR; fc="killed rc=$rc after ${el}s, before the watchdog (OOM / runner signal?)"
  elif [ "$rc" -eq 0 ] && grep -q 'VERIFICATION:- SUCCESSFUL' "$log" && grep -q 'Complete - 1 successfully verified harnesses, 0 failures' "$log"; then
    v=SUCCESSFUL
    if [ -n "$cov" ]; then set -- $cov; [ "$1" = "$3" ] || v=VACUOUS; fi
  elif echo "$fc" | grep -Eq '^[1-9][0-9]* of'; then v=FAILED
  else v=ERROR; fi
}
