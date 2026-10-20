#!/bin/zsh
# stopq.sh <logdir-substring>: stop MY q.sh queue writing to that logdir and the job it is running
# (kills only the process group that kh.py created).
pat=$1
for q in $(pgrep -f "tools/q.sh .* $pat "); do kill $q; done
for k in $(pgrep -f "kh.py .* $pat "); do
  for c in $(pgrep -P $k); do kill -9 -$c 2>/dev/null; done
  kill $k
done
