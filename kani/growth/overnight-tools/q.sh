#!/bin/zsh
# usage: q.sh <crate> <limit> <logdir> "<kani flags>" h1 h2 ...   (sequential; one job at a time)
crate=$1; lim=$2; ld=$3; flags=$4; shift 4
for h in "$@"; do
  while (( $(sysctl -n vm.loadavg | awk '{print int($2)}') > 55 )); do sleep 20; done
  python3 -I $HOME/wt-v22-kani2/tools/kh.py $crate $h $lim $ld ${=flags}
done
echo QDONE
