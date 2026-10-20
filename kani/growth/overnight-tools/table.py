#!/usr/bin/env python3
"""Collect every kh.py SUMMARY.tsv row under ~/wt-v22-kani2/logs into one markdown table.
The LAST row per (harness, solver, features) wins; earlier attempts are listed in 'tries'."""
import glob, os, collections

rows = collections.OrderedDict()
tries = collections.Counter()
for p in sorted(glob.glob(os.path.expanduser("~/wt-v22-kani2/logs/*/SUMMARY.tsv"))):
    if "/mutants/" in p:
        continue
    for line in open(p):
        a = line.rstrip("\n").split("\t")
        if len(a) < 9:
            continue
        t, h, st, cov, nf, wall, peak, crate = a[:8]
        extra = a[8] if len(a) > 8 else ""
        solver = extra.split("--solver ")[1].split()[0] if "--solver " in extra else "attr/default"
        feats = extra.split("--features ")[1].split()[0] if "--features " in extra else "-"
        crate_s = crate.replace(os.path.expanduser("~/wt-v22-kani2/"), "")
        k = (h, solver, feats, crate_s)
        tries[k] += 1
        rows[k] = (t, st, cov, wall, peak, os.path.basename(os.path.dirname(p)))
print("| harness | crate | features | solver | verdict | covers | wall s | attempts |")
print("|---|---|---|---|---|---|---|---|")
for (h, solver, feats, crate), (t, st, cov, wall, peak, d) in sorted(rows.items()):
    print(f"| `{h.split('::')[-1]}` | {crate} | {feats} | {solver} | {st} | {cov} | {wall} | {tries[(h, solver, feats, crate)]} |")
m = os.path.expanduser("~/wt-v22-kani2/logs/mutants/SUMMARY.tsv")
if os.path.exists(m):
    print("\n| mutant | target harness | build | verdict | covers | wall s | result |")
    print("|---|---|---|---|---|---|---|")
    for line in open(m):
        a = line.rstrip("\n").split("\t")
        if len(a) >= 7:
            print(f"| {a[0]} | `{a[1].split('::')[-1]}` | {a[2]} | {a[3]} | {a[4]} | {a[5]} | {a[6]} |")
