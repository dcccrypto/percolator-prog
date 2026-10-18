#!/usr/bin/env python3
"""Merge the result sets of the v2.2 final run into one results dir for summarize.py.

  python3 combine_results.py <out dir> --first <run> [--rerun <dir>]... [--r2 <run-r2> [--r2-rerun <dir>]...]

Final row per id: an r2 re-run row > the r2 row > a first-freeze re-run row > the first-freeze row.
A re-run row is accepted ONLY where the row it replaces is NO-VERDICT* (single pre-registered re-run), and an id
may appear in at most one re-run dir of its freeze; a first-freeze re-run row for an id that is in run-r2 aborts.
Writes <out>/results.tsv (final rows, runner format), <out>/queue-final.tsv (queue.tsv + the r2-only new rows)
and <out>/provenance.tsv (id, first-freeze status, r2 status, source of the final row, final status): a superseded
first-freeze FAIL stays visible there (reported as FAIL + link, never hidden).
"""
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
opt = {"--first": [], "--rerun": [], "--r2": [], "--r2-rerun": []}
a = sys.argv[2:]
for k, v in zip(a[0::2], a[1::2]):
    opt[k].append(v)
assert len(opt["--first"]) == 1 and len(opt["--r2"]) <= 1, __doc__
def load(d):
    p = os.path.join(d, "results.tsv")
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()] if os.path.exists(p) else []
    return (rows[0] if rows else None), {r[0]: r for r in rows[1:]}
def merge_reruns(dirs, base, what):
    m = {}
    for d in dirs:
        for i, r in load(d)[1].items():
            if i in m:
                sys.exit(f"{i}: in two {what} re-run dirs")
            if i not in base or not base[i][4].startswith("NO-VERDICT"):
                sys.exit(f"{i}: {what} re-run row but the row it replaces is {base.get(i, ['?'] * 5)[4]}")
            m[i] = r
    return m
hdr, first = load(opt["--first"][0])
r2 = load(opt["--r2"][0])[1] if opt["--r2"] else {}
rr1 = merge_reruns(opt["--rerun"], first, "first-freeze")
rr2 = merge_reruns(opt["--r2-rerun"], r2, "r2")
for i in rr1:
    if i in r2:
        sys.exit(f"{i}: first-freeze re-run row for an r2 id")
os.makedirs(out, exist_ok=True)
ids = list(first) + [i for i in r2 if i not in first]
n = {"first": 0, "rerun": 0, "r2": 0, "r2-rerun": 0}
with open(os.path.join(out, "results.tsv"), "w") as f, open(os.path.join(out, "provenance.tsv"), "w") as pf:
    f.write("\t".join(hdr) + "\n")
    pf.write("id\tfirst_status\tr2_status\tfinal_source\tfinal_status\n")
    for i in ids:
        src, row = ("r2-rerun", rr2[i]) if i in rr2 else ("r2", r2[i]) if i in r2 else ("rerun", rr1[i]) if i in rr1 else ("first", first[i])
        n[src] += 1
        f.write("\t".join(row) + "\n")
        pf.write(f"{i}\t{first[i][4] if i in first else 'NOT-IN-FIRST'}\t{r2[i][4] if i in r2 else '-'}\t{src}\t{row[4]}\n")
q1 = [l.rstrip("\n") for l in open(os.path.join(here, "queue.tsv"))]
have = {l.split("\t")[0] for l in q1 if l and not l.startswith("#")}
extra = [l.rstrip("\n") for l in open(os.path.join(here, "queue-r2.tsv")) if l.strip() and not l.startswith("#") and l.split("\t")[0] not in have]
open(os.path.join(out, "queue-final.tsv"), "w").write("\n".join(q1 + extra) + "\n")
print(f"combined {len(ids)} ids: final from {n}; queue-final {len(have) + len(extra)} rows")
