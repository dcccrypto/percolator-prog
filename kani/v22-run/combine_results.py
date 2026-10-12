#!/usr/bin/env python3
"""Merge the three result sets of the v2.2 final run into one results dir for summarize.py.

  python3 combine_results.py <run (first freeze)> <run-r2 (second freeze)> <run-rerun> <out dir>

Per id, the FINAL row is: the r2 row if the id is in run-r2 (first-freeze row superseded, pre-registered);
else the re-run row if the id is in run-rerun (single NO-VERDICT re-run, result final); else the first-freeze row.
Writes <out>/results.tsv (final rows, runner format), <out>/queue-final.tsv (queue.tsv + the r2-only new rows,
for summarize.py) and <out>/provenance.tsv (id, first status, source of the final row, final status).
A first-freeze FAIL that was superseded stays visible in provenance.tsv (it is reported as FAIL + link, never hidden).
Aborts if run-rerun holds a row that was not NO-VERDICT* in the first freeze, or an id that is also in run-r2.
"""
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
first, r2, rerun, out = sys.argv[1:5]
def load(d):
    p = os.path.join(d, "results.tsv")
    rows = [l.rstrip("\n").split("\t") for l in open(p) if l.strip()] if os.path.exists(p) else []
    return (rows[0] if rows else None), {r[0]: r for r in rows[1:]}
hdr, a = load(first); _, b = load(r2); _, c = load(rerun)
for i, r in c.items():
    if i in b:
        sys.exit(f"{i}: in both run-r2 and run-rerun")
    if i not in a or not a[i][4].startswith("NO-VERDICT"):
        sys.exit(f"{i}: re-run row but first-freeze status is {a.get(i, ['?'] * 5)[4]}")
os.makedirs(out, exist_ok=True)
ids = list(a) + [i for i in b if i not in a]
with open(os.path.join(out, "results.tsv"), "w") as f, open(os.path.join(out, "provenance.tsv"), "w") as pf:
    f.write("\t".join(hdr) + "\n"); pf.write("id\tfirst_status\tfinal_source\tfinal_status\n")
    for i in ids:
        src, row = ("r2", b[i]) if i in b else ("rerun", c[i]) if i in c else ("first", a[i])
        f.write("\t".join(row) + "\n")
        pf.write(f"{i}\t{a[i][4] if i in a else 'NOT-IN-FIRST'}\t{src}\t{row[4]}\n")
q1 = [l.rstrip("\n") for l in open(os.path.join(here, "queue.tsv"))]
have = {l.split("\t")[0] for l in q1 if l and not l.startswith("#")}
extra = [l.rstrip("\n") for l in open(os.path.join(here, "queue-r2.tsv")) if l.strip() and not l.startswith("#") and l.split("\t")[0] not in have]
open(os.path.join(out, "queue-final.tsv"), "w").write("\n".join(q1 + extra) + "\n")
print(f"combined: first={len(a)} r2={len(b)} rerun={len(c)} -> {len(ids)} ids; queue-final {len(have) + len(extra)} rows")
