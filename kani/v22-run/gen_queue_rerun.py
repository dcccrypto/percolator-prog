#!/usr/bin/env python3
"""Queue for the pre-registered single re-run of first-freeze NO-VERDICT / NO-VERDICT-OOM rows.

  python3 gen_queue_rerun.py <first-freeze results.tsv> [<first-freeze queue.tsv>] > queue-rerun.tsv

Rows: every queue.tsv row whose first-freeze status starts with NO-VERDICT and whose id is NOT in r2_ids.txt
(r2 rows are re-run on the second freeze instead). Rows are copied verbatim from the first-freeze queue.tsv
(same id, class, workdir, flavour, deps, harness, args), so the run is at the FIRST freeze's trees and locks.
The `# subset-queue` header makes compare_list.py treat it as a subset.
"""
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
res = sys.argv[1]
qpath = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "queue.tsv")
r2 = {l.strip() for l in open(os.path.join(here, "r2_ids.txt")) if l.strip() and not l.startswith("#")}
st = {}
for l in open(res):
    f = l.rstrip("\n").split("\t")
    if f[0] != "id":
        st[f[0]] = f[4]
out = []
for l in open(qpath):
    if not l.strip() or l.startswith("#"):
        continue
    f = l.rstrip("\n").split("\t")
    if st.get(f[0], "").startswith("NO-VERDICT") and f[0].split("@")[0] not in r2:
        out.append(l.rstrip("\n"))
missing = [i for i in st if st[i].startswith("NO-VERDICT") and i.split("@")[0] not in r2 and not any(o.split("\t")[0] == i for o in out)]
if missing:
    sys.exit(f"results rows not in the queue: {missing[:5]}")
print(f"# subset-queue rerun: {len(out)} first-freeze NO-VERDICT / NO-VERDICT-OOM rows not in r2 (from {os.path.basename(res)})")
print("# id\tclass\tworkdir\tflavour\tdeps\tharness\targs")
print("\n".join(out))
