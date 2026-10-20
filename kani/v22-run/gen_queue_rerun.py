#!/usr/bin/env python3
"""Queues for the pre-registered single re-run of NO-VERDICT rows, split by class (amendment 2026-10-12 04:50).

  python3 gen_queue_rerun.py <results.tsv> <queue.tsv> <out prefix> [--include-r2]

Writes <prefix>-timeout.tsv (rows whose status in <results.tsv> is exactly NO-VERDICT: 8,000 s / 16 GB, 2 lanes)
and <prefix>-oom.tsv (status NO-VERDICT-OOM: 8,000 s / 32 GB, 1 lane). Rows are copied verbatim from <queue.tsv>
(same id, class, workdir, flavour, deps, harness, args).
First freeze: <results> = run/results.tsv, <queue> = queue.tsv; ids in r2_ids.txt are EXCLUDED (they run on the
second freeze). Second freeze: <results> = run-r2/results.tsv, <queue> = queue-r2.tsv with --include-r2 (every row
of that queue is an r2 row; its one re-run is on the second-freeze code).
Each output starts with `# subset-queue` (compare_list.py). An id in the results but not in the queue aborts.
"""
import os, sys
here = os.path.dirname(os.path.abspath(__file__))
args = [a for a in sys.argv[1:] if not a.startswith("--")]
include_r2 = "--include-r2" in sys.argv
if len(args) != 3:
    sys.exit(__doc__)
res, qpath, prefix = args
r2 = set() if include_r2 else {l.strip() for l in open(os.path.join(here, "r2_ids.txt")) if l.strip() and not l.startswith("#")}
st = {}
for l in open(res):
    f = l.rstrip("\n").split("\t")
    if f[0] != "id":
        st[f[0]] = f[4]
rows = {}
for l in open(qpath):
    if l.strip() and not l.startswith("#"):
        rows[l.split("\t")[0]] = l.rstrip("\n")
out = {"timeout": [], "oom": []}
for i, s in st.items():
    if not s.startswith("NO-VERDICT") or i.split("@")[0] in r2:
        continue
    if i not in rows:
        sys.exit(f"{i}: in the results but not in {qpath}")
    out["oom" if s == "NO-VERDICT-OOM" else "timeout"].append(rows[i])
for k, v in out.items():
    with open(f"{prefix}-{k}.tsv", "w") as f:
        f.write(f"# subset-queue rerun {k} class: {len(v)} rows from {os.path.basename(os.path.dirname(os.path.abspath(res)))}/results.tsv"
                + ("" if include_r2 else " (r2 ids excluded)") + "\n# id\tclass\tworkdir\tflavour\tdeps\tharness\targs\n" + "\n".join(v) + ("\n" if v else ""))
    print(f"{prefix}-{k}.tsv: {len(v)} rows")
