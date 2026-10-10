#!/usr/bin/env python3
"""Second-freeze (r2) queue: EXACTLY the rows named in r2_ids.txt (the 36 diag-table engine rows, which
must already be in queue.tsv) plus the NEW harnesses in r2_new.txt (which must NOT be in queue.tsv).

  python3 gen_queue_r2.py <source root> [<workdir root>] > queue-r2.tsv

<source root> holds the r2 proof trees (harness names are read from source by gen_queue.py, so the new
harness is found); workdir paths are rewritten to <workdir root> (default: the first-freeze kani-work root,
where the second freeze is checked out), so every r2 row is byte-identical to its queue.tsv row
(id, class, workdir, flavour, deps, harness, args). Any id missing, duplicated, or differing aborts.
The output starts with `# subset-queue`, which tells compare_list.py the queue is a deliberate subset
(every queued name must be listed exactly; list names not queued are not a difference).
"""
import os, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
src = os.path.abspath(sys.argv[1])
dst = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.abspath(os.path.join(here, "..", "..", ".."))
ids = lambda f: [l.strip() for l in open(os.path.join(here, f)) if l.strip() and not l.startswith("#")]
want_old, want_new = ids("r2_ids.txt"), ids("r2_new.txt")
gen = subprocess.run([sys.executable, "-I", os.path.join(here, "gen_queue.py"), src], capture_output=True, text=True, check=True).stdout
rows = {}
for l in gen.split("\n"):
    if not l or l.startswith("#"):
        continue
    f = l.split("\t")
    if f[2] == src or f[2].startswith(src + "/"):
        f[2] = dst + f[2][len(src):]
    if f[0] in rows:
        sys.exit(f"duplicate id {f[0]} in the generated queue")
    rows[f[0]] = "\t".join(f)
first = {}
for l in open(os.path.join(here, "queue.tsv")):
    if l.strip() and not l.startswith("#"):
        first[l.split("\t")[0]] = l.rstrip("\n")
out = []
for i in want_old:
    if i not in first:
        sys.exit(f"{i}: not in the first-freeze queue.tsv")
    if i not in rows:
        sys.exit(f"{i}: not found in the r2 source")
    if rows[i] != first[i]:
        sys.exit(f"{i}: r2 row differs from queue.tsv\n  r2:    {rows[i]}\n  first: {first[i]}")
    out.append(rows[i])
for i in want_new:
    if i in first:
        sys.exit(f"{i}: listed as NEW but already in queue.tsv")
    if i not in rows:
        sys.exit(f"{i}: new harness not found in the r2 source")
    out.append(rows[i])
if len(set(out)) != len(want_old) + len(want_new):
    sys.exit("row count mismatch")
print(f"# subset-queue r2: {len(want_old)} first-freeze rows (r2_ids.txt) + {len(want_new)} new (r2_new.txt) = {len(out)}")
print("# id\tclass\tworkdir\tflavour\tdeps\tharness\targs")
print("\n".join(out))
