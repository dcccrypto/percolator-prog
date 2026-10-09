#!/usr/bin/env python3
"""Write the frozen-SHA file for the run (rev 2 R4.1): every proof worktree must be clean; records each
repo's HEAD. The file lives OUTSIDE the repos (a committed copy could never hold its own commit's sha).
  python3 freeze.py <kani-work root> <out file>"""
import os, subprocess, sys
root, out = sys.argv[1], sys.argv[2]
rows = []
for r in ["percolator", "percolator-prog", "percolator-stake", "percolator-match", "percolator-nft"]:
    d = os.path.join(root, r)
    dirty = subprocess.run(["git", "-C", d, "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    if dirty:
        sys.exit(f"{r} is not clean:\n{dirty}")
    sha = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    rows.append(f"{r}\t{sha}")
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
open(out, "w").write("# repo dir name -> frozen HEAD (freeze.py)\n" + "\n".join(rows) + "\n")
print(open(out).read(), end="")
