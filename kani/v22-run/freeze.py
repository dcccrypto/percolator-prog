#!/usr/bin/env python3
"""Write the frozen-SHA file for the run (rev 2 R4.1): every proof worktree must be clean; records each
repo's HEAD, plus (as `# lock` comment lines, ignored by the run_v22/run_mutants parsers) the sha256 of every
Cargo.lock in each repo (tracked or git-ignored) that the Kani build will use (coordinator 2026-10-10: the
stake Kani rows use stake-kani-Cargo.lock while its SBF artefact uses the release lock). The file lives OUTSIDE the repos (a committed copy could never hold its own commit's sha).
  python3 freeze.py <kani-work root> <out file>"""
import hashlib, os, subprocess, sys
root, out = sys.argv[1], sys.argv[2]
rows = []
for r in ["percolator", "percolator-prog", "percolator-stake", "percolator-match", "percolator-nft"]:
    d = os.path.join(root, r)
    dirty = subprocess.run(["git", "-C", d, "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    if dirty:
        sys.exit(f"{r} is not clean:\n{dirty}")
    sha = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    rows.append(f"{r}\t{sha}")
locks = []
for r in ["percolator", "percolator-prog", "percolator-stake", "percolator-match", "percolator-nft"]:
    d = os.path.join(root, r)
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if x not in ("target", ".git", "node_modules"))
        if "Cargo.lock" in fn:
            p = os.path.join(dp, "Cargo.lock")
            rel = os.path.relpath(p, root)
            tracked = subprocess.run(["git", "-C", d, "ls-files", "--error-unmatch", os.path.relpath(p, d)],
                                     capture_output=True).returncode == 0
            locks.append(f"# lock\t{rel}\t{hashlib.sha256(open(p, 'rb').read()).hexdigest()}\t{'tracked' if tracked else 'git-ignored'}")
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
open(out, "w").write("# repo dir name -> frozen HEAD (freeze.py)\n" + "\n".join(rows) + "\n"
                     + "# Cargo.lock sha256 per crate dir at freeze time (lock<TAB>path<TAB>sha256<TAB>git state)\n"
                     + "\n".join(locks) + "\n")
print(open(out).read(), end="")
