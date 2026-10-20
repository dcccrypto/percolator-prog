#!/usr/bin/env python3
"""Overnight mutant runner (growth crate in ~/wt-v22-kani2 ONLY). Re-uses the mutant table in
kani/growth/mutants/mutants.py, writes mutants/<file>_mutant.rs, runs the named NEW target harness
via kh.py (z3), and records CAUGHT if the verdict is FAIL (or a cover that the clean run satisfied
becomes unsatisfied: reported as COVER-LOST, also caught). For `nc` targets the mutant copy is
stripped of its cfg(kani) contract attributes exactly like gen_nc.sh.

usage: mut.py <name>:<module>::<harness>[:nc] ...
"""
import os, re, subprocess, sys

G = os.path.expanduser("~/wt-v22-kani2/percolator-prog/kani/growth")
TOOLS = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.expanduser("~/wt-v22-kani2/logs/mutants")
sys.path.insert(0, os.path.join(G, "mutants"))
from mutants import MUTANTS  # noqa: E402

table = {m[0]: m for m in MUTANTS}
STRIP = re.compile(r"^#\[cfg_attr\(kani, kani::(ensures|requires)\(.*\n", re.M)
os.makedirs(LOG, exist_ok=True)
for spec in sys.argv[1:]:
    parts = spec.split(":")
    name, harness = parts[0], parts[1] + "::" + parts[3]
    nc = len(parts) > 4 and parts[4] == "nc"
    _, f, old, new, _h, crate = table[name]
    f = os.path.normpath(os.path.join(G, f)) if not os.path.isabs(f) else f
    # the table's paths point at the old worktree: re-root them onto this worktree
    base = os.path.basename(f)
    f = os.path.expanduser("~/wt-v22-kani2/percolator-prog/src/" + base)
    src = open(f).read()
    assert src.count(old) == 1, (name, f)
    mut = src.replace(old, new)
    if nc:
        mut = STRIP.sub("", mut)
    feat = {"growth": "growth_mutant", "vlp": "vlp_mutant"}[crate]
    out = os.path.join(G, "mutants", ("growth_v19" if crate == "growth" else "vault_lp_v18") + "_mutant.rs")
    open(out, "w").write(mut)
    feats = "devnet," + feat + (",nc" if nc else "")
    flags = ["--features", feats, "-Z", "stubbing", "--solver", "z3"]
    if not nc:
        flags[3:3] = ["-Z", "function-contracts"]
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.expanduser("~/wt-v22-kani2/target-growth-mut" + ("-nc" if nc else "")))
    r = subprocess.run([sys.executable, "-I", os.path.join(TOOLS, "kh.py"), G, harness, "600",
                        os.path.join(LOG, name)] + flags, env=env, capture_output=True, text=True)
    row = r.stdout.strip().split("\t")
    st = row[2] if len(row) > 2 else "ERR"
    verdict = "CAUGHT" if st == "FAIL" else ("COVER-LOST?" if st == "PASS_NOCOVER" else "NOT-CAUGHT(" + st + ")")
    line = "\t".join([name, harness, ("nc" if nc else "contracts"), st, row[3] if len(row) > 3 else "-",
                      row[5] if len(row) > 5 else "-", verdict])
    with open(os.path.join(LOG, "SUMMARY.tsv"), "a") as s:
        s.write(line + "\n")
    print(line, flush=True)
    os.remove(out)
