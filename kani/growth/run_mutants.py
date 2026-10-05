#!/usr/bin/env python3
"""Mutant matrix, run ONCE after the real run (sequential: one mutant file / one matcher src at
a time). Each mutant must turn its target harness red (VERIFICATION FAILED, or a cover
UNSATISFIED that the real run satisfied). Matcher sources are copied aside and restored, and
restoration is checked byte-for-byte. Usage: ./run_mutants.py <tag>"""
import os, subprocess, sys, time, shutil, re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "mutants"))
from mutants import MUTANTS
tag = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
P = "/Users/khubair/wt-growth-v19/percolator-prog"
M = "/Users/khubair/wt-growth-v19/percolator-match"
LIMIT = int(os.environ.get("LIMIT", "1500"))
L = os.path.join(HERE, "logs", tag)
os.makedirs(L, exist_ok=True)
summ = open(os.path.join(L, "SUMMARY"), "w")
os.chdir(HERE)
ONLY = [x for x in os.environ.get("ONLY", "").split(",") if x]
for name, f, old, new, h, crate in MUTANTS:
    if ONLY and name not in ONLY:
        continue
    t0 = time.time()
    log = os.path.join(L, f"{name}.log")
    restore = None
    if crate == "growth":
        src = open(f).read()
        assert src.count(old) == 1, name
        open("mutants/growth_v19_mutant.rs", "w").write(src.replace(old, new))
        cmd = ["cargo", "kani", "-Z", "stubbing", "--features", "growth_mutant", "--harness", f"proofs::{h}", "--exact"]
        cwd = HERE
    elif crate == "lpnet":
        cmd = ["cargo", "kani", "-Z", "stubbing", "--features", "lpnet_mutant", "--harness", f"proofs::{h}", "--exact"]
        cwd = HERE
    else:
        orig = open(f).read()
        assert orig.count(old) == 1, name
        shutil.copy(f, f + ".kani-orig")
        open(f, "w").write(orig.replace(old, new))
        restore = f
        mod = "v2" if f.endswith("v2.rs") else "vamm"
        cmd = ["cargo", "kani", "--harness", f"{mod}::proofs::{h}", "--exact"]
        cwd = M
    try:
        with open(log, "w") as out:
            r = subprocess.run(cmd, cwd=cwd, stdout=out, stderr=subprocess.STDOUT, timeout=LIMIT)
        status = "ran"
    except subprocess.TimeoutExpired:
        status = f"TIMEOUT ({LIMIT}s)"
    finally:
        if restore:
            shutil.copy(restore + ".kani-orig", restore)
            os.remove(restore + ".kani-orig")
            assert open(restore).read() == orig, f"{name}: restore mismatch"
    txt = open(log).read()
    v = re.findall(r"^VERIFICATION:.*$", txt, re.M)
    c = re.findall(r"^.*cover properties satisfied.*$", txt, re.M)
    caught = bool(v) and "FAILED" in v[-1]
    summ.write(f"{name} | {h} | {(v[-1] if v else status)} | {(c[-1].strip() if c else 'no cover line')} | {'CAUGHT' if caught else 'CHECK'} | {int(time.time()-t0)}s\n")
    summ.flush()
if os.path.exists("mutants/growth_v19_mutant.rs"):
    os.remove("mutants/growth_v19_mutant.rs")
summ.write("DONE\n")
