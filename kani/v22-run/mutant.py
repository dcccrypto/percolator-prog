#!/usr/bin/env python3
"""Apply / restore / check mutants from any kani/mutants/v22/*.tsv manifest (header-driven columns:
id, file, line, [nth], original, replacement, target..., expected...). Work ONLY in a dedicated mutant
worktree checked out at the proof commit (never the proof worktree; never `git stash`).
Escapes in original/replacement: \\n, \\t, \\\\.
Rule: a single-line original must occur on the recorded line (its nth occurrence there if `nth` is
given, else exactly once on that line); a multi-line original must occur exactly once in the file.
  mutant.py check   <manifest> <repo root>
  mutant.py apply   <manifest> <id> <repo root>
  mutant.py restore <manifest> <id> <repo root>"""
import subprocess, sys
un = lambda s: s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
def rows(m):
    lines = [l.rstrip("\n") for l in open(m) if l.strip() and not l.startswith("#")]
    hdr = lines[0].split("\t")
    col = {h.split("(")[0].strip(): i for i, h in enumerate(hdr)}
    oi = col.get("original"); ri = col.get("replacement")
    ti = col.get("target", col.get("target_harness"))
    for l in lines[1:]:
        f = l.split("\t")
        yield dict(id=f[0], file=f[1], line=int(f[2].split("-")[0]), nth=int(f[col["nth"]]) if "nth" in col and f[col["nth"]] else None,
                   orig=un(f[oi]), repl=un(f[ri]), target=f[ti] if ti is not None else "")
def locate(src, r):
    if "\n" in r["orig"]:
        return src.count(r["orig"]) == 1
    L = src.split("\n")
    if r["line"] - 1 >= len(L):
        return False
    c = L[r["line"] - 1].count(r["orig"])
    return c >= (r["nth"] or 1) if r["nth"] else c == 1
def apply(src, r):
    if "\n" in r["orig"]:
        return src.replace(r["orig"], r["repl"], 1)
    L = src.split("\n"); s = L[r["line"] - 1]; n = r["nth"] or 1; i = -1
    for _ in range(n):
        i = s.index(r["orig"], i + 1)
    L[r["line"] - 1] = s[:i] + r["repl"] + s[i + len(r["orig"]):]
    return "\n".join(L)
cmd = sys.argv[1]
if cmd == "check":
    bad = 0; n = 0
    for r in rows(sys.argv[2]):
        n += 1
        if not locate(open(f"{sys.argv[3]}/{r['file']}").read(), r):
            bad += 1; print("BAD", r["id"], r["file"], r["line"])
    print(f"rows {n} bad {bad}"); sys.exit(1 if bad else 0)
m, i, root = sys.argv[2], sys.argv[3], sys.argv[4]
r = next((x for x in rows(m) if x["id"] == i), None) or sys.exit("no mutant " + i)
p = f"{root}/{r['file']}"
if cmd == "apply":
    src = open(p).read(); assert locate(src, r), "original not at the recorded place"
    open(p, "w").write(apply(src, r)); print(f"applied {i} -> target {r['target']}")
elif cmd == "restore":
    subprocess.run(["git", "-C", root, "checkout", "--", r["file"]], check=True); print("restored", r["file"])
