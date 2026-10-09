#!/usr/bin/env python3
"""Post-process results.tsv (rev 2 R4.4): CONDITIONAL for dependants whose contract/lemma did not PASS,
PASS_NOCOVER only for harnesses on the frozen allow-list (else DESIGN-FAIL-NOCOVER).
Allow-list lines are queue ids `crate:name` (matched against the results id, with any `@mainnet` flavour
suffix removed); a bare `name` line (no `:`) still matches the harness basename in any crate. Text after
whitespace or `#` on a line is ignored.
  python3 summarize.py <results.tsv> <nocover_allow.txt> > final.tsv"""
import sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
hdr, rows = rows[0], rows[1:]
allow = {l.split("#")[0].split()[0] for l in open(sys.argv[2]) if l.split("#")[0].strip()}
allow_ids = {a for a in allow if ":" in a}
allow_bare = {a for a in allow if ":" not in a}


def allowed(r):
    return r[0].split("@")[0] in allow_ids or r[3].split("::")[-1] in allow_bare


st = {r[0]: r[4] for r in rows}
print("\t".join(hdr + ["final"]))
for r in rows:
    s = r[4]
    deps = [d for d in r[10].split(",") if d and d != "-"]
    if s == "PASS_NOCOVER" and not allowed(r):
        s = "DESIGN-FAIL-NOCOVER"
    if s in ("PASS", "PASS_NOCOVER") and any(st.get(d) != "PASS" for d in deps):
        s = "CONDITIONAL(" + ",".join(d for d in deps if st.get(d) != "PASS") + ")"
    print("\t".join(r + [s]))
