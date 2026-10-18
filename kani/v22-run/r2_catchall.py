#!/usr/bin/env python3
"""Second-freeze catch-all (r2 review B1, pre-registered): list every first-freeze FAIL row whose ONLY failed
checks are CBMC memcmp unwinding assertions (`Check N: memcmp.unwind.*` with `Status: FAILURE`), and say
whether r2_ids.txt already has it. Run before the second freeze; every row printed as MISSING must be
added to r2_ids.txt (then regenerate queue-r2.tsv). Exit 1 if any is missing.

  python3 r2_catchall.py <first-freeze run out dir>
"""
import os, re, sys

out = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
have = {l.strip() for l in open(os.path.join(here, "r2_ids.txt")) if l.strip() and not l.startswith("#")}
rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(out, "results.tsv")) if l.strip()]
hdr, rows = rows[0], rows[1:]
si = hdr.index("status")
chk = re.compile(r"^Check \d+: (\S+)\s*$")
missing = 0
for r in rows:
    if r[si] != "FAIL":
        continue
    log = os.path.join(out, "logs", r[0] + ".log")
    failed, last = [], None
    for line in open(log, errors="replace"):
        m = chk.match(line)
        if m:
            last = m.group(1)
        elif "Status: FAILURE" in line and last:
            failed.append(last)
    if failed and all(f.startswith("memcmp.unwind.") for f in failed):
        tag = "in r2" if r[0] in have else "MISSING"
        missing += tag == "MISSING"
        print(f"{tag}\t{r[0]}\t{','.join(sorted(set(failed)))}")
print(f"r2_catchall: {missing} memcmp-unwind-only FAIL rows missing from r2_ids.txt")
sys.exit(1 if missing else 0)
