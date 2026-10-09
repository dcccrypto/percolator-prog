#!/usr/bin/env python3
"""Post-process a run (rev 2 R4.4; review round 2 N5).

  python3 summarize.py <out dir> <queue.tsv> <nocover_allow.txt> > final.tsv

* Every queue id appears exactly once: ids with no results row are emitted as NOT-RUN (coverage can
  never shrink silently after an ALERT exit 3 or a stop).
* CONDITIONAL(<deps>) for a PASS / PASS_NOCOVER whose contract / lemma dependency is not PASS
  (deps come from the queue, so a dependency that never ran also makes its dependants CONDITIONAL).
* PASS_NOCOVER only for ids on the frozen allow-list (queue ids `crate:name`, an `@mainnet` suffix is
  ignored; a bare `name` line still matches the harness basename), else DESIGN-FAIL-NOCOVER.
* A header block (lines starting `#`) gives the status counts and whether <out>/ALERT exists.
"""
import collections, os, sys

outdir, queue_path, allow_path = sys.argv[1], sys.argv[2], sys.argv[3]
qrows = [l.rstrip("\n").split("\t") for l in open(queue_path) if l.strip() and not l.startswith("#")]
queue = collections.OrderedDict((r[0], r) for r in qrows)  # id class workdir flavour deps harness args

res_path = os.path.join(outdir, "results.tsv")
rows = [l.rstrip("\n").split("\t") for l in open(res_path) if l.strip()] if os.path.exists(res_path) else []
hdr, rows = (rows[0], rows[1:]) if rows else (
    ["id", "class", "flavour", "harness", "status", "covers", "failed", "wall_s", "sha", "dirty", "deps", "cmd", "cwd", "n_verif"], [])
res = {r[0]: r for r in rows}

allow = {l.split("#")[0].split()[0] for l in open(allow_path) if l.split("#")[0].strip()}
allow_ids = {a for a in allow if ":" in a}
allow_bare = {a for a in allow if ":" not in a}


def allowed(hid, harness):
    return hid.split("@")[0] in allow_ids or harness.split("::")[-1] in allow_bare


st = {hid: (res[hid][4] if hid in res else "NOT-RUN") for hid in queue}
out, counts = [], collections.Counter()
for hid, q in queue.items():
    deps = [d for d in q[4].split(",") if d and d != "-"]
    if hid in res:
        r = list(res[hid])
        r += [""] * (len(hdr) - len(r))
    else:
        r = [hid, q[1], q[3], q[5], "NOT-RUN", "-", "-", "-", "-", "-", q[4], "cargo kani " + " ".join(q[6:]), q[2], "-"]
    s = r[4]
    if s == "PASS_NOCOVER" and not allowed(hid, r[3]):
        s = "DESIGN-FAIL-NOCOVER"
    if s in ("PASS", "PASS_NOCOVER") and any(st.get(d) != "PASS" for d in deps):
        s = "CONDITIONAL(" + ",".join(f"{d}={st.get(d, 'UNKNOWN-DEP')}" for d in deps if st.get(d) != "PASS") + ")"
    counts[s.split("(")[0]] += 1
    out.append(r + [s])
extra = [h for h in res if h not in queue]
alert = os.path.join(outdir, "ALERT")
print(f"# queue ids: {len(queue)}; results rows: {len(rows)}; not in queue: {len(extra)}")
print("# ALERT: " + ("PRESENT (" + open(alert).read().strip().splitlines()[-1] + ")" if os.path.exists(alert) else "absent"))
for k, v in sorted(counts.items()):
    print(f"# {k}: {v}")
for h in extra:
    print(f"# WARNING: results row {h} is not in the queue")
print("\t".join(hdr + ["final"]))
for r in out:
    print("\t".join(r))
