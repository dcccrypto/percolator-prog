#!/usr/bin/env python3
"""Diff the queue against `cargo kani list --format json` for one workdir + flavour (review M6).

  python3 compare_list.py <queue.tsv> <kani-list.json> <workdir> <flavour> [<args>]

kani-list.json (Kani 0.67, file-version 0.1) has
  "standard-harnesses": {"<file>": ["name", ...], ...}
  "contract-harnesses": {"<file>": ["name", ...], ...}   (a flat list is accepted too)
plus "contracts" and "totals". Names from both harness maps are compared with the `harness` column of
every queue row whose workdir (realpath) equals <workdir> and whose flavour equals <flavour>.

Names are compared by their last `::` segment (the queue carries a module prefix such as `proofs::` for
src-module harnesses; `cargo kani list` may print it with or without the module path). Review round 3 B4: whenever the list
name carries a module path (`a::b::f`), the queue's harness string must EQUAL it (the runner passes
`--exact --harness <queue name>`, so a bare or wrong-path queue name would match nothing and ERROR); such
a row is reported PATH-MISMATCH and is a difference. A list name that
appears in several files (same fn in two test targets) is one name; one queue row runs both copies.

With <args> (the cargo-kani args of this invocation; preflight.sh passes them), only queue rows whose
args column equals <args> are selected (review round 3: a stake `--lib` preflight checks the 6 lib rows
alone); a list name queued in the same workdir and flavour under OTHER args is reported as
`other-args (ok)`, not as a difference (a `--tests` build also lists the lib's harnesses).

Exit 0 only when the two sets are equal. Exception: the `mainnet` flavour is a deliberate SUBSET re-run
(mainnet_secondary.txt), so for it every queued name must be listed, and extra list names are reported
but are not a difference. Any other difference, an empty selection, or a bad JSON exits 1.
"""
import json
import os
import sys

SUBSET_FLAVOURS = {"mainnet"}


def names_from_list(path):
    d = json.load(open(path))
    out = []
    for key in ("standard-harnesses", "contract-harnesses"):
        v = d.get(key, {})
        if isinstance(v, dict):
            for _f, ns in v.items():
                out.extend(ns)
        elif isinstance(v, list):
            out.extend(x if isinstance(x, str) else x.get("name", "") for x in v)
        else:
            sys.exit(f"{path}: unexpected {key!r} type {type(v).__name__}")
    tot = d.get("totals", {})
    want = tot.get("standard-harnesses", 0) + tot.get("contract-harnesses", 0)
    if tot and want != len(out):
        sys.exit(f"{path}: totals say {want} harnesses, maps hold {len(out)}")
    return out


def names_from_queue(path, workdir, flavour, args=None):
    """(selected names, names of the same workdir+flavour queued under other args)"""
    wd = os.path.realpath(workdir)
    out, other = [], []
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if os.path.realpath(f[2]) == wd and f[3] == flavour:
            if args is None or " ".join(f[6].split()) == " ".join(args.split()):
                out.append(f[5])
            else:
                other.append(f[5])
    return out, other


def base(n):
    return n.split("::")[-1]


def main():
    if len(sys.argv) not in (5, 6):
        sys.exit(__doc__)
    qpath, lpath, wd, flav = sys.argv[1:5]
    qargs = sys.argv[5] if len(sys.argv) == 6 else None
    q, q_other = names_from_queue(qpath, wd, flav, qargs)
    lst = names_from_list(lpath)
    if not q:
        print(f"compare_list: no queue rows for workdir={wd} flavour={flav}")
        return 1
    qb, lb = {}, {}
    for n in q:
        qb.setdefault(base(n), []).append(n)
    for n in lst:
        lb.setdefault(base(n), []).append(n)
    amb = {b: v for b, v in qb.items() if len(set(v)) > 1}
    only_q = sorted(set(qb) - set(lb))
    only_l = sorted(set(lb) - set(qb))
    other_b = {base(n) for n in q_other}
    lfull = set(lst)
    pathmis = []
    for b, v in sorted(qb.items()):
        pathed = [n for n in lb.get(b, []) if "::" in n]
        for n in set(v):
            if pathed and n not in lfull:
                pathmis.append((n, sorted(set(pathed))))
    print(f"compare_list: workdir={wd} flavour={flav} args={qargs!r} queue={len(q)} rows ({len(qb)} names) "
          f"list={len(lst)} entries ({len(lb)} names)")
    for b, v in sorted(amb.items()):
        print(f"  AMBIGUOUS queue basename {b}: {sorted(set(v))}")
    for b in only_q:
        print(f"  QUEUE-ONLY {qb[b][0]}  (queued but not a harness per cargo kani list)")
    for n, want in pathmis:
        print(f"  PATH-MISMATCH queue {n!r} != cargo kani list {want}  (--exact would match nothing)")
    subset = flav in SUBSET_FLAVOURS
    only_l_other = [b for b in only_l if b in other_b]
    only_l = [b for b in only_l if b not in other_b]
    for b in only_l_other:
        print(f"  other-args (ok) {lb[b][0]}")
    for b in only_l:
        print(f"  {'list-only (subset flavour, ok)' if subset else 'LIST-ONLY'} {lb[b][0]}"
              + ("" if subset else "  (harness missing from the queue)"))
    bad = bool(amb or only_q or pathmis or (only_l and not subset))
    print("compare_list: " + ("DIFFERENT" if bad else "MATCH"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
