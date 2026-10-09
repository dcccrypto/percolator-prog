#!/usr/bin/env python3
"""Diff the queue against `cargo kani list --format json` for one workdir + flavour (review M6).

  python3 compare_list.py <queue.tsv> <kani-list.json> <workdir> <flavour>

kani-list.json (Kani 0.67, file-version 0.1) has
  "standard-harnesses": {"<file>": ["name", ...], ...}
  "contract-harnesses": {"<file>": ["name", ...], ...}   (a flat list is accepted too)
plus "contracts" and "totals". Names from both harness maps are compared with the `harness` column of
every queue row whose workdir (realpath) equals <workdir> and whose flavour equals <flavour>.

Names are compared by their last `::` segment (the queue carries a module prefix such as `proofs::` for
src-module harnesses; `cargo kani list` may print it with or without the module path). A list name that
appears in several files (same fn in two test targets) is one name; one queue row runs both copies.

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


def names_from_queue(path, workdir, flavour):
    wd = os.path.realpath(workdir)
    out = []
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if os.path.realpath(f[2]) == wd and f[3] == flavour:
            out.append(f[5])
    return out


def base(n):
    return n.split("::")[-1]


def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    qpath, lpath, wd, flav = sys.argv[1:]
    q = names_from_queue(qpath, wd, flav)
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
    print(f"compare_list: workdir={wd} flavour={flav} queue={len(q)} rows ({len(qb)} names) "
          f"list={len(lst)} entries ({len(lb)} names)")
    for b, v in sorted(amb.items()):
        print(f"  AMBIGUOUS queue basename {b}: {sorted(set(v))}")
    for b in only_q:
        print(f"  QUEUE-ONLY {qb[b][0]}  (queued but not a harness per cargo kani list)")
    subset = flav in SUBSET_FLAVOURS
    for b in only_l:
        print(f"  {'list-only (subset flavour, ok)' if subset else 'LIST-ONLY'} {lb[b][0]}"
              + ("" if subset else "  (harness missing from the queue)"))
    bad = bool(amb or only_q or (only_l and not subset))
    print("compare_list: " + ("DIFFERENT" if bad else "MATCH"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
