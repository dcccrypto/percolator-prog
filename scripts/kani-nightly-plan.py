#!/usr/bin/env python3
"""Kani nightly plan: check ci/kani-nightly-harnesses.tsv against the tree and build the per-harness matrix.

usage: scripts/kani-nightly-plan.py --groups all --timeout 70m --long-timeout 315m --memcap 13G \
           --maxpar 8 [--solver z3] [--root .] [--out $GITHUB_OUTPUT]

Groups (crate + flags: scripts/kani-nightly-shard.sh):
  lib, tests, contlev, p3, p3-engine, growth  the 85 no-verdict harnesses of the 10-30/31 triage, --timeout
  bonds571, growth-occ                        LONG groups (Khubair R5, 2 Nov): harnesses that time out at
                                              90 min locally, --long-timeout (default 315m)
A TSV row is either an exact harness path or a glob ('*' in the last path segment), e.g.
  growth-occ  proofs::kani_growth_occ_*
expanded HERE, at run time, against the `#[kani::proof]` fns of the group's source dirs, so the list
follows the branch (the #572 occupancy harnesses may be renamed or removed by the per-notional
redesign). A glob that matches nothing is a ::warning:: (the group simply has no rows), not a failure.
An exact row with no matching `fn` is an error (name rot).

Budget per job (timeout-minutes 350): setup (checkout, toolchain, kani from cache, build) + watchdog
(= harness timeout + 10 min) + 1 min must fit. Setup budget 25 min for the wrapper groups (full
wrapper build), 15 min for the long sub-crate groups (tiny crates, no engine build).
Each matrix entry carries its own timeout and whether it needs a z3 binary (harness attribute
#[kani::solver(z3)] or --solver z3).
"""
import argparse
import fnmatch
import json
import math
import os
import re
import sys

DIRS = {
    'lib': ['src'], 'tests': ['tests'], 'contlev': ['kani/contlev/src'], 'p3': ['kani/p3/src'],
    'p3-engine': ['kani/p3-engine/src'], 'growth': ['kani/growth/src'],
    'bonds571': ['kani/bonds571/src'], 'growth-occ': ['kani/growth/src'],
}
ORDER = ['lib', 'tests', 'growth', 'p3', 'contlev', 'p3-engine', 'bonds571', 'growth-occ']
LONG = {'bonds571', 'growth-occ'}
SETUP_MIN = {g: (15 if g in LONG else 25) for g in DIRS}
JOB_LIMIT = 350
SOLVERS = {'', 'cadical', 'kissat', 'minisat', 'z3', 'bitwuzla', 'cvc5'}
# #[kani::proof] then any further attributes, then the fn.
PROOF_RE = re.compile(r'#\[kani::proof\]((?:\s*(?:#\[[^\]]*\]|//[^\n]*))*)\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)')


def die(msg):
    print(f'::error::{msg}')
    sys.exit(1)


def minutes(t):
    return int(t[:-1]) * {'s': 1 / 60, 'm': 1, 'h': 60}[t[-1]]


def proofs_in(root, dirs):
    """fn name -> attribute text of every #[kani::proof] fn under dirs."""
    found = {}
    for d in dirs:
        for dp, _, files in os.walk(os.path.join(root, d)):
            for f in sorted(files):
                if f.endswith('.rs'):
                    with open(os.path.join(dp, f), encoding='utf-8', errors='replace') as fh:
                        for m in PROOF_RE.finditer(fh.read()):
                            found[m.group(2)] = m.group(1)
    return found


def fn_exists(root, dirs, fn):
    pat = re.compile(rf'fn {re.escape(fn)}\b')
    for d in dirs:
        for dp, _, files in os.walk(os.path.join(root, d)):
            for f in files:
                if f.endswith('.rs'):
                    with open(os.path.join(dp, f), encoding='utf-8', errors='replace') as fh:
                        if pat.search(fh.read()):
                            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--list', default='ci/kani-nightly-harnesses.tsv')
    ap.add_argument('--groups', default='all')
    ap.add_argument('--timeout', default='70m')
    ap.add_argument('--long-timeout', default='315m')
    ap.add_argument('--memcap', default='13G')
    ap.add_argument('--maxpar', default='8')
    ap.add_argument('--solver', default='')
    ap.add_argument('--out', default=os.environ.get('GITHUB_OUTPUT', '/dev/stdout'))
    a = ap.parse_args()
    for name, val, rx in (('harness_timeout', a.timeout, r'[0-9]+[smh]'), ('long_timeout', a.long_timeout, r'[0-9]+[smh]'),
                          ('mem_cap', a.memcap, r'[0-9]+[MG]'), ('max_parallel', a.maxpar, r'[1-9][0-9]?'),
                          ('groups', a.groups, r'[a-z0-9,-]+')):
        if not re.fullmatch(rx, val):
            die(f'bad {name} {val!r}')
    if a.solver not in SOLVERS:
        die(f'bad solver {a.solver!r} (one of {sorted(SOLVERS - {""})} or empty = harness attribute)')

    path = os.path.join(a.root, a.list)
    rows = [l.rstrip('\n').split('\t') for l in open(path) if l.strip() and not l.startswith('#')]
    bad = [r for r in rows if len(r) != 2]
    if bad:
        die(f'malformed rows (want <group>\\t<harness>): {bad}')
    sel = None if a.groups == 'all' else set(a.groups.split(','))
    if sel and not sel <= set(DIRS):
        die(f'unknown group(s) {sorted(sel - set(DIRS))}')

    cache = {}

    def proofs(g):
        if g not in cache:
            cache[g] = proofs_in(a.root, DIRS[g])
        return cache[g]

    missing, warnings, expanded = [], [], []   # expanded: (group, harness path, fn)
    for g, h in rows:
        if g not in DIRS:
            missing.append(f'{g}\t{h} (unknown group)')
            continue
        prefix, _, fn = h.rpartition('::')
        if '*' in prefix:
            missing.append(f'{g}\t{h} (glob only allowed in the last path segment)')
            continue
        if any(c in fn for c in '*?['):
            hits = sorted(n for n in proofs(g) if fnmatch.fnmatchcase(n, fn))
            if not hits:
                warnings.append(f'glob row {g}\t{h} matches no #[kani::proof] fn in {DIRS[g]} (group has no rows from it)')
            expanded += [(g, (prefix + '::' if prefix else '') + n, n) for n in hits]
        else:
            if not fn_exists(a.root, DIRS[g], fn):
                missing.append(f'{g}\t{h}')
            expanded.append((g, h, fn))
    if missing:
        die('harness rows with no matching fn in the tree:\n' + '\n'.join(missing))
    names = [h for _, h, _ in expanded]
    dup = sorted({h for h in names if names.count(h) > 1})
    if dup:
        die('harness names listed twice (after glob expansion): ' + ', '.join(dup))

    budget = {}
    for g in DIRS:
        t = a.long_timeout if g in LONG else a.timeout
        wd = math.floor(minutes(t)) + 10
        budget[g] = (t, wd)
    inc, expected = [], []
    for g in ORDER:
        if sel and g not in sel:
            continue
        t, wd = budget[g]
        if SETUP_MIN[g] + wd + 1 > JOB_LIMIT:
            die(f'group {g}: timeout {t} (watchdog {wd}m) + setup {SETUP_MIN[g]}m does not fit the {JOB_LIMIT} min job limit')
        i = 0
        for gg, h, fn in expanded:
            if gg != g:
                continue
            attrs = proofs(g).get(fn, '')
            z3 = a.solver == 'z3' or (not a.solver and 'kani::solver(z3)' in attrs)
            inc.append({'group': g, 'idx': i, 'harness': h, 'timeout': t, 'z3': z3})
            expected.append(h)
            i += 1
    for w in warnings:
        print(f'::warning::{w}')
    if not inc:
        die('no harnesses selected')
    if len(inc) > 256:
        die(f'{len(inc)} harness jobs > GitHub matrix limit 256')
    per = {}
    for e in inc:
        per.setdefault(e['group'], []).append(e)
    print(f'{len(rows)} TSV rows -> {len(expanded)} harnesses; {len(inc)} selected = {len(inc)} jobs, {a.maxpar} at a time, '
          f'mem cap {a.memcap}, solver {a.solver or "per harness attribute"}')
    for g, es in per.items():
        t, wd = budget[g]
        print(f'  {g}: {len(es)} jobs, timeout {t} (watchdog {wd}m), z3 needed by {sum(e["z3"] for e in es)}')
        for e in es:
            print(f'    {e["harness"]}{"  [z3]" if e["z3"] else ""}')
    with open(a.out, 'a') as f:
        f.write('matrix=' + json.dumps({'include': inc}) + '\n')
        f.write('expected=' + json.dumps(expected) + '\n')
        f.write(f'memcap={a.memcap}\nmaxpar={a.maxpar}\nsolver={a.solver}\n')


if __name__ == '__main__':
    main()
