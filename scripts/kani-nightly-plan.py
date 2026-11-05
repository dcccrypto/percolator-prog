#!/usr/bin/env python3
"""Kani nightly plan: check ci/kani-nightly-harnesses.tsv against the tree and build the per-harness matrix.

usage: scripts/kani-nightly-plan.py --groups all --timeout 180m --long-timeout 315m --memcap 13G \
           --maxpar 12 [--runner ubuntu-latest] [--solver z3] [--root .] [--out $GITHUB_OUTPUT]

Groups (crate + flags: scripts/kani-nightly-shard.sh):
  lib, tests, contlev, p3, p3-engine, growth  the 85 no-verdict harnesses of the 10-30/31 triage, --timeout
  bonds571, growth-occ                        LONG groups (Khubair R5, 2 Nov): harnesses that time out at
                                              90 min locally, --long-timeout (default 315m)
A TSV row is either an exact harness path or a glob ('*' in the last path segment), e.g.
  growth-occ  proofs::kani_growth_occ_*
expanded HERE, at run time, against the harnesses of the group's source dirs on the branch being run.
RED (plan fails, nothing runs): a glob that matches nothing, an exact row that is not a harness
(name rot), and any `kani::proof` / `kani::proof_for_contract` this script cannot tie to a `fn`: a
harness must never drop out of the selection silently, because a green run would not show it.
Harness detection (harnesses_in): a small lexer blanks comments and strings, then whole attribute
blocks are read with bracket balancing, so attribute order, `proof_for_contract`, `cfg_attr(kani, ..)`,
`unsafe fn` and nested brackets in an attribute are all handled.

Budget per job (timeout-minutes 350): setup (checkout, toolchain, kani from cache, build) + watchdog
(= harness timeout + 10 min) + 1 min must fit. Setup budget 25 min for the wrapper groups (full
wrapper build), 15 min for the long sub-crate groups (tiny crates, no engine build).
Each matrix entry carries its own timeout and whether it needs a z3 binary (harness attribute
#[kani::solver(z3)], wherever it sits among the attributes, or --solver z3).
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
PROOF_TOK = re.compile(r'\bkani::proof(?:_for_contract)?\b')
ATTR_START = re.compile(r'#\s*\[')
ITEM_FN = re.compile(r'\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:(?:const|async|unsafe|default)\s+|extern\s*(?:""\s*)?)*fn\s+(\w+)')
Z3_ATTR = re.compile(r'\bkani::solver\s*\(\s*z3\s*\)')


def die(msg):
    print(f'::error::{msg}')
    sys.exit(1)


def minutes(t):
    return int(t[:-1]) * {'s': 1 / 60, 'm': 1, 'h': 60}[t[-1]]


def blank(src):
    """src with comments and string/char literals blanked; newlines kept, so offsets give line numbers."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == '//':
            while i < n and src[i] != '\n':
                i += 1
        elif two == '/*':
            depth, i = 1, i + 2
            while i < n and depth:
                if src[i:i + 2] == '/*':
                    depth, i = depth + 1, i + 2
                elif src[i:i + 2] == '*/':
                    depth, i = depth - 1, i + 2
                else:
                    out.append('\n' if src[i] == '\n' else ' ')
                    i += 1
        elif c == '"' or (c in 'rb' and (not i or not (src[i - 1].isalnum() or src[i - 1] == '_'))
                          and (m := re.match(r'b?r(#*)"|b"', src[i:i + 40]))):
            if c == '"' or src[i:i + 2] == 'b"':       # ordinary string, escapes apply
                i += 1 if c == '"' else 2
                while i < n and src[i] != '"':
                    if src[i] == '\n':
                        out.append('\n')
                    i += 2 if src[i] == '\\' else 1
                i += 1
            else:                                      # raw string: ends at "###
                end = '"' + m.group(1)
                i += m.end()
                while i < n and not src.startswith(end, i):
                    if src[i] == '\n':
                        out.append('\n')
                    i += 1
                i += len(end)
            out.append('""')
        elif c == "'" and (m := re.match(r"'(?:\\.[^']*|[^\\'])'", src[i:i + 12])):   # char literal, not a lifetime
            i += m.end()
            out.append("' '")
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def attr_end(code, start):
    """index just past the `]` closing the attribute whose `[` is the first one at or after start."""
    i, depth = code.index('[', start), 0
    while i < len(code):
        depth += (code[i] == '[') - (code[i] == ']')
        i += 1
        if depth == 0:
            return i
    return -1


def harnesses_in(src):
    """(fn name -> text of its attribute block, [offsets of proof attributes tied to no fn])."""
    code = blank(src)
    found, bad, pos, tied = {}, [], 0, 0
    while (m := ATTR_START.search(code, pos)):
        i, block = m.start(), []
        while (a := ATTR_START.match(code, i)):
            e = attr_end(code, a.start())
            if e < 0:
                return found, bad + [a.start()]
            block.append(code[a.start():e])
            i = e
            while i < len(code) and code[i].isspace():
                i += 1
        text = ' '.join(block)
        n = len(PROOF_TOK.findall(text))
        if n:
            fn = ITEM_FN.match(code, i)
            if fn:
                found[fn.group(1)] = found.get(fn.group(1), '') + text
                tied += n
            else:
                bad.append(m.start())
                tied += n
        pos = i
    if len(PROOF_TOK.findall(code)) != tied:     # a proof attribute outside any attribute block we read
        bad += [t.start() for t in PROOF_TOK.finditer(code)][:1]
    return found, bad


def proofs_in(root, dirs):
    """fn name -> attribute text of every harness under dirs. Fails closed on what it cannot classify."""
    found, unknown = {}, []
    for d in dirs:
        for dp, _, files in os.walk(os.path.join(root, d)):
            for f in sorted(files):
                if not f.endswith('.rs'):
                    continue
                path = os.path.join(dp, f)
                with open(path, encoding='utf-8', errors='replace') as fh:
                    src = fh.read()
                got, bad = harnesses_in(src)
                for k, v in got.items():
                    found[k] = found.get(k, '') + v
                code = blank(src)
                unknown += [f'{os.path.relpath(path, root)}:{code.count(chr(10), 0, b) + 1}' for b in bad]
    if unknown:
        die('kani::proof attribute(s) not tied to a fn; fix the harness or scripts/kani-nightly-plan.py:\n' + '\n'.join(unknown))
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.')
    ap.add_argument('--list', default='ci/kani-nightly-harnesses.tsv')
    ap.add_argument('--groups', default='all')
    ap.add_argument('--timeout', default='180m')
    ap.add_argument('--long-timeout', default='315m')
    ap.add_argument('--memcap', default='13G')
    ap.add_argument('--maxpar', default='12')
    # runs-on label of the harness jobs (default the 4 vCPU / 16 GB GitHub runner). A bigger runner
    # only exists once one is provisioned (larger runners need an org on Team/Enterprise, or a
    # self-hosted machine); raise --memcap with it (keep it ~3 GB below the machine's RAM).
    ap.add_argument('--runner', default='ubuntu-latest')
    ap.add_argument('--solver', default='')
    ap.add_argument('--out', default=os.environ.get('GITHUB_OUTPUT', '/dev/stdout'))
    a = ap.parse_args()
    for name, val, rx in (('harness_timeout', a.timeout, r'[0-9]+[smh]'), ('long_timeout', a.long_timeout, r'[0-9]+[smh]'),
                          ('mem_cap', a.memcap, r'[0-9]+[MG]'), ('max_parallel', a.maxpar, r'[1-9][0-9]?'),
                          ('groups', a.groups, r'[a-z0-9,-]+'), ('runner', a.runner, r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}')):
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

    missing, expanded = [], []   # expanded: (group, harness path, fn)
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
                missing.append(f'{g}\t{h} (glob matches no harness in {DIRS[g]})')
            expanded += [(g, (prefix + '::' if prefix else '') + n, n) for n in hits]
        else:
            if fn not in proofs(g):
                missing.append(f'{g}\t{h}')
            expanded.append((g, h, fn))
    if missing:
        die('harness rows that match no harness in the tree:\n' + '\n'.join(missing))
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
            z3 = a.solver == 'z3' or (not a.solver and bool(Z3_ATTR.search(attrs)))
            inc.append({'group': g, 'idx': i, 'harness': h, 'timeout': t, 'z3': z3})
            expected.append(h)
            i += 1
    if not inc:
        die('no harnesses selected')
    if len(inc) > 256:
        die(f'{len(inc)} harness jobs > GitHub matrix limit 256')
    per = {}
    for e in inc:
        per.setdefault(e['group'], []).append(e)
    print(f'{len(rows)} TSV rows -> {len(expanded)} harnesses; {len(inc)} selected = {len(inc)} jobs, {a.maxpar} at a time on {a.runner}, '
          f'mem cap {a.memcap}, solver {a.solver or "per harness attribute"}')
    for g, es in per.items():
        t, wd = budget[g]
        print(f'  {g}: {len(es)} jobs, timeout {t} (watchdog {wd}m), z3 needed by {sum(e["z3"] for e in es)}')
        for e in es:
            print(f'    {e["harness"]}{"  [z3]" if e["z3"] else ""}')
    with open(a.out, 'a') as f:
        f.write('matrix=' + json.dumps({'include': inc}) + '\n')
        f.write('expected=' + json.dumps(expected) + '\n')
        f.write(f'memcap={a.memcap}\nmaxpar={a.maxpar}\nsolver={a.solver}\nrunner={a.runner}\n')


if __name__ == '__main__':
    main()
