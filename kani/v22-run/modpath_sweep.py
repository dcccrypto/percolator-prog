#!/usr/bin/env python3
"""Module-path sweep (review round 3 B4): for every queued harness, derive its fully qualified path
from the SOURCE (crate-root module of the file + inline `mod x {` nesting) and compare it with the
queue `harness` column, which `run_v22.py` passes to `cargo kani --exact --harness`.

  python3 modpath_sweep.py <queue.tsv> <root containing the frozen worktrees (as for gen_queue.py)>

The file of each harness is found by gen_queue's own parser (gen_queue.CRATES + harnesses()). The
file's module prefix: "" for a crate root (`[lib] path`, src/lib.rs, src/main.rs) and for tests/*.rs
(each is its own crate root); otherwise the chain of `mod <stem>;` / `#[path = "<file>"] mod <name>;`
declarations up to the crate root. Exit 0 iff every queue row matches; mismatches are printed.
"""
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
qpath, wroot = sys.argv[1], sys.argv[2]
src = open(os.path.join(here, "gen_queue.py")).read().split('print("# id')[0]
g = {"__file__": os.path.join(here, "gen_queue.py"), "__name__": "gen_queue_lib"}
exec(compile(src, "gen_queue.py", "exec"), g)
CRATES, harnesses, code_lines = g["CRATES"], g["harnesses"], g["code_lines"]

modopen = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_0-9]+)\s*\{")
moddecl = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_0-9]+)\s*;")
pathattr = re.compile(r'^\s*#\[path\s*=\s*"([^"]+)"\]')


def strip(line):
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])'", "''", line)
    return line.split("//")[0]


def nesting(txt):
    """{attr_or_fn_lineno: [inline mod names enclosing that line]}"""
    stack, depth, out = [], 0, {}
    for i, line in code_lines(txt):
        s = strip(line)
        out[i] = [n for n, _ in stack]
        m = modopen.match(s)
        if m:
            stack.append((m.group(1), depth))
        depth += s.count("{") - s.count("}")
        while stack and depth <= stack[-1][1]:
            stack.pop()
    return out


def crate_root(absd):
    toml = os.path.join(absd, "Cargo.toml")
    t = open(toml).read() if os.path.exists(toml) else ""
    sec, libpath = None, None
    for l in t.split("\n"):
        if l.strip().startswith("["):
            sec = l.strip()
        elif sec == "[lib]":
            m = re.match(r'\s*path\s*=\s*"([^"]+)"', l)
            libpath = m.group(1) if m else libpath
    return os.path.normpath(os.path.join(absd, libpath or "src/lib.rs"))


def file_prefix(absd, path, root):
    """Module path of `path` within the crate rooted at `root` (search the declaring file)."""
    if os.path.normpath(path) == root or path.startswith(os.path.join(absd, "tests") + os.sep):
        return ""
    stem = os.path.splitext(os.path.basename(path))[0]
    srcdir = os.path.join(absd, "src")
    for dp, _dn, fns in os.walk(srcdir):
        for fn in fns:
            if not fn.endswith(".rs"):
                continue
            decl = os.path.join(dp, fn)
            lines = open(decl).read().split("\n")
            for k, line in enumerate(lines):
                m = moddecl.match(strip(line))
                if not m:
                    continue
                pa = pathattr.match(lines[k - 1]) if k else None
                target = os.path.normpath(os.path.join(os.path.dirname(decl), pa.group(1))) if pa else None
                if target == os.path.normpath(path) or (not pa and m.group(1) == stem
                                                         and os.path.dirname(decl) == os.path.dirname(path)):
                    nest = nesting("\n".join(lines)).get(k + 1, [])
                    parent = file_prefix(absd, decl, root)
                    return parent + "".join(n + "::" for n in nest) + m.group(1) + "::"
    sys.exit(f"cannot find the module declaration of {path}")


expect = {}
for wd, files, _prefix, flav, args in CRATES:
    absd = os.path.join(wroot, wd)
    root = crate_root(absd)
    for fl in files:
        p = os.path.join(absd, fl)
        if not os.path.exists(p):
            continue
        txt = open(p).read()
        nest = nesting(txt)
        pre = file_prefix(absd, p, root)
        for n, ln in harnesses(txt, p):
            full = pre + "".join(m + "::" for m in nest.get(ln, [])) + n
            expect.setdefault((absd, n), set()).add(full)

bad = rows = 0
for line in open(qpath):
    if line.startswith("#") or not line.strip():
        continue
    f = line.rstrip("\n").split("\t")
    rows += 1
    n = f[5].split("::")[-1]
    want = expect.get((f[2], n))
    if not want or f[5] not in want:
        bad += 1
        print(f"MISMATCH {f[0]}: queue {f[5]!r} vs source {sorted(want or [])}")
print(f"modpath_sweep: {rows} rows, {bad} mismatches")
sys.exit(1 if bad else 0)
