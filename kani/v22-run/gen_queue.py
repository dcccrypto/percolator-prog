#!/usr/bin/env python3
"""Generate queue.tsv for run_v22.py from the frozen proof trees (rev 2 R4.1 item 6, R4.3).

  python3 gen_queue.py <root containing percolator, percolator-prog, percolator-stake, percolator-match> > queue.tsv

Harness names are read from source (`#[kani::proof]` / `#[kani::proof_for_contract]` then the next `fn`); the
preflight's `cargo kani list` output must agree name for name (compare before the run). Class defaults: S;
overrides from classes.tsv (name, class, deps). Every name must be unique per crate; duplicates abort.
"""
import os, re, sys

root = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
over = {}
for l in open(os.path.join(here, "classes.tsv")):
    if l.strip() and not l.startswith("#"):
        f = l.rstrip("\n").split("\t")
        over[f[0]] = (f[1], f[2] if len(f) > 2 else "-")

ENG = "--tests --features fuzz -Z stubbing"
WRP_DEV = "--tests --features devnet -Z function-contracts -Z stubbing"
WRP_MAIN = "--tests -Z function-contracts -Z stubbing"
PATHC_DEV = "--features devnet -Z function-contracts -Z stubbing"
PATHC = "-Z function-contracts -Z stubbing"

# (workdir, files, module prefix fn(file)->prefix, flavour, args)
CRATES = [
    ("percolator", ["tests/proofs_v16.rs", "tests/proofs_v17_fork.rs", "tests/proofs_v16_arithmetic.rs",
                    "tests/proofs_v16_asymmetric_a_accrual.rs", "tests/proofs_v21_funding_scale.rs",
                    "tests/proofs_v22_funding_exact.rs", "tests/proofs_v22_final.rs", "tests/proofs_v22_band.rs"],
     "", "none", ENG),
    ("percolator-prog", ["tests/v16_kani.rs", "tests/kani_design_p1.rs", "tests/growth_kani.rs", "tests/v16_fee_split.rs",
                         "tests/v22_kani_ad.rs", "tests/v22_kani_cfl.rs"], "", "devnet", WRP_DEV),
    ("percolator-prog", ["src/v16_program.rs"], "p1_kani_proofs::", "devnet", WRP_DEV),
    ("percolator-prog/kani/growth", ["src/proofs.rs"], "proofs::", "devnet", PATHC_DEV),
    ("percolator-prog/kani/p3", ["src/proofs.rs"], "proofs::", "devnet", PATHC_DEV),
    ("percolator-prog/kani/p3-engine", ["src/proofs.rs"], "proofs::", "devnet", PATHC_DEV),
    ("percolator-stake", ["tests/kani.rs", "tests/kani_v5.rs"], "", "none", "--tests"),
    # stake NEW-1 (b83ddf9): cfg(kani) child module of processor, hooked at the END of src/processor.rs
    ("percolator-stake", ["src/kani_v22_new1.rs"], "processor::kani_v22_new1::", "none", "--lib"),
    ("percolator-stake/kani/v5-units", ["src/proofs.rs"], "proofs::", "devnet", PATHC_DEV),
    ("percolator-match", ["src/v2.rs"], "v2::proofs::", "none", PATHC),
    ("percolator-match", ["src/vamm.rs"], "vamm::proofs::", "none", PATHC),
]
# flavour-dependent wrapper harnesses also run in the mainnet flavour (rev 2 R2.2/R2.3)
MAINNET_TOO = {l.strip() for l in open(os.path.join(here, "mainnet_secondary.txt")) if l.strip() and not l.startswith("#")}

# Only real attributes count: the attribute must open a source line (leading whitespace only), and lines
# inside `//` comments or `/* */` blocks are skipped (M6: a doc-comment `#[kani::proof]` queued a non-harness).
attr = re.compile(r"^\s*#\[kani::(?:proof|proof_for_contract\([^)]*\))\]")
fnline = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\s+([A-Za-z_0-9]+)\s*[(<]")


def code_lines(txt):
    """Yield (lineno, line) for source lines outside comments (whole-line `//` comments and `/* */` blocks)."""
    in_block = False
    for i, line in enumerate(txt.split("\n"), 1):
        st = line.strip()
        if in_block:
            if "*/" in st:
                in_block = False
            continue
        if st.startswith("//"):
            continue
        if st.startswith("/*"):
            in_block = "*/" not in st[2:]
            continue
        yield i, line


def harnesses(txt, path):
    """[(name, attr_lineno)] for every real #[kani::proof] / #[kani::proof_for_contract(..)] item."""
    out, pending, depth = [], None, 0
    for i, line in code_lines(txt):
        st = line.strip()
        if depth > 0:  # continuation of a multi-line attribute, e.g. #[kani::stub(\n a,\n b\n)]
            depth += st.count("[") - st.count("]")
            continue
        if attr.match(line):
            pending = pending or i  # stacked kani attributes still name one fn
            continue
        if pending is None:
            continue
        m = fnline.match(line)
        if m:
            out.append((m.group(1), pending))
            pending = None
        elif st.startswith("#["):
            depth = st.count("[") - st.count("]")  # other attributes (unwind, stub, solver, cfg)
        elif not st:
            continue
        else:
            sys.exit(f"{path}:{pending}: kani attribute not followed by a fn (line {i}: {st[:80]})")
    if pending is not None:
        sys.exit(f"{path}:{pending}: kani attribute at end of file")
    return out


print("# id\tclass\tworkdir\tflavour\tdeps\tharness\targs")
for wd, files, prefix, flav, args in CRATES:
    absd = os.path.join(root, wd)
    seen = set()
    for f in files:
        p = os.path.join(absd, f)
        if not os.path.exists(p):
            sys.stderr.write(f"missing {p}\n")
            continue
        txt = open(p).read()
        for n, _ln in harnesses(txt, p):
            if n in seen:
                # the same name in two test targets of one crate: --exact runs BOTH under one
                # invocation (same fully qualified name); the second entry is recorded, not re-queued
                sys.stderr.write(f"note: {n} also defined in {f} ({wd}); one queue entry runs both\n")
                continue
            seen.add(n)
            cls, deps = over.get(n, ("S", "-"))
            crate = wd.replace("/", "_")
            hid = f"{crate}:{n}"
            print("\t".join([hid, cls, absd, flav, deps, prefix + n, args]))
            if n in MAINNET_TOO and flav == "devnet":
                margs = WRP_MAIN if args == WRP_DEV else PATHC
                print("\t".join([hid + "@mainnet", cls, absd, "mainnet", deps, prefix + n, margs]))
