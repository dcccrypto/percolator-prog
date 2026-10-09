#!/usr/bin/env python3
"""PASS_NOCOVER allow-list generator / checker (kani v22-final, design rev 2 R3.3 / rev 2.1 item 8; review M7).

A harness qualifies for PASS_NOCOVER only if its own body (found by brace matching, with comments and
string/char literals blanked) has
  * no `kani::cover!`,
  * no `kani::assume` and no `return` (a SUCCESSFUL verdict without a cover line cannot then hide an
    unsatisfiable path in the harness itself), and
  * at least one assertion that is NOT inside an `if` / `if let` / `else` block (or a guarded match arm):
    if every assert sits under a condition, a condition that never holds passes vacuously (review M7,
    `kani_e2_auth_accept_implies_all_gates`). A body with no assertion at all is a panic-freedom harness;
    it is accepted and marked `# no assert`.
Assertions are `assert!`, `assert_eq!`, `assert_ne!`, `kani::assert(` and calls to `assert_*(` helpers.
Helpers a harness calls are NOT inspected: a helper that assumes would need its own cover; the generator
prints the helper names it saw so the reviewer can check them.

Generate (every `#[kani::proof]` in the files that qualifies):
  python3 -I kani/nocover_allow.py [--id-prefix <queue crate id>] FILE... > list
Check named harnesses (prints `ok <name>` or `EXCLUDE <name>: <reasons>` for each; exit 0):
  python3 -I kani/nocover_allow.py --check NAME[,NAME...] [--id-prefix <crate id>] FILE...
With --id-prefix the output is queue ids `<crate id>:<name>` (gen_queue.py: the workdir relative to the
kani-work root with `/` -> `_`, e.g. `percolator`, `percolator-prog`, `percolator-stake`).
The frozen output is kani/nocover_allow.txt; summarize.py accepts PASS_NOCOVER only for its entries.
"""
import argparse
import re
import sys

ATTR = re.compile(r"^[ \t]*#\[kani::proof\][^\n]*$", re.M)
FN = re.compile(r"\bfn\s+([A-Za-z0-9_]+)\s*[(<]")
ASSERT = re.compile(r"\b(?:assert(?:_eq|_ne)?!|kani::assert\s*\(|assert_[a-z0-9_]+\s*\()")
COND = re.compile(r"\b(?:if|else)\b")


def blank(src):
    """Same-length copy of src with comments, string literals and brace char literals replaced by spaces."""
    out, i, n = list(src), 0, len(src)

    def wipe(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            wipe(i, j)
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            wipe(i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 8]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            h = re.match(r'r(#*)"', src[i:]).group(1)
            j = src.find('"' + h, i + 2 + len(h))
            j = n if j < 0 else j + 1 + len(h)
            wipe(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            wipe(i, j + 1)
            i = j + 1
        elif src.startswith("'{'", i) or src.startswith("'}'", i):
            wipe(i, i + 3)
            i += 3
        else:
            i += 1
    return "".join(out)


def harness_bodies(src):
    """{name: (body_text_blanked, raw_body)} for every #[kani::proof] fn (not proof_for_contract)."""
    b = blank(src)
    res = {}
    for m in ATTR.finditer(b):
        f = FN.search(b, m.end())
        if not f:
            continue
        o = b.find("{", f.end())
        depth, j = 0, o
        while j < len(b):
            if b[j] == "{":
                depth += 1
            elif b[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        res.setdefault(f.group(1), (b[o + 1:j], src[o + 1:j]))
    return res


def unconditional_asserts(body):
    """(n_asserts, n_unconditional) for a blanked body (outermost braces removed)."""
    stack, last, total, uncond = [], 0, 0, 0
    events = sorted([(m.start(), "a") for m in ASSERT.finditer(body)] +
                    [(i, ch) for i, ch in enumerate(body) if ch in "{};"])
    for pos, kind in events:
        if kind == "a":
            total += 1
            if not any(stack):
                uncond += 1
        elif kind == "{":
            stack.append(bool(COND.search(body[last:pos])))
            last = pos + 1
        elif kind == "}":
            if stack:
                stack.pop()
            last = pos + 1
        else:
            last = pos + 1
    return total, uncond


def verdict(body):
    why = []
    if "kani::cover!" in body:
        why.append("has kani::cover!")
    if "kani::assume" in body:
        why.append("has kani::assume")
    if re.search(r"\breturn\b", body):
        why.append("has return")
    total, uncond = unconditional_asserts(body)
    if total and not uncond:
        why.append(f"all {total} asserts under if/else")
    return why, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--id-prefix", default="")
    ap.add_argument("--check", default="")
    a = ap.parse_args()
    bodies = {}
    for f in a.files:
        for k, v in harness_bodies(open(f).read()).items():
            bodies.setdefault(k, v)
    tag = (lambda n: f"{a.id_prefix}:{n}") if a.id_prefix else (lambda n: n)
    if a.check:
        for n in [x for x in a.check.split(",") if x]:
            if n not in bodies:
                print(f"EXCLUDE {tag(n)}: no #[kani::proof] fn of that name in {', '.join(a.files)}")
                continue
            why, total = verdict(bodies[n][0])
            print(f"EXCLUDE {tag(n)}: {'; '.join(why)}" if why else f"ok {tag(n)}" + ("" if total else "  # no assert"))
        return
    out, skipped = [], []
    for n, (body, _raw) in bodies.items():
        why, total = verdict(body)
        if why:
            if "has kani::cover!" not in why:
                skipped.append((n, why))
            continue
        helpers = sorted(set(re.findall(r"\b(assert_[a-z0-9_]+)\s*\(", body)))
        note = []
        if helpers:
            note.append("helpers: " + ",".join(helpers))
        if not total:
            note.append("no assert")
        out.append((n, note))
    for name, note in out:
        print(tag(name) + ("\t# " + "; ".join(note) if note else ""))
    for n, why in skipped:
        print(f"# skipped {tag(n)}: {'; '.join(why)}", file=sys.stderr)
    print(f"# {len(out)} harnesses", file=sys.stderr)


if __name__ == "__main__":
    main()
