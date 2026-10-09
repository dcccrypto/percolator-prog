#!/usr/bin/env python3
"""PASS_NOCOVER allow-list generator (kani v22-final, design rev 2 R3.3 / rev 2.1 item 8).

Lists the harnesses of tests/v16_kani.rs that declare NO kani::cover! and whose own body contains
no `kani::assume` and no `return` (so a SUCCESSFUL verdict without a cover line cannot hide an
unsatisfiable path in the harness itself). Helpers a harness calls are NOT inspected: a helper
that assumes would need its own cover; the generator prints the helper names it saw so the
reviewer can check them. Output is frozen in kani/nocover_allow.txt and printed into the preflight
log; the runner accepts PASS_NOCOVER only for names in that file.

usage: python3 -I kani/nocover_allow.py tests/v16_kani.rs > kani/nocover_allow.txt
"""
import re
import sys

src = open(sys.argv[1]).read()
starts = [m.start() for m in re.finditer(r"#\[kani::proof\]", src)]
out = []
for i, s in enumerate(starts):
    e = starts[i + 1] if i + 1 < len(starts) else len(src)
    chunk = src[s:e]
    m = re.search(r"fn\s+([A-Za-z0-9_]+)\s*\(", chunk)
    if not m:
        continue
    body = chunk[m.end():]
    # cut at the end of the function: the first line that is exactly "}" at column 0
    end = re.search(r"\n}\n", body)
    body = body[: end.start()] if end else body
    if "kani::cover!" in body or "kani::assume" in body or re.search(r"\breturn\b", body):
        continue
    helpers = sorted(set(re.findall(r"\b(assert_[a-z0-9_]+)\s*\(", body)))
    out.append((m.group(1), helpers))
for name, helpers in out:
    print(name + ("\t# helpers: " + ",".join(helpers) if helpers else ""))
print(f"# {len(out)} harnesses", file=sys.stderr)
