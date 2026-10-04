#!/usr/bin/env python3
"""SBF stack-frame gate (security round 3, F-1).

The SBF VM gives every function a fixed 4,096-byte stack frame, and `cargo build-sbf` prints NO
diagnostic when a function's frame reaches it: on 2026-10-04 one extra 32-byte local in
`handle_trade_nocpi_zero_copy` (then at 4,064 of 4,096 B) silently corrupted the fee accrual
(Custom 15 on every legacy trade). This gate parses the `.stack_sizes` section that
`RUSTFLAGS="-Z emit-stack-sizes"` makes LLVM emit (codegen is otherwise unchanged) and fails:

  * if ANY function's frame exceeds LIMIT (4096 - 256 = 3840 B), unless it is listed in the
    baseline as a pre-existing over-budget function, in which case it may not grow past its
    recorded size and may never reach 4096;
  * if any PINNED function (the hot-path executors, marked `pin` in the baseline) grows past
    its recorded size.

Usage: sbf_stack_sizes.py <unstripped .so> <baseline file> [--print N]
The .so must be the UNSTRIPPED artifact (target/sbpf-solana-solana/release/<crate>.so); the
deploy copy has the section stripped. llvm-readelf comes from $LLVM_READELF or the newest
~/.cache/solana/*/platform-tools.
Baseline lines: `<bytes> <function path> [pin]`; `#` comments.
"""
import glob, os, re, struct, subprocess, sys

HARD = 4096
LIMIT = HARD - 256


def readelf():
    env = os.environ.get("LLVM_READELF")
    if env:
        return env
    c = sorted(glob.glob(os.path.expanduser("~/.cache/solana/*/platform-tools/llvm/bin/llvm-readelf")))
    if not c:
        sys.exit("llvm-readelf not found: set LLVM_READELF")
    return c[-1]


def frames(so):
    re_ = readelf()
    hdr = subprocess.run([re_, "-SW", so], capture_output=True, text=True, check=True).stdout
    m = re.search(r"\.stack_sizes\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)", hdr)
    if not m:
        sys.exit(f"{so}: no .stack_sizes section (build with RUSTFLAGS='-Z emit-stack-sizes', unstripped .so)")
    off, sz = int(m.group(1), 16), int(m.group(2), 16)
    data = open(so, "rb").read()[off:off + sz]
    syms = {}
    out = subprocess.run([re_, "-sW", "--demangle", so], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[3] == "FUNC":
            syms[int(p[1], 16)] = " ".join(p[7:])
    i, res = 0, {}
    while i + 8 <= len(data):
        addr = struct.unpack_from("<Q", data, i)[0]
        i += 8
        v = sh = 0
        while True:
            b = data[i]
            i += 1
            v |= (b & 0x7F) << sh
            sh += 7
            if not b & 0x80:
                break
        a2 = addr >> 32 if addr > 0xFFFFFFFF else addr
        name = re.sub(r"::h[0-9a-f]{16}$", "", syms.get(a2, syms.get(addr, hex(addr))))
        res[name] = max(v, res.get(name, 0))
    return res


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    so, base_path = sys.argv[1], sys.argv[2]
    show = int(sys.argv[sys.argv.index("--print") + 1]) if "--print" in sys.argv else 10
    f = frames(so)
    base, pins = {}, set()
    for line in open(base_path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        p = line.split()
        base[p[1]] = int(p[0])
        if len(p) > 2 and p[2] == "pin":
            pins.add(p[1])
    top = sorted(f.items(), key=lambda kv: -kv[1])
    print(f"functions {len(f)}  max {top[0][1]}  limit {LIMIT}  hard {HARD}")
    for n, v in top[:show]:
        print(f"  {v:5d}  {n}")
    bad = []
    for n, v in f.items():
        if v >= HARD:
            bad.append(f"{n}: {v} B reaches the {HARD}-byte SBF frame")
        elif v > LIMIT and n not in base:
            bad.append(f"{n}: {v} B > {LIMIT} (new function over budget)")
        elif n in base and v > base[n] and (n in pins or v > LIMIT):
            bad.append(f"{n}: {v} B grew past its recorded {base[n]} B")
    for n in sorted(pins):
        if n not in f:
            bad.append(f"{n}: pinned function not found (renamed? update the baseline)")
        else:
            print(f"  pin {f[n]:5d} / {base[n]}  {n}")
    if bad:
        print("SBF FRAME GATE: FAIL")
        for b in bad:
            print("  " + b)
        sys.exit(1)
    print("SBF FRAME GATE: OK")


if __name__ == "__main__":
    main()
