#!/usr/bin/env python3
"""Mechanical resolution of the four known conflict hunks when folding percolator-prog #539 (R-10/R-12) and
#540 (mainnet-ids) into release/v22-wrapper-rem (see docs/FOLD_V22_539_540.md).

Every conflicted hunk is an ADJACENT APPEND (RC side + our side): keep BOTH, RC side first. Then:
  * ALL_NAMED_TAGS: replace the first two padding sentinels (201, 202) with TAG_PROPOSE_G9_FEED_ALLOWLIST and
    TAG_COMMIT_G9_FEED_ALLOWLIST (length stays 41);
  * `lag_policy` (RC-only exhaustive match over Instruction, compile error otherwise): add MarkFree arms for the two
    new instructions;
  * V22_ERROR_CODES: append `PercolatorError::G9AllowlistTimelock as u32,` and bump the length 26 -> 27.
Idempotent. Usage (conflicted files first; pass ONLY the ones git reports as conflicted, `src/p4_rescue_ins.rs` is
conflicted too when #541 is merged before #539, both append to its tests module):

    git -c merge.conflictstyle=zdiff3 merge --no-commit --no-ff <branch>   # zdiff3 (NOT `git checkout --conflict=diff3`, which
                                                                          # re-merges with wider hunks and a non-empty base)
    scripts/fold-resolve-v22-539-540.py src/v16_program.rs src/bin/sdk_parity_fixtures.rs [src/p4_rescue_ins.rs]
    scripts/fold-resolve-v22-539-540.py --rc-release-docs      # after #540: wires the release gate on the RC

SAFETY: every conflict must be diff3 style with an EMPTY base section (a pure double-append). A conflict with
a non-empty base or no base marker is NOT an append and the script aborts without writing anything.
`--rc-release-docs` edits `docs/v22-mainnet-release-checklist.md` (build command requires `--features mainnet-ids`; adds the
pin and mainnet-flavour gate steps) and `scripts/check-mainnet-sbf.sh` (calls `scripts/check-mainnet-pin.sh "$SO"` right
before its final PASS line). Both edits are idempotent text edits.
"""
import re, sys

def keep_both(text, path="?"):
    # diff3 style REQUIRED: <<<<<<< ours / ||||||| base / ======= / >>>>>>> theirs; the base must be empty.
    pat = re.compile(r"<<<<<<< [^\n]*\n(.*?)(\|\|\|\|\|\|\| [^\n]*\n(.*?))?=======\n(.*?)>>>>>>> [^\n]*\n", re.S)
    def fix(m):
        if m.group(2) is None:
            sys.exit("ABORT %s: conflict without a base section; run `git checkout --conflict=diff3 -- %s` first" % (path, path))
        if m.group(3).strip():
            sys.exit("ABORT %s: a conflict has a NON-EMPTY base (not a pure append); resolve by hand:\n%s" % (path, m.group(0)[:600]))
        return m.group(1) + m.group(4)
    return pat.sub(fix, text)

def patch_arrays(text):
    if "TAG_PROPOSE_G9_FEED_ALLOWLIST, TAG_COMMIT_G9_FEED_ALLOWLIST" not in text and "ALL_NAMED_TAGS: [u8; 41]" in text:
        text = text.replace("TAG_EVICT_AND_TRADE_CPI, 201, 202, 203, 204, 205, 206, 207,",
                            "TAG_EVICT_AND_TRADE_CPI, TAG_PROPOSE_G9_FEED_ALLOWLIST, TAG_COMMIT_G9_FEED_ALLOWLIST,\n        203, 204, 205, 206, 207,", 1)
    if "G9AllowlistTimelock as u32," not in text and "V22_ERROR_CODES: [u32; 26]" in text:
        text = text.replace("V22_ERROR_CODES: [u32; 26]", "V22_ERROR_CODES: [u32; 27]", 1)
        text = text.replace("        PercolatorError::BondSlippage as u32,\n    ];",
                            "        PercolatorError::BondSlippage as u32,\n        PercolatorError::G9AllowlistTimelock as u32,\n    ];", 1)
    # RC-only exhaustive match (`lag_policy`, no conflict marker but a compile error without it):
    marker = 'Instruction::SetG9FeedAllowlist { .. } => entry("SetG9FeedAllowlist", LagPolicy::MarkFree, "upgrade-authority config"),'
    if marker in text and 'Instruction::ProposeG9FeedAllowlist { .. } => entry(' not in text:
        text = text.replace(marker, marker + '''
            Instruction::ProposeG9FeedAllowlist { .. } => entry("ProposeG9FeedAllowlist", LagPolicy::MarkFree, "upgrade-authority config (timelocked proposal)"),
            Instruction::CommitG9FeedAllowlist => entry("CommitG9FeedAllowlist", LagPolicy::MarkFree, "upgrade-authority config (timelock commit)"),''', 1)
    return text

def rc_release_docs():
    ck = "docs/v22-mainnet-release-checklist.md"
    c = open(ck).read()
    if "check-mainnet-pin.sh" not in c:
        c = c.replace("cargo build-sbf --sbf-out-dir out/mainnet            # NO --features devnet\nscripts/check-mainnet-sbf.sh out/mainnet/percolator_prog.so",
                      "cargo build-sbf --features mainnet-ids --sbf-out-dir out/mainnet   # NO --features devnet; mainnet-ids is REQUIRED\nscripts/check-mainnet-sbf.sh out/mainnet/percolator_prog.so   # calls check-mainnet-pin.sh (below)\nscripts/check-mainnet-pin.sh out/mainnet/percolator_prog.so   # must print OK: pinned mainnet build\nscripts/mainnet-flavour-tests.sh out/mainnet/percolator_prog.so   # must print MAINNET FLAVOUR TESTS: OK (all ignored mainnet tests ran)\nscripts/pin-flavour-tests.sh   # builds the placeholder-pin .so itself; tag 94 only under the pinned matcher (never a release artifact)", 1)
        c = c.replace("## 2. Reproducible-build hash comparison", """The pinned set (stake, wrapper, vault-LP matcher, fee authority) lives in `src/mainnet_ids.rs` as
`RELEASE-STEP` placeholders: `--features mainnet-ids` does NOT COMPILE until all four are set. The build
carries a marker: `check-mainnet-pin.sh` REJECTS a `mainnet-ids-test-placeholders` build
(`PCLR-PIN:TEST...`) and an unpinned build (`PCLR-PIN:NONE`: no feature, or devnet) and accepts only
`PCLR-PIN:MAINNET-OK`. Also change the stake / NFT allowlists to the mainnet wrapper id in the same release.

## 2. Reproducible-build hash comparison""", 1)
        c = c.replace("`cargo build-sbf --sbf-out-dir out/mainnet` and `shasum", "`cargo build-sbf --features mainnet-ids --sbf-out-dir out/mainnet` and `shasum", 1)
        open(ck, "w").write(c)
    sh = "scripts/check-mainnet-sbf.sh"
    t = open(sh).read()
    if "check-mainnet-pin.sh" not in t:
        t = t.replace('echo "check-mainnet-sbf: PASS"', '"$ROOT/scripts/check-mainnet-pin.sh" "$SO"\necho "check-mainnet-sbf: PASS"', 1)
        open(sh, "w").write(t)
    print("wired release docs")

if sys.argv[1:] == ["--rc-release-docs"]:
    rc_release_docs(); sys.exit(0)
for path in sys.argv[1:]:
    s = open(path).read()
    s = keep_both(s, path)
    if path.endswith("v16_program.rs"):
        s = patch_arrays(s)
    assert "<<<<<<<" not in s and ">>>>>>>" not in s, path
    open(path, "w").write(s)
    print("resolved", path)
