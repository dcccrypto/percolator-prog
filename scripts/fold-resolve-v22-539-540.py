#!/usr/bin/env python3
"""Mechanical resolution of the four known conflict hunks when folding percolator-prog #539 (R-10/R-12) and
#540 (mainnet-ids) into release/v22-wrapper-rem (see docs/FOLD_V22_539_540.md).

Every conflicted hunk is an ADJACENT APPEND (RC side + our side): keep BOTH, RC side first. Then:
  * ALL_NAMED_TAGS: replace the first two padding sentinels (201, 202) with TAG_PROPOSE_G9_FEED_ALLOWLIST and
    TAG_COMMIT_G9_FEED_ALLOWLIST (length stays 41);
  * `lag_policy` (RC-only exhaustive match over Instruction, compile error otherwise): add MarkFree arms for the two
    new instructions;
  * V22_ERROR_CODES: append `PercolatorError::G9AllowlistTimelock as u32,` and bump the length 26 -> 27.
Idempotent. Usage: scripts/fold-resolve-v22-539-540.py src/v16_program.rs src/bin/sdk_parity_fixtures.rs
"""
import re, sys

def keep_both(text):
    # diff3 style: <<<<<<< HEAD / ||||||| base / ======= / >>>>>>> theirs   (or plain 2-way)
    pat = re.compile(r"<<<<<<< [^\n]*\n(.*?)(?:\|\|\|\|\|\|\| [^\n]*\n.*?)?=======\n(.*?)>>>>>>> [^\n]*\n", re.S)
    return pat.sub(lambda m: m.group(1) + m.group(2), text)

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

for path in sys.argv[1:]:
    s = open(path).read()
    s = keep_both(s)
    if path.endswith("v16_program.rs"):
        s = patch_arrays(s)
    assert "<<<<<<<" not in s and ">>>>>>>" not in s, path
    open(path, "w").write(s)
    print("resolved", path)
