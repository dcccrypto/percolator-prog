//! RCK round 2 (RC2 4db44b69): the DEX pin bit `DEPTH_DEX_PINNED` (0x40) survives every depth /
//! graduation write. `growth_v19::depth_push_update` and `graduation_reset` rebuild the source byte
//! WITHOUT 0x40; `AssetGrowthV19::set_depth_state` / `set_graduation` re-apply the stored pin bit.
//! Every harness calls the production fns and carries covers (a verdict counts only with every
//! cover SATISFIED). Design: ~/wt-v22kani-1020/reports/RCK.md §5 R2-3.
#![cfg(kani)]

use percolator_prog::growth_v19::*;
use percolator_prog::state::AssetGrowthV19;

const PIN: u8 = DEPTH_DEX_PINNED;

/// A record with any valid depth byte (0x40 allowed), any depth fields, any flags and any VALID
/// window (the validator's shape).
fn any_record() -> AssetGrowthV19 {
    let mut g = AssetGrowthV19::default();
    let b: u8 = kani::any();
    kani::assume(depth_source_byte_ok(b));
    g.depth_source = b;
    g.depth_e6 = kani::any();
    g.depth_slot = kani::any();
    g.depth_prev_e6 = kani::any();
    g.depth_last_good_e6 = kani::any();
    g.depth_last_good_slot = kani::any();
    g.depth_rise_slot64_le = kani::any();
    g.flags = kani::any();
    g.depth_tw_cur_le = kani::any();
    g.depth_tw_prev_le = kani::any();
    g.depth_tw_bucket_le = kani::any();
    kani::assume(depth_tw_window_ok(g.depth_tw()));
    g
}

/// RCK-7: one PushAuthMark depth write (v16_program.rs:28785 at 4db44b69) keeps the pin bit
/// exactly, keeps the byte valid, and otherwise stores exactly the writer's byte.
/// Mutant M-P1: `set_depth_state` writes `d.depth_source` verbatim -> FAIL.
#[kani::proof]
fn kani_rck_rc2_push_keeps_dex_pin() {
    let mut g = any_record();
    let before = g.depth_source;
    let src: u8 = kani::any();
    let d: u64 = kani::any();
    let now: u64 = kani::any();
    let seed: u64 = kani::any();
    let unit: u64 = if kani::any() { 1 } else { 1_000_000 };
    let o = depth_push_update(g.depth_state(), src, d, now, seed, unit);
    g.set_depth_state(o);
    let after = g.depth_source;
    assert_eq!(depth_dex_pinned(after), depth_dex_pinned(before), "the pin bit is kept exactly");
    assert!(depth_source_byte_ok(after), "the byte stays valid");
    assert_eq!(after & !PIN, o.depth_source & !PIN, "every other bit is the writer's");
    kani::cover!(depth_dex_pinned(before) && !depth_ever(before) && depth_ever(after), "pinned: a fresh push sets EVER, pin kept");
    kani::cover!(depth_dex_pinned(before) && src == DEPTH_SOURCE_DEX, "pinned: a DEX push");
    kani::cover!(depth_dex_pinned(before) && src == DEPTH_SOURCE_NONE, "pinned: an absent push");
    kani::cover!(!depth_dex_pinned(before) && !depth_dex_pinned(after), "unpinned stays unpinned");
    kani::cover!(depth_dex_pinned(before) && o.depth_source & PIN == 0, "the writer drops 0x40; the setter keeps it");
}

/// RCK-8: the I-1 reset write (`set_graduation(graduation_reset(..))`, v16_program.rs:7995) keeps
/// the pin bit and a valid byte. Mutant M-P2: `set_graduation` writes `f.depth_source` verbatim.
#[kani::proof]
fn kani_rck_rc2_reset_keeps_dex_pin() {
    let mut g = any_record();
    let before = g.depth_source;
    let la: u16 = kani::any();
    let lt: u16 = kani::any();
    let now: u64 = kani::any();
    let f = graduation_reset(la, lt, now);
    g.set_graduation(f);
    let after = g.depth_source;
    assert_eq!(depth_dex_pinned(after), depth_dex_pinned(before), "the pin survives I-1");
    assert!(depth_source_byte_ok(after));
    assert_eq!(after & !PIN, f.depth_source & !PIN, "otherwise the reset byte (0: EVER cleared)");
    kani::cover!(depth_dex_pinned(before) && depth_ever(before) && after == PIN, "pinned + EVER: reset to pin only");
    kani::cover!(!depth_dex_pinned(before) && after == 0, "unpinned: reset to 0");
}
