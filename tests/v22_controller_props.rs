//! v2.2 round 3 (2026-10-14, "one adaptive per-market controller",
//! `~/percolator-ops/ledger/v22-adaptive-controller-design-2026-10-14.md` §3-§4) property tests on
//! the REAL pure functions at FULL width. The `kani_r3_*` harnesses (in `src/v16_program.rs`)
//! bound the same functions to narrow widths; neither alone is the claim. Every property has a
//! named mutant as a NEGATIVE CONTROL (a deterministic witness shows the mutant violates it), so
//! no property is vacuous.
#![cfg(not(kani))]

use percolator_prog::growth_v19 as gv;
use percolator_prog::vault_lp_v18 as vl;
use proptest::prelude::*;

// ── item 1 (GAP-8): alpha <= 50% everywhere until F3 is proven; cushion on by default ─────────

/// MUTANT (GAP-8): the round-2 rule (a band market may allocate up to the band maximum).
fn alpha_in_force_mutant_round2(stored: u16) -> u16 {
    stored
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// GAP-8: with F3 unproven, the dial ceiling is 50% on every market and the alpha in force
    /// is `min(stored, 50%)`; once F3 is proven, band markets get the band maximum and the
    /// stored (setter-bounded) dial is used as written. The in-force alpha never exceeds the
    /// stored dial, and the allocation limit at the in-force alpha never exceeds 50% of C_eff.
    #[test]
    fn gap8_alpha_cap(stored in any::<u16>(), band in any::<bool>(), c_eff in any::<u128>(), allocated in any::<u128>(), drawable in any::<u128>()) {
        prop_assert_eq!(gv::alloc_alpha_max_bps_for(false, band), 5_000);
        prop_assert_eq!(gv::alloc_alpha_max_bps_for(true, band), if band { gv::ALLOC_ALPHA_MAX_BAND_BPS } else { 5_000 });
        prop_assert_eq!(gv::alloc_alpha_max_bps(band), gv::alloc_alpha_max_bps_for(gv::F3_PROVEN, band));
        let a = gv::alloc_alpha_in_force_bps_for(false, stored);
        prop_assert!(a <= 5_000 && a <= stored);
        prop_assert_eq!(a, stored.min(5_000));
        prop_assert_eq!(gv::alloc_alpha_in_force_bps_for(true, stored), stored);
        if stored <= gv::ALLOC_ALPHA_MAX_BAND_BPS {
            if let Some(lim) = vl::vault_lp_alloc_limit(c_eff, allocated, drawable, a, vl::ALLOC_BUFFER_MIN_BPS) {
                let half = vl::bps_floor(c_eff, 5_000).unwrap();
                prop_assert!(allocated.saturating_add(lim) <= half.max(allocated));
            }
        }
    }

    /// GAP-8: the default cushion split never over-fills the target and the senior part plus
    /// the cushion is the whole leg (the defaults are a valid both-or-neither pair).
    #[test]
    fn gap8_default_cushion_split(avail in any::<u64>(), c_eff in any::<u64>(), junior in any::<u64>()) {
        let (s, k) = vl::cushion_split(avail as u128, vl::CUSHION_SHARE_DEFAULT_BPS, vl::CUSHION_TARGET_DEFAULT_BPS, c_eff as u128, junior as u128).unwrap();
        prop_assert_eq!(s + k, avail as u128);
        prop_assert!(k <= (avail as u128) / 2);
        let target = vl::bps_ceil(c_eff as u128, vl::CUSHION_TARGET_DEFAULT_BPS).unwrap();
        prop_assert!(k <= target.saturating_sub(junior as u128));
    }
}

#[test]
fn r3_item1_mutants_are_caught() {
    // GAP-8: a 70% stored band dial allocates at most 50% now; the round-2 rule would allow 70%.
    assert_eq!(gv::alloc_alpha_in_force_bps_for(false, 7_000), 5_000);
    assert_eq!(alpha_in_force_mutant_round2(7_000), 7_000, "mutant witness: round-2 rule exceeds 50%");
    let lim = vl::vault_lp_alloc_limit(10_000, 0, 10_000, alpha_in_force_mutant_round2(7_000), vl::ALLOC_BUFFER_MIN_BPS).unwrap();
    assert!(lim > 5_000, "mutant witness: allocates {lim} > 50% of C 10,000");
    let lim = vl::vault_lp_alloc_limit(10_000, 0, 10_000, gv::alloc_alpha_in_force_bps_for(false, 7_000), vl::ALLOC_BUFFER_MIN_BPS).unwrap();
    assert_eq!(lim, 5_000);
    // The defaults are on (non-zero, both-or-neither).
    assert_eq!((vl::CUSHION_TARGET_DEFAULT_BPS, vl::CUSHION_SHARE_DEFAULT_BPS), (2_000, 5_000));
}

// ── item 3 (D1(a), GAP-4) after security review F-1 fix A: graded stress TARGET, down at once ──

/// MUTANT (D1(a)): round 2's ADL predicate (A != 1 or mode != Normal).
fn adl_mutant_round2(a_long_is_one: bool, a_short_is_one: bool, ml: u8, ms: u8) -> bool {
    !a_long_is_one || !a_short_is_one || ml != 0 || ms != 0
}

/// MUTANT (F-1 i): the round-3 1x-per-call descent restored in the in-force read
/// `max(target, stored - 1x)` (stored <= target: stored).
fn in_force_mutant_one_step(stored: u16, target: u16) -> u16 {
    if stored <= target {
        stored
    } else {
        target.max(stored.saturating_sub(gv::RATCHET_STEP_X100))
    }
}

/// MUTANT (F-1 i, writer): the round-3 ratchet fall `max(target, prev - 1x)` per call.
fn writer_fall_mutant_one_step(prev: u16, target: u16) -> u16 {
    target.max(prev.saturating_sub(gv::RATCHET_STEP_X100))
}

/// MUTANT (F-1 ii): stale / zero / missing depth does NOT drop the ceiling at once -- the gate
/// keeps reading the stored ceiling until a writer runs (no `min` with the live target when the
/// target came from a tier-0 / no-depth reading).
fn in_force_mutant_stale_kept(stored: u16, target: u16, depth_usable: bool) -> u16 {
    if depth_usable {
        stored.min(target)
    } else {
        stored
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// The stress level is the highest flag; the cap is monotone non-increasing in the level and
    /// non-decreasing in the tier, `L_table(tier - s)` floored at launch for s = 1, 2, launch at 3.
    #[test]
    fn item3_stress_cap(dr in any::<bool>(), adl in any::<bool>(), hl in any::<bool>(), tier in 0u8..=3, la in any::<u16>(), lt in any::<u16>(), lev in any::<[u16; 3]>()) {
        let s = gv::stress_level(dr, adl, hl);
        prop_assert_eq!(s, if hl { 3 } else if adl { 2 } else if dr { 1 } else { 0 });
        let tab = gv::tier_leverage(lev, la, lt);
        for st in 0u8..3 {
            prop_assert!(gv::stress_cap_x100(st + 1, tier, tab) <= gv::stress_cap_x100(st, tier, tab));
        }
        if tier < 3 { prop_assert!(gv::stress_cap_x100(s, tier, tab) <= gv::stress_cap_x100(s, tier + 1, tab)); }
        prop_assert_eq!(gv::stress_cap_x100(3, tier, tab), tab[0]);
        if s == 1 || s == 2 { prop_assert_eq!(gv::stress_cap_x100(s, tier, tab), tab[tier.saturating_sub(s) as usize]); }
        prop_assert!(!gv::real_adl(0, 0));
    }

    /// Down at once: whenever the live target is below the stored ceiling, the gate reads the
    /// target in the same slot (`min(stored, target)`) and one writer call lands the stored
    /// ceiling on it (the floor -- launch -- under the h-lock), stamped `now`.
    #[test]
    fn item3_down_at_once(prev in any::<u16>(), target in any::<u16>(), ps in any::<u64>(), now in any::<u64>(), st in 0u8..=3, launch in any::<u16>()) {
        let floor = launch.min(target);
        let (c, cs) = gv::ratchet_ceiling_x100(prev, ps, target, floor, st, now);
        if prev > target {
            prop_assert_eq!(c, if st >= gv::STRESS_HLOCK { floor } else { target }, "writer: down at once");
            prop_assert_eq!(cs, now);
        }
        let f = gv::ceiling_in_force_x100(true, prev, target, launch, u16::MAX);
        prop_assert_eq!(f, prev.min(target));
    }

    /// Stale / zero / missing depth: the venue tier is 0, the target is launch, and the ceiling
    /// in force is launch in the SAME read whatever was stored (full width, every stress level).
    #[test]
    fn item3_stale_depth_launch_at_once(stored in any::<u16>(), st in 0u8..=3, la in any::<u16>(), lt in any::<u16>(), lev in any::<[u16; 3]>(), band in any::<u16>()) {
        let tab = gv::tier_leverage(lev, la, lt);
        // tier 0 (no usable depth) -> graduation off, L_table(0) = launch
        let grad = gv::graduation_on(true, band as u64, 0);
        prop_assert!(!grad);
        let t = gv::target_ceiling_x100(grad, st, la, lt, gv::l_table_x100(0, tab), gv::stress_cap_x100(st, 0, tab));
        prop_assert_eq!(t, la.min(lt));
        prop_assert_eq!(gv::ceiling_in_force_x100(true, stored, t, la, lt), stored.min(la.min(lt)));
    }
}

#[test]
fn r3_item3_mutants_are_caught() {
    // D1(a): a matched band liquidation (A_short < 1, modes Normal) is not ADL now; the round-2
    // predicate read it as ADL (-> launch).
    assert!(!gv::real_adl(0, 0));
    assert!(adl_mutant_round2(true, false, 0, 0), "mutant witness: A != 1 read as ADL");
    // F-1 fix A: stored 20x, target 5x (depth collapse): in force 5x in the same read, and one
    // writer call lands the stored ceiling on 5x.
    assert_eq!(gv::ceiling_in_force_x100(true, 2_000, 500, 500, 2_000), 500);
    assert_eq!(gv::ratchet_ceiling_x100(2_000, 0, 500, 500, gv::STRESS_NONE, 1), (500, 1));
    assert_eq!(gv::ratchet_ceiling_x100(2_000, 0, 1_000, 500, gv::STRESS_DRAW, 1), (1_000, 1), "draw: to L_table(tier-1) at once");
    // mutant (i): the 1x/call descent comes back -> 19x in force, 19x stored: caught by both
    // item3_down_at_once assertions
    assert_eq!(in_force_mutant_one_step(2_000, 500), 1_900, "mutant witness (i): in force 19x, not 5x");
    assert_eq!(writer_fall_mutant_one_step(2_000, 500), 1_900, "mutant witness (i): writer 19x, not 5x");
    // mutant (ii): stale / zero / missing depth kept at the stored 20x -> caught by
    // item3_stale_depth_launch_at_once
    assert_eq!(in_force_mutant_stale_kept(2_000, 500, false), 2_000, "mutant witness (ii): stale keeps 20x");
    assert_ne!(in_force_mutant_stale_kept(2_000, 500, false), gv::ceiling_in_force_x100(true, 2_000, 500, 500, 2_000));
}

// ── item 4 (GAP-5, D-I1, D2): time-weighted two-bucket window ───────────────────────────────

/// MUTANT (GAP-5): round 2 fed the raw fresh reading (no window): a one-sample spike counts.
fn window_mutant_round2(_w: gv::DepthWindow, r: u32) -> u32 {
    r
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// The window minimum is <= every sample folded into the current and (adjacent) previous
    /// bucket; a sample more than one bucket old never raises it (it is dropped, never folded
    /// up); the window is full iff the previous bucket is present; ring wrap-around is safe.
    #[test]
    fn item4_window(samples in prop::collection::vec((any::<u32>(), 0u64..3_000), 1..40), start in any::<u64>()) {
        let mut w = gv::DepthWindow::default();
        let mut slot = start / 2;
        let mut seen: Vec<(u64, u32)> = Vec::new();
        for (r, dt) in samples {
            let r = r.min(gv::DEPTH_TW_ABSENT - 1);
            slot = slot.saturating_add(dt);
            w = gv::depth_tw_update(w, r, slot);
            seen.push((slot / gv::DEPTH_TW_BUCKET_SLOTS, r));
            prop_assert!(gv::depth_tw_window_ok(w));
            let b = slot / gv::DEPTH_TW_BUCKET_SLOTS;
            let m = gv::depth_tw_min_atoms(w, 1).unwrap();
            for &(sb, sr) in &seen {
                if sb == b || (w.prev_tokens != gv::DEPTH_TW_ABSENT && sb + 1 == b) {
                    prop_assert!(m <= sr as u64, "min {m} above a window sample {sr}");
                }
            }
            prop_assert!(m <= r as u64);
            prop_assert_eq!(gv::depth_tw_full(w), w.prev_tokens != gv::DEPTH_TW_ABSENT);
        }
    }

    /// D-I1 + D2 at the limiter: the first reading is <= T1/16; a zero window holds last_good
    /// and its slot; any positive window minimum yields <= max(2 * decayed base, T1/16).
    #[test]
    fn item4_limiter(lg in any::<u64>(), lgs in any::<u64>(), re in any::<u32>(), w in any::<u64>(), full in any::<bool>(), slot in any::<u64>(), seed in any::<u64>()) {
        let floor = seed / gv::DEPTH_BOOTSTRAP_DIV;
        let (a, _, s) = gv::depth_rate_limited(false, lg, lgs, re, w, full, slot, seed);
        prop_assert!(a <= floor && a <= w && s == slot);
        let (b, r2, s2) = gv::depth_rate_limited(true, lg, lgs, re, 0, full, slot, seed);
        prop_assert_eq!((b, r2, s2), (lg, re, lgs));
        if w > 0 {
            let (c, _, _) = gv::depth_rate_limited(true, lg, lgs, re, w, full, slot, seed);
            let base = gv::sticky_depth_e6(lg, lgs, slot);
            prop_assert!(c <= base.saturating_mul(2).max(floor).max(base));
            prop_assert!(c <= w.max(base));
        }
    }
}

#[test]
fn r3_item4_mutants_are_caught() {
    let b = gv::DEPTH_TW_BUCKET_SLOTS;
    // a $2k bucket then a $50M spike in the next bucket: the window still reads $2k
    let w = gv::depth_tw_update(gv::depth_tw_update(gv::DepthWindow::default(), 2_000, b), 50_000_000, 2 * b);
    assert_eq!(gv::depth_tw_min_atoms(w, 1), Some(2_000));
    assert_eq!(window_mutant_round2(w, 50_000_000), 50_000_000, "mutant witness: the spike counts");
    // D2: round 2 zeroed last_good on a real 0 (the mutant); now it is held
    let (held, _, _) = gv::depth_rate_limited(true, 150_000, 7, 0, 0, true, 100, 25_000);
    assert_eq!(held, 150_000);
    // D-I1: the first reading of a $500M flash is T1/16, not T1 - 1
    let (first, _, _) = gv::depth_rate_limited(false, 0, 0, 0, 500_000_000, false, 5, 24_999);
    assert_eq!(first, 24_999 / 16);
}

// ── continuous leverage (2026-10-19): log-interpolated curve over the tier anchors ─────────
// Replaces round 3 item 5's "never looser than the step" ramps (Khubair 10-19: "it's not truly
// dynamic if it's 5x/10x -- it should be able to go to 6x etc"). The curve equals the tier table
// AT each anchor (T1/4, T1, T2, T3) and is continuous and monotone between them.

/// The round-2 STEP table (the NEGATIVE CONTROL for continuity: it jumps at every threshold).
fn step_table(d: u64, th: [u64; 3], t: [u64; 4]) -> u64 {
    t[gv::depth_tier_for(d, th) as usize]
}

/// The round-3 item-5 25% ramp, verbatim (removed from src; kept here as the NEGATIVE CONTROL
/// for "equal to the table at each anchor": it reads the LOWER value at T_i).
fn r3_ramp_removed(d: u64, th: [u64; 3], table: [u64; 4]) -> u64 {
    let i = gv::depth_tier_for(d, th) as usize;
    if i == 0 {
        return table[0];
    }
    let lo_x = th[i - 1];
    let next = if i < 3 { th[i] } else { u64::MAX };
    let ramp_end = core::cmp::min(lo_x.saturating_add(lo_x / 4), next);
    let (lo, hi) = (table[i - 1], table[i]);
    if d >= ramp_end || ramp_end <= lo_x || hi <= lo {
        return hi;
    }
    lo + ((((hi - lo) as u128) * ((d - lo_x) as u128)) / ((ramp_end - lo_x) as u128)) as u64
}

/// MUTANT: linear in depth (not log) between anchors -- still continuous, but its value at the
/// geometric mid-point differs (the log-interp witness below).
fn linear_mutant(d: u64, th: [u64; 3], t: [u64; 4]) -> u64 {
    let a = gv::curve_anchors(th);
    if d < a[0] { return t[0]; }
    for i in 1..4 {
        if d < a[i] {
            return t[i - 1] + (t[i] - t[i - 1]) * (d - a[i - 1]) / (a[i] - a[i - 1]);
        }
    }
    t[3]
}

/// The largest jump of `f` between neighbouring sample depths of a fine sweep over
/// `[lo, hi]` with step `max(1, x >> shift)` (relative resolution 2^-shift), plus the exact
/// atom-adjacent pairs `(a - 1, a)` and `(a, a + 1)` at each anchor.
fn max_jump(f: &dyn Fn(u64) -> u64, lo: u64, hi: u64, shift: u32, anchors: &[u64]) -> (u64, u64) {
    let mut worst = (0u64, 0u64);
    let mut x = lo;
    let mut prev = f(x);
    while x < hi {
        let nx = x + core::cmp::max(1, x >> shift);
        let v = f(nx);
        let j = v.abs_diff(prev);
        if j > worst.0 { worst = (j, nx); }
        prev = v;
        x = nx;
    }
    for &a in anchors {
        if a == 0 || a == u64::MAX { continue; }
        for (p, q) in [(a - 1, a), (a, a + 1)] {
            let j = f(q).abs_diff(f(p));
            if j > worst.0 { worst = (j, q); }
        }
    }
    worst
}

const USD: u64 = 1_000_000;

/// Realistic per-market configs: the default thresholds, the UA floors, a wide spacing; on 6- and
/// 9-decimal collateral.
fn configs() -> Vec<[u64; 3]> {
    let mut v = vec![];
    for dec in [6u8, 9] {
        for th in [[0u32; 3], [5_000, 20_000, 100_000], [10_000, 200_000, 5_000_000], [30_000, 40_000, 150_000]] {
            v.push(gv::tier_thresholds(th, dec));
        }
    }
    v
}

fn tables() -> Vec<[u16; 4]> {
    vec![
        gv::tier_leverage([0; 3], 500, 2_000),       // default 20x market launched at 5x
        gv::tier_leverage([0; 3], 200, 2_000),       // launched at 2x
        gv::tier_leverage([0; 3], 500, 500),         // a 5x market: flat
        gv::tier_leverage([700, 2_500, 5_000], 300, 5_000), // a steep 50x table
        gv::tier_leverage([1_000, 5_000, 10_000], 100, 10_000), // 100x table (max u16 headroom)
    ]
}

fn u64t(t: [u16; 4]) -> [u64; 4] {
    [t[0] as u64, t[1] as u64, t[2] as u64, t[3] as u64]
}

/// CONTINUITY at fine resolution: no jump > 1 (x100 for leverage, bps for κ / λ) between
/// neighbouring depths (relative step 2^-20) anywhere on [T1/8, 2·T3], and across each anchor's
/// atom-adjacent pairs, for every realistic config and table.
#[test]
fn contlev_continuous_at_fine_resolution() {
    for th in configs() {
        let anc = gv::curve_anchors(th);
        for tab in tables() {
            let t = u64t(tab);
            for table in [t, gv::KAPPA_TABLE_BPS, gv::LAMBDA_DEPTH_TABLE_BPS] {
                let f = |d: u64| gv::curve_u64(d, th, table);
                let (j, at) = max_jump(&f, anc[0] / 2, th[2].saturating_mul(2), 20, &anc);
                assert!(j <= 1, "jump {j} at depth {at} (th {th:?}, table {table:?})");
            }
        }
    }
}

/// NEGATIVE CONTROL for the continuity test: the round-2 step table FAILS it (a 5x jump at T2
/// and 10x at T3 on the default table; κ doubles at T1), and so would any regression to steps.
#[test]
fn contlev_negative_control_step_table_fails_continuity() {
    let th = gv::tier_thresholds([0; 3], 6);
    let anc = gv::curve_anchors(th);
    let t = u64t(gv::tier_leverage([0; 3], 500, 2_000));
    let f = |d: u64| step_table(d, th, t);
    let (j, at) = max_jump(&f, anc[0] / 2, th[2] * 2, 20, &anc);
    assert_eq!(j, 1_000, "the step table jumps 10x at T3");
    assert!(at >= th[2] && at <= th[2] + (th[2] >> 19), "at T3 ({at})");
    let fk = |d: u64| step_table(d, th, gv::KAPPA_TABLE_BPS);
    assert!(max_jump(&fk, anc[0] / 2, th[2] * 2, 20, &anc).0 >= 5_000, "κ step doubles at T1");
    // the removed r3 ramp is continuous but NOT equal to the table at the anchors
    assert_eq!(r3_ramp_removed(th[1], th, t), 500, "r3 ramp reads 5x AT T2");
    assert_eq!(gv::curve_u64(th[1], th, t), 1_000, "the curve reads the table (10x) AT T2");
    // the linear-in-depth mutant: at the geometric mid-point $50k of [$25k, $100k] it reads 6.67x,
    // the log curve 7.5x
    assert_eq!(linear_mutant(50_000 * USD, th, t), 666);
    assert_eq!(gv::curve_u64(50_000 * USD, th, t), 750);
}

/// The curve table of the ledger (default thresholds, 6 decimals, 20x market launched at 5x;
/// and launched at 2x). Pins the numbers the ledger quotes.
#[test]
fn contlev_ledger_curve_table() {
    let th = gv::tier_thresholds([0; 3], 6);
    let l = u64t(gv::tier_leverage([0; 3], 500, 2_000));
    let rows: [(u64, u64, u64, u64); 12] = [
        // ($, L x100, κ bps, λ bps)
        (5_000, 500, 5_000, 10_000),
        (10_000, 500, 6_695, 10_000),
        (20_000, 500, 9_195, 10_000),
        (25_000, 500, 10_000, 10_000),
        (40_000, 669, 10_000, 13_390),
        (50_000, 750, 10_000, 15_000),
        (75_000, 896, 10_000, 17_924),
        (100_000, 1_000, 10_000, 20_000),
        (200_000, 1_430, 14_306, 24_306),
        (300_000, 1_682, 16_826, 26_826),
        (500_000, 2_000, 20_000, 30_000),
        (1_000_000, 2_000, 20_000, 30_000),
    ];
    for (usd, lx, k, lam) in rows {
        let d = usd * USD;
        assert_eq!(gv::curve_u64(d, th, l), lx, "L at ${usd}");
        assert_eq!(gv::curve_u64(d, th, gv::KAPPA_TABLE_BPS), k, "κ at ${usd}");
        assert_eq!(gv::curve_u64(d, th, gv::LAMBDA_DEPTH_TABLE_BPS), lam, "λ at ${usd}");
    }
}

/// The one discontinuity the curve does NOT remove: GRADUATION (kept discrete, `graduation_on`
/// needs tier >= 1 on BOTH depths). Below T1 the target is launch; at T1 it is L1. On a market
/// launched at L1 (the default 5x memecoin config) the jump is 0; launched below L1 it is
/// exactly L1 - launch (the ratchet still climbs it 1x per epoch; the fall is at once).
#[test]
fn contlev_graduation_step_is_the_only_jump() {
    let th = gv::tier_thresholds([0; 3], 6);
    let band = 64u64;
    for (la, expect_jump) in [(500u16, 0u16), (200, 300)] {
        let tab = gv::tier_leverage([0; 3], la, 2_000);
        let target = |d: u64| {
            let tier = gv::combined_tier(gv::depth_tier_for(d, th), gv::depth_tier_for(d, th));
            let grad = gv::graduation_on(true, band, tier);
            let dials = gv::smooth_dials(d, d, th, tab);
            gv::target_ceiling_x100(grad, gv::STRESS_NONE, la, 2_000, dials.l_signal_x100, u16::MAX)
        };
        assert_eq!(target(th[0] - 1), la, "below T1: launch");
        assert_eq!(target(th[0]), tab[1]);
        assert_eq!(target(th[0]) - target(th[0] - 1), expect_jump);
        // above T1 the effective target is continuous
        let f = |d: u64| target(d) as u64;
        let (j, _) = max_jump(&f, th[0], th[2] * 2, 20, &th[1..]);
        assert!(j <= 1, "effective target continuous above T1: jump {j}");
    }
}

fn arb_th() -> impl Strategy<Value = [u64; 3]> {
    (1u64..1_000_000_000, 1u64..1_000_000_000, 1u64..1_000_000_000).prop_map(|(a, b, c)| [a, a + b, a + b + c])
}

fn arb_table() -> impl Strategy<Value = [u64; 4]> {
    (0u64..50_000, 0u64..50_000, 0u64..50_000, 0u64..50_000).prop_map(|(a, b, c, d)| [a, a + b, a + b + c, a + b + c + d])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// log2_q16 is monotone and its integer part exact, at full u64 width.
    #[test]
    fn contlev_log2_monotone(x in 1u64.., y in 1u64..) {
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        let (la, lb) = (gv::log2_q16(a).unwrap(), gv::log2_q16(b).unwrap());
        prop_assert!(la <= lb);
        prop_assert_eq!(la >> gv::LOG2_FRAC_BITS, 63 - a.leading_zeros());
        // within 2^-15 of the true value (below it)
        let exact = (a as f64).log2() * 65_536.0;
        prop_assert!((la as f64) <= exact + 1e-6 && exact - (la as f64) < 2.0, "{a}: {la} vs {exact}");
    }

    /// Monotone; between t[0] and t[3]; in [step(d), next step] (never tighter than the round-2
    /// step, never looser than the next anchor's value); EQUAL to the table at each anchor;
    /// t[0] below anchor 0 and t[3] from T3.
    #[test]
    fn contlev_curve_props(d in any::<u64>(), e in any::<u64>(), th in arb_th(), t in arb_table()) {
        let f = |x: u64| gv::curve_u64(x, th, t);
        let (a, b) = if d <= e { (d, e) } else { (e, d) };
        prop_assert!(f(a) <= f(b), "monotone");
        let v = f(d);
        prop_assert!(v >= t[0] && v <= t[3]);
        let i = gv::depth_tier_for(d, th) as usize;
        prop_assert!(v >= step_table(d, th, t), "never below the step");
        prop_assert!(v <= t[core::cmp::min(i + 1, 3)], "never above the next anchor's value");
        let anc = gv::curve_anchors(th);
        for k in 0..4 {
            if anc[k] > 0 && (k == 0 || anc[k] > anc[k - 1]) {
                prop_assert_eq!(f(anc[k]), t[k], "equal to the table at anchor {}", k);
            }
        }
        if d < anc[0] { prop_assert_eq!(v, t[0]); }
        if d >= th[2] { prop_assert_eq!(v, t[3]); }
    }

    /// The dials: min(venue curve, book curve) for each table (so the smaller depth binds),
    /// never above L_tier, never below launch, κ in [0.5, 2], λ in [1x, 3x]; the venue-only value
    /// is >= the signal (the fall-only writer's upper bound).
    #[test]
    fn contlev_dials(v in any::<u64>(), b in any::<u64>(), th in arb_th(), la in 100u16..=2_000, lt in 100u16..=10_000, lev in any::<[u16; 3]>()) {
        let tab = gv::tier_leverage(lev, la.min(lt), lt);
        let (d, vl) = gv::smooth_dials_and_venue_l(v, b, th, tab);
        let t = u64t(tab);
        prop_assert_eq!(d.l_signal_x100 as u64, gv::curve_u64(v, th, t).min(gv::curve_u64(b, th, t)));
        prop_assert_eq!(d.l_signal_x100 as u64, gv::curve_u64(v.min(b), th, t), "min(venue, book) = the smaller depth");
        prop_assert_eq!(d.kappa_bps as u64, gv::curve_u64(v.min(b), th, gv::KAPPA_TABLE_BPS));
        prop_assert_eq!(d.lambda_depth_bps as u64, gv::curve_u64(v.min(b), th, gv::LAMBDA_DEPTH_TABLE_BPS));
        prop_assert_eq!(vl as u64, gv::curve_u64(v, th, t));
        prop_assert!(vl >= d.l_signal_x100);
        prop_assert!(d.l_signal_x100 <= lt && d.l_signal_x100 >= la.min(lt), "within [launch, L_tier]");
        prop_assert!(d.kappa_bps >= 5_000 && d.kappa_bps <= 20_000);
        prop_assert!(d.lambda_depth_bps >= 10_000 && d.lambda_depth_bps <= 30_000);
        // the target built from it never exceeds L_tier
        let tier = gv::combined_tier(gv::depth_tier_for(v, th), gv::depth_tier_for(b, th));
        let tgt = gv::target_ceiling_x100(gv::graduation_on(true, 64, tier), 0, la, lt, d.l_signal_x100, u16::MAX);
        prop_assert!(tgt <= lt);
        if v.min(b) < th[0] { prop_assert_eq!(tgt, la.min(lt), "below T1: launch"); }
    }

    /// Fail closed: a saturated anchor is never met and a segment toward it is flat; a zero
    /// depth reads t[0]; an attested venue depth never reads above L_m (m = attested_max_tier).
    #[test]
    fn contlev_fail_closed(d in any::<u64>(), th in arb_th(), t in arb_table(), m in 0u8..=3, eff in any::<u64>()) {
        prop_assert_eq!(gv::curve_u64(0, th, t), t[0]);
        let sat = [th[0], u64::MAX, u64::MAX];
        prop_assert!(gv::curve_u64(d, sat, t) <= t[1], "saturated T2 / T3: never above L1");
        prop_assert_eq!(gv::curve_u64(d, [u64::MAX; 3], t), t[0]);
        prop_assert_eq!(gv::curve_value(gv::CURVE_POS_FAIL, t), t[0]);
        let cap = gv::venue_depth_capped(eff, gv::DEPTH_SOURCE_ATTESTED, th, m);
        let me = gv::attested_max_tier_eff(m) as usize;
        prop_assert!(gv::curve_u64(cap, th, t) <= t[me], "attested cap at anchor {}", me);
        if eff >= th[me.min(3) - 1] && me < 3 { prop_assert_eq!(gv::curve_u64(cap, th, t), t[me], "reaches L_m"); }
        prop_assert_eq!(gv::venue_depth_capped(eff, gv::DEPTH_SOURCE_NONE, th, m), 0);
    }
}

// ── item 6 (GAP-6): the volatility input ───────────────────────────────────────────────────

/// MUTANT: no seed (the first calm sample sets the variance to ~0 -> L_vol at the engine IMR).
fn vol_update_mutant_noseed(_var: u32, has: bool, x: u64) -> u32 {
    if has { 0 } else { x.min(u32::MAX as u64) as u32 }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// Full width: the sample never understates the capped move; the EWMA stays between the old
    /// value and the sample (the seed bounds the first); L_vol is monotone non-increasing in the
    /// variance and never above 1e6 / IMR; no data never loosens above launch.
    #[test]
    fn item6_vol(p0 in 1u64..u64::MAX, p1 in any::<u64>(), dt in 1u64..1_000_000, var in any::<u32>(), has in any::<bool>(), x in any::<u64>(), v1 in any::<u32>(), v2 in any::<u32>(), h in 0u64..1_000_000, imr in 1u64..=10_000, fee in 0u64..1_000, sig in any::<u16>(), launch in any::<u16>()) {
        let smp = gv::vol_sample_x100(p0, p1, dt).unwrap();
        let mv = ((p1 as u128).abs_diff(p0 as u128) * 10_000) / (p0 as u128);
        let mv = mv.min(gv::VOL_MOVE_CAP_BPS as u128);
        prop_assert!(smp as u128 >= mv * mv * 100 / dt as u128);
        let u = gv::vol_update_x100(var, has, x);
        let xs = x.min(u32::MAX as u64) as u32;
        if has { prop_assert!(u >= var.min(xs) && u <= var.max(xs)); } else { prop_assert!(u >= gv::VOL_VAR_SEED_X100.max(xs)); }
        let (a, b) = if v1 <= v2 { (v1, v2) } else { (v2, v1) };
        let la = gv::l_vol_x100(imr, gv::sigma_h_bps(a, h), fee);
        let lb = gv::l_vol_x100(imr, gv::sigma_h_bps(b, h), fee);
        prop_assert!(lb <= la);
        prop_assert!(la as u64 <= 1_000_000 / imr);
        prop_assert!(gv::l_signal_with_vol(sig, None, launch) <= launch);
        prop_assert!(gv::l_signal_with_vol(sig, Some(la), launch) <= sig.min(la));
    }
}

#[test]
fn r3_item6_mutants_are_caught() {
    // no seed: one calm sample would read "no volatility" -> the engine IMR's leverage at once
    assert_eq!(vol_update_mutant_noseed(0, false, 0), 0);
    assert_eq!(gv::vol_update_x100(0, false, 0), gv::VOL_VAR_SEED_X100);
    let calm = gv::l_vol_x100(500, gv::sigma_h_bps(vol_update_mutant_noseed(0, false, 0), 1_200), 50);
    let seeded = gv::l_vol_x100(500, gv::sigma_h_bps(gv::VOL_VAR_SEED_X100, 1_200), 50);
    assert!(calm > seeded, "mutant witness: {calm} > {seeded}");
}

// ── item 7 (GAP-10, GAP-13c) ─────────────────────────────────────────────────────────────────

/// MUTANT (round 2): the rent snapshot takes the new N_cap at once.
fn rent_snapshot_mutant_round2(_prev: u64, st: u32, new: u64, _now: u64) -> (u64, u32) {
    (new, st)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_096))]

    /// The rent snapshot: rises at once; a fall is never below max(new, prev >> k) for the whole
    /// 900-slot windows k since the stamp (a never-stamped one: one halving), never below the new
    /// value, never above prev; a sequence of writes falls at most 2x per 900 slots.
    #[test]
    fn item7_rent_snapshot(prev in any::<u64>(), st in any::<u32>(), new in any::<u64>(), now in any::<u64>()) {
        let (v, st2) = gv::rent_snapshot_smooth(prev, st, new, now);
        if prev == 0 || new >= prev { prop_assert_eq!((v, st2), (new, st)); return Ok(()); }
        prop_assert!(v >= new && v <= prev);
        let k = if st == 0 { 1 } else { now.saturating_sub(((st - 1) as u64).saturating_mul(64).saturating_add(63)) / 900 };
        let floor = if k >= 64 { 0 } else { prev >> k };
        prop_assert_eq!(v, new.max(floor).min(prev));
    }

    #[test]
    fn item7_rent_sequence(start in 1u64..u64::MAX, steps in prop::collection::vec((0u64..2_000, any::<u64>()), 1..30)) {
        let (mut v, mut st, mut now) = (start, 0u32, 10_000u64);
        let mut last_fall_slot: Option<u64> = None;
        for (dt, new) in steps {
            now += dt;
            let (n, s2) = gv::rent_snapshot_smooth(v, st, new, now);
            if n < v {
                prop_assert!(n >= v / 2 || last_fall_slot.is_none_or(|l| now >= l + 900) || st == 0, "<= 2x per 900 slots");
                if let Some(l) = last_fall_slot {
                    let k = (now - l) / 900;
                    prop_assert!(k >= 1 || st == 0);
                    if k < 64 { prop_assert!(n >= v >> k); }
                }
                last_fall_slot = Some(now);
            }
            v = n; st = s2;
        }
    }
}

#[test]
fn r3_item7_mutants_are_caught() {
    // a real 0 depth: round 2 jumped every open position to max rent at once (snapshot 1)
    assert_eq!(rent_snapshot_mutant_round2(1_000_000, 0, 1, 10).0, 1);
    assert_eq!(gv::rent_snapshot_smooth(1_000_000, 0, 1, 10), (500_000, 1), "one halving, stamped (never 0)");
    assert_eq!(gv::rent_snapshot_smooth(500_000, 1, 1, 11).0, 500_000, "and held in its window");
    // min leg: a thin market whose kappa_0 capacity cannot hold one minimum leg is refused
    assert!(!gv::band_min_leg_fits_depth(100_000_000, Some(150_000_000)));
}
