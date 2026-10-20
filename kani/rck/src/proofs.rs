//! RCK harnesses: v22 RC (75fca911) coverage gaps G-2 (off-band identity, ANY dials) and G-3
//! (the composed time-weighted depth reader). Design written before any run:
//! ~/wt-v22kani-1020/reports/RCK.md §2. Every harness calls the PRODUCTION functions of
//! `growth_v19` and carries `kani::cover!`s; a verdict counts only with every cover SATISFIED.

use crate::growth_v19::*;

// ── recording stub of `n_cap_q`: any result, every call's arguments recorded ─────────────────
// Sound for an identity claim: the stub admits every return value (the real, pure, deterministic
// `n_cap_q` among them), so "the caller returns exactly what the callee returned, called once with
// exactly these arguments" holds for the real callee too.
const NC_CAP: usize = 4;
static mut NC_N: usize = 0;
static mut NC_ARGS: [(u128, u32, u64, u128); NC_CAP] = [(0, 0, 0, 0); NC_CAP];
static mut NC_RET: [Option<u128>; NC_CAP] = [None; NC_CAP];

fn n_cap_q_rec(c_m: u128, lambda_bps: u32, price_e6: u64, pos_scale: u128) -> Option<u128> {
    let r: Option<u128> = kani::any();
    unsafe {
        let n = NC_N;
        if n < NC_CAP {
            NC_ARGS[n] = (c_m, lambda_bps, price_e6, pos_scale);
            NC_RET[n] = r;
        }
        NC_N = n + 1;
    }
    r
}

fn nc_calls() -> usize {
    unsafe { NC_N }
}

// ── recording stub of `growth_matcher_caps` ───────────────────────────────────────────────
static mut GM_N: usize = 0;
static mut GM_ARGS: (bool, u128, u32, u64, u128, u128) = (false, 0, 0, 0, 0, 0);
static mut GM_RET: (u128, u128) = (0, 0);

fn growth_matcher_caps_rec(
    hlock_active: bool,
    c_m: u128,
    lambda_bps: u32,
    price_e6: u64,
    pos_scale: u128,
    max_position_abs_q: u128,
) -> (u128, u128) {
    let r: (u128, u128) = kani::any();
    unsafe {
        if GM_N == 0 {
            GM_ARGS = (hlock_active, c_m, lambda_bps, price_e6, pos_scale, max_position_abs_q);
            GM_RET = r;
        }
        GM_N += 1;
    }
    r
}

/// RCK-1 (G-2): off the clamp, `n_cap_g8_q_dials` is EXACTLY growth-1's `n_cap_q` at the STORED
/// λ, for ANY dials (λ_depth, κ), any cap depth (none, a sticky 0, any value), any price and
/// scale, at full widths. Lever: `n_cap_q` replaced by a recording stub (no u128 arithmetic left).
/// Mutant: off-band `n_cap_q(c_m, min(stored, λ_depth), ..)` -> FAIL (args).
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_q_rec)]
fn kani_rck_g2_ncap_dials_off_band_is_growth1() {
    let c_m: u128 = kani::any();
    let stored: u32 = kani::any();
    let lam_d: u32 = kani::any();
    let kappa: u32 = kani::any();
    let depth: Option<u64> = kani::any();
    let price: u64 = kani::any();
    let ps: u128 = kani::any();
    let r = n_cap_g8_q_dials(false, c_m, stored, lam_d, kappa, depth, price, ps);
    assert_eq!(nc_calls(), 1, "off-band: exactly one n_cap_q call");
    let (args, ret) = unsafe { (NC_ARGS[0], NC_RET[0]) };
    assert_eq!(args, (c_m, stored, price, ps), "off-band: n_cap_q at the STORED λ, same price/scale");
    assert_eq!(r, ret, "off-band: the result IS n_cap_q's");
    kani::cover!(lam_d < stored && ret.is_some_and(|x| x > 0), "λ_depth below stored λ: ignored off-band");
    kani::cover!(depth == Some(0) && r.is_some_and(|x| x > 0), "a sticky 0 is ignored off-band");
    kani::cover!(depth.is_some_and(|d| d > 0) && kappa == 0 && r.is_some_and(|x| x > 0), "κ 0 with a depth: ignored");
    kani::cover!(r.is_none() && price != 0, "callee None passed through");
}

/// RCK-2 (G-2, the fn with no harness at the RC): off the clamp, `growth_matcher_caps_g8_dials`
/// is EXACTLY `growth_matcher_caps(hlock, c_m, stored λ, price, scale, max_pos)` for ANY dials and
/// cap depth, at full widths. Lever: recording stub on `growth_matcher_caps`; `n_cap_q` stubbed
/// with the counting stub, asserted never called (the off-band path computes nothing else).
/// Mutant: drop the `if !clamp` early return -> FAIL.
#[kani::proof]
#[kani::stub(crate::growth_v19::growth_matcher_caps, growth_matcher_caps_rec)]
#[kani::stub(crate::growth_v19::n_cap_q, n_cap_q_rec)]
fn kani_rck_g2_matcher_caps_dials_off_band_is_growth1() {
    let hl: bool = kani::any();
    let c_m: u128 = kani::any();
    let stored: u32 = kani::any();
    let lam_d: u32 = kani::any();
    let kappa: u32 = kani::any();
    let depth: Option<u64> = kani::any();
    let price: u64 = kani::any();
    let ps: u128 = kani::any();
    let mq: u128 = kani::any();
    let r = growth_matcher_caps_g8_dials(hl, false, c_m, stored, lam_d, kappa, depth, price, ps, mq);
    let (n, args, ret) = unsafe { (GM_N, GM_ARGS, GM_RET) };
    assert_eq!(n, 1, "off-band: exactly one growth_matcher_caps call");
    assert_eq!(args, (hl, c_m, stored, price, ps, mq), "off-band: growth-1 caps at the STORED λ");
    assert_eq!(r, ret, "off-band: the result IS growth_matcher_caps'");
    assert_eq!(nc_calls(), 0, "off-band: no depth / λ_eff computation");
    kani::cover!(hl, "h-lock on: still the growth-1 rule");
    kani::cover!(lam_d < stored && depth.is_some() && ret.0 > 0, "λ_depth and a depth would clamp on-band: ignored");
    kani::cover!(depth.is_none() && lam_d < stored, "no depth, λ_depth below stored: stored λ used");
    kani::cover!(depth == Some(0) && ret.0 > 0, "a sticky 0 is ignored off-band");
}

/// RCK-3 (G-3): the PRODUCTION composition of the depth readers (v16_program.rs:43568 and :43602):
/// `u = usable_depth_e6(fresh, lg, tw)`, `cap = cap_depth_e6(src, u, lg, lgs, now, tw)`.
/// `u` is exactly `min(fresh, lg, tw)`; once DEPTH_EVER the cap is never `None`; every cap is
/// `<= last_good`, `<= the window minimum` and `<= the fresh reading`; the sticky cap decays
/// monotonically in `now` (as `cap_depth_e6`, not only `sticky_depth_e6`).
/// Mutant: `usable_depth_e6` ignores `last_good` -> FAIL.
#[kani::proof]
fn kani_rck_g3_composed_depth_reader() {
    let src: u8 = kani::any();
    let ever: bool = kani::any();
    let byte = if ever { src | DEPTH_EVER } else { src & !DEPTH_EVER };
    let fresh: Option<u64> = kani::any();
    let lg: u64 = kani::any();
    let lgs: u64 = kani::any();
    let n1: u64 = kani::any();
    let n2: u64 = kani::any();
    kani::assume(n1 <= n2);
    let tw: Option<u64> = kani::any();
    let twv = tw.unwrap_or(u64::MAX);

    let u = usable_depth_e6(fresh, lg, tw);
    assert_eq!(u, fresh.map(|f| f.min(lg).min(twv)), "usable == min(fresh, last_good, tw)");

    let c1 = cap_depth_e6(byte, u, lg, lgs, n1, tw);
    if ever {
        assert!(c1.is_some(), "never uncapped once DEPTH_EVER");
    }
    if let Some(c) = c1 {
        assert!(c <= lg, "cap <= last_good");
        assert!(c <= twv, "cap <= window minimum");
        if let Some(f) = fresh {
            assert!(c <= f, "cap <= the fresh reading");
        }
    }
    if fresh.is_some() {
        assert_eq!(c1, u, "fresh: the cap is the usable depth");
    }
    if !ever && fresh.is_none() {
        assert_eq!(c1, None, "never had depth: no cap");
    }
    // sticky path: no fresh reading at either time
    let s1 = cap_depth_e6(byte, None, lg, lgs, n1, tw);
    let s2 = cap_depth_e6(byte, None, lg, lgs, n2, tw);
    let st1 = sticky_depth_e6(lg, lgs, n1);
    if ever {
        assert_eq!(s1, Some(st1.min(twv)), "sticky cap == min(sticky, tw)");
        assert!(s2.unwrap() <= s1.unwrap(), "the sticky cap decays monotonically in now");
    }
    let k1 = n1.saturating_sub(lgs) / DEPTH_STICKY_EPOCH_SLOTS;
    kani::cover!(fresh.is_some_and(|f| f < lg && f < twv) && c1 == fresh, "fresh binds");
    kani::cover!(fresh.is_some_and(|f| lg < f && lg < twv) && c1 == Some(lg), "last_good binds on the fresh path");
    kani::cover!(fresh.is_some_and(|f| twv < f && twv < lg) && c1 == tw, "window binds on the fresh path");
    kani::cover!(ever && tw.is_some_and(|t| t < st1) && s1 == tw, "window binds on the sticky path");
    kani::cover!(ever && s2.unwrap_or(0) < s1.unwrap_or(0), "staleness strictly lowers the cap");
    kani::cover!(ever && k1 >= 64 && lg > 0 && s1 == Some(0), "k >= 64: cap 0, still capped");
    kani::cover!(!ever && fresh.is_none() && c1.is_none(), "never had depth: None");
    kani::cover!(ever && n1 < lgs && lg > 0 && s1 == Some(lg.min(twv)), "future last-good stamp: no decay");
}

/// RCK-4 (G-2, the ceiling third of `kani_g8_off_band_identity`, which is NV under cadical 900 s
/// and z3 2400 s because of its u128 n_cap parts, proved by RCK-1/2 instead): off the clamp the
/// ceiling in force is exactly `min(L_launch, L_tier)`, whatever the stored ceiling and target.
/// Mutant: off-band `min(stored, launch)` (reads the stored ceiling off the clamp) -> FAIL.
#[kani::proof]
fn kani_rck_g2_ceiling_off_band_is_launch() {
    let stored: u16 = kani::any();
    let tgt: u16 = kani::any();
    let la: u16 = kani::any();
    let lt: u16 = kani::any();
    let f = ceiling_in_force_x100(false, stored, tgt, la, lt);
    assert_eq!(f, la.min(lt), "off-band: launch, never the stored / target ceiling");
    kani::cover!(stored > la.min(lt) && tgt > la.min(lt), "a graduated stored ceiling and target ignored");
    kani::cover!(stored < la.min(lt), "a stored ceiling below launch ignored too");
    kani::cover!(la > lt && f == lt, "L_tier binds");
}
