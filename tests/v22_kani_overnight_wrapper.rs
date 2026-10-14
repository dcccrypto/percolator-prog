//! v2.2 Kani overnight (2026-10-14): verdict-bearing SPLIT replacements for the wrapper rows that had NO
//! VERDICT in the official v2.2 final run (bonds W-C-5..9, rescue W-D-1/2, growth R6 tag 93). The original
//! harnesses are kept unchanged in `tests/v22_kani_cfl.rs`, `tests/v22_kani_ad.rs`, `tests/growth_kani.rs`.
//!
//! Run (session runner, one at a time):
//!   cargo kani --tests --features devnet -Z function-contracts -Z stubbing --exact --harness <name>
//!
//! Decomposition rules used here (each harness says which one it uses):
//! * STUB-ANY: a production function WITHOUT a Kani contract whose result the asserted property does not
//!   depend on (beyond its type / its None-condition) is replaced by an arbitrary value. Sound: the stub's
//!   behaviours include the real one, and every assertion is universal.
//! * STUB-MEMO: a PURE production function (no state, no contract) is replaced by an arbitrary value that
//!   is CONSISTENT across calls with the same arguments (a small memo table). Sound: the real function is one
//!   of the functions the memo stub can behave as (determinism is the only property used).
//! * STUB-MODEL: a production function is replaced by a closed-form model that a separate PASSING harness
//!   proves equal to it on the whole domain used here (CONDITIONAL on that harness).
//! * FLOOR + ALGEBRA: a nonlinear claim `Q(f(x))` is split into (a) the exact floor facts of the REAL
//!   composite `f` (remainder form, both directions), and (b) an algebra lemma over FRESH symbols: every
//!   value satisfying (a)'s facts satisfies `Q`. (a) /\ (b) => original. The floor facts determine the
//!   floor uniquely, so (b) quantifies over exactly the real value (no over-approximation is lost).
//! * Every new harness carries `kani::cover!` witnesses; PASS counts only with all covers satisfied.
#![cfg(kani)]
#![allow(clippy::all)]
#![allow(static_mut_refs)]

extern crate kani;

use percolator_prog::bond_v20::*;
use percolator_prog::ix::Instruction;
use percolator_prog::p4_rescue_ins as p4;
use percolator_prog::vault_lp_v18::{alloc_junior_ok, bps_floor, junior_withdraw_allowed};

// Stub targets must resolve at compile time.
#[allow(unused_imports)]
use percolator_prog::bond_v20::bond_coupon_split as _t1;
#[allow(unused_imports)]
use percolator_prog::growth_v19::n_cap_q as _t2;
#[allow(unused_imports)]
use percolator_prog::vault_lp_v18::bps_ceil as _t3;
#[allow(unused_imports)]
use percolator_prog::vault_lp_v18::bps_floor as _t4;

fn min2(a: u128, b: u128) -> u128 {
    if a < b { a } else { b }
}

// ─────────────────────────────── STUB-MEMO / STUB-ANY / STUB-MODEL stubs ───────────────────────────────

const MEMO_N: usize = 4;

/// STUB-MEMO for `vault_lp_v18::bps_ceil(x, bps)`: `None` iff `bps > 10_000` (exactly the production
/// None-condition), otherwise an arbitrary value, consistent for repeated `(x, bps)`.
static mut CEIL_USED: [bool; MEMO_N] = [false; MEMO_N];
static mut CEIL_X: [u128; MEMO_N] = [0; MEMO_N];
static mut CEIL_B: [u16; MEMO_N] = [0; MEMO_N];
static mut CEIL_V: [u128; MEMO_N] = [0; MEMO_N];
fn bps_ceil_memo(x: u128, bps: u16) -> Option<u128> {
    if bps as u128 > 10_000 {
        return None;
    }
    unsafe {
        let mut i = 0;
        while i < MEMO_N {
            if CEIL_USED[i] && CEIL_X[i] == x && CEIL_B[i] == bps {
                return Some(CEIL_V[i]);
            }
            i += 1;
        }
        let v: u128 = kani::any();
        let mut j = 0;
        while j < MEMO_N {
            if !CEIL_USED[j] {
                CEIL_USED[j] = true;
                CEIL_X[j] = x;
                CEIL_B[j] = bps;
                CEIL_V[j] = v;
                break;
            }
            j += 1;
        }
        Some(v)
    }
}

/// STUB-MEMO for `vault_lp_v18::bps_floor(x, bps)` (same None-condition as production), with the range
/// fact `result <= x` (CONDITIONAL on `kani_v22_bps_floor_range_lemma` below, u64 x; every caller in
/// `kani_v22_wc8a_split_a_waterfall_structure` passes x <= u64::MAX).
static mut FLOOR_USED: [bool; MEMO_N] = [false; MEMO_N];
static mut FLOOR_X: [u128; MEMO_N] = [0; MEMO_N];
static mut FLOOR_B: [u16; MEMO_N] = [0; MEMO_N];
static mut FLOOR_V: [u128; MEMO_N] = [0; MEMO_N];
fn bps_floor_memo(x: u128, bps: u16) -> Option<u128> {
    if bps as u128 > 10_000 {
        return None;
    }
    unsafe {
        let mut i = 0;
        while i < MEMO_N {
            if FLOOR_USED[i] && FLOOR_X[i] == x && FLOOR_B[i] == bps {
                return Some(FLOOR_V[i]);
            }
            i += 1;
        }
        let v: u128 = kani::any();
        kani::assume(v <= x); // range fact, proven by kani_v22_bps_floor_range_lemma
        let mut j = 0;
        while j < MEMO_N {
            if !FLOOR_USED[j] {
                FLOOR_USED[j] = true;
                FLOOR_X[j] = x;
                FLOOR_B[j] = bps;
                FLOOR_V[j] = v;
                break;
            }
            j += 1;
        }
        Some(v)
    }
}

/// STUB-ANY for `growth_v19::n_cap_q` (no contract): any `Option<u128>`.
fn n_cap_q_any(_c_m: u128, _lambda_bps: u32, _price_e6: u64, _pos_scale: u128) -> Option<u128> {
    kani::any()
}

/// STUB-MODEL for `bond_v20::bond_coupon_split`: `kani_v22_wc12_bond_coupon_split` (official run: PASS
/// 2/2, 5291 s, `wt-kani-f1`) proves, for ALL u64 `available`, `due`: `cp + rest == available` and
/// `cp == min(due, available / 2)`. That determines the pair, so on u64 inputs the function IS this model.
fn bond_coupon_split_model(available: u128, due: u128) -> (u128, u128) {
    let cap = available / 2;
    let c = if due < cap { due } else { cap };
    (c, available - c)
}

// ═══════════════════════════════════════ W-C-7 (bond lock vs open OI) ═══════════════════════════════

/// Replaces W-C-7 `kani_v22_wc7_bond_lock_vs_open_oi` (NO-VERDICT 1800 s). STUB-ANY on `n_cap_q`.
/// Composition: both original assertions are universal in the two `n_cap_q` results (`ok` is compared
/// against `n_after >= need` for whatever `n_after` is, and `ok => n_after >= need >= lp` gives the A4
/// lock for ANY `n_before`), so proving them for arbitrary `Option<u128>` results proves them for the
/// real ones. WIDER than the original: OI / LP legs full u128 (original u16); the n_cap_q inputs are
/// irrelevant to the stubbed property (kept at the original types).
#[kani::proof]
#[kani::stub(percolator_prog::growth_v19::n_cap_q, n_cap_q_any)]
fn kani_v22_wc7_split_a_lock_any_capacity() {
    let c_m = kani::any::<u64>() as u128;
    let x = kani::any::<u64>() as u128;
    kani::assume(x <= c_m); // the original's assume (withdrawal within the capital)
    let lambda = kani::any::<u8>() as u32;
    let price = kani::any::<u8>() as u64;
    let ps = kani::any::<u8>() as u128;
    let (oi_l, oi_s, lp): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let n_after = percolator_prog::growth_v19::n_cap_q(c_m - x, lambda, price, ps);
    let ok = bond_withdraw_lock_ok(n_after, oi_l, oi_s, lp);
    let need = if oi_l > oi_s { oi_l } else { oi_s };
    let need = if need > lp { need } else { lp };
    assert_eq!(ok, match n_after { Some(n) => n >= need, None => need == 0 });
    if ok {
        if let (Some(nb), Some(na)) = (percolator_prog::growth_v19::n_cap_q(c_m, lambda, price, ps), n_after) {
            assert!(percolator_prog::vault_lp_v18::a4_capacity_lock_ok(nb, na, lp), "the A4 lock is implied");
        }
    }
    kani::cover!(!ok && lp > 0, "refused by the LP's own leg");
    kani::cover!(!ok && lp == 0 && oi_l > 0, "refused with a FLAT LP: open user OI");
    kani::cover!(ok && need > 0, "admitted below capacity");
    kani::cover!(ok && n_after.is_none() && need == 0, "growth off, nothing open");
}

// ═══════════════════════════════════ W-C-8a (fee waterfall) ══════════════════════════════════════════

/// Replaces W-C-8a `kani_v22_wc8a_fee_waterfall3_conserves_and_orders` (NO-VERDICT 1800 s).
/// STUB-MODEL `bond_coupon_split` (CONDITIONAL on W-C-12 PASS, u64 domain) + STUB-MEMO `bps_floor`,
/// `bps_ceil`. Composition: `fee_waterfall3` is the real composition (coupon split, then the real
/// `cushion_split`); the only arithmetic left symbolic is `bps_floor`/`bps_ceil`, and the original
/// assertions use them only through (i) their None-condition (kept exact) and (ii) "the cushion is at most
/// `bps_floor(avail - cp, share)`", which compares two calls with the SAME arguments (memo-consistent =
/// determinism). WIDER than the original: u64 amounts (original u32).
#[kani::proof]
#[kani::stub(percolator_prog::bond_v20::bond_coupon_split, bond_coupon_split_model)]
#[kani::stub(percolator_prog::vault_lp_v18::bps_floor, bps_floor_memo)]
#[kani::stub(percolator_prog::vault_lp_v18::bps_ceil, bps_ceil_memo)]
fn kani_v22_wc8a_split_a_waterfall_structure() {
    let avail = kani::any::<u64>() as u128;
    let due = kani::any::<u64>() as u128;
    let share: u16 = kani::any();
    let target: u16 = kani::any();
    let c_eff = kani::any::<u64>() as u128;
    let level = kani::any::<u64>() as u128;
    kani::assume(share <= 10_000 && target <= 10_000); // the original's assume (config bounds)
    let r = fee_waterfall3(avail, due, share, target, c_eff, level);
    let (cp, cu, se) = r.unwrap();
    assert_eq!(cp + cu + se, avail, "conservation");
    assert_eq!(cp, min2(due, avail / 2), "coupon = min(due, half the leg)");
    assert!(cu <= bps_floor(avail - cp, share).unwrap(), "cushion only sees the rest");
    if share == 0 || target == 0 {
        assert_eq!(cu, 0);
    }
    kani::cover!(due > 0 && cp == due && cp < avail / 2, "coupon below the leg cap");
    kani::cover!(cp == avail / 2 && due > cp, "leg cap binds (thin leg)");
    kani::cover!(cp > 0 && cu > 0, "cushion engaged after the coupon");
}

/// Lemma for the bps_floor memo stub's range fact: the REAL `bps_floor(x, bps) <= x` and is `Some` for
/// every u64 `x` and `bps <= 10_000` (None exactly when `bps > 10_000`). kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_bps_floor_range_lemma() {
    let x = kani::any::<u64>() as u128;
    let bps: u16 = kani::any();
    let r = bps_floor(x, bps);
    if bps as u128 > 10_000 {
        assert!(r.is_none());
    } else {
        assert!(r.unwrap() <= x);
    }
    kani::cover!(bps == 10_000 && r == Some(x) && x > 0, "full share");
    kani::cover!(bps < 10_000 && r.is_some_and(|v| v < x), "partial share");
}

// ═══════════════════════════════════ W-C-9 (junior gates exclude bonds) ══════════════════════════════

/// Replaces W-C-9 `kani_v22_wc9_junior_gates_exclude_bonds` (NO-VERDICT 8002 s). STUB-MEMO `bps_ceil`
/// (the only division; `junior_floor_atoms` = `bps_ceil`). Composition: every original assertion uses the
/// floor / the L-3 minimum only as "some value >= 0, the same in the 3-tranche and 2-tranche gate for the
/// same `(C, bps)`" — exactly what the memo stub provides. Same u64 domain as the original.
#[kani::proof]
#[kani::stub(percolator_prog::vault_lp_v18::bps_ceil, bps_ceil_memo)]
fn kani_v22_wc9_split_a_gates_any_floor() {
    let (v, c, cb, cover, amt) = (
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
    );
    let floor: u16 = kani::any();
    let ok3 = junior_withdraw_allowed3(v, c, cb, cover, amt, floor);
    if ok3 {
        let a = tranche_split3(v, c, cb);
        let b = tranche_split3(v - amt, c, cb);
        assert!(b.bond == a.bond && b.senior == a.senior, "a junior withdrawal never reaches bond or senior value");
    }
    if cb == 0 {
        assert_eq!(ok3, junior_withdraw_allowed(v, c, cover, amt, floor));
    }
    let al3 = alloc_junior_ok3(v, c, cb);
    if al3 {
        assert!(alloc_junior_ok(v, c), "tighten-only");
    }
    if cb == 0 {
        assert_eq!(al3, alloc_junior_ok(v, c));
    }
    assert_eq!(resolved_junior_surplus3(v, c, cb) + resolved_bond_value(v, c, cb), v.saturating_sub(c));
    kani::cover!(ok3 && cb > 0 && amt > 0, "admitted with bonds present");
    kani::cover!(!ok3 && junior_withdraw_allowed3(v, c, 0, cover, amt, floor), "refused only because of bonds");
}

// ═══════════════════════════════════ W-C-8b (coupon due / gate / base) ═══════════════════════════════

/// W-C-8b split (a): gate and base, no arithmetic beyond compare/min. Same domains as the original.
#[kani::proof]
fn kani_v22_wc8b_split_a_gate_and_base() {
    let (cb, bv) = (kani::any::<u32>() as u128, kani::any::<u32>() as u128);
    let base = coupon_base(cb, bv);
    assert_eq!(base, min2(cb, bv), "base = min(C_b, bond value)");
    let live: bool = kani::any();
    let o = kani::any::<u32>() as u128;
    let g = coupon_gate_open(live, cb, o, bv);
    assert_eq!(g, live && cb > 0 && o == 0 && bv >= cb);
    if bv < cb {
        assert!(!g, "an impaired tranche earns nothing");
    }
    if g {
        assert_eq!(base, cb, "an open gate accrues on the whole claim");
    }
    kani::cover!(g, "gate open");
    kani::cover!(live && cb > 0 && bv >= cb && o > 0 && !g, "gate closed by a senior draw");
    kani::cover!(live && cb > 0 && o == 0 && bv < cb && !g, "gate closed by impairment");
}

/// W-C-8b split (b): `coupon_due` never pays more than one year, on the REAL `coupon_due` /
/// `mul_div_floor`. BOUNDED like the original: base u32 (any u32 covers every `coupon_base(cb, bv)` with
/// u32 cb, bv), rate <= 3_000, dt full u64. kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc8b_split_b_due_at_most_one_year() {
    let base = kani::any::<u32>() as u128;
    let rate = kani::any::<u16>() as u32;
    kani::assume(rate <= 3_000); // BOND_COUPON_MAX_BPS-scale domain of the original
    let dt: u64 = kani::any();
    let due = coupon_due(base, rate, dt).unwrap();
    assert!(due * 10_000 <= base * rate as u128, "never more than one year of coupon");
    kani::cover!((dt as u128) > SLOTS_PER_YEAR && due > 0, "one-year clamp");
    kani::cover!((dt as u128) < SLOTS_PER_YEAR && due > 0, "partial year");
}

/// W-C-8b split (c): the interval is clamped to one year: `coupon_due(b, r, dt) == coupon_due(b, r,
/// min(dt, 1y))`. For `dt <= 1y` the two calls are the same call (reflexivity of a pure function); this
/// harness proves the `dt > 1y` branch. Same domain as the original. kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc8b_split_c_clamp() {
    let base = kani::any::<u32>() as u128;
    let rate = kani::any::<u16>() as u32;
    kani::assume(rate <= 3_000);
    let dt: u64 = kani::any();
    kani::assume((dt as u128) > SLOTS_PER_YEAR); // the only non-trivial branch (see doc)
    let dtc = if (dt as u128) > SLOTS_PER_YEAR { SLOTS_PER_YEAR as u64 } else { dt };
    let due = coupon_due(base, rate, dt);
    assert_eq!(coupon_due(base, rate, dtc), due, "the interval is clamped to one year");
    kani::cover!(due.is_some_and(|d| d > 0), "non-zero clamped coupon");
}

// ═══════════════════════════════════ W-C-5 (bond deposit) ════════════════════════════════════════════

/// W-C-5 split (a): FLOOR facts of the real `bond_shares_for_deposit` (real `mul_div_floor`), branch
/// structure exact. BOUNDED exactly as the original: amount u16, shares and value u8. kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc5_split_a_deposit_floor() {
    let amount = kani::any::<u16>() as u128;
    let b = kani::any::<u8>() as u128;
    let value = kani::any::<u8>() as u128;
    kani::assume(amount > 0); // the original's assume
    let m = bond_shares_for_deposit(amount, b, value);
    if b == 0 {
        assert_eq!(m, Some(amount), "genesis 1:1");
    } else if value == 0 {
        assert!(m.is_none(), "zero value with shares outstanding fails closed");
    } else {
        let m = m.unwrap();
        assert!(m * value <= amount * b, "rounds down");
        assert!(amount * b < m * value + value, "exact floor");
        kani::cover!((amount * b) % value == 0 && m > 0, "exact");
        kani::cover!((amount * b) % value != 0, "floored");
    }
    kani::cover!(b == 0, "genesis");
}

/// W-C-5 split (b): ALGEBRA. For every m with `m * value <= amount * b` (split (a)), incumbents are not
/// diluted: `(value + amount) * b >= value * (b + m)`. Fresh symbols at the original widths (m <= 2^24 is
/// implied by the hypothesis). kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc5_split_b_no_dilution_algebra() {
    let amount = kani::any::<u16>() as u64;
    let b = kani::any::<u8>() as u64;
    let value = kani::any::<u8>() as u64;
    let m = kani::any::<u32>() as u64;
    kani::assume(amount > 0 && b > 0 && value > 0); // the branch split (a) leaves to this lemma
    kani::assume(m * value <= amount * b); // split (a)'s floor fact
    assert!((value + amount) * b >= value * (b + m), "incumbents not diluted");
    kani::cover!(m * value == amount * b && m > 0, "exact");
    kani::cover!(m * value < amount * b && m > 0, "floored");
}

// ═══════════════════════════════════ W-C-6 (bond redemption) ═════════════════════════════════════════

/// W-C-6 split (a): FLOOR facts of the real `bond_atoms_for_redemption` / `bond_claim_after_redemption`
/// (real `mul_div_floor`). BOUNDED as the original: all u8. kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc6_split_a_redemption_floor() {
    let (b, sh, cb, value) = (
        kani::any::<u8>() as u128,
        kani::any::<u8>() as u128,
        kani::any::<u8>() as u128,
        kani::any::<u8>() as u128,
    );
    kani::assume(b > 0 && value <= cb); // the original's assume
    let pay = bond_atoms_for_redemption(sh, b, value);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if sh > b {
        assert!(pay.is_none() && cb2.is_none());
    } else {
        let (pay, cb2) = (pay.unwrap(), cb2.unwrap());
        assert!(cb2 <= cb);
        let slice = cb - cb2;
        assert!(pay * b <= sh * value && sh * value < pay * b + b, "payout = floor(sh * value / B)");
        assert!(slice * b <= sh * cb && sh * cb < slice * b + b, "slice = floor(sh * C_b / B)");
        kani::cover!(sh < b && value == cb && cb > 0 && sh > 0, "whole tranche");
        kani::cover!(sh < b && value < cb && sh > 0, "impaired tranche");
        kani::cover!(sh == b && cb > 0, "full redemption");
    }
    kani::cover!(sh > b, "over-redemption refused");
}

/// W-C-6 split (b): ALGEBRA. From the exact floor facts of split (a), the original W-C-6 claims. Fresh
/// u8 symbols (pay, slice <= 255 follow from the facts). kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_v22_wc6_split_b_redemption_algebra() {
    let (b, sh, cb, value) = (
        kani::any::<u8>() as u64,
        kani::any::<u8>() as u64,
        kani::any::<u8>() as u64,
        kani::any::<u8>() as u64,
    );
    let pay = kani::any::<u16>() as u64;
    let slice = kani::any::<u16>() as u64;
    kani::assume(b > 0 && value <= cb && sh <= b); // original assume + the branch split (a) leaves here
    kani::assume(pay * b <= sh * value && sh * value < pay * b + b); // split (a), payout floor
    kani::assume(slice * b <= sh * cb && sh * cb < slice * b + b); // split (a), slice floor
    kani::assume(slice <= cb); // split (a): cb2 = cb - slice is Some
    let cb2 = cb - slice;
    assert!(pay <= value && pay * b <= sh * value);
    if sh == b {
        assert_eq!(cb2, 0, "full redemption clears C_b");
    } else {
        assert!(cb2 * b >= cb * (b - sh), "remaining claim per share not lowered");
        assert!((value - pay) * b >= value * (b - sh), "remaining value per share not lowered");
        if cb > 0 {
            assert!(cb2 > 0, "C_b == 0 <=> B == 0 preserved");
        }
    }
    kani::cover!(sh < b && value == cb && cb > 0 && sh > 0, "whole tranche");
    kani::cover!(sh < b && value < cb && sh > 0, "impaired tranche");
    kani::cover!(sh == b && cb > 0, "full redemption");
}

// ═══════════════════════════════════ W-D-1 / W-D-2 (rescue) ══════════════════════════════════════════

/// W-D-1 split (a) at width `$t`: FLOOR facts of the real `rescue_shares` / `rescue_claim_delta` under the
/// original's impaired-shape assumptions. Split (b): ALGEBRA, the REAL predicates
/// `rescue_value_no_dilution` / `rescue_claim_no_dilution` hold for every (m, dc) satisfying the facts.
macro_rules! wd1_pair {
    ($a:ident, $b:ident, $t:ty) => {
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $a() {
            let v = kani::any::<$t>() as u128;
            let c = kani::any::<$t>() as u128;
            let s = kani::any::<$t>() as u128;
            let x = kani::any::<$t>() as u128;
            // the original's impaired shape (what `rescue_admitted` implies; W-D-3 proves that bridge)
            kani::assume(v > 0 && s > 0 && v < c && x > 0 && x <= 10 * v);
            let m = p4::rescue_shares(x, s, v).unwrap();
            let dc = p4::rescue_claim_delta(m, c, s).unwrap();
            assert!(m * v <= x * s && x * s < m * v + v, "m = floor(x * S / v)");
            assert!(dc * s <= m * c && m * c < dc * s + s, "dc = floor(m * C / S)");
            kani::cover!(m * c > x * s, "strictly cheaper than par");
            kani::cover!(m > 0, "shares minted");
        }

        #[kani::proof]
        #[kani::solver(kissat)]
        fn $b() {
            let v = kani::any::<$t>() as u128;
            let c = kani::any::<$t>() as u128;
            let s = kani::any::<$t>() as u128;
            let x = kani::any::<$t>() as u128;
            let m = kani::any::<u64>() as u128;
            let dc = kani::any::<u64>() as u128;
            kani::assume(v > 0 && s > 0 && v < c && x > 0 && x <= 10 * v); // same shape as split (a)
            kani::assume(m * v <= x * s && x * s < m * v + v); // split (a) fact for m
            kani::assume(dc * s <= m * c && m * c < dc * s + s); // split (a) fact for dc
            assert!(p4::rescue_value_no_dilution(v, x, s, m));
            assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
            kani::cover!(m * c > x * s, "strictly cheaper than par");
            kani::cover!(m > 0 && dc > 0, "shares minted, claim grows");
        }
    };
}
wd1_pair!(kani_v22_wd1_split_a_floor_u16, kani_v22_wd1_split_b_algebra_u16, u16);
wd1_pair!(kani_v22_wd1_split_a_floor_u8, kani_v22_wd1_split_b_algebra_u8, u8);

/// W-D-2 split (a) at width `$t`: FLOOR facts of the real `rescue_claim_delta`. Split (b): ALGEBRA, the
/// REAL predicate `rescue_par_per_share_not_raised` and the one-atom bound hold for every dc satisfying
/// the facts.
macro_rules! wd2_pair {
    ($a:ident, $b:ident, $t:ty, $w:ty) => {
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $a() {
            let c = kani::any::<$t>() as u128;
            let s = kani::any::<$t>() as u128;
            let m = kani::any::<$t>() as u128;
            kani::assume(s > 0); // the original's assume
            let dc = p4::rescue_claim_delta(m, c, s).unwrap();
            assert!(dc * s <= m * c && m * c < dc * s + s, "dc = floor(m * C / S)");
            kani::cover!(dc > 0, "claim grows");
            kani::cover!(dc > 0 && (m * c) % s != 0, "floored");
        }

        #[kani::proof]
        #[kani::solver(kissat)]
        fn $b() {
            let c = kani::any::<$t>() as u128;
            let s = kani::any::<$t>() as u128;
            let m = kani::any::<$t>() as u128;
            let dc = kani::any::<$w>() as u128;
            kani::assume(s > 0);
            kani::assume(dc * s <= m * c && m * c < dc * s + s); // split (a) fact
            assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
            assert!((c + dc) * s + s > c * (s + m));
            kani::cover!(dc > 0, "claim grows");
            kani::cover!(dc > 0 && (m * c) % s != 0, "floored");
        }
    };
}
wd2_pair!(kani_v22_wd2_split_a_floor_u32, kani_v22_wd2_split_b_algebra_u32, u32, u64);
wd2_pair!(kani_v22_wd2_split_a_floor_u16, kani_v22_wd2_split_b_algebra_u16, u16, u32);
wd2_pair!(kani_v22_wd2_split_a_floor_u8, kani_v22_wd2_split_b_algebra_u8, u8, u16);

// ═══════════════════════════════════ R6 tag 93 wire round trip ═══════════════════════════════════════

/// The spec layout of the tag-93 V19 body: `[93, ai u16, band u16, k u32, floor u128, oi u128, ext u8,
/// maxfee u16, lambda u32, kink u16, (util u16 if != 0)]`, little-endian; length 50 or 52. Built in a
/// STACK array (fixed size 52 <= CBMC's field-sensitivity limit), so the tag byte is a constant in symex.
#[derive(Clone, Copy)]
struct T93 {
    ai: u16,
    band: u16,
    k: u32,
    floor: u128,
    oi: u128,
    ext: u8,
    maxfee: u16,
    lambda: u32,
    kink: u16,
    util: u16,
}

fn any_t93() -> T93 {
    T93 {
        ai: kani::any(),
        band: kani::any(),
        k: kani::any(),
        floor: kani::any(),
        oi: kani::any(),
        ext: kani::any(),
        maxfee: kani::any(),
        lambda: kani::any(),
        kink: kani::any(),
        util: kani::any(),
    }
}

fn put<const N: usize>(buf: &mut [u8; 52], off: usize, b: [u8; N]) {
    let mut i = 0;
    while i < N {
        buf[off + i] = b[i];
        i += 1;
    }
}

fn spec93(f: &T93) -> ([u8; 52], usize) {
    let mut buf = [0u8; 52];
    buf[0] = 93;
    put(&mut buf, 1, f.ai.to_le_bytes());
    put(&mut buf, 3, f.band.to_le_bytes());
    put(&mut buf, 5, f.k.to_le_bytes());
    put(&mut buf, 9, f.floor.to_le_bytes());
    put(&mut buf, 25, f.oi.to_le_bytes());
    buf[41] = f.ext;
    put(&mut buf, 42, f.maxfee.to_le_bytes());
    put(&mut buf, 44, f.lambda.to_le_bytes());
    put(&mut buf, 48, f.kink.to_le_bytes());
    put(&mut buf, 50, f.util.to_le_bytes());
    (buf, if f.util == 0 { 50 } else { 52 })
}

fn limits93(f: &T93) -> Instruction {
    Instruction::SetAssetRiskLimits {
        asset_index: f.ai,
        exec_band_bps: f.band,
        lp_exposure_k_bps: f.k,
        lp_floor_atoms: f.floor,
        side_oi_cap_q: f.oi,
        matcher_ext_mode: f.ext,
        max_requested_fee_bps: f.maxfee,
    }
}

fn ix93(f: &T93) -> Instruction {
    Instruction::SetAssetRiskLimitsV19 {
        limits: Box::new(limits93(f)),
        growth_lambda_bps: f.lambda,
        growth_kink_bps: f.kink,
        growth_util_fee_max_bps: f.util,
    }
}

/// Field-by-field equality of a decoded instruction with the V19 tag-93 spec fields. Equivalent to
/// `*d == ix93(f)` (derived PartialEq compares the variant then every field; the Box by its contents), but
/// written as a match on the EXPECTED variant so symex does not instantiate the derived `==` for every
/// other variant (their Vec fields made the first b1 run unwind memcmp without end).
fn is_ix93(d: &Instruction, f: &T93) -> bool {
    match d {
        Instruction::SetAssetRiskLimitsV19 { limits, growth_lambda_bps, growth_kink_bps, growth_util_fee_max_bps } => {
            *growth_lambda_bps == f.lambda
                && *growth_kink_bps == f.kink
                && *growth_util_fee_max_bps == f.util
                && is_limits93(limits, f)
        }
        _ => false,
    }
}

fn is_limits93(d: &Instruction, f: &T93) -> bool {
    match d {
        Instruction::SetAssetRiskLimits {
            asset_index,
            exec_band_bps,
            lp_exposure_k_bps,
            lp_floor_atoms,
            side_oi_cap_q,
            matcher_ext_mode,
            max_requested_fee_bps,
        } => {
            *asset_index == f.ai
                && *exec_band_bps == f.band
                && *lp_exposure_k_bps == f.k
                && *lp_floor_atoms == f.floor
                && *side_oi_cap_q == f.oi
                && *matcher_ext_mode == f.ext
                && *max_requested_fee_bps == f.maxfee
        }
        _ => false,
    }
}

/// R6 tag 93 split (a), ENCODE: `ix.encode()` is byte-for-byte the spec layout (length 50 / 52).
/// Replaces the encode half of `kani_growth_r6_tag93_v19_roundtrip` (NO-VERDICT-OOM 1670 s).
#[kani::proof]
#[kani::unwind(56)]
fn kani_growth_r6_tag93_split_a_encode_is_spec() {
    let f = any_t93();
    let ix = ix93(&f);
    let b = ix.encode();
    let (sp, len) = spec93(&f);
    assert_eq!(b.len(), len);
    let mut i = 0;
    while i < len {
        assert_eq!(b[i], sp[i]);
        i += 1;
    }
    kani::cover!(f.util == 0, "6-byte form");
    kani::cover!(f.util != 0, "8-byte form");
    core::mem::forget(ix);
    core::mem::forget(b);
}

/// R6 tag 93 split (b), DECODE, one harness per trailer form so the slice length is a LITERAL (a symbolic
/// length kept every `read_bytes32` loop of the other tags alive in symex: the 10-04 OOM / the first run of
/// this split, NO-VERDICT 900 s). The spec bytes decode to the instruction. With split (a) (`encode(ix)`
/// equals these bytes, length 50 iff util == 0) and decode being a pure function of the byte content:
/// `decode(encode(ix)) == ix`. (b0) + (b1) exhaust util == 0 / util != 0.
#[kani::proof]
#[kani::unwind(56)]
fn kani_growth_r6_tag93_split_b0_decode_spec_6byte() {
    let mut f = any_t93();
    f.util = 0; // the 6-byte trailer form (b1 covers util != 0)
    let (sp, _len) = spec93(&f);
    let d = Instruction::decode(&sp[..50]);
    assert!(d.as_ref().is_ok_and(|x| is_ix93(x, &f)));
    kani::cover!(f.lambda != 0 && f.kink != 0, "6-byte form, non-zero dials");
    core::mem::forget(d);
}

#[kani::proof]
#[kani::unwind(56)]
fn kani_growth_r6_tag93_split_b1_decode_spec_8byte() {
    let f = any_t93();
    kani::assume(f.util != 0); // the 8-byte trailer form (b0 covers util == 0)
    let (sp, _len) = spec93(&f);
    let d = Instruction::decode(&sp[..52]);
    assert!(d.as_ref().is_ok_and(|x| is_ix93(x, &f)));
    kani::cover!(f.util == u16::MAX, "8-byte form, max util");
    core::mem::forget(d);
}

/// R6 tag 93 split (c), LEGACY PREFIX: the first 44 spec bytes (= the first 44 bytes of `encode(ix)` by
/// split (a)) decode as the legacy `SetAssetRiskLimits` carrying the same limits.
#[kani::proof]
#[kani::unwind(56)]
fn kani_growth_r6_tag93_split_c_legacy_prefix() {
    let f = any_t93();
    let (sp, _len) = spec93(&f);
    let lim = limits93(&f);
    let d2 = Instruction::decode(&sp[..44]);
    assert!(d2.as_ref().is_ok_and(|x| *x == lim));
    kani::cover!(f.ext != 0 || f.maxfee != 0, "non-zero legacy trailer");
    core::mem::forget(d2);
    core::mem::forget(lim);
}

/// R6 tag 93 split (d), ZERO-UTIL 8-BYTE TRAILER REFUSED: the 52-byte spec form with the util bytes zeroed
/// (= `encode(ix)` with `z[50] = z[51] = 0` when util != 0, by split (a)) refuses.
#[kani::proof]
#[kani::unwind(56)]
fn kani_growth_r6_tag93_split_d_zero_util_refused() {
    let f = any_t93();
    kani::assume(f.util != 0); // the original's `if util != 0` branch
    let (mut z, _len) = spec93(&f);
    z[50] = 0;
    z[51] = 0;
    let d3 = Instruction::decode(&z[..52]);
    assert!(d3.is_err());
    kani::cover!(true, "zero-util 8-byte form reached");
    core::mem::forget(d3);
}

// ═══════════════════════════════════ NEGATIVE CONTROLS (expected FAIL) ═══════════════════════════════
// Each mutates ONE relation of a replacement harness above to show it can fail. Run once each; results in
// ~/wt-v22-kani2/reports/wrapper.md. Not release-gate harnesses.

/// NC for W-C-9 split (a): the BOND-BLIND two-tranche gate (the BOND-MP5 bug class: the junior gate
/// ignores bonds) must violate "a junior withdrawal never reaches bond value". Expected: FAIL.
#[kani::proof]
#[kani::stub(percolator_prog::vault_lp_v18::bps_ceil, bps_ceil_memo)]
fn negctrl_wc9_bond_blind_gate() {
    let (v, c, cb, cover, amt) = (
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
    );
    let floor: u16 = kani::any();
    let ok = junior_withdraw_allowed(v, c, cover, amt, floor); // MUTANT: bond-blind
    if ok {
        let a = tranche_split3(v, c, cb);
        let b = tranche_split3(v - amt, c, cb);
        assert!(b.bond == a.bond && b.senior == a.senior);
    }
}

/// NC for W-C-8a split (a): coupon model WITHOUT the 50% leg cap (BOND-MP8 class). Expected: FAIL.
fn bond_coupon_split_nocap(available: u128, due: u128) -> (u128, u128) {
    let c = if due < available { due } else { available };
    (c, available - c)
}
#[kani::proof]
#[kani::stub(percolator_prog::bond_v20::bond_coupon_split, bond_coupon_split_nocap)]
#[kani::stub(percolator_prog::vault_lp_v18::bps_floor, bps_floor_memo)]
#[kani::stub(percolator_prog::vault_lp_v18::bps_ceil, bps_ceil_memo)]
fn negctrl_wc8a_no_leg_cap() {
    let avail = kani::any::<u64>() as u128;
    let due = kani::any::<u64>() as u128;
    let share: u16 = kani::any();
    let target: u16 = kani::any();
    kani::assume(share <= 10_000 && target <= 10_000);
    let (cp, _cu, _se) = fee_waterfall3(avail, due, share, target, kani::any::<u64>() as u128, kani::any::<u64>() as u128).unwrap();
    assert_eq!(cp, min2(due, avail / 2));
}

/// NC for R6 tag 93 split (a): a spec with lambda and kink swapped must not match encode. Expected: FAIL.
#[kani::proof]
#[kani::unwind(56)]
fn negctrl_tag93_swapped_layout() {
    let f = any_t93();
    let ix = ix93(&f);
    let b = ix.encode();
    let (mut sp, len) = spec93(&f);
    put(&mut sp, 44, [f.kink.to_le_bytes()[0], f.kink.to_le_bytes()[1], 0, 0]); // MUTANT: kink at 44
    let l = f.lambda.to_le_bytes();
    put(&mut sp, 48, [l[0], l[1]]);
    let mut i = 0;
    while i < len {
        assert_eq!(b[i], sp[i]);
        i += 1;
    }
    core::mem::forget(ix);
    core::mem::forget(b);
}

/// NC for W-C-5 split (b): a CEIL-rounded mint (`m * value < amount * b + value`, i.e. rounded up allowed)
/// must dilute incumbents somewhere. Expected: FAIL.
#[kani::proof]
#[kani::solver(kissat)]
fn negctrl_wc5_ceil_mint_dilutes() {
    let amount = kani::any::<u16>() as u64;
    let b = kani::any::<u8>() as u64;
    let value = kani::any::<u8>() as u64;
    let m = kani::any::<u32>() as u64;
    kani::assume(amount > 0 && b > 0 && value > 0);
    kani::assume(m * value < amount * b + value); // MUTANT: ceil instead of floor
    assert!((value + amount) * b >= value * (b + m));
}
