//! Kani design 2026-09-30 (Sentinel) — P3, production `src/vault_lp_v18.rs` (path-included).
//! Design doc: ~/percolator-ops/ledger/kani-proof-design-2026-09-30.md; revisions per the
//! hermetic review ~/percolator-ops/ledger/kani-design-review-2026-09-30.md (§10 of the doc).
//!
//! Method: linear properties at FULL width; share wiring through ARGUMENT-CAPTURE stubs of
//! `mul_div_floor` (no multiplier in the harness or the stub: the stub records its operands and
//! returns a fresh value; floor semantics are L-DIV, i.e. the definition of `/`); small-width
//! regressions (suffix `s`) only where they catch rounding mutants cheaply. No 128-bit
//! division lemma is attempted (review: definitional, cannot converge).
//! Run: cargo kani -Z stubbing --exact --harness proofs::<name>

use crate::vault_lp_v18::*;

// ── argument-capture stub for mul_div_floor ────────────────────────────────────────────────
static mut CAP_CALLS: u8 = 0;
static mut CAP_A: u128 = 0;
static mut CAP_B: u128 = 0;
static mut CAP_D: u128 = 0;
static mut CAP_RET: Option<u128> = None;

/// Records the FIRST call's operands and its (fresh, arbitrary) return; forces None iff d == 0
/// (the only arm of the real body that is not the definition of `/`). No arithmetic claim.
fn capture_mul_div_floor(a: u128, b: u128, d: u128) -> Option<u128> {
    let r: Option<u128> = if d == 0 { None } else { kani::any() };
    unsafe {
        if CAP_CALLS == 0 {
            CAP_A = a;
            CAP_B = b;
            CAP_D = d;
            CAP_RET = r;
        }
        CAP_CALLS = CAP_CALLS.saturating_add(1);
    }
    r
}
fn cap() -> (u8, u128, u128, u128, Option<u128>) {
    unsafe { (CAP_CALLS, CAP_A, CAP_B, CAP_D, CAP_RET) }
}
fn cap_reset() {
    unsafe {
        CAP_CALLS = 0;
        CAP_RET = None;
    }
}

static mut FLOOR_STUB: Option<u128> = None;
/// Deterministic arbitrary junior floor (fixed per run; the rule and the assertion see it).
fn stub_junior_floor_atoms(_c: u128, _bps: u16) -> Option<u128> {
    unsafe { FLOOR_STUB }
}

// ── D-P3-00s  mul_div_floor small-width regression (u8 operands): Some(q) with
// q*d <= a*b < q*d + d, None iff d == 0. Catches ceil / +1 mutants. Full width is L-DIV.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_00s_mul_div_floor_u8() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let d: u8 = kani::any();
    let r = mul_div_floor(a as u128, b as u128, d as u128);
    if d == 0 {
        assert!(r.is_none());
        return;
    }
    let p = a as u128 * b as u128;
    let q = r.unwrap();
    let dd = d as u128;
    let qd = q * dd;
    assert!(qd <= p && p - qd < dd);
    kani::cover!(q > 0 && p % d as u128 != 0, "non-exact floor");
}

// ── D-P3-01  Waterfall, full u128: static split + LOSS and GAIN transitions + senior deposit
// neutrality for the junior.
#[kani::proof]
fn kani_design_p3_01_waterfall_transitions_full_width() {
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let s = tranche_split(v, c);
    assert_eq!(s.senior + s.junior, v);
    assert_eq!(s.senior, v.min(c));
    assert_eq!(senior_impaired(v, c), v < c);
    let l: u128 = kani::any();
    kani::assume(l <= v);
    let a = tranche_split(v - l, c);
    assert_eq!(s.junior - a.junior, l.min(s.junior), "junior loses min(L, junior)");
    assert_eq!(s.senior - a.senior, l - l.min(s.junior), "senior loses only the excess");
    let g: u128 = kani::any();
    kani::assume(v.checked_add(g).is_some());
    let up = tranche_split(v + g, c);
    assert_eq!(up.senior - s.senior, g.min(c - s.senior), "senior restored first");
    assert_eq!(up.junior - s.junior, g - g.min(c - s.senior));
    let amt: u128 = kani::any();
    kani::assume(v.checked_add(amt).is_some() && c.checked_add(amt).is_some());
    let dep = tranche_split(v + amt, c + amt);
    assert_eq!(dep.junior, s.junior);
    kani::cover!(l > 0 && s.junior > 0 && l > s.junior, "loss spills from junior into senior");
    kani::cover!(l > 0 && l < s.junior, "loss fully absorbed by the junior");
    kani::cover!(g > 0 && v < c && v + g > c, "gain restores the senior then pays the junior");
    kani::cover!(v < c && amt > 0, "deposit into an impaired vault");
}

// ── D-P3-03  Conservative (IM-lane) equity, full width; fails closed ONLY when capital exceeds
// i128 or the negative terms overflow.
#[kani::proof]
fn kani_design_p3_03_conservative_equity_full_width() {
    let cap_: u128 = kani::any();
    let pnl: i128 = kani::any();
    let fee: i128 = kani::any();
    let r = conservative_equity(cap_, pnl, fee);
    if cap_ > i128::MAX as u128 {
        assert!(r.is_none());
        return;
    }
    let neg = pnl.min(0).checked_add(fee.min(0));
    match (neg, r) {
        (Some(nn), Some(e)) => {
            let raw = (cap_ as i128) + nn; // cap >= 0, nn <= 0: cannot overflow
            assert_eq!(e, if raw <= 0 { 0 } else { raw as u128 });
            assert!(e <= cap_, "never above capital");
        }
        (Some(_), None) => panic!("spurious fail-closed: cap + pnl- + fee- cannot overflow here"),
        (None, Some(e)) => assert!(e <= cap_),
        (None, None) => {}
    }
    kani::cover!(matches!(r, Some(e) if e == cap_ && pnl > 0 && fee > 0), "positive pnl and credit not counted");
    kani::cover!(matches!(r, Some(0)) && cap_ > 0, "wiped");
    kani::cover!(r.is_none() && cap_ <= i128::MAX as u128, "overflow of the negative terms fails closed");
}

// ── D-P3-04  Junior withdraw (tag 97 Live), full u128, for ANY floor value (stubbed
// deterministically). Tag 97 refuses amount == 0 before this predicate
// (`v16_program.rs:26921`, LpVaultZeroAmount), hence the assume. Also recall (tag 98):
// `recall_limit` is exactly the senior shortfall.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::junior_floor_atoms, stub_junior_floor_atoms)]
fn kani_design_p3_04_junior_withdraw_and_recall_full_width() {
    let fl: Option<u128> = kani::any();
    unsafe { FLOOR_STUB = fl };
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let cover: u128 = kani::any();
    let amount: u128 = kani::any();
    let bps: u16 = kani::any();
    let ok = junior_withdraw_allowed(v, c, cover, amount, bps);
    if ok {
        let f = fl.unwrap();
        assert!(cover >= c);
        let post = tranche_split(v - amount, c);
        // glue-free: the senior's share is untouched for every amount (incl. 0)
        assert_eq!(post.senior, tranche_split(v, c).senior, "senior share unchanged by the junior leaving");
        assert!(post.junior >= f, "junior floor kept");
        if amount > 0 {
            assert_eq!(post.senior, c, "senior whole after a real withdrawal");
        }
    }
    if fl.is_none() || cover < c {
        assert!(!ok);
    }
    kani::cover!(ok && amount > 0 && c > 0 && fl.unwrap() > 0, "allowed with seniors and a floor");
    kani::cover!(!ok && cover >= c && fl.is_some() && v > c, "refused by the floor");
    kani::cover!(!ok && cover < c, "refused: senior not backed");
    // recall (98): exactly the shortfall, zero when fully backed
    assert_eq!(recall_limit(c, cover), c.saturating_sub(cover));
    kani::cover!(recall_limit(c, cover) > 0, "recall shortfall");
}

// ── D-P3-05  Deposit share wiring, full u128, capture stub: genesis mints 1:1; zero senior value
// refuses; otherwise exactly ONE call mul_div_floor(amount, S, senior_value) (operands as a set
// for the product, the divisor exact) and its result is returned unchanged.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, capture_mul_div_floor)]
fn kani_design_p3_05_deposit_shares_wiring() {
    cap_reset();
    let amount: u128 = kani::any();
    let s: u128 = kani::any();
    let senior: u128 = kani::any();
    let r = senior_shares_for_deposit(amount, s, senior);
    let (calls, a, b, d, ret) = cap();
    if s == 0 {
        assert_eq!(r, Some(amount), "genesis 1:1");
        assert_eq!(calls, 0);
        return;
    }
    if senior == 0 {
        assert!(r.is_none(), "zero senior value refuses");
        return;
    }
    assert_eq!(calls, 1);
    assert!((a == amount && b == s) || (a == s && b == amount), "product operands");
    assert_eq!(d, senior, "divided by the senior value");
    assert_eq!(r, ret, "result returned unchanged");
    kani::cover!(matches!(r, Some(m) if m > 0), "non-genesis mint");
}

// ── D-P3-06  Redemption wiring, full u128, capture stub: bad inputs refused without a call;
// payout = mul_div_floor(shares, V_s, S) exactly; removed claim = mul_div_floor(shares, C, S)
// exactly and subtracted from C (underflow impossible is L-SLICE, paper); principal portion
// never exceeds the payout.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, capture_mul_div_floor)]
fn kani_design_p3_06_redemption_wiring() {
    let shares: u128 = kani::any();
    let s: u128 = kani::any();
    let sv: u128 = kani::any();
    let c: u128 = kani::any();
    let bad = s == 0 || shares > s;
    cap_reset();
    let pay = senior_atoms_for_redemption(shares, s, sv);
    let (calls, a, b, d, ret) = cap();
    if bad {
        assert!(pay.is_none() && calls == 0, "bad input refused before any division");
    } else {
        assert_eq!(calls, 1);
        assert!((a == shares && b == sv) || (a == sv && b == shares));
        assert_eq!(d, s);
        assert_eq!(pay, ret);
        assert_eq!(pay.is_none(), ret.is_none());
    }
    cap_reset();
    let after = senior_claim_after_redemption(c, shares, s);
    let (calls2, a2, b2, d2, ret2) = cap();
    if bad {
        assert!(after.is_none() && calls2 == 0);
    } else {
        assert_eq!(calls2, 1);
        assert!((a2 == shares && b2 == c) || (a2 == c && b2 == shares));
        assert_eq!(d2, s);
        match ret2 {
            Some(sl) if sl <= c => assert_eq!(after, Some(c - sl)),
            _ => assert!(after.is_none(), "an impossible slice fails closed, never wraps"),
        }
    }
    let avail: u128 = kani::any();
    if let Some(p) = pay {
        if let Some(pp) = senior_principal_portion(shares, avail, s, p) {
            assert!(pp <= p);
        }
    }
    kani::cover!(!bad && matches!(pay, Some(p) if p > 0), "redemption priced");
    kani::cover!(bad, "bad input");
}

// ── D-P3-07  Skew funding rate, full width: crowded side pays, zero when disabled/balanced,
// |rate| <= max. (|rate| <= slope and monotonicity: L-SKEW, paper.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_07_skew_rate_sign_and_cap_full_width() {
    let lp: i128 = kani::any();
    let oi: u128 = kani::any();
    let slope: u64 = kani::any();
    let max: u64 = kani::any();
    let r = skew_funding_rate_e9(lp, oi, slope, max);
    assert!(r.unsigned_abs() <= max as u128);
    if lp < 0 {
        assert!(r >= 0, "vault LP short => longs pay");
    }
    if lp > 0 {
        assert!(r <= 0, "vault LP long => shorts pay");
    }
    if lp == 0 || oi == 0 || slope == 0 || max == 0 {
        assert_eq!(r, 0);
    }
    kani::cover!(lp < 0 && r > 0, "longs pay");
    kani::cover!(lp > 0 && r < 0, "shorts pay");
    kani::cover!(r.unsigned_abs() == max as u128 && max > 0, "capped");
}

// ── D-P3-08  Combined rate handed to the engine is always inside +-max_abs.
#[kani::proof]
fn kani_design_p3_08_combined_rate_within_engine_bound() {
    let p: i128 = kani::any();
    let s: i128 = kani::any();
    let m: u64 = kani::any();
    let r = combine_funding_rate_e9(p, s, m);
    assert!(r.unsigned_abs() <= m as u128);
    if let Some(sum) = p.checked_add(s) {
        if sum.unsigned_abs() <= m as u128 {
            assert_eq!(r, sum);
        }
    }
    kani::cover!(r == m as i128 && m > 0, "clamped high");
    kani::cover!(r == -(m as i128) && m > 0, "clamped low");
    kani::cover!(p.checked_add(s).is_none(), "saturating sum");
}

// ── D-P3-09  Step IMR bounds, full width (monotonicity: L-STEP, paper).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_09_step_imr_bounds_full_width() {
    let x: u128 = kani::any();
    let cap_: u128 = kani::any();
    let base: u64 = kani::any();
    let max: u16 = kani::any();
    let r = step_imr_bps(x, cap_, base, max);
    assert!(r >= base && r <= base.max(max as u64));
    if cap_ == 0 || (max as u64) <= base {
        assert_eq!(r, base);
    }
    kani::cover!(r > base && r < max as u64, "ramping");
    kani::cover!(r == max as u64 && (max as u64) > base, "at ceiling");
}

// ── D-P3-10  Vault-LP exposure gate (H2), full width, capture stub for notional_atoms ->
// mul_div_floor: a non-growing fill is never refused; growth is admitted only after
// notional = mul_div_floor(|after|, price, scale) returned Some and equity*lev did not overflow.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, capture_mul_div_floor)]
fn kani_design_p3_10_exposure_gate_full_width() {
    cap_reset();
    let before: i128 = kani::any();
    let after: i128 = kani::any();
    let equity: u128 = kani::any();
    let lev: u32 = kani::any();
    let price: u64 = kani::any();
    let scale: u128 = kani::any();
    let ok = vault_lp_exposure_allowed(before, after, equity, lev, price, scale);
    let grows = after.unsigned_abs() > before.unsigned_abs();
    let (calls, a, b, d, ret) = cap();
    if !grows {
        assert!(ok, "reducing never refused");
        assert_eq!(calls, 0);
    }
    if grows && ok {
        assert_eq!(calls, 1);
        assert!((a == after.unsigned_abs() && b == price as u128) || (a == price as u128 && b == after.unsigned_abs()));
        assert_eq!(d, scale);
        assert!(ret.is_some());
        assert!(equity.checked_mul(lev as u128).is_some());
        // review 7.1 optional pin: the RETURNED notional is what is compared
        assert!(ret.unwrap() <= equity * lev as u128 / BPS);
    }
    kani::cover!(!grows && equity == 0 && before != 0, "reduce with zero equity allowed");
    kani::cover!(grows && ok, "growth admitted");
    kani::cover!(grows && !ok, "growth refused");
}

// ── D-P3-11  Auto-pin caps, FULL u64 price: pinned caps finite, non-zero, <= engine bound;
// price 0 and prices that would round a cap to 0 fail closed. (Ordering + USD bound: L-PIN.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_11_autopin_caps_full_u64() {
    let price: u64 = kani::any();
    let r = pinned_matcher_caps(price);
    if price == 0 {
        assert!(r.is_none());
    }
    if let Some(c) = r {
        assert!(c.max_fill_abs > 0 && c.max_inventory_abs > 0);
        assert!(c.max_fill_abs <= ENGINE_MAX_POSITION_ABS_Q && c.max_inventory_abs <= ENGINE_MAX_POSITION_ABS_Q);
        assert_eq!(c.liquidity_notional_e6, PIN_LIQUIDITY_USD * 1_000_000);
    }
    kani::cover!(matches!(r, Some(c) if c.max_inventory_abs == ENGINE_MAX_POSITION_ABS_Q), "tiny price clamps to the engine bound");
    kani::cover!(r.is_none() && price > 0, "huge price fails closed (would round to 0)");
    kani::cover!(matches!(r, Some(c) if c.max_fill_abs < ENGINE_MAX_POSITION_ABS_Q), "division branch");
}

// ── D-P3-12s  bps rounding small-width regression (x u16, b <= 1e4): bps_floor is the exact floor
// of x*b/1e4, bps_ceil the exact ceil, both None for b > 1e4. Catches floor<->ceil and +1 mutants
// in split_fee / effective_senior_claim / junior_floor_atoms / leverage_gate_ok (all live money
// paths). Full width is L-BPS (paper).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_12s_bps_rounding_u16() {
    let x: u16 = kani::any();
    let b: u16 = kani::any();
    let fl = bps_floor(x as u128, b);
    let ce = bps_ceil(x as u128, b);
    if b as u128 > BPS {
        assert!(fl.is_none() && ce.is_none());
        return;
    }
    let n = x as u128 * b as u128;
    let f = fl.unwrap();
    let c = ce.unwrap();
    assert!(f * BPS <= n && n < f * BPS + BPS, "exact floor");
    assert!(c * BPS >= n && c * BPS < n + BPS, "exact ceil");
    let (sen, jun) = split_fee(x as u128, b).unwrap();
    assert_eq!(sen, f);
    assert_eq!(sen + jun, x as u128);
    kani::cover!(n % BPS != 0 && f > 0, "rounding case");
    kani::cover!(b as u128 == BPS && x > 0, "all to senior");
}
