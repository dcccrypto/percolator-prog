//! Kani design 2026-09-30 (Sentinel) — P3 FINAL `58e379f1`, production `src/vault_lp_v18.rs`.
//! Design doc: ~/percolator-ops/ledger/kani-proof-design-2026-09-30.md (entries D-P3-*).
//!
//! Method. Linear properties (waterfall, splits, clamps, gates) are proven over the FULL u128 /
//! i128 domain. Properties that hinge on `floor(a*b/d)` use a SPEC STUB of `mul_div_floor`
//! (D-P3-00 is the refinement obligation; it is the definition of Rust's `/`) so the solver
//! never re-derives 128-bit division; the stubbed harnesses then prove the operand wiring,
//! guards and rounding direction of each share function, which is exactly where a bug would
//! live. Nonlinear monotonicity facts are NOT claimed here (see the doc's lemma list).
//! Run: cargo kani -Z stubbing --exact --harness proofs::<name>

use crate::vault_lp_v18::*;

// ── spec stubs ──────────────────────────────────────────────────────────────────────────

/// Spec of `mul_div_floor` (D-P3-00): None iff d == 0 or a*b overflows u128; otherwise the
/// unique q with q*d <= a*b < q*d + d.
fn spec_mul_div_floor(a: u128, b: u128, d: u128) -> Option<u128> {
    if d == 0 {
        return None;
    }
    let p = a.checked_mul(b)?;
    let q: u128 = kani::any();
    let qd = q.checked_mul(d);
    kani::assume(matches!(qd, Some(x) if x <= p && p - x < d));
    Some(q)
}

static mut FLOOR_STUB: Option<u128> = None;
/// Deterministic arbitrary junior floor (any value, fixed per harness run).
fn stub_junior_floor_atoms(_c: u128, _bps: u16) -> Option<u128> {
    unsafe { FLOOR_STUB }
}

// ── D-P3-00  mul_div_floor refines its spec (full u128). Expected expensive: it is a 128-bit
// divider against a 128-bit multiplier. If it has no verdict, the spec is the definition of
// Rust integer division and is stated as an axiom, never as a Kani result.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_00_mul_div_floor_refines_spec() {
    let a: u128 = kani::any();
    let b: u128 = kani::any();
    let d: u128 = kani::any();
    let r = mul_div_floor(a, b, d);
    match (d == 0, a.checked_mul(b)) {
        (true, _) | (_, None) => assert!(r.is_none()),
        (false, Some(p)) => {
            let q = r.unwrap();
            let qd = q.checked_mul(d).unwrap();
            assert!(qd <= p && p - qd < d);
        }
    }
    kani::cover!(r.is_none() && d != 0, "overflow fails closed");
    kani::cover!(matches!(r, Some(q) if q > 0 && a.checked_mul(b).unwrap() % d != 0), "non-exact floor");
}

// ── D-P3-00b  Width-split fallback of D-P3-00: the same refinement for a, b, d < 2^64 (every
// share/claim operand the processor passes is a u64 atom or share count widened to u128).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_00b_mul_div_floor_refines_spec_u64_operands() {
    let a: u64 = kani::any();
    let b: u64 = kani::any();
    let d: u64 = kani::any();
    let r = mul_div_floor(a as u128, b as u128, d as u128);
    if d == 0 {
        assert!(r.is_none());
        return;
    }
    let p = a as u128 * b as u128;
    let q = r.unwrap();
    let qd = q * d as u128; // q <= p/d, so q*d <= p < 2^128
    assert!(qd <= p && p - qd < d as u128);
    kani::cover!(q > 0 && p % d as u128 != 0, "non-exact floor");
}

// ── D-P3-01  Waterfall, full u128: static split + LOSS and GAIN transitions + deposit
// neutrality for the junior.
#[kani::proof]
fn kani_design_p3_01_waterfall_transitions_full_width() {
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let s = tranche_split(v, c);
    assert_eq!(s.senior + s.junior, v);
    assert_eq!(s.senior, v.min(c));
    assert_eq!(senior_impaired(v, c), v < c);
    // loss L <= v: junior absorbs first, senior loses only the excess
    let l: u128 = kani::any();
    kani::assume(l <= v);
    let a = tranche_split(v - l, c);
    assert_eq!(s.junior - a.junior, l.min(s.junior), "junior loses min(L, junior)");
    assert_eq!(s.senior - a.senior, l - l.min(s.junior), "senior loses only the excess");
    // gain G: senior restored first, junior only above the claim
    let g: u128 = kani::any();
    kani::assume(v.checked_add(g).is_some());
    let up = tranche_split(v + g, c);
    assert_eq!(up.senior - s.senior, g.min(c - s.senior), "senior restored first");
    assert_eq!(up.junior - s.junior, g - g.min(c - s.senior));
    // senior deposit `amt` raises V and C together: the junior is untouched
    let amt: u128 = kani::any();
    kani::assume(v.checked_add(amt).is_some() && c.checked_add(amt).is_some());
    let dep = tranche_split(v + amt, c + amt);
    assert_eq!(dep.junior, s.junior);
    kani::cover!(l > 0 && s.junior > 0 && l > s.junior, "loss spills from junior into senior");
    kani::cover!(l > 0 && l < s.junior, "loss fully absorbed by the junior");
    kani::cover!(g > 0 && v < c && v + g > c, "gain restores the senior then pays the junior");
    kani::cover!(v < c && amt > 0, "deposit into an impaired vault");
}

// ── D-P3-02  Resolved settlement split (H1), full u128: conserves, never over-refills the
// seniors, junior paid only once seniors are fully backed.
#[kani::proof]
fn kani_design_p3_02_resolved_split_full_width() {
    let p: u128 = kani::any();
    let c: u128 = kani::any();
    let n: u128 = kani::any();
    let (tb, tj) = resolved_settle_split(p, c, n);
    assert_eq!(tb + tj, p);
    let shortfall = c.saturating_sub(n);
    assert_eq!(tb, p.min(shortfall));
    if tj > 0 {
        assert!(n + tb >= c);
    }
    kani::cover!(tb > 0 && tj > 0, "refill then junior");
    kani::cover!(tj == 0 && p > 0 && shortfall >= p, "all to seniors");
    kani::cover!(tb == 0 && p > 0 && n >= c, "seniors whole: all to junior");
}

// ── D-P3-03  Conservative (IM-lane) equity, full width: never credits positive pnl or fee
// credit, clamps at zero, fails closed only when capital exceeds i128.
#[kani::proof]
fn kani_design_p3_03_conservative_equity_full_width() {
    let cap: u128 = kani::any();
    let pnl: i128 = kani::any();
    let fee: i128 = kani::any();
    let r = conservative_equity(cap, pnl, fee);
    if cap > i128::MAX as u128 {
        assert!(r.is_none());
        return;
    }
    let neg = pnl.min(0).checked_add(fee.min(0));
    match (neg, r) {
        (Some(nn), Some(e)) => {
            let raw = (cap as i128).checked_add(nn);
            if let Some(raw) = raw {
                assert_eq!(e, if raw <= 0 { 0 } else { raw as u128 });
            }
            assert!(e <= cap, "never above capital");
        }
        (_, None) => {}
        (None, Some(e)) => assert!(e <= cap),
    }
    kani::cover!(matches!(r, Some(e) if e == cap && pnl > 0 && fee > 0), "positive pnl and credit not counted");
    kani::cover!(matches!(r, Some(0)) && cap > 0, "wiped");
    kani::cover!(r.is_none() && cap <= i128::MAX as u128, "overflow of the negative terms fails closed");
}

// ── D-P3-04  Junior withdraw (tag 102 Live), full u128, for ANY floor value the floor function
// can return (stubbed deterministically): allowed => senior fully backed, amount + floor within
// the junior, and after the withdrawal the senior is still whole and the junior >= floor.
#[kani::proof]
#[kani::stub(crate::vault_lp_v18::junior_floor_atoms, stub_junior_floor_atoms)]
fn kani_design_p3_04_junior_withdraw_full_width() {
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
        assert_eq!(post.senior, c, "senior still whole");
        assert!(post.junior >= f, "junior floor kept");
    }
    if fl.is_none() || cover < c {
        assert!(!ok);
    }
    kani::cover!(ok && amount > 0 && c > 0 && fl.unwrap() > 0, "allowed with seniors and a floor");
    kani::cover!(!ok && cover >= c && fl.is_some() && v > c, "refused by the floor");
    kani::cover!(!ok && cover < c, "refused: senior not backed");
}

// ── D-P3-05  Deposit share wiring, full u128 (stubbed division): genesis mints 1:1; zero senior
// value refuses; otherwise minted = floor(amount*S/senior): never over-mints and never
// under-mints by a whole share. Operand order / rounding direction are what this pins.
#[kani::proof]
#[kani::solver(kissat)]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, spec_mul_div_floor)]
fn kani_design_p3_05_deposit_shares_wiring() {
    let amount: u128 = kani::any();
    let s: u128 = kani::any();
    let senior: u128 = kani::any();
    let r = senior_shares_for_deposit(amount, s, senior);
    if s == 0 {
        assert_eq!(r, Some(amount));
        return;
    }
    if senior == 0 {
        assert!(r.is_none());
        return;
    }
    match amount.checked_mul(s) {
        None => assert!(r.is_none(), "overflow fails closed"),
        Some(num) => {
            let m = r.unwrap();
            let md = m.checked_mul(senior);
            assert!(matches!(md, Some(x) if x <= num), "never over-mints");
            assert!(num - md.unwrap() < senior, "never under-mints by a whole share");
        }
    }
    kani::cover!(matches!(r, Some(m) if m > 0) && s > 0, "non-genesis mint");
    kani::cover!(r.is_none() && senior != 0, "overflow refused");
}

// ── D-P3-06  Redemption wiring, full u128 (stubbed division): payout = floor(shares*V_s/S),
// removed claim = floor(shares*C/S), bad inputs refused, claim never underflows; principal
// portion never exceeds the payout.
#[kani::proof]
#[kani::solver(kissat)]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, spec_mul_div_floor)]
fn kani_design_p3_06_redemption_wiring() {
    let shares: u128 = kani::any();
    let s: u128 = kani::any();
    let sv: u128 = kani::any();
    let c: u128 = kani::any();
    let pay = senior_atoms_for_redemption(shares, s, sv);
    let after = senior_claim_after_redemption(c, shares, s);
    let bad = s == 0 || shares > s;
    if bad {
        assert!(pay.is_none() && after.is_none());
        return;
    }
    if let (Some(p), Some(num)) = (pay, shares.checked_mul(sv)) {
        let ps = p.checked_mul(s);
        assert!(matches!(ps, Some(x) if x <= num), "payout never above pro rata");
        assert!(num - ps.unwrap() < s, "payout floor is exact");
    }
    if let (Some(a), Some(num)) = (after, shares.checked_mul(c)) {
        let slice = c - a;
        let sl = slice.checked_mul(s);
        assert!(matches!(sl, Some(x) if x <= num), "claim removed never above pro rata");
        assert!(num - sl.unwrap() < s);
    }
    let avail: u128 = kani::any();
    if let Some(p) = pay {
        if let Some(pp) = senior_principal_portion(shares, avail, s, p) {
            assert!(pp <= p);
        }
    }
    kani::cover!(matches!(pay, Some(p) if p > 0) && shares < s, "partial redemption");
    kani::cover!(shares == s && matches!(after, Some(0)), "last redeemer clears the claim");
}

// ── D-P3-07  Skew funding rate, full width: crowded side pays, zero at balance / disabled,
// |rate| <= max. (|rate| <= slope and monotonicity are nonlinear: lemma L-SKEW, not claimed.)
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

// ── D-P3-08  Combined rate handed to the engine is always inside +-max_abs (the ONLY wrapper
// contribution to funding conservation; the zero-sum itself is the engine's D-ENG-02).
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

// ── D-P3-09  Step IMR bounds, full width: always in [base, max(base, max)], equals base when
// disabled. (Monotonicity in crowding is nonlinear: lemma, not claimed.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p3_09_step_imr_bounds_full_width() {
    let x: u128 = kani::any();
    let cap: u128 = kani::any();
    let base: u64 = kani::any();
    let max: u16 = kani::any();
    let r = step_imr_bps(x, cap, base, max);
    assert!(r >= base && r <= base.max(max as u64));
    if cap == 0 || (max as u64) <= base {
        assert_eq!(r, base);
    }
    kani::cover!(r > base && r < max as u64, "ramping");
    kani::cover!(r == max as u64 && (max as u64) > base, "at ceiling");
}

// ── D-P3-10  Vault-LP exposure gate (H2), full width: a fill that does not grow |LP| is never
// refused (an over-leveraged vault stays closable); growth is admitted only when
// every overflow / zero scale fails closed.
#[kani::proof]
#[kani::solver(kissat)]
#[kani::stub(crate::vault_lp_v18::mul_div_floor, spec_mul_div_floor)]
fn kani_design_p3_10_exposure_gate_full_width() {
    let before: i128 = kani::any();
    let after: i128 = kani::any();
    let equity: u128 = kani::any();
    let lev: u32 = kani::any();
    let price: u64 = kani::any();
    let scale: u128 = kani::any();
    let ok = vault_lp_exposure_allowed(before, after, equity, lev, price, scale);
    let grows = after.unsigned_abs() > before.unsigned_abs();
    if !grows {
        assert!(ok);
    }
    if grows && ok {
        // growth is admitted only through the checked path: a real scale, a representable
        // |after|*price and equity*lev (every overflow / zero scale fails closed). The
        // inequality notional <= lim itself is the implementation's single comparison.
        assert!(scale != 0);
        assert!(after.unsigned_abs().checked_mul(price as u128).is_some());
        assert!(equity.checked_mul(lev as u128).is_some());
    }
    kani::cover!(!grows && equity == 0 && before != 0, "reduce with zero equity allowed");
    kani::cover!(grows && ok, "growth admitted");
    kani::cover!(grows && !ok && scale != 0, "growth refused");
}

// ── D-P3-11  Auto-pin caps (tag 94), FULL u64 price: whenever pinned, every cap is finite and
// non-zero (0 would mean UNLIMITED to the matcher), bounded by the engine position bound; a
// price that would round a cap to 0 fails closed. (Ordering fill <= inventory and the USD
// notional bound are floor-monotonicity facts: lemma L-PIN, not claimed.)
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
