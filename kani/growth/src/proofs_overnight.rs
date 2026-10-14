//! Overnight 2026-10-14 (ledger v22-kani-overnight-2026-10-14.md): decomposed replacements for
//! the growth rows that were NO-VERDICT in the v22 final run.
//!
//! Decomposition rule used here: a harness that ran a 128-bit divider for REAL (u8 operands,
//! "computed") is split into
//!   (P) the primitive's exact contract, `kani_growth_c_mul_div_floor` / `_ceil` (PASS in the v22
//!       final run; u8 operands + the P1 width lift recorded in the results file), and
//!   (Q) the SAME property with the primitive replaced by that contract (`stub_verified`), i.e.
//!       "every value the contract allows satisfies the property".
//! (P) ∧ (Q) ⇒ the original property. (Q) no longer bit-blasts a divider; where the operands
//! allow it (Q) is stated at FULL width, which is stronger than the original u8 bound.
//! Every harness carries covers; PASS counts only with every cover satisfied.

use crate::growth_v19::*;

// ── L1–L4 order lemmas, by contract ─────────────────────────────────────────────────────────

/// L1 (Q-part): ceil(a·b/d) is monotone in b. Operands u8 as in the original (the lemma is
/// consumed with u8-bounded P3 operands); quotients are contract values.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_lc1_ceil_monotone_in_b() {
    let a = kani::any::<u8>() as u128;
    let b1 = kani::any::<u8>() as u128;
    let b2 = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(b1 <= b2 && d > 0);
    let q1 = mul_div_ceil_u128(a, b1, d).unwrap();
    let q2 = mul_div_ceil_u128(a, b2, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && b1 < b2 && a > 0, "equal (ceil plateau)");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_lc2_ceil_monotone_in_a() {
    let a1 = kani::any::<u8>() as u128;
    let a2 = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(a1 <= a2 && d > 0);
    let q1 = mul_div_ceil_u128(a1, b, d).unwrap();
    let q2 = mul_div_ceil_u128(a2, b, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && a1 < a2 && b > 0, "equal");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_lc3_ceil_antitone_in_d() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d1 = kani::any::<u8>() as u128;
    let d2 = kani::any::<u8>() as u128;
    kani::assume(d1 > 0 && d1 <= d2);
    let q1 = mul_div_ceil_u128(a, b, d1).unwrap();
    let q2 = mul_div_ceil_u128(a, b, d2).unwrap();
    assert!(q2 <= q1);
    kani::cover!(q2 < q1, "strict");
    kani::cover!(q2 == q1 && d1 < d2 && a * b > 0, "equal");
}

#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_lc4_floor_monotone_in_a() {
    let a1 = kani::any::<u8>() as u128;
    let a2 = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    kani::assume(a1 <= a2 && d > 0);
    let q1 = crate::vault_lp_v18::mul_div_floor(a1, b, d).unwrap();
    let q2 = crate::vault_lp_v18::mul_div_floor(a2, b, d).unwrap();
    assert!(q1 <= q2);
    kani::cover!(q1 < q2, "strict");
    kani::cover!(q1 == q2 && a1 < a2 && b > 0, "equal (floor plateau)");
}

// ── T7 gap solvency, by contract ───────────────────────────────────────────────────────────

/// L5 = T7 gap solvency (Q-part): mmr >= r_gap + fee ⇒ ceil(N·mmr/1e4) >= floor(N·r/1e4) +
/// ceil(N·f/1e4). Divisor is the constant 1e4, so the notional is u64 here (original: u8).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_t7c_rule_implies_gap_solvency() {
    let n = kani::any::<u64>() as u128;
    let r: u16 = kani::any();
    let f: u16 = kani::any();
    let mmr: u16 = kani::any();
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let mm = mul_div_ceil_u128(n, mmr as u128, 10_000).unwrap();
    let gap = crate::vault_lp_v18::mul_div_floor(n, r as u128, 10_000).unwrap();
    let fee = mul_div_ceil_u128(n, f as u128, 10_000).unwrap();
    assert!(mm >= gap + fee);
    kani::cover!(mm == gap + fee && n > 0 && r > 0 && f > 0, "tight");
    kani::cover!(mm > gap + fee, "slack");
    kani::cover!(n > u32::MAX as u128 && r > 0 && f > 0, "wide notional");
}

/// Same lemma at the original u8 bound (the exact original statement, by contract).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_t7c8_rule_implies_gap_solvency_u8() {
    let n = kani::any::<u8>() as u128;
    let r: u16 = kani::any();
    let f: u16 = kani::any();
    let mmr: u16 = kani::any();
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let mm = mul_div_ceil_u128(n, mmr as u128, 10_000).unwrap();
    let gap = crate::vault_lp_v18::mul_div_floor(n, r as u128, 10_000).unwrap();
    let fee = mul_div_ceil_u128(n, f as u128, 10_000).unwrap();
    assert!(mm >= gap + fee);
    kani::cover!(mm == gap + fee && n > 0 && r > 0 && f > 0, "tight");
    kani::cover!(mm > gap + fee, "slack");
}

// ── composite exact C1 specs at FULL width, by primitive contract ──────────────────────────
// Original `kani_growth_c_<fn>`: exact spec, u8 operands, REAL primitive (NO-VERDICT 4000 s).
// Here: exact spec, FULL u128 operands, primitive by contract. Composite structure is also
// proved separately with an arbitrary primitive (`proofs_nc::kani_growth_s*`).

#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_cz_n_cap_q() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = n_cap_q(c, l, p, s);
    assert!(spec::n_cap_q(c, l, p, s, r), "exact C1 spec");
    kani::cover!(p == 0 && r.is_none(), "None: price 0");
    kani::cover!(r.is_some_and(|n| n > 0), "Some: capacity");
    kani::cover!(r == Some(0) && c > 0 && l > 0 && s > 0, "Some: rounds to 0");
    kani::cover!(p != 0 && r.is_none() && c.checked_mul(l as u128).is_some(), "None: primitive overflow");
}

#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_cz_liquidity_notional_e6() {
    let c: u128 = kani::any();
    let l: u32 = kani::any();
    let r = liquidity_notional_e6(c, l);
    assert!(spec::liquidity_notional_e6(c, l, r), "exact C1 spec");
    kani::cover!(r.is_some_and(|x| x > 0), "Some: depth");
    kani::cover!(r == Some(0) && c > 0 && l > 0, "Some: rounds to 0");
    kani::cover!(r.is_none(), "None: overflow");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_cz_risk_notional_ceil() {
    let q: u128 = kani::any();
    let p: u64 = kani::any();
    let s: u128 = kani::any();
    let r = risk_notional_ceil(q, p, s);
    assert!(spec::risk_notional_ceil(q, p, s, r), "exact C1 spec");
    kani::cover!(s == 0 && r.is_none(), "None: scale 0");
    kani::cover!(r.is_some_and(|x| x > 0), "Some: notional");
    kani::cover!(r == Some(0) && s > 0, "Some: flat");
}

#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_cz_leg_im_req() {
    let n: u128 = kani::any();
    let imr: u64 = kani::any();
    let m: u128 = kani::any();
    let r = leg_im_req(n, imr, m);
    assert!(spec::leg_im_req(n, imr, m, r), "exact C1 spec");
    kani::cover!(n == 0 && r == Some(0), "Some(0): flat");
    kani::cover!(n > 0 && imr > 10_000 && r.is_none(), "None: imr > 10,000");
    kani::cover!(r.is_some_and(|v| v == m && m > 0 && n > 0 && imr > 0), "Some: min binds");
    kani::cover!(r.is_some_and(|v| v > m && n > 0), "Some: ceil binds");
}

#[kani::proof_for_contract(crate::growth_v19::dyn_imr_bps)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_cz_dyn_imr_bps() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let k: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, k);
    let valid = base <= 10_000 && k <= 10_000;
    kani::cover!(valid && n > 0 && lp > 0 && lp <= n && r == Some(base), "Some: below the kink");
    kani::cover!(valid && lp < n && r.is_some_and(|x| x > base && x < 10_000), "Some: between the kink and u == 1");
    kani::cover!(valid && lp == n && k < 10_000 && base < 10_000 && r == Some(10_000), "Some: exactly 10,000 at u == 1");
    kani::cover!(valid && lp > n && r.is_none(), "None: lp > n");
    kani::cover!(valid && n == 0 && r.is_none(), "None: n == 0");
    kani::cover!(!valid && r.is_none(), "None: invalid dials");
}

#[kani::proof_for_contract(crate::growth_v19::utilisation_fee_bps)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_cz_utilisation_fee_bps() {
    let o: u128 = kani::any();
    let n: u128 = kani::any();
    let k: u16 = kani::any();
    let m: u16 = kani::any();
    let r = utilisation_fee_bps(o, n, k, m);
    kani::cover!(n == 0 && r.is_none(), "None: n == 0");
    kani::cover!(n > 0 && k > 10_000 && r.is_none(), "None: k > 10,000");
    kani::cover!(r == Some(0) && m > 0 && o > 0, "Some(0): at/below the kink");
    kani::cover!(r.is_some_and(|f| f > 0 && f < m) && o < n, "Some: between the kink and u == 1");
    kani::cover!(r.is_some_and(|f| f == m && m > 0) && o == n && k < 10_000, "Some(max): u == 1");
    kani::cover!(r.is_some_and(|f| f == m && m > 0) && o > n, "Some(max): u > 1 (capped)");
}

#[kani::proof_for_contract(crate::growth_v19::util_fee_on_fill_bps)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_cz_util_fee_on_fill_bps() {
    let f: u16 = kani::any();
    let o: u128 = kani::any();
    let fill: u128 = kani::any();
    let r = util_fee_on_fill_bps(f, o, fill);
    kani::cover!(r == f && f > 0, "plain open: full rate");
    kani::cover!(r > 0 && r < f, "flip: opening share");
    kani::cover!(fill > 0 && o > 0 && f > 0 && r == 0, "rounds to 0");
    kani::cover!(fill == 0 || o == 0 || f == 0, "zero input");
}

// ── W-G-3 / W-G-2 / T5-at-capacity / W-G-1 by contract, wider than the originals ──────────

/// W-G-3: dyn IMR in [base, MAX] -- FULL width (original u8 / u16), ceil by contract.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_wc_g3_dyn_imr_not_below_base() {
    let lp: u128 = kani::any();
    let n: u128 = kani::any();
    let base: u64 = kani::any();
    let kink: u16 = kani::any();
    let r = dyn_imr_bps(lp, n, base, kink);
    if let Some(x) = r {
        assert!(x >= base, "dyn IMR >= base");
        assert!(x <= MAX_IMR_BPS);
    }
    kani::cover!(r == Some(base) && lp > 0, "at or below the kink");
    kani::cover!(r.is_some_and(|x| x > base), "above the kink");
    kani::cover!(r.is_none(), "refused");
}

/// u == 1 on the crowd side costs 100% margin: u64 N_cap (original u8), real gate, real
/// `n_cap_q` and `dyn_imr_bps`, both primitives by contract (the ceil range facts give
/// ceil(span·den/den) == span; the floor contract gives N_cap == equity at 1x / price 1 / scale 1).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
fn kani_growth_t5c_at_capacity_costs_full_margin() {
    let n = kani::any::<u64>() as u128;
    kani::assume(n > 0);
    let lb: i8 = kani::any();
    let la: i8 = kani::any();
    let g = GrowthGateIn {
        taker_before_q: 0,
        taker_after_q: 1,
        taker_eff_after_abs_q: 1,
        taker_equity: 0,
        taker_cert_initial_req: None,
        lp: Some(GrowthLpIn {
            before_q: lb as i128,
            mid_q: lb as i128,
            after_q: la as i128,
            eff_after_abs_q: (la as i128).unsigned_abs(),
            users_oi_side_after_q: n,
            equity: n, // N_cap == equity at lambda 1x, price 1, pos_scale 1 (S1 + floor contract)
        }),
        price_e6: 1,
        pos_scale: 1,
        engine_imr_bps: kani::any::<u16>() as u64,
        min_nonzero_im_req: 0,
        ceil_imr_bps: kani::any::<u16>() as u64,
        lambda_bps: 10_000,
        kink_bps: kani::any(),
        crowd_blocked: false,
        asset_bound: true,
    };
    kani::assume(joins_crowd(lb as i128, la as i128));
    kani::assume(g.kink_bps < 10_000 && g.ceil_imr_bps <= 10_000 && g.ceil_imr_bps >= g.engine_imr_bps);
    let r = growth_required_imr_bps(&g);
    assert_eq!(r, Ok(10_000));
    kani::cover!(r == Ok(10_000) && g.ceil_imr_bps < 10_000 && g.kink_bps > 0 && n > u32::MAX as u128, "full margin at a u64 capacity");
}

// ∀-value N_cap stub (V4 pattern: `n_cap_q` carries no contract; the harness draws the value
// freely, so a property proved here holds for EVERY capacity value, incl. None).
static mut ON_NCAP: Option<u128> = None;
fn on_n_cap_any(_c: u128, _l: u32, _p: u64, _s: u128) -> Option<u128> {
    unsafe { ON_NCAP }
}

/// W-G-2 at FULL width (original: real n_cap_q at u8 operands): `Ok(r) ⇒ engine <= r <= MAX`
/// for EVERY N_cap value (∀-stub) and every gate field; `dyn_imr_bps` runs for real with the
/// ceil primitive by contract. No assumption on engine_imr_bps.
#[kani::proof]
#[kani::stub(crate::growth_v19::n_cap_q, on_n_cap_any)]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_wc_g2_required_imr_not_below_engine() {
    unsafe { ON_NCAP = kani::any() };
    let lp_some: bool = kani::any();
    let lp = if lp_some {
        Some(GrowthLpIn {
            before_q: kani::any(),
            mid_q: kani::any(),
            after_q: kani::any(),
            eff_after_abs_q: kani::any(),
            users_oi_side_after_q: kani::any(),
            equity: kani::any(),
        })
    } else {
        None
    };
    let g = GrowthGateIn {
        taker_before_q: kani::any(),
        taker_after_q: kani::any(),
        taker_eff_after_abs_q: kani::any(),
        taker_equity: kani::any(),
        taker_cert_initial_req: kani::any(),
        lp,
        price_e6: kani::any(),
        pos_scale: kani::any(),
        engine_imr_bps: kani::any(),
        min_nonzero_im_req: kani::any(),
        ceil_imr_bps: kani::any(),
        lambda_bps: kani::any(),
        kink_bps: kani::any(),
        crowd_blocked: kani::any(),
        asset_bound: kani::any(),
    };
    let r = growth_required_imr_bps(&g);
    if let Ok(x) = r {
        assert!(x >= g.engine_imr_bps, "never below the engine IMR");
        assert!(x <= MAX_IMR_BPS);
    }
    let crowd = g.lp.is_some_and(|l| joins_crowd(l.mid_q, l.after_q));
    kani::cover!(r.is_ok() && g.lp.is_none(), "no LP: ceiling");
    kani::cover!(r.is_ok() && g.lp.is_some() && !crowd, "thin open: ceiling");
    kani::cover!(r.is_ok_and(|x| x > g.ceil_imr_bps) && crowd, "crowd above the kink");
    kani::cover!(r == Err(GrowthVerdict::LeverageExceeded), "ceil below engine refused");
    kani::cover!(r == Err(GrowthVerdict::CapacityFull), "capacity refused");
}

/// W-G-1 by contract at the ORIGINAL bounds (u16 notional / IMRs / min): growth_margin_required
/// with the REAL `leg_im_req` (two legs), ceil primitive by contract.
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_wc_g1_requirement_never_below_engine_or_per_asset_u16() {
    let n = kani::any::<u16>() as u128;
    let eng = kani::any::<u16>() as u64;
    let dy = kani::any::<u16>() as u64;
    let m = kani::any::<u16>() as u128;
    let cert: Option<u128> = kani::any();
    kani::assume(eng <= 10_000 && dy <= 10_000);
    // growth_required_imr_bps never returns an IMR below the engine IMR (W-G-2).
    kani::assume(dy >= eng);
    let dyn_leg = leg_im_req(n, dy, m);
    let eng_leg = leg_im_req(n, eng, m);
    let r = growth_margin_required(cert, n, eng, dy, m);
    if let Some(r) = r {
        assert!(dyn_leg.is_some_and(|d| r >= d), "never below the per-asset (dyn) leg");
        if let (Some(c), Some(_e)) = (cert, eng_leg) {
            assert!(r >= c, "never below the engine certificate");
        }
    } else {
        assert!(cert.is_some() && cert.unwrap().saturating_sub(eng_leg.unwrap()).checked_add(dyn_leg.unwrap()).is_none());
    }
    kani::cover!(cert.is_some() && dy > eng && r.is_some_and(|x| x > cert.unwrap()), "cert path, dyn above engine");
    kani::cover!(cert.is_some_and(|c| eng_leg.is_some_and(|e| c < e)) && r.is_some(), "saturating path");
    kani::cover!(cert.is_none() && r.is_some() && n > 0, "no cert");
    kani::cover!(r.is_none(), "None refused (overflow)");
}

/// W-G-1 by contract, notional widened to u64 (min u64).
#[kani::proof]
#[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
fn kani_growth_wc_g1_requirement_never_below_engine_or_per_asset_u64() {
    let n = kani::any::<u64>() as u128;
    let eng = kani::any::<u16>() as u64;
    let dy = kani::any::<u16>() as u64;
    let m = kani::any::<u64>() as u128;
    let cert: Option<u128> = kani::any();
    kani::assume(eng <= 10_000 && dy <= 10_000);
    kani::assume(dy >= eng);
    let dyn_leg = leg_im_req(n, dy, m);
    let eng_leg = leg_im_req(n, eng, m);
    let r = growth_margin_required(cert, n, eng, dy, m);
    if let Some(r) = r {
        assert!(dyn_leg.is_some_and(|d| r >= d), "never below the per-asset (dyn) leg");
        if let (Some(c), Some(_e)) = (cert, eng_leg) {
            assert!(r >= c, "never below the engine certificate");
        }
    } else {
        assert!(cert.is_some() && cert.unwrap().saturating_sub(eng_leg.unwrap()).checked_add(dyn_leg.unwrap()).is_none());
    }
    kani::cover!(cert.is_some() && dy > eng && r.is_some_and(|x| x > cert.unwrap()), "cert path, dyn above engine");
    kani::cover!(cert.is_none() && r.is_some() && n > u32::MAX as u128, "no cert, wide notional");
    kani::cover!(r.is_none(), "None refused (overflow)");
}

// ── negative controls (`--features negctl`): each MUST FAIL under the same solver/stubs ────
#[cfg(feature = "negctl")]
mod neg {
    use crate::growth_v19::*;

    /// lc1 with the inequality made strict: the ceil plateau is a counterexample.
    #[kani::proof]
    #[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
    fn neg_lc1_strict() {
        let a = kani::any::<u8>() as u128;
        let b1 = kani::any::<u8>() as u128;
        let b2 = kani::any::<u8>() as u128;
        let d = kani::any::<u8>() as u128;
        kani::assume(b1 < b2 && d > 0);
        let q1 = mul_div_ceil_u128(a, b1, d).unwrap();
        let q2 = mul_div_ceil_u128(a, b2, d).unwrap();
        assert!(q1 < q2);
    }

    /// t7c without the fee in the rule (mmr >= r only): gap solvency must break.
    #[kani::proof]
    #[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
    #[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
    fn neg_t7c_rule_without_fee() {
        let n = kani::any::<u64>() as u128;
        let r: u16 = kani::any();
        let f: u16 = kani::any();
        let mmr: u16 = kani::any();
        kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr >= r);
        let mm = mul_div_ceil_u128(n, mmr as u128, 10_000).unwrap();
        let gap = crate::vault_lp_v18::mul_div_floor(n, r as u128, 10_000).unwrap();
        let fee = mul_div_ceil_u128(n, f as u128, 10_000).unwrap();
        assert!(mm >= gap + fee);
    }

    /// wc_g3 with `> base`: the below-kink branch returns exactly base.
    #[kani::proof]
    #[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
    fn neg_wc_g3_strict() {
        let lp: u128 = kani::any();
        let n: u128 = kani::any();
        let base: u64 = kani::any();
        let kink: u16 = kani::any();
        if let Some(x) = dyn_imr_bps(lp, n, base, kink) {
            assert!(x > base);
        }
    }

    /// cz_leg_im_req's claim with a floor-style relation: ceil != floor on inexact products.
    #[kani::proof]
    #[kani::stub_verified(crate::growth_v19::mul_div_ceil_u128)]
    fn neg_leg_is_floor() {
        let n: u128 = kani::any();
        let imr: u64 = kani::any();
        kani::assume(n > 0 && imr <= 10_000 && n.checked_mul(imr as u128).is_some());
        if let Some(v) = leg_im_req(n, imr, 0) {
            assert!(v.checked_mul(10_000).is_some_and(|x| x <= n * imr as u128));
        }
    }
}

// ── T7 split (original kani_growth_t7_rule_implies_gap_solvency NO-VERDICT; t7c* NO-VERDICT) ──
// T7 ⇐ E1 ∧ E2 ∧ T7m by substitution: E1/E2 pin the REAL primitives at the t7 operands (u8
// notional, bps <= 1e4, divisor the constant 1e4) to exact u32 arithmetic; T7m is the inequality
// in u32 arithmetic.

/// E1: mul_div_ceil_u128(n, x, 1e4) == ceil(n·x / 1e4) computed in u32, n u8, x <= 1e4.
#[kani::proof]
fn kani_growth_t7e1_ceil_bps_exact_u8() {
    let n = kani::any::<u8>() as u32;
    let x = kani::any::<u16>() as u32;
    kani::assume(x <= 10_000);
    let r = mul_div_ceil_u128(n as u128, x as u128, 10_000);
    assert_eq!(r, Some((n * x).div_ceil(10_000) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && (n * x) % 10_000 != 0), "rounds up");
    kani::cover!(r.is_some_and(|q| q > 0 && (n * x) % 10_000 == 0), "exact");
}

/// E2: mul_div_floor(n, x, 1e4) == floor(n·x / 1e4) computed in u32, n u8, x <= 1e4.
#[kani::proof]
fn kani_growth_t7e2_floor_bps_exact_u8() {
    let n = kani::any::<u8>() as u32;
    let x = kani::any::<u16>() as u32;
    kani::assume(x <= 10_000);
    let r = crate::vault_lp_v18::mul_div_floor(n as u128, x as u128, 10_000);
    assert_eq!(r, Some(((n * x) / 10_000) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && (n * x) % 10_000 != 0), "rounds down");
}

/// T7m: mmr >= r + f ⇒ ceil(n·mmr/1e4) >= floor(n·r/1e4) + ceil(n·f/1e4), u32 arithmetic,
/// n u8, bps <= 1e4 (the original t7 domain).
#[kani::proof]
fn kani_growth_t7m_gap_solvency_math_u8() {
    let n = kani::any::<u8>() as u32;
    let r = kani::any::<u16>() as u32;
    let f = kani::any::<u16>() as u32;
    let mmr = kani::any::<u16>() as u32;
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr >= r + f);
    let mm = (n * mmr).div_ceil(10_000);
    let gap = (n * r) / 10_000;
    let fee = (n * f).div_ceil(10_000);
    assert!(mm >= gap + fee);
    kani::cover!(mm == gap + fee && n > 0 && r > 0 && f > 0, "tight");
    kani::cover!(mm > gap + fee, "slack");
}

// ── L1–L4 split (originals NO-VERDICT; lc* NO-VERDICT): L_i ⇐ EL ∧ L_i m by substitution ─────
// EL1/EL2: the REAL primitives equal exact u32 arithmetic on the original u8 domain (one 128-bit
// divider each, as in kani_growth_c_mul_div_*). L1m–L4m: the order facts in u32 arithmetic.

/// EL1: mul_div_ceil_u128(a, b, d) == ceil(a·b/d) in u32, every u8 a, b, d > 0.
#[kani::proof]
fn kani_growth_el1_ceil_exact_u8() {
    let a = kani::any::<u8>() as u32;
    let b = kani::any::<u8>() as u32;
    let d = kani::any::<u8>() as u32;
    kani::assume(d > 0);
    let r = mul_div_ceil_u128(a as u128, b as u128, d as u128);
    assert_eq!(r, Some((a * b).div_ceil(d) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "rounds up");
}

/// EL2: mul_div_floor(a, b, d) == floor(a·b/d) in u32, every u8 a, b, d > 0.
#[kani::proof]
fn kani_growth_el2_floor_exact_u8() {
    let a = kani::any::<u8>() as u32;
    let b = kani::any::<u8>() as u32;
    let d = kani::any::<u8>() as u32;
    kani::assume(d > 0);
    let r = crate::vault_lp_v18::mul_div_floor(a as u128, b as u128, d as u128);
    assert_eq!(r, Some(((a * b) / d) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "rounds down");
}

fn c32(a: u32, b: u32, d: u32) -> u32 {
    (a * b).div_ceil(d)
}

#[kani::proof]
fn kani_growth_l1m_ceil_monotone_in_b_u8() {
    let (a, b1, b2, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    kani::assume(b1 <= b2 && d > 0);
    assert!(c32(a, b1, d) <= c32(a, b2, d));
    kani::cover!(c32(a, b1, d) < c32(a, b2, d), "strict");
    kani::cover!(c32(a, b1, d) == c32(a, b2, d) && b1 < b2 && a > 0, "plateau");
}

#[kani::proof]
fn kani_growth_l2m_ceil_monotone_in_a_u8() {
    let (a1, a2, b, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    kani::assume(a1 <= a2 && d > 0);
    assert!(c32(a1, b, d) <= c32(a2, b, d));
    kani::cover!(c32(a1, b, d) < c32(a2, b, d), "strict");
    kani::cover!(c32(a1, b, d) == c32(a2, b, d) && a1 < a2 && b > 0, "plateau");
}

#[kani::proof]
fn kani_growth_l3m_ceil_antitone_in_d_u8() {
    let (a, b, d1, d2) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    kani::assume(d1 > 0 && d1 <= d2);
    assert!(c32(a, b, d2) <= c32(a, b, d1));
    kani::cover!(c32(a, b, d2) < c32(a, b, d1), "strict");
    kani::cover!(c32(a, b, d2) == c32(a, b, d1) && d1 < d2 && a * b > 0, "plateau");
}

#[kani::proof]
fn kani_growth_l4m_floor_monotone_in_a_u8() {
    let (a1, a2, b, d) = (kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32, kani::any::<u8>() as u32);
    kani::assume(a1 <= a2 && d > 0);
    assert!(a1 * b / d <= a2 * b / d);
    kani::cover!(a1 * b / d < a2 * b / d, "strict");
    kani::cover!(a1 * b / d == a2 * b / d && a1 < a2 && b > 0, "plateau");
}
