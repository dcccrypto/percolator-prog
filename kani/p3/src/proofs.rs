//! Kani harnesses for `vault_lp_v18` (the production file). Run locally, never in CI:
//!   cargo kani --harness <name>
//! Every harness carries `kani::cover!` witnesses; a harness whose covers are not ALL
//! satisfied is vacuous and does not count as a pass.
//!
//! Bounds: harnesses with symbolic u128 multiply+divide draw u16 inputs (cast to u128) so CBMC
//! terminates on this machine; add-only / compare-only harnesses use u64. The functions are
//! over u128, so every proof is a BOUNDED proof and is stated as such in the report.

use crate::vault_lp_v18::*;

fn u(x: u16) -> u128 {
    x as u128
}

/// Narrower bound for the harnesses whose assertions multiply a symbolic floor-division result
/// back up (128-bit nonlinear circuits CBMC could not finish on u16 inputs in 13+ minutes).
fn b(x: u8) -> u128 {
    x as u128
}

// ── Waterfall ────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_waterfall_conservation_and_junior_first() {
    let v: u64 = kani::any();
    let c: u64 = kani::any();
    let (v, c) = (v as u128, c as u128);
    let s = tranche_split(v, c);
    assert!(s.senior + s.junior == v);
    assert!(s.senior <= c);
    if s.junior > 0 {
        assert!(s.senior == c);
    }
    if s.senior < c {
        assert!(s.junior == 0);
    }
    assert!(senior_impaired(v, c) == (s.senior < c));
    kani::cover!(v < c, "impaired");
    kani::cover!(v == c && c > 0, "exactly covered");
    kani::cover!(v > c, "junior surplus");
}

// ── Deposit ──────────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_deposit_no_dilution() {
    let amount = b(kani::any());
    let s = b(kani::any());
    let senior = b(kani::any());
    match senior_shares_for_deposit(amount, s, senior) {
        Some(minted) => {
            if s == 0 {
                assert!(minted == amount);
            } else {
                // price after >= price before: (senior+amount)/(S+minted) >= senior/S
                assert!((senior + amount) * s >= senior * (s + minted));
                // never more than the pro-rata share
                assert!(minted * senior <= amount * s);
            }
        }
        None => assert!(s != 0 && senior == 0),
    }
    kani::cover!(s == 0, "genesis");
    kani::cover!(s > 0 && senior > 0 && amount > 0, "non-genesis");
    kani::cover!(s > 0 && senior == 0, "refused: zero senior value");
}

// ── Redemption ───────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_redemption_no_dilution() {
    let c = b(kani::any());
    let v = b(kani::any());
    let s = b(kani::any());
    let shares = b(kani::any());
    let avail = b(kani::any());
    kani::assume(s > 0 && shares <= s);
    let senior_value = tranche_split(v, c).senior;
    let payout = senior_atoms_for_redemption(shares, s, senior_value).unwrap();
    let c_after = senior_claim_after_redemption(c, shares, s).unwrap();
    let slice = c - c_after;
    assert!(payout <= senior_value);
    // remaining holders' per-share claim never falls: c_after/(S-shares) >= c/S
    assert!(c_after * s >= c * (s - shares));
    if v >= c {
        // senior whole: the claim removed is exactly what was paid
        assert!(payout == slice);
    }
    let principal = senior_principal_portion(shares, avail, s, payout).unwrap();
    assert!(principal <= payout);
    kani::cover!(v >= c && shares > 0 && shares < s, "whole, partial redemption");
    kani::cover!(v < c && shares > 0, "impaired redemption");
    kani::cover!(shares == s && c > 0, "last redeemer");
    kani::cover!(principal < payout, "payout includes earnings");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_redemption_rejects_bad_inputs() {
    let s = u(kani::any());
    let shares = u(kani::any());
    let c = u(kani::any());
    let bad = s == 0 || shares > s;
    assert!(senior_atoms_for_redemption(shares, s, c).is_none() == bad);
    assert!(senior_claim_after_redemption(c, shares, s).is_none() == bad);
    kani::cover!(bad, "bad input");
    kani::cover!(!bad, "good input");
}

// ── Fee split / bps rounding ─────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_fee_split_and_bps_exact() {
    let fee: u64 = kani::any();
    let bps: u16 = kani::any();
    let x = fee as u128;
    let fl = bps_floor(x, bps);
    let ce = bps_ceil(x, bps);
    if bps as u128 > BPS {
        assert!(fl.is_none() && ce.is_none() && split_fee(x, bps).is_none());
    } else {
        let exact_num = x * bps as u128;
        assert!(fl.unwrap() == exact_num / BPS);
        assert!(ce.unwrap() == (exact_num + BPS - 1) / BPS);
        let (sen, jun) = split_fee(x, bps).unwrap();
        assert!(sen + jun == x);
        assert!(sen == fl.unwrap());
    }
    kani::cover!(bps as u128 > BPS, "invalid bps");
    kani::cover!(bps == 10_000 && fee > 0, "all to senior");
    kani::cover!(bps > 0 && bps < 10_000 && (x * bps as u128) % BPS != 0, "rounding case");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_effective_senior_claim() {
    let c: u64 = kani::any();
    let h: u64 = kani::any();
    let bps: u16 = kani::any();
    kani::assume(bps <= 10_000);
    let e = effective_senior_claim(c as u128, h as u128, bps).unwrap();
    assert!(e == c as u128 + (h as u128 * bps as u128) / BPS);
    assert!(e >= c as u128 && e <= c as u128 + h as u128);
    kani::cover!(h > 0 && bps == 10_000, "full harvest to senior");
}

// ── Junior withdraw / recall ─────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_junior_withdraw_keeps_floor_and_senior_backing() {
    let v = u(kani::any());
    let c = u(kani::any());
    let cover = u(kani::any());
    let amount = u(kani::any());
    let bps: u16 = kani::any();
    kani::assume(bps <= 10_000);
    // Processor shape: V = backing cover + max(0, LP value), so V >= cover always.
    kani::assume(v >= cover);
    if junior_withdraw_allowed(v, c, cover, amount, bps) {
        assert!(cover >= c);
        assert!(amount <= v);
        let post = tranche_split(v - amount, c);
        assert!(post.junior >= junior_floor_atoms(c, bps).unwrap());
        // the senior is still whole after the junior leaves
        assert!(post.senior == c);
    }
    kani::cover!(junior_withdraw_allowed(v, c, cover, amount, bps) && c > 0 && amount > 0, "allowed with seniors");
    kani::cover!(cover < c, "refused: senior not backed");
    kani::cover!(cover >= c && v > c && !junior_withdraw_allowed(v, c, cover, amount, bps), "refused: floor");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_recall_limit_exact() {
    let c: u64 = kani::any();
    let cover: u64 = kani::any();
    let l = recall_limit(c as u128, cover as u128);
    if cover < c {
        assert!(l == (c - cover) as u128);
        assert!(cover as u128 + l == c as u128);
    } else {
        assert!(l == 0);
    }
    kani::cover!(cover < c, "shortfall");
    kani::cover!(cover >= c, "no shortfall");
}

// ── Skew funding ─────────────────────────────────────────────────────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_skew_sign_bound_zero() {
    let lp: i16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u16 = kani::any();
    let max: u16 = kani::any();
    let r = skew_funding_rate_e9(lp as i128, oi as u128, slope as u64, max as u64);
    assert!(r.unsigned_abs() <= max as u128);
    assert!(r.unsigned_abs() <= slope as u128);
    if lp < 0 {
        assert!(r >= 0);
    }
    if lp > 0 {
        assert!(r <= 0);
    }
    if lp == 0 || slope == 0 || max == 0 || oi == 0 {
        assert!(r == 0);
    }
    kani::cover!(lp < 0 && r > 0, "LP short: longs pay");
    kani::cover!(lp > 0 && r < 0, "LP long: shorts pay");
    kani::cover!(r.unsigned_abs() == max as u128 && max > 0, "capped");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_skew_monotone_in_imbalance() {
    let a: u16 = kani::any();
    let b: u16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u16 = kani::any();
    let max: u16 = kani::any();
    kani::assume(a <= b);
    let neg: bool = kani::any();
    let (qa, qb) = if neg {
        (-(a as i128), -(b as i128))
    } else {
        (a as i128, b as i128)
    };
    let ra = skew_funding_rate_e9(qa, oi as u128, slope as u64, max as u64);
    let rb = skew_funding_rate_e9(qb, oi as u128, slope as u64, max as u64);
    assert!(ra.unsigned_abs() <= rb.unsigned_abs());
    kani::cover!(ra.unsigned_abs() < rb.unsigned_abs(), "strictly grows");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_combine_within_engine_bound() {
    let p: i128 = kani::any();
    let s: i128 = kani::any();
    let m: u64 = kani::any();
    let r = combine_funding_rate_e9(p, s, m);
    assert!(r.unsigned_abs() <= m as u128);
    if let Some(sum) = p.checked_add(s) {
        if sum.unsigned_abs() <= m as u128 {
            assert!(r == sum);
        }
    }
    kani::cover!(r == m as i128 && m > 0, "clamped high");
    kani::cover!(r == -(m as i128) && m > 0, "clamped low");
    kani::cover!(r != 0 && r.unsigned_abs() < m as u128, "passthrough");
}

/// Skew-funding CONSERVATION — over a MODEL of the engine formula, not the engine itself.
///
/// `V16Core::kernel_adl_scaled_accrual_index_deltas` is `pub(crate)` in the engine and cannot
/// be called from here. The model below transcribes engine `v16.rs` @ 35ddd692:
///   :14777-14782  funding_index_delta = floor_div(rate * dt * price, FUNDING_DEN)
///   :1626-1641    f_long = -(funding_index_delta * a_long); f_short = funding_index_delta * a_short
/// For a balanced book (q_long == q_short, a_long == a_short) the per-side F increments, each
/// scaled by that side's size, sum to zero for EVERY rate the wrapper can hand the engine
/// (`combine_funding_rate_e9` output). Settlement rounding of individual legs is NOT modelled.
// WITHDRAWN (Sentinel final pass, 2026-09-29): `kani_p3_skew_funding_zero_sum_model` proved
// zero-sum over a TRANSCRIPTION of the engine's per-side funding formula, i.e. it compared the
// model with itself — circular. The engine kernel (`kernel_adl_scaled_accrual_index_deltas`) is
// `pub(crate)` and cannot be called from here without an engine change, so no non-circular Kani
// proof of skew-funding conservation is claimed. What IS claimed, and where it is proven:
//   * the wrapper only hands the engine a rate inside `±max_abs_funding_e9_per_slot`
//     (`kani_p3_combine_within_engine_bound`, covers satisfied);
//   * sign / bound / zero-at-balance / monotonicity of the skew rate (the `kani_p3_skew_*`
//     harnesses);
//   * zero-sum of the transfer is MEASURED end to end through the real engine BPF in LiteSVM
//     (`p3_skew_funding_crowded_long_pays_vault_lp`: paid 600 == received 600;
//     `p3_skew_funding_identical_on_crank_and_trade_paths`: -60 / +60 on both paths), which is
//     empirical evidence, not a proof.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_step_imr_bounds_and_monotone() {
    let x: u16 = kani::any();
    let y: u16 = kani::any();
    let cap: u16 = kani::any();
    let base: u16 = kani::any();
    let max: u16 = kani::any();
    kani::assume(x <= y);
    let base = base as u64;
    let sx = step_imr_bps(x as u128, cap as u128, base, max);
    let sy = step_imr_bps(y as u128, cap as u128, base, max);
    assert!(sx >= base);
    assert!(sx <= core::cmp::max(base, max as u64));
    assert!(sx <= sy);
    kani::cover!(sx > base && sx < max as u64, "ramping");
    kani::cover!(sy == max as u64 && max as u64 > base, "at ceiling");
    kani::cover!(cap == 0, "disabled");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_leverage_gate_exact() {
    let equity = u(kani::any());
    let notional = u(kani::any());
    let imr: u16 = kani::any();
    let imr = imr as u64;
    let ok = leverage_gate_ok(equity, notional, imr);
    if imr > 10_000 {
        assert!(!ok);
    } else {
        let req = (notional * imr as u128 + 9_999) / 10_000;
        assert!(ok == (equity >= req));
        assert!(ok == (equity * 10_000 >= notional * imr as u128));
    }
    kani::cover!(ok && imr > 0 && notional > 0, "passes");
    kani::cover!(!ok && imr <= 10_000, "refused");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_conservative_equity() {
    let cap: u64 = kani::any();
    let pnl: i64 = kani::any();
    let fee: i64 = kani::any();
    let e = conservative_equity(cap as u128, pnl as i128, fee as i128).unwrap();
    let raw = cap as i128 + core::cmp::min(pnl as i128, 0) + core::cmp::min(fee as i128, 0);
    assert!(e == if raw <= 0 { 0 } else { raw as u128 });
    assert!(e <= cap as u128);
    kani::cover!(pnl > 0 && e == cap as u128 && fee >= 0, "positive pnl not credited");
    kani::cover!(e == 0 && cap > 0, "wiped");
}

// ── P3-H2 vault-LP exposure cap / P3-H1 resolved settlement split ──────────────────────────

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_h2_exposure_cap_exact_and_reducing_always_allowed() {
    let before: i16 = kani::any();
    let after: i16 = kani::any();
    let equity = u(kani::any());
    let lev: u16 = kani::any();
    let price: u16 = kani::any();
    let scale: u128 = 1_000; // bounded stand-in for POS_SCALE (same algebra)
    let ok = vault_lp_exposure_allowed(before as i128, after as i128, equity, lev as u32, price as u64, scale);
    if (after as i128).unsigned_abs() <= (before as i128).unsigned_abs() {
        assert!(ok, "a fill that does not grow |lp| is never refused");
    } else {
        let notional = (after as i128).unsigned_abs() * price as u128 / scale;
        assert!(ok == (notional <= equity * lev as u128 / 10_000));
    }
    kani::cover!(ok && (after as i128).unsigned_abs() > (before as i128).unsigned_abs(), "growth admitted");
    kani::cover!(!ok, "growth refused");
    kani::cover!(ok && (after as i128).unsigned_abs() < (before as i128).unsigned_abs() && equity == 0, "reduce with zero equity");
}

#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_h1_resolved_split_conserves_and_is_senior_first() {
    let payout: u64 = kani::any();
    let c: u64 = kani::any();
    let nav: u64 = kani::any();
    let (p, c, n) = (payout as u128, c as u128, nav as u128);
    let (to_backing, to_junior) = resolved_settle_split(p, c, n);
    assert!(to_backing + to_junior == p, "conservation");
    let shortfall = if c > n { c - n } else { 0 };
    assert!(to_backing <= shortfall, "never over-refills the seniors");
    if to_junior > 0 {
        assert!(n + to_backing >= c, "junior paid only once seniors are fully backed");
    }
    kani::cover!(to_backing > 0 && to_junior > 0, "partial refill then junior");
    kani::cover!(to_junior == 0 && p > 0, "all to seniors");
    kani::cover!(to_backing == 0 && p > 0, "seniors covered, all to junior");
}

// ── Auto-pin: caps invariant at bind time (tag 94) ───────────────────────────────────────

/// For ANY positive price, the caps tag 94 pins are FINITE and NON-ZERO (0 = unlimited to the
/// matcher, so it must never be pinned), bounded by the engine position bound, ordered
/// (fill <= inventory), and never exceed their USD notional at that price
/// (q * price <= usd * 1e12). A price for which a cap would round to 0 fails closed (None).
/// Price is u32 (up to $4,294 e6); the production function takes u64.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_p3_autopin_caps_finite_nonzero_bounded() {
    let price: u32 = kani::any();
    kani::assume(price > 0);
    let r = pinned_matcher_caps(price as u64);
    kani::cover!(r.is_some(), "caps pinned");
    kani::cover!(
        r.map(|c| c.max_inventory_abs == ENGINE_MAX_POSITION_ABS_Q).unwrap_or(false),
        "tiny price clamps to the engine bound"
    );
    if let Some(c) = r {
        assert!(c.max_fill_abs > 0 && c.max_inventory_abs > 0);
        assert!(c.max_fill_abs <= ENGINE_MAX_POSITION_ABS_Q);
        assert!(c.max_inventory_abs <= ENGINE_MAX_POSITION_ABS_Q);
        assert!(c.max_fill_abs <= c.max_inventory_abs);
        assert!(c.max_fill_abs * price as u128 <= PIN_MAX_FILL_USD * 1_000_000_000_000);
        assert!(c.max_inventory_abs * price as u128 <= PIN_MAX_INVENTORY_USD * 1_000_000_000_000);
        assert_eq!(c.liquidity_notional_e6, PIN_LIQUIDITY_USD * 1_000_000);
    }
}
