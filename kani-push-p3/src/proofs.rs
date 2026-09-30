//! Kani push 2026-09-30 (Anvil) — P3 tranche waterfall, share rounding, skew funding.
//!
//! Complements the builder's `kani/p3/src/proofs.rs` (static split properties, u16-bounded
//! share math). These harnesses add:
//!  - TRANSITION properties of the waterfall (a loss/gain moves junior first), at full u128;
//!  - flow neutrality: a deposit and a fee crank never move value into or out of the junior;
//!  - share rounding at full u64 width, incl. the deposit->redeem round trip;
//!  - skew-funding conservation through the REAL engine kernel
//!    (`percolator::kani_adl_scaled_accrual_index_deltas`, the engine's own cfg(kani) shim) and
//!    the engine's own signed floor, for ASYMMETRIC per-side A (the builder's model fixes
//!    a_long == a_short, which makes zero-sum hold by construction).
//! Every harness declares covers; SUCCESSFUL counts only with every cover SATISFIED.

use crate::vault_lp_v18::*;
use percolator::wide_math::floor_div_signed_conservative_i128;
use percolator::{FUNDING_DEN, MIN_A_SIDE, ADL_ONE, POS_SCALE};

// ── Waterfall transitions ────────────────────────────────────────────────────────────────

/// JUNIOR ABSORBS FIRST; SENIOR NEVER LOSES WHILE JUNIOR > 0. For any vault value V, senior
/// claim C and loss L <= V: the senior loses exactly max(0, L - junior) and the junior exactly
/// min(L, junior). So while the junior covers the loss the senior is untouched, and the senior
/// is hit only by the excess. Full u128.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_loss_hits_junior_first_full_width() {
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let loss: u128 = kani::any();
    kani::assume(loss <= v);
    let b = tranche_split(v, c);
    let a = tranche_split(v - loss, c);
    // conservation on both sides
    assert_eq!(b.senior + b.junior, v);
    assert_eq!(a.senior + a.junior, v - loss);
    let junior_loss = b.junior - a.junior;
    let senior_loss = b.senior - a.senior;
    assert_eq!(junior_loss + senior_loss, loss);
    assert_eq!(junior_loss, core::cmp::min(loss, b.junior));
    assert_eq!(senior_loss, loss.saturating_sub(b.junior));
    if loss <= b.junior {
        assert_eq!(a.senior, b.senior);
    }
    kani::cover!(loss > 0 && loss <= b.junior && c > 0, "loss fully absorbed by junior");
    kani::cover!(b.junior > 0 && loss > b.junior, "junior wiped, senior takes the excess");
    kani::cover!(b.junior == 0 && loss > 0, "impaired vault: senior takes it all");
}

/// A GAIN goes to the junior while the senior is whole, and first restores an impaired senior.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_gain_restores_senior_first_full_width() {
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let gain: u128 = kani::any();
    kani::assume(v.checked_add(gain).is_some());
    let b = tranche_split(v, c);
    let a = tranche_split(v + gain, c);
    assert!(a.senior >= b.senior && a.junior >= b.junior);
    let senior_gain = a.senior - b.senior;
    assert_eq!(senior_gain, core::cmp::min(gain, c - b.senior));
    assert_eq!(a.junior - b.junior, gain - senior_gain);
    kani::cover!(b.senior < c && a.senior == c && a.junior > 0, "restores senior, rest to junior");
    kani::cover!(b.senior < c && a.senior < c && gain > 0, "partial restore");
}

/// FLOW NEUTRALITY 1 — a (non-impaired) Earn deposit never changes the junior: V and C both
/// rise by `amount`. (Impaired deposits are refused by the processor: `senior_impaired`.)
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_never_moves_junior() {
    let v: u128 = kani::any();
    let c: u128 = kani::any();
    let amount: u128 = kani::any();
    kani::assume(v.checked_add(amount).is_some() && c.checked_add(amount).is_some());
    kani::assume(!senior_impaired(v, c));
    let b = tranche_split(v, c);
    let a = tranche_split(v + amount, c + amount);
    assert_eq!(a.junior, b.junior);
    assert_eq!(a.senior, b.senior + amount);
    kani::cover!(amount > 0 && b.junior > 0, "deposit next to a live junior");
}

/// FLOW NEUTRALITY 2 — the LP fee crank (tag 78) is value-neutral for BOTH tranches: before the
/// crank the harvestable leg H sits in V and its senior part is priced into C_eff; after, H is
/// in backing (V unchanged) and C grows by exactly `split_fee(H).senior`. So the split, and hence
/// the price of a senior share, is identical either side of the crank.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_fee_crank_is_tranche_neutral() {
    let backing: u64 = kani::any();
    let lp_value: u64 = kani::any();
    let h: u64 = kani::any();
    let c: u64 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s_bps <= 10_000);
    let (backing, lp_value, h, c) = (backing as u128, lp_value as u128, h as u128, c as u128);
    // before: H still harvestable
    let v0 = vault_value(backing, h, lp_value).unwrap();
    let ce0 = effective_senior_claim(c, h, s_bps).unwrap();
    let before = tranche_split(v0, ce0);
    // crank: H moves into backing, C += senior part
    let (senior_part, junior_part) = split_fee(h, s_bps).unwrap();
    assert_eq!(senior_part + junior_part, h);
    let v1 = vault_value(backing + h, 0, lp_value).unwrap();
    let ce1 = effective_senior_claim(c + senior_part, 0, s_bps).unwrap();
    let after = tranche_split(v1, ce1);
    assert_eq!(v0, v1);
    assert_eq!(before, after);
    kani::cover!(h > 0 && s_bps > 0 && s_bps < 10_000 && before.junior > 0, "crank with both tranches live");
}

/// CLAIM TEST (expected FAIL on c7437518; a finding, not a proof bug). Redemption crank-timing
/// neutrality: a senior who redeems BEFORE the fee crank is paid the same as one who redeems
/// right AFTER it. Deposit pricing uses C_eff = C + senior part of the harvestable leg
/// (v16_program.rs ~22436), but redemption pricing uses the RAW claim C (senior_value = C when
/// nav >= C, ~23272), so a redeemer who does not crank first forfeits their pro-rata part of
/// the pending senior fee to the holders who stay.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_redemption_is_crank_timing_neutral() {
    let c: u16 = kani::any();
    let h: u16 = kani::any();
    let s: u16 = kani::any();
    let shares: u16 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s > 0 && shares > 0 && shares <= s && s_bps <= 10_000);
    let (c, h, s, shares) = (c as u128, h as u128, s as u128, shares as u128);
    // senior whole (nav >= C): processor pays against C
    let before_crank = senior_atoms_for_redemption(shares, s, c).unwrap();
    let (senior_part, _) = split_fee(h, s_bps).unwrap();
    let after_crank = senior_atoms_for_redemption(shares, s, c + senior_part).unwrap();
    kani::cover!(senior_part > 0, "pending senior fee");
    assert_eq!(before_crank, after_crank);
}

// ── Share rounding, full u64 width ───────────────────────────────────────────────────────

/// DEPOSIT never favours the depositor over the vault, at u64 width: the minted shares are
/// at most the exact pro-rata amount, and the per-share senior value never falls.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_rounding_favours_vault_u64() {
    let amount: u64 = kani::any();
    let s: u64 = kani::any();
    let senior: u64 = kani::any();
    kani::assume(s > 0 && senior > 0);
    let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
    let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
    // minted * senior <= amount * s  (never over-mints); both products < 2^128
    assert!(minted * senior <= amount * s);
    // tight: one more share would over-mint
    assert!((minted + 1) * senior > amount * s);
    kani::cover!(minted > 0 && (amount * s) % senior != 0, "rounded down");
}

/// REDEMPTION never favours the redeemer, at u64 width: payout <= exact pro-rata, and the
/// remaining holders' per-share senior value never falls.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_redemption_rounding_favours_vault_u64() {
    let shares: u64 = kani::any();
    let s: u64 = kani::any();
    let senior: u64 = kani::any();
    kani::assume(s > 0 && shares <= s);
    let (shares, s, senior) = (shares as u128, s as u128, senior as u128);
    let paid = senior_atoms_for_redemption(shares, s, senior).unwrap();
    assert!(paid * s <= shares * senior);
    assert!(paid <= senior);
    // remaining per-share value: (senior - paid)/(s - shares) >= senior/s
    assert!((senior - paid) * s >= senior * (s - shares));
    kani::cover!(shares > 0 && shares < s && (shares * senior) % s != 0, "rounded down");
}

/// ROUND TRIP: deposit `amount` then immediately redeem the minted shares (senior whole, no
/// other flow) never returns more than `amount`. u32 amounts/shares/values.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_redeem_round_trip_never_profits() {
    let amount: u32 = kani::any();
    let s: u32 = kani::any();
    let senior: u32 = kani::any();
    kani::assume(s > 0 && senior > 0);
    let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
    let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
    let s2 = s + minted;
    let senior2 = senior + amount; // C += amount, V += amount, not impaired
    let back = senior_atoms_for_redemption(minted, s2, senior2).unwrap();
    assert!(back <= amount);
    kani::cover!(minted > 0 && back < amount, "round trip loses dust to the vault");
    kani::cover!(minted > 0 && back == amount, "exact round trip");
}

// ── Skew funding conservation through the real engine kernel ─────────────────────────────

/// SKEW FUNDING IS ZERO-SUM (conservative). The wrapper's combined rate (premium + skew,
/// clamped) is turned into a funding index delta by the engine formula (v16.rs:14777-14782,
/// the engine's own `floor_div_signed_conservative_i128`), then into per-side F deltas by the
/// REAL engine kernel `kani_adl_scaled_accrual_index_deltas`, for ANY per-side A in
/// [MIN_A_SIDE, ADL_ONE] (asymmetric after ADL). Two matched legs of equal effective size,
/// each settled as `floor(q * dF / (a_side * POS_SCALE))` (the engine's realize rule, with
/// a_basis = the live side A), sum to a value in [-1, 0]: funding never mints, and destroys at
/// most one atom of rounding dust. Also: the crowded side pays.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_through_engine_kernel() {
    let premium: i16 = kani::any();
    let lp_net: i32 = kani::any();
    let oi: u32 = kani::any();
    let slope: u16 = kani::any();
    let cap: u16 = kani::any();
    let max_abs: u16 = kani::any();
    let dt: u8 = kani::any();
    let price: u32 = kani::any();
    let q: u16 = kani::any();
    let a_long: u128 = kani::any();
    let a_short: u128 = kani::any();
    kani::assume(a_long >= MIN_A_SIDE && a_long <= ADL_ONE);
    kani::assume(a_short >= MIN_A_SIDE && a_short <= ADL_ONE);
    kani::assume(price > 0);

    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    assert!(rate.unsigned_abs() <= max_abs as u128);
    let n = rate * dt as i128 * price as i128;
    let fid = floor_div_signed_conservative_i128(n, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);

    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    assert!(net <= 0 && net >= -1);
    // the crowded side pays: vault LP short (traders long) and no premium => longs pay
    if premium == 0 && lp_net < 0 && fid > 0 && q > 0 {
        assert!(long_pnl <= 0 && short_pnl >= 0);
    }
    kani::cover!(a_long != a_short && fid != 0 && q > 0 && long_pnl != 0, "asymmetric-A transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
}

/// Bounded companion of the harness above (in case the full symbolic A does not finish): the
/// per-side A ranges over the ten asymmetric grid points k·MIN_A_SIDE (k = 1..=10, i.e. 0.1 ..
/// 1.0 of ADL_ONE) and the size/price/rate fields are narrower. Same assertions, same kernel.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_grid_a() {
    let premium: i8 = kani::any();
    let lp_net: i16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u8 = kani::any();
    let cap: u8 = kani::any();
    let max_abs: u8 = kani::any();
    let dt: u8 = kani::any();
    let price: u16 = kani::any();
    let q: u8 = kani::any();
    let kl: u8 = kani::any();
    let ks: u8 = kani::any();
    kani::assume(kl >= 1 && kl <= 10 && ks >= 1 && ks <= 10 && price > 0);
    let a_long = MIN_A_SIDE * kl as u128;
    let a_short = MIN_A_SIDE * ks as u128;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(kl != ks && fid != 0 && q > 0 && long_pnl != 0, "asymmetric-A transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}

/// u32 companion of `kani_push_p3_fee_crank_is_tranche_neutral` (same assertions).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_fee_crank_is_tranche_neutral_u32() {
    let backing: u32 = kani::any();
    let lp_value: u32 = kani::any();
    let h: u32 = kani::any();
    let c: u32 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s_bps <= 10_000);
    let (backing, lp_value, h, c) = (backing as u128, lp_value as u128, h as u128, c as u128);
    let v0 = vault_value(backing, h, lp_value).unwrap();
    let ce0 = effective_senior_claim(c, h, s_bps).unwrap();
    let before = tranche_split(v0, ce0);
    let (senior_part, junior_part) = split_fee(h, s_bps).unwrap();
    let v1 = vault_value(backing + h, 0, lp_value).unwrap();
    let ce1 = effective_senior_claim(c + senior_part, 0, s_bps).unwrap();
    let after = tranche_split(v1, ce1);
    kani::cover!(h > 0 && s_bps > 0 && s_bps < 10_000 && before.junior > 0, "crank with both tranches live");
    assert_eq!(senior_part + junior_part, h);
    assert_eq!(v0, v1);
    assert_eq!(before, after);
}

/// u16 companion of the round trip (symbolic u128 division is the solver bottleneck; the
/// builder's share harnesses use the same width).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_redeem_round_trip_u16() {
    let amount: u16 = kani::any();
    let s: u16 = kani::any();
    let senior: u16 = kani::any();
    kani::assume(s > 0 && senior > 0);
    let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
    let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
    let back = senior_atoms_for_redemption(minted, s + minted, senior + amount).unwrap();
    kani::cover!(minted > 0 && back < amount, "round trip loses dust to the vault");
    kani::cover!(minted > 0 && back == amount, "exact round trip");
    assert!(back <= amount);
}

/// u16-fee companion of the fee-crank neutrality proof: the 128-bit dividers inside
/// `bps_floor` are the solver bottleneck, so the harvestable leg is u16 (values u32).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_fee_crank_is_tranche_neutral_h16() {
    let backing: u32 = kani::any();
    let lp_value: u32 = kani::any();
    let h: u16 = kani::any();
    let c: u32 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s_bps <= 10_000);
    let (backing, lp_value, h, c) = (backing as u128, lp_value as u128, h as u128, c as u128);
    let v0 = vault_value(backing, h, lp_value).unwrap();
    let ce0 = effective_senior_claim(c, h, s_bps).unwrap();
    let before = tranche_split(v0, ce0);
    let (senior_part, junior_part) = split_fee(h, s_bps).unwrap();
    let v1 = vault_value(backing + h, 0, lp_value).unwrap();
    let ce1 = effective_senior_claim(c + senior_part, 0, s_bps).unwrap();
    let after = tranche_split(v1, ce1);
    kani::cover!(h > 0 && s_bps > 0 && s_bps < 10_000 && before.junior > 0, "crank with both tranches live");
    assert_eq!(senior_part + junior_part, h);
    assert_eq!(v0, v1);
    assert_eq!(before, after);
}

/// Audit fix for `_grid_a` (its negative control SURVIVED: with u8/u16 magnitudes the funding
/// index delta is ≤ 4, so even the flat-A bug rounds to [-1, 0] and the grid domain cannot see
/// the bug class). Here the per-side A is a fixed ASYMMETRIC pair (0.3 vs 1.0 of ADL_ONE; the
/// constant divisors keep CBMC tractable) and the magnitudes are realistic: rate up to the
/// u16 bound, dt up to 65 535 slots, e6 price up to 4.29e9, |q| up to 4.29e9 Q.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_fixed_asym_a() {
    let premium: i16 = kani::any();
    let lp_net: i32 = kani::any();
    let oi: u32 = kani::any();
    let slope: u16 = kani::any();
    let cap: u16 = kani::any();
    let max_abs: u16 = kani::any();
    let dt: u16 = kani::any();
    let price: u32 = kani::any();
    let q: u32 = kani::any();
    kani::assume(price > 0);
    let a_long = MIN_A_SIDE * 3;
    let a_short = ADL_ONE;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    // NEGATIVE CONTROL (feature neg_flat_a): the pre-#114 engine bug, flat ADL_ONE per side.
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(fid != 0 && long_pnl < -1_000, "material transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}

// ── Release-gate set (2026-09-30 02:00): widths chosen so CBMC finishes on this machine. ──
// Every 128-bit symbolic-divisor harness above u8 timed out at 30-45 min (see the ledger); the
// production functions are unchanged (u128 internally), only the symbolic INPUT range shrinks.
// Rounding-direction and operand-order bugs are width-independent and show at u8 (the negative
// controls below prove the harnesses can see them).

/// SHARE ROUNDING — DEPOSIT never favours the depositor (u8 inputs, production u128 math).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_rounding_favours_vault_u8() {
    let amount: u8 = kani::any();
    let s: u8 = kani::any();
    let senior: u8 = kani::any();
    kani::assume(s > 0 && senior > 0);
    let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
    let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
    kani::cover!(minted > 0 && (amount * s) % senior != 0, "rounded down");
    assert!(minted * senior <= amount * s); // never over-mints
    assert!((minted + 1) * senior > amount * s); // floor, not worse
    // price per share never falls: (senior+amount)/(s+minted) >= senior/s
    assert!((senior + amount) * s >= senior * (s + minted));
}

/// SHARE ROUNDING — REDEMPTION never favours the redeemer (u8 inputs).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_redemption_rounding_favours_vault_u8() {
    let shares: u8 = kani::any();
    let s: u8 = kani::any();
    let senior: u8 = kani::any();
    kani::assume(s > 0 && shares <= s);
    let (shares, s, senior) = (shares as u128, s as u128, senior as u128);
    let paid = senior_atoms_for_redemption(shares, s, senior).unwrap();
    kani::cover!(shares > 0 && shares < s && (shares * senior) % s != 0, "rounded down");
    assert!(paid * s <= shares * senior);
    assert!((senior - paid) * s >= senior * (s - shares));
}

/// ROUND TRIP: deposit then immediately redeem the minted shares never returns more than paid.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_deposit_redeem_round_trip_u8() {
    let amount: u8 = kani::any();
    let s: u8 = kani::any();
    let senior: u8 = kani::any();
    kani::assume(s > 0 && senior > 0);
    let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
    let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
    let back = senior_atoms_for_redemption(minted, s + minted, senior + amount).unwrap();
    kani::cover!(minted > 0 && back < amount, "round trip loses dust to the vault");
    kani::cover!(minted > 0 && back == amount, "exact round trip");
    assert!(back <= amount);
}

/// NAV CONSERVATION through the fee crank (tag 78): value-neutral for BOTH tranches (u8 fee,
/// u16 values).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_fee_crank_is_tranche_neutral_h8() {
    let backing: u16 = kani::any();
    let lp_value: u16 = kani::any();
    let h: u8 = kani::any();
    let c: u16 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s_bps <= 10_000);
    let (backing, lp_value, h, c) = (backing as u128, lp_value as u128, h as u128, c as u128);
    let v0 = vault_value(backing, h, lp_value).unwrap();
    let ce0 = effective_senior_claim(c, h, s_bps).unwrap();
    let before = tranche_split(v0, ce0);
    let (senior_part, junior_part) = split_fee(h, s_bps).unwrap();
    let v1 = vault_value(backing + h, 0, lp_value).unwrap();
    let ce1 = effective_senior_claim(c + senior_part, 0, s_bps).unwrap();
    let after = tranche_split(v1, ce1);
    kani::cover!(h > 0 && s_bps > 0 && s_bps < 10_000 && before.junior > 0 && senior_part > 0, "crank with both tranches live");
    assert_eq!(senior_part + junior_part, h);
    assert_eq!(before.senior + before.junior, v0);
    assert_eq!(v0, v1);
    assert_eq!(before, after);
}

/// SKEW FUNDING ZERO-SUM, non-circular and able to see the bug class: real wrapper rate
/// functions -> engine fid formula -> REAL engine kernel with a FIXED ASYMMETRIC A pair
/// (0.3 vs 1.0 of ADL_ONE) -> engine signed floor settlement. Magnitudes are large enough that
/// the flat-A (#114) bug mints value (negative control), small enough for CBMC.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_asym_a_small() {
    let premium: i8 = kani::any();
    let lp_net: i16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u8 = kani::any();
    let cap: u8 = kani::any();
    let max_abs: u8 = kani::any();
    let dt: u8 = kani::any();
    let price: u32 = kani::any();
    let q: u16 = kani::any();
    kani::assume(price > 0);
    let a_long = MIN_A_SIDE * 3;
    let a_short = ADL_ONE;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let q = q as i128;
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(fid != 0 && long_pnl < -10, "material transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
    if premium == 0 && lp_net < 0 && fid > 0 && q > 0 {
        assert!(long_pnl <= 0 && short_pnl >= 0); // crowded side pays
    }
}

/// SKEW FUNDING ZERO-SUM with FEW symbolic bits but LARGE magnitudes (so the flat-A #114 bug is
/// visible, unlike `_grid_a`): size q = q8 * 10_000 Q, price = p16 * 1_000 e6, per-side A on
/// the asymmetric grid k·MIN_A_SIDE. Real wrapper rate fns -> engine fid formula -> REAL engine
/// kernel -> engine signed floor settlement.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_scaled() {
    let premium: i8 = kani::any();
    let lp_net: i16 = kani::any();
    let oi: u16 = kani::any();
    let slope: u8 = kani::any();
    let cap: u8 = kani::any();
    let max_abs: u8 = kani::any();
    let dt: u8 = kani::any();
    let p16: u16 = kani::any();
    let q8: u8 = kani::any();
    let kl: u8 = kani::any();
    let ks: u8 = kani::any();
    kani::assume(kl >= 1 && kl <= 10 && ks >= 1 && ks <= 10 && p16 > 0);
    let a_long = MIN_A_SIDE * kl as u128;
    let a_short = MIN_A_SIDE * ks as u128;
    let price = p16 as i128 * 1_000;
    let q = q8 as i128 * 10_000;
    let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
    let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(kl != ks && fid != 0 && long_pnl < -1, "asymmetric-A material transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}

// ── Lemma form (2026-09-30 03:50). The share-rounding claims reduce EXACTLY to the floor
// property of the two pricing functions, because
//   (senior+amount)*S - senior*(S+minted) = amount*S - senior*minted          (deposit)
//   (senior-paid)*S   - senior*(S-shares) = shares*senior - paid*S            (redemption)
//   minted*(senior+amount) <= amount*(S+minted)  <=>  minted*senior <= amount*S  (round trip)
// so "price per share never falls", "redeemer never over-paid" and "round trip <= deposit" are
// algebraic corollaries of L1/L2 below. The solver cannot see the distributivity, which is why
// the whole-claim harnesses time out; the lemmas avoid it. Split into sub-ranges so they run in
// parallel.
macro_rules! floor_lemmas {
    ($dep:ident, $red:ident, $t:ty) => {
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $dep() {
            let amount: $t = kani::any();
            let s: $t = kani::any();
            let senior: $t = kani::any();
            kani::assume(s > 0 && senior > 0);
            let (amount, s, senior) = (amount as u128, s as u128, senior as u128);
            let minted = senior_shares_for_deposit(amount, s, senior).unwrap();
            kani::cover!(minted > 0 && (amount * s) % senior != 0, "rounded down");
            assert!(minted * senior <= amount * s); // L1a: never over-mints (=> price never falls)
            assert!((minted + 1) * senior > amount * s); // L1b: exactly floor
        }
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $red() {
            let shares: $t = kani::any();
            let s: $t = kani::any();
            let senior: $t = kani::any();
            kani::assume(s > 0 && shares <= s);
            let (shares, s, senior) = (shares as u128, s as u128, senior as u128);
            let paid = senior_atoms_for_redemption(shares, s, senior).unwrap();
            kani::cover!(shares > 0 && (shares * senior) % s != 0, "rounded down");
            assert!(paid * s <= shares * senior); // L2a: never over-pays (=> stayers never diluted)
            assert!((paid + 1) * s > shares * senior); // L2b: exactly floor
        }
    };
}
floor_lemmas!(kani_push_p3_lemma_deposit_floor_u8, kani_push_p3_lemma_redeem_floor_u8, u8);
floor_lemmas!(kani_push_p3_lemma_deposit_floor_u16, kani_push_p3_lemma_redeem_floor_u16, u16);
floor_lemmas!(kani_push_p3_lemma_deposit_floor_u32, kani_push_p3_lemma_redeem_floor_u32, u32);
floor_lemmas!(kani_push_p3_lemma_deposit_floor_u64, kani_push_p3_lemma_redeem_floor_u64, u64);

/// L3 (NAV / crank neutrality lemma): the fee crank's senior part is exactly the senior share
/// priced into C_eff beforehand, and the two parts sum to the fee — full u128. With L3 the crank
/// is tranche-neutral by additions alone (V unchanged; C_eff unchanged).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_lemma_crank_senior_part_full() {
    let c: u128 = kani::any();
    let h: u128 = kani::any();
    let s_bps: u16 = kani::any();
    kani::assume(s_bps <= 10_000);
    let (sp, jp) = split_fee(h, s_bps).unwrap();
    let ce0 = effective_senior_claim(c, h, s_bps);
    kani::cover!(sp > 0 && jp > 0, "both parts non-zero");
    assert_eq!(sp + jp, h);
    if let Some(ce0) = ce0 {
        assert_eq!(ce0, c + sp); // C_eff before == C + senior part credited by the crank
        assert_eq!(effective_senior_claim(c + sp, 0, s_bps), Some(ce0)); // == C_eff after
    }
}

// Sub-range split of `_scaled` (its clean run hit 2400 s): the per-side A pair is fixed per
// harness (constant divisors), everything else as in `_scaled`. Pairs cover both asymmetry
// directions and the extremes (0.1 and 1.0 of ADL_ONE).
macro_rules! skew_scaled_fixed {
    ($name:ident, $kl:expr, $ks:expr) => {
        #[kani::proof]
        #[kani::solver(kissat)]
        fn $name() {
            let premium: i8 = kani::any();
            let lp_net: i16 = kani::any();
            let oi: u16 = kani::any();
            let slope: u8 = kani::any();
            let cap: u8 = kani::any();
            let max_abs: u8 = kani::any();
            let dt: u8 = kani::any();
            let p16: u16 = kani::any();
            let q8: u8 = kani::any();
            kani::assume(p16 > 0);
            let a_long = MIN_A_SIDE * $kl;
            let a_short = MIN_A_SIDE * $ks;
            let price = p16 as i128 * 1_000;
            let q = q8 as i128 * 10_000;
            let skew = skew_funding_rate_e9(lp_net as i128, oi as u128, slope as u64, cap as u64);
            let rate = combine_funding_rate_e9(premium as i128, skew, max_abs as u64);
            let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price, FUNDING_DEN);
            let (_kl, _ks, f_long, f_short) =
                percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
            #[cfg(feature = "neg_flat_a")]
            let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
            let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
            let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
            let net = long_pnl + short_pnl;
            kani::cover!(fid != 0 && long_pnl < -1, "material transfer");
            kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
            assert!(net <= 0 && net >= -1);
        }
    };
}
skew_scaled_fixed!(kani_push_p3_skew_scaled_a_3_10, 3u128, 10u128);
skew_scaled_fixed!(kani_push_p3_skew_scaled_a_10_3, 10u128, 3u128);
skew_scaled_fixed!(kani_push_p3_skew_scaled_a_1_10, 1u128, 10u128);
skew_scaled_fixed!(kani_push_p3_skew_scaled_a_7_2, 7u128, 2u128);

/// SKEW FUNDING ZERO-SUM, tractable AND bug-sensitive: same pipeline as `_scaled`
/// (real wrapper rate fns -> engine fid formula -> REAL engine kernel -> engine signed floor), with
/// 8-bit symbolic factors and constant scale-ups so that |q * fid| reaches ~4e7 (above the
/// ~1e6 needed for the flat-A #114 bug to mint), and per-side A on the asymmetric grid.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_skew_funding_conserves_mid() {
    let premium: i8 = kani::any();
    let lp_net: i8 = kani::any();
    let oi: u8 = kani::any();
    let slope: u8 = kani::any();
    let cap: u8 = kani::any();
    let max_abs: u8 = kani::any();
    let dt: u8 = kani::any();
    let p8: u8 = kani::any();
    let q8: u8 = kani::any();
    let kl: u8 = kani::any();
    let ks: u8 = kani::any();
    kani::assume(kl >= 1 && kl <= 10 && ks >= 1 && ks <= 10 && p8 > 0);
    let a_long = MIN_A_SIDE * kl as u128;
    let a_short = MIN_A_SIDE * ks as u128;
    let price = p8 as i128 * 1_000_000; // $1 .. $255
    let q = q8 as i128 * 10_000;
    let skew = skew_funding_rate_e9(lp_net as i128 * 1_000, oi as u128 * 1_000, slope as u64 * 100, cap as u64 * 100);
    let rate = combine_funding_rate_e9(premium as i128 * 100, skew, max_abs as u64 * 100);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price, FUNDING_DEN);
    let (_kl, _ks, f_long, f_short) =
        percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short).unwrap();
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    let long_pnl = floor_div_signed_conservative_i128(q * f_long, a_long * POS_SCALE);
    let short_pnl = floor_div_signed_conservative_i128(q * f_short, a_short * POS_SCALE);
    let net = long_pnl + short_pnl;
    kani::cover!(kl != ks && fid != 0 && long_pnl < -1, "asymmetric-A material transfer");
    kani::cover!(skew != 0 && premium == 0 && long_pnl < 0, "skew alone moves value");
    assert!(net <= 0 && net >= -1);
}

/// SKEW ZERO-SUM, lemma K (full width): the REAL engine kernel scales each side's funding index
/// delta by THAT side's live A: `F_long = -fid*a_long`, `F_short = +fid*a_short`, for any fid the
/// wrapper's clamped rate can produce and any A in [MIN_A_SIDE, ADL_ONE]. With the engine's realize
/// rule `floor(q*dF/(a_basis*POS_SCALE))` and a_basis = the side's live A, each matched leg of size
/// q then realizes exactly floor(-q*fid/POS_SCALE) resp. floor(q*fid/POS_SCALE), whose sum is in
/// [-1, 0] (floor(x) + floor(-x) ∈ {-1, 0}). The flat-A (#114) bug is exactly a violation of K.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p3_lemma_engine_kernel_scales_funding_per_side() {
    let premium: i64 = kani::any();
    let skew: i64 = kani::any();
    let max_abs: u32 = kani::any();
    let dt: u32 = kani::any();
    let price: u64 = kani::any();
    kani::assume(price as u128 <= percolator::MAX_ORACLE_PRICE as u128);
    let rate = combine_funding_rate_e9(premium as i128, skew as i128, max_abs as u64);
    let fid = floor_div_signed_conservative_i128(rate * dt as i128 * price as i128, FUNDING_DEN);
    let a_long: u128 = kani::any();
    let a_short: u128 = kani::any();
    kani::assume(a_long >= MIN_A_SIDE && a_long <= ADL_ONE);
    kani::assume(a_short >= MIN_A_SIDE && a_short <= ADL_ONE);
    let r = percolator::kani_adl_scaled_accrual_index_deltas(0, fid, a_long, a_short);
    kani::cover!(r.is_ok() && a_long != a_short && fid != 0, "asymmetric A, non-zero funding");
    let (_kl, _ks, f_long, f_short) = r.unwrap();
    #[cfg(feature = "neg_flat_a")]
    let (f_long, f_short) = (-(fid * ADL_ONE as i128), fid * ADL_ONE as i128);
    assert_eq!(f_long, -(fid * a_long as i128));
    assert_eq!(f_short, fid * a_short as i128);
}

// ── Solver diagnostics (2026-09-30 03:00): the smallest division lemma, three solvers. ──
fn diag_body() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let d: u8 = kani::any();
    kani::assume(d > 0);
    let r = mul_div_floor(a as u128, b as u128, d as u128).unwrap();
    kani::cover!(r > 0 && (a as u128 * b as u128) % d as u128 != 0, "non-exact");
    assert!(r * d as u128 <= a as u128 * b as u128);
}
#[kani::proof]
#[kani::solver(cadical)]
fn kani_diag_muldiv_u8_cadical() { diag_body() }
#[kani::proof]
#[kani::solver(kissat)]
fn kani_diag_muldiv_u8_kissat() { diag_body() }
#[kani::proof]
#[kani::solver(minisat)]
fn kani_diag_muldiv_u8_minisat() { diag_body() }
