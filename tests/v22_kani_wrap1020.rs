//! v22kani 2026-10-20, agent WRAP: Kani harnesses for the wrapper S1 fixes landed after 48f0ced2
//! (head 4d69ee52). cfg(kani) only; every harness calls the REAL public production function(s) that
//! carry the fix's decision or arithmetic. The fixes themselves sit inside private `processor`
//! handlers that no harness crate can call; see ~/wt-v22kani-1020/reports/WRAP.md section 2 for the
//! per-fix scope (what each harness proves, and what only the native LiteSVM tests can see).
//!
//! Run: cargo kani --tests --features devnet -Z function-contracts -Z stubbing --exact --harness <name>
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use core::mem::{offset_of, size_of};
use percolator::{
    PortfolioAccountV16Account, PortfolioLegV16Account, V16PodI128, V16PodU128, V16PodU32, V16PodU64,
    POS_SCALE, PORTFOLIO_LEG_V16_EMPTY_ACCOUNT, V16_MAX_PORTFOLIO_ASSETS_N,
};
use percolator_prog::bond_v20::{bond_withdraw_lock_ok, tranche_split3};
use percolator_prog::constants::{
    HEADER_LEN, KIND_PORTFOLIO, MAGIC, PORTFOLIO_ACCOUNT_LEN, PORTFOLIO_MATCHER_CONTROL_OFF, VERSION,
};
use percolator_prog::growth_v19::n_cap_q;
use percolator_prog::state;
use percolator_prog::vault_lp_v18::creator_fee_vested;

const EPOCH_MAX: u64 = (1u64 << 49) - 1;

/// 16-byte-aligned backing (as a real account's data region), so the production `bytemuck`
/// view is never refused for alignment; callers use `&mut buf[..PORTFOLIO_ACCOUNT_LEN]`.
fn portfolio_store() -> Vec<u128> {
    vec![0u128; PORTFOLIO_ACCOUNT_LEN / 16 + 1]
}

fn init_header(d: &mut [u8]) {
    d[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    d[8..10].copy_from_slice(&VERSION.to_le_bytes());
    d[10] = KIND_PORTFOLIO;
}

fn leg_off(k: usize) -> usize {
    HEADER_LEN + offset_of!(PortfolioAccountV16Account, legs) + k * size_of::<PortfolioLegV16Account>()
}

fn write_leg(d: &mut [u8], k: usize, active: u8, asset: u32, mid: u64, side: u8, basis: i128) {
    let mut leg = PORTFOLIO_LEG_V16_EMPTY_ACCOUNT;
    leg.active = active;
    leg.asset_index = V16PodU32::new(asset);
    leg.market_id = V16PodU64::new(mid);
    leg.side = side;
    leg.basis_pos_q = V16PodI128::new(basis);
    let off = leg_off(k);
    d[off..off + size_of::<PortfolioLegV16Account>()].copy_from_slice(bytemuck::bytes_of(&leg));
}

// ── AUD-S1-23: position_epoch advance on third-party reshapes ─────────────────────────────────

/// H23a. `state::bump_portfolio_position_epoch` (the write every S1-23 bump goes through) advances
/// position_epoch by EXACTLY one, leaves the enabled bit, the trade-fee-cap bits and every byte
/// outside the 8-byte control word unchanged, and fails closed at the 49-bit maximum or on an invalid
/// control word. Symbolic: the whole control word, one symbolic byte at a symbolic position outside it.
/// Mutant M23a: `checked_add(1)` -> `checked_add(0)` in `next_portfolio_position_control`.
#[kani::proof]
#[kani::unwind(9)]
fn kani_w1020_s1_23_bump_advances_epoch_by_exactly_one() {
    let control: u64 = kani::any();
    let mut st = portfolio_store();
    let d: &mut [u8] = &mut bytemuck::cast_slice_mut::<u128, u8>(&mut st)[..PORTFOLIO_ACCOUNT_LEN];
    init_header(d);
    d[PORTFOLIO_MATCHER_CONTROL_OFF..PORTFOLIO_MATCHER_CONTROL_OFF + 8].copy_from_slice(&control.to_le_bytes());
    let j: usize = kani::any();
    kani::assume(j >= HEADER_LEN && j < PORTFOLIO_ACCOUNT_LEN);
    kani::assume(j < PORTFOLIO_MATCHER_CONTROL_OFF || j >= PORTFOLIO_MATCHER_CONTROL_OFF + 8);
    let noise: u8 = kani::any();
    d[j] = noise;
    let epoch = (control >> 1) & EPOCH_MAX;
    let enabled = control & 1;
    let fee_cap = control >> 50;
    let valid = fee_cap <= 10_000; // enabled is one bit, always <= 1
    let r = state::bump_portfolio_position_epoch(d);
    assert_eq!(r.is_ok(), valid && epoch < EPOCH_MAX, "Ok iff valid and below the maximum");
    if let Ok(next) = r {
        assert_eq!(next, epoch + 1);
        let c2 = u64::from_le_bytes(d[PORTFOLIO_MATCHER_CONTROL_OFF..PORTFOLIO_MATCHER_CONTROL_OFF + 8].try_into().unwrap());
        assert_eq!((c2 >> 1) & EPOCH_MAX, epoch + 1, "stored epoch advanced by one");
        assert_eq!(c2 & 1, enabled, "enabled bit untouched");
        assert_eq!(c2 >> 50, fee_cap, "fee cap untouched");
        assert_eq!(state::read_portfolio_position_epoch(d).ok(), Some(epoch + 1));
        assert_eq!(d[j], noise, "no other byte written");
        kani::cover!(epoch == EPOCH_MAX - 1, "COVER: last representable advance");
        kani::cover!(enabled == 1 && fee_cap > 0, "COVER: advance with enabled + fee cap set");
    } else {
        kani::cover!(valid && epoch == EPOCH_MAX, "COVER: epoch exhausted, fails closed");
        kani::cover!(!valid, "COVER: invalid control word refused");
    }
}

/// H23b. `state::portfolio_position_vector` (the before/after snapshot `with_position_epoch_bumps`
/// compares) changes IFF an active leg's (asset_index, market_id, side, basis_pos_q) changes or the
/// leg closes; a change anywhere else (here: capital, the leg's a_basis) leaves it equal, so a plain
/// refresh does not advance the epoch. Leg slot k symbolic among all 16; both tuples symbolic.
/// Mutant M23b: the vector drops `basis_pos_q` (a partial liquidation would not bump).
#[kani::proof]
#[kani::unwind(18)]
fn kani_w1020_s1_23_position_vector_detects_exactly_reshapes() {
    let k: usize = kani::any();
    kani::assume(k < V16_MAX_PORTFOLIO_ASSETS_N);
    let (aa, am, as_, ab): (u32, u64, u8, i128) = (kani::any(), kani::any(), kani::any(), kani::any());
    let (ba, bm, bs, bb): (u32, u64, u8, i128) = (kani::any(), kani::any(), kani::any(), kani::any());
    let b_active: bool = kani::any();
    let (mut sa, mut sb) = (portfolio_store(), portfolio_store());
    let da: &mut [u8] = &mut bytemuck::cast_slice_mut::<u128, u8>(&mut sa)[..PORTFOLIO_ACCOUNT_LEN];
    let db: &mut [u8] = &mut bytemuck::cast_slice_mut::<u128, u8>(&mut sb)[..PORTFOLIO_ACCOUNT_LEN];
    init_header(da);
    init_header(db);
    write_leg(da, k, 1, aa, am, as_, ab);
    write_leg(db, k, b_active as u8, ba, bm, bs, bb);
    // non-position noise in B: capital and the leg's a_basis
    let cap: u128 = kani::any();
    let coff = HEADER_LEN + offset_of!(PortfolioAccountV16Account, capital);
    db[coff..coff + 16].copy_from_slice(&cap.to_le_bytes());
    let abasis: u128 = kani::any();
    let aoff = leg_off(k) + offset_of!(PortfolioLegV16Account, a_basis);
    db[aoff..aoff + 16].copy_from_slice(bytemuck::bytes_of(&V16PodU128::new(abasis)));
    let va = state::portfolio_position_vector(da);
    let vb = state::portfolio_position_vector(db);
    assert!(va.is_some() && vb.is_some(), "a well-formed portfolio is readable");
    let (va, vb) = (va.unwrap(), vb.unwrap());
    assert_eq!(va.len(), 1);
    let same_tuple = aa == ba && am == bm && as_ == bs && ab == bb;
    assert_eq!(va == vb, b_active && same_tuple, "vector equal iff the position is unchanged");
    kani::cover!(va == vb && cap != 0, "COVER: capital changed, no bump");
    kani::cover!(b_active && aa == ba && am == bm && as_ == bs && ab != bb, "COVER: only basis changed -> bump");
    kani::cover!(b_active && aa == ba && am == bm && ab == bb && as_ != bs, "COVER: only side changed -> bump");
    kani::cover!(!b_active && same_tuple, "COVER: leg closed -> bump");
    kani::cover!(k == V16_MAX_PORTFOLIO_ASSETS_N - 1, "COVER: last leg slot");
}

// ── AUD-S1-24: a Live insurance debit consumes its authority epoch ───────────────────────────

/// H24. The lane write the tag-57 Live debit now performs (`advance_authority_epoch_view` ->
/// `state::next_authority_epoch`) admits only the CURRENT epoch, advances it by exactly one, and after
/// it the SAME signed `expected` is refused by the check every epoch-bound tag runs
/// (`state::require_current_authority_epoch`): a replay of the signed withdrawal cannot land. Full u64.
/// Mutant M24: `current.checked_add(1)` -> `current.checked_add(0)`.
#[kani::proof]
fn kani_w1020_s1_24_debit_consumes_the_epoch() {
    let cur: u64 = kani::any();
    let exp: u64 = kani::any();
    let r = state::next_authority_epoch(cur, exp);
    assert_eq!(r.is_ok(), cur == exp && cur < u64::MAX);
    if let Ok(n) = r {
        assert_eq!(n, cur + 1);
        assert!(state::require_current_authority_epoch(n, exp).is_err(), "replay of the same signed epoch refused");
        assert!(state::require_current_authority_epoch(n, n).is_ok(), "the next epoch is live");
        kani::cover!(true, "COVER: debit admitted and consumed");
    } else {
        kani::cover!(cur != exp, "COVER: stale epoch refused");
        kani::cover!(cur == exp && cur == u64::MAX, "COVER: counter exhausted fails closed");
    }
}

// ── AUD-S1-15: tag 97 junior withdraw held to the open-interest lock ─────────────────────────

/// H15. The S1-15 check as wired: `n_after = n_cap_q(c_m - amount, λ, price, POS_SCALE).unwrap_or(0)`
/// (what `growth_n_cap_for_view` returns for a growth asset) and `bond_withdraw_lock_ok(Some(n_after),
/// oi_long, oi_short, |lp_eff|)`. FULL width (c_m, amount, OI, inventory u128; λ u32; price u64).
/// Proves: admitted => post-withdraw capacity covers BOTH sides' open interest and the LP's own
/// inventory; refused otherwise; a capacity overflow or a zero price (None) fails closed to capacity 0.
/// Mutant M15: `bond_withdraw_lock_ok` ignores `oi_short_q` (the flat-LP self-funding hole on the short side).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_w1020_s1_15_junior_withdraw_lock_full_width() {
    let c_m: u128 = kani::any();
    let amount: u128 = kani::any();
    let lambda: u32 = kani::any();
    let price: u64 = kani::any();
    let (oi_l, oi_s, lp): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let raw = n_cap_q(c_m.saturating_sub(amount), lambda, price, POS_SCALE);
    let n_after = raw.unwrap_or(0);
    let ok = bond_withdraw_lock_ok(Some(n_after), oi_l, oi_s, lp);
    assert_eq!(ok, n_after >= oi_l && n_after >= oi_s && n_after >= lp, "admitted iff capacity covers every side and the LP");
    if raw.is_none() {
        assert_eq!(ok, oi_l == 0 && oi_s == 0 && lp == 0, "capacity unknown => only a fully flat market passes");
    }
    kani::cover!(ok && oi_l > 0 && oi_s > 0, "COVER: admitted with open interest on both sides");
    kani::cover!(!ok && lp == 0 && oi_l == 0 && oi_s > 0 && n_after > 0, "COVER: flat LP refused by SHORT open interest");
    kani::cover!(!ok && lp == 0 && oi_s == 0 && oi_l > 0 && n_after > 0, "COVER: flat LP refused by LONG open interest");
    kani::cover!(raw.is_none() && oi_l > 0, "COVER: no capacity number, refused");
}

// ── AUD-S1-16: a junior withdrawal re-arms the creator-fee vesting flag ──────────────────────

/// H16. The re-arm decision as wired: `junior_after = tranche_split3(v - amount, C_eff, C_b).junior`,
/// re-arm iff `!creator_fee_vested(junior_after, C_eff, share, target)`. Proves the decision is the
/// exact cushion threshold `junior_after * 10_000 < C_eff * target` (ceil semantics, no rounding gap)
/// when the cushion is configured, never re-arms when it is off, fails closed (re-arms) on an invalid
/// target > 10_000, and that a withdrawal never RAISES the junior level (so it can only move the flag
/// toward "not vested"). Values u128 with C_eff, v < 2^113 (products in u128; atoms are u64 in production).
/// Mutant M16: `creator_fee_vested` uses `bps_floor` (the junior one atom below target would vest).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_w1020_s1_16_rearm_is_exact_cushion_threshold() {
    let (v, amount, c_eff, cb): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    let share: u16 = kani::any();
    let target: u16 = kani::any();
    kani::assume(v < (1u128 << 113) && c_eff < (1u128 << 113));
    let before = tranche_split3(v, c_eff, cb).junior;
    let junior_after = tranche_split3(v.saturating_sub(amount), c_eff, cb).junior;
    assert!(junior_after <= before, "a withdrawal never raises the junior level");
    let rearm = !creator_fee_vested(junior_after, c_eff, share, target);
    if share == 0 || target == 0 {
        assert!(!rearm, "cushion off: never re-armed");
    } else if target > 10_000 {
        assert!(rearm, "invalid target fails closed");
    } else {
        let lhs = junior_after * 10_000;
        let rhs = c_eff * target as u128;
        assert_eq!(rearm, lhs < rhs, "re-arm iff junior below ceil(C_eff * target / 1e4)");
        kani::cover!(rearm && lhs + 10_000 > rhs && rhs % 10_000 != 0, "COVER: one atom below a fractional target re-arms");
        kani::cover!(!rearm && lhs == rhs, "COVER: exactly at target stays vested");
        kani::cover!(rearm && before * 10_000 >= rhs, "COVER: the withdrawal itself crossed the target");
    }
}
