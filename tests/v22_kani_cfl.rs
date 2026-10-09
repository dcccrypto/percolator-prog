//! Kani v2.2 final run (design: ~/percolator-ops/ledger/kani-v22-final-run-design-2026-10-09.md, rev 2 and
//! rev 2.1): Wave C capacity bonds (W-C-*), fill events (W-FE-*) and the LP share mint (W-LP-*), on the
//! FULL wrapper crate (real constants, real modules; no copied production code).
//!
//! Run ONCE, deployed flavour first:
//!   cargo kani --tests --features devnet -Z function-contracts -Z stubbing --exact --harness <name>
//! Every harness carries `kani::cover!` witnesses; SUCCESSFUL with an unsatisfied cover is VACUOUS.
//!
//! Width policy (rev 2 R2.4, adjusted here): where a property needs `mul_div_floor` the harness calls
//! the REAL primitive at bounded operands (u8 / u16, stated per harness) instead of `stub_verified`:
//! a `proof_for_contract` of a dependency-crate function from an integration-test crate is not an
//! established Kani path, and the real primitive at bounded width removes the CONDITIONAL dependency.
//! Every such result is labelled "bounded" in the results table.
//!
//! Evidence labels used below: PROOF, BOUNDED, MODEL-LEVEL (proves a proof-only model of the lazy bond
//! representation, not a production path), CONDITIONAL(on <harness>).
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use percolator::{
    Market, MarketGroupV16HeaderAccount, MarketGroupV16ViewMut, PortfolioAccountV16Account,
    PortfolioV16ViewMut, V16PodI128, V16PodU128, V16PodU32, V16PodU64, ADL_ONE, MAX_POSITION_ABS_Q,
};
use percolator_prog::bond_v20::*;
use percolator_prog::fill_events_v22 as fe;
use percolator_prog::growth_v19::n_cap_q;
use percolator_prog::lp_share_meta_v22 as meta;
use percolator_prog::vault_lp_v18::{
    a4_capacity_lock_ok, alloc_junior_ok, bps_floor, junior_withdraw_allowed, tranche_split,
    vault_lp_draw_halts, vault_lp_draw_move, vault_lp_draw_step, DrawState,
    DRAW_OP_BOND_WITHDRAW, DRAW_OP_JUNIOR_RELEASE_102, DRAW_OP_JUNIOR_WITHDRAW_97,
    DRAW_OP_LP_RISK_INCREASING_FILL, DRAW_OP_RECALL_98, DRAW_OP_SENIOR_DEPOSIT_75,
    DRAW_OP_SENIOR_REDEEM_77, DRAW_OP_SENIOR_REQUEST_76,
};

// Stub targets must resolve; pin their paths at compile time (a typo would otherwise surface only in
// Kani's stub resolution, inside the one run).
#[allow(unused_imports)]
use percolator_prog::lp_share_meta_v22::base58_encode as _stub_target_base58;
#[allow(unused_imports)]
use solana_program::log::sol_log_data as _stub_target_sol_log_data;

fn u64a() -> u128 {
    kani::any::<u64>() as u128
}
fn u32a() -> u128 {
    kani::any::<u32>() as u128
}
fn u16a() -> u128 {
    kani::any::<u16>() as u128
}
fn u8a() -> u128 {
    kani::any::<u8>() as u128
}
fn min2(a: u128, b: u128) -> u128 {
    if a < b { a } else { b }
}

// ═══════════════════════════════════ Wave C: capacity bonds ═══════════════════════════════════

/// W-C-1 (B1; I-T1, I-T2, I-T8). PROOF, u64 operands (add/sub/min only, so the u64 range carries no
/// width argument beyond the u64 representability of every claim). Mutant BOND-MP1.
#[kani::proof]
fn kani_v22_wc1_split3_conserves_and_orders() {
    let (v, cs, cb) = (u64a(), u64a(), u64a());
    let s = tranche_split3(v, cs, cb);
    assert_eq!(s.senior + s.bond + s.junior, v, "conservation");
    assert!(s.senior <= cs && s.bond <= cb);
    if s.junior > 0 {
        assert!(s.bond == cb && s.senior == cs, "junior only after both claims are whole");
    }
    if s.bond < cb {
        assert_eq!(s.junior, 0);
    }
    if s.senior < cs {
        assert!(s.bond == 0 && s.junior == 0);
    }
    let s0 = tranche_split3(v, cs, 0);
    let t = tranche_split(v, cs);
    assert!(s0.senior == t.senior && s0.bond == 0 && s0.junior == t.junior, "I-T8");
    kani::cover!(v < cs, "v < C_s");
    kani::cover!(v >= cs && v < cs + cb, "C_s <= v < C_s + C_b");
    kani::cover!(cb > 0 && v == cs + cb, "v == C_s + C_b");
    kani::cover!(cb > 0 && v > cs + cb, "v > C_s + C_b");
    kani::cover!(cb == 0 && v > cs, "no bonds");
}

/// W-C-2 (B2; I-T3). MODEL-LEVEL: `draw_step3` is a proof model (production books through the P3
/// step; bonds design §5); its senior output must equal the production `vault_lp_draw_step`. u64.
/// Mutant BOND-MP7 (†).
#[kani::proof]
fn kani_v22_wc2_draw3_order() {
    let s = DrawState { senior_claim: u64a(), outstanding: u64a(), junior_surplus: u64a(), drawable: u64a() };
    let (cb, d) = (u64a(), u64a());
    let (next, moved, jc, bc, sl) = draw_step3(s, cb, d);
    let (pn, pm, psl) = vault_lp_draw_step(s, d);
    assert!(next == pn && moved == pm && sl == psl, "senior books are the production step's");
    let (sub, sd) = vault_lp_draw_move(d, s.junior_surplus, s.drawable);
    assert_eq!(moved, sub + sd);
    assert_eq!(jc + bc, sub);
    let bond_in = min2(s.junior_surplus, cb);
    assert!(jc <= s.junior_surplus - bond_in, "junior covers only its own part");
    assert!(bc <= bond_in);
    if bc > 0 {
        assert_eq!(jc, s.junior_surplus - bond_in, "junior first");
    }
    if sd > 0 {
        assert_eq!(bc, bond_in, "bonds before seniors");
    }
    kani::cover!(jc > 0 && bc == 0 && sd == 0, "junior only");
    kani::cover!(jc > 0 && bc > 0 && sd == 0, "junior then bond");
    kani::cover!(jc > 0 && bc > 0 && sd > 0, "junior, bond, senior");
    kani::cover!(jc == 0 && bc > 0 && s.junior_surplus <= cb, "bond with no junior");
    kani::cover!(s.drawable < d && moved == s.drawable && moved > 0, "backing-limited");
}

/// W-C-3 (B3). MODEL-LEVEL: the lazy split equals the explicit draw. u64. Mutants BOND-MP1, BOND-MP7.
#[kani::proof]
fn kani_v22_wc3_lazy_split_equals_explicit_draw() {
    let (cs, nav, cb, d) = (u64a(), u64a(), u64a(), u64a());
    let s = DrawState { senior_claim: cs, outstanding: 0, junior_surplus: nav.saturating_sub(cs), drawable: nav };
    let (n, moved, jc, bc, _) = draw_step3(s, cb, d);
    let before = tranche_split3(nav, cs, cb);
    let after = tranche_split3(nav - moved, n.senior_claim, cb);
    assert_eq!(before.junior - after.junior, jc, "junior value falls by its cover");
    assert_eq!(before.bond - after.bond, bc, "bond value falls by its cover");
    assert_eq!(before.senior - after.senior, moved - jc - bc, "senior value falls by the senior draw");
    kani::cover!(jc > 0 && bc == 0, "junior only");
    kani::cover!(jc > 0 && bc > 0 && moved == jc + bc, "junior then bond");
    kani::cover!(bc > 0 && moved > jc + bc, "into the seniors");
    kani::cover!(nav < cs && moved > 0, "already impaired");
}

/// W-C-4 (B4, recover3 only; recover4/backstop-first is LiteSVM per rev 2 R1.8). MODEL-LEVEL. u64
/// (`v < u64::MAX` for the monotonicity step). Mutant BOND-MP2 (†).
#[kani::proof]
fn kani_v22_wc4_recover3_restores_senior_bond_junior() {
    let (v, cs, o, cb) = (u64a(), u64a(), u64a(), u64a());
    kani::assume(v < u64::MAX as u128);
    let (cs1, o1, s) = recover3(v, cs, o, cb);
    assert_eq!(cs1 + o1, cs + o, "restoration moves outstanding into the claim");
    if s.bond > 0 {
        assert_eq!(o1, 0, "bonds only after the seniors are whole");
    }
    if s.junior > 0 {
        assert!(o1 == 0 && s.bond == cb);
    }
    let (cs2, o2, s2) = recover3(v + 1, cs, o, cb);
    assert!(s2.senior >= s.senior && s2.bond >= s.bond && s2.junior >= s.junior, "monotone in value");
    assert!(o2 <= o1 && cs2 >= cs1);
    kani::cover!(o1 > 0 && cs1 > cs, "partial senior restore");
    kani::cover!(o > 0 && o1 == 0 && s.bond > 0 && s.bond < cb, "seniors whole, bonds partial");
    kani::cover!(o > 0 && o1 == 0 && s.junior > 0, "all whole, junior > 0");
}

/// W-C-5 (B5; I-T5). BOUNDED: amount u16, shares and value u8 (real `mul_div_floor`). Mutant BOND-MP6.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc5_bond_deposit_no_dilution() {
    let amount = u16a();
    let (b, value) = (u8a(), u8a());
    kani::assume(amount > 0);
    let m = bond_shares_for_deposit(amount, b, value);
    if b == 0 {
        assert_eq!(m, Some(amount), "genesis 1:1");
    } else if value == 0 {
        assert!(m.is_none(), "zero value with shares outstanding fails closed");
    } else {
        let m = m.unwrap();
        assert!((value + amount) * b >= value * (b + m), "incumbents not diluted");
        assert!(m * value <= amount * b, "rounds down");
    }
    kani::cover!(b == 0, "genesis");
    kani::cover!(b > 0 && value > 0 && (amount * b) % value == 0 && m.is_some_and(|x| x > 0), "exact");
    kani::cover!(b > 0 && value > 0 && (amount * b) % value != 0, "floored");
}

/// W-C-6 (B6). BOUNDED u8 (real `mul_div_floor`). Mutant BOND-SLICE (slice rounded up).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc6_bond_redemption_no_dilution() {
    let (b, sh, cb, value) = (u8a(), u8a(), u8a(), u8a());
    kani::assume(b > 0 && value <= cb);
    let pay = bond_atoms_for_redemption(sh, b, value);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if sh > b {
        assert!(pay.is_none() && cb2.is_none());
    } else {
        let (pay, cb2) = (pay.unwrap(), cb2.unwrap());
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
    }
    kani::cover!(sh < b && value == cb && cb > 0 && sh > 0, "whole tranche");
    kani::cover!(sh < b && value < cb && sh > 0, "impaired tranche");
    kani::cover!(sh == b && cb > 0, "full redemption");
}

/// W-C-7 (B7; I-T6, the self-funding attack) on the REAL `n_cap_q` (it has no contract; rev 2 R1.8).
/// BOUNDED: c_m, x, OI u16; lambda, price, pos_scale u8. Mutant BOND-MP3.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc7_bond_lock_vs_open_oi() {
    let c_m = u16a();
    let x = u16a();
    kani::assume(x <= c_m);
    let lambda = kani::any::<u8>() as u32;
    let price = kani::any::<u8>() as u64;
    let ps = u8a();
    let (oi_l, oi_s, lp) = (u16a(), u16a(), u16a());
    let n_after = n_cap_q(c_m - x, lambda, price, ps);
    let ok = bond_withdraw_lock_ok(n_after, oi_l, oi_s, lp);
    let need = if oi_l > oi_s { oi_l } else { oi_s };
    let need = if need > lp { need } else { lp };
    assert_eq!(ok, match n_after { Some(n) => n >= need, None => need == 0 });
    if ok {
        if let (Some(nb), Some(na)) = (n_cap_q(c_m, lambda, price, ps), n_after) {
            assert!(a4_capacity_lock_ok(nb, na, lp), "the A4 lock is implied");
        }
    }
    kani::cover!(!ok && lp > 0, "refused by the LP's own leg");
    kani::cover!(!ok && lp == 0 && oi_l > 0, "refused with a FLAT LP: open user OI");
    kani::cover!(ok && need > 0, "admitted below capacity");
    kani::cover!(ok && n_after.is_none() && need == 0, "growth off, nothing open");
}

/// W-C-8a (B8, waterfall). MODEL-LEVEL for `fee_waterfall3` (the composition model); the coupon layer
/// inside it is the production `bond_coupon_split`. u32. Mutants BOND-MP4 (†), BOND-MP8 (†).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc8a_fee_waterfall3_conserves_and_orders() {
    let (avail, due) = (u32a(), u32a());
    let share: u16 = kani::any();
    let target: u16 = kani::any();
    let (c_eff, level) = (u32a(), u32a());
    kani::assume(share <= 10_000 && target <= 10_000);
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

/// W-C-8b (B8, coupon accrual, gate, base). PROOF of the production `coupon_due`, `coupon_gate_open`,
/// `coupon_base`; BOUNDED: claim and value u32, rate <= 3,000, dt u64 (real `mul_div_floor`, constant
/// divisor). Mutants BOND-MP10, BOND-MP11.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc8b_coupon_due_gate_base() {
    let (cb, bv) = (u32a(), u32a());
    let rate = kani::any::<u16>() as u32;
    kani::assume(rate <= 3_000);
    let dt: u64 = kani::any();
    let base = coupon_base(cb, bv);
    assert_eq!(base, min2(cb, bv), "base = min(C_b, bond value)");
    let due = coupon_due(base, rate, dt).unwrap();
    assert!(due * 10_000 <= base * rate as u128, "never more than one year of coupon");
    let dtc = if (dt as u128) > SLOTS_PER_YEAR { SLOTS_PER_YEAR as u64 } else { dt };
    assert_eq!(coupon_due(base, rate, dtc), Some(due), "the interval is clamped to one year");
    let live: bool = kani::any();
    let o = u32a();
    let g = coupon_gate_open(live, cb, o, bv);
    assert_eq!(g, live && cb > 0 && o == 0 && bv >= cb);
    if bv < cb {
        assert!(!g, "an impaired tranche earns nothing");
    }
    kani::cover!((dt as u128) > SLOTS_PER_YEAR && due > 0, "one-year clamp");
    kani::cover!(due > 0 && g, "coupon accrues on an open gate");
    kani::cover!(live && cb > 0 && bv >= cb && o > 0 && !g, "gate closed by a senior draw");
    kani::cover!(live && cb > 0 && o == 0 && bv < cb && !g, "gate closed by impairment");
}

/// W-C-9 (B9). PROOF, u64 (bps math is the overflow-free decomposition). Mutant BOND-MP5.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc9_junior_gates_exclude_bonds() {
    let (v, c, cb, cover, amt) = (u64a(), u64a(), u64a(), u64a(), u64a());
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

/// W-C-10 (B10, rebuilt: there is no D-P3-26 Kani harness on the final head). PROOF on the real
/// `vault_lp_draw_halts`. Mutant BOND-HALT (drop op 8).
#[kani::proof]
fn kani_v22_wc10_draw_halts_incl_bond_withdraw() {
    let o: u128 = kani::any();
    let op: u8 = kani::any();
    let h = vault_lp_draw_halts(o, op);
    let gated = op == DRAW_OP_LP_RISK_INCREASING_FILL
        || op == DRAW_OP_JUNIOR_WITHDRAW_97
        || op == DRAW_OP_JUNIOR_RELEASE_102
        || op == DRAW_OP_RECALL_98
        || op == DRAW_OP_BOND_WITHDRAW;
    assert_eq!(h, o > 0 && gated);
    if op == DRAW_OP_SENIOR_DEPOSIT_75 || op == DRAW_OP_SENIOR_REQUEST_76 || op == DRAW_OP_SENIOR_REDEEM_77 {
        assert!(!h, "75/76/77 never halt");
    }
    kani::cover!(h && op == DRAW_OP_BOND_WITHDRAW, "bond withdraw halted");
    kani::cover!(o > 0 && op == DRAW_OP_SENIOR_REDEEM_77 && !h, "senior redeem stays open");
}

/// W-C-11 (B11). PROOF (bonus ceiling is 0 on the final code). Mutant BOND-MP9.
#[kani::proof]
fn kani_v22_wc11_bond_config_bounds() {
    let coupon: u16 = kani::any();
    let bonus: u16 = kani::any();
    let cd: u32 = kani::any();
    let cap: u16 = kani::any();
    let ok = bond_config_ok(coupon, bonus, cd, cap);
    assert_eq!(ok, coupon <= 2_000 && bonus == 0 && (9_000..=1_512_000).contains(&cd) && (1..=5_000).contains(&cap));
    kani::cover!(ok && coupon == 2_000 && cd == 9_000 && cap == 5_000, "upper/lower edges admitted");
    kani::cover!(!ok && bonus == 1 && coupon <= 2_000 && cap == 1 && cd == 1_512_000, "any bonus refused");
    kani::cover!(!ok && cap == 0, "cap 0 refused");
}

/// W-C-12 (`bond_coupon_split`, rev 2 R1.8). PROOF, u64. Note: the 50% leg cap lives INSIDE this
/// function (`BOND_COUPON_MAX_LEG_BPS`), so `cp == min(due, floor(available / 2))` here (rev 2's row
/// said `min(due, available)`; corrected). Mutant BOND-MP8 shares the cap line.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wc12_bond_coupon_split() {
    let (avail, due) = (u64a(), u64a());
    let (cp, rest) = bond_coupon_split(avail, due);
    assert_eq!(cp + rest, avail);
    assert_eq!(cp, min2(due, avail / 2));
    kani::cover!(due < avail / 2 && cp == due, "due binds");
    kani::cover!(due > avail / 2 && cp == avail / 2 && avail > 1, "cap binds");
}

// ═══════════════════════════════════ fill events ══════════════════════════════════════════════

/// W-FE-1. PROOF, full i128. Mutants FE-M1 (`Some(0)` returned), FE-M2 (Unreadable mapped to 0).
#[kani::proof]
fn kani_v22_fe1_liquidation_delta_q() {
    let q: i128 = kani::any();
    let a: i128 = kani::any();
    let k: u8 = kani::any();
    let after = match k % 3 {
        0 => fe::LegAfter::Absent,
        1 => fe::LegAfter::Unreadable,
        _ => fe::LegAfter::Size(a),
    };
    let r = fe::liquidation_delta_q(q, after);
    assert!(r != Some(0), "never Some(0)");
    match after {
        fe::LegAfter::Unreadable => assert!(r.is_none(), "unreadable is never a close"),
        fe::LegAfter::Absent => assert_eq!(r, 0i128.checked_sub(q).filter(|d| *d != 0)),
        fe::LegAfter::Size(x) => assert_eq!(r, x.checked_sub(q).filter(|d| *d != 0)),
    }
    kani::cover!(matches!(after, fe::LegAfter::Absent) && q != 0 && q != i128::MIN && r.is_some(), "absent = full close");
    kani::cover!(matches!(after, fe::LegAfter::Absent) && q == i128::MIN, "absent overflow");
    kani::cover!(matches!(after, fe::LegAfter::Unreadable) && q != 0, "unreadable");
    kani::cover!(matches!(after, fe::LegAfter::Size(_)) && r.is_some(), "partial change");
    kani::cover!(matches!(after, fe::LegAfter::Size(_)) && a == q, "no change");
    kani::cover!(matches!(after, fe::LegAfter::Size(_)) && a.checked_sub(q).is_none(), "size overflow");
}

/// W-FE-5. PROOF, full u128. Mutant FE-M6 (truncating cast).
#[kani::proof]
fn kani_v22_fe5_sat_u64() {
    let v: u128 = kani::any();
    let w: u128 = kani::any();
    let s = fe::sat_u64(v);
    if v <= u64::MAX as u128 {
        assert_eq!(s as u128, v);
    } else {
        assert_eq!(s, u64::MAX);
    }
    if v <= w {
        assert!(s <= fe::sat_u64(w), "monotone");
    }
    kani::cover!(v > u64::MAX as u128, "saturates");
    kani::cover!(v < u64::MAX as u128 && v > 0, "exact");
}

/// W-FE-6 (sub 4, G9_RESTORE_PNL): lemma on the real `sat_u64` composed with the real
/// `backstop_restore_split` (u64 inputs, so `moved` fits u64). PROOF of the arithmetic; the binding at the
/// handler (`src/v16_program.rs:37410-37418`) is LiteSVM.
#[kani::proof]
fn kani_v22_fe6_sub4_split() {
    let (o, room, req, pcap, cap) = (u64a(), u64a(), u64a(), u64a(), u64a());
    let (p, c) = percolator_prog::p4_rescue_ins::backstop_restore_split(o, room, req, pcap, cap);
    let m = p + c;
    kani::assume(m <= u64::MAX as u128);
    let a = fe::sat_u64(p) as u128;
    let b = fe::sat_u64(m.saturating_sub(p)) as u128;
    assert!(a == p && b == c && a + b == m, "a = from_pnl, b = from_cap, a + b = moved");
    let (p2, m2) = (u64a(), u64a());
    if p2 <= m2 {
        assert_eq!(fe::sat_u64(p2) as u128 + fe::sat_u64(m2 - p2) as u128, m2);
    }
    kani::cover!(p > 0 && c > 0, "both sources");
    kani::cover!(p == 0 && c > 0, "capital only");
    kani::cover!(p > 0 && c == 0, "PnL only");
}

fn any_rec() -> fe::FillRec {
    fe::FillRec {
        asset_index: kani::any(),
        asset_gen: kani::any(),
        flags: kani::any(),
        requested_q: kani::any(),
        executed_q: kani::any(),
        price_e6: kani::any(),
        quoted_price_e6: kani::any(),
        fee_atoms: kani::any(),
        backing_fee_atoms: kani::any(),
    }
}

fn rd<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    let mut x = [0u8; N];
    x.copy_from_slice(&b[o..o + N]);
    x
}

/// W-FE-2. PROOF of the FILL encoder for every `n <= 11`: length `100 + 75n` and every field at its
/// documented offset (the spec decoder below reads the bytes back, so decode∘encode is the identity).
/// Mutant FE-M3 (requested/executed swapped).
#[kani::proof]
#[kani::unwind(13)]
fn kani_v22_fe2_encode_fill_layout() {
    assert_eq!(fe::FILL_FIXED_LEN, 100);
    assert_eq!(fe::FILL_REC_LEN, 75);
    let n: usize = kani::any();
    kani::assume(n <= fe::MAX_FILL_RECS_PER_LINE);
    let recs = [any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec(), any_rec()];
    let tag: u8 = kani::any();
    let market: [u8; 32] = kani::any();
    let taker: [u8; 32] = kani::any();
    let lp: [u8; 32] = kani::any();
    let mut buf = [0u8; fe::FILL_BUF_LEN];
    let len = fe::encode_fill(&mut buf, tag, &market, &taker, &lp, 0, n, &|i| recs[i]);
    assert_eq!(len, 100 + 75 * n);
    assert!(buf[0] == fe::KIND_FILL && buf[1] == fe::VERSION && buf[2] == tag);
    assert!(rd::<32>(&buf, 3) == market && rd::<32>(&buf, 35) == taker && rd::<32>(&buf, 67) == lp);
    assert_eq!(buf[99] as usize, n);
    let mut i = 0usize;
    while i < fe::MAX_FILL_RECS_PER_LINE {
        if i < n {
            let o = 100 + 75 * i;
            let r = recs[i];
            assert_eq!(u16::from_le_bytes(rd(&buf, o)), r.asset_index);
            assert_eq!(u64::from_le_bytes(rd(&buf, o + 2)), r.asset_gen);
            assert_eq!(buf[o + 10], r.flags);
            assert_eq!(i128::from_le_bytes(rd(&buf, o + 11)), r.requested_q);
            assert_eq!(i128::from_le_bytes(rd(&buf, o + 27)), r.executed_q);
            assert_eq!(u64::from_le_bytes(rd(&buf, o + 43)), r.price_e6);
            assert_eq!(u64::from_le_bytes(rd(&buf, o + 51)), r.quoted_price_e6);
            assert_eq!(u64::from_le_bytes(rd(&buf, o + 59)), r.fee_atoms);
            assert_eq!(u64::from_le_bytes(rd(&buf, o + 67)), r.backing_fee_atoms);
        }
        i += 1;
    }
    kani::cover!(n == 0, "header only");
    kani::cover!(n == 5, "partial line");
    kani::cover!(n == 11, "full line");
}

/// W-FE-3. PROOF of the REDUCE (134 B) and MOVE (62 B) encoders, every field at its offset. Mutant FE-M4.
#[kani::proof]
fn kani_v22_fe3_encode_reduce_and_move_layout() {
    assert_eq!(fe::REDUCE_LEN, 134);
    assert_eq!(fe::MOVE_LEN, 62);
    let tag: u8 = kani::any();
    let market: [u8; 32] = kani::any();
    let port: [u8; 32] = kani::any();
    let cp: [u8; 32] = kani::any();
    let (ai, gen, reason, q, px): (u16, u64, u8, i128, u64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let mut b = [0u8; fe::REDUCE_LEN];
    let len = fe::encode_reduce(&mut b, tag, &market, &port, &cp, ai, gen, reason, q, px);
    assert_eq!(len, 134);
    assert!(b[0] == fe::KIND_REDUCE && b[1] == fe::VERSION && b[2] == tag && rd::<32>(&b, 3) == market);
    assert!(rd::<32>(&b, 35) == port && rd::<32>(&b, 67) == cp);
    assert_eq!(u16::from_le_bytes(rd(&b, 99)), ai);
    assert_eq!(u64::from_le_bytes(rd(&b, 101)), gen);
    assert_eq!(b[109], reason);
    assert_eq!(i128::from_le_bytes(rd(&b, 110)), q);
    assert_eq!(u64::from_le_bytes(rd(&b, 126)), px);
    let sub: u8 = kani::any();
    let (x, y, z): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let mut m = [0u8; fe::MOVE_LEN];
    let mlen = fe::encode_move(&mut m, tag, &market, sub, ai, x, y, z);
    assert_eq!(mlen, 62);
    assert!(m[0] == fe::KIND_MOVE && m[35] == sub && u16::from_le_bytes(rd(&m, 36)) == ai);
    assert!(u64::from_le_bytes(rd(&m, 38)) == x && u64::from_le_bytes(rd(&m, 46)) == y && u64::from_le_bytes(rd(&m, 54)) == z);
    kani::cover!(sub == fe::MOVE_G9_RESTORE_PNL, "sub 4");
    kani::cover!(reason == fe::REASON_LIQUIDATION && q < 0, "liquidation reduce");
}

static mut LOG_CALLS: usize = 0;
static mut LOG_LEN: [usize; 4] = [0; 4];
static mut LOG_NREC: [u8; 4] = [0; 4];
static mut LOG_FIRST: [u16; 4] = [0; 4];

/// Recorder for `sol_log_data` (a syscall): records each line's length, record count and first asset.
fn record_log(data: &[&[u8]]) {
    unsafe {
        let k = LOG_CALLS;
        assert!(k < 4, "at most 3 lines for n <= 23");
        let d = data[0];
        LOG_LEN[k] = d.len();
        LOG_NREC[k] = d[99];
        LOG_FIRST[k] = if d.len() >= 102 { u16::from_le_bytes([d[100], d[101]]) } else { u16::MAX };
        LOG_CALLS = k + 1;
    }
}

/// W-FE-4. PROOF of `emit_fills` chunking for `n <= 23`: `ceil(n/11)` lines, line j carries records
/// `[11j, min(n, 11j + 11))` in order. `sol_log_data` stubbed by a recorder. Mutant FE-M5 (`min(12, ..)`).
#[kani::proof]
#[kani::unwind(13)]
#[kani::stub(solana_program::log::sol_log_data, record_log)]
fn kani_v22_fe4_emit_fills_chunking() {
    let n: usize = kani::any();
    kani::assume(n <= 23);
    let market = [1u8; 32];
    let who = [2u8; 32];
    fe::emit_fills(fe::TAG_BATCH_CPI, &market, &who, &who, n, |i| fe::FillRec {
        asset_index: i as u16,
        asset_gen: 0,
        flags: 0,
        requested_q: 0,
        executed_q: 0,
        price_e6: 0,
        quoted_price_e6: 0,
        fee_atoms: 0,
        backing_fee_atoms: 0,
    });
    let calls = unsafe { LOG_CALLS };
    assert_eq!(calls, n.div_ceil(11));
    let mut j = 0usize;
    while j < 3 {
        if j < calls {
            let want = core::cmp::min(11, n - 11 * j);
            let (len, nrec, first) = unsafe { (LOG_LEN[j], LOG_NREC[j], LOG_FIRST[j]) };
            assert_eq!(nrec as usize, want);
            assert_eq!(len, 100 + 75 * want);
            assert!(len <= fe::FILL_BUF_LEN);
            assert_eq!(first as usize, 11 * j, "leg order");
        }
        j += 1;
    }
    kani::cover!(n == 0 && calls == 0, "nothing to emit");
    kani::cover!(n == 11 && calls == 1, "one full line");
    kani::cover!(n == 12 && calls == 2, "split");
    kani::cover!(n == 23 && calls == 3, "three lines");
}

/// W-FE-8 (fill events round 2, N-1 and N-2; rev 2 R1.10). PROOF on the pub
/// `processor::liquidation_event_view` over a real engine market slot and portfolio account (zeroed Pod
/// images, with the fields the view reads made symbolic): two candidate after-legs in slots 0 and 1 with
/// symbolic activity, asset index, generation, side, size and ADL epoch snapshot; unit A. The expected
/// value is computed from the documented rule (first active leg of the current generation on the asset;
/// readable at the side's epoch, 0 at a reset epoch in mode 2, else UNREADABLE) through the production
/// `liquidation_delta_q` (W-FE-1). Memory: one 1,024 B wrapper blob + one slot + one portfolio (concrete
/// zeros except the symbolic fields). Mutants FE-M7 (N-1: None mapped to Absent), FE-M8 (N-2: asset index only).
#[kani::proof]
#[kani::unwind(17)]
fn kani_v22_fe8_liquidation_event_view_n1_n2() {
    type St = percolator_prog::state::AssetOracleStorageV16;
    let mut header: MarketGroupV16HeaderAccount = bytemuck::Zeroable::zeroed();
    let mut markets: [Market<St>; 1] = [bytemuck::Zeroable::zeroed()];
    let gen: u64 = kani::any();
    let epoch: u64 = kani::any();
    let mode: u8 = kani::any();
    let price: u64 = kani::any();
    kani::assume(gen > 0 && gen < u64::MAX && epoch > 0 && epoch < u64::MAX && mode <= 2);
    {
        let a = &mut markets[0].engine.asset;
        a.market_id = V16PodU64::new(gen);
        a.a_long = V16PodU128::new(ADL_ONE);
        a.a_short = V16PodU128::new(ADL_ONE);
        a.epoch_long = V16PodU64::new(epoch);
        a.epoch_short = V16PodU64::new(epoch);
        a.mode_long = mode;
        a.mode_short = mode;
        a.effective_price = V16PodU64::new(price);
    }
    let mut acct: PortfolioAccountV16Account = bytemuck::Zeroable::zeroed();
    // spec inputs of the two candidate legs
    let mut spec: [(bool, u32, u64, u8, u128, u64); 2] = [(false, 0, 0, 0, 0, 0); 2];
    let mut s = 0usize;
    while s < 2 {
        let active: bool = kani::any();
        let ai = kani::any::<bool>() as u32; // asset 0 or 1
        let stale_gen: bool = kani::any();
        let mid = if stale_gen { gen + 1 } else { gen };
        let side = kani::any::<bool>() as u8;
        let raw: u128 = kani::any();
        kani::assume(raw <= MAX_POSITION_ABS_Q);
        let e: u8 = kani::any();
        let esnap = match e % 3 { 0 => epoch, 1 => epoch - 1, _ => epoch + 1 };
        let l = &mut acct.legs[s];
        l.active = active as u8;
        l.asset_index = V16PodU32::new(ai);
        l.market_id = V16PodU64::new(mid);
        l.side = side;
        l.basis_pos_q = V16PodI128::new(if side == 0 { raw as i128 } else { -(raw as i128) });
        l.a_basis = V16PodU128::new(ADL_ONE);
        l.epoch_snap = V16PodU64::new(esnap);
        spec[s] = (active, ai, mid, side, raw, esnap);
        s += 1;
    }
    let q_before: i128 = kani::any();
    kani::assume(q_before.unsigned_abs() <= MAX_POSITION_ABS_Q);
    let before = [(0u16, q_before)];
    let group = MarketGroupV16ViewMut::new(&mut header, &mut markets);
    let portfolio = PortfolioV16ViewMut::new(&mut acct);
    let r = percolator_prog::processor::liquidation_event_view(&group, &portfolio, &before, 0);
    // spec
    let mut after = fe::LegAfter::Absent;
    let mut matched = 2usize;
    let mut k = 0usize;
    while k < 2 {
        let (active, ai, mid, side, raw, esnap) = spec[k];
        if matched == 2 && active && ai == 0 && mid == gen {
            matched = k;
            after = if esnap == epoch {
                fe::LegAfter::Size(if side == 0 { raw as i128 } else { -(raw as i128) })
            } else if mode == 2 && esnap.checked_add(1) == Some(epoch) {
                fe::LegAfter::Size(0)
            } else {
                fe::LegAfter::Unreadable
            };
        }
        k += 1;
    }
    let expected = fe::liquidation_delta_q(q_before, after).map(|d| (0u16, gen, d, price));
    assert_eq!(r, expected);
    let s0_stale_same_index = spec[0].0 && spec[0].1 == 0 && spec[0].2 != gen;
    kani::cover!(matches!(after, fe::LegAfter::Unreadable) && q_before != 0 && r.is_none(), "N-1: unreadable suppresses");
    kani::cover!(s0_stale_same_index && matched == 1 && r.is_some(), "N-2: stale generation passed over");
    kani::cover!(matched == 2 && q_before != 0 && r.is_some(), "absent = full close");
    kani::cover!(matched < 2 && matches!(after, fe::LegAfter::Size(x) if x != 0 && x != q_before) && r.is_some(), "partial");
}

// ═══════════════════════════════════ LP share mint ════════════════════════════════════════════

const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// W-LP-1 (r1 obl. 1). PROOF over every `[u8; 32]`: no out-of-bounds (Kani's bounds checks), output
/// length in 32..=44, alphabet only, one leading '1' per leading zero byte. COST: L, high timeout risk
/// (32 x <= 44 symbolic div-by-58 steps); W-LP-2/3 are CONDITIONAL on it. Mutants LP-M1, LP-M2.
#[kani::proof]
#[kani::unwind(46)]
#[kani::solver(cadical)]
fn kani_v22_lp1_base58_encode_bounds_alphabet() {
    let key: [u8; 32] = kani::any();
    let (out, k) = meta::base58_encode(&key);
    assert!((32..=44).contains(&k), "length 32..=44");
    let mut z = 0usize;
    while z < 32 && key[z] == 0 {
        z += 1;
    }
    let mut i = 0usize;
    while i < 44 {
        if i < k {
            assert!(B58_ALPHABET.contains(&out[i]), "alphabet only");
        }
        if i < z {
            assert_eq!(out[i], b'1', "leading zero byte -> '1'");
        }
        i += 1;
    }
    if z < 32 {
        assert!(out[z] != b'1', "exactly z leading '1's");
    }
    kani::cover!(k == 44, "maximal length");
    kani::cover!(k == 32 && z == 32, "all-zero key");
    kani::cover!(z > 0 && z < 32, "leading zeros");
}

/// Checked model of `base58_encode` (rev 2 R2.4): the postcondition W-LP-1 proves (length, alphabet).
/// No precondition. Dependants are CONDITIONAL on W-LP-1.
fn base58_model(_key: &[u8; 32]) -> ([u8; 44], usize) {
    let k: usize = kani::any();
    kani::assume((32..=44).contains(&k));
    let mut out = [b'1'; 44];
    let mut i = 0usize;
    while i < 44 {
        let c: u8 = kani::any();
        kani::assume(B58_ALPHABET.contains(&c));
        out[i] = c;
        i += 1;
    }
    (out, k)
}

fn ticker_spec(t: &[u8]) -> bool {
    let mut ok = !t.is_empty() && t.len() <= 8;
    let mut i = 0usize;
    while i < t.len() {
        ok = ok && (t[i].is_ascii_uppercase() || t[i].is_ascii_digit());
        i += 1;
    }
    ok
}

/// W-LP-2 (r1 obl. 2, r2 R9). PROOF, CONDITIONAL(on kani_v22_lp1_base58_encode_bounds_alphabet):
/// `ticker_ok` exact; accepted tickers give a name <= 32 that starts with the fixed framing and carries
/// the ticker, a symbol <= 10 starting "pe"; refused tickers give None; the generic name is 30 bytes and
/// starts "Percolator Earn Share ". Mutants LP-M3, LP-M4.
#[kani::proof]
#[kani::unwind(46)]
#[kani::stub(percolator_prog::lp_share_meta_v22::base58_encode, base58_model)]
fn kani_v22_lp2_ticker_name_symbol_bounds() {
    let market: [u8; 32] = kani::any();
    let bytes: [u8; 9] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 9);
    let t = &bytes[..len];
    let ok = meta::ticker_ok(t);
    assert_eq!(ok, ticker_spec(t));
    let name = meta::ticker_name(&market, t);
    let sym = meta::ticker_symbol(t);
    if ok {
        let n = name.unwrap();
        let s = sym.unwrap();
        assert_eq!(n.len(), 16 + len + 1 + 6);
        assert!(n.len() <= meta::MPL_MAX_NAME_LEN);
        assert!(n.starts_with(meta::LP_SHARE_TICKER_NAME_PREFIX), "framing leads");
        assert!(&n[16..16 + len] == t);
        assert!(s.len() == 2 + len && s.len() <= meta::MPL_MAX_SYMBOL_LEN && s.starts_with(meta::LP_SHARE_SYMBOL_PREFIX));
    } else {
        assert!(name.is_none() && sym.is_none());
    }
    let g = meta::generic_name(&market);
    assert!(g.len() == 30 && g.len() <= meta::MPL_MAX_NAME_LEN && g.starts_with(meta::LP_SHARE_NAME_PREFIX));
    kani::cover!(ok && len == 1, "1-char ticker");
    kani::cover!(ok && len == 8, "8-char ticker");
    kani::cover!(!ok && len == 9, "too long");
    kani::cover!(!ok && len == 3 && t[0].is_ascii_lowercase(), "lowercase refused");
    kani::cover!(!ok && len == 0, "empty refused");
}

/// W-LP-3 (r1 obl. 2, R10). PROOF, CONDITIONAL(on W-LP-1): the uri is exactly base ++ path ++ base58,
/// at most 200 bytes, on BOTH compile-time bases, and `share_uri` uses this build's base. Mutant LP-M5.
#[kani::proof]
#[kani::unwind(46)]
#[kani::stub(percolator_prog::lp_share_meta_v22::base58_encode, base58_model)]
fn kani_v22_lp3_share_uri_shape() {
    let market: [u8; 32] = kani::any();
    assert!(meta::LP_SHARE_URI_MAX_LEN <= meta::MPL_MAX_URI_LEN);
    let mut which = 0u8;
    while which < 3 {
        let base: &str = match which {
            0 => meta::LP_SHARE_URI_BASE_DEVNET,
            1 => meta::LP_SHARE_URI_BASE_MAINNET,
            _ => meta::LP_SHARE_URI_BASE,
        };
        let u = if which == 2 { meta::share_uri(&market) } else { meta::share_uri_with_base(base, &market) };
        let bl = base.len();
        let pl = meta::LP_SHARE_URI_PATH.len();
        assert!(u.starts_with(base.as_bytes()));
        assert!(&u[bl..bl + pl] == meta::LP_SHARE_URI_PATH.as_bytes());
        let tail = u.len() - bl - pl;
        assert!((32..=44).contains(&tail));
        assert!(u.len() <= meta::MPL_MAX_URI_LEN);
        let mut i = bl + pl;
        while i < u.len() {
            assert!(B58_ALPHABET.contains(&u[i]));
            i += 1;
        }
        which += 1;
    }
    #[cfg(feature = "devnet")]
    assert_eq!(meta::LP_SHARE_URI_BASE, meta::LP_SHARE_URI_BASE_DEVNET);
    #[cfg(not(feature = "devnet"))]
    assert_eq!(meta::LP_SHARE_URI_BASE, meta::LP_SHARE_URI_BASE_MAINNET);
    kani::cover!(market[0] == 0, "any market");
}

fn rd_u32(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}

/// Checks the Borsh DataV2 body at `o`; returns the offset after it.
fn check_data_v2(d: &[u8], mut o: usize, n: &[u8], s: &[u8], u: &[u8]) -> usize {
    for f in [n, s, u] {
        assert_eq!(rd_u32(d, o), f.len());
        o += 4;
        assert!(&d[o..o + f.len()] == f);
        o += f.len();
    }
    assert!(d[o] == 0 && d[o + 1] == 0, "seller fee 0");
    assert!(d[o + 2] == 0 && d[o + 3] == 0 && d[o + 4] == 0, "creators, collection, uses None");
    o + 5
}

/// W-LP-4 (r1 obl. 3, r2 R4/R8). PROOF of both instruction-data builders for name <= 32, symbol <= 10,
/// uri <= 16 (BOUNDED uri length: the layout is length-prefixed and uniform in it). Mutants LP-M6, LP-M7.
#[kani::proof]
#[kani::unwind(34)]
fn kani_v22_lp4_metadata_instruction_data() {
    let nb: [u8; 32] = kani::any();
    let sb: [u8; 10] = kani::any();
    let ub: [u8; 16] = kani::any();
    let (nl, sl, ul): (usize, usize, usize) = (kani::any(), kani::any(), kani::any());
    kani::assume(nl <= 32 && sl <= 10 && ul <= 16);
    let (n, s, u) = (&nb[..nl], &sb[..sl], &ub[..ul]);
    let mutable: bool = kani::any();
    let c = meta::create_metadata_v3_data(n, s, u, mutable);
    assert_eq!(c[0], meta::MPL_IX_CREATE_METADATA_ACCOUNT_V3);
    let o = check_data_v2(&c, 1, n, s, u);
    assert!(c[o] == mutable as u8 && c[o + 1] == 0 && c.len() == o + 2);
    let freeze: bool = kani::any();
    let d = meta::update_metadata_v2_data(n, s, u, freeze);
    assert!(d[0] == meta::MPL_IX_UPDATE_METADATA_ACCOUNT_V2 && d[1] == 1, "data: Some");
    let o = check_data_v2(&d, 2, n, s, u);
    assert!(d[o] == 0, "new_update_authority: None");
    assert!(d[o + 1] == 0, "primary_sale_happened: None");
    if freeze {
        assert!(d[o + 2] == 1 && d[o + 3] == 0 && d.len() == o + 4, "is_mutable: Some(false)");
    } else {
        assert!(d[o + 2] == 0 && d.len() == o + 3, "is_mutable: None");
    }
    kani::cover!(mutable && freeze && nl == 32, "generic create, ticker freeze");
    kani::cover!(!mutable && !freeze && sl == 10, "ticker create, generic repair");
}

/// W-LP-5 (r2 R1/R2/R3/R4). PROOF: the two CPI builders sign only with the registry PDA, pass the mint
/// read-only, the transient payer PDA as the only writable signer, and nothing else. Mutant LP-M8.
#[kani::proof]
fn kani_v22_lp5_cpi_account_lists() {
    use solana_program::pubkey::Pubkey;
    let md = Pubkey::new_from_array(kani::any());
    let mint = Pubkey::new_from_array(kani::any());
    let reg = Pubkey::new_from_array(kani::any());
    let payer = Pubkey::new_from_array(kani::any());
    let m: bool = kani::any();
    let ix = meta::create_metadata_ix(&md, &mint, &reg, &payer, b"", b"", b"", m);
    assert_eq!(ix.program_id, meta::MPL_PROGRAM_ID);
    assert_eq!(ix.accounts.len(), 6);
    let a = &ix.accounts;
    assert!(a[0].pubkey == md && a[0].is_writable && !a[0].is_signer);
    assert!(a[1].pubkey == mint && !a[1].is_writable && !a[1].is_signer, "mint read-only");
    assert!(a[2].pubkey == reg && a[2].is_signer && !a[2].is_writable, "mint authority = registry");
    assert!(a[3].pubkey == payer && a[3].is_signer && a[3].is_writable, "payer = transient PDA");
    assert!(a[4].pubkey == reg && !a[4].is_signer && !a[4].is_writable, "update authority = registry");
    assert!(a[5].pubkey == solana_program::system_program::ID && !a[5].is_writable && !a[5].is_signer);
    assert_eq!(ix.data[0], meta::MPL_IX_CREATE_METADATA_ACCOUNT_V3);
    let f: bool = kani::any();
    let up = meta::update_metadata_ix(&md, &reg, b"", b"", b"", f);
    assert_eq!(up.program_id, meta::MPL_PROGRAM_ID);
    assert_eq!(up.accounts.len(), 2);
    assert!(up.accounts[0].pubkey == md && up.accounts[0].is_writable && !up.accounts[0].is_signer);
    assert!(up.accounts[1].pubkey == reg && up.accounts[1].is_signer && !up.accounts[1].is_writable);
    assert_eq!(up.data[0], meta::MPL_IX_UPDATE_METADATA_ACCOUNT_V2);
    kani::cover!(m && f, "both builders");
}

/// W-LP-6 (r1 obl. 4, r2 R6/R8). PROOF: `record_state` never panics on any byte string up to 400 B
/// (market concrete, so `generic_name` / `share_uri` evaluate concretely); every non-NotOurs result passed
/// the key/authority/mint prefix; `Mutable { canonical_generic: true }` carries exactly the generic name
/// and symbol. COST: M-L (symbolic 400 B, unwind 210). Mutant LP-M9.
#[kani::proof]
#[kani::unwind(210)]
#[kani::solver(cadical)]
fn kani_v22_lp6_record_state_total() {
    let data: [u8; 400] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 400);
    let reg: [u8; 32] = kani::any();
    let mint: [u8; 32] = kani::any();
    let market = [7u8; 32];
    let d = &data[..len];
    let st = meta::record_state(d, &reg, &mint, &market);
    match st {
        meta::RecordState::NotOurs => {}
        _ => {
            assert!(len >= 65 && d[0] == meta::MPL_KEY_METADATA_V1);
            assert!(d[1..33] == reg && d[33..65] == mint);
        }
    }
    if st == (meta::RecordState::Mutable { canonical_generic: true }) {
        let trim = |s: &[u8]| -> usize {
            let mut e = s.len();
            while e > 0 && s[e - 1] == 0 {
                e -= 1;
            }
            e
        };
        let nl = rd_u32(d, 65);
        let name = &d[69..69 + nl];
        assert!(&name[..trim(name)] == &meta::generic_name(&market)[..]);
        let so = 69 + nl;
        let sl = rd_u32(d, so);
        let sym = &d[so + 4..so + 4 + sl];
        assert!(&sym[..trim(sym)] == &meta::LP_SHARE_GENERIC_SYMBOL[..]);
        let uo = so + 4 + sl;
        let ul = rd_u32(d, uo);
        let fo = uo + 4 + ul;
        assert!(d[fo] == 0 && d[fo + 1] == 0, "seller fee 0");
        assert_eq!(d[fo + 2], 0, "no creators");
    }
    kani::cover!(st == meta::RecordState::NotOurs && len >= 65, "not ours");
    kani::cover!(st == meta::RecordState::Immutable, "immutable");
    kani::cover!(st == (meta::RecordState::Mutable { canonical_generic: false }), "ours, mutable, not canonical");
    kani::cover!(st == (meta::RecordState::Mutable { canonical_generic: true }), "ours, canonical generic");
}
