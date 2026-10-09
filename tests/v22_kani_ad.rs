//! v2.2 final Kani run: Wave A (lot precision, R3-M1 exits), Wave B (band/rent wrapper half) and
//! Wave D (rescue, insurance units, G9 backstop, W-4 split, allowlist, mainnet pin) harnesses on
//! the FULL wrapper crate (real `constants`, `state`, `oracle_v16`, `ix`, pure modules; nothing
//! copied). Design: `~/percolator-ops/ledger/kani-v22-final-run-design-2026-10-09.md` rev 1,
//! amended by rev 2 (R1.6, R1.7, R1.9, R2.4) and rev 2.1.
//!
//! Run (ONCE, after review; deployed flavour first):
//!   cargo kani --tests --features devnet -Z function-contracts -Z stubbing --exact --harness <name>
//! Flavour-dependent harnesses (mainnet secondary, same command without `--features devnet`):
//!   kani_v22_wa3_profile_shape, kani_v22_wa19_exit_requires_loss_current_flavour,
//!   kani_v22_wb2_band_lambda_and_alpha_caps, kani_v22_wd15_g9_oracle_allowed_truth_table,
//!   kani_v22_wd30_switchboard_program_predicate. Their assertions branch on
//!   `cfg!(feature = "devnet")`, so the same harness is right in both builds.
//!
//! Width policy (rev 2 R2.4 as resolved in review addendum W3): add/sub/min/compare at full width;
//! any symbolic `*` or `/` runs through the REAL primitive at the bounded operands stated per
//! harness (`vault_lp_v18::mul_div_floor` and `p4_rescue_ins::mul_div_ceil` are called, never
//! stubbed): no harness depends on a `proof_for_contract` of a dependency-crate function from an
//! integration test (the same policy as `tests/v22_kani_cfl.rs`). Results are labelled BOUNDED.
//! `kani_v22_mul_div_ceil_lemma` proves `mul_div_ceil` exact on the u16 domain its callers use.
//!
//! Every harness carries `kani::cover!` on each claimed branch; SUCCESSFUL with an unsatisfied
//! cover is VACUOUS (a failure). Mutant ids refer to rev 2 R4.5 / `kani/mutants/v22/wrapper_ad.tsv`.
#![cfg(kani)]
#![allow(clippy::all)]

extern crate kani;

use percolator_prog::constants;
use percolator_prog::growth_v19;
use percolator_prog::ix::Instruction;
use percolator_prog::mainnet_ids;
use percolator_prog::oracle_v16;
use percolator_prog::p4_rescue_ins as p4;
use percolator_prog::state;
use percolator_prog::vault_lp_v18 as vlp;
use percolator_prog::wave_a_v22 as wa;
use solana_program::pubkey::Pubkey;

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract / lemma harnesses (run FIRST: dependants are CONDITIONAL on them)
// ════════════════════════════════════════════════════════════════════════════════════════════


/// rev 2 R2.4: `p4_rescue_ins::mul_div_ceil` (`src/p4_rescue_ins.rs:31`) is the exact ceiling on
/// `a, b, d: u16`, `None` iff `d == 0` there (no overflow at this width). Every Wave D caller of it
/// below runs at u16 operands, inside this lemma's domain. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_mul_div_ceil_lemma() {
    let a = kani::any::<u16>() as u128;
    let b = kani::any::<u16>() as u128;
    let d = kani::any::<u16>() as u128;
    let r = p4::mul_div_ceil(a, b, d);
    if d == 0 {
        assert!(r.is_none());
    } else {
        let q = r.unwrap();
        let p = a * b;
        assert!(q * d >= p);
        assert!(q * d - p < d);
    }
    kani::cover!(d == 0, "None");
    kani::cover!(d != 0 && (a * b) % d != 0, "rounded up");
    kani::cover!(d != 0 && (a * b) % d == 0, "exact");
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Wave A
// ════════════════════════════════════════════════════════════════════════════════════════════

/// W-A-0 (K8-1, restored by rev 2 R1.6): `exit_gate` truth table, exhaustive over its five
/// booleans (`src/wave_a_v22.rs:185`). Mutant M8-1 (`if keeper_ok` -> `if true`). Cost S.
#[kani::proof]
fn kani_v22_wa0_exit_gate_truth_table() {
    let bound: bool = kani::any();
    let live: bool = kani::any();
    let signed: bool = kani::any();
    let keeper_ok: bool = kani::any();
    let req: bool = kani::any();
    let g = wa::exit_gate(bound, live, signed, keeper_ok, req);
    if bound || !live {
        assert_eq!(g, wa::ExitGate::Allow { require_loss_current: false });
    } else if signed {
        assert_eq!(g, wa::ExitGate::Allow { require_loss_current: req });
    } else if keeper_ok {
        assert_eq!(g, wa::ExitGate::Allow { require_loss_current: true });
    } else {
        assert_eq!(g, wa::ExitGate::NeedsRedeemerSignature);
    }
    // I-X4: an unsigned live non-bound exit is never allowed without keeper_ok, and always gated
    if !bound && live && !signed {
        if let wa::ExitGate::Allow { require_loss_current } = g {
            assert!(keeper_ok && require_loss_current);
        }
    }
    kani::cover!(bound || !live, "bound / resolved row");
    kani::cover!(!bound && live && signed, "signed row");
    kani::cover!(!bound && live && !signed && keeper_ok, "keeper row");
    kani::cover!(!bound && live && !signed && !keeper_ok, "needs signature row");
}

/// W-A-1 (K7-1, I-P2): `oracle_v16::clamp_toward_engine_dt` (`src/v16_program.rs:11700`) makes
/// progress at and above the crashed floor (`p >= 10_000`, the 1e7 floor after a 99.9% fall) and
/// never overshoots. Bounded: `p, target: u32`, `cap, dt: u16` cast up; the full-u64 claim is the
/// proptest `i_p2_progress_at_and_above_the_crashed_floor_full_width`. Mutant M7-1 (precondition
/// lowered to `p >= 9_999`: the tight cover then fails progress). Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wa1_lot_floor_guarantees_progress() {
    let p = kani::any::<u32>() as u64;
    let target = kani::any::<u32>() as u64;
    let cap = kani::any::<u16>() as u64;
    let dt = kani::any::<u16>() as u64;
    kani::assume(p >= 10_000 && target >= 1 && target != p && cap >= 1 && dt >= 1);
    let next = oracle_v16::clamp_toward_engine_dt(p, target, cap, dt);
    assert!(next != p, "progress (never spec CatchupRequired)");
    if target > p {
        assert!(p < next && next <= target);
    } else {
        assert!(target <= next && next < p);
    }
    kani::cover!(target > p, "up-move");
    kani::cover!(target < p, "down-move");
    kani::cover!(p == 10_000 && cap == 1 && dt == 1 && (next == p + 1 || next + 1 == p), "1 bps tick at the floor");
}

/// W-A-2 (K7-2): sharpness below the floor: `p in [1, 9_999]`, cap 1, dt 1 => no progress.
/// Cost S.
#[kani::proof]
fn kani_v22_wa2_lot_floor_is_tight() {
    let p = kani::any::<u16>() as u64;
    let target = kani::any::<u32>() as u64;
    kani::assume(p >= 1 && p <= 9_999 && target >= 1 && target != p);
    let next = oracle_v16::clamp_toward_engine_dt(p, target, 1, 1);
    assert_eq!(next, p);
    kani::cover!(p == 9_999, "the floor edge");
}

fn profile_with(mode: u8, pad: [u8; 5]) -> state::AssetOracleProfileV16 {
    let mut p = state::AssetOracleProfileV16::default();
    p.oracle_mode = mode;
    p._padding0 = pad;
    p
}

/// W-A-3 (K7-3): the profile byte validator `state::profile_lot_and_p4_bytes_ok`
/// (`src/v16_program.rs:4478`) is exactly the stated predicate over `_padding0` and the mode,
/// with the final `P4_FLAGS_KNOWN_MASK` (bit0 INS_UNITS_REQUIRED | bit2 EXIT_REQUIRES_LOSS_CURRENT;
/// flavour-independent, run in both flavours). Mutant M7-3 (drop `lot_mode_ok`). Cost S.
#[kani::proof]
#[kani::unwind(8)]
fn kani_v22_wa3_profile_shape() {
    let pad: [u8; 5] = kani::any();
    let mode: u8 = kani::any();
    kani::assume(mode < 4);
    let p = profile_with(mode, pad);
    let lot = pad[constants::PROFILE_LOT_EXP_IDX];
    let flags = pad[constants::PROFILE_P4_FLAGS_IDX];
    let expect = lot <= constants::LOT_EXP_MAX
        && (lot == 0 || mode == constants::ORACLE_MODE_AUTH_MARK || mode == constants::ORACLE_MODE_MANUAL)
        && flags & !constants::P4_FLAGS_KNOWN_MASK == 0
        && pad[2..] == [0u8; 3];
    assert_eq!(state::profile_lot_and_p4_bytes_ok(&p), expect);
    kani::cover!(expect && lot == 15 && mode == constants::ORACLE_MODE_AUTH_MARK, "lot 15 on AuthMark accepted");
    kani::cover!(!expect && lot == 1 && mode == constants::ORACLE_MODE_HYBRID_AFTER_HOURS, "lot on Hybrid refused");
    kani::cover!(expect && flags == constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT, "bit2 accepted");
    kani::cover!(expect && flags == constants::P4_FLAG_INS_UNITS_REQUIRED, "bit0 accepted (Wave D)");
    kani::cover!(!expect && flags == 2, "unknown bit1 refused");
}

/// W-A-4 (K7-4, I-P1): `state::carried_profile_padding0` (`src/v16_program.rs:4498`) is the
/// identity on lot and flags or error 119; bit2 is never cleared. Mutant M7-4 (returns
/// `NEW_PROFILE_PADDING0`). Cost S.
#[kani::proof]
#[kani::unwind(8)]
fn kani_v22_wa4_lot_carry_is_identity_or_119() {
    let lot: u8 = kani::any();
    let flags: u8 = kani::any();
    let old_mode: u8 = kani::any();
    let new_mode: u8 = kani::any();
    kani::assume(lot <= 15 && (flags == 0 || flags == constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT) && old_mode < 4 && new_mode < 4);
    let mut pad = [0u8; 5];
    pad[constants::PROFILE_LOT_EXP_IDX] = lot;
    pad[constants::PROFILE_P4_FLAGS_IDX] = flags;
    let p = profile_with(old_mode, pad);
    let r = state::carried_profile_padding0(&p, new_mode);
    let ok_mode = lot == 0 || new_mode == constants::ORACLE_MODE_AUTH_MARK || new_mode == constants::ORACLE_MODE_MANUAL;
    if ok_mode {
        assert!(r.as_ref().is_ok_and(|x| *x == pad));
    } else {
        let e: solana_program::program_error::ProgramError =
            percolator_prog::error::PercolatorError::LotConfigInvalid.into();
        assert!(r.as_ref().is_err_and(|x| *x == e));
    }
    kani::cover!(ok_mode && lot == 6 && new_mode == constants::ORACLE_MODE_AUTH_MARK, "AuthMark keeps lot 6");
    kani::cover!(!ok_mode && lot == 6 && new_mode == constants::ORACLE_MODE_EWMA_MARK, "EWMA with lot 6 refused");
    kani::cover!(ok_mode && lot == 0 && new_mode == constants::ORACLE_MODE_EWMA_MARK && flags != 0, "EWMA lot 0 keeps bit2");
}

/// W-A-5 (K7-5): `lot_price_below_floor(g, m) == g && m < 1e7` (`src/wave_a_v22.rs:26`), u64
/// full; `lot_exp_ok(l) == (l <= 15)`. Mutant M7-5 (predicate `false`). Cost S.
#[kani::proof]
fn kani_v22_wa5_lot_floor_predicate() {
    let g: bool = kani::any();
    let m: u64 = kani::any();
    let l: u8 = kani::any();
    assert_eq!(wa::lot_price_below_floor(g, m), g && m < 10_000_000);
    assert_eq!(wa::lot_exp_ok(l), l <= 15);
    kani::cover!(g && m < 10_000_000, "below floor");
    kani::cover!(g && m >= 10_000_000, "at or above floor");
    kani::cover!(!g, "non-growth");
}

fn any_counters() -> wa::LossCounters {
    wa::LossCounters {
        stale_long: kani::any(),
        stale_short: kani::any(),
        barrier_long: kani::any(),
        barrier_short: kani::any(),
        obligation_long: kani::any(),
        obligation_short: kani::any(),
        b_stale_accounts: kani::any(),
        negative_pnl_accounts: kani::any(),
        stale_certificates: kani::any(),
    }
}

fn genuine_zero(c: &wa::LossCounters) -> bool {
    c.barrier_long == 0
        && c.barrier_short == 0
        && c.obligation_long == 0
        && c.obligation_short == 0
        && c.b_stale_accounts == 0
        && c.negative_pnl_accounts == 0
        && c.stale_certificates == 0
}

/// W-A-6 (K8-1' rev 3, 9 counters): `loss_gate` (`src/wave_a_v22.rs:120`):
/// `Pass <=> !require || all zero`; `DipFloor <=> require && signed && stale != 0 && every genuine
/// counter zero`; else `Refuse`; an unsigned exit is never `DipFloor`. Full u64 counters.
/// Mutants R2 (no DipFloor fallback), R6 (b_stale ignored). Cost S.
#[kani::proof]
fn kani_v22_wa6_loss_gate() {
    let c = any_counters();
    let req: bool = kani::any();
    let signed: bool = kani::any();
    let all_zero = c.stale_long == 0 && c.stale_short == 0 && genuine_zero(&c);
    let g = wa::loss_gate(req, &c, signed);
    let expect = if !req || all_zero {
        wa::LossGate::Pass
    } else if signed && genuine_zero(&c) {
        wa::LossGate::DipFloor
    } else {
        wa::LossGate::Refuse
    };
    assert_eq!(g, expect);
    if !signed {
        assert!(g != wa::LossGate::DipFloor);
    }
    kani::cover!(g == wa::LossGate::Pass && req, "pass, loss-current");
    kani::cover!(g == wa::LossGate::DipFloor, "dip floor (stale only)");
    kani::cover!(g == wa::LossGate::Refuse && signed && c.b_stale_accounts != 0, "b_stale refuses a signed exit");
    kani::cover!(g == wa::LossGate::Refuse && !signed && (c.stale_long != 0), "unsigned stale refused");
}

/// W-A-7 (K8-2, I-X1): `effective_min_payout == max(wire, stored)`; `payout_meets_min` exact
/// (u128 atoms full width). Mutant M8-2 (`effective_min_payout = wire`). Cost S.
#[kani::proof]
fn kani_v22_wa7_min_payout() {
    let wire: u64 = kani::any();
    let stored: u64 = kani::any();
    let atoms: u128 = kani::any();
    let m = wa::effective_min_payout(wire, stored);
    assert_eq!(m, core::cmp::max(wire, stored));
    assert_eq!(wa::payout_meets_min(atoms, m), atoms >= m as u128);
    if wa::payout_meets_min(atoms, m) {
        assert!(atoms >= wire as u128 && atoms >= stored as u128);
    }
    kani::cover!(wire > stored, "wire binds");
    kani::cover!(stored > wire, "stored binds");
    kani::cover!(atoms == m as u128, "boundary admitted");
    kani::cover!(m > 0 && atoms + 1 == m as u128, "one below refused");
}

/// W-A-8 (K8-3): `loss_current <=>` all nine counters zero. Mutant: drop the barrier terms.
/// Cost S.
#[kani::proof]
fn kani_v22_wa8_loss_current_iff_all_zero() {
    let c = any_counters();
    let z = c.stale_long == 0 && c.stale_short == 0 && genuine_zero(&c);
    assert_eq!(wa::loss_current(&c), z);
    assert_eq!(wa::no_pending_genuine_loss(&c), genuine_zero(&c));
    kani::cover!(z, "loss-current");
    kani::cover!(!z && c.barrier_long != 0 && c.stale_long == 0, "barrier alone blocks");
}

/// W-A-9 (K8-4 rev, T9-P3 model over REAL functions): one non-bound pot, u8 amounts. A zero-sum
/// pair pending (winner gain `g` registered only when the winner is touched; loser loss `l == g`
/// routed into physical only when the loser is touched). Cohort census (A-1, engine-side):
/// `stale = !touch_w + !touch_l` on the loser/winner sides. An exit is priced on the CURRENT state
/// through the real `nonbound_pot_available` and `mul_div_floor`; executed iff `exit_gate`,
/// `loss_gate`, the dip floor (on `DipFloor`) and `payout_meets_min` pass. Asserts:
/// executed on `Pass` with the gate required => `x == x_ref` (value moved 0);
/// executed on `DipFloor` => `dip_floor_ok(x, par)` and `x >= min`; an unsigned executed exit is
/// loss-current. Mutants M8-4 (`loss_current` -> true), rule 1 removed. Cost M (model-level label).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wa9_t9_p3_dip_model() {
    let p = kani::any::<u8>() as u128;
    let h = kani::any::<u8>() as u128;
    let w_reg = kani::any::<u8>() as u128;
    let g = kani::any::<u8>() as u128;
    let sh = kani::any::<u8>() as u128;
    let s = kani::any::<u8>() as u128;
    let min = kani::any::<u8>() as u64;
    let tw: bool = kani::any();
    let tl: bool = kani::any();
    let signed: bool = kani::any();
    let keeper_ok: bool = kani::any();
    kani::assume(s > 0 && sh <= s && h + g <= 255 && w_reg + g <= 255 && w_reg <= h);
    let l = g; // zero-sum pair
    let reg = w_reg + if tw { g } else { 0 };
    let phys = h + if tl { l } else { 0 };
    let net = phys.saturating_sub(reg);
    let net_ref = (h + l).saturating_sub(w_reg + g);
    let x = vlp::mul_div_floor(sh, vlp::nonbound_pot_available(p, net), s).unwrap();
    let x_ref = vlp::mul_div_floor(sh, vlp::nonbound_pot_available(p, net_ref), s).unwrap();
    let mut c = wa::LossCounters::default();
    c.stale_long = (!tl) as u64;
    c.stale_short = (!tw) as u64;
    let par = vlp::mul_div_floor(sh, p, s).unwrap();
    let executed = match wa::exit_gate(false, true, signed, keeper_ok, true) {
        wa::ExitGate::NeedsRedeemerSignature => false,
        wa::ExitGate::Allow { require_loss_current } => {
            let ok_gate = match wa::loss_gate(require_loss_current, &c, signed) {
                wa::LossGate::Pass => true,
                wa::LossGate::DipFloor => wa::dip_floor_ok(x, par),
                wa::LossGate::Refuse => false,
            };
            ok_gate && wa::payout_meets_min(x, min)
        }
    };
    if executed {
        assert!(x >= min as u128);
        if wa::loss_current(&c) {
            assert_eq!(x, x_ref, "loss-current exit moves no value");
        } else {
            assert!(signed, "a keeper exit is always loss-current");
            assert!(wa::dip_floor_ok(x, par));
        }
    }
    kani::cover!(executed && tw && tl, "executed, all touched");
    kani::cover!(!executed && tw && !tl && !signed && keeper_ok, "keeper exit inside the dip refused");
    kani::cover!(executed && !wa::loss_current(&c) && signed, "signed exit on the dip floor");
    kani::cover!(executed && !signed && keeper_ok, "keeper exit on a loss-current book");
}

/// W-A-10 (K8-6'): `dip_floor_ok(payout, par) <=> 1e4 * payout >= 9_975 * par`
/// (`src/wave_a_v22.rs:133`), `payout: u128` full, `par: u64` cast up. Mutant: 9975 -> 9900.
/// Cost S.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wa10_dip_floor() {
    let payout: u128 = kani::any();
    let par = kani::any::<u64>() as u128;
    kani::assume(payout <= u64::MAX as u128);
    assert_eq!(wa::dip_floor_ok(payout, par), payout * 10_000 >= par * 9_975);
    kani::cover!(payout * 10_000 == par * 9_975 && par > 0, "boundary admitted");
    kani::cover!(payout * 10_000 < par * 9_975 && (payout + 1) * 10_000 >= par * 9_975, "one atom below refused");
}

/// W-A-11 (K8-7'): `cross_pot_netting` (`src/wave_a_v22.rs:157`) at full u128 width (add/sub/min
/// only): (i) ΣP invariant, (ii) no principal underflow `P_a', P_b' >= 0` (explicit, rev 2 R1.6),
/// (iii) `min(P_a',x_a) + min(P_b',x_b) == min(ΣP, Σx)` when a surplus and a deficit coexist,
/// (iv) backing unchanged (the function moves principal only), (v) `m == 0` otherwise.
/// u64 operands (so the sums fit). Mutants: `m = surplus + deficit`; wrong direction. Cost S.
#[kani::proof]
fn kani_v22_wa11_cross_pot_netting() {
    let pa = kani::any::<u64>() as u128;
    let xa = kani::any::<u64>() as u128;
    let pb = kani::any::<u64>() as u128;
    let xb = kani::any::<u64>() as u128;
    let (m, from_a) = wa::cross_pot_netting(pa, xa, pb, xb);
    let pair = (xa > pa && xb < pb) || (xb > pb && xa < pa);
    if !pair {
        assert_eq!(m, 0);
    } else {
        // (ii): the source pot has at least m of principal
        let (pa2, pb2) = if from_a {
            assert!(m <= pa);
            (pa - m, pb + m)
        } else {
            assert!(m <= pb);
            (pa + m, pb - m)
        };
        assert_eq!(pa2 + pb2, pa + pb); // (i)
        let lhs = core::cmp::min(pa2, xa) + core::cmp::min(pb2, xb);
        assert_eq!(lhs, core::cmp::min(pa + pb, xa + xb)); // (iii)
        assert!(lhs >= core::cmp::min(pa, xa) + core::cmp::min(pb, xb));
    }
    kani::cover!(pair && !from_a && (xa - pa) < (pb - xb), "m = surplus < deficit");
    kani::cover!(pair && !from_a && (xa - pa) > (pb - xb), "m = deficit < surplus");
    kani::cover!(pair && from_a, "mirror direction");
    kani::cover!(!pair, "m = 0");
}

/// W-A-12 (K8-8): `refresh_weight(legs) == BASE + legs` (saturating); at the leg cap 4 a refresh
/// weighs <= 7, so the 34-unit budget admits exactly 4 four-leg refreshes (5 would be 35). The
/// CU model is measured, not proved. Cost S.
#[kani::proof]
fn kani_v22_wa12_refresh_weight() {
    let legs: u32 = kani::any();
    assert_eq!(wa::refresh_weight(legs), constants::REDEMPTION_REFRESH_BASE_WEIGHT.saturating_add(legs));
    let cap = constants::WRAPPER_MAX_PORTFOLIO_ASSETS as u32;
    assert_eq!(cap, 4);
    if legs <= cap {
        assert!(wa::refresh_weight(legs) <= 7);
    }
    assert!(4 * wa::refresh_weight(cap) <= constants::REDEMPTION_REFRESH_WEIGHT_BUDGET);
    assert!(5 * wa::refresh_weight(cap) > constants::REDEMPTION_REFRESH_WEIGHT_BUDGET);
    kani::cover!(legs == cap, "a cap-leg refresh");
    kani::cover!(legs == u32::MAX, "saturation");
}

/// W-A-13 (K8-5 tag 77): `[77][domain u16][min u64][n u8]` decodes iff `n <= 8` and not
/// (`min == 0 && n == 0`), and then round-trips byte for byte; the 3-byte form decodes as the
/// legacy `ExecuteRedemption`. Mutant M8-5 (refresh cap check removed). Cost M.
#[kani::proof]
#[kani::unwind(40)]
fn kani_v22_wa13_tag77_v22_roundtrip() {
    let domain: u16 = kani::any();
    let min: u64 = kani::any();
    let n: u8 = kani::any();
    let mut data = [0u8; 12];
    data[0] = 77;
    data[1..3].copy_from_slice(&domain.to_le_bytes());
    data[3..11].copy_from_slice(&min.to_le_bytes());
    data[11] = n;
    let d = Instruction::decode(&data);
    let ok = n <= constants::REDEMPTION_REFRESH_MAX && !(min == 0 && n == 0);
    assert_eq!(d.is_ok(), ok);
    if let Ok(ref ix) = d {
        assert_eq!(*ix, Instruction::ExecuteRedemptionV22 { domain, min_payout_atoms: min, n_refresh: n });
        let e = ix.encode();
        assert!(e.as_slice() == &data[..]);
        core::mem::forget(e);
    }
    let legacy = Instruction::decode(&data[..3]);
    assert!(matches!(legacy, Ok(Instruction::ExecuteRedemption { domain: dd }) if dd == domain));
    kani::cover!(ok && n == 0 && min > 0, "n 0 with a floor");
    kani::cover!(ok && n == 8, "n = 8");
    kani::cover!(!ok && n == 9, "n = 9 refused");
    kani::cover!(!ok && n == 0 && min == 0, "all-zero trailer refused");
    core::mem::forget(legacy);
    core::mem::forget(d);
}

/// W-A-14 (K8-5 tag 76 + A4): `[76][shares u128][min u64][keeper_ok u8]` decodes iff
/// `keeper_ok <= 1 && min != 0` (A4: a v2.2 request always carries a floor), round-trips; the
/// 17-byte form is the legacy request. Mutant: A4 check removed. Cost M.
#[kani::proof]
#[kani::unwind(40)]
fn kani_v22_wa14_tag76_v22_roundtrip() {
    let shares: u128 = kani::any();
    let min: u64 = kani::any();
    let k: u8 = kani::any();
    let mut data = [0u8; 26];
    data[0] = 76;
    data[1..17].copy_from_slice(&shares.to_le_bytes());
    data[17..25].copy_from_slice(&min.to_le_bytes());
    data[25] = k;
    let d = Instruction::decode(&data);
    let ok = k <= 1 && min != 0;
    assert_eq!(d.is_ok(), ok);
    if let Ok(ref ix) = d {
        assert_eq!(*ix, Instruction::RequestRedeemLpSharesV22 { shares, min_payout_atoms: min, keeper_ok: k });
        let e = ix.encode();
        assert!(e.as_slice() == &data[..]);
        core::mem::forget(e);
    }
    let legacy = Instruction::decode(&data[..17]);
    assert!(matches!(legacy, Ok(Instruction::RequestRedeemLpShares { shares: s }) if s == shares));
    kani::cover!(ok && k == 1, "keeper_ok request");
    kani::cover!(!ok && k == 1 && min == 0, "A4: keeper_ok without a floor refused");
    kani::cover!(!ok && k == 2, "keeper_ok > 1 refused");
    core::mem::forget(legacy);
    core::mem::forget(d);
}

/// The canonical base InitMarket used by the W-A-15 length classes (any valid base; the trailer
/// grammar does not read the base fields).
fn base_init_market() -> Instruction {
    Instruction::InitMarket {
        max_portfolio_assets: 1,
        h_min: 1,
        h_max: 2,
        initial_price: 100,
        min_nonzero_mm_req: 1,
        min_nonzero_im_req: 2,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: 0,
        liquidation_fee_cap: 0,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 100,
        max_accrual_dt_slots: 10,
        max_abs_funding_e9_per_slot: 0,
        min_funding_lifetime_slots: 10,
        max_account_b_settlement_chunks: 1,
        max_bankrupt_close_chunks: 1,
        max_bankrupt_close_lifetime_slots: 100,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    }
}

/// W-A-15 helper: decode `base ++ trailer` where `trailer` holds `L` symbolic bytes; returns
/// (decode ok, round-trip holds on ok, trailer bytes). Grammar `growth(4) [lot(1)] [rent(6)
/// [band(18)]]` (`src/v16_program.rs:9010-9080`).
fn w_a15_case<const L: usize>() -> (bool, [u8; L]) {
    let t: [u8; L] = kani::any();
    let base = base_init_market();
    let mut data = base.encode();
    data.extend_from_slice(&t);
    let d = Instruction::decode(&data);
    let ok = d.is_ok();
    if let Ok(ref ix) = d {
        let e = ix.encode();
        assert!(e == data, "decode(x) re-encodes to x");
        core::mem::forget(e);
    }
    core::mem::forget(d);
    core::mem::forget(data);
    core::mem::forget(base);
    (ok, t)
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// W-A-15 len 0: the bare base decodes and round-trips. Cost S.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len0() {
    let (ok, _) = w_a15_case::<0>();
    assert!(ok);
    kani::cover!(ok, "base form");
}

/// W-A-15 len 4 (InitMarketV19): ok iff both growth fields non-zero. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len4() {
    let (ok, t) = w_a15_case::<4>();
    assert_eq!(ok, le16(&t[0..2]) != 0 && le16(&t[2..4]) != 0);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok, "zero growth field refused");
}

/// W-A-15 len 5 (InitMarketLotV22): ok iff growth non-zero and lot != 0 (canonical). Mutant: the
/// lot-0 refusal (`src/v16_program.rs:9034`) removed. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len5() {
    let (ok, t) = w_a15_case::<5>();
    assert_eq!(ok, le16(&t[0..2]) != 0 && le16(&t[2..4]) != 0 && t[4] != 0);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok && t[4] == 0 && le16(&t[0..2]) != 0 && le16(&t[2..4]) != 0, "lot 0 refused");
}

/// W-A-15 len 10 (V22, no lot, rent only): ok iff `l_launch != 0` and `r_gap != 0`. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len10() {
    let (ok, t) = w_a15_case::<10>();
    assert_eq!(ok, le16(&t[0..2]) != 0 && le16(&t[2..4]) != 0);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok, "refused");
}

/// W-A-15 len 11 (V22, lot + rent): ok iff lot != 0, `l_launch != 0`, `r_gap != 0`. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len11() {
    let (ok, t) = w_a15_case::<11>();
    assert_eq!(ok, t[4] != 0 && le16(&t[0..2]) != 0 && le16(&t[2..4]) != 0);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok && t[4] == 0, "lot 0 refused");
}

/// W-A-15 len 28 (V22, rent + band): ok iff `band_bps != 0` and `l_launch != 0` (r_gap may be 0
/// on a band market). Band block starts at trailer offset 10. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len28() {
    let (ok, t) = w_a15_case::<28>();
    assert_eq!(ok, le16(&t[10..12]) != 0 && le16(&t[2..4]) != 0);
    kani::cover!(ok && le16(&t[0..2]) == 0, "band market with derived r_gap 0");
    kani::cover!(!ok && le16(&t[10..12]) == 0, "band_bps 0 refused");
}

/// W-A-15 len 29 (V22, lot + rent + band): ok iff lot != 0, band != 0, `l_launch != 0`. Band block
/// at trailer offset 11. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_len29() {
    let (ok, t) = w_a15_case::<29>();
    assert_eq!(ok, t[4] != 0 && le16(&t[11..13]) != 0 && le16(&t[2..4]) != 0);
    kani::cover!(ok, "accepted");
    kani::cover!(!ok && t[4] == 0, "lot 0 refused");
}

/// W-A-15 refused class: every other remainder length in 1..=40 is refused (the trailer reads
/// fail or the trailing-byte check fires). One harness over a symbolic length. Cost M.
#[kani::proof]
#[kani::unwind(300)]
fn kani_v22_wa15_refused() {
    let t: [u8; 40] = kani::any();
    let n: usize = kani::any();
    kani::assume(n >= 1 && n <= 40 && ![4usize, 5, 10, 11, 28, 29].contains(&n));
    let base = base_init_market();
    let mut data = base.encode();
    data.extend_from_slice(&t[..n]);
    let d = Instruction::decode(&data);
    assert!(d.is_err());
    kani::cover!(n == 1, "one byte");
    kani::cover!(n == 6, "growth + 2");
    kani::cover!(n == 40, "too long");
    core::mem::forget(d);
    core::mem::forget(data);
    core::mem::forget(base);
}

/// W-A-19 (new, rev 2 R1.6): `state::profile_exit_requires_loss_current`
/// (`src/v16_program.rs:4471`): devnet => equals the bit2 flag; mainnet => always true. Run in
/// both flavours. Cost S.
#[kani::proof]
fn kani_v22_wa19_exit_requires_loss_current_flavour() {
    let pad: [u8; 5] = kani::any();
    let mode: u8 = kani::any();
    let p = profile_with(mode, pad);
    let bit = pad[constants::PROFILE_P4_FLAGS_IDX] & constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT != 0;
    let r = state::profile_exit_requires_loss_current(&p);
    // review addendum W2: statement-level #[cfg] so each build carries only its own covers (an
    // `if cfg!(..)` branch left the other flavour's cover unreachable in every build).
    #[cfg(feature = "devnet")]
    {
        assert_eq!(r, bit);
        kani::cover!(!r, "devnet: flag off -> not required");
    }
    #[cfg(not(feature = "devnet"))]
    {
        assert!(r);
        kani::cover!(!bit, "mainnet forces it on without the flag");
    }
    kani::cover!(bit, "flag on");
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Wave B (wrapper half)
// ════════════════════════════════════════════════════════════════════════════════════════════

/// W-B-1 (I-R1): `growth_v19::rent_rate_e9` (`src/growth_v19.rs:947`): `n_cap == 0` or kink > 1e4
/// => None; `u <= kink` => 0; `<= max`; `users >= n_cap` => max; monotone non-decreasing in users.
/// Real function (incl. the real `mul_div_ceil_u128`) at bounded operands: users/n_cap u16, kink
/// u16 <= 1e4, max u16. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wb1_rent_rate_kink_cap_monotone() {
    let u1 = kani::any::<u16>() as u128;
    let u2 = kani::any::<u16>() as u128;
    let n = kani::any::<u16>() as u128;
    let kink: u16 = kani::any();
    let max = kani::any::<u16>() as u64;
    kani::assume(kink as u128 <= 10_000);
    let r1 = growth_v19::rent_rate_e9(u1, n, kink, max);
    if n == 0 {
        assert!(r1.is_none());
    } else {
        let a = r1.unwrap();
        assert!(a <= max);
        if u1 * 10_000 <= kink as u128 * n {
            assert_eq!(a, 0);
        }
        // review addendum W1: at kink = 10_000 and u1 == n the below-kink rule (rate 0) applies,
        // so "at capacity => max" holds only strictly above the kink.
        if u1 >= n && u1 * 10_000 > kink as u128 * n {
            assert_eq!(a, max);
        }
        if u2 >= u1 {
            let b = growth_v19::rent_rate_e9(u2, n, kink, max).unwrap();
            assert!(b >= a, "monotone in users");
        }
    }
    kani::cover!(n == 0, "no capacity");
    kani::cover!(n > 0 && u1 * 10_000 <= kink as u128 * n, "below kink");
    kani::cover!(n > 0 && u1 * 10_000 > kink as u128 * n && u1 < n && max > 0, "kink region");
    kani::cover!(n > 0 && u1 >= n && u1 * 10_000 > kink as u128 * n && max > 0, "at capacity, above the kink");
    kani::cover!(n > 0 && u1 == n && kink == 10_000, "kink = 100%: at capacity is still below the kink");
}

/// W-B-2 (rev 2 R1.7): `band_lambda_max_bps` (`src/growth_v19.rs:818`) is `<=
/// BAND_LAMBDA_CAP_BPS` and `lambda * (mmr + G) <= 1e4 * 9_500`; flavour caps: devnet lambda cap
/// `MAX_LAMBDA_BPS` (10x) and alpha 70%; mainnet 3x and alpha 60% (`:833-857`). Both flavours.
/// Cost S.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wb2_band_lambda_and_alpha_caps() {
    let mmr = kani::any::<u16>() as u64;
    let g = kani::any::<u16>() as u64;
    let r = growth_v19::band_lambda_max_bps(mmr, g);
    let den = mmr as u128 + g as u128;
    if den == 0 {
        assert!(r.is_none());
    } else {
        let l = r.unwrap();
        assert!(l <= growth_v19::BAND_LAMBDA_CAP_BPS);
        assert!(l as u128 * den <= 10_000 * 9_500);
    }
    if cfg!(feature = "devnet") {
        assert_eq!(growth_v19::BAND_LAMBDA_CAP_BPS, growth_v19::MAX_LAMBDA_BPS);
        assert_eq!(growth_v19::ALLOC_ALPHA_MAX_BAND_BPS, 7_000);
    } else {
        assert_eq!(growth_v19::BAND_LAMBDA_CAP_BPS, 30_000);
        assert_eq!(growth_v19::ALLOC_ALPHA_MAX_BAND_BPS, 6_000);
    }
    assert_eq!(growth_v19::alloc_alpha_max_bps(true), growth_v19::ALLOC_ALPHA_MAX_BAND_BPS);
    kani::cover!(r.is_some_and(|l| l == growth_v19::BAND_LAMBDA_CAP_BPS), "capped");
    kani::cover!(r.is_some_and(|l| l < growth_v19::BAND_LAMBDA_CAP_BPS), "uncapped");
    kani::cover!(den == 0, "zero denominator");
}

/// W-B-3: `graduation_allowed(b, t) <=> b != 0 && t >= 1`. Cost S.
#[kani::proof]
fn kani_v22_wb3_graduation_requires_band_and_depth() {
    let b: u64 = kani::any();
    let t: u8 = kani::any();
    assert_eq!(growth_v19::graduation_allowed(b, t), b != 0 && t >= 1);
    kani::cover!(growth_v19::graduation_allowed(b, t), "allowed");
    kani::cover!(b == 0 && t >= 1, "no band");
}

/// W-B-4 (I-1): `c_launch_atoms_for(c) >= MIN_C_LAUNCH_ATOMS` and `>= c` (u128 full). Cost S.
#[kani::proof]
fn kani_v22_wb4_c_launch_floor() {
    let c: u128 = kani::any();
    let r = growth_v19::c_launch_atoms_for(c);
    assert!(r >= growth_v19::MIN_C_LAUNCH_ATOMS && r >= c);
    assert!(r == c || r == growth_v19::MIN_C_LAUNCH_ATOMS);
    kani::cover!(r == c, "c above floor");
    kani::cover!(r > c, "floor binds");
}

/// W-B-5: `rent_rate_e9_fail_closed <= rent_max` and `== rent_max` whenever `rent_rate_e9` is
/// None (bounded as W-B-1). Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wb5_rent_rate_fail_closed() {
    let u = kani::any::<u16>() as u128;
    let n = kani::any::<u16>() as u128;
    let kink: u16 = kani::any();
    let max = kani::any::<u16>() as u64;
    let r = growth_v19::rent_rate_e9_fail_closed(u, n, kink, max);
    assert!(r <= max);
    if growth_v19::rent_rate_e9(u, n, kink, max).is_none() {
        assert_eq!(r, max);
    }
    kani::cover!(n == 0, "None -> max");
    kani::cover!(kink as u128 > 10_000 && n > 0, "kink out of domain -> max");
    kani::cover!(n > 0 && kink as u128 <= 10_000, "in domain");
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Wave D
// ════════════════════════════════════════════════════════════════════════════════════════════

/// W-D-1 (L-RES, I-RS1): rescue no dilution, on the real `rescue_shares` / `rescue_claim_delta` and
/// the real `mul_div_floor`, u16 operands (review round 2 N6: the u32 x u64 version bit-blasted a full
/// 128-bit divider at a width likely to time out). At u16 the admission floor (`RESCUE_MIN_ATOMS` =
/// 1e8) is unreachable, so the harness assumes the impaired shape `v > 0, s > 0, v < c, 0 < x <= 10v`
/// that `rescue_admitted` implies, not admission itself: the no-dilution facts depend only on the
/// floor rounding, not on the floor / size gates (those are W-D-3, at x < 2^34). Labelled BOUNDED.
/// Mutant: `rescue_shares` with div_ceil. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd1_rescue_no_dilution() {
    let v = kani::any::<u16>() as u128;
    let c = kani::any::<u16>() as u128;
    let s = kani::any::<u16>() as u128;
    let x = kani::any::<u16>() as u128;
    kani::assume(v > 0 && s > 0 && v < c && x > 0 && x <= 10 * v);
    let m = p4::rescue_shares(x, s, v).unwrap();
    let dc = p4::rescue_claim_delta(m, c, s).unwrap();
    assert!(p4::rescue_value_no_dilution(v, x, s, m));
    assert!(p4::rescue_claim_no_dilution(v, c, s, m, dc));
    kani::cover!(m * c > x * s, "strictly cheaper than par");
    kani::cover!(m > 0, "shares minted");
}

/// W-D-2 (I-RS2): par per share not raised by a rescue; falls by less than one atom per share.
/// Mutant: `rescue_claim_delta` with div_ceil. Cost M-L (real `mul_div_floor`, bounded; review addendum W3).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd2_rescue_par_per_share() {
    let c = kani::any::<u32>() as u128;
    let s = kani::any::<u32>() as u128;
    let m = kani::any::<u32>() as u128;
    kani::assume(s > 0);
    let dc = p4::rescue_claim_delta(m, c, s).unwrap();
    assert!(p4::rescue_par_per_share_not_raised(c, s, m, dc));
    assert!((c + dc) * s + s > c * (s + m));
    kani::cover!(dc > 0, "claim grows");
}

/// W-D-3 (I-RS3 pure arm): `rescue_admitted Ok =>` impaired, at or above the 5% NAV floor, amount
/// in `[RESCUE_MIN_ATOMS, 10 v]`. `x: u64 < 2^34`, others u32. Mutants: drop the floor clause; drop
/// `v >= par`. Cost S.
#[kani::proof]
fn kani_v22_wd3_rescue_refuses_floor() {
    let x = kani::any::<u64>() as u128;
    let v = kani::any::<u32>() as u128;
    let c = kani::any::<u32>() as u128;
    let s = kani::any::<u32>() as u128;
    kani::assume(x < (1u128 << 34));
    let r = p4::rescue_admitted(x, v, c, s);
    if r.is_ok() {
        assert!(v < c);
        assert!(v * 10_000 >= c * 500 && v > 0);
        assert!(x >= p4::RESCUE_MIN_ATOMS && x <= 10 * v);
        assert!(s > 0);
    }
    kani::cover!(r == Err(p4::RescueRefusal::NavFloor), "dead vault refused");
    kani::cover!(r == Err(p4::RescueRefusal::NotImpaired), "not impaired");
    kani::cover!(r.is_ok(), "admitted");
}

/// W-D-4 (I-S3): unit mint and burn never dilute; a dust top-up mints 0. u16 operands (the burn
/// path calls the real `mul_div_ceil`, inside `kani_v22_mul_div_ceil_lemma`'s domain); the mint
/// uses the real `mul_div_floor`. Mutants: topup div_ceil; burn floor. Cost M-L (bounded; review
/// addendum W3).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd4_units_mint_burn_no_dilution() {
    let i = kani::any::<u16>() as u128;
    let u = kani::any::<u16>() as u128;
    let x = kani::any::<u16>() as u128;
    let a = kani::any::<u16>() as u128;
    kani::assume(i > 0 && u > 0);
    let m = p4::ins_units_for_topup(x, u, i).unwrap();
    assert!(p4::ins_mint_no_dilution(i, u, x, m));
    kani::assume(a <= i);
    if let Some(b) = p4::ins_units_to_burn(a, u, i) {
        assert!(b <= u);
        assert!(p4::ins_burn_no_dilution(i, u, a, b));
    }
    kani::cover!(m == 0 && x > 0, "dust top-up mints nothing");
    kani::cover!(a > 0 && p4::ins_units_to_burn(a, u, i).is_some(), "burn");
}

/// W-D-5 (W-1): an admitted top-up (`x > 0`, rev 2 R1.9) mints `m > 0`, does not dilute, loses at
/// most 1 bp + 1 atom; genesis needs `INS_UNITS_GENESIS_MIN_ATOMS`. Review round 2 N6: the general
/// arm runs at u16 operands on the real `ins_units_for_topup` / `mul_div_floor` (BOUNDED); the genesis
/// arm has no division (`m == x`) and keeps a u32 `x` so both sides of the 1e6 genesis minimum are
/// reachable. Mutant: drop `minted == 0` refusal. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd5_admitted_mint_positive_and_bounded() {
    let genesis: bool = kani::any();
    if genesis {
        let x = kani::any::<u32>() as u128;
        kani::assume(x > 0);
        let i = kani::any::<u32>() as u128;
        let m = p4::ins_units_for_topup(x, 0, i).unwrap();
        assert_eq!(m, x);
        assert_eq!(p4::ins_mint_admissible(x, m, 0, i), x >= p4::INS_UNITS_GENESIS_MIN_ATOMS);
        kani::cover!(x >= p4::INS_UNITS_GENESIS_MIN_ATOMS, "genesis admitted");
        kani::cover!(x < p4::INS_UNITS_GENESIS_MIN_ATOMS, "dust genesis refused");
        return;
    }
    let u = kani::any::<u16>() as u128;
    let i = kani::any::<u16>() as u128;
    let x = kani::any::<u16>() as u128;
    kani::assume(x > 0 && u > 0 && i > 0);
    let m = p4::ins_units_for_topup(x, u, i).unwrap();
    if p4::ins_mint_admissible(x, m, u, i) {
        assert!(m > 0);
        assert!(p4::ins_mint_no_dilution(i, u, x, m));
        let value = m * i / u;
        assert!(value <= x);
        assert!(x - value <= x / 10_000 + 1);
    }
    kani::cover!(p4::ins_mint_admissible(x, m, u, i) && u != i, "admitted with u != i");
    kani::cover!(m == 0, "refused: mints nothing");
}

/// W-D-6 (I-S3, losses): a loss is shared pro rata between two classes, within the floor
/// rounding (u16, real `ins_units_value` and real `mul_div_floor`). Mutant: per-class denominators.
/// Cost M-L (real `mul_div_floor`, bounded; review addendum W3).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd6_loss_pro_rata() {
    let us = kani::any::<u16>() as u128;
    let uc = kani::any::<u16>() as u128;
    let i = kani::any::<u16>() as u128;
    let l = kani::any::<u16>() as u128;
    kani::assume(us > 0 && uc > 0 && l <= i);
    let t = us + uc;
    let vs0 = p4::ins_units_value(us, t, i).unwrap();
    let vc0 = p4::ins_units_value(uc, t, i).unwrap();
    let vs1 = p4::ins_units_value(us, t, i - l).unwrap();
    let vc1 = p4::ins_units_value(uc, t, i - l).unwrap();
    let lhs = vs1 * vc0;
    let rhs = vc1 * vs0;
    let diff = if lhs > rhs { lhs - rhs } else { rhs - lhs };
    // floor errors e_k < 1 give |diff| < vs0 + vc0 + 1, hence <= vs0 + vc0 (design bound)
    assert!(diff <= vs0 + vc0, "pro rata within rounding (cross-multiplied)");
    assert!(vs1 <= vs0 && vc1 <= vc0);
    assert!(vs0 + vc0 <= i && vs1 + vc1 <= i - l, "the classes never hold more than the fund");
    kani::cover!(l > 0 && vs1 < vs0 && vc1 < vc0, "both classes lose");
}

/// W-D-7 (I-S5): `backstop_draw_amount` bounded by deficit, free insurance and the cumulative cap.
/// u32 values, `cap <= 1e4`, `free <= gross`. Mutant: drop the cap term. Cost S.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd7_backstop_bounded() {
    let d = kani::any::<u32>() as u128;
    let f = kani::any::<u32>() as u128;
    let g = kani::any::<u32>() as u128;
    let o = kani::any::<u32>() as u128;
    let cap: u16 = kani::any();
    kani::assume(cap <= 10_000 && f <= g);
    let m = p4::backstop_draw_amount(d, f, g, o, cap);
    assert!(m <= d && m <= f);
    assert!(m == 0 || (o + m) * 10_000 <= (g + o) * cap as u128);
    kani::cover!(m == d && m > 0, "deficit binds");
    kani::cover!(m == f && m > 0 && m < d, "free binds");
    kani::cover!(m > 0 && m < d && m < f, "cap binds");
}

/// W-D-8 (I-S5 order): `backstop_due => d > 0 && drawable == 0 && pending == 0 && senior_nav == 0`
/// and conversely (u128 full). Mutant: drop `senior_nav == 0`. Cost S.
#[kani::proof]
fn kani_v22_wd8_backstop_only_after_seniors() {
    let d: u128 = kani::any();
    let dr: u128 = kani::any();
    let p: u128 = kani::any();
    let n: u128 = kani::any();
    assert_eq!(p4::backstop_due(d, dr, p, n), d != 0 && dr == 0 && p == 0 && n == 0);
    kani::cover!(p4::backstop_due(d, dr, p, n), "due");
    kani::cover!(d != 0 && dr == 0 && p == 0 && n != 0, "reserved senior NAV blocks");
}

/// W-D-9 (I-S6): recovery repays the backstop first: `backstop_recovery_split` exact; then the
/// seniors are restored by 0 while `v - c_eff <= o` (real `vault_lp_recover` fed the net value,
/// u16). Mutant: omit `- o`. Cost S.
#[kani::proof]
fn kani_v22_wd9_recovery_backstop_first() {
    let r: u128 = kani::any();
    let o: u128 = kani::any();
    let (b, rest) = p4::backstop_recovery_split(r, o);
    assert_eq!(b + rest, r);
    assert_eq!(b, core::cmp::min(r, o));
    let v = kani::any::<u16>() as u128;
    let c_eff = kani::any::<u16>() as u128;
    let ob = kani::any::<u16>() as u128;
    let l = vlp::DrawLedger {
        senior_claim: kani::any::<u16>() as u128,
        drawn: kani::any::<u16>() as u128,
        outstanding: kani::any::<u16>() as u128,
        pending: 0,
    };
    let above = v.saturating_sub(c_eff).saturating_sub(ob);
    let (_, to_seniors) = vlp::vault_lp_recover(l, above);
    if v.saturating_sub(c_eff) <= ob {
        assert_eq!(to_seniors, 0);
    }
    kani::cover!(r > o && o > 0, "backstop then rest");
    kani::cover!(v.saturating_sub(c_eff) <= ob && v > c_eff && l.outstanding > 0, "backstop absorbs the recovery");
    kani::cover!(to_seniors > 0, "seniors restored after the backstop");
}

/// W-D-10 (W-2 window): delay elapsed => proposal open, delay and window bounds; a lapsed proposal
/// never executes; saturation arm near `u64::MAX`. Mutants: delay ignored; window bound dropped.
/// Cost S.
#[kani::proof]
fn kani_v22_wd10_g9_window() {
    let p: u64 = kani::any();
    let n: u64 = kani::any();
    let e = p4::g9_delay_elapsed(p, n);
    if e {
        assert!(p != 0);
        assert!(n as u128 >= p as u128 + p4::G9_DELAY_SLOTS as u128);
        assert!((n as u128) < p as u128 + (p4::G9_DELAY_SLOTS + p4::G9_EXEC_WINDOW_SLOTS) as u128);
        assert!(p4::g9_proposal_open(p, n));
    }
    if !p4::g9_proposal_open(p, n) {
        assert!(!e);
    }
    kani::cover!(e, "executable");
    kani::cover!(p != 0 && !e && p4::g9_proposal_open(p, n), "pending, not yet");
    kani::cover!(p > u64::MAX - 10_000, "saturation arm");
}

/// W-D-11 (W-2 epoch room): `drawn + room <= max(drawn, floor(base * cap / 1e4))` (u128 full,
/// `bps_floor` is overflow-free). Mutant: cap dropped. Cost S.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd11_epoch_room() {
    let base = kani::any::<u64>() as u128;
    let drawn = kani::any::<u64>() as u128;
    let cap: u16 = kani::any();
    kani::assume(cap <= 10_000);
    let room = p4::g9_epoch_room(base, drawn, cap);
    let lim = vlp::bps_floor(base, cap).unwrap();
    assert!(drawn + room <= core::cmp::max(drawn, lim));
    kani::cover!(room > 0, "room left");
    kani::cover!(room == 0 && drawn > 0, "epoch exhausted");
}

/// W-D-12 (W-2 eligibility): `g9_vault_eligible(s, d) <=> s > 0 && d > 0`. Cost S.
#[kani::proof]
fn kani_v22_wd12_g9_eligibility() {
    let s: u128 = kani::any();
    let d: u128 = kani::any();
    assert_eq!(p4::g9_vault_eligible(s, d), s > 0 && d > 0);
    kani::cover!(p4::g9_vault_eligible(s, d), "eligible");
    kani::cover!(s > 0 && d == 0, "no booked draw");
}

/// W-D-13 (W-3): the combined reading is `min(Σp, Σf)`: `min(p_a,f_a) + min(p_b,f_b) + m ==
/// min(p_a+p_b, f_a+f_b)` with `m` from the real `cross_pot_netting`; corollary: with the combined
/// reading `>= par`, `rescue_admitted` refuses (`NotImpaired`). u32. Cost S.
#[kani::proof]
fn kani_v22_wd13_combined_reading_is_min_sum() {
    let pa = kani::any::<u32>() as u128;
    let fa = kani::any::<u32>() as u128;
    let pb = kani::any::<u32>() as u128;
    let fb = kani::any::<u32>() as u128;
    let (m, _) = wa::cross_pot_netting(pa, fa, pb, fb);
    let v = core::cmp::min(pa, fa) + core::cmp::min(pb, fb) + m;
    assert_eq!(v, core::cmp::min(pa + pb, fa + fb));
    let par = kani::any::<u32>() as u128;
    let x = kani::any::<u64>() as u128;
    let s = kani::any::<u32>() as u128;
    kani::assume(par > 0 && s > 0 && fa + fb >= par && pa + pb >= par);
    assert!(p4::rescue_admitted(x, v, par, s).is_err());
    kani::cover!(m > 0, "netting applies");
}

/// W-D-14 (W-9, halt half only): the fill op halts iff the halt mirror is non-zero
/// (`vault_lp_draw_halts(mirror, FILL) == (mirror != 0)`). NOT implementable as designed for the
/// mirror itself: `vault_lp_halt_mirror` is a private processor fn (`src/v16_program.rs:32606`);
/// a shim would move panic locations (P-7). Its body (`drawn_outstanding + backstop`, saturating)
/// stays with LiteSVM: `tests/p4_wave_d.rs:2627` `sec_d6_fill_halt_counts_the_backstop`, killed-by row
/// `LS-W9` of `kani/mutants/v22/wrapper_litesvm.tsv`. Cost S.
#[kani::proof]
fn kani_v22_wd14_halt_on_mirror() {
    let mirror: u128 = kani::any();
    let op: u8 = kani::any();
    assert_eq!(vlp::vault_lp_draw_halts(mirror, vlp::DRAW_OP_LP_RISK_INCREASING_FILL), mirror != 0);
    if mirror == 0 {
        assert!(!vlp::vault_lp_draw_halts(mirror, op));
    }
    // seniors 75/76/77 never halt
    assert!(!vlp::vault_lp_draw_halts(mirror, vlp::DRAW_OP_SENIOR_DEPOSIT_75));
    assert!(!vlp::vault_lp_draw_halts(mirror, vlp::DRAW_OP_SENIOR_REQUEST_76));
    assert!(!vlp::vault_lp_draw_halts(mirror, vlp::DRAW_OP_SENIOR_REDEEM_77));
    kani::cover!(mirror != 0, "halted");
}

/// W-D-15 (R-1/R-8): `g9_oracle_allowed` truth table: without the override, allowed iff mode is
/// Hybrid AND authenticated; the override is monotone and admits everything; at the handler the
/// override is `cfg!(feature = "devnet")` (gate G-WD). Flavour-dependent assertion. Mutants
/// M-R1a..d, override ignored. Cost S.
#[kani::proof]
fn kani_v22_wd15_g9_oracle_allowed_truth_table() {
    let mode: u8 = kani::any();
    let auth: bool = kani::any();
    let dev: bool = kani::any();
    let a = p4::g9_oracle_allowed(mode, auth, dev);
    if !dev {
        assert_eq!(a, mode == 1 && auth);
    } else {
        assert!(a);
    }
    if p4::g9_oracle_allowed(mode, auth, false) {
        assert!(p4::g9_oracle_allowed(mode, auth, true));
    }
    let flavour = cfg!(feature = "devnet");
    assert_eq!(p4::g9_oracle_allowed(mode, auth, flavour), flavour || (mode == 1 && auth));
    kani::cover!(a && !dev, "authenticated Hybrid");
    kani::cover!(!a && mode == 1 && !auth, "R-8: unauthenticated Hybrid refused");
    kani::cover!(!a && mode == 3, "AuthMark refused");
    kani::cover!(!a && mode == 2, "EWMA refused");
    kani::cover!(dev && mode == 0, "devnet override");
}

/// W-D-16 (R-2): `ins_burn_admissible` with `burned != class` is exactly the 1 bp + 1 atom bound;
/// a full-class exit is always admitted. u16 (real `mul_div_ceil` in the lemma's domain).
/// `assume(burned > 0)` with its cover. Mutants M-R2a..e. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd16_burn_admissible_bounds_loss() {
    let a = kani::any::<u16>() as u128;
    let u = kani::any::<u16>() as u128;
    let i = kani::any::<u16>() as u128;
    let held = kani::any::<u16>() as u128;
    kani::assume(u > 0 && i > 0 && a <= i);
    let burned = match p4::ins_units_to_burn(a, u, i) {
        Some(b) => b,
        None => return,
    };
    kani::assume(burned > 0 && held >= burned);
    let ok = p4::ins_burn_admissible(a, burned, u, i, held);
    if burned == held {
        assert!(ok, "full exit always admitted");
    } else {
        let value = burned * i / u;
        assert_eq!(ok, value.saturating_sub(a) <= a / 10_000 + 1);
    }
    kani::cover!(ok && burned != held, "admitted partial");
    kani::cover!(!ok && burned != held, "refused: one whole unit for a tiny withdrawal");
    kani::cover!(ok && burned == held, "admitted via full exit");
    kani::cover!(burned > 0, "assumption satisfiable");
}

/// W-D-16b (R-2, overflow arm): when `burned * I_free` overflows u128 the burn is refused (fail
/// closed) unless it is a full-class exit or `a == 0`. Linear check only (`checked_mul` overflow
/// detection), full u128 width. Kills mutant D27 (`None => return true`), which the u16 harness
/// cannot reach. Cost S.
#[kani::proof]
fn kani_v22_wd16b_burn_admissible_overflow_fails_closed() {
    let a: u128 = kani::any();
    let burned: u128 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let held: u128 = kani::any();
    kani::assume(a != 0 && burned != held && u != 0 && burned.checked_mul(i).is_none());
    assert!(!p4::ins_burn_admissible(a, burned, u, i, held));
    kani::cover!(true, "overflow arm reached");
}

/// W-D-17 (R-2 full exit): `held == ceil(a*U/I)` (full class exit) loses less than one unit's
/// value and is never paid more than burned. `U <= 255, I <= 4095`. Mutant: burn floor. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd17_full_exit_loss_below_one_unit() {
    let u = kani::any::<u8>() as u128;
    let i = (kani::any::<u16>() & 0x0fff) as u128;
    let a = (kani::any::<u16>() & 0x0fff) as u128;
    kani::assume(u > 0 && i > 0 && a > 0 && a <= i);
    if let Some(held) = p4::ins_units_to_burn(a, u, i) {
        let value_floor = held * i / u;
        let value_ceil = (held * i).div_ceil(u);
        assert!(value_ceil >= a, "never paid more than burned");
        assert!(value_floor - a < i.div_ceil(u), "over-burn below one unit's value");
        kani::cover!(value_floor > a, "rounding is lossy");
    }
}

/// W-D-18 (R-2): burn then re-mint never nets more units than burned (u8). Mutants: topup
/// div_ceil; burn floor. Cost M-L (real `mul_div_floor`, bounded; review addendum W3).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd18_burn_then_mint_no_gain() {
    let u = kani::any::<u8>() as u128;
    let i = kani::any::<u8>() as u128;
    let a = kani::any::<u8>() as u128;
    kani::assume(u > 0 && i > 0 && a > 0 && a < i);
    if let Some(b) = p4::ins_units_to_burn(a, u, i) {
        if b < u {
            let m = p4::ins_units_for_topup(a, u - b, i - a).unwrap();
            assert!(m <= b);
            kani::cover!(m < b, "strict loss on the round trip");
        }
    }
}

/// W-D-19 (R-6): `backstop_restore_free(e, im, cap) == min(cap, e - (im + ceil(im/10)))`
/// (saturating), so `f > 0 => e - f >= im + buf`; `e <= im + buf => 0`. `im: u32`, `e, cap: u64`
/// (no overflow arm here; see W-D-25 for it). Mutants M-R6a..d. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd19_restore_free_keeps_im_buffer() {
    let e = kani::any::<u64>() as u128;
    let im = kani::any::<u32>() as u128;
    let cap = kani::any::<u64>() as u128;
    let buf = im.div_ceil(10);
    let f = p4::backstop_restore_free(e, im, cap);
    assert_eq!(f, core::cmp::min(cap, e.saturating_sub(im + buf)));
    if f > 0 {
        assert!(e - f >= im + buf);
    }
    if e <= im + buf {
        assert_eq!(f, 0);
    }
    kani::cover!(f == cap && f > 0, "capital-limited");
    kani::cover!(f > 0 && f < cap, "equity-limited");
    kani::cover!(f == 0 && e > im, "the buffer, not IM, blocks");
    kani::cover!(im == 0 && f > 0, "flat LP");
    kani::cover!(im % 10 != 0 && f > 0, "rounded buffer");
}

/// W-D-20 (R-6): `backstop_restore_amount(o, free, req) <= min(o, free)`, `<= req` when set,
/// `== min(o, free)` when `req == 0`. u128 full. Mutant: drop `.min(requested)`. Cost S.
#[kani::proof]
fn kani_v22_wd20_restore_amount_never_exceeds_free() {
    let o: u128 = kani::any();
    let f: u128 = kani::any();
    let r: u128 = kani::any();
    let a = p4::backstop_restore_amount(o, f, r);
    let m = core::cmp::min(o, f);
    assert!(a <= m);
    if r == 0 {
        assert_eq!(a, m);
    } else {
        assert!(a <= r);
        assert_eq!(a, core::cmp::min(m, r));
    }
    kani::cover!(r != 0 && r < m, "request binds");
}

/// W-D-21 (K-R12-1, supersedes the R-7 truth table): `g9_leg_ok(s, k, a) <=> k && a && s != Other`
/// (12 cases). Mutants: Chainlink exempt; `Other => true`; drop `key_matches`. Cost S.
#[kani::proof]
fn kani_v22_wd21_leg_ok_truth_table() {
    let sel: u8 = kani::any();
    kani::assume(sel < 3);
    let s = match sel {
        0 => p4::G9LegSource::Chainlink,
        1 => p4::G9LegSource::Switchboard,
        _ => p4::G9LegSource::Other,
    };
    let k: bool = kani::any();
    let a: bool = kani::any();
    assert_eq!(p4::g9_leg_ok(s, k, a), k && a && s != p4::G9LegSource::Other);
    kani::cover!(sel == 0 && k && a, "listed Chainlink ok");
    kani::cover!(sel == 0 && k && !a, "unlisted Chainlink refused (R-12)");
    kani::cover!(sel == 1 && k && a, "listed Switchboard ok");
    kani::cover!(sel == 2 && k && a, "Other refused");
    kani::cover!(!k && a, "key mismatch refused");
}

/// W-D-22 (R-9): `g9_senior_drawn_room` never lends beyond the seniors' still-outstanding loss;
/// `r == 0` once outstanding reaches the licence. u32. Mutants M-R9a..d. Cost S.
#[kani::proof]
fn kani_v22_wd22_licence_never_exceeds_outstanding_loss() {
    let dr = kani::any::<u32>() as u128;
    let so = kani::any::<u32>() as u128;
    let o = kani::any::<u32>() as u128;
    let r = p4::g9_senior_drawn_room(dr, so, o);
    assert!(r <= dr && r <= so);
    if r > 0 {
        assert!(r + o <= core::cmp::min(dr, so));
    }
    if o >= core::cmp::min(dr, so) {
        assert_eq!(r, 0);
    }
    kani::cover!(r > 0, "room");
    kani::cover!(r == 0 && o > 0, "exhausted");
    kani::cover!(dr > so && r > 0, "post-recovery state");
}

/// W-D-22b (R-9): monotone in recovery: `room(dr, so - rec, o) <= room(dr, so, o)`. u32. Cost S.
#[kani::proof]
fn kani_v22_wd22b_licence_shrinks_on_recovery() {
    let dr = kani::any::<u32>() as u128;
    let so = kani::any::<u32>() as u128;
    let o = kani::any::<u32>() as u128;
    let rec = kani::any::<u32>() as u128;
    kani::assume(rec <= so);
    let a = p4::g9_senior_drawn_room(dr, so - rec, o);
    let b = p4::g9_senior_drawn_room(dr, so, o);
    assert!(a <= b);
    kani::cover!(a < b, "strict");
}

/// W-D-23: the G9 amount composition in the handler's order (`src/v16_program.rs:37222-37249`):
/// draw amount (cumulative cap 50%) -> `min` R-9 licence -> `min` epoch room on `gross + o` at
/// 20% -> `min` caller max. Each bound holds and each `min` binds in some trace. u16. Mutants:
/// any single `min` removed. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd23_g9_amount_composed_bounds() {
    let d = kani::any::<u16>() as u128;
    let free = kani::any::<u16>() as u128;
    let gross = kani::any::<u16>() as u128;
    let o = kani::any::<u16>() as u128;
    let drawn = kani::any::<u16>() as u128;
    let sr = kani::any::<u16>() as u128;
    let ed = kani::any::<u16>() as u128;
    let maxa = kani::any::<u16>() as u128;
    kani::assume(free <= gross);
    let a1 = p4::backstop_draw_amount(d, free, gross, o, p4::BACKSTOP_CAP_BPS);
    let lic = p4::g9_senior_drawn_room(drawn, sr, o);
    let ep = p4::g9_epoch_room(gross + o, ed, p4::G9_EPOCH_CAP_BPS);
    let mut amt = a1.min(lic).min(ep);
    if maxa != 0 {
        amt = amt.min(maxa);
    }
    assert!(amt <= d && amt <= free);
    if amt > 0 {
        assert!(o + amt <= core::cmp::min(drawn, sr));
        assert!((o + amt) * 10_000 <= (gross + o) * 5_000);
        assert!(ed + amt <= core::cmp::max(ed, (gross + o) * 2_000 / 10_000));
    }
    kani::cover!(amt > 0 && amt == d, "deficit binds");
    kani::cover!(amt > 0 && amt == lic && lic < d, "licence binds");
    kani::cover!(amt > 0 && amt == ep && ep < lic && ep < a1, "epoch room binds");
    kani::cover!(amt > 0 && amt == free && free < d, "free binds");
}

/// W-D-24 (K-W4-1): `backstop_restore_split` at full u128 width (min/sub only): `p + c <=
/// min(outstanding, room, req-if-set)`, `p <= pnl_cap`, `c <= capital`, PnL first, mode-1
/// equivalence at `pnl_cap == 0`. Mutants: capital first; no `.min(capital)`; no equity room; `p`
/// uncapped. Cost S.
#[kani::proof]
fn kani_v22_wd24_restore_split() {
    let out: u128 = kani::any();
    let room: u128 = kani::any();
    let req: u128 = kani::any();
    let pc: u128 = kani::any();
    let cap: u128 = kani::any();
    let (p, c) = p4::backstop_restore_split(out, room, req, pc, cap);
    let want = p4::backstop_restore_amount(out, room, req);
    assert!(p <= want && c <= want - p, "no overflow of p + c");
    assert!(p + c <= out && p + c <= room);
    if req != 0 {
        assert!(p + c <= req);
    }
    assert!(p <= pc && c <= cap);
    if c > 0 {
        assert_eq!(p, core::cmp::min(pc, want), "PnL first");
    }
    if pc == 0 {
        assert_eq!((p, c), (0, core::cmp::min(want, cap)), "mode-1 equivalence");
    }
    kani::cover!(p > 0 && c > 0, "both sources");
    kani::cover!(p > 0 && c == 0, "PnL only");
    kani::cover!(p == 0 && c > 0, "capital only");
    kani::cover!(req != 0 && req < core::cmp::min(out, room), "request binds");
    kani::cover!(room < out && room < req, "room binds");
}

/// W-D-25 (K-W4-2): `backstop_restore_free == min(backstop_restore_equity_room, capital)` and the
/// room is 0 when `equity <= IM`; `im: u64` cast up, plus the overflow arm (`im > u128::MAX/1000`:
/// both fail closed to 0). Mutant: free computed without the equity room. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_wd25_restore_free_is_min_room_capital() {
    let e: u128 = kani::any();
    let cap: u128 = kani::any();
    let small: bool = kani::any();
    let im: u128 = if small {
        kani::any::<u64>() as u128
    } else {
        let v: u128 = kani::any();
        kani::assume(v > u128::MAX / 1_000);
        v
    };
    let room = p4::backstop_restore_equity_room(e, im);
    assert_eq!(p4::backstop_restore_free(e, im, cap), core::cmp::min(room, cap));
    assert!(room <= e);
    if e <= im {
        assert_eq!(room, 0);
    }
    if !small {
        assert_eq!(room, 0, "overflow fails closed");
    }
    kani::cover!(small && room > 0, "room");
    kani::cover!(!small, "overflow arm");
}

/// D-TAG abstraction (rev 1 1.9, rev 2.1): a key array of `N` entries where every entry is
/// `[t; 32]` (`t: u8` symbolic), except entry `full` which is a fully symbolic 32-byte key. The
/// functions under proof compare keys only for equality with each other and with `[0; 32]`;
/// 4 x 16 = 64 keys need 65 distinct values, which `u8` tags provide, so every equality pattern is
/// realised. The fully symbolic entry covers keys that differ in one byte only.
fn tagged_keys<const N: usize>(full: usize) -> [[u8; 32]; N] {
    let mut ks = [[0u8; 32]; N];
    let mut i = 0;
    while i < N {
        if i == full {
            ks[i] = kani::any();
        } else {
            let t: u8 = kani::any();
            ks[i] = [t; 32];
        }
        i += 1;
    }
    ks
}

/// W-D-26 (K-R10-1): `g9_allowlist_removal_only(cur, new) <=> every new key is in cur` (slices of
/// length <= 4, D-TAG); set equality when both directions; `commit_ready(0, _) == false` and
/// `commit_ready(s, n) <=> n >= s + 216,000` with no wrap; monotone in `now`. Mutants: delay
/// ignored; `>` for `>=`; removal_only always true; `contains` inverted. Cost S.
#[kani::proof]
#[kani::unwind(34)]
fn kani_v22_wd26_allowlist_removal_and_commit() {
    let cur: [[u8; 32]; 4] = tagged_keys::<4>(0);
    let new: [[u8; 32]; 4] = tagged_keys::<4>(1);
    let nc: usize = kani::any();
    let nn: usize = kani::any();
    kani::assume(nc <= 4 && nn <= 4);
    let r = p4::g9_allowlist_removal_only(&cur[..nc], &new[..nn]);
    let mut expect = true;
    for k in new[..nn].iter() {
        if !cur[..nc].contains(k) {
            expect = false;
        }
    }
    assert_eq!(r, expect);
    kani::cover!(r && nn > 0 && nn < nc, "a strict removal");
    kani::cover!(!r, "an addition refused");
    let s: u64 = kani::any();
    let n: u64 = kani::any();
    let n2: u64 = kani::any();
    let ready = p4::g9_allowlist_commit_ready(s, n);
    let t = constants::G9_ALLOWLIST_TIMELOCK_SLOTS;
    assert_eq!(t, 216_000);
    assert_eq!(ready, s != 0 && (s as u128 + t as u128) <= u64::MAX as u128 && n as u128 >= s as u128 + t as u128);
    if ready && n2 >= n {
        assert!(p4::g9_allowlist_commit_ready(s, n2));
    }
    kani::cover!(ready, "commit ready");
    kani::cover!(s != 0 && !ready && n >= s, "inside the timelock");
    kani::cover!(s > u64::MAX - t, "overflow arm fails closed");
}

/// W-D-27 (K-R10-2): `state::validate_g9_feed_allowlist` (`src/v16_program.rs:7289`) at the
/// production CAP 16 (D-TAG on all four arrays): `Ok <=>` version 1, counts <= 16, zero pad, keys
/// and owners non-zero in `[..count)`, keys pairwise distinct there (owners need NOT be distinct),
/// zero tails, the same for `pending_*`, and `pending_slot == 0 <=> pending_count == 0`.
/// Mutants: drop the pending iff clause; drop key distinctness. Cost M.
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
fn kani_v22_wd27_allowlist_record_validator() {
    let mut x: state::G9FeedAllowlistV22 = bytemuck::Zeroable::zeroed();
    x.count = kani::any();
    x.version = kani::any();
    x.bump = kani::any();
    x.pending_count = kani::any();
    x._pad = kani::any();
    x.pending_slot = kani::any();
    x.keys = tagged_keys::<16>(0);
    x.owners = tagged_keys::<16>(1);
    x.pending_keys = tagged_keys::<16>(2);
    x.pending_owners = tagged_keys::<16>(3);
    let ok = state::validate_g9_feed_allowlist(&x).is_ok();
    const CAP: usize = 16;
    let n = x.count as usize;
    let pn = x.pending_count as usize;
    let well = |ks: &[[u8; 32]; CAP], os: &[[u8; 32]; CAP], n: usize| -> bool {
        if n > CAP {
            return false;
        }
        let mut good = true;
        let mut i = 0;
        while i < CAP {
            if i < n {
                if ks[i] == [0u8; 32] || os[i] == [0u8; 32] {
                    good = false;
                }
                let mut j = i + 1;
                while j < n {
                    if ks[i] == ks[j] {
                        good = false;
                    }
                    j += 1;
                }
            } else if ks[i] != [0u8; 32] || os[i] != [0u8; 32] {
                good = false;
            }
            i += 1;
        }
        good
    };
    let expect = x.version == constants::G9_FEED_ALLOWLIST_VERSION
        && n <= CAP
        && pn <= CAP
        && x._pad == [0u8; 4]
        && well(&x.keys, &x.owners, n)
        && well(&x.pending_keys, &x.pending_owners, pn)
        && ((x.pending_slot_u64() == 0) == (pn == 0));
    assert_eq!(ok, expect);
    kani::cover!(ok && n == 16 && pn == 0, "full record, no proposal");
    kani::cover!(ok && n > 1 && x.owners[0] == x.owners[1], "shared owner accepted");
    kani::cover!(!ok && n >= 2 && x.keys[0] == x.keys[1] && x.keys[0] != [0u8; 32], "duplicate key refused");
    kani::cover!(!ok && pn == 0 && x.pending_slot_u64() != 0, "orphan pending slot refused");
    kani::cover!(ok && pn > 0, "open proposal accepted");
}

/// W-D-28 (K-R10-2 owner pin): `g9_owner_matches(a, b) <=> a, b Some && equal`; `g9_leg_feed_owner`
/// reads `[10..42)` (Chainlink) / `[2056..2088)` (Switchboard), `None` when short or `Other`.
/// Mutants: `None == None` true; Switchboard offset 2048. Cost M (2,100 symbolic bytes).
#[kani::proof]
#[kani::unwind(34)]
fn kani_v22_wd28_owner_pin() {
    let a: Option<[u8; 32]> = kani::any();
    let b: Option<[u8; 32]> = kani::any();
    assert_eq!(p4::g9_owner_matches(a.as_ref(), b.as_ref()), a.is_some() && b.is_some() && a == b);
    let data: [u8; 2100] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 2100);
    let d = &data[..len];
    let cl = p4::g9_leg_feed_owner(p4::G9LegSource::Chainlink, d);
    let sb = p4::g9_leg_feed_owner(p4::G9LegSource::Switchboard, d);
    assert!(p4::g9_leg_feed_owner(p4::G9LegSource::Other, d).is_none());
    assert_eq!(oracle_v16::CL_OFF_FEED_OWNER, 10);
    assert_eq!(oracle_v16::SB_OFF_FEED_AUTHORITY, 2056);
    if len >= 42 {
        assert!(cl.is_some_and(|o| o[..] == data[10..42]));
    } else {
        assert!(cl.is_none());
    }
    if len >= 2088 {
        assert!(sb.is_some_and(|o| o[..] == data[2056..2088]));
    } else {
        assert!(sb.is_none());
    }
    kani::cover!(a.is_none() && b.is_none(), "both missing never match");
    kani::cover!(len == 2087, "one byte short");
    kani::cover!(sb.is_some(), "switchboard owner read");
}

/// W-D-29 (K-PIN-1): `mainnet_ids::ids_consistent(&[a, b, c, d]) <=>` all four non-zero and
/// pairwise distinct (`src/mainnet_ids.rs:107`); full symbolic keys. Mutants: drop `!same`; set
/// flag `||` -> `&&`. Cost S.
#[kani::proof]
#[kani::unwind(34)]
fn kani_v22_wd29_ids_consistent() {
    let ids: [[u8; 32]; 4] = kani::any();
    let mut expect = true;
    for i in 0..4 {
        if ids[i] == [0u8; 32] {
            expect = false;
        }
        for j in (i + 1)..4 {
            if ids[i] == ids[j] {
                expect = false;
            }
        }
    }
    assert_eq!(mainnet_ids::ids_consistent(&ids), expect);
    kani::cover!(expect, "consistent");
    kani::cover!(ids[3] == [0u8; 32] && ids[0] != [0u8; 32], "an unset arm");
    kani::cover!(ids[1] == ids[2] && ids[1] != [0u8; 32], "an equal pair");
}

/// W-D-30 (R12-2): `oracle_v16::is_switchboard_on_demand_program` (`src/v16_program.rs:11130`):
/// true for the mainnet On-Demand id on both flavours; true for the devnet id iff `devnet`;
/// false for any other owner. Flavour-dependent; run in both. Mutant: drop the cfg guard (killed
/// by the mainnet run). Cost S.
#[kani::proof]
#[kani::unwind(34)]
fn kani_v22_wd30_switchboard_program_predicate() {
    let raw: [u8; 32] = kani::any();
    let owner = Pubkey::new_from_array(raw);
    let main = oracle_v16::SWITCHBOARD_ON_DEMAND_MAINNET_PROGRAM_ID;
    let dev = oracle_v16::SWITCHBOARD_ON_DEMAND_DEVNET_PROGRAM_ID;
    let r = oracle_v16::is_switchboard_on_demand_program(&owner);
    assert_eq!(r, owner == main || (cfg!(feature = "devnet") && owner == dev));
    assert!(oracle_v16::is_switchboard_on_demand_program(&main));
    assert_eq!(oracle_v16::is_switchboard_on_demand_program(&dev), cfg!(feature = "devnet"));
    kani::cover!(owner == main, "mainnet id");
    kani::cover!(owner == dev, "devnet id");
    kani::cover!(!r, "other owner");
}
