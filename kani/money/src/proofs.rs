//! Money-path no-dilution proofs (2026-10-14, LP-audit item 9). Run ONCE each on final code.
//!
//! WHY the earlier no-dilution harnesses timed out (every solver, every width down to u8): they
//! asked a bit-level solver to prove the FACTORED inequality, e.g. `(V + a) * B >= V * (B + m)`,
//! from the floor fact `m * V <= a * B`. That step is two ring identities (distributivity and
//! commutativity of `*`) plus cancelling `V * B`; a SAT solver can only "see" them by comparing
//! different multiplier circuits bit by bit, which is the classic hard case (it timed out even on
//! 8-bit operands). So the claim is split at that joint:
//!
//!   (C) primitive contract: the floor / ceil primitive returns the exact quotient in remainder
//!       form. Proved here on the REAL primitive at u8 operands (`money_c_*`); the lift to u128 is
//!       the same paper step the growth proofs use (the bodies are two-line wrappers over core u128
//!       `checked_mul`, `/`, `%`; their own logic is width-independent).
//!   (W) FULL-WIDTH wiring, on the REAL production function: every u128 input symbolic, the
//!       primitive replaced by its proven contract (`stub_verified`, or for `p4::mul_div_ceil`,
//!       which carries no contract attribute, a stub that assumes EXACTLY the relation `money_c_p4_ceil`
//!       proves). Asserted: every guard / fail-closed branch, the operands and rounding direction,
//!       and the no-dilution claim in its EXPANDED form, written over the SAME product terms the
//!       contract uses (so no multiplier has to be re-derived).
//!   (P) paper: expanded form <=> factored form, by distributivity / commutativity of integer `*`
//!       (stated per harness). Checked natively, factored form, on the real functions:
//!       exhaustive at small widths + proptest at full width (tests/v22_money_paths_native.rs).
//!
//! Every harness carries `kani::cover!` on each asserted branch; a SUCCESSFUL run with an
//! unsatisfied cover does not count. Mutants: `--features mut_*` (see ../mkmutants.py).
use crate::bond_v20::{bond_atoms_for_redemption, bond_claim_after_redemption, bond_shares_for_deposit};
use crate::growth_v19::spec;
use crate::p4_rescue_ins::{
    ins_units_for_topup, ins_units_to_burn, ins_units_value, rescue_admitted, rescue_claim_delta,
    rescue_shares, RESCUE_MAX_MULT, RESCUE_MIN_ATOMS,
};

// ── (C) primitive contracts, REAL primitives, u8 operands ───────────────────────────────────────

/// (C1) `vault_lp_v18::mul_div_floor` meets its contract (`mul_div_floor_spec` exact floor in
/// remainder form, None <=> d == 0 or overflow; plus the range fact). u8 operands widened to u128.
#[kani::proof_for_contract(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(cadical)]
fn money_c_mul_div_floor() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    let r = crate::vault_lp_v18::mul_div_floor(a, b, d);
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "inexact floor");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d == 0), "exact");
    kani::cover!(r == Some(0) && a * b > 0, "rounds to 0");
}

/// (C2) the REAL `p4_rescue_ins::mul_div_ceil` (no contract attribute in production) satisfies the
/// exact ceil relation `growth_v19::spec::mul_div_ceil` (None <=> d == 0 or overflow; Some(q) =>
/// `ceil_rel(a*b, d, q)`). u8 operands. This is the relation `p4_mul_div_ceil_stub` assumes.
#[kani::proof]
#[kani::solver(cadical)]
fn money_c_p4_ceil() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    let r = crate::p4_rescue_ins::mul_div_ceil(a, b, d);
    assert!(spec::mul_div_ceil(a, b, d, r), "p4 mul_div_ceil is the exact ceil");
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "rounds up");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d == 0), "exact");
    kani::cover!(r == Some(0), "zero product");
}

/// Stub for `p4_rescue_ins::mul_div_ceil`: ANY result satisfying exactly the relation (C2) proves.
fn p4_mul_div_ceil_stub(a: u128, b: u128, d: u128) -> Option<u128> {
    let r: Option<u128> = kani::any();
    kani::assume(spec::mul_div_ceil(a, b, d, r));
    r
}

// ── (W) bonds ─────────────────────────────────────────────────────────────────────────────────

/// W-C-5 bond DEPOSIT no-dilution, FULL u128 width, REAL `bond_shares_for_deposit`.
/// Expanded claim: `m * V <= amount * B` (and `amount * B - m * V < V`: exactly the floor).
/// (P): `(V + amount) * B - V * (B + m) = amount * B - m * V`, so the expanded claim is exactly
/// "incumbents not diluted" `(V+amount)/(B+m) >= V/B`; and `amount*(B+m) - m*(V+amount) =
/// amount*B - m*V`, i.e. "the new shares are worth at most what was paid".
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn money_wc5_bond_deposit_no_dilution_full() {
    let amount: u128 = kani::any();
    let b: u128 = kani::any();
    let v: u128 = kani::any();
    let r = bond_shares_for_deposit(amount, b, v);
    if b == 0 {
        assert!(r == Some(amount), "genesis mints 1:1");
        kani::cover!(amount > 0, "COVER: genesis");
        return;
    }
    if v == 0 {
        assert!(r.is_none(), "zero value with shares outstanding fails closed");
        kani::cover!(true, "COVER: zero value refused");
        return;
    }
    match (r, amount.checked_mul(b)) {
        (Some(m), Some(p)) => {
            let mv = m.checked_mul(v);
            assert!(mv.is_some());
            let mv = mv.unwrap();
            assert!(mv <= p, "incumbents not diluted (expanded): m*V <= amount*B");
            assert!(p - mv < v, "exact floor: one share less would under-mint");
            kani::cover!(m > 0 && p - mv > 0, "COVER: floored mint");
            kani::cover!(m > 0 && p == mv, "COVER: exact mint");
            kani::cover!(m > 0 && amount > u64::MAX as u128 && v > u64::MAX as u128, "COVER: beyond u64");
        }
        (None, None) => kani::cover!(true, "COVER: product overflow fails closed"),
        _ => assert!(false, "None exactly on overflow"),
    }
}

/// W-C-6 bond REDEMPTION no-dilution, FULL width, REAL `bond_atoms_for_redemption` and
/// `bond_claim_after_redemption`. Expanded claims: payout `pay * B <= sh * value` (and `< + B`),
/// slice `slice * B <= sh * C_b` (and `< + B`) with `C_b' = C_b - slice`.
/// (P): `(value - pay) * B - value * (B - sh) = sh*value - pay*B` (remaining value per share not
/// lowered, i.e. the leaver takes at most its pro-rata), and `C_b' * B - C_b * (B - sh) =
/// sh*C_b - slice*B` (remaining claim per share not lowered).
/// NOT asserted here (order facts, not ring identities; native-checked): `pay <= value`,
/// `slice <= C_b` (so `C_b'` is Some), `sh == B => C_b' == 0`.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn money_wc6_bond_redemption_no_dilution_full() {
    let sh: u128 = kani::any();
    let b: u128 = kani::any();
    let value: u128 = kani::any();
    let cb: u128 = kani::any();
    let pay = bond_atoms_for_redemption(sh, b, value);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if b == 0 || sh > b {
        assert!(pay.is_none() && cb2.is_none(), "B == 0 or shares > B fail closed");
        kani::cover!(sh > b, "COVER: over-redemption refused");
        return;
    }
    match (pay, sh.checked_mul(value)) {
        (Some(pay), Some(p)) => {
            let pb = pay.checked_mul(b);
            assert!(pb.is_some());
            let pb = pb.unwrap();
            assert!(pb <= p, "leaver takes at most its pro-rata (expanded): pay*B <= sh*value");
            assert!(p - pb < b, "exact floor");
            kani::cover!(pay > 0 && sh < b && p - pb > 0, "COVER: partial redemption, floored");
            kani::cover!(pay > 0 && sh == b, "COVER: full redemption");
        }
        (None, None) => kani::cover!(true, "COVER: payout overflow fails closed"),
        _ => assert!(false, "payout None exactly on overflow"),
    }
    match (cb2, sh.checked_mul(cb)) {
        (Some(c2), Some(p)) => {
            assert!(c2 <= cb);
            let slice = cb - c2;
            let sb = slice.checked_mul(b);
            assert!(sb.is_some());
            let sb = sb.unwrap();
            assert!(sb <= p, "claim slice at most pro-rata (expanded): slice*B <= sh*C_b");
            assert!(p - sb < b, "exact floor slice");
            kani::cover!(slice > 0 && sh < b && value < cb, "COVER: impaired tranche, claim slice");
            kani::cover!(slice > 0 && sh < b && value == cb, "COVER: whole tranche, claim slice");
        }
        (None, None) => kani::cover!(true, "COVER: slice overflow fails closed"),
        (None, Some(_)) => {} // slice > C_b: impossible for sh <= B (order fact; native-checked)
        (Some(_), None) => assert!(false, "claim Some only without overflow"),
    }
}

// ── (W) rescue, ON THE ADMITTED RANGE ─────────────────────────────────────────────────────────

/// W-D-1 / I-RS2 rescue no-dilution, FULL u128 width, restricted to ADMITTED rescues: the REAL
/// `rescue_admitted(x, v, par, s)` is assumed Ok (the earlier W-D-1 box held NO admitted input).
/// The processor prices the shares on `x_eff = min(value added, x) <= x` (v16_program.rs:37919),
/// refuses `m == 0`, and on a bound vault adds `dC = rescue_claim_delta(m, C, S)` with `C = par`.
/// Expanded claims: L-RES `m * v <= x_eff * S` (and `< + v`); I-RS2 `dC * S <= m * C` (and `< + S`).
/// (P): `(v + x_eff) * S - v * (S + m) = x_eff*S - m*v` (value per share not lowered at the same
/// reading) and `C * (S + m) - (C + dC) * S = m*C - dC*S` (par per share not raised).
/// NOT asserted (order facts): the claim half `(C + dC) * S >= v * (S + m)` (needs `v < C`);
/// native-checked, and enforced at run time by `rescue_claim_no_dilution` (fail closed).
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn money_wd1_rescue_admitted_no_dilution_full() {
    let x: u128 = kani::any();
    let v: u128 = kani::any();
    let par: u128 = kani::any();
    let s: u128 = kani::any();
    let x_eff: u128 = kani::any();
    kani::assume(rescue_admitted(x, v, par, s).is_ok());
    kani::assume(x_eff <= x);
    // Admission facts at full width (W-D-3 proved them only for x < 2^34).
    assert!(s > 0 && v > 0 && v < par, "admitted => shares outstanding and impaired");
    assert!(x >= RESCUE_MIN_ATOMS, "admitted => at least the minimum");
    assert!(v.checked_mul(RESCUE_MAX_MULT).is_some_and(|mx| x <= mx), "admitted => x <= 10 v");
    kani::cover!(x == RESCUE_MIN_ATOMS, "COVER: smallest admitted rescue");
    let m = rescue_shares(x_eff, s, v);
    match (m, x_eff.checked_mul(s)) {
        (Some(m), Some(p)) => {
            let mv = m.checked_mul(v);
            assert!(mv.is_some());
            let mv = mv.unwrap();
            assert!(mv <= p, "L-RES (expanded): m*v <= x_eff*S");
            assert!(p - mv < v, "exact floor: rounded against the rescuer by < 1 share");
            kani::cover!(m > 0 && p - mv > 0, "COVER: admitted rescue, floored mint");
            kani::cover!(m > 0 && x_eff < x, "COVER: admitted rescue priced on x_eff < x");
            if m > 0 {
                match (rescue_claim_delta(m, par, s), m.checked_mul(par)) {
                    (Some(dc), Some(q)) => {
                        let ds = dc.checked_mul(s);
                        assert!(ds.is_some());
                        let ds = ds.unwrap();
                        assert!(ds <= q, "I-RS2 (expanded): dC*S <= m*C, par per share not raised");
                        assert!(q - ds < s, "exact floor dC");
                        kani::cover!(dc > 0 && q - ds > 0, "COVER: admitted rescue, claim delta floored");
                    }
                    (None, None) => kani::cover!(true, "COVER: claim-delta overflow fails closed"),
                    _ => assert!(false, "dC None exactly on overflow"),
                }
            }
        }
        (None, None) => kani::cover!(true, "COVER: share-price overflow fails closed"),
        _ => assert!(false, "m None exactly on overflow"),
    }
}

// ── (W) insurance units (wrapper side) ─────────────────────────────────────────────────────────

/// Insurance-unit MINT no-dilution, FULL width, REAL `ins_units_for_topup`.
/// Expanded: `m * I <= x * U` (and `< + I`). (P): `(I + x) * U - I * (U + m) = x*U - m*I`
/// (incumbents not diluted; the doc's `(I_mint + x) * U >= I_mint * (U + minted)`), and
/// `x*(U+m) - m*(I+x) = x*U - m*I` (new units worth at most what was paid).
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn money_s3_ins_units_mint_no_dilution_full() {
    let x: u128 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let r = ins_units_for_topup(x, u, i);
    if u == 0 {
        assert!(r == Some(x), "genesis 1:1");
        kani::cover!(x > 0, "COVER: genesis");
        return;
    }
    if i == 0 {
        assert!(r.is_none(), "U > 0 with a worthless fund: the caller must reset first");
        kani::cover!(true, "COVER: reset required");
        return;
    }
    match (r, x.checked_mul(u)) {
        (Some(m), Some(p)) => {
            let mi = m.checked_mul(i);
            assert!(mi.is_some());
            let mi = mi.unwrap();
            assert!(mi <= p, "mint no-dilution (expanded): m*I <= x*U");
            assert!(p - mi < i, "exact floor");
            kani::cover!(m > 0 && p - mi > 0, "COVER: floored mint");
            kani::cover!(m > 0 && p == mi, "COVER: exact mint");
        }
        (None, None) => kani::cover!(true, "COVER: overflow fails closed"),
        _ => assert!(false, "None exactly on overflow"),
    }
}

/// Insurance-unit BURN no-dilution, FULL width, REAL `ins_units_to_burn` (its ceil primitive
/// replaced by the relation `money_c_p4_ceil` proves). Expanded: `ceil_rel(a*U, I, b)`, i.e.
/// `b == 0 => a*U == 0`, else `(b-1)*I < a*U <= (b-1)*I + I`. (P): `(b-1)*I + I = b*I`, so
/// `a*U <= b*I`: the burned units are worth at least what is paid out, and
/// `(I - a)*U - I*(U - b) = b*I - a*U >= 0` (stayers not diluted).
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::stub(crate::p4_rescue_ins::mul_div_ceil, p4_mul_div_ceil_stub)]
#[kani::solver(z3)]
fn money_s3_ins_units_burn_no_dilution_full() {
    let a: u128 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let r = ins_units_to_burn(a, u, i);
    if u == 0 || i == 0 || a > i {
        assert!(r.is_none(), "nothing withdrawable / beyond the free fund fails closed");
        kani::cover!(u > 0 && i > 0 && a > i, "COVER: beyond the free fund refused");
        return;
    }
    match (r, a.checked_mul(u)) {
        (Some(b), Some(p)) => {
            assert!(b <= u, "never burns more units than exist");
            assert!(spec::ceil_rel(p, i, b), "burn rounds UP (expanded): a*U <= b*I, one unit less would not cover it");
            kani::cover!(b > 1 && b < u && (b - 1).checked_mul(i).is_some_and(|x| p - x < i), "COVER: partial burn, rounded up");
            kani::cover!(b == u, "COVER: whole ledger burned");
        }
        (None, Some(_)) => kani::cover!(true, "COVER: ceil above U refused"),
        (None, None) => kani::cover!(true, "COVER: overflow fails closed"),
        (Some(_), None) => assert!(false, "Some only without overflow"),
    }
}

// ── (W) stake <-> wrapper unit math: the stake mirrors ARE the wrapper functions ──────────────────
// No stub: both REAL functions, every input symbolic at full width. With these, the wrapper (W)
// proofs above carry over verbatim to the stake's `expected_topup_units` / `expected_recover_burn`
// / `deployed_value` (the stake sync requires the wrapper to match exactly, error 45).

/// Stake `expected_topup_units(a, U, I)` == wrapper `ins_units_for_topup(a, U, I)` (after the
/// wrapper's reset when `U > 0, I == 0`: both then mint 1:1).
#[kani::proof]
#[kani::solver(z3)]
fn money_s3_stake_topup_units_equal_wrapper_full() {
    let a: u64 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let s = crate::stake_math::expected_topup_units(a, u, i);
    let w = ins_units_for_topup(a as u128, if i == 0 { 0 } else { u }, i);
    assert!(s == w, "stake expects exactly the wrapper's minted units");
    kani::cover!(u > 0 && i > 0 && s.is_some_and(|m| m > 0), "COVER: priced mint");
    kani::cover!(u > 0 && i == 0, "COVER: reset arm");
    kani::cover!(s.is_none(), "COVER: overflow");
}

/// Stake `expected_recover_burn(r, U, I)` == wrapper `ins_units_to_burn(r, U, I)` wherever the
/// wrapper does not refuse a burn above U (the wrapper's extra `b > U` guard).
#[kani::proof]
#[kani::solver(z3)]
fn money_s3_stake_recover_burn_equal_wrapper_full() {
    let r: u64 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let s = crate::stake_math::expected_recover_burn(r, u, i);
    let w = ins_units_to_burn(r as u128, u, i);
    assert!(w == s.filter(|b| *b <= u), "stake expects exactly the wrapper's burned units");
    kani::cover!(w.is_some_and(|b| b > 0), "COVER: priced burn");
    kani::cover!(s.is_some() && w.is_none(), "COVER: wrapper refuses b > U");
    kani::cover!(s.is_none() && u > 0 && i > 0, "COVER: refused (r > I or overflow)");
}

/// Stake `deployed_value(Us, U, I)` == wrapper `ins_units_value(Us, U, I)` (narrowed to u64).
#[kani::proof]
#[kani::solver(z3)]
fn money_s3_stake_deployed_value_equal_wrapper_full() {
    let us: u128 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let s = crate::stake_math::deployed_value(us, u, i);
    let w = ins_units_value(us, u, i);
    assert!(s == w.and_then(|v| u64::try_from(v).ok()), "stake values its units as the wrapper does");
    kani::cover!(s.is_some_and(|v| v > 0), "COVER: positive value");
    kani::cover!(w.is_some() && s.is_none(), "COVER: beyond u64 fails closed");
}

/// Stake `deployed_value` FULL width with the floor contract: `v * U <= Us * I` (and `< + U`).
/// Range / monotonicity (`v <= I` for `Us <= U`; a lower I never raises it) are order facts:
/// native-checked.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn money_s3_ins_units_value_floor_full() {
    let us: u128 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    let r = ins_units_value(us, u, i);
    if u == 0 {
        assert!(r == Some(0));
        return;
    }
    if us > u {
        assert!(r.is_none());
        kani::cover!(true, "COVER: more units than exist refused");
        return;
    }
    match (r, us.checked_mul(i)) {
        (Some(v), Some(p)) => {
            let vu = v.checked_mul(u);
            assert!(vu.is_some());
            let vu = vu.unwrap();
            assert!(vu <= p && p - vu < u, "value = floor(Us * I / U): never over-valued");
            kani::cover!(v > 0 && p - vu > 0, "COVER: floored value");
        }
        (None, None) => kani::cover!(true, "COVER: overflow fails closed"),
        _ => assert!(false),
    }
}
