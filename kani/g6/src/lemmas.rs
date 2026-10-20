//! G6 no-dilution as a chain of FULL-WIDTH (u128) Kani lemmas (agent WRAP, v22kani 2026-10-20).
//!
//! Why every earlier no-dilution harness was NO-VERDICT (calibrated by kani/probe1020, report WRAP.md
//! section 1): no solver decides a step that mixes a ring identity with an inequality at 128 bits.
//! z3 decides ring IDENTITIES in wrapping form (sum-of-monomials normalisation; 0.13 s for
//! distributivity at u128) but not linear inequalities over 256-bit overflow encodings; kissat decides
//! LINEAR steps over products that appear as shared terms (63 s) and the Rust `/` floor relation in
//! CBMC's divider order `q*d` (240 s) but no ring identity. So every lemma below is one of:
//!   (R) a ring identity in wrapping arithmetic                          -> z3
//!   (L) a linear step whose nonlinear facts arrive as stubbed lemmas    -> kissat
//!   (D) the floor/ceil division relation of a production primitive      -> kissat
//! and every composition stubs the lemmas it uses with `stub_verified` (each proved by its own
//! `proof_for_contract`). A PASS of a composition therefore depends on the lemma PASSES named in its
//! doc; the chain is only as strong as its weakest NV link, and the report lists each link's verdict.
//!
//! Lemmas are "ghost" functions: empty body, the `ensures` IS the statement (`requires` its hypothesis).
#![allow(unused_variables)]

use crate::bond_v20::{bond_atoms_for_redemption, bond_claim_after_redemption, bond_shares_for_deposit};
use crate::p4_rescue_ins::{ins_units_for_topup, rescue_claim_delta, rescue_shares};
use crate::vault_lp_v18::mul_div_floor;

// ═════════════════════════════════════ toolkit (R) / (L) ═════════════════════════════════════

/// (R) modular distributivity.
#[kani::ensures(|_: &()| x.wrapping_add(y).wrapping_mul(z) == x.wrapping_mul(z).wrapping_add(y.wrapping_mul(z)))]
pub fn lem_dist_w(x: u128, y: u128, z: u128) {}

/// (R) modular commutativity.
#[kani::ensures(|_: &()| x.wrapping_mul(y) == y.wrapping_mul(x))]
pub fn lem_comm_w(x: u128, y: u128) {}

/// (L) the value of a non-overflowing `checked_mul` is the wrapping product.
#[kani::ensures(|_: &()| x.checked_mul(y).is_none_or(|v| v == x.wrapping_mul(y)))]
pub fn lem_link(x: u128, y: u128) {}

/// Monotonicity of `*` (no-overflow form): `x <= y` and `y*z` fits => `x*z` fits and `x*z <= y*z`.
#[kani::requires(x <= y)]
#[kani::ensures(|_: &()| y.checked_mul(z).is_none_or(|yz| x.checked_mul(z).is_some_and(|xz| xz <= yz)))]
pub fn lem_mono(x: u128, y: u128, z: u128) {}

#[kani::proof_for_contract(lem_dist_w)]
#[kani::solver(z3)]
fn g6_r_dist_w() {
    lem_dist_w(kani::any(), kani::any(), kani::any());
}

#[kani::proof_for_contract(lem_comm_w)]
#[kani::solver(z3)]
fn g6_r_comm_w() {
    lem_comm_w(kani::any(), kani::any());
}

#[kani::proof_for_contract(lem_link)]
fn g6_l_link() {
    let (x, y): (u128, u128) = (kani::any(), kani::any());
    lem_link(x, y);
    kani::cover!(x.checked_mul(y).is_some_and(|v| v > u64::MAX as u128), "COVER: product beyond u64");
    kani::cover!(x.checked_mul(y).is_none(), "COVER: overflow");
}

#[kani::proof_for_contract(lem_mono)]
fn g6_l_mono() {
    let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    lem_mono(x, y, z);
    kani::cover!(x < y && z > 1 && y.checked_mul(z).is_some_and(|v| v > u64::MAX as u128), "COVER: strict, beyond u64");
}

/// (L) integer distributivity, forward: `x+y` fits and `(x+y)*z` fits => `x*z`, `y*z` fit and
/// `(x+y)*z == x*z + y*z` (the sum does not wrap). From: lem_dist_w (R), lem_link (L), lem_mono (L).
#[kani::requires(x.checked_add(y).is_some())]
#[kani::ensures(|_: &()| x.wrapping_add(y).checked_mul(z).is_none_or(|l| x.checked_mul(z).is_some_and(|xz| y.checked_mul(z).is_some_and(|yz| xz.checked_add(yz) == Some(l)))))]
pub fn lem_dist_c(x: u128, y: u128, z: u128) {}

#[kani::proof_for_contract(lem_dist_c)]
#[kani::stub_verified(lem_dist_w)]
#[kani::stub_verified(lem_link)]
#[kani::stub_verified(lem_mono)]
#[kani::solver(kissat)]
fn g6_l_dist_c() {
    let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(x.checked_add(y).is_some());
    let s = x.wrapping_add(y);
    lem_dist_w(x, y, z);
    lem_link(s, z);
    lem_link(x, z);
    lem_link(y, z);
    lem_mono(x, s, z);
    lem_mono(y, s, z);
    lem_dist_c(x, y, z);
    kani::cover!(s.checked_mul(z).is_some_and(|l| l > u64::MAX as u128) && x > 0 && y > 0, "COVER: both summands, beyond u64");
}

/// (L) checked commutativity. From: lem_comm_w (R), lem_link (L) for both orders, plus the
/// overflow flag's symmetry (PR6 shape; z3 decided it directly in 86 s, so this lemma is proved
/// DIRECTLY by z3, no stub).
#[kani::ensures(|_: &()| x.checked_mul(y) == y.checked_mul(x))]
pub fn lem_comm_c(x: u128, y: u128) {}

#[kani::proof_for_contract(lem_comm_c)]
#[kani::solver(z3)]
fn g6_r_comm_c() {
    lem_comm_c(kani::any(), kani::any());
}

/// (L) cancellation: `x*z <= y*z`, `z > 0` (both fit) => `x <= y`. From: lem_mono, lem_dist_c.
/// (If `x > y` then `x >= y+1`, so `x*z >= (y+1)*z = y*z + z > y*z`.)
#[kani::requires(z > 0)]
#[kani::ensures(|_: &()| x.checked_mul(z).is_none_or(|xz| y.checked_mul(z).is_none_or(|yz| xz > yz || x <= y)))]
pub fn lem_cancel(x: u128, y: u128, z: u128) {}

#[kani::proof_for_contract(lem_cancel)]
#[kani::stub_verified(lem_mono)]
#[kani::stub_verified(lem_dist_c)]
#[kani::solver(kissat)]
fn g6_l_cancel() {
    let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(z > 0);
    if y < u128::MAX && x > y {
        lem_mono(y + 1, x, z);
        lem_dist_c(y, 1, z);
    }
    lem_cancel(x, y, z);
    kani::cover!(x > y && y.checked_mul(z).is_some() && x.checked_mul(z).is_some(), "COVER: x > y, both fit");
}

// ═════════════════════════════ paper lemmas (L), each from the toolkit ═════════════════════════

/// FM, floor mint (W-C-5 bond deposit, W-D-1 L-RES rescue, insurance-unit mint):
/// `m*V <= a*B`  =>  `(B+m)*V <= (V+a)*B` whenever `(V+a)*B` fits (and then `(B+m)*V` fits too
/// when it is asked for: here both are stated under "both fit", the form of the production
/// predicates `rescue_value_no_dilution` / `ins_mint_no_dilution`).
/// Paper: (V+a)B = VB + aB, (B+m)V = BV + mV, VB = BV, mV <= aB.
#[kani::requires(m.checked_mul(v).is_some_and(|mv| a.checked_mul(b).is_some_and(|ab| mv <= ab)))]
#[kani::requires(v.checked_add(a).is_some() && b.checked_add(m).is_some())]
#[kani::ensures(|_: &()| v.wrapping_add(a).checked_mul(b).is_none_or(|l| b.wrapping_add(m).checked_mul(v).is_none_or(|r| r <= l)))]
pub fn lem_fm(v: u128, a: u128, b: u128, m: u128) {}

#[kani::proof_for_contract(lem_fm)]
#[kani::stub_verified(lem_dist_c)]
#[kani::stub_verified(lem_comm_c)]
#[kani::solver(kissat)]
fn g6_p_fm() {
    let (v, a, b, m): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(m.checked_mul(v).is_some_and(|mv| a.checked_mul(b).is_some_and(|ab| mv <= ab)));
    kani::assume(v.checked_add(a).is_some() && b.checked_add(m).is_some());
    lem_dist_c(v, a, b);
    lem_dist_c(b, m, v);
    lem_comm_c(b, v);
    lem_fm(v, a, b, m);
    kani::cover!(m > 0 && v.checked_mul(b).is_some_and(|x| x > u64::MAX as u128) && v.wrapping_add(a).checked_mul(b).is_some(), "COVER: non-trivial, beyond u64");
}

/// FR, floor redeem (W-C-6 payout and claim slice): `sh <= B`, `p <= val`, `p*B <= sh*val`, `val*B`
/// fits  =>  `(val-p)*B` and `val*(B-sh)` fit and `val*(B-sh) <= (val-p)*B` (what stays per share is
/// not lowered). Paper: valB = (val-p)B + pB = val(B-sh) + val·sh (via BV/VB), pB <= sh·val.
#[kani::requires(sh <= b && p <= val)]
#[kani::requires(p.checked_mul(b).is_some_and(|pb| sh.checked_mul(val).is_some_and(|sv| pb <= sv)))]
#[kani::requires(val.checked_mul(b).is_some())]
#[kani::ensures(|_: &()| (val - p).checked_mul(b).is_some_and(|l| val.checked_mul(b - sh).is_some_and(|r| r <= l)))]
pub fn lem_fr(val: u128, p: u128, sh: u128, b: u128) {}

#[kani::proof_for_contract(lem_fr)]
#[kani::stub_verified(lem_dist_c)]
#[kani::stub_verified(lem_comm_c)]
#[kani::solver(kissat)]
fn g6_p_fr() {
    let (val, p, sh, b): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(sh <= b && p <= val);
    kani::assume(p.checked_mul(b).is_some_and(|pb| sh.checked_mul(val).is_some_and(|sv| pb <= sv)));
    kani::assume(val.checked_mul(b).is_some());
    lem_dist_c(val - p, p, b); // val*B = (val-p)*B + p*B
    lem_comm_c(val, b);
    lem_dist_c(b - sh, sh, val); // B*val = (B-sh)*val + sh*val
    lem_comm_c(b - sh, val);
    lem_fr(val, p, sh, b);
    kani::cover!(p > 0 && sh > 0 && sh < b && val.checked_mul(b).is_some_and(|x| x > u64::MAX as u128), "COVER: partial, beyond u64");
}

/// PAR, rescue claim (I-RS2): `dC*S <= m*C`  =>  `(C+dC)*S <= C*(S+m)` whenever both fit
/// (`rescue_par_per_share_not_raised`). Paper: (C+dC)S = CS + dC·S, (S+m)C = SC + mC, CS = SC.
#[kani::requires(dc.checked_mul(s).is_some_and(|ds| m.checked_mul(c).is_some_and(|mc| ds <= mc)))]
#[kani::requires(c.checked_add(dc).is_some() && s.checked_add(m).is_some())]
#[kani::ensures(|_: &()| c.wrapping_add(dc).checked_mul(s).is_none_or(|l| s.wrapping_add(m).checked_mul(c).is_none_or(|r| l <= r)))]
pub fn lem_par(c: u128, dc: u128, s: u128, m: u128) {}

#[kani::proof_for_contract(lem_par)]
#[kani::stub_verified(lem_dist_c)]
#[kani::stub_verified(lem_comm_c)]
#[kani::solver(kissat)]
fn g6_p_par() {
    let (c, dc, s, m): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(dc.checked_mul(s).is_some_and(|ds| m.checked_mul(c).is_some_and(|mc| ds <= mc)));
    kani::assume(c.checked_add(dc).is_some() && s.checked_add(m).is_some());
    lem_dist_c(c, dc, s);
    lem_dist_c(s, m, c);
    lem_comm_c(s, c);
    lem_par(c, dc, s, m);
    kani::cover!(dc > 0 && c.checked_mul(s).is_some_and(|x| x > u64::MAX as u128) && c.wrapping_add(dc).checked_mul(s).is_some(), "COVER: non-trivial, beyond u64");
}

/// CB, ceil burn (insurance-unit burn): `a <= I`, `b <= U`, `a*U <= b*I`, `I*U` fits  =>
/// `(I-a)*U` and `(U-b)*I` fit and `(U-b)*I <= (I-a)*U` (`ins_burn_no_dilution`).
/// Paper: IU = (I-a)U + aU = (U-b)I + bI (via UI/IU), aU <= bI.
#[kani::requires(a <= i && b <= u)]
#[kani::requires(a.checked_mul(u).is_some_and(|au| b.checked_mul(i).is_some_and(|bi| au <= bi)))]
#[kani::requires(i.checked_mul(u).is_some())]
#[kani::ensures(|_: &()| (i - a).checked_mul(u).is_some_and(|l| (u - b).checked_mul(i).is_some_and(|r| r <= l)))]
pub fn lem_cb(i: u128, a: u128, u: u128, b: u128) {}

#[kani::proof_for_contract(lem_cb)]
#[kani::stub_verified(lem_dist_c)]
#[kani::stub_verified(lem_comm_c)]
#[kani::solver(kissat)]
fn g6_p_cb() {
    let (i, a, u, b): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(a <= i && b <= u);
    kani::assume(a.checked_mul(u).is_some_and(|au| b.checked_mul(i).is_some_and(|bi| au <= bi)));
    kani::assume(i.checked_mul(u).is_some());
    lem_dist_c(i - a, a, u); // I*U = (I-a)*U + a*U
    lem_comm_c(i, u);
    lem_dist_c(u - b, b, i); // U*I = (U-b)*I + b*I
    lem_cb(i, a, u, b);
    kani::cover!(a > 0 && b > 0 && b < u && i.checked_mul(u).is_some_and(|x| x > u64::MAX as u128), "COVER: partial burn, beyond u64");
}

/// CEIL step: `ceil_rel(p, d, q)` (the relation the burn primitive returns) with `q*d` fitting
/// gives `p <= q*d`. From lem_dist_c((q-1), 1, d).
#[kani::requires(d > 0 && q > 0 && (q - 1).checked_mul(d).is_some_and(|x| x < p && p - x <= d))]
#[kani::ensures(|_: &()| q.checked_mul(d).is_none_or(|qd| p <= qd))]
pub fn lem_ceil_up(p: u128, d: u128, q: u128) {}

#[kani::proof_for_contract(lem_ceil_up)]
#[kani::stub_verified(lem_dist_c)]
#[kani::solver(kissat)]
fn g6_p_ceil_up() {
    let (p, d, q): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(d > 0 && q > 0);
    kani::assume((q - 1).checked_mul(d).is_some_and(|x| x < p && p - x <= d));
    lem_dist_c(q - 1, 1, d);
    lem_ceil_up(p, d, q);
    kani::cover!(q > 1 && d > 1 && q.checked_mul(d).is_some_and(|qd| qd > p), "COVER: rounded up");
}

// ═════════════════════════════ (D) production primitives at FULL width ═════════════════════════

/// L0: the production `vault_lp_v18::mul_div_floor` satisfies its OWN contract (exact floor in
/// remainder form + the range fact) for EVERY u128 input. kissat (PR3: the `q*d` floor relation in
/// CBMC's divider order is decided at full width in 240 s).
#[kani::proof_for_contract(mul_div_floor)]
#[kani::solver(kissat)]
fn g6_d_mul_div_floor_contract_full() {
    let (a, b, d): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = mul_div_floor(a, b, d);
    kani::cover!(r.is_some_and(|q| q > u64::MAX as u128), "COVER: quotient beyond u64");
    kani::cover!(r.is_some() && d > u64::MAX as u128, "COVER: divisor beyond u64");
    kani::cover!(a.checked_mul(b).is_none() && d > 0, "COVER: product overflow -> None");
}

/// L0c: the production `p4_rescue_ins::mul_div_ceil` (no contract attribute) returns exactly the
/// ceil relation `growth_v19::spec::mul_div_ceil` for EVERY u128 input. kissat.
#[kani::proof]
#[kani::solver(kissat)]
fn g6_d_mul_div_ceil_full() {
    let (a, b, d): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = crate::p4_rescue_ins::mul_div_ceil(a, b, d);
    assert!(crate::growth_v19::spec::mul_div_ceil(a, b, d, r), "exact ceil relation");
    kani::cover!(r.is_some_and(|q| q > u64::MAX as u128), "COVER: quotient beyond u64");
    kani::cover!(r.is_some_and(|q| q > 0) && a.checked_mul(b).is_some_and(|p| p % d != 0), "COVER: rounded up");
}

/// Stub for `p4_rescue_ins::mul_div_ceil` used by the wiring harnesses: ANY result satisfying
/// exactly the relation `g6_d_mul_div_ceil_full` proves (sound iff that harness PASSES).
pub fn p4_mul_div_ceil_stub(a: u128, b: u128, d: u128) -> Option<u128> {
    let r: Option<u128> = kani::any();
    kani::assume(crate::growth_v19::spec::mul_div_ceil(a, b, d, r));
    r
}

// ═════════════════════════ (W) production wiring, FULL width, each one composition ══════════════

/// W-C-5 bond DEPOSIT no-dilution on the REAL `bond_shares_for_deposit` (u128 every input).
/// Chain: L0 (floor contract, stub_verified) -> FM (stub_verified). Asserts the fail-closed branches,
/// that the new shares are worth at most what was paid (`m*V <= a*B`, contract form), and the FACTORED
/// claim `(B+m)*V <= (V+a)*B` whenever both sides fit. Mutant MG1: the mint rounds up (+1 share).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_fm)]
#[kani::solver(kissat)]
fn g6_w_wc5_bond_deposit_no_dilution_full() {
    let (a, b, v): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = bond_shares_for_deposit(a, b, v);
    if b == 0 {
        assert!(r == Some(a), "genesis 1:1");
        kani::cover!(a > 0, "COVER: genesis");
        return;
    }
    if v == 0 {
        assert!(r.is_none(), "zero value with shares outstanding fails closed");
        return;
    }
    let Some(m) = r else {
        assert!(a.checked_mul(b).is_none(), "None only on product overflow");
        kani::cover!(true, "COVER: overflow fails closed");
        return;
    };
    assert!(m.checked_mul(v).is_some_and(|mv| a.checked_mul(b).is_some_and(|ab| mv <= ab)), "new shares worth at most what was paid");
    if v.checked_add(a).is_some() && b.checked_add(m).is_some() {
        lem_fm(v, a, b, m);
        if let (Some(l), Some(rr)) = (v.wrapping_add(a).checked_mul(b), b.wrapping_add(m).checked_mul(v)) {
            assert!(rr <= l, "incumbents not diluted: (B+m)*V <= (V+a)*B");
            kani::cover!(m > 0 && rr < l, "COVER: floored mint, strict");
            kani::cover!(m > 0 && a > u64::MAX as u128 && v > u64::MAX as u128, "COVER: beyond u64");
        }
    }
}

/// W-C-6 bond REDEMPTION no-dilution on the REAL `bond_atoms_for_redemption` and
/// `bond_claim_after_redemption`. Chain: L0 -> lem_mono, lem_comm_c, lem_cancel (order fact
/// `pay <= value`) -> FR. Under `value*B` (resp. `C_b*B`) fitting: the payout never exceeds the
/// tranche value and the remaining value per share is not lowered; when the claim update is Some, the
/// remaining claim per share is not lowered (that it is Some is an order fact left to the native tests).
/// Mutants MG2 (payout +1 atom), MG2b (claim slice +1).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_mono)]
#[kani::stub_verified(lem_comm_c)]
#[kani::stub_verified(lem_cancel)]
#[kani::stub_verified(lem_fr)]
#[kani::solver(kissat)]
fn g6_w_wc6_bond_redemption_no_dilution_full() {
    let (sh, b, val, cb): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    let pay = bond_atoms_for_redemption(sh, b, val);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if b == 0 || sh > b {
        assert!(pay.is_none() && cb2.is_none(), "B == 0 or shares > B fail closed");
        kani::cover!(sh > b, "COVER: over-redemption refused");
        return;
    }
    match pay {
        None => assert!(sh.checked_mul(val).is_none(), "payout None only on overflow"),
        Some(p) => {
            if val.checked_mul(b).is_some() {
                lem_mono(sh, b, val);
                lem_comm_c(b, val);
                lem_cancel(p, val, b);
                assert!(p <= val, "payout never exceeds the tranche value");
                lem_fr(val, p, sh, b);
                assert!((val - p).checked_mul(b).is_some_and(|l| val.checked_mul(b - sh).is_some_and(|r| r <= l)), "remaining value per share not lowered");
                kani::cover!(p > 0 && sh < b && val > u64::MAX as u128, "COVER: partial redemption beyond u64");
            }
        }
    }
    // Claim half. `bond_claim_after_redemption` = C_b - floor(sh*C_b/B) (checked_sub): the slice is
    // named through its result, so the harness reasons about the SAME primitive call.
    let Some(c2) = cb2 else { return };
    assert!(c2 <= cb);
    let slice = cb - c2;
    if cb.checked_mul(b).is_some() {
        lem_mono(sh, b, cb);
        lem_comm_c(b, cb);
        lem_cancel(slice, cb, b);
        lem_fr(cb, slice, sh, b);
        assert!(c2.checked_mul(b).is_some_and(|l| cb.checked_mul(b - sh).is_some_and(|r| r <= l)), "remaining claim per share not lowered");
        kani::cover!(slice > 0 && sh < b && cb > u64::MAX as u128, "COVER: claim slice beyond u64");
    }
}

/// W-D-1 L-RES and I-RS2, restricted to ADMITTED rescues (the REAL `rescue_admitted` is assumed Ok;
/// the processor prices on `x_eff <= x`). Chain: L0 -> FM / PAR. Asserts the production runtime
/// predicates `rescue_value_no_dilution` and `rescue_par_per_share_not_raised` hold whenever their own
/// products fit, i.e. the processor's fail-closed gates refuse an admitted rescue ONLY on overflow.
/// Mutants MG3 (`rescue_shares` +1 share), MG7 (`rescue_claim_delta` +1).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_fm)]
#[kani::stub_verified(lem_par)]
#[kani::solver(kissat)]
fn g6_w_wd1_rescue_admitted_no_dilution_full() {
    let (x, v, par, s, x_eff): (u128, u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(crate::p4_rescue_ins::rescue_admitted(x, v, par, s).is_ok());
    kani::assume(x_eff <= x);
    kani::cover!(x == crate::p4_rescue_ins::RESCUE_MIN_ATOMS, "COVER: smallest admitted rescue");
    let Some(m) = rescue_shares(x_eff, s, v) else {
        assert!(x_eff.checked_mul(s).is_none(), "share price None only on overflow");
        return;
    };
    if v.checked_add(x_eff).is_some() && s.checked_add(m).is_some() {
        lem_fm(v, x_eff, s, m);
        let fits = v.wrapping_add(x_eff).checked_mul(s).is_some() && s.wrapping_add(m).checked_mul(v).is_some();
        assert!(crate::p4_rescue_ins::rescue_value_no_dilution(v, x_eff, s, m) == fits, "L-RES gate refuses only on overflow");
        kani::cover!(fits && m > 0, "COVER: admitted rescue passes the L-RES gate");
    }
    if m > 0 {
        let Some(dc) = rescue_claim_delta(m, par, s) else { return };
        if par.checked_add(dc).is_some() && s.checked_add(m).is_some() {
            lem_par(par, dc, s, m);
            let fits = par.wrapping_add(dc).checked_mul(s).is_some() && s.wrapping_add(m).checked_mul(par).is_some();
            assert!(crate::p4_rescue_ins::rescue_par_per_share_not_raised(par, s, m, dc) == fits, "I-RS2 holds whenever it fits");
            kani::cover!(fits && dc > 0, "COVER: claim delta, par per share not raised");
        }
    }
}

/// W-D-4 insurance-unit MINT no-dilution on the REAL `ins_units_for_topup`: the production predicate
/// `ins_mint_no_dilution(I, U, x, m)` holds whenever its products fit. Chain: L0 -> FM. Mutant MG8
/// (mint rounds up).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_fm)]
#[kani::solver(kissat)]
fn g6_w_wd4_units_mint_no_dilution_full() {
    let (x, u, i): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(u > 0 && i > 0);
    let Some(m) = ins_units_for_topup(x, u, i) else {
        assert!(x.checked_mul(u).is_none());
        return;
    };
    if i.checked_add(x).is_some() && u.checked_add(m).is_some() {
        lem_fm(i, x, u, m);
        let fits = i.wrapping_add(x).checked_mul(u).is_some() && u.wrapping_add(m).checked_mul(i).is_some();
        assert!(crate::p4_rescue_ins::ins_mint_no_dilution(i, u, x, m) == fits, "mint no-dilution whenever it fits");
        kani::cover!(fits && m > 0 && x > u64::MAX as u128, "COVER: mint beyond u64");
    }
}

/// W-D-4 insurance-unit BURN no-dilution on the REAL `ins_units_to_burn` (its ceil primitive replaced
/// by the relation L0c proves). Chain: L0c -> CEIL-UP -> CB. Asserts: `b <= U`, `a*U <= b*I` (the
/// withdrawer pays at least the incumbents' price) and `ins_burn_no_dilution(I, U, a, b)` whenever
/// `I*U` and `b*I` fit. Mutant MG4 (burn floors).
#[kani::proof]
#[kani::stub(crate::p4_rescue_ins::mul_div_ceil, p4_mul_div_ceil_stub)]
#[kani::stub_verified(lem_ceil_up)]
#[kani::stub_verified(lem_cb)]
#[kani::solver(kissat)]
fn g6_w_wd4_units_burn_no_dilution_full() {
    let (a, u, i): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let Some(b) = crate::p4_rescue_ins::ins_units_to_burn(a, u, i) else { return };
    assert!(b <= u && a <= i && u > 0 && i > 0);
    let p = a.checked_mul(u);
    assert!(p.is_some(), "Some only without overflow");
    if b > 0 {
        lem_ceil_up(p.unwrap(), i, b);
    }
    if i.checked_mul(u).is_some() && b.checked_mul(i).is_some() {
        assert!(a.checked_mul(u).is_some_and(|au| b.checked_mul(i).is_some_and(|bi| au <= bi)), "burn priced no better than the incumbents");
        lem_cb(i, a, u, b);
        assert!(crate::p4_rescue_ins::ins_burn_no_dilution(i, u, a, b), "stayers not diluted");
        kani::cover!(b > 0 && b < u && a > u64::MAX as u128, "COVER: partial burn beyond u64");
    }
}

// ═══════════════════ (W) Earn senior shares (kani/p3 rows kani_p3_deposit/redemption_no_dilution) ══════════

/// P3 deposit no-dilution, FULL width, REAL `vault_lp_v18::senior_shares_for_deposit` (same chain as
/// W5: D1 -> FM). Replaces the u8-bounded `kani_p3_deposit_no_dilution` (NV). Mutant MG9 (+1 share).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_fm)]
#[kani::solver(kissat)]
fn g6_w_p3_senior_deposit_no_dilution_full() {
    let (a, s, v): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = crate::vault_lp_v18::senior_shares_for_deposit(a, s, v);
    if s == 0 {
        assert!(r == Some(a));
        return;
    }
    if v == 0 {
        assert!(r.is_none());
        return;
    }
    let Some(m) = r else {
        assert!(a.checked_mul(s).is_none());
        return;
    };
    assert!(m.checked_mul(v).is_some_and(|mv| a.checked_mul(s).is_some_and(|ab| mv <= ab)), "never more than the pro-rata share");
    if v.checked_add(a).is_some() && s.checked_add(m).is_some() {
        lem_fm(v, a, s, m);
        if let (Some(l), Some(rr)) = (v.wrapping_add(a).checked_mul(s), s.wrapping_add(m).checked_mul(v)) {
            assert!(rr <= l, "price per share after >= before");
            kani::cover!(m > 0 && rr < l && a > u64::MAX as u128, "COVER: floored mint beyond u64");
        }
    }
}

/// P3 redemption no-dilution, FULL width, REAL `senior_atoms_for_redemption` and
/// `senior_claim_after_redemption` (same chain as W6). Replaces the u8-bounded
/// `kani_p3_redemption_no_dilution` (NV) for the payout / claim halves. Mutant MG10 (payout +1).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_mono)]
#[kani::stub_verified(lem_comm_c)]
#[kani::stub_verified(lem_cancel)]
#[kani::stub_verified(lem_fr)]
#[kani::solver(kissat)]
fn g6_w_p3_senior_redemption_no_dilution_full() {
    let (sh, s, val, c): (u128, u128, u128, u128) = (kani::any(), kani::any(), kani::any(), kani::any());
    let pay = crate::vault_lp_v18::senior_atoms_for_redemption(sh, s, val);
    let c2 = crate::vault_lp_v18::senior_claim_after_redemption(c, sh, s);
    if s == 0 || sh > s {
        assert!(pay.is_none() && c2.is_none());
        return;
    }
    if let Some(p) = pay {
        if val.checked_mul(s).is_some() {
            lem_mono(sh, s, val);
            lem_comm_c(s, val);
            lem_cancel(p, val, s);
            assert!(p <= val, "payout never exceeds the senior value");
            lem_fr(val, p, sh, s);
            assert!((val - p).checked_mul(s).is_some_and(|l| val.checked_mul(s - sh).is_some_and(|r| r <= l)));
            kani::cover!(p > 0 && sh < s && val > u64::MAX as u128, "COVER: partial redemption beyond u64");
        }
    } else {
        assert!(sh.checked_mul(val).is_none());
    }
    let Some(c2) = c2 else { return };
    assert!(c2 <= c);
    let slice = c - c2;
    if c.checked_mul(s).is_some() {
        lem_mono(sh, s, c);
        lem_comm_c(s, c);
        lem_cancel(slice, c, s);
        lem_fr(c, slice, sh, s);
        assert!(c2.checked_mul(s).is_some_and(|l| c.checked_mul(s - sh).is_some_and(|r| r <= l)), "remaining per-share claim never falls");
        kani::cover!(slice > 0 && sh < s && c > u64::MAX as u128, "COVER: claim slice beyond u64");
    }
}

/// W-D-2 (I-RS2) for ANY rescue size (not only admitted): the REAL `rescue_claim_delta(m, C, S)`
/// keeps par per share from rising (`rescue_par_per_share_not_raised` true whenever it fits) and the
/// claim added is short of exact pro rata by less than one atom per share: `m*C < dC*S + S`
/// (contract form). Chain: D1 -> PAR. Replaces the u32 `kani_v22_wd2_rescue_par_per_share` (NV).
/// Mutant MG7 (`rescue_claim_delta` +1).
#[kani::proof]
#[kani::stub_verified(mul_div_floor)]
#[kani::stub_verified(lem_par)]
#[kani::solver(kissat)]
fn g6_w_wd2_rescue_par_per_share_full() {
    let (c, s, m): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(s > 0);
    let Some(dc) = rescue_claim_delta(m, c, s) else {
        assert!(m.checked_mul(c).is_none());
        return;
    };
    assert!(dc.checked_mul(s).is_some_and(|ds| m.checked_mul(c).is_some_and(|mc| ds <= mc && mc - ds < s)), "floor: par falls by < 1 atom per share");
    if c.checked_add(dc).is_some() && s.checked_add(m).is_some() {
        lem_par(c, dc, s, m);
        let fits = c.wrapping_add(dc).checked_mul(s).is_some() && s.wrapping_add(m).checked_mul(c).is_some();
        assert!(crate::p4_rescue_ins::rescue_par_per_share_not_raised(c, s, m, dc) == fits);
        kani::cover!(fits && dc > 0 && c > u64::MAX as u128, "COVER: claim grows, beyond u64");
    }
}

// ═══════════════ lever 1 (coordinator 14:3x): the chain restated in checked_mul form ONLY ═══════════════
// No wrapping term anywhere: every product the lemma, its proof and its users mention is `checked_mul`,
// so lemma terms and production terms are the same circuit kind. Each lemma is proved DIRECTLY (no stubs).

/// Integer distributivity, checked form only, proved directly.
#[kani::requires(x.checked_add(y).is_some())]
#[kani::ensures(|_: &()| (x + y).checked_mul(z).is_none_or(|l| x.checked_mul(z).is_some_and(|xz| y.checked_mul(z).is_some_and(|yz| xz.checked_add(yz) == Some(l)))))]
pub fn lem_dist_cc(x: u128, y: u128, z: u128) {}

#[kani::proof_for_contract(lem_dist_cc)]
fn g6c_dist_direct() {
    let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    lem_dist_cc(x, y, z);
    kani::cover!(x > 0 && y > 0 && x.wrapping_add(y).checked_mul(z).is_some_and(|l| l > u64::MAX as u128), "COVER: both summands, beyond u64");
}

/// Monotonicity, checked form, proved directly (same statement as `lem_mono`; separate entry so the
/// z3 run is its own row).
#[kani::proof_for_contract(lem_mono)]
fn g6c_mono_direct() {
    let (x, y, z): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    lem_mono(x, y, z);
    kani::cover!(x < y && z > 1 && y.checked_mul(z).is_some_and(|v| v > u64::MAX as u128), "COVER: strict, beyond u64");
}

/// D1 split (a): the production `mul_div_floor` meets the SPEC half of its contract (exact floor in
/// remainder form, checked products), every u128 input. Plain proof, asserts the production spec fn.
#[kani::proof]
fn g6c_d1a_floor_spec_full() {
    let (a, b, d): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = mul_div_floor(a, b, d);
    assert!(crate::vault_lp_v18::mul_div_floor_spec(a, b, d, r));
    kani::cover!(r.is_some_and(|q| q > u64::MAX as u128) && d > 1, "COVER: quotient beyond u64");
    kani::cover!(a.checked_mul(b).is_none() && d > 0, "COVER: overflow -> None");
}

/// D1 split (b): the RANGE half of the contract (`b <= d => q <= a`), every u128 input.
#[kani::proof]
fn g6c_d1b_floor_facts_full() {
    let (a, b, d): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    let r = mul_div_floor(a, b, d);
    assert!(crate::vault_lp_v18::mul_div_floor_facts(a, b, d, r));
    kani::cover!(b <= d && r.is_some_and(|q| q > 0 && q < a) && a > u64::MAX as u128, "COVER: b <= d, strict, beyond u64");
}
