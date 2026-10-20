//! weak-1020 D6: full-u128 lifts of the bounded (u8) bond floor splits, through the kernel CONTRACT of
//! `vault_lp_v18::mul_div_floor` (`kani::ensures`: exact floor in remainder form, None iff d == 0 or a*b
//! overflows). The contract is proved here by `proof_for_contract` (u8 operands, as `kani_growth_c_mul_div_floor`,
//! plus a pre-planned u64/z3 attempt) and then `stub_verified` in the full-width harnesses. Width-generic step
//! (the same one kani/growth documents): the body is `if d == 0 { None } else { a.checked_mul(b).map(|p| p / d) }`;
//! its contract is the semantics of core u128 `checked_mul` and `/`, which do not depend on the operand width.
//! Every covers must be SATISFIED.
use crate::bond_v20::*;
use crate::vault_lp_v18::mul_div_floor;

/// The kernel contract at u8 operands (identical domain to `kani_growth_c_mul_div_floor`).
#[kani::proof_for_contract(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(cadical)]
fn kani_weak_c_mul_div_floor() {
    let a = kani::any::<u8>() as u128;
    let b = kani::any::<u8>() as u128;
    let d = kani::any::<u8>() as u128;
    let r = mul_div_floor(a, b, d);
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > 0 && (a * b) % d != 0), "inexact floor");
    kani::cover!(r.is_some_and(|q| b < d && q < a), "fact b <= d: q <= a (strict)");
}

/// Pre-planned: the same contract at u64 operands (products up to 2^128 - 2^65 + 1, no overflow), z3.
/// If it passes, the paper width step shrinks from u8 -> u128 to u64 -> u128 (only the overflow branch remains).
#[kani::proof_for_contract(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn kani_weak_c_mul_div_floor_u64() {
    let a = kani::any::<u64>() as u128;
    let b = kani::any::<u64>() as u128;
    let d = kani::any::<u64>() as u128;
    let r = mul_div_floor(a, b, d);
    kani::cover!(d == 0, "d == 0 -> None");
    kani::cover!(r.is_some_and(|q| q > u32::MAX as u128), "large quotient");
}

/// W-C-5 split (a) at FULL u128 width (was u8): the REAL `bond_shares_for_deposit`, branch structure exact,
/// floor facts with checked products, and the overflow branch (unreachable at u8) fails closed.
/// Mutant MP6 (deposit rounds up) must turn it RED.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(cadical)]
fn kani_weak_wc5_deposit_floor_full_u128() {
    wc5_body(kani::any(), kani::any(), kani::any());
}

/// weak-1020 rev 2 (after `kani_weak_wc6_redemption_floor_full_u128` had NO VERDICT at 2400 s, cadical): the same
/// body at u64 operands (every product fits u128, so the overflow branch is unreachable here), z3.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn kani_weak_wc5_deposit_floor_u64() {
    wc5_body(kani::any::<u64>() as u128, kani::any::<u64>() as u128, kani::any::<u64>() as u128);
}

fn wc5_body(amount: u128, b: u128, value: u128) {
    kani::assume(amount > 0); // the original's assume (a deposit moves at least one atom)
    let m = bond_shares_for_deposit(amount, b, value);
    if b == 0 {
        assert_eq!(m, Some(amount), "genesis 1:1");
        kani::cover!(true, "genesis");
    } else if value == 0 {
        assert!(m.is_none(), "zero value with shares outstanding fails closed");
        kani::cover!(true, "impaired-to-zero refused");
    } else {
        match amount.checked_mul(b) {
            None => {
                assert!(m.is_none(), "an overflowing amount * B fails closed");
            }
            Some(p) => {
                let m = m.unwrap();
                let mv = m.checked_mul(value);
                assert!(mv.is_some_and(|mv| mv <= p), "rounds down: m * value <= amount * B");
                assert!(mv.is_some_and(|mv| p - mv < value), "exact floor: amount * B < m * value + value");
                kani::cover!(p % value == 0 && m > 0, "exact");
                kani::cover!(p > u64::MAX as u128, "product above u64");
                kani::cover!(p % value != 0, "floored");
            }
        }
    }
}

/// W-C-6 split (a) at FULL u128 width (was u8): the REAL `bond_atoms_for_redemption` and
/// `bond_claim_after_redemption`. Payout: exact floor of shares * value / B (or None iff the product overflows).
/// Claim: whenever the new claim is Some, the slice removed is the exact floor of shares * C_b / B and the claim
/// never grows. NOT lifted (stays with the u8 row): that the claim is always Some and that a full redemption
/// clears it; both need `q * B <= sh * C_b, sh <= B => q <= C_b`, a nonlinear step the contract does not state.
/// Mutant MW6 (slice rounded up) must turn it RED.
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(cadical)]
fn kani_weak_wc6_redemption_floor_full_u128() {
    wc6_body(kani::any(), kani::any(), kani::any(), kani::any());
}

/// weak-1020 rev 2: the same body at u64 operands, z3 (see `kani_weak_wc5_deposit_floor_u64`).
#[kani::proof]
#[kani::stub_verified(crate::vault_lp_v18::mul_div_floor)]
#[kani::solver(z3)]
fn kani_weak_wc6_redemption_floor_u64() {
    wc6_body(
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
        kani::any::<u64>() as u128,
    );
}

fn wc6_body(b: u128, sh: u128, cb: u128, value: u128) {
    kani::assume(b > 0 && value <= cb); // the original's assume
    let pay = bond_atoms_for_redemption(sh, b, value);
    let cb2 = bond_claim_after_redemption(cb, sh, b);
    if sh > b {
        assert!(pay.is_none() && cb2.is_none(), "over-redemption refused");
        kani::cover!(true, "over-redemption refused");
        return;
    }
    match sh.checked_mul(value) {
        None => assert!(pay.is_none(), "overflowing payout product fails closed"),
        Some(p) => {
            let q = pay.unwrap();
            let qb = q.checked_mul(b);
            assert!(qb.is_some_and(|qb| qb <= p && p - qb < b), "payout = floor(sh * value / B)");
            kani::cover!(sh < b && value < cb && q > 0, "impaired tranche pays pro rata");
        }
    }
    if let Some(c2) = cb2 {
        assert!(c2 <= cb, "the claim never grows");
        let slice = cb - c2;
        let p = sh.checked_mul(cb);
        assert!(p.is_some(), "a Some claim implies the slice product did not overflow");
        let p = p.unwrap();
        let sb = slice.checked_mul(b);
        assert!(sb.is_some_and(|sb| sb <= p && p - sb < b), "slice = floor(sh * C_b / B)");
        kani::cover!(sh < b && c2 > 0 && slice > 0, "partial redemption");
        kani::cover!(sh == b && cb > 0 && c2 == 0, "full redemption clears C_b");
    }
}
