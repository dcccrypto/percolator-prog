//! v22kani GROW lane (2026-10-20). Replacements for the order-lemma and T7 rows that stayed
//! NO-VERDICT (lc*/el*/l*m/t7c*/t7m). Report: ~/wt-v22kani-1020/reports/GROW.md.
//!
//! Lever: the narrowest exact machine type. The u8-domain twins (`el1/el2`, `l1m..l4m`, `t7m`)
//! did their arithmetic in u32. In u32 every divider's quotient is a fresh 32-bit vector that the
//! solver does not know is small. Here:
//! * the products of u8 operands are computed in u16 (255 * 255 = 65,025 fits);
//! * the dividers are u16 (quotient 16 bits);
//! * T7 is split into an ALGEBRA step (no division at all) and a LINEAR step (divisor the
//!   constant 1e4, so every product with the quotient is a constant multiplication: linear).
//!
//! What the composition gives (paper, one line each, in the report):
//! * L_i on the u8 domain = ELu (production primitive == u16 exact arithmetic) ∧ L_i u (order
//!   fact in u16 arithmetic), by substitution.
//! * T7 on the u8 / u16 notional domain = E1 ∧ E2 (production primitives == exact arithmetic,
//!   PASS at head) ∧ T7alg ∧ T7lin.
use crate::growth_v19::*;

// ── ELu: the REAL primitives equal exact u16 arithmetic on the u8 domain ───────────────────

/// ELu1: `mul_div_ceil_u128(a, b, d) == ceil(a·b/d)` computed in u16, every u8 a, b, d > 0.
/// Real production primitive (one 128-bit divider); spec in u16.
/// Mutant: `p-ceil` (div_ceil -> floor) must turn it red.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_grow_el1u_ceil_exact_u8() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let d: u8 = kani::any();
    kani::assume(d > 0);
    let p = (a as u16) * (b as u16);
    let r = mul_div_ceil_u128(a as u128, b as u128, d as u128);
    assert_eq!(r, Some(p.div_ceil(d as u16) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && p % (d as u16) != 0), "rounds up");
    kani::cover!(r.is_some_and(|q| q > 0 && p % (d as u16) == 0), "exact");
    kani::cover!(r == Some(0), "zero product");
}

/// ELu2: `mul_div_floor(a, b, d) == floor(a·b/d)` computed in u16, every u8 a, b, d > 0.
/// Mutant: `p-floor` (floor -> div_ceil) must turn it red.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_grow_el2u_floor_exact_u8() {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    let d: u8 = kani::any();
    kani::assume(d > 0);
    let p = (a as u16) * (b as u16);
    let r = crate::vault_lp_v18::mul_div_floor(a as u128, b as u128, d as u128);
    assert_eq!(r, Some((p / d as u16) as u128));
    kani::cover!(r.is_some_and(|q| q > 0 && p % (d as u16) != 0), "rounds down");
    kani::cover!(r.is_some_and(|q| q > 0 && p % (d as u16) == 0), "exact");
}

// ── L1u..L4u: the order facts in u16 arithmetic (pure arithmetic lemmas, no production) ────
// These state facts about integer floor/ceil. They call no production function on purpose:
// production is tied in by ELu1/ELu2 (substitution). Each carries a negative control below.

fn c16(a: u8, b: u8, d: u8) -> u16 {
    ((a as u16) * (b as u16)).div_ceil(d as u16)
}
fn f16(a: u8, b: u8, d: u8) -> u16 {
    ((a as u16) * (b as u16)) / (d as u16)
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_l1u_ceil_monotone_in_b() {
    let (a, b1, b2, d): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(b1 <= b2 && d > 0);
    assert!(c16(a, b1, d) <= c16(a, b2, d));
    kani::cover!(c16(a, b1, d) < c16(a, b2, d), "strict");
    kani::cover!(c16(a, b1, d) == c16(a, b2, d) && b1 < b2 && a > 0, "plateau");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_l2u_ceil_monotone_in_a() {
    let (a1, a2, b, d): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(a1 <= a2 && d > 0);
    assert!(c16(a1, b, d) <= c16(a2, b, d));
    kani::cover!(c16(a1, b, d) < c16(a2, b, d), "strict");
    kani::cover!(c16(a1, b, d) == c16(a2, b, d) && a1 < a2 && b > 0, "plateau");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_l3u_ceil_antitone_in_d() {
    let (a, b, d1, d2): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(d1 > 0 && d1 <= d2);
    assert!(c16(a, b, d2) <= c16(a, b, d1));
    kani::cover!(c16(a, b, d2) < c16(a, b, d1), "strict");
    kani::cover!(c16(a, b, d2) == c16(a, b, d1) && d1 < d2 && a > 0 && b > 0, "plateau");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_l4u_floor_monotone_in_a() {
    let (a1, a2, b, d): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(a1 <= a2 && d > 0);
    assert!(f16(a1, b, d) <= f16(a2, b, d));
    kani::cover!(f16(a1, b, d) < f16(a2, b, d), "strict");
    kani::cover!(f16(a1, b, d) == f16(a2, b, d) && a1 < a2 && b > 0, "plateau");
}

// ── T7 split: T7m ⇐ T7alg ∧ T7lin ──────────────────────────────────────────────────────────
// T7m: mmr >= r + f ⇒ ceil(n·mmr/1e4) >= floor(n·r/1e4) + ceil(n·f/1e4).
// T7alg (no division): mmr >= r + f ⇒ n·mmr >= n·r + n·f.
// T7lin (no variable product): C >= A + B ⇒ ceil(C/1e4) >= floor(A/1e4) + ceil(B/1e4), for ALL
//   u128 A, B, C with A + B not overflowing (FULL width; the divisor is the constant 1e4).
// With A = n·r, B = n·f, C = n·mmr: T7alg gives C >= A + B, T7lin gives T7m.

/// T7alg at the original u8 notional (n u8, bps <= 1e4), products in u32.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_t7alg_u8() {
    let n: u8 = kani::any();
    let (r, f, mmr): (u16, u16, u16) = (kani::any(), kani::any(), kani::any());
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let (n, r, f, mmr) = (n as u32, r as u32, f as u32, mmr as u32);
    assert!(n * mmr >= n * r + n * f);
    kani::cover!(n * mmr == n * r + n * f && n > 0 && r > 0 && f > 0, "tight");
    kani::cover!(n * mmr > n * r + n * f, "slack");
}

/// T7alg at a u16 notional (16 x 14-bit products, in u32: 65,535 · 10,000 < 2^32).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_t7alg_u16() {
    let n: u16 = kani::any();
    let (r, f, mmr): (u16, u16, u16) = (kani::any(), kani::any(), kani::any());
    kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr as u32 >= r as u32 + f as u32);
    let (n, r, f, mmr) = (n as u32, r as u32, f as u32, mmr as u32);
    assert!(n * mmr >= n * r + n * f);
    kani::cover!(n * mmr == n * r + n * f && n > 255 && r > 0 && f > 0, "tight, wide notional");
    kani::cover!(n * mmr > n * r + n * f && n > 255, "slack, wide notional");
}

/// T7lin at FULL u128 width: only additions, comparisons and division by the constant 1e4.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_grow_t7lin_full_width() {
    let (a, b, c): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
    kani::assume(a.checked_add(b).is_some_and(|s| c >= s));
    let mm = c.div_ceil(10_000);
    let gap = a / 10_000;
    let fee = b.div_ceil(10_000);
    assert!(mm >= gap + fee);
    kani::cover!(mm == gap + fee && a > 0 && b > 0 && c % 10_000 != 0, "tight, rounded");
    kani::cover!(mm > gap + fee, "slack");
    kani::cover!(c > u64::MAX as u128 && a > u64::MAX as u128 && b > 0, "full width");
}

// ── negative controls (`--features negctl`): each MUST FAIL ───────────────────────────────
#[cfg(feature = "negctl")]
mod neg {
    use super::*;

    /// L1u made strict: the ceil plateau is a counterexample.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn neg_grow_l1u_strict() {
        let (a, b1, b2, d): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(b1 < b2 && d > 0);
        assert!(c16(a, b1, d) < c16(a, b2, d));
    }

    /// L3u reversed (ceil increasing in d) must fail.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn neg_grow_l3u_reversed() {
        let (a, b, d1, d2): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(d1 > 0 && d1 <= d2);
        assert!(c16(a, b, d2) >= c16(a, b, d1));
    }

    /// T7lin with the gap rounded UP (ceil) instead of down must fail.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn neg_grow_t7lin_gap_ceil() {
        let (a, b, c): (u128, u128, u128) = (kani::any(), kani::any(), kani::any());
        kani::assume(a.checked_add(b).is_some_and(|s| c >= s));
        assert!(c.div_ceil(10_000) >= a.div_ceil(10_000) + b.div_ceil(10_000));
    }

    /// T7alg without the fee in the rule (mmr >= r only) must fail.
    #[kani::proof]
    #[kani::solver(kissat)]
    fn neg_grow_t7alg_rule_without_fee() {
        let n: u8 = kani::any();
        let (r, f, mmr): (u16, u16, u16) = (kani::any(), kani::any(), kani::any());
        kani::assume(r <= 10_000 && f <= 10_000 && mmr <= 10_000 && mmr >= r);
        let (n, r, f, mmr) = (n as u32, r as u32, f as u32, mmr as u32);
        assert!(n * mmr >= n * r + n * f);
    }
}
