//! v22kani GROW lane (2026-10-20): replacements for the DEX depth-source rows of
//! `src/depth_src_v22.rs::kani_proofs` that were NO-VERDICT / FAIL at wrapper 4d69ee52
//! (`kani_dex_isqrt_exact_u64`, `kani_dex_depth_floor_exact`, `kani_dex_valuation_floor`,
//! `kani_dex_pin_check_all_or_nothing`). Every harness calls the PRODUCTION function.
//! Report: ~/wt-v22kani-1020/reports/GROW.md. Run (one build, several harnesses):
//!   (in kani/dexwrap) cargo kani --harness <name> [--harness <name> ...]
//! Moved out of tests/ (2026-10-20 06:15Z): `cargo kani --tests` compiles every test target and
//! the base's tests/v16_kani.rs does not compile (E0061, pre-existing, not GROW's). Here the wrapper
//! is a plain path dependency (lib only, feature devnet).
#![cfg(kani)]

use percolator_prog::depth_src_v22::*;

// ── pin check, orientation made concrete ──────────────────────────────────────────────────
// The audit's FAIL (cadical + kissat) is on `sides.vault[b]` / `sides.mint[b]`, i.e. 32-byte
// array compares at an index DERIVED from symbolic `flags`. Native replay of all three
// counterexamples disagreed with Kani. Here `flags` is a constant per harness, so `pin.sides()`
// folds to constant indices. `pin_matches` reads only bits 0 (`is_active`) and 1 (`sides`) of
// `flags`, so the cases {1, 3} (active, both orientations) plus "inactive for any flags" cover
// every behaviour.

fn any_key() -> [u8; 32] {
    kani::any()
}

fn any_pin(flags: u8) -> DepthSourceV22 {
    DepthSourceV22 {
        market: any_key(),
        amm_program: any_key(),
        pool: any_key(),
        base_vault: any_key(),
        quote_vault: any_key(),
        base_mint: any_key(),
        quote_mint: any_key(),
        market_id: kani::any(),
        set_slot: 0,
        asset_index: kani::any(),
        base_decimals: kani::any(),
        quote_decimals: kani::any(),
        flags,
        version: DEPTH_SOURCE_VERSION,
        bump: kani::any(),
        amm_kind: kani::any(),
        _reserved: [0; 8],
    }
}

fn any_view() -> PushView {
    PushView {
        market: any_key(),
        asset_index: kani::any(),
        market_id: kani::any(),
        pool_key: any_key(),
        pool_owner: any_key(),
        sides: PoolSides {
            mint: [any_key(), any_key()],
            vault: [any_key(), any_key()],
            token_program: [kani::any::<bool>().then(any_key), kani::any::<bool>().then(any_key)],
        },
        base_vault_key: any_key(),
        quote_vault_key: any_key(),
        base_vault_program: any_key(),
        quote_vault_program: any_key(),
        base_vault: TokenAcct { mint: any_key(), amount: kani::any() },
        quote_vault: TokenAcct { mint: any_key(), amount: kani::any() },
    }
}

/// The 17 conjuncts of the design (`pin_matches` doc), at constant side indices `B`, `Q`.
fn pin_spec<const B: usize, const Q: usize>(pin: &DepthSourceV22, v: &PushView) -> bool {
    let prog = |side: usize, o: &[u8; 32]| v.sides.token_program[side].map_or(true, |p| p == *o);
    pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0
        && pin.market == v.market
        && pin.asset_index == v.asset_index
        && pin.market_id == v.market_id
        && v.pool_owner == pin.amm_program
        && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
        && v.pool_key == pin.pool
        && v.base_vault_key == pin.base_vault
        && v.quote_vault_key == pin.quote_vault
        && v.sides.vault[B] == pin.base_vault
        && v.sides.vault[Q] == pin.quote_vault
        && v.sides.mint[B] == pin.base_mint
        && v.sides.mint[Q] == pin.quote_mint
        && v.base_vault.mint == pin.base_mint
        && v.quote_vault.mint == pin.quote_mint
        && prog(B, &v.base_vault_program)
        && prog(Q, &v.quote_vault_program)
}

/// `pin_spec` minus the `sides.vault[B] == pin.base_vault` conjunct (a cover helper).
fn pin_spec_except_vault_b<const B: usize, const Q: usize>(pin: &DepthSourceV22, v: &PushView) -> bool {
    let prog = |side: usize, o: &[u8; 32]| v.sides.token_program[side].map_or(true, |p| p == *o);
    pin.flags & DEPTH_SRC_FLAG_ACTIVE != 0
        && pin.market == v.market
        && pin.asset_index == v.asset_index
        && pin.market_id == v.market_id
        && v.pool_owner == pin.amm_program
        && amm_kind_for_program(&v.pool_owner) == Some(pin.amm_kind)
        && v.pool_key == pin.pool
        && v.base_vault_key == pin.base_vault
        && v.quote_vault_key == pin.quote_vault
        && v.sides.vault[Q] == pin.quote_vault
        && v.sides.mint[B] == pin.base_mint
        && v.sides.mint[Q] == pin.quote_mint
        && v.base_vault.mint == pin.base_mint
        && v.quote_vault.mint == pin.quote_mint
        && prog(B, &v.base_vault_program)
        && prog(Q, &v.quote_vault_program)
}

fn pin_case<const B: usize, const Q: usize>(flags: u8) {
    let pin = any_pin(flags);
    let v = any_view();
    let ok = pin_matches(&pin, &v);
    assert_eq!(ok, pin_spec::<B, Q>(&pin, &v), "all-or-nothing");
    if ok {
        // soundness half: the vault accounts ARE the pool's own vaults in the pinned orientation,
        // and every mint agrees per side.
        assert!(v.base_vault_key == v.sides.vault[B] && v.quote_vault_key == v.sides.vault[Q]);
        assert!(v.base_vault.mint == v.sides.mint[B] && v.quote_vault.mint == v.sides.mint[Q]);
        assert!(amm_kind_for_program(&v.pool_owner).is_some(), "allow-listed owner");
    }
    kani::cover!(ok, "a matching view is accepted");
    kani::cover!(
        !ok && v.sides.vault[B] != pin.base_vault && pin_spec_except_vault_b::<B, Q>(&pin, &v),
        "only the pool's own base vault field differs"
    );
    kani::cover!(!ok && v.sides.vault[B] == pin.base_vault && v.sides.vault[Q] == pin.base_vault, "pool vaults swapped / duplicated");
}

/// Active, base = pool side 0 (`flags` = ACTIVE).
/// Mutant: production `v.sides.vault[b] == pin.base_vault` -> `v.sides.vault[q] == ...` (red).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_grow_dex_pin_check_side0() {
    pin_case::<0, 1>(DEPTH_SRC_FLAG_ACTIVE);
}

/// Active, base = pool side 1 (`flags` = ACTIVE | BASE_IS_SIDE1).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_grow_dex_pin_check_side1() {
    pin_case::<1, 0>(DEPTH_SRC_FLAG_ACTIVE | DEPTH_SRC_FLAG_BASE_IS_SIDE1);
}

/// Inactive pin (bit 0 clear, any other bits): never matches.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_grow_dex_pin_check_inactive() {
    let flags: u8 = kani::any();
    kani::assume(flags & DEPTH_SRC_FLAG_ACTIVE == 0);
    let pin = any_pin(flags);
    let v = any_view();
    let ok = pin_matches(&pin, &v);
    assert!(!ok, "an inactive pin never matches");
    kani::cover!(flags & DEPTH_SRC_FLAG_BASE_IS_SIDE1 != 0 && pin.market == v.market, "inactive, side-1 flag set");
}

// ── valuation: exact wiring at FULL u64 width ─────────────────────────────────────────────

/// `reserve_value_e6(BaseAtMark, ..)` for EVERY u64 base and mark and every decimals / lot
/// exponent: `None` iff mark == 0 or dec > 18 or lot > LOT_EXP_MAX. Otherwise
/// `Some(min(floor(base·mark / 10^(dec+lot)), u64::MAX))`, the design formula (module doc), with
/// Rust's `/` as the floor (trusted base, as for the growth primitives). The original was u32 base
/// and mark with a relational floor assert (NO-VERDICT 900 s cadical). Here the spec uses the same
/// product and power terms, so z3 can share them; the claim checked is the WIRING (operands,
/// exponent = dec + lot, the guards, the cap).
/// `QuoteIsCollateral` is the identity on the quote reserve.
/// Mutants: round up (`div_ceil`); ignore `lot_exp` (`pow(base_decimals)`); cap at u32::MAX.
#[kani::proof]
#[kani::solver(z3)]
#[kani::unwind(10)]
fn kani_grow_dex_valuation_wiring_full_width() {
    let base: u64 = kani::any();
    let quote: u64 = kani::any();
    let mark: u64 = kani::any();
    let dec: u8 = kani::any();
    let lot: u8 = kani::any();
    kani::assume(dec <= 40 && lot <= 40);
    let v = reserve_value_e6(ValuePath::BaseAtMark, base, quote, mark, dec, lot);
    let refused = mark == 0 || dec > DEPTH_SRC_MAX_DECIMALS || lot > percolator_prog::constants::LOT_EXP_MAX;
    if refused {
        assert!(v.is_none());
    } else {
        let p = 10u128.pow(dec as u32 + lot as u32);
        let exact = (base as u128) * (mark as u128) / p;
        let want = if exact > u64::MAX as u128 { u64::MAX } else { exact as u64 };
        assert_eq!(v, Some(want));
    }
    assert_eq!(reserve_value_e6(ValuePath::QuoteIsCollateral, base, quote, mark, dec, lot), Some(quote));
    kani::cover!(v == Some(0) && base > 0 && mark > 0, "value floors to 0");
    kani::cover!(v == Some(u64::MAX) && dec + lot > 0, "capped at u64::MAX");
    kani::cover!(v.is_some_and(|x| x > 0 && x < u64::MAX) && dec == 18 && lot == 15, "largest exponent");
    kani::cover!(v.is_none() && mark != 0 && lot > 15, "lot exponent out of range refused");
}

// ── isqrt and the +2% depth at the widths the solver can decide ───────────────────────────

/// `isqrt_u128` is the exact floor square root for every n < 2^32 (production, real loop).
/// The original (u64 n) was NO-VERDICT at 900 s. Mutants: return `y` instead of `x`; `y > x`
/// for `y >= x`; start below sqrt(n) (`bits / 2`).
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(10)]
fn kani_grow_dex_isqrt_exact_u32() {
    let n32: u32 = kani::any();
    let n = n32 as u128;
    let x = isqrt_u128(n);
    assert!(x * x <= n);
    assert!((x + 1) * (x + 1) > n);
    kani::cover!(n > 1 && x * x == n, "perfect square");
    kani::cover!(n > 1 && x * x < n && (x + 1) * (x + 1) == n + 1, "one below a square");
    kani::cover!(n > 1 << 31, "top of the u32 range");
}

/// `plus2pct_depth_e6` is the exact floor of R·(1 − 1/sqrt(1.02)) for every u16 reserve
/// (same assertions as `kani_dex_depth_floor_exact`, which was NO-VERDICT at u32).
/// Mutants: `m = m0` always; `>` for `>=` in `depth_pred`; `R - m - 1`.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(10)]
fn kani_grow_dex_depth_floor_exact_u16() {
    let r16: u16 = kani::any();
    let r = r16 as u64;
    let d = plus2pct_depth_e6(r);
    assert!(d <= r);
    let m = (r - d) as u128;
    let q = (r as u128) * (r as u128);
    assert!(51 * m * m >= 50 * q, "m large enough: depth never overstated");
    assert!(m == 0 || 51 * (m - 1) * (m - 1) < 50 * q, "m minimal: depth is the floor");
    assert!(d as u128 * 100 <= r as u128, "under 1% of the reserve");
    kani::cover!(r == 0 && d == 0, "zero reserve");
    kani::cover!(r > 0 && r < 102 && d == 0, "sub-atom depth floors to 0");
    kani::cover!(d > 0, "positive depth");
    kani::cover!(r > 1 << 15, "top of the u16 range");
}
