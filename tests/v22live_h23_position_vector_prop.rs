//! v22live 2026-10-20: native randomized check of H23b's statement (Kani H23b/H23c are NO VERDICT, CBMC out of
//! memory): `state::portfolio_position_vector` before vs after is EQUAL iff leg k stays active with an
//! unchanged (asset_index, market_id, side, basis_pos_q). Changes to capital, the leg's a_basis/k_snap/
//! loss_weight and other non-position bytes never change it. All 16 slots, edge values, 200k random cases.
use core::mem::{offset_of, size_of};
use percolator::{
    PortfolioAccountV16Account, PortfolioLegV16Account, V16PodI128, V16PodU128, V16PodU32, V16PodU64,
    PORTFOLIO_LEG_V16_EMPTY_ACCOUNT, V16_MAX_PORTFOLIO_ASSETS_N,
};
use percolator_prog::constants::{HEADER_LEN, KIND_PORTFOLIO, MAGIC, PORTFOLIO_ACCOUNT_LEN, VERSION};
use percolator_prog::state;

type Tup = (u32, u64, u8, i128);

struct Rng(u64);
impl Rng {
    fn u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn i128(&mut self) -> i128 {
        const E: [i128; 6] = [0, 1, -1, i128::MAX, i128::MIN, 1 << 64];
        if self.u64() % 4 == 0 { E[(self.u64() % 6) as usize] } else { ((self.u64() as u128) << 64 | self.u64() as u128) as i128 }
    }
    fn tup(&mut self) -> Tup {
        const U32E: [u32; 3] = [0, 1, u32::MAX];
        const U64E: [u64; 3] = [0, 1, u64::MAX];
        let a = if self.u64() % 4 == 0 { U32E[(self.u64() % 3) as usize] } else { self.u64() as u32 };
        let m = if self.u64() % 4 == 0 { U64E[(self.u64() % 3) as usize] } else { self.u64() };
        (a, m, (self.u64() % 3) as u8, self.i128())
    }
}

fn leg_off(k: usize) -> usize {
    HEADER_LEN + offset_of!(PortfolioAccountV16Account, legs) + k * size_of::<PortfolioLegV16Account>()
}

fn image() -> Vec<u8> {
    let mut d = vec![0u8; PORTFOLIO_ACCOUNT_LEN];
    d[0..8].copy_from_slice(&MAGIC.to_le_bytes());
    d[8..10].copy_from_slice(&VERSION.to_le_bytes());
    d[10] = KIND_PORTFOLIO;
    d
}

fn write_leg(d: &mut [u8], k: usize, active: u8, t: Tup) {
    let mut leg = PORTFOLIO_LEG_V16_EMPTY_ACCOUNT;
    leg.active = active;
    leg.asset_index = V16PodU32::new(t.0);
    leg.market_id = V16PodU64::new(t.1);
    leg.side = t.2;
    leg.basis_pos_q = V16PodI128::new(t.3);
    let o = leg_off(k);
    d[o..o + size_of::<PortfolioLegV16Account>()].copy_from_slice(bytemuck::bytes_of(&leg));
}

fn put_u128(d: &mut [u8], off: usize, v: u128) {
    d[off..off + 16].copy_from_slice(&v.to_le_bytes());
}

/// One case: A has leg k active with `ta`; B has leg k (active = b_active) with `tb`, plus noise in
/// non-position fields. Returns (vector equal, expected equal).
fn case(k: usize, ta: Tup, tb: Tup, b_active: bool, noise: (u128, u128, i128, u128)) -> (bool, bool) {
    let mut d = image();
    write_leg(&mut d, k, 1, ta);
    let va = state::portfolio_position_vector(&d).expect("A readable");
    assert_eq!(va, vec![ta]);
    write_leg(&mut d, k, b_active as u8, tb);
    put_u128(&mut d, HEADER_LEN + offset_of!(PortfolioAccountV16Account, capital), noise.0);
    let lo = leg_off(k);
    put_u128(&mut d, lo + offset_of!(PortfolioLegV16Account, a_basis), noise.1);
    d[lo + offset_of!(PortfolioLegV16Account, k_snap)..][..16].copy_from_slice(&V16PodI128::new(noise.2).bytes);
    put_u128(&mut d, lo + offset_of!(PortfolioLegV16Account, loss_weight), noise.3);
    let _ = V16PodU128::new(0);
    let vb = state::portfolio_position_vector(&d).expect("B readable");
    (va == vb, b_active && ta == tb)
}

#[test]
fn h23_vector_equal_iff_position_unchanged_every_slot_edge_cases() {
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut seen = [0usize; 5]; // equal, basis-only, side-only, closed, other-field
    for k in 0..V16_MAX_PORTFOLIO_ASSETS_N {
        let ta = r.tup();
        let n = (r.u64() as u128, r.u64() as u128, r.i128(), r.u64() as u128);
        // unchanged position, noise only
        let (eq, exp) = case(k, ta, ta, true, n);
        assert!(eq && exp, "slot {k}: noise changed the vector");
        seen[0] += 1;
        // each position field alone
        let mut t = ta; t.3 = t.3.wrapping_add(1); assert_eq!(case(k, ta, t, true, n), (false, false), "basis k={k}"); seen[1] += 1;
        let mut t = ta; t.2 ^= 1; assert_eq!(case(k, ta, t, true, n), (false, false), "side k={k}"); seen[2] += 1;
        let mut t = ta; t.0 = t.0.wrapping_add(1); assert_eq!(case(k, ta, t, true, n), (false, false), "asset k={k}");
        let mut t = ta; t.1 = t.1.wrapping_add(1); assert_eq!(case(k, ta, t, true, n), (false, false), "market k={k}");
        // leg closed with the same tuple
        assert_eq!(case(k, ta, ta, false, n), (false, false), "closed k={k}"); seen[3] += 1;
        // single-bit basis flips at every bit
        for bit in 0..128 { let mut t = ta; t.3 ^= 1i128 << bit; assert_eq!(case(k, ta, t, true, n), (false, false)); }
        seen[4] += 1;
    }
    assert!(seen.iter().all(|&c| c == V16_MAX_PORTFOLIO_ASSETS_N));
}

#[test]
fn h23_vector_equal_iff_position_unchanged_random() {
    let mut r = Rng(0x2545_f491_4f6c_dd1d);
    let (mut eq_cases, mut ne_cases) = (0u32, 0u32);
    for _ in 0..200_000 {
        let k = (r.u64() % V16_MAX_PORTFOLIO_ASSETS_N as u64) as usize;
        let ta = r.tup();
        // half the time start from ta and perturb at most one field, so equal cases are common
        let tb = match r.u64() % 6 { 0 => ta, 1 => (r.tup().0, ta.1, ta.2, ta.3), 2 => (ta.0, r.u64(), ta.2, ta.3),
            3 => (ta.0, ta.1, (r.u64() % 3) as u8, ta.3), 4 => (ta.0, ta.1, ta.2, r.i128()), _ => r.tup() };
        let b_active = r.u64() % 8 != 0;
        let n = (r.u64() as u128, r.u64() as u128, r.i128(), r.u64() as u128);
        let (eq, exp) = case(k, ta, tb, b_active, n);
        assert_eq!(eq, exp, "k={k} ta={ta:?} tb={tb:?} active={b_active}");
        if exp { eq_cases += 1 } else { ne_cases += 1 }
    }
    assert!(eq_cases > 10_000 && ne_cases > 10_000, "both outcomes exercised: {eq_cases}/{ne_cases}");
}
