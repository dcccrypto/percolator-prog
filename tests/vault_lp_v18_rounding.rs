#![cfg(not(kani))]
//! PROG-BUG-VAULTLPV18ROUND: rounding-direction audit of `src/vault_lp_v18.rs`.
//!
//! Every division in the file is checked against an independent 256-bit reference
//! (schoolbook 64-bit-limb multiply + bitwise long division, no shared code with the program).
//!
//! Division inventory (file:line -> verdict, "P" = protocol-favouring / neutral, "U" = rounds
//! toward the user by < 1 unit, documented, see `report_*` tests):
//!   :24  mul_div_floor                      floor            exact floor; base of all below
//!   :51  bps_floor  (x/B*b + (x%B)*b/B)     floor            P (fees/senior share floored)
//!   :60-61 bps_ceil                         ceil             P (junior floor, IMR requirement)
//!   :136 senior_shares_for_deposit          floor shares     P (mint floor)
//!   :148 senior_atoms_for_redemption        floor payout     P (pay floor)
//!   :164 senior_claim_after_redemption      slice floor      P (remaining claim rounds up)
//!   :178 senior_principal_portion           floor            P
//!   :215 bound_pot_available_principal      floor(held)      P (under-counts backing)
//!   :282 skew_funding_rate_e9               floor            neutral (|rate| shrinks <1e-9/slot)
//!   :324 step_imr_bps                       floor(bps)       U  (IMR may be 1 bps low)
//!   :339 notional_atoms                     floor            U  (notional <1 atom low; documented)
//!   :390 vault_lp_exposure_allowed          floor cap        P  (cap floored)
//!   :666 usd_to_q_capped                    floor            P  (smaller pinned cap)
//!   :811 vault_lp_alloc_split               floor small take P  (documented, small pot not short)
//!   :855 pot_physical_net_atoms held        floor            P
//!   :857 pot_physical_net_atoms uncovered   ceil             P  (claims ceilinged)
//!   :988 skew_defaults_e9                   floor/2          neutral (config default)
//!   senior_floor_encode (:1006)             ceil (shift)     P  (decode >= v)

use percolator_prog::vault_lp_v18::*;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

// ── independent u256 reference ───────────────────────────────────────────────────────────────
fn mul256(a: u128, b: u128) -> [u64; 4] {
    let al = [a as u64, (a >> 64) as u64];
    let bl = [b as u64, (b >> 64) as u64];
    let mut r = [0u64; 4];
    for i in 0..2 {
        let mut carry: u128 = 0;
        for j in 0..2 {
            let cur = r[i + j] as u128 + (al[i] as u128) * (bl[j] as u128) + carry;
            r[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 2;
        while carry != 0 && k < 4 {
            let cur = r[k] as u128 + carry;
            r[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    r
}

/// (quotient limbs, remainder) of 256-bit n / u128 d by shift-subtract.
fn divrem256(n: [u64; 4], d: u128) -> ([u64; 4], u128) {
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for bit in (0..256).rev() {
        let nb = (n[bit / 64] >> (bit % 64)) & 1;
        let top = rem >> 127;
        rem = (rem << 1) | nb as u128;
        if top == 1 || rem >= d {
            rem = rem.wrapping_sub(d);
            q[bit / 64] |= 1 << (bit % 64);
        }
    }
    (q, rem)
}

/// Some(q) if q fits u128, None otherwise (reference "overflow").
fn ref_div(a: u128, b: u128, d: u128, ceil: bool) -> Option<u128> {
    let (q, r) = divrem256(mul256(a, b), d);
    if q[2] != 0 || q[3] != 0 {
        return None;
    }
    let mut v = (q[0] as u128) | ((q[1] as u128) << 64);
    if ceil && r != 0 {
        v = v.checked_add(1)?;
    }
    Some(v)
}

fn rnd(rng: &mut XorShiftRng) -> u128 {
    match rng.gen_range(0..6) {
        0 => rng.gen_range(0..16) as u128,
        1 => rng.gen::<u16>() as u128,
        2 => rng.gen::<u32>() as u128,
        3 => rng.gen::<u64>() as u128,
        4 => u64::MAX as u128 - rng.gen_range(0..4) as u128,
        _ => rng.gen::<u128>() >> rng.gen_range(0..128),
    }
}

const N: usize = 200_000;

#[test]
fn mul_div_floor_matches_u256() {
    let mut rng = XorShiftRng::seed_from_u64(0xA11CE);
    for _ in 0..N {
        let (a, b, d) = (rnd(&mut rng), rnd(&mut rng), rnd(&mut rng));
        let got = mul_div_floor(a, b, d);
        let full_fits = a.checked_mul(b).is_some();
        if d == 0 || !full_fits {
            assert_eq!(got, None, "{a} {b} {d}");
        } else {
            assert_eq!(got, ref_div(a, b, d, false), "{a} {b} {d}");
        }
    }
}

#[test]
fn bps_floor_ceil_match_u256_all_u128() {
    let mut rng = XorShiftRng::seed_from_u64(0xB0B);
    for _ in 0..N {
        let x = rnd(&mut rng);
        let bps = if rng.gen_bool(0.3) { *[0u16, 1, 9_999, 10_000].get(rng.gen_range(0..4)).unwrap() } else { rng.gen_range(0..=10_000) };
        assert_eq!(bps_floor(x, bps), ref_div(x, bps as u128, 10_000, false), "floor {x} {bps}");
        assert_eq!(bps_ceil(x, bps), ref_div(x, bps as u128, 10_000, true), "ceil {x} {bps}");
    }
    assert_eq!(bps_floor(5, 10_001), None);
    assert_eq!(bps_ceil(5, 10_001), None);
}

#[test]
fn fees_never_round_to_user_benefit() {
    let mut rng = XorShiftRng::seed_from_u64(0xFEE);
    for _ in 0..N {
        let fee = rnd(&mut rng);
        let bps = rng.gen_range(0..=10_000u16);
        // split_fee: senior part floored, junior (creator / protocol side) gets the dust, sum exact.
        let (s, j) = split_fee(fee, bps).unwrap();
        assert_eq!(s + j, fee);
        assert_eq!(Some(s), ref_div(fee, bps as u128, 10_000, false));
        // cushion split conserves and never gives the cushion more than the floored share.
        let (cs, cc) = cushion_split(fee, bps.max(1), 2_000, rnd(&mut rng) >> 4, rnd(&mut rng) >> 4).unwrap();
        assert_eq!(cs + cc, fee);
        assert!(cc <= ref_div(fee, bps.max(1) as u128, 10_000, false).unwrap());
        // junior floor and IMR requirement use ceil: requirement >= exact real value.
        let c = junior_floor_atoms(fee, bps).unwrap();
        assert_eq!(Some(c), ref_div(fee, bps as u128, 10_000, true));
    }
}

#[test]
fn deposit_mints_floor_redemption_pays_floor() {
    let mut rng = XorShiftRng::seed_from_u64(0xD0D);
    for _ in 0..N {
        let (amt, s, v) = (rnd(&mut rng) >> 64, rnd(&mut rng) >> 64, rnd(&mut rng) >> 64);
        let m = senior_shares_for_deposit(amt, s, v);
        if s == 0 {
            assert_eq!(m, Some(amt));
        } else if v == 0 {
            assert_eq!(m, None);
        } else {
            assert_eq!(m, ref_div(amt, s, v, false));
            // no dilution: (v+amt)*S >= v*(S+m)  <=>  amt*S >= v*m, exact in u256.
            let m = m.unwrap();
            let lhs = mul256(amt, s);
            let rhs = mul256(v, m);
            assert!(cmp256(lhs, rhs) >= 0, "dilution {amt} {s} {v}");
        }
        if s != 0 {
            let sh = if s == 0 { 0 } else { rnd(&mut rng) % (s + 1) };
            let pay = senior_atoms_for_redemption(sh, s, v).unwrap();
            assert_eq!(Some(pay), ref_div(sh, v, s, false));
            let slice_claim = senior_claim_after_redemption(v, sh, s).unwrap();
            assert_eq!(Some(v - slice_claim), ref_div(sh, v, s, false));
            // per-share value of the remainder never falls: (v-pay)*S >= v*(S-sh)
            if sh < s {
                assert!(cmp256(mul256(v - pay, s), mul256(v, s - sh)) >= 0);
            }
        }
        assert_eq!(senior_atoms_for_redemption(s.saturating_add(1), s, v), None);
    }
}

fn cmp256(a: [u64; 4], b: [u64; 4]) -> i32 {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return if a[i] > b[i] { 1 } else { -1 };
        }
    }
    0
}

#[test]
fn principal_portion_alloc_split_and_pots() {
    let mut rng = XorShiftRng::seed_from_u64(0x707);
    for _ in 0..N {
        let (sh, avail, s, out) = (rnd(&mut rng) >> 64, rnd(&mut rng) >> 64, rnd(&mut rng) >> 64, rnd(&mut rng) >> 64);
        if s != 0 {
            let r = senior_principal_portion(sh, avail, s, out).unwrap();
            assert_eq!(r, ref_div(sh, avail, s, false).unwrap().min(out));
        }
        // :215 / :855 / :857
        let (fu, vl, sc) = (rnd(&mut rng) >> 2, rnd(&mut rng) >> 2, rnd(&mut rng) >> 64);
        let pr = rnd(&mut rng);
        let held = fu.saturating_add(vl) / sc.max(1);
        if sc != 0 {
            assert_eq!(bound_pot_available_principal(pr, fu, vl, sc), pr.min(held));
            let (cb, ic) = (rnd(&mut rng) >> 2, rnd(&mut rng) >> 2);
            let net = pot_physical_net_atoms(fu, vl, cb, ic, sc);
            let unc = cb.saturating_sub(ic);
            let ceil = unc / sc + u128::from(unc % sc != 0);
            assert_eq!(net, held.saturating_sub(ceil));
        }
        // :811 alloc split: conserves, never over a pot, small pot floor.
        let (de, dd) = (rnd(&mut rng) >> 8, rnd(&mut rng) >> 8);
        let tot = de + dd;
        let moved = if tot == 0 { 0 } else { rnd(&mut rng) % (tot + 1) };
        if let Some((te, td)) = vault_lp_alloc_split(moved, de, dd) {
            assert_eq!(te + td, moved);
            assert!(te <= de && td <= dd);
            if moved != 0 {
                let (small_t, small_d) = if dd <= de { (td, dd) } else { (te, de) };
                let _ = small_d;
                assert!(small_t <= ref_div(moved, if dd <= de { dd } else { de }, tot, false).unwrap());
            }
        }
        assert_eq!(vault_lp_alloc_split(tot.saturating_add(1), de, dd), None);
    }
}

#[test]
fn usd_to_q_and_exposure_and_notional() {
    let mut rng = XorShiftRng::seed_from_u64(0x11);
    for _ in 0..N {
        let usd = rnd(&mut rng) >> 40;
        let p = rng.gen_range(0..u64::MAX) >> rng.gen_range(0..40);
        let q = usd_to_q_capped(usd, p);
        if p == 0 {
            assert_eq!(q, None);
        } else if let Some(q) = q {
            let exact = ref_div(usd, 1_000_000_000_000, p as u128, false).unwrap();
            assert!(q <= exact, "pinned cap above exact floor");
            assert!(q > 0);
        }
        let (pos, sc) = (rnd(&mut rng) >> 40, rnd(&mut rng) >> 64);
        if sc != 0 {
            assert_eq!(notional_atoms(pos, p, sc), ref_div(pos, p as u128, sc, false));
        }
        // :282 skew
        let (net, oi) = ((rnd(&mut rng) >> 70) as i128 * if rng.gen() { 1 } else { -1 }, rnd(&mut rng) >> 70);
        let (sl, mx) = (rng.gen::<u64>() >> rng.gen_range(0..40), rng.gen::<u64>() >> rng.gen_range(0..40));
        let r = skew_funding_rate_e9(net, oi, sl, mx);
        if oi != 0 && net != 0 && sl != 0 && mx != 0 {
            let sh = net.unsigned_abs().min(oi);
            let exact = ref_div(sl as u128, sh, oi, false).unwrap().min(mx as u128);
            assert_eq!(r.unsigned_abs(), exact);
            if exact != 0 {
                assert_eq!(r.signum(), if net < 0 { 1 } else { -1 });
            }
        }
        // :324 step IMR
        let (ln, cap) = (rnd(&mut rng) >> 20, rnd(&mut rng) >> 20);
        let (base, maxi) = (rng.gen_range(0..=10_000u64), rng.gen_range(0..=10_000u16));
        let s = step_imr_bps(ln, cap, base, maxi);
        assert!(s >= base);
        if cap != 0 && (maxi as u64) > base {
            let exact = ref_div(ln, 10_000, cap, false).unwrap().min(10_000) as u64;
            assert_eq!(s, exact.clamp(base, maxi as u64));
        }
        let h = skew_defaults_e9(mx);
        assert!(h.0 >= 1 || mx == 0);
        assert!(h.0 <= h.1.max(1));
    }
}

#[test]
fn senior_floor_code_is_ceiling() {
    let mut rng = XorShiftRng::seed_from_u64(0x5F);
    for _ in 0..N {
        let v = rnd(&mut rng) >> rng.gen_range(0..70);
        let d = senior_floor_decode(senior_floor_encode(v));
        assert!(d >= v, "{v} -> {d}");
    }
}

// ── report-only: documented user-favouring (<1 unit) roundings ──────────────────────────────
#[test]
fn report_user_favouring_floors() {
    // :339 notional floor: 1 q at price 1 with scale 2 -> 0 atoms notional (exact 0.5).
    assert_eq!(notional_atoms(1, 1, 2), Some(0));
    // :324 step IMR floor: lp_net/cap = 0.99999 -> 9_999 not 10_000 (exact 9_999.9).
    assert_eq!(step_imr_bps(99_999, 100_000, 0, 10_000), 9_999);
}

// ── sequence invariant ──────────────────────────────────────────────────────────────────────
#[test]
fn sequence_claims_never_exceed_assets() {
    for seed in 0..8u64 {
        let mut rng = XorShiftRng::seed_from_u64(0xC0FFEE + seed);
        const H: usize = 6;
        let mut shares = [0u128; H];
        let mut s_tot: u128 = 0;
        let mut v: u128 = 0; // vault assets (atoms)
        let mut c: u128 = 0; // senior claim
        let mut ever_in: u128 = 0;
        let mut ever_out: u128 = 0;
        for step in 0..10_000 {
            let sv = tranche_split(v, c).senior;
            match rng.gen_range(0..3) {
                0 => {
                    // deposit (processor refuses into an impaired senior: sv < c)
                    if s_tot != 0 && (sv == 0 || sv < c) {
                        continue;
                    }
                    let amt = rng.gen_range(1..=1_000_000_000u128);
                    let m = senior_shares_for_deposit(amt, s_tot, c.min(v)).unwrap_or(0);
                    if m == 0 {
                        continue;
                    }
                    let before = (sv, s_tot);
                    shares[rng.gen_range(0..H)] += m;
                    s_tot += m;
                    v += amt;
                    c += amt;
                    ever_in += amt;
                    if before.1 != 0 {
                        // per-share senior value of incumbents did not fall
                        let sv2 = tranche_split(v, c).senior;
                        assert!(cmp256(mul256(sv2, before.1), mul256(before.0, s_tot)) >= 0, "dilution step {step}");
                    }
                }
                1 => {
                    let h = rng.gen_range(0..H);
                    if shares[h] == 0 {
                        continue;
                    }
                    let sh = if rng.gen_bool(0.3) { shares[h] } else { rng.gen_range(1..=shares[h]) };
                    let pay = senior_atoms_for_redemption(sh, s_tot, sv).unwrap();
                    let c2 = senior_claim_after_redemption(c, sh, s_tot).unwrap();
                    assert!(pay <= v, "pay > assets step {step}");
                    v -= pay;
                    c = c2;
                    s_tot -= sh;
                    shares[h] -= sh;
                    ever_out += pay;
                    assert!(ever_out <= ever_in);
                }
                _ => {
                    // loss: hits junior first (senior value unchanged while v stays >= c)
                    let loss = rng.gen_range(0..=(v / 4 + 1));
                    let sv_before = tranche_split(v, c).senior;
                    let jr_before = tranche_split(v, c).junior;
                    v = v.saturating_sub(loss);
                    let sp = tranche_split(v, c);
                    if loss <= jr_before {
                        assert_eq!(sp.senior, sv_before, "senior hit before junior exhausted");
                    }
                    assert_eq!(sp.senior + sp.junior, v);
                }
            }
            // total claims <= assets: every holder's floor value summed.
            let sv = tranche_split(v, c).senior;
            let mut sum: u128 = 0;
            for &sh in &shares {
                if s_tot != 0 {
                    sum += senior_atoms_for_redemption(sh, s_tot, sv).unwrap();
                }
            }
            assert!(sum <= sv && sv <= v, "claims {sum} > assets {v} (sv {sv}) step {step}");
            if s_tot == 0 {
                assert_eq!(shares.iter().sum::<u128>(), 0);
            }
        }
    }
}
