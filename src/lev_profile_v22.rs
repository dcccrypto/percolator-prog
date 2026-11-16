//! v2.2 decision 1 (night 2026-10-28, plan P3): the volatility-derived engine profile, plan v2 §3
//! PROFILE, as a PURE function. InitMarket still validates the creator's profile exactly as before:
//! using the profile AS the market's profile is an owner decision (ledger `v22-night-plans-2026-10-28.md`
//! P3), because for low-σ majors the derived MMR (260 bps at σ 2 %/day) is below today's seed-kit
//! 600 bps, i.e. a loosening.
//!
//! Day1 2026-10-28: WIRED, TIGHTEN-ONLY, OFF by default. The guarded-open check (`lev_trade_post`)
//! may read the profile as a FLOOR: `MMR_lev = max(MMR, P.mmr)` in `L_trader`, `IMR = max(IMR, P.imr)`
//! in the leverage gate, with σ = the guard's burst-floored variance over one day. It can only refuse
//! more opens, never fewer, and it never touches the engine's own margins (liquidation is unchanged),
//! the short-side cap (a higher MMR would LOOSEN it) or InitMarket. `VOL_PROFILE_LIVE = false`: the
//! program behaves exactly as before (the .so is byte-identical to the unwired build); turning it on is
//! an upgrade (owner decision). `profile_floor` is the only combiner; unit tests + Kani pin it.
//!
//! ```text
//! d   = clamp(ceil(32·σ_prior_bps/1000), 64, 256)      band (bps)
//! cap = ceil(d/32)                                       per-slot cap (bps); dt 100; epoch 600
//! G   = band_worst_adverse_bps(d)                        engine G(d)
//! lin = cap·dt + ceil(F·dt·1e4/1e9) + ceil((1e4 + cap·dt)·liq/1e4)
//! bsl = G + ceil((F + R)·2·E·1e4/1e9) + ceil((1e4 + G)·liq/1e4)
//! MMR = roundup10(max(lin, bsl));  IMR = max(500, MMR + max(50, MMR/10))
//! ```
//! Funding cap F = 111 e9/slot (0.1 %/h at 400 ms), rent R = 100 e9/slot, liquidation fee 50 bps
//! (the seed kit's). Pinned to `sims/v22lev/levmodel.py::profile_for_sigma` by the unit test below.

pub const BPS: u64 = 10_000;
pub const DT_SLOTS: u64 = 100;
pub const EPOCH_SLOTS: u64 = 600;
pub const FUNDING_E9: u64 = 111;
pub const RENT_E9: u64 = 100;
pub const LIQ_FEE_BPS: u64 = 50;
pub const BAND_MIN_BPS: u64 = 64;
pub const BAND_MAX_BPS: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolProfile {
    pub band_bps: u64,
    pub cap_bps: u64,
    pub g_bps: u64,
    pub lin_bps: u64,
    pub bsl_bps: u64,
    pub mmr_bps: u64,
    pub imr_bps: u64,
}

fn div_ceil(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}

/// The profile for a daily volatility prior `sigma_day_bps` (6000 = 60 %/day). `None` only if the
/// engine refuses the derived band (never for the clamped 64..=256).
pub fn profile_for_sigma_bps(sigma_day_bps: u64) -> Option<VolProfile> {
    let d = div_ceil(sigma_day_bps.saturating_mul(32), 1_000).clamp(BAND_MIN_BPS, BAND_MAX_BPS);
    let cap = div_ceil(d, 32);
    let g = percolator::band_rent::band_worst_adverse_bps(d).ok()?;
    let lin = cap * DT_SLOTS
        + div_ceil(FUNDING_E9 * DT_SLOTS * BPS, 1_000_000_000)
        + div_ceil((BPS + cap * DT_SLOTS) * LIQ_FEE_BPS, BPS);
    let bsl = g
        + div_ceil((FUNDING_E9 + RENT_E9) * 2 * EPOCH_SLOTS * BPS, 1_000_000_000)
        + div_ceil((BPS + g) * LIQ_FEE_BPS, BPS);
    let mmr = div_ceil(core::cmp::max(lin, bsl), 10) * 10;
    let imr = core::cmp::max(500, mmr + core::cmp::max(50, mmr / 10));
    Some(VolProfile { band_bps: d, cap_bps: cap, g_bps: g, lin_bps: lin, bsl_bps: bsl, mmr_bps: mmr, imr_bps: imr })
}

/// Day1 2026-10-28: the profile floor on guarded opens. OFF: `profile_floor` is the identity and the
/// wiring in `lev_trade_post` is compiled out. Turning it on is an upgrade and an owner decision.
pub const VOL_PROFILE_LIVE: bool = false;

/// One day in slots (400 ms), the horizon the profile's σ prior is quoted over.
pub const SIGMA_DAY_SLOTS: u64 = 216_000;

/// σ over one day (bps) from a per-slot variance (`vol_var_x100` units), as `growth_v19::sigma_h_bps`.
pub fn sigma_day_bps(var_x100: u32) -> u64 {
    crate::growth_v19::sigma_h_bps(var_x100, SIGMA_DAY_SLOTS)
}

/// The tighten-only combiner: `(max(mmr, p.mmr), max(imr, p.imr))` when `live` and a profile exists,
/// else `(mmr, imr)` UNCHANGED. Never below either input (Kani `kani_vol_profile_floor_*`).
pub fn profile_floor(live: bool, mmr_bps: u64, imr_bps: u64, profile: Option<(u64, u64)>) -> (u64, u64) {
    match (live, profile) {
        (true, Some((p_mmr, p_imr))) => (core::cmp::max(mmr_bps, p_mmr), core::cmp::max(imr_bps, p_imr)),
        _ => (mmr_bps, imr_bps),
    }
}

/// The profile's `(MMR, IMR)` for a burst-floored variance, `None` without volatility data.
pub fn profile_mmr_imr_for_var(var_x100: Option<u32>) -> Option<(u64, u64)> {
    let p = profile_for_sigma_bps(sigma_day_bps(var_x100?))?;
    Some((p.mmr_bps, p.imr_bps))
}

/// The wiring in `lev_trade_post`: `(MMR for L_trader, IMR floor for the leverage gate)`. `var_eff` (the
/// guard's burst-floored variance, `None` without volatility data) is only evaluated when LIVE; OFF this
/// is the constant `(mmr, 0)`, so the gate is exactly the unwired one (`max(imr, 0) == imr`).
#[inline(always)]
pub fn open_gate_floor(mmr_bps: u64, var_eff: impl FnOnce() -> Option<u32>) -> (u64, u64) {
    let prof = if VOL_PROFILE_LIVE { profile_mmr_imr_for_var(var_eff()) } else { None };
    profile_floor(VOL_PROFILE_LIVE, mmr_bps, 0, prof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (σ bps/day, d, cap, G, MMR, IMR) from `levmodel.profile_for_sigma` (python, 2026-10-28).
    const SIM: [(u64, u64, u64, u64, u64, u64); 9] = [
        (200, 64, 2, 194, 260, 500),
        (600, 64, 2, 194, 260, 500),
        (1500, 64, 2, 194, 260, 500),
        (3000, 96, 3, 292, 360, 500),
        (6000, 192, 6, 592, 660, 726),
        (8000, 256, 8, 795, 860, 946),
        (10000, 256, 8, 795, 860, 946),
        (12000, 256, 8, 795, 860, 946),
        (20000, 256, 8, 795, 860, 946),
    ];

    #[test]
    fn profile_matches_the_sim_grid() {
        for (s, d, cap, g, mmr, imr) in SIM {
            let p = profile_for_sigma_bps(s).expect("profile");
            assert_eq!((p.band_bps, p.cap_bps, p.g_bps, p.mmr_bps, p.imr_bps), (d, cap, g, mmr, imr), "σ {s}");
        }
    }

    #[test]
    fn profile_is_monotone_and_safe() {
        let mut prev = profile_for_sigma_bps(0).unwrap();
        for s in (0..=30_000u64).step_by(37) {
            let p = profile_for_sigma_bps(s).unwrap();
            assert!(p.band_bps >= prev.band_bps && p.mmr_bps >= prev.mmr_bps && p.imr_bps >= prev.imr_bps, "σ {s}");
            // the §1.3 envelope the engine checks: MMR covers the worst band move plus fees
            assert!(p.mmr_bps >= p.bsl_bps && p.mmr_bps >= p.lin_bps && p.imr_bps > p.mmr_bps);
            assert!((BAND_MIN_BPS..=BAND_MAX_BPS).contains(&p.band_bps));
            prev = p;
        }
        // the loosening the plan flags: a 2 %/day major derives MMR 260 (seed kit today: 600)
        assert!(profile_for_sigma_bps(200).unwrap().mmr_bps < 600);
    }

    #[test]
    fn vol_profile_is_off_by_default() {
        assert!(!VOL_PROFILE_LIVE, "turning the profile floor on is an upgrade and an owner decision");
        // the wired gate OFF: MMR unchanged, IMR floor 0, and the variance is never even read
        for m in [0u64, 260, 600, 1_000, u64::MAX] {
            assert_eq!(open_gate_floor(m, || panic!("variance read while OFF")), (m, 0));
        }
    }

    /// Default OFF is the identity, bit for bit, on every input (incl. a profile far above the market's).
    #[test]
    fn profile_floor_off_is_identity() {
        let grid = [0u64, 1, 9, 10, 260, 500, 599, 600, 726, 1_000, 5_000, 10_000, u64::MAX];
        for &m in &grid {
            for &i in &grid {
                for p in [None, Some((0, 0)), Some((260, 500)), Some((860, 946)), Some((u64::MAX, u64::MAX))] {
                    assert_eq!(profile_floor(false, m, i, p), (m, i), "off m {m} i {i} p {p:?}");
                }
                // and ON without volatility data is unchanged too
                assert_eq!(profile_floor(true, m, i, None), (m, i));
            }
        }
    }

    /// ON only tightens: never below the inputs, and equal to them when the profile is looser
    /// (the low-σ major case the plan flags: MMR 600 / IMR 1000 vs P 260 / 500 stays 600 / 1000).
    #[test]
    fn profile_floor_on_only_tightens() {
        assert_eq!(profile_floor(true, 600, 1_000, profile_mmr_imr_for_var(Some(1))), (600, 1_000));
        assert_eq!(profile_floor(true, 300, 500, Some((660, 726))), (660, 726));
        assert_eq!(profile_floor(true, 700, 500, Some((660, 726))), (700, 726));
        for m in (0..=2_000u64).step_by(7) {
            for i in (0..=3_000u64).step_by(11) {
                for v in [0u32, 1, 50, 400, 2_000, 20_000, u32::MAX] {
                    let (fm, fi) = profile_floor(true, m, i, profile_mmr_imr_for_var(Some(v)));
                    assert!(fm >= m && fi >= i, "m {m} i {i} v {v}");
                }
            }
        }
    }

    /// σ_day from the variance agrees with the sim's σ grid points: var such that σ_day = s gives P(s).
    #[test]
    fn profile_for_var_reads_sigma_over_one_day() {
        // σ_day = ceil(sqrt(var·216000/100)): var 0 -> σ 0 -> the 64 bps band row.
        assert_eq!(profile_mmr_imr_for_var(Some(0)), Some((260, 500)));
        assert_eq!(profile_mmr_imr_for_var(None), None);
        // var 1_667 -> σ_day = ceil(sqrt(3_600_720)) = 1_898 bps -> d = 61 -> 64 (floor row).
        assert_eq!(sigma_day_bps(1_667), 1_898);
        // var 16_666 -> σ_day = ceil(sqrt(35_998_560)) = 6_000 -> the 60 %/day row (MMR 660 / IMR 726).
        assert_eq!(sigma_day_bps(16_666), 6_000);
        assert_eq!(profile_mmr_imr_for_var(Some(16_666)), Some((660, 726)));
        // σ is monotone in var, so the floor is too
        let mut prev = (0, 0);
        for v in (0..=200_000u32).step_by(97) {
            let p = profile_mmr_imr_for_var(Some(v)).unwrap();
            assert!(p.0 >= prev.0 && p.1 >= prev.1, "var {v}");
            prev = p;
        }
    }
}

// Day1 2026-10-28: Kani. The wrapper's cfg(kani) build is blocked by the engine (#301), so these run
// in a scratch crate that includes this file by path with the engine's `band_worst_adverse_bps`
// copied verbatim (ledger v22-day1-2026-10-28.md); kept here so the harnesses live with the code.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// OFF is the identity for every input, whatever the profile.
    #[kani::proof]
    fn kani_vol_profile_floor_off_is_identity() {
        let m: u64 = kani::any();
        let i: u64 = kani::any();
        let p: Option<(u64, u64)> = kani::any();
        assert_eq!(profile_floor(false, m, i, p), (m, i));
        assert_eq!(profile_floor(true, m, i, None), (m, i));
    }

    /// ON never lowers either margin, and only ever returns an input or the profile's value.
    #[kani::proof]
    fn kani_vol_profile_floor_tighten_only() {
        let live: bool = kani::any();
        let m: u64 = kani::any();
        let i: u64 = kani::any();
        let p: Option<(u64, u64)> = kani::any();
        let (fm, fi) = profile_floor(live, m, i, p);
        assert!(fm >= m && fi >= i);
        match p {
            Some((pm, pi)) if live => assert!((fm == m || fm == pm) && (fi == i || fi == pi)),
            _ => assert!(fm == m && fi == i),
        }
    }

    /// Wired into the gate, the floor can only LOWER the trader leverage: for every market MMR and every
    /// profile, `L_trader(floored MMR) <= L_trader(MMR)`. σ_1h / jump are taken from a grid (none, calm,
    /// the burst test's 10 %/h, 80 %/day's 1_634, a large σ; jump 0 / 20 % / 35 % / max) so the integer
    /// sqrt is concrete: a fully symbolic σ did not finish in 10 min (the sqrt is a u128 Newton loop).
    #[kani::proof]
    fn kani_vol_profile_floor_lowers_l_trader() {
        const S: [Option<u64>; 5] = [None, Some(100), Some(1_054), Some(1_634), Some(10_000)];
        const J: [u16; 4] = [0, 2_000, 3_500, u16::MAX];
        let m: u64 = kani::any();
        let p: Option<(u64, u64)> = kani::any();
        let (fm, _) = profile_floor(true, m, 0, p);
        for s in S {
            for j in J {
                let off = crate::lev_guard_v22::l_trader_x100(m, s, j);
                let on = crate::lev_guard_v22::l_trader_x100(fm, s, j);
                assert!(on <= off);
            }
        }
    }

    /// The derived profile is internally safe for every σ: band in 64..=256, MMR covers both the
    /// linear and the band-worst envelopes, IMR > MMR and IMR >= 500.
    #[kani::proof]
    fn kani_vol_profile_envelope_any_sigma() {
        let s: u64 = kani::any();
        let p = profile_for_sigma_bps(s).unwrap();
        assert!(p.band_bps >= BAND_MIN_BPS && p.band_bps <= BAND_MAX_BPS);
        assert!(p.mmr_bps >= p.lin_bps && p.mmr_bps >= p.bsl_bps);
        assert!(p.imr_bps > p.mmr_bps && p.imr_bps >= 500);
    }
}

/// Reference-model property tests: an independent plain-u128 implementation of the documented rule
/// (module doc), compared with the production functions over the full domains.
#[cfg(test)]
mod ref_model_tests {
    use super::*;
    use proptest::prelude::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn cdiv(a: u128, b: u128) -> u128 {
        assert!(b > 0);
        (a + b - 1) / b
    }

    /// smallest s with s*s >= x (binary search, no Newton)
    fn ceil_sqrt(x: u128) -> u128 {
        let (mut lo, mut hi) = (0u128, 1u128 << 64);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if mid * mid >= x { hi = mid } else { lo = mid + 1 }
        }
        lo
    }

    /// (band, cap, g, lin, bsl, mmr, imr) straight from the doc block, u128, no saturation.
    fn ref_profile(sigma: u128) -> (u128, u128, u128, u128, u128, u128, u128) {
        let d = cdiv(sigma * 32, 1000).clamp(64, 256);
        let cap = cdiv(d, 32);
        let g = cdiv((10_000 + d) * (10_000 + d), 10_000 - d) - 10_000;
        let lin = cap * 100 + cdiv(111 * 100 * 10_000, 1_000_000_000) + cdiv((10_000 + cap * 100) * 50, 10_000);
        let bsl = g + cdiv((111 + 100) * 2 * 600 * 10_000, 1_000_000_000) + cdiv((10_000 + g) * 50, 10_000);
        let mmr = cdiv(lin.max(bsl), 10) * 10;
        let imr = 500u128.max(mmr + 50u128.max(mmr / 10));
        (d, cap, g, lin, bsl, mmr, imr)
    }

    fn check_sigma(s: u64) {
        let p = profile_for_sigma_bps(s).expect("profile");
        let r = ref_profile(s as u128);
        let got = (
            p.band_bps as u128, p.cap_bps as u128, p.g_bps as u128, p.lin_bps as u128,
            p.bsl_bps as u128, p.mmr_bps as u128, p.imr_bps as u128,
        );
        assert_eq!(got, r, "sigma {s}");
    }

    #[test]
    fn sigma_exhaustive_low_range() {
        for s in 0..=20_000u64 {
            check_sigma(s);
        }
    }

    /// every clamp / band-step boundary (d = ceil(32 s / 1000) changes) and the saturation edge
    #[test]
    fn sigma_boundaries_and_extremes() {
        let mut pts: Vec<u64> = Vec::new();
        pts.extend_from_slice(&[u64::MAX, u64::MAX - 1, u64::MAX / 32, u64::MAX / 32 + 1, u64::MAX / 32 - 1, u64::MAX / 1000, 1 << 63]);
        for d in 1..=300u64 {
            let s = (d * 1000) / 32;
            for x in s.saturating_sub(2)..=s + 2 {
                pts.push(x);
            }
        }
        for s in pts {
            check_sigma(s);
        }
        // saturation before the clamp is harmless: anything >= 8000 is the top band
        assert_eq!(profile_for_sigma_bps(u64::MAX).unwrap().band_bps, BAND_MAX_BPS);
        assert_eq!(profile_for_sigma_bps(u64::MAX / 32 + 1).unwrap(), profile_for_sigma_bps(8_000).unwrap());
    }

    #[test]
    fn div_ceil_matches_reference() {
        for a in [0u64, 1, 31, 32, 33, 999, 1000, 1001, u64::MAX - 1, u64::MAX] {
            for b in [1u64, 2, 3, 10, 32, 1000, u64::MAX] {
                assert_eq!(div_ceil(a, b) as u128, cdiv(a as u128, b as u128), "{a}/{b}");
            }
        }
    }

    #[test]
    fn sigma_day_matches_reference_and_is_monotone() {
        let r = |v: u32| ceil_sqrt(cdiv(v as u128 * 216_000, 100)).min(u64::MAX as u128) as u64;
        for v in [0u32, 1, 2, 99, 100, 101, 1_667, 16_666, 1 << 31, u32::MAX - 1, u32::MAX] {
            assert_eq!(sigma_day_bps(v), r(v), "var {v}");
        }
        // strided sweep across the whole u32 range (step 4099, ~1M points), monotone + exact
        let mut prev = 0u64;
        let mut v = 0u32;
        loop {
            let s = sigma_day_bps(v);
            assert!(s >= prev, "var {v}");
            if v % 97 == 0 {
                assert_eq!(s, r(v), "var {v}");
            }
            prev = s;
            match v.checked_add(4099) {
                Some(n) => v = n,
                None => break,
            }
        }
        // σ never overflows into the saturation branch for any u32 var
        assert!(sigma_day_bps(u32::MAX) < 1 << 40);
    }

    #[test]
    fn mmr_imr_for_var_composes_sigma_and_profile() {
        assert_eq!(profile_mmr_imr_for_var(None), None);
        for v in [0u32, 1, 1_667, 16_666, 50_000, 1_000_000, u32::MAX] {
            let (_, _, _, _, _, mmr, imr) = ref_profile(sigma_day_bps(v) as u128);
            assert_eq!(profile_mmr_imr_for_var(Some(v)), Some((mmr as u64, imr as u64)), "var {v}");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn prop_profile_any_sigma(s in any::<u64>()) { check_sigma(s); }

        #[test]
        fn prop_profile_invariants(s in any::<u64>()) {
            let p = profile_for_sigma_bps(s).unwrap();
            prop_assert!((BAND_MIN_BPS..=BAND_MAX_BPS).contains(&p.band_bps));
            prop_assert!(p.mmr_bps >= p.lin_bps && p.mmr_bps >= p.bsl_bps && p.mmr_bps % 10 == 0);
            prop_assert!(p.imr_bps >= 500 && p.imr_bps > p.mmr_bps);
            prop_assert!(p.imr_bps >= p.mmr_bps + 50);
        }

        #[test]
        fn prop_sigma_day_exact(v in any::<u32>()) {
            let s = sigma_day_bps(v) as u128;
            let x = cdiv(v as u128 * 216_000, 100);
            prop_assert!(s * s >= x && (s == 0 || (s - 1) * (s - 1) < x));
        }

        #[test]
        fn prop_floor_never_below_inputs(live in any::<bool>(), m in any::<u64>(), i in any::<u64>(),
                                         p in proptest::option::of((any::<u64>(), any::<u64>()))) {
            let (fm, fi) = profile_floor(live, m, i, p);
            prop_assert!(fm >= m && fi >= i);
            match p {
                Some((pm, pi)) if live => prop_assert_eq!((fm, fi), (m.max(pm), i.max(pi))),
                _ => prop_assert_eq!((fm, fi), (m, i)),
            }
        }

        #[test]
        fn prop_floor_composed_with_var(m in any::<u64>(), i in any::<u64>(), v in proptest::option::of(any::<u32>())) {
            let prof = profile_mmr_imr_for_var(v);
            let (fm, fi) = profile_floor(true, m, i, prof);
            prop_assert!(fm >= m && fi >= i);
            if let Some((pm, pi)) = prof {
                prop_assert_eq!((fm, fi), (m.max(pm), i.max(pi)));
            }
        }

        #[test]
        fn prop_open_gate_identity_when_off(m in any::<u64>(), v in proptest::option::of(any::<u32>())) {
            // VOL_PROFILE_LIVE is false: (mmr, 0) and the closure is never evaluated
            prop_assert!(!VOL_PROFILE_LIVE);
            prop_assert_eq!(open_gate_floor(m, || panic!("read while OFF")), (m, 0));
            let _ = v;
        }

        #[test]
        fn prop_profile_monotone(a in any::<u64>(), b in any::<u64>()) {
            let (lo, hi) = (a.min(b), a.max(b));
            let (pl, ph) = (profile_for_sigma_bps(lo).unwrap(), profile_for_sigma_bps(hi).unwrap());
            prop_assert!(ph.band_bps >= pl.band_bps && ph.mmr_bps >= pl.mmr_bps && ph.imr_bps >= pl.imr_bps);
        }
    }
}
