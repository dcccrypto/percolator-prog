//! v2.2 decision 1 (night 2026-10-28, plan P3): the volatility-derived engine profile, plan v2 §3
//! PROFILE, as a PURE function. NOT WIRED: no handler calls it. InitMarket still validates the
//! creator's profile exactly as before. Wiring it is an owner decision (ledger
//! `v22-night-plans-2026-10-28.md` P3): for low-σ majors the derived MMR (260 bps at σ 2 %/day) is
//! below today's seed-kit 600 bps, i.e. a loosening.
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
}
