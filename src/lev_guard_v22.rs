//! v2.2 leverage build (2026-10-27, owner go "implement plan and commit and test thoroughly"):
//! pure rules for the LP stop (W1), the holder risk overlay, the move-freeze price band, the
//! new-token rules, the pre-W1 λ fallback and the minimum creator stake.
//!
//! Source of every rule: `~/percolator-ops/ledger/v22-leverage-algo-plan-v2-2026-10-25.md` §0a
//! (owner decisions D-a..D-l), §1 and §3, and `v22-leverage-sims-2026-10-25.md` §13 / §14. The
//! build plan and its log: `v22-levbuild-2026-10-27.md`.
//!
//! EVERY RULE HERE IS TIGHTEN-ONLY against the controller that exists today (`growth_v19`): a
//! leverage term is applied as `min(existing ceiling, term)` and a size term as
//! `min(existing N_cap, term)`, with the D-d floors (`L_floor`, `N_floor`) only ever lifting the
//! NEW term back towards the existing value, never above it. Nothing here runs on a reducing fill.
//!
//! Free of `AccountInfo` and syscalls, so every function is unit-tested on the host; Kani
//! harnesses for the tighten-only and order-independence properties are at the bottom.

/// Basis points.
pub const BPS: u128 = 10_000;

// ── time (slots; 400 ms per slot, the convention every growth constant already uses) ────────

pub const SLOTS_PER_HOUR: u64 = 9_000;
pub const SLOTS_PER_DAY: u64 = 216_000;
/// D-j: no opens before the token is 6 h old.
pub const AGE_NO_OPEN_SLOTS: u64 = 6 * SLOTS_PER_HOUR;
/// D-k: the 35 % dump default runs to 24 h.
pub const AGE_DAY_SLOTS: u64 = SLOTS_PER_DAY;
/// G1 / D-l: young-token rules (20 % dump default, β 0.1, m_ind 100 % for the rug case) to 7 d.
pub const AGE_WEEK_SLOTS: u64 = 7 * SLOTS_PER_DAY;
/// Sims §13 `m_tail`: 100 % under 30 d, 50 % after (no Pyth).
pub const AGE_MONTH_SLOTS: u64 = 30 * SLOTS_PER_DAY;

/// The age bands every new-token rule reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgeBand {
    /// `age < 6 h` (D-j): no opens at all, closes only.
    NoOpen,
    /// `6 h <= age < 24 h` (D-k): J_dump default 35 %.
    Day,
    /// `24 h <= age < 7 d` (G1): J_dump default 20 %; β 0.1 (D-l); m_ind 100 % for the rug (G4).
    Week,
    /// `7 d <= age < 30 d`: m_tail 100 %.
    Month,
    /// `age >= 30 d`: m_tail 50 %.
    Mature,
}

/// The token's age band. `t0_slot` is the guard's T0 (the earliest slot the program can vouch
/// for: the guard's creation, or an upgrade-authority backdate). A T0 in the future (clock or
/// data fault) reads age 0 and fails closed to `NoOpen`.
pub fn age_band(t0_slot: u64, now: u64) -> AgeBand {
    let age = now.saturating_sub(t0_slot);
    if now < t0_slot || age < AGE_NO_OPEN_SLOTS {
        AgeBand::NoOpen
    } else if age < AGE_DAY_SLOTS {
        AgeBand::Day
    } else if age < AGE_WEEK_SLOTS {
        AgeBand::Week
    } else if age < AGE_MONTH_SLOTS {
        AgeBand::Month
    } else {
        AgeBand::Mature
    }
}

impl AgeBand {
    /// Under 7 d (G1, G4, D-l).
    pub fn young(self) -> bool {
        self <= AgeBand::Week
    }
}

// ── holder risk report (D-d, decisions 11 / 20 / 21) ─────────────────────────────────────────

/// G2: a report is "fresh" for 3 h and is held (last value used) to 24 h.
pub const REPORT_FRESH_SLOTS: u64 = 3 * SLOTS_PER_HOUR;
pub const REPORT_HELD_SLOTS: u64 = SLOTS_PER_DAY;

/// D-k / G1 dump defaults (bps): 35 % at 6–24 h, 20 % at 1–7 d.
pub const J_DUMP_DEFAULT_DAY_BPS: u16 = 3_500;
pub const J_DUMP_DEFAULT_WEEK_BPS: u16 = 2_000;
/// G1: `m_ind` default 50 % for an unreported token under 7 d.
pub const M_IND_DEFAULT_YOUNG_BPS: u16 = 5_000;
/// G2: a token >= 7 d old whose report went stale (> 24 h): `J_dump >= 10 %`, `m_ind >= 25 %`.
pub const J_DUMP_STALE_OLD_BPS: u16 = 1_000;
pub const M_IND_STALE_OLD_BPS: u16 = 2_500;

/// What the risk key last wrote (stored in the guard). `slot == 0` = never reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RiskReport {
    /// Largest plausible holder dump as a price drop (bps, <= 10_000).
    pub j_dump_bps: u16,
    /// Insider / holder dump size used by the short-side cap (bps of price, <= 10_000).
    pub m_ind_bps: u16,
    /// A leverage cap (x100). 0 = no cap from the report.
    pub l_cap_x100: u16,
    /// A size multiplier on N_cap (bps, <= 10_000). 10_000 = none.
    pub n_mult_bps: u16,
    /// Authenticated slot of the write.
    pub slot: u64,
}

/// A report a risk key may store: every bps field within `[0, 10_000]`. (The tighten-only
/// property does not depend on this: the merge clamps anyway.)
pub fn report_ok(r: &RiskReport) -> bool {
    r.j_dump_bps <= 10_000 && r.m_ind_bps <= 10_000 && r.n_mult_bps <= 10_000
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportAge {
    None,
    Fresh,
    Held,
    Stale,
}

pub fn report_age(slot: u64, now: u64) -> ReportAge {
    if slot == 0 {
        return ReportAge::None;
    }
    if now < slot {
        // A future-stamped report cannot be trusted to be current: treat as stale (defaults,
        // which are themselves the floor of what any report can say).
        return ReportAge::Stale;
    }
    let a = now - slot;
    if a <= REPORT_FRESH_SLOTS {
        ReportAge::Fresh
    } else if a <= REPORT_HELD_SLOTS {
        ReportAge::Held
    } else {
        ReportAge::Stale
    }
}

/// Facts anyone can prove from chain accounts (D-d permissionless tighten path).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PermFacts {
    /// The pinned base mint still has a mint authority.
    pub mint_auth_live: bool,
    /// The pinned base mint still has a freeze authority.
    pub freeze_auth_live: bool,
    /// The worst proven single-holder dump (CPMM price drop, bps) and the slot it was proven.
    pub holder_dump_bps: u16,
    pub holder_dump_slot: u64,
}

/// A permissionless holder proof counts for 24 h (the holder may move the tokens afterwards; a
/// new proof can be submitted any time).
pub const HOLDER_PROOF_SLOTS: u64 = SLOTS_PER_DAY;

/// The merged overlay the gate applies. Each field is the TIGHTEST of the on-chain default and
/// every live input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overlay {
    pub j_dump_bps: u16,
    pub m_ind_bps: u16,
    /// Leverage cap (x100); `u16::MAX` = none. The D-d floor is applied later (`l_overlay_x100`).
    pub l_cap_x100: u16,
    /// Size multiplier (bps, <= 10_000). The D-d floor is applied later (`n_overlay_q`).
    pub n_mult_bps: u16,
}

fn max16(a: u16, b: u16) -> u16 {
    if a > b { a } else { b }
}
fn min16(a: u16, b: u16) -> u16 {
    if a < b { a } else { b }
}
fn cap_bps(x: u16) -> u16 {
    min16(x, 10_000)
}

/// The on-chain default (plan v2 "B" = T0 + T1 + the age default, G1 / G2 / G3 / D-k): what a
/// market reads with no report at all. A report can only RAISE `j_dump` / `m_ind` above it and
/// LOWER `l_cap` / `n_mult` below it (N15).
pub fn default_overlay(band: AgeBand, rep: ReportAge) -> Overlay {
    let (j, m) = match band {
        AgeBand::NoOpen | AgeBand::Day => (J_DUMP_DEFAULT_DAY_BPS, M_IND_DEFAULT_YOUNG_BPS),
        AgeBand::Week => (J_DUMP_DEFAULT_WEEK_BPS, M_IND_DEFAULT_YOUNG_BPS),
        AgeBand::Month | AgeBand::Mature => match rep {
            // G2 / G3: a report that went stale leaves a moderate floor on an older token.
            ReportAge::Stale => (J_DUMP_STALE_OLD_BPS, M_IND_STALE_OLD_BPS),
            _ => (0, 0),
        },
    };
    Overlay { j_dump_bps: j, m_ind_bps: m, l_cap_x100: u16::MAX, n_mult_bps: 10_000 }
}

/// The merged overlay (D-d): `default` ⊓ `report (if fresh or held)` ⊓ `permissionless facts`.
/// Tighten-only by construction: every field is a max (j, m) or a min (l, n) with the default.
pub fn merge_overlay(band: AgeBand, report: &RiskReport, perm: &PermFacts, now: u64) -> Overlay {
    let rep = report_age(report.slot, now);
    let mut o = default_overlay(band, rep);
    if matches!(rep, ReportAge::Fresh | ReportAge::Held) {
        o.j_dump_bps = max16(o.j_dump_bps, cap_bps(report.j_dump_bps));
        o.m_ind_bps = max16(o.m_ind_bps, cap_bps(report.m_ind_bps));
        if report.l_cap_x100 != 0 {
            o.l_cap_x100 = min16(o.l_cap_x100, report.l_cap_x100);
        }
        o.n_mult_bps = min16(o.n_mult_bps, cap_bps(report.n_mult_bps));
    }
    if perm.holder_dump_slot != 0
        && now >= perm.holder_dump_slot
        && now - perm.holder_dump_slot <= HOLDER_PROOF_SLOTS
    {
        let d = cap_bps(perm.holder_dump_bps);
        o.j_dump_bps = max16(o.j_dump_bps, d);
        o.m_ind_bps = max16(o.m_ind_bps, d);
    }
    if perm.mint_auth_live || perm.freeze_auth_live {
        // Decisions 12 / 13 (sims: "should not get a market at all"), bounded by the D-d
        // floors: leverage to L_floor (a cap of 1 is lifted to the floor later) and size to
        // N_floor (a multiplier of 0 is lifted to the floor later).
        o.l_cap_x100 = 1;
        o.n_mult_bps = 0;
    }
    o
}

/// D-d floor on leverage: `L_floor = min(2x, L_eng)` (x100).
pub const L_FLOOR_X100: u16 = 200;
pub fn l_floor_x100(l_eng_x100: u16) -> u16 {
    min16(L_FLOOR_X100, l_eng_x100)
}

// ── trader leverage with the dump term (plan v2 §3 LEVERAGE) ─────────────────────────────────

/// z = 2.33 over 1 h (decision 2), as a ratio 233 / 100.
pub const Z_NUM: u64 = 233;
pub const Z_DEN: u64 = 100;
/// φ_open: the opening cost in the cushion (levmodel `PHI_OPEN` = 0.30 %).
pub const PHI_OPEN_BPS: u64 = 30;

/// `L_trader = 1 / (MMR + φ_open + sqrt((z·σ_1h)² + J²))`, x100, floored (tighter). `sigma_1h_bps`
/// `None` (no volatility data) reads 0 here: the existing controller already pins a market with
/// no data at launch, and this term is a `min` on top of it.
pub fn l_trader_x100(mmr_bps: u64, sigma_1h_bps: Option<u64>, jump_bps: u16) -> u16 {
    let zs = sigma_1h_bps.unwrap_or(0).saturating_mul(Z_NUM).div_ceil(Z_DEN) as u128;
    let j = jump_bps as u128;
    let cushion = crate::growth_v19::isqrt_ceil_u128(zs.saturating_mul(zs).saturating_add(j * j));
    let den = (mmr_bps as u128).saturating_add(PHI_OPEN_BPS as u128).saturating_add(cushion);
    if den == 0 {
        return u16::MAX;
    }
    let l = 1_000_000u128 / den;
    if l > u16::MAX as u128 { u16::MAX } else { l as u16 }
}

/// Decision 25 / G8: after a breaker trip, `m_oracle = 0.75` on leverage for 24 h.
pub const M_ORACLE_NUM: u32 = 3;
pub const M_ORACLE_DEN: u32 = 4;

/// The leverage ceiling in force with the overlay (x100):
/// `min(existing, max(L_floor, min(L_trader, l_cap)·m_oracle, [frozen])))`. NEVER above
/// `existing` (tighten-only); the floor only lifts the NEW term.
pub fn l_overlay_x100(
    existing_x100: u16,
    l_trader_x100: u16,
    l_cap_x100: u16,
    m_oracle: bool,
    frozen_x100: Option<u16>,
    l_eng_x100: u16,
) -> u16 {
    let mut t = min16(l_trader_x100, l_cap_x100);
    if m_oracle {
        t = ((t as u32) * M_ORACLE_NUM / M_ORACLE_DEN) as u16;
    }
    if let Some(f) = frozen_x100 {
        t = min16(t, f);
    }
    let t = max16(l_floor_x100(l_eng_x100), t);
    min16(existing_x100, t)
}

// ── size: age rule, report multiplier, N_floor (D-d, D-j) ────────────────────────────────────

/// D-d `N_floor` in collateral notional: $200 (whole tokens of the $1 collateral, scaled by the
/// collateral decimals at the call site).
pub const N_FLOOR_USD: u64 = 200;

/// The capacity in force with the overlay (Q): `0` under 6 h (D-j, overrides the floor), else
/// `min(n_cap, max(n_cap·n_mult, min(n_cap, n_floor)), [frozen])`. Never above `n_cap`.
pub fn n_overlay_q(n_cap_q: u128, band: AgeBand, n_mult_bps: u16, n_floor_q: u128, frozen_q: Option<u128>) -> u128 {
    if band == AgeBand::NoOpen {
        return 0;
    }
    let scaled = n_cap_q / BPS * (cap_bps(n_mult_bps) as u128)
        + (n_cap_q % BPS) * (cap_bps(n_mult_bps) as u128) / BPS;
    let floor = if n_floor_q < n_cap_q { n_floor_q } else { n_cap_q };
    let mut v = if scaled > floor { scaled } else { floor };
    if let Some(f) = frozen_q {
        // A freeze never lifts the floor above itself and never raises: min with the snapshot.
        if f < v {
            v = f;
        }
    }
    if v > n_cap_q { n_cap_q } else { v }
}

// ── short side: the corrected dump cap (sims §13, D-l, G4) ───────────────────────────────────

/// β (bps): 0.1 under 7 d (D-l), 0.5 after.
pub const BETA_YOUNG_BPS: u16 = 1_000;
pub const BETA_BPS: u16 = 5_000;
pub fn beta_bps(band: AgeBand) -> u16 {
    if band.young() { BETA_YOUNG_BPS } else { BETA_BPS }
}

/// `m_tail` (bps): 100 % under 30 d, 50 % older (no Pyth confirmation exists in v2.2).
pub fn m_tail_bps(band: AgeBand) -> u16 {
    if band < AgeBand::Mature { 10_000 } else { 5_000 }
}

/// The dump size the short cap uses: `max(m_ind_rug, 1 %, m_tail)` with `m_ind_rug = 100 %`
/// under 7 d (G4: a rug is a 100 % dump).
pub fn m_dump_bps(band: AgeBand, m_ind_bps: u16) -> u16 {
    let rug = if band.young() { 10_000 } else { cap_bps(m_ind_bps) };
    max16(max16(rug, 100), m_tail_bps(band))
}

/// The users' short notional allowed (collateral atoms):
/// `long_users · min(1, MMR/m) + β·C_m/m` (sims §13 decision 15, β per D-l).
pub fn short_users_cap_notional(long_users_notional: u128, c_m: u128, mmr_bps: u64, band: AgeBand, m_ind_bps: u16) -> u128 {
    let m = m_dump_bps(band, m_ind_bps) as u128; // >= 100, never 0
    let off_bps = core::cmp::min(BPS, (mmr_bps as u128).saturating_mul(BPS) / m);
    let offset = mul_div_floor_sat(long_users_notional, off_bps, BPS);
    let dump = mul_div_floor_sat(c_m, beta_bps(band) as u128, m);
    offset.saturating_add(dump)
}

// ── burst memory (decision 28, sims MC-2b; night 2026-10-28 P2) ───────────────────────────────

/// `σ_eff ≥ k·σ_peak` with k = 0.5, i.e. on the variance `var_eff ≥ var_peak / 4`.
pub const BURST_VAR_FLOOR_DIV: u32 = 4;
/// The peak's half-life: 7 days (plan §13; the H8 fix of the sim).
pub const BURST_HALF_LIFE_SLOTS: u64 = 7 * SLOTS_PER_DAY;

/// The stored peak decayed over `elapsed` slots: halved per whole half-life, then LINEAR inside the
/// current half-life (`p·(1 − f/2)`, f ∈ [0, 1)), which is never below the exact `p·2^(−f)`: it decays no
/// faster than the sim's exponential (tighter, never looser).
pub fn burst_decay(peak: u32, elapsed: u64) -> u32 {
    let halvings = elapsed / BURST_HALF_LIFE_SLOTS;
    if halvings >= 32 {
        return 0;
    }
    let p = (peak >> halvings) as u64;
    let rem = elapsed % BURST_HALF_LIFE_SLOTS;
    // p - p·rem/(2·HL), rounded so the result stays >= the exact value (subtract the floor).
    let cut = p.saturating_mul(rem) / (2 * BURST_HALF_LIFE_SLOTS);
    (p - cut) as u32
}

/// Fold the current variance into the memory. A new high (>= the decayed peak) restarts the clock;
/// otherwise the stored peak and slot are kept (decay is read from the original high, so repeated
/// samples never compound the linear segments). A slot behind the peak's (clock fault) reads elapsed 0.
pub fn burst_update(peak: u32, peak_slot: u64, var_now: u32, now: u64) -> (u32, u64) {
    let eff = burst_decay(peak, now.saturating_sub(peak_slot));
    if var_now >= eff {
        (var_now, now)
    } else {
        (peak, peak_slot)
    }
}

/// The variance the leverage term uses: `max(var_now, decayed_peak / 4)`. Tighten-only (>= var_now).
pub fn burst_var_eff(peak: u32, peak_slot: u64, var_now: u32, now: u64) -> u32 {
    let floor = burst_decay(peak, now.saturating_sub(peak_slot)) / BURST_VAR_FLOOR_DIV;
    if floor > var_now { floor } else { var_now }
}

// ── price band: the on-chain mirror of the keeper breaker (decision 25, G8) ──────────────────

/// Keeper breaker thresholds: 10 % between consecutive samples, 30 % against the 1-h reference.
pub const BREAKER_SAMPLE_BPS: u64 = 1_000;
pub const BREAKER_HOUR_BPS: u64 = 3_000;
/// 10-24 §A.4.5 abnormal move: `|move vs 1 h| > 4·σ_24h/√24 = 4·σ_1h` -> move-freeze only.
pub const ABNORMAL_SIGMA_MULT: u64 = 4;
pub const FREEZE_SLOTS: u64 = SLOTS_PER_HOUR;
pub const M_ORACLE_SLOTS: u64 = SLOTS_PER_DAY;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PriceBand {
    pub last_px_e6: u64,
    pub last_slot: u64,
    pub ref_px_e6: u64,
    pub ref_slot: u64,
    /// Upward movement of L / N_cap frozen while `now < freeze_until`.
    pub freeze_until: u64,
    /// `m_oracle = 0.75` while `now < oracle_until`.
    pub oracle_until: u64,
}

/// `|a - b| / b` in bps, rounded up; `b == 0` reads as a full move.
pub fn move_bps(a: u64, b: u64) -> u64 {
    if b == 0 {
        return u64::MAX;
    }
    let d = (a as u128).abs_diff(b as u128);
    let m = (d * BPS).div_ceil(b as u128);
    if m > u64::MAX as u128 { u64::MAX } else { m as u64 }
}

/// What one price observation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trip {
    None,
    /// Abnormal move (σ test): freeze only.
    Freeze,
    /// Breaker threshold: freeze and m_oracle.
    Breaker,
}

/// Observe the authenticated mark `px` at `now`. The 1-h reference rolls forward once it is an
/// hour old. A zero price is ignored (no information). `sigma_1h_bps = None`: no σ test.
pub fn observe_price(b: &PriceBand, px: u64, now: u64, sigma_1h_bps: Option<u64>) -> (PriceBand, Trip) {
    let mut n = *b;
    if px == 0 {
        return (n, Trip::None);
    }
    if n.last_px_e6 == 0 || n.ref_px_e6 == 0 {
        n.last_px_e6 = px;
        n.last_slot = now;
        n.ref_px_e6 = px;
        n.ref_slot = now;
        return (n, Trip::None);
    }
    let sample = move_bps(px, n.last_px_e6);
    let hour = move_bps(px, n.ref_px_e6);
    let mut trip = Trip::None;
    if sample > BREAKER_SAMPLE_BPS || hour > BREAKER_HOUR_BPS {
        trip = Trip::Breaker;
    } else if let Some(s) = sigma_1h_bps {
        if s > 0 && hour > s.saturating_mul(ABNORMAL_SIGMA_MULT) {
            trip = Trip::Freeze;
        }
    }
    match trip {
        Trip::Breaker => {
            n.freeze_until = core::cmp::max(n.freeze_until, now.saturating_add(FREEZE_SLOTS));
            n.oracle_until = core::cmp::max(n.oracle_until, now.saturating_add(M_ORACLE_SLOTS));
        }
        Trip::Freeze => {
            n.freeze_until = core::cmp::max(n.freeze_until, now.saturating_add(FREEZE_SLOTS));
        }
        Trip::None => {}
    }
    n.last_px_e6 = px;
    n.last_slot = now;
    if now.saturating_sub(n.ref_slot) >= SLOTS_PER_HOUR {
        n.ref_px_e6 = px;
        n.ref_slot = now;
    }
    (n, trip)
}

pub fn frozen(b: &PriceBand, now: u64) -> bool {
    now < b.freeze_until
}
pub fn m_oracle_on(b: &PriceBand, now: u64) -> bool {
    now < b.oracle_until
}

// ── the LP stop (W1): NAV per share, trailing peak, reference (D-b, D-c, D-i) ────────────────

/// NAV per share scale: 1.0 = 1e12.
pub const NAV_ONE: u128 = 1_000_000_000_000;

/// The flow-adjusted NAV-per-share index of the vault LP. A deposit or a withdrawal changes the
/// equity AND the flow counters by the same amount, so it moves neither the index nor the peak
/// (D-b: "a deposit followed by a withdrawal must not be able to trip the stop").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NavState {
    pub navps: u128,
    pub last_equity: u128,
    pub last_in: u128,
    pub last_out: u128,
    /// The current 24-h bucket's peak and the previous bucket's peak: the peak used is
    /// `max(cur, prev)`, the maximum over the last 24–48 h (never below the true trailing 24-h
    /// peak, so the stop can only fire as early or earlier).
    pub peak_cur: u128,
    pub peak_prev: u128,
    pub bucket_start: u64,
    /// D-i: NAV/share at the last stop reset or epoch start.
    pub ref_navps: u128,
    pub last_slot: u64,
}

impl NavState {
    pub fn initialised(&self) -> bool {
        self.navps != 0 || self.ref_navps != 0
    }
    pub fn peak(&self) -> u128 {
        if self.peak_cur > self.peak_prev { self.peak_cur } else { self.peak_prev }
    }
}

/// Start (or restart) an epoch at NAV/share 1.0 with the current equity and flow counters.
pub fn nav_epoch_start(equity: u128, flow_in: u128, flow_out: u128, now: u64) -> NavState {
    NavState {
        navps: NAV_ONE,
        last_equity: equity,
        last_in: flow_in,
        last_out: flow_out,
        peak_cur: NAV_ONE,
        peak_prev: NAV_ONE,
        bucket_start: now,
        ref_navps: NAV_ONE,
        last_slot: now,
    }
}

/// One sample. `equity` is the vault LP's conservative equity now; `flow_in` / `flow_out` the
/// MONOTONIC cumulative atoms moved into / out of the LP by deposits, allocations, draws (in)
/// and withdrawals, recalls (out). Pure flows never move the index.
///
/// The program cannot see WHEN in the interval a flow landed, so a P&L in the same interval has
/// two readings: flows at the END (`econ = equity − Δin + Δout`, `navps' = navps·econ/last`) or at
/// the START (`navps' = navps·equity/(last + Δin − Δout)`). The index takes the HIGHER one
/// (night audit 2026-10-28, F1): D-b requires that flows can never trip the stop, and the
/// end-only reading let a routine inflow (an Earn allocation, a creator top-up) followed by a
/// small loss read as a loss of the PRE-flow equity (a 6 % loss after a 9× allocation read as
/// 60 %), firing W1 against healthy users. For a pure outflow the end reading is already the
/// higher one, so withdrawals behave as before. Residual: a loss in the same interval as an
/// inflow is measured against the larger base (bounded masking; exact needs a sample at the flow).
///
/// GH#627 root cause: "the higher reading wins" also picks the SMALLER base for a gain, and a
/// base is not bounded below by anything real -- earn `P`, withdraw all but one atom, sample, and
/// the gain read as `P / 1 atom` (×1e6 per $1, `u128::MAX` in five cycles; a deposit-earn-withdraw
/// round trip does the same from a dust `last`). The P&L itself is exact,
/// `P = equity + Δout − Δin − last`; only which capital earned it is unknown, and that capital
/// was at most `last + Δin` (every inflow there from the start, every outflow leaving at the
/// end). So the reading is CAPPED at the gross reading `navps·(equity + Δout)/(last + Δin)`:
///   - a pure flow (`P = 0`) gives `num == den`, the index does not move (D-b unchanged);
///   - a loss (`P < 0`) reads F1 exactly: the gross reading is the mildest one, so the cap never
///     binds, and F1 stays NET-based, so a deposit-withdraw round trip cannot dilute a loss;
///   - a gain (`P > 0`) can never lift the index more than `P` earned on the most capital that
///     could have earned it, which is at most what the same `P` does with no flow at all
///     (`(last + P)/last`). No ordering or splitting of flows can amplify a gain, and a near-zero
///     base can no longer turn a small profit into a huge index gain (and so hide a real stop
///     behind the D-i reference).
/// No constant is involved: the bound is the interval's own data. Plain intervals (no flow) are
/// unchanged; only a gain in the same interval as a flow reads lower than under F1 alone -- and
/// the keeper / app poke before a flow (D16) makes those intervals exact anyway.
///
/// Epoch restart (fresh 1.0): no previous equity (first capital), or the index reached 0 (the
/// LP was wiped; D-i "epoch start"), or a counter went backwards (data fault: fail to a clean
/// epoch rather than invent a loss).
pub fn nav_sample(st: &NavState, equity: u128, flow_in: u128, flow_out: u128, now: u64) -> NavState {
    if !st.initialised() || st.last_equity == 0 || st.navps == 0 || flow_in < st.last_in || flow_out < st.last_out {
        return nav_epoch_start(equity, flow_in, flow_out, now);
    }
    let din = flow_in - st.last_in;
    let dout = flow_out - st.last_out;
    // End reading: econ = equity - din + dout, clamped at 0 (a loss beyond everything reads as 0).
    let econ = equity.saturating_add(dout).saturating_sub(din);
    let mut navps = nav_scale(st.navps, econ, st.last_equity);
    if din != 0 || dout != 0 {
        // Start reading (F1): the flows joined the base before the P&L. The higher reading wins.
        let base = st.last_equity.saturating_add(din).saturating_sub(dout);
        if base != 0 {
            let start = nav_scale(st.navps, equity, base);
            if start > navps {
                navps = start;
            }
        }
        // GH#627: never above the gross reading (see above). The sums are atom counts and cannot
        // reach 2^128; saturating only keeps the function total.
        let gross = nav_scale(st.navps, equity.saturating_add(dout), st.last_equity.saturating_add(din));
        if navps > gross {
            navps = gross;
        }
    }
    let mut n = *st;
    n.navps = navps;
    n.last_equity = equity;
    n.last_in = flow_in;
    n.last_out = flow_out;
    n.last_slot = now;
    let since = now.saturating_sub(n.bucket_start);
    if since >= 2 * SLOTS_PER_DAY {
        // Both buckets are older than the window: the peak restarts at the current value.
        n.peak_prev = navps;
        n.peak_cur = navps;
        n.bucket_start = now;
    } else if since >= SLOTS_PER_DAY {
        n.peak_prev = n.peak_cur;
        n.peak_cur = navps;
        n.bucket_start = now;
    }
    if navps > n.peak_cur {
        n.peak_cur = navps;
    }
    n
}

/// `navps · num / den` (floored), exactly `navps` when `num == den` (a pure flow, or no P&L): no
/// division on that path, so `mul_div_floor_sat`'s saturation for astronomically large inputs can
/// never move the index on a flow, and the flow-neutrality proof (`kani_lev_nav_flow_neutral`)
/// needs no 128-bit division (task 4, night 2026-10-28).
pub fn nav_scale(navps: u128, num: u128, den: u128) -> u128 {
    if num == den {
        navps
    } else {
        mul_div_floor_sat(navps, num, den)
    }
}

/// D-b + D-i: the stop fires at NAV/share <= 50 % of the trailing peak OR <= 50 % of the
/// reference. An uninitialised state never fires.
pub fn lp_stop_triggered(st: &NavState) -> bool {
    if !st.initialised() {
        return false;
    }
    // GH#627: compare by division, never by doubling. `navps.saturating_mul(2)` pinned to
    // `u128::MAX` once the index saturated, and `peak() >= navps` was `u128::MAX` too, so the test
    // read `MAX <= MAX` -- the stop latched on with NO drawdown, and `nav_stop_reset` could not
    // clear it because it restarts the reference and both peaks AT the current index.
    // Exactly equivalent for every value: for integers `navps * 2 <= p` iff `navps <= p / 2`.
    st.navps <= st.peak() / 2 || st.navps <= st.ref_navps / 2
}

/// After a completed stop round: the reference and both peaks restart at the current NAV/share
/// (D-i "NAV/share at the last LP-stop reset"), so the next stop needs a fresh 50 % fall.
pub fn nav_stop_reset(st: &NavState) -> NavState {
    let mut n = *st;
    n.ref_navps = st.navps;
    n.peak_cur = st.navps;
    n.peak_prev = st.navps;
    n
}

/// W1 keep-fraction (bps): `k = floor(target / |LP net| · 1e4)`; `10_000` when the LP is already
/// within target (nothing to do). Rounded DOWN: the cut is never smaller than exact.
pub fn w1_keep_bps(lp_net_abs_q: u128, target_q: u128) -> u16 {
    if lp_net_abs_q == 0 || lp_net_abs_q <= target_q {
        return 10_000;
    }
    (mul_div_floor_sat(target_q, BPS, lp_net_abs_q)) as u16
}

/// W1 keep-fraction from the AGGREGATE book (bps): the users opposite the LP hold `users_opp_q`;
/// the LP's excess over target is `E = |LP net| - target`; cutting every opposing account to
/// `k = (U - E) / U` removes exactly `E` (rounded so the cut is never smaller), so the LP reaches
/// the target only once EVERY opposing account has been cut (up to per-account rounding): the
/// round cannot close early on whichever accounts a caller listed first (rule 27).
/// `10_000` when the LP is within target; `0` when the excess is at least the whole opposing book.
pub fn w1_keep_bps_users(users_opp_q: u128, lp_net_abs_q: u128, target_q: u128) -> u16 {
    if lp_net_abs_q <= target_q {
        return 10_000;
    }
    let excess = lp_net_abs_q - target_q;
    if users_opp_q == 0 || excess >= users_opp_q {
        return 0;
    }
    mul_div_floor_sat(users_opp_q - excess, BPS, users_opp_q) as u16
}

/// The position an opposing account keeps under keep-fraction `k`: `floor(|pos|·k/1e4)`, or 0 when
/// the remainder would be below `min_leg_q` (a band leg below the minimum cannot stand; the whole
/// leg goes). Never above `|pos|`.
pub fn w1_keep_q(pos_abs_q: u128, keep_bps: u16, min_leg_q: u128) -> u128 {
    let k = cap_bps(keep_bps) as u128;
    let keep = pos_abs_q / BPS * k + (pos_abs_q % BPS) * k / BPS;
    if keep < min_leg_q { 0 } else { keep }
}

/// What to cut from ONE opposing leg: the pro-rata reduction, but never more than the round's
/// outstanding excess, and never leaving a leg below `min_leg_q`.
///
/// `w1_keep_q` returning 0 means the pro-rata remainder cannot stand as a band leg (it is below the
/// market minimum, or `keep_bps` is 0), so that leg is all-or-nothing. It is only taken in full when
/// the round still needs that much: a leg that cannot be cut without overshooting is left alone
/// rather than destroyed. Without that budget the per-leg minimum silently overrides the aggregate
/// rule and the round removes up to `1/(1-k)` times the excess (#612).
///
/// Invariants, for every input: `cut <= pos_abs_q`; the remainder `pos_abs_q - cut` is either 0 or
/// at least `min_leg_q`; and a WHOLE-leg cut never exceeds `remaining_q`.
pub fn w1_cut_q(pos_abs_q: u128, keep_bps: u16, min_leg_q: u128, remaining_q: u128) -> u128 {
    if pos_abs_q == 0 {
        return 0;
    }
    let keep = w1_keep_q(pos_abs_q, keep_bps, min_leg_q);
    if keep == 0 {
        // All or nothing: a partial cut would leave a standing leg below the market minimum. Take
        // the whole leg only while the round still needs that much. This is the budget that was
        // missing, and the only place it binds.
        return if pos_abs_q <= remaining_q { pos_abs_q } else { 0 };
    }
    // The pro-rata cut is deliberately NOT clamped. Flooring already makes the pro-rata total
    // exceed the excess by up to one lot per leg, and clamping it would make an account's own
    // outcome depend on where it sat in the caller's list -- the order and grouping independence a
    // round is specified to have, pinned by
    // `lev_w1_lp_stop_round_cuts_opposing_users_once_and_order_independent`.
    pos_abs_q - keep
}

/// D11 (#612 defect 4): is the LP's leftover excess over the round's target smaller than one
/// minimum leg? Every live leg is at or above `min_leg_q` (a fill that would leave less is refused,
/// error 113), and `w1_cut_q` takes a whole leg only while `pos <= remaining`. So once the excess
/// is below `min_leg_q` no whole-leg cut can ever be admitted again and the round cannot converge;
/// it would only be replaced every `W1_ROUND_SLOTS` and re-open, with F3 blocking crowd-side opens
/// meanwhile. The LP is then as close to target as the market's own granularity allows, and the
/// round (or an opening that would start one) is treated as within target.
pub fn w1_leftover_below_leg(lp_abs_q: u128, target_q: u128, min_leg_q: u128) -> bool {
    lp_abs_q.saturating_sub(target_q) < min_leg_q
}

/// The LP-side target `λ_eff · C_m_now` in Q (`growth_v19::n_cap_q`).
pub fn w1_target_q(c_m: u128, lambda_eff_bps: u32, price_e6: u64, pos_scale: u128) -> u128 {
    crate::growth_v19::n_cap_q(c_m, lambda_eff_bps, price_e6, pos_scale).unwrap_or(0)
}

/// The per-round touched set: `KEY_TAG_LEN`-byte key prefixes, one per opposing account already
/// reduced in this round. An account is reduced at most once per round, so the keep-fraction
/// applies once to each account whatever the order of the calls (rule 27 / v16.9.1 K/F order: the
/// outcome per account does not depend on which other accounts a caller lists, or in what order).
///
/// The prefix is the account's IDENTITY in that set, so its width is a security parameter, not a
/// space optimisation: two distinct portfolios sharing a prefix are ONE entry, and the second is
/// skipped by `lev_guard_lp_stop` as already cut. Portfolio addresses are client-chosen
/// (`handle_init_portfolio` takes any program-owned account of the right length), so an attacker
/// picks both halves of such a pair in advance -- a BIRTHDAY search over addresses they control,
/// not a targeted preimage against a victim. At 8 bytes that is ~2^32 candidates, which
/// `createAccountWithSeed` reduces to ~2^32 SHA-256 hashes; at 16 it is ~2^64 and infeasible.
///
/// Halving the cap keeps `LEV_GUARD_TOUCHED_LEN` (and therefore the account length and its rent)
/// bit-for-bit unchanged, so no guard has to be migrated and no client length check moves. 256
/// accounts per round is well above the keeper's own default throughput, and a round with more
/// opposing accounts than the cap is already handled by the F4 one-hour stale-round replacement
/// below.
pub const KEY_TAG_LEN: usize = 16;
pub const W1_TOUCHED_CAP: usize = 256;
pub fn key_tag(key: &[u8; 32]) -> [u8; KEY_TAG_LEN] {
    let mut t = [0u8; KEY_TAG_LEN];
    t.copy_from_slice(&key[..KEY_TAG_LEN]);
    t
}
/// Night audit 2026-10-28 (F4): a W1 round lives at most one hour. While live it blocks every
/// fill that grows the LP's net (F3); once stale the next W1 call closes it and, if the stop
/// still holds, opens a fresh round with `k` from the book as it is then (so more than
/// `W1_TOUCHED_CAP` opposing accounts, or an account the keeper never reached, cannot wedge the
/// market: liveness).
pub const W1_ROUND_SLOTS: u64 = SLOTS_PER_HOUR;
pub fn w1_round_live(round_active: u8, round_open_slot: u64, now: u64) -> bool {
    round_active == 1 && now.saturating_sub(round_open_slot) <= W1_ROUND_SLOTS
}
pub fn touched_contains(set: &[[u8; KEY_TAG_LEN]], n: usize, tag: &[u8; KEY_TAG_LEN]) -> bool {
    set.iter().take(n).any(|t| t == tag)
}

// ── the λ fallback until W1 ships (D-c step 1, D-h) ──────────────────────────────────────────

/// D-h: `λ <= 1.0` while only the 72-h fallback is live. Flip ONLY with a separate owner go once
/// W1 has run end to end (D-c step 2: then the horizon returns to 24 h and this cap is removed).
pub const W1_LIVE: bool = false;
pub const LAMBDA_CAP_PRE_W1_BPS: u32 = 10_000;
/// The λ_vol horizon: 72 h before W1, 24 h after.
pub const LAMBDA_VOL_HORIZON_SLOTS: u64 = if W1_LIVE { SLOTS_PER_DAY } else { 3 * SLOTS_PER_DAY };

/// `λ_vol = 0.95 / (2·σ_H)` in bps: `floor(0.95e4 · 1e4 / (2·σ_bps)) = floor(47_500_000 / σ_bps)`.
/// `σ == 0` -> no cap.
pub fn lambda_vol_bps(sigma_h_bps: u64) -> u32 {
    if sigma_h_bps == 0 {
        return u32::MAX;
    }
    let v = 47_500_000u64 / sigma_h_bps;
    if v > u32::MAX as u64 { u32::MAX } else { v as u32 }
}

/// `min(λ_eff, [1.0 before W1], λ_vol(σ over the horizon))`. Tighten-only.
pub fn lambda_fallback_bps(lambda_eff_bps: u32, sigma_h_bps: u64) -> u32 {
    let mut l = lambda_eff_bps;
    if !W1_LIVE && LAMBDA_CAP_PRE_W1_BPS < l {
        l = LAMBDA_CAP_PRE_W1_BPS;
    }
    let v = lambda_vol_bps(sigma_h_bps);
    if v < l { v } else { l }
}

// ── the minimum creator stake (decision 7) ───────────────────────────────────────────────────

/// $500 of the $1 collateral.
pub const MIN_CREATOR_STAKE_USD: u64 = 500;

/// `500 · 10^decimals` atoms. `None` above 30 decimals (never a real mint).
pub fn min_creator_stake_atoms(decimals: u8) -> Option<u128> {
    if decimals > 30 {
        return None;
    }
    (MIN_CREATOR_STAKE_USD as u128).checked_mul(10u128.checked_pow(decimals as u32)?)
}

/// The junior's net contribution (deposited − withdrawn, saturating).
pub fn junior_net(deposited: u128, withdrawn: u128) -> u128 {
    deposited.saturating_sub(withdrawn)
}

/// A junior position is acceptable iff it is 0 (no stake, nothing live) or at least the minimum.
pub fn junior_stake_ok(net_after: u128, min_atoms: u128) -> bool {
    net_after == 0 || net_after >= min_atoms
}

/// D1: the junior's VALUE after a withdrawal of `amount`: the junior layer of the three-way
/// waterfall (`tranche_split3`) on the vault value left. Tag 97 tests THIS against the creator
/// minimum (not net deposits): after any loss net deposits can never reach 0, which locked the
/// whole stake. Value 0 (a full exit) or value >= the minimum is allowed (`junior_stake_ok`); the
/// junior floor (`junior_withdraw_allowed3`) is a separate gate and still binds.
pub fn junior_value_after_withdraw(vault_value: u128, amount: u128, senior_claim_eff: u128, bond_claim: u128) -> u128 {
    crate::bond_v20::tranche_split3(vault_value.saturating_sub(amount), senior_claim_eff, bond_claim).junior
}

/// D1: tag 103 allocates senior (Earn) capital only while the junior's current VALUE is at least
/// the creator minimum.
pub fn junior_value_allows_allocation(vault_value: u128, senior_claim_eff: u128, bond_claim: u128, min_atoms: u128) -> bool {
    crate::bond_v20::tranche_split3(vault_value, senior_claim_eff, bond_claim).junior >= min_atoms
}

// ── the permissionless holder proof ──────────────────────────────────────────────────────────

/// The CPMM price drop when a holder sells `q` base tokens into a pool holding `r` base tokens:
/// `1 − (R/(R+q))²`, bps, rounded UP (the ratio is floored before squaring). `r == 0` = 100 %.
pub fn cpmm_dump_bps(r: u64, q: u64) -> u16 {
    if q == 0 {
        return 0;
    }
    if r == 0 {
        return 10_000;
    }
    let den = r as u128 + q as u128;
    let ratio = (r as u128) * 1_000_000_000 / den; // floor, <= 1e9
    let kept_bps = ratio * ratio / 100_000_000_000_000; // floor(ratio² · 1e4 / 1e18)
    (BPS - kept_bps) as u16
}

// ── the guard record: `["lev_guard", market]`, header kind 17, body at `HEADER_LEN` ───────────

pub const LEV_GUARD_SEED: &[u8] = b"lev_guard";
pub const LEV_GUARD_VERSION: u8 = 1;
/// `flags` bit 0 / 1: the pinned base mint was last proven to have a live mint / freeze authority.
pub const GUARD_FLAG_MINT_AUTH: u8 = 1 << 0;
pub const GUARD_FLAG_FREEZE_AUTH: u8 = 1 << 1;
/// D12 / GH#614 bit 2 (`0x04`): op 3 has read the pinned base mint's authorities at least once.
/// Bits 0/1 alone cannot tell "proven clean" from "never looked". A record written before this bit
/// existed reads 0 = never proven, which is the tight answer. The record layout is unchanged: this
/// is a previously spare flag bit (`validate_guard` used to refuse it).
pub const GUARD_FLAG_PERM_PROVEN: u8 = 1 << 2;
pub const GUARD_FLAGS_KNOWN: u8 =
    GUARD_FLAG_MINT_AUTH | GUARD_FLAG_FREEZE_AUTH | GUARD_FLAG_PERM_PROVEN;

/// Tag 124 ops.
pub const OP_INIT: u8 = 0;
pub const OP_SET_RISK_KEY: u8 = 1;
pub const OP_REPORT: u8 = 2;
pub const OP_TIGHTEN: u8 = 3;
pub const OP_POKE: u8 = 4;
pub const OP_LP_STOP: u8 = 5;
pub const OP_SET_T0: u8 = 6;

fn u128_of(b: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*b)
}

/// One record per market. u128 fields are LE byte arrays (Pod, no implicit padding).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LevGuardV22 {
    pub market: [u8; 32],   // 0..32
    /// The holder risk key (D-d, decision 20). Zero = none (reports refused). Upgrade authority.
    pub risk_key: [u8; 32], // 32..64
    /// T0: the earliest slot the program vouches for as the token's start (the guard's creation,
    /// or an upgrade-authority backdate). Every age rule reads it.
    pub t0_slot: u64,       // 64..72
    pub asset_index: u16,   // 72..74
    pub version: u8,        // 74
    pub bump: u8,           // 75
    pub flags: u8,          // 76
    pub round_active: u8,   // 77  W1: 1 while a stop round is open
    pub round_lp_long: u8,  // 78  W1: the LP side when the round opened (1 long, 0 short)
    pub _pad0: u8,          // 79
    // ── risk report (key-written) ──
    pub rep_j_dump_bps: u16, // 80
    pub rep_m_ind_bps: u16,  // 82
    pub rep_l_cap_x100: u16, // 84
    pub rep_n_mult_bps: u16, // 86
    pub rep_slot: u64,       // 88..96
    // ── permissionless holder proof ──
    pub holder_dump_bps: u16, // 96
    pub round_keep_bps: u16,  // 98  W1 keep-fraction of the open round
    pub touched_n: u16,       // 100 W1 accounts reduced in this round
    pub _pad1: [u8; 2],       // 102..104
    pub holder_dump_slot: u64, // 104..112
    // ── price band ──
    pub pb_last_px: u64,      // 112
    pub pb_last_slot: u64,    // 120
    pub pb_ref_px: u64,       // 128
    pub pb_ref_slot: u64,     // 136
    pub pb_freeze_until: u64, // 144
    pub pb_oracle_until: u64, // 152
    pub frozen_l_x100: u16,   // 160
    pub _pad2: [u8; 6],       // 162..168
    pub frozen_n_q: [u8; 16], // 168..184
    // ── NAV per share (LP stop) ──
    pub navps: [u8; 16],       // 184
    pub nav_last_equity: [u8; 16], // 200
    pub nav_last_in: [u8; 16],  // 216
    pub nav_last_out: [u8; 16], // 232
    pub nav_peak_cur: [u8; 16], // 248
    pub nav_peak_prev: [u8; 16], // 264
    pub nav_ref: [u8; 16],      // 280
    pub nav_bucket_start: u64,  // 296
    pub nav_last_slot: u64,     // 304
    // ── W1 round ──
    pub round_id: u64,          // 312
    pub round_target_q: [u8; 16], // 320..336
    /// Night audit 2026-10-28 (F4): the slot the open round started. A round older than
    /// `W1_ROUND_SLOTS` is stale: it no longer blocks opens and the next W1 call replaces it.
    pub round_open_slot: u64,     // 336..344
    /// Decision 28 (night 2026-10-28, P2) burst memory: the running peak of the market's
    /// volatility variance (`vol_var_x100`) and the slot it was set; read decayed (7-day half-life).
    pub burst_var_peak_x100: u32, // 344..348
    pub _pad3: [u8; 4],           // 348..352
    pub burst_peak_slot: u64,     // 352..360
}
/// The record proper (360 B, small enough for a 4 KB SBF frame). The W1 touched set follows it
/// in the account body as `W1_TOUCHED_CAP` key prefixes of `KEY_TAG_LEN` bytes, read and written
/// in place (`touched_has_in`, `touch_in`), never copied onto the stack.
pub const LEV_GUARD_REC_LEN: usize = 360;
pub const LEV_GUARD_TOUCHED_LEN: usize = KEY_TAG_LEN * W1_TOUCHED_CAP;
pub const LEV_GUARD_BODY_LEN: usize = LEV_GUARD_REC_LEN + LEV_GUARD_TOUCHED_LEN;
/// The touched region, and so the guard account and its rent, are UNCHANGED by the tag widening
/// (16 x 256 == 8 x 512): nothing to migrate, and the SDK / keeper / app length checks still hold.
const _: () = assert!(LEV_GUARD_TOUCHED_LEN == 4_096);
const _: () = assert!(LEV_GUARD_BODY_LEN == 4_456);
const _: () = assert!(W1_TOUCHED_CAP <= u16::MAX as usize);
const _: () = assert!(core::mem::size_of::<LevGuardV22>() == LEV_GUARD_REC_LEN);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, rep_j_dump_bps) == 80);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, holder_dump_slot) == 104);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, pb_last_px) == 112);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, frozen_n_q) == 168);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, navps) == 184);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, round_id) == 312);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, round_open_slot) == 336);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, burst_var_peak_x100) == 344);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, burst_peak_slot) == 352);

impl LevGuardV22 {
    pub fn report(&self) -> RiskReport {
        RiskReport {
            j_dump_bps: self.rep_j_dump_bps,
            m_ind_bps: self.rep_m_ind_bps,
            l_cap_x100: self.rep_l_cap_x100,
            n_mult_bps: self.rep_n_mult_bps,
            slot: self.rep_slot,
        }
    }
    /// D12: have the mint/freeze authorities ever been read by op 3?
    pub fn perm_proven(&self) -> bool {
        self.flags & GUARD_FLAG_PERM_PROVEN != 0
    }
    /// D12 (fail TIGHT): the permissionless facts the open gate feeds to `merge_overlay`. Where
    /// `proof_required` (mainnet builds) and the authorities were never proven, both read as LIVE,
    /// so the existing authority-live clamp (L_floor 2x, N_floor $200) applies instead of the
    /// no-clamp path a never-checked mint used to take. Once op 3 has proven the mint, the stored
    /// bits speak (clean = full limits, live = clamp).
    pub fn perm_for_gate(&self, proof_required: bool) -> PermFacts {
        let mut p = self.perm();
        if proof_required && !self.perm_proven() {
            p.mint_auth_live = true;
            p.freeze_auth_live = true;
        }
        p
    }
    pub fn perm(&self) -> PermFacts {
        PermFacts {
            mint_auth_live: self.flags & GUARD_FLAG_MINT_AUTH != 0,
            freeze_auth_live: self.flags & GUARD_FLAG_FREEZE_AUTH != 0,
            holder_dump_bps: self.holder_dump_bps,
            holder_dump_slot: self.holder_dump_slot,
        }
    }
    pub fn price_band(&self) -> PriceBand {
        PriceBand {
            last_px_e6: self.pb_last_px,
            last_slot: self.pb_last_slot,
            ref_px_e6: self.pb_ref_px,
            ref_slot: self.pb_ref_slot,
            freeze_until: self.pb_freeze_until,
            oracle_until: self.pb_oracle_until,
        }
    }
    pub fn set_price_band(&mut self, b: &PriceBand) {
        self.pb_last_px = b.last_px_e6;
        self.pb_last_slot = b.last_slot;
        self.pb_ref_px = b.ref_px_e6;
        self.pb_ref_slot = b.ref_slot;
        self.pb_freeze_until = b.freeze_until;
        self.pb_oracle_until = b.oracle_until;
    }
    pub fn frozen_n(&self) -> u128 {
        u128_of(&self.frozen_n_q)
    }
    pub fn nav(&self) -> NavState {
        NavState {
            navps: u128_of(&self.navps),
            last_equity: u128_of(&self.nav_last_equity),
            last_in: u128_of(&self.nav_last_in),
            last_out: u128_of(&self.nav_last_out),
            peak_cur: u128_of(&self.nav_peak_cur),
            peak_prev: u128_of(&self.nav_peak_prev),
            bucket_start: self.nav_bucket_start,
            ref_navps: u128_of(&self.nav_ref),
            last_slot: self.nav_last_slot,
        }
    }
    pub fn set_nav(&mut self, n: &NavState) {
        self.navps = n.navps.to_le_bytes();
        self.nav_last_equity = n.last_equity.to_le_bytes();
        self.nav_last_in = n.last_in.to_le_bytes();
        self.nav_last_out = n.last_out.to_le_bytes();
        self.nav_peak_cur = n.peak_cur.to_le_bytes();
        self.nav_peak_prev = n.peak_prev.to_le_bytes();
        self.nav_ref = n.ref_navps.to_le_bytes();
        self.nav_bucket_start = n.bucket_start;
        self.nav_last_slot = n.last_slot;
    }
    pub fn round_target(&self) -> u128 {
        u128_of(&self.round_target_q)
    }
}

/// Whether `key` is among the first `n` tags of the touched region (`LEV_GUARD_TOUCHED_LEN` B).
pub fn touched_has_in(region: &[u8], n: u16, key: &[u8; 32]) -> bool {
    let t = key_tag(key);
    (0..(n as usize).min(W1_TOUCHED_CAP)).any(|i| {
        region
            .get(i * KEY_TAG_LEN..i * KEY_TAG_LEN + KEY_TAG_LEN)
            .is_some_and(|b| b == t.as_slice())
    })
}

/// Append `key`'s tag at index `n` of the region. `false` when full (fail closed: the caller
/// refuses rather than reduce an account it could not record).
pub fn touch_in(region: &mut [u8], n: u16, key: &[u8; 32]) -> bool {
    let i = n as usize;
    if i >= W1_TOUCHED_CAP {
        return false;
    }
    match region.get_mut(i * KEY_TAG_LEN..i * KEY_TAG_LEN + KEY_TAG_LEN) {
        Some(b) => {
            b.copy_from_slice(&key_tag(key));
            true
        }
        None => false,
    }
}

/// Structural validation of a stored record (every reader runs it).
pub fn validate_guard(g: &LevGuardV22) -> bool {
    g.version == LEV_GUARD_VERSION
        && g.flags & !GUARD_FLAGS_KNOWN == 0
        && g.round_active <= 1
        && g.round_lp_long <= 1
        && (g.touched_n as usize) <= W1_TOUCHED_CAP
        && g.round_keep_bps <= 10_000
        && report_ok(&g.report())
        && g._pad0 == 0
        && g._pad1 == [0; 2]
        && g._pad2 == [0; 6]
        && g._pad3 == [0; 4]
}

/// A fresh record for `market`.
pub fn new_guard(market: [u8; 32], asset_index: u16, t0_slot: u64, bump: u8) -> LevGuardV22 {
    let mut g: LevGuardV22 = bytemuck::Zeroable::zeroed();
    g.market = market;
    g.asset_index = asset_index;
    g.t0_slot = t0_slot;
    g.version = LEV_GUARD_VERSION;
    g.bump = bump;
    g
}

/// Read the SPL / Token-2022 `COption<Pubkey>` mint and freeze authorities of a mint account
/// (offsets 0 and 46; tag 1 = Some). `None` if the account is too short or a tag is not 0/1.
pub fn mint_authorities(data: &[u8]) -> Option<(bool, bool)> {
    if data.len() < 82 {
        return None;
    }
    let tag = |o: usize| -> Option<bool> {
        match u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    };
    Some((tag(0)?, tag(46)?))
}

// ── arithmetic ───────────────────────────────────────────────────────────────────────────────

/// `floor(a · b / d)` saturating at u128::MAX; `d == 0` reads 0 (callers never pass it).
pub fn mul_div_floor_sat(a: u128, b: u128, d: u128) -> u128 {
    if d == 0 {
        return 0;
    }
    match a.checked_mul(b) {
        Some(p) => p / d,
        None => {
            // (a / d) · b + (a % d) · b / d, each saturating.
            let hi = (a / d).saturating_mul(b);
            let lo = match (a % d).checked_mul(b) {
                Some(p) => p / d,
                None => u128::MAX,
            };
            hi.saturating_add(lo)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// The touched set must separate two portfolios that share an 8-byte address prefix. Such a
    /// pair is cheap to obtain (a birthday search over client-chosen portfolio addresses), and
    /// while they shared one entry the second account escaped `lev_guard_lp_stop`'s reduce for
    /// the whole round -- repeatably, since the F4 stale-round replacement resets `touched_n`.
    ///
    /// Negative control: `a` and `b` differ ONLY at byte 8, so on an 8-byte tag `key_tag(&a) ==
    /// key_tag(&b)` and the first assertion fails.
    #[test]
    fn touched_set_separates_keys_sharing_an_8_byte_prefix() {
        let mut a = [7u8; 32];
        let mut b = [7u8; 32];
        a[8] = 1;
        b[8] = 2;
        assert_ne!(key_tag(&a), key_tag(&b), "an 8-byte prefix is not an identity");

        let mut region = [0u8; LEV_GUARD_TOUCHED_LEN];
        assert!(touch_in(&mut region, 0, &a));
        assert!(touched_has_in(&region, 1, &a), "a was cut");
        assert!(
            !touched_has_in(&region, 1, &b),
            "b was never cut, so it must still be reducible in this round"
        );
    }

    /// The tag is a prefix, so anything beyond `KEY_TAG_LEN` still collides. Pinned so the bound
    /// is explicit: 16 bytes puts a birthday search at ~2^64, not that collisions are impossible.
    #[test]
    fn key_tag_is_a_prefix_of_known_width() {
        let mut a = [7u8; 32];
        let mut b = [7u8; 32];
        a[KEY_TAG_LEN] = 1;
        b[KEY_TAG_LEN] = 2;
        assert_eq!(key_tag(&a), key_tag(&b));
        assert_eq!(key_tag(&[3u8; 32]), [3u8; KEY_TAG_LEN]);
    }

    const H: u64 = SLOTS_PER_HOUR;
    const D: u64 = SLOTS_PER_DAY;

    // ── ages: boundaries at 6 h / 24 h / 7 d / 30 d ──────────────────────────────────────────
    #[test]
    fn age_band_boundaries() {
        let t0 = 1_000_000;
        assert_eq!(age_band(t0, t0), AgeBand::NoOpen);
        assert_eq!(age_band(t0, t0 + 6 * H - 1), AgeBand::NoOpen);
        assert_eq!(age_band(t0, t0 + 6 * H), AgeBand::Day);
        assert_eq!(age_band(t0, t0 + D - 1), AgeBand::Day);
        assert_eq!(age_band(t0, t0 + D), AgeBand::Week);
        assert_eq!(age_band(t0, t0 + 7 * D - 1), AgeBand::Week);
        assert_eq!(age_band(t0, t0 + 7 * D), AgeBand::Month);
        assert_eq!(age_band(t0, t0 + 30 * D - 1), AgeBand::Month);
        assert_eq!(age_band(t0, t0 + 30 * D), AgeBand::Mature);
        // future-stamped T0 fails closed
        assert_eq!(age_band(t0, t0 - 1), AgeBand::NoOpen);
        assert_eq!(age_band(u64::MAX, 0), AgeBand::NoOpen);
        assert!(AgeBand::Week.young() && !AgeBand::Month.young());
    }

    // ── overlay: defaults by age, staleness ladder, tighten-only ────────────────────────────
    #[test]
    fn overlay_defaults_by_age() {
        let r = RiskReport::default();
        let p = PermFacts::default();
        let o = merge_overlay(AgeBand::Day, &r, &p, 5);
        assert_eq!((o.j_dump_bps, o.m_ind_bps), (3_500, 5_000));
        let o = merge_overlay(AgeBand::Week, &r, &p, 5);
        assert_eq!((o.j_dump_bps, o.m_ind_bps), (2_000, 5_000));
        let o = merge_overlay(AgeBand::Month, &r, &p, 5);
        assert_eq!((o.j_dump_bps, o.m_ind_bps, o.l_cap_x100, o.n_mult_bps), (0, 0, u16::MAX, 10_000));
    }

    #[test]
    fn overlay_report_freshness_ladder() {
        let now = 10 * D;
        let mk = |age: u64| RiskReport { j_dump_bps: 4_000, m_ind_bps: 6_000, l_cap_x100: 300, n_mult_bps: 5_000, slot: now - age };
        let p = PermFacts::default();
        // fresh (<= 3 h) and held (<= 24 h): applied
        for age in [0, 3 * H, 3 * H + 1, D] {
            let o = merge_overlay(AgeBand::Mature, &mk(age), &p, now);
            assert_eq!((o.j_dump_bps, o.m_ind_bps, o.l_cap_x100, o.n_mult_bps), (4_000, 6_000, 300, 5_000), "age {age}");
        }
        // stale (> 24 h) on an older token: the moderate floor, not the report
        let o = merge_overlay(AgeBand::Mature, &mk(D + 1), &p, now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps, o.l_cap_x100, o.n_mult_bps), (1_000, 2_500, u16::MAX, 10_000));
        // stale on a young token: the age default
        let o = merge_overlay(AgeBand::Week, &mk(D + 1), &p, now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps), (2_000, 5_000));
        // future-stamped: stale
        let r = RiskReport { slot: now + 1, ..mk(0) };
        assert_eq!(report_age(r.slot, now), ReportAge::Stale);
    }

    #[test]
    fn overlay_report_cannot_loosen_defaults() {
        // a "clean" report on a 6-24 h token cannot lower the 35 % default
        let now = 100 * D;
        let r = RiskReport { j_dump_bps: 0, m_ind_bps: 0, l_cap_x100: 0, n_mult_bps: 10_000, slot: now };
        let o = merge_overlay(AgeBand::Day, &r, &PermFacts::default(), now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps, o.l_cap_x100, o.n_mult_bps), (3_500, 5_000, u16::MAX, 10_000));
        // out-of-range report fields are clamped, never read as looser
        let r = RiskReport { j_dump_bps: u16::MAX, m_ind_bps: u16::MAX, l_cap_x100: 0, n_mult_bps: u16::MAX, slot: now };
        let o = merge_overlay(AgeBand::Mature, &r, &PermFacts::default(), now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps, o.n_mult_bps), (10_000, 10_000, 10_000));
        assert!(!report_ok(&r));
    }

    #[test]
    fn overlay_tighten_only_exhaustive_grid() {
        let now = 1_000 * D;
        let bands = [AgeBand::NoOpen, AgeBand::Day, AgeBand::Week, AgeBand::Month, AgeBand::Mature];
        let vals = [0u16, 1, 99, 100, 2_000, 3_500, 5_000, 9_999, 10_000, 10_001, u16::MAX];
        for band in bands {
            for age in [0, 3 * H, D, D + 1, 0u64.wrapping_sub(1)] {
                let slot = if age == u64::MAX { 0 } else { now - age };
                let base = default_overlay(band, report_age(slot, now));
                for &j in &vals {
                    for &n in &vals {
                        for &l in &[0u16, 1, 200, 500, u16::MAX] {
                            let r = RiskReport { j_dump_bps: j, m_ind_bps: j, l_cap_x100: l, n_mult_bps: n, slot };
                            for perm in [PermFacts::default(), PermFacts { mint_auth_live: true, ..Default::default() }, PermFacts { holder_dump_bps: j, holder_dump_slot: now, ..Default::default() }] {
                                let o = merge_overlay(band, &r, &perm, now);
                                assert!(o.j_dump_bps >= base.j_dump_bps && o.m_ind_bps >= base.m_ind_bps);
                                assert!(o.l_cap_x100 <= base.l_cap_x100 && o.n_mult_bps <= base.n_mult_bps);
                                assert!(o.j_dump_bps <= 10_000 && o.m_ind_bps <= 10_000 && o.n_mult_bps <= 10_000);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn overlay_permissionless_facts() {
        let now = 50 * D;
        let r = RiskReport::default();
        // mint or freeze authority: leverage to the floor, size to the floor
        for p in [PermFacts { mint_auth_live: true, ..Default::default() }, PermFacts { freeze_auth_live: true, ..Default::default() }] {
            let o = merge_overlay(AgeBand::Mature, &r, &p, now);
            assert_eq!((o.l_cap_x100, o.n_mult_bps), (1, 0));
            assert_eq!(l_overlay_x100(2_000, 2_000, o.l_cap_x100, false, None, 2_000), 200);
            assert_eq!(n_overlay_q(1_000_000, AgeBand::Mature, o.n_mult_bps, 50_000, None), 50_000);
        }
        // a holder proof raises j / m for 24 h, then expires
        let p = PermFacts { holder_dump_bps: 4_200, holder_dump_slot: now - D, ..Default::default() };
        let o = merge_overlay(AgeBand::Mature, &r, &p, now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps), (4_200, 4_200));
        let p = PermFacts { holder_dump_slot: now - D - 1, ..p };
        let o = merge_overlay(AgeBand::Mature, &r, &p, now);
        assert_eq!((o.j_dump_bps, o.m_ind_bps), (0, 0));
        // a future-stamped proof does not count
        let p = PermFacts { holder_dump_slot: now + 1, ..p };
        assert_eq!(merge_overlay(AgeBand::Mature, &r, &p, now).j_dump_bps, 0);
    }

    // ── L_trader and the leverage overlay ───────────────────────────────────────────────────
    #[test]
    fn l_trader_matches_levmodel() {
        // levmodel: L_tr = 1 / (MMR + 0.003 + sqrt((2.33 σ)² + J²))
        // MMR 10 %, σ_1h 0, J 35 %: 1 / (0.1 + 0.003 + 0.35) = 2.207 -> 220
        assert_eq!(l_trader_x100(1_000, None, 3_500), 220);
        // MMR 6 %, σ_1h 100 bps, J 0: 1 / (0.06 + 0.003 + 0.0233) = 11.58 -> 1158
        assert_eq!(l_trader_x100(600, Some(100), 0), 1_158);
        // σ and J combine in quadrature: 2.33·150 = 349.5 -> 350 (ceil), J 2000 -> sqrt(350² + 2000²) = 2030.4 -> 2031
        assert_eq!(l_trader_x100(600, Some(150), 2_000), (1_000_000u64 / (600 + 30 + 2_031)) as u16);
        // monotone non-increasing in σ and J
        let mut prev = u16::MAX;
        for j in (0..=10_000u16).step_by(250) {
            let l = l_trader_x100(1_000, Some(80), j);
            assert!(l <= prev);
            prev = l;
        }
        let mut prev = u16::MAX;
        for s in (0..=5_000u64).step_by(37) {
            let l = l_trader_x100(1_000, Some(s), 2_000);
            assert!(l <= prev);
            prev = l;
        }
    }

    #[test]
    fn l_overlay_never_above_existing_and_respects_floor() {
        for existing in [100u16, 150, 200, 300, 500, 1_000, 2_000] {
            for lt in [100u16, 199, 200, 220, 1_158, 5_000] {
                for cap in [1u16, 200, 400, u16::MAX] {
                    for mo in [false, true] {
                        for fz in [None, Some(150u16), Some(300)] {
                            let l_eng = 2_000u16;
                            let v = l_overlay_x100(existing, lt, cap, mo, fz, l_eng);
                            assert!(v <= existing, "tighten-only");
                            assert!(v >= core::cmp::min(existing, l_floor_x100(l_eng)), "floor");
                        }
                    }
                }
            }
        }
        // the floor never exceeds L_eng
        assert_eq!(l_floor_x100(150), 150);
        assert_eq!(l_overlay_x100(150, 100, 100, false, None, 150), 150);
        // m_oracle 0.75
        assert_eq!(l_overlay_x100(1_000, 800, u16::MAX, true, None, 2_000), 600);
        // frozen at 400 caps a higher trader leverage
        assert_eq!(l_overlay_x100(1_000, 800, u16::MAX, false, Some(400), 2_000), 400);
    }

    // ── size: D-j age rule, multiplier, floors, freeze ──────────────────────────────────────
    #[test]
    fn n_overlay_rules() {
        // D-j: zero under 6 h whatever the floor
        assert_eq!(n_overlay_q(1_000_000, AgeBand::NoOpen, 10_000, 1_000_000, None), 0);
        assert_eq!(n_overlay_q(u128::MAX, AgeBand::NoOpen, 10_000, u128::MAX, None), 0);
        // multiplier, then the floor lifts it back to min(n_cap, floor)
        assert_eq!(n_overlay_q(1_000_000, AgeBand::Day, 5_000, 0, None), 500_000);
        assert_eq!(n_overlay_q(1_000_000, AgeBand::Day, 0, 200_000, None), 200_000);
        assert_eq!(n_overlay_q(100_000, AgeBand::Day, 0, 200_000, None), 100_000);
        // a freeze caps at the snapshot
        assert_eq!(n_overlay_q(1_000_000, AgeBand::Mature, 10_000, 0, Some(300_000)), 300_000);
        // never above n_cap
        for n in [0u128, 1, 9_999, 10_000, 1 << 100, u128::MAX] {
            for m in [0u16, 1, 5_000, 10_000, u16::MAX] {
                for f in [0u128, 7, n, u128::MAX] {
                    for fz in [None, Some(0u128), Some(n / 2)] {
                        assert!(n_overlay_q(n, AgeBand::Week, m, f, fz) <= n);
                    }
                }
            }
        }
    }

    // ── short side ──────────────────────────────────────────────────────────────────────────
    #[test]
    fn short_cap_young_vs_old() {
        let c_m = 10_000_000_000u128; // $10k at 6 dp
        // < 7 d: m = 100 % (rug), β 0.1, offset min(1, MMR/m) = 10 %
        let cap = short_users_cap_notional(0, c_m, 1_000, AgeBand::Week, 0);
        assert_eq!(cap, c_m / 10);
        let cap = short_users_cap_notional(5_000_000_000, c_m, 1_000, AgeBand::Day, 0);
        assert_eq!(cap, 500_000_000 + c_m / 10);
        // 7–30 d: m_tail 100 %, β 0.5
        assert_eq!(short_users_cap_notional(0, c_m, 1_000, AgeBand::Month, 0), c_m / 2);
        // >= 30 d: m_tail 50 %, β 0.5 -> C_m, unless the holder model says a bigger dump
        assert_eq!(short_users_cap_notional(0, c_m, 1_000, AgeBand::Mature, 0), c_m);
        assert_eq!(short_users_cap_notional(0, c_m, 1_000, AgeBand::Mature, 8_000), c_m * 5_000 / 8_000);
        // D-l: β 0.1 under 7 d is 5x tighter than 0.5 at the same m
        assert_eq!(beta_bps(AgeBand::Week), 1_000);
        assert_eq!(beta_bps(AgeBand::Month), 5_000);
        // m never below 1 % (no division blow-up), never above 100 %
        for b in [AgeBand::Day, AgeBand::Mature] {
            for m in [0u16, 1, 99, 100, 10_000, u16::MAX] {
                let d = m_dump_bps(b, m);
                assert!((100..=10_000).contains(&d));
            }
        }
        // monotone: more longs or more C_m never shrinks the cap; a bigger m never grows it
        let mut prev = 0;
        for l in (0..1_000_000_000u128).step_by(97_000_000) {
            let c = short_users_cap_notional(l, c_m, 600, AgeBand::Mature, 3_000);
            assert!(c >= prev);
            prev = c;
        }
        let mut prev = u128::MAX;
        for m in (0..=10_000u16).step_by(500) {
            let c = short_users_cap_notional(1_000_000, c_m, 600, AgeBand::Mature, m);
            assert!(c <= prev);
            prev = c;
        }
    }

    // ── price band ──────────────────────────────────────────────────────────────────────────
    #[test]
    fn price_band_breaker_and_freeze() {
        let (b, t) = observe_price(&PriceBand::default(), 1_000_000, 100, None);
        assert_eq!(t, Trip::None);
        assert_eq!((b.last_px_e6, b.ref_px_e6), (1_000_000, 1_000_000));
        // 10 % exactly: no trip; 10 % + 1 bps: breaker
        let (b2, t) = observe_price(&b, 1_100_000, 110, None);
        assert_eq!(t, Trip::None);
        let (b3, t) = observe_price(&b, 1_100_100, 110, None);
        assert_eq!(t, Trip::Breaker);
        assert!(frozen(&b3, 110) && frozen(&b3, 110 + FREEZE_SLOTS - 1) && !frozen(&b3, 110 + FREEZE_SLOTS));
        assert!(m_oracle_on(&b3, 110 + M_ORACLE_SLOTS - 1) && !m_oracle_on(&b3, 110 + M_ORACLE_SLOTS));
        // staircase: three 9.5 % steps inside an hour trip the 30 % hour rule on the 3rd
        let (s1, t1) = observe_price(&b2, 1_204_500, 200, None); // +9.5 % vs 1.1 -> 20.45 % vs ref
        assert_eq!(t1, Trip::None);
        let (_, t2) = observe_price(&s1, 1_318_927, 300, None); // +9.5 % -> 31.9 % vs ref
        assert_eq!(t2, Trip::Breaker);
        // the reference rolls after an hour: the same staircase over > 1 h does not trip the
        // hour rule on the late step
        let (s1, _) = observe_price(&b2, 1_204_500, 100 + SLOTS_PER_HOUR, None);
        assert_eq!(s1.ref_px_e6, 1_204_500);
        let (_, t) = observe_price(&s1, 1_318_927, 100 + SLOTS_PER_HOUR + 10, None);
        assert_eq!(t, Trip::None);
        // σ test: a 2 % move vs ref with σ_1h 40 bps (> 4σ = 160 bps) freezes only
        let (b4, t) = observe_price(&b, 1_020_000, 120, Some(40));
        assert_eq!(t, Trip::Freeze);
        assert!(frozen(&b4, 120) && !m_oracle_on(&b4, 120));
        // a zero price is ignored
        assert_eq!(observe_price(&b, 0, 999, None), (b, Trip::None));
        // freezes extend, never shorten
        let (b5, _) = observe_price(&b3, 2_000_000, 115, None);
        assert_eq!(b5.freeze_until, 115 + FREEZE_SLOTS);
        // still 100 % above the 1-h reference: the freeze extends from the new sample
        let (b6, t6) = observe_price(&b5, 2_000_000, 116, None);
        assert_eq!(t6, Trip::Breaker);
        assert_eq!(b6.freeze_until, 116 + FREEZE_SLOTS);
        // a calm sample inside the window (ref rolled) leaves the deadline where it was
        let calm = PriceBand { ref_px_e6: 2_000_000, ..b6 };
        let (b7, t7) = observe_price(&calm, 2_000_000, 117, None);
        assert_eq!(t7, Trip::None);
        assert_eq!(b7.freeze_until, b6.freeze_until);
        // dumps trip the same way
        let (_, t) = observe_price(&b, 899_000, 101, None);
        assert_eq!(t, Trip::Breaker);
    }

    // ── LP stop ─────────────────────────────────────────────────────────────────────────────
    #[test]
    fn nav_index_ignores_deposits_and_withdrawals() {
        let mut s = nav_epoch_start(1_000, 1_000, 0, 0);
        // a deposit of 9,000 with no P&L: index unchanged
        s = nav_sample(&s, 10_000, 10_000, 0, 10);
        assert_eq!(s.navps, NAV_ONE);
        // withdraw 9,000: unchanged
        s = nav_sample(&s, 1_000, 10_000, 9_000, 20);
        assert_eq!(s.navps, NAV_ONE);
        assert!(!lp_stop_triggered(&s));
        // deposit + loss in one interval (F1): the deposit cannot TRIP the stop. The loss is read
        // against the post-deposit base (600 of 6,000), not as 60 % of the pre-deposit 1,000.
        let s0 = nav_epoch_start(1_000, 0, 0, 0);
        let s1 = nav_sample(&s0, 1_000 - 600 + 5_000, 5_000, 0, 10); // lost 600, deposited 5,000
        assert_eq!(s1.navps, NAV_ONE * 5_400 / 6_000);
        assert!(!lp_stop_triggered(&s1));
        // the same loss with no flow in the interval still trips
        let s1 = nav_sample(&s0, 1_000 - 600, 0, 0, 10);
        assert_eq!(s1.navps, NAV_ONE * 400 / 1_000);
        assert!(lp_stop_triggered(&s1));
        // a loss bigger than the whole post-deposit base still reads as a stop
        let s1 = nav_sample(&s0, 2_500, 5_000, 0, 10); // 6,000 -> 2,500
        assert!(lp_stop_triggered(&s1), "navps {}", s1.navps);
        // withdraw then loss: the withdrawal cannot fake a loss
        let s1 = nav_sample(&s0, 1_000 - 900, 0, 900, 10); // withdrew 900, no P&L
        assert_eq!(s1.navps, NAV_ONE);
        assert!(!lp_stop_triggered(&s1));
    }

    #[test]
    fn nav_triggers_peak_and_reference() {
        // peak trigger: up 40 %, then down to 50 % of the peak
        let s = nav_epoch_start(1_000, 0, 0, 0);
        let s = nav_sample(&s, 1_400, 0, 0, 10);
        assert_eq!(s.peak(), NAV_ONE * 14 / 10);
        let s2 = nav_sample(&s, 701, 0, 0, 20);
        assert!(!lp_stop_triggered(&s2));
        let s2 = nav_sample(&s, 700, 0, 0, 20);
        assert!(lp_stop_triggered(&s2));
        // reference trigger: a slow bleed below 50 % of the reference after the peak has
        // rolled out of the window still fires (D-i)
        let mut s = nav_epoch_start(1_000, 0, 0, 0);
        for (i, e) in [900u128, 800, 700, 600, 501].iter().enumerate() {
            s = nav_sample(&s, *e, 0, 0, (i as u64 + 1) * 2 * SLOTS_PER_DAY + 1);
        }
        assert_eq!(s.peak(), NAV_ONE * 501 / 1_000);
        assert!(!lp_stop_triggered(&s));
        s = nav_sample(&s, 500, 0, 0, 12 * SLOTS_PER_DAY);
        assert!(lp_stop_triggered(&s), "ref trigger");
        // after a reset the next stop needs a fresh 50 % fall
        let r = nav_stop_reset(&s);
        assert!(!lp_stop_triggered(&r));
        let r2 = nav_sample(&r, 251, 0, 0, 12 * SLOTS_PER_DAY + 5);
        assert!(!lp_stop_triggered(&r2));
        let r2 = nav_sample(&r, 250, 0, 0, 12 * SLOTS_PER_DAY + 5);
        assert!(lp_stop_triggered(&r2));
    }

    #[test]
    fn nav_peak_buckets_cover_24h() {
        // a peak 23 h ago is still in force; one more than 48 h ago is not
        let s = nav_epoch_start(1_000, 0, 0, 0);
        let s = nav_sample(&s, 2_000, 0, 0, 1); // peak 2.0 at slot 1
        let s = nav_sample(&s, 1_000, 0, 0, 23 * SLOTS_PER_HOUR);
        assert_eq!(s.peak(), 2 * NAV_ONE);
        assert!(lp_stop_triggered(&s));
        let s = nav_sample(&s, 1_000, 0, 0, 25 * SLOTS_PER_HOUR); // bucket rolls: prev keeps 2.0
        assert_eq!(s.peak(), 2 * NAV_ONE);
        let s = nav_sample(&s, 1_000, 0, 0, 25 * SLOTS_PER_HOUR + 2 * SLOTS_PER_DAY);
        assert_eq!(s.peak(), NAV_ONE);
    }

    #[test]
    fn nav_epoch_restarts() {
        let s = nav_epoch_start(1_000, 0, 0, 0);
        // wiped: index 0 -> stop fires
        let w = nav_sample(&s, 0, 0, 0, 5);
        assert_eq!(w.navps, 0);
        assert!(lp_stop_triggered(&w));
        // the next sample starts a clean epoch (no perpetual stop on a dead index)
        let n = nav_sample(&w, 3_000, 3_000, 0, 6);
        assert_eq!(n.navps, NAV_ONE);
        assert!(!lp_stop_triggered(&n));
        // a counter going backwards fails to a clean epoch, never to a fake loss
        let b = nav_sample(&s, 1_000, 0, 0, 5);
        let b2 = nav_sample(&NavState { last_in: 10, ..b }, 1_000, 5, 0, 6);
        assert_eq!(b2.navps, NAV_ONE);
        assert!(!lp_stop_triggered(&NavState::default()));
    }

    /// Night audit F1 regression: an inflow followed (in the same sample interval) by a loss that
    /// is under 50 % of the POST-inflow base never trips the stop, for any inflow multiple. On the
    /// end-only reading a 9x allocation then a 6 % loss read as NAV/share 0.4 (stop).
    #[test]
    fn nav_inflow_then_small_loss_never_trips_f1() {
        let s0 = nav_epoch_start(1_000, 0, 0, 0);
        // the concrete case: 1,000 + 9,000 allocated, then 6 % of 10,000 lost
        let s1 = nav_sample(&s0, 10_000 - 600, 9_000, 0, 10);
        assert_eq!(s1.navps, NAV_ONE * 9_400 / 10_000);
        assert!(!lp_stop_triggered(&s1));
        for mult in [1u128, 2, 5, 9, 50, 1_000] {
            let f = 1_000 * mult;
            for loss_pct in [1u128, 10, 25, 40, 49] {
                let x = (1_000 + f) * loss_pct / 100;
                let s1 = nav_sample(&s0, 1_000 + f - x, f, 0, 10);
                assert!(!lp_stop_triggered(&s1), "inflow {f} loss {x}: navps {}", s1.navps);
            }
            // >= 50 % of the post-inflow base: still a stop
            let x = (1_000 + f) * 51 / 100;
            let s1 = nav_sample(&s0, 1_000 + f - x, f, 0, 10);
            assert!(lp_stop_triggered(&s1), "inflow {f} loss {x}: navps {}", s1.navps);
        }
        // an outflow interval is unchanged (end reading): a loss after a withdrawal reads against
        // the pre-withdrawal base, as before the fix
        let s1 = nav_sample(&s0, 1_000 - 100 - 450, 0, 100, 10);
        assert_eq!(s1.navps, NAV_ONE * 550 / 1_000);
    }

    /// Night audit F4: a round is live for one hour after it opens, then stale.
    #[test]
    fn w1_round_liveness_window_f4() {
        assert!(!w1_round_live(0, 100, 100));
        assert!(w1_round_live(1, 100, 100));
        assert!(w1_round_live(1, 100, 100 + W1_ROUND_SLOTS));
        assert!(!w1_round_live(1, 100, 101 + W1_ROUND_SLOTS));
        // a clock behind the open slot reads live (fail closed: keeps blocking LP-growing opens)
        assert!(w1_round_live(1, 100, 50));
    }

    /// Night P2: burst memory decay bounds (never faster than 2^(−t/HL)), clock restart on a new high,
    /// no compounding, and the k = 0.5 floor.
    #[test]
    fn burst_memory_decay_update_and_floor() {
        let hl = BURST_HALF_LIFE_SLOTS;
        assert_eq!(burst_decay(1_000_000, 0), 1_000_000);
        assert_eq!(burst_decay(1_000_000, hl), 500_000);
        assert_eq!(burst_decay(1_000_000, 2 * hl), 250_000);
        assert_eq!(burst_decay(1_000_000, 64 * hl), 0);
        assert_eq!(burst_decay(u32::MAX, 0), u32::MAX);
        // never below the exact exponential, never above the undecayed peak, monotone in time
        let mut prev = u32::MAX;
        for i in 0..=200u64 {
            let t = i * hl / 40;
            let d = burst_decay(1_000_000, t);
            let exact = 1_000_000f64 * 2f64.powf(-(t as f64) / hl as f64);
            assert!(d as f64 + 1.0 >= exact, "t {t}: {d} < exact {exact}");
            assert!(d <= 1_000_000 && d <= prev, "t {t}");
            prev = d;
        }
        // update: a new high restarts; a lower sample keeps the original peak and slot
        assert_eq!(burst_update(100, 5, 200, 10), (200, 10));
        assert_eq!(burst_update(1_000, 5, 200, 10), (1_000, 5));
        let (p, t) = burst_update(1_000, 0, 10, hl);
        assert_eq!((p, t), (1_000, 0), "no compounding: decay keeps reading from the original high");
        // floor: var_eff >= peak/4, never below var_now
        assert_eq!(burst_var_eff(4_000, 0, 10, 0), 1_000);
        assert_eq!(burst_var_eff(4_000, 0, 2_000, 0), 2_000);
        assert_eq!(burst_var_eff(4_000, 0, 10, hl), 500);
        assert_eq!(burst_var_eff(0, 0, 7, 0), 7);
        // a clock behind the peak slot reads no decay (tighter)
        assert_eq!(burst_var_eff(4_000, 100, 0, 50), 1_000);
    }

    #[test]
    fn nav_deposit_withdraw_cycles_never_trip_proptest_style() {
        // many deterministic pseudo-random flow cycles with zero P&L: the index stays 1.0
        let mut s = nav_epoch_start(1_000_000, 1_000_000, 0, 0);
        let (mut eq, mut fin, mut fout) = (1_000_000u128, 1_000_000u128, 0u128);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for i in 0..5_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let amt = (x % 5_000_000) as u128;
            if x & 1 == 0 {
                eq += amt;
                fin += amt;
            } else {
                let a = core::cmp::min(amt, eq.saturating_sub(1));
                eq -= a;
                fout += a;
            }
            s = nav_sample(&s, eq, fin, fout, i * 100);
            assert_eq!(s.navps, NAV_ONE, "step {i}");
            assert!(!lp_stop_triggered(&s));
        }
    }

    #[test]
    fn w1_keep_fraction_and_order_independence() {
        assert_eq!(w1_keep_bps(1_000, 2_000), 10_000);
        assert_eq!(w1_keep_bps(0, 0), 10_000);
        assert_eq!(w1_keep_bps(1_000, 500), 5_000);
        assert_eq!(w1_keep_bps(3, 1), 3_333);
        // each account keeps the same fraction; the total kept is <= target (rounding down)
        let pos = [1_000u128, 2_500, 7, 999_999, 40_000];
        let lp: u128 = pos.iter().sum();
        let target = lp / 3;
        let k = w1_keep_bps(lp, target);
        let kept: u128 = pos.iter().map(|p| w1_keep_q(*p, k, 0)).sum();
        assert!(kept <= target, "{kept} > {target}");
        // the per-account result depends only on (pos, k): any order gives the same vector
        let fwd: Vec<u128> = pos.iter().map(|p| w1_keep_q(*p, k, 0)).collect();
        let mut rev: Vec<u128> = pos.iter().rev().map(|p| w1_keep_q(*p, k, 0)).collect();
        rev.reverse();
        assert_eq!(fwd, rev);
        // a remainder below the minimum leg closes the whole leg
        assert_eq!(w1_keep_q(1_000, 5_000, 600), 0);
        assert_eq!(w1_keep_q(1_000, 5_000, 500), 500);
        assert!(w1_keep_q(u128::MAX, 9_999, 0) < u128::MAX);
        // touched set
        let set = [key_tag(&[1u8; 32]), key_tag(&[2u8; 32])];
        assert!(touched_contains(&set, 2, &key_tag(&[2u8; 32])));
        assert!(!touched_contains(&set, 1, &key_tag(&[2u8; 32])));
    }

    #[test]
    fn w1_keep_from_the_aggregate_book() {
        // within target / empty book / excess beyond the book
        assert_eq!(w1_keep_bps_users(600, 500, 500), 10_000);
        assert_eq!(w1_keep_bps_users(0, 600, 100), 0);
        assert_eq!(w1_keep_bps_users(600, 900, 100), 0);
        // users 600 all opposite, LP 600, target 240: E 360, k = 240/600 = 40 %
        assert_eq!(w1_keep_bps_users(600, 600, 240), 4_000);
        // with 100 same-side users: LP 500, target 240, E 260, k = 340/600
        assert_eq!(w1_keep_bps_users(600, 500, 240), 5_666);
        // cutting every opposing account removes at least E, and the LP lands within target only
        // after the LAST account is cut
        let pos = [300_000u128, 200_000, 100_000];
        let users: u128 = pos.iter().sum();
        for (same, target) in [(0u128, 240_000u128), (100_000, 240_000), (0, 1), (50_000, 400_000)] {
            let lp = users - same;
            let k = w1_keep_bps_users(users, lp, target);
            let mut lp_now = lp;
            for (i, p) in pos.iter().enumerate() {
                let cut = p - w1_keep_q(*p, k, 0);
                lp_now -= cut;
                if i + 1 < pos.len() && lp > target {
                    assert!(lp_now > target, "closed early after {} accounts (same {same}, target {target})", i + 1);
                }
            }
            assert!(lp_now <= target, "after all cuts the LP is within target: {lp_now} vs {target}");
        }
    }

    /// #612: the aggregate rule is pro-rata and exact, but `w1_keep_q` closes a sub-minimum
    /// remainder IN FULL. With a real `min_leg_q` that overrides the aggregate and the round
    /// removes the whole opposing side; `w1_cut_q` carries the outstanding excess as a budget, so
    /// it cannot. Note what the test above does differently: it passes `min_leg_q = 0`, the one
    /// value that disables the branch this is about.
    #[test]
    fn w1_cut_q_cannot_overshoot_the_rounds_excess() {
        // 256 opposing legs at the market minimum. InitMarket floors `band_min_leg_notional` at 10
        // whole collateral tokens, and a trade may not leave a leg below it (error 113), so this is
        // an ordinary book, not a contrived one. Price 1.00, 6 decimals.
        const MIN_LEG: u128 = 10_000_000;
        let pos = [MIN_LEG; 256];
        let users: u128 = pos.iter().sum();
        let target: u128 = 500 * 1_000_000;
        let lp = target + MIN_LEG; // the excess to remove is ONE minimum leg
        let excess = lp - target;
        let k = w1_keep_bps_users(users, lp, target);
        assert_eq!(k, 9_960, "the rule intends to keep 99.6%: one leg's worth removed in total");

        // the old per-leg call: 99.6% of the minimum is below the minimum, so every leg is wiped
        assert_eq!(w1_keep_q(MIN_LEG, k, MIN_LEG), 0);
        let old_total: u128 = pos.iter().map(|p| p - w1_keep_q(*p, k, MIN_LEG)).sum();
        assert_eq!(old_total, users, "the entire opposing side goes");
        assert_eq!(old_total / excess, 256, "256x the excess the round asked for");

        // with the budget: exactly the excess, and it stops after the first leg
        let mut remaining = excess;
        let (mut total, mut cuts) = (0u128, 0usize);
        for p in pos.iter() {
            let cut = w1_cut_q(*p, k, MIN_LEG, remaining);
            if cut == 0 {
                continue;
            }
            total += cut;
            remaining -= cut;
            cuts += 1;
        }
        assert_eq!(total, excess, "exactly the excess, never more");
        assert_eq!(cuts, 1, "one minimum leg closed, not 256");
        assert_eq!(lp - total, target, "the LP lands on target and never crosses it");
    }

    /// #612: in a mixed book the budget changes only which sub-minimum legs are wiped. The
    /// pro-rata legs keep exactly their keep-fraction whatever order they are listed in, which is
    /// what the integration test
    /// `lev_w1_lp_stop_round_cuts_opposing_users_once_and_order_independent` pins end to end.
    #[test]
    fn w1_cut_q_leaves_pro_rata_legs_order_independent() {
        const MIN_LEG: u128 = 10_000_000;
        let k: u16 = 5_000;
        let big = [400 * MIN_LEG, 250 * MIN_LEG, 150 * MIN_LEG];
        let run = |order: &[usize; 3], budget: u128| -> [u128; 3] {
            let mut remaining = budget;
            let mut kept = [0u128; 3];
            for &i in order {
                let cut = w1_cut_q(big[i], k, MIN_LEG, remaining);
                remaining = remaining.saturating_sub(cut);
                kept[i] = big[i] - cut;
            }
            kept
        };
        // whatever the order, and whatever is left of the budget, each leg keeps its fraction
        let mut want = [0u128; 3];
        for (w, p) in want.iter_mut().zip(big) {
            *w = p * u128::from(k) / 10_000;
        }
        assert_eq!(run(&[0, 1, 2], u128::MAX), want);
        assert_eq!(run(&[2, 1, 0], u128::MAX), want);
        assert_eq!(run(&[1, 2, 0], 1), want, "an exhausted budget does not spare a pro-rata leg");
    }

    /// #612: a leg that cannot be cut without overshooting is left alone, not destroyed.
    #[test]
    fn w1_cut_q_skips_a_leg_it_cannot_cut_within_budget() {
        const MIN_LEG: u128 = 10_000_000;
        // the pro-rata remainder would be sub-minimum, so the leg is all-or-nothing -- and taking
        // the whole leg is more than the round still needs
        assert_eq!(w1_cut_q(MIN_LEG, 9_960, MIN_LEG, MIN_LEG - 1), 0);
        // the round needs exactly this much: take it
        assert_eq!(w1_cut_q(MIN_LEG, 9_960, MIN_LEG, MIN_LEG), MIN_LEG);
        // a leg with room for a valid remainder is cut pro-rata, and the budget does NOT touch it:
        // its own outcome must not depend on where the caller listed it. The flooring slack is why
        // the pro-rata total can pass the excess at all, and it is at most one lot per leg.
        assert_eq!(w1_cut_q(100 * MIN_LEG, 5_000, MIN_LEG, u128::MAX), 50 * MIN_LEG);
        assert_eq!(w1_cut_q(100 * MIN_LEG, 5_000, MIN_LEG, 7), 50 * MIN_LEG);
        assert_eq!(w1_cut_q(100 * MIN_LEG, 5_000, MIN_LEG, 0), 50 * MIN_LEG);
        // keep of 100% cuts nothing
        assert_eq!(w1_cut_q(100 * MIN_LEG, 10_000, MIN_LEG, u128::MAX), 0);
    }

    /// D11 (#612 defect 4): the round that never converges. 256 legs at the minimum, the LP one
    /// minimum leg PLUS a sliver over target... then a first whole-leg cut brings it to a sliver
    /// (< one leg) over target, and no whole leg is admitted afterwards.
    #[test]
    fn w1_round_with_leftover_below_one_leg_never_converges_without_the_close_rule() {
        const MIN_LEG: u128 = 10_000_000;
        let target: u128 = 500 * 1_000_000;
        let lp0 = target + MIN_LEG + MIN_LEG / 2; // excess 1.5 legs
        let pos = [MIN_LEG; 256];
        let users: u128 = pos.iter().sum();
        let k = w1_keep_bps_users(users, lp0, target);
        let mut lp = lp0;
        let mut remaining = lp0 - target;
        for p in pos.iter() {
            let cut = w1_cut_q(*p, k, MIN_LEG, remaining);
            lp -= cut;
            remaining = remaining.saturating_sub(cut);
        }
        // every leg was visited: one whole leg went, then the 0.5-leg leftover admits none
        assert_eq!(lp, target + MIN_LEG / 2, "the round is stuck half a leg above target");
        assert!(lp > target, "plain `lp <= target` never closes it");
        // the rule: the leftover is below one leg, so the round closes
        assert!(w1_leftover_below_leg(lp, target, MIN_LEG), "D11: close it");
        // and an opening in that state is acknowledged rather than started
        assert!(w1_leftover_below_leg(target + MIN_LEG - 1, target, MIN_LEG));
    }

    /// D11: a real drawdown keeps the stop armed. The rule never reads or writes the NAV state, and
    /// it only fires within one leg of target; anything a leg or more over keeps the round open.
    #[test]
    fn w1_leftover_rule_keeps_a_real_excess_open_and_the_stop_armed() {
        const MIN_LEG: u128 = 10_000_000;
        let target: u128 = 500 * 1_000_000;
        assert!(!w1_leftover_below_leg(target + MIN_LEG, target, MIN_LEG), "exactly one leg: still needs a cut");
        assert!(!w1_leftover_below_leg(target + 50 * MIN_LEG, target, MIN_LEG));
        assert!(w1_leftover_below_leg(target + MIN_LEG - 1, target, MIN_LEG));
        assert!(w1_leftover_below_leg(target, target, MIN_LEG), "at target");
        assert!(w1_leftover_below_leg(target - 1, target, MIN_LEG), "under target");
        // a price of 0 gives min_leg_q = MAX: the lag gate refuses first, but the rule must not panic
        assert!(w1_leftover_below_leg(u128::MAX - 1, 0, u128::MAX));
        // a halved NAV/share with the LP far over target: the stop is triggered and stays so, since
        // the rule does not touch the NAV reference (only an acknowledged close does)
        let nav = NavState {
            navps: 400,
            peak_cur: 1_000,
            peak_prev: 1_000,
            ref_navps: 1_000,
            last_equity: 1,
            ..Default::default()
        };
        assert!(lp_stop_triggered(&nav));
        assert!(!w1_leftover_below_leg(target + 40 * MIN_LEG, target, MIN_LEG));
        assert!(lp_stop_triggered(&nav), "the round stays open and the reference is untouched");
    }

    /// #612: for every shape, a cut stays inside the leg, never leaves a standing leg below the
    /// market minimum, and -- where it takes a WHOLE leg -- stays inside the round's budget. A
    /// pro-rata cut is intentionally not budget-gated (see `w1_cut_q`), so there is no blanket
    /// `cut <= remaining` to assert.
    #[test]
    fn w1_cut_q_invariants_hold_for_every_shape() {
        let mut st = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for _ in 0..200_000 {
            let min_leg = u128::from(next() % 50_000);
            let pos = u128::from(next() % 1_000_000);
            let k = (next() % 12_000) as u16;
            let rem = u128::from(next() % 1_000_000);
            let cut = w1_cut_q(pos, k, min_leg, rem);
            assert!(cut <= pos, "cut {cut} over leg {pos}");
            // `keep == 0` is exactly the all-or-nothing case, and the only one the budget gates
            if cut == pos && pos > 0 {
                assert!(cut <= rem, "whole leg {cut} taken over budget {rem}");
            }
            let left = pos - cut;
            assert!(
                left == 0 || left >= min_leg || pos < min_leg,
                "left a standing leg below the minimum: pos {pos} k {k} min {min_leg} cut {cut} left {left}"
            );
        }
    }

    // ── λ fallback ──────────────────────────────────────────────────────────────────────────
    #[test]
    fn lambda_fallback_rules() {
        assert!(!W1_LIVE);
        assert_eq!(LAMBDA_VOL_HORIZON_SLOTS, 3 * SLOTS_PER_DAY);
        // D-h: λ <= 1.0 before W1
        assert_eq!(lambda_fallback_bps(30_000, 1), 10_000);
        assert_eq!(lambda_fallback_bps(5_000, 1), 5_000);
        // λ_vol = 0.95 / (2σ): σ_72h 50 % -> 0.95
        assert_eq!(lambda_vol_bps(5_000), 9_500);
        assert_eq!(lambda_fallback_bps(30_000, 5_000), 9_500);
        // σ 0 -> no vol cap
        assert_eq!(lambda_vol_bps(0), u32::MAX);
        // tighten-only and monotone in σ
        let mut prev = u32::MAX;
        for s in (0..200_000u64).step_by(331) {
            let l = lambda_fallback_bps(30_000, s);
            assert!(l <= 30_000 && l <= LAMBDA_CAP_PRE_W1_BPS);
            assert!(l <= prev);
            prev = l;
        }
    }

    // ── min creator stake ───────────────────────────────────────────────────────────────────
    #[test]
    fn min_stake_decimals() {
        assert_eq!(min_creator_stake_atoms(6), Some(500_000_000));
        assert_eq!(min_creator_stake_atoms(9), Some(500_000_000_000));
        assert_eq!(min_creator_stake_atoms(0), Some(500));
        assert_eq!(min_creator_stake_atoms(30), Some(500 * 10u128.pow(30)));
        assert_eq!(min_creator_stake_atoms(31), None);
        let m = min_creator_stake_atoms(6).unwrap();
        assert!(junior_stake_ok(0, m));
        assert!(!junior_stake_ok(1, m));
        assert!(!junior_stake_ok(m - 1, m));
        assert!(junior_stake_ok(m, m));
        assert_eq!(junior_net(5, 9), 0);
        assert_eq!(junior_net(9, 5), 4);
    }

    // ── holder proof ────────────────────────────────────────────────────────────────────────
    #[test]
    fn cpmm_dump_values() {
        assert_eq!(cpmm_dump_bps(1_000, 0), 0);
        assert_eq!(cpmm_dump_bps(0, 5), 10_000);
        // q = R: price falls to 1/4 -> 75 %
        assert_eq!(cpmm_dump_bps(1_000, 1_000), 7_500);
        // q = R/9: (0.9)² = 0.81 -> 19 %
        assert_eq!(cpmm_dump_bps(9_000, 1_000), 1_900);
        // extremes never overflow and stay within [0, 100 %]
        assert!(cpmm_dump_bps(u64::MAX, u64::MAX) <= 10_000);
        assert!(cpmm_dump_bps(1, u64::MAX) <= 10_000);
        // monotone in q
        let mut prev = 0;
        for q in (0..1_000_000u64).step_by(7_919) {
            let d = cpmm_dump_bps(500_000, q);
            assert!(d >= prev);
            prev = d;
        }
    }

    #[test]
    fn guard_record_roundtrip_and_validation() {
        let mut g = new_guard([7u8; 32], 0, 1234, 254);
        assert!(validate_guard(&g));
        assert_eq!(core::mem::size_of::<LevGuardV22>(), LEV_GUARD_REC_LEN);
        let n = nav_sample(&nav_epoch_start(1_000, 5, 6, 10), 900, 5, 6, 20);
        g.set_nav(&n);
        assert_eq!(g.nav(), n);
        let pb = PriceBand { last_px_e6: 1, last_slot: 2, ref_px_e6: 3, ref_slot: 4, freeze_until: 5, oracle_until: 6 };
        g.set_price_band(&pb);
        assert_eq!(g.price_band(), pb);
        // touched set (in place): once per key, fails closed when full
        let mut region = [0u8; LEV_GUARD_TOUCHED_LEN];
        let k1 = [1u8; 32];
        assert!(!touched_has_in(&region, 0, &k1));
        assert!(touch_in(&mut region, 0, &k1));
        assert!(touched_has_in(&region, 1, &k1));
        assert!(!touched_has_in(&region, 0, &k1), "n bounds the search");
        for i in 1..W1_TOUCHED_CAP {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64 + 1_000).to_le_bytes());
            assert!(touch_in(&mut region, i as u16, &k));
        }
        assert!(!touch_in(&mut region, W1_TOUCHED_CAP as u16, &[9u8; 32]), "full set refuses");
        assert!(touched_has_in(&region, W1_TOUCHED_CAP as u16, &k1));
        g.touched_n = W1_TOUCHED_CAP as u16;
        assert!(validate_guard(&g));
        // structural refusals
        let mut b = g;
        b.flags = 8; // bit 2 is GUARD_FLAG_PERM_PROVEN now (D12); bit 3 is still spare
        assert!(!validate_guard(&b));
        let mut b = g;
        b.rep_n_mult_bps = 10_001;
        assert!(!validate_guard(&b));
        let mut b = g;
        b.version = 2;
        assert!(!validate_guard(&b));
        let mut b = g;
        b._pad2 = [1, 0, 0, 0, 0, 0];
        assert!(!validate_guard(&b));
    }

    /// D12: unproven -> the authority-live overlay (L 2x, N $200); proven clean -> full limits;
    /// proven live -> the same clamp. Devnet (`proof_required = false`) is unchanged.
    #[test]
    fn unproven_guard_gets_the_authority_live_overlay_when_proof_is_required() {
        let now = 10 * SLOTS_PER_DAY;
        let rep = RiskReport::default();
        let fresh = new_guard([3u8; 32], 0, 1, 255);
        assert!(!fresh.perm_proven());
        let ov = |g: &LevGuardV22, req: bool| merge_overlay(AgeBand::Mature, &rep, &g.perm_for_gate(req), now);
        // unproven, required: clamped exactly like a proven-live authority
        let live = merge_overlay(
            AgeBand::Mature,
            &rep,
            &PermFacts { mint_auth_live: true, ..Default::default() },
            now,
        );
        assert_eq!((live.l_cap_x100, live.n_mult_bps), (1, 0));
        assert_eq!(ov(&fresh, true), live, "unproven: tight (L 2x floor, N $200 floor)");
        // unproven, not required (devnet): as before, no clamp
        assert_eq!(ov(&fresh, false).l_cap_x100, u16::MAX);
        assert_eq!(ov(&fresh, false).n_mult_bps, 10_000);
        // proven clean: full limits either way
        let mut clean = fresh;
        clean.flags = GUARD_FLAG_PERM_PROVEN;
        assert!(validate_guard(&clean));
        assert_eq!(ov(&clean, true).l_cap_x100, u16::MAX);
        assert_eq!(ov(&clean, true).n_mult_bps, 10_000);
        // proven with a live mint authority / freeze authority: the clamp
        for bit in [GUARD_FLAG_MINT_AUTH, GUARD_FLAG_FREEZE_AUTH] {
            let mut g = fresh;
            g.flags = GUARD_FLAG_PERM_PROVEN | bit;
            assert!(validate_guard(&g));
            assert_eq!((ov(&g, true).l_cap_x100, ov(&g, true).n_mult_bps), (1, 0));
        }
        // the holder-dump proof is untouched by the substitution
        let mut h = fresh;
        h.holder_dump_bps = 1_234;
        h.holder_dump_slot = now;
        assert_eq!(h.perm_for_gate(true).holder_dump_bps, 1_234);
    }

    /// D1: the creator minimum is tested on VALUE. $500 in, $100 lost, $400 left: a full $400
    /// exit leaves value 0 (allowed by the stake rule; net deposits would say $100 and refuse it),
    /// a partial exit leaving $300 is refused, and the junior floor still binds on its own.
    #[test]
    fn creator_stake_is_tested_on_value_with_an_exit_to_zero() {
        use crate::bond_v20::junior_withdraw_allowed3;
        let min = min_creator_stake_atoms(6).unwrap(); // $500
        let usd = |d: u128| d * 1_000_000;
        let (dep, withdrawn) = (usd(500), 0u128);
        let value = usd(400); // after the $100 loss; no senior: V is all junior
        // the old rule, for the record: net after a full exit of the value is $100, in (0, min)
        let net_after = junior_net(dep, withdrawn + value);
        assert_eq!(net_after, usd(100));
        assert!(!junior_stake_ok(net_after, min), "rc23: refused");
        // the new rule
        let after = junior_value_after_withdraw(value, value, 0, 0);
        assert_eq!(after, 0);
        assert!(junior_stake_ok(after, min), "full exit at value: allowed");
        let after = junior_value_after_withdraw(value, usd(100), 0, 0);
        assert_eq!(after, usd(300));
        assert!(!junior_stake_ok(after, min), "leaves $300: refused");
        let after = junior_value_after_withdraw(usd(600), usd(100), 0, 0);
        assert!(junior_stake_ok(after, min), "leaves exactly $500: allowed");
        assert!(!junior_stake_ok(junior_value_after_withdraw(usd(600), usd(100) + 1, 0, 0), min), "leaves $500 - 1 atom");
        // a withdrawal larger than the vault value cannot underflow
        assert_eq!(junior_value_after_withdraw(usd(10), usd(20), 0, 0), 0);
        // the junior floor still binds: Earn senior claim $1000 (floor 20%), junior value $400
        let (v, c, b) = (usd(1_400), usd(1_000), 0u128);
        assert_eq!(junior_value_after_withdraw(v, usd(400), c, b), 0, "the stake rule alone would allow it");
        assert!(!junior_withdraw_allowed3(v, c, b, c, usd(400), 2_000), "...but the floor refuses the full exit");
        assert!(junior_withdraw_allowed3(v, c, b, c, usd(200), 2_000), "up to junior - floor");
        // bonds sit between the senior and the junior: the junior value excludes them
        assert_eq!(junior_value_after_withdraw(usd(1_400), 0, usd(1_000), usd(300)), usd(100));
    }

    /// D1: tag 103 allocates Earn money only while the stake's current value is at least $500.
    #[test]
    fn allocation_needs_the_stake_value_not_the_net_deposit() {
        let min = min_creator_stake_atoms(6).unwrap();
        let usd = |d: u128| d * 1_000_000;
        // $500 deposited, $100 lost: V = senior $1000 + junior $400
        assert!(!junior_value_allows_allocation(usd(1_400), usd(1_000), 0, min));
        assert!(junior_value_allows_allocation(usd(1_500), usd(1_000), 0, min));
        assert!(!junior_value_allows_allocation(usd(1_500) - 1, usd(1_000), 0, min));
        // a profitable stake clears the minimum even though net deposits are below it
        assert!(junior_value_allows_allocation(usd(1_000) + usd(520), usd(1_000), 0, min));
        // no stake at all
        assert!(!junior_value_allows_allocation(usd(1_000), usd(1_000), 0, min));
        // the bond's claim comes out before the junior
        assert!(!junior_value_allows_allocation(usd(1_800), usd(1_000), usd(400), min));
    }

    /// GH#627 (#629): the 50 % test must not read a saturated index as a drawdown. The issue's
    /// path to `u128::MAX` (earn, withdraw to a 1-atom base, sample) is closed at the root by the
    /// gross-reading cap (`gh627_earn_then_withdraw_to_dust_reads_the_gain_on_the_capital_that_
    /// earned_it`), so the saturated state is built directly: the predicate must stay correct at
    /// the extreme on its own, and the honest trigger must still work there.
    #[test]
    fn saturated_navps_is_not_a_drawdown_and_the_reset_still_clears() {
        let slot = 1_000u64;
        let (fin, fout) = (0u128, 0u128);
        let st = NavState {
            navps: u128::MAX,
            peak_cur: u128::MAX,
            peak_prev: u128::MAX,
            ref_navps: u128::MAX,
            ..nav_epoch_start(1_000_000_000, fin, fout, slot)
        };
        assert_eq!(st.navps, u128::MAX);
        assert_eq!(st.peak(), u128::MAX, "the peak follows the index up");

        // the defect: doubling saturates, so the old test read MAX <= MAX as a 50 % fall
        assert_eq!(st.navps.saturating_mul(2), u128::MAX, "the doubling that used to latch it on");
        // the fix: a saturated index at its own peak is no drawdown at all
        assert!(!lp_stop_triggered(&st), "a saturated index is not a 50 % fall");
        // and the reset is no longer a no-op that cannot clear a latched stop
        assert!(!lp_stop_triggered(&nav_stop_reset(&st)));
        let quiet = nav_sample(&st, st.last_equity, fin, fout, slot + 10);
        assert_eq!(quiet.navps, u128::MAX, "a quiet interval leaves the index where it is");
        assert!(!lp_stop_triggered(&quiet));

        // the honest trigger still fires at the same extreme: half of a MAX peak is a real fall
        let halved = NavState { navps: u128::MAX / 2, ..st };
        assert!(lp_stop_triggered(&halved), "a genuine 50 % fall from a saturated peak must fire");
        let just_above = NavState { navps: u128::MAX / 2 + 1, ..st };
        assert!(!lp_stop_triggered(&just_above), "one atom above half must not fire");
        // the reference arm, independently of the peak
        let on_ref = NavState { navps: 50, peak_cur: 60, peak_prev: 60, ref_navps: 100, ..st };
        assert!(lp_stop_triggered(&on_ref), "ref arm: 50 is half of 100");
        let off_ref = NavState { navps: 51, peak_cur: 60, peak_prev: 60, ref_navps: 100, ..st };
        assert!(!lp_stop_triggered(&off_ref));
    }

    // ── GH#627 root cause: no ordering of flows may amplify a gain ─────────────────────────────

    /// The rc23 reading before the #627 root-cause fix (F1 alone: the higher of the end and the
    /// start reading), kept as the reference the new rule is compared against.
    fn f1_reading(st: &NavState, equity: u128, flow_in: u128, flow_out: u128) -> u128 {
        let din = flow_in - st.last_in;
        let dout = flow_out - st.last_out;
        let econ = equity.saturating_add(dout).saturating_sub(din);
        let mut navps = nav_scale(st.navps, econ, st.last_equity);
        if din != 0 || dout != 0 {
            let base = st.last_equity.saturating_add(din).saturating_sub(dout);
            if base != 0 {
                let start = nav_scale(st.navps, equity, base);
                if start > navps {
                    navps = start;
                }
            }
        }
        navps
    }

    /// The interval's P&L is exact, `P = equity + Δout − Δin − last`; only WHICH capital earned it
    /// is ambiguous. The issue's attack (earn `P`, withdraw all but one atom, sample) used to read
    /// the gain against a 1-atom base: ×(1+P) per cycle, `u128::MAX` in five. Now the gain is read
    /// against the most capital that could have earned it, so each cycle moves the index by
    /// exactly `(E + P) / E` -- what the same P&L does with no flow at all -- and it never
    /// saturates. Both variants from the issue: $1 earned (pre-D1) and $500 left standing (D1).
    #[test]
    fn gh627_earn_then_withdraw_to_dust_reads_the_gain_on_the_capital_that_earned_it() {
        const D: u128 = 1_000_000; // 6-decimal collateral: $1 = 1e6 atoms
        for p in [D, 500 * D] {
            let mut slot = 1_000u64;
            let e = 1_000 * D;
            let mut st = nav_epoch_start(e, 0, 0, slot);
            let (mut fin, mut fout) = (0u128, 0u128);
            let mut expect = NAV_ONE;
            for cycle in 1..=50 {
                // put the capital back (a pure flow: the index must not move)
                slot += 10;
                let top_up = e - st.last_equity;
                fin += top_up;
                let before = st.navps;
                st = nav_sample(&st, st.last_equity + top_up, fin, fout, slot);
                assert_eq!(st.navps, before, "cycle {cycle}: a pure deposit moved the index");
                // earn P, withdraw all but one atom of the pre-gain capital, ONE interval
                slot += 10;
                let out = st.last_equity - 1;
                fout += out;
                st = nav_sample(&st, st.last_equity - out + p, fin, fout, slot);
                expect = mul_div_floor_sat(expect, e + p, e);
                assert_eq!(st.navps, expect, "cycle {cycle}: the gain is P on E, not P on 1 atom");
            }
            assert!(st.navps < u128::MAX / 1_000_000, "50 cycles cannot approach saturation");
            // and the same P&L with no flow at all moves the index by the same factor
            let quiet = nav_sample(&nav_epoch_start(e, 0, 0, 0), e + p, 0, 0, 10);
            assert_eq!(quiet.navps, mul_div_floor_sat(NAV_ONE, e + p, e));
        }
    }

    /// The round-trip variant a net-only base cannot see: deposit `X`, earn on it, withdraw it all,
    /// inside one interval, from a dust `last`. Net flow is `-P`, so `max(last, net base)` would
    /// still be 1 atom; the gross base `last + Δin` is the capital that was really there.
    #[test]
    fn gh627_round_trip_from_dust_does_not_amplify() {
        const D: u128 = 1_000_000;
        let st = nav_epoch_start(1, 0, 0, 0); // a 1-atom LP
        let x = 10_000 * D;
        let p = 100 * D;
        // in X, +P on X, out X + P: equity back at 1 atom
        let n = nav_sample(&st, 1, x, x + p, 10);
        assert_eq!(n.navps, mul_div_floor_sat(NAV_ONE, 1 + x + p, 1 + x), "+1 % on X, not ×1e8");
        assert!(f1_reading(&st, 1, x, x + p) > NAV_ONE * 1_000_000, "the F1 reading it replaces");
    }

    /// Deterministic fuzz over random states and intervals (xorshift, ~200k cases). Invariants:
    ///  I1 flow neutrality: no P&L ⇒ the index does not move, whatever the flows;
    ///  I2 no amplification: a gain never lifts the index above the gross reading
    ///     `(equity + Δout) / (last + Δin)`, hence never above the no-flow reading `(last + P) / last`;
    ///  I3 losses unchanged: for `P <= 0` the reading is exactly F1's (deposits still cannot trip);
    ///  I4 no flows ⇒ identical to the rc23 reading (nothing changes in the plain case);
    ///  I5 monotone in equity: more equity never reads lower (no perverse incentive);
    ///  I6 a gain never reads below the start: P >= 0 ⇒ navps' >= navps.
    #[test]
    fn nav_sample_flow_invariants_fuzz() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut gains_changed = 0u64;
        for i in 0..200_000u64 {
            // magnitudes from dust to 1e15 atoms ($1e9 at 6 decimals); index from 1 to 1e24
            let mag = |r: u64, bits: u64| -> u128 { (r % (1u64 << (r % bits).max(1))) as u128 };
            let last = 1 + mag(next(), 50);
            let navps = 1 + mag(next(), 62) * (1 + (next() % 1_000_000) as u128);
            let (lin, lout) = (mag(next(), 60), mag(next(), 60));
            let st = NavState {
                navps,
                last_equity: last,
                last_in: lin,
                last_out: lout,
                peak_cur: navps,
                peak_prev: navps,
                bucket_start: 0,
                ref_navps: navps,
                last_slot: 0,
            };
            let kind = next() % 4;
            let din = if kind == 1 || kind == 3 { mag(next(), 50) } else { 0 };
            let dout = if kind == 2 || kind == 3 { mag(next(), 50) % (last + din + 1) } else { 0 };
            // P in [-(last + din - dout), +2·(last + din)]
            let cap = last + din - dout;
            let pnl: i128 = if next() % 2 == 0 {
                -((next() as u128 % (cap + 1)) as i128)
            } else {
                (next() as u128 % (2 * (last + din) + 1)) as i128
            };
            let equity = (cap as i128 + pnl) as u128;
            let n = nav_sample(&st, equity, lin + din, lout + dout, 10);
            let f1 = f1_reading(&st, equity, lin + din, lout + dout);
            if pnl == 0 {
                assert_eq!(n.navps, navps, "I1 case {i}");
            }
            let gross = nav_scale(navps, equity + dout, last + din);
            if pnl > 0 {
                assert!(n.navps <= gross, "I2 gross case {i}");
                let no_flow = nav_scale(navps, last + pnl as u128, last);
                assert!(n.navps <= no_flow, "I2 no-flow case {i}");
                assert!(n.navps >= navps, "I6 case {i}");
                if n.navps != f1 {
                    gains_changed += 1;
                }
            } else {
                assert_eq!(n.navps, f1, "I3 case {i}");
            }
            if din == 0 && dout == 0 {
                assert_eq!(n.navps, f1, "I4 case {i}");
            }
            let n_more = nav_sample(&st, equity + 1, lin + din, lout + dout, 10);
            assert!(n_more.navps >= n.navps, "I5 case {i}");
        }
        assert!(gains_changed > 10_000, "the fuzz must exercise the changed branch: {gains_changed}");
    }

    /// Saturation is unreachable through flows: 10,000 adversarial intervals (any flows, gains up
    /// to +100 % of the capital that could have earned them) from a 1-atom LP keep the index at or
    /// below the product of the per-interval gross factors, and that product -- the honest
    /// compounding of the capital present -- is what it would take to saturate (~89 doublings).
    #[test]
    fn nav_index_growth_is_bounded_by_real_returns() {
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut st = nav_epoch_start(1, 0, 0, 0);
        let (mut fin, mut fout) = (0u128, 0u128);
        let mut bound_num_log2 = 0f64;
        for k in 1..=10_000u64 {
            let last = st.last_equity.max(1);
            let din = (next() % 1_000_000_000) as u128;
            let dout = (next() as u128) % (last + din);
            // a gain of at most 1 % of the gross capital, the adversary's best ordering applied
            let gross = last + din;
            let p = (next() as u128) % (gross / 100 + 1);
            fin += din;
            fout += dout;
            let eq = gross - dout + p;
            st = nav_sample(&st, eq, fin, fout, k * 10);
            bound_num_log2 += ((gross + p) as f64 / gross as f64).log2();
            assert!(st.navps != u128::MAX, "interval {k}: saturated");
        }
        let got = (st.navps as f64 / NAV_ONE as f64).log2();
        assert!(got <= bound_num_log2 + 1e-6, "index {got} above the honest compounding {bound_num_log2}");
    }

    /// GH#627 follow-up: the division form is the doubling form wherever `2 · navps` does not
    /// overflow, so the fix changes nothing below saturation. Boundary values around every
    /// power of two and odd/even halves, plus pseudo-random triples, against the exact
    /// (non-saturating) doubling.
    #[test]
    fn lp_stop_division_matches_exact_doubling_below_saturation() {
        let exact = |st: &NavState| -> bool {
            let twice = st.navps.checked_mul(2).expect("domain: 2 * navps fits");
            twice <= st.peak() || twice <= st.ref_navps
        };
        let mut vals: alloc::vec::Vec<u128> = alloc::vec![0, 1, 2, 3, NAV_ONE, NAV_ONE / 2, NAV_ONE / 2 + 1];
        for k in 1..128u32 {
            let p = 1u128 << k;
            vals.extend([p - 1, p, p + 1]);
        }
        vals.extend([u128::MAX, u128::MAX - 1, u128::MAX / 2, u128::MAX / 2 + 1]);
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..2_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let hi = (x as u128) << 64 | (x.rotate_left(29) as u128);
            vals.push(hi >> (x % 128));
        }
        let mut checked = 0u64;
        for &n in vals.iter().filter(|&&n| n != 0 && n <= u128::MAX / 2) {
            for &p in vals.iter() {
                for &r in [0u128, n, p, p / 2, n.saturating_mul(2), u128::MAX].iter() {
                    let st = NavState { navps: n, peak_cur: p, peak_prev: 0, ref_navps: r, ..NavState::default() };
                    assert_eq!(lp_stop_triggered(&st), exact(&st), "navps {n} peak {p} ref {r}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 1_000_000, "checked {checked}");
    }

    #[test]
    fn mint_authority_parse() {
        let mut d = [0u8; 82];
        assert_eq!(mint_authorities(&d), Some((false, false)));
        d[0] = 1;
        assert_eq!(mint_authorities(&d), Some((true, false)));
        d[46] = 1;
        assert_eq!(mint_authorities(&d), Some((true, true)));
        d[0] = 2;
        assert_eq!(mint_authorities(&d), None);
        assert_eq!(mint_authorities(&[0u8; 81]), None);
    }

    #[test]
    fn mul_div_sat_edges() {
        assert_eq!(mul_div_floor_sat(10, 3, 4), 7);
        assert_eq!(mul_div_floor_sat(u128::MAX, 2, 2), u128::MAX);
        assert_eq!(mul_div_floor_sat(u128::MAX, 1, 1), u128::MAX);
        assert_eq!(mul_div_floor_sat(1, 1, 0), 0);
    }
}

/// Kani: the tighten-only and order-independence properties (bounded).
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_band() -> AgeBand {
        match kani::any::<u8>() % 5 {
            0 => AgeBand::NoOpen,
            1 => AgeBand::Day,
            2 => AgeBand::Week,
            3 => AgeBand::Month,
            _ => AgeBand::Mature,
        }
    }

    /// N15: the merged overlay is never looser than the on-chain default, for every report and
    /// every permissionless fact.
    #[kani::proof]
    fn kani_lev_overlay_tighten_only() {
        let band = any_band();
        let now: u64 = kani::any();
        let r = RiskReport {
            j_dump_bps: kani::any(),
            m_ind_bps: kani::any(),
            l_cap_x100: kani::any(),
            n_mult_bps: kani::any(),
            slot: kani::any(),
        };
        let p = PermFacts {
            mint_auth_live: kani::any(),
            freeze_auth_live: kani::any(),
            holder_dump_bps: kani::any(),
            holder_dump_slot: kani::any(),
        };
        let o = merge_overlay(band, &r, &p, now);
        let b = default_overlay(band, report_age(r.slot, now));
        assert!(o.j_dump_bps >= b.j_dump_bps && o.m_ind_bps >= b.m_ind_bps);
        assert!(o.l_cap_x100 <= b.l_cap_x100 && o.n_mult_bps <= b.n_mult_bps);
    }

    /// The leverage overlay is never above the existing ceiling, and never below
    /// `min(existing, L_floor)`.
    #[kani::proof]
    fn kani_lev_l_overlay_bounds() {
        let (e, t, c, l): (u16, u16, u16, u16) = (kani::any(), kani::any(), kani::any(), kani::any());
        let mo: bool = kani::any();
        let fz: Option<u16> = if kani::any() { Some(kani::any()) } else { None };
        let v = l_overlay_x100(e, t, c, mo, fz, l);
        assert!(v <= e);
        assert!(v >= core::cmp::min(e, l_floor_x100(l)));
    }

    /// The size overlay is never above N_cap, and is 0 under 6 h.
    #[kani::proof]
    fn kani_lev_n_overlay_bounds() {
        let n: u128 = kani::any();
        let m: u16 = kani::any();
        let f: u128 = kani::any();
        let band = any_band();
        let fz: Option<u128> = if kani::any() { Some(kani::any()) } else { None };
        let v = n_overlay_q(n, band, m, f, fz);
        assert!(v <= n);
        if band == AgeBand::NoOpen {
            assert!(v == 0);
        }
    }

    /// W1: an account's kept position depends only on (its position, k), and never exceeds it.
    #[kani::proof]
    fn kani_lev_w1_keep_bounded() {
        // 32-bit widths keep the symbolic multiply / divide tractable (CBMC); the arithmetic is
        // the same code path at every width (u128 in the function).
        let p: u32 = kani::any();
        let k: u16 = kani::any();
        let m: u32 = kani::any();
        let v = w1_keep_q(p as u128, k, m as u128);
        assert!(v <= p as u128);
        if k >= 10_000 && (p as u128) >= m as u128 {
            assert!(v == p as u128);
        }
    }

    /// λ fallback is tighten-only.
    #[kani::proof]
    fn kani_lev_lambda_fallback_tighten_only() {
        let l: u32 = kani::any();
        let s: u64 = kani::any();
        let v = lambda_fallback_bps(l, s);
        assert!(v <= l);
        if !W1_LIVE {
            assert!(v <= LAMBDA_CAP_PRE_W1_BPS);
        }
    }

    /// A pure flow (deposit or withdrawal with no P&L) never moves NAV per share.
    #[kani::proof]
    fn kani_lev_nav_flow_neutral() {
        let e0: u32 = kani::any();
        let fin: u32 = kani::any();
        let fout: u32 = kani::any();
        let a: u32 = kani::any();
        kani::assume(e0 > 0);
        let s = nav_epoch_start(e0 as u128, fin as u128, fout as u128, 0);
        let dep: bool = kani::any();
        let n = if dep {
            nav_sample(&s, e0 as u128 + a as u128, fin as u128 + a as u128, fout as u128, 1)
        } else {
            kani::assume(a <= e0);
            nav_sample(&s, (e0 - a) as u128, fin as u128, fout as u128 + a as u128, 1)
        };
        assert!(n.navps == NAV_ONE || n.last_equity == 0 || e0 as u128 + a as u128 == 0);
        assert!(!lp_stop_triggered(&n) || (!dep && a == e0));
    }

    /// Night P2: burst memory only ever raises the variance the leverage term reads (tighten-only),
    /// and the decayed peak never exceeds the stored one.
    #[kani::proof]
    fn kani_lev_burst_tighten_only() {
        let peak: u32 = kani::any();
        let var_now: u32 = kani::any();
        let peak_slot: u64 = kani::any();
        let now: u64 = kani::any();
        let e = burst_var_eff(peak, peak_slot, var_now, now);
        assert!(e >= var_now);
        assert!(burst_decay(peak, now.saturating_sub(peak_slot)) <= peak);
        let (p2, _) = burst_update(peak, peak_slot, var_now, now);
        assert!(p2 >= var_now || p2 == peak);
    }

    /// D-b, from ANY stored NAV state (not only an epoch start): a pure deposit or withdrawal
    /// (no P&L) leaves NAV per share exactly unchanged, and a stop that did not hold before the
    /// flow does not hold after it (whatever bucket roll the sample's slot causes). Night
    /// 2026-10-28: provable without 128-bit division thanks to `nav_scale`'s `num == den` path.
    #[kani::proof]
    fn kani_lev_nav_pure_flow_any_state() {
        let navps: u64 = kani::any();
        let last: u64 = kani::any();
        let lin: u64 = kani::any();
        let lout: u64 = kani::any();
        let st = NavState {
            navps: navps as u128,
            last_equity: last as u128,
            last_in: lin as u128,
            last_out: lout as u128,
            peak_cur: kani::any::<u64>() as u128,
            peak_prev: kani::any::<u64>() as u128,
            bucket_start: kani::any(),
            ref_navps: kani::any::<u64>() as u128,
            last_slot: kani::any(),
        };
        kani::assume(navps > 0 && last > 0);
        let now: u64 = kani::any();
        kani::assume(now >= st.bucket_start);
        let a: u64 = kani::any();
        let dep: bool = kani::any();
        let n = if dep {
            nav_sample(&st, last as u128 + a as u128, lin as u128 + a as u128, lout as u128, now)
        } else {
            kani::assume(a <= last);
            nav_sample(&st, (last - a) as u128, lin as u128, lout as u128 + a as u128, now)
        };
        assert!(n.navps == st.navps);
        assert!(lp_stop_triggered(&st) || !lp_stop_triggered(&n));
    }
}
