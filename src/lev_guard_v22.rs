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
/// and withdrawals, recalls (out). The economic value at the sample is `equity - (Δin - Δout)`
/// (every flow in the interval is treated as arriving at its end, so a deposit can never mask
/// a loss and a withdrawal can never fake one), and `navps' = navps · econ / last_equity`.
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
    // econ = equity - din + dout, clamped at 0 (a loss beyond everything reads as 0).
    let econ = equity.saturating_add(dout).saturating_sub(din);
    let navps = mul_div_floor_sat(st.navps, econ, st.last_equity);
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

/// D-b + D-i: the stop fires at NAV/share <= 50 % of the trailing peak OR <= 50 % of the
/// reference. An uninitialised state never fires.
pub fn lp_stop_triggered(st: &NavState) -> bool {
    if !st.initialised() {
        return false;
    }
    let twice = st.navps.saturating_mul(2);
    twice <= st.peak() || twice <= st.ref_navps
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

/// The LP-side target `λ_eff · C_m_now` in Q (`growth_v19::n_cap_q`).
pub fn w1_target_q(c_m: u128, lambda_eff_bps: u32, price_e6: u64, pos_scale: u128) -> u128 {
    crate::growth_v19::n_cap_q(c_m, lambda_eff_bps, price_e6, pos_scale).unwrap_or(0)
}

/// The per-round touched set: 8-byte key prefixes, one per opposing account already reduced in
/// this round. An account is reduced at most once per round, so the keep-fraction applies once
/// to each account whatever the order of the calls (rule 27 / v16.9.1 K/F order: the outcome per
/// account does not depend on which other accounts a caller lists, or in what order).
pub const W1_TOUCHED_CAP: usize = 512;
pub fn key_tag(key: &[u8; 32]) -> u64 {
    u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]])
}
pub fn touched_contains(set: &[u64], n: usize, tag: u64) -> bool {
    set.iter().take(n).any(|t| *t == tag)
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
pub const GUARD_FLAGS_KNOWN: u8 = GUARD_FLAG_MINT_AUTH | GUARD_FLAG_FREEZE_AUTH;

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
}
/// The record proper (336 B, small enough for a 4 KB SBF frame). The W1 touched set follows it
/// in the account body as `W1_TOUCHED_CAP` LE u64 tags, read and written in place
/// (`touched_has_in`, `touch_in`), never copied onto the stack.
pub const LEV_GUARD_REC_LEN: usize = 336;
pub const LEV_GUARD_TOUCHED_LEN: usize = 8 * W1_TOUCHED_CAP;
pub const LEV_GUARD_BODY_LEN: usize = LEV_GUARD_REC_LEN + LEV_GUARD_TOUCHED_LEN;
const _: () = assert!(core::mem::size_of::<LevGuardV22>() == LEV_GUARD_REC_LEN);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, rep_j_dump_bps) == 80);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, holder_dump_slot) == 104);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, pb_last_px) == 112);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, frozen_n_q) == 168);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, navps) == 184);
const _: () = assert!(core::mem::offset_of!(LevGuardV22, round_id) == 312);

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
            .get(i * 8..i * 8 + 8)
            .is_some_and(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) == t)
    })
}

/// Append `key`'s tag at index `n` of the region. `false` when full (fail closed: the caller
/// refuses rather than reduce an account it could not record).
pub fn touch_in(region: &mut [u8], n: u16, key: &[u8; 32]) -> bool {
    let i = n as usize;
    if i >= W1_TOUCHED_CAP {
        return false;
    }
    match region.get_mut(i * 8..i * 8 + 8) {
        Some(b) => {
            b.copy_from_slice(&key_tag(key).to_le_bytes());
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
        // deposit + loss in one interval: the deposit cannot mask the loss
        let s0 = nav_epoch_start(1_000, 0, 0, 0);
        let s1 = nav_sample(&s0, 1_000 - 600 + 5_000, 5_000, 0, 10); // lost 600, deposited 5,000
        assert_eq!(s1.navps, NAV_ONE * 400 / 1_000);
        assert!(lp_stop_triggered(&s1));
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
        assert!(touched_contains(&set, 2, key_tag(&[2u8; 32])));
        assert!(!touched_contains(&set, 1, key_tag(&[2u8; 32])));
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
        b.flags = 4;
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
}
