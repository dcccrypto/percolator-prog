//! F1 follow-on inputs differential (job J-20261116-PROG-BUG-F1INPUTSDIFF).
//!
//! `src/f1_refresh_liq_v22.rs` is the pure decision (Kani-proved). `f1_follow_on_wanted` in
//! `src/v16_program.rs` fills its `F1Inputs` from the market / portfolio bytes after the refresh.
//! Nothing checked those inputs against the engine. This file does, on the REAL processor
//! (`processor::process_instruction`, in-process, the same harness as `acct_sub_crank_liq.rs`):
//!
//! For accounts with 1-4 legs and 0-3 occupied source domains, at the instant the crank refreshes
//! the account, an independent engine view is taken on a clone (host-side `full_account_refresh`,
//! `build_actionable_summary_at_slot`, the certificate, and the engine's own
//! `liquidate_account_not_atomic` on a second clone). From it the expected `F1Inputs` are built and
//! the kernel is asked what it would do. The real crank is then run and must agree:
//!   * fires exactly when the expected inputs say so (observed by the account changing),
//!   * never fails because the engine refused the follow-on liquidation (a refused
//!     liquidation fails the whole instruction, refresh included),
//!   * fires only if the engine's `Liquidate` is accepted.
//! The min_shortfall boundary (requirement 0 / 199 / 200 / 201) is pinned both on the pure kernel
//! and at the processor, with the shortfall set to `min_shortfall(req) - 1 / 0 / +1` on real
//! accounts.
//!
//! Domains are counted from the target's `source_domains` after the setup (`is_occupied`), and the
//! matrix asserts every (legs 1..=4) x (domains 0..=3) cell was actually reached.
#![cfg(not(kani))]

mod acct_sub_harness;

use acct_sub_harness::*;
use percolator::{LiquidationRequestV16, TradeRequestV16, POS_SCALE};
use percolator_prog::{
    f1_refresh_liq_v22 as f1,
    ix::{CrankObservationHint, Instruction},
    state,
};
use solana_program::pubkey::Pubkey;

// ---------------------------------------------------------------------------------------------
// pure kernel pins
// ---------------------------------------------------------------------------------------------

#[test]
fn min_shortfall_boundaries() {
    // ceil(req / 200), floor 1
    assert_eq!(f1::min_shortfall(0), 1);
    assert_eq!(f1::min_shortfall(1), 1);
    assert_eq!(f1::min_shortfall(199), 1);
    assert_eq!(f1::min_shortfall(200), 1);
    assert_eq!(f1::min_shortfall(201), 2);
    assert_eq!(f1::min_shortfall(400), 2);
    assert_eq!(f1::min_shortfall(401), 3);
    assert_eq!(f1::min_shortfall(u128::MAX), u128::MAX / 200 + 1);
    // shortfall_material at each requirement: the smallest material shortfall is min_shortfall
    for req in [199u128, 200, 201, 1_000, 1_000_001] {
        let ms = f1::min_shortfall(req);
        assert!(!f1::shortfall_material((req - (ms - 1)) as i128, req), "req {req}: shortfall {} must be dust", ms - 1);
        if ms <= req {
            assert!(f1::shortfall_material((req - ms) as i128, req), "req {req}: shortfall {ms} must be material");
            assert!(f1::shortfall_material((req - ms - 1).max(1) as i128, req) || req - ms - 1 == 0);
        }
        assert!(!f1::shortfall_material(req as i128, req), "req {req}: no shortfall");
    }
    // req 0: equity <= 0 is always material, equity > 0 is never below maintenance
    assert!(f1::shortfall_material(0, 0));
    assert!(f1::shortfall_material(-1, 0));
    assert!(!f1::shortfall_material(1, 0));
    // shape budget
    for legs in 0..=6u8 {
        for dom in 0..=8u8 {
            assert_eq!(f1::shape_within_budget(legs, dom), legs <= 3 && dom as u16 <= 2 * legs as u16, "legs {legs} dom {dom}");
        }
    }
    // the engine certified deficit mirror
    assert_eq!(f1::engine_certified_liq_deficit(-5, 100), 5);
    assert_eq!(f1::engine_certified_liq_deficit(40, 100), 60);
    assert_eq!(f1::engine_certified_liq_deficit(100, 100), 0);
    assert_eq!(f1::engine_certified_liq_deficit(101, 100), 0);
}

// ---------------------------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------------------------

fn init_ix(n: u16) -> Instruction {
    let Instruction::InitMarket {
        h_min, h_max, initial_price, min_nonzero_mm_req, min_nonzero_im_req, max_trading_fee_bps, trade_fee_base_bps,
        liquidation_fee_bps, liquidation_fee_cap, min_liquidation_abs, max_accrual_dt_slots, max_abs_funding_e9_per_slot,
        min_funding_lifetime_slots, max_account_b_settlement_chunks, max_bankrupt_close_chunks,
        max_bankrupt_close_lifetime_slots, public_b_chunk_atoms, maintenance_fee_per_slot, ..
    } = default_init_market_ix()
    else {
        unreachable!()
    };
    // same market as tests/v16_cu.rs `x1_env(n, false)`: 10% margins, 5% per-slot price cap
    Instruction::InitMarket {
        max_portfolio_assets: n,
        h_min, h_max, initial_price, min_nonzero_mm_req, min_nonzero_im_req,
        maintenance_margin_bps: 1_000,
        initial_margin_bps: 1_000,
        max_trading_fee_bps, trade_fee_base_bps, liquidation_fee_bps, liquidation_fee_cap, min_liquidation_abs,
        max_price_move_bps_per_slot: 500,
        max_accrual_dt_slots, max_abs_funding_e9_per_slot, min_funding_lifetime_slots,
        max_account_b_settlement_chunks, max_bankrupt_close_chunks, max_bankrupt_close_lifetime_slots,
        public_b_chunk_atoms, maintenance_fee_per_slot,
    }
}

fn market_for(n: u16) -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), program_id(), state::market_account_len_for_capacity(n as usize).unwrap()).writable()
}

fn portfolio_for(n: u16) -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), program_id(), state::portfolio_account_len_for_market_slots(n as usize).unwrap()).writable()
}

#[derive(Clone)]
struct World {
    n: u16,
    market: TestAccount,
    t: TestAccount,
    c: TestAccount,
    /// the slot every asset was accrued to (the crank runs at this slot: dt = 0)
    slot: u64,
}

type Views<'a> = (state::MarketViewMutV16<'a>, percolator::PortfolioV16ViewMut<'a>, percolator::PortfolioV16ViewMut<'a>);

/// Host-side access to the market and the two portfolios.
fn host<R>(w: &mut World, f: impl FnOnce(&mut Views<'_>) -> R) -> R {
    let (_, _, slots, _) = state::read_market_config_mode_and_capacity(&w.market.data).unwrap();
    let (_, group) = state::market_view_mut(&mut w.market.data).unwrap();
    let t = state::portfolio_view_mut_for_market_slots(&mut w.t.data, slots).unwrap();
    let c = state::portfolio_view_mut_for_market_slots(&mut w.c.data, slots).unwrap();
    let mut v: Views<'_> = (group, t, c);
    f(&mut v)
}

fn occupied(w: &World) -> usize {
    state::read_portfolio(&w.t.data).unwrap().source_domains.iter().filter(|d| d.is_occupied()).count()
}

fn legs(w: &World) -> u32 {
    percolator::active_bitmap_count_ones(state::read_portfolio(&w.t.data).unwrap().active_bitmap)
}

/// Build the target T (long every asset, `rev` of them later flipped short to occupy source
/// domains) against a counterparty C, then drop the price. Returns the world accrued to the final
/// slot with T holding a huge capital (so it is healthy); `with_capital` pokes the capital later.
fn build(n: u16, rev: usize) -> World {
    let mut admin = signer();
    let mut market = market_for(n);
    let mut mint = mint_account();
    run_ix(init_ix(n), &mut [&mut admin, &mut market, &mut mint]).expect("init market");
    let mut t_owner = signer();
    let mut c_owner = signer();
    let mut t = portfolio_for(n);
    let mut c = portfolio_for(n);
    init_portfolio(&mut t_owner, &mut market, &mut t);
    init_portfolio(&mut c_owner, &mut market, &mut c);
    deposit(&mut t_owner, &mut market, &mut t, 500_000_000);
    deposit(&mut c_owner, &mut market, &mut c, 2_000_000_000);
    let mut w = World { n, market, t, c, slot: 0 };
    let nn = n as usize;
    let q = (100_000 * POS_SCALE) as i128;
    let mut slot = 0u64;
    host(&mut w, |(group, t, c)| {
        let mut step = |group: &mut state::MarketViewMutV16<'_>, price: u64| {
            slot += 1;
            for a in 0..nn {
                group.accrue_asset_to_not_atomic(a, slot, price, 0, true).unwrap();
                group.markets[a].engine.asset.raw_oracle_target_price = percolator::V16PodU64::new(price);
            }
        };
        let tr = |group: &mut state::MarketViewMutV16<'_>, long: &mut percolator::PortfolioV16ViewMut<'_>, short: &mut percolator::PortfolioV16ViewMut<'_>, a: usize, size_q: i128, px: u64| {
            group.execute_trade_with_fee_loss_stale_scoped_not_atomic(long, short, TradeRequestV16 { asset_index: a, size_q, exec_price: px, fee_bps: 0 }, true)
        };
        for a in 0..nn {
            tr(group, t, c, a, q, 100).expect("open");
        }
        for p in [104u64, 108] {
            step(group, p);
        }
        group.full_account_refresh_not_atomic(c).unwrap();
        group.full_account_refresh_not_atomic(t).unwrap();
        for a in 0..rev.min(nn) {
            tr(group, c, t, a, 2 * q, 108).expect("flip"); // T short q, C long q on this asset
        }
        for p in [104u64, 100, 96, 92] {
            step(group, p);
        }
        group.full_account_refresh_not_atomic(c).unwrap();
        group.full_account_refresh_not_atomic(t).unwrap();
    });
    w.slot = slot;
    w
}

/// Set T's capital (vault and c_tot follow), keeping the books consistent.
fn with_capital(w: &mut World, cap: u128) {
    host(w, |(group, t, _)| {
        let old = t.header.capital.get();
        t.header.capital = percolator::V16PodU128::new(cap);
        let c_tot = group.header.c_tot.get();
        group.header.c_tot = percolator::V16PodU128::new(c_tot - old + cap);
        let vault = group.header.vault.get();
        group.header.vault = percolator::V16PodU128::new(vault - old + cap);
    });
}

// ---------------------------------------------------------------------------------------------
// the engine's own view after the refresh, independent of `f1_follow_on_wanted`
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct EngineView {
    equity: i128,
    req: u128,
    deficit: u128,
    liquidatable: bool,
    b_stale: bool,
    pending_close: bool,
    expired_close: bool,
    recovery_eligible: bool,
    resolved_winner: bool,
    live: bool,
    legs: u8,
    domains: u8,
    /// the engine's `Liquidate` of the first active leg (what the crank's plan selects) is accepted
    engine_accepts: bool,
    /// ... of EVERY active leg
    engine_accepts_all: bool,
}

fn engine_view(w: &World) -> EngineView {
    let mut refreshed = w.clone();
    let now = w.slot;
    let (equity, req, deficit, summary, live, active) = host(&mut refreshed, |(group, t, _)| {
        let cert = group.full_account_refresh_not_atomic(t).expect("engine refresh");
        let s = group.build_actionable_summary_at_slot(&t.as_view(), now).expect("summary");
        let c = t.header.health_cert.try_to_runtime().unwrap();
        let _ = cert;
        let active: Vec<usize> = (0..percolator::V16_MAX_PORTFOLIO_ASSETS_N)
            .filter(|s| t.header.legs[*s].active == 1)
            .map(|s| t.header.legs[s].asset_index.get() as usize)
            .collect();
        (c.certified_equity, c.certified_maintenance_req, c.certified_liq_deficit, s, group.header.mode == 0, active)
    });
    let accepts = |asset: usize| -> bool {
        let mut x = refreshed.clone();
        host(&mut x, |(group, t, _)| {
            group.full_account_refresh_not_atomic(t).is_ok() && group.liquidate_account_not_atomic(t, LiquidationRequestV16 { asset_index: asset }).is_ok()
        })
    };
    let engine_accepts = active.first().map(|a| accepts(*a)).unwrap_or(false);
    let engine_accepts_all = !active.is_empty() && active.iter().all(|a| accepts(*a));
    EngineView {
        equity,
        req,
        deficit,
        liquidatable: summary.liquidatable,
        b_stale: summary.b_stale,
        pending_close: summary.pending_close,
        expired_close: summary.expired_close,
        recovery_eligible: summary.recovery_eligible,
        resolved_winner: summary.resolved_winner,
        live,
        legs: active.len() as u8,
        domains: occupied(&refreshed) as u8,
        engine_accepts,
        engine_accepts_all,
    }
}

fn expected_inputs(v: &EngineView) -> f1::F1Inputs {
    f1::F1Inputs {
        first_step_certified_refresh: true,
        steps_taken: 0,
        live: v.live,
        engine_liquidatable: v.liquidatable,
        b_stale: v.b_stale,
        pending_close: v.pending_close,
        expired_close: v.expired_close,
        recovery_eligible: v.recovery_eligible,
        resolved_winner: v.resolved_winner,
        certified_equity: v.equity,
        certified_maintenance_req: v.req,
        certified_liq_deficit: v.deficit,
        vault_lp: false,
        // the engine's own truth: its liquidation of every active leg is accepted
        legs_reducible: v.engine_accepts_all,
        active_legs: v.legs,
        occupied_source_domains: v.domains,
    }
}

fn crank(w: &mut World) -> Result<(), String> {
    let ix = Instruction::PermissionlessCrank {
        now_slot: w.slot,
        observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
    };
    let mut caller = signer();
    run_ix(ix, &mut [&mut caller, &mut w.market, &mut w.t]).map_err(|e| format!("{e:?}"))
}

#[derive(Debug)]
struct Row {
    legs: u8,
    domains: u8,
    delta: i128,
    expect_fire: bool,
    fired: bool,
    ok: bool,
    engine_accepts: bool,
    verdict: &'static str,
}

/// One cell: returns the row, panicking nothing; the caller asserts the matrix.
fn run_cell(w0: &World, view_target_delta: Option<i128>) -> (Row, EngineView) {
    // choose the capital so that equity == req - delta on the refreshed state
    let mut w = w0.clone();
    let probe = engine_view(&w);
    if let Some(delta) = view_target_delta {
        let want = probe.req as i128 - delta;
        let cap = host(&mut w, |(_, t, _)| t.header.capital.get()) as i128;
        let new_cap = (cap + (want - probe.equity)).max(0);
        with_capital(&mut w, new_cap as u128);
    }
    let v = engine_view(&w);
    let inputs = expected_inputs(&v);
    let expect_fire = f1::follow_on_liquidation(&inputs);
    // refresh-only reference state (what the crank leaves if it does NOT fire)
    let mut reference = w.clone();
    host(&mut reference, |(group, t, _)| {
        group.full_account_refresh_not_atomic(t).unwrap();
    });
    let before_legs = legs(&w);
    let before_pos = positions(&w);
    let res = crank(&mut w);
    let after_pos = positions(&w);
    let fired = res.is_ok() && after_pos != before_pos;
    let ok = res.is_ok();
    let verdict = if !ok {
        if v.engine_accepts { "INSTRUCTION-FAILED (engine would accept)" } else { "INSTRUCTION-FAILED (engine refuses)" }
    } else if fired != expect_fire {
        if fired { "FIRED-BUT-NOT-EXPECTED" } else { "MISSED-FOLLOW-ON" }
    } else if fired && !v.engine_accepts {
        "FIRED-WITHOUT-ENGINE-ACCEPT"
    } else {
        "match"
    };
    let _ = before_legs;
    let delta = v.req as i128 - v.equity;
    if !ok {
        println!("  crank error: {}", res.unwrap_err());
    }
    (Row { legs: v.legs, domains: v.domains, delta, expect_fire, fired, ok, engine_accepts: v.engine_accepts, verdict }, v)
}

/// (asset, effective-size-bearing bytes) of the target: the leg table.
fn positions(w: &World) -> Vec<u8> {
    let p = state::read_portfolio(&w.t.data).unwrap();
    let mut out = vec![];
    for l in p.legs.iter() {
        out.extend_from_slice(format!("{:?}", (l.active, l.asset_index, l.basis_q, l.position_basis_q)).as_bytes());
    }
    out
}

// ---------------------------------------------------------------------------------------------
// matrix
// ---------------------------------------------------------------------------------------------

#[test]
fn f1_inputs_match_engine_matrix_legs_x_domains() {
    let mut reached = std::collections::BTreeSet::new();
    let mut bad: Vec<String> = vec![];
    for n in 1u16..=4 {
        for rev in 0..=(n as usize) {
            let base = build(n, rev);
            let (l, d) = (legs(&base), occupied(&base));
            println!("n={n} rev={rev}: legs={l} occupied domains={d}");
            // shortfalls: none, dust, around the boundary, material, deep, insolvent
            let probe = engine_view(&base);
            let ms = f1::min_shortfall(probe.req) as i128;
            for delta in [-1i128, 0, 1, ms - 1, ms, ms + 1, probe.req as i128 / 10, probe.req as i128 + 1] {
                let (row, _) = run_cell(&base, Some(delta));
                println!("  want_delta={delta:>12} -> {row:?}");
                reached.insert((row.legs, row.domains));
                if row.verdict != "match" {
                    bad.push(format!("n={n} rev={rev} {row:?}"));
                }
            }
        }
    }
    println!("cells reached (legs, domains): {reached:?}");
    assert!(bad.is_empty(), "processor inputs disagree with the engine:\n{}", bad.join("\n"));
}
