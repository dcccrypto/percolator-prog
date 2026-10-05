// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! growth-v19 fork replays (plan §2.1 worked examples): OTC, Jimothy and STONK, the three
//! listed markets whose over-levered creator LP took the crowd fills that drained it. Shows
//! that the growth gate would have CLOSED the crowd side while leaving the thin side open.
//!
//! # Method (key-free, read-only)
//! * `tests/fixtures/growth_fork/<market>.json`: READ-ONLY dumps (one `getMultipleAccounts`,
//!   one context slot) of the slab, every wrapper-owned portfolio whose `market_group_id`
//!   (offset 16) is the slab, the LP's matcher context, and the Clock sysvar. Fetcher:
//!   `tests/fixtures/growth_fork/fetch.py` (devnet relaunch wrapper `ETDLAdi…`, matcher
//!   `EDKKgRaV…`; no keys, no sends).
//! * Part 1 (pure, on the live bytes): decode the LP with the program's own decoders, compute
//!   `C_m`, the ADL-effective LP net, `N_cap = 1x * C_m / P` and `u`, and run the program's own
//!   `growth_v19::growth_gate` for a crowd-side and a thin-side open.
//! * Part 2 (LiteSVM fork): mount THIS build's wrapper at the live id and THIS build's matcher
//!   at the canonical id, load every account, and send a crowd-side TradeCpi from the market's
//!   largest non-LP portfolio (owner listed as signer, `with_sigverify(false)`; no account data
//!   rewritten to fit a signer). Run three ways: growth OFF (the slab as fetched: the NEGATIVE
//!   CONTROL), growth ON + BOUND (the opt-in rewrites: asset 0's `AssetGrowthV19` at
//!   [672, 792) with `l_launch = tier`, lambda 1x, kink 50%, AND the market's LP recorded as
//!   asset 0's bound vault LP -- the growth-1 shape since N-1) and growth ON + UNBOUND (the
//!   growth record only: every open is refused, 97). The live engine may refuse first (h-lock,
//!   loss-stale, ADL); every outcome is printed and the assertions are exactly what the
//!   bytes support.
use litesvm::LiteSVM;
use percolator::{SideV16, POS_SCALE};
use percolator_prog::{
    constants::KIND_PORTFOLIO, growth_v19, ix::Instruction as ProgInstruction, risk_limits_v17,
    state,
};
use solana_program::pubkey;
use solana_sdk::{
    account::Account,
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;

const WRAPPER_ID: Pubkey = pubkey!("ETDLAdiAyWnEUngspYczTXUceT6X8f92eZQvr8nmSkWB");
const MATCHER_ID: Pubkey = pubkey!("EDKKgRaVHna6FCxiY1kgMzegD9rpaN1nwJNSzAzeBUBX");
const GROWTH_CAPACITY_FULL: u32 = 93;
const GROWTH_REQUIRES_BOUND_VAULT_LP: u32 = 97;

fn so(path: &str) -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(path);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64 byte {c}"),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=' && *c != b'\n').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c) << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if chunk.len() > 2 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(acc as u8);
        }
    }
    out
}

struct Fixture {
    name: String,
    slab: Pubkey,
    clock: Clock,
    accounts: Vec<(Pubkey, Account)>,
}

fn load(name: &str) -> Fixture {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(format!("tests/fixtures/growth_fork/{name}.json"));
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        v["wrapper_program"].as_str().unwrap(),
        WRAPPER_ID.to_string()
    );
    let clock: Clock = bincode::deserialize(&b64(v["clock_sysvar_b64"].as_str().unwrap())).unwrap();
    let accounts = v["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["pubkey"].as_str().unwrap().parse().unwrap(),
                Account {
                    lamports: a["lamports"].as_u64().unwrap(),
                    data: b64(a["data_b64"].as_str().unwrap()),
                    owner: a["owner"].as_str().unwrap().parse().unwrap(),
                    executable: a["executable"].as_bool().unwrap(),
                    rent_epoch: 0,
                },
            )
        })
        .collect();
    Fixture {
        name: name.to_string(),
        slab: v["slab"].as_str().unwrap().parse().unwrap(),
        clock,
        accounts,
    }
}

fn data<'a>(fx: &'a Fixture, k: &Pubkey) -> &'a [u8] {
    &fx.accounts.iter().find(|(kk, _)| kk == k).unwrap().1.data
}

fn portfolios(fx: &Fixture) -> Vec<Pubkey> {
    fx.accounts
        .iter()
        .filter(|(_, a)| a.owner == WRAPPER_ID && a.data.len() > 10 && a.data[10] == KIND_PORTFOLIO)
        .map(|(k, _)| *k)
        .collect()
}

/// The LP: the portfolio with an ENABLED matcher config.
fn lp_of(fx: &Fixture) -> Pubkey {
    let lps: Vec<Pubkey> = portfolios(fx)
        .into_iter()
        .filter(|k| {
            state::read_portfolio_matcher_config(data(fx, k))
                .unwrap()
                .enabled()
                == 1
        })
        .collect();
    assert_eq!(lps.len(), 1, "{}: exactly one matcher LP", fx.name);
    lps[0]
}

/// (raw signed, ADL-effective signed) position on asset 0, via the program's own port of the
/// engine's `kernel_adl_effective_quantity_ceil`.
fn positions(fx: &Fixture, portfolio: &Pubkey) -> (i128, i128) {
    let (_, g) = state::read_market(data(fx, &fx.slab)).unwrap();
    let p = state::read_portfolio(data(fx, portfolio)).unwrap();
    for l in p.legs.iter().filter(|l| l.active && l.asset_index == 0) {
        let raw = l.basis_pos_q.unsigned_abs();
        let (a, epoch) = match l.side {
            SideV16::Long => (g.assets[0].a_long, g.assets[0].epoch_long),
            SideV16::Short => (g.assets[0].a_short, g.assets[0].epoch_short),
        };
        let eff = if l.epoch_snap == epoch {
            risk_limits_v17::adl_effective_abs_q(raw, l.a_basis, a).unwrap()
        } else {
            0
        };
        let s = if l.side == SideV16::Long { 1 } else { -1 };
        if std::env::var_os("GROWTH_FORK_DEBUG").is_some() {
            eprintln!(
                "  leg {:?} raw {raw} eff {eff} snap {} epoch {epoch} a_basis {} a {a}",
                l.side, l.epoch_snap, l.a_basis
            );
        }
        return (s * raw as i128, s * eff as i128);
    }
    (0, 0)
}

fn conservative_equity(fx: &Fixture, portfolio: &Pubkey) -> u128 {
    let p = state::read_portfolio(data(fx, portfolio)).unwrap();
    percolator_prog::vault_lp_v18::conservative_equity(p.capital, p.pnl, p.fee_credits).unwrap()
}

struct Live {
    lp: Pubkey,
    lp_eff: i128,
    c_m: u128,
    price: u64,
    imr: u64,
    n_cap: u128,
    hlock: bool,
}

fn live(fx: &Fixture) -> Live {
    let (_, g) = state::read_market(data(fx, &fx.slab)).unwrap();
    let lp = lp_of(fx);
    let (_, lp_eff) = positions(fx, &lp);
    let c_m = conservative_equity(fx, &lp);
    let price = g.assets[0].effective_price;
    let n_cap = growth_v19::n_cap_q(c_m, growth_v19::DEFAULT_LAMBDA_BPS, price, POS_SCALE).unwrap();
    Live {
        lp,
        lp_eff,
        c_m,
        price,
        imr: g.config.initial_margin_bps,
        n_cap,
        hlock: g.bankruptcy_hlock_active,
    }
}

/// The program's own gate for a 1,000-unit crowd-side and thin-side open against an LP with
/// conservative equity `c_m` and ADL-effective net `lp_eff`, at the engine IMR tier (10x here).
fn gate_verdicts(
    c_m: u128,
    lp_eff: i128,
    price: u64,
    imr: u64,
) -> (growth_v19::GrowthVerdict, growth_v19::GrowthVerdict) {
    let crowd_dir: i128 = if lp_eff < 0 { 1 } else { -1 };
    // N-1: the thin side is capacity-bounded too (its users OI <= N_cap), so the probe open is
    // 1,000 units or a tenth of N_cap, whichever is smaller.
    let n = growth_v19::n_cap_q(c_m, growth_v19::DEFAULT_LAMBDA_BPS, price, POS_SCALE).unwrap();
    let size = core::cmp::min(1_000 * POS_SCALE, n / 10) as i128;
    let ceil =
        growth_v19::ceiling_imr_bps(imr, growth_v19::leverage_x100_for_imr_bps(imr).unwrap())
            .unwrap();
    let gate = |taker_size: i128| {
        let lp_after = lp_eff - taker_size;
        growth_v19::growth_gate(&growth_v19::GrowthGateIn {
            taker_before_q: 0,
            taker_after_q: taker_size,
            taker_eff_after_abs_q: taker_size.unsigned_abs(),
            taker_equity: u128::MAX / 4, // ANY equity: the crowd refusal is capacity, not margin
            taker_cert_initial_req: None,
            lp: Some(growth_v19::GrowthLpIn {
                before_q: lp_eff,
                mid_q: lp_eff, // an open from flat has no reducing part
                after_q: lp_after,
                eff_after_abs_q: lp_after.unsigned_abs(),
                // N-1: users OI on the taker's side. The snapshot has no per-side OI, so the
                // crowd side uses |LP_after| (a LOWER bound of the crowd's users OI: the
                // CapacityFull verdict is therefore sound) and the thin side the taker's own
                // open (the thin side's prior OI is not recorded; Part 2 uses the slab's real OI).
                users_oi_side_after_q: if (taker_size > 0) == (lp_eff < 0) {
                    lp_after.unsigned_abs()
                } else {
                    taker_size.unsigned_abs()
                },
                equity: c_m,
            }),
            price_e6: price,
            pos_scale: POS_SCALE,
            engine_imr_bps: imr,
            min_nonzero_im_req: 0,
            ceil_imr_bps: ceil,
            lambda_bps: growth_v19::DEFAULT_LAMBDA_BPS,
            kink_bps: growth_v19::DEFAULT_KINK_BPS,
            crowd_blocked: false, // capacity alone; the h-lock is not needed for the verdict
            asset_bound: true,    // as if bound (growth-1 admits opens only there)
        })
    };
    (gate(crowd_dir * size), gate(-crowd_dir * size))
}

fn u_display(c_m: u128, lp_eff: i128, price: u64) -> (u128, String) {
    let n = growth_v19::n_cap_q(c_m, growth_v19::DEFAULT_LAMBDA_BPS, price, POS_SCALE).unwrap();
    let u_bps = if n == 0 {
        u128::MAX
    } else {
        lp_eff.unsigned_abs() * 10_000 / n
    };
    (n, format!("{}.{:02}%", u_bps / 100, u_bps % 100))
}

/// Part 1a: the 10-04 audit snapshot (slot 507,235,567), when all three LPs still held the
/// crowd's inventory. Inputs are the audit's recorded live fields (fixture provenance in the
/// JSON); C_m = capital + min(pnl, 0) (all three had positive PnL, which gets no credit).
#[test]
fn growth_fork_replay_audit_snapshot_closes_all_three_crowds() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/growth_fork/audit_snapshot_507235567.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
    let num = |x: &serde_json::Value| -> i128 { x.as_str().unwrap().parse().unwrap() };
    let mut seen = 0;
    for name in ["otc", "jimothy", "stonk"] {
        let m = &v["markets"][name];
        let pnl = num(&m["lp_pnl"]);
        let c_m = percolator_prog::vault_lp_v18::conservative_equity(
            num(&m["lp_capital"]) as u128,
            pnl,
            0,
        )
        .unwrap();
        let lp_eff = num(&m["lp_eff_q"]);
        let price = num(&m["price_e6"]) as u64;
        let imr = num(&m["initial_margin_bps"]) as u64;
        let (n, u) = u_display(c_m, lp_eff, price);
        let (crowd, thin) = gate_verdicts(c_m, lp_eff, price, imr);
        eprintln!("[audit {name}] C_m {c_m} LP eff {lp_eff} @ {price} -> N_cap {n}, u = {u}: crowd {crowd:?}, thin {thin:?}");
        assert!(lp_eff.unsigned_abs() >= n, "{name}: u >= 1");
        assert_eq!(
            crowd,
            growth_v19::GrowthVerdict::CapacityFull,
            "{name}: the crowd side would have been closed"
        );
        assert_eq!(
            thin,
            growth_v19::GrowthVerdict::Allow,
            "{name}: the thin side stays open"
        );
        // NEGATIVE CONTROL: the same LP with 20x the capital is within capacity.
        let (crowd_rich, _) = gate_verdicts(c_m * 20, lp_eff, price, imr);
        assert_ne!(
            crowd_rich,
            growth_v19::GrowthVerdict::CapacityFull,
            "{name}: capital opens the crowd side"
        );
        seen += 1;
    }
    assert_eq!(seen, 3);
}

// ── Part 2: LiteSVM fork ────────────────────────────────────────────────────

/// Growth rewrites on the fetched slab: `Off` (as fetched, the NEGATIVE CONTROL), `Bound`
/// (growth record + the market's LP recorded as asset 0's BOUND vault LP: the growth-1 shape,
/// opens are admitted only there since N-1) and `Unbound` (growth record only).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Growth {
    Off,
    Bound,
    Unbound,
}

fn fork(fx: &Fixture, growth: Growth) -> LiteSVM {
    let growth_on = growth != Growth::Off;
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.add_program(WRAPPER_ID, &so("target/deploy/percolator_prog.so"));
    svm.add_program(
        MATCHER_ID,
        &so("../percolator-match/target/deploy/percolator_match.so"),
    );
    for (k, a) in &fx.accounts {
        let mut a = a.clone();
        if growth_on && *k == fx.slab {
            let (_, g) = state::read_market(&a.data).unwrap();
            let imr = g.config.initial_margin_bps;
            let tier = growth_v19::leverage_x100_for_imr_bps(imr).unwrap();
            let rec = state::AssetGrowthV19 {
                lambda_bps: growth_v19::DEFAULT_LAMBDA_BPS,
                l_launch_x100: tier,
                l_tier_x100: tier,
                ceil_x100: tier,
                kink_bps: growth_v19::DEFAULT_KINK_BPS,
                r_gap_bps: 400,
                version: growth_v19::GROWTH_VERSION,
                ..Default::default()
            };
            let r = state::asset_growth_range(&a.data, 0).unwrap();
            let slot0 = r.start - percolator_prog::constants::ASSET_GROWTH_OFF;
            let slot_end = slot0 + percolator_prog::constants::ASSET_ORACLE_WRAPPER_LEN;
            state::asset_growth_to_wrapper_bytes(&mut a.data[slot0..slot_end], &rec, imr).unwrap();
            if growth == Growth::Bound {
                let mut v = state::read_asset_vault_lp(&a.data, 0).unwrap();
                v.vault_lp_portfolio = lp_of(fx).to_bytes();
                v.flags |= state::ASSET_VAULT_LP_FLAG_BOUND;
                state::asset_vault_lp_to_wrapper_bytes(&mut a.data[slot0..slot_end], &v).unwrap();
            }
        }
        svm.set_account(*k, a).unwrap();
    }
    svm.set_sysvar(&fx.clock);
    svm
}

fn trade_cpi(
    svm: &mut LiteSVM,
    fx: &Fixture,
    taker: &Pubkey,
    lp: &Pubkey,
    size_q: i128,
) -> Result<(), TransactionError> {
    let md = svm.get_account(&fx.slab).unwrap().data;
    let (cfg, _, _, market_id, _, _) = state::read_market_trade_preflight(&md, 0).unwrap();
    let td = svm.get_account(taker).unwrap().data;
    let ld = svm.get_account(lp).unwrap().data;
    let owner = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&td).unwrap().1);
    let mcfg = state::read_portfolio_matcher_config(&ld).unwrap();
    let ix = Instruction {
        program_id: WRAPPER_ID,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(fx.slab, false),
            AccountMeta::new(*taker, false),
            AccountMeta::new(*lp, false),
            AccountMeta::new_readonly(Pubkey::new_from_array(mcfg.matcher_program), false),
            AccountMeta::new(Pubkey::new_from_array(mcfg.matcher_context), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(mcfg.matcher_delegate), false),
        ],
        data: ProgInstruction::TradeCpi {
            account_a_portfolio_id: state::read_portfolio_id(&td).unwrap(),
            account_a_position_epoch: state::read_portfolio_position_epoch(&td).unwrap(),
            account_b_portfolio_id: state::read_portfolio_id(&ld).unwrap(),
            account_b_position_epoch: state::read_portfolio_position_epoch(&ld).unwrap(),
            market_id,
            account_b_matcher_sequence: state::read_portfolio_matcher_sequence(&ld).unwrap(),
            asset_index: 0,
            size_q,
            fee_bps: cfg.trade_fee_base_bps,
            limit_price: 0,
            backing_fee_cap_bps: 10_000,
        }
        .encode(),
    };
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    svm.expire_blockhash();
    let msg = Message::new(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        Some(&payer.pubkey()),
    );
    let mut tx = Transaction::new_unsigned(msg);
    tx.signatures = vec![Signature::default(); tx.message.header.num_required_signatures as usize];
    tx.partial_sign(&[&payer], svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|f| f.err)
}

/// The largest-capital non-LP portfolio (the taker for the fork trades).
fn taker_of(fx: &Fixture, lp: &Pubkey) -> Pubkey {
    portfolios(fx)
        .into_iter()
        .filter(|k| k != lp)
        .max_by_key(|k| state::read_portfolio(data(fx, k)).unwrap().capital)
        .unwrap()
}

fn custom(r: &Result<(), TransactionError>) -> Option<u32> {
    match r {
        Err(TransactionError::InstructionError(2, InstructionError::Custom(c))) => Some(*c),
        _ => None,
    }
}

fn raw_pos(svm: &LiteSVM, k: &Pubkey) -> i128 {
    let p = state::read_portfolio(&svm.get_account(k).unwrap().data).unwrap();
    p.legs
        .iter()
        .find(|l| l.active && l.asset_index == 0)
        .map(|l| match l.side {
            SideV16::Long => l.basis_pos_q.unsigned_abs() as i128,
            SideV16::Short => -(l.basis_pos_q.unsigned_abs() as i128),
        })
        .unwrap_or(0)
}

/// TradeNoCpi (no clip): taker vs the LP portfolio, both owners as (fake) signers.
fn trade_nocpi(
    svm: &mut LiteSVM,
    fx: &Fixture,
    taker: &Pubkey,
    lp: &Pubkey,
    size_q: i128,
) -> Result<(), TransactionError> {
    let md = svm.get_account(&fx.slab).unwrap().data;
    let (cfg, _, _, market_id, _, _) = state::read_market_trade_preflight(&md, 0).unwrap();
    let (_, g) = state::read_market(&md).unwrap();
    let td = svm.get_account(taker).unwrap().data;
    let ld = svm.get_account(lp).unwrap().data;
    let owner_a = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&td).unwrap().1);
    let owner_b = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&ld).unwrap().1);
    let ix = Instruction {
        program_id: WRAPPER_ID,
        accounts: vec![
            AccountMeta::new(owner_a, true),
            AccountMeta::new(owner_b, true),
            AccountMeta::new(fx.slab, false),
            AccountMeta::new(*taker, false),
            AccountMeta::new(*lp, false),
        ],
        data: ProgInstruction::TradeNoCpi {
            account_a_portfolio_id: state::read_portfolio_id(&td).unwrap(),
            account_a_position_epoch: state::read_portfolio_position_epoch(&td).unwrap(),
            account_b_portfolio_id: state::read_portfolio_id(&ld).unwrap(),
            account_b_position_epoch: state::read_portfolio_position_epoch(&ld).unwrap(),
            market_id,
            asset_index: 0,
            size_q,
            exec_price: g.assets[0].effective_price,
            fee_bps: cfg.trade_fee_base_bps,
            backing_fee_cap_bps: 10_000,
        }
        .encode(),
    };
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    svm.expire_blockhash();
    let msg = Message::new(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        Some(&payer.pubkey()),
    );
    let mut tx = Transaction::new_unsigned(msg);
    tx.signatures = vec![Signature::default(); tx.message.header.num_required_signatures as usize];
    tx.partial_sign(&[&payer], svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ()).map_err(|f| f.err)
}

/// One open on a fresh fork; returns (outcome, taker fill).
fn open(
    fx: &Fixture,
    growth: Growth,
    nocpi: bool,
    taker: &Pubkey,
    lp: &Pubkey,
    size: i128,
) -> (Result<(), TransactionError>, i128) {
    let mut svm = fork(fx, growth);
    let before = raw_pos(&svm, taker);
    let r = if nocpi {
        trade_nocpi(&mut svm, fx, taker, lp, size)
    } else {
        trade_cpi(&mut svm, fx, taker, lp, size)
    };
    (r, raw_pos(&svm, taker) - before)
}

/// Part 2 (live bytes at the fetch slot). Growth is NEVER looser than the live market, and
/// with LP inventory above capacity the crowd side is closed: zero fill on TradeCpi (the LP
/// headroom IS N_cap), GrowthCapacityFull on the unclipped TradeNoCpi.
fn replay(name: &str) {
    let fx = load(name);
    let l = live(&fx);
    let taker = taker_of(&fx, &l.lp);
    let (n, u) = u_display(l.c_m, l.lp_eff, l.price);
    eprintln!(
        "[{}] live: LP {} C_m {} LP eff {} @ {} -> N_cap {n}, u = {u}, hlock {}",
        fx.name, l.lp, l.c_m, l.lp_eff, l.price, l.hlock
    );
    let crowd_dir: i128 = if l.lp_eff < 0 { 1 } else { -1 };
    let size = 100 * POS_SCALE as i128;
    for (dir, side) in [(crowd_dir, "crowd/long-if-LP-flat"), (-crowd_dir, "thin")] {
        for nocpi in [false, true] {
            let (r_off, f_off) = open(&fx, Growth::Off, nocpi, &taker, &l.lp, dir * size);
            let (r_on, f_on) = open(&fx, Growth::Bound, nocpi, &taker, &l.lp, dir * size);
            eprintln!(
                "[{}] {side} {}: growth OFF -> {:?} fill {f_off}; growth ON -> {:?} fill {f_on}",
                fx.name,
                if nocpi { "TradeNoCpi" } else { "TradeCpi" },
                r_off,
                r_on
            );
            // N-1: growth-1 admits opens only against a BOUND vault LP. On the same slab with
            // the growth record but no bind, every open the live market would fill is refused
            // with GrowthRequiresBoundVaultLp.
            let (r_unb, f_unb) = open(&fx, Growth::Unbound, nocpi, &taker, &l.lp, dir * size);
            eprintln!(
                "[{}] {side} {}: growth ON, UNBOUND -> {:?} fill {f_unb}",
                fx.name,
                if nocpi { "TradeNoCpi" } else { "TradeCpi" },
                r_unb
            );
            // The probe is an OPEN for the taker unless it reduces the taker's own position
            // (the fixture's largest portfolio may already sit on the crowd side).
            let taker_eff = positions(&fx, &taker).1;
            let opens = growth_v19::taker_risk_increasing(taker_eff, taker_eff + dir * size);
            if opens {
                assert_eq!(f_unb, 0, "{}: unbound growth fills no open", fx.name);
                // TradeCpi may answer a zero fill first (the matcher's closed mode under the
                // h-lock, or the N_cap headroom clip); the unclipped NoCpi route names the
                // refusal wherever the live engine would have filled it.
                if nocpi && r_off.is_ok() && f_off != 0 {
                    assert_eq!(
                        custom(&r_unb),
                        Some(GROWTH_REQUIRES_BOUND_VAULT_LP),
                        "{}: unbound",
                        fx.name
                    );
                }
            } else {
                // reductions are never refused by growth (M-1), bound or not
                assert_eq!(
                    (r_unb.is_ok(), f_unb),
                    (r_off.is_ok(), f_off),
                    "{}: unbound reduce",
                    fx.name
                );
                assert_eq!(
                    (r_on.is_ok(), f_on),
                    (r_off.is_ok(), f_off),
                    "{}: bound reduce",
                    fx.name
                );
            }
            // never looser than the live market
            if r_on.is_ok() {
                assert!(
                    r_off.is_ok(),
                    "{}: growth accepted what the live market refused",
                    fx.name
                );
                assert!(
                    f_on.unsigned_abs() <= f_off.unsigned_abs(),
                    "{}: growth filled more than live",
                    fx.name
                );
            }
        }
    }
    if l.lp_eff.unsigned_abs() >= n && l.lp_eff != 0 {
        // u >= 1 on the live bytes: the crowd side gets no fill under growth...
        let (r_cpi, f_cpi) = open(&fx, Growth::Bound, false, &taker, &l.lp, crowd_dir * size);
        assert!(
            r_cpi.is_err() || f_cpi == 0,
            "{}: crowd TradeCpi gets no fill",
            fx.name
        );
        // ...and where the live engine would still ACCEPT the unclipped NoCpi fill, growth names
        // the refusal (where the live engine already refuses first -- h-lock / ADL / loss-stale
        // -- the "never looser" check above covers it).
        let (r_live, _) = open(&fx, Growth::Off, true, &taker, &l.lp, crowd_dir * size);
        let (r_nocpi, _) = open(&fx, Growth::Bound, true, &taker, &l.lp, crowd_dir * size);
        if r_live.is_ok() {
            assert_eq!(
                custom(&r_nocpi),
                Some(GROWTH_CAPACITY_FULL),
                "{}: crowd TradeNoCpi named refusal",
                fx.name
            );
        }
    }
    if l.lp_eff == 0 && l.hlock {
        // Flat LP + latched market h-lock: every open grows |LP| (joins the "crowd"), and the
        // plan's rule closes LP growth while the h-lock is on -> growth closes BOTH sides.
        let (r, f) = open(&fx, Growth::Bound, true, &taker, &l.lp, size);
        let (r2, f2) = open(&fx, Growth::Bound, true, &taker, &l.lp, -size);
        assert!(
            r.is_err() && r2.is_err() && f == 0 && f2 == 0,
            "{}: h-lock closes LP growth",
            fx.name
        );
    }
}

#[test]
fn growth_fork_replay_otc() {
    replay("otc");
}

#[test]
fn growth_fork_replay_jimothy() {
    replay("jimothy");
}

#[test]
fn growth_fork_replay_stonk() {
    replay("stonk");
}

#[test]
#[ignore = "diagnostic: GROWTH_FORK_DEBUG=1 cargo test -- --ignored growth_fork_dump"]
fn growth_fork_dump() {
    for n in ["otc", "stonk", "jimothy"] {
        let fx = load(n);
        let (_, g) = state::read_market(data(&fx, &fx.slab)).unwrap();
        eprintln!(
            "== {n}: price {} oi L {} S {} hlock {} epoch L {} S {}",
            g.assets[0].effective_price,
            g.assets[0].oi_eff_long_q,
            g.assets[0].oi_eff_short_q,
            g.bankruptcy_hlock_active,
            g.assets[0].epoch_long,
            g.assets[0].epoch_short
        );
        for k in portfolios(&fx) {
            let p = state::read_portfolio(data(&fx, &k)).unwrap();
            let en = state::read_portfolio_matcher_config(data(&fx, &k))
                .unwrap()
                .enabled();
            let (raw, eff) = positions(&fx, &k);
            eprintln!(
                "  {k} lp_enabled {en} cap {} pnl {} fee {} raw {raw} eff {eff}",
                p.capital, p.pnl, p.fee_credits
            );
        }
    }
}

/// ADL-effective signed position of `k` on asset 0, read from the fork's CURRENT state.
fn eff_pos_svm(svm: &LiteSVM, slab: &Pubkey, k: &Pubkey) -> i128 {
    let (_, g) = state::read_market(&svm.get_account(slab).unwrap().data).unwrap();
    let p = state::read_portfolio(&svm.get_account(k).unwrap().data).unwrap();
    for l in p.legs.iter().filter(|l| l.active && l.asset_index == 0) {
        let (a, epoch) = match l.side {
            SideV16::Long => (g.assets[0].a_long, g.assets[0].epoch_long),
            SideV16::Short => (g.assets[0].a_short, g.assets[0].epoch_short),
        };
        let eff = if l.epoch_snap == epoch {
            risk_limits_v17::adl_effective_abs_q(l.basis_pos_q.unsigned_abs(), l.a_basis, a)
                .unwrap()
        } else {
            0
        };
        return if l.side == SideV16::Long {
            eff as i128
        } else {
            -(eff as i128)
        };
    }
    0
}

/// Q2 (re-verification): the TAKER_REDUCING classification of a growth leg is made on the
/// ADL-EFFECTIVE position. Jimothy's largest portfolio is long with A ~ 0.53 (raw 203,125 /
/// effective 107,980 units). A sell of `eff + 10` units over-closes the effective position
/// although it only "reduces" the raw basis: on the growth (bound) fork the single route
/// clips it to exactly the close (the taker ends FLAT); it is not marked reducing and passed
/// through as a close that turns into an unmarked 10-unit short. NEGATIVE CONTROL: mutant
/// `q2-raw` (classify on the raw basis) -- the taker ends short and this test fails.
#[test]
fn growth_fork_q2_reduce_bit_is_effective_jimothy() {
    let fx = load("jimothy");
    let l = live(&fx);
    let taker = taker_of(&fx, &l.lp);
    let (raw, eff) = positions(&fx, &taker);
    assert!(
        eff > 0 && raw > eff,
        "fixture carries an ADL haircut: raw {raw} eff {eff}"
    );
    let over = eff + 10 * POS_SCALE as i128;
    assert!(over < raw, "the probe sits inside the haircut");
    let mut svm = fork(&fx, Growth::Bound);
    let r = trade_cpi(&mut svm, &fx, &taker, &l.lp, -over);
    let after = eff_pos_svm(&svm, &fx.slab, &taker);
    eprintln!("[jimothy Q2] sell eff+10 ({over}) on growth: {r:?} -> taker eff {eff} -> {after}");
    assert!(r.is_ok(), "the close fills");
    assert_eq!(
        after, 0,
        "clipped to exactly the effective close, never an unmarked flip"
    );
    // the legacy market (growth OFF) is unchanged by growth-v19: report what it does
    let mut off = fork(&fx, Growth::Off);
    let r0 = trade_cpi(&mut off, &fx, &taker, &l.lp, -over);
    eprintln!(
        "[jimothy Q2] growth OFF: {r0:?} -> taker eff {}",
        eff_pos_svm(&off, &fx.slab, &taker)
    );
}

/// Kani rev 5 (b), the R11 modelling assumption: the engine's aggregate effective OI per side
/// equals the sum of the per-leg ADL-effective positions (up to per-leg rounding dust), so
/// `users_side_oi_q(oi_eff_side, vault_lp_eff)` is the users' summed effective legs. Checked on
/// a REAL post-ADL state (Jimothy: A_long ~ 0.53, A_short ~ 0.66 on the live fixture) loaded in
/// LiteSVM, before and after an engine-applied fill on the fork.
#[test]
fn growth_fork_oi_eff_equals_sum_of_effective_legs_after_adl() {
    let fx = load("jimothy");
    let l = live(&fx);
    let check = |svm: &LiteSVM, what: &str| {
        let (_, g) = state::read_market(&svm.get_account(&fx.slab).unwrap().data).unwrap();
        let a = &g.assets[0];
        assert!(
            a.a_long < 1_000_000_000_000_000 && a.a_short < 1_000_000_000_000_000,
            "{what}: the fixture is post-ADL (A < 1)"
        );
        let (mut long, mut short, mut legs) = (0u128, 0u128, 0u128);
        let mut users_long = 0u128;
        let mut users_short = 0u128;
        for k in portfolios(&fx) {
            let e = eff_pos_svm(svm, &fx.slab, &k);
            if e != 0 {
                legs += 1;
            }
            if e > 0 {
                long += e.unsigned_abs();
            } else {
                short += e.unsigned_abs();
            }
            if k != l.lp {
                if e > 0 {
                    users_long += e.unsigned_abs();
                } else {
                    users_short += e.unsigned_abs();
                }
            }
        }
        let lp_eff = eff_pos_svm(svm, &fx.slab, &l.lp);
        let ul = growth_v19::users_side_oi_q(a.oi_eff_long_q, lp_eff, true);
        let us = growth_v19::users_side_oi_q(a.oi_eff_short_q, lp_eff, false);
        eprintln!(
            "[jimothy OI {what}] oi_eff L {} S {} | sum eff legs L {long} S {short} ({legs} legs) | users L {ul} vs {users_long}, S {us} vs {users_short}",
            a.oi_eff_long_q, a.oi_eff_short_q
        );
        assert!(long.abs_diff(a.oi_eff_long_q) <= legs, "{what}: long side");
        assert!(
            short.abs_diff(a.oi_eff_short_q) <= legs,
            "{what}: short side"
        );
        assert!(
            ul.abs_diff(users_long) <= legs && us.abs_diff(users_short) <= legs,
            "{what}: users OI"
        );
    };
    let mut svm = fork(&fx, Growth::Bound);
    check(&svm, "fixture");
    let taker = taker_of(&fx, &l.lp);
    let r = trade_cpi(&mut svm, &fx, &taker, &l.lp, -10 * POS_SCALE as i128);
    assert!(r.is_ok(), "a reduce fills: {r:?}");
    check(&svm, "after a fill");
}
