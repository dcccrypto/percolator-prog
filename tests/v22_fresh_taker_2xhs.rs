//! QA 2026-10-15 20:48 (v2.2 fresh-taker CU / Custom 121), replayed on LiteSVM from a consistent devnet
//! snapshot of the multi-asset market 2xhsLP9N… (5 AUTH_MARK assets, cap 4) at slot 511,474,461:
//! the LP 6w14eZR3… and the peer GV86syBh… each hold 4 legs; JB5PkWDs… is a flat (fresh) taker.
//!
//! What it pins (program unchanged; the fix is the CLIENT / KEEPER transaction shape):
//!  * the old SDK Q-7 shape [LP observing every asset, (taker), LP, trade] for a fresh taker is refused
//!    Custom(121): its own accrual moves K and re-stales the peer;
//!  * adding the peer refresh in Q-7 order refreshes the LP twice and runs out of the 1.4M budget;
//!  * the keeper's atomic round [peer observing every asset, LP refresh-only LAST] fits with margin and
//!    leaves every positioned portfolio current; after it a fresh taker's [Deposit, TradeCpi] (no crank)
//!    opens every asset inside FRESH_TAKER_OPEN_CU_BUDGET;
//!  * with a stale peer, the 2-tx flow (tx1 = that round, tx2 = [Deposit, TradeCpi] in a later slot) works;
//!  * a hint-less crank in a LATER slot advances the market clock through one asset only and makes the
//!    other exposed assets loss-stale (why the keeper/app must never send one alone on a multi-asset market).
//! Wrapper: P1_WRAPPER_SO or target/deploy; matcher: SYNC_MATCHER_SO or ../percolator-match/target/deploy.
#![cfg(not(kani))]
use litesvm::LiteSVM;
use percolator_prog::{
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    state,
};
use solana_sdk::{
    account::Account,
    clock::Clock,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    message::Message,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Signature,
    transaction::Transaction,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v22_fresh_taker/2xhs-511474461.json")
}
fn wrapper_path() -> PathBuf {
    std::env::var_os("P1_WRAPPER_SO").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_prog.so"))
}
fn matcher_path() -> PathBuf {
    std::env::var_os("SYNC_MATCHER_SO").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../percolator-match/target/deploy/percolator_match.so"))
}
fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const WRAPPER: &str = "6kpg2wi7vwkn7E9rvodXSktYRhna8TWjiZrC1dBek6NM";
const MATCHER: &str = "AsHvEJ8zNctKmdeS57H5E4w6nkTLi3bPVpd6ZCLc2ayN";
const ORACLE_AUTH: &str = "FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7";
const TAKER_OWNER: &str = "62BPRR33QdRsq11tmQPEhW5LzpnuVz4sFfHmQqQtz15g";

struct Env {
    svm: LiteSVM,
    w: Pubkey,
    m: Pubkey,
    payer: Pubkey,
    k: HashMap<String, Pubkey>,
    slot: u64,
    ts: i64,
    taker_ata: Pubkey,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TxOut {
    err: Option<String>,
    total: u64,
    per: Vec<(String, u64)>,
    logs: Vec<String>,
}

impl Env {
    fn new() -> Self {
        let snap: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap();
        let slot = snap["slot"].as_u64().unwrap();
        let mut svm = LiteSVM::new().with_sigverify(false).with_transaction_history(0);
        let w = pk(WRAPPER);
        let m = pk(MATCHER);
        svm.add_program(w, &std::fs::read(wrapper_path()).expect("wrapper BPF"));
        svm.add_program(m, &std::fs::read(matcher_path()).expect("matcher BPF"));
        let mut k = HashMap::new();
        for (name, a) in snap["accounts"].as_object().unwrap() {
            let key = pk(a["pubkey"].as_str().unwrap());
            k.insert(name.clone(), key);
            if a.get("missing").is_some() {
                continue;
            }
            svm.set_account(key, Account {
                lamports: a["lamports"].as_u64().unwrap(),
                data: hex(a["data"].as_str().unwrap()),
                owner: pk(a["owner"].as_str().unwrap()),
                executable: false,
                rent_epoch: 0,
            }).unwrap();
        }
        let payer = Pubkey::new_unique();
        svm.airdrop(&payer, 100_000_000_000).unwrap();
        for s in [ORACLE_AUTH, TAKER_OWNER] {
            svm.airdrop(&pk(s), 10_000_000_000).unwrap();
        }
        // taker token account with 1,000 sUSDC
        let taker_ata = Pubkey::new_unique();
        let mut data = vec![0u8; spl_token::state::Account::LEN];
        spl_token::state::Account {
            mint: k["mint"],
            owner: pk(TAKER_OWNER),
            amount: 1_000_000_000,
            delegate: COption::None,
            state: spl_token::state::AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }.pack_into_slice(&mut data);
        svm.set_account(taker_ata, Account { lamports: 10_000_000, data, owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let mut e = Env { svm, w, m, payer, k, slot, ts, taker_ata };
        e.set_slot(slot);
        e
    }
    fn set_slot(&mut self, s: u64) {
        self.svm.warp_to_slot(s);
        let mut c: Clock = self.svm.get_sysvar();
        c.slot = s;
        c.unix_timestamp = self.ts + ((s as i64 - self.slot as i64) * 4) / 10;
        self.svm.set_sysvar(&c);
    }
    fn data(&self, name: &str) -> Vec<u8> {
        self.svm.get_account(&self.k[name]).unwrap().data
    }
    fn market_id(&self, asset: u16) -> u64 {
        state::read_market_trade_preflight(&self.data("market"), asset as usize).map(|t| t.3).unwrap()
    }
    fn obs_seq(&self, asset: u16) -> u64 {
        state::read_asset_control_sequences(&self.data("market"), asset as usize).unwrap().oracle_observation
    }
    #[allow(dead_code)]
    fn describe(&self, tag: &str) {
        let mut d = self.data("market");
        let (_, group) = state::market_view_mut(&mut d).unwrap();
        let h = &group.header;
        println!("FTCFG max_abs_funding_e9_per_slot {} rent_max_e9_per_slot {} max_price_move_bps_per_slot {} max_accrual_dt {}",
            h.config.max_abs_funding_e9_per_slot.get(), h.config.rent_max_e9_per_slot.get(), h.config.max_price_move_bps_per_slot.get(), h.config.max_accrual_dt_slots.get());
        println!(
            "FTSTATE {tag}: clock {} current_slot {} epochs oracle {} funding {} risk {} asset_set {}",
            self.svm.get_sysvar::<Clock>().slot, h.current_slot.get(), h.oracle_epoch.get(), h.funding_epoch.get(), h.risk_epoch.get(), h.asset_set_epoch.get()
        );
        for i in 0..5 {
            let a = &group.markets[i].engine.asset;
            println!(
                "FTSTATE {tag}:   a{i} slot_last {} eff {} target {} stale L/S {}/{} stored L/S {}/{} kf_epoch L/S {}/{}",
                a.slot_last.get(), a.effective_price.get(), a.raw_oracle_target_price.get(),
                a.stale_account_count_long.get(), a.stale_account_count_short.get(),
                a.stored_pos_count_long.get(), a.stored_pos_count_short.get(),
                a.kf_epoch_long.get(), a.kf_epoch_short.get()
            );
        }
    }
    fn send(&mut self, label: &str, ixs: Vec<(String, Instruction)>) -> TxOut {
        let mut all = vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ];
        let names: Vec<String> = ixs.iter().map(|x| x.0.clone()).collect();
        all.extend(ixs.into_iter().map(|x| x.1));
        let msg = Message::new(&all, Some(&self.payer));
        let mut tx = Transaction::new_unsigned(msg.clone());
        tx.signatures = vec![Signature::default(); msg.header.num_required_signatures as usize];
        self.svm.expire_blockhash();
        tx.message.recent_blockhash = self.svm.latest_blockhash();
        let r = self.svm.send_transaction(tx);
        let (err, meta) = match r {
            Ok(m) => (None, m),
            Err(f) => (Some(format!("{:?}", f.err)), f.meta),
        };
        // per top-level ix CU (depth-1 "consumed" lines of the wrapper / token program, skipping compute budget)
        let mut per = Vec::new();
        let mut depth = 0usize;
        let mut idx = 0usize;
        for l in &meta.logs {
            if let Some(rest) = l.strip_prefix("Program ") {
                if rest.contains(" invoke [") {
                    depth = rest.rsplit('[').next().unwrap().trim_end_matches(']').parse().unwrap_or(depth + 1);
                    continue;
                }
                if depth == 1 && rest.contains(" consumed ") {
                    let n: u64 = rest.split(" consumed ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap();
                    per.push((names.get(idx).cloned().unwrap_or("?".into()), n));
                }
                if rest.ends_with(" success") || rest.contains(" failed") {
                    if depth == 1 {
                        // compute budget ixs log no "consumed" line but do log invoke/success in 1.18
                        if !rest.starts_with("ComputeBudget") {
                            idx += 1;
                        }
                    }
                    depth = depth.saturating_sub(1);
                }
            }
        }
        let out = TxOut { err, total: meta.compute_units_consumed, per, logs: meta.logs };
        println!(
            "FTTX {label}: {} | total {} | {}",
            out.err.clone().unwrap_or("OK".into()),
            out.total,
            out.per.iter().map(|(n, c)| format!("{n}={c}")).collect::<Vec<_>>().join(" ")
        );
        if std::env::var_os("FT_PROBE").is_some() {
            let mut tag = String::new();
            let mut prev: Option<u64> = None;
            let mut line = String::new();
            for l in &out.logs {
                if l.contains(" invoke [1]") {
                    if !line.is_empty() { println!("    PROBE {line}"); }
                    line.clear();
                    prev = None;
                }
                if let Some(t) = l.strip_prefix("Program log: ") {
                    if t.starts_with("W:") || t.starts_with("E:") { tag = t.to_string(); }
                }
                if let Some(r) = l.strip_prefix("Program consumption: ") {
                    let rem: u64 = r.split(' ').next().unwrap().parse().unwrap();
                    if let Some(p) = prev { line.push_str(&format!(" +{}>{}", p - rem, tag)); } else { line.push_str(&format!(" [{}]{}", rem, tag)); }
                    prev = Some(rem);
                }
            }
            if !line.is_empty() { println!("    PROBE {line}"); }
        }
        if out.err.is_some() && std::env::var_os("FT_LOGS").is_some() {
            for l in out.logs.iter().rev().take(14).collect::<Vec<_>>().into_iter().rev() {
                println!("    {l}");
            }
        }
        out
    }
    fn push_ix(&self, asset: u16, mark: u64) -> (String, Instruction) {
        (format!("push{asset}"), Instruction {
            program_id: self.w,
            accounts: vec![AccountMeta::new(pk(ORACLE_AUTH), true), AccountMeta::new(self.k["market"], false)],
            data: ProgInstruction::PushAuthMark {
                asset_index: asset,
                market_id: self.market_id(asset),
                now_slot: self.svm.get_sysvar::<Clock>().slot,
                mark_e6: mark,
                observation_sequence: self.obs_seq(asset) + 1,
            }.encode(),
        })
    }
    fn crank_ix(&self, who: &str, obs: &[u16]) -> (String, Instruction) {
        (format!("crank {who}{}", if obs.is_empty() { String::new() } else { format!(" obs{obs:?}") }), Instruction {
            program_id: self.w,
            accounts: vec![AccountMeta::new(self.payer, true), AccountMeta::new(self.k["market"], false), AccountMeta::new(self.k[who], false)],
            data: ProgInstruction::PermissionlessCrank {
                now_slot: 0,
                observations: obs.iter().map(|&a| CrankObservationHint { asset_index: a, oracle_accounts: 0 }).collect(),
            }.encode(),
        })
    }
    fn deposit_ix(&self, amount: u128) -> (String, Instruction) {
        let d = self.data("fresh");
        ("deposit".into(), Instruction {
            program_id: self.w,
            accounts: vec![
                AccountMeta::new(pk(TAKER_OWNER), true),
                AccountMeta::new(self.k["market"], false),
                AccountMeta::new(self.k["fresh"], false),
                AccountMeta::new(self.taker_ata, false),
                AccountMeta::new(self.k["vault"], false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
            data: ProgInstruction::Deposit {
                portfolio_id: state::read_portfolio_id(&d).unwrap(),
                expected_sequence: state::read_portfolio_matcher_sequence(&d).unwrap(),
                amount,
            }.encode(),
        })
    }
    /// TradeCpi of the fresh taker against the LP. `seq_bump`: the deposit in the same tx bumps the
    /// taker's sequence? (not part of the trade binding; only the LP's matcher sequence is).
    fn trade_ix(&self, asset: u16, size_q: i128) -> (String, Instruction) {
        let a = self.data("fresh");
        let b = self.data("lp");
        ("TradeCpi".into(), Instruction {
            program_id: self.w,
            accounts: vec![
                AccountMeta::new(pk(TAKER_OWNER), true),
                AccountMeta::new(self.k["market"], false),
                AccountMeta::new(self.k["fresh"], false),
                AccountMeta::new(self.k["lp"], false),
                AccountMeta::new_readonly(self.m, false),
                AccountMeta::new(self.k["ctx"], false),
                AccountMeta::new_readonly(self.k["delegate"], false),
            ],
            data: ProgInstruction::TradeCpi {
                account_a_portfolio_id: state::read_portfolio_id(&a).unwrap(),
                account_a_position_epoch: state::read_portfolio_position_epoch(&a).unwrap(),
                account_b_portfolio_id: state::read_portfolio_id(&b).unwrap(),
                account_b_position_epoch: state::read_portfolio_position_epoch(&b).unwrap(),
                market_id: self.market_id(asset),
                account_b_matcher_sequence: state::read_portfolio_matcher_sequence(&b).unwrap(),
                asset_index: asset,
                size_q,
                fee_bps: 100,
                limit_price: 0,
                backing_fee_cap_bps: 0,
            }.encode(),
        })
    }
    fn eff(&self, asset: usize) -> u64 {
        let mut d = self.data("market");
        let (_, group) = state::market_view_mut(&mut d).unwrap();
        group.markets[asset].engine.asset.effective_price.get()
    }
}

/// Keeper-style move: advance `dt` slots and push every asset's mark scaled by (1 + bps/1e4); asset 2 (cbBTC) static.
fn move_prices(e: &mut Env, dt: u64, bps: i64) {
    let s = e.svm.get_sysvar::<Clock>().slot + dt;
    e.set_slot(s);
    let ixs: Vec<_> = (0u16..5)
        .map(|a| {
            let p = e.eff(a as usize) as i128;
            let mark = if a == 2 { p } else { p + p * bps as i128 / 10_000 };
            e.push_ix(a, mark as u64)
        })
        .collect();
    e.send(&format!("push x5 (+{bps} bps, dt {dt})"), ixs);
}


/// Budget for a fresh taker's open against a 4-leg LP on a cap-4 market: [Deposit, TradeCpi], no crank.
/// Measured 367k-405k on this fixture; the budget keeps > 55% of the 1.4M transaction limit free.
const FRESH_TAKER_OPEN_CU_BUDGET: u64 = 600_000;
/// The refresh round (tx1 of the 2-tx flow / the keeper's atomic round) stays under the F1 10% line.
const REFRESH_ROUND_CU_BUDGET: u64 = 1_260_000;
const SIZE: [(u16, i128); 4] = [(0, 100_000), (1, 100_000), (2, 5_000), (3, 100_000)];
const ALL: [u16; 5] = [0, 1, 2, 3, 4];

/// The market as QA met it: the keeper's last round, then a new mark (+5 bps) and 12 slots.
fn qa_state() -> Env {
    let mut e = Env::new();
    move_prices(&mut e, 3, 5);
    let r = e.send("keeper round", vec![e.crank_ix("gv86", &ALL), e.crank_ix("lp", &[])]);
    assert!(r.err.is_none(), "setup round: {:?}", r.err);
    move_prices(&mut e, 12, 5);
    e
}
fn err_has(o: &TxOut, s: &str) -> bool {
    o.err.as_deref().is_some_and(|e| e.contains(s))
}

#[test]
fn v22_fresh_taker_old_q7_shape_is_refused_121_or_runs_out_of_compute() {
    for (k, q) in [(0u16, 100_000i128), (1, 100_000), (3, 100_000)] {
        // SDK Q-7 after its 22-drops: [LP observing every asset, trade] -> the peer is stale.
        let mut e = qa_state();
        let ixs = vec![e.deposit_ix(300_000_000), e.crank_ix("lp", &ALL), e.trade_ix(k, q)];
        let o = e.send(&format!("a{k} old Q-7"), ixs);
        assert!(err_has(&o, "Custom(121)"), "asset {k}: expected EngineLossStale (121), got {:?}", o.err);
        // ... and with the peer refresh added in Q-7 order the LP is refreshed twice: over 1.4M.
        let mut e = qa_state();
        let ixs = vec![e.deposit_ix(300_000_000), e.crank_ix("lp", &ALL), e.crank_ix("gv86", &[]), e.crank_ix("lp", &[]), e.trade_ix(k, q)];
        let o = e.send(&format!("a{k} old Q-7 + peer"), ixs);
        assert!(err_has(&o, "ProgramFailedToComplete") || err_has(&o, "ComputationalBudgetExceeded"), "asset {k}: expected compute exhaustion, got {:?} ({} CU)", o.err, o.total);
    }
}

#[test]
fn v22_fresh_taker_open_after_atomic_round_fits_the_budget_on_every_asset() {
    for (k, q) in SIZE {
        let mut e = qa_state();
        // the keeper's atomic round (peer observes every asset, LP refresh-only LAST)
        let r = e.send("atomic round", vec![e.crank_ix("gv86", &ALL), e.crank_ix("lp", &[])]);
        assert!(r.err.is_none(), "round: {:?}", r.err);
        assert!(r.total <= REFRESH_ROUND_CU_BUDGET, "round {} CU > {REFRESH_ROUND_CU_BUDGET}", r.total);
        let s = e.svm.get_sysvar::<Clock>().slot + 2;
        e.set_slot(s);
        let ixs = vec![e.deposit_ix(300_000_000), e.trade_ix(k, q)];
        let o = e.send(&format!("a{k} fresh open"), ixs);
        assert!(o.err.is_none(), "asset {k}: fresh open refused {:?}", o.err);
        assert!(o.total <= FRESH_TAKER_OPEN_CU_BUDGET, "asset {k}: {} CU > {FRESH_TAKER_OPEN_CU_BUDGET}", o.total);
        let p = state::read_portfolio(&e.data("fresh")).unwrap();
        assert_eq!(percolator::active_bitmap_count_ones(p.active_bitmap), 1, "asset {k}: one leg opened");
    }
}

#[test]
fn v22_fresh_taker_two_tx_flow_after_a_peer_was_staled() {
    let mut e = qa_state();
    // someone's observing crank on the LP re-stales the peer: an open now answers 121
    let o = e.send("LP obs all", vec![e.crank_ix("lp", &ALL)]);
    assert!(o.err.is_none());
    let ixs = vec![e.deposit_ix(300_000_000), e.trade_ix(1, 100_000)];
    assert!(err_has(&e.send("open with stale peer", ixs), "Custom(121)"));
    // tx1: refresh round (peer observes every asset, LP last); tx2 two slots later: the order alone
    let s = e.svm.get_sysvar::<Clock>().slot + 1;
    e.set_slot(s);
    let r = e.send("tx1", vec![e.crank_ix("gv86", &ALL), e.crank_ix("lp", &[])]);
    assert!(r.err.is_none(), "tx1: {:?}", r.err);
    assert!(r.total <= REFRESH_ROUND_CU_BUDGET, "tx1 {} CU", r.total);
    let s = e.svm.get_sysvar::<Clock>().slot + 2;
    e.set_slot(s);
    let ixs = vec![e.deposit_ix(300_000_000), e.trade_ix(1, 100_000)];
    let o = e.send("tx2", ixs);
    assert!(o.err.is_none(), "tx2: {:?}", o.err);
    assert!(o.total <= FRESH_TAKER_OPEN_CU_BUDGET, "tx2 {} CU", o.total);
}

#[test]
fn v22_hintless_crank_in_a_later_slot_leaves_other_exposed_assets_loss_stale() {
    let mut e = qa_state();
    assert!(e.send("LP obs all", vec![e.crank_ix("lp", &ALL)]).err.is_none());
    let s = e.svm.get_sysvar::<Clock>().slot + 2;
    e.set_slot(s);
    // hint-less refreshes in a later slot: accepted (the peer is stale), but they advance the
    // market clock through the first leg's asset (0) only
    let r = e.send("hint-less pair", vec![e.crank_ix("gv86", &[]), e.crank_ix("lp", &[])]);
    assert!(r.err.is_none(), "{:?}", r.err);
    let ixs = vec![e.deposit_ix(300_000_000), e.trade_ix(0, 100_000)];
    let o = e.send("open a0", ixs);
    assert!(o.err.is_none(), "asset 0 (the advanced one) opens: {:?}", o.err);
    for (k, q) in [(1u16, 100_000i128), (3, 100_000)] {
        let ixs = vec![e.trade_ix(k, q)];
        let o = e.send(&format!("open a{k}"), ixs);
        assert!(err_has(&o, "Custom(121)"), "asset {k}: expected 121 (behind the market clock), got {:?}", o.err);
    }
}
