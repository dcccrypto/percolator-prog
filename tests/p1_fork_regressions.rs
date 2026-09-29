// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P1 fork regressions — replay the four live devnet failure shapes (2026-09-28/29
//! "locked markets diagnosed", `~/percolator-ops/ledger/deployments.md`; §2 of
//! `perp-liquidity-assessment-2026-09-29.md`) against the REAL live account state,
//! running the DEPLOYED v18.2 wrapper bytes and the P1 candidate bytes side by side.
//!
//! # Method (key-free, deterministic)
//! * `tests/fixtures/p1_fork/<market>.json` are READ-ONLY dumps of every
//!   wrapper-owned account whose provenance `market_group_id` (offset 16) is the
//!   market slab, the slab itself, and the matcher context referenced by the LP's
//!   matcher config, all from ONE `getMultipleAccounts` call (so one context slot),
//!   plus the `Clock` sysvar. Fetcher: `tests/fixtures/p1_fork/fetch.py`.
//! * The wrapper is mounted at its live id `GnwdeQr…` (PDAs — the matcher delegate —
//!   are derived under it), the matcher at its live id `4seJWjv3…` from the sibling
//!   `.so` (byte-identical to the live ProgramData, verified at fixture time).
//! * `with_sigverify(false)`: the taker's owner is listed as a signer with a
//!   default (all-zero) signature. NO account data is rewritten to make a signer
//!   fit; no private key is read.
//! * The `Clock` is the fixture's Clock sysvar (its slot = the fetch slot).
//! * Deployed bytes: `P1_FORK_DEPLOYED_SO` or
//!   `/Users/khubair/deploycand-v182/out/wrapper-v18.2.so`, sha256 pinned to the
//!   live ProgramData prefix `4472b383…`. Candidate bytes: `target/deploy/
//!   percolator_prog.so` (build with `cargo build-sbf -- --features devnet`).
//!
//! Each test runs the SAME replay on both byte sets. The deployed run is the
//! negative control and pins the live failure code; the candidate run pins the P1
//! behaviour.

use litesvm::LiteSVM;
use percolator::{SideModeV16, SideV16};
use percolator_prog::{
    constants::KIND_PORTFOLIO,
    ix::Instruction as ProgInstruction,
    state,
};
use solana_program::pubkey;
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::hashv,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;

const WRAPPER_ID: Pubkey = pubkey!("GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ");
const MATCHER_ID: Pubkey = pubkey!("4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT");

const DEPLOYED_SO_DEFAULT: &str = "/Users/khubair/deploycand-v182/out/wrapper-v18.2.so";
const DEPLOYED_SO_SHA256: &str = "4472b3832fda102aae8d28b3c1efc642a4b919f3671d93076ca6f88cce51e98b";
/// Matcher 12bd671, 58,488 B; equal to the first 58,488 B of the live 4seJWjv3 ProgramData.
const MATCHER_SO_SHA256: &str = "659eaf9dfd90e7253154a621fa98f3664df95179860cbef0814cc2fc7d0a62c6";

const ASSET: u16 = 0;

// Wrapper error ordinals (PercolatorError -> Custom(n)).
const E_ENGINE_STALE: u32 = 19;
const E_LOCK_ACTIVE: u32 = 21;
const E_INSUFFICIENT_IM: u32 = 49;
const E_SAME_OWNER: u32 = 67;
const E_LP_FLOOR_HALT: u32 = 69;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bytes {
    Deployed,
    Candidate,
}

fn sha256_hex(b: &[u8]) -> String {
    hashv(&[b])
        .to_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn wrapper_bytes(which: Bytes) -> Vec<u8> {
    match which {
        Bytes::Deployed => {
            let p = std::env::var("P1_FORK_DEPLOYED_SO")
                .unwrap_or_else(|_| DEPLOYED_SO_DEFAULT.to_string());
            let b = std::fs::read(&p).unwrap_or_else(|e| panic!("read deployed .so {p}: {e}"));
            assert_eq!(
                sha256_hex(&b),
                DEPLOYED_SO_SHA256,
                "deployed .so at {p} is not the live v18.2 wrapper"
            );
            b
        }
        Bytes::Candidate => {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("target/deploy/percolator_prog.so");
            let b = std::fs::read(&p).unwrap_or_else(|e| {
                panic!("read candidate .so {}: {e} (cargo build-sbf -- --features devnet)", p.display())
            });
            assert_ne!(
                sha256_hex(&b),
                DEPLOYED_SO_SHA256,
                "candidate .so is byte-identical to the deployed wrapper — stale build?"
            );
            eprintln!("candidate wrapper sha256 {} ({} B)", sha256_hex(&b), b.len());
            b
        }
    }
}

fn matcher_bytes() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../percolator-match/target/deploy/percolator_match.so");
    let b = std::fs::read(&p).unwrap_or_else(|e| panic!("read matcher .so {}: {e}", p.display()));
    assert_eq!(sha256_hex(&b), MATCHER_SO_SHA256, "matcher .so is not deployed 12bd671");
    b
}

// ── Fixtures ────────────────────────────────────────────────────────────────

struct Fixture {
    name: String,
    slab: Pubkey,
    fetch_slot: u64,
    clock: Clock,
    accounts: Vec<(Pubkey, Account)>,
}

fn b64(s: &str) -> Vec<u8> {
    // Minimal standard-alphabet base64 decoder (no extra dev-dependency).
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

fn load_fixture(name: &str) -> Fixture {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(format!("tests/fixtures/p1_fork/{name}.json"));
    let raw = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let clock: Clock = bincode::deserialize(&b64(v["clock_sysvar_b64"].as_str().unwrap())).unwrap();
    let mut accounts = Vec::new();
    for a in v["accounts"].as_array().unwrap() {
        let key: Pubkey = a["pubkey"].as_str().unwrap().parse().unwrap();
        let owner: Pubkey = a["owner"].as_str().unwrap().parse().unwrap();
        accounts.push((
            key,
            Account {
                lamports: a["lamports"].as_u64().unwrap(),
                data: b64(a["data_b64"].as_str().unwrap()),
                owner,
                executable: a["executable"].as_bool().unwrap(),
                rent_epoch: 0,
            },
        ));
    }
    Fixture {
        name: name.to_string(),
        slab: v["slab"].as_str().unwrap().parse().unwrap(),
        fetch_slot: v["fetch_slot"].as_u64().unwrap(),
        clock,
        accounts,
    }
}

// ── Environment ─────────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    payer: Keypair,
    slab: Pubkey,
    which: Bytes,
    label: String,
}

fn env(fx: &Fixture, which: Bytes) -> Env {
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.add_program(WRAPPER_ID, &wrapper_bytes(which));
    svm.add_program(MATCHER_ID, &matcher_bytes());
    for (k, a) in &fx.accounts {
        svm.set_account(*k, a.clone()).unwrap();
    }
    svm.set_sysvar(&fx.clock);
    assert_eq!(
        svm.get_sysvar::<Clock>().slot,
        fx.clock.slot,
        "Clock must be the fixture's"
    );
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    Env {
        svm,
        payer,
        slab: fx.slab,
        which,
        label: format!("{}/{:?}", fx.name, which),
    }
}

type Outcome = (Result<(), TransactionError>, Vec<String>);

impl Env {
    /// Send with the payer really signing and `fake_signers` listed as signers with
    /// a default signature (sigverify is off).
    fn send(&mut self, ixs: Vec<Instruction>, fake_signers: &[Pubkey]) -> Outcome {
        self.svm.expire_blockhash();
        let mut all = vec![
            solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(
                1_400_000,
            ),
        ];
        all.extend(ixs);
        let msg = Message::new(&all, Some(&self.payer.pubkey()));
        for s in fake_signers {
            assert!(
                msg.account_keys[..msg.header.num_required_signatures as usize].contains(s),
                "fake signer {s} is not a required signer of the message"
            );
        }
        let mut tx = Transaction::new_unsigned(msg);
        tx.signatures = vec![Signature::default(); tx.message.header.num_required_signatures as usize];
        tx.partial_sign(&[&self.payer], self.svm.latest_blockhash());
        match self.svm.send_transaction(tx) {
            Ok(meta) => (Ok(()), meta.logs),
            Err(f) => (Err(f.err), f.meta.logs),
        }
    }

    fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.svm.get_account(k).unwrap().data
    }

    fn expire_bucket(&mut self, domain: u16) -> Outcome {
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![AccountMeta::new(self.slab, false)],
            data: ProgInstruction::ExpireBackingBucket { domain }.encode(),
        };
        self.send(vec![ix], &[])
    }

    fn finalize_side(&mut self, side: u8) -> Outcome {
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![AccountMeta::new(self.slab, false)],
            data: ProgInstruction::FinalizeResetSide {
                asset_index: ASSET,
                side,
            }
            .encode(),
        };
        self.send(vec![ix], &[])
    }

    /// TradeCpi (tag 10): `taker` (account_a) against `lp` (account_b) via the LP's
    /// registered matcher. Signer = taker owner (fake signature).
    fn trade_cpi(&mut self, taker: &Pubkey, lp: &Pubkey, size_q: i128) -> Outcome {
        let md = self.data(&self.slab);
        let (cfg, _, _, market_id, _, _) =
            state::read_market_trade_preflight(&md, ASSET as usize).unwrap();
        let td = self.data(taker);
        let ld = self.data(lp);
        let taker_owner = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&td).unwrap().1);
        let mcfg = state::read_portfolio_matcher_config(&ld).unwrap();
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new(taker_owner, true),
                AccountMeta::new(self.slab, false),
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
                asset_index: ASSET,
                size_q,
                fee_bps: cfg.trade_fee_base_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            }
            .encode(),
        };
        self.send(vec![ix], &[taker_owner])
    }

    fn portfolios(&self, fx: &Fixture) -> Vec<Pubkey> {
        fx.accounts
            .iter()
            .filter(|(_, a)| a.owner == WRAPPER_ID && a.data.len() > 10 && a.data[10] == KIND_PORTFOLIO)
            .map(|(k, _)| *k)
            .collect()
    }

    fn lp(&self, fx: &Fixture) -> Pubkey {
        let lps: Vec<Pubkey> = self
            .portfolios(fx)
            .into_iter()
            .filter(|k| {
                state::read_portfolio_matcher_config(&self.data(k))
                    .map(|c| c.enabled() == 1 && Pubkey::new_from_array(c.matcher_program) == MATCHER_ID)
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(lps.len(), 1, "{}: expected exactly one matcher LP, got {lps:?}", fx.name);
        lps[0]
    }

    fn owner(&self, k: &Pubkey) -> Pubkey {
        Pubkey::new_from_array(state::read_portfolio_owner_preflight(&self.data(k)).unwrap().1)
    }

    /// Signed basis position of `k` on ASSET (0 when no active leg).
    fn pos(&self, k: &Pubkey) -> i128 {
        let p = state::read_portfolio(&self.data(k)).unwrap();
        p.legs
            .iter()
            .filter(|l| l.active && l.asset_index == ASSET as u32)
            .map(|l| l.basis_pos_q)
            .sum()
    }

    fn capital_pnl(&self, k: &Pubkey) -> (u128, i128, i128) {
        let p = state::read_portfolio(&self.data(k)).unwrap();
        (p.capital, p.pnl, p.fee_credits)
    }

    fn req_id(&self) -> u64 {
        state::next_market_matcher_req_id(&self.data(&self.slab)).unwrap()
    }

    fn dump(&self, fx: &Fixture) {
        let md = self.data(&self.slab);
        let (_cfg, g) = state::read_market(&md).unwrap();
        let a = &g.assets[ASSET as usize];
        eprintln!(
            "[{}] fetch_slot={} clock={} market.current_slot={} mode={:?} eff_px={} oi_long={} oi_short={} mode_long={:?} mode_short={:?} vault={} ins={} c_tot={}",
            self.label, fx.fetch_slot, self.svm.get_sysvar::<Clock>().slot, g.current_slot, g.mode,
            a.effective_price, a.oi_eff_long_q, a.oi_eff_short_q, a.mode_long, a.mode_short,
            g.vault, g.insurance, g.c_tot
        );
        for (d, b) in g.source_backing_buckets.iter().enumerate() {
            if b.status != percolator::BackingBucketStatusV16::Empty || b.fresh_unliened_backing_num != 0 {
                eprintln!("   bucket d{d}: {:?}", b);
            }
        }
        if let Ok(p) = state::read_asset_oracle_profile(&md, ASSET as usize) {
            eprintln!(
                "   asset_admin={} last_good_oracle_slot={}",
                Pubkey::new_from_array(p.asset_admin),
                p.last_good_oracle_slot
            );
        }
        for k in self.portfolios(fx) {
            let d = self.data(&k);
            let p = state::read_portfolio(&d).unwrap();
            let m = state::read_portfolio_matcher_config(&d)
                .map(|c| format!("en={} ctx={}", c.enabled(), Pubkey::new_from_array(c.matcher_context)))
                .unwrap_or_else(|e| format!("{e:?}"));
            eprintln!(
                "   pf {k} owner={} cap={} pnl={} fee_credits={} pos={} stale={} b_stale={} matcher[{m}]",
                Pubkey::new_from_array(p.provenance_header.owner),
                p.capital, p.pnl, p.fee_credits, self.pos(&k), p.stale_state, p.b_stale_state
            );
        }
    }
}

fn custom_code(r: &Result<(), TransactionError>) -> Option<u32> {
    match r {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) => Some(*c),
        _ => None,
    }
}

fn show(label: &str, o: &Outcome) {
    eprintln!("--- {label}: {:?}", o.0);
    for l in &o.1 {
        if l.contains("Program log") || l.contains("failed") || l.contains("invoke [2]") {
            eprintln!("      {l}");
        }
    }
}

/// Diagnostic dump of every fixture under both byte sets (asserts only that the
/// fixture parses and the Clock is pinned). Run with `--nocapture` to see state.
#[test]
fn p1_fork_survey() {
    for name in ["collect", "murphy", "textit", "ansem"] {
        let fx = load_fixture(name);
        for which in [Bytes::Deployed, Bytes::Candidate] {
            let e = env(&fx, which);
            e.dump(&fx);
        }
    }
}


// ── Replay helpers ──────────────────────────────────────────────────────────

const MATCHER_INVOKE_LOG: &str = "Program 4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT invoke [2]";

fn matcher_invoked(o: &Outcome) -> bool {
    o.1.iter().any(|l| l == MATCHER_INVOKE_LOG)
}

fn expect_code(o: &Outcome, code: u32, label: &str) {
    match &o.0 {
        Err(TransactionError::InstructionError(2, InstructionError::Custom(c))) => {
            assert_eq!(*c, code, "{label}: expected Custom({code}), got Custom({c}); logs {:#?}", o.1)
        }
        other => panic!("{label}: expected InstructionError(2, Custom({code})), got {other:?}; logs {:#?}", o.1),
    }
}

fn expect_ok(o: &Outcome, label: &str) {
    assert!(o.0.is_ok(), "{label}: expected Ok, got {:?}; logs {:#?}", o.0, o.1);
}

fn bucket_status(e: &Env, d: usize) -> percolator::BackingBucketStatusV16 {
    let (_, g) = state::read_market(&e.data(&e.slab)).unwrap();
    g.source_backing_buckets[d].status
}

fn short_mode(e: &Env) -> SideModeV16 {
    let (_, g) = state::read_market(&e.data(&e.slab)).unwrap();
    g.assets[ASSET as usize].mode_short
}

/// The permissionless repairs a keeper (PR #130) / self-healing frontend would
/// prepend, each asserted to land AND to change state (proof of life):
///   * tag 89 ExpireBackingBucket on every LAPSED Fresh bucket (`expiry_slot <= clock`)
///   * tag 45 FinalizeResetSide(short) when the short side is ResetPending.
/// Returns the list of repairs applied, for the report.
fn apply_live_repairs(e: &mut Env) -> Vec<String> {
    let mut applied = Vec::new();
    let now = e.svm.get_sysvar::<Clock>().slot;
    let (_, g) = state::read_market(&e.data(&e.slab)).unwrap();
    let lapsed: Vec<usize> = g
        .source_backing_buckets
        .iter()
        .enumerate()
        .filter(|(_, b)| b.status == percolator::BackingBucketStatusV16::Fresh && b.expiry_slot <= now)
        .map(|(d, _)| d)
        .collect();
    for d in lapsed {
        let o = e.expire_bucket(d as u16);
        expect_ok(&o, &format!("{} tag89 d{d}", e.label));
        assert_ne!(
            bucket_status(e, d),
            percolator::BackingBucketStatusV16::Fresh,
            "{} tag89 d{d} must move the lapsed bucket out of Fresh",
            e.label
        );
        applied.push(format!("tag89 ExpireBackingBucket d{d}"));
    }
    if short_mode(e) == SideModeV16::ResetPending {
        let o = e.finalize_side(1);
        expect_ok(&o, &format!("{} tag45 short", e.label));
        assert_eq!(short_mode(e), SideModeV16::Normal, "{} tag45 must reopen the short side", e.label);
        applied.push("tag45 FinalizeResetSide(short)".to_string());
    }
    eprintln!("[{}] repairs applied: {applied:?}", e.label);
    applied
}

fn pk(s: &str) -> Pubkey {
    s.parse().unwrap()
}

/// Run one TradeCpi and restore the three touched accounts afterwards, so
/// successive probes all start from the same repaired live state.
fn probe(e: &mut Env, taker: &Pubkey, lp: &Pubkey, size: i128) -> Outcome {
    let snap: Vec<(Pubkey, Account)> = [e.slab, *taker, *lp]
        .iter()
        .map(|k| (*k, e.svm.get_account(k).unwrap()))
        .collect();
    let o = e.trade_cpi(taker, lp, size);
    show(&format!("{} TradeCpi size {size}", e.label), &o);
    for (k, a) in snap {
        e.svm.set_account(k, a).unwrap();
    }
    o
}

fn unit() -> i128 {
    percolator::POS_SCALE as i128
}

/// Shapes 1/2/3 share one replay: a flat, zero-capital matcher LP after the live
/// repairs; a distinct-owner taker opens either way (both GROW the flat LP).
/// Deployed: engine Custom(49) AFTER the matcher ran. Candidate: LpFloorHalt
/// Custom(69) BEFORE the matcher is invoked. When `self_taker` is given (a taker
/// owned by the LP owner / asset_admin), the candidate refuses it with
/// SameOwnerTrade Custom(67), also pre-matcher, while deployed reaches the engine.
fn replay_zero_capital_lp(name: &str, taker: &str, self_taker: Option<(&str, u32)>) {
    let fx = load_fixture(name);
    for which in [Bytes::Deployed, Bytes::Candidate] {
        let mut e = env(&fx, which);
        let lp = e.lp(&fx);
        let t = pk(taker);
        // Shape pin: the live LP is flat with zero capital and zero PnL.
        assert_eq!(e.capital_pnl(&lp), (0, 0, 0), "{}: LP capital/pnl/fee_credits", e.label);
        assert_eq!(e.pos(&lp), 0, "{}: LP flat", e.label);
        let md = state::read_asset_oracle_profile(&e.data(&e.slab), ASSET as usize).unwrap();
        assert_ne!(e.owner(&t), e.owner(&lp), "{}: taker must not be the LP owner", e.label);
        assert_ne!(e.owner(&t).to_bytes(), md.asset_admin, "{}: taker must not be asset_admin", e.label);
        apply_live_repairs(&mut e);
        for size in [unit(), -unit()] {
            let o = probe(&mut e, &t, &lp, size);
            match which {
                Bytes::Deployed => {
                    expect_code(&o, E_INSUFFICIENT_IM, &format!("{} grow {size}", e.label));
                    assert!(matcher_invoked(&o), "{}: deployed reaches the engine via the matcher", e.label);
                }
                Bytes::Candidate => {
                    expect_code(&o, E_LP_FLOOR_HALT, &format!("{} grow {size}", e.label));
                    assert!(!matcher_invoked(&o), "{}: LpFloorHalt must fire before the matcher", e.label);
                }
            }
        }
        if let Some((st, deployed_code)) = self_taker {
            let st = pk(st);
            assert!(
                e.owner(&st) == e.owner(&lp) || e.owner(&st).to_bytes() == md.asset_admin,
                "{}: self_taker must be owned by the LP owner or asset_admin",
                e.label
            );
            let o = probe(&mut e, &st, &lp, unit());
            match which {
                Bytes::Deployed => {
                    expect_code(&o, deployed_code, &format!("{} self-owned taker", e.label));
                    assert!(matcher_invoked(&o));
                }
                Bytes::Candidate => {
                    expect_code(&o, E_SAME_OWNER, &format!("{} self-owned taker", e.label));
                    assert!(!matcher_invoked(&o), "{}: SameOwnerTrade must fire before the matcher", e.label);
                }
            }
        }
    }
}

/// Shape 1 — COLLECT (3t67LQ…): lapsed d1 + short ResetPending, then LP capital 0.
/// LP E5nysm… (owner 9sM73A… = asset_admin); taker GGMfwK… (owner AXa339…);
/// self-owned taker JE7SHW… (owner 9sM73A…).
#[test]
fn p1_fork_collect_zero_capital_lp() {
    replay_zero_capital_lp(
        "collect",
        "GGMfwKxJDokS1ukbyTdZcidv5zAY6nW5H7csfyY3qJ1E",
        // deployed: engine IM gate, Custom(49)
        Some(("JE7SHWNAfGXPnAjLsSZpNJSuefWjMFp8eEJnHHyiyz5K", E_INSUFFICIENT_IM)),
    );
}

/// Shape 2 — Murphy (7h3wNx…): lapsed d0 + d1 + short ResetPending, then LP capital 0.
/// LP EXgiHL… (owner AXa339… = asset_admin); taker 9noH7P… (owner 9sM73A…);
/// self-owned taker CQwnpC… (owner AXa339…).
#[test]
fn p1_fork_murphy_zero_capital_lp() {
    replay_zero_capital_lp(
        "murphy",
        "9noH7PkT7uKuZGTSjBopKt4gMx7CnbydNQz2ZmVf3AwH",
        // deployed: Custom(21) — this taker has capital 0 and a +370M PnL claim on the
        // just-expired buckets, so its own lien fails first.
        Some(("CQwnpCEatEfkJr6CJA86LMDXwcqkUVwmDi7SvkWNCmSQ", E_LOCK_ACTIVE)),
    );
}

/// Shape 3 — TEXTIT (DnFhDd…). HONEST NOTE: the ledger's shape (LP holding a
/// +2.04M PnL claim on an empty/expired domain-1 bucket → shorts Custom(21)) is NOT
/// the live state at the fixture slot: the LP 5oYeGq… now has capital 0, PnL 0,
/// flat, and both buckets are Fresh with future expiries (re-funded). Only the
/// short side is still ResetPending. So the live TEXTIT replay is the same
/// zero-capital shape as COLLECT/Murphy, and is pinned as such.
#[test]
fn p1_fork_textit_live_state() {
    replay_zero_capital_lp(
        "textit",
        "7xmwLShWzrUqqgQ7vtLupJDL9npmBjnd566jwximzrvV",
        // self-owned taker HRDZUj… (owner 9sM73A… = LP owner = asset_admin)
        Some(("HRDZUjjCjeRQCp6DQ7V4E1qkxnippUHuhsV7SUe7PWts", E_INSUFFICIENT_IM)),
    );
}

/// Shape 4 — ANSEM (5bVTTM…): the creator DwgobU… is asset_admin, owns the matcher
/// LP 2SewEc… (short 16,511,677,058 Q) and the bankrupt trader DcVGSE… (long, the
/// LP's only counterparty). Deployed bytes let the creator's trader trade against
/// the creator's own LP: the LP-reducing sell LANDS (Ok), the LP-growing buy fails
/// only on Custom(21). Candidate: both are SameOwnerTrade Custom(67) with the
/// matcher never invoked.
#[test]
fn p1_fork_ansem_self_owned_taker() {
    let fx = load_fixture("ansem");
    let lp_key = pk("2SewEcvfyyEx3HE8NL8jjH6YJdtzGvZKvWbS2QqxhtZP");
    let t = pk("DcVGSEfZtu8A8yyNSwLMJsfyT3ZobTvDxdx5X9wtvytX");
    for which in [Bytes::Deployed, Bytes::Candidate] {
        let mut e = env(&fx, which);
        let lp = e.lp(&fx);
        assert_eq!(lp, lp_key);
        let admin = state::read_asset_oracle_profile(&e.data(&e.slab), ASSET as usize).unwrap().asset_admin;
        assert_eq!(e.owner(&t), e.owner(&lp), "ANSEM: taker and LP share an owner");
        assert_eq!(e.owner(&t).to_bytes(), admin, "ANSEM: that owner is the asset_admin");
        let lp_before = e.pos(&lp);
        assert_eq!(lp_before, -16_511_677_058);
        apply_live_repairs(&mut e);
        // Taker buys: LP grows its short.
        let grow = probe(&mut e, &t, &lp, unit());
        // Taker sells: LP reduces its short.
        let reduce_snap = e.svm.get_account(&lp).unwrap();
        let reduce = e.trade_cpi(&t, &lp, -unit());
        show(&format!("{} TradeCpi size {}", e.label, -unit()), &reduce);
        match which {
            Bytes::Deployed => {
                expect_code(&grow, E_LOCK_ACTIVE, "ANSEM deployed grow");
                assert!(matcher_invoked(&grow));
                expect_ok(&reduce, "ANSEM deployed reduce (self-trade lands)");
                assert!(matcher_invoked(&reduce));
                assert_eq!(e.pos(&lp), lp_before + unit(), "deployed: the self-trade moved the LP");
                assert_eq!(e.pos(&t), -lp_before - unit(), "deployed: the self-trade moved the taker");
            }
            Bytes::Candidate => {
                expect_code(&grow, E_SAME_OWNER, "ANSEM candidate grow");
                assert!(!matcher_invoked(&grow));
                expect_code(&reduce, E_SAME_OWNER, "ANSEM candidate reduce");
                assert!(!matcher_invoked(&reduce));
                assert_eq!(e.svm.get_account(&lp).unwrap().data, reduce_snap.data, "candidate: LP untouched");
            }
        }
    }
}

// ── Fixture-derived SYNTHETIC: floored LP with an open position ────────────
//
// No live market has a floored matcher LP that still holds a position AND a
// distinct-owner counterparty, so "a reducing trade still works on a halted LP"
// cannot be replayed on untouched live state. SYNTHETIC variant, clearly labelled:
//   * start from the ANSEM fixture (+ its live tag-89 repair);
//   * rewrite ONLY the taker DcVGSE…'s owner field (provenance header + wire copy)
//     to a fresh test key, so it is no longer the LP owner / asset_admin (the LP's
//     owner is untouched: the matcher delegate PDA depends on it);
//   * floor the LP with tag 93 SetAssetRiskLimits { lp_floor_atoms = 1e12 } signed
//     (fake signature, sigverify off) as the LIVE upgrade authority FbTbDe…, whose
//     ProgramData header is `wrapper_programdata_header.json` (live bytes).
// Candidate only: the deployed wrapper has no tag 93 / no floor concept.

fn mount_programdata(e: &mut Env) -> Pubkey {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/p1_fork/wrapper_programdata_header.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let pd = pk(v["programdata"].as_str().unwrap());
    let (derived, _) = Pubkey::find_program_address(
        &[WRAPPER_ID.as_ref()],
        &solana_sdk::bpf_loader_upgradeable::id(),
    );
    assert_eq!(pd, derived, "fixture ProgramData must be the wrapper's PDA");
    let hdr = b64(v["header_45_b64"].as_str().unwrap());
    e.svm
        .set_account(
            pd,
            Account {
                lamports: 1_000_000_000,
                data: hdr,
                owner: solana_sdk::bpf_loader_upgradeable::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    pk(v["upgrade_authority"].as_str().unwrap())
}

fn set_lp_floor(e: &mut Env, floor: u128) {
    let authority = mount_programdata(e);
    let (pd, _) = Pubkey::find_program_address(&[WRAPPER_ID.as_ref()], &solana_sdk::bpf_loader_upgradeable::id());
    let ix = Instruction {
        program_id: WRAPPER_ID,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new_readonly(pd, false),
            AccountMeta::new(e.slab, false),
        ],
        data: ProgInstruction::SetAssetRiskLimits {
            asset_index: ASSET,
            exec_band_bps: 0,
            lp_exposure_k_bps: 0,
            lp_floor_atoms: floor,
            side_oi_cap_q: 0,
            matcher_ext_mode: 0,
        }
        .encode(),
    };
    let o = e.send(vec![ix], &[authority]);
    match &o.0 {
        Ok(()) => {}
        Err(err) => panic!("tag 93 as live upgrade authority: {err:?}; {:#?}", o.1),
    }
    let limits = state::read_asset_risk_limits(&e.data(&e.slab), ASSET as usize).unwrap();
    assert_eq!(limits.lp_floor_atoms, floor, "tag 93 must store the floor");
}

fn rewrite_portfolio_owner(e: &mut Env, k: &Pubkey, new_owner: &Pubkey) {
    let mut a = e.svm.get_account(k).unwrap();
    let old = e.owner(k).to_bytes();
    // ProvenanceHeaderV16Account.owner at HEADER_LEN + 64; wire owner right after the
    // 100-byte provenance header.
    const PROV_OWNER: usize = 16 + 64;
    const WIRE_OWNER: usize = 16 + 100;
    assert_eq!(&a.data[PROV_OWNER..PROV_OWNER + 32], &old);
    assert_eq!(&a.data[WIRE_OWNER..WIRE_OWNER + 32], &old);
    a.data[PROV_OWNER..PROV_OWNER + 32].copy_from_slice(new_owner.as_ref());
    a.data[WIRE_OWNER..WIRE_OWNER + 32].copy_from_slice(new_owner.as_ref());
    e.svm.set_account(*k, a).unwrap();
    assert_eq!(e.owner(k), *new_owner, "owner rewrite must parse back");
}

#[test]
fn p1_fork_synthetic_floored_lp_reduce_still_works() {
    let fx = load_fixture("ansem");
    let mut e = env(&fx, Bytes::Candidate);
    e.label = "SYNTHETIC(ansem-derived)/Candidate".into();
    let lp = e.lp(&fx);
    let t = pk("DcVGSEfZtu8A8yyNSwLMJsfyT3ZobTvDxdx5X9wtvytX");
    apply_live_repairs(&mut e);
    let new_owner = Pubkey::new_unique();
    rewrite_portfolio_owner(&mut e, &t, &new_owner);

    // Control before flooring: the distinct-owner taker's LP-growing buy is NOT
    // halted by the (default, 0) floor — it gets past the P1 pre-matcher gates and
    // the matcher runs (the engine then refuses on the live Custom(21), as deployed).
    let pre = probe(&mut e, &t, &lp, unit());
    expect_code(&pre, E_LOCK_ACTIVE, "unfloored grow");
    assert!(matcher_invoked(&pre), "unfloored: the matcher must be invoked");

    // LP equity_init = capital 2,690,889,202 (pnl > 0 is not credited) < 1e12 floor.
    set_lp_floor(&mut e, 1_000_000_000_000);
    let lp_before = e.pos(&lp);
    let t_before = e.pos(&t);
    assert!(lp_before < 0 && t_before == -lp_before);

    // Grow on a floored LP: LpFloorHalt, pre-matcher.
    let grow = probe(&mut e, &t, &lp, unit());
    expect_code(&grow, E_LP_FLOOR_HALT, "floored grow");
    assert!(!matcher_invoked(&grow));

    // Reduce-through-flat (P1-K1): request |LP| + 1 unit; clipped to flatten.
    let snap: Vec<(Pubkey, Account)> =
        [e.slab, t, lp].iter().map(|k| (*k, e.svm.get_account(k).unwrap())).collect();
    let through = e.trade_cpi(&t, &lp, lp_before - unit());
    show(&format!("{} TradeCpi size {}", e.label, lp_before - unit()), &through);
    expect_ok(&through, "floored reduce-through-flat");
    assert!(matcher_invoked(&through));
    assert_eq!(e.pos(&lp), 0, "reduce-through-flat is clipped to exactly flat (LP)");
    assert_eq!(e.pos(&t), 0, "reduce-through-flat is clipped to exactly flat (taker)");
    for (k, a) in snap {
        e.svm.set_account(k, a).unwrap();
    }

    // Reduce on a floored LP: lands, both positions move by exactly one unit.
    let reduce = e.trade_cpi(&t, &lp, -unit());
    show(&format!("{} TradeCpi size {}", e.label, -unit()), &reduce);
    expect_ok(&reduce, "floored reduce");
    assert!(matcher_invoked(&reduce));
    assert_eq!(e.pos(&lp), lp_before + unit(), "floored reduce moved the LP toward flat");
    assert_eq!(e.pos(&t), t_before - unit(), "floored reduce moved the taker");
}
