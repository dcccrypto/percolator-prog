//! INDEPENDENT SUITE (2026-09-30) — P1 wrapper safety release, adversarial scenarios.
//!
//! Expected values come from the P1 DESIGN DOC (`p1-safety-release-2026-09-29.md`,
//! "Frontend interface" + §1 table) and `p1-p2-matcher-call-extension-abi-2026-09-30.md`,
//! and from engine spec.md §9 rule 7/9. Builder code was read only for wire layouts.
//!
//! Every test is written for the P1 spec. Run it against both binaries:
//!   INDEP_WRAPPER_SO=~/wt-indep/baseline-so/wrapper-v18.2.so   (negative control)
//!   INDEP_WRAPPER_SO=~/wt-indep/p1-so/percolator_prog-<sha>.so (must pass)
//! Tests tagged `[record]` print behaviour and only assert invariants that hold on both.
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator::POS_SCALE;
use percolator_prog::{ix::Instruction as ProgInstruction, state};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const PX: u64 = 1_000_000;
const U: i128 = POS_SCALE as i128; // one base unit in engine Q

// ── doc constants ──────────────────────────────────────────────────────────
const E_BAND: u32 = 66;
const E_SAME_OWNER: u32 = 67;
const E_LP_CAP: u32 = 68;
const E_LP_FLOOR: u32 = 69;
const E_SIDE_OI: u32 = 70;
const E_IM: u32 = 49;
const LIMITS_OFF: usize = 1958; // + 2325*i  (doc: "Absolute byte offset")

fn params(initial_price: u64, fee_bps: u64) -> V16CuMarketParams {
    // Envelope-valid 10x market (same family as the conservation fuzz world).
    V16CuMarketParams {
        h_max: 50,
        initial_price,
        min_nonzero_mm_req: 599,
        min_nonzero_im_req: 600,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        liquidation_fee_bps: 50,
        liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
        max_price_move_bps_per_slot: 20,
        max_accrual_dt_slots: 20,
        trade_fee_base_bps: fee_bps,
        max_bankrupt_close_lifetime_slots: 100,
        max_abs_funding_e9_per_slot: 1_000,
        min_funding_lifetime_slots: 10_000_000,
        ..V16CuMarketParams::default()
    }
}

struct Lp {
    owner: Keypair,
    port: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

struct W {
    env: V16CuEnv,
    mp: Pubkey,
    upgrader: Keypair,
    fee_bps: u64,
}

impl W {
    fn new(price: u64, fee_bps: u64) -> Self {
        let mut env = V16CuEnv::new_with_init_params(params(price, fee_bps));
        let mp = Pubkey::new_unique();
        let bytes = std::fs::read(matcher_program_path()).unwrap();
        env.svm.add_program(mp, &bytes);
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, price);
        // Mock ProgramData with a dedicated upgrade authority (same byte contract as
        // tests/v16_cu.rs tag-85 fixture).
        let upgrader = Keypair::new();
        env.ensure_signer_account(upgrader.pubkey());
        let (pd, _) = Pubkey::find_program_address(
            &[env.program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        );
        let mut d = vec![0u8; 45];
        d[0..4].copy_from_slice(&3u32.to_le_bytes());
        d[12] = 1;
        d[13..45].copy_from_slice(upgrader.pubkey().as_ref());
        env.svm
            .set_account(
                pd,
                Account {
                    lamports: 1_000_000_000,
                    data: d,
                    owner: solana_sdk::bpf_loader_upgradeable::id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        W { env, mp, upgrader, fee_bps }
    }

    fn program_data(&self) -> Pubkey {
        Pubkey::find_program_address(
            &[self.env.program_id.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        )
        .0
    }

    fn user(&mut self, dep: u128) -> (Keypair, Pubkey) {
        let k = Keypair::new();
        let p = self.env.create_portfolio(&k);
        if dep > 0 {
            self.env.deposit(&k, p, dep);
        }
        (k, p)
    }

    fn lp(&mut self, dep: u128, spread_bps: u32, max_total_bps: u32) -> Lp {
        let (owner, port) = self.user(dep);
        let mp = self.mp;
        let (ctx, delegate, _) = self
            .env
            .init_matcher_context_with_passive_spread(&owner, mp, port, spread_bps, max_total_bps);
        Lp { owner, port, ctx, delegate }
    }

    fn cpi_metas(&self, taker: &Pubkey, tp: Pubkey, lp: &Lp) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(*taker, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(tp, false),
            AccountMeta::new(lp.port, false),
            AccountMeta::new_readonly(self.mp, false),
            AccountMeta::new(lp.ctx, false),
            AccountMeta::new_readonly(lp.delegate, false),
        ]
    }

    fn trade_cpi(&mut self, taker: &Keypair, tp: Pubkey, lp: &Lp, size: i128, limit: u64) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(lp.port);
        let metas = self.cpi_metas(&taker.pubkey(), tp, lp);
        self.env.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id: 1,
                account_b_matcher_sequence: bseq,
                asset_index: 0,
                size_q: size,
                fee_bps: self.fee_bps,
                limit_price: limit,
                backing_fee_cap_bps: 10_000,
            },
            metas,
            &[taker],
        )
    }

    fn batch_cpi(&mut self, taker: &Keypair, tp: Pubkey, lp: &Lp, size: i128) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(lp.port);
        let metas = self.cpi_metas(&taker.pubkey(), tp, lp);
        self.env.send(
            ProgInstruction::BatchTradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                account_b_matcher_sequence: bseq,
                max_slippage_atoms: u128::MAX,
                max_fee_atoms: u128::MAX,
                legs: vec![percolator_prog::ix::BatchTradeCpiLeg {
                    asset_index: 0,
                    market_id: 1,
                    size_q: size,
                    fee_bps: self.fee_bps,
                    limit_price: 0,
                }],
            },
            metas,
            &[taker],
        )
    }

    fn trade_nocpi(&mut self, a: &Keypair, pa: Pubkey, b: &Keypair, pb: Pubkey, size: i128) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let mark = self.env.market_state().1.assets[0].effective_price;
        self.env
            .try_trade_asset_with_cu(0, a, pa, b, pb, size, mark, self.fee_bps)
    }

    /// Tag 93 SetAssetRiskLimits, raw bytes per the doc (41/42 B).
    fn set_limits_as(
        &mut self,
        signer: &Keypair,
        band: u16,
        k: u32,
        floor: u128,
        side_cap: u128,
        ext: Option<u8>,
    ) -> Result<u64, String> {
        let mut data = vec![93u8];
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&band.to_le_bytes());
        data.extend_from_slice(&k.to_le_bytes());
        data.extend_from_slice(&floor.to_le_bytes());
        data.extend_from_slice(&side_cap.to_le_bytes());
        if let Some(e) = ext {
            data.push(e);
        }
        self.env.ensure_signer_account(signer.pubkey());
        self.env.svm.expire_blockhash();
        let ix = Instruction {
            program_id: self.env.program_id,
            accounts: vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new_readonly(self.program_data(), false),
                AccountMeta::new(self.env.market, false),
            ],
            data,
        };
        let payer = self.env.payer.insecure_clone();
        send_raw_tx(&mut self.env.svm, &payer, ix, &[signer])
    }

    fn set_limits(&mut self, band: u16, k: u32, floor: u128, side_cap: u128) {
        let up = self.upgrader.insecure_clone();
        self.set_limits_as(&up, band, k, floor, side_cap, None)
            .expect("tag 93 SetAssetRiskLimits by the upgrade authority (P1 only)");
    }

    fn pos(&self, p: Pubkey) -> i128 {
        self.env
            .portfolio_state(p)
            .legs
            .iter()
            .find(|l| l.active && l.asset_index == 0)
            .map(|l| l.basis_pos_q)
            .unwrap_or(0)
    }

    fn ctx_exec_price(&self, ctx: Pubkey) -> u64 {
        let d = self.env.svm.get_account(&ctx).unwrap().data;
        u64::from_le_bytes(d[8..16].try_into().unwrap())
    }

    fn slot(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    /// Move the AUTH mark and let the effective price fully catch up via permissionless cranks.
    fn move_mark(&mut self, new_mark: u64, crank_on: &[Pubkey]) {
        let s = self.slot() + 1;
        self.env.svm.warp_to_slot(s);
        self.env.push_auth_mark_for_asset_as_admin(0, s, new_mark);
        for _ in 0..200 {
            let (_, g) = self.env.market_state();
            if g.assets[0].effective_price == new_mark {
                break;
            }
            let s = self.slot() + 20;
            self.env.svm.warp_to_slot(s);
            self.env.push_auth_mark_for_asset_as_admin(0, s, new_mark);
            for p in crank_on {
                self.env.svm.expire_blockhash();
                let _ = try_refresh(&mut self.env, *p, s);
            }
        }
        let s = self.slot() + 1;
        self.env.svm.warp_to_slot(s);
        self.env.push_auth_mark_for_asset_as_admin(0, s, new_mark);
        for p in crank_on {
            self.env.svm.expire_blockhash();
            let _ = try_refresh(&mut self.env, *p, s);
        }
    }

    fn limits_bytes(&self) -> Vec<u8> {
        let d = self.env.svm.get_account(&self.env.market).unwrap().data;
        d[LIMITS_OFF..LIMITS_OFF + 64].to_vec()
    }
}

fn code(r: &Result<u64, String>) -> Option<u32> {
    r.as_ref().err().and_then(|e| custom_code(e))
}

fn expect_code(r: Result<u64, String>, c: u32, label: &str) {
    match &r {
        Ok(_) => panic!("{label}: expected Custom({c}) but tx SUCCEEDED"),
        Err(e) => assert_eq!(custom_code(e), Some(c), "{label}: expected Custom({c}); got {}", &e[..e.len().min(300)]),
    }
}

/// Doc: cap_q = floor(E·k·1e6 / (10_000·price)).
fn doc_cap_q(e: u128, k: u128, price: u128) -> u128 {
    e * k * POS_SCALE / (10_000 * price)
}

/// Doc: E = max(0, capital + min(pnl,0) − max(0, −fee_credits)).
fn doc_equity(w: &W, p: Pubkey) -> u128 {
    let s = w.env.portfolio_state(p);
    let e = s.capital as i128 + s.pnl.min(0) - (-s.fee_credits).max(0);
    e.max(0) as u128
}

// ════════════════════════════════════════════════════════════════════════════
// 1. Oracle band
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_band_default_500_accepts_exact_edge_both_sides() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 500, 9_000);
    let (t, tp) = w.user(100_000_000);
    w.trade_cpi(&t, tp, &lp, U, 0).expect("buy at exactly ref*(1+500bps) must be inside the band");
    assert_eq!(w.ctx_exec_price(lp.ctx), 1_050_000, "vacuity: matcher quoted exactly at the edge");
    assert_eq!(w.pos(tp), U);
    w.trade_cpi(&t, tp, &lp, -2 * U, 0).expect("sell at exactly ref*(1-500bps) must be inside the band");
    assert_eq!(w.ctx_exec_price(lp.ctx), 950_000, "vacuity: bid edge");
    assert_eq!(w.pos(tp), -U);
}

#[test]
fn p1_band_default_500_refuses_one_bps_outside_66() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 501, 9_000);
    let (t, tp) = w.user(100_000_000);
    let before = w.env.svm.get_account(&w.env.market).unwrap().data;
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_BAND, "501bps ask outside default 500bps band");
    expect_code(w.trade_cpi(&t, tp, &lp, -U, 0), E_BAND, "501bps bid outside default 500bps band");
    assert_eq!(w.env.svm.get_account(&w.env.market).unwrap().data, before, "refusal must not mutate");
    assert_eq!(w.pos(tp), 0);
}

/// Matcher ceil-rounding pushes an at-spread ask one tick past ref·(1+band): the doc rule
/// `|exec−ref|·1e4 ≤ ref·band` is strict integer math, so the fill must be refused.
#[test]
fn p1_band_rounding_one_e6_tick_outside_is_refused() {
    let px = 1_000_001u64;
    let mut w = W::new(px, 0);
    let lp = w.lp(1_000_000_000, 500, 9_000);
    let (t, tp) = w.user(100_000_000);
    // Matcher ask = ceil(1_000_001·10_500/10_000) = 1_050_002; |Δ|·1e4 = 500_010_000 > ref·500 = 500_000_500.
    let r = w.trade_cpi(&t, tp, &lp, U, 0);
    expect_code(r, E_BAND, "ask 1 tick beyond the exact band edge");
    // Bid = floor(1_000_001·9_500/10_000) = 950_000; |Δ|·1e4 = 500_010_000 > 500_000_500 → also outside.
    expect_code(w.trade_cpi(&t, tp, &lp, -U, 0), E_BAND, "bid 1 tick beyond the band edge");
}

#[test]
fn p1_band_limit_price_zero_or_max_does_not_bypass() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 2_000, 9_000); // 20% quote
    let (t, tp) = w.user(100_000_000);
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_BAND, "limit 0 = inside band, not any price");
    expect_code(w.trade_cpi(&t, tp, &lp, U, u64::MAX), E_BAND, "consenting taker limit cannot widen band");
}

#[test]
fn p1_band_set_via_tag93_tightens_to_100bps() {
    let mut w = W::new(PX, 0);
    let lp_ok = w.lp(1_000_000_000, 100, 9_000);
    let lp_bad = w.lp(1_000_000_000, 101, 9_000);
    let (t, tp) = w.user(100_000_000);
    // Default band (500) accepts both before tightening — vacuity for the tag-93 effect.
    w.trade_cpi(&t, tp, &lp_bad, U, 0).expect("101bps inside default band");
    w.set_limits(100, 0, 0, 0);
    let b = w.limits_bytes();
    assert_eq!(u16::from_le_bytes([b[36], b[37]]), 100, "band persisted at doc offset +36");
    w.trade_cpi(&t, tp, &lp_ok, U, 0).expect("100bps == band edge accepted");
    expect_code(w.trade_cpi(&t, tp, &lp_bad, U, 0), E_BAND, "101bps outside tag-93 band");
}

#[test]
fn p1_band_batch_trade_cpi_is_banded() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 501, 9_000);
    let (t, tp) = w.user(100_000_000);
    expect_code(w.batch_cpi(&t, tp, &lp, U), E_BAND, "BatchTradeCpi leg outside band");
    let lp2 = w.lp(1_000_000_000, 500, 9_000);
    w.batch_cpi(&t, tp, &lp2, U).expect("BatchTradeCpi at band edge accepted");
    assert_eq!(w.pos(tp), U);
}

// ════════════════════════════════════════════════════════════════════════════
// 2. Same-owner
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_same_owner_lp_owner_as_taker_67() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 0, 100);
    let owner = lp.owner.insecure_clone();
    let own_taker = w.env.create_portfolio(&owner);
    w.env.deposit(&owner, own_taker, 100_000_000);
    expect_code(w.trade_cpi(&owner, own_taker, &lp, U, 0), E_SAME_OWNER, "LP owner trading its own LP");
    expect_code(w.batch_cpi(&owner, own_taker, &lp, U), E_SAME_OWNER, "LP owner via BatchTradeCpi");
    assert_eq!(w.pos(own_taker), 0);
}

#[test]
fn p1_same_owner_asset_admin_as_taker_67() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 0, 100);
    let admin = w.env.admin.insecure_clone();
    let ap = w.env.create_portfolio(&admin);
    w.env.deposit(&admin, ap, 100_000_000);
    expect_code(w.trade_cpi(&admin, ap, &lp, U, 0), E_SAME_OWNER, "asset_admin (creator) as taker");
}

/// Pins the doc's own caveat: a SECOND wallet of the same person is not caught (hygiene only).
/// This is the ANSEM shape and must stay documented as unfixed by P1.
#[test]
fn p1_same_owner_second_wallet_bypass_is_not_caught() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 0, 100);
    let (sock, sp) = w.user(100_000_000);
    w.trade_cpi(&sock, sp, &lp, 5 * U, 0).expect("second wallet trades the creator's LP");
    assert_eq!(w.pos(sp), 5 * U);
    assert_eq!(w.pos(lp.port), -5 * U);
}

// ════════════════════════════════════════════════════════════════════════════
// 3/4. LP exposure cap + headroom clip + zero fill
// ════════════════════════════════════════════════════════════════════════════

/// Odd k + non-round price so floor() matters. Doc: cap_q = ⌊E·k·1e6/(1e4·price)⌋.
#[test]
fn p1_lp_cap_exact_boundary_fills_and_one_over_is_clipped() {
    let px = 1_000_003u64;
    let mut w = W::new(px, 0);
    let lp = w.lp(1_000_000, 0, 100); // E = 1e6 atoms
    let k = 3_333u32;
    w.set_limits(0, k, 0, 0);
    let e = doc_equity(&w, lp.port);
    let cap = doc_cap_q(e, k as u128, px as u128);
    assert_eq!(e, 1_000_000);
    assert_eq!(cap, 333_299, "doc formula sanity (1e6·3333·1e6/(1e4·1_000_003) floored)");
    let (t, tp) = w.user(100_000_000);
    // One over: TradeCpi clips to exactly cap.
    w.trade_cpi(&t, tp, &lp, cap as i128 + 1, 0).expect("over-cap TradeCpi must clip, not revert");
    assert_eq!(w.pos(lp.port), -(cap as i128), "clip lands exactly on the doc cap");
    assert_eq!(w.pos(tp), cap as i128);
}

#[test]
fn p1_lp_cap_exact_boundary_request_equal_to_cap_fills_fully() {
    let px = 1_000_003u64;
    let mut w = W::new(px, 0);
    let lp = w.lp(1_000_000, 0, 100);
    w.set_limits(0, 3_333, 0, 0);
    let cap = doc_cap_q(doc_equity(&w, lp.port), 3_333, px as u128);
    let (t, tp) = w.user(100_000_000);
    w.trade_cpi(&t, tp, &lp, cap as i128, 0).expect("exactly cap fills");
    assert_eq!(w.pos(tp), cap as i128);
}

#[test]
fn p1_lp_cap_batch_over_cap_refused_68() {
    let px = 1_000_003u64;
    let mut w = W::new(px, 0);
    let lp = w.lp(1_000_000, 0, 100);
    w.set_limits(0, 3_333, 0, 0);
    let cap = doc_cap_q(doc_equity(&w, lp.port), 3_333, px as u128);
    let (t, tp) = w.user(100_000_000);
    expect_code(w.batch_cpi(&t, tp, &lp, cap as i128 + 1), E_LP_CAP, "batch is atomic: named refusal");
    w.batch_cpi(&t, tp, &lp, cap as i128).expect("batch exactly at cap");
}

/// E excludes positive PnL: an LP that is winning must not get a larger cap.
#[test]
fn p1_lp_cap_ignores_lp_positive_pnl() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(2_000_000, 0, 100);
    w.set_limits(0, 10_000, 0, 0); // k = 1x
    let (t, tp) = w.user(100_000_000);
    w.trade_cpi(&t, tp, &lp, U, 0).expect("open 1 unit (LP short 1)");
    // Price falls 2% -> LP short gains.
    w.move_mark(980_000, &[lp.port, tp]);
    let s = w.env.portfolio_state(lp.port);
    assert!(s.pnl > 0 || s.capital > 2_000_000, "vacuity: LP must be winning (pnl {} cap {})", s.pnl, s.capital);
    let price = w.env.market_state().1.assets[0].effective_price as u128;
    let e = doc_equity(&w, lp.port);
    let cap = doc_cap_q(e, 10_000, price);
    let p_abs = w.pos(lp.port).unsigned_abs();
    let m = cap.max(p_abs);
    let headroom = m - p_abs; // LP grows short on a taker buy
    let with_pnl = doc_cap_q(e + s.pnl.max(0) as u128, 10_000, price).max(p_abs) - p_abs;
    let before = w.pos(tp);
    w.trade_cpi(&t, tp, &lp, 50 * U, 0).expect("over-headroom buy clips");
    let filled = (w.pos(tp) - before) as u128;
    eprintln!("[cap-vs-pnl] E={e} pnl={} price={price} cap={cap} |p|={p_abs} headroom={headroom} with_pnl={with_pnl} filled={filled}", s.pnl);
    assert_eq!(filled, headroom, "fill must equal doc headroom computed WITHOUT positive pnl");
    if s.pnl > 0 {
        assert!(with_pnl > headroom, "vacuity: counting pnl would have allowed more");
    }
}

/// Zero fill: headroom 0 -> Ok, no position change, no fee, req-id committed, vault synced.
#[test]
fn p1_headroom_zero_fill_moves_nothing_and_consumes_sequence() {
    let mut w = W::new(PX, 30);
    let lp = w.lp(1_000_000, 0, 100);
    w.set_limits(0, 10_000, 0, 0);
    let (t, tp) = w.user(100_000_000);
    let (_, sq_a, _) = w.env.portfolio_identity(lp.port);
    w.trade_cpi(&t, tp, &lp, 10 * U, 0).expect("fill to cap");
    let (_, sq_b, _) = w.env.portfolio_identity(lp.port);
    eprintln!("[zero-fill] normal (clipped) fill advanced LP matcher_sequence {sq_a} -> {sq_b}");
    let lp_pos = w.pos(lp.port);
    assert!(lp_pos < 0, "vacuity: LP at cap");
    let (_, g0) = w.env.market_state();
    let taker0 = w.env.portfolio_state(tp);
    let (_, seq0, _) = w.env.portfolio_identity(lp.port);
    let rid0 = u64::from_le_bytes(w.env.svm.get_account(&lp.ctx).unwrap().data[32..40].try_into().unwrap());
    w.trade_cpi(&t, tp, &lp, U, 0).expect("headroom 0 => Ok zero fill (not 49)");
    let (_, g1) = w.env.market_state();
    let taker1 = w.env.portfolio_state(tp);
    assert_eq!(w.pos(lp.port), lp_pos, "no LP position change");
    assert_eq!(taker1.capital, taker0.capital, "no fee charged on a zero fill");
    assert_eq!(g1.insurance, g0.insurance, "no fee reached insurance");
    assert_eq!(w.env.token_amount(w.env.vault) as u128, g1.vault, "vault sync");
    let (_, seq1, _) = w.env.portfolio_identity(lp.port);
    assert_eq!(seq1, seq0, "LP matcher_sequence is config-bound (unchanged by fills)");
    // Doc says the zero fill is 'Ok, req_id committed'. Whatever the wrapper does, the stale
    // matcher response left in ctx (req_id rid0) must never be consumed again: the next real
    // fill must carry a strictly newer req_id.
    let ctxd = w.env.svm.get_account(&lp.ctx).unwrap().data;
    let rid1 = u64::from_le_bytes(ctxd[32..40].try_into().unwrap());
    let matcher_called = rid1 != rid0;
    w.trade_cpi(&t, tp, &lp, U, 0).expect("second zero fill");
    w.trade_cpi(&t, tp, &lp, -U / 2, 0).expect("reducing fill (headroom available) must fill");
    assert_eq!(w.pos(lp.port), lp_pos + U / 2, "reducing fill landed");
    let rid3 = u64::from_le_bytes(w.env.svm.get_account(&lp.ctx).unwrap().data[32..40].try_into().unwrap());
    eprintln!("[zero-fill] matcher invoked on zero fill: {matcher_called}; req_id prev-fill {rid0} -> next real fill {rid3} (2 zero fills in between)");
    assert!(rid3 > rid0, "stale matcher response must not be reusable");
}

// ════════════════════════════════════════════════════════════════════════════
// 5. LP floor halt
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_lp_floor_halt_refuses_growth_allows_reduction_69() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(10_000_000, 0, 100);
    let (t, tp) = w.user(100_000_000);
    w.trade_cpi(&t, tp, &lp, 3 * U, 0).expect("open while healthy");
    // Floor at/above LP equity => halted (doc: halted = E <= lp_floor_atoms).
    let e = doc_equity(&w, lp.port);
    w.set_limits(0, 0, e, 0);
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_LP_FLOOR, "growing LP short while halted");
    expect_code(w.batch_cpi(&t, tp, &lp, U), E_LP_FLOOR, "batch growing while halted");
    w.trade_cpi(&t, tp, &lp, -U, 0).expect("reducing LP exposure works while halted");
    assert_eq!(w.pos(lp.port), -2 * U);
    // Flip beyond flat grows the other side -> refused.
    expect_code(w.trade_cpi(&t, tp, &lp, -3 * U, 0), E_LP_FLOOR, "flip through zero grows LP long");
    w.trade_cpi(&t, tp, &lp, -2 * U, 0).expect("exact flatten allowed");
    assert_eq!(w.pos(lp.port), 0);
}

/// Halt griefing: with trades at mark, the LP's equity cannot be moved by trading alone
/// (fees go to insurance, fills settle at mark). Record the price move required instead.
#[test]
fn p1_lp_halt_griefing_cost_record() {
    let mut w = W::new(PX, 30);
    let lp = w.lp(10_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    let e0 = doc_equity(&w, lp.port);
    for _ in 0..20 {
        w.trade_cpi(&t, tp, &lp, 5 * U, 0).expect("open");
        w.trade_cpi(&t, tp, &lp, -5 * U, 0).expect("close");
    }
    let e1 = doc_equity(&w, lp.port);
    let taker_paid = 1_000_000_000u128 - w.env.portfolio_state(tp).capital;
    eprintln!("[halt-grief] 20 round trips of 5 units: LP equity {e0} -> {e1}; attacker paid {taker_paid} atoms in fees");
    assert_eq!(e1, e0, "wash trading at mark must not change LP equity");
    // Price-move cost: attacker long X units against LP; mark +m% => LP loses X·m.
    let x = 10 * U;
    w.trade_cpi(&t, tp, &lp, x, 0).expect("attacker opens");
    w.move_mark(1_100_000, &[lp.port, tp]);
    let e2 = doc_equity(&w, lp.port);
    eprintln!("[halt-grief] attacker long 10 units, mark +10%: LP equity {e1} -> {e2} (needs an oracle move; keeper-signed AUTH mark)");
}

// ════════════════════════════════════════════════════════════════════════════
// 6. Side OI cap
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_side_oi_cap_growth_only_70() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    let (b, bp) = w.user(1_000_000_000);
    w.set_limits(0, 0, 0, (3 * U) as u128);
    w.trade_cpi(&t, tp, &lp, 3 * U, 0).expect("grow long OI to exactly the cap");
    assert_eq!(w.env.market_state().1.assets[0].oi_eff_long_q, (3 * U) as u128);
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_SIDE_OI, "long OI past cap via TradeCpi");
    expect_code(w.trade_nocpi(&t, tp, &b, bp, U), E_SIDE_OI, "long OI past cap via TradeNoCpi (all routes)");
    // Lower cap below current OI: shrink still allowed.
    w.set_limits(0, 0, 0, U as u128);
    w.trade_cpi(&t, tp, &lp, -U, 0).expect("shrinking long OI above a lowered cap");
    assert_eq!(w.env.market_state().1.assets[0].oi_eff_long_q, (2 * U) as u128);
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_SIDE_OI, "still above cap: no growth");
}

// ════════════════════════════════════════════════════════════════════════════
// 7. Tag 93 authorization + persistence
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_tag93_only_upgrade_authority_and_persists_at_doc_offsets() {
    let mut w = W::new(PX, 0);
    let before = w.limits_bytes();
    assert!(before.iter().all(|b| *b == 0), "fresh market limits are all-zero (defaults)");
    let admin = w.env.admin.insecure_clone();
    let rnd = Keypair::new();
    for (who, k) in [("marketauth/asset_admin/creator", &admin), ("random", &rnd)] {
        let r = w.set_limits_as(k, 123, 4_567, 89, 1_011, Some(1));
        assert!(r.is_err(), "tag 93 by {who} must be refused");
        eprintln!("[tag93] {who}: code {:?}", code(&r));
        assert_eq!(w.limits_bytes(), before, "refused tag 93 by {who} must not write");
    }
    // Wrong ProgramData account (not the program's PDA) must be refused even with the right signer.
    let up = w.upgrader.insecure_clone();
    let fake_pd = Pubkey::new_unique();
    let mut d = vec![0u8; 45];
    d[0..4].copy_from_slice(&3u32.to_le_bytes());
    d[12] = 1;
    d[13..45].copy_from_slice(up.pubkey().as_ref());
    w.env
        .svm
        .set_account(fake_pd, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 })
        .unwrap();
    let mut data = vec![93u8, 0, 0];
    data.extend_from_slice(&7u16.to_le_bytes()[..0]);
    let mut raw = vec![93u8];
    raw.extend_from_slice(&0u16.to_le_bytes());
    raw.extend_from_slice(&123u16.to_le_bytes());
    raw.extend_from_slice(&4_567u32.to_le_bytes());
    raw.extend_from_slice(&89u128.to_le_bytes());
    raw.extend_from_slice(&1_011u128.to_le_bytes());
    let _ = data;
    w.env.svm.expire_blockhash();
    let payer = w.env.payer.insecure_clone();
    let r = send_raw_tx(
        &mut w.env.svm,
        &payer,
        Instruction {
            program_id: w.env.program_id,
            accounts: vec![
                AccountMeta::new(up.pubkey(), true),
                AccountMeta::new_readonly(fake_pd, false),
                AccountMeta::new(w.env.market, false),
            ],
            data: raw,
        },
        &[&up],
    );
    assert!(r.is_err(), "spoofed ProgramData must be refused");
    // Real authority succeeds; fields at doc offsets.
    w.set_limits_as(&up, 123, 4_567, 89, 1_011, Some(1)).expect("upgrade authority sets limits");
    let b = w.limits_bytes();
    assert_eq!(u128::from_le_bytes(b[0..16].try_into().unwrap()), 1_011, "side_oi_cap_q @+0");
    assert_eq!(u128::from_le_bytes(b[16..32].try_into().unwrap()), 89, "lp_floor_atoms @+16");
    assert_eq!(u32::from_le_bytes(b[32..36].try_into().unwrap()), 4_567, "lp_exposure_k_bps @+32");
    assert_eq!(u16::from_le_bytes(b[36..38].try_into().unwrap()), 123, "exec_band_bps @+36");
    assert_eq!(b[38], 1, "matcher_ext_mode @+38");
    assert!(b[39..64].iter().all(|x| *x == 0), "reserved stays zero");
}

// ════════════════════════════════════════════════════════════════════════════
// 8. LP drain (COLLECT / Murphy shape)
// ════════════════════════════════════════════════════════════════════════════

/// Traders win repeatedly against a small LP. Baseline: the next open fails Custom(49).
/// P1: never 49 — a clip / zero fill (Ok) or 69.
#[test]
fn p1_lp_drain_never_reverts_49() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(3_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    let mut mark = PX;
    let mut min_eq: i128 = i128::MAX;
    let mut results = Vec::new();
    for round in 0..12 {
        let r = w.trade_cpi(&t, tp, &lp, 20 * U, 0);
        results.push(format!("r{round}:open={:?}", r.as_ref().map(|_| "ok").map_err(|e| custom_code(e))));
        assert_ne!(code(&r), Some(E_IM), "round {round}: open must never revert with Custom(49) on P1");
        mark = mark * 103 / 100;
        w.move_mark(mark, &[lp.port, tp]);
        let tpos = w.pos(tp);
        if tpos != 0 {
            let r = w.trade_cpi(&t, tp, &lp, -tpos, 0);
            results.push(format!("close={:?}", r.as_ref().map(|_| "ok").map_err(|e| custom_code(e))));
        }
        let s = w.env.portfolio_state(lp.port);
        min_eq = min_eq.min(s.capital as i128 + s.pnl);
    }
    eprintln!("[lp-drain] {} | LP min equity {min_eq}", results.join(" "));
    let (_, g) = w.env.market_state();
    assert_eq!(w.env.token_amount(w.env.vault) as u128, g.vault);
}

// ════════════════════════════════════════════════════════════════════════════
// 10. Stale-mark fills (spec §9 rule 7: reject risk-increasing trades while target != effective)
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_stale_mark_risk_increasing_fill_during_lag_is_rejected() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(1_000_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    // Exposed OI is required for the per-slot clamp to bind (zero-OI fast-forward, spec §10.13).
    w.trade_cpi(&t, tp, &lp, 5 * U, 0).expect("seed open interest");
    let s = w.slot() + 1;
    w.env.svm.warp_to_slot(s);
    w.env.push_auth_mark_for_asset_as_admin(0, s, 1_100_000); // +10% target, effective lags
    let s2 = s + 1;
    w.env.svm.warp_to_slot(s2);
    w.env.push_auth_mark_for_asset_as_admin(0, s2, 1_100_000);
    let _ = try_refresh(&mut w.env, lp.port, s2); // one bounded step: effective moves <= 20bps/slot
    let (_, g) = w.env.market_state();
    assert_ne!(g.assets[0].raw_oracle_target_price, g.assets[0].effective_price, "vacuity: market must be lagged");
    eprintln!("[stale] target {} effective {}", g.assets[0].raw_oracle_target_price, g.assets[0].effective_price);
    let r = w.trade_cpi(&t, tp, &lp, 10 * U, 0);
    eprintln!("[stale] TradeCpi buy during lag: {:?} exec_price_in_ctx={}", r.as_ref().map_err(|e| custom_code(e)), w.ctx_exec_price(lp.ctx));
    if g.assets[0].raw_oracle_target_price != g.assets[0].effective_price {
        assert!(r.is_err(), "spec §9.7: a risk-increasing fill at the lagged mark must be rejected");
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 9. [record] TEXTIT one-sided domain — expired domain-1 bucket
// ════════════════════════════════════════════════════════════════════════════

#[test]
fn p1_record_one_sided_domain_after_bucket_lapse() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(2_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    w.trade_cpi(&t, tp, &lp, 10 * U, 0).expect("taker long 10 vs LP");
    // Price down: taker loses (domain of long side opens a loss bucket), LP wins backed PnL.
    w.move_mark(900_000, &[tp, lp.port]);
    let (_, g) = w.env.market_state();
    let st: Vec<String> = g.source_backing_buckets.iter().map(|b| format!("{:?}@{}", b.status, b.expiry_slot)).collect();
    eprintln!("[textit] buckets after loss: {st:?}; LP pnl {} cap {}", w.env.portfolio_state(lp.port).pnl, w.env.portfolio_state(lp.port).capital);
    // Lapse all buckets without repairs.
    let far = w.slot() + 2_000;
    w.env.svm.warp_to_slot(far);
    w.env.push_auth_mark_for_asset_as_admin(0, far, 900_000);
    for _ in 0..200 {
        w.env.svm.expire_blockhash();
        if try_refresh(&mut w.env, lp.port, far).is_err() { break; }
        if w.env.market_state().1.assets[0].slot_last >= far { break; }
    }
    let buy = w.trade_cpi(&t, tp, &lp, U, 0);
    let sell = w.trade_cpi(&t, tp, &lp, -20 * U, 0);
    eprintln!("[textit] lapsed: taker buy -> {:?}, taker sell (grows LP long) -> {:?}", buy.as_ref().map_err(|e| custom_code(e)), sell.as_ref().map_err(|e| custom_code(e)));
    assert_ne!(code(&sell), Some(E_IM), "P1: never Custom(49) on the dead side");
}

// ════════════════════════════════════════════════════════════════════════════
// Extra edges: opposite-side headroom, batch aggregation, NoCpi scope gap
// ════════════════════════════════════════════════════════════════════════════

/// Doc: if sign(p) != d, headroom = M + |p| with M = max(cap_q, |p|).
#[test]
fn p1_headroom_through_zero_is_cap_plus_existing_opposite_position() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(2_000_000, 0, 100);
    w.set_limits(0, 10_000, 0, 0); // k=1x -> cap_q = E (price 1e6)
    let (t, tp) = w.user(1_000_000_000);
    w.trade_cpi(&t, tp, &lp, -U, 0).expect("taker sells 1 -> LP long 1");
    assert_eq!(w.pos(lp.port), U);
    let e = doc_equity(&w, lp.port);
    let cap = doc_cap_q(e, 10_000, PX as u128);
    let p = U as u128;
    let m = cap.max(p);
    let headroom = m + p;
    let before = w.pos(tp);
    w.trade_cpi(&t, tp, &lp, 50 * U, 0).expect("big buy clips");
    let filled = (w.pos(tp) - before) as u128;
    eprintln!("[headroom-flip] E={e} cap={cap} |p|={p} doc headroom={headroom} filled={filled}");
    assert_eq!(filled, headroom, "fill through zero = M + |p|");
    assert_eq!(w.pos(lp.port), -(cap as i128), "LP ends exactly at -cap");
}

/// Two same-asset legs each within cap but jointly over it: refused. Control shows the refusal is
/// the duplicate-asset rule (9), so cross-leg cap aggregation is unreachable on one asset.
#[test]
fn p1_batch_same_asset_legs_refused_9_so_cross_leg_cap_is_unreachable() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(2_000_000, 0, 100);
    w.set_limits(0, 10_000, 0, 0);
    let cap = doc_cap_q(doc_equity(&w, lp.port), 10_000, PX as u128) as i128;
    let (t, tp) = w.user(1_000_000_000);
    let leg = |sz: i128| percolator_prog::ix::BatchTradeCpiLeg { asset_index: 0, market_id: 1, size_q: sz, fee_bps: 0, limit_price: 0 };
    w.env.svm.expire_blockhash();
    let (aid, _, aep) = w.env.portfolio_identity(tp);
    let (bid, bseq, bep) = w.env.portfolio_identity(lp.port);
    let metas = w.cpi_metas(&t.pubkey(), tp, &lp);
    let r = w.env.send(
        ProgInstruction::BatchTradeCpi {
            account_a_portfolio_id: aid, account_a_position_epoch: aep,
            account_b_portfolio_id: bid, account_b_position_epoch: bep,
            account_b_matcher_sequence: bseq, max_slippage_atoms: u128::MAX, max_fee_atoms: u128::MAX,
            legs: vec![leg(cap / 2 + 1), leg(cap / 2 + 1)],
        },
        metas,
        &[&t],
    );
    eprintln!("[batch-2leg] cap={cap} legs={} each -> {:?}", cap / 2 + 1, r.as_ref().map_err(|e| custom_code(e)));
    assert_eq!(w.pos(tp), 0, "no partial application");
    assert!(r.is_err(), "jointly over-cap batch must be refused");
    // Control: two tiny same-asset legs — is the refusal about the cap or about duplicate legs?
    w.env.svm.expire_blockhash();
    let (aid, _, aep) = w.env.portfolio_identity(tp);
    let (bid, bseq, bep) = w.env.portfolio_identity(lp.port);
    let metas = w.cpi_metas(&t.pubkey(), tp, &lp);
    let r2 = w.env.send(
        ProgInstruction::BatchTradeCpi {
            account_a_portfolio_id: aid, account_a_position_epoch: aep,
            account_b_portfolio_id: bid, account_b_position_epoch: bep,
            account_b_matcher_sequence: bseq, max_slippage_atoms: u128::MAX, max_fee_atoms: u128::MAX,
            legs: vec![leg(1_000), leg(1_000)],
        },
        metas,
        &[&t],
    );
    eprintln!("[batch-2leg] control tiny duplicate legs -> {:?}", r2.as_ref().map_err(|e| custom_code(e)));
    assert_eq!(code(&r2), Some(9), "duplicate same-asset legs are refused regardless of size");
}

/// [record / design gap] P1 scopes cap/floor/same-owner to the matcher routes. A creator who
/// controls the LP key and a second wallet can still grow a HALTED LP's exposure via TradeNoCpi.
#[test]
fn p1_record_tradenocpi_bypasses_lp_floor_halt_and_cap() {
    let mut w = W::new(PX, 0);
    let lp = w.lp(2_000_000, 0, 100);
    let (t, tp) = w.user(1_000_000_000);
    let e = doc_equity(&w, lp.port);
    w.set_limits(0, 10_000, e, 0); // halted (E <= floor), cap = 1x
    expect_code(w.trade_cpi(&t, tp, &lp, U, 0), E_LP_FLOOR, "vacuity: CPI route is halted");
    let lp_owner = lp.owner.insecure_clone();
    let r = w.trade_nocpi(&t, tp, &lp_owner, lp.port, 15 * U);
    eprintln!("[nocpi-gap] halted LP, TradeNoCpi 15 units (cap {} q) -> {:?}; LP pos {}", doc_cap_q(e, 10_000, PX as u128), r.as_ref().map_err(|x| custom_code(x)), w.pos(lp.port));
}
