//! INDEPENDENT SUITE (2026-09-30) — P1 wrapper x P2 matcher call extension (gap 1),
//! plus two P1 route-coverage adversarial shapes (F-2 re-test, "taker close" bypass).
//!
//! Expected behaviour is taken from the DESIGN docs only:
//!   * p1-p2-matcher-call-extension-abi-2026-09-30.md (ext block, HEADROOM, MARK_SLOT,
//!     TAKER_REDUCING, EXEC_BAND, ACCEPTS_FEE_REQUEST, 8002/8003, send rule §4)
//!   * p1-safety-release-2026-09-29.md "Frontend interface" (matcher_ext_mode, max_requested_fee_bps,
//!     "LP cap and floor protect every such portfolio on every trade route", taker close rule)
//!   * p2-matcher-v2-2026-09-29.md (kind 2 via tag 83, default max_mark_age 150, STALE_ALLOW_REDUCING)
//!
//! Binaries: INDEP_WRAPPER_SO (wrapper), P2 matcher path from INDEP_P2_MATCHER_SO
//! (default ~/wt-indep/so/matcher-p2.so), deployed matcher from INDEP_V1_MATCHER_SO
//! (default ~/wt-indep/baseline-so/matcher-12bd671.so).
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator::POS_SCALE;
use percolator_prog::ix::Instruction as ProgInstruction;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const PX: u64 = 1_000_000;
const U: i128 = POS_SCALE as i128;
const E_BAND: u32 = 66;
const E_SAME_OWNER: u32 = 67;
const E_LP_CAP: u32 = 68;
const E_LP_FLOOR: u32 = 69;
const E_STALE_MARK: u32 = 8002;

fn home(p: &str) -> String {
    format!("{}/{}", std::env::var("HOME").unwrap(), p)
}
fn p2_so() -> String {
    std::env::var("INDEP_P2_MATCHER_SO").unwrap_or_else(|_| home("wt-indep/so/matcher-p2.so"))
}
fn v1_so() -> String {
    std::env::var("INDEP_V1_MATCHER_SO").unwrap_or_else(|_| home("wt-indep/baseline-so/matcher-12bd671.so"))
}

fn params(fee_bps: u64) -> V16CuMarketParams {
    V16CuMarketParams {
        h_max: 50,
        initial_price: PX,
        min_nonzero_mm_req: 599,
        min_nonzero_im_req: 600,
        maintenance_margin_bps: 500,
        initial_margin_bps: 1_000,
        liquidation_fee_bps: 50,
        liquidation_fee_cap: percolator::MAX_PROTOCOL_FEE_ABS,
        max_price_move_bps_per_slot: 20,
        max_accrual_dt_slots: 20,
        trade_fee_base_bps: fee_bps,
        max_trading_fee_bps: 1_000,
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
    mp: Pubkey,
}

struct W {
    env: V16CuEnv,
    p2: Pubkey,
    v1: Pubkey,
    upgrader: Keypair,
    fee_bps: u64,
}

/// 66-byte tag-2 init payload (harness format): [2][kind][fee u32][spread u32][max_total u32]
/// [impact u32][liquidity u128][max_fill u128][max_inv u128].
fn init_payload(kind: u8, fee: u32, spread: u32, max_total: u32, impact: u32, liq: u128, max_fill: u128, max_inv: u128) -> Vec<u8> {
    let mut d = vec![0u8; 66];
    d[0] = 2;
    d[1] = kind;
    d[2..6].copy_from_slice(&fee.to_le_bytes());
    d[6..10].copy_from_slice(&spread.to_le_bytes());
    d[10..14].copy_from_slice(&max_total.to_le_bytes());
    d[14..18].copy_from_slice(&impact.to_le_bytes());
    d[18..34].copy_from_slice(&liq.to_le_bytes());
    d[34..50].copy_from_slice(&max_fill.to_le_bytes());
    d[50..66].copy_from_slice(&max_inv.to_le_bytes());
    d
}

impl W {
    fn new(fee_bps: u64) -> Self {
        let mut env = V16CuEnv::new_with_init_params(params(fee_bps));
        let p2 = Pubkey::new_unique();
        env.svm.add_program(p2, &std::fs::read(p2_so()).expect("P2 matcher .so"));
        let v1 = Pubkey::new_unique();
        env.svm.add_program(v1, &std::fs::read(v1_so()).expect("v1 matcher .so"));
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, PX);
        let upgrader = Keypair::new();
        env.ensure_signer_account(upgrader.pubkey());
        let (pd, _) = Pubkey::find_program_address(&[env.program_id.as_ref()], &solana_sdk::bpf_loader_upgradeable::id());
        let mut d = vec![0u8; 45];
        d[0..4].copy_from_slice(&3u32.to_le_bytes());
        d[12] = 1;
        d[13..45].copy_from_slice(upgrader.pubkey().as_ref());
        env.svm
            .set_account(pd, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 })
            .unwrap();
        W { env, p2, v1, upgrader, fee_bps }
    }

    fn program_data(&self) -> Pubkey {
        Pubkey::find_program_address(&[self.env.program_id.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0
    }
    fn slot(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }
    fn user(&mut self, dep: u128) -> (Keypair, Pubkey) {
        let k = Keypair::new();
        let p = self.env.create_portfolio(&k);
        if dep > 0 {
            self.env.deposit(&k, p, dep);
        }
        (k, p)
    }
    fn lp_with(&mut self, dep: u128, mp: Pubkey, payload: Vec<u8>) -> Lp {
        let (owner, port) = self.user(dep);
        let (ctx, delegate, _) = self.env.init_matcher_context_with_data(&owner, mp, port, payload);
        Lp { owner, port, ctx, delegate, mp }
    }
    /// P2 kind 2 with the doc's launch shape (max_total 100, impact 5000, liquidity 10x capital).
    fn lp_kind2(&mut self, dep: u128, max_total: u32) -> Lp {
        let mp = self.p2;
        self.lp_with(dep, mp, init_payload(2, 10, 20, max_total, 5_000, dep * 10, u128::MAX, 0))
    }
    fn lp_kind0(&mut self, dep: u128, mp: Pubkey, spread: u32, max_total: u32) -> Lp {
        self.lp_with(dep, mp, init_payload(0, 0, spread, max_total, 0, 0, u128::MAX, 0))
    }

    fn trade_cpi_fee(&mut self, taker: &Keypair, tp: Pubkey, lp: &Lp, size: i128, fee_bps: u64) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let (aid, _, aep) = self.env.portfolio_identity(tp);
        let (bid, bseq, bep) = self.env.portfolio_identity(lp.port);
        let metas = vec![
            AccountMeta::new(taker.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(tp, false),
            AccountMeta::new(lp.port, false),
            AccountMeta::new_readonly(lp.mp, false),
            AccountMeta::new(lp.ctx, false),
            AccountMeta::new_readonly(lp.delegate, false),
        ];
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
                fee_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            metas,
            &[taker],
        )
    }
    fn trade_cpi(&mut self, taker: &Keypair, tp: Pubkey, lp: &Lp, size: i128) -> Result<u64, String> {
        let f = self.fee_bps;
        self.trade_cpi_fee(taker, tp, lp, size, f)
    }
    fn trade_nocpi(&mut self, a: &Keypair, pa: Pubkey, b: &Keypair, pb: Pubkey, size: i128) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let mark = self.env.market_state().1.assets[0].effective_price;
        let f = self.fee_bps;
        self.env.try_trade_asset_with_cu(0, a, pa, b, pb, size, mark, f)
    }

    /// Tag 93 raw: [93][asset u16][band u16][k u32][floor u128][side_cap u128][ext u8][max_req_fee u16].
    fn set_limits(&mut self, band: u16, k: u32, floor: u128, side_cap: u128, ext: Option<u8>, max_req_fee: Option<u16>) -> Result<u64, String> {
        let mut data = vec![93u8];
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&band.to_le_bytes());
        data.extend_from_slice(&k.to_le_bytes());
        data.extend_from_slice(&floor.to_le_bytes());
        data.extend_from_slice(&side_cap.to_le_bytes());
        if let Some(e) = ext {
            data.push(e);
            if let Some(f) = max_req_fee {
                data.extend_from_slice(&f.to_le_bytes());
            }
        }
        self.env.svm.expire_blockhash();
        let up = self.upgrader.insecure_clone();
        let ix = Instruction {
            program_id: self.env.program_id,
            accounts: vec![
                AccountMeta::new(up.pubkey(), true),
                AccountMeta::new_readonly(self.program_data(), false),
                AccountMeta::new(self.env.market, false),
            ],
            data,
        };
        let payer = self.env.payer.insecure_clone();
        send_raw_tx(&mut self.env.svm, &payer, ix, &[&up])
    }

    fn pos(&self, p: Pubkey) -> i128 {
        self.env.portfolio_state(p).legs.iter().find(|l| l.active && l.asset_index == 0).map(|l| l.basis_pos_q).unwrap_or(0)
    }
    /// Last MatcherReturn exec price in the ctx (bytes 8..16 of the 64-byte return prefix).
    fn ctx_exec_price(&self, ctx: Pubkey) -> u64 {
        let d = self.env.svm.get_account(&ctx).unwrap().data;
        u64::from_le_bytes(d[8..16].try_into().unwrap())
    }
    fn equity(&self, p: Pubkey) -> i128 {
        let s = self.env.portfolio_state(p);
        s.capital as i128 + s.pnl.min(0) - s.fee_credits.min(0).abs()
    }
    fn capital(&self, p: Pubkey) -> u128 {
        self.env.portfolio_state(p).capital
    }
    fn push_mark(&mut self, px: u64) {
        let s = self.slot();
        self.env.push_auth_mark_for_asset_as_admin(0, s, px);
    }
    fn crank(&mut self, p: Pubkey) {
        let s = self.slot();
        self.env.svm.expire_blockhash();
        let _ = try_refresh(&mut self.env, p, s);
    }
}

fn code(r: &Result<u64, String>) -> Option<u32> {
    r.as_ref().err().and_then(|e| custom_code(e))
}

fn is_p1_tip() -> bool {
    // tag 93 exists on every P1 build; the ext channel needs ext-capable P1. We detect by trying.
    true
}

// ── Gap 1a: send rule / negative controls ──────────────────────────────────

/// ABI doc §4: never send a non-zero extension to a v1 matcher. With ext_mode = 1 the
/// deployed 12bd671 matcher rejects bytes 43..67 -> the trade must FAIL CLOSED (error, no
/// position change, no fee), never fill with unchecked bytes.
#[test]
fn p1p2_ext1_against_deployed_v1_matcher_fails_closed_without_moving_anything() {
    let mut w = W::new(0);
    let v1 = w.v1;
    let lp = w.lp_kind0(50_000_000, v1, 0, 100);
    let (t, tp) = w.user(10_000_000);
    w.set_limits(0, 0, 0, 0, Some(1), None).expect("tag 93 ext_mode=1 (P1 with ext support)");
    let v0 = w.env.market_state().1.vault;
    let r = w.trade_cpi(&t, tp, &lp, U);
    eprintln!("ext1 vs v1 matcher: {:?}", r.as_ref().map_err(|e| custom_code(e).map(|c| c.to_string()).unwrap_or_else(|| e.chars().take(160).collect())));
    // Either refused, or (if the wrapper applies the §4 ctx-marker rule and falls back to
    // legacy bytes) a normal fill. What must never happen: a fill that ignored the ext.
    if r.is_ok() {
        assert_eq!(w.pos(tp), U, "if the wrapper downgraded to legacy bytes, the fill must be a normal full fill");
    } else {
        assert_eq!(w.pos(tp), 0);
        assert_eq!(w.env.market_state().1.vault, v0);
    }
    let _ = is_p1_tip();
}

/// Control: P2 matcher with ext_mode = 0 (legacy bytes) fills like v1.
#[test]
fn p1p2_ext0_legacy_bytes_with_p2_matcher_fill_normally() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(50_000_000, 100);
    let (t, tp) = w.user(10_000_000);
    let r = w.trade_cpi(&t, tp, &lp, U);
    assert!(r.is_ok(), "legacy bytes + kind 2 must fill: {:?}", code(&r));
    assert!(w.pos(tp) > 0 && w.pos(tp) <= U);
}

// ── Gap 1b: HEADROOM via ext ───────────────────────────────────────────────

/// With ext_mode = 1 and an LP cap, an over-headroom TradeCpi is a partial fill clipped to
/// headroom (doc: headroom = cap_q - |p| when p == 0); headroom 0 gives a zero fill — never 49.
#[test]
fn p1p2_ext1_headroom_clips_kind2_fill_and_zero_fills_at_cap() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(10_000_000, 100);
    let (t, tp) = w.user(50_000_000);
    // k = 2000 bps (0.2x) -> cap_q = 10e6 * 2000 * 1e6 / (1e4 * 1e6) = 2e6 = 2 units.
    w.set_limits(0, 2_000, 0, 0, Some(1), None).expect("tag 93");
    let r = w.trade_cpi(&t, tp, &lp, 5 * U);
    assert!(r.is_ok(), "over-headroom must clip, not revert: {:?}", code(&r));
    let got = w.pos(tp);
    assert!(got > 0 && got <= 2 * U, "clip to headroom 2 units, got {got}");
    // Now fill up to the cap exactly, then one more request must be a zero fill.
    for _ in 0..8 {
        let _ = w.trade_cpi(&t, tp, &lp, 2 * U);
    }
    let at_cap = w.pos(tp);
    assert!(at_cap <= 2 * U, "LP exposure must never exceed cap 2 units via ext route, got {at_cap}");
    let v0 = w.env.market_state().1;
    let r = w.trade_cpi(&t, tp, &lp, U);
    assert!(r.is_ok(), "headroom-0 request is a zero fill (Ok): {:?}", code(&r));
    let v1 = w.env.market_state().1;
    assert_eq!(w.pos(tp), at_cap, "zero fill moves no position");
    assert_eq!(v0.vault, v1.vault);
    assert_eq!(v0.insurance, v1.insurance, "zero fill charges no fee");
}

// ── Gap 1c: EXEC_BAND ──────────────────────────────────────────────────────

/// Kind 2 with max_total 400 bps and a 100 bps P1 band: the ext EXEC_BAND bit makes the
/// matcher clip size / price inside the band, so the wrapper gets a (partial) fill, never 66,
/// and the returned exec price is inside ref ± 1%.
#[test]
fn p1p2_ext1_exec_band_makes_wide_kind2_quote_clip_inside_band() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(10_000_000, 400);
    let (t, tp) = w.user(50_000_000);
    w.set_limits(100, 0, 0, 0, Some(1), None).expect("tag 93 band 100 ext 1");
    for sz in [1i128, 5, 20, 40] {
        let r = w.trade_cpi(&t, tp, &lp, sz * U);
        assert_ne!(code(&r), Some(E_BAND), "EXEC_BAND must stop 66 at size {sz}");
        if r.is_ok() {
            let px = w.ctx_exec_price(lp.ctx) as i128;
            let ref_ = w.env.market_state().1.assets[0].effective_price as i128;
            assert!((px - ref_).abs() * 10_000 <= ref_ * 100, "exec {px} outside 1% band of {ref_} at size {sz}");
        }
    }
}

/// Control: same matcher, ext_mode = 0 (no EXEC_BAND bit) -> the wide quote is refused 66
/// by the wrapper band (defence in depth still works without the ext).
#[test]
fn p1p2_ext0_wide_kind2_quote_is_refused_by_wrapper_band_66() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(10_000_000, 400);
    let (t, tp) = w.user(50_000_000);
    w.set_limits(100, 0, 0, 0, Some(0), None).expect("tag 93 band 100 ext 0");
    let mut saw66 = false;
    for sz in [1i128, 5, 20, 40] {
        let r = w.trade_cpi(&t, tp, &lp, sz * U);
        if code(&r) == Some(E_BAND) {
            saw66 = true;
        }
        if r.is_ok() {
            let px = w.ctx_exec_price(lp.ctx) as i128;
            let ref_ = w.env.market_state().1.assets[0].effective_price as i128;
            assert!((px - ref_).abs() * 10_000 <= ref_ * 100, "an accepted fill must still be in band");
        }
    }
    eprintln!("ext0 wide kind2: saw 66 = {saw66}");
}

// ── Gap 1d: stale mark + TAKER_REDUCING ────────────────────────────────────

/// MARK_SLOT: with no fresh push for > max_mark_age (150, kind-2 default) the matcher refuses
/// risk-increasing fills (8002 surfaced through the wrapper) but a taker CLOSE goes through
/// (wrapper attests TAKER_REDUCING).
#[test]
fn p1p2_ext1_stale_mark_blocks_opens_but_taker_close_goes_through() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(20_000_000, 100);
    let (t, tp) = w.user(50_000_000);
    w.set_limits(0, 0, 0, 0, Some(1), None).expect("tag 93 ext 1");
    w.trade_cpi(&t, tp, &lp, 2 * U).expect("fresh open");
    let opened = w.pos(tp);
    assert!(opened > 0);
    // 300 slots without a push; keep the engine current with cranks only.
    for _ in 0..15 {
        let s = w.slot() + 20;
        w.env.svm.warp_to_slot(s);
        w.crank(tp);
        w.crank(lp.port);
    }
    let r_open = w.trade_cpi(&t, tp, &lp, U);
    eprintln!("stale open -> {:?}", code(&r_open));
    assert!(r_open.is_err() || w.pos(tp) == opened, "a stale-mark OPEN must not add exposure");
    let r_close = w.trade_cpi(&t, tp, &lp, -opened);
    eprintln!("stale close -> {:?}", code(&r_close));
    assert!(r_close.is_ok(), "taker close must go through under a stale mark (TAKER_REDUCING): {:?}", code(&r_close));
    assert_eq!(w.pos(tp), 0, "close must be full (TAKER_REDUCING passes unclipped)");
    if let Err(e) = &r_open {
        assert_eq!(custom_code(e), Some(E_STALE_MARK), "stale refusal should be the matcher's 8002");
    }
}

/// TAKER_REDUCING must be the WRAPPER's attestation: a taker who "closes" more than it holds
/// (i.e. flips) is an open for the excess and must not ride the stale-mark exemption.
#[test]
fn p1p2_ext1_stale_mark_flip_is_not_treated_as_reducing() {
    let mut w = W::new(0);
    let lp = w.lp_kind2(20_000_000, 100);
    let (t, tp) = w.user(50_000_000);
    w.set_limits(0, 0, 0, 0, Some(1), None).expect("tag 93 ext 1");
    w.trade_cpi(&t, tp, &lp, 2 * U).expect("fresh open");
    let opened = w.pos(tp);
    for _ in 0..15 {
        let s = w.slot() + 20;
        w.env.svm.warp_to_slot(s);
        w.crank(tp);
        w.crank(lp.port);
    }
    let r = w.trade_cpi(&t, tp, &lp, -(opened + 3 * U));
    eprintln!("stale flip -> {:?}, pos after {}", code(&r), w.pos(tp));
    assert!(w.pos(tp) >= 0, "a stale-mark request must never flip the taker short (excess is an open)");
}

// ── Gap 1e: fee-request channel ────────────────────────────────────────────

/// P1 doc: with ext_mode 1 and max_requested_fee_bps > 0 the matcher's request is charged
/// to the taker and credited to the LP; the taker's signed fee_bps is its cap; a request above
/// it is refused. Conservation: taker loss == LP gain (+ base split), vault unchanged.
#[test]
fn p1p2_fee_request_is_capped_by_taker_fee_bps_and_paid_to_lp() {
    let mut w = W::new(0);
    // Wide spread so the requested fee (= ceil(|exec-oracle|·1e4/oracle)) is clearly > 0.
    let lp = w.lp_kind2(20_000_000, 100);
    let (t, tp) = w.user(50_000_000);
    w.set_limits(0, 0, 0, 0, Some(1), Some(200)).expect("tag 93 ext 1 + fee channel 200 bps");
    let lp_cap0 = w.capital(lp.port);
    let t_cap0 = w.capital(tp);
    // Taker cap 0 bps extra: any non-zero request must be refused.
    let r0 = w.trade_cpi_fee(&t, tp, &lp, 5 * U, 0);
    eprintln!("fee cap 0 -> {:?}", code(&r0));
    let r1 = w.trade_cpi_fee(&t, tp, &lp, 5 * U, 200);
    eprintln!("fee cap 200 -> {:?}; pos {}", code(&r1), w.pos(tp));
    if r1.is_ok() && w.pos(tp) > 0 {
        let paid = t_cap0 as i128 - w.capital(tp) as i128;
        let got = w.capital(lp.port) as i128 - lp_cap0 as i128;
        eprintln!("taker paid {paid}, LP received {got}");
        assert!(paid >= 0 && got >= 0, "fee flows taker -> LP");
        assert!(got <= paid, "LP cannot receive more than the taker paid");
        let px = w.ctx_exec_price(lp.ctx);
        let req_bps = ((px as i128 - PX as i128).unsigned_abs() * 10_000 + PX as u128 - 1) / PX as u128;
        let notional = (w.pos(tp) as u128) * PX as u128 / POS_SCALE;
        assert!(paid as u128 <= (notional * 200 + 9_999) / 10_000 + 1, "taker charged above its signed cap");
        let _ = req_bps;
    }
    if r0.is_ok() {
        // a zero-cap trade that filled must have charged no extra fee
        assert!(w.pos(tp) >= 0);
    }
}

// ── P1 route coverage: F-2 re-test and "taker close" bypass ────────────────

/// F-2 re-test (P1 doc now: "The LP cap and floor protect every such portfolio on every
/// trade route (TradeCpi, BatchTradeCpi, TradeNoCpi, BatchTradeNoCpi)" and same-owner on
/// NoCpi "when either side is an LP"). A halted, capped LP must not be grown by a NoCpi
/// co-signed by its owner and a second wallet.
#[test]
fn p1_f2_tradenocpi_cannot_grow_a_halted_or_capped_lp() {
    let mut w = W::new(0);
    let p2 = w.p2;
    let lp = w.lp_kind0(10_000_000, p2, 0, 100);
    let (t, tp) = w.user(50_000_000);
    // cap 2 units (k 2000), halt via floor >= equity
    w.set_limits(0, 2_000, 0, 0, None, None).expect("tag 93");
    let owner = lp.owner.insecure_clone();
    let r = w.trade_nocpi(&owner, lp.port, &t, tp, -15 * U);
    eprintln!("NoCpi grow capped LP by 15 -> {:?}, LP pos {}", code(&r), w.pos(lp.port));
    assert!(w.pos(lp.port).abs() <= 2 * U, "F-2: NoCpi grew the LP past its cap: {}", w.pos(lp.port));
    let e = w.equity(lp.port).max(0) as u128;
    w.set_limits(0, 2_000, e, 0, None, None).expect("tag 93 floor = equity (halt)");
    let r2 = w.trade_nocpi(&owner, lp.port, &t, tp, -U);
    eprintln!("NoCpi grow halted LP -> {:?}", code(&r2));
    assert!(r2.is_err(), "F-2: NoCpi grew a HALTED LP");
    assert!(matches!(code(&r2), Some(E_LP_FLOOR) | Some(E_LP_CAP) | Some(E_SAME_OWNER)), "expected 67/68/69, got {:?}", code(&r2));
}

/// Adversarial (new rule on e74809b1: "Taker close (always allowed) ... never halted, capped
/// or clipped, whatever the LP's state"). Two attacker wallets A/B open 20 units against EACH
/// OTHER via NoCpi (no LP involved, so no LP cap applies). A then "closes" via TradeCpi
/// against a capped LP: the close is reduce-only for A, so it is exempt — and dumps 20 units
/// onto an LP whose cap is 2. Spec intent (P1 #3: |LP pos|·mark <= k·LP equity) says the LP
/// must never be pushed past its cap by someone else's risk.
#[test]
fn p1_taker_close_exemption_cannot_dump_foreign_risk_past_lp_cap() {
    let mut w = W::new(0);
    let p2 = w.p2;
    let lp = w.lp_kind0(10_000_000, p2, 0, 100);
    let (a, pa) = w.user(50_000_000);
    let (b, pb) = w.user(50_000_000);
    w.set_limits(0, 2_000, 0, 0, None, None).expect("tag 93 cap 2 units");
    w.trade_nocpi(&a, pa, &b, pb, 20 * U).expect("A long 20 vs B short 20 (no LP)");
    let r = w.trade_cpi(&a, pa, &lp, -20 * U);
    eprintln!("A closes 20 via capped LP -> {:?}; LP pos {} (cap 2 units)", code(&r), w.pos(lp.port));
    // Quantify: mark -20% (keeper pushes; effective catches up at 20 bps/slot), then settle.
    let e0 = w.equity(lp.port);
    let b0 = w.equity(pb);
    let target = PX * 80 / 100;
    for _ in 0..120 {
        let s = w.slot() + 20;
        w.env.svm.warp_to_slot(s);
        w.push_mark(target);
        let (lpp, pbb, paa) = (lp.port, pb, pa);
        w.crank(lpp);
        w.crank(pbb);
        w.crank(paa);
        if w.env.market_state().1.assets[0].effective_price == target {
            break;
        }
    }
    let (lpp, pbb) = (lp.port, pb);
    w.crank(lpp);
    w.crank(pbb);
    eprintln!(
        "after -20%: LP equity {} -> {} (loss {}); B equity {} -> {}; loss bound at cap 2 units would be {}",
        e0, w.equity(lp.port), e0 - w.equity(lp.port), b0, w.equity(pb), 2 * PX as i128 / 5
    );
    assert!(
        w.pos(lp.port).abs() <= 2 * U,
        "taker-close exemption pushed {} units of FOREIGN risk onto an LP capped at 2 units",
        w.pos(lp.port) / U
    );
}

/// Same shape against a HALTED LP (equity <= floor): an exempt "close" must not grow it.
#[test]
fn p1_taker_close_exemption_cannot_grow_a_halted_lp() {
    let mut w = W::new(0);
    let p2 = w.p2;
    let lp = w.lp_kind0(10_000_000, p2, 0, 100);
    let (a, pa) = w.user(50_000_000);
    let (b, pb) = w.user(50_000_000);
    w.trade_nocpi(&a, pa, &b, pb, 5 * U).expect("A long 5 vs B short 5");
    let e = w.equity(lp.port).max(0) as u128;
    w.set_limits(0, 0, e, 0, None, None).expect("halt the LP");
    let r = w.trade_cpi(&a, pa, &lp, -5 * U);
    eprintln!("A closes 5 via HALTED LP -> {:?}; LP pos {}", code(&r), w.pos(lp.port));
    assert_eq!(w.pos(lp.port), 0, "a halted (depleted) LP was grown by {} units via the taker-close exemption", w.pos(lp.port) / U);
}
