//! Ports of boyle-michael's aeyakovenko/percolator#175 PoCs
//! (`tests/v16_cu/cross_asset_source_netting.rs`, `tests/v16_cu/cross_asset_claim_rollover.rs`,
//! issue comments 2026-08-14; verbatim copies and sha256 in
//! `percolator-ops/ledger/evidence/boyle-175/`) onto OUR wrapper ABI (6377376a lineage).
//!
//! Port deltas, identical across tests (none changes the economics under test):
//! - Upstream per-asset authority rotation (`ASSET_AUTH_ORACLE` / `ASSET_AUTH_BACKING_BUCKET`)
//!   does not exist in our ABI; marks are pushed and the domain-3 backing is provided by the
//!   market admin. The actor-independence claim is a reachability claim, not an economic one.
//! - Upstream's `auth_matcher` fixture is replaced by our passive percolator-match matcher,
//!   initialised by the LP owner once; every trade after that is signed by the taker only.
//! - `BatchTradeCpi` leg order is reproduced by sequential single-leg `TradeCpi` in the same
//!   order (attachment order is what selects the physical leg slot).
//! - The two single-transaction "atomic" sequences are sent as consecutive transactions. The
//!   end state is the same; atomicity only removes the victim's chance to react.
//!
//! Three families:
//! - `boyle175_asw_*`  "as written": boyle's assertions of the STRANDED state, ported. On an
//!   engine with the negative-first whole-account K/F plan (upstream 661110b3, in our 35ddd692)
//!   the same-refresh witnesses no longer strand anything, so these are EXPECTED TO FAIL on
//!   both the deployed and the fixed engine; they document that the PoCs as written are stale.
//! - `boyle175_ok_*`   the same scenarios, asserting the CORRECT outcome (every claim backed,
//!   provider whole, every account exits at fair equity, vault drains to zero).
//! - `boyle175_ts_*`   the time-separated form (each mark settled in its own refresh), which the
//!   ordering fix cannot reach: red on 35ddd692, green on the source-reclassification fix.
use super::*;

const PRICE: u64 = 100;
const PROFIT_PRICE: u64 = 110;
const LOSS_PRICE: u64 = 90;
const LATER_LOSS_PRICE: u64 = 80;
const DEPOSIT: u128 = 1_000;
const PNL: u128 = 10;
const PROFIT_ASSET: u16 = 1;
const LOSS_ASSET: u16 = 0;
const PROFIT_SOURCE_DOMAIN: u16 = 3; // asset-1 short source backs a long winner
const LOSS_SOURCE_DOMAIN: usize = 0; // asset-0 long source backs a short winner

#[derive(Clone, Copy)]
struct Route {
    program: Pubkey,
    context: Pubkey,
    delegate: Pubkey,
}

struct Witness {
    env: V16CuEnv,
    taker_owner: Keypair,
    lp_owner: Keypair,
    taker: Pubkey,
    lp: Pubkey,
    route: Route,
}

fn add_matcher(env: &mut V16CuEnv) -> Pubkey {
    let program = Pubkey::new_unique();
    let bytes = std::fs::read(matcher_program_path()).expect("read matcher BPF");
    env.svm.add_program(program, &bytes);
    program
}

fn lp_route(env: &mut V16CuEnv, program: Pubkey, owner: &Keypair, lp: Pubkey) -> Route {
    let (context, delegate, _) = env.init_matcher_context(owner, program, lp);
    Route {
        program,
        context,
        delegate,
    }
}

#[allow(clippy::too_many_arguments)]
fn trade(
    env: &mut V16CuEnv,
    taker_owner: &Keypair,
    taker: Pubkey,
    lp_owner: &Keypair,
    lp: Pubkey,
    route: Route,
    asset_index: u16,
    size_q: i128,
) {
    env.svm.expire_blockhash();
    env.try_trade_cpi_with_cu_on_asset(
        taker_owner,
        taker,
        lp_owner,
        lp,
        route.program,
        route.context,
        route.delegate,
        asset_index,
        size_q,
        0,
    )
    .unwrap_or_else(|e| panic!("taker-only TradeCpi asset {asset_index} size {size_q}: {e}"));
}

fn crank_at(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64, assets: &[u16]) {
    env.svm.expire_blockhash();
    env.crank(
        portfolio,
        ProgInstruction::PermissionlessCrank {
            now_slot,
            observations: assets
                .iter()
                .map(|&asset_index| CrankObservationHint {
                    asset_index,
                    oracle_accounts: 0,
                })
                .collect(),
        },
    );
}

fn try_crank(env: &mut V16CuEnv, portfolio: Pubkey, now_slot: u64) -> Result<u64, String> {
    env.svm.expire_blockhash();
    env.send(
        ProgInstruction::PermissionlessCrank {
            now_slot,
            observations: vec![],
        },
        vec![
            AccountMeta::new(env.payer.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
        ],
        &[],
    )
}

fn try_convert(
    env: &mut V16CuEnv,
    owner: &Keypair,
    portfolio: Pubkey,
    amount: u128,
) -> Result<u64, String> {
    env.svm.expire_blockhash();
    let (portfolio_id, _, position_epoch) = env.portfolio_identity(portfolio);
    env.send(
        ProgInstruction::ConvertReleasedPnl {
            portfolio_id,
            position_epoch,
            amount,
        },
        vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
        ],
        &[owner],
    )
}

fn try_withdraw(
    env: &mut V16CuEnv,
    owner: &Keypair,
    portfolio: Pubkey,
    amount: u128,
) -> Result<Pubkey, String> {
    env.svm.expire_blockhash();
    let dest = env.token_account(owner.pubkey(), 0);
    let (portfolio_id, expected_sequence, _) = env.portfolio_identity(portfolio);
    env.send(
        ProgInstruction::Withdraw {
            portfolio_id,
            expected_sequence,
            amount,
        },
        vec![
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(portfolio, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[owner],
    )
    .map(|_| dest)
}

fn try_withdraw_backing(env: &mut V16CuEnv, amount: u128) -> Result<Pubkey, String> {
    env.svm.expire_blockhash();
    let admin = env.admin.pubkey();
    let dest = env.token_account(admin, 0);
    env.try_withdraw_backing_bucket_to_admin_token_with_cu(dest, PROFIT_SOURCE_DOMAIN, amount)
        .map(|_| dest)
}

fn setup_with_risk(backing: u128, margin_bps: u64, max_move_bps: u64) -> Witness {
    let mut env =
        V16CuEnv::new_with_market_params_and_price_move(2, margin_bps, margin_bps, max_move_bps);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(LOSS_ASSET, 1, PRICE);
    env.configure_auth_mark_for_asset_as_admin(PROFIT_ASSET, 1, PRICE);
    let taker_owner = Keypair::new();
    let lp_owner = Keypair::new();
    let taker = env.create_portfolio(&taker_owner);
    let lp = env.create_portfolio(&lp_owner);
    env.deposit(&taker_owner, taker, DEPOSIT);
    env.deposit(&lp_owner, lp, DEPOSIT);
    env.top_up_backing_bucket(PROFIT_SOURCE_DOMAIN, backing, 100);
    let program = add_matcher(&mut env);
    let route = lp_route(&mut env, program, &lp_owner, lp);
    Witness {
        env,
        taker_owner,
        lp_owner,
        taker,
        lp,
        route,
    }
}

fn setup() -> Witness {
    setup_with_risk(PNL, 10_000, 10_000)
}

fn w_trade(w: &mut Witness, asset: u16, size_q: i128) {
    let (to, lo) = (w.taker_owner.insecure_clone(), w.lp_owner.insecure_clone());
    trade(&mut w.env, &to, w.taker, &lo, w.lp, w.route, asset, size_q);
}

fn open(w: &mut Witness, profitable_first: bool) {
    let order = if profitable_first {
        [PROFIT_ASSET, LOSS_ASSET]
    } else {
        [LOSS_ASSET, PROFIT_ASSET]
    };
    for asset in order {
        w_trade(w, asset, POS_SCALE as i128);
    }
    let taker = w.env.portfolio_state(w.taker);
    let lp = w.env.portfolio_state(w.lp);
    for (slot, asset) in order.iter().enumerate() {
        assert_eq!(taker.legs[slot].asset_index, *asset as u32, "taker leg slot {slot}");
        assert_eq!(lp.legs[slot].asset_index, *asset as u32, "LP leg slot {slot}");
    }
}

fn flatten(w: &mut Witness, profitable_first: bool) {
    let order = if profitable_first {
        [PROFIT_ASSET, LOSS_ASSET]
    } else {
        [LOSS_ASSET, PROFIT_ASSET]
    };
    for asset in order {
        w_trade(w, asset, -(POS_SCALE as i128));
    }
    assert!(percolator::active_bitmap_is_empty(
        w.env.portfolio_state(w.taker).active_bitmap
    ));
    assert!(percolator::active_bitmap_is_empty(
        w.env.portfolio_state(w.lp).active_bitmap
    ));
}

/// Both marks committed at slot 2, then each account refreshed once (boyle's shape).
fn marks_same_refresh(w: &mut Witness, first: Pubkey, second: Pubkey) {
    w.env.svm.warp_to_slot(2);
    w.env
        .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, 2, PROFIT_PRICE);
    w.env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, 2, LOSS_PRICE);
    crank_at(&mut w.env, first, 2, &[PROFIT_ASSET, LOSS_ASSET]);
    crank_at(&mut w.env, second, 2, &[]);
}

/// Time-separated: the profitable asset moves and both accounts settle it first; the losing
/// asset moves one slot later and both accounts settle again.
fn marks_time_separated(w: &mut Witness) {
    let (taker, lp) = (w.taker, w.lp);
    w.env.svm.warp_to_slot(2);
    w.env
        .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, 2, PROFIT_PRICE);
    w.env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, 2, PRICE);
    crank_at(&mut w.env, taker, 2, &[PROFIT_ASSET, LOSS_ASSET]);
    crank_at(&mut w.env, lp, 2, &[]);
    w.env.svm.warp_to_slot(3);
    w.env
        .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, 3, PROFIT_PRICE);
    w.env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, 3, LOSS_PRICE);
    crank_at(&mut w.env, taker, 3, &[PROFIT_ASSET, LOSS_ASSET]);
    crank_at(&mut w.env, lp, 3, &[]);
}

fn now_slot(w: &Witness) -> u64 {
    w.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
}

/// Every domain with outstanding positive claims is fully backed.
fn assert_claims_backed(env: &V16CuEnv, label: &str) {
    let (_, group) = env.market_state();
    for (d, source) in group.source_credit.iter().enumerate() {
        if source.positive_claim_bound_num != 0 {
            assert_eq!(
                source.credit_rate_num,
                percolator::CREDIT_RATE_SCALE,
                "{label}: domain {d} claim {} under-backed (fresh {})",
                source.positive_claim_bound_num / BOUND_SCALE,
                source.fresh_reserved_backing_num / BOUND_SCALE,
            );
        }
    }
    assert_eq!(env.token_amount(env.vault), group.vault as u64, "{label}: SPL vault");
}

/// Flatten, convert every positive claim, withdraw every account's full capital and the
/// provider's principal; the market must end with nothing ownerless in the vault.
fn exit_everyone_and_assert_drained(w: &mut Witness, profitable_first: bool, label: &str) {
    flatten(w, profitable_first);
    for (owner, portfolio) in [
        (w.taker_owner.insecure_clone(), w.taker),
        (w.lp_owner.insecure_clone(), w.lp),
    ] {
        let pnl = w.env.portfolio_state(portfolio).pnl;
        if pnl > 0 {
            // A prior conversion moves the risk epoch: recertify with fresh marks (same
            // prices) at a new slot before converting.
            let slot = now_slot(w) + 1;
            w.env.svm.warp_to_slot(slot);
            let (_, group) = w.env.market_state();
            let (p1, p0) = (group.assets[1].effective_price, group.assets[0].effective_price);
            w.env.push_auth_mark_for_asset_as_admin(PROFIT_ASSET, slot, p1);
            w.env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, slot, p0);
            crank_at(&mut w.env, portfolio, slot, &[PROFIT_ASSET, LOSS_ASSET]);
            try_convert(&mut w.env, &owner, portfolio, pnl as u128)
                .unwrap_or_else(|e| panic!("{label}: backed claim must convert: {e}"));
        }
    }
    let mut paid = 0u128;
    for (owner, portfolio) in [
        (w.taker_owner.insecure_clone(), w.taker),
        (w.lp_owner.insecure_clone(), w.lp),
    ] {
        let state = w.env.portfolio_state(portfolio);
        assert_eq!(state.pnl, 0, "{label}: no residual pnl");
        assert_eq!(state.capital, DEPOSIT, "{label}: net-zero round trip");
        let dest = try_withdraw(&mut w.env, &owner, portfolio, DEPOSIT)
            .unwrap_or_else(|e| panic!("{label}: fair-equity withdraw must succeed: {e}"));
        paid += w.env.token_amount(dest) as u128;
    }
    assert_eq!(paid, 2 * DEPOSIT, "{label}: both traders withdraw their deposits");
    let (_, group) = w.env.market_state();
    let provider_fresh =
        group.source_backing_buckets[PROFIT_SOURCE_DOMAIN as usize].fresh_unliened_backing_num
            / BOUND_SCALE;
    assert_eq!(provider_fresh, PNL, "{label}: provider principal restored in domain 3");
    let dest = try_withdraw_backing(&mut w.env, PNL)
        .unwrap_or_else(|e| panic!("{label}: provider must withdraw its principal: {e}"));
    assert_eq!(w.env.token_amount(dest), PNL as u64);
    let (_, drained) = w.env.market_state();
    assert_eq!(
        (drained.vault, drained.c_tot, drained.pnl_pos_tot),
        (0, 0, 0),
        "{label}: nothing ownerless left in the vault"
    );
    assert_eq!(w.env.token_amount(w.env.vault), 0);
}

// ---------------------------------------------------------------------------------------------
// As written (stale on an engine with 661110b3). Each is boyle's assertion set, ported.
// ---------------------------------------------------------------------------------------------

fn asw_assert_live_stranded_state(w: &Witness) {
    let taker = w.env.portfolio_state(w.taker);
    let lp = w.env.portfolio_state(w.lp);
    let (_, group) = w.env.market_state();
    assert_eq!(taker.capital, DEPOSIT);
    assert_eq!(taker.pnl, 0);
    assert_eq!(lp.capital, DEPOSIT - PNL);
    assert_eq!(lp.pnl, PNL as i128);
    assert_eq!(group.c_tot, 2 * DEPOSIT - PNL);
    assert_eq!(group.pnl_pos_tot, PNL);
    assert_eq!(
        group.source_credit[LOSS_SOURCE_DOMAIN].positive_claim_bound_num,
        PNL * BOUND_SCALE
    );
    assert_eq!(
        group.source_backing_buckets[LOSS_SOURCE_DOMAIN].fresh_unliened_backing_num, 0,
        "no asset-0 backing was reserved when the taker's later loss was netted"
    );
    assert_eq!(
        group.source_backing_buckets[PROFIT_SOURCE_DOMAIN as usize].fresh_unliened_backing_num,
        PNL * BOUND_SCALE
    );
    assert_eq!(group.vault, 2 * DEPOSIT + PNL);
}

#[test]
#[ignore = "boyle #175 as written: stale on 661110b3 engines (expected to FAIL)"]
fn boyle175_asw_profitable_first_strands_flat_lp_claim() {
    let mut w = setup();
    open(&mut w, true);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, t, l);
    asw_assert_live_stranded_state(&w);
}

#[test]
#[ignore = "boyle #175 as written: stale on 661110b3 engines (expected to FAIL)"]
fn boyle175_asw_not_cured_by_refreshing_lp_first() {
    let mut w = setup();
    open(&mut w, true);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, l, t);
    asw_assert_live_stranded_state(&w);
}

#[test]
#[ignore = "boyle #175 as written: stale on 661110b3 engines (expected to FAIL)"]
fn boyle175_asw_reverse_order_moves_lock_to_provider() {
    let mut w = setup();
    open(&mut w, false);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, t, l);
    let taker = w.env.portfolio_state(w.taker);
    let lp = w.env.portfolio_state(w.lp);
    assert_eq!(taker.capital, DEPOSIT - PNL);
    assert_eq!(taker.pnl, PNL as i128);
    assert_eq!(lp.capital, DEPOSIT, "boyle: LP flat at 1000/0");
    assert_eq!(lp.pnl, 0);
    flatten(&mut w, false);
    let (to, tk) = (w.taker_owner.insecure_clone(), w.taker);
    try_convert(&mut w.env, &to, tk, PNL).expect("taker converts");
    assert!(
        try_withdraw_backing(&mut w.env, PNL).is_err(),
        "boyle: the provider cannot withdraw its ten atoms"
    );
}

#[test]
#[ignore = "boyle #175 as written: stale on 661110b3 engines (expected to FAIL)"]
fn boyle175_asw_full_deposit_lock_at_ten_percent_margin() {
    const SIZE_Q: i128 = 50 * POS_SCALE as i128;
    let mut w = setup_with_risk(DEPOSIT, 1_000, 500);
    w_trade(&mut w, PROFIT_ASSET, SIZE_Q);
    w_trade(&mut w, LOSS_ASSET, SIZE_Q);
    let flat_owner = Keypair::new();
    let flat = w.env.create_portfolio(&flat_owner);
    for (slot, profit_price, loss_price) in
        [(2, 105, 95), (3, 110, 91), (4, 115, 87), (5, 120, 83), (6, 120, 80)]
    {
        w.env.svm.warp_to_slot(slot);
        w.env
            .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, slot, profit_price);
        w.env
            .push_auth_mark_for_asset_as_admin(LOSS_ASSET, slot, loss_price);
        crank_at(&mut w.env, flat, slot, &[PROFIT_ASSET, LOSS_ASSET]);
    }
    let (t, l) = (w.taker, w.lp);
    crank_at(&mut w.env, t, 6, &[]);
    crank_at(&mut w.env, l, 6, &[]);
    let lp = w.env.portfolio_state(w.lp);
    assert_eq!(
        (lp.capital, lp.pnl),
        (0, DEPOSIT as i128),
        "boyle: one refresh locks 100% of the LP's deposit behind an unsupported claim"
    );
    let (_, group) = w.env.market_state();
    assert_eq!(
        group.source_backing_buckets[LOSS_SOURCE_DOMAIN].fresh_unliened_backing_num, 0,
        "boyle: no asset-0 backing behind the LP's claim"
    );
    w_trade(&mut w, PROFIT_ASSET, -SIZE_Q);
    w_trade(&mut w, LOSS_ASSET, -SIZE_Q);
    let (lo, lp_key) = (w.lp_owner.insecure_clone(), w.lp);
    let convert = try_convert(&mut w.env, &lo, lp_key, DEPOSIT);
    assert!(
        convert.as_ref().is_err_and(|e| e.contains("Custom(21)")),
        "boyle: entire-deposit claim stays EngineLockActive in Live: {convert:?}"
    );
}

#[test]
#[ignore = "boyle #175 as written: stale on 661110b3 engines (expected to FAIL)"]
fn boyle175_asw_old_claim_rollover_premise() {
    // Rollover premise: after A's profitable-first cross-asset refresh, B holds an UNBACKED
    // ten-atom asset-0 claim (boyle: "old d0 claim initially has no backing").
    let r = rollover_world();
    assert!(
        r.b_initial_convert
            .as_ref()
            .is_err_and(|e| e.contains("Custom(21)")),
        "boyle: old d0 claim initially has no backing: {:?}",
        r.b_initial_convert
    );
}

// ---------------------------------------------------------------------------------------------
// Correct outcome, same scenarios.
// ---------------------------------------------------------------------------------------------

#[test]
fn boyle175_ok_profitable_first_same_refresh() {
    let mut w = setup();
    open(&mut w, true);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, t, l);
    assert_claims_backed(&w.env, "profit-first taker-first");
    exit_everyone_and_assert_drained(&mut w, true, "profit-first taker-first");
}

#[test]
fn boyle175_ok_profitable_first_same_refresh_lp_first() {
    let mut w = setup();
    open(&mut w, true);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, l, t);
    assert_claims_backed(&w.env, "profit-first LP-first");
    exit_everyone_and_assert_drained(&mut w, true, "profit-first LP-first");
}

#[test]
fn boyle175_ok_reverse_order_same_refresh_provider_whole() {
    let mut w = setup();
    open(&mut w, false);
    let (t, l) = (w.taker, w.lp);
    marks_same_refresh(&mut w, t, l);
    assert_claims_backed(&w.env, "loss-first");
    exit_everyone_and_assert_drained(&mut w, false, "loss-first");
}

#[test]
fn boyle175_ok_full_deposit_ten_percent_margin() {
    const SIZE_Q: i128 = 50 * POS_SCALE as i128;
    let mut w = setup_with_risk(DEPOSIT, 1_000, 500);
    w_trade(&mut w, PROFIT_ASSET, SIZE_Q);
    w_trade(&mut w, LOSS_ASSET, SIZE_Q);
    let flat_owner = Keypair::new();
    let flat = w.env.create_portfolio(&flat_owner);
    for (slot, profit_price, loss_price) in
        [(2, 105, 95), (3, 110, 91), (4, 115, 87), (5, 120, 83), (6, 120, 80)]
    {
        w.env.svm.warp_to_slot(slot);
        w.env
            .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, slot, profit_price);
        w.env
            .push_auth_mark_for_asset_as_admin(LOSS_ASSET, slot, loss_price);
        crank_at(&mut w.env, flat, slot, &[PROFIT_ASSET, LOSS_ASSET]);
    }
    let (t, l) = (w.taker, w.lp);
    crank_at(&mut w.env, t, 6, &[]);
    crank_at(&mut w.env, l, 6, &[]);
    assert_claims_backed(&w.env, "full-deposit");
    let lp = w.env.portfolio_state(w.lp);
    assert_eq!(
        lp.capital as i128 + lp.pnl,
        DEPOSIT as i128,
        "LP equity is its deposit (+1000 on asset 0, -1000 on asset 1)"
    );
    // The flattened LP converts its whole claim and withdraws its deposit.
    w_trade(&mut w, PROFIT_ASSET, -SIZE_Q);
    w_trade(&mut w, LOSS_ASSET, -SIZE_Q);
    let (lo, lp_key) = (w.lp_owner.insecure_clone(), w.lp);
    let pnl = w.env.portfolio_state(lp_key).pnl;
    if pnl > 0 {
        try_convert(&mut w.env, &lo, lp_key, pnl as u128)
            .unwrap_or_else(|e| panic!("full-deposit: backed claim must convert: {e}"));
    }
    try_withdraw(&mut w.env, &lo, lp_key, DEPOSIT)
        .unwrap_or_else(|e| panic!("full-deposit: LP withdraws its deposit: {e}"));
}

// ---------------------------------------------------------------------------------------------
// Time-separated form: red on 35ddd692, green with the source-reclassification fix.
// ---------------------------------------------------------------------------------------------

#[test]
fn boyle175_ts_profitable_first_time_separated() {
    let mut w = setup();
    open(&mut w, true);
    marks_time_separated(&mut w);
    assert_claims_backed(&w.env, "time-separated profit-first");
    exit_everyone_and_assert_drained(&mut w, true, "time-separated profit-first");
}

#[test]
fn boyle175_ts_loss_first_time_separated() {
    let mut w = setup();
    open(&mut w, false);
    marks_time_separated(&mut w);
    assert_claims_backed(&w.env, "time-separated loss-first");
    exit_everyone_and_assert_drained(&mut w, false, "time-separated loss-first");
}

#[test]
fn boyle175_ts_full_deposit_ten_percent_margin() {
    // boyle's severity shape, but each account settles every step (keeper cadence), so the
    // asset-1 gain is booked before the asset-0 loss lands.
    const SIZE_Q: i128 = 50 * POS_SCALE as i128;
    let mut w = setup_with_risk(DEPOSIT, 1_000, 500);
    w_trade(&mut w, PROFIT_ASSET, SIZE_Q);
    w_trade(&mut w, LOSS_ASSET, SIZE_Q);
    let (t, l) = (w.taker, w.lp);
    for (slot, profit_price, loss_price) in [
        (2, 105, 100),
        (3, 110, 100),
        (4, 115, 100),
        (5, 120, 100),
        (6, 120, 95),
        (7, 120, 90),
        (8, 120, 86),
        (9, 120, 82),
        (10, 120, 80),
    ] {
        w.env.svm.warp_to_slot(slot);
        w.env
            .push_auth_mark_for_asset_as_admin(PROFIT_ASSET, slot, profit_price);
        w.env
            .push_auth_mark_for_asset_as_admin(LOSS_ASSET, slot, loss_price);
        crank_at(&mut w.env, t, slot, &[PROFIT_ASSET, LOSS_ASSET]);
        crank_at(&mut w.env, l, slot, &[]);
        assert_claims_backed(&w.env, &format!("keeper cadence slot {slot}"));
    }
    let lp = w.env.portfolio_state(w.lp);
    assert_eq!(lp.capital as i128 + lp.pnl, DEPOSIT as i128);
}

// ---------------------------------------------------------------------------------------------
// Claim rollover (cross_asset_claim_rollover.rs), ported.
// ---------------------------------------------------------------------------------------------

struct Rollover {
    b_initial_convert: Result<u64, String>,
    b_capital: u128,
    b_pnl: i128,
    d_convert: Option<Result<u64, String>>,
    a_convert: Option<Result<u64, String>>,
    provider: Result<(), String>,
    group_vault: u128,
    group_c_tot: u128,
    group_pnl_pos_tot: u128,
}

fn rollover_world() -> Rollover {
    let mut env = V16CuEnv::new_with_market_params_and_price_move(2, 10_000, 10_000, 10_000);
    env.svm.warp_to_slot(1);
    env.configure_auth_mark_for_asset_as_admin(LOSS_ASSET, 1, PRICE);
    env.configure_auth_mark_for_asset_as_admin(PROFIT_ASSET, 1, PRICE);
    let [a_o, v_o, b_o, c_o, d_o] = [(); 5].map(|_| Keypair::new());
    let a = env.create_portfolio(&a_o);
    let v = env.create_portfolio(&v_o);
    let b = env.create_portfolio(&b_o);
    let c = env.create_portfolio(&c_o);
    let d = env.create_portfolio(&d_o);
    for (o, p) in [(&a_o, a), (&v_o, v), (&b_o, b), (&c_o, c), (&d_o, d)] {
        env.deposit(o, p, DEPOSIT);
    }
    env.top_up_backing_bucket(PROFIT_SOURCE_DOMAIN, PNL, 100);
    let program = add_matcher(&mut env);
    let v_route = lp_route(&mut env, program, &v_o, v);
    let b_route = lp_route(&mut env, program, &b_o, b);
    let a_route = lp_route(&mut env, program, &a_o, a);
    let d_route = lp_route(&mut env, program, &d_o, d);

    trade(&mut env, &a_o, a, &v_o, v, v_route, PROFIT_ASSET, POS_SCALE as i128);
    trade(&mut env, &a_o, a, &b_o, b, b_route, LOSS_ASSET, POS_SCALE as i128);
    env.svm.warp_to_slot(2);
    env.push_auth_mark_for_asset_as_admin(PROFIT_ASSET, 2, PROFIT_PRICE);
    env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, 2, LOSS_PRICE);
    crank_at(&mut env, a, 2, &[PROFIT_ASSET, LOSS_ASSET]);
    crank_at(&mut env, v, 2, &[]);
    crank_at(&mut env, b, 2, &[]);
    trade(&mut env, &a_o, a, &v_o, v, v_route, PROFIT_ASSET, -(POS_SCALE as i128));
    trade(&mut env, &a_o, a, &b_o, b, b_route, LOSS_ASSET, -(POS_SCALE as i128));
    let b_initial_convert = try_convert(&mut env, &b_o, b, PNL);

    let mut d_convert = None;
    if b_initial_convert.is_err() {
        // boyle's continuation: a later pair on asset 0 creates fresh d0 backing that B's
        // old claim takes first.
        env.finalize_reset_side_with_cu(LOSS_ASSET, 0);
        env.finalize_reset_side_with_cu(LOSS_ASSET, 1);
        trade(&mut env, &c_o, c, &d_o, d, d_route, LOSS_ASSET, POS_SCALE as i128);
        env.svm.warp_to_slot(3);
        env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, 3, LATER_LOSS_PRICE);
        crank_at(&mut env, c, 3, &[LOSS_ASSET]);
        trade(&mut env, &b_o, b, &a_o, a, a_route, LOSS_ASSET, POS_SCALE as i128);
        trade(&mut env, &b_o, b, &a_o, a, a_route, LOSS_ASSET, -(POS_SCALE as i128));
        let _ = try_convert(&mut env, &b_o, b, PNL);
        crank_at(&mut env, d, 3, &[]);
        trade(&mut env, &c_o, c, &d_o, d, d_route, LOSS_ASSET, -(POS_SCALE as i128));
        d_convert = Some(try_convert(&mut env, &d_o, d, PNL));
    }
    // Every remaining claim must convert and the provider must withdraw its principal:
    // nothing is left ownerless.
    let a_pnl = env.portfolio_state(a).pnl;
    let a_convert = if a_pnl > 0 {
        // B's conversion moved the risk epoch; recertify A with fresh marks first.
        let slot = env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot + 1;
        env.svm.warp_to_slot(slot);
        let (_, group) = env.market_state();
        let (p1, p0) = (group.assets[1].effective_price, group.assets[0].effective_price);
        env.push_auth_mark_for_asset_as_admin(PROFIT_ASSET, slot, p1);
        env.push_auth_mark_for_asset_as_admin(LOSS_ASSET, slot, p0);
        crank_at(&mut env, a, slot, &[PROFIT_ASSET, LOSS_ASSET]);
        Some(try_convert(&mut env, &a_o, a, a_pnl as u128))
    } else {
        None
    };
    let provider = try_withdraw_backing(&mut env, PNL).map(|_| ());
    let bs = env.portfolio_state(b);
    let (_, group) = env.market_state();
    Rollover {
        b_initial_convert,
        b_capital: bs.capital,
        b_pnl: bs.pnl,
        d_convert,
        a_convert,
        provider,
        group_vault: group.vault,
        group_c_tot: group.c_tot,
        group_pnl_pos_tot: group.pnl_pos_tot,
    }
}

#[test]
fn boyle175_ok_rollover_old_claim_is_backed() {
    let r = rollover_world();
    assert!(
        r.b_initial_convert.is_ok(),
        "B's asset-0 claim must be backed by A's crystallized loss: {:?}",
        r.b_initial_convert
    );
    assert_eq!((r.b_capital, r.b_pnl), (DEPOSIT + PNL, 0));
    assert!(r.d_convert.is_none());
    assert!(
        matches!(r.a_convert, Some(Ok(_))),
        "A's asset-1 claim converts against the provider-backed domain: {:?}",
        r.a_convert
    );
    assert!(r.provider.is_ok(), "provider withdraws its principal: {:?}", r.provider);
    assert_eq!(r.group_pnl_pos_tot, 0);
    assert_eq!(r.group_vault, r.group_c_tot, "every atom is owned capital");
}
