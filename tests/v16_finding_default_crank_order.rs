//! Findings 1 and 2 (engine #172 / #212): a default's shortfall is charged twice when
//! the winner settles after the loser's liquidation.
//!
//! Reproduced through the production SBF wrapper in LiteSVM with public instructions only:
//! InitMarket, InitPortfolio, Deposit, ConfigureAuthMark, PushAuthMark, TopUpBackingBucket,
//! TradeNoCpi, PermissionlessCrank, ResolveMarket, CloseResolved, ClaimResolvedPayoutTopup,
//! WithdrawBackingBucket. Fees and funding are zero, so every payout has an exact fair value:
//!
//! ```text
//! winner fair payout = winner deposit + loser deposit   (the loser's equity is negative)
//! provider fair recovery = provider principal           (no fees, nothing owed to it)
//! ```
//!
//! Exception: with a 1-atom provider, the winner-first order (on `b22bef7d` too) spends that
//! atom backing the winner, so that case checks conservation and order independence only.
//!
//! Each case runs twice from the same state. The only difference is who the keeper cranks
//! first after the price move: the loser (attack: what an auto-crank does) or the winner
//! (control). Residual attribution must not depend on caller order, so both runs must pay the
//! same fair amounts. The test asserts that and fails while the bug is present.
//!
//! Original test by Augustas11 (comment on engine PR #212). Added here: the small-default and
//! 1-atom-provider cases, and assertions on conservation and on attack == control.
//!
//! The engine is selected by the `percolator` dependency in Cargo.toml. Point it at engine
//! `b22bef7d` (3 of 4 fail) or at dcccrypto/percolator `exp/172-settleb-after-kf` (4 pass).
//!
//! Drop into percolator-prog `tests/` and run against the built artifact:
//!
//! ```text
//! cargo build-sbf --tools-version v1.52
//! (cd tests/fixtures/auth_matcher && cargo build-sbf --tools-version v1.52)
//! cargo test --test v16_finding_default_crank_order -- --nocapture --test-threads=1
//! ```

use percolator::POS_SCALE;
use percolator_prog::ix::CrankObservationHint;

#[allow(dead_code)]
mod support;

use support::v16_svm::{MarketConfig, V16Svm, PRIMARY_ACTOR_COUNT};

const LOSER: usize = 0;
const WINNER: usize = 1;
const BYSTANDER: usize = 2;
const ASSET: u16 = 0;
const START_PRICE: u64 = 10_000;
const BACKING_EXPIRY: u64 = 1_000_000;

#[derive(Clone, Copy, Debug)]
struct Case {
    name: &'static str,
    initial_margin_bps: u64,
    maintenance_margin_bps: u64,
    price_cap_bps: u64,
    loser_deposit: u128,
    winner_deposit: u128,
    /// Whole units the winner holds against the loser.
    units: i128,
    /// True when the winner is long (price goes up), false when the winner is short.
    winner_long: bool,
    /// Consecutive full-cap moves against the loser, one per slot, no crank on either party.
    slots: u64,
    /// Assert the exact (winner, provider) split, not only conservation and order independence.
    /// False only for the 1-atom provider: there the clean order (master included) spends the
    /// provider's atom backing the winner's claim, so the split differs from deposits by 1.
    exact_split: bool,
    /// Fresh counterparty backing: (domain, amount). Domain 0 = asset-0 long side
    /// (long losers pay in, backs short gains); domain 1 = asset-0 short side.
    provider: Option<(u16, u128)>,
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    loser_payout: u64,
    winner_payout: u64,
    provider_recovered: u64,
    vault_left: u64,
    final_price: u64,
}

fn observations() -> Vec<CrankObservationHint> {
    vec![CrankObservationHint {
        asset_index: ASSET,
        oracle_accounts: 0,
    }]
}

fn config(case: &Case) -> MarketConfig {
    let mut deposits = [0u128; PRIMARY_ACTOR_COUNT];
    deposits[LOSER] = case.loser_deposit;
    deposits[WINNER] = case.winner_deposit;
    let mut balances = [0u64; PRIMARY_ACTOR_COUNT];
    balances[LOSER] = case.loser_deposit as u64;
    balances[WINNER] = case.winner_deposit as u64;
    MarketConfig {
        initial_price: START_PRICE,
        h_max: 10,
        min_nonzero_mm_req: 1,
        min_nonzero_im_req: 2,
        maintenance_margin_bps: case.maintenance_margin_bps,
        initial_margin_bps: case.initial_margin_bps,
        max_trading_fee_bps: 0,
        liquidation_fee_bps: 0,
        liquidation_fee_cap: 0,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: case.price_cap_bps,
        // One slot per accrual, as the engine-level repro: every crank advances one capped step.
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 0,
        min_funding_lifetime_slots: 4,
        max_bankrupt_close_lifetime_slots: 100,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
        actor_deposits: deposits,
        actor_token_balances: balances,
    }
}

/// Crank one portfolio until the engine reports no further progress.
fn crank_to_fixpoint(env: &mut V16Svm, actor: usize, slot: u64, label: &str) -> Vec<String> {
    let mut log = Vec::new();
    for _ in 0..16 {
        match env.crank_if_actionable(actor, slot, observations()) {
            Ok(Some(_)) => log.push(format!("{label}: crank actor {actor} progressed")),
            Ok(None) => return log,
            Err(e) => panic!("{label}: crank actor {actor} failed: {e}"),
        }
    }
    panic!("{label}: crank actor {actor} did not reach a fixpoint");
}

/// Everything the provider can take back from `domain` through the public
/// WithdrawBackingBucket instruction. Greedy power-of-two withdrawals: a withdrawal of `x`
/// succeeds iff `x` is at most what is still withdrawable, and a rejected one leaves no
/// state behind, so the sum is exactly the withdrawable total.
fn withdraw_all_backing(env: &mut V16Svm, domain: u16) -> u64 {
    let before = env.token_amount(env.provider_destination_token);
    for bit in (0..40).rev() {
        let _ = env.withdraw_backing_bucket(domain, 1u128 << bit);
    }
    env.token_amount(env.provider_destination_token) - before
}

fn portfolio_open(env: &V16Svm, actor: usize) -> bool {
    env.svm
        .get_account(&env.actors[actor].portfolio)
        .is_some_and(|a| percolator_prog::state::read_portfolio(&a.data).is_ok())
}

/// ClosePortfolio for every portfolio that still exists (an open receipt blocks it).
fn close_portfolios(env: &mut V16Svm) {
    for actor in 0..PRIMARY_ACTOR_COUNT {
        if portfolio_open(env, actor) {
            let _ = env.close_primary_portfolio(actor);
        }
    }
}

fn run(case: &Case, winner_first: bool) -> Outcome {
    let mut env = V16Svm::new_with_asset_count([0x5a; 32], config(case), 1);
    if let Some((domain, amount)) = case.provider {
        env.top_up_backing_bucket(domain, amount, BACKING_EXPIRY)
            .expect("provider TopUpBackingBucket");
    }
    let size_q = case.units * POS_SCALE as i128;
    let signed = if case.winner_long { size_q } else { -size_q };
    // Account a (taker) is the winner: positive size_q = taker buys.
    env.trade_no_cpi(WINNER, LOSER, ASSET, signed, START_PRICE, 0)
        .expect("TradeNoCpi winner vs loser");

    let mut slot = env.current_slot();
    let mut price = START_PRICE;
    for _ in 0..case.slots {
        let step = price * case.price_cap_bps / 10_000;
        price = if case.winner_long {
            price + step
        } else {
            price - step
        };
        slot += 1;
        env.warp_to_slot(slot);
        env.push_auth_mark(ASSET, slot, price)
            .expect("authority PushAuthMark");
        // A flat bystander portfolio carries the accrual; neither party is touched.
        env.crank(BYSTANDER, slot, observations())
            .expect("accrual crank on bystander");
    }
    let effective = env.primary_market_state().1.assets[ASSET as usize].effective_price;

    let label = if winner_first { "control" } else { "attack" };
    let order: &[usize] = if winner_first {
        &[WINNER, LOSER, WINNER]
    } else {
        &[LOSER, WINNER]
    };
    for &actor in order {
        crank_to_fixpoint(&mut env, actor, slot, label);
    }
    for actor in [LOSER, WINNER] {
        crank_to_fixpoint(&mut env, actor, slot, label);
    }

    slot += 1;
    env.warp_to_slot(slot);
    env.resolve_market().expect("ResolveMarket");
    for actor in 0..PRIMARY_ACTOR_COUNT {
        env.close_resolved_primary(actor)
            .unwrap_or_else(|e| panic!("CloseResolved actor {actor}: {e}"));
    }
    for actor in [LOSER, WINNER] {
        let _ = env.claim_resolved_payout_topup_primary(actor);
    }
    // The provider takes back its backing once every portfolio is gone (WithdrawBackingBucket
    // requires that in Resolved mode).
    close_portfolios(&mut env);
    let provider_recovered = match case.provider {
        Some((domain, _)) => withdraw_all_backing(&mut env, domain),
        None => 0,
    };
    // Rounding dust can leave a receipt top-up waiting on backing expiry. Let the clock pass
    // expiry, expire the buckets through the resolved crank, claim, and close the rest.
    {
        let expiry_slot = BACKING_EXPIRY + 1;
        env.warp_to_slot(expiry_slot);
        for _ in 0..2 {
            for actor in [LOSER, WINNER] {
                let _ = env.crank(actor, expiry_slot, observations());
            }
        }
        for actor in [LOSER, WINNER] {
            let _ = env.claim_resolved_payout_topup_primary(actor);
        }
        close_portfolios(&mut env);
    }
    Outcome {
        loser_payout: env.token_amount(env.actors[LOSER].destination_token),
        winner_payout: env.token_amount(env.actors[WINNER].destination_token),
        provider_recovered,
        vault_left: env.token_amount(env.vault),
        final_price: effective,
    }
}

fn check(case: &Case) {
    let attack = run(case, false);
    let control = run(case, true);
    let fair_winner = (case.winner_deposit + case.loser_deposit) as u64;
    let fair_provider = case.provider.map_or(0, |(_, a)| a as u64);
    println!(
        "{}: fair winner {fair_winner}, fair provider {fair_provider}",
        case.name
    );
    println!("{}: attack  (loser cranked first)  {attack:?}", case.name);
    println!("{}: control (winner cranked first) {control:?}", case.name);
    assert_eq!(attack.final_price, control.final_price);
    for (label, o) in [("control", &control), ("attack", &attack)] {
        assert_eq!(
            (o.winner_payout + o.provider_recovered, o.vault_left),
            (fair_winner + fair_provider, 0),
            "{}: {label} must pay out every deposited atom",
            case.name
        );
    }
    assert_eq!(
        (attack.winner_payout, attack.provider_recovered),
        (control.winner_payout, control.provider_recovered),
        "{}: loser-first crank order changes who pays the default",
        case.name
    );
    if case.exact_split {
        assert_eq!(
            (control.winner_payout, control.provider_recovered),
            (fair_winner, fair_provider),
            "{}: control must be exact",
            case.name
        );
    }
}

/// Finding 1 (a): the winner pays the shortfall a second time.
#[test]
fn v16_finding_winner_pays_default_twice_when_loser_cranked_first() {
    check(&Case {
        name: "winner-pays-twice",
        initial_margin_bps: 5_000,
        maintenance_margin_bps: 2_500,
        price_cap_bps: 2_000,
        loser_deposit: 692_730,
        winner_deposit: 904_405,
        units: 85,
        winner_long: true,
        slots: 6,
        exact_split: true,
        provider: None,
    });
}

/// Finding 2 (b): the backing provider pays the shortfall instead.
#[test]
fn v16_finding_provider_pays_default_when_loser_cranked_first() {
    check(&Case {
        name: "provider-pays",
        initial_margin_bps: 2_000,
        maintenance_margin_bps: 1_000,
        price_cap_bps: 500,
        loser_deposit: 200_000,
        winner_deposit: 1_000_000,
        units: 100,
        winner_long: false,
        slots: 6,
        exact_split: true,
        provider: Some((0, 78_464)),
    });
}

/// The small solvent-winner case from the #172 comment of 2026-11-05 (reported fixed by #212).
#[test]
fn v16_finding_small_default_payout_when_loser_cranked_first() {
    check(&Case {
        name: "small-default",
        initial_margin_bps: 1_000,
        maintenance_margin_bps: 500,
        price_cap_bps: 400,
        loser_deposit: 10_000,
        winner_deposit: 100_000,
        units: 9,
        winner_long: true,
        slots: 4,
        exact_split: true,
        provider: None,
    });
}

/// Case (a) with a 1-atom provider on the loser's domain (domain 1 = short side, which backs the
/// long winner's gain). Fair recovery is 1: anything more means the phantom receivable booked by
/// the cure lets the bucket authority withdraw loser-paid value.
#[test]
fn v16_finding_bucket_authority_recovery_after_double_charge() {
    check(&Case {
        name: "authority-recovery",
        initial_margin_bps: 5_000,
        maintenance_margin_bps: 2_500,
        price_cap_bps: 2_000,
        loser_deposit: 692_730,
        winner_deposit: 904_405,
        units: 85,
        winner_long: true,
        slots: 6,
        exact_split: false,
        provider: Some((1, 1)),
    });
}
