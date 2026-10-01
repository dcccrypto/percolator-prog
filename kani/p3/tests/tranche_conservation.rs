//! Tranche-accounting conservation over random flow sequences, driven ONLY through the
//! production `vault_lp_v18` functions (or the mutant copy under `--cfg p3_mutant`).
//!
//! Physical model (mirrors the processor): V = B (backing pots, where Earn deposits, fee
//! cranks and recalls land and Earn redemptions are paid from) + L (vault LP capital, where the
//! junior deposits/withdraws and trading PnL lands). Losses may hit L or B (a trader's gain
//! realised against backing).

use p3_vault_lp_proofs::vault_lp_v18::*;
use proptest::prelude::*;

const FLOOR_BPS: u16 = 1_000;

#[derive(Clone, Debug)]
enum Op {
    SeniorDeposit(u64),
    SeniorRedeem(u16), // bps of outstanding shares
    FeeCrank(u64),
    PnlGain(u64),
    PnlLoss(u64, bool), // amount, from backing (true) or LP (false)
    JuniorDeposit(u64),
    JuniorWithdraw(u64),
    Recall(u64),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1u64..5_000_000).prop_map(Op::SeniorDeposit),
        (1u16..=10_000).prop_map(Op::SeniorRedeem),
        (0u64..200_000).prop_map(Op::FeeCrank),
        (0u64..3_000_000).prop_map(Op::PnlGain),
        ((0u64..3_000_000), any::<bool>()).prop_map(|(a, b)| Op::PnlLoss(a, b)),
        (1u64..3_000_000).prop_map(Op::JuniorDeposit),
        (1u64..3_000_000).prop_map(Op::JuniorWithdraw),
        (1u64..3_000_000).prop_map(Op::Recall),
    ]
}

#[derive(Default, Debug)]
struct M {
    b: u128,
    l: u128,
    c: u128,
    s: u128,
    senior_in: u128,
    senior_out: u128,
    junior_in: u128,
    junior_out: u128,
    fees_in: u128,
    gains: u128,
    losses: u128,
}

impl M {
    fn v(&self) -> u128 {
        self.b + self.l
    }
}

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
static IMPAIRED_STEPS: AtomicU64 = AtomicU64::new(0);
static JUNIOR_EXITS: AtomicU64 = AtomicU64::new(0);
static RECALLS: AtomicU64 = AtomicU64::new(0);
static REDEEMS: AtomicU64 = AtomicU64::new(0);
static JUNIOR_POSITIVE_LOSSES: AtomicU64 = AtomicU64::new(0);

fn run(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let mut m = M::default();
    let mut exercised_impaired = false;
    for o in ops {
        let v0 = m.v();
        let split0 = tranche_split(v0, m.c);
        let s0 = m.s;
        let c0 = m.c;
        match o {
            Op::SeniorDeposit(a) => {
                let a = a as u128;
                if !senior_impaired(v0, m.c) {
                    if let Some(minted) = senior_shares_for_deposit(a, m.s, m.c) {
                        if minted > 0 {
                            m.b += a;
                            m.c += a;
                            m.s += minted;
                            m.senior_in += a;
                        }
                    }
                }
            }
            Op::SeniorRedeem(bps) => {
                if m.s > 0 {
                    let k = core::cmp::max(1, m.s * bps as u128 / 10_000);
                    let payout = senior_atoms_for_redemption(k, m.s, split0.senior).unwrap();
                    let c_after = senior_claim_after_redemption(m.c, k, m.s).unwrap();
                    prop_assert!(payout <= split0.senior);
                    if payout <= m.b {
                        // physical liquidity from backing only; otherwise fail closed (skip)
                        m.b -= payout;
                        m.c = c_after;
                        m.s -= k;
                        m.senior_out += payout;
                        REDEEMS.fetch_add(1, Relaxed);
                    }
                }
            }
            Op::FeeCrank(f) => {
                if m.s > 0 {
                    let f = f as u128;
                    let (sen, jun) = split_fee(f, 10_000).unwrap();
                    prop_assert_eq!(sen + jun, f);
                    m.b += f;
                    m.c += sen;
                    m.fees_in += f;
                }
            }
            Op::PnlGain(g) => {
                m.l += g as u128;
                m.gains += g as u128;
            }
            Op::PnlLoss(x, from_backing) => {
                let x = x as u128;
                let x = if from_backing { x.min(m.b) } else { x.min(m.l) };
                if from_backing {
                    m.b -= x;
                } else {
                    m.l -= x;
                }
                m.losses += x;
                if x > 0 && tranche_split(m.v(), m.c).junior > 0 && m.s > 0 {
                    JUNIOR_POSITIVE_LOSSES.fetch_add(1, Relaxed);
                }
            }
            Op::JuniorDeposit(a) => {
                m.l += a as u128;
                m.junior_in += a as u128;
            }
            Op::JuniorWithdraw(a) => {
                let a = a as u128;
                if a <= m.l && junior_withdraw_allowed(v0, m.c, m.b, a, FLOOR_BPS) {
                    m.l -= a;
                    m.junior_out += a;
                    JUNIOR_EXITS.fetch_add(1, Relaxed);
                    let post = tranche_split(m.v(), m.c);
                    prop_assert!(post.senior == m.c, "senior impaired by junior exit");
                    prop_assert!(post.junior >= junior_floor_atoms(m.c, FLOOR_BPS).unwrap());
                    prop_assert!(m.b >= m.c, "senior lost backing cover");
                }
            }
            Op::Recall(a) => {
                let a = (a as u128).min(recall_limit(m.c, m.b)).min(m.l);
                if a > 0 {
                    m.l -= a;
                    m.b += a;
                    RECALLS.fetch_add(1, Relaxed);
                    prop_assert!(m.b <= m.c, "recall overshot the senior shortfall");
                }
            }
        }
        // ── invariants after every step ──
        let v = m.v();
        let sp = tranche_split(v, m.c);
        prop_assert_eq!(sp.senior + sp.junior, v);
        prop_assert_eq!(
            m.senior_in + m.junior_in + m.fees_in + m.gains,
            m.senior_out + m.junior_out + m.losses + v,
            "cash identity broken"
        );
        if sp.senior < m.c {
            exercised_impaired = true;
            IMPAIRED_STEPS.fetch_add(1, Relaxed);
            prop_assert_eq!(sp.junior, 0, "senior impaired while junior still holds value");
        }
        // Senior per-share value never falls while the junior still holds value.
        if sp.junior > 0 && s0 > 0 && m.s > 0 && split0.senior == c0 {
            prop_assert!(
                sp.senior * s0 >= split0.senior * m.s,
                "senior per-share value fell while junior > 0: before {}/{} after {}/{}",
                split0.senior,
                s0,
                sp.senior,
                m.s
            );
        }
        // Seniors lose (per share) only once the junior is exhausted.
        if s0 > 0 && m.s > 0 && sp.senior * s0 < split0.senior * m.s {
            prop_assert_eq!(sp.junior, 0, "seniors lost before junior hit zero");
        }
    }
    let _ = exercised_impaired;
    Ok(())
}

#[test]
fn tranche_conservation() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 10_000,
        ..ProptestConfig::default()
    });
    runner
        .run(&proptest::collection::vec(op(), 1..60), run)
        .expect("tranche conservation property failed");
    let (i, j, r, d, l) = (
        IMPAIRED_STEPS.load(Relaxed),
        JUNIOR_EXITS.load(Relaxed),
        RECALLS.load(Relaxed),
        REDEEMS.load(Relaxed),
        JUNIOR_POSITIVE_LOSSES.load(Relaxed),
    );
    println!("P3 COVERAGE cases=10000 impaired_steps={i} junior_exits={j} recalls={r} redemptions={d} losses_absorbed_by_junior={l}");
    assert!(i > 0 && j > 0 && r > 0 && d > 0 && l > 0, "a branch was never exercised");
}

/// Proof of life: a fixed sequence that MUST reach the impaired region and a junior exit, so
/// the property above is known to traverse both branches.
#[test]
fn proof_of_life_reaches_impairment_and_junior_exit() {
    let ops = vec![
        Op::SeniorDeposit(1_000_000),
        Op::JuniorDeposit(200_000),
        Op::FeeCrank(10_000),
        Op::PnlGain(50_000),
        Op::JuniorWithdraw(100_000),
        Op::PnlLoss(150_000, false),
        Op::PnlLoss(300_000, true),
        Op::SeniorRedeem(5_000),
        Op::Recall(10),
    ];
    run(ops.clone()).unwrap();
    // replay by hand to check the regions were actually visited
    let c = 1_000_000u128 + 10_000;
    let v_after_losses = 1_000_000 + 200_000 + 10_000 + 50_000 - 100_000 - 150_000 - 300_000;
    assert!(tranche_split(v_after_losses, c).senior < c, "fixture did not impair the senior");
    assert!(junior_withdraw_allowed(1_260_000, c, 1_010_000, 100_000, FLOOR_BPS));
}
