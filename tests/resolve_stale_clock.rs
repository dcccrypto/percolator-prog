//! BPF/LiteSVM pins for `handle_resolve_stale_permissionless` (tag 39, src/v16_program.rs).
//!
//! The handler takes no signer and resolves with `authenticated_slot_or_fallback(now_slot)`: the
//! Clock slot wins, the wire `now_slot` is only a fallback if the Clock sysvar is unavailable (it
//! always is available under LiteSVM, so the wire value must never change the result). Maturity is
//! `oracle_v16::permissionless_stale_matured`: `stale_slots != 0 && clock.saturating_sub(last_good)
//! >= stale_slots`. Guards before it: mode != Live (21 EngineLockActive), clock < header.current_slot
//! (19 EngineStale).
//!
//! Needs the SBF at target/deploy/percolator_prog.so (or INDEP_WRAPPER_SO).
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator::MarketModeV16;
use percolator_prog::{error::PercolatorError, ix::Instruction as ProgInstruction};
use solana_sdk::instruction::AccountMeta;

const L: u64 = 1_000; // last_good_oracle_slot
const S: u64 = 28; // stale_slots (boundary pair 27 / 28)

fn setup(stale_slots: u64, last_good: u64, current_slot: u64) -> V16CuEnv {
    let mut env = V16CuEnv::new();
    if stale_slots != 0 {
        env.configure_permissionless_resolve_with_cu(stale_slots, 5);
    }
    env.mutate_market(|cfg, group| {
        cfg.permissionless_resolve_stale_slots = stale_slots;
        cfg.last_good_oracle_slot = last_good;
        group.header.current_slot = percolator::V16PodU64::new(current_slot);
    });
    env
}

fn resolve(env: &mut V16CuEnv, clock: u64, wire: u64) -> Result<u64, String> {
    env.svm.warp_to_slot(clock);
    env.svm.expire_blockhash();
    let market = env.market;
    env.send(
        ProgInstruction::ResolveStalePermissionless { now_slot: wire },
        vec![AccountMeta::new(market, false)],
        &[],
    )
}

fn code(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
}

fn expect_err(r: Result<u64, String>, e: PercolatorError, what: &str) {
    let msg = r.expect_err(&format!("{what}: must be refused"));
    assert!(msg.contains(&code(e)), "{what}: expected {e:?} ({}), got {msg}", code(e));
}

fn mode(env: &V16CuEnv) -> MarketModeV16 {
    env.market_state().1.mode
}

const WIRES: [u64; 4] = [0, 1, L + S - 1, u64::MAX];

#[test]
fn wire_slot_never_matures_a_fresh_market() {
    for wire in WIRES {
        let mut env = setup(S, L, 0);
        expect_err(resolve(&mut env, L + S - 1, wire), PercolatorError::OracleStale, &format!("wire {wire}"));
        assert_eq!(mode(&env), MarketModeV16::Live);
    }
}

#[test]
fn wire_slot_zero_past_or_far_future_never_blocks_a_matured_market() {
    for wire in WIRES {
        let mut env = setup(S, L, 0);
        resolve(&mut env, L + S, wire).unwrap_or_else(|e| panic!("wire {wire}: {e}"));
        assert_eq!(mode(&env), MarketModeV16::Resolved, "wire {wire}");
        // The resolved slot is the Clock slot, not the wire value.
        assert_eq!(env.market_state().1.header.resolved_slot.get(), L + S, "wire {wire}");
    }
}

#[test]
fn boundary_minus_one_refused_then_exact_boundary_resolves() {
    let mut env = setup(S, L, 0);
    expect_err(resolve(&mut env, L + S - 1, 0), PercolatorError::OracleStale, "L+S-1");
    assert_eq!(mode(&env), MarketModeV16::Live);
    resolve(&mut env, L + S, 0).expect("L+S resolves");
    assert_eq!(mode(&env), MarketModeV16::Resolved);
}

#[test]
fn stale_slots_zero_never_resolves() {
    for clock in [L, L + 1, L + S, L + 1_000_000, u64::MAX / 2] {
        let mut env = setup(0, L, 0);
        expect_err(resolve(&mut env, clock, u64::MAX), PercolatorError::OracleStale, &format!("clock {clock}"));
        assert_eq!(mode(&env), MarketModeV16::Live);
    }
}

#[test]
fn last_good_ahead_of_clock_saturates_without_underflow() {
    // last_good 100_000 > clock 50: saturating_sub gives 0, so not matured (no panic, no wrap).
    for wire in [0, 50, u64::MAX] {
        let mut env = setup(S, 100_000, 0);
        expect_err(resolve(&mut env, 50, wire), PercolatorError::OracleStale, &format!("wire {wire}"));
        assert_eq!(mode(&env), MarketModeV16::Live);
    }
    // Even a last_good of u64::MAX cannot wrap into "matured".
    let mut env = setup(S, u64::MAX, 0);
    expect_err(resolve(&mut env, 50, u64::MAX), PercolatorError::OracleStale, "last_good u64::MAX");
}

#[test]
fn clock_below_current_slot_is_engine_stale_even_if_matured() {
    // Matured by clock (clock - L >= S) but header.current_slot is ahead of the clock.
    for wire in [0, u64::MAX] {
        let mut env = setup(S, L, L + S + 100);
        expect_err(resolve(&mut env, L + S, wire), PercolatorError::EngineStale, &format!("wire {wire}"));
        assert_eq!(mode(&env), MarketModeV16::Live);
    }
    // Control: clock == current_slot passes the guard and resolves.
    let mut env = setup(S, L, L + S);
    resolve(&mut env, L + S, 0).expect("clock == current_slot resolves");
}

#[test]
fn already_resolved_is_engine_lock_active_and_state_unchanged() {
    let mut env = setup(S, L, 0);
    resolve(&mut env, L + S, 0).expect("first resolve");
    let before = env.svm.get_account(&env.market).unwrap();
    for (clock, wire) in [(L + S + 5, 0), (L + S + 5, u64::MAX)] {
        expect_err(resolve(&mut env, clock, wire), PercolatorError::EngineLockActive, "second resolve");
    }
    assert_eq!(env.svm.get_account(&env.market).unwrap().data, before.data);
}

#[test]
fn resolve_emits_market_resolved_move_event_once() {
    // Decode every `Program data:` log and count MOVE lines for tag 39 with sub MOVE_MARKET_RESOLVED.
    fn count(logs: &[String], market: &[u8; 32], resolved_slot: u64) -> usize {
        use percolator_prog::fill_events_v22 as ev;
        logs.iter()
            .filter_map(|l| l.strip_prefix("Program data: "))
            .filter(|b64| {
                let mut buf = [0u8; ev::MOVE_LEN];
                let n = ev::encode_move(
                    &mut buf,
                    ev::TAG_RESOLVE_STALE_PERMISSIONLESS,
                    market,
                    ev::MOVE_MARKET_RESOLVED,
                    ev::NO_ASSET,
                    resolved_slot,
                    0,
                    0,
                );
                b64_decode(b64.trim()).as_deref() == Some(&buf[..n])
            })
            .count()
    }

    let mut env = setup(S, L, 0);
    // A refused attempt emits nothing.
    let market = env.market.to_bytes();
    let _ = resolve(&mut env, L + S - 1, 0);
    assert_eq!(count(&last_logs(), &market, L + S - 1), 0);
    resolve(&mut env, L + S, 0).expect("resolve");
    let logs = last_logs();
    assert_eq!(count(&logs, &market, L + S), 1, "exactly one market-resolved MOVE: {logs:#?}");
    // A repeat is refused and emits no second event.
    let _ = resolve(&mut env, L + S + 1, 0);
    assert_eq!(count(&last_logs(), &market, L + S), 0);
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().take_while(|&c| c != b'=') {
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}
