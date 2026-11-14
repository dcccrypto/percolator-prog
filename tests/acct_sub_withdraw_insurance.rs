//! Account-substitution matrix for `WithdrawInsurance` (tag 41), job J-20261114-PROG-ACCTSUB2.
//!
//! Follow-up of the PROG-ACCTSUB matrix, which left this instruction out: `handle_withdraw_insurance`
//! reads `Clock::get()` and the native harness has no Clock sysvar. `set_syscall_stubs` is
//! process-global, so the stub lives in this separate test binary (same trick as
//! `v16_creator_fee_isolation.rs`) and cannot change any other test.
//!
//! Account list: [authority, market, dest_token, vault_token, vault_authority, token_program].
//!
//! NOTE the instruction is PERMISSIONLESS on purpose (W4-PAYOUT): once the market is Resolved and
//! empty, anyone may settle an authority's reserve, but only INTO that authority's own token account
//! and only the WHOLE reserve. So "signer missing" is not a reject cell here; the signer cells check
//! the two things that make the unsigned path safe (beneficiary binding, no partial chunks).
//!
//! Columns: A market not owned by this program, C signer missing, D market read-only,
//! F wrong authority, G1 uninitialised (fake) market, H wrong vault-authority PDA / wrong vault,
//! I duplicate accounts, T SPL token account read-only, P wrong token program.
#![cfg(not(kani))]

mod acct_sub_harness;

use acct_sub_harness::*;
use percolator_prog::{ix::Instruction, state};
use solana_program::{clock::Clock, program_pack::Pack, program_stubs, pubkey::Pubkey, sysvar::Sysvar};
use spl_token::state::Account as TokenAccount;

struct ClockStubs;

impl program_stubs::SyscallStubs for ClockStubs {
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        let clock = Clock {
            slot: 1,
            epoch_start_timestamp: 0,
            epoch: 0,
            leader_schedule_epoch: 0,
            unix_timestamp: 0,
        };
        unsafe {
            *(var_addr as *mut Clock) = clock;
        }
        solana_program::entrypoint::SUCCESS
    }
}

fn install_clock_stub() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        program_stubs::set_syscall_stubs(Box::new(ClockStubs));
    });
}

/// If the stub ever stops working every cell would "reject" with UnsupportedSysvar and pass for the
/// wrong reason. Pin it, and pin that the baseline really reaches the handler's success path.
#[test]
fn acct_sub_wi_clock_stub_is_installed() {
    install_clock_stub();
    assert_eq!(Clock::get().map(|c| c.slot), Ok(1));
}

const RESERVE: u128 = 100;

fn fx_wi(resolved: bool) -> SubFx {
    install_clock_stub();
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let mut source = user_token_account(admin.key, mint, RESERVE as u64);
    let mut vault = vault_token_account(&market, mint, 0);
    let mut tp = token_program_account();
    let epoch = state::read_asset_control_sequences(&market.data, 0).unwrap().authority_epoch;
    run_ix(
        Instruction::TopUpInsurance {
            market_id: 1,
            intent_id: next_intent_id(),
            amount: RESERVE,
            authority_epoch: epoch,
        },
        &mut [&mut admin, &mut market, &mut source, &mut vault, &mut tp],
    )
    .expect("fixture: top up insurance");
    if resolved {
        let frontier = state::read_asset_generation_frontier(&market.data).unwrap();
        run_ix(
            Instruction::ResolveMarket { asset_generation_frontier: frontier, authority_epoch: epoch },
            &mut [&mut admin, &mut market],
        )
        .expect("fixture: resolve");
    }
    let dest = user_token_account(admin.key, mint, 0);
    let vault = vault_token_account(&market, mint, RESERVE as u64);
    let va = vault_authority_account(&market);
    SubFx {
        accts: vec![admin, market, dest, vault, va, tp],
        ix: |_| Instruction::WithdrawInsurance { amount: RESERVE },
        market: 1,
        portfolio: None,
        signers: vec![0],
        tokens: vec![2, 3],
        vault: Some(3),
        vault_auth: Some(4),
        spare_portfolio: None,
    }
}
fn fx_resolved() -> SubFx {
    fx_wi(true)
}
fn fx_live() -> SubFx {
    fx_wi(false)
}

macro_rules! cell {
    ($name:ident, $build:ident, $mutate:expr) => {
        #[test]
        fn $name() {
            let mut fx = $build();
            ($mutate)(&mut fx);
            let before: Vec<Vec<u8>> = fx.accts.iter().map(|a| a.data.clone()).collect();
            let r = sub_run_raw(&mut fx);
            assert!(r.is_err(), "substituted account was ACCEPTED: {r:?}");
            // a rejected call must leave the market bytes alone
            assert_eq!(fx.accts[fx.market].data, before[fx.market], "market mutated by a rejected call");
        }
    };
}
/// Same as `cell!` but with the harness rollback (the runtime's behaviour for a failed
/// instruction). Used where the handler checks the token accounts / vault PDA only AFTER it has
/// debited the market (v16_program.rs `handle_withdraw_insurance`: debit L23665, vault PDA check
/// L23715, `verify_withdrawable_token_accounts` L23723). A failed instruction is reverted by the
/// runtime, so this is an ordering note and not a fund-loss bug.
macro_rules! cell_rb {
    ($name:ident, $build:ident, $mutate:expr) => {
        #[test]
        fn $name() {
            let mut fx = $build();
            ($mutate)(&mut fx);
            let r = sub_run(&mut fx);
            assert!(r.is_err(), "substituted account was ACCEPTED: {r:?}");
        }
    };
}
macro_rules! dup_cell {
    ($name:ident, [$(($i:expr, $j:expr)),+]) => {
        #[test]
        fn $name() {
            $(
                let mut fx = fx_resolved();
                let r = sub_run_dup(&mut fx, $i, $j);
                assert!(r.is_err(), "duplicate ({}, {}) was ACCEPTED: {r:?}", $i, $j);
            )+
        }
    };
}

// ---- baselines -------------------------------------------------------------------------------
#[test]
fn acct_sub_wi_baseline_signed_full_withdraw() {
    let mut fx = fx_resolved();
    sub_run(&mut fx).expect("unmutated fixture must succeed");
    let (_, group) = state::read_market(&fx.accts[1].data).unwrap();
    assert_eq!(group.insurance, 0, "the handler really ran to the payout");
}
#[test]
fn acct_sub_wi_baseline_live_market_is_the_only_difference() {
    // the live fixture is the same list; only the mode differs, and it must be refused
    let mut fx = fx_live();
    assert!(sub_run(&mut fx).is_err());
}

// ---- A / D / G1: the market account ----------------------------------------------------------
cell!(acct_sub_wi_a_market_wrong_program, fx_resolved, m_a);
cell!(acct_sub_wi_d_market_readonly, fx_resolved, m_d);
cell!(acct_sub_wi_g1_fake_market, fx_resolved, m_g1);
cell!(acct_sub_wi_x_market_not_resolved, fx_live, |_fx: &mut SubFx| {});

// ---- C: signer missing (permissionless by design, see header) --------------------------------
/// Unsigned + the authority's own dest + the whole reserve is the designed liveness path.
#[test]
fn acct_sub_wi_c1_unsigned_whole_reserve_is_allowed_and_pays_the_authority_only() {
    let mut fx = fx_resolved();
    m_c(&mut fx);
    sub_run(&mut fx).expect("unsigned whole-reserve settle is the designed permissionless path");
    let dest = TokenAccount::unpack(&fx.accts[2].data).unwrap();
    assert_eq!(dest.owner, fx.accts[0].key, "dest is the authority's own token account");
    assert_eq!(state::read_market(&fx.accts[1].data).unwrap().1.insurance, 0);
}
// Unsigned caller names a destination owned by someone else: refused (beneficiary binding).
cell_rb!(acct_sub_wi_c2_unsigned_dest_owned_by_attacker, fx_resolved, |fx: &mut SubFx| {
    m_c(fx);
    let t = TokenAccount::unpack(&fx.accts[2].data).unwrap();
    fx.accts[2].data = make_token_data(t.mint, Pubkey::new_unique(), t.amount);
});
// Unsigned caller asks for a chunk (cooldown lever, AUD-S1-11): refused.
cell!(acct_sub_wi_c3_unsigned_partial_amount, fx_resolved, |fx: &mut SubFx| {
    m_c(fx);
    fx.ix = |_| Instruction::WithdrawInsurance { amount: RESERVE / 2 };
});

// ---- F: wrong authority ----------------------------------------------------------------------
// Attacker signs and names their own dest: the bound insurance_authority is someone else, capacity 0.
cell!(acct_sub_wi_f1_wrong_authority_own_dest, fx_resolved, |fx: &mut SubFx| {
    let attacker = signer();
    let t = TokenAccount::unpack(&fx.accts[2].data).unwrap();
    fx.accts[2].data = make_token_data(t.mint, attacker.key, t.amount);
    fx.accts[0] = attacker;
});
// Attacker signs but the dest is still the real authority's: dest owner != authority key.
cell!(acct_sub_wi_f2_wrong_authority_victim_dest, fx_resolved, |fx: &mut SubFx| {
    fx.accts[0] = signer();
});
// Same, unsigned: anyone-can-crank must not turn a stranger key into a beneficiary.
cell!(acct_sub_wi_f3_stranger_authority_unsigned, fx_resolved, |fx: &mut SubFx| {
    let mut stranger = signer();
    stranger.is_signer = false;
    let t = TokenAccount::unpack(&fx.accts[2].data).unwrap();
    fx.accts[2].data = make_token_data(t.mint, stranger.key, t.amount);
    fx.accts[0] = stranger;
});

// ---- H: vault authority PDA / vault ----------------------------------------------------------
cell_rb!(acct_sub_wi_h1_wrong_vault_authority_pda, fx_resolved, m_h);
cell_rb!(acct_sub_wi_h2_vault_owned_by_someone_else, fx_resolved, |fx: &mut SubFx| {
    fx.accts[4].key = vault_authority(&fx.accts[1]); // keep the PDA right...
    let t = TokenAccount::unpack(&fx.accts[3].data).unwrap();
    // ...but the vault token account is controlled by an attacker key
    fx.accts[3].data = make_token_data(t.mint, Pubkey::new_unique(), t.amount);
});
cell_rb!(acct_sub_wi_h3_vault_is_the_dest_account, fx_resolved, |fx: &mut SubFx| {
    // attacker passes the (admin-owned) dest token account as the vault too
    fx.accts[3] = fx.accts[2].clone();
});

// ---- T / P: token accounts and program -------------------------------------------------------
cell!(acct_sub_wi_t1_dest_token_readonly, fx_resolved, |fx: &mut SubFx| fx.accts[2].is_writable = false);
cell!(acct_sub_wi_t2_vault_token_readonly, fx_resolved, |fx: &mut SubFx| fx.accts[3].is_writable = false);
cell!(acct_sub_wi_p_wrong_token_program, fx_resolved, |fx: &mut SubFx| fx.accts[5].key = Pubkey::new_unique());

// ---- I: duplicate accounts -------------------------------------------------------------------
dup_cell!(acct_sub_wi_i1_dest_is_vault, [(2, 3)]);
dup_cell!(acct_sub_wi_i2_market_is_dest_or_vault, [(1, 2), (1, 3)]);
dup_cell!(acct_sub_wi_i3_authority_is_market_dest_or_vault, [(0, 1), (0, 2), (0, 3)]);
dup_cell!(acct_sub_wi_i4_vault_authority_is_vault_or_dest, [(3, 4), (2, 4)]);
dup_cell!(acct_sub_wi_i5_token_program_is_vault_authority, [(4, 5)]);
