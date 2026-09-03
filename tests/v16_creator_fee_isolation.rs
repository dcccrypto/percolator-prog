//! Creator-fee-claim ISOLATION, direction B (2026-07-23 design, testing item 6):
//! `WithdrawInsuranceAsset` (tag 57) must NOT be able to reduce
//! `creator_fee_claimable_atoms`.
//!
//! # Why this is its own test binary
//!
//! `tests/v16_wrapper.rs`'s native in-process harness has no sysvar support, so
//! `Clock::get()` returns `UnsupportedSysvar` — which is exactly why every
//! existing tag-57 test in that file is in its baseline-failing set
//! (`handle_withdraw_insurance_asset` reads `Clock::get()?` up front for the
//! #396 cooldown, before anything else). Direction B therefore cannot be
//! written there at all.
//!
//! `solana_program::program_stubs::set_syscall_stubs` is PROCESS-GLOBAL, so
//! installing a Clock stub inside `v16_wrapper.rs` would silently change the
//! environment of its other ~220 tests (and race with them across the test
//! harness's threads). A separate binary gets its own process, so the stub is
//! contained. The stub supplies the Clock sysvar ONLY; `sol_invoke_signed`
//! keeps the default stub behaviour (logs, returns Ok), identical to
//! `v16_wrapper.rs`, so SPL balances do not move here either and every
//! assertion below is on wrapper/engine state.
//!
//! The harness below is a deliberately minimal copy of `v16_wrapper.rs`'s (no
//! portfolios, no trades) — `tests/common/mod.rs` is the LiteSVM cross-program
//! harness and loads a PREBUILT `target/deploy/percolator_prog.so`, which would
//! test yesterday's bytecode rather than this source tree.

#![cfg(not(kani))]

use percolator_prog::{ix::Instruction, processor, state};
use solana_program::{
    account_info::AccountInfo, clock::Clock, program_error::ProgramError, program_option::COption,
    program_pack::Pack, program_stubs, pubkey::Pubkey, sysvar::Sysvar,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

// ── Syscall stubs: supply Clock, leave everything else at the default ───────

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

/// Guards the guard: if `Clock::get()` ever stops working here, every test in
/// this file would fail for an environmental reason rather than a behavioural
/// one — and, worse, a future refactor could leave them passing vacuously by
/// short-circuiting before the sysvar read. Pin it explicitly.
#[test]
fn clock_sysvar_stub_is_actually_installed() {
    install_clock_stub();
    assert_eq!(
        Clock::get().map(|c| c.slot),
        Ok(1),
        "the tag-57 path needs a working Clock sysvar; without it these tests \
         would fail with UnsupportedSysvar instead of exercising the handler"
    );
}

// ── Minimal harness (mirrors tests/v16_wrapper.rs) ──────────────────────────

struct TestAccount {
    key: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data: Vec<u8>,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
}

impl TestAccount {
    fn new(key: Pubkey, owner: Pubkey, data_len: usize) -> Self {
        Self {
            key,
            owner,
            lamports: 1_000_000,
            data: vec![0u8; data_len],
            is_signer: false,
            is_writable: false,
            executable: false,
        }
    }

    fn new_with_data(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> Self {
        Self {
            key,
            owner,
            lamports: 1_000_000,
            data,
            is_signer: false,
            is_writable: false,
            executable: false,
        }
    }

    fn signer(mut self) -> Self {
        self.is_signer = true;
        self
    }

    fn writable(mut self) -> Self {
        self.is_writable = true;
        self
    }

    fn executable(mut self) -> Self {
        self.is_writable = false;
        self.executable = true;
        self
    }

    fn to_info<'a>(&'a mut self) -> AccountInfo<'a> {
        AccountInfo::new(
            &self.key,
            self.is_signer,
            self.is_writable,
            &mut self.lamports,
            &mut self.data,
            &self.owner,
            self.executable,
            0,
        )
    }
}

fn program_id() -> Pubkey {
    percolator_prog::id()
}

fn signer() -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0).signer()
}

/// A signer with a CHOSEN key — needed to sign as an asset's own `asset_admin`.
fn signer_with_key(key: Pubkey) -> TestAccount {
    TestAccount::new(key, Pubkey::new_unique(), 0).signer()
}

fn market_account() -> TestAccount {
    let capacity = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize;
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::market_account_len_for_capacity(capacity).unwrap(),
    )
    .writable()
}

fn make_mint_data() -> Vec<u8> {
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}

fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut data,
    )
    .unwrap();
    data
}

fn mint_account() -> TestAccount {
    TestAccount::new_with_data(Pubkey::new_unique(), spl_token::ID, make_mint_data())
}

fn user_token_account(owner: Pubkey, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data(mint, owner, amount),
    )
    .writable()
}

fn vault_authority(market: &TestAccount) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", market.key.as_ref()], &program_id()).0
}

fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse()
        .unwrap();
    Pubkey::find_program_address(
        &[
            vault_authority.as_ref(),
            spl_token::ID.as_ref(),
            mint.as_ref(),
        ],
        &ata_program,
    )
    .0
}

fn vault_token_account(market: &TestAccount, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        canonical_vault_ata(&vault_authority(market), &mint),
        spl_token::ID,
        make_token_data(mint, vault_authority(market), amount),
    )
    .writable()
}

fn vault_authority_account(market: &TestAccount) -> TestAccount {
    TestAccount::new(vault_authority(market), Pubkey::new_unique(), 0)
}

fn token_program_account() -> TestAccount {
    TestAccount::new(spl_token::ID, Pubkey::new_unique(), 0).executable()
}

fn run_ix(ix: Instruction, accounts: &mut [&mut TestAccount]) -> Result<(), ProgramError> {
    let data = ix.encode();
    let snapshots: Vec<(u64, Vec<u8>)> = accounts
        .iter()
        .map(|a| (a.lamports, a.data.clone()))
        .collect();
    let result = {
        let infos: Vec<AccountInfo> = accounts.iter_mut().map(|a| a.to_info()).collect();
        processor::process_instruction(&program_id(), &infos, &data)
    };
    if result.is_err() {
        for (account, (lamports, data)) in accounts.iter_mut().zip(snapshots) {
            account.lamports = lamports;
            account.data = data;
        }
    }
    result
}

fn default_init_market_ix() -> Instruction {
    default_init_market_ix_with_assets(1)
}

/// GH#420: the same fixture with a chosen asset count.
///
/// The default is single-asset, which cannot express "asset 0's admin drains
/// asset 1's fees" at all — there is no asset 1, so the claim is rejected as
/// out-of-range and the test would look like it passed for the right reason
/// while proving nothing.
fn default_init_market_ix_with_assets(max_portfolio_assets: u16) -> Instruction {
    Instruction::InitMarket {
        max_portfolio_assets,
        h_min: 0,
        h_max: 10,
        initial_price: 100,
        min_nonzero_mm_req: 1,
        min_nonzero_im_req: 2,
        maintenance_margin_bps: 10_000,
        initial_margin_bps: 10_000,
        max_trading_fee_bps: 10_000,
        trade_fee_base_bps: 0,
        liquidation_fee_bps: 0,
        liquidation_fee_cap: 0,
        min_liquidation_abs: 0,
        max_price_move_bps_per_slot: 10_000,
        max_accrual_dt_slots: 1,
        max_abs_funding_e9_per_slot: 0,
        min_funding_lifetime_slots: 1,
        max_account_b_settlement_chunks: 1,
        max_bankrupt_close_chunks: 1,
        max_bankrupt_close_lifetime_slots: 100,
        public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
        maintenance_fee_per_slot: 0,
    }
}

fn init_market(admin: &mut TestAccount, market: &mut TestAccount) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(default_init_market_ix(), &mut [admin, market, &mut mint]).unwrap();
    mint_key
}

fn init_market_two_assets(admin: &mut TestAccount, market: &mut TestAccount) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(
        default_init_market_ix_with_assets(2),
        &mut [admin, market, &mut mint],
    )
    .unwrap();
    mint_key
}

// ── The isolation tests ─────────────────────────────────────────────────────

/// A nonzero insurance-withdraw cooldown is what makes tag 57 PERSIST the
/// wrapper config (`handle_withdraw_insurance_asset` only calls
/// `write_wrapper_config` when `cooldown_dirty`, i.e. when this is > 0).
///
/// Without it the direction-B assertions below are VACUOUS: tag 57 would never
/// write cfg back in this fixture, so no cfg-level regression — not even a bare
/// `cfg.creator_fee_claimable_atoms = 0;` spliced into the handler — could be
/// observed by re-reading the account. Proven by mutation on 2026-07-24: with
/// the cooldown at 0 that splice left every test here green.
///
/// Any value > 0 arms the write-back; the value itself is irrelevant because
/// `check_insurance_withdraw_cooldown` is a no-op while
/// `last_insurance_withdraw_slot == 0` (the first withdrawal is always allowed),
/// and each test below performs at most one tag-57 call.
const TEST_INSURANCE_WITHDRAW_COOLDOWN_SLOTS: u64 = 25;

/// Seeds a live market with BOTH a funded per-domain insurance budget (the loss
/// backstop, which tag 57 spends) and a nonzero creator claim (which it must
/// not touch).
fn seed_both_pots(market: &mut TestAccount, claimable: u64, budget_long: u128, budget_short: u128) {
    let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
    cfg.creator_fee_claimable_atoms = claimable;
    // See the constant's docs: this is what forces tag 57 to write cfg back, and
    // is therefore what makes every `creator_fee_claimable_atoms` assertion in
    // this file falsifiable rather than vacuous.
    cfg.insurance_withdraw_cooldown_slots = TEST_INSURANCE_WITHDRAW_COOLDOWN_SLOTS;
    cfg.last_insurance_withdraw_slot = 0;
    group.insurance_domain_budget[0] = budget_long;
    group.insurance_domain_budget[1] = budget_short;
    group.insurance = 10_000;
    group.vault = 10_000;
    group.c_tot = 0;
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

/// Positive control shared by the direction-B tests: proves the tag-57 call
/// under test actually PERSISTED the wrapper config, so that the neighbouring
/// "the creator claim is unchanged" assertion is a real observation of the
/// post-instruction account and not an artifact of a config that was never
/// written. `last_insurance_withdraw_slot` moves 0 -> `now_slot` (the stubbed
/// Clock's slot 1) on exactly the write-back this file needs to exist.
fn assert_tag57_persisted_the_wrapper_config(
    cfg_before: &state::WrapperConfigV16,
    cfg_after: &state::WrapperConfigV16,
) {
    assert_eq!(
        cfg_before.last_insurance_withdraw_slot, 0,
        "fixture precondition: the cooldown clock starts unset"
    );
    assert_eq!(
        cfg_after.last_insurance_withdraw_slot, 1,
        "VACUITY GUARD: tag 57 must have written the wrapper config back (stubbed \
         Clock slot = 1). If this fires, the creator-claim assertions in this file \
         are no longer observing a persisted config and prove nothing — fix the \
         fixture, do not delete this check"
    );
}

/// ISOLATION direction B: draining the backstop through tag 57 must leave the
/// creator's claim untouched, atom for atom.
#[test]
fn withdraw_insurance_asset_cannot_reduce_the_creator_claim() {
    install_clock_stub();
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_both_pots(&mut market, 100, 150, 90);

    let (cfg_before, group_before) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_before.creator_fee_claimable_atoms, 100);
    assert_eq!(group_before.insurance_domain_budget[0], 150);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 10_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 0,
            amount: 120,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("the insurance_operator must be able to draw down the backstop (tag 57 still works)");

    let (cfg_after, group_after) = state::read_market(&market.data).unwrap();
    // Positive control #1: the instruction persisted cfg at all (see the helper).
    assert_tag57_persisted_the_wrapper_config(&cfg_before, &cfg_after);
    // Positive control #2: the backstop really did move, so the negative assertion
    // below is about isolation and not about a no-op instruction.
    assert_eq!(
        group_before.insurance_domain_budget[0] + group_before.insurance_domain_budget[1]
            - group_after.insurance_domain_budget[0]
            - group_after.insurance_domain_budget[1],
        120,
        "tag 57 must actually have spent 120 atoms of backstop budget"
    );
    assert_eq!(
        group_before.insurance - group_after.insurance,
        120,
        "and 120 atoms must have left the insurance fund"
    );
    // The point of the test.
    assert_eq!(
        cfg_after.creator_fee_claimable_atoms, 100,
        "WithdrawInsuranceAsset must not decrement creator_fee_claimable_atoms"
    );
}

/// Draining the backstop to ZERO still leaves the creator claim intact and
/// still claimable through tag 90 — the two pots do not share capacity.
#[test]
fn a_fully_drained_backstop_still_leaves_the_creator_claim_payable() {
    install_clock_stub();
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_both_pots(&mut market, 100, 60, 40);
    let (cfg_before, _) = state::read_market(&market.data).unwrap();

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 10_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 0,
            amount: 100,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("draining the whole per-asset backstop must succeed");

    let (cfg_mid, group_mid) = state::read_market(&market.data).unwrap();
    assert_tag57_persisted_the_wrapper_config(&cfg_before, &cfg_mid);
    assert_eq!(group_mid.insurance_domain_budget[0], 0);
    assert_eq!(group_mid.insurance_domain_budget[1], 0);
    assert_eq!(
        cfg_mid.creator_fee_claimable_atoms, 100,
        "the creator claim survives a fully drained backstop"
    );

    run_ix(
        Instruction::WithdrawCreatorFee {
            amount: 100,
            asset_index: 0,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("and is still payable afterwards");
    let (cfg_end, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_end.creator_fee_claimable_atoms, 0);
}

/// GH#420: asset 1's creator fees are claimable by ASSET 1's admin, and are NOT
/// drainable by asset 0's.
///
/// This is the headline of the issue. Every asset's creator cut used to accumulate
/// into one market-wide counter while the withdrawal check named asset 0's
/// `asset_admin` only, so in a multi-asset market the base deployer could withdraw
/// fees earned on assets 1..N and those assets' creators could never claim theirs.
#[test]
fn asset0_admin_cannot_drain_asset1_creator_fees() {
    install_clock_stub();
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);

    // Credit asset 1's creator pot directly; the accrual path is covered in
    // v16_wrapper.rs, and this test is about WHO may withdraw it.
    // Asset 1 needs a real `asset_admin`: a zeroed one matches NO signer
    // (`live_authority_matches` rejects a zero authority), so the positive control
    // below would fail for that reason rather than for the one under test.
    let asset1_admin_key = Pubkey::new_unique();
    {
        let mut p1 = state::read_asset_oracle_profile(&market.data, 1).unwrap();
        p1.creator_fee_claimable_atoms = 100;
        p1.asset_admin = asset1_admin_key.to_bytes();
        state::write_asset_oracle_profile(&mut market.data, 1, &p1).unwrap();
    }
    seed_both_pots(&mut market, 100, 150, 90);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 10_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    // Asset 0's admin claiming AGAINST ASSET 1 must be refused. Before GH#420 the
    // authority check read asset 0's profile regardless of whose fees these were,
    // so this succeeded and the atoms left with the wrong party.
    let before = market.data.clone();
    let stolen = run_ix(
        Instruction::WithdrawCreatorFee {
            amount: 100,
            asset_index: 1,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    );
    assert!(
        stolen.is_err(),
        "asset 0's admin must NOT be able to claim asset 1's creator fees"
    );
    assert_eq!(
        market.data, before,
        "the refused claim must leave the market byte-identical"
    );
    assert_eq!(
        state::read_asset_oracle_profile(&market.data, 1)
            .unwrap()
            .creator_fee_claimable_atoms,
        100,
        "asset 1's pot must be untouched"
    );

    // POSITIVE CONTROL: asset 1's OWN admin can claim it. Without this the
    // rejection above would pass against a handler that refused everything.
    let mut owner = signer_with_key(asset1_admin_key);
    let mut dest1 = user_token_account(owner.key, mint, 0);
    run_ix(
        Instruction::WithdrawCreatorFee {
            amount: 100,
            asset_index: 1,
        },
        &mut [
            &mut owner,
            &mut market,
            &mut dest1,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("asset 1's own admin must be able to claim asset 1's creator fees");
    assert_eq!(
        state::read_asset_oracle_profile(&market.data, 1)
            .unwrap()
            .creator_fee_claimable_atoms,
        0,
        "asset 1's pot must be drained by its own admin"
    );
}

/// The mirror of direction A, asserted here too because this binary is the only
/// place both instructions can run against the same market: a creator claim
/// must not shrink the backstop that tag 57 is entitled to spend afterwards.
#[test]
fn withdraw_creator_fee_leaves_the_backstop_fully_spendable_by_tag57() {
    install_clock_stub();
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    seed_both_pots(&mut market, 100, 150, 90);

    let mut dest = user_token_account(admin.key, mint, 0);
    let mut vault = vault_token_account(&market, mint, 10_000);
    let mut vault_auth = vault_authority_account(&market);
    let mut token_program = token_program_account();

    run_ix(
        Instruction::WithdrawCreatorFee {
            amount: 100,
            asset_index: 0,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("the creator claim must be payable");

    let (cfg_mid, group_mid) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg_mid.creator_fee_claimable_atoms, 0);
    assert_eq!(
        (
            group_mid.insurance_domain_budget[0],
            group_mid.insurance_domain_budget[1]
        ),
        (150, 90),
        "the creator claim must not have touched the backstop"
    );

    // And the backstop is still spendable in full — proving the claim did not
    // consume its capacity indirectly (e.g. via the shared insurance fund).
    run_ix(
        Instruction::WithdrawInsuranceAsset {
            asset_index: 0,
            amount: 240,
        },
        &mut [
            &mut admin,
            &mut market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
    .expect("the full backstop must still be spendable after a creator claim");
    let (_, group_end) = state::read_market(&market.data).unwrap();
    assert_eq!(group_end.insurance_domain_budget[0], 0);
    assert_eq!(group_end.insurance_domain_budget[1], 0);
}
