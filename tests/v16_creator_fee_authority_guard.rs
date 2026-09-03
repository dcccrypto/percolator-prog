//! Creator-fee-claim AUTHORITY GUARD (2026-07-24).
//!
//! Tag 90 `WithdrawCreatorFee` is gated on **asset 0's `asset_admin`** and
//! nothing else (2026-07-24 re-gate; it was `insurance_operator` until the
//! staked-create-flow lockout was found). That key is therefore the creator's
//! revenue: whoever can rewrite it can take the claim.
//!
//! `handle_update_asset_lifecycle`'s privileged re-activation branch is the ONE
//! path that rewrites the per-asset authorities (including `asset_admin`) on an
//! ALREADY-EXISTING slot, and it is gated on `cfg.marketauth` — which on a
//! STAKED market is the stake-pool PDA (`StakeInitPool` rotates `cfg.marketauth`
//! to it). So that branch reaching asset 0 would hand the creator's revenue to
//! the pool. A guard now pins it shut:
//!
//! ```ignore
//! if asset_index == 0 {
//!     return Err(PercolatorError::AssetSlotAlreadyConfigured.into());
//! }
//! ```
//!
//! # Why this file exists, and why it seeds a lifecycle directly
//!
//! The guard is DEFENSE IN DEPTH: today asset 0 is unreachable there anyway,
//! but only EMERGENTLY, via two checks that live far apart —
//!
//!   1. the in-service check immediately above it rejects
//!      Active/DrainOnly/Recovery, and
//!   2. `ASSET_ACTION_RETIRE` rejects `asset_index == 0`, so asset 0 can never
//!      become Retired in the first place.
//!
//! A test that merely fires ACTIVATE at a normal (Active) asset 0 therefore
//! proves NOTHING about the guard: check (1) answers first, with the very same
//! error code, whether or not the guard exists.  (That test is included below
//! as `activate_on_a_live_asset_zero_is_rejected_before_the_guard_is_reached`
//! and is explicitly labelled as not load-bearing.)
//!
//! To make the guard observable, `asset_zero_seeded_retired_*` seeds asset 0's
//! lifecycle to Retired directly in the account — i.e. it simulates exactly the
//! future in which someone relaxes check (2), adds a new non-in-service
//! lifecycle, or otherwise lets asset 0 out of service. That is the scenario
//! the guard exists for, so that is the scenario the test must create.
//! `identical_retired_seed_activates_normally_at_asset_index_one` is the
//! positive control: the SAME seeding at index 1 activates successfully, so the
//! index-0 rejection is attributable to the index and not to an unactivatable
//! fixture.
//!
//! Harness: a minimal in-process copy of `tests/v16_wrapper.rs`'s (no
//! portfolios, no trades, no Clock stub — `authenticated_slot_or_fallback`
//! falls back to the instruction's `now_slot` when the sysvar is unavailable,
//! which makes slots deterministic here). `tests/common/mod.rs` is deliberately
//! NOT used: it is the LiteSVM harness and loads a PREBUILT
//! `target/deploy/percolator_prog.so`, i.e. yesterday's bytecode rather than
//! this source tree.

#![cfg(not(kani))]

use percolator::AssetLifecycleV16;
use percolator_prog::{ix::Instruction, processor, state};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, program_option::COption,
    program_pack::Pack, pubkey::Pubkey,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

/// `PercolatorError::AssetSlotAlreadyConfigured`. Pinned as a literal so this
/// file also fails if the ordinal shifts (ordinals are wire-visible).
const ERR_ASSET_SLOT_ALREADY_CONFIGURED: ProgramError = ProgramError::Custom(61);
/// `PercolatorError::Unauthorized`.
const ERR_UNAUTHORIZED: ProgramError = ProgramError::Custom(8);
/// `PercolatorError::InvalidInstruction`.
const ERR_INVALID_INSTRUCTION: ProgramError = ProgramError::Custom(9);

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

    // Kept byte-identical to the harness in `tests/v16_wrapper.rs` /
    // `tests/v16_creator_fee_isolation.rs` (a `to_*` that takes `&mut self`) so
    // the three copies stay diffable; silenced locally so this new file adds no
    // clippy warning of its own.
    #[allow(clippy::wrong_self_convention)]
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

/// Two asset slots, so index 1 exists as a re-activation target and index 0 is
/// strictly below `max_market_slots` (i.e. the append path cannot be taken for
/// it — every ACTIVATE at index 0 lands in the privileged re-activation branch
/// that carries the guard).
fn init_two_asset_market(admin: &mut TestAccount, market: &mut TestAccount) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(
        Instruction::InitMarket {
            max_portfolio_assets: 2,
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
        },
        &mut [admin, market, &mut mint],
    )
    .unwrap();
    // Fixture assumption, asserted rather than assumed: asset 0's profile is
    // stored per-slot and is only regenerated from the config by the host-side
    // `state::write_market` when the oracle mode is NOT manual. Every seeding
    // helper below relies on manual mode to leave asset 0's authorities alone.
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(
        cfg.oracle_mode,
        percolator_prog::constants::ORACLE_MODE_MANUAL,
        "fixture precondition: manual oracle mode, so state::write_market does \
         not rewrite asset 0's profile from the config"
    );
    mint_key
}

/// Drives an asset slot to `Retired` directly, simulating the future in which a
/// lifecycle change lets asset 0 out of service (see the file header). Mirrors
/// the shape the engine requires of a re-activatable retired slot: a nonzero
/// `market_id` (already true for every slot `InitMarket` configures) and a
/// nonzero `retired_slot`.
fn seed_asset_slot_retired(market: &mut TestAccount, asset_index: usize, retired_slot: u64) {
    let (cfg, mut group) = state::read_market(&market.data).unwrap();
    assert_ne!(
        group.assets[asset_index].market_id, 0,
        "a retired slot the engine will re-activate must carry a market_id"
    );
    group.assets[asset_index].lifecycle = AssetLifecycleV16::Retired;
    group.assets[asset_index].retired_slot = retired_slot;
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

/// Simulates `StakeInitPool`'s `cfg.marketauth = <stake pool PDA>` rotation.
/// Writes ONLY the wrapper config, exactly as the on-chain handler does, so
/// asset 0's stored profile (and therefore its `asset_admin`, the tag-90 claim
/// gate) is untouched — which is the whole point of the property under test.
fn rotate_marketauth(market: &mut TestAccount, new_marketauth: [u8; 32]) {
    let (mut cfg, _) = state::read_market(&market.data).unwrap();
    cfg.marketauth = new_marketauth;
    state::write_wrapper_config(&mut market.data, &cfg).unwrap();
}

/// Gives the market a claimable creator balance plus enough unbudgeted surplus
/// in `insurance`/`vault` for tag 90 to actually pay it out.
fn seed_creator_claim(market: &mut TestAccount, claimable: u64) {
    let (mut cfg, mut group) = state::read_market(&market.data).unwrap();
    cfg.creator_fee_claimable_atoms = claimable;
    group.insurance = 10_000;
    group.vault = 10_000;
    group.c_tot = 0;
    state::write_market(&mut market.data, &cfg, &group).unwrap();
}

/// Reads asset `asset_index`'s `asset_admin` -- the key tag 90
/// `WithdrawCreatorFee` gates on. The re-activation branch under test rewrites
/// this field (`profile.asset_admin = authority.key`), so it is the field whose
/// integrity the `if asset_index == 0` guard protects.
fn asset_admin_of(market: &TestAccount, asset_index: usize) -> [u8; 32] {
    state::read_asset_oracle_profile(&market.data, asset_index)
        .unwrap()
        .asset_admin
}

fn activate_ix(
    asset_index: u16,
    now_slot: u64,
    initial_price: u64,
    authority: [u8; 32],
) -> Instruction {
    Instruction::UpdateAssetLifecycle {
        action: processor::ASSET_ACTION_ACTIVATE,
        asset_index,
        now_slot,
        initial_price,
        insurance_authority: authority,
        insurance_operator: authority,
        backing_bucket_authority: authority,
        oracle_authority: authority,
    }
}

fn retire_ix(asset_index: u16, now_slot: u64) -> Instruction {
    Instruction::UpdateAssetLifecycle {
        action: processor::ASSET_ACTION_RETIRE,
        asset_index,
        now_slot,
        initial_price: 0,
        insurance_authority: [0u8; 32],
        insurance_operator: [0u8; 32],
        backing_bucket_authority: [0u8; 32],
        oracle_authority: [0u8; 32],
    }
}

/// Runs tag 90 for `authority` against a freshly built account set.
fn withdraw_creator_fee(
    authority: &mut TestAccount,
    market: &mut TestAccount,
    mint: Pubkey,
    amount: u128,
) -> Result<(), ProgramError> {
    let mut dest = user_token_account(authority.key, mint, 0);
    let mut vault = vault_token_account(market, mint, 10_000);
    let mut vault_auth = vault_authority_account(market);
    let mut token_program = token_program_account();
    run_ix(
        Instruction::WithdrawCreatorFee {
            amount,
            asset_index: 0,
        },
        &mut [
            authority,
            market,
            &mut dest,
            &mut vault,
            &mut vault_auth,
            &mut token_program,
        ],
    )
}

// ── The guard ───────────────────────────────────────────────────────────────

/// THE LOAD-BEARING TEST. `marketauth` (here: the stake pool that
/// `StakeInitPool` installed) attempts to re-activate asset 0 and install
/// ITSELF as every per-asset authority — including `asset_admin`, the one key
/// tag 90 accepts. It must be rejected, asset 0's `asset_admin` must still be
/// the creator's, and the creator's claim must still be payable.
///
/// Mutation-proven 2026-07-24: deleting `if asset_index == 0 { return Err(...) }`
/// from `handle_update_asset_lifecycle`'s ACTIVATE branch makes this test fail
/// (the activation succeeds, `asset_admin` becomes the pool's key, and the pool
/// can then claim).
#[test]
fn asset_zero_seeded_retired_cannot_be_reactivated_by_marketauth() {
    let mut creator = signer();
    let mut stake_pool = signer();
    let mut market = market_account();
    let mint = init_two_asset_market(&mut creator, &mut market);

    // InitMarket bootstraps asset 0's asset_admin to the creator.
    assert_eq!(
        asset_admin_of(&market, 0),
        creator.key.to_bytes(),
        "fixture precondition: the creator holds asset 0's asset_admin"
    );

    seed_creator_claim(&mut market, 100);
    seed_asset_slot_retired(&mut market, 0, 1);
    rotate_marketauth(&mut market, stake_pool.key.to_bytes());

    let attack = run_ix(
        activate_ix(0, 4, 100, stake_pool.key.to_bytes()),
        &mut [&mut stake_pool, &mut market],
    );
    assert_eq!(
        attack,
        Err(ERR_ASSET_SLOT_ALREADY_CONFIGURED),
        "marketauth must not be able to re-activate asset 0 (that branch rewrites \
         the per-asset authorities, and asset 0's asset_admin IS the creator-fee key)"
    );
    assert_eq!(
        asset_admin_of(&market, 0),
        creator.key.to_bytes(),
        "asset 0's asset_admin must be unchanged by the rejected attempt"
    );

    // The theft this guard prevents, spelled out: the pool cannot claim...
    assert_eq!(
        withdraw_creator_fee(&mut stake_pool, &mut market, mint, 100),
        Err(ERR_UNAUTHORIZED),
        "the stake pool must not be able to claim the creator's fees"
    );
    // ...and the creator still can, in full.
    withdraw_creator_fee(&mut creator, &mut market, mint, 100)
        .expect("the creator's claim must survive the attempted authority rewrite");
    let (cfg, _) = state::read_market(&market.data).unwrap();
    assert_eq!(cfg.creator_fee_claimable_atoms, 0);
}

/// POSITIVE CONTROL for the test above. The identical retired-slot seeding at
/// index 1 DOES activate, and DOES install the caller as `asset_admin`.
/// Without this, `asset_zero_seeded_retired_cannot_be_reactivated_by_marketauth`
/// could be passing because the seeded slot is simply not activatable at all —
/// i.e. it could be vacuous.
#[test]
fn identical_retired_seed_activates_normally_at_asset_index_one() {
    let mut creator = signer();
    let mut stake_pool = signer();
    let mut market = market_account();
    init_two_asset_market(&mut creator, &mut market);

    seed_asset_slot_retired(&mut market, 1, 1);
    rotate_marketauth(&mut market, stake_pool.key.to_bytes());

    run_ix(
        activate_ix(1, 4, 100, stake_pool.key.to_bytes()),
        &mut [&mut stake_pool, &mut market],
    )
    .expect("the same seeded retired slot must be activatable at a nonzero index");
    assert_eq!(
        asset_admin_of(&market, 1),
        stake_pool.key.to_bytes(),
        "the re-activation branch does install the caller as asset_admin (the \
         creator-fee key) — which is exactly why it must never reach asset 0"
    );
    assert_eq!(
        asset_admin_of(&market, 0),
        creator.key.to_bytes(),
        "and it must not touch asset 0's asset_admin while doing so"
    );
}

/// THE GUARD MUST NOT BE OVER-BROAD. Legitimate slot recycling — retire a
/// non-zero asset through the real instruction, then re-activate it with fresh
/// domain authorities — must still work end to end.
#[test]
fn retired_nonzero_slot_recycling_still_sets_fresh_domain_authorities() {
    let mut creator = signer();
    let mut market = market_account();
    init_two_asset_market(&mut creator, &mut market);
    let new_operator = Pubkey::new_unique().to_bytes();

    run_ix(retire_ix(1, 2), &mut [&mut creator, &mut market])
        .expect("marketauth must be able to retire a nonzero asset slot");
    let (cfg_retired, group_retired) = state::read_market(&market.data).unwrap();
    assert_eq!(
        group_retired.assets[1].lifecycle,
        AssetLifecycleV16::Retired
    );
    assert_eq!(cfg_retired.free_market_slot_count, 1);

    run_ix(
        activate_ix(1, 1_000, 101, new_operator),
        &mut [&mut creator, &mut market],
    )
    .expect("a RETIRED nonzero slot must still be recyclable with new authorities");

    let (cfg_reused, group_reused) = state::read_market(&market.data).unwrap();
    assert_eq!(group_reused.assets[1].lifecycle, AssetLifecycleV16::Active);
    assert_eq!(cfg_reused.free_market_slot_count, 0);
    let profile1 = state::read_asset_oracle_profile(&market.data, 1).unwrap();
    assert_eq!(profile1.insurance_operator, new_operator);
    assert_eq!(profile1.insurance_authority, new_operator);
    assert_eq!(profile1.backing_bucket_authority, new_operator);
    assert_eq!(profile1.oracle_authority, new_operator);
    // ...including asset_admin, which the branch sets to the re-activating signer
    // (the creator here). This is exactly the write the asset-0 guard blocks.
    assert_eq!(profile1.asset_admin, creator.key.to_bytes());
    assert_eq!(
        asset_admin_of(&market, 0),
        creator.key.to_bytes(),
        "recycling slot 1 must leave asset 0's creator-fee authority (asset_admin) alone"
    );
}

/// The OTHER half of the two-check safety the guard backstops: asset 0 can
/// never be retired, so on today's code it can never become re-activatable.
/// Pinned so that relaxing this check is a visible, deliberate act rather than
/// a silent re-opening of the creator-fee theft path.
///
/// Mutation-proven 2026-07-24: dropping `asset_index == 0 ||` from
/// `ASSET_ACTION_RETIRE`'s reject condition makes this test fail.
#[test]
fn asset_zero_can_never_be_retired() {
    let mut creator = signer();
    let mut market = market_account();
    init_two_asset_market(&mut creator, &mut market);

    assert_eq!(
        run_ix(retire_ix(0, 2), &mut [&mut creator, &mut market]),
        Err(ERR_INVALID_INSTRUCTION),
        "asset 0 must not be retirable — a retired asset 0 is re-activatable, \
         and re-activation rewrites the creator-fee authority"
    );
    let (_, group) = state::read_market(&market.data).unwrap();
    assert_eq!(group.assets[0].lifecycle, AssetLifecycleV16::Active);
}

/// NOT LOAD-BEARING, and documented as such so nobody mistakes it for coverage
/// of the guard: a normal, in-service asset 0 is rejected by the in-service
/// lifecycle check that sits ABOVE the guard, with the same error code. This
/// test passes with or without `if asset_index == 0`. It is here only to pin
/// the ordinary path's behaviour.
#[test]
fn activate_on_a_live_asset_zero_is_rejected_before_the_guard_is_reached() {
    let mut creator = signer();
    let mut stake_pool = signer();
    let mut market = market_account();
    init_two_asset_market(&mut creator, &mut market);
    rotate_marketauth(&mut market, stake_pool.key.to_bytes());

    assert_eq!(
        run_ix(
            activate_ix(0, 4, 100, stake_pool.key.to_bytes()),
            &mut [&mut stake_pool, &mut market]
        ),
        Err(ERR_ASSET_SLOT_ALREADY_CONFIGURED)
    );
    assert_eq!(asset_admin_of(&market, 0), creator.key.to_bytes());
}
