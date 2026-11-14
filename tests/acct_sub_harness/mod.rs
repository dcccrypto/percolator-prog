//! Shared in-process harness for the two account-substitution binaries
//! (`acct_sub_withdraw_insurance.rs`, `acct_sub_crank_liq.rs`). Job J-20261114-PROG-ACCTSUB2.
//!
//! A deliberately small copy of the `tests/v16_wrapper.rs` harness (that file is one 29k-line test
//! binary and cannot be imported). Lives in a sub-directory so cargo does not build it as its own
//! test target. Every account-substitution cell swaps in ONE hostile account and requires the
//! wrapper to reject; each fixture has a baseline test that the unmutated list succeeds.
#![allow(dead_code)]

use percolator_prog::{ix::Instruction, processor, state};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, program_option::COption,
    program_pack::Pack, pubkey::Pubkey,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};

pub fn next_intent_id() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Clone)]
pub struct TestAccount {
    pub key: Pubkey,
    pub owner: Pubkey,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub is_signer: bool,
    pub is_writable: bool,
    pub executable: bool,
}

impl TestAccount {
    pub fn new(key: Pubkey, owner: Pubkey, data_len: usize) -> Self {
        Self::new_with_data(key, owner, vec![0u8; data_len])
    }
    pub fn new_with_data(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> Self {
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
    pub fn signer(mut self) -> Self {
        self.is_signer = true;
        self
    }
    pub fn writable(mut self) -> Self {
        self.is_writable = true;
        self
    }
    pub fn executable(mut self) -> Self {
        self.is_writable = false;
        self.executable = true;
        self
    }
    pub fn to_info<'a>(&'a mut self) -> AccountInfo<'a> {
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

pub fn program_id() -> Pubkey {
    percolator_prog::id()
}

pub fn signer() -> TestAccount {
    TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0).signer()
}

pub fn market_account() -> TestAccount {
    let capacity = percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize;
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::market_account_len_for_capacity(capacity).unwrap(),
    )
    .writable()
}

pub fn portfolio_account() -> TestAccount {
    TestAccount::new(
        Pubkey::new_unique(),
        program_id(),
        state::portfolio_account_len_for_market_slots(
            percolator_prog::constants::WRAPPER_MAX_PORTFOLIO_ASSETS as usize,
        )
        .unwrap(),
    )
    .writable()
}

pub fn make_mint_data() -> Vec<u8> {
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

pub fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
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

pub fn mint_account() -> TestAccount {
    TestAccount::new_with_data(Pubkey::new_unique(), spl_token::ID, make_mint_data())
}

pub fn user_token_account(owner: Pubkey, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        Pubkey::new_unique(),
        spl_token::ID,
        make_token_data(mint, owner, amount),
    )
    .writable()
}

pub fn vault_authority(market: &TestAccount) -> Pubkey {
    Pubkey::find_program_address(&[b"vault", market.key.as_ref()], &program_id()).0
}

pub fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
        .parse()
        .unwrap();
    Pubkey::find_program_address(
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

pub fn vault_token_account(market: &TestAccount, mint: Pubkey, amount: u64) -> TestAccount {
    TestAccount::new_with_data(
        canonical_vault_ata(&vault_authority(market), &mint),
        spl_token::ID,
        make_token_data(mint, vault_authority(market), amount),
    )
    .writable()
}

pub fn vault_authority_account(market: &TestAccount) -> TestAccount {
    TestAccount::new(vault_authority(market), Pubkey::new_unique(), 0)
}

pub fn token_program_account() -> TestAccount {
    TestAccount::new(spl_token::ID, Pubkey::new_unique(), 0).executable()
}

fn install_rent_sysvar_stub() {
    struct RentSysvarStub;
    impl solana_program::program_stubs::SyscallStubs for RentSysvarStub {
        fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
            // SAFETY: `Rent::get()` passes a pointer to a properly aligned `Rent`.
            unsafe { *(var_addr as *mut solana_program::rent::Rent) = Default::default() };
            solana_program::entrypoint::SUCCESS
        }
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        solana_program::program_stubs::set_syscall_stubs(Box::new(RentSysvarStub));
    });
}

/// InitMarket / InitPortfolio need the new account to sign (the real client's createAccount key
/// does); InitPortfolio also reads the rent sysvar and needs a rent-exempt account. Mirrors
/// `with_d26_init_signer` in v16_wrapper.rs. Only the crank binary calls this: the
/// withdraw-insurance binary installs its own Clock stub and never inits a portfolio.
fn with_init_signer<R>(
    ix: &Instruction,
    accounts: &mut [&mut TestAccount],
    f: impl FnOnce(&mut [&mut TestAccount]) -> R,
) -> R {
    let idx = match ix {
        Instruction::InitMarket { .. } => Some(1),
        Instruction::InitPortfolio => Some(2),
        _ => None,
    };
    let Some(i) = idx.filter(|i| *i < accounts.len()) else {
        return f(accounts);
    };
    if matches!(ix, Instruction::InitPortfolio) {
        install_rent_sysvar_stub();
        let rent = solana_program::rent::Rent::default().minimum_balance(accounts[i].data.len());
        accounts[i].lamports = accounts[i].lamports.max(rent);
    }
    let was = accounts[i].is_signer;
    accounts[i].is_signer = true;
    let r = f(accounts);
    accounts[i].is_signer = was;
    r
}

/// Runs one instruction; on error restores every account (as the runtime does on a failed tx).
pub fn run_ix(ix: Instruction, accounts: &mut [&mut TestAccount]) -> Result<(), ProgramError> {
    let data = ix.encode();
    let snapshots: Vec<(u64, Vec<u8>)> = accounts
        .iter()
        .map(|a| (a.lamports, a.data.clone()))
        .collect();
    let result = with_init_signer(&ix, accounts, |accounts| {
        let infos: Vec<AccountInfo> = accounts.iter_mut().map(|a| a.to_info()).collect();
        processor::process_instruction(&program_id(), &infos, &data)
    });
    if result.is_err() {
        for (account, (lamports, data)) in accounts.iter_mut().zip(snapshots) {
            account.lamports = lamports;
            account.data = data;
        }
    }
    result
}

/// Same WITHOUT the rollback, so "a rejected call left the account bytes alone" is a real
/// observation of the handler (fail-closed ordering) and not something the harness guarantees.
pub fn run_ix_no_rollback(ix: Instruction, accounts: &mut [&mut TestAccount]) -> Result<(), ProgramError> {
    let data = ix.encode();
    with_init_signer(&ix, accounts, |accounts| {
        let infos: Vec<AccountInfo> = accounts.iter_mut().map(|a| a.to_info()).collect();
        processor::process_instruction(&program_id(), &infos, &data)
    })
}

pub fn default_init_market_ix() -> Instruction {
    Instruction::InitMarket {
        max_portfolio_assets: 1,
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

pub fn init_market(admin: &mut TestAccount, market: &mut TestAccount) -> Pubkey {
    let mut mint = mint_account();
    let mint_key = mint.key;
    run_ix(default_init_market_ix(), &mut [admin, market, &mut mint]).unwrap();
    mint_key
}

pub fn init_portfolio(owner: &mut TestAccount, market: &mut TestAccount, portfolio: &mut TestAccount) {
    run_ix(Instruction::InitPortfolio, &mut [owner, market, portfolio]).unwrap();
}

pub fn portfolio_identity(portfolio: &TestAccount) -> (u64, u64, u64) {
    (
        state::read_portfolio_id(&portfolio.data).unwrap(),
        state::read_portfolio_matcher_sequence(&portfolio.data).unwrap(),
        state::read_portfolio_position_epoch(&portfolio.data).unwrap(),
    )
}

pub fn deposit(
    owner: &mut TestAccount,
    market: &mut TestAccount,
    portfolio: &mut TestAccount,
    amount: u128,
) {
    let mint = Pubkey::new_from_array(state::read_market(&market.data).unwrap().0.collateral_mint);
    let amount_u64 = u64::try_from(amount).unwrap();
    let mut source_token = user_token_account(owner.key, mint, amount_u64);
    let mut vault_token = vault_token_account(market, mint, 0);
    let mut token_program = token_program_account();
    let (portfolio_id, expected_sequence, _) = portfolio_identity(portfolio);
    run_ix(
        Instruction::Deposit { portfolio_id, expected_sequence, amount },
        &mut [owner, market, portfolio, &mut source_token, &mut vault_token, &mut token_program],
    )
    .unwrap();
}

pub fn configure_base_ewma_mark(admin: &mut TestAccount, market: &mut TestAccount, now_slot: u64, mark_e6: u64) {
    let observation_sequence =
        state::read_asset_control_sequences(&market.data, 0).unwrap().oracle_observation + 1;
    run_ix(
        Instruction::ConfigureEwmaMark {
            market_id: 1,
            asset_index: 0,
            now_slot,
            initial_mark_e6: mark_e6,
            mark_ewma_halflife_slots: 1,
            mark_min_fee: 0,
            observation_sequence,
        },
        &mut [admin, market],
    )
    .unwrap();
}

pub fn push_base_ewma_mark(admin: &mut TestAccount, market: &mut TestAccount, now_slot: u64, mark_e6: u64) {
    let observation_sequence =
        state::read_asset_control_sequences(&market.data, 0).unwrap().oracle_observation + 1;
    run_ix(
        Instruction::PushEwmaMark {
            market_id: 1,
            asset_index: 0,
            now_slot,
            mark_e6,
            observation_sequence,
        },
        &mut [admin, market],
    )
    .unwrap();
}

// ---- substitution machinery ------------------------------------------------------------------

#[derive(Clone)]
pub struct SubFx {
    pub accts: Vec<TestAccount>,
    pub ix: fn(&[TestAccount]) -> Instruction,
    pub market: usize,
    pub portfolio: Option<usize>,
    pub signers: Vec<usize>,
    /// SPL token accounts the handler requires writable.
    pub tokens: Vec<usize>,
    pub vault: Option<usize>,
    pub vault_auth: Option<usize>,
    /// A portfolio bound to a DIFFERENT initialised market.
    pub spare_portfolio: Option<TestAccount>,
}

pub fn sub_run(fx: &mut SubFx) -> Result<(), ProgramError> {
    let ix = (fx.ix)(&fx.accts);
    let mut refs: Vec<&mut TestAccount> = fx.accts.iter_mut().collect();
    run_ix(ix, &mut refs)
}

/// `sub_run` without the rollback (what the handler itself left behind).
pub fn sub_run_raw(fx: &mut SubFx) -> Result<(), ProgramError> {
    let ix = (fx.ix)(&fx.accts);
    let mut refs: Vec<&mut TestAccount> = fx.accts.iter_mut().collect();
    run_ix_no_rollback(ix, &mut refs)
}

/// Runs with slot `j` holding the same `AccountInfo` as slot `i` (either order), the way the
/// runtime hands one shared `AccountInfo` to a handler when the same key appears twice. Slot `j`'s
/// own account is replaced; slots `i` and `j` then both carry account `i`.
pub fn sub_run_dup(fx: &mut SubFx, i: usize, j: usize) -> Result<(), ProgramError> {
    assert!(i != j);
    let ix = (fx.ix)(&fx.accts);
    let data = ix.encode();
    let mut infos: Vec<Option<AccountInfo>> = Vec::new();
    for (k, a) in fx.accts.iter_mut().enumerate() {
        infos.push(if k == j { None } else { Some(a.to_info()) });
    }
    let shared = infos[i].clone().unwrap();
    infos[j] = Some(shared);
    let infos: Vec<AccountInfo> = infos.into_iter().map(|x| x.unwrap()).collect();
    processor::process_instruction(&program_id(), &infos, &data)
}

pub fn m_a(fx: &mut SubFx) {
    fx.accts[fx.market].owner = Pubkey::new_unique();
}
pub fn m_b(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    fx.accts[p].owner = Pubkey::new_unique();
}
pub fn m_c(fx: &mut SubFx) {
    let s = fx.signers[0];
    fx.accts[s].is_signer = false;
}
pub fn m_d(fx: &mut SubFx) {
    fx.accts[fx.market].is_writable = false;
}
pub fn m_e(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    fx.accts[p].is_writable = false;
}
pub fn m_g1(fx: &mut SubFx) {
    let len = fx.accts[fx.market].data.len();
    fx.accts[fx.market].data = vec![0u8; len];
}
pub fn m_g2(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    let spare = fx.spare_portfolio.take().unwrap();
    fx.accts[p] = spare;
}
pub fn m_h(fx: &mut SubFx) {
    if let Some(va) = fx.vault_auth {
        fx.accts[va].key = Pubkey::new_unique();
    } else {
        let v = fx.vault.unwrap();
        let t = TokenAccount::unpack(&fx.accts[v].data).unwrap();
        fx.accts[v].data = make_token_data(t.mint, Pubkey::new_unique(), t.amount);
    }
}
