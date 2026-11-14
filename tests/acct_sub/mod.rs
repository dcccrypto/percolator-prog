//! Account-substitution matrix for the money-moving instructions (job J-20261114-PROG-ACCTSUB).
//!
//! Attacker view: the caller picks every account in the list. For each instruction we swap in one
//! hostile account at a time and require the wrapper to reject. Each fixture also has a baseline
//! test that the UNMUTATED account list succeeds, so a rejection below cannot come from a broken
//! fixture.
//!
//! Columns: A market not owned by this program, B portfolio not owned by this program,
//! C signer missing, D market read-only, E portfolio read-only, F other user's portfolio /
//! non-authorized signer, G1 uninitialised (fake) market slab, G2 portfolio bound to another market,
//! H wrong vault-authority PDA or wrong vault authority, I duplicate accounts (one account passed
//! in two slots), T SPL token account read-only.
//!
//! This module lives in `tests/acct_sub/` and is compiled into the `v16_wrapper` test binary so it
//! can reuse that file's fixtures.
use super::*;

struct SubFx {
    accts: Vec<TestAccount>,
    ix: fn(&[TestAccount]) -> Instruction,
    market: usize,
    portfolio: Option<usize>,
    signers: Vec<usize>,
    /// SPL token accounts the handler requires writable.
    tokens: Vec<usize>,
    /// Token accounts whose SPL owner is the (first) signer.
    owner_tokens: Vec<usize>,
    vault: Option<usize>,
    vault_auth: Option<usize>,
    /// A portfolio bound to a DIFFERENT initialised market, same owner key as the signer.
    spare_portfolio: Option<TestAccount>,
}

fn sub_run(fx: &mut SubFx) -> Result<(), ProgramError> {
    let ix = (fx.ix)(&fx.accts);
    let mut refs: Vec<&mut TestAccount> = fx.accts.iter_mut().collect();
    run_ix(ix, &mut refs)
}

/// Runs with account `j` aliased onto account `i` (i < j), the way the runtime hands one shared
/// `AccountInfo` to a handler when the same key appears twice.
fn sub_run_dup(fx: &mut SubFx, i: usize, j: usize) -> Result<(), ProgramError> {
    assert!(i < j);
    let ix = (fx.ix)(&fx.accts);
    let data = ix.encode();
    let mut infos: Vec<AccountInfo> = Vec::new();
    for (k, a) in fx.accts.iter_mut().enumerate() {
        if k == j {
            let shared = infos[i].clone();
            infos.push(shared);
        } else {
            infos.push(a.to_info());
        }
    }
    processor::process_instruction(&program_id(), &infos, &data)
}

fn sub_attacker_token(fx: &mut SubFx, idx: usize, attacker: Pubkey) {
    let t = TokenAccount::unpack(&fx.accts[idx].data).unwrap();
    fx.accts[idx].data = make_token_data(t.mint, attacker, t.amount);
}

// ---- mutations -------------------------------------------------------------------------------
fn m_a(fx: &mut SubFx) {
    fx.accts[fx.market].owner = Pubkey::new_unique();
}
fn m_b(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    fx.accts[p].owner = Pubkey::new_unique();
}
fn m_c(fx: &mut SubFx) {
    for s in fx.signers.clone() {
        // one at a time is covered by `m_c_each`; here: the first signer
        fx.accts[s].is_signer = false;
        break;
    }
}
fn m_d(fx: &mut SubFx) {
    fx.accts[fx.market].is_writable = false;
}
fn m_e(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    fx.accts[p].is_writable = false;
}
fn m_f(fx: &mut SubFx) {
    let attacker = signer();
    let s = fx.signers[0];
    for t in fx.owner_tokens.clone() {
        sub_attacker_token(fx, t, attacker.key);
    }
    fx.accts[s] = attacker;
}
fn m_g1(fx: &mut SubFx) {
    let len = fx.accts[fx.market].data.len();
    fx.accts[fx.market].data = vec![0u8; len];
}
fn m_g2(fx: &mut SubFx) {
    let p = fx.portfolio.unwrap();
    let spare = fx.spare_portfolio.take().unwrap();
    fx.accts[p] = spare;
}
fn m_h(fx: &mut SubFx) {
    if let Some(va) = fx.vault_auth {
        fx.accts[va].key = Pubkey::new_unique();
    } else {
        let v = fx.vault.unwrap();
        let t = TokenAccount::unpack(&fx.accts[v].data).unwrap();
        fx.accts[v].data = make_token_data(t.mint, Pubkey::new_unique(), t.amount);
    }
}
fn m_t(fx: &mut SubFx) {
    for t in fx.tokens.clone() {
        fx.accts[t].is_writable = false;
        let r = sub_run(fx);
        fx.accts[t].is_writable = true;
        assert!(r.is_err(), "read-only token account {t} must be rejected");
    }
    // leave the fixture in a state that also fails, so the macro's own assert holds
    let t = fx.tokens[0];
    fx.accts[t].is_writable = false;
}

macro_rules! sub_cell {
    ($name:ident, $build:ident, $chk:ident) => {
        #[test]
        fn $name() {
            let mut fx = $build();
            $chk(&mut fx);
            let r = sub_run(&mut fx);
            assert!(r.is_err(), "substituted account was ACCEPTED: {r:?}");
        }
    };
}
macro_rules! sub_baseline {
    ($name:ident, $build:ident) => {
        #[test]
        fn $name() {
            let mut fx = $build();
            sub_run(&mut fx).expect("unmutated fixture must succeed");
        }
    };
}
macro_rules! sub_dup {
    ($name:ident, $build:ident, [$(($i:expr, $j:expr)),+]) => {
        #[test]
        fn $name() {
            $(
                let mut fx = $build();
                let r = sub_run_dup(&mut fx, $i, $j);
                assert!(r.is_err(), "duplicate ({}, {}) was ACCEPTED: {r:?}", $i, $j);
            )+
        }
    };
}

// ---- fixtures --------------------------------------------------------------------------------
#[allow(dead_code)]
struct Base {
    admin: TestAccount,
    market: TestAccount,
    owner: TestAccount,
    portfolio: TestAccount,
    mint: Pubkey,
    spare_market: TestAccount,
    spare_portfolio: TestAccount,
}

fn base(deposit_amount: u128) -> Base {
    let mut admin = signer();
    let mut market = market_account();
    let mint = init_market(&mut admin, &mut market);
    let mut owner = signer();
    let mut portfolio = portfolio_account();
    init_portfolio(&mut owner, &mut market, &mut portfolio);
    if deposit_amount > 0 {
        deposit(&mut owner, &mut market, &mut portfolio, deposit_amount);
    }
    // a second, fully initialised market with a portfolio owned by the SAME key
    let mut admin_b = signer();
    let mut spare_market = market_account();
    init_market(&mut admin_b, &mut spare_market);
    let mut owner_again = TestAccount::new(owner.key, Pubkey::new_unique(), 0).signer();
    let mut spare_portfolio = portfolio_account();
    init_portfolio(&mut owner_again, &mut spare_market, &mut spare_portfolio);
    if deposit_amount > 0 {
        deposit(&mut owner_again, &mut spare_market, &mut spare_portfolio, deposit_amount);
    }
    Base { admin, market, owner, portfolio, mint, spare_market, spare_portfolio }
}

fn fx_deposit() -> SubFx {
    let b = base(0);
    let src = user_token_account(b.owner.key, b.mint, 1_000);
    let vault = vault_token_account(&b.market, b.mint, 0);
    SubFx {
        accts: vec![b.owner, b.market, b.portfolio, src, vault, token_program_account()],
        ix: |a| {
            let (portfolio_id, expected_sequence, _) = portfolio_identity(&a[2]);
            Instruction::Deposit { portfolio_id, expected_sequence, amount: 100 }
        },
        market: 1,
        portfolio: Some(2),
        signers: vec![0],
        tokens: vec![3, 4],
        owner_tokens: vec![3],
        vault: Some(4),
        vault_auth: None,
        spare_portfolio: Some(b.spare_portfolio),
    }
}

fn fx_withdraw() -> SubFx {
    let b = base(1_000);
    let dest = user_token_account(b.owner.key, b.mint, 0);
    let vault = vault_token_account(&b.market, b.mint, 1_000);
    let va = vault_authority_account(&b.market);
    SubFx {
        accts: vec![b.owner, b.market, b.portfolio, dest, vault, va, token_program_account()],
        ix: |a| {
            let (portfolio_id, expected_sequence, _) = portfolio_identity(&a[2]);
            Instruction::Withdraw { portfolio_id, expected_sequence, amount: 100 }
        },
        market: 1,
        portfolio: Some(2),
        signers: vec![0],
        tokens: vec![3, 4],
        owner_tokens: vec![3],
        vault: Some(4),
        vault_auth: Some(5),
        spare_portfolio: Some(b.spare_portfolio),
    }
}

fn fx_close() -> SubFx {
    let mut b = base(1_000);
    withdraw(&mut b.owner, &mut b.market, &mut b.portfolio, 1_000);
    // ClosePortfolio demands the closer be writable (it receives the rent when the closer is the owner).
    b.owner.is_writable = true;
    SubFx {
        accts: vec![b.owner, b.market, b.portfolio],
        ix: |a| {
            let (portfolio_id, expected_sequence, position_epoch) = portfolio_identity(&a[2]);
            Instruction::ClosePortfolio { portfolio_id, expected_sequence, position_epoch }
        },
        market: 1,
        portfolio: Some(2),
        signers: vec![0],
        tokens: vec![],
        owner_tokens: vec![],
        vault: None,
        vault_auth: None,
        spare_portfolio: Some(b.spare_portfolio),
    }
}

fn fx_crank() -> SubFx {
    let b = base(1_000);
    let caller = TestAccount::new(Pubkey::new_unique(), Pubkey::new_unique(), 0);
    SubFx {
        accts: vec![caller, b.market, b.portfolio],
        ix: |_| Instruction::PermissionlessCrank {
            now_slot: 1,
            observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }],
        },
        market: 1,
        portfolio: Some(2),
        signers: vec![],
        tokens: vec![],
        owner_tokens: vec![],
        vault: None,
        vault_auth: None,
        spare_portfolio: Some(b.spare_portfolio),
    }
}

fn fx_trade() -> SubFx {
    let mut b = base(1_000_000);
    let mut owner_b = signer();
    let mut pb = portfolio_account();
    init_portfolio(&mut owner_b, &mut b.market, &mut pb);
    deposit(&mut owner_b, &mut b.market, &mut pb, 1_000_000);
    SubFx {
        accts: vec![b.owner, owner_b, b.market, b.portfolio, pb],
        ix: |a| {
            let (ida, _, epa) = portfolio_identity(&a[3]);
            let (idb, _, epb) = portfolio_identity(&a[4]);
            Instruction::TradeNoCpi {
                account_a_portfolio_id: ida,
                account_a_position_epoch: epa,
                account_b_portfolio_id: idb,
                account_b_position_epoch: epb,
                market_id: 1,
                asset_index: 0,
                size_q: POS_SCALE as i128,
                exec_price: 100,
                fee_bps: 0,
                backing_fee_cap_bps: 10_000,
            }
        },
        market: 2,
        portfolio: Some(3),
        signers: vec![0, 1],
        tokens: vec![],
        owner_tokens: vec![],
        vault: None,
        vault_auth: None,
        spare_portfolio: Some(b.spare_portfolio),
    }
}

/// WithdrawInsurance reads `Clock::get()?`, which the plain native harness cannot serve (the
/// older insurance tests are in KNOWN_FAILING for that reason). Serve a fixed clock, keeping the
/// rent stub the InitPortfolio helper needs.
fn install_clock_and_rent_stub() {
    struct Stub;
    impl solana_program::program_stubs::SyscallStubs for Stub {
        fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
            unsafe { *(var_addr as *mut solana_program::rent::Rent) = Default::default() };
            solana_program::entrypoint::SUCCESS
        }
        fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
            let clock = solana_program::clock::Clock { slot: 1_000_000_000,..Default::default() };
            unsafe { *(var_addr as *mut solana_program::clock::Clock) = clock };
            solana_program::entrypoint::SUCCESS
        }
    }
    // The rent-only stub is installed once per process by the first InitPortfolio; make sure it
    // has run so it can never replace this one afterwards.
    install_rent_sysvar_stub();
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        solana_program::program_stubs::set_syscall_stubs(Box::new(Stub));
    });
}

fn fx_withdraw_insurance() -> SubFx {
    install_clock_and_rent_stub();
    // No portfolio: terminal insurance withdrawal needs zero materialised portfolios.
    let mut b = {
        let mut admin = signer();
        let mut market = market_account();
        let mint = init_market(&mut admin, &mut market);
        Base {
            admin,
            market,
            owner: signer(),
            portfolio: portfolio_account(),
            mint,
            spare_market: market_account(),
            spare_portfolio: portfolio_account(),
        }
    };
    let mut source = user_token_account(b.admin.key, b.mint, 100);
    let mut vault = vault_token_account(&b.market, b.mint, 100);
    let mut tp = token_program_account();
    let epoch = state::read_asset_control_sequences(&b.market.data, 0).unwrap().authority_epoch;
    run_ix(
        Instruction::TopUpInsuranceDomain { domain: 0, market_id: 1, intent_id: next_intent_id(), amount: 100, authority_epoch: epoch },
        &mut [&mut b.admin, &mut b.market, &mut source, &mut vault, &mut tp],
    )
    .unwrap();
    let frontier = state::read_asset_generation_frontier(&b.market.data).unwrap();
    run_ix(
        Instruction::ResolveMarket { asset_generation_frontier: frontier, authority_epoch: epoch },
        &mut [&mut b.admin, &mut b.market],
    )
    .unwrap();
    let dest = user_token_account(b.admin.key, b.mint, 0);
    let va = vault_authority_account(&b.market);
    SubFx {
        accts: vec![b.admin, b.market, dest, vault, va, tp],
        ix: |_| Instruction::WithdrawInsurance { amount: 100 },
        market: 1,
        portfolio: None,
        signers: vec![0],
        tokens: vec![2, 3],
        owner_tokens: vec![2],
        vault: Some(3),
        vault_auth: Some(4),
        spare_portfolio: None,
    }
}

fn fx_withdraw_protocol_fee() -> SubFx {
    let mut b = base(0);
    seed_protocol_fee_fixture(&mut b.market, b.admin.key.to_bytes(), 100, 0, 100, 100);
    let dest = user_token_account(b.admin.key, b.mint, 0);
    let vault = vault_token_account(&b.market, b.mint, 100);
    let va = vault_authority_account(&b.market);
    SubFx {
        accts: vec![b.admin, b.market, dest, vault, va, token_program_account()],
        ix: |a| Instruction::WithdrawProtocolFee {
            amount: 50,
            authority_epoch: state::read_protocol_fee_authority_epoch(&a[1].data).unwrap_or(0),
        },
        market: 1,
        portfolio: None,
        signers: vec![0],
        tokens: vec![2, 3],
        owner_tokens: vec![2],
        vault: Some(3),
        vault_auth: Some(4),
        spare_portfolio: None,
    }
}

fn fx_withdraw_creator_fee() -> SubFx {
    let mut b = base(0);
    seed_creator_fee_fixture(&mut b.market, 100, 1_000, 1_000);
    let dest = user_token_account(b.admin.key, b.mint, 0);
    let vault = vault_token_account(&b.market, b.mint, 1_000);
    let va = vault_authority_account(&b.market);
    SubFx {
        accts: vec![b.admin, b.market, dest, vault, va, token_program_account()],
        ix: |a| Instruction::WithdrawCreatorFee {
            amount: 50,
            asset_index: 0,
            authority_epoch: state::read_asset_control_sequences(&a[1].data, 0)
                .map(|s| s.authority_epoch)
                .unwrap_or(0),
        },
        market: 1,
        portfolio: None,
        signers: vec![0],
        tokens: vec![2, 3],
        owner_tokens: vec![2],
        vault: Some(3),
        vault_auth: Some(4),
        spare_portfolio: None,
    }
}

// ---- baselines -------------------------------------------------------------------------------
sub_baseline!(acct_sub_baseline_deposit, fx_deposit);
sub_baseline!(acct_sub_baseline_withdraw, fx_withdraw);
sub_baseline!(acct_sub_baseline_close_portfolio, fx_close);
sub_baseline!(acct_sub_baseline_crank, fx_crank);
sub_baseline!(acct_sub_baseline_trade_nocpi, fx_trade);
sub_baseline!(acct_sub_baseline_withdraw_insurance, fx_withdraw_insurance);
sub_baseline!(acct_sub_baseline_withdraw_protocol_fee, fx_withdraw_protocol_fee);
sub_baseline!(acct_sub_baseline_withdraw_creator_fee, fx_withdraw_creator_fee);

// ---- Deposit ---------------------------------------------------------------------------------
sub_cell!(acct_sub_deposit_a_market_wrong_program, fx_deposit, m_a);
sub_cell!(acct_sub_deposit_b_portfolio_wrong_program, fx_deposit, m_b);
sub_cell!(acct_sub_deposit_c_signer_missing, fx_deposit, m_c);
sub_cell!(acct_sub_deposit_d_market_readonly, fx_deposit, m_d);
sub_cell!(acct_sub_deposit_e_portfolio_readonly, fx_deposit, m_e);
sub_cell!(acct_sub_deposit_f_other_users_portfolio, fx_deposit, m_f);
sub_cell!(acct_sub_deposit_g1_fake_market, fx_deposit, m_g1);
sub_cell!(acct_sub_deposit_g2_portfolio_of_other_market, fx_deposit, m_g2);
sub_cell!(acct_sub_deposit_h_wrong_vault_authority, fx_deposit, m_h);
sub_cell!(acct_sub_deposit_t_token_readonly, fx_deposit, m_t);
sub_dup!(acct_sub_deposit_i_duplicate_accounts, fx_deposit, [(3, 4), (1, 2)]);

// ---- Withdraw --------------------------------------------------------------------------------
sub_cell!(acct_sub_withdraw_a_market_wrong_program, fx_withdraw, m_a);
sub_cell!(acct_sub_withdraw_b_portfolio_wrong_program, fx_withdraw, m_b);
sub_cell!(acct_sub_withdraw_c_signer_missing, fx_withdraw, m_c);
sub_cell!(acct_sub_withdraw_d_market_readonly, fx_withdraw, m_d);
sub_cell!(acct_sub_withdraw_e_portfolio_readonly, fx_withdraw, m_e);
sub_cell!(acct_sub_withdraw_f_other_users_portfolio, fx_withdraw, m_f);
sub_cell!(acct_sub_withdraw_g1_fake_market, fx_withdraw, m_g1);
sub_cell!(acct_sub_withdraw_g2_portfolio_of_other_market, fx_withdraw, m_g2);
sub_cell!(acct_sub_withdraw_h_wrong_vault_authority_pda, fx_withdraw, m_h);
sub_cell!(acct_sub_withdraw_t_token_readonly, fx_withdraw, m_t);
sub_dup!(acct_sub_withdraw_i_duplicate_accounts, fx_withdraw, [(3, 4), (1, 2)]);

// ---- TradeNoCpi ------------------------------------------------------------------------------
sub_cell!(acct_sub_trade_a_market_wrong_program, fx_trade, m_a);
sub_cell!(acct_sub_trade_b_portfolio_wrong_program, fx_trade, m_b);
sub_cell!(acct_sub_trade_c_signer_missing, fx_trade, m_c);
sub_cell!(acct_sub_trade_d_market_readonly, fx_trade, m_d);
sub_cell!(acct_sub_trade_e_portfolio_readonly, fx_trade, m_e);
sub_cell!(acct_sub_trade_f_other_users_portfolio, fx_trade, m_f);
sub_cell!(acct_sub_trade_g1_fake_market, fx_trade, m_g1);
sub_cell!(acct_sub_trade_g2_portfolio_of_other_market, fx_trade, m_g2);
sub_dup!(acct_sub_trade_i_duplicate_accounts, fx_trade, [(3, 4), (2, 3)]);

// ---- Liquidate (the public crank: refresh + F1 liquidation step) -----------------------------
sub_cell!(acct_sub_crank_a_market_wrong_program, fx_crank, m_a);
sub_cell!(acct_sub_crank_b_portfolio_wrong_program, fx_crank, m_b);
sub_cell!(acct_sub_crank_d_market_readonly, fx_crank, m_d);
sub_cell!(acct_sub_crank_e_portfolio_readonly, fx_crank, m_e);
sub_cell!(acct_sub_crank_g1_fake_market, fx_crank, m_g1);
sub_cell!(acct_sub_crank_g2_portfolio_of_other_market, fx_crank, m_g2);

// ---- ClosePortfolio --------------------------------------------------------------------------
sub_cell!(acct_sub_close_a_market_wrong_program, fx_close, m_a);
sub_cell!(acct_sub_close_b_portfolio_wrong_program, fx_close, m_b);
sub_cell!(acct_sub_close_c_signer_missing, fx_close, m_c);
sub_cell!(acct_sub_close_d_market_readonly, fx_close, m_d);
sub_cell!(acct_sub_close_e_portfolio_readonly, fx_close, m_e);
sub_cell!(acct_sub_close_f_other_users_portfolio, fx_close, m_f);
sub_cell!(acct_sub_close_g1_fake_market, fx_close, m_g1);
sub_cell!(acct_sub_close_g2_portfolio_of_other_market, fx_close, m_g2);
sub_dup!(acct_sub_close_i_duplicate_accounts, fx_close, [(1, 2)]);

// ---- WithdrawInsurance -----------------------------------------------------------------------
sub_cell!(acct_sub_insurance_a_market_wrong_program, fx_withdraw_insurance, m_a);
sub_cell!(acct_sub_insurance_d_market_readonly, fx_withdraw_insurance, m_d);
sub_cell!(acct_sub_insurance_f_non_authority_signer, fx_withdraw_insurance, m_f);
sub_cell!(acct_sub_insurance_g1_fake_market, fx_withdraw_insurance, m_g1);
sub_cell!(acct_sub_insurance_h_wrong_vault_authority_pda, fx_withdraw_insurance, m_h);
sub_cell!(acct_sub_insurance_t_token_readonly, fx_withdraw_insurance, m_t);
sub_dup!(acct_sub_insurance_i_duplicate_accounts, fx_withdraw_insurance, [(2, 3)]);

// ---- WithdrawProtocolFee ---------------------------------------------------------------------
sub_cell!(acct_sub_protocol_fee_a_market_wrong_program, fx_withdraw_protocol_fee, m_a);
sub_cell!(acct_sub_protocol_fee_c_signer_missing, fx_withdraw_protocol_fee, m_c);
sub_cell!(acct_sub_protocol_fee_d_market_readonly, fx_withdraw_protocol_fee, m_d);
sub_cell!(acct_sub_protocol_fee_f_non_authority_signer, fx_withdraw_protocol_fee, m_f);
sub_cell!(acct_sub_protocol_fee_g1_fake_market, fx_withdraw_protocol_fee, m_g1);
sub_cell!(acct_sub_protocol_fee_h_wrong_vault_authority_pda, fx_withdraw_protocol_fee, m_h);
sub_cell!(acct_sub_protocol_fee_t_token_readonly, fx_withdraw_protocol_fee, m_t);
sub_dup!(acct_sub_protocol_fee_i_duplicate_accounts, fx_withdraw_protocol_fee, [(2, 3)]);

// ---- WithdrawCreatorFee ----------------------------------------------------------------------
sub_cell!(acct_sub_creator_fee_a_market_wrong_program, fx_withdraw_creator_fee, m_a);
sub_cell!(acct_sub_creator_fee_c_signer_missing, fx_withdraw_creator_fee, m_c);
sub_cell!(acct_sub_creator_fee_d_market_readonly, fx_withdraw_creator_fee, m_d);
sub_cell!(acct_sub_creator_fee_f_non_authority_signer, fx_withdraw_creator_fee, m_f);
sub_cell!(acct_sub_creator_fee_g1_fake_market, fx_withdraw_creator_fee, m_g1);
sub_cell!(acct_sub_creator_fee_h_wrong_vault_authority_pda, fx_withdraw_creator_fee, m_h);
sub_cell!(acct_sub_creator_fee_t_token_readonly, fx_withdraw_creator_fee, m_t);
sub_dup!(acct_sub_creator_fee_i_duplicate_accounts, fx_withdraw_creator_fee, [(2, 3)]);
