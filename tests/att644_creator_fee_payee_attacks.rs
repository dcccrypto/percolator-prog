//! prog#587 (2026-10-31): a first-loss (burned `asset_admin`) creator's fee reaches the payee
//! recorded before the burn, permissionlessly, and nobody can redirect it.
//!
//! Harness: copied from `p1_close_fees.rs` (real InitMarket / tag 85 / stake tag 19 Bind /
//! Deposit / fee-bearing TradeNoCpi / Withdraw / ClosePortfolio / ResolveMarket / tags 84, 87,
//! 90, 125, 65 / CloseSlab on the real wrapper BPF). The only byte-level fixture writes are the
//! same as there (crafted stake pool, mint supply) plus planted SPL token accounts (the payee's
//! ATA, attacker accounts) and, in the spoof test, a forged program-owned record.
//!
//! NEGATIVE CONTROLS (PR body): tests 1-6, 8, 9 fail on the rc23 wrapper (1adcb05b): tag 125 does not
//! exist there, and a burned asset's creator pot has no claim path. Test 7 pins UNCHANGED
//! behaviour (no payee => refused + re-booked), so it passes there by design; its control is a
//! mutant that stops the re-book. Every guard in the fix has its own mutant (PR body table).
mod common;

use common::{
    assemble_five_program_svm, assert_custom, make_mint_data, make_token_data, send_ixs,
    spl_token_classic_id, PERCOLATOR_MAINNET, STAKE_ID,
};
use percolator_prog::ix::Instruction as ProgInstruction;
use percolator_prog::state;
use solana_program::instruction::{AccountMeta, Instruction};
use solana_sdk::transaction::TransactionError;
use solana_sdk::{account::Account, pubkey::Pubkey, signature::Keypair, signer::Signer};
use spl_token::solana_program::program_pack::Pack;
use spl_token::state::{Account as TokenAccount, Mint};

const MAX_ASSETS: u16 = 2;
const POS_SCALE: i128 = 1_000_000;
const SIZE_Q: i128 = POS_SCALE * 100_000;
const PRICE: u64 = 100;
const FEE_BPS: u64 = 500;
const DEPOSIT: u128 = 30_000_000_000;
const MINT_SUPPLY: u64 = 1_000_000_000_000_000;

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

/// v4 StakePool (408 B) -- copied from `v16_fee_split.rs::craft_stake_pool_v4`.
#[allow(clippy::too_many_arguments)]
fn craft_stake_pool_v4(
    market: &Pubkey,
    admin: &Pubkey,
    collateral_mint: &Pubkey,
    lp_mint: &Pubkey,
    stake_vault: &Pubkey,
    total_lp_supply: u64,
    percolator_program: &Pubkey,
    vault_authority_bump: u8,
) -> Vec<u8> {
    let mut d = vec![0u8; 480]; // v5 (Phase 4 item 6): 408 -> 480
    d[0] = 1;
    d[1] = 255;
    d[2] = vault_authority_bump;
    d[8..40].copy_from_slice(market.as_ref());
    d[40..72].copy_from_slice(admin.as_ref());
    d[72..104].copy_from_slice(collateral_mint.as_ref());
    d[104..136].copy_from_slice(lp_mint.as_ref());
    d[136..168].copy_from_slice(stake_vault.as_ref());
    d[176..184].copy_from_slice(&total_lp_supply.to_le_bytes());
    d[224..256].copy_from_slice(percolator_program.as_ref());
    d[320..328].copy_from_slice(b"SPOOL_V1");
    d[328] = 5; // CURRENT_VERSION (v5)
    d[408] = 1; // v5 risk_mode = FIRST_LOSS (tag 87 pays first-loss pools only)
    d
}

struct Env {
    svm: litesvm::LiteSVM,
    payer: Keypair,
    admin: Keypair,
    fee_auth: Keypair,
    market: Pubkey,
    market_kp: Keypair, // D26: InitMarket requires the market account's signature
    mint: Pubkey,
    vault: Pubkey,
    vault_authority: Pubkey,
    pool_pda: Pubkey,
    stake_vault: Pubkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Legs {
    protocol_accrued: u128,
    protocol_withdrawn: u128,
    lp_accrued: u128,
    lp_withdrawn: u128,
    ins_accrued: u128,
    ins_withdrawn: u128,
    creator_cfg: u64,
    creator_asset0: u64,
}

impl Legs {
    fn creator_owed(&self) -> u128 {
        self.creator_cfg as u128 + self.creator_asset0 as u128
    }
    fn total_accrued(&self) -> u128 {
        self.protocol_accrued + self.lp_accrued + self.ins_accrued + self.creator_owed()
    }
}

impl Env {
    fn new() -> Self {
        Self::build(true, false)
    }

    /// `bind`: run the real stake tag-19 Bind (else asset 0's `insurance_authority` stays the
    /// creator's key, i.e. UNBOUND). `burn_asset_admin`: burn asset 0's `asset_admin` via the
    /// real tag 65 after the bind, so the creator pot has no signer left.
    fn build(bind: bool, burn_asset_admin: bool) -> Self {
        let mut svm = assemble_five_program_svm(Pubkey::new_unique());
        let payer = Keypair::new();
        let admin = Keypair::new();
        let fee_auth = Keypair::new();
        let market_kp = Keypair::new(); // D26: InitMarket requires the market account's signature
        let market = market_kp.pubkey();
        let mint = Pubkey::new_unique();
        let (vault_authority, _) =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &PERCOLATOR_MAINNET);
        let vault = canonical_vault_ata(&vault_authority, &mint);
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&fee_auth.pubkey(), 1_000_000_000).unwrap();

        // Placeholder mint with a large tracked supply so an SPL Burn (the F4 bug
        // path) is observable as a supply decrease instead of an underflow.
        let mut mint_data = make_mint_data();
        {
            let mut m = Mint::unpack(&mint_data).unwrap();
            m.supply = MINT_SUPPLY;
            Mint::pack(m, &mut mint_data).unwrap();
        }
        let mut env = Env {
            svm,
            payer,
            admin,
            fee_auth,
            market,
            market_kp,
            mint,
            vault,
            vault_authority,
            pool_pda: Pubkey::default(),
            stake_vault: Pubkey::default(),
        };
        env.plant(mint, mint_data, spl_token_classic_id());
        env.plant(
            vault,
            make_token_data(mint, vault_authority, 0),
            spl_token_classic_id(),
        );
        let market_len = state::market_account_len_for_capacity(MAX_ASSETS as usize).unwrap();
        env.plant(market, vec![0u8; market_len], PERCOLATOR_MAINNET);
        env.init_market();
        env.set_protocol_fee_authority_via_tag85();
        env.setup_stake_pool(bind);
        if burn_asset_admin {
            env.burn_asset_admin();
        }
        env
    }

    /// Real tag 65 `UpdateAssetAuthority { kind: ASSET_AUTH_ADMIN, new_pubkey: 0 }`.
    fn burn_asset_admin(&mut self) {
        let admin = self.admin.insecure_clone();
        let authority_epoch = self.authority_epoch(0);
        self.send(
            ProgInstruction::UpdateAssetAuthority {
                market_id: 1,
                asset_index: 0,
                kind: 0,
                new_pubkey: [0u8; 32],
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("burn asset 0 asset_admin (tag 65)");
        assert_eq!(self.asset0_profile().asset_admin, [0u8; 32]);
    }

    fn asset0_profile(&self) -> state::AssetOracleProfileV16 {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        let n = core::mem::size_of::<state::AssetOracleProfileV16>();
        bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n])
    }

    fn plant(&mut self, key: Pubkey, data: Vec<u8>, owner: Pubkey) {
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }

    fn new_token_account(&mut self, owner: Pubkey, amount: u64) -> Pubkey {
        let k = Pubkey::new_unique();
        self.plant(
            k,
            make_token_data(self.mint, owner, amount),
            spl_token_classic_id(),
        );
        k
    }

    fn send(
        &mut self,
        ix_data: Vec<u8>,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: PERCOLATOR_MAINNET,
            accounts,
            data: ix_data,
        };
        send_ixs(&mut self.svm, &payer, vec![ix], signers)
    }

    fn authority_epoch(&self, asset: usize) -> u64 {
        state::read_asset_control_sequences(
            &self.svm.get_account(&self.market).unwrap().data,
            asset,
        )
        .unwrap()
        .authority_epoch
    }

    fn init_market(&mut self) {
        let admin = self.admin.insecure_clone();
        self.send(
            ProgInstruction::InitMarket {
                max_portfolio_assets: MAX_ASSETS,
                h_min: 0,
                h_max: 10,
                initial_price: PRICE,
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
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, true),
                AccountMeta::new_readonly(self.mint, false),
            ],
            &[&admin, &self.market_kp.insecure_clone()],
        )
        .expect("InitMarket");
    }

    /// Real tag 85. `InitMarket` hardcodes `PROTOCOL_FEE_AUTHORITY_DEFAULT`, whose key
    /// the test does not hold; rotate it to `fee_auth` through the real upgrade-authority
    /// gate, with a ProgramData account matching `read_program_data_upgrade_authority`.
    fn set_protocol_fee_authority_via_tag85(&mut self) {
        let admin = self.admin.insecure_clone();
        let (program_data_key, _) = Pubkey::find_program_address(
            &[PERCOLATOR_MAINNET.as_ref()],
            &solana_sdk::bpf_loader_upgradeable::id(),
        );
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(admin.pubkey().as_ref());
        self.plant(
            program_data_key,
            pd,
            solana_sdk::bpf_loader_upgradeable::id(),
        );
        self.send(
            ProgInstruction::SetProtocolFeeAuthority {
                new_authority: self.fee_auth.pubkey().to_bytes(),
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(program_data_key, false),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("SetProtocolFeeAuthority (tag 85)");
        let data = self.svm.get_account(&self.market).unwrap().data;
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&data).unwrap();
        assert_eq!(
            cfg.protocol_fee_authority,
            self.fee_auth.pubkey().to_bytes()
        );
    }

    /// Crafted v4 pool + (optionally) REAL stake tag 19 Bind (same as `v16_fee_split.rs`).
    /// `asset_admin` is NOT burned here: tag 90 is gated on it.
    fn setup_stake_pool(&mut self, bind: bool) {
        let (pool_pda, _) =
            Pubkey::find_program_address(&[b"stake_pool", self.market.as_ref()], &STAKE_ID);
        let (vault_auth, vault_auth_bump) =
            Pubkey::find_program_address(&[b"vault_auth", pool_pda.as_ref()], &STAKE_ID);
        let stake_vault = self.new_token_account(vault_auth, 0);
        let pool_bytes = craft_stake_pool_v4(
            &self.market,
            &self.admin.pubkey(),
            &self.mint,
            &Pubkey::new_unique(),
            &stake_vault,
            1_000,
            &PERCOLATOR_MAINNET,
            vault_auth_bump,
        );
        self.plant(pool_pda, pool_bytes, STAKE_ID);
        self.pool_pda = pool_pda;
        self.stake_vault = stake_vault;
        if !bind {
            assert_eq!(
                self.asset0_profile().insurance_authority,
                self.admin.pubkey().to_bytes()
            );
            return;
        }
        let admin = self.admin.insecure_clone();
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: STAKE_ID,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(pool_pda, false), // stake 0f88ff1+: a v5 bind records the seed, pool must be writable
                AccountMeta::new_readonly(vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(PERCOLATOR_MAINNET, false),
            ],
            data: vec![19u8],
        };
        // Stake 0f88ff1+ binds single-asset markets only (M-1b, error 48). This fixture needs two asset
        // slots (asset 1 carries a creator pot), so present max_market_slots = 1 for the bind only.
        self.poke_max_market_slots(1);
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect("stake Bind (tag 19)");
        self.poke_max_market_slots(MAX_ASSETS as u32);
        assert_eq!(
            self.asset0_profile().insurance_authority,
            vault_auth.to_bytes()
        );
    }

    fn market_closed(&self) -> bool {
        self.svm.get_account(&self.market).unwrap().data.len()
            == percolator_prog::constants::HEADER_LEN
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let portfolio_kp = Keypair::new(); // D26: InitPortfolio requires the portfolio account's signature
        let portfolio = portfolio_kp.pubkey();
        let len = state::portfolio_account_len_for_market_slots(MAX_ASSETS as usize).unwrap();
        self.plant(portfolio, vec![0u8; len], PERCOLATOR_MAINNET);
        self.send(
            ProgInstruction::InitPortfolio.encode(),
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, true),
            ],
            &[owner, &portfolio_kp],
        )
        .expect("InitPortfolio");
        portfolio
    }

    fn identity(&self, portfolio: Pubkey) -> (u64, u64, u64) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        (
            state::read_portfolio_id(&data).unwrap(),
            state::read_portfolio_matcher_sequence(&data).unwrap(),
            state::read_portfolio_position_epoch(&data).unwrap(),
        )
    }

    fn capital_and_pnl(&self, portfolio: Pubkey) -> (u128, i128) {
        let data = self.svm.get_account(&portfolio).unwrap().data;
        let p = state::read_portfolio_boxed_for_market_slots(&data, MAX_ASSETS as usize).unwrap();
        (p.capital, p.pnl)
    }

    fn deposit(&mut self, owner: &Keypair, portfolio: Pubkey, amount: u128) {
        let source = self.new_token_account(owner.pubkey(), amount as u64);
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        self.send(
            ProgInstruction::Deposit {
                portfolio_id,
                expected_sequence,
                amount,
            }
            .encode(),
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(source, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[owner],
        )
        .expect("Deposit");
    }

    #[allow(clippy::too_many_arguments)]
    fn trade(&mut self, owner_a: &Keypair, a: Pubkey, owner_b: &Keypair, b: Pubkey, size_q: i128) {
        let (a_id, _, a_epoch) = self.identity(a);
        let (b_id, _, b_epoch) = self.identity(b);
        self.send(
            ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id: 1,
                asset_index: 0,
                size_q,
                exec_price: PRICE,
                fee_bps: FEE_BPS,
                backing_fee_cap_bps: 10_000,
            }
            .encode(),
            vec![
                AccountMeta::new(owner_a.pubkey(), true),
                AccountMeta::new(owner_b.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(a, false),
                AccountMeta::new(b, false),
            ],
            &[owner_a, owner_b],
        )
        .expect("fee-bearing TradeNoCpi");
    }

    /// Withdraw the portfolio's entire capital; returns the amount withdrawn.
    fn withdraw_all(&mut self, owner: &Keypair, portfolio: Pubkey) -> u128 {
        let (capital, pnl) = self.capital_and_pnl(portfolio);
        assert_eq!(pnl, 0, "flat at the entry price: no pnl to settle");
        let dest = self.new_token_account(owner.pubkey(), 0);
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        self.send(
            ProgInstruction::Withdraw {
                portfolio_id,
                expected_sequence,
                amount: capital,
            }
            .encode(),
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[owner],
        )
        .expect("Withdraw");
        assert_eq!(self.token_amount(dest) as u128, capital);
        capital
    }

    fn close_portfolio(&mut self, owner: &Keypair, portfolio: Pubkey) {
        let (portfolio_id, expected_sequence, position_epoch) = self.identity(portfolio);
        self.send(
            ProgInstruction::ClosePortfolio {
                portfolio_id,
                expected_sequence,
                position_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        )
        .expect("ClosePortfolio");
    }

    fn resolve(&mut self) {
        let admin = self.admin.insecure_clone();
        let authority_epoch = self.authority_epoch(0);
        let asset_generation_frontier = state::read_asset_generation_frontier(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
        self.send(
            ProgInstruction::ResolveMarket {
                asset_generation_frontier,
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
        .expect("ResolveMarket");
        let (mode, _, _) = self.header_mode_ctot_count();
        assert_eq!(mode, 1, "market must actually be Resolved");
    }

    fn withdraw_protocol_fee(&mut self) -> Result<Pubkey, TransactionError> {
        let fee_auth = self.fee_auth.insecure_clone();
        let dest = self.new_token_account(fee_auth.pubkey(), 0);
        let authority_epoch = state::read_protocol_fee_authority_epoch(
            &self.svm.get_account(&self.market).unwrap().data,
        )
        .unwrap();
        self.send(
            ProgInstruction::WithdrawProtocolFee {
                amount: 0,
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(fee_auth.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[&fee_auth],
        )
        .map(|_| dest)
    }

    fn withdraw_creator_fee(&mut self, amount: u128) -> Result<Pubkey, TransactionError> {
        let admin = self.admin.insecure_clone();
        let dest = self.new_token_account(admin.pubkey(), 0);
        let authority_epoch = self.authority_epoch(0);
        self.send(
            ProgInstruction::WithdrawCreatorFee {
                amount,
                asset_index: 0,
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[&admin],
        )
        .map(|_| dest)
    }

    fn withdraw_to_stake(&mut self) -> Result<(), TransactionError> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
        self.send(
            ProgInstruction::WithdrawInsuranceReserveToStake.encode(),
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.pool_pda, false),
                AccountMeta::new(self.stake_vault, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[&cranker],
        )
    }

    /// CloseSlab with the primary mint at index 6 so the unbudgeted-residue burn CAN run
    /// (that is the F4 bug path). Returns the admin's sweep destination.
    fn close_slab(&mut self) -> (Result<(), TransactionError>, Pubkey) {
        let admin = self.admin.insecure_clone();
        let dest = self.new_token_account(admin.pubkey(), 0);
        let authority_epoch = self.authority_epoch(0);
        let res = self.send(
            ProgInstruction::CloseSlab { authority_epoch }.encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
                AccountMeta::new(self.mint, false),
            ],
            &[&admin],
        );
        (res, dest)
    }

    fn token_amount(&self, key: Pubkey) -> u64 {
        TokenAccount::unpack(&self.svm.get_account(&key).unwrap().data)
            .unwrap()
            .amount
    }

    /// SPL balance, or `None` when the token account was closed.
    fn token_amount_opt(&self, key: Pubkey) -> Option<u64> {
        let acct = self.svm.get_account(&key)?;
        if acct.data.len() < TokenAccount::LEN || acct.lamports == 0 {
            return None;
        }
        TokenAccount::unpack(&acct.data).ok().map(|a| a.amount)
    }

    fn mint_supply(&self) -> u64 {
        Mint::unpack(&self.svm.get_account(&self.mint).unwrap().data)
            .unwrap()
            .supply
    }

    fn legs(&self) -> Legs {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (cfg, _, _, _) = state::read_market_config_mode_and_capacity(&data).unwrap();
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        let n = core::mem::size_of::<state::AssetOracleProfileV16>();
        let p0: state::AssetOracleProfileV16 =
            bytemuck::pod_read_unaligned(&group.markets[0].wrapper[..n]);
        let p1: state::AssetOracleProfileV16 =
            bytemuck::pod_read_unaligned(&group.markets[1].wrapper[..n]);
        assert_eq!(p1.creator_fee_claimable_atoms, 0, "asset 1 never traded");
        Legs {
            protocol_accrued: cfg.protocol_fee_accrued_atoms,
            protocol_withdrawn: cfg.protocol_fee_withdrawn_atoms,
            lp_accrued: cfg.lp_fee_accrued_atoms,
            lp_withdrawn: cfg.lp_fee_withdrawn_atoms,
            ins_accrued: cfg.insurance_reserve_accrued_atoms,
            ins_withdrawn: cfg.insurance_reserve_withdrawn_atoms,
            creator_cfg: cfg.creator_fee_claimable_atoms,
            creator_asset0: p0.creator_fee_claimable_atoms,
        }
    }

    fn header_mode_ctot_count(&self) -> (u8, u128, u64) {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        (
            group.header.mode,
            group.header.c_tot.get(),
            group.header.materialized_portfolio_count.get(),
        )
    }

    fn header_insurance_vault(&self) -> (u128, u128) {
        let mut data = self.svm.get_account(&self.market).unwrap().data;
        let (_, group) = state::market_view_mut(&mut data).unwrap();
        (group.header.insurance.get(), group.header.vault.get())
    }
}

/// Two traders, one open + one close fee-bearing trade (taker pays 500 bps on 10M
/// notional each time), both flat at the entry price. Returns
/// (env, taker, taker_pf, maker, maker_pf, fees_charged) where `fees_charged` is
/// measured from the traders' side: total deposited minus total withdrawable capital.
fn traded_flat_market() -> (Env, Keypair, Pubkey, Keypair, Pubkey, u128) {
    traded_flat_market_in(Env::new())
}

fn traded_flat_market_in(mut env: Env) -> (Env, Keypair, Pubkey, Keypair, Pubkey, u128) {
    let taker = Keypair::new();
    let maker = Keypair::new();
    let taker_pf = env.create_portfolio(&taker);
    let maker_pf = env.create_portfolio(&maker);
    env.deposit(&taker, taker_pf, DEPOSIT);
    env.deposit(&maker, maker_pf, DEPOSIT);
    env.trade(&taker, taker_pf, &maker, maker_pf, SIZE_Q);
    env.trade(&taker, taker_pf, &maker, maker_pf, -SIZE_Q);
    let (tc, _) = env.capital_and_pnl(taker_pf);
    let (mc, _) = env.capital_and_pnl(maker_pf);
    let fees_charged = 2 * DEPOSIT - tc - mc;
    assert!(fees_charged > 0, "the trades must have charged a real fee");
    let legs = env.legs();
    assert_eq!(
        legs.total_accrued(),
        fees_charged,
        "every charged atom must be booked to exactly one of the four legs"
    );
    assert!(legs.protocol_accrued > 0 && legs.lp_accrued > 0 && legs.ins_accrued > 0);
    assert!(legs.creator_owed() > 0, "default split pays the creator");
    (env, taker, taker_pf, maker, maker_pf, fees_charged)
}

/// Terminal-empty: both portfolios withdrawn + closed, then ResolveMarket.
fn terminal_empty_market_with_fees() -> (Env, u128) {
    terminal_empty_market_with_fees_in(Env::new())
}

fn terminal_empty_market_with_fees_in(env: Env) -> (Env, u128) {
    let (mut env, taker, taker_pf, maker, maker_pf, fees) = traded_flat_market_in(env);
    env.withdraw_all(&taker, taker_pf);
    env.withdraw_all(&maker, maker_pf);
    env.close_portfolio(&taker, taker_pf);
    env.close_portfolio(&maker, maker_pf);
    env.resolve();
    let (mode, c_tot, count) = env.header_mode_ctot_count();
    assert_eq!((mode, c_tot, count), (1, 0, 0), "terminal-empty Resolved");
    assert_eq!(
        env.token_amount(env.vault) as u128,
        fees,
        "after every trader left, the vault holds exactly the fee legs"
    );
    (env, fees)
}

// ─────────────────────────────────────────────────────────────────────────────
// prog#587 helpers
// ─────────────────────────────────────────────────────────────────────────────
const UNAUTHORIZED: u32 = 8;
const OVER_CLAIM: u32 = 62;
const FEES_OUTSTANDING: u32 = 71;
const PAYEE_INVALID: u32 = 136;
const ENGINE_STALE: u32 = 19;

/// A genuine on-chain refusal (an InstructionError from the program), never a harness error.
fn refused(res: Result<(), TransactionError>, label: &str) -> u32 {
    match res {
        Err(TransactionError::InstructionError(_, e)) => {
            println!("{label}: refused with {e:?}");
            match e {
                solana_program::instruction::InstructionError::Custom(c) => c,
                _ => u32::MAX,
            }
        }
        other => panic!("{label}: expected a program refusal, got {other:?}"),
    }
}

fn payee_pda(market: &Pubkey, asset_index: u16) -> Pubkey {
    state::derive_creator_fee_payee(&PERCOLATOR_MAINNET, market, asset_index).0
}

impl Env {
    /// Tag 125 signed by `signer`, with an explicit epoch (so a stale replay can be built).
    fn set_payee_as(
        &mut self,
        signer: &Keypair,
        asset_index: u16,
        payee: Pubkey,
        authority_epoch: u64,
    ) -> Result<(), TransactionError> {
        self.fund(&signer.pubkey());
        let pda = payee_pda(&self.market, asset_index);
        let market_id = self.generation(asset_index);
        self.send(
            ProgInstruction::SetCreatorFeePayee {
                asset_index,
                market_id,
                payee: payee.to_bytes(),
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            &[signer],
        )
    }

    /// The asset slot's LIVE generation (`market_id`), as tag 125 binds it.
    fn generation(&self, asset_index: u16) -> u64 {
        state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            false,
        )
        .unwrap()
        .0
    }

    fn fund(&mut self, k: &Pubkey) {
        if self.svm.get_balance(k).unwrap_or(0) == 0 {
            self.svm.airdrop(k, 1_000_000_000).unwrap();
        }
    }

    fn set_payee(&mut self, payee: Pubkey) {
        let admin = self.admin.insecure_clone();
        let e = self.authority_epoch(0);
        self.set_payee_as(&admin, 0, payee, e).expect("tag 125 by the live asset_admin");
        assert_eq!(self.authority_epoch(0), e + 1, "tag 125 advances the epoch lane");
    }

    /// The payee's canonical ATA for the collateral mint (planted empty).
    fn plant_ata(&mut self, owner: Pubkey) -> Pubkey {
        let ata = canonical_vault_ata(&owner, &self.mint);
        self.plant(ata, make_token_data(self.mint, owner, 0), spl_token_classic_id());
        ata
    }

    /// Tag 90 sent by `caller` (any key), paying `dest`, with `payee_acct` at `[6]` if given.
    fn claim_as(
        &mut self,
        caller: &Keypair,
        amount: u128,
        dest: Pubkey,
        payee_acct: Option<Pubkey>,
    ) -> Result<(), TransactionError> {
        self.fund(&caller.pubkey());
        let authority_epoch = self.authority_epoch(0);
        let mut metas = vec![
            AccountMeta::new(caller.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(self.vault, false),
            AccountMeta::new_readonly(self.vault_authority, false),
            AccountMeta::new_readonly(spl_token_classic_id(), false),
        ];
        if let Some(p) = payee_acct {
            metas.push(AccountMeta::new_readonly(p, false));
        }
        self.send(
            ProgInstruction::WithdrawCreatorFee {
                amount,
                asset_index: 0,
                authority_epoch,
            }
            .encode(),
            metas,
            &[caller],
        )
    }

    fn p4_flags0(&self) -> u8 {
        self.asset0_profile()._padding0[percolator_prog::constants::PROFILE_P4_FLAGS_IDX]
    }
}

/// bind + payee recorded by the live admin + burn (the seeded first-loss sequence).
fn first_loss_env(payee: Pubkey) -> Env {
    let mut env = Env::build(true, false);
    env.set_payee(payee);
    assert_ne!(env.p4_flags0() & percolator_prog::constants::P4_FLAG_CREATOR_FEE_PAYEE, 0);
    env.burn_asset_admin();
    env
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. A first-loss (burned) market's creator fee reaches the recorded payee; anyone can crank it.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_burned_market_creator_fee_reaches_recorded_payee_permissionlessly() {
    let payee = Pubkey::new_unique();
    let (mut env, _taker, _tpf, _maker, _mpf, fees) = traded_flat_market_in(first_loss_env(payee));
    let legs0 = env.legs();
    let owed = legs0.creator_owed();
    assert!(owed > 0);
    let ata = env.plant_ata(payee);
    let vault0 = env.token_amount(env.vault);
    let pda = payee_pda(&env.market, 0);

    // Over-claim refused, nothing moves.
    let cranker = Keypair::new();
    assert_custom(env.claim_as(&cranker, owed + 1, ata, Some(pda)), OVER_CLAIM, "over-claim");
    assert_eq!(env.legs(), legs0);

    // A stranger pays the payee in two parts (exact debit each time).
    let half = owed / 2;
    env.claim_as(&cranker, half, ata, Some(pda)).expect("permissionless tag 90, part 1");
    let other = Keypair::new();
    env.claim_as(&other, owed - half, ata, Some(pda)).expect("permissionless tag 90, part 2");
    assert_eq!(env.token_amount(ata) as u128, owed, "the payee received the whole creator leg");
    assert_eq!((vault0 - env.token_amount(env.vault)) as u128, owed, "vault paid exactly that");

    // Conservation of the split: only the creator leg moved; the other three are untouched.
    let legs1 = env.legs();
    assert_eq!(legs1.creator_owed(), 0);
    assert_eq!(
        (legs1.protocol_accrued, legs1.protocol_withdrawn, legs1.lp_accrued, legs1.lp_withdrawn,
         legs1.ins_accrued, legs1.ins_withdrawn),
        (legs0.protocol_accrued, legs0.protocol_withdrawn, legs0.lp_accrued, legs0.lp_withdrawn,
         legs0.ins_accrued, legs0.ins_withdrawn),
    );
    assert_eq!(legs0.total_accrued(), fees, "every fee atom booked to one leg");
    // A further claim has nothing left.
    assert_custom(env.claim_as(&cranker, 1, ata, Some(pda)), OVER_CLAIM, "drained");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Nobody can redirect it.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_nobody_can_redirect_a_burned_creator_fee() {
    let payee = Pubkey::new_unique();
    let (mut env, ..) = traded_flat_market_in(first_loss_env(payee));
    let owed = env.legs().creator_owed();
    let legs0 = env.legs();
    let ata = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    let attacker = Keypair::new();
    let admin = env.admin.insecure_clone();

    // (a) a token account the payee owns but which is not its canonical ATA.
    let side = env.new_token_account(payee, 0);
    assert_custom(env.claim_as(&attacker, owed, side, Some(pda)), PAYEE_INVALID, "non-ATA dest");
    // (b) the attacker's own ATA.
    let atk_ata = env.plant_ata(attacker.pubkey());
    refused(env.claim_as(&attacker, owed, atk_ata, Some(pda)), "attacker ATA");
    // (c) the ex-admin (also marketauth here) to its own account: old signed route is gone.
    let adm_dest = env.new_token_account(admin.pubkey(), 0);
    refused(env.claim_as(&admin, owed, adm_dest, Some(pda)), "ex-admin own account");
    // (d) no payee account at all.
    refused(env.claim_as(&attacker, owed, ata, None), "missing [6]");
    // (e) a forged program-owned kind-19 record at a non-PDA address naming the attacker.
    let forged = Pubkey::new_unique();
    let mut rec = env.svm.get_account(&pda).unwrap();
    rec.data[percolator_prog::constants::HEADER_LEN + 32..percolator_prog::constants::HEADER_LEN + 64]
        .copy_from_slice(attacker.pubkey().as_ref());
    env.svm.set_account(forged, rec).unwrap();
    assert_custom(env.claim_as(&attacker, owed, atk_ata, Some(forged)), PAYEE_INVALID, "forged record");
    // (f) the PDA of ANOTHER asset index (never recorded) / a system account at the right PDA.
    let other_pda = payee_pda(&env.market, 1);
    assert_custom(env.claim_as(&attacker, owed, ata, Some(other_pda)), PAYEE_INVALID, "asset-1 PDA");
    // (g) an encumbered payee ATA (delegate set): refused like every permissionless payout (W5).
    {
        let mut a = env.svm.get_account(&ata).unwrap();
        let mut t = TokenAccount::unpack(&a.data).unwrap();
        t.delegate = solana_program::program_option::COption::Some(attacker.pubkey());
        t.delegated_amount = u64::MAX;
        TokenAccount::pack(t, &mut a.data).unwrap();
        env.svm.set_account(ata, a.clone()).unwrap();
        refused(env.claim_as(&attacker, owed, ata, Some(pda)), "delegated ATA");
        let mut t = TokenAccount::unpack(&a.data).unwrap();
        t.delegate = solana_program::program_option::COption::None;
        t.delegated_amount = 0;
        TokenAccount::pack(t, &mut a.data).unwrap();
        env.svm.set_account(ata, a).unwrap();
    }
    // (h) after the burn nobody can re-point the payee: not the ex-admin, not the attacker.
    let e = env.authority_epoch(0);
    assert_custom(env.set_payee_as(&admin, 0, attacker.pubkey(), e), PAYEE_INVALID, "ex-admin re-point");
    assert_custom(env.set_payee_as(&attacker, 0, attacker.pubkey(), e), PAYEE_INVALID, "attacker re-point");
    // (i) nor can the burned admin be revived to do it (tag 65 has no admin to sign).
    let revive = env
        .send(
            ProgInstruction::UpdateAssetAuthority {
                market_id: 1,
                asset_index: 0,
                kind: 0,
                new_pubkey: attacker.pubkey().to_bytes(),
                authority_epoch: e,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new_readonly(attacker.pubkey(), true),
                AccountMeta::new(env.market, false),
            ],
            &[&admin, &attacker],
        );
    refused(revive, "revive burned admin (tag 65)");

    // Nothing moved through any of that; the real payee still gets all of it.
    assert_eq!(env.legs(), legs0);
    assert_eq!(env.token_amount(atk_ata), 0);
    env.claim_as(&attacker, owed, ata, Some(pda)).expect("anyone may pay the real payee");
    assert_eq!(env.token_amount(ata) as u128, owed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Non-burned markets are unchanged: a live admin keeps the signed route, even with a payee.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_live_admin_market_unchanged_payee_route_inactive() {
    let payee = Pubkey::new_unique();
    let mut e = Env::build(true, false);
    e.set_payee(payee);
    let (mut env, ..) = traded_flat_market_in(e);
    let owed = env.legs().creator_owed();
    let ata = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    let stranger = Keypair::new();
    assert_custom(
        env.claim_as(&stranger, owed, ata, Some(pda)),
        UNAUTHORIZED,
        "admin live: no permissionless route",
    );
    // The admin claims to any account it owns, exactly as before #587.
    let dest = env.withdraw_creator_fee(owed).expect("admin-signed tag 90");
    assert_eq!(env.token_amount(dest) as u128, owed);
    assert_eq!(env.token_amount(ata), 0);
    // And a market that never set a payee behaves as before too: burned => refused.
    let (mut env2, ..) = traded_flat_market_in(Env::build(true, true));
    let owed2 = env2.legs().creator_owed();
    let ata2 = env2.plant_ata(payee);
    let pda2 = payee_pda(&env2.market, 0);
    assert_custom(env2.claim_as(&stranger, owed2, ata2, Some(pda2)), UNAUTHORIZED, "no payee recorded");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Payee rotation before the burn: admin-only, epoch-bound, no-op refused; last one wins.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_payee_rotation_before_burn_is_admin_only_and_replay_safe() {
    let p1 = Pubkey::new_unique();
    let p2 = Pubkey::new_unique();
    let mut env = Env::build(true, false);
    let admin = env.admin.insecure_clone();
    let e0 = env.authority_epoch(0);
    env.set_payee(p1);
    let stranger = Keypair::new();
    assert_custom(env.set_payee_as(&stranger, 0, p2, e0 + 1), PAYEE_INVALID, "stranger");
    assert_custom(env.set_payee_as(&admin, 0, p1, e0 + 1), PAYEE_INVALID, "no-op");
    env.set_payee(p2);
    // A held "set p1" signed against the old epoch cannot replay over p2.
    assert_custom(env.set_payee_as(&admin, 0, p1, e0), ENGINE_STALE, "stale epoch replay");
    env.burn_asset_admin();
    let (mut env, ..) = traded_flat_market_in(env);
    let owed = env.legs().creator_owed();
    let pda = payee_pda(&env.market, 0);
    let a1 = env.plant_ata(p1);
    let a2 = env.plant_ata(p2);
    refused(env.claim_as(&stranger, owed, a1, Some(pda)), "old payee");
    env.claim_as(&stranger, owed, a2, Some(pda)).expect("current payee");
    assert_eq!(env.token_amount(a2) as u128, owed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Resolve / close: the pot is NOT re-booked to the protocol; close waits for the payout.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_resolve_close_path_pays_payee_not_protocol() {
    let payee = Pubkey::new_unique();
    let (mut env, fees) = terminal_empty_market_with_fees_in(first_loss_env(payee));
    let legs0 = env.legs();
    let creator_owed = legs0.creator_owed();
    assert!(creator_owed > 0);
    let supply0 = env.mint_supply();

    // The re-book step runs (LP -> staker) but leaves the payee-backed creator pot alone.
    let (res, _) = env.close_slab();
    res.expect("CloseSlab re-book step");
    let legs1 = env.legs();
    assert_eq!(legs1.creator_owed(), creator_owed, "creator pot NOT re-booked");
    assert_eq!(legs1.protocol_accrued, legs0.protocol_accrued, "protocol did not take it");

    // Protocol + stake legs claimed; close still refuses while the creator leg is owed.
    let d = env.withdraw_protocol_fee().expect("tag 84");
    let protocol_claimed = env.token_amount(d) as u128;
    let stake_before = env.token_amount(env.stake_vault);
    env.withdraw_to_stake().expect("tag 87 terminal");
    let stake_received = (env.token_amount(env.stake_vault) - stake_before) as u128;
    let (res, _) = env.close_slab();
    assert_custom(res, FEES_OUTSTANDING, "creator leg still owed");

    // Anyone pays the payee while Resolved; then the market closes, burning nothing.
    let ata = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    env.claim_as(&Keypair::new(), creator_owed, ata, Some(pda)).expect("resolved payout");
    assert_eq!(env.token_amount(ata) as u128, creator_owed);
    let (res, _) = env.close_slab();
    res.expect("CloseSlab after every leg claimed");
    assert!(env.market_closed());
    assert_eq!(env.mint_supply(), supply0, "nothing burned");
    assert_eq!(fees, protocol_claimed + stake_received + creator_owed, "conservation to the atom");
}
impl Env {
    /// Copied from `p1_close_fees.rs` (stake Bind is single-asset only; see `setup_stake_pool`).
    fn poke_max_market_slots(&mut self, n: u32) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, group) = state::market_view_mut(&mut acct.data).unwrap();
            group.header.config.max_market_slots = percolator::V16PodU32::new(n);
        }
        self.svm.set_account(self.market, acct).unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// prog#587 helpers for the lifecycle / rebuild tests
// ─────────────────────────────────────────────────────────────────────────────
const GENERATION_MISMATCH: u32 = 65;

impl Env {
    /// `send`, but prints the program log on a refusal (diagnosis of lifecycle preconditions).
    fn send_logged(
        &mut self,
        ix_data: Vec<u8>,
        accounts: Vec<AccountMeta>,
        signers: &[&Keypair],
    ) -> Result<(), TransactionError> {
        let payer = self.payer.insecure_clone();
        self.svm.expire_blockhash();
        let ix = Instruction { program_id: PERCOLATOR_MAINNET, accounts, data: ix_data };
        let mut all_signers = vec![&payer];
        all_signers.extend_from_slice(signers);
        let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[common::heap_ix(), common::cu_ix(), ix],
            Some(&payer.pubkey()),
            &all_signers,
            self.svm.latest_blockhash(),
        );
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| {
            for l in &e.meta.logs {
                println!("  log: {l}");
            }
            e.err
        })
    }

    fn clock_slot(&self) -> u64 {
        self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    fn profile(&self, asset_index: usize) -> state::AssetOracleProfileV16 {
        state::read_asset_oracle_profile(&self.svm.get_account(&self.market).unwrap().data, asset_index)
            .unwrap()
    }

    fn payee_bit(&self, asset_index: usize) -> bool {
        state::profile_has_creator_fee_payee(&self.profile(asset_index))
    }

    /// Real tag 40 signed by `marketauth` (= `admin` here). ACTIVATE binds the generation
    /// frontier, every other action the slot's live `market_id`; the epoch is asset 0's lane.
    fn lifecycle(&mut self, action: u8, asset_index: u16) -> Result<(), TransactionError> {
        let admin = self.admin.insecure_clone();
        let activation = action == percolator_prog::processor::ASSET_ACTION_ACTIVATE;
        let (current, next) = state::read_asset_lifecycle_generation_preflight(
            &self.svm.get_account(&self.market).unwrap().data,
            asset_index as usize,
            activation,
        )
        .unwrap();
        let a = admin.pubkey().to_bytes();
        let (auth, price) = if activation { (a, PRICE) } else { ([0u8; 32], 0) };
        // RETIRE stamps `retired_slot` from the Clock and canonicalisation refuses 0.
        let now_slot = self.clock_slot() + 1;
        self.svm.warp_to_slot(now_slot);
        let authority_epoch = self.authority_epoch(0);
        self.send_logged(
            ProgInstruction::UpdateAssetLifecycle {
                action,
                asset_index,
                market_id: if activation { next } else { current },
                authority_epoch,
                now_slot,
                initial_price: price,
                max_init_fee: u128::MAX,
                insurance_authority: auth,
                insurance_operator: auth,
                backing_bucket_authority: auth,
                oracle_authority: auth,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
            ],
            &[&admin],
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. The payee record and the destination cannot be spoofed: owner / kind / market / asset /
//    version / length tampering of the REAL PDA, and every wrong-destination shape.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_payee_record_and_destination_spoofs_refused() {
    use percolator_prog::constants::{HEADER_LEN, KIND_POOL_CLAIM};
    use percolator_prog::error::PercolatorError as E;
    let payee = Pubkey::new_unique();
    let (mut env, ..) = traded_flat_market_in(first_loss_env(payee));
    let owed = env.legs().creator_owed();
    let legs0 = env.legs();
    let ata = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    let cranker = Keypair::new();
    let real = env.svm.get_account(&pda).unwrap();
    assert_eq!(real.owner, PERCOLATOR_MAINNET);
    assert_eq!(real.data.len(), state::creator_fee_payee_account_len());
    assert_eq!(real.data[10], percolator_prog::constants::KIND_CREATOR_FEE_PAYEE);
    assert_eq!(&real.data[HEADER_LEN + 32..HEADER_LEN + 64], payee.as_ref());

    // (1) record tampering, each on the REAL PDA address, restored after.
    let h = HEADER_LEN;
    let mut cases: Vec<(&str, Account)> = Vec::new();
    let mut a = real.clone();
    a.owner = spl_token_classic_id();
    cases.push(("owner = token program", a));
    let mut a = real.clone();
    a.owner = solana_sdk::system_program::id();
    cases.push(("owner = system program", a));
    let mut a = real.clone();
    a.data[10] = KIND_POOL_CLAIM;
    cases.push(("header kind 18", a));
    let mut a = real.clone();
    a.data[h..h + 32].copy_from_slice(Pubkey::new_unique().as_ref());
    cases.push(("stored market differs", a));
    let mut a = real.clone();
    a.data[h + 64..h + 66].copy_from_slice(&1u16.to_le_bytes());
    cases.push(("stored asset index differs", a));
    let mut a = real.clone();
    a.data[h + 66] = 2;
    cases.push(("version", a));
    let mut a = real.clone();
    a.data[h + 32..h + 64].fill(0);
    cases.push(("zero payee", a));
    let mut a = real.clone();
    a.data.push(0);
    cases.push(("length + 1", a));
    for (label, acct) in cases {
        env.svm.set_account(pda, acct).unwrap();
        assert_custom(env.claim_as(&cranker, owed, ata, Some(pda)), PAYEE_INVALID, label);
        env.svm.set_account(pda, real.clone()).unwrap();
    }

    // (2) destination shapes.
    // close authority set on the payee's canonical ATA (W5: encumbered).
    {
        let a0 = env.svm.get_account(&ata).unwrap();
        let mut a = a0.clone();
        let mut t = TokenAccount::unpack(&a.data).unwrap();
        t.close_authority = solana_program::program_option::COption::Some(cranker.pubkey());
        TokenAccount::pack(t, &mut a.data).unwrap();
        env.svm.set_account(ata, a).unwrap();
        assert_custom(
            env.claim_as(&cranker, owed, ata, Some(pda)),
            E::InvalidTokenAccount as u32,
            "close-authority ATA",
        );
        env.svm.set_account(ata, a0).unwrap();
    }
    // the canonical ATA ADDRESS holding an account owned by someone else.
    {
        let a0 = env.svm.get_account(&ata).unwrap();
        let mut a = a0.clone();
        let mut t = TokenAccount::unpack(&a.data).unwrap();
        t.owner = cranker.pubkey();
        TokenAccount::pack(t, &mut a.data).unwrap();
        env.svm.set_account(ata, a).unwrap();
        assert_custom(
            env.claim_as(&cranker, owed, ata, Some(pda)),
            E::InvalidTokenAccount as u32,
            "right address, wrong owner",
        );
        env.svm.set_account(ata, a0).unwrap();
    }
    // the payee's canonical ATA for ANOTHER mint.
    let other_mint = Pubkey::new_unique();
    let other_ata = canonical_vault_ata(&payee, &other_mint);
    env.plant(other_ata, make_token_data(other_mint, payee, 0), spl_token_classic_id());
    assert_custom(env.claim_as(&cranker, owed, other_ata, Some(pda)), E::InvalidMint as u32, "other-mint ATA");
    // the vault itself.
    let vault = env.vault;
    assert_custom(env.claim_as(&cranker, owed, vault, Some(pda)), E::InvalidTokenAccount as u32, "vault as dest");

    // Nothing moved; the untampered claim then pays the payee in full.
    assert_eq!(env.legs(), legs0);
    env.claim_as(&cranker, owed, ata, Some(pda)).expect("control: untampered claim pays");
    assert_eq!(env.token_amount(ata) as u128, owed);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. No payee recorded before the burn: behaviour unchanged. Tag 90 refused for everyone and
//    CloseSlab re-books the creator pot to the protocol leg.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_no_payee_burned_market_unchanged_close_rebooks_to_protocol() {
    let (mut env, _fees) = terminal_empty_market_with_fees_in(Env::build(true, true));
    assert!(!env.payee_bit(0));
    let legs0 = env.legs();
    let owed = legs0.creator_owed();
    assert!(owed > 0);
    let stranger = Keypair::new();
    let ata = env.plant_ata(stranger.pubkey());
    let pda = payee_pda(&env.market, 0);
    assert_custom(env.claim_as(&stranger, owed, ata, Some(pda)), UNAUTHORIZED, "no payee: refused");
    assert_custom(env.claim_as(&stranger, owed, ata, None), UNAUTHORIZED, "no payee, no [6]: refused");
    let (res, _) = env.close_slab();
    res.expect("CloseSlab re-book step");
    let legs1 = env.legs();
    assert_eq!(legs1.creator_owed(), 0, "orphaned creator pot re-booked");
    assert_eq!(legs1.protocol_accrued, legs0.protocol_accrued + owed, "to the protocol leg");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Generation hygiene: a slot re-activated for a new creator does NOT inherit the previous
//    generation's payee bit (RETIRE carries p4 flags; the activation clears bit 3), and tag 125
//    is bound to the slot's live generation.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_reactivated_asset_does_not_inherit_payee() {
    use percolator_prog::processor::{ASSET_ACTION_ACTIVATE, ASSET_ACTION_RETIRE};
    let mut env = Env::build(false, false);
    let admin = env.admin.insecure_clone();
    // Cycle asset 1 once so its asset_admin is known to be the activator (marketauth).
    env.lifecycle(ASSET_ACTION_RETIRE, 1).expect("retire asset 1");
    env.lifecycle(ASSET_ACTION_ACTIVATE, 1).expect("activate asset 1");
    assert_eq!(env.profile(1).asset_admin, admin.pubkey().to_bytes());
    let gen1 = env.generation(1);

    // Tag 125 for asset 1, generation-bound.
    let p1 = Pubkey::new_unique();
    let e = env.authority_epoch(1);
    // A stale generation is refused (encode by hand with market_id - 1).
    {
        let pda = payee_pda(&env.market, 1);
        let res = env.send(
            ProgInstruction::SetCreatorFeePayee {
                asset_index: 1,
                market_id: gen1 - 1,
                payee: p1.to_bytes(),
                authority_epoch: e,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            &[&admin],
        );
        assert_custom(res, GENERATION_MISMATCH, "stale generation");
        // Another asset's PDA address is refused.
        let wrong = payee_pda(&env.market, 0);
        let res = env.send(
            ProgInstruction::SetCreatorFeePayee {
                asset_index: 1,
                market_id: gen1,
                payee: p1.to_bytes(),
                authority_epoch: e,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(env.market, false),
                AccountMeta::new(wrong, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            &[&admin],
        );
        assert_custom(res, PAYEE_INVALID, "asset-0 PDA for asset 1");
    }
    // Griefing: someone pre-funds the PDA address (a system account with lamports) before the
    // first tag 125; creation must still succeed (allocate + assign path).
    env.svm.airdrop(&payee_pda(&env.market, 1), 1).unwrap();
    env.set_payee_as(&admin, 1, p1, e).expect("tag 125 on asset 1 (pre-funded PDA)");
    assert!(env.payee_bit(1));
    assert!(!env.payee_bit(0), "asset 0 untouched");

    // RETIRE carries p4 flags (I-P1) ...
    env.lifecycle(ASSET_ACTION_RETIRE, 1).expect("retire again");
    // ... but the re-activation for the next creator clears the payee bit.
    env.lifecycle(ASSET_ACTION_ACTIVATE, 1).expect("re-activate");
    assert_ne!(env.generation(1), gen1, "new generation");
    let prof = env.profile(1);
    assert!(!state::profile_has_creator_fee_payee(&prof), "payee bit cleared on re-activation");
    assert_ne!(
        state::profile_p4_flags(&prof) & percolator_prog::constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT,
        0,
        "the other carried p4 bits are untouched"
    );
    // The new generation's admin can record a payee afresh over the stale PDA (even the same
    // key: with the bit clear there is no "current" payee).
    let e2 = env.authority_epoch(1);
    env.set_payee_as(&admin, 1, p1, e2).expect("fresh tag 125 in the new generation");
    assert!(env.payee_bit(1));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. A profile REBUILD (tag 62 ConfigureAuthMark, by the surviving oracle authority after the
//    burn) keeps the payee bit, and the payee route keeps working.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn f587_profile_rebuild_keeps_payee() {
    let payee = Pubkey::new_unique();
    let (mut env, ..) = traded_flat_market_in(first_loss_env(payee));
    let owed = env.legs().creator_owed();
    let admin = env.admin.insecure_clone();
    assert_eq!(env.profile(0).oracle_authority, admin.pubkey().to_bytes());
    let mode0 = env.profile(0).oracle_mode;
    let obs = state::read_asset_control_sequences(&env.svm.get_account(&env.market).unwrap().data, 0)
        .unwrap()
        .oracle_observation;
    let now_slot = env.clock_slot().max(1);
    let market_id = env.generation(0);
    env.send(
        ProgInstruction::ConfigureAuthMark {
            asset_index: 0,
            market_id,
            now_slot,
            initial_mark_e6: PRICE,
            observation_sequence: obs + 1,
        }
        .encode(),
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    )
    .expect("tag 62 rebuilds asset 0's profile");
    let prof = env.profile(0);
    assert_ne!(prof.oracle_mode, mode0, "the profile was really rebuilt");
    assert_eq!(prof.asset_admin, [0u8; 32]);
    assert!(state::profile_has_creator_fee_payee(&prof), "payee bit survives the rebuild");
    let ata = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    env.claim_as(&Keypair::new(), owed, ata, Some(pda)).expect("payee route after the rebuild");
    assert_eq!(env.token_amount(ata) as u128, owed);
}

// ═════════════════════════════════════════════════════════════════════════════
// att644 (independent attacker, 2026-10-31). Attack tests on top of the PR #644 harness.
// ═════════════════════════════════════════════════════════════════════════════

/// A1 (liveness): a creator records the market's own `vault_authority` PDA as payee before the
/// burn. Its canonical ATA IS the vault, so tag 90's payee route can never pay (dest == vault),
/// and because a payee is recorded CloseSlab no longer re-books the pot either: the pot is
/// stranded and CloseSlab refuses for ever. Pre-#587 the same burned market always closed.
#[test]
fn att644_a1_vault_authority_payee_strands_pot_and_blocks_close_forever() {
    let mut env = Env::build(true, false);
    let va = env.vault_authority;
    env.set_payee(va);
    env.burn_asset_admin();
    let (mut env, _fees) = terminal_empty_market_with_fees_in(env);
    let owed = env.legs().creator_owed();
    assert!(owed > 0);
    // The payee's canonical ATA is the vault itself.
    assert_eq!(canonical_vault_ata(&va, &env.mint), env.vault);
    let (res, _) = env.close_slab();
    res.expect("CloseSlab re-book step (LP -> staker only)");
    assert_eq!(env.legs().creator_owed(), owed, "creator pot not re-booked (payee recorded)");
    env.withdraw_protocol_fee().expect("tag 84");
    env.withdraw_to_stake().expect("tag 87 terminal");
    let pda = payee_pda(&env.market, 0);
    let vault = env.vault;
    let c = refused(env.claim_as(&Keypair::new(), owed, vault, Some(pda)), "pay payee ATA (= vault)");
    println!("A1: tag 90 to the payee's ATA (the vault) refused with Custom({c})");
    // No other destination is accepted for this route.
    let other = env.plant_ata(Keypair::new().pubkey());
    let c2 = refused(env.claim_as(&Keypair::new(), owed, other, Some(pda)), "pay other ATA");
    println!("A1: tag 90 to any other ATA refused with Custom({c2})");
    // Tag 125 can no longer change the payee (admin burned).
    let admin = env.admin.insecure_clone();
    let e = env.authority_epoch(0);
    // Resolved: mode gate (21) fires first; on Live it is 136 (PR test 2).
    let c3 = refused(env.set_payee_as(&admin, 0, Pubkey::new_unique(), e), "tag 125 after burn");
    assert!(c3 == 21 || c3 == PAYEE_INVALID);
    for i in 0..3 {
        let (res, _) = env.close_slab();
        assert_custom(res, FEES_OUTSTANDING, &format!("CloseSlab attempt {i}: refused for ever"));
    }
    assert!(!env.market_closed());
    assert_eq!(env.legs().creator_owed(), owed, "pot stranded");
}

/// A2 (cross-market PDA spoof): an attacker creates their own market, records THEMSELVES as
/// payee there, and passes that real program-owned kind-19 record as `[6]` for the victim's
/// burned market. Must be refused (PDA derivation binds the market).
#[test]
fn att644_a2_payee_record_from_another_market_refused() {
    let attacker = Keypair::new();
    // Attacker's market + real tag-125 record.
    let mut evil = Env::build(true, false);
    evil.set_payee(attacker.pubkey());
    let evil_pda = payee_pda(&evil.market, 0);
    let evil_rec = evil.svm.get_account(&evil_pda).unwrap();
    assert_eq!(evil_rec.owner, PERCOLATOR_MAINNET);
    // Victim: burned market with an honest payee.
    let honest = Pubkey::new_unique();
    let (mut env, _t, _tp, _m, _mp, _fees) = traded_flat_market_in(first_loss_env(honest));
    let owed = env.legs().creator_owed();
    assert!(owed > 0);
    env.svm.set_account(evil_pda, evil_rec).unwrap();
    let ata = env.plant_ata(attacker.pubkey());
    assert_custom(
        env.claim_as(&attacker, owed, ata, Some(evil_pda)),
        PAYEE_INVALID,
        "foreign market's payee record",
    );
    // And the victim's real PDA does not let the attacker's ATA through either.
    let pda = payee_pda(&env.market, 0);
    assert_custom(env.claim_as(&attacker, owed, ata, Some(pda)), 11, "attacker ATA (InvalidTokenAccount)");
    assert_eq!(env.legs().creator_owed(), owed);
}

/// A3 (front-run / ordering): burn then tag 125 in ONE transaction is refused atomically, and
/// a stale-epoch tag 125 replay (the epoch the live admin already consumed) is refused.
#[test]
fn att644_a3_set_after_burn_same_tx_and_stale_epoch_replay_refused() {
    let mut env = Env::build(true, false);
    let admin = env.admin.insecure_clone();
    let e0 = env.authority_epoch(0);
    env.set_payee(Pubkey::new_unique()); // consumes e0
    // stale replay of e0 with a different payee
    assert!(env.set_payee_as(&admin, 0, Pubkey::new_unique(), e0).is_err(), "stale epoch replay");
    let e1 = env.authority_epoch(0);
    let pda = payee_pda(&env.market, 0);
    let burn = Instruction {
        program_id: PERCOLATOR_MAINNET,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        data: ProgInstruction::UpdateAssetAuthority {
            market_id: 1,
            asset_index: 0,
            kind: 0,
            new_pubkey: [0u8; 32],
            authority_epoch: e1,
        }
        .encode(),
    };
    let set = Instruction {
        program_id: PERCOLATOR_MAINNET,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data: ProgInstruction::SetCreatorFeePayee {
            asset_index: 0,
            market_id: env.generation(0),
            payee: Pubkey::new_unique().to_bytes(),
            authority_epoch: e1 + 1,
        }
        .encode(),
    };
    let payer = env.payer.insecure_clone();
    env.svm.expire_blockhash();
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[common::heap_ix(), common::cu_ix(), burn, set],
        Some(&payer.pubkey()),
        &[&payer, &admin],
        env.svm.latest_blockhash(),
    );
    let r = env.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err);
    let c = refused(r, "burn + set in one tx");
    assert_eq!(c, PAYEE_INVALID);
    assert_ne!(env.asset0_profile().asset_admin, [0u8; 32], "whole tx rolled back");
}

/// A4 (rotation): after the live admin rotates `asset_admin` to a new key (tag 65 kind 0), the
/// OLD admin can no longer move the payee; the new admin can (it holds the pre-burn power).
#[test]
fn att644_a4_rotated_out_admin_cannot_set_payee() {
    let mut env = Env::build(true, false);
    let old = env.admin.insecure_clone();
    let newk = Keypair::new();
    env.set_payee(Pubkey::new_unique());
    let e = env.authority_epoch(0);
    env.send(
        ProgInstruction::UpdateAssetAuthority {
            market_id: 1,
            asset_index: 0,
            kind: 0,
            new_pubkey: newk.pubkey().to_bytes(),
            authority_epoch: e,
        }
        .encode(),
        vec![
            AccountMeta::new(old.pubkey(), true),
            AccountMeta::new_readonly(newk.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&old, &newk],
    )
    .expect("rotate asset_admin");
    let e = env.authority_epoch(0);
    assert_custom(env.set_payee_as(&old, 0, Pubkey::new_unique(), e), PAYEE_INVALID, "old admin");
    let e = env.authority_epoch(0);
    env.set_payee_as(&newk, 0, Pubkey::new_unique(), e).expect("new admin may set");
}
