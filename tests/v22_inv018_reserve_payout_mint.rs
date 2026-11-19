//! INV-018 on the v2.2-only payout paths: a payout that its beneficiary did not sign is
//! made in the primary mint (#477, the rule of upstream 0b06131f).
//!
//! `marketauth` names the secondary mint while the market is empty and anyone can send
//! tokens to the secondary vault. A permissionless payout whose caller picks the mint would
//! clear a claim in a mint of the authority's making and leave the primary tokens in the
//! vault, where `CloseSlab` pays them to the authority.
//!
//! Paths covered here (real wrapper BPF, the harness of `v22_587_creator_fee_payee.rs`):
//!   * tag 90 `WithdrawCreatorFee` payee route (burned `asset_admin`, permissionless)
//!   * tag 87 `WithdrawInsuranceReserveToStake` (permissionless, pays the stake pool vault)
//! Tag 101 `VaultLpSettleResolved` is covered in `tests/p3_vault_lp.rs`; the lost-key
//! reserve payouts in `tests/v16_cu.rs` (`inv_018_reserve_payout_lostkey`).
#![allow(dead_code)]
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

const INVALID_MINT: u32 = percolator_prog::error::PercolatorError::InvalidMint as u32;

impl Env {
    /// Copied from `v22_587_creator_fee_payee.rs` (stake Bind is single-asset only).
    fn poke_max_market_slots(&mut self, n: u32) {
        let mut acct = self.svm.get_account(&self.market).unwrap();
        {
            let (_, group) = state::market_view_mut(&mut acct.data).unwrap();
            group.header.config.max_market_slots = percolator::V16PodU32::new(n);
        }
        self.svm.set_account(self.market, acct).unwrap();
    }

    /// Names a secondary base-unit mint on the still-empty market (the only time the
    /// wrapper accepts it) and plants its canonical vault holding `vault_amount`.
    fn add_secondary_mint(&mut self, vault_amount: u64) -> (Pubkey, Pubkey) {
        let secondary = Pubkey::new_unique();
        self.plant(secondary, make_mint_data(), spl_token_classic_id());
        let admin = self.admin.insecure_clone();
        let authority_epoch = self.authority_epoch(0);
        self.send(
            ProgInstruction::UpdateBaseUnitMints {
                primary_mint: self.mint.to_bytes(),
                secondary_mint: secondary.to_bytes(),
                authority_epoch,
            }
            .encode(),
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(secondary, false),
            ],
            &[&admin],
        )
        .expect("UpdateBaseUnitMints on the empty market");
        let secondary_vault = canonical_vault_ata(&self.vault_authority, &secondary);
        self.set_secondary_vault(secondary, secondary_vault, vault_amount);
        (secondary, secondary_vault)
    }

    fn set_secondary_vault(&mut self, secondary: Pubkey, vault: Pubkey, amount: u64) {
        let authority = self.vault_authority;
        self.plant(vault, make_token_data(secondary, authority, amount), spl_token_classic_id());
    }

    /// Tag 90 sent by `caller`, drawing from `vault_token`.
    fn claim_from(
        &mut self,
        caller: &Keypair,
        amount: u128,
        dest: Pubkey,
        vault_token: Pubkey,
        payee_acct: Option<Pubkey>,
    ) -> Result<(), TransactionError> {
        self.fund(&caller.pubkey());
        let authority_epoch = self.authority_epoch(0);
        let mut metas = vec![
            AccountMeta::new(caller.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(vault_token, false),
            AccountMeta::new_readonly(self.vault_authority, false),
            AccountMeta::new_readonly(spl_token_classic_id(), false),
        ];
        if let Some(p) = payee_acct {
            metas.push(AccountMeta::new_readonly(p, false));
        }
        self.send(
            ProgInstruction::WithdrawCreatorFee { amount, asset_index: 0, authority_epoch }
                .encode(),
            metas,
            &[caller],
        )
    }

    fn withdraw_to_stake_from(&mut self, vault_token: Pubkey) -> Result<(), TransactionError> {
        let cranker = Keypair::new();
        self.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
        self.send(
            ProgInstruction::WithdrawInsuranceReserveToStake.encode(),
            vec![
                AccountMeta::new(cranker.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.pool_pda, false),
                AccountMeta::new(self.stake_vault, false),
                AccountMeta::new(vault_token, false),
                AccountMeta::new_readonly(self.vault_authority, false),
                AccountMeta::new_readonly(spl_token_classic_id(), false),
            ],
            &[&cranker],
        )
    }

    fn frame(&self, keys: &[Pubkey]) -> Vec<Option<Account>> {
        keys.iter().map(|k| self.svm.get_account(k)).collect()
    }
}

/// A creator-fee claim that goes to the recorded payee is made without a signature from the
/// payee (or anyone with authority). It is paid in the primary mint; the secondary mint is
/// refused with every tracked account unchanged.
#[test]
fn v22_inv018_unsigned_creator_fee_payout_is_primary_mint() {
    let payee = Pubkey::new_unique();
    let mut env = Env::build(true, false);
    let (secondary, secondary_vault) = env.add_secondary_mint(0);
    env.set_payee(payee);
    env.burn_asset_admin();
    let (mut env, ..) = traded_flat_market_in(env);
    let owed = env.legs().creator_owed();
    assert!(owed > 0);
    env.set_secondary_vault(secondary, secondary_vault, owed as u64);
    let payee_secondary = canonical_vault_ata(&payee, &secondary);
    env.plant(payee_secondary, make_token_data(secondary, payee, 0), spl_token_classic_id());
    let payee_primary = env.plant_ata(payee);
    let pda = payee_pda(&env.market, 0);
    let vault = env.vault;
    let tracked = [env.market, vault, secondary_vault, payee_secondary, payee_primary];

    let caller = Keypair::new();
    let before = env.frame(&tracked);
    assert_custom(
        env.claim_from(&caller, owed, payee_secondary, secondary_vault, Some(pda)),
        INVALID_MINT,
        "an unsigned creator-fee payout in the secondary mint",
    );
    assert_eq!(env.frame(&tracked), before, "the refused payout changes nothing");

    let primary_before = env.token_amount(vault);
    env.claim_from(&caller, owed, payee_primary, vault, Some(pda))
        .expect("the unsigned creator-fee payout is made in the primary mint");
    assert_eq!(env.token_amount(payee_primary) as u128, owed);
    assert_eq!(env.token_amount(payee_secondary), 0);
    assert_eq!((primary_before - env.token_amount(vault)) as u128, owed);
    assert_eq!(env.token_amount(secondary_vault) as u128, owed, "secondary vault untouched");
}

/// The live `asset_admin` signs its own claim and keeps the choice of either mint.
#[test]
fn v22_inv018_admin_signed_creator_fee_may_take_secondary_mint() {
    let mut env = Env::build(true, false);
    let (secondary, secondary_vault) = env.add_secondary_mint(0);
    let (mut env, ..) = traded_flat_market_in(env);
    let owed = env.legs().creator_owed();
    assert!(owed > 0);
    env.set_secondary_vault(secondary, secondary_vault, owed as u64);
    let admin = env.admin.insecure_clone();
    let dest = canonical_vault_ata(&admin.pubkey(), &secondary);
    env.plant(dest, make_token_data(secondary, admin.pubkey(), 0), spl_token_classic_id());
    env.claim_from(&admin, owed, dest, secondary_vault, None)
        .expect("the signing asset_admin takes the secondary mint");
    assert_eq!(env.token_amount(dest) as u128, owed);
    assert_eq!(env.token_amount(secondary_vault), 0);
}

/// The permissionless stake-reserve payout goes to the stake pool's vault. Its beneficiary
/// signs nothing, so it is paid in the primary mint: a pool vault held in the secondary
/// mint is refused with every tracked account unchanged.
#[test]
fn v22_inv018_unsigned_stake_reserve_payout_is_primary_mint() {
    let mut env = Env::build(true, false);
    let (secondary, secondary_vault) = env.add_secondary_mint(0);
    let (mut env, ..) = terminal_empty_market_with_fees_in(env);
    let accrued = {
        let l = env.legs();
        l.ins_accrued - l.ins_withdrawn
    };
    assert!(accrued > 0);
    // The pool's vault, at the same address, held in the secondary mint.
    let stake_vault = env.stake_vault;
    let (pool_pda, _) = (env.pool_pda, 0);
    let (vault_auth, _) = Pubkey::find_program_address(&[b"vault_auth", pool_pda.as_ref()], &STAKE_ID);
    let primary_stake_vault = env.svm.get_account(&stake_vault).unwrap();
    env.plant(stake_vault, make_token_data(secondary, vault_auth, 0), spl_token_classic_id());
    // The secondary vault holds as much as the primary one, so only the mint decides.
    let primary_balance = env.token_amount(env.vault);
    env.set_secondary_vault(secondary, secondary_vault, primary_balance);
    let vault = env.vault;
    let tracked = [env.market, vault, secondary_vault, stake_vault];
    let before = env.frame(&tracked);
    assert_custom(
        env.withdraw_to_stake_from(secondary_vault),
        INVALID_MINT,
        "an unsigned stake-reserve payout in the secondary mint",
    );
    assert_eq!(env.frame(&tracked), before, "the refused payout changes nothing");

    // Primary rail: the pool's vault in the primary mint is paid.
    env.svm.set_account(stake_vault, primary_stake_vault).unwrap();
    let paid_before = env.token_amount(vault);
    env.withdraw_to_stake_from(vault)
        .expect("the unsigned stake-reserve payout is made in the primary mint");
    let paid = paid_before - env.token_amount(vault);
    assert!(paid > 0, "the primary rail pays the stake vault");
    assert_eq!(env.token_amount(stake_vault), paid);
    assert_eq!(env.token_amount(secondary_vault), primary_balance, "secondary vault untouched");
}
