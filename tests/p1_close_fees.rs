//! P1 F4 -- CloseSlab must never burn an owed fee leg.
//!
//! Ledger: `percolator-ops/ledger/fee-flow-audit-2026-09-29.md` F4. Before P1,
//! `handle_close_slab` ran the terminal retirement with `additional_reserved = 0`,
//! which SPL-burns ALL unbudgeted insurance -- and the four fee legs (protocol,
//! creator, LP, staker) live exactly there. P1 makes CloseSlab refuse with
//! `CloseSlabFeesOutstanding` = Custom(71) while any leg is owed, and allows
//! tag 87 on a terminal-empty Resolved market (folding an orphaned LP leg into the
//! staker leg first) so every leg has an exit before close.
//!
//! Every fixture here drives REAL instructions end to end: InitMarket, tag 85
//! (SetProtocolFeeAuthority, with a mocked ProgramData since LiteSVM mounts the
//! wrapper under the non-upgradeable loader), stake tag 19 Bind, Deposit,
//! fee-bearing TradeNoCpi, Withdraw, ClosePortfolio, ResolveMarket, tags 84/90/87,
//! CloseSlab. The only byte-level fixture writes are (a) the crafted v4 stake pool
//! (same as `v16_fee_split.rs`), (b) the SPL mint supply (placeholder mint), and
//! (c) in test 4 only, the LP-vault sentinel stamped on one backing bucket, because
//! a real LP vault's domain cannot be torn down to terminal-empty (dead-share floor).

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
        let market = Pubkey::new_unique();
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
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.mint, false),
            ],
            &[&admin],
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
                AccountMeta::new_readonly(pool_pda, false),
                AccountMeta::new_readonly(vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(PERCOLATOR_MAINNET, false),
            ],
            data: vec![19u8],
        };
        send_ixs(&mut self.svm, &payer, vec![ix], &[&admin]).expect("stake Bind (tag 19)");
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
        let portfolio = Pubkey::new_unique();
        let len = state::portfolio_account_len_for_market_slots(MAX_ASSETS as usize).unwrap();
        self.plant(portfolio, vec![0u8; len], PERCOLATOR_MAINNET);
        self.send(
            ProgInstruction::InitPortfolio.encode(),
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
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
// 1. CloseSlab refuses (Custom 71) while any fee leg is owed; nothing is burned.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_f4_close_slab_refuses_with_custom_71_while_fee_legs_outstanding() {
    let (mut env, fees) = terminal_empty_market_with_fees();
    let legs0 = env.legs();
    let lp_owed = legs0.lp_accrued - legs0.lp_withdrawn;
    let vault0 = env.token_amount(env.vault);
    let supply0 = env.mint_supply();

    // Call 1 (P1-W1): the re-book step. Bound stake pool, no LP-vault domain -> the LP leg
    // is re-booked onto the staker leg; persisted, Ok, market NOT closed, nothing moves.
    let (res, dest) = env.close_slab();
    res.expect("CloseSlab re-book step");
    assert!(
        !env.market_closed(),
        "the re-book step must not close the market"
    );
    let legs1 = env.legs();
    assert_eq!(legs1.lp_withdrawn, legs1.lp_accrued, "LP leg re-booked");
    assert_eq!(
        legs1.ins_accrued,
        legs0.ins_accrued + lp_owed,
        "... onto the staker leg"
    );
    assert_eq!(
        legs1.protocol_accrued, legs0.protocol_accrued,
        "bound: staker leg stays"
    );
    assert_eq!(
        legs1.creator_owed(),
        legs0.creator_owed(),
        "live asset_admin: creator stays"
    );
    assert_eq!(
        legs1.total_accrued() - lp_owed,
        fees,
        "re-book conserves the owed total"
    );
    assert_eq!(env.token_amount(env.vault), vault0);
    assert_eq!(env.mint_supply(), supply0);
    assert_eq!(env.token_amount(dest), 0);

    // Call 2: nothing left to re-book; legs are claimable and backed -> Custom(71).
    let legs_before = env.legs();
    let vault_before = env.token_amount(env.vault);
    let supply_before = env.mint_supply();
    let market_before = env.svm.get_account(&env.market).unwrap();

    let (res, dest) = env.close_slab();

    let vault_after = env.token_amount_opt(env.vault);
    let supply_after = env.mint_supply();
    let dest_after = env.token_amount_opt(dest);
    println!(
        "EVIDENCE F4 close_slab: result={res:?} fees_owed={fees} vault {vault_before} -> {vault_after:?} \
         mint_supply {supply_before} -> {supply_after} (burned={}) admin_dest={dest_after:?} closed={}",
        supply_before - supply_after,
        env.market_closed()
    );

    assert_custom(res, 71, "CloseSlab on a market that still owes fee legs");
    assert_eq!(
        vault_after,
        Some(vault_before),
        "vault SPL balance unchanged"
    );
    assert_eq!(supply_after, supply_before, "nothing burned");
    assert_eq!(dest_after, Some(0), "nothing swept to the admin");
    let market_after = env.svm.get_account(&env.market).unwrap();
    assert_eq!(
        market_after.data, market_before.data,
        "market bytes unchanged"
    );
    assert_eq!(market_after.lamports, market_before.lamports);
    assert_eq!(env.legs(), legs_before, "no leg marked paid");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Happy path: 84 + 90 + terminal 87 (staker + folded LP), then CloseSlab.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_f4_claim_all_legs_then_close_slab_conserves_every_fee_atom() {
    let (mut env, fees) = terminal_empty_market_with_fees();
    let legs0 = env.legs();
    assert_eq!(
        (
            legs0.protocol_withdrawn,
            legs0.lp_withdrawn,
            legs0.ins_withdrawn
        ),
        (0, 0, 0)
    );
    let supply0 = env.mint_supply();

    // Protocol leg (tag 84, amount 0 = all).
    let proto_dest = env
        .withdraw_protocol_fee()
        .expect("tag 84 on terminal-empty Resolved");
    let protocol_claimed = env.token_amount(proto_dest) as u128;
    assert_eq!(protocol_claimed, legs0.protocol_accrued);

    // Creator leg (tag 90, exact).
    let creator_owed = legs0.creator_owed();
    let creator_dest = env
        .withdraw_creator_fee(creator_owed)
        .expect("tag 90 on terminal-empty Resolved");
    let creator_claimed = env.token_amount(creator_dest) as u128;
    assert_eq!(creator_claimed, creator_owed);

    // Tag 87 on the terminal-empty market: staker leg + folded LP leg.
    let legs1 = env.legs();
    let ins_owed = legs1.ins_accrued - legs1.ins_withdrawn;
    let lp_owed = legs1.lp_accrued - legs1.lp_withdrawn;
    assert!(ins_owed > 0 && lp_owed > 0);
    let stake_before = env.token_amount(env.stake_vault);
    let vault_before_87 = env.token_amount(env.vault);
    env.withdraw_to_stake()
        .expect("tag 87 must be allowed on a terminal-empty Resolved market");
    let stake_received = (env.token_amount(env.stake_vault) - stake_before) as u128;
    let legs2 = env.legs();
    println!(
        "EVIDENCE tag87 terminal: ins_owed={ins_owed} lp_owed={lp_owed} stake_received={stake_received} \
         legs_after={legs2:?}"
    );
    assert_eq!(
        stake_received,
        ins_owed + lp_owed,
        "stake vault receives exactly insurance_reserve_owed + lp_owed"
    );
    assert_eq!(
        (vault_before_87 - env.token_amount(env.vault)) as u128,
        stake_received
    );
    assert_eq!(
        legs2.lp_withdrawn, legs2.lp_accrued,
        "lp_fee_withdrawn == lp_fee_accrued"
    );
    assert_eq!(
        legs2.ins_withdrawn, legs2.ins_accrued,
        "insurance_reserve_withdrawn == insurance_reserve_accrued"
    );
    assert_eq!(
        legs2.ins_accrued,
        legs1.ins_accrued + lp_owed,
        "the LP leg was re-booked onto the staker leg"
    );
    assert_eq!(
        env.token_amount(env.vault),
        0,
        "vault fully drained of fee legs"
    );
    let (ins, vault_hdr) = env.header_insurance_vault();
    assert_eq!((ins, vault_hdr), (0, 0));

    // Now CloseSlab succeeds and burns NOTHING.
    let (res, dest) = env.close_slab();
    res.expect("CloseSlab once every fee leg is claimed");
    assert_eq!(env.mint_supply(), supply0, "no atom burned at close");
    assert_eq!(env.token_amount(dest), 0, "no residue swept to the admin");
    assert!(env.market_closed(), "market closed to its tombstone");

    // Conservation, to the atom.
    assert_eq!(
        fees,
        protocol_claimed + creator_claimed + stake_received,
        "total fees charged == protocol claimed + creator claimed + stake vault received"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Tag 87 on a Resolved market that still has a materialized portfolio: 21.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_f4_tag87_on_resolved_market_with_live_portfolio_is_engine_lock_active() {
    let (mut env, taker, taker_pf, _maker, _maker_pf, _fees) = traded_flat_market();
    // One trader leaves; the maker's portfolio stays materialized with capital.
    env.withdraw_all(&taker, taker_pf);
    env.close_portfolio(&taker, taker_pf);
    env.resolve();
    let (mode, c_tot, count) = env.header_mode_ctot_count();
    assert_eq!(mode, 1);
    assert!(c_tot > 0, "maker capital still in the market");
    assert_eq!(count, 1, "one portfolio still materialized");

    let legs_before = env.legs();
    assert!(legs_before.ins_accrued > legs_before.ins_withdrawn);
    assert!(legs_before.lp_accrued > legs_before.lp_withdrawn);
    let stake_before = env.token_amount(env.stake_vault);
    let vault_before = env.token_amount(env.vault);

    assert_custom(
        env.withdraw_to_stake(),
        21, // EngineLockActive
        "tag 87 on a non-terminal Resolved market",
    );
    assert_eq!(
        env.token_amount(env.stake_vault),
        stake_before,
        "no tokens moved"
    );
    assert_eq!(env.token_amount(env.vault), vault_before);
    assert_eq!(env.legs(), legs_before, "no leg folded or marked paid");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. LP-vault-funded domain: terminal 87 must NOT fold the LP leg.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_f4_tag87_terminal_does_not_fold_lp_leg_when_lp_vault_domain_present() {
    let (mut env, _fees) = terminal_empty_market_with_fees();
    // Stamp asset 0's long backing bucket as an LP-vault-bound domain (non-Empty status,
    // expiry = LP_VAULT_BACKING_EXPIRY_SLOT) -- the exact signal
    // `lp_vault_funded_backing_domain_present_view` and CloseSlab's dead-share guard scan for.
    // `Expired` with zero amounts is the only non-Empty shape the engine's static bucket
    // validation accepts without real backing atoms (a `Fresh` stamp with 0 backing fails
    // `validate_shape` with EngineInvalidConfig, Custom(14)).
    {
        let mut acct = env.svm.get_account(&env.market).unwrap();
        let market_id = state::read_market_trade_preflight(&acct.data, 0).unwrap().3;
        {
            let (_, group) = state::market_view_mut(&mut acct.data).unwrap();
            let b = &mut group.markets[0].engine.backing_long;
            b.status = 2; // BackingBucketStatusV16::Expired
            b.market_id = percolator::V16PodU64::new(market_id);
            b.expiry_slot = percolator::V16PodU64::new(
                percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT,
            );
        }
        env.svm.set_account(env.market, acct).unwrap();
    }
    let legs0 = env.legs();
    let ins_owed = legs0.ins_accrued - legs0.ins_withdrawn;
    let lp_owed = legs0.lp_accrued - legs0.lp_withdrawn;
    assert!(lp_owed > 0);
    let stake_before = env.token_amount(env.stake_vault);

    env.withdraw_to_stake()
        .expect("tag 87 still pays the staker leg on a terminal-empty market");
    let stake_received = (env.token_amount(env.stake_vault) - stake_before) as u128;
    let legs1 = env.legs();
    println!("EVIDENCE lp-vault domain: ins_owed={ins_owed} lp_owed={lp_owed} stake_received={stake_received}");
    assert_eq!(stake_received, ins_owed, "only the staker leg moved");
    assert_eq!(
        legs1.lp_withdrawn, legs0.lp_withdrawn,
        "lp_fee_withdrawn unchanged"
    );
    assert_eq!(
        legs1.ins_accrued, legs0.ins_accrued,
        "LP leg NOT folded into staker leg"
    );
    assert_eq!(legs1.ins_withdrawn, legs0.ins_accrued);

    // CloseSlab is blocked by the dead-share guard first (21), before the fee check.
    let (res, _) = env.close_slab();
    assert_custom(res, 21, "CloseSlab with an LP-vault-bound domain present");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. P1-W1: UNBOUND stake -> CloseSlab re-books staker + LP legs onto protocol.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_w1_unbound_stake_rebooks_staker_and_lp_legs_to_protocol_then_closes() {
    let (mut env, fees) = terminal_empty_market_with_fees_in(Env::build(false, false));
    let legs0 = env.legs();
    let lp_owed = legs0.lp_accrued - legs0.lp_withdrawn;
    let ins_owed = legs0.ins_accrued - legs0.ins_withdrawn;
    let creator_owed = legs0.creator_owed();
    let supply0 = env.mint_supply();
    // Unbound: tag 87 has no destination on this market.
    assert_custom(
        env.withdraw_to_stake(),
        56, // StakePoolAuthorityMismatch
        "tag 87 on an unbound market",
    );

    // Claim everything claimable first (84 = its own leg, 90 = creator).
    let d = env.withdraw_protocol_fee().expect("tag 84");
    let mut protocol_claimed = env.token_amount(d) as u128;
    assert_eq!(protocol_claimed, legs0.protocol_accrued);
    let d = env.withdraw_creator_fee(creator_owed).expect("tag 90");
    let creator_claimed = env.token_amount(d) as u128;
    assert_eq!(creator_claimed, creator_owed);

    // CloseSlab #1: re-book step (LP -> staker -> protocol), Ok, NOT closed.
    let vault_before = env.token_amount(env.vault);
    let (res, _) = env.close_slab();
    println!(
        "EVIDENCE W1 unbound first CloseSlab: {res:?} legs={:?}",
        env.legs()
    );
    res.expect("CloseSlab re-book step on an unbound market (market must be closable)");
    assert!(!env.market_closed());
    let legs1 = env.legs();
    assert_eq!(legs1.lp_withdrawn, legs1.lp_accrued, "LP leg re-booked");
    assert_eq!(
        legs1.ins_withdrawn, legs1.ins_accrued,
        "staker leg re-booked"
    );
    assert_eq!(legs1.ins_accrued, legs0.ins_accrued + lp_owed);
    assert_eq!(
        legs1.protocol_accrued,
        legs0.protocol_accrued + lp_owed + ins_owed,
        "staker + LP legs now owed to protocol"
    );
    assert_eq!(
        env.token_amount(env.vault),
        vault_before,
        "re-book moves no tokens"
    );

    // CloseSlab #2 refuses while the re-booked protocol leg is owed.
    let (res, _) = env.close_slab();
    assert_custom(res, 71, "CloseSlab with the re-booked protocol leg owed");

    // Protocol claims the re-booked leg; then the close succeeds, burning nothing.
    let d = env.withdraw_protocol_fee().expect("tag 84 (re-booked leg)");
    let second = env.token_amount(d) as u128;
    assert_eq!(second, lp_owed + ins_owed);
    protocol_claimed += second;
    assert_eq!(env.token_amount(env.vault), 0);
    let (res, dest) = env.close_slab();
    res.expect("CloseSlab after every leg is claimed");
    assert!(env.market_closed());
    assert_eq!(env.mint_supply(), supply0, "nothing burned");
    assert_eq!(env.token_amount(dest), 0);
    assert_eq!(
        fees,
        protocol_claimed + creator_claimed,
        "conservation to the atom"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. P1-W1: burned asset_admin -> creator pot re-booked onto protocol.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn p1_w1_burned_asset_admin_creator_pot_rebooked_to_protocol() {
    let (mut env, fees) = terminal_empty_market_with_fees_in(Env::build(true, true));
    let legs0 = env.legs();
    let creator_owed = legs0.creator_owed();
    let lp_owed = legs0.lp_accrued - legs0.lp_withdrawn;
    assert!(creator_owed > 0 && legs0.creator_asset0 > 0);
    let supply0 = env.mint_supply();
    // No signer can ever claim it: tag 90 by the ex-admin is Unauthorized.
    assert_custom(
        env.withdraw_creator_fee(creator_owed).map(|_| ()),
        8, // Unauthorized
        "tag 90 by the ex-admin after the burn",
    );

    let (res, _) = env.close_slab();
    res.expect("CloseSlab re-book step");
    assert!(!env.market_closed());
    let legs1 = env.legs();
    assert_eq!(legs1.creator_owed(), 0, "creator pot re-booked");
    assert_eq!(
        legs1.protocol_accrued,
        legs0.protocol_accrued + creator_owed,
        "... onto protocol"
    );
    assert_eq!(
        legs1.ins_accrued,
        legs0.ins_accrued + lp_owed,
        "bound: LP -> staker"
    );
    assert_eq!(
        legs1.ins_withdrawn, legs0.ins_withdrawn,
        "bound: staker leg stays"
    );

    let (res, _) = env.close_slab();
    assert_custom(res, 71, "legs still owed after re-book");
    let d = env.withdraw_protocol_fee().expect("tag 84");
    let protocol_claimed = env.token_amount(d) as u128;
    assert_eq!(protocol_claimed, legs0.protocol_accrued + creator_owed);
    let stake_before = env.token_amount(env.stake_vault);
    env.withdraw_to_stake().expect("tag 87 terminal");
    let stake_received = (env.token_amount(env.stake_vault) - stake_before) as u128;
    assert_eq!(stake_received, legs1.ins_accrued - legs1.ins_withdrawn);
    let (res, _) = env.close_slab();
    res.expect("CloseSlab after all legs claimed");
    assert!(env.market_closed());
    assert_eq!(env.mint_supply(), supply0, "nothing burned");
    assert_eq!(
        fees,
        protocol_claimed + stake_received,
        "conservation to the atom"
    );
}
