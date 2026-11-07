// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! bigtest-2026-11-05 finding 2, END TO END ON A REAL LOCAL VALIDATOR (Agave `solana-test-validator`, real
//! upgradeable loader, real SPL token + ATA programs, real clock). Not part of the default suite: every test is
//! `#[ignore]` and needs `F2_RPC_URL`.
//!
//!   solana-test-validator --reset --ledger <dir> \
//!     --upgradeable-program <percolator_prog::id()> target/deploy/percolator_prog.so <admin pubkey> \
//!     --bpf-program <CANONICAL_VAULT_LP_MATCHER_PROGRAM> ../percolator-match/target/deploy/percolator_match.so
//!   F2_RPC_URL=http://127.0.0.1:8899 F2_PAYER=<keypair json> \
//!     cargo test --features devnet --test f2_local_validator -- --ignored --nocapture --test-threads 1
//!
//! Each scenario builds its own market + bound vault LP, opens traders long against the LP, walks the auth mark
//! down until they are below maintenance but NOT bankrupt, and liquidates them through tag 5:
//!   * old client  (no vault-LP account)   -> unilateral close, A_short < ADL_ONE, every new open refused (120)
//!   * new client  (vault LP appended)      -> matched close, A stays ADL_ONE, new opens land, no side was closed
//!   * mixed       (old first, then new)    -> the matched close does not deepen an existing latch
//! Every price push is in the SAME transaction as the cranks that need it (a same-slot observation).
use percolator_prog::{
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    state::{self, derive_lp_backing_ledger, derive_lp_escrow, derive_lp_vault_mint, derive_lp_vault_registry, derive_vault_lp_state},
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, Mint};

const MATCHER_CONTEXT_LEN: usize = 320;
const PRICE: u64 = 1_000_000;
const POS: i128 = percolator::POS_SCALE as i128;
const DOMAIN: u16 = 0;
const ADL_ONE: u128 = percolator::ADL_ONE;
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let p: Pubkey = ATA_PROGRAM.parse().unwrap();
    Pubkey::find_program_address(&[owner.as_ref(), spl_token::ID.as_ref(), mint.as_ref()], &p).0
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: ATA_PROGRAM.parse().unwrap(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        data: vec![1], // CreateIdempotent
    }
}

struct Lp {
    portfolio: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

struct Trader {
    kp: Keypair,
    portfolio: Pubkey,
}

struct Net {
    rpc: RpcClient,
    pid: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    mint: Pubkey,
    vault_token: Pubkey,
    registry: Pubkey,
    vault_lp: Pubkey,
    ledger: Pubkey,
    sibling: Pubkey,
    matcher: Pubkey,
    plen: usize,
    paid_in: u128,
    mark: u64,
    sent: u32,
    /// every trader portfolio that holds a position (refreshed in the same tx as an open: else 121 LossStale)
    positioned: Vec<Pubkey>,
}

fn pi(ix: ProgInstruction, pid: Pubkey, accounts: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: pid, accounts, data: ix.encode() }
}

impl Net {
    fn send(&mut self, ixs: Vec<Instruction>, extra: &[&Keypair]) -> Result<(), String> {
        let mut all = vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ];
        all.extend(ixs);
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra);
        let bh = self.rpc.get_latest_blockhash().map_err(|e| format!("{e:?}"))?;
        let tx = Transaction::new_signed_with_payer(&all, Some(&self.payer.pubkey()), &signers, bh);
        self.sent += 1;
        self.rpc.send_and_confirm_transaction(&tx).map(|_| ()).map_err(|e| format!("{e:?}"))
    }

    fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.rpc.get_account_data(k).expect("account")
    }

    fn rent(&self, len: usize) -> u64 {
        self.rpc.get_minimum_balance_for_rent_exemption(len).unwrap()
    }

    fn create_owned(&self, kp: &Keypair, len: usize, owner: &Pubkey) -> Instruction {
        system_instruction::create_account(&self.payer.pubkey(), &kp.pubkey(), self.rent(len), len as u64, owner)
    }

    fn new(rpc_url: &str) -> Net {
        let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
        let payer = read_keypair_file(std::env::var("F2_PAYER").expect("F2_PAYER")).unwrap();
        let admin = read_keypair_file(std::env::var("F2_ADMIN").expect("F2_ADMIN")).unwrap();
        let pid = percolator_prog::id();
        let matcher = percolator_prog::constants::CANONICAL_VAULT_LP_MATCHER_PROGRAM;
        let market_kp = Keypair::new();
        let market = market_kp.pubkey();
        let mint_kp = Keypair::new();
        let mint = mint_kp.pubkey();
        let vault_authority = Pubkey::find_program_address(&[b"vault", market.as_ref()], &pid).0;
        let mut n = Net {
            rpc,
            pid,
            payer,
            admin,
            market,
            mint,
            vault_token: ata(&vault_authority, &mint),
            registry: derive_lp_vault_registry(&pid, &market).0,
            vault_lp: derive_vault_lp_state(&pid, &market).0,
            ledger: derive_lp_backing_ledger(&pid, &market, DOMAIN).0,
            sibling: derive_lp_backing_ledger(&pid, &market, DOMAIN ^ 1).0,
            matcher,
            plen: state::portfolio_account_len_for_market_slots(1).unwrap(),
            paid_in: 0,
            mark: PRICE,
            sent: 0,
            positioned: Vec::new(),
        };
        for k in [n.admin.pubkey()] {
            let _ = n.rpc.request_airdrop(&k, 100_000_000_000);
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let admin = n.admin.insecure_clone();
        let payer_key = n.payer.pubkey();
        let mlen = state::market_account_len_for_capacity(1).unwrap();
        let ixs = vec![
            n.create_owned(&mint_kp, Mint::LEN, &spl_token::ID),
            spl_token::instruction::initialize_mint2(&spl_token::ID, &mint, &admin.pubkey(), None, 0).unwrap(),
            create_ata_ix(&payer_key, &vault_authority, &mint),
        ];
        n.send(ixs, &[&mint_kp]).expect("mint + vault ATA");
        // InitMarket: the p3 harness config, except max_price_move 50 bps/slot x max_accrual_dt 10 slots (the
        // same 5% per-accrual envelope as 500 x 1): a real validator advances slots between transactions.
        let init = ProgInstruction::InitMarket {
            max_portfolio_assets: 1,
            h_min: 0,
            h_max: 10,
            initial_price: PRICE,
            min_nonzero_mm_req: 1,
            min_nonzero_im_req: 2,
            maintenance_margin_bps: 1_000,
            initial_margin_bps: 1_000,
            max_trading_fee_bps: 10_000,
            trade_fee_base_bps: 0,
            liquidation_fee_bps: 0,
            liquidation_fee_cap: 0,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 50,
            max_accrual_dt_slots: 10,
            max_abs_funding_e9_per_slot: 0,
            // must be >= max_accrual_dt_slots (InitMarket refuses InvalidAccountData otherwise)
            min_funding_lifetime_slots: 10,
            max_account_b_settlement_chunks: 1,
            max_bankrupt_close_chunks: 1,
            max_bankrupt_close_lifetime_slots: 100,
            public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
            maintenance_fee_per_slot: 0,
        };
        let ixs = vec![
            n.create_owned(&market_kp, mlen, &pid),
            pi(init, pid, vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, true),
                AccountMeta::new_readonly(mint, false),
            ]),
        ];
        n.send(ixs, &[&admin, &market_kp]).expect("init market");
        let seq = n.oracle_seq() + 1;
        let slot = n.rpc.get_slot().unwrap();
        n.send(
            vec![pi(
                ProgInstruction::ConfigureAuthMark { market_id: 1, asset_index: 0, now_slot: slot, initial_mark_e6: PRICE, observation_sequence: seq },
                pid,
                vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)],
            )],
            &[&admin],
        )
        .expect("configure auth mark");
        let (registry, lp_mint) = (n.registry, derive_lp_vault_mint(&pid, &market).0);
        let _ = derive_lp_escrow(&pid, &market);
        n.send(
            vec![pi(
                ProgInstruction::CreateLpVault {
                    fee_share_bps: 5_000,
                    redemption_cooldown_slots: percolator_prog::constants::MIN_BOUND_VAULT_REDEMPTION_COOLDOWN_SLOTS,
                    oi_reservation_threshold_bps: 0,
                    domain: DOMAIN,
                },
                pid,
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(market, false),
                    AccountMeta::new(registry, false),
                    AccountMeta::new(lp_mint, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(mint, false),
                ],
            )],
            &[&admin],
        )
        .expect("create lp vault");
        n
    }

    fn oracle_seq(&self) -> u64 {
        state::read_asset_control_sequences(&self.data(&self.market), 0).unwrap().oracle_observation
    }

    fn market_state(&self) -> (state::WrapperConfigV16, state::MarketGroupV16) {
        state::read_market(&self.data(&self.market)).unwrap()
    }

    fn a(&self) -> (u128, u128) {
        let (_, g) = self.market_state();
        (g.assets[0].a_long, g.assets[0].a_short)
    }

    fn effective_price(&self) -> u64 {
        self.market_state().1.assets[0].effective_price
    }

    fn portfolio(&self, k: Pubkey) -> state::PortfolioAccountV16 {
        state::read_portfolio(&self.data(&k)).unwrap()
    }

    fn position(&self, k: Pubkey) -> i128 {
        for leg in self.portfolio(k).legs.iter() {
            if leg.active && leg.asset_index == 0 {
                return match leg.side {
                    percolator::SideV16::Long => leg.basis_pos_q.unsigned_abs() as i128,
                    percolator::SideV16::Short => -(leg.basis_pos_q.unsigned_abs() as i128),
                };
            }
        }
        0
    }

    /// ADL-EFFECTIVE signed position (raw basis scaled by the side's A over the leg's A snapshot): what a matched close
    /// moves one-for-one. On an unlatched asset (A = ADL_ONE everywhere) it equals the raw position.
    fn effective(&self, k: Pubkey) -> i128 {
        let (_, g) = self.market_state();
        for leg in self.portfolio(k).legs.iter() {
            if leg.active && leg.asset_index == 0 {
                let a = match leg.side {
                    percolator::SideV16::Long => g.assets[0].a_long,
                    percolator::SideV16::Short => g.assets[0].a_short,
                };
                let q = (leg.basis_pos_q.unsigned_abs() * a / leg.a_basis) as i128;
                return match leg.side {
                    percolator::SideV16::Long => q,
                    percolator::SideV16::Short => -q,
                };
            }
        }
        0
    }

    fn tok(&self, k: &Pubkey) -> u64 {
        TokenAccount::unpack(&self.data(k)).unwrap().amount
    }

    fn assert_conserved(&self, what: &str) {
        let (_, g) = self.market_state();
        let spl = self.tok(&self.vault_token) as u128;
        assert_eq!(spl, g.vault, "[{what}] SPL vault {spl} != engine vault {}", g.vault);
        assert_eq!(self.paid_in, spl, "[{what}] paid in {} != SPL vault {spl}", self.paid_in);
    }

    fn identity(&self, k: Pubkey) -> (u64, u64, u64) {
        let d = self.data(&k);
        (
            state::read_portfolio_id(&d).unwrap(),
            state::read_portfolio_matcher_sequence(&d).unwrap(),
            state::read_portfolio_position_epoch(&d).unwrap(),
        )
    }

    /// A funded token account of `owner` (its ATA), `amount` minted by the admin.
    fn fund(&mut self, owner: &Pubkey, amount: u64) -> Pubkey {
        let a = ata(owner, &self.mint);
        let admin = self.admin.insecure_clone();
        let payer_key = self.payer.pubkey();
        let ixs = vec![
            create_ata_ix(&payer_key, owner, &self.mint),
            spl_token::instruction::mint_to(&spl_token::ID, &self.mint, &a, &admin.pubkey(), &[], amount).unwrap(),
        ];
        self.send(ixs, &[&admin]).expect("fund");
        a
    }

    fn bind(&mut self) -> Lp {
        let lp_kp = Keypair::new();
        let ctx_kp = Keypair::new();
        let lp = lp_kp.pubkey();
        let ctx = ctx_kp.pubkey();
        let delegate = Pubkey::find_program_address(
            &[b"matcher", self.market.as_ref(), lp.as_ref(), self.registry.as_ref(), self.matcher.as_ref(), ctx.as_ref()],
            &self.pid,
        )
        .0;
        let admin = self.admin.insecure_clone();
        let ixs = vec![
            self.create_owned(&lp_kp, self.plen, &self.pid),
            self.create_owned(&ctx_kp, MATCHER_CONTEXT_LEN, &self.matcher.clone()),
            pi(
                ProgInstruction::InitVaultLp { junior_floor_bps: 1_000 },
                self.pid,
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(self.market, false),
                    AccountMeta::new(self.registry, false),
                    AccountMeta::new(self.vault_lp, false),
                    AccountMeta::new(lp, true), // #684: signs (also signs its createAccount)
                    AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                    AccountMeta::new_readonly(self.ledger, false),
                    AccountMeta::new_readonly(self.sibling, false),
                    AccountMeta::new_readonly(self.matcher, false),
                    AccountMeta::new(ctx, false),
                    AccountMeta::new_readonly(delegate, false),
                ],
            ),
        ];
        self.send(ixs, &[&admin, &lp_kp, &ctx_kp]).expect("tag 94 bind");
        // junior capital: $20 (exposure cap 20 units at $1)
        let src = self.fund(&admin.pubkey(), 20_000_000);
        let ix = pi(
            ProgInstruction::DepositJuniorTranche { amount: 20_000_000 },
            self.pid,
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(state::derive_lev_guard(&self.pid, &self.market).0, false),
                AccountMeta::new(state::derive_vault_lp_ext(&self.pid, &self.market).0, false),
            ],
        );
        self.send(vec![ix], &[&admin]).expect("junior deposit");
        self.paid_in += 20_000_000;
        Lp { portfolio: lp, ctx, delegate }
    }

    fn new_trader(&mut self, capital: u64) -> Trader {
        let kp = Keypair::new();
        let pkp = Keypair::new();
        let portfolio = pkp.pubkey();
        let ixs = vec![
            system_instruction::transfer(&self.payer.pubkey(), &kp.pubkey(), 1_000_000_000),
            self.create_owned(&pkp, self.plen, &self.pid),
            pi(ProgInstruction::InitPortfolio, self.pid, vec![
                AccountMeta::new(kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, true),
            ]),
        ];
        self.send(ixs, &[&kp, &pkp]).expect("init portfolio");
        let src = self.fund(&kp.pubkey(), capital);
        let (portfolio_id, expected_sequence, _) = self.identity(portfolio);
        let ix = pi(
            ProgInstruction::Deposit { portfolio_id, expected_sequence, amount: capital as u128 },
            self.pid,
            vec![
                AccountMeta::new(kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );
        self.send(vec![ix], &[&kp]).expect("deposit");
        self.paid_in += capital as u128;
        Trader { kp, portfolio }
    }

    fn push_ix(&self, mark: u64) -> Instruction {
        let slot = self.rpc.get_slot().unwrap();
        pi(
            ProgInstruction::PushAuthMark { market_id: 1, asset_index: 0, now_slot: slot, mark_e6: mark, observation_sequence: self.oracle_seq() + 1 },
            self.pid,
            vec![AccountMeta::new(self.admin.pubkey(), true), AccountMeta::new(self.market, false)],
        )
    }

    /// tag 5 with one observation hint; `lp_tail` appends the bound vault LP (the new client).
    fn crank_ix(&self, portfolio: Pubkey, lp_tail: Option<Pubkey>) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            AccountMeta::new(self.market, false),
            AccountMeta::new(portfolio, false),
        ];
        if let Some(lp) = lp_tail {
            accounts.push(AccountMeta::new(lp, false));
        }
        pi(
            ProgInstruction::PermissionlessCrank { now_slot: 0, observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 0 }] },
            self.pid,
            accounts,
        )
    }

    /// [push mark, crank each] in ONE transaction.
    fn push_and_crank(&mut self, cranks: &[(Pubkey, Option<Pubkey>)]) -> Result<(), String> {
        let mut ixs = vec![self.push_ix(self.mark)];
        for (p, t) in cranks {
            ixs.push(self.crank_ix(*p, *t));
        }
        let admin = self.admin.insecure_clone();
        self.send(ixs, &[&admin])
    }

    /// Walk the auth mark to `target`, cranking only the vault LP, until the engine's effective price is there.
    fn move_price(&mut self, target: u64, lp: Pubkey) {
        self.mark = target;
        for _ in 0..200 {
            // 22 (EngineNonProgress) = nothing to accrue yet in this slot: wait for the next one
            let r = self.push_and_crank(&[(lp, None)]);
            assert!(r.is_ok() || err_code(&r, 22), "push + LP crank: {r:?}");
            if self.effective_price() == target {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        panic!("effective price never reached {target}: {}", self.effective_price());
    }

    fn trade_ix(&self, t: &Trader, lp: &Lp, size_q: i128) -> Instruction {
        let (a_id, _, a_epoch) = self.identity(t.portfolio);
        let (b_id, b_seq, b_epoch) = self.identity(lp.portfolio);
        let market_id = state::read_market_trade_preflight(&self.data(&self.market), 0).unwrap().3;
        pi(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: a_id,
                account_a_position_epoch: a_epoch,
                account_b_portfolio_id: b_id,
                account_b_position_epoch: b_epoch,
                market_id,
                account_b_matcher_sequence: b_seq,
                asset_index: 0,
                size_q,
                fee_bps: 0,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            self.pid,
            vec![
                AccountMeta::new(t.kp.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(t.portfolio, false),
                AccountMeta::new(lp.portfolio, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
        )
    }

    /// [push mark, crank LP, (crank trader if positioned), trade] in ONE transaction.
    /// Run [push, cranks..., tail] pruning cranks that answer 22 (already current); the keeper's prune.
    fn bundle(&mut self, mut cranks: Vec<Pubkey>, tail: Option<(&Trader, &Lp, i128)>) -> Result<(), String> {
        let mut last = Ok(());
        for _ in 0..16 {
            let mut ixs = vec![self.push_ix(self.mark)];
            for p in &cranks {
                ixs.push(self.crank_ix(*p, None));
            }
            let mut extra = vec![self.admin.insecure_clone()];
            if let Some((t, lp, q)) = tail {
                ixs.push(self.trade_ix(t, lp, q));
                extra.push(t.kp.insecure_clone());
            }
            let tail_index = 3 + cranks.len(); // 2 compute-budget ixs, the push, the cranks
            let refs: Vec<&Keypair> = extra.iter().collect();
            last = self.send(ixs, &refs);
            match failing_index(&last) {
                Some(i) if err_code(&last, 22) && i >= 3 && i < tail_index => {
                    cranks.remove(i - 3);
                }
                Some(i) if err_code(&last, 22) && tail.is_none() && i == 2 => break,
                _ => break,
            }
            if cranks.is_empty() && tail.is_none() {
                return Ok(());
            }
        }
        last
    }

    /// An open: [push, LP crank, trade]. 121 (LossStale: other positioned portfolios carry an unsettled loss after a
    /// price move) -> refresh them in their own txs (two per tx: the trade alone needs ~625k CU), then retry.
    fn trade(&mut self, t: &Trader, lp: &Lp, size_q: i128) -> Result<(), String> {
        let mut last = self.bundle(vec![lp.portfolio], Some((t, lp, size_q)));
        if err_code(&last, 121) {
            let others: Vec<Pubkey> = self.positioned.iter().copied().filter(|p| *p != t.portfolio).collect();
            for chunk in others.chunks(2) {
                let mut c = vec![lp.portfolio];
                c.extend_from_slice(chunk);
                let _ = self.bundle(c, None);
            }
            let mut c = vec![lp.portfolio];
            if self.positioned.contains(&t.portfolio) {
                c.push(t.portfolio);
            }
            last = self.bundle(c, Some((t, lp, size_q)));
        }
        if let Err(e) = &last {
            if e.contains("ProgramFailedToComplete") {
                let cu: Vec<&str> = e.match_indices(" consumed ").map(|(i, _)| &e[i..(i + 32).min(e.len())]).collect();
                println!("[compute] open bundle ran out: {cu:?}");
            }
        }
        if last.is_ok() && !self.positioned.contains(&t.portfolio) && self.position(t.portfolio) != 0 {
            self.positioned.push(t.portfolio);
        }
        last
    }

    /// Liquidate `t` through tag 5 (old client: `with_lp = None`) until its position moves.
    fn liquidate(&mut self, t: &Trader, with_lp: Option<Pubkey>) -> i128 {
        let p0 = self.position(t.portfolio);
        for _ in 0..8 {
            let r = self.push_and_crank(&[(t.portfolio, with_lp)]);
            assert!(r.is_ok() || err_code(&r, 22), "push + liquidation crank: {r:?}");
            if r.is_err() {
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
            let p = self.position(t.portfolio);
            if p != p0 {
                return p0 - p;
            }
        }
        panic!("{} was never liquidated", t.portfolio);
    }

    fn lp_key(&self) -> Pubkey {
        Pubkey::new_from_array(state::read_vault_lp_state(&self.data(&self.vault_lp)).unwrap().lp_portfolio)
    }
}

fn failing_index(r: &Result<(), String>) -> Option<usize> {
    let s = r.as_ref().err()?;
    let at = s.find("InstructionError(")? + "InstructionError(".len();
    s[at..].split(',').next()?.trim().parse().ok()
}

fn err_code(r: &Result<(), String>, code: u32) -> bool {
    matches!(r, Err(s) if s.contains(&format!("Custom({code})")))
}

fn rpc_url() -> String {
    std::env::var("F2_RPC_URL").expect("F2_RPC_URL (a running solana-test-validator)")
}

/// Three THIN traders (5 units long each, $1) and one HEALTHY holder (3 units long, $5) vs the bound vault LP, walked to
/// $0.87: the thin ones are below maintenance (equity ~$0.35 < MM ~$0.435) and not bankrupt; the holder is healthy.
fn world() -> (Net, Lp, Vec<Trader>, Trader) {
    let mut n = Net::new(&rpc_url());
    let lp = n.bind();
    let mut ts = Vec::new();
    for _ in 0..3 {
        let t = n.new_trader(1_000_000);
        n.trade(&t, &lp, 5 * POS).expect("open 5 long vs the vault LP");
        ts.push(t);
    }
    let h = n.new_trader(5_000_000);
    n.trade(&h, &lp, 3 * POS).expect("healthy holder opens 3 long");
    assert_eq!(n.a(), (ADL_ONE, ADL_ONE));
    n.move_price(870_000, lp.portfolio);
    assert_eq!(n.a(), (ADL_ONE, ADL_ONE), "walking the price ADLs nothing");
    (n, lp, ts, h)
}

#[test]
#[ignore]
fn f2_validator_old_client_liquidations_latch_the_market() {
    let (mut n, lp, ts, h) = world();
    let lp_pos0 = n.position(lp.portfolio);
    let mut prev = ADL_ONE;
    for (i, t) in ts.iter().enumerate() {
        let closed = n.liquidate(t, None);
        let (al, ash) = n.a();
        println!("[old client] closed {closed} of trader {i}: A_long {al} A_short {ash} (ADL_ONE {ADL_ONE}); LP raw {}", n.position(lp.portfolio));
        assert!(closed > 0 && n.position(t.portfolio) > 0, "a partial, non-bankrupt close");
        assert_eq!(al, ADL_ONE);
        assert!(ash < prev, "each unilateral close scales the LP's short side further");
        prev = ash;
    }
    assert_eq!(n.position(lp.portfolio), lp_pos0, "the LP's raw basis never moved: only its EFFECTIVE size was scaled");
    let fresh = n.new_trader(5_000_000);
    let r = n.trade(&fresh, &lp, POS);
    println!("[old client] new long open: {}", if err_code(&r, 120) { "refused 120 EngineAdlReduceOnly".to_string() } else { format!("{r:?}") });
    assert!(err_code(&r, 120), "every open refused EngineAdlReduceOnly (120): {r:?}");
    let r = n.trade(&fresh, &lp, -POS);
    println!("[old client] new short open: {}", if err_code(&r, 120) { "refused 120".to_string() } else { format!("{r:?}") });
    assert!(err_code(&r, 120), "the other direction too: {r:?}");
    n.trade(&h, &lp, -POS).expect("a holder can still reduce");
    let r = n.trade(&h, &lp, POS);
    assert!(err_code(&r, 120), "but not grow back: {r:?}");
    assert!(n.a().1 < ADL_ONE, "still latched");
    n.assert_conserved("old client");
    println!("[old client] PASS; txs sent: {}", n.sent);
}

#[test]
#[ignore]
fn f2_validator_new_client_liquidations_keep_the_market_open() {
    let (mut n, lp, ts, h) = world();
    for (i, t) in ts.iter().enumerate() {
        let lp_before = n.position(lp.portfolio);
        let closed = n.liquidate(t, Some(lp.portfolio));
        let (al, ash) = n.a();
        println!("[new client] closed {closed} of trader {i}: A_long {al} A_short {ash}; LP raw {lp_before} -> {}", n.position(lp.portfolio));
        assert!(closed > 0 && n.position(t.portfolio) > 0, "a partial, non-bankrupt close");
        assert_eq!((al, ash), (ADL_ONE, ADL_ONE), "matched close: no A factor moved");
        assert_eq!(n.position(lp.portfolio), lp_before + closed, "the LP's short shrank by exactly the closed size");
        let rec = state::read_asset_vault_lp(&n.data(&n.market), 0).unwrap();
        assert_eq!(rec.lp_net_q, n.position(lp.portfolio), "the vault-LP skew snapshot follows the LP's position");
    }
    // Opens land right away; no side was ever closed (the LP still holds a short, every trader still a long).
    let fresh = n.new_trader(5_000_000);
    n.trade(&fresh, &lp, POS).expect("a new long opens after matched liquidations");
    let fresh2 = n.new_trader(5_000_000);
    n.trade(&fresh2, &lp, -POS).expect("a new short opens too");
    n.trade(&h, &lp, POS).expect("an existing holder can grow");
    assert_eq!(n.a(), (ADL_ONE, ADL_ONE));
    assert!(n.position(lp.portfolio) < 0, "the LP side was never closed");
    for t in ts.iter() {
        assert!(n.position(t.portfolio) > 0, "no trader was closed out");
    }
    println!("[new client] opens: long OK, short OK, holder grow OK; LP raw {}", n.position(lp.portfolio));
    n.assert_conserved("new client");
    println!("[new client] PASS; txs sent: {}", n.sent);
}

#[test]
#[ignore]
fn f2_validator_mixed_matched_close_does_not_deepen_an_existing_latch() {
    let (mut n, lp, ts, _h) = world();
    n.liquidate(&ts[0], None);
    let ash = n.a().1;
    assert!(ash < ADL_ONE);
    for t in &ts[1..] {
        let lp_eff_before = n.effective(lp.portfolio);
        let closed = n.liquidate(t, Some(lp.portfolio));
        let ash2 = n.a().1;
        let lp_eff = n.effective(lp.portfolio);
        println!("[mixed] latched A_short {ash}; a matched liquidation closed {closed}: A_short {ash2}; LP effective {lp_eff_before} -> {lp_eff} (raw {})", n.position(lp.portfolio));
        assert_eq!(ash2, ash, "the matched close does not scale the side further");
        // effective sizes are floor-rounded per leg: within 1 unit of the exact matched delta
        assert!((lp_eff - (lp_eff_before + closed)).abs() <= 1, "the LP's EFFECTIVE short shrank by the closed size");
    }
    // An EXISTING latch is not lifted by matched liquidations: opens stay refused until a side is flat (or tag 104).
    let fresh = n.new_trader(5_000_000);
    let r = n.trade(&fresh, &lp, POS);
    println!("[mixed] new long open on the already-latched market: {}", if err_code(&r, 120) { "refused 120".to_string() } else { format!("{r:?}") });
    assert!(err_code(&r, 120), "{r:?}");
    n.assert_conserved("mixed");
    println!("[mixed] PASS; txs sent: {}", n.sent);
}
