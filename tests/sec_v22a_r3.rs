//! Earn-drain replay (Devnet v2 audit, 2026-10-04): LiteSVM replays of LIVE markets, run on the
//! deployed wrapper bytes and on the #175-fixed (E1) bytes.
//!
//! The wrapper bytes come from `INDEP_WRAPPER_SO` (default `target/deploy/percolator_prog.so`):
//! * deployed: `7c906e45` + engine `35ddd692` (`7d1e0021…bb1f`, the live ETDLAdi dump);
//! * fixed:    `7c906e45` + engine `release/v18.3-engine-175` (E1, #175 source reclass).
//!
//! swordcat `6xDeQPKMP2BR3NDWd3oY7oMaVLiaq1UPeNb4K1TAuNF6` was FLAT from creation (slot
//! 507,031,028) until the only user trade, `QCkc1Nic…` (slot 507,168,164): 9VDNak deposits 109.14
//! and shorts 98,579,387,186 q against LP `59UGmZEQ` (1,000), with a non-bound Earn vault of
//! 1,000 per pot and 425 of insurance. Nothing but keeper traffic touches the slab after that. So
//! a fresh market with the decoded live InitMarket / InitMatcherCtx / 74 / 75 parameters, opened
//! at the engine price the wrapper handed the matcher (2,625 e6), followed by EVERY successful
//! keeper instruction on the slab in chain order (`tests/fixtures/earn_drain/`: 11,926
//! PushAuthMark + 2,591 PermissionlessCrank), is a faithful replay. The deployed-bytes run is
//! checked against the live account state at the lp-earn audit snapshot (slot 507,240,948).
//!
//! Slots are shifted by `SLOT_OFFSET` so the market can be created at slot 0 (no accrual gap).
#![cfg(not(kani))]
#![allow(dead_code)]
mod indep_harness;

use indep_harness::*;
use percolator::BOUND_SCALE;
use percolator_prog::{ix::CrankObservationHint, ix::Instruction as ProgInstruction, state};
use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const CANONICAL_MATCHER: &str = "DfTxJUT5BbERs1tR33dP82kaUJ1NLymRxXErXAYXcDam";

/// Live market + LP + Earn + trade parameters, all decoded from the market's own transactions.
#[derive(Clone)]
struct LiveMarket {
    name: &'static str,
    params: V16CuMarketParams,
    /// matcher ctx (tag 53 InitMatcherCtx as sent live)
    m_kind: u8,
    m_fee_bps: u32,
    m_spread_bps: u32,
    m_max_total_bps: u32,
    m_impact_k_bps: u32,
    m_liquidity_e6: u128,
    m_max_fill: u128,
    m_max_inventory: u128,
    lp_capital: u64,
    insurance: u64,
    earn_fee_share_bps: u16,
    earn_cooldown: u64,
    earn_oi_res_bps: u16,
    earn_pots: [u64; 2],
    /// engine price at the first replayed trade (the oracle the wrapper passed the matcher)
    open_price_e6: u64,
    trade_slot: u64,
    /// (capital, size_q, fee_bps, limit_price, backing_fee_cap_bps)
    trades: Vec<(u64, i128, u64, u64, u16)>,
    events_csv: &'static str,
}

fn swordcat() -> LiveMarket {
    LiveMarket {
        name: "swordcat",
        // tag 0 InitMarket, 3LKdrk6m… (slot 507,031,028)
        params: V16CuMarketParams {
            max_portfolio_assets: 14,
            h_min: 1_000,
            h_max: 100_000,
            initial_price: 2_625,
            min_nonzero_mm_req: 1_000_000,
            min_nonzero_im_req: 2_000_000,
            maintenance_margin_bps: 833,
            initial_margin_bps: 1_667,
            max_trading_fee_bps: 5,
            trade_fee_base_bps: 5,
            liquidation_fee_bps: 50,
            liquidation_fee_cap: 10_000_000_000,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 6,
            max_accrual_dt_slots: 100,
            max_abs_funding_e9_per_slot: 0,
            min_funding_lifetime_slots: 500,
            max_account_b_settlement_chunks: 10,
            max_bankrupt_close_chunks: 10,
            max_bankrupt_close_lifetime_slots: 500,
            public_b_chunk_atoms: 1_000_000_000_000,
            maintenance_fee_per_slot: 0,
        },
        // tag 53, 2o6ud5cL…
        m_kind: 1,
        m_fee_bps: 5,
        m_spread_bps: 50,
        m_max_total_bps: 200,
        m_impact_k_bps: 200,
        m_liquidity_e6: 5_000_000_000,
        m_max_fill: 98_580_441_640,
        m_max_inventory: 394_321_766_561,
        lp_capital: 1_000_000_000,
        insurance: 425_000_000,
        // tags 74 / 75 / 75, 3Q6rKMEB…
        earn_fee_share_bps: 1_000,
        earn_cooldown: 150,
        earn_oi_res_bps: 8_000,
        earn_pots: [1_000_000_000, 1_000_000_000],
        open_price_e6: 2_625,
        trade_slot: 507_168_164,
        // QCkc1Nic…: deposit 109.14, TradeCpi size -98,579,387,186, fee 5, limit 2,387, cap 0
        trades: vec![(109_140_000, -98_579_387_186, 5, 2_387, 0)],
        events_csv: "tests/fixtures/earn_drain/swordcat_keeper_events.csv",
    }
}

/// backpack `CzKfk54TNja7UQFyDrHfad8pKSU3QkteZhDhQwkSLDcQ`: InitMarket 5yFPz4gi… (slot 506,304,160),
/// matcher ctx 2VcoSJLT…, LP 3QUmmSAZ 1,000, insurance 100, Earn 1,000 + 1,000 (2GEoaQpB…). Flat
/// until the first trade (AXa339sR / AT6jpcWM short 311,526,479,750 q, 3y4PCxvi…, engine price
/// 2,794); every later user and keeper instruction comes from the fixture, in chain order.
fn backpack() -> LiveMarket {
    LiveMarket {
        name: "backpack",
        params: V16CuMarketParams {
            max_portfolio_assets: 14,
            h_min: 1_000,
            h_max: 100_000,
            initial_price: 2_794,
            min_nonzero_mm_req: 1_000_000,
            min_nonzero_im_req: 2_000_000,
            maintenance_margin_bps: 500,
            initial_margin_bps: 1_000,
            max_trading_fee_bps: 5,
            trade_fee_base_bps: 5,
            liquidation_fee_bps: 50,
            liquidation_fee_cap: 10_000_000_000,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 4,
            max_accrual_dt_slots: 100,
            // InitMarket sets 0: funding is identically zero on this market (f_long = f_short = 0
            // on chain at slot 507,254,978).
            max_abs_funding_e9_per_slot: 0,
            min_funding_lifetime_slots: 500,
            max_account_b_settlement_chunks: 10,
            max_bankrupt_close_chunks: 10,
            max_bankrupt_close_lifetime_slots: 500,
            public_b_chunk_atoms: 1_000_000_000_000,
            maintenance_fee_per_slot: 0,
        },
        m_kind: 1,
        m_fee_bps: 5,
        m_spread_bps: 50,
        m_max_total_bps: 200,
        m_impact_k_bps: 200,
        m_liquidity_e6: 10_000_000_000,
        m_max_fill: 318_066_157_760,
        m_max_inventory: 1_272_264_631_043,
        lp_capital: 1_000_000_000,
        insurance: 100_000_000,
        earn_fee_share_bps: 1_000,
        earn_cooldown: 150,
        earn_oi_res_bps: 8_000,
        earn_pots: [1_000_000_000, 1_000_000_000],
        open_price_e6: 2_794,
        trade_slot: 506_308_793,
        trades: vec![],
        events_csv: "tests/fixtures/earn_drain/backpack_events.csv",
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Snap {
    slot: u64,
    trader_cap: u128,
    trader_pnl: i128,
    lp_cap: u128,
    lp_pnl: i128,
    fresh: [u128; 2],
    valid: [u128; 2],
    consumed: [u128; 2],
    impaired: [u128; 2],
    claim: [u128; 2],
    receivable: [u128; 2],
    spent: [u128; 2],
    rate: [u128; 2],
    vault: u128,
    c_tot: u128,
    ppt: u128,
    insurance: u128,
    fresh_total: u128,
    earnings_total: u128,
    earn_principal: u128,
    earn_nav: u128,
    /// The pre-E3 ledger reading of Earn NAV (`principal - (loss - recovery)`), kept for the
    /// harvest tests' "value is stranded" vacuity guards: the Resolved harvest repairs exactly
    /// the state that reading describes, which E3 no longer leaves stranded in Live.
    earn_nav_ledger: u128,
    p_last: u64,
}

impl Snap {
    /// vault − c_tot − pnl_pos_tot − insurance − Earn NAV: the audit's "unowned" quantity.
    fn unowned(&self) -> i128 {
        self.vault as i128
            - self.c_tot as i128
            - self.ppt as i128
            - self.insurance as i128
            - self.earn_nav as i128
    }
    /// Engine `Residual = V - (C_tot + I + E + F)` (spec §3), the junior pool. Every open claim
    /// here is source-backed (paid from F, never from Residual), so anything in Residual is owned
    /// by nobody.
    /// `unowned` under the pre-E3 ledger reading of Earn NAV.
    fn unowned_ledger(&self) -> i128 {
        self.unowned() + self.earn_nav as i128 - self.earn_nav_ledger as i128
    }
    fn engine_residual(&self) -> i128 {
        self.vault as i128
            - self.c_tot as i128
            - self.insurance as i128
            - self.earnings_total as i128
            - self.fresh_total as i128
    }
    fn earn_loss(&self) -> u128 {
        self.earn_principal.saturating_sub(self.earn_nav)
    }
    fn consumed_total(&self) -> u128 {
        self.consumed[0] + self.consumed[1]
    }
    fn print(&self, label: &str) {
        let u = |x: u128| x as f64 / 1e6;
        let i = |x: i128| x as f64 / 1e6;
        eprintln!(
            "[{label}] slot {} P_last {} | trader cap {:.6} pnl {:.6} | LP cap {:.6} pnl {:.6}",
            self.slot,
            self.p_last,
            u(self.trader_cap),
            i(self.trader_pnl),
            u(self.lp_cap),
            i(self.lp_pnl)
        );
        for d in 0..2 {
            eprintln!(
                "[{label}]   d{d}: fresh {:.6} valid {:.6} consumed {:.6} impaired {:.6} | claim {:.6} receivable {:.6} spent {:.6} rate {:.4}",
                u(self.fresh[d]), u(self.valid[d]), u(self.consumed[d]), u(self.impaired[d]),
                u(self.claim[d]), u(self.receivable[d]), u(self.spent[d]),
                self.rate[d] as f64 / 1e12
            );
        }
        eprintln!(
            "[{label}]   vault {:.6} c_tot {:.6} pnl_pos_tot {:.6} ins {:.6} F {:.6} | Earn principal {:.6} NAV {:.6} loss {:.6} | UNOWNED {:.6} | engine Residual {:.6}",
            u(self.vault), u(self.c_tot), u(self.ppt), u(self.insurance), u(self.fresh_total),
            u(self.earn_principal), u(self.earn_nav), u(self.earn_loss()), i(self.unowned()),
            i(self.engine_residual())
        );
    }
}

struct Replay {
    env: V16CuEnv,
    lm: LiveMarket,
    matcher: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    ledgers: [Pubkey; 2],
    lp_owner: Keypair,
    lp: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
    traders: Vec<(Keypair, Pubkey)>,
    offset: u64,
    push_err: usize,
    crank_err: usize,
    crank_codes: std::collections::BTreeMap<u32, usize>,
    user_err: Vec<String>,
    /// (count, sum, max) CU of successful keeper cranks / pushes.
    crank_cu: (u64, u64, u64),
    push_cu: (u64, u64, u64),
    peak_consumed: u128,
    peak_earn_loss: u128,
}

impl Replay {
    fn new(lm: LiveMarket) -> Self {
        let mut env = V16CuEnv::new_with_init_params(lm.params);
        let matcher: Pubkey = CANONICAL_MATCHER.parse().unwrap();
        let bytes = std::fs::read(matcher_program_path()).expect("matcher so");
        env.svm.add_program(matcher, &bytes);
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, lm.open_price_e6);
        let pid = env.program_id;
        let market = env.market;
        let (registry, _) = state::derive_lp_vault_registry(&pid, &market);
        let (lp_mint, _) = state::derive_lp_vault_mint(&pid, &market);
        let ledgers = [
            state::derive_lp_backing_ledger(&pid, &market, 0).0,
            state::derive_lp_backing_ledger(&pid, &market, 1).0,
        ];
        // LP portfolio + matcher ctx (tags 1, 44, 53), deposit (3), insurance (73).
        let lp_owner = Keypair::new();
        env.svm.airdrop(&lp_owner.pubkey(), 10_000_000_000).unwrap();
        let lp = env.create_portfolio(&lp_owner);
        env.deposit(&lp_owner, lp, lm.lp_capital as u128);
        let mut data = vec![2u8, lm.m_kind];
        data.extend_from_slice(&lm.m_fee_bps.to_le_bytes());
        data.extend_from_slice(&lm.m_spread_bps.to_le_bytes());
        data.extend_from_slice(&lm.m_max_total_bps.to_le_bytes());
        data.extend_from_slice(&lm.m_impact_k_bps.to_le_bytes());
        data.extend_from_slice(&lm.m_liquidity_e6.to_le_bytes());
        data.extend_from_slice(&lm.m_max_fill.to_le_bytes());
        data.extend_from_slice(&lm.m_max_inventory.to_le_bytes());
        let (ctx, delegate, _) = env.init_matcher_context_with_data(&lp_owner, matcher, lp, data);
        if lm.insurance > 0 {
            env.top_up_insurance(lm.insurance as u128);
        }
        let mut r = Replay {
            env,
            lm: lm.clone(),
            matcher,
            registry,
            lp_mint,
            ledgers,
            lp_owner,
            lp,
            ctx,
            delegate,
            traders: Vec::new(),
            offset: 0,
            push_err: 0,
            crank_err: 0,
            crank_codes: Default::default(),
            user_err: Vec::new(),
            crank_cu: (0, 0, 0),
            push_cu: (0, 0, 0),
            peak_consumed: 0,
            peak_earn_loss: 0,
        };
        r.create_vault();
        let creator = Keypair::new();
        r.env
            .svm
            .airdrop(&creator.pubkey(), 10_000_000_000)
            .unwrap();
        for d in 0..2u16 {
            if lm.earn_pots[d as usize] > 0 {
                r.earn_deposit(&creator, lm.earn_pots[d as usize], d)
                    .expect("75 Earn deposit");
            }
        }
        // Map the live trade slot to replay slot 100.
        r.offset = lm.trade_slot - 100;
        r
    }

    fn create_vault(&mut self) {
        let admin = self.env.admin.insecure_clone();
        let (m, reg, mint) = (self.env.market, self.registry, self.lp_mint);
        self.env
            .send(
                ProgInstruction::CreateLpVault {
                    fee_share_bps: self.lm.earn_fee_share_bps,
                    redemption_cooldown_slots: self.lm.earn_cooldown,
                    oi_reservation_threshold_bps: self.lm.earn_oi_res_bps,
                    domain: 0,
                },
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(m, false),
                    AccountMeta::new(reg, false),
                    AccountMeta::new(mint, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                    AccountMeta::new_readonly(self.env.mint, false), // [6] collateral mint (prog#542)
                ],
                &[&admin],
            )
            .expect("74 CreateLpVault");
    }

    fn earn_deposit(&mut self, who: &Keypair, amount: u64, domain: u16) -> Result<u64, String> {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self
            .env
            .token_account_for_mint(self.lp_mint, who.pubkey(), 0);
        let src = self
            .env
            .token_account_for_mint(self.env.mint, who.pubkey(), amount);
        // Live layout (3Q6rKMEB…): [7] is always the REGISTRY-domain ledger, [10] its sibling,
        // whichever pot `domain` targets.
        let (own, sib) = (self.ledgers[0], self.ledgers[1]);
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(ata, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new(own, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(sib, false),
        ];
        self.env.send(
            ProgInstruction::DepositToLpVault {
                amount: amount as u128,
                domain,
            },
            metas,
            &[who],
        )
    }

    fn warp_live(&mut self, live_slot: u64) {
        let s = live_slot - self.offset;
        if s > self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot {
            self.env.svm.warp_to_slot(s);
        }
    }

    fn open_trades(&mut self) {
        self.warp_live(self.lm.trade_slot);
        for (capital, size_q, fee_bps, limit_price, cap) in self.lm.trades.clone() {
            let k = Keypair::new();
            self.env.svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
            let p = self.env.create_portfolio(&k);
            self.env.deposit(&k, p, capital as u128);
            let (aid, _, aep) = self.env.portfolio_identity(p);
            let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
            let market_id = state::read_market_trade_preflight(
                &self.env.svm.get_account(&self.env.market).unwrap().data,
                0,
            )
            .unwrap()
            .3;
            self.env.svm.expire_blockhash();
            self.env
                .send(
                    ProgInstruction::TradeCpi {
                        account_a_portfolio_id: aid,
                        account_a_position_epoch: aep,
                        account_b_portfolio_id: bid,
                        account_b_position_epoch: bep,
                        market_id,
                        account_b_matcher_sequence: bseq,
                        asset_index: 0,
                        size_q,
                        fee_bps,
                        limit_price,
                        backing_fee_cap_bps: cap,
                    },
                    vec![
                        AccountMeta::new(k.pubkey(), true),
                        AccountMeta::new(self.env.market, false),
                        AccountMeta::new(p, false),
                        AccountMeta::new(self.lp, false),
                        AccountMeta::new_readonly(self.matcher, false),
                        AccountMeta::new(self.ctx, false),
                        AccountMeta::new_readonly(self.delegate, false),
                    ],
                    &[&k],
                )
                .unwrap_or_else(|e| panic!("{}: live trade did not replay: {e}", self.lm.name));
            self.traders.push((k, p));
        }
    }

    fn push(&mut self, live_slot: u64, live_now: u64, mark: u64) {
        self.warp_live(live_slot);
        let observation_sequence = self.env.control_sequences(0).oracle_observation + 1;
        let market_id = state::read_market_trade_preflight(
            &self.env.svm.get_account(&self.env.market).unwrap().data,
            0,
        )
        .unwrap()
        .3;
        let admin = self.env.admin.insecure_clone();
        self.env.svm.expire_blockhash();
        let r = self.env.send(
            ProgInstruction::PushAuthMark {
                market_id,
                asset_index: 0,
                now_slot: live_now.saturating_sub(self.offset), // inert: the handler reads the Clock sysvar
                mark_e6: mark,
                observation_sequence,
            },
            vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(self.env.market, false),
            ],
            &[&admin],
        );
        match r {
            Ok(cu) => {
                self.push_cu = (
                    self.push_cu.0 + 1,
                    self.push_cu.1 + cu,
                    self.push_cu.2.max(cu),
                )
            }
            Err(_) => self.push_err += 1,
        }
    }

    fn crank_at(&mut self, live_slot: u64, now_slot: u64, p: Pubkey) {
        self.warp_live(live_slot);
        let payer = self.env.payer.pubkey();
        self.env.svm.expire_blockhash();
        let r = self.env.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: if now_slot == 0 {
                    0
                } else {
                    now_slot.saturating_sub(self.offset)
                },
                observations: vec![CrankObservationHint {
                    asset_index: 0,
                    oracle_accounts: 0,
                }],
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(p, false),
            ],
            &[],
        );
        match r {
            Ok(cu) => {
                self.crank_cu = (
                    self.crank_cu.0 + 1,
                    self.crank_cu.1 + cu,
                    self.crank_cu.2.max(cu),
                )
            }
            Err(e) => {
                self.crank_err += 1;
                *self
                    .crank_codes
                    .entry(custom_code(&e).unwrap_or(u32::MAX))
                    .or_default() += 1;
            }
        }
    }

    /// Earn NAV exactly as the non-bound wrapper prices it (`lp_vault_combined_nav_atoms`).
    /// E3 (2026-10-05): per pot the available principal is the PROGRAM's own pure rule
    /// `vault_lp_v18::nonbound_pot_available(principal, pot_physical_net_atoms(..))`, i.e.
    /// `min(ledger principal, physical backing net of the claims the pot owes)`, plus the LP fee
    /// share of the synced earnings. (Before E3 this mirrored `principal - (loss - recovery)`:
    /// `earn_nav_ledger` keeps that reading for the before/after reports.)
    fn earn_nav(&self, g: &state::MarketGroupV16) -> (u128, u128) {
        self.earn_nav_rule(g, true)
    }

    /// The pre-E3 ledger reading (loss on a rise of consumed + impaired, recovery on a fall).
    fn earn_nav_ledger(&self, g: &state::MarketGroupV16) -> (u128, u128) {
        self.earn_nav_rule(g, false)
    }

    fn earn_nav_rule(&self, g: &state::MarketGroupV16, e3: bool) -> (u128, u128) {
        let mut principal = 0u128;
        let mut nav = 0u128;
        for d in 0..2usize {
            let Some(acc) = self.env.svm.get_account(&self.ledgers[d]) else {
                continue;
            };
            let Ok(l) = state::read_backing_domain_ledger(&acc.data) else {
                continue;
            };
            let b = &g.source_backing_buckets[d];
            let unavailable =
                (b.consumed_liened_backing_num + b.impaired_liened_backing_num) / BOUND_SCALE;
            let (mut loss, mut rec) = (l.cumulative_loss_atoms, l.cumulative_recovery_atoms);
            if unavailable >= l.last_observed_unavailable_principal_atoms {
                loss += unavailable - l.last_observed_unavailable_principal_atoms;
            } else {
                rec += l.last_observed_unavailable_principal_atoms - unavailable;
            }
            let earn = (l.total_earnings_atoms + b.utilization_fee_earnings
                - l.last_observed_bucket_earnings_atoms
                    .min(b.utilization_fee_earnings))
            .saturating_sub(l.total_earnings_withdrawn_atoms);
            let lp_earn = earn * self.lm.earn_fee_share_bps as u128 / 10_000;
            principal += l.total_principal_atoms;
            let available = if e3 {
                let c = &g.source_credit[d];
                let ins_cover = c.insurance_credit_reserved_num.saturating_sub(
                    c.valid_liened_insurance_num + c.impaired_liened_insurance_num,
                );
                percolator_prog::vault_lp_v18::nonbound_pot_available(
                    l.total_principal_atoms,
                    percolator_prog::vault_lp_v18::pot_physical_net_atoms(
                        b.fresh_unliened_backing_num,
                        b.valid_liened_backing_num,
                        c.positive_claim_bound_num,
                        ins_cover,
                        BOUND_SCALE,
                    ),
                )
            } else {
                l.total_principal_atoms.saturating_sub(loss.saturating_sub(rec))
            };
            nav += available + lp_earn;
        }
        (principal, nav)
    }

    fn snap(&self) -> Snap {
        let (_, g) = self.env.market_state();
        let pf = |k: Pubkey| {
            self.env
                .svm
                .get_account(&k)
                .and_then(|a| state::read_portfolio(&a.data).ok())
                .map(|s| (s.capital, s.pnl))
                .unwrap_or((0, 0))
        };
        let (lp_capital, lp_pnl) = pf(self.lp);
        let (tc, tpnl) = self.traders.first().map(|(_, p)| pf(*p)).unwrap_or((0, 0));
        let (earn_principal, earn_nav) = self.earn_nav(&g);
        let earn_nav_ledger = self.earn_nav_ledger(&g).1;
        let mut s = Snap {
            slot: self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot + self.offset,
            trader_cap: tc,
            trader_pnl: tpnl,
            lp_cap: lp_capital,
            lp_pnl,
            vault: g.vault,
            c_tot: g.c_tot,
            ppt: g.pnl_pos_tot,
            insurance: g.insurance,
            fresh_total: g.source_fresh_backing_total_num / BOUND_SCALE,
            earnings_total: g.backing_provider_earnings_total,
            earn_principal,
            earn_nav,
            earn_nav_ledger,
            p_last: g.assets[0].effective_price,
            ..Default::default()
        };
        for d in 0..2 {
            let b = &g.source_backing_buckets[d];
            let c = &g.source_credit[d];
            s.fresh[d] = b.fresh_unliened_backing_num / BOUND_SCALE;
            s.valid[d] = b.valid_liened_backing_num / BOUND_SCALE;
            s.consumed[d] = b.consumed_liened_backing_num / BOUND_SCALE;
            s.impaired[d] = b.impaired_liened_backing_num / BOUND_SCALE;
            s.claim[d] = c.positive_claim_bound_num / BOUND_SCALE;
            s.receivable[d] = c.provider_receivable_num / BOUND_SCALE;
            s.spent[d] = c.spent_backing_num / BOUND_SCALE;
            s.rate[d] = c.credit_rate_num;
        }
        s
    }

    fn portfolio_for(&self, code: &str) -> Pubkey {
        match code {
            "L" => self.lp,
            "T" => self.traders[0].1,
            n => self.traders[n.parse::<usize>().expect("user code") - 1].1,
        }
    }

    fn user_op(&mut self, e: &Ev) {
        self.warp_live(e.slot);
        let r: Result<u64, String> = match e.k {
            'i' => {
                let k = Keypair::new();
                self.env.svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
                let p = self.env.create_portfolio(&k);
                assert_eq!(
                    self.traders.len() + 1,
                    e.user,
                    "users are numbered in creation order"
                );
                self.traders.push((k, p));
                Ok(0)
            }
            'd' => {
                let (k, p) = (
                    self.traders[e.user - 1].0.insecure_clone(),
                    self.traders[e.user - 1].1,
                );
                let src =
                    self.env
                        .token_account_for_mint(self.env.mint, k.pubkey(), e.amount as u64);
                let (pid, seq, _) = self.env.portfolio_identity(p);
                self.env.svm.expire_blockhash();
                self.env.send(
                    ProgInstruction::Deposit {
                        portfolio_id: pid,
                        expected_sequence: seq,
                        amount: e.amount,
                    },
                    vec![
                        AccountMeta::new(k.pubkey(), true),
                        AccountMeta::new(self.env.market, false),
                        AccountMeta::new(p, false),
                        AccountMeta::new(src, false),
                        AccountMeta::new(self.env.vault, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                    ],
                    &[&k],
                )
            }
            'w' => {
                let (k, p) = (
                    self.traders[e.user - 1].0.insecure_clone(),
                    self.traders[e.user - 1].1,
                );
                let dest = self
                    .env
                    .token_account_for_mint(self.env.mint, k.pubkey(), 0);
                let (pid, seq, _) = self.env.portfolio_identity(p);
                self.env.svm.expire_blockhash();
                self.env.send(
                    ProgInstruction::Withdraw {
                        portfolio_id: pid,
                        expected_sequence: seq,
                        amount: e.amount,
                    },
                    vec![
                        AccountMeta::new(k.pubkey(), true),
                        AccountMeta::new(self.env.market, false),
                        AccountMeta::new(p, false),
                        AccountMeta::new(dest, false),
                        AccountMeta::new(self.env.vault, false),
                        AccountMeta::new_readonly(self.env.vault_authority, false),
                        AccountMeta::new_readonly(spl_token::ID, false),
                    ],
                    &[&k],
                )
            }
            't' => {
                let (k, p) = (
                    self.traders[e.user - 1].0.insecure_clone(),
                    self.traders[e.user - 1].1,
                );
                self.trade_live(&k, p, e.size, e.fee, e.limit, e.cap)
            }
            _ => unreachable!(),
        };
        if let Err(err) = r {
            self.user_err.push(format!(
                "{} slot {} user {}: {:?}",
                e.k,
                e.slot,
                e.user,
                custom_code(&err)
            ));
        }
    }

    fn trade_live(
        &mut self,
        k: &Keypair,
        p: Pubkey,
        size_q: i128,
        fee_bps: u64,
        limit_price: u64,
        cap: u16,
    ) -> Result<u64, String> {
        let (aid, _, aep) = self.env.portfolio_identity(p);
        let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
        let market_id = state::read_market_trade_preflight(
            &self.env.svm.get_account(&self.env.market).unwrap().data,
            0,
        )
        .unwrap()
        .3;
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id,
                account_b_matcher_sequence: bseq,
                asset_index: 0,
                size_q,
                fee_bps,
                limit_price,
                backing_fee_cap_bps: cap,
            },
            vec![
                AccountMeta::new(k.pubkey(), true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(p, false),
                AccountMeta::new(self.lp, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(self.ctx, false),
                AccountMeta::new_readonly(self.delegate, false),
            ],
            &[k],
        )
    }

    /// Replay every event with live tx slot <= `until`; returns the snapshot there.
    fn run_to(&mut self, events: &[Ev], cursor: &mut usize, until: u64) -> Snap {
        while *cursor < events.len() && events[*cursor].slot <= until {
            let e = events[*cursor].clone();
            match e.k {
                'p' => self.push(e.slot, e.now, e.mark),
                'c' => {
                    for w in &e.who {
                        let p = self.portfolio_for(w);
                        self.crank_at(e.slot, e.now, p);
                    }
                }
                _ => self.user_op(&e),
            }
            *cursor += 1;
            if (*cursor).is_multiple_of(50) {
                let s = self.snap();
                self.peak_consumed = self.peak_consumed.max(s.consumed_total());
                self.peak_earn_loss = self.peak_earn_loss.max(s.earn_loss());
            }
        }
        self.snap()
    }
}

#[derive(Clone, Debug)]
struct Ev {
    k: char,
    slot: u64,
    now: u64,
    mark: u64,
    who: Vec<String>,
    user: usize,
    amount: u128,
    size: i128,
    fee: u64,
    limit: u64,
    cap: u16,
}

fn load_events(path: &str) -> Vec<Ev> {
    let full = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("{full}: {e}"))
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            let mut e = Ev {
                k: f[0].chars().next().unwrap(),
                slot: f[1].parse().unwrap(),
                now: 0,
                mark: 0,
                who: vec![],
                user: 0,
                amount: 0,
                size: 0,
                fee: 0,
                limit: 0,
                cap: 0,
            };
            match e.k {
                'p' => {
                    e.now = f[2].parse().unwrap();
                    e.mark = f[3].parse().unwrap();
                }
                'c' => {
                    e.now = f[2].parse().unwrap();
                    e.who = if f[3].contains('|') || f[3].parse::<usize>().is_ok() || f[3] == "L" {
                        f[3].split('|').map(String::from).collect()
                    } else {
                        // swordcat format: one letter per portfolio ("L", "T")
                        f[3].chars().map(|c| c.to_string()).collect()
                    };
                }
                'i' => e.user = f[2].parse().unwrap(),
                'd' | 'w' => {
                    e.user = f[2].parse().unwrap();
                    e.amount = f[3].parse().unwrap();
                }
                't' => {
                    e.user = f[2].parse().unwrap();
                    e.size = f[3].parse().unwrap();
                    e.fee = f[4].parse().unwrap();
                    e.limit = f[5].parse().unwrap();
                    e.cap = f[6].parse().unwrap();
                }
                other => panic!("unknown event kind {other}"),
            }
            e
        })
        .collect()
}

/// Audit snapshot slot (`audit-2026-10-04/lp-earn.md`, scan.json).
const AUDIT_SLOT: u64 = 507_240_948;

fn run_swordcat() -> (Replay, Snap, Snap, Snap) {
    let lm = swordcat();
    let events = load_events(lm.events_csv);
    let mut r = Replay::new(lm);
    r.open_trades();
    let after_trade = r.snap();
    let mut cur = 0usize;
    let at_audit = r.run_to(&events, &mut cur, AUDIT_SLOT);
    let end = r.run_to(&events, &mut cur, u64::MAX);
    (r, after_trade, at_audit, end)
}

/// Report: deployed vs fixed bytes, swordcat end to end. Run once per `INDEP_WRAPPER_SO`.
/// Asserts only that the replay itself is faithful enough to read (every keeper push lands).
#[test]
fn swordcat_replay_report() {
    let (r, t0, a, e) = run_swordcat();
    eprintln!("wrapper so: {:?}", std::env::var("INDEP_WRAPPER_SO").ok());
    t0.print("after trade");
    a.print("audit slot 507240948");
    e.print("end (507250189)");
    eprintln!(
        "CU keeper cranks n={} mean={} max={} | pushes n={} mean={} max={}",
        r.crank_cu.0,
        r.crank_cu.1 / r.crank_cu.0.max(1),
        r.crank_cu.2,
        r.push_cu.0,
        r.push_cu.1 / r.push_cu.0.max(1),
        r.push_cu.2
    );
    eprintln!(
        "push errors {} / crank errors {} {:?} | peak consumed {:.6} | peak Earn loss {:.6}",
        r.push_err,
        r.crank_err,
        r.crank_codes,
        r.peak_consumed as f64 / 1e6,
        r.peak_earn_loss as f64 / 1e6
    );
    assert_eq!(r.push_err, 0, "every live push must replay");
}

/// E1 acceptance on the live path: after every keeper settlement of the one swordcat position, the
/// engine leaves NO unowned residual (`V - C_tot - I - E - F`, with every open claim source-backed).
/// RED on deployed bytes (the netted support falls into Residual: 1,575 at the audit slot), GREEN on
/// E1 (the support is booked into the loss domain's pot).
#[test]
fn swordcat_engine_residual_is_dust_after_live_walk() {
    let (_r, _t0, a, e) = run_swordcat();
    for (label, s) in [("audit", a), ("end", e)] {
        assert_eq!(
            s.ppt,
            s.claim[0] + s.claim[1],
            "{label}: every open claim is source-backed"
        );
        assert!(
            s.engine_residual() <= 2,
            "{label}: {} atoms of vault value owned by nobody (consumed {:?})",
            s.engine_residual(),
            s.consumed
        );
    }
}

/// The single-trade drain, as an invariant: once the market has netted, Earn's booked loss can
/// never exceed what open winners are still owed (their positive claims), because that is the
/// only value the pots have actually paid out. RED on deployed bytes (#175: 1,378.93 booked
/// against 207.61 of open claims at the audit slot live), GREEN on E1.
#[test]
fn swordcat_earn_loss_bounded_by_open_claims() {
    let (_r, _t0, a, e) = run_swordcat();
    for (label, s) in [("audit", a), ("end", e)] {
        let open_claims = s.claim[0] + s.claim[1];
        assert!(
            s.earn_loss() <= open_claims + 1,
            "{label}: Earn booked {} of loss against {} of open winner claims (consumed {:?}, unowned {})",
            s.earn_loss(),
            open_claims,
            s.consumed,
            s.unowned()
        );
    }
}

// ---------------------------------------------------------------------------------------------
// R-2 PoC (security review of bc228e1b, "NAV round trip through I-2 attribution", MEDIUM, never
// PoC'd). The non-bound ledger books EVERY rise of a pot's consumed backing as vault loss and
// every fall as recovery, regardless of WHOSE backing was consumed. An actor who controls both
// legs of a zero-sum pair can therefore move the vault's NAV with their own money:
//   1. pair A1 long / A2 short against the LP; price up; A1 converts its gain. The conversion
//      consumes pot d1 (A1's source), which A2's loss had just refilled: physically the pot is
//      whole, but the ledger books A1's payout as Earn loss. NAV drops (kept <= 10%, so R-1 and
//      the either-pot rule still accept deposits).
//   2. E deposits at the depressed NAV.
//   3. price up again: A2's new loss is routed to d1 and refills the receivable, which the ledger
//      books as RECOVERY. NAV is back at par. A1 holds the new gain unconverted.
//   4. E redeems at the restored NAV.
//   5. A1 converts: the consumption is booked as loss on whoever still holds shares.
// The pair nets to zero (A1 + A2), so every token E takes out above its deposit comes from the
// incumbent's NAV. The test asserts the safety property and is RED on the deployed bytes.
// ---------------------------------------------------------------------------------------------

fn r2_market() -> LiveMarket {
    LiveMarket {
        name: "r2",
        params: V16CuMarketParams {
            max_portfolio_assets: 14,
            h_min: 1,
            h_max: 10,
            initial_price: 1_000_000,
            min_nonzero_mm_req: 1_000,
            min_nonzero_im_req: 2_000,
            maintenance_margin_bps: 500,
            initial_margin_bps: 1_000,
            max_trading_fee_bps: 100,
            trade_fee_base_bps: 0,
            liquidation_fee_bps: 0,
            liquidation_fee_cap: 0,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 40,
            max_accrual_dt_slots: 10,
            max_abs_funding_e9_per_slot: 0,
            min_funding_lifetime_slots: 500,
            max_account_b_settlement_chunks: 10,
            max_bankrupt_close_chunks: 10,
            max_bankrupt_close_lifetime_slots: 500,
            public_b_chunk_atoms: 1_000_000_000_000,
            maintenance_fee_per_slot: 0,
        },
        m_kind: 0,
        m_fee_bps: 0,
        m_spread_bps: 0,
        m_max_total_bps: 0,
        m_impact_k_bps: 0,
        m_liquidity_e6: 0,
        m_max_fill: u128::MAX,
        m_max_inventory: 0,
        lp_capital: 10_000_000_000,
        insurance: 0,
        earn_fee_share_bps: 0,
        earn_cooldown: 1,
        earn_oi_res_bps: 8_000,
        earn_pots: [1_000_000_000, 1_000_000_000],
        open_price_e6: 1_000_000,
        trade_slot: 100,
        trades: vec![],
        events_csv: "",
    }
}

impl Replay {
    fn now(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }
    /// Walk the authenticated mark to `target` within the per-slot cap, settling `who` each slot.
    fn walk(&mut self, target: u64, who: &[Pubkey]) {
        loop {
            let s = self.now() + 1;
            self.env.svm.warp_to_slot(s);
            self.env.push_auth_mark_for_asset_as_admin(0, s, target);
            for p in who {
                self.crank_pf(*p);
            }
            let (_, g) = self.env.market_state();
            if g.assets[0].effective_price == target
                && g.assets[0].slot_last == g.current_slot
                && !g.loss_stale_active
            {
                break;
            }
        }
    }
    fn crank_pf(&mut self, p: Pubkey) {
        let slot = self.now();
        let payer = self.env.payer.pubkey();
        self.env.svm.expire_blockhash();
        let _ = slot;
        let r = self.env.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: 0,
                observations: vec![CrankObservationHint {
                    asset_index: 0,
                    oracle_accounts: 0,
                }],
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(p, false),
            ],
            &[],
        );
        if let Err(e) = r {
            if std::env::var("R2_DEBUG").is_ok() {
                eprintln!("crank {p} err {:?}", custom_code(&e));
            }
        }
    }
    fn new_trader(&mut self, capital: u64) -> (Keypair, Pubkey) {
        let k = Keypair::new();
        self.env.svm.airdrop(&k.pubkey(), 10_000_000_000).unwrap();
        let p = self.env.create_portfolio(&k);
        self.env.deposit(&k, p, capital as u128);
        (k, p)
    }
    fn trade(&mut self, k: &Keypair, p: Pubkey, size_q: i128) -> Result<u64, String> {
        let (aid, _, aep) = self.env.portfolio_identity(p);
        let (bid, bseq, bep) = self.env.portfolio_identity(self.lp);
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: aid,
                account_a_position_epoch: aep,
                account_b_portfolio_id: bid,
                account_b_position_epoch: bep,
                market_id: 1,
                account_b_matcher_sequence: bseq,
                asset_index: 0,
                size_q,
                fee_bps: 0,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(k.pubkey(), true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(p, false),
                AccountMeta::new(self.lp, false),
                AccountMeta::new_readonly(self.matcher, false),
                AccountMeta::new(self.ctx, false),
                AccountMeta::new_readonly(self.delegate, false),
            ],
            &[k],
        )
    }
    /// Hold the mark for `slots` (warmup), settling `who`.
    fn hold(&mut self, slots: u64, who: &[Pubkey]) {
        let (_, g) = self.env.market_state();
        if g.mode != percolator::MarketModeV16::Live {
            // Resolved: no marks to push; only the clock moves.
            let s = self.now() + slots;
            self.env.svm.warp_to_slot(s);
            return;
        }
        let px = g.assets[0].effective_price;
        for _ in 0..slots {
            let s = self.now() + 1;
            self.env.svm.warp_to_slot(s);
            self.env.push_auth_mark_for_asset_as_admin(0, s, px);
            for p in who {
                self.crank_pf(*p);
            }
        }
    }
    fn convert_all(&mut self, k: &Keypair, p: Pubkey) -> Result<u128, String> {
        let st = self.env.portfolio_state(p);
        let amt = st.pnl.max(0) as u128;
        let (portfolio_id, _, position_epoch) = self.env.portfolio_identity(p);
        self.env.svm.expire_blockhash();
        self.env
            .send(
                ProgInstruction::ConvertReleasedPnl {
                    portfolio_id,
                    position_epoch,
                    amount: u64::MAX as u128,
                },
                vec![
                    AccountMeta::new(k.pubkey(), true),
                    AccountMeta::new(self.env.market, false),
                    AccountMeta::new(p, false),
                ],
                &[k],
            )
            .map(|_| amt)
    }
    fn deposit_shares(
        &mut self,
        who: &Keypair,
        amount: u64,
        domain: u16,
    ) -> Result<(Pubkey, u64), String> {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self
            .env
            .token_account_for_mint(self.lp_mint, who.pubkey(), 0);
        let src = self
            .env
            .token_account_for_mint(self.env.mint, who.pubkey(), amount);
        let metas = vec![
            AccountMeta::new(who.pubkey(), true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(ata, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new(self.ledgers[0], false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.ledgers[1], false),
        ];
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::DepositToLpVault {
                amount: amount as u128,
                domain,
            },
            metas,
            &[who],
        )?;
        Ok((ata, self.env.token_amount(ata)))
    }
    /// 76 then (after the cooldown) 77; returns the SPL paid to the holder.
    fn redeem_all(&mut self, who: &Keypair, ata: Pubkey) -> Result<u64, String> {
        let shares = self.env.token_amount(ata) as u128;
        let pid = self.env.program_id;
        let escrow = state::derive_lp_escrow(&pid, &self.env.market).0;
        let red = state::derive_lp_redemption(&pid, &self.registry, &who.pubkey()).0;
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::RequestRedeemLpShares { shares },
            vec![
                AccountMeta::new(who.pubkey(), true),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(escrow, false),
                AccountMeta::new(red, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[who],
        )?;
        self.hold(self.lm.earn_cooldown + 1, &[]);
        let dest = self
            .env
            .token_account_for_mint(self.env.mint, who.pubkey(), 0);
        let payer = self.env.payer.pubkey();
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::ExecuteRedemption { domain: 0 },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(red, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(escrow, false),
                AccountMeta::new(self.env.vault, false),
                AccountMeta::new_readonly(self.env.vault_authority, false),
                AccountMeta::new(self.ledgers[0], false),
                AccountMeta::new(dest, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new(self.ledgers[1], false),
                AccountMeta::new(who.pubkey(), true), // H-1(b): the redeemer signs a Live non-bound 77
            ],
            &[who],
        )?;
        Ok(self.env.token_amount(dest))
    }
    fn share_supply(&self) -> u64 {
        use solana_sdk::program_pack::Pack;
        spl_token::state::Mint::unpack(&self.env.svm.get_account(&self.lp_mint).unwrap().data)
            .unwrap()
            .supply
    }
}

#[derive(Debug)]
struct R2Outcome {
    nav_before_entry: u128,
    e_deposit: u64,
    e_shares: u64,
    nav_at_exit: u128,
    e_paid: u64,
    incumbent_nav_end: u128,
    incumbent_principal: u128,
    pair_net: i128,
    pots_physical_minus_claims_end: i128,
}

/// Steps 1-5 above. `l1` and `l2` are the two price legs in e6 (on a 1,000-token pair at 1.0).
fn run_r2(l1: u64, l2: u64, e_deposit: u64, e_pot: u16) -> R2Outcome {
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    let pair = [a1, a2, r.lp];
    // 1. pair open; price up l1; both legs closed; A1 converts its released gain.
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    r.walk(1_000_000 + l1, &pair);
    r.trade(&a1k, a1, -q).expect("A1 close");
    r.trade(&a2k, a2, q).expect("A2 close");
    r.hold(r.lm.params.h_max + 2, &pair);
    r.convert_all(&a1k, a1).expect("A1 convert #1");
    let s1 = r.snap();
    s1.print("R-2 after step 1 (A1 converted)");
    // 2. E enters at the depressed NAV (R-1: impairment <= 10%).
    let e = Keypair::new();
    let (e_ata, e_shares) = r
        .deposit_shares(&e, e_deposit, e_pot)
        .expect("E 75 at the depressed NAV");
    // 3. pair re-opened; price up l2: A2's loss refills d1 (booked as RECOVERY); A1 holds its new
    //    gain as an unconverted claim.
    r.trade(&a1k, a1, q).expect("A1 long #2");
    r.trade(&a2k, a2, -q).expect("A2 short #2");
    r.walk(1_000_000 + l1 + l2, &pair);
    r.trade(&a1k, a1, -q).expect("A1 close #2");
    r.trade(&a2k, a2, q).expect("A2 close #2");
    r.hold(r.lm.params.h_max + 2, &pair);
    let s3 = r.snap();
    s3.print("R-2 after step 3 (A2 loss refilled d1)");
    for (n, pk) in [("A1", a1), ("A2", a2), ("LP", r.lp)] {
        let st = r.env.portfolio_state(pk);
        eprintln!(
            "R-2 step3 {n}: cap {} pnl {} src {:?} legs {:?}",
            st.capital,
            st.pnl,
            st.source_claim_bound_num,
            st.legs
                .iter()
                .filter(|l| l.basis_pos_q != 0)
                .map(|l| l.basis_pos_q)
                .collect::<Vec<_>>()
        );
    }
    // 4. E exits at the restored NAV.
    let e_paid = r.redeem_all(&e, e_ata).expect("E 77");
    eprintln!("R-2 E deposited {e_deposit} for {e_shares} shares; paid {e_paid}");
    // 5. A1 converts the second gain: the consumption is booked on the remaining holders.
    r.hold(r.lm.params.h_max + 2, &pair);
    r.convert_all(&a1k, a1).expect("A1 convert #2");
    let s5 = r.snap();
    s5.print("R-2 after step 5 (A1 converted #2)");
    let st1 = r.env.portfolio_state(a1);
    let st2 = r.env.portfolio_state(a2);
    let pair_net = st1.capital as i128 + st1.pnl + st2.capital as i128 + st2.pnl - 2_000_000_000;
    let phys: i128 = (0..2)
        .map(|d| (s5.fresh[d] + s5.valid[d]) as i128 - s5.claim[d] as i128)
        .sum();
    R2Outcome {
        nav_before_entry: s1.earn_nav,
        e_deposit,
        e_shares,
        nav_at_exit: s3.earn_nav,
        e_paid,
        incumbent_nav_end: s5.earn_nav,
        incumbent_principal: s5.earn_principal,
        pair_net,
        pots_physical_minus_claims_end: phys,
    }
}

/// R-2 safety property: an Earn deposit/redeem round trip by an actor whose own trading is
/// zero-sum cannot take value from the incumbent holder. RED on the deployed bytes AND on E1 (the
/// PoC): +89.50 taken from a 2,000 incumbent at 9% entry impairment. Closes with E3 (charge the
/// vault only its pro-rata share of pot consumption / credit loss-routed gross as recovery).
/// GREEN since E3 (2026-10-05, physical attribution `nonbound_available_e3`).
#[test]
fn r2_attribution_round_trip_cannot_extract_from_incumbents() {
    // l1 = 9% of vault principal (under R-1's 10% entry pause), l2 = l1.
    let o = run_r2(180_000, 180_000, 1_800_000_000, 0);
    eprintln!("R-2 outcome: {o:#?}");
    assert!(
        o.e_paid as u128 <= o.e_deposit as u128,
        "R-2: E deposited {} and redeemed {} ({} of value taken); incumbent NAV {} on principal {}; \
         the pair nets {} and the pots still physically hold {} net of claims",
        o.e_deposit,
        o.e_paid,
        o.e_paid as i128 - o.e_deposit as i128,
        o.incumbent_nav_end,
        o.incumbent_principal,
        o.pair_net,
        o.pots_physical_minus_claims_end
    );
}

// ---------------------------------------------------------------------------------------------
// backpack: the winner AT6jpcWM (short 311,526 from 0.002794 into a fall to 0.000175) should be up
// about +811 by K; on chain it holds pnl +4.36 with capital 757.90. Funding is 0 by config.
// ---------------------------------------------------------------------------------------------

/// Live account state read at slot 507,254,978 (getMultipleAccounts, decoded by state::read_*).
const BP_LIVE_WIN_CAP: u128 = 757_902_064;
const BP_LIVE_WIN_PNL: i128 = 4_361_367;
const BP_LIVE_LP_CAP: u128 = 296_030_155;
const BP_LIVE_CONSUMED: [u128; 2] = [1_000_208_896, 1_068_095_752];

fn run_backpack() -> (Replay, Vec<(u64, Snap)>) {
    let lm = backpack();
    let events = load_events(lm.events_csv);
    let mut r = Replay::new(lm);
    let mut cur = 0usize;
    let mut out = Vec::new();
    // checkpoints: after the first trade, the bottom of each leg, and the end
    for cp in [
        506_308_793u64,
        506_361_042,
        506_461_455,
        506_866_188,
        507_167_466,
        507_240_948,
        u64::MAX,
    ] {
        let s = r.run_to(&events, &mut cur, cp);
        out.push((cp, s));
    }
    (r, out)
}

#[test]
fn backpack_replay_report() {
    let (r, snaps) = run_backpack();
    eprintln!("wrapper so: {:?}", std::env::var("INDEP_WRAPPER_SO").ok());
    for (cp, s) in &snaps {
        s.print(&format!("backpack <= {cp}"));
    }
    eprintln!(
        "CU keeper cranks n={} mean={} max={} | pushes n={} mean={} max={}",
        r.crank_cu.0,
        r.crank_cu.1 / r.crank_cu.0.max(1),
        r.crank_cu.2,
        r.push_cu.0,
        r.push_cu.1 / r.push_cu.0.max(1),
        r.push_cu.2
    );
    eprintln!(
        "push errors {} / crank errors {} {:?} / user errors {:?} | peak consumed {:.6} | peak Earn loss {:.6}",
        r.push_err,
        r.crank_err,
        r.crank_codes,
        r.user_err,
        r.peak_consumed as f64 / 1e6,
        r.peak_earn_loss as f64 / 1e6
    );
    let end = snaps.last().unwrap().1;
    let lp = r.env.portfolio_state(r.lp);
    eprintln!(
        "LIVE (507,254,978): winner cap {} pnl {} | LP cap {} | consumed {:?}",
        BP_LIVE_WIN_CAP, BP_LIVE_WIN_PNL, BP_LIVE_LP_CAP, BP_LIVE_CONSUMED
    );
    eprintln!(
        "REPLAY end:          winner cap {} pnl {} | LP cap {} | consumed {:?}",
        end.trader_cap, end.trader_pnl, lp.capital, end.consumed
    );
    let w = r.env.portfolio_state(r.traders[0].1);
    eprintln!(
        "winner resid_cryst {} resid_spent {} resid_recv {} src {:?}",
        w.residual_crystallized_loss_atoms_total,
        w.residual_spent_principal_atoms_total,
        w.residual_received_atoms_total,
        w.source_claim_bound_num
    );
}

/// backpack's "missing +811": the short winner keeps what K says it won. Funding is identically 0
/// on this market (config), so equity − deposits must equal the K gain minus fees:
/// 311,526.48 × (0.002794 − 0.000175) − 0.435 entry fee = +815.45. RED on deployed bytes (the
/// round-trip netting drains d0 into Residual, d0's credit rate collapses, and every later loss
/// burns face at 1/rate: live pnl +4.36), GREEN on E1. The engine residual must also be dust.
#[test]
fn backpack_winner_keeps_k_gain_and_no_unowned_residual() {
    let (r, snaps) = run_backpack();
    let end = snaps.last().unwrap().1;
    let deposited: i128 = 99_500_000 + 800_000_000;
    let gain = end.trader_cap as i128 + end.trader_pnl - deposited;
    assert!(
        gain >= 815_000_000,
        "winner AT6jpcWM: equity gain {} (cap {} pnl {}), K implies +815.45; user errors {:?}",
        gain,
        end.trader_cap,
        end.trader_pnl,
        r.user_err
    );
    assert!(
        end.engine_residual() <= 2,
        "{} atoms owned by nobody",
        end.engine_residual()
    );
}

/// lp-earn §8's "second leak path": a 75 deposit into a pot that carries a provider receivable
/// pays the receivable down with the NEW depositor's principal, and the non-bound ledger never
/// books that as recovery. Step 1 of the R-2 world (pots physically whole, 180 booked as loss),
/// then a deposit into d1. Safety property: after the deposit, NAV equals the pots' physical
/// backing net of open claims. RED on deployed and E1 (needs E3: the add-path refill).
/// GREEN since E3 (2026-10-05): NAV is the pots' physical backing net of claims.
#[test]
fn deposit_refilling_a_receivable_is_booked_as_recovery() {
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    // MEASURED witness (2026-10-05): an incumbent H whose redemption reveals the program's own
    // NAV (the mirror below is the program's pure rule, so on its own it cannot catch a handler
    // that does not apply it). Ledger rule: H ~940; E3: H whole at 1,000.
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, 1_000_000_000, 0).expect("H 75");
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    let pair = [a1, a2, r.lp];
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    r.walk(1_180_000, &pair);
    r.trade(&a1k, a1, -q).expect("A1 close");
    r.trade(&a2k, a2, q).expect("A2 close");
    r.hold(r.lm.params.h_max + 2, &pair);
    r.convert_all(&a1k, a1).expect("A1 convert");
    let before = r.snap();
    assert_eq!(before.consumed[1], 180_000_000, "d1 carries the receivable");
    let e = Keypair::new();
    r.deposit_shares(&e, 1_800_000_000, 1).expect("75 into d1");
    let s = r.snap();
    s.print("after 75 into the receivable pot");
    let phys: u128 = (0..2).map(|d| s.fresh[d] + s.valid[d] - s.claim[d]).sum();
    assert_eq!(
        s.earn_nav, phys,
        "NAV {} vs physical {}: the depositor's principal paid the receivable (consumed {:?}) and no recovery was booked",
        s.earn_nav, phys, s.consumed
    );
    let h_paid = r.redeem_all(&h, h_ata).expect("H 77");
    assert!(
        (h_paid as i128 - 1_000_000_000).abs() <= 2,
        "measured: H paid {h_paid} for 1,000e6 (the refill must not dilute the incumbent)"
    );
}

// ---------------------------------------------------------------------------------------------
// Resolved terminal harvest for NON-bound Earn vaults (§5 of earn-drain-replay-2026-10-04.md).
// On a resolved, terminal-flat market, value that no account owns must reach the Earn holders:
//   (a) engine Residual `V - (C + I + E + F)` (on the deployed engine, #175 round-trip support);
//   (b) pot backing the non-bound ledger does not credit (I-2: a receivable refilled by another
//       actor's loss, booked as Earn loss).
// Before the fix tag 78 refuses every non-bound Resolved call (EngineLockActive) and 77 prices
// from the ledger, so both stay in the vault forever.
// ---------------------------------------------------------------------------------------------

impl Replay {
    fn crank_fees_78(&mut self, target_domain: u16) -> Result<u64, String> {
        let payer = self.env.payer.pubkey();
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::LpVaultCrankFees {
                domain: target_domain,
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.ledgers[0], false),
                AccountMeta::new(self.ledgers[1], false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[],
        )
    }
    fn close_resolved_any(&mut self, owner: Pubkey, p: Pubkey) -> Result<u64, String> {
        let dest = self.env.token_account_for_mint(self.env.mint, owner, 0);
        self.env.svm.expire_blockhash();
        self.env.send(
            ProgInstruction::CloseResolved {
                fee_rate_per_slot: 0,
            },
            vec![
                AccountMeta::new_readonly(owner, false),
                AccountMeta::new(self.env.market, false),
                AccountMeta::new(p, false),
                AccountMeta::new(dest, false),
                AccountMeta::new(self.env.vault, false),
                AccountMeta::new_readonly(self.env.vault_authority, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(nft_registry_pda(&self.env.market), false),
            ],
            &[],
        )
    }
}

#[derive(Debug)]
struct HarvestOutcome {
    stranded_before: i128,
    engine_residual_before: i128,
    r78: [Result<u64, Option<u32>>; 2],
    unowned_after_78: i128,
    engine_residual_after_78: i128,
    incumbent_paid: u64,
    vault_left: u64,
}

/// The harvest world up to terminal-flat (Resolved, every portfolio closed), before any 78.
struct TerminalWorld {
    r: Replay,
    h: Keypair,
    h_atas: [Pubkey; 2],
    stranded_before: i128,
    engine_residual_before: i128,
}

/// (InitMarket with 14 slots configures all 14 assets, as on every live slab; asset 0 trades.)
fn terminal_flat_world() -> TerminalWorld {
    resolved_world(Closing::All)
}

#[derive(Clone, Copy, PartialEq)]
enum Closing {
    /// CloseResolved + tag 8 on everyone: terminal-flat, nothing materialized.
    All,
    /// Same, but A2 (emptied by CloseResolved) is NOT tag-8 closed: one materialized portfolio.
    KeepA2Materialized,
    /// Nobody is closed: Resolved with trader capital still in portfolios.
    None,
}

fn resolved_world(closing: Closing) -> TerminalWorld {
    let mut r = Replay::new(r2_market());
    // The incumbent is the only Earn holder: re-deposit as a known key so it can redeem.
    let h = Keypair::new();
    let (h_ata0, _) = r.deposit_shares(&h, 1_000_000_000, 0).expect("H 75 d0");
    let (h_ata1, _) = r.deposit_shares(&h, 1_000_000_000, 1).expect("H 75 d1");
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    let (tk, t) = r.new_trader(1_000_000_000);
    let all = [a1, a2, t, r.lp];
    // (b) I-2: the pair's conversion is booked as Earn loss although A2's loss refilled the pot.
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    // (a) a single trader's round trip: its gain is netted against the reversal's loss.
    r.trade(&tk, t, q).expect("T long");
    r.walk(1_100_000, &all);
    r.hold(r.lm.params.h_max + 2, &all);
    r.trade(&a1k, a1, -q).expect("A1 close");
    r.trade(&a2k, a2, q).expect("A2 close");
    r.hold(r.lm.params.h_max + 2, &all);
    r.convert_all(&a1k, a1).expect("A1 convert");
    r.walk(1_000_000, &all);
    r.hold(r.lm.params.h_max + 2, &all);
    r.trade(&tk, t, -q).expect("T close");
    r.hold(r.lm.params.h_max + 2, &all);
    let s = r.snap();
    s.print("pre-resolve");
    // Measured with the pre-E3 ledger reading: the stranding the harvest was built to return
    // (under E3 the I-2 part is already priced to Earn in Live; Residual is not).
    let stranded_before = s.unowned_ledger();
    let engine_residual_before = s.engine_residual();
    // Resolve and close every portfolio (terminal-flat).
    r.env.resolve();
    let owners = [
        (a1k.pubkey(), a1),
        (a2k.pubkey(), a2),
        (tk.pubkey(), t),
        (r.lp_owner.pubkey(), r.lp),
    ];
    match closing {
        Closing::None => {
            return TerminalWorld {
                r,
                h,
                h_atas: [h_ata0, h_ata1],
                stranded_before,
                engine_residual_before,
            };
        }
        Closing::KeepA2Materialized => {
            r.close_resolved_any(a2k.pubkey(), a2)
                .expect("A2 CloseResolved");
            let rest = [owners[0], owners[2], owners[3]];
            close_all_resolved(&mut r, &rest);
            let (_, g) = r.env.market_state();
            assert_eq!(
                (g.c_tot, g.materialized_portfolio_count),
                (0, 1),
                "only A2 stays materialized"
            );
            return TerminalWorld {
                r,
                h,
                h_atas: [h_ata0, h_ata1],
                stranded_before,
                engine_residual_before,
            };
        }
        Closing::All => close_all_resolved(&mut r, &owners),
    }
    let (_, g) = r.env.market_state();
    assert_eq!(
        (g.c_tot, g.materialized_portfolio_count, g.pnl_pos_tot),
        (0, 0, 0),
        "terminal-flat (vault {}, mode {:?})",
        g.vault,
        g.mode
    );
    TerminalWorld {
        r,
        h,
        h_atas: [h_ata0, h_ata1],
        stranded_before,
        engine_residual_before,
    }
}

/// CloseResolved then permissionless tag 8 on each portfolio, until nothing is materialized.
fn close_all_resolved(r: &mut Replay, owners: &[(Pubkey, Pubkey)]) {
    for round in 0..6 {
        for &(k, p) in owners {
            if r.env
                .svm
                .get_account(&p)
                .is_none_or(|a| a.data.iter().all(|b| *b == 0) || a.lamports == 0)
            {
                continue;
            }
            let res = r.close_resolved_any(k, p);
            if std::env::var("R2_DEBUG").is_ok() {
                eprintln!(
                    "round {round} close {p}: {:?}",
                    res.as_ref().map_err(|e| custom_code(e))
                );
            }
        }
        // Permissionless tag 8 on each emptied portfolio (rent to its owner), as the keeper does.
        for &(k, p) in owners {
            let closer = Keypair::new();
            r.env.ensure_signer_account(closer.pubkey());
            let Ok((pid, seq, ep)) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                r.env.portfolio_identity(p)
            })) else {
                continue;
            };
            r.env.svm.expire_blockhash();
            let _ = r.env.send(
                ProgInstruction::ClosePortfolio {
                    portfolio_id: pid,
                    expected_sequence: seq,
                    position_epoch: ep,
                },
                vec![
                    AccountMeta::new(closer.pubkey(), true),
                    AccountMeta::new(r.env.market, false),
                    AccountMeta::new(p, false),
                    AccountMeta::new(k, false),
                ],
                &[&closer],
            );
        }
        let (_, g) = r.env.market_state();
        if g.materialized_portfolio_count == 0 {
            break;
        }
    }
}

/// Write only the bytes of the fields `f` changes (read_market/write_market is not byte-neutral
/// on these slabs: it rewrites wrapper bytes it does not model).
fn mutate_market_surgical(r: &mut Replay, f: impl FnOnce(&mut state::MarketGroupV16)) {
    let original = r.env.svm.get_account(&r.env.market).expect("market");
    let (cfg, mut g) = state::read_market(&original.data).expect("read market");
    let mut noop = original.data.clone();
    state::write_market(&mut noop, &cfg, &g).unwrap();
    f(&mut g);
    let mut mutated = original.data.clone();
    state::write_market(&mut mutated, &cfg, &g).unwrap();
    let mut acct = original;
    for i in 0..acct.data.len() {
        if mutated[i] != noop[i] {
            acct.data[i] = mutated[i];
        }
    }
    r.env.svm.set_account(r.env.market, acct).unwrap();
}

fn run_resolved_harvest() -> HarvestOutcome {
    let TerminalWorld {
        mut r,
        h,
        h_atas,
        stranded_before,
        engine_residual_before,
    } = terminal_flat_world();
    // Harvest both pots, then the incumbent redeems everything it holds.
    let r78 = [
        r.crank_fees_78(0).map_err(|e| custom_code(&e)),
        r.crank_fees_78(1).map_err(|e| custom_code(&e)),
    ];
    let after78 = r.snap();
    after78.print("after 78");
    let mut incumbent_paid = 0u64;
    for ata in h_atas {
        incumbent_paid += r
            .redeem_all(&h, ata)
            .unwrap_or_else(|e| panic!("H 77: {e}"));
    }
    let vault_left = r.env.token_amount(r.env.vault);
    HarvestOutcome {
        stranded_before,
        engine_residual_before,
        r78,
        unowned_after_78: after78.unowned(),
        engine_residual_after_78: after78.engine_residual(),
        incumbent_paid,
        vault_left,
    }
}

/// Fix acceptance: after Resolve, a non-bound vault's holders recover the stranded value.
/// The incumbent H holds half the shares of a 4,000 vault (the replay creator holds the other
/// half); every trade is zero-sum (pair + round trip, fee 0), so H's half of the pots is exactly
/// 2,000 plus half of everything stranded.
#[test]
fn nonbound_resolved_terminal_harvest_returns_stranded_value() {
    let o = run_resolved_harvest();
    eprintln!("harvest outcome: {o:#?}");
    assert!(
        o.stranded_before > 0,
        "the scenario must strand value (vacuity guard)"
    );
    assert!(
        o.r78.iter().all(|r| r.is_ok()),
        "tag 78 must run on a non-bound terminal-flat market: {:?}",
        o.r78
    );
    assert!(
        o.unowned_after_78.abs() <= 2,
        "after 78 nothing may stay unowned: {}",
        o.unowned_after_78
    );
    assert!(
        o.engine_residual_after_78.abs() <= 2,
        "after 78 Residual must be dust: {}",
        o.engine_residual_after_78
    );
    assert!(
        (o.incumbent_paid as i128 - 2_000_000_000).abs() <= 2,
        "H paid {} for 2,000 deposited; {} was stranded (engine residual {})",
        o.incumbent_paid,
        o.stranded_before,
        o.engine_residual_before
    );
}

/// F-1 (security review of E1): 2-asset slab. Asset 1 carries a pending terminal insurance
/// recredit (receivable on its long source × insurance spent on its short domain), and the slab
/// carries extra claim-free Residual. The harvest on ASSET 0's vault must run asset 1's recredit
/// before absorbing the slab-global Residual. Without that, insurance's 40 goes to asset 0's Earn
/// holders. RED on 54825149 (single-asset recredit), GREEN on the F-1 build.
#[test]
fn f1_harvest_runs_every_assets_insurance_recredit_before_absorbing_residual() {
    const R: u128 = 40_000_000; // receivable on asset 1's long source
    const X: u128 = 40_000_000; // insurance spent on asset 1's short domain
    const Y: u128 = 100_000_000; // extra claim-free Residual
    let TerminalWorld { mut r, .. } = terminal_flat_world();
    let bs = BOUND_SCALE;
    mutate_market_surgical(&mut r, |g| {
        g.source_credit[2].provider_receivable_num = R * bs;
        g.source_credit[2].spent_backing_num = R * bs;
        g.source_backing_buckets[2].consumed_liened_backing_num = R * bs;
        g.source_backing_buckets[2].status = percolator::BackingBucketStatusV16::Expired;
        g.insurance_domain_budget[3] = X; // a domain that spent X had a budget of at least X
        g.insurance_domain_spent[3] = X;
        g.vault += Y;
    });
    let vault_tokens = r.env.token_amount(r.env.vault) as u128;
    let (mint, va) = (r.env.mint, r.env.vault_authority);
    r.env
        .set_token_account_amount(r.env.vault, mint, va, (vault_tokens + Y) as u64);
    let before = r.snap();
    before.print("F-1 before 78");
    let r78 = r.crank_fees_78(0);
    let after = r.snap();
    after.print("F-1 after 78");
    r78.unwrap_or_else(|e| panic!("78 on asset 0's vault: {e}"));
    assert!(
        before.engine_residual() >= (R as i128),
        "vacuity: residual covers the entitlement"
    );
    assert_eq!(
        after.insurance - before.insurance,
        R.min(X),
        "asset 1's insurance recredit ran before the residual was absorbed into asset 0's pot"
    );
    assert_eq!(
        after.engine_residual(),
        0,
        "the rest of the Residual is absorbed"
    );
}

/// Raw offset of asset 0's wrapper receipt-only counter (`MARKET_RESOLVED_RECEIPT_ONLY_OFF` within
/// the asset slot, whose wrapper bytes come first).
fn receipt_only_counter_offset() -> usize {
    use percolator_prog::constants::{
        HEADER_LEN, MARKET_GROUP_LEN, MARKET_RESOLVED_RECEIPT_ONLY_OFF, WRAPPER_CONFIG_LEN,
    };
    HEADER_LEN + WRAPPER_CONFIG_LEN + MARKET_GROUP_LEN + MARKET_RESOLVED_RECEIPT_ONLY_OFF
}

/// F-2: with receipts OPEN, the non-bound harvest must not credit pot stray to Earn (it stays
/// reserved, P3 option (b) / upstream c3988149's per-bucket junior need). The open receipt here
/// is the WRAPPER's own state, set directly: one materialized, emptied portfolio counted
/// receipt-only (the counter `resolved_terminal_flat` reads), so `receipts_open` is true. An
/// E1-native receipt needs a legacy unbacked claim (see p3_resolved_lock's legacy fixture).
/// RED on 54825149 (the stray was credited), GREEN on the F-2 build.
#[test]
fn f2_receipts_open_harvest_does_not_credit_pot_stray() {
    let TerminalWorld { mut r, .. } = resolved_world(Closing::KeepA2Materialized);
    let off = receipt_only_counter_offset();
    let mut acct = r.env.svm.get_account(&r.env.market).unwrap();
    acct.data[off..off + 8].copy_from_slice(&1u64.to_le_bytes());
    r.env.svm.set_account(r.env.market, acct).unwrap();
    let before = r.snap();
    before.print("F-2 before 78 (receipts open)");
    let r78 = r.crank_fees_78(0);
    let after = r.snap();
    after.print("F-2 after 78");
    r78.unwrap_or_else(|e| panic!("78 with receipts open: {e}"));
    assert!(
        before.fresh[0] > before.earn_nav_ledger.min(before.fresh[0]) || before.unowned_ledger() > 0,
        "vacuity: there is pot stray to protect"
    );
    assert_eq!(
        after.earn_nav, before.earn_nav,
        "no pot stray credited to Earn while receipts are open"
    );
    assert_eq!(
        after.engine_residual(),
        before.engine_residual(),
        "the receipts' residual is untouched"
    );
}

/// F-3: a Resolved non-bound 77 runs the harvest inline, so the first redeemer cannot leave its
/// share of the stranded value to later redeemers, and nobody has to crank 78 first. No 78 is
/// sent. RED on 54825149 (H paid 1,850), GREEN on the F-3 build (H paid 2,000).
#[test]
fn f3_resolved_77_harvests_inline_without_78() {
    let TerminalWorld {
        mut r,
        h,
        h_atas,
        stranded_before,
        ..
    } = terminal_flat_world();
    assert!(stranded_before > 0, "vacuity: value is stranded");
    let mut paid = 0u64;
    for ata in h_atas {
        paid += r
            .redeem_all(&h, ata)
            .unwrap_or_else(|e| panic!("H 77: {e}"));
    }
    eprintln!("F-3: H paid {paid} without any 78 (stranded before resolve {stranded_before})");
    assert!(
        (paid as i128 - 2_000_000_000).abs() <= 2,
        "H paid {paid}, owed 2,000"
    );
}

/// F-6b: tag 78 stays refused (21) on a Resolved market that still has an OPEN portfolio with
/// trader capital (a real one, not a synthetic c_tot byte): converting insurance or absorbing
/// residual there would take value traders can still claim.
#[test]
fn f6_resolved_78_refused_while_a_real_portfolio_is_open() {
    let TerminalWorld { mut r, .. } = resolved_world(Closing::None);
    let (_, g) = r.env.market_state();
    assert!(
        g.c_tot > 0 && g.materialized_portfolio_count > 0,
        "vacuity: traders still hold capital"
    );
    let before = r.snap();
    for d in 0..2u16 {
        let e = r
            .crank_fees_78(d)
            .expect_err("78 must refuse while a portfolio is open");
        assert_eq!(custom_code(&e), Some(21), "EngineLockActive, got {e}");
    }
    let after = r.snap();
    assert_eq!(
        (after.vault, after.insurance, after.fresh_total),
        (before.vault, before.insurance, before.fresh_total)
    );
}


// ---------------------------------------------------------------------------------------------
// E3 conservation (2026-10-05, plan §2.8): `vault - c_tot - pnl_pos_tot - insurance - Earn NAV`
// ("unowned") over random zero-sum pair flows, Earn deposits into either pot, and redemptions.
// Property, after every step (all accounts cranked):
//   (a) unowned >= -dust          nothing is promised twice (NAV never over-prices);
//   (b) unowned <= stray + dust   the only unowned value is pot backing ABOVE the vault's own
//       principal (loss backing beyond every registered claim, which the Resolved harvest hands
//       to the vault); never value INSIDE Earn's principal -- which is exactly where the R-2
//       round trip (I-2) and the deposit-refill leak stranded it before E3.
// ---------------------------------------------------------------------------------------------

fn pot_strays(r: &Replay, g: &state::MarketGroupV16) -> u128 {
    let mut stray = 0u128;
    for d in 0..2usize {
        let principal = r
            .env
            .svm
            .get_account(&r.ledgers[d])
            .and_then(|a| state::read_backing_domain_ledger(&a.data).ok())
            .map(|l| l.total_principal_atoms)
            .unwrap_or(0);
        let b = &g.source_backing_buckets[d];
        let c = &g.source_credit[d];
        let phys = (b.fresh_unliened_backing_num + b.valid_liened_backing_num) / BOUND_SCALE;
        let owed = c.positive_claim_bound_num.div_ceil(BOUND_SCALE);
        stray += phys.saturating_sub(owed).saturating_sub(principal);
    }
    stray
}

#[derive(Clone, Debug)]
enum ConsOp {
    Pair { up: bool, bps: u64 },
    Deposit { pot: u16, units: u64 },
    RedeemAll,
}

fn cons_op() -> impl proptest::strategy::Strategy<Value = ConsOp> {
    use proptest::prelude::*;
    prop_oneof![
        (any::<bool>(), 50u64..900).prop_map(|(up, bps)| ConsOp::Pair { up, bps }),
        (0u16..2, 100u64..2_000).prop_map(|(pot, units)| ConsOp::Deposit { pot, units }),
        Just(ConsOp::RedeemAll),
    ]
}

fn run_conservation(ops: &[ConsOp]) -> (i128, u128, usize) {
    const DUST: i128 = 4;
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(2_000_000_000);
    let (a2k, a2) = r.new_trader(2_000_000_000);
    let all = [a1, a2, r.lp];
    let e = Keypair::new();
    let mut e_atas: Vec<Pubkey> = vec![];
    let (mut worst_unowned, mut max_stray, mut checked) = (0i128, 0u128, 0usize);
    for op in ops {
        match op {
            ConsOp::Pair { up, bps } => {
                let (_, g) = r.env.market_state();
                let p0 = g.assets[0].effective_price;
                let delta = p0 * bps / 10_000;
                let target = if *up { p0 + delta } else { p0.saturating_sub(delta).max(100_000) };
                if r.trade(&a1k, a1, q).is_err() || r.trade(&a2k, a2, -q).is_err() {
                    continue;
                }
                r.walk(target, &all);
                let _ = r.trade(&a1k, a1, -q);
                let _ = r.trade(&a2k, a2, q);
                r.hold(r.lm.params.h_max + 2, &all);
                let _ = r.convert_all(&a1k, a1);
                let _ = r.convert_all(&a2k, a2);
            }
            ConsOp::Deposit { pot, units } => {
                if let Ok((ata, _)) = r.deposit_shares(&e, units * 1_000_000, *pot) {
                    if !e_atas.contains(&ata) {
                        e_atas.push(ata);
                    }
                }
            }
            ConsOp::RedeemAll => {
                for ata in e_atas.clone() {
                    if r.env.token_amount(ata) > 0 {
                        let _ = r.redeem_all(&e, ata);
                    }
                }
            }
        }
        r.hold(1, &all);
        let s = r.snap();
        let (_, g) = r.env.market_state();
        let stray = pot_strays(&r, &g);
        let unowned = s.unowned();
        assert!(
            unowned >= -DUST,
            "(a) over-promised: unowned {unowned} after {op:?} (NAV {} vault {} c_tot {} ppt {} ins {})",
            s.earn_nav, s.vault, s.c_tot, s.ppt, s.insurance
        );
        assert!(
            unowned <= stray as i128 + DUST,
            "(b) {unowned} unowned but only {stray} of pot backing sits above principal after {op:?}: \
             value inside Earn's principal is stranded (NAV {}, physical net {:?})",
            s.earn_nav,
            (0..2).map(|d| s.fresh[d] + s.valid[d] - s.claim[d].min(s.fresh[d] + s.valid[d])).collect::<Vec<_>>()
        );
        worst_unowned = worst_unowned.max(unowned);
        max_stray = max_stray.max(stray);
        checked += 1;
    }
    // MEASURED tie-in: the NAV the property used (the program's pure E3 rule, applied by the
    // mirror) must be the NAV the PROGRAM prices a deposit at. Probe: 1,000 USDC into pot 0;
    // implied NAV = amount * S / shares_minted, exact up to the floor on the minted shares.
    let s = r.snap();
    let s_before = state::read_lp_vault_registry(&r.env.svm.get_account(&r.registry).unwrap().data)
        .unwrap()
        .total_lp_shares_outstanding;
    let probe = Keypair::new();
    let amount: u128 = 1_000_000_000;
    if s.earn_nav > 0 && s_before > 0 {
        if let Ok((_, minted)) = r.deposit_shares(&probe, amount as u64, 0) {
            let implied = amount * s_before / minted as u128;
            let tol = s.earn_nav / minted as u128 + 2;
            assert!(
                implied.abs_diff(s.earn_nav) <= tol,
                "program prices NAV {implied} but the property used {} (tol {tol})",
                s.earn_nav
            );
        }
    }
    (worst_unowned, max_stray, checked)
}

/// Deterministic anchor for the property: the R-2 sequence itself, then a deposit into the
/// receivable pot. GREEN on E3; RED before (unowned 180 with 0 stray).
#[test]
fn e3_conservation_r2_sequence() {
    let ops = [
        ConsOp::Pair { up: true, bps: 1_800 },
        ConsOp::Deposit { pot: 0, units: 1_800 },
        ConsOp::Pair { up: true, bps: 1_525 },
        ConsOp::RedeemAll,
        ConsOp::Deposit { pot: 1, units: 1_800 },
    ];
    let (u, st, n) = run_conservation(&ops);
    eprintln!("E3 anchor: worst unowned {u}, max stray {st}, {n} checks");
    assert_eq!(n, ops.len());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 8, max_shrink_iters: 16, .. Default::default() })]
    #[test]
    fn e3_conservation_proptest(ops in proptest::collection::vec(cons_op(), 1..6)) {
        let (u, st, n) = run_conservation(&ops);
        eprintln!("E3 proptest: {n} checks, worst unowned {u}, max stray {st}");
    }
}

// ── Sentinel review (2026-10-05): E3 touch-order variant of R-2 ─────────────────────────────
// E3 prices a non-bound pot at min(principal, held - registered claims). A winner's claim is
// registered when the WINNER is touched; the loser's loss is routed into the pot only when the
// LOSER is touched. A zero-sum pair can therefore order the two touches around a deposit.
fn walk_only(r: &mut Replay, target: u64, who: &[Pubkey]) {
    for _ in 0..400 {
        let s = r.now() + 1;
        r.env.svm.warp_to_slot(s);
        r.env.push_auth_mark_for_asset_as_admin(0, s, target);
        for p in who {
            r.crank_pf(*p);
        }
        let (_, g) = r.env.market_state();
        if g.assets[0].effective_price == target && g.assets[0].slot_last == g.current_slot {
            return;
        }
    }
    panic!("walk_only did not converge");
}

fn run_touch_order(l: u64, e_deposit: u64, e_pot: u16) -> (u128, u128, u64, u64, i128) {
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    let s0 = r.snap();
    s0.print("TO s0 (pair open)");
    // Price up: touch ONLY the winner A1 (and the LP); the loser A2 stays untouched.
    let lp = r.lp;
    walk_only(&mut r, 1_000_000 + l, &[a1, lp]);
    let s1 = r.snap();
    s1.print("TO s1 (winner touched, loser not)");
    eprintln!("TO s1 claim {:?} fresh {:?} nav {} ledger_nav {}", s1.claim, s1.fresh, s1.earn_nav, s1.earn_nav_ledger);
    let e = Keypair::new();
    let (e_ata, e_shares) = r.deposit_shares(&e, e_deposit, e_pot).expect("E 75 at the dip");
    // Now touch the loser: its loss is routed into the pot.
    r.crank_pf(a2);
    r.crank_pf(a1);
    let s2 = r.snap();
    s2.print("TO s2 (loser touched)");
    eprintln!("TO s2 claim {:?} fresh {:?} nav {} ledger_nav {}", s2.claim, s2.fresh, s2.earn_nav, s2.earn_nav_ledger);
    let e_paid = r.redeem_all(&e, e_ata).expect("E 77");
    let s3 = r.snap();
    s3.print("TO s3 (E redeemed)");
    eprintln!("TO E deposited {e_deposit} for {e_shares} shares; paid {e_paid}; incumbents nav {}", s3.earn_nav);
    let st1 = r.env.portfolio_state(a1);
    let st2 = r.env.portfolio_state(a2);
    let pair_net = st1.capital as i128 + st1.pnl + st2.capital as i128 + st2.pnl - 2_000_000_000;
    (s1.earn_nav, s2.earn_nav, e_paid, e_shares, pair_net)
}

#[test]
fn sentinel_e3_touch_order_round_trip_cannot_extract() {
    let (nav_dip, nav_after, e_paid, _shares, pair_net) = run_touch_order(180_000, 1_800_000_000, 0);
    eprintln!("TO nav at deposit {nav_dip}, after loser touch {nav_after}, E paid {e_paid}, pair net {pair_net}");
    assert!(
        e_paid as u128 <= 1_800_000_000,
        "touch-order: E deposited 1,800 and redeemed {} (nav at entry {}, at exit {}), pair nets {}",
        e_paid, nav_dip, nav_after, pair_net
    );
}

// ── H-1 acceptance property (2026-10-05): touch order is attacker-chosen ────────────────────
// A zero-sum pair (A1 long / A2 short against the LP, always opened and closed together) plus an
// Earn identity E. Every step chooses WHICH accounts are touched, so a winner's claim can be
// registered while the loser's loss is not yet routed (and the reverse), conversions can run
// before the counterparty is touched, and E can deposit and redeem (its own 77) at any point.
// Property: E never takes out more than it put in (+dust); its trading half is zero-sum, so any
// excess would be taken from the incumbents.
#[derive(Clone, Debug)]
enum TouchOp {
    Open,
    Walk { up: bool, bps: u64, touch_a1: bool, touch_a2: bool },
    Touch { a1: bool },
    Close,
    Convert { a1: bool },
    Deposit { pot: u16, units: u64 },
    Redeem,
}

fn touch_op() -> impl proptest::strategy::Strategy<Value = TouchOp> {
    use proptest::prelude::*;
    prop_oneof![
        1 => Just(TouchOp::Open),
        3 => (any::<bool>(), 300u64..1_800, any::<bool>(), any::<bool>())
            .prop_map(|(up, bps, touch_a1, touch_a2)| TouchOp::Walk { up, bps, touch_a1, touch_a2 }),
        2 => any::<bool>().prop_map(|a1| TouchOp::Touch { a1 }),
        1 => Just(TouchOp::Close),
        1 => any::<bool>().prop_map(|a1| TouchOp::Convert { a1 }),
        2 => (0u16..2, 200u64..2_000).prop_map(|(pot, units)| TouchOp::Deposit { pot, units }),
        2 => Just(TouchOp::Redeem),
    ]
}

/// Returns (E deposited, E paid).
fn run_touch_ops(ops: &[TouchOp]) -> (u128, u128) {
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(3_000_000_000);
    let (a2k, a2) = r.new_trader(3_000_000_000);
    let lp = r.lp;
    let e = Keypair::new();
    let (mut dep, mut paid) = (0u128, 0u128);
    let mut atas: Vec<Pubkey> = vec![];
    let mut open = false;
    for op in ops {
        match op {
            TouchOp::Open if !open => {
                if r.trade(&a1k, a1, q).is_ok() {
                    if r.trade(&a2k, a2, -q).is_ok() {
                        open = true;
                    } else {
                        let _ = r.trade(&a1k, a1, -q);
                    }
                }
            }
            TouchOp::Walk { up, bps, touch_a1, touch_a2 } => {
                let p0 = r.env.market_state().1.assets[0].effective_price;
                let d = p0 * bps / 10_000;
                let target = if *up { p0 + d } else { p0.saturating_sub(d).max(200_000) };
                let mut who = vec![lp];
                if *touch_a1 {
                    who.push(a1);
                }
                if *touch_a2 {
                    who.push(a2);
                }
                walk_only(&mut r, target, &who);
            }
            TouchOp::Touch { a1: x } => r.crank_pf(if *x { a1 } else { a2 }),
            TouchOp::Close if open => {
                let _ = r.trade(&a1k, a1, -q);
                let _ = r.trade(&a2k, a2, q);
                open = false;
            }
            TouchOp::Convert { a1: x } => {
                let (k, p) = if *x { (&a1k, a1) } else { (&a2k, a2) };
                let _ = r.convert_all(&k.insecure_clone(), p);
            }
            TouchOp::Deposit { pot, units } => {
                if let Ok((ata, _)) = r.deposit_shares(&e, units * 1_000_000, *pot) {
                    dep += (*units as u128) * 1_000_000;
                    if !atas.contains(&ata) {
                        atas.push(ata);
                    }
                }
            }
            TouchOp::Redeem => {
                for ata in atas.clone() {
                    if r.env.token_amount(ata) > 0 {
                        if let Ok(p) = r.redeem_all(&e, ata) {
                            paid += p as u128;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // Attacker-optimal final exit: everything touched (every pending loss routed), then E leaves.
    if open {
        let _ = r.trade(&a1k, a1, -q);
        let _ = r.trade(&a2k, a2, q);
    }
    for _ in 0..2 {
        r.crank_pf(a1);
        r.crank_pf(a2);
        r.crank_pf(lp);
    }
    for ata in atas.clone() {
        if r.env.token_amount(ata) > 0 {
            if let Ok(p) = r.redeem_all(&e, ata) {
                paid += p as u128;
            }
        }
    }
    (dep, paid)
}

/// Deterministic anchor: the reviewer's ordering expressed in the property's alphabet.
#[test]
fn h1_touch_order_anchor_cannot_extract() {
    let ops = [
        TouchOp::Open,
        TouchOp::Walk { up: true, bps: 1_800, touch_a1: true, touch_a2: false },
        TouchOp::Deposit { pot: 0, units: 1_800 },
        TouchOp::Touch { a1: false },
        TouchOp::Redeem,
    ];
    let (dep, paid) = run_touch_ops(&ops);
    eprintln!("H-1 anchor: E deposited {dep}, paid {paid}");
    assert!(paid <= dep + 2, "E extracted {} (deposited {dep}, paid {paid})", paid as i128 - dep as i128);
}

/// One round: a price walk touching a random subset of the pair, then (each optional) an E
/// deposit, a separate touch, a conversion and an E redemption, in that order.
fn touch_round() -> impl proptest::strategy::Strategy<Value = Vec<TouchOp>> {
    use proptest::prelude::*;
    (
        any::<bool>(),
        300u64..1_800,
        any::<bool>(),
        any::<bool>(),
        proptest::option::of((0u16..2, 200u64..2_000)),
        proptest::option::of(any::<bool>()),
        proptest::option::of(any::<bool>()),
        any::<bool>(),
    )
        .prop_map(|(up, bps, touch_a1, touch_a2, dep, touch, conv, redeem)| {
            let mut v = vec![TouchOp::Walk { up, bps, touch_a1, touch_a2 }];
            if let Some((pot, units)) = dep {
                v.push(TouchOp::Deposit { pot, units });
            }
            if let Some(a1) = touch {
                v.push(TouchOp::Touch { a1 });
            }
            if let Some(a1) = conv {
                v.push(TouchOp::Convert { a1 });
            }
            if redeem {
                v.push(TouchOp::Redeem);
            }
            v
        })
}

fn touch_program() -> impl proptest::strategy::Strategy<Value = Vec<TouchOp>> {
    use proptest::prelude::*;
    (proptest::collection::vec(touch_round(), 1..4), proptest::collection::vec(touch_op(), 0..3)).prop_map(
        |(rounds, tail)| {
            let mut v = vec![TouchOp::Open];
            for r in rounds {
                v.extend(r);
            }
            v.extend(tail);
            v
        },
    )
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 24, max_shrink_iters: 32, .. Default::default() })]
    #[test]
    fn h1_touch_order_proptest_cannot_extract(ops in touch_program()) {
        let (dep, paid) = run_touch_ops(&ops);
        proptest::prop_assert!(paid <= dep + 2, "E extracted {}: deposited {dep}, paid {paid}, ops {ops:?}", paid as i128 - dep as i128);
    }
}

// ── v2.2 Wave A item 8: R3-M1 (security-review-p2b-earn-allocation round 3) ────────────────
// R3-M1: a Live non-bound 77 is priced on E3 = min(P, phys - registered claims). Between a
// winner's touch (claim registered) and its loser's touch (loss routed) E3 dips, so an HONEST
// redeemer exiting inside that window is under-paid by share x (par - E3), and the remaining
// holders (possibly the attacker who kept the dip open) gain it once the loser is touched.
// The fix: (1) a redeemer-signed `min_payout`, (2) up to 8 stale portfolios refreshed inline,
// (3) EXIT_REQUIRES_LOSS_CURRENT (p4 bit2, on for every new market; forced on in mainnet
// builds), (4) keeper-executable requests (`keeper_ok`), always loss-gated.

const R3M1_DEPOSIT: u64 = 1_000_000_000;
const ERR_EXPECTED_SIGNER: u32 = percolator_prog::error::PercolatorError::ExpectedSigner as u32;
const ERR_BELOW_MIN: u32 = 117;
const ERR_NOT_LOSS_CURRENT: u32 = 118;

struct R3m1 {
    r: Replay,
    q: i128,
    a1k: Keypair,
    a1: Pubkey,
    a2k: Keypair,
    a2: Pubkey,
    h: Keypair,
    h_ata: Pubkey,
    m: Keypair,
    m_ata: Pubkey,
}

/// H (honest) and M (the attacker) each enter at par in a calm book, then a zero-sum pair opens
/// against the LP and the mark walks +18% touching ONLY the winner A1 and the LP: the reviewer's
/// dip (claim registered, loser A2 untouched).
fn r3m1_world() -> R3m1 {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let m = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75 at par");
    let (m_ata, _) = r.deposit_shares(&m, R3M1_DEPOSIT, 0).expect("M 75 at par");
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    let lp = r.lp;
    walk_only(&mut r, 1_180_000, &[a1, lp]);
    let (_, g) = r.env.market_state();
    assert!(
        g.assets[0].stale_account_count_long + g.assets[0].stale_account_count_short > 0,
        "the dip must exist: the loser A2 is untouched (stale)"
    );
    R3m1 { r, q, a1k, a1, a2k, a2, h, h_ata, m, m_ata }
}

impl Replay {
    fn redemption_pda(&self, who: &Pubkey) -> Pubkey {
        state::derive_lp_redemption(&self.env.program_id, &self.registry, who).0
    }
    /// Tag 76, legacy (`ext == None`) or the v2.2 wire `(min_payout, keeper_ok)`.
    fn request_76(&mut self, who: &Keypair, ata: Pubkey, ext: Option<(u64, u8)>) -> Result<u64, String> {
        let shares = self.env.token_amount(ata) as u128;
        let pid = self.env.program_id;
        let escrow = state::derive_lp_escrow(&pid, &self.env.market).0;
        let red = self.redemption_pda(&who.pubkey());
        self.env.svm.expire_blockhash();
        let ix = match ext {
            None => ProgInstruction::RequestRedeemLpShares { shares },
            Some((min_payout_atoms, keeper_ok)) => ProgInstruction::RequestRedeemLpSharesV22 {
                shares,
                min_payout_atoms,
                keeper_ok,
            },
        };
        self.env.send(
            ix,
            vec![
                AccountMeta::new(who.pubkey(), true),
                AccountMeta::new(self.registry, false),
                AccountMeta::new(self.lp_mint, false),
                AccountMeta::new(ata, false),
                AccountMeta::new(escrow, false),
                AccountMeta::new(red, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            ],
            &[who],
        )
    }
    /// Tag 77 for `who`'s pending request. `wire == None`: the legacy 3-byte wire (what the app
    /// sends today). `Some((min, refresh))`: the v2.2 wire with `refresh` as accounts [13..].
    /// `signed`: the redeemer signs [12] (H-1(b)); otherwise only the payer (a keeper) signs.
    /// Returns (SPL paid to `who` by THIS call, CU).
    fn execute_77(
        &mut self,
        who: &Keypair,
        wire: Option<(u64, Vec<Pubkey>)>,
        signed: bool,
    ) -> Result<(u64, u64), String> {
        let pid = self.env.program_id;
        let escrow = state::derive_lp_escrow(&pid, &self.env.market).0;
        let red = self.redemption_pda(&who.pubkey());
        let dest = self.env.token_account_for_mint(self.env.mint, who.pubkey(), 0);
        let before = self.env.token_amount(dest);
        let payer = self.env.payer.pubkey();
        let mut metas = vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(red, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(escrow, false),
            AccountMeta::new(self.env.vault, false),
            AccountMeta::new_readonly(self.env.vault_authority, false),
            AccountMeta::new(self.ledgers[0], false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new(self.ledgers[1], false),
            AccountMeta::new(who.pubkey(), signed),
        ];
        let ix = match wire {
            None => ProgInstruction::ExecuteRedemption { domain: 0 },
            Some((min_payout_atoms, refresh)) => {
                let n_refresh = refresh.len() as u8;
                for p in refresh {
                    metas.push(AccountMeta::new(p, false));
                }
                ProgInstruction::ExecuteRedemptionV22 {
                    domain: 0,
                    min_payout_atoms,
                    n_refresh,
                }
            }
        };
        self.env.svm.expire_blockhash();
        let signers: Vec<&Keypair> = if signed { vec![who] } else { vec![] };
        let cu = self.env.send(ix, metas, &signers)?;
        Ok((self.env.token_amount(dest) - before, cu))
    }
    /// The redeemer-visible state a refused 77 must leave untouched.
    fn exit_state(&self, who: &Pubkey) -> (u64, u64, u128, bool, u64) {
        let escrow = state::derive_lp_escrow(&self.env.program_id, &self.env.market).0;
        let reg = state::read_lp_vault_registry(&self.env.svm.get_account(&self.registry).unwrap().data).unwrap();
        let red = self.env.svm.get_account(&self.redemption_pda(who));
        let live = red.is_some_and(|a| state::read_lp_redemption(&a.data).is_ok());
        let vault_spl = self.env.token_amount(self.env.vault);
        (self.env.token_amount(escrow), self.share_supply(), reg.total_lp_shares_outstanding, live, vault_spl)
    }
    /// Clear (`on == false`) or set p4_flags bit2 on asset 0's profile, by direct account write:
    /// the legacy / devnet-off behaviour on the SAME binary (no setter exists, by design).
    fn set_exit_requires_loss_current(&mut self, on: bool) {
        let mut acct = self.env.svm.get_account(&self.env.market).unwrap();
        let mut p = state::read_asset_oracle_profile(&acct.data, 0).unwrap();
        let bit = percolator_prog::constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT;
        p._padding0[percolator_prog::constants::PROFILE_P4_FLAGS_IDX] =
            if on { bit } else { 0 };
        state::write_asset_oracle_profile(&mut acct.data, 0, &p).unwrap();
        self.env.svm.set_account(self.env.market, acct).unwrap();
    }
}

fn code(r: &Result<(u64, u64), String>) -> Option<u32> {
    r.as_ref().err().and_then(|e| custom_code(e))
}

/// THE PORT. Reviewer's R3-M1: H exits inside the dip with the 3-byte 77 the app sends today.
/// * ff65ec50 (before): H is paid ~share x E3 (< its 1,000 at par) and M later redeems the gap
///   -> the first assertion FAILS (proved by running this test on the baseline .so).
/// * v2.2 (after): the dip exit is REFUSED (118, nothing moves); H's SDK flow then refreshes
///   the book inline (n_refresh = 3) under its own signed floor and is paid par; M gains 0.
#[test]
fn r3m1_honest_exit_inside_dip_is_not_skimmed() {
    let mut w = r3m1_world();
    let lp = w.r.lp;
    w.r.request_76(&w.h, w.h_ata, None).expect("H 76");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let before = w.r.exit_state(&w.h.pubkey());
    let dip = w.r.execute_77(&w.h, None, true);
    eprintln!("R3-M1 legacy 77 inside the dip: {dip:?}");
    let paid_in_dip = dip.as_ref().map(|x| x.0).unwrap_or(0) as u128;
    assert!(
        dip.is_err() || paid_in_dip + 2 >= R3M1_DEPOSIT as u128,
        "R3-M1 skim: H deposited {R3M1_DEPOSIT} at par and was paid {paid_in_dip} inside the dip"
    );
    assert_eq!(code(&dip), Some(ERR_NOT_LOSS_CURRENT), "the dip exit is refused as not loss-current");
    assert_eq!(w.r.exit_state(&w.h.pubkey()), before, "a refused 77 moves nothing");
    // H's honest SDK flow: refresh every positioned portfolio inline, floor = its par quote.
    let (paid, cu) = w
        .r
        .execute_77(&w.h, Some((R3M1_DEPOSIT - 2, vec![w.a1, w.a2, lp])), true)
        .expect("H 77 with inline refresh");
    eprintln!("R3-M1 H paid {paid} (deposit {R3M1_DEPOSIT}), CU {cu}");
    assert!(paid + 2 >= R3M1_DEPOSIT, "H under-paid after the inline refresh: {paid}");
    // M (the dip-holder) gains nothing from H's exit.
    w.r.request_76(&w.m, w.m_ata, None).expect("M 76");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let (m_paid, _) = w.r.execute_77(&w.m, Some((1, vec![w.a1, w.a2, lp])), true).expect("M 77");
    assert!(m_paid <= R3M1_DEPOSIT + 2, "M extracted {} from H's exit", m_paid as i128 - R3M1_DEPOSIT as i128);
    let _ = (&w.a1k, &w.a2k, w.q);
}

/// Same binary, EXIT_REQUIRES_LOSS_CURRENT cleared (the devnet-off / legacy shape): the legacy
/// dip exit reproduces the skim (this is the R3-M1 PoC, live), and rule 1 alone already stops
/// it for a redeemer who signs a floor: 117 with no state change, then par once the loser is
/// touched.
#[test]
fn r3m1_skim_reproduces_without_bit2_and_min_payout_stops_it() {
    let mut w = r3m1_world();
    w.r.set_exit_requires_loss_current(false);
    // H2 = M here: a second redeemer who signs a floor.
    w.r.request_76(&w.h, w.h_ata, None).expect("H 76");
    w.r.request_76(&w.m, w.m_ata, None).expect("M 76");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    // M signs its par quote as the floor inside the dip: refused, nothing moves.
    let before = w.r.exit_state(&w.m.pubkey());
    let refused = w.r.execute_77(&w.m, Some((R3M1_DEPOSIT - 2, vec![])), true);
    assert_eq!(code(&refused), Some(ERR_BELOW_MIN), "{refused:?}");
    assert_eq!(w.r.exit_state(&w.m.pubkey()), before, "a 117 moves nothing");
    // H, no floor, legacy wire, bit2 off: the skim (R3-M1 reproduced on the same binary).
    let (h_paid, _) = w.r.execute_77(&w.h, None, true).expect("legacy 77 executes with bit2 off");
    eprintln!("R3-M1 reproduced with bit2 off: H paid {h_paid} for {R3M1_DEPOSIT}");
    assert!(h_paid + 2 < R3M1_DEPOSIT, "expected the R3-M1 under-payment with bit2 off, got {h_paid}");
    // The loser is touched; M's floor now clears and M collects H's gap (the skim's beneficiary).
    w.r.crank_pf(w.a2);
    let (m_paid, _) = w
        .r
        .execute_77(&w.m, Some((R3M1_DEPOSIT - 2, vec![])), true)
        .expect("M 77 after the loser touch");
    assert!(m_paid >= R3M1_DEPOSIT - 2, "floor honoured: {m_paid}");
    eprintln!("R3-M1 beneficiary M paid {m_paid}");
}

/// Rule 1 on a loss-current book: a floor above the quote is refused (117, nothing moves); the
/// floor stored at tag 76 binds even a legacy 77; a floor at or below the quote executes.
#[test]
fn min_payout_is_honoured_wire_and_stored() {
    let mut w = r3m1_world();
    let lp = w.r.lp;
    for p in [w.a1, w.a2, lp] {
        w.r.crank_pf(p);
    }
    // Stored floor above the quote; legacy 77 (wire floor 0) still refuses.
    w.r.request_76(&w.h, w.h_ata, Some((R3M1_DEPOSIT + 1_000, 0))).expect("H 76 v2.2");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let before = w.r.exit_state(&w.h.pubkey());
    let r1 = w.r.execute_77(&w.h, None, true);
    assert_eq!(code(&r1), Some(ERR_BELOW_MIN), "stored floor binds the legacy wire: {r1:?}");
    // A lower wire floor cannot undercut the stored one (max of both).
    let r2 = w.r.execute_77(&w.h, Some((1, vec![w.a1, w.a2, lp])), true);
    assert_eq!(code(&r2), Some(ERR_BELOW_MIN), "{r2:?}");
    assert_eq!(w.r.exit_state(&w.h.pubkey()), before, "117 moves nothing");
    // M: a wire floor above the quote refuses; at the quote it pays >= the floor.
    w.r.request_76(&w.m, w.m_ata, None).expect("M 76");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let r3 = w.r.execute_77(&w.m, Some((R3M1_DEPOSIT + 1, vec![])), true);
    assert_eq!(code(&r3), Some(ERR_BELOW_MIN), "{r3:?}");
    let (paid, _) = w.r.execute_77(&w.m, Some((R3M1_DEPOSIT - 2, vec![])), true).expect("M at its floor");
    assert!(paid >= R3M1_DEPOSIT - 2, "I-X1: paid {paid} >= floor");
}

/// Rule 2's cap: at most REDEMPTION_REFRESH_MAX = 8 inline refreshes (9 is refused at decode);
/// 8 refreshes of 9 stale portfolios leave the book stale (118); the full book inline (8 + one
/// external crank) executes, and the 8-refresh 77 fits the 1.4M CU budget.
#[test]
fn refresh_cap_is_eight_and_fits_the_budget() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut traders = vec![];
    for i in 0..9 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, if i % 2 == 0 { q } else { -q }).expect("open");
        traders.push(p);
    }
    let lp = r.lp;
    walk_only(&mut r, 1_050_000, &[lp]); // only the LP is touched: 9 stale traders
    // keeper_ok request: the UNSIGNED path stays strictly loss-gated (A1's dip fallback is for
    // redeemer-signed exits only), so the cap is measured on the strict gate.
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    // 9 is not a valid wire.
    let mut nine = ProgInstruction::ExecuteRedemptionV22 { domain: 0, min_payout_atoms: 1, n_refresh: 8 }.encode();
    *nine.last_mut().unwrap() = 9;
    assert!(ProgInstruction::decode(&nine).is_err(), "n_refresh 9 must not decode");
    // 8 of 9: still stale (the whole transaction, refreshes included, reverts).
    let r8 = r.execute_77(&h, Some((1, traders[..8].to_vec())), false);
    assert_eq!(code(&r8), Some(ERR_NOT_LOSS_CURRENT), "{r8:?}");
    let (_, g) = r.env.market_state();
    assert_eq!(
        g.assets[0].stale_account_count_long + g.assets[0].stale_account_count_short,
        9,
        "the refused 77 reverted its refreshes"
    );
    // The 9th refreshed by any permissionless crank; then 8 REAL inline refreshes complete it.
    r.crank_pf(traders[8]);
    let (paid, cu) = r.execute_77(&h, Some((1, traders[..8].to_vec())), false).expect("8 inline + 1 cranked");
    eprintln!("refresh cap: 8-refresh 77 used {cu} CU, paid {paid}");
    assert!(cu < 1_400_000, "8 inline refreshes + redemption must fit 1.4M CU, used {cu}");
    assert!(paid > 0);
}

/// Rule 4: an unsigned (keeper) 77 needs a keeper_ok request; it is then loss-gated and floored
/// by the redeemer's stored minimum; a legacy request stays redeemer-signed only.
#[test]
fn keeper_execution_requires_keeper_ok_loss_current_and_stored_floor() {
    let mut w = r3m1_world();
    let lp = w.r.lp;
    // Legacy request: unsigned refused even on a current book.
    w.r.request_76(&w.m, w.m_ata, None).expect("M 76 legacy");
    // keeper_ok request with a floor.
    w.r.request_76(&w.h, w.h_ata, Some((R3M1_DEPOSIT - 2, 1))).expect("H 76 keeper_ok");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let stale = w.r.execute_77(&w.h, None, false);
    assert_eq!(code(&stale), Some(ERR_NOT_LOSS_CURRENT), "unsigned keeper exit in the dip: {stale:?}");
    let unsigned_legacy = w.r.execute_77(&w.m, Some((1, vec![w.a1, w.a2, lp])), false);
    assert_eq!(code(&unsigned_legacy), Some(ERR_EXPECTED_SIGNER), "{unsigned_legacy:?}");
    // Keeper refreshes inline and executes H's request at par (>= H's own floor).
    let (paid, _) = w
        .r
        .execute_77(&w.h, Some((1, vec![w.a1, w.a2, lp])), false)
        .expect("keeper 77 on a loss-current book");
    assert!(paid >= R3M1_DEPOSIT - 2, "I-X4: keeper exit at the redeemer's floor, paid {paid}");
    // A keeper_ok request whose stored floor is above the (exact) quote: the keeper cannot
    // execute it, on a loss-current book, at any wire floor of its own.
    let k = Keypair::new();
    let (k_ata, _) = w.r.deposit_shares(&k, R3M1_DEPOSIT, 0).expect("K 75");
    w.r.request_76(&k, k_ata, Some((R3M1_DEPOSIT + 1_000, 1))).expect("K 76 keeper_ok");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let before = w.r.exit_state(&k.pubkey());
    let low = w.r.execute_77(&k, Some((1, vec![w.a1, w.a2, lp])), false);
    assert_eq!(code(&low), Some(ERR_BELOW_MIN), "stored floor binds the keeper: {low:?}");
    assert_eq!(w.r.exit_state(&k.pubkey()), before, "117 moves nothing");
}

/// I-P/I-X: a new market's asset-0 profile carries EXIT_REQUIRES_LOSS_CURRENT and an oracle
/// re-anchor keeps it (no reconfiguration can clear it).
#[test]
fn exit_requires_loss_current_is_default_and_survives_reconfiguration() {
    let mut r = Replay::new(r2_market());
    let bit = percolator_prog::constants::P4_FLAG_EXIT_REQUIRES_LOSS_CURRENT;
    let flags = |r: &Replay| {
        let d = r.env.svm.get_account(&r.env.market).unwrap().data;
        state::profile_p4_flags(&state::read_asset_oracle_profile(&d, 0).unwrap())
    };
    assert_eq!(flags(&r), bit, "set at InitMarket");
    let s = r.now() + 1;
    r.env.svm.warp_to_slot(s);
    r.env.configure_auth_mark_for_asset_as_admin(0, s, 1_000_000);
    assert_eq!(flags(&r), bit, "kept by ConfigureAuthMark");
}

// ── I-X1 / I-X2 property: an honest third-party redeemer inside attacker-ordered touches ─────
#[derive(Clone, Debug)]
enum HOp {
    Touch(TouchOp),
    /// A5: a levered trader busts on a 15% walk (`up`: the walk direction) and is liquidated.
    Bust { up: bool },
    /// H tries to exit: legacy 77 (`inline == false`) or v2.2 with the full book inline, floor =
    /// `min_bps` of its par deposit.
    HExit { inline: bool, min_bps: u64 },
}

fn h_program() -> impl proptest::strategy::Strategy<Value = Vec<HOp>> {
    use proptest::prelude::*;
    let h_exit = (proptest::bool::weighted(0.25), 0u64..10_001).prop_map(|(inline, min_bps)| HOp::HExit { inline, min_bps });
    // An exit attempt right after every price walk (the moment an attacker's dip is open),
    // plus the tail ones.
    (touch_program(), proptest::collection::vec(h_exit, 4..8), 0usize..6, any::<bool>()).prop_map(|(ops, exits, bust_at, bust_up)| {
        let mut v: Vec<HOp> = vec![];
        let mut e = exits.into_iter();
        let mut busted = false;
        for (i, op) in ops.into_iter().enumerate() {
            let walk = matches!(op, TouchOp::Walk { .. });
            v.push(HOp::Touch(op));
            // A5: a bankruptcy at the first walk at or after `bust_at` (bust_at 0..3: most
            // programs; 3..6: some never bust, keeping clean-book histories in the mix).
            if walk && i >= bust_at && !busted {
                busted = true;
                v.push(HOp::Bust { up: bust_up });
                if let Some(x) = e.next() {
                    v.push(x);
                }
            }
            if walk {
                if let Some(x) = e.next() {
                    v.push(x);
                }
            }
        }
        v.extend(e);
        v
    })
}

impl Replay {
    /// Security review A3: the EXIT NAV is the COMBINED-pot E3, `min(ΣP, Σ phys) + Σ LP
    /// earnings` (independent model of what the program's ledger netting yields).
    fn earn_nav_exit(&self, g: &state::MarketGroupV16) -> u128 {
        let (mut p, mut phys, mut earn_total) = (0u128, 0u128, 0u128);
        for d in 0..2usize {
            let Some(acc) = self.env.svm.get_account(&self.ledgers[d]) else { continue };
            let Ok(l) = state::read_backing_domain_ledger(&acc.data) else { continue };
            let b = &g.source_backing_buckets[d];
            let c = &g.source_credit[d];
            let ins_cover = c.insurance_credit_reserved_num.saturating_sub(
                c.valid_liened_insurance_num + c.impaired_liened_insurance_num,
            );
            let earn = (l.total_earnings_atoms + b.utilization_fee_earnings
                - l.last_observed_bucket_earnings_atoms.min(b.utilization_fee_earnings))
            .saturating_sub(l.total_earnings_withdrawn_atoms);
            earn_total += earn * self.lm.earn_fee_share_bps as u128 / 10_000;
            p += l.total_principal_atoms;
            phys += percolator_prog::vault_lp_v18::pot_physical_net_atoms(
                b.fresh_unliened_backing_num,
                b.valid_liened_backing_num,
                c.positive_claim_bound_num,
                ins_cover,
                BOUND_SCALE,
            );
        }
        p.min(phys) + earn_total
    }
    fn principal_total(&self) -> u128 {
        (0..2usize)
            .filter_map(|d| self.env.svm.get_account(&self.ledgers[d]))
            .filter_map(|a| state::read_backing_domain_ledger(&a.data).ok())
            .map(|l| l.total_principal_atoms)
            .sum()
    }
    fn loss_current_now(&self) -> bool {
        let (_, g) = self.env.market_state();
        let a = &g.assets[0];
        a.stale_account_count_long == 0
            && a.stale_account_count_short == 0
            && self.no_genuine_loss_now()
    }
    /// A5: no domain barrier, retained obligation or pending B-index settlement.
    fn no_genuine_loss_now(&self) -> bool {
        let (_, g) = self.env.market_state();
        let a = &g.assets[0];
        g.pending_domain_loss_barriers.iter().take(2).all(|b| *b == 0)
            && a.pending_obligation_count_long == 0
            && a.pending_obligation_count_short == 0
            && g.b_stale_account_count == 0
            && g.negative_pnl_account_count == 0
            && g.stale_certificate_count == 0
    }
    /// H's exact claim on the CURRENT state under the program's own non-bound rule
    /// (floor(shares x E3 NAV / S)), computed by the test's independent E3 model.
    fn reference_payout(&self, shares: u128) -> u128 {
        let (_, g) = self.env.market_state();
        let nav = self.earn_nav_exit(&g);
        let reg = state::read_lp_vault_registry(&self.env.svm.get_account(&self.registry).unwrap().data).unwrap();
        shares * nav / reg.total_lp_shares_outstanding
    }
}

/// Coverage counters (non-vacuity): dip exits refused (118), signed dip exits executed under
/// the A1 bounded-dip floor, and exits refused while a genuine loss was pending (A5).
static R3M1_DIP_REFUSALS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static R3M1_DIP_EXECS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static R3M1_GENUINE_LOSS_REFUSALS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static R3M1_BUSTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// One executed H exit: (paid, signed floor, all-touched reference payout).
type HExitRecord = (u64, u64, u128);

/// Runs the attacker's history with H's exit attempts interleaved; asserts R3-M1's rules at
/// every attempt and returns the executed exit (`None` only if a genuine loss is still pending
/// at the end, the documented A7 liveness coupling). At every attempt:
/// * loss-current => executed pays the combined-pot E3 reference (I-X2, A3) and >= floor;
/// * NOT loss-current => refused (118 / value-safe wait), OR (A1) executed only if the book has
///   no genuine pending loss (A5) and the payout is within EXIT_DIP_BPS of par (and >= floor).
///
/// An inline exit first applies the same refreshes as permissionless cranks (I-X3).
fn run_h_ops(ops: &[HOp]) -> (Option<HExitRecord>, u32) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let h = Keypair::new();
    let (h_ata, h_shares) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75 at par");
    r.request_76(&h, h_ata, None).expect("H 76");
    let (a1k, a1) = r.new_trader(3_000_000_000);
    let (a2k, a2) = r.new_trader(3_000_000_000);
    let lp = r.lp;
    let e = Keypair::new();
    let mut atas: Vec<Pubkey> = vec![];
    let mut busts: Vec<Pubkey> = vec![];
    let mut open = false;
    let mut refusals = 0u32;
    let attempt = |r: &mut Replay, busts: &[Pubkey], inline: bool, min: u64, refusals: &mut u32| -> Option<HExitRecord> {
        let mut book = vec![a1, a2, lp];
        book.extend_from_slice(busts);
        if inline {
            // Drive the book to quiescence first: each crank is ONE bounded progress step (a
            // bust may need a liquidation, then an absorption, then a K/F re-touch), so a single
            // round can leave work that the 77's own inline refresh would then perform, and the
            // snapshot below would classify a state the program never priced (found by this
            // proptest at bdff6a6e: a loss-current 77 paying the exact reference after a bust was
            // misread as a stale exit). After quiescence the inline refresh is a no-op.
            for _ in 0..4 {
                for p in book.iter() {
                    r.crank_pf(*p);
                }
            }
        }
        let lc = r.loss_current_now();
        let genuine_clear = r.no_genuine_loss_now();
        let reference = r.reference_payout(h_shares as u128);
        let reg = state::read_lp_vault_registry(&r.env.svm.get_account(&r.registry).unwrap().data).unwrap();
        let par = h_shares as u128 * r.principal_total() / reg.total_lp_shares_outstanding;
        let wire = if inline {
            Some((min.max(1), book.clone()))
        } else if min > 0 {
            Some((min, vec![]))
        } else {
            None
        };
        match r.execute_77(&h, wire, true) {
            Ok((paid, _)) => {
                assert!(paid >= min, "I-X1: paid {paid} < floor {min}");
                if lc {
                    assert!(
                        (paid as u128).abs_diff(reference) <= 2,
                        "I-X2/A3: paid {paid}, combined all-touched reference {reference}"
                    );
                } else {
                    assert!(genuine_clear, "A5: a stale exit executed while a genuine loss was pending (paid {paid})");
                    assert!(
                        paid as u128 * 10_000 >= par * (10_000 - percolator_prog::wave_a_v22::EXIT_DIP_BPS as u128),
                        "A1: a stale exit paid {paid}, more than EXIT_DIP_BPS below par {par}"
                    );
                    R3M1_DIP_EXECS.fetch_add(1, Relaxed);
                }
                Some((paid, min, reference))
            }
            Err(err) => {
                let c = custom_code(&err);
                // Value-safe "wait" refusals only: not loss-current / beyond the dip bound (118),
                // below the floor (117), cooldown (36), pot liquidity (21 / 25), the
                // stay-fully-backed gate (122).
                assert!(
                    matches!(c, Some(ERR_NOT_LOSS_CURRENT) | Some(ERR_BELOW_MIN) | Some(36) | Some(21) | Some(25) | Some(122)),
                    "H exit refused for an unexpected reason (lc {lc}): {err}"
                );
                if lc {
                    assert_ne!(c, Some(ERR_NOT_LOSS_CURRENT), "118 on a loss-current book: {err}");
                    if c == Some(ERR_BELOW_MIN) {
                        assert!(reference < min as u128 + 2, "117 although the reference {reference} clears {min}");
                    }
                } else if c == Some(ERR_NOT_LOSS_CURRENT) {
                    if genuine_clear {
                        R3M1_DIP_REFUSALS.fetch_add(1, Relaxed);
                    } else {
                        R3M1_GENUINE_LOSS_REFUSALS.fetch_add(1, Relaxed);
                    }
                }
                *refusals += 1;
                None
            }
        }
    };
    for op in ops {
        match op {
            HOp::HExit { inline, min_bps } => {
                let min = R3M1_DEPOSIT * min_bps / 10_000;
                if let Some(rec) = attempt(&mut r, &busts, *inline, min, &mut refusals) {
                    return (Some(rec), refusals);
                }
            }
            HOp::Bust { up } => {
                // A5: a 9.5x-levered trader on the losing side of a 15% walk (only the LP is
                // touched during the walk), then cranked: liquidation with a bankruptcy residual
                // (insurance is 0 on r2), i.e. ADL obligations / loss weights / barriers.
                if busts.len() < 2 {
                    let p0 = r.env.market_state().1.assets[0].effective_price as i128;
                    let cap: u64 = 20_000_000;
                    let notional = 190_000_000i128;
                    let qb = notional * percolator::POS_SCALE as i128 / p0;
                    let (bk, bp) = r.new_trader(cap);
                    if r.trade(&bk, bp, if *up { -qb } else { qb }).is_ok() {
                        busts.push(bp);
                        let d = p0 as u64 * 1_500 / 10_000;
                        let target = if *up { p0 as u64 + d } else { (p0 as u64).saturating_sub(d).max(200_000) };
                        walk_only(&mut r, target, &[lp]);
                        r.crank_pf(bp);
                        R3M1_BUSTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            HOp::Touch(t) => match t {
                TouchOp::Open if !open => {
                    if r.trade(&a1k, a1, q).is_ok() {
                        if r.trade(&a2k, a2, -q).is_ok() {
                            open = true;
                        } else {
                            let _ = r.trade(&a1k, a1, -q);
                        }
                    }
                }
                TouchOp::Walk { up, bps, touch_a1, touch_a2 } => {
                    let p0 = r.env.market_state().1.assets[0].effective_price;
                    let d = p0 * bps / 10_000;
                    let target = if *up { p0 + d } else { p0.saturating_sub(d).max(200_000) };
                    let mut who = vec![lp];
                    if *touch_a1 {
                        who.push(a1);
                    }
                    if *touch_a2 {
                        who.push(a2);
                    }
                    walk_only(&mut r, target, &who);
                }
                TouchOp::Touch { a1: x } => r.crank_pf(if *x { a1 } else { a2 }),
                TouchOp::Close if open => {
                    let _ = r.trade(&a1k, a1, -q);
                    let _ = r.trade(&a2k, a2, q);
                    open = false;
                }
                TouchOp::Convert { a1: x } => {
                    let (k, p) = if *x { (&a1k, a1) } else { (&a2k, a2) };
                    let _ = r.convert_all(&k.insecure_clone(), p);
                }
                TouchOp::Deposit { pot, units } => {
                    if let Ok((ata, _)) = r.deposit_shares(&e, units * 1_000_000, *pot) {
                        if !atas.contains(&ata) {
                            atas.push(ata);
                        }
                    }
                }
                TouchOp::Redeem => {
                    for ata in atas.clone() {
                        if r.env.token_amount(ata) > 0 {
                            let _ = r.redeem_all(&e, ata);
                        }
                    }
                }
                _ => {}
            },
        }
    }
    // Liveness: once the pair is flat, H always gets out with the full book inline (the
    // attacker cannot hold the exit hostage), at a floor of 0.
    if open {
        let _ = r.trade(&a1k, a1, -q);
        let _ = r.trade(&a2k, a2, q);
    }
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    for _ in 0..2 {
        for p in [a1, a2, lp].iter().chain(busts.iter()) {
            r.crank_pf(*p);
        }
    }
    let rec = attempt(&mut r, &busts, true, 0, &mut refusals);
    if rec.is_none() {
        // Only acceptable while a genuine loss (bankrupt close / ADL) is still pending: the
        // documented A7 coupling, never a mispricing.
        assert!(!r.no_genuine_loss_now(), "H's final inline exit must execute on a clean book");
    }
    (rec, refusals)
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 24, max_shrink_iters: 16, .. Default::default() })]
    /// I-X1 and I-X2 for an honest third-party redeemer inside attacker-ordered touches (see
    /// `run_h_ops`). NOTE: the reference is the ALL-TOUCHED E3 value, not par: E3 caps each pot
    /// at its own principal, so a loss routed into one pot does not offset a claim on the
    /// other (pre-existing E3 design, independent of touch order; found by this proptest at
    /// 0.87% on a 3-walk history and recorded as an Info finding).
    #[test]
    fn r3m1_third_party_redeemer_proptest(ops in h_program()) {
        // Every assertion is inside `run_h_ops` (per attempt); here only non-vacuity: H's exit
        // executed exactly once, with a real payout.
        use std::sync::atomic::Ordering::Relaxed;
        let (rec, refusals) = run_h_ops(&ops);
        eprintln!(
            "R3-M1 property case: exit {rec:?}, refusals {refusals}; so far: dip refused {}, dip executed {}, genuine-loss refused {}, busts {}",
            R3M1_DIP_REFUSALS.load(Relaxed), R3M1_DIP_EXECS.load(Relaxed),
            R3M1_GENUINE_LOSS_REFUSALS.load(Relaxed), R3M1_BUSTS.load(Relaxed)
        );
        if let Some((paid, _min, reference)) = rec {
            proptest::prop_assert!(paid > 0 && reference > 0);
        }
    }
}

// ── v2.2 security review (Sentinel, 2026-10-05) regressions: A1, A3, A4 ──────────────────────

/// A1 world: H at par, `n` positioned single-leg traders (alternating long/short, 10 tokens) and
/// the LP, everyone refreshed at 1.02; then ONE ordinary keeper mark move (+4 bps) cranking only
/// the LP: every trader is K/F-stale again (the reviewer's S1).
fn a1_world(n: usize) -> (Replay, Keypair, Pubkey, Vec<Pubkey>) {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    for i in 0..n {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, if i % 2 == 0 { q } else { -q }).expect("open");
        tr.push(p);
    }
    let lp = r.lp;
    let mut all = tr.clone();
    all.push(lp);
    walk_only(&mut r, 1_020_000, &all);
    let s = r.now() + 1;
    r.env.svm.warp_to_slot(s);
    r.env.push_auth_mark_for_asset_as_admin(0, s, 1_020_400);
    r.crank_pf(lp);
    (r, h, h_ata, tr)
}

/// A1 regression (reviewer S1 at n = 12, before the fix Custom(118) for every exit): with 12
/// positioned traders the book cannot be made loss-current by 8 inline refreshes after an
/// ordinary mark move. The redeemer-SIGNED exit now executes under the bounded-dip floor
/// (payout >= par x (1 - 25 bps)); the unsigned keeper exit stays strictly gated (118).
#[test]
fn a1_signed_exit_on_a_twelve_trader_moving_book_executes_within_the_dip_bound() {
    let (mut r, h, h_ata, tr) = a1_world(12);
    let (_, g) = r.env.market_state();
    let stale = g.assets[0].stale_account_count_long + g.assets[0].stale_account_count_short;
    assert!(stale > 8, "more than 8 stale positioned portfolios: {stale}");
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    let keeper = r.execute_77(&h, Some((1, tr[..8].to_vec())), false);
    assert_eq!(code(&keeper), Some(ERR_NOT_LOSS_CURRENT), "the keeper path stays strict: {keeper:?}");
    let (paid, cu) = r
        .execute_77(&h, Some((1, tr[..8].to_vec())), true)
        .expect("A1: signed exit on a 12-trader moving book");
    eprintln!("A1 12-trader signed exit: paid {paid} (par {R3M1_DEPOSIT}), CU {cu}");
    assert!(paid as u128 * 10_000 >= R3M1_DEPOSIT as u128 * 9_975, "within 25 bps of par: {paid}");
}

/// A1 bound: a skim beyond EXIT_DIP_BPS is still refused for a signed exit. The reviewer's
/// R3-M1 dip (4.5%) with a signed, floor-less legacy 77: 118 and nothing moves (the port
/// `r3m1_honest_exit_inside_dip_is_not_skimmed` asserts the same on its own world).
#[test]
fn a1_signed_dip_exit_beyond_the_bound_is_still_refused() {
    let mut w = r3m1_world();
    w.r.request_76(&w.h, w.h_ata, None).expect("H 76");
    w.r.env.svm.warp_to_slot(w.r.now() + w.r.lm.earn_cooldown + 1);
    let before = w.r.exit_state(&w.h.pubkey());
    let dip = w.r.execute_77(&w.h, None, true);
    assert_eq!(code(&dip), Some(ERR_NOT_LOSS_CURRENT), "4.5% dip is beyond the 25 bps bound: {dip:?}");
    assert_eq!(w.r.exit_state(&w.h.pubkey()), before);
}

/// A3 regression (the builder's proptest seed; reviewer S3): with every account refreshed the
/// exit paid 991,306,666 for 1,000,000,000 (0.8693% below par) because E3 capped each pot at
/// its own principal. With the combined-pot exit (ledger netting) it pays par.
#[test]
fn a3_builders_seed_pays_par_with_combined_pot_e3() {
    let ops = vec![
        HOp::Touch(TouchOp::Open),
        HOp::Touch(TouchOp::Walk { up: true, bps: 302, touch_a1: false, touch_a2: false }),
        HOp::Touch(TouchOp::Convert { a1: true }),
        HOp::Touch(TouchOp::Redeem),
        HOp::Touch(TouchOp::Walk { up: false, bps: 843, touch_a1: true, touch_a2: false }),
        HOp::HExit { inline: true, min_bps: 7540 },
    ];
    let (rec, _) = run_h_ops(&ops);
    let (paid, _, reference) = rec.expect("H exited");
    eprintln!("A3 seed: H paid {paid} (reference {reference}, par {R3M1_DEPOSIT})");
    assert!(paid + 2 >= R3M1_DEPOSIT, "A3: the seed must pay par, got {paid}");
}

/// A4 regression (reviewer S4): a keeper_ok request with no floor is refused at decode, so it
/// can never be executed by a third party at an arbitrary moment. NEGATIVE CONTROL in the same
/// test: with a floor it is accepted.
#[test]
fn a4_keeper_ok_without_a_floor_is_refused() {
    let mut w = r3m1_world();
    let r0 = w.r.request_76(&w.h, w.h_ata, Some((0, 1)));
    assert!(
        r0.as_ref().is_err_and(|e| e.contains("InvalidInstructionData")),
        "A4: keeper_ok=1 with min_payout=0 must not decode: {r0:?}"
    );
    w.r.request_76(&w.h, w.h_ata, Some((1, 1))).expect("with a floor");
}

/// A6 (security review): 14-leg portfolios. One inline refresh of a 14-leg portfolio costs
/// ~530k CU, so 8 of them (or even 3) would exhaust the 1.4M meter. The leg-weighted budget
/// (3 + legs per refresh, <= 38) refuses 3 x 14-leg up front (InvalidInstruction, not a CU
/// abort), and 2 x 14-leg + 77 executes within 1.3M CU. Measured on the strict keeper path so
/// every refresh is real and the 77 executes. NEGATIVE CONTROL: the 8 single-leg case in
/// `refresh_cap_is_eight_and_fits_the_budget` still fits (32 units).
#[test]
fn a6_fourteen_leg_refreshes_are_leg_weighted_and_fit_the_budget() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let assets: u16 = 14;
    let px = 1_000_000u64;
    {
        let (_, g) = r.env.market_state();
        assert!(g.assets.len() >= assets as usize, "market has {} asset slots", g.assets.len());
        for a in 1..assets as usize {
            assert_eq!(g.assets[a].lifecycle, percolator::AssetLifecycleV16::Active, "asset {a} in service");
        }
    }
    // counterparty for assets 1..13
    let cp_owner = Keypair::new();
    r.env.svm.airdrop(&cp_owner.pubkey(), 10_000_000_000).unwrap();
    let cp = r.env.create_portfolio(&cp_owner);
    r.env.deposit(&cp_owner, cp, 100_000_000_000);
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    // one tag 5 on the counterparty with every asset hinted: accrues all 14 assets to now
    let crank_all = |r: &mut Replay| {
        let payer = r.env.payer.pubkey();
        let market = r.env.market;
        r.env.svm.expire_blockhash();
        r.env
            .send(
                ProgInstruction::PermissionlessCrank {
                    now_slot: 0,
                    observations: (0..assets)
                        .map(|a| CrankObservationHint { asset_index: a, oracle_accounts: 0 })
                        .collect(),
                },
                vec![AccountMeta::new(payer, true), AccountMeta::new(market, false), AccountMeta::new(cp, false)],
                &[],
            )
            .ok();
    };
    for i in 0..3 {
        let (k, p) = r.new_trader(1_000_000_000);
        let side = if i % 2 == 0 { q } else { -q };
        crank_all(&mut r);
        r.trade(&k, p, side).expect("asset 0 leg vs LP");
        for a in 1..assets {
            r.env.svm.expire_blockhash();
            r.env
                .try_trade_asset_with_cu(a, &k, p, &cp_owner, cp, side, px, 0)
                .unwrap_or_else(|e| panic!("asset {a} leg: {e}"));
        }
        let legs = percolator::active_bitmap_count_ones(r.env.portfolio_state(p).active_bitmap);
        assert_eq!(legs, assets as u32, "trader {i} holds a leg on every asset");
        tr.push(p);
    }
    let lp = r.lp;
    walk_only(&mut r, 1_020_000, &[lp]); // asset 0 moves: the 8 traders are stale on it
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    // accrue assets 1..13 in THIS slot (one tag 5 on the counterparty with every hint)
    crank_all(&mut r);
    let three = r.execute_77(&h, Some((1, tr.clone())), false);
    assert!(
        three.as_ref().is_err_and(|e| e.contains("Custom(13)") || custom_code(e) == Some(percolator_prog::error::PercolatorError::InvalidInstruction as u32)),
        "A6: 3 x 14-leg refreshes must be refused by the leg budget, not run out of CU: {three:?}"
    );
    assert!(three.as_ref().is_err_and(|e| !e.contains("exceeded CUs meter")));
    r.crank_pf(tr[2]); // the third portfolio refreshed by any permissionless crank
    let (paid, cu) = r
        .execute_77(&h, Some((1, tr[..2].to_vec())), false)
        .expect("2 x 14-leg inline refreshes + 77");
    eprintln!("A6: 2 refreshes of 14-leg portfolios + 77 = {cu} CU (paid {paid})");
    assert!(cu <= 1_300_000, "A6: {cu} CU exceeds the 1.3M budget");
}

/// A5 (security review): a redeemer-signed exit on a K/F-stale book must NOT use the A1
/// bounded-dip fallback while a GENUINE loss is pending (retained socialized-loss obligation,
/// pending B-index settlement, domain loss barrier): the fallback could otherwise front-run a
/// known bankruptcy. A real liquidation against the matcher LP settles its ADL through K at once
/// (nothing stays pending: measured, see `a1_world` + 9.5x bust, all counters 0), so the pending
/// state is a STATE POKE of the market header's `b_stale_account_count` (1) on the reviewer's
/// 9-trader K/F-stale book. NEGATIVE CONTROL in the same test: the same exit without the poke
/// executes under the dip floor.
#[test]
fn a5_signed_stale_exit_refused_while_a_genuine_loss_is_pending() {
    let (mut r, h, h_ata, _tr) = a1_world(9);
    r.request_76(&h, h_ata, None).expect("H 76");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    assert!(!r.loss_current_now() && r.no_genuine_loss_now(), "K/F-stale only");
    mutate_market_surgical(&mut r, |g| g.b_stale_account_count = 1);
    assert!(!r.no_genuine_loss_now(), "non-vacuity: a genuine loss is pending");
    let before = r.exit_state(&h.pubkey());
    let res = r.execute_77(&h, None, true);
    assert_eq!(code(&res), Some(ERR_NOT_LOSS_CURRENT), "A5: {res:?}");
    assert_eq!(r.exit_state(&h.pubkey()), before);
    mutate_market_surgical(&mut r, |g| g.b_stale_account_count = 0);
    let (paid, _) = r.execute_77(&h, None, true).expect("control: K/F-stale only -> dip floor");
    assert!(paid as u128 * 10_000 >= R3M1_DEPOSIT as u128 * 9_975, "{paid}");
}

// ── Sentinel's adversarial tests for #527 (tests/sec_v22a_replay.rs, 2026-10-05), adopted as
// regressions and re-asserted against the fixed behaviour. Reviewer-authored scenarios. ─────

impl Replay {
    fn stale_total(&self) -> u64 {
        let (_, g) = self.env.market_state();
        g.assets[0].stale_account_count_long + g.assets[0].stale_account_count_short
    }
    fn push_only(&mut self, target: u64) {
        let s = self.now() + 1;
        self.env.svm.warp_to_slot(s);
        self.env.push_auth_mark_for_asset_as_admin(0, s, target);
    }
}

/// Reviewer S1 (all n): with n <= 8 the full book fits the inline refresh; with n = 9 / 12 it
/// cannot be made loss-current, and the signed exit now executes under the A1 dip floor
/// (was Custom(118) for every exit).
#[test]
fn sec_s1_signed_exit_liveness_with_many_positioned_portfolios() {
    for n in [7usize, 8, 9, 12] {
        let (mut r, h, h_ata, tr) = a1_world(n);
        let lp = r.lp;
        r.request_76(&h, h_ata, None).expect("H 76");
        r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
        let mut all = tr.clone();
        all.push(lp);
        let refs: Vec<Pubkey> = if tr.len() < 8 { all } else { tr[..8].to_vec() };
        let (paid, cu) = r.execute_77(&h, Some((1, refs)), true).unwrap_or_else(|e| panic!("n={n}: {e}"));
        eprintln!("SEC-S1 n={n}: paid {paid}, CU {cu}");
        assert!(paid as u128 * 10_000 >= R3M1_DEPOSIT as u128 * 9_975, "n={n}: {paid}");
    }
}

/// Reviewer S1b: a keeper sweep that spans slots never converges while the mark moves one tick
/// per slot (still true: it is the engine's cohort rule). The keeper (unsigned) exit stays
/// refused; the redeemer-signed exit executes within the dip bound; a same-slot sweep makes the
/// book loss-current again and the legacy exit pays par.
#[test]
fn sec_s1b_cross_slot_sweep_keeper_strict_signed_bounded() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    for i in 0..12 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, if i % 2 == 0 { q } else { -q }).expect("open");
        tr.push(p);
    }
    let lp = r.lp;
    let mut all = tr.clone();
    all.push(lp);
    walk_only(&mut r, 1_020_000, &all);
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    let mut px = 1_020_000u64;
    let mut min_stale = u64::MAX;
    for _ in 0..3 {
        for p in all.iter() {
            px += 100;
            r.push_only(px);
            r.crank_pf(*p);
            min_stale = min_stale.min(r.stale_total());
        }
    }
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    assert!(min_stale > 0, "a cross-slot sweep never reaches zero while the mark moves");
    let keeper = r.execute_77(&h, Some((1, tr[..8].to_vec())), false);
    assert_eq!(code(&keeper), Some(ERR_NOT_LOSS_CURRENT), "keeper path strict: {keeper:?}");
    let s = r.now();
    for p in all.iter() {
        r.crank_pf(*p);
    }
    assert_eq!((r.now(), r.stale_total()), (s, 0), "same-slot sweep is clean");
    let (paid, _) = r.execute_77(&h, None, true).expect("legacy 77 after a same-slot sweep");
    assert!(paid + 2 >= R3M1_DEPOSIT, "{paid}");
}

/// Reviewer S2 / S2b: exit BEFORE accrual (mark pushed, not cranked) vs after the inline
/// refresh. The reviewer found no difference (1,000,000,000 both); pinned as a regression.
#[test]
fn sec_s2_s2b_exit_before_accrual_pays_the_same() {
    for hedged in [true, false] {
        let mut paid = vec![];
        for inline in [false, true] {
            let mut r = Replay::new(r2_market());
            let h = Keypair::new();
            let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H");
            let lp = r.lp;
            let book = if hedged {
                let q: i128 = 1_000 * percolator::POS_SCALE as i128;
                let (a1k, a1) = r.new_trader(1_000_000_000);
                let (a2k, a2) = r.new_trader(1_000_000_000);
                r.trade(&a1k, a1, q).expect("A1");
                r.trade(&a2k, a2, -q).expect("A2");
                vec![a1, a2, lp]
            } else {
                let q: i128 = 5_000 * percolator::POS_SCALE as i128;
                let (ak, a) = r.new_trader(3_000_000_000);
                r.trade(&ak, a, q).expect("A long vs LP");
                vec![a, lp]
            };
            walk_only(&mut r, 1_000_000, &book);
            r.request_76(&h, h_ata, None).expect("H 76");
            r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
            r.push_only(1_004_000);
            let wire = if inline { Some((1, book.clone())) } else { Some((1, vec![])) };
            paid.push(r.execute_77(&h, wire, true).expect("exit").0);
        }
        eprintln!("SEC-S2 hedged={hedged}: before accrual {} vs after {}", paid[0], paid[1]);
        assert_eq!(paid[0], paid[1], "hedged={hedged}");
    }
}

/// Reviewer S3b: two equal holders exit one after the other after a closed zero-sum pair. With
/// the combined-pot exit (A3) both get par (before: the first exiter lost its share of the
/// stranded cross-pot surplus).
#[test]
fn sec_s3b_two_holders_both_exit_at_par_after_a_closed_pair() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let m = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H");
    let (m_ata, _) = r.deposit_shares(&m, R3M1_DEPOSIT, 0).expect("M");
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let (a1k, a1) = r.new_trader(1_000_000_000);
    let (a2k, a2) = r.new_trader(1_000_000_000);
    let lp = r.lp;
    let pair = [a1, a2, lp];
    r.trade(&a1k, a1, q).unwrap();
    r.trade(&a2k, a2, -q).unwrap();
    r.walk(1_090_000, &pair);
    r.trade(&a1k, a1, -q).unwrap();
    r.trade(&a2k, a2, q).unwrap();
    r.hold(r.lm.params.h_max + 2, &pair);
    r.convert_all(&a1k, a1).ok();
    r.hold(3, &pair);
    let h_paid = r.redeem_all(&h, h_ata).expect("H exits");
    let m_paid = r.redeem_all(&m, m_ata).expect("M exits");
    eprintln!("SEC-S3b H paid {h_paid}, M paid {m_paid} (par {R3M1_DEPOSIT} each)");
    assert!(h_paid + 2 >= R3M1_DEPOSIT && m_paid + 2 >= R3M1_DEPOSIT, "H {h_paid} M {m_paid}");
}

/// Reviewer S6: 8 inline refreshes where each refreshed long is underwater after a 12% walk
/// (liquidating refreshes). Must stay inside 1.3M CU; strict keeper path so all 8 are real.
#[test]
fn sec_s6_cu_eight_liquidating_refreshes() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 100 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    for _ in 0..8 {
        let (k, p) = r.new_trader(11_000_000);
        r.trade(&k, p, q).expect("open levered long");
        tr.push(p);
    }
    let lp = r.lp;
    walk_only(&mut r, 880_000, &[lp]);
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    let res = r.execute_77(&h, Some((1, tr.clone())), false);
    eprintln!("SEC-S6 8 liquidating refreshes: {:?}", res.as_ref().map(|x| x.1).map_err(|e| custom_code(e)));
    if let Ok((_, cu)) = res {
        assert!(cu <= 1_300_000, "S6: {cu}");
    } else {
        // a liquidation can leave a genuine loss pending: then a refusal (118) is the A5 rule
        assert_eq!(code(&res), Some(ERR_NOT_LOSS_CURRENT), "{res:?}");
        assert!(!r.no_genuine_loss_now() || r.stale_total() > 0);
    }
}

/// Market whose bankruptcy residuals and per-account B settlement move in 1-USDC chunks, so a
/// real bust leaves pending socialized-loss settlement across several touches.
fn chunked_b_market() -> LiveMarket {
    let mut lm = r2_market();
    lm.params.public_b_chunk_atoms = std::env::var("A5X_CHUNK").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    lm
}

impl Replay {
    fn loss_snapshot(&self) -> String {
        let (_, g) = self.env.market_state();
        let a = &g.assets[0];
        format!(
            "stale {}/{} obl {}/{} b_stale {} barriers {:?} b_num {}/{} neg_pnl {} stale_certs {}",
            a.stale_account_count_long, a.stale_account_count_short,
            a.pending_obligation_count_long, a.pending_obligation_count_short,
            g.b_stale_account_count, &g.pending_domain_loss_barriers[..2],
            a.b_long_num, a.b_short_num, g.negative_pnl_account_count, g.stale_certificate_count
        )
    }
}

#[test]
#[ignore = "exploration: prints the counters through a real chunked bankruptcy"]
fn a5_explore_real_chunked_bankruptcy() {
    let mut r = Replay::new(chunked_b_market());
    let h = Keypair::new();
    let (_h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut shorts = vec![];
    for _ in 0..3 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, -q).expect("short");
        shorts.push(p);
    }
    let lp = r.lp;
    let p0 = r.env.market_state().1.assets[0].effective_price as i128;
    let qb = 190_000_000i128 * percolator::POS_SCALE as i128 / p0;
    let (bk, bp) = r.new_trader(20_000_000);
    r.trade(&bk, bp, qb).expect("levered long");
    eprintln!("A5X open: {}", r.loss_snapshot());
    walk_only(&mut r, (p0 as u64) * 85 / 100, &[lp]);
    eprintln!("A5X after walk: {}", r.loss_snapshot());
    for i in 0..12 {
        r.crank_pf(bp);
        eprintln!("A5X bust crank {i}: {}", r.loss_snapshot());
    }
    for i in 0..6 {
        r.crank_pf(lp);
        eprintln!("A5X lp crank {i}: {}", r.loss_snapshot());
        for p in shorts.iter() {
            r.crank_pf(*p);
        }
        eprintln!("A5X shorts crank {i}: {}", r.loss_snapshot());
    }
}

/// A6 round 2: two 14-leg portfolios that are LIQUIDATABLE after an asset-0 drop (a 100-token
/// asset-0 long + 13 x 10-token legs on $25 capital, asset 0 down 15%). One inline refresh is
/// one bounded crank, so each refresh liquidates (at most one leg) on top of re-certifying 14
/// legs: the heaviest refresh the budget admits (2 x 17 = 34 units).
#[test]
fn a6_two_liquidating_fourteen_leg_refreshes_cu() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let assets: u16 = 14;
    let px = 1_000_000u64;
    let cp_owner = Keypair::new();
    r.env.svm.airdrop(&cp_owner.pubkey(), 10_000_000_000).unwrap();
    let cp = r.env.create_portfolio(&cp_owner);
    r.env.deposit(&cp_owner, cp, 100_000_000_000);
    let crank_all = |r: &mut Replay| {
        let payer = r.env.payer.pubkey();
        let market = r.env.market;
        r.env.svm.expire_blockhash();
        r.env
            .send(
                ProgInstruction::PermissionlessCrank {
                    now_slot: 0,
                    observations: (0..assets)
                        .map(|a| CrankObservationHint { asset_index: a, oracle_accounts: 0 })
                        .collect(),
                },
                vec![AccountMeta::new(payer, true), AccountMeta::new(market, false), AccountMeta::new(cp, false)],
                &[],
            )
            .ok();
    };
    let q10: i128 = 10 * percolator::POS_SCALE as i128;
    let q100: i128 = 100 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    for _ in 0..2 {
        let (k, p) = r.new_trader(25_000_000);
        crank_all(&mut r);
        r.trade(&k, p, q100).expect("asset 0 long 100 vs LP");
        for a in 1..assets {
            r.env.svm.expire_blockhash();
            r.env
                .try_trade_asset_with_cu(a, &k, p, &cp_owner, cp, q10, px, 0)
                .unwrap_or_else(|e| panic!("asset {a} leg: {e}"));
        }
        tr.push(p);
    }
    let lp = r.lp;
    walk_only(&mut r, 850_000, &[lp]);
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    crank_all(&mut r);
    let before: Vec<i128> = tr.iter().map(|p| r.env.portfolio_state(*p).capital as i128).collect();
    let res = r.execute_77(&h, Some((1, tr.clone())), false);
    let after: Vec<i128> = tr.iter().map(|p| r.env.portfolio_state(*p).capital as i128).collect();
    eprintln!("A6-LIQ 2 x 14-leg liquidating refreshes: {:?} (capital {before:?} -> {after:?})", res.as_ref().map(|x| x.1).map_err(|e| custom_code(e)));
    let (_, cu) = res.expect("2 x 14-leg liquidating refreshes + 77");
    assert!(cu <= 1_260_000, "A6: {cu} CU leaves < 10% headroom under 1.4M");
}

/// A6 round 2: oracle-tail refreshes on a NON-AuthMark vault asset. Asset 0 is reconfigured to
/// Hybrid with one Pyth leg; every inline refresh then parses the oracle tail. 8 single-leg
/// stale traders (8 x 4 = 32 units) on the strict keeper path.
#[test]
fn a6_hybrid_oracle_tail_eight_refreshes_cu() {
    use solana_sdk::clock::Clock;
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let feed = [7u8; 32];
    // LiteSVM starts at unix_timestamp 0; Pyth needs a real (positive, fresh) publish time.
    let mut clock = r.env.svm.get_sysvar::<Clock>();
    clock.unix_timestamp = 1_700_000_000;
    r.env.svm.set_sysvar(&clock);
    let ts = clock.unix_timestamp;
    let pyth = r.env.set_pyth_price(&feed, 1_000_000, -6, ts);
    let slot = r.now();
    r.env
        .try_configure_hybrid_with_cu(1, 0, [feed, [0u8; 32], [0u8; 32]], &[pyth], slot, ts, 0, 0, 10_000)
        .expect("asset 0 -> Hybrid (1 Pyth leg)");
    let crank_o = |r: &mut Replay, p: Pubkey, oracle: Pubkey| -> Result<u64, String> {
        let payer = r.env.payer.pubkey();
        let market = r.env.market;
        r.env.svm.expire_blockhash();
        r.env.send(
            ProgInstruction::PermissionlessCrank {
                now_slot: 0,
                observations: vec![CrankObservationHint { asset_index: 0, oracle_accounts: 1 }],
            },
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new(market, false),
                AccountMeta::new(p, false),
                AccountMeta::new_readonly(oracle, false),
            ],
            &[],
        )
    };
    let lp = r.lp;
    crank_o(&mut r, lp, pyth).ok();
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut tr = vec![];
    for i in 0..8 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, if i % 2 == 0 { q } else { -q }).unwrap_or_else(|e| panic!("open {i}: {e}"));
        tr.push(p);
    }
    // walk the external price +2% over a few slots, cranking only the LP (traders go stale)
    let mut px = 1_000_000i64;
    let mut oracle = pyth;
    let mut t = ts;
    let mut tick = |r: &mut Replay, t: &mut i64| {
        let s = r.now() + 1;
        r.env.svm.warp_to_slot(s);
        *t += 1;
        let mut c = r.env.svm.get_sysvar::<Clock>();
        c.unix_timestamp = *t;
        r.env.svm.set_sysvar(&c);
    };
    for _ in 0..8 {
        tick(&mut r, &mut t);
        px += 2_500;
        oracle = r.env.set_pyth_price(&feed, px, -6, t);
        crank_o(&mut r, lp, oracle).unwrap_or_else(|e| panic!("lp crank: {e}"));
    }
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    tick(&mut r, &mut t);
    tick(&mut r, &mut t);
    oracle = r.env.set_pyth_price(&feed, px, -6, t);
    // the 77's oracle tail follows the 8 refresh accounts
    let pid = r.env.program_id;
    let escrow = state::derive_lp_escrow(&pid, &r.env.market).0;
    let red = r.redemption_pda(&h.pubkey());
    let dest = r.env.token_account_for_mint(r.env.mint, h.pubkey(), 0);
    let payer = r.env.payer.pubkey();
    let mut metas = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(r.env.market, false),
        AccountMeta::new(r.registry, false),
        AccountMeta::new(red, false),
        AccountMeta::new(r.lp_mint, false),
        AccountMeta::new(escrow, false),
        AccountMeta::new(r.env.vault, false),
        AccountMeta::new_readonly(r.env.vault_authority, false),
        AccountMeta::new(r.ledgers[0], false),
        AccountMeta::new(dest, false),
        AccountMeta::new_readonly(spl_token::ID, false),
        AccountMeta::new(r.ledgers[1], false),
        AccountMeta::new(h.pubkey(), false),
    ];
    for p in tr.iter() {
        metas.push(AccountMeta::new(*p, false));
    }
    metas.push(AccountMeta::new_readonly(oracle, false));
    r.env.svm.expire_blockhash();
    let res = r.env.send(
        ProgInstruction::ExecuteRedemptionV22 { domain: 0, min_payout_atoms: 1, n_refresh: 8 },
        metas,
        &[],
    );
    eprintln!("A6-HYB 8 oracle-tail refreshes + 77: {:?}", res.as_ref().map_err(|e| custom_code(e)));
    let cu = res.expect("8 hybrid refreshes + 77");
    assert!(cu <= 1_260_000, "A6 hybrid: {cu} CU leaves < 10% headroom under 1.4M");
}

/// A5 round 2, REAL repro (no state poke): a 9.5x-levered long busts on a 15% walk in a market
/// whose bankruptcy residual exceeds `public_b_chunk_atoms` (2 USDC). After the bust's crank the
/// account's unabsorbed deficit is pending (`negative_pnl_account_count` = 1) and the shorts are
/// K/F-stale; the redeemer-SIGNED exit, which would otherwise take the dip fallback, is refused
/// with 118 and nothing moves.
///
/// Why not `b_stale_account_count`: measured (`a5_explore_real_chunked_bankruptcy`, ignored), a
/// residual > `public_b_chunk_atoms` never starts the multi-step close in this harness (every
/// later crank fails EngineInvalidConfig = 14: an engine-side wedge, recorded in findings.md),
/// and a residual <= the chunk is socialized through K at once, so every account settles its B
/// share in one touch: per-account B-staleness is not reachable here. The pending state that IS
/// reachable is the unabsorbed negative PnL, which the gate now includes.
#[test]
fn a5_real_bust_pending_negative_pnl_refuses_the_signed_fallback() {
    let mut lm = r2_market();
    lm.params.public_b_chunk_atoms = 2_000_000;
    let mut r = Replay::new(lm);
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    for _ in 0..3 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, -q).expect("short");
    }
    let lp = r.lp;
    let p0 = r.env.market_state().1.assets[0].effective_price as i128;
    let qb = 190_000_000i128 * percolator::POS_SCALE as i128 / p0;
    let (bk, bp) = r.new_trader(20_000_000);
    r.trade(&bk, bp, qb).expect("levered long");
    r.request_76(&h, h_ata, None).expect("H 76");
    walk_only(&mut r, (p0 as u64) * 85 / 100, &[lp]);
    r.crank_pf(bp);
    eprintln!("A5 real: {}", r.loss_snapshot());
    let (_, g) = r.env.market_state();
    assert!(g.negative_pnl_account_count > 0, "non-vacuity: an unabsorbed deficit is pending");
    assert!(!r.no_genuine_loss_now());
    let before = r.exit_state(&h.pubkey());
    let res = r.execute_77(&h, None, true);
    assert_eq!(code(&res), Some(ERR_NOT_LOSS_CURRENT), "A5 real: {res:?}");
    assert_eq!(r.exit_state(&h.pubkey()), before);
}

/// Round 2 multi-asset: the vault (asset 0) is loss-current, asset 1 is not (a trader holds
/// legs on both; asset 1's mark moves and only the counterparty is touched). The UNSIGNED
/// keeper exit is refused (118: every configured asset must be loss-current); the redeemer-
/// signed exit is unaffected (the vault asset's own pot is exact). NEGATIVE CONTROL in the same
/// test: once asset 1 is refreshed the keeper exit executes.
#[test]
fn multi_asset_keeper_exit_needs_every_asset_loss_current() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let m = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let (m_ata, _) = r.deposit_shares(&m, R3M1_DEPOSIT, 0).expect("M 75");
    let s = r.now() + 1;
    r.env.svm.warp_to_slot(s);
    r.env.configure_auth_mark_for_asset_as_admin(1, s, 1_000_000);
    let cp_owner = Keypair::new();
    r.env.svm.airdrop(&cp_owner.pubkey(), 10_000_000_000).unwrap();
    let cp = r.env.create_portfolio(&cp_owner);
    r.env.deposit(&cp_owner, cp, 10_000_000_000);
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let (tk, t) = r.new_trader(1_000_000_000);
    r.trade(&tk, t, q).expect("asset 0 leg vs LP");
    r.env.svm.expire_blockhash();
    r.env.try_trade_asset_with_cu(1, &tk, t, &cp_owner, cp, q, 1_000_000, 0).expect("asset 1 leg");
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.request_76(&m, m_ata, None).expect("M 76");
    // asset 1 moves; only the counterparty is cranked on asset 1 (the trader stays stale there)
    let crank1 = |r: &mut Replay, p: Pubkey| {
        let payer = r.env.payer.pubkey();
        let market = r.env.market;
        r.env.svm.expire_blockhash();
        r.env
            .send(
                ProgInstruction::PermissionlessCrank {
                    now_slot: 0,
                    observations: vec![
                        CrankObservationHint { asset_index: 0, oracle_accounts: 0 },
                        CrankObservationHint { asset_index: 1, oracle_accounts: 0 },
                    ],
                },
                vec![AccountMeta::new(payer, true), AccountMeta::new(market, false), AccountMeta::new(p, false)],
                &[],
            )
            .ok();
    };
    for i in 1..=5u64 {
        let s = r.now() + 1;
        r.env.svm.warp_to_slot(s);
        r.env.push_auth_mark_for_asset_as_admin(1, s, 1_000_000 + 1_000 * i);
        r.env.push_auth_mark_for_asset_as_admin(0, s, 1_000_000);
        crank1(&mut r, cp);
        let lp = r.lp;
        crank1(&mut r, lp);
    }
    // the trader's asset-0 leg stays current: asset 0's mark never moves (K unchanged)
    let (_, g) = r.env.market_state();
    let a0 = &g.assets[0];
    let a1 = &g.assets[1];
    eprintln!(
        "MULTI: asset0 stale {}/{} asset1 stale {}/{}",
        a0.stale_account_count_long, a0.stale_account_count_short, a1.stale_account_count_long, a1.stale_account_count_short
    );
    assert_eq!(a0.stale_account_count_long + a0.stale_account_count_short, 0, "vault asset current");
    assert!(a1.stale_account_count_long + a1.stale_account_count_short > 0, "asset 1 stale");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    let keeper = r.execute_77(&h, None, false);
    assert_eq!(code(&keeper), Some(ERR_NOT_LOSS_CURRENT), "keeper exit with asset 1 stale: {keeper:?}");
    let (m_paid, _) = r.execute_77(&m, None, true).expect("signed exit: the vault asset is current");
    assert!(m_paid + 2 >= R3M1_DEPOSIT, "{m_paid}");
    crank1(&mut r, t);
    let (h_paid, _) = r.execute_77(&h, None, false).expect("control: keeper exit once every asset is current");
    assert!(h_paid + 2 >= R3M1_DEPOSIT, "{h_paid}");
}

// =============================================================================================
// ROUND 3 reviewer tests: is negative_pnl_account_count a liveness grief?
// =============================================================================================

fn sec_bust_world(chunk: u64, lev_notional: i128, capital: u64) -> (Replay, Keypair, Pubkey, Vec<Pubkey>, Pubkey) {
    let mut lm = r2_market();
    lm.params.public_b_chunk_atoms = chunk as u128;
    let mut r = Replay::new(lm);
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let q: i128 = 10 * percolator::POS_SCALE as i128;
    let mut shorts = vec![];
    for _ in 0..3 {
        let (k, p) = r.new_trader(100_000_000);
        r.trade(&k, p, -q).expect("short");
        shorts.push(p);
    }
    let p0 = r.env.market_state().1.assets[0].effective_price as i128;
    let qb = lev_notional * percolator::POS_SCALE as i128 / p0;
    let (bk, bp) = r.new_trader(capital);
    r.trade(&bk, bp, qb).expect("levered long");
    r.request_76(&h, h_ata, None).expect("H 76");
    let _ = bk;
    (r, h, h_ata, shorts, bp)
}

fn sec_report(tag: &str, r: &mut Replay, h: &Keypair, all: &[Pubkey]) {
    let (_, g) = r.env.market_state();
    eprintln!("SEC-R3 {tag}: {} | status ok", r.loss_snapshot());
    let _ = (h, all, g);
}

/// N1: a SOLVENT but underwater (below maintenance? no: above) account, touched: does it count?
#[test]
fn sec_r3_n1_solvent_underwater_account_does_not_count() {
    // 5x long (100e6 notional on 20e6), walk -10%: loss 10e6 < 20e6 capital, equity 10e6 > MM.
    let (mut r, h, _ha, shorts, bp) = sec_bust_world(1_000_000_000_000, 100_000_000, 20_000_000);
    let lp = r.lp;
    let p0 = r.env.market_state().1.assets[0].effective_price;
    walk_only(&mut r, p0 * 90 / 100, &[lp]);
    r.crank_pf(bp);
    sec_report("solvent-underwater touched", &mut r, &h, &[]);
    let (_, g) = r.env.market_state();
    assert_eq!(g.negative_pnl_account_count, 0, "a touched solvent account settles from principal");
    let _ = shorts;
}

/// N2/N3: a bust. Default chunk (1e12) and the builder's small chunk (2e6). After the bust,
/// keep cranking everyone for 40 slots; report the counters and whether a signed exit works.
#[test]
fn sec_r3_n2_bust_persistence_default_chunk() {
    sec_bust_persistence("default chunk", 1_000_000_000_000);
}
#[test]
fn sec_r3_n3_bust_persistence_small_chunk() {
    sec_bust_persistence("small chunk 2e6", 2_000_000);
}
fn sec_bust_persistence(tag: &str, chunk: u64) {
    let (mut r, h, _ha, shorts, bp) = sec_bust_world(chunk, 190_000_000, 20_000_000);
    let lp = r.lp;
    let p0 = r.env.market_state().1.assets[0].effective_price;
    walk_only(&mut r, p0 * 85 / 100, &[lp]);
    r.crank_pf(bp);
    eprintln!("SEC-R3 [{tag}] after bust crank: {}", r.loss_snapshot());
    let mut all = shorts.clone();
    all.push(bp);
    all.push(lp);
    for k in 0..40u64 {
        r.hold(1, &all);
        if k == 0 || k == 9 || k == 39 {
            eprintln!("SEC-R3 [{tag}] +{} slots of full cranks: {}", k + 1, r.loss_snapshot());
        }
    }
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    let res = r.execute_77(&h, Some((1, all.clone())), true);
    eprintln!("SEC-R3 [{tag}] signed exit with full refresh: {:?}", res.as_ref().map(|x| x.0).map_err(|e| custom_code(e)));
}
