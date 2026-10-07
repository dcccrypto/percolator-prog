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

// ═════════════════ Sentinel v22 Wave D review (2026-10-05): rescue adversarial tests ═════════════════
const SEC_DEPOSIT: u64 = 2_000_000_000;

impl Replay {
    fn sec_pots(&self) -> Vec<(u128, i128)> {
        let s = self.snap();
        let mut v = vec![];
        for d in 0..2usize {
            let l = state::read_backing_domain_ledger(&self.env.svm.get_account(&self.ledgers[d]).unwrap().data).unwrap();
            v.push((l.total_principal_atoms, (s.fresh[d] + s.valid[d]) as i128 - s.claim[d] as i128));
        }
        v
    }
    fn stale_total(&self) -> u64 {
        let (_, g) = self.env.market_state();
        g.assets[0].stale_account_count_long + g.assets[0].stale_account_count_short
    }
    fn sec_rescue(&mut self, who: &Keypair, amount: u64, min_shares: u128) -> (Pubkey, Result<u64, String>) {
        self.env.ensure_signer_account(who.pubkey());
        let ata = self.env.token_account_for_mint(self.lp_mint, who.pubkey(), 0);
        let src = self.env.token_account_for_mint(self.env.mint, who.pubkey(), amount);
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
        let r = self.env.send(ProgInstruction::RescueDeposit { tranche: 0, amount, min_shares }, metas, &[who]);
        (ata, r)
    }
}

/// SEC-D1: the E3 per-pot cap wedge (Wave A review A3: a hedged zero-sum pair strands over-principal
/// surplus in the other pot, so E3 < par although the vault physically holds par) makes a perfectly
/// SOLVENT vault look "impaired". Does tag 112 admit a rescue, and at what price vs par?
#[test]
fn sec_d1_rescue_admitted_on_a_solvent_vault_by_the_e3_wedge() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let m = Keypair::new();
    let (_h_ata, h_sh) = r.deposit_shares(&h, SEC_DEPOSIT, 0).expect("H");
    let (_m_ata, m_sh) = r.deposit_shares(&m, SEC_DEPOSIT, 0).expect("M");
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
    let s = r.snap();
    s.print("SEC-D1 after pair closed + A1 converted");
    let pots = r.sec_pots();
    let st1 = r.env.portfolio_state(a1);
    let st2 = r.env.portfolio_state(a2);
    let pair_net = st1.capital as i128 + st1.pnl + st2.capital as i128 + st2.pnl - 2_000_000_000;
    eprintln!("SEC-D1 pots (principal, phys-claims) {:?}; earn principal {} E3 NAV {}; pair net {}; stale {}", pots, s.earn_principal, s.earn_nav, pair_net, r.stale_total());
    let par = s.earn_principal;
    let v = s.earn_nav;
    eprintln!("SEC-D1 par {par} E3 v {v} => impairment {:.4}% (physical sum of pots {})", (par as f64 - v as f64) / par as f64 * 100.0, pots.iter().map(|p| p.1).sum::<i128>());
    // Rescuer: R buys at the "impaired" E3 value.
    let rr = Keypair::new();
    let x = 10 * v.min(par) as u64 / 11; // below 10v cap
    let x = x.max(100_000_000);
    let (r_ata, res) = r.sec_rescue(&rr, x, 1);
    let minted = r.env.token_amount(r_ata);
    let fair_at_par = (x as u128) * (h_sh as u128 + m_sh as u128) / par;
    eprintln!("SEC-D1 rescue x={x} -> {:?}; minted {minted}; shares a par-priced entry would give {fair_at_par}; S before {}", res, h_sh + m_sh);
    if res.is_ok() && fair_at_par > 0 {
        eprintln!("SEC-D1 rescuer got {:.4}% more shares than par-priced entry", (minted as f64 / fair_at_par as f64 - 1.0) * 100.0);
    }
    let s2 = r.snap();
    s2.print("SEC-D1 after rescue");
    eprintln!("SEC-D1 pots after {:?}; E3 NAV after {} (principal {})", r.sec_pots(), s2.earn_nav, s2.earn_principal);
}

/// SEC-D1b: the exact Wave-A-review A3 seed (E3 per-pot cap wedge: H paid 0.8693% below par), then
/// a rescuer instead of the H exit.
#[test]
fn sec_d1b_rescue_on_the_a3_wedge_seed() {
    let mut r = Replay::new(r2_market());
    let q: i128 = 1_000 * percolator::POS_SCALE as i128;
    let h = Keypair::new();
    let (_h_ata, h_shares) = r.deposit_shares(&h, SEC_DEPOSIT / 2, 0).expect("H 75 at par");
    let (a1k, a1) = r.new_trader(3_000_000_000);
    let (a2k, a2) = r.new_trader(3_000_000_000);
    let lp = r.lp;
    r.trade(&a1k, a1, q).expect("A1 long");
    r.trade(&a2k, a2, -q).expect("A2 short");
    let up = |r: &mut Replay, bps: u64, up: bool, who: &[Pubkey]| {
        let p0 = r.env.market_state().1.assets[0].effective_price;
        let d = p0 * bps / 10_000;
        let target = if up { p0 + d } else { p0.saturating_sub(d).max(200_000) };
        walk_only(r, target, who);
    };
    up(&mut r, 302, true, &[lp]);
    let _ = r.convert_all(&a1k.insecure_clone(), a1);
    up(&mut r, 843, false, &[lp, a1]);
    for p in [a1, a2, lp] {
        r.crank_pf(p);
    }
    let s = r.snap();
    s.print("SEC-D1b pre-rescue");
    let pots = r.sec_pots();
    eprintln!("SEC-D1b pots (ledger principal, physical net of claims) {:?}; principal {} E3 NAV {}; stale {}", pots, s.earn_principal, s.earn_nav, r.stale_total());
    let (par, v) = (s.earn_principal, s.earn_nav);
    eprintln!("SEC-D1b par {par} v {v} => {:.4}% below par; sum of physical nets {}", (par as f64 - v as f64) / par as f64 * 100.0, pots.iter().map(|p| p.1).sum::<i128>());
    let rr = Keypair::new();
    let x = ((10 * v) / 11).min(u64::MAX as u128) as u64;
    let (r_ata, res) = r.sec_rescue(&rr, x, 1);
    let minted = r.env.token_amount(r_ata);
    let s_before = r.registry_shares_total(h_shares as u128);
    eprintln!("SEC-D1b rescue x={x} -> {:?}", res.as_ref().map_err(|e| e.chars().take(80).collect::<String>()));
    eprintln!("SEC-D1b minted {minted}; par-priced entry would mint {}; S before {s_before}", (x as u128) * s_before / par);
    let s2 = r.snap();
    eprintln!("SEC-D1b after: principal {} E3 NAV {} pots {:?}", s2.earn_principal, s2.earn_nav, r.sec_pots());
}

impl Replay {
    fn registry_shares_total(&self, fallback: u128) -> u128 {
        let d = self.env.svm.get_account(&self.registry).map(|a| a.data).unwrap_or_default();
        state::read_lp_vault_registry(&d).map(|x| x.total_lp_shares_outstanding).unwrap_or(fallback)
    }
}
