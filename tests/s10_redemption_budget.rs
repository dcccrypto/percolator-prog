//! S10 (stranded-backing repair): the tag-77 redemption's inline refreshes carry NO unclaimed-backing
//! move budget; the tag-5 refresh crank does. Deterministic pin of that grant.
//!
//! HARNESS PROVENANCE: everything between the "copied harness" markers below is copied verbatim
//! from `tests/earn_drain_replay.rs` at commit b871b8a6 (only the pieces this test uses: the
//! `LiveMarket` / `Replay` types, `Replay::new` and its vault setup, the `r2_market` fixture, the
//! deposit / trade / tag-76 / tag-77 helpers and `walk_only`). `earn_drain_replay.rs` is the
//! reviewer's replay file and MUST NOT be edited to host tests; if its harness changes, re-copy the
//! pieces here instead of including that file as a module (that would register its tests twice).
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

// ───────────── copied harness (earn_drain_replay.rs @ b871b8a6) : begin ─────────────

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

const R3M1_DEPOSIT: u64 = 1_000_000_000;

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
    fn now(&self) -> u64 {
        self.env.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
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
    fn redemption_pda(&self, who: &Pubkey) -> Pubkey {
        state::derive_lp_redemption(&self.env.program_id, &self.registry, who).0
    }
}

// ───────────── copied harness (earn_drain_replay.rs @ b871b8a6) : end ─────────────

/// (fresh backing, provider-principal mirror) of asset 0's long (0) / short (1) domain, in atoms.
fn s10_fresh_and_mirror(r: &Replay, domain: usize) -> (u128, u128) {
    let mut data = r.env.svm.get_account(&r.env.market).unwrap().data;
    let (_, group) = state::market_view_mut(&mut data).unwrap();
    let e = &group.markets[0].engine;
    let (b, m) = if domain == 0 {
        (e.backing_long.try_to_runtime().unwrap(), e.provider_principal_long.get())
    } else {
        (e.backing_short.try_to_runtime().unwrap(), e.provider_principal_short.get())
    };
    (b.fresh_unliened_backing_num / BOUND_SCALE, m / BOUND_SCALE)
}

/// Loser cash of a domain: fresh backing above the provider-principal mirror (rule A), in atoms.
/// A pot funding or a redemption draw moves fresh and mirror together and leaves it unchanged; only
/// a loss booking, a claim consumption or the S10 move changes it.
fn s10_loser_cash(r: &Replay, domain: usize) -> u128 {
    let (f, m) = s10_fresh_and_mirror(r, domain);
    f.saturating_sub(m)
}

/// FORCED stranded state (direct account write, the shape of
/// `p3_vault_lp::s10_forced_deficit_never_moves_earn_pot_principal`): `loser` atoms of loser cash
/// on top of the pot in domain 0 and claims in domain 1 that exceed its backing by `short` atoms.
fn s10_force_stranded(r: &mut Replay, loser: u128, short: u128) {
    let mut acct = r.env.svm.get_account(&r.env.market).unwrap();
    {
        let (_, mut group) = state::market_view_mut(&mut acct.data).unwrap();
        let l = loser * BOUND_SCALE;
        let c;
        {
            let e = &mut group.markets[0].engine;
            let mut b = e.backing_long.try_to_runtime().unwrap();
            b.fresh_unliened_backing_num += l;
            e.backing_long = percolator::BackingBucketV16Account::from_runtime(&b);
            let mut s = e.source_credit_long.try_to_runtime().unwrap();
            s.fresh_reserved_backing_num += l;
            e.source_credit_long = percolator::SourceCreditStateV16Account::from_runtime(&s);
            let mut o = e.source_credit_short.try_to_runtime().unwrap();
            let target = o.fresh_reserved_backing_num + short * BOUND_SCALE;
            assert!(target > o.positive_claim_bound_num, "vacuity: the poke raises the claims");
            c = target - o.positive_claim_bound_num;
            o.positive_claim_bound_num = target;
            o.credit_rate_num = (o.fresh_reserved_backing_num * percolator::CREDIT_RATE_SCALE) / o.positive_claim_bound_num;
            e.source_credit_short = percolator::SourceCreditStateV16Account::from_runtime(&o);
        }
        let h = &mut group.header;
        h.source_fresh_backing_total_num = percolator::V16PodU128::new(h.source_fresh_backing_total_num.get() + l);
        h.source_claim_bound_total_num = percolator::V16PodU128::new(h.source_claim_bound_total_num.get() + c);
        h.pnl_pos_bound_tot_num = percolator::V16PodU128::new(h.pnl_pos_bound_tot_num.get() + c);
        h.pnl_pos_bound_tot = percolator::V16PodU128::new(h.pnl_pos_bound_tot_num.get() / BOUND_SCALE);
        h.vault = percolator::V16PodU128::new(h.vault.get() + loser);
    }
    r.env.svm.set_account(r.env.market, acct).unwrap();
}

/// A forced stranded state (5,000,000 atoms of loser cash in domain 0, a 40,000,000-atom claim
/// shortfall in domain 1). A tag-77 redemption whose inline refresh settles the LAST stale
/// portfolio of the asset (so every guard of the move holds) moves NOTHING: the redemption's
/// refreshes carry no S10 budget. The next tag-5 refresh crank that completes a cohort makes the
/// move. Deterministic pin of the grant: with the flag inverted (tag 77 grants, tag 5 denies) the
/// redemption moves the cash and the crank does not, and both halves of this test fail.
#[test]
fn s10_redemption_refresh_moves_nothing_and_the_next_tag5_crank_does() {
    let mut r = Replay::new(r2_market());
    let h = Keypair::new();
    let (h_ata, _) = r.deposit_shares(&h, R3M1_DEPOSIT, 0).expect("H 75");
    let (tk, tp) = r.new_trader(1_000_000_000);
    r.trade(&tk, tp, 100 * percolator::POS_SCALE as i128).expect("T long 100 vs LP");
    r.request_76(&h, h_ata, Some((1, 1))).expect("H 76 keeper_ok");
    r.env.svm.warp_to_slot(r.now() + r.lm.earn_cooldown + 1);
    s10_force_stranded(&mut r, 5_000_000, 40_000_000);
    // the mark moves; only the LP is cranked, so the trader is the asset's last stale portfolio
    let lp = r.lp;
    walk_only(&mut r, 1_002_000, &[lp]);
    let before = (s10_loser_cash(&r, 0), s10_loser_cash(&r, 1));
    assert!(before.0 >= 5_000_000, "vacuity: the forced loser cash is in domain 0: {before:?}");
    // tag 77 refreshes the trader inline: the cohort completes inside the redemption
    let (paid, _cu) = r.execute_77(&h, Some((1, vec![tp])), false).expect("77 with one inline refresh");
    assert!(paid > 0, "vacuity: the redemption paid");
    let (_, g) = r.env.market_state();
    let after_77 = (s10_loser_cash(&r, 0), s10_loser_cash(&r, 1));
    eprintln!("S10-77 loser cash (d0, d1): before {before:?} after tag 77 {after_77:?} (paid {paid}, stale long/short {}/{})", g.assets[0].stale_account_count_long, g.assets[0].stale_account_count_short);
    assert_eq!((g.assets[0].stale_account_count_long, g.assets[0].stale_account_count_short), (0, 0), "vacuity: the inline refresh settled the last stale leg (the move's V1 guard held)");
    assert_eq!(after_77, before, "a redemption's inline refresh must not move backing between the domains");
    // the keeper's next refresh cranks (tag 5): the LP, then the trader completes the cohort
    walk_only(&mut r, 1_004_000, &[lp, tp]);
    let after_5 = (s10_loser_cash(&r, 0), s10_loser_cash(&r, 1));
    eprintln!("S10-77 loser cash (d0, d1) after the tag-5 cranks {after_5:?}");
    assert!(after_5.0 + 1_000 <= after_77.0, "the tag-5 refresh crank moved loser cash out of domain 0: {after_77:?} -> {after_5:?}");
}
