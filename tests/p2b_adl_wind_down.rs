// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P2b L2: tag 104 `AdlWindDown` and tag 105 `SetAdlWindDownMaxSlots`, on a LiteSVM fork of
//! the LIVE Percolator market (9EPm8nB8), which has been ADL close-only since 10-03.
//!
//! # Method (key-free, read-only)
//! * `tests/fixtures/p2b_adl/percolator.json`: READ-ONLY dump (getProgramAccounts on the
//!   market_group_id + ONE getMultipleAccounts at one context slot + the Clock sysvar) by
//!   `tests/fixtures/p2b_adl/fetch.py`. No keys, no sends.
//! * THIS build's wrapper `.so` (with engine `feat/p2b-lock-exits`) is mounted at the live
//!   wrapper id. Signers that the program checks (the oracle authority for PushAuthMark, the
//!   upgrade authority for tag 105, owners for the reopen trade) are passed as fake signatures
//!   with `with_sigverify(false)`; tag 104 itself needs NO signer.
//! * Time: the fork's Clock is advanced and the oracle authority re-pushes the SAME mark, so
//!   the price is fresh but unmoved and every value change is attributable to the wind-down.
//!
//! Negative controls are in-test (the same fork, one input changed): not yet armed, armed but
//! not expired, after the reset (no ADL), loosening the bound, a non-upgrade-authority signer,
//! and tag 93 rewriting the P1 limits (must not touch the episode).
#[path = "common/v21_upgrade.rs"]
mod v21_upgrade;

use litesvm::LiteSVM;
use percolator::{SideV16, ADL_ONE};
use percolator_prog::{
    constants::KIND_PORTFOLIO,
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    state,
};
use solana_program::pubkey;
use solana_sdk::{
    account::Account,
    bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    clock::Clock,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;

#[path = "support/fill_events.rs"]
mod fill_events;

thread_local! {
    /// v2.2 fill events: logs of the last transaction (success or failure) sent by this thread.
    static LAST_LOGS: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

const WRAPPER_ID: Pubkey = pubkey!("ETDLAdiAyWnEUngspYczTXUceT6X8f92eZQvr8nmSkWB");
const E_NON_PROGRESS: u32 = 22;
const E_PROVENANCE: u32 = 16;
const E_UNAUTHORIZED: u32 = 8;
const E_INVALID_INSTRUCTION: u32 = 9;
const E_ADL_REDUCE_ONLY: u32 = 120;
const E_LOCK_ACTIVE: u32 = 21;
const E_ORACLE_STALE: u32 = 27;

fn so(path: &str) -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(path);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64 byte {c}"),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|c| *c != b'=' && *c != b'\n').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c) << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if chunk.len() > 2 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(acc as u8);
        }
    }
    out
}

struct Fork {
    svm: LiteSVM,
    slab: Pubkey,
    mint: Pubkey,
    clock: Clock,
    portfolios: Vec<Pubkey>,
    obs_seq: u64,
}

fn fork() -> Fork {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/p2b_adl/percolator.json");
    let raw = std::fs::read_to_string(&p).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["wrapper_program"].as_str().unwrap(), WRAPPER_ID.to_string());
    let clock: Clock = bincode::deserialize(&b64(v["clock_sysvar_b64"].as_str().unwrap())).unwrap();
    let slab: Pubkey = v["slab"].as_str().unwrap().parse().unwrap();
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.add_program(WRAPPER_ID, &so("target/deploy/percolator_prog.so"));
    let mut portfolios = Vec::new();
    for a in v["accounts"].as_array().unwrap() {
        let k: Pubkey = a["pubkey"].as_str().unwrap().parse().unwrap();
        let raw = b64(a["data_b64"].as_str().unwrap());
        let owner: Pubkey = a["owner"].as_str().unwrap().parse().unwrap();
        let raw_len = raw.len();
        // v2.2: the captured deployed bytes are re-encoded for this layout: the funding-scale
        // drift tail (zero) and the band/rent words (zero) are inserted, nothing else moves.
        let data = v21_upgrade::upgrade_v21_account(&WRAPPER_ID, &owner, raw);
        let lamports = a["lamports"].as_u64().unwrap() + 7_000 * (data.len() - raw_len) as u64;
        let acc = Account {
            lamports,
            data,
            owner,
            executable: a["executable"].as_bool().unwrap(),
            rent_epoch: 0,
        };
        if acc.owner == WRAPPER_ID && acc.data.len() > 10 && acc.data[10] == KIND_PORTFOLIO {
            portfolios.push(k);
        }
        svm.set_account(k, acc).unwrap();
    }
    svm.set_sysvar(&clock);
    let obs_seq = state::read_asset_control_sequences(&svm.get_account(&slab).unwrap().data, 0)
        .map(|c| c.oracle_observation)
        .unwrap_or(0);
    let mint = Pubkey::new_from_array(
        state::read_market(&svm.get_account(&slab).unwrap().data).unwrap().0.collateral_mint,
    );
    Fork {
        svm,
        slab,
        mint,
        clock,
        portfolios,
        obs_seq,
    }
}

impl Fork {
    fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.svm.get_account(k).unwrap().data
    }
    fn group(&self) -> state::MarketGroupV16 {
        state::read_market(&self.data(&self.slab)).unwrap().1
    }
    fn limits(&self) -> state::AssetRiskLimitsV17 {
        state::read_asset_risk_limits(&self.data(&self.slab), 0).unwrap()
    }
    fn leg(&self, k: &Pubkey) -> Option<(SideV16, u128)> {
        let p = state::read_portfolio(&self.data(k)).unwrap();
        p.legs
            .iter()
            .find(|l| l.active && l.asset_index == 0)
            .map(|l| (l.side, l.basis_pos_q.unsigned_abs()))
    }
    fn side_legs(&self, side: SideV16) -> Vec<Pubkey> {
        self.portfolios
            .iter()
            .copied()
            .filter(|k| matches!(self.leg(k), Some((s, _)) if s == side))
            .collect()
    }
    /// insurance + sum(capital + pnl) over every portfolio of the market.
    fn value(&self) -> i128 {
        let g = self.group();
        let mut v = g.insurance as i128;
        for k in &self.portfolios {
            let p = state::read_portfolio(&self.data(k)).unwrap();
            v += p.capital as i128 + p.pnl;
        }
        v
    }

    fn send(&mut self, ix: Instruction) -> Result<(), TransactionError> {
        let payer = Keypair::new();
        self.svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        self.svm.expire_blockhash();
        let msg = Message::new(
            &[
                solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(
                    256 * 1024,
                ),
                solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(
                    1_400_000,
                ),
                ix,
            ],
            Some(&payer.pubkey()),
        );
        let mut tx = Transaction::new_unsigned(msg);
        tx.signatures =
            vec![Signature::default(); tx.message.header.num_required_signatures as usize];
        tx.partial_sign(&[&payer], self.svm.latest_blockhash());
        match self.svm.send_transaction(tx) {
            Ok(m) => {
                LAST_LOGS.with(|l| *l.borrow_mut() = m.logs.clone());
                Ok(())
            }
            Err(f) => {
                LAST_LOGS.with(|l| *l.borrow_mut() = f.meta.logs.clone());
                Err(f.err)
            }
        }
    }

    fn warp(&mut self, slots: u64) {
        self.clock.slot += slots;
        self.clock.unix_timestamp += (slots * 2 / 5) as i64;
        self.svm.set_sysvar(&self.clock);
        self.svm.warp_to_slot(self.clock.slot);
    }

    /// Re-push the CURRENT effective mark as the live oracle authority (fresh, unmoved price).
    fn push_same_mark(&mut self) {
        let px = self.group().assets[0].effective_price;
        self.push_mark(px);
    }

    fn push_mark(&mut self, mark: u64) {
        let md = self.data(&self.slab);
        let profile = state::read_asset_oracle_profile(&md, 0).unwrap();
        let authority = Pubkey::new_from_array(profile.oracle_authority);
        let market_id = state::read_market_trade_preflight(&md, 0).unwrap().3;
        self.obs_seq += 1;
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(self.slab, false),
            ],
            data: ProgInstruction::PushAuthMark {
                asset_index: 0,
                market_id,
                now_slot: self.clock.slot,
                mark_e6: mark,
                observation_sequence: self.obs_seq,
            }
            .encode(),
        };
        self.send(ix).expect("PushAuthMark as the live oracle authority");
    }

    fn wind_down(&mut self, k: &Pubkey) -> Result<(), TransactionError> {
        let d = self.data(k);
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(*k, false),
                AccountMeta::new_readonly(self.mint, false),
            ],
            data: ProgInstruction::AdlWindDown {
                now_slot: self.clock.slot,
                asset_index: 0,
                portfolio_id: state::read_portfolio_id(&d).unwrap(),
                position_epoch: state::read_portfolio_position_epoch(&d).unwrap(),
            }
            .encode(),
        };
        self.send(ix)
    }

    /// Repeat tag 104 until it stops making price-catch-up-only progress (the single accrual
    /// segment is capped at max_accrual_dt_slots, exactly as the crank is).
    fn wind_down_settled(&mut self, k: &Pubkey) -> Result<(), TransactionError> {
        for _ in 0..64 {
            let before = self.leg(k);
            let slot_last_before = self.group().assets[0].slot_last;
            self.wind_down(k)?;
            if self.leg(k) != before || self.group().assets[0].slot_last == slot_last_before {
                return Ok(());
            }
        }
        Ok(())
    }

    fn crank(&mut self, k: &Pubkey) -> Result<(), TransactionError> {
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new(Pubkey::new_unique(), false),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(*k, false),
            ],
            data: ProgInstruction::PermissionlessCrank {
                now_slot: self.clock.slot,
                observations: vec![CrankObservationHint {
                    asset_index: 0,
                    oracle_accounts: 0,
                }],
            }
            .encode(),
        };
        self.send(ix)
    }

    fn finalize_resets(&mut self) {
        for side in 0..2u8 {
            let ix = Instruction {
                program_id: WRAPPER_ID,
                accounts: vec![AccountMeta::new(self.slab, false)],
                data: ProgInstruction::FinalizeResetSide {
                    asset_index: 0,
                    side,
                }
                .encode(),
            };
            let _ = self.send(ix);
        }
    }

    fn mount_programdata(&mut self) -> Pubkey {
        let authority = Pubkey::new_unique();
        let (pd, _) =
            Pubkey::find_program_address(&[WRAPPER_ID.as_ref()], &bpf_loader_upgradeable::id());
        let data = bincode::serialize(&UpgradeableLoaderState::ProgramData {
            slot: 0,
            upgrade_authority_address: Some(authority),
        })
        .unwrap();
        self.svm
            .set_account(
                pd,
                Account {
                    lamports: 1_000_000_000,
                    data,
                    owner: bpf_loader_upgradeable::id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        authority
    }

    fn set_max_slots(&mut self, signer: Pubkey, max: u32) -> Result<(), TransactionError> {
        let (pd, _) =
            Pubkey::find_program_address(&[WRAPPER_ID.as_ref()], &bpf_loader_upgradeable::id());
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new_readonly(signer, true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(self.slab, false),
            ],
            data: ProgInstruction::SetAdlWindDownMaxSlots {
                asset_index: 0,
                max_episode_slots: max,
            }
            .encode(),
        };
        self.send(ix)
    }

    fn set_p1_limits(&mut self, signer: Pubkey) -> Result<(), TransactionError> {
        let (pd, _) =
            Pubkey::find_program_address(&[WRAPPER_ID.as_ref()], &bpf_loader_upgradeable::id());
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new_readonly(signer, true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(self.slab, false),
            ],
            data: ProgInstruction::SetAssetRiskLimits {
                asset_index: 0,
                exec_band_bps: 0,
                lp_exposure_k_bps: 0,
                lp_floor_atoms: 7,
                side_oi_cap_q: 0,
                matcher_ext_mode: 0,
                max_requested_fee_bps: 0,
            }
            .encode(),
        };
        self.send(ix)
    }
}

fn custom(r: &Result<(), TransactionError>) -> Option<u32> {
    match r {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) => Some(*c),
        _ => None,
    }
}

fn in_adl(f: &Fork) -> bool {
    let a = &f.group().assets[0];
    a.a_long != ADL_ONE || a.a_short != ADL_ONE
}

#[test]
fn p2b_tag104_arms_then_waits_for_the_episode_bound() {
    let mut f = fork();
    assert!(in_adl(&f), "the fixture is the live close-only Percolator market");
    let shorts = f.side_legs(SideV16::Short);
    assert!(!shorts.is_empty());
    let target = shorts[0];
    let leg0 = f.leg(&target);
    assert_eq!(f.limits().adl_episode_since_slot, 0, "deployed bytes: no episode recorded");

    // Arm: Ok, the episode is recorded at this slot with the current epochs, nothing closes.
    f.wind_down_settled(&target).expect("first call arms");
    let l = f.limits();
    let armed_at = l.adl_episode_since_slot;
    assert_eq!(armed_at, f.clock.slot);
    let a = &f.group().assets[0];
    let key = percolator_prog::processor::adl_episode_key(a.market_id, a.epoch_long, a.epoch_short);
    assert_eq!((l.adl_episode_epoch_long, l.adl_episode_epoch_short), key);
    assert_eq!(f.leg(&target), leg0, "NEGATIVE CONTROL: armed, not expired -> no close");

    // One slot short of the default bound: still nothing.
    let n = state::ADL_WIND_DOWN_DEFAULT_MAX_EPISODE_SLOTS as u64;
    f.warp(n - 1);
    f.push_same_mark();
    f.wind_down_settled(&target).unwrap();
    assert_eq!(f.leg(&target), leg0, "NEGATIVE CONTROL: N-1 slots -> no close");
    assert_eq!(f.limits().adl_episode_since_slot, armed_at, "re-calls never move the start");

    // A wrong episode binding is refused once the bound is met (no blind targeting).
    f.warp(1);
    f.push_same_mark();
    let d = f.data(&target);
    let bad = Instruction {
        program_id: WRAPPER_ID,
        accounts: vec![
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(f.slab, false),
            AccountMeta::new(target, false),
            AccountMeta::new_readonly(f.mint, false),
        ],
        data: ProgInstruction::AdlWindDown {
            now_slot: f.clock.slot,
            asset_index: 0,
            portfolio_id: state::read_portfolio_id(&d).unwrap(),
            position_epoch: state::read_portfolio_position_epoch(&d).unwrap() + 1,
        }
        .encode(),
    };
    // Drain the price catch-up through the ordinary crank so the binding check answers.
    for _ in 0..64 {
        let s = f.group().assets[0].slot_last;
        let _ = f.crank(&target);
        if f.group().assets[0].slot_last == s {
            break;
        }
    }
    let r = f.send(bad);
    assert_eq!(
        custom(&r),
        Some(E_PROVENANCE),
        "NEGATIVE CONTROL: a stale (portfolio_id, position_epoch) binding is refused: {r:?}"
    );
    assert_eq!(f.leg(&target), leg0);
    // The correct binding closes it.
    let leg_before = state::read_portfolio(&f.data(&target))
        .unwrap()
        .legs
        .iter()
        .find(|l| l.active && l.asset_index == 0)
        .cloned()
        .expect("open leg");
    let asset_before = f.group().assets[0].clone();
    f.wind_down_settled(&target).expect("bound met");
    assert!(f.leg(&target).is_none(), "closed at the mark once the episode bound is met");
    // v2.2 fill events: the closing call emitted ONE REDUCE (tag 104, reason 2): the whole leg's
    // ADL-EFFECTIVE size on this A-scaled close-only market (not the raw basis), a short being
    // covered by a positive size, at the asset's effective price.
    let evs = fill_events::wrapper_events(&LAST_LOGS.with(|l| l.borrow().clone()), &WRAPPER_ID);
    assert_eq!(evs.len(), 1, "{evs:?}");
    let fill_events::Event::Reduce { ix_tag, portfolio, counterparty, asset_index, reason, signed_reduced_q, price_e6, .. } =
        &evs[0]
    else {
        panic!("expected REDUCE: {evs:?}")
    };
    assert_eq!((*ix_tag, *portfolio, *counterparty, *asset_index, *reason), (104, target, Pubkey::default(), 0, 2));
    let effective = percolator_prog::risk_limits_v17::adl_effective_abs_q(
        leg_before.basis_pos_q.unsigned_abs(),
        leg_before.a_basis,
        asset_before.a_short,
    )
    .expect("effective size");
    assert_eq!(*signed_reduced_q, effective as i128, "the effective size closed, short covered");
    assert!(*signed_reduced_q > 0);
    assert_eq!(*price_e6, f.group().assets[0].effective_price);
}

#[test]
fn p2b_tag104_after_the_bound_winds_down_reopens_and_conserves_value() {
    let mut f = fork();
    assert!(in_adl(&f));
    let shorts = f.side_legs(SideV16::Short);
    let longs = f.side_legs(SideV16::Long);
    eprintln!("live book: {} long legs, {} short legs", longs.len(), shorts.len());

    // Settle every account at the fork's clock so the value ledger is exact.
    for k in f.portfolios.clone() {
        let _ = f.crank(&k);
    }
    f.wind_down_settled(&shorts[0]).expect("arm");
    let n = state::ADL_WIND_DOWN_DEFAULT_MAX_EPISODE_SLOTS as u64;
    f.warp(n);
    f.push_same_mark();
    for k in f.portfolios.clone() {
        for _ in 0..64 {
            let s = f.group().assets[0].slot_last;
            let _ = f.crank(&k);
            if f.group().assets[0].slot_last == s {
                break;
            }
        }
    }
    let vault0 = f.group().vault;
    let value0 = f.value();

    // Before: a fresh open is refused with the distinct ADL code.
    let opener = longs[0];
    let counter = shorts[0];

    for (i, k) in shorts.iter().enumerate() {
        f.wind_down_settled(k)
            .unwrap_or_else(|e| panic!("wind-down of short {i} ({k}): {e:?}"));
        {
            let a = &f.group().assets[0];
            let l = f.limits();
            eprintln!(
                "after short {i}: A {}/{} OI {}/{} epochs {}/{} modes {:?}/{:?} pos {}/{} rec since {} ep {}/{} leg {:?}",
                a.a_long, a.a_short, a.oi_eff_long_q, a.oi_eff_short_q, a.epoch_long, a.epoch_short,
                a.mode_long, a.mode_short, a.stored_pos_count_long, a.stored_pos_count_short,
                l.adl_episode_since_slot, l.adl_episode_epoch_long, l.adl_episode_epoch_short, f.leg(k)
            );
        }
        // Closed at the mark. The LAST leg of a side can leave a few q of ADL-ceiling basis
        // residue with zero effective quantity: the side reset (epoch bump) makes it a stale
        // reset survivor that the ordinary crank clears below.
        let reset = f.group().assets[0].epoch_short != 0;
        assert!(f.leg(k).is_none() || reset, "short {i} closed at the mark");
    }
    assert!(!in_adl(&f), "the last short leg zeroes both sides and resets A");

    // After the reset there is no episode to wind down: refused (NEGATIVE CONTROL).
    let r = f.wind_down(&longs[0]);
    assert_eq!(
        custom(&r),
        Some(E_NON_PROGRESS),
        "tag 104 on a non-ADL market must refuse: {r:?}"
    );

    // Survivors settle through the ordinary crank, both resets finalize.
    for k in f.portfolios.clone() {
        let _ = f.crank(&k);
    }
    f.finalize_resets();
    for k in f.portfolios.clone() {
        assert!(f.leg(&k).is_none(), "every reset survivor settled flat ({k})");
    }
    let g = f.group();
    let a = &g.assets[0];
    assert_eq!((a.a_long, a.a_short), (ADL_ONE, ADL_ONE));
    assert_eq!((a.oi_eff_long_q, a.oi_eff_short_q), (0, 0));

    // CONSERVATION on the live book: engine vault untouched, value exactly unchanged.
    assert_eq!(g.vault, vault0, "vault untouched");
    assert_eq!(f.value(), value0, "insurance + sum(capital + pnl) unchanged, no fee");

    // The market reopens: an open is no longer refused with the ADL code.
    let open = {
        let md = f.data(&f.slab);
        let (cfg, _, _, market_id, _, _) = state::read_market_trade_preflight(&md, 0).unwrap();
        let ad = f.data(&opener);
        let bd = f.data(&counter);
        let owner_a = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&ad).unwrap().1);
        let owner_b = Pubkey::new_from_array(state::read_portfolio_owner_preflight(&bd).unwrap().1);
        Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new(owner_a, true),
                AccountMeta::new(owner_b, true),
                AccountMeta::new(f.slab, false),
                AccountMeta::new(opener, false),
                AccountMeta::new(counter, false),
            ],
            data: ProgInstruction::TradeNoCpi {
                account_a_portfolio_id: state::read_portfolio_id(&ad).unwrap(),
                account_a_position_epoch: state::read_portfolio_position_epoch(&ad).unwrap(),
                account_b_portfolio_id: state::read_portfolio_id(&bd).unwrap(),
                account_b_position_epoch: state::read_portfolio_position_epoch(&bd).unwrap(),
                market_id,
                asset_index: 0,
                size_q: 1_000_000,
                exec_price: g.assets[0].effective_price,
                fee_bps: cfg.trade_fee_base_bps,
                backing_fee_cap_bps: 10_000,
            }
            .encode(),
        }
    };
    let r = f.send(open);
    assert_ne!(
        custom(&r),
        Some(E_ADL_REDUCE_ONLY),
        "after the wind-down the market is no longer close-only: {r:?}"
    );
    eprintln!("reopen trade -> {r:?}");
}

#[test]
fn p2b_tag105_tightens_only_and_tag93_preserves_the_episode() {
    let mut f = fork();
    let ua = f.mount_programdata();
    // Not the upgrade authority: refused.
    let r = f.set_max_slots(Pubkey::new_unique(), 100);
    assert_eq!(custom(&r), Some(E_UNAUTHORIZED));
    // Loosening above the default: refused. Zero: refused.
    let r = f.set_max_slots(ua, state::ADL_WIND_DOWN_DEFAULT_MAX_EPISODE_SLOTS + 1);
    assert_eq!(custom(&r), Some(E_INVALID_INSTRUCTION));
    let r = f.set_max_slots(ua, 0);
    assert_eq!(custom(&r), Some(E_INVALID_INSTRUCTION));
    // Tighten: ok; then loosening back is refused.
    f.set_max_slots(ua, 300).expect("tighten");
    assert_eq!(f.limits().adl_max_episode_slots, 300);
    let r = f.set_max_slots(ua, 301);
    assert_eq!(custom(&r), Some(E_INVALID_INSTRUCTION), "tighten-only");

    // Arm an episode, then tag 93 rewrites the P1 limits: the episode and bound survive.
    let target = f.side_legs(SideV16::Short)[0];
    f.wind_down_settled(&target).expect("arm");
    let before = f.limits();
    assert_ne!(before.adl_episode_since_slot, 0);
    f.set_p1_limits(ua).expect("tag 93");
    let after = f.limits();
    assert_eq!(after.lp_floor_atoms, 7);
    assert_eq!(after.adl_max_episode_slots, 300);
    assert_eq!(after.adl_episode_since_slot, before.adl_episode_since_slot);
    assert_eq!(after.adl_episode_epoch_long, before.adl_episode_epoch_long);
    assert_eq!(after.adl_episode_epoch_short, before.adl_episode_epoch_short);

    // With the tightened bound the wind-down is live 300 slots after arming.
    let leg0 = f.leg(&target);
    f.warp(299);
    f.push_same_mark();
    f.wind_down_settled(&target).unwrap();
    assert_eq!(f.leg(&target), leg0, "299 < 300: not yet");
    f.warp(1);
    f.push_same_mark();
    f.wind_down_settled(&target).expect("bound met");
    assert!(f.leg(&target).is_none(), "closed once the tightened bound is met");
}

/// Review M-1: tag 104 never force-closes at a lagging, pending or stale mark.
#[test]
fn p2b_tag104_refuses_a_lagging_or_stale_mark() {
    let mut f = fork();
    let target = f.side_legs(SideV16::Short)[0];
    f.wind_down_settled(&target).expect("arm");
    let n = state::ADL_WIND_DOWN_DEFAULT_MAX_EPISODE_SLOTS as u64;
    f.warp(n);
    f.push_same_mark();
    // Catch the asset fully up to the clock first (bounded segments), re-pushing so the mark
    // stays fresh, so the next push lands with dt = 0 and the effective price cannot move.
    for _ in 0..256 {
        if f.group().assets[0].slot_last >= f.clock.slot {
            break;
        }
        let _ = f.crank(&target);
        f.push_same_mark();
    }
    assert_eq!(f.group().assets[0].slot_last, f.clock.slot, "asset caught up to the clock");
    let leg0 = f.leg(&target);

    // (a) LAGGING / PENDING: the oracle authority pushes a mark 40% away. The effective price
    // steps toward it rate-limited, so target != effective (and the pushed mark is pending).
    let mut lag = fork_clone_state(&f);
    let px = lag.group().assets[0].effective_price;
    lag.push_mark(px + px * 2 / 5);
    let r = lag.wind_down_settled(&target);
    {
        let a = &lag.group().assets[0];
        eprintln!(
            "lag probe: r={r:?} target={} eff={} slot_last={} clock={} leg={:?}",
            a.raw_oracle_target_price, a.effective_price, a.slot_last, lag.clock.slot, lag.leg(&target)
        );
    }
    assert_eq!(custom(&r), Some(E_LOCK_ACTIVE), "lagging/pending mark: refused: {r:?}");
    assert_eq!(lag.leg(&target), leg0, "nothing moved");

    // (b) STALE: the keeper stopped. No push for longer than the mark-age bound.
    let mut stale = fork_clone_state(&f);
    stale.warp(state::ADL_WIND_DOWN_MAX_MARK_AGE_SLOTS + 1);
    let r = stale.wind_down_settled(&target);
    assert_eq!(custom(&r), Some(E_ORACLE_STALE), "stale pushed mark: refused: {r:?}");
    assert_eq!(stale.leg(&target), leg0);

    // NEGATIVE CONTROL: the same state with a fresh, unmoved mark closes.
    f.push_same_mark();
    f.wind_down_settled(&target).expect("fresh mark");
    assert!(f.leg(&target).is_none(), "fresh, unmoved mark: closed at the mark");
}

/// A second fork carrying the CURRENT state of `f` (accounts, clock, obs sequence).
fn fork_clone_state(f: &Fork) -> Fork {
    let mut g = fork();
    for k in f.portfolios.iter().chain([f.slab].iter()) {
        g.svm.set_account(*k, f.svm.get_account(k).unwrap()).unwrap();
    }
    g.clock = f.clock.clone();
    g.svm.set_sysvar(&g.clock);
    g.svm.warp_to_slot(g.clock.slot);
    g.obs_seq = f.obs_seq;
    g
}

/// Review I-1: the dust bound is one whole unit of the market's collateral mint.
#[test]
fn p2b_dust_bound_scales_with_collateral_decimals() {
    assert_eq!(state::adl_wind_down_dust_notional_atoms(6), 1_000_000);
    assert_eq!(state::adl_wind_down_dust_notional_atoms(9), 1_000_000_000);
    assert_eq!(state::adl_wind_down_dust_notional_atoms(0), 1);
    // The live Percolator collateral (sim-USDC) has 6 decimals: the bound is 1.00.
    let f = fork();
    let mint = f.svm.get_account(&f.mint).unwrap();
    assert_eq!(mint.data[44], 6, "live collateral mint decimals");
}

fn set_mint_decimals(f: &mut Fork, key: Pubkey, decimals: u8) {
    let mut acc = f.svm.get_account(&f.mint).unwrap();
    acc.data[44] = decimals;
    f.svm.set_account(key, acc).unwrap();
}

/// Review I-5 (W5): tag 104 must reject any collateral-mint account other than the market's
/// own (the dust bound is derived from it). A look-alike mint with 9 or 18 decimals would
/// otherwise inflate the dust bound by 10^3..10^12 and let anyone close immediately.
#[test]
fn p2b_tag104_rejects_a_wrong_collateral_mint() {
    for decimals in [9u8, 18u8] {
        let mut f = fork();
        let target = f.side_legs(SideV16::Short)[0];
        let leg0 = f.leg(&target);
        let fake = Pubkey::new_unique();
        set_mint_decimals(&mut f, fake, decimals);
        let d = f.data(&target);
        let ix = Instruction {
            program_id: WRAPPER_ID,
            accounts: vec![
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(f.slab, false),
                AccountMeta::new(target, false),
                AccountMeta::new_readonly(fake, false),
            ],
            data: ProgInstruction::AdlWindDown {
                now_slot: f.clock.slot,
                asset_index: 0,
                portfolio_id: state::read_portfolio_id(&d).unwrap(),
                position_epoch: state::read_portfolio_position_epoch(&d).unwrap(),
            }
            .encode(),
        };
        let r = f.send(ix);
        assert_eq!(
            r,
            Err(TransactionError::InstructionError(2, InstructionError::InvalidArgument)),
            "a {decimals}-decimal look-alike mint must be refused"
        );
        assert_eq!(f.leg(&target), leg0);
        assert_eq!(f.limits().adl_episode_since_slot, 0, "nothing recorded");
    }
}

/// Review I-5 (W4): the handler derives the dust bound from the market's collateral decimals.
/// The live Percolator short side is ~162.7 (6-dp) of notional: at 6 decimals (bound 1.00)
/// the first call only arms; were the collateral 9 decimals (bound 10^9 atoms) the same side
/// is dust and the first call closes at once.
#[test]
fn p2b_tag104_dust_bound_follows_collateral_decimals() {
    // CONTROL: the real 6-decimal mint -> armed only.
    let mut f = fork();
    let target = f.side_legs(SideV16::Short)[0];
    let leg0 = f.leg(&target);
    f.wind_down_settled(&target).expect("arm");
    assert_eq!(f.leg(&target), leg0, "6 dp: not dust, only armed");
    assert_ne!(f.limits().adl_episode_since_slot, 0);

    // The same market with 9-decimal collateral: the side is dust, closed on the first call.
    let mut g = fork();
    let mint = g.mint;
    set_mint_decimals(&mut g, mint, 9);
    g.wind_down_settled(&target).expect("dust close");
    assert!(g.leg(&target).is_none(), "9 dp: the side is dust, closed without waiting");
}

/// Coordination with Builder C (#526): record bytes 42..44 (asset-slot 650..652) are C's
/// senior floor, 44..64 (652..672) are the P2b episode. With BOTH non-zero, the record must
/// validate, and a tag-93 rewrite of the P1 limits must preserve both ranges bit for bit.
#[test]
fn p2b_tag93_preserves_both_owned_ranges_of_the_risk_limits_tail() {
    let mut f = fork();
    let ua = f.mount_programdata();
    use percolator_prog::constants::{ASSET_RISK_LIMITS_OFF, MARKET_GROUP_LEN, MARKET_GROUP_OFF};
    let off = MARKET_GROUP_OFF + MARKET_GROUP_LEN + ASSET_RISK_LIMITS_OFF; // asset 0
    let mut acc = f.svm.get_account(&f.slab).unwrap();
    // C's range (650..652) and the P2b episode (652..672), both non-zero.
    acc.data[off + 42] = 0x34;
    acc.data[off + 43] = 0x12;
    let mut l = state::read_asset_risk_limits(&acc.data, 0).unwrap();
    l.adl_max_episode_slots = 300;
    l.adl_episode_since_slot = 77;
    l.adl_episode_epoch_long = 0xAABB_CCDD;
    l.adl_episode_epoch_short = 0x1122_3344;
    state::write_asset_risk_limits(&mut acc.data, 0, &l).unwrap();
    let tail_before = acc.data[off + 42..off + 64].to_vec();
    assert_eq!(&tail_before[..2], &[0x34, 0x12], "the writer keeps C's bytes");
    f.svm.set_account(f.slab, acc).unwrap();
    state::read_asset_risk_limits(&f.data(&f.slab), 0).expect("both ranges non-zero validate");

    f.set_p1_limits(ua).expect("tag 93");
    let d = f.data(&f.slab);
    let after = state::read_asset_risk_limits(&d, 0).expect("still validates after tag 93");
    assert_eq!(after.lp_floor_atoms, 7, "tag 93 applied the P1 limits");
    assert_eq!(&d[off + 42..off + 64], &tail_before[..], "tag 93 preserved bytes 42..64 exactly");
}

