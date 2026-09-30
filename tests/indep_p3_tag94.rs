//! INDEPENDENT SUITE — P3 tag 94 InitVaultLp, NEW protocol path (path B), from the design doc
//! (ledger/p3-vault-owned-lp-2026-09-29.md §0.3 row 94, §0.5 step 5):
//!   Path A: [0] marketauth (s,w) — junior owner := marketauth.
//!   Path B: [0] upgrade authority (s,w), same accounts [1..7], tail [8] ProgramData PDA
//!           (find_program_address([wrapper_id], BPFLoaderUpgradeab1e)), [9] junior_owner (s)
//!           — junior owner := [9]. Exists because stake-bound markets have a keyless PDA marketauth.
//!   Row 94 also: "vault must exist and not yet be bound" (re-point refused, 72 VaultLpAlreadyBound).
//! Encoding raw (tag 94, u16 junior_floor_bps). vault_lp_state junior_owner at [112..144].
//! Wrapper .so: INDEP_WRAPPER_SO. Negative control: a pre-path-B P3 .so (008f88ed).
#![cfg(not(kani))]
mod indep_harness;

use indep_harness::*;
use percolator_prog::{ix::Instruction as ProgInstruction, state};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

const PRICE: u64 = 1_000_000;
const E_ALREADY_BOUND: u32 = 72;

struct T {
    env: V16CuEnv,
    registry: Pubkey,
    lp_mint: Pubkey,
    ledger0: Pubkey,
    ledger1: Pubkey,
    state_pda: Pubkey,
    upgrade: Keypair,
    program_data: Pubkey,
    matcher: Pubkey,
}

fn pd_bytes(authority: Option<&Pubkey>) -> Vec<u8> {
    let mut pd = vec![0u8; 45];
    pd[0..4].copy_from_slice(&3u32.to_le_bytes()); // ProgramData
    if let Some(a) = authority {
        pd[12] = 1;
        pd[13..45].copy_from_slice(a.as_ref());
    }
    pd
}

impl T {
    fn new() -> Self {
        let mut env = V16CuEnv::new_with_init_params(V16CuMarketParams { initial_price: PRICE, ..V16CuMarketParams::default() });
        env.svm.warp_to_slot(1);
        env.configure_auth_mark_for_asset_as_admin(0, 1, PRICE);
        let pid = env.program_id;
        let market = env.market;
        let registry = state::derive_lp_vault_registry(&pid, &market).0;
        let lp_mint = state::derive_lp_vault_mint(&pid, &market).0;
        let ledger0 = state::derive_lp_backing_ledger(&pid, &market, 0).0;
        let ledger1 = state::derive_lp_backing_ledger(&pid, &market, 1).0;
        let state_pda = Pubkey::find_program_address(&[b"vault_lp", market.as_ref()], &pid).0;
        let upgrade = Keypair::new();
        env.svm.airdrop(&upgrade.pubkey(), 10_000_000_000).unwrap();
        let program_data = Pubkey::find_program_address(&[pid.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
        env.svm
            .set_account(program_data, Account { lamports: 1_000_000_000, data: pd_bytes(Some(&upgrade.pubkey())), owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 })
            .unwrap();
        // 07a1d0eb auto-pin: mount the matcher at the CANONICAL id.
        let matcher: Pubkey = "4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT".parse().unwrap();
        env.svm.add_program(matcher, &std::fs::read(matcher_program_path()).expect("matcher so"));
        let mut t = T { env, registry, lp_mint, ledger0, ledger1, state_pda, upgrade, program_data, matcher };
        t.create_vault();
        t
    }

    fn create_vault(&mut self) {
        let admin = self.env.admin.insecure_clone();
        self.env.svm.expire_blockhash();
        self.env
            .send(
                ProgInstruction::CreateLpVault { fee_share_bps: 0, redemption_cooldown_slots: 0, oi_reservation_threshold_bps: 0, domain: 0 },
                vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(self.env.market, false),
                    AccountMeta::new(self.registry, false),
                    AccountMeta::new(self.lp_mint, false),
                    AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
                &[&admin],
            )
            .expect("74 CreateLpVault");
    }

    fn fresh_lp(&mut self) -> Pubkey {
        let lp = Pubkey::new_unique();
        let len = self.env.portfolio_account_len;
        let pid = self.env.program_id;
        self.env.svm.set_account(lp, Account { lamports: 1_000_000_000, data: vec![0; len], owner: pid, executable: false, rent_epoch: 0 }).unwrap();
        lp
    }

    fn base_metas(&self, signer0: &Pubkey, lp: Pubkey) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(*signer0, true),
            AccountMeta::new(self.env.market, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.state_pda, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.ledger0, false),
            AccountMeta::new(self.ledger1, false),
        ]
    }

    fn send(&mut self, metas: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        self.env.svm.expire_blockhash();
        let ix = Instruction { program_id: self.env.program_id, accounts: metas, data: vec![94, 0xe8, 0x03] }; // floor 1000 bps
        send_raw_tx(&mut self.env.svm, &self.env.payer.insecure_clone(), ix, signers)
    }

    /// Path A (marketauth).
    fn init_a(&mut self, signer: &Keypair) -> Result<u64, String> {
        let lp = self.fresh_lp();
        let mut metas = self.base_metas(&signer.pubkey(), lp);
        if !std::env::var("P3_LEGACY_BIND").map_or(false, |v| v == "1") {
            metas.extend(self.autopin_tail(lp));
        }
        self.send(metas, &[signer])
    }

    /// 07a1d0eb tag 94 tail: [8] canonical matcher, [9] ctx (w, zeroed), [10] delegate.
    fn autopin_tail(&mut self, lp: Pubkey) -> Vec<AccountMeta> {
        let ctx = Pubkey::new_unique();
        self.env.svm.set_account(ctx, Account { lamports: 1_000_000_000, data: vec![0; 320], owner: self.matcher, executable: false, rent_epoch: 0 }).unwrap();
        let del = Pubkey::find_program_address(&[b"matcher", self.env.market.as_ref(), lp.as_ref(), self.registry.as_ref(), self.matcher.as_ref(), ctx.as_ref()], &self.env.program_id).0;
        self.env.svm.set_account(del, Account { lamports: 1_000_000_000, data: vec![], owner: Pubkey::default(), executable: false, rent_epoch: 0 }).unwrap();
        vec![AccountMeta::new_readonly(self.matcher, false), AccountMeta::new(ctx, false), AccountMeta::new_readonly(del, false)]
    }

    /// Path B. `junior_signs` false puts [9] in as a non-signer (the tx is still signed by the
    /// upgrade signer only). `pd` overrides the [8] account.
    fn init_b(&mut self, ua: &Keypair, pd: Pubkey, junior: &Keypair, junior_signs: bool) -> Result<u64, String> {
        let lp = self.fresh_lp();
        let mut metas = self.base_metas(&ua.pubkey(), lp);
        metas.push(AccountMeta::new_readonly(pd, false));
        metas.push(if junior_signs { AccountMeta::new(junior.pubkey(), true) } else { AccountMeta::new(junior.pubkey(), false) });
        if junior_signs {
            self.send(metas, &[ua, junior])
        } else {
            self.send(metas, &[ua])
        }
    }

    fn junior_owner(&self) -> Option<Pubkey> {
        let d = self.env.svm.get_account(&self.state_pda)?.data;
        if d.len() < 144 {
            return None;
        }
        Some(Pubkey::new_from_array(d[112..144].try_into().unwrap()))
    }

    fn snapshot(&self) -> (Vec<u8>, Option<Vec<u8>>, Vec<u8>) {
        (
            self.env.svm.get_account(&self.env.market).unwrap().data,
            self.env.svm.get_account(&self.state_pda).map(|a| a.data),
            self.env.svm.get_account(&self.registry).unwrap().data,
        )
    }
}

fn refused(r: &Result<u64, String>) -> Option<u32> {
    match r {
        Ok(_) => None,
        Err(e) => Some(custom_code(e).unwrap_or(u32::MAX)),
    }
}

/// (1) Positive: upgrade authority + junior both sign, correct ProgramData -> bound, junior := [9].
#[test]
fn tag94_b_removed_path_b_invocation_is_refused() {
    // USER DECISION (2026-09-30): path B is REMOVED from the relaunch. The full path-B
    // invocation (upgrade authority [0] + ProgramData [8] + signing junior [9], signer is NOT
    // marketauth) must now be REFUSED with no state change and no junior bound.
    let mut t = T::new();
    let junior = Keypair::new();
    t.env.svm.airdrop(&junior.pubkey(), 1_000_000_000).unwrap();
    let (ua, pd) = (t.upgrade.insecure_clone(), t.program_data);
    let before = t.snapshot();
    let r = t.init_b(&ua, pd, &junior, true);
    eprintln!("tag94 path-B invocation (removed) -> {:?}", refused(&r));
    assert!(r.is_err(), "path B was removed: the UA + ProgramData + junior invocation must be refused");
    assert_eq!(t.snapshot(), before, "refusal must not change state");
    assert_eq!(t.junior_owner(), None, "no junior may be bound via the removed path");
}

/// (2) A non-authority in the upgrade-authority slot (marketauth, random) with a real
/// ProgramData and a signing junior -> refused, no state change.
#[test]
fn tag94_b_removed_refused_for_any_non_marketauth_signer() {
    let mut t = T::new();
    let junior = Keypair::new();
    t.env.svm.airdrop(&junior.pubkey(), 1_000_000_000).unwrap();
    let rand = Keypair::new();
    t.env.svm.airdrop(&rand.pubkey(), 10_000_000_000).unwrap();
    let pd = t.program_data;
    for who in [rand.insecure_clone()] {
        let before = t.snapshot();
        let r = t.init_b(&who, pd, &junior, true);
        eprintln!("tag94 B by non-authority -> {:?}", refused(&r));
        assert!(r.is_err(), "non-authority must be refused on path B");
        assert_eq!(t.snapshot(), before, "refusal must not change state");
    }
    // marketauth in slot [0] with the path-B tail: must not bind the NAMED junior (it may
    // legitimately bind via path A with junior := marketauth — record which).
    let admin = t.env.admin.insecure_clone();
    let r = t.init_b(&admin, pd, &junior, true);
    eprintln!("tag94 B-shaped by marketauth -> {:?}; junior {:?}", refused(&r), t.junior_owner());
    assert_ne!(t.junior_owner(), Some(junior.pubkey()), "marketauth must not be able to name a different junior via the protocol tail");
    // Path B removed: even the REAL upgrade authority is refused on a fresh market.
    let mut t2 = T::new();
    let (ua, pd2) = (t2.upgrade.insecure_clone(), t2.program_data);
    t2.env.svm.airdrop(&junior.pubkey(), 1_000_000_000).unwrap();
    let before2 = t2.snapshot();
    assert!(t2.init_b(&ua, pd2, &junior, true).is_err(), "path B removed: real UA is refused too");
    assert_eq!(t2.snapshot(), before2);
    // Vacuity: path A by marketauth still works on that market.
    let admin2 = t2.env.admin.insecure_clone();
    t2.init_a(&admin2).expect("path A still binds");
}

/// (3) Wrong ProgramData: another program's PDA, wrong owner, spoofed authority, authority=None.
#[test]
fn tag94_b_wrong_program_data_refused() {
    let junior = Keypair::new();
    let cases: Vec<(&str, Box<dyn Fn(&mut T) -> Pubkey>)> = vec![
        ("other program's ProgramData PDA", Box::new(|t: &mut T| {
            let other = Pubkey::new_unique();
            let k = Pubkey::find_program_address(&[other.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
            let d = pd_bytes(Some(&t.upgrade.pubkey()));
            t.env.svm.set_account(k, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 }).unwrap();
            k
        })),
        ("right key, wrong owner", Box::new(|t: &mut T| {
            let k = t.program_data;
            let d = pd_bytes(Some(&t.upgrade.pubkey()));
            t.env.svm.set_account(k, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::system_program::ID, executable: false, rent_epoch: 0 }).unwrap();
            k
        })),
        ("right key, different authority", Box::new(|t: &mut T| {
            let k = t.program_data;
            let d = pd_bytes(Some(&Pubkey::new_unique()));
            t.env.svm.set_account(k, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 }).unwrap();
            k
        })),
        ("right key, authority None (immutable)", Box::new(|t: &mut T| {
            let k = t.program_data;
            let d = pd_bytes(None);
            t.env.svm.set_account(k, Account { lamports: 1_000_000_000, data: d, owner: solana_sdk::bpf_loader_upgradeable::id(), executable: false, rent_epoch: 0 }).unwrap();
            k
        })),
    ];
    for (label, mk) in cases {
        let mut t = T::new();
        t.env.svm.airdrop(&junior.pubkey(), 1_000_000_000).unwrap();
        let pd = mk(&mut t);
        let before = t.snapshot();
        let ua = t.upgrade.insecure_clone();
        let r = t.init_b(&ua, pd, &junior, true);
        eprintln!("tag94 B {label} -> {:?}", refused(&r));
        assert!(r.is_err(), "{label}: must be refused");
        assert_eq!(t.snapshot(), before, "{label}: refusal must not change state");
    }
}

/// (4) Junior present but not a signer -> refused. Junior missing -> refused or falls back to
/// path A semantics (junior := [0]); record which. Neither may bind an unsigned third party.
#[test]
fn tag94_b_junior_must_sign() {
    let mut t = T::new();
    let junior = Keypair::new();
    let (ua, pd) = (t.upgrade.insecure_clone(), t.program_data);
    let before = t.snapshot();
    let r = t.init_b(&ua, pd, &junior, false);
    eprintln!("tag94 B junior not signer -> {:?}", refused(&r));
    assert!(r.is_err(), "unsigned junior must be refused");
    assert_eq!(t.snapshot(), before, "no state change");
    // junior account missing (only [8] ProgramData tail)
    let lp = t.fresh_lp();
    let mut metas = t.base_metas(&ua.pubkey(), lp);
    metas.push(AccountMeta::new_readonly(pd, false));
    let r2 = t.send(metas, &[&ua]);
    eprintln!("tag94 B junior missing -> {:?}; junior {:?}", refused(&r2), t.junior_owner());
    assert!(r2.is_err(), "UA without a junior must not bind (UA would become junior)");
    assert_ne!(t.junior_owner(), Some(ua.pubkey()));
}

/// (5) Re-point: tag 94 again on an already-bound vault (either path, different junior) must be
/// refused and must not change the junior owner / LP binding.
#[test]
fn tag94_repoint_existing_vault_lp_refused() {
    let mut t = T::new();
    let j1 = Keypair::new();
    let j2 = Keypair::new();
    t.env.svm.airdrop(&j1.pubkey(), 1_000_000_000).unwrap();
    t.env.svm.airdrop(&j2.pubkey(), 1_000_000_000).unwrap();
    let (ua, pd) = (t.upgrade.insecure_clone(), t.program_data);
    let admin0 = t.env.admin.insecure_clone();
    t.init_a(&admin0).expect("first bind via path A (path B removed)");
    let bound = t.junior_owner();
    assert_eq!(bound, Some(admin0.pubkey()));
    let _ = &j1;
    let before = t.snapshot();
    let r = t.init_b(&ua, pd, &j2, true);
    eprintln!("tag94 re-point via B -> {:?}", refused(&r));
    assert!(r.is_err(), "re-point via B must be refused");
    let admin = t.env.admin.insecure_clone();
    let r2 = t.init_a(&admin);
    eprintln!("tag94 re-point via A -> {:?}", refused(&r2));
    assert!(r2.is_err(), "re-point via A must be refused");
    assert_eq!(t.snapshot(), before, "re-point attempts must not change state");
    assert_eq!(t.junior_owner(), bound);
    for (lbl, rr) in [("B", &r), ("A", &r2)] {
        if refused(rr) != Some(E_ALREADY_BOUND) {
            eprintln!("NOTE: re-point via {lbl} refused with {:?}, not 72 VaultLpAlreadyBound", refused(rr));
        }
    }
}

/// (6) Path A unchanged: marketauth binds, junior := marketauth. Also the reverse re-point:
/// after A, path B cannot re-point.
#[test]
fn tag94_a_legacy_marketauth_path_unchanged_and_not_repointable_by_b() {
    let mut t = T::new();
    let admin = t.env.admin.insecure_clone();
    t.init_a(&admin).expect("path A by marketauth");
    assert_eq!(t.junior_owner(), Some(admin.pubkey()));
    let j = Keypair::new();
    t.env.svm.airdrop(&j.pubkey(), 1_000_000_000).unwrap();
    let (ua, pd) = (t.upgrade.insecure_clone(), t.program_data);
    let before = t.snapshot();
    let r = t.init_b(&ua, pd, &j, true);
    eprintln!("tag94 B after A -> {:?}", refused(&r));
    assert!(r.is_err());
    assert_eq!(t.snapshot(), before);
    // non-marketauth on path A
    let mut t2 = T::new();
    let rnd = Keypair::new();
    t2.env.svm.airdrop(&rnd.pubkey(), 10_000_000_000).unwrap();
    let r2 = t2.init_a(&rnd);
    eprintln!("tag94 A by non-marketauth -> {:?}", refused(&r2));
    assert!(r2.is_err());
}
