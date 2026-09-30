// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! P3 fork regressions: bind a vault-owned LP on the REAL live account state of the four
//! devnet failure markets (ANSEM, COLLECT, Murphy, TEXTIT), then replay each market's
//! failure shape against it. The P3 candidate bytes run beside the DEPLOYED v18.2 bytes,
//! which serve as the negative control.
//!
//! # Fixtures (read-only, no keys)
//! * `tests/fixtures/p1_fork/<market>.json` holds P1's dumps: every wrapper-owned account
//!   of the market, the matcher ctx, and the Clock, from ONE `getMultipleAccounts` call.
//! * `tests/fixtures/p3_fork/spl.json` holds the SPL accounts P1's dumps omit: the
//!   collateral mint, each market's vault token account (owner `["vault", market]`), each
//!   Earn LP mint `["lp_vault_mint", market]`, and each marketauth's account. Fetcher:
//!   `tests/fixtures/p3_fork/fetch_spl.py`. NOTE: it was fetched ~62k slots AFTER P1's
//!   dumps. Every test asserts that the vault token balance still equals the engine's
//!   `header.vault` at the P1 slot. If it did not, the fixture pair would be inconsistent.
//! * The ProgramData header is `tests/fixtures/p1_fork/wrapper_programdata_header.json`
//!   (upgrade authority `FbTbDe…`).
//!
//! # What is and is not real
//! * LIVE, never rewritten: the slab, the registry, the portfolios, the matcher ctx, the
//!   vault token account, the LP mint and the Clock.
//! * NEW accounts are created by REAL instructions: system `create_account` for the
//!   vault-LP portfolio and its matcher ctx, system `transfer` to pre-fund the
//!   `["vault_lp", market]` PDA, and `InitPortfolio` for traders.
//! * TEST-SUPPLIED capital: new SPL token accounts with balances. They cover the Earn
//!   depositor, the junior source (owned by the junior key) and the traders. They are
//!   fresh capital arriving; no live balance is edited.
//! * SIGNERS are listed with a default signature (`with_sigverify(false)`), as in P1:
//!   - the upgrade authority `FbTbDe…` (tags 99 and 95; the protocol holds it);
//!   - new traders and depositors;
//!   - the MARKETAUTH for tags 94 and 96. On all four markets the marketauth is the
//!     percolator-stake POOL PDA `["stake_pool", slab]` (owner `GCHhcgw…`): off-curve, and the
//!     deployed stake program has no proxy for wrapper tags 94/96/97/102, so ON CHAIN these
//!     markets can never bind. The replay SIMULATES the marketauth's signature, standing in
//!     for the relaunch flow (fresh market, admin marketauth binds before stake InitPool).
//!     Controls pin both facts: listing the PDA without a signature gets ExpectedSigner, and
//!     the removed protocol path B (upgrade authority + ProgramData + junior) gets Unauthorized.
//!   - the live oracle authority `FbTbDe…`, for AUTH_MARK pushes (the keeper holds this key).
//! * PERMISSIONLESS REPAIRS run before every replay. Each is a real instruction anyone
//!   can send:
//!   - tag 89 on lapsed buckets;
//!   - tag 45 on a ResetPending side;
//!   - PermissionlessCrank until the asset accrual reaches the clock. The fixtures lag by
//!     about 2.2k slots, and while the asset lags with OI open the engine treats it as
//!     loss-stale (21 on every risk-increasing trade);
//!   - a crank of each live portfolio while stale accounts exist (ANSEM's bankrupt pair).
//! * The clock advances only inside the price-move helper, as time passing.

use litesvm::LiteSVM;
use percolator::SideModeV16;
use percolator_prog::{
    constants::KIND_PORTFOLIO,
    ix::{CrankObservationHint, Instruction as ProgInstruction},
    state::{
        self, derive_lp_backing_ledger, derive_lp_vault_mint, derive_lp_vault_registry,
        derive_vault_lp_state,
    },
};
use solana_program::pubkey;
use solana_sdk::{
    account::Account,
    clock::Clock,
    hash::hashv,
    instruction::{AccountMeta, Instruction, InstructionError},
    message::Message,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState};
use std::path::PathBuf;

const WRAPPER_ID: Pubkey = pubkey!("GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ");
const MATCHER_ID: Pubkey = pubkey!("4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT");
const STAKE_ID: Pubkey = pubkey!("GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3");

const DEPLOYED_SO_DEFAULT: &str = "/Users/khubair/deploycand-v182/out/wrapper-v18.2.so";
const DEPLOYED_SO_SHA256: &str = "4472b3832fda102aae8d28b3c1efc642a4b919f3671d93076ca6f88cce51e98b";
const MATCHER_SO_SHA256: &str = "659eaf9dfd90e7253154a621fa98f3664df95179860cbef0814cc2fc7d0a62c6";
const MATCHER_CONTEXT_LEN: usize = 320;

const ASSET: u16 = 0;

// Wrapper error ordinals (PercolatorError -> Custom(n)).
const E_INSUFFICIENT_IM: u32 = 49;
const E_VAULT_LP_EXPOSURE_CAP: u32 = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bytes {
    Deployed,
    Candidate,
}

fn sha256_hex(b: &[u8]) -> String {
    hashv(&[b]).to_bytes().iter().map(|x| format!("{x:02x}")).collect()
}

fn wrapper_bytes(which: Bytes) -> Vec<u8> {
    match which {
        Bytes::Deployed => {
            let p = std::env::var("P1_FORK_DEPLOYED_SO").unwrap_or_else(|_| DEPLOYED_SO_DEFAULT.to_string());
            let b = std::fs::read(&p).unwrap_or_else(|e| panic!("read deployed .so {p}: {e}"));
            assert_eq!(sha256_hex(&b), DEPLOYED_SO_SHA256, "deployed .so at {p} is not the live v18.2 wrapper");
            b
        }
        Bytes::Candidate => {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("target/deploy/percolator_prog.so");
            let b = std::fs::read(&p)
                .unwrap_or_else(|e| panic!("read candidate .so {}: {e} (cargo build-sbf --features devnet)", p.display()));
            assert_ne!(sha256_hex(&b), DEPLOYED_SO_SHA256, "candidate .so is the deployed wrapper — stale build?");
            eprintln!("candidate wrapper sha256 {} ({} B)", sha256_hex(&b), b.len());
            b
        }
    }
}

fn matcher_bytes() -> Vec<u8> {
    // CI dumps the live matcher bytes and passes them here (as for the P1 fork suite).
    let p = std::env::var_os("P1_FORK_MATCHER_SO").map(PathBuf::from).unwrap_or_else(|| {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../percolator-match/target/deploy/percolator_match.so");
        p
    });
    let b = std::fs::read(&p).unwrap_or_else(|e| panic!("read matcher .so {}: {e}", p.display()));
    assert_eq!(sha256_hex(&b), MATCHER_SO_SHA256, "matcher .so is not deployed 12bd671");
    b
}

fn spl_token_program_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from).unwrap_or_else(|| {
        let mut h = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
        h.push(".cargo");
        h
    });
    for reg in std::fs::read_dir(cargo_home.join("registry/src")).expect("registry/src") {
        let cand = reg.expect("entry").path().join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if cand.exists() {
            return cand;
        }
    }
    panic!("spl_token BPF not found");
}

// ── Fixtures ────────────────────────────────────────────────────────────────

struct Fixture {
    name: String,
    slab: Pubkey,
    fetch_slot: u64,
    clock: Clock,
    accounts: Vec<(Pubkey, Account)>,
    /// From spl.json: (vault token, collateral mint, LP mint, marketauth).
    vault_token: (Pubkey, Account),
    mint: (Pubkey, Account),
    lp_mint: (Pubkey, Account),
    marketauth: Pubkey,
    marketauth_owner: Pubkey,
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

fn json_account(a: &serde_json::Value) -> (Pubkey, Account) {
    (
        a["pubkey"].as_str().unwrap().parse().unwrap(),
        Account {
            lamports: a["lamports"].as_u64().unwrap(),
            data: b64(a["data_b64"].as_str().unwrap()),
            owner: a["owner"].as_str().unwrap().parse().unwrap(),
            executable: a["executable"].as_bool().unwrap(),
            rent_epoch: 0,
        },
    )
}

fn load_fixture(name: &str) -> Fixture {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(root.join(format!("tests/fixtures/p1_fork/{name}.json"))).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let clock: Clock = bincode::deserialize(&b64(v["clock_sysvar_b64"].as_str().unwrap())).unwrap();
    let accounts = v["accounts"].as_array().unwrap().iter().map(json_account).collect();
    let spl: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("tests/fixtures/p3_fork/spl.json")).unwrap()).unwrap();
    let m = &spl["markets"][name];
    let slab: Pubkey = v["slab"].as_str().unwrap().parse().unwrap();
    assert_eq!(m["slab"].as_str().unwrap(), slab.to_string(), "spl.json market mismatch");
    let vts = m["vault_tokens"].as_array().unwrap();
    assert_eq!(vts.len(), 1, "{name}: exactly one vault token account");
    Fixture {
        name: name.to_string(),
        slab,
        fetch_slot: v["fetch_slot"].as_u64().unwrap(),
        clock,
        accounts,
        vault_token: json_account(&vts[0]),
        mint: json_account(&spl["mint"]),
        lp_mint: json_account(&m["lp_mint"]),
        marketauth: m["marketauth"].as_str().unwrap().parse().unwrap(),
        marketauth_owner: m["marketauth_account"]["owner"].as_str().unwrap().parse().unwrap(),
    }
}

fn pk(s: &str) -> Pubkey {
    s.parse().unwrap()
}

fn unit() -> i128 {
    percolator::POS_SCALE as i128
}

fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

// ── Environment ─────────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    payer: Keypair,
    slab: Pubkey,
    label: String,
    mint: Pubkey,
    vault_token: Pubkey,
    registry: Pubkey,
    lp_mint: Pubkey,
    ledger: Pubkey,
    sibling: Pubkey,
    vault_lp: Pubkey,
    marketauth: Pubkey,
    domain: u16,
    plen: usize,
    /// TEST-SUPPLIED SPL that entered the vault (Earn seed + junior + trader deposits).
    supplied_in: u128,
    /// Every live portfolio in the fixture.
    live_portfolios: Vec<Pubkey>,
    /// A real keypair used only as the junior in the removed-path-B control.
    junior: Keypair,
}

type Outcome = (Result<(), TransactionError>, Vec<String>);

fn env(fx: &Fixture, which: Bytes) -> Env {
    let mut svm = LiteSVM::new().with_sigverify(false);
    svm.add_program(WRAPPER_ID, &wrapper_bytes(which));
    svm.add_program(MATCHER_ID, &matcher_bytes());
    svm.add_program(spl_token::ID, &std::fs::read(spl_token_program_path()).unwrap());
    for (k, a) in &fx.accounts {
        svm.set_account(*k, a.clone()).unwrap();
    }
    for (k, a) in [&fx.vault_token, &fx.mint, &fx.lp_mint] {
        svm.set_account(*k, a.clone()).unwrap();
    }
    svm.set_sysvar(&fx.clock);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
    let (registry, _) = derive_lp_vault_registry(&WRAPPER_ID, &fx.slab);
    let reg = state::read_lp_vault_registry(&svm.get_account(&registry).expect("live registry").data).unwrap();
    let domain = reg.domain;
    let (lp_mint, _) = derive_lp_vault_mint(&WRAPPER_ID, &fx.slab);
    assert_eq!(lp_mint, fx.lp_mint.0, "LP mint PDA");
    assert_eq!(reg.lp_mint, lp_mint.to_bytes(), "registry.lp_mint");
    let vault_authority = Pubkey::find_program_address(&[b"vault", fx.slab.as_ref()], &WRAPPER_ID).0;
    let vt = TokenAccount::unpack(&fx.vault_token.1.data).unwrap();
    assert_eq!(vt.owner, vault_authority, "vault token owner = vault authority PDA");
    let plen = fx
        .accounts
        .iter()
        .find(|(_, a)| a.owner == WRAPPER_ID && a.data.len() > 10 && a.data[10] == KIND_PORTFOLIO)
        .map(|(_, a)| a.data.len())
        .unwrap();
    let e = Env {
        svm,
        payer,
        slab: fx.slab,
        label: format!("{}/{:?}", fx.name, which),
        mint: fx.mint.0,
        vault_token: fx.vault_token.0,
        registry,
        lp_mint,
        ledger: derive_lp_backing_ledger(&WRAPPER_ID, &fx.slab, domain).0,
        sibling: derive_lp_backing_ledger(&WRAPPER_ID, &fx.slab, domain ^ 1).0,
        vault_lp: derive_vault_lp_state(&WRAPPER_ID, &fx.slab).0,
        marketauth: fx.marketauth,
        domain,
        plen,
        supplied_in: 0,
        live_portfolios: fx
            .accounts
            .iter()
            .filter(|(_, a)| a.owner == WRAPPER_ID && a.data.len() > 10 && a.data[10] == KIND_PORTFOLIO)
            .map(|(k, _)| *k)
            .collect(),
        junior: Keypair::new(),
    };
    // Fixture-pair consistency: the later SPL fetch must agree with the P1 slab dump.
    let (_, g) = state::read_market(&e.data(&e.slab)).unwrap();
    assert_eq!(vt.amount as u128, g.vault, "{}: SPL vault balance != engine header.vault", e.label);
    // The marketauth is the stake pool PDA (see module docs).
    let (pool, _) = Pubkey::find_program_address(&[b"stake_pool", fx.slab.as_ref()], &STAKE_ID);
    assert_eq!(fx.marketauth, pool, "{}: marketauth is the stake pool PDA", e.label);
    assert_eq!(fx.marketauth_owner, STAKE_ID);
    assert!(!fx.marketauth.is_on_curve(), "{}: marketauth is off-curve (no private key exists)", e.label);
    let (cfg, _) = state::read_market(&e.data(&e.slab)).unwrap();
    assert_eq!(cfg.marketauth, fx.marketauth.to_bytes(), "{}: slab marketauth", e.label);
    e
}

impl Env {
    fn send(&mut self, ixs: Vec<Instruction>, fake_signers: &[Pubkey], real: &[&Keypair]) -> Outcome {
        self.svm.expire_blockhash();
        let mut all = vec![
            solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(256 * 1024),
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ];
        all.extend(ixs);
        let msg = Message::new(&all, Some(&self.payer.pubkey()));
        for s in fake_signers {
            assert!(
                msg.account_keys[..msg.header.num_required_signatures as usize].contains(s),
                "fake signer {s} is not a required signer"
            );
        }
        let mut tx = Transaction::new_unsigned(msg);
        tx.signatures = vec![Signature::default(); tx.message.header.num_required_signatures as usize];
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(real);
        tx.partial_sign(&signers, self.svm.latest_blockhash());
        match self.svm.send_transaction(tx) {
            Ok(meta) => (Ok(()), meta.logs),
            Err(f) => (Err(f.err), f.meta.logs),
        }
    }

    fn wrapper_ix(&self, ix: ProgInstruction, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction { program_id: WRAPPER_ID, accounts, data: ix.encode() }
    }

    fn data(&self, k: &Pubkey) -> Vec<u8> {
        self.svm.get_account(k).unwrap().data
    }

    fn tok(&self, k: &Pubkey) -> u64 {
        TokenAccount::unpack(&self.data(k)).unwrap().amount
    }

    /// TEST-SUPPLIED capital: a NEW SPL token account of `mint` owned by `owner`.
    fn new_token(&mut self, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
        let k = Pubkey::new_unique();
        self.svm
            .set_account(
                k,
                Account {
                    lamports: 2_039_280,
                    data: make_token_data(mint, owner, amount),
                    owner: spl_token::ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        k
    }

    /// A NEW account created by a real system `create_account` (payer + new key both sign).
    fn create_owned(&mut self, owner: &Pubkey, len: usize) -> Pubkey {
        let kp = Keypair::new();
        let lamports = self.svm.minimum_balance_for_rent_exemption(len);
        let ix = system_instruction::create_account(&self.payer.pubkey(), &kp.pubkey(), lamports, len as u64, owner);
        let o = self.send(vec![ix], &[], &[&kp]);
        expect_ok(&o, "system create_account");
        kp.pubkey()
    }

    fn market(&self) -> (state::WrapperConfigV16, state::MarketGroupV16) {
        state::read_market(&self.data(&self.slab)).unwrap()
    }

    fn portfolio(&self, k: &Pubkey) -> state::PortfolioAccountV16 {
        state::read_portfolio(&self.data(k)).unwrap()
    }

    fn pos(&self, k: &Pubkey) -> i128 {
        self.portfolio(k)
            .legs
            .iter()
            .filter(|l| l.active && l.asset_index == ASSET as u32)
            .map(|l| match l.side {
                percolator::SideV16::Long => l.basis_pos_q.unsigned_abs() as i128,
                percolator::SideV16::Short => -(l.basis_pos_q.unsigned_abs() as i128),
            })
            .sum()
    }

    fn capital_pnl(&self, k: &Pubkey) -> (u128, i128, i128) {
        let p = self.portfolio(k);
        (p.capital, p.pnl, p.fee_credits)
    }

    fn vlp(&self) -> state::VaultLpStateV18 {
        state::read_vault_lp_state(&self.data(&self.vault_lp)).unwrap()
    }

    fn asset_rec(&self) -> state::AssetVaultLpV18 {
        state::read_asset_vault_lp(&self.data(&self.slab), ASSET as usize).unwrap()
    }

    /// Backing NAV the Earn side sees (own + sibling ledger), as the program computes it:
    /// read from the ledgers the wrapper keeps.
    fn ledger_dump(&self) -> String {
        let mut s = String::new();
        for k in [self.ledger, self.sibling] {
            match self.svm.get_account(&k) {
                Some(a) if a.owner == WRAPPER_ID => s.push_str(&format!(" ledger {k}: {} B;", a.data.len())),
                _ => s.push_str(&format!(" ledger {k}: absent;")),
            }
        }
        s
    }

    fn dump(&self, fx: &Fixture) {
        let (cfg, g) = self.market();
        let a = &g.assets[ASSET as usize];
        let prof = state::read_asset_oracle_profile(&self.data(&self.slab), ASSET as usize).unwrap();
        eprintln!(
            "[{}] fetch_slot={} clock={} mode={:?} oracle_mode={} eff_px={} oi_long={} oi_short={} mode_long={:?} mode_short={:?} vault={} ins={} c_tot={} trade_fee_bps={} domain={} backing_auth={} registry={} oracle_auth={} asset_admin={} last_good_oracle_slot={}",
            self.label, fx.fetch_slot, self.svm.get_sysvar::<Clock>().slot, g.mode, prof.oracle_mode,
            a.effective_price, a.oi_eff_long_q, a.oi_eff_short_q, a.mode_long, a.mode_short, g.vault,
            g.insurance, g.c_tot, cfg.trade_fee_base_bps, self.domain,
            Pubkey::new_from_array(prof.backing_bucket_authority), self.registry,
            Pubkey::new_from_array(prof.oracle_authority), Pubkey::new_from_array(prof.asset_admin),
            prof.last_good_oracle_slot
        );
        eprintln!("   {}", self.ledger_dump());
        for (d, b) in g.source_backing_buckets.iter().enumerate() {
            if b.status != percolator::BackingBucketStatusV16::Empty || b.fresh_unliened_backing_num != 0 {
                eprintln!("   bucket d{d}: {:?}", b);
            }
        }
    }

    // ── permissionless live repairs (as P1) ───────────────────────────────

    fn apply_live_repairs(&mut self) -> Vec<String> {
        let mut applied = Vec::new();
        let now = self.svm.get_sysvar::<Clock>().slot;
        let (_, g) = self.market();
        let lapsed: Vec<usize> = g
            .source_backing_buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| b.status == percolator::BackingBucketStatusV16::Fresh && b.expiry_slot <= now)
            .map(|(d, _)| d)
            .collect();
        for d in lapsed {
            let ix = self.wrapper_ix(
                ProgInstruction::ExpireBackingBucket { domain: d as u16 },
                vec![AccountMeta::new(self.slab, false)],
            );
            let o = self.send(vec![ix], &[], &[]);
            expect_ok(&o, &format!("{} tag89 d{d}", self.label));
            applied.push(format!("tag89 ExpireBackingBucket d{d}"));
        }
        let (_, g) = self.market();
        if g.assets[ASSET as usize].mode_short == SideModeV16::ResetPending {
            let ix = self.wrapper_ix(
                ProgInstruction::FinalizeResetSide { asset_index: ASSET, side: 1 },
                vec![AccountMeta::new(self.slab, false)],
            );
            let o = self.send(vec![ix], &[], &[]);
            expect_ok(&o, &format!("{} tag45 short", self.label));
            applied.push("tag45 FinalizeResetSide(short)".to_string());
        }
        // Accrual catch-up: every live market's asset accrual lags the clock by ~2.2k slots,
        // and one PermissionlessCrank accrues at most `max_accrual_dt_slots`. While
        // `asset.slot_last < header.current_slot` with OI open, the engine treats the asset
        // as loss-stale and refuses every risk-increasing trade with 21. That is the live
        // "accrue-staleness lock". Crank until the asset is current.
        let first = self.live_portfolios[0];
        let mut n = 0;
        loop {
            let o = self.crank(first);
            expect_ok(&o, &format!("{} accrual crank", self.label));
            n += 1;
            let (_, g) = self.market();
            if g.assets[ASSET as usize].slot_last == g.current_slot {
                break;
            }
            assert!(n < 200, "{}: accrual never caught up", self.label);
        }
        applied.push(format!("{n}x PermissionlessCrank accrual catch-up"));
        // Stale live accounts (ANSEM: the bankrupt creator pair, stale L/S = 1/1) also make the
        // asset loss-stale. A permissionless crank of each live portfolio settles them.
        let (_, g) = self.market();
        let a = &g.assets[ASSET as usize];
        if a.stale_account_count_long + a.stale_account_count_short != 0 {
            for k in self.live_portfolios.clone() {
                let o = self.crank(k);
                // 22 = EngineNonProgress: nothing left to settle on that portfolio.
                if custom_code(&o) != Some(22) {
                    expect_ok(&o, &format!("{} crank live {k}", self.label));
                }
            }
            let (_, g) = self.market();
            let a = &g.assets[ASSET as usize];
            assert_eq!(a.stale_account_count_long + a.stale_account_count_short, 0, "{}: stale accounts cleared", self.label);
            applied.push("PermissionlessCrank of each live portfolio (stale accounts -> 0)".to_string());
        }
        eprintln!("[{}] repairs applied: {applied:?}", self.label);
        applied
    }

    // ── Earn seed (tag 75) ─────────────────────────────────────────────────

    fn earn_deposit(&mut self, amount: u64, bound_lp: Option<Pubkey>) -> Outcome {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
        let src = self.new_token(self.mint, kp.pubkey(), amount);
        let lp_ata = self.new_token(self.lp_mint, kp.pubkey(), 0);
        let mut accts = vec![
            AccountMeta::new(kp.pubkey(), true),
            AccountMeta::new(self.slab, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.lp_mint, false),
            AccountMeta::new(lp_ata, false),
            AccountMeta::new(src, false),
            AccountMeta::new(self.vault_token, false),
            AccountMeta::new(self.ledger, false),
            AccountMeta::new_readonly(spl_token::ID, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new(self.sibling, false),
        ];
        if let Some(lp) = bound_lp {
            accts.push(AccountMeta::new(self.vault_lp, false));
            accts.push(AccountMeta::new_readonly(lp, false));
        }
        let ix = self.wrapper_ix(
            ProgInstruction::DepositToLpVault { amount: amount as u128, domain: self.domain },
            accts,
        );
        let o = self.send(vec![ix], &[], &[&kp]);
        if o.0.is_ok() {
            self.supplied_in += amount as u128;
        }
        o
    }

    // ── P3 bind sequence ────────────────────────────────────────────────

    /// NEW vault-LP portfolio (real system `create_account`), and the `["vault_lp", market]`
    /// PDA pre-funded by a real system transfer.
    fn prepare_vault_lp(&mut self) -> Pubkey {
        let lp = self.create_owned(&WRAPPER_ID, self.plen);
        let rent = self.svm.minimum_balance_for_rent_exemption(state::vault_lp_state_account_len());
        let fund = system_instruction::transfer(&self.payer.pubkey(), &self.vault_lp, rent);
        let o = self.send(vec![fund], &[], &[]);
        expect_ok(&o, "prefund vault_lp PDA");
        lp
    }

    fn init_vault_lp_accounts(&self, admin: Pubkey, lp: Pubkey) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(self.slab, false),
            AccountMeta::new(self.registry, false),
            AccountMeta::new(self.vault_lp, false),
            AccountMeta::new(lp, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
            AccountMeta::new_readonly(self.ledger, false),
            AccountMeta::new_readonly(self.sibling, false),
        ]
    }

    /// Auto-pin tail for tag 94: [8] canonical matcher, [9] fresh ctx, [10] delegate.
    fn autopin_tail(&mut self, lp: Pubkey) -> (Vec<AccountMeta>, Pubkey, Pubkey) {
        let ctx = self.create_owned(&MATCHER_ID, MATCHER_CONTEXT_LEN);
        let delegate = Pubkey::find_program_address(
            &[b"matcher", self.slab.as_ref(), lp.as_ref(), self.registry.as_ref(), MATCHER_ID.as_ref(), ctx.as_ref()],
            &WRAPPER_ID,
        )
        .0;
        (
            vec![
                AccountMeta::new_readonly(MATCHER_ID, false),
                AccountMeta::new(ctx, false),
                AccountMeta::new_readonly(delegate, false),
            ],
            ctx,
            delegate,
        )
    }

    /// tag 94, marketauth path (the ONLY path since the path-B removal): [0] = the live
    /// marketauth (the stake-pool PDA), listed as a FAKE signer. SIMULATED: on chain that PDA
    /// cannot sign; relaunch markets are created fresh and bound by the admin marketauth BEFORE
    /// stake InitPool, which is the state this replay stands in for. The junior owner is
    /// therefore the marketauth.
    fn init_vault_lp(&mut self, floor_bps: u16) -> (VaultLp, Outcome) {
        let lp = self.prepare_vault_lp();
        let mut accts = self.init_vault_lp_accounts(self.marketauth, lp);
        let (tail, ctx, delegate) = self.autopin_tail(lp);
        accts.extend(tail);
        let ix = self.wrapper_ix(ProgInstruction::InitVaultLp { junior_floor_bps: floor_bps }, accts);
        let ma = self.marketauth;
        (VaultLp { portfolio: lp, ctx, delegate }, self.send(vec![ix], &[ma], &[]))
    }

    /// tag 94, LEGACY marketauth path (A), sent the only way the chain allows for these
    /// markets: the off-curve stake-pool PDA is listed but cannot sign (no key exists, and no
    /// stake proxy exists).
    fn init_vault_lp_legacy_unsigned(&mut self, floor_bps: u16) -> Outcome {
        let lp = self.prepare_vault_lp();
        let mut accts = self.init_vault_lp_accounts(self.marketauth, lp);
        accts[0] = AccountMeta::new(self.marketauth, false);
        let ix = self.wrapper_ix(ProgInstruction::InitVaultLp { junior_floor_bps: floor_bps }, accts);
        self.send(vec![ix], &[], &[])
    }

    /// tag 94 in the REMOVED protocol shape ("path B"): [0] = the live upgrade authority
    /// (fake-signed), [8] = ProgramData, [9] = a real signing junior. Must be refused.
    fn init_vault_lp_former_path_b(&mut self, floor_bps: u16) -> Outcome {
        let lp = self.prepare_vault_lp();
        let (auth, pd) = self.mount_programdata();
        let mut accts = self.init_vault_lp_accounts(auth, lp);
        accts.push(AccountMeta::new_readonly(pd, false));
        accts.push(AccountMeta::new_readonly(self.junior.pubkey(), true));
        let ix = self.wrapper_ix(ProgInstruction::InitVaultLp { junior_floor_bps: floor_bps }, accts);
        let junior = self.junior.insecure_clone();
        self.send(vec![ix], &[auth], &[&junior])
    }

    fn mount_programdata(&mut self) -> (Pubkey, Pubkey) {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/p1_fork/wrapper_programdata_header.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let pd = pk(v["programdata"].as_str().unwrap());
        let (derived, _) =
            Pubkey::find_program_address(&[WRAPPER_ID.as_ref()], &solana_sdk::bpf_loader_upgradeable::id());
        assert_eq!(pd, derived);
        self.svm
            .set_account(
                pd,
                Account {
                    lamports: 1_000_000_000,
                    data: b64(v["header_45_b64"].as_str().unwrap()),
                    owner: solana_sdk::bpf_loader_upgradeable::id(),
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        (pk(v["upgrade_authority"].as_str().unwrap()), pd)
    }

    /// tag 99 as the live upgrade authority.
    fn set_vault_lp_risk(&mut self, vault_lp_max_lev_bps: u32) -> Outcome {
        let (auth, pd) = self.mount_programdata();
        let ix = self.wrapper_ix(
            ProgInstruction::SetVaultLpRisk {
                asset_index: ASSET,
                skew_slope_e9: 0,
                skew_max_e9: 0,
                lev_cap_q: 0,
                lev_max_imr_bps: 0,
                vault_lp_max_lev_bps,
                approved_matcher_program: MATCHER_ID.to_bytes(),
            },
            vec![
                AccountMeta::new(auth, true),
                AccountMeta::new_readonly(pd, false),
                AccountMeta::new(self.slab, false),
            ],
        );
        self.send(vec![ix], &[auth], &[])
    }

    /// tag 95 as the live upgrade authority. The ctx is a NEW matcher-owned account
    /// (real system create_account).
    /// tag 96 signed by the junior owner = the marketauth (fake signer, see `init_vault_lp`).
    fn junior_deposit(&mut self, lp: Pubkey, amount: u64) -> Outcome {
        let ma = self.marketauth;
        let src = self.new_token(self.mint, ma, amount);
        let ix = self.wrapper_ix(
            ProgInstruction::DepositJuniorTranche { amount: amount as u128 },
            vec![
                AccountMeta::new(ma, true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(self.vault_lp, false),
                AccountMeta::new(lp, false),
                AccountMeta::new(src, false),
                AccountMeta::new(self.vault_token, false),
                AccountMeta::new_readonly(spl_token::ID, false),
            ],
        );
        let o = self.send(vec![ix], &[ma], &[]);
        if o.0.is_ok() {
            self.supplied_in += amount as u128;
        }
        o
    }

    // ── traders ──────────────────────────────────────────────────────────

    /// NEW portfolio owned by `owner` (fake-signed: `owner` is either a fresh test key or a
    /// live wallet that could sign), funded with TEST-SUPPLIED capital.
    fn new_trader(&mut self, owner: Pubkey, capital: u64) -> Pubkey {
        let p = self.create_owned(&WRAPPER_ID, self.plen);
        let ix = self.wrapper_ix(
            ProgInstruction::InitPortfolio,
            vec![AccountMeta::new(owner, true), AccountMeta::new(self.slab, false), AccountMeta::new(p, false)],
        );
        let o = self.send(vec![ix], &[owner], &[]);
        expect_ok(&o, &format!("{} InitPortfolio", self.label));
        if capital > 0 {
            let src = self.new_token(self.mint, owner, capital);
            let d = self.data(&p);
            let ix = self.wrapper_ix(
                ProgInstruction::Deposit {
                    portfolio_id: state::read_portfolio_id(&d).unwrap(),
                    expected_sequence: state::read_portfolio_matcher_sequence(&d).unwrap(),
                    amount: capital as u128,
                },
                vec![
                    AccountMeta::new(owner, true),
                    AccountMeta::new(self.slab, false),
                    AccountMeta::new(p, false),
                    AccountMeta::new(src, false),
                    AccountMeta::new(self.vault_token, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
            );
            let o = self.send(vec![ix], &[owner], &[]);
            expect_ok(&o, &format!("{} trader Deposit", self.label));
            self.supplied_in += capital as u128;
        }
        p
    }

    fn owner(&self, k: &Pubkey) -> Pubkey {
        Pubkey::new_from_array(state::read_portfolio_owner_preflight(&self.data(k)).unwrap().1)
    }

    /// TradeCpi (tag 10): `taker` against the vault LP.
    fn trade(&mut self, taker: &Pubkey, lp: &VaultLp, size_q: i128) -> Outcome {
        let md = self.data(&self.slab);
        let (cfg, _, _, market_id, _, _) = state::read_market_trade_preflight(&md, ASSET as usize).unwrap();
        let td = self.data(taker);
        let ld = self.data(&lp.portfolio);
        let owner = self.owner(taker);
        let ix = self.wrapper_ix(
            ProgInstruction::TradeCpi {
                account_a_portfolio_id: state::read_portfolio_id(&td).unwrap(),
                account_a_position_epoch: state::read_portfolio_position_epoch(&td).unwrap(),
                account_b_portfolio_id: state::read_portfolio_id(&ld).unwrap(),
                account_b_position_epoch: state::read_portfolio_position_epoch(&ld).unwrap(),
                market_id,
                account_b_matcher_sequence: state::read_portfolio_matcher_sequence(&ld).unwrap(),
                asset_index: ASSET,
                size_q,
                fee_bps: cfg.trade_fee_base_bps,
                limit_price: 0,
                backing_fee_cap_bps: 10_000,
            },
            vec![
                AccountMeta::new(owner, true),
                AccountMeta::new(self.slab, false),
                AccountMeta::new(*taker, false),
                AccountMeta::new(lp.portfolio, false),
                AccountMeta::new_readonly(MATCHER_ID, false),
                AccountMeta::new(lp.ctx, false),
                AccountMeta::new_readonly(lp.delegate, false),
            ],
        );
        let o = self.send(vec![ix], &[owner], &[]);
        show(&format!("{} TradeCpi size {size_q}", self.label), &o);
        o
    }

    fn crank(&mut self, portfolio: Pubkey) -> Outcome {
        let now = self.svm.get_sysvar::<Clock>().slot;
        let payer = self.payer.pubkey();
        let ix = self.wrapper_ix(
            ProgInstruction::PermissionlessCrank {
                now_slot: now,
                observations: vec![CrankObservationHint { asset_index: ASSET, oracle_accounts: 0 }],
            },
            vec![AccountMeta::new(payer, true), AccountMeta::new(self.slab, false), AccountMeta::new(portfolio, false)],
        );
        self.send(vec![ix], &[], &[])
    }
}

struct VaultLp {
    portfolio: Pubkey,
    ctx: Pubkey,
    delegate: Pubkey,
}

fn show(label: &str, o: &Outcome) {
    eprintln!("--- {label}: {:?}", o.0);
    for l in &o.1 {
        if l.contains("Program log") || l.contains("failed") || l.contains("invoke [2]") {
            eprintln!("      {l}");
        }
    }
}

fn custom_code(o: &Outcome) -> Option<u32> {
    match &o.0 {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) => Some(*c),
        _ => None,
    }
}

fn expect_ok(o: &Outcome, label: &str) {
    assert!(o.0.is_ok(), "{label}: expected Ok, got {:?}; logs {:#?}", o.0, o.1);
}

fn expect_code(o: &Outcome, code: u32, label: &str) {
    assert_eq!(custom_code(o), Some(code), "{label}: expected Custom({code}), got {:?}; logs {:#?}", o.0, o.1);
}

/// Stage-by-stage binding outcome, for the survey and for the shapes.
struct Bound {
    lp: VaultLp,
    seed: u64,
    junior: u64,
}

const EARN_SEED: u64 = 1_000_000_000; // 1,000 units of the 6-dp devnet collateral
const JUNIOR: u64 = 200_000_000;

/// Full bind on the CANDIDATE bytes: repairs → Earn seed (75) → 94 → 99 → 95 → 96.
/// Panics with the failing stage and code (a live market that cannot be bound is a
/// finding, reported by `p3_fork_bind_survey`).
/// Returns None when the live market is multi-asset: since F14-Q2 a vault LP binds only on a
/// single-asset market (error 86). The four live markets were created with several configured
/// asset slots, so on the FINAL head they are refused at tag 94 — asserted here; the drain /
/// win shapes themselves are covered on single-asset markets by `tests/p3_vault_lp.rs`
/// (R2/R3 reconstructions, H2, F-14 tests).
fn bind(e: &mut Env, max_lev_bps: u32) -> Option<Bound> {
    let (_, g0) = e.market();
    if g0.config.max_market_slots > 1 {
        let (_, o) = e.init_vault_lp(2_000);
        expect_code(&o, 86, &format!("{} tag94 on a multi-asset live market (F14-Q2)", e.label));
        eprintln!("[{}] multi-asset live market ({} slots): tag 94 refused with 86 (F14-Q2)", e.label, g0.config.max_market_slots);
        return None;
    }
    Some(bind_single(e, max_lev_bps))
}

fn bind_single(e: &mut Env, max_lev_bps: u32) -> Bound {
    e.apply_live_repairs();
    let o = e.earn_deposit(EARN_SEED, None);
    show(&format!("{} tag75 Earn seed", e.label), &o);
    let seed = if o.0.is_ok() {
        EARN_SEED
    } else {
        // LIVE-STATE FINDING (pre-existing, identical on the deployed v18.2 bytes; see
        // `p3_fork_earn_seed_blocked_by_foreign_fresh_bucket`): the Earn domain's bucket is
        // Fresh with a finite expiry set by a non-Earn funder, and `add_fresh_counterparty_
        // backing_view` refuses a second expiry with EngineLockActive. The vault binds with
        // whatever Earn NAV the market already has.
        expect_code(&o, 21, &format!("{} tag75 Earn seed", e.label));
        let (_, g) = e.market();
        let b = g.source_backing_buckets[e.domain as usize];
        assert_eq!(b.status, percolator::BackingBucketStatusV16::Fresh);
        assert_ne!(b.expiry_slot, percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT);
        eprintln!(
            "[{}] Earn seed REFUSED (21): bucket d{} Fresh with foreign expiry {} (Earn uses {}) — binding without a seed",
            e.label,
            e.domain,
            b.expiry_slot,
            percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT
        );
        0
    };
    let (vlp, o) = e.init_vault_lp(2_000);
    show(&format!("{} tag94", e.label), &o);
    expect_ok(&o, &format!("{} tag94 InitVaultLp + auto-pin (marketauth path, simulated PDA signature)", e.label));
    let lp = vlp.portfolio;
    // Tag 95 is no longer needed (auto-pin); tag 99 remains a protocol ADJUSTMENT (the 5x
    // negative controls use it).
    if max_lev_bps != 0 {
        let o = e.set_vault_lp_risk(max_lev_bps);
        show(&format!("{} tag99", e.label), &o);
        expect_ok(&o, &format!("{} tag99 SetVaultLpRisk", e.label));
    }
    let o = e.junior_deposit(lp, JUNIOR);
    show(&format!("{} tag96", e.label), &o);
    expect_ok(&o, &format!("{} tag96 DepositJuniorTranche", e.label));
    let st = e.vlp();
    assert_eq!(st.lp_portfolio, lp.to_bytes());
    assert_eq!(st.junior_owner, e.marketauth.to_bytes(), "junior owner = the marketauth (path A only)");
    assert_eq!(e.capital_pnl(&lp).0, JUNIOR as u128, "junior capital lands in the vault LP");
    let rec = e.asset_rec();
    assert_eq!(rec.vault_lp_portfolio, lp.to_bytes());
    assert_eq!(rec.approved_matcher_program, MATCHER_ID.to_bytes());
    eprintln!(
        "[{}] BOUND: vault LP {lp}, C = {}, junior capital = {}, max_lev_bps = {}",
        e.label, st.senior_claim_atoms, JUNIOR, rec.vault_lp_max_lev_bps
    );
    Bound { lp: vlp, seed, junior: JUNIOR }
}

// ── Survey + negative control on the deployed bytes ─────────────────────────

/// Every market: dump live state; bind a vault LP on the candidate bytes; show that the
/// deployed v18.2 bytes have no tag 94 at all (negative control: the P3 path does not
/// exist on-chain today).
#[test]
fn p3_fork_bind_survey() {
    for name in ["ansem", "collect", "murphy", "textit"] {
        let fx = load_fixture(name);
        // Deployed: tag 94 is not an instruction.
        let mut d = env(&fx, Bytes::Deployed);
        d.dump(&fx);
        d.apply_live_repairs();
        let (_, o) = d.init_vault_lp(2_000);
        show(&format!("{} tag94", d.label), &o);
        assert!(o.0.is_err(), "{}: deployed v18.2 must not know tag 94", d.label);
        assert!(
            d.svm.get_account(&d.vault_lp).map(|a| a.owner != WRAPPER_ID).unwrap_or(true),
            "{}: deployed created no vault-LP state",
            d.label
        );
        // Candidate controls on the same live state (fresh envs).
        // (a) The LEGACY marketauth path cannot be used here: the stake-pool PDA is off-curve
        //     and no stake proxy exists, so it can only be listed without signing. Refused.
        let mut c = env(&fx, Bytes::Candidate);
        c.apply_live_repairs();
        let o = c.init_vault_lp_legacy_unsigned(2_000);
        show(&format!("{} tag94 legacy (marketauth unsigned)", c.label), &o);
        expect_code(
            &o,
            percolator_prog::error::PercolatorError::ExpectedSigner as u32,
            &format!("{}: legacy path needs the PDA's signature (ExpectedSigner)", c.label),
        );
        // (b) The REMOVED protocol path B (upgrade authority + ProgramData + signing junior),
        //     even signed by the REAL upgrade authority. Refused: tag 94 is marketauth-only.
        let o = c.init_vault_lp_former_path_b(2_000);
        show(&format!("{} tag94 former path B", c.label), &o);
        expect_code(&o, percolator_prog::error::PercolatorError::Unauthorized as u32, &format!("{} former path B", c.label));
        assert!(
            c.svm.get_account(&c.vault_lp).map(|a| a.owner != WRAPPER_ID).unwrap_or(true),
            "{}: refused paths created no vault-LP state",
            c.label
        );
        // Candidate: full bind through the marketauth path (simulated PDA signature).
        let mut c = env(&fx, Bytes::Candidate);
        let Some(b) = bind(&mut c, 0) else { return; };
        c.dump(&fx);
        eprintln!("[{}] survey: seed={} junior={}", c.label, b.seed, b.junior);
    }
}

/// LIVE-STATE FINDING, not P3: after the permissionless repairs, an Earn deposit (tag 75)
/// is refused with EngineLockActive (21) on COLLECT and TEXTIT, identically on the
/// deployed v18.2 bytes and on the candidate. The Earn domain's bucket is Fresh with a
/// finite expiry that a non-Earn funder set. `add_fresh_counterparty_backing_view` only
/// accepts `LP_VAULT_BACKING_EXPIRY_SLOT` on a Fresh bucket. ANSEM and Murphy accept the
/// deposit on both byte sets.
#[test]
fn p3_fork_earn_seed_blocked_by_foreign_fresh_bucket() {
    for (name, blocked) in [("ansem", false), ("collect", true), ("murphy", false), ("textit", true)] {
        let fx = load_fixture(name);
        let mut codes = Vec::new();
        for which in [Bytes::Deployed, Bytes::Candidate] {
            let mut e = env(&fx, which);
            e.apply_live_repairs();
            let o = e.earn_deposit(EARN_SEED, None);
            eprintln!("[{}] tag75 Earn deposit after repairs -> {:?}", e.label, o.0);
            if blocked {
                expect_code(&o, 21, &e.label);
                let (_, g) = e.market();
                let b = g.source_backing_buckets[e.domain as usize];
                assert_eq!(b.status, percolator::BackingBucketStatusV16::Fresh, "{}", e.label);
                assert_ne!(b.expiry_slot, percolator_prog::constants::LP_VAULT_BACKING_EXPIRY_SLOT);
                eprintln!("[{}]   bucket d{} expiry {} (foreign)", e.label, e.domain, b.expiry_slot);
            } else {
                expect_ok(&o, &e.label);
            }
            codes.push(custom_code(&o));
        }
        assert_eq!(codes[0], codes[1], "{name}: deployed and candidate must agree (pre-existing)");
    }
}

// ── Shape helpers ───────────────────────────────────────────────────────────

/// Senior-side observables. The bucket fields move in real time; the ledger NAV moves only
/// on vault instructions. C is the senior claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeniorSide {
    c: u128,
    ledger_nav: u128,
    own_fresh: u128,
    own_consumed: u128,
    own_impaired: u128,
    sib_consumed: u128,
    sib_impaired: u128,
}

impl SeniorSide {
    /// No senior harm, relative to `before`. C and the ledger NAV are unchanged. Fresh
    /// backing did not shrink. No lien was newly consumed or impaired on either domain.
    /// A DECREASE in consumed liens is a recovery that pays down a pre-existing live
    /// receivable. It is allowed and reported.
    fn no_harm_since(&self, before: &SeniorSide) -> bool {
        self.c == before.c
            && self.ledger_nav == before.ledger_nav
            && self.own_fresh >= before.own_fresh
            && self.own_consumed <= before.own_consumed
            && self.own_impaired <= before.own_impaired
            && self.sib_consumed <= before.sib_consumed
            && self.sib_impaired <= before.sib_impaired
    }
}

impl Env {
    fn ledger_nav(&self) -> u128 {
        let mut nav = 0u128;
        for key in [self.ledger, self.sibling] {
            if let Some(a) = self.svm.get_account(&key) {
                if let Ok(l) = state::read_backing_domain_ledger(&a.data) {
                    nav += l.total_principal_atoms - (l.cumulative_loss_atoms - l.cumulative_recovery_atoms);
                }
            }
        }
        nav
    }

    fn senior_side(&self) -> SeniorSide {
        let (_, g) = self.market();
        let own = g.source_backing_buckets[self.domain as usize];
        let sib = g.source_backing_buckets[(self.domain ^ 1) as usize];
        SeniorSide {
            c: self.vlp().senior_claim_atoms,
            ledger_nav: self.ledger_nav(),
            own_fresh: own.fresh_unliened_backing_num,
            own_consumed: own.consumed_liened_backing_num,
            own_impaired: own.impaired_liened_backing_num,
            sib_consumed: sib.consumed_liened_backing_num,
            sib_impaired: sib.impaired_liened_backing_num,
        }
    }

    fn equity(&self, k: &Pubkey) -> i128 {
        let (cap, pnl, _) = self.capital_pnl(k);
        cap as i128 + pnl
    }

    fn price(&self) -> u64 {
        self.market().1.assets[ASSET as usize].effective_price
    }

    /// AUTH_MARK (oracle_mode 3) push signed by the LIVE oracle authority (`FbTbDe…`, the
    /// keeper's key; fake signature). One slot per push, cranking `crank` each step, until
    /// the engine's effective price reaches `target`.
    fn move_price(&mut self, target: u64, crank: &[Pubkey]) {
        let prof = state::read_asset_oracle_profile(&self.data(&self.slab), ASSET as usize).unwrap();
        assert_eq!(prof.oracle_mode, 3, "AUTH_MARK");
        let auth = Pubkey::new_from_array(prof.oracle_authority);
        // One push per step. The step starts at 1 slot and doubles (cap 100 =
        // `max_accrual_dt_slots`) while the effective price does not move: on sub-cent e6
        // prices (Murphy: 341) a one-slot move cap rounds to zero.
        let mut step = 1u64;
        for _ in 0..2_000 {
            let before = self.price();
            let slot = self.svm.get_sysvar::<Clock>().slot + step;
            self.svm.warp_to_slot(slot);
            let md = self.data(&self.slab);
            let market_id = state::read_market_trade_preflight(&md, ASSET as usize).unwrap().3;
            let seq = state::read_asset_control_sequences(&md, ASSET as usize).unwrap().oracle_observation + 1;
            let ix = self.wrapper_ix(
                ProgInstruction::PushAuthMark {
                    asset_index: ASSET,
                    market_id,
                    now_slot: slot,
                    mark_e6: target,
                    observation_sequence: seq,
                },
                vec![AccountMeta::new(auth, true), AccountMeta::new(self.slab, false)],
            );
            let o = self.send(vec![ix], &[auth], &[]);
            if o.0.is_err() {
                show(&format!("{} PushAuthMark {target} @ {slot}", self.label), &o);
                panic!("{}: PushAuthMark failed: {:?}", self.label, o.0);
            }
            // Keep the asset accrual current (each crank accrues <= 100 slots).
            let first = crank.first().copied().unwrap_or(self.live_portfolios[0]);
            for _ in 0..4 {
                let _ = self.crank(first);
                let (_, g) = self.market();
                if g.assets[ASSET as usize].slot_last == g.current_slot {
                    break;
                }
            }
            for p in crank {
                let o = self.crank(*p);
                if o.0.is_err() && custom_code(&o) != Some(22) {
                    show(&format!("{} crank {p}", self.label), &o);
                }
            }
            if self.price() == target {
                eprintln!("[{}] mark reached {target} at slot {slot}", self.label);
                return;
            }
            if self.price() == before {
                step = (step * 2).min(100);
            }
        }
        panic!("{}: price never reached {target} (at {})", self.label, self.price());
    }

    /// Trade `taker` against a LIVE matcher LP through that LP's own matcher config (the P1
    /// replay path), for the deployed-bytes negative controls.
    fn trade_live_lp(&mut self, taker: &Pubkey, lp: &Pubkey, size_q: i128) -> Outcome {
        let ld = self.data(lp);
        let mcfg = state::read_portfolio_matcher_config(&ld).unwrap();
        let v = VaultLp {
            portfolio: *lp,
            ctx: Pubkey::new_from_array(mcfg.matcher_context),
            delegate: Pubkey::new_from_array(mcfg.matcher_delegate),
        };
        assert_eq!(Pubkey::new_from_array(mcfg.matcher_program), MATCHER_ID);
        self.trade(taker, &v, size_q)
    }

    fn spl_conserved(&self, what: &str) {
        let (_, g) = self.market();
        assert_eq!(self.tok(&self.vault_token) as u128, g.vault, "[{}] {what}: SPL vault != header.vault", self.label);
    }
}

/// Largest whole-unit size whose notional (`units · price_e6` atoms) is `bps` of `atoms`.
fn units_for(atoms: u128, price_e6: u64, bps: u128) -> i128 {
    ((atoms * bps / 10_000) / price_e6 as u128) as i128 * unit()
}

fn creator_of(e: &Env) -> Pubkey {
    Pubkey::new_from_array(state::read_asset_oracle_profile(&e.data(&e.slab), ASSET as usize).unwrap().asset_admin)
}

// ── Shape: ANSEM ────────────────────────────────────────────────────────────

/// ANSEM (5bVTTM…) live shape: the creator (asset_admin DwgobU…) trades against liquidity
/// it controls. Under P3, the counterparty is the vault LP. A creator-owned second wallet
/// (a NEW portfolio owned by the LIVE creator key DwgobU…) goes long against it, the mark
/// rises 10%, and the wallet closes with a profit. Asserted: the profit is paid EXACTLY by
/// the vault LP's (junior) equity, and every senior-side observable is unchanged (C, the
/// ledger NAV, and the own/sibling bucket consumed/impaired liens).
///
/// Negative control (non-vacuity), same live state: the protocol raises the vault LP's
/// leverage to 5x (tag 99). The junior shrinks to 5,000,000 and the move is +40%, so the
/// LP's loss exceeds the junior. The "win paid by the junior, seniors untouched" invariant
/// must then NOT hold as a whole, i.e. the assertion can fail.
#[test]
fn p3_fork_ansem_creator_win_is_paid_by_the_junior() {
    let fx = load_fixture("ansem");
    let mut e = env(&fx, Bytes::Candidate);
    let Some(b) = bind(&mut e, 0) else { return; };
    let creator = creator_of(&e);
    assert_eq!(creator, pk("DwgobUX12AvegxPWGerEucV7222TpBFjzPK5FmePspfs"));
    let px0 = e.price();
    let size = units_for(b.junior as u128, px0, 5_000); // 0.5x the junior
    // A wallet PROVABLY owned by the creator is refused by P1's same-owner / asset_admin
    // guard even against the vault LP (67, before the matcher runs).
    let owned = e.new_trader(creator, 100_000_000);
    assert_eq!(e.owner(&owned), creator);
    let o = e.trade(&owned, &b.lp, size);
    expect_code(&o, 67, "ANSEM creator-owned wallet vs the vault LP");
    // So the realistic attack is a Sybil wallet (a fresh key the chain cannot link to the
    // creator). That is what the rest of this test exercises.
    let w2 = e.new_trader(Pubkey::new_unique(), 100_000_000);
    let o = e.trade(&w2, &b.lp, size);
    expect_ok(&o, "ANSEM creator Sybil wallet opens long vs the vault LP");
    let s0 = e.senior_side();
    let lp0 = e.equity(&b.lp.portfolio);
    let w0 = e.equity(&w2);
    let target = px0 + px0 / 10;
    e.move_price(target, &[b.lp.portfolio, w2]);
    let o = e.trade(&w2, &b.lp, -size);
    expect_ok(&o, "ANSEM creator Sybil wallet closes");
    for _ in 0..3 {
        let s = e.svm.get_sysvar::<Clock>().slot + 1;
        e.svm.warp_to_slot(s);
        let _ = e.crank(b.lp.portfolio);
        let _ = e.crank(w2);
    }
    let s1 = e.senior_side();
    let gain = e.equity(&w2) - w0;
    let lp_loss = lp0 - e.equity(&b.lp.portfolio);
    eprintln!(
        "[ansem] size {} units @ {px0}->{target}: creator wallet-2 gain {gain}, vault-LP loss {lp_loss}; senior side {s0:?} -> {s1:?}",
        size / unit()
    );
    assert!(gain > 0, "the creator's second wallet won");
    // The winner also pays the closing trade fee (base bps on the close notional, rounded
    // up). That fee goes to the fee legs, not to the vault LP. So the vault LP's loss equals
    // the winner's gross win: its net gain plus that fee.
    let (cfg, _) = e.market();
    let close_fee =
        ((size / unit()) as u128 * e.price() as u128 * cfg.trade_fee_base_bps as u128).div_ceil(10_000) as i128;
    eprintln!("[ansem] close fee {close_fee} ({} bps)", cfg.trade_fee_base_bps);
    assert_eq!(lp_loss, gain + close_fee, "the gross win is paid exactly by the vault LP (junior)");
    assert!(s1.no_harm_since(&s0), "no senior harm: {s0:?} -> {s1:?}");
    eprintln!(
        "[ansem] recovery on pre-existing receivables: own {} sib {} (num, /1e12 = atoms)",
        s0.own_consumed - s1.own_consumed,
        s0.sib_consumed - s1.sib_consumed
    );
    assert_eq!(e.pos(&w2), 0);
    assert_eq!(e.pos(&b.lp.portfolio), 0);
    e.spl_conserved("ANSEM");

    // ── negative control ──
    let mut n = env(&fx, Bytes::Candidate);
    n.label = "ansem/Candidate/NC-5x-thin-junior".into();
    n.apply_live_repairs();
    let o = n.earn_deposit(EARN_SEED, None);
    expect_ok(&o, "NC seed");
    let (vlp, o) = n.init_vault_lp(2_000);
    expect_ok(&o, "NC tag94 (+ auto-pin)");
    let lp = vlp.portfolio;
    expect_ok(&n.set_vault_lp_risk(50_000), "NC tag99 5x (protocol adjustment)");
    let thin: u64 = 5_000_000;
    expect_ok(&n.junior_deposit(lp, thin), "NC tag96");
    let nsize = units_for(thin as u128, px0, 45_000); // 4.5x the thin junior
    let w = n.new_trader(Pubkey::new_unique(), 100_000_000);
    expect_ok(&n.trade(&w, &vlp, nsize), "NC open");
    let ns0 = n.senior_side();
    let nlp0 = n.equity(&vlp.portfolio);
    let nw0 = n.equity(&w);
    n.move_price(px0 + px0 * 4 / 10, &[vlp.portfolio, w]);
    let close = n.trade(&w, &vlp, -nsize);
    for _ in 0..3 {
        let s = n.svm.get_sysvar::<Clock>().slot + 1;
        n.svm.warp_to_slot(s);
        let _ = n.crank(vlp.portfolio);
        let _ = n.crank(w);
    }
    let ns1 = n.senior_side();
    let ngain = n.equity(&w) - nw0;
    let nloss = nlp0 - n.equity(&vlp.portfolio);
    eprintln!(
        "[ansem NC] close {:?}; gain {ngain}, vault-LP loss {nloss} (junior {thin}); vault LP equity after {}; senior side {ns0:?} -> {ns1:?}",
        close.0,
        n.equity(&vlp.portfolio)
    );
    let (ncfg, _) = n.market();
    let nfee =
        ((nsize / unit()) as u128 * n.price() as u128 * ncfg.trade_fee_base_bps as u128).div_ceil(10_000) as i128;
    let invariant_holds = close.0.is_ok() && ngain > 0 && nloss == ngain + nfee && ns1.no_harm_since(&ns0);
    assert!(
        !invariant_holds,
        "NC: with the junior exhausted the junior-pays/seniors-untouched invariant must be falsifiable"
    );
}

// ── Shape: COLLECT / Murphy (zero-capital LP drain) ─────────────────────────

/// COLLECT (3t67LQ…) and Murphy (7h3wNx…) live shape: the market's matcher LP was drained
/// to zero capital, and then every open failed deep in the engine with InsufficientIM (49)
/// or the lien lock. P1 pins that on the deployed bytes against the LIVE LP. Under P3, on
/// the same live state:
/// 1. a winner opens against the vault LP at 0.9x of the junior;
/// 2. the mark rises 50%, which drains the junior;
/// 3. a LATE risk-increasing open is refused with 80 (VaultLpExposureCapExceeded), before
///    any 49;
/// 4. the winner's close still works;
/// 5. nothing on the senior side moves.
///
/// Negative controls:
/// * cap raised to 5x (tag 99): the same late open is NOT refused with 80;
/// * deployed v18.2 bytes, same live state: a distinct taker against the LIVE zero-capital
///   LP fails with 49 (the live failure).
fn replay_drain(name: &str, live_lp: &str, live_taker: &str) {
    let fx = load_fixture(name);
    // Deployed negative control: the live failure.
    let mut d = env(&fx, Bytes::Deployed);
    d.apply_live_repairs();
    let o = d.trade_live_lp(&pk(live_taker), &pk(live_lp), unit());
    expect_code(&o, E_INSUFFICIENT_IM, &format!("{} live LP grow (the live failure)", d.label));

    for cap_bps in [0u32, 50_000] {
        let mut e = env(&fx, Bytes::Candidate);
        e.label = format!("{name}/Candidate/cap={cap_bps}");
        let Some(b) = bind(&mut e, cap_bps) else { return; };
        let px0 = e.price();
        let size = units_for(b.junior as u128, px0, 9_000);
        let winner = e.new_trader(Pubkey::new_unique(), 1_000_000_000);
        let o = e.trade(&winner, &b.lp, size);
        expect_ok(&o, &format!("{} winner opens 0.9x", e.label));
        let s0 = e.senior_side();
        let lp_eq0 = e.equity(&b.lp.portfolio);
        e.move_price(px0 + px0 / 2, &[b.lp.portfolio, winner]);
        let lp_eq1 = e.equity(&b.lp.portfolio);
        eprintln!(
            "[{}] size {} units; mark {px0}->{}: vault-LP stored equity {lp_eq0} -> {lp_eq1} (unsettled until touched; junior {})",
            e.label,
            size / unit(),
            e.price(),
            b.junior
        );
        let late = e.new_trader(Pubkey::new_unique(), 1_000_000_000);
        let late_size = size / 5;
        let r = e.trade(&late, &b.lp, late_size);
        if cap_bps == 0 {
            expect_code(&r, E_VAULT_LP_EXPOSURE_CAP, &format!("{} late crowd-growing open", e.label));
        } else {
            assert_ne!(custom_code(&r), Some(E_VAULT_LP_EXPOSURE_CAP), "NC {}: cap raised, 80 must not fire", e.label);
            eprintln!("[{}] NC late open with cap raised -> {:?}", e.label, r.0);
            continue;
        }
        let o = e.trade(&winner, &b.lp, -size);
        expect_ok(&o, &format!("{} winner closes", e.label));
        let s1 = e.senior_side();
        eprintln!("[{}] senior side {s0:?} -> {s1:?}; winner equity {}", e.label, e.equity(&winner));
        let lp_eq2 = e.equity(&b.lp.portfolio);
        eprintln!("[{}] vault-LP equity after the winner's close: {lp_eq2} (was {lp_eq0})", e.label);
        assert!(lp_eq2 < lp_eq0, "{}: the junior was drained by the winner", e.label);
        assert!(s1.no_harm_since(&s0), "{}: no senior harm from the drain: {s0:?} -> {s1:?}", e.label);
        eprintln!(
            "[{}] recovery on pre-existing receivables: own {} sib {} (num; /1e12 = atoms); vault-LP loss {}",
            e.label,
            s0.own_consumed - s1.own_consumed,
            s0.sib_consumed - s1.sib_consumed,
            lp_eq0 - lp_eq2
        );
        assert_eq!(e.pos(&b.lp.portfolio), 0);
        e.spl_conserved("drain");
    }
}

#[test]
fn p3_fork_collect_drain_refused_with_80_not_49() {
    replay_drain(
        "collect",
        "E5nysmJfBN93vptj1bvBSihDL5pc39vHjPfPg5vVMyTE",
        "GGMfwKxJDokS1ukbyTdZcidv5zAY6nW5H7csfyY3qJ1E",
    );
}

#[test]
fn p3_fork_murphy_drain_refused_with_80_not_49() {
    replay_drain(
        "murphy",
        "EXgiHLfxf1t2v2nzr6Ym3Db8fp4BzZx8XLWdbvqY4Bms",
        "9noH7PkT7uKuZGTSjBopKt4gMx7CnbydNQz2ZmVf3AwH",
    );
}

// ── Shape: TEXTIT ───────────────────────────────────────────────────────────

/// TEXTIT (DnFhDd…) live state: the short side was ResetPending, and the live LP had zero
/// capital (P1 finding: the ledger's "empty domain 1" shape is no longer live). Under P3,
/// after the permissionless repairs, the following all land on the same live state:
/// * a short opens against the vault LP, which goes long;
/// * a long opens against it;
/// * the mark moves 5%;
/// * both close.
///
/// SPL is conserved throughout.
///
/// Negative control: on the deployed bytes, the same short open against the LIVE LP fails
/// with 49.
#[test]
fn p3_fork_textit_both_sides_open_and_close() {
    let fx = load_fixture("textit");
    let mut d = env(&fx, Bytes::Deployed);
    d.apply_live_repairs();
    let o = d.trade_live_lp(
        &pk("7xmwLShWzrUqqgQ7vtLupJDL9npmBjnd566jwximzrvV"),
        &pk("5oYeGqkwRJTawiYN1Tszsg773BUKpNLgEpSE8h6jDQbe"),
        -unit(),
    );
    expect_code(&o, E_INSUFFICIENT_IM, "TEXTIT deployed live-LP short (the live failure)");

    let mut e = env(&fx, Bytes::Candidate);
    let Some(b) = bind(&mut e, 0) else { return; };
    let px0 = e.price();
    let s_size = units_for(b.junior as u128, px0, 5_000);
    let l_size = units_for(b.junior as u128, px0, 3_000);
    let short = e.new_trader(Pubkey::new_unique(), 1_000_000_000);
    let long = e.new_trader(Pubkey::new_unique(), 1_000_000_000);
    expect_ok(&e.trade(&short, &b.lp, -s_size), "TEXTIT short opens vs vault LP");
    expect_ok(&e.trade(&long, &b.lp, l_size), "TEXTIT long opens vs vault LP");
    assert_eq!(e.pos(&b.lp.portfolio), s_size - l_size, "vault LP nets the two");
    e.move_price(px0 + px0 / 20, &[b.lp.portfolio, short, long]);
    expect_ok(&e.trade(&short, &b.lp, s_size), "TEXTIT short closes");
    expect_ok(&e.trade(&long, &b.lp, -l_size), "TEXTIT long closes");
    assert_eq!(e.pos(&b.lp.portfolio), 0);
    eprintln!(
        "[textit] short {} / long {} units @ {px0}->{}; equities short {} long {} vault-LP {}",
        s_size / unit(),
        l_size / unit(),
        e.price(),
        e.equity(&short),
        e.equity(&long),
        e.equity(&b.lp.portfolio)
    );
    e.spl_conserved("TEXTIT");
}
