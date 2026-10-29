// Skip this integration-test binary when Kani builds the test suite.
#![cfg(not(kani))]
//! v2.2 growth round 2, R2.1 item 4: the ON-CHAIN DEX depth source (tag 123 `SetDepthSource`,
//! PDA kind 16 `["depth_src", market]`, PushAuthMark depth mode 2, error 129).
//!
//! Part A — fixture parse tests on REAL mainnet account bytes (`tests/fixtures/depth_src/`,
//! fetched read-only with `solana account <pk> -u mainnet-beta --output json` on 2026-10-14,
//! mainnet slot ~456,832,460; one `getAccountInfo` per account, so balances of different
//! accounts are not from one atomic snapshot):
//! * PumpSwap AMM `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA`: CHILLHOUSE pool
//!   `35TqQMeiRwEbK6FR5qiPwastuAAvo32VjnULJpxVSxUK` (SPL Token, WSOL quote) and swordcat pool
//!   `8ewuF2o8ACro7fqWepZ3tKhkbBjndZU4Ldk9scRPw83d` (Token-2022 coin + base vault).
//! * Raydium CPMM `CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C`: WSOL/USELESS
//!   `Q2sPHPdUWFMg7M7wwrQKLrn619cAucfRsmhVJffodSp` (the asset is side 1) and NEAR/USDC
//!   `gyYigqG8vdEMkDNTTVL6at2msbHdTDWyb6bccyR238U` (USDC quote: the quote-is-collateral path).
//!
//! Part B — full-width proptests of the depth math against an independent 256-bit reference,
//! the valuation, the pin check (every single-field mutation refuses) and the mode decode.
//!
//! Part C — LiteSVM on the REAL wrapper BPF (`target/deploy/percolator_prog.so`, `--features
//! devnet`) with the fixture accounts loaded: SetDepthSource happy path + every refusal, mode-2
//! pushes (source 2 stored), forged pools, missing PDA, cleared pin, and the 35 B / mode-1 forms
//! unchanged afterwards. Every refusal carries its accepted control.
use litesvm::LiteSVM;
use percolator_prog::{
    depth_src_v22 as ds,
    error::PercolatorError,
    growth_v19,
    ix::{InitMarketPhase4, Instruction as ProgInstruction},
    state,
};
use proptest::prelude::*;
use solana_sdk::{
    account::Account,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::path::PathBuf;
use std::str::FromStr;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────────────────────

const CHILL_POOL: &str = "35TqQMeiRwEbK6FR5qiPwastuAAvo32VjnULJpxVSxUK";
const CHILL_BASE_VAULT: &str = "3QYT2XGvYdEvE77CfQxefYdczPqEh3N9Nzjj2iZa7Y3s";
const CHILL_QUOTE_VAULT: &str = "HcjVRqzrZnBZ2nSZcqqo88A37BPAMXo2cGLSNWDFgSkV";
const CHILL_MINT: &str = "GkyPYa7NnCFbduLknCfBfP7p8564X1VZhwZYJ6CZpump";
const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";
const SWORD_POOL: &str = "8ewuF2o8ACro7fqWepZ3tKhkbBjndZU4Ldk9scRPw83d";
const SWORD_BASE_VAULT: &str = "7ZYdwpNFTwnyNruJXxiMkjELBm5PTacRSaVgymrmVQaJ";
const SWORD_QUOTE_VAULT: &str = "DGp73iXvD9iTPDSUQUfXdLhL979csERXDcVDi23NxCW";
const SWORD_MINT: &str = "5tCju6YNxHq5zrA6tGndr6F7TK42mpUFmeE31cSFpump";
const USELESS_POOL: &str = "Q2sPHPdUWFMg7M7wwrQKLrn619cAucfRsmhVJffodSp";
const USELESS_VAULT0: &str = "HgNPDD8bpbSrGyHegiCT5xrYxHTfwLfZydwGkjNCJRKA";
const USELESS_VAULT1: &str = "9xsCiNwYQXM3ZeHFSVj9JQdP1vREJREpN23f6wvxA1ty";
const USELESS_MINT: &str = "Dz9mQ9NzkBcCsuGPFJ3r1bS4wgqKMHBPiVuniW8Mbonk";
const NEAR_POOL: &str = "gyYigqG8vdEMkDNTTVL6at2msbHdTDWyb6bccyR238U";
const NEAR_VAULT0: &str = "HjwLQwmWDxPEHPH4jTVpDb174vPHcGVaB332qiG2FLva";
const NEAR_VAULT1: &str = "DXcM4a7GwdK3Epi9uNiPhAurn33igYR2FScyPjrxudf9";
const NEAR_MINT: &str = "3ZLekZYq2qkZiSpnSvabjit34tUkjSwD1JFuW9as9wBG";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

fn pk(s: &str) -> Pubkey {
    Pubkey::from_str(s).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = A.iter().position(|x| *x == c).expect("base64") as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

/// A fixture account (`<role>__<pubkey>.json`, the `solana account --output json` output).
fn fixture(key: &str) -> Account {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/depth_src");
    let path = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_str().unwrap().ends_with(&format!("__{key}.json")))
        .unwrap_or_else(|| panic!("no fixture for {key}"));
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(v["pubkey"].as_str().unwrap(), key);
    let a = &v["account"];
    assert_eq!(a["data"][1].as_str().unwrap(), "base64");
    Account {
        lamports: a["lamports"].as_u64().unwrap(),
        data: b64(a["data"][0].as_str().unwrap()),
        owner: pk(a["owner"].as_str().unwrap()),
        executable: false,
        rent_epoch: 0,
    }
}

fn tok(key: &str) -> ds::TokenAcct {
    let a = fixture(key);
    ds::parse_token_account(&a.owner.to_bytes(), &a.data).expect("token account")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Part A: real mainnet bytes
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The allow-list ids are the owners of the real pools; nothing else is accepted.
#[test]
fn a_allow_list_matches_real_owners() {
    assert_eq!(fixture(CHILL_POOL).owner, ds::PUMPSWAP_AMM_PROGRAM_ID);
    assert_eq!(fixture(SWORD_POOL).owner, ds::PUMPSWAP_AMM_PROGRAM_ID);
    assert_eq!(fixture(USELESS_POOL).owner, ds::RAYDIUM_CPMM_PROGRAM_ID);
    assert_eq!(fixture(NEAR_POOL).owner, ds::RAYDIUM_CPMM_PROGRAM_ID);
    assert_eq!(ds::amm_kind_for_program(&ds::PUMPSWAP_AMM_PROGRAM_ID.to_bytes()), Some(ds::AMM_PUMPSWAP));
    assert_eq!(ds::amm_kind_for_program(&ds::RAYDIUM_CPMM_PROGRAM_ID.to_bytes()), Some(ds::AMM_RAYDIUM_CPMM));
    // devnet CPMM: only in a devnet build (this test binary links the host lib without features).
    assert_eq!(
        ds::amm_kind_for_program(&ds::RAYDIUM_CPMM_DEVNET_PROGRAM_ID.to_bytes()),
        if cfg!(feature = "devnet") { Some(ds::AMM_RAYDIUM_CPMM) } else { None }
    );
    for other in [spl_token::ID, Pubkey::new_from_array([0xAB; 32]), pk("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8")] {
        assert_eq!(ds::amm_kind_for_program(&other.to_bytes()), None, "{other}");
    }
}

/// PumpSwap `Pool`: discriminator, mints and vault keys at the verified offsets (43 / 75 /
/// 139 / 171), the vault accounts belong to those mints, and the trading reserves. CHILLHOUSE's
/// quote side: vault 1,770,174,112,124 lamports, `virtual_quote_reserves` = -1,797 (fees kept in
/// the vault: protocol 62 + creator 1,735), so effective == real == 1,770,174,110,327.
#[test]
fn a_pumpswap_chillhouse_layout_and_reserves() {
    let pool = fixture(CHILL_POOL);
    assert_eq!(pool.data.len(), 301);
    assert_eq!(pool.data[..8], ds::PUMPSWAP_POOL_DISC);
    let s = ds::parse_pool(ds::AMM_PUMPSWAP, &pool.data).unwrap();
    assert_eq!(s.mint, [pk(CHILL_MINT).to_bytes(), pk(WSOL_MINT).to_bytes()]);
    assert_eq!(s.vault, [pk(CHILL_BASE_VAULT).to_bytes(), pk(CHILL_QUOTE_VAULT).to_bytes()]);
    assert_eq!(s.token_program, [None, None]);
    let (bv, qv) = (tok(CHILL_BASE_VAULT), tok(CHILL_QUOTE_VAULT));
    assert_eq!((bv.mint, qv.mint), (s.mint[0], s.mint[1]));
    assert_eq!((bv.amount, qv.amount), (171_449_177_380_421, 1_770_174_112_124));
    let vq = i128::from_le_bytes(pool.data[245..261].try_into().unwrap());
    let pf = u64::from_le_bytes(pool.data[271..279].try_into().unwrap());
    let cf = u64::from_le_bytes(pool.data[279..287].try_into().unwrap());
    assert_eq!((vq, pf, cf), (-1_797, 62, 1_735));
    let r = ds::pool_reserves(ds::AMM_PUMPSWAP, &pool.data, [bv.amount, qv.amount]).unwrap();
    assert_eq!(r, [171_449_177_380_421, 1_770_174_110_327]);
    // mints: CHILLHOUSE 6 decimals, WSOL 9 (SPL Token, 82 B)
    let (cm, wm) = (fixture(CHILL_MINT), fixture(WSOL_MINT));
    assert_eq!(ds::parse_mint(&cm.owner.to_bytes(), &cm.data), Some(6));
    assert_eq!(ds::parse_mint(&wm.owner.to_bytes(), &wm.data), Some(9));
    // Implied pool price: 1,770.17 SOL / 171.45M CHILLHOUSE = 1.0325e-5 SOL (~ $0.0012 at ~$116).
    let price_sol_e12 = r[1] as u128 * 1_000_000_000_000 * 1_000_000 / (r[0] as u128 * 1_000_000_000);
    assert_eq!(price_sol_e12, 10_324_774);
}

/// PumpSwap with a Token-2022 coin (swordcat): the base vault is a 170 B Token-2022 account
/// (`AccountType::Account` + ImmutableOwner), the mint a 431 B Token-2022 mint with only
/// MetadataPointer (18) + TokenMetadata (19), decimals 6.
#[test]
fn a_pumpswap_swordcat_token2022() {
    let pool = fixture(SWORD_POOL);
    let s = ds::parse_pool(ds::AMM_PUMPSWAP, &pool.data).unwrap();
    assert_eq!(s.mint, [pk(SWORD_MINT).to_bytes(), pk(WSOL_MINT).to_bytes()]);
    assert_eq!(s.vault, [pk(SWORD_BASE_VAULT).to_bytes(), pk(SWORD_QUOTE_VAULT).to_bytes()]);
    let bva = fixture(SWORD_BASE_VAULT);
    assert_eq!((bva.owner, bva.data.len(), bva.data[165]), (ds::TOKEN_2022_PROGRAM_ID, 170, 2));
    let bv = tok(SWORD_BASE_VAULT);
    assert_eq!((bv.mint, bv.amount), (s.mint[0], 35_107_081_881_503));
    let m = fixture(SWORD_MINT);
    assert_eq!((m.owner, m.data.len()), (ds::TOKEN_2022_PROGRAM_ID, 431));
    assert_eq!(ds::parse_mint(&m.owner.to_bytes(), &m.data), Some(6));
    // NEGATIVE CONTROL: the same mint with its first extension retyped to TransferFeeConfig (1)
    // or PermanentDelegate (12) is refused; a non-zero byte in the 82..165 padding is refused.
    for t in [1u16, 12, 14, 26] {
        let mut d = m.data.clone();
        d[166..168].copy_from_slice(&t.to_le_bytes());
        assert_eq!(ds::parse_mint(&m.owner.to_bytes(), &d), None, "ext {t}");
    }
    let mut d = m.data.clone();
    d[100] = 1;
    assert_eq!(ds::parse_mint(&m.owner.to_bytes(), &d), None);
    // the same bytes owned by SPL Token (an extended mint is Token-2022 only)
    assert_eq!(ds::parse_mint(&spl_token::ID.to_bytes(), &m.data), None);
    assert_eq!(ds::parse_token_account(&spl_token::ID.to_bytes(), &bva.data), None);
}

/// Raydium CPMM `PoolState` (637 B, packed): vaults at 72/104, mints at 168/200, token programs
/// at 232/264, status at 329, fee counters at 341..373 and 397..413; reserves = vault - fees.
#[test]
fn a_raydium_cpmm_layout_and_reserves() {
    let pool = fixture(USELESS_POOL);
    assert_eq!((pool.data.len(), &pool.data[..8]), (637, &ds::RAYDIUM_POOL_DISC[..]));
    let s = ds::parse_pool(ds::AMM_RAYDIUM_CPMM, &pool.data).unwrap();
    assert_eq!(s.mint, [pk(WSOL_MINT).to_bytes(), pk(USELESS_MINT).to_bytes()]);
    assert_eq!(s.vault, [pk(USELESS_VAULT0).to_bytes(), pk(USELESS_VAULT1).to_bytes()]);
    assert_eq!(s.token_program, [Some(spl_token::ID.to_bytes()), Some(spl_token::ID.to_bytes())]);
    let (v0, v1) = (tok(USELESS_VAULT0), tok(USELESS_VAULT1));
    assert_eq!((v0.amount, v1.amount), (20_289_655_263_781, 12_467_112_346_546));
    let r = ds::pool_reserves(ds::AMM_RAYDIUM_CPMM, &pool.data, [v0.amount, v1.amount]).unwrap();
    // protocol 9,902,635 + fund 8,598,177 (side 0); 426,251 + 2,928,986 (side 1); creator 0
    assert_eq!(r, [20_289_636_762_969, 12_467_108_991_309]);
    // the asset (USELESS) is side 1
    assert_eq!(
        ds::orientation(&s, &v1_key(), &v0_key(), &pk(USELESS_MINT).to_bytes(), &pk(WSOL_MINT).to_bytes()),
        Some(ds::DEPTH_SRC_FLAG_BASE_IS_SIDE1)
    );
    // NEAR/USDC: USDC (6 decimals) is side 1, the quote
    let near = fixture(NEAR_POOL);
    let s = ds::parse_pool(ds::AMM_RAYDIUM_CPMM, &near.data).unwrap();
    assert_eq!(s.mint, [pk(NEAR_MINT).to_bytes(), pk(USDC_MINT).to_bytes()]);
    let (n0, n1) = (tok(NEAR_VAULT0), tok(NEAR_VAULT1));
    let r = ds::pool_reserves(ds::AMM_RAYDIUM_CPMM, &near.data, [n0.amount, n1.amount]).unwrap();
    assert_eq!(r, [269_144_043_864_280, 1_377_211_761_778]);
    let um = fixture(USDC_MINT);
    assert_eq!(ds::parse_mint(&um.owner.to_bytes(), &um.data), Some(6));
    // NEGATIVE CONTROLS: swaps disabled (status bit 2) refuses; a fee counter above the vault
    // balance refuses; a 1-byte-short pool, a wrong discriminator, and a PumpSwap parse of a
    // Raydium pool all refuse.
    let mut d = near.data.clone();
    d[329] |= 1 << 2;
    assert_eq!(ds::pool_reserves(ds::AMM_RAYDIUM_CPMM, &d, [n0.amount, n1.amount]), None);
    d[329] = 1 << 0; // deposits disabled only: still a trading pool
    assert!(ds::pool_reserves(ds::AMM_RAYDIUM_CPMM, &d, [n0.amount, n1.amount]).is_some());
    let mut d = near.data.clone();
    d[397..405].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(ds::pool_reserves(ds::AMM_RAYDIUM_CPMM, &d, [n0.amount, n1.amount]), None);
    assert_eq!(ds::parse_pool(ds::AMM_RAYDIUM_CPMM, &near.data[..636]), None);
    let mut d = near.data.clone();
    d[0] ^= 1;
    assert_eq!(ds::parse_pool(ds::AMM_RAYDIUM_CPMM, &d), None);
    assert_eq!(ds::parse_pool(ds::AMM_PUMPSWAP, &near.data), None);
    assert_eq!(ds::parse_pool(ds::AMM_RAYDIUM_CPMM, &fixture(CHILL_POOL).data), None);
    assert_eq!(ds::parse_pool(9, &near.data), None);
}

fn v0_key() -> [u8; 32] {
    pk(USELESS_VAULT0).to_bytes()
}
fn v1_key() -> [u8; 32] {
    pk(USELESS_VAULT1).to_bytes()
}

/// PumpSwap quote side: fees waiting in the vault are not liquidity, a boost is not real tokens
/// (`min(effective, real)`), a negative effective reserve and an underflow refuse; a pool shorter
/// than the appended fields reads them as 0.
#[test]
fn a_pumpswap_quote_side_rules() {
    let pool = fixture(CHILL_POOL).data;
    let set_vq = |d: &mut Vec<u8>, v: i128| d[245..261].copy_from_slice(&v.to_le_bytes());
    let mut d = pool.clone();
    set_vq(&mut d, 5_000); // a boost: effective = vault + 5,000 > real
    assert_eq!(ds::pool_reserves(ds::AMM_PUMPSWAP, &d, [1, 1_000_000]).unwrap()[1], 1_000_000 - 62 - 1_735);
    set_vq(&mut d, -2_000_000); // effective < 0
    assert_eq!(ds::pool_reserves(ds::AMM_PUMPSWAP, &d, [1, 1_000_000]), None);
    let mut d = pool.clone();
    d[279..287].copy_from_slice(&2_000_000u64.to_le_bytes()); // creator fees above the vault
    assert_eq!(ds::pool_reserves(ds::AMM_PUMPSWAP, &d, [1, 1_000_000]), None);
    // a pre-upgrade pool (243 B: no virtual reserves, no fee counters): quote = the raw vault
    assert_eq!(ds::pool_reserves(ds::AMM_PUMPSWAP, &pool[..243], [7, 1_000_000]), Some([7, 1_000_000]));
    assert!(ds::parse_pool(ds::AMM_PUMPSWAP, &pool[..243]).is_some());
    assert_eq!(ds::parse_pool(ds::AMM_PUMPSWAP, &pool[..ds::PUMPSWAP_POOL_MIN_LEN - 1]), None);
}

/// Token accounts: frozen / uninitialized refused; an SPL Token account must be exactly 165 B.
#[test]
fn a_token_account_rules() {
    let a = fixture(CHILL_BASE_VAULT);
    let o = a.owner.to_bytes();
    assert!(ds::parse_token_account(&o, &a.data).is_some());
    for st in [0u8, 2] {
        let mut d = a.data.clone();
        d[108] = st;
        assert_eq!(ds::parse_token_account(&o, &d), None, "state {st}");
    }
    let mut d = a.data.clone();
    d.push(2);
    assert_eq!(ds::parse_token_account(&o, &d), None, "SPL Token: exactly 165 B");
    assert_eq!(ds::parse_token_account(&[0xAB; 32], &a.data), None, "not a token program");
    assert_eq!(ds::parse_token_account(&o, &a.data[..164]), None);
}

/// Collateral valuation with real numbers. CHILLHOUSE ~ $0.0012 per token, lot_exp 4: a lot is
/// 10^4 tokens ~ $12 -> per-lot mark 12,000,000 e6. Base reserve 171,449,177.380421 tokens:
/// value = 171,449,177,380,421 * 12,000,000 / 10^(6 + 4) = 205,739,012,856 ($205,739.01);
/// depth = 2,027,034,782 ($2,027.03) -> TIER 0 (tier 1 needs $25,000 of +-2% depth, i.e. a
/// ~$2.54M reserve per side). NEAR/USDC (quote = collateral): 1,377,211,761,778 -> depth
/// 13,568,919,694 ($13,568.92), also tier 0.
#[test]
fn a_valuation_real_numbers() {
    let v = ds::reserve_value_e6(ds::ValuePath::BaseAtMark, 171_449_177_380_421, 1_770_174_110_327, 12_000_000, 6, 4).unwrap();
    assert_eq!(v, 205_739_012_856);
    assert_eq!(ds::plus2pct_depth_e6(v), 2_027_034_782);
    assert_eq!(growth_v19::venue_tier(2_027_034_782, growth_v19::DEPTH_SOURCE_DEX, growth_v19::tier_thresholds([0; 3], 6), 0), 0);
    let v = ds::reserve_value_e6(ds::ValuePath::QuoteIsCollateral, 269_144_043_864_280, 1_377_211_761_778, 0, 9, 0).unwrap();
    assert_eq!(ds::plus2pct_depth_e6(v), 13_568_919_694);
    // The same CHILLHOUSE reserve at lot_exp 0 (a per-TOKEN mark of 1,200 e6) gives the same value.
    assert_eq!(ds::reserve_value_e6(ds::ValuePath::BaseAtMark, 171_449_177_380_421, 0, 1_200, 6, 0), Some(205_739_012_856));
    // What tier 1 would need: a reserve with depth >= $25k.
    let r1 = (1u64..).map(|k| k * 1_000_000_000).find(|r| ds::plus2pct_depth_e6(*r) >= growth_v19::DEPTH_TIER1_E6).unwrap();
    assert_eq!(r1, 2_538_000_000_000); // ~$2.538M of quote-side value
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Part B: properties
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// 256-bit `k * x` for a u128 `x` and a small `k` (< 2^64), as (hi, lo). Independent of the
/// program's `depth_pred` (which avoids 256-bit arithmetic by a different rearrangement).
fn mul_small(x: u128, k: u128) -> (u128, u128) {
    let a = (x & u64::MAX as u128) * k;
    let b = (x >> 64) * k;
    let (lo, c) = a.overflowing_add(b << 64);
    ((b >> 64) + u128::from(c), lo)
}

/// Reference predicate `51 m^2 >= 50 r^2` in 256 bits.
fn ref_pred(m: u64, r: u64) -> bool {
    mul_small(m as u128 * m as u128, 51) >= mul_small(r as u128 * r as u128, 50)
}

/// Reference depth: binary search for the smallest m in [0, r] with the predicate.
fn ref_depth(r: u64) -> u64 {
    let (mut lo, mut hi) = (0u64, r);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if ref_pred(mid, r) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    r - lo
}

fn sample_pin() -> ds::DepthSourceV22 {
    ds::DepthSourceV22 {
        market: [1; 32],
        amm_program: ds::RAYDIUM_CPMM_PROGRAM_ID.to_bytes(),
        pool: [2; 32],
        base_vault: [3; 32],
        quote_vault: [4; 32],
        base_mint: [5; 32],
        quote_mint: [6; 32],
        market_id: 9,
        set_slot: 0,
        asset_index: 0,
        base_decimals: 6,
        quote_decimals: 9,
        flags: ds::DEPTH_SRC_FLAG_ACTIVE | ds::DEPTH_SRC_FLAG_BASE_IS_SIDE1,
        version: ds::DEPTH_SOURCE_VERSION,
        bump: 255,
        amm_kind: ds::AMM_RAYDIUM_CPMM,
        _reserved: [0; 8],
    }
}

fn sample_view() -> ds::PushView {
    let tp = spl_token::ID.to_bytes();
    ds::PushView {
        market: [1; 32],
        asset_index: 0,
        market_id: 9,
        pool_key: [2; 32],
        pool_owner: ds::RAYDIUM_CPMM_PROGRAM_ID.to_bytes(),
        sides: ds::PoolSides { mint: [[6; 32], [5; 32]], vault: [[4; 32], [3; 32]], token_program: [Some(tp), Some(tp)] },
        base_vault_key: [3; 32],
        quote_vault_key: [4; 32],
        base_vault_program: tp,
        quote_vault_program: tp,
        base_vault: ds::TokenAcct { mint: [5; 32], amount: 1 },
        quote_vault: ds::TokenAcct { mint: [6; 32], amount: 1 },
    }
}

/// Every single-field corruption of the push view (one byte flipped in field `f`) refuses.
fn mutate_view(v: &mut ds::PushView, f: u8, byte: usize) {
    let b = byte % 32;
    match f % 17 {
        0 => v.market[b] ^= 1,
        1 => v.asset_index ^= 1,
        2 => v.market_id ^= 1,
        3 => v.pool_key[b] ^= 1,
        4 => v.pool_owner[b] ^= 1,
        5 => v.sides.mint[0][b] ^= 1,
        6 => v.sides.mint[1][b] ^= 1,
        7 => v.sides.vault[0][b] ^= 1,
        8 => v.sides.vault[1][b] ^= 1,
        9 => v.sides.token_program[0] = Some([0xAB; 32]),
        10 => v.sides.token_program[1] = Some([0xAB; 32]),
        11 => v.base_vault_key[b] ^= 1,
        12 => v.quote_vault_key[b] ^= 1,
        13 => v.base_vault_program[b] ^= 1,
        14 => v.quote_vault_program[b] ^= 1,
        15 => v.base_vault.mint[b] ^= 1,
        _ => v.quote_vault.mint[b] ^= 1,
    }
}

#[test]
fn b_reference_agrees_on_edges_and_keeper_vectors() {
    for r in [0u64, 1, 2, 50, 51, 100, 101, 102, 103, 1 << 32, (1 << 32) + 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        assert_eq!(ds::plus2pct_depth_e6(r), ref_depth(r), "R={r}");
    }
    for r in 0u64..20_000 {
        assert_eq!(ds::plus2pct_depth_e6(r), ref_depth(r), "R={r}");
    }
    assert_eq!(ds::plus2pct_depth_e6(1_000_000 * 1_000_000), 9_852_457_023);
    assert_eq!(ds::plus2pct_depth_e6(u64::MAX), 181_745_753_206_511_237);
    // NEGATIVE CONTROLS: a round-to-nearest mutant and an "m - 1" mutant differ from the floor.
    let mutant_nearest = |r: u64| ((r as f64) * (1.0 - 1.0 / 1.02f64.sqrt())).round() as u64;
    assert!((0u64..2_000).any(|r| mutant_nearest(r) != ds::plus2pct_depth_e6(r)));
    let mutant_m_minus_1 = |r: u64| if r == 0 { 0 } else { r - (r - ds::plus2pct_depth_e6(r)).saturating_sub(1) };
    assert!((1u64..200).any(|r| mutant_m_minus_1(r) != ref_depth(r)));
}

#[test]
fn b_pin_check_controls() {
    assert!(ds::validate_depth_source(&sample_pin()));
    assert!(ds::pin_matches(&sample_pin(), &sample_view()), "CONTROL: the matching view is accepted");
    let mut p = sample_pin();
    p.flags &= !ds::DEPTH_SRC_FLAG_ACTIVE;
    assert!(!ds::pin_matches(&p, &sample_view()), "an inactive pin refuses");
    let mut p = sample_pin();
    p.flags &= !ds::DEPTH_SRC_FLAG_BASE_IS_SIDE1;
    assert!(!ds::pin_matches(&p, &sample_view()), "the wrong orientation refuses");
    // A cleared record validates; any stray pin byte in a cleared record does not.
    let c = ds::DepthSourceV22::cleared([1; 32], 7);
    assert!(ds::validate_depth_source(&c));
    let mut c2 = c;
    c2.pool[0] = 1;
    assert!(!ds::validate_depth_source(&c2));
    // An active record whose program is off the allow-list / of another kind does not validate.
    let mut p = sample_pin();
    p.amm_kind = ds::AMM_PUMPSWAP;
    assert!(!ds::validate_depth_source(&p));
    let mut p = sample_pin();
    p.amm_program = [0xAB; 32];
    assert!(!ds::validate_depth_source(&p));
    let mut p = sample_pin();
    p.base_decimals = 19;
    assert!(!ds::validate_depth_source(&p));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    /// The program's depth equals the 256-bit reference over the FULL u64 range, is the exact
    /// floor (`51 m^2 >= 50 R^2` and `51 (m-1)^2 < 50 R^2`), never exceeds the true value, and
    /// is non-decreasing.
    #[test]
    fn b_depth_full_width(r in any::<u64>(), k in 0u64..1_000_000) {
        let d = ds::plus2pct_depth_e6(r);
        prop_assert_eq!(d, ref_depth(r));
        let m = r - d;
        prop_assert!(ref_pred(m, r));
        prop_assert!(m == 0 || !ref_pred(m - 1, r));
        prop_assert!((d as u128) * 1_000_000_000 <= (r as u128) * 9_852_457_024);
        let r2 = r.saturating_add(k);
        prop_assert!(ds::plus2pct_depth_e6(r2) >= d);
        prop_assert_eq!(ds::depth_pred(m, r), ref_pred(m, r));
        if m > 0 { prop_assert_eq!(ds::depth_pred(m - 1, r), ref_pred(m - 1, r)); }
    }

    /// `depth_pred` equals the 256-bit reference for every m <= r.
    #[test]
    fn b_depth_pred_full_width(r in any::<u64>(), m in any::<u64>()) {
        let m = if r == u64::MAX { m } else { m % (r + 1) };
        prop_assert_eq!(ds::depth_pred(m, r), ref_pred(m, r));
    }

    /// isqrt is the exact floor over the full u128 range.
    #[test]
    fn b_isqrt_full_width(n in any::<u128>()) {
        let x = ds::isqrt_u128(n);
        prop_assert!(x.checked_mul(x).is_some_and(|s| s <= n));
        prop_assert!((x + 1).checked_mul(x + 1).is_none_or(|s| s > n));
    }

    /// Valuation: the exact floor `base * mark / 10^(dec + lot)` capped at u64::MAX; the quote
    /// path is the quote reserve; bounds refuse.
    #[test]
    fn b_valuation(base in any::<u64>(), quote in any::<u64>(), mark in any::<u64>(), dec in 0u8..=20, lot in 0u8..=16) {
        let v = ds::reserve_value_e6(ds::ValuePath::BaseAtMark, base, quote, mark, dec, lot);
        if mark == 0 || dec > 18 || lot > 15 {
            prop_assert_eq!(v, None);
        } else {
            let exact = (base as u128) * (mark as u128) / 10u128.pow(dec as u32 + lot as u32);
            prop_assert_eq!(v, Some(exact.min(u64::MAX as u128) as u64));
        }
        prop_assert_eq!(ds::reserve_value_e6(ds::ValuePath::QuoteIsCollateral, base, quote, mark, dec, lot), Some(quote));
    }

    /// The pin check is all-or-nothing: any single corrupted field refuses.
    #[test]
    fn b_pin_check_every_single_field(f in any::<u8>(), byte in any::<usize>()) {
        let mut v = sample_view();
        mutate_view(&mut v, f, byte);
        prop_assert!(!ds::pin_matches(&sample_pin(), &v));
    }

    /// Mode decode: exactly (0, 0), (1, any), (2, 0) decode.
    #[test]
    fn b_mode_decode(mode in any::<u8>(), d in any::<u64>()) {
        let r = ds::decode_depth_mode(mode, d);
        match (mode, d) {
            (0, 0) => prop_assert_eq!(r, Some(ds::DepthMode::None)),
            (1, d) => prop_assert_eq!(r, Some(ds::DepthMode::Attested(d))),
            (2, 0) => prop_assert_eq!(r, Some(ds::DepthMode::Dex)),
            _ => prop_assert_eq!(r, None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Part C: LiteSVM on the real wrapper BPF
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// CHILLHOUSE per-lot mark at lot_exp 4 (~ $0.0012 per token).
const MARK: u64 = 12_000_000;
const ENGINE_IMR: u64 = 1_000;

fn code(e: PercolatorError) -> String {
    format!("Custom({})", e as u32)
}

fn program_path() -> PathBuf {
    if let Some(p) = std::env::var_os("GROWTH_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_prog.so");
    assert!(path.exists(), "BPF not found at {path:?}; run cargo build-sbf --features devnet");
    path
}

fn seeded_keypair(tag: u8) -> Keypair {
    solana_sdk::signer::keypair::keypair_from_seed(&[tag; 32]).unwrap()
}

fn assert_err(r: &Result<u64, String>, code: &str, what: &str) {
    match r {
        Err(e) => assert!(e.contains(code), "{what}: expected {code}, got {e}"),
        Ok(_) => panic!("{what}: expected {code}, got Ok"),
    }
}

fn mint_data(decimals: u8) -> Vec<u8> {
    let mut data = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint { mint_authority: COption::None, supply: 0, decimals, is_initialized: true, freeze_authority: COption::None },
        &mut data,
    )
    .unwrap();
    data
}

fn token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; TokenAccount::LEN];
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
        &mut data,
    )
    .unwrap();
    data
}

fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program = pk("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    Pubkey::find_program_address(&[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()], &ata_program).0
}

/// The five pool accounts of a pin: (pool, base vault, quote vault, base mint, quote mint).
#[derive(Clone, Copy)]
struct PoolKeys {
    pool: Pubkey,
    base_vault: Pubkey,
    quote_vault: Pubkey,
    base_mint: Pubkey,
    quote_mint: Pubkey,
}

fn chill() -> PoolKeys {
    PoolKeys {
        pool: pk(CHILL_POOL),
        base_vault: pk(CHILL_BASE_VAULT),
        quote_vault: pk(CHILL_QUOTE_VAULT),
        base_mint: pk(CHILL_MINT),
        quote_mint: pk(WSOL_MINT),
    }
}

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    ua: Keypair,
    program_data: Pubkey,
    market: Pubkey,
    slot: u64,
}

impl Env {
    /// A v2.2 band market (growth ON) with `lot_exp` 4, genesis per-lot price `MARK`, collateral
    /// `collateral` (a synthetic 6-decimal mint unless the fixture provides it), an AuthMark
    /// asset, the upgrade-authority ProgramData mock, and every fixture account loaded.
    fn new(collateral: Pubkey) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(program_path()).expect("read wrapper BPF"));
        let payer = seeded_keypair(1);
        let admin = seeded_keypair(2);
        let ua = seeded_keypair(3);
        for k in [&payer, &admin, &ua] {
            svm.airdrop(&k.pubkey(), 100_000_000_000).unwrap();
        }
        // D26: InitMarket requires the market account's signature, so the market is a seeded keypair.
        let market_kp = seeded_keypair(0x11);
        let market = market_kp.pubkey();
        let acct = |data: Vec<u8>, owner: Pubkey| Account { lamports: 1_000_000_000, data, owner, executable: false, rent_epoch: 0 };
        // every fixture account at its real address
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/depth_src");
        for e in std::fs::read_dir(dir).unwrap() {
            let name = e.unwrap().file_name().into_string().unwrap();
            let key = name.rsplit("__").next().unwrap().trim_end_matches(".json").to_string();
            svm.set_account(pk(&key), fixture(&key)).unwrap();
        }
        if svm.get_account(&collateral).is_none() {
            svm.set_account(collateral, acct(mint_data(6), spl_token::ID)).unwrap();
        }
        let vault_authority = Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id).0;
        let vault = canonical_vault_ata(&vault_authority, &collateral);
        svm.set_account(vault, acct(token_data(collateral, vault_authority, 0), spl_token::ID)).unwrap();
        svm.set_account(market, acct(vec![0u8; state::market_account_len_for_capacity(1).unwrap()], program_id)).unwrap();
        let program_data = Pubkey::find_program_address(&[program_id.as_ref()], &solana_sdk::bpf_loader_upgradeable::id()).0;
        let mut pd = vec![0u8; 45];
        pd[0..4].copy_from_slice(&3u32.to_le_bytes());
        pd[12] = 1;
        pd[13..45].copy_from_slice(ua.pubkey().as_ref());
        svm.set_account(program_data, acct(pd, solana_sdk::bpf_loader_upgradeable::id())).unwrap();
        let mut env = Env { svm, program_id, payer, admin, ua, program_data, market, slot: 1 };
        let base = ProgInstruction::InitMarket {
            max_portfolio_assets: 1,
            h_min: 0,
            h_max: 10,
            initial_price: MARK,
            min_nonzero_mm_req: 10,
            min_nonzero_im_req: 20,
            maintenance_margin_bps: 500,
            initial_margin_bps: ENGINE_IMR,
            max_trading_fee_bps: 10_000,
            trade_fee_base_bps: 0,
            liquidation_fee_bps: 100,
            liquidation_fee_cap: 1_000_000_000_000_000,
            min_liquidation_abs: 0,
            max_price_move_bps_per_slot: 4,
            max_accrual_dt_slots: 1,
            max_abs_funding_e9_per_slot: 1,
            min_funding_lifetime_slots: 1,
            max_account_b_settlement_chunks: 1,
            max_bankrupt_close_chunks: 1,
            max_bankrupt_close_lifetime_slots: 1_000_000,
            public_b_chunk_atoms: percolator::MAX_VAULT_TVL,
            maintenance_fee_per_slot: 0,
        };
        let init = ProgInstruction::InitMarketV22 {
            market: Box::new(base),
            growth_r_gap_bps: 0,
            growth_l_launch_x100: 1_000,
            lot_exp: 4,
            phase4: InitMarketPhase4 {
                rent_max_e9_per_slot: 23,
                rent_kink_bps: 5_000,
                band_bps: 100,
                band_max_epoch_slots: 600,
                band_max_pin_slots: 9_000,
                band_min_leg_notional: 10_000_000,
            },
        };
        let admin = env.admin.insecure_clone();
        env.send(
            init,
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, true), AccountMeta::new_readonly(collateral, false)],
            &[&admin, &market_kp],
        )
        .expect("init market");
        let seq = env.oracle_seq() + 1;
        env.send(
            ProgInstruction::ConfigureAuthMark { market_id: 1, asset_index: 0, now_slot: env.slot, initial_mark_e6: MARK, observation_sequence: seq },
            vec![AccountMeta::new(admin.pubkey(), true), AccountMeta::new(market, false)],
            &[&admin],
        )
        .expect("configure auth mark");
        env
    }

    fn send_ixs(&mut self, ixs: Vec<Instruction>, signers: &[&Keypair]) -> Result<u64, String> {
        let mut all = vec![&self.payer];
        all.extend_from_slice(signers);
        let mut v = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
        v.extend(ixs);
        self.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(&v, Some(&self.payer.pubkey()), &all, self.svm.latest_blockhash());
        self.svm.send_transaction(tx).map(|m| m.compute_units_consumed).map_err(|e| format!("{e:?}"))
    }

    fn send(&mut self, ix: ProgInstruction, accounts: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<u64, String> {
        let i = Instruction { program_id: self.program_id, accounts, data: ix.encode() };
        self.send_ixs(vec![i], signers)
    }

    fn oracle_seq(&self) -> u64 {
        let data = self.svm.get_account(&self.market).unwrap().data;
        state::read_asset_control_sequences(&data, 0).unwrap().oracle_observation
    }

    fn warp(&mut self, n: u64) {
        self.slot += n;
        self.svm.warp_to_slot(self.slot);
    }

    fn growth(&self) -> state::AssetGrowthV19 {
        state::read_asset_growth(&self.svm.get_account(&self.market).unwrap().data, 0, ENGINE_IMR).unwrap().expect("growth on")
    }

    fn pda(&self) -> Pubkey {
        state::derive_depth_source(&self.program_id, &self.market).0
    }

    fn record(&self) -> Option<ds::DepthSourceV22> {
        self.svm
            .get_account(&self.pda())
            .filter(|a| !a.data.is_empty())
            .map(|a| state::read_depth_source(&a.data).expect("valid record"))
    }

    /// Tag 123 with explicit accounts.
    fn set_source_with(&mut self, signer: &Keypair, op: u8, market_id: u64, pda: Pubkey, k: Option<PoolKeys>) -> Result<u64, String> {
        let mut accounts = vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new_readonly(self.program_data, false),
            // F-3: tag 123 writes the pin bit into the market's growth record.
            AccountMeta::new(self.market, false),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ];
        // Decision 16 (night 2026-10-28): the pool-claim PDAs. op 1: `[10]` the new pool's claim, `[11]`
        // the old pool's when the pin moves; op 0: `[5]` the pinned pool's claim.
        let old_pool = self.record().map(|r| r.pool).filter(|p| *p != [0u8; 32]);
        if let Some(k) = k {
            for a in [k.pool, k.base_vault, k.quote_vault, k.base_mint, k.quote_mint] {
                accounts.push(AccountMeta::new_readonly(a, false));
            }
            accounts.push(AccountMeta::new(self.claim_pda(&k.pool.to_bytes()), false));
            if let Some(op_) = old_pool.filter(|p| *p != k.pool.to_bytes()) {
                accounts.push(AccountMeta::new(self.claim_pda(&op_), false));
            }
        } else if let Some(op_) = old_pool {
            accounts.push(AccountMeta::new(self.claim_pda(&op_), false));
        }
        let signer = signer.insecure_clone();
        self.send(ProgInstruction::SetDepthSource { op, asset_index: 0, market_id }, accounts, &[&signer])
    }

    fn claim_pda(&self, pool: &[u8; 32]) -> Pubkey {
        state::derive_pool_claim(&self.program_id, pool).0
    }

    fn claim(&self, pool: &[u8; 32]) -> Option<ds::PoolClaimV22> {
        self.svm
            .get_account(&self.claim_pda(pool))
            .filter(|a| !a.data.is_empty() && a.lamports > 0)
            .map(|a| state::read_pool_claim(&a.data).expect("valid claim"))
    }

    fn set_source(&mut self, k: PoolKeys) -> Result<u64, String> {
        let (ua, pda) = (self.ua.insecure_clone(), self.pda());
        self.set_source_with(&ua, 1, 1, pda, Some(k))
    }

    fn clear_source(&mut self) -> Result<u64, String> {
        let (ua, pda) = (self.ua.insecure_clone(), self.pda());
        self.set_source_with(&ua, 0, 1, pda, None)
    }

    fn push_ix(&self, seq: u64, mode: u8, depth_e6: u64, mark: u64, trailing: &[Pubkey]) -> Instruction {
        let data = if mode == 255 {
            ProgInstruction::PushAuthMark { market_id: 1, asset_index: 0, now_slot: self.slot, mark_e6: mark, observation_sequence: seq }.encode()
        } else {
            ProgInstruction::PushAuthMarkDepth {
                market_id: 1,
                asset_index: 0,
                now_slot: self.slot,
                mark_e6: mark,
                observation_sequence: seq,
                depth_mode: mode,
                depth_e6,
            }
            .encode()
        };
        let mut accounts = vec![AccountMeta::new(self.admin.pubkey(), true), AccountMeta::new(self.market, false)];
        accounts.extend(trailing.iter().map(|a| AccountMeta::new_readonly(*a, false)));
        Instruction { program_id: self.program_id, accounts, data }
    }

    /// One PushAuthMark; `mode` 255 = the 35-byte form.
    fn push(&mut self, mode: u8, depth_e6: u64, trailing: &[Pubkey]) -> Result<u64, String> {
        let ix = self.push_ix(self.oracle_seq() + 1, mode, depth_e6, MARK, trailing);
        let admin = self.admin.insecure_clone();
        self.send_ixs(vec![ix], &[&admin])
    }

    fn dex_accounts(&self, k: PoolKeys) -> Vec<Pubkey> {
        vec![self.pda(), k.pool, k.base_vault, k.quote_vault]
    }

    /// SEC-RC2 L-RC2-1: a mode-1 (attested) push on a DEX-pinned asset LANDS (was: refused 129
    /// with nothing written, 4db44b69 / RC2 50a336d4). Its mark is applied (sequence consumed,
    /// oracle target = the pushed mark), its attested depth is ignored (the depth state is
    /// byte-identical before and after) and the pin bit is kept.
    fn mode1_on_pin_lands_mark_ignores_depth(&mut self, depth_e6: u64, what: &str) {
        let before = self.growth();
        assert!(growth_v19::depth_dex_pinned(before.depth_source), "{what}: setup: pinned");
        let seq = self.oracle_seq();
        let profile0 = state::read_asset_oracle_profile(&self.svm.get_account(&self.market).unwrap().data, 0).unwrap();
        let mark = if profile0.oracle_target_price_e6 == MARK + MARK / 100 { MARK + MARK / 50 } else { MARK + MARK / 100 };
        let ix = self.push_ix(seq + 1, 1, depth_e6, mark, &[]);
        let admin = self.admin.insecure_clone();
        self.send_ixs(vec![ix], &[&admin]).unwrap_or_else(|e| panic!("{what}: mode 1 on a pinned asset must land (L-RC2-1): {e}"));
        assert_eq!(self.oracle_seq(), seq + 1, "{what}: the push landed (sequence consumed)");
        let profile = state::read_asset_oracle_profile(&self.svm.get_account(&self.market).unwrap().data, 0).unwrap();
        assert_eq!(profile.oracle_target_price_e6, mark, "{what}: the mark landed");
        let after = self.growth();
        assert_eq!(after.depth_state(), before.depth_state(), "{what}: the attested depth is ignored (depth state untouched)");
        assert!(growth_v19::depth_dex_pinned(after.depth_source), "{what}: the pin bit is kept");
    }

    /// Snapshot of everything a refused push must not change.
    fn snapshot(&self) -> (u64, Vec<u8>) {
        (self.oracle_seq(), self.svm.get_account(&self.market).unwrap().data)
    }
}

/// CHILLHOUSE (PumpSwap, SPL Token): tag 123 creates the PDA with the verified pin; a mode-2
/// push stores the program-computed depth 2,027,034,782 (base 171,449,177,380,421 atoms at the
/// 12,000,000 per-lot mark, lot_exp 4: value 205,739,012,856) with source 2, stamped now; a later
/// mode-2 push rotates it; afterwards the 35 B form zeroes the depth exactly as before. F-3: the
/// pin sets `DEPTH_DEX_PINNED` and a keeper-attested (mode 1) push is refused while it is set.
#[test]
fn c_set_depth_source_and_mode2_push_chillhouse() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    assert!(env.record().is_none());
    env.set_source(chill()).expect("SetDepthSource");
    let r = env.record().unwrap();
    assert_eq!(r.market, env.market.to_bytes());
    assert_eq!(r.amm_program, ds::PUMPSWAP_AMM_PROGRAM_ID.to_bytes());
    assert_eq!((r.pool, r.base_vault, r.quote_vault), (pk(CHILL_POOL).to_bytes(), pk(CHILL_BASE_VAULT).to_bytes(), pk(CHILL_QUOTE_VAULT).to_bytes()));
    assert_eq!((r.base_mint, r.quote_mint), (pk(CHILL_MINT).to_bytes(), pk(WSOL_MINT).to_bytes()));
    assert_eq!((r.base_decimals, r.quote_decimals, r.flags, r.amm_kind, r.asset_index, r.market_id), (6, 9, ds::DEPTH_SRC_FLAG_ACTIVE, ds::AMM_PUMPSWAP, 0, 1));
    let acct = env.svm.get_account(&env.pda()).unwrap();
    assert_eq!((acct.owner, acct.data.len(), acct.data[10]), (env.program_id, state::depth_source_account_len(), 16));
    assert_eq!(state::depth_source_account_len(), 16 + 256);

    env.warp(2);
    let dex = env.dex_accounts(chill());
    let cu_dex = env.push(2, 0, &dex).expect("mode 2 push");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6, g.depth_source), (2_027_034_782, 0, growth_v19::DEPTH_SOURCE_DEX | growth_v19::DEPTH_DEX_PINNED));
    assert_eq!(g.depth_slot, env.slot);
    // second sample in a later slot: rotates
    env.warp(1);
    env.push(2, 0, &dex).expect("mode 2 push 2");
    let g = env.growth();
    // merged with the tiers branch: byte 44 = source 2 | DEPTH_PREV_REAL | DEPTH_EVER
    assert_eq!((g.depth_e6, g.depth_prev_e6, g.depth_source), (2_027_034_782, 2_027_034_782, 2 | growth_v19::DEPTH_PREV_REAL | growth_v19::DEPTH_EVER | growth_v19::DEPTH_DEX_PINNED));
    assert_eq!(growth_v19::effective_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, env.slot), 2_027_034_782);
    assert_eq!(growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot), Some(2_027_034_782));
    // R2-M1 + round 3 D-I1: the market's first fresh reading is min(r, T1 / 16)
    assert_eq!(g.depth_last_good_e6, (growth_v19::DEPTH_TIER1_E6 - 1) / 16);
    // 35 B afterwards: as today (zeroes, prev keeps the last depth, source 0)
    env.warp(1);
    let cu_35 = env.push(255, 0, &[]).expect("35 B push");
    let g = env.growth();
    assert_eq!((g.depth_e6, g.depth_prev_e6, g.depth_source), (0, 2_027_034_782, growth_v19::DEPTH_PREV_REAL | growth_v19::DEPTH_EVER | growth_v19::DEPTH_DEX_PINNED));
    // CU: mode 2 costs the four account reads, the pin check, the isqrt and one log line on
    // top of the 35 B push (incl. the transaction's compute-budget instruction).
    eprintln!("CU mode2={cu_dex} 35B={cu_35} delta={}", cu_dex.saturating_sub(cu_35));
    assert!(cu_dex < cu_35 + 40_000, "mode 2 overhead bounded: {cu_dex} vs {cu_35}");
    // F-3 + L-RC2-1: mode 1 (keeper-attested) on the pinned market: OLD (4db44b69 / RC2) refused
    // 129 with nothing written; NEW the mark lands and the attested depth is ignored.
    env.warp(1);
    env.mode1_on_pin_lands_mark_ignores_depth(30_000_000_000, "chillhouse: mode 1 on a DEX-pinned market");
    // Coordinator ruling (merge): a REAL on-chain zero depth (mode 2, the pool's asset vault
    // emptied: STATE POKE of the token amount) is a fresh reading of 0 at once: DEPTH_EVER, every
    // reader 0 through the time-weighted window (the κ cap is 0 on a clamp-enforced market),
    // never "absent". Round 3 D2: the last good depth itself is held.
    let mut bv = env.svm.get_account(&pk(CHILL_BASE_VAULT)).unwrap();
    bv.data[64..72].copy_from_slice(&0u64.to_le_bytes());
    env.svm.set_account(pk(CHILL_BASE_VAULT), bv).unwrap();
    env.warp(1);
    env.push(2, 0, &dex).expect("mode 2 with an empty asset side (PumpSwap: value 0, depth 0)");
    let g = env.growth();
    assert_eq!((g.depth_e6, growth_v19::depth_source_of(g.depth_source)), (0, 2), "a real DEX 0");
    assert_eq!(growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot), Some(0));
    assert_eq!((g.depth_last_good_e6, g.depth_source & growth_v19::DEPTH_EVER), ((growth_v19::DEPTH_TIER1_E6 - 1) / 16, growth_v19::DEPTH_EVER));
    assert_eq!(g.depth_tw_min_e6(), Some(0), "the window holds the zero");
    assert_eq!(
        growth_v19::usable_depth_e6(growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot), g.depth_last_good_e6, g.depth_tw_min_e6()),
        Some(0),
        "every reader: 0 at once"
    );
    // re-pin is allowed (replace) and keeps the same account
    env.set_source(chill()).expect("re-set");
    assert!(env.record().unwrap().is_active());
}

/// Mode 2 with depth_e6 != 0 is a wire error (128), never a 129, never written.
#[test]
fn c_mode2_nonzero_wire_depth_is_128() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).unwrap();
    env.warp(1);
    let before = env.snapshot();
    let dex = env.dex_accounts(chill());
    assert_err(&env.push(2, 1, &dex), &code(PercolatorError::DepthInputInvalid), "mode 2 with a wire depth");
    assert_eq!(env.snapshot(), before);
    env.push(2, 0, &dex).expect("CONTROL: the same push with depth 0");
}

/// Every SetDepthSource refusal, each next to an accepted control; nothing is created.
#[test]
fn c_set_depth_source_refusals() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let (ua, pda) = (env.ua.insecure_clone(), env.pda());
    // non-UA signer (the market admin): Unauthorized
    let admin = env.admin.insecure_clone();
    assert_err(&env.set_source_with(&admin, 1, 1, pda, Some(chill())), &code(PercolatorError::Unauthorized), "non-UA");
    // wrong pool owner: the CHILLHOUSE bytes at a new address owned by another program
    let forged = Pubkey::new_from_array([0xA1; 32]);
    let mut a = fixture(CHILL_POOL);
    a.owner = Pubkey::new_from_array([0xAB; 32]);
    env.svm.set_account(forged, a).unwrap();
    let k = PoolKeys { pool: forged, ..chill() };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(k)), &code(PercolatorError::DepthSourceInvalid), "pool owner off the allow-list");
    // vault mismatch: another (real-format) token account of the same mint, not the pool's vault
    let other_vault = Pubkey::new_from_array([0xA2; 32]);
    env.svm
        .set_account(other_vault, Account { lamports: 1_000_000_000, data: token_data(pk(CHILL_MINT), Pubkey::new_from_array([7; 32]), 10u64.pow(18)), owner: spl_token::ID, executable: false, rent_epoch: 0 })
        .unwrap();
    let k = PoolKeys { base_vault: other_vault, ..chill() };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(k)), &code(PercolatorError::DepthSourceInvalid), "base vault not the pool's");
    // mint mismatch: a different mint for the base side
    let other_mint = Pubkey::new_from_array([0xA3; 32]);
    env.svm.set_account(other_mint, Account { lamports: 1_000_000_000, data: mint_data(6), owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    let k = PoolKeys { base_mint: other_mint, ..chill() };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(k)), &code(PercolatorError::DepthSourceInvalid), "base mint mismatch");
    // swapped sides with the mints left: (vault, mint) pairs no longer match
    let k = PoolKeys { base_vault: pk(CHILL_QUOTE_VAULT), quote_vault: pk(CHILL_BASE_VAULT), ..chill() };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(k)), &code(PercolatorError::DepthSourceInvalid), "vault/mint pairs crossed");
    // a frozen vault (state poke on the real vault)
    let mut fz = env.svm.get_account(&pk(CHILL_BASE_VAULT)).unwrap();
    fz.data[108] = 2;
    let frozen = Pubkey::new_from_array([0xA4; 32]);
    env.svm.set_account(frozen, fz).unwrap();
    let k = PoolKeys { base_vault: frozen, ..chill() };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(k)), &code(PercolatorError::DepthSourceInvalid), "frozen vault");
    // wrong PDA: the PDA of another market
    let wrong = state::derive_depth_source(&env.program_id, &Pubkey::new_from_array([0x99; 32])).0;
    assert_err(&env.set_source_with(&ua, 1, 1, wrong, Some(chill())), &code(PercolatorError::DepthSourceInvalid), "wrong PDA");
    // wrong generation
    assert_err(&env.set_source_with(&ua, 1, 2, pda, Some(chill())), &code(PercolatorError::AssetGenerationMismatch), "stale market_id");
    // clear with nothing to clear
    assert_err(&env.clear_source(), &code(PercolatorError::DepthSourceInvalid), "clear without a record");
    // missing pool accounts on op 1
    assert!(env.set_source_with(&ua, 1, 1, pda, None).is_err());
    // nothing was created by any refusal
    assert!(env.svm.get_account(&pda).is_none_or(|a| a.data.is_empty()));
    // CONTROL: the same UA with the right accounts succeeds
    env.set_source(chill()).expect("control");
    assert!(env.record().unwrap().is_active());
}

/// Mode-2 refusals (each 129, the market account byte-identical, the sequence not consumed),
/// each next to the accepted control: no PDA, forged pool (another owner), forged pool at the
/// pinned key with attacker vault fields, a non-pool vault, swapped vault order, missing
/// accounts, a record of another market, the cleared pin; and the 35 B form afterwards.
#[test]
fn c_mode2_refusals() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let ok = env.dex_accounts(chill());
    env.warp(1);
    // no PDA yet
    let before = env.snapshot();
    assert_err(&env.push(2, 0, &ok), &code(PercolatorError::DepthSourceInvalid), "mode 2 without a PDA");
    assert_eq!(env.snapshot(), before, "nothing written");
    env.set_source(chill()).unwrap();
    // forged pool owned by another program, same bytes
    let forged = Pubkey::new_from_array([0xB1; 32]);
    let mut a = fixture(CHILL_POOL);
    a.owner = Pubkey::new_from_array([0xAB; 32]);
    env.svm.set_account(forged, a).unwrap();
    let before = env.snapshot();
    let v = vec![env.pda(), forged, pk(CHILL_BASE_VAULT), pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "forged pool owner");
    assert_eq!(env.snapshot(), before);
    // a real-owner pool at another key (the swordcat pool) with CHILLHOUSE vaults
    let v = vec![env.pda(), pk(SWORD_POOL), pk(CHILL_BASE_VAULT), pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "unpinned pool");
    // a non-pool token account of the base mint as the base vault (a whale wallet)
    let whale = Pubkey::new_from_array([0xB2; 32]);
    env.svm
        .set_account(whale, Account { lamports: 1_000_000_000, data: token_data(pk(CHILL_MINT), Pubkey::new_from_array([7; 32]), 10u64.pow(18)), owner: spl_token::ID, executable: false, rent_epoch: 0 })
        .unwrap();
    let v = vec![env.pda(), pk(CHILL_POOL), whale, pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "whale wallet as vault");
    // vaults swapped
    let v = vec![env.pda(), pk(CHILL_POOL), pk(CHILL_QUOTE_VAULT), pk(CHILL_BASE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "vaults swapped");
    // missing trailing accounts
    let v = vec![env.pda(), pk(CHILL_POOL), pk(CHILL_BASE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "3 of 4 accounts");
    assert_err(&env.push(2, 0, &[]), &code(PercolatorError::DepthSourceInvalid), "no accounts");
    // the pinned pool key now carries attacker vault fields (state poke: the AMM rewrote it)
    let saved_pool = env.svm.get_account(&pk(CHILL_POOL)).unwrap();
    let mut p = saved_pool.clone();
    p.data[139..171].copy_from_slice(whale.as_ref());
    env.svm.set_account(pk(CHILL_POOL), p).unwrap();
    let v = vec![env.pda(), pk(CHILL_POOL), whale, pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "pool's own vault field changed (attacker vault passed)");
    assert_err(&env.push(2, 0, &ok), &code(PercolatorError::DepthSourceInvalid), "pool's own vault field changed (pinned vault passed)");
    env.svm.set_account(pk(CHILL_POOL), saved_pool).unwrap();
    // a valid record of ANOTHER market, at that market's PDA, passed here
    let other_market = Pubkey::new_from_array([0x98; 32]);
    let (other_pda, other_bump) = state::derive_depth_source(&env.program_id, &other_market);
    let mut rec = env.record().unwrap();
    rec.market = other_market.to_bytes();
    rec.bump = other_bump;
    let mut data = vec![0u8; state::depth_source_account_len()];
    data[..16].copy_from_slice(&env.svm.get_account(&env.pda()).unwrap().data[..16]);
    data[16..].copy_from_slice(bytemuck::bytes_of(&rec));
    env.svm.set_account(other_pda, Account { lamports: 1_000_000_000, data, owner: env.program_id, executable: false, rent_epoch: 0 }).unwrap();
    let v = vec![other_pda, pk(CHILL_POOL), pk(CHILL_BASE_VAULT), pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "another market's record");
    // the right record copied to a non-PDA address owned by the program
    let copy = Pubkey::new_from_array([0xB3; 32]);
    let a = env.svm.get_account(&env.pda()).unwrap();
    env.svm.set_account(copy, a).unwrap();
    let v = vec![copy, pk(CHILL_POOL), pk(CHILL_BASE_VAULT), pk(CHILL_QUOTE_VAULT)];
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "record at a non-PDA address");
    let before = env.snapshot();
    assert_eq!(before.0, env.oracle_seq());
    // CONTROL
    env.push(2, 0, &ok).expect("control: the pinned accounts");
    assert_eq!(growth_v19::depth_source_of(env.growth().depth_source), 2);
    // the pin cleared by the UA: mode 2 refused again (fail closed), non-UA cannot clear
    env.warp(1);
    let (admin, pda) = (env.admin.insecure_clone(), env.pda());
    assert_err(&env.set_source_with(&admin, 0, 1, pda, None), &code(PercolatorError::Unauthorized), "non-UA clear");
    env.clear_source().expect("UA clear");
    let r = env.record().unwrap();
    assert!(!r.is_active());
    assert_eq!(r, ds::DepthSourceV22::cleared(env.market.to_bytes(), r.bump));
    let before = env.snapshot();
    assert_err(&env.push(2, 0, &ok), &code(PercolatorError::DepthSourceInvalid), "cleared pin");
    assert_eq!(env.snapshot(), before);
    // the 35 B push behaves as today
    env.push(255, 0, &[]).expect("35 B after the refusals");
    let g = env.growth();
    assert_eq!((g.depth_e6, growth_v19::depth_source_of(g.depth_source)), (0, 0));
    // re-pinning restores mode 2
    env.set_source(chill()).expect("re-pin after clear");
    env.warp(1);
    env.push(2, 0, &ok).expect("mode 2 after re-pin");
    assert_eq!(env.growth().depth_e6, 2_027_034_782);
}

/// Raydium CPMM, the asset on side 1 (WSOL/USELESS): flags carry BASE_IS_SIDE1, the base side
/// is the USELESS vault net of fees (12,467,108,991,309) at the 12e6 per-lot mark (lot_exp 4,
/// 6 decimals): value 14,960,530,789 -> depth 147,397,986.
#[test]
fn c_raydium_side1_asset() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let k = PoolKeys {
        pool: pk(USELESS_POOL),
        base_vault: pk(USELESS_VAULT1),
        quote_vault: pk(USELESS_VAULT0),
        base_mint: pk(USELESS_MINT),
        quote_mint: pk(WSOL_MINT),
    };
    env.set_source(k).expect("pin side 1");
    assert_eq!(env.record().unwrap().flags, ds::DEPTH_SRC_FLAG_ACTIVE | ds::DEPTH_SRC_FLAG_BASE_IS_SIDE1);
    env.warp(1);
    let v = env.dex_accounts(k);
    env.push(2, 0, &v).expect("mode 2");
    assert_eq!((env.growth().depth_e6, growth_v19::depth_source_of(env.growth().depth_source)), (147_397_986, 2));
    // NEGATIVE CONTROL: a pool with swaps disabled is refused at push time
    let mut p = env.svm.get_account(&k.pool).unwrap();
    p.data[329] |= 1 << 2;
    env.svm.set_account(k.pool, p).unwrap();
    env.warp(1);
    assert_err(&env.push(2, 0, &v), &code(PercolatorError::DepthSourceInvalid), "swap disabled");
}

/// NEAR/USDC (Raydium CPMM) on a market whose collateral IS the pool's quote mint (USDC): the
/// depth comes straight from the quote reserve net of fees (1,377,211,761,778 -> 13,568,919,694),
/// independent of the mark.
#[test]
fn c_quote_is_collateral_path() {
    let mut env = Env::new(pk(USDC_MINT));
    let k = PoolKeys { pool: pk(NEAR_POOL), base_vault: pk(NEAR_VAULT0), quote_vault: pk(NEAR_VAULT1), base_mint: pk(NEAR_MINT), quote_mint: pk(USDC_MINT) };
    env.set_source(k).expect("pin");
    env.warp(1);
    let v = env.dex_accounts(k);
    env.push(2, 0, &v).expect("mode 2");
    assert_eq!(env.growth().depth_e6, 13_568_919_694);
    // NEGATIVE CONTROL: the asset side may not be the collateral mint
    let (ua, pda) = (env.ua.insecure_clone(), env.pda());
    let crossed = PoolKeys { base_vault: pk(NEAR_VAULT1), quote_vault: pk(NEAR_VAULT0), base_mint: pk(USDC_MINT), quote_mint: pk(NEAR_MINT), ..k };
    assert_err(&env.set_source_with(&ua, 1, 1, pda, Some(crossed)), &code(PercolatorError::DepthSourceInvalid), "asset = collateral");
}

/// swordcat: a Token-2022 coin and base vault (PumpSwap) pin and push.
#[test]
fn c_token2022_swordcat() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let k = PoolKeys { pool: pk(SWORD_POOL), base_vault: pk(SWORD_BASE_VAULT), quote_vault: pk(SWORD_QUOTE_VAULT), base_mint: pk(SWORD_MINT), quote_mint: pk(WSOL_MINT) };
    env.set_source(k).expect("pin T22");
    env.warp(1);
    let v = env.dex_accounts(k);
    env.push(2, 0, &v).expect("mode 2");
    // 35,107,081,881,503 base atoms * 12e6 / 1e10 = 42,128,498,257 -> 415,069,218
    assert_eq!(env.growth().depth_e6, 415_069_218);
    // NEGATIVE CONTROL: the mint retyped to carry a PermanentDelegate extension is refused
    let mut m = env.svm.get_account(&k.base_mint).unwrap();
    m.data[166..168].copy_from_slice(&12u16.to_le_bytes());
    env.svm.set_account(k.base_mint, m).unwrap();
    assert_err(&env.set_source(k), &code(PercolatorError::DepthSourceInvalid), "T22 permanent delegate");
}

/// Mark used for the base path: min(stored mark, this push's mark). A push that doubles the mark
/// values the reserve at the OLD mark; the next push (stored mark now doubled) at the new one.
#[test]
fn c_mark_min_of_before_and_now() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).unwrap();
    env.warp(1);
    let v = env.dex_accounts(chill());
    let seq = env.oracle_seq() + 1;
    let ix = env.push_ix(seq, 2, 0, MARK + 4_800, &v); // within the 4 bps/slot price cap
    let admin = env.admin.insecure_clone();
    env.send_ixs(vec![ix], &[&admin]).expect("higher mark");
    assert_eq!(env.growth().depth_e6, 2_027_034_782, "valued at the lower (stored) mark");
    let lower = ds::plus2pct_depth_e6(ds::reserve_value_e6(ds::ValuePath::BaseAtMark, 171_449_177_380_421, 0, MARK - 4_800, 6, 4).unwrap());
    env.warp(1);
    let seq = env.oracle_seq() + 1;
    let ix = env.push_ix(seq, 2, 0, MARK - 4_800, &v);
    env.send_ixs(vec![ix], &[&admin]).expect("lower mark");
    assert_eq!(env.growth().depth_e6, lower, "valued at this push's lower mark");
    assert!(lower < 2_027_034_782);
}

/// Several pushes in ONE transaction (tag 63 has no batched form; a batch is several
/// instructions, each with its own four accounts): both mode-2 instructions verify their own
/// accounts; a bad second instruction fails the whole transaction (nothing written).
#[test]
fn c_two_pushes_in_one_transaction() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).unwrap();
    env.warp(1);
    let v = env.dex_accounts(chill());
    let seq = env.oracle_seq();
    let admin = env.admin.insecure_clone();
    let bad = vec![env.pda(), pk(SWORD_POOL), pk(SWORD_BASE_VAULT), pk(SWORD_QUOTE_VAULT)];
    let before = env.snapshot();
    let r = env.send_ixs(vec![env.push_ix(seq + 1, 2, 0, MARK, &v), env.push_ix(seq + 2, 2, 0, MARK, &bad)], &[&admin]);
    assert_err(&r, &code(PercolatorError::DepthSourceInvalid), "second entry forged");
    assert_eq!(env.snapshot(), before, "the whole transaction is rolled back");
    env.send_ixs(vec![env.push_ix(seq + 1, 2, 0, MARK, &v), env.push_ix(seq + 2, 2, 0, MARK, &v)], &[&admin]).expect("two good entries");
    assert_eq!(env.oracle_seq(), seq + 2);
    assert_eq!(env.growth().depth_e6, 2_027_034_782);
}

/// Wire: tag 123 is exactly 12 bytes `[123][op][asset u16][market_id u64]`; op 2.. and other
/// lengths are InvalidInstructionData; the encoder round-trips.
#[test]
fn c_tag123_wire() {
    let ix = ProgInstruction::SetDepthSource { op: 1, asset_index: 3, market_id: 0x0102030405060708 };
    let d = ix.encode();
    assert_eq!(d, vec![123, 1, 3, 0, 8, 7, 6, 5, 4, 3, 2, 1]);
    assert!(matches!(ProgInstruction::decode(&d), Ok(ProgInstruction::SetDepthSource { op: 1, asset_index: 3, market_id: 0x0102030405060708 })));
    for bad in [vec![123u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![123, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![123, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]] {
        assert!(ProgInstruction::decode(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(code(PercolatorError::DepthSourceInvalid), "Custom(129)");
    // tag 63 mode 2 decodes only with depth 0
    let p = ProgInstruction::PushAuthMarkDepth { market_id: 1, asset_index: 0, now_slot: 1, mark_e6: 1, observation_sequence: 1, depth_mode: 2, depth_e6: 0 }.encode();
    assert_eq!(p.len(), 44);
    assert!(ProgInstruction::decode(&p).is_ok());
    let mut p2 = p.clone();
    p2[36] = 1;
    assert!(ProgInstruction::decode(&p2).is_err());
}

/// Merge fix (coordinator): in mode 2 the oracle-signer check runs BEFORE the DEX account
/// checks. A wrong signer with BAD DEX accounts gets the authority error (Unauthorized), not
/// 129; the right signer with the same bad accounts gets 129; nothing is written either way.
#[test]
fn c_mode2_wrong_signer_is_refused_before_the_dex_accounts() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).expect("SetDepthSource");
    env.warp(1);
    let bad = vec![env.pda(), pk(CHILL_POOL), pk(CHILL_QUOTE_VAULT), pk(CHILL_BASE_VAULT)]; // vaults swapped
    let before = env.snapshot();
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let mut ix = env.push_ix(env.oracle_seq() + 1, 2, 0, MARK, &bad);
    ix.accounts[0] = AccountMeta::new(stranger.pubkey(), true);
    let r = env.send_ixs(vec![ix], &[&stranger]);
    assert_err(&r, &code(PercolatorError::Unauthorized), "wrong signer + bad DEX accounts: the auth error first");
    assert_eq!(env.snapshot(), before);
    // the right signer with the same bad accounts: 129
    assert_err(&env.push(2, 0, &bad), &code(PercolatorError::DepthSourceInvalid), "right signer, bad accounts");
    assert_eq!(env.snapshot(), before);
    // CONTROL: right signer, right accounts
    let ok = env.dex_accounts(chill());
    env.push(2, 0, &ok).expect("control");
}

/// Security review R2-M1 on the DEX source (the reviewer's scenario): the pool's asset vault
/// inflated 1,000x (STATE POKE of the token amount: balanced liquidity added) and held for two
/// adjacent-slot mode-2 pushes. Round 3: the first reading is T1/16 (D-I1); a spike inside one
/// bucket adds nothing (the time-weighted window keeps the honest minimum); liquidity HELD over a
/// full window rises at most 2x per 9,000 slots, and the honest pool takes it back down at once.
/// Round 2 (no limiter) stored the inflated reading (tier 3 on a $500k+ read).
#[test]
fn c_mode2_flash_liquidity_is_rate_limited() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).expect("SetDepthSource");
    let dex = env.dex_accounts(chill());
    env.warp(1);
    env.push(2, 0, &dex).expect("mode 2");
    env.warp(1);
    env.push(2, 0, &dex).expect("mode 2 pair");
    let real = 2_027_034_782u64;
    let floor = (growth_v19::DEPTH_TIER1_E6 - 1) / 16;
    assert_eq!(env.growth().depth_last_good_e6, floor, "D-I1: first reading T1 / 16");
    let honest = env.svm.get_account(&pk(CHILL_BASE_VAULT)).unwrap();
    let mut big = honest.clone();
    let amt = u64::from_le_bytes(big.data[64..72].try_into().unwrap());
    big.data[64..72].copy_from_slice(&(amt * 1_000).to_le_bytes());
    env.svm.set_account(pk(CHILL_BASE_VAULT), big.clone()).unwrap();
    env.warp(1);
    env.push(2, 0, &dex).expect("inflated 1");
    env.warp(1);
    env.push(2, 0, &dex).expect("inflated 2");
    let g = env.growth();
    assert!(g.depth_e6 > 900 * real, "the pool reads ~1,000x");
    assert_eq!(g.depth_last_good_e6, floor, "no rise");
    assert_eq!(g.depth_tw_min_e6(), Some(real / 1_000_000 * 1_000_000), "the window keeps the honest minimum (whole tokens, floor)");
    assert_eq!(
        growth_v19::usable_depth_e6(
            growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot),
            g.depth_last_good_e6,
            g.depth_tw_min_e6(),
        ),
        Some(floor),
        "every reader uses min(fresh, rate-limited, window)"
    );
    // held over a full window into the rise window: one doubling
    // D-L2: past the rise window (stamp * 64 + 63 + 9,000)
    let st = u32::from_le_bytes(env.growth().depth_rise_slot64_le) as u64;
    let next = st * 64 + 63 + 9_000;
    while env.slot + 600 < next - 1 {
        env.warp(600);
        env.push(2, 0, &dex).expect("held inflated");
    }
    assert_eq!(env.growth().depth_last_good_e6, floor, "held, but the 9,000 slots are not over");
    env.warp(next - env.slot);
    env.push(2, 0, &dex).expect("inflated 3");
    env.warp(1);
    env.push(2, 0, &dex).expect("inflated 4");
    assert_eq!(env.growth().depth_last_good_e6, 2 * floor, "one doubling per window");
    // the liquidity leaves: down at once
    env.svm.set_account(pk(CHILL_BASE_VAULT), honest).unwrap();
    env.warp(1);
    env.push(2, 0, &dex).expect("honest 1");
    // down at once to the window minimum: the honest reading in whole tokens (floor)
    assert_eq!(env.growth().depth_last_good_e6, real / 1_000_000 * 1_000_000, "min(real, inflated) = real: down at once");
}

// ── v2.2 DEATH F-3 (= SEC-RC L-2) and SEC-RC L-1 ─────────────────────────────────────────────

/// F-3 + SEC-RC2 L-RC2-1: while the market is pinned to its DEX pool a keeper-attested (mode 1)
/// push LANDS its mark but its depth is ignored (depth state byte-identical; was: the whole push
/// refused 129 on 4db44b69 / RC2 50a336d4). Before the pin and after the UA clears it, mode 1
/// stores an attested depth as before. The 35 B form, mode 0 and mode 2 stay allowed while pinned, and
/// none of them drops the pin bit. On 75fca911 the mode-1 push lands and replaces the pool's
/// reading (source 2 -> 1), which is the finding.
#[test]
fn f3_attested_depth_refused_while_dex_pinned() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let dex = env.dex_accounts(chill());
    // CONTROL: no pin yet, mode 1 lands (source 1)
    env.warp(1);
    env.push(1, 30_000_000_000, &[]).expect("mode 1 before any pin");
    assert_eq!(growth_v19::depth_source_of(env.growth().depth_source), growth_v19::DEPTH_SOURCE_ATTESTED);
    assert!(!growth_v19::depth_dex_pinned(env.growth().depth_source));
    // the pin sets the bit at once (before any mode-2 reading)
    env.set_source(chill()).expect("pin");
    assert!(growth_v19::depth_dex_pinned(env.growth().depth_source), "tag 123 op 1 sets DEPTH_DEX_PINNED");
    env.warp(1);
    // OLD: refused 129, nothing written. NEW (L-RC2-1): the mark lands, the $1M lie is ignored.
    env.mode1_on_pin_lands_mark_ignores_depth(1_000_000_000_000, "mode 1 right after the pin");
    env.push(2, 0, &dex).expect("mode 2 while pinned");
    let g = env.growth();
    assert_eq!(growth_v19::depth_source_of(g.depth_source), growth_v19::DEPTH_SOURCE_DEX);
    assert!(growth_v19::depth_dex_pinned(g.depth_source));
    env.warp(1);
    let pool = env.growth().depth_state();
    env.mode1_on_pin_lands_mark_ignores_depth(1_000_000_000_000, "mode 1 after a DEX reading (the ncc-liedex lie)");
    assert_eq!(env.growth().depth_state(), pool, "the pool reading stands, byte for byte");
    assert_eq!(growth_v19::depth_source_of(env.growth().depth_source), growth_v19::DEPTH_SOURCE_DEX, "the pool reading stands");
    env.push(255, 0, &[]).expect("35 B while pinned (absent: the conservative direction)");
    assert!(growth_v19::depth_dex_pinned(env.growth().depth_source), "35 B keeps the bit");
    env.warp(1);
    env.push(0, 0, &[]).expect("mode 0 while pinned");
    assert!(growth_v19::depth_dex_pinned(env.growth().depth_source), "mode 0 keeps the bit");
    env.warp(1);
    env.push(2, 0, &dex).expect("mode 2 again");
    // the UA clears the pin: the bit goes, mode 1 lands again
    env.clear_source().expect("UA clear");
    assert!(!growth_v19::depth_dex_pinned(env.growth().depth_source), "tag 123 op 0 clears the bit");
    env.warp(1);
    env.push(1, 30_000_000_000, &[]).expect("mode 1 after the clear");
    assert_eq!(growth_v19::depth_source_of(env.growth().depth_source), growth_v19::DEPTH_SOURCE_ATTESTED);
    // re-pin: refused again
    env.set_source(chill()).expect("re-pin");
    env.warp(1);
    env.mode1_on_pin_lands_mark_ignores_depth(30_000_000_000, "mode 1 after a re-pin");
    // tag 123 with the market read-only is refused (it must write the bit); nothing changes
    let (ua, pda) = (env.ua.insecure_clone(), env.pda());
    let before = (env.svm.get_account(&env.market).unwrap().data, env.record());
    let accounts = vec![
        AccountMeta::new(ua.pubkey(), true),
        AccountMeta::new_readonly(env.program_data, false),
        AccountMeta::new_readonly(env.market, false),
        AccountMeta::new(pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    assert!(env.send(ProgInstruction::SetDepthSource { op: 0, asset_index: 0, market_id: 1 }, accounts, &[&ua]).is_err(), "read-only market at tag 123");
    assert_eq!((env.svm.get_account(&env.market).unwrap().data, env.record()), before);
}

/// F-3: a pin made before the bit existed (state poke: the bit cleared under an active pin) is
/// covered from its first mode-2 reading on: that reading proves an active pin and sets the bit.
#[test]
fn f3_mode2_reading_sets_the_pin_bit_for_an_older_pin() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).expect("pin");
    let mut data = env.svm.get_account(&env.market).unwrap().data;
    let mut g = state::read_asset_growth(&data, 0, ENGINE_IMR).unwrap().unwrap();
    g.depth_source &= !growth_v19::DEPTH_DEX_PINNED;
    state::write_asset_growth(&mut data, 0, &g, ENGINE_IMR).unwrap();
    let mut a = env.svm.get_account(&env.market).unwrap();
    a.data = data;
    env.svm.set_account(env.market, a).unwrap();
    assert!(!growth_v19::depth_dex_pinned(env.growth().depth_source), "setup: an older pin without the bit");
    env.warp(1);
    let dex = env.dex_accounts(chill());
    env.push(2, 0, &dex).expect("mode 2");
    assert!(growth_v19::depth_dex_pinned(env.growth().depth_source), "a DEX reading sets the bit");
    env.warp(1);
    env.mode1_on_pin_lands_mark_ignores_depth(30_000_000_000, "mode 1 after the first DEX reading");
}

/// F-3: the pure decision, every (pinned, mode) pair; and the validator accepts the bit.
#[test]
fn f3_depth_push_mode_allowed_table() {
    for byte in 0u8..=255 {
        if !growth_v19::depth_source_byte_ok(byte) {
            continue;
        }
        let pinned = byte & growth_v19::DEPTH_DEX_PINNED != 0;
        for mode in [None, Some(0u8), Some(1), Some(2)] {
            let want = !(pinned && mode == Some(growth_v19::DEPTH_MODE_ATTESTED));
            assert_eq!(growth_v19::depth_push_mode_allowed(byte, mode), want, "byte {byte:#04x} mode {mode:?}");
        }
    }
    assert!(growth_v19::depth_source_byte_ok(growth_v19::DEPTH_DEX_PINNED | growth_v19::DEPTH_EVER | growth_v19::DEPTH_PREV_REAL | 2));
    assert!(!growth_v19::depth_source_byte_ok(0x08) && !growth_v19::depth_source_byte_ok(0x10) && !growth_v19::depth_source_byte_ok(0x20));
    assert_eq!(growth_v19::depth_source_of(growth_v19::DEPTH_DEX_PINNED | 2), 2, "the bit is not a source");
}

/// SEC-RC L-1: the RC validator refuses a growth record with flags 0 and a non-empty depth
/// window (the shape the controller rollback refuses), and a window write migrates the record to
/// the round-3 layout first, so no legitimate write can produce that shape. On 75fca911 the
/// validator accepts it.
#[test]
fn l1_flags0_with_a_window_is_refused_and_window_writes_migrate() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    for _ in 0..3 {
        env.warp(1);
        env.push(1, 30_000_000_000, &[]).expect("depth pushes open the window");
    }
    let g = env.growth();
    assert!(g.depth_tw().bucket_p1 != 0, "setup: a window exists");
    assert_ne!(g.flags & growth_v19::GROWTH_FLAG_R3_LAYOUT, 0, "setup: the push migrated the record");
    state::validate_asset_growth(&g, ENGINE_IMR).expect("CONTROL: the real record validates");
    let mut bad = g;
    bad.flags = 0;
    assert!(state::validate_asset_growth(&bad, ENGINE_IMR).is_err(), "flags 0 with a window must be refused");
    let mut no_window = bad;
    no_window.set_depth_tw(growth_v19::DepthWindow { cur_tokens: 0, prev_tokens: 0, bucket_p1: 0 });
    no_window.vol_var_x100_le = [0; 4];
    no_window.rent_stamp64_le = [0; 4];
    state::validate_asset_growth(&no_window, ENGINE_IMR).expect("CONTROL: flags 0 without a window is the pre-round-3 shape");
    // a window write on a flags-0 record migrates it (bit 0 set, bytes 0..8 zeroed)
    let mut pre = no_window;
    pre.vol_var_x100_le = [7; 4];
    pre.set_depth_tw(g.depth_tw());
    assert_ne!(pre.flags & growth_v19::GROWTH_FLAG_R3_LAYOUT, 0, "set_depth_tw migrates first");
    assert_eq!(pre.vol_var_x100_le, [0; 4], "the retired c_launch bytes are zeroed by the migration");
    state::validate_asset_growth(&pre, ENGINE_IMR).expect("the migrated record validates");
    assert!(growth_v19::depth_tw_layout_ok(growth_v19::GROWTH_FLAG_R3_LAYOUT, g.depth_tw()));
    assert!(!growth_v19::depth_tw_layout_ok(0, g.depth_tw()));
    assert!(growth_v19::depth_tw_layout_ok(0, growth_v19::DepthWindow { cur_tokens: 0, prev_tokens: 0, bucket_p1: 0 }));
}

/// SEC-RC2 L-RC2-1: a stale keeper that sends ONLY mode-1 pushes to a DEX-pinned market keeps the
/// price live (every mark lands, so the stale clock never runs) while depth fails closed by age:
/// the last pool reading keeps its own slot, so after `DEPTH_MAX_AGE_SLOTS` it is no longer fresh,
/// and the attested values never appear anywhere. On RC2 (cc720a0e) every one of these pushes is
/// refused 129 and the mark freezes.
#[test]
fn l_rc2_1_mode1_on_pin_keeps_the_mark_live_and_depth_fails_closed_by_age() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.set_source(chill()).expect("pin");
    env.warp(1);
    let dex = env.dex_accounts(chill());
    env.push(2, 0, &dex).expect("mode 2: the pool reading");
    let pool = env.growth().depth_state();
    let last_pool_slot = env.slot;
    assert_eq!(pool.depth_e6, 2_027_034_782);
    for i in 0..4 {
        env.warp(50);
        env.mode1_on_pin_lands_mark_ignores_depth(1_000_000_000_000 + i, "stale keeper push");
    }
    let g = env.growth();
    assert_eq!(g.depth_state(), pool, "no attested value ever stored");
    assert!(env.slot - last_pool_slot > growth_v19::DEPTH_MAX_AGE_SLOTS, "setup: past the freshness bound");
    assert_eq!(
        growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot),
        None,
        "with no mode-2 reading the pool depth goes stale (fail closed for depth)"
    );
    // CONTROL: an honest mode-2 push refreshes it
    env.push(2, 0, &dex).expect("mode 2 again");
    let g = env.growth();
    assert!(growth_v19::fresh_depth_e6(g.depth_e6, g.depth_prev_e6, g.depth_slot, g.depth_source, env.slot).is_some());
}

/// SEC-RC2 L-RC2-1 control: on an UNPINNED market mode 1 is unchanged (the attested depth is
/// stored, source 1, and the mark lands).
#[test]
fn l_rc2_1_unpinned_mode1_unchanged() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    env.warp(1);
    let seq = env.oracle_seq();
    let mark = MARK + MARK / 100;
    let ix = env.push_ix(seq + 1, 1, 30_000_000_000, mark, &[]);
    let admin = env.admin.insecure_clone();
    env.send_ixs(vec![ix], &[&admin]).expect("mode 1 on an unpinned market");
    let g = env.growth();
    assert_eq!((g.depth_e6, growth_v19::depth_source_of(g.depth_source)), (30_000_000_000, growth_v19::DEPTH_SOURCE_ATTESTED));
    assert!(!growth_v19::depth_dex_pinned(g.depth_source));
    assert_eq!(state::read_asset_oracle_profile(&env.svm.get_account(&env.market).unwrap().data, 0).unwrap().oracle_target_price_e6, mark);
    assert_eq!(env.oracle_seq(), seq + 1);
}

/// Decision 16 (night 2026-10-28): one growth market per spot pool. Tag 123 claims the pinned pool for the
/// market (`["pool_claim", pool]`, kind 18); a pool claimed by ANOTHER market cannot be pinned (nothing is
/// written); the same market may re-pin; clearing the pin releases the claim (rent back to the UA), after
/// which the pool is free again. Wrong claim PDA and a foreign-owned claim account are refused.
#[test]
fn pool_claim_one_market_per_pool() {
    let mut env = Env::new(Pubkey::new_from_array([0x12; 32]));
    let pool = chill().pool.to_bytes();
    // pin: the claim is created for this market
    env.set_source(chill()).expect("pin creates the claim");
    let c = env.claim(&pool).expect("claim exists");
    assert_eq!(c.market, env.market.to_bytes());
    assert_eq!(c.pool, pool);
    // the same market re-pins: fine, still one claim
    env.warp(1);
    env.set_source(chill()).expect("same-market re-pin");
    assert_eq!(env.claim(&pool).unwrap().market, env.market.to_bytes());
    // clear: released (account emptied, lamports returned)
    let ua_before = env.svm.get_account(&env.ua.pubkey()).unwrap().lamports;
    env.warp(1);
    env.clear_source().expect("clear releases the claim");
    assert!(env.claim(&pool).is_none(), "claim released");
    assert!(env.svm.get_account(&env.ua.pubkey()).unwrap().lamports > ua_before - 10_000, "rent refunded (minus fees)");
    // ANOTHER market holds the claim (injected: a program-owned kind-18 record naming a different market):
    // the pin is refused and nothing is written
    let other = Pubkey::new_unique();
    let (cpda, bump) = state::derive_pool_claim(&env.program_id, &pool);
    let mut data = vec![0u8; state::pool_claim_account_len()];
    let rec = ds::PoolClaimV22 {
        pool,
        market: other.to_bytes(),
        asset_index: 0,
        version: ds::POOL_CLAIM_VERSION,
        bump,
        _reserved: [0; 12],
    };
    state::write_pool_claim(&mut data, &rec, true).unwrap();
    let acct = solana_sdk::account::Account { lamports: 10_000_000, data, owner: env.program_id, executable: false, rent_epoch: 0 };
    env.svm.set_account(cpda, acct.clone()).unwrap();
    let before = env.record();
    env.warp(1);
    let r = env.set_source(chill());
    assert!(r.as_ref().err().is_some_and(|e| e.contains("Custom(129)")), "claimed elsewhere: {r:?}");
    assert_eq!(env.record(), before, "pin not written");
    assert_eq!(env.claim(&pool).unwrap().market, other.to_bytes(), "the other market keeps its claim");
    // the same record owned by another program is not a claim: refused
    let mut foreign = acct.clone();
    foreign.owner = Pubkey::new_unique();
    env.svm.set_account(cpda, foreign).unwrap();
    env.warp(1);
    assert!(env.set_source(chill()).is_err(), "foreign-owned claim account");
    // a wrong claim PDA in [10]: refused
    env.svm.set_account(cpda, solana_sdk::account::Account { lamports: 0, data: vec![], owner: solana_sdk::system_program::id(), executable: false, rent_epoch: 0 }).unwrap();
    let (ua, pda) = (env.ua.insecure_clone(), env.pda());
    let k = chill();
    let mut accounts = vec![
        AccountMeta::new(ua.pubkey(), true),
        AccountMeta::new_readonly(env.program_data, false),
        AccountMeta::new(env.market, false),
        AccountMeta::new(pda, false),
        AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
    ];
    for a in [k.pool, k.base_vault, k.quote_vault, k.base_mint, k.quote_mint] {
        accounts.push(AccountMeta::new_readonly(a, false));
    }
    accounts.push(AccountMeta::new(Pubkey::new_unique(), false));
    env.warp(1);
    let r = env.send(ProgInstruction::SetDepthSource { op: 1, asset_index: 0, market_id: 1 }, accounts, &[&ua]);
    assert!(r.as_ref().err().is_some_and(|e| e.contains("Custom(129)")), "wrong claim PDA: {r:?}");
    // free again: the pin lands and claims it
    env.warp(1);
    env.set_source(chill()).expect("unclaimed pool pins");
    assert_eq!(env.claim(&pool).unwrap().market, env.market.to_bytes());
}
