//! v2.2 (prog#542): the LP / Earn share mint's wallet-facing identity.
//!
//! Pure helpers behind tag 122 `InitLpShareMetadata`: the token name, symbol and uri, the
//! Metaplex Token Metadata instruction data, and the reader that tells a GENERIC record from a
//! named one. Free of `AccountInfo` and syscalls so every function is unit-tested on the host.
//!
//! Two forms, both built here from the market address and (optionally) a ticker:
//!
//! ```text
//! generic (anyone):      name   = "Percolator Earn Share " + first 8 base58 chars of the market
//!                        symbol = "pEARN"                              (record stays MUTABLE)
//! ticker  (marketauth):  name   = "Percolator Earn " + TICKER + " " + first 6 base58 chars
//!                        symbol = "pe" + TICKER                        (record is IMMUTABLE)
//! both:                  uri    = LP_SHARE_URI_BASE + "/api/earn-share/" + market (base58)
//! ```
//!
//! IMPERSONATION RULE (security review R9). The ticker is CREATOR-CHOSEN AND UNVERIFIED (the
//! program stores no token identity for a market; the creator of a junk market can call it
//! `USDC`). What the caller can never remove is the framing, and the framing LEADS: every name
//! starts with `Percolator Earn `, so a wallet that truncates the name still shows it; the
//! symbol always starts with lowercase `pe`, while a ticker is `A-Z 0-9` only, so a share
//! symbol can never equal a ticker. The name also ends with a fragment of the market address,
//! so two markets that pick the same ticker do not get the same name (they do get the same
//! symbol: `pe` + 8 leaves no room in Metaplex's 10 bytes). The uri takes no caller input.

extern crate alloc;
use alloc::vec::Vec;
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
};

/// The Metaplex Token Metadata program (same id on devnet and mainnet): the only CPI target.
pub const MPL_PROGRAM_ID: Pubkey = crate::constants::MPL_TOKEN_METADATA_PROGRAM_ID;

/// Generic name prefix (22 bytes, trailing space included).
pub const LP_SHARE_NAME_PREFIX: &[u8; 22] = b"Percolator Earn Share ";
/// How many base58 characters of the market address follow the generic prefix.
pub const LP_SHARE_NAME_MARKET_CHARS: usize = 8;
/// Generic name length: 30 bytes.
pub const LP_SHARE_GENERIC_NAME_LEN: usize = 22 + LP_SHARE_NAME_MARKET_CHARS;
/// Generic symbol.
pub const LP_SHARE_GENERIC_SYMBOL: &[u8; 5] = b"pEARN";
/// Ticker-form name prefix (16 bytes, trailing space included). It LEADS the name and the
/// caller cannot remove or alter it. It is also a prefix of the generic name.
pub const LP_SHARE_TICKER_NAME_PREFIX: &[u8; 16] = b"Percolator Earn ";
/// How many base58 characters of the market address end a ticker-form name.
pub const LP_SHARE_TICKER_NAME_MARKET_CHARS: usize = 6;
/// Ticker-form symbol prefix. Lowercase, so it can never be produced by a ticker.
pub const LP_SHARE_SYMBOL_PREFIX: &[u8; 2] = b"pe";
/// Longest ticker: 8, set by Metaplex's 10-byte symbol (`pe` + 8). The name is then 31 bytes.
pub const LP_SHARE_TICKER_MAX: usize = 8;

/// Metaplex limits.
pub const MPL_MAX_NAME_LEN: usize = 32;
pub const MPL_MAX_SYMBOL_LEN: usize = 10;
pub const MPL_MAX_URI_LEN: usize = 200;

const _: () = assert!(LP_SHARE_GENERIC_NAME_LEN <= MPL_MAX_NAME_LEN);
const _: () = assert!(LP_SHARE_GENERIC_SYMBOL.len() <= MPL_MAX_SYMBOL_LEN);
const _: () = assert!(
    LP_SHARE_TICKER_NAME_PREFIX.len() + LP_SHARE_TICKER_MAX + 1 + LP_SHARE_TICKER_NAME_MARKET_CHARS
        <= MPL_MAX_NAME_LEN
);
const _: () = assert!(LP_SHARE_SYMBOL_PREFIX.len() + LP_SHARE_TICKER_MAX <= MPL_MAX_SYMBOL_LEN);

/// Where the share token's JSON metadata is served, devnet builds (`--features devnet`).
pub const LP_SHARE_URI_BASE_DEVNET: &str = "https://play.percolator.trade";
/// Where it is served, mainnet builds. FOUNDER DECISION: this is the default chosen by the
/// builder; confirm or change it before a mainnet build. A ticker record is immutable, so its
/// uri can NEVER be corrected: whoever controls this domain controls what wallets show for the
/// share token, for good (security review R10). `scripts/check-mainnet-sbf.sh` asserts this
/// exact string is in the mainnet `.so`.
pub const LP_SHARE_URI_BASE_MAINNET: &str = "https://percolator.trade";
/// The base compiled into THIS build.
#[cfg(feature = "devnet")]
pub const LP_SHARE_URI_BASE: &str = LP_SHARE_URI_BASE_DEVNET;
#[cfg(not(feature = "devnet"))]
pub const LP_SHARE_URI_BASE: &str = LP_SHARE_URI_BASE_MAINNET;
/// Path between the base and the market address.
pub const LP_SHARE_URI_PATH: &str = "/api/earn-share/";
/// Longest uri this build can produce (a base58 address is at most 44 characters).
pub const LP_SHARE_URI_MAX_LEN: usize = LP_SHARE_URI_BASE.len() + LP_SHARE_URI_PATH.len() + 44;
const _: () = assert!(LP_SHARE_URI_MAX_LEN <= MPL_MAX_URI_LEN);

/// Seed of the transient fee-payer PDA `["lp_share_meta_payer", lp_mint]` (security review R3):
/// system-owned, no data, funded and drained inside tag 122. It is the ONLY payer handed to
/// Metaplex, so no user signature and no marketauth signature ever enters that CPI.
pub const LP_SHARE_META_PAYER_SEED: &[u8] = b"lp_share_meta_payer";
/// Lamports moved into the fee-payer PDA before the create CPI; whatever Metaplex does not take
/// (rent for the record + its create fee, 15,115,600 today) is returned to the caller in the
/// same instruction. This is also the most a hostile Metaplex upgrade could take per call.
pub const LP_SHARE_META_FUND_LAMPORTS: u64 = 30_000_000;

const _: () = assert!(LP_SHARE_URI_BASE_DEVNET.len() + LP_SHARE_URI_PATH.len() + 44 <= MPL_MAX_URI_LEN);
const _: () = assert!(LP_SHARE_URI_BASE_MAINNET.len() + LP_SHARE_URI_PATH.len() + 44 <= MPL_MAX_URI_LEN);

/// Metaplex Token Metadata instruction discriminators.
pub const MPL_IX_CREATE_METADATA_ACCOUNT_V3: u8 = 33;
pub const MPL_IX_UPDATE_METADATA_ACCOUNT_V2: u8 = 15;
/// Seed prefix of the Metaplex metadata PDA: `["metadata", token_metadata_program, mint]`.
pub const MPL_METADATA_SEED: &[u8] = b"metadata";
/// `Key::MetadataV1`, the first byte of a Metaplex metadata account.
pub const MPL_KEY_METADATA_V1: u8 = 4;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 of a 32-byte key (the string every explorer shows): the bytes and their count
/// (32..=44).
pub fn base58_encode(key: &[u8; 32]) -> ([u8; 44], usize) {
    // Little-endian base-58 digits; 32 bytes need at most 44.
    let mut digits = [0u8; 45];
    let mut len = 0usize;
    for &byte in key.iter() {
        let mut carry = byte as u32;
        let mut i = 0usize;
        while i < len {
            carry += (digits[i] as u32) << 8;
            digits[i] = (carry % 58) as u8;
            carry /= 58;
            i += 1;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            carry /= 58;
            len += 1;
        }
    }
    let zeros = key.iter().take_while(|b| **b == 0).count();
    let mut out = [b'1'; 44];
    let mut k = zeros;
    let mut d = len;
    while d > 0 {
        d -= 1;
        out[k] = B58[digits[d] as usize];
        k += 1;
    }
    (out, k)
}

/// A ticker the program accepts: 1..=8 bytes, each `A-Z` or `0-9`.
pub fn ticker_ok(ticker: &[u8]) -> bool {
    !ticker.is_empty()
        && ticker.len() <= LP_SHARE_TICKER_MAX
        && ticker.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// The generic name for `market`.
pub fn generic_name(market: &[u8; 32]) -> [u8; LP_SHARE_GENERIC_NAME_LEN] {
    let mut out = [0u8; LP_SHARE_GENERIC_NAME_LEN];
    out[..22].copy_from_slice(LP_SHARE_NAME_PREFIX);
    let (b58, _) = base58_encode(market);
    out[22..].copy_from_slice(&b58[..LP_SHARE_NAME_MARKET_CHARS]);
    out
}

/// `"Percolator Earn " + TICKER + " " + first 6 base58 characters of the market`. `None`
/// unless `ticker_ok`.
pub fn ticker_name(market: &[u8; 32], ticker: &[u8]) -> Option<Vec<u8>> {
    if !ticker_ok(ticker) {
        return None;
    }
    let (b58, _) = base58_encode(market);
    let mut out = Vec::with_capacity(MPL_MAX_NAME_LEN);
    out.extend_from_slice(LP_SHARE_TICKER_NAME_PREFIX);
    out.extend_from_slice(ticker);
    out.push(b' ');
    out.extend_from_slice(&b58[..LP_SHARE_TICKER_NAME_MARKET_CHARS]);
    Some(out)
}

/// `"pe" + TICKER`. `None` unless `ticker_ok`.
pub fn ticker_symbol(ticker: &[u8]) -> Option<Vec<u8>> {
    if !ticker_ok(ticker) {
        return None;
    }
    let mut out = Vec::with_capacity(MPL_MAX_SYMBOL_LEN);
    out.extend_from_slice(LP_SHARE_SYMBOL_PREFIX);
    out.extend_from_slice(ticker);
    Some(out)
}

/// `LP_SHARE_URI_BASE + "/api/earn-share/" + base58(market)`: no caller input.
pub fn share_uri(market: &[u8; 32]) -> Vec<u8> {
    share_uri_with_base(LP_SHARE_URI_BASE, market)
}

/// The uri for an explicit base (tests pin both compile-time bases through this).
pub fn share_uri_with_base(base: &str, market: &[u8; 32]) -> Vec<u8> {
    let (b58, n) = base58_encode(market);
    let mut out = Vec::with_capacity(base.len() + LP_SHARE_URI_PATH.len() + n);
    out.extend_from_slice(base.as_bytes());
    out.extend_from_slice(LP_SHARE_URI_PATH.as_bytes());
    out.extend_from_slice(&b58[..n]);
    out
}

/// Name, symbol and uri for `market`: the ticker form when `ticker` is non-empty, else the
/// generic form. `None` for a ticker that is not `ticker_ok`.
pub fn share_identity(market: &[u8; 32], ticker: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let uri = share_uri(market);
    if ticker.is_empty() {
        return Some((generic_name(market).to_vec(), LP_SHARE_GENERIC_SYMBOL.to_vec(), uri));
    }
    Some((ticker_name(market, ticker)?, ticker_symbol(ticker)?, uri))
}

fn push_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
}

/// Borsh `DataV2 { name, symbol, uri, seller_fee_basis_points: 0, creators: None,
/// collection: None, uses: None }`.
fn push_data_v2(out: &mut Vec<u8>, name: &[u8], symbol: &[u8], uri: &[u8]) {
    push_str(out, name);
    push_str(out, symbol);
    push_str(out, uri);
    out.extend_from_slice(&[0, 0]); // seller_fee_basis_points
    out.extend_from_slice(&[0, 0, 0]); // creators, collection, uses: None
}

/// Metaplex `CreateMetadataAccountV3` data: `DataV2`, `is_mutable`, `collection_details: None`.
/// The generic record is created mutable (it can still be upgraded or repaired); the ticker
/// record is created immutable.
pub fn create_metadata_v3_data(name: &[u8], symbol: &[u8], uri: &[u8], is_mutable: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 12 + name.len() + symbol.len() + uri.len() + 7);
    out.push(MPL_IX_CREATE_METADATA_ACCOUNT_V3);
    push_data_v2(&mut out, name, symbol, uri);
    out.push(is_mutable as u8);
    out.push(0); // collection_details: None
    out
}

/// Metaplex `UpdateMetadataAccountV2` data (security review R4): `data: Some(DataV2)` with
/// seller fee 0 and `creators` / `collection` / `uses` = `None`; `new_update_authority: None`
/// (the registry PDA stays the authority, always); `primary_sale_happened: None`;
/// `is_mutable: Some(false)` when `freeze` (the ticker upgrade), else `None`.
pub fn update_metadata_v2_data(name: &[u8], symbol: &[u8], uri: &[u8], freeze: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 12 + name.len() + symbol.len() + uri.len() + 9);
    out.push(MPL_IX_UPDATE_METADATA_ACCOUNT_V2);
    out.push(1); // data: Some
    push_data_v2(&mut out, name, symbol, uri);
    out.push(0); // new_update_authority: None
    out.push(0); // primary_sale_happened: None
    if freeze {
        out.extend_from_slice(&[1, 0]); // is_mutable: Some(false)
    } else {
        out.push(0); // is_mutable: None
    }
    out
}

/// THE create CPI (security review R1 / R2 / R3). Exactly six accounts, in Metaplex's order:
/// metadata (writable), mint (**read-only**), mint authority = registry PDA (signer),
/// payer = the transient fee-payer PDA (signer, writable), update authority = registry PDA,
/// system program. There is no parameter through which a user, a marketauth, a token program,
/// a token account or a market could be added.
#[allow(clippy::too_many_arguments)]
pub fn create_metadata_ix(
    metadata: &Pubkey,
    mint: &Pubkey,
    registry: &Pubkey,
    meta_payer: &Pubkey,
    name: &[u8],
    symbol: &[u8],
    uri: &[u8],
    is_mutable: bool,
) -> Instruction {
    Instruction {
        program_id: MPL_PROGRAM_ID,
        accounts: [
            AccountMeta::new(*metadata, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*registry, true),
            AccountMeta::new(*meta_payer, true),
            AccountMeta::new_readonly(*registry, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ]
        .to_vec(),
        data: create_metadata_v3_data(name, symbol, uri, is_mutable),
    }
}

/// THE update CPI (security review R4). Exactly two accounts: metadata (writable) and the
/// update authority = registry PDA (read-only signer). No payer, no mint.
pub fn update_metadata_ix(
    metadata: &Pubkey,
    registry: &Pubkey,
    name: &[u8],
    symbol: &[u8],
    uri: &[u8],
    freeze: bool,
) -> Instruction {
    Instruction {
        program_id: MPL_PROGRAM_ID,
        accounts: [
            AccountMeta::new(*metadata, false),
            AccountMeta::new_readonly(*registry, true),
        ]
        .to_vec(),
        data: update_metadata_v2_data(name, symbol, uri, freeze),
    }
}

/// What an existing Metaplex metadata account is to this program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordState {
    /// Not a `MetadataV1` this program can act on: wrong key byte, another mint, an update
    /// authority that is not the registry PDA, or a layout that does not parse. Nothing is
    /// signed for it.
    NotOurs,
    /// Ours and frozen (`is_mutable == false`): final. Metaplex itself refuses data changes.
    Immutable,
    /// Ours and mutable. `canonical_generic` = it already carries exactly the generic content
    /// (name, symbol, uri, seller fee 0, no creators).
    Mutable { canonical_generic: bool },
}

fn take<'a>(data: &'a [u8], o: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = o.checked_add(n)?;
    let s = data.get(*o..end)?;
    *o = end;
    Some(s)
}

fn take_str<'a>(data: &'a [u8], o: &mut usize, max: usize) -> Option<&'a [u8]> {
    let n = take(data, o, 4)?;
    let n = u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize;
    if n > max {
        return None;
    }
    let s = take(data, o, n)?;
    // Metaplex has padded these with NUL bytes in some versions: compare without the padding.
    let end = s.iter().rposition(|b| *b != 0).map(|p| p + 1).unwrap_or(0);
    Some(&s[..end])
}

/// Classify the bytes of an existing metadata account (security review R6 / R8). The `once`
/// latch is `is_mutable`, a flag Metaplex itself enforces, not something inferred from the
/// name. Never panics: any byte string that does not parse is `NotOurs`.
pub fn record_state(data: &[u8], registry: &[u8; 32], mint: &[u8; 32], market: &[u8; 32]) -> RecordState {
    let parsed = (|| {
        let mut o = 0usize;
        if take(data, &mut o, 1)? != [MPL_KEY_METADATA_V1] {
            return None;
        }
        if take(data, &mut o, 32)? != registry || take(data, &mut o, 32)? != mint {
            return None;
        }
        let name = take_str(data, &mut o, MPL_MAX_NAME_LEN)?;
        let symbol = take_str(data, &mut o, MPL_MAX_SYMBOL_LEN)?;
        let uri = take_str(data, &mut o, MPL_MAX_URI_LEN)?;
        let fee = take(data, &mut o, 2)?;
        let has_creators = match take(data, &mut o, 1)? {
            [0] => false,
            [1] => {
                let n = take(data, &mut o, 4)?;
                let n = u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize;
                if n > 5 {
                    return None;
                }
                take(data, &mut o, n * 34)?;
                true
            }
            _ => return None,
        };
        take(data, &mut o, 1)?; // primary_sale_happened
        let is_mutable = match take(data, &mut o, 1)? {
            [0] => false,
            [1] => true,
            _ => return None,
        };
        if !is_mutable {
            return Some(RecordState::Immutable);
        }
        let canonical_generic = name == generic_name(market)
            && symbol == LP_SHARE_GENERIC_SYMBOL
            && uri == share_uri(market).as_slice()
            && fee == [0, 0]
            && !has_creators;
        Some(RecordState::Mutable { canonical_generic })
    })();
    parsed.unwrap_or(RecordState::NotOurs)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use solana_program::pubkey::Pubkey;
    use std::{string::String, string::ToString, vec};

    fn s(b: &[u8]) -> String {
        String::from_utf8(b.to_vec()).unwrap()
    }

    fn check_b58(key: [u8; 32]) {
        let want = Pubkey::new_from_array(key).to_string();
        let (got, n) = base58_encode(&key);
        assert_eq!(s(&got[..n]), want, "key {key:?}");
    }

    #[test]
    fn base58_matches_pubkey_display() {
        check_b58([0u8; 32]);
        check_b58([0xff; 32]);
        let mut k = [0u8; 32];
        k[31] = 1;
        check_b58(k);
        for z in 1..=31usize {
            let mut k = [0xabu8; 32];
            for b in k.iter_mut().take(z) {
                *b = 0;
            }
            check_b58(k);
        }
        let mut st: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2_000 {
            let mut k = [0u8; 32];
            for b in k.iter_mut() {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                *b = st as u8;
            }
            check_b58(k);
        }
        for _ in 0..200 {
            check_b58(Pubkey::new_unique().to_bytes());
        }
    }

    #[test]
    fn uri_bases_are_pinned() {
        assert_eq!(LP_SHARE_URI_BASE_DEVNET, "https://play.percolator.trade");
        assert_eq!(LP_SHARE_URI_BASE_MAINNET, "https://percolator.trade");
        assert_eq!(LP_SHARE_URI_PATH, "/api/earn-share/");
        #[cfg(feature = "devnet")]
        assert_eq!(LP_SHARE_URI_BASE, LP_SHARE_URI_BASE_DEVNET);
        #[cfg(not(feature = "devnet"))]
        assert_eq!(LP_SHARE_URI_BASE, LP_SHARE_URI_BASE_MAINNET);
        for base in [LP_SHARE_URI_BASE_DEVNET, LP_SHARE_URI_BASE_MAINNET] {
            assert!(base.starts_with("https://") && !base.ends_with('/'));
        }
    }

    #[test]
    fn uri_is_exactly_base_path_market_and_fits() {
        for key in [[0u8; 32], [0xff; 32], Pubkey::new_unique().to_bytes()] {
            let m = Pubkey::new_from_array(key).to_string();
            assert_eq!(s(&share_uri_with_base(LP_SHARE_URI_BASE_DEVNET, &key)), std::format!("https://play.percolator.trade/api/earn-share/{m}"));
            assert_eq!(s(&share_uri_with_base(LP_SHARE_URI_BASE_MAINNET, &key)), std::format!("https://percolator.trade/api/earn-share/{m}"));
            assert_eq!(s(&share_uri(&key)), std::format!("{LP_SHARE_URI_BASE}/api/earn-share/{m}"));
            assert!(share_uri(&key).len() <= LP_SHARE_URI_MAX_LEN && LP_SHARE_URI_MAX_LEN <= MPL_MAX_URI_LEN);
        }
    }

    #[test]
    fn ticker_charset_and_length() {
        for ok in ["A", "Z", "0", "9", "SOL", "BURNIE", "1000PEPE", "ABCDEFGH"] {
            assert!(ticker_ok(ok.as_bytes()), "{ok}");
        }
        for bad in ["", "ABCDEFGHI", "sol", "Sol", "SO L", "SOL ", " SOL", "SOL-", "SO.L", "$SOL", "SOL\0", "S\u{00d6}L", "USDC\n"] {
            assert!(!ticker_ok(bad.as_bytes()), "{bad:?}");
            if !bad.is_empty() {
                assert!(share_identity(&[1; 32], bad.as_bytes()).is_none(), "{bad:?}");
            }
        }
        // every single byte value: only A-Z and 0-9 pass
        for b in 0u8..=255 {
            assert_eq!(ticker_ok(&[b]), b.is_ascii_uppercase() || b.is_ascii_digit(), "byte {b}");
        }
    }

    /// The framing LEADS every name, for EVERY accepted ticker, and the limits hold at the
    /// maximum ticker length.
    #[test]
    fn framing_leads_and_names_fit() {
        let market = Pubkey::new_unique().to_bytes();
        let m = Pubkey::new_from_array(market).to_string();
        for t in ["A", "SOL", "USDC", "BURNIE", "ABCDEFGH", "99999999"] {
            let (name, symbol, uri) = share_identity(&market, t.as_bytes()).unwrap();
            assert_eq!(s(&name), std::format!("Percolator Earn {t} {}", &m[..6]));
            assert_eq!(s(&symbol), std::format!("pe{t}"));
            assert!(name.starts_with(b"Percolator Earn "), "the framing leads");
            assert!(symbol.starts_with(b"pe"));
            assert!(name.len() <= MPL_MAX_NAME_LEN && symbol.len() <= MPL_MAX_SYMBOL_LEN);
            // a share symbol can never itself be a ticker (lowercase prefix)
            assert!(!ticker_ok(&symbol));
            assert_eq!(uri, share_uri(&market));
        }
        assert_eq!(ticker_name(&market, b"ABCDEFGH").unwrap().len(), 31);
        assert_eq!(ticker_symbol(b"ABCDEFGH").unwrap().len(), 10);
        // generic: same leading framing
        let (name, symbol, uri) = share_identity(&market, b"").unwrap();
        assert_eq!(s(&name), std::format!("Percolator Earn Share {}", &m[..8]));
        assert!(name.starts_with(LP_SHARE_TICKER_NAME_PREFIX));
        assert_eq!(s(&symbol), "pEARN");
        assert_eq!(uri, share_uri(&market));
    }

    /// Two markets with the SAME ticker do not get the same name (the fragment is a
    /// disambiguator, not proof of authenticity: 6 base58 characters can be ground).
    #[test]
    fn same_ticker_on_two_markets_gives_different_names() {
        let (a, b) = (Pubkey::new_from_array([0xaa; 32]), Pubkey::new_from_array([0x55; 32]));
        let na = ticker_name(&a.to_bytes(), b"1000PEPE").unwrap();
        let nb = ticker_name(&b.to_bytes(), b"1000PEPE").unwrap();
        assert_ne!(na, nb);
        assert_eq!(s(&na), std::format!("Percolator Earn 1000PEPE {}", &a.to_string()[..6]));
        assert_eq!(s(&nb), std::format!("Percolator Earn 1000PEPE {}", &b.to_string()[..6]));
        assert_eq!(na.len(), 31);
    }

    /// R4: byte-exact instruction data.
    #[test]
    fn instruction_data_is_the_expected_borsh() {
        let (name, symbol, uri) = (&b"Percolator Earn SOL Azaggu"[..], &b"peSOL"[..], &b"https://x/y"[..]);
        let mut body = vec![];
        body.extend_from_slice(&26u32.to_le_bytes());
        body.extend_from_slice(name);
        body.extend_from_slice(&5u32.to_le_bytes());
        body.extend_from_slice(symbol);
        body.extend_from_slice(&11u32.to_le_bytes());
        body.extend_from_slice(uri);
        body.extend_from_slice(&[0, 0]); // seller_fee_basis_points = 0
        body.push(0); // creators: None
        body.push(0); // collection: None
        body.push(0); // uses: None
        for mutable in [true, false] {
            let mut want = vec![33u8];
            want.extend_from_slice(&body);
            want.push(mutable as u8); // is_mutable
            want.push(0); // collection_details: None
            assert_eq!(create_metadata_v3_data(name, symbol, uri, mutable), want);
        }
        // update, generic repair: stays mutable
        let mut want = vec![15u8, 1];
        want.extend_from_slice(&body);
        want.push(0); // new_update_authority: None
        want.push(0); // primary_sale_happened: None
        want.push(0); // is_mutable: None
        assert_eq!(update_metadata_v2_data(name, symbol, uri, false), want);
        // update, ticker upgrade: freeze
        let mut want = vec![15u8, 1];
        want.extend_from_slice(&body);
        want.push(0); // new_update_authority: None
        want.push(0); // primary_sale_happened: None
        want.extend_from_slice(&[1, 0]); // is_mutable: Some(false)
        assert_eq!(update_metadata_v2_data(name, symbol, uri, true), want);
        // only discriminators 33 and 15 are ever produced (R1)
        assert_eq!((MPL_IX_CREATE_METADATA_ACCOUNT_V3, MPL_IX_UPDATE_METADATA_ACCOUNT_V2), (33, 15));
    }

    /// R1 / R2 / R3 / R4: the exact account lists of the two CPIs.
    #[test]
    fn cpi_account_lists_are_exact() {
        let (md, mint, reg, pp) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let mpl: Pubkey = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s".parse().unwrap();
        let c = create_metadata_ix(&md, &mint, &reg, &pp, b"n", b"s", b"u", true);
        assert_eq!(c.program_id, mpl);
        assert_eq!(
            c.accounts,
            vec![
                AccountMeta::new(md, false),
                AccountMeta::new_readonly(mint, false), // the mint is NEVER writable
                AccountMeta::new_readonly(reg, true),
                AccountMeta::new(pp, true),
                AccountMeta::new_readonly(reg, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ]
        );
        assert_eq!(c.data[0], 33);
        // the only signers are the two PDAs of this program
        assert!(c.accounts.iter().filter(|a| a.is_signer).all(|a| a.pubkey == reg || a.pubkey == pp));
        let u = update_metadata_ix(&md, &reg, b"n", b"s", b"u", true);
        assert_eq!(u.program_id, mpl);
        assert_eq!(u.accounts, vec![AccountMeta::new(md, false), AccountMeta::new_readonly(reg, true)]);
        assert_eq!(u.data[0], 15);
    }

    #[allow(clippy::too_many_arguments)]
    fn rec(auth: [u8; 32], mint: [u8; 32], name: &[u8], symbol: &[u8], uri: &[u8], fee: u16, creators: usize, mutable: u8) -> std::vec::Vec<u8> {
        let mut d = vec![MPL_KEY_METADATA_V1];
        d.extend_from_slice(&auth);
        d.extend_from_slice(&mint);
        for f in [name, symbol, uri] {
            d.extend_from_slice(&(f.len() as u32).to_le_bytes());
            d.extend_from_slice(f);
        }
        d.extend_from_slice(&fee.to_le_bytes());
        if creators == 0 {
            d.push(0);
        } else {
            d.push(1);
            d.extend_from_slice(&(creators as u32).to_le_bytes());
            d.extend_from_slice(&vec![7u8; creators * 34]);
        }
        d.push(0); // primary sale
        d.push(mutable);
        d.extend_from_slice(&[0u8; 60]);
        d
    }

    #[test]
    fn record_state_classification() {
        let (reg, mint, market) = ([1u8; 32], [2u8; 32], Pubkey::new_unique().to_bytes());
        let (g, gs, u) = (generic_name(&market), LP_SHARE_GENERIC_SYMBOL, share_uri(&market));
        let canon = RecordState::Mutable { canonical_generic: true };
        let stale = RecordState::Mutable { canonical_generic: false };
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 0, 0, 1), &reg, &mint, &market), canon);
        // NUL-padded strings (older Metaplex versions pad)
        let mut padded = g.to_vec();
        padded.extend_from_slice(&[0, 0]);
        assert_eq!(record_state(&rec(reg, mint, &padded, b"pEARN\0\0\0\0\0", &u, 0, 0, 1), &reg, &mint, &market), canon);
        // mutable, ours, but not the canonical generic content: every field matters
        assert_eq!(record_state(&rec(reg, mint, b"USDC", gs, &u, 0, 0, 1), &reg, &mint, &market), stale);
        assert_eq!(record_state(&rec(reg, mint, &g, b"USDC", &u, 0, 0, 1), &reg, &mint, &market), stale);
        assert_eq!(record_state(&rec(reg, mint, &g, gs, b"https://evil.example/x", 0, 0, 1), &reg, &mint, &market), stale);
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 500, 0, 1), &reg, &mint, &market), stale);
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 0, 2, 1), &reg, &mint, &market), stale);
        assert_eq!(record_state(&rec(reg, mint, &generic_name(&[9; 32]), gs, &u, 0, 0, 1), &reg, &mint, &market), stale);
        // frozen: final whatever it says
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 0, 0, 0), &reg, &mint, &market), RecordState::Immutable);
        assert_eq!(record_state(&rec(reg, mint, b"USDC", b"USDC", b"", 0, 0, 0), &reg, &mint, &market), RecordState::Immutable);
        // not ours
        assert_eq!(record_state(&rec([7; 32], mint, &g, gs, &u, 0, 0, 1), &reg, &mint, &market), RecordState::NotOurs);
        assert_eq!(record_state(&rec(reg, [7; 32], &g, gs, &u, 0, 0, 1), &reg, &mint, &market), RecordState::NotOurs);
        let mut bad = rec(reg, mint, &g, gs, &u, 0, 0, 1);
        bad[0] = 0;
        assert_eq!(record_state(&bad, &reg, &mint, &market), RecordState::NotOurs);
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 0, 0, 2), &reg, &mint, &market), RecordState::NotOurs);
        assert_eq!(record_state(&rec(reg, mint, &g, gs, &u, 0, 6, 1), &reg, &mint, &market), RecordState::NotOurs);
        // every truncation of a valid record, and absurd lengths: never a panic, never "ours"
        let full = rec(reg, mint, &g, gs, &u, 0, 0, 1);
        let end = 1 + 64 + 4 + g.len() + 4 + gs.len() + 4 + u.len() + 2 + 1 + 1 + 1;
        for n in 0..end {
            assert_eq!(record_state(&full[..n], &reg, &mint, &market), RecordState::NotOurs, "len {n}");
        }
        assert_eq!(record_state(&full[..end], &reg, &mint, &market), canon);
        for off in [65usize, 69 + g.len()] {
            let mut huge = full.clone();
            huge[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(record_state(&huge, &reg, &mint, &market), RecordState::NotOurs);
        }
    }
}
