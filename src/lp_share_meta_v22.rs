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
//!                        symbol = "pEARN"
//! ticker  (marketauth):  name   = TICKER + " Earn Share - Percolator"
//!                        symbol = "pe" + TICKER
//! both:                  uri    = LP_SHARE_URI_BASE + "/api/earn-share/" + market (base58)
//! ```
//!
//! IMPERSONATION RULE. The ticker is CREATOR-CHOSEN AND UNVERIFIED (the program stores no token
//! identity for a market; the creator of a junk market can call it `USDC`). What the caller can
//! never remove is the framing: the name always ends in ` Earn Share - Percolator` and the
//! symbol always starts with lowercase `pe`, while a ticker is `A-Z 0-9` only, so a share
//! token's symbol can never equal a ticker and its name can never be a bare asset name. The uri
//! takes no caller input at all.
//!
//! Why ` - ` and not ` · `: Metaplex caps the name at 32 BYTES and `·` is two. With the
//! 8-character ticker the symbol limit allows, `TICKER Earn Share · Percolator` would be 33.

extern crate alloc;
use alloc::vec::Vec;

/// Generic name prefix (22 bytes, trailing space included).
pub const LP_SHARE_NAME_PREFIX: &[u8; 22] = b"Percolator Earn Share ";
/// How many base58 characters of the market address follow the generic prefix.
pub const LP_SHARE_NAME_MARKET_CHARS: usize = 8;
/// Generic name length: 30 bytes.
pub const LP_SHARE_GENERIC_NAME_LEN: usize = 22 + LP_SHARE_NAME_MARKET_CHARS;
/// Generic symbol.
pub const LP_SHARE_GENERIC_SYMBOL: &[u8; 5] = b"pEARN";
/// Ticker-form name suffix (24 bytes). The caller cannot remove or alter it.
pub const LP_SHARE_NAME_SUFFIX: &[u8; 24] = b" Earn Share - Percolator";
/// Ticker-form symbol prefix. Lowercase, so it can never be produced by a ticker.
pub const LP_SHARE_SYMBOL_PREFIX: &[u8; 2] = b"pe";
/// Longest ticker: 8, set by Metaplex's 10-byte symbol (`pe` + 8). The name is then exactly 32.
pub const LP_SHARE_TICKER_MAX: usize = 8;

/// Metaplex limits.
pub const MPL_MAX_NAME_LEN: usize = 32;
pub const MPL_MAX_SYMBOL_LEN: usize = 10;
pub const MPL_MAX_URI_LEN: usize = 200;

const _: () = assert!(LP_SHARE_GENERIC_NAME_LEN <= MPL_MAX_NAME_LEN);
const _: () = assert!(LP_SHARE_GENERIC_SYMBOL.len() <= MPL_MAX_SYMBOL_LEN);
const _: () = assert!(LP_SHARE_TICKER_MAX + LP_SHARE_NAME_SUFFIX.len() <= MPL_MAX_NAME_LEN);
const _: () = assert!(LP_SHARE_SYMBOL_PREFIX.len() + LP_SHARE_TICKER_MAX <= MPL_MAX_SYMBOL_LEN);

/// Where the share token's JSON metadata is served, devnet builds (`--features devnet`).
pub const LP_SHARE_URI_BASE_DEVNET: &str = "https://play.percolator.trade";
/// Where it is served, mainnet builds. FOUNDER DECISION: this is the default chosen by the
/// builder; confirm or change it before a mainnet build (the uri of a named record can only be
/// corrected by a later program upgrade that adds an update path).
pub const LP_SHARE_URI_BASE_MAINNET: &str = "https://percolator.trade";
/// The base compiled into THIS build.
#[cfg(feature = "devnet")]
pub const LP_SHARE_URI_BASE: &str = LP_SHARE_URI_BASE_DEVNET;
#[cfg(not(feature = "devnet"))]
pub const LP_SHARE_URI_BASE: &str = LP_SHARE_URI_BASE_MAINNET;
/// Path between the base and the market address.
pub const LP_SHARE_URI_PATH: &str = "/api/earn-share/";

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

/// `TICKER + " Earn Share - Percolator"`. `None` unless `ticker_ok`.
pub fn ticker_name(ticker: &[u8]) -> Option<Vec<u8>> {
    if !ticker_ok(ticker) {
        return None;
    }
    let mut out = Vec::with_capacity(MPL_MAX_NAME_LEN);
    out.extend_from_slice(ticker);
    out.extend_from_slice(LP_SHARE_NAME_SUFFIX);
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
    Some((ticker_name(ticker)?, ticker_symbol(ticker)?, uri))
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

/// Metaplex `CreateMetadataAccountV3` data: `DataV2`, `is_mutable = true`,
/// `collection_details: None`.
///
/// Mutable on purpose, with the registry PDA as update authority: only this program can sign
/// an update, and the only update it ever signs is generic -> ticker form, once (tag 122).
pub fn create_metadata_v3_data(name: &[u8], symbol: &[u8], uri: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 12 + name.len() + symbol.len() + uri.len() + 7);
    out.push(MPL_IX_CREATE_METADATA_ACCOUNT_V3);
    push_data_v2(&mut out, name, symbol, uri);
    out.push(1); // is_mutable = true
    out.push(0); // collection_details: None
    out
}

/// Metaplex `UpdateMetadataAccountV2` data: `data: Some(DataV2)`, `new_update_authority: None`,
/// `primary_sale_happened: None`, `is_mutable: None` (the record stays mutable and the registry
/// PDA stays its update authority).
pub fn update_metadata_v2_data(name: &[u8], symbol: &[u8], uri: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 12 + name.len() + symbol.len() + uri.len() + 8);
    out.push(MPL_IX_UPDATE_METADATA_ACCOUNT_V2);
    out.push(1); // data: Some
    push_data_v2(&mut out, name, symbol, uri);
    out.extend_from_slice(&[0, 0, 0]); // new_update_authority, primary_sale_happened, is_mutable: None
    out
}

/// True iff `data` is a Metaplex metadata account for `mint`, whose update authority is
/// `registry`, and whose name is still the GENERIC name of `market` (Metaplex may pad the name
/// with NUL bytes). This is the "once" latch of the upgrade path: after the upgrade the name is
/// the ticker form, so a second upgrade is refused. Any layout it does not recognise is `false`
/// (fail closed: no update is signed).
pub fn is_generic_record(data: &[u8], registry: &[u8; 32], mint: &[u8; 32], market: &[u8; 32]) -> bool {
    if data.len() < 69 || data[0] != MPL_KEY_METADATA_V1 {
        return false;
    }
    if data[1..33] != registry[..] || data[33..65] != mint[..] {
        return false;
    }
    let n = u32::from_le_bytes([data[65], data[66], data[67], data[68]]) as usize;
    if !(LP_SHARE_GENERIC_NAME_LEN..=MPL_MAX_NAME_LEN).contains(&n) || data.len() < 69 + n {
        return false;
    }
    let name = &data[69..69 + n];
    name[..LP_SHARE_GENERIC_NAME_LEN] == generic_name(market)[..]
        && name[LP_SHARE_GENERIC_NAME_LEN..].iter().all(|b| *b == 0)
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
            assert!(share_uri(&key).len() <= MPL_MAX_URI_LEN);
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

    /// The framing is present for EVERY accepted ticker and the limits hold at the maximum.
    #[test]
    fn framing_is_always_present_and_names_fit() {
        let market = Pubkey::new_unique().to_bytes();
        for t in ["A", "SOL", "USDC", "BURNIE", "ABCDEFGH", "99999999"] {
            let (name, symbol, uri) = share_identity(&market, t.as_bytes()).unwrap();
            assert_eq!(s(&name), std::format!("{t} Earn Share - Percolator"));
            assert_eq!(s(&symbol), std::format!("pe{t}"));
            assert!(name.ends_with(b" Earn Share - Percolator"));
            assert!(symbol.starts_with(b"pe"));
            assert!(name.len() <= MPL_MAX_NAME_LEN && symbol.len() <= MPL_MAX_SYMBOL_LEN);
            // a share symbol can never itself be a ticker (lowercase prefix)
            assert!(!ticker_ok(&symbol));
            assert_eq!(uri, share_uri(&market));
        }
        assert_eq!(ticker_name(b"ABCDEFGH").unwrap().len(), 32);
        assert_eq!(ticker_symbol(b"ABCDEFGH").unwrap().len(), 10);
        // generic
        let (name, symbol, uri) = share_identity(&market, b"").unwrap();
        let m = Pubkey::new_from_array(market).to_string();
        assert_eq!(s(&name), std::format!("Percolator Earn Share {}", &m[..8]));
        assert_eq!(s(&symbol), "pEARN");
        assert_eq!(uri, share_uri(&market));
    }

    #[test]
    fn instruction_data_is_the_expected_borsh() {
        let d = create_metadata_v3_data(b"SOL Earn Share - Percolator", b"peSOL", b"https://x/y");
        let mut want = vec![33u8];
        want.extend_from_slice(&27u32.to_le_bytes());
        want.extend_from_slice(b"SOL Earn Share - Percolator");
        want.extend_from_slice(&5u32.to_le_bytes());
        want.extend_from_slice(b"peSOL");
        want.extend_from_slice(&11u32.to_le_bytes());
        want.extend_from_slice(b"https://x/y");
        want.extend_from_slice(&[0, 0]); // seller fee
        want.extend_from_slice(&[0, 0, 0]); // creators, collection, uses
        let mut create = want.clone();
        create.extend_from_slice(&[1, 0]); // is_mutable = true, collection_details None
        assert_eq!(d, create);
        let u = update_metadata_v2_data(b"SOL Earn Share - Percolator", b"peSOL", b"https://x/y");
        let mut upd = vec![15u8, 1];
        upd.extend_from_slice(&want[1..]);
        upd.extend_from_slice(&[0, 0, 0]); // authority / primary sale / is_mutable: None
        assert_eq!(u, upd);
    }

    fn record(update_authority: [u8; 32], mint: [u8; 32], name: &[u8]) -> std::vec::Vec<u8> {
        let mut d = vec![MPL_KEY_METADATA_V1];
        d.extend_from_slice(&update_authority);
        d.extend_from_slice(&mint);
        d.extend_from_slice(&(name.len() as u32).to_le_bytes());
        d.extend_from_slice(name);
        d.extend_from_slice(&[0u8; 100]);
        d
    }

    #[test]
    fn generic_record_latch() {
        let (reg, mint, market) = ([1u8; 32], [2u8; 32], Pubkey::new_unique().to_bytes());
        let g = generic_name(&market);
        assert!(is_generic_record(&record(reg, mint, &g), &reg, &mint, &market));
        // NUL-padded to 32 (older Metaplex versions pad)
        let mut padded = g.to_vec();
        padded.extend_from_slice(&[0, 0]);
        assert!(is_generic_record(&record(reg, mint, &padded), &reg, &mint, &market));
        // a named record, another market's generic name, a foreign authority / mint, a wrong key
        assert!(!is_generic_record(&record(reg, mint, b"SOL Earn Share - Percolator"), &reg, &mint, &market));
        assert!(!is_generic_record(&record(reg, mint, &generic_name(&[9; 32])), &reg, &mint, &market));
        assert!(!is_generic_record(&record([7; 32], mint, &g), &reg, &mint, &market));
        assert!(!is_generic_record(&record(reg, [7; 32], &g), &reg, &mint, &market));
        let mut bad = record(reg, mint, &g);
        bad[0] = 0;
        assert!(!is_generic_record(&bad, &reg, &mint, &market));
        // padded with something that is not NUL
        let mut junk = g.to_vec();
        junk.extend_from_slice(b"!!");
        assert!(!is_generic_record(&record(reg, mint, &junk), &reg, &mint, &market));
        // truncated / absurd length
        assert!(!is_generic_record(&[], &reg, &mint, &market));
        assert!(!is_generic_record(&record(reg, mint, &g)[..80], &reg, &mint, &market));
        let mut huge = record(reg, mint, &g);
        huge[65..69].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!is_generic_record(&huge, &reg, &mint, &market));
    }
}
