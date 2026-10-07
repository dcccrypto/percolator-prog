//! v2.2 (prog#542): the LP / Earn share mint's wallet-facing identity.
//!
//! Pure, allocation-light helpers behind tag 122 `InitLpShareMetadata`: the token name and
//! symbol, and the Metaplex Token Metadata `CreateMetadataAccountV3` instruction data. Free of
//! `AccountInfo` and syscalls so every function is unit-tested on the host.
//!
//! IMPERSONATION RULE. Nothing here takes caller input. The wrapper stores no token identity
//! (no symbol, no name) for a market, so the only honest name is a generic one plus something
//! derived from the market address:
//!
//! ```text
//! name   = "Percolator Earn Share " + first 8 base58 characters of the market address
//! symbol = "pEARN"
//! uri    = ""
//! ```
//!
//! The fixed prefix is 22 of the 30 characters, so even a ground market address (a creator can
//! grind the 8-character suffix) cannot make the token read as another asset.

/// Fixed name prefix (22 bytes, trailing space included).
pub const LP_SHARE_NAME_PREFIX: &[u8; 22] = b"Percolator Earn Share ";
/// How many base58 characters of the market address follow the prefix.
pub const LP_SHARE_NAME_MARKET_CHARS: usize = 8;
/// Full name length: 30 bytes, under Metaplex's 32-byte `MAX_NAME_LENGTH`.
pub const LP_SHARE_NAME_LEN: usize = 22 + LP_SHARE_NAME_MARKET_CHARS;
/// Fixed symbol (5 bytes, under Metaplex's 10-byte `MAX_SYMBOL_LENGTH`).
pub const LP_SHARE_SYMBOL: &[u8; 5] = b"pEARN";
/// Metaplex Token Metadata instruction discriminator for `CreateMetadataAccountV3`.
pub const MPL_IX_CREATE_METADATA_ACCOUNT_V3: u8 = 33;
/// Seed prefix of the Metaplex metadata PDA: `["metadata", token_metadata_program, mint]`.
pub const MPL_METADATA_SEED: &[u8] = b"metadata";
/// Exact length of the instruction data built by [`create_metadata_v3_data`].
pub const CREATE_METADATA_V3_DATA_LEN: usize =
    1 + (4 + LP_SHARE_NAME_LEN) + (4 + LP_SHARE_SYMBOL.len()) + 4 + 2 + 3 + 1 + 1;

// Metaplex limits: MAX_NAME_LENGTH 32, MAX_SYMBOL_LENGTH 10.
const _: () = assert!(LP_SHARE_NAME_LEN <= 32);
const _: () = assert!(LP_SHARE_SYMBOL.len() <= 10);

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The first `LP_SHARE_NAME_MARKET_CHARS` characters of the base58 encoding of a 32-byte key
/// (the same string every explorer and wallet shows for the address). A 32-byte key always
/// encodes to at least 32 characters, so the prefix always exists.
pub fn base58_prefix(key: &[u8; 32]) -> [u8; LP_SHARE_NAME_MARKET_CHARS] {
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
    let mut out = [b'1'; LP_SHARE_NAME_MARKET_CHARS];
    let mut k = zeros.min(LP_SHARE_NAME_MARKET_CHARS);
    let mut d = len;
    while k < LP_SHARE_NAME_MARKET_CHARS && d > 0 {
        d -= 1;
        out[k] = B58[digits[d] as usize];
        k += 1;
    }
    out
}

/// The share token's name for `market`.
pub fn lp_share_name(market: &[u8; 32]) -> [u8; LP_SHARE_NAME_LEN] {
    let mut out = [0u8; LP_SHARE_NAME_LEN];
    out[..22].copy_from_slice(LP_SHARE_NAME_PREFIX);
    out[22..].copy_from_slice(&base58_prefix(market));
    out
}

/// Borsh data of Metaplex `CreateMetadataAccountV3` for the share mint of `market`:
/// `DataV2 { name, symbol, uri: "", seller_fee_basis_points: 0, creators: None,
/// collection: None, uses: None }, is_mutable: false, collection_details: None`.
///
/// `is_mutable = false`: the name can never be changed afterwards, by anyone (the update
/// authority is the registry PDA, which no instruction signs an update for; immutability makes
/// that a property of the metadata account instead of a property of this program's source).
pub fn create_metadata_v3_data(market: &[u8; 32]) -> [u8; CREATE_METADATA_V3_DATA_LEN] {
    let mut out = [0u8; CREATE_METADATA_V3_DATA_LEN];
    let name = lp_share_name(market);
    let mut o = 0usize;
    out[o] = MPL_IX_CREATE_METADATA_ACCOUNT_V3;
    o += 1;
    out[o..o + 4].copy_from_slice(&(LP_SHARE_NAME_LEN as u32).to_le_bytes());
    o += 4;
    out[o..o + LP_SHARE_NAME_LEN].copy_from_slice(&name);
    o += LP_SHARE_NAME_LEN;
    out[o..o + 4].copy_from_slice(&(LP_SHARE_SYMBOL.len() as u32).to_le_bytes());
    o += 4;
    out[o..o + LP_SHARE_SYMBOL.len()].copy_from_slice(LP_SHARE_SYMBOL);
    o += LP_SHARE_SYMBOL.len();
    // uri: empty string (u32 0); seller_fee_basis_points: 0 (u16); creators / collection /
    // uses: None (three 0 bytes); is_mutable: false (0); collection_details: None (0).
    // All zero already.
    o += 4 + 2 + 3 + 1 + 1;
    debug_assert!(o == CREATE_METADATA_V3_DATA_LEN);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use solana_program::pubkey::Pubkey;
    use std::{string::ToString, vec};

    fn check(key: [u8; 32]) {
        let want = Pubkey::new_from_array(key).to_string();
        let got = base58_prefix(&key);
        assert_eq!(core::str::from_utf8(&got).unwrap(), &want[..8], "key {key:?}");
    }

    #[test]
    fn base58_prefix_matches_pubkey_display() {
        check([0u8; 32]);
        check([0xff; 32]);
        let mut k = [0u8; 32];
        k[31] = 1;
        check(k);
        // leading zero bytes: 1..=9 of them (more than the 8 characters kept)
        for z in 1..=9usize {
            let mut k = [0xabu8; 32];
            for b in k.iter_mut().take(z) {
                *b = 0;
            }
            check(k);
        }
        // a deterministic spread of keys
        let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..2_000 {
            let mut k = [0u8; 32];
            for b in k.iter_mut() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                *b = s as u8;
            }
            check(k);
        }
        for _ in 0..200 {
            check(Pubkey::new_unique().to_bytes());
        }
    }

    #[test]
    fn name_and_symbol_fit_metaplex_limits_and_keep_the_fixed_prefix() {
        let market = Pubkey::new_unique();
        let name = lp_share_name(&market.to_bytes());
        let s = core::str::from_utf8(&name).unwrap();
        assert!(s.starts_with("Percolator Earn Share "));
        assert_eq!(&s[22..], &market.to_string()[..8]);
    }

    #[test]
    fn create_metadata_data_is_the_expected_borsh() {
        let market = Pubkey::new_unique();
        let d = create_metadata_v3_data(&market.to_bytes());
        let name = lp_share_name(&market.to_bytes());
        let mut want = vec![33u8];
        want.extend_from_slice(&30u32.to_le_bytes());
        want.extend_from_slice(&name);
        want.extend_from_slice(&5u32.to_le_bytes());
        want.extend_from_slice(b"pEARN");
        want.extend_from_slice(&0u32.to_le_bytes()); // uri ""
        want.extend_from_slice(&0u16.to_le_bytes()); // seller fee
        want.extend_from_slice(&[0, 0, 0]); // creators, collection, uses: None
        want.push(0); // is_mutable = false
        want.push(0); // collection_details: None
        assert_eq!(d.to_vec(), want);
    }
}
