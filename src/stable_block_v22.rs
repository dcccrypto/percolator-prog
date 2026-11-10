//! Stablecoin tracked-asset refusal (r6, 2026-11-10; owner decision 2026-11-09, Council R2-11 / R3-10).
//!
//! A perp on a dollar stablecoin is meaningless. What the perp TRACKS is never the market's collateral
//! mint (that is the margin token and is normally USDC): it is set by the oracle configuration
//! (`ConfigureHybridOracle` legs, a Pyth / Chainlink feed id) and by the DEX depth-source pin (the
//! pool's non-collateral base side). Those two are the gates; `InitMarket` is untouched and a
//! USDC-collateral market still initialises. Markets already configured are unaffected (no migration).
//!
//! Compile-time denylists, linear scan (32 mints + 8 feed ids, a few hundred CU at worst).
//! Mainnet only: a devnet stable mint is a different address and is not listed.

use solana_program::pubkey;
use solana_program::pubkey::Pubkey;

/// Mainnet stablecoin mints (from `out/stablecoin-mints.json`, 2026-11-10: native, bridged and yield-bearing USD; sources per entry in the PR body). Base-side mints of a DEX depth-source pin may not be any of these.
pub const STABLE_MINTS: &[Pubkey] = &[
    pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"), // USDC
    pubkey!("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"), // USDT
    pubkey!("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"), // PYUSD
    pubkey!("USDSwr9ApdHk5bvJKMjzff41FfuX8bSxdKcR81vTwcA"), // USDS
    pubkey!("9zNQRsGLjNKwCUU5Gq5LR8beUCPzQMVMqKAi3SSZh54u"), // FDUSD
    pubkey!("DEkqHyPN7GMRJ5cArtQFAWefqbZb33Hyf6s5iCwjEonT"), // USDe
    pubkey!("Eh6XEPhSwoLv5wFApukmnaVSHQ6sAnoD9BmgmwQoN2sN"), // sUSDe
    pubkey!("2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"), // USDG
    pubkey!("USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB"), // USD1
    pubkey!("AUSD1jCcCyPLybk1YnvPWsHQSrZ46dxwoMniN4N2UEB9"), // AUSD
    pubkey!("A1KLoBrKBde8Ty9qtNQUtq3C2ortoC3u7twggz7sEto6"), // USDY
    pubkey!("USDH1SM1ojwWUga67PGrgFWUHibbjqMvuMaDkRJTgkX"), // USDH
    pubkey!("7kbnvuGBxxj8AG9qp8Scn56muWGaRaFqxg1FsRp3PaFT"), // UXD
    pubkey!("5YMkXAYccHSGnHn9nob9xEvv6Pvka9DZWH7nTbotTu9E"), // hyUSD
    pubkey!("GzX1ireZDU865FiMaKrdVB1H6AE8LAqWYCg6chrMrfBw"), // frxUSD
    pubkey!("EjmyN6qEC1Tf1JxiG1ae7UTJhUxSwk1TCWNWqxWV4J6o"), // DAI
    pubkey!("A9mUU4qviSctJVPJdBJWkb28deg915LYJKrzQ19ji3FM"), // USDCet
    pubkey!("Dn4noZ5jgGfkntzcQSUZ8czkreiZ1ForXYoV2H8Dm7S1"), // USDTet
    pubkey!("E2VmbootbVCBkMNNxKQgCLMS1X3NoGMaYAsufaAsf7M"), // USDCpo
    pubkey!("5goWRao6a3yNC4d6UjMdQxonkCMvKBwdpubU3qhfcdf1"), // USDTpo
    pubkey!("FCqfQSujuPxy6V42UvafBhsysWtEq1vhjfMN1PUbgaxA"), // USDCbs
    pubkey!("8qJSyQprMC57TWKaYEmetUR3UUiTP2M3hXdcvFhkZdmv"), // USDTbs
    pubkey!("9vMJfxuKxXBoEa7rM12mYLMwTacLMLDJqHozw96WQL8i"), // UST
    pubkey!("DdFPRnccQqLD4zCHrBqdY95D6hvw6PLWp9DEXj1fLCL9"), // aeUSDC
    pubkey!("eqKJTf1Do4MDPyKisMYqVaUFpkEFAs3riGF3ceDH2Ca"), // apUSDC
    pubkey!("8XSsNvaKU9FDhYWAv7Yc7qSNwuJSzVrXBNEk7AFiWF69"), // abUSDC
    pubkey!("8Yv9Jz4z7BUHP68dz8E8m3tMe6NKgpMUKn8KVqrPA6Fr"), // aaUSDC
    pubkey!("DHpoYejUDqzByb6HAdaLWF7KZvwUv2vWYDY9cTENNZui"), // acUSDC
    pubkey!("Bn113WT6rbdgwrm12UJtnmNqGqZjY4it2WoUQuQopFVn"), // aeUSDT
    pubkey!("DNhZkUaxHXYvpxZ7LNnHtss8sQgdAfd1ZYS1fB7LKWUZ"), // apUSDT
    pubkey!("E77cpQ4VncGmcAXX16LHFFzNBEBb2U7Ar7LBmZNfCgwL"), // abUSDT
    pubkey!("FwEHs3kJEdMa2qZHv7SgzCiFXUQPEycEXksfBkwmS8gj"), // aaUSDT
];

/// Pyth price-feed ids (Hermes `/v2/price_feeds`, verified 2026-11-10) of major USD stablecoin / USD.
pub const STABLE_PYTH_FEED_IDS: &[[u8; 32]] = &[
    // Crypto.USDC/USD eaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a
    [0xea, 0xa0, 0x20, 0xc6, 0x1c, 0xc4, 0x79, 0x71, 0x28, 0x13, 0x46, 0x1c, 0xe1, 0x53, 0x89, 0x4a, 0x96, 0xa6, 0xc0, 0x0b, 0x21, 0xed, 0x0c, 0xfc, 0x27, 0x98, 0xd1, 0xf9, 0xa9, 0xe9, 0xc9, 0x4a],
    // Crypto.USDT/USD 2b89b9dc8fdf9f34709a5b106b472f0f39bb6ca9ce04b0fd7f2e971688e2e53b
    [0x2b, 0x89, 0xb9, 0xdc, 0x8f, 0xdf, 0x9f, 0x34, 0x70, 0x9a, 0x5b, 0x10, 0x6b, 0x47, 0x2f, 0x0f, 0x39, 0xbb, 0x6c, 0xa9, 0xce, 0x04, 0xb0, 0xfd, 0x7f, 0x2e, 0x97, 0x16, 0x88, 0xe2, 0xe5, 0x3b],
    // Crypto.PYUSD/USD c1da1b73d7f01e7ddd54b3766cf7fcd644395ad14f70aa706ec5384c59e76692
    [0xc1, 0xda, 0x1b, 0x73, 0xd7, 0xf0, 0x1e, 0x7d, 0xdd, 0x54, 0xb3, 0x76, 0x6c, 0xf7, 0xfc, 0xd6, 0x44, 0x39, 0x5a, 0xd1, 0x4f, 0x70, 0xaa, 0x70, 0x6e, 0xc5, 0x38, 0x4c, 0x59, 0xe7, 0x66, 0x92],
    // Crypto.USDS/USD 77f0971af11cc8bac224917275c1bf55f2319ed5c654a1ca955c82fa2d297ea1
    [0x77, 0xf0, 0x97, 0x1a, 0xf1, 0x1c, 0xc8, 0xba, 0xc2, 0x24, 0x91, 0x72, 0x75, 0xc1, 0xbf, 0x55, 0xf2, 0x31, 0x9e, 0xd5, 0xc6, 0x54, 0xa1, 0xca, 0x95, 0x5c, 0x82, 0xfa, 0x2d, 0x29, 0x7e, 0xa1],
    // Crypto.FDUSD/USD ccdc1a08923e2e4f4b1e6ea89de6acbc5fe1948e9706f5604b8cb50bc1ed3979
    [0xcc, 0xdc, 0x1a, 0x08, 0x92, 0x3e, 0x2e, 0x4f, 0x4b, 0x1e, 0x6e, 0xa8, 0x9d, 0xe6, 0xac, 0xbc, 0x5f, 0xe1, 0x94, 0x8e, 0x97, 0x06, 0xf5, 0x60, 0x4b, 0x8c, 0xb5, 0x0b, 0xc1, 0xed, 0x39, 0x79],
    // Crypto.USDE/USD 6ec879b1e9963de5ee97e9c8710b742d6228252a5e2ca12d4ae81d7fe5ee8c5d
    [0x6e, 0xc8, 0x79, 0xb1, 0xe9, 0x96, 0x3d, 0xe5, 0xee, 0x97, 0xe9, 0xc8, 0x71, 0x0b, 0x74, 0x2d, 0x62, 0x28, 0x25, 0x2a, 0x5e, 0x2c, 0xa1, 0x2d, 0x4a, 0xe8, 0x1d, 0x7f, 0xe5, 0xee, 0x8c, 0x5d],
    // Crypto.DAI/USD b0948a5e5313200c632b51bb5ca32f6de0d36e9950a942d19751e833f70dabfd
    [0xb0, 0x94, 0x8a, 0x5e, 0x53, 0x13, 0x20, 0x0c, 0x63, 0x2b, 0x51, 0xbb, 0x5c, 0xa3, 0x2f, 0x6d, 0xe0, 0xd3, 0x6e, 0x99, 0x50, 0xa9, 0x42, 0xd1, 0x97, 0x51, 0xe8, 0x33, 0xf7, 0x0d, 0xab, 0xfd],
    // Crypto.USDG/USD daa58c6a3ce7d4b9c46c32a6e646012c17c4a2b24c08dd8c5e476118b855a7da
    [0xda, 0xa5, 0x8c, 0x6a, 0x3c, 0xe7, 0xd4, 0xb9, 0xc4, 0x6c, 0x32, 0xa6, 0xe6, 0x46, 0x01, 0x2c, 0x17, 0xc4, 0xa2, 0xb2, 0x4c, 0x08, 0xdd, 0x8c, 0x5e, 0x47, 0x61, 0x18, 0xb8, 0x55, 0xa7, 0xda],
];

/// True when `mint` is a denylisted stablecoin mint.
#[inline]
pub fn is_stable_mint(mint: &[u8; 32]) -> bool {
    STABLE_MINTS.iter().any(|m| m.as_ref() == mint.as_slice())
}

/// True when `feed` is a denylisted stablecoin / USD feed id.
#[inline]
pub fn is_stable_feed(feed: &[u8; 32]) -> bool {
    STABLE_PYTH_FEED_IDS.iter().any(|f| f == feed)
}

/// True when the oracle legs price a stablecoin and nothing else: every used leg (the first
/// `count`) is a denylisted feed. A genuine cross (any non-stable leg, e.g. X/USD divided by
/// USDC/USD) tracks that other asset and stays allowed.
pub fn oracle_legs_track_only_stable(count: u8, feeds: &[[u8; 32]]) -> bool {
    let n = count as usize;
    n != 0 && n <= feeds.len() && feeds[..n].iter().all(is_stable_feed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints() {
        let usdc = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").to_bytes();
        assert!(is_stable_mint(&usdc));
        assert!(!is_stable_mint(&[7u8; 32]));
    }

    #[test]
    fn every_listed_mint_matches_and_is_distinct() {
        assert_eq!(STABLE_MINTS.len(), 32);
        for (i, a) in STABLE_MINTS.iter().enumerate() {
            assert!(is_stable_mint(&a.to_bytes()));
            for b in &STABLE_MINTS[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn legs() {
        let s = STABLE_PYTH_FEED_IDS[0];
        let o = [9u8; 32];
        assert!(oracle_legs_track_only_stable(1, &[s, [0; 32], [0; 32]]));
        assert!(oracle_legs_track_only_stable(2, &[s, STABLE_PYTH_FEED_IDS[1], [0; 32]]));
        assert!(!oracle_legs_track_only_stable(2, &[o, s, [0; 32]]));
        assert!(!oracle_legs_track_only_stable(1, &[o, s, [0; 32]]));
        assert!(!oracle_legs_track_only_stable(0, &[s, s, s]));
    }

    #[test]
    fn feeds_distinct() {
        for (i, a) in STABLE_PYTH_FEED_IDS.iter().enumerate() {
            for b in &STABLE_PYTH_FEED_IDS[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
