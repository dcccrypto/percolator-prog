//! Reference decoder for the v2.2 wrapper events (`docs/v22-fill-events.md`), written
//! independently of `src/fill_events_v22.rs` (it reads raw bytes at the documented offsets), plus
//! the indexer attribution rule: a `Program data:` line belongs to the wrapper only if the
//! innermost open invoke frame at that line is the wrapper.
#![allow(dead_code)]

use solana_sdk::pubkey::Pubkey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillRecord {
    pub asset_index: u16,
    pub asset_gen: u64,
    pub flags: u8,
    pub requested_q: i128,
    pub executed_q: i128,
    pub price_e6: u64,
    pub quoted_price_e6: u64,
    pub fee_atoms: u64,
    pub backing_fee_atoms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Fill {
        ix_tag: u8,
        market: Pubkey,
        taker: Pubkey,
        lp: Pubkey,
        recs: Vec<FillRecord>,
    },
    Reduce {
        ix_tag: u8,
        market: Pubkey,
        portfolio: Pubkey,
        counterparty: Pubkey,
        asset_index: u16,
        asset_gen: u64,
        reason: u8,
        signed_reduced_q: i128,
        price_e6: u64,
    },
    Move {
        ix_tag: u8,
        market: Pubkey,
        sub: u8,
        asset_index: u16,
        a: u64,
        b: u64,
        c: u64,
    },
}

pub const FLAG_CLIPPED: u8 = 1;
pub const FLAG_PARTIAL: u8 = 2;
pub const FLAG_ZERO: u8 = 4;
pub const FLAG_MATCHER: u8 = 8;

fn b64(s: &str) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = T.iter().position(|x| *x == c).expect("base64 char") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn i128le(b: &[u8], o: usize) -> i128 {
    i128::from_le_bytes(b[o..o + 16].try_into().unwrap())
}
fn key(b: &[u8], o: usize) -> Pubkey {
    Pubkey::new_from_array(b[o..o + 32].try_into().unwrap())
}

/// Decode one event payload (the raw bytes behind one base64 token).
pub fn decode(b: &[u8]) -> Event {
    assert!(b.len() >= 35, "short event: {}", b.len());
    assert_eq!(b[1], 1, "unknown version");
    let ix_tag = b[2];
    let market = key(b, 3);
    match b[0] {
        1 => {
            let taker = key(b, 35);
            let lp = key(b, 67);
            let n = b[99] as usize;
            assert_eq!(b.len(), 100 + 75 * n, "fill length");
            let recs = (0..n)
                .map(|i| {
                    let o = 100 + 75 * i;
                    FillRecord {
                        asset_index: u16le(b, o),
                        asset_gen: u64le(b, o + 2),
                        flags: b[o + 10],
                        requested_q: i128le(b, o + 11),
                        executed_q: i128le(b, o + 27),
                        price_e6: u64le(b, o + 43),
                        quoted_price_e6: u64le(b, o + 51),
                        fee_atoms: u64le(b, o + 59),
                        backing_fee_atoms: u64le(b, o + 67),
                    }
                })
                .collect();
            Event::Fill { ix_tag, market, taker, lp, recs }
        }
        2 => {
            assert_eq!(b.len(), 134, "reduce length");
            Event::Reduce {
                ix_tag,
                market,
                portfolio: key(b, 35),
                counterparty: key(b, 67),
                asset_index: u16le(b, 99),
                asset_gen: u64le(b, 101),
                reason: b[109],
                signed_reduced_q: i128le(b, 110),
                price_e6: u64le(b, 126),
            }
        }
        3 => {
            assert_eq!(b.len(), 62, "move length");
            Event::Move {
                ix_tag,
                market,
                sub: b[35],
                asset_index: u16le(b, 36),
                a: u64le(b, 38),
                b: u64le(b, 46),
                c: u64le(b, 54),
            }
        }
        k => panic!("unknown event kind {k}"),
    }
}

/// Indexer attribution rule over a transaction's log lines: walk the invoke/success/failed frames
/// and keep a `Program data:` token only when the innermost open frame is `wrapper`.
pub fn wrapper_events(logs: &[String], wrapper: &Pubkey) -> Vec<Event> {
    let w = wrapper.to_string();
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for l in logs {
        if let Some(rest) = l.strip_prefix("Program ") {
            if let Some((id, tail)) = rest.split_once(' ') {
                if tail.starts_with("invoke [") {
                    stack.push(id.to_string());
                    continue;
                }
                if tail == "success" || tail.starts_with("failed") {
                    stack.pop();
                    continue;
                }
            }
        }
        if let Some(data) = l.strip_prefix("Program data: ") {
            if stack.last().map(|s| s == &w).unwrap_or(false) {
                for tok in data.split(' ').filter(|t| !t.is_empty()) {
                    out.push(decode(&b64(tok)));
                }
            }
        }
    }
    out
}

/// Raw base64 tokens attributed to the wrapper (for the worked examples in the doc).
pub fn wrapper_tokens(logs: &[String], wrapper: &Pubkey) -> Vec<String> {
    let w = wrapper.to_string();
    let mut stack: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for l in logs {
        if let Some(rest) = l.strip_prefix("Program ") {
            if let Some((id, tail)) = rest.split_once(' ') {
                if tail.starts_with("invoke [") {
                    stack.push(id.to_string());
                    continue;
                }
                if tail == "success" || tail.starts_with("failed") {
                    stack.pop();
                    continue;
                }
            }
        }
        if let Some(data) = l.strip_prefix("Program data: ") {
            if stack.last().map(|s| s == &w).unwrap_or(false) {
                out.extend(data.split(' ').filter(|t| !t.is_empty()).map(str::to_string));
            }
        }
    }
    out
}
