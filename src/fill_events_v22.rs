//! v2.2 executed-fill / reduction / value-move events (`docs/v22-fill-events.md`).
//!
//! One compact, versioned binary record per event line, emitted with `sol_log_data` (a single
//! base64 token after `Program data: `). All integers are little-endian, `i128` is two's
//! complement, pubkeys are the raw 32 bytes.
//!
//! Header (every event, 35 bytes):
//!
//! | off | len | field |
//! |---|---|---|
//! | 0 | 1 | `kind` (1 FILL, 2 REDUCE, 3 MOVE) |
//! | 1 | 1 | `version` (1) |
//! | 2 | 1 | `ix_tag`: the wrapper instruction tag that executed the emitting handler |
//! | 3 | 32 | `market` account |
//!
//! This module is pure apart from the final `sol_log_data` call: the encoders write into a
//! caller-supplied buffer and return the length, so they are unit-testable natively and add no
//! heap use (the buffers live in the `#[inline(never)]` emitters' own frames).

use solana_program::log::sol_log_data;

pub const KIND_FILL: u8 = 1;
pub const KIND_REDUCE: u8 = 2;
pub const KIND_MOVE: u8 = 3;
pub const VERSION: u8 = 1;

/// Wrapper instruction tags used as `ix_tag` (the executing handler's own tag).
pub const TAG_CRANK: u8 = 5;
pub const TAG_TRADE_NOCPI: u8 = 6;
pub const TAG_TRADE_CPI: u8 = 10;
pub const TAG_REBALANCE_REDUCE: u8 = 44;
pub const TAG_BATCH_NOCPI: u8 = 66;
pub const TAG_BATCH_CPI: u8 = 67;
pub const TAG_EXECUTE_REDEMPTION: u8 = 77;
pub const TAG_ADL_WIND_DOWN: u8 = 104;
pub const TAG_SETTLE_HOLDING_RENT: u8 = 106;
pub const TAG_INSURANCE_BACKSTOP: u8 = 111;
pub const TAG_SWEEP_BAND_DUST: u8 = 118;
pub const TAG_EVICT_AND_TRADE: u8 = 119;

/// FILL flags.
/// The requested size was clipped to the LP's headroom before the matcher was called.
pub const FLAG_CLIPPED: u8 = 1;
/// The matcher filled less than it was asked to (non-zero).
pub const FLAG_PARTIAL: u8 = 2;
/// Nothing executed (`executed_q == 0`): clipped to zero by headroom, or the matcher returned 0.
pub const FLAG_ZERO: u8 = 4;
/// The fill was routed through an external matcher (TradeCpi / BatchTradeCpi); clear on NoCpi.
pub const FLAG_MATCHER: u8 = 8;

/// REDUCE reasons.
pub const REASON_REBALANCE_REDUCE: u8 = 1;
pub const REASON_ADL_WIND_DOWN: u8 = 2;
pub const REASON_LIQUIDATION: u8 = 3;
pub const REASON_DUST_SWEEP: u8 = 4;
pub const REASON_EVICTION: u8 = 5;

/// MOVE subkinds.
pub const MOVE_EARN_EXIT: u8 = 1;
pub const MOVE_G9: u8 = 2;
pub const MOVE_RENT_ROUTED: u8 = 3;

pub const HEADER_LEN: usize = 35;
/// FILL fixed part: header + taker portfolio + LP portfolio + record count.
pub const FILL_FIXED_LEN: usize = HEADER_LEN + 32 + 32 + 1;
/// One FILL record.
pub const FILL_REC_LEN: usize = 2 + 8 + 1 + 16 + 16 + 8 + 8 + 8 + 8;
/// Records per line (the BatchTradeCpi maximum); a longer batch is split across lines.
pub const MAX_FILL_RECS_PER_LINE: usize = 11;
pub const FILL_BUF_LEN: usize = FILL_FIXED_LEN + MAX_FILL_RECS_PER_LINE * FILL_REC_LEN;
pub const REDUCE_LEN: usize = HEADER_LEN + 32 + 32 + 2 + 8 + 1 + 16 + 8;
pub const MOVE_LEN: usize = HEADER_LEN + 1 + 2 + 8 + 8 + 8;

/// Asset index meaning "no asset" in a MOVE.
pub const NO_ASSET: u16 = u16::MAX;

/// One executed (or zero-executed) leg of a fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillRec {
    pub asset_index: u16,
    /// The asset's `market_id` (generation), so a re-used asset index is unambiguous.
    pub asset_gen: u64,
    pub flags: u8,
    /// Signed size the trader asked for (wire size, before any headroom clip). Positive = taker long.
    pub requested_q: i128,
    /// Signed size that executed (0 on a zero fill).
    pub executed_q: i128,
    /// Price the position was BOOKED at (the asset's `effective_price`). On a zero fill: the
    /// reference price only, nothing was booked.
    pub price_e6: u64,
    /// The price the matcher quoted (TradeCpi) or the wire `exec_price` (TradeNoCpi). It is NOT
    /// the booked price. 0 when no matcher was reached.
    pub quoted_price_e6: u64,
    /// Engine trade fee charged (taker + maker-fallback), atoms, saturating at `u64::MAX`.
    pub fee_atoms: u64,
    /// Backing-domain fee charged on top (single trades only; 0 in batches), atoms.
    pub backing_fee_atoms: u64,
}

#[inline]
pub fn sat_u64(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

#[inline]
fn put(buf: &mut [u8], off: &mut usize, bytes: &[u8]) {
    buf[*off..*off + bytes.len()].copy_from_slice(bytes);
    *off += bytes.len();
}

#[inline]
fn put_header(buf: &mut [u8], off: &mut usize, kind: u8, tag: u8, market: &[u8; 32]) {
    put(buf, off, &[kind, VERSION, tag]);
    put(buf, off, market);
}

pub fn encode_fill_rec(buf: &mut [u8], off: &mut usize, r: &FillRec) {
    put(buf, off, &r.asset_index.to_le_bytes());
    put(buf, off, &r.asset_gen.to_le_bytes());
    put(buf, off, &[r.flags]);
    put(buf, off, &r.requested_q.to_le_bytes());
    put(buf, off, &r.executed_q.to_le_bytes());
    put(buf, off, &r.price_e6.to_le_bytes());
    put(buf, off, &r.quoted_price_e6.to_le_bytes());
    put(buf, off, &r.fee_atoms.to_le_bytes());
    put(buf, off, &r.backing_fee_atoms.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
/// Encode one FILL line holding `n <= MAX_FILL_RECS_PER_LINE` records produced by `rec(i)`.
/// Returns the encoded length.
pub fn encode_fill<F: Fn(usize) -> FillRec>(
    buf: &mut [u8; FILL_BUF_LEN],
    tag: u8,
    market: &[u8; 32],
    taker: &[u8; 32],
    lp: &[u8; 32],
    first: usize,
    n: usize,
    rec: &F,
) -> usize {
    let mut off = 0usize;
    put_header(buf, &mut off, KIND_FILL, tag, market);
    put(buf, &mut off, taker);
    put(buf, &mut off, lp);
    put(buf, &mut off, &[n as u8]);
    let mut i = 0usize;
    while i < n {
        encode_fill_rec(buf, &mut off, &rec(first + i));
        i += 1;
    }
    off
}

#[allow(clippy::too_many_arguments)]
pub fn encode_reduce(
    buf: &mut [u8; REDUCE_LEN],
    tag: u8,
    market: &[u8; 32],
    portfolio: &[u8; 32],
    counterparty: &[u8; 32],
    asset_index: u16,
    asset_gen: u64,
    reason: u8,
    signed_reduced_q: i128,
    price_e6: u64,
) -> usize {
    let mut off = 0usize;
    put_header(buf, &mut off, KIND_REDUCE, tag, market);
    put(buf, &mut off, portfolio);
    put(buf, &mut off, counterparty);
    put(buf, &mut off, &asset_index.to_le_bytes());
    put(buf, &mut off, &asset_gen.to_le_bytes());
    put(buf, &mut off, &[reason]);
    put(buf, &mut off, &signed_reduced_q.to_le_bytes());
    put(buf, &mut off, &price_e6.to_le_bytes());
    off
}

#[allow(clippy::too_many_arguments)]
pub fn encode_move(
    buf: &mut [u8; MOVE_LEN],
    tag: u8,
    market: &[u8; 32],
    sub: u8,
    asset_index: u16,
    a: u64,
    b: u64,
    c: u64,
) -> usize {
    let mut off = 0usize;
    put_header(buf, &mut off, KIND_MOVE, tag, market);
    put(buf, &mut off, &[sub]);
    put(buf, &mut off, &asset_index.to_le_bytes());
    put(buf, &mut off, &a.to_le_bytes());
    put(buf, &mut off, &b.to_le_bytes());
    put(buf, &mut off, &c.to_le_bytes());
    off
}

/// Emit FILL lines for `n` records (`rec(i)` for `i in 0..n`). A batch over
/// `MAX_FILL_RECS_PER_LINE` legs is split across several lines, in leg order.
#[inline(never)]
pub fn emit_fills<F: Fn(usize) -> FillRec>(
    tag: u8,
    market: &[u8; 32],
    taker: &[u8; 32],
    lp: &[u8; 32],
    n: usize,
    rec: F,
) {
    let mut buf = [0u8; FILL_BUF_LEN];
    let mut first = 0usize;
    while first < n {
        let take = core::cmp::min(MAX_FILL_RECS_PER_LINE, n - first);
        let len = encode_fill(&mut buf, tag, market, taker, lp, first, take, &rec);
        sol_log_data(&[&buf[..len]]);
        first += take;
    }
}

/// Emit one REDUCE line. `counterparty` is all zero when the reduction is unilateral.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_reduce(
    tag: u8,
    market: &[u8; 32],
    portfolio: &[u8; 32],
    counterparty: &[u8; 32],
    asset_index: u16,
    asset_gen: u64,
    reason: u8,
    signed_reduced_q: i128,
    price_e6: u64,
) {
    let mut buf = [0u8; REDUCE_LEN];
    let len = encode_reduce(
        &mut buf,
        tag,
        market,
        portfolio,
        counterparty,
        asset_index,
        asset_gen,
        reason,
        signed_reduced_q,
        price_e6,
    );
    sol_log_data(&[&buf[..len]]);
}

/// Emit one MOVE line.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_move(tag: u8, market: &[u8; 32], sub: u8, asset_index: u16, a: u64, b: u64, c: u64) {
    let mut buf = [0u8; MOVE_LEN];
    let len = encode_move(&mut buf, tag, market, sub, asset_index, a, b, c);
    sol_log_data(&[&buf[..len]]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(b: &[u8]) -> std::string::String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = std::string::String::new();
        for c in b.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }

    const M: [u8; 32] = [1; 32];
    const T: [u8; 32] = [2; 32];
    const L: [u8; 32] = [3; 32];

    #[test]
    fn lengths_match_the_documented_layout() {
        assert_eq!(HEADER_LEN, 35);
        assert_eq!(FILL_FIXED_LEN, 100);
        assert_eq!(FILL_REC_LEN, 75);
        assert_eq!(REDUCE_LEN, 134);
        assert_eq!(MOVE_LEN, 62);
        let mut b = [0u8; FILL_BUF_LEN];
        let r = FillRec {
            asset_index: 3,
            asset_gen: 9,
            flags: FLAG_CLIPPED | FLAG_MATCHER,
            requested_q: -5,
            executed_q: -2,
            price_e6: 7,
            quoted_price_e6: 8,
            fee_atoms: 1,
            backing_fee_atoms: 2,
        };
        let n = encode_fill(&mut b, 10, &[1; 32], &[2; 32], &[3; 32], 0, 1, &|_| r);
        assert_eq!(n, FILL_FIXED_LEN + FILL_REC_LEN);
        assert_eq!(&b[..3], &[KIND_FILL, VERSION, 10]);
        assert_eq!(b[99], 1);
        assert_eq!(&b[100..102], &3u16.to_le_bytes());
        assert_eq!(&b[111..127], &(-5i128).to_le_bytes());
    }

    #[allow(clippy::too_many_arguments)]
    fn rec(asset: u16, gen: u64, flags: u8, req: i128, ex: i128, price: u64, quoted: u64, fee: u64) -> FillRec {
        FillRec {
            asset_index: asset,
            asset_gen: gen,
            flags,
            requested_q: req,
            executed_q: ex,
            price_e6: price,
            quoted_price_e6: quoted,
            fee_atoms: fee,
            backing_fee_atoms: 0,
        }
    }

    /// The worked examples in `docs/v22-fill-events.md` are generated by an independent encoder
    /// (python `struct`); this pins them to the on-chain encoder and to the document text.
    #[test]
    fn doc_worked_examples_are_current() {
        let doc = include_str!("../docs/v22-fill-events.md");
        let mut b = [0u8; FILL_BUF_LEN];
        let ex1 = [rec(0, 7, FLAG_CLIPPED | FLAG_MATCHER, 15_000_000, 10_000_000, 100_000_000, 100_000_000, 1_000)];
        let n = encode_fill(&mut b, 10, &M, &T, &L, 0, 1, &|i| ex1[i]);
        let e1 = b64(&b[..n]);
        let ex2 = [rec(0, 7, FLAG_CLIPPED | FLAG_ZERO | FLAG_MATCHER, 3_000_000, 0, 100_000_000, 0, 0)];
        let n = encode_fill(&mut b, 10, &M, &T, &L, 0, 1, &|i| ex2[i]);
        let e2 = b64(&b[..n]);
        let ex3 = [
            rec(0, 7, FLAG_MATCHER, 1_000_000, 1_000_000, 100_000_000, 100_000_000, 0),
            rec(1, 8, FLAG_MATCHER | FLAG_PARTIAL, 2_000_000, 500_000, 250_000_000, 249_000_000, 0),
        ];
        let n = encode_fill(&mut b, 67, &M, &T, &L, 0, 2, &|i| ex3[i]);
        let e3 = b64(&b[..n]);
        let mut rb = [0u8; REDUCE_LEN];
        let n = encode_reduce(&mut rb, 44, &M, &T, &[0; 32], 0, 7, REASON_REBALANCE_REDUCE, -4_000_000, 100_000_000);
        let e4 = b64(&rb[..n]);
        let mut mb = [0u8; MOVE_LEN];
        let n = encode_move(&mut mb, 77, &M, MOVE_EARN_EXIT, NO_ASSET, 9_000_000, 1_250_000, 10_000_000);
        let e5 = b64(&mb[..n]);
        for e in [&e1, &e2, &e3, &e4, &e5] {
            assert!(doc.contains(e.as_str()), "docs/v22-fill-events.md is missing the example {e}");
        }
    }
}
