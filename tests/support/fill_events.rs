//! Reference decoder for the v2.2 wrapper events (`docs/v22-fill-events.md`), written
//! independently of `src/fill_events_v22.rs` (it reads raw bytes at the documented offsets), plus
//! the indexer attribution rule (`tx_events`): a `Program data:` line belongs to the wrapper only
//! if the innermost open invoke frame at that line is the wrapper, where frames are opened and
//! closed ONLY by the runtime's own lines. Anything a program can print with `msg!` /
//! `sol_log_data` starts with `Program log: ` / `Program data: ` and never moves a frame.
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

/// Why a token was skipped instead of decoded. A decoder never panics on wire data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Not base64, or shorter than the two bytes that carry kind and version.
    Malformed,
    /// A kind this decoder does not know (a newer program). Skip it.
    UnknownKind(u8),
    /// A version this decoder does not know (a newer layout). Skip it.
    UnknownVersion(u8),
    /// A known kind and version whose length does not match the documented layout.
    BadLength,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = T.iter().position(|x| *x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
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

/// Decode one event payload (the raw bytes behind one base64 token). An unknown kind or version
/// is `Err(Skip::..)`: the caller skips the token, it never panics.
pub fn decode(b: &[u8]) -> Result<Event, Skip> {
    if b.len() < 2 {
        return Err(Skip::Malformed);
    }
    // Kind and version are the first two bytes in every version; check them before any length.
    if !(1..=3).contains(&b[0]) {
        return Err(Skip::UnknownKind(b[0]));
    }
    if b[1] != 1 {
        return Err(Skip::UnknownVersion(b[1]));
    }
    if b.len() < 35 {
        return Err(Skip::BadLength);
    }
    let ix_tag = b[2];
    let market = key(b, 3);
    match b[0] {
        1 => {
            if b.len() < 100 {
                return Err(Skip::BadLength);
            }
            let taker = key(b, 35);
            let lp = key(b, 67);
            let n = b[99] as usize;
            if b.len() != 100 + 75 * n {
                return Err(Skip::BadLength);
            }
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
            Ok(Event::Fill { ix_tag, market, taker, lp, recs })
        }
        2 => {
            if b.len() != 134 {
                return Err(Skip::BadLength);
            }
            Ok(Event::Reduce {
                ix_tag,
                market,
                portfolio: key(b, 35),
                counterparty: key(b, 67),
                asset_index: u16le(b, 99),
                asset_gen: u64le(b, 101),
                reason: b[109],
                signed_reduced_q: i128le(b, 110),
                price_e6: u64le(b, 126),
            })
        }
        _ => {
            if b.len() != 62 {
                return Err(Skip::BadLength);
            }
            Ok(Event::Move {
                ix_tag,
                market,
                sub: b[35],
                asset_index: u16le(b, 36),
                a: u64le(b, 38),
                b: u64le(b, 46),
                c: u64le(b, 54),
            })
        }
    }
}

/// Decode one base64 token (the text after `Program data: `).
pub fn decode_token(tok: &str) -> Result<Event, Skip> {
    decode(&b64(tok).ok_or(Skip::Malformed)?)
}

/// Why a transaction's events are UNKNOWN (never "no events"): the indexer must reconcile the
/// affected portfolios from account state instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// `logMessages` is null or empty (the RPC node did not keep them).
    NoLogs,
    /// The runtime's `Log truncated` marker is present: any line may be missing.
    Truncated,
    /// `Program <id> invoke [n]` whose depth is not the current stack depth + 1.
    BadInvokeDepth,
    /// `Program <id> success` / `failed: ` whose id is not the innermost open frame.
    BadReturn,
    /// A `Program data:` line outside every frame.
    DataOutsideFrame,
    /// The log ended with a frame still open.
    UnclosedFrame,
}

/// What a transaction's logs say about wrapper events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxEvents {
    /// The transaction failed: its events describe nothing that happened. Ignore them.
    Failed,
    /// The events cannot be established from the logs. Not "no events".
    Unknown(Unknown),
    /// The complete list of wrapper events, in order, and how many wrapper tokens were skipped
    /// (unknown kind / version / malformed).
    Known { events: Vec<Event>, skipped: Vec<Skip> },
}

/// The exact element the runtime's log collector inserts once when the 10,000-byte budget is hit.
pub const LOG_TRUNCATED: &str = "Log truncated";

/// `Program <base58 pubkey> <tail>` -> `(id, tail)`; None for every line a program can print
/// itself (`Program log: ..`, `Program data: ..`) because `log:` / `data:` are not pubkeys.
fn runtime_program_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("Program ")?;
    let (id, tail) = rest.split_once(' ')?;
    // Exactly a base58 32-byte key, in canonical text form.
    let pk: Pubkey = id.parse().ok()?;
    if pk.to_string() != id {
        return None;
    }
    Some((id, tail))
}

/// `invoke [n]` -> n. Strict: decimal digits only, nothing after the bracket.
fn invoke_depth(tail: &str) -> Option<usize> {
    let d = tail.strip_prefix("invoke [")?.strip_suffix(']')?;
    if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    d.parse().ok()
}

/// The strict frame walk (doc: "Trust model and the attribution rule"). Each element of `logs` is
/// ONE log line and is treated as atomic: it is never joined with its neighbours and never split
/// on a newline, so text a program prints cannot become a line of its own.
///
/// * push only on `Program <base58 pubkey> invoke [n]` with `n == stack depth + 1`;
/// * pop only on exactly `Program <top of stack> success` or a line starting
///   `Program <top of stack> failed: `;
/// * a `Program data: ` element belongs to the program on top of the stack;
/// * any inconsistency makes the WHOLE transaction's events unknown.
///
/// Returns the base64 tokens whose frame is `wrapper`.
pub fn wrapper_frame_tokens(logs: &[String], wrapper: &Pubkey) -> Result<Vec<String>, Unknown> {
    if logs.is_empty() {
        return Err(Unknown::NoLogs);
    }
    if logs.iter().any(|l| l == LOG_TRUNCATED) {
        return Err(Unknown::Truncated);
    }
    let w = wrapper.to_string();
    let mut stack: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for l in logs {
        if let Some((id, tail)) = runtime_program_line(l) {
            if let Some(depth) = invoke_depth(tail) {
                if depth != stack.len() + 1 {
                    return Err(Unknown::BadInvokeDepth);
                }
                stack.push(id);
            } else if tail == "success" || tail.starts_with("failed: ") {
                if stack.last() != Some(&id) {
                    return Err(Unknown::BadReturn);
                }
                stack.pop();
            }
            // Any other runtime line about a program (`consumed N of M compute units`) is ignored.
            continue;
        }
        if let Some(data) = l.strip_prefix("Program data: ") {
            match stack.last() {
                None => return Err(Unknown::DataOutsideFrame),
                Some(top) if *top == w => {
                    out.extend(data.split(' ').filter(|t| !t.is_empty()).map(str::to_string));
                }
                Some(_) => {}
            }
        }
    }
    if !stack.is_empty() {
        return Err(Unknown::UnclosedFrame);
    }
    Ok(out)
}

/// The indexer entry point. `tx_succeeded` is `meta.err == null`; `logs` is `meta.logMessages`
/// (None when the RPC returned null).
pub fn tx_events(tx_succeeded: bool, logs: Option<&[String]>, wrapper: &Pubkey) -> TxEvents {
    if !tx_succeeded {
        return TxEvents::Failed;
    }
    let Some(logs) = logs else {
        return TxEvents::Unknown(Unknown::NoLogs);
    };
    let tokens = match wrapper_frame_tokens(logs, wrapper) {
        Ok(t) => t,
        Err(u) => return TxEvents::Unknown(u),
    };
    let mut events = Vec::new();
    let mut skipped = Vec::new();
    for tok in tokens {
        match decode_token(&tok) {
            Ok(e) => events.push(e),
            Err(s) => skipped.push(s),
        }
    }
    TxEvents::Known { events, skipped }
}

/// Test convenience over the logs of a transaction the caller knows succeeded: the wrapper's
/// events, panicking if they are unknown or if any wrapper token was skipped.
pub fn wrapper_events(logs: &[String], wrapper: &Pubkey) -> Vec<Event> {
    match tx_events(true, Some(logs), wrapper) {
        TxEvents::Known { events, skipped } => {
            assert!(skipped.is_empty(), "wrapper tokens skipped: {skipped:?}");
            events
        }
        other => panic!("wrapper events not established: {other:?}"),
    }
}

/// Raw base64 tokens attributed to the wrapper (for the worked examples in the doc).
pub fn wrapper_tokens(logs: &[String], wrapper: &Pubkey) -> Vec<String> {
    wrapper_frame_tokens(logs, wrapper).expect("consistent frames")
}
