//! v2.2 fill events: the indexer attribution rule on synthetic logs (no `.so` needed).
//!
//! Security review 2026-10-07, M-1: the first reference walker popped a frame on any line whose
//! tail was `success` and pushed on any tail starting `invoke [`, without checking that the id was
//! a program id or the top of the stack. A matcher's `msg!("success")` prints
//! `Program log: success`, which that walker read as "the matcher returned", so the matcher's next
//! `sol_log_data` line was attributed to the wrapper. These tests pin the strict rule
//! (`fill_events::wrapper_frame_tokens`): frames move only on the runtime's own lines.
//!
//! The first three cases are the reviewer's probes (`zz_sentinel_attr.rs`), with the assertions
//! turned round: the forgery must NOT be attributed.

#[path = "support/fill_events.rs"]
mod fill_events;
use fill_events::{tx_events, wrapper_frame_tokens, Event, Skip, TxEvents, Unknown, FLAG_CLIPPED, FLAG_MATCHER, FLAG_ZERO};
use solana_sdk::pubkey::Pubkey;

/// A forged FILL (executed 10 units, fee 1,000) naming market 0x01.., taker 0x02.., LP 0x03...
const FORGED: &str = "AQEKAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAQAABwAAAAAAAAAJwOHkAAAAAAAAAAAAAAAAAICWmAAAAAAAAAAAAAAAAAAA4fUFAAAAAADh9QUAAAAA6AMAAAAAAAAAAAAAAAAAAA==";
/// The wrapper's real event for the same accounts: a ZERO fill (CLIPPED|ZERO|MATCHER).
const REAL: &str = "AQEKAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAQAABwAAAAAAAAANwMYtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4fUFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

/// A TradeCpi transaction: wrapper [1] -> matcher [2] (the matcher prints `matcher_lines`), then
/// the wrapper's real event.
fn tx_logs(wrapper: &Pubkey, matcher: &Pubkey, matcher_lines: &[&str]) -> Vec<String> {
    let mut l = vec![format!("Program {wrapper} invoke [1]"), format!("Program {matcher} invoke [2]")];
    l.extend(matcher_lines.iter().map(|s| s.to_string()));
    l.push(format!("Program {matcher} consumed 5000 of 900000 compute units"));
    l.push(format!("Program {matcher} success"));
    l.push(format!("Program data: {REAL}"));
    l.push(format!("Program {wrapper} consumed 90000 of 1400000 compute units"));
    l.push(format!("Program {wrapper} success"));
    l
}

fn known(logs: &[String], wrapper: &Pubkey) -> Vec<Event> {
    match tx_events(true, Some(logs), wrapper) {
        TxEvents::Known { events, skipped } => {
            assert!(skipped.is_empty(), "{skipped:?}");
            events
        }
        other => panic!("expected Known, got {other:?}"),
    }
}

/// Exactly the wrapper's real ZERO fill and nothing else.
fn assert_only_the_real_zero_fill(evs: &[Event]) {
    assert_eq!(evs.len(), 1, "only the wrapper's own event: {evs:#?}");
    let Event::Fill { ix_tag, recs, .. } = &evs[0] else { panic!("{evs:?}") };
    assert_eq!(*ix_tag, 10);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].executed_q, 0, "the real ZERO fill, not the forged 10-unit fill");
    assert_eq!(recs[0].fee_atoms, 0);
    assert_eq!(recs[0].flags, FLAG_CLIPPED | FLAG_ZERO | FLAG_MATCHER);
}

/// Reviewer probe 1: the matcher does `msg!("success"); sol_log_data(&[forged])`. The loose rule
/// popped the matcher frame on `Program log: success` and attributed the forgery to the wrapper
/// (and then lost the real event). Strict rule: `log:` is not a program id, nothing pops.
#[test]
fn forged_program_log_success_does_not_pop_the_matcher_frame() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let forged_line = format!("Program data: {FORGED}");
    let logs = tx_logs(&w, &m, &["Program log: success", &forged_line]);
    assert_only_the_real_zero_fill(&known(&logs, &w));
}

/// Reviewer probe 2: the matcher also prints `invoke [2]` so the loose walker's stack ended
/// balanced and it reported the forgery AND the real event. Strict rule: neither line is a frame.
#[test]
fn forged_program_log_invoke_does_not_rebalance_the_stack() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let forged_line = format!("Program data: {FORGED}");
    let logs = tx_logs(&w, &m, &["Program log: success", &forged_line, "Program log: invoke [2]"]);
    assert_only_the_real_zero_fill(&known(&logs, &w));
}

/// Reviewer probe 3 (control): an honest matcher's own data line is in the matcher's frame.
#[test]
fn control_honest_matcher_data_line_is_not_attributed() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let forged_line = format!("Program data: {FORGED}");
    let logs = tx_logs(&w, &m, &[&forged_line]);
    assert_only_the_real_zero_fill(&known(&logs, &w));
}

/// More spellings a program can reach with `msg!`: all start with `Program log: ` and none moves
/// a frame, including text that names the real wrapper / matcher ids.
#[test]
fn msg_text_naming_real_program_ids_never_moves_a_frame() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let forged_line = format!("Program data: {FORGED}");
    for spoof in [
        format!("Program log: Program {m} success"),
        format!("Program log: {m} success"),
        "Program log: failed: custom program error: 0x1".to_string(),
        format!("Program log: Program {w} invoke [1]"),
        "Program log: Log truncated".to_string(),
        "Program log: success".to_string(),
    ] {
        let logs = tx_logs(&w, &m, &[&spoof, &forged_line]);
        assert_only_the_real_zero_fill(&known(&logs, &w));
    }
}

/// Each `logMessages` element is atomic. A program can put newlines inside ONE `msg!`; an indexer
/// that joined the log and split it on '\n' would turn that text into lines of its own (a real
/// looking `Program <matcher> success`, then a `Program data:` line in the wrapper's frame).
#[test]
fn an_element_with_embedded_newlines_stays_one_line() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let multi = format!("Program log: x\nProgram {m} success\nProgram data: {FORGED}\nProgram {m} invoke [2]");
    let logs = tx_logs(&w, &m, &[&multi]);
    assert_only_the_real_zero_fill(&known(&logs, &w));

    // The wrong way (join, re-split), shown so the rule's reason is on the page: the same log now
    // carries the forged event in the wrapper's frame.
    let resplit: Vec<String> = logs.join("\n").split('\n').map(str::to_string).collect();
    let toks = wrapper_frame_tokens(&resplit, &w).expect("frames look consistent after the re-split");
    assert!(toks.iter().any(|t| t == FORGED), "join + re-split is forgeable: {toks:?}");
}

/// `Log truncated` anywhere: the events are unknown, never "no fill". The collector keeps
/// accepting shorter lines after the marker, so the frames can still look complete.
#[test]
fn log_truncated_anywhere_makes_the_events_unknown() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let base = tx_logs(&w, &m, &[]);
    for at in 0..=base.len() {
        let mut logs = base.clone();
        logs.insert(at, "Log truncated".to_string());
        assert_eq!(
            tx_events(true, Some(&logs), &w),
            TxEvents::Unknown(Unknown::Truncated),
            "marker at {at}"
        );
    }
    // The realistic shape: the event line itself was the one dropped.
    let mut logs = base.clone();
    let i = logs.iter().position(|l| l.starts_with("Program data: ")).unwrap();
    logs[i] = "Log truncated".to_string();
    assert_eq!(tx_events(true, Some(&logs), &w), TxEvents::Unknown(Unknown::Truncated));
}

/// Null or empty `logMessages`: unknown.
#[test]
fn null_or_empty_logs_make_the_events_unknown() {
    let w = Pubkey::new_unique();
    assert_eq!(tx_events(true, None, &w), TxEvents::Unknown(Unknown::NoLogs));
    assert_eq!(tx_events(true, Some(&[]), &w), TxEvents::Unknown(Unknown::NoLogs));
}

/// A failed transaction is never decoded, whatever its logs say.
#[test]
fn failed_transaction_events_are_ignored() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let logs = tx_logs(&w, &m, &[]);
    assert_eq!(tx_events(false, Some(&logs), &w), TxEvents::Failed);
    assert_eq!(tx_events(false, None, &w), TxEvents::Failed);
}

/// Any frame inconsistency marks the whole transaction unknown, even when a well-formed wrapper
/// event was seen before it.
#[test]
fn any_frame_inconsistency_marks_the_whole_transaction_unknown() {
    let (w, m, other) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let data = format!("Program data: {REAL}");
    let cases: Vec<(Vec<String>, Unknown)> = vec![
        // invoke depth skips a level
        (
            vec![format!("Program {w} invoke [1]"), format!("Program {m} invoke [3]")],
            Unknown::BadInvokeDepth,
        ),
        // a second top-level frame opened while one is still open
        (
            vec![format!("Program {w} invoke [1]"), data.clone(), format!("Program {m} invoke [1]")],
            Unknown::BadInvokeDepth,
        ),
        // depth 0 / first frame not at depth 1
        (vec![format!("Program {w} invoke [2]")], Unknown::BadInvokeDepth),
        // success for a program that is not the innermost open frame
        (
            vec![
                format!("Program {w} invoke [1]"),
                format!("Program {m} invoke [2]"),
                format!("Program {w} success"),
            ],
            Unknown::BadReturn,
        ),
        // success for a program that was never invoked
        (
            vec![format!("Program {w} invoke [1]"), data.clone(), format!("Program {other} success")],
            Unknown::BadReturn,
        ),
        // failed for a program that is not the innermost open frame
        (
            vec![
                format!("Program {w} invoke [1]"),
                format!("Program {m} invoke [2]"),
                format!("Program {w} failed: custom program error: 0x1"),
            ],
            Unknown::BadReturn,
        ),
        // success with nothing open
        (vec![format!("Program {w} success")], Unknown::BadReturn),
        // data outside every frame
        (vec![data.clone()], Unknown::DataOutsideFrame),
        // the log stops with a frame open
        (vec![format!("Program {w} invoke [1]"), data.clone()], Unknown::UnclosedFrame),
    ];
    for (logs, why) in cases {
        assert_eq!(tx_events(true, Some(&logs), &w), TxEvents::Unknown(why), "{logs:#?}");
    }
}

/// The push / pop lines must match exactly: near misses are not frames.
#[test]
fn near_miss_runtime_lines_are_not_frames() {
    let (w, m) = (Pubkey::new_unique(), Pubkey::new_unique());
    let forged_line = format!("Program data: {FORGED}");
    // None of these may pop the matcher frame (each is followed by the forged data line).
    for not_a_pop in [
        format!("Program {m} success "),
        format!("Program {m} successful"),
        format!("Program {m} failed"),
        format!("Program {m} failedx: y"),
        format!(" Program {m} success"),
        format!("program {m} success"),
        format!("Program  {m} success"),
    ] {
        let logs = tx_logs(&w, &m, &[&not_a_pop, &forged_line]);
        assert_only_the_real_zero_fill(&known(&logs, &w));
    }
    // None of these may push a frame: if one did, the log would end unbalanced (unknown).
    for not_a_push in [
        format!("Program {w} invoke [2] "),
        format!("Program {w} invoke [x]"),
        format!("Program {w} invoke [+3]"),
        format!("Program {w} invoke []"),
        format!("Program {w} invoke [3"),
        "Program notapubkey invoke [3]".to_string(),
    ] {
        let logs = tx_logs(&w, &m, &[&not_a_push, &forged_line]);
        assert_only_the_real_zero_fill(&known(&logs, &w));
    }
    // A real failed line (with the `failed: ` prefix) does pop, as the top of the stack.
    let logs = vec![
        format!("Program {w} invoke [1]"),
        format!("Program {m} invoke [2]"),
        format!("Program {m} failed: custom program error: 0x7"),
        format!("Program data: {REAL}"),
        format!("Program {w} failed: custom program error: 0x7"),
    ];
    assert_eq!(wrapper_frame_tokens(&logs, &w).unwrap(), vec![REAL.to_string()]);
}

/// The wrapper entered by CPI, and a forged copy emitted by the outer program before and after:
/// only the line in the wrapper's own frame counts.
#[test]
fn wrapper_called_by_cpi_keeps_its_own_lines_only() {
    let (w, outer) = (Pubkey::new_unique(), Pubkey::new_unique());
    let logs = vec![
        format!("Program {outer} invoke [1]"),
        format!("Program data: {FORGED}"),
        format!("Program {w} invoke [2]"),
        format!("Program data: {REAL}"),
        format!("Program {w} success"),
        format!("Program data: {FORGED}"),
        format!("Program {outer} success"),
    ];
    assert_only_the_real_zero_fill(&known(&logs, &w));
}

fn b64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// A decoder skips what it does not know and never panics: an unknown kind, an unknown version, a
/// known kind with the wrong length, bytes that are not base64, an empty payload. The known
/// events around them still decode.
#[test]
fn unknown_kind_and_version_are_skipped_not_a_panic() {
    let w = Pubkey::new_unique();
    let mut kind9 = vec![9u8, 1, 10];
    kind9.extend([7u8; 200]);
    let mut version2 = vec![1u8, 2, 10];
    version2.extend([7u8; 172]);
    let kind0 = vec![0u8, 1, 10, 0];
    let short_fill = vec![1u8, 1, 10, 0, 0];
    let mut bad_n = vec![1u8, 1, 10];
    bad_n.extend([0u8; 97]); // n = 0 would be 100 bytes; make n = 3 with no records
    bad_n[99] = 3;
    let short_reduce = {
        let mut v = vec![2u8, 1, 44];
        v.extend([0u8; 100]);
        v
    };
    let long_move = {
        let mut v = vec![3u8, 1, 77];
        v.extend([0u8; 80]);
        v
    };
    let logs = vec![
        format!("Program {w} invoke [1]"),
        format!("Program data: {}", b64(&kind9)),
        format!("Program data: {}", b64(&version2)),
        format!("Program data: {REAL}"),
        format!("Program data: {}", b64(&kind0)),
        format!("Program data: {}", b64(&short_fill)),
        format!("Program data: {}", b64(&bad_n)),
        format!("Program data: {}", b64(&short_reduce)),
        format!("Program data: {}", b64(&long_move)),
        "Program data: !!!not-base64!!!".to_string(),
        format!("Program data: {}", b64(&[1u8])),
        format!("Program {w} success"),
    ];
    let TxEvents::Known { events, skipped } = tx_events(true, Some(&logs), &w) else {
        panic!("frames are consistent")
    };
    assert_only_the_real_zero_fill(&events);
    assert_eq!(
        skipped,
        vec![
            Skip::UnknownKind(9),
            Skip::UnknownVersion(2),
            Skip::UnknownKind(0),
            Skip::BadLength,
            Skip::BadLength,
            Skip::BadLength,
            Skip::BadLength,
            Skip::Malformed,
            Skip::Malformed,
        ]
    );
    // decode() directly, on every prefix of a real event: never a panic.
    let mut real = vec![1u8, 1, 10];
    real.extend([5u8; 97 + 75]);
    real[99] = 1;
    assert!(fill_events::decode(&real).is_ok());
    for n in 0..real.len() {
        assert!(fill_events::decode(&real[..n]).is_err(), "prefix {n}");
    }
}
