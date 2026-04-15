//! Fuzz target: `Instruction::decode`
//!
//! Feed arbitrary bytes into the instruction decoder and assert it never
//! panics — only returns Ok(instruction) or Err(ProgramError).
//!
//! Coverage intent:
//! - Every tag branch in the match (0-71+)
//! - All integer read helpers (read_u8, read_u16, read_u32, read_u64,
//!   read_u128, read_i64, read_i128, read_pubkey, read_bytes32)
//! - Truncated / oversized payloads
//! - The extended-tail length gate in InitMarket (tag 0)
//! - The `read_risk_params` private path, exercised via tags that call it

#![no_main]

use libfuzzer_sys::fuzz_target;
use percolator_prog::fuzz_helpers::fuzz_decode_instruction;

fuzz_target!(|data: &[u8]| {
    // The result is intentionally discarded — we only care that this never
    // panics.  Both Ok(_) and Err(_) are valid outcomes.
    let _ = fuzz_decode_instruction(data);
});
