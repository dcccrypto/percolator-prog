//! Fuzz target: `read_risk_params` (exercised via `Instruction::decode`)
//!
//! `read_risk_params` is a private function inside `mod ix`.  We reach it
//! by routing through `Instruction::decode` with tag=0 (InitMarket), which
//! is exactly the production call-site.  The prefix bytes for the earlier
//! fixed fields are filled with zeroes so the fuzzer can focus its corpus
//! entropy on the risk-params portion of the payload.
//!
//! The function is called with every possible byte-length from 0 to 500 to
//! verify the bounds guards and the "must have >=48 bytes remaining" check.

#![no_main]

use libfuzzer_sys::fuzz_target;
use percolator_prog::fuzz_helpers::fuzz_read_risk_params_via_decode;

fuzz_target!(|data: &[u8]| {
    // Limit corpus to a reasonable window; libFuzzer may generate longer
    // inputs but we reject them to keep iteration speed high.
    if data.len() > 500 {
        return;
    }
    // Drive the private `read_risk_params` path via the InitMarket decoder.
    // Any return value (Ok or Err) is acceptable; only a panic is a failure.
    let _ = fuzz_read_risk_params_via_decode(data);
});
