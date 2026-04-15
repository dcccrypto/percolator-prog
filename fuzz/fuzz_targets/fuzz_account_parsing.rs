//! Fuzz target: account struct parsing from arbitrary bytes
//!
//! This target exercises the two paths by which the program reads account data
//! from raw slab bytes:
//!
//! 1. `zc::engine_ref` — the unsafe zero-copy island that casts a `&[u8]`
//!    slice into a `&RiskEngine`.  It validates alignment, buffer length, and
//!    enum discriminants before creating the reference.  Malformed data must
//!    return `Err(ProgramError::InvalidAccountData)` — never produce UB.
//!
//! 2. `state::read_header` / `state::read_config` (via the safe wrappers) —
//!    bytemuck `copy_from_slice` paths.  These are safe as long as the buffer
//!    is long enough; the wrapper returns `None` on short buffers.
//!
//! We also perform a few field reads on successfully parsed engines to ensure
//! that accessing `engine.accounts[i]` on a fuzzed engine does not panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use percolator_prog::{
    fuzz_helpers::{fuzz_read_header, fuzz_read_config},
    zc,
};

fuzz_target!(|data: &[u8]| {
    // --- Path 1: zero-copy engine parse ----------------------------------------
    // `zc::engine_ref` guards alignment, length, and enum discriminants.
    // On valid-looking bytes it returns &RiskEngine; on bad bytes it returns Err.
    // Either outcome is correct — a panic or UB is the failure mode we detect.
    match zc::engine_ref(data) {
        Ok(engine) => {
            // If the cast succeeded, perform some read-only field accesses to
            // ensure the compiler did not elide the length/alignment checks and
            // that field offsets are sound.
            let _max_accounts = engine.params.max_accounts;
            let _c_tot = engine.c_tot.get();
            let _insurance = engine.insurance_fund.balance.get();
            // Iterate a bounded number of accounts to exercise the array path.
            let n = (engine.params.max_accounts as usize)
                .min(engine.accounts.len())
                .min(4); // cap to keep the fuzz loop fast
            for i in 0..n {
                let _cap = engine.accounts[i].capital.get();
                let _kind = engine.accounts[i].kind;
            }
        }
        Err(_) => {
            // Expected for most fuzz inputs — buffer too short, misaligned, or
            // invalid enum discriminant.  Not a failure.
        }
    }

    // --- Path 2: bytemuck header / config parse ---------------------------------
    // Safe wrappers return None on short buffers, Some(_) otherwise.
    let _ = fuzz_read_header(data);
    let _ = fuzz_read_config(data);
});
