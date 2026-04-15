//! Fuzz target: slab header and config parsing
//!
//! `state::read_header` and `state::read_config` perform direct slice indexing
//! and will panic if the buffer is shorter than `HEADER_LEN` or
//! `HEADER_LEN + CONFIG_LEN` respectively.  The safe wrappers in
//! `fuzz_helpers` add the length guard and return `Option` instead of
//! panicking, allowing the fuzzer to exercise both the short-buffer (None)
//! path and the full bytemuck copy path.
//!
//! We also feed the raw data into `fuzz_decode_instruction` so the fuzzer can
//! discover any header-related decode paths in a single pass.

#![no_main]

use libfuzzer_sys::fuzz_target;
use percolator_prog::fuzz_helpers::{
    fuzz_decode_instruction, fuzz_read_header, fuzz_read_config, fuzz_read_header_and_config,
};

fuzz_target!(|data: &[u8]| {
    // Path 1: safe header-only parse (guards data.len() < HEADER_LEN).
    let _ = fuzz_read_header(data);

    // Path 2: safe config-only parse (guards data.len() < HEADER_LEN + CONFIG_LEN).
    let _ = fuzz_read_config(data);

    // Path 3: combined header + config parse.
    let _ = fuzz_read_header_and_config(data);

    // Path 4: also run the data through the instruction decoder for cross-coverage.
    // A malformed slab that also happens to be a valid instruction encoding is an
    // interesting corpus entry — we want to detect any shared parse ambiguity.
    let _ = fuzz_decode_instruction(data);
});
