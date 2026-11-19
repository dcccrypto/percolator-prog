# AuthMark push CU: job notes (J-20261118-PROG-CU-AUTHMARKPUSHb)

Base d27f3d73. Status: **baseline not yet measured** (partial report).

Timeline:
- Shared target dir `~/agent-work/cu-target-prog-d27f3d73` was already being built by the sibling EWMA job (its build-sbf has run 80+ min under load).
- My `build-sbf` + `cargo test --release --test v16_cu --no-run` waited ~33 min for the slot lock (held by another job), got it, then blocked on cargo's "file lock on build directory" held by the sibling build.
- No CU numbers yet.

Code read (src/v16_program.rs `handle_push_auth_mark` ~L30169): candidate costs are
`validate_shape()` over the whole group, `read_oracle_profile_from_view`/`write_oracle_profile_to_view`
full-profile copies, `asset_growth_from/to_wrapper_bytes` round trip, and the final
`write_wrapper_config`. None changed; no src edits made.
