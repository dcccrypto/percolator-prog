// Skip when Kani builds the test suite.
#![cfg(not(kani))]
//! PRE-DEPLOY WIRE CONTRACT GUARD — runs against the COMPILED BPF bytecode.
//!
//! WHY THIS EXISTS: on 2026-08-05 a wrapper built from the wrong checkout was
//! deployed to devnet. That build's PermissionlessCrank decoder still read the
//! pre-W3 53-byte payload (`close_q` + `fee_bps`), while the keeper/SDK 4.3.0
//! sent the 29-byte W3 payload. Every crank on every market failed with
//! `InvalidInstructionData`, cranking AND pricing stopped, and the markets were
//! quarantined until the program was rebuilt from the canonical tree.
//!
//! Nothing in the test suite caught it, because every other test constructs the
//! instruction through the wrapper's OWN Rust enum — which is by definition
//! self-consistent. This test instead hand-rolls the EXACT bytes the deployed
//! keeper emits and asserts the compiled program accepts them.
//!
//! WIRE UPDATE (v16 integration, a9318945): tag 5 is no longer the fixed
//! 29-byte W3 shape above. Upstream Group-B subsystem #2 (AutoCrankObservation,
//! d63c4dc9 + 7d0d2539, adopted in `src/v16_program.rs`'s `ix::Instruction`)
//! replaced the caller-classified `action`/`asset_index`/`funding_rate_e9`/
//! `recovery_reason` payload with a variable-length `now_slot` + bounded
//! `Vec<CrankObservationHint>` list — the caller now only reports which assets
//! it has fresh oracle evidence for, and the engine's `AutoCrankPlanV16`
//! selector picks the action. Keep byte-for-byte in sync with
//! @percolatorct/sdk's `encodePermissionlessCrank` for this shape
//! (percolator-sdk owns the TS side; this file only asserts what the COMPILED
//! PROGRAM decodes):
//!   tag u8 (5) | now_slot u64 | n u8 | n * (asset_index u16 | oracle_accounts u8)
//!   = 1 + 8 + 1 + 3*n bytes  (10 bytes at n=0, 13 bytes for the common n=1 case)
//! See `src/v16_program.rs`'s `ix::Instruction::decode`/`encode` (tag-5 arm) for
//! the canonical implementation this test independently cross-checks.
//!
//! HEAP-CRASH GUARD (2026-09-21 hardening): the previous version of this
//! canary asserted only `!err_text.contains("InvalidInstructionData")`, which
//! passes VACUOUSLY if the compiled artifact CRASHES instead of decoding
//! cleanly — LiteSVM's `simulate_transaction` surfaces a BPF heap access
//! violation as `InstructionError(_, ProgramFailedToComplete)` with an
//! "Access violation in heap section ... of size 8" log line, not
//! `InvalidInstructionData`, so the old assertion silently passed on a crash.
//!
//! Root-caused: this crash reproduces for EVERY instruction tag — including a
//! single-byte bogus-tag payload that never reaches `Instruction::decode`'s
//! account-touching handlers at all — but ONLY when the program is built
//! `--no-default-features` (the legacy `solana_program::entrypoint::deserialize`
//! + `BumpAllocator` entrypoint at `src/v16_program.rs:27986`). It does NOT
//! reproduce under the `anchor-v2` feature (`src/v16_program.rs:28032`), which
//! is the entrypoint actually deployed (Cargo.toml: "v16 deploys through the
//! Anchor v2 / Pinocchio entrypoint by default; `--no-default-features` remains
//! available for legacy local compatibility"). Both entrypoints funnel into the
//! identical `processor::process_instruction` — the crash sits in the legacy
//! entrypoint's account/heap setup on this LiteSVM version, before any
//! wire-specific logic runs, so this is a `--no-default-features` +
//! synthetic-account-setup test-harness artifact, not a decode-logic or
//! account-validation bug, and it is not reachable through the production
//! (anchor-v2) build path. FLAGGING (not fixing): if `--no-default-features`
//! is ever used for something other than "legacy local compatibility" (e.g. a
//! real deploy target), this heap-AV needs its own investigation before that
//! happens — it was NOT investigated further here since it sits entirely
//! outside the deployed entrypoint.
//!
//! The assertions below now require the compiled artifact to get PAST decode
//! without crashing — either failure mode (decode-reject or crash) now fails
//! this test explicitly, with a message that names which one happened.
use litesvm::LiteSVM;
use percolator_prog::ix::{CrankObservationHint, Instruction as ProgInstruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;
use std::path::PathBuf;

const IX_TAG_PERMISSIONLESS_CRANK: u8 = 5;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    p
}

/// Byte-for-byte mirror of the SDK's `encodePermissionlessCrank` for the
/// current (post-AutoCrankObservation) wire. Hand-rolled independently of
/// `percolator_prog::ix::Instruction::encode()` — see the module doc for why
/// that independence matters (every OTHER test goes through the wrapper's own
/// enum, which by construction can never disagree with itself).
fn keeper_encode_permissionless_crank(now_slot: u64, observations: &[(u16, u8)]) -> Vec<u8> {
    assert!(observations.len() <= u8::MAX as usize);
    let mut d = Vec::with_capacity(10 + 3 * observations.len());
    d.push(IX_TAG_PERMISSIONLESS_CRANK);
    d.extend_from_slice(&now_slot.to_le_bytes());
    d.push(observations.len() as u8);
    for &(asset_index, oracle_accounts) in observations {
        d.extend_from_slice(&asset_index.to_le_bytes());
        d.push(oracle_accounts);
    }
    d
}

#[test]
fn keeper_crank_payload_size_matches_tag5_wire_formula() {
    let empty = keeper_encode_permissionless_crank(12_345, &[]);
    assert_eq!(
        empty.len(),
        10,
        "keeper crank wire size drifted: {} bytes for zero observations. The \
         current tag-5 wire is tag(1)+now_slot(8)+n(1) = 10 bytes at n=0. A \
         program expecting a different size rejects EVERY crank with \
         InvalidInstructionData.",
        empty.len()
    );
    assert_eq!(empty[0], IX_TAG_PERMISSIONLESS_CRANK);

    let one_obs = keeper_encode_permissionless_crank(12_345, &[(0, 0)]);
    assert_eq!(
        one_obs.len(),
        13,
        "keeper crank wire size drifted: {} bytes for one observation (the \
         common real-keeper case). Expected tag(1)+now_slot(8)+n(1)+3*1 = 13.",
        one_obs.len()
    );
}

/// Ground-truth wire-contract check: drive `Instruction::decode()` directly
/// (no BPF VM, no LiteSVM, no account list) on the hand-rolled keeper bytes.
/// This is immune to the `--no-default-features`/LiteSVM heap-AV artifact
/// documented in the module doc — it exercises exactly, and only, the
/// decode-side wire contract, against the SAME source tree the compiled
/// artifact below is built from.
#[test]
fn instruction_decode_accepts_the_real_keeper_crank_wire() {
    let data = keeper_encode_permissionless_crank(777, &[(3, 0)]);
    let decoded = ProgInstruction::decode(&data)
        .expect("the compiled decode logic must accept the current keeper wire");
    assert_eq!(
        decoded,
        ProgInstruction::PermissionlessCrank {
            now_slot: 777,
            observations: vec![CrankObservationHint {
                asset_index: 3,
                oracle_accounts: 0,
            }],
        },
        "decoded PermissionlessCrank fields do not match the hand-rolled keeper wire"
    );
}

#[test]
fn instruction_decode_rejects_the_legacy_pre_autocrank_wire() {
    // The OLD (pre-a9318945) 29-byte W3 shape:
    //   tag u8 | action u8 | asset_index u16 | now_slot u64 | funding_rate_e9 i128 | recovery_reason u8
    let mut legacy = Vec::with_capacity(29);
    legacy.push(IX_TAG_PERMISSIONLESS_CRANK);
    legacy.push(0u8); // action
    legacy.extend_from_slice(&0u16.to_le_bytes()); // asset_index
    legacy.extend_from_slice(&1u64.to_le_bytes()); // now_slot
    legacy.extend_from_slice(&0i128.to_le_bytes()); // funding_rate_e9
    legacy.push(0u8); // recovery_reason
    assert_eq!(
        ProgInstruction::decode(&legacy),
        Err(solana_program::program_error::ProgramError::InvalidInstructionData),
        "the current decode arm must cleanly reject the retired pre-AutoCrankObservation \
         29-byte wire, not silently reinterpret its bytes as a valid now_slot/observations pair"
    );
}

/// THE COMPILED-ARTIFACT GUARD: feed the compiled program the keeper's real
/// bytes and assert it gets PAST decode — i.e. it neither rejects them as
/// malformed NOR crashes trying to process them. A stale/wrong-checkout build
/// (this canary's whole reason for existing, see module doc) fails decode with
/// `InvalidInstructionData` before ever touching account state. A memory-safety
/// regression crashes instead of erring cleanly — previously indistinguishable
/// from a PASS here; now its own explicit, separately-diagnosed failure.
#[test]
fn compiled_program_accepts_the_real_keeper_crank_wire() {
    let path = program_path();
    assert!(
        path.exists(),
        "BPF not found at {path:?} — run `cargo build-sbf` first. This test must run \
         against the SAME artifact that will be deployed."
    );
    let mut svm = LiteSVM::new();
    let program_id = Pubkey::new_unique();
    svm.add_program_from_file(program_id, &path)
        .expect("compiled wrapper must load into LiteSVM");

    let kp = solana_sdk::signature::Keypair::new();
    let payer = kp.pubkey();
    svm.airdrop(&payer, 10_000_000_000).unwrap();

    // Deliberately pass junk accounts. We are NOT testing the crank's business
    // logic here — only that the payload DECODES. A wire-format mismatch fails
    // at decode with InvalidInstructionData; a correct build gets past decode
    // and fails later on account validation (observed: IncorrectProgramId,
    // since these junk accounts are owned by the System Program rather than
    // this program) — that later-stage failure is the PASS condition.
    let data = keeper_encode_permissionless_crank(1, &[(0, 0)]);
    let ix = solana_sdk::instruction::Instruction {
        program_id,
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(payer, true),
            solana_sdk::instruction::AccountMeta::new(Pubkey::new_unique(), false),
            solana_sdk::instruction::AccountMeta::new(Pubkey::new_unique(), false),
        ],
        data,
    };
    let tx: solana_sdk::transaction::VersionedTransaction =
        solana_sdk::transaction::Transaction::new_signed_with_payer(
            &[ix],
            Some(&kp.pubkey()),
            &[&kp],
            svm.latest_blockhash(),
        )
        .into();
    let res = svm.simulate_transaction(tx);
    let err_text = match res {
        Ok(_) => String::new(),
        Err(e) => format!("{e:?}"),
    };
    assert!(
        !err_text.contains("InvalidInstructionData"),
        "THE COMPILED PROGRAM REJECTED THE KEEPER'S CRANK PAYLOAD AS MALFORMED.\n\
         This is the 2026-08-05 outage signature re-targeted at the current \
         AutoCrankObservation wire: the build expects a different \
         PermissionlessCrank shape than the deployed keeper emits, so every \
         crank on every market would fail.\n\
         DO NOT DEPLOY THIS ARTIFACT.\nerror: {err_text}"
    );
    // THE HEAP-CRASH GUARD: a crash is not a pass. Without this, a build that
    // segfaults on every instruction (see module doc — a real, reproduced
    // failure mode under `--no-default-features`) would satisfy the assertion
    // above (its error text doesn't mention InvalidInstructionData either) and
    // this canary would report a false PASS on a broken artifact.
    assert!(
        !err_text.contains("ProgramFailedToComplete") && !err_text.contains("Access violation"),
        "THE COMPILED PROGRAM CRASHED INSTEAD OF CLEANLY ACCEPTING OR REJECTING \
         THE KEEPER'S CRANK PAYLOAD.\nA crash here is indistinguishable from an \
         outage in production and must never be treated as a passing decode \
         check.\nDO NOT DEPLOY THIS ARTIFACT.\nerror: {err_text}"
    );
}
