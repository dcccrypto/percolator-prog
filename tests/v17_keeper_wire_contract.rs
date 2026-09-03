// Skip when Kani builds the test suite.
#![cfg(not(kani))]
//! PRE-DEPLOY WIRE CONTRACT GUARD — runs against the COMPILED BPF bytecode.
//!
//! WHY THIS EXISTS: on 2026-08-05 a wrapper built from the wrong checkout was
//! deployed to devnet. That build's PermissionlessCrank decoder still read the
//! pre-W3 53-byte payload (`close_q` + `fee_bps`), while the keeper/SDK 4.3.0
//! send the 29-byte W3 payload. Every crank on every market failed with
//! `InvalidInstructionData`, cranking AND pricing stopped, and the markets were
//! quarantined until the program was rebuilt from the canonical tree.
//!
//! Nothing in the test suite caught it, because every other test constructs the
//! instruction through the wrapper's OWN Rust enum — which is by definition
//! self-consistent. This test instead hand-rolls the EXACT bytes the deployed
//! keeper emits and asserts the compiled program accepts them.
//!
//! Keep byte-for-byte in sync with @percolatorct/sdk `encodePermissionlessCrank`:
//!   tag u8 | action u8 | asset_index u16 | now_slot u64 | funding_rate_e9 i128 | recovery_reason u8
//!   = 1 + 1 + 2 + 8 + 16 + 1 = 29 bytes
use litesvm::LiteSVM;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::Signer;
use std::path::PathBuf;

const IX_TAG_PERMISSIONLESS_CRANK: u8 = 5;
/// The exact wire size the deployed keeper emits (SDK 4.3.0, post-W3).
const KEEPER_CRANK_WIRE_LEN: usize = 29;

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    p
}

/// Byte-for-byte mirror of the SDK's `encodePermissionlessCrank`.
fn keeper_encode_permissionless_crank(
    action: u8,
    asset_index: u16,
    now_slot: u64,
    recovery_reason: u8,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(KEEPER_CRANK_WIRE_LEN);
    d.push(IX_TAG_PERMISSIONLESS_CRANK);
    d.push(action);
    d.extend_from_slice(&asset_index.to_le_bytes());
    d.extend_from_slice(&now_slot.to_le_bytes());
    d.extend_from_slice(&0i128.to_le_bytes()); // funding_rate_e9 hardcoded 0
    d.push(recovery_reason);
    d
}

#[test]
fn keeper_crank_payload_is_exactly_29_bytes() {
    let d = keeper_encode_permissionless_crank(0, 0, 12_345, 0);
    assert_eq!(
        d.len(),
        KEEPER_CRANK_WIRE_LEN,
        "keeper crank wire size drifted: {} bytes. The deployed keeper emits {} \
         (post-W3, no close_q/fee_bps). A program expecting a different size rejects \
         EVERY crank with InvalidInstructionData.",
        d.len(),
        KEEPER_CRANK_WIRE_LEN
    );
    assert_eq!(d[0], IX_TAG_PERMISSIONLESS_CRANK);
}

/// THE GUARD: feed the compiled program the keeper's real bytes and assert it does
/// NOT reject them as malformed. A pre-W3 build fails here with InvalidInstructionData
/// before ever touching account state — exactly the outage signature.
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
    // logic here — only that the payload DECODES. A wire-format mismatch fails at
    // decode with InvalidInstructionData; a correct build gets past decode and
    // fails later on account validation, which is the PASS condition.
    let data = keeper_encode_permissionless_crank(0, 0, 1, 0);
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
         This is the 2026-08-05 outage signature: the build expects a different \
         PermissionlessCrank wire format than the deployed keeper emits, so every \
         crank on every market would fail.\n\
         DO NOT DEPLOY THIS ARTIFACT.\nerror: {err_text}"
    );
}
