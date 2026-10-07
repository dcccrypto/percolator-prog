//! v2.2 item 4: the `mainnet-ids` flavour's runtime pin. Needs the `.so` built with the TEST
//! placeholders (never a release build):
//!   cargo build-sbf --tools-version v1.52 --features mainnet-ids-test-placeholders \
//!       --sbf-out-dir <dir>
//!   MAINNET_IDS_SO=<dir>/percolator_prog.so cargo test --test mainnet_ids_flavour
//! Without `MAINNET_IDS_SO` the tests are skipped (they cannot run on the devnet `.so`).
//!
//! Asserts: the binary runs ONLY at its pinned wrapper id (`[0xA2; 32]`); mounted at any other
//! address every instruction is refused with `IncorrectProgramId` before touching state (the
//! negative control proves the pin is what refuses, because the pinned mount reaches the
//! instruction decoder and fails there instead).

use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

const PINNED_WRAPPER: Pubkey = Pubkey::new_from_array([0xA2; 32]);

fn so() -> Option<Vec<u8>> {
    let p = std::env::var_os("MAINNET_IDS_SO")?;
    Some(std::fs::read(p).expect("read MAINNET_IDS_SO"))
}

fn run(id: Pubkey, bytes: &[u8]) -> InstructionError {
    let mut svm = LiteSVM::new();
    svm.add_program(id, bytes);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    // 0xFF is not a wrapper tag: a program that RUNS answers InvalidInstructionData; a program
    // that refuses its address answers IncorrectProgramId before decoding.
    let ix = Instruction {
        program_id: id,
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![0xFF],
    };
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], svm.latest_blockhash());
    match svm.send_transaction(tx) {
        Err(e) => match e.err {
            TransactionError::InstructionError(_, ie) => ie,
            other => panic!("unexpected tx error {other:?}"),
        },
        Ok(_) => panic!("0xFF must never succeed"),
    }
}

#[test]
fn mainnet_flavour_runs_only_at_its_pinned_id() {
    let Some(bytes) = so() else {
        eprintln!("MAINNET_IDS_SO not set: skipped");
        return;
    };
    let at_pin = run(PINNED_WRAPPER, &bytes);
    assert_ne!(at_pin, InstructionError::IncorrectProgramId, "the pinned mount must run: {at_pin:?}");
    // Negative controls: a different address, and the devnet placeholder id.
    for other in [Pubkey::new_from_array([0xA3; 32]), percolator_prog::id()] {
        let e = run(other, &bytes);
        assert_eq!(e, InstructionError::IncorrectProgramId, "mounted at {other}: {e:?}");
    }
}
