//! Phase 3A cross-cut shared harness boilerplate.
//!
//! Extracted (per the Phase 3A design doc, `~/wrapper-engine-deep-audit/
//! phase3a_crosscut_design.md`) so the assembled 5-program harness — and the
//! later economic-spine / invariant sub-phases — stop re-defining `program_path`
//! / `make_mint_data` / `send` in every file. This module is included by the
//! cross-cut integration tests via `mod common;`. As a `tests/common/mod.rs`
//! subdirectory module it is NOT compiled as a standalone test binary, and it
//! does not touch any existing harness (they keep their own copies).
//!
//! # The cross-program trust topology (LOCKED — design doc §"Harness strategy")
//!
//! `.so` BPF loading is version-agnostic, but the *host* dep graph cannot mix
//! litesvm 0.1.0 (solana 1.18) and 0.6.1 (solana 2.2). We therefore host the
//! harness in the wrapper crate at **litesvm 0.1.0** and load matcher / NFT /
//! stake as raw `.so` bytes. The wrapper MUST mount at the **mainnet** program
//! id `ESa89R5…`, NOT `percolator_prog::id()` (the `Perco1ator…` test
//! placeholder), because BOTH the NFT `verify_portfolio_program` allowlist
//! (`cpi_v16.rs`) AND the stake `InitPool` allowlist (`processor.rs`)
//! fail-closed to the mainnet id. Every wrapper-owned account is crafted with
//! `owner = PERCOLATOR_MAINNET`, and every wrapper PDA must be derived under it.

#![allow(dead_code)]

use litesvm::LiteSVM;
use solana_program::pubkey;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::{Instruction, InstructionError},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::path::PathBuf;

// ── Program IDs (cross-repo trust topology) ─────────────────────────────────

/// Wrapper mounts here (mainnet id) — NOT `percolator_prog::id()`. The NFT and
/// stake allowlists fail-closed to this key.
pub const PERCOLATOR_MAINNET: Pubkey = pubkey!("ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv");

/// NFT program id (derived from `percolator_nft-keypair.json`).
pub const NFT_PROGRAM_ID: Pubkey = pubkey!("2kYRqexMf5JnwTK15Vj8qxQX3qkBDzBZvH45SVFRmKYU");

/// Stake program id. MUST equal the wrapper's pinned
/// `constants::STAKE_PROGRAM_ID` — tag 87 (`WithdrawInsuranceReserveToStake`)
/// asserts `pool_ai.owner == STAKE_PROGRAM_ID` before reading a single byte of
/// the pool, so mounting the stake `.so` anywhere else makes every tag-87 test
/// fail with `StakePoolOwnerMismatch` (Custom(55)).
///
/// Was `9tbLt8fs…` (the local `percolator_stake-keypair.json`), which is a
/// throwaway dev key that was never deployed anywhere. It is now the real
/// DEPLOYED devnet program, lineage-verified by rebuild-and-compare
/// (see `constants::STAKE_PROGRAM_ID`). `tests/v16_fee_split.rs::
/// pinned_stake_program_id_matches_the_id_the_harness_mounts` asserts the two
/// stay in lockstep, so this can never drift silently.
///
/// ⚠ Tag-87 tests therefore require BOTH the `.so` and the host lib to carry
/// the pin: `cargo build-sbf --features devnet` and
/// `cargo test --features devnet`. Without the feature the wrapper has no
/// pinned id at all and tag 87 fails closed with `StakeProgramNotPinned`
/// (Custom(60)) — correct behaviour, but it makes the tag-87 suite red.
pub const STAKE_ID: Pubkey = pubkey!("GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3");

/// Token-2022 program id (loaded via `with_spl_programs()`).
pub const TOKEN_2022: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated-Token-Account program id (loaded via `with_spl_programs()`).
pub const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Classic SPL Token (`Tokenkeg…`) — the ONLY token program the wrapper vault
/// accepts (`verify_token_program`, `v16_program.rs:12391`).
pub fn spl_token_classic_id() -> Pubkey {
    spl_token::ID
}

// ── `.so` path helpers ──────────────────────────────────────────────────────

fn manifest_join(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push(rel);
    assert!(
        p.exists(),
        "BPF missing at {} — run `cargo build-sbf` in the owning repo first",
        p.display()
    );
    p
}

pub fn wrapper_so_path() -> PathBuf {
    manifest_join("target/deploy/percolator_prog.so")
}
pub fn nft_so_path() -> PathBuf {
    manifest_join("../percolator-nft/target/deploy/percolator_nft.so")
}
pub fn stake_so_path() -> PathBuf {
    manifest_join("../percolator-stake/target/deploy/percolator_stake.so")
}
pub fn matcher_so_path() -> PathBuf {
    manifest_join("../percolator-match/target/deploy/percolator_match.so")
}

// ── 5-program LiteSVM assembly (LOCKED load order, design doc §"load order") ──

/// One litesvm-0.1 instance with all five programs mounted:
///   1. `with_spl_programs()` → classic spl_token 3.5.0 (`Tokenkeg`),
///      Token-2022 1.0.0 (`TokenzQd`), ATA 1.1.1
///   2. wrapper `.so` at `PERCOLATOR_MAINNET`
///   3. NFT `.so` at `NFT_PROGRAM_ID`
///   4. stake `.so` at `STAKE_ID`
///   5. matcher `.so` at `matcher_id` (matcher needs no fixed id)
pub fn assemble_five_program_svm(matcher_id: Pubkey) -> LiteSVM {
    let mut svm = LiteSVM::new().with_spl_programs();
    svm.add_program(
        PERCOLATOR_MAINNET,
        &std::fs::read(wrapper_so_path()).expect("read wrapper .so"),
    );
    svm.add_program(
        NFT_PROGRAM_ID,
        &std::fs::read(nft_so_path()).expect("read nft .so"),
    );
    svm.add_program(
        STAKE_ID,
        &std::fs::read(stake_so_path()).expect("read stake .so"),
    );
    svm.add_program(
        matcher_id,
        &std::fs::read(matcher_so_path()).expect("read matcher .so"),
    );
    svm
}

// ── SPL fixture data ─────────────────────────────────────────────────────────

/// Uninitialized→initialized classic-SPL `Mint` bytes (supply 0, decimals 0).
pub fn make_mint_data() -> Vec<u8> {
    let mut d = vec![0u8; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: COption::None,
            supply: 0,
            decimals: 0,
            is_initialized: true,
            freeze_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

/// Initialized classic-SPL token-account bytes for `(mint, owner, amount)`.
pub fn make_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(
        TokenAccount {
            mint,
            owner,
            amount,
            delegate: COption::None,
            state: AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        },
        &mut d,
    )
    .unwrap();
    d
}

// ── Compute-budget prefixes + raw send ───────────────────────────────────────

/// 1.4M CU — the per-tx ceiling the multi-program chains run against.
pub fn cu_ix() -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
}

/// 128 KiB heap — required once a tx chains Token-2022 → hook → wrapper CPI.
pub fn heap_ix() -> Instruction {
    ComputeBudgetInstruction::request_heap_frame(128 * 1024)
}

/// Send raw instructions (prefixed with heap+cu budget), returning the unwrapped
/// `TransactionError` on failure so callers can `assert_custom`. A fresh
/// blockhash is taken per send so byte-identical instructions don't collide as
/// `AlreadyProcessed`.
pub fn send_ixs(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: Vec<Instruction>,
    extra_signers: &[&Keypair],
) -> Result<(), TransactionError> {
    svm.expire_blockhash();
    let mut all = Vec::with_capacity(2 + ixs.len());
    all.push(heap_ix());
    all.push(cu_ix());
    all.extend(ixs);
    let mut signers = vec![payer];
    signers.extend_from_slice(extra_signers);
    let tx = Transaction::new_signed_with_payer(
        &all,
        Some(&payer.pubkey()),
        &signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
}

// ── Anti-hollow structural assertions (carried from Phase 2.E) ───────────────

/// Pin the EXACT operative `Custom(code)`. The non-Custom and `Ok` arms are what
/// defeat "passed for the wrong reason".
pub fn assert_custom(res: Result<(), TransactionError>, code: u32, label: &str) {
    match res {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) => {
            assert_eq!(
                c, code,
                "{label}: expected operative Custom({code}), got Custom({c})"
            );
        }
        Err(other) => {
            panic!("{label}: expected operative Custom({code}), got non-Custom {other:?}")
        }
        Ok(()) => panic!("{label}: expected operative Custom({code}), but the tx SUCCEEDED"),
    }
}

/// Assert the result did NOT fail with `Custom(code)` — used for the positive
/// side of a differential (e.g. proving a gate was *passed*, not that the whole
/// instruction succeeded).
pub fn assert_not_custom(res: &Result<(), TransactionError>, code: u32, label: &str) {
    if let Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) = res {
        assert_ne!(
            *c, code,
            "{label}: expected NOT to fail with Custom({code}), but it did"
        );
    }
}

/// Assert a raw send failed with a specific `InstructionError` *from the program*
/// (proving the program was entered and executed under the VM, as opposed to a
/// loader/account rejection like a missing or non-executable program).
pub fn assert_instruction_error(
    res: &Result<(), TransactionError>,
    expected: InstructionError,
    label: &str,
) {
    match res {
        Err(TransactionError::InstructionError(_, got)) => {
            assert_eq!(
                *got, expected,
                "{label}: expected program InstructionError {expected:?}, got {got:?}"
            );
        }
        Err(other) => {
            panic!("{label}: expected a program InstructionError, got tx-level {other:?}")
        }
        Ok(()) => panic!("{label}: expected a program InstructionError, but the tx SUCCEEDED"),
    }
}
